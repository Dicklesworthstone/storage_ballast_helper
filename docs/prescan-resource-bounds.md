# Bounded-memory, resumable pre-scan pages

The pre-scan cursor previously collected every depth-one entry in a scan root,
sorted the entire collection, removed the already-visited prefix, and only then
truncated it. Selection now filters the resume prefix while enumerating and
retains only the smallest page of remaining paths in a max-heap. A smaller name
encountered late replaces the largest retained name; sorting reuses the heap
allocation. Retained names are bounded throughout selection, independently of
the total number of directory entries.

## Preparation survives a pass boundary

`entries_to_visit`, the method already used by the daemon, retains its directory
iterator and selection heap when preparation runs out of its slice. Each call
reads at most sixteen chunks of 256 entries and checks a 50 ms elapsed-time
allowance between chunks. `WouldBlock` means preparation or reader admission is
pending, not EOF. The existing daemon error-yield branch calls `complete_root`;
the incomplete page proof preserves continuation and read-ahead on that branch.

If enumeration and sorting finish at the end of a slice, the prepared page is
retained for the next call. Stopping before examining the returned names therefore
does not require preparing the same page again. The explicit
`poll_entries_to_visit` API also accepts caller-supplied budget/cancellation
checks and returns a lazy `RootPage`; the existing daemon entry API still returns
a `Vec<PathBuf>`, not the lazy iterator. The daemon retains its existing pass,
shutdown and heartbeat checks between calls. No claim is made that its `PassLimits`
or heartbeat callback has been moved inside individual filesystem operations.

Four live roots share `ROOT_ENTRY_CAP` (200,000) cached names, with at most 50,000
names and one retained directory iterator per root. These are cache-entry and
path-count bounds, not a raw-byte memory limit; returned vectors or retained page
handles also own memory. A smaller page can require more whole-directory
traversals than the old single-root page size.

When all four readers are active, a fifth root receives `WouldBlock` without
evicting an unfinished reader. Eviction on every miss would make a cyclic scan of
five large roots restart all five forever. Actual root completion releases its
slot. A reader not requested for an hour can be reclaimed on a later admission
attempt, so roots no longer scheduled do not reserve capacity indefinitely.
Requests renew only the reader they actually reuse; waiting for a busy cache does
not renew unrelated readers. This is not a completion guarantee for arbitrary
request schedules or a permanently changing filesystem.

Normal cursors constructed on the same scanner thread share only volatile
read-ahead through a weak, thread-local cache. This includes the daemon's fresh
scratch cursor for each event-scoped pass. Their completed positions and page
proofs remain independent, so event-scoped work cannot advance configured-root
checkpoint coverage. Clones retain their own completion proof. A forced reset
clears shared speculative reads; peers keep their completed positions. Dropping
the last cursor releases the cache and its directory handles.

## A full page is not a completed root

Selection records whether enumeration saw more eligible names than fit in the
page. The daemon's existing `entries_to_visit`, `advance`, `complete_root`
sequence uses that evidence: consuming a capped page preserves its last examined
name instead of restarting at the root's beginning. An exactly-full final page
is distinguishable from a capped page and needs no extra empty pass.

Completion gives the next configured root a turn while retaining a continuation
for each unfinished root. Scanning a different mount, or a request containing
only a subset of roots, no longer forgets those continuations. Checkpoints carry
the selected `root` and `after` plus the other unfinished roots. Completing a root
removes its continuation, and a forced reset clears every root's progress.
Continuation storage scales with the number of unfinished roots, not the number
of children in any root.

Reading a page is not completed work. A partially examined final page retains
its last examined name. Failed enumeration invalidates earlier completion
proofs and preserves existing progress when the daemon yields to another root.
Page evidence and read-ahead are neither persisted nor included in progress
equality: a read alone does not trigger a checkpoint write. A restart loses
unfinished enumeration, not the previously checkpointed completed positions.

## Durable restart progress

`PrescanCursor::save/load` use a versioned, SHA-256-checked envelope. UTF-8 paths
remain readable strings; other Unix paths use a `unix_bytes` array. Continuations
are an ordered sequence of root/resume pairs, so even a non-UTF-8 root is
representable without JSON object-key restrictions. Existing UTF-8 checkpoints
are accepted and upgraded on the next save. A corrupt, unsupported, inconsistent
or oversized checkpoint restarts discovery rather than authorizing any deletion.

The cursor checkpoint is limited to 4 MiB, 8,192 continuation roots, 16 KiB per
path and 512 KiB of combined raw path data. These are persistence bounds, not
limits on the live scan. Invalid saves preserve the previous checkpoint. Loads
accept only bounded regular files, refuse final-component symlinks, open FIFOs
nonblocking on Unix, bound growth during a read, and reject changed snapshots.

Saves create an owner-only, randomly named staging file. On Unix its creation,
publication and failed-save cleanup are relative to an opened state-directory
descriptor. The file is synced before rename; directory links and publication
are synced as well. A replaced state-directory pathname cannot redirect these
operations into a different directory. Failures before publication leave the
previous checkpoint intact; a directory-sync failure after publication is
reported without rolling back over a concurrent writer. This is not a guarantee
against an adversary with write authority over the opened state directory.

The scanner candidate index also encodes non-UTF-8 `CandidateIndexRecord.path`
values without discarding the rest of the checkpoint. Ordinary UTF-8 records
retain their existing version-2 serialization and checksum inputs. Mixed-name
indexes retain identity bindings, invalidations and failure cooldowns across
restart. This change concerns these two checkpoint surfaces; it does not claim
byte-preserving JSON output for every CLI command or decision-record type.

## Scope and tests

Enumeration must still inspect the whole directory to find the smallest names
in an unspecified order. An individual filesystem call, the final bounded sort,
and collection of a ready page into the existing entry API's vector are not
interruptible. The 50 ms check is cooperative, not a hard I/O deadline or a
universal scan-latency guarantee. Daemon pass scheduling and empty-pass pacing
still affect how quickly a paused preparation is revisited. New names absent
from a retained page are discovered in a later sweep. Work inside a single
depth-one entry still follows the daemon's existing nested traversal and budget
policy. Candidate scoring, protection, pressure thresholds and mutation policy
are unchanged. This does not claim to fix the separately observed macOS
candidate-discovery fixture failures.

Existing selection and checkpoint tests remain. The paging tests execute the
daemon's page/advance/completion sequence across capped and exactly-full pages,
multiple roots, alternating mount requests, repeated restarts, partial pages,
enumeration failures, independent rewind clones, legacy checkpoints, forced
resets, disappearing tails, and changing enumeration order. Parent API tests
retry only the explicit `WouldBlock` preparation state; their ordering and
coverage assertions remain.

`prescan_cursor::enumeration::tests` covers bounded chunks, retained completed
pages, root replacement, independent scratch progress, forced resets, descriptor
lifetime, the existing daemon entry/error-yield sequence, multi-root admission,
and the inactive-reader lease boundary. The contention case cycles through
seven real directory roots with four slots and verifies delivery of every name,
not merely eventual admission. These Rust tests require execution through `rch`
and native macOS qualification; source review or a scheduling model is not a
substitute for those runs.

`prescan_cursor::checkpoint::tests` adds restart encoding, corruption, resource
bounds, FIFO/symlink refusal, concurrent publication, owner permissions, failed
publication and parent-replacement cases. `core::path_serde::tests` covers the
candidate index's mixed-name persistence, failure cooldown boundary, revocation,
identity replacement and malformed-byte fallback. Its arbitrary-byte property
checks representation round-trips, not filesystem filename admission: APFS and
Linux filesystems need not admit the same names. Native platform execution is
still required to qualify the filesystem paths.
