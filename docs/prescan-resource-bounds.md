# Bounded-memory, resumable scanner directory pages

The pre-scan cursor previously collected every depth-one entry in a scan root,
sorted the entire collection, removed the already-visited prefix, and only then
truncated it. Selection now filters the resume prefix while enumerating and
retains only the smallest page of remaining paths in a max-heap. A smaller name
encountered late replaces the largest retained name; sorting reuses the heap
allocation. Retained names are bounded throughout selection, independently of
the total number of directory entries.

## Preparation survives a pass boundary

The daemon uses `poll_entries_to_visit` through `PassLimits::prescan_page`.
Preparation retains its directory iterator and selection heap when the live
pre-scan CPU share, phase deadline, pass deadline or shutdown check stops it.
The callback runs between chunks of at most 256 names and renews the scanner
heartbeat. `Ok(None)` means the phase paused; `WouldBlock` means reader admission
is pending. Neither means EOF. Yielding calls `complete_root` to give the next
root a turn; the incomplete page proof preserves continuation and read-ahead.

If enumeration and sorting finish at the end of a slice, the prepared page is
retained for the next call. Stopping before examining the returned names therefore
does not require preparing the same page again. The returned `RootPage` clones
one name at a time, so entering a resumed daemon pass does not copy a whole
50,000-name page before checking its allowance. The convenience
`entries_to_visit` API still returns a vector and uses its own sixteen-chunk,
50 ms preparation slice; the daemon no longer uses that API. Budget and
heartbeat checks remain cooperative between filesystem operations.

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
read-ahead through a weak, thread-local cache. The daemon explicitly derives
each event-scoped scratch cursor with `scoped_read_ahead`. Completed positions
and page proofs remain independent, so event-scoped work cannot advance configured-root
checkpoint coverage. Clones retain their own completion proof. A forced reset
clears shared speculative reads; peers keep their completed positions. Dropping
the last cursor releases the cache and its directory handles.

## A full page is not a completed root

Selection records whether enumeration saw more eligible names than fit in the
page. The daemon's `poll_entries_to_visit`, `advance`, `complete_root`
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

## Recursive enumeration also survives a finite slice

A large directory below the priority pre-scan's depth limit can consume a whole
recursive walk allowance before its children are queued. Restarting that listing
at its first name on every pass hides the descendants indefinitely. Unix walks
that omit file sizing and do not follow symlinks now retain the unfinished
directory iterator, structural observations and child basenames. Completed
parent listings are also retained so revisiting ancestors need not repeat all
their enumeration before reaching the unfinished descendant.

Each scanner thread retains at most four partial-reader reservations and sixteen
completed parent pages. Completed pages together retain at most 65,536 child
names; each partial reader retains at most its current window's child names.
These are handle and name-count bounds, not byte limits. Idle entries expire
after one hour when the cache is next consulted. A checked-out reader keeps its
reservation during slow native I/O, and a guard releases that reservation if
its worker unwinds. Rotating the active root subset does not discard unfinished
reads. This state is process-local and is not a persisted traversal checkpoint.

Reuse requires the same device, inode, modification time and change time.
Before dispatching retained names, the walker checks `.sbh-protect` again and
revalidates `CACHEDIR.TAG` contents. Current exclusions, protection, maximum
depth, opaque classification and device policy still control traversal. A
failed observation cannot become a permanently cached complete page. Children
are queued only after actual enumeration EOF, and cancellation during child
dispatch does not advance the directory's processing window.

When dispatch or a queued child is interrupted, the page uses one-child turns
on later visits. An unchanged parent listing is revalidated before each turn;
ordinary pages keep parallel dispatch. Queued and active continuations share
an additional allowance of sixteen frames and 65,536 child names. If that
allowance is occupied, discovery retains the existing full-dispatch path.

Output advances saved scheduling priority only when the walk stream returns it
to the consumer. Fresh policy refusals may move past an ineligible child without
claiming completion. A result's receipt also gives held ancestors a turn, so an
inner page need not finish in one slice before another branch can be reached.
Output left in a batch or
channel at cancellation remains unfinished. Each pass still attempts a whole
circular page: accumulated priority is never subtree-completion evidence. A
parent already received during an interrupted walk is delayed until its child
cycle finishes, while an uninterrupted walk still returns every directory once.
No queued work item or old traversal policy is replayed across walks.

The 1,048,576-name per-visit cap yields a retained reader on these daemon walks.
File-sizing, follow-symlink and non-Unix walks do not retain observations: at
the cap they leave the directory unfinished, dispatch no children from that
listing, and retry from its start on a later walk. This preserves the requirement
to inspect the entire listing for a protection marker. Retained enumeration
does not guarantee completion for every topology or a continuously changing or
unreadable tree. Finite frame/page admission, expensive individual filesystem
calls and changes that invalidate retained membership remain limits on progress.

## Scope and tests

Enumeration must still inspect the whole directory to find the smallest names
in an unspecified order. An individual filesystem call and the final bounded
sort are not interruptible. The daemon's pass checks are cooperative, not a
hard I/O deadline or a universal scan-latency guarantee. Daemon pass scheduling
and empty-pass pacing still affect how quickly a paused preparation is revisited. New names absent
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

Daemon tests also drive the production `PassLimits::prescan_page` path with
the default Critical CPU allowance and injected cumulative CPU observations.
They verify that enumeration yields the pre-scan share, retains recursive
discovery's remaining allowance, and eventually delivers every name. A shutdown
test covers both an already-prepared page and a root not yet opened. These
deterministic accounting tests are not a throughput measurement on a fleet host.

The recursive walk tests use real deep directories and deterministic heartbeat
cancellation to exercise successive finite slices, inserted protection markers,
directory replacement, changed traversal policy, changed tag contents and
cancellation during child dispatch. Cache tests cover bounded admission and
completed pages, expiration, unwind cleanup and failed-observation retries.
These tests do not establish a fleet completion rate or qualify native macOS.

Public walker regressions also cover equally finite child-dispatch slices,
cancellation after receiving nested parent/leaf results, retained full-walk
output, and changed scope/protection/identity. Their heartbeat schedule lets
the consumer receive published results before each funded boundary; output
drained after cancellation is counted only as unfinished, never as discovery.

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

## Fair turns for protected-root target surveys

The target-only tier has its own discovery and survey path. Surveys of targets
found under one protected root share 120 seconds and 2,000,000 examined entries
per pass. An incomplete candidate remains unsurveyed and cannot be nominated.
The next pass starts after the last target which received its turn, wrapping
through the freshly discovered, sorted candidates. A target interrupted after
earlier targets used part of the allowance is retried first on the next pass.
Only an incomplete target which received the first, full allowance spends its
turn. A large target therefore cannot spend every later target's turn on every
pass, while targets which individually fit a full allowance all get one.
Each root keeps its own position; a missing or newly protected cursor target
does not prevent its successor from being tried.

This position is volatile scheduling state. A replaced root inode or material
scanner configuration change starts a new sequence, and a late old worker
cannot overwrite the new generation's state. Unrelated worker or event tuning
keeps the position. Every attempted candidate receives fresh discovery, purity,
age, active-reference and identity checks; prior attempts authorize nothing.
An expired allowance before the first attempt spends no turn. The selection
reports incomplete coverage whenever discovery or a survey is incomplete.

Discovery itself still restarts with its existing 30-second, 50,000-directory,
65,536-entry-per-directory and depth limits. This change gives fair survey turns
only to targets that discovery reaches; it does not prove progress beyond a
repeatedly truncated discovery prefix or interrupt a blocked filesystem call.
Real-filesystem tests reduce the entry allowance to cover a large first target,
independent roots, successive successful nominations, new protection markers,
new activity and impurities, root replacement, and configuration generations.
