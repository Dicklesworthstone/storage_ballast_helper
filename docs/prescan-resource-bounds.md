# Bounded-memory, resumable pre-scan pages

The pre-scan cursor previously collected every depth-one entry in a scan root,
sorted the entire collection, removed the already-visited prefix, and only then
truncated it to `ROOT_ENTRY_CAP`. Page selection now filters the resume prefix
while enumerating and retains only the smallest `ROOT_ENTRY_CAP` remaining paths
in a max-heap. A smaller name encountered late replaces the largest retained
name; sorting reuses the heap allocation. Retained names are bounded throughout
selection, independently of the total number of directory entries.

## A full page is not a completed root

Selection now also records whether enumeration saw more eligible names than fit
in the page. The daemon's existing `entries_to_visit`, `advance`, `complete_root`
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
A cloned cursor owns independent page evidence, so budget rewinds cannot share
mutable completion state. Page evidence is neither persisted nor included in
progress equality: a read alone does not trigger a checkpoint write.

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
in an unspecified order. This is not an I/O deadline or universal scan-latency
guarantee. Newly created names before a resume point are picked up on the next
completed sweep. Work inside a single depth-one entry still follows the daemon's
existing nested traversal and budget policy. Candidate scoring, protection,
pressure thresholds, and mutation policy are unchanged. This does not claim to
fix the separately observed macOS candidate-discovery fixture failures.

Existing selection and checkpoint tests remain. The paging tests execute the
daemon's page/advance/completion sequence across capped and exactly-full pages,
multiple roots, alternating mount requests, repeated restarts, partial pages,
enumeration failures, independent rewind clones, legacy checkpoints, forced
resets, disappearing tails, and changing enumeration order.

`prescan_cursor::checkpoint::tests` adds restart encoding, corruption, resource
bounds, FIFO/symlink refusal, concurrent publication, owner permissions, failed
publication and parent-replacement cases. `core::path_serde::tests` covers the
candidate index's mixed-name persistence, failure cooldown boundary, revocation,
identity replacement and malformed-byte fallback. Its arbitrary-byte property
checks representation round-trips, not filesystem filename admission: APFS and
Linux filesystems need not admit the same names. Native platform execution is
still required to qualify the filesystem paths.
