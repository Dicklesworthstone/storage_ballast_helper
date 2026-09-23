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
only a subset of roots, no longer forgets those continuations. Checkpoints retain
the original `root` and `after` fields and add the other unfinished roots; older
checkpoints still load. Completing a root removes its continuation, and a forced
reset clears every root's progress. Continuation storage scales with the number
of unfinished roots, not the number of children in any root.

Reading a page is not completed work. A partially examined final page retains
its last examined name. Failed enumeration invalidates earlier completion
proofs and preserves existing progress when the daemon yields to another root.
A cloned cursor owns independent page evidence, so budget rewinds cannot share
mutable completion state. Page evidence is neither persisted nor included in
progress equality: a read alone does not trigger a checkpoint write.

## Scope and tests

Enumeration must still inspect the whole directory to find the smallest names
in an unspecified order. This is not an I/O deadline or universal scan-latency
guarantee. Newly created names before a resume point are picked up on the next
completed sweep. Work inside a single depth-one entry still follows the daemon's
existing nested traversal and budget policy. Candidate scoring, protection,
pressure thresholds, and mutation policy are unchanged. This does not claim to
fix the separately observed macOS candidate-discovery fixture failures.

Existing selection and checkpoint tests remain. Twelve additional tests execute
the daemon's page/advance/completion sequence across capped and exactly-full
pages, multiple roots, alternating mount requests, repeated restarts, partial
pages, enumeration failures, independent rewind clones, legacy checkpoints,
forced resets, disappearing tails, and changing enumeration order.
