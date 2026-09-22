# Bounded-memory pre-scan page selection

The pre-scan cursor previously collected every depth-one entry in a scan root,
sorted the entire collection, removed the already-visited prefix, and only then
truncated it to `ROOT_ENTRY_CAP`. That bounded the returned vector but not the
memory required to construct it. A root containing millions of temporary entries
could exhaust the scanner's memory before the cap took effect.

Page selection now filters the resume prefix while enumerating and retains only
the smallest `ROOT_ENTRY_CAP` remaining paths in a max-heap. A smaller name
encountered late replaces the largest retained name. Converting that heap into
ascending order reuses its allocation. Retained path count is bounded throughout
selection, independent of the number of names enumerated; path lengths and the
filesystem's directory iterator still contribute their own storage costs.

The selection result is identical to sorting all successfully enumerated names,
filtering names at or before the cursor, and taking the first page. Ordering uses
native `PathBuf` comparisons without lossy UTF-8 conversion. An enumeration error
is returned rather than hidden in a partial page. Scoring, protection, pressure
thresholds, and the cursor checkpoint format are unchanged.

## Scope

This bounds page-construction memory, not enumeration time. The complete root
still has to be enumerated to find the smallest names in an unspecified directory
order. It is not a benchmark speedup claim, a deadline guarantee, or a fix for the
separate pre-scan candidate-dispatch failures observed in macOS CI.

A full returned page is not proof that the root has been exhausted. Cursor callers
must resume after the last returned name rather than equating the page cap with
end-of-root. The daemon's current unconditional `complete_root` after consuming a
full page remains a separate caller-side limitation; this change does not claim
to fix that scheduling behavior.

Six additional tests cover adversarial enumeration order against a full-sort
reference, late-arriving smaller names, filtering before capping, multi-page
coverage when enumeration order changes, mid-enumeration errors, and byte-exact
Unix path ordering. Existing cursor, checkpoint, and resume tests are preserved.
