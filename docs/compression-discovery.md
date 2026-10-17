# Discover cold compression candidates

Use the read-only directory selector to find cold files without building a shell
argument list or following directory symlinks:

```sh
sbh --json compress --discover -- /data/cold-archive
```

This is **metadata discovery**, not a compression-ratio estimate or permission
to rewrite every reported file. Alone it never calls the compression mutation
backend, creates a journal, deletes files, changes service policy, or enables
automatic compression. `--discover` conflicts with `--recover-journal`. Native
discovery currently requires Linux x86-64/AArch64 with `openat2`; unsupported
targets report an unsupported no-op.

## Compress what discovery selected

Adding `--apply` with both consents runs the explicit-file executor on exactly
the selected candidates, in the same pass:

```sh
sudo sbh --json compress --discover --apply --allow-zstd-feature --quiescent \
  -- /data/cold-archive
```

Every apply check in `btrfs-compression.md` still runs, including the open,
executing and mapped-file vetoes, shared-extent exclusion, journal intent and
content verification. On top of them, each file is refused (outcome `failed`,
nothing rewritten) when its device, inode, size, mtime, ctime or link count
differ from what discovery recorded, or when its root was replaced, it left the
root, or it gained Git ancestry. Root and Git checks repeat between chunks.

The JSON adds an `apply` object with the ordinary `sbh.compression.v1` report
and its `activity_delivery`; `read_only` is false and `mutation_attempted`
reports whether any file was rewritten. An empty selection creates no journal.
Discovery limits still bound the selection, so a budget stop or `--max-files`
continuation returns exit 4 even when every selected file compressed: resume
with `--after-hex` and the same roots. Otherwise the exit code is the apply
pass's own.

## Selection and limits

Supply 1..32 real directory roots. Discovery canonicalizes and pins them,
deduplicates overlapping roots, enumerates each directory in native pathname
order, refuses descendant mount crossings and symlinks, and prunes protected or
leased trees. It reuses the existing configured protection patterns, marker
checks and sacred-path catalog. Hard-linked files, young/future-dated files,
small files and already-compressed suffixes are excluded.

### Git content is excluded, including untracked build outputs

Discovery and explicit-file execution now share a fresh, metadata-only Git
ancestry check. It excludes whole worktrees (tracked and untracked files), `.git`
internals, linked worktree/submodule gitfiles, and bare or relocated Git
administrative directories identified by `HEAD` plus `objects`, `refs`,
`packed-refs`, or `commondir`. A malformed, empty, or dangling `.git` marker is
also a conservative veto. The check does not invoke Git, parse configuration,
follow a gitfile target, or read object contents. Arbitrary external object
stores with none of these markers are not discovered by this layout heuristic.

Repository directories are pruned before enumeration and counted under
`discovery.skipped.git_repository`; a count is a pruned visit, not the number of
files inside it. An explicit root already inside a repository is excluded too.
Marker/ancestry inspection errors produce an incomplete scan, not negative Git
evidence. Ancestry work is bounded at 256 directories per check.

The executor repeats this veto before opening an input for rewrite and between
chunks. A retained library selection also rechecks it through `validate_file`
and `validate_scope`, so adding a Git marker after discovery cannot make the old
selection bypass the veto. These checks are observations, not a repository
creation lock. Quiescence and every existing executor protection remain required;
there is no compression force override, including for ignored worktree files.

`--min-size-bytes`, `--min-age-secs`, `--max-files`, and `--max-bytes` use the
existing compression defaults and safety floors. Logical bytes limit selected
work and are **not** bytes that can necessarily be reclaimed. Selection does
not yet check live process references or physical extents; ordinary file preview
and apply still perform those checks.

Traversal defaults are 32 levels below each root, 100,000 directory entries,
4096 directories and a separate 30-second cooperative discovery deadline.
Override these using `--max-depth`, `--max-entries`, `--max-directories`, and
`--discovery-timeout-secs`. Hard limits reject depths over 64, entry limits over
1,000,000, directory limits over 8192, and discovery deadlines over 60 seconds.
`--timeout-secs` remains the explicit-file execution/recovery budget; it is not
the directory discovery deadline. An in-flight filesystem call may exceed a
cooperative deadline.

The JSON schema is `sbh.compression.discovery.v1`. It reports canonical roots,
entries/directories examined, selected count and logical bytes, grouped
exclusions, completion status, and any stop reason. Each candidate carries a
lossy display `path` and an exact `native_path_hex`. Display strings must not be
used to reconstruct unusual native filenames.

A budget stop or incomplete read produces exit 4 and `discovery.complete=false`,
not an empty successful scan. Invalid input produces exit 1; a root/config
inspection failure produces its corresponding error report. A partially read
directory contributes no selected children: the selector must read and sort the
whole directory before treating it as an ordered prefix. Even a completed walk
is not a filesystem snapshot; files may change afterwards.

## Continue a file-count-limited selection

When `--max-files` stops an otherwise complete sorted prefix, JSON includes
`discovery.resume_after_hex`. Continue after that exact native pathname:

```sh
sbh --json compress --discover --max-files 128 \
  --after-hex TOKEN_FROM_PREVIOUS_REPORT -- /data/cold-archive
```

Use the same roots and selection filters. A continuation outside those roots is
rejected. A continuation is only a skip hint; it never authorizes mutation or
suppresses fresh protection checks. Rewind by omitting it to reconsider earlier
files after the filesystem or policy changes. Entry/depth/time failures do not
invent a continuation past unexamined work.

The library selection retains discovered file stamps and pinned roots; the
executor's `validate_file` and `validate_scope` calls are the discovered-apply
checks above. The daemon runs the same discover-then-apply pass when
`[compress]` is enabled (`btrfs-compression.md`, Daemon tier). Explicit-file
journal explanations are documented separately in `compression-explain.md`.
