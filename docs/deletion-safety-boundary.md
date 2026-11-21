# Protection at the deletion boundary

A scored candidate and a public `DeletionPlan` are inputs, not authorization to
bypass the receiving executor's safety policy. The planner, batch preflight,
and final mutation recheck share admission in
`src/scanner/deletion/eligibility.rs`.

## Files are protected too

Individual files pass the sacred catalog's direct path and filename rules.
This covers database files such as `*.db`, `*.sqlite`, and `*.sqlite3`, as well
as operator-configured exact paths, globs, and descendants of protected paths.
Previously the executor's sacred-containment call was guarded by `is_dir()`,
so a prebuilt file candidate could bypass those rules even though a directory
containing the same file was refused.

Directories retain the bounded recursive containment check and its scan-cost
accounting. A candidate that reaches mutation gets a fresh content check after
authorization callbacks and filesystem probes: an unchanged directory inode
does not prove that nobody added a repository or protected content underneath
it. Positive sacred-path evidence can be reused to refuse a candidate; an
earlier empty walk cannot authorize its later removal.

The deep repository/protection walk must inspect every entry it reaches within
its directory budget. Directory-open, iteration, entry-type, and Git-file read
errors produce `containment_incomplete`; cleanup retains the entire candidate
for a later pass. A disappearing entry is incomplete evidence too. This hold
applies before both unlink and quarantine, including the final recheck after
authorization. A readable, empty cache marker can still be distinguished from
a repository; an unreadable marker cannot.

## Ancestor markers are live instructions

Before mutation, the executor checks `.sbh-protect` in the candidate directory
and its ancestors, or in the parent and ancestors of a file candidate. This
also catches markers added after the candidate was scored or planned. Marker
checks do not read their contents: any marker entry, including a dangling
symlink, protects the subtree. Unexpected filesystem errors fail closed.

Existing paths are canonicalized for these checks, so accessing a candidate
through a symlinked parent cannot hide the real object's protected ancestors.
No unprotected verdict is cached between planning and mutation. The existing
symlink, filesystem-identity, source-tree, lease, and open-file checks remain.
These path-based rechecks reduce stale-evidence gaps; they do not claim complete
protection against every concurrent hostile namespace change.

Both irreversible removal and quarantine honor these rules. Emergency Review
consent does not override a hard veto, category suspension, or a protection
marker. A quarantine failure retains the candidate rather than silently
selecting irreversible removal; see `docs/quarantine-recovery.md`.

Quarantine also carries the executor's verified source identity into its
transaction. It binds the source parent and checks that identity before
creating or locking the store, then checks the same object after preparation
and before moving it. Replacing the source while the store is being prepared
cannot silently substitute a different payload. The final identity check and
rename remain separate syscalls.

## Process absence is fresh for each deletion batch

Opening an existing object file or changing a process's working directory does
not change the artifact root's modification time. A previous open-file sweep
therefore cannot establish that a later batch's candidates remain unused,
even when their directory timestamps have not changed.

On Linux, a recent cached sweep can refuse candidates it positively observed
in use. A batch with any candidate that would otherwise pass obtains a fresh
process sweep; incomplete visibility holds the batch. The sweep is shared
within that batch, rather than repeated for each candidate. This closes reuse
of stale absence between batches, while the existing leases and final identity
checks continue to guard the later mutation boundary.

## Direct removal stays within verified directory descriptors

Irreversible cleanup and quarantine purge share the descriptor-relative remover.
The executor compares the exact final stat result with the scanner identity,
then binds that root to an opened parent before removal. A parent alias such as
macOS `/tmp` is resolved once; subsequent child lookups and mutations use the
opened directory and a single basename.

The root must be a regular file or directory on its parent's filesystem.
Descendant directories are opened without following symlinks and checked against
their observed identities. Linux additionally requires `openat2(NO_XDEV)`, which
rejects same-device bind mounts as well as device changes; an unavailable or
blocked `openat2` fails closed. Other Unix systems use no-follow opens and device
checks. Symlink children are unlinked as entries without opening their targets.

Recognized regenerable Go and Cargo caches may add owner traversal/write bits
through verified directory handles. File permissions are never widened: deleting
one cache name must not change the permissions of an external hardlink. A
directory that cannot be opened for reading remains a refusal, including an
unreadable `0000` directory; there is no pathname-based chmod fallback. Ordinary
artifacts and quarantine purges retain their conservative permission policy.

Direct removal allocates no store or recovery record, preserving emergency
operation on a full disk. It may remove earlier children before discovering a
boundary or error, and reports success only after removing the root. This is
descriptor confinement with identity rechecks, not an atomic whole-tree
transaction: a last-moment rename after a check can still affect the originally
opened object, and the final identity check and unlink are separate syscalls.

## Standalone rustc incremental caches

A standalone `rustc -C incremental=DIR` cache does not need to be named
`incremental` or live inside a Cargo `target` directory. The scanner recognizes
its compiler-specific crate/session layout and versioned `RSIC` metadata
headers. Every entry must be accounted for; unknown contents, symlinks,
incomplete reads, missing session locks, or exhausted inspection budgets keep
the cache. Each proof is bounded to 200,000 entries and two seconds of cooperative
inspection. Generated names alone are not sufficient evidence. Ordinary object
files may be hardlinked, but session lock files must be empty and have one link.

The executor renews that proof and acquires nonblocking exclusive locks on every
observed session lock, including orphan locks. A shared compiler reader or an
exclusive writer keeps the entire cache. Entries changed in the last ten
seconds are also retained: rustc creates a new lock file before locking it.
The existing age, open-reference, source-tree, lease, and protection-marker
rules still apply. Linux and macOS are the supported lock implementations;
other platforms cannot authorize this new removal path.

The locks stay held through direct removal. Holding old session locks cannot
stop a compiler from creating a different session with a new lock, so the
descriptor-relative remover also checks a positive inventory of relative paths,
devices, inodes, and entry types before descent and immediately before unlink.
An unlisted or replaced entry stops removal without touching that entry. Some
previously approved children may already have been removed; an interrupted
operation does not report the whole cache's bytes as reclaimed.

This proof requirement is retained across planning, interactive confirmation,
and live authorization callbacks. A stale or manually constructed candidate
cannot bypass the compiler checks by supplying an ordinary `target` label.

Whole-cache quarantine is refused with `incremental_quarantine_unsupported`.
An atomic rename of the root cannot exclude a newly created, independently
locked session, and a requested recoverable cleanup never falls back to unlink.
Pressure cleanup and emergency cleanup can use guarded direct removal. To
review an explicit manual cleanup, use
`sbh clean PATH --no-quarantine --dry-run` before choosing direct removal.
A quarantine refusal does not place the candidate in a repeat-deletion backoff,
so a later direct pressure pass can reconsider it immediately.

## Regression coverage

Unit tests beside the admission helper exercise the public batch and checked
per-item APIs with deliberately prebuilt plans. They cover builtin database
file rules, exact and glob file protection, protected-directory descendants,
markers introduced after planning for both files and directories, aliased
parents, dangling markers, and markers introduced between preflight and the
mutation helper. Positive controls prove an unprotected file still unlinks or
round-trips through quarantine and undo. These tests supplement the public-API
integration tests in `tests/deletion_boundary.rs`.

Executor regressions also add nested protection markers and repositories from
the authorization callback, after preflight has already accepted the target.
Both unlink and quarantine retain those targets. A separate retained-descriptor
case reopens an existing artifact without changing its root timestamp after a
previous empty process sweep, and verifies that the next batch keeps it.
Quarantine tests replace files and directories after admission and during
store preparation; stable controls still quarantine and restore successfully.
Containment regressions inject permission, disappearance, and I/O failures at
directory-open, iterator, and entry-type boundaries, and exercise unreadable
deep subtrees and Git files through the real filesystem. Refused candidates
retain their contents and never acquire a quarantine store.

Direct-removal regressions also cover captured-root replacement, parent replacement
before mutation, symlink substitution at descent/open checkpoints, leaf replacement
before unlink, stable parent aliases, external hardlink permissions, and filesystem
boundaries. Bind-mount fixtures require mount capability and report a skip when it
is unavailable; separate read-only Linux tests exercise existing mount boundaries
without attempting to remove system paths.

Standalone compiler-cache tests cover structural recognition, fresh and active
caches, shared and exclusive session locks held by a separate process, forged
and stale classifications, malformed metadata, non-session contents, symlinks,
and markers added after planning. Additional authorization and confirmation
tests preserve a cache that changes after admission. The confined-removal tests
introduce new sessions, replacement files, hardlinks under unapproved names,
and special files after the initial inventory, verifying that none inherits
permission from an approved parent. Quarantine and dry-run tests require an
explicit refusal with no fallback unlink or recovery-store allocation.
