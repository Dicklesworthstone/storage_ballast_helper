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

Directories retain the existing bounded recursive containment check, including
its per-batch reuse and scan-cost accounting. The additional admission check
does not perform a second recursive directory walk.

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

## Regression coverage

Unit tests beside the admission helper exercise the public batch and checked
per-item APIs with deliberately prebuilt plans. They cover builtin database
file rules, exact and glob file protection, protected-directory descendants,
markers introduced after planning for both files and directories, aliased
parents, dangling markers, and markers introduced between preflight and the
mutation helper. Positive controls prove an unprotected file still unlinks or
round-trips through quarantine and undo. These tests supplement the public-API
integration tests in `tests/deletion_boundary.rs`.

Direct-removal regressions also cover captured-root replacement, parent replacement
before mutation, symlink substitution at descent/open checkpoints, leaf replacement
before unlink, stable parent aliases, external hardlink permissions, and filesystem
boundaries. Bind-mount fixtures require mount capability and report a skip when it
is unavailable; separate read-only Linux tests exercise existing mount boundaries
without attempting to remove system paths.
