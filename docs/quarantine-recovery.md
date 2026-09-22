# Quarantine recovery and integrity

Quarantine retains the only copy of an approved cleanup candidate until undo,
expiry, or a pressure drain. Moving it is now a write-ahead transaction:

1. Reserve a previously unused decision directory and write an owner-only
   `<decision-id>.pending` manifest. Sync the manifest, store directory, and its ancestor links
   before moving the candidate.
2. Move the candidate with an atomic no-replace rename on Linux and macOS.
3. Sync the source and holding directories, publish `<decision-id>.json`,
   and sync the store directory.

An interrupted move with a payload and a valid pending manifest remains visible
in quarantine inventory, `sbh undo`, and pressure drains after restarting. A
pending manifest with no held payload is **not** reclaimable space and never
authorizes deletion of its original path. Retrying quarantine can clear an
abandoned reservation only when the original path and device/inode still match,
no payload was moved, and the reserved directory is empty. Otherwise preserve
the record for investigation; never invent a replacement manifest or delete the
original. Filesystems that cannot supply atomic no-replace rename are refused;
there is no overwrite-capable fallback inside quarantine.

Once the payload has moved, a finalization failure is reported on stderr and the
recovery metadata is retained. It is not returned as a quarantine failure that
could cause the executor to delete a newly recreated original. A failed sync
means power-loss durability cannot be promised; it does not erase the available
recovery record.

Undo never overwrites a rebuilt original, an existing suffixed destination,
or a dangling symlink, even if the destination appears concurrently. The
`--force-suffix` option chooses an alternate name; it does not authorize
clobbering that name. File names are preserved without lossy UTF-8 conversion.
When undo moved the payload but stopped before removing its manifest, retrying
undo recognizes the exact inode at the original or suffixed destination and
finishes bookkeeping without moving it again, including pending-only manifests.
Explicit undo can also cancel an unmoved reservation by recognizing that the
original inode is still in place. A rebuilt file with a different identity is not treated as a completed restore. Normal purge also syncs the
payload removal before discarding the manifest.

Purge and undo validate the manifest's id, containing directory, payload path,
and recorded device/inode. They refuse substituted payloads and symlinked entry
directories. A purge removes only the approved payload, not unrelated siblings
placed in its decision directory. An already missing payload contributes zero
reclaimed bytes. Malformed manifests are not silently treated as valid deletion
instructions; direct record/undo/purge requests fail, while a bulk inventory can
skip invalid records and continue processing healthy entries.

Mutating store operations use a non-blocking, process-scoped directory lock. No
lock file needs allocation on a full disk, and process exit releases the lock.
A concurrent operation is refused rather than waiting indefinitely. The
executor's existing policy for an unavailable quarantine is unchanged.

Implementation: `src/scanner/quarantine.rs` and
`src/scanner/quarantine/safety.rs`. Regression tests cover interrupted moves,
metadata-write refusal, duplicate ids, path substitution, identity replacement,
concurrent-operation refusal, no-clobber undo, and pressure draining recovery
records. These checks do not claim protection against every possible hostile
concurrent filesystem namespace change.
