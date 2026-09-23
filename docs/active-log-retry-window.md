# Active-log recovery after truncation

Truncation preserves the inode, not a non-append writer's file offset. A writer
that resumes at its previous offset can recreate a large logical file around a
small fresh tail. The allocation-based size gate remains necessary, but the
truncator now also has a bounded recovery window for repeated operations.

## Distinguish refills from ambiguous regrowth

A successful truncation records its pre-truncation logical size and completion
time for sixty seconds. A repeat still passes the configured size and age gates.
Within that window, it may proceed immediately when either its logical length
has grown by at least the configured minimum beyond the previous size, or a
bounded prefix read finds nonzero data at the beginning of the file. The latter
keeps ordinary text logs that genuinely refill actionable, including repeated
pressure sweeps. Otherwise it reports `RecentTruncation` and retains the bytes.

This is a recovery heuristic, not proof of a writer's append mode or of how much
new application data a logical gap contains. A zero-prefix log or an unreadable
prefix can be deferred for the remaining window. The prefix read is at most
4096 bytes and must come from the inspected inode; no log contents are emitted
in diagnostics. The first truncation does not gain a read-permission requirement.
After the window expires, normal size and age eligibility applies again. Skipped
or failed retries do not slide the previous completion time.

## Coordinate concurrent sweeps

An in-process reservation permits only one admitted operation on a tracked file
identity at a time. The shared table lock is released before filesystem I/O.
Metadata is refreshed after admission so a preceding sweep's old size cannot be
credited again, nor used to authorize truncating a now-small or freshly modified
refill. Failure or early return releases the reservation and restores the old
recovery record; success records its completion time after the mutation.

Tracking uses device/inode and birth time when available, with a path-qualified
identity when birth time is unavailable. Different files remain independent.
At most 4096 identities are retained; expired records are reclaimed before
refusing additional identities, without evicting active reservations or live
windows. This is process-local coordination, not a cross-process lock or a
filesystem I/O deadline. Concurrent application writers remain outside the
reservation protocol.

Dry runs report potential reclaimable bytes without consulting or changing
failure or success history. Allocation-based accounting, no-follow opens, inode
checks, existing failure backoff, configured minimum sizes and ages, and the
pressure-driven age bypass remain in force. Deferred attempts report no newly
reclaimed bytes.

Seventeen new tests cover window boundaries, non-sliding retries, delayed
completion, bounded identity storage, independent files, live non-append
writers, immediate text refills, new-tail admission, failed mutation, dry runs,
replacement identities, prefix identity checks, and size/age changes at the
reservation boundary. Existing pressure and live-writer regressions are retained.
