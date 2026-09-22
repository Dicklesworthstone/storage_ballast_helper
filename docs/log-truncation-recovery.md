# Active-log reclamation under sustained pressure

The active-log truncator is a separate reclamation path for configured log files
whose writers keep file descriptors open. It truncates in place rather than
unlinking the file and leaving its blocks pinned by the writer.

## Failed attempts back off

The daemon's repeated calls now share a process-local failure history. A failed
candidate or invalid pattern cools down for sixty seconds measured from the end
of the failing operation. Repeated sweeps during that interval report
`FailureBackoff` in `skipped_with_reason`; they do not repeat the failed
operation or emit the same error through the report's `errors` list. Critical
pressure does not bypass this cooldown.

Independent paths continue to be processed. Duplicate and overlapping patterns
visit a candidate path only once per sweep, including dry runs. The history is
bounded to 4096 entries; at saturation, new attempts are deferred instead of
evicting live cooldowns and recreating a failure storm. Expired history is
removed in memory, without filesystem work. No history lock is held across I/O.

Dry runs bypass the cooldown and do not populate or clear it, so inspection
continues to show what would be reclaimed without changing the daemon's retry
schedule. History is intentionally process-local: a new process starts fresh.

This implements the truncator-backoff portion of `bd-1ar1`. It does not claim
completion of that bead's separate general message-template throttling or
sixty-minute production log-growth acceptance criteria.

## Mutation follows the inspected inode

The truncator compares the opened descriptor's device and inode to the file
inspected before opening. A replacement regular file or replaced parent directory
cannot redirect truncation to a different inode. The size and age gates run
again against descriptor metadata before `set_len(0)`, so a log that was shrunk
or refreshed during opening is reassessed. Leaf symlink refusal and nonblocking
open remain in effect. Platforms without stable file identity refuse mutation.

Future modification times count as fresh, not old, outside the existing
pressure-driven age bypass. These descriptor checks narrow stale-inspection
races; they do not make the entire filesystem operation atomic with respect to
all concurrent writers.

## Sparse holes are not reclaimed data

A writer without append mode retains its old file offset after truncation. Its
next write can create a huge logical file with only a few allocated blocks.
The size gate and byte estimate now use the smaller of logical size and
allocated bytes on Unix. Such a log no longer repeatedly qualifies solely
because of its holes, and those holes are not reported as bytes freed.

Byte totals saturate instead of overflowing. Reported bytes remain an estimate;
filesystem snapshots and other retention mechanisms can delay actual free-space
growth. The writer's inode and open descriptor survive successful truncation.

## Regression coverage

Unit tests under `src/scanner/log_truncator/` cover cooldown boundaries, slow
failures, bounded failure storms, dry-run isolation, independent healthy paths,
overlapping patterns, regular-file and parent replacement, refreshed/shrunk
inodes, future timestamps, sparse allocation accounting, and a live non-append
writer resuming after truncation. Failure timing is injected without sleeps;
identity and sparse-writer cases operate on real temporary files.
