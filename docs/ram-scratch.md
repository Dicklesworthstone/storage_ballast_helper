# Host RAM-scratch headroom

`sbh check --ram-scratch` is a read-only Linux diagnostic for occupied tmpfs
space in relation to host RAM and swap. It includes `/tmp`, `/dev/shm`, `/run`
and visible `/run/user/<uid>` mounts **without adding any deletion roots**.

```sh
sbh check --ram-scratch
sudo sbh --json check --ram-scratch --ram-scratch-timeout-secs 30
```

Root may improve process and directory visibility, but is not a guarantee of a
complete scan across namespaces. This mode does not load daemon configuration,
start services, modify process state, create activity logs or compression
journals, or change existing cleanup policy. Ordinary path/space/prediction
checks are separate and cannot be combined with `--ram-scratch`.

## What is measured

The report sums **occupied filesystem blocks**, not the configured sizes of
tmpfs mounts. Bind aliases share a filesystem ID and contribute only the largest
observed usage for that filesystem; all visible mount names remain in the report.
Snapshots are not atomic across mounts or processes.

Warnings are additive reasons in one host assessment:

- Occupied tmpfs exceeds half of host RAM.
- Less than 10% of nonzero configured swap is free, and occupied tmpfs exceeds
  the visible process VmSwap sum. Incomplete process visibility produces a
  separate uncertainty reason instead of claiming this comparison is complete.
- `/run` or an immediate numeric `/run/user/<uid>` mount holds at least 4 GiB,
  or has less than 10% available space while occupied.

Process VmSwap does not account for shmem swap. These comparisons identify risk,
not the exact owner or cause of swapped pages. `nominal_ram_plus_swap_bytes` is
reported for context, **not as safe remaining allocation capacity**: zram itself
uses RAM, and host counters do not establish a container's cgroup headroom.
Unmeasurable ramfs occupancy or missing mount/process observations is explicit.
Large empty tmpfs limits do not by themselves generate a warning.

## Top-entry diagnostics

On a warning, the command samples top-level entries on occupied mounts using
metadata-only, descriptor-relative traversal. It reports numeric owner UID,
observed allocated bytes, and hours since the newest observed mtime/ctime.
Restoring an old mtime does not hide a recent ctime. The displayed owner is that
of the top-level entry; descendants can have different owners.

Traversal does not follow symlinks, cross descendant mount points, read payload
contents, or open inputs for writing. Hard-linked inodes are counted only once
within a mount probe. Display strings are accompanied by `native_path_hex`.

There is no claim of a complete filesystem snapshot or reclaimable byte total.
Truncated, changed, inaccessible or aliased trees retain sampled sizes and have
unknown age. A mount with incomplete coverage reports `complete=false`; the
ranking is only among observed entries. Even a complete age measurement is not
proof of inactivity or permission to remove an entry.

Defaults are 10 seconds shared by host collection and attribution, 20,000 total
attribution directory entries, depth 8 below each top-level child, and 10 results
per mount. Remaining time and entry budgets are shared across mount probes so a
large `/tmp` does not monopolize them. Override with:

```sh
sudo sbh --json check --ram-scratch \
  --ram-scratch-timeout-secs 30 \
  --ram-scratch-max-entries 50000 \
  --ram-scratch-depth 12 --ram-scratch-top 20
```

Hard limits are 60 seconds, 100,000 attribution entries, depth 32, and 50 results
per mount. Process collection separately attempts at most 16,384 processes and
256 mount paths by default. Deadlines are cooperative; kernel I/O can overrun
an in-flight call. Healthy host assessments avoid directory attribution work.

JSON uses `sbh.ram_scratch.v1`. Exit 0 is healthy or explicitly unsupported,
1 is a complete warning (or invalid runtime limits), 2 is a collection/output
failure, and 4 is incomplete host or attribution evidence. A warning remains
visible with exit 4; partial coverage must not be interpreted as healthy.

## Remaining integration

This command and the shared assessment do not yet schedule periodic daemon
warnings or change JSONL mirror routing. The shared
`ram_log_destination_healthy` predicate is available for that integration, but
merely adding the predicate does not stop a daemon from using its existing RAM
fallback. No new deletion paths or automatic cleanup actions are introduced.
