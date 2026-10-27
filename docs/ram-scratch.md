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

## Ordinary path preflight checks

On Linux, `sbh check PATH` automatically collects a fresh host RAM-scratch
assessment when PATH is on tmpfs or ramfs and its ordinary space checks pass.
A tmpfs size limit can leave plenty of free blocks while the host has exhausted
swap; that condition now prevents a successful preflight. Disk-backed paths do
not trigger host mount or process collection.

```sh
sbh check /tmp --need 5G
sbh --json check /dev/shm --target-free 15
```

The same warning predicates described below apply. A complete warning exits 1
with reason `ram_scratch_pressure`; missing, inaccessible, or bounded-out
evidence exits 4 with reason `ram_scratch_incomplete`. A disappeared target
mount or unmeasurable ramfs occupancy is incomplete, never healthy. JSON includes
the fresh `ram_scratch` report. `--allow-unprotected` applies only to the daemon's
reclaim capability and does not bypass the RAM checks.

A **positive explicit `--need`** on Linux tmpfs or ramfs additionally checks the
requested bytes against a fresh host `MemAvailable` reading and every finite
`memory.high` / `memory.max` boundary in the caller's visible cgroup-v2 ancestry.
Each ancestor uses its **own** `memory.current`; the tightest observed remaining
headroom wins. A healthy host and a large tmpfs size limit cannot override a
small process or ancestor allowance. This comparison uses the requested byte
count directly, with no additional percentage reserve. Swap is neither added to
available RAM nor required to accommodate the request; disabled or exhausted
cgroup swap alone does not reject otherwise adequate RAM headroom.

`memory.high` is a reclaim/throttling boundary, while `memory.max` is a hard
limit. The report distinguishes them. Observed headroom is the nonnegative
difference between the boundary and the scope's current charge; it does not
assume that charged pages can be reclaimed. Exceeding it exits 1 with reason
`ram_write_headroom`. Unreadable, unstable, malformed or bounded-out memory
evidence exits 4 with reason `ram_write_admission_incomplete`. Incomplete evidence
from either RAM check takes precedence over a known warning, and both reports
remain available. A complete healthy RAM-backed check exits 0 and remains silent
in human mode.

JSON adds `ram_write_admission` separately from the host `ram_scratch` report:

| Field | Meaning |
| --- | --- |
| `schema` | `sbh.ram_write_admission.v1` |
| `requested_bytes` | The positive explicit `--need` value |
| `host_available_bytes` | Fresh host `MemAvailable`, or null if unavailable/inconsistent |
| `process_boundary` | Tightest finite visible boundary, or null; includes `scope`, `boundary`, `boundary_kind` (`throttle` or `hard_limit`), `current_bytes` and `limit_bytes` |
| `observed_headroom_bytes` | Minimum of host availability and observed process headroom; null when evidence is incomplete |
| `limiting_factor` | `host_available`, `process_boundary`, or null when incomplete |
| `complete`, `issues`, `exit_code` | Evidence status, details and this admission result |
| `read_only`, `scope` | Observation-only contract and coverage |

A null `process_boundary` means no finite boundary was observed only when
`complete` is true. An unreadable hierarchy also produces null, with `complete`
false and a reported issue. No request, `--need 0`, and disk-backed targets do not
perform this additional memory-headroom query; their `ram_write_admission` is
null where the field is emitted.

This preflight reads host counters and process status files, with a cooperative
10-second deadline, at most 16,384 processes and 256 RAM-backed mount paths.
It does not walk scratch directories, consult an old daemon warning, delete or
relocate files, or raise a mount's daemon pressure level. The additional byte
admission reuses the bounded cgroup observer described below, with a separate
100 ms cooperative deadline, and reads only the memory boundaries relevant to
RAM. A successful check is an observation, **not a memory reservation or an OOM
guarantee**: charges and limits can change immediately, and cgroup namespaces can
hide further enforcing ancestors. Use `--ram-scratch` separately for the fuller
host report and optional top-entry attribution.

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

Defaults are 10 seconds shared by host collection and attribution, 2,000,000
total attribution directory entries, depth 8 below each top-level child, and 10
results per mount. Remaining time and entry budgets are shared across mount
probes so a large `/tmp` does not monopolize them. Mounts are probed smallest
first, so what a small runtime mount leaves unused passes to the fuller ones
instead of each mount being held to an even share. Override with:

```sh
sudo sbh --json check --ram-scratch \
  --ram-scratch-timeout-secs 30 \
  --ram-scratch-max-entries 4000000 \
  --ram-scratch-depth 12 --ram-scratch-top 20
```

Hard limits are 60 seconds, 5,000,000 attribution entries, depth 32, and 50
results per mount. Process collection separately attempts at most 16,384 processes and
256 mount paths by default. Deadlines are cooperative; kernel I/O can overrun
an in-flight call. Healthy host assessments avoid directory attribution work.

JSON uses `sbh.ram_scratch.v1`. Exit 0 is healthy or explicitly unsupported,
1 is a complete warning (or invalid runtime limits), 2 is a collection/output
failure, and 4 is incomplete host or attribution evidence. A warning remains
visible with exit 4; partial coverage must not be interpreted as healthy.

## Periodic daemon warnings

On Linux, receiving the daemon-start event arms a report-only observer with a
30-second startup grace. A new sample is due five minutes after the previous
probe is consumed. CLI preview, discovery, recovery and ordinary one-shot logs
do not emit that lifecycle event and do not arm the observer.

Collection runs in at most one independent read-only worker. It retains no
logger producer handle, never scans on the monitor/executor or logger thread,
and publishes through the existing dual logger into JSONL and SQLite when
available. It does not open a second activity writer. Admission closes with the
normal logger shutdown boundary; a blocked probe is detached rather than waited
on or replaced. Its in-flight kernel operation may finish later. Stalls become
incomplete observations, not fresh healthy reports or a respawn loop.

Periodic work uses smaller limits than the operator command: two cooperative
seconds for up to 4096 process statuses and 128 mount paths, and five seconds
shared with optional attribution. On warnings, attribution visits at most 16
unique occupied filesystems, 1,000,000 entries total, depth 4, and retains three
observed entries per mount. Omitted or incomplete work is explicit. These limits
are not a hard real-time guarantee and do not establish a filesystem snapshot.

`SBH-RAM-SCRATCH` is one combined warning, not one event per mount or entry.
Unchanged warnings repeat at most every 15 minutes; newly observed risk reasons
can be reported at the next sample. Reasons remain remembered across threshold
flapping until a complete healthy sample. `SBH-RAM-SCRATCH-INCOMPLETE` identifies
missing evidence or a stalled/failed probe. Missing evidence cannot clear an
existing warning. A complete healthy sample emits one recovery event, then
healthy observations are silent.

The versioned `sbh.ram_scratch.observation.v1` JSON object in activity `details`
contains the assessment, collection timestamp, sampled entry ownership/age,
coverage flags and scope limitations. Payloads exceeding 128 KiB use an explicitly
truncated summary with `complete=false`. Generic deletion size/decision fields
remain unset; no reclaimed bytes or cleanup authority are invented. Logging is
best-effort; RAM-route refusal and its buffered-record tradeoff are described
below.

## RAM-backed log destination protection

The JSONL writer checks fallback and mirror destinations independently of the
five-minute report-only observer. A RAM-backed destination requires at least
10% of host RAM available, at least 20% of its filesystem available, and at least
10% of configured swap free. Having no configured swap is not itself a refusal.
An empty tmpfs does not override low host RAM. Missing filesystem identity,
unreadable or inconsistent RAM/mount counters, and a read-only RAM filesystem
refuse admission rather than being interpreted as healthy. A verified disk-backed
fallback is not subject to the RAM-headroom policy. The existing `Start` margin
used when the daemon requests a mirror is 15% host RAM, 15% swap and 25% filesystem
headroom; the `Keep` check uses the lower floors above.

On Linux, a host-healthy RAM route also needs headroom within **this process's
visible cgroup-v2 hierarchy**. The guard observes `memory.current` against each
finite `memory.high` and `memory.max`, separately for the leaf and every visible
ancestor. It never compares a parent's limit with a child's smaller usage.
Each finite constraint requires 10% remaining for `Keep`, or 15% for `Start`.
A zero memory limit or usage beyond a finite limit refuses the route.

Finite, nonzero `memory.swap.max` is checked against that scope's
`memory.swap.current` with the same percentage margin. A disabled swap allowance
(`memory.swap.max=0`, with zero usage) is not itself a refusal. Unlimited values
and kernels without both swap-accounting files add no swap constraint. Swap is
never added to a RAM allocation allowance, and the independent host swap check
still applies.

The cgroup observer reads only kernel metadata. It verifies procfs/cgroup2 file
identity, opens cgroup path components without following symlinks, and rejects
traversal, malformed records and changed membership, mount tables or limits.
A missing memory-controller interface needs evidence that its parent has not
enabled the controller; partially missing interfaces are unknown, not unlimited.
Only a visible hierarchy mounted from its root is accepted: a bind-mounted
subtree cannot stand in for hidden enforcing ancestors. Legacy cgroup-v1 memory
controllers, missing unified membership and unreadable hierarchy evidence refuse
RAM logging rather than silently falling back to host-only admission. This does
not disable the primary disk route or a verified disk-backed fallback.

One cgroup observation has bounds of 32 ancestor scopes, 512 logical file reads,
3 MiB of aggregate input and a 100 ms cooperative deadline, with smaller per-file
limits. Component opens and metadata verification are additional bounded work,
not included in the logical-read count. The deadline does not interrupt a blocked
kernel operation. Healthy/absent observations are not cached between checks;
recovery is evaluated from new evidence. Filesystem-only platform overlays
forward the same local constraint query instead of discarding it.

Checks cover opening, recovery, ongoing writes, explicit flush/fsync, idle ticks,
mirror shutdown, and writer destruction. Memory and filesystem capacity are read
at admission; the platform's existing bounded mount-table cache is reused. These
checks do not enumerate processes or perform directory attribution on the logger
thread. `sbh check --ram-scratch`, its host report schema and the periodic
report-only observer remain host-wide diagnostics, not cgroup reports.

When a mirror becomes unsafe, mirroring stops and the primary continues. When an
active fallback becomes unsafe, subsequent records use stderr. Pending buffers
for the refused route are discarded **without flushing into the RAM filesystem**,
including during shutdown. This intentionally prioritizes headroom over retaining
those pending fallback records; it is not a lossless delivery guarantee. A
`[SBH-JSONL] fallback/mirror refused` diagnostic is emitted at most once every
30 seconds. Recovery can still reopen the primary regardless of fallback refusal.
The existing write-triggered recovery retry can reopen a healthy fallback, and a
mirror can be enabled again when requested after headroom recovers.

The fallback and mirror retain their 16 MiB, non-rotating cap. A single oversized
record cannot bypass that cap on an empty file: it remains eligible for the
primary but is skipped by the mirror, or uses stderr when already on fallback.
Failed truncation stops the affected route instead of allowing unbounded appends.
Rotation failure applies the cap to the newly selected fallback too. Handover
closes the mirror before opening the same file as the fallback, avoiding two
buffered writers and duplicate handover records.

These are best-effort observations, not memory reservations or atomic filesystem
snapshots. Cgroup namespaces can hide further enforcing ancestors, charges and
limits can change after a check, and concurrent path/mount replacement is not
prevented. The guard covers JSONL fallback and mirror routes, not an operator-
selected primary on RAM, SQLite, or storage chosen by a stderr consumer. No
cgroup controls are written, no reclaim is requested, and no new deletion paths
or automatic cleanup actions are introduced.
