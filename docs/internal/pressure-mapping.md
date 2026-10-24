# Memory Pressure Mapping

Bead: `bd-hqu2.6`

This note defines how `sbh` maps platform-native memory pressure signals into
the daemon behavior matrix. The important contract is:

> Cross-platform parity lives in behavior, not in identical native signals.

Linux and macOS expose different memory pressure surfaces. `sbh` preserves the
native signal details for diagnostics, then normalizes both platforms into the
same behavior rows: `Normal`, `Warn`, and `Critical`.

## Shared Model

The platform abstraction returns:

```text
MemoryPressure {
  level: Normal | Warn | Critical | Unknown,
  free_pages,
  used_pages,
  page_size_bytes,
  compressor_used_bytes,
  swap_total_bytes,
  swap_used_bytes,
  linux_psi_avg10,
}
```

The daemon policy layer then maps native memory pressure into
`BehaviorPressureLevel`:

| Native memory level | Behavior row | Rationale |
|---|---|---|
| `Normal` | `Normal` | No memory-specific throttling is needed. |
| `Warn` | `Warn` | Prefer less memory-heavy scans and safer cleanup choices. |
| `Critical` | `Critical` | Survival actions take priority; avoid broad traversal. |
| `Unknown` | `Warn` | Missing pressure data is not safe enough for `Normal`. |

Disk pressure is normalized independently:

| Disk pressure level | Behavior column |
|---|---|
| `Green` | `Normal` |
| `Yellow`, `Orange` | `Warn` |
| `Red`, `Critical` | `Critical` |

The dispatch table combines those two normalized values. For example, healthy
memory plus red disk can scan aggressively and release ballast, while critical
memory plus red disk uses definite-only cleanup and releases ballast first.

When both normalized inputs are `Critical`, the daemon emits a
`BehaviorEmergency` notification event. On macOS, an enabled desktop channel
delivers that event through `osascript -e 'display notification ...'`. Urgent
notification delivery is capped per event category by
`notifications.urgent_notify_interval_secs` (default 300 seconds) so repeated
Critical+Critical transitions alert the operator without flooding Notification
Center.

## Behavior Transition Hysteresis

The daemon applies time hysteresis to behavior-mode transitions after startup.
This prevents a noisy memory or disk signal from flapping scan, cleanup, and
ballast behavior back and forth within a few polling ticks.

The default minimum interval is 5 seconds for repeated transitions in the same
direction:

- Escalating transitions are rate-limited against the previous escalation.
- Recovering transitions are rate-limited against the previous recovery.
- Escalation and recovery timers are independent, so a genuine reversal can
  still apply immediately.
- A deferred transition applies when its window ends. The memory subscription
  reports a level only when it changes, so the daemon keeps the deferred level
  as its latest memory reading, re-evaluates it on every tick and every 500 ms
  while sleeping, and logs `behavior mode transition deferred` once per target.
  A newer reading replaces it; a config reload keeps it.

The interval is configured with `pressure.behavior_hysteresis_secs` or the
`SBH_PRESSURE_BEHAVIOR_HYSTERESIS_SECS` environment variable. A value of `0`
disables behavior transition hysteresis. The startup seed bypasses hysteresis so
the daemon begins in the behavior cell that matches the initial pressure sample.

## Linux Signal

Linux reads the `some avg10` PSI field from `/proc/pressure/memory` and, on a
supported cgroup-v2 hierarchy, from **this process's** `memory.pressure` file.
Service-local stalls can be severe while the host sample remains quiet. The
policy uses the **maximum known sample**, never the sum of percentages from
overlapping task populations. `linux_psi_avg10` carries that effective maximum
in centipercent (`12.34` becomes `1234`); it is no longer a host-only field.
The page, RAM and swap counters still describe the host and are not rewritten
as container capacity. A standalone CLI probe observes the CLI's cgroup, which
need not be the running daemon's cgroup.

The local observer reuses the cgroup admission reader's verified procfs/cgroup2
files, native path handling and bounded namespace resolution. It rechecks
membership, mount tables and the optional `cgroup.pressure` accounting switch
before publishing. Explicitly disabled accounting, malformed/truncated PSI,
unreadable v2 files or a changed observation are unknown evidence, not zero
pressure. Kernels lacking the accounting-switch file can still provide valid
PSI. Hierarchies identified as unsupported by the existing membership resolver
(including legacy memory-controller hierarchies) retain host-only PSI behavior.
This differs intentionally from RAM-write admission, which requires supported
local-limit evidence before allowing a RAM route.

The observer samples the current cgroup's task population, not its siblings or
ancestors' aggregate PSI. It performs no process enumeration, cgroup writes,
reclaim request or directory attribution. A normal supported observation uses
seven logical reads and a 100 ms cooperative deadline through the existing
3 MiB/512-read limits; each PSI record is capped at 4096 bytes. No local sample
or resolved path is cached across calls. These bounds do not interrupt blocked
kernel calls and are not an atomic process/mount snapshot.

| Effective Linux PSI `some avg10` | Native `MemoryPressureLevel` |
|---:|---|
| no valid sample, or an applicable source is missing while all known samples are below Warn | `Unknown` |
| all applicable sources available and maximum `< 5.00%` | `Normal` |
| maximum `>= 5.00%` and `< 20.00%` | `Warn` |
| maximum `>= 20.00%` | `Critical` |

Known warning/critical evidence survives failure of the other source. Unknown
coverage cannot be used to claim Normal. The existing subscription exit bands
use the same effective PSI: Warn holds down to 4%, and Critical holds down to
16%, before recovery can move to a lower level. These are stall-time thresholds,
not percentages of free memory. The kernel PSI interface and per-cgroup format
are described in `https://docs.kernel.org/accounting/psi.html`; the accounting
switch is documented in `https://docs.kernel.org/admin-guide/cgroup-v2.html`.

### Subscription continuity

Linux first registers a host PSI trigger and waits through `epoll`. The trigger
uses the existing one-second 5% threshold (`some 50000 1000000`). Every one-second
wait timeout also samples, **including at Normal**, because a host event cannot
be relied upon to announce service-local stalls or process migration. If setup
is refused, the subscription starts with the polling implementation.

If an established event source fails or reports an error/hangup, its descriptor
and trigger are dropped once. The same worker samples immediately and thereafter
uses one-second sleeps. It neither retries the broken source in a hot loop nor
creates replacement workers. The subscription's source label records its initial
transport selection; it does not change when an epoll worker falls back at runtime.
Interrupted waits retain the source and recheck subscription lifetime.

A failed initial memory read no longer prevents the polling subscription from
starting. Failed samples publish Unknown with absent counters instead of leaving
a stale Normal value in the daemon. Repeated Unknown samples are silent; a later
successful level change reports recovery. An initial Unknown is announced once
so a successful earlier daemon seed cannot mask an unavailable subscription seed.
Both wait completion and sample completion recheck lifetime before doing more
work or publishing. Shutdown does not cancel a native read already in progress,
and the final lifetime check is not a synchronization barrier against a concurrent
callback. No behavior thresholds or cleanup permissions are changed by this logic.

## macOS Signal

macOS does not expose Linux PSI. The platform data model keeps macOS-only
compression separate from swap:

| macOS field | Meaning |
|---|---|
| `free_pages` | Pages immediately free according to Mach VM stats. |
| `compressor_used_bytes` | RAM consumed by compressed pages; not swap. |
| `swap_used_bytes` | Bytes spilled to disk-backed swap. |
| `linux_psi_avg10` | Always `None` on macOS. |

Apple exposes memory-pressure levels through dispatch memory pressure sources,
but not the numeric thresholds that produce those levels. Current `sbh` code
therefore infers the same native levels from VM stats conservatively:

| macOS VM state | Native `MemoryPressureLevel` |
|---|---|
| total pages unavailable | `Unknown` |
| free pages `< 2%` and swap is active | `Critical` |
| free pages `< 5%` and compressor is at least `10%` of pages | `Warn` |
| free pages `< 5%` and swap is active | `Warn` |
| otherwise | `Normal` |

When a future native dispatch event source is wired in, the event labels should
feed the same `MemoryPressureLevel` enum. The daemon behavior table should not
change just because the signal source changes from polling to events.

## Why Behavior Mapping Is The Stable Contract

The user-visible requirement is the same on both platforms:

- During normal memory conditions, let the disk policy decide how much work to
  do.
- During warning memory pressure, reduce scan breadth and prefer higher
  confidence cleanup.
- During critical memory pressure, avoid broad memory-heavy traversal and favor
  already-known definite candidates plus ballast release.

That contract does not require Linux and macOS to agree on the same raw metric.
It only requires that each native backend reports a defensible
`MemoryPressureLevel`, and that the policy layer maps that level consistently.

## Operator Diagnostics

Diagnostics must show both the normalized level and the native evidence:

- Linux output should include `linux_psi_avg10` when available.
- macOS output should include free pages, compressor bytes, and swap bytes.
- macOS output must not call compressed memory "swap".
- Unknown pressure data should be explained and treated as warning behavior.

This lets operators compare outcomes across Linux and macOS without hiding the
platform-specific evidence behind the normalized behavior row.

## Forecast bound (2026-09-02)

`rates.<mount>.seconds_to_red` in `state.json` is the conformal lower bound `tte_lo` when the mount's calibrator is past warm-up, else the EWMA point estimate; `rates.<mount>.forecast` carries `tte_point_s`, `tte_lo_s`, `coverage_target`, `coverage_empirical`, `alpha`, `samples` and `coverage_state`. The PID feedforward, the mount controller's Reclaim trigger and the predictive policy all consume the bound. See README "Conformal Time-to-Red Bound" and `src/monitor/conformal.rs`.
