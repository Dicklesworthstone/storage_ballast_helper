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

The interval is configured with `pressure.behavior_hysteresis_secs` or the
`SBH_PRESSURE_BEHAVIOR_HYSTERESIS_SECS` environment variable. A value of `0`
disables behavior transition hysteresis. The startup seed bypasses hysteresis so
the daemon begins in the behavior cell that matches the initial pressure sample.

## Linux Signal

Linux uses PSI from `/proc/pressure/memory`, specifically the `some avg10`
field. The code stores this as centipercent in `linux_psi_avg10` so `12.34`
becomes `1234`.

For daemon subscriptions, Linux first registers a PSI trigger on
`/proc/pressure/memory` and waits for it through `epoll`. The trigger uses the
same 5% one-second threshold as the `Warn` boundary (`some 50000 1000000`).
If the kernel, container, or permissions reject PSI triggers, the PAL falls
back to the existing one-second sampler while preserving the same normalized
behavior rows.

| Linux PSI `some avg10` | Native `MemoryPressureLevel` |
|---:|---|
| missing or unreadable | `Unknown` |
| `< 5.00%` | `Normal` |
| `>= 5.00%` and `< 20.00%` | `Warn` |
| `>= 20.00%` | `Critical` |

These thresholds are Linux-specific because PSI measures stall time: the share
of recent wall time in which at least one task was delayed by memory pressure.
They are not memory-free percentages and should not be reused as macOS page
thresholds.

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
