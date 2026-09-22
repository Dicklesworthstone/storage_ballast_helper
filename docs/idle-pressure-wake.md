# Pressure escalation during idle backoff

An empty scan parks its mount in `Idle` and exponentially backs off further
scans. That remains the default for unchanged pressure. It must not, however,
make a healthy empty scan suppress reclamation when the disk subsequently fills.

The mount controller now interrupts an idle backoff when a scannable mount
reaches a pressure level higher than the levels already attempted during the
current empty-pass incident. It also wakes for a newly actionable, confident
time-to-red prediction, including while the measured level is still Green.
Forecasts must be finite, nonnegative, and within `action_horizon`.

## Bounded retries, not a return to hot-loop scanning

The controller remembers the highest attempted pressure, not just the previous
tick's pressure. Repeated readings at the same level, Red/Orange jitter, and
empty passes completed during a temporary dip do not repeatedly wake it. Each
higher severity supplies one new early retry. An unchanged forecast is likewise
covered after an attempt, rather than waking every tick.

An early retry does not reset the consecutive-empty-pass count. If it is empty,
the normal exponential backoff continues. The remembered incident is reset by
a productive pass, an explicit forced scan/config reload, or the configured
number of consecutive Green readings without an actionable prediction. A
brief dip or one low-confidence forecast reading is not a sustained recovery.

Dirty-root events, forced scans, reloads, newly releasable ballast, and scheduled
backoff expiry retain their existing wake behavior. A pressure wake is consumed
only when the idle controller can leave that state; a mount without scan roots
cannot spend it on a fictitious scan. State transitions and `rescan_in_secs`
continue to report the controller's real state.

This changes scheduling, not deletion authorization. Observe-only mounts do not
gain a reclaim surface. Empty ballast-only mounts do not scan. Mounts recovering
from a write failure still require the existing recovery checks. The behavior
matrix, scoring, identity checks, active-process protection, and executor safety
vetoes remain downstream of scan dispatch. Pressure on one mount does not wake
an unrelated idle mount.

## Regression coverage

`tests/mount_pressure_wake.rs` exercises the public controller: immediate wake
inside an hour-long backoff, ascending severities, stable pressure, jitter,
confident forecasts, invalid forecasts, healthy-window rearming, explicit wakes,
backoff expiry, unavailable actuators, recovery, status, and mount isolation.
Unit tests in `src/daemon/mount_controller/idle_wake.rs` exercise the bounded
incident memory directly. These tests use injected observations and clocks;
they neither delete real artifacts nor alter production pressure thresholds.
