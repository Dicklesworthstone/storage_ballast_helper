//! Per-mount control state machine and the tick cadence rule.
//!
//! One [`MountController`] per monitored mount decides, from that mount's own
//! pressure reading and what sbh can actually do on it (its [`MountSurface`]),
//! whether the mount is being reclaimed, maintained, only observed, recovering
//! from a write failure, or idle. The daemon combines the controllers' cadence
//! contributions into one tick with [`global_tick`]: a mount sbh cannot act on
//! never tightens the loop. That rule is what ends the v0.5.1 hot loop where a
//! pressured `/` with no root_path drove the Orange poll interval while every
//! tick logged "cannot reclaim, backing off" and starved the mounts that did
//! have work.
//!
//! The controller is pure: it takes a [`MountTickInput`] and returns a
//! [`MountDecision`]. Filesystem probes, ballast release and scan dispatch stay
//! in the daemon, which is what keeps every transition table-testable.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::monitor::burst::ReserveMethod;
use crate::monitor::pid::PressureLevel;

/// Poll interval while a mount is in [`MountState::Recovery`]: fast enough to
/// notice the volume becoming writable again, slow enough not to hammer it.
pub const RECOVERY_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Cap on the idle rescan backoff (`min_rescan_interval * 2^n`).
pub const IDLE_BACKOFF_CAP: Duration = Duration::from_hours(1);

/// Green ticks a reclaiming mount must see in a row before it returns to
/// maintenance. Keeps a mount that oscillates around a threshold from
/// flapping between cadences.
pub const DEFAULT_RECOVERY_CLEAN_WINDOWS: u32 = 3;

// ──────────────────── surface ────────────────────

/// What sbh can do on a mount. Derived by the daemon each tick from config
/// (root_paths, cross_devices), the ballast coordinator and, once catalog
/// roots exist, the catalog derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MountSurface {
    /// Configured `scanner.root_paths` that live on this mount.
    pub configured_roots: usize,
    /// Catalog-derived roots (known-safe caches) on this mount.
    pub catalog_roots: usize,
    /// The mount has a ballast pool sbh can release.
    pub ballast_pool: bool,
    /// `scanner.cross_devices = true`: pressure here may drive scans of every
    /// configured root, so the mount is actionable even without its own root.
    pub cross_device_fallback: bool,
}

/// Which kind of surface a mount offers, in priority order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceKind {
    /// At least one configured root on the mount.
    Configured,
    /// Only catalog-derived roots: scans are catalog-only.
    Catalog,
    /// No roots here but cross-device reclamation may relieve it.
    CrossDevice,
    /// Only a ballast pool: release is possible, scanning is not.
    BallastOnly,
    /// Nothing sbh can act on.
    None,
}

impl MountSurface {
    /// The most capable kind of surface this mount offers.
    #[must_use]
    pub const fn kind(self) -> SurfaceKind {
        if self.configured_roots > 0 {
            SurfaceKind::Configured
        } else if self.catalog_roots > 0 {
            SurfaceKind::Catalog
        } else if self.cross_device_fallback {
            SurfaceKind::CrossDevice
        } else if self.ballast_pool {
            SurfaceKind::BallastOnly
        } else {
            SurfaceKind::None
        }
    }

    /// Whether the mount can be scanned at all.
    #[must_use]
    pub const fn scannable(self) -> bool {
        self.configured_roots > 0 || self.catalog_roots > 0 || self.cross_device_fallback
    }

    /// Whether the mount can be acted on in any way.
    #[must_use]
    pub const fn actionable(self) -> bool {
        self.scannable() || self.ballast_pool
    }
}

impl fmt::Display for SurfaceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Configured => "configured",
            Self::Catalog => "catalog",
            Self::CrossDevice => "cross_device",
            Self::BallastOnly => "ballast_only",
            Self::None => "none",
        })
    }
}

// ──────────────────── state ────────────────────

/// Control state of one mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountState {
    /// Reported and notified, never scanned, never drives the tick.
    ObserveOnly,
    /// Healthy and actionable: maintenance cadence, ballast replenish,
    /// predictive scans only.
    Maintain,
    /// Under pressure (or predicted to be): scans and ballast release on the
    /// PID cadence.
    Reclaim,
    /// The executor could not write on this mount (EROFS/ENOSPC); wait for a
    /// probe write to succeed before reclaiming again.
    Recovery,
    /// A full pass found nothing to reclaim and no ballast to release; rescan
    /// only on wake signals or after an exponential backoff.
    Idle,
}

impl MountState {
    /// Stable snake_case name used in `state.json`, logs and `sbh status`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObserveOnly => "observe_only",
            Self::Maintain => "maintain",
            Self::Reclaim => "reclaim",
            Self::Recovery => "recovery",
            Self::Idle => "idle",
        }
    }
}

impl fmt::Display for MountState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a mount is not being worked on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdleReason {
    /// No root_path, catalog root, ballast pool or cross-device fallback on
    /// this device: sbh has nothing it could act on.
    #[serde(rename = "no_root_path_on_device")]
    NoSurface,
    /// The last full pass produced zero dispatchable candidates and the pool
    /// had nothing left to release.
    NothingToReclaim,
    /// Waiting for the volume to accept writes again.
    WriteFailure,
}

impl IdleReason {
    /// Stable snake_case name used in `state.json`, logs and `sbh status`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoSurface => "no_root_path_on_device",
            Self::NothingToReclaim => "nothing_to_reclaim",
            Self::WriteFailure => "write_failure",
        }
    }
}

impl fmt::Display for IdleReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ──────────────────── inputs / outputs ────────────────────

/// Signals that wake an idle mount before its backoff expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WakeSignals {
    /// Filesystem events touched roots on this mount.
    pub dirty_roots: bool,
    /// Operator asked for a scan (SIGUSR1).
    pub forced_scan: bool,
    /// Config reload changed what sbh may act on.
    pub reload: bool,
}

impl WakeSignals {
    /// Whether any wake signal fired.
    #[must_use]
    pub const fn any(self) -> bool {
        self.dirty_roots || self.forced_scan || self.reload
    }
}

/// Everything the controller looks at on one tick.
#[derive(Debug, Clone, Copy)]
pub struct MountTickInput {
    /// The mount's own pressure level from its PID controller.
    pub level: PressureLevel,
    /// The mount's own urgency (0.0–1.0).
    pub urgency: f64,
    /// Free space on the mount, percent.
    pub free_pct: f64,
    /// EWMA time-to-red, when the estimator has one.
    pub seconds_to_red: Option<f64>,
    /// Whether the prediction clears the configured confidence floor.
    pub prediction_confident: bool,
    /// What sbh can act on here this tick.
    pub surface: MountSurface,
    /// The mount's ballast pool still has files to release.
    pub releasable_ballast: bool,
    /// The executor reported a write failure on this mount since last tick.
    pub recovery_needed: bool,
    /// Result of the daemon's probe write while in `Recovery` (`None` when no
    /// probe was attempted this tick).
    pub recovery_probe_ok: Option<bool>,
    /// Signals that wake an idle mount early.
    pub wake: WakeSignals,
    /// The tick's clock, so backoffs are testable.
    pub now: Instant,
}

/// What the daemon should do for this mount on this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MountDecision {
    /// State after this tick.
    pub state: MountState,
    /// `(from, to)` when this tick changed the state.
    pub transition: Option<(MountState, MountState)>,
    /// Dispatch a scan for this mount's roots.
    pub scan: bool,
    /// Release ballast on this mount (subject to the behavior matrix).
    pub release_ballast: bool,
    /// Attempt a probe write on the mount (it is recovering).
    pub probe_write: bool,
}

/// Tunables, derived from config by the daemon.
#[derive(Debug, Clone, Copy)]
pub struct MountControllerConfig {
    /// Predictive escalation: enter `Reclaim` when time-to-red is within this.
    pub action_horizon: Duration,
    /// Green ticks in a row before `Reclaim` returns to `Maintain`.
    pub recovery_clean_windows: u32,
    /// First idle backoff; doubles on each empty pass, capped at
    /// [`IDLE_BACKOFF_CAP`].
    pub min_rescan_interval: Duration,
    /// Free percent below which a recovering mount stays in `Recovery` even
    /// when the probe write succeeds.
    pub red_min_free_pct: f64,
}

impl Default for MountControllerConfig {
    fn default() -> Self {
        Self {
            action_horizon: Duration::from_mins(30),
            recovery_clean_windows: DEFAULT_RECOVERY_CLEAN_WINDOWS,
            min_rescan_interval: Duration::from_mins(5),
            red_min_free_pct: 6.0,
        }
    }
}

// ──────────────────── controller ────────────────────

/// Control state for one mount. See the module docs for the state machine.
#[derive(Debug, Clone)]
pub struct MountController {
    mount: PathBuf,
    config: MountControllerConfig,
    state: MountState,
    idle_reason: Option<IdleReason>,
    level: PressureLevel,
    urgency: f64,
    surface: MountSurface,
    entered_at: Option<Instant>,
    /// Consecutive Green ticks while reclaiming.
    clean_ticks: u32,
    /// Empty passes in a row; drives the idle backoff exponent.
    empty_passes: u32,
    /// When an idle mount may be rescanned without a wake signal.
    idle_until: Option<Instant>,
    last_transition: Option<(MountState, MountState)>,
}

impl MountController {
    /// A controller for `mount`, starting as observe-only until it is given
    /// a surface.
    #[must_use]
    pub fn new(mount: PathBuf, config: MountControllerConfig) -> Self {
        Self {
            mount,
            config,
            state: MountState::ObserveOnly,
            idle_reason: Some(IdleReason::NoSurface),
            level: PressureLevel::Green,
            urgency: 0.0,
            surface: MountSurface::default(),
            entered_at: None,
            clean_ticks: 0,
            empty_passes: 0,
            idle_until: None,
            last_transition: None,
        }
    }

    /// The mount point this controller owns.
    #[must_use]
    pub fn mount(&self) -> &Path {
        &self.mount
    }

    /// Current control state.
    #[must_use]
    pub const fn state(&self) -> MountState {
        self.state
    }

    /// Why the mount is not being worked on, when it is not.
    #[must_use]
    pub const fn idle_reason(&self) -> Option<IdleReason> {
        self.idle_reason
    }

    /// Pressure level seen on the last tick.
    #[must_use]
    pub const fn level(&self) -> PressureLevel {
        self.level
    }

    /// Urgency seen on the last tick.
    #[must_use]
    pub const fn urgency(&self) -> f64 {
        self.urgency
    }

    /// Surface seen on the last tick.
    #[must_use]
    pub const fn surface(&self) -> MountSurface {
        self.surface
    }

    /// Consecutive empty passes; drives the idle backoff exponent.
    #[must_use]
    pub const fn empty_passes(&self) -> u32 {
        self.empty_passes
    }

    /// Time at which an idle mount rescans on its own, if it is idle.
    #[must_use]
    pub const fn idle_until(&self) -> Option<Instant> {
        self.idle_until
    }

    /// Replace the tunables (config reload).
    pub fn set_config(&mut self, config: MountControllerConfig) {
        self.config = config;
    }

    /// Advance the state machine one tick.
    #[allow(clippy::too_many_lines)]
    pub fn observe(&mut self, input: MountTickInput) -> MountDecision {
        self.level = input.level;
        self.urgency = input.urgency;
        self.surface = input.surface;
        let before = self.state;

        let pressured = input.level >= PressureLevel::Yellow;
        let predicted = input.prediction_confident
            && input
                .seconds_to_red
                .is_some_and(|seconds| seconds <= self.config.action_horizon.as_secs_f64());
        let wants_reclaim = pressured || predicted;

        // A write failure trumps everything: nothing sbh does on this mount
        // can succeed until a probe write does.
        if input.recovery_needed && self.state != MountState::Recovery {
            self.enter(
                MountState::Recovery,
                Some(IdleReason::WriteFailure),
                input.now,
            );
        }

        match self.state {
            MountState::ObserveOnly => {
                if input.surface.actionable() {
                    let next = if wants_reclaim {
                        MountState::Reclaim
                    } else {
                        MountState::Maintain
                    };
                    self.enter(next, None, input.now);
                }
            }
            MountState::Maintain => {
                if !input.surface.actionable() {
                    self.enter(
                        MountState::ObserveOnly,
                        Some(IdleReason::NoSurface),
                        input.now,
                    );
                } else if wants_reclaim {
                    self.enter(MountState::Reclaim, None, input.now);
                }
            }
            MountState::Reclaim => {
                if !input.surface.actionable() {
                    self.enter(
                        MountState::ObserveOnly,
                        Some(IdleReason::NoSurface),
                        input.now,
                    );
                } else if wants_reclaim {
                    self.clean_ticks = 0;
                } else {
                    self.clean_ticks = self.clean_ticks.saturating_add(1);
                    if self.clean_ticks >= self.config.recovery_clean_windows {
                        self.enter(MountState::Maintain, None, input.now);
                    }
                }
            }
            MountState::Recovery => {
                if input.recovery_probe_ok == Some(true)
                    && input.free_pct >= self.config.red_min_free_pct
                {
                    let next = if input.surface.actionable() {
                        MountState::Reclaim
                    } else {
                        MountState::ObserveOnly
                    };
                    let reason = (next == MountState::ObserveOnly).then_some(IdleReason::NoSurface);
                    self.enter(next, reason, input.now);
                }
            }
            MountState::Idle => {
                let backoff_expired = self.idle_until.is_none_or(|until| input.now >= until);
                if !input.surface.actionable() {
                    self.enter(
                        MountState::ObserveOnly,
                        Some(IdleReason::NoSurface),
                        input.now,
                    );
                } else if input.wake.any() || backoff_expired || input.releasable_ballast {
                    if input.wake.forced_scan || input.wake.reload {
                        self.empty_passes = 0;
                    }
                    let next = if wants_reclaim {
                        MountState::Reclaim
                    } else {
                        MountState::Maintain
                    };
                    self.enter(next, None, input.now);
                }
            }
        }

        let transition = (self.state != before).then_some((before, self.state));
        self.last_transition = transition.or(self.last_transition);

        let scan = self.state == MountState::Reclaim && input.surface.scannable();
        let release_ballast = self.state == MountState::Reclaim
            && input.surface.ballast_pool
            && input.releasable_ballast;
        MountDecision {
            state: self.state,
            transition,
            scan,
            release_ballast,
            probe_write: self.state == MountState::Recovery,
        }
    }

    /// Record the outcome of a full scan pass over this mount's roots.
    ///
    /// A pass with nothing dispatchable and no ballast left to release parks
    /// the mount in `Idle` with an exponential rescan backoff; anything found
    /// resets the backoff. Returns the transition, if any.
    pub fn note_pass(
        &mut self,
        dispatchable_candidates: usize,
        releasable_ballast: bool,
        now: Instant,
    ) -> Option<(MountState, MountState)> {
        if dispatchable_candidates > 0 {
            self.empty_passes = 0;
            return None;
        }
        if releasable_ballast || !matches!(self.state, MountState::Reclaim | MountState::Maintain) {
            return None;
        }
        self.empty_passes = self.empty_passes.saturating_add(1);
        let before = self.state;
        self.enter(MountState::Idle, Some(IdleReason::NothingToReclaim), now);
        self.idle_until = Some(now + self.idle_backoff());
        Some((before, self.state))
    }

    /// `min_rescan_interval * 2^(empty_passes - 1)`, capped.
    #[must_use]
    pub fn idle_backoff(&self) -> Duration {
        let exponent = self.empty_passes.saturating_sub(1).min(16);
        let scaled = self
            .config
            .min_rescan_interval
            .saturating_mul(1u32 << exponent);
        scaled.min(IDLE_BACKOFF_CAP)
    }

    /// This mount's contribution to the daemon tick.
    ///
    /// `pid_interval` is the interval the mount's own PID controller asked
    /// for. Mounts sbh is not working on contribute nothing, so they can never
    /// tighten the loop.
    #[must_use]
    pub fn cadence(&self, base_poll: Duration, pid_interval: Duration) -> Option<Duration> {
        match self.state {
            MountState::ObserveOnly | MountState::Idle => None,
            MountState::Maintain => Some(base_poll),
            MountState::Reclaim => Some(pid_interval.min(base_poll)),
            MountState::Recovery => Some(RECOVERY_POLL_INTERVAL),
        }
    }

    fn enter(&mut self, next: MountState, reason: Option<IdleReason>, now: Instant) {
        if self.state == next {
            return;
        }
        self.state = next;
        self.idle_reason = reason;
        self.entered_at = Some(now);
        if next != MountState::Reclaim {
            self.clean_ticks = 0;
        }
        if next != MountState::Idle {
            self.idle_until = None;
        }
    }
}

/// Combine per-mount cadence contributions into one tick: the tightest
/// interval among mounts sbh is working on, or the base poll when none is.
#[must_use]
pub fn global_tick<I>(contributions: I, base_poll: Duration) -> Duration
where
    I: IntoIterator<Item = Option<Duration>>,
{
    contributions
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(base_poll)
        .min(base_poll)
}

/// How sbh could reclaim space on a mount, for `state.json`, `sbh status`,
/// `sbh check` and `sbh doctor`: the surface kind read as a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReclaimCapability {
    /// Configured roots on the mount can be scanned and cleaned.
    Configured,
    /// Only catalog roots (known-safe caches) can be cleaned.
    Catalog,
    /// No root here; `scanner.cross_devices` lets other roots' cleanup help.
    CrossDevice,
    /// Only a ballast pool: release is possible, nothing can be cleaned.
    BallastOnly,
    /// Nothing at all: pressure here can only be observed.
    #[default]
    None,
}

impl ReclaimCapability {
    /// The capability a surface kind amounts to.
    #[must_use]
    pub const fn from_surface(kind: SurfaceKind) -> Self {
        match kind {
            SurfaceKind::Configured => Self::Configured,
            SurfaceKind::Catalog => Self::Catalog,
            SurfaceKind::CrossDevice => Self::CrossDevice,
            SurfaceKind::BallastOnly => Self::BallastOnly,
            SurfaceKind::None => Self::None,
        }
    }

    /// The `state.json` spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::Catalog => "catalog",
            Self::CrossDevice => "cross_device",
            Self::BallastOnly => "ballast_only",
            Self::None => "none",
        }
    }
}

/// The ballast reserve on a mount as the daemon sees it.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ReserveState {
    /// Bytes releasable right now.
    pub present_bytes: u64,
    /// Bytes the configuration asks for on this mount.
    pub target_bytes: u64,
    /// Minutes the present reserve would buy at the mount's current fill
    /// rate; absent when the mount is not filling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub horizon_minutes: Option<f64>,
    /// The reserve is short of its target because the headroom floor refused
    /// further files (not because files were released).
    pub floor_limited: bool,
    /// Bytes held in the mount's quarantine (Layer 7): reclaimable on
    /// demand, drained oldest-first before any new deletion at Orange+.
    #[serde(default)]
    pub quarantined_bytes: u64,
    /// What the observed write bursts say the reserve should be
    /// (bd-rc-master-ajg1.2.18); absent until the mount has been observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<ReserveBurst>,
}

/// The reserve target derived from the mount's write bursts: the 0.99
/// quantile of used-bytes growth per reaction window, floored at two
/// ballast files.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ReserveBurst {
    /// Bytes the reserve should hold.
    pub recommended_bytes: u64,
    /// The 0.99 burst quantile before the floor.
    pub q99_bytes: u64,
    /// Reaction windows observed so far.
    pub windows: u64,
    /// Length of the reaction window the samples were taken over.
    pub reaction_window_secs: f64,
    /// `floor`, `tail` (Pareto extrapolation) or `quantile`.
    pub method: ReserveMethod,
    /// Minutes the present reserve buys at the 0.99 burst rate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub horizon_minutes: Option<f64>,
}

impl Default for ReserveBurst {
    fn default() -> Self {
        Self {
            recommended_bytes: 0,
            q99_bytes: 0,
            windows: 0,
            reaction_window_secs: 0.0,
            method: ReserveMethod::Floor,
            horizon_minutes: None,
        }
    }
}

/// Whether pressure on a mount finds sbh unable to do anything about it:
/// no reclaim surface, or a ballast pool that is the only surface and is
/// empty. `Green` is never unprotected.
#[must_use]
pub fn unprotected_pressure(record: &MountStateRecord) -> bool {
    if record.level == "green" {
        return false;
    }
    match record.reclaim_capability {
        ReclaimCapability::None => true,
        ReclaimCapability::BallastOnly => record
            .reserve_state
            .is_none_or(|reserve| reserve.present_bytes == 0),
        _ => false,
    }
}

/// Snapshot of a controller for `state.json` and `sbh status`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MountStateRecord {
    /// Mount point.
    pub mount: String,
    /// Control state.
    pub state: MountState,
    /// Why the mount is not being worked on, when it is not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_reason: Option<IdleReason>,
    /// What sbh can act on here.
    pub surface: SurfaceKind,
    /// Pressure level, lowercase.
    pub level: String,
    /// Urgency (0.0–1.0).
    pub urgency: f64,
    /// Seconds until an idle mount rescans on its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rescan_in_secs: Option<u64>,
    /// How sbh could reclaim here (the surface kind as a capability).
    #[serde(default)]
    pub reclaim_capability: ReclaimCapability,
    /// The ballast reserve on this mount, when the daemon knows it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserve_state: Option<ReserveState>,
}

impl MountController {
    /// Snapshot for `state.json` and `sbh status`. The reserve is filled in
    /// by the daemon, which owns the ballast pools.
    #[must_use]
    pub fn record(&self, now: Instant) -> MountStateRecord {
        MountStateRecord {
            mount: self.mount.to_string_lossy().into_owned(),
            state: self.state,
            idle_reason: self.idle_reason,
            surface: self.surface.kind(),
            level: format!("{:?}", self.level).to_lowercase(),
            urgency: self.urgency,
            rescan_in_secs: self
                .idle_until
                .map(|until| until.saturating_duration_since(now).as_secs()),
            reclaim_capability: ReclaimCapability::from_surface(self.surface.kind()),
            reserve_state: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configured() -> MountSurface {
        MountSurface {
            configured_roots: 1,
            ..MountSurface::default()
        }
    }

    fn input(level: PressureLevel, surface: MountSurface, now: Instant) -> MountTickInput {
        MountTickInput {
            level,
            urgency: match level {
                PressureLevel::Green => 0.0,
                PressureLevel::Yellow => 0.3,
                PressureLevel::Orange => 0.6,
                PressureLevel::Red => 0.85,
                PressureLevel::Critical => 1.0,
            },
            free_pct: match level {
                PressureLevel::Green => 40.0,
                PressureLevel::Yellow => 17.0,
                PressureLevel::Orange => 12.0,
                PressureLevel::Red => 5.0,
                PressureLevel::Critical => 1.0,
            },
            seconds_to_red: None,
            prediction_confident: false,
            surface,
            releasable_ballast: false,
            recovery_needed: false,
            recovery_probe_ok: None,
            wake: WakeSignals::default(),
            now,
        }
    }

    fn fresh() -> MountController {
        MountController::new(PathBuf::from("/data"), MountControllerConfig::default())
    }

    #[test]
    fn surface_kind_follows_priority_order() {
        let cases = [
            (MountSurface::default(), SurfaceKind::None),
            (
                MountSurface {
                    ballast_pool: true,
                    ..MountSurface::default()
                },
                SurfaceKind::BallastOnly,
            ),
            (
                MountSurface {
                    cross_device_fallback: true,
                    ballast_pool: true,
                    ..MountSurface::default()
                },
                SurfaceKind::CrossDevice,
            ),
            (
                MountSurface {
                    catalog_roots: 2,
                    cross_device_fallback: true,
                    ..MountSurface::default()
                },
                SurfaceKind::Catalog,
            ),
            (
                MountSurface {
                    configured_roots: 1,
                    catalog_roots: 2,
                    ..MountSurface::default()
                },
                SurfaceKind::Configured,
            ),
        ];
        for (surface, kind) in cases {
            assert_eq!(surface.kind(), kind, "{surface:?}");
        }
        assert!(!MountSurface::default().actionable());
        assert!(
            MountSurface {
                ballast_pool: true,
                ..MountSurface::default()
            }
            .actionable()
        );
        assert!(
            !MountSurface {
                ballast_pool: true,
                ..MountSurface::default()
            }
            .scannable()
        );
    }

    struct Case {
        name: &'static str,
        setup: fn(&mut MountController, Instant),
        input: fn(Instant) -> MountTickInput,
        expect: MountState,
        reason: Option<IdleReason>,
    }

    /// Every transition in the design table, driven from a fresh controller.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn transitions_follow_the_design_table() {
        let now = Instant::now();
        let cases = [
            Case {
                name: "no surface stays observe-only",
                setup: |_, _| {},
                input: |now| input(PressureLevel::Orange, MountSurface::default(), now),
                expect: MountState::ObserveOnly,
                reason: Some(IdleReason::NoSurface),
            },
            Case {
                name: "green with a root becomes maintain",
                setup: |_, _| {},
                input: |now| input(PressureLevel::Green, configured(), now),
                expect: MountState::Maintain,
                reason: None,
            },
            Case {
                name: "yellow with a root becomes reclaim",
                setup: |_, _| {},
                input: |now| input(PressureLevel::Yellow, configured(), now),
                expect: MountState::Reclaim,
                reason: None,
            },
            Case {
                name: "maintain escalates on a confident short horizon",
                setup: |c, now| {
                    c.observe(input(PressureLevel::Green, configured(), now));
                },
                input: |now| MountTickInput {
                    seconds_to_red: Some(10.0 * 60.0),
                    prediction_confident: true,
                    ..input(PressureLevel::Green, configured(), now)
                },
                expect: MountState::Reclaim,
                reason: None,
            },
            Case {
                name: "maintain ignores an unconfident short horizon",
                setup: |c, now| {
                    c.observe(input(PressureLevel::Green, configured(), now));
                },
                input: |now| MountTickInput {
                    seconds_to_red: Some(10.0 * 60.0),
                    prediction_confident: false,
                    ..input(PressureLevel::Green, configured(), now)
                },
                expect: MountState::Maintain,
                reason: None,
            },
            Case {
                name: "reclaim loses its surface -> observe-only",
                setup: |c, now| {
                    c.observe(input(PressureLevel::Orange, configured(), now));
                },
                input: |now| input(PressureLevel::Orange, MountSurface::default(), now),
                expect: MountState::ObserveOnly,
                reason: Some(IdleReason::NoSurface),
            },
            Case {
                name: "write failure -> recovery from any state",
                setup: |c, now| {
                    c.observe(input(PressureLevel::Orange, configured(), now));
                },
                input: |now| MountTickInput {
                    recovery_needed: true,
                    ..input(PressureLevel::Orange, configured(), now)
                },
                expect: MountState::Recovery,
                reason: Some(IdleReason::WriteFailure),
            },
            Case {
                name: "recovery waits for a successful probe",
                setup: |c, now| {
                    c.observe(MountTickInput {
                        recovery_needed: true,
                        ..input(PressureLevel::Orange, configured(), now)
                    });
                },
                input: |now| MountTickInput {
                    recovery_probe_ok: Some(false),
                    ..input(PressureLevel::Orange, configured(), now)
                },
                expect: MountState::Recovery,
                reason: Some(IdleReason::WriteFailure),
            },
            Case {
                name: "recovery stays while free is below red even if the probe works",
                setup: |c, now| {
                    c.observe(MountTickInput {
                        recovery_needed: true,
                        ..input(PressureLevel::Red, configured(), now)
                    });
                },
                input: |now| MountTickInput {
                    recovery_probe_ok: Some(true),
                    ..input(PressureLevel::Red, configured(), now)
                },
                expect: MountState::Recovery,
                reason: Some(IdleReason::WriteFailure),
            },
            Case {
                name: "recovery -> reclaim once the probe writes above red",
                setup: |c, now| {
                    c.observe(MountTickInput {
                        recovery_needed: true,
                        ..input(PressureLevel::Orange, configured(), now)
                    });
                },
                input: |now| MountTickInput {
                    recovery_probe_ok: Some(true),
                    ..input(PressureLevel::Orange, configured(), now)
                },
                expect: MountState::Reclaim,
                reason: None,
            },
            Case {
                name: "idle wakes on dirty roots",
                setup: |c, now| {
                    c.observe(input(PressureLevel::Green, configured(), now));
                    c.note_pass(0, false, now);
                },
                input: |now| MountTickInput {
                    wake: WakeSignals {
                        dirty_roots: true,
                        ..WakeSignals::default()
                    },
                    ..input(PressureLevel::Green, configured(), now)
                },
                expect: MountState::Maintain,
                reason: None,
            },
            Case {
                name: "idle wakes into reclaim when pressured",
                setup: |c, now| {
                    c.observe(input(PressureLevel::Green, configured(), now));
                    c.note_pass(0, false, now);
                },
                input: |now| MountTickInput {
                    wake: WakeSignals {
                        forced_scan: true,
                        ..WakeSignals::default()
                    },
                    ..input(PressureLevel::Orange, configured(), now)
                },
                expect: MountState::Reclaim,
                reason: None,
            },
            Case {
                name: "idle stays idle inside its backoff without a wake",
                setup: |c, now| {
                    c.observe(input(PressureLevel::Green, configured(), now));
                    c.note_pass(0, false, now);
                },
                input: |now| {
                    input(
                        PressureLevel::Green,
                        configured(),
                        now + Duration::from_secs(1),
                    )
                },
                expect: MountState::Idle,
                reason: Some(IdleReason::NothingToReclaim),
            },
            Case {
                name: "idle rescans after the backoff expires",
                setup: |c, now| {
                    c.observe(input(PressureLevel::Green, configured(), now));
                    c.note_pass(0, false, now);
                },
                input: |now| {
                    input(
                        PressureLevel::Green,
                        configured(),
                        now + Duration::from_mins(6),
                    )
                },
                expect: MountState::Maintain,
                reason: None,
            },
            Case {
                name: "idle wakes when ballast becomes releasable",
                setup: |c, now| {
                    c.observe(input(PressureLevel::Orange, configured(), now));
                    c.note_pass(0, false, now);
                },
                input: |now| MountTickInput {
                    releasable_ballast: true,
                    ..input(PressureLevel::Orange, configured(), now)
                },
                expect: MountState::Reclaim,
                reason: None,
            },
        ];

        for case in cases {
            let mut controller = fresh();
            (case.setup)(&mut controller, now);
            let decision = controller.observe((case.input)(now));
            assert_eq!(decision.state, case.expect, "{}", case.name);
            assert_eq!(controller.idle_reason(), case.reason, "{}", case.name);
        }
    }

    #[test]
    fn reclaim_returns_to_maintain_after_the_clean_window() {
        let now = Instant::now();
        let mut controller = fresh();
        controller.observe(input(PressureLevel::Orange, configured(), now));
        assert_eq!(controller.state(), MountState::Reclaim);

        for tick in 1..DEFAULT_RECOVERY_CLEAN_WINDOWS {
            let decision = controller.observe(input(PressureLevel::Green, configured(), now));
            assert_eq!(decision.state, MountState::Reclaim, "tick {tick}");
        }
        // One pressured tick resets the clean window.
        controller.observe(input(PressureLevel::Yellow, configured(), now));
        for _ in 1..DEFAULT_RECOVERY_CLEAN_WINDOWS {
            controller.observe(input(PressureLevel::Green, configured(), now));
        }
        assert_eq!(controller.state(), MountState::Reclaim);
        let decision = controller.observe(input(PressureLevel::Green, configured(), now));
        assert_eq!(decision.state, MountState::Maintain);
        assert_eq!(
            decision.transition,
            Some((MountState::Reclaim, MountState::Maintain))
        );
    }

    #[test]
    fn decisions_scan_and_release_only_while_reclaiming() {
        let now = Instant::now();
        let mut controller = fresh();
        let surface = MountSurface {
            configured_roots: 1,
            ballast_pool: true,
            ..MountSurface::default()
        };

        let maintain = controller.observe(MountTickInput {
            releasable_ballast: true,
            ..input(PressureLevel::Green, surface, now)
        });
        assert!(!maintain.scan && !maintain.release_ballast && !maintain.probe_write);

        let reclaim = controller.observe(MountTickInput {
            releasable_ballast: true,
            ..input(PressureLevel::Orange, surface, now)
        });
        assert!(reclaim.scan && reclaim.release_ballast);

        let drained = controller.observe(input(PressureLevel::Orange, surface, now));
        assert!(drained.scan && !drained.release_ballast);

        // Ballast-only surface: release, never scan.
        let mut pool_only = fresh();
        let decision = pool_only.observe(MountTickInput {
            releasable_ballast: true,
            ..input(
                PressureLevel::Red,
                MountSurface {
                    ballast_pool: true,
                    ..MountSurface::default()
                },
                now,
            )
        });
        assert_eq!(decision.state, MountState::Reclaim);
        assert!(!decision.scan && decision.release_ballast);

        let recovering = controller.observe(MountTickInput {
            recovery_needed: true,
            ..input(PressureLevel::Orange, surface, now)
        });
        assert!(recovering.probe_write && !recovering.scan && !recovering.release_ballast);
    }

    #[test]
    fn empty_passes_back_off_exponentially_and_cap() {
        let now = Instant::now();
        let mut controller = fresh();
        let config = MountControllerConfig::default();
        let mut expected = config.min_rescan_interval;
        for pass in 1..=5u32 {
            controller.observe(input(PressureLevel::Green, configured(), now));
            let transition = controller.note_pass(0, false, now);
            assert_eq!(
                transition,
                Some((MountState::Maintain, MountState::Idle)),
                "pass {pass}"
            );
            assert_eq!(controller.empty_passes(), pass);
            assert_eq!(controller.idle_backoff(), expected, "pass {pass}");
            expected = (expected * 2).min(IDLE_BACKOFF_CAP);
            // Wake it so the next pass can be recorded.
            controller.observe(MountTickInput {
                wake: WakeSignals {
                    dirty_roots: true,
                    ..WakeSignals::default()
                },
                ..input(PressureLevel::Green, configured(), now)
            });
        }
        for _ in 0..20 {
            controller.note_pass(0, false, now);
            controller.observe(MountTickInput {
                wake: WakeSignals {
                    dirty_roots: true,
                    ..WakeSignals::default()
                },
                ..input(PressureLevel::Green, configured(), now)
            });
        }
        assert_eq!(controller.idle_backoff(), IDLE_BACKOFF_CAP);

        // A productive pass resets the backoff; an empty pass with ballast
        // left to release does not park the mount.
        assert_eq!(controller.note_pass(3, false, now), None);
        assert_eq!(controller.empty_passes(), 0);
        assert_eq!(controller.note_pass(0, true, now), None);
        assert_eq!(controller.state(), MountState::Maintain);
    }

    /// Invariant 10: the tick follows the tightest mount sbh is working on;
    /// mounts it cannot act on never tighten it.
    #[test]
    fn cadence_rule_ignores_observe_only_and_idle_mounts() {
        let now = Instant::now();
        let base = Duration::from_secs(60);
        let pid = Duration::from_secs(15);

        // Mount A: Orange, no root, no pool -> observe-only.
        let mut a = MountController::new(PathBuf::from("/"), MountControllerConfig::default());
        a.observe(input(PressureLevel::Orange, MountSurface::default(), now));
        // Mount B: Green with a root -> maintain.
        let mut b = MountController::new(PathBuf::from("/data"), MountControllerConfig::default());
        b.observe(input(PressureLevel::Green, configured(), now));

        assert_eq!(a.cadence(base, pid), None);
        assert_eq!(b.cadence(base, pid), Some(base));
        assert_eq!(
            global_tick([a.cadence(base, pid), b.cadence(base, pid)], base),
            base
        );

        // B under pressure: the PID interval wins.
        b.observe(input(PressureLevel::Orange, configured(), now));
        assert_eq!(
            global_tick([a.cadence(base, pid), b.cadence(base, pid)], base),
            pid
        );

        // Only observe-only mounts: base poll, never faster.
        assert_eq!(global_tick([a.cadence(base, pid)], base), base);
        assert_eq!(global_tick(std::iter::empty(), base), base);

        // Idle B contributes nothing even under pressure; recovery polls at 30s.
        b.note_pass(0, false, now);
        assert_eq!(b.cadence(base, pid), None);
        b.observe(MountTickInput {
            recovery_needed: true,
            ..input(PressureLevel::Orange, configured(), now)
        });
        assert_eq!(b.cadence(base, pid), Some(RECOVERY_POLL_INTERVAL));
        // A PID interval slower than base never loosens the loop either.
        let mut c = MountController::new(PathBuf::from("/x"), MountControllerConfig::default());
        c.observe(input(PressureLevel::Yellow, configured(), now));
        assert_eq!(c.cadence(base, Duration::from_secs(600)), Some(base));
    }

    #[test]
    fn record_serializes_state_and_reason_for_status() {
        let now = Instant::now();
        let mut controller =
            MountController::new(PathBuf::from("/"), MountControllerConfig::default());
        controller.observe(input(PressureLevel::Orange, MountSurface::default(), now));
        let record = controller.record(now);
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["mount"], "/");
        assert_eq!(json["state"], "observe_only");
        assert_eq!(json["idle_reason"], "no_root_path_on_device");
        assert_eq!(json["surface"], "none");
        assert_eq!(json["level"], "orange");
        assert!(json.get("rescan_in_secs").is_none());

        let mut idle = fresh();
        idle.observe(input(PressureLevel::Green, configured(), now));
        idle.note_pass(0, false, now);
        let record = idle.record(now);
        assert_eq!(record.state, MountState::Idle);
        assert_eq!(record.idle_reason, Some(IdleReason::NothingToReclaim));
        assert_eq!(record.rescan_in_secs, Some(5 * 60));
        let back: MountStateRecord =
            serde_json::from_value(serde_json::to_value(&record).unwrap()).unwrap();
        assert_eq!(back, record);
    }

    /// Capability follows the surface kind; a pressured mount is
    /// unprotected only with no capability, or a ballast-only surface whose
    /// reserve is empty; Green is never unprotected; records written before
    /// the field existed read back as `none`.
    #[test]
    fn reclaim_capability_and_unprotected_pressure() {
        let cases = [
            (
                MountSurface {
                    configured_roots: 1,
                    ..MountSurface::default()
                },
                ReclaimCapability::Configured,
            ),
            (
                MountSurface {
                    catalog_roots: 2,
                    ..MountSurface::default()
                },
                ReclaimCapability::Catalog,
            ),
            (
                MountSurface {
                    cross_device_fallback: true,
                    ..MountSurface::default()
                },
                ReclaimCapability::CrossDevice,
            ),
            (
                MountSurface {
                    ballast_pool: true,
                    ..MountSurface::default()
                },
                ReclaimCapability::BallastOnly,
            ),
            (MountSurface::default(), ReclaimCapability::None),
        ];
        for (surface, want) in cases {
            assert_eq!(ReclaimCapability::from_surface(surface.kind()), want);
            assert_eq!(
                serde_json::to_value(want).unwrap(),
                serde_json::Value::String(want.as_str().to_string())
            );
        }

        let record =
            |level: &str, capability: ReclaimCapability, reserve: Option<u64>| MountStateRecord {
                mount: "/".to_string(),
                state: MountState::ObserveOnly,
                idle_reason: None,
                surface: SurfaceKind::None,
                level: level.to_string(),
                urgency: 0.5,
                rescan_in_secs: None,
                reclaim_capability: capability,
                reserve_state: reserve.map(|present_bytes| ReserveState {
                    present_bytes,
                    target_bytes: 1 << 30,
                    horizon_minutes: None,
                    floor_limited: false,
                    quarantined_bytes: 0,
                    burst: None,
                }),
            };
        assert!(unprotected_pressure(&record(
            "orange",
            ReclaimCapability::None,
            None
        )));
        assert!(!unprotected_pressure(&record(
            "green",
            ReclaimCapability::None,
            None
        )));
        assert!(!unprotected_pressure(&record(
            "orange",
            ReclaimCapability::Configured,
            None
        )));
        assert!(unprotected_pressure(&record(
            "red",
            ReclaimCapability::BallastOnly,
            Some(0)
        )));
        assert!(!unprotected_pressure(&record(
            "red",
            ReclaimCapability::BallastOnly,
            Some(4096)
        )));

        let old: MountStateRecord = serde_json::from_str(
            r#"{"mount":"/","state":"observe_only","surface":"none","level":"orange","urgency":0.9}"#,
        )
        .unwrap();
        assert_eq!(old.reclaim_capability, ReclaimCapability::None);
        assert!(old.reserve_state.is_none());
    }
}
