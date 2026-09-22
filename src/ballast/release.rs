//! Pressure-responsive ballast release: PID-driven incremental deletion strategy
//! with cooldown-based automatic replenishment.
//!
//! Graduated fallback release strategy based on PID urgency (when PID
//! controller itself recommends 0 files):
//! - 0.0..0.3: no release
//! - 0.3..0.6: release 1 file
//! - 0.6..0.9: release 3 files
//! - 0.9..1.0: release ALL ballast (emergency)
//!
//! Replenishment only occurs when pressure stays Green for the configured cooldown
//! period, and is paused if pressure rises during the process.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::ballast::manager::{BallastManager, ReleaseReport};
use crate::core::errors::Result;
use crate::monitor::pid::{PressureLevel, PressureResponse};

// ──────────────────── release controller ────────────────────

/// Minimum duration to wait after a release before measuring observed delta free (5 seconds).
pub const RELEASE_SETTLE_DURATION: Duration = Duration::from_secs(5);

/// A pending ballast release awaiting effectiveness measurement after the settle period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingRelease {
    /// Total bytes released in this measurement window.
    pub bytes_released: u64,
    /// Free bytes observed immediately before the release.
    pub free_before: u64,
    /// Timestamp of the latest release in the measurement window.
    pub released_at: Instant,
}

/// Per-mount state for release/replenishment tracking.
#[derive(Debug)]
struct MountReleaseState {
    /// When we last released ballast (for cooldown calculation).
    last_release_time: Option<Instant>,
    /// When pressure first returned to Green (for replenishment cooldown).
    green_since: Option<Instant>,
    /// Last time a file was replenished.
    last_replenish_time: Option<Instant>,
    /// Count of non-green ticks since green_since was set. Allows brief
    /// pressure spikes (e.g. compilation bursts) without resetting the
    /// entire replenishment cooldown.
    non_green_interruptions: u32,
    /// Files the daemon released on this mount since it was last Green for
    /// a full cooldown; reported so an operator can see what the reserve
    /// is rebuilding, not a cap on replenishment (a reserve short for any
    /// other reason is rebuilt too).
    released_since_green: usize,
    /// Observed release effectiveness EWMA (eta_m): delta_free / bytes_released.
    /// Prior 1.0, EWMA alpha 0.3, clamp [0.05, 1.0].
    release_efficiency: f64,
    /// Pending release awaiting the >= 5s settle measurement.
    pending_release: Option<PendingRelease>,
}

impl Default for MountReleaseState {
    fn default() -> Self {
        Self {
            last_release_time: None,
            green_since: None,
            last_replenish_time: None,
            non_green_interruptions: 0,
            released_since_green: 0,
            release_efficiency: 1.0,
            pending_release: None,
        }
    }
}

/// Non-Green ticks tolerated inside a replenish cooldown before it restarts.
///
/// Covers a compilation burst that spikes one mount to Yellow for a tick or
/// two without holding the reserve rebuild back for the whole cooldown again.
pub const TOLERATED_INTERRUPTIONS: u32 = 3;

/// Tracks release/replenishment state across monitoring loop iterations.
pub struct BallastReleaseController {
    states: HashMap<PathBuf, MountReleaseState>,
    /// Cooldown before replenishment begins after returning to green.
    replenish_cooldown: Duration,
    /// Minimum interval between individual file replenishments.
    replenish_interval: Duration,
}

impl BallastReleaseController {
    /// Create a new controller with the given replenish cooldown (minutes).
    pub fn new(replenish_cooldown_minutes: u64) -> Self {
        Self {
            states: HashMap::new(),
            replenish_cooldown: Duration::from_secs(replenish_cooldown_minutes * 60),
            replenish_interval: Duration::from_mins(5), // 5 min between files
        }
    }

    /// Determine how many ballast files to release based on PID urgency.
    ///
    /// Returns 0 if no release is needed (Green/Yellow with low urgency).
    pub fn files_to_release(
        &mut self,
        mount_path: &Path,
        response: &PressureResponse,
        available: usize,
        configured_total: usize,
    ) -> usize {
        if available == 0 {
            return 0;
        }

        // Emergency release follows actual inventory, including surplus files
        // left after a configuration change. A zero/shrunken configured pool
        // must never strand an otherwise releasable reserve under Critical.
        if response.level == PressureLevel::Critical || response.urgency >= 0.9 {
            return available;
        }

        // Missing files count as physically released, including across restarts.
        let already_released = configured_total.saturating_sub(available);
        let urgency_recommendation = if response.urgency >= 0.6 {
            3
        } else if response.urgency >= 0.3 {
            1
        } else {
            0
        };
        let level_floor = match response.level {
            PressureLevel::Red => 3,
            PressureLevel::Orange => 1,
            _ => 0,
        };
        let target_released = response
            .release_ballast_files
            .max(urgency_recommendation)
            .max(level_floor);

        let state = self.states.entry(mount_path.to_path_buf()).or_default();
        let eta = state.release_efficiency;
        // Scale the CUMULATIVE target before subtracting physical releases.
        // Four files released at eta=0.25 meet an Orange target of one, but
        // escalating to a target of three still needs eight more files. Scaling
        // only the deficit would mistakenly return zero after those four files.
        let scaled_target = if eta < 1.0 {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let count = ((target_released as f64) / eta).ceil() as usize;
            count
        } else {
            target_released
        };

        scaled_target
            .saturating_sub(already_released)
            .min(available)
    }

    /// Execute a pressure-driven release cycle.
    ///
    /// Returns the release report if any files were released, or None.
    pub fn maybe_release(
        &mut self,
        mount_path: &Path,
        manager: &mut BallastManager,
        response: &PressureResponse,
    ) -> Result<Option<ReleaseReport>> {
        let to_release = self.files_to_release(
            mount_path,
            response,
            manager.available_count(),
            manager.config().file_count,
        );

        if to_release == 0 {
            return Ok(None);
        }

        let report = manager.release(to_release)?;
        if report.files_released > 0 {
            self.on_released(mount_path, report.files_released);
        }

        Ok(Some(report))
    }

    /// Record a successful release event.
    pub fn on_released(&mut self, mount_path: &Path, count: usize) {
        let state = self.states.entry(mount_path.to_path_buf()).or_default();
        state.last_release_time = Some(Instant::now());
        // Reset green timer since we just released (we're under pressure).
        state.green_since = None;
        state.non_green_interruptions = 0;
        state.released_since_green = state.released_since_green.saturating_add(count);
    }

    /// Record a ballast release event and queue it for effectiveness measurement.
    pub fn record_release(
        &mut self,
        mount_path: &Path,
        bytes_released: u64,
        free_before: u64,
        now: Instant,
    ) {
        // A failed/empty release must not erase a real measurement in flight.
        if bytes_released == 0 {
            return;
        }

        // The new pre-release reading can settle an older completed window.
        // Otherwise combine overlapping releases instead of forgetting the
        // earlier bytes/baseline; wait five seconds after the LAST release.
        self.update_effectiveness(mount_path, free_before, now);
        let state = self.states.entry(mount_path.to_path_buf()).or_default();
        if let Some(pending) = state.pending_release.as_mut() {
            pending.bytes_released = pending.bytes_released.saturating_add(bytes_released);
            pending.released_at = pending.released_at.max(now);
        } else {
            state.pending_release = Some(PendingRelease {
                bytes_released,
                free_before,
                released_at: now,
            });
        }
    }

    /// Update release effectiveness on a tick if at least 5s has elapsed since release.
    /// Uses EWMA with alpha = 0.3, clamped to [0.05, 1.0]. Never blocks or sleeps.
    pub fn update_effectiveness(&mut self, mount_path: &Path, free_now: u64, now: Instant) -> f64 {
        let state = self.states.entry(mount_path.to_path_buf()).or_default();
        if let Some(pending) = state.pending_release
            && now.duration_since(pending.released_at) >= RELEASE_SETTLE_DURATION
        {
            let observed_delta = free_now.saturating_sub(pending.free_before);
            if pending.bytes_released > 0 {
                // Unrelated cleanup can free more than the ballast batch.
                // Bound the observation BEFORE smoothing so one such event
                // cannot wipe out the mount's low-effectiveness history.
                let observed_eta =
                    ((observed_delta as f64) / (pending.bytes_released as f64)).min(1.0);
                let alpha = 0.3;
                let new_eta =
                    f64::mul_add(1.0 - alpha, state.release_efficiency, alpha * observed_eta);
                state.release_efficiency = new_eta.clamp(0.05, 1.0);
            }
            state.pending_release = None;
        }
        state.release_efficiency
    }

    /// Get current release efficiency for `mount_path` (prior 1.0).
    #[must_use]
    pub fn release_efficiency(&self, mount_path: &Path) -> f64 {
        self.states
            .get(mount_path)
            .map_or(1.0, |s| s.release_efficiency)
    }

    /// Set release efficiency for `mount_path` (for test setup or persistence restore).
    pub fn set_release_efficiency(&mut self, mount_path: &Path, efficiency: f64) {
        let state = self.states.entry(mount_path.to_path_buf()).or_default();
        // NaN survives f64::clamp and would turn release counts into zero.
        // Invalid restored telemetry falls back to the unmeasured prior.
        state.release_efficiency = if efficiency.is_finite() {
            efficiency.clamp(0.05, 1.0)
        } else {
            1.0
        };
    }

    /// Feed one tick's pressure level for `mount_path`. Runs every tick from
    /// the daemon, whatever the mount's control state, so a Yellow or
    /// Orange excursion restarts the replenish cooldown even while the mount
    /// is reclaiming and no replenish is being considered. Up to
    /// [`TOLERATED_INTERRUPTIONS`] non-Green ticks inside a cooldown are
    /// forgiven; beyond that the cooldown starts over at the next Green.
    pub fn observe_level(&mut self, mount_path: &Path, current_level: PressureLevel) {
        let state = self.states.entry(mount_path.to_path_buf()).or_default();
        if current_level == PressureLevel::Green {
            state.green_since.get_or_insert_with(Instant::now);
            return;
        }
        if state.green_since.is_some() {
            state.non_green_interruptions += 1;
            if state.non_green_interruptions > TOLERATED_INTERRUPTIONS {
                state.green_since = None;
                state.non_green_interruptions = 0;
            }
        }
    }

    /// Files released on `mount_path` since it last completed a Green
    /// cooldown (what the reserve is rebuilding).
    #[must_use]
    pub fn released_since_green(&self, mount_path: &Path) -> usize {
        self.states
            .get(mount_path)
            .map_or(0, |state| state.released_since_green)
    }

    /// Check if conditions are met for replenishment and replenish one file.
    ///
    /// Returns true if a file was replenished.
    pub fn maybe_replenish(
        &mut self,
        mount_path: &Path,
        manager: &mut BallastManager,
        current_level: PressureLevel,
        free_pct_check: &dyn Fn() -> f64,
    ) -> Result<bool> {
        self.observe_level(mount_path, current_level);
        if !self.is_ready_for_replenish(
            mount_path,
            current_level,
            manager.available_count(),
            manager.config().file_count,
        ) {
            return Ok(false);
        }

        // Replenish at most one file per cycle to avoid a burst of disk activity.
        let report = manager.replenish_one(Some(free_pct_check))?;
        if report.files_created > 0 {
            self.on_replenished(mount_path, report.files_created);
            return Ok(true);
        }

        Ok(false)
    }

    /// Whether a mount may replenish one file now: Green, Green for the full
    /// cooldown (as fed by [`Self::observe_level`] every tick), short of its
    /// configured files, and past the per-file rate limit. Pure with
    /// respect to the cooldown: the observation happens in `observe_level`.
    pub fn is_ready_for_replenish(
        &mut self,
        mount_path: &Path,
        current_level: PressureLevel,
        current_files: usize,
        target_files: usize,
    ) -> bool {
        if current_level != PressureLevel::Green {
            return false;
        }
        let state = self.states.entry(mount_path.to_path_buf()).or_default();

        // Cooldown: must be green for the full cooldown period. An observer
        // that never saw Green (no observe_level call yet) is not ready.
        let now = Instant::now();
        let Some(green_since) = state.green_since else {
            return false;
        };
        if now.duration_since(green_since) < self.replenish_cooldown {
            return false;
        }

        // Nothing to replenish if all configured files are present.
        if current_files >= target_files {
            return false;
        }

        // Rate limit: one file every replenish_interval.
        if let Some(last) = state.last_replenish_time
            && now.duration_since(last) < self.replenish_interval
        {
            return false;
        }

        true
    }

    /// Record a successful replenishment event.
    pub fn on_replenished(&mut self, mount_path: &Path, count: usize) {
        let state = self.states.entry(mount_path.to_path_buf()).or_default();
        state.last_replenish_time = Some(Instant::now());
        state.released_since_green = state.released_since_green.saturating_sub(count);
    }

    /// Reset all state (e.g., after config reload).
    pub fn reset(&mut self) {
        self.states.clear();
    }
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::ballast::manager::BallastManager;
    use crate::core::config::BallastConfig;

    fn test_config() -> BallastConfig {
        BallastConfig {
            file_count: 5,
            file_size_bytes: 4096 + 4096, // tiny files for tests
            replenish_cooldown_minutes: 0,
            auto_provision: true,
            overrides: std::collections::BTreeMap::new(),
        }
    }

    fn test_response(level: PressureLevel, urgency: f64, release: usize) -> PressureResponse {
        PressureResponse {
            level,
            urgency,
            scan_interval: Duration::from_secs(1),
            release_ballast_files: release,
            max_delete_batch: 10,
            fallback_active: false,
            causing_mount: PathBuf::from("/test"),
            free_pct: 5.0,
            predicted_seconds: None,
        }
    }

    fn one_hour_ago() -> Instant {
        Instant::now()
            .checked_sub(Duration::from_hours(1))
            .expect("current instant must support one-hour subtraction in tests")
    }

    /// The cooldown is fed by `observe_level` every tick, so an excursion
    /// while the mount is reclaiming (when the daemon never asks about
    /// replenishment) still restarts it; brief spikes are forgiven; a mount
    /// that was never seen Green is not ready; the released-since-Green
    /// count follows releases and replenishments.
    #[test]
    fn interruptions_observed_on_every_tick_restart_the_cooldown() {
        let mount = Path::new("/test");
        let mut ctrl = BallastReleaseController::new(0);
        ctrl.replenish_cooldown = Duration::from_millis(40);
        ctrl.replenish_interval = Duration::ZERO;

        // Never observed: not ready even at Green with files missing.
        assert!(!ctrl.is_ready_for_replenish(mount, PressureLevel::Green, 3, 5));

        // Green long enough: ready.
        ctrl.observe_level(mount, PressureLevel::Green);
        std::thread::sleep(Duration::from_millis(50));
        assert!(ctrl.is_ready_for_replenish(mount, PressureLevel::Green, 3, 5));
        assert!(!ctrl.is_ready_for_replenish(mount, PressureLevel::Green, 5, 5));

        // Three Yellow ticks are forgiven: the cooldown keeps its start.
        for _ in 0..TOLERATED_INTERRUPTIONS {
            ctrl.observe_level(mount, PressureLevel::Yellow);
        }
        ctrl.observe_level(mount, PressureLevel::Green);
        assert!(ctrl.is_ready_for_replenish(mount, PressureLevel::Green, 3, 5));

        // A fourth non-Green tick (an Orange episode the mount reclaims
        // through) restarts it: not ready until a full cooldown of Green.
        ctrl.observe_level(mount, PressureLevel::Orange);
        ctrl.observe_level(mount, PressureLevel::Green);
        assert!(!ctrl.is_ready_for_replenish(mount, PressureLevel::Green, 3, 5));
        std::thread::sleep(Duration::from_millis(50));
        assert!(ctrl.is_ready_for_replenish(mount, PressureLevel::Green, 3, 5));

        // Not Green right now: never ready, whatever the history.
        assert!(!ctrl.is_ready_for_replenish(mount, PressureLevel::Yellow, 3, 5));

        // Releases count towards what the reserve is rebuilding; a release
        // also restarts the cooldown.
        ctrl.on_released(mount, 2);
        assert_eq!(ctrl.released_since_green(mount), 2);
        assert!(!ctrl.is_ready_for_replenish(mount, PressureLevel::Green, 3, 5));
        ctrl.on_replenished(mount, 1);
        assert_eq!(ctrl.released_since_green(mount), 1);
        ctrl.on_replenished(mount, 5);
        assert_eq!(ctrl.released_since_green(mount), 0);
        assert_eq!(ctrl.released_since_green(Path::new("/other")), 0);
    }

    #[test]
    fn no_release_when_green() {
        let mut ctrl = BallastReleaseController::new(30);
        let response = test_response(PressureLevel::Green, 0.0, 0);
        assert_eq!(
            ctrl.files_to_release(Path::new("/test"), &response, 5, 5),
            0
        );
    }

    #[test]
    fn graduated_release_by_urgency() {
        let mut ctrl = BallastReleaseController::new(30);
        let mount = Path::new("/test");

        // Low urgency, PID says 0 -> use urgency fallback.
        let r = test_response(PressureLevel::Orange, 0.4, 0);
        assert_eq!(ctrl.files_to_release(mount, &r, 5, 5), 1);

        let r = test_response(PressureLevel::Red, 0.7, 0);
        assert_eq!(ctrl.files_to_release(mount, &r, 5, 5), 3);

        let r = test_response(PressureLevel::Critical, 0.95, 0);
        assert_eq!(ctrl.files_to_release(mount, &r, 5, 5), 5); // all
    }

    #[test]
    fn respects_pid_recommendation() {
        let mut ctrl = BallastReleaseController::new(30);
        let r = test_response(PressureLevel::Orange, 0.5, 2);
        assert_eq!(ctrl.files_to_release(Path::new("/test"), &r, 5, 5), 2);
    }

    #[test]
    fn release_capped_at_available() {
        let mut ctrl = BallastReleaseController::new(30);
        let r = test_response(PressureLevel::Critical, 1.0, 0);
        assert_eq!(ctrl.files_to_release(Path::new("/test"), &r, 2, 2), 2); // only 2 available
    }

    #[test]
    fn maybe_release_deletes_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), test_config()).unwrap();
        mgr.provision(None).unwrap();
        assert_eq!(mgr.available_count(), 5);

        let mut ctrl = BallastReleaseController::new(0);
        let response = test_response(PressureLevel::Red, 0.7, 3);
        let mount = dir.path();

        let report = ctrl.maybe_release(mount, &mut mgr, &response).unwrap();

        assert!(report.is_some());
        let r = report.unwrap();
        assert_eq!(r.files_released, 3);
        assert_eq!(mgr.available_count(), 2);
    }

    #[test]
    fn replenish_requires_green_cooldown() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), test_config()).unwrap();
        mgr.provision(None).unwrap();
        let mount = dir.path();

        // Release some files.
        let mut ctrl = BallastReleaseController::new(0); // 0 min cooldown
        let response = test_response(PressureLevel::Critical, 1.0, 5);
        ctrl.maybe_release(mount, &mut mgr, &response).unwrap();
        assert_eq!(mgr.available_count(), 0);

        // Can't replenish while red.
        let replenished = ctrl
            .maybe_replenish(mount, &mut mgr, PressureLevel::Red, &|| 50.0)
            .unwrap();
        assert!(!replenished);

        // Set green_since to the past to satisfy cooldown.
        let state = ctrl.states.entry(mount.to_path_buf()).or_default();
        state.green_since = Some(one_hour_ago());
        state.last_replenish_time = None;

        let replenished = ctrl
            .maybe_replenish(mount, &mut mgr, PressureLevel::Green, &|| 50.0)
            .unwrap();
        assert!(replenished);
        assert!(mgr.available_count() > 0);
    }

    #[test]
    fn replenish_pauses_when_pressure_rises() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), test_config()).unwrap();
        mgr.provision(None).unwrap();
        let mount = dir.path();

        let mut ctrl = BallastReleaseController::new(0);
        let response = test_response(PressureLevel::Critical, 1.0, 5);
        ctrl.maybe_release(mount, &mut mgr, &response).unwrap();

        ctrl.states
            .entry(mount.to_path_buf())
            .or_default()
            .green_since = Some(one_hour_ago());

        // Replenish one file.
        ctrl.maybe_replenish(mount, &mut mgr, PressureLevel::Green, &|| 50.0)
            .unwrap();
        let count_after_first = mgr.available_count();

        // Brief pressure spike is tolerated (up to 3 interruptions).
        ctrl.maybe_replenish(mount, &mut mgr, PressureLevel::Orange, &|| 50.0)
            .unwrap();
        assert!(ctrl.states.get(mount).and_then(|s| s.green_since).is_some());

        // 4+ interruptions reset green_since.
        ctrl.maybe_replenish(mount, &mut mgr, PressureLevel::Orange, &|| 50.0)
            .unwrap();
        ctrl.maybe_replenish(mount, &mut mgr, PressureLevel::Orange, &|| 50.0)
            .unwrap();
        ctrl.maybe_replenish(mount, &mut mgr, PressureLevel::Orange, &|| 50.0)
            .unwrap();
        assert!(ctrl.states.get(mount).and_then(|s| s.green_since).is_none());

        // Even after setting green again, cooldown restarts.
        let replenished = ctrl
            .maybe_replenish(mount, &mut mgr, PressureLevel::Green, &|| 50.0)
            .unwrap();
        assert!(!replenished);
        assert_eq!(mgr.available_count(), count_after_first);
    }

    #[test]
    fn replenish_detects_externally_deleted_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), test_config()).unwrap();
        mgr.provision(None).unwrap();
        let mount = dir.path();

        // Externally delete 3 ballast files.
        let files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                e.path()
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("SBH_BALLAST_FILE_"))
            })
            .take(3)
            .collect();
        assert_eq!(files.len(), 3);
        for f in &files {
            std::fs::remove_file(f.path()).unwrap();
        }

        let mut mgr = BallastManager::new(dir.path().to_path_buf(), test_config()).unwrap();
        assert_eq!(mgr.available_count(), 2);

        let mut ctrl = BallastReleaseController::new(0);
        let state = ctrl.states.entry(mount.to_path_buf()).or_default();
        state.green_since = Some(one_hour_ago());

        let replenished = ctrl
            .maybe_replenish(mount, &mut mgr, PressureLevel::Green, &|| 50.0)
            .unwrap();
        assert!(replenished);
        assert!(mgr.available_count() > 2);
    }

    #[test]
    fn reset_clears_state() {
        let mut ctrl = BallastReleaseController::new(30);
        let mount = Path::new("/test");
        let state = ctrl.states.entry(mount.to_path_buf()).or_default();
        state.last_release_time = Some(Instant::now());
        state.green_since = Some(Instant::now());

        ctrl.reset();

        assert!(ctrl.states.is_empty());
    }

    #[test]
    fn continuous_pressure_does_not_drain_pool_if_target_reached() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), test_config()).unwrap();
        mgr.provision(None).unwrap();
        assert_eq!(mgr.available_count(), 5);

        let mut ctrl = BallastReleaseController::new(0);
        let mount = dir.path();
        // Orange pressure recommends releasing 1 file (target=1).
        let response = test_response(PressureLevel::Orange, 0.5, 1);

        // Tick 1
        ctrl.maybe_release(mount, &mut mgr, &response).unwrap();
        assert_eq!(mgr.available_count(), 4);

        // Tick 2
        ctrl.maybe_release(mount, &mut mgr, &response).unwrap();
        // BUG FIXED: target is 1, already released 1 -> needed 0.
        assert_eq!(mgr.available_count(), 4);

        // Tick 3
        ctrl.maybe_release(mount, &mut mgr, &response).unwrap();
        assert_eq!(mgr.available_count(), 4);

        // Now escalate to Red (target 3).
        let red_response = test_response(PressureLevel::Red, 0.7, 3);
        ctrl.maybe_release(mount, &mut mgr, &red_response).unwrap();
        // Should release 2 more to reach 3 total.
        assert_eq!(mgr.available_count(), 2);
    }

    #[test]
    fn with_eta_0_25_controller_requests_4x_files_capped() {
        let mut ctrl = BallastReleaseController::new(30);
        let mount = Path::new("/test");
        ctrl.set_release_efficiency(mount, 0.25);

        // Target 1 file (Orange pressure)
        let r = test_response(PressureLevel::Orange, 0.4, 0);
        // With 10 available, 1 / 0.25 = 4 files requested
        assert_eq!(ctrl.files_to_release(mount, &r, 10, 10), 4);

        // When only 3 files are available in a 3-file pool, capped at available count
        assert_eq!(ctrl.files_to_release(mount, &r, 3, 3), 3);
    }

    #[test]
    fn effectiveness_settle_measurement_and_ewma() {
        let mut ctrl = BallastReleaseController::new(30);
        let mount = Path::new("/test");
        let start = Instant::now();

        // 100 MB released when free was 1000 MB
        ctrl.record_release(mount, 100_000_000, 1_000_000_000, start);

        // Tick before 5s settle duration: no change
        let free_at_4s = 1_025_000_000; // only 25 MB freed
        let eta_early =
            ctrl.update_effectiveness(mount, free_at_4s, start + Duration::from_secs(4));
        assert!((eta_early - 1.0).abs() < 1e-6);

        // Tick after 5s settle duration: observed eta = 25 MB / 100 MB = 0.25
        // EWMA: 0.3 * 0.25 + 0.7 * 1.0 = 0.075 + 0.700 = 0.775
        let eta_settled =
            ctrl.update_effectiveness(mount, free_at_4s, start + Duration::from_secs(6));
        assert!((eta_settled - 0.775).abs() < 1e-6);
        assert_eq!(ctrl.release_efficiency(mount), eta_settled);
    }

    #[test]
    fn ineffective_releases_scale_the_cumulative_target_on_escalation() {
        let mut ctrl = BallastReleaseController::new(30);
        let mount = Path::new("/test");
        ctrl.set_release_efficiency(mount, 0.25);
        let orange = test_response(PressureLevel::Orange, 0.4, 1);
        let red = test_response(PressureLevel::Red, 0.7, 3);

        assert_eq!(ctrl.files_to_release(mount, &orange, 20, 20), 4);
        assert_eq!(ctrl.files_to_release(mount, &orange, 16, 20), 0);
        assert_eq!(ctrl.files_to_release(mount, &red, 16, 20), 8);
        assert_eq!(ctrl.files_to_release(mount, &red, 8, 20), 0);
    }

    #[test]
    fn settled_ineffectiveness_reopens_an_unmet_release_target() {
        let mut ctrl = BallastReleaseController::new(30);
        let mount = Path::new("/test");
        let orange = test_response(PressureLevel::Orange, 0.4, 1);
        let now = Instant::now();

        assert_eq!(ctrl.files_to_release(mount, &orange, 10, 10), 1);
        ctrl.record_release(mount, 100, 1_000, now);
        assert_eq!(ctrl.files_to_release(mount, &orange, 9, 10), 0);
        // A snapshot-pinned release freed nothing: the EWMA falls to 0.7.
        ctrl.update_effectiveness(mount, 1_000, now + RELEASE_SETTLE_DURATION);
        assert_eq!(ctrl.files_to_release(mount, &orange, 9, 10), 1);
        assert_eq!(ctrl.files_to_release(mount, &orange, 8, 10), 0);
    }

    #[test]
    fn scaled_targets_are_bounded_and_do_not_repeat_at_steady_pressure() {
        let mount = Path::new("/test");
        for eta in [0.05, 0.25, 0.5, 0.75, 1.0] {
            let mut ctrl = BallastReleaseController::new(30);
            ctrl.set_release_efficiency(mount, eta);
            for total in 0..=32 {
                for available in 0..=total {
                    for target in 0..=8 {
                        let response = test_response(PressureLevel::Green, 0.0, target);
                        let count = ctrl.files_to_release(mount, &response, available, total);
                        assert!(count <= available);
                        assert_eq!(
                            ctrl.files_to_release(mount, &response, available - count, total),
                            0,
                            "eta={eta}, total={total}, available={available}, target={target}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn emergency_releases_actual_inventory_after_config_shrink() {
        let mut ctrl = BallastReleaseController::new(30);
        let mount = Path::new("/test");
        let critical = test_response(PressureLevel::Critical, 0.0, 0);
        let urgent = test_response(PressureLevel::Red, 0.95, 0);
        for configured in [0, 1, 3, 5, 10] {
            assert_eq!(ctrl.files_to_release(mount, &critical, 5, configured), 5);
            assert_eq!(ctrl.files_to_release(mount, &urgent, 5, configured), 5);
        }
    }

    #[test]
    fn invalid_efficiency_cannot_disable_pressure_release() {
        let mut ctrl = BallastReleaseController::new(30);
        let mount = Path::new("/test");
        let response = test_response(PressureLevel::Orange, 0.4, 1);
        for efficiency in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            ctrl.set_release_efficiency(mount, efficiency);
            assert_eq!(ctrl.release_efficiency(mount), 1.0);
            assert_eq!(ctrl.files_to_release(mount, &response, 10, 10), 1);
        }
        // An invalid urgency alone does not fabricate an emergency at Green.
        let unknown = test_response(PressureLevel::Green, f64::NAN, 0);
        assert_eq!(ctrl.files_to_release(mount, &unknown, 10, 10), 0);
    }

    #[test]
    fn overlapping_releases_preserve_bytes_baseline_and_last_settle_time() {
        let mut ctrl = BallastReleaseController::new(30);
        let mount = Path::new("/test");
        let now = Instant::now();
        ctrl.record_release(mount, 100, 1_000, now);
        ctrl.record_release(mount, 300, 1_025, now + Duration::from_secs(3));
        assert_eq!(
            ctrl.states[mount].pending_release,
            Some(PendingRelease {
                bytes_released: 400,
                free_before: 1_000,
                released_at: now + Duration::from_secs(3),
            })
        );
        assert_eq!(
            ctrl.update_effectiveness(mount, 1_025, now + Duration::from_secs(6)),
            1.0
        );
        // 25 observed bytes out of 400 released: eta = 0.7 + 0.3 * 0.0625.
        let eta = ctrl.update_effectiveness(mount, 1_025, now + Duration::from_secs(8));
        assert!((eta - 0.71875).abs() < 1e-6);
        assert!(ctrl.states[mount].pending_release.is_none());
        assert_eq!(
            ctrl.update_effectiveness(mount, 2_000, now + Duration::from_secs(20)),
            eta
        );
    }

    #[test]
    fn subsequent_release_settles_a_completed_measurement_first() {
        let mut ctrl = BallastReleaseController::new(30);
        let mount = Path::new("/test");
        let now = Instant::now();
        ctrl.record_release(mount, 100, 1_000, now);
        ctrl.record_release(mount, 100, 1_025, now + Duration::from_secs(6));
        assert!((ctrl.release_efficiency(mount) - 0.775).abs() < 1e-6);
        let eta = ctrl.update_effectiveness(mount, 1_050, now + Duration::from_secs(11));
        assert!((eta - 0.6175).abs() < 1e-6);
    }

    #[test]
    fn empty_release_does_not_replace_pending_measurement() {
        let mut ctrl = BallastReleaseController::new(30);
        let mount = Path::new("/test");
        let now = Instant::now();
        ctrl.record_release(mount, 100, 1_000, now);
        ctrl.record_release(mount, 0, 5_000, now + Duration::from_secs(4));
        let eta = ctrl.update_effectiveness(mount, 1_025, now + RELEASE_SETTLE_DURATION);
        assert!((eta - 0.775).abs() < 1e-6);
    }

    #[test]
    fn unrelated_cleanup_does_not_erase_low_efficiency_history() {
        let mut ctrl = BallastReleaseController::new(30);
        let mount = Path::new("/test");
        let now = Instant::now();
        ctrl.set_release_efficiency(mount, 0.25);
        ctrl.record_release(mount, 100, 1_000, now);
        let eta = ctrl.update_effectiveness(mount, 2_000, now + RELEASE_SETTLE_DURATION);
        assert!((eta - 0.475).abs() < 1e-6);
        // Samples for another mount do not contaminate this mount's history.
        assert_eq!(ctrl.release_efficiency(Path::new("/other")), 1.0);
    }
}
