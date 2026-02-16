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

/// Per-mount state for release/replenishment tracking.
#[derive(Debug, Default)]
struct MountReleaseState {
    /// When we last released ballast (for cooldown calculation).
    last_release_time: Option<Instant>,
    /// When pressure first returned to Green (for replenishment cooldown).
    green_since: Option<Instant>,
    /// Last time a file was replenished.
    last_replenish_time: Option<Instant>,
    /// Total files released since last full replenishment.
    files_released_since_green: usize,
}

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
            replenish_interval: Duration::from_secs(5 * 60), // 5 min between files
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
    ) -> usize {
        if available == 0 {
            return 0;
        }

        let pid_recommendation = response.release_ballast_files;

        // Graduated fallback based on urgency.
        let urgency_recommendation = if response.urgency < 0.3 {
            0
        } else if response.urgency < 0.6 {
            1
        } else if response.urgency < 0.9 {
            3
        } else {
            available // Emergency
        };

        // Safety floor based on pressure level.
        let level_floor = match response.level {
            PressureLevel::Critical => available, // Always release all on Critical
            PressureLevel::Red => 3,              // Always release at least 3 on Red
            PressureLevel::Orange => 1,           // Always release at least 1 on Orange
            _ => 0,
        };

        // Take the maximum of all signals to ensure safety.
        let target_released = pid_recommendation
            .max(urgency_recommendation)
            .max(level_floor);

        // Get current state for this mount.
        let state = self.states.entry(mount_path.to_path_buf()).or_default();

        // Calculate how many MORE files need to be released to reach the target state.
        let needed = target_released.saturating_sub(state.files_released_since_green);

        needed.min(available)
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
        let to_release =
            self.files_to_release(mount_path, response, manager.available_count());

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
        state.files_released_since_green += count;
        // Reset green timer since we just released (we're under pressure).
        state.green_since = None;
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

    /// Check if a specific mount is ready for replenishment.
    pub fn is_ready_for_replenish(
        &mut self,
        mount_path: &Path,
        current_level: PressureLevel,
        current_files: usize,
        target_files: usize,
    ) -> bool {
        let state = self.states.entry(mount_path.to_path_buf()).or_default();

        // Only replenish when green.
        if current_level != PressureLevel::Green {
            state.green_since = None;
            return false;
        }

        // Track when we first reached green.
        let now = Instant::now();
        let green_since = *state.green_since.get_or_insert(now);

        // Cooldown: must be green for the full cooldown period.
        if now.duration_since(green_since) < self.replenish_cooldown {
            return false;
        }

        // Nothing to replenish if all configured files are present.
        if current_files >= target_files && state.files_released_since_green == 0 {
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
        state.files_released_since_green = state
            .files_released_since_green
            .saturating_sub(count);
    }

    /// Reset all state (e.g., after config reload).
    pub fn reset(&mut self) {
        self.states.clear();
    }

    /// How many files have been released since the last full green period (for specific mount).
    pub fn files_released_since_green(&self, mount_path: &Path) -> usize {
        self.states
            .get(mount_path)
            .map_or(0, |s| s.files_released_since_green)
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
            predicted_seconds: None,
        }
    }

    fn one_hour_ago() -> Instant {
        Instant::now()
            .checked_sub(Duration::from_secs(3_600))
            .expect("current instant must support one-hour subtraction in tests")
    }

    #[test]
    fn no_release_when_green() {
        let mut ctrl = BallastReleaseController::new(30);
        let response = test_response(PressureLevel::Green, 0.0, 0);
        assert_eq!(ctrl.files_to_release(Path::new("/test"), &response, 5), 0);
    }

    #[test]
    fn graduated_release_by_urgency() {
        let mut ctrl = BallastReleaseController::new(30);
        let mount = Path::new("/test");

        // Low urgency, PID says 0 -> use urgency fallback.
        let r = test_response(PressureLevel::Orange, 0.4, 0);
        assert_eq!(ctrl.files_to_release(mount, &r, 5), 1);

        let r = test_response(PressureLevel::Red, 0.7, 0);
        assert_eq!(ctrl.files_to_release(mount, &r, 5), 3);

        let r = test_response(PressureLevel::Critical, 0.95, 0);
        assert_eq!(ctrl.files_to_release(mount, &r, 5), 5); // all
    }

    #[test]
    fn respects_pid_recommendation() {
        let mut ctrl = BallastReleaseController::new(30);
        let r = test_response(PressureLevel::Orange, 0.5, 2);
        assert_eq!(ctrl.files_to_release(Path::new("/test"), &r, 5), 2);
    }

    #[test]
    fn release_capped_at_available() {
        let mut ctrl = BallastReleaseController::new(30);
        let r = test_response(PressureLevel::Critical, 1.0, 0);
        assert_eq!(ctrl.files_to_release(Path::new("/test"), &r, 2), 2); // only 2 available
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
        assert_eq!(ctrl.files_released_since_green(mount), 3);
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

        ctrl.states.entry(mount.to_path_buf()).or_default().green_since = Some(one_hour_ago());

        // Replenish one file.
        ctrl.maybe_replenish(mount, &mut mgr, PressureLevel::Green, &|| 50.0)
            .unwrap();
        let count_after_first = mgr.available_count();

        // Pressure rises — green_since resets.
        ctrl.maybe_replenish(mount, &mut mgr, PressureLevel::Orange, &|| 50.0)
            .unwrap();
        assert!(ctrl
            .states
            .get(mount)
            .and_then(|s| s.green_since)
            .is_none());

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
        state.files_released_since_green = 5;
        state.last_release_time = Some(Instant::now());
        state.green_since = Some(Instant::now());

        ctrl.reset();

        assert_eq!(ctrl.files_released_since_green(mount), 0);
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
        assert_eq!(ctrl.files_released_since_green(mount), 1);

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
        assert_eq!(ctrl.files_released_since_green(mount), 3);
    }
}
