//! Pressure-responsive ballast release: PID-driven incremental deletion strategy
//! with cooldown-based automatic replenishment.
//!
//! Graduated release strategy based on PID urgency:
//! - 0.0..0.3: release 1 file
//! - 0.3..0.6: release 3 files
//! - 0.6..0.9: release half of remaining ballast
//! - 0.9..1.0: release ALL ballast (emergency)
//!
//! Replenishment only occurs when pressure stays Green for the configured cooldown
//! period, and is paused if pressure rises during the process.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::time::{Duration, Instant};

use crate::ballast::manager::{BallastManager, ReleaseReport};
use crate::core::errors::Result;
use crate::monitor::pid::{PressureLevel, PressureResponse};

// ──────────────────── release controller ────────────────────

/// Tracks release/replenishment state across monitoring loop iterations.
pub struct BallastReleaseController {
    /// When we last released ballast (for cooldown calculation).
    last_release_time: Option<Instant>,
    /// When pressure first returned to Green (for replenishment cooldown).
    green_since: Option<Instant>,
    /// Cooldown before replenishment begins after returning to green.
    replenish_cooldown: Duration,
    /// Minimum interval between individual file replenishments.
    replenish_interval: Duration,
    /// Last time a file was replenished.
    last_replenish_time: Option<Instant>,
    /// Total files released since last full replenishment.
    files_released_since_green: usize,
}

impl BallastReleaseController {
    /// Create a new controller with the given replenish cooldown (minutes).
    pub fn new(replenish_cooldown_minutes: u64) -> Self {
        Self {
            last_release_time: None,
            green_since: None,
            replenish_cooldown: Duration::from_secs(replenish_cooldown_minutes * 60),
            replenish_interval: Duration::from_secs(5 * 60), // 5 min between files
            last_replenish_time: None,
            files_released_since_green: 0,
        }
    }

    /// Determine how many ballast files to release based on PID urgency.
    ///
    /// Returns 0 if no release is needed (Green/Yellow with low urgency).
    pub fn files_to_release(&self, response: &PressureResponse, available: usize) -> usize {
        if available == 0 {
            return 0;
        }

        // Use the PID controller's own recommendation first.
        if response.release_ballast_files > 0 {
            return response.release_ballast_files.min(available);
        }

        // Graduated fallback based on urgency.
        let urgency = response.urgency;
        if urgency < 0.3 {
            0
        } else if urgency < 0.6 {
            1_usize.min(available)
        } else if urgency < 0.9 {
            3_usize.min(available)
        } else {
            // Emergency: release everything.
            available
        }
    }

    /// Execute a pressure-driven release cycle.
    ///
    /// Returns the release report if any files were released, or None.
    pub fn maybe_release(
        &mut self,
        manager: &mut BallastManager,
        response: &PressureResponse,
    ) -> Result<Option<ReleaseReport>> {
        let to_release = self.files_to_release(response, manager.available_count());

        if to_release == 0 {
            return Ok(None);
        }

        let report = manager.release(to_release)?;
        if report.files_released > 0 {
            self.last_release_time = Some(Instant::now());
            self.files_released_since_green += report.files_released;
            // Reset green timer since we just released (we're under pressure).
            self.green_since = None;
        }

        Ok(Some(report))
    }

    /// Check if conditions are met for replenishment and replenish one file.
    ///
    /// Returns true if a file was replenished.
    pub fn maybe_replenish(
        &mut self,
        manager: &mut BallastManager,
        current_level: PressureLevel,
        free_pct_check: &dyn Fn() -> f64,
    ) -> Result<bool> {
        // Only replenish when green.
        if current_level != PressureLevel::Green {
            self.green_since = None;
            return Ok(false);
        }

        // Track when we first reached green.
        let now = Instant::now();
        let green_since = *self.green_since.get_or_insert(now);

        // Cooldown: must be green for the full cooldown period.
        if now.duration_since(green_since) < self.replenish_cooldown {
            return Ok(false);
        }

        // Nothing to replenish if all files are present.
        if manager.available_count() >= manager.inventory().len()
            && self.files_released_since_green == 0
        {
            return Ok(false);
        }

        // Rate limit: one file every replenish_interval.
        if let Some(last) = self.last_replenish_time {
            if now.duration_since(last) < self.replenish_interval {
                return Ok(false);
            }
        }

        // Replenish one file (provision is idempotent — creates missing files).
        let report = manager.replenish(Some(free_pct_check))?;
        if report.files_created > 0 {
            self.last_replenish_time = Some(Instant::now());
            self.files_released_since_green =
                self.files_released_since_green.saturating_sub(report.files_created);
            return Ok(true);
        }

        Ok(false)
    }

    /// Reset all state (e.g., after config reload).
    pub fn reset(&mut self) {
        self.last_release_time = None;
        self.green_since = None;
        self.last_replenish_time = None;
        self.files_released_since_green = 0;
    }

    /// How many files have been released since the last full green period.
    pub fn files_released_since_green(&self) -> usize {
        self.files_released_since_green
    }
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ballast::manager::BallastManager;
    use crate::core::config::BallastConfig;

    fn test_config() -> BallastConfig {
        BallastConfig {
            file_count: 5,
            file_size_bytes: 4096 + 4096, // tiny files for tests
            replenish_cooldown_minutes: 0,
            auto_provision: true,
            overrides: std::collections::HashMap::new(),
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
        }
    }

    #[test]
    fn no_release_when_green() {
        let ctrl = BallastReleaseController::new(30);
        let response = test_response(PressureLevel::Green, 0.0, 0);
        assert_eq!(ctrl.files_to_release(&response, 5), 0);
    }

    #[test]
    fn graduated_release_by_urgency() {
        let ctrl = BallastReleaseController::new(30);

        // Low urgency, PID says 0 -> use urgency fallback.
        let r = test_response(PressureLevel::Orange, 0.4, 0);
        assert_eq!(ctrl.files_to_release(&r, 5), 1);

        let r = test_response(PressureLevel::Red, 0.7, 0);
        assert_eq!(ctrl.files_to_release(&r, 5), 3);

        let r = test_response(PressureLevel::Critical, 0.95, 0);
        assert_eq!(ctrl.files_to_release(&r, 5), 5); // all
    }

    #[test]
    fn respects_pid_recommendation() {
        let ctrl = BallastReleaseController::new(30);
        let r = test_response(PressureLevel::Orange, 0.5, 2);
        assert_eq!(ctrl.files_to_release(&r, 5), 2);
    }

    #[test]
    fn release_capped_at_available() {
        let ctrl = BallastReleaseController::new(30);
        let r = test_response(PressureLevel::Critical, 1.0, 0);
        assert_eq!(ctrl.files_to_release(&r, 2), 2); // only 2 available
    }

    #[test]
    fn maybe_release_deletes_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), test_config()).unwrap();
        mgr.provision(None).unwrap();
        assert_eq!(mgr.available_count(), 5);

        let mut ctrl = BallastReleaseController::new(0);
        let response = test_response(PressureLevel::Red, 0.7, 3);
        let report = ctrl.maybe_release(&mut mgr, &response).unwrap();

        assert!(report.is_some());
        let r = report.unwrap();
        assert_eq!(r.files_released, 3);
        assert_eq!(mgr.available_count(), 2);
        assert_eq!(ctrl.files_released_since_green(), 3);
    }

    #[test]
    fn replenish_requires_green_cooldown() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), test_config()).unwrap();
        mgr.provision(None).unwrap();

        // Release some files.
        let mut ctrl = BallastReleaseController::new(0); // 0 min cooldown
        let response = test_response(PressureLevel::Critical, 1.0, 5);
        ctrl.maybe_release(&mut mgr, &response).unwrap();
        assert_eq!(mgr.available_count(), 0);

        // Can't replenish while red.
        let replenished = ctrl
            .maybe_replenish(&mut mgr, PressureLevel::Red, &|| 50.0)
            .unwrap();
        assert!(!replenished);

        // Set green_since to the past to satisfy cooldown.
        ctrl.green_since = Some(Instant::now() - Duration::from_secs(3600));
        ctrl.last_replenish_time = None;

        let replenished = ctrl
            .maybe_replenish(&mut mgr, PressureLevel::Green, &|| 50.0)
            .unwrap();
        assert!(replenished);
        assert!(mgr.available_count() > 0);
    }

    #[test]
    fn replenish_pauses_when_pressure_rises() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), test_config()).unwrap();
        mgr.provision(None).unwrap();

        let mut ctrl = BallastReleaseController::new(0);
        let response = test_response(PressureLevel::Critical, 1.0, 5);
        ctrl.maybe_release(&mut mgr, &response).unwrap();

        ctrl.green_since = Some(Instant::now() - Duration::from_secs(3600));

        // Replenish one file.
        ctrl.maybe_replenish(&mut mgr, PressureLevel::Green, &|| 50.0)
            .unwrap();
        let count_after_first = mgr.available_count();

        // Pressure rises — green_since resets.
        ctrl.maybe_replenish(&mut mgr, PressureLevel::Orange, &|| 50.0)
            .unwrap();
        assert!(ctrl.green_since.is_none());

        // Even after setting green again, cooldown restarts.
        let replenished = ctrl
            .maybe_replenish(&mut mgr, PressureLevel::Green, &|| 50.0)
            .unwrap();
        assert!(!replenished);
        assert_eq!(mgr.available_count(), count_after_first);
    }

    #[test]
    fn reset_clears_state() {
        let mut ctrl = BallastReleaseController::new(30);
        ctrl.files_released_since_green = 5;
        ctrl.last_release_time = Some(Instant::now());
        ctrl.green_since = Some(Instant::now());

        ctrl.reset();

        assert_eq!(ctrl.files_released_since_green(), 0);
        assert!(ctrl.last_release_time.is_none());
        assert!(ctrl.green_since.is_none());
    }
}
