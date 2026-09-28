//! Regression test: ballast release stability across daemon restarts.
#![allow(missing_docs)]

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::time::Duration;
    use storage_ballast_helper::ballast::manager::BallastManager;
    use storage_ballast_helper::ballast::release::BallastReleaseController;
    use storage_ballast_helper::core::config::BallastConfig;
    use storage_ballast_helper::monitor::pid::{PressureLevel, PressureResponse};

    fn test_config() -> BallastConfig {
        BallastConfig {
            file_count: 5,
            file_size_bytes: 4096 + 4096,
            replenish_cooldown_minutes: 0,
            auto_provision: true,
            overrides: BTreeMap::new(),
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

    #[test]
    fn restart_under_pressure_does_not_over_release() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), test_config()).unwrap();
        // Not a floor test: do not depend on how full the host running it is.
        mgr.set_provision_floor(0.0);
        mgr.provision(None).unwrap();
        let mount = dir.path();

        // 1. Initial run: Release 3 files (Red pressure).
        let mut ctrl = BallastReleaseController::new(0);
        let red_response = test_response(PressureLevel::Red, 0.7, 3);
        ctrl.maybe_release(mount, &mut mgr, &red_response).unwrap();

        // Verify state after initial release.
        assert_eq!(
            mgr.available_count(),
            2,
            "Should have 2 files remaining (5 - 3)"
        );

        // 2. Simulate restart: Create FRESH controller (empty state).
        // This forgets 'files_released_since_green'.
        let mut fresh_ctrl = BallastReleaseController::new(0);

        // 3. Pressure is still Red (target 3).
        // With old logic: available=2, released_since_green=0. Target=3. Needed=3. Release min(3, 2) = 2.
        // With new logic: available=2, configured=5. Missing=3. Target=3. Needed = 3 - 3 = 0.

        let report = fresh_ctrl
            .maybe_release(mount, &mut mgr, &red_response)
            .unwrap();

        // Should release NOTHING because we already have 3 missing (which meets the target of 3).
        if let Some(r) = report {
            assert_eq!(
                r.files_released, 0,
                "Should not release additional files after restart"
            );
        }

        assert_eq!(mgr.available_count(), 2, "Pool count should remain stable");
    }
}
