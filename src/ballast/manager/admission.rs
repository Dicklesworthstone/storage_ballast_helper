//! Fail-closed, per-file headroom admission against a fresh capacity reading.
//!
//! A caller's percentage can make the bound stricter, never override the actual
//! filesystem. Missing callbacks do not disable the reserve's headroom floor.

use super::{Admission, BallastManager};
use crate::core::errors::{Result, SbhError};
use crate::platform::pal::FsStats;

// A million units per percentage point. Round floors upward and caller-provided
// availability downward, then do the byte arithmetic in u128. This avoids losing
// small files in floating-point subtraction on volumes larger than 2^53 bytes.
const UNITS_PER_PERCENT: u64 = 1_000_000;
const PERCENT_DENOMINATOR: u128 = 100_000_000;

pub(super) fn check(
    manager: &BallastManager,
    free_pct_check: Option<&dyn Fn() -> f64>,
) -> Result<Admission> {
    let caller_pct = free_pct_check.map(|check| check());
    // Probe after the caller: even a cached optimistic callback cannot mask a
    // newly-full or read-only filesystem. Never turn a failed probe into zero
    // cost for the candidate file.
    let stats = manager.platform.fs_stats(&manager.ballast_dir)?;
    evaluate(
        &stats,
        manager.config.file_size_bytes,
        manager.provision_floor_pct,
        caller_pct,
    )
    .map_err(|details| SbhError::FsStats {
        path: manager.ballast_dir.clone(),
        details: format!("cannot establish ballast headroom: {details}"),
    })
}

fn evaluate(
    stats: &FsStats,
    file_bytes: u64,
    floor_pct: f64,
    caller_pct: Option<f64>,
) -> std::result::Result<Admission, &'static str> {
    if stats.is_readonly {
        return Err("filesystem is read-only");
    }
    if stats.total_bytes == 0 || stats.available_bytes > stats.total_bytes {
        return Err("invalid filesystem capacity");
    }
    if !valid_pct(floor_pct) {
        return Err("invalid provisioning floor");
    }
    if caller_pct.is_some_and(|pct| !valid_pct(pct)) {
        return Err("invalid caller free-space reading");
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let floor_units = (floor_pct * UNITS_PER_PERCENT as f64).ceil() as u64;
    let total = u128::from(stats.total_bytes);
    let floor_bytes = (total * u128::from(floor_units)).div_ceil(PERCENT_DENOMINATOR);
    let mut available = u128::from(stats.available_bytes);
    if let Some(pct) = caller_pct {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let units = (pct * UNITS_PER_PERCENT as f64).floor() as u64;
        available = available.min(total * u128::from(units) / PERCENT_DENOMINATOR);
    }
    let cost = u128::from(file_bytes);
    let after = available.saturating_sub(cost);
    #[allow(clippy::cast_precision_loss)]
    let free_pct_after = after as f64 / stats.total_bytes as f64 * 100.0;
    // The explicit cost check matters at a zero-percent floor: saturation
    // must not admit a file larger than all the remaining available space.
    if cost <= available && after >= floor_bytes {
        Ok(Admission::Admit {
            free_pct_after: Some(free_pct_after),
        })
    } else {
        Ok(Admission::Refuse { free_pct_after })
    }
}

fn valid_pct(pct: f64) -> bool {
    pct.is_finite() && (0.0..=100.0).contains(&pct)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::BallastConfig;
    use crate::platform::pal::{MemoryInfo, MockPlatform, MountPoint, Platform, PlatformPaths};
    use std::collections::{BTreeMap, HashMap};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    fn stats(total: u64, available: u64) -> FsStats {
        FsStats {
            total_bytes: total,
            free_bytes: available,
            available_bytes: available,
            fs_type: "mockfs".to_string(),
            mount_point: PathBuf::from("/"),
            is_readonly: false,
        }
    }

    fn platform(root: &Path, reading: Option<FsStats>) -> Arc<dyn Platform> {
        let mut readings = HashMap::new();
        if let Some(reading) = reading {
            readings.insert(PathBuf::from("/"), reading);
        }
        let mut platform = MockPlatform::new(
            vec![MountPoint {
                path: PathBuf::from("/"),
                device: "mockdev".to_string(),
                fs_type: "mockfs".to_string(),
                is_ram_backed: false,
            }],
            readings,
            MemoryInfo {
                total_bytes: 1 << 30,
                available_bytes: 1 << 29,
                swap_total_bytes: 0,
                swap_free_bytes: 0,
            },
            PlatformPaths::default(),
        );
        // MockPlatform does not inspect the real filesystem for block counts.
        // Each 8192-byte test file has 16 blocks; without these explicit values
        // every otherwise-valid file is classified as sparse and rebuilt again.
        for index in 1..=3 {
            platform = platform.with_block_count(
                root.join(format!("SBH_BALLAST_FILE_{index:05}.dat")),
                16,
            );
        }
        Arc::new(platform)
    }

    fn manager(root: &Path, reading: Option<FsStats>) -> BallastManager {
        let mut manager = BallastManager::with_platform(
            root.to_path_buf(),
            BallastConfig {
                file_count: 3,
                file_size_bytes: 8192,
                replenish_cooldown_minutes: 0,
                auto_provision: true,
                overrides: BTreeMap::new(),
            },
            platform(root, reading),
        )
        .unwrap();
        manager.set_provision_floor(10.0);
        manager.set_skip_fallocate(true);
        manager
    }

    fn admitted(result: std::result::Result<Admission, &'static str>) -> bool {
        matches!(result, Ok(Admission::Admit { .. }))
    }

    #[test]
    fn absent_callback_still_checks_the_live_floor() {
        let temp = tempfile::tempdir().unwrap();
        let mut manager = manager(temp.path(), Some(stats(1_000_000, 90_000)));
        for gradual in [false, true] {
            let report = if gradual {
                manager.replenish_one(None)
            } else {
                manager.provision(None)
            }
            .unwrap();
            assert_eq!(report.files_created, 0);
            assert_eq!(report.skipped_for_floor, 3);
            assert!(report.errors.is_empty());
            assert!(!manager.file_path(1).exists());
        }
    }

    #[test]
    fn missing_capacity_never_becomes_zero_allocation_cost() {
        let temp = tempfile::tempdir().unwrap();
        let mut manager = manager(temp.path(), None);
        let report = manager.provision(Some(&|| 99.0)).unwrap();
        assert_eq!(report.files_created, 0);
        assert_eq!(report.errors.len(), 1);
        assert_eq!(
            report.skipped_for_floor, 0,
            "unknown is not a measured floor refusal"
        );
        assert_eq!(report.free_pct_after, None);
        assert!(!manager.file_path(1).exists());
        assert_eq!(manager.replenish_one(None).unwrap().files_created, 0);
    }

    #[test]
    fn optimistic_cached_percentage_cannot_override_live_capacity() {
        let temp = tempfile::tempdir().unwrap();
        let mut manager = manager(temp.path(), Some(stats(1_000_000, 90_000)));
        let report = manager.provision(Some(&|| 99.0)).unwrap();
        assert_eq!(report.files_created, 0);
        assert!(report.skipped_for_floor > 0);
        assert!(!manager.file_path(1).exists());
    }

    #[test]
    fn more_conservative_callback_remains_a_veto() {
        let temp = tempfile::tempdir().unwrap();
        let mut manager = manager(temp.path(), Some(stats(1_000_000, 800_000)));
        let report = manager.provision(Some(&|| 9.0)).unwrap();
        assert_eq!(report.files_created, 0);
        assert_eq!(report.skipped_for_floor, 3);
    }

    #[test]
    fn damaged_existing_reserve_survives_a_headroom_refusal() {
        for gradual in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("SBH_BALLAST_FILE_00001.dat");
            fs::write(&path, b"damaged but still releasable reserve").unwrap();
            let mut manager = manager(temp.path(), Some(stats(1_000_000, 90_000)));
            let report = if gradual {
                manager.replenish_one(None)
            } else {
                manager.provision(None)
            }
            .unwrap();
            assert_eq!(report.files_created, 0);
            assert!(report.skipped_for_floor > 0);
            let retained = fs::read(path).unwrap();
            assert_eq!(retained, b"damaged but still releasable reserve");
        }
    }

    #[test]
    fn damaged_existing_reserve_survives_a_capacity_probe_failure() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("SBH_BALLAST_FILE_00001.dat");
        fs::write(&path, b"reserve").unwrap();
        let mut manager = manager(temp.path(), None);
        let report = manager.replenish_one(Some(&|| 100.0)).unwrap();
        assert_eq!(report.files_created, 0);
        assert_eq!(report.errors.len(), 1);
        assert_eq!(fs::read(path).unwrap(), b"reserve");
    }

    #[test]
    fn invalid_capacity_and_readonly_mounts_stop_real_provisioning() {
        let readonly = FsStats {
            is_readonly: true,
            ..stats(1_000_000, 800_000)
        };
        for reading in [stats(0, 0), stats(100, 101), readonly] {
            let temp = tempfile::tempdir().unwrap();
            let mut manager = manager(temp.path(), Some(reading));
            let report = manager.provision(Some(&|| 100.0)).unwrap();
            assert_eq!(report.files_created, 0);
            assert_eq!(report.errors.len(), 1);
            assert_eq!(report.skipped_for_floor, 0);
            assert!(!manager.file_path(1).exists());
        }
    }

    #[test]
    fn invalid_caller_samples_never_admit_or_serialize_nonfinite_values() {
        for pct in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, 100.01] {
            let temp = tempfile::tempdir().unwrap();
            let mut manager = manager(temp.path(), Some(stats(1_000_000, 800_000)));
            let report = manager.replenish_one(Some(&|| pct)).unwrap();
            assert_eq!(report.files_created, 0);
            assert_eq!(report.errors.len(), 1);
            assert_eq!(report.free_pct_after, None);
        }
    }

    #[test]
    fn healthy_headroom_still_builds_and_repairs_one_file() {
        let temp = tempfile::tempdir().unwrap();
        let mut manager = manager(temp.path(), Some(stats(1_000_000, 800_000)));
        let first = manager.replenish_one(None).unwrap();
        assert_eq!(first.files_created, 1);
        assert!(first.errors.is_empty());
        fs::write(manager.file_path(1), b"bad").unwrap();
        let repaired = manager.replenish_one(None).unwrap();
        assert_eq!(repaired.files_created, 1);
        assert!(repaired.errors.is_empty());
        // The mock reports no allocated blocks; verify on the real platform.
        let on_disk =
            BallastManager::new(temp.path().to_path_buf(), manager.config().clone()).unwrap();
        let verified = on_disk.verify_single_file(&manager.file_path(1), 1);
        assert!(verified.is_ok(), "{verified:?}");
        assert!(!manager.file_path(2).exists());
    }

    #[test]
    fn gradual_refill_advances_past_valid_files_without_rewriting_them() {
        let temp = tempfile::tempdir().unwrap();
        let mut manager = manager(temp.path(), Some(stats(1_000_000, 800_000)));
        assert_eq!(manager.replenish_one(None).unwrap().files_created, 1);
        let first = fs::read(manager.file_path(1)).unwrap();
        for expected_count in [2, 3] {
            let report = manager.replenish_one(None).unwrap();
            assert_eq!(report.files_created, 1);
            assert_eq!(report.files_skipped, expected_count - 1);
            assert_eq!(manager.available_count(), expected_count);
            assert_eq!(fs::read(manager.file_path(1)).unwrap(), first);
        }
        let complete = manager.replenish_one(None).unwrap();
        assert_eq!(complete.files_created, 0);
        assert_eq!(complete.files_skipped, 3);
    }

    #[test]
    fn a_complete_valid_pool_needs_no_capacity_probe_to_remain_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let mut manager = manager(temp.path(), Some(stats(1_000_000, 800_000)));
        assert_eq!(manager.provision(None).unwrap().files_created, 3);
        let original = fs::read(manager.file_path(1)).unwrap();
        manager.platform = platform(temp.path(), None);
        let report = manager.provision(None).unwrap();
        assert_eq!(report.files_created, 0);
        assert_eq!(report.files_skipped, 3);
        assert!(report.errors.is_empty());
        assert_eq!(fs::read(manager.file_path(1)).unwrap(), original);
    }

    #[test]
    fn invalid_second_sample_preserves_the_completed_prefix_of_a_bulk_refill() {
        let temp = tempfile::tempdir().unwrap();
        let mut manager = manager(temp.path(), Some(stats(1_000_000, 800_000)));
        let calls = std::cell::Cell::new(0);
        let probe = || {
            calls.set(calls.get() + 1);
            if calls.get() == 1 { 80.0 } else { f64::NAN }
        };
        let report = manager.provision(Some(&probe)).unwrap();
        assert_eq!(calls.get(), 2);
        assert_eq!(report.files_created, 1);
        assert_eq!(report.total_bytes, 8192);
        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.skipped_for_floor, 0);
        assert!(manager.verify_single_file(&manager.file_path(1), 1).is_ok());
        assert!(!manager.file_path(2).exists());
        assert!(!manager.file_path(3).exists());
    }

    #[test]
    fn actual_file_cost_is_checked_even_when_the_caller_reports_full_headroom() {
        let temp = tempfile::tempdir().unwrap();
        // One byte short after paying for an 8192-byte file above the 10% floor.
        let mut manager = manager(temp.path(), Some(stats(1_000_000, 108_191)));
        let report = manager.replenish_one(Some(&|| 100.0)).unwrap();
        assert_eq!(report.files_created, 0);
        assert!(report.skipped_for_floor > 0);
        assert!(!manager.file_path(1).exists());
        manager.platform = platform(temp.path(), Some(stats(1_000_000, 108_192)));
        assert_eq!(manager.replenish_one(Some(&|| 100.0)).unwrap().files_created, 1);
    }

    #[test]
    fn exact_byte_boundary_admits_and_one_byte_less_refuses() {
        assert!(admitted(evaluate(&stats(1000, 110), 10, 10.0, None)));
        assert!(!admitted(evaluate(&stats(1000, 109), 10, 10.0, None)));
        assert!(!admitted(evaluate(&stats(1000, 100), 1, 10.0, None)));
    }

    #[test]
    fn zero_floor_does_not_admit_a_file_larger_than_available_space() {
        assert!(admitted(evaluate(&stats(1000, 10), 10, 0.0, None)));
        assert!(!admitted(evaluate(&stats(1000, 10), 11, 0.0, None)));
        assert!(!admitted(evaluate(&stats(1000, 0), 1, 0.0, None)));
    }

    #[test]
    fn large_volumes_do_not_round_the_next_file_cost_to_zero() {
        let full = stats(u64::MAX, u64::MAX);
        let empty = stats(u64::MAX, 0);
        assert!(!admitted(evaluate(&full, 1, 100.0, None)));
        assert!(!admitted(evaluate(&empty, u64::MAX, 0.0, None)));
        assert!(admitted(evaluate(&full, u64::MAX, 0.0, None)));
    }

    #[test]
    fn floor_rounds_up_and_available_percentage_rounds_down() {
        let at_floor = stats(1_000_000, 100_000);
        let ample = stats(1000, 900);
        assert!(!admitted(evaluate(&at_floor, 0, 10.000_000_1, None)));
        assert!(!admitted(evaluate(&ample, 1, 10.0, Some(10.099_999_9))));
        assert!(admitted(evaluate(&ample, 1, 10.0, Some(10.1))));
    }

    #[test]
    fn invalid_floor_setters_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let mut manager = manager(temp.path(), Some(stats(1_000_000, 800_000)));
        for invalid in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            manager.set_provision_floor(invalid);
            assert_eq!(manager.provision_floor_pct().to_bits(), 100.0_f64.to_bits());
            assert_eq!(manager.replenish_one(None).unwrap().files_created, 0);
        }
    }

    #[test]
    fn byte_admission_matches_an_integer_reference_across_boundaries() {
        for total in [1_u64, 997, 1_000_000, 1_u64 << 54, u64::MAX] {
            for pct in [0_u8, 6, 10, 14, 20, 99, 100] {
                let floor = (u128::from(total) * u128::from(pct)).div_ceil(100);
                for available in [0, total / 10, total / 2, total] {
                    for file in [0, 1, 8192, total] {
                        let expected = u128::from(available) >= u128::from(file) + floor;
                        let reading = stats(total, available);
                        assert_eq!(
                            admitted(evaluate(&reading, file, f64::from(pct), None)),
                            expected,
                            "total={total} free={available} file={file} floor={pct}"
                        );
                    }
                }
            }
        }
    }
}
