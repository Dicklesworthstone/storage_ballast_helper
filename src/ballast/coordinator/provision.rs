//! Grow only the uncovered portion of a pool's configured reserve.
//!
//! Adopted files already reserve space on this filesystem. Allocating a second
//! full pool wastes that headroom and can immediately trigger another release.
//! Credit verified bytes, never legacy file counts or a temporary smaller config:
//! lowering file_count would make the manager prune valid high-index files.

use super::BallastPool;
use crate::ballast::manager::{BallastManager, ProvisionReport};
use crate::core::errors::Result;

pub(super) fn provision(
    pool: &mut BallastPool,
    free_pct_check: Option<&dyn Fn() -> f64>,
) -> Result<ProvisionReport> {
    grow(pool, free_pct_check, usize::MAX)
}

pub(super) fn replenish_one(
    pool: &mut BallastPool,
    free_pct_check: Option<&dyn Fn() -> f64>,
) -> Result<ProvisionReport> {
    grow(pool, free_pct_check, 1)
}

fn empty_report(manager: &BallastManager) -> ProvisionReport {
    ProvisionReport {
        files_created: 0,
        files_skipped: 0,
        total_bytes: 0,
        errors: Vec::new(),
        skipped_for_floor: 0,
        floor_pct: manager.provision_floor_pct(),
        free_pct_after: None,
        created: Vec::new(),
    }
}

fn valid_managed_bytes(manager: &BallastManager) -> u64 {
    manager
        .inventory()
        .iter()
        .filter(|file| file.integrity_ok)
        .map(|file| file.size)
        .fold(0, u64::saturating_add)
}

fn missing_bytes(target: u64, adopted: u64, managed: u64) -> u64 {
    target.saturating_sub(adopted.saturating_add(managed))
}

fn grow(
    pool: &mut BallastPool,
    free_pct_check: Option<&dyn Fn() -> f64>,
    max_files: usize,
) -> Result<ProvisionReport> {
    if pool.stranded.files().is_empty() {
        // Preserve the manager's normal idempotent provision/repair behavior
        // when there is no retired reserve to credit.
        return if max_files == 1 {
            pool.manager.replenish_one(free_pct_check)
        } else {
            pool.manager.provision(free_pct_check)
        };
    }

    let mut report = empty_report(&pool.manager);
    report.errors = pool.stranded.refresh();
    if !report.errors.is_empty() {
        // Unknown is not empty. A provisioner holding an old pool's lock must
        // not cause us to allocate a duplicate pool, nor block this caller.
        return Ok(report);
    }

    // Updating with the SAME config performs the manager's read-only rescan.
    // Refresh external CLI releases/provisioning without changing its index
    // range, platform, allocation strategy, or configured headroom floor.
    let config = pool.manager.config().clone();
    pool.manager.update_config(config);
    report.files_skipped = pool
        .manager
        .inventory()
        .iter()
        .filter(|file| file.integrity_ok)
        .count();
    let target = pool.manager.configured_pool_bytes();
    let adopted = pool.stranded.bytes();

    for _ in 0..max_files.min(pool.expected_count()) {
        let before = valid_managed_bytes(&pool.manager);
        if missing_bytes(target, adopted, before) == 0 {
            break;
        }
        // Keep the full config. Each step still rechecks actual file integrity
        // and applies the live after-allocation free-space floor under .lock.
        let step = match pool.manager.replenish_one(free_pct_check) {
            Ok(step) => step,
            Err(error) => {
                report
                    .errors
                    .push(format!("reserve growth failed: {error}"));
                break;
            }
        };
        let made_progress = step.files_created > 0;
        let halt = !made_progress || !step.errors.is_empty() || step.skipped_for_floor > 0;
        report.files_created = report.files_created.saturating_add(step.files_created);
        report.total_bytes = report.total_bytes.saturating_add(step.total_bytes);
        report.skipped_for_floor = report
            .skipped_for_floor
            .saturating_add(step.skipped_for_floor);
        report.free_pct_after = step.free_pct_after.or(report.free_pct_after);
        report.errors.extend(step.errors);
        report.created.extend(step.created);
        if halt {
            break;
        }
        if valid_managed_bytes(&pool.manager) <= before {
            report.errors.push(
                "created ballast did not increase verified reserve; stopping growth".to_string(),
            );
            break;
        }
    }
    Ok(report)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::ballast::coordinator::{ProvisionStrategy, stranded::StrandedReserve};
    use crate::core::config::BallastConfig;
    use rustix::fs::{FlockOperation, flock};
    use std::collections::BTreeMap;
    use std::fs::{self, File};
    use std::path::{Path, PathBuf};

    const UNIT: u64 = 8192;

    fn config(count: usize, size: u64) -> BallastConfig {
        BallastConfig {
            file_count: count,
            file_size_bytes: size,
            replenish_cooldown_minutes: 0,
            auto_provision: true,
            overrides: BTreeMap::new(),
        }
    }

    fn fixture(
        count: usize,
        size: u64,
        retired_count: usize,
        retired_size: u64,
    ) -> (tempfile::TempDir, BallastPool) {
        let temp = tempfile::tempdir().unwrap();
        let active = temp.path().join("active");
        let retired = temp.path().join("retired");
        let mut legacy =
            BallastManager::new(retired.clone(), config(retired_count, retired_size)).unwrap();
        let report = legacy.provision(None).unwrap();
        assert_eq!(report.files_created, retired_count, "{report:?}");
        let stranded = StrandedReserve::discover(&[retired], &active, temp.path());
        assert_eq!(stranded.files().len(), retired_count);
        let mut manager = BallastManager::new(active.clone(), config(count, size)).unwrap();
        manager.set_provision_floor(0.0);
        let pool = BallastPool {
            mount_point: temp.path().to_path_buf(),
            ballast_dir: active,
            fs_type: "ext4".to_string(),
            strategy: ProvisionStrategy::Fallocate,
            manager,
            stranded,
        };
        (temp, pool)
    }

    fn file(dir: &Path, index: u32) -> PathBuf {
        dir.join(format!("SBH_BALLAST_FILE_{index:05}.dat"))
    }

    #[test]
    fn a_fully_adopted_reserve_does_not_allocate_a_second_pool() {
        let (_temp, mut pool) = fixture(3, UNIT, 1, 3 * UNIT);
        let report = provision(&mut pool, None).unwrap();
        assert_eq!(report.files_created, 0);
        assert_eq!(report.total_bytes, 0);
        assert!(report.errors.is_empty());
        assert!(!pool.ballast_dir.exists());
        assert_eq!(pool.expected_count(), 3, "configured intent is unchanged");
        assert_eq!(pool.releasable_bytes(), 3 * UNIT);
        assert_eq!(replenish_one(&mut pool, None).unwrap().files_created, 0);
        assert!(!pool.ballast_dir.exists());
    }

    #[test]
    fn partial_adoption_creates_only_the_rounded_up_byte_deficit() {
        let (_temp, mut pool) = fixture(5, UNIT, 1, UNIT + UNIT / 2);
        let report = provision(&mut pool, None).unwrap();
        assert_eq!(report.files_created, 4, "{report:?}");
        assert_eq!(report.total_bytes, 4 * UNIT);
        assert_eq!(report.created.len(), 4);
        assert!(report.errors.is_empty());
        assert_eq!(pool.expected_count(), 5);
        assert_eq!(pool.actual_count(), 4);
        assert_eq!(pool.stranded.files().len(), 1);
        assert!(!file(&pool.ballast_dir, 5).exists());
        assert!(pool.releasable_bytes() >= 5 * UNIT);
        assert!(pool.releasable_bytes() < 6 * UNIT);
    }

    #[test]
    fn many_small_legacy_files_do_not_satisfy_a_larger_byte_target() {
        let (_temp, mut pool) = fixture(3, 2 * UNIT, 4, UNIT);
        let report = provision(&mut pool, None).unwrap();
        assert_eq!(
            report.files_created, 1,
            "four old files cover only two new slots"
        );
        assert_eq!(report.total_bytes, 2 * UNIT);
        assert_eq!(pool.releasable_bytes(), 6 * UNIT);
    }

    #[test]
    fn daemon_replenishment_remains_one_file_at_a_time() {
        let (_temp, mut pool) = fixture(5, UNIT, 1, UNIT);
        for count in 1..=4 {
            let report = replenish_one(&mut pool, None).unwrap();
            assert_eq!(report.files_created, 1);
            assert_eq!(report.total_bytes, UNIT);
            assert_eq!(pool.actual_count(), count);
        }
        assert_eq!(replenish_one(&mut pool, None).unwrap().files_created, 0);
        assert_eq!(pool.releasable_bytes(), 5 * UNIT);
    }

    #[test]
    fn externally_released_legacy_files_are_not_credited() {
        let (_temp, mut pool) = fixture(3, UNIT, 3, UNIT);
        fs::remove_file(&pool.stranded.files()[0].0).unwrap();
        let report = provision(&mut pool, None).unwrap();
        assert_eq!(report.files_created, 1);
        assert_eq!(pool.stranded.files().len(), 2);
        assert_eq!(pool.releasable_bytes(), 3 * UNIT);
        assert!(report.errors.is_empty());
    }

    #[test]
    fn corrupt_legacy_bytes_do_not_hide_a_missing_reserve() {
        let (_temp, mut pool) = fixture(3, UNIT, 1, 3 * UNIT);
        let retired = pool.stranded.files()[0].0.clone();
        fs::write(&retired, b"not reserve any longer").unwrap();
        let report = provision(&mut pool, None).unwrap();
        assert_eq!(report.files_created, 3);
        assert_eq!(pool.stranded.files().len(), 0);
        assert_eq!(fs::read(retired).unwrap(), b"not reserve any longer");
    }

    #[test]
    fn refreshing_managed_inventory_preserves_high_index_files() {
        use std::os::unix::fs::MetadataExt;
        let (_temp, mut pool) = fixture(3, UNIT, 1, UNIT);
        pool.manager.provision(None).unwrap();
        let retained = file(&pool.ballast_dir, 3);
        let inode = fs::metadata(&retained).unwrap().ino();
        fs::remove_file(file(&pool.ballast_dir, 1)).unwrap();
        fs::remove_file(file(&pool.ballast_dir, 2)).unwrap();
        // Cached inventory still claims three managed files. A re-scan must
        // see the loss, without lowering file_count and pruning index three.
        assert_eq!(pool.actual_count(), 3);
        let report = provision(&mut pool, None).unwrap();
        assert_eq!(report.files_created, 1);
        assert_eq!(pool.actual_count(), 2);
        assert_eq!(pool.expected_count(), 3);
        assert_eq!(fs::metadata(retained).unwrap().ino(), inode);
        assert_eq!(pool.releasable_bytes(), 3 * UNIT);
    }

    #[test]
    fn broken_managed_files_are_not_credited_as_verified_reserve() {
        let (_temp, mut pool) = fixture(3, UNIT, 1, UNIT);
        fs::create_dir_all(&pool.ballast_dir).unwrap();
        fs::write(file(&pool.ballast_dir, 1), b"partial old allocation").unwrap();
        let report = provision(&mut pool, None).unwrap();
        assert_eq!(report.files_created, 2);
        assert_eq!(valid_managed_bytes(&pool.manager), 2 * UNIT);
        assert_eq!(pool.expected_count(), 3);
        assert!(report.errors.is_empty());
    }

    #[test]
    fn adopted_credit_never_bypasses_the_live_headroom_floor() {
        let (_temp, mut pool) = fixture(3, UNIT, 1, UNIT);
        pool.manager.set_provision_floor(20.0);
        let report = provision(&mut pool, Some(&|| 0.0)).unwrap();
        assert_eq!(report.files_created, 0);
        assert!(report.skipped_for_floor > 0);
        assert_eq!(report.floor_pct, 20.0);
        assert!(report.errors.is_empty());
        assert!(pool.stranded.files()[0].0.exists());
        assert!(!file(&pool.ballast_dir, 1).exists());
    }

    #[test]
    fn unavailable_legacy_inventory_defers_growth_without_waiting_or_allocating() {
        let (_temp, mut pool) = fixture(3, UNIT, 1, UNIT);
        let retired_dir = pool.stranded.files()[0].0.parent().unwrap().to_path_buf();
        let lock = File::open(retired_dir.join(".lock")).unwrap();
        flock(&lock, FlockOperation::NonBlockingLockExclusive).unwrap();
        let report = provision(&mut pool, None).unwrap();
        assert_eq!(report.files_created, 0);
        assert!(!report.errors.is_empty());
        assert!(!pool.ballast_dir.exists());
        drop(lock);
        assert_eq!(provision(&mut pool, None).unwrap().files_created, 2);
    }

    #[test]
    fn managed_lock_failure_is_reported_without_discarding_adopted_reserve() {
        let (_temp, mut pool) = fixture(3, UNIT, 1, UNIT);
        fs::write(&pool.ballast_dir, b"not a directory").unwrap();
        let report = provision(&mut pool, None).unwrap();
        assert_eq!(report.files_created, 0);
        assert!(!report.errors.is_empty());
        assert!(pool.stranded.files()[0].0.exists());
        assert_eq!(pool.stranded.bytes(), UNIT);
    }

    #[test]
    fn zero_target_preserves_old_reserve_without_creating_an_active_pool() {
        let (_temp, mut pool) = fixture(0, UNIT, 2, UNIT);
        assert_eq!(provision(&mut pool, None).unwrap().files_created, 0);
        assert!(!pool.ballast_dir.exists());
        assert_eq!(pool.stranded.files().len(), 2);
    }

    #[test]
    fn a_pool_without_adopted_files_keeps_normal_provision_and_replenish_behavior() {
        let (_temp, mut pool) = fixture(3, UNIT, 0, UNIT);
        assert_eq!(provision(&mut pool, None).unwrap().files_created, 3);
        pool.manager.release(2).unwrap();
        assert_eq!(replenish_one(&mut pool, None).unwrap().files_created, 1);
        assert_eq!(pool.actual_count(), 2);
    }

    #[test]
    fn byte_deficit_saturates_instead_of_wrapping() {
        assert_eq!(missing_bytes(u64::MAX, u64::MAX, u64::MAX), 0);
        assert_eq!(missing_bytes(0, 0, 0), 0);
        assert_eq!(missing_bytes(u64::MAX, 1, 1), u64::MAX - 2);
        assert_eq!(missing_bytes(100, 40, 20), 40);
        assert_eq!(missing_bytes(100, 120, 0), 0);
    }
}
