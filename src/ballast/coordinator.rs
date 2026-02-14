//! Multi-volume ballast pool coordinator: per-filesystem pool management
//! with auto-detection, per-volume overrides, and targeted release.
//!
//! Each monitored filesystem gets its own ballast pool so that releasing
//! ballast on volume A actually frees space on volume A (not some other mount).

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::ballast::manager::{BallastManager, ProvisionReport, ReleaseReport, VerifyReport};
use crate::core::config::BallastConfig;
use crate::core::errors::Result;
use crate::platform::pal::{MountPoint, Platform};

// ──────────────────── constants ────────────────────

/// Subdirectory name placed on each volume for ballast files.
const BALLAST_SUBDIR: &str = ".sbh/ballast";

/// Filesystem types where `fallocate()` reserves real blocks.
const FALLOCATE_FRIENDLY: &[&str] = &["ext4", "xfs", "ext3", "ext2"];

/// CoW filesystems where fallocate doesn't prevent dedup — random data required.
const COW_FILESYSTEMS: &[&str] = &["btrfs", "zfs", "bcachefs"];

/// RAM-backed filesystems where ballast is counterproductive.
const RAM_FILESYSTEMS: &[&str] = &["tmpfs", "ramfs", "devtmpfs"];

/// Network filesystems where ballast is unreliable.
const NETWORK_FILESYSTEMS: &[&str] = &["nfs", "nfs4", "cifs", "smbfs", "fuse.sshfs"];

// ──────────────────── types ────────────────────

/// Provisioning strategy based on filesystem type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionStrategy {
    /// Use fallocate for instant block allocation (ext4, xfs).
    Fallocate,
    /// Write random data to defeat CoW dedup (btrfs, zfs).
    RandomData,
    /// Skip entirely — ballast on this FS type is counterproductive.
    Skip,
}

/// A single per-volume ballast pool.
pub struct BallastPool {
    pub mount_point: PathBuf,
    pub ballast_dir: PathBuf,
    pub fs_type: String,
    pub strategy: ProvisionStrategy,
    manager: BallastManager,
}

impl BallastPool {
    /// How many bytes can be released from this pool.
    pub fn releasable_bytes(&self) -> u64 {
        self.manager.releasable_bytes()
    }

    /// Number of ballast files currently available (not released).
    pub fn available_count(&self) -> usize {
        self.manager.available_count()
    }

    /// Total files expected in this pool (from config).
    pub fn expected_count(&self) -> usize {
        self.manager.inventory().len()
    }
}

/// Status snapshot of a single pool for reporting.
#[derive(Debug, Clone)]
pub struct PoolInventory {
    pub mount_point: PathBuf,
    pub ballast_dir: PathBuf,
    pub fs_type: String,
    pub strategy: ProvisionStrategy,
    pub files_available: usize,
    pub files_total: usize,
    pub releasable_bytes: u64,
    pub skipped: bool,
    pub skip_reason: Option<String>,
}

/// Aggregated provision report across all volumes.
#[derive(Debug, Clone)]
pub struct MultiProvisionReport {
    pub per_volume: Vec<(PathBuf, ProvisionReport)>,
    pub skipped_volumes: Vec<(PathBuf, String)>,
}

impl MultiProvisionReport {
    pub fn total_files_created(&self) -> usize {
        self.per_volume.iter().map(|(_, r)| r.files_created).sum()
    }

    pub fn total_bytes(&self) -> u64 {
        self.per_volume.iter().map(|(_, r)| r.total_bytes).sum()
    }

    pub fn has_errors(&self) -> bool {
        self.per_volume.iter().any(|(_, r)| !r.errors.is_empty())
    }
}

// ──────────────────── coordinator ────────────────────

/// Coordinates ballast pools across multiple filesystem volumes.
///
/// Each monitored volume gets its own pool with independent file inventory.
/// Release targets the exact volume under pressure.
pub struct BallastPoolCoordinator {
    pools: HashMap<PathBuf, BallastPool>,
    /// Retained for dynamic reconfiguration and `inventory()` reporting.
    #[allow(dead_code)]
    config: BallastConfig,
}

impl BallastPoolCoordinator {
    /// Discover and initialize pools for all unique mount points derived from
    /// the given watched paths. Skips RAM-backed and read-only filesystems.
    pub fn discover(
        config: &BallastConfig,
        watched_paths: &[PathBuf],
        platform: &dyn Platform,
    ) -> Result<Self> {
        let mounts = platform.mount_points()?;
        let mut pools = HashMap::new();

        // Deduplicate watched paths by mount point.
        let mut seen_mounts = HashMap::<PathBuf, MountPoint>::new();
        for path in watched_paths {
            if let Some(mount) = find_mount(path, &mounts) {
                seen_mounts
                    .entry(mount.path.clone())
                    .or_insert_with(|| mount.clone());
            }
        }

        for (mount_path, mount) in &seen_mounts {
            let mount_str = mount_path.to_string_lossy();

            // Check override: explicitly disabled?
            if !config.is_volume_enabled(&mount_str) {
                continue;
            }

            // Skip RAM-backed (tmpfs/ramfs) — ballast on RAM defeats the purpose.
            if mount.is_ram_backed || RAM_FILESYSTEMS.contains(&mount.fs_type.as_str()) {
                continue;
            }

            // Skip network filesystems — unreliable for ballast.
            if NETWORK_FILESYSTEMS.contains(&mount.fs_type.as_str()) {
                continue;
            }

            // Check read-only via platform.
            let stats = platform.fs_stats(mount_path)?;
            if stats.is_readonly {
                continue;
            }

            let strategy = provision_strategy(&mount.fs_type);
            if strategy == ProvisionStrategy::Skip {
                continue;
            }

            // Determine ballast directory for this volume.
            let ballast_dir = mount_path.join(BALLAST_SUBDIR);

            // Build per-volume config.
            let file_count = config.effective_file_count(&mount_str);
            let file_size_bytes = config.effective_file_size_bytes(&mount_str);
            let pool_config = BallastConfig {
                file_count,
                file_size_bytes,
                replenish_cooldown_minutes: config.replenish_cooldown_minutes,
                auto_provision: config.auto_provision,
                overrides: HashMap::new(), // per-pool doesn't need nested overrides
            };

            let manager = BallastManager::new(ballast_dir.clone(), pool_config)?;

            pools.insert(
                mount_path.clone(),
                BallastPool {
                    mount_point: mount_path.clone(),
                    ballast_dir,
                    fs_type: mount.fs_type.clone(),
                    strategy,
                    manager,
                },
            );
        }

        Ok(Self {
            pools,
            config: config.clone(),
        })
    }

    /// Provision all pools (idempotent: skips existing valid files).
    pub fn provision_all(
        &mut self,
        platform: &dyn Platform,
    ) -> Result<MultiProvisionReport> {
        let mut per_volume = Vec::new();
        let mut skipped_volumes = Vec::new();

        for (mount_path, pool) in &mut self.pools {
            // Pre-flight: check free space on this specific volume.
            let free_pct = match platform.fs_stats(mount_path) {
                Ok(stats) => stats.free_pct(),
                Err(e) => {
                    skipped_volumes.push((
                        mount_path.clone(),
                        format!("failed to get fs stats: {e}"),
                    ));
                    continue;
                }
            };

            let mount_path_clone = mount_path.clone();
            let platform_ref = platform;
            let free_check = move || -> f64 {
                platform_ref
                    .fs_stats(&mount_path_clone)
                    .map(|s| s.free_pct())
                    .unwrap_or(0.0)
            };

            if free_pct < 20.0 {
                skipped_volumes.push((
                    mount_path.clone(),
                    format!("free space too low ({free_pct:.1}% < 20%)"),
                ));
                continue;
            }

            match pool.manager.provision(Some(&free_check)) {
                Ok(report) => per_volume.push((mount_path.clone(), report)),
                Err(e) => {
                    skipped_volumes.push((
                        mount_path.clone(),
                        format!("provision failed: {e}"),
                    ));
                }
            }
        }

        Ok(MultiProvisionReport {
            per_volume,
            skipped_volumes,
        })
    }

    /// Release ballast files on a SPECIFIC mount point under pressure.
    ///
    /// Returns None if the mount has no pool or no available files.
    pub fn release_for_mount(
        &mut self,
        mount_path: &Path,
        count: usize,
    ) -> Result<Option<ReleaseReport>> {
        let Some(pool) = self.pools.get_mut(mount_path) else {
            return Ok(None);
        };

        if pool.manager.available_count() == 0 {
            return Ok(None);
        }

        let report = pool.manager.release(count)?;
        Ok(Some(report))
    }

    /// Replenish ballast on a specific mount point after pressure subsides.
    pub fn replenish_for_mount(
        &mut self,
        mount_path: &Path,
        free_pct_check: Option<&dyn Fn() -> f64>,
    ) -> Result<Option<ProvisionReport>> {
        let Some(pool) = self.pools.get_mut(mount_path) else {
            return Ok(None);
        };

        let report = pool.manager.replenish(free_pct_check)?;
        Ok(Some(report))
    }

    /// Verify integrity of all pools.
    pub fn verify_all(&mut self) -> Vec<(PathBuf, VerifyReport)> {
        self.pools
            .iter_mut()
            .map(|(mount, pool)| (mount.clone(), pool.manager.verify()))
            .collect()
    }

    /// Get inventory snapshot across all pools.
    pub fn inventory(&self) -> Vec<PoolInventory> {
        self.pools
            .values()
            .map(|pool| PoolInventory {
                mount_point: pool.mount_point.clone(),
                ballast_dir: pool.ballast_dir.clone(),
                fs_type: pool.fs_type.clone(),
                strategy: pool.strategy,
                files_available: pool.available_count(),
                files_total: pool.manager.inventory().len(),
                releasable_bytes: pool.releasable_bytes(),
                skipped: false,
                skip_reason: None,
            })
            .collect()
    }

    /// Total releasable bytes across all pools.
    pub fn total_releasable(&self) -> u64 {
        self.pools.values().map(BallastPool::releasable_bytes).sum()
    }

    /// Number of pools.
    pub fn pool_count(&self) -> usize {
        self.pools.len()
    }

    /// Check if a specific mount point has a pool.
    pub fn has_pool(&self, mount_path: &Path) -> bool {
        self.pools.contains_key(mount_path)
    }

    /// Get the pool for a specific mount point (immutable).
    pub fn pool_for_mount(&self, mount_path: &Path) -> Option<&BallastPool> {
        self.pools.get(mount_path)
    }

    /// Resolve a path to its mount point and return the associated pool.
    pub fn pool_for_path(
        &self,
        path: &Path,
        platform: &dyn Platform,
    ) -> Result<Option<&BallastPool>> {
        let mounts = platform.mount_points()?;
        let Some(mount) = find_mount(path, &mounts) else {
            return Ok(None);
        };
        Ok(self.pools.get(&mount.path))
    }

    /// Release ballast for a path (resolves to mount point first).
    pub fn release_for_path(
        &mut self,
        path: &Path,
        count: usize,
        platform: &dyn Platform,
    ) -> Result<Option<ReleaseReport>> {
        let mounts = platform.mount_points()?;
        let Some(mount) = find_mount(path, &mounts) else {
            return Ok(None);
        };
        self.release_for_mount(&mount.path, count)
    }
}

// ──────────────────── helpers ────────────────────

fn provision_strategy(fs_type: &str) -> ProvisionStrategy {
    if RAM_FILESYSTEMS.contains(&fs_type) || NETWORK_FILESYSTEMS.contains(&fs_type) {
        return ProvisionStrategy::Skip;
    }
    if COW_FILESYSTEMS.contains(&fs_type) {
        return ProvisionStrategy::RandomData;
    }
    if FALLOCATE_FRIENDLY.contains(&fs_type) {
        return ProvisionStrategy::Fallocate;
    }
    // Unknown FS — default to random data (safest).
    ProvisionStrategy::RandomData
}

fn find_mount<'a>(path: &Path, mounts: &'a [MountPoint]) -> Option<&'a MountPoint> {
    mounts
        .iter()
        .filter(|mount| path.starts_with(&mount.path))
        .max_by_key(|mount| mount.path.as_os_str().len())
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::BallastVolumeOverride;
    use crate::platform::pal::{FsStats, MemoryInfo, MockPlatform, PlatformPaths};
    use std::collections::HashMap;

    fn tiny_ballast_config() -> BallastConfig {
        BallastConfig {
            file_count: 3,
            file_size_bytes: 4096 + 4096, // header + 4KB data
            replenish_cooldown_minutes: 0,
            auto_provision: true,
            overrides: HashMap::new(),
        }
    }

    fn mock_platform_two_volumes(
        dir_data: &Path,
        dir_tmp: &Path,
    ) -> MockPlatform {
        let mounts = vec![
            MountPoint {
                path: dir_data.to_path_buf(),
                device: "/dev/sda1".to_string(),
                fs_type: "ext4".to_string(),
                is_ram_backed: false,
            },
            MountPoint {
                path: dir_tmp.to_path_buf(),
                device: "/dev/sdb1".to_string(),
                fs_type: "ext4".to_string(),
                is_ram_backed: false,
            },
        ];

        let total = 100_000_000_000u64;
        let available = 50_000_000_000u64;
        let stats = HashMap::from([
            (
                dir_data.to_path_buf(),
                FsStats {
                    total_bytes: total,
                    free_bytes: available,
                    available_bytes: available,
                    fs_type: "ext4".to_string(),
                    mount_point: dir_data.to_path_buf(),
                    is_readonly: false,
                },
            ),
            (
                dir_tmp.to_path_buf(),
                FsStats {
                    total_bytes: total,
                    free_bytes: available,
                    available_bytes: available,
                    fs_type: "ext4".to_string(),
                    mount_point: dir_tmp.to_path_buf(),
                    is_readonly: false,
                },
            ),
        ]);

        MockPlatform::new(
            mounts,
            stats,
            MemoryInfo {
                total_bytes: 32_000_000_000,
                available_bytes: 16_000_000_000,
                swap_total_bytes: 0,
                swap_free_bytes: 0,
            },
            PlatformPaths::default(),
        )
    }

    #[test]
    fn discover_creates_pools_for_each_mount() {
        let dir_data = tempfile::tempdir().unwrap();
        let dir_tmp = tempfile::tempdir().unwrap();
        let platform = mock_platform_two_volumes(dir_data.path(), dir_tmp.path());

        let watched = vec![dir_data.path().to_path_buf(), dir_tmp.path().to_path_buf()];
        let config = tiny_ballast_config();

        let coordinator = BallastPoolCoordinator::discover(&config, &watched, &platform).unwrap();
        assert_eq!(coordinator.pool_count(), 2);
        assert!(coordinator.has_pool(dir_data.path()));
        assert!(coordinator.has_pool(dir_tmp.path()));
    }

    #[test]
    fn discover_skips_ram_backed_volumes() {
        let dir_data = tempfile::tempdir().unwrap();
        let dir_tmp = tempfile::tempdir().unwrap();

        let mounts = vec![
            MountPoint {
                path: dir_data.path().to_path_buf(),
                device: "/dev/sda1".to_string(),
                fs_type: "ext4".to_string(),
                is_ram_backed: false,
            },
            MountPoint {
                path: dir_tmp.path().to_path_buf(),
                device: "tmpfs".to_string(),
                fs_type: "tmpfs".to_string(),
                is_ram_backed: true,
            },
        ];

        let stats = HashMap::from([
            (
                dir_data.path().to_path_buf(),
                FsStats {
                    total_bytes: 100_000_000_000,
                    free_bytes: 50_000_000_000,
                    available_bytes: 50_000_000_000,
                    fs_type: "ext4".to_string(),
                    mount_point: dir_data.path().to_path_buf(),
                    is_readonly: false,
                },
            ),
            (
                dir_tmp.path().to_path_buf(),
                FsStats {
                    total_bytes: 1_000_000_000,
                    free_bytes: 500_000_000,
                    available_bytes: 500_000_000,
                    fs_type: "tmpfs".to_string(),
                    mount_point: dir_tmp.path().to_path_buf(),
                    is_readonly: false,
                },
            ),
        ]);

        let platform = MockPlatform::new(
            mounts,
            stats,
            MemoryInfo {
                total_bytes: 32_000_000_000,
                available_bytes: 16_000_000_000,
                swap_total_bytes: 0,
                swap_free_bytes: 0,
            },
            PlatformPaths::default(),
        );

        let watched = vec![dir_data.path().to_path_buf(), dir_tmp.path().to_path_buf()];
        let config = tiny_ballast_config();

        let coordinator = BallastPoolCoordinator::discover(&config, &watched, &platform).unwrap();
        assert_eq!(coordinator.pool_count(), 1);
        assert!(coordinator.has_pool(dir_data.path()));
        assert!(!coordinator.has_pool(dir_tmp.path()));
    }

    #[test]
    fn discover_skips_disabled_overrides() {
        let dir_data = tempfile::tempdir().unwrap();
        let dir_scratch = tempfile::tempdir().unwrap();
        let platform = mock_platform_two_volumes(dir_data.path(), dir_scratch.path());

        let mut config = tiny_ballast_config();
        config.overrides.insert(
            dir_scratch.path().to_string_lossy().to_string(),
            BallastVolumeOverride {
                enabled: false,
                file_count: None,
                file_size_bytes: None,
            },
        );

        let watched = vec![dir_data.path().to_path_buf(), dir_scratch.path().to_path_buf()];

        let coordinator = BallastPoolCoordinator::discover(&config, &watched, &platform).unwrap();
        assert_eq!(coordinator.pool_count(), 1);
        assert!(coordinator.has_pool(dir_data.path()));
        assert!(!coordinator.has_pool(dir_scratch.path()));
    }

    #[test]
    fn provision_all_creates_files_on_each_volume() {
        let dir_data = tempfile::tempdir().unwrap();
        let dir_scratch = tempfile::tempdir().unwrap();
        let platform = mock_platform_two_volumes(dir_data.path(), dir_scratch.path());

        let watched = vec![dir_data.path().to_path_buf(), dir_scratch.path().to_path_buf()];
        let config = tiny_ballast_config();

        let mut coordinator =
            BallastPoolCoordinator::discover(&config, &watched, &platform).unwrap();
        let report = coordinator.provision_all(&platform).unwrap();

        assert_eq!(report.total_files_created(), 6); // 3 per volume
        assert!(report.skipped_volumes.is_empty());
        assert!(!report.has_errors());
    }

    #[test]
    fn release_targets_specific_mount() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let platform = mock_platform_two_volumes(dir_a.path(), dir_b.path());

        let watched = vec![dir_a.path().to_path_buf(), dir_b.path().to_path_buf()];
        let config = tiny_ballast_config();

        let mut coordinator =
            BallastPoolCoordinator::discover(&config, &watched, &platform).unwrap();
        coordinator.provision_all(&platform).unwrap();

        // Release 2 files from volume A only.
        let report = coordinator
            .release_for_mount(dir_a.path(), 2)
            .unwrap()
            .expect("should have a release report");
        assert_eq!(report.files_released, 2);

        // Volume A should have 1 left, volume B still has 3.
        let pool_a = coordinator.pool_for_mount(dir_a.path()).unwrap();
        assert_eq!(pool_a.available_count(), 1);

        let pool_b = coordinator.pool_for_mount(dir_b.path()).unwrap();
        assert_eq!(pool_b.available_count(), 3);
    }

    #[test]
    fn release_for_unknown_mount_returns_none() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let platform = mock_platform_two_volumes(dir_a.path(), dir_b.path());

        let watched = vec![dir_a.path().to_path_buf()];
        let config = tiny_ballast_config();

        let mut coordinator =
            BallastPoolCoordinator::discover(&config, &watched, &platform).unwrap();

        let result = coordinator.release_for_mount(Path::new("/nonexistent"), 1).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn total_releasable_aggregates_all_pools() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let platform = mock_platform_two_volumes(dir_a.path(), dir_b.path());

        let watched = vec![dir_a.path().to_path_buf(), dir_b.path().to_path_buf()];
        let config = tiny_ballast_config();

        let mut coordinator =
            BallastPoolCoordinator::discover(&config, &watched, &platform).unwrap();
        coordinator.provision_all(&platform).unwrap();

        // 3 files per volume * 2 volumes * (4096 + 4096) bytes each
        let expected = 6 * config.file_size_bytes;
        assert_eq!(coordinator.total_releasable(), expected);
    }

    #[test]
    fn per_volume_overrides_applied() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let platform = mock_platform_two_volumes(dir_a.path(), dir_b.path());

        let mut config = tiny_ballast_config();
        // Override: volume A gets 2 files instead of 3.
        config.overrides.insert(
            dir_a.path().to_string_lossy().to_string(),
            BallastVolumeOverride {
                enabled: true,
                file_count: Some(2),
                file_size_bytes: None,
            },
        );

        let watched = vec![dir_a.path().to_path_buf(), dir_b.path().to_path_buf()];
        let mut coordinator =
            BallastPoolCoordinator::discover(&config, &watched, &platform).unwrap();
        coordinator.provision_all(&platform).unwrap();

        // Volume A: 2 files, Volume B: 3 files (default)
        let pool_a = coordinator.pool_for_mount(dir_a.path()).unwrap();
        assert_eq!(pool_a.available_count(), 2);

        let pool_b = coordinator.pool_for_mount(dir_b.path()).unwrap();
        assert_eq!(pool_b.available_count(), 3);
    }

    #[test]
    fn verify_all_reports_per_volume() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let platform = mock_platform_two_volumes(dir_a.path(), dir_b.path());

        let watched = vec![dir_a.path().to_path_buf(), dir_b.path().to_path_buf()];
        let config = tiny_ballast_config();

        let mut coordinator =
            BallastPoolCoordinator::discover(&config, &watched, &platform).unwrap();
        coordinator.provision_all(&platform).unwrap();

        let reports = coordinator.verify_all();
        assert_eq!(reports.len(), 2);
        for (_, report) in &reports {
            assert_eq!(report.files_ok, 3);
            assert_eq!(report.files_corrupted, 0);
        }
    }

    #[test]
    fn replenish_for_mount_recreates_released() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let platform = mock_platform_two_volumes(dir_a.path(), dir_b.path());

        let watched = vec![dir_a.path().to_path_buf(), dir_b.path().to_path_buf()];
        let config = tiny_ballast_config();

        let mut coordinator =
            BallastPoolCoordinator::discover(&config, &watched, &platform).unwrap();
        coordinator.provision_all(&platform).unwrap();

        // Release all from volume A.
        coordinator.release_for_mount(dir_a.path(), 3).unwrap();
        assert_eq!(
            coordinator.pool_for_mount(dir_a.path()).unwrap().available_count(),
            0
        );

        // Replenish volume A.
        let report = coordinator
            .replenish_for_mount(dir_a.path(), None)
            .unwrap()
            .expect("should have provision report");
        assert_eq!(report.files_created, 3);
        assert_eq!(
            coordinator.pool_for_mount(dir_a.path()).unwrap().available_count(),
            3
        );
    }

    #[test]
    fn inventory_returns_all_pools() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let platform = mock_platform_two_volumes(dir_a.path(), dir_b.path());

        let watched = vec![dir_a.path().to_path_buf(), dir_b.path().to_path_buf()];
        let config = tiny_ballast_config();

        let mut coordinator =
            BallastPoolCoordinator::discover(&config, &watched, &platform).unwrap();
        coordinator.provision_all(&platform).unwrap();

        let inv = coordinator.inventory();
        assert_eq!(inv.len(), 2);
        for item in &inv {
            assert_eq!(item.files_available, 3);
            assert!(!item.skipped);
        }
    }

    #[test]
    fn provision_strategy_detection() {
        assert_eq!(provision_strategy("ext4"), ProvisionStrategy::Fallocate);
        assert_eq!(provision_strategy("xfs"), ProvisionStrategy::Fallocate);
        assert_eq!(provision_strategy("btrfs"), ProvisionStrategy::RandomData);
        assert_eq!(provision_strategy("zfs"), ProvisionStrategy::RandomData);
        assert_eq!(provision_strategy("tmpfs"), ProvisionStrategy::Skip);
        assert_eq!(provision_strategy("ramfs"), ProvisionStrategy::Skip);
        assert_eq!(provision_strategy("nfs"), ProvisionStrategy::Skip);
        assert_eq!(provision_strategy("nfs4"), ProvisionStrategy::Skip);
        // Unknown FS defaults to RandomData.
        assert_eq!(provision_strategy("foobarfs"), ProvisionStrategy::RandomData);
    }

    #[test]
    fn discover_deduplicates_mount_points() {
        let dir_data = tempfile::tempdir().unwrap();
        let platform = {
            let mounts = vec![MountPoint {
                path: dir_data.path().to_path_buf(),
                device: "/dev/sda1".to_string(),
                fs_type: "ext4".to_string(),
                is_ram_backed: false,
            }];
            let stats = HashMap::from([(
                dir_data.path().to_path_buf(),
                FsStats {
                    total_bytes: 100_000_000_000,
                    free_bytes: 50_000_000_000,
                    available_bytes: 50_000_000_000,
                    fs_type: "ext4".to_string(),
                    mount_point: dir_data.path().to_path_buf(),
                    is_readonly: false,
                },
            )]);
            MockPlatform::new(
                mounts,
                stats,
                MemoryInfo {
                    total_bytes: 32_000_000_000,
                    available_bytes: 16_000_000_000,
                    swap_total_bytes: 0,
                    swap_free_bytes: 0,
                },
                PlatformPaths::default(),
            )
        };

        // Two watched paths on the same mount.
        let sub_a = dir_data.path().join("projects");
        let sub_b = dir_data.path().join("builds");
        std::fs::create_dir_all(&sub_a).unwrap();
        std::fs::create_dir_all(&sub_b).unwrap();
        let watched = vec![sub_a, sub_b];
        let config = tiny_ballast_config();

        let coordinator = BallastPoolCoordinator::discover(&config, &watched, &platform).unwrap();
        // Only one pool even though two watched paths.
        assert_eq!(coordinator.pool_count(), 1);
    }

    #[test]
    fn discover_skips_readonly_volumes() {
        let dir_data = tempfile::tempdir().unwrap();

        let mounts = vec![MountPoint {
            path: dir_data.path().to_path_buf(),
            device: "/dev/sda1".to_string(),
            fs_type: "ext4".to_string(),
            is_ram_backed: false,
        }];
        let stats = HashMap::from([(
            dir_data.path().to_path_buf(),
            FsStats {
                total_bytes: 100_000_000_000,
                free_bytes: 50_000_000_000,
                available_bytes: 50_000_000_000,
                fs_type: "ext4".to_string(),
                mount_point: dir_data.path().to_path_buf(),
                is_readonly: true, // <-- read-only
            },
        )]);
        let platform = MockPlatform::new(
            mounts,
            stats,
            MemoryInfo {
                total_bytes: 32_000_000_000,
                available_bytes: 16_000_000_000,
                swap_total_bytes: 0,
                swap_free_bytes: 0,
            },
            PlatformPaths::default(),
        );

        let watched = vec![dir_data.path().to_path_buf()];
        let config = tiny_ballast_config();

        let coordinator = BallastPoolCoordinator::discover(&config, &watched, &platform).unwrap();
        assert_eq!(coordinator.pool_count(), 0);
    }
}
