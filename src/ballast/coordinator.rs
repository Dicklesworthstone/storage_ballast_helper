//! Multi-volume ballast pool coordinator: per-filesystem pool management
//! with auto-detection, per-volume overrides, and targeted release.
//!
//! Each monitored filesystem gets its own ballast pool so that releasing
//! ballast on volume A actually frees space on volume A (not some other mount).

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

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

    /// Number of files currently on disk in this pool.
    pub fn actual_count(&self) -> usize {
        self.manager.inventory().len()
    }

    /// Number of files this pool is configured to hold.
    pub fn expected_count(&self) -> usize {
        self.manager.config().file_count
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

#[derive(Debug, Clone)]
struct SkippedPoolInfo {
    ballast_dir: PathBuf,
    fs_type: String,
    strategy: ProvisionStrategy,
    reason: String,
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
    skipped_pools: HashMap<PathBuf, SkippedPoolInfo>,
}

impl BallastPoolCoordinator {
    /// Discover and initialize pools for all unique mount points derived from
    /// the given watched paths. Skips RAM-backed and read-only filesystems.
    pub fn discover(
        config: &BallastConfig,
        watched_paths: &[PathBuf],
        platform: &dyn Platform,
    ) -> Result<Self> {
        let manager_platform: Arc<dyn Platform> = Arc::new(crate::platform::current());
        Self::discover_with_manager_platform(config, watched_paths, platform, &manager_platform)
    }

    /// Discover and initialize pools, honoring an operator-configured ballast
    /// directory.
    ///
    /// `configured_ballast_dir` is the operator's `[paths] ballast_dir`. When
    /// it is `Some`, the pool whose mount point contains that directory is
    /// provisioned at that exact path instead of the per-volume `.sbh/ballast`
    /// subdirectory default. All other volumes keep the subdirectory default so
    /// per-volume release semantics are preserved.
    pub fn discover_with_configured_dir(
        config: &BallastConfig,
        watched_paths: &[PathBuf],
        platform: &dyn Platform,
        configured_ballast_dir: Option<&Path>,
    ) -> Result<Self> {
        let manager_platform: Arc<dyn Platform> = Arc::new(crate::platform::current());
        Self::discover_inner(
            config,
            watched_paths,
            platform,
            &manager_platform,
            configured_ballast_dir,
        )
    }

    pub(crate) fn discover_with_manager_platform(
        config: &BallastConfig,
        watched_paths: &[PathBuf],
        platform: &dyn Platform,
        manager_platform: &Arc<dyn Platform>,
    ) -> Result<Self> {
        Self::discover_inner(config, watched_paths, platform, manager_platform, None)
    }

    pub(crate) fn discover_inner(
        config: &BallastConfig,
        watched_paths: &[PathBuf],
        platform: &dyn Platform,
        manager_platform: &Arc<dyn Platform>,
        configured_ballast_dir: Option<&Path>,
    ) -> Result<Self> {
        let mounts = platform.mount_points()?;
        let mut pools = HashMap::new();
        let mut skipped_pools = HashMap::new();

        // Deduplicate watched paths by mount point.
        let mut seen_mounts = HashMap::<PathBuf, MountPoint>::new();
        for path in watched_paths {
            if let Some(mount) = find_mount(path, &mounts) {
                seen_mounts
                    .entry(mount.path.clone())
                    .or_insert_with(|| mount.clone());
            }
        }

        // Identify which discovered mount actually owns the operator-configured
        // ballast dir, so only that single pool is redirected to the configured
        // path (not every ancestor mount, e.g. `/` of `/data/...`).
        let configured_owner_mount =
            configured_owner_mount(configured_ballast_dir, &mounts, &seen_mounts);

        for (mount_path, mount) in &seen_mounts {
            let mount_str = mount_path.to_string_lossy();
            let strategy = provision_strategy(&mount.fs_type);
            let configured_for_mount = configured_ballast_dir
                .filter(|_| configured_owner_mount.as_deref() == Some(mount_path.as_path()));
            let resolved_dir = resolve_ballast_dir(mount_path, configured_for_mount);
            let skip_dir = resolved_dir.clone();
            let mut skip_with = |reason: String| {
                skipped_pools.insert(
                    mount_path.clone(),
                    SkippedPoolInfo {
                        ballast_dir: skip_dir.clone(),
                        fs_type: mount.fs_type.clone(),
                        strategy,
                        reason,
                    },
                );
            };

            // Warn about non-UTF-8 mount paths that may cause config-matching issues.
            if mount_path.to_str().is_none() {
                eprintln!(
                    "[SBH-WARN] mount path contains non-UTF-8 bytes, lossy representation: {mount_str}"
                );
            }

            // Check override: explicitly disabled?
            if !config.is_volume_enabled(&mount_str) {
                skip_with("disabled via ballast volume override".to_string());
                continue;
            }

            // Skip RAM-backed (tmpfs/ramfs) — ballast on RAM defeats the purpose.
            if mount.is_ram_backed || RAM_FILESYSTEMS.contains(&mount.fs_type.as_str()) {
                skip_with("ram-backed filesystem (ballast disabled)".to_string());
                continue;
            }

            // Skip network filesystems — unreliable for ballast.
            if NETWORK_FILESYSTEMS.contains(&mount.fs_type.as_str()) {
                skip_with("network filesystem (ballast disabled)".to_string());
                continue;
            }

            // Check read-only via platform. Skip volumes where fs_stats fails
            // (e.g. permission denied) rather than aborting discovery for all.
            let stats = match platform.fs_stats(mount_path) {
                Ok(stats) => stats,
                Err(err) => {
                    skip_with(format!("failed to stat filesystem: {err}"));
                    continue;
                }
            };
            if stats.is_readonly {
                skip_with("read-only filesystem".to_string());
                continue;
            }

            if strategy == ProvisionStrategy::Skip {
                skip_with("filesystem strategy marked as skip".to_string());
                continue;
            }

            // Configured ballast_dir on this mount is honored verbatim;
            // otherwise fall back to the per-volume subdirectory.
            let ballast_dir = resolved_dir;
            let pool_config = per_volume_config(config, &mount_str);

            let mut manager = match BallastManager::with_platform(
                ballast_dir.clone(),
                pool_config,
                Arc::clone(manager_platform),
            ) {
                Ok(manager) => manager,
                Err(err) => {
                    skip_with(format!("failed to initialize ballast manager: {err}"));
                    continue;
                }
            };

            // On CoW filesystems, force random-data writes (fallocate zeros are
            // trivially deduplicated, defeating the purpose of ballast).
            if strategy == ProvisionStrategy::RandomData {
                manager.set_skip_fallocate(true);
            }

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
            skipped_pools,
        })
    }

    /// Provision all pools (idempotent: skips existing valid files).
    pub fn provision_all(&mut self, platform: &dyn Platform) -> Result<MultiProvisionReport> {
        let mut per_volume = Vec::new();
        let mut skipped_volumes = Vec::new();

        for (mount_path, pool) in &mut self.pools {
            // Pre-flight: check free space on this specific volume.
            let free_pct = match platform.fs_stats(mount_path) {
                Ok(stats) => stats.free_pct(),
                Err(e) => {
                    skipped_volumes
                        .push((mount_path.clone(), format!("failed to get fs stats: {e}")));
                    continue;
                }
            };

            let mount_path_clone = mount_path.clone();
            let platform_ref = platform;
            let free_check = move || -> f64 {
                platform_ref
                    .fs_stats(&mount_path_clone)
                    .map_or(0.0, |s| s.free_pct())
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
                    skipped_volumes.push((mount_path.clone(), format!("provision failed: {e}")));
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

    /// Replenish at most one ballast file on a specific mount point after
    /// pressure subsides.  Gradual one-file-at-a-time replenishment avoids a
    /// burst of disk I/O at the moment the system is recovering from pressure.
    pub fn replenish_for_mount(
        &mut self,
        mount_path: &Path,
        free_pct_check: Option<&dyn Fn() -> f64>,
    ) -> Result<Option<ProvisionReport>> {
        let Some(pool) = self.pools.get_mut(mount_path) else {
            return Ok(None);
        };

        let report = pool.manager.replenish_one(free_pct_check)?;
        Ok(Some(report))
    }

    /// Verify integrity of all pools.
    pub fn verify_all(&mut self) -> Vec<(PathBuf, VerifyReport)> {
        self.pools
            .iter_mut()
            .map(|(mount, pool)| {
                let report = match pool.manager.verify() {
                    Ok(r) => r,
                    Err(e) => VerifyReport {
                        files_checked: 0,
                        files_ok: 0,
                        files_corrupted: 0,
                        files_missing: 0,
                        details: vec![format!("verification failed: {e}")],
                    },
                };
                (mount.clone(), report)
            })
            .collect()
    }

    /// Get inventory snapshot across all pools.
    pub fn inventory(&self) -> Vec<PoolInventory> {
        let mut inventory: Vec<PoolInventory> = self
            .pools
            .values()
            .map(|pool| PoolInventory {
                mount_point: pool.mount_point.clone(),
                ballast_dir: pool.ballast_dir.clone(),
                fs_type: pool.fs_type.clone(),
                strategy: pool.strategy,
                files_available: pool.available_count(),
                files_total: pool.expected_count(),
                releasable_bytes: pool.releasable_bytes(),
                skipped: false,
                skip_reason: None,
            })
            .collect();

        inventory.extend(
            self.skipped_pools
                .iter()
                .map(|(mount_point, skipped)| PoolInventory {
                    mount_point: mount_point.clone(),
                    ballast_dir: skipped.ballast_dir.clone(),
                    fs_type: skipped.fs_type.clone(),
                    strategy: skipped.strategy,
                    files_available: 0,
                    files_total: 0,
                    releasable_bytes: 0,
                    skipped: true,
                    skip_reason: Some(skipped.reason.clone()),
                }),
        );

        inventory.sort_by(|left, right| left.mount_point.cmp(&right.mount_point));
        inventory
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

    /// Propagate configuration updates to all pools.
    pub fn update_config(&mut self, config: &BallastConfig) {
        for (mount_path, pool) in &mut self.pools {
            let mount_str = mount_path.to_string_lossy();
            let pool_config = per_volume_config(config, &mount_str);
            pool.manager.update_config(pool_config);
        }
    }
}

// ──────────────────── helpers ────────────────────

/// Build the per-volume `BallastConfig` for one mount, applying any
/// per-volume file-count / file-size overrides for that mount.
fn per_volume_config(config: &BallastConfig, mount_str: &str) -> BallastConfig {
    BallastConfig {
        file_count: config.effective_file_count(mount_str),
        file_size_bytes: config.effective_file_size_bytes(mount_str),
        replenish_cooldown_minutes: config.replenish_cooldown_minutes,
        auto_provision: config.auto_provision,
        overrides: BTreeMap::new(),
    }
}

/// Find the discovered mount that owns the operator-configured ballast dir.
///
/// Returns the mount path (longest matching prefix) only when that mount is
/// among the volumes we are provisioning pools for, so an ancestor mount like
/// `/` is never redirected away from its `.sbh/ballast` default.
fn configured_owner_mount(
    configured_ballast_dir: Option<&Path>,
    mounts: &[MountPoint],
    seen_mounts: &HashMap<PathBuf, MountPoint>,
) -> Option<PathBuf> {
    let dir = configured_ballast_dir?;
    let mount = find_mount(dir, mounts)?;
    if seen_mounts.contains_key(&mount.path) {
        Some(mount.path.clone())
    } else {
        None
    }
}

/// Resolve the ballast directory for a single volume.
///
/// When the operator configured an explicit `[paths] ballast_dir` and that
/// directory lives on this `mount_path`, the configured directory is used
/// verbatim (honoring issue #14). Otherwise the per-volume `.sbh/ballast`
/// subdirectory is used so that ballast still lands on the right filesystem.
pub(crate) fn resolve_ballast_dir(mount_path: &Path, configured: Option<&Path>) -> PathBuf {
    if let Some(configured) = configured {
        // Only honor the configured dir for the mount that actually contains
        // it; other discovered volumes keep their own subdirectory pool.
        if configured.starts_with(mount_path) {
            return configured.to_path_buf();
        }
    }
    mount_path.join(BALLAST_SUBDIR)
}

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
    use crate::platform::types::PalError;
    use std::collections::HashMap;

    fn tiny_ballast_config() -> BallastConfig {
        BallastConfig {
            file_count: 3,
            file_size_bytes: 4096 + 4096, // header + 4KB data
            replenish_cooldown_minutes: 0,
            auto_provision: true,
            overrides: BTreeMap::new(),
        }
    }

    fn mock_platform_two_volumes(dir_data: &Path, dir_tmp: &Path) -> MockPlatform {
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

        let watched = vec![
            dir_data.path().to_path_buf(),
            dir_scratch.path().to_path_buf(),
        ];

        let coordinator = BallastPoolCoordinator::discover(&config, &watched, &platform).unwrap();
        assert_eq!(coordinator.pool_count(), 1);
        assert!(coordinator.has_pool(dir_data.path()));
        assert!(!coordinator.has_pool(dir_scratch.path()));
        let inv = coordinator.inventory();
        assert_eq!(inv.len(), 2);
        assert!(inv.iter().any(|item| {
            item.mount_point == dir_scratch.path()
                && item.skipped
                && item
                    .skip_reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("disabled"))
        }));
    }

    #[test]
    fn provision_all_creates_files_on_each_volume() {
        let dir_data = tempfile::tempdir().unwrap();
        let dir_scratch = tempfile::tempdir().unwrap();
        let platform = mock_platform_two_volumes(dir_data.path(), dir_scratch.path());

        let watched = vec![
            dir_data.path().to_path_buf(),
            dir_scratch.path().to_path_buf(),
        ];
        let config = tiny_ballast_config();

        let manager_platform: Arc<dyn Platform> = Arc::new(platform.clone());
        let mut coordinator = BallastPoolCoordinator::discover_with_manager_platform(
            &config,
            &watched,
            &platform,
            &manager_platform,
        )
        .unwrap();
        let report = coordinator.provision_all(&platform).unwrap();

        assert_eq!(report.total_files_created(), 6); // 3 per volume
        assert!(
            report.skipped_volumes.is_empty(),
            "expected no skipped volumes, got {:?}",
            report.skipped_volumes
        );
        assert!(!report.has_errors());
    }

    #[test]
    fn provision_all_reports_storage_full_without_aborting_other_volumes() {
        let dir_data = tempfile::tempdir().unwrap();
        let dir_scratch = tempfile::tempdir().unwrap();
        let failing_ballast = dir_data
            .path()
            .join(BALLAST_SUBDIR)
            .join("SBH_BALLAST_FILE_00001.dat");
        let platform = mock_platform_two_volumes(dir_data.path(), dir_scratch.path())
            .with_preallocate_failure(
                failing_ballast,
                PalError::method_failed(
                    "macos",
                    "preallocate_file",
                    "No space left on device (os error 28)",
                ),
            );

        let watched = vec![
            dir_data.path().to_path_buf(),
            dir_scratch.path().to_path_buf(),
        ];
        let config = tiny_ballast_config();

        let manager_platform: Arc<dyn Platform> = Arc::new(platform.clone());
        let mut coordinator = BallastPoolCoordinator::discover_with_manager_platform(
            &config,
            &watched,
            &platform,
            &manager_platform,
        )
        .unwrap();
        let report = coordinator.provision_all(&platform).unwrap();

        let failed = report
            .per_volume
            .iter()
            .find(|(mount, _)| mount == dir_data.path())
            .expect("failed volume should still have a provision report");
        let succeeded = report
            .per_volume
            .iter()
            .find(|(mount, _)| mount == dir_scratch.path())
            .expect("healthy volume should still provision");

        assert_eq!(failed.1.files_created, 0);
        assert_eq!(failed.1.errors.len(), 1);
        assert!(failed.1.errors[0].contains("storage exhausted"));
        assert_eq!(succeeded.1.files_created, 3);
        assert!(
            report.skipped_volumes.is_empty(),
            "a storage-full volume must be reported per-volume, not skipped; got {:?}",
            report.skipped_volumes
        );
        assert!(report.has_errors());
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

        let result = coordinator
            .release_for_mount(Path::new("/nonexistent"), 1)
            .unwrap();
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
            coordinator
                .pool_for_mount(dir_a.path())
                .unwrap()
                .available_count(),
            0
        );

        // Replenish volume A (one file per call, matching daemon tick behavior).
        let mut total_created = 0;
        for _ in 0..3 {
            let report = coordinator
                .replenish_for_mount(dir_a.path(), None)
                .unwrap()
                .expect("should have provision report");
            total_created += report.files_created;
        }
        assert_eq!(total_created, 3);
        assert_eq!(
            coordinator
                .pool_for_mount(dir_a.path())
                .unwrap()
                .available_count(),
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
            assert_eq!(item.files_total, 3);
            assert!(!item.skipped);
        }
    }

    #[test]
    fn inventory_reports_configured_total_before_provision() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let platform = mock_platform_two_volumes(dir_a.path(), dir_b.path());

        let watched = vec![dir_a.path().to_path_buf(), dir_b.path().to_path_buf()];
        let config = tiny_ballast_config();

        // Discover but do NOT provision.
        let coordinator = BallastPoolCoordinator::discover(&config, &watched, &platform).unwrap();

        let inv = coordinator.inventory();
        assert_eq!(inv.len(), 2);
        for item in &inv {
            // files_total must reflect configured count, not on-disk files.
            assert_eq!(item.files_total, 3);
            assert_eq!(item.files_available, 0);
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
        assert_eq!(
            provision_strategy("foobarfs"),
            ProvisionStrategy::RandomData
        );
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
    fn resolve_ballast_dir_honors_configured_dir_on_owning_mount() {
        // Regression for issue #14: when an explicit ballast_dir is configured
        // and lives on this mount, it must be honored verbatim — NOT rewritten
        // to the hardcoded `<mount>/.sbh/ballast` default.
        let mount = Path::new("/data");
        let configured = Path::new("/data/sbh/ballast");
        assert_eq!(
            resolve_ballast_dir(mount, Some(configured)),
            PathBuf::from("/data/sbh/ballast"),
        );
        // Sanity: it must not be the hardcoded subdir default.
        assert_ne!(
            resolve_ballast_dir(mount, Some(configured)),
            mount.join(BALLAST_SUBDIR),
        );
    }

    #[test]
    fn resolve_ballast_dir_falls_back_to_subdir_when_unset() {
        let mount = Path::new("/data");
        assert_eq!(
            resolve_ballast_dir(mount, None),
            PathBuf::from("/data/.sbh/ballast"),
        );
    }

    #[test]
    fn resolve_ballast_dir_ignores_configured_dir_on_other_mount() {
        // The discover loop only passes `Some(configured)` to the owning mount;
        // every other mount receives `None` and must keep its subdir default.
        // This mirrors that contract: a non-owning mount sees `None`.
        let other_mount = Path::new("/");
        assert_eq!(
            resolve_ballast_dir(other_mount, None),
            PathBuf::from("/.sbh/ballast"),
        );
    }

    #[test]
    fn discover_honors_configured_ballast_dir_not_hardcoded_default() {
        // End-to-end on the coordinator: a configured ballast_dir under the
        // watched mount must drive the pool's ballast_dir, proving the daemon's
        // `[paths] ballast_dir` reaches the provisioner (issue #14).
        let dir_data = tempfile::tempdir().unwrap();
        let configured = dir_data.path().join("custom").join("ballast");

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

        let watched = vec![dir_data.path().to_path_buf()];
        let config = tiny_ballast_config();

        let coordinator = BallastPoolCoordinator::discover_with_configured_dir(
            &config,
            &watched,
            &platform,
            Some(configured.as_path()),
        )
        .unwrap();

        let pool = coordinator
            .pool_for_mount(dir_data.path())
            .expect("pool should exist for watched mount");
        assert_eq!(
            pool.ballast_dir, configured,
            "provisioner must resolve to the configured ballast_dir"
        );
        assert_ne!(
            pool.ballast_dir,
            dir_data.path().join(BALLAST_SUBDIR),
            "must not fall back to the hardcoded .sbh/ballast default when configured",
        );
    }

    #[test]
    fn discover_redirects_only_the_owning_volume_to_configured_dir() {
        // Two volumes; the configured ballast_dir lives on dir_data only. The
        // dir_data pool must use the configured dir; the other volume keeps its
        // `.sbh/ballast` subdir default (preserves per-volume release).
        let dir_data = tempfile::tempdir().unwrap();
        let dir_other = tempfile::tempdir().unwrap();
        let platform = mock_platform_two_volumes(dir_data.path(), dir_other.path());

        let configured = dir_data.path().join("explicit").join("ballast");
        let watched = vec![
            dir_data.path().to_path_buf(),
            dir_other.path().to_path_buf(),
        ];
        let config = tiny_ballast_config();

        let coordinator = BallastPoolCoordinator::discover_with_configured_dir(
            &config,
            &watched,
            &platform,
            Some(configured.as_path()),
        )
        .unwrap();

        let owning = coordinator.pool_for_mount(dir_data.path()).unwrap();
        assert_eq!(owning.ballast_dir, configured);

        let other = coordinator.pool_for_mount(dir_other.path()).unwrap();
        assert_eq!(other.ballast_dir, dir_other.path().join(BALLAST_SUBDIR));
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
        let inv = coordinator.inventory();
        assert_eq!(inv.len(), 1);
        assert!(inv[0].skipped);
        assert!(
            inv[0]
                .skip_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("read-only"))
        );
    }
}
