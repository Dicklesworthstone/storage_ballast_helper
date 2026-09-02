//! Test-mode filesystem injection (W10).
//!
//! One mechanism that lets a real `sbh daemon` binary see mounts and
//! free-space readings that do not exist on the test host, so multi-mount
//! pressure scenarios run end to end on a single-filesystem CI runner.
//!
//! Activation needs two environment variables:
//!
//! - `SBH_TEST_MODE=1`
//! - `SBH_TEST_FS_STATS=<json>` with the shape
//!   `{"mounts":[{"path":"/data","fs_type":"ext4","total":1000000,"free":120000,
//!   "series":[{"after_secs":30,"free":60000}]}]}`
//!
//! Every PAL mount query goes through [`TestOverlayPlatform`]: `fs_stats`,
//! `capacity`, `mount_points`, `mounts` and `is_ram_backed` answer from the
//! injected table for paths under an injected mount and delegate everything
//! else to the real platform. A `series` steps `free` over time from process
//! start, which is how a rising-usage scenario is expressed. A daemon started
//! in test mode under a service manager refuses to run: the injected table
//! must never drive a production unit.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use serde::Deserialize;

use crate::core::errors::{Result, SbhError};
use crate::platform::pal::{
    BlockDeviceInfo, FsStats, MemoryInfo, MountPoint, Platform, PlatformPaths, ServiceManager,
};
use crate::platform::types::{
    Capacity, FullDiskAccessStatus, LocalSnapshotInfo, MappedRegion, MemoryPressure,
    MemoryPressureCallback, MountInfo, OpenFile, ProcessInfo, ProcessIo, SacredPath, SelfStats,
    ServiceKind, SubscriptionHandle,
};
use crate::tuning::writeback::WritebackState;

/// Environment variable that enables test mode.
pub const TEST_MODE_ENV: &str = "SBH_TEST_MODE";
/// Environment variable carrying the injected mount table (JSON).
pub const TEST_FS_STATS_ENV: &str = "SBH_TEST_FS_STATS";

/// One point of a rising/falling usage series.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct InjectedPoint {
    /// Seconds after overlay creation at which this reading takes effect.
    pub after_secs: u64,
    /// Free (and available) bytes from then on.
    pub free: u64,
}

/// One injected mount.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct InjectedMount {
    /// Mount point; paths under it answer from this entry.
    pub path: PathBuf,
    /// Filesystem type reported for the mount (`ext4` by default).
    #[serde(default = "default_fs_type")]
    pub fs_type: String,
    /// Device name reported for the mount.
    #[serde(default)]
    pub device: Option<String>,
    /// Total bytes.
    pub total: u64,
    /// Free bytes at time zero.
    pub free: u64,
    /// Whether the mount is RAM-backed (tmpfs-like).
    #[serde(default)]
    pub ram_backed: bool,
    /// Whether the mount is read-only.
    #[serde(default)]
    pub readonly: bool,
    /// Free bytes over time, applied in order of `after_secs`.
    #[serde(default)]
    pub series: Vec<InjectedPoint>,
}

fn default_fs_type() -> String {
    "ext4".to_string()
}

/// The injected mount table.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct InjectedFsTable {
    /// Injected mounts, longest path wins for a given query path.
    #[serde(default)]
    pub mounts: Vec<InjectedMount>,
}

impl InjectedFsTable {
    /// Parse the JSON form used by `SBH_TEST_FS_STATS`.
    pub fn parse(json: &str) -> Result<Self> {
        let table: Self = serde_json::from_str(json).map_err(|e| SbhError::InvalidConfig {
            details: format!("{TEST_FS_STATS_ENV}: {e}"),
        })?;
        for mount in &table.mounts {
            if !mount.path.is_absolute() {
                return Err(SbhError::InvalidConfig {
                    details: format!(
                        "{TEST_FS_STATS_ENV}: mount path must be absolute: {}",
                        mount.path.display()
                    ),
                });
            }
            if mount.total == 0 || mount.free > mount.total {
                return Err(SbhError::InvalidConfig {
                    details: format!(
                        "{TEST_FS_STATS_ENV}: {} needs 0 < free <= total (got free={} total={})",
                        mount.path.display(),
                        mount.free,
                        mount.total
                    ),
                });
            }
            if mount.series.iter().any(|point| point.free > mount.total) {
                return Err(SbhError::InvalidConfig {
                    details: format!(
                        "{TEST_FS_STATS_ENV}: {} has a series point above total",
                        mount.path.display()
                    ),
                });
            }
        }
        Ok(table)
    }

    /// The injected mount that owns `path`, if any (longest prefix wins).
    #[must_use]
    pub fn owner(&self, path: &Path) -> Option<&InjectedMount> {
        self.mounts
            .iter()
            .filter(|mount| path.starts_with(&mount.path))
            .max_by_key(|mount| mount.path.as_os_str().len())
    }
}

impl InjectedMount {
    /// Free bytes `elapsed_secs` after overlay creation.
    #[must_use]
    pub fn free_at(&self, elapsed_secs: u64) -> u64 {
        self.series
            .iter()
            .filter(|point| point.after_secs <= elapsed_secs)
            .max_by_key(|point| point.after_secs)
            .map_or(self.free, |point| point.free)
    }

    fn stats_at(&self, elapsed_secs: u64) -> FsStats {
        let free = self.free_at(elapsed_secs).min(self.total);
        FsStats {
            total_bytes: self.total,
            free_bytes: free,
            available_bytes: free,
            fs_type: self.fs_type.clone(),
            mount_point: self.path.clone(),
            is_readonly: self.readonly,
        }
    }

    fn mount_point(&self) -> MountPoint {
        MountPoint {
            path: self.path.clone(),
            device: self
                .device
                .clone()
                .unwrap_or_else(|| format!("sbh-test:{}", self.path.display())),
            fs_type: self.fs_type.clone(),
            is_ram_backed: self.ram_backed,
        }
    }
}

/// Whether test mode is requested by the environment.
#[must_use]
pub fn test_mode_requested() -> bool {
    std::env::var_os(TEST_MODE_ENV).is_some_and(|value| value == "1" || value == "true")
}

/// Refuse to run a test-mode daemon under a service manager. The injected
/// table exists for the e2e runner; a unit that inherited the variables
/// would make the daemon act on fiction.
pub fn refuse_under_service_manager() -> Result<()> {
    if !test_mode_requested() {
        return Ok(());
    }
    let managed = [
        "INVOCATION_ID",
        "NOTIFY_SOCKET",
        "LAUNCH_JOB_KEY",
        "XPC_SERVICE_NAME",
    ]
    .iter()
    .find(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()));
    managed.map_or(Ok(()), |name| {
        Err(SbhError::Runtime {
            details: format!(
                "{TEST_MODE_ENV} is set but the process runs under a service manager \
                 ({name} present); refusing to start with injected filesystem statistics"
            ),
        })
    })
}

/// Wrap `inner` in the overlay when the environment asks for it.
///
/// `SBH_TEST_FS_STATS` without `SBH_TEST_MODE=1` is ignored, so a stray
/// variable cannot change a production daemon's view of its disks. An
/// unparsable table is an error: a scenario must not run on real stats by
/// accident.
pub fn wrap_if_requested(inner: Arc<dyn Platform>) -> Result<Arc<dyn Platform>> {
    if !test_mode_requested() {
        return Ok(inner);
    }
    let Some(raw) = std::env::var_os(TEST_FS_STATS_ENV) else {
        return Ok(inner);
    };
    let table = InjectedFsTable::parse(&raw.to_string_lossy())?;
    eprintln!(
        "[SBH-TEST] {TEST_MODE_ENV}=1: {} injected mount(s) overlay the platform: {}",
        table.mounts.len(),
        table
            .mounts
            .iter()
            .map(|m| format!("{} total={} free={}", m.path.display(), m.total, m.free))
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(Arc::new(TestOverlayPlatform::new(inner, table)))
}

/// A platform whose mount queries answer from an injected table first.
pub struct TestOverlayPlatform {
    inner: Arc<dyn Platform>,
    table: InjectedFsTable,
    started: Instant,
}

impl TestOverlayPlatform {
    /// Overlay `table` on `inner`; series time starts now.
    #[must_use]
    pub fn new(inner: Arc<dyn Platform>, table: InjectedFsTable) -> Self {
        Self {
            inner,
            table,
            started: Instant::now(),
        }
    }

    fn elapsed_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    /// The injected table.
    #[must_use]
    pub fn table(&self) -> &InjectedFsTable {
        &self.table
    }
}

impl Platform for TestOverlayPlatform {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn fs_stats(&self, path: &Path) -> Result<FsStats> {
        self.table.owner(path).map_or_else(
            || self.inner.fs_stats(path),
            |mount| Ok(mount.stats_at(self.elapsed_secs())),
        )
    }

    fn mount_points(&self) -> Result<Vec<MountPoint>> {
        let mut mounts: Vec<MountPoint> = self
            .inner
            .mount_points()
            .unwrap_or_default()
            .into_iter()
            .filter(|real| !self.table.mounts.iter().any(|m| m.path == real.path))
            .collect();
        mounts.extend(self.table.mounts.iter().map(InjectedMount::mount_point));
        Ok(mounts)
    }

    fn is_ram_backed(&self, path: &Path) -> Result<bool> {
        self.table.owner(path).map_or_else(
            || self.inner.is_ram_backed(path),
            |mount| Ok(mount.ram_backed),
        )
    }

    fn default_paths(&self) -> PlatformPaths {
        self.inner.default_paths()
    }

    fn memory_info(&self) -> Result<MemoryInfo> {
        self.inner.memory_info()
    }

    fn service_manager(&self) -> Box<dyn ServiceManager> {
        self.inner.service_manager()
    }

    fn capacity(&self, mount: &Path) -> Result<Capacity> {
        self.fs_stats(mount).map(Into::into)
    }

    fn mounts(&self) -> Result<Vec<MountInfo>> {
        self.mount_points()
            .map(|mounts| mounts.into_iter().map(Into::into).collect())
    }

    fn local_time_machine_snapshots(&self, mount: &Path) -> Result<Vec<LocalSnapshotInfo>> {
        self.inner.local_time_machine_snapshots(mount)
    }

    fn memory_pressure(&self) -> Result<MemoryPressure> {
        self.inner.memory_pressure()
    }

    fn full_disk_access_status(&self) -> Result<FullDiskAccessStatus> {
        self.inner.full_disk_access_status()
    }

    fn subscribe_memory_pressure(
        &self,
        callback: MemoryPressureCallback,
    ) -> Result<SubscriptionHandle> {
        self.inner.subscribe_memory_pressure(callback)
    }

    fn process_list(&self) -> Result<Vec<ProcessInfo>> {
        self.inner.process_list()
    }

    fn process_io(&self, pid: i32) -> Result<ProcessIo> {
        self.inner.process_io(pid)
    }

    fn open_files_under(&self, path: &Path) -> Result<Vec<OpenFile>> {
        self.inner.open_files_under(path)
    }

    fn executables_under(&self, path: &Path) -> Result<Vec<ProcessInfo>> {
        self.inner.executables_under(path)
    }

    fn mmap_regions_under(&self, path: &Path) -> Result<Vec<MappedRegion>> {
        self.inner.mmap_regions_under(path)
    }

    fn self_stats(&self) -> Result<SelfStats> {
        self.inner.self_stats()
    }

    fn preallocate_file(&self, path: &Path, size: u64) -> Result<()> {
        self.inner.preallocate_file(path, size)
    }

    fn file_block_count(&self, path: &Path) -> Result<u64> {
        self.inner.file_block_count(path)
    }

    fn user_home(&self) -> PathBuf {
        self.inner.user_home()
    }

    fn temp_dirs(&self) -> Vec<PathBuf> {
        self.inner.temp_dirs()
    }

    fn cache_roots(&self) -> Vec<PathBuf> {
        self.inner.cache_roots()
    }

    fn sacred_paths(&self) -> Vec<SacredPath> {
        self.inner.sacred_paths()
    }

    fn service_kind(&self) -> ServiceKind {
        self.inner.service_kind()
    }

    fn writeback_state(&self) -> Result<WritebackState> {
        self.inner.writeback_state()
    }

    fn block_device_for(&self, path: &Path) -> Result<BlockDeviceInfo> {
        self.inner.block_device_for(path)
    }

    fn apply_writeback_runtime(&self, dirty_bytes: u64, dirty_background_bytes: u64) -> Result<()> {
        self.inner
            .apply_writeback_runtime(dirty_bytes, dirty_background_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::{InjectedFsTable, TestOverlayPlatform, refuse_under_service_manager};
    use crate::platform::pal::{MockPlatform, Platform};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    const TABLE: &str = r#"{"mounts":[
        {"path":"/injected","total":1000000,"free":120000,"fs_type":"btrfs"},
        {"path":"/injected/deep","total":50000,"free":40000,"ram_backed":true,
         "series":[{"after_secs":0,"free":30000},{"after_secs":3600,"free":1000}]}
    ]}"#;

    #[test]
    fn table_parses_and_rejects_impossible_readings() {
        let table = InjectedFsTable::parse(TABLE).unwrap();
        assert_eq!(table.mounts.len(), 2);
        assert_eq!(table.mounts[0].fs_type, "btrfs");
        assert!(table.mounts[1].ram_backed);
        assert!(
            InjectedFsTable::parse(r#"{"mounts":[{"path":"rel","total":10,"free":1}]}"#).is_err()
        );
        assert!(
            InjectedFsTable::parse(r#"{"mounts":[{"path":"/x","total":10,"free":11}]}"#).is_err()
        );
        assert!(
            InjectedFsTable::parse(r#"{"mounts":[{"path":"/x","total":0,"free":0}]}"#).is_err()
        );
        assert!(InjectedFsTable::parse("not json").is_err());
    }

    #[test]
    fn overlay_answers_from_the_longest_injected_prefix_and_delegates_the_rest() {
        let table = InjectedFsTable::parse(TABLE).unwrap();
        let overlay = TestOverlayPlatform::new(Arc::new(MockPlatform::healthy()), table);

        let outer = overlay.fs_stats(Path::new("/injected/projects/x")).unwrap();
        assert_eq!(outer.total_bytes, 1_000_000);
        assert_eq!(outer.available_bytes, 120_000);
        assert_eq!(outer.mount_point, PathBuf::from("/injected"));
        assert_eq!(outer.fs_type, "btrfs");

        // The deeper mount wins for its subtree and its series starts at 0 s.
        let deep = overlay.fs_stats(Path::new("/injected/deep/file")).unwrap();
        assert_eq!(deep.mount_point, PathBuf::from("/injected/deep"));
        assert_eq!(deep.available_bytes, 30_000);
        assert!(
            overlay
                .is_ram_backed(Path::new("/injected/deep/x"))
                .unwrap()
        );
        assert!(!overlay.is_ram_backed(Path::new("/injected/x")).unwrap());

        // Paths outside the table come from the real platform (the mock's `/`).
        let real = overlay.fs_stats(Path::new("/var/tmp")).unwrap();
        assert_eq!(real.mount_point, PathBuf::from("/"));

        let mounts = overlay.mount_points().unwrap();
        assert!(mounts.iter().any(|m| m.path == Path::new("/")));
        assert!(mounts.iter().any(|m| m.path == Path::new("/injected")));
        assert!(
            mounts
                .iter()
                .any(|m| m.path == Path::new("/injected/deep") && m.is_ram_backed)
        );
        assert_eq!(
            overlay
                .capacity(Path::new("/injected"))
                .unwrap()
                .total_bytes,
            1_000_000
        );
        assert_eq!(overlay.name(), MockPlatform::healthy().name());
    }

    #[test]
    fn series_steps_free_space_over_time() {
        let table = InjectedFsTable::parse(TABLE).unwrap();
        let mount = &table.mounts[1];
        assert_eq!(mount.free_at(0), 30_000);
        assert_eq!(mount.free_at(3599), 30_000);
        assert_eq!(mount.free_at(3600), 1_000);
        assert_eq!(
            table.mounts[0].free_at(10_000),
            120_000,
            "no series keeps the base reading"
        );
    }

    #[test]
    fn service_manager_refusal_only_applies_in_test_mode() {
        // Not in test mode: never refuses, whatever else is set.
        assert!(refuse_under_service_manager().is_ok());
    }
}
