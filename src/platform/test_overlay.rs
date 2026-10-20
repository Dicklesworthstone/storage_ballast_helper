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
    Capacity, ExecutablesResult, FullDiskAccessStatus, LocalSnapshotInfo, MappedRegion,
    MemoryPressure, MemoryPressureCallback, MountInfo, OpenFilesResult, ProcessInfo, ProcessIo,
    SacredPath, SelfStats, ServiceKind, SubscriptionHandle,
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
        // A real mount at or under an injected one is shadowed: the injected
        // mount answers every query below it. Listed anyway, it gave the
        // collector a binding whose readings named the injected mount, so
        // each collection of it failed the ownership check and dropped the
        // whole topology; with `/` injected that was every real mount, and
        // the idle daemon re-resolved all of them several times a second
        // (~100 mounts on trj, bd-du48).
        let mut mounts: Vec<MountPoint> = self
            .inner
            .mount_points()
            .unwrap_or_default()
            .into_iter()
            .filter(|real| self.table.owner(&real.path).is_none())
            .collect();
        mounts.extend(self.table.mounts.iter().map(InjectedMount::mount_point));
        Ok(mounts)
    }

    fn mount_lookup_path(&self, path: &Path) -> Result<PathBuf> {
        self.table.owner(path).map_or_else(
            || self.inner.mount_lookup_path(path),
            |_| Ok(crate::core::paths::resolve_absolute_path(path)),
        )
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

    fn ram_write_memory_refusal(&self, minimum_available_percent: u8) -> Result<Option<String>> {
        self.inner
            .ram_write_memory_refusal(minimum_available_percent)
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

    fn process_list_without_command_lines(&self) -> Result<Vec<ProcessInfo>> {
        self.inner.process_list_without_command_lines()
    }

    fn process_list_brief(&self) -> Result<Vec<ProcessInfo>> {
        self.inner.process_list_brief()
    }

    fn process_io(&self, pid: i32) -> Result<ProcessIo> {
        self.inner.process_io(pid)
    }

    fn open_files_under(&self, path: &Path) -> Result<OpenFilesResult> {
        self.inner.open_files_under(path)
    }

    fn build_directories_in_use(&self) -> Vec<(i32, std::path::PathBuf)> {
        self.inner.build_directories_in_use()
    }

    fn build_directories_in_use_checked(&self) -> (Vec<(i32, PathBuf)>, bool) {
        self.inner.build_directories_in_use_checked()
    }

    fn executables_under(&self, path: &Path) -> Result<ExecutablesResult> {
        self.inner.executables_under(path)
    }

    fn mmap_regions_under(&self, path: &Path) -> Result<Vec<MappedRegion>> {
        self.inner.mmap_regions_under(path)
    }

    fn mmap_regions_under_roots(&self, roots: &[PathBuf]) -> Result<Vec<MappedRegion>> {
        self.inner.mmap_regions_under_roots(roots)
    }

    fn open_files_under_roots(&self, roots: &[std::path::PathBuf]) -> Result<OpenFilesResult> {
        self.inner.open_files_under_roots(roots)
    }

    fn executables_under_roots(&self, roots: &[std::path::PathBuf]) -> Result<ExecutablesResult> {
        self.inner.executables_under_roots(roots)
    }

    fn self_stats(&self) -> Result<SelfStats> {
        self.inner.self_stats()
    }

    fn preallocate_file(&self, path: &Path, size: u64) -> Result<()> {
        self.inner.preallocate_file(path, size)
    }

    fn preallocate_open_file(&self, file: &std::fs::File, path: &Path, size: u64) -> Result<()> {
        self.inner.preallocate_open_file(file, path, size)
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

    /// bd-du48: a real mount under an injected one is not listed, so the
    /// collector binds the path to the injected mount and reads it without
    /// rediscovering the topology. Before, the real `/injected/real` was
    /// listed, its reading named `/injected`, and every collection failed
    /// the ownership check and dropped the topology.
    #[test]
    fn real_mounts_under_an_injected_mount_are_shadowed() {
        use crate::monitor::fs_stats::FsStatsCollector;
        use crate::platform::pal::{FsStats, MemoryInfo, MountPoint, PlatformPaths};
        use std::collections::HashMap;
        use std::time::Duration;

        let real = |path: &str| MountPoint {
            path: PathBuf::from(path),
            device: format!("dev{path}"),
            fs_type: "realfs".to_string(),
            is_ram_backed: false,
        };
        let stats = |path: &str| FsStats {
            total_bytes: 9_000,
            free_bytes: 9_000,
            available_bytes: 9_000,
            fs_type: "realfs".to_string(),
            mount_point: PathBuf::from(path),
            is_readonly: false,
        };
        let mounts = ["/", "/injected/real", "/other"];
        let inner = MockPlatform::new(
            mounts.iter().map(|path| real(path)).collect(),
            mounts
                .iter()
                .map(|path| (PathBuf::from(path), stats(path)))
                .collect::<HashMap<_, _>>(),
            MemoryInfo {
                total_bytes: 1 << 30,
                available_bytes: 1 << 29,
                swap_total_bytes: 0,
                swap_free_bytes: 0,
            },
            PlatformPaths::default(),
        );
        let overlay =
            TestOverlayPlatform::new(Arc::new(inner), InjectedFsTable::parse(TABLE).unwrap());

        let listed: Vec<PathBuf> = overlay
            .mount_points()
            .unwrap()
            .into_iter()
            .map(|mount| mount.path)
            .collect();
        assert!(listed.contains(&PathBuf::from("/other")), "{listed:?}");
        assert!(listed.contains(&PathBuf::from("/injected")), "{listed:?}");
        assert!(
            !listed.contains(&PathBuf::from("/injected/real")),
            "{listed:?}"
        );

        let collector = FsStatsCollector::new(Arc::new(overlay), Duration::from_secs(60));
        let reading = collector
            .collect(Path::new("/injected/real/file"))
            .expect("the injected mount answers for the shadowed real one");
        assert_eq!(reading.mount_point, PathBuf::from("/injected"));
        assert_eq!(reading.available_bytes, 120_000);
        assert_eq!(
            collector
                .collect(Path::new("/other/x"))
                .unwrap()
                .available_bytes,
            9_000
        );
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

    #[test]
    fn descriptor_preallocation_delegates_failure_without_touching_the_file() {
        use crate::platform::types::PalError;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("ballast");
        std::fs::write(&path, b"preserve").unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let inner = MockPlatform::healthy().with_preallocate_failure(
            &path,
            PalError::method_failed("mock", "preallocate_file", "ENOSPC"),
        );
        let overlay = TestOverlayPlatform::new(Arc::new(inner), InjectedFsTable::default());
        let error = overlay
            .preallocate_open_file(&file, &path, 8192)
            .unwrap_err();
        assert!(error.to_string().contains("ENOSPC"));
        assert_eq!(std::fs::read(path).unwrap(), b"preserve");
    }

    mod reference_delegation {
        use super::*;
        use crate::core::errors::Result;
        use crate::platform::pal::{
            FsStats, MemoryInfo, MountPoint, PlatformPaths, ServiceManager,
        };
        use crate::platform::types::{
            ExecutablesResult, MappedRegion, OpenFile, OpenFileKind, OpenFileMode, OpenFilesResult,
            PalError, ProcessInfo,
        };
        use std::sync::Mutex;

        #[derive(Default)]
        struct StrictReferences {
            calls: Mutex<Vec<&'static str>>,
        }

        impl StrictReferences {
            fn record(&self, name: &'static str) {
                self.calls.lock().unwrap().push(name);
            }

            fn batch(&self, name: &'static str, roots: &[PathBuf]) {
                assert_eq!(roots, &[PathBuf::from("/one"), PathBuf::from("/two")]);
                self.record(name);
            }
        }

        impl Platform for StrictReferences {
            fn fs_stats(&self, path: &Path) -> Result<FsStats> {
                MockPlatform::healthy().fs_stats(path)
            }
            fn mount_points(&self) -> Result<Vec<MountPoint>> {
                Ok(Vec::new())
            }
            fn is_ram_backed(&self, _: &Path) -> Result<bool> {
                Ok(false)
            }
            fn default_paths(&self) -> PlatformPaths {
                PlatformPaths::default()
            }
            fn memory_info(&self) -> Result<MemoryInfo> {
                MockPlatform::healthy().memory_info()
            }
            fn service_manager(&self) -> Box<dyn ServiceManager> {
                panic!("process evidence must not control services")
            }
            fn process_list(&self) -> Result<Vec<ProcessInfo>> {
                panic!("no-argv queries must not fall back to command-line reads")
            }
            fn process_list_without_command_lines(&self) -> Result<Vec<ProcessInfo>> {
                self.record("processes");
                Ok(Vec::new())
            }
            fn build_directories_in_use(&self) -> Vec<(i32, PathBuf)> {
                panic!("checked evidence must not pass through a positive-only API")
            }
            fn build_directories_in_use_checked(&self) -> (Vec<(i32, PathBuf)>, bool) {
                self.record("builds");
                (vec![(42, PathBuf::from("/active"))], false)
            }
            fn open_files_under(&self, _: &Path) -> Result<OpenFilesResult> {
                panic!("batch descriptor scope must not be split into per-root queries")
            }
            fn open_files_under_roots(&self, roots: &[PathBuf]) -> Result<OpenFilesResult> {
                self.batch("files", roots);
                Ok(OpenFilesResult {
                    files: vec![OpenFile {
                        pid: 42,
                        path: PathBuf::from("/one/active"),
                        fd: Some(7),
                        kind: OpenFileKind::Regular,
                        mode: OpenFileMode::Read,
                    }],
                    complete: false,
                    incomplete_reason: Some("unreadable peer process".to_owned()),
                })
            }
            fn executables_under(&self, _: &Path) -> Result<ExecutablesResult> {
                panic!("batch executable scope must not be split")
            }
            fn executables_under_roots(&self, roots: &[PathBuf]) -> Result<ExecutablesResult> {
                self.batch("executables", roots);
                Ok(ExecutablesResult {
                    processes: Vec::new(),
                    complete: false,
                })
            }
            fn mmap_regions_under(&self, _: &Path) -> Result<Vec<MappedRegion>> {
                panic!("batch mapping scope must not be split")
            }
            fn mmap_regions_under_roots(&self, roots: &[PathBuf]) -> Result<Vec<MappedRegion>> {
                self.batch("mappings", roots);
                Err(PalError::method_failed(
                    "fixture",
                    "mmap_regions_under_roots",
                    "mapped metadata refused",
                )
                .into())
            }
        }

        #[test]
        fn checked_build_observation_keeps_partial_positives_and_coverage() {
            let inner = Arc::new(StrictReferences::default());
            let overlay = TestOverlayPlatform::new(inner.clone(), InjectedFsTable::default());
            let (directories, complete) = overlay.build_directories_in_use_checked();
            assert!(!complete);
            assert_eq!(directories, vec![(42, PathBuf::from("/active"))]);
            assert_eq!(*inner.calls.lock().unwrap(), vec!["builds"]);
        }

        #[test]
        fn batch_results_keep_partial_references_errors_and_one_shared_query() {
            let inner = Arc::new(StrictReferences::default());
            let overlay = TestOverlayPlatform::new(inner.clone(), InjectedFsTable::default());
            let roots = vec![PathBuf::from("/one"), PathBuf::from("/two")];
            let files = overlay.open_files_under_roots(&roots).unwrap();
            assert!(!files.complete);
            assert_eq!(
                files.incomplete_reason.as_deref(),
                Some("unreadable peer process")
            );
            assert_eq!(files.files.len(), 1);
            assert_eq!(files.files[0].path, PathBuf::from("/one/active"));
            assert_eq!(files.files[0].pid, 42);
            assert_eq!(files.files[0].fd, Some(7));
            let executables = overlay.executables_under_roots(&roots).unwrap();
            assert!(!executables.complete);
            assert!(executables.processes.is_empty());
            let error = overlay.mmap_regions_under_roots(&roots).unwrap_err();
            assert!(error.to_string().contains("mapped metadata refused"));
            assert_eq!(
                *inner.calls.lock().unwrap(),
                vec!["files", "executables", "mappings"]
            );
        }

        #[test]
        fn nested_overlays_do_not_reintroduce_argv_reads_or_complete_verdicts() {
            let inner = Arc::new(StrictReferences::default());
            let first = Arc::new(TestOverlayPlatform::new(
                inner.clone(),
                InjectedFsTable::default(),
            ));
            let outer = TestOverlayPlatform::new(first, InjectedFsTable::default());
            assert!(
                outer
                    .process_list_without_command_lines()
                    .unwrap()
                    .is_empty()
            );
            let (directories, complete) = outer.build_directories_in_use_checked();
            assert!(!complete);
            assert_eq!(directories, vec![(42, PathBuf::from("/active"))]);
            assert_eq!(*inner.calls.lock().unwrap(), vec!["processes", "builds"]);
        }
    }
}
