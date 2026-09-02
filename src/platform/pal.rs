//! PAL trait and platform-specific implementations (Linux, macOS, Windows).

#![allow(missing_docs)]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::core::config::PathsConfig;
use crate::core::errors::{Result, SbhError};
use crate::platform::types::{
    Capacity, FullDiskAccessStatus, LocalSnapshotInfo, MappedRegion, MemoryPressure,
    MemoryPressureCallback, MemoryPressureLevel, MountInfo, OpenFile, PalError, ProcessInfo,
    ProcessIo, SacredPath, SelfStats, ServiceKind, SubscriptionHandle,
};

/// Filesystem statistics for a path/mount.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FsStats {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub available_bytes: u64,
    pub fs_type: String,
    pub mount_point: PathBuf,
    pub is_readonly: bool,
}

impl FsStats {
    #[must_use]
    pub fn free_pct(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        {
            (self.available_bytes as f64 * 100.0) / self.total_bytes as f64
        }
    }
}

/// Mount-point metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MountPoint {
    pub path: PathBuf,
    pub device: String,
    pub fs_type: String,
    pub is_ram_backed: bool,
}

/// Backing block-device characteristics for a path, used to size writeback limits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockDeviceInfo {
    /// Resolved base block device (e.g. `nvme0n1`, `sda`), or the raw device when
    /// the disk could not be resolved (LVM/mapper/network mounts).
    pub device: String,
    /// Raw device string from the mount table (e.g. `/dev/mapper/vg-root`).
    pub source_device: String,
    /// Filesystem type backing the path (e.g. `btrfs`, `ext4`).
    pub fs_type: String,
    /// `Some(true)` rotational (HDD), `Some(false)` non-rotational (SSD/NVMe),
    /// `None` when the rotational flag could not be read.
    pub rotational: Option<bool>,
    /// Device model string when available.
    pub model: Option<String>,
}

/// Current system memory info.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_free_bytes: u64,
}

/// Platform-specific data/service directories.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlatformPaths {
    pub ballast_dir: PathBuf,
    pub state_file: PathBuf,
    pub sqlite_db: PathBuf,
    pub jsonl_log: PathBuf,
}

impl From<FsStats> for Capacity {
    fn from(value: FsStats) -> Self {
        Self {
            mount_point: value.mount_point,
            fs_type: value.fs_type,
            total_bytes: value.total_bytes,
            free_bytes: value.free_bytes,
            available_bytes: value.available_bytes,
            is_readonly: value.is_readonly,
            container_id: None,
            container_total_bytes: None,
            container_available_bytes: None,
            volume_total_bytes: Some(value.total_bytes),
            volume_available_bytes: Some(value.available_bytes),
            volume_role: None,
            shared_volumes: Vec::new(),
            is_primary: false,
            purgeable_bytes: None,
            local_snapshot_bytes: None,
        }
    }
}

impl From<MountPoint> for MountInfo {
    fn from(value: MountPoint) -> Self {
        Self {
            device: value.device,
            mount_point: value.path,
            fs_type: value.fs_type,
            container_id: None,
            total_bytes: None,
            available_bytes: None,
            purgeable_bytes: None,
            local_snapshot_bytes: None,
            is_readonly: false,
            is_ram_backed: value.is_ram_backed,
            is_apfs_data_volume: false,
            is_apfs_system_snapshot: false,
            is_apfs_vm_volume: false,
        }
    }
}

impl Default for PlatformPaths {
    fn default() -> Self {
        let defaults = PathsConfig::default();
        Self {
            ballast_dir: defaults.ballast_dir,
            state_file: defaults.state_file,
            sqlite_db: defaults.sqlite_db,
            jsonl_log: defaults.jsonl_log,
        }
    }
}

fn pal_not_implemented<T>(os_name: &'static str, method_name: &'static str) -> Result<T> {
    Err(PalError::not_implemented(os_name, method_name).into())
}

pub(crate) fn verify_preallocated_blocks(
    os_name: &'static str,
    path: &Path,
    size: u64,
    blocks_512: u64,
) -> Result<()> {
    let allocated_bytes = blocks_512.checked_mul(512).ok_or_else(|| {
        PalError::method_failed(
            os_name,
            "preallocate_file",
            format!("allocated block count overflowed for {}", path.display()),
        )
    })?;

    if allocated_bytes < size {
        return Err(PalError::method_failed(
            os_name,
            "preallocate_file",
            format!(
                "{} has {allocated_bytes} allocated bytes after preallocation; expected at least {size}",
                path.display()
            ),
        )
        .into());
    }

    Ok(())
}

/// Service control surface (systemd, launchd, etc.).
pub trait ServiceManager: Send + Sync {
    fn install(&self) -> Result<()>;
    fn uninstall(&self) -> Result<()>;
    fn status(&self) -> Result<String>;

    fn watchdog_enabled(&self, watchdog_sec: u64) -> bool {
        let _ = watchdog_sec;
        false
    }

    fn notify_watchdog(&self, status: &str) -> Result<()> {
        let _ = status;
        Ok(())
    }

    /// Tell the service manager that startup is complete.
    ///
    /// systemd `Type=notify` units stay in `activating` until the daemon sends
    /// `READY=1` and are killed at `TimeoutStartSec` otherwise; managers
    /// without a readiness protocol accept the default no-op.
    fn notify_ready(&self) -> Result<()> {
        Ok(())
    }

    /// Tell the service manager that an orderly shutdown has begun
    /// (`STOPPING=1` for systemd). Default no-op.
    fn notify_stopping(&self) -> Result<()> {
        Ok(())
    }

    fn restart(&self) -> Result<()> {
        pal_not_implemented("service", "restart")
    }

    fn logs_path(&self) -> Result<Option<PathBuf>> {
        Ok(None)
    }

    fn is_loaded(&self) -> Result<bool> {
        let status = self.status()?;
        Ok(matches!(status.as_str(), "active" | "loaded" | "running"))
    }
}

/// OS abstraction used by monitoring and daemon orchestration.
pub trait Platform: Send + Sync {
    fn name(&self) -> &'static str {
        "unknown"
    }

    fn fs_stats(&self, path: &Path) -> Result<FsStats>;
    fn mount_points(&self) -> Result<Vec<MountPoint>>;
    fn is_ram_backed(&self, path: &Path) -> Result<bool>;
    fn default_paths(&self) -> PlatformPaths;
    fn memory_info(&self) -> Result<MemoryInfo>;
    fn service_manager(&self) -> Box<dyn ServiceManager>;

    fn capacity(&self, mount: &Path) -> Result<Capacity> {
        self.fs_stats(mount).map(Into::into)
    }

    fn mounts(&self) -> Result<Vec<MountInfo>> {
        self.mount_points()
            .map(|mounts| mounts.into_iter().map(Into::into).collect())
    }

    fn local_time_machine_snapshots(&self, _mount: &Path) -> Result<Vec<LocalSnapshotInfo>> {
        Ok(Vec::new())
    }

    fn memory_pressure(&self) -> Result<MemoryPressure> {
        pal_not_implemented(self.name(), "memory_pressure")
    }

    fn full_disk_access_status(&self) -> Result<FullDiskAccessStatus> {
        Ok(FullDiskAccessStatus::not_applicable(self.name()))
    }

    fn subscribe_memory_pressure(
        &self,
        _callback: MemoryPressureCallback,
    ) -> Result<SubscriptionHandle> {
        pal_not_implemented(self.name(), "subscribe_memory_pressure")
    }

    fn process_list(&self) -> Result<Vec<ProcessInfo>> {
        pal_not_implemented(self.name(), "process_list")
    }

    fn process_io(&self, _pid: i32) -> Result<ProcessIo> {
        pal_not_implemented(self.name(), "process_io")
    }

    fn open_files_under(&self, _path: &Path) -> Result<Vec<OpenFile>> {
        pal_not_implemented(self.name(), "open_files_under")
    }

    fn executables_under(&self, _path: &Path) -> Result<Vec<ProcessInfo>> {
        pal_not_implemented(self.name(), "executables_under")
    }

    fn mmap_regions_under(&self, _path: &Path) -> Result<Vec<MappedRegion>> {
        pal_not_implemented(self.name(), "mmap_regions_under")
    }

    fn self_stats(&self) -> Result<SelfStats> {
        pal_not_implemented(self.name(), "self_stats")
    }

    fn preallocate_file(&self, _path: &Path, _size: u64) -> Result<()> {
        pal_not_implemented(self.name(), "preallocate_file")
    }

    fn file_block_count(&self, path: &Path) -> Result<u64> {
        let meta = fs::metadata(path).map_err(|source| SbhError::Io {
            path: path.to_path_buf(),
            source,
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(meta.blocks())
        }
        #[cfg(not(unix))]
        {
            Ok(meta.len().saturating_add(511) / 512)
        }
    }

    fn user_home(&self) -> PathBuf {
        std::env::var_os("HOME").map_or_else(|| PathBuf::from("/"), PathBuf::from)
    }

    fn temp_dirs(&self) -> Vec<PathBuf> {
        vec![std::env::temp_dir()]
    }

    fn cache_roots(&self) -> Vec<PathBuf> {
        std::env::var_os("HOME")
            .map_or_else(Vec::new, |home| vec![PathBuf::from(home).join(".cache")])
    }

    fn sacred_paths(&self) -> Vec<SacredPath> {
        Vec::new()
    }

    fn service_kind(&self) -> ServiceKind {
        ServiceKind::None
    }

    /// Snapshot the kernel's current dirty-page (writeback) configuration.
    ///
    /// Only meaningful where the kernel exposes tunable writeback limits (Linux
    /// `/proc/sys/vm`). Other platforms return a not-implemented PAL error, which
    /// callers treat as "not applicable".
    fn writeback_state(&self) -> Result<crate::tuning::writeback::WritebackState> {
        pal_not_implemented(self.name(), "writeback_state")
    }

    /// Resolve the backing block device + characteristics for a path.
    fn block_device_for(&self, _path: &Path) -> Result<BlockDeviceInfo> {
        pal_not_implemented(self.name(), "block_device_for")
    }

    /// Apply writeback byte limits to the running kernel (requires privilege).
    ///
    /// This writes the live `/proc/sys/vm` knobs only; persistence across reboot
    /// is handled separately by the caller via a `sysctl.d` snippet. Never called
    /// from the daemon — only from privileged, operator-invoked CLI paths.
    fn apply_writeback_runtime(
        &self,
        _dirty_bytes: u64,
        _dirty_background_bytes: u64,
    ) -> Result<()> {
        pal_not_implemented(self.name(), "apply_writeback_runtime")
    }
}

/// No-op service manager for early development and tests.
#[derive(Debug, Default)]
pub struct NoopServiceManager;

impl ServiceManager for NoopServiceManager {
    fn install(&self) -> Result<()> {
        Ok(())
    }

    fn uninstall(&self) -> Result<()> {
        Ok(())
    }

    fn status(&self) -> Result<String> {
        Ok("unknown".to_string())
    }
}

/// In-memory mock implementation for deterministic tests.
#[derive(Debug, Clone)]
pub struct MockPlatform {
    name: &'static str,
    mounts: Vec<MountPoint>,
    stats_by_mount: HashMap<PathBuf, FsStats>,
    memory: MemoryInfo,
    paths: PlatformPaths,
    memory_pressure: MemoryPressure,
    full_disk_access: FullDiskAccessStatus,
    subscription: SubscriptionHandle,
    processes: Vec<ProcessInfo>,
    process_io: HashMap<i32, ProcessIo>,
    open_files: Vec<OpenFile>,
    executables: Vec<ProcessInfo>,
    mmap_regions: Vec<MappedRegion>,
    self_stats: SelfStats,
    preallocated: Vec<(PathBuf, u64)>,
    preallocate_failures: HashMap<PathBuf, PalError>,
    block_counts: HashMap<PathBuf, u64>,
    local_snapshots: HashMap<PathBuf, Vec<LocalSnapshotInfo>>,
    home: PathBuf,
    temp_dirs: Vec<PathBuf>,
    cache_roots: Vec<PathBuf>,
    sacred_paths: Vec<SacredPath>,
    service_kind: ServiceKind,
}

impl MockPlatform {
    #[must_use]
    pub fn new(
        mounts: Vec<MountPoint>,
        stats_by_mount: HashMap<PathBuf, FsStats>,
        memory: MemoryInfo,
        paths: PlatformPaths,
    ) -> Self {
        Self {
            name: "mock",
            mounts,
            stats_by_mount,
            memory,
            paths,
            memory_pressure: default_mock_memory_pressure(),
            full_disk_access: FullDiskAccessStatus::not_applicable("mock"),
            subscription: SubscriptionHandle::active("mock"),
            processes: Vec::new(),
            process_io: HashMap::new(),
            open_files: Vec::new(),
            executables: Vec::new(),
            mmap_regions: Vec::new(),
            self_stats: default_mock_self_stats(),
            preallocated: Vec::new(),
            preallocate_failures: HashMap::new(),
            block_counts: HashMap::new(),
            local_snapshots: HashMap::new(),
            home: PathBuf::from("/home/mock"),
            temp_dirs: vec![PathBuf::from("/tmp")],
            cache_roots: vec![PathBuf::from("/home/mock/.cache")],
            sacred_paths: Vec::new(),
            service_kind: ServiceKind::None,
        }
    }

    #[must_use]
    pub fn healthy() -> Self {
        let mount = PathBuf::from("/");
        let stats = FsStats {
            total_bytes: 1_000_000_000_000,
            free_bytes: 500_000_000_000,
            available_bytes: 500_000_000_000,
            fs_type: "mockfs".to_string(),
            mount_point: mount.clone(),
            is_readonly: false,
        };
        let mut stats_by_mount = HashMap::new();
        stats_by_mount.insert(mount.clone(), stats);
        Self::new(
            vec![MountPoint {
                path: mount,
                device: "mockdev".to_string(),
                fs_type: "mockfs".to_string(),
                is_ram_backed: false,
            }],
            stats_by_mount,
            MemoryInfo {
                total_bytes: 64 * 1024 * 1024 * 1024,
                available_bytes: 32 * 1024 * 1024 * 1024,
                swap_total_bytes: 8 * 1024 * 1024 * 1024,
                swap_free_bytes: 8 * 1024 * 1024 * 1024,
            },
            PlatformPaths::default(),
        )
    }

    #[must_use]
    pub fn with_name(mut self, name: &'static str) -> Self {
        self.name = name;
        self
    }

    #[must_use]
    pub fn with_memory_pressure(mut self, memory_pressure: MemoryPressure) -> Self {
        self.memory_pressure = memory_pressure;
        self
    }

    #[must_use]
    pub fn with_full_disk_access_status(mut self, status: FullDiskAccessStatus) -> Self {
        self.full_disk_access = status;
        self
    }

    #[must_use]
    pub fn with_subscription(mut self, subscription: SubscriptionHandle) -> Self {
        self.subscription = subscription;
        self
    }

    #[must_use]
    pub fn with_process(mut self, process: ProcessInfo) -> Self {
        self.processes.push(process);
        self
    }

    #[must_use]
    pub fn with_process_io(mut self, io: ProcessIo) -> Self {
        self.process_io.insert(io.pid, io);
        self
    }

    #[must_use]
    pub fn with_open_file(mut self, open_file: OpenFile) -> Self {
        self.open_files.push(open_file);
        self
    }

    #[must_use]
    pub fn with_executable(mut self, process: ProcessInfo) -> Self {
        self.executables.push(process);
        self
    }

    #[must_use]
    pub fn with_mmap_region(mut self, region: MappedRegion) -> Self {
        self.mmap_regions.push(region);
        self
    }

    #[must_use]
    pub fn with_self_stats(mut self, stats: SelfStats) -> Self {
        self.self_stats = stats;
        self
    }

    #[must_use]
    pub fn with_preallocated_file(mut self, path: impl Into<PathBuf>, size: u64) -> Self {
        self.preallocated.push((path.into(), size));
        self
    }

    #[must_use]
    pub fn with_preallocate_failure(mut self, path: impl Into<PathBuf>, failure: PalError) -> Self {
        self.preallocate_failures.insert(path.into(), failure);
        self
    }

    #[must_use]
    pub fn with_block_count(mut self, path: impl Into<PathBuf>, blocks: u64) -> Self {
        self.block_counts.insert(path.into(), blocks);
        self
    }

    #[must_use]
    pub fn with_local_time_machine_snapshots(
        mut self,
        mount: impl Into<PathBuf>,
        snapshots: Vec<LocalSnapshotInfo>,
    ) -> Self {
        self.local_snapshots.insert(mount.into(), snapshots);
        self
    }

    #[must_use]
    pub fn with_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = home.into();
        self
    }

    #[must_use]
    pub fn with_temp_dirs(mut self, temp_dirs: Vec<PathBuf>) -> Self {
        self.temp_dirs = temp_dirs;
        self
    }

    #[must_use]
    pub fn with_cache_roots(mut self, cache_roots: Vec<PathBuf>) -> Self {
        self.cache_roots = cache_roots;
        self
    }

    #[must_use]
    pub fn with_sacred_paths(mut self, sacred_paths: Vec<SacredPath>) -> Self {
        self.sacred_paths = sacred_paths;
        self
    }

    #[must_use]
    pub fn with_service_kind(mut self, service_kind: ServiceKind) -> Self {
        self.service_kind = service_kind;
        self
    }
}

impl Platform for MockPlatform {
    fn name(&self) -> &'static str {
        self.name
    }

    fn fs_stats(&self, path: &Path) -> Result<FsStats> {
        let mount = find_mount(path, &self.mounts).ok_or_else(|| SbhError::FsStats {
            path: path.to_path_buf(),
            details: "mock mount not found".to_string(),
        })?;
        self.stats_by_mount
            .get(&mount.path)
            .cloned()
            .ok_or_else(|| SbhError::FsStats {
                path: mount.path.clone(),
                details: "mock stats not found".to_string(),
            })
    }

    fn mount_points(&self) -> Result<Vec<MountPoint>> {
        Ok(self.mounts.clone())
    }

    fn local_time_machine_snapshots(&self, mount: &Path) -> Result<Vec<LocalSnapshotInfo>> {
        Ok(self.local_snapshots.get(mount).cloned().unwrap_or_default())
    }

    fn is_ram_backed(&self, path: &Path) -> Result<bool> {
        Ok(find_mount(path, &self.mounts).is_some_and(|mount| mount.is_ram_backed))
    }

    fn default_paths(&self) -> PlatformPaths {
        self.paths.clone()
    }

    fn memory_info(&self) -> Result<MemoryInfo> {
        Ok(self.memory.clone())
    }

    fn service_manager(&self) -> Box<dyn ServiceManager> {
        Box::<NoopServiceManager>::default()
    }

    fn memory_pressure(&self) -> Result<MemoryPressure> {
        Ok(self.memory_pressure.clone())
    }

    fn full_disk_access_status(&self) -> Result<FullDiskAccessStatus> {
        Ok(self.full_disk_access.clone())
    }

    fn subscribe_memory_pressure(
        &self,
        _callback: MemoryPressureCallback,
    ) -> Result<SubscriptionHandle> {
        Ok(self.subscription.clone())
    }

    fn process_list(&self) -> Result<Vec<ProcessInfo>> {
        Ok(self.processes.clone())
    }

    fn process_io(&self, pid: i32) -> Result<ProcessIo> {
        self.process_io
            .get(&pid)
            .cloned()
            .ok_or_else(|| PalError::not_implemented(self.name(), "process_io").into())
    }

    fn open_files_under(&self, path: &Path) -> Result<Vec<OpenFile>> {
        let root = crate::core::paths::resolve_absolute_path(path);
        Ok(self
            .open_files
            .iter()
            .filter(|open_file| {
                crate::core::paths::resolve_absolute_path(&open_file.path).starts_with(&root)
            })
            .cloned()
            .collect())
    }

    fn executables_under(&self, path: &Path) -> Result<Vec<ProcessInfo>> {
        let root = crate::core::paths::resolve_absolute_path(path);
        Ok(self
            .executables
            .iter()
            .filter(|process| {
                process.executable.as_deref().is_some_and(|executable| {
                    crate::core::paths::resolve_absolute_path(executable).starts_with(&root)
                })
            })
            .cloned()
            .collect())
    }

    fn mmap_regions_under(&self, path: &Path) -> Result<Vec<MappedRegion>> {
        let root = crate::core::paths::resolve_absolute_path(path);
        Ok(self
            .mmap_regions
            .iter()
            .filter(|region| {
                crate::core::paths::resolve_absolute_path(&region.path).starts_with(&root)
            })
            .cloned()
            .collect())
    }

    fn self_stats(&self) -> Result<SelfStats> {
        Ok(self.self_stats.clone())
    }

    fn preallocate_file(&self, path: &Path, size: u64) -> Result<()> {
        if let Some(failure) = self.preallocate_failures.get(path) {
            return Err(SbhError::Pal {
                source: failure.clone(),
            });
        }

        let request_is_expected = self
            .preallocated
            .iter()
            .any(|(expected_path, expected_size)| expected_path == path && *expected_size == size)
            || self.preallocated.is_empty();

        if !request_is_expected {
            return Err(PalError::method_failed(
                self.name(),
                "preallocate_file",
                format!(
                    "unexpected mock preallocation request for {}",
                    path.display()
                ),
            )
            .into());
        }

        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let file = opts.open(path).map_err(|source| SbhError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        file.set_len(size).map_err(|source| SbhError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        file.sync_all().map_err(|source| SbhError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }

    fn file_block_count(&self, path: &Path) -> Result<u64> {
        Ok(self.block_counts.get(path).copied().unwrap_or(0))
    }

    fn user_home(&self) -> PathBuf {
        self.home.clone()
    }

    fn temp_dirs(&self) -> Vec<PathBuf> {
        self.temp_dirs.clone()
    }

    fn cache_roots(&self) -> Vec<PathBuf> {
        self.cache_roots.clone()
    }

    fn sacred_paths(&self) -> Vec<SacredPath> {
        self.sacred_paths.clone()
    }

    fn service_kind(&self) -> ServiceKind {
        self.service_kind
    }
}

impl Default for MockPlatform {
    fn default() -> Self {
        Self::healthy()
    }
}

fn default_mock_memory_pressure() -> MemoryPressure {
    MemoryPressure {
        level: MemoryPressureLevel::Normal,
        free_pages: None,
        used_pages: None,
        page_size_bytes: None,
        compressor_used_bytes: None,
        swap_total_bytes: None,
        swap_used_bytes: None,
        linux_psi_avg10: None,
    }
}

fn default_mock_self_stats() -> SelfStats {
    SelfStats {
        rss_bytes: 0,
        virtual_memory_bytes: 0,
        cpu_user_micros: 0,
        cpu_system_micros: 0,
        idle_wakeups: None,
        bytes_read: None,
        bytes_written: None,
    }
}

/// Detect active platform implementation.
pub fn detect_platform() -> Result<Arc<dyn Platform>> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        Ok(Arc::new(crate::platform::current()))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(SbhError::UnsupportedPlatform {
            details: "sbh requires Linux or macOS".to_string(),
        })
    }
}

fn find_mount<'a>(path: &Path, mounts: &'a [MountPoint]) -> Option<&'a MountPoint> {
    mounts
        .iter()
        .filter(|mount| path.starts_with(&mount.path))
        .max_by_key(|mount| mount.path.as_os_str().len())
}

#[cfg(test)]
mod tests {
    use super::{MockPlatform, Platform, ServiceKind};
    use crate::platform::types::{
        MappedRegion, OpenFile, OpenFileKind, OpenFileMode, ProcessInfo, ProcessIo, SacredPath,
        SacredPathKind, SacredPathSource,
    };
    use std::path::PathBuf;

    fn process(pid: i32, name: &str, executable: Option<PathBuf>) -> ProcessInfo {
        ProcessInfo {
            pid,
            parent_pid: None,
            name: name.to_string(),
            command_line: Vec::new(),
            executable,
            cwd: None,
            start_time_unix_ms: None,
            virtual_memory_bytes: None,
            resident_memory_bytes: None,
            cpu_user_micros: None,
            cpu_system_micros: None,
        }
    }

    #[test]
    fn mock_platform_builder_covers_extended_pal_methods() {
        let temp = tempfile::tempdir().expect("mock root tempdir");
        let root = temp.path().to_path_buf();
        let open_path = root.join("target/debug/object.o");
        let executable_path = root.join("target/debug/tool");
        let mmap_path = root.join("target/incremental/cache.bin");
        let ballast_path = root.join("ballast.bin");
        let sacred = SacredPath {
            pattern: "~/Pictures/Photos Library.photoslibrary".to_string(),
            kind: SacredPathKind::ExactMatch,
            reason: "Photos library".to_string(),
            source: SacredPathSource::Builtin,
        };

        let platform = MockPlatform::healthy()
            .with_name("mock-macos")
            .with_process(process(42, "rustc", None))
            .with_process_io(ProcessIo {
                pid: 42,
                bytes_read_total: 10,
                bytes_written_total: 20,
                bytes_read_recent_15m: Some(3),
                bytes_written_recent_15m: Some(4),
            })
            .with_open_file(OpenFile {
                pid: 42,
                path: open_path.clone(),
                fd: Some(9),
                kind: OpenFileKind::Regular,
                mode: OpenFileMode::ReadWrite,
            })
            .with_executable(process(42, "rustc", Some(executable_path.clone())))
            .with_mmap_region(MappedRegion {
                pid: 42,
                path: mmap_path.clone(),
                start_address: Some(0x1000),
                end_address: Some(0x2000),
                protection: Some("r--".to_string()),
            })
            .with_block_count(ballast_path.clone(), 16)
            .with_preallocated_file(ballast_path.clone(), 1024)
            .with_home("/Users/mock")
            .with_temp_dirs(vec![PathBuf::from("/private/tmp")])
            .with_cache_roots(vec![PathBuf::from("/Users/mock/Library/Caches")])
            .with_sacred_paths(vec![sacred.clone()])
            .with_service_kind(ServiceKind::Launchd);

        assert_eq!(platform.name(), "mock-macos");
        assert_eq!(platform.process_list().unwrap()[0].pid, 42);
        assert_eq!(platform.process_io(42).unwrap().bytes_written_total, 20);
        assert_eq!(platform.open_files_under(&root).unwrap()[0].path, open_path);
        assert_eq!(
            platform.executables_under(&root).unwrap()[0].executable,
            Some(executable_path)
        );
        assert_eq!(
            platform.mmap_regions_under(&root).unwrap()[0].path,
            mmap_path
        );
        assert_eq!(platform.file_block_count(&ballast_path).unwrap(), 16);
        platform.preallocate_file(&ballast_path, 1024).unwrap();
        assert_eq!(platform.user_home(), PathBuf::from("/Users/mock"));
        assert_eq!(platform.temp_dirs(), vec![PathBuf::from("/private/tmp")]);
        assert_eq!(
            platform.cache_roots(),
            vec![PathBuf::from("/Users/mock/Library/Caches")]
        );
        assert_eq!(platform.sacred_paths(), vec![sacred]);
        assert_eq!(platform.service_kind(), ServiceKind::Launchd);
    }

    #[test]
    fn mock_platform_drives_active_reference_collection_without_real_syscalls() {
        let temp = tempfile::tempdir().expect("active reference tempdir");
        let root = temp.path().to_path_buf();
        let candidate = root.join("target");
        let open_path = candidate.join("debug/object.o");
        let executable_path = candidate.join("debug/tool");
        let mmap_path = candidate.join("incremental/cache.bin");

        let platform = MockPlatform::healthy()
            .with_process(process(7, "cargo", None))
            .with_open_file(OpenFile {
                pid: 7,
                path: open_path,
                fd: Some(3),
                kind: OpenFileKind::Regular,
                mode: OpenFileMode::Read,
            })
            .with_executable(process(7, "cargo", Some(executable_path)))
            .with_mmap_region(MappedRegion {
                pid: 7,
                path: mmap_path,
                start_address: Some(0x1000),
                end_address: Some(0x2000),
                protection: Some("r--".to_string()),
            });

        let index = crate::scanner::walker::collect_active_reference_index(
            &platform,
            std::slice::from_ref(&root),
        );
        let normalized_candidate = crate::core::paths::resolve_absolute_path(&candidate);
        let summary = index.summary_for(&normalized_candidate);
        let process = summary
            .processes
            .iter()
            .find(|process| process.pid == 7)
            .expect("mock process should be represented in active reference summary");

        assert!(index.is_complete());
        assert_eq!(process.name.as_deref(), Some("cargo"));
        assert_eq!(process.open_file_descriptors, 1);
        assert!(process.running_executable);
        assert_eq!(process.mmap_regions, 1);
    }
}
