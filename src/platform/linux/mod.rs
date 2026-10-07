//! Linux PAL implementation.

#![allow(missing_docs)]

pub mod cleanup_catalog;

#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use parking_lot::RwLock;

#[cfg(target_os = "linux")]
use crate::core::errors::{Result, SbhError};
#[cfg(target_os = "linux")]
use crate::platform::pal::{
    BlockDeviceInfo, FsStats, MemoryInfo, MountPoint, Platform, PlatformPaths, ServiceManager,
    verify_preallocated_blocks,
};
#[cfg(target_os = "linux")]
use crate::platform::sacred_catalog::cross_platform_sacred_paths;
#[cfg(target_os = "linux")]
use crate::platform::types::{
    ExecutablesResult, MemoryPressure, MemoryPressureCallback, OpenFilesResult, PalError,
    ProcessInfo, ProcessIo, SacredPath, SelfStats, ServiceKind, SubscriptionHandle,
};

#[cfg(target_os = "linux")]
pub mod disk;
#[cfg(target_os = "linux")]
pub mod memory;
#[cfg(target_os = "linux")]
pub mod process;
#[cfg(target_os = "linux")]
pub mod service;
#[cfg(target_os = "linux")]
pub mod writeback;

/// Linux platform implementation using `/proc` + `statvfs`.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct LinuxPal {
    mounts_cache: RwLock<Option<(Vec<MountPoint>, Instant)>>,
    cache_ttl: Duration,
}

#[cfg(target_os = "linux")]
impl Default for LinuxPal {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl LinuxPal {
    #[must_use]
    pub fn new() -> Self {
        Self {
            mounts_cache: RwLock::new(None),
            cache_ttl: Duration::from_secs(5),
        }
    }

    fn get_cached_mounts(&self) -> Result<Vec<MountPoint>> {
        {
            let cache = self.mounts_cache.read();
            if let Some((mounts, collected_at)) = &*cache
                && collected_at.elapsed() < self.cache_ttl
            {
                return Ok(mounts.clone());
            }
        }

        let mounts = disk::read_mount_points()?;
        *self.mounts_cache.write() = Some((mounts.clone(), Instant::now()));
        Ok(mounts)
    }
}

/// Resolve once per query, before both classification and capacity inspection.
/// Lexically removing `..` before following a symlink changes its meaning.
/// Do not cache these resolutions: an operator can retarget a pool alias while
/// the mount table itself is unchanged. Failure is unknown, not disk-backed.
#[cfg(target_os = "linux")]
fn resolve_mount_path(path: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(path).map_err(|error| SbhError::FsStats {
        path: path.to_path_buf(),
        details: format!("could not resolve mount query: {error}"),
    })
}

#[cfg(target_os = "linux")]
impl Platform for LinuxPal {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn fs_stats(&self, path: &Path) -> Result<FsStats> {
        let resolved = resolve_mount_path(path)?;
        let mounts = self.mount_points()?;
        let mount = disk::find_mount(&resolved, &mounts).ok_or_else(|| SbhError::FsStats {
            path: path.to_path_buf(),
            details: "could not map resolved path to mount point".to_string(),
        })?;
        let stat = nix::sys::statvfs::statvfs(&resolved).map_err(|error| SbhError::FsStats {
            path: path.to_path_buf(),
            details: error.to_string(),
        })?;
        let fragment = stat.fragment_size() as u64;
        Ok(FsStats {
            total_bytes: stat.blocks().saturating_mul(fragment),
            free_bytes: stat.blocks_free().saturating_mul(fragment),
            available_bytes: stat.blocks_available().saturating_mul(fragment),
            fs_type: mount.fs_type.clone(),
            mount_point: mount.path.clone(),
            is_readonly: stat.flags().contains(nix::sys::statvfs::FsFlags::ST_RDONLY),
        })
    }

    fn mount_points(&self) -> Result<Vec<MountPoint>> {
        self.get_cached_mounts()
    }

    fn is_ram_backed(&self, path: &Path) -> Result<bool> {
        let resolved = resolve_mount_path(path)?;
        let mounts = self.mount_points()?;
        let mount = disk::find_mount(&resolved, &mounts).ok_or_else(|| SbhError::FsStats {
            path: path.to_path_buf(),
            details: "could not map resolved path to mount point".to_string(),
        })?;
        Ok(mount.is_ram_backed)
    }

    fn default_paths(&self) -> PlatformPaths {
        PlatformPaths::default()
    }

    fn memory_info(&self) -> Result<MemoryInfo> {
        memory::read_memory_info()
    }

    fn memory_pressure(&self) -> Result<MemoryPressure> {
        memory::read_memory_pressure()
    }

    fn subscribe_memory_pressure(
        &self,
        callback: MemoryPressureCallback,
    ) -> Result<SubscriptionHandle> {
        memory::subscribe_memory_pressure(callback)
    }

    fn process_list(&self) -> Result<Vec<ProcessInfo>> {
        process::read_process_list()
    }

    fn process_io(&self, pid: i32) -> Result<ProcessIo> {
        process::read_process_io(pid)
    }

    fn open_files_under(&self, path: &Path) -> Result<OpenFilesResult> {
        process::read_open_files_under(path)
    }

    fn executables_under(&self, path: &Path) -> Result<ExecutablesResult> {
        process::read_executables_under(path)
    }

    fn mmap_regions_under(&self, path: &Path) -> Result<Vec<crate::platform::types::MappedRegion>> {
        process::read_mmap_regions_under(path)
    }

    fn self_stats(&self) -> Result<SelfStats> {
        process::read_self_stats()
    }

    fn service_manager(&self) -> Box<dyn ServiceManager> {
        service::service_manager()
    }

    fn preallocate_file(&self, path: &Path, size: u64) -> Result<()> {
        use rustix::fs::{FallocateFlags, fallocate};
        use std::os::unix::fs::OpenOptionsExt as _;

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| SbhError::io(path, error))?;

        fallocate(&file, FallocateFlags::empty(), 0, size).map_err(|error| {
            PalError::method_failed("linux", "preallocate_file", error.to_string())
        })?;
        file.sync_all().map_err(|error| SbhError::io(path, error))?;

        let blocks = self.file_block_count(path)?;
        verify_preallocated_blocks("linux", path, size, blocks)
    }

    fn sacred_paths(&self) -> Vec<SacredPath> {
        cross_platform_sacred_paths().to_vec()
    }

    fn service_kind(&self) -> ServiceKind {
        ServiceKind::Systemd
    }

    fn writeback_state(&self) -> Result<crate::tuning::writeback::WritebackState> {
        let total_ram_bytes = self.memory_info()?.total_bytes;
        Ok(writeback::read_state(total_ram_bytes))
    }

    fn block_device_for(&self, path: &Path) -> Result<BlockDeviceInfo> {
        let resolved = resolve_mount_path(path)?;
        let mounts = self.mount_points()?;
        writeback::block_device_for(&resolved, &mounts)
    }

    fn apply_writeback_runtime(&self, dirty_bytes: u64, dirty_background_bytes: u64) -> Result<()> {
        writeback::apply_runtime(dirty_bytes, dirty_background_bytes)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn preallocate_file_reserves_blocks_on_linux() {
        let dir = tempfile::TempDir::new().expect("temp dir should be created");
        let path = dir.path().join("preallocated-linux.bin");
        let size = 1024 * 1024;
        let platform = LinuxPal::new();

        platform
            .preallocate_file(&path, size)
            .expect("linux preallocation should succeed");

        let metadata = std::fs::metadata(&path).expect("preallocated file should exist");
        assert_eq!(metadata.len(), size);
        let allocated_bytes = platform
            .file_block_count(&path)
            .expect("block count should be readable")
            * 512;
        assert!(allocated_bytes >= size);
    }

    #[test]
    fn linux_pal_self_stats_reports_current_process() {
        let platform = LinuxPal::new();
        let stats = platform
            .self_stats()
            .expect("linux self stats should be readable");

        assert!(stats.rss_bytes > 0);
        assert!(stats.virtual_memory_bytes >= stats.rss_bytes);
        assert_eq!(stats.idle_wakeups, None);
        assert!(stats.bytes_read.is_some());
        assert!(stats.bytes_written.is_some());
    }

    // Free bytes can change between probes; compare mount identity and stable
    // capacity properties, not a fictitious globally frozen filesystem.
    fn assert_same_mount(platform: &LinuxPal, target: &Path, query: &Path) {
        let expected = platform.fs_stats(target).unwrap();
        let actual = platform.fs_stats(query).unwrap();
        assert_eq!(actual.mount_point, expected.mount_point, "query={query:?}");
        assert_eq!(actual.fs_type, expected.fs_type, "query={query:?}");
        assert_eq!(actual.total_bytes, expected.total_bytes);
        assert_eq!(actual.is_readonly, expected.is_readonly);
        assert_eq!(
            platform.is_ram_backed(query).unwrap(),
            platform.is_ram_backed(target).unwrap()
        );
        let expected_device = platform.block_device_for(target).unwrap();
        let actual_device = platform.block_device_for(query).unwrap();
        assert_eq!(actual_device.source_device, expected_device.source_device);
        assert_eq!(actual_device.fs_type, expected_device.fs_type);
    }

    #[test]
    fn relative_mount_queries_match_the_resolved_working_directory() {
        let platform = LinuxPal::new();
        let cwd = std::fs::canonicalize(".").unwrap();
        for path in [Path::new("."), Path::new("./.")] {
            assert_same_mount(&platform, &cwd, path);
        }
    }

    #[test]
    fn symlinked_directory_and_file_use_the_targets_mount() {
        let temp = tempfile::tempdir().unwrap();
        let platform = LinuxPal::new();
        for (name, target) in [("directory", "/proc"), ("file", "/proc/self/status")] {
            let alias = temp.path().join(name);
            std::os::unix::fs::symlink(target, &alias).unwrap();
            assert_same_mount(&platform, Path::new(target), &alias);
            assert_eq!(std::fs::read_link(alias).unwrap(), Path::new(target));
        }
    }

    #[test]
    fn parent_components_are_resolved_after_following_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let alias = temp.path().join("kernel");
        std::os::unix::fs::symlink("/proc/sys/kernel", &alias).unwrap();
        assert_same_mount(
            &LinuxPal::new(),
            Path::new("/proc/sys"),
            &alias.join(".."),
        );
    }

    #[test]
    fn retargeted_aliases_do_not_inherit_old_mount_classification() {
        let temp = tempfile::tempdir().unwrap();
        let alias = temp.path().join("current");
        let retired = temp.path().join("retired-link");
        let platform = LinuxPal::new();
        std::os::unix::fs::symlink("/proc", &alias).unwrap();
        assert_same_mount(&platform, Path::new("/proc"), &alias);
        std::fs::rename(&alias, &retired).unwrap();
        std::os::unix::fs::symlink("/dev", &alias).unwrap();
        assert_same_mount(&platform, Path::new("/dev"), &alias);
        assert_eq!(std::fs::read_link(retired).unwrap(), Path::new("/proc"));
    }

    #[test]
    fn byte_named_aliases_preserve_the_targets_native_scope() {
        use std::os::unix::ffi::OsStringExt;

        let temp = tempfile::tempdir().unwrap();
        let alias = temp
            .path()
            .join(std::ffi::OsString::from_vec(b"alias-\xff\n with space".to_vec()));
        std::os::unix::fs::symlink("/proc", &alias).unwrap();
        assert_same_mount(&LinuxPal::new(), Path::new("/proc"), &alias);
    }

    #[test]
    fn missing_cyclic_and_unmapped_paths_are_unknown_not_disk_backed() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing");
        let dangling = temp.path().join("dangling");
        let cycle = temp.path().join("cycle");
        std::os::unix::fs::symlink(&missing, &dangling).unwrap();
        std::os::unix::fs::symlink(&cycle, &cycle).unwrap();
        let platform = LinuxPal::new();
        for path in [&missing, &dangling, &cycle] {
            assert!(platform.fs_stats(path).is_err());
            assert!(platform.is_ram_backed(path).is_err());
            assert!(platform.block_device_for(path).is_err());
        }
        // An existing path outside the available mount snapshot is also unknown.
        let unmapped = LinuxPal {
            mounts_cache: RwLock::new(Some((Vec::new(), Instant::now()))),
            cache_ttl: Duration::from_secs(3600),
        };
        assert!(unmapped.fs_stats(temp.path()).is_err());
        assert!(unmapped.is_ram_backed(temp.path()).is_err());
        assert!(unmapped.block_device_for(temp.path()).is_err());
        assert!(!missing.exists());
    }

    #[test]
    fn ram_backed_alias_uses_the_real_memory_filesystem() {
        let target = Path::new("/dev/shm");
        let platform = LinuxPal::new();
        if !std::fs::metadata(target).is_ok_and(|meta| meta.is_dir())
            || !platform.is_ram_backed(target).unwrap()
        {
            eprintln!("SKIP: this namespace has no RAM-backed /dev/shm fixture");
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let alias = temp.path().join("memory-pool");
        std::os::unix::fs::symlink(target, &alias).unwrap();
        assert_same_mount(&platform, target, &alias);
        assert!(platform.is_ram_backed(&alias).unwrap());
    }
}
