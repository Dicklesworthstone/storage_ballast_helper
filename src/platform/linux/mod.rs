//! Linux PAL implementation.

#![allow(missing_docs)]

pub mod cleanup_catalog;

#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
#[cfg(target_os = "linux")]
use std::path::Path;
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

#[cfg(target_os = "linux")]
impl Platform for LinuxPal {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn fs_stats(&self, path: &Path) -> Result<FsStats> {
        let mounts = self.mount_points()?;
        let mount = disk::find_mount(path, &mounts).ok_or_else(|| SbhError::FsStats {
            path: path.to_path_buf(),
            details: "could not map path to mount point".to_string(),
        })?;
        let stat = nix::sys::statvfs::statvfs(path).map_err(|error| SbhError::FsStats {
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
        let mounts = self.mount_points()?;
        let Some(mount) = disk::find_mount(path, &mounts) else {
            return Ok(false);
        };
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
        let mounts = self.mount_points()?;
        writeback::block_device_for(path, &mounts)
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
}
