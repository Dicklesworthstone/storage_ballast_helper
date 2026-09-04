//! macOS PAL implementation.

#![cfg(target_os = "macos")]
#![allow(missing_docs)]

use std::fs::{self, File};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use crate::core::errors::Result;
use crate::platform::macos::libproc::{
    ProcFdInfo, ProcFdType, ProcRegionWithPathInfo, ProcTaskAllInfo, VnodeFdInfoWithPath,
    proc_listpids_safe, proc_pid_command_line, proc_pid_list_fds, proc_pid_region_path,
    proc_pid_rusage_v4_safe, proc_pidfdinfo_vnode_path, proc_pidinfo_task_all, proc_pidpath_safe,
};
use crate::platform::macos::sacred_catalog::platform_macos_sacred_paths;
use crate::platform::macos::sys::{
    self, ApfsInventory, ApfsVolume, ApfsVolumeRole, StatfsSnapshot, SwapUsage, VmStats,
};
use crate::platform::pal::{
    FsStats, MemoryInfo, MountPoint, Platform, PlatformPaths, ServiceManager,
    verify_preallocated_blocks,
};
use crate::platform::types::{
    Capacity, ExecutablesResult, FullDiskAccessState, FullDiskAccessStatus, LocalSnapshotInfo,
    MappedRegion, MemoryPressure, MemoryPressureCallback, MemoryPressureLevel, MountInfo,
    OPEN_FILES_MAX_PIDS, OPEN_FILES_SCAN_BUDGET, OpenFile, OpenFileKind, OpenFileMode,
    OpenFilesResult, PalError, ProcessInfo, ProcessIo, SacredPath, SelfStats, ServiceKind,
    SnapshotThinningEstimate, SubscriptionHandle,
};
use parking_lot::RwLock;

const FDA_CACHE_TTL_SECS: u64 = 60;
const FDA_CACHE_TTL: Duration = Duration::from_secs(FDA_CACHE_TTL_SECS);
const OPEN_FILES_CACHE_TTL_SECS: u64 = 30;
const OPEN_FILES_CACHE_TTL: Duration = Duration::from_secs(OPEN_FILES_CACHE_TTL_SECS);
const OPEN_FILES_CACHE_MAX_ENTRIES: usize = 64;
const MMAP_REGIONS_SCAN_TIMEOUT: Duration = Duration::from_secs(12);
const MEMORY_PRESSURE_POLL_INTERVAL: Duration = Duration::from_secs(5);
static FDA_STATUS_CACHE: OnceLock<RwLock<Option<(Instant, FullDiskAccessStatus)>>> =
    OnceLock::new();
static OPEN_FILES_UNDER_CACHE: OnceLock<RwLock<Vec<CachedOpenFilesUnder>>> = OnceLock::new();

#[derive(Debug, Clone)]
struct CachedOpenFilesUnder {
    root: PathBuf,
    collected_at: Instant,
    open_files: Vec<OpenFile>,
    complete: bool,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct MacOsPal;

impl MacOsPal {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Platform for MacOsPal {
    fn name(&self) -> &'static str {
        "macos"
    }

    fn fs_stats(&self, path: &Path) -> Result<FsStats> {
        let stats = sys::statfs(path).map_err(|error| macos_method_error("fs_stats", &error))?;
        let inventory = sys::apfs_inventory().ok();
        Ok(capacity_to_fs_stats(statfs_to_capacity(
            stats,
            inventory.as_ref(),
        )))
    }

    fn mount_points(&self) -> Result<Vec<MountPoint>> {
        sys::mounted_filesystems()
            .map(|mounts| mounts.into_iter().map(statfs_to_mount_point).collect())
            .map_err(|error| macos_method_error("mount_points", &error))
    }

    fn is_ram_backed(&self, path: &Path) -> Result<bool> {
        sys::statfs(path)
            .map(|stats| stats.is_ram_backed())
            .map_err(|error| macos_method_error("is_ram_backed", &error))
    }

    fn default_paths(&self) -> PlatformPaths {
        PlatformPaths::default()
    }

    fn memory_info(&self) -> Result<MemoryInfo> {
        let total_bytes = macos_total_memory_bytes("memory_info")?;
        let stats =
            sys::read_vm_stats().map_err(|error| macos_method_error("memory_info", &error))?;
        let swap =
            sys::vm_swapusage().map_err(|error| macos_method_error("memory_info", &error))?;
        Ok(memory_info_from_vm_stats(total_bytes, stats, &swap))
    }

    fn service_manager(&self) -> Box<dyn ServiceManager> {
        crate::daemon::service::service_manager_for_default_control_kind(ServiceKind::Launchd)
    }

    fn capacity(&self, mount: &Path) -> Result<Capacity> {
        let stats = sys::statfs(mount).map_err(|error| macos_method_error("capacity", &error))?;
        let inventory = sys::apfs_inventory().ok();
        let local_snapshot_bytes = local_snapshot_bytes_for_capacity(&stats, inventory.as_ref());
        let mut capacity = statfs_to_capacity(stats, inventory.as_ref());
        let thinning_estimate = estimate_reclaimable_by_snapshot_thinning(
            &capacity.mount_point,
            capacity.available_bytes,
            inventory.as_ref(),
            capacity.container_id.as_deref(),
        );
        capacity.purgeable_bytes = thinning_estimate.as_ref().map(|est| est.bytes);
        capacity.estimated_reclaimable_by_snapshot_thinning = thinning_estimate;
        capacity.local_snapshot_bytes = local_snapshot_bytes;
        Ok(capacity)
    }

    fn mounts(&self) -> Result<Vec<MountInfo>> {
        let inventory = sys::apfs_inventory().ok();
        sys::mounted_filesystems()
            .map(|mounts| {
                mounts
                    .into_iter()
                    .map(|stats| {
                        let local_snapshot_bytes =
                            local_snapshot_bytes_for_capacity(&stats, inventory.as_ref());
                        statfs_to_mount_info(stats, inventory.as_ref(), local_snapshot_bytes)
                    })
                    .collect()
            })
            .map_err(|error| macos_method_error("mounts", &error))
    }

    fn local_time_machine_snapshots(&self, mount: &Path) -> Result<Vec<LocalSnapshotInfo>> {
        let stats = sys::statfs(mount)
            .map_err(|error| macos_method_error("local_time_machine_snapshots", &error))?;
        let inventory = sys::apfs_inventory().ok();
        let volume = inventory
            .as_ref()
            .and_then(|inventory| inventory.volume_for_device(&stats.device));
        sys::local_time_machine_snapshots(&stats.mount_point, inventory.as_ref(), volume)
            .map(|snapshots| {
                snapshots
                    .into_iter()
                    .map(local_snapshot_info_from_sys)
                    .collect()
            })
            .map_err(|error| macos_method_error("local_time_machine_snapshots", &error))
    }

    fn memory_pressure(&self) -> Result<MemoryPressure> {
        read_current_memory_pressure("memory_pressure")
    }

    fn full_disk_access_status(&self) -> Result<FullDiskAccessStatus> {
        Ok(cached_full_disk_access_status(&self.user_home()))
    }

    fn subscribe_memory_pressure(
        &self,
        callback: MemoryPressureCallback,
    ) -> Result<SubscriptionHandle> {
        let callback: Arc<dyn Fn(MemoryPressure) + Send + Sync + 'static> = Arc::from(callback);
        spawn_native_memory_pressure_subscription(Arc::clone(&callback)).or_else(|_| {
            let callback = Arc::clone(&callback);
            spawn_memory_pressure_subscription(
                "macos-memory-pressure-poll",
                MEMORY_PRESSURE_POLL_INTERVAL,
                Box::new(move |pressure| callback(pressure)),
                || read_current_memory_pressure("subscribe_memory_pressure"),
            )
        })
    }

    fn process_list(&self) -> Result<Vec<ProcessInfo>> {
        let current_pid = current_process_pid();
        let processes = proc_listpids_safe()
            .map_err(|error| macos_method_error("process_list", &error))?
            .into_iter()
            .filter(|pid| *pid > 0 && *pid != current_pid)
            .filter_map(process_info_for_pid_without_command_line)
            .collect();
        Ok(processes)
    }

    fn process_io(&self, pid: i32) -> Result<ProcessIo> {
        let usage = proc_pid_rusage_v4_safe(pid)
            .map_err(|error| macos_method_error("process_io", &error))?;
        Ok(ProcessIo {
            pid,
            bytes_read_total: usage.ri_diskio_bytesread,
            bytes_written_total: usage.ri_diskio_byteswritten,
            bytes_read_recent_15m: None,
            bytes_written_recent_15m: None,
        })
    }

    fn open_files_under(&self, path: &Path) -> Result<OpenFilesResult> {
        let root = process_observed_path(path);
        cached_open_files_under(&root)
    }

    fn executables_under(&self, path: &Path) -> Result<ExecutablesResult> {
        let root = process_observed_path(path);
        let root_variants = macos_process_path_variants(&root);
        let mut processes: Vec<ProcessInfo> = Vec::new();
        let deadline = Instant::now() + OPEN_FILES_SCAN_BUDGET;
        let mut pids_scanned: usize = 0;
        let mut incomplete = false;

        for pid in process_pids_current_first()
            .map_err(|error| macos_method_error("executables_under", &error))?
        {
            if pids_scanned >= OPEN_FILES_MAX_PIDS || Instant::now() >= deadline {
                incomplete = true;
                break;
            }
            pids_scanned += 1;
            if let Some(process) = process_info_for_pid_without_command_line(pid) {
                if executable_is_under(&process, &root_variants) {
                    processes.push(process);
                }
            }
        }
        processes.sort_by(|left, right| {
            left.pid
                .cmp(&right.pid)
                .then_with(|| left.name.cmp(&right.name))
        });
        Ok(ExecutablesResult {
            processes,
            complete: !incomplete,
        })
    }

    fn mmap_regions_under(&self, path: &Path) -> Result<Vec<MappedRegion>> {
        let root = process_observed_path(path);
        let root_variants = macos_process_path_variants(&root);
        let deadline = Instant::now() + MMAP_REGIONS_SCAN_TIMEOUT;
        let mut regions = Vec::new();
        for pid in process_pids_current_first()
            .map_err(|error| macos_method_error("mmap_regions_under", &error))?
        {
            if Instant::now() >= deadline {
                return Err(macos_scan_timeout(
                    "mmap_regions_under",
                    MMAP_REGIONS_SCAN_TIMEOUT,
                ));
            }
            regions.extend(mapped_regions_for_pid_under(pid, &root_variants, deadline)?);
        }
        regions.sort_by(|left, right| {
            left.pid
                .cmp(&right.pid)
                .then_with(|| left.start_address.cmp(&right.start_address))
                .then_with(|| left.path.cmp(&right.path))
        });
        Ok(regions)
    }

    fn self_stats(&self) -> Result<SelfStats> {
        let usage = sys::current_mach_task_usage()
            .map_err(|error| macos_method_error("self_stats", &error))?;
        let rusage = proc_pid_rusage_v4_safe(current_process_pid())
            .map_err(|error| macos_method_error("self_stats", &error))?;

        Ok(SelfStats {
            rss_bytes: usage.rss_bytes,
            virtual_memory_bytes: usage.virtual_memory_bytes,
            cpu_user_micros: usage.cpu_user_micros,
            cpu_system_micros: usage.cpu_system_micros,
            idle_wakeups: Some(
                rusage
                    .ri_pkg_idle_wkups
                    .saturating_add(rusage.ri_interrupt_wkups),
            ),
            bytes_read: Some(rusage.ri_diskio_bytesread),
            bytes_written: Some(rusage.ri_diskio_byteswritten),
        })
    }

    fn preallocate_file(&self, path: &Path, size: u64) -> Result<()> {
        use rustix::fs::{FallocateFlags, fallocate};
        use std::os::unix::fs::OpenOptionsExt as _;

        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| crate::core::errors::SbhError::io(path, error))?;

        fallocate(&file, FallocateFlags::empty(), 0, size).map_err(|error| {
            PalError::method_failed("macos", "preallocate_file", error.to_string())
        })?;
        file.sync_all()
            .map_err(|error| crate::core::errors::SbhError::io(path, error))?;

        let blocks = self.file_block_count(path)?;
        verify_preallocated_blocks("macos", path, size, blocks)
    }

    fn user_home(&self) -> PathBuf {
        std::env::var_os("HOME").map_or_else(|| PathBuf::from("/"), PathBuf::from)
    }

    fn temp_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = vec![std::env::temp_dir(), PathBuf::from("/private/tmp")];
        dirs.sort();
        dirs.dedup();
        dirs
    }

    fn cache_roots(&self) -> Vec<PathBuf> {
        std::env::var_os("HOME").map_or_else(Vec::new, |home| {
            vec![PathBuf::from(home).join("Library/Caches")]
        })
    }

    fn sacred_paths(&self) -> Vec<SacredPath> {
        platform_macos_sacred_paths()
    }

    fn service_kind(&self) -> ServiceKind {
        ServiceKind::Launchd
    }
}

fn cached_open_files_under(root: &Path) -> Result<OpenFilesResult> {
    let now = Instant::now();
    let cache = OPEN_FILES_UNDER_CACHE.get_or_init(|| RwLock::new(Vec::new()));
    {
        let cached = cache.read();
        if let Some(entry) = cached.iter().find(|entry| entry.root == root)
            && now.duration_since(entry.collected_at) <= OPEN_FILES_CACHE_TTL
        {
            return Ok(OpenFilesResult {
                files: entry.open_files.clone(),
                complete: entry.complete,
            });
        }
    }

    let result = collect_open_files_under(root)?;
    {
        let mut cache = cache.write();
        cache.retain(|entry| now.duration_since(entry.collected_at) <= OPEN_FILES_CACHE_TTL);
        if let Some(entry) = cache.iter_mut().find(|entry| entry.root == root) {
            entry.collected_at = now;
            entry.open_files.clone_from(&result.files);
            entry.complete = result.complete;
        } else {
            if cache.len() >= OPEN_FILES_CACHE_MAX_ENTRIES {
                cache.remove(0);
            }
            cache.push(CachedOpenFilesUnder {
                root: root.to_path_buf(),
                collected_at: now,
                open_files: result.files.clone(),
                complete: result.complete,
            });
        }
    }
    Ok(result)
}

fn collect_open_files_under(root: &Path) -> Result<OpenFilesResult> {
    let pids =
        proc_listpids_safe().map_err(|error| macos_method_error("open_files_under", &error))?;
    let mut open_files: Vec<OpenFile> = Vec::new();
    let deadline = Instant::now() + OPEN_FILES_SCAN_BUDGET;
    let mut pids_scanned: usize = 0;
    let mut incomplete = false;

    for pid in pids {
        if pids_scanned >= OPEN_FILES_MAX_PIDS || Instant::now() >= deadline {
            incomplete = true;
            break;
        }
        if pid > 0 {
            pids_scanned += 1;
            open_files.extend(open_files_for_pid_under(pid, root));
        }
    }
    open_files.sort_by(|left, right| {
        left.pid
            .cmp(&right.pid)
            .then_with(|| left.fd.cmp(&right.fd))
            .then_with(|| left.path.cmp(&right.path))
    });
    Ok(OpenFilesResult {
        files: open_files,
        complete: !incomplete,
    })
}

fn macos_method_error(
    method: &'static str,
    error: &impl ToString,
) -> crate::core::errors::SbhError {
    PalError::method_failed("macos", method, error.to_string()).into()
}

fn macos_scan_timeout(method: &'static str, timeout: Duration) -> crate::core::errors::SbhError {
    macos_method_error(
        method,
        &format!("{method} exceeded {timeout:?} scan budget"),
    )
}

fn macos_total_memory_bytes(method: &'static str) -> Result<u64> {
    sys::sysctl::read::<u64>("hw.memsize").map_err(|error| macos_method_error(method, &error))
}

fn memory_info_from_vm_stats(total_bytes: u64, stats: VmStats, swap: &SwapUsage) -> MemoryInfo {
    let available_pages = stats
        .free_count
        .saturating_add(stats.inactive_count)
        .min(total_pages(total_bytes, stats.page_size_bytes));
    let (swap_total_bytes, swap_free_bytes) = match swap {
        SwapUsage::Known(usage) => (usage.total_bytes, usage.free_bytes),
        SwapUsage::Unknown => (0, 0),
    };

    MemoryInfo {
        total_bytes,
        available_bytes: available_pages.saturating_mul(stats.page_size_bytes),
        swap_total_bytes,
        swap_free_bytes,
    }
}

fn memory_pressure_from_vm_stats(
    total_bytes: u64,
    stats: VmStats,
    swap: &SwapUsage,
) -> MemoryPressure {
    let total_pages = total_pages(total_bytes, stats.page_size_bytes);
    let used_pages = total_pages.checked_sub(stats.free_count);
    let compressor_used_bytes = Some(
        stats
            .compressor_page_count
            .saturating_mul(stats.page_size_bytes),
    );
    let (swap_total_bytes, swap_used_bytes) = match swap {
        SwapUsage::Known(usage) => (
            Some(usage.total_bytes),
            Some(usage.total_bytes.saturating_sub(usage.free_bytes)),
        ),
        SwapUsage::Unknown => (None, None),
    };

    MemoryPressure {
        level: infer_macos_memory_pressure_level(total_pages, stats, swap_used_bytes),
        free_pages: Some(stats.free_count),
        used_pages,
        page_size_bytes: Some(stats.page_size_bytes),
        compressor_used_bytes,
        swap_total_bytes,
        swap_used_bytes,
        linux_psi_avg10: None,
    }
}

fn read_current_memory_pressure(method: &'static str) -> Result<MemoryPressure> {
    let total_bytes = macos_total_memory_bytes(method)?;
    let stats = sys::read_vm_stats().map_err(|error| macos_method_error(method, &error))?;
    let swap = sys::vm_swapusage().map_err(|error| macos_method_error(method, &error))?;
    Ok(memory_pressure_from_vm_stats(total_bytes, stats, &swap))
}

fn spawn_native_memory_pressure_subscription(
    callback: Arc<dyn Fn(MemoryPressure) + Send + Sync + 'static>,
) -> Result<SubscriptionHandle> {
    let source = sbh_mach::subscribe_memory_pressure_events(move |event| {
        callback(memory_pressure_from_dispatch_event(event));
    })
    .map_err(|error| macos_method_error("subscribe_memory_pressure", &error))?;

    Ok(SubscriptionHandle::active_with_resource(
        "macos-memory-pressure-dispatch",
        source,
    ))
}

fn memory_pressure_from_dispatch_event(event: sbh_mach::MemoryPressureEvent) -> MemoryPressure {
    let dispatch_level = memory_pressure_level_from_dispatch_event(event);
    let mut pressure = read_current_memory_pressure("subscribe_memory_pressure.dispatch")
        .unwrap_or_else(|_| empty_dispatch_memory_pressure(dispatch_level));
    if dispatch_level != MemoryPressureLevel::Unknown {
        pressure.level = dispatch_level;
    }
    pressure
}

fn memory_pressure_level_from_dispatch_event(
    event: sbh_mach::MemoryPressureEvent,
) -> MemoryPressureLevel {
    match event {
        sbh_mach::MemoryPressureEvent::Normal => MemoryPressureLevel::Normal,
        sbh_mach::MemoryPressureEvent::Warn => MemoryPressureLevel::Warn,
        sbh_mach::MemoryPressureEvent::Critical => MemoryPressureLevel::Critical,
        sbh_mach::MemoryPressureEvent::Unknown(_) => MemoryPressureLevel::Unknown,
    }
}

fn empty_dispatch_memory_pressure(level: MemoryPressureLevel) -> MemoryPressure {
    MemoryPressure {
        level,
        free_pages: None,
        used_pages: None,
        page_size_bytes: None,
        compressor_used_bytes: None,
        swap_total_bytes: None,
        swap_used_bytes: None,
        linux_psi_avg10: None,
    }
}

fn spawn_memory_pressure_subscription<F>(
    source: &'static str,
    interval: Duration,
    callback: MemoryPressureCallback,
    sampler: F,
) -> Result<SubscriptionHandle>
where
    F: Fn() -> Result<MemoryPressure> + Send + 'static,
{
    let initial = sampler()?;
    let liveness = Arc::new(());
    let weak_liveness = Arc::downgrade(&liveness);
    let thread_name = format!("sbh-{source}");
    let thread = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || {
            let mut last_level = initial.level;
            loop {
                std::thread::sleep(interval);
                if weak_liveness.upgrade().is_none() {
                    break;
                }
                let Ok(pressure) = sampler() else {
                    continue;
                };
                if pressure.level != last_level {
                    last_level = pressure.level;
                    callback(pressure);
                }
            }
        })
        .map_err(|error| macos_method_error("subscribe_memory_pressure", &error))?;
    drop(thread);

    Ok(SubscriptionHandle::active_with_liveness(source, liveness))
}

fn total_pages(total_bytes: u64, page_size_bytes: u64) -> u64 {
    total_bytes.checked_div(page_size_bytes).unwrap_or(0)
}

fn infer_macos_memory_pressure_level(
    total_pages: u64,
    stats: VmStats,
    swap_used_bytes: Option<u64>,
) -> MemoryPressureLevel {
    if total_pages == 0 {
        return MemoryPressureLevel::Unknown;
    }

    let free_pct = pages_pct(stats.free_count, total_pages);
    let compressor_pct = pages_pct(stats.compressor_page_count, total_pages);
    let swap_is_active = swap_used_bytes.is_some_and(|bytes| bytes > 0);

    // Apple exposes dispatch memory-pressure levels but not the exact numeric
    // thresholds. Until bd-hqu2.5 wires event notifications, keep the mapping
    // conservative: warn only when free pages are scarce and the compressor is
    // doing meaningful work; critical requires near-exhausted free pages plus
    // evidence that memory pressure has spilled into swap.
    if free_pct < 2.0 && swap_is_active {
        MemoryPressureLevel::Critical
    } else if free_pct < 5.0 && (compressor_pct >= 10.0 || swap_is_active) {
        MemoryPressureLevel::Warn
    } else {
        MemoryPressureLevel::Normal
    }
}

fn pages_pct(pages: u64, total_pages: u64) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    {
        (pages as f64 * 100.0) / total_pages as f64
    }
}

fn cached_full_disk_access_status(home: &Path) -> FullDiskAccessStatus {
    let cache = FDA_STATUS_CACHE.get_or_init(|| RwLock::new(None));
    {
        let cached = cache.read();
        if let Some((checked_at, status)) = &*cached
            && checked_at.elapsed() < FDA_CACHE_TTL
        {
            let mut status = status.clone();
            status.cached = true;
            return status;
        }
    }

    let status = probe_full_disk_access_status(home);
    *cache.write() = Some((Instant::now(), status.clone()));
    status
}

fn probe_full_disk_access_status(home: &Path) -> FullDiskAccessStatus {
    let mail_root = home.join("Library/Mail");
    let entries = match fs::read_dir(&mail_root) {
        Ok(entries) => entries,
        Err(error) if is_fda_permission_denied(&error) => {
            return fda_status(
                FullDiskAccessState::Missing,
                Some(mail_root),
                "permission denied while listing Mail data; grant Full Disk Access to sbh",
            );
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return fda_status(
                FullDiskAccessState::NotConfigured,
                Some(mail_root),
                "Mail data directory is not present for this user",
            );
        }
        Err(error) => {
            return fda_status(
                FullDiskAccessState::Unknown,
                Some(mail_root),
                format!("could not inspect Mail data directory: {error}"),
            );
        }
    };

    let mut version_dirs = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if is_fda_permission_denied(&error) => {
                return fda_status(
                    FullDiskAccessState::Missing,
                    Some(mail_root),
                    "permission denied while reading Mail data; grant Full Disk Access to sbh",
                );
            }
            Err(error) => {
                return fda_status(
                    FullDiskAccessState::Unknown,
                    Some(mail_root),
                    format!("could not read Mail data entry: {error}"),
                );
            }
        };
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('V') {
            version_dirs.push(entry.path());
        }
    }
    version_dirs.sort();

    let mut last_probe = None;
    for version_dir in version_dirs {
        let probe = version_dir.join("MailData").join("Envelope Index");
        last_probe = Some(probe.clone());
        match File::open(&probe) {
            Ok(_) => {
                return fda_status(
                    FullDiskAccessState::Granted,
                    Some(probe),
                    "Mail Envelope Index was readable",
                );
            }
            Err(error) if is_fda_permission_denied(&error) => {
                return fda_status(
                    FullDiskAccessState::Missing,
                    Some(probe),
                    "permission denied while reading Mail Envelope Index; grant Full Disk Access to sbh",
                );
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return fda_status(
                    FullDiskAccessState::Unknown,
                    Some(probe),
                    format!("could not read Mail Envelope Index: {error}"),
                );
            }
        }
    }

    fda_status(
        FullDiskAccessState::NotConfigured,
        Some(last_probe.unwrap_or(mail_root)),
        "no MailData/Envelope Index probe file was found under ~/Library/Mail/V*",
    )
}

fn fda_status(
    state: FullDiskAccessState,
    probe_path: Option<PathBuf>,
    detail: impl Into<String>,
) -> FullDiskAccessStatus {
    FullDiskAccessStatus {
        state,
        probe_path,
        detail: detail.into(),
        cache_ttl_seconds: FDA_CACHE_TTL_SECS,
        cached: false,
    }
}

fn is_fda_permission_denied(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::EPERM) || error.kind() == io::ErrorKind::PermissionDenied
}

fn capacity_to_fs_stats(capacity: Capacity) -> FsStats {
    FsStats {
        total_bytes: capacity.total_bytes,
        free_bytes: capacity.free_bytes,
        available_bytes: capacity.available_bytes,
        fs_type: capacity.fs_type,
        mount_point: capacity.mount_point,
        is_readonly: capacity.is_readonly,
    }
}

fn statfs_to_mount_point(stats: StatfsSnapshot) -> MountPoint {
    let is_ram_backed = stats.is_ram_backed();
    MountPoint {
        path: stats.mount_point,
        device: stats.device,
        fs_type: stats.fs_type,
        is_ram_backed,
    }
}

fn statfs_to_capacity(stats: StatfsSnapshot, inventory: Option<&ApfsInventory>) -> Capacity {
    let volume_total_bytes = stats.total_bytes();
    let volume_free_bytes = stats.free_bytes();
    let volume_available_bytes = stats.available_bytes();
    let volume = inventory.and_then(|inventory| inventory.volume_for_device(&stats.device));
    let container_total_bytes = volume.and_then(|volume| volume.container_total_bytes);
    let container_available_bytes = volume.and_then(|volume| volume.container_available_bytes);
    let effective_total_bytes = container_total_bytes.unwrap_or(volume_total_bytes);
    let effective_available_bytes = container_available_bytes.unwrap_or(volume_available_bytes);
    let is_primary = volume.is_some_and(|volume| volume.has_role(&ApfsVolumeRole::Data))
        || (stats.fs_type.eq_ignore_ascii_case("apfs")
            && stats.mount_point == Path::new("/System/Volumes/Data"));
    Capacity {
        mount_point: stats.mount_point,
        fs_type: stats.fs_type,
        total_bytes: effective_total_bytes,
        free_bytes: container_available_bytes.unwrap_or(volume_free_bytes),
        available_bytes: effective_available_bytes,
        is_readonly: stats.is_readonly,
        container_id: volume.map(|volume| volume.container_id.clone()),
        container_total_bytes,
        container_available_bytes,
        volume_total_bytes: Some(volume_total_bytes),
        volume_available_bytes: Some(volume_available_bytes),
        volume_role: volume.and_then(ApfsVolume::role_label),
        shared_volumes: inventory
            .zip(volume)
            .map_or_else(Vec::new, |(inventory, volume)| {
                inventory.sibling_volume_names(volume)
            }),
        is_primary,
        purgeable_bytes: None,
        local_snapshot_bytes: None,
        estimated_reclaimable_by_snapshot_thinning: None,
    }
}

fn local_snapshot_bytes_for_capacity(
    stats: &StatfsSnapshot,
    inventory: Option<&ApfsInventory>,
) -> Option<u64> {
    let inventory = inventory?;
    let volume = inventory.volume_for_device(&stats.device)?;
    let is_data_volume = volume.has_role(&ApfsVolumeRole::Data)
        || (stats.fs_type.eq_ignore_ascii_case("apfs")
            && stats.mount_point == Path::new("/System/Volumes/Data"));
    if !is_data_volume {
        return None;
    }

    inventory
        .unattributed_container_used_bytes(&volume.container_id)
        .filter(|bytes| *bytes > 0)
}

fn local_snapshot_info_from_sys(snapshot: sys::LocalSnapshotInfo) -> LocalSnapshotInfo {
    LocalSnapshotInfo {
        name: snapshot.name,
        date: snapshot.date,
        retained_bytes_estimate: snapshot.retained_bytes_estimate,
        mount_path: snapshot.mount_path,
    }
}

fn statfs_to_mount_info(
    stats: StatfsSnapshot,
    inventory: Option<&ApfsInventory>,
    local_snapshot_bytes: Option<u64>,
) -> MountInfo {
    let is_apfs = stats.fs_type.eq_ignore_ascii_case("apfs");
    let total_bytes = stats.total_bytes();
    let available_bytes = stats.available_bytes();
    let is_ram_backed = stats.is_ram_backed();
    let volume = inventory.and_then(|inventory| inventory.volume_for_device(&stats.device));
    let is_apfs_data_volume = volume.is_some_and(|volume| volume.has_role(&ApfsVolumeRole::Data))
        || (is_apfs && stats.mount_point == Path::new("/System/Volumes/Data"));
    let is_apfs_system_snapshot = volume
        .is_some_and(|volume| volume.has_role(&ApfsVolumeRole::System))
        || (is_apfs && stats.mount_point == Path::new("/") && stats.is_readonly);
    let is_apfs_vm_volume = volume.is_some_and(|volume| volume.has_role(&ApfsVolumeRole::Vm))
        || (is_apfs && stats.mount_point == Path::new("/System/Volumes/VM"));
    let effective_available_bytes = volume
        .and_then(|volume| volume.container_available_bytes)
        .unwrap_or(available_bytes);
    let thinning_estimate = estimate_reclaimable_by_snapshot_thinning(
        &stats.mount_point,
        effective_available_bytes,
        inventory,
        volume.map(|volume| volume.container_id.as_str()),
    );
    let purgeable_bytes = thinning_estimate.as_ref().map(|est| est.bytes);
    let mount_point = stats.mount_point;
    MountInfo {
        device: stats.device,
        mount_point,
        fs_type: stats.fs_type,
        container_id: volume.map(|volume| volume.container_id.clone()),
        total_bytes: volume
            .and_then(|volume| volume.container_total_bytes)
            .or(Some(total_bytes)),
        available_bytes: Some(effective_available_bytes),
        purgeable_bytes,
        local_snapshot_bytes,
        estimated_reclaimable_by_snapshot_thinning: thinning_estimate,
        is_readonly: stats.is_readonly,
        is_ram_backed,
        is_apfs_data_volume,
        is_apfs_system_snapshot,
        is_apfs_vm_volume,
    }
}

fn estimate_reclaimable_by_snapshot_thinning(
    mount_point: &Path,
    counted_available_bytes: u64,
    inventory: Option<&ApfsInventory>,
    container_id: Option<&str>,
) -> Option<SnapshotThinningEstimate> {
    let query_foundation = std::env::var("SBH_MACOS_QUERY_FOUNDATION_PURGEABLE")
        .ok()
        .map_or(true, |val| {
            !matches!(
                val.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            )
        });

    if query_foundation {
        if let Ok(Some(important_available)) = sys::important_usage_available_bytes(mount_point) {
            if let Some(bytes) = purgeable_bytes_from_important_available(
                important_available,
                counted_available_bytes,
            ) {
                return Some(SnapshotThinningEstimate::new(bytes, "foundation"));
            }
        }
    }

    purgeable_bytes_from_apfs_inventory(inventory, container_id)
        .map(|bytes| SnapshotThinningEstimate::new(bytes, "apfs_unattributed"))
}

fn purgeable_bytes_from_important_available(
    important_available_bytes: u64,
    counted_available_bytes: u64,
) -> Option<u64> {
    important_available_bytes
        .checked_sub(counted_available_bytes)
        .filter(|bytes| *bytes > 0)
}

fn purgeable_bytes_from_apfs_inventory(
    inventory: Option<&ApfsInventory>,
    container_id: Option<&str>,
) -> Option<u64> {
    let container_id = container_id?;
    inventory?
        .unattributed_container_used_bytes(container_id)
        .filter(|bytes| *bytes > 0)
}

fn current_process_pid() -> i32 {
    i32::try_from(std::process::id()).expect("current process id should fit in i32")
}

#[cfg(test)]
fn process_info_for_pid(pid: i32) -> Option<ProcessInfo> {
    let raw = proc_pidinfo_task_all(pid).ok()?;
    Some(process_info_from_task_all(pid, raw, true))
}

fn process_info_for_pid_without_command_line(pid: i32) -> Option<ProcessInfo> {
    let raw = proc_pidinfo_task_all(pid).ok()?;
    Some(process_info_from_task_all(pid, raw, false))
}

fn process_info_from_task_all(
    pid: i32,
    raw: ProcTaskAllInfo,
    include_command_line: bool,
) -> ProcessInfo {
    let name = process_name(&raw);
    let executable = proc_pidpath_safe(pid).ok();
    let command_line = if include_command_line {
        proc_pid_command_line(pid).unwrap_or_default()
    } else {
        Vec::new()
    };
    ProcessInfo {
        pid,
        parent_pid: positive_pid(raw.pbsd.pbi_ppid.0),
        name,
        command_line,
        executable,
        cwd: None,
        start_time_unix_ms: start_time_unix_ms(raw.pbsd.pbi_start_tvsec, raw.pbsd.pbi_start_tvusec),
        virtual_memory_bytes: Some(raw.ptinfo.pti_virtual_size),
        resident_memory_bytes: Some(raw.ptinfo.pti_resident_size),
        cpu_user_micros: Some(nanos_to_micros(raw.ptinfo.pti_total_user)),
        cpu_system_micros: Some(nanos_to_micros(raw.ptinfo.pti_total_system)),
    }
}

fn process_name(raw: &ProcTaskAllInfo) -> String {
    let name = c_char_array_to_string(&raw.pbsd.pbi_name);
    if name.is_empty() {
        c_char_array_to_string(&raw.pbsd.pbi_comm)
    } else {
        name
    }
}

fn c_char_array_to_string(raw: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = raw
        .iter()
        .copied()
        .take_while(|c| *c != 0)
        .map(|c| c.to_ne_bytes()[0])
        .collect();
    String::from_utf8_lossy(&bytes).trim().to_string()
}

fn positive_pid(pid: u32) -> Option<i32> {
    if pid == 0 {
        return None;
    }
    i32::try_from(pid).ok()
}

fn start_time_unix_ms(seconds: u64, micros: u64) -> Option<i64> {
    let millis = seconds
        .checked_mul(1000)?
        .checked_add(micros.checked_div(1000)?)?;
    i64::try_from(millis).ok()
}

fn nanos_to_micros(nanos: u64) -> u64 {
    nanos / 1_000
}

fn process_pids_current_first() -> io::Result<Vec<i32>> {
    let current_pid = current_process_pid();
    let mut pids: Vec<i32> = proc_listpids_safe()?
        .into_iter()
        .filter(|pid| *pid > 0)
        .collect();
    pids.sort_by_key(|pid| (*pid != current_pid, *pid));
    pids.dedup();
    Ok(pids)
}

fn executable_is_under(process: &ProcessInfo, root_variants: &[PathBuf]) -> bool {
    process
        .executable
        .as_deref()
        .and_then(|path| observed_process_path_under_root(path, root_variants))
        .is_some()
}

fn open_files_for_pid_under(pid: i32, root: &Path) -> Vec<OpenFile> {
    let Ok(fds) = proc_pid_list_fds(pid) else {
        return Vec::new();
    };
    let root_variants = macos_process_path_variants(root);
    fds.into_iter()
        .filter_map(|fd| open_file_for_fd_under(pid, fd, &root_variants))
        .collect()
}

fn open_file_for_fd_under(pid: i32, fd: ProcFdInfo, root_variants: &[PathBuf]) -> Option<OpenFile> {
    if fd.fd_type().ok()? != ProcFdType::VNODE {
        return None;
    }
    let info = proc_pidfdinfo_vnode_path(pid, fd.proc_fd.0)
        .ok()
        .flatten()?;
    let path = observed_process_path_under_root(info.path().ok()?, root_variants)?;
    Some(OpenFile {
        pid,
        path,
        fd: Some(fd.proc_fd.0),
        kind: open_file_kind(&info),
        mode: open_file_mode(info.pfi.fi_openflags),
    })
}

fn open_file_kind(info: &VnodeFdInfoWithPath) -> OpenFileKind {
    match info.pvip.vip_vi.vi_stat.vst_mode & libc::S_IFMT {
        libc::S_IFREG => OpenFileKind::Regular,
        libc::S_IFDIR => OpenFileKind::Directory,
        libc::S_IFSOCK => OpenFileKind::Socket,
        libc::S_IFIFO => OpenFileKind::Pipe,
        libc::S_IFCHR | libc::S_IFBLK => OpenFileKind::Device,
        _ => OpenFileKind::Unknown,
    }
}

fn open_file_mode(open_flags: u32) -> OpenFileMode {
    const FREAD: u32 = 0x1;
    const FWRITE: u32 = 0x2;
    match (open_flags & FREAD != 0, open_flags & FWRITE != 0) {
        (true, true) => OpenFileMode::ReadWrite,
        (true, false) => OpenFileMode::Read,
        (false, true) => OpenFileMode::Write,
        (false, false) => OpenFileMode::Unknown,
    }
}

fn mapped_regions_for_pid_under(
    pid: i32,
    root_variants: &[PathBuf],
    deadline: Instant,
) -> Result<Vec<MappedRegion>> {
    const MAX_REGIONS_PER_PID: usize = 16_384;

    let mut address = 0;
    let mut regions = Vec::new();
    for _ in 0..MAX_REGIONS_PER_PID {
        if Instant::now() >= deadline {
            return Err(macos_scan_timeout(
                "mmap_regions_under",
                MMAP_REGIONS_SCAN_TIMEOUT,
            ));
        }
        let Ok(info) = proc_pid_region_path(pid, address) else {
            break;
        };
        let start = info.prp_prinfo.pri_address;
        let size = info.prp_prinfo.pri_size;
        if size == 0 {
            break;
        }
        if let Some(region) = mapped_region_under(pid, &info, root_variants) {
            regions.push(region);
        }
        let Some(next_address) = start.checked_add(size) else {
            break;
        };
        if next_address <= address {
            break;
        }
        address = next_address;
    }
    Ok(regions)
}

fn mapped_region_under(
    pid: i32,
    info: &ProcRegionWithPathInfo,
    root_variants: &[PathBuf],
) -> Option<MappedRegion> {
    let path = observed_process_path_under_root(info.prp_vip.path().ok()?, root_variants)?;
    let start = info.prp_prinfo.pri_address;
    let end = start.checked_add(info.prp_prinfo.pri_size);
    Some(MappedRegion {
        pid,
        path,
        start_address: Some(start),
        end_address: end,
        protection: Some(region_protection(info.prp_prinfo.pri_protection)),
    })
}

#[cfg(test)]
fn process_path_is_under_root(path: &Path, root: &Path) -> bool {
    let root_variants = macos_process_path_variants(root);
    observed_process_path_under_root(path, &root_variants).is_some()
}

fn observed_process_path_under_root(path: &Path, root_variants: &[PathBuf]) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    if process_path_matches_root_variants(path, root_variants) {
        return Some(normalize_process_path(path));
    }
    let alias = macos_private_mount_alias(path)?;
    if process_path_matches_root_variants(&alias, root_variants) {
        return Some(normalize_process_path(path));
    }
    None
}

fn process_path_matches_root_variants(path: &Path, root_variants: &[PathBuf]) -> bool {
    root_variants
        .iter()
        .any(|root| path.starts_with(root.as_path()))
}

fn macos_process_path_variants(path: &Path) -> Vec<PathBuf> {
    let normalized = process_observed_path(path);
    let mut variants = vec![normalized.clone()];
    if let Some(alias) = macos_private_mount_alias(&normalized) {
        variants.push(alias);
    }
    variants.sort();
    variants.dedup();
    variants
}

fn macos_private_mount_alias(path: &Path) -> Option<PathBuf> {
    for (visible, private) in [
        (Path::new("/tmp"), Path::new("/private/tmp")),
        (Path::new("/var"), Path::new("/private/var")),
        (Path::new("/etc"), Path::new("/private/etc")),
    ] {
        if let Ok(rest) = path.strip_prefix(visible) {
            return Some(private.join(rest));
        }
        if let Ok(rest) = path.strip_prefix(private) {
            return Some(visible.join(rest));
        }
    }
    None
}

fn process_observed_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(|_| path.to_path_buf(), |cwd| cwd.join(path))
    };
    normalize_process_path(&absolute)
}

fn normalize_process_path(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(..) | Component::RootDir | Component::Normal(_) => {
                components.push(component);
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if let Some(Component::Normal(_)) = components.last() {
                    components.pop();
                }
            }
        }
    }
    components.into_iter().collect()
}

fn region_protection(bits: u32) -> String {
    const VM_PROT_READ: u32 = 0x01;
    const VM_PROT_WRITE: u32 = 0x02;
    const VM_PROT_EXECUTE: u32 = 0x04;
    let read = if bits & VM_PROT_READ != 0 { 'r' } else { '-' };
    let write = if bits & VM_PROT_WRITE != 0 { 'w' } else { '-' };
    let execute = if bits & VM_PROT_EXECUTE != 0 {
        'x'
    } else {
        '-'
    };
    format!("{read}{write}{execute}")
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex, mpsc};
    use std::time::{Duration, Instant};

    use crate::platform::macos::sys::{
        ApfsContainer, ApfsInventory, ApfsVolume, ApfsVolumeRole,
        LocalSnapshotInfo as SysLocalSnapshotInfo, StatfsSnapshot, SwapUsage, SwapUsageInfo,
        VmStats,
    };
    use crate::platform::pal::Platform;
    use crate::platform::types::{MemoryPressure, MemoryPressureLevel};

    use super::MacOsPal;

    fn assert_platform<T: Platform>(_platform: &T) {}

    #[test]
    fn macos_pal_implements_platform() {
        let platform = MacOsPal::new();
        assert_platform(&platform);
        assert_eq!(platform.name(), "macos");
    }

    #[test]
    fn macos_pal_default_service_manager_targets_user_launchd_control() {
        let logs_path = MacOsPal::new()
            .service_manager()
            .logs_path()
            .expect("macOS service manager should expose launchd log path")
            .expect("macOS service manager should not fall back to noop");

        assert!(
            logs_path.ends_with(Path::new("Library/Logs/sbh/sbh.log")),
            "macOS PAL default service manager should target user launchd control, got {}",
            logs_path.display()
        );
    }

    #[test]
    fn memory_info_projects_available_memory_and_swap() {
        let stats = VmStats {
            page_size_bytes: 4096,
            free_count: 10,
            active_count: 120,
            inactive_count: 30,
            wire_count: 80,
            speculative_count: 4,
            compressor_page_count: 20,
            throttled_count: 0,
        };
        let swap = SwapUsage::Known(SwapUsageInfo {
            total_bytes: 1_000,
            used_bytes: 400,
            free_bytes: 600,
            encrypted: true,
        });

        let memory = super::memory_info_from_vm_stats(1_024 * 4096, stats, &swap);

        assert_eq!(memory.total_bytes, 1_024 * 4096);
        assert_eq!(memory.available_bytes, 40 * 4096);
        assert_eq!(memory.swap_total_bytes, 1_000);
        assert_eq!(memory.swap_free_bytes, 600);
    }

    #[test]
    fn memory_pressure_maps_normal_warn_and_critical_levels() {
        let total_pages = 1_000;
        let total_bytes = total_pages * 4096;
        let base = VmStats {
            page_size_bytes: 4096,
            free_count: 400,
            active_count: 300,
            inactive_count: 200,
            wire_count: 80,
            speculative_count: 20,
            compressor_page_count: 10,
            throttled_count: 0,
        };
        let no_swap = SwapUsage::Known(SwapUsageInfo {
            total_bytes: 1_000,
            used_bytes: 0,
            free_bytes: 1_000,
            encrypted: true,
        });
        let active_swap = SwapUsage::Known(SwapUsageInfo {
            total_bytes: 1_000,
            used_bytes: 500,
            free_bytes: 500,
            encrypted: true,
        });

        let normal = super::memory_pressure_from_vm_stats(total_bytes, base, &no_swap);
        assert_eq!(normal.level, MemoryPressureLevel::Normal);
        assert_eq!(normal.free_pages, Some(400));
        assert_eq!(normal.used_pages, Some(600));
        assert_eq!(normal.page_size_bytes, Some(4096));
        assert_eq!(normal.compressor_used_bytes, Some(10 * 4096));
        assert_eq!(normal.swap_total_bytes, Some(1_000));
        assert_eq!(normal.swap_used_bytes, Some(0));
        assert_eq!(normal.linux_psi_avg10, None);

        let warn = super::memory_pressure_from_vm_stats(
            total_bytes,
            VmStats {
                free_count: 40,
                compressor_page_count: 150,
                ..base
            },
            &no_swap,
        );
        assert_eq!(warn.level, MemoryPressureLevel::Warn);

        let critical = super::memory_pressure_from_vm_stats(
            total_bytes,
            VmStats {
                free_count: 10,
                compressor_page_count: 150,
                ..base
            },
            &active_swap,
        );
        assert_eq!(critical.level, MemoryPressureLevel::Critical);
    }

    #[test]
    fn memory_pressure_reports_unknown_without_page_size() {
        let pressure = super::memory_pressure_from_vm_stats(
            16 * 4096,
            VmStats {
                page_size_bytes: 0,
                free_count: 0,
                active_count: 0,
                inactive_count: 0,
                wire_count: 0,
                speculative_count: 0,
                compressor_page_count: 0,
                throttled_count: 0,
            },
            &SwapUsage::Unknown,
        );

        assert_eq!(pressure.level, MemoryPressureLevel::Unknown);
        assert_eq!(pressure.swap_total_bytes, None);
        assert_eq!(pressure.swap_used_bytes, None);
    }

    #[test]
    fn dispatch_memory_pressure_events_map_to_pal_levels() {
        assert_eq!(
            super::memory_pressure_level_from_dispatch_event(sbh_mach::MemoryPressureEvent::Normal),
            MemoryPressureLevel::Normal
        );
        assert_eq!(
            super::memory_pressure_level_from_dispatch_event(sbh_mach::MemoryPressureEvent::Warn),
            MemoryPressureLevel::Warn
        );
        assert_eq!(
            super::memory_pressure_level_from_dispatch_event(
                sbh_mach::MemoryPressureEvent::Critical
            ),
            MemoryPressureLevel::Critical
        );
        assert_eq!(
            super::memory_pressure_level_from_dispatch_event(
                sbh_mach::MemoryPressureEvent::Unknown(0)
            ),
            MemoryPressureLevel::Unknown
        );
    }

    #[test]
    fn native_memory_pressure_subscription_constructs() {
        let callback: Arc<dyn Fn(MemoryPressure) + Send + Sync + 'static> = Arc::new(|_| {});
        let handle = super::spawn_native_memory_pressure_subscription(callback)
            .expect("native dispatch memory-pressure source should construct");

        assert!(handle.active);
        assert_eq!(handle.source, "macos-memory-pressure-dispatch");
        drop(handle);
    }

    #[test]
    fn memory_pressure_subscription_reports_level_transitions() {
        let samples = Arc::new(Mutex::new(VecDeque::from([
            test_memory_pressure(MemoryPressureLevel::Normal),
            test_memory_pressure(MemoryPressureLevel::Warn),
            test_memory_pressure(MemoryPressureLevel::Warn),
            test_memory_pressure(MemoryPressureLevel::Critical),
        ])));
        let sampler_samples = Arc::clone(&samples);
        let (tx, rx) = mpsc::channel();

        let handle = super::spawn_memory_pressure_subscription(
            "test-memory-pressure",
            Duration::from_millis(1),
            Box::new(move |pressure| {
                tx.send(pressure.level).expect("receiver should be alive");
            }),
            move || {
                let mut samples = sampler_samples
                    .lock()
                    .expect("sample lock should not poison");
                Ok(samples
                    .pop_front()
                    .unwrap_or_else(|| test_memory_pressure(MemoryPressureLevel::Critical)))
            },
        )
        .expect("subscription should start");

        assert!(handle.active);
        assert_eq!(handle.source, "test-memory-pressure");
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1))
                .expect("warn transition"),
            MemoryPressureLevel::Warn,
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1))
                .expect("critical transition"),
            MemoryPressureLevel::Critical,
        );
        drop(handle);
    }

    #[test]
    fn macos_pal_memory_methods_return_live_data() {
        let platform = MacOsPal::new();
        let memory = platform
            .memory_info()
            .expect("macOS memory info should be readable");
        let pressure = platform
            .memory_pressure()
            .expect("macOS memory pressure should be readable");

        assert!(memory.total_bytes > 0);
        assert!(memory.available_bytes <= memory.total_bytes);
        assert!(pressure.page_size_bytes.is_some_and(|bytes| bytes >= 4096));
        assert!(pressure.free_pages.is_some());
        assert!(pressure.used_pages.is_some());
        assert_eq!(pressure.linux_psi_avg10, None);
    }

    fn test_memory_pressure(level: MemoryPressureLevel) -> MemoryPressure {
        MemoryPressure {
            level,
            free_pages: None,
            used_pages: None,
            page_size_bytes: Some(4096),
            compressor_used_bytes: None,
            swap_total_bytes: None,
            swap_used_bytes: None,
            linux_psi_avg10: None,
        }
    }

    #[test]
    fn capacity_uses_apfs_container_totals_for_data_volume() {
        let stats = StatfsSnapshot {
            mount_point: PathBuf::from("/System/Volumes/Data"),
            device: "/dev/disk3s5".to_string(),
            fs_type: "apfs".to_string(),
            block_size: 1,
            blocks: 400,
            blocks_free: 120,
            blocks_available: 100,
            is_readonly: false,
        };
        let inventory = ApfsInventory {
            containers: vec![ApfsContainer {
                container_id: "/dev/disk3".to_string(),
                uuid: Some("container-uuid".to_string()),
                capacity_total_bytes: Some(1_000),
                capacity_available_bytes: Some(250),
                physical_stores: vec!["/dev/disk0s2".to_string()],
            }],
            volumes: vec![
                ApfsVolume {
                    device_id: "/dev/disk3s1".to_string(),
                    container_id: "/dev/disk3".to_string(),
                    name: Some("Macintosh HD".to_string()),
                    roles: vec![ApfsVolumeRole::System],
                    capacity_in_use_bytes: Some(200),
                    container_total_bytes: Some(1_000),
                    container_available_bytes: Some(250),
                },
                ApfsVolume {
                    device_id: "/dev/disk3s5".to_string(),
                    container_id: "/dev/disk3".to_string(),
                    name: Some("Data".to_string()),
                    roles: vec![ApfsVolumeRole::Data],
                    capacity_in_use_bytes: Some(650),
                    container_total_bytes: Some(1_000),
                    container_available_bytes: Some(250),
                },
                ApfsVolume {
                    device_id: "/dev/disk3s6".to_string(),
                    container_id: "/dev/disk3".to_string(),
                    name: Some("VM".to_string()),
                    roles: vec![ApfsVolumeRole::Vm],
                    capacity_in_use_bytes: None,
                    container_total_bytes: Some(1_000),
                    container_available_bytes: Some(250),
                },
            ],
        };

        let capacity = super::statfs_to_capacity(stats, Some(&inventory));

        assert_eq!(capacity.total_bytes, 1_000);
        assert_eq!(capacity.free_bytes, 250);
        assert_eq!(capacity.available_bytes, 250);
        assert_eq!(capacity.container_id.as_deref(), Some("/dev/disk3"));
        assert_eq!(capacity.container_total_bytes, Some(1_000));
        assert_eq!(capacity.container_available_bytes, Some(250));
        assert_eq!(capacity.volume_total_bytes, Some(400));
        assert_eq!(capacity.volume_available_bytes, Some(100));
        assert_eq!(capacity.volume_role.as_deref(), Some("Data"));
        assert_eq!(capacity.shared_volumes, vec!["Macintosh HD", "VM"]);
        assert!(capacity.is_primary);
    }

    #[test]
    fn fs_stats_projection_uses_effective_apfs_container_capacity() {
        let capacity = crate::platform::types::Capacity {
            mount_point: PathBuf::from("/System/Volumes/Data"),
            fs_type: "apfs".to_string(),
            total_bytes: 1_000,
            free_bytes: 250,
            available_bytes: 250,
            is_readonly: false,
            container_id: Some("/dev/disk3".to_string()),
            container_total_bytes: Some(1_000),
            container_available_bytes: Some(250),
            volume_total_bytes: Some(400),
            volume_available_bytes: Some(100),
            volume_role: Some("Data".to_string()),
            shared_volumes: vec!["Macintosh HD".to_string()],
            is_primary: true,
            purgeable_bytes: Some(50),
            local_snapshot_bytes: Some(64),
            estimated_reclaimable_by_snapshot_thinning: None,
        };

        let stats = super::capacity_to_fs_stats(capacity);

        assert_eq!(stats.total_bytes, 1_000);
        assert_eq!(stats.free_bytes, 250);
        assert_eq!(stats.available_bytes, 250);
        assert!((stats.free_pct() - 25.0).abs() < f64::EPSILON);
        assert_eq!(stats.mount_point, PathBuf::from("/System/Volumes/Data"));
    }

    #[test]
    fn local_snapshot_info_mapping_preserves_tmutil_fields() {
        let snapshot = SysLocalSnapshotInfo {
            name: "com.apple.TimeMachine.2026-05-07-010203.local".to_string(),
            date: Some("2026-05-07-010203".to_string()),
            retained_bytes_estimate: Some(64),
            mount_path: PathBuf::from("/"),
        };

        let mapped = super::local_snapshot_info_from_sys(snapshot);

        assert_eq!(mapped.name, "com.apple.TimeMachine.2026-05-07-010203.local");
        assert_eq!(mapped.date.as_deref(), Some("2026-05-07-010203"));
        assert_eq!(mapped.retained_bytes_estimate, Some(64));
        assert_eq!(mapped.mount_path, PathBuf::from("/"));
    }

    #[test]
    fn local_snapshot_capacity_probe_skips_unidentified_or_non_data_volumes() {
        let stats = StatfsSnapshot {
            mount_point: PathBuf::from("/"),
            device: "/dev/disk3s1".to_string(),
            fs_type: "apfs".to_string(),
            block_size: 1,
            blocks: 400,
            blocks_free: 120,
            blocks_available: 100,
            is_readonly: true,
        };

        assert_eq!(super::local_snapshot_bytes_for_capacity(&stats, None), None);

        let inventory = ApfsInventory {
            containers: vec![ApfsContainer {
                container_id: "/dev/disk3".to_string(),
                uuid: Some("container-uuid".to_string()),
                capacity_total_bytes: Some(1_000),
                capacity_available_bytes: Some(250),
                physical_stores: vec!["/dev/disk0s2".to_string()],
            }],
            volumes: vec![ApfsVolume {
                device_id: "/dev/disk3s1".to_string(),
                container_id: "/dev/disk3".to_string(),
                name: Some("Macintosh HD".to_string()),
                roles: vec![ApfsVolumeRole::System],
                capacity_in_use_bytes: Some(200),
                container_total_bytes: Some(1_000),
                container_available_bytes: Some(250),
            }],
        };

        assert_eq!(
            super::local_snapshot_bytes_for_capacity(&stats, Some(&inventory)),
            None
        );
    }

    #[test]
    fn mount_info_uses_apfs_container_metadata_and_snapshot_estimate() {
        let stats = StatfsSnapshot {
            mount_point: PathBuf::from("/Volumes/TestData"),
            device: "/dev/disk3s5".to_string(),
            fs_type: "apfs".to_string(),
            block_size: 1,
            blocks: 400,
            blocks_free: 120,
            blocks_available: 100,
            is_readonly: false,
        };
        let inventory = ApfsInventory {
            containers: vec![ApfsContainer {
                container_id: "/dev/disk3".to_string(),
                uuid: Some("container-uuid".to_string()),
                capacity_total_bytes: Some(1_000),
                capacity_available_bytes: Some(250),
                physical_stores: vec!["/dev/disk0s2".to_string()],
            }],
            volumes: vec![
                ApfsVolume {
                    device_id: "/dev/disk3s1".to_string(),
                    container_id: "/dev/disk3".to_string(),
                    name: Some("Macintosh HD".to_string()),
                    roles: vec![ApfsVolumeRole::System],
                    capacity_in_use_bytes: Some(100),
                    container_total_bytes: Some(1_000),
                    container_available_bytes: Some(250),
                },
                ApfsVolume {
                    device_id: "/dev/disk3s5".to_string(),
                    container_id: "/dev/disk3".to_string(),
                    name: Some("Data".to_string()),
                    roles: vec![ApfsVolumeRole::Data],
                    capacity_in_use_bytes: Some(600),
                    container_total_bytes: Some(1_000),
                    container_available_bytes: Some(250),
                },
            ],
        };

        let mount_info = super::statfs_to_mount_info(stats, Some(&inventory), Some(64));

        assert_eq!(mount_info.container_id.as_deref(), Some("/dev/disk3"));
        assert_eq!(mount_info.total_bytes, Some(1_000));
        assert_eq!(mount_info.available_bytes, Some(250));
        assert_eq!(mount_info.purgeable_bytes, Some(50));
        assert_eq!(mount_info.local_snapshot_bytes, Some(64));
        assert!(mount_info.is_apfs_data_volume);
        assert!(!mount_info.is_apfs_system_snapshot);
        assert!(!mount_info.is_apfs_vm_volume);
    }

    #[test]
    fn mount_info_marks_apfs_system_and_vm_roles() {
        let inventory = ApfsInventory {
            containers: vec![ApfsContainer {
                container_id: "/dev/disk3".to_string(),
                uuid: Some("container-uuid".to_string()),
                capacity_total_bytes: Some(1_000),
                capacity_available_bytes: Some(250),
                physical_stores: vec!["/dev/disk0s2".to_string()],
            }],
            volumes: vec![
                ApfsVolume {
                    device_id: "/dev/disk3s1".to_string(),
                    container_id: "/dev/disk3".to_string(),
                    name: Some("Macintosh HD".to_string()),
                    roles: vec![ApfsVolumeRole::System],
                    capacity_in_use_bytes: Some(100),
                    container_total_bytes: Some(1_000),
                    container_available_bytes: Some(250),
                },
                ApfsVolume {
                    device_id: "/dev/disk3s6".to_string(),
                    container_id: "/dev/disk3".to_string(),
                    name: Some("VM".to_string()),
                    roles: vec![ApfsVolumeRole::Vm],
                    capacity_in_use_bytes: Some(50),
                    container_total_bytes: Some(1_000),
                    container_available_bytes: Some(250),
                },
            ],
        };

        let system = super::statfs_to_mount_info(
            StatfsSnapshot {
                mount_point: PathBuf::from("/Volumes/TestSystem"),
                device: "/dev/disk3s1".to_string(),
                fs_type: "apfs".to_string(),
                block_size: 1,
                blocks: 400,
                blocks_free: 120,
                blocks_available: 100,
                is_readonly: true,
            },
            Some(&inventory),
            None,
        );
        let vm = super::statfs_to_mount_info(
            StatfsSnapshot {
                mount_point: PathBuf::from("/Volumes/TestVM"),
                device: "/dev/disk3s6".to_string(),
                fs_type: "apfs".to_string(),
                block_size: 1,
                blocks: 400,
                blocks_free: 120,
                blocks_available: 100,
                is_readonly: false,
            },
            Some(&inventory),
            None,
        );

        assert!(system.is_apfs_system_snapshot);
        assert!(!system.is_apfs_data_volume);
        assert!(!system.is_apfs_vm_volume);
        assert!(vm.is_apfs_vm_volume);
        assert!(!vm.is_apfs_system_snapshot);
        assert!(!vm.is_apfs_data_volume);
    }

    #[test]
    fn macos_pal_mounts_reports_live_apfs_annotations_when_available() {
        let Ok(inventory) = crate::platform::macos::sys::apfs_inventory() else {
            return;
        };
        if inventory.volumes.is_empty() {
            return;
        }

        let platform = MacOsPal::new();
        let mounts = platform
            .mounts()
            .expect("macOS mount inventory should be readable");
        let apfs_mounts: Vec<_> = mounts
            .iter()
            .filter(|mount| mount.fs_type.eq_ignore_ascii_case("apfs"))
            .collect();
        if apfs_mounts.is_empty() {
            return;
        }

        assert!(apfs_mounts.iter().any(|mount| mount.container_id.is_some()));
        assert!(apfs_mounts.iter().any(|mount| {
            mount.is_apfs_data_volume || mount.is_apfs_system_snapshot || mount.is_apfs_vm_volume
        }));
    }

    #[test]
    fn purgeable_estimate_subtracts_counted_free_space() {
        assert_eq!(
            super::purgeable_bytes_from_important_available(900, 250),
            Some(650)
        );
        assert_eq!(
            super::purgeable_bytes_from_important_available(250, 250),
            None
        );
        assert_eq!(
            super::purgeable_bytes_from_important_available(200, 250),
            None
        );
    }

    #[test]
    fn purgeable_inventory_fallback_uses_unattributed_container_bytes() {
        let inventory = ApfsInventory {
            containers: vec![ApfsContainer {
                container_id: "/dev/disk3".to_string(),
                uuid: Some("container-uuid".to_string()),
                capacity_total_bytes: Some(1_000),
                capacity_available_bytes: Some(250),
                physical_stores: vec!["/dev/disk0s2".to_string()],
            }],
            volumes: vec![
                ApfsVolume {
                    device_id: "/dev/disk3s1".to_string(),
                    container_id: "/dev/disk3".to_string(),
                    name: Some("Macintosh HD".to_string()),
                    roles: vec![ApfsVolumeRole::System],
                    capacity_in_use_bytes: Some(200),
                    container_total_bytes: Some(1_000),
                    container_available_bytes: Some(250),
                },
                ApfsVolume {
                    device_id: "/dev/disk3s5".to_string(),
                    container_id: "/dev/disk3".to_string(),
                    name: Some("Data".to_string()),
                    roles: vec![ApfsVolumeRole::Data],
                    capacity_in_use_bytes: Some(500),
                    container_total_bytes: Some(1_000),
                    container_available_bytes: Some(250),
                },
            ],
        };

        assert_eq!(
            super::purgeable_bytes_from_apfs_inventory(Some(&inventory), Some("/dev/disk3")),
            Some(50)
        );
    }

    #[test]
    fn process_list_returns_visible_processes_except_self_and_pid_zero() {
        let platform = MacOsPal::new();
        let processes = platform
            .process_list()
            .expect("macOS process list should be readable");
        assert!(!processes.is_empty());
        assert!(!processes.iter().any(|process| process.pid == 0));
        assert!(
            !processes
                .iter()
                .any(|process| process.pid == super::current_process_pid())
        );
        assert!(processes.iter().all(|process| !process.name.is_empty()));
        assert!(
            processes
                .iter()
                .any(|process| process.resident_memory_bytes.is_some())
        );
    }

    #[test]
    fn process_info_for_current_pid_includes_command_line() {
        let current = super::current_process_pid();
        let process =
            super::process_info_for_pid(current).expect("current process info should be readable");

        assert_eq!(process.pid, current);
        assert!(!process.command_line.is_empty());
        assert!(process.cpu_user_micros.is_some());
        assert!(process.cpu_system_micros.is_some());
    }

    #[test]
    fn process_path_matching_handles_private_mount_aliases_without_realpath() {
        assert!(super::process_path_is_under_root(
            Path::new("/private/tmp/sbh/open-file"),
            Path::new("/tmp/sbh")
        ));
        assert!(super::process_path_is_under_root(
            Path::new("/tmp/sbh/open-file"),
            Path::new("/private/tmp/sbh")
        ));
        assert!(super::process_path_is_under_root(
            Path::new("/private/var/folders/sbh/open-file"),
            Path::new("/var/folders/sbh")
        ));
        assert!(!super::process_path_is_under_root(
            Path::new("/private/tmp/sbh-other/open-file"),
            Path::new("/tmp/sbh")
        ));
    }

    #[test]
    fn process_io_returns_lifetime_rusage_counters_for_current_process() {
        let current = super::current_process_pid();
        let platform = MacOsPal::new();
        let io = platform
            .process_io(current)
            .expect("current process rusage should be readable");
        let raw = crate::platform::macos::libproc::proc_pid_rusage_v4_safe(current)
            .expect("current process raw rusage should be readable");

        assert_eq!(io.pid, current);
        assert!(io.bytes_read_total <= raw.ri_diskio_bytesread);
        assert!(io.bytes_written_total <= raw.ri_diskio_byteswritten);
        assert_eq!(io.bytes_read_recent_15m, None);
        assert_eq!(io.bytes_written_recent_15m, None);
    }

    #[test]
    fn macos_self_stats_reports_current_process() {
        let platform = MacOsPal::new();
        let stats = platform
            .self_stats()
            .expect("macOS self stats should be readable");
        let raw =
            crate::platform::macos::libproc::proc_pid_rusage_v4_safe(super::current_process_pid())
                .expect("current process raw rusage should be readable");

        assert!(stats.rss_bytes > 0);
        assert!(stats.virtual_memory_bytes >= stats.rss_bytes);
        assert_eq!(
            stats.idle_wakeups,
            Some(raw.ri_pkg_idle_wkups.saturating_add(raw.ri_interrupt_wkups))
        );
        assert!(
            stats
                .bytes_read
                .is_some_and(|bytes| bytes <= raw.ri_diskio_bytesread)
        );
        assert!(
            stats
                .bytes_written
                .is_some_and(|bytes| bytes <= raw.ri_diskio_byteswritten)
        );
    }

    #[test]
    fn open_files_under_returns_current_process_tempfile_fd() {
        let dir = tempfile::TempDir::new().expect("temp dir should be created");
        let file_path = dir.path().join("open-file.txt");
        let _file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_path)
            .expect("temp file should stay open for fd scan");
        let expected = std::fs::canonicalize(&file_path).expect("temp file should canonicalize");

        let platform = MacOsPal::new();
        let open_files = platform
            .open_files_under(dir.path())
            .expect("macOS open fd scan should be readable");
        assert!(open_files.complete);

        let actual = open_files
            .files
            .iter()
            .find(|open_file| {
                open_file.pid == super::current_process_pid() && open_file.path == expected
            })
            .expect("current process open tempfile should be reported");
        assert_eq!(actual.kind, crate::platform::types::OpenFileKind::Regular);
        assert_eq!(actual.mode, crate::platform::types::OpenFileMode::ReadWrite);
        assert!(actual.fd.is_some());
    }

    #[test]
    fn open_files_under_reuses_recent_cached_snapshot() {
        assert_eq!(super::OPEN_FILES_CACHE_TTL, Duration::from_secs(30));

        let dir = tempfile::TempDir::new().expect("temp dir should be created");
        let file_path = dir.path().join("cached-open-file.txt");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_path)
            .expect("temp file should stay open for first fd scan");
        let expected = std::fs::canonicalize(&file_path).expect("temp file should canonicalize");

        let platform = MacOsPal::new();
        let first = platform
            .open_files_under(dir.path())
            .expect("first macOS open fd scan should be readable");
        assert!(first.complete);
        assert!(first.files.iter().any(|open_file| {
            open_file.pid == super::current_process_pid() && open_file.path == expected
        }));

        drop(file);

        let second = platform
            .open_files_under(dir.path())
            .expect("cached macOS open fd scan should be readable");
        assert!(second.complete);
        assert!(
            second.files.iter().any(|open_file| {
                open_file.pid == super::current_process_pid() && open_file.path == expected
            }),
            "recent open_files_under calls should reuse the cached 30s snapshot"
        );
    }

    #[test]
    fn executables_under_returns_current_process_executable() {
        let current_exe = std::env::current_exe().expect("current executable should be known");
        let root = current_exe
            .parent()
            .expect("current executable should have parent");
        let expected =
            std::fs::canonicalize(&current_exe).expect("current executable should canonicalize");

        let platform = MacOsPal::new();
        let processes = platform
            .executables_under(root)
            .expect("macOS executable scan should be readable");
        assert!(processes.complete);

        assert!(processes.processes.iter().any(|process| {
            process.pid == super::current_process_pid()
                && process.executable.as_deref() == Some(expected.as_path())
        }));
    }

    #[test]
    fn file_block_count_reports_allocated_blocks_for_macos_file() {
        let dir = tempfile::TempDir::new().expect("temp dir should be created");
        let path = dir.path().join("block-count.bin");
        let payload = vec![0x5a; 16 * 1024];
        let mut file = std::fs::File::create(&path).expect("temp file should be created");
        file.write_all(&payload)
            .expect("temp file payload should be written");
        file.sync_all().expect("temp file should sync");
        drop(file);

        let platform = MacOsPal::new();
        let blocks = platform
            .file_block_count(&path)
            .expect("file block count should be readable");

        let metadata_blocks = std::fs::metadata(&path)
            .expect("temp file metadata should be readable")
            .blocks();
        assert_eq!(blocks, metadata_blocks);
        assert!(blocks > 0);
    }

    #[test]
    fn preallocate_file_reserves_blocks_on_macos() {
        let dir = tempfile::TempDir::new().expect("temp dir should be created");
        let path = dir.path().join("preallocated-macos.bin");
        let size = 1024 * 1024;
        let platform = MacOsPal::new();

        platform
            .preallocate_file(&path, size)
            .expect("macOS preallocation should succeed");

        let metadata = std::fs::metadata(&path).expect("preallocated file should exist");
        assert_eq!(metadata.len(), size);
        let allocated_bytes = platform
            .file_block_count(&path)
            .expect("block count should be readable")
            * 512;
        assert!(allocated_bytes >= size);
    }

    #[test]
    fn preallocate_64mib_ballast_file_in_under_one_second() {
        let dir = tempfile::TempDir::new().expect("temp dir should be created");
        let path = dir.path().join("ballast-64mib.bin");
        let size = 64 * 1024 * 1024;
        let platform = MacOsPal::new();

        let start = std::time::Instant::now();
        platform
            .preallocate_file(&path, size)
            .expect("macOS 64 MiB preallocation should succeed");
        let elapsed = start.elapsed();

        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "64 MiB preallocation took {elapsed:?}, expected < 1s"
        );
        let metadata = std::fs::metadata(&path).expect("preallocated file should exist");
        assert_eq!(metadata.len(), size);
    }

    #[test]
    fn mmap_regions_under_reports_current_process_executable_mapping() {
        let current_exe = std::env::current_exe().expect("current executable should be known");
        let root = current_exe
            .parent()
            .expect("current executable should have parent");
        let expected =
            std::fs::canonicalize(&current_exe).expect("current executable should canonicalize");

        let root_variants = super::macos_process_path_variants(root);
        let regions = super::mapped_regions_for_pid_under(
            super::current_process_pid(),
            &root_variants,
            Instant::now() + super::MMAP_REGIONS_SCAN_TIMEOUT,
        )
        .expect("current process macOS mapped region scan should be readable");

        assert!(regions.iter().any(|region| {
            region.pid == super::current_process_pid()
                && region.path == expected
                && region.start_address.is_some()
                && region.end_address.is_some()
                && region.protection.is_some()
        }));
    }
}
