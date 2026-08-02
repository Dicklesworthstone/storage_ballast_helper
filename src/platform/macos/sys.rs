//! Safe macOS filesystem syscall adapters.

#![cfg(target_os = "macos")]
#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::mount::MntFlags;
use nix::sys::statfs::{Statfs, statfs as nix_statfs};
use parking_lot::RwLock;
use plist::Value;
use std::sync::{OnceLock, mpsc};

const STATFS_STRUCT_SIZE_BYTES: usize = core::mem::size_of::<libc::statfs>();
const STATFS_MOUNT_NAME_BYTES: usize = core::mem::size_of::<[libc::c_char; 1024]>();
const STATFS_TYPE_NAME_BYTES: usize = core::mem::size_of::<[libc::c_char; 16]>();
const IMPORTANT_USAGE_AVAILABLE_KEY: &str = "NSURLVolumeAvailableCapacityForImportantUsageKey";
const FIRMLINK_DATA_ROOT: &str = "/System/Volumes/Data";

const _: [(); 2168] = [(); STATFS_STRUCT_SIZE_BYTES];
const _: [(); 1024] = [(); STATFS_MOUNT_NAME_BYTES];
const _: [(); 16] = [(); STATFS_TYPE_NAME_BYTES];

const APFS_CACHE_TTL_SECS: u64 = 5 * 60;
const APFS_CACHE_TTL: Duration = Duration::from_secs(APFS_CACHE_TTL_SECS);
const MOUNTED_FILESYSTEMS_CACHE_TTL: Duration = Duration::from_secs(5);
const MOUNT_COMMAND_TIMEOUT: Duration = Duration::from_secs(6);
const MOUNT_COMMAND_FAILURE_BACKOFF: Duration = Duration::from_mins(5);
const DISKUTIL_APFS_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const TMUTIL_LIST_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const TMUTIL_THIN_COMMAND_TIMEOUT: Duration = Duration::from_mins(2);
const MACOS_COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(25);
const MACOS_COMMAND_OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const MACOS_COMMAND_KILL_REAP_ATTEMPTS: usize = 10;
pub const LOCAL_SNAPSHOT_THIN_AMOUNT_BYTES: u64 = 9_999_999_999_999_999;
pub const LOCAL_SNAPSHOT_THIN_URGENCY: u8 = 4;
type MountedFilesystemsCache = RwLock<Option<(Instant, Vec<StatfsSnapshot>)>>;
type MountCommandBackoff = RwLock<Option<Instant>>;

static APFS_INVENTORY_CACHE: OnceLock<RwLock<Option<(Instant, ApfsInventory)>>> = OnceLock::new();
static MOUNTED_FILESYSTEMS_CACHE: OnceLock<MountedFilesystemsCache> = OnceLock::new();
static MOUNT_COMMAND_BACKOFF_UNTIL: OnceLock<MountCommandBackoff> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatfsSnapshot {
    pub mount_point: PathBuf,
    pub device: String,
    pub fs_type: String,
    pub block_size: u64,
    pub blocks: u64,
    pub blocks_free: u64,
    pub blocks_available: u64,
    pub is_readonly: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountCommandEntry {
    device: String,
    mount_point: PathBuf,
    is_local: bool,
}

impl StatfsSnapshot {
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.blocks.saturating_mul(self.block_size)
    }

    #[must_use]
    pub fn free_bytes(&self) -> u64 {
        self.blocks_free.saturating_mul(self.block_size)
    }

    #[must_use]
    pub fn available_bytes(&self) -> u64 {
        self.blocks_available.saturating_mul(self.block_size)
    }

    #[must_use]
    pub fn is_ram_backed(&self) -> bool {
        matches!(
            self.fs_type.to_ascii_lowercase().as_str(),
            "devfs" | "mfs" | "ramfs" | "tmpfs"
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApfsInventory {
    pub containers: Vec<ApfsContainer>,
    pub volumes: Vec<ApfsVolume>,
}

impl ApfsInventory {
    #[must_use]
    pub fn volume_for_device(&self, device_id: &str) -> Option<&ApfsVolume> {
        let normalized = normalize_device_id(device_id);
        self.volumes
            .iter()
            .find(|volume| volume.device_id == normalized)
            .or_else(|| {
                parent_apfs_volume_device(&normalized).and_then(|parent| {
                    self.volumes
                        .iter()
                        .find(|volume| volume.device_id == parent)
                })
            })
    }

    #[must_use]
    pub fn sibling_volume_names(&self, volume: &ApfsVolume) -> Vec<String> {
        let mut siblings: Vec<String> = self
            .volumes
            .iter()
            .filter(|candidate| candidate.container_id == volume.container_id)
            .filter(|candidate| candidate.device_id != volume.device_id)
            .map(ApfsVolume::display_name)
            .collect();
        siblings.sort();
        siblings.dedup();
        siblings
    }

    #[must_use]
    pub fn unattributed_container_used_bytes(&self, container_id: &str) -> Option<u64> {
        let container = self
            .containers
            .iter()
            .find(|candidate| candidate.container_id == container_id)?;
        let total_bytes = container.capacity_total_bytes?;
        let available_bytes = container.capacity_available_bytes?;
        let used_bytes = total_bytes.checked_sub(available_bytes)?;
        let volume_bytes = self
            .volumes
            .iter()
            .filter(|volume| volume.container_id == container_id)
            .filter_map(|volume| volume.capacity_in_use_bytes)
            .fold(0_u64, u64::saturating_add);
        used_bytes.checked_sub(volume_bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApfsContainer {
    pub container_id: String,
    pub uuid: Option<String>,
    pub capacity_total_bytes: Option<u64>,
    pub capacity_available_bytes: Option<u64>,
    pub physical_stores: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApfsVolume {
    pub device_id: String,
    pub container_id: String,
    pub name: Option<String>,
    pub roles: Vec<ApfsVolumeRole>,
    pub capacity_in_use_bytes: Option<u64>,
    pub container_total_bytes: Option<u64>,
    pub container_available_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSnapshotInfo {
    pub name: String,
    pub date: Option<String>,
    pub retained_bytes_estimate: Option<u64>,
    pub mount_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSnapshotThinReport {
    pub mount_path: PathBuf,
    pub requested_bytes: u64,
    pub urgency: u8,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapUsage {
    Known(SwapUsageInfo),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapUsageInfo {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmStats {
    pub page_size_bytes: u64,
    pub free_count: u64,
    pub active_count: u64,
    pub inactive_count: u64,
    pub wire_count: u64,
    pub speculative_count: u64,
    pub compressor_page_count: u64,
    pub throttled_count: u64,
}

impl VmStats {
    #[must_use]
    pub fn accounted_pages(&self) -> u64 {
        self.free_count
            .saturating_add(self.active_count)
            .saturating_add(self.inactive_count)
            .saturating_add(self.wire_count)
            .saturating_add(self.compressor_page_count)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachTaskUsage {
    pub rss_bytes: u64,
    pub virtual_memory_bytes: u64,
    pub cpu_user_micros: u64,
    pub cpu_system_micros: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachThreadBasicInfo {
    pub user_time_micros: u64,
    pub system_time_micros: u64,
    pub cpu_usage_scaled: i32,
    pub run_state: i32,
    pub flags: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmlinkMap {
    pub mappings: Vec<FirmlinkMapping>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmlinkMapping {
    pub visible_path: PathBuf,
    pub data_path: PathBuf,
    pub source: FirmlinkSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmlinkSource {
    SystemFirmlink,
    SyntheticConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApfsVolumeRole {
    Data,
    System,
    Preboot,
    Vm,
    Update,
    Recovery,
    Other(String),
}

impl ApfsVolume {
    #[must_use]
    pub fn has_role(&self, role: &ApfsVolumeRole) -> bool {
        self.roles.iter().any(|candidate| candidate == role)
    }

    #[must_use]
    pub fn role_label(&self) -> Option<String> {
        if self.roles.is_empty() {
            return None;
        }
        Some(
            self.roles
                .iter()
                .map(ApfsVolumeRole::as_str)
                .collect::<Vec<_>>()
                .join(","),
        )
    }

    #[must_use]
    pub fn display_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| self.device_id.clone())
    }
}

impl FirmlinkMap {
    #[must_use]
    pub fn resolve(&self, path: &Path) -> PathBuf {
        self.mappings
            .iter()
            .find_map(|mapping| resolve_with_mapping(path, mapping))
            .unwrap_or_else(|| path.to_path_buf())
    }
}

pub fn statfs(path: &Path) -> io::Result<StatfsSnapshot> {
    let raw = nix_statfs(path).map_err(nix_error)?;
    let location = whichdisk::resolve(path).ok();
    let mount_point = location.as_ref().map_or_else(
        || path.to_path_buf(),
        |info| info.mount_point().to_path_buf(),
    );
    let device = location
        .as_ref()
        .map_or_else(String::new, |info| os_str_to_string(info.device()));

    Ok(snapshot_from_statfs(&raw, mount_point, device))
}

pub fn mounted_filesystems() -> io::Result<Vec<StatfsSnapshot>> {
    let cache = MOUNTED_FILESYSTEMS_CACHE.get_or_init(|| RwLock::new(None));
    {
        let cached = cache.read();
        if let Some((collected_at, filesystems)) = &*cached
            && collected_at.elapsed() < MOUNTED_FILESYSTEMS_CACHE_TTL
        {
            return Ok(filesystems.clone());
        }
    }

    let mut filesystems = Vec::new();
    for mount in mount_command_entries()? {
        if !mount.is_local {
            continue;
        }
        match statfs_for_mount(&mount.mount_point, OsStr::new(&mount.device)) {
            Ok(snapshot) => filesystems.push(snapshot),
            Err(error) => eprintln!(
                "[sbh] warning: skipping macOS mount {}: {error}",
                mount.mount_point.display()
            ),
        }
    }
    filesystems.sort_by(|left, right| {
        right
            .mount_point
            .as_os_str()
            .len()
            .cmp(&left.mount_point.as_os_str().len())
            .then_with(|| left.mount_point.cmp(&right.mount_point))
    });
    *cache.write() = Some((Instant::now(), filesystems.clone()));
    Ok(filesystems)
}

fn mount_command_entries() -> io::Result<Vec<MountCommandEntry>> {
    let now = Instant::now();
    if mount_command_in_backoff(now) {
        return whichdisk_mount_entries();
    }

    let mut command = Command::new("/sbin/mount");
    match command_output_with_timeout(&mut command, MOUNT_COMMAND_TIMEOUT) {
        Ok(Some(output)) if output.status.success() => {
            clear_mount_command_failure_backoff();
            let entries = parse_mount_command_output(&String::from_utf8_lossy(&output.stdout));
            if entries.is_empty() {
                whichdisk_mount_entries()
            } else {
                Ok(entries)
            }
        }
        Ok(Some(output)) => {
            remember_mount_command_failure(now);
            let detail = String::from_utf8_lossy(&output.stderr);
            eprintln!(
                "[sbh] warning: /sbin/mount failed with status {}: {}; falling back to whichdisk",
                output.status,
                detail.trim()
            );
            whichdisk_mount_entries()
        }
        Ok(None) => {
            remember_mount_command_failure(now);
            eprintln!(
                "[sbh] warning: /sbin/mount timed out after {MOUNT_COMMAND_TIMEOUT:?}; falling back to whichdisk"
            );
            whichdisk_mount_entries()
        }
        Err(error) => {
            remember_mount_command_failure(now);
            eprintln!("[sbh] warning: /sbin/mount unavailable: {error}; falling back to whichdisk");
            whichdisk_mount_entries()
        }
    }
}

fn mount_command_in_backoff(now: Instant) -> bool {
    let backoff = MOUNT_COMMAND_BACKOFF_UNTIL.get_or_init(|| RwLock::new(None));
    backoff
        .read()
        .as_ref()
        .is_some_and(|retry_at| now < *retry_at)
}

fn remember_mount_command_failure(now: Instant) {
    let backoff = MOUNT_COMMAND_BACKOFF_UNTIL.get_or_init(|| RwLock::new(None));
    *backoff.write() = now.checked_add(MOUNT_COMMAND_FAILURE_BACKOFF);
}

fn clear_mount_command_failure_backoff() {
    if let Some(backoff) = MOUNT_COMMAND_BACKOFF_UNTIL.get() {
        *backoff.write() = None;
    }
}

fn command_timeout_error(command_name: &str, timeout: Duration) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("{command_name} timed out after {timeout:?}"),
    )
}

/// Hand a child we can no longer wait for on this thread to a detached reaper.
///
/// `Child::drop` deliberately does **not** wait, so dropping a spawned child
/// that has not been reaped leaves a zombie for the lifetime of the process.
/// In a long-running daemon that is a permanent leak: observed in the wild as
/// ~400 zombies parented to a single `sbh daemon` after two days, which is a
/// third of the machine's whole process table.
///
/// Blocking in `wait()` is precisely what must not happen on the caller's
/// thread — that is the point of the timeout — and precisely what is harmless
/// on a throwaway one.
fn reap_detached(child: Child) {
    thread::spawn(move || {
        let mut child = child;
        let _ = child.wait();
    });
}

fn command_output_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> io::Result<Option<Output>> {
    command_output_with_timeout_inner(command, timeout, MACOS_COMMAND_KILL_REAP_ATTEMPTS)
}

/// `kill_reap_attempts` is a parameter purely so tests can force the slow path.
/// Whether the bounded window is missed depends on kernel scheduling and on
/// whether the child is wedged in an uninterruptible syscall, neither of which
/// a test can arrange reliably — but setting the budget to zero exercises the
/// exact same code, which is the part that used to leak.
fn command_output_with_timeout_inner(
    command: &mut Command,
    timeout: Duration,
    kill_reap_attempts: usize,
) -> io::Result<Option<Output>> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdout = child.stdout.take().map(spawn_command_stream_reader);
    let mut stderr = child.stderr.take().map(spawn_command_stream_reader);
    let deadline = Instant::now() + timeout;

    loop {
        // Every exit path below must either have reaped the child or handed it
        // to `reap_detached`. Returning while still owning an unreaped `Child`
        // is what leaks a zombie.
        match child.try_wait() {
            Ok(Some(status)) => {
                // Reaped: dropping `child` from here on is safe.
                let Some(stdout) =
                    receive_command_stream(stdout.take(), MACOS_COMMAND_OUTPUT_DRAIN_TIMEOUT)?
                else {
                    return Ok(None);
                };
                let Some(stderr) =
                    receive_command_stream(stderr.take(), MACOS_COMMAND_OUTPUT_DRAIN_TIMEOUT)?
                else {
                    return Ok(None);
                };
                return Ok(Some(Output {
                    status,
                    stdout,
                    stderr,
                }));
            }
            Ok(None) => {}
            Err(error) => {
                reap_detached(child);
                return Err(error);
            }
        }

        if Instant::now() >= deadline {
            let _ = child.kill();

            // Fast path: a killed child normally dies at once, and reaping it
            // here avoids spawning a thread on every timeout.
            for _ in 0..kill_reap_attempts {
                match child.try_wait() {
                    Ok(Some(_)) => return Ok(None),
                    Ok(None) => thread::sleep(MACOS_COMMAND_POLL_INTERVAL),
                    // Surface the error as the pre-fix code did, but hand the
                    // child off first — swallowing it here would silently turn
                    // a broken wait into "timed out", and dropping it would
                    // reintroduce the leak on the error path.
                    Err(error) => {
                        reap_detached(child);
                        return Err(error);
                    }
                }
            }

            // Slow path. This window is only 250ms, and it is missed for two
            // very ordinary reasons: the child is blocked in an uninterruptible
            // syscall on a wedged filesystem, so SIGKILL cannot land until the
            // syscall returns; or the machine is loaded enough that the child's
            // exit and our next poll simply do not fit inside it. The latter
            // makes this leak self-reinforcing — a slow box misses the window
            // more often, and every miss adds a zombie that makes it slower.
            reap_detached(child);
            return Ok(None);
        }
        thread::sleep(MACOS_COMMAND_POLL_INTERVAL);
    }
}

fn spawn_command_stream_reader<R>(mut reader: R) -> mpsc::Receiver<io::Result<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut output = Vec::new();
        let result = reader.read_to_end(&mut output).map(|_| output);
        let _ = sender.send(result);
    });
    receiver
}

fn receive_command_stream(
    receiver: Option<mpsc::Receiver<io::Result<Vec<u8>>>>,
    timeout: Duration,
) -> io::Result<Option<Vec<u8>>> {
    let Some(receiver) = receiver else {
        return Ok(Some(Vec::new()));
    };
    match receiver.recv_timeout(timeout) {
        Ok(result) => result.map(Some),
        Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
        Err(mpsc::RecvTimeoutError::Disconnected) => Ok(Some(Vec::new())),
    }
}

fn whichdisk_mount_entries() -> io::Result<Vec<MountCommandEntry>> {
    whichdisk::list().map_err(io::Error::other).map(|mounts| {
        mounts
            .into_iter()
            .map(|mount| MountCommandEntry {
                device: os_str_to_string(mount.device()),
                mount_point: mount.mount_point().to_path_buf(),
                is_local: true,
            })
            .collect()
    })
}

fn parse_mount_command_output(raw: &str) -> Vec<MountCommandEntry> {
    let mut by_mount_point = BTreeMap::new();
    for line in raw.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let Some((device, rest)) = line.split_once(" on ") else {
            continue;
        };
        let Some((mount_point, options)) = rest.rsplit_once(" (") else {
            continue;
        };
        let is_local = options
            .trim_end_matches(')')
            .split(',')
            .map(str::trim)
            .any(|option| option == "local");
        by_mount_point.insert(PathBuf::from(mount_point), (device.to_string(), is_local));
    }

    by_mount_point
        .into_iter()
        .map(|(mount_point, (device, is_local))| MountCommandEntry {
            device,
            mount_point,
            is_local,
        })
        .collect()
}

pub fn apfs_inventory() -> io::Result<ApfsInventory> {
    let cache = APFS_INVENTORY_CACHE.get_or_init(|| RwLock::new(None));
    {
        let cached = cache.read();
        if let Some((collected_at, inventory)) = &*cached
            && collected_at.elapsed() < APFS_CACHE_TTL
        {
            return Ok(inventory.clone());
        }
    }

    let mut command = Command::new("/usr/sbin/diskutil");
    command.args(["apfs", "list", "-plist"]);
    let Some(output) = command_output_with_timeout(&mut command, DISKUTIL_APFS_COMMAND_TIMEOUT)?
    else {
        return Err(command_timeout_error(
            "diskutil apfs list -plist",
            DISKUTIL_APFS_COMMAND_TIMEOUT,
        ));
    };
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "diskutil apfs list -plist failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let inventory = parse_apfs_inventory(&output.stdout)?;
    *cache.write() = Some((Instant::now(), inventory.clone()));
    Ok(inventory)
}

pub fn local_time_machine_snapshots(
    mount: &Path,
    inventory: Option<&ApfsInventory>,
    volume: Option<&ApfsVolume>,
) -> io::Result<Vec<LocalSnapshotInfo>> {
    let mut command = Command::new("/usr/bin/tmutil");
    command.arg("listlocalsnapshots").arg(mount);
    let Some(output) = command_output_with_timeout(&mut command, TMUTIL_LIST_COMMAND_TIMEOUT)?
    else {
        return Err(command_timeout_error(
            "tmutil listlocalsnapshots",
            TMUTIL_LIST_COMMAND_TIMEOUT,
        ));
    };
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "tmutil listlocalsnapshots {} failed with status {}: {}",
            mount.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let retained_total_estimate = inventory.zip(volume).and_then(|(inventory, volume)| {
        // APFS does not expose per-snapshot byte counts through tmutil; treat
        // container usage that is not attributed to mounted volumes as a
        // retained-by-snapshots estimate.
        inventory.unattributed_container_used_bytes(&volume.container_id)
    });
    Ok(parse_tmutil_local_snapshots(
        &String::from_utf8_lossy(&output.stdout),
        mount,
        retained_total_estimate,
    ))
}

pub fn thin_local_time_machine_snapshots(mount: &Path) -> io::Result<LocalSnapshotThinReport> {
    thin_local_time_machine_snapshots_with(
        mount,
        LOCAL_SNAPSHOT_THIN_AMOUNT_BYTES,
        LOCAL_SNAPSHOT_THIN_URGENCY,
    )
}

pub fn thin_local_time_machine_snapshots_with(
    mount: &Path,
    requested_bytes: u64,
    urgency: u8,
) -> io::Result<LocalSnapshotThinReport> {
    let mut command = Command::new("/usr/bin/tmutil");
    command.args(tmutil_thinlocalsnapshots_args(
        mount,
        requested_bytes,
        urgency,
    ));
    let Some(output) = command_output_with_timeout(&mut command, TMUTIL_THIN_COMMAND_TIMEOUT)?
    else {
        return Err(command_timeout_error(
            "tmutil thinlocalsnapshots",
            TMUTIL_THIN_COMMAND_TIMEOUT,
        ));
    };
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "tmutil thinlocalsnapshots {} {} {} failed with status {}: {}",
            mount.display(),
            requested_bytes,
            urgency,
            output.status,
            stderr.trim()
        )));
    }

    Ok(LocalSnapshotThinReport {
        mount_path: mount.to_path_buf(),
        requested_bytes,
        urgency,
        stdout,
        stderr,
    })
}

#[must_use]
pub fn tmutil_thinlocalsnapshots_args(
    mount: &Path,
    requested_bytes: u64,
    urgency: u8,
) -> Vec<OsString> {
    vec![
        OsString::from("thinlocalsnapshots"),
        mount.as_os_str().to_os_string(),
        OsString::from(requested_bytes.to_string()),
        OsString::from(urgency.to_string()),
    ]
}

pub fn important_usage_available_bytes(mount: &Path) -> io::Result<Option<u64>> {
    use objc2_foundation::{NSArray, NSNumber, NSString, NSURL};

    let path = NSString::from_str(&mount.to_string_lossy());
    let url = NSURL::fileURLWithPath(&path);
    let key = NSString::from_str(IMPORTANT_USAGE_AVAILABLE_KEY);
    let keys = NSArray::from_slice(&[&*key]);
    let values = url
        .resourceValuesForKeys_error(&keys)
        .map_err(|_| io::Error::other("NSURL resourceValuesForKeys failed"))?;
    let Some(value) = values.objectForKey(&key) else {
        return Ok(None);
    };
    let Some(number) = value.downcast_ref::<NSNumber>() else {
        return Ok(None);
    };

    Ok(Some(number.unsignedLongLongValue()))
}

pub fn vm_swapusage() -> io::Result<SwapUsage> {
    sysctl::read::<String>("vm.swapusage").map(|raw| parse_vm_swapusage(&raw))
}

pub fn read_vm_stats() -> io::Result<VmStats> {
    sbh_mach::host_vm_stats()
        .map(|stats| VmStats {
            page_size_bytes: stats.page_size_bytes,
            free_count: stats.free_count,
            active_count: stats.active_count,
            inactive_count: stats.inactive_count,
            wire_count: stats.wire_count,
            speculative_count: stats.speculative_count,
            compressor_page_count: stats.compressor_page_count,
            throttled_count: stats.throttled_count,
        })
        .map_err(mach_error)
}

pub fn current_mach_task_usage() -> io::Result<MachTaskUsage> {
    sbh_mach::current_task_usage()
        .map(|usage| MachTaskUsage {
            rss_bytes: usage.rss_bytes,
            virtual_memory_bytes: usage.virtual_memory_bytes,
            cpu_user_micros: usage.cpu_user_micros,
            cpu_system_micros: usage.cpu_system_micros,
        })
        .map_err(mach_error)
}

pub fn current_mach_thread_basic_info() -> io::Result<MachThreadBasicInfo> {
    sbh_mach::current_thread_basic_info()
        .map(|info| MachThreadBasicInfo {
            user_time_micros: info.user_time_micros,
            system_time_micros: info.system_time_micros,
            cpu_usage_scaled: info.cpu_usage_scaled,
            run_state: info.run_state,
            flags: info.flags,
        })
        .map_err(mach_error)
}

pub fn firmlink_map() -> io::Result<FirmlinkMap> {
    firmlink_map_from_paths(
        Path::new("/usr/share/firmlinks"),
        Path::new("/etc/synthetic.conf"),
    )
}

pub fn firmlink_map_from_paths(
    firmlinks_path: &Path,
    synthetic_conf_path: &Path,
) -> io::Result<FirmlinkMap> {
    let firmlinks = fs::read_to_string(firmlinks_path)?;
    let synthetic_conf = match fs::read_to_string(synthetic_conf_path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error),
    };
    Ok(parse_firmlink_map(&firmlinks, &synthetic_conf))
}

pub fn resolve_firmlinked_path(path: &Path) -> io::Result<PathBuf> {
    firmlink_map().map(|map| map.resolve(path))
}

#[must_use]
pub fn parse_firmlink_map(firmlinks: &str, synthetic_conf: &str) -> FirmlinkMap {
    let mut mappings: Vec<FirmlinkMapping> = parse_system_firmlinks(firmlinks)
        .chain(parse_synthetic_conf(synthetic_conf))
        .collect();
    mappings.sort_by(|left, right| {
        right
            .visible_path
            .as_os_str()
            .len()
            .cmp(&left.visible_path.as_os_str().len())
            .then_with(|| left.visible_path.cmp(&right.visible_path))
    });
    mappings.dedup_by(|left, right| {
        left.visible_path == right.visible_path
            && left.data_path == right.data_path
            && left.source == right.source
    });
    FirmlinkMap { mappings }
}

#[must_use]
pub fn parse_vm_swapusage(raw: &str) -> SwapUsage {
    let Some(total_bytes) = labeled_byte_count(raw, "total") else {
        return SwapUsage::Unknown;
    };
    let Some(used_bytes) = labeled_byte_count(raw, "used") else {
        return SwapUsage::Unknown;
    };
    let Some(free_bytes) = labeled_byte_count(raw, "free") else {
        return SwapUsage::Unknown;
    };

    SwapUsage::Known(SwapUsageInfo {
        total_bytes,
        used_bytes,
        free_bytes,
        encrypted: raw.contains("(encrypted)"),
    })
}

pub fn parse_vm_stat(raw: &str) -> io::Result<VmStats> {
    let mut values = BTreeMap::<String, u64>::new();
    let mut page_size_bytes = None;

    for line in raw.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if page_size_bytes.is_none() {
            page_size_bytes = parse_vm_stat_page_size(line);
        }

        let Some((label, value_raw)) = line.split_once(':') else {
            continue;
        };
        let Some(value) = parse_vm_stat_count(value_raw) else {
            continue;
        };
        values.insert(vm_stat_label_key(label), value);
    }

    let page_size_bytes = page_size_bytes.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "vm_stat output did not include a page size",
        )
    })?;
    let required = |label: &str| {
        values.get(label).copied().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("vm_stat output missing required field: {label}"),
            )
        })
    };

    Ok(VmStats {
        page_size_bytes,
        free_count: required("pages free")?,
        active_count: required("pages active")?,
        inactive_count: required("pages inactive")?,
        wire_count: required("pages wired down")?,
        speculative_count: required("pages speculative")?,
        compressor_page_count: required("pages occupied by compressor")?,
        throttled_count: required("pages throttled")?,
    })
}

fn parse_vm_stat_page_size(line: &str) -> Option<u64> {
    let (_, after_prefix) = line.split_once("page size of ")?;
    let (size, _) = after_prefix.split_once(" bytes")?;
    size.trim().parse().ok()
}

fn parse_vm_stat_count(value_raw: &str) -> Option<u64> {
    let token = value_raw
        .split_whitespace()
        .next()?
        .trim_end_matches('.')
        .replace(',', "");
    token.parse().ok()
}

fn vm_stat_label_key(label: &str) -> String {
    label
        .trim()
        .trim_matches('"')
        .to_ascii_lowercase()
        .replace('\t', " ")
}

fn parse_system_firmlinks(firmlinks: &str) -> impl Iterator<Item = FirmlinkMapping> + '_ {
    firmlinks.lines().filter_map(|line| {
        let mut fields = config_fields(line);
        let visible = fields.next()?;
        let target = fields.next()?;
        let visible_path = absolute_root_path(visible);
        let data_path = firmlink_target_path(target);
        Some(FirmlinkMapping {
            visible_path,
            data_path,
            source: FirmlinkSource::SystemFirmlink,
        })
    })
}

fn parse_synthetic_conf(synthetic_conf: &str) -> impl Iterator<Item = FirmlinkMapping> + '_ {
    synthetic_conf.lines().filter_map(|line| {
        let mut fields = config_fields(line);
        let visible = fields.next()?;
        let target = fields.next()?;
        Some(FirmlinkMapping {
            visible_path: absolute_root_path(visible),
            data_path: absolute_root_path(target),
            source: FirmlinkSource::SyntheticConfig,
        })
    })
}

fn config_fields(line: &str) -> impl Iterator<Item = &str> {
    line.split('#')
        .next()
        .unwrap_or_default()
        .split_whitespace()
}

fn absolute_root_path(path: &str) -> PathBuf {
    let path = path.trim();
    if path.starts_with('/') {
        PathBuf::from(path)
    } else {
        Path::new("/").join(path)
    }
}

fn firmlink_target_path(target: &str) -> PathBuf {
    let target = target.trim();
    if target.starts_with('/') {
        PathBuf::from(target)
    } else {
        Path::new(FIRMLINK_DATA_ROOT).join(target)
    }
}

fn resolve_with_mapping(path: &Path, mapping: &FirmlinkMapping) -> Option<PathBuf> {
    let suffix = path.strip_prefix(&mapping.visible_path).ok()?;
    Some(if suffix.as_os_str().is_empty() {
        mapping.data_path.clone()
    } else {
        mapping.data_path.join(suffix)
    })
}

pub mod sysctl {
    use std::io;

    use ::sysctl::{Ctl, CtlType, CtlValue, Sysctl};

    pub trait ReadableValue: Sized {
        fn read_type() -> (CtlType, &'static str);
        fn from_ctl_value(name: &str, value: CtlValue) -> io::Result<Self>;
    }

    pub fn read<T: ReadableValue>(name: &str) -> io::Result<T> {
        let (mut ctl_type, mut format) = T::read_type();
        if name == "vm.swapusage" && ctl_type == CtlType::String {
            ctl_type = CtlType::Struct;
            format = "";
        }
        let ctl = Ctl::new_with_type(name, ctl_type, format)
            .map_err(|error| sysctl_error(name, &error))?;
        let value = ctl.value().map_err(|error| sysctl_error(name, &error))?;
        T::from_ctl_value(name, value)
    }

    pub fn read_mib<T: ReadableValue>(mib: &[libc::c_int]) -> io::Result<T> {
        if mib.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sysctl MIB must not be empty",
            ));
        }

        let label = format!("MIB {mib:?}");
        let ctl = Ctl::Oid(mib.to_vec());
        let value = ctl.value().map_err(|error| sysctl_error(&label, &error))?;
        T::from_ctl_value(&label, value)
    }

    impl ReadableValue for i32 {
        fn read_type() -> (CtlType, &'static str) {
            (CtlType::Int, "I")
        }

        fn from_ctl_value(name: &str, value: CtlValue) -> io::Result<Self> {
            match value {
                CtlValue::Int(value) | CtlValue::S32(value) => Ok(value),
                CtlValue::Uint(value) | CtlValue::U32(value) => Self::try_from(value)
                    .map_err(|_| sysctl_type_error(name, "i32", "unsigned value exceeds i32")),
                other => Err(sysctl_type_error(
                    name,
                    "i32",
                    &format!("got {}", ctl_value_label(&other)),
                )),
            }
        }
    }

    impl ReadableValue for u64 {
        fn read_type() -> (CtlType, &'static str) {
            (CtlType::Int, "LU")
        }

        fn from_ctl_value(name: &str, value: CtlValue) -> io::Result<Self> {
            match value {
                CtlValue::U64(value) | CtlValue::Ulong(value) => Ok(value),
                CtlValue::Uint(value) | CtlValue::U32(value) => Ok(Self::from(value)),
                CtlValue::Int(value) | CtlValue::S32(value) if value >= 0 => Self::try_from(value)
                    .map_err(|_| sysctl_type_error(name, "u64", "signed value is negative")),
                CtlValue::Long(value) | CtlValue::S64(value) if value >= 0 => Self::try_from(value)
                    .map_err(|_| sysctl_type_error(name, "u64", "signed value is negative")),
                other => Err(sysctl_type_error(
                    name,
                    "u64",
                    &format!("got {}", ctl_value_label(&other)),
                )),
            }
        }
    }

    impl ReadableValue for String {
        fn read_type() -> (CtlType, &'static str) {
            (CtlType::String, "")
        }

        fn from_ctl_value(name: &str, value: CtlValue) -> io::Result<Self> {
            match value {
                CtlValue::String(value) => Ok(value),
                CtlValue::Struct(value) if name == "vm.swapusage" => {
                    format_swapusage_struct(&value)
                }
                other => Err(sysctl_type_error(
                    name,
                    "String",
                    &format!("got {}", ctl_value_label(&other)),
                )),
            }
        }
    }

    impl ReadableValue for Vec<u8> {
        fn read_type() -> (CtlType, &'static str) {
            (CtlType::Struct, "")
        }

        fn from_ctl_value(name: &str, value: CtlValue) -> io::Result<Self> {
            match value {
                CtlValue::Struct(value) | CtlValue::Node(value) => Ok(value),
                other => Err(sysctl_type_error(
                    name,
                    "raw bytes",
                    &format!("got {}", ctl_value_label(&other)),
                )),
            }
        }
    }

    fn format_swapusage_struct(raw: &[u8]) -> io::Result<String> {
        let total = native_u64(raw.get(0..8))
            .ok_or_else(|| malformed_struct_error("vm.swapusage", "missing total bytes"))?;
        let free = native_u64(raw.get(8..16))
            .ok_or_else(|| malformed_struct_error("vm.swapusage", "missing free bytes"))?;
        let used = native_u64(raw.get(16..24))
            .ok_or_else(|| malformed_struct_error("vm.swapusage", "missing used bytes"))?;
        let encrypted = native_u32(raw.get(28..32))
            .ok_or_else(|| malformed_struct_error("vm.swapusage", "missing encryption flag"))?
            != 0;
        let encrypted_label = if encrypted { "  (encrypted)" } else { "" };

        Ok(format!(
            "total = {}M  used = {}M  free = {}M{encrypted_label}",
            bytes_to_mib_decimal(total),
            bytes_to_mib_decimal(used),
            bytes_to_mib_decimal(free)
        ))
    }

    fn native_u64(bytes: Option<&[u8]>) -> Option<u64> {
        bytes
            .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
            .map(u64::from_ne_bytes)
    }

    fn native_u32(bytes: Option<&[u8]>) -> Option<u32> {
        bytes
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map(u32::from_ne_bytes)
    }

    fn bytes_to_mib_decimal(bytes: u64) -> String {
        let centimib = u128::from(bytes).saturating_mul(100) / 1_048_576;
        format!("{}.{:02}", centimib / 100, centimib % 100)
    }

    fn malformed_struct_error(name: &str, detail: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("sysctl {name} returned malformed struct: {detail}"),
        )
    }

    fn sysctl_error(name: &str, error: &::sysctl::SysctlError) -> io::Error {
        io::Error::other(format!("sysctl {name} failed: {error}"))
    }

    fn sysctl_type_error(name: &str, expected: &str, detail: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("sysctl {name} did not return {expected}: {detail}"),
        )
    }

    fn ctl_value_label(value: &CtlValue) -> &'static str {
        match value {
            CtlValue::None => "none",
            CtlValue::Node(_) => "node",
            CtlValue::Int(_) | CtlValue::S32(_) => "i32",
            CtlValue::String(_) => "string",
            CtlValue::S64(_) => "i64",
            CtlValue::Struct(_) => "struct",
            CtlValue::Uint(_) | CtlValue::U32(_) => "u32",
            CtlValue::Long(_) => "long",
            CtlValue::Ulong(_) => "ulong",
            CtlValue::U64(_) => "u64",
            CtlValue::U8(_) => "u8",
            CtlValue::U16(_) => "u16",
            CtlValue::S8(_) => "i8",
            CtlValue::S16(_) => "i16",
        }
    }
}

fn labeled_byte_count(raw: &str, label: &str) -> Option<u64> {
    let (_, after_label) = raw.split_once(label)?;
    let after_equals = after_label.trim_start().strip_prefix('=')?;
    let token = after_equals.split_whitespace().next()?;
    parse_size_token(token)
}

fn parse_size_token(token: &str) -> Option<u64> {
    let token = token.trim().trim_end_matches(',');
    if token.is_empty() {
        return None;
    }
    let (number, multiplier) = match token.as_bytes().last().copied()? {
        b'K' | b'k' => (&token[..token.len() - 1], 1024_u128),
        b'M' | b'm' => (&token[..token.len() - 1], 1_048_576_u128),
        b'G' | b'g' => (&token[..token.len() - 1], 1_073_741_824_u128),
        b'T' | b't' => (&token[..token.len() - 1], 1_099_511_627_776_u128),
        b'B' | b'b' => (&token[..token.len() - 1], 1_u128),
        candidate if candidate.is_ascii_digit() => (token, 1_u128),
        _ => return None,
    };
    decimal_to_units(number, multiplier)
}

fn decimal_to_units(number: &str, multiplier: u128) -> Option<u64> {
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    if whole.is_empty() || !whole.chars().all(|candidate| candidate.is_ascii_digit()) {
        return None;
    }
    if !fraction.chars().all(|candidate| candidate.is_ascii_digit()) {
        return None;
    }

    let whole_units = whole.parse::<u128>().ok()?.checked_mul(multiplier)?;
    let fraction_units = if fraction.is_empty() {
        0
    } else {
        let scale = 10_u128.checked_pow(u32::try_from(fraction.len()).ok()?)?;
        fraction.parse::<u128>().ok()?.checked_mul(multiplier)? / scale
    };
    u64::try_from(whole_units.checked_add(fraction_units)?).ok()
}

#[must_use]
pub fn parse_tmutil_local_snapshots(
    raw: &str,
    mount_path: &Path,
    retained_total_estimate: Option<u64>,
) -> Vec<LocalSnapshotInfo> {
    let names: Vec<String> = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("Snapshots for disk "))
        .filter(|line| line.starts_with("com.apple.TimeMachine."))
        .map(ToOwned::to_owned)
        .collect();
    let estimates = distribute_snapshot_estimate(retained_total_estimate, names.len());
    names
        .into_iter()
        .enumerate()
        .map(|(index, name)| LocalSnapshotInfo {
            date: local_snapshot_date(&name),
            name,
            retained_bytes_estimate: estimates.get(index).copied().flatten(),
            mount_path: mount_path.to_path_buf(),
        })
        .collect()
}

pub fn parse_apfs_inventory(raw: &[u8]) -> io::Result<ApfsInventory> {
    let value = Value::from_reader(Cursor::new(raw)).map_err(io::Error::other)?;
    let root = value.as_dictionary().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "APFS plist root is not a dictionary",
        )
    })?;
    let containers = root
        .get("Containers")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "APFS plist has no Containers array",
            )
        })?;

    let mut parsed_containers = Vec::new();
    let mut parsed_volumes = Vec::new();
    for container_value in containers {
        let container = container_value.as_dictionary().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "APFS container is not a dictionary",
            )
        })?;
        let container_id = required_device_id(container, "ContainerReference")?;
        let capacity_total_bytes = optional_u64(container, "CapacityCeiling");
        let capacity_available_bytes = optional_u64(container, "CapacityFree");
        let physical_stores = container
            .get("PhysicalStores")
            .and_then(Value::as_array)
            .map(|stores| {
                stores
                    .iter()
                    .filter_map(Value::as_dictionary)
                    .filter_map(|store| optional_device_id(store, "DeviceIdentifier"))
                    .collect()
            })
            .unwrap_or_default();

        parsed_containers.push(ApfsContainer {
            container_id: container_id.clone(),
            uuid: optional_string(container, "APFSContainerUUID"),
            capacity_total_bytes,
            capacity_available_bytes,
            physical_stores,
        });

        if let Some(volumes) = container.get("Volumes").and_then(Value::as_array) {
            for volume_value in volumes {
                let volume = volume_value.as_dictionary().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "APFS volume is not a dictionary",
                    )
                })?;
                let device_id = required_device_id(volume, "DeviceIdentifier")?;
                let roles = volume_roles(volume);
                parsed_volumes.push(ApfsVolume {
                    device_id,
                    container_id: container_id.clone(),
                    name: optional_string(volume, "Name"),
                    roles,
                    capacity_in_use_bytes: optional_u64(volume, "CapacityInUse"),
                    container_total_bytes: capacity_total_bytes,
                    container_available_bytes: capacity_available_bytes,
                });
            }
        }
    }

    Ok(ApfsInventory {
        containers: parsed_containers,
        volumes: parsed_volumes,
    })
}

fn statfs_for_mount(mount_point: &Path, device: &OsStr) -> io::Result<StatfsSnapshot> {
    let raw = nix_statfs(mount_point).map_err(nix_error)?;
    Ok(snapshot_from_statfs(
        &raw,
        mount_point.to_path_buf(),
        os_str_to_string(device),
    ))
}

fn snapshot_from_statfs(raw: &Statfs, mount_point: PathBuf, device: String) -> StatfsSnapshot {
    StatfsSnapshot {
        mount_point,
        device,
        fs_type: raw.filesystem_type_name().to_string(),
        block_size: u64::from(raw.block_size()),
        blocks: raw.blocks(),
        blocks_free: raw.blocks_free(),
        blocks_available: raw.blocks_available(),
        is_readonly: raw.flags().contains(MntFlags::MNT_RDONLY),
    }
}

fn os_str_to_string(value: &OsStr) -> String {
    value.to_string_lossy().into_owned()
}

fn nix_error(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

fn mach_error(error: sbh_mach::MachError) -> io::Error {
    io::Error::other(error)
}

fn required_device_id(dict: &plist::Dictionary, key: &'static str) -> io::Result<String> {
    optional_device_id(dict, key).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("APFS plist entry missing {key}"),
        )
    })
}

fn optional_device_id(dict: &plist::Dictionary, key: &str) -> Option<String> {
    optional_string(dict, key).map(|device_id| with_dev_prefix(&device_id))
}

fn optional_string(dict: &plist::Dictionary, key: &str) -> Option<String> {
    dict.get(key)
        .and_then(Value::as_string)
        .map(ToOwned::to_owned)
}

fn optional_u64(dict: &plist::Dictionary, key: &str) -> Option<u64> {
    dict.get(key).and_then(Value::as_unsigned_integer)
}

fn distribute_snapshot_estimate(total: Option<u64>, count: usize) -> Vec<Option<u64>> {
    let Some(total) = total else {
        return vec![None; count];
    };
    if count == 0 {
        return Vec::new();
    }
    let count_u64 = u64::try_from(count).unwrap_or(u64::MAX);
    let per_snapshot = total / count_u64;
    let mut remainder = total % count_u64;
    (0..count)
        .map(|_| {
            let extra = u64::from(remainder > 0);
            remainder = remainder.saturating_sub(extra);
            Some(per_snapshot.saturating_add(extra))
        })
        .collect()
}

fn local_snapshot_date(name: &str) -> Option<String> {
    let suffix = name.strip_prefix("com.apple.TimeMachine.")?;
    let timestamp = suffix.strip_suffix(".local").unwrap_or(suffix);
    if timestamp.len() >= "YYYY-MM-DD-HHMMSS".len()
        && timestamp
            .chars()
            .take("YYYY-MM-DD-HHMMSS".len())
            .all(|candidate| candidate.is_ascii_digit() || candidate == '-')
    {
        Some(timestamp[.."YYYY-MM-DD-HHMMSS".len()].to_string())
    } else {
        None
    }
}

fn volume_roles(dict: &plist::Dictionary) -> Vec<ApfsVolumeRole> {
    let mut roles: Vec<ApfsVolumeRole> = dict
        .get("Roles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_string)
        .map(ApfsVolumeRole::from)
        .collect();
    roles.sort();
    roles.dedup();
    roles
}

fn normalize_device_id(device_id: &str) -> String {
    with_dev_prefix(device_id.trim())
}

fn with_dev_prefix(device_id: &str) -> String {
    if device_id.starts_with("/dev/") {
        device_id.to_string()
    } else {
        format!("/dev/{device_id}")
    }
}

fn parent_apfs_volume_device(device_id: &str) -> Option<String> {
    let device_name = device_id.rsplit('/').next().unwrap_or(device_id);
    let after_disk = device_name.strip_prefix("disk")?;
    let disk_number_len = after_disk.find('s')?;
    if disk_number_len == 0
        || !after_disk[..disk_number_len]
            .chars()
            .all(|candidate| candidate.is_ascii_digit())
        || after_disk.matches('s').count() < 2
    {
        return None;
    }

    let suffix_start = device_id.rfind('s')?;
    Some(device_id[..suffix_start].to_string())
}

impl From<&str> for ApfsVolumeRole {
    fn from(value: &str) -> Self {
        match value {
            "Data" => Self::Data,
            "System" => Self::System,
            "Preboot" => Self::Preboot,
            "VM" => Self::Vm,
            "Update" => Self::Update,
            "Recovery" => Self::Recovery,
            other => Self::Other(other.to_string()),
        }
    }
}

impl Ord for ApfsVolumeRole {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.sort_key()
            .cmp(&other.sort_key())
            .then_with(|| match (self, other) {
                (Self::Other(left), Self::Other(right)) => left.cmp(right),
                _ => std::cmp::Ordering::Equal,
            })
    }
}

impl PartialOrd for ApfsVolumeRole {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl ApfsVolumeRole {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Data => "Data",
            Self::System => "System",
            Self::Preboot => "Preboot",
            Self::Vm => "VM",
            Self::Update => "Update",
            Self::Recovery => "Recovery",
            Self::Other(value) => value,
        }
    }

    fn sort_key(&self) -> u8 {
        match self {
            Self::System => 0,
            Self::Data => 1,
            Self::Preboot => 2,
            Self::Vm => 3,
            Self::Update => 4,
            Self::Recovery => 5,
            Self::Other(_) => 6,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::Path;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use super::{
        ApfsVolumeRole, FirmlinkSource, LOCAL_SNAPSHOT_THIN_AMOUNT_BYTES,
        LOCAL_SNAPSHOT_THIN_URGENCY, SwapUsage, SwapUsageInfo, command_output_with_timeout,
        command_output_with_timeout_inner, firmlink_map, firmlink_map_from_paths,
        important_usage_available_bytes, mounted_filesystems, parent_apfs_volume_device,
        parse_apfs_inventory, parse_firmlink_map, parse_tmutil_local_snapshots, parse_vm_stat,
        parse_vm_swapusage, read_vm_stats, resolve_firmlinked_path, statfs, sysctl,
        tmutil_thinlocalsnapshots_args, vm_swapusage,
    };

    const fn mib(value: u64) -> u64 {
        value * 1_048_576
    }

    const fn gib(value: u64) -> u64 {
        value * 1_073_741_824
    }

    const fn tib(value: u64) -> u64 {
        value * 1_099_511_627_776
    }

    #[test]
    fn command_output_with_timeout_captures_fast_command() {
        let mut command = Command::new("/bin/echo");
        command.arg("sbh-ok");

        let output = command_output_with_timeout(&mut command, Duration::from_secs(1))
            .expect("echo should execute")
            .expect("echo should complete before timeout");

        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout), "sbh-ok\n");
    }

    #[test]
    fn command_output_with_timeout_kills_slow_command() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 2"]);

        let output = command_output_with_timeout(&mut command, Duration::from_millis(50))
            .expect("sleep should spawn and be killed cleanly");

        assert!(output.is_none());
    }

    /// A timed-out child must never be left unreaped.
    ///
    /// The daemon calls this helper on a schedule for `mount`/`diskutil`/
    /// `tmutil`. Before the fix, every timeout whose child outlived the 250ms
    /// post-kill reap window leaked a zombie permanently, because
    /// `Child::drop` does not wait. Two days of that produced ~400 zombies
    /// parented to one `sbh daemon`.
    ///
    /// A zero-attempt kill budget forces the slow path every time, which is the
    /// branch that used to `drop` an unreaped `Child`. Reverting the fix to
    /// `drop(child)` makes this test fail with a lingering zombie.
    #[test]
    fn command_output_with_timeout_reaps_child_that_outlives_kill_window() {
        let baseline = zombie_children_of_self();

        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 5"]);

        let output = command_output_with_timeout_inner(&mut command, Duration::from_millis(50), 0)
            .expect("child should spawn and time out cleanly");
        assert!(output.is_none(), "a timed-out command yields no output");

        // The detached reaper runs concurrently, so allow it a moment to land.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if zombie_children_of_self() <= baseline {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }

        panic!(
            "timed-out child left unreaped: {} zombie(s), baseline {baseline}",
            zombie_children_of_self()
        );
    }

    /// Count zombie processes whose parent is this test process.
    ///
    /// Deliberately panics rather than returning 0 if `ps` cannot run: a count
    /// of zero is the assertion's success value, so a failed measurement would
    /// otherwise make the test pass without having measured anything.
    fn zombie_children_of_self() -> usize {
        let ppid = std::process::id().to_string();
        let output = Command::new("/bin/ps")
            .args(["-Ao", "ppid=,stat="])
            .output()
            .expect("ps must run for this test to mean anything");
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
                let mut parts = line.split_whitespace();
                let parent = parts.next()?;
                let stat = parts.next()?;
                (parent == ppid && stat.starts_with('Z')).then_some(())
            })
            .count()
    }

    #[test]
    fn command_output_with_timeout_rejects_inherited_pipe_after_exit() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 2 & echo sbh-ok"]);

        let started_at = Instant::now();
        let output = command_output_with_timeout(&mut command, Duration::from_secs(1))
            .expect("shell should spawn cleanly");

        assert!(output.is_none());
        assert!(started_at.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn statfs_tmp_reports_plausible_values() {
        let stats = statfs(Path::new("/tmp")).expect("/tmp statfs should work on macOS");
        assert_eq!(stats.block_size, 4096);
        assert!(stats.blocks > 0);
        assert!(stats.blocks_available > 0);
        assert!(stats.total_bytes() > stats.available_bytes());
        assert!(!stats.fs_type.is_empty());
        assert!(stats.mount_point.is_absolute());
    }

    #[test]
    fn mounted_filesystems_include_root() {
        let mounts = mounted_filesystems().expect("mounted filesystems should be discoverable");
        assert!(!mounts.is_empty());
        assert!(
            mounts
                .iter()
                .any(|mount| mount.mount_point == Path::new("/"))
        );
    }

    #[test]
    fn mounted_filesystems_include_data_volume_when_present() {
        let data_volume = Path::new("/System/Volumes/Data");
        if !data_volume.exists() {
            return;
        }

        let mounts = mounted_filesystems().expect("mounted filesystems should be discoverable");
        assert!(mounts.iter().any(|mount| mount.mount_point == data_volume));
    }

    #[test]
    fn parses_mount_command_output_with_nobrowse_apfs_and_automount_override() {
        let raw = "\
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
/dev/disk3s5 on /System/Volumes/Data (apfs, local, journaled, nobrowse, protect, root data)
map -static on /Volumes/trj-data (autofs, automounted, nobrowse)
10.10.10.1:/data on /Volumes/trj-data (nfs, nodev, nosuid, automounted, nobrowse)
";

        let entries = super::parse_mount_command_output(raw);

        assert!(entries.iter().any(|entry| {
            entry.device == "/dev/disk3s5"
                && entry.mount_point == Path::new("/System/Volumes/Data")
                && entry.is_local
        }));
        assert!(entries.iter().any(|entry| {
            entry.device == "10.10.10.1:/data"
                && entry.mount_point == Path::new("/Volumes/trj-data")
                && !entry.is_local
        }));
        assert!(!entries.iter().any(|entry| entry.device == "map -static"
            && entry.mount_point == Path::new("/Volumes/trj-data")));
    }

    #[test]
    #[ignore = "Foundation CacheDelete capacity queries can block on unhealthy automounts"]
    fn important_usage_available_capacity_reports_for_root_volume() {
        let capacity = important_usage_available_bytes(Path::new("/"))
            .expect("Foundation should report root capacity");

        assert!(capacity.is_some_and(|bytes| bytes > 0));
    }

    #[test]
    fn sysctl_by_name_reads_plausible_hw_values() {
        let memsize = sysctl::read::<u64>("hw.memsize").expect("hw.memsize should be readable");
        let physical_cpus =
            sysctl::read::<i32>("hw.physicalcpu").expect("hw.physicalcpu should be readable");

        assert!(memsize >= 1_073_741_824);
        assert!((1..=1024).contains(&physical_cpus));
    }

    #[test]
    fn sysctl_by_name_reads_swapusage_string() {
        let swapusage =
            sysctl::read::<String>("vm.swapusage").expect("vm.swapusage should be readable");

        assert!(swapusage.contains("total = "));
        assert!(swapusage.contains("used = "));
        assert!(swapusage.contains("free = "));
    }

    #[test]
    fn sysctl_mib_reads_hw_memsize() {
        let memsize = sysctl::read_mib::<u64>(&[libc::CTL_HW, libc::HW_MEMSIZE])
            .expect("CTL_HW/HW_MEMSIZE should be readable");

        assert!(memsize >= 1_073_741_824);
    }

    #[test]
    fn parses_firmlink_and_synthetic_mappings() {
        let firmlinks = "\
/Users\tUsers
/System\tSystem
/System/Library/Caches\tSystem/Library/Caches
";
        let synthetic_conf = "\
# root-level synthetic links
dp\t/Users/jemanuel/projects
nix
relative-target\tVolumes/External
";

        let map = parse_firmlink_map(firmlinks, synthetic_conf);

        assert_eq!(
            map.resolve(Path::new("/Users/jemanuel")),
            Path::new("/System/Volumes/Data/Users/jemanuel")
        );
        assert_eq!(
            map.resolve(Path::new("/System/Library/Caches/com.apple")),
            Path::new("/System/Volumes/Data/System/Library/Caches/com.apple")
        );
        assert_eq!(
            map.resolve(Path::new("/dp/storage_ballast_helper")),
            Path::new("/Users/jemanuel/projects/storage_ballast_helper")
        );
        assert_eq!(
            map.resolve(Path::new("/relative-target/cache")),
            Path::new("/Volumes/External/cache")
        );
        assert_eq!(
            map.resolve(Path::new("/nix/store")),
            Path::new("/nix/store")
        );

        assert!(map.mappings.iter().any(|mapping| {
            mapping.visible_path == Path::new("/Users")
                && mapping.source == FirmlinkSource::SystemFirmlink
        }));
        assert!(map.mappings.iter().any(|mapping| {
            mapping.visible_path == Path::new("/dp")
                && mapping.source == FirmlinkSource::SyntheticConfig
        }));
    }

    #[test]
    fn firmlink_map_from_paths_reads_synthetic_fixture_files() {
        let temp_dir = tempfile::tempdir().expect("temp dir should be created");
        let firmlinks_path = temp_dir.path().join("firmlinks");
        let synthetic_path = temp_dir.path().join("synthetic.conf");
        std::fs::write(&firmlinks_path, "/Applications\tApplications\n")
            .expect("firmlink fixture should be writable");
        std::fs::write(&synthetic_path, "data\t/Volumes/Data\n")
            .expect("synthetic fixture should be writable");

        let map = firmlink_map_from_paths(&firmlinks_path, &synthetic_path)
            .expect("fixtures should parse");

        assert_eq!(
            map.resolve(Path::new("/Applications/Safari.app")),
            Path::new("/System/Volumes/Data/Applications/Safari.app")
        );
        assert_eq!(
            map.resolve(Path::new("/data/projects")),
            Path::new("/Volumes/Data/projects")
        );
    }

    #[test]
    fn live_firmlink_map_resolves_users_when_present() {
        let map = firmlink_map().expect("system firmlink table should be readable");
        let has_users = map
            .mappings
            .iter()
            .any(|mapping| mapping.visible_path == Path::new("/Users"));

        if has_users {
            assert_eq!(
                resolve_firmlinked_path(Path::new("/Users/jemanuel"))
                    .expect("firmlinked path should resolve"),
                Path::new("/System/Volumes/Data/Users/jemanuel")
            );
        }
    }

    #[test]
    fn live_vm_swapusage_parses_when_readable() {
        let usage = vm_swapusage().expect("vm.swapusage should be readable");

        let SwapUsage::Known(usage) = usage else {
            panic!("current macOS vm.swapusage output should parse");
        };
        assert!(usage.total_bytes >= usage.used_bytes);
        assert!(usage.total_bytes >= usage.free_bytes);
    }

    #[test]
    fn live_vm_stats_report_plausible_page_accounting() {
        let stats = read_vm_stats().expect("vm_stat should report Mach VM counters");
        let total_bytes = sysctl::read::<u64>("hw.memsize").expect("hw.memsize should be readable");
        let total_pages = total_bytes / stats.page_size_bytes;
        let accounted = stats.accounted_pages();
        let delta = accounted.abs_diff(total_pages);
        let tolerance = total_pages / 10;

        assert!(stats.page_size_bytes >= 4096);
        assert!(stats.free_count > 0);
        assert!(stats.active_count > 0);
        assert!(stats.inactive_count > 0);
        assert!(stats.wire_count > 0);
        assert!(
            delta <= tolerance,
            "accounted pages {accounted} should be within {tolerance} pages of total {total_pages}"
        );
    }

    #[test]
    fn current_mach_task_usage_reports_plausible_memory() {
        let usage = super::current_mach_task_usage().expect("Mach task usage should be readable");
        let total_bytes = sysctl::read::<u64>("hw.memsize").expect("hw.memsize should be readable");

        assert!(usage.rss_bytes > 1_048_576);
        assert!(usage.rss_bytes < total_bytes);
        assert!(usage.virtual_memory_bytes >= usage.rss_bytes);
    }

    #[test]
    fn current_mach_thread_basic_info_reports_run_state() {
        let info = super::current_mach_thread_basic_info()
            .expect("Mach current thread info should be readable");

        assert!((1..=5).contains(&info.run_state));
    }

    #[test]
    fn parses_vm_stat_output() {
        let raw = "\
Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                              965751.
Pages active:                            436024.
Pages inactive:                          601322.
Pages speculative:                       221523.
Pages throttled:                              0.
Pages wired down:                        699748.
Pages purgeable:                           1488.
\"Translation faults\":               44529996857.
Pages occupied by compressor:           1221199.
";

        let stats = parse_vm_stat(raw).expect("vm_stat output should parse");

        assert_eq!(stats.page_size_bytes, 16_384);
        assert_eq!(stats.free_count, 965_751);
        assert_eq!(stats.active_count, 436_024);
        assert_eq!(stats.inactive_count, 601_322);
        assert_eq!(stats.speculative_count, 221_523);
        assert_eq!(stats.throttled_count, 0);
        assert_eq!(stats.wire_count, 699_748);
        assert_eq!(stats.compressor_page_count, 1_221_199);
        assert_eq!(stats.accounted_pages(), 3_924_044);
    }

    #[test]
    fn vm_stat_parse_requires_page_size_and_core_counts() {
        assert!(parse_vm_stat("Pages free: 1.").is_err());
        assert!(
            parse_vm_stat(
                "Mach Virtual Memory Statistics: (page size of 4096 bytes)\nPages free: 1.\n"
            )
            .is_err()
        );
    }

    #[test]
    fn parses_vm_swapusage_string_variants() {
        let cases = [
            (
                "typical encrypted",
                "total = 8192.00M  used = 1234.50M  free = 6957.50M  (encrypted)",
                SwapUsageInfo {
                    total_bytes: mib(8192),
                    used_bytes: mib(1234) + mib(1) / 2,
                    free_bytes: mib(6957) + mib(1) / 2,
                    encrypted: true,
                },
            ),
            (
                "all zero",
                "total = 0.00M used = 0.00M free = 0.00M (encrypted)",
                SwapUsageInfo {
                    total_bytes: 0,
                    used_bytes: 0,
                    free_bytes: 0,
                    encrypted: true,
                },
            ),
            (
                "large tebibyte units",
                "total = 2.00T used = 512.00G free = 1536.00G",
                SwapUsageInfo {
                    total_bytes: tib(2),
                    used_bytes: gib(512),
                    free_bytes: gib(1536),
                    encrypted: false,
                },
            ),
            (
                "without encrypted suffix",
                "total = 4096.00M used = 128.00M free = 3968.00M",
                SwapUsageInfo {
                    total_bytes: mib(4096),
                    used_bytes: mib(128),
                    free_bytes: mib(3968),
                    encrypted: false,
                },
            ),
        ];

        for (name, raw, expected) in cases {
            assert_eq!(
                parse_vm_swapusage(raw),
                SwapUsage::Known(expected),
                "{name}"
            );
        }
    }

    #[test]
    fn vm_swapusage_parse_failure_is_unknown() {
        assert_eq!(parse_vm_swapusage("total unavailable"), SwapUsage::Unknown);
        assert_eq!(
            parse_vm_swapusage("total = nope used = 1.00M free = 2.00M"),
            SwapUsage::Unknown
        );
    }

    #[test]
    fn parses_diskutil_apfs_inventory() {
        let sample = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Containers</key>
  <array>
    <dict>
      <key>ContainerReference</key><string>disk3</string>
      <key>APFSContainerUUID</key><string>container-uuid</string>
      <key>CapacityCeiling</key><integer>1995218165760</integer>
      <key>CapacityFree</key><integer>667402285056</integer>
      <key>PhysicalStores</key>
      <array>
        <dict><key>DeviceIdentifier</key><string>disk0s2</string></dict>
      </array>
      <key>Volumes</key>
      <array>
        <dict>
          <key>DeviceIdentifier</key><string>disk3s1</string>
          <key>Name</key><string>Macintosh HD</string>
          <key>Roles</key><array><string>System</string></array>
          <key>CapacityInUse</key><integer>12269772800</integer>
        </dict>
        <dict>
          <key>DeviceIdentifier</key><string>disk3s5</string>
          <key>Name</key><string>Data</string>
          <key>Roles</key><array><string>Data</string></array>
          <key>CapacityInUse</key><integer>1290235314176</integer>
        </dict>
        <dict>
          <key>DeviceIdentifier</key><string>disk3s6</string>
          <key>Name</key><string>VM</string>
          <key>Roles</key><array><string>VM</string></array>
        </dict>
      </array>
    </dict>
  </array>
</dict>
</plist>"#;

        let inventory = parse_apfs_inventory(sample).expect("sample should parse");
        assert_eq!(inventory.containers.len(), 1);
        assert_eq!(inventory.volumes.len(), 3);

        let data = inventory
            .volume_for_device("/dev/disk3s5")
            .expect("data volume should be indexed");
        assert_eq!(data.container_id, "/dev/disk3");
        assert!(data.has_role(&ApfsVolumeRole::Data));
        assert_eq!(data.container_total_bytes, Some(1_995_218_165_760));
        assert_eq!(data.container_available_bytes, Some(667_402_285_056));

        let system_snapshot = inventory
            .volume_for_device("/dev/disk3s1s1")
            .expect("system snapshot should map to its parent volume");
        assert!(system_snapshot.has_role(&ApfsVolumeRole::System));
    }

    #[test]
    fn parent_apfs_volume_strips_snapshot_suffix() {
        assert_eq!(
            parent_apfs_volume_device("/dev/disk3s1s1").as_deref(),
            Some("/dev/disk3s1")
        );
        assert_eq!(parent_apfs_volume_device("/dev/disk3s1"), None);
    }

    #[test]
    fn parses_tmutil_local_snapshot_names_and_distributes_estimate() {
        let raw = "\
Snapshots for disk /:
com.apple.TimeMachine.2026-05-07-010203.local
com.apple.TimeMachine.2026-05-07-040506.local
";

        let snapshots = parse_tmutil_local_snapshots(raw, Path::new("/"), Some(101));

        assert_eq!(snapshots.len(), 2);
        assert_eq!(
            snapshots[0].name,
            "com.apple.TimeMachine.2026-05-07-010203.local"
        );
        assert_eq!(snapshots[0].date.as_deref(), Some("2026-05-07-010203"));
        assert_eq!(snapshots[0].retained_bytes_estimate, Some(51));
        assert_eq!(snapshots[1].retained_bytes_estimate, Some(50));
        assert_eq!(snapshots[0].mount_path, Path::new("/"));
    }

    #[test]
    fn tmutil_parser_ignores_header_and_non_time_machine_snapshots() {
        let raw = "\
Snapshots for disk /:
com.apple.os.update-abc
";

        let snapshots = parse_tmutil_local_snapshots(raw, Path::new("/"), Some(100));

        assert!(snapshots.is_empty());
    }

    #[test]
    fn thinlocalsnapshots_args_match_force_thin_contract() {
        let args = tmutil_thinlocalsnapshots_args(
            Path::new("/System/Volumes/Data"),
            LOCAL_SNAPSHOT_THIN_AMOUNT_BYTES,
            LOCAL_SNAPSHOT_THIN_URGENCY,
        );

        assert_eq!(
            args,
            vec![
                OsString::from("thinlocalsnapshots"),
                OsString::from("/System/Volumes/Data"),
                OsString::from("9999999999999999"),
                OsString::from("4"),
            ]
        );
    }
}
