//! PAL trait and platform-specific implementations (Linux, macOS, Windows).

#![allow(missing_docs)]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::core::config::PathsConfig;
use crate::core::errors::{Result, SbhError};

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

/// Service control surface (systemd, launchd, etc.).
pub trait ServiceManager: Send + Sync {
    fn install(&self) -> Result<()>;
    fn uninstall(&self) -> Result<()>;
    fn status(&self) -> Result<String>;
}

/// OS abstraction used by monitoring and daemon orchestration.
pub trait Platform: Send + Sync {
    fn fs_stats(&self, path: &Path) -> Result<FsStats>;
    fn mount_points(&self) -> Result<Vec<MountPoint>>;
    fn is_ram_backed(&self, path: &Path) -> Result<bool>;
    fn default_paths(&self) -> PlatformPaths;
    fn memory_info(&self) -> Result<MemoryInfo>;
    fn service_manager(&self) -> Box<dyn ServiceManager>;
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

/// Linux platform implementation using `/proc` + `statvfs`.
#[derive(Debug)]
pub struct LinuxPlatform {
    mounts_cache: RwLock<Option<(Vec<MountPoint>, Instant)>>,
    cache_ttl: Duration,
}

impl Default for LinuxPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxPlatform {
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

        let raw = fs::read_to_string("/proc/self/mounts").map_err(|source| SbhError::Io {
            path: PathBuf::from("/proc/self/mounts"),
            source,
        })?;
        let mounts = parse_proc_mounts(&raw);

        *self.mounts_cache.write() = Some((mounts.clone(), Instant::now()));
        Ok(mounts)
    }
}

impl Platform for LinuxPlatform {
    fn fs_stats(&self, path: &Path) -> Result<FsStats> {
        let mounts = self.mount_points()?;
        let mount = find_mount(path, &mounts).ok_or_else(|| SbhError::FsStats {
            path: path.to_path_buf(),
            details: "could not map path to mount point".to_string(),
        })?;
        let stat = nix::sys::statvfs::statvfs(path).map_err(|error| SbhError::FsStats {
            path: path.to_path_buf(),
            details: error.to_string(),
        })?;
        let fragment = stat.fragment_size();
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
        let Some(mount) = find_mount(path, &mounts) else {
            return Ok(false);
        };
        Ok(mount.is_ram_backed)
    }

    fn default_paths(&self) -> PlatformPaths {
        PlatformPaths::default()
    }

    fn memory_info(&self) -> Result<MemoryInfo> {
        let raw = fs::read_to_string("/proc/meminfo").map_err(|source| SbhError::Io {
            path: PathBuf::from("/proc/meminfo"),
            source,
        })?;
        parse_meminfo(&raw)
    }

    fn service_manager(&self) -> Box<dyn ServiceManager> {
        match crate::daemon::service::SystemdServiceManager::from_env(false) {
            Ok(mgr) => Box::new(mgr),
            Err(_) => Box::<NoopServiceManager>::default(),
        }
    }
}

/// In-memory mock implementation for deterministic tests.
#[derive(Debug, Clone)]
pub struct MockPlatform {
    mounts: Vec<MountPoint>,
    stats_by_mount: HashMap<PathBuf, FsStats>,
    memory: MemoryInfo,
    paths: PlatformPaths,
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
            mounts,
            stats_by_mount,
            memory,
            paths,
        }
    }
}

impl Platform for MockPlatform {
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
}

/// Detect active platform implementation.
pub fn detect_platform() -> Result<Arc<dyn Platform>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Arc::new(LinuxPlatform::new()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(SbhError::UnsupportedPlatform {
            details: "only Linux is currently implemented".to_string(),
        })
    }
}

fn parse_proc_mounts(raw: &str) -> Vec<MountPoint> {
    let mut mounts = Vec::new();
    for line in raw.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            // Skip malformed lines (pseudo-filesystems or kernel artifacts)
            // rather than failing the entire mount parse.
            eprintln!("[sbh] warning: skipping malformed /proc/self/mounts line: {line}");
            continue;
        }
        let mount_path = unescape_mount_field(fields[1]);
        let fs_type = fields[2].to_string();
        mounts.push(MountPoint {
            path: PathBuf::from(mount_path),
            device: fields[0].to_string(),
            is_ram_backed: is_ram_fs(&fs_type),
            fs_type,
        });
    }
    mounts.sort_by(|left, right| {
        right
            .path
            .as_os_str()
            .len()
            .cmp(&left.path.as_os_str().len())
    });
    mounts
}

fn parse_meminfo(raw: &str) -> Result<MemoryInfo> {
    let mut values = HashMap::<&str, u64>::new();
    for line in raw.lines() {
        let mut parts = line.split(':');
        let Some(key) = parts.next() else {
            continue;
        };
        let Some(rest) = parts.next() else {
            continue;
        };
        let mut tokens = rest.split_whitespace();
        let first_token = tokens.next().ok_or_else(|| SbhError::MountParse {
            details: format!("invalid /proc/meminfo line: {line}"),
        })?;
        let raw_value = first_token
            .parse::<u64>()
            .map_err(|error| SbhError::MountParse {
                details: format!("invalid meminfo value in line {line:?}: {error}"),
            })?;
        let multiplier = meminfo_unit_multiplier(tokens.next(), line)?;
        values.insert(key.trim(), raw_value.saturating_mul(multiplier));
    }

    Ok(MemoryInfo {
        total_bytes: *values.get("MemTotal").unwrap_or(&0),
        available_bytes: *values.get("MemAvailable").unwrap_or(&0),
        swap_total_bytes: *values.get("SwapTotal").unwrap_or(&0),
        swap_free_bytes: *values.get("SwapFree").unwrap_or(&0),
    })
}

fn meminfo_unit_multiplier(unit: Option<&str>, line: &str) -> Result<u64> {
    match unit {
        Some("kB" | "KB" | "KiB") => Ok(1024_u64),
        Some("mB" | "MB" | "MiB") => Ok(1024_u64 * 1024),
        Some("gB" | "GB" | "GiB") => Ok(1024_u64 * 1024 * 1024),
        None => Ok(1),
        Some(other) => Err(SbhError::MountParse {
            details: format!("unsupported meminfo unit in line {line:?}: {other}"),
        }),
    }
}

fn find_mount<'a>(path: &Path, mounts: &'a [MountPoint]) -> Option<&'a MountPoint> {
    mounts
        .iter()
        .filter(|mount| path.starts_with(&mount.path))
        .max_by_key(|mount| mount.path.as_os_str().len())
}

fn is_ram_fs(fs_type: &str) -> bool {
    matches!(fs_type, "tmpfs" | "ramfs" | "devtmpfs")
}

/// Decode octal escape sequences (`\NNN`) used by the Linux kernel in
/// `/proc/mounts` and `/etc/mtab` for special characters in paths.
fn unescape_mount_field(raw: &str) -> String {
    let mut result = String::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let a = bytes[i + 1];
            let b = bytes[i + 2];
            let c = bytes[i + 3];
            if (b'0'..=b'7').contains(&a)
                && (b'0'..=b'7').contains(&b)
                && (b'0'..=b'7').contains(&c)
            {
                let val = (a - b'0') * 64 + (b - b'0') * 8 + (c - b'0');
                result.push(char::from(val));
                i += 4;
                continue;
            }
        }
        result.push(char::from(bytes[i]));
        i += 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use crate::core::errors::SbhError;

    use super::{
        MountPoint, find_mount, is_ram_fs, parse_meminfo, parse_proc_mounts, unescape_mount_field,
    };
    use std::path::Path;

    #[test]
    fn parses_mount_table() {
        let sample = "/dev/sda1 / ext4 rw,relatime 0 0\n\
                      tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n";
        let mounts = parse_proc_mounts(sample);
        assert_eq!(mounts.len(), 2);
        assert!(mounts.iter().any(|entry| entry.path == Path::new("/tmp")));
        assert!(mounts.iter().any(|entry| entry.fs_type == "ext4"));
    }

    #[test]
    fn find_mount_prefers_longest_prefix() {
        let mounts = vec![
            MountPoint {
                path: "/".into(),
                device: "root".to_string(),
                fs_type: "ext4".to_string(),
                is_ram_backed: false,
            },
            MountPoint {
                path: "/tmp".into(),
                device: "tmpfs".to_string(),
                fs_type: "tmpfs".to_string(),
                is_ram_backed: true,
            },
        ];
        let mount = find_mount(Path::new("/tmp/work"), &mounts).expect("mount expected");
        assert_eq!(mount.path, Path::new("/tmp"));
    }

    #[test]
    fn parses_meminfo_with_kib_units() {
        let info = parse_meminfo(
            "MemTotal:       32768000 kB\n\
             MemAvailable:   16384000 kB\n\
             SwapTotal:       8192000 kB\n\
             SwapFree:        4096000 kB\n",
        )
        .expect("meminfo should parse");
        assert_eq!(info.total_bytes, 33_554_432_000);
        assert_eq!(info.available_bytes, 16_777_216_000);
        assert_eq!(info.swap_total_bytes, 8_388_608_000);
        assert_eq!(info.swap_free_bytes, 4_194_304_000);
    }

    #[test]
    fn parses_meminfo_without_unit_suffix() {
        let info = parse_meminfo(
            "MemTotal:       1024 kB\n\
             MemAvailable:   512 kB\n\
             SwapTotal:      0\n\
             SwapFree:       0\n",
        )
        .expect("meminfo should parse");
        assert_eq!(info.total_bytes, 1_048_576);
        assert_eq!(info.available_bytes, 524_288);
        assert_eq!(info.swap_total_bytes, 0);
        assert_eq!(info.swap_free_bytes, 0);
    }

    #[test]
    fn rejects_meminfo_with_unknown_unit_suffix() {
        let error = parse_meminfo(
            "MemTotal:       1024 blocks\n\
             MemAvailable:   512 kB\n\
             SwapTotal:      0 kB\n\
             SwapFree:       0 kB\n",
        )
        .expect_err("unknown unit suffix should fail");

        assert!(
            matches!(error, SbhError::MountParse { .. }),
            "expected mount-parse error, got: {error:?}"
        );
        assert!(
            error
                .to_string()
                .contains("unsupported meminfo unit in line"),
            "expected unsupported-unit context, got: {error}"
        );
    }

    #[test]
    fn ram_fs_detection_matches_expected_types() {
        assert!(is_ram_fs("tmpfs"));
        assert!(is_ram_fs("ramfs"));
        assert!(!is_ram_fs("ext4"));
    }

    #[test]
    fn unescape_mount_field_handles_all_octal_sequences() {
        // \040 = space, \011 = tab, \134 = backslash, \012 = newline
        assert_eq!(unescape_mount_field("/mnt/my\\040dir"), "/mnt/my dir");
        assert_eq!(unescape_mount_field("/mnt/a\\011b"), "/mnt/a\tb");
        assert_eq!(unescape_mount_field("/mnt/a\\134b"), "/mnt/a\\b");
        assert_eq!(unescape_mount_field("/mnt/a\\012b"), "/mnt/a\nb");
        // No escapes passes through.
        assert_eq!(unescape_mount_field("/mnt/simple"), "/mnt/simple");
        // Trailing backslash without enough digits passes through.
        assert_eq!(unescape_mount_field("/mnt/a\\04"), "/mnt/a\\04");
    }
}
