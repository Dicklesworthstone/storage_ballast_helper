//! Volumes that no scanner root covers.
//!
//! The daemon measures pressure only on the mounts of `scanner.root_paths`
//! (plus `/`). A volume nobody listed there was invisible: on css
//! (2026-10-23) TMPDIR and the build trees had moved to a ZFS pool that no
//! root covered, the pool's top-level quota reached zero, and sbh logged
//! nothing while 104 tasks blocked writing to it and sshd stopped answering.
//!
//! [`uncovered_mount_levels`] finds those volumes and classifies their free
//! space with the same thresholds the controllers use, so the daemon can
//! raise its ReclaimUnavailable alert for them. They only feed that alert:
//! they get no controller, never enter the worst-mount response and never
//! steer policy, so a data volume that is full by design cannot push the
//! global level to Critical.

use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::core::config::PressureConfig;
use crate::monitor::pid::{PressureLevel, classify_level};
use crate::platform::pal::{FsStats, MountPoint};

/// How often the daemon re-enumerates mounts for this check. Not every tick:
/// 95328ba removed a per-tick statfs sweep of every mount.
pub const UNCOVERED_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Volumes smaller than this are not worth an alert.
pub const UNCOVERED_MIN_TOTAL_BYTES: u64 = 1 << 30;

/// At most this many volumes are measured per refresh.
pub const UNCOVERED_MAX_MOUNTS: usize = 64;

/// Kernel pseudo filesystems, RAM-backed and image filesystems, and network
/// mounts: none of them holds local space this host can reclaim. FUSE types
/// (`fuse`, `fuseblk`, `fuse.*`) are excluded by prefix.
const NO_LOCAL_SPACE_FS_TYPES: &[&str] = &[
    "proc",
    "sysfs",
    "devtmpfs",
    "devpts",
    "devfs",
    "tmpfs",
    "ramfs",
    "cgroup",
    "cgroup2",
    "securityfs",
    "debugfs",
    "tracefs",
    "pstore",
    "bpf",
    "mqueue",
    "hugetlbfs",
    "configfs",
    "fusectl",
    "autofs",
    "binfmt_misc",
    "efivarfs",
    "nsfs",
    "rpc_pipefs",
    "selinuxfs",
    "squashfs",
    "iso9660",
    "overlay",
    "nfs",
    "nfs4",
    "cifs",
    "smb3",
    "smbfs",
    "9p",
    "virtiofs",
    "ceph",
    "glusterfs",
    "afs",
];

/// Whether `mount` can hold local data that fills up.
#[must_use]
pub fn watchable_mount(mount: &MountPoint) -> bool {
    !mount.is_ram_backed
        && !mount.fs_type.starts_with("fuse")
        && !NO_LOCAL_SPACE_FS_TYPES.contains(&mount.fs_type.as_str())
}

/// The pressure level of every watchable, writable volume of at least
/// [`UNCOVERED_MIN_TOTAL_BYTES`] whose mount is not in `monitored`, one entry
/// per device.
///
/// A device already monitored under another path (a bind mount of `/`, say)
/// is skipped, and so is a path whose statfs resolves to a different mount
/// point, which is that mount's reading, not this one's.
#[must_use]
pub fn uncovered_mount_levels<S: BuildHasher>(
    mounts: &[MountPoint],
    monitored: &HashSet<PathBuf, S>,
    stat: impl Fn(&Path) -> Option<FsStats>,
    pressure: &PressureConfig,
) -> HashMap<PathBuf, PressureLevel> {
    let mut seen_devices: HashSet<&str> = mounts
        .iter()
        .filter(|mount| monitored.contains(&mount.path))
        .map(|mount| mount.device.as_str())
        .collect();
    let mut levels = HashMap::new();
    for mount in mounts.iter().filter(|mount| watchable_mount(mount)) {
        if levels.len() >= UNCOVERED_MAX_MOUNTS {
            break;
        }
        if monitored.contains(&mount.path) || !seen_devices.insert(mount.device.as_str()) {
            continue;
        }
        let Some(stats) = stat(&mount.path) else {
            continue;
        };
        if stats.mount_point != mount.path
            || stats.is_readonly
            || stats.total_bytes < UNCOVERED_MIN_TOTAL_BYTES
        {
            continue;
        }
        let [green, yellow, orange, red] = pressure.free_pct_thresholds_for(stats.total_bytes);
        levels.insert(
            mount.path.clone(),
            classify_level(stats.free_pct(), green, yellow, orange, red),
        );
    }
    levels
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    fn mount(path: &str, device: &str, fs_type: &str) -> MountPoint {
        MountPoint {
            path: PathBuf::from(path),
            device: device.to_string(),
            fs_type: fs_type.to_string(),
            is_ram_backed: fs_type == "tmpfs" || fs_type == "ramfs",
        }
    }

    fn stats(mount_point: &str, total_gib: u64, available_gib: u64) -> FsStats {
        FsStats {
            total_bytes: total_gib * GIB,
            free_bytes: available_gib * GIB,
            available_bytes: available_gib * GIB,
            fs_type: "zfs".to_string(),
            mount_point: PathBuf::from(mount_point),
            is_readonly: false,
        }
    }

    /// The css layout on 2026-10-23: only `/` monitored, TMPDIR's ZFS
    /// dataset at zero available behind the pool's top-level quota.
    #[test]
    fn css_tmpdir_dataset_at_quota_is_reported_critical() {
        let mounts = vec![
            mount("/", "/dev/nvme0n1p4", "ext4"),
            mount("/proc", "proc", "proc"),
            mount("/dev/shm", "tmpfs", "tmpfs"),
            mount("/data/ssd", "buildpool", "zfs"),
            mount("/data/ssd/tmp", "buildpool/tmp", "zfs"),
            mount("/data/ssd/build", "buildpool/build", "zfs"),
            mount("/mnt/nas", "nas", "fuseblk"),
        ];
        let monitored: HashSet<PathBuf> = [PathBuf::from("/")].into();
        let stat = |path: &Path| match path.to_str()? {
            // The pool's own root dataset: 512 MiB, under the size floor.
            "/data/ssd" => Some(FsStats {
                total_bytes: GIB / 2,
                ..stats("/data/ssd", 0, 0)
            }),
            "/data/ssd/tmp" => Some(stats("/data/ssd/tmp", 440, 0)),
            "/data/ssd/build" => Some(stats("/data/ssd/build", 800, 400)),
            "/mnt/nas" => Some(stats("/mnt/nas", 10_000, 10)),
            _ => None,
        };
        let levels = uncovered_mount_levels(&mounts, &monitored, stat, &PressureConfig::default());

        assert_eq!(
            levels.get(Path::new("/data/ssd/tmp")),
            Some(&PressureLevel::Critical)
        );
        assert_eq!(
            levels.get(Path::new("/data/ssd/build")),
            Some(&PressureLevel::Green)
        );
        assert!(!levels.contains_key(Path::new("/")), "monitored already");
        assert!(!levels.contains_key(Path::new("/proc")));
        assert!(!levels.contains_key(Path::new("/dev/shm")));
        assert!(!levels.contains_key(Path::new("/mnt/nas")), "network/FUSE");
        assert!(
            !levels.contains_key(Path::new("/data/ssd")),
            "smaller than {UNCOVERED_MIN_TOTAL_BYTES} bytes"
        );
    }

    #[test]
    fn bind_mounts_shadowed_paths_and_read_only_volumes_are_skipped() {
        let mounts = vec![
            mount("/", "/dev/sda1", "ext4"),
            // A bind mount of the monitored root device.
            mount("/srv/bound-root", "/dev/sda1", "ext4"),
            mount("/data/ssd/work", "buildpool/work", "zfs"),
            // The same dataset bind-mounted again: one entry per device.
            mount("/data/projects/mtdt/scratch/ssd", "buildpool/work", "zfs"),
            // statfs resolves to another mount (shadowed path).
            mount("/data/old", "/dev/sdb1", "ext4"),
            mount("/media/ro", "/dev/sdc1", "ext4"),
        ];
        let monitored: HashSet<PathBuf> = [PathBuf::from("/")].into();
        let stat = |path: &Path| match path.to_str()? {
            "/data/ssd/work" => Some(stats("/data/ssd/work", 1000, 30)),
            "/data/projects/mtdt/scratch/ssd" => {
                Some(stats("/data/projects/mtdt/scratch/ssd", 1000, 30))
            }
            "/media/ro" => Some(FsStats {
                is_readonly: true,
                ..stats("/media/ro", 500, 0)
            }),
            // `/`, its bind mount, and the shadowed `/data/old` all resolve to `/`.
            _ => Some(stats("/", 900, 100)),
        };
        let levels = uncovered_mount_levels(&mounts, &monitored, stat, &PressureConfig::default());

        assert_eq!(
            levels.keys().collect::<Vec<_>>(),
            vec![Path::new("/data/ssd/work")],
            "{levels:?}"
        );
        // 3% free: below the default red threshold.
        assert_eq!(levels[Path::new("/data/ssd/work")], PressureLevel::Critical);
    }

    #[test]
    fn measurement_is_bounded() {
        let mounts: Vec<MountPoint> = (0..UNCOVERED_MAX_MOUNTS + 10)
            .map(|i| mount(&format!("/vol/{i}"), &format!("dev{i}"), "ext4"))
            .collect();
        let calls = std::cell::Cell::new(0_usize);
        let stat = |path: &Path| {
            calls.set(calls.get() + 1);
            Some(stats(path.to_str().unwrap(), 100, 50))
        };
        let levels =
            uncovered_mount_levels(&mounts, &HashSet::new(), stat, &PressureConfig::default());
        assert_eq!(levels.len(), UNCOVERED_MAX_MOUNTS);
        assert_eq!(calls.get(), UNCOVERED_MAX_MOUNTS);
    }
}
