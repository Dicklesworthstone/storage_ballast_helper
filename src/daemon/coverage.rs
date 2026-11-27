//! Volumes that no scanner root covers.
//!
//! The daemon measures pressure only on the mounts of `scanner.root_paths`
//! (plus `/`). A volume nobody listed there was invisible: on css
//! (2026-10-23) TMPDIR and the build trees had moved to a ZFS pool that no
//! root covered, the pool's top-level quota reached zero, and sbh logged
//! nothing while 104 tasks blocked writing to it and sshd stopped answering.
//!
//! [`UncoveredMountTracker`] finds those volumes and classifies their free
//! space with the same thresholds the controllers use, so the daemon can
//! raise its ReclaimUnavailable alert for them. They only feed that alert:
//! they get no controller, never enter the worst-mount response and never
//! steer policy, so a data volume that is full by design cannot push the
//! global level to Critical.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::hash::BuildHasher;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::core::config::PressureConfig;
use crate::monitor::pid::{PressureLevel, classify_level};
use crate::platform::pal::{FsStats, MountPoint};

/// How often the daemon re-enumerates mounts for this check. Not every tick:
/// 95328ba removed a per-tick statfs sweep of every mount.
pub const UNCOVERED_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Volumes smaller than this are not worth an alert.
pub const UNCOVERED_MIN_TOTAL_BYTES: u64 = 1 << 30;

/// At most this many capacity lookups are attempted per poll, including failures.
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

/// A filesystem may have several usable aliases. A failed first alias must
/// not hide every other path to the same device.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum FilesystemKey {
    Device { device: String, fs_type: String },
    Path { path: PathBuf, fs_type: String },
}

impl FilesystemKey {
    fn of(mount: &MountPoint) -> Self {
        if mount.device.is_empty() {
            Self::Path {
                path: mount.path.clone(),
                fs_type: mount.fs_type.clone(),
            }
        } else {
            Self::Device {
                device: mount.device.clone(),
                fs_type: mount.fs_type.clone(),
            }
        }
    }
}

struct ObservedPressure {
    mount: PathBuf,
    level: PressureLevel,
    observed_at: Instant,
    unknown: bool,
}

struct PendingFilesystem {
    key: FilesystemKey,
    next_alias: usize,
}

struct ObservationRound {
    started: Instant,
    last_poll: Instant,
    planned: bool,
    pending: VecDeque<PendingFilesystem>,
}

/// A bounded retry window consumes asynchronously requested observations
/// before their cache expires. Stalled volumes never cause endless polling.
const PROBE_RETRY_WINDOW: Duration = Duration::from_secs(10);
const PROBE_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// One capacity result with the native owner and acquisition time that
/// produced it. Cached counters must not be paired with a newer inventory's
/// replacement device or relabelled as a fresh observation.
#[derive(Clone)]
pub struct UncoveredObservation {
    /// Filesystem identity observed with these counters.
    pub owner: MountPoint,
    /// Counters measured on that owner.
    pub stats: FsStats,
    /// Original native acquisition time, preserved through cache hits.
    pub collected_at: Instant,
}

/// Observations for alerting only. Unknown readings preserve an incident's
/// history but must not emit reminders or authorize any cleanup.
pub struct UncoveredSnapshot {
    /// Latest observed level for each retained filesystem incident.
    pub levels: HashMap<PathBuf, PressureLevel>,
    /// Retained paths lacking a current successful observation.
    pub unknown: HashSet<PathBuf>,
    /// Old ownership disappeared, changed, or became covered by the monitor.
    /// Forget its notification acknowledgement before reporting a replacement.
    pub retired: Vec<PathBuf>,
}

/// Fair, bounded observation of local filesystems outside the pressure loop.
///
/// Each poll performs at most 64 capacity lookups, including failures. Rounds
/// rotate through devices, and failed aliases rotate within each selected
/// device. A missing sample preserves the last incident without inventing
/// recovery; topology changes retire the old device's incident explicitly.
#[derive(Default)]
pub struct UncoveredMountTracker {
    observed: HashMap<FilesystemKey, ObservedPressure>,
    alias_cursors: HashMap<FilesystemKey, usize>,
    cursor: Option<FilesystemKey>,
    round: Option<ObservationRound>,
    next_round: Option<Instant>,
    poll_interval: Option<Duration>,
}

impl UncoveredMountTracker {
    /// Match the collector's observation lifetime while retaining a small
    /// minimum wait and the normal half-second upper bound.
    pub fn set_poll_interval(&mut self, interval: Duration) {
        self.poll_interval = Some(interval.clamp(Duration::from_millis(5), PROBE_POLL_INTERVAL));
    }

    fn poll_interval(&self) -> Duration {
        self.poll_interval.unwrap_or(PROBE_POLL_INTERVAL)
    }

    /// Time until a pending result needs a lightweight wakeup. Idle rounds
    /// do not alter the daemon's sleep or pressure-control cadence.
    #[must_use]
    pub fn next_poll_delay(&self, now: Instant) -> Option<Duration> {
        self.round.as_ref().map(|round| {
            self.poll_interval()
                .saturating_sub(now.saturating_duration_since(round.last_poll))
        })
    }

    /// Whether the next bounded polling step is due.
    #[must_use]
    pub fn poll_due(&self, now: Instant) -> bool {
        self.round.as_ref().map_or_else(
            || self.next_round.is_none_or(|next| now >= next),
            |round| now.saturating_duration_since(round.last_poll) >= self.poll_interval(),
        )
    }

    /// Whether a requested round still needs its asynchronous results.
    #[must_use]
    pub fn has_pending_round(&self) -> bool {
        self.round.is_some()
    }

    /// Configuration changes invalidate coverage, not the last real incident.
    /// The next successful inventory decides which owners remain uncovered.
    pub fn invalidate(&mut self) {
        self.round = None;
        self.next_round = None;
        for observation in self.observed.values_mut() {
            observation.unknown = true;
        }
    }

    /// Inventory failure is unknown, never an empty mount list. Callers may
    /// poll an active round from their existing lightweight sleep wakeups;
    /// they need not accelerate the daemon's pressure-control tick.
    pub fn poll<S: BuildHasher>(
        &mut self,
        mounts: Option<&[MountPoint]>,
        monitored: &HashSet<PathBuf, S>,
        mut stat: impl FnMut(&MountPoint) -> Option<UncoveredObservation>,
        pressure: &PressureConfig,
        now: Instant,
    ) -> Option<UncoveredSnapshot> {
        if !self.poll_due(now) {
            return None;
        }
        let mut round = self.round.take().unwrap_or_else(|| ObservationRound {
            started: now,
            last_poll: now,
            planned: false,
            pending: VecDeque::new(),
        });
        round.last_poll = now;
        let mut retired = Vec::new();

        if let Some(mounts) = mounts {
            let groups = uncovered_groups(mounts, monitored);
            retired = self.retire_missing_owners(&groups);
            self.alias_cursors.retain(|key, _| groups.contains_key(key));

            self.plan_round(&mut round, &groups);
            round
                .pending
                .retain(|pending| groups.contains_key(&pending.key));
            // Every selected device receives at most one lookup in this poll.
            // Failures remain pending; the next poll tries its next alias.
            let attempts = round.pending.len().min(UNCOVERED_MAX_MOUNTS);
            for _ in 0..attempts {
                let mut pending = round.pending.pop_front().expect("pending device exists");
                let aliases = &groups[&pending.key];
                let alias_index = pending.next_alias % aliases.len();
                let alias = aliases[alias_index];
                pending.next_alias = (alias_index + 1) % aliases.len();
                let level = stat(alias)
                    .filter(|observation| {
                        self.observed
                            .get(&pending.key)
                            .is_none_or(|old| observation.collected_at >= old.observed_at)
                    })
                    .and_then(|observation| {
                        observed_level(alias, &observation, pressure)
                            .map(|level| (level, observation.collected_at))
                    });
                if let Some((level, observed_at)) = level {
                    self.alias_cursors.insert(pending.key.clone(), alias_index);
                    let reported = self
                        .observed
                        .get(&pending.key)
                        .map_or_else(|| alias.path.clone(), |old| old.mount.clone());
                    self.observed.insert(
                        pending.key,
                        ObservedPressure {
                            mount: reported,
                            level,
                            observed_at,
                            unknown: false,
                        },
                    );
                } else {
                    self.alias_cursors
                        .insert(pending.key.clone(), pending.next_alias);
                    if let Some(old) = self.observed.get_mut(&pending.key) {
                        old.unknown = true;
                    }
                    round.pending.push_back(pending);
                }
            }
        } else {
            for observation in self.observed.values_mut() {
                observation.unknown = true;
            }
        }

        if (round.planned && round.pending.is_empty())
            || now.saturating_duration_since(round.started) >= PROBE_RETRY_WINDOW
        {
            self.next_round = now.checked_add(UNCOVERED_REFRESH_INTERVAL);
        } else {
            self.round = Some(round);
        }
        Some(self.snapshot(now, retired))
    }

    fn plan_round(
        &mut self,
        round: &mut ObservationRound,
        groups: &BTreeMap<FilesystemKey, Vec<&MountPoint>>,
    ) {
        if round.planned {
            return;
        }
        let keys: Vec<_> = groups.keys().cloned().collect();
        let start = self
            .cursor
            .as_ref()
            .and_then(|cursor| keys.iter().position(|key| key > cursor))
            .unwrap_or(0);
        round.pending = keys
            .iter()
            .cycle()
            .skip(start)
            .take(keys.len().min(UNCOVERED_MAX_MOUNTS))
            .cloned()
            .map(|key| {
                let next_alias = self.alias_cursors.get(&key).copied().unwrap_or(0);
                PendingFilesystem { key, next_alias }
            })
            .collect();
        self.cursor = round.pending.back().map(|pending| pending.key.clone());
        round.planned = true;
    }

    fn retire_missing_owners(
        &mut self,
        groups: &BTreeMap<FilesystemKey, Vec<&MountPoint>>,
    ) -> Vec<PathBuf> {
        let mut retired = Vec::new();
        self.observed.retain(|key, observation| {
            let Some(aliases) = groups.get(key) else {
                retired.push(observation.mount.clone());
                return false;
            };
            if !aliases.iter().any(|alias| alias.path == observation.mount) {
                retired.push(observation.mount.clone());
                observation.mount = aliases[0].path.clone();
                observation.unknown = true;
            }
            true
        });
        retired.sort();
        retired
    }

    fn snapshot(&self, now: Instant, retired: Vec<PathBuf>) -> UncoveredSnapshot {
        let mut levels = HashMap::new();
        let mut unknown = HashSet::new();
        for observation in self.observed.values() {
            levels.insert(observation.mount.clone(), observation.level);
            if observation.unknown
                || now.saturating_duration_since(observation.observed_at)
                    > UNCOVERED_REFRESH_INTERVAL
            {
                unknown.insert(observation.mount.clone());
            }
        }
        UncoveredSnapshot {
            levels,
            unknown,
            retired,
        }
    }
}

fn uncovered_groups<'a, S: BuildHasher>(
    mounts: &'a [MountPoint],
    monitored: &HashSet<PathBuf, S>,
) -> BTreeMap<FilesystemKey, Vec<&'a MountPoint>> {
    let covered: HashSet<_> = mounts
        .iter()
        .filter(|mount| monitored.contains(&mount.path))
        .map(FilesystemKey::of)
        .collect();
    let mut groups = BTreeMap::<FilesystemKey, Vec<&MountPoint>>::new();
    for mount in mounts.iter().filter(|mount| watchable_mount(mount)) {
        let key = FilesystemKey::of(mount);
        if !covered.contains(&key) {
            groups.entry(key).or_default().push(mount);
        }
    }
    for aliases in groups.values_mut() {
        // Preserve the native inventory's preferred alias while deduplicating.
        let mut seen = HashSet::new();
        aliases.retain(|alias| seen.insert(alias.path.clone()));
    }
    groups
}

fn observed_level(
    mount: &MountPoint,
    observation: &UncoveredObservation,
    pressure: &PressureConfig,
) -> Option<PressureLevel> {
    let stats = &observation.stats;
    if observation.owner != *mount
        || stats.mount_point != mount.path
        || stats.fs_type != mount.fs_type
        || stats.is_readonly
        || stats.total_bytes < UNCOVERED_MIN_TOTAL_BYTES
        || stats.free_bytes > stats.total_bytes
        || stats.available_bytes > stats.free_bytes
    {
        return None;
    }
    let [green, yellow, orange, red] = pressure.free_pct_thresholds_for(stats.total_bytes);
    Some(classify_level(stats.free_pct(), green, yellow, orange, red))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const GIB: u64 = 1 << 30;

    impl UncoveredMountTracker {
        /// Capacity-only fixtures stand for current, coherently owned samples.
        /// Provenance regressions below call poll directly with native frames.
        fn poll_stats<S: BuildHasher>(
            &mut self,
            mounts: Option<&[MountPoint]>,
            monitored: &HashSet<PathBuf, S>,
            mut stat: impl FnMut(&Path) -> Option<FsStats>,
            pressure: &PressureConfig,
            now: Instant,
        ) -> Option<UncoveredSnapshot> {
            self.poll(
                mounts,
                monitored,
                |owner| {
                    Some(UncoveredObservation {
                        owner: owner.clone(),
                        stats: stat(&owner.path)?,
                        collected_at: now,
                    })
                },
                pressure,
                now,
            )
        }
    }

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

    fn levels_once(
        mounts: &[MountPoint],
        monitored: &HashSet<PathBuf>,
        stat: impl FnMut(&Path) -> Option<FsStats>,
        pressure: &PressureConfig,
    ) -> HashMap<PathBuf, PressureLevel> {
        UncoveredMountTracker::default()
            .poll_stats(Some(mounts), monitored, stat, pressure, Instant::now())
            .unwrap()
            .levels
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
        let levels = levels_once(&mounts, &monitored, stat, &PressureConfig::default());

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
        let levels = levels_once(&mounts, &monitored, stat, &PressureConfig::default());

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
            Some(FsStats {
                fs_type: "ext4".into(),
                ..stats(path.to_str().unwrap(), 100, 50)
            })
        };
        let levels = levels_once(&mounts, &HashSet::new(), stat, &PressureConfig::default());
        assert_eq!(levels.len(), UNCOVERED_MAX_MOUNTS);
        assert_eq!(calls.get(), UNCOVERED_MAX_MOUNTS);
    }

    #[test]
    fn failed_and_ineligible_probes_count_toward_budget_and_later_mounts_get_a_turn() {
        let mounts: Vec<_> = (0..UNCOVERED_MAX_MOUNTS + 10)
            .map(|index| {
                mount(
                    &format!("/vol/{index:03}"),
                    &format!("device-{index:03}"),
                    "zfs",
                )
            })
            .collect();
        let mut tracker = UncoveredMountTracker::default();
        let monitored = HashSet::new();
        let pressure = PressureConfig::default();
        let start = Instant::now();
        let calls = std::cell::Cell::new(0);
        let probe = |path: &Path| {
            calls.set(calls.get() + 1);
            let index: usize = path.file_name()?.to_str()?.parse().ok()?;
            if index >= UNCOVERED_MAX_MOUNTS {
                return Some(stats(path.to_str()?, 100, 0));
            }
            match index % 4 {
                0 => None,
                1 => Some(FsStats {
                    is_readonly: true,
                    ..stats(path.to_str()?, 100, 0)
                }),
                2 => Some(stats(path.to_str()?, 0, 0)),
                _ => Some(FsStats {
                    available_bytes: 101 * GIB,
                    ..stats(path.to_str()?, 100, 50)
                }),
            }
        };
        let initial = tracker
            .poll_stats(Some(&mounts), &monitored, probe, &pressure, start)
            .unwrap();
        assert!(initial.levels.is_empty());
        assert_eq!(calls.get(), UNCOVERED_MAX_MOUNTS);
        assert!(tracker.has_pending_round());
        calls.set(0);
        tracker
            .poll_stats(
                Some(&mounts),
                &monitored,
                probe,
                &pressure,
                start + PROBE_RETRY_WINDOW,
            )
            .unwrap();
        assert_eq!(calls.get(), UNCOVERED_MAX_MOUNTS);
        assert!(!tracker.has_pending_round());
        assert!(
            !tracker.poll_due(start + PROBE_RETRY_WINDOW + PROBE_POLL_INTERVAL),
            "unavailable volumes must back off after their retry window"
        );
        calls.set(0);
        let later = tracker
            .poll_stats(
                Some(&mounts),
                &monitored,
                probe,
                &pressure,
                start + PROBE_RETRY_WINDOW + UNCOVERED_REFRESH_INTERVAL,
            )
            .unwrap();
        assert_eq!(calls.get(), UNCOVERED_MAX_MOUNTS);
        for volume in &mounts[UNCOVERED_MAX_MOUNTS..] {
            assert_eq!(
                later.levels.get(&volume.path),
                Some(&PressureLevel::Critical),
                "failed early probes must not permanently hide {}",
                volume.path.display()
            );
        }
    }

    #[test]
    fn failed_first_alias_does_not_hide_an_exhausted_filesystem() {
        let mounts = [
            mount("/alias-a", "buildpool", "zfs"),
            mount("/alias-b", "buildpool", "zfs"),
        ];
        let mut tracker = UncoveredMountTracker::default();
        let monitored = HashSet::new();
        let pressure = PressureConfig::default();
        let start = Instant::now();
        let probe =
            |path: &Path| (path == Path::new("/alias-b")).then(|| stats("/alias-b", 100, 0));
        assert!(
            tracker
                .poll_stats(Some(&mounts), &monitored, probe, &pressure, start)
                .unwrap()
                .levels
                .is_empty()
        );
        let observed = tracker
            .poll_stats(
                Some(&mounts),
                &monitored,
                probe,
                &pressure,
                start + PROBE_POLL_INTERVAL,
            )
            .unwrap();
        assert_eq!(
            observed.levels,
            HashMap::from([(PathBuf::from("/alias-b"), PressureLevel::Critical)])
        );
        assert!(observed.unknown.is_empty());
        assert!(!tracker.has_pending_round());
    }

    #[test]
    fn missing_or_invalid_readings_hold_an_incident_until_verified_recovery() {
        let mounts = [mount("/work", "buildpool", "zfs")];
        let mut tracker = UncoveredMountTracker::default();
        let monitored = HashSet::new();
        let pressure = PressureConfig::default();
        let start = Instant::now();
        tracker
            .poll_stats(
                Some(&mounts),
                &monitored,
                |_| Some(stats("/work", 100, 0)),
                &pressure,
                start,
            )
            .unwrap();
        let missing = tracker
            .poll_stats(
                Some(&mounts),
                &monitored,
                |_| None,
                &pressure,
                start + UNCOVERED_REFRESH_INTERVAL,
            )
            .unwrap();
        assert_eq!(missing.levels[Path::new("/work")], PressureLevel::Critical);
        assert!(missing.unknown.contains(Path::new("/work")));
        assert!(missing.retired.is_empty());

        let invalid = tracker
            .poll_stats(
                Some(&mounts),
                &monitored,
                |_| {
                    Some(FsStats {
                        available_bytes: 101 * GIB,
                        ..stats("/work", 100, 50)
                    })
                },
                &pressure,
                start + UNCOVERED_REFRESH_INTERVAL + PROBE_POLL_INTERVAL,
            )
            .unwrap();
        assert_eq!(invalid.levels[Path::new("/work")], PressureLevel::Critical);
        assert!(invalid.unknown.contains(Path::new("/work")));
        let healthy = tracker
            .poll_stats(
                Some(&mounts),
                &monitored,
                |_| Some(stats("/work", 100, 50)),
                &pressure,
                start + UNCOVERED_REFRESH_INTERVAL + PROBE_POLL_INTERVAL * 2,
            )
            .unwrap();
        assert_eq!(healthy.levels[Path::new("/work")], PressureLevel::Green);
        assert!(healthy.unknown.is_empty());
    }

    #[test]
    fn inventory_failure_is_unknown_but_removal_and_new_coverage_retire_ownership() {
        let mounts = [
            mount("/work", "buildpool", "zfs"),
            mount("/covered-alias", "buildpool", "zfs"),
        ];
        let mut tracker = UncoveredMountTracker::default();
        let mut monitored = HashSet::new();
        let pressure = PressureConfig::default();
        let start = Instant::now();
        tracker
            .poll_stats(
                Some(&mounts),
                &monitored,
                |path| Some(stats(path.to_str()?, 100, 0)),
                &pressure,
                start,
            )
            .unwrap();
        let missing = tracker
            .poll_stats(
                None,
                &monitored,
                |_| panic!("inventory failure must not probe an invented owner"),
                &pressure,
                start + UNCOVERED_REFRESH_INTERVAL,
            )
            .unwrap();
        assert_eq!(missing.levels.len(), 1);
        assert_eq!(missing.unknown.len(), 1);
        assert!(missing.retired.is_empty());

        monitored.insert(PathBuf::from("/work"));
        let covered = tracker
            .poll_stats(
                Some(&mounts),
                &monitored,
                |_| panic!("already monitored device must not be probed"),
                &pressure,
                start + UNCOVERED_REFRESH_INTERVAL + PROBE_POLL_INTERVAL,
            )
            .unwrap();
        assert!(covered.levels.is_empty());
        assert_eq!(covered.retired, vec![PathBuf::from("/work")]);

        // A configuration change can make the same device uncovered again.
        monitored.clear();
        tracker.invalidate();
        let reopened = tracker
            .poll_stats(
                Some(&mounts),
                &monitored,
                |path| Some(stats(path.to_str()?, 100, 0)),
                &pressure,
                start + UNCOVERED_REFRESH_INTERVAL + PROBE_POLL_INTERVAL * 2,
            )
            .unwrap();
        assert_eq!(reopened.levels.len(), 1);
        tracker.invalidate();
        let removed = tracker
            .poll_stats(
                Some(&[]),
                &monitored,
                |_| panic!("removed mounts must not be probed"),
                &pressure,
                start + UNCOVERED_REFRESH_INTERVAL + PROBE_POLL_INTERVAL * 3,
            )
            .unwrap();
        assert!(removed.levels.is_empty());
        assert_eq!(removed.retired, vec![PathBuf::from("/work")]);
    }

    #[test]
    fn replacement_at_the_same_path_cannot_inherit_the_old_incident() {
        let old = [mount("/work", "old-device", "zfs")];
        let new = [mount("/work", "new-device", "zfs")];
        let mut tracker = UncoveredMountTracker::default();
        let monitored = HashSet::new();
        let pressure = PressureConfig::default();
        let start = Instant::now();
        tracker
            .poll_stats(
                Some(&old),
                &monitored,
                |_| Some(stats("/work", 100, 0)),
                &pressure,
                start,
            )
            .unwrap();
        let replaced = tracker
            .poll_stats(
                Some(&new),
                &monitored,
                |_| None,
                &pressure,
                start + UNCOVERED_REFRESH_INTERVAL,
            )
            .unwrap();
        assert!(replaced.levels.is_empty());
        assert!(replaced.unknown.is_empty());
        assert_eq!(replaced.retired, vec![PathBuf::from("/work")]);
    }

    #[test]
    fn stalled_inventory_retry_window_is_bounded() {
        let mut tracker = UncoveredMountTracker::default();
        let start = Instant::now();
        let monitored = HashSet::new();
        let pressure = PressureConfig::default();
        for elapsed in [Duration::ZERO, PROBE_POLL_INTERVAL, PROBE_RETRY_WINDOW] {
            tracker
                .poll_stats(
                    None,
                    &monitored,
                    |_| panic!("no inventory"),
                    &pressure,
                    start + elapsed,
                )
                .unwrap();
        }
        assert!(!tracker.has_pending_round());
        assert!(
            tracker
                .poll_stats(
                    None,
                    &monitored,
                    |_| panic!("no inventory"),
                    &pressure,
                    start + PROBE_RETRY_WINDOW + PROBE_POLL_INTERVAL,
                )
                .is_none()
        );
    }

    #[test]
    fn failed_alias_rotation_survives_the_end_of_a_retry_window() {
        let mounts: Vec<_> = (0..30)
            .map(|index| mount(&format!("/alias/{index:02}"), "buildpool", "zfs"))
            .collect();
        let mut tracker = UncoveredMountTracker::default();
        let monitored = HashSet::new();
        let pressure = PressureConfig::default();
        let start = Instant::now();
        let probe =
            |path: &Path| (path == Path::new("/alias/25")).then(|| stats("/alias/25", 100, 0));
        for step in 0..=20 {
            let snapshot = tracker
                .poll_stats(
                    Some(&mounts),
                    &monitored,
                    probe,
                    &pressure,
                    start + PROBE_POLL_INTERVAL * step,
                )
                .unwrap();
            assert!(snapshot.levels.is_empty());
        }
        assert!(!tracker.has_pending_round());
        let next_round = start + PROBE_RETRY_WINDOW + UNCOVERED_REFRESH_INTERVAL;
        let mut observed = None;
        for step in 0..5 {
            observed = tracker.poll_stats(
                Some(&mounts),
                &monitored,
                probe,
                &pressure,
                next_round + PROBE_POLL_INTERVAL * step,
            );
        }
        assert_eq!(
            observed.unwrap().levels[Path::new("/alias/25")],
            PressureLevel::Critical
        );
        let next = tracker
            .poll_stats(
                Some(&mounts),
                &monitored,
                |path| {
                    assert_eq!(path, Path::new("/alias/25"), "reuse the working alias");
                    Some(stats("/alias/25", 100, 50))
                },
                &pressure,
                next_round + PROBE_POLL_INTERVAL * 4 + UNCOVERED_REFRESH_INTERVAL,
            )
            .unwrap();
        assert_eq!(next.levels[Path::new("/alias/25")], PressureLevel::Green);
    }

    fn native_observation(
        owner: &MountPoint,
        available_gib: u64,
        collected_at: Instant,
    ) -> UncoveredObservation {
        UncoveredObservation {
            owner: owner.clone(),
            stats: FsStats {
                fs_type: owner.fs_type.clone(),
                ..stats(owner.path.to_str().unwrap(), 100, available_gib)
            },
            collected_at,
        }
    }

    #[test]
    fn new_inventory_owner_cannot_borrow_cached_counters_from_the_replaced_device() {
        let old = mount("/work", "old-device", "zfs");
        let new = mount("/work", "new-device", "zfs");
        let monitored = HashSet::new();
        let pressure = PressureConfig::default();
        let start = Instant::now();
        let mut tracker = UncoveredMountTracker::default();
        tracker
            .poll(
                Some(std::slice::from_ref(&old)),
                &monitored,
                |_| Some(native_observation(&old, 0, start)),
                &pressure,
                start,
            )
            .unwrap();

        // The inventory refreshed independently of the per-path cache.
        // Path and filesystem type match, but these healthy counters still
        // belong to the old device and must not become the new owner's state.
        let replaced_at = start + UNCOVERED_REFRESH_INTERVAL;
        let cached_old = native_observation(&old, 50, replaced_at - Duration::from_secs(1));
        let replaced = tracker
            .poll(
                Some(std::slice::from_ref(&new)),
                &monitored,
                |_| Some(cached_old.clone()),
                &pressure,
                replaced_at,
            )
            .unwrap();
        assert_eq!(replaced.retired, vec![PathBuf::from("/work")]);
        assert!(
            replaced.levels.is_empty(),
            "old counters cannot establish a new owner"
        );
        assert!(tracker.has_pending_round());

        let fresh_at = replaced_at + PROBE_POLL_INTERVAL;
        let fresh = tracker
            .poll(
                Some(std::slice::from_ref(&new)),
                &monitored,
                |_| Some(native_observation(&new, 0, fresh_at)),
                &pressure,
                fresh_at,
            )
            .unwrap();
        assert_eq!(fresh.levels[Path::new("/work")], PressureLevel::Critical);
        assert!(fresh.unknown.is_empty());
    }

    #[test]
    fn older_healthy_alias_cannot_erase_newer_pressure_on_the_same_device() {
        let mounts = [
            mount("/alias-a", "buildpool", "zfs"),
            mount("/alias-b", "buildpool", "zfs"),
        ];
        let monitored = HashSet::new();
        let pressure = PressureConfig::default();
        let start = Instant::now();
        let mut tracker = UncoveredMountTracker::default();
        tracker
            .poll(
                Some(&mounts),
                &monitored,
                |owner| Some(native_observation(owner, 0, start)),
                &pressure,
                start,
            )
            .unwrap();
        let retry = start + UNCOVERED_REFRESH_INTERVAL;
        tracker
            .poll(Some(&mounts), &monitored, |_| None, &pressure, retry)
            .unwrap();
        let old_at = start.checked_sub(Duration::from_secs(1)).unwrap();
        let older = tracker
            .poll(
                Some(&mounts),
                &monitored,
                |owner| {
                    assert_eq!(owner.path, Path::new("/alias-b"));
                    Some(native_observation(owner, 50, old_at))
                },
                &pressure,
                retry + PROBE_POLL_INTERVAL,
            )
            .unwrap();
        assert_eq!(older.levels[Path::new("/alias-a")], PressureLevel::Critical);
        assert!(older.unknown.contains(Path::new("/alias-a")));

        let recovered_at = retry + PROBE_POLL_INTERVAL * 2;
        let recovered = tracker
            .poll(
                Some(&mounts),
                &monitored,
                |owner| Some(native_observation(owner, 50, recovered_at)),
                &pressure,
                recovered_at,
            )
            .unwrap();
        assert_eq!(
            recovered.levels[Path::new("/alias-a")],
            PressureLevel::Green
        );
        assert!(recovered.unknown.is_empty());
    }

    #[test]
    fn cache_hits_preserve_native_age_instead_of_renewing_notification_evidence() {
        let owner = mount("/work", "buildpool", "zfs");
        let monitored = HashSet::new();
        let pressure = PressureConfig::default();
        let start = Instant::now();
        let sample = native_observation(&owner, 0, start);
        let mut tracker = UncoveredMountTracker::default();
        tracker
            .poll(
                Some(std::slice::from_ref(&owner)),
                &monitored,
                |_| Some(sample.clone()),
                &pressure,
                start,
            )
            .unwrap();
        let cached = tracker
            .poll(
                Some(std::slice::from_ref(&owner)),
                &monitored,
                |_| Some(sample.clone()),
                &pressure,
                start + UNCOVERED_REFRESH_INTERVAL + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(cached.levels[Path::new("/work")], PressureLevel::Critical);
        assert!(
            cached.unknown.contains(Path::new("/work")),
            "re-reading the same sample cannot authorize a fresh reminder"
        );
    }
}
