//! Special location registry: /tmp, /dev/shm, RAM-backed mounts with buffer targets.

#![allow(missing_docs)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::core::errors::Result;
use crate::platform::pal::{FsStats, Platform};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecialKind {
    Tmpfs,
    DevShm,
    Ramfs,
    UserTmp,
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecialLocation {
    pub path: PathBuf,
    pub kind: SpecialKind,
    pub buffer_pct: u8,
    pub scan_interval: Duration,
    pub priority: u8,
}

impl SpecialLocation {
    #[must_use]
    pub fn needs_attention(&self, stats: &FsStats) -> bool {
        stats.free_pct() < f64::from(self.buffer_pct)
    }

    #[must_use]
    pub fn scan_due(&self, last_scan: Option<Instant>, now: Instant) -> bool {
        last_scan.is_none_or(|last| now.duration_since(last) >= self.scan_interval)
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpecialLocationRegistry {
    locations: Vec<SpecialLocation>,
}

impl SpecialLocationRegistry {
    #[must_use]
    pub fn new(locations: Vec<SpecialLocation>) -> Self {
        let mut deduped = HashMap::<PathBuf, SpecialLocation>::new();
        for location in locations {
            // Later entries intentionally win so operator-provided custom paths
            // can override auto-discovered defaults for the same location.
            deduped.insert(location.path.clone(), location);
        }
        let mut unique: Vec<SpecialLocation> = deduped.into_values().collect();
        unique.sort_by(|left, right| {
            right
                .priority
                .cmp(&left.priority)
                .then_with(|| left.path.cmp(&right.path))
        });
        Self { locations: unique }
    }

    pub fn discover(platform: &dyn Platform, custom_paths: &[PathBuf]) -> Result<Self> {
        let mounts = platform.mount_points()?;
        let mut locations = Vec::<SpecialLocation>::new();

        for mount in mounts {
            if !mount.is_ram_backed {
                continue;
            }
            // Ignore pseudo runtime mounts that are not actionable for pressure control.
            // On macOS, `/dev` (devfs) reports 0 free by design and would otherwise
            // create permanent critical alerts.
            if should_ignore_ram_backed_mount(mount.path.as_path(), &mount.fs_type) {
                continue;
            }
            // Skip systemd runtime dirs — these are small credential/session tmpfs
            // mounts that are always "full" by design and not actionable.
            let path_str = mount.path.to_string_lossy();
            if path_str.starts_with("/run/credentials/")
                || path_str.starts_with("/run/user/")
                || path_str == "/run/lock"
                || path_str == "/run"
            {
                continue;
            }
            let kind = match mount.path.as_path() {
                p if p == Path::new("/dev/shm") => SpecialKind::DevShm,
                p if p == Path::new("/tmp") => SpecialKind::Tmpfs,
                _ if mount.fs_type == "ramfs" => SpecialKind::Ramfs,
                _ => SpecialKind::Tmpfs,
            };
            let (buffer_pct, scan_interval, priority) = match kind {
                SpecialKind::DevShm => (20, Duration::from_secs(3), 255),
                SpecialKind::Ramfs => (18, Duration::from_secs(4), 220),
                SpecialKind::Tmpfs => (15, Duration::from_secs(5), 200),
                SpecialKind::UserTmp | SpecialKind::Custom(_) => (15, Duration::from_secs(5), 150),
            };
            locations.push(SpecialLocation {
                path: mount.path,
                kind,
                buffer_pct,
                scan_interval,
                priority,
            });
        }

        for path in custom_paths {
            locations.push(SpecialLocation {
                path: path.clone(),
                kind: SpecialKind::Custom(path.display().to_string()),
                buffer_pct: 15,
                scan_interval: Duration::from_secs(5),
                priority: 140,
            });
        }

        if locations
            .iter()
            .all(|location| location.path != Path::new("/tmp"))
        {
            locations.push(SpecialLocation {
                path: PathBuf::from("/tmp"),
                kind: SpecialKind::UserTmp,
                buffer_pct: 15,
                scan_interval: Duration::from_secs(5),
                priority: 160,
            });
        }

        if locations
            .iter()
            .all(|location| location.path != Path::new("/data/tmp"))
        {
            locations.push(SpecialLocation {
                path: PathBuf::from("/data/tmp"),
                kind: SpecialKind::UserTmp,
                buffer_pct: 15,
                scan_interval: Duration::from_secs(5),
                priority: 155,
            });
        }

        Ok(Self::new(locations))
    }

    #[must_use]
    pub fn all(&self) -> &[SpecialLocation] {
        &self.locations
    }
}

fn should_ignore_ram_backed_mount(path: &Path, fs_type: &str) -> bool {
    let path_str = path.to_string_lossy();
    path_str == "/dev" || fs_type.eq_ignore_ascii_case("devfs")
}

#[cfg(test)]
mod tests {
    use super::{SpecialKind, SpecialLocationRegistry};
    use crate::core::errors::{Result, SbhError};
    use crate::platform::pal::{
        FsStats, MemoryInfo, MountPoint, Platform, PlatformPaths, ServiceManager,
    };
    use std::path::{Path, PathBuf};

    #[derive(Default)]
    struct TestServiceManager;
    impl ServiceManager for TestServiceManager {
        fn install(&self) -> Result<()> {
            Ok(())
        }
        fn uninstall(&self) -> Result<()> {
            Ok(())
        }
        fn status(&self) -> Result<String> {
            Ok("ok".to_string())
        }
    }

    struct TestPlatform {
        mounts: Vec<MountPoint>,
    }

    impl Platform for TestPlatform {
        fn fs_stats(&self, _path: &Path) -> Result<FsStats> {
            Err(SbhError::Runtime {
                details: "not used in this test".to_string(),
            })
        }
        fn mount_points(&self) -> Result<Vec<MountPoint>> {
            Ok(self.mounts.clone())
        }
        fn is_ram_backed(&self, _path: &Path) -> Result<bool> {
            Ok(false)
        }
        fn default_paths(&self) -> PlatformPaths {
            PlatformPaths::default()
        }
        fn memory_info(&self) -> Result<MemoryInfo> {
            Ok(MemoryInfo {
                total_bytes: 1,
                available_bytes: 1,
                swap_total_bytes: 0,
                swap_free_bytes: 0,
            })
        }
        fn service_manager(&self) -> Box<dyn ServiceManager> {
            Box::<TestServiceManager>::default()
        }
    }

    #[test]
    fn discover_includes_tmpfs_and_custom_locations() {
        let platform = TestPlatform {
            mounts: vec![MountPoint {
                path: PathBuf::from("/dev/shm"),
                device: "tmpfs".to_string(),
                fs_type: "tmpfs".to_string(),
                is_ram_backed: true,
            }],
        };
        let registry =
            SpecialLocationRegistry::discover(&platform, &[PathBuf::from("/data/tmp/custom")])
                .expect("discovery should succeed");
        assert!(
            registry
                .all()
                .iter()
                .any(|location| location.path == Path::new("/dev/shm"))
        );
        assert!(
            registry
                .all()
                .iter()
                .any(|location| matches!(location.kind, SpecialKind::Custom(_)))
        );
        assert!(
            registry
                .all()
                .iter()
                .any(|location| location.path == Path::new("/tmp"))
        );
    }

    #[test]
    fn needs_attention_when_below_buffer() {
        use super::{FsStats, SpecialKind, SpecialLocation};
        use std::time::Duration;

        let loc = SpecialLocation {
            path: PathBuf::from("/tmp"),
            kind: SpecialKind::Tmpfs,
            buffer_pct: 15,
            scan_interval: Duration::from_secs(5),
            priority: 200,
        };
        let stats_low = FsStats {
            total_bytes: 1000,
            free_bytes: 100, // 10% free — below buffer_pct 15
            available_bytes: 100,
            fs_type: "tmpfs".to_string(),
            mount_point: PathBuf::from("/tmp"),
            is_readonly: false,
        };
        assert!(loc.needs_attention(&stats_low));

        let stats_ok = FsStats {
            total_bytes: 1000,
            free_bytes: 200, // 20% free — above buffer_pct 15
            available_bytes: 200,
            fs_type: "tmpfs".to_string(),
            mount_point: PathBuf::from("/tmp"),
            is_readonly: false,
        };
        assert!(!loc.needs_attention(&stats_ok));
    }

    #[test]
    fn scan_due_when_never_scanned() {
        use super::{SpecialKind, SpecialLocation};
        use std::time::{Duration, Instant};

        let loc = SpecialLocation {
            path: PathBuf::from("/tmp"),
            kind: SpecialKind::Tmpfs,
            buffer_pct: 15,
            scan_interval: Duration::from_secs(60),
            priority: 200,
        };
        assert!(loc.scan_due(None, Instant::now()));
    }

    #[test]
    fn scan_not_due_when_recently_scanned() {
        use super::{SpecialKind, SpecialLocation};
        use std::time::{Duration, Instant};

        let loc = SpecialLocation {
            path: PathBuf::from("/tmp"),
            kind: SpecialKind::Tmpfs,
            buffer_pct: 15,
            scan_interval: Duration::from_secs(60),
            priority: 200,
        };
        let now = Instant::now();
        assert!(!loc.scan_due(Some(now), now));
    }

    #[test]
    fn registry_deduplicates_paths() {
        use super::{SpecialKind, SpecialLocation};
        use std::time::Duration;

        let locations = vec![
            SpecialLocation {
                path: PathBuf::from("/tmp"),
                kind: SpecialKind::Tmpfs,
                buffer_pct: 15,
                scan_interval: Duration::from_secs(5),
                priority: 200,
            },
            SpecialLocation {
                path: PathBuf::from("/tmp"),
                kind: SpecialKind::UserTmp,
                buffer_pct: 10,
                scan_interval: Duration::from_secs(5),
                priority: 160,
            },
        ];
        let registry = SpecialLocationRegistry::new(locations);
        assert_eq!(registry.all().len(), 1);
        assert!(matches!(registry.all()[0].kind, SpecialKind::UserTmp));
    }

    #[test]
    fn registry_sorts_by_priority_descending() {
        use super::{SpecialKind, SpecialLocation};
        use std::time::Duration;

        let locations = vec![
            SpecialLocation {
                path: PathBuf::from("/data/tmp"),
                kind: SpecialKind::Custom("custom".to_string()),
                buffer_pct: 15,
                scan_interval: Duration::from_secs(5),
                priority: 100,
            },
            SpecialLocation {
                path: PathBuf::from("/dev/shm"),
                kind: SpecialKind::DevShm,
                buffer_pct: 20,
                scan_interval: Duration::from_secs(3),
                priority: 255,
            },
            SpecialLocation {
                path: PathBuf::from("/tmp"),
                kind: SpecialKind::Tmpfs,
                buffer_pct: 15,
                scan_interval: Duration::from_secs(5),
                priority: 200,
            },
        ];
        let registry = SpecialLocationRegistry::new(locations);
        let all = registry.all();
        assert_eq!(all[0].priority, 255);
        assert_eq!(all[1].priority, 200);
        assert_eq!(all[2].priority, 100);
    }

    #[test]
    fn discover_adds_tmp_fallback_when_no_tmpfs_mount() {
        let platform = TestPlatform { mounts: vec![] };
        let registry =
            SpecialLocationRegistry::discover(&platform, &[]).expect("discovery should succeed");
        assert!(
            registry
                .all()
                .iter()
                .any(|loc| loc.path == Path::new("/tmp")),
            "/tmp should be added as fallback"
        );
    }

    #[test]
    fn discover_adds_data_tmp_fallback() {
        let platform = TestPlatform { mounts: vec![] };
        let registry =
            SpecialLocationRegistry::discover(&platform, &[]).expect("discovery should succeed");
        assert!(
            registry
                .all()
                .iter()
                .any(|loc| loc.path == Path::new("/data/tmp")),
            "/data/tmp should be added as fallback"
        );
    }

    #[test]
    fn discover_ignores_devfs_mounts() {
        let platform = TestPlatform {
            mounts: vec![MountPoint {
                path: PathBuf::from("/dev"),
                device: "devfs".to_string(),
                fs_type: "devfs".to_string(),
                is_ram_backed: true,
            }],
        };
        let registry =
            SpecialLocationRegistry::discover(&platform, &[]).expect("discovery should succeed");
        assert!(
            registry
                .all()
                .iter()
                .all(|location| location.path != Path::new("/dev")),
            "/dev should not be treated as a pressure-managed special location",
        );
    }

    #[test]
    fn discover_custom_path_overrides_mount_defaults() {
        let platform = TestPlatform {
            mounts: vec![MountPoint {
                path: PathBuf::from("/tmp"),
                device: "tmpfs".to_string(),
                fs_type: "tmpfs".to_string(),
                is_ram_backed: true,
            }],
        };
        let registry = SpecialLocationRegistry::discover(&platform, &[PathBuf::from("/tmp")])
            .expect("discovery should succeed");

        let tmp = registry
            .all()
            .iter()
            .find(|location| location.path == Path::new("/tmp"))
            .expect("/tmp entry should exist");
        assert!(matches!(tmp.kind, SpecialKind::Custom(_)));
        assert_eq!(tmp.priority, 140);
    }
}
