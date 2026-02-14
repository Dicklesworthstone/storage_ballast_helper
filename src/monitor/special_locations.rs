//! Special location registry: /tmp, /dev/shm, RAM-backed mounts with buffer targets.

#![allow(missing_docs)]

use std::collections::HashSet;
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
        let mut unique = Vec::new();
        let mut seen = HashSet::<PathBuf>::new();
        for location in locations {
            if seen.insert(location.path.clone()) {
                unique.push(location);
            }
        }
        unique.sort_by(|left, right| right.priority.cmp(&left.priority));
        Self { locations: unique }
    }

    pub fn discover(platform: &dyn Platform, custom_paths: &[PathBuf]) -> Result<Self> {
        let mounts = platform.mount_points()?;
        let mut locations = Vec::<SpecialLocation>::new();

        for mount in mounts {
            if !mount.is_ram_backed {
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

        Ok(Self::new(locations))
    }

    #[must_use]
    pub fn all(&self) -> &[SpecialLocation] {
        &self.locations
    }
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
}
