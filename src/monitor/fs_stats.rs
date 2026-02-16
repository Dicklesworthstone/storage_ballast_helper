//! Filesystem statistics collector: statvfs wrapper, usage percentages, inode tracking.

#![allow(missing_docs)]

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use crate::core::errors::{Result, SbhError};
use crate::platform::pal::{FsStats, MountPoint, Platform};

#[derive(Debug, Clone)]
struct CachedStats {
    stats: FsStats,
    collected_at: Instant,
}

/// Cache-aware, mount-deduplicating filesystem statistics collector.
pub struct FsStatsCollector {
    platform: Arc<dyn Platform>,
    cache_ttl: Duration,
    cache: RwLock<HashMap<PathBuf, CachedStats>>,
    mount_cache: RwLock<Option<(Vec<MountPoint>, Instant)>>,
}

impl FsStatsCollector {
    #[must_use]
    pub fn new(platform: Arc<dyn Platform>, cache_ttl: Duration) -> Self {
        Self {
            platform,
            cache_ttl,
            cache: RwLock::new(HashMap::new()),
            mount_cache: RwLock::new(None),
        }
    }

    pub fn collect(&self, path: &Path) -> Result<FsStats> {
        let mounts = self.cached_mounts()?;
        let lookup_path = crate::core::paths::resolve_absolute_path(path);
        let mount = find_mount(&lookup_path, &mounts).ok_or_else(|| SbhError::FsStats {
            path: path.to_path_buf(),
            details: "path does not belong to known mount".to_string(),
        })?;
        self.collect_for_mount(&mount.path)
    }

    pub fn collect_many(&self, paths: &[PathBuf]) -> Result<HashMap<PathBuf, FsStats>> {
        if paths.is_empty() {
            return Ok(HashMap::new());
        }
        let mounts = self.cached_mounts()?;
        let resolved_paths: Vec<PathBuf> = paths
            .iter()
            .map(|path| crate::core::paths::resolve_absolute_path(path))
            .collect();
        let mut mounts_needed = HashSet::<PathBuf>::new();
        for (path, resolved_path) in paths.iter().zip(&resolved_paths) {
            let Some(mount) = find_mount(resolved_path, &mounts) else {
                return Err(SbhError::FsStats {
                    path: path.clone(),
                    details: "path does not belong to known mount".to_string(),
                });
            };
            mounts_needed.insert(mount.path.clone());
        }

        let mut per_mount = HashMap::<PathBuf, FsStats>::new();
        for mount_path in mounts_needed {
            let stats = self.collect_for_mount(&mount_path)?;
            per_mount.insert(mount_path, stats);
        }

        let mut out = HashMap::with_capacity(paths.len());
        for (path, resolved_path) in paths.iter().zip(&resolved_paths) {
            let mount = find_mount(resolved_path, &mounts).ok_or_else(|| SbhError::FsStats {
                path: path.clone(),
                details: "path does not belong to known mount".to_string(),
            })?;
            let stats = per_mount
                .get(&mount.path)
                .cloned()
                .ok_or_else(|| SbhError::FsStats {
                    path: mount.path.clone(),
                    details: "mount stats missing after collection".to_string(),
                })?;
            out.insert(path.clone(), stats);
        }

        Ok(out)
    }

    pub fn prune_expired_cache(&self) {
        let now = Instant::now();
        let ttl = self.cache_ttl;
        self.cache
            .write()
            .retain(|_, entry| now.duration_since(entry.collected_at) <= ttl);

        // Also clear mount cache if expired.
        let mut mc = self.mount_cache.write();
        if let Some((_, cached_at)) = mc.as_ref() {
            if now.duration_since(*cached_at) > ttl {
                *mc = None;
            }
        }
    }

    fn cached_mounts(&self) -> Result<Vec<MountPoint>> {
        {
            let mc = self.mount_cache.read();
            if let Some((ref mounts, cached_at)) = *mc {
                if cached_at.elapsed() <= self.cache_ttl {
                    return Ok(mounts.clone());
                }
            }
        }
        let fresh = self.platform.mount_points()?;
        *self.mount_cache.write() = Some((fresh.clone(), Instant::now()));
        Ok(fresh)
    }

    fn collect_for_mount(&self, mount_path: &Path) -> Result<FsStats> {
        if let Some(hit) = self.cache_hit(mount_path) {
            return Ok(hit);
        }

        let fresh = self.platform.fs_stats(mount_path)?;
        self.cache.write().insert(
            mount_path.to_path_buf(),
            CachedStats {
                stats: fresh.clone(),
                collected_at: Instant::now(),
            },
        );
        Ok(fresh)
    }

    fn cache_hit(&self, mount_path: &Path) -> Option<FsStats> {
        let cache = self.cache.read();
        let entry = cache.get(mount_path)?;
        if entry.collected_at.elapsed() > self.cache_ttl {
            return None;
        }
        let stats = entry.stats.clone();
        drop(cache);
        Some(stats)
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
    use super::FsStatsCollector;
    use crate::core::errors::{Result, SbhError};
    use crate::platform::pal::{
        FsStats, MemoryInfo, MountPoint, Platform, PlatformPaths, ServiceManager,
    };
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

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

    struct CountingPlatform {
        mounts: Vec<MountPoint>,
        stats: HashMap<PathBuf, FsStats>,
        fs_stats_calls: AtomicUsize,
        mount_points_calls: AtomicUsize,
    }

    impl CountingPlatform {
        fn new(mounts: Vec<MountPoint>, stats: HashMap<PathBuf, FsStats>) -> Self {
            Self {
                mounts,
                stats,
                fs_stats_calls: AtomicUsize::new(0),
                mount_points_calls: AtomicUsize::new(0),
            }
        }
    }

    impl Platform for CountingPlatform {
        fn fs_stats(&self, path: &Path) -> Result<FsStats> {
            self.fs_stats_calls.fetch_add(1, Ordering::SeqCst);
            self.stats
                .get(path)
                .cloned()
                .ok_or_else(|| SbhError::FsStats {
                    path: path.to_path_buf(),
                    details: "missing stats".to_string(),
                })
        }

        fn mount_points(&self) -> Result<Vec<MountPoint>> {
            self.mount_points_calls.fetch_add(1, Ordering::SeqCst);
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
    fn collect_many_deduplicates_mount_queries() {
        let mounts = vec![MountPoint {
            path: PathBuf::from("/tmp"),
            device: "tmpfs".to_string(),
            fs_type: "tmpfs".to_string(),
            is_ram_backed: true,
        }];
        let tmp_stats = FsStats {
            total_bytes: 100,
            free_bytes: 80,
            available_bytes: 80,
            fs_type: "tmpfs".to_string(),
            mount_point: PathBuf::from("/tmp"),
            is_readonly: false,
        };
        let platform = Arc::new(CountingPlatform::new(
            mounts,
            HashMap::from([(PathBuf::from("/tmp"), tmp_stats.clone())]),
        ));
        let collector = FsStatsCollector::new(platform.clone(), Duration::from_secs(5));

        let inputs = vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")];
        let out = collector
            .collect_many(&inputs)
            .expect("collect_many should work");
        assert_eq!(out.len(), 2);
        assert_eq!(out[&PathBuf::from("/tmp/a")], tmp_stats);
        assert_eq!(platform.fs_stats_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cache_hit_avoids_repeat_syscall() {
        let mounts = vec![MountPoint {
            path: PathBuf::from("/tmp"),
            device: "tmpfs".to_string(),
            fs_type: "tmpfs".to_string(),
            is_ram_backed: true,
        }];
        let tmp_stats = FsStats {
            total_bytes: 100,
            free_bytes: 80,
            available_bytes: 80,
            fs_type: "tmpfs".to_string(),
            mount_point: PathBuf::from("/tmp"),
            is_readonly: false,
        };
        let platform = Arc::new(CountingPlatform::new(
            mounts,
            HashMap::from([(PathBuf::from("/tmp"), tmp_stats)]),
        ));
        let collector = FsStatsCollector::new(platform.clone(), Duration::from_secs(10));

        let _first = collector
            .collect(Path::new("/tmp/work"))
            .expect("first collect should work");
        let _second = collector
            .collect(Path::new("/tmp/work"))
            .expect("second collect should hit cache");

        assert_eq!(platform.fs_stats_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn collect_many_empty_input() {
        let mounts = vec![MountPoint {
            path: PathBuf::from("/"),
            device: "root".to_string(),
            fs_type: "ext4".to_string(),
            is_ram_backed: false,
        }];
        let platform = Arc::new(CountingPlatform::new(mounts, HashMap::new()));
        let collector = FsStatsCollector::new(platform.clone(), Duration::from_secs(5));
        let out = collector
            .collect_many(&[])
            .expect("empty collect_many should succeed");
        assert!(out.is_empty());
        assert_eq!(platform.fs_stats_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn collect_fails_for_unknown_mount() {
        let platform = Arc::new(CountingPlatform::new(
            vec![MountPoint {
                path: PathBuf::from("/tmp"),
                device: "tmpfs".to_string(),
                fs_type: "tmpfs".to_string(),
                is_ram_backed: true,
            }],
            HashMap::new(),
        ));
        let collector = FsStatsCollector::new(platform, Duration::from_secs(5));
        let err = collector
            .collect(Path::new("/unknown/path"))
            .expect_err("should fail");
        assert!(err.to_string().contains("does not belong to known mount"));
    }

    #[test]
    fn prune_expired_cache_removes_old_entries() {
        let mounts = vec![MountPoint {
            path: PathBuf::from("/tmp"),
            device: "tmpfs".to_string(),
            fs_type: "tmpfs".to_string(),
            is_ram_backed: true,
        }];
        let stats = FsStats {
            total_bytes: 100,
            free_bytes: 80,
            available_bytes: 80,
            fs_type: "tmpfs".to_string(),
            mount_point: PathBuf::from("/tmp"),
            is_readonly: false,
        };
        let platform = Arc::new(CountingPlatform::new(
            mounts,
            HashMap::from([(PathBuf::from("/tmp"), stats)]),
        ));
        // Use zero TTL so everything expires immediately.
        let collector = FsStatsCollector::new(platform.clone(), Duration::ZERO);
        let _ = collector
            .collect(Path::new("/tmp/foo"))
            .expect("first collect");
        // Wait a tiny bit for expiry.
        std::thread::sleep(Duration::from_millis(1));
        collector.prune_expired_cache();
        // After prune, next collect should call platform again.
        let _ = collector
            .collect(Path::new("/tmp/foo"))
            .expect("second collect");
        assert_eq!(platform.fs_stats_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn mount_cache_avoids_repeat_proc_reads() {
        let mounts = vec![MountPoint {
            path: PathBuf::from("/tmp"),
            device: "tmpfs".to_string(),
            fs_type: "tmpfs".to_string(),
            is_ram_backed: true,
        }];
        let stats = FsStats {
            total_bytes: 100,
            free_bytes: 80,
            available_bytes: 80,
            fs_type: "tmpfs".to_string(),
            mount_point: PathBuf::from("/tmp"),
            is_readonly: false,
        };
        let platform = Arc::new(CountingPlatform::new(
            mounts,
            HashMap::from([(PathBuf::from("/tmp"), stats)]),
        ));
        let collector = FsStatsCollector::new(platform.clone(), Duration::from_secs(10));

        // Two collect calls should only read mount_points() once.
        let _ = collector.collect(Path::new("/tmp/a")).expect("first");
        let _ = collector.collect(Path::new("/tmp/b")).expect("second");
        assert_eq!(platform.mount_points_calls.load(Ordering::SeqCst), 1);

        // collect_many should also reuse the cached mounts.
        let _ = collector
            .collect_many(&[PathBuf::from("/tmp/c")])
            .expect("many");
        assert_eq!(platform.mount_points_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn prune_clears_expired_mount_cache() {
        let mounts = vec![MountPoint {
            path: PathBuf::from("/tmp"),
            device: "tmpfs".to_string(),
            fs_type: "tmpfs".to_string(),
            is_ram_backed: true,
        }];
        let stats = FsStats {
            total_bytes: 100,
            free_bytes: 80,
            available_bytes: 80,
            fs_type: "tmpfs".to_string(),
            mount_point: PathBuf::from("/tmp"),
            is_readonly: false,
        };
        let platform = Arc::new(CountingPlatform::new(
            mounts,
            HashMap::from([(PathBuf::from("/tmp"), stats)]),
        ));
        // Zero TTL so caches expire immediately.
        let collector = FsStatsCollector::new(platform.clone(), Duration::ZERO);

        let _ = collector.collect(Path::new("/tmp/a")).expect("first");
        assert_eq!(platform.mount_points_calls.load(Ordering::SeqCst), 1);

        std::thread::sleep(Duration::from_millis(1));
        collector.prune_expired_cache();

        // After prune, mount cache is cleared; next collect reads mount_points() again.
        let _ = collector.collect(Path::new("/tmp/a")).expect("second");
        assert_eq!(platform.mount_points_calls.load(Ordering::SeqCst), 2);
    }

    #[cfg(unix)]
    #[test]
    fn collect_resolves_symlink_path_to_mount() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().expect("tempdir");
        let mount_real = tmp.path().join("mount-real");
        std::fs::create_dir_all(&mount_real).expect("create mount");
        let link_mount = tmp.path().join("mount-link");
        symlink(&mount_real, &link_mount).expect("create symlink");
        std::fs::create_dir_all(link_mount.join("work")).expect("create child");

        let mounts = vec![MountPoint {
            path: mount_real.clone(),
            device: "dev".to_string(),
            fs_type: "ext4".to_string(),
            is_ram_backed: false,
        }];
        let stats = FsStats {
            total_bytes: 100,
            free_bytes: 60,
            available_bytes: 60,
            fs_type: "ext4".to_string(),
            mount_point: mount_real.clone(),
            is_readonly: false,
        };
        let platform = Arc::new(CountingPlatform::new(
            mounts,
            HashMap::from([(mount_real, stats.clone())]),
        ));
        let collector = FsStatsCollector::new(platform.clone(), Duration::from_secs(5));

        let observed = collector
            .collect(&link_mount.join("work"))
            .expect("symlink path should resolve to mount");
        assert_eq!(observed, stats);
        assert_eq!(platform.fs_stats_calls.load(Ordering::SeqCst), 1);
    }
}
