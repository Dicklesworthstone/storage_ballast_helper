//! Filesystem statistics collector: statvfs wrapper, usage percentages, inode tracking.

#![allow(missing_docs)]

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use crate::core::errors::{Result, SbhError};
use crate::platform::pal::{FsStats, MountPoint, Platform};

#[derive(Debug, Clone)]
struct CachedStats {
    binding: MountBinding,
    stats: FsStats,
    collected_at: Instant,
}

/// The PAL's ownership evidence, including the resolved mount spelling.
/// A reused pathname alone is not a cache identity.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MountBinding {
    path: PathBuf,
    resolved: PathBuf,
    device: String,
    fs_type: String,
    is_ram_backed: bool,
}

impl MountBinding {
    fn of(mount: &MountPoint) -> Self {
        Self {
            path: mount.path.clone(),
            resolved: crate::core::paths::resolve_absolute_path(&mount.path),
            device: mount.device.clone(),
            fs_type: mount.fs_type.clone(),
            is_ram_backed: mount.is_ram_backed,
        }
    }
}

#[derive(Debug, Clone)]
struct MountSnapshot {
    bindings: Vec<MountBinding>,
    collected_at: Instant,
    generation: u64,
}

#[derive(Default)]
struct CollectorState {
    cache: HashMap<PathBuf, CachedStats>,
    mounts: Option<MountSnapshot>,
    generation: u64,
}

/// Cache-aware, mount-deduplicating filesystem statistics collector.
///
/// Readings belong to a discovered mount binding, not merely its path. A
/// topology refresh invalidates changed bindings, and an in-flight read from
/// an older discovery cannot publish into the new snapshot. This is a cache
/// consistency contract, not an atomic kernel mount-namespace snapshot: the
/// PAL and configured discovery TTL still bound detection of mount changes.
pub struct FsStatsCollector {
    platform: Arc<dyn Platform>,
    cache_ttl: Duration,
    state: RwLock<CollectorState>,
}

impl FsStatsCollector {
    #[must_use]
    pub fn new(platform: Arc<dyn Platform>, cache_ttl: Duration) -> Self {
        Self {
            platform,
            cache_ttl,
            state: RwLock::new(CollectorState::default()),
        }
    }

    pub fn collect(&self, path: &Path) -> Result<FsStats> {
        let mounts = self.cached_mounts()?;
        let lookup_path = self.platform.mount_lookup_path(path)?;
        let mount =
            find_mount(&lookup_path, &mounts.bindings).ok_or_else(|| SbhError::FsStats {
                path: path.to_path_buf(),
                details: "path does not belong to known mount".to_string(),
            })?;
        self.collect_for_mount(mount, mounts.generation)
    }

    pub fn collect_many(&self, paths: &[PathBuf]) -> Result<HashMap<PathBuf, FsStats>> {
        if paths.is_empty() {
            return Ok(HashMap::new());
        }
        let mounts = self.cached_mounts()?;
        let resolved_paths: Vec<PathBuf> = paths
            .iter()
            .map(|path| self.platform.mount_lookup_path(path))
            .collect::<Result<_>>()?;
        let mut mounts_needed = BTreeMap::new();
        let mut owners = Vec::with_capacity(paths.len());
        for (path, resolved_path) in paths.iter().zip(&resolved_paths) {
            let Some(mount) = find_mount(resolved_path, &mounts.bindings) else {
                return Err(SbhError::FsStats {
                    path: path.clone(),
                    details: "path does not belong to known mount".to_string(),
                });
            };
            mounts_needed.insert(mount.path.clone(), mount);
            owners.push((path, mount));
        }

        let mut per_mount = HashMap::<PathBuf, FsStats>::new();
        for (mount_path, mount) in mounts_needed {
            let stats = self.collect_for_mount(mount, mounts.generation)?;
            per_mount.insert(mount_path, stats);
        }

        // Do not assemble a batch across different topology generations.
        let state = self.state.read();
        ensure_generation(&state, mounts.generation, &paths[0])?;
        let mut out = HashMap::with_capacity(paths.len());
        for (path, mount) in owners {
            let reading = per_mount
                .get(&mount.path)
                .cloned()
                .ok_or_else(|| SbhError::FsStats {
                    path: mount.path.clone(),
                    details: "mount stats missing after collection".to_string(),
                })?;
            out.insert(path.clone(), reading);
        }

        Ok(out)
    }

    pub fn prune_expired_cache(&self) {
        let now = Instant::now();
        let ttl = self.cache_ttl;
        let mut state = self.state.write();
        state
            .cache
            .retain(|_, entry| now.duration_since(entry.collected_at) <= ttl);

        if state
            .mounts
            .as_ref()
            .is_some_and(|snapshot| now.duration_since(snapshot.collected_at) > ttl)
        {
            state.mounts = None;
        }
    }

    pub fn set_ttl(&mut self, ttl: Duration) {
        if self.cache_ttl == ttl {
            return;
        }
        self.cache_ttl = ttl;
        // Increasing a TTL must not resurrect evidence that already expired.
        let state = self.state.get_mut();
        state.cache.clear();
        state.mounts = None;
    }

    fn cached_mounts(&self) -> Result<MountSnapshot> {
        {
            let state = self.state.read();
            if let Some(snapshot) = &state.mounts
                && snapshot.collected_at.elapsed() <= self.cache_ttl
            {
                return Ok(snapshot.clone());
            }
        }
        // Serialize discoveries, not capacity probes. An older slow discovery
        // cannot overwrite a newer topology, and concurrent misses share it.
        let mut state = self.state.write();
        if let Some(snapshot) = &state.mounts
            && snapshot.collected_at.elapsed() <= self.cache_ttl
        {
            return Ok(snapshot.clone());
        }
        state.mounts = None;
        let collected_at = Instant::now();
        let bindings: Vec<_> = self
            .platform
            .mount_points()?
            .iter()
            .map(MountBinding::of)
            .collect();
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or_else(|| SbhError::FsStats {
                path: PathBuf::from("/"),
                details: "mount discovery generation exhausted".to_string(),
            })?;
        let snapshot = MountSnapshot {
            bindings,
            collected_at,
            generation: state.generation,
        };
        state
            .cache
            .retain(|_, entry| snapshot.bindings.contains(&entry.binding));
        state.mounts = Some(snapshot.clone());
        drop(state);
        Ok(snapshot)
    }

    fn collect_for_mount(&self, mount: &MountBinding, generation: u64) -> Result<FsStats> {
        let collected_at = Instant::now();
        if crate::core::paths::resolve_absolute_path(&mount.path) != mount.resolved {
            self.invalidate(mount, generation, collected_at);
            return Err(changed_mount(&mount.path));
        }
        {
            let state = self.state.read();
            ensure_generation(&state, generation, &mount.path)?;
            if let Some(hit) = state.cache.get(&mount.path)
                && hit.binding == *mount
                && hit.collected_at.elapsed() <= self.cache_ttl
            {
                return Ok(hit.stats.clone());
            }
        }

        let fresh = match self.platform.fs_stats(&mount.path) {
            Ok(fresh) => fresh,
            Err(error) => {
                self.invalidate(mount, generation, collected_at);
                return Err(error);
            }
        };
        if crate::core::paths::resolve_absolute_path(&mount.path) != mount.resolved
            || crate::core::paths::resolve_absolute_path(&fresh.mount_point) != mount.resolved
            || fresh.fs_type != mount.fs_type
        {
            self.invalidate(mount, generation, collected_at);
            return Err(changed_mount(&mount.path));
        }
        let mut state = self.state.write();
        ensure_generation(&state, generation, &mount.path)?;
        if state
            .cache
            .get(&mount.path)
            .is_some_and(|entry| entry.collected_at > collected_at)
        {
            // Capacity probes need not finish in the order they started.
            // Never replace a later observation with this older result.
            return Err(SbhError::FsStats {
                path: mount.path.clone(),
                details: "filesystem reading superseded by a newer observation".to_string(),
            });
        }
        state.cache.insert(
            mount.path.clone(),
            CachedStats {
                binding: mount.clone(),
                stats: fresh.clone(),
                collected_at,
            },
        );
        drop(state);
        Ok(fresh)
    }

    fn invalidate(&self, mount: &MountBinding, generation: u64, started: Instant) {
        let mut state = self.state.write();
        // A late error from an obsolete probe must not evict a newer reading.
        if state
            .cache
            .get(&mount.path)
            .is_some_and(|entry| entry.collected_at > started)
        {
            return;
        }
        if state
            .mounts
            .as_ref()
            .is_some_and(|snapshot| snapshot.generation == generation)
        {
            state.cache.remove(&mount.path);
            state.mounts = None;
        }
    }
}

fn changed_mount(path: &Path) -> SbhError {
    SbhError::FsStats {
        path: path.to_path_buf(),
        details: "mount ownership changed during collection; rediscovery required".to_string(),
    }
}

fn ensure_generation(state: &CollectorState, generation: u64, path: &Path) -> Result<()> {
    if state
        .mounts
        .as_ref()
        .is_some_and(|snapshot| snapshot.generation == generation)
    {
        Ok(())
    } else {
        Err(changed_mount(path))
    }
}

fn find_mount<'a>(path: &Path, mounts: &'a [MountBinding]) -> Option<&'a MountBinding> {
    mounts
        .iter()
        .filter(|mount| path.starts_with(&mount.resolved))
        // Compare the prefix that matched, not the length of a symlink alias.
        .max_by_key(|mount| mount.resolved.components().count())
}

#[cfg(test)]
mod topology_tests;

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
