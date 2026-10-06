//! A discovery can expire before a more recently collected capacity sample.
//! Reproduce that ordering without sleeping, including actual in-flight reads.

use super::*;
use crate::platform::pal::{MemoryInfo, NoopServiceManager, PlatformPaths, ServiceManager};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

struct ProbeGate {
    entered: SyncSender<()>,
    resume: Receiver<()>,
}

#[derive(Default)]
struct ChangingPlatform {
    mounts: RwLock<Vec<MountPoint>>,
    stats: RwLock<HashMap<PathBuf, FsStats>>,
    calls: Mutex<Vec<PathBuf>>,
    discoveries: AtomicUsize,
    fail_discovery: AtomicBool,
    next_probe: Mutex<Option<ProbeGate>>,
}

impl ChangingPlatform {
    fn install(&self, mount: MountPoint, free: u64) {
        self.stats.write().insert(
            mount.path.clone(),
            FsStats {
                total_bytes: 100,
                free_bytes: free,
                available_bytes: free,
                fs_type: mount.fs_type.clone(),
                mount_point: mount.path.clone(),
                is_readonly: false,
            },
        );
        let mut mounts = self.mounts.write();
        mounts.retain(|old| old.path != mount.path);
        mounts.push(mount);
    }

    fn pause_next_probe(&self) -> (Receiver<()>, SyncSender<()>) {
        let (entered_tx, entered_rx) = sync_channel(1);
        let (resume_tx, resume_rx) = sync_channel(1);
        *self.next_probe.lock() = Some(ProbeGate {
            entered: entered_tx,
            resume: resume_rx,
        });
        (entered_rx, resume_tx)
    }
}

impl Platform for ChangingPlatform {
    fn fs_stats(&self, path: &Path) -> Result<FsStats> {
        self.calls.lock().push(path.to_path_buf());
        // Capture the old result before blocking, including an old failure.
        let observed = self.stats.read().get(path).cloned();
        let gate = self.next_probe.lock().take();
        if let Some(gate) = gate {
            gate.entered.send(()).expect("probe observer");
            gate.resume
                .recv_timeout(Duration::from_secs(5))
                .expect("release blocked probe");
        }
        observed.ok_or_else(|| SbhError::FsStats {
            path: path.to_path_buf(),
            details: "injected unavailable filesystem".to_string(),
        })
    }

    fn mount_points(&self) -> Result<Vec<MountPoint>> {
        self.discoveries.fetch_add(1, Ordering::SeqCst);
        if self.fail_discovery.load(Ordering::SeqCst) {
            return Err(SbhError::FsStats {
                path: PathBuf::from("/"),
                details: "injected unavailable mount inventory".to_string(),
            });
        }
        Ok(self.mounts.read().clone())
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
        Box::new(NoopServiceManager)
    }
}

fn mount(path: &Path, device: &str) -> MountPoint {
    MountPoint {
        path: path.to_path_buf(),
        device: device.to_string(),
        fs_type: "ext4".to_string(),
        is_ram_backed: false,
    }
}

type Fixture = (
    tempfile::TempDir,
    PathBuf,
    Arc<ChangingPlatform>,
    Arc<FsStatsCollector>,
);

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let path = std::fs::canonicalize(temp.path()).unwrap();
    let platform = Arc::new(ChangingPlatform::default());
    platform.install(mount(&path, "device-a"), 80);
    let collector = Arc::new(FsStatsCollector::new(
        platform.clone(),
        Duration::from_secs(60),
    ));
    (temp, path, platform, collector)
}

fn expire_discovery(collector: &FsStatsCollector) {
    collector.state.write().mounts.as_mut().unwrap().collected_at =
        Instant::now().checked_sub(Duration::from_hours(1)).unwrap();
}

fn expire_sample(collector: &FsStatsCollector, path: &Path) {
    collector.state.write().cache.get_mut(path).unwrap().collected_at =
        Instant::now().checked_sub(Duration::from_hours(1)).unwrap();
}

#[test]
fn refreshed_device_type_and_ram_bindings_do_not_reuse_a_paths_old_capacity() {
    for changed_field in 0..3 {
        let (_temp, path, platform, collector) = fixture();
        assert_eq!(collector.collect(&path).unwrap().available_bytes, 80);
        let mut replacement = mount(&path, "device-a");
        match changed_field {
            0 => replacement.device = "device-b".to_string(),
            1 => replacement.fs_type = "xfs".to_string(),
            _ => replacement.is_ram_backed = true,
        }
        platform.install(replacement, 2);
        // Only the discovery aged out. The old capacity sample is still fresh.
        expire_discovery(&collector);
        assert_eq!(collector.collect(&path).unwrap().available_bytes, 2);
        assert_eq!(platform.calls.lock().len(), 2);
    }
}

#[test]
fn rebinding_one_mount_preserves_an_unrelated_mounts_fresh_sample() {
    let (_temp, path, platform, collector) = fixture();
    let other = path.join("other");
    std::fs::create_dir(&other).unwrap();
    platform.install(mount(&other, "device-other"), 45);
    collector.collect(&path).unwrap();
    collector.collect(&other).unwrap();
    platform.install(mount(&path, "replacement"), 3);
    expire_discovery(&collector);
    assert_eq!(collector.collect(&path).unwrap().available_bytes, 3);
    assert_eq!(collector.collect(&other).unwrap().available_bytes, 45);
    assert_eq!(platform.calls.lock().len(), 3);
}

#[test]
fn removed_mount_and_failed_discovery_never_become_zero_or_stale_readings() {
    let (_temp, path, platform, collector) = fixture();
    collector.collect(&path).unwrap();
    expire_discovery(&collector);
    platform.fail_discovery.store(true, Ordering::SeqCst);
    assert!(collector.collect(&path).is_err());
    assert!(collector.state.read().mounts.is_none());
    platform.fail_discovery.store(false, Ordering::SeqCst);
    platform.mounts.write().clear();
    assert!(collector.collect(&path).is_err());
    assert!(collector.state.read().cache.is_empty());
    assert_eq!(platform.calls.lock().len(), 1);
}

#[test]
fn reported_parent_filesystem_is_rejected_and_triggers_rediscovery() {
    let (_temp, path, platform, collector) = fixture();
    platform.stats.write().get_mut(&path).unwrap().mount_point = PathBuf::from("/");
    assert!(
        collector
            .collect(&path)
            .unwrap_err()
            .to_string()
            .contains("ownership changed")
    );
    assert!(collector.state.read().cache.is_empty());
    platform.install(mount(&path, "device-a"), 15);
    assert_eq!(collector.collect(&path).unwrap().available_bytes, 15);
    assert_eq!(platform.discoveries.load(Ordering::SeqCst), 2);
}

#[test]
fn reported_type_change_is_unknown_until_a_consistent_discovery() {
    let (_temp, path, platform, collector) = fixture();
    platform.stats.write().get_mut(&path).unwrap().fs_type = "xfs".to_string();
    assert!(collector.collect(&path).is_err());
    assert!(collector.state.read().cache.is_empty());
    let mut replacement = mount(&path, "device-b");
    replacement.fs_type = "xfs".to_string();
    platform.install(replacement, 5);
    assert_eq!(collector.collect(&path).unwrap().fs_type, "xfs");
}

#[test]
fn in_flight_old_success_cannot_publish_over_a_new_mount() {
    let (_temp, path, platform, collector) = fixture();
    collector.collect(&path).unwrap();
    expire_sample(&collector, &path);
    let (entered, resume) = platform.pause_next_probe();
    let worker_collector = collector.clone();
    let worker_path = path.clone();
    let worker = std::thread::spawn(move || worker_collector.collect(&worker_path));
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    platform.install(mount(&path, "device-b"), 2);
    expire_discovery(&collector);
    let current = collector.collect(&path);
    // Always unblock and join before asserting the replacement's result.
    resume.send(()).unwrap();
    let old = worker.join().unwrap();
    assert_eq!(current.unwrap().available_bytes, 2);
    assert!(old.is_err());
    assert_eq!(collector.collect(&path).unwrap().available_bytes, 2);
    assert_eq!(platform.calls.lock().len(), 3);
}

#[test]
fn late_old_failure_does_not_evict_a_new_mounts_reading() {
    let (_temp, path, platform, collector) = fixture();
    collector.collect(&path).unwrap();
    expire_sample(&collector, &path);
    platform.stats.write().remove(&path);
    let (entered, resume) = platform.pause_next_probe();
    let worker_collector = collector.clone();
    let worker_path = path.clone();
    let worker = std::thread::spawn(move || worker_collector.collect(&worker_path));
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    platform.install(mount(&path, "device-b"), 7);
    expire_discovery(&collector);
    let current = collector.collect(&path);
    resume.send(()).unwrap();
    let old = worker.join().unwrap();
    assert_eq!(current.unwrap().available_bytes, 7);
    assert!(old.is_err());
    assert_eq!(collector.collect(&path).unwrap().available_bytes, 7);
    assert_eq!(platform.discoveries.load(Ordering::SeqCst), 2);
    assert_eq!(platform.calls.lock().len(), 3);
}

#[test]
fn late_capacity_success_or_error_cannot_erase_a_newer_same_mount_sample() {
    for fail_old in [false, true] {
        let (_temp, path, platform, collector) = fixture();
        collector.collect(&path).unwrap();
        expire_sample(&collector, &path);
        if fail_old {
            platform.stats.write().remove(&path);
        }
        let (entered, resume) = platform.pause_next_probe();
        let worker_collector = collector.clone();
        let worker_path = path.clone();
        let worker = std::thread::spawn(move || worker_collector.collect(&worker_path));
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        // No topology refresh: a second capacity sample finishes first.
        platform.install(mount(&path, "device-a"), 1);
        let current = collector.collect(&path);
        resume.send(()).unwrap();
        let old = worker.join().unwrap();
        assert_eq!(current.unwrap().available_bytes, 1);
        assert!(old.is_err());
        assert_eq!(collector.collect(&path).unwrap().available_bytes, 1);
        assert_eq!(platform.discoveries.load(Ordering::SeqCst), 1);
        assert_eq!(platform.calls.lock().len(), 3);
    }
}

#[test]
fn failed_current_probe_is_not_cached_and_can_recover_on_the_next_collection() {
    let (_temp, path, platform, collector) = fixture();
    collector.collect(&path).unwrap();
    expire_sample(&collector, &path);
    platform.stats.write().remove(&path);
    assert!(collector.collect(&path).is_err());
    assert!(!collector.state.read().cache.contains_key(&path));
    platform.install(mount(&path, "device-a"), 9);
    assert_eq!(collector.collect(&path).unwrap().available_bytes, 9);
    assert_eq!(platform.discoveries.load(Ordering::SeqCst), 2);
}

#[test]
fn changing_the_ttl_cannot_resurrect_an_expired_sample() {
    let (_temp, path, platform, collector) = fixture();
    collector.collect(&path).unwrap();
    expire_sample(&collector, &path);
    platform.install(mount(&path, "device-a"), 10);
    let mut collector = Arc::try_unwrap(collector).ok().unwrap();
    collector.set_ttl(Duration::from_hours(2));
    assert_eq!(collector.collect(&path).unwrap().available_bytes, 10);
    assert_eq!(platform.calls.lock().len(), 2);
}

#[test]
fn a_batch_deduplicates_mount_probes_and_has_deterministic_probe_order() {
    let (_temp, path, platform, collector) = fixture();
    let child = path.join("nested");
    std::fs::create_dir(&child).unwrap();
    platform.install(mount(&child, "nested-device"), 4);
    let inputs = vec![
        child.join("a"),
        path.join("b"),
        child.join("c"),
        path.join("b"),
    ];
    let result = collector.collect_many(&inputs).unwrap();
    assert_eq!(result.len(), 3);
    assert_eq!(result[&inputs[0]].available_bytes, 4);
    assert_eq!(result[&inputs[1]].available_bytes, 80);
    assert_eq!(*platform.calls.lock(), vec![path, child]);
}

#[cfg(unix)]
#[test]
fn a_long_parent_alias_cannot_outrank_a_deeper_resolved_mount() {
    use std::os::unix::fs::symlink;
    let (_temp, path, platform, collector) = fixture();
    let alias = path.join("a-deliberately-long-parent-alias");
    let deep = path.join("x");
    std::fs::create_dir(&deep).unwrap();
    std::fs::create_dir(deep.join("work")).unwrap();
    symlink(&path, &alias).unwrap();
    platform.mounts.write().clear();
    platform.install(mount(&alias, "parent"), 80);
    platform.install(mount(&deep, "nested"), 1);
    assert!(alias.as_os_str().len() > deep.as_os_str().len());
    let result = collector.collect(&deep.join("work")).unwrap();
    assert_eq!(result.mount_point, deep);
    assert_eq!(result.available_bytes, 1);
    assert_eq!(platform.calls.lock().len(), 1);
}

#[cfg(unix)]
#[test]
fn alias_retargeting_is_part_of_cache_ownership_even_with_unchanged_pal_labels() {
    use std::os::unix::fs::symlink;
    let (_temp, path, platform, collector) = fixture();
    let first = path.join("first");
    let second = path.join("second");
    let alias = path.join("alias");
    std::fs::create_dir(&first).unwrap();
    std::fs::create_dir(&second).unwrap();
    symlink(&first, &alias).unwrap();
    platform.mounts.write().clear();
    platform.install(mount(&alias, "same-label"), 80);
    assert_eq!(collector.collect(&alias).unwrap().available_bytes, 80);
    // Rename the old link away rather than changing its referent or payload.
    std::fs::rename(&alias, path.join("retired-alias")).unwrap();
    symlink(&second, &alias).unwrap();
    platform.install(mount(&alias, "same-label"), 6);
    expire_discovery(&collector);
    assert_eq!(collector.collect(&alias).unwrap().available_bytes, 6);
    assert_eq!(platform.calls.lock().len(), 2);
    assert!(first.is_dir() && second.is_dir());
}
