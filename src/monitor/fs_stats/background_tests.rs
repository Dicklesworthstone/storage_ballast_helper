//! Exercise the actual PAL-to-background-collector boundary. Channel gates
//! stall individual native operations without sleeping or hanging the suite.

use super::*;
use crate::platform::pal::{MemoryInfo, NoopServiceManager, PlatformPaths, ServiceManager};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

const WAIT: Duration = Duration::from_secs(5);
const CACHE: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Stage {
    Lookup,
    Owner,
    Capacity,
    Inodes,
    Ram,
    Inventory,
    FullCapacity,
    CapacityMetadata,
}

struct Gate {
    entered: SyncSender<()>,
    resume: Receiver<()>,
}

#[derive(Default)]
struct IsolatedPlatform {
    mounts: RwLock<Vec<MountPoint>>,
    gates: Mutex<BTreeMap<(Stage, PathBuf), Gate>>,
    calls: Mutex<Vec<(Stage, PathBuf)>>,
    rewrite: RwLock<Option<(PathBuf, PathBuf)>>,
    invalid_inodes: AtomicBool,
    capacity_metadata: AtomicBool,
}

impl IsolatedPlatform {
    fn install(&self, path: &Path, device: &str) {
        let mut mounts = self.mounts.write();
        mounts.retain(|mount| mount.path != path);
        mounts.push(MountPoint {
            path: path.to_path_buf(),
            device: device.to_string(),
            fs_type: "ext4".to_string(),
            is_ram_backed: false,
        });
    }

    fn gate(&self, stage: Stage, path: &Path) -> (Receiver<()>, SyncSender<()>) {
        if stage == Stage::CapacityMetadata {
            self.capacity_metadata.store(true, Ordering::SeqCst);
        }
        let (entered_tx, entered_rx) = sync_channel(1);
        let (resume_tx, resume_rx) = sync_channel(1);
        self.gates.lock().insert(
            (stage, path.to_path_buf()),
            Gate {
                entered: entered_tx,
                resume: resume_rx,
            },
        );
        (entered_rx, resume_tx)
    }

    fn enter(&self, stage: Stage, path: &Path) {
        let key = (stage, path.to_path_buf());
        self.calls.lock().push(key.clone());
        let gate = self.gates.lock().remove(&key);
        if let Some(gate) = gate {
            gate.entered.send(()).unwrap();
            gate.resume
                .recv_timeout(WAIT)
                .expect("release native probe");
        }
    }

    fn owner(&self, path: &Path) -> Result<MountPoint> {
        self.mounts
            .read()
            .iter()
            .filter(|mount| path.starts_with(&mount.path))
            .max_by_key(|mount| mount.path.components().count())
            .cloned()
            .ok_or_else(|| SbhError::FsStats {
                path: path.to_path_buf(),
                details: "injected unknown owner".to_string(),
            })
    }

    fn native_stats(&self, path: &Path) -> Result<FsStats> {
        // Capture before pausing so replacement tests return the old frame.
        let owner = self.owner(path)?;
        self.enter(Stage::Capacity, path);
        Ok(FsStats {
            total_bytes: 100,
            free_bytes: 80,
            available_bytes: 75,
            fs_type: owner.fs_type,
            mount_point: owner.path,
            is_readonly: false,
        })
    }
}

impl Platform for IsolatedPlatform {
    fn fs_stats(&self, path: &Path) -> Result<FsStats> {
        self.enter(Stage::FullCapacity, path);
        self.native_stats(path)
    }

    fn observe_fs_stats(&self, path: &Path) -> Result<FsStats> {
        self.native_stats(path)
    }

    fn has_capacity_metadata(&self) -> bool {
        self.capacity_metadata.load(Ordering::SeqCst)
    }

    fn refresh_capacity_metadata(&self) -> Result<()> {
        self.enter(Stage::CapacityMetadata, Path::new("/"));
        Ok(())
    }

    fn inode_stats(&self, path: &Path) -> Result<Option<InodeStats>> {
        self.enter(Stage::Inodes, path);
        Ok(Some(InodeStats {
            total: 100,
            free: 80,
            available: if self.invalid_inodes.load(Ordering::SeqCst) {
                90
            } else {
                70
            },
        }))
    }

    fn mount_points(&self) -> Result<Vec<MountPoint>> {
        self.enter(Stage::Inventory, Path::new("/"));
        Ok(self.mounts.read().clone())
    }

    fn mount_identity(&self, path: &Path) -> Result<MountPoint> {
        self.enter(Stage::Owner, path);
        self.owner(path)
    }

    fn mount_lookup_path(&self, path: &Path) -> Result<PathBuf> {
        self.enter(Stage::Lookup, path);
        if let Some((from, to)) = &*self.rewrite.read()
            && let Ok(suffix) = path.strip_prefix(from)
        {
            return Ok(to.join(suffix));
        }
        Ok(path.to_path_buf())
    }

    fn is_ram_backed(&self, path: &Path) -> Result<bool> {
        self.enter(Stage::Ram, path);
        Ok(self.owner(path)?.is_ram_backed)
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

fn fixture() -> (tempfile::TempDir, PathBuf, Arc<IsolatedPlatform>) {
    let temporary = tempfile::tempdir().unwrap();
    let path = std::fs::canonicalize(temporary.path()).unwrap();
    let platform = Arc::new(IsolatedPlatform::default());
    platform.install(Path::new("/"), "root-device");
    platform.install(&path, "temporary-device");
    (temporary, path, platform)
}

fn await_sample(collector: &FsStatsCollector, path: &Path) -> FsStatsSample {
    let deadline = Instant::now() + WAIT;
    loop {
        match collector.collect_sample(path) {
            Ok(sample) => return sample,
            Err(error) => assert!(
                Instant::now() < deadline,
                "probe failed to complete: {error}"
            ),
        }
        std::thread::yield_now();
    }
}

fn await_error(collector: &FsStatsCollector, path: &Path, expected: &str) {
    let deadline = Instant::now() + WAIT;
    loop {
        match collector.collect_sample(path) {
            Ok(_) => panic!("invalid frame became authoritative"),
            Err(error) => {
                if error.to_string().contains(expected) {
                    return;
                }
                assert!(
                    Instant::now() < deadline,
                    "expected {expected:?}, received {error}"
                );
            }
        }
        std::thread::yield_now();
    }
}

#[test]
fn every_native_pressure_stage_is_isolated_from_a_stalled_peer() {
    for stage in [
        Stage::Lookup,
        Stage::Owner,
        Stage::Capacity,
        Stage::Inodes,
        Stage::Ram,
    ] {
        let (_temporary, path, platform) = fixture();
        let (entered, resume) = platform.gate(stage, &path);
        let collector = FsStatsCollector::new_background(platform, CACHE, CACHE);
        assert!(collector.collect(&path).is_err());
        entered.recv_timeout(WAIT).unwrap();
        // The other worker remains inside its gated native call throughout
        // this successful root observation and all its auxiliary probes.
        let healthy = await_sample(&collector, Path::new("/"));
        assert_eq!(healthy.stats.mount_point, Path::new("/"), "{stage:?}");
        assert_eq!(healthy.inode_stats().unwrap().available, 70);
        assert_eq!(healthy.is_ram_backed(), Some(false));
        resume.send(()).unwrap();
        assert_eq!(await_sample(&collector, &path).stats.mount_point, path);
    }
}

#[test]
fn blocked_inventory_and_unrelated_aliases_do_not_block_targeted_collection() {
    let (_temporary, path, platform) = fixture();
    let unrelated = path.join("unrelated-unavailable-alias");
    platform.install(&unrelated, "unavailable-device");
    let (inventory_entered, inventory_resume) = platform.gate(Stage::Inventory, Path::new("/"));
    let (alias_entered, alias_resume) = platform.gate(Stage::Lookup, &unrelated);
    let collector = FsStatsCollector::new_background(platform.clone(), CACHE, CACHE);
    assert!(collector.mount_points().is_err());
    inventory_entered.recv_timeout(WAIT).unwrap();
    let sample = await_sample(&collector, &path);
    assert_eq!(sample.stats.mount_point, path);
    assert!(alias_entered.try_recv().is_err());
    assert_eq!(
        platform
            .calls
            .lock()
            .iter()
            .filter(|(stage, _)| *stage == Stage::Inventory)
            .count(),
        1
    );
    assert!(
        !platform
            .calls
            .lock()
            .iter()
            .any(|(_, queried)| queried == &unrelated)
    );
    inventory_resume.send(()).unwrap();
    drop(alias_resume);
}

#[test]
fn cached_frame_carries_native_auxiliary_evidence_without_reprobing() {
    let (_temporary, path, platform) = fixture();
    let collector = FsStatsCollector::new_background(platform.clone(), CACHE, CACHE);
    let first = await_sample(&collector, &path);
    let call_count = platform.calls.lock().len();
    let second = collector.collect_sample(&path).unwrap();
    assert_eq!(first.collected_at, second.collected_at);
    assert!(first.same_filesystem_as(&second));
    assert_eq!(platform.calls.lock().len(), call_count);
    assert_eq!(second.inode_stats(), InodeStats::new(100, 80, 70));
    assert_eq!(second.is_ram_backed(), Some(false));
    assert_eq!(second.query_directory(), first.query_directory());
    assert_eq!(
        second.query_directory(),
        ObservedDirectory::collect(&path).as_ref()
    );
    #[cfg(unix)]
    assert_eq!(
        second.mount_device_id(),
        mount_directory_identity(&path).unwrap().map(|(dev, _)| dev)
    );
}

#[test]
fn synchronous_collector_does_not_add_auxiliary_native_calls() {
    let (_temporary, path, platform) = fixture();
    let collector = FsStatsCollector::new(platform.clone(), CACHE);
    let sample = collector.collect_sample(&path).unwrap();
    assert!(!collector.is_background());
    assert!(sample.inode_stats().is_none());
    assert!(sample.is_ram_backed().is_none());
    assert!(sample.mount_device_id().is_none());
    assert!(
        !platform
            .calls
            .lock()
            .iter()
            .any(|(stage, _)| matches!(stage, Stage::Inodes | Stage::Ram | Stage::Owner))
    );
}

#[test]
fn replaced_mount_cannot_publish_a_paused_old_frame() {
    let (_temporary, path, platform) = fixture();
    let (entered, resume) = platform.gate(Stage::Capacity, &path);
    let collector = FsStatsCollector::new_background(platform.clone(), CACHE, CACHE);
    assert!(collector.collect(&path).is_err());
    entered.recv_timeout(WAIT).unwrap();
    platform.install(&path, "replacement-device");
    resume.send(()).unwrap();
    await_error(&collector, &path, "mount ownership changed");
    collector.invalidate_observations();
    let fresh = await_sample(&collector, &path);
    assert_eq!(fresh.binding.device, "replacement-device");
}

#[cfg(unix)]
#[test]
fn reused_directory_path_cannot_preserve_a_replaced_inode_identity() {
    let (_temporary, path, platform) = fixture();
    let owner = path.join("mount");
    std::fs::create_dir(&owner).unwrap();
    platform.install(&owner, "same-device");
    let (entered, resume) = platform.gate(Stage::Capacity, &owner);
    let collector = FsStatsCollector::new_background(platform, CACHE, CACHE);
    assert!(collector.collect(&owner).is_err());
    entered.recv_timeout(WAIT).unwrap();
    std::fs::rename(&owner, path.join("detached-mount")).unwrap();
    std::fs::create_dir(&owner).unwrap();
    resume.send(()).unwrap();
    await_error(&collector, &owner, "mount ownership changed");
}

#[cfg(unix)]
#[test]
fn replaced_query_directory_cannot_publish_admission_on_an_unchanged_mount() {
    let (_temporary, mount, platform) = fixture();
    let query = mount.join("configured-root");
    std::fs::create_dir(&query).unwrap();
    let (entered, resume) = platform.gate(Stage::Capacity, &mount);
    let collector = FsStatsCollector::new_background(platform, CACHE, CACHE);
    assert!(collector.collect(&query).is_err());
    entered.recv_timeout(WAIT).unwrap();
    std::fs::rename(&query, mount.join("retired-root")).unwrap();
    std::fs::create_dir(&query).unwrap();
    resume.send(()).unwrap();
    await_error(&collector, &query, "mount ownership changed");

    collector.invalidate_observations();
    let fresh = await_sample(&collector, &query);
    assert_eq!(
        fresh.query_directory(),
        ObservedDirectory::collect(&query).as_ref()
    );
    assert_eq!(fresh.stats.mount_point, mount);
}

#[test]
fn a_file_capacity_query_cannot_become_directory_admission() {
    let (_temporary, mount, platform) = fixture();
    let query = mount.join("state.json");
    std::fs::write(&query, b"{}").unwrap();
    let collector = FsStatsCollector::new_background(platform, CACHE, CACHE);
    let sample = await_sample(&collector, &query);
    assert_eq!(sample.stats.mount_point, mount);
    assert!(sample.query_directory().is_none());
}

#[test]
fn incomplete_batch_still_starts_later_healthy_roots() {
    let (_temporary, path, platform) = fixture();
    let (entered, resume) = platform.gate(Stage::Capacity, &path);
    let collector = FsStatsCollector::new_background(platform.clone(), CACHE, CACHE);
    assert!(collector.collect_many(&[path, PathBuf::from("/")]).is_err());
    entered.recv_timeout(WAIT).unwrap();
    let deadline = Instant::now() + WAIT;
    // Observe the native call without issuing another root request. This
    // proves collect_many scheduled it after the first incomplete reading.
    loop {
        if platform
            .calls
            .lock()
            .contains(&(Stage::Capacity, PathBuf::from("/")))
        {
            break;
        }
        assert!(Instant::now() < deadline, "batch skipped the healthy root");
        std::thread::yield_now();
    }
    resume.send(()).unwrap();
}

#[test]
fn inode_failure_makes_the_whole_native_frame_unknown() {
    let (_temporary, path, platform) = fixture();
    platform.invalid_inodes.store(true, Ordering::SeqCst);
    let collector = FsStatsCollector::new_background(platform, CACHE, CACHE);
    await_error(&collector, &path, "inconsistent filesystem inode counters");
}

#[test]
fn targeted_owner_uses_the_same_firmlink_namespace_as_the_query() {
    let (_temporary, path, platform) = fixture();
    *platform.rewrite.write() = Some((
        path.clone(),
        PathBuf::from("/System/Volumes/Data/Volumes/Test"),
    ));
    let collector = FsStatsCollector::new_background(platform, CACHE, CACHE);
    let sample = await_sample(&collector, &path.join("inside"));
    assert_eq!(sample.stats.mount_point, path);
    assert_eq!(
        sample.binding.resolved,
        Path::new("/System/Volumes/Data/Volumes/Test")
    );
}

#[cfg(unix)]
#[test]
fn symlink_mount_owner_cannot_supply_authoritative_device_evidence() {
    let (temporary, path, platform) = fixture();
    let alias = temporary.path().join("owner-alias");
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    platform.install(&alias, "symlink-device");
    let collector = FsStatsCollector::new_background(platform, CACHE, CACHE);
    await_error(&collector, &alias, "not a real directory");
}

#[test]
fn native_background_frame_observes_a_real_temporary_root() {
    let temporary = tempfile::tempdir().unwrap();
    let platform = crate::platform::pal::detect_platform().unwrap();
    let collector = FsStatsCollector::new_background(platform.clone(), CACHE, CACHE);
    let sample = await_sample(&collector, temporary.path());
    assert_eq!(
        sample.stats.mount_point,
        platform.mount_identity(temporary.path()).unwrap().path
    );
    assert!(sample.stats.total_bytes > 0);
    assert!(sample.is_ram_backed().is_some());
    #[cfg(unix)]
    assert!(sample.mount_device_id().is_some());
}

#[test]
fn test_overlay_keeps_injected_observations_independent_of_native_inventory() {
    use crate::platform::test_overlay::{InjectedFsTable, TestOverlayPlatform};

    let (_temporary, path, platform) = fixture();
    let table = InjectedFsTable::parse(
        &serde_json::json!({
            "mounts": [{
                "path": path,
                "device": "injected-device",
                "fs_type": "tmpfs",
                "total": 1000,
                "free": 20,
                "inodes": {"total": 500, "free": 40, "available": 30},
                "ram_backed": true
            }]
        })
        .to_string(),
    )
    .unwrap();
    let overlay = Arc::new(TestOverlayPlatform::new(platform.clone(), table));
    let collector = FsStatsCollector::new_background(overlay, CACHE, CACHE);
    let sample = await_sample(&collector, &path);
    assert_eq!(sample.stats.total_bytes, 1000);
    assert_eq!(sample.stats.available_bytes, 20);
    assert_eq!(sample.stats.fs_type, "tmpfs");
    assert_eq!(sample.binding.device, "injected-device");
    assert_eq!(sample.inode_stats(), InodeStats::new(500, 40, 30));
    assert_eq!(sample.is_ram_backed(), Some(true));
    assert!(
        platform.calls.lock().is_empty(),
        "injected owners must not consult native capacity or inventory"
    );
}

#[test]
fn optional_metadata_cannot_hold_root_capacity_or_mount_inventory() {
    use crate::platform::test_overlay::{InjectedFsTable, TestOverlayPlatform};

    let (_temporary, _path, platform) = fixture();
    let (metadata_entered, metadata_resume) =
        platform.gate(Stage::CapacityMetadata, Path::new("/"));
    let (full_entered, full_resume) = platform.gate(Stage::FullCapacity, Path::new("/"));
    // An overlay must forward the latency-sensitive method too: falling back
    // to its full fs_stats would reintroduce unrelated auxiliary disk I/O.
    let overlay = Arc::new(TestOverlayPlatform::new(
        platform.clone(),
        InjectedFsTable::default(),
    ));
    let collector = FsStatsCollector::new_background(overlay, Duration::ZERO, CACHE);
    assert!(collector.collect(Path::new("/")).is_err());
    metadata_entered.recv_timeout(WAIT).unwrap();
    let root = await_sample(&collector, Path::new("/"));
    assert_eq!(root.stats.mount_point, Path::new("/"));
    assert!(
        !platform
            .calls
            .lock()
            .iter()
            .any(|(stage, _)| *stage == Stage::Inventory)
    );
    assert!(
        full_entered.try_recv().is_err(),
        "pressure must not invoke full capacity discovery"
    );
    let deadline = Instant::now() + WAIT;
    loop {
        if let Ok(mounts) = collector.mount_points() {
            assert!(mounts.iter().any(|mount| mount.path == Path::new("/")));
            break;
        }
        assert!(
            Instant::now() < deadline,
            "inventory waited for optional metadata"
        );
        std::thread::yield_now();
    }
    assert_eq!(
        platform
            .calls
            .lock()
            .iter()
            .filter(|(stage, _)| *stage == Stage::CapacityMetadata)
            .count(),
        1
    );
    metadata_resume.send(()).unwrap();
    let deadline = Instant::now() + WAIT;
    loop {
        let _ = collector.collect(Path::new("/"));
        if platform
            .calls
            .lock()
            .iter()
            .filter(|(stage, _)| *stage == Stage::CapacityMetadata)
            .count()
            >= 2
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "sample polling did not renew optional metadata"
        );
        std::thread::yield_now();
    }
    drop(full_resume);
}

#[cfg(target_os = "linux")]
#[test]
fn native_background_query_resolution_bypasses_retargeted_ancestor_cache() {
    let temporary = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(temporary.path()).unwrap();
    let original = base.join("original");
    let replacement = base.join("replacement");
    std::fs::create_dir_all(original.join("child")).unwrap();
    std::fs::create_dir_all(replacement.join("child")).unwrap();
    let alias = base.join("alias");
    std::os::unix::fs::symlink(&original, &alias).unwrap();
    let query = alias.join("child");
    // Warm the general-purpose ancestor cache that synchronous callers use.
    assert_eq!(
        crate::core::paths::resolve_absolute_path(&query),
        original.join("child")
    );
    let platform = crate::platform::pal::detect_platform().unwrap();
    let collector = FsStatsCollector::new_background(platform, CACHE, CACHE);
    assert_eq!(
        await_sample(&collector, &query).resolved_query(),
        Some(original.join("child").as_path())
    );
    std::fs::rename(&alias, base.join("retired-alias")).unwrap();
    std::os::unix::fs::symlink(&replacement, &alias).unwrap();
    collector.invalidate_observations();
    assert_eq!(
        await_sample(&collector, &query).resolved_query(),
        Some(replacement.join("child").as_path())
    );
}
