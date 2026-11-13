//! One retained background worker for automatic reserve growth.
//!
//! Admission and completion are memory-only. The worker owns a separate pool
//! snapshot, so a slow allocation never owns the monitor's coordinator. A
//! cancelled worker retains its slot until it actually exits; native I/O cannot
//! be killed safely and must not turn repeated ticks into unbounded threads.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::ballast::coordinator::BallastReplenishment;
use crate::ballast::manager::ProvisionReport;
use crate::core::errors::Result;

/// Expired monitor evidence cannot authorize another allocation chunk.
const PERMISSION_MAX_AGE: Duration = Duration::from_secs(60);

type ReplenishmentResult = (BallastReplenishment, Result<ProvisionReport>);

struct Permission {
    cancelled: AtomicBool,
    observed_at: Mutex<Instant>,
    shutdown: Arc<AtomicBool>,
}

impl Permission {
    fn allowed(&self) -> bool {
        !self.cancelled.load(Ordering::Acquire)
            && !self.shutdown.load(Ordering::Acquire)
            && self.observed_at.lock().elapsed() < PERMISSION_MAX_AGE
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

struct Worker {
    mount: PathBuf,
    permission: Arc<Permission>,
    handle: JoinHandle<ReplenishmentResult>,
}

/// Automatic refill scheduling state; never waits for a running worker.
#[derive(Default)]
pub(super) struct BallastReplenisher {
    worker: Option<Worker>,
}

impl BallastReplenisher {
    pub(super) fn busy(&self) -> bool {
        self.worker.is_some()
    }

    /// The pool still authorized to refill. A cancelled worker retains its
    /// slot, but must not be reported as rebuilding protection.
    pub(super) fn active_mount(&self) -> Option<&Path> {
        self.worker
            .as_ref()
            .filter(|worker| worker.permission.allowed())
            .map(|worker| worker.mount.as_path())
    }

    pub(super) fn start(
        &mut self,
        mut task: BallastReplenishment,
        shutdown: Arc<AtomicBool>,
        now: Instant,
    ) -> std::io::Result<bool> {
        if self.busy() || shutdown.load(Ordering::Acquire) {
            return Ok(false);
        }
        let mount = task.mount().to_path_buf();
        let permission = Arc::new(Permission {
            cancelled: AtomicBool::new(false),
            observed_at: Mutex::new(now),
            shutdown,
        });
        let worker_permission = Arc::clone(&permission);
        let handle = std::thread::Builder::new()
            .name("sbh-ballast-refill".into())
            .spawn(move || {
                let report = task.run(&|| worker_permission.allowed());
                (task, report)
            })?;
        self.worker = Some(Worker {
            mount,
            permission,
            handle,
        });
        Ok(true)
    }

    /// Renew only from this tick's eligible physical pools. Cancellation is
    /// irreversible even if pressure recovers before a blocked syscall returns.
    pub(super) fn observe(&self, eligible: &HashSet<PathBuf>, now: Instant) {
        if let Some(worker) = &self.worker {
            if eligible.contains(&worker.mount) && worker.permission.allowed() {
                *worker.permission.observed_at.lock() = now;
            } else {
                worker.permission.cancel();
            }
        }
    }

    pub(super) fn cancel_mount(&self, mount: &Path) {
        if let Some(worker) = &self.worker
            && worker.mount == mount
        {
            worker.permission.cancel();
        }
    }

    pub(super) fn cancel(&self) {
        if let Some(worker) = &self.worker {
            worker.permission.cancel();
        }
    }

    /// Join only a finished thread. The result's generation is checked again
    /// by the coordinator before its inventory can become current.
    pub(super) fn poll(&mut self) -> Option<std::thread::Result<ReplenishmentResult>> {
        if !self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.handle.is_finished())
        {
            return None;
        }
        self.worker.take().map(|worker| worker.handle.join())
    }
}

impl Drop for BallastReplenisher {
    fn drop(&mut self) {
        self.cancel();
        // Dropping a JoinHandle detaches it. Its irreversible cancellation and
        // shared shutdown flag remain live until native I/O returns.
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::ballast::coordinator::BallastPoolCoordinator;
    use crate::core::config::BallastConfig;
    use crate::platform::pal::{
        FsStats, MemoryInfo, MockPlatform, MountPoint, Platform, PlatformPaths, ServiceManager,
    };
    use std::collections::{BTreeMap, HashMap};
    use std::sync::atomic::AtomicUsize;

    struct BlockingPlatform {
        inner: MockPlatform,
        block_next: AtomicBool,
        calls: AtomicUsize,
        entered: crossbeam_channel::Sender<()>,
        release: crossbeam_channel::Receiver<()>,
    }

    impl Platform for BlockingPlatform {
        fn fs_stats(&self, path: &Path) -> Result<FsStats> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.block_next.swap(false, Ordering::AcqRel) {
                let _ = self.entered.send(());
                let _ = self.release.recv();
            }
            self.inner.fs_stats(path)
        }

        fn mount_points(&self) -> Result<Vec<MountPoint>> {
            self.inner.mount_points()
        }

        fn is_ram_backed(&self, path: &Path) -> Result<bool> {
            self.inner.is_ram_backed(path)
        }

        fn default_paths(&self) -> PlatformPaths {
            self.inner.default_paths()
        }

        fn memory_info(&self) -> Result<MemoryInfo> {
            self.inner.memory_info()
        }

        fn service_manager(&self) -> Box<dyn ServiceManager> {
            self.inner.service_manager()
        }
    }

    struct Fixture {
        directory: tempfile::TempDir,
        coordinator: BallastPoolCoordinator,
        platform: Arc<BlockingPlatform>,
        entered: crossbeam_channel::Receiver<()>,
        release: crossbeam_channel::Sender<()>,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let mount = directory.path().to_path_buf();
            let (entered_tx, entered) = crossbeam_channel::bounded(1);
            let (release, release_rx) = crossbeam_channel::bounded(1);
            let platform = Arc::new(BlockingPlatform {
                inner: MockPlatform::new(
                    vec![MountPoint {
                        path: mount.clone(),
                        device: "refill-test-device".into(),
                        fs_type: "ext4".into(),
                        is_ram_backed: false,
                    }],
                    HashMap::from([(
                        mount.clone(),
                        FsStats {
                            total_bytes: 1 << 30,
                            free_bytes: 1 << 29,
                            available_bytes: 1 << 29,
                            fs_type: "ext4".into(),
                            mount_point: mount.clone(),
                            is_readonly: false,
                        },
                    )]),
                    MockPlatform::healthy().memory_info().unwrap(),
                    PlatformPaths::default(),
                ),
                block_next: AtomicBool::new(false),
                calls: AtomicUsize::new(0),
                entered: entered_tx,
                release: release_rx,
            });
            let manager_platform: Arc<dyn Platform> = platform.clone();
            let coordinator = BallastPoolCoordinator::discover_with_manager_platform(
                &BallastConfig {
                    file_count: 2,
                    file_size_bytes: 8192,
                    replenish_cooldown_minutes: 0,
                    auto_provision: true,
                    overrides: BTreeMap::new(),
                },
                &[mount],
                platform.as_ref(),
                &manager_platform,
            )
            .unwrap();
            Self {
                directory,
                coordinator,
                platform,
                entered,
                release,
            }
        }

        fn task(&self) -> BallastReplenishment {
            self.coordinator
                .prepare_replenishment(self.directory.path())
                .unwrap()
        }

        fn wait_for_probe(&self) {
            self.entered.recv_timeout(Duration::from_secs(10)).unwrap();
        }
    }

    fn finish(worker: &mut BallastReplenisher) -> ReplenishmentResult {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(result) = worker.poll() {
                return result.unwrap();
            }
            assert!(Instant::now() < deadline, "refill worker did not finish");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn ballast_refill_blocked_probe_keeps_one_slot_and_irreversible_cancellation() {
        let mut fixture = Fixture::new();
        let mut worker = BallastReplenisher::default();
        let shutdown = Arc::new(AtomicBool::new(false));
        fixture.platform.block_next.store(true, Ordering::Release);
        let before = fixture.platform.calls.load(Ordering::Relaxed);
        let task = fixture.task();
        assert_eq!(fixture.platform.calls.load(Ordering::Relaxed), before);
        assert!(
            worker
                .start(task, Arc::clone(&shutdown), Instant::now())
                .unwrap()
        );
        fixture.wait_for_probe();

        // The real worker is blocked in fs_stats. Monitor operations still
        // return, and recovery never starts another worker alongside it.
        assert!(worker.poll().is_none());
        worker.observe(&HashSet::new(), Instant::now());
        let eligible = HashSet::from([fixture.directory.path().to_path_buf()]);
        for _ in 0..3 {
            worker.observe(&eligible, Instant::now());
            assert!(
                !worker
                    .start(fixture.task(), Arc::clone(&shutdown), Instant::now())
                    .unwrap()
            );
        }
        assert!(worker.busy());
        fixture.release.send(()).unwrap();
        let (task, report) = finish(&mut worker);
        let report = report.unwrap();
        assert_eq!(report.files_created, 0);
        assert!(report.created.is_empty());
        assert!(!report.errors.is_empty());
        assert!(fixture.coordinator.finish_replenishment(task));
        assert_eq!(fixture.coordinator.total_releasable(), 0);

        // A new generation can rebuild a reserve after the cancelled worker
        // has exited. Publication remains one completed file at a time.
        assert!(
            worker
                .start(fixture.task(), shutdown, Instant::now())
                .unwrap()
        );
        let (task, report) = finish(&mut worker);
        assert_eq!(report.unwrap().files_created, 1);
        assert!(fixture.coordinator.finish_replenishment(task));
        assert_eq!(fixture.coordinator.total_releasable(), 8192);
    }

    #[test]
    fn ballast_refill_pressure_cancels_only_its_own_pool() {
        let fixture = Fixture::new();
        let mut worker = BallastReplenisher::default();
        fixture.platform.block_next.store(true, Ordering::Release);
        worker
            .start(
                fixture.task(),
                Arc::new(AtomicBool::new(false)),
                Instant::now(),
            )
            .unwrap();
        fixture.wait_for_probe();
        worker.cancel_mount(&fixture.directory.path().join("unrelated"));
        worker.observe(
            &HashSet::from([fixture.directory.path().to_path_buf()]),
            Instant::now(),
        );
        fixture.release.send(()).unwrap();
        assert_eq!(finish(&mut worker).1.unwrap().files_created, 1);
    }

    #[test]
    fn ballast_refill_stale_evidence_and_shutdown_stop_blocked_work() {
        for expired in [false, true] {
            let fixture = Fixture::new();
            let mut worker = BallastReplenisher::default();
            let shutdown = Arc::new(AtomicBool::new(false));
            fixture.platform.block_next.store(true, Ordering::Release);
            worker
                .start(fixture.task(), Arc::clone(&shutdown), Instant::now())
                .unwrap();
            fixture.wait_for_probe();
            if expired {
                *worker
                    .worker
                    .as_ref()
                    .unwrap()
                    .permission
                    .observed_at
                    .lock() = Instant::now().checked_sub(PERMISSION_MAX_AGE).unwrap();
            } else {
                shutdown.store(true, Ordering::Release);
            }
            fixture.release.send(()).unwrap();
            let report = finish(&mut worker).1.unwrap();
            assert_eq!(report.files_created, 0, "expired={expired}");
            assert!(report.created.is_empty());
            assert!(!report.errors.is_empty());
        }
    }
}
