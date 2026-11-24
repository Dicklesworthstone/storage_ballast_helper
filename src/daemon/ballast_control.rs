//! Retained native workers for operator ballast commands.
//!
//! Each slot owns one physical pool until its thread exits. The monitor can
//! cancel work and poll receipts without waiting for filesystem operations.
//! Explicit commands retain their requested count and native headroom checks.

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use crate::ballast::coordinator::{BallastRelease, BallastReplenishment};
use crate::ballast::manager::{ProvisionReport, ReleaseReport};
use crate::core::errors::Result;

const WORKER_LIMIT: usize = 2;

pub(super) enum ControlBallastTask {
    Release { task: BallastRelease, count: usize },
    Replenish(BallastReplenishment),
}

impl ControlBallastTask {
    pub(super) fn mount(&self) -> &Path {
        match self {
            Self::Release { task, .. } => task.mount(),
            Self::Replenish(task) => task.mount(),
        }
    }

    fn run(self, still_allowed: &dyn Fn() -> bool) -> ControlBallastOutcome {
        match self {
            Self::Release { mut task, count } => {
                let report = task.run_manual(count, still_allowed);
                ControlBallastOutcome::Release { task, report }
            }
            Self::Replenish(mut task) => {
                let result = task.run(still_allowed);
                ControlBallastOutcome::Replenish { task, result }
            }
        }
    }
}

pub(super) enum ControlBallastOutcome {
    /// Refused before entering the native actuator, so no mutation receipt exists.
    Refused(String),
    Release {
        task: BallastRelease,
        report: ReleaseReport,
    },
    Replenish {
        task: BallastReplenishment,
        result: Result<ProvisionReport>,
    },
}

pub(super) struct ControlBallastCompletion {
    pub command_id: u64,
    pub requested_mount: PathBuf,
    pub pool_mount: PathBuf,
    pub outcome: thread::Result<ControlBallastOutcome>,
}

struct Permission {
    cancelled: AtomicBool,
    shutdown: Arc<AtomicBool>,
    deadline: Instant,
}

impl Permission {
    fn allowed(&self) -> bool {
        !self.cancelled.load(Ordering::Acquire)
            && !self.shutdown.load(Ordering::Acquire)
            && Instant::now() < self.deadline
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

/// Cached routing is only a scheduling hint. Bind the selected path to its
/// physical keeper on the worker, then recheck both around every mutation.
struct NativePoolBinding {
    requested_mount: PathBuf,
    pool_mount: PathBuf,
    device_id: u64,
    revoked: Cell<bool>,
}

impl NativePoolBinding {
    fn capture(
        requested_mount: &Path,
        pool_mount: &Path,
        permission: &Permission,
    ) -> std::result::Result<Self, String> {
        let cancelled =
            || "operator ballast command was cancelled or expired before native I/O".to_string();
        if !permission.allowed() {
            return Err(cancelled());
        }
        let device_id = Self::native_device(pool_mount)?;
        if !permission.allowed() {
            return Err(cancelled());
        }
        let requested_device = Self::native_device(requested_mount)?;
        if !permission.allowed() {
            return Err(cancelled());
        }
        if requested_device != device_id {
            return Err(format!(
                "requested ballast mount {} is on a different filesystem from configured pool {}",
                requested_mount.display(),
                pool_mount.display(),
            ));
        }
        let binding = Self {
            requested_mount: requested_mount.to_path_buf(),
            pool_mount: pool_mount.to_path_buf(),
            device_id,
            revoked: Cell::new(false),
        };
        if !binding.allowed(permission) {
            return Err("ballast mount binding changed or the command was cancelled during native admission".into());
        }
        Ok(binding)
    }

    fn native_device(path: &Path) -> std::result::Result<u64, String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let metadata = std::fs::metadata(path).map_err(|error| {
                format!("cannot verify ballast mount {}: {error}", path.display())
            })?;
            if !metadata.is_dir() {
                return Err(format!(
                    "ballast mount {} is not a directory",
                    path.display()
                ));
            }
            Ok(metadata.dev())
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err("native ballast mount binding is unavailable on this platform".into())
        }
    }

    fn allowed(&self, permission: &Permission) -> bool {
        if self.revoked.get() {
            return false;
        }
        // Each metadata call can block. Permission must still hold after it
        // returns; one refusal permanently withdraws this task's authority.
        let allowed = permission.allowed()
            && Self::native_device(&self.pool_mount).is_ok_and(|device| device == self.device_id)
            && permission.allowed()
            && Self::native_device(&self.requested_mount)
                .is_ok_and(|device| device == self.device_id)
            && permission.allowed();
        if !allowed {
            self.revoked.set(true);
        }
        allowed
    }
}

struct Worker {
    command_id: u64,
    requested_mount: PathBuf,
    mount: PathBuf,
    permission: Arc<Permission>,
    handle: JoinHandle<ControlBallastOutcome>,
}

struct WakeOnDrop<F: FnOnce()> {
    wake: Option<F>,
}

impl<F: FnOnce()> Drop for WakeOnDrop<F> {
    fn drop(&mut self) {
        if let Some(wake) = self.wake.take() {
            wake();
        }
    }
}

#[derive(Default)]
pub(super) struct BallastControlWorkers {
    workers: Vec<Worker>,
    intervention_since_sample: bool,
}

impl BallastControlWorkers {
    pub(super) fn capacity_available(&self) -> bool {
        self.workers.len() < WORKER_LIMIT
    }

    pub(super) fn busy(&self) -> bool {
        !self.workers.is_empty()
    }

    pub(super) fn busy_mount(&self, mount: &Path) -> bool {
        self.workers.iter().any(|worker| worker.mount == mount)
    }

    pub(super) fn start(
        &mut self,
        command_id: u64,
        requested_mount: PathBuf,
        task: ControlBallastTask,
        shutdown: Arc<AtomicBool>,
        deadline: Instant,
        wake: impl FnOnce() + Send + 'static,
    ) -> std::io::Result<bool> {
        if !self.capacity_available()
            || self.busy_mount(task.mount())
            || shutdown.load(Ordering::Acquire)
            || Instant::now() >= deadline
        {
            return Ok(false);
        }
        let mount = task.mount().to_path_buf();
        let permission = Arc::new(Permission {
            cancelled: AtomicBool::new(false),
            shutdown,
            deadline,
        });
        let worker_permission = Arc::clone(&permission);
        let worker_requested_mount = requested_mount.clone();
        let worker_pool_mount = mount.clone();
        let handle = thread::Builder::new()
            .name("sbh-control-ballast".into())
            .spawn(move || {
                // Wake on both a normal receipt and unwinding. The monitor
                // still owns the slot until is_finished() permits a join.
                let _wake = WakeOnDrop { wake: Some(wake) };
                let binding = match NativePoolBinding::capture(
                    &worker_requested_mount,
                    &worker_pool_mount,
                    &worker_permission,
                ) {
                    Ok(binding) => binding,
                    Err(error) => return ControlBallastOutcome::Refused(error),
                };
                let mut outcome = task.run(&|| binding.allowed(&worker_permission));
                if binding.revoked.get() {
                    // Keep completed file receipts even if a later guard
                    // withdraws the alias or command's remaining authority.
                    let error = "operator ballast permission or requested mount binding changed during native work".to_string();
                    match &mut outcome {
                        ControlBallastOutcome::Release { report, .. } => report.errors.push(error),
                        ControlBallastOutcome::Replenish { result: Ok(report), .. } => report.errors.push(error),
                        _ => {}
                    }
                }
                outcome
            })?;
        self.workers.push(Worker {
            command_id,
            requested_mount,
            mount,
            permission,
            handle,
        });
        self.intervention_since_sample = true;
        Ok(true)
    }

    pub(super) fn cancel_mount(&self, mount: &Path) {
        for worker in &self.workers {
            if worker.mount == mount {
                worker.permission.cancel();
            }
        }
    }

    pub(super) fn cancel_command(&self, command_id: u64) {
        for worker in &self.workers {
            if worker.command_id == command_id {
                worker.permission.cancel();
            }
        }
    }

    pub(super) fn cancel(&self) {
        for worker in &self.workers {
            worker.permission.cancel();
        }
    }

    /// Completed threads still occupy their pool until the monitor consumes
    /// their receipt. Cancellation alone never frees a native worker slot.
    pub(super) fn poll(&mut self) -> Vec<ControlBallastCompletion> {
        let mut completed = Vec::new();
        let mut occupied = Vec::new();
        for worker in self.workers.drain(..) {
            if worker.handle.is_finished() {
                self.intervention_since_sample = true;
                completed.push(ControlBallastCompletion {
                    command_id: worker.command_id,
                    requested_mount: worker.requested_mount,
                    pool_mount: worker.mount,
                    outcome: worker.handle.join(),
                });
            } else {
                occupied.push(worker);
            }
        }
        self.workers = occupied;
        completed
    }

    pub(super) fn take_forecast_intervention(&mut self) -> bool {
        std::mem::take(&mut self.intervention_since_sample) || self.busy()
    }
}

impl Drop for BallastControlWorkers {
    fn drop(&mut self) {
        self.cancel();
        // A blocked native operation can outlive shutdown. Its detached
        // thread keeps the cancellation token until that operation returns.
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
    use std::time::Duration;

    struct BlockingPlatform {
        inner: MockPlatform,
        block_next: AtomicBool,
        panic_next: AtomicBool,
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
            assert!(
                !self.panic_next.swap(false, Ordering::AcqRel),
                "injected native probe failure"
            );
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
                        device: "control-ballast-test".into(),
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
                panic_next: AtomicBool::new(false),
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

        fn task(&self) -> ControlBallastTask {
            ControlBallastTask::Replenish(
                self.coordinator
                    .prepare_replenishment(self.directory.path())
                    .unwrap(),
            )
        }

        fn block(&self) {
            self.platform.block_next.store(true, Ordering::Release);
        }

        fn wait_for_probe(&self) {
            self.entered.recv_timeout(Duration::from_secs(10)).unwrap();
        }
    }

    fn finish(workers: &mut BallastControlWorkers) -> ControlBallastCompletion {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let mut completed = workers.poll();
            if !completed.is_empty() {
                assert_eq!(completed.len(), 1);
                return completed.pop().unwrap();
            }
            assert!(
                Instant::now() < deadline,
                "operator ballast work did not finish"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn created(completion: ControlBallastCompletion) -> ProvisionReport {
        let ControlBallastOutcome::Replenish { result, .. } = completion.outcome.unwrap() else {
            panic!("expected a refill receipt");
        };
        result.unwrap()
    }

    #[test]
    fn manual_ballast_keeps_two_native_slots_and_pool_exclusion_after_cancellation() {
        let first = Fixture::new();
        let second = Fixture::new();
        let third = Fixture::new();
        let mut workers = BallastControlWorkers::default();
        let shutdown = Arc::new(AtomicBool::new(false));
        let deadline = Instant::now() + Duration::from_secs(60);
        let alias = first.directory.path().join("selected-alias");
        std::fs::create_dir(&alias).unwrap();
        first.block();
        assert!(
            workers
                .start(
                    1,
                    alias.clone(),
                    first.task(),
                    Arc::clone(&shutdown),
                    deadline,
                    || {},
                )
                .unwrap()
        );
        first.wait_for_probe();
        assert!(workers.capacity_available());
        assert!(
            !workers
                .start(
                    2,
                    alias.clone(),
                    first.task(),
                    Arc::clone(&shutdown),
                    deadline,
                    || {},
                )
                .unwrap()
        );
        second.block();
        assert!(
            workers
                .start(
                    3,
                    second.directory.path().to_path_buf(),
                    second.task(),
                    Arc::clone(&shutdown),
                    deadline,
                    || {},
                )
                .unwrap()
        );
        second.wait_for_probe();
        workers.cancel_mount(first.directory.path());
        assert!(workers.busy_mount(first.directory.path()));
        assert!(workers.busy_mount(second.directory.path()));
        assert!(!workers.capacity_available());
        assert!(workers.poll().is_empty());
        assert!(workers.take_forecast_intervention());
        assert!(
            !workers
                .start(
                    4,
                    third.directory.path().to_path_buf(),
                    third.task(),
                    shutdown,
                    deadline,
                    || {},
                )
                .unwrap()
        );

        first.release.send(()).unwrap();
        let first_result = finish(&mut workers);
        assert_eq!(first_result.command_id, 1);
        assert_eq!(first_result.requested_mount, alias);
        assert_eq!(first_result.pool_mount, first.directory.path());
        assert_eq!(created(first_result).files_created, 0);
        assert!(!workers.busy_mount(first.directory.path()));
        assert!(workers.capacity_available());
        assert!(workers.busy_mount(second.directory.path()));
        second.release.send(()).unwrap();
        let second_result = finish(&mut workers);
        assert_eq!(second_result.command_id, 3);
        assert_eq!(created(second_result).files_created, 1);
        assert!(!workers.busy());
        assert!(workers.take_forecast_intervention());
        assert!(!workers.take_forecast_intervention());
    }

    #[test]
    fn manual_ballast_deadline_and_shutdown_refuse_or_cancel_native_work() {
        let fixture = Fixture::new();
        let mut workers = BallastControlWorkers::default();
        let shutdown = Arc::new(AtomicBool::new(false));
        let calls = fixture.platform.calls.load(Ordering::Relaxed);
        assert!(
            !workers
                .start(
                    1,
                    fixture.directory.path().to_path_buf(),
                    fixture.task(),
                    Arc::clone(&shutdown),
                    Instant::now(),
                    || {},
                )
                .unwrap()
        );
        shutdown.store(true, Ordering::Release);
        assert!(
            !workers
                .start(
                    2,
                    fixture.directory.path().to_path_buf(),
                    fixture.task(),
                    Arc::clone(&shutdown),
                    Instant::now() + Duration::from_secs(60),
                    || {},
                )
                .unwrap()
        );
        assert_eq!(fixture.platform.calls.load(Ordering::Relaxed), calls);
        assert!(!workers.busy());
        let expired = Permission {
            cancelled: AtomicBool::new(false),
            shutdown: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now(),
        };
        assert!(!expired.allowed());

        shutdown.store(false, Ordering::Release);
        fixture.block();
        assert!(
            workers
                .start(
                    3,
                    fixture.directory.path().to_path_buf(),
                    fixture.task(),
                    Arc::clone(&shutdown),
                    Instant::now() + Duration::from_secs(60),
                    || {},
                )
                .unwrap()
        );
        fixture.wait_for_probe();
        shutdown.store(true, Ordering::Release);
        assert!(workers.busy());
        assert!(workers.poll().is_empty());
        fixture.release.send(()).unwrap();
        assert_eq!(created(finish(&mut workers)).files_created, 0);
    }

    #[test]
    fn manual_ballast_deadline_retains_a_blocked_native_slot_without_refilling() {
        let fixture = Fixture::new();
        fixture.block();
        let mut workers = BallastControlWorkers::default();
        let deadline = Instant::now() + Duration::from_secs(1);
        assert!(
            workers
                .start(
                    3,
                    fixture.directory.path().to_path_buf(),
                    fixture.task(),
                    Arc::new(AtomicBool::new(false)),
                    deadline,
                    || {},
                )
                .unwrap()
        );
        fixture.wait_for_probe();
        while Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(workers.busy_mount(fixture.directory.path()));
        assert!(workers.poll().is_empty());
        assert!(
            !workers
                .start(
                    4,
                    fixture.directory.path().to_path_buf(),
                    fixture.task(),
                    Arc::new(AtomicBool::new(false)),
                    Instant::now() + Duration::from_secs(60),
                    || {},
                )
                .unwrap()
        );
        fixture.release.send(()).unwrap();
        assert_eq!(created(finish(&mut workers)).files_created, 0);
        assert!(!workers.busy());
    }

    #[test]
    fn manual_ballast_command_cancellation_preserves_unrelated_requests() {
        for cancelled_command in [4, 5] {
            let fixture = Fixture::new();
            fixture.block();
            let mut workers = BallastControlWorkers::default();
            workers
                .start(
                    4,
                    fixture.directory.path().to_path_buf(),
                    fixture.task(),
                    Arc::new(AtomicBool::new(false)),
                    Instant::now() + Duration::from_secs(60),
                    || {},
                )
                .unwrap();
            fixture.wait_for_probe();
            workers.cancel_command(cancelled_command);
            assert!(workers.busy_mount(fixture.directory.path()));
            fixture.release.send(()).unwrap();
            assert_eq!(
                created(finish(&mut workers)).files_created,
                usize::from(cancelled_command != 4),
            );
        }
    }

    #[test]
    fn manual_ballast_release_reports_the_requested_count_and_alias() {
        let mut fixture = Fixture::new();
        assert_eq!(
            fixture
                .coordinator
                .provision_all(fixture.platform.as_ref())
                .unwrap()
                .total_files_created(),
            2
        );
        let task = fixture
            .coordinator
            .prepare_release(fixture.directory.path())
            .unwrap();
        let alias = fixture.directory.path().join("operator-selection");
        std::fs::create_dir(&alias).unwrap();
        let mut workers = BallastControlWorkers::default();
        let (wake, awake) = crossbeam_channel::bounded(1);
        assert!(
            workers
                .start(
                    7,
                    alias.clone(),
                    ControlBallastTask::Release { task, count: 1 },
                    Arc::new(AtomicBool::new(false)),
                    Instant::now() + Duration::from_secs(60),
                    move || {
                        let _ = wake.try_send(());
                    },
                )
                .unwrap()
        );
        let completed = finish(&mut workers);
        awake.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(awake.try_recv().is_err());
        assert_eq!(completed.command_id, 7);
        assert_eq!(completed.requested_mount, alias);
        let ControlBallastOutcome::Release { task, report } = completed.outcome.unwrap() else {
            panic!("expected a release receipt");
        };
        assert_eq!(report.files_released, 1);
        assert_eq!(report.released.len(), 1);
        assert!(report.errors.is_empty());
        assert!(fixture.coordinator.finish_release(task));
        assert_eq!(
            fixture
                .coordinator
                .pool_for_mount(fixture.directory.path())
                .unwrap()
                .available_count(),
            1
        );
    }

    #[test]
    fn manual_ballast_requested_alias_binding_refuses_foreign_devices_and_stays_revoked() {
        use std::os::unix::fs::{MetadataExt, symlink};

        let fixture = Fixture::new();
        let Ok(foreign) = tempfile::tempdir_in("/dev/shm") else {
            eprintln!("skipped: no writable independent filesystem at /dev/shm");
            return;
        };
        let pool_device = std::fs::metadata(fixture.directory.path()).unwrap().dev();
        if std::fs::metadata(foreign.path()).unwrap().dev() == pool_device {
            eprintln!("skipped: /dev/shm and the pool share a device");
            return;
        }
        let mut workers = BallastControlWorkers::default();
        let calls = fixture.platform.calls.load(Ordering::Relaxed);
        assert!(
            workers
                .start(
                    10,
                    foreign.path().to_path_buf(),
                    fixture.task(),
                    Arc::new(AtomicBool::new(false)),
                    Instant::now() + Duration::from_secs(60),
                    || {},
                )
                .unwrap()
        );
        let ControlBallastOutcome::Refused(reason) = finish(&mut workers).outcome.unwrap() else {
            panic!("a foreign requested mount must be refused before the actuator runs");
        };
        assert!(reason.contains("different filesystem"));
        assert_eq!(fixture.platform.calls.load(Ordering::Relaxed), calls);

        let alias = fixture.directory.path().join("live-alias");
        symlink(fixture.directory.path(), &alias).unwrap();
        let permission = Permission {
            cancelled: AtomicBool::new(false),
            shutdown: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + Duration::from_secs(60),
        };
        let binding =
            NativePoolBinding::capture(&alias, fixture.directory.path(), &permission).unwrap();
        assert!(binding.allowed(&permission));
        fixture.block();
        assert!(
            workers
                .start(
                    11,
                    alias.clone(),
                    fixture.task(),
                    Arc::new(AtomicBool::new(false)),
                    Instant::now() + Duration::from_secs(60),
                    || {},
                )
                .unwrap()
        );
        fixture.wait_for_probe();
        std::fs::remove_file(&alias).unwrap();
        symlink(foreign.path(), &alias).unwrap();
        assert!(!binding.allowed(&permission));
        fixture.release.send(()).unwrap();
        let report = created(finish(&mut workers));
        assert_eq!(report.files_created, 0);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("mount binding changed"))
        );

        std::fs::remove_file(&alias).unwrap();
        symlink(fixture.directory.path(), &alias).unwrap();
        assert!(
            !binding.allowed(&permission),
            "restoring a path cannot renew revoked authority"
        );
    }

    #[test]
    fn manual_ballast_worker_panic_returns_a_receipt_and_releases_the_slot() {
        let fixture = Fixture::new();
        fixture.platform.panic_next.store(true, Ordering::Release);
        let mut workers = BallastControlWorkers::default();
        let (wake, awake) = crossbeam_channel::bounded(1);
        workers
            .start(
                9,
                fixture.directory.path().to_path_buf(),
                fixture.task(),
                Arc::new(AtomicBool::new(false)),
                Instant::now() + Duration::from_secs(60),
                move || {
                    let _ = wake.try_send(());
                },
            )
            .unwrap();
        let completed = finish(&mut workers);
        awake.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(awake.try_recv().is_err());
        assert_eq!(completed.command_id, 9);
        assert_eq!(completed.pool_mount, fixture.directory.path());
        assert!(completed.outcome.is_err());
        assert!(!workers.busy());
        assert!(workers.capacity_available());
    }
}
