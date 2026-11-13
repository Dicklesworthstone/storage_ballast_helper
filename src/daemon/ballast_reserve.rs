//! Read-only reserve observations, kept off the pressure-monitoring thread.
//!
//! One retained worker bounds concurrent inventory I/O. Results belong to the
//! coordinator's pool mutation epochs, so a slow observation cannot undo a
//! later release. Neither these observations nor their reporting grants refill
//! authority; the existing controller and provisioner remain the only gates.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::ballast::coordinator::{
    BallastPoolCoordinator, BallastRefillBlocker, BallastReserveObservationResult,
    BallastReserveSnapshot, BallastReserveState,
};
use crate::daemon::notifications::NotificationEvent;
use crate::daemon::self_monitor::{
    DAEMON_STATE_STALE_THRESHOLD_SECS, DAEMON_STATE_WRITE_INTERVAL_SECS,
};
use crate::platform::pal::Platform;

const OBSERVATION_INTERVAL: Duration = Duration::from_secs(DAEMON_STATE_WRITE_INTERVAL_SECS);
const MAX_OBSERVATION_AGE: Duration = Duration::from_secs(DAEMON_STATE_STALE_THRESHOLD_SECS);

struct ObservationWorker {
    started_at: Instant,
    handle: JoinHandle<BallastReserveObservationResult>,
}

struct ObservedReserve {
    snapshot: BallastReserveSnapshot,
    started_at: Instant,
    pending: bool,
}

/// In-memory observations only: a restarted daemon must inspect its pools
/// again, never restore a saved claim that reserve bytes still exist.
#[derive(Default)]
pub(super) struct BallastReserveMonitor {
    worker: Option<ObservationWorker>,
    last_started: Option<Instant>,
    refresh_requested: bool,
    reload_pending: bool,
    observations: HashMap<PathBuf, ObservedReserve>,
    reported: HashMap<(PathBuf, PathBuf), BallastReserveState>,
    latest_notifications: HashMap<(PathBuf, PathBuf), NotificationEvent>,
}

impl BallastReserveMonitor {
    /// Invalidate a changed pool immediately, without joining a running probe.
    /// Its completion will also be checked against the coordinator's revision.
    pub(super) fn invalidate(&mut self, mount: &Path) {
        self.invalidate_at(mount, Instant::now());
    }

    fn invalidate_at(&mut self, mount: &Path, now: Instant) {
        if let Some(observation) = self.observations.get_mut(mount) {
            let stale = observation
                .snapshot
                .refill_blockers
                .contains(&BallastRefillBlocker::ObservationStale);
            // A busy or denied pool can be invalidated by every release
            // attempt. Those retries must not postpone the first pending
            // observation's deadline or hide an already reportable Unknown.
            if !observation.pending && !stale {
                observation.started_at = now;
            }
            if !stale {
                mark_pending(&mut observation.snapshot);
                observation.pending = true;
            }
        }
        self.refresh_requested = true;
    }

    /// A reload can replace both pool identity and the floor rule. Invalidate
    /// evidence while retaining uncertainty deadlines until the current pool
    /// seeds confirm which identities survived. Transition history for those
    /// pools also survives, so recovery reaches the notification manager.
    pub(super) fn invalidate_all(&mut self) {
        self.invalidate_all_at(Instant::now());
    }

    fn invalidate_all_at(&mut self, now: Instant) {
        let mounts: Vec<_> = self.observations.keys().cloned().collect();
        for mount in mounts {
            self.invalidate_at(&mount, now);
        }
        // Even an expired row waits for identity reconciliation before its
        // retained notification can be delivered after a reload.
        for observation in self.observations.values_mut() {
            observation.pending = true;
        }
        self.reload_pending = true;
        self.refresh_requested = true;
    }

    /// Start or consume a read-only observation without waiting on native I/O.
    /// The return value means the state file has new evidence to publish.
    pub(super) fn tick(
        &mut self,
        coordinator: &BallastPoolCoordinator,
        platform: &Arc<dyn Platform>,
        now: Instant,
    ) -> std::io::Result<bool> {
        let mut changed = false;
        // Seeds use only pool configuration. Even an initial probe stuck in
        // native I/O eventually yields an explicit unknown reserve, instead
        // of silently leaving the status record without any observation.
        if self.refresh_requested || self.last_started.is_none() {
            changed |= self.seed_observations(coordinator, now);
        }
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.handle.is_finished())
            && let Some(worker) = self.worker.take()
        {
            if let Ok(result) = worker.handle.join() {
                changed |= self.accept_observation(coordinator, result, worker.started_at);
            } else {
                // Retry at the ordinary cadence; a failing observer must
                // not create a thread or diagnostic storm on every tick.
                for observation in self.observations.values_mut() {
                    mark_stale(&mut observation.snapshot);
                    observation.pending = false;
                }
                changed = true;
            }
        }

        changed |= self.expire_observations(now);

        let due = self.refresh_requested
            || self.last_started.is_none_or(|last| {
                now.checked_duration_since(last)
                    .is_some_and(|elapsed| elapsed >= OBSERVATION_INTERVAL)
            });
        if self.worker.is_none() && due {
            let task = coordinator.prepare_reserve_observation();
            let platform = Arc::clone(platform);
            self.last_started = Some(now);
            self.refresh_requested = false;
            let handle = std::thread::Builder::new()
                .name("sbh-reserve-observer".into())
                .spawn(move || task.run(platform.as_ref()))?;
            self.worker = Some(ObservationWorker {
                started_at: now,
                handle,
            });
        }
        Ok(changed)
    }

    fn seed_observations(&mut self, coordinator: &BallastPoolCoordinator, now: Instant) -> bool {
        let seeds = coordinator.reserve_observation_seeds();
        let active_pools: HashSet<_> = seeds
            .iter()
            .map(|snapshot| (snapshot.mount_point.clone(), snapshot.ballast_dir.clone()))
            .collect();
        // A changed or removed physical pool must not inherit an old cursor.
        // The same pool retains its cursor across policy-only reloads.
        self.reported.retain(|key, _| active_pools.contains(key));
        self.latest_notifications
            .retain(|key, _| active_pools.contains(key));
        let previous_count = self.observations.len();
        self.observations.retain(|mount, observation| {
            active_pools.contains(&(mount.clone(), observation.snapshot.ballast_dir.clone()))
        });
        let mut changed =
            std::mem::take(&mut self.reload_pending) || self.observations.len() != previous_count;
        for snapshot in seeds {
            match self.observations.entry(snapshot.mount_point.clone()) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(ObservedReserve {
                        snapshot,
                        started_at: now,
                        pending: true,
                    });
                    changed = true;
                }
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    let observation = entry.get_mut();
                    let stale = observation
                        .snapshot
                        .refill_blockers
                        .contains(&BallastRefillBlocker::ObservationStale);
                    if observation.pending || stale {
                        changed |= observation.snapshot.files_total != snapshot.files_total
                            || observation.snapshot.configured_bytes != snapshot.configured_bytes
                            || (stale && observation.pending);
                        // Reloaded targets are configuration, not inventory
                        // evidence. Keep the original uncertainty deadline.
                        observation.snapshot.files_total = snapshot.files_total;
                        observation.snapshot.configured_bytes = snapshot.configured_bytes;
                        observation.snapshot.state = snapshot.state;
                        if stale {
                            observation.pending = false;
                        }
                    }
                }
            }
        }
        changed
    }

    fn accept_observation(
        &mut self,
        coordinator: &BallastPoolCoordinator,
        result: BallastReserveObservationResult,
        started_at: Instant,
    ) -> bool {
        let snapshots = coordinator.accept_reserve_observation(result);
        let changed = !snapshots.is_empty();
        for snapshot in snapshots {
            self.observations.insert(
                snapshot.mount_point.clone(),
                ObservedReserve {
                    snapshot,
                    started_at,
                    pending: false,
                },
            );
        }
        changed
    }

    fn expire_observations(&mut self, now: Instant) -> bool {
        let mut changed = false;
        for observation in self.observations.values_mut() {
            if now
                .checked_duration_since(observation.started_at)
                .is_none_or(|age| age >= MAX_OBSERVATION_AGE)
                && !observation
                    .snapshot
                    .refill_blockers
                    .contains(&BallastRefillBlocker::ObservationStale)
            {
                mark_stale(&mut observation.snapshot);
                observation.pending = false;
                changed = true;
            }
        }
        changed
    }

    /// Attach decisions from the existing admission path. The boolean asks
    /// for a state write when explanations change, even in the same reserve
    /// band. Only a band transition produces a notification.
    pub(super) fn report(
        &mut self,
        blockers: &HashMap<PathBuf, Vec<BallastRefillBlocker>>,
        active_refill: Option<&Path>,
    ) -> (Vec<NotificationEvent>, bool) {
        let mut events = Vec::new();
        let mut changed = false;
        let mut mounts: Vec<_> = self.observations.keys().cloned().collect();
        mounts.sort();
        for mount in mounts {
            let Some(observation) = self.observations.get_mut(&mount) else {
                continue;
            };
            let snapshot = &mut observation.snapshot;
            let old_blockers = snapshot.refill_blockers.clone();
            let old_in_progress = snapshot.refill_in_progress;
            let stale = old_blockers.contains(&BallastRefillBlocker::ObservationStale);
            let readonly = old_blockers.contains(&BallastRefillBlocker::ReadOnlyFilesystem);
            snapshot.refill_blockers = blockers
                .get(&mount)
                .cloned()
                .unwrap_or_else(|| vec![BallastRefillBlocker::NotEvaluated]);
            snapshot.refill_in_progress = active_refill == Some(mount.as_path());
            if stale {
                push_blocker(snapshot, BallastRefillBlocker::ObservationStale);
            } else if !snapshot.inventory_authoritative && !observation.pending && !readonly {
                push_blocker(snapshot, BallastRefillBlocker::InventoryUnreadable);
            }
            if readonly {
                push_blocker(snapshot, BallastRefillBlocker::ReadOnlyFilesystem);
            } else if !stale && snapshot.headroom_error.is_some() {
                push_blocker(snapshot, BallastRefillBlocker::FilesystemStatsUnavailable);
            }
            if snapshot
                .headroom
                .is_some_and(|headroom| !headroom.can_allocate)
            {
                push_blocker(snapshot, BallastRefillBlocker::SafetyFloor);
            }
            changed |= old_blockers != snapshot.refill_blockers
                || old_in_progress != snapshot.refill_in_progress;
            if observation.pending {
                continue;
            }
            let key = (mount, snapshot.ballast_dir.clone());
            let previous = self.reported.insert(key.clone(), snapshot.state);
            if previous == Some(snapshot.state)
                || (previous.is_none()
                    && matches!(
                        snapshot.state,
                        BallastReserveState::Healthy | BallastReserveState::Unconfigured
                    ))
            {
                if let Some(NotificationEvent::BallastReserveChanged { reserve, .. }) =
                    self.latest_notifications.get_mut(&key)
                {
                    reserve.clone_from(snapshot);
                }
                continue;
            }
            let event = NotificationEvent::BallastReserveChanged {
                mount: snapshot.mount_point.display().to_string(),
                previous,
                reserve: snapshot.clone(),
            };
            self.latest_notifications.insert(key, event.clone());
            events.push(event);
        }
        (events, changed)
    }

    /// Current pool identities include pending observations, so delivery
    /// history survives a refresh but never outlives a removed pool.
    pub(super) fn pool_scopes(&self) -> impl Iterator<Item = (&Path, &Path)> {
        self.observations.values().map(|observation| {
            (
                observation.snapshot.mount_point.as_path(),
                observation.snapshot.ballast_dir.as_path(),
            )
        })
    }

    pub(super) fn snapshot(&self, mount: &Path) -> Option<&BallastReserveSnapshot> {
        self.observations.get(mount).map(|value| &value.snapshot)
    }

    /// Retry the latest transition without replaying its activity log entry.
    /// The notification manager deduplicates accepted deliveries, but leaves
    /// disabled or full-queue delivery eligible for a subsequent tick.
    pub(super) fn delivery_events(&self) -> Vec<NotificationEvent> {
        let mut entries: Vec<_> = self.latest_notifications.iter().collect();
        entries.sort_by_key(|(left, _)| *left);
        entries
            .into_iter()
            .filter(|((mount, directory), _)| {
                self.observations.get(mount).is_some_and(|observation| {
                    !observation.pending && observation.snapshot.ballast_dir == *directory
                })
            })
            .map(|(_, event)| event.clone())
            .collect()
    }
}

fn push_blocker(snapshot: &mut BallastReserveSnapshot, blocker: BallastRefillBlocker) {
    if !snapshot.refill_blockers.contains(&blocker) {
        snapshot.refill_blockers.push(blocker);
    }
}

fn mark_stale(snapshot: &mut BallastReserveSnapshot) {
    snapshot.inventory_authoritative = false;
    snapshot.state = BallastReserveState::classify(snapshot.configured_bytes, 0, false);
    // After expiry even a previously observed file may have disappeared. Do
    // not present its former allocation as a current lower bound.
    snapshot.files_available = 0;
    snapshot.releasable_bytes = 0;
    snapshot.unreadable_count = 0;
    snapshot.headroom = None;
    snapshot.headroom_error = Some("reserve observation is stale".into());
    snapshot.refill_in_progress = false;
    snapshot.refill_blockers = vec![BallastRefillBlocker::ObservationStale];
}

fn mark_pending(snapshot: &mut BallastReserveSnapshot) {
    mark_stale(snapshot);
    snapshot.observed_at.clear();
    snapshot.headroom_error = None;
    snapshot.refill_blockers = vec![BallastRefillBlocker::NotEvaluated];
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::core::config::BallastConfig;
    use crate::core::errors::Result;
    use crate::platform::pal::{
        FsStats, MemoryInfo, MockPlatform, MountPoint, PlatformPaths, ServiceManager,
    };
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

    struct ProbePlatform {
        inner: MockPlatform,
        free: AtomicU64,
        readonly: AtomicBool,
        block_next: AtomicBool,
        probes: AtomicUsize,
        entered: crossbeam_channel::Sender<()>,
        release: crossbeam_channel::Receiver<()>,
    }

    impl Platform for ProbePlatform {
        fn fs_stats(&self, path: &Path) -> Result<FsStats> {
            let mut stats = self.inner.fs_stats(path)?;
            self.probes.fetch_add(1, Ordering::Relaxed);
            if self.block_next.swap(false, Ordering::AcqRel) {
                self.entered.send(()).unwrap();
                self.release.recv_timeout(Duration::from_secs(10)).unwrap();
            }
            let free = self.free.load(Ordering::Acquire);
            stats.available_bytes = free;
            stats.free_bytes = free;
            stats.is_readonly = self.readonly.load(Ordering::Acquire);
            Ok(stats)
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

        fn file_block_count(&self, path: &Path) -> Result<u64> {
            self.inner.file_block_count(path)
        }
    }

    struct Fixture {
        directory: tempfile::TempDir,
        coordinator: BallastPoolCoordinator,
        platform: Arc<ProbePlatform>,
        entered: crossbeam_channel::Receiver<()>,
        release: crossbeam_channel::Sender<()>,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let mount = directory.path().to_path_buf();
            let mut inner = MockPlatform::new(
                vec![MountPoint {
                    path: mount.clone(),
                    device: "reserve-observer-fixture".into(),
                    // Random writes produce real allocated blocks in the tiny
                    // fixture, independent of the host filesystem's fallocate.
                    fs_type: "btrfs".into(),
                    is_ram_backed: false,
                }],
                HashMap::from([(
                    mount.clone(),
                    FsStats {
                        total_bytes: 1_000_000,
                        free_bytes: 800_000,
                        available_bytes: 800_000,
                        fs_type: "btrfs".into(),
                        mount_point: mount.clone(),
                        is_readonly: false,
                    },
                )]),
                MockPlatform::healthy().memory_info().unwrap(),
                PlatformPaths::default(),
            );
            for index in 1..=10 {
                inner = inner.with_block_count(
                    mount
                        .join(".sbh/ballast")
                        .join(format!("SBH_BALLAST_FILE_{index:05}.dat")),
                    16,
                );
            }
            let (entered_tx, entered) = crossbeam_channel::bounded(1);
            let (release, release_rx) = crossbeam_channel::bounded(1);
            let platform = Arc::new(ProbePlatform {
                inner,
                free: AtomicU64::new(800_000),
                readonly: AtomicBool::new(false),
                block_next: AtomicBool::new(false),
                probes: AtomicUsize::new(0),
                entered: entered_tx,
                release: release_rx,
            });
            let manager_platform: Arc<dyn Platform> = platform.clone();
            let mut coordinator = BallastPoolCoordinator::discover_with_manager_platform(
                &BallastConfig {
                    file_count: 10,
                    file_size_bytes: 8192,
                    replenish_cooldown_minutes: 0,
                    ..BallastConfig::default()
                },
                &[mount],
                platform.as_ref(),
                &manager_platform,
            )
            .unwrap();
            coordinator.set_provision_floor(15.0);
            assert_eq!(
                coordinator
                    .provision_all(platform.as_ref())
                    .unwrap()
                    .total_files_created(),
                10,
            );
            // Still above the floor before allocation, but one more complete
            // 8192-byte file would leave only 14.2808% free.
            platform.free.store(151_000, Ordering::Release);
            Self {
                directory,
                coordinator,
                platform,
                entered,
                release,
            }
        }

        fn mount(&self) -> &Path {
            self.directory.path()
        }

        fn blocked(&self) -> HashMap<PathBuf, Vec<BallastRefillBlocker>> {
            HashMap::from([(
                self.mount().to_path_buf(),
                vec![
                    BallastRefillBlocker::PressurePolicy,
                    BallastRefillBlocker::DryRun,
                ],
            )])
        }

        fn observe(&self, monitor: &mut BallastReserveMonitor, now: Instant) {
            let result = self
                .coordinator
                .prepare_reserve_observation()
                .run(self.platform.as_ref());
            assert!(monitor.accept_observation(&self.coordinator, result, now));
            assert!(!monitor.expire_observations(now));
        }

        fn release_files(&mut self, count: usize) {
            let mount = self.mount().to_path_buf();
            assert_eq!(
                self.coordinator
                    .release_for_mount(&mount, count)
                    .unwrap()
                    .unwrap()
                    .files_released,
                count,
            );
        }
    }

    fn states(events: &[NotificationEvent]) -> Vec<BallastReserveState> {
        events
            .iter()
            .map(|event| match event {
                NotificationEvent::BallastReserveChanged { reserve, .. } => reserve.state,
                _ => panic!("unexpected reserve event"),
            })
            .collect()
    }

    #[test]
    fn actual_pool_releases_and_recovery_notify_only_material_bands() {
        let mut fixture = Fixture::new();
        let mut monitor = BallastReserveMonitor::default();
        let now = Instant::now();
        fixture.observe(&mut monitor, now);
        assert!(monitor.report(&fixture.blocked(), None).0.is_empty());

        for (released, expected) in [
            (5, BallastReserveState::Depleted),
            (3, BallastReserveState::Critical),
            (2, BallastReserveState::Exhausted),
        ] {
            fixture.release_files(released);
            monitor.invalidate(fixture.mount());
            let pending = monitor.snapshot(fixture.mount()).unwrap();
            assert_eq!(pending.state, BallastReserveState::Unknown);
            assert_eq!(pending.releasable_bytes, 0);
            assert!(monitor.report(&fixture.blocked(), None).0.is_empty());
            fixture.observe(&mut monitor, now);
            let (events, _) = monitor.report(&fixture.blocked(), None);
            assert_eq!(states(&events), vec![expected]);
            let snapshot = monitor.snapshot(fixture.mount()).unwrap();
            assert!(!snapshot.headroom.unwrap().can_allocate);
            assert!(
                snapshot
                    .refill_blockers
                    .contains(&BallastRefillBlocker::SafetyFloor)
            );
            assert!(snapshot.summary().contains("safety floor 15.000%"));
            assert!(monitor.report(&fixture.blocked(), None).0.is_empty());
        }

        // Improved pressure alone is not a recovered reserve. The floor stays
        // unchanged and the real existing replenisher performs each allocation.
        fixture.platform.free.store(500_000, Ordering::Release);
        fixture.observe(&mut monitor, now);
        let eligible = HashMap::from([(fixture.mount().to_path_buf(), Vec::new())]);
        let (events, changed) = monitor.report(&eligible, None);
        assert!(events.is_empty());
        assert!(changed);
        assert_eq!(
            monitor.snapshot(fixture.mount()).unwrap().state,
            BallastReserveState::Exhausted,
        );
        let mut recovered = Vec::new();
        for _ in 0..10 {
            let mount = fixture.mount().to_path_buf();
            let report = fixture
                .coordinator
                .replenish_for_mount(&mount, None)
                .unwrap()
                .unwrap();
            assert_eq!(report.files_created, 1, "{report:?}");
            monitor.invalidate(&mount);
            fixture.observe(&mut monitor, now);
            recovered.extend(states(&monitor.report(&eligible, None).0));
        }
        assert_eq!(
            recovered,
            vec![
                BallastReserveState::Critical,
                BallastReserveState::Depleted,
                BallastReserveState::Healthy,
            ],
        );
        assert_eq!(
            monitor.snapshot(fixture.mount()).unwrap().files_available,
            10
        );
    }

    #[test]
    fn prolonged_yellow_is_quiet_and_a_restart_reobserves_the_empty_reserve() {
        let mut fixture = Fixture::new();
        fixture.release_files(10);
        let mut monitor = BallastReserveMonitor::default();
        let start = Instant::now();
        fixture.observe(&mut monitor, start);
        assert_eq!(
            states(&monitor.report(&fixture.blocked(), None).0),
            vec![BallastReserveState::Exhausted],
        );
        for tick in 1_u64..=1404 {
            // 1404 * 30 seconds = 11.7 hours. Time advances without sleeping;
            // every snapshot still probes the real tiny fixture read-only.
            let now = start + Duration::from_secs(tick * 30);
            fixture.observe(&mut monitor, now);
            assert!(monitor.report(&fixture.blocked(), None).0.is_empty());
            let snapshot = monitor.snapshot(fixture.mount()).unwrap();
            assert_eq!(snapshot.files_available, 0);
            assert_eq!(snapshot.state, BallastReserveState::Exhausted);
            assert!(!snapshot.headroom.unwrap().can_allocate);
        }
        let pool = fixture.coordinator.pool_for_mount(fixture.mount()).unwrap();
        assert_eq!(pool.available_count(), 0, "observation must not allocate");
        assert!(std::fs::read_dir(&pool.ballast_dir).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("SBH_BALLAST_")
        }));

        let mut restarted = BallastReserveMonitor::default();
        assert!(restarted.snapshot(fixture.mount()).is_none());
        fixture.observe(&mut restarted, start);
        assert_eq!(
            states(&restarted.report(&fixture.blocked(), None).0),
            vec![BallastReserveState::Exhausted],
            "a new daemon reports its fresh observation without release history",
        );
        assert!(restarted.report(&fixture.blocked(), None).0.is_empty());
    }

    #[test]
    fn unreadable_inventory_notifies_unknown_without_claiming_exhaustion() {
        let fixture = Fixture::new();
        let mut monitor = BallastReserveMonitor::default();
        let now = Instant::now();
        fixture.observe(&mut monitor, now);
        assert!(monitor.report(&fixture.blocked(), None).0.is_empty());
        let pool_dir = fixture
            .coordinator
            .pool_for_mount(fixture.mount())
            .unwrap()
            .ballast_dir
            .clone();
        let retained = fixture.mount().join("retained-pool");
        std::fs::rename(&pool_dir, &retained).unwrap();
        // Deterministic unreadability under root and ordinary users alike.
        std::fs::write(&pool_dir, b"not a directory").unwrap();
        fixture.observe(&mut monitor, now);
        let (events, _) = monitor.report(&fixture.blocked(), None);
        assert_eq!(states(&events), vec![BallastReserveState::Unknown]);
        let snapshot = monitor.snapshot(fixture.mount()).unwrap();
        assert!(!snapshot.inventory_authoritative);
        assert!(snapshot.unreadable_count > 0);
        assert!(
            snapshot
                .refill_blockers
                .contains(&BallastRefillBlocker::InventoryUnreadable)
        );
        assert!(!events[0].summary().contains("no ballast reserve remains"));
        fixture.observe(&mut monitor, now);
        assert!(monitor.report(&fixture.blocked(), None).0.is_empty());
        assert!(retained.join("SBH_BALLAST_FILE_00001.dat").exists());
    }

    #[test]
    fn readonly_inventory_is_unknown_without_an_unreadable_diagnosis() {
        let fixture = Fixture::new();
        let mut monitor = BallastReserveMonitor::default();
        let now = Instant::now();
        fixture.observe(&mut monitor, now);
        assert!(monitor.report(&fixture.blocked(), None).0.is_empty());
        fixture.platform.readonly.store(true, Ordering::Release);
        fixture.observe(&mut monitor, now);
        let (events, _) = monitor.report(&fixture.blocked(), None);
        assert_eq!(states(&events), vec![BallastReserveState::Unknown]);
        let snapshot = monitor.snapshot(fixture.mount()).unwrap();
        assert!(!snapshot.inventory_authoritative);
        assert!(snapshot.releasable_bytes > 0);
        assert_eq!(snapshot.unreadable_count, 0);
        assert!(
            snapshot
                .refill_blockers
                .contains(&BallastRefillBlocker::ReadOnlyFilesystem)
        );
        assert!(
            !snapshot
                .refill_blockers
                .contains(&BallastRefillBlocker::InventoryUnreadable)
        );
        assert!(snapshot.summary().contains("bytes observed"));
        assert!(monitor.report(&fixture.blocked(), None).0.is_empty());

        assert!(monitor.expire_observations(now + MAX_OBSERVATION_AGE));
        assert!(monitor.report(&fixture.blocked(), None).0.is_empty());
        let stale = monitor.snapshot(fixture.mount()).unwrap();
        assert_eq!(stale.releasable_bytes, 0);
        assert_eq!(stale.unreadable_count, 0);
        assert!(
            !stale
                .refill_blockers
                .contains(&BallastRefillBlocker::ReadOnlyFilesystem)
        );
        assert!(
            stale
                .refill_blockers
                .contains(&BallastRefillBlocker::ObservationStale)
        );
        assert!(
            !stale
                .refill_blockers
                .contains(&BallastRefillBlocker::FilesystemStatsUnavailable)
        );
    }

    #[test]
    fn blocked_initial_probe_expires_unknown_without_starting_more_workers() {
        let fixture = Fixture::new();
        fixture.platform.block_next.store(true, Ordering::Release);
        let before = fixture.platform.probes.load(Ordering::Relaxed);
        let platform: Arc<dyn Platform> = fixture.platform.clone();
        let mut monitor = BallastReserveMonitor::default();
        let start = Instant::now();
        assert!(
            monitor
                .tick(&fixture.coordinator, &platform, start)
                .unwrap()
        );
        fixture
            .entered
            .recv_timeout(Duration::from_secs(10))
            .unwrap();
        let worker_id = monitor.worker.as_ref().unwrap().handle.thread().id();
        assert_eq!(
            monitor.snapshot(fixture.mount()).unwrap().state,
            BallastReserveState::Unknown,
        );
        assert!(monitor.report(&fixture.blocked(), None).0.is_empty());

        for seconds in [30, 89, 90, 600, 42_120] {
            monitor
                .tick(
                    &fixture.coordinator,
                    &platform,
                    start + Duration::from_secs(seconds),
                )
                .unwrap();
            let (events, _) = monitor.report(&fixture.blocked(), None);
            assert_eq!(events.len(), usize::from(seconds == 90));
            if seconds == 90 {
                assert_eq!(states(&events), vec![BallastReserveState::Unknown]);
            }
            assert_eq!(
                monitor.worker.as_ref().unwrap().handle.thread().id(),
                worker_id,
                "a stalled native call retains the single worker slot",
            );
            assert_eq!(fixture.platform.probes.load(Ordering::Relaxed), before + 1);
            let snapshot = monitor.snapshot(fixture.mount()).unwrap();
            assert_eq!(snapshot.releasable_bytes, 0);
            assert!(!snapshot.inventory_authoritative);
        }

        fixture.release.send(()).unwrap();
        let worker = monitor.worker.take().unwrap();
        let result = worker.handle.join().unwrap();
        assert!(monitor.accept_observation(&fixture.coordinator, result, worker.started_at));
        assert!(monitor.expire_observations(start + Duration::from_secs(42_120)));
        assert_eq!(
            monitor.snapshot(fixture.mount()).unwrap().state,
            BallastReserveState::Unknown,
            "late completion cannot make an expired read authoritative",
        );
        assert!(monitor.report(&fixture.blocked(), None).0.is_empty());
    }

    #[test]
    fn repeated_invalidation_keeps_the_first_deadline_and_stale_delivery() {
        let fixture = Fixture::new();
        let platform: Arc<dyn Platform> = fixture.platform.clone();
        let mut monitor = BallastReserveMonitor::default();
        let start = Instant::now();
        fixture.observe(&mut monitor, start);
        assert!(monitor.report(&fixture.blocked(), None).0.is_empty());

        fixture.platform.block_next.store(true, Ordering::Release);
        let before = fixture.platform.probes.load(Ordering::Relaxed);
        let invalidated_at = start + Duration::from_secs(1);
        monitor.invalidate_at(fixture.mount(), invalidated_at);
        monitor
            .tick(&fixture.coordinator, &platform, invalidated_at)
            .unwrap();
        fixture
            .entered
            .recv_timeout(Duration::from_secs(10))
            .unwrap();
        let worker_id = monitor.worker.as_ref().unwrap().handle.thread().id();

        // Model failed release attempts while the observer is stuck. Each
        // attempt invalidates its evidence, including after expiry; none
        // supplies a fresh observation that could restart the grace period.
        for seconds in [30, 60, 89, 90, 120, 600, 42_120] {
            let now = invalidated_at + Duration::from_secs(seconds);
            monitor.invalidate_at(fixture.mount(), now);
            monitor.tick(&fixture.coordinator, &platform, now).unwrap();
            let (events, _) = monitor.report(&fixture.blocked(), None);
            assert_eq!(events.len(), usize::from(seconds == 90));
            if seconds == 90 {
                assert_eq!(states(&events), vec![BallastReserveState::Unknown]);
            }
            let expected_delivery = if seconds >= 90 {
                vec![BallastReserveState::Unknown]
            } else {
                Vec::new()
            };
            assert_eq!(states(&monitor.delivery_events()), expected_delivery);
            let snapshot = monitor.snapshot(fixture.mount()).unwrap();
            assert_eq!(snapshot.releasable_bytes, 0);
            assert!(!snapshot.inventory_authoritative);
            assert_eq!(
                snapshot
                    .refill_blockers
                    .contains(&BallastRefillBlocker::ObservationStale),
                seconds >= 90,
            );
            assert_eq!(
                monitor.worker.as_ref().unwrap().handle.thread().id(),
                worker_id,
            );
            assert_eq!(fixture.platform.probes.load(Ordering::Relaxed), before + 1);
        }

        fixture.release.send(()).unwrap();
        let worker = monitor.worker.take().unwrap();
        let result = worker.handle.join().unwrap();
        let recovered_at = invalidated_at + Duration::from_secs(42_121);
        assert!(monitor.accept_observation(&fixture.coordinator, result, worker.started_at));
        assert!(monitor.expire_observations(recovered_at));
        assert!(monitor.report(&fixture.blocked(), None).0.is_empty());

        // A genuinely current observation ends the uncertainty episode. Its
        // next invalidation receives a fresh, bounded grace period.
        fixture.observe(&mut monitor, recovered_at);
        assert_eq!(
            states(&monitor.report(&fixture.blocked(), None).0),
            vec![BallastReserveState::Healthy],
        );
        let next_invalidation = recovered_at + Duration::from_secs(1);
        monitor.invalidate_at(fixture.mount(), next_invalidation);
        assert!(!monitor.expire_observations(next_invalidation + Duration::from_secs(89)));
        assert!(monitor.report(&fixture.blocked(), None).0.is_empty());
        assert!(monitor.expire_observations(next_invalidation + MAX_OBSERVATION_AGE));
        assert_eq!(
            states(&monitor.report(&fixture.blocked(), None).0),
            vec![BallastReserveState::Unknown],
        );
        assert!(monitor.report(&fixture.blocked(), None).0.is_empty());
    }

    #[test]
    fn repeated_reload_keeps_uncertainty_deadline_and_refreshes_configuration() {
        let mut fixture = Fixture::new();
        let platform: Arc<dyn Platform> = fixture.platform.clone();
        let mut monitor = BallastReserveMonitor::default();
        let start = Instant::now();
        fixture.observe(&mut monitor, start);
        assert!(monitor.report(&fixture.blocked(), None).0.is_empty());

        fixture.platform.block_next.store(true, Ordering::Release);
        let before = fixture.platform.probes.load(Ordering::Relaxed);
        monitor.invalidate_all_at(start);
        monitor
            .tick(&fixture.coordinator, &platform, start)
            .unwrap();
        fixture
            .entered
            .recv_timeout(Duration::from_secs(10))
            .unwrap();
        let worker_id = monitor.worker.as_ref().unwrap().handle.thread().id();
        fixture.coordinator.update_config(&BallastConfig {
            file_count: 20,
            file_size_bytes: 8192,
            replenish_cooldown_minutes: 0,
            ..BallastConfig::default()
        });
        fixture.coordinator.set_provision_floor(20.0);

        for seconds in [30, 60, 89, 90, 120, 600, 42_120] {
            let now = start + Duration::from_secs(seconds);
            monitor.invalidate_all_at(now);
            assert!(monitor.delivery_events().is_empty());
            monitor.tick(&fixture.coordinator, &platform, now).unwrap();
            let (events, _) = monitor.report(&fixture.blocked(), None);
            assert_eq!(events.len(), usize::from(seconds == 90));
            if seconds == 90 {
                assert_eq!(states(&events), vec![BallastReserveState::Unknown]);
            }
            let snapshot = monitor.snapshot(fixture.mount()).unwrap();
            assert_eq!(snapshot.files_total, 20);
            assert_eq!(snapshot.configured_bytes, 20 * 8192);
            assert_eq!(snapshot.releasable_bytes, 0);
            assert!(snapshot.headroom.is_none());
            assert!(!snapshot.inventory_authoritative);
            assert_eq!(
                snapshot
                    .refill_blockers
                    .contains(&BallastRefillBlocker::ObservationStale),
                seconds >= 90,
            );
            assert_eq!(monitor.delivery_events().len(), usize::from(seconds >= 90),);
            assert_eq!(
                monitor.worker.as_ref().unwrap().handle.thread().id(),
                worker_id,
            );
            assert_eq!(fixture.platform.probes.load(Ordering::Relaxed), before + 1);
        }

        fixture.release.send(()).unwrap();
        let worker = monitor.worker.take().unwrap();
        let result = worker.handle.join().unwrap();
        assert!(!monitor.accept_observation(&fixture.coordinator, result, worker.started_at));
        let recovered_at = start + Duration::from_secs(42_121);
        fixture.observe(&mut monitor, recovered_at);
        assert_eq!(
            states(&monitor.report(&fixture.blocked(), None).0),
            vec![BallastReserveState::Depleted],
        );
        let headroom = monitor.snapshot(fixture.mount()).unwrap().headroom.unwrap();
        assert!((headroom.floor_pct - 20.0).abs() < f64::EPSILON);

        let next_reload = recovered_at + Duration::from_secs(1);
        monitor.invalidate_all_at(next_reload);
        assert!(monitor.seed_observations(&fixture.coordinator, next_reload));
        assert!(!monitor.expire_observations(next_reload + Duration::from_secs(89)));
        assert!(monitor.report(&fixture.blocked(), None).0.is_empty());
        assert!(monitor.expire_observations(next_reload + MAX_OBSERVATION_AGE));
        assert_eq!(
            states(&monitor.report(&fixture.blocked(), None).0),
            vec![BallastReserveState::Unknown],
        );
    }

    #[test]
    fn reload_replacement_directory_gets_a_new_uncertainty_episode() {
        let mut fixture = Fixture::new();
        let mut monitor = BallastReserveMonitor::default();
        let start = Instant::now();
        fixture.observe(&mut monitor, start);
        assert!(monitor.report(&fixture.blocked(), None).0.is_empty());
        assert!(monitor.expire_observations(start + MAX_OBSERVATION_AGE));
        assert_eq!(
            states(&monitor.report(&fixture.blocked(), None).0),
            vec![BallastReserveState::Unknown],
        );

        let replacement_dir = fixture.mount().join("replacement-ballast");
        let platform: Arc<dyn Platform> = fixture.platform.clone();
        fixture.coordinator = BallastPoolCoordinator::discover_inner(
            &BallastConfig {
                file_count: 3,
                file_size_bytes: 8192,
                ..BallastConfig::default()
            },
            &[fixture.mount().to_path_buf()],
            fixture.platform.as_ref(),
            &platform,
            Some(&replacement_dir),
        )
        .unwrap();
        let reloaded_at = start + Duration::from_secs(120);
        monitor.invalidate_all_at(reloaded_at);
        assert!(monitor.delivery_events().is_empty());
        assert!(monitor.seed_observations(&fixture.coordinator, reloaded_at));
        assert!(monitor.reported.is_empty());
        assert!(monitor.latest_notifications.is_empty());
        let snapshot = monitor.snapshot(fixture.mount()).unwrap();
        assert_eq!(snapshot.ballast_dir, replacement_dir);
        assert_eq!(snapshot.files_total, 3);
        assert!(snapshot.observed_at.is_empty());
        assert!(!monitor.expire_observations(reloaded_at + Duration::from_secs(89)));
        assert!(monitor.report(&fixture.blocked(), None).0.is_empty());
        assert!(monitor.expire_observations(reloaded_at + MAX_OBSERVATION_AGE));
        assert_eq!(
            states(&monitor.report(&fixture.blocked(), None).0),
            vec![BallastReserveState::Unknown],
        );
    }

    #[test]
    fn reload_preserves_recovery_transitions_and_forgets_removed_pools() {
        let mut fixture = Fixture::new();
        fixture.release_files(10);
        let mut monitor = BallastReserveMonitor::default();
        let now = Instant::now();
        fixture.observe(&mut monitor, now);
        assert_eq!(
            states(&monitor.report(&fixture.blocked(), None).0),
            vec![BallastReserveState::Exhausted],
        );

        monitor.invalidate_all();
        assert!(monitor.delivery_events().is_empty());
        assert!(monitor.seed_observations(&fixture.coordinator, now));
        assert!(monitor.delivery_events().is_empty());
        fixture.observe(&mut monitor, now);
        assert!(monitor.report(&fixture.blocked(), None).0.is_empty());

        // Refill completes while the reloaded daemon still awaits its first
        // current observation. Healthy must be a recovery transition, not an
        // initial quiet state that leaves downstream dedup stuck at Exhausted.
        monitor.invalidate_all();
        assert!(monitor.seed_observations(&fixture.coordinator, now));
        fixture.platform.free.store(500_000, Ordering::Release);
        for _ in 0..10 {
            let mount = fixture.mount().to_path_buf();
            assert_eq!(
                fixture
                    .coordinator
                    .replenish_for_mount(&mount, None)
                    .unwrap()
                    .unwrap()
                    .files_created,
                1,
            );
        }
        let eligible = HashMap::from([(fixture.mount().to_path_buf(), Vec::new())]);
        fixture.observe(&mut monitor, now);
        assert_eq!(
            states(&monitor.report(&eligible, None).0),
            vec![BallastReserveState::Healthy],
        );
        assert_eq!(
            states(&monitor.delivery_events()),
            vec![BallastReserveState::Healthy]
        );

        fixture.release_files(10);
        monitor.invalidate(fixture.mount());
        fixture.observe(&mut monitor, now);
        assert_eq!(
            states(&monitor.report(&eligible, None).0),
            vec![BallastReserveState::Exhausted],
        );

        let replacement = Fixture::new();
        monitor.invalidate_all();
        assert!(monitor.seed_observations(&replacement.coordinator, now));
        assert!(monitor.snapshot(fixture.mount()).is_none());
        assert!(monitor.reported.is_empty());
        assert!(monitor.latest_notifications.is_empty());
        assert!(monitor.delivery_events().is_empty());
    }

    #[test]
    fn invalidation_hides_old_bytes_and_rejects_a_pre_release_result() {
        let mut fixture = Fixture::new();
        let mut monitor = BallastReserveMonitor::default();
        let now = Instant::now();
        fixture.observe(&mut monitor, now);
        assert!(monitor.report(&fixture.blocked(), None).0.is_empty());
        let before_release = fixture
            .coordinator
            .prepare_reserve_observation()
            .run(fixture.platform.as_ref());
        fixture.release_files(10);
        monitor.invalidate(fixture.mount());
        let snapshot = monitor.snapshot(fixture.mount()).unwrap();
        assert_eq!(snapshot.state, BallastReserveState::Unknown);
        assert_eq!(snapshot.releasable_bytes, 0);
        assert!(snapshot.headroom.is_none());
        assert!(snapshot.observed_at.is_empty());
        assert!(monitor.delivery_events().is_empty());
        assert!(!monitor.accept_observation(&fixture.coordinator, before_release, now));
        assert!(monitor.report(&fixture.blocked(), None).0.is_empty());

        let expired_at = monitor.observations[fixture.mount()].started_at + MAX_OBSERVATION_AGE;
        assert!(monitor.expire_observations(expired_at));
        assert_eq!(
            states(&monitor.report(&fixture.blocked(), None).0),
            vec![BallastReserveState::Unknown],
        );
        fixture.observe(&mut monitor, expired_at);
        assert_eq!(
            states(&monitor.report(&fixture.blocked(), None).0),
            vec![BallastReserveState::Exhausted],
        );
    }
}
