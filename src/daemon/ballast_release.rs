//! Bounded automatic ballast release without native I/O on the monitor.
//!
//! Two retained slots let an unrelated pool proceed when one device stalls.
//! Cancelled work keeps its slot until the syscall returns. Admission, renewal,
//! polling and first-chance cleanup holds are memory-only; every unlink renews
//! live authority on the worker after its native identity checks.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};

use crate::ballast::coordinator::{BallastPoolCoordinator, BallastRelease, BallastReleasePlan};
use crate::ballast::manager::ReleaseReport;
use crate::ballast::release::BallastReleaseController;
use crate::core::config::ScannerConfig;
use crate::monitor::pid::{PressureLevel, PressureResponse};
use crate::platform::pal::Platform;

use super::policy::PolicyEngine;

const WORKER_LIMIT: usize = 2;
const FIRST_CHANCE: Duration = Duration::from_secs(2);
const RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// Reserve authority supplied by this mount's admitted exhaustion forecast.
/// Keep it separate from physical pressure: a small volume can fill in seconds
/// while its percentage-based PID still has zero urgency.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum ForecastRelease {
    Imminent,
    Critical,
}

/// A physical pool's intent from this tick's original native observation.
#[derive(Clone)]
pub(super) struct ReleaseRequest {
    pub pool: PathBuf,
    pub response: PressureResponse,
    pub recovery: bool,
    pub forecast: Option<ForecastRelease>,
    pub observed_at: Instant,
    pub max_age: Duration,
    pub policy_transitions: u64,
    pub device_id: u64,
}

impl ReleaseRequest {
    fn strength(&self) -> usize {
        if self.recovery
            || self.forecast == Some(ForecastRelease::Critical)
            || self.response.level == PressureLevel::Critical
            || self.response.urgency >= 0.9
        {
            return usize::MAX;
        }
        let urgency = if self.response.urgency >= 0.6 {
            3
        } else {
            usize::from(self.response.urgency >= 0.3)
        };
        let floor = match self.response.level {
            PressureLevel::Red => 3,
            PressureLevel::Orange => 1,
            _ => 0,
        };
        self.response
            .release_ballast_files
            .max(urgency)
            .max(floor)
            .max(usize::from(self.forecast.is_some()))
    }

    fn fresh(&self, now: Instant) -> bool {
        now.checked_duration_since(self.observed_at)
            .is_some_and(|age| age < self.max_age)
    }

    /// A weaker request must not revive an old release-all invocation.
    fn renews(&self, old: &Self, now: Instant) -> bool {
        self.pool == old.pool
            && self.device_id == old.device_id
            && self.policy_transitions == old.policy_transitions
            && self.recovery == old.recovery
            && self.forecast >= old.forecast
            && self.strength() >= old.strength()
            && self.fresh(now)
    }
}

#[derive(Clone)]
pub(super) struct ReleaseContext {
    pub platform: Arc<dyn Platform>,
    pub policy: Arc<Mutex<PolicyEngine>>,
    pub scanner: Arc<RwLock<ScannerConfig>>,
    pub shutdown: Arc<AtomicBool>,
}

pub(super) struct ReleaseStart {
    pub pool: PathBuf,
    pub recovery: bool,
}

pub(super) struct ReleaseCompletion {
    pub task: BallastRelease,
    pub report: ReleaseReport,
    pub request: ReleaseRequest,
    pub free_before: Option<u64>,
    pub completed_at: Instant,
}

struct Permission {
    cancelled: AtomicBool,
    evidence: Mutex<(Instant, Duration)>,
    policy_transitions: u64,
    requires_forecast_policy: bool,
    context: ReleaseContext,
}

impl Permission {
    fn new(request: &ReleaseRequest, context: ReleaseContext) -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            evidence: Mutex::new((request.observed_at, request.max_age)),
            policy_transitions: request.policy_transitions,
            requires_forecast_policy: request.forecast.is_some(),
            context,
        }
    }

    fn allowed(&self) -> bool {
        if self.cancelled.load(Ordering::Acquire) {
            return false;
        }
        let fresh = {
            let (observed_at, max_age) = *self.evidence.lock();
            Instant::now()
                .checked_duration_since(observed_at)
                .is_some_and(|age| age < max_age)
        };
        // Guards are released before any native probe or unlink. A contended
        // control update fails closed instead of parking behind its lock.
        let scanner_allows = self
            .context
            .scanner
            .try_read()
            .is_some_and(|scanner| !scanner.dry_run);
        let policy_allows = self.context.policy.try_lock().is_some_and(|policy| {
            !policy.config().kill_switch
                && policy.transitions_total() == self.policy_transitions
                && (!self.requires_forecast_policy || policy.mode().allows_deletion())
        });
        // Physical pressure may release sacrificial reserve in Observe mode.
        // A forecast cannot add adaptive authority in Observe/FallbackSafe,
        // and every mode transition revokes the captured authorization.
        let allowed = fresh
            && scanner_allows
            && policy_allows
            && !self.context.shutdown.load(Ordering::Acquire);
        if !allowed {
            self.cancel();
        }
        allowed && !self.cancelled.load(Ordering::Acquire)
    }

    fn renew(&self, request: &ReleaseRequest) {
        // Expiry and every other refusal are sticky: a later healthy tick
        // cannot resurrect a request paused inside a native call.
        if self.allowed() {
            *self.evidence.lock() = (request.observed_at, request.max_age);
        }
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

struct Worker {
    request: ReleaseRequest,
    permission: Arc<Permission>,
    handle: JoinHandle<ReleaseCompletion>,
}

/// Automatic release state. Occupied slots include irrevocably cancelled work.
#[derive(Default)]
pub(super) struct BallastReleaser {
    requests: BTreeMap<PathBuf, ReleaseRequest>,
    workers: Vec<Worker>,
    last_started: BTreeMap<PathBuf, Instant>,
    first_chance: BTreeMap<PathBuf, Instant>,
    intervention_since_sample: bool,
}

impl BallastReleaser {
    pub(super) fn begin_tick(&mut self) {
        self.requests.clear();
    }

    /// Alias requests share one physical worker and the strongest live intent.
    pub(super) fn request(&mut self, request: ReleaseRequest) {
        if !request.fresh(Instant::now()) || request.strength() == 0 {
            return;
        }
        let replace = self.requests.get(&request.pool).is_none_or(|old| {
            request.device_id != old.device_id
                || request.policy_transitions != old.policy_transitions
                || request.strength() > old.strength()
                || (request.strength() == old.strength() && request.observed_at > old.observed_at)
        });
        if replace {
            self.requests.insert(request.pool.clone(), request);
        }
    }

    /// Renew after collecting the entire tick's intents, then admit fairly.
    /// Preparing a task invalidates older inventory observations immediately.
    pub(super) fn start_pending(
        &mut self,
        coordinator: &mut BallastPoolCoordinator,
        controller: &BallastReleaseController,
        context: ReleaseContext,
        now: Instant,
    ) -> Vec<std::result::Result<ReleaseStart, (PathBuf, std::io::Error)>> {
        self.requests.retain(|_, request| request.fresh(now));
        self.first_chance
            .retain(|pool, _| self.requests.contains_key(pool));
        self.last_started.retain(|pool, started| {
            self.requests.contains_key(pool)
                || now.saturating_duration_since(*started) < RETRY_INTERVAL
        });
        for worker in &self.workers {
            match self.requests.get(&worker.request.pool) {
                Some(request) if request.renews(&worker.request, now) => {
                    worker.permission.renew(request);
                }
                _ => worker.permission.cancel(),
            }
        }

        // Older/unserved pools precede a fast no-op pool. A stuck slot is never
        // replaced, and queued requests never hold unrelated cleanup.
        let mut candidates: Vec<_> = self.requests.keys().cloned().collect();
        candidates.sort_by(|left, right| {
            self.last_started
                .get(left)
                .cmp(&self.last_started.get(right))
                .then_with(|| left.cmp(right))
        });
        let mut starts = Vec::new();
        for pool in candidates {
            if self.workers.len() >= WORKER_LIMIT {
                break;
            }
            if self.busy_mount(&pool)
                || self
                    .last_started
                    .get(&pool)
                    .is_some_and(|last| now.saturating_duration_since(*last) < RETRY_INTERVAL)
            {
                continue;
            }
            let request = self.requests[&pool].clone();
            let permission = Arc::new(Permission::new(&request, context.clone()));
            if !permission.allowed() {
                continue;
            }
            let Some(mut task) = coordinator.prepare_release(&pool) else {
                continue;
            };
            let mut response = request.response.clone();
            // The native controller must receive the same minimum request as
            // admission. Raising strength alone would still produce a no-op
            // when physical Green pressure recommends zero files.
            if request.forecast.is_some() {
                response.release_ballast_files = response.release_ballast_files.max(1);
            }
            let plan = BallastReleasePlan {
                response,
                release_all: request.recovery
                    || request.forecast == Some(ForecastRelease::Critical),
                history: controller.cached_pool_history(&pool),
                unbound_history: controller.cached_unbound_pool_history(&pool),
                efficiency: controller.release_efficiency(&pool),
                device_id: request.device_id,
            };
            let worker_permission = Arc::clone(&permission);
            let worker_request = request.clone();
            let recovery = request.recovery;
            let platform = Arc::clone(&context.platform);
            self.last_started.insert(pool.clone(), now);
            let result = std::thread::Builder::new()
                .name("sbh-ballast-release".into())
                .spawn(move || {
                    // Unknown free space is not a zero baseline. A stalled
                    // native pre-sample retains this slot and no monitor lock.
                    let free_before = if worker_permission.allowed() {
                        platform
                            .fs_stats(task.mount())
                            .ok()
                            .and_then(|stats| (!stats.is_readonly).then_some(stats.available_bytes))
                    } else {
                        None
                    };
                    let report = task.run(&plan, &|| worker_permission.allowed());
                    ReleaseCompletion {
                        task,
                        report,
                        request: worker_request,
                        free_before,
                        completed_at: Instant::now(),
                    }
                });
            match result {
                Ok(handle) => {
                    self.first_chance.entry(pool.clone()).or_insert(now);
                    self.intervention_since_sample = true;
                    self.workers.push(Worker {
                        request,
                        permission,
                        handle,
                    });
                    starts.push(Ok(ReleaseStart { pool, recovery }));
                }
                Err(error) => starts.push(Err((pool, error))),
            }
        }
        starts
    }

    #[cfg(test)]
    pub(super) fn elapse_retry_interval(&mut self, pool: &Path) {
        if let Some(started) = self.last_started.get_mut(pool) {
            *started = Instant::now()
                .checked_sub(RETRY_INTERVAL)
                .unwrap_or(*started);
        }
    }

    pub(super) fn busy(&self) -> bool {
        !self.workers.is_empty()
    }

    pub(super) fn busy_mount(&self, mount: &Path) -> bool {
        self.workers
            .iter()
            .any(|worker| worker.request.pool == mount)
    }

    pub(super) fn requested(&self, mount: &Path) -> bool {
        self.requests
            .get(mount)
            .is_some_and(|request| request.fresh(Instant::now()))
    }

    /// Only running authorized work gets a fixed first chance before cleanup.
    /// Renewal and retry cannot restart the hold during continuous pressure.
    pub(super) fn waits_mount(&self, mount: &Path, now: Instant) -> bool {
        self.first_chance
            .get(mount)
            .is_some_and(|first| now.saturating_duration_since(*first) < FIRST_CHANCE)
            && self.workers.iter().any(|worker| {
                worker.request.pool == mount
                    && worker.permission.allowed()
                    && self
                        .requests
                        .get(mount)
                        .is_some_and(|request| request.renews(&worker.request, now))
            })
    }

    pub(super) fn cancel_mount(&mut self, mount: &Path) {
        self.requests.remove(mount);
        self.first_chance.remove(mount);
        for worker in &self.workers {
            if worker.request.pool == mount {
                worker.permission.cancel();
            }
        }
    }

    pub(super) fn cancel(&mut self) {
        self.requests.clear();
        self.first_chance.clear();
        for worker in &self.workers {
            worker.permission.cancel();
        }
    }

    /// Censor samples spanning admission, an occupied native worker, or its
    /// first completed receipt; only actual reports provide release credit.
    pub(super) fn take_forecast_intervention(&mut self) -> bool {
        std::mem::take(&mut self.intervention_since_sample) || self.busy()
    }

    pub(super) fn poll(&mut self) -> Vec<std::thread::Result<ReleaseCompletion>> {
        let mut completed = Vec::new();
        let mut occupied = Vec::new();
        for worker in self.workers.drain(..) {
            if worker.handle.is_finished() {
                self.intervention_since_sample = true;
                completed.push(worker.handle.join());
            } else {
                occupied.push(worker);
            }
        }
        self.workers = occupied;
        completed
    }
}

impl Drop for BallastReleaser {
    fn drop(&mut self) {
        self.cancel();
        // Running handles detach on drop, carrying sticky cancellation and the
        // shared shutdown token until native I/O eventually returns.
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::core::config::BallastConfig;
    use crate::core::errors::Result;
    use crate::platform::pal::{
        FsStats, MemoryInfo, MockPlatform, MountPoint, PlatformPaths, ServiceManager,
    };
    use std::collections::{BTreeSet, HashMap};
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::sync::atomic::AtomicUsize;

    struct BlockingPlatform {
        inner: MockPlatform,
        blocked: Mutex<BTreeSet<PathBuf>>,
        calls: AtomicUsize,
        entered: crossbeam_channel::Sender<PathBuf>,
        release: crossbeam_channel::Receiver<()>,
    }

    impl Platform for BlockingPlatform {
        fn fs_stats(&self, path: &Path) -> Result<FsStats> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let blocked = self.blocked.lock().remove(path);
            if blocked {
                let _ = self.entered.send(path.to_path_buf());
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
        _directory: tempfile::TempDir,
        mounts: Vec<PathBuf>,
        coordinator: BallastPoolCoordinator,
        platform: Arc<BlockingPlatform>,
        context: ReleaseContext,
        controller: BallastReleaseController,
        entered: crossbeam_channel::Receiver<PathBuf>,
        release: crossbeam_channel::Sender<()>,
    }

    impl Fixture {
        fn new(count: usize) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let mounts: Vec<_> = (0..count)
                .map(|index| directory.path().join(format!("mount-{index}")))
                .collect();
            let mut stats = HashMap::new();
            let mut mount_points = Vec::new();
            for (index, mount) in mounts.iter().enumerate() {
                let pool = mount.join(".sbh/ballast");
                fs::create_dir_all(&pool).unwrap();
                for slot in 1..=2 {
                    // Configured damaged regular reserve is still releasable.
                    fs::write(
                        pool.join(format!("SBH_BALLAST_FILE_{slot:05}.dat")),
                        vec![0u8; 8192],
                    )
                    .unwrap();
                }
                mount_points.push(MountPoint {
                    path: mount.clone(),
                    device: format!("/dev/release-test-{index}"),
                    fs_type: "ext4".into(),
                    is_ram_backed: false,
                });
                stats.insert(
                    mount.clone(),
                    FsStats {
                        total_bytes: 1 << 30,
                        free_bytes: 1 << 27,
                        available_bytes: 1 << 27,
                        fs_type: "ext4".into(),
                        mount_point: mount.clone(),
                        is_readonly: false,
                    },
                );
            }
            let (entered_tx, entered) = crossbeam_channel::bounded(count.max(1));
            let (release, release_rx) = crossbeam_channel::bounded(count.max(1));
            let platform = Arc::new(BlockingPlatform {
                inner: MockPlatform::new(
                    mount_points,
                    stats,
                    MockPlatform::healthy().memory_info().unwrap(),
                    PlatformPaths::default(),
                ),
                blocked: Mutex::new(BTreeSet::new()),
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
                &mounts,
                platform.as_ref(),
                &manager_platform,
            )
            .unwrap();
            assert_eq!(coordinator.pool_count(), count);
            let context = ReleaseContext {
                platform: platform.clone(),
                policy: Arc::new(Mutex::new(PolicyEngine::new(Default::default()))),
                scanner: Arc::new(RwLock::new(ScannerConfig::default())),
                shutdown: Arc::new(AtomicBool::new(false)),
            };
            Self {
                _directory: directory,
                mounts,
                coordinator,
                platform,
                context,
                controller: BallastReleaseController::new(0),
                entered,
                release,
            }
        }

        fn request(&self, index: usize) -> ReleaseRequest {
            let pool = self.mounts[index].clone();
            ReleaseRequest {
                response: PressureResponse {
                    level: PressureLevel::Critical,
                    urgency: 1.0,
                    scan_interval: Duration::from_secs(1),
                    release_ballast_files: 0,
                    max_delete_batch: 0,
                    fallback_active: false,
                    causing_mount: pool.clone(),
                    free_pct: 1.0,
                    predicted_seconds: None,
                },
                device_id: fs::metadata(&pool).unwrap().dev(),
                pool,
                recovery: false,
                forecast: None,
                observed_at: Instant::now(),
                max_age: Duration::from_secs(60),
                policy_transitions: self.context.policy.lock().transitions_total(),
            }
        }

        fn start(&mut self, releaser: &mut BallastReleaser) -> usize {
            let starts = releaser.start_pending(
                &mut self.coordinator,
                &self.controller,
                self.context.clone(),
                Instant::now(),
            );
            assert!(starts.iter().all(std::result::Result::is_ok));
            starts.len()
        }

        fn block(&self, index: usize) {
            self.platform
                .blocked
                .lock()
                .insert(self.mounts[index].clone());
        }

        fn wait_for_probe(&self, index: usize) {
            assert_eq!(
                self.entered.recv_timeout(Duration::from_secs(10)).unwrap(),
                self.mounts[index],
            );
        }

        fn physical_count(&self, index: usize) -> usize {
            (1..=2)
                .filter(|slot| {
                    self.mounts[index]
                        .join(format!(".sbh/ballast/SBH_BALLAST_FILE_{slot:05}.dat"))
                        .exists()
                })
                .count()
        }
    }

    fn finish_one(releaser: &mut BallastReleaser) -> ReleaseCompletion {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let mut results = releaser.poll();
            if !results.is_empty() {
                assert_eq!(results.len(), 1);
                return results.pop().unwrap().unwrap();
            }
            assert!(Instant::now() < deadline, "release worker did not finish");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Exercise the real estimator and policy with a small mostly-empty
    /// volume. A live writer is imminent while negative PID error still wins
    /// over feedforward, so percentage pressure supplies no release request.
    fn green_imminent_response(
        mount: &Path,
        critical: bool,
    ) -> (PressureResponse, ForecastRelease) {
        use crate::monitor::ewma::DiskRateEstimator;
        use crate::monitor::pid::{PidConfig, PidPressureController, PressureReading};
        use crate::monitor::predictive::{PredictiveAction, PredictiveActionPolicy};

        let start = Instant::now()
            .checked_sub(Duration::from_secs(1810))
            .unwrap();
        let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 5);
        let mut free = 2_500_000_000_u64;
        let total = 3_000_000_000_u64;
        let threshold = 300_000_000;
        for step in 0..=360_u64 {
            estimator.update(free, start + Duration::from_secs(step * 5), threshold);
        }
        let mut estimate = None;
        let mut at = start;
        let intervals = if critical { 2_u64 } else { 1 };
        for step in 1..=intervals {
            free -= 500_000_000;
            at = start + Duration::from_secs(1800 + step * 5);
            estimate = Some(estimator.update(free, at, threshold));
        }
        let estimate = estimate.unwrap();
        let reading = PressureReading {
            free_bytes: free,
            total_bytes: total,
            mount: mount.to_path_buf(),
        };
        let action = PredictiveActionPolicy::new(Default::default()).evaluate(
            &estimate,
            reading.free_pct(),
            mount.to_path_buf(),
        );
        match action {
            PredictiveAction::ImminentDanger {
                critical: actual, ..
            } => assert_eq!(actual, critical),
            other => panic!("fixture must produce admitted imminent exhaustion: {other:?}"),
        }
        let mut pid = PidPressureController::new(&PidConfig::default(), Duration::from_secs(5));
        pid.set_action_horizon_minutes(30.0);
        let response = pid.update(reading, Some(estimate.seconds_to_threshold), at);
        assert_eq!(response.level, PressureLevel::Green);
        assert!(response.urgency.abs() < f64::EPSILON);
        assert_eq!(response.release_ballast_files, 0);
        (
            response,
            if critical {
                ForecastRelease::Critical
            } else {
                ForecastRelease::Imminent
            },
        )
    }

    #[test]
    fn admitted_imminence_releases_reserve_even_when_the_pid_requests_nothing() {
        for critical in [false, true] {
            let mut fixture = Fixture::new(1);
            let mut releaser = BallastReleaser::default();
            let (response, forecast) = green_imminent_response(&fixture.mounts[0], critical);
            let mut request = fixture.request(0);
            request.response = response;
            // Negative control: physical Green pressure alone has no authority.
            releaser.request(request.clone());
            assert_eq!(fixture.start(&mut releaser), 0);
            request.forecast = Some(forecast);
            releaser.request(request.clone());
            assert_eq!(fixture.start(&mut releaser), 1);
            let completion = finish_one(&mut releaser);
            let expected = if critical { 2 } else { 1 };
            assert_eq!(completion.report.files_released, expected);
            assert_eq!(completion.request.response.level, PressureLevel::Green);
            assert!(completion.request.response.urgency.abs() < f64::EPSILON);
            assert_eq!(completion.request.response.release_ballast_files, 0);
            let (before, after) = completion.task.observations().unwrap();
            fixture
                .controller
                .observe_pool_inventory(&fixture.mounts[0], before);
            fixture.controller.on_released(&fixture.mounts[0], expected);
            fixture
                .controller
                .observe_pool_inventory(&fixture.mounts[0], after);
            assert!(fixture.coordinator.finish_release(completion.task));
            assert_eq!(fixture.physical_count(0), 2 - expected);

            // Non-critical imminence uses the existing cumulative allowance,
            // rather than releasing one more file on every pressure tick.
            if !critical {
                releaser.begin_tick();
                releaser.elapse_retry_interval(&fixture.mounts[0]);
                releaser.request(request);
                assert_eq!(fixture.start(&mut releaser), 1);
                assert_eq!(finish_one(&mut releaser).report.files_released, 0);
                assert_eq!(fixture.physical_count(0), 1);
            }
        }
    }

    #[test]
    fn withdrawn_or_weaker_forecast_cannot_revive_a_stalled_release() {
        for weaker in [false, true] {
            let mut fixture = Fixture::new(1);
            let mut releaser = BallastReleaser::default();
            let (response, forecast) = green_imminent_response(&fixture.mounts[0], true);
            let mut request = fixture.request(0);
            request.response = response;
            request.forecast = Some(forecast);
            fixture.block(0);
            releaser.request(request.clone());
            assert_eq!(fixture.start(&mut releaser), 1);
            fixture.wait_for_probe(0);

            let mut withdrawn = request.clone();
            withdrawn.forecast = weaker.then_some(ForecastRelease::Imminent);
            releaser.begin_tick();
            releaser.request(withdrawn);
            assert_eq!(fixture.start(&mut releaser), 0);
            assert!(!releaser.waits_mount(&fixture.mounts[0], Instant::now()));
            releaser.begin_tick();
            releaser.request(request);
            assert_eq!(fixture.start(&mut releaser), 0);
            fixture.release.send(()).unwrap();
            assert_eq!(finish_one(&mut releaser).report.files_released, 0);
            assert_eq!(fixture.physical_count(0), 2);
        }
    }

    #[test]
    fn observe_and_fallback_modes_cannot_grant_forecast_only_release() {
        use super::super::policy::{ActiveMode, PolicyConfig};

        for mode in [ActiveMode::Observe, ActiveMode::FallbackSafe] {
            let mut fixture = Fixture::new(1);
            *fixture.context.policy.lock() = PolicyEngine::new(PolicyConfig {
                initial_mode: mode,
                ..Default::default()
            });
            let mut releaser = BallastReleaser::default();
            let (response, forecast) = green_imminent_response(&fixture.mounts[0], true);
            let mut request = fixture.request(0);
            request.response = response;
            request.forecast = Some(forecast);
            releaser.request(request);
            assert_eq!(fixture.start(&mut releaser), 0, "{mode:?}");
            assert_eq!(fixture.physical_count(0), 2);

            // Conservative physical-pressure rescue keeps its existing
            // behavior even when adaptive predictions are held.
            releaser.begin_tick();
            releaser.request(fixture.request(0));
            assert_eq!(fixture.start(&mut releaser), 1, "{mode:?}");
            assert_eq!(finish_one(&mut releaser).report.files_released, 2);
        }
    }

    #[test]
    fn forecast_release_rechecks_mode_and_expiry_after_a_blocked_native_probe() {
        use super::super::policy::{ActiveMode, PolicyConfig};

        for mode in [
            Some(ActiveMode::Observe),
            Some(ActiveMode::FallbackSafe),
            None,
        ] {
            let mut fixture = Fixture::new(1);
            let mut releaser = BallastReleaser::default();
            let (response, forecast) = green_imminent_response(&fixture.mounts[0], true);
            let mut request = fixture.request(0);
            request.response = response;
            request.forecast = Some(forecast);
            fixture.block(0);
            releaser.request(request);
            assert_eq!(fixture.start(&mut releaser), 1);
            fixture.wait_for_probe(0);
            if let Some(mode) = mode {
                *fixture.context.policy.lock() = PolicyEngine::new(PolicyConfig {
                    initial_mode: mode,
                    ..Default::default()
                });
            } else {
                *releaser.workers[0].permission.evidence.lock() = (
                    Instant::now().checked_sub(Duration::from_secs(61)).unwrap(),
                    Duration::from_secs(60),
                );
            }
            fixture.release.send(()).unwrap();
            assert_eq!(finish_one(&mut releaser).report.files_released, 0);
            assert_eq!(fixture.physical_count(0), 2);
        }
    }

    #[test]
    fn stalled_release_keeps_monitor_and_other_pools_progressing_with_two_slots() {
        let mut fixture = Fixture::new(3);
        let mut releaser = BallastReleaser::default();
        fixture.block(0);
        releaser.request(fixture.request(0));
        let calls = fixture.platform.calls.load(Ordering::Relaxed);
        assert_eq!(fixture.start(&mut releaser), 1);
        fixture.wait_for_probe(0);
        assert_eq!(fixture.platform.calls.load(Ordering::Relaxed), calls + 1);

        releaser.begin_tick();
        for index in 0..3 {
            releaser.request(fixture.request(index));
        }
        assert_eq!(fixture.start(&mut releaser), 1);
        assert_eq!(releaser.workers.len(), WORKER_LIMIT);
        assert!(!releaser.waits_mount(&fixture.mounts[2], Instant::now()));
        assert!(releaser.take_forecast_intervention());
        let second = finish_one(&mut releaser);
        assert_eq!(second.request.pool, fixture.mounts[1]);
        assert_eq!(second.report.files_released, 2);
        assert!(fixture.coordinator.finish_release(second.task));
        assert!(releaser.busy_mount(&fixture.mounts[0]));

        // The unserved pool wins the free slot ahead of the fast completed one.
        assert_eq!(fixture.start(&mut releaser), 1);
        let third = finish_one(&mut releaser);
        assert_eq!(third.request.pool, fixture.mounts[2]);
        assert_eq!(third.report.files_released, 2);
        assert!(fixture.coordinator.finish_release(third.task));

        releaser.cancel_mount(&fixture.mounts[0]);
        for _ in 0..3 {
            releaser.begin_tick();
            releaser.request(fixture.request(0));
            assert_eq!(fixture.start(&mut releaser), 0);
            assert!(releaser.busy_mount(&fixture.mounts[0]));
            assert!(!releaser.waits_mount(&fixture.mounts[0], Instant::now()));
            assert!(releaser.poll().is_empty());
        }
        fixture.release.send(()).unwrap();
        let cancelled = finish_one(&mut releaser);
        assert_eq!(cancelled.report.files_released, 0);
        assert!(cancelled.task.observations().is_none());
        assert!(!fixture.coordinator.finish_release(cancelled.task));
        assert_eq!(fixture.physical_count(0), 2);
        assert!(!releaser.busy());
        assert!(releaser.take_forecast_intervention());
        assert!(!releaser.take_forecast_intervention());
    }

    #[test]
    fn weaker_pressure_irrevocably_cancels_a_stalled_release_all_intent() {
        let mut fixture = Fixture::new(1);
        let mut releaser = BallastReleaser::default();
        fixture.block(0);
        releaser.request(fixture.request(0));
        assert_eq!(fixture.start(&mut releaser), 1);
        fixture.wait_for_probe(0);

        let mut weaker = fixture.request(0);
        weaker.response.level = PressureLevel::Orange;
        weaker.response.urgency = 0.4;
        releaser.begin_tick();
        releaser.request(weaker);
        assert_eq!(fixture.start(&mut releaser), 0);
        assert!(!releaser.waits_mount(&fixture.mounts[0], Instant::now()));
        releaser.begin_tick();
        releaser.request(fixture.request(0));
        assert_eq!(fixture.start(&mut releaser), 0);
        fixture.release.send(()).unwrap();
        let completion = finish_one(&mut releaser);
        assert_eq!(completion.report.files_released, 0);
        assert_eq!(fixture.physical_count(0), 2);
    }

    #[test]
    fn first_chance_deadline_does_not_renew_with_live_pressure() {
        let mut fixture = Fixture::new(1);
        let mut releaser = BallastReleaser::default();
        fixture.block(0);
        releaser.request(fixture.request(0));
        assert_eq!(fixture.start(&mut releaser), 1);
        fixture.wait_for_probe(0);
        let first = releaser.first_chance[&fixture.mounts[0]];
        assert!(releaser.waits_mount(&fixture.mounts[0], first));
        releaser.begin_tick();
        releaser.request(fixture.request(0));
        assert_eq!(fixture.start(&mut releaser), 0);
        assert!(!releaser.waits_mount(&fixture.mounts[0], first + FIRST_CHANCE));
        assert_eq!(releaser.first_chance[&fixture.mounts[0]], first);
        releaser.cancel();
        fixture.release.send(()).unwrap();
        assert_eq!(finish_one(&mut releaser).report.files_released, 0);
    }

    #[test]
    fn native_probe_return_must_renew_live_policy_and_unexpired_evidence() {
        for cause in 0..5 {
            let mut fixture = Fixture::new(1);
            let mut releaser = BallastReleaser::default();
            fixture.block(0);
            releaser.request(fixture.request(0));
            assert_eq!(fixture.start(&mut releaser), 1);
            fixture.wait_for_probe(0);
            match cause {
                0 => fixture.context.scanner.write().dry_run = true,
                1 => fixture.context.shutdown.store(true, Ordering::Release),
                2 | 3 => {
                    let mut policy = fixture.context.policy.lock();
                    let mut config = policy.config().clone();
                    config.kill_switch = true;
                    policy.update_config(config.clone());
                    if cause == 3 {
                        // Returning to a permitted mode does not restore the
                        // previous policy generation's release authority.
                        config.kill_switch = false;
                        policy.update_config(config);
                    }
                }
                _ => {
                    *releaser.workers[0].permission.evidence.lock() = (
                        Instant::now().checked_sub(Duration::from_secs(61)).unwrap(),
                        Duration::from_secs(60),
                    );
                    releaser.begin_tick();
                    releaser.request(fixture.request(0));
                    assert_eq!(fixture.start(&mut releaser), 0);
                }
            }
            fixture.release.send(()).unwrap();
            let completion = finish_one(&mut releaser);
            assert_eq!(completion.report.files_released, 0, "cause={cause}");
            assert_eq!(fixture.physical_count(0), 2, "cause={cause}");
        }
    }

    #[test]
    fn observe_mode_keeps_sacrificial_reserve_relief_available() {
        let mut fixture = Fixture::new(1);
        *fixture.context.policy.lock() = PolicyEngine::new(super::super::policy::PolicyConfig {
            initial_mode: super::super::policy::ActiveMode::Observe,
            ..Default::default()
        });
        let mut releaser = BallastReleaser::default();
        releaser.request(fixture.request(0));
        assert_eq!(fixture.start(&mut releaser), 1);
        let completion = finish_one(&mut releaser);
        assert_eq!(completion.report.files_released, 2);
        assert!(fixture.coordinator.finish_release(completion.task));
        assert_eq!(fixture.physical_count(0), 0);
    }

    #[test]
    fn actual_completion_publishes_inventory_and_preserves_stale_receipt_audit() {
        for stale in 0..3 {
            let mut fixture = Fixture::new(1);
            let mut releaser = BallastReleaser::default();
            releaser.request(fixture.request(0));
            assert_eq!(fixture.start(&mut releaser), 1);
            let completion = finish_one(&mut releaser);
            assert_eq!(completion.report.files_released, 2);
            assert_eq!(completion.report.released.len(), 2);
            assert_eq!(completion.free_before, Some(1 << 27));
            assert!(completion.task.observations().is_some());
            if stale == 1 {
                // Reload invalidates publication without erasing completed
                // unlink receipts, which the monitor must still audit.
                fixture
                    .coordinator
                    .retain_release_only(&BallastConfig::default(), false);
            } else if stale == 2 {
                fixture
                    .coordinator
                    .invalidate_pool_inventory(&fixture.mounts[0]);
            }
            assert_eq!(
                fixture
                    .coordinator
                    .release_budget_is_current(&completion.task),
                stale == 0,
            );
            assert_eq!(
                fixture.coordinator.finish_release(completion.task),
                stale == 0,
            );
            if stale == 0 {
                assert_eq!(
                    fixture
                        .coordinator
                        .pool_for_mount(&fixture.mounts[0])
                        .unwrap()
                        .available_count(),
                    0,
                );
            }
            assert_eq!(fixture.physical_count(0), 0);
        }
    }
}
