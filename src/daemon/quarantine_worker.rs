//! Quarantine I/O belongs to one retained worker, never the pressure monitor.
//!
//! A running sweep gets a finite first chance on its own mount. Pending work
//! cannot hold another mount's emergency cleanup, and an expired/cancelled
//! worker cannot regain authority after its native I/O eventually returns.

use super::{
    ActiveMode, ActivityEvent, ActivityLoggerHandle, Arc, AtomicBool, AtomicU64, CandidacyScore,
    Config, Duration, HashMap, HashSet, Instant, MonitoringDaemon, MountTickResponse, Mutex,
    Ordering, Path, PathBuf, Platform, PolicyEngine, PressureLevel,
    QUARANTINE_FIRST_CHANCE_SECS, QUARANTINE_PRESSURE_RETRY_SECS, QUARANTINE_SWEEP_INTERVAL,
    QuarantineRecord, QuarantineStore, QuarantineSweepMode, RwLock, ScannerConfig,
    SharedExecutorConfig, SharedRegret, SkipReason, SystemTime, VecDeque, bounded,
    scanner_mutation_scope_matches, thread,
};

#[derive(Clone)]
struct SweepLease {
    generation: Arc<AtomicU64>,
    admitted_generation: u64,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}

impl SweepLease {
    fn current_at(&self, now: Instant) -> bool {
        if now >= self.deadline
            || self.generation.load(Ordering::Acquire) != self.admitted_generation
        {
            // Cancellation is irreversible even if a caller later observes
            // an earlier instant. Releasing a hold cannot revive its worker.
            self.cancelled.store(true, Ordering::Release);
        }
        !self.cancelled.load(Ordering::Acquire)
    }

    fn current(&self) -> bool {
        self.current_at(Instant::now())
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

#[derive(Clone)]
struct FirstChance {
    mount: PathBuf,
    lease: SweepLease,
}

/// A hold is installed only after the worker successfully starts. No queued
/// task holds cleanup, and expiry revokes the worker before releasing cleanup.
#[derive(Default)]
pub(super) struct QuarantineFirst {
    active: RwLock<Option<FirstChance>>,
}

impl QuarantineFirst {
    #[cfg(test)]
    pub(super) fn holds_mount(&self, mount: &Path) -> bool {
        self.active
            .read()
            .as_ref()
            .is_some_and(|hold| hold.mount == mount && hold.lease.current())
    }

    pub(super) fn authorize(
        &self,
        candidate: &CandidacyScore,
        platform: &dyn Platform,
    ) -> std::result::Result<(), SkipReason> {
        let Some(hold) = self.active.read().clone() else {
            return Ok(());
        };
        if !hold.lease.current() {
            return Ok(());
        }
        let stats = platform
            .fs_stats(&candidate.path)
            .map_err(|_| SkipReason::PolicyChanged)?;
        // The probe itself may block. An expired first chance is irrevocably
        // cancelled, so it cannot stop this separate, freshly admitted work.
        if hold.lease.current() && stats.mount_point == hold.mount {
            Err(SkipReason::PolicyChanged)
        } else {
            Ok(())
        }
    }

    fn install(&self, mount: PathBuf, lease: SweepLease) {
        *self.active.write() = Some(FirstChance { mount, lease });
    }

    fn finish(&self, lease: &SweepLease) {
        let mut active = self.active.write();
        if active
            .as_ref()
            .is_some_and(|hold| Arc::ptr_eq(&hold.lease.cancelled, &lease.cancelled))
        {
            *active = None;
        }
    }
}

#[derive(Clone)]
struct SweepTask {
    tick: MountTickResponse,
    roots: Vec<PathBuf>,
    cap_pct: u8,
    allow_mutation: bool,
    observed_at: Instant,
    first_root: usize,
    policy_transitions: u64,
}

impl SweepTask {
    fn mount(&self) -> &Path {
        &self.tick.response.causing_mount
    }

    fn pressured(&self) -> bool {
        self.tick.response.level >= PressureLevel::Orange
    }

    fn resource_scoped(&self) -> bool {
        self.tick.ram_reclaim.is_some() || self.tick.inode_reclaim.is_some()
    }
}

#[derive(Default)]
struct SweepResult {
    held_bytes: Option<u64>,
    attempted: bool,
    visited_roots: usize,
    finished_at: Option<Instant>,
    authorized_at_finish: bool,
}

struct RunningSweep {
    task: SweepTask,
    lease: SweepLease,
    worker: thread::JoinHandle<SweepResult>,
}

/// One completed inventory sample. Successful purge receipts and resource
/// allowance charges are already recorded by the worker before publication.
pub(super) struct QuarantineSweepCompletion {
    pub(super) mount: PathBuf,
    pub(super) held_bytes: Option<u64>,
    pub(super) attempted: bool,
}

/// One running worker, one pending task per current mount, and fair turns.
/// A cancelled native operation retains its handle until it really exits.
#[derive(Default)]
pub(super) struct QuarantineSweeper {
    generation: Arc<AtomicU64>,
    running: Option<RunningSweep>,
    pending: VecDeque<SweepTask>,
    last_finished: HashMap<PathBuf, Instant>,
    next_root: HashMap<PathBuf, usize>,
    completed_relief: HashMap<PathBuf, (MountTickResponse, SweepLease, Instant, u64)>,
}

impl QuarantineSweeper {
    /// Retained running and completed passes may have changed free space.
    /// Inventory-only tasks supply no evidence of an intervention.
    pub(super) fn forecast_intervention(&self) -> bool {
        self.running
            .as_ref()
            .is_some_and(|running| running.task.allow_mutation)
    }

    pub(super) fn busy(&self) -> bool {
        self.running.is_some()
    }

    #[cfg(test)]
    pub(super) fn finished(&self) -> bool {
        self.running
            .as_ref()
            .is_some_and(|running| running.worker.is_finished())
    }

    pub(super) fn cancel(&mut self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        if let Some(running) = &self.running {
            running.lease.cancel();
        }
        self.pending.clear();
        self.completed_relief.clear();
        self.last_finished.clear();
        self.next_root.clear();
    }

    pub(super) fn poll(
        &mut self,
        first: &QuarantineFirst,
        now: Instant,
    ) -> Option<QuarantineSweepCompletion> {
        if !self
            .running
            .as_ref()
            .is_some_and(|running| running.worker.is_finished())
        {
            if let Some(running) = &self.running {
                running.lease.current_at(now);
            }
            return None;
        }
        // Joining a finished handle cannot wait on native I/O.
        let running = self.running.take()?;
        first.finish(&running.lease);
        let mount = running.task.mount().to_path_buf();
        let result = running.worker.join().unwrap_or_default();
        let same_generation =
            running.lease.generation.load(Ordering::Acquire) == running.lease.admitted_generation;
        if same_generation {
            self.last_finished.insert(mount.clone(), now);
            self.next_root.insert(
                mount.clone(),
                running
                    .task
                    .first_root
                    .saturating_add(result.visited_roots.max(1)),
            );
        }
        let current = same_generation && result.authorized_at_finish;
        if current
            && running.task.resource_scoped()
            && !running.lease.cancelled.load(Ordering::Acquire)
            && let Some(finished_at) = result.finished_at
        {
            self.completed_relief.insert(
                mount.clone(),
                (
                    running.task.tick,
                    running.lease,
                    finished_at,
                    running.task.policy_transitions,
                ),
            );
        }
        Some(QuarantineSweepCompletion {
            mount,
            held_bytes: current.then_some(result.held_bytes).flatten(),
            attempted: result.attempted,
        })
    }

    /// The successor of a completed resource sweep shares its spent allowance.
    /// Recovery, changed resource type, reload or expiry instead requires the
    /// monitor's newly observed pass; no old permission is resurrected.
    pub(super) fn apply_completed_relief(
        &mut self,
        tick: &mut MountTickResponse,
        policy_transitions: u64,
    ) {
        let Some((completed, lease, finished_at, admitted_policy)) =
            self.completed_relief.remove(&tick.response.causing_mount)
        else {
            return;
        };
        if lease.cancelled.load(Ordering::Acquire)
            || lease.generation.load(Ordering::Acquire) != lease.admitted_generation
            || policy_transitions != admitted_policy
            || finished_at.elapsed() >= QUARANTINE_SWEEP_INTERVAL
        {
            return;
        }
        if let (Some(current), Some(previous)) = (&mut tick.ram_reclaim, &completed.ram_reclaim) {
            current.share_remaining_allowance(previous);
        } else if let (Some(current), Some(previous)) =
            (&mut tick.inode_reclaim, &completed.inode_reclaim)
        {
            current.share_remaining_allowance(previous);
        }
    }

    /// Resource scans wait only for their own admitted first chance. Pending
    /// jobs and an expired native operation cannot hold another pass.
    pub(super) fn resource_scan_waits(&self, mount: &Path) -> bool {
        self.running.as_ref().is_some_and(|running| {
            running.task.mount() == mount
                && running.task.allow_mutation
                && running.task.resource_scoped()
                && running.lease.current()
        })
    }

    pub(super) fn observe(
        &mut self,
        responses: &[MountTickResponse],
        root_mounts: &[(PathBuf, Option<PathBuf>)],
        recovering_mounts: &HashSet<PathBuf>,
        config: &Config,
        policy: (ActiveMode, u64),
        now: Instant,
    ) {
        let (mode, policy_transitions) = policy;
        if let Some(running) = &self.running {
            running.lease.current_at(now);
            let current = responses.iter().find(|tick| {
                tick.response.causing_mount == running.task.tick.response.causing_mount
            });
            if current.is_none()
                || running.task.policy_transitions != policy_transitions
                || (running.task.allow_mutation
                    && (config.scanner.dry_run
                        || mode != ActiveMode::Enforce
                        || recovering_mounts.contains(running.task.mount())))
                || current.is_some_and(|tick| {
                    (running.task.tick.ram_reclaim.is_some() && tick.ram_reclaim.is_none())
                        || (running.task.tick.inode_reclaim.is_some()
                            && tick.inode_reclaim.is_none())
                        || (running.task.pressured() && tick.response.level < PressureLevel::Orange)
                })
            {
                running.lease.cancel();
            }
        }
        let current_mounts: HashSet<_> = responses
            .iter()
            .map(|tick| tick.response.causing_mount.clone())
            .collect();
        self.pending
            .retain(|task| current_mounts.contains(task.mount()));
        self.last_finished
            .retain(|mount, _| current_mounts.contains(mount));
        self.next_root
            .retain(|mount, _| current_mounts.contains(mount));
        self.completed_relief
            .retain(|mount, (_, lease, finished_at, admitted_policy)| {
                current_mounts.contains(mount)
                    && !lease.cancelled.load(Ordering::Acquire)
                    && lease.generation.load(Ordering::Acquire) == lease.admitted_generation
                    && *admitted_policy == policy_transitions
                    && now.saturating_duration_since(*finished_at) < QUARANTINE_SWEEP_INTERVAL
            });

        let mut ordered: Vec<_> = responses.iter().collect();
        ordered.sort_by(|left, right| {
            right
                .response
                .level
                .cmp(&left.response.level)
                .then_with(|| {
                    left.response
                        .causing_mount
                        .cmp(&right.response.causing_mount)
                })
        });
        for tick in ordered {
            let mount = &tick.response.causing_mount;
            let mut roots: Vec<_> = root_mounts
                .iter()
                .filter(|(_, root_mount)| root_mount.as_ref() == Some(mount))
                .map(|(root, _)| root.clone())
                .collect();
            roots.sort();
            roots.dedup();
            let pressured = tick.response.level >= PressureLevel::Orange;
            let interval = if pressured {
                Duration::from_secs(QUARANTINE_PRESSURE_RETRY_SECS)
            } else {
                QUARANTINE_SWEEP_INTERVAL
            };
            if roots.is_empty()
                || self
                    .running
                    .as_ref()
                    .is_some_and(|running| running.task.mount() == mount)
                || self
                    .last_finished
                    .get(mount)
                    .is_some_and(|last| now.saturating_duration_since(*last) < interval)
            {
                self.pending.retain(|task| task.mount() != mount);
                continue;
            }
            let task = SweepTask {
                tick: tick.clone(),
                roots,
                cap_pct: config.scanner.quarantine_max_bytes_pct,
                allow_mutation: !recovering_mounts.contains(mount)
                    && !config.scanner.dry_run
                    && mode == ActiveMode::Enforce
                    && (!(tick.ram_reclaim.is_some() || tick.inode_reclaim.is_some()) || pressured),
                observed_at: now,
                first_root: self.next_root.get(mount).copied().unwrap_or(0),
                policy_transitions,
            };
            if let Some(pending) = self.pending.iter_mut().find(|task| task.mount() == mount) {
                // Fresh observation, same queue position: a busy mount cannot
                // continually reinsert itself ahead of its waiting peers.
                *pending = task;
            } else {
                self.pending.push_back(task);
            }
        }
    }

    pub(super) fn start(
        &mut self,
        mut context: QuarantineSweepContext,
        now: Instant,
        emergency_only: bool,
    ) {
        if self.busy() || context.shutdown.load(Ordering::Acquire) {
            return;
        }
        let Some(index) = self
            .pending
            .iter()
            .position(|task| !emergency_only || task.tick.response.level >= PressureLevel::Red)
        else {
            return;
        };
        let Some(mut task) = self.pending.remove(index) else {
            return;
        };
        let deadline = task.observed_at + Duration::from_secs(QUARANTINE_FIRST_CHANCE_SECS);
        if now >= deadline {
            return;
        }
        let offset = task.first_root % task.roots.len();
        task.roots.rotate_left(offset);
        context.admitted_policy_transitions = task.policy_transitions;
        let lease = SweepLease {
            generation: Arc::clone(&self.generation),
            admitted_generation: self.generation.load(Ordering::Acquire),
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline,
        };
        let first = Arc::clone(&context.executor.quarantine_first);
        let worker_task = task.clone();
        let worker_lease = lease.clone();
        let (begin_tx, begin_rx) = bounded(1);
        match thread::Builder::new()
            .name("sbh-quarantine".to_string())
            .spawn(move || {
                if begin_rx.recv().is_err() {
                    return SweepResult::default();
                }
                context.run(&worker_task, Some(&worker_lease))
            }) {
            Ok(worker) => {
                if task.allow_mutation {
                    first.install(task.mount().to_path_buf(), lease.clone());
                }
                let _ = begin_tx.send(());
                self.running = Some(RunningSweep {
                    task,
                    lease,
                    worker,
                });
            }
            Err(error) => {
                lease.cancel();
                self.last_finished.insert(task.mount().to_path_buf(), now);
                eprintln!("[SBH-QUARANTINE] worker could not start: {error}");
            }
        }
    }
}

impl Drop for QuarantineSweeper {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Owned references used at native mutation boundaries. No monitor lock is
/// held while probing filesystems, traversing payloads, syncing or logging.
pub(super) struct QuarantineSweepContext {
    platform: Arc<dyn Platform>,
    executor: Arc<SharedExecutorConfig>,
    scanner: Arc<RwLock<ScannerConfig>>,
    admitted_scanner: ScannerConfig,
    policy: Arc<Mutex<PolicyEngine>>,
    admitted_policy_transitions: u64,
    regret: Arc<SharedRegret>,
    logger: ActivityLoggerHandle,
    shutdown: Arc<AtomicBool>,
}

/// The original namespace remains the operator's protection boundary after a
/// recoverable move. Check it independently of the store's own protect marker.
fn authorize_original_path(
    record: &QuarantineRecord,
    scanner: &ScannerConfig,
) -> std::result::Result<(), SkipReason> {
    use crate::scanner::protection;

    let spellings = protection::exclusion_path_spellings(&record.original_path)
        .map_err(|_| SkipReason::SacredStowaway)?;
    if protection::path_overlaps_exclusion(&spellings[0], &scanner.excluded_paths)
        || protection::path_overlaps_current_protection(&spellings[0], &scanner.protected_paths)
            .map_err(|_| SkipReason::SacredStowaway)?
    {
        return Err(SkipReason::SacredStowaway);
    }
    for path in &spellings {
        for ancestor in path.ancestors() {
            match std::fs::symlink_metadata(ancestor.join(protection::MARKER_FILENAME)) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                // A rebuilt file at the original leaf has no marker of its
                // own. Still check every parent and all configured patterns.
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotADirectory
                        && ancestor == path.as_path() => {}
                _ => return Err(SkipReason::SacredStowaway),
            }
        }
    }
    Ok(())
}

impl QuarantineSweepContext {
    pub(super) fn new(daemon: &MonitoringDaemon) -> Self {
        Self {
            platform: Arc::clone(&daemon.platform),
            executor: Arc::clone(&daemon.shared_executor_config),
            scanner: Arc::clone(&daemon.shared_scanner_config),
            admitted_scanner: daemon.shared_scanner_config.read().clone(),
            policy: Arc::clone(&daemon.policy_engine),
            admitted_policy_transitions: daemon.policy_engine.lock().transitions_total(),
            regret: Arc::clone(&daemon.regret),
            logger: daemon.logger_handle.clone(),
            shutdown: daemon.signal_handler.shutdown_token(),
        }
    }

    fn current(&self, lease: Option<&SweepLease>) -> bool {
        !self.shutdown.load(Ordering::Acquire)
            && lease.is_none_or(SweepLease::current)
            && self.policy.lock().transitions_total() == self.admitted_policy_transitions
            && scanner_mutation_scope_matches(&self.admitted_scanner, &self.scanner.read(), false)
    }

    /// A past move into quarantine does not override a later protection,
    /// exclusion or category suspension. Renew these for every cleanup mode.
    fn authorize_record_policy(
        &self,
        record: &QuarantineRecord,
    ) -> std::result::Result<(), SkipReason> {
        let scanner = self.scanner.read().clone();
        authorize_original_path(record, &scanner)?;
        if !scanner_mutation_scope_matches(&scanner, &self.scanner.read(), false) {
            return Err(SkipReason::PolicyChanged);
        }
        if let Some(category) = record.category()
            && self
                .regret
                .calibrator
                .lock()
                .suspended(&format!("{category:?}"), Instant::now())
        {
            return Err(SkipReason::CategorySuspended);
        }
        Ok(())
    }

    pub(super) fn authorize_resource_record(
        &self,
        tick: &MountTickResponse,
        record: &QuarantineRecord,
    ) -> std::result::Result<(), SkipReason> {
        if tick.ram_reclaim.is_none() && tick.inode_reclaim.is_none() {
            return self.authorize_record_policy(record);
        }
        let scanner = self.scanner.read().clone();
        match (&tick.ram_reclaim, &tick.inode_reclaim) {
            (Some(relief), None) => {
                if !relief.accepts_quarantined(record, false) {
                    return Err(SkipReason::PolicyChanged);
                }
                relief.authorize_quarantine_scope(record, &scanner)?;
            }
            (None, Some(relief)) => {
                if !relief.accepts_quarantined(record, false) {
                    return Err(SkipReason::PolicyChanged);
                }
                relief.authorize_quarantine_scope(record, &scanner)?;
            }
            (None, None) => return Ok(()),
            (Some(_), Some(_)) => return Err(SkipReason::PolicyChanged),
        }
        if !scanner_mutation_scope_matches(&scanner, &self.scanner.read(), false) {
            return Err(SkipReason::PolicyChanged);
        }
        self.authorize_record_policy(record)
    }

    fn authorize_mutation(&self, approved_mode: ActiveMode) -> std::result::Result<(), SkipReason> {
        if self.shutdown.load(Ordering::Acquire) || self.scanner.read().dry_run {
            return Err(SkipReason::PolicyChanged);
        }
        let current_mode = self.policy.lock().mode();
        if approved_mode != ActiveMode::Enforce || current_mode != ActiveMode::Enforce {
            return Err(SkipReason::PolicyChanged);
        }
        self.executor
            .authorize_mutation(approved_mode, current_mode)
    }

    pub(super) fn authorize_maintenance(
        &self,
        mount: &Path,
        mutation_path: &Path,
        level: PressureLevel,
        approved_mode: ActiveMode,
    ) -> std::result::Result<(), SkipReason> {
        self.executor.authorize_dispatch(false, false)?;
        if self
            .executor
            .compression_first
            .defers_mount(mount, level, Instant::now())
        {
            return Err(SkipReason::CompressionFirst);
        }
        self.authorize_mutation(approved_mode)?;
        // A still-unidentified incident holds overlapping paths, not every
        // store under the mount. Device holds are resolved from this store.
        self.executor.authorize_recovery_path(mutation_path, None)
    }

    pub(super) fn authorize_pressure(
        &self,
        tick: &MountTickResponse,
        store: &QuarantineStore,
        record: &QuarantineRecord,
        approved_mode: ActiveMode,
    ) -> std::result::Result<(), SkipReason> {
        let mount = &tick.response.causing_mount;
        let level = tick.response.level;
        self.authorize_mutation(approved_mode)?;
        // Scope renewal resolves aliases and directory identities. Never keep
        // the shared configuration locked across those native operations: a
        // blocked volume must not prevent the monitor from publishing reload.
        let scanner = self.scanner.read().clone();
        match (&tick.ram_reclaim, &tick.inode_reclaim) {
            (Some(relief), None) => {
                relief.authorize_scope(store.root(), &scanner)?;
                relief.authorize_mount(self.platform.as_ref())?;
            }
            (None, Some(relief)) => {
                relief.authorize_policy(&self.executor.inode_pressure.read())?;
                relief.authorize_scope(store.root(), &scanner)?;
                relief.authorize_mount(self.platform.as_ref())?;
            }
            (None, None) => self.executor.authorize_disk_reclaim_path(
                store.root(),
                Some(mount),
                level,
                self.platform.as_ref(),
            )?,
            (Some(_), Some(_)) => return Err(SkipReason::PolicyChanged),
        }
        if tick.ram_reclaim.is_some() || tick.inode_reclaim.is_some() {
            let stats = self
                .platform
                .fs_stats(store.root())
                .map_err(|_| SkipReason::PolicyChanged)?;
            if stats.mount_point != *mount
                || stats.is_readonly
                || stats.total_bytes == 0
                || stats.free_bytes > stats.total_bytes
                || stats.available_bytes > stats.free_bytes
            {
                return Err(SkipReason::PolicyChanged);
            }
        }
        self.authorize_resource_record(tick, record)?;
        self.executor
            .authorize_dispatch(tick.ram_reclaim.is_some(), tick.inode_reclaim.is_some())?;
        self.authorize_mutation(approved_mode)?;
        if tick.inode_reclaim.is_none()
            && self
                .executor
                .compression_first
                .defers_mount(mount, level, Instant::now())
        {
            return Err(SkipReason::CompressionFirst);
        }
        self.executor.authorize_recovery_path(store.root(), None)
    }

    #[allow(clippy::too_many_lines)]
    fn run(&self, task: &SweepTask, lease: Option<&SweepLease>) -> SweepResult {
        let mut result = SweepResult::default();
        if !self.current(lease) {
            return result;
        }
        let now_unix = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        let cap_bytes = self
            .platform
            .fs_stats(task.mount())
            .ok()
            .map(|stats| (stats.total_bytes / 100).saturating_mul(u64::from(task.cap_pct)));
        let mut held = Some(0_u64);
        for root in &task.roots {
            if !self.current(lease) {
                held = None;
                break;
            }
            result.visited_roots += 1;
            let store = QuarantineStore::under(root);
            let approved_mode = self.policy.lock().mode();
            if !task.allow_mutation
                || approved_mode != ActiveMode::Enforce
                || self.scanner.read().dry_run
                || (task.tick.inode_reclaim.is_none()
                    && self.executor.compression_first.defers_mount(
                        task.mount(),
                        task.tick.response.level,
                        Instant::now(),
                    ))
            {
                held = held
                    .zip(store.held_bytes().ok())
                    .map(|(sum, bytes)| sum.saturating_add(bytes));
                continue;
            }
            let mode = if task.pressured() {
                QuarantineSweepMode::Pressure
            } else {
                QuarantineSweepMode::Maintenance { cap_bytes }
            };
            result.attempted = true;
            let mut active_record = None;
            let mut admitted_artifacts = 0usize;
            let mut admitted_bytes = 0u64;
            let mut bytes_before_active = 0u64;
            let select = |record: &QuarantineRecord| {
                self.current(lease)
                    && self.authorize_resource_record(&task.tick, record).is_ok()
                    && self.current(lease)
            };
            let gate = |record: &QuarantineRecord| {
                if !self.current(lease) {
                    return false;
                }
                if active_record.as_ref() != Some(&record.decision_id) {
                    active_record = Some(record.decision_id.clone());
                    admitted_artifacts = admitted_artifacts.saturating_add(1);
                    bytes_before_active = admitted_bytes;
                    admitted_bytes = admitted_bytes.saturating_add(record.size_bytes);
                }
                if task
                    .tick
                    .inode_reclaim
                    .as_ref()
                    .is_some_and(|relief| admitted_artifacts > relief.remaining_artifacts())
                    || task
                        .tick
                        .ram_reclaim
                        .as_ref()
                        .is_some_and(|relief| bytes_before_active >= relief.remaining_bytes())
                {
                    return false;
                }
                self.authorize_pressure(&task.tick, &store, record, approved_mode)
                    .is_ok()
                    && self.current(lease)
            };
            let maintenance_select = |record: &QuarantineRecord| {
                self.current(lease)
                    && self.authorize_record_policy(record).is_ok()
                    && self.current(lease)
            };
            let maintenance_gate = |_: &QuarantineRecord| {
                self.current(lease)
                    && self
                        .authorize_maintenance(
                            task.mount(),
                            store.root(),
                            task.tick.response.level,
                            approved_mode,
                        )
                        .is_ok()
                    && self.current(lease)
            };
            match store.sweep_with_filters_and_gates(
                now_unix,
                mode,
                select,
                gate,
                maintenance_select,
                maintenance_gate,
            ) {
                Ok(swept) => {
                    held = held.map(|sum| sum.saturating_add(swept.held_bytes));
                    let (why, mut drained) = (swept.reason, swept.drained);
                    for completion in drained.completed.drain(..) {
                        if let Some(relief) = &task.tick.ram_reclaim {
                            relief.record_unlinked_bytes(completion.record.size_bytes);
                        }
                        if let Some(relief) = &task.tick.inode_reclaim {
                            relief.record_unlinked();
                        }
                        self.regret.note_quarantine_purged(&completion);
                        self.logger
                            .send(ActivityEvent::QuarantinePurged(Box::new(completion)));
                    }
                    if drained.entries > 0 {
                        let message = format!(
                            "quarantine under {} drained {} entr{} ({} bytes) for {why} at {:?}",
                            root.display(),
                            drained.entries,
                            if drained.entries == 1 { "y" } else { "ies" },
                            drained.bytes,
                            task.tick.response.level,
                        );
                        eprintln!("[SBH-QUARANTINE] {message}");
                        self.logger.send(ActivityEvent::Info { message });
                    }
                    for failure in drained.new_failures() {
                        let message = format!(
                            "quarantine entry {} under {} will not unlink: {} ({})",
                            failure.decision_id,
                            root.display(),
                            failure.error,
                            failure.path.display(),
                        );
                        eprintln!("[SBH-QUARANTINE] {message}");
                        self.logger.send(ActivityEvent::Error {
                            code: failure.code.clone(),
                            message,
                        });
                    }
                }
                Err(error) => {
                    held = None;
                    eprintln!(
                        "[SBH-QUARANTINE] sweep under {} failed: {error}",
                        root.display()
                    );
                }
            }
        }
        result.held_bytes = held;
        result.finished_at = Some(Instant::now());
        result.authorized_at_finish = self.current(lease);
        result
    }

    /// Existing gate regression tests exercise the same worker body without
    /// scheduling; production always calls it on the retained worker thread.
    #[cfg(test)]
    pub(super) fn run_inline(
        &self,
        tick: &MountTickResponse,
        roots: Vec<PathBuf>,
        config: &Config,
    ) -> QuarantineSweepCompletion {
        let task = SweepTask {
            tick: tick.clone(),
            roots,
            cap_pct: config.scanner.quarantine_max_bytes_pct,
            allow_mutation: !config.scanner.dry_run
                && self.policy.lock().mode() == ActiveMode::Enforce
                && (!(tick.ram_reclaim.is_some() || tick.inode_reclaim.is_some())
                    || tick.response.level >= PressureLevel::Orange),
            observed_at: Instant::now(),
            first_root: 0,
            policy_transitions: self.admitted_policy_transitions,
        };
        let result = self.run(&task, None);
        QuarantineSweepCompletion {
            mount: task.mount().to_path_buf(),
            held_bytes: result.held_bytes,
            attempted: result.attempted,
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::core::config::PathsConfig;
    use crate::daemon::loop_main::DaemonArgs;
    use crate::daemon::self_monitor::MountRateState;
    use crate::monitor::pid::PressureResponse;
    use crate::monitor::predictive::PredictiveAction;
    use crate::platform::pal::{FsStats, MemoryInfo, MockPlatform, MountPoint, PlatformPaths};
    use crate::scanner::regret::Outcome;
    use crate::scanner::scoring::ArtifactCertainty;
    use std::fs;

    struct Fixture {
        daemon: MonitoringDaemon,
        directory: tempfile::TempDir,
        root: PathBuf,
    }

    impl Fixture {
        fn new(pressured: bool) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let base = directory.path();
            let root = base.join("scan");
            fs::create_dir(&root).unwrap();
            let mut config = Config::with_paths(PathsConfig {
                config_file: base.join("config.toml"),
                ballast_dir: base.join("ballast"),
                state_file: base.join("state.json"),
                sqlite_db: base.join("activity.sqlite3"),
                jsonl_log: base.join("activity.jsonl"),
            });
            config.scanner.root_paths = vec![root.clone()];
            config.scanner.protected_paths.clear();
            config.scanner.excluded_paths.clear();
            config.scanner.quarantine_max_bytes_pct = 0;
            config.ballast.auto_provision = false;
            config.policy.initial_mode = ActiveMode::Enforce;
            let available = if pressured { 1 << 30 } else { 90 << 30 };
            let platform = MockPlatform::new(
                vec![MountPoint {
                    path: PathBuf::from("/"),
                    device: "mock".to_string(),
                    fs_type: "mockfs".to_string(),
                    is_ram_backed: false,
                }],
                HashMap::from([(
                    PathBuf::from("/"),
                    FsStats {
                        total_bytes: 100 << 30,
                        free_bytes: available,
                        available_bytes: available,
                        fs_type: "mockfs".to_string(),
                        mount_point: PathBuf::from("/"),
                        is_readonly: false,
                    },
                )]),
                MemoryInfo {
                    total_bytes: 64 << 30,
                    available_bytes: 32 << 30,
                    swap_total_bytes: 8 << 30,
                    swap_free_bytes: 8 << 30,
                },
                PlatformPaths::default(),
            )
            .with_home(base)
            .with_temp_dirs(Vec::new())
            .with_cache_roots(Vec::new());
            let daemon = MonitoringDaemon::init_with_platform(
                config,
                &DaemonArgs::default(),
                Arc::new(platform),
            )
            .unwrap();
            Self {
                daemon,
                directory,
                root,
            }
        }

        fn hold(&self, id: &str, category: &str, ttl: Duration) -> QuarantineRecord {
            let source = self.root.join(id).join("target");
            fs::create_dir_all(&source).unwrap();
            fs::write(source.join("payload.bin"), b"retained").unwrap();
            QuarantineStore::under(&self.root)
                .quarantine(
                    &source,
                    id,
                    8,
                    ttl,
                    Some(serde_json::json!({"category": category, "certainty": "Definite"})),
                )
                .unwrap()
        }

        fn sweep(&self, pressured: bool) -> QuarantineSweepCompletion {
            let response = PressureResponse {
                level: if pressured {
                    PressureLevel::Critical
                } else {
                    PressureLevel::Green
                },
                urgency: 0.7,
                scan_interval: Duration::from_secs(1),
                release_ballast_files: 0,
                max_delete_batch: 10,
                fallback_active: false,
                causing_mount: PathBuf::from("/"),
                free_pct: if pressured { 1.0 } else { 90.0 },
                predicted_seconds: None,
            };
            let tick = MountTickResponse {
                filesystem_response: response.clone(),
                response,
                backing_pressure: None,
                ram_reclaim: None,
                inode_pressure: None,
                inode_reclaim: None,
                seconds_to_red: None,
                prediction_confident: false,
                predictive_action: PredictiveAction::Clear,
                uncalibrated_predictive_action: None,
                imminent_danger: false,
                rate: MountRateState::default(),
                device_id: None,
            };
            QuarantineSweepContext::new(&self.daemon).run_inline(
                &tick,
                vec![self.root.clone()],
                &self.daemon.config,
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.daemon.quarantine_sweeper.cancel();
            self.daemon.logger_handle.shutdown();
            if let Some(logger) = self.daemon.logger_join.take() {
                let _ = logger.join();
            }
        }
    }

    #[test]
    fn ordinary_quarantine_sweeps_keep_newly_protected_records_and_purge_eligible_siblings() {
        for mode in ["pressure", "ttl", "cap"] {
            for restriction in [
                "protected",
                "protected-descendant",
                "protected-glob-descendant",
                "excluded",
                "excluded-descendant",
                "marker",
                "suspended",
            ] {
                let pressured = mode == "pressure";
                let mut fixture = Fixture::new(pressured);
                let ttl = if mode == "ttl" {
                    Duration::ZERO
                } else {
                    Duration::from_hours(24)
                };
                let kept = fixture.hold("a", "RustTarget", ttl);
                let eligible = fixture.hold("b", "GoCache", ttl);
                let mut updated = fixture.daemon.config.clone();
                match restriction {
                    "protected" => updated.scanner.protected_paths.push(
                        kept.original_path.parent().unwrap().display().to_string(),
                    ),
                    "protected-descendant" => updated.scanner.protected_paths.push(
                        kept.original_path.join("keep").display().to_string(),
                    ),
                    "protected-glob-descendant" => updated.scanner.protected_paths.push(
                        format!("{}/keep/**", kept.original_path.display()),
                    ),
                    "excluded" => updated
                        .scanner
                        .excluded_paths
                        .push(kept.original_path.clone()),
                    "excluded-descendant" => updated
                        .scanner
                        .excluded_paths
                        .push(kept.original_path.join("keep")),
                    "marker" => fs::write(
                        kept.original_path.parent().unwrap().join(".sbh-protect"),
                        b"",
                    )
                    .unwrap(),
                    "suspended" => {
                        let mut calibrator = fixture.daemon.regret.calibrator.lock();
                        for _ in 0..10 {
                            calibrator.record(
                                "RustTarget",
                                ArtifactCertainty::Definite,
                                Outcome::Regret,
                                Instant::now(),
                            );
                        }
                        assert!(calibrator.suspended("RustTarget", Instant::now()));
                    }
                    _ => unreachable!(),
                }
                fixture.daemon.apply_config_reload(Ok(updated));
                let completion = fixture.sweep(pressured);
                assert!(completion.attempted, "{mode}: {restriction}");
                assert_eq!(completion.held_bytes, Some(8), "{mode}: {restriction}");
                assert_eq!(
                    fs::read(kept.quarantine_path.join("payload.bin")).unwrap(),
                    b"retained"
                );
                assert!(
                    !eligible.quarantine_path.exists(),
                    "{mode}: {restriction}"
                );
                let store = QuarantineStore::under(&fixture.root);
                assert_eq!(store.record("a").unwrap(), Some(kept));
                assert!(store.record("b").unwrap().is_none());
                assert!(store.stuck_entries().unwrap().is_empty());
            }
        }
    }

    #[test]
    fn quarantine_protection_renews_config_aliases_without_a_discovery_cache_delay() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new(true);
        let kept = fixture.hold("a", "RustTarget", Duration::from_hours(24));
        let outside = fixture.directory.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let alias = fixture.directory.path().join("protected-alias");
        symlink(&outside, &alias).unwrap();
        let mut scanner = fixture.daemon.config.scanner.clone();
        scanner.protected_paths = vec![format!("{}/target/keep/**", alias.display())];
        assert_eq!(authorize_original_path(&kept, &scanner), Ok(()));
        let _ = crate::core::paths::resolve_absolute_path(&alias);
        fs::rename(&alias, fixture.directory.path().join("old-alias")).unwrap();
        symlink(kept.original_path.parent().unwrap(), &alias).unwrap();
        assert_eq!(
            authorize_original_path(&kept, &scanner),
            Err(SkipReason::SacredStowaway)
        );
        assert_eq!(
            fs::read(kept.quarantine_path.join("payload.bin")).unwrap(),
            b"retained"
        );
    }

    #[test]
    fn rebuilt_original_files_and_missing_original_parents_do_not_block_eligible_records() {
        let fixture = Fixture::new(true);
        let rebuilt = fixture.hold("a", "RustTarget", Duration::from_hours(24));
        fs::write(&rebuilt.original_path, b"new artifact").unwrap();
        assert_eq!(
            authorize_original_path(&rebuilt, &fixture.daemon.config.scanner),
            Ok(())
        );
        assert_eq!(fixture.sweep(true).held_bytes, Some(0));
        assert!(!rebuilt.quarantine_path.exists());
        assert_eq!(
            fs::read(&rebuilt.original_path).unwrap(),
            b"new artifact"
        );

        let missing = fixture.hold("b", "RustTarget", Duration::from_hours(24));
        fs::rename(
            missing.original_path.parent().unwrap(),
            fixture.root.join("retired-parent"),
        )
        .unwrap();
        assert_eq!(
            authorize_original_path(&missing, &fixture.daemon.config.scanner),
            Ok(())
        );
        assert_eq!(fixture.sweep(true).held_bytes, Some(0));
        assert!(!missing.quarantine_path.exists());
    }
}
