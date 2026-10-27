//! Opt-in daemon tier: lossless zstd compression of cold files on btrfs
//! (bd-rxq5).
//!
//! With `[compress] enabled`, the monitor calls [`CompressTier::tick`] on every
//! tick. A pass starts when a configured root sits on btrfs whose mount is at
//! or above `start_level`, no pass is running, and `interval_minutes` have
//! passed since the last start. Root probes and passes have separate bounded
//! worker slots, so filesystem admission, discovery and rewrite I/O do not run
//! on the monitor. A root awaiting fresh evidence cannot hold cleanup. It finds files under
//! due roots, resuming where the previous pass stopped, and runs the same
//! checked executor as `sbh compress --discover --apply`. Every file outcome
//! reaches the activity log, and a summary line names the bytes saved. Nothing
//! is ever deleted, and a root on another filesystem is never touched.
//!
//! On ts2 (2026-10-14..16, `/` at 93-97% and sbh at Red or Critical) the same
//! method, run by hand, freed several hundred GB from idle scratch while the
//! deletion scanner freed megabytes per hour.

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use crate::core::config::{CompressConfig, Config, PressureConfig};
use crate::logger::compression::CompressionActivity;
use crate::logger::dual::{ActivityEvent, ActivityLoggerHandle};
use crate::monitor::pid::{PressureLevel, classify_level};
use crate::platform::pal::{FsStats, Platform};
use crate::scanner::compression::{
    self, CompressionMode, CompressionObservation, CompressionReport, ConcurrencyAcknowledgement,
    discovery,
};
use crate::scanner::walker::identity_for_path;
use crate::tuning::writeback::human_bytes;

/// A configured root as the monitor sees it this tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootStatus {
    /// The configured directory.
    pub root: PathBuf,
    /// Whether the filesystem holding it is btrfs.
    pub btrfs: bool,
    /// Pressure of the mount holding it. Uses its controller when present,
    /// otherwise the current free space and configured pressure thresholds.
    pub level: Option<PressureLevel>,
    /// Mount whose pressure governs this root, when it could be resolved.
    pub mount_point: Option<PathBuf>,
    /// Device identity used to hold only cleanup on this filesystem.
    pub device_id: Option<u64>,
}

/// Freshness is measured from probe completion, using monotonic time. A probe
/// which itself exceeds this window supplies unknown evidence instead.
const ROOT_PROBE_MAX_AGE: Duration = Duration::from_secs(60);
/// Matches the validated configuration limit and bounds queued snapshots.
const ROOT_PROBE_LIMIT: usize = 32;

#[derive(Debug)]
struct RootEvidence {
    root: PathBuf,
    stats: Option<FsStats>,
    device_id: Option<u64>,
    completed_at: Instant,
}

impl RootEvidence {
    fn fresh(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.completed_at) < ROOT_PROBE_MAX_AGE
    }

    /// Controller levels are live monitor evidence, never a value captured by
    /// the worker before a potentially slow filesystem query.
    fn status(
        &self,
        mount_levels: &HashMap<PathBuf, PressureLevel>,
        pressure: &PressureConfig,
    ) -> RootStatus {
        RootStatus {
            root: self.root.clone(),
            btrfs: self
                .stats
                .as_ref()
                .is_some_and(|stats| stats.fs_type == "btrfs"),
            level: self
                .stats
                .as_ref()
                .filter(|stats| !stats.is_readonly && stats.total_bytes > 0)
                .map(|stats| {
                    mount_levels
                        .get(&stats.mount_point)
                        .copied()
                        .unwrap_or_else(|| {
                            let [green, yellow, orange, red] =
                                pressure.free_pct_thresholds_for(stats.total_bytes);
                            classify_level(stats.free_pct(), green, yellow, orange, red)
                        })
                }),
            mount_point: self.stats.as_ref().map(|stats| stats.mount_point.clone()),
            device_id: self.device_id,
        }
    }
}

/// There is at most one native probe worker, even if a syscall never returns.
/// Cancellation invalidates its output; it does not pretend to kill native I/O.
#[derive(Debug)]
struct RootProbe {
    receive: mpsc::Receiver<RootEvidence>,
    cancelled: Arc<AtomicBool>,
    worker: std::thread::JoinHandle<()>,
}

/// A pass captures its configuration. Revoke it when consent, work limits or
/// the executor's protected paths change; unrelated UI/notification settings
/// do not change its authority to rewrite a file.
#[derive(Debug, PartialEq, Eq)]
struct CompressionScope {
    compress: CompressConfig,
    protected_paths: Vec<String>,
    control_paths: [PathBuf; 6],
}

impl From<&Config> for CompressionScope {
    fn from(config: &Config) -> Self {
        Self {
            compress: config.compress.clone(),
            protected_paths: config.scanner.protected_paths.clone(),
            // Keep these aligned with compression::linux::check_control_paths.
            // The database sidecars and journal directory derive from them.
            control_paths: [
                config.paths.config_file.clone(),
                config.paths.state_file.clone(),
                config.paths.sqlite_db.clone(),
                config.paths.jsonl_log.clone(),
                config.update.metadata_cache_file.clone(),
                config.notifications.file.path.clone(),
            ],
        }
    }
}

/// A bounded first chance for lossless reclaim, shared with the executor.
/// Only the first pass in a Yellow/Orange pressure episode can delay cleanup.
/// Completion or failure releases its holds; cancellation waits for worker exit.
/// Red/Critical pressure and the deadline bypass a hold even during native I/O.
#[derive(Debug, Default)]
pub(super) struct CompressionFirst {
    state: parking_lot::Mutex<FirstState>,
}

#[derive(Debug, Default)]
struct FirstState {
    holds: HashMap<u64, MountHold>,
    attempted: HashSet<PathBuf>,
}

#[derive(Debug)]
struct MountHold {
    mounts: HashSet<PathBuf>,
    until: Instant,
}

impl CompressionFirst {
    pub(super) fn update_levels(&self, levels: &HashMap<PathBuf, PressureLevel>) {
        let eligible = |mount: &PathBuf| {
            matches!(
                levels.get(mount),
                Some(PressureLevel::Yellow | PressureLevel::Orange)
            )
        };
        let mut state = self.state.lock();
        state.holds.retain(|_, hold| {
            // Keep every known alias while this device is held. A Green alias
            // may turn Red before the originally pressured alias does.
            !hold.mounts.iter().any(|mount| {
                matches!(
                    levels.get(mount),
                    Some(PressureLevel::Red | PressureLevel::Critical)
                )
            }) && hold.mounts.iter().any(eligible)
        });
        state.attempted.retain(eligible);
    }

    /// Publish before spawning the pass or dispatching non-emergency cleanup.
    pub(super) fn begin(
        &self,
        roots: &[RootStatus],
        known_roots: &[RootStatus],
        now: Instant,
        allowance: Duration,
    ) -> usize {
        let Some(until) = now.checked_add(allowance) else {
            return 0;
        };
        let emergency_devices: HashSet<_> = roots
            .iter()
            .chain(known_roots)
            .filter(|root| root.level.is_some_and(|level| level >= PressureLevel::Red))
            .filter_map(|root| root.device_id)
            .collect();
        let mut state = self.state.lock();
        state
            .holds
            .retain(|device, _| !emergency_devices.contains(device));
        // Several roots may share a mount. Mark the episode after considering
        // all its devices (btrfs subvolumes can have distinct st_dev values).
        let mut attempted = HashSet::new();
        for root in roots {
            let (Some(mount), Some(device)) = (&root.mount_point, root.device_id) else {
                continue;
            };
            if root.btrfs
                && matches!(
                    root.level,
                    Some(PressureLevel::Yellow | PressureLevel::Orange)
                )
                && !state.attempted.contains(mount)
                && !emergency_devices.contains(&device)
            {
                let hold = state.holds.entry(device).or_insert_with(|| MountHold {
                    mounts: HashSet::new(),
                    until,
                });
                hold.mounts.insert(mount.clone());
                hold.mounts.extend(
                    roots
                        .iter()
                        .chain(known_roots)
                        .filter(|alias| alias.device_id == Some(device))
                        .filter_map(|alias| alias.mount_point.clone()),
                );
                attempted.insert(mount.clone());
            }
        }
        let mounts = attempted.len();
        state.attempted.extend(attempted);
        mounts
    }

    fn finish(&self) {
        self.state.lock().holds.clear();
    }

    /// Check at the mutation boundary as well as before a scan: a queued
    /// candidate may have been scored before the compression pass started.
    pub(super) fn defers_device(&self, device: u64, level: PressureLevel, now: Instant) -> bool {
        level < PressureLevel::Red
            && self
                .state
                .lock()
                .holds
                .get(&device)
                .is_some_and(|hold| now < hold.until)
    }

    pub(super) fn defers_mount(
        &self,
        mount: &std::path::Path,
        level: PressureLevel,
        now: Instant,
    ) -> bool {
        level < PressureLevel::Red
            && self
                .state
                .lock()
                .holds
                .values()
                .any(|hold| hold.mounts.contains(mount) && now < hold.until)
    }
}

/// The roots a pass should cover now; empty when no pass is due. Pure: it
/// reads no clock and touches no file.
#[must_use]
pub fn due_roots(
    config: &CompressConfig,
    roots: &[RootStatus],
    running: bool,
    last_start: Option<Instant>,
    now: Instant,
) -> Vec<PathBuf> {
    let Some(start) = due_start_level(config, running, last_start, now) else {
        return Vec::new();
    };
    roots
        .iter()
        .filter(|status| status.btrfs && status.level.is_some_and(|level| level >= start))
        .map(|status| status.root.clone())
        .collect()
}

/// Decide whether mount evidence is needed, before issuing filesystem queries.
/// A busy or cooling tier must not repeatedly stat roots on the monitor thread.
fn due_start_level(
    config: &CompressConfig,
    running: bool,
    last_start: Option<Instant>,
    now: Instant,
) -> Option<PressureLevel> {
    let start = config.start_pressure_level()?;
    let interval = Duration::from_secs(config.interval_minutes.saturating_mul(60));
    if !config.enabled
        || running
        || last_start.is_some_and(|last| now.saturating_duration_since(last) < interval)
    {
        return None;
    }
    Some(start)
}

/// Scheduling state of the tier: at most one pass and one root probe in flight.
#[derive(Debug, Default)]
pub struct CompressTier {
    running: Arc<AtomicBool>,
    /// Raised by [`CompressTier::stop_running_pass`]; the pass checks it
    /// before each file and between the chunks of a started one.
    stop: Arc<AtomicBool>,
    last_start: Option<Instant>,
    /// Where discovery may resume without skipping unvisited selected files.
    /// Execution commits only its visited prefix; after all selected files
    /// have been considered, discovery's own frontier takes over.
    /// `None` starts from the top. This is not a durable completion ledger.
    resume_after: Arc<Mutex<Option<PathBuf>>>,
    first: Arc<CompressionFirst>,
    probe: Option<RootProbe>,
    probe_roots: Vec<PathBuf>,
    evidence: HashMap<PathBuf, RootEvidence>,
    /// An old worker's token stays cancelled even if roots are removed and
    /// re-added, or the same configuration is re-enabled before it returns.
    probes_invalidated: AtomicBool,
    next_probe_root: usize,
    scope: Option<CompressionScope>,
}

impl CompressTier {
    pub(super) fn with_first(first: Arc<CompressionFirst>) -> Self {
        Self {
            first,
            ..Self::default()
        }
    }

    /// Drain completed observations without waiting on a worker or touching
    /// the filesystem. Even cancelled workers keep their slot until they exit.
    fn poll_probes(&mut self, roots: &[PathBuf], now: Instant) {
        let changed = self.probe_roots != roots;
        if self.probes_invalidated.swap(false, Ordering::AcqRel) || changed {
            if let Some(probe) = &self.probe {
                probe.cancelled.store(true, Ordering::Release);
            }
            self.evidence.clear();
            self.next_probe_root = 0;
            self.probe_roots = roots.to_vec();
            if changed && self.running.load(Ordering::Acquire) {
                // Removing a root also revokes an already running pass's old
                // scope. Its normal chunk-boundary cancellation still applies.
                self.stop.store(true, Ordering::Release);
            }
        }
        if let Some(probe) = &self.probe {
            let accept = !probe.cancelled.load(Ordering::Acquire);
            for observation in probe.receive.try_iter() {
                if accept && observation.fresh(now) && roots.contains(&observation.root) {
                    self.evidence.insert(observation.root.clone(), observation);
                }
            }
            // Joining an already-finished thread cannot wait on native I/O.
            // Keep a blocked slot: repeatedly replacing it would leak workers.
            if probe.worker.is_finished()
                && let Some(probe) = self.probe.take()
            {
                if probe.worker.join().is_err() {
                    eprintln!("[SBH-COMPRESS] root probe worker failed");
                }
                // A final observation can arrive between try_iter reporting
                // empty and is_finished. Joining seals that publication race.
                for observation in probe.receive.try_iter() {
                    if accept && observation.fresh(now) && roots.contains(&observation.root) {
                        self.evidence.insert(observation.root.clone(), observation);
                    }
                }
            }
        }
        self.evidence
            .retain(|_, observation| observation.fresh(now));
    }

    fn start_probe(&mut self, roots: &[PathBuf], platform: &Arc<dyn Platform>) {
        if self.probe.is_some() || roots.is_empty() {
            return;
        }
        let mut ordered = roots.to_vec();
        let offset = self.next_probe_root % ordered.len();
        ordered.rotate_left(offset);
        ordered.truncate(ROOT_PROBE_LIMIT);
        let (send, receive) = mpsc::sync_channel(ROOT_PROBE_LIMIT);
        let cancelled = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&cancelled);
        let platform = Arc::clone(platform);
        match std::thread::Builder::new()
            .name("sbh-compress-roots".into())
            .spawn(move || {
                for root in ordered {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    let observation = probe_root(root, platform.as_ref());
                    if stop.load(Ordering::Acquire) || send.try_send(observation).is_err() {
                        break;
                    }
                }
            }) {
            Ok(worker) => {
                self.probe = Some(RootProbe {
                    receive,
                    cancelled,
                    worker,
                });
            }
            Err(error) => eprintln!("[SBH-COMPRESS] root probe thread failed to start: {error}"),
        }
    }

    /// Start a pass on its own thread when one is due.
    pub fn tick(
        &mut self,
        now: Instant,
        config: &Config,
        platform: &Arc<dyn Platform>,
        mount_levels: &HashMap<PathBuf, PressureLevel>,
        logger: &ActivityLoggerHandle,
    ) {
        let scope = CompressionScope::from(config);
        if self
            .scope
            .as_ref()
            .is_some_and(|previous| previous != &scope)
        {
            self.stop_running_pass();
            // An old pass may still finish discovery or cancellation. Give
            // the new scope its own cursor so that late publication cannot
            // skip work under the new roots or newly admitted policy.
            self.resume_after = Arc::new(Mutex::new(None));
        }
        self.scope = Some(scope);
        self.first.update_levels(mount_levels);
        if !config.compress.enabled {
            self.stop_running_pass();
        }
        self.poll_probes(&config.compress.roots, now);
        let running = self.running.load(Ordering::Acquire);
        if due_start_level(&config.compress, running, self.last_start, now).is_none() {
            return;
        }
        let statuses: Vec<_> = config
            .compress
            .roots
            .iter()
            .filter_map(|root| self.evidence.get(root))
            .map(|observation| observation.status(mount_levels, &config.pressure))
            .collect();
        let roots = due_roots(&config.compress, &statuses, running, self.last_start, now);
        if roots.is_empty() {
            if config
                .compress
                .roots
                .iter()
                .any(|root| !self.evidence.contains_key(root))
            {
                self.start_probe(&config.compress.roots, platform);
            }
            return;
        }
        // If a later probe blocks, the ready prefix can still start. On the
        // next cycle give roots beyond that prefix first access to the worker.
        if let Some(index) = config
            .compress
            .roots
            .iter()
            .rposition(|root| roots.contains(root))
        {
            self.next_probe_root = (index + 1) % config.compress.roots.len();
        }
        self.last_start = Some(now);
        // No pass is running (due_roots checked), so no stop is pending.
        self.stop.store(false, Ordering::Release);
        self.running.store(true, Ordering::Release);
        // Only controllers can maintain a cleanup hold across ticks. A root
        // configured solely for compression may start a pass, but must not
        // delay cleanup through an unmonitored alias of a device or create a
        // new deletion-scanning scope.
        let cleanup_roots: Vec<_> = statuses
            .iter()
            .filter(|status| {
                roots.contains(&status.root)
                    && status
                        .mount_point
                        .as_ref()
                        .is_some_and(|mount| mount_levels.contains_key(mount))
            })
            .cloned()
            .collect();
        // Discovery has a 60-second cooperative budget; apply has the operator's
        // bounded policy deadline. The hold itself uses monotonic wall time, so
        // a stuck syscall cannot postpone deletion indefinitely.
        let allowance = Duration::from_secs(60)
            .saturating_add(Duration::from_secs(config.compress.policy.timeout_secs));
        let held_mounts = self.first.begin(&cleanup_roots, &statuses, now, allowance);
        let guard = RunningGuard {
            running: Arc::clone(&self.running),
            first: Arc::clone(&self.first),
        };
        if held_mounts > 0 {
            let message = format!(
                "lossless reclaim first on {held_mounts} mount(s): permanent cleanup waits \
                 until this pass finishes or {} seconds elapse; Red/Critical never wait",
                allowance.as_secs(),
            );
            eprintln!("[SBH-COMPRESS] {message}");
            logger.send(ActivityEvent::Info { message });
        }
        let stop = Arc::clone(&self.stop);
        let resume_after = Arc::clone(&self.resume_after);
        let config = config.clone();
        let platform = Arc::clone(platform);
        let logger = logger.clone();
        let spawned = std::thread::Builder::new()
            .name("sbh-compress".to_string())
            .spawn(move || {
                let _guard = guard;
                let message = run_pass(
                    &roots,
                    &config,
                    platform.as_ref(),
                    &resume_after,
                    &stop,
                    &logger,
                );
                eprintln!("[SBH-COMPRESS] {message}");
                logger.send(ActivityEvent::Info { message });
            });
        if let Err(error) = spawned {
            // The closure, and with it the guard, was dropped: running is clear.
            eprintln!("[SBH-COMPRESS] pass thread failed to start: {error}");
        }
    }

    /// Tell a running pass to stop: the daemon's policy no longer allows
    /// changes (observe or fallback-safe mode, the kill switch, dry-run, the
    /// tier was switched off, or shutdown). It stops before its next file, or before
    /// the next chunk of the file it is rewriting, whose raw remainder a
    /// later pass picks up. Also invalidates pending admission evidence, without
    /// waiting for a blocked root probe or starting a replacement worker.
    pub fn stop_running_pass(&self) {
        self.probes_invalidated.store(true, Ordering::Release);
        if let Some(probe) = &self.probe {
            probe.cancelled.store(true, Ordering::Release);
        }
        if self.running.load(Ordering::Acquire) {
            if !self.stop.swap(true, Ordering::AcqRel) {
                eprintln!("[SBH-COMPRESS] stopping the running pass");
            }
        } else {
            self.first.finish();
        }
    }
}

/// Clears `running` when the pass ends, however it ends.
struct RunningGuard {
    running: Arc<AtomicBool>,
    first: Arc<CompressionFirst>,
}

impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.first.finish();
        self.running.store(false, Ordering::Release);
    }
}

/// The only root admission path which performs filesystem I/O. It runs on
/// the probe worker, never on the monitor or in cancellation/drop handling.
fn probe_root(root: PathBuf, platform: &dyn Platform) -> RootEvidence {
    let started = Instant::now();
    let mut stats = platform.fs_stats(&root).ok();
    let mut device_id = stats
        .as_ref()
        .filter(|stats| stats.fs_type == "btrfs")
        .and_then(|_| identity_for_path(&root, true).ok())
        .map(|identity| identity.device_id);
    let completed_at = Instant::now();
    if completed_at.saturating_duration_since(started) >= ROOT_PROBE_MAX_AGE {
        // A fresh completion timestamp cannot refresh an old filesystem
        // reading when a later identity lookup was stuck for a long time.
        stats = None;
        device_id = None;
    }
    RootEvidence {
        root,
        stats,
        device_id,
        completed_at,
    }
}

/// One pass: discover, then apply to exactly what discovery selected.
/// Returns the summary line.
fn run_pass(
    roots: &[PathBuf],
    config: &Config,
    platform: &dyn Platform,
    resume_after: &Mutex<Option<PathBuf>>,
    stop: &AtomicBool,
    logger: &ActivityLoggerHandle,
) -> String {
    let policy = &config.compress.policy;
    let after = resume_after.lock().ok().and_then(|resume| resume.clone());
    // The largest budgets discovery accepts. A resumed walk re-reads the
    // cursor's ancestors first (a temp root can hold tens of thousands of
    // entries), so small budgets would leave little for new ground.
    let limits = discovery::DiscoveryLimits {
        max_entries: 1_000_000,
        max_directories: 8192,
        timeout_secs: 60,
        after,
        ..discovery::DiscoveryLimits::default()
    };
    let selection = match discovery::discover(roots, policy, &limits, config, platform) {
        Ok(selection) => selection,
        Err(error) => {
            // A cursor from other roots (the due set changed) is refused; drop
            // it so the next pass starts from the top instead of failing too.
            if let Ok(mut resume) = resume_after.lock() {
                *resume = None;
            }
            return format!("discovery under {} root(s) failed: {error}", roots.len());
        }
    };
    let report = selection.report();
    let next = match report
        .resume_after_hex
        .as_deref()
        .map(discovery::continuation_path)
        .transpose()
    {
        Ok(next) => next,
        Err(error) => return format!("discovery returned an invalid continuation: {error}"),
    };
    if report.selected_files == 0 {
        // No selected work can be lost here. Retain discovery progress through
        // excluded entries, including incomplete pages with no eligible files.
        if let Ok(mut resume) = resume_after.lock() {
            *resume = next;
        }
        return format!(
            "nothing eligible under {} root(s) ({} entries examined{})",
            roots.len(),
            report.entries_examined,
            if report.complete { "" } else { ", partial" }
        );
    }
    let mode = CompressionMode {
        apply: true,
        allow_zstd_feature: config.compress.allow_zstd_feature,
        acknowledgement: ConcurrencyAcknowledgement::Unattended,
    };
    let mut observer = |observation: CompressionObservation<'_>| {
        record_outcome(observation, logger);
    };
    execute_and_resume(&selection.paths(), next, resume_after, || {
        compression::run_discovered(
            &selection,
            policy,
            mode,
            config,
            platform,
            Some(stop),
            &mut observer,
        )
    })
}

/// Commit a skip hint only after the checked executor returns. Discovery can
/// run far ahead of rewriting; its last selected path is not an execution
/// receipt. Timeouts and safety stops must leave the unvisited tail available.
/// The closure is the ordinary executor, with unchanged admission and auditing.
fn execute_and_resume(
    selected: &[PathBuf],
    discovery_next: Option<PathBuf>,
    resume_after: &Mutex<Option<PathBuf>>,
    execute: impl FnOnce() -> io::Result<CompressionReport>,
) -> String {
    let before = match resume_after.lock() {
        Ok(resume) => resume.clone(),
        Err(_) => return "pass refused before any rewrite: continuation state is poisoned".into(),
    };
    // Do not hold the cursor mutex during native I/O or activity callbacks.
    let report = match execute() {
        Ok(report) => report,
        Err(error) => return format!("pass refused before any rewrite: {error}"),
    };
    let summary = summarize(&report);
    if !report.supported || report.dry_run {
        return summary;
    }
    let visited = report.files.len();
    if visited.checked_add(report.unvisited_files) != Some(selected.len())
        || report
            .files
            .iter()
            .zip(selected)
            .any(|(file, path)| &file.path != path)
    {
        // A canonical path changing after selection, or a future executor
        // changing its ordering, must not move the cursor outside the observed
        // prefix. Retrying is safer than guessing from lossy display strings.
        return format!("{summary}; continuation retained: execution was not a selected prefix");
    }
    let next = if report.unvisited_files == 0 {
        discovery_next
    } else if visited == 0 {
        before
    } else {
        // A visit includes a checked skip/failure, not just a successful
        // compression. Retrying a permanently refused first file every pass
        // would starve the rest; its outcome remains in the pass report.
        Some(selected[visited - 1].clone())
    };
    match resume_after.lock() {
        Ok(mut resume) => {
            *resume = next;
            summary
        }
        Err(_) => format!("{summary}; continuation unavailable: next pass must rediscover"),
    }
}

/// An outcome with a journal entry becomes a ledger row; anything else is
/// already in the pass summary.
fn record_outcome(observation: CompressionObservation<'_>, logger: &ActivityLoggerHandle) {
    let Some(journal) = observation.journal_path else {
        return;
    };
    if let Ok(activity) = CompressionActivity::new(
        observation.file,
        journal,
        observation.journal_outcome_recorded,
    ) {
        logger.send(ActivityEvent::CompressionRecorded(Box::new(activity)));
    }
}

/// Outcome counts and referenced bytes saved. Saved bytes are not yet free
/// space: btrfs releases an old extent once nothing references it.
fn summarize(report: &CompressionReport) -> String {
    let count = |outcome: &str| {
        report
            .files
            .iter()
            .filter(|file| file.outcome == outcome)
            .count()
    };
    let saved: u64 = report
        .files
        .iter()
        .filter_map(|file| file.reclaim.as_ref())
        .map(|reclaim| reclaim.referenced_bytes_saved)
        .sum();
    format!(
        "pass: {} compressed, {} partial, {} skipped, {} failed, {} unvisited; {} referenced \
         bytes saved{}",
        count("compressed"),
        count("partial"),
        count("skipped"),
        count("failed"),
        report.unvisited_files,
        human_bytes(saved),
        report
            .stop_reason
            .as_deref()
            .map(|reason| format!("; stopped: {reason}"))
            .unwrap_or_default()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_statuses(
        roots: &[PathBuf],
        platform: &dyn Platform,
        mount_levels: &HashMap<PathBuf, PressureLevel>,
        pressure: &PressureConfig,
    ) -> Vec<RootStatus> {
        roots
            .iter()
            .map(|root| probe_root(root.clone(), platform).status(mount_levels, pressure))
            .collect()
    }

    #[derive(Default)]
    struct ProbeGate {
        allowed: parking_lot::Mutex<HashSet<PathBuf>>,
        all: AtomicBool,
        changed: parking_lot::Condvar,
    }

    impl ProbeGate {
        fn release(&self, path: &std::path::Path) {
            self.allowed.lock().insert(path.to_path_buf());
            self.changed.notify_all();
        }

        fn release_all(&self) {
            let _guard = self.allowed.lock();
            self.all.store(true, Ordering::Release);
            self.changed.notify_all();
        }

        fn wait(&self, path: &std::path::Path) {
            let mut allowed = self.allowed.lock();
            while !self.all.load(Ordering::Acquire) && !allowed.contains(path) {
                self.changed.wait(&mut allowed);
            }
        }
    }

    struct ControlledPlatform {
        inner: crate::platform::pal::MockPlatform,
        requests: mpsc::Sender<PathBuf>,
        gate: Arc<ProbeGate>,
    }

    impl Platform for ControlledPlatform {
        fn fs_stats(&self, path: &std::path::Path) -> crate::core::errors::Result<FsStats> {
            let _ = self.requests.send(path.to_path_buf());
            self.gate.wait(path);
            self.inner.fs_stats(path)
        }

        fn mount_points(
            &self,
        ) -> crate::core::errors::Result<Vec<crate::platform::pal::MountPoint>> {
            self.inner.mount_points()
        }

        fn is_ram_backed(&self, path: &std::path::Path) -> crate::core::errors::Result<bool> {
            self.inner.is_ram_backed(path)
        }

        fn default_paths(&self) -> crate::platform::pal::PlatformPaths {
            self.inner.default_paths()
        }

        fn memory_info(&self) -> crate::core::errors::Result<crate::platform::pal::MemoryInfo> {
            self.inner.memory_info()
        }

        fn service_manager(&self) -> Box<dyn crate::platform::pal::ServiceManager> {
            self.inner.service_manager()
        }
    }

    struct ProbeFixture {
        platform: Arc<dyn Platform>,
        requests: mpsc::Receiver<PathBuf>,
        gate: Arc<ProbeGate>,
    }

    impl ProbeFixture {
        fn new(stats: Vec<FsStats>) -> Self {
            let (send, requests) = mpsc::channel();
            let gate = Arc::new(ProbeGate::default());
            let platform = Arc::new(ControlledPlatform {
                inner: mounted_platform(stats),
                requests: send,
                gate: Arc::clone(&gate),
            });
            Self {
                platform,
                requests,
                gate,
            }
        }

        fn requested(&self, root: &std::path::Path) {
            assert_eq!(
                self.requests.recv_timeout(Duration::from_secs(5)).unwrap(),
                root
            );
        }

        /// A separate caller and a bounded receive prove the monitor returned
        /// while native probe I/O remains blocked, without a timing benchmark.
        fn monitor(
            &self,
            mut tier: CompressTier,
            work: impl FnOnce(&mut CompressTier) + Send + 'static,
        ) -> CompressTier {
            let (send, receive) = mpsc::sync_channel(1);
            let caller = std::thread::spawn(move || {
                work(&mut tier);
                let _ = send.send(tier);
            });
            let result = receive.recv_timeout(Duration::from_secs(5));
            if result.is_err() {
                // A regression must fail the test rather than leave a native
                // worker or the test caller blocked after its assertion.
                self.gate.release_all();
            }
            caller.join().unwrap();
            result.expect("monitor tick/stop waited for a blocked root probe")
        }
    }

    impl Drop for ProbeFixture {
        fn drop(&mut self) {
            self.gate.release_all();
        }
    }

    struct ProbeLogger {
        handle: ActivityLoggerHandle,
        join: Option<std::thread::JoinHandle<()>>,
        _directory: tempfile::TempDir,
    }

    impl ProbeLogger {
        fn new() -> Self {
            use crate::logger::dual::{DualLoggerConfig, spawn_logger};
            use crate::logger::jsonl::JsonlConfig;

            let directory = tempfile::tempdir().unwrap();
            let (handle, join) = spawn_logger(DualLoggerConfig {
                sqlite_path: None,
                jsonl_config: JsonlConfig {
                    path: directory.path().join("activity.jsonl"),
                    fallback_path: None,
                    max_size_bytes: 1024 * 1024,
                    max_rotated_files: 1,
                    fsync_interval_secs: 60,
                },
                channel_capacity: 32,
                run_id: None,
            })
            .unwrap();
            Self {
                handle,
                join: Some(join),
                _directory: directory,
            }
        }
    }

    impl Drop for ProbeLogger {
        fn drop(&mut self) {
            self.handle.shutdown();
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    fn probe_config(roots: &[&str]) -> Config {
        Config {
            compress: CompressConfig {
                roots: roots.iter().map(PathBuf::from).collect(),
                ..enabled()
            },
            ..Config::default()
        }
    }

    fn drain_finished_probe(tier: &mut CompressTier, roots: &[PathBuf]) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while tier.probe.is_some() {
            tier.poll_probes(roots, Instant::now());
            assert!(Instant::now() < deadline, "released probe did not finish");
            std::thread::yield_now();
        }
    }

    #[test]
    fn blocked_root_io_never_blocks_ticks_stop_or_grows_a_worker_backlog() {
        let root = PathBuf::from("/sbh-test-blocked-root/scratch");
        let fixture = ProbeFixture::new(vec![volume("/sbh-test-blocked-root", "btrfs", 1000, 120)]);
        let logger = ProbeLogger::new();
        let config = probe_config(&["/sbh-test-blocked-root/scratch"]);
        let initial = config.clone();
        let platform = Arc::clone(&fixture.platform);
        let handle = logger.handle.clone();
        let tier = fixture.monitor(CompressTier::default(), move |tier| {
            tier.tick(
                Instant::now(),
                &initial,
                &platform,
                &HashMap::new(),
                &handle,
            );
        });
        fixture.requested(&root);
        let platform = Arc::clone(&fixture.platform);
        let handle = logger.handle.clone();
        let repeated = config.clone();
        let mut tier = fixture.monitor(tier, move |tier| {
            for _ in 0..32 {
                tier.tick(
                    Instant::now(),
                    &repeated,
                    &platform,
                    &HashMap::new(),
                    &handle,
                );
            }
            tier.stop_running_pass();
            for _ in 0..32 {
                tier.tick(
                    Instant::now(),
                    &repeated,
                    &platform,
                    &HashMap::new(),
                    &handle,
                );
            }
        });
        assert!(
            fixture.requests.try_recv().is_err(),
            "only one native query is outstanding"
        );
        assert!(tier.last_start.is_none());
        assert!(!tier.running.load(Ordering::Acquire));
        assert!(
            tier.first.state.lock().holds.is_empty(),
            "unknown roots cannot hold cleanup"
        );
        assert!(
            tier.probe
                .as_ref()
                .unwrap()
                .cancelled
                .load(Ordering::Acquire)
        );
        fixture.gate.release_all();
        drain_finished_probe(&mut tier, &config.compress.roots);
        assert!(tier.evidence.is_empty(), "cancelled results remain invalid");
    }

    #[test]
    fn scope_reload_cancels_old_work_and_discards_its_late_continuation() {
        type ScopeChange = (&'static str, fn(&mut Config));
        let cases: [ScopeChange; 11] = [
            ("roots", |config| {
                config.compress.roots = vec![PathBuf::from("/sbh-test-new-scope/scratch")];
            }),
            ("disabled", |config| config.compress.enabled = false),
            ("feature consent", |config| {
                config.compress.allow_zstd_feature = false;
            }),
            ("work policy", |config| {
                config.compress.policy.min_age_secs *= 2;
            }),
            ("protected paths", |config| {
                config
                    .scanner
                    .protected_paths
                    .push("/newly-protected/**".into());
            }),
            ("configuration path", |config| {
                config.paths.config_file = PathBuf::from("/new/config.toml");
            }),
            ("state and journal path", |config| {
                config.paths.state_file = PathBuf::from("/new/state.json");
            }),
            ("database and sidecar paths", |config| {
                config.paths.sqlite_db = PathBuf::from("/new/activity.sqlite3");
            }),
            ("activity log path", |config| {
                config.paths.jsonl_log = PathBuf::from("/new/activity.jsonl");
            }),
            ("update cache path", |config| {
                config.update.metadata_cache_file = PathBuf::from("/new/update.json");
            }),
            ("notification log path", |config| {
                config.notifications.file.path = PathBuf::from("/new/notifications.jsonl");
            }),
        ];
        let logger = ProbeLogger::new();
        for (label, change) in cases {
            let root = PathBuf::from("/sbh-test-scope/scratch");
            let fixture = ProbeFixture::new(vec![volume("/sbh-test-scope", "btrfs", 1000, 120)]);
            let config = probe_config(&["/sbh-test-scope/scratch"]);
            let mut tier = CompressTier::default();
            tier.tick(
                Instant::now(),
                &config,
                &fixture.platform,
                &HashMap::new(),
                &logger.handle,
            );
            fixture.requested(&root);
            // Model an admitted worker's lifetime using the production guard.
            // A later root's native probe remains blocked during the reload.
            tier.running.store(true, Ordering::Release);
            let guard = RunningGuard {
                running: Arc::clone(&tier.running),
                first: Arc::clone(&tier.first),
            };
            let old_cursor = Arc::clone(&tier.resume_after);
            *old_cursor.lock().unwrap() = Some(root.join("already-visited"));
            let mut reloaded = config.clone();
            change(&mut reloaded);
            tier.tick(
                Instant::now(),
                &reloaded,
                &fixture.platform,
                &HashMap::new(),
                &logger.handle,
            );
            assert!(tier.stop.load(Ordering::Acquire), "{label}");
            assert!(tier.running.load(Ordering::Acquire), "{label}");
            assert!(!Arc::ptr_eq(&old_cursor, &tier.resume_after), "{label}");
            // Restoring the old settings cannot revive work already revoked,
            // replace a blocked native worker, or start another rewrite pass.
            tier.tick(
                Instant::now(),
                &config,
                &fixture.platform,
                &HashMap::new(),
                &logger.handle,
            );
            assert!(tier.stop.load(Ordering::Acquire), "{label}");
            assert!(tier.last_start.is_none(), "{label}");
            assert!(fixture.requests.try_recv().is_err(), "{label}");
            *old_cursor.lock().unwrap() = Some(root.join("late-old-policy-progress"));
            drop(guard);
            assert_eq!(*tier.resume_after.lock().unwrap(), None, "{label}");
            fixture.gate.release_all();
            drain_finished_probe(&mut tier, &config.compress.roots);
            assert!(tier.evidence.is_empty(), "{label}");
        }
    }

    #[test]
    fn unrelated_reload_keeps_active_work_probe_evidence_and_continuation() {
        let root = PathBuf::from("/sbh-test-unrelated-reload/scratch");
        let fixture = ProbeFixture::new(vec![volume(
            "/sbh-test-unrelated-reload",
            "btrfs",
            1000,
            120,
        )]);
        let logger = ProbeLogger::new();
        let mut config = probe_config(&["/sbh-test-unrelated-reload/scratch"]);
        let mut tier = CompressTier::default();
        tier.tick(
            Instant::now(),
            &config,
            &fixture.platform,
            &HashMap::new(),
            &logger.handle,
        );
        fixture.requested(&root);
        tier.running.store(true, Ordering::Release);
        let guard = RunningGuard {
            running: Arc::clone(&tier.running),
            first: Arc::clone(&tier.first),
        };
        let cursor = Arc::clone(&tier.resume_after);
        *cursor.lock().unwrap() = Some(root.join("progress"));
        config.notifications.enabled = !config.notifications.enabled;
        config.notifications.min_notify_interval_secs += 30;
        config.dashboard.kill_switch = !config.dashboard.kill_switch;
        tier.tick(
            Instant::now(),
            &config,
            &fixture.platform,
            &HashMap::new(),
            &logger.handle,
        );
        assert!(!tier.stop.load(Ordering::Acquire));
        assert!(tier.running.load(Ordering::Acquire));
        assert!(Arc::ptr_eq(&cursor, &tier.resume_after));
        assert_eq!(
            *tier.resume_after.lock().unwrap(),
            Some(root.join("progress"))
        );
        fixture.gate.release_all();
        drain_finished_probe(&mut tier, &config.compress.roots);
        assert!(tier.evidence.contains_key(&root));
        drop(guard);
        tier.stop_running_pass();
    }

    #[test]
    fn removed_readded_and_reenabled_roots_cannot_accept_an_old_workers_result() {
        for change_roots in [true, false] {
            let root = PathBuf::from("/sbh-test-old-generation/scratch");
            let fixture =
                ProbeFixture::new(vec![volume("/sbh-test-old-generation", "btrfs", 1000, 120)]);
            let logger = ProbeLogger::new();
            let mut config = probe_config(&["/sbh-test-old-generation/scratch"]);
            let mut tier = CompressTier::default();
            tier.tick(
                Instant::now(),
                &config,
                &fixture.platform,
                &HashMap::new(),
                &logger.handle,
            );
            fixture.requested(&root);
            if change_roots {
                config.compress.roots = vec![PathBuf::from("/sbh-test-other-generation/scratch")];
            } else {
                config.compress.enabled = false;
            }
            tier.tick(
                Instant::now(),
                &config,
                &fixture.platform,
                &HashMap::new(),
                &logger.handle,
            );
            config.compress.roots = vec![root.clone()];
            config.compress.enabled = true;
            tier.tick(
                Instant::now(),
                &config,
                &fixture.platform,
                &HashMap::new(),
                &logger.handle,
            );
            assert!(
                fixture.requests.try_recv().is_err(),
                "a blocked slot is not replaced"
            );
            fixture.gate.release_all();
            drain_finished_probe(&mut tier, &config.compress.roots);
            assert!(
                tier.evidence.is_empty(),
                "the old generation was permanently revoked"
            );
            assert!(tier.last_start.is_none());

            tier.tick(
                Instant::now(),
                &config,
                &fixture.platform,
                &HashMap::new(),
                &logger.handle,
            );
            fixture.requested(&root);
            drain_finished_probe(&mut tier, &config.compress.roots);
            tier.tick(
                Instant::now(),
                &config,
                &fixture.platform,
                &HashMap::new(),
                &logger.handle,
            );
            assert!(
                tier.last_start.is_some(),
                "a fresh valid root eventually starts a pass"
            );
            tier.stop_running_pass();
        }
    }

    #[test]
    fn delayed_probe_uses_live_controller_levels_at_admission() {
        let root = PathBuf::from("/sbh-test-live-controller/scratch");
        let mount = PathBuf::from("/sbh-test-live-controller");
        let fixture =
            ProbeFixture::new(vec![volume("/sbh-test-live-controller", "btrfs", 1000, 1)]);
        let logger = ProbeLogger::new();
        let config = probe_config(&["/sbh-test-live-controller/scratch"]);
        let mut tier = CompressTier::default();
        let critical = HashMap::from([(mount.clone(), PressureLevel::Critical)]);
        tier.tick(
            Instant::now(),
            &config,
            &fixture.platform,
            &critical,
            &logger.handle,
        );
        fixture.requested(&root);
        fixture.gate.release_all();
        drain_finished_probe(&mut tier, &config.compress.roots);
        let green = HashMap::from([(mount.clone(), PressureLevel::Green)]);
        tier.tick(
            Instant::now(),
            &config,
            &fixture.platform,
            &green,
            &logger.handle,
        );
        assert!(
            tier.last_start.is_none(),
            "the earlier Critical sample is not admission authority"
        );
        assert!(
            fixture.requests.try_recv().is_err(),
            "fresh observations need no repeated I/O"
        );
        let yellow = HashMap::from([(mount, PressureLevel::Yellow)]);
        tier.tick(
            Instant::now(),
            &config,
            &fixture.platform,
            &yellow,
            &logger.handle,
        );
        assert!(tier.last_start.is_some());
        tier.stop_running_pass();
    }

    #[test]
    fn expired_and_disabled_completed_snapshots_need_new_admission_evidence() {
        for disable in [false, true] {
            let root = PathBuf::from("/sbh-test-expiring-root/scratch");
            let fixture =
                ProbeFixture::new(vec![volume("/sbh-test-expiring-root", "btrfs", 1000, 500)]);
            let logger = ProbeLogger::new();
            let config = probe_config(&["/sbh-test-expiring-root/scratch"]);
            let mut tier = CompressTier::default();
            tier.tick(
                Instant::now(),
                &config,
                &fixture.platform,
                &HashMap::new(),
                &logger.handle,
            );
            fixture.requested(&root);
            fixture.gate.release_all();
            drain_finished_probe(&mut tier, &config.compress.roots);
            let completed = tier.evidence[&root].completed_at;
            let now = if disable {
                tier.stop_running_pass();
                Instant::now()
            } else {
                completed + ROOT_PROBE_MAX_AGE
            };
            let levels = HashMap::from([(
                PathBuf::from("/sbh-test-expiring-root"),
                PressureLevel::Critical,
            )]);
            tier.tick(now, &config, &fixture.platform, &levels, &logger.handle);
            assert!(
                tier.last_start.is_none(),
                "old snapshots cannot authorize a pass"
            );
            fixture.requested(&root);
            tier.stop_running_pass();
            drain_finished_probe(&mut tier, &config.compress.roots);
        }
    }

    #[test]
    fn a_ready_root_runs_while_a_later_root_is_blocked_and_rotates_the_next_probe() {
        let first = PathBuf::from("/sbh-test-probe-first/scratch");
        let second = PathBuf::from("/sbh-test-probe-second/scratch");
        let fixture = ProbeFixture::new(vec![
            volume("/sbh-test-probe-first", "btrfs", 1000, 120),
            volume("/sbh-test-probe-second", "btrfs", 1000, 120),
        ]);
        let logger = ProbeLogger::new();
        let config = probe_config(&[
            "/sbh-test-probe-first/scratch",
            "/sbh-test-probe-second/scratch",
        ]);
        let mut tier = CompressTier::default();
        tier.tick(
            Instant::now(),
            &config,
            &fixture.platform,
            &HashMap::new(),
            &logger.handle,
        );
        fixture.requested(&first);
        fixture.gate.release(&first);
        fixture.requested(&second);
        tier.tick(
            Instant::now(),
            &config,
            &fixture.platform,
            &HashMap::new(),
            &logger.handle,
        );
        let started = tier
            .last_start
            .expect("the ready root starts despite a later blocked probe");
        assert!(tier.probe.is_some());
        assert_eq!(tier.next_probe_root, 1);
        fixture.gate.release_all();
        drain_finished_probe(&mut tier, &config.compress.roots);
        let deadline = Instant::now() + Duration::from_secs(5);
        while tier.running.load(Ordering::Acquire) {
            assert!(Instant::now() < deadline, "empty pass did not finish");
            std::thread::yield_now();
        }
        let due = started + Duration::from_mins(config.compress.interval_minutes);
        tier.tick(
            due,
            &config,
            &fixture.platform,
            &HashMap::new(),
            &logger.handle,
        );
        fixture.requested(&second);
        fixture.requested(&first);
        tier.stop_running_pass();
        drain_finished_probe(&mut tier, &config.compress.roots);
    }

    #[test]
    fn first_chance_is_per_device_bounded_and_does_not_repeat_within_an_episode() {
        let first = CompressionFirst::default();
        let now = Instant::now();
        let root = status("/data", true, Some(PressureLevel::Orange));
        first.begin(
            std::slice::from_ref(&root),
            &[],
            now,
            Duration::from_secs(30),
        );
        assert!(first.defers_device(1, PressureLevel::Orange, now));
        assert!(first.defers_mount(std::path::Path::new("/data"), PressureLevel::Yellow, now));
        assert!(!first.defers_device(2, PressureLevel::Orange, now));
        assert!(!first.defers_mount(std::path::Path::new("/other"), PressureLevel::Orange, now));
        assert!(!first.defers_device(1, PressureLevel::Red, now));
        assert!(!first.defers_device(1, PressureLevel::Critical, now));
        assert!(!first.defers_device(1, PressureLevel::Orange, now + Duration::from_secs(30)));

        // The pass can still be in an uninterruptible syscall, or another
        // pass can become due. Neither extends this pressure episode's hold.
        first.begin(
            std::slice::from_ref(&root),
            &[],
            now + Duration::from_secs(31),
            Duration::from_secs(30),
        );
        assert!(!first.defers_device(1, PressureLevel::Orange, now + Duration::from_secs(31)));
        first.finish();
        first.begin(
            std::slice::from_ref(&root),
            &[],
            now + Duration::from_secs(60),
            Duration::from_secs(30),
        );
        assert!(!first.defers_device(1, PressureLevel::Orange, now + Duration::from_secs(60)));

        first.update_levels(&HashMap::from([(
            PathBuf::from("/data"),
            PressureLevel::Green,
        )]));
        first.begin(
            &[root],
            &[],
            now + Duration::from_secs(90),
            Duration::from_secs(30),
        );
        assert!(first.defers_device(1, PressureLevel::Orange, now + Duration::from_secs(90)));
    }

    #[test]
    fn live_emergency_or_completion_releases_even_an_older_queued_batch() {
        let first = Arc::new(CompressionFirst::default());
        let now = Instant::now();
        let root = status("/data", true, Some(PressureLevel::Yellow));
        first.begin(
            std::slice::from_ref(&root),
            &[],
            now,
            Duration::from_secs(30),
        );
        first.update_levels(&HashMap::from([(
            PathBuf::from("/data"),
            PressureLevel::Red,
        )]));
        assert!(!first.defers_device(1, PressureLevel::Yellow, now));

        first.begin(&[root], &[], now, Duration::from_secs(30));
        let running = Arc::new(AtomicBool::new(true));
        let guard = RunningGuard {
            running: Arc::clone(&running),
            first: Arc::clone(&first),
        };
        assert!(first.defers_device(1, PressureLevel::Yellow, now));
        drop(guard);
        assert!(!running.load(Ordering::Acquire));
        assert!(!first.defers_device(1, PressureLevel::Yellow, now));
    }

    #[test]
    fn aliases_and_btrfs_subvolume_devices_share_the_mounts_first_chance() {
        let first = CompressionFirst::default();
        let now = Instant::now();
        let a = status("/data", true, Some(PressureLevel::Orange));
        let alias = status("/alias", true, Some(PressureLevel::Orange));
        let subvolume = RootStatus {
            root: PathBuf::from("/data/subvolume"),
            device_id: Some(2),
            ..a.clone()
        };
        first.begin(&[a, alias, subvolume], &[], now, Duration::from_secs(30));
        for mount in ["/data", "/alias"] {
            assert!(first.defers_mount(std::path::Path::new(mount), PressureLevel::Orange, now));
        }
        for device in [1, 2] {
            assert!(first.defers_device(device, PressureLevel::Orange, now));
        }
        first.update_levels(&HashMap::from([
            (PathBuf::from("/data"), PressureLevel::Green),
            (PathBuf::from("/alias"), PressureLevel::Orange),
        ]));
        assert!(first.defers_mount(std::path::Path::new("/alias"), PressureLevel::Orange, now));
        // The alias shares device 1, so its cleanup shares the same hold.
        assert!(first.defers_mount(std::path::Path::new("/data"), PressureLevel::Green, now));
        assert!(!first.defers_device(2, PressureLevel::Orange, now));
    }

    #[test]
    fn unsupported_unresolved_and_emergency_roots_never_hold_cleanup() {
        let first = CompressionFirst::default();
        let now = Instant::now();
        for mut root in [
            status("/ext4", false, Some(PressureLevel::Orange)),
            status("/green", true, Some(PressureLevel::Green)),
            status("/red", true, Some(PressureLevel::Red)),
            status("/critical", true, Some(PressureLevel::Critical)),
            status("/unknown", true, None),
        ] {
            first.begin(
                std::slice::from_ref(&root),
                &[],
                now,
                Duration::from_secs(30),
            );
            assert!(!first.defers_device(1, PressureLevel::Yellow, now));
            root.level = Some(PressureLevel::Orange);
            root.device_id = None;
            first.begin(&[root], &[], now, Duration::from_secs(30));
            assert!(!first.defers_device(1, PressureLevel::Orange, now));
        }
    }

    #[test]
    fn emergency_aliases_prevent_new_holds_and_release_older_queued_work() {
        let now = Instant::now();
        for emergency in [PressureLevel::Red, PressureLevel::Critical] {
            let first = CompressionFirst::default();
            let root = status("/data", true, Some(PressureLevel::Orange));
            let alias = status("/alias", true, Some(emergency));
            let independent = RootStatus {
                device_id: Some(2),
                ..status("/other", true, Some(PressureLevel::Orange))
            };
            first.begin(&[root, independent], &[alias], now, Duration::from_secs(30));
            assert!(!first.defers_device(1, PressureLevel::Orange, now));
            assert!(first.defers_device(2, PressureLevel::Orange, now));
        }

        let first = CompressionFirst::default();
        let root = status("/data", true, Some(PressureLevel::Orange));
        let alias = status("/alias", true, Some(PressureLevel::Green));
        let subvolume = RootStatus {
            root: PathBuf::from("/data/subvolume"),
            device_id: Some(2),
            ..root.clone()
        };
        first.begin(&[root, subvolume], &[alias], now, Duration::from_secs(30));
        assert!(first.defers_device(1, PressureLevel::Orange, now));
        first.update_levels(&HashMap::from([
            (PathBuf::from("/data"), PressureLevel::Orange),
            (PathBuf::from("/alias"), PressureLevel::Green),
        ]));
        first.update_levels(&HashMap::from([
            (PathBuf::from("/data"), PressureLevel::Orange),
            (PathBuf::from("/alias"), PressureLevel::Red),
        ]));
        assert!(!first.defers_device(1, PressureLevel::Orange, now));
        assert!(first.defers_device(2, PressureLevel::Orange, now));
        first.update_levels(&HashMap::from([(
            PathBuf::from("/data"),
            PressureLevel::Critical,
        )]));
        assert!(!first.defers_device(2, PressureLevel::Orange, now));
    }

    #[test]
    fn cancellation_holds_cleanup_until_worker_exit_or_the_original_deadline() {
        let first = Arc::new(CompressionFirst::default());
        let now = Instant::now();
        first.begin(
            &[status("/data", true, Some(PressureLevel::Orange))],
            &[],
            now,
            Duration::from_secs(30),
        );
        let tier = CompressTier::with_first(Arc::clone(&first));
        tier.running.store(true, Ordering::Release);
        let guard = RunningGuard {
            running: Arc::clone(&tier.running),
            first: Arc::clone(&first),
        };
        tier.stop_running_pass();
        assert!(tier.stop.load(Ordering::Acquire));
        assert!(first.defers_device(1, PressureLevel::Orange, now));
        assert!(!first.defers_device(1, PressureLevel::Orange, now + Duration::from_secs(30)));
        drop(guard);
        assert!(!first.defers_device(1, PressureLevel::Orange, now));
        assert!(!tier.running.load(Ordering::Acquire));
    }

    fn paths() -> Vec<PathBuf> {
        ["/cache/a.bin", "/cache/b.bin", "/cache/c.bin"]
            .into_iter()
            .map(PathBuf::from)
            .collect()
    }

    fn execution_report(selected: &[PathBuf], outcomes: &[&str]) -> CompressionReport {
        use crate::scanner::compression::{CompressionFileReport, CompressionPolicy};

        assert!(outcomes.len() <= selected.len());
        CompressionReport {
            schema: "sbh.compression.v1",
            dry_run: false,
            supported: true,
            policy: CompressionPolicy::default(),
            journal_path: None,
            files: selected
                .iter()
                .zip(outcomes)
                .map(|(path, outcome)| CompressionFileReport {
                    path: path.clone(),
                    operation_id: None,
                    outcome: (*outcome).to_owned(),
                    detail: "injected executor visit; no native mutation".into(),
                    logical_bytes: 1024,
                    physical_data_bytes_before: None,
                    physical_data_bytes_after: None,
                    processed_bytes: 0,
                    mutation_attempted: false,
                    sha256_before: None,
                    sha256_after: None,
                    content_verified: false,
                    reclaim: None,
                    accounting_error: None,
                })
                .collect(),
            unvisited_files: selected.len() - outcomes.len(),
            stop_reason: (outcomes.len() < selected.len()).then(|| "injected stop".into()),
            elapsed_ms: 0,
            exit_code: if outcomes.len() < selected.len() {
                4
            } else {
                0
            },
        }
    }

    #[test]
    fn partial_execution_commits_only_the_visited_prefix_after_the_executor_returns() {
        let selected = paths();
        let previous = Some(PathBuf::from("/cache/0.bin"));
        let cursor = Mutex::new(previous.clone());
        let message = execute_and_resume(&selected, Some(selected[2].clone()), &cursor, || {
            assert_eq!(
                *cursor.lock().unwrap(),
                previous,
                "no early cursor publication"
            );
            Ok(execution_report(&selected, &["compressed"]))
        });
        assert_eq!(*cursor.lock().unwrap(), Some(selected[0].clone()));
        assert!(message.contains("2 unvisited"), "{message}");
    }

    #[test]
    fn complete_discovery_does_not_wrap_while_selected_files_are_unvisited() {
        let selected = paths();
        let cursor = Mutex::new(None);
        execute_and_resume(&selected, None, &cursor, || {
            Ok(execution_report(&selected, &["skipped", "failed"]))
        });
        assert_eq!(*cursor.lock().unwrap(), Some(selected[1].clone()));
    }

    #[test]
    fn fully_visited_selection_uses_discoverys_frontier_or_wraps_on_completion() {
        let selected = paths();
        // Discovery can finish excluded entries beyond the last selected file.
        for next in [Some(PathBuf::from("/cache/z-excluded")), None] {
            let cursor = Mutex::new(Some(PathBuf::from("/cache/0.bin")));
            execute_and_resume(&selected, next.clone(), &cursor, || {
                Ok(execution_report(
                    &selected,
                    &["skipped", "failed", "compressed"],
                ))
            });
            assert_eq!(*cursor.lock().unwrap(), next);
        }
    }

    #[test]
    fn failed_or_zero_visit_pass_retains_the_incoming_cursor() {
        let selected = paths();
        for previous in [None, Some(PathBuf::from("/cache/0.bin"))] {
            let cursor = Mutex::new(previous.clone());
            let message = execute_and_resume(&selected, Some(selected[2].clone()), &cursor, || {
                Err(io::Error::other("I/O priority admission failed"))
            });
            assert!(message.contains("I/O priority admission failed"));
            assert_eq!(*cursor.lock().unwrap(), previous);
            execute_and_resume(&selected, None, &cursor, || {
                Ok(execution_report(&selected, &[]))
            });
            assert_eq!(*cursor.lock().unwrap(), previous);
        }
    }

    #[test]
    fn preview_and_unsupported_reports_never_consume_daemon_work() {
        let selected = paths();
        let previous = Some(PathBuf::from("/cache/0.bin"));
        for (supported, dry_run) in [(false, false), (true, true)] {
            let cursor = Mutex::new(previous.clone());
            execute_and_resume(&selected, None, &cursor, || {
                let mut report = execution_report(&selected, &["eligible", "eligible", "eligible"]);
                report.supported = supported;
                report.dry_run = dry_run;
                Ok(report)
            });
            assert_eq!(*cursor.lock().unwrap(), previous);
        }
    }

    #[test]
    fn malformed_or_nonprefix_execution_reports_cannot_advance_continuation() {
        let selected = paths();
        let previous = Some(PathBuf::from("/cache/0.bin"));
        for case in 0..5 {
            let cursor = Mutex::new(previous.clone());
            let message = execute_and_resume(&selected, Some(selected[2].clone()), &cursor, || {
                let mut report = execution_report(&selected, &["skipped", "failed"]);
                match case {
                    0 => report.unvisited_files = usize::MAX,
                    1 => report.unvisited_files = 0,
                    2 => report.files.swap(0, 1),
                    3 => report.files[1].path = selected[0].clone(),
                    _ => report.files[0].path = PathBuf::from("/other/replaced.bin"),
                }
                Ok(report)
            });
            assert!(
                message.contains("continuation retained"),
                "case {case}: {message}"
            );
            assert_eq!(*cursor.lock().unwrap(), previous);
        }
    }

    #[test]
    fn consecutive_partial_passes_reach_every_unvisited_file_before_wrapping() {
        let selected = paths();
        let cursor = Mutex::new(None);
        let mut visited = Vec::new();
        for expected in &selected {
            let after = cursor.lock().unwrap().clone();
            let remaining: Vec<_> = selected
                .iter()
                .filter(|path| after.as_ref().is_none_or(|after| *path > after))
                .cloned()
                .collect();
            assert_eq!(remaining.first(), Some(expected));
            execute_and_resume(&remaining, None, &cursor, || {
                visited.push(remaining[0].clone());
                Ok(execution_report(&remaining, &["skipped"]))
            });
        }
        assert_eq!(visited, selected);
        assert_eq!(*cursor.lock().unwrap(), None);
    }

    #[cfg(unix)]
    #[test]
    fn native_byte_paths_are_not_reconstructed_from_display_reports() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        let selected = vec![
            PathBuf::from(OsString::from_vec(b"/cache/a-\xff.bin".to_vec())),
            PathBuf::from("/cache/b.bin"),
        ];
        let cursor = Mutex::new(None);
        execute_and_resume(&selected, None, &cursor, || {
            Ok(execution_report(&selected, &["skipped"]))
        });
        assert_eq!(*cursor.lock().unwrap(), Some(selected[0].clone()));
        let cursor = Mutex::new(None);
        let message = execute_and_resume(&selected, None, &cursor, || {
            let mut report = execution_report(&selected, &["skipped"]);
            report.files[0].path = PathBuf::from(selected[0].to_string_lossy().into_owned());
            Ok(report)
        });
        assert!(message.contains("continuation retained"));
        assert_eq!(*cursor.lock().unwrap(), None);
    }

    #[test]
    fn running_cooling_and_invalid_schedules_do_not_issue_root_io() {
        use crate::core::errors::Result;
        use crate::logger::dual::{DualLoggerConfig, spawn_logger};
        use crate::logger::jsonl::JsonlConfig;
        use crate::platform::pal::{
            FsStats, MemoryInfo, MountPoint, PlatformPaths, ServiceManager,
        };
        use std::path::Path;

        struct NoQueries;
        impl Platform for NoQueries {
            fn fs_stats(&self, _: &Path) -> Result<FsStats> {
                panic!("root I/O before due time")
            }
            fn mount_points(&self) -> Result<Vec<MountPoint>> {
                panic!("unexpected mount query")
            }
            fn is_ram_backed(&self, _: &Path) -> Result<bool> {
                panic!("unexpected RAM query")
            }
            fn default_paths(&self) -> PlatformPaths {
                PlatformPaths::default()
            }
            fn memory_info(&self) -> Result<MemoryInfo> {
                panic!("unexpected memory query")
            }
            fn service_manager(&self) -> Box<dyn ServiceManager> {
                panic!("unexpected service query")
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let (logger, join) = spawn_logger(DualLoggerConfig {
            sqlite_path: None,
            jsonl_config: JsonlConfig {
                path: dir.path().join("activity.jsonl"),
                fallback_path: None,
                max_size_bytes: 1024 * 1024,
                max_rotated_files: 1,
                fsync_interval_secs: 60,
            },
            channel_capacity: 8,
            run_id: None,
        })
        .unwrap();
        let platform: Arc<dyn Platform> = Arc::new(NoQueries);
        let now = Instant::now();
        for (running, last_start, start_level) in [
            (true, None, "yellow"),
            (false, Some(now), "yellow"),
            (false, None, "invalid"),
        ] {
            let config = Config {
                compress: CompressConfig {
                    start_level: start_level.into(),
                    ..enabled()
                },
                ..Config::default()
            };
            let mut tier = CompressTier {
                running: Arc::new(AtomicBool::new(running)),
                last_start,
                ..CompressTier::default()
            };
            tier.tick(now, &config, &platform, &HashMap::new(), &logger);
            assert_eq!(tier.last_start, last_start);
            assert_eq!(tier.running.load(Ordering::Acquire), running);
            assert_eq!(*tier.resume_after.lock().unwrap(), None);
        }
        logger.shutdown();
        join.join().unwrap();
    }

    fn enabled() -> CompressConfig {
        CompressConfig {
            enabled: true,
            roots: vec![PathBuf::from("/data/tmp"), PathBuf::from("/srv/ext4")],
            allow_zstd_feature: true,
            ..CompressConfig::default()
        }
    }

    fn volume(
        mount: &str,
        fs_type: &str,
        total_gib: u64,
        available_gib: u64,
    ) -> crate::platform::pal::FsStats {
        crate::platform::pal::FsStats {
            total_bytes: total_gib << 30,
            free_bytes: available_gib << 30,
            available_bytes: available_gib << 30,
            fs_type: fs_type.into(),
            mount_point: PathBuf::from(mount),
            is_readonly: false,
        }
    }

    fn mounted_platform(
        stats: Vec<crate::platform::pal::FsStats>,
    ) -> crate::platform::pal::MockPlatform {
        use crate::platform::pal::{MockPlatform, MountPoint, PlatformPaths};

        let mounts = stats
            .iter()
            .map(|stats| MountPoint {
                path: stats.mount_point.clone(),
                device: stats.mount_point.display().to_string(),
                fs_type: stats.fs_type.clone(),
                is_ram_backed: false,
            })
            .collect();
        MockPlatform::new(
            mounts,
            stats
                .into_iter()
                .map(|stats| (stats.mount_point.clone(), stats))
                .collect(),
            MockPlatform::healthy().memory_info().unwrap(),
            PlatformPaths::default(),
        )
    }

    #[test]
    fn compression_only_volumes_use_their_own_pressure_without_scanner_controllers() {
        let platform = mounted_platform(vec![
            volume("/archive", "btrfs", 1000, 120),
            volume("/healthy", "btrfs", 1000, 500),
            volume("/unsupported", "ext4", 1000, 0),
        ]);
        let config = CompressConfig {
            roots: [
                "/archive/first",
                "/archive/second",
                "/healthy/scratch",
                "/unsupported/scratch",
                "/missing/scratch",
            ]
            .into_iter()
            .map(PathBuf::from)
            .collect(),
            ..enabled()
        };
        // A healthy scanned root must not hide the independently configured
        // archive's pressure, and a critical root must not make healthy
        // compression volumes eligible either.
        for scanned_level in [PressureLevel::Green, PressureLevel::Critical] {
            let levels = HashMap::from([(PathBuf::from("/"), scanned_level)]);
            let statuses = root_statuses(
                &config.roots,
                &platform,
                &levels,
                &PressureConfig::default(),
            );
            assert_eq!(statuses[0].level, Some(PressureLevel::Orange));
            assert_eq!(statuses[2].level, Some(PressureLevel::Green));
            assert!(!statuses[3].btrfs);
            assert_eq!(statuses[4].level, None);
            assert_eq!(
                due_roots(&config, &statuses, false, None, Instant::now()),
                vec![
                    PathBuf::from("/archive/first"),
                    PathBuf::from("/archive/second")
                ]
            );
        }
    }

    #[test]
    fn monitored_volumes_keep_the_controller_level_instead_of_raw_reclassification() {
        let roots = vec![PathBuf::from("/archive/scratch")];
        for (available_gib, level) in [(500, PressureLevel::Red), (1, PressureLevel::Green)] {
            let platform = mounted_platform(vec![volume("/archive", "btrfs", 1000, available_gib)]);
            let statuses = root_statuses(
                &roots,
                &platform,
                &HashMap::from([(PathBuf::from("/archive"), level)]),
                &PressureConfig::default(),
            );
            assert_eq!(statuses[0].level, Some(level));
            assert_eq!(
                due_roots(&enabled(), &statuses, false, None, Instant::now()).is_empty(),
                level == PressureLevel::Green,
                "preserve controller hysteresis and prediction"
            );
        }
    }

    #[test]
    fn compression_only_pressure_honors_configured_percentages_and_absolute_floors() {
        let roots = vec![PathBuf::from("/archive/scratch")];
        let platform = mounted_platform(vec![volume("/archive", "btrfs", 2000, 160)]);
        let levels = HashMap::new();
        let statuses = root_statuses(&roots, &platform, &levels, &PressureConfig::default());
        assert_eq!(statuses[0].level, Some(PressureLevel::Red));

        let floors = PressureConfig {
            green_min_free_bytes: 100 << 30,
            yellow_min_free_bytes: 80 << 30,
            orange_min_free_bytes: 60 << 30,
            red_min_free_bytes: 40 << 30,
            ..PressureConfig::default()
        };
        let statuses = root_statuses(&roots, &platform, &levels, &floors);
        assert_eq!(statuses[0].level, Some(PressureLevel::Green));
        assert!(due_roots(&enabled(), &statuses, false, None, Instant::now()).is_empty());

        let percentages = PressureConfig {
            green_min_free_pct: 10.0,
            yellow_min_free_pct: 7.0,
            orange_min_free_pct: 4.0,
            red_min_free_pct: 1.0,
            ..PressureConfig::default()
        };
        let statuses = root_statuses(&roots, &platform, &levels, &percentages);
        assert_eq!(statuses[0].level, Some(PressureLevel::Yellow));
        assert_eq!(
            due_roots(&enabled(), &statuses, false, None, Instant::now()),
            roots
        );
    }

    #[test]
    fn readonly_unknown_capacity_and_failed_samples_never_admit_compression() {
        let mut readonly = volume("/readonly", "btrfs", 1000, 0);
        readonly.is_readonly = true;
        let platform = mounted_platform(vec![readonly, volume("/unknown", "btrfs", 0, 0)]);
        let config = CompressConfig {
            roots: ["/readonly/scratch", "/unknown/scratch", "/missing/scratch"]
                .into_iter()
                .map(PathBuf::from)
                .collect(),
            start_level: "green".into(),
            ..enabled()
        };
        let levels = HashMap::from([
            (PathBuf::from("/readonly"), PressureLevel::Critical),
            (PathBuf::from("/unknown"), PressureLevel::Critical),
        ]);
        let statuses = root_statuses(
            &config.roots,
            &platform,
            &levels,
            &PressureConfig::default(),
        );
        assert!(statuses.iter().all(|status| status.level.is_none()));
        assert!(due_roots(&config, &statuses, false, None, Instant::now()).is_empty());
    }

    fn status(root: &str, btrfs: bool, level: Option<PressureLevel>) -> RootStatus {
        RootStatus {
            root: PathBuf::from(root),
            btrfs,
            level,
            mount_point: Some(PathBuf::from(root)),
            device_id: Some(1),
        }
    }

    #[test]
    fn a_pass_is_due_only_for_btrfs_roots_at_or_above_the_start_level() {
        let now = Instant::now();
        let roots = [
            status("/data/tmp", true, Some(PressureLevel::Yellow)),
            status("/srv/ext4", false, Some(PressureLevel::Critical)),
            status("/data/cold", true, Some(PressureLevel::Green)),
            status("/data/unmonitored", true, None),
        ];
        assert_eq!(
            due_roots(&enabled(), &roots, false, None, now),
            vec![PathBuf::from("/data/tmp")],
            "only the btrfs root whose mount is at yellow or above"
        );
        let orange = CompressConfig {
            start_level: "orange".to_string(),
            ..enabled()
        };
        assert!(due_roots(&orange, &roots, false, None, now).is_empty());
    }

    #[test]
    fn no_pass_when_disabled_running_or_inside_the_interval() {
        let now = Instant::now();
        let roots = [status("/data/tmp", true, Some(PressureLevel::Red))];
        let off = CompressConfig {
            enabled: false,
            ..enabled()
        };
        assert!(due_roots(&off, &roots, false, None, now).is_empty());
        assert!(due_roots(&enabled(), &roots, true, None, now).is_empty());

        let interval = Duration::from_mins(30);
        let earlier = now
            .checked_sub(interval.checked_sub(Duration::from_secs(1)).unwrap())
            .unwrap();
        assert!(due_roots(&enabled(), &roots, false, Some(earlier), now).is_empty());
        let long_ago = now.checked_sub(interval).unwrap();
        assert_eq!(
            due_roots(&enabled(), &roots, false, Some(long_ago), now),
            vec![PathBuf::from("/data/tmp")]
        );
    }

    #[test]
    fn an_unknown_start_level_never_starts_a_pass() {
        let config = CompressConfig {
            start_level: "amber".to_string(),
            ..enabled()
        };
        let roots = [status("/data/tmp", true, Some(PressureLevel::Critical))];
        assert!(due_roots(&config, &roots, false, None, Instant::now()).is_empty());
    }

    #[test]
    fn a_stop_reaches_only_a_running_pass() {
        let tier = CompressTier::default();
        tier.stop_running_pass();
        assert!(
            !tier.stop.load(Ordering::Acquire),
            "nothing running, nothing to stop"
        );
        tier.running.store(true, Ordering::Release);
        tier.stop_running_pass();
        assert!(tier.stop.load(Ordering::Acquire));
        // Repeated ticks outside the policy keep it raised (and log once).
        tier.stop_running_pass();
        assert!(tier.stop.load(Ordering::Acquire));
    }

    #[test]
    fn a_disabled_tier_does_no_work_and_starts_no_thread() {
        use crate::logger::dual::{DualLoggerConfig, spawn_logger};
        use crate::logger::jsonl::JsonlConfig;
        use crate::platform::pal::MockPlatform;

        let dir = tempfile::tempdir().unwrap();
        let (logger, join) = spawn_logger(DualLoggerConfig {
            sqlite_path: None,
            jsonl_config: JsonlConfig {
                path: dir.path().join("activity.jsonl"),
                fallback_path: None,
                max_size_bytes: 1024 * 1024,
                max_rotated_files: 1,
                fsync_interval_secs: 60,
            },
            channel_capacity: 8,
            run_id: None,
        })
        .unwrap();
        let platform: Arc<dyn Platform> = Arc::new(MockPlatform::healthy());
        let mut tier = CompressTier::default();
        tier.tick(
            Instant::now(),
            &Config::default(),
            &platform,
            &HashMap::from([(PathBuf::from("/"), PressureLevel::Critical)]),
            &logger,
        );
        assert!(tier.last_start.is_none());
        assert!(!tier.running.load(Ordering::Acquire));
        logger.shutdown();
        join.join().unwrap();
    }
}
