//! Main monitoring loop: tiered polling, channel-based shutdown, thread orchestration.
//!
//! Architecture: single process with 4 threads communicating via bounded crossbeam channels:
//! - **Monitor thread** (main): polls filesystem stats, updates EWMA, runs PID controller
//! - **Scanner thread**: walks directories, scores candidates (triggered by monitor)
//! - **Executor thread**: deletes candidates from the ranked queue
//! - **Logger thread**: writes to SQLite + JSONL (via dual.rs)
//!
//! Thread panic recovery: if any worker thread panics, the monitor thread detects it
//! and respawns it (up to 3 times in 5 minutes). The monitor thread itself is the
//! "last line of defense" — if it panics, systemd's WatchdogSec restarts the process.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crossbeam_channel::{
    Receiver, RecvTimeoutError, SendTimeoutError, Sender, TryRecvError, TrySendError, bounded,
};
use parking_lot::{Mutex, RwLock};
use serde_json::{Value, json};

use crate::ballast::coordinator::BallastPoolCoordinator;
use crate::ballast::release::BallastReleaseController;
use crate::core::config::{Config, ScannerConfig, ScannerEngineMode};
use crate::core::errors::{Result, SbhError};
use crate::daemon::compress_tier::{CompressTier, CompressionFirst};
use crate::daemon::control::{
    BallastAction as ControlBallastAction, ControlBackend, ControlCommand, ControlResponse,
    ControlServer, Peer, PolicyAction, persist_policy_mode,
};
use crate::daemon::cpu_budget::{CpuBudget, MAX_TICK_YIELD, PassCpuGuard, paced_pct};
use crate::daemon::mount_controller::{
    IdleReason, MountController, MountControllerConfig, MountState, MountStateRecord, MountSurface,
    MountTickInput, ReserveBurst, ReserveState, WakeSignals, global_tick,
};
use crate::daemon::notifications::{NotificationEvent, NotificationLevel, NotificationManager};
use crate::daemon::policy::{
    ActiveMode, BallastAction, BehaviorDispatchTable, BehaviorMode, BehaviorPressureLevel,
    CleanupAction, NotificationPriority, PolicyEngine, ScanAggressiveness,
};
use crate::daemon::process_io_history::ProcessIoHistory;
use crate::daemon::self_monitor::{
    DaemonLock, LoggingState, MountPressure, MountRateState, PolicyStateRecord, SelfMonitor,
    SelfMonitorTick, ThreadHeartbeat, ThreadState, ThreadStatus, ThreadsState,
    assess_logging_placement, nearest_existing_ancestor,
};
use crate::daemon::signals::{SignalHandler, WatchdogHeartbeat, resolve_watchdog_sec};
use crate::daemon::target_tier::TargetTier;
use crate::logger::dual::{
    ActivityEvent, ActivityLoggerHandle, DualLoggerConfig, ScanCompletionTelemetry, spawn_logger,
};
use crate::logger::jsonl::JsonlConfig;
use crate::monitor::burst::BurstStats;
use crate::monitor::conformal::{ConformalCalibrator, ConformalConfig, TteInterval};
use crate::monitor::ewma::{DiskRateEstimator, RateEstimate};
use crate::monitor::fs_stats::FsStatsCollector;
use crate::monitor::guardrails::ForecastSnapshot;
use crate::monitor::guardrails::{
    AdaptiveGuard, CalibrationObservation, DeletionFailureMonitor, GuardDiagnostics, GuardStatus,
    PredictionScorecard,
};
use crate::monitor::pid::{
    PidConfig, PidPressureController, PressureLevel, PressureReading, PressureResponse,
};
use crate::monitor::predictive::{PredictiveAction, PredictiveActionPolicy};
use crate::monitor::special_locations::{
    AlertThrottle, HorizonRule, SpecialAlert, SpecialLocationRegistry,
};
use crate::monitor::voi_scheduler::VoiScheduler;
use crate::platform::cleanup_catalog::{self, ExpandedCatalogRoot};
use crate::platform::pal::{MemoryInfo, Platform, detect_platform};
use crate::platform::types::{
    FullDiskAccessState, FullDiskAccessStatus, MemoryPressure, MemoryPressureLevel,
};
use crate::scanner::deletion::{
    DeletionConfig, DeletionExecutor, DeletionMode, FreedBasis, SkipReason,
};
use crate::scanner::engine::{ScannerEngine, SelectedScannerEngine};
use crate::scanner::events::{
    EventInvalidation, EventSourceConfig, EventSourceStats, ScannerEventSource,
};
use crate::scanner::index::{
    CandidateIndexRecord, IndexedIdentity, ScannerCandidateIndex, ScannerIndexContext,
    ScannerIndexLoadStatus,
};
use crate::scanner::patterns::{
    ArtifactCategory, ArtifactClassification, ArtifactPatternRegistry, OpaqueTreeDisposition,
    StructuralSignals,
};
use crate::scanner::planner::{PlanRequest, RiskBudgetByLevel, plan_batch};
use crate::scanner::prescan_cursor::PrescanCursor;
use crate::scanner::protection::{self, ProtectionRegistry};
use crate::scanner::quarantine::{QuarantineStore, SweepMode as QuarantineSweepMode};
use crate::scanner::regret::{
    EntryIdentity, Outcome, RegretCalibrator, RegretConfig, RegretDetector, Watch,
    certainty_from_name,
};
use crate::scanner::scoring::{
    ActiveReferenceSummary, ArtifactCertainty, CandidacyScore, ScoringEngine,
};
use crate::scanner::walker::{
    ActiveReferenceIndex, ActiveReferenceScanConfig, DirectoryWalker, WalkEntry, WalkStream,
    WalkerConfig, collect_active_reference_index_cached, collect_open_path_ancestors_cached,
};

// ──────────────────── channel capacities ────────────────────

/// Monitor → Scanner: bounded(2), one buffered request while the scanner
/// processes another.
///
/// Under urgent pressure we replace one stale queued request with the latest
/// signal so high-priority actions are not starved.
pub const SCANNER_CHANNEL_CAP: usize = 2;
/// Scanner → Executor: bounded(64). Natural backpressure — scanner blocks on send.
pub const EXECUTOR_CHANNEL_CAP: usize = 64;
/// Candidate count threshold for dispatching a deletion batch before walk completion.
const EARLY_DISPATCH_MULTIPLIER: usize = 4;
/// Max time to wait before dispatching first non-empty deletion batch during a scan.
const EARLY_DISPATCH_MAX_WAIT: Duration = Duration::from_secs(10);

/// Maximum entries to process in a single scan pass.
/// Prevents the scanner from taking hours on massive directory trees (e.g. 500GB+
/// of nested cargo targets). When the budget is reached, whatever candidates have
/// been found so far are sent to the executor. The next scan request will continue.
const SCAN_ENTRY_BUDGET: usize = 500_000;
const V2_PRESSURE_RECLAIM_BYTES_PER_CANDIDATE: u64 = 256 * 1_048_576;

/// Maximum wall-clock time for a single scan pass (seconds).
/// After this deadline, the scanner processes accumulated candidates and returns.
/// This is the fallback when the config value is 0; the default config value (300s)
/// is preferred over this constant.
const SCAN_TIME_BUDGET_SECS: u64 = 300;

/// Ceiling on the pressure-extended scan budget (1 hour). A pass this long
/// only happens on a host whose tree genuinely takes that long to walk; the
/// CPU allowance still paces it.
const MAX_SCAN_TIME_BUDGET_SECS: u64 = 3600;
/// Cooldown between repeated swap-thrash warnings while pressure remains.
const SWAP_THRASH_WARNING_COOLDOWN: Duration = Duration::from_mins(15);
/// B5: minimum interval between "pressured device has no root_path" warnings.
const DEVICE_AFFINITY_WARN_INTERVAL: Duration = Duration::from_mins(15);
/// Minimum interval between growth-attribution reports (SBH-2007) per mount:
/// the probe walks up to `attribution::PROBE_BUDGET_ENTRIES` per directory.
const ATTRIBUTION_REPORT_INTERVAL: Duration = Duration::from_hours(1);
/// How long a mount must stay at Red or worse before it is attributed.
const ATTRIBUTION_SUSTAINED_PRESSURE: Duration = Duration::from_mins(10);
/// bd-ffjj: how often the RAM fallback's headroom is re-checked while the
/// logging mount stays pressured (the check reads the mount table).
const LOGGING_RAM_RECHECK: Duration = Duration::from_secs(30);
/// Swap usage threshold that indicates probable paging thrash.
const SWAP_THRASH_USED_PCT_THRESHOLD: f64 = 70.0;
/// Minimum free RAM for high swap use to indicate thrash (anomalous paging
/// despite ample memory). Per README: "at least 8 GiB of RAM remains free".
const SWAP_THRASH_MIN_AVAILABLE_RAM_BYTES: u64 = 8 * 1024 * 1024 * 1024;
/// Even under high pressure, avoid deleting extremely fresh temp artifacts.
const TEMP_FAST_TRACK_MIN_OBSERVED_AGE: Duration = Duration::from_mins(2);
/// Recheck macOS Full Disk Access grants without adding pressure-loop noise.
const FULL_DISK_ACCESS_RECHECK_INTERVAL: Duration = Duration::from_mins(5);
/// Memory pressure callbacks wake the monitor loop instead of waiting for the
/// next disk-pressure poll.
pub const MEMORY_PRESSURE_CHANNEL_CAP: usize = 16;
/// Maximum time the monitor loop may wait between memory-pressure event checks.
const MEMORY_PRESSURE_WAKE_INTERVAL: Duration = Duration::from_millis(500);
/// Per-tick daemon work budget before the self-throttle treats ticks as expensive.
const TICK_THROTTLE_SLOW_TICK_THRESHOLD: Duration = Duration::from_millis(200);
/// Consecutive expensive ticks before backing off from the PID interval.
const TICK_THROTTLE_SUSTAINED_TICKS: u8 = 3;
/// Consecutive expensive ticks before escalating to the maximum backoff.
const TICK_THROTTLE_ESCALATE_TICKS: u8 = TICK_THROTTLE_SUSTAINED_TICKS * 2;
/// First self-throttle interval under sustained daemon resource pressure.
const TICK_THROTTLE_FIRST_BACKOFF: Duration = Duration::from_secs(30);
/// Maximum self-throttle interval under sustained daemon resource pressure.
const TICK_THROTTLE_MAX_BACKOFF: Duration = Duration::from_mins(1);
/// Worker shutdown poll interval. Workers use timeouts instead of indefinite
/// channel receives so SIGTERM can stop the daemon even while senders are alive.
const WORKER_SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Maximum time to wait for an individual worker thread during shutdown.
/// Total time `shutdown()` spends joining the scanner and executor, shared
/// between them: five seconds under the systemd unit's `TimeoutStopSec=30`
/// so the final state write and the logger flush still happen before the
/// service manager would SIGKILL the process.
const WORKER_SHUTDOWN_JOIN_BUDGET: Duration = Duration::from_secs(25);

/// A worker whose heartbeat is older than this is reported as stalled in
/// `state.json` and `sbh status`.
///
/// Distinct from the health-check cadence: a scan pass or a large deletion
/// may legitimately run for tens of seconds between beats.
pub const THREAD_STALL_THRESHOLD: Duration = Duration::from_secs(60);

/// Entries walked between scanner heartbeats inside a pass.
const SCANNER_BEAT_EVERY_ENTRIES: usize = 256;

// ──────────────────── shared executor config ────────────────────

/// Config shared between main thread and executor via atomics.
/// Updated by config reload, read by executor at batch start.
struct SharedExecutorConfig {
    dry_run: AtomicBool,
    max_batch_size: AtomicUsize,
    /// f64 stored as u64 bits (to_bits/from_bits).
    min_score_bits: AtomicU64,
    repeat_base_cooldown_secs: AtomicU64,
    repeat_max_cooldown_secs: AtomicU64,
    /// Minimum [`ArtifactCertainty`] rank the current behavior cell dispatches
    /// (set from the cleanup action on every behavior transition).
    min_certainty_rank: AtomicU8,
    /// Layer 7: Green batches quarantine instead of removing.
    quarantine_enabled: AtomicBool,
    quarantine_ttl_secs: AtomicU64,
    /// bd-8aeq: batches that actually removed something; see
    /// [`Self::reclaim_events`].
    reclaim_events: AtomicU64,
    /// W1 planner: the risk budget table and one false-positive loss.
    planner: RwLock<(RiskBudgetByLevel, f64)>,
    /// A live, bounded first chance for lossless reclaim on a pressured mount.
    compression_first: Arc<CompressionFirst>,
}

impl SharedExecutorConfig {
    fn new(
        dry_run: bool,
        max_batch_size: usize,
        min_score: f64,
        repeat_base_cooldown: u64,
        repeat_max_cooldown: u64,
        quarantine_enabled: bool,
        quarantine_ttl_secs: u64,
    ) -> Self {
        Self {
            dry_run: AtomicBool::new(dry_run),
            max_batch_size: AtomicUsize::new(max_batch_size),
            min_score_bits: AtomicU64::new(min_score.to_bits()),
            repeat_base_cooldown_secs: AtomicU64::new(repeat_base_cooldown),
            repeat_max_cooldown_secs: AtomicU64::new(repeat_max_cooldown),
            min_certainty_rank: AtomicU8::new(ArtifactCertainty::Unclear.rank()),
            quarantine_enabled: AtomicBool::new(quarantine_enabled),
            quarantine_ttl_secs: AtomicU64::new(quarantine_ttl_secs),
            reclaim_events: AtomicU64::new(0),
            planner: RwLock::new((RiskBudgetByLevel::default(), 50.0)),
            compression_first: Arc::new(CompressionFirst::default()),
        }
    }

    /// Set the planner's risk budget table and loss unit (config load and
    /// reload).
    fn set_planner(&self, table: RiskBudgetByLevel, false_positive_loss: f64) {
        *self.planner.write() = (table, false_positive_loss);
    }

    fn min_certainty(&self) -> ArtifactCertainty {
        ArtifactCertainty::from_rank(self.min_certainty_rank.load(Ordering::Relaxed))
    }

    /// Number of executor batches that removed at least one item for real
    /// (not dry-run). The scanner compares it across passes: a pass whose
    /// dispatches moved this counter made progress, one whose dispatches did
    /// not (dry-run, observe mode, every candidate dampened or failed) is
    /// paced like an empty pass.
    fn reclaim_events(&self) -> u64 {
        self.reclaim_events.load(Ordering::Relaxed)
    }

    fn note_reclaim(&self) {
        self.reclaim_events.fetch_add(1, Ordering::Relaxed);
    }

    fn set_min_certainty(&self, certainty: ArtifactCertainty) {
        self.min_certainty_rank
            .store(certainty.rank(), Ordering::Relaxed);
    }

    fn min_score(&self) -> f64 {
        f64::from_bits(self.min_score_bits.load(Ordering::Relaxed))
    }

    fn set_min_score(&self, val: f64) {
        self.min_score_bits.store(val.to_bits(), Ordering::Relaxed);
    }

    fn authorize_mutation(
        &self,
        approved_mode: ActiveMode,
        current_mode: ActiveMode,
    ) -> std::result::Result<(), SkipReason> {
        if self.dry_run.load(Ordering::Relaxed)
            || !current_mode.allows_deletion()
            // An Enforce-approved batch has not passed Canary's quota.
            // Leave it for fresh policy evaluation after this restriction.
            || (approved_mode == ActiveMode::Enforce && current_mode == ActiveMode::Canary)
        {
            return Err(SkipReason::PolicyChanged);
        }
        Ok(())
    }

    fn authorize_compression_first(
        &self,
        candidate: &CandidacyScore,
        level: PressureLevel,
    ) -> std::result::Result<(), SkipReason> {
        let identity = candidate
            .identity
            .or_else(|| crate::scanner::walker::identity_for_path(&candidate.path, false).ok());
        if identity.is_some_and(|identity| {
            self.compression_first
                .defers_device(identity.device_id, level, Instant::now())
        }) {
            Err(SkipReason::CompressionFirst)
        } else {
            Ok(())
        }
    }

    fn repeat_base_cooldown_secs(&self) -> u64 {
        self.repeat_base_cooldown_secs.load(Ordering::Relaxed)
    }

    fn repeat_max_cooldown_secs(&self) -> u64 {
        self.repeat_max_cooldown_secs.load(Ordering::Relaxed)
    }
}

// ──────────────────── regret labels (Q4) ────────────────────

/// The regret detector the executor feeds and the tick resolves, and the
/// calibrator whose per-category view the scanner applies before scoring.
struct SharedRegret {
    detector: Mutex<RegretDetector>,
    calibrator: Mutex<RegretCalibrator>,
}

impl SharedRegret {
    fn new(config: &Config) -> Self {
        let regret = regret_config(config);
        Self {
            detector: Mutex::new(RegretDetector::new(regret.window)),
            calibrator: Mutex::new(RegretCalibrator::new(regret)),
        }
    }

    /// Reconfigure both feedback components while retaining pending
    /// observation deadlines and the category evidence already collected.
    fn update_config(&self, config: &Config) {
        let regret = regret_config(config);
        let mut detector = self.detector.lock();
        let mut calibrator = self.calibrator.lock();
        detector.set_window(regret.window);
        calibrator.update_config(regret);
        // Publish the paired update before releasing either guard. Retain the
        // original reverse acquisition order while making the release explicit.
        drop((calibrator, detector));
    }

    /// The scoring engine's view: a calibration factor per category and
    /// the categories whose deletions are suspended right now.
    fn scoring_view(&self, now: Instant) -> (HashMap<String, f64>, HashSet<String>) {
        let calibrator = self.calibrator.lock();
        let suspended = calibrator
            .summaries()
            .into_iter()
            .filter(|summary| calibrator.suspended(&summary.category, now))
            .map(|summary| summary.category)
            .collect();
        (calibrator.calibrations(), suspended)
    }

    /// Recheck queued work at the execution boundary: its scoring snapshot
    /// may predate a category alarm raised during the scan or this batch.
    fn authorize_deletion(
        &self,
        candidate: &CandidacyScore,
        logger: &ActivityLoggerHandle,
    ) -> std::result::Result<(), SkipReason> {
        let category = format!("{:?}", candidate.classification.category);
        let suspended = {
            let calibrator = self.calibrator.lock();
            calibrator.suspended(&category, Instant::now())
        };
        if suspended {
            // Release the evidence lock before logging or filesystem work.
            logger.send(ActivityEvent::Info {
                message: format!(
                    "regret category {category} is suspended; skipped {}",
                    candidate.path.display()
                ),
            });
            Err(SkipReason::CategorySuspended)
        } else {
            Ok(())
        }
    }

    /// Begin observation at the unlink's completion, without moving the
    /// deadline if acquiring the detector lock takes time.
    fn watch_unlinked(
        &self,
        candidate: &CandidacyScore,
        identity: &EntryIdentity,
        completed_at: Instant,
    ) {
        let watch = Watch {
            decision_id: crate::scanner::decision_record::stable_decision_id(
                &candidate.path,
                candidate.identity,
                candidate.size_bytes,
            ),
            path: candidate.path.clone(),
            identity: identity.clone(),
            category: format!("{:?}", candidate.classification.category),
            certainty: candidate.decision.certainty,
            deleted_at: completed_at,
        };
        self.detector.lock().watch(watch);
    }
}

fn regret_config(config: &Config) -> RegretConfig {
    RegretConfig {
        window: Duration::from_secs(config.scoring.regret_window_minutes.saturating_mul(60)),
        alpha_definite: config.scoring.regret_alpha_definite,
        alpha_likely: config.scoring.regret_alpha_likely,
        suspend: Duration::from_secs(config.scoring.regret_suspend_minutes.saturating_mul(60)),
        ..RegretConfig::default()
    }
}

/// Rebuild the regret calibrator from the last 30 days of stored outcomes
/// (daemon start); suspensions are not replayed.
fn replay_regret_outcomes(regret: &SharedRegret, sqlite_db: &Path) {
    let Ok(db) = crate::logger::sqlite::SqliteLogger::open_read_only(sqlite_db) else {
        return;
    };
    let since = (chrono::Utc::now() - chrono::Duration::days(30))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let Ok(outcomes) = db.outcomes_since(&since) else {
        return;
    };
    let count = outcomes.len();
    regret.calibrator.lock().replay(
        outcomes.into_iter().filter_map(|stored| {
            Outcome::from_name(&stored.outcome).map(|outcome| {
                (
                    stored.category,
                    certainty_from_name(&stored.certainty),
                    outcome,
                )
            })
        }),
        Instant::now(),
    );
    if count > 0 {
        eprintln!("[SBH-REGRET] replayed {count} stored outcome(s) into the category calibrator");
    }
}

/// Whether a process has its working directory or an open file under
/// `parent`: the sign that something still used the deleted entry's
/// neighbourhood when it came back.
fn parent_in_use(platform: &dyn Platform, parent: &Path) -> bool {
    if platform
        .open_files_under(parent)
        .is_ok_and(|result| !result.files.is_empty())
    {
        return true;
    }
    // Runs on the monitor thread and needs only cwd: no argv reads, which
    // can block behind another process's memory-map lock.
    platform
        .process_list_without_command_lines()
        .is_ok_and(|processes| {
            processes.iter().any(|process| {
                process
                    .cwd
                    .as_deref()
                    .is_some_and(|cwd| cwd.starts_with(parent))
            })
        })
}

// ──────────────────── thread panic tracking ────────────────────

pub const MAX_RESPAWNS: u32 = 3;
pub const RESPAWN_WINDOW: Duration = Duration::from_mins(5);
pub const THREAD_HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(10);
/// How often a filling mount logs its `[SBH-FORECAST]` calibration line.
const FORECAST_LOG_INTERVAL: Duration = Duration::from_secs(60);
/// How often calm mounts have their quarantine expired and capped (Layer 7).
const QUARANTINE_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

struct ThreadHealth {
    panic_times: Vec<Instant>,
}

impl ThreadHealth {
    fn new() -> Self {
        Self {
            panic_times: Vec::new(),
        }
    }

    /// Record a panic. Returns false if the thread has exceeded the respawn limit.
    fn record_panic(&mut self) -> bool {
        let now = Instant::now();
        self.panic_times
            .retain(|t| now.duration_since(*t) < RESPAWN_WINDOW);
        self.panic_times.push(now);
        self.panic_times.len() <= MAX_RESPAWNS as usize
    }
}

// ──────────────────── daemon tick self-throttle ────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TickThrottleReason {
    RssWarning,
    SlowTick,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum TickThrottleStage {
    #[default]
    Normal,
    Backoff30s,
    Backoff60s,
}

impl TickThrottleStage {
    const fn interval(self) -> Option<Duration> {
        match self {
            Self::Normal => None,
            Self::Backoff30s => Some(TICK_THROTTLE_FIRST_BACKOFF),
            Self::Backoff60s => Some(TICK_THROTTLE_MAX_BACKOFF),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TickThrottleDecision {
    interval: Duration,
    stage: TickThrottleStage,
    reason: Option<TickThrottleReason>,
    stage_changed: bool,
}

#[derive(Debug, Default)]
struct AdaptiveTickThrottle {
    consecutive_pressure_ticks: u8,
    stage: TickThrottleStage,
}

impl AdaptiveTickThrottle {
    fn observe(
        &mut self,
        requested_interval: Duration,
        self_monitor_tick: SelfMonitorTick,
        tick_duration: Duration,
    ) -> TickThrottleDecision {
        let reason = if self_monitor_tick.rss_bytes > self_monitor_tick.rss_warning_bytes {
            Some(TickThrottleReason::RssWarning)
        } else if tick_duration > TICK_THROTTLE_SLOW_TICK_THRESHOLD {
            Some(TickThrottleReason::SlowTick)
        } else {
            None
        };

        let previous_stage = self.stage;
        if reason.is_some() {
            self.consecutive_pressure_ticks = self.consecutive_pressure_ticks.saturating_add(1);
            self.stage = if self.consecutive_pressure_ticks >= TICK_THROTTLE_ESCALATE_TICKS {
                TickThrottleStage::Backoff60s
            } else if self.consecutive_pressure_ticks >= TICK_THROTTLE_SUSTAINED_TICKS {
                TickThrottleStage::Backoff30s
            } else {
                TickThrottleStage::Normal
            };
        } else {
            self.consecutive_pressure_ticks = 0;
            self.stage = TickThrottleStage::Normal;
        }

        let interval = self.stage.interval().map_or(requested_interval, |minimum| {
            requested_interval.max(minimum)
        });

        TickThrottleDecision {
            interval,
            stage: self.stage,
            reason,
            stage_changed: self.stage != previous_stage,
        }
    }
}

// ──────────────────── inter-thread messages ────────────────────

/// Message from monitor to scanner: "scan these paths at this urgency level."
#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub paths: Vec<PathBuf>,
    pub urgency: f64,
    pub pressure_level: PressureLevel,
    /// Actual free percentage for the mount/root that triggered this scan.
    /// `None` is allowed for synthetic unit-test requests and degraded callers.
    pub free_pct: Option<f64>,
    pub max_delete_batch: usize,
    /// Explicit operator/service request that must reconcile the configured roots
    /// even when v2 has no dirty event roots under green/yellow pressure.
    pub force_full_scan: bool,
    /// When config is reloaded, this carries the updated scoring and scanner config.
    pub config_update: Option<(
        crate::core::config::ScoringConfig,
        crate::core::config::ScannerConfig,
    )>,
    /// Catalog-only scan (W1 catalog roots): each entry is one known-safe
    /// cache location on a pressured device without a configured root. The
    /// scanner treats every root as an opaque candidate unit (bounded probe,
    /// no descent) instead of walking `paths`. Empty for ordinary scans.
    pub catalog_roots: Vec<ExpandedCatalogRoot>,
    /// A Green maintenance pass (Q6): the scheduler chose `paths`, so the v2
    /// engine walks them even without dirty event roots.
    pub maintenance: bool,
    /// W1 planner: the bytes this pass should reclaim to bring the pressured
    /// mount back to Green; `None` while the mount is not pressured.
    pub target_bytes: Option<u64>,
}

/// How a long startup step keeps a `Type=notify` unit from timing out.
#[derive(Debug, Clone, Copy)]
struct StartupExtension {
    /// Each request makes the start timeout at least this far from now.
    extend_by: Duration,
    /// How often the request is repeated while the step runs.
    every: Duration,
    /// Stop asking after this long, so a step that hangs still lets the
    /// service manager's timeout fail the start.
    max: Duration,
}

impl StartupExtension {
    const DEFAULT: Self = Self {
        extend_by: Duration::from_secs(30),
        every: Duration::from_secs(10),
        max: Duration::from_mins(15),
    };
}

/// Run `work` while repeatedly asking the service manager for more startup
/// time; the requests stop when `work` returns, after `extension.max`, or
/// once `stop` is set. systemd applies `EXTEND_TIMEOUT_USEC` to whichever
/// timeout is running, so extending after a stop request would also hold off
/// the stop timeout: a `systemctl stop` during provisioning waited minutes.
fn with_startup_extension<T>(
    service_manager: Box<dyn crate::platform::pal::ServiceManager>,
    status: &str,
    extension: StartupExtension,
    stop: &AtomicBool,
    work: impl FnOnce() -> T,
) -> T {
    let (done_tx, done_rx) = bounded::<()>(0);
    thread::scope(|scope| {
        scope.spawn(move || {
            let started = Instant::now();
            while started.elapsed() < extension.max && !stop.load(Ordering::Relaxed) {
                let _ = service_manager.notify_extend_startup(extension.extend_by, status);
                if !matches!(
                    done_rx.recv_timeout(extension.every),
                    Err(RecvTimeoutError::Timeout)
                ) {
                    break;
                }
            }
        });
        let result = work();
        drop(done_tx);
        result
    })
}

/// B6: consecutive no-progress passes after which even Red/Critical pressure
/// stops bypassing the empty-pass cooldown ("terminal idle"). Re-walking a
/// tree whose every candidate is protected cannot free bytes no matter how
/// red the disk is; the observed failure mode (#15) was 1000+ consecutive
/// no-progress scans pegging a core for days at 97% disk because the Red
/// bypass made the cooldown unreachable. Special-location triggers (e.g. a
/// full `/dev/shm`) synthesize Red-level requests even when the root disk is
/// far below the pressure thresholds, so the same hot-loop could fire at 82%
/// disk. Three strikes is enough to prove the tree is barren while still
/// letting genuine emergencies get immediate rescans.
const TERMINAL_IDLE_EMPTY_PASSES: u32 = 3;

/// B6: cap on the empty-pass cooldown while pressure is Red/Critical and the
/// scanner is terminally idle. The exponential backoff may reach 32× the base
/// interval (48 min at the default 90s base) — acceptable when parked below
/// the thresholds, but under genuine Red pressure the daemon must still
/// re-check for newly-deletable files on a long-timer wake, not once an hour.
const TERMINAL_IDLE_PRESSURED_RESCAN_CAP: Duration = Duration::from_mins(5);

/// B6: decide whether to skip a scan pass because a recent pass found nothing
/// reclaimable and the rescan cooldown has not yet elapsed.
///
/// The cooldown is deliberately *narrow*: it only suppresses routine pressure-
/// driven re-scans. It is bypassed for
/// - operator/service forced scans (`force_full_scan`),
/// - config reloads (`config_update`), which must take effect immediately,
/// - maintenance passes (`maintenance`), paced by `maintenance_interval_secs`,
/// - synthetic requests (`free_pct` is `None`), used by tests/degraded callers,
/// - rising danger (Red/Critical pressure), where disk safety overrides pacing
///   — but only until [`TERMINAL_IDLE_EMPTY_PASSES`] consecutive no-progress
///   passes prove that re-scanning cannot help; from then on Red/Critical
///   waits too, on a cooldown capped at
///   [`TERMINAL_IDLE_PRESSURED_RESCAN_CAP`] so emergencies still get periodic
///   long-timer re-checks (#15).
///
/// A `cooldown` of zero (config `min_rescan_interval_secs == 0`) disables it.
#[must_use]
fn empty_pass_cooldown_active(
    last_empty_pass_at: Option<Instant>,
    now: Instant,
    cooldown: Duration,
    request: &ScanRequest,
    consecutive_empty_passes: u32,
) -> bool {
    if cooldown.is_zero() {
        return false;
    }
    if request.force_full_scan
        || request.config_update.is_some()
        || request.free_pct.is_none()
        || request.maintenance
    {
        return false;
    }
    let cooldown = if request.pressure_level >= PressureLevel::Red {
        if consecutive_empty_passes < TERMINAL_IDLE_EMPTY_PASSES {
            // Rising danger overrides pacing while a rescan can still
            // plausibly make progress.
            return false;
        }
        // Terminal idle: nothing was reclaimable for several passes in a row.
        // Keep pacing even under Red/Critical, but wake on a shorter timer
        // than the fully backed-off interval.
        cooldown.min(TERMINAL_IDLE_PRESSURED_RESCAN_CAP)
    } else {
        cooldown
    };
    last_empty_pass_at.is_some_and(|last| now.duration_since(last) < cooldown)
}

/// A pressure-driven request at a higher level than the last completed pass:
/// the disk is filling in a way the earlier, empty passes did not see, so the
/// pacing they built no longer applies. Maintenance passes carry no such
/// signal, and the first pass of a run has nothing to compare against.
#[must_use]
fn pressure_escalated(last_pass_level: Option<PressureLevel>, request: &ScanRequest) -> bool {
    !request.maintenance
        && last_pass_level.is_some_and(|previous| request.pressure_level > previous)
}

/// How long an empty pass at a level keeps a return to that level from
/// counting as an escalation. A host whose free space hovers at a threshold
/// crosses it every minute or two: each return to Red after an Orange event
/// pass looked like new information and cleared the backoff, so Red never
/// reached terminal idle and rescanned the same tree back-to-back (hz1 on
/// 2026-10-13: 365 resets and 816 passes in 6 h, 723 of them finding nothing).
/// The window equals the terminal-idle wake, so a flapping host is re-checked
/// as often as one that stays put.
const ESCALATION_HYSTERESIS: Duration = TERMINAL_IDLE_PRESSURED_RESCAN_CAP;

/// Remember the highest level a recent pass found nothing at. A lower-level
/// empty pass does not erase a higher one still inside the window; a pass at
/// the same or a higher level refreshes it.
fn note_empty_pass_level(
    peak: &mut Option<(PressureLevel, Instant)>,
    level: PressureLevel,
    now: Instant,
) {
    let keep = peak.is_some_and(|(peak_level, at)| {
        peak_level > level && now.saturating_duration_since(at) < ESCALATION_HYSTERESIS
    });
    if !keep {
        *peak = Some((level, now));
    }
}

/// Whether a pass at `level` or above came back empty within the hysteresis
/// window: a rise to `level` is then the threshold flapping, not new
/// information, and keeps the empty-pass streak.
fn rise_already_scanned_empty(
    peak: Option<(PressureLevel, Instant)>,
    level: PressureLevel,
    now: Instant,
) -> bool {
    peak.is_some_and(|(peak_level, at)| {
        peak_level >= level && now.saturating_duration_since(at) < ESCALATION_HYSTERESIS
    })
}

/// Absolute floor between pressure-driven scan passes when the duty-cycle
/// limiter is enabled.
///
/// The proportional rule alone (`T * (100-pct)/pct`) collapses to ~0 for a very
/// cheap pass, which would still let a fast-but-fruitless tree spin. A small
/// fixed floor keeps the loop from busy-waiting without hurting responsiveness.
const DUTY_CYCLE_MIN_PASS_GAP: Duration = Duration::from_secs(5);

/// Ceiling on the idle debt a single pass can accrue.
///
/// Without this, a pass that exhausts `scan_time_budget_secs` (default **900**)
/// would owe 45 minutes at the default 25% — long enough for a filling disk to
/// blow through Red before the scanner looks again. That would trade the
/// hot-loop for a worse failure, and it contradicts the principle already
/// encoded in [`TERMINAL_IDLE_PRESSURED_RESCAN_CAP`]: even while pacing, a
/// pressured host must still get a periodic re-check.
///
/// Trade-off, stated plainly: for a pass longer than
/// `cap * pct / (100 - pct)` the realised duty cycle exceeds `pct` (a 900s pass
/// capped at 300s runs at ~75%, not 25%). That is deliberate. A pass that long
/// means the scan budget is being exhausted every time, and there bounded
/// latency matters more than a strict CPU bound — 75% of a scan window still
/// beats the unbounded back-to-back re-walk this replaces.
const DUTY_CYCLE_MAX_DEBT: Duration = Duration::from_mins(5);

/// #15: minimum idle time owed after a scan pass, to bound scanner CPU.
///
/// `empty_pass_cooldown_active` only paces passes that reclaimed **nothing**.
/// The hot-loop that kept sbh disabled on most of the fleet is the *productive*
/// case: on a chronically-full host every pass frees a trickle (css measured 72
/// deletions / 1.55 GB per hour), so `consecutive_empty_passes` resets to 0 on
/// every pass, the Red/Critical bypass never expires, and the daemon re-walks
/// back-to-back forever at ~100% CPU.
///
/// Bounding the *duty cycle* fixes that without giving up reclaim: after a pass
/// lasting `T`, owe `T * (100 - pct) / pct` of idle, so at most `pct` of
/// wall-clock is spent scanning regardless of tree size, disk fullness or
/// pressure level. Because the debt is proportional, a cheap pass under genuine
/// Red pressure still comes back almost immediately; only expensive passes are
/// throttled, which is exactly the case that pins a core.
///
/// This bounds *scanning time*, not core count. The scan itself is parallel
/// (`scanner.parallelism`, default `cores/2`), so CPU during a scan window can
/// reach several cores and the process-wide share lands near
/// `pct * parallelism`, not `pct` of one core. Measured on a Red host: 156% →
/// 32% at the default, which is what that model predicts — the point is that
/// the share is now *bounded and tunable* instead of unbounded.
///
/// The result is clamped to [`DUTY_CYCLE_MIN_PASS_GAP`] (so a trivially fast
/// pass cannot busy-wait) and [`DUTY_CYCLE_MAX_DEBT`] (so a budget-exhausting
/// pass cannot stall reclaim on a filling disk).
///
/// `pct == 0` (or `>= 100`) disables the limiter.
#[must_use]
fn duty_cycle_idle_debt(last_pass_duration: Duration, pct: u8) -> Duration {
    if pct == 0 || pct >= 100 {
        return Duration::ZERO;
    }
    let owed = last_pass_duration
        .saturating_mul(u32::from(100 - pct))
        .checked_div(u32::from(pct))
        .unwrap_or(Duration::ZERO);
    owed.clamp(DUTY_CYCLE_MIN_PASS_GAP, DUTY_CYCLE_MAX_DEBT)
}

/// #15: decide whether to defer a pass because the scanner still owes idle time
/// from the previous pass.
///
/// Deliberately bypassed for the same requests as the empty-pass cooldown —
/// operator/forced scans, config reloads and synthetic requests — so an operator
/// can always force an immediate scan. Unlike that cooldown this is **not**
/// bypassed by Red/Critical pressure: pressure is precisely when the hot-loop
/// fires, and the proportional debt already keeps cheap passes responsive.
#[must_use]
fn duty_cycle_defer_active(
    last_pass_finished_at: Option<Instant>,
    last_pass_duration: Duration,
    now: Instant,
    request: &ScanRequest,
    pct: u8,
) -> bool {
    if request.force_full_scan || request.config_update.is_some() || request.free_pct.is_none() {
        return false;
    }
    let debt = duty_cycle_idle_debt(last_pass_duration, pct);
    if debt.is_zero() {
        return false;
    }
    last_pass_finished_at.is_some_and(|last| now.duration_since(last) < debt)
}

/// B6: exponential backoff for the empty-pass cooldown.
///
/// `min_rescan_interval_secs` is the *base* pause after a single no-progress
/// pass. When passes keep finding nothing reclaimable — the steady state on a
/// disk parked below the green threshold whose only candidates are all protected
/// (e.g. SQLite/`.git`/`.beads` test fixtures) — each consecutive empty pass
/// doubles the pause, capped at 32× the base. A perpetually-pressured-but-
/// nothing-to-reclaim disk thus decays from one scan per `base`s to one scan per
/// ~32×base instead of re-walking back-to-back and pinning a core. The counter
/// resets to the base interval on the first productive pass. Red/Critical
/// pressure bypasses the cooldown only until [`TERMINAL_IDLE_EMPTY_PASSES`]
/// consecutive no-progress passes; after that even Red/Critical waits, on a
/// cooldown capped at [`TERMINAL_IDLE_PRESSURED_RESCAN_CAP`] (handled in
/// `empty_pass_cooldown_active`, #15).
///
/// A base of `0` disables the cooldown (legacy behavior).
#[must_use]
fn effective_empty_pass_cooldown(base_secs: u64, consecutive_empty_passes: u32) -> Duration {
    if base_secs == 0 {
        return Duration::ZERO;
    }
    // consecutive==1 (first empty pass) → 1×; cap the shift at 5 → 32× max.
    let shift = consecutive_empty_passes.saturating_sub(1).min(5);
    let multiplier = 1u64 << shift; // 1, 2, 4, 8, 16, 32
    Duration::from_secs(base_secs.saturating_mul(multiplier))
}

/// bd-qxrh: fold a pass that dispatched nothing into the empty-pass streak.
///
/// One *timed-out* empty pass is inconclusive: its budget may have run out
/// before the walk reached anything reclaimable. A run of them is not. When
/// every pass is cut short (by `scan_time_budget_secs` or, more often, by the
/// daemon CPU bucket), counting none of them meant the streak never grew, so
/// Red/Critical never reached terminal idle and re-scanned as fast as the duty
/// cycle allowed, for hours, with nothing to reclaim (mac-mini-max on
/// 2026-10-12: a `red_pressure` pass every ~20 s, all `timed_out=true`,
/// 0 candidates, 0 bytes freed). Every [`TERMINAL_IDLE_EMPTY_PASSES`]
/// consecutive timed-out empty passes therefore count as one conclusive one.
fn record_empty_pass(
    consecutive_empty_passes: &mut u32,
    inconclusive_empty_passes: &mut u32,
    timed_out: bool,
) {
    if timed_out {
        *inconclusive_empty_passes = inconclusive_empty_passes.saturating_add(1);
        if *inconclusive_empty_passes < TERMINAL_IDLE_EMPTY_PASSES {
            return;
        }
    }
    *inconclusive_empty_passes = 0;
    *consecutive_empty_passes = consecutive_empty_passes.saturating_add(1);
}

/// A pass that dispatched candidates. Its dispatch is unconfirmed until the
/// next pass sees the executor's reclaim counter move, so it resets the
/// empty-pass streak only when the previous dispatch did reclaim something.
/// Resetting on every dispatch capped the streak at one (#36): a host whose
/// dispatches never reclaim (dry-run, observe, every candidate failing)
/// rescanned at the base interval forever instead of backing off toward
/// terminal idle.
fn record_dispatching_pass(
    previous_dispatch_reclaimed_nothing: bool,
    consecutive_empty_passes: &mut u32,
    inconclusive_empty_passes: &mut u32,
    last_empty_pass_at: &mut Option<Instant>,
) {
    if previous_dispatch_reclaimed_nothing {
        return;
    }
    *consecutive_empty_passes = 0;
    *inconclusive_empty_passes = 0;
    *last_empty_pass_at = None;
}

/// Process CPU (user+system) this process has consumed so far, in micros.
fn current_scan_cpu_micros() -> Option<u64> {
    let stats = crate::platform::current().self_stats().ok()?;
    Some(
        stats
            .cpu_user_micros
            .saturating_add(stats.cpu_system_micros),
    )
}

#[must_use]
fn scan_reason_for_request(request: &ScanRequest) -> &'static str {
    if !request.catalog_roots.is_empty() {
        return "catalog";
    }
    if request.maintenance {
        return "maintenance";
    }
    if request.force_full_scan {
        return "forced";
    }
    if request.config_update.is_some() {
        return "config_reload";
    }
    if request.free_pct.is_none() {
        return "synthetic";
    }

    match request.pressure_level {
        PressureLevel::Green => {
            if request.urgency > 0.0 {
                "green_scheduled"
            } else {
                "green_idle"
            }
        }
        PressureLevel::Yellow => "yellow_pressure",
        PressureLevel::Orange => "orange_pressure",
        PressureLevel::Red => "red_pressure",
        PressureLevel::Critical => "critical_pressure",
    }
}

/// Scored candidates ready for deletion.
#[derive(Debug, Clone)]
pub struct DeletionBatch {
    pub candidates: Vec<CandidacyScore>,
    pub pressure_level: PressureLevel,
    pub urgency: f64,
    /// W1 planner: the byte target of the pass that produced the batch.
    pub target_bytes: Option<u64>,
    /// Set by the target-only tier alone (bd-232u): the resolved
    /// `scanner.target_only_roots` root whose pure, idle cargo target dirs
    /// the batch holds. The executor drops any candidate that is not strictly
    /// inside it or carries no identity, and lifts only the `protected_paths`
    /// patterns that cover the root as a whole; patterns naming something
    /// inside it, `.sbh-protect` markers and every other check still apply.
    pub target_only_root: Option<PathBuf>,
}

/// Results reported from worker threads back to the main monitoring loop.
#[derive(Debug)]
struct RootScanResult {
    path: PathBuf,
    candidates_found: usize,
    potential_bytes: u64,
    false_positives: usize,
    duration: Duration,
    /// The v2 event source reported changes under this root before the
    /// pass (feeds the scheduler's hazard rate).
    dirty: bool,
}

#[derive(Debug)]
enum WorkerReport {
    /// Scanner completed a scan pass.
    ScanCompleted {
        candidates: usize,
        duration: Duration,
        root_stats: Vec<RootScanResult>,
        timed_out: bool,
        /// Pressure examined by this pass, before any newer monitor tick.
        pressure_level: PressureLevel,
        /// A Green maintenance walk or an event-scoped pass: run on the
        /// scanner's own schedule, not for any mount's pressure or prediction
        /// (bd-lihi). Its empty result cannot park a mount in Reclaim.
        background: bool,
    },
    /// Executor completed a deletion batch.
    DeletionCompleted {
        deleted: u64,
        /// What to report as freed; `freed_basis` says how it is known.
        /// Reporting only: no control decision reads it (bd-oj33).
        bytes_freed: u64,
        freed_basis: FreedBasis,
        /// The free space measured around the removals, when every one was.
        bytes_freed_observed: Option<u64>,
        failed: u64,
        /// Candidates whose filesystem answered EROFS or ENOSPC: their
        /// mounts need recovery, not another attempt.
        recovery_paths: Vec<PathBuf>,
        /// Set when the deletion-failure e-process crossed its alarm
        /// threshold on this batch: the dominant failure reason and count.
        failure_alarm: Option<(&'static str, u64)>,
    },
}

/// Commands the control socket cannot run on its own thread: they need the
/// main loop's state (the self monitor, the ballast coordinator).
pub const CONTROL_CHANNEL_CAP: usize = 16;

#[derive(Debug)]
enum MainLoopCommand {
    /// Break the tick sleep so a signal-flag request runs now.
    Wake,
    /// Write `state.json` on this tick and answer when it is on disk.
    WriteState(Sender<()>),
    /// Release or replenish ballast through the coordinator.
    Ballast {
        action: ControlBallastAction,
        reply: Sender<std::result::Result<Value, String>>,
    },
}

/// The daemon side of the control socket: signal-flag commands and ledger
/// lookups are answered on the connection thread, everything else goes to
/// the main loop through [`MainLoopCommand`].
struct DaemonControlBackend {
    signal_handler: SignalHandler,
    control_tx: Sender<MainLoopCommand>,
    logger: ActivityLoggerHandle,
    policy_engine: Arc<Mutex<PolicyEngine>>,
    state_file: PathBuf,
    sqlite_db: PathBuf,
    config_file: PathBuf,
    started_at: String,
    start_instant: Instant,
}

impl DaemonControlBackend {
    fn wake(&self) {
        let _ = self.control_tx.try_send(MainLoopCommand::Wake);
    }

    fn policy(&self, action: PolicyAction, peer: Option<Peer>) -> ControlResponse {
        let (before, after, changed) = {
            let mut engine = self.policy_engine.lock();
            let before = engine.mode();
            let changed = match action {
                PolicyAction::Status => false,
                PolicyAction::Promote => engine.promote(),
                PolicyAction::Demote => engine.demote(),
            };
            (before, engine.mode(), changed)
        };
        let mut result = json!({
            "action": action.as_str(),
            "mode": after.to_string(),
            "previous_mode": before.to_string(),
            "changed": changed,
        });
        if changed {
            match persist_policy_mode(&self.config_file, &after.to_string()) {
                Ok(backup) => {
                    result["config_file"] = json!(self.config_file);
                    result["backup"] = json!(backup);
                }
                Err(error) => {
                    result["persist_error"] = json!(error.to_string());
                }
            }
            self.logger.send(ActivityEvent::Info {
                message: format!(
                    "control socket: policy {} {before} -> {after} (uid {}, pid {}); persisted={}",
                    action.as_str(),
                    peer.map_or_else(|| "?".to_string(), |p| p.uid.to_string()),
                    peer.map_or_else(|| "?".to_string(), |p| p.pid.to_string()),
                    result.get("backup").is_some() || !self.config_file.exists()
                ),
            });
        }
        ControlResponse::success(result)
    }

    fn status(&self) -> ControlResponse {
        let (reply_tx, reply_rx) = bounded::<()>(1);
        if self
            .control_tx
            .try_send(MainLoopCommand::WriteState(reply_tx))
            .is_err()
        {
            return ControlResponse::failure("busy", "the main loop command queue is full");
        }
        match reply_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(()) => match SelfMonitor::read_state(&self.state_file) {
                Ok(state) => match serde_json::to_value(state) {
                    Ok(value) => ControlResponse::success(value),
                    Err(error) => ControlResponse::failure("unavailable", error.to_string()),
                },
                Err(error) => ControlResponse::failure("unavailable", error),
            },
            Err(_) => ControlResponse::failure(
                "timeout",
                "the main loop did not write state.json within 10 s",
            ),
        }
    }

    fn explain(&self, id: &str) -> ControlResponse {
        let ledger = match crate::logger::sqlite::SqliteLogger::open_read_only(&self.sqlite_db) {
            Ok(ledger) => ledger,
            Err(error) => {
                return ControlResponse::failure(
                    "unavailable",
                    format!("decision ledger {}: {error}", self.sqlite_db.display()),
                );
            }
        };
        match ledger.decision_by_id(id) {
            Ok(Some((record, occurrences))) => match serde_json::to_value(&record) {
                Ok(record) => ControlResponse::success(json!({
                    "record": record,
                    "occurrences": occurrences,
                })),
                Err(error) => ControlResponse::failure("unavailable", error.to_string()),
            },
            Ok(None) => ControlResponse::failure(
                "not_found",
                format!("no decision {id} in {}", self.sqlite_db.display()),
            ),
            Err(error) => ControlResponse::failure("unavailable", error.to_string()),
        }
    }

    fn ballast(&self, action: ControlBallastAction) -> ControlResponse {
        let (reply_tx, reply_rx) = bounded::<std::result::Result<Value, String>>(1);
        if self
            .control_tx
            .try_send(MainLoopCommand::Ballast {
                action,
                reply: reply_tx,
            })
            .is_err()
        {
            return ControlResponse::failure("busy", "the main loop command queue is full");
        }
        match reply_rx.recv_timeout(Duration::from_secs(60)) {
            Ok(Ok(result)) => ControlResponse::success(result),
            Ok(Err(error)) => ControlResponse::failure("failed", error),
            Err(_) => ControlResponse::failure(
                "timeout",
                "the main loop did not finish the ballast action within 60 s",
            ),
        }
    }
}

impl ControlBackend for DaemonControlBackend {
    fn handle(&self, command: ControlCommand, peer: Option<Peer>) -> ControlResponse {
        if command.is_mutating() {
            self.logger.send(ActivityEvent::Info {
                message: format!(
                    "control socket: {} requested by uid {} pid {}",
                    command.name(),
                    peer.map_or_else(|| "?".to_string(), |p| p.uid.to_string()),
                    peer.map_or_else(|| "?".to_string(), |p| p.pid.to_string()),
                ),
            });
        }
        match command {
            ControlCommand::Ping => ControlResponse::success(json!({
                "pid": std::process::id(),
                "started_at": self.started_at,
                "version": env!("CARGO_PKG_VERSION"),
                "uptime_secs": self.start_instant.elapsed().as_secs(),
                "policy_mode": self.policy_engine.lock().mode().to_string(),
            })),
            ControlCommand::Status => self.status(),
            ControlCommand::ScanNow { paths, force } => {
                if !paths.is_empty() {
                    return ControlResponse::failure(
                        "bad_request",
                        "scan-now: per-path scans are not supported yet; the forced scan covers the configured roots",
                    );
                }
                self.signal_handler.request_scan();
                self.wake();
                ControlResponse::success(json!({
                    "queued": true,
                    "force": force,
                    "note": "the next tick runs a forced scan of the configured roots (the SIGUSR1 path)",
                }))
            }
            ControlCommand::Reload => {
                self.signal_handler.request_reload();
                self.wake();
                ControlResponse::success(json!({ "queued": true }))
            }
            ControlCommand::Policy(action) => self.policy(action, peer),
            ControlCommand::Explain { id } => self.explain(&id),
            ControlCommand::Ballast(action) => self.ballast(action),
            ControlCommand::Shutdown => {
                self.signal_handler.request_shutdown();
                self.wake();
                ControlResponse::success(json!({ "stopping": true }))
            }
        }
    }
}

#[derive(Debug, Clone)]
struct ScannerIndexFeedback {
    identity: IndexedIdentity,
    path: PathBuf,
}

#[derive(Debug, Clone)]
struct MemoryPressureEvent {
    pressure: MemoryPressure,
    received_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BehaviorTransition {
    from_memory: MemoryPressureLevel,
    to_memory: MemoryPressureLevel,
    from_disk: PressureLevel,
    to_disk: PressureLevel,
    from_mode: BehaviorMode,
    to_mode: BehaviorMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BehaviorTransitionDirection {
    Escalating,
    Recovering,
}

#[derive(Debug, Clone, Copy)]
struct PendingBehaviorTarget {
    memory_level: MemoryPressureLevel,
    disk_level: PressureLevel,
    mode: BehaviorMode,
}

#[derive(Debug, Clone, Copy)]
enum BehaviorUpdate {
    Unchanged,
    Applied(BehaviorTransition),
    Deferred {
        direction: BehaviorTransitionDirection,
        remaining: Duration,
        /// The same target was already waiting; the daemon logs a deferral once.
        repeated: bool,
    },
}

#[derive(Debug, Clone)]
struct PressureBehaviorState {
    table: BehaviorDispatchTable,
    memory_level: MemoryPressureLevel,
    disk_level: PressureLevel,
    mode: BehaviorMode,
    last_escalation_at: Option<Instant>,
    last_recovery_at: Option<Instant>,
    pending_target: Option<PendingBehaviorTarget>,
}

impl PressureBehaviorState {
    fn new(
        table: BehaviorDispatchTable,
        memory_level: MemoryPressureLevel,
        disk_level: PressureLevel,
    ) -> Self {
        let mode = table.mode_for(memory_level, disk_level);
        Self {
            table,
            memory_level,
            disk_level,
            mode,
            last_escalation_at: None,
            last_recovery_at: None,
            pending_target: None,
        }
    }

    /// Swap in a reloaded matrix and re-resolve the current cell without
    /// hysteresis (the pressure levels did not change; the policy did). A
    /// deferred target stays: it holds the latest memory reading, and the
    /// next evaluation re-resolves its mode against the new matrix.
    fn replace_table(&mut self, table: BehaviorDispatchTable) -> Option<BehaviorTransition> {
        self.table = table;
        let next_mode = self.table.mode_for(self.memory_level, self.disk_level);
        if next_mode == self.mode {
            return None;
        }
        Some(self.apply_behavior_transition(self.memory_level, self.disk_level, next_mode))
    }

    fn table(&self) -> &BehaviorDispatchTable {
        &self.table
    }

    /// The memory level to evaluate next: a deferred target's while one waits
    /// out its hysteresis window, else the applied one. The subscription
    /// reports a level once, when it changes, so a deferred target is the
    /// daemon's only record of it; evaluating the applied level instead would
    /// cancel the target and run the wrong mode until the next change.
    fn latest_memory_level(&self) -> MemoryPressureLevel {
        self.pending_target
            .map_or(self.memory_level, |pending| pending.memory_level)
    }

    const fn has_pending_target(&self) -> bool {
        self.pending_target.is_some()
    }

    #[cfg(test)]
    fn update(
        &mut self,
        memory_level: MemoryPressureLevel,
        disk_level: PressureLevel,
    ) -> Option<BehaviorTransition> {
        self.update_with_hysteresis(memory_level, disk_level, Instant::now(), Duration::ZERO)
            .into_transition()
    }

    fn update_with_hysteresis(
        &mut self,
        memory_level: MemoryPressureLevel,
        disk_level: PressureLevel,
        now: Instant,
        min_interval: Duration,
    ) -> BehaviorUpdate {
        let next_mode = self.table.mode_for(memory_level, disk_level);
        if self.memory_level == memory_level
            && self.disk_level == disk_level
            && self.mode == next_mode
        {
            self.pending_target = None;
            return BehaviorUpdate::Unchanged;
        }

        if self.pending_target.is_some_and(|pending| {
            pending.memory_level != memory_level
                || pending.disk_level != disk_level
                || pending.mode != next_mode
        }) {
            self.pending_target = None;
        }

        let Some(direction) =
            transition_direction(self.memory_level, memory_level, self.disk_level, disk_level)
        else {
            let transition = self.apply_behavior_transition(memory_level, disk_level, next_mode);
            self.pending_target = None;
            return BehaviorUpdate::Applied(transition);
        };

        if let Some(remaining) = self.hysteresis_remaining(direction, now, min_interval) {
            // A differing target was cleared above, so one still here is this one.
            let repeated = self.pending_target.is_some();
            self.pending_target = Some(PendingBehaviorTarget {
                memory_level,
                disk_level,
                mode: next_mode,
            });
            return BehaviorUpdate::Deferred {
                direction,
                remaining,
                repeated,
            };
        }

        let transition = self.apply_behavior_transition(memory_level, disk_level, next_mode);
        self.record_transition_direction(direction, now);
        self.pending_target = None;
        BehaviorUpdate::Applied(transition)
    }

    fn apply_behavior_transition(
        &mut self,
        memory_level: MemoryPressureLevel,
        disk_level: PressureLevel,
        next_mode: BehaviorMode,
    ) -> BehaviorTransition {
        let transition = BehaviorTransition {
            from_memory: self.memory_level,
            to_memory: memory_level,
            from_disk: self.disk_level,
            to_disk: disk_level,
            from_mode: self.mode,
            to_mode: next_mode,
        };
        self.memory_level = memory_level;
        self.disk_level = disk_level;
        self.mode = next_mode;
        transition
    }

    fn hysteresis_remaining(
        &self,
        direction: BehaviorTransitionDirection,
        now: Instant,
        min_interval: Duration,
    ) -> Option<Duration> {
        if min_interval.is_zero() {
            return None;
        }

        let last = match direction {
            BehaviorTransitionDirection::Escalating => self.last_escalation_at,
            BehaviorTransitionDirection::Recovering => self.last_recovery_at,
        }?;
        let elapsed = now.saturating_duration_since(last);
        if elapsed >= min_interval {
            None
        } else {
            min_interval.checked_sub(elapsed)
        }
    }

    fn record_transition_direction(
        &mut self,
        direction: BehaviorTransitionDirection,
        now: Instant,
    ) {
        match direction {
            BehaviorTransitionDirection::Escalating => self.last_escalation_at = Some(now),
            BehaviorTransitionDirection::Recovering => self.last_recovery_at = Some(now),
        }
    }
}

#[cfg(test)]
impl BehaviorUpdate {
    const fn into_transition(self) -> Option<BehaviorTransition> {
        match self {
            Self::Applied(transition) => Some(transition),
            Self::Unchanged | Self::Deferred { .. } => None,
        }
    }
}

fn transition_direction(
    from_memory: MemoryPressureLevel,
    to_memory: MemoryPressureLevel,
    from_disk: PressureLevel,
    to_disk: PressureLevel,
) -> Option<BehaviorTransitionDirection> {
    use std::cmp::Ordering;

    let memory_order =
        behavior_pressure_rank(BehaviorPressureLevel::from_memory_pressure(to_memory)).cmp(
            &behavior_pressure_rank(BehaviorPressureLevel::from_memory_pressure(from_memory)),
        );
    // Disk levels are totally ordered (Green < Yellow < Orange < Red < Critical);
    // a Yellow -> Orange move is an escalation even though both were one
    // "warn" column in the v0.5 matrix.
    let disk_order = to_disk.cmp(&from_disk);

    match (memory_order, disk_order) {
        (Ordering::Equal, Ordering::Equal) => None,
        (Ordering::Greater | Ordering::Equal, Ordering::Greater | Ordering::Equal) => {
            Some(BehaviorTransitionDirection::Escalating)
        }
        (Ordering::Less | Ordering::Equal, Ordering::Less | Ordering::Equal) => {
            Some(BehaviorTransitionDirection::Recovering)
        }
        (Ordering::Greater | Ordering::Less, Ordering::Less | Ordering::Greater) => None,
    }
}

const fn behavior_pressure_rank(level: BehaviorPressureLevel) -> u8 {
    match level {
        BehaviorPressureLevel::Normal => 0,
        BehaviorPressureLevel::Warn => 1,
        BehaviorPressureLevel::Critical => 2,
    }
}

/// Bounded capacity for the worker→monitor results channel.
pub const REPORT_CHANNEL_CAP: usize = 64;

// ──────────────────── daemon configuration ────────────────────

/// Arguments for `sbh daemon` subcommand.
#[derive(Debug, Clone)]
pub struct DaemonArgs {
    /// Run in foreground (default, systemd manages backgrounding).
    pub foreground: bool,
    /// Optional PID file path for non-systemd setups.
    pub pidfile: Option<PathBuf>,
    /// Systemd watchdog timeout in seconds (0 = disabled).
    pub watchdog_sec: u64,
}

impl Default for DaemonArgs {
    fn default() -> Self {
        Self {
            foreground: true,
            pidfile: None,
            watchdog_sec: 0,
        }
    }
}

struct MountMonitor {
    rate_estimator: DiskRateEstimator,
    pressure_controller: PidPressureController,
    guard: AdaptiveGuard,
    last_guard_sample: Option<GuardSample>,
    /// Conformal calibration of the time-to-red forecast.
    conformal: ConformalCalibrator,
}

/// One mount's reading from `check_pressure`, kept so `handle_pressure` can
/// drive every mount from its own response instead of only the worst one.
#[derive(Debug, Clone)]
struct MountTickResponse {
    response: crate::monitor::pid::PressureResponse,
    seconds_to_red: Option<f64>,
    prediction_confident: bool,
    /// The mount's EWMA estimate, for `state.json` (`rates`, `rate_bps`).
    rate: MountRateState,
}

/// A finite, positive prediction or nothing.
fn finite_positive(seconds: f64) -> Option<f64> {
    (seconds.is_finite() && seconds > 0.0).then_some(seconds)
}

/// Once per `FORECAST_LOG_INTERVAL` per filling mount, the calibration
/// line that makes the coverage guarantee auditable in the field
/// (`stats --json .forecast.coverage_by_day` aggregates it).
fn log_forecast(
    last_forecast_log: &mut HashMap<PathBuf, Instant>,
    logger: &ActivityLoggerHandle,
    mount: &Path,
    estimate: &RateEstimate,
    interval: Option<&TteInterval>,
    now: Instant,
) {
    let Some(interval) = interval else {
        return;
    };
    if interval.samples == 0 {
        return;
    }
    let due = last_forecast_log
        .get(mount)
        .is_none_or(|last| now.saturating_duration_since(*last) >= FORECAST_LOG_INTERVAL);
    if !due {
        return;
    }
    last_forecast_log.insert(mount.to_path_buf(), now);
    let coverage = interval
        .coverage_empirical
        .map_or_else(|| "-".to_string(), |c| format!("{c:.3}"));
    let message = format!(
        "forecast mount={} tte_point={:.0} tte_lo={:.0} alpha={:.3} coverage={coverage} samples={} state={:?} rate={:.0}",
        mount.display(),
        interval.point_secs,
        interval.lo_secs,
        interval.alpha,
        interval.samples,
        interval.coverage_state,
        estimate.bytes_per_second
    );
    eprintln!("[SBH-FORECAST] {message}");
    logger.send(ActivityEvent::Info { message });
}

/// Conformal calibration tunables derived from config.
fn conformal_config(config: &Config) -> ConformalConfig {
    ConformalConfig {
        coverage_target: config.pressure.prediction.coverage_target,
        ..ConformalConfig::default()
    }
}

/// The estimate the predictive policy and the controllers act on: the
/// point forecast shrunk to the conformal lower bound (the same relative
/// factor applies to the time to exhaustion).
fn calibrated_estimate(estimate: &RateEstimate, interval: Option<&TteInterval>) -> RateEstimate {
    let mut calibrated = estimate.clone();
    if let Some(interval) = interval
        && interval.point_secs.is_finite()
        && interval.point_secs > 0.0
        && interval.lo_secs.is_finite()
    {
        let factor = (interval.lo_secs / interval.point_secs).clamp(0.0, 1.0);
        calibrated.seconds_to_threshold = interval.lo_secs;
        if calibrated.seconds_to_exhaustion.is_finite() {
            calibrated.seconds_to_exhaustion *= factor;
        }
    }
    calibrated
}

/// Controller tunables derived from config.
fn mount_controller_config(config: &Config) -> MountControllerConfig {
    MountControllerConfig {
        action_horizon: Duration::from_secs_f64(
            (config.pressure.prediction.action_horizon_minutes * 60.0).max(0.0),
        ),
        recovery_clean_windows: crate::daemon::mount_controller::DEFAULT_RECOVERY_CLEAN_WINDOWS,
        min_rescan_interval: Duration::from_secs(config.scanner.min_rescan_interval_secs.max(1)),
        red_min_free_pct: config.pressure.red_min_free_pct,
    }
}

/// Entry budget for sizing one catalog root.
///
/// A catalog scan probes every derived root (a hundred or more under one
/// home), so the per-root budget is what bounds the whole pass: a truncated
/// probe reports a size lower bound and the tree's newest sampled mtime,
/// which is enough to rank and gate the root.
pub const CATALOG_PROBE_MAX_ENTRIES: usize = 50_000;
/// Depth budget for the catalog root probe.
pub const CATALOG_PROBE_MAX_DEPTH: usize = 5;

/// Turn derived catalog roots into opaque candidate units for the scanner
/// loop. Each root is probed once (allocated size, newest mtime, structural
/// markers); roots used more recently than their rule's minimum idle age are
/// left alone. Returns the entries and how many roots were skipped as young.
fn catalog_walk_entries(roots: &[ExpandedCatalogRoot]) -> (Vec<WalkEntry>, usize) {
    let now = SystemTime::now();
    let mut entries = Vec::with_capacity(roots.len());
    let mut skipped_young = 0usize;
    for root in roots {
        let Ok(std_meta) = std::fs::symlink_metadata(&root.path) else {
            continue;
        };
        if !std_meta.is_dir() {
            continue;
        }
        let probe = crate::scanner::walker::tree_newest_mtime(
            &root.path,
            CATALOG_PROBE_MAX_ENTRIES,
            CATALOG_PROBE_MAX_DEPTH,
        );
        let mut metadata = crate::scanner::walker::entry_metadata(&std_meta);
        metadata.content_size_bytes = probe.allocated_bytes.max(metadata.size_bytes);
        metadata.tree_last_modified = probe.newest_mtime;
        let idle = now
            .duration_since(metadata.effective_age_timestamp())
            .unwrap_or(Duration::ZERO);
        if idle < root.min_age {
            skipped_young += 1;
            continue;
        }
        let confidence = root.confidence.as_name_confidence();
        let classification = ArtifactClassification {
            pattern_name: Cow::Borrowed(root.rule),
            category: crate::scanner::patterns::ArtifactCategory::CacheDir,
            name_confidence: confidence,
            structural_confidence: confidence,
            combined_confidence: confidence,
        };
        entries.push(WalkEntry {
            path: root.path.clone(),
            metadata,
            depth: 0,
            structural_signals: probe.signals,
            is_open: false,
            opaque_tree: Some(crate::scanner::patterns::OpaqueTreeClassification {
                disposition: OpaqueTreeDisposition::CandidateOpaque,
                reason: Cow::Owned(format!("catalog root ({})", root.rule)),
                classification,
            }),
        });
    }
    (entries, skipped_young)
}

/// Whether a catalog scan is due for a mount: never dispatched yet, the
/// pressure level rose since the last one, or the rescan interval elapsed.
fn catalog_epoch_due(
    previous: Option<(PressureLevel, Instant)>,
    level: PressureLevel,
    now: Instant,
    rescan_interval: Duration,
) -> bool {
    previous.is_none_or(|(prev_level, at)| {
        level > prev_level || now.saturating_duration_since(at) >= rescan_interval
    })
}

/// The daemon-wide idle reason for `state.json`: when every mount is
/// observe-only or idle, the idle reason shared by the most mounts; `None`
/// while any mount maintains, reclaims or recovers (or nothing is known).
fn daemon_idle_reason(controllers: &[MountStateRecord]) -> Option<String> {
    if controllers.is_empty()
        || controllers
            .iter()
            .any(|c| !matches!(c.state, MountState::ObserveOnly | MountState::Idle))
    {
        return None;
    }
    let mut counts: HashMap<&'static str, usize> = HashMap::new();
    for record in controllers {
        if let Some(reason) = record.idle_reason {
            *counts.entry(reason.as_str()).or_default() += 1;
        }
    }
    counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(a.0)))
        .map(|(reason, _)| reason.to_string())
}

/// A pre-scan candidate's age by the walker's rule: files by mtime;
/// directories by the newest of their mtime, birth time and a bounded probe
/// of the tree, so a tree created a moment ago with old mtimes (a copy, an
/// extracted archive) is as young as the walker would find it.
fn prescan_age(path: &Path) -> Duration {
    let Ok(meta) = path.metadata() else {
        return Duration::ZERO;
    };
    let entry = crate::scanner::walker::entry_metadata(&meta);
    let mut newest = entry.effective_age_timestamp();
    if entry.is_dir {
        let probe = crate::scanner::walker::tree_newest_mtime(
            path,
            crate::scanner::walker::TREE_IDLE_PROBE_MAX_ENTRIES,
            crate::scanner::walker::TREE_IDLE_PROBE_MAX_DEPTH,
        );
        if let Some(tree_newest) = probe.newest_mtime {
            newest = newest.max(tree_newest);
        }
    }
    newest.elapsed().unwrap_or(Duration::ZERO)
}

/// Recursive allocated size of a pre-scan directory candidate.
///
/// The pre-scan used to plan every directory at a flat 100 MiB, so a 2 MiB
/// `.ruff_cache` was planned and logged as 100 MiB (css 2026-09-25,
/// `freed=104857600B observed_freed=2195456B`). This uses the walker's
/// bounded probe and, like the walker, keeps the floor only when the probe
/// was cut short and the remainder could be any size.
fn prescan_dir_size(path: &Path, cross_devices: bool, cancel: &AtomicBool) -> u64 {
    use crate::scanner::walker::{OPAQUE_CANDIDATE_SIZE_FLOOR, OPAQUE_SIZE_PROBE_BUDGET};
    let Ok(meta) = path.symlink_metadata() else {
        return OPAQUE_CANDIDATE_SIZE_FLOOR;
    };
    let probe = crate::scanner::walker::opaque_tree_probe(
        path,
        cross_devices,
        crate::scanner::walker::device_id(&meta),
        OPAQUE_SIZE_PROBE_BUDGET,
        cancel,
    );
    if probe.truncated {
        probe.allocated_bytes.max(OPAQUE_CANDIDATE_SIZE_FLOOR)
    } else {
        probe.allocated_bytes
    }
}

/// Probe write used to leave `MountState::Recovery`: 4 KiB into the mount's
/// ballast directory (or `<mount>/.sbh`), removed again on success.
fn probe_mount_writable(mount: &Path, ballast_dir: Option<&Path>) -> bool {
    let dir = ballast_dir.map_or_else(|| mount.join(".sbh"), Path::to_path_buf);
    if std::fs::create_dir_all(&dir).is_err() {
        return false;
    }
    let probe = dir.join("probe");
    let written = std::fs::write(&probe, [0u8; 4096]).is_ok();
    let _ = std::fs::remove_file(&probe);
    written
}

struct GuardSample {
    at: Instant,
    available_bytes: u64,
    predicted_rate: f64,
    predicted_tte: f64,
}

impl MountMonitor {
    fn new(config: &Config) -> Self {
        let rate_estimator = DiskRateEstimator::with_history_cap(
            config.telemetry.ewma_base_alpha,
            config.telemetry.ewma_min_alpha,
            config.telemetry.ewma_max_alpha,
            config.telemetry.ewma_min_samples,
            config.telemetry.ewma_rate_history_size,
        );

        let mut pressure_controller = PidPressureController::new(
            &PidConfig::from(&config.pressure),
            Duration::from_millis(config.pressure.poll_interval_ms),
        );
        if config.pressure.prediction.enabled {
            pressure_controller
                .set_action_horizon_minutes(config.pressure.prediction.action_horizon_minutes);
        }

        let guard_config = crate::monitor::guardrails::GuardrailConfig {
            min_observations: config.telemetry.guardrail_min_observations,
            window_size: config.telemetry.guardrail_window_size,
            ..crate::monitor::guardrails::GuardrailConfig::default()
        };

        Self {
            rate_estimator,
            pressure_controller,
            guard: AdaptiveGuard::new(guard_config),
            last_guard_sample: None,
            conformal: ConformalCalibrator::new(conformal_config(config)),
        }
    }

    /// The conformal lower bound for a point estimate, from this mount's
    /// calibration.
    fn forecast_interval(&self, predicted_tte: f64) -> TteInterval {
        self.conformal.lower_bound(predicted_tte)
    }

    fn update_config(&mut self, config: &Config) {
        if self.conformal.config() != &conformal_config(config) {
            self.conformal = ConformalCalibrator::new(conformal_config(config));
        }
        self.rate_estimator.update_params(
            config.telemetry.ewma_base_alpha,
            config.telemetry.ewma_min_alpha,
            config.telemetry.ewma_max_alpha,
            config.telemetry.ewma_min_samples,
        );

        self.pressure_controller
            .apply_config(&PidConfig::from(&config.pressure));
        self.pressure_controller
            .set_base_poll_interval(Duration::from_millis(config.pressure.poll_interval_ms));

        if config.pressure.prediction.enabled {
            self.pressure_controller
                .set_action_horizon_minutes(config.pressure.prediction.action_horizon_minutes);
        } else {
            self.pressure_controller.disable_urgency_boost();
        }
    }

    fn observe_guard(
        &mut self,
        now: Instant,
        available_bytes: u64,
        threshold_bytes: u64,
        rate_estimate: &RateEstimate,
    ) -> GuardDiagnostics {
        if let Some(previous) = &self.last_guard_sample
            && let Some(dt) = now.checked_duration_since(previous.at)
        {
            let dt_seconds = dt.as_secs_f64();
            if dt_seconds > 1e-6 {
                let consumed_bytes = previous.available_bytes as f64 - available_bytes as f64;
                let actual_rate = consumed_bytes / dt_seconds;
                let actual_tte = if available_bytes <= threshold_bytes {
                    dt_seconds
                } else {
                    f64::INFINITY
                };
                // Mark observation as a burst outlier when the actual rate
                // exceeds the MAD-based robust upper bound. During bursts,
                // prediction error is expected (EWMA damps the spike) — counting
                // these as calibration failures permanently poisons the guard on
                // machines with bursty workloads (rustc, cargo build, etc.).
                let burst_outlier = rate_estimate.burst_state.is_burst_outlier(actual_rate);
                // A fill rate that could not reach the red threshold within a
                // day is calibration noise on this mount, not evidence.
                self.guard.set_material_rate(
                    crate::monitor::guardrails::material_rate_for_headroom(
                        available_bytes.saturating_sub(threshold_bytes),
                    ),
                );
                self.guard.observe(CalibrationObservation {
                    predicted_rate: previous.predicted_rate,
                    actual_rate,
                    predicted_tte: previous.predicted_tte,
                    actual_tte,
                    burst_outlier,
                });
                // Conformal calibration: a recovery worth more than 1% of the
                // red threshold is an intervention (ballast, a reclaim, an
                // external delete), so the trajectory the pending predictions
                // were made on is gone; otherwise they resolve against a
                // crossing or their own horizon, and each resolution is a
                // coverage outcome for the guard's e-process.
                let recovered = available_bytes.saturating_sub(previous.available_bytes);
                if recovered > threshold_bytes / 100 {
                    self.conformal.discard_pending();
                }
                let crossed = previous.available_bytes > threshold_bytes
                    && available_bytes <= threshold_bytes;
                let resolved = self.conformal.observe(now, crossed);
                for _ in 0..resolved.covered {
                    self.guard.observe_coverage(true);
                }
                for _ in 0..resolved.missed {
                    self.guard.observe_coverage(false);
                }
            }
        }

        let predicted_rate = if rate_estimate.bytes_per_second.is_finite() {
            rate_estimate.bytes_per_second
        } else {
            0.0
        };
        let predicted_tte = if rate_estimate.seconds_to_threshold.is_finite()
            && rate_estimate.seconds_to_threshold >= 0.0
        {
            rate_estimate.seconds_to_threshold
        } else {
            f64::INFINITY
        };
        // Only a mount filling at a material rate contributes calibration
        // samples (idle neutrality); the bound is published either way.
        if predicted_rate > self.guard.material_rate() {
            self.conformal.enroll(now, predicted_tte);
        }
        let interval = self.conformal.lower_bound(predicted_tte);
        self.guard
            .set_forecast(Some(ForecastSnapshot::from_interval(
                &interval,
                self.conformal.config().coverage_target,
            )));
        self.last_guard_sample = Some(GuardSample {
            at: now,
            available_bytes,
            predicted_rate,
            predicted_tte,
        });

        self.guard.diagnostics()
    }
}

// ──────────────────── main daemon struct ────────────────────

/// The monitoring daemon: orchestrates all sbh components.
pub struct MonitoringDaemon {
    config: Config,
    #[allow(dead_code)] // used by downstream beads (walker, protection)
    platform: Arc<dyn Platform>,
    logger_handle: ActivityLoggerHandle,
    logger_join: Option<thread::JoinHandle<()>>,
    signal_handler: SignalHandler,
    watchdog: WatchdogHeartbeat,
    /// Q7: the daemon-wide CPU token bucket, observed once per tick here and
    /// consulted by the scanner before each discretionary pass.
    cpu_budget: Arc<Mutex<CpuBudget>>,
    /// Exclusive liveness lock next to `state.json`; held until the daemon exits.
    daemon_lock: DaemonLock,
    /// Optional `--pidfile`, removed again on orderly shutdown.
    pidfile: Option<PathBuf>,
    fs_collector: FsStatsCollector,
    mount_monitors: HashMap<PathBuf, MountMonitor>,
    /// One control state machine per mount (W1.1): decides per mount whether
    /// sbh reclaims, maintains, only observes, recovers or idles, and what
    /// each mount contributes to the tick cadence.
    mount_controllers: HashMap<PathBuf, MountController>,
    /// Every mount's response from the last `check_pressure`, consumed by
    /// `handle_pressure` so each mount is driven by its own reading.
    mount_responses: Vec<MountTickResponse>,
    /// Wake signals (SIGUSR1, reload) collected for the next tick's
    /// controllers.
    wake_next_tick: WakeSignals,
    /// Mounts the executor reported as read-only or out of metadata space
    /// since the last tick; each enters `MountState::Recovery`.
    pending_recovery: HashSet<PathBuf>,
    /// Policy transitions already logged as `policy_transition` events
    /// (a cursor into `PolicyEngine::transitions_total`).
    policy_transitions_seen: u64,
    /// Mounts whose last provision or replenish pass stopped at the headroom
    /// floor: their reserve is short by plan, not by release.
    floor_limited: HashSet<PathBuf>,
    /// Once-per-epoch throttle for the "nothing to reclaim here" alert.
    reclaim_alerts: AlertThrottle,
    /// Derived catalog roots per mount (W1 catalog roots), refreshed every
    /// `scanner.catalog_rescan_interval_secs`.
    catalog_root_cache: HashMap<PathBuf, (Instant, Vec<ExpandedCatalogRoot>)>,
    /// Last catalog scan per mount: the level it was dispatched at and when.
    /// One catalog scan per pressure epoch; a rising level re-arms it.
    catalog_epochs: HashMap<PathBuf, (PressureLevel, Instant)>,
    /// Mounts currently at Critical: the `emergency` event is emitted once
    /// when a mount enters Critical, not on every tick it stays there.
    emergency_mounts: HashSet<PathBuf>,
    /// Latest EWMA fill rate per mount (bytes per second), for the
    /// special-location horizon rule.
    mount_rates: HashMap<PathBuf, f64>,
    /// Where the daemon's own files live relative to what it reclaims
    /// (bd-rc-master-ajg1.7.4), and whether the JSONL log is currently
    /// mirrored to the RAM fallback because that mount is pressured.
    logging_placement: LoggingState,
    /// The level last reported for the logging mount, so the log line and
    /// the mirror switch happen per level change, never per tick.
    logging_level_logged: Option<PressureLevel>,
    /// When the RAM fallback's headroom was last checked while the logging
    /// mount was pressured (bd-ffjj).
    logging_ram_checked_at: Option<Instant>,
    /// Per-location alert throttle for the special-location horizon rule.
    special_alerts: AlertThrottle,
    /// When the last Green maintenance pass was dispatched.
    last_maintenance_scan: Option<Instant>,
    /// Layer 7: when the quarantines were last swept for expired entries
    /// and the size cap (`QUARANTINE_SWEEP_INTERVAL`).
    last_quarantine_sweep: Option<Instant>,
    /// When each mount's `[SBH-FORECAST]` calibration line was last logged.
    last_forecast_log: HashMap<PathBuf, Instant>,
    /// Bytes held in quarantine per mount, from the last sweep
    /// (`state.json` `reserve_state.quarantined_bytes`).
    quarantine_held: HashMap<PathBuf, u64>,
    special_locations: SpecialLocationRegistry,
    ballast_coordinator: BallastPoolCoordinator,
    release_controller: BallastReleaseController,
    notification_manager: NotificationManager,
    scoring_engine: ScoringEngine,
    voi_scheduler: VoiScheduler,
    /// When the last maintenance plan was made and what it chose, for the
    /// state file's `voi` block (bd-rc-master-ajg1.4.11).
    last_voi_plan: Option<(String, crate::monitor::voi_scheduler::ScanPlan)>,
    shared_executor_config: Arc<SharedExecutorConfig>,
    /// Regret labels (Q4).
    regret: Arc<SharedRegret>,
    shared_scoring_config: Arc<RwLock<crate::core::config::ScoringConfig>>,
    shared_scanner_config: Arc<RwLock<crate::core::config::ScannerConfig>>,
    start_time: Instant,
    last_pressure_level: PressureLevel,
    /// Highest pressure level that was notified within the cooldown window.
    /// Used to suppress oscillation noise: after notifying at Orange, we won't
    /// re-notify at Yellow even if pressure dips to Green and comes back up.
    last_notified_pressure_level: PressureLevel,
    last_pressure_notify_time: Option<Instant>,
    last_special_scan: HashMap<PathBuf, Instant>,
    /// Per-special-location alert episode: (highest level notified in it, when
    /// its alert was last seen). See [`special_episode_step`] and
    /// [`special_episode_over`]; prevents the oscillation spam the main
    /// pressure loop also suppresses.
    last_special_notify: HashMap<PathBuf, (PressureLevel, Instant)>,
    last_predictive_warning: Option<Instant>,
    last_predictive_level: Option<NotificationLevel>,
    last_ewma_confidence: f64,
    predictive_policy: PredictiveActionPolicy,
    last_predictive_action: PredictiveAction,
    /// Whether any cleanup was dispatched in the previous tick (scan or ballast release).
    /// Used by the prediction scorecard to distinguish interventions from false alarms.
    last_tick_cleanup_ran: bool,
    last_swap_thrash_warning: Option<Instant>,
    swap_thrash_active: bool,
    last_scan_channel_warn: Option<Instant>,
    scan_channel_warn_suppressed: u64,
    /// When a SIGUSR1 scan the full scan queue could not take yet arrived;
    /// it is retried every tick until queued.
    forced_scan_pending_since: Option<Instant>,
    /// Rate-limit for the B5 "pressured device has no root_path" warning so the
    /// back-off path does not spam logs on every tick.
    last_device_affinity_warn: Option<Instant>,
    /// When each mount last got a growth-attribution report (SBH-2007).
    attribution_reported: HashMap<PathBuf, Instant>,
    /// Since when each mount has been continuously at Red or worse.
    attribution_pressured_since: HashMap<PathBuf, Instant>,
    /// Opt-in lossless compression passes on btrfs (`[compress]`, bd-rxq5).
    compress_tier: CompressTier,
    /// Pure idle cargo targets inside `scanner.target_only_roots` (bd-232u).
    target_tier: TargetTier,
    last_summary_report: Instant,
    summary_scans: u64,
    summary_scan_timeouts: u64,
    summary_candidates: u64,
    summary_deleted: u64,
    summary_failed: u64,
    summary_bytes_freed: u64,
    /// How `summary_bytes_freed` is known, and what was measured beside it.
    summary_freed_basis: FreedBasis,
    summary_bytes_freed_observed: Option<u64>,
    last_full_disk_access_check: Option<Instant>,
    last_full_disk_access_state: Option<FullDiskAccessState>,
    full_disk_access_granted_logged: bool,
    process_io_history: ProcessIoHistory,
    /// Per-mount write-burst windows and the reserve they imply
    /// (bd-rc-master-ajg1.2.18), persisted beside `state.json`.
    burst_stats: BurstStats,
    /// When the last scan pass completed and how long it took, so the next
    /// deletion report can close a reaction-window cycle.
    last_scan_completed: Option<(Instant, Duration)>,
    self_monitor: SelfMonitor,
    tick_throttle: AdaptiveTickThrottle,
    policy_engine: Arc<Mutex<PolicyEngine>>,
    /// bd-rc-master-ajg1.4.9: the control socket's channel into the main
    /// loop (fresh state writes, ballast actions, wake-ups), the running
    /// listener, and the `status` requests waiting for the next state write.
    control_tx: Sender<MainLoopCommand>,
    control_rx: Receiver<MainLoopCommand>,
    control_server: Option<ControlServer>,
    pending_control: Vec<MainLoopCommand>,
    pending_state_replies: Vec<Sender<()>>,
    behavior_state: PressureBehaviorState,
    shared_guard_diagnostics: Arc<RwLock<Option<GuardDiagnostics>>>,
    scanner_heartbeat: Arc<ThreadHeartbeat>,
    executor_heartbeat: Arc<ThreadHeartbeat>,
    prediction_scorecard: PredictionScorecard,
}

fn bytes_to_pct(value: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        #[allow(clippy::cast_precision_loss)]
        {
            (value as f64 * 100.0) / total as f64
        }
    }
}

fn is_swap_thrash_risk(memory: &MemoryInfo) -> bool {
    is_swap_thrash_risk_inner(memory, is_swap_zram_backed())
}

fn is_swap_thrash_risk_inner(memory: &MemoryInfo, zram_backed: bool) -> bool {
    if memory.swap_total_bytes == 0 {
        return false;
    }

    let swap_used_bytes = memory
        .swap_total_bytes
        .saturating_sub(memory.swap_free_bytes);
    let swap_used_pct = bytes_to_pct(swap_used_bytes, memory.swap_total_bytes);

    if swap_used_pct < SWAP_THRASH_USED_PCT_THRESHOLD {
        return false;
    }

    // Suppress false positive when plenty of RAM is available: real swap thrash
    // only happens when both swap is heavily used AND RAM is exhausted.  High
    // swap with ample free RAM means cold pages were swapped out — normal.
    // The zram-specific check is kept as an additional gate because zram swap
    // is compressed memory (not disk paging), so the bar is even lower there.
    if zram_backed {
        let total_ram = memory.total_bytes.max(1);
        #[allow(clippy::cast_precision_loss)]
        let free_ram_pct = (memory.available_bytes as f64 * 100.0) / total_ram as f64;
        if free_ram_pct > 40.0 {
            return false;
        }
    }

    // Thrash risk requires RAM to be low. If the system still has plenty of
    // available RAM, swap usage alone doesn't indicate thrashing.
    memory.available_bytes < SWAP_THRASH_MIN_AVAILABLE_RAM_BYTES
}

/// Check if swap is backed by zram (compressed memory, not disk).
fn is_swap_zram_backed() -> bool {
    std::path::Path::new("/sys/block/zram0").exists()
}

fn normalized_path(path: &Path) -> Cow<'_, str> {
    let raw = path.to_string_lossy();
    if std::path::MAIN_SEPARATOR == '\\' {
        Cow::Owned(raw.replace('\\', "/"))
    } else {
        raw
    }
}

fn is_tmp_like_path(path: &Path) -> bool {
    let normalized = normalized_path(path);
    let text = normalized.as_ref();
    text == "/tmp"
        || text.starts_with("/tmp/")
        || text == "/var/tmp"
        || text.starts_with("/var/tmp/")
        || text == "/data/tmp"
        || text.starts_with("/data/tmp/")
        || text == "/private/tmp"
        || text.starts_with("/private/tmp/")
        || crate::scanner::patterns::is_darwin_user_temp_path(path)
}

/// rch's bare in-tree target dirs (`.rch-target/`, `rch-target/`, plus
/// underscore variants) are reliably reclaimable build caches that rch
/// regenerates from scratch on the next dispatch. Under Orange/Red
/// pressure they should bypass the tmp-only path gate so a 100%-full
/// project mount can self-heal — the open-file check in the executor
/// remains the real safety net for in-flight builds.
fn is_named_in_tree_rch_target(classification: &ArtifactClassification) -> bool {
    matches!(
        classification.pattern_name.as_ref(),
        "rch-target-bare-dot"
            | "rch-target-bare-dot-underscore"
            | "rch-target-bare-hyphen"
            | "rch-target-bare-underscore"
    )
}

/// Patterns that name a whole cargo home; they classify as temp directories.
fn is_cargo_home_pattern(classification: &ArtifactClassification) -> bool {
    matches!(
        classification.pattern_name.as_ref(),
        "cargo-home-prefix" | "tmp-cargo-home" | "rch-cargo-home" | "dot-cargo-prefix"
    )
}

fn should_fast_track_temp_age(
    pressure_level: PressureLevel,
    path: &Path,
    classification: &ArtifactClassification,
) -> bool {
    if pressure_level < PressureLevel::Orange {
        return false;
    }
    if classification.category == ArtifactCategory::Unknown {
        return false;
    }
    // A cache proves "regenerable", not "abandoned". Fast-tracking one gave
    // a live cargo home's stores, minutes old and being compiled from, the
    // configured minimum age: first the CACHEDIR.TAG'd registry/ and git/
    // (bd-d1kt), then, in a real-build proof on macOS, a default ~/.cargo's
    // registry/src classified as an opaque cargo cache, 174 s old, deleted at
    // "age 300 s" under the running build. No cache of any kind, and no cargo
    // home by name, is fast-tracked.
    if matches!(
        classification.category,
        ArtifactCategory::CacheDir | ArtifactCategory::GoCache
    ) || is_cargo_home_pattern(classification)
    {
        return false;
    }
    // Restrict fast-track to tmp-like roots, with one carved-out exception:
    // explicit bare in-tree rch target dirs (see `is_named_in_tree_rch_target`).
    if !is_tmp_like_path(path) && !is_named_in_tree_rch_target(classification) {
        return false;
    }

    // Never fast-track broad ecosystem caches by category alone.
    // These are common in /tmp but can also include active dependency trees.
    if matches!(
        classification.category,
        ArtifactCategory::NodeModules | ArtifactCategory::PythonCache
    ) {
        return false;
    }

    // Under Orange+ pressure, fast-track all classified build artifacts in
    // tmp-like paths. The open-file check in the executor is the real safety
    // net for in-progress builds; the age floor is a secondary guard that
    // causes unnecessary delays when disk is critically low.
    if matches!(
        classification.category,
        ArtifactCategory::RustTarget
            | ArtifactCategory::BuildOutput
            | ArtifactCategory::CacheDir
            | ArtifactCategory::GoCache
            | ArtifactCategory::AgentWorkspace
            | ArtifactCategory::TempDir
    ) {
        return true;
    }

    if classification.name_confidence >= 0.85 {
        return true;
    }

    matches!(
        classification.pattern_name.as_ref(),
        "cargo-target-prefix"
            | "target-suffix"
            | "dot-target-prefix"
            | "underscore-target-prefix"
            | "frankenterm-prefix"
            | "cargo-home-prefix"
            | "dot-cargo-prefix"
            | "agent-ft-suffix"
            | "tmp-cargo-home"
            | "rch-cargo-home"
            | "tmp-codex"
            | "tmp-pijs"
            | "tmp-ext"
            | "pi-agent"
            | "pi-target"
            | "pi-opus"
            | "cass-target"
            | "br-build"
            | "rch-target-underscore"
            | "rch-target-dot"
            | "rch-target-hyphen"
            | "rch-target-bare-dot"
            | "rch-target-bare-dot-underscore"
            | "rch-target-bare-hyphen"
            | "rch-target-bare-underscore"
            | "target-codex"
    )
}

fn adjusted_candidate_age(
    observed_age: Duration,
    min_file_age_minutes: u64,
    pressure_level: PressureLevel,
    path: &Path,
    classification: &ArtifactClassification,
) -> Duration {
    adjusted_candidate_age_after_arrival(
        observed_age,
        min_file_age_minutes,
        pressure_level,
        path,
        classification,
        || candidate_arrival_age(path),
    )
}

/// The fast-track shortens the wait for an old tree whose contents were
/// recently touched, not for a tree that has just arrived. JE's policy
/// (bd-macg, 2026-10-14): a candidate whose root arrived less than the
/// minimum age ago keeps its real age. On fmd a JE-approved copy of idle
/// tmpfs scratch into /data/tmp was deleted five minutes after the copy,
/// recorded at the 600 s minimum, and hz2 lost a 1.9 GB copied
/// `node_modules` the same way. `arrival` is asked only when the fast-track
/// would apply; an unknown arrival keeps the real age.
fn adjusted_candidate_age_after_arrival(
    observed_age: Duration,
    min_file_age_minutes: u64,
    pressure_level: PressureLevel,
    path: &Path,
    classification: &ArtifactClassification,
    arrival: impl FnOnce() -> Option<Duration>,
) -> Duration {
    if !should_fast_track_temp_age(pressure_level, path, classification) {
        return observed_age;
    }
    if observed_age < TEMP_FAST_TRACK_MIN_OBSERVED_AGE {
        return observed_age;
    }

    let min_age = Duration::from_secs(min_file_age_minutes.saturating_mul(60));
    if arrival().is_none_or(|arrived| arrived < min_age) {
        return observed_age;
    }
    observed_age.max(min_age)
}

/// How long ago a candidate's root came to be where it is: the newer of its
/// birth time and its status-change time. A copy is born when it is copied;
/// a tree moved into place keeps its birth time and mtime but gets a new
/// ctime; an extracted archive is born when it is extracted. Writes deep
/// inside a build tree change neither. A time in the future counts as now.
fn candidate_arrival_age(path: &Path) -> Option<Duration> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    #[cfg(unix)]
    let changed = {
        use std::os::unix::fs::MetadataExt as _;
        u64::try_from(metadata.ctime())
            .ok()
            .map(|secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
    };
    #[cfg(not(unix))]
    let changed = None;
    let arrived = [metadata.created().ok(), changed]
        .into_iter()
        .flatten()
        .max()?;
    Some(
        SystemTime::now()
            .duration_since(arrived)
            .unwrap_or(Duration::ZERO),
    )
}

fn push_unique_path(paths: &mut Vec<PathBuf>, candidate: PathBuf) {
    if !paths.iter().any(|existing| existing == &candidate) {
        paths.push(candidate);
    }
}

fn path_is_same_or_descendant(candidate: &Path, ancestor: &Path) -> bool {
    if candidate == ancestor || candidate.starts_with(ancestor) {
        return true;
    }

    let (Ok(candidate), Ok(ancestor)) = (candidate.canonicalize(), ancestor.canonicalize()) else {
        return false;
    };
    candidate == ancestor || candidate.starts_with(ancestor)
}

/// One tick of a special location's alert episode. `previous` is the level
/// notified so far in the episode and when its alert was last seen. Returns
/// the level to notify from (`None`: stay quiet) and the episode's notified
/// level afterwards. A new episode notifies from Green; inside one only an
/// escalation notifies, so a level that wobbles with the write rate is one
/// alert instead of one per wobble.
fn special_episode_step(
    previous: Option<(PressureLevel, Instant)>,
    level: PressureLevel,
) -> (Option<PressureLevel>, PressureLevel) {
    match previous {
        None => (Some(PressureLevel::Green), level),
        Some((notified, _)) if level > notified => (Some(notified), level),
        Some((notified, _)) => (None, notified),
    }
}

/// A special location's alert episode ends once the alert has stayed clear
/// for a whole alert interval; a burst that dips under the horizon and back
/// within it is still the same episode.
fn special_episode_over(
    previous: Option<(PressureLevel, Instant)>,
    now: Instant,
    alert_interval: Duration,
) -> bool {
    previous.is_none_or(|(_, last_seen)| {
        now.checked_duration_since(last_seen)
            .is_none_or(|clear_for| clear_for >= alert_interval)
    })
}

fn special_location_scan_roots(location: &Path, configured_roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for root in configured_roots {
        if path_is_same_or_descendant(root, location) {
            push_unique_path(&mut roots, root.clone());
        }
    }

    if roots.is_empty()
        && configured_roots
            .iter()
            .any(|root| path_is_same_or_descendant(location, root))
    {
        push_unique_path(&mut roots, location.to_path_buf());
    }

    if roots.is_empty() {
        push_unique_path(&mut roots, location.to_path_buf());
    }

    roots
}

fn effective_scan_budget(config: &ScannerConfig, pressure_level: PressureLevel) -> Duration {
    let base_budget_secs = if config.scan_time_budget_secs > 0 {
        config.scan_time_budget_secs
    } else {
        SCAN_TIME_BUDGET_SECS
    };
    let budget_secs = match pressure_level {
        PressureLevel::Red | PressureLevel::Critical | PressureLevel::Orange => {
            // Pressure *extends* the budget. The old `.min(600)` clamped it
            // instead: with the default 900 s base, Orange and above got 600 s
            // — a shorter pass than Green — which is backwards on precisely
            // the hosts that need the longest walk.
            base_budget_secs
                .saturating_mul(2)
                .clamp(base_budget_secs, MAX_SCAN_TIME_BUDGET_SECS)
        }
        _ => base_budget_secs,
    };
    Duration::from_secs(budget_secs)
}

fn v2_pressure_candidate_byte_target(request: &ScanRequest) -> Option<u64> {
    if request.pressure_level < PressureLevel::Orange || request.max_delete_batch == 0 {
        return None;
    }
    Some(
        V2_PRESSURE_RECLAIM_BYTES_PER_CANDIDATE
            .saturating_mul(request.max_delete_batch.max(1) as u64),
    )
}

/// How often the idle scanner polls the event source for changes.
const EVENT_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// What an event-triggered pass inherits from the last request the main
/// loop sent: the configured roots and the mount's level and free space.
struct EventPassTemplate {
    paths: Vec<PathBuf>,
    pressure_level: PressureLevel,
    free_pct: Option<f64>,
    max_delete_batch: usize,
}

impl EventPassTemplate {
    fn from_request(request: &ScanRequest) -> Self {
        Self {
            paths: request.paths.clone(),
            pressure_level: request.pressure_level,
            free_pct: request.free_pct,
            max_delete_batch: request.max_delete_batch,
        }
    }
}

/// Poll the event source while the scanner is idle and, when events left
/// scan paths dirty at Green or Yellow, build the pass that reconciles them.
/// Under Orange and above the main loop drives passes on its own cadence.
/// The invalidation accumulates in `pending` until a pass consumes it, so a
/// pass deferred by pacing loses nothing.
fn event_triggered_request(
    source: Option<&mut ScannerEventSource>,
    pending: &mut Option<EventInvalidation>,
    last_poll: &mut Instant,
    template: Option<&EventPassTemplate>,
) -> Option<ScanRequest> {
    if last_poll.elapsed() < EVENT_POLL_INTERVAL {
        return None;
    }
    *last_poll = Instant::now();
    let source = source?;
    let template = template?;
    if !matches!(
        template.pressure_level,
        PressureLevel::Green | PressureLevel::Yellow
    ) {
        return None;
    }
    let fresh = source.drain();
    if fresh.requires_reconciliation() {
        match pending.as_mut() {
            Some(kept) => kept.merge(fresh),
            None => *pending = Some(fresh),
        }
    }
    if pending
        .as_ref()
        .is_none_or(|kept| !kept.requires_reconciliation())
    {
        return None;
    }
    Some(ScanRequest {
        paths: template.paths.clone(),
        urgency: 0.0,
        pressure_level: template.pressure_level,
        free_pct: template.free_pct,
        max_delete_batch: template.max_delete_batch,
        force_full_scan: false,
        config_update: None,
        catalog_roots: Vec::new(),
        maintenance: false,
        target_bytes: None,
    })
}

/// Dirty scan paths may be unwatched frontier subtrees below a configured
/// root, so a root counts as dirty when any dirty path lies under it.
fn dirty_under(dirty_roots: &BTreeSet<PathBuf>, path: &Path) -> bool {
    dirty_roots.contains(path) || dirty_roots.iter().any(|dirty| dirty.starts_with(path))
}

fn v2_active_scan_paths(
    request: &ScanRequest,
    dirty_roots: &BTreeSet<PathBuf>,
) -> Option<Vec<PathBuf>> {
    if request.force_full_scan || request.maintenance {
        return None;
    }
    match request.pressure_level {
        PressureLevel::Green | PressureLevel::Yellow => {
            if dirty_roots.is_empty() {
                Some(Vec::new())
            } else {
                Some(dirty_roots.iter().cloned().collect())
            }
        }
        PressureLevel::Orange | PressureLevel::Red | PressureLevel::Critical => None,
    }
}

fn v2_effective_parallelism(config: &ScannerConfig, pressure_level: PressureLevel) -> usize {
    let configured = config.parallelism.max(1);
    match pressure_level {
        PressureLevel::Green | PressureLevel::Yellow => 1,
        PressureLevel::Orange => configured.min(2),
        PressureLevel::Red | PressureLevel::Critical => configured.min(4),
    }
}

/// Whether the Btrfs compression tier (bd-rxq5) may start a pass. It rewrites
/// files in place, so it runs only where the policy lets the daemon change the
/// filesystem: not in observe or fallback-safe mode (the kill switch forces
/// the latter), and not under `scanner.dry_run`. When it may not, a pass
/// already running is told to stop (`CompressTier::stop_running_pass`).
fn compress_tier_may_run(config: &Config, mode: ActiveMode) -> bool {
    config.compress.enabled && !config.scanner.dry_run && mode.allows_deletion()
}

fn fallback_log_truncation_free_pct(pressure_level: PressureLevel) -> f64 {
    match pressure_level {
        PressureLevel::Green | PressureLevel::Yellow => 100.0,
        PressureLevel::Orange => 10.0,
        PressureLevel::Red | PressureLevel::Critical => 0.0,
    }
}

fn log_truncation_free_pct_for_request(request: &ScanRequest) -> f64 {
    request
        .free_pct
        .filter(|pct| pct.is_finite())
        .unwrap_or_else(|| fallback_log_truncation_free_pct(request.pressure_level))
}

/// Which of a pass's limits stopped it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PassStop {
    /// `scanner.prescan_time_budget_secs` — the *phase* is over, but the pass
    /// continues into the general walker.
    PrescanPhase,
    /// The pre-scan spent [`PRESCAN_CPU_SHARE`] of the pass's CPU allowance;
    /// like [`Self::PrescanPhase`] it ends only the phase.
    PrescanCpuShare,
    /// `scanner.scan_time_budget_secs` — the pass's wall ceiling.
    Wall,
    /// The daemon's measured CPU allowance for this pass (Q7).
    Cpu,
}

impl PassStop {
    /// The limit's name, for the operator-facing log line.
    const fn label(self) -> &'static str {
        match self {
            Self::PrescanPhase => "prescan wall budget",
            Self::PrescanCpuShare => "prescan cpu share",
            Self::Wall => "scan wall budget",
            Self::Cpu => "daemon cpu budget",
        }
    }

    /// Whether this stop ends the whole pass (as opposed to just the
    /// priority pre-scan phase).
    const fn ends_pass(self) -> bool {
        matches!(self, Self::Wall | Self::Cpu)
    }
}

/// The limits one scan pass runs under.
///
/// Before 0.6.2 there was a single `scan_deadline`, and the daemon-wide CPU
/// budget was folded into it by converting available CPU-seconds into wall
/// time as `cpu_secs / scanner.parallelism`. Because the token bucket is
/// clamped to its burst (5 CPU-seconds), that gave every discretionary pass a
/// hard wall ceiling of `burst / parallelism` — 0.6-0.7 s on the fleet's
/// 14-16 core hosts — which the priority pre-scan hit before it could
/// enumerate a large `/data/projects`. Keeping the CPU limit as a *measured*
/// CPU limit ([`PassCpuGuard`]) restores the configured wall budget
/// (`scanner.scan_time_budget_secs`, 900 s by default) as the thing that
/// actually bounds the pass.
struct PassLimits {
    scan_start: Instant,
    /// Wall ceiling for the whole pass.
    deadline: Instant,
    /// Wall ceiling for the priority pre-scan phase alone.
    prescan_deadline: Instant,
    /// Measured CPU allowance for the whole pass.
    cpu: PassCpuGuard,
}

impl PassLimits {
    /// The limits for a pass starting now.
    fn new(
        scan_start: Instant,
        deadline: Instant,
        prescan_budget: Duration,
        cpu: PassCpuGuard,
    ) -> Self {
        let prescan_deadline = if prescan_budget.is_zero() {
            deadline
        } else {
            deadline.min(scan_start + prescan_budget)
        };
        Self {
            scan_start,
            deadline,
            prescan_deadline,
            cpu,
        }
    }

    /// Whether the priority pre-scan must stop now, and which limit says so.
    /// The pass-ending limits are checked first so their verdict wins.
    fn prescan_stop(&mut self) -> Option<PassStop> {
        let now = Instant::now();
        if now >= self.deadline {
            return Some(PassStop::Wall);
        }
        if self.cpu.exhausted(now) {
            return Some(PassStop::Cpu);
        }
        if now >= self.prescan_deadline {
            return Some(PassStop::PrescanPhase);
        }
        self.cpu
            .allowance_secs()
            .is_some_and(|allowance| self.cpu.spent_secs() >= allowance * PRESCAN_CPU_SHARE)
            .then_some(PassStop::PrescanCpuShare)
    }

    /// Whether the general walk must stop now, and which limit says so.
    fn walk_stop(&mut self) -> Option<PassStop> {
        let now = Instant::now();
        if now >= self.deadline {
            return Some(PassStop::Wall);
        }
        self.cpu.exhausted(now).then_some(PassStop::Cpu)
    }

    /// Wall time since the pass started.
    fn elapsed(&self) -> Duration {
        self.scan_start.elapsed()
    }
}

/// Share of a pass's CPU allowance the priority pre-scan may spend before the
/// general walk takes over.
///
/// Since the CPU budget binds at Critical (41ad7f5), a pre-scan that probes
/// each nominee's tree spent the whole allowance on its own: on ts2
/// (2026-10-21) every pass after the restart's sixth stopped inside it after
/// 38-1,041 of /data/tmp's 23,301 top-level entries, and the walk never ran.
const PRESCAN_CPU_SHARE: f64 = 0.5;

/// Shortest gap between two operator-facing `SBH-2007` budget warnings.
const BUDGET_WARNING_INTERVAL: Duration = Duration::from_mins(5);

/// Whether a budget warning may be logged now, recording it if so.
fn claim_budget_warning(last: &mut Option<Instant>, now: Instant) -> bool {
    if last.is_some_and(|at| now.saturating_duration_since(at) < BUDGET_WARNING_INTERVAL) {
        return false;
    }
    *last = Some(now);
    true
}

/// The process's cumulative user+system CPU time in seconds, for
/// [`PassCpuGuard`].
fn current_scan_cpu_secs() -> Option<f64> {
    #[allow(clippy::cast_precision_loss)]
    current_scan_cpu_micros().map(|micros| micros as f64 / 1_000_000.0)
}

/// Paths whose mounts get a ballast pool.
///
/// Scan roots, special locations, the state dir and the configured ballast
/// dir's parent. Shared by the daemon and the CLI so `sbh ballast status`
/// enumerates exactly the daemon's pools.
#[must_use]
pub fn ballast_discovery_paths(
    config: &Config,
    special_locations: &SpecialLocationRegistry,
) -> Vec<PathBuf> {
    let mut paths = Vec::with_capacity(config.scanner.root_paths.len() + 4);
    for root in &config.scanner.root_paths {
        push_unique_path(&mut paths, root.clone());
    }
    for location in special_locations.all() {
        push_unique_path(&mut paths, location.path.clone());
    }
    if let Some(parent) = config.paths.state_file.parent() {
        push_unique_path(&mut paths, parent.to_path_buf());
    }
    if let Some(parent) = config.paths.ballast_dir.parent() {
        push_unique_path(&mut paths, parent.to_path_buf());
    }
    paths
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanEnqueueStatus {
    Queued,
    ReplacedStale,
    DeferredFull,
    Disconnected,
}

fn enqueue_scan_request(
    scan_tx: &Sender<ScanRequest>,
    scan_rx: &Receiver<ScanRequest>,
    request: ScanRequest,
    replace_on_full: bool,
) -> ScanEnqueueStatus {
    match scan_tx.try_send(request) {
        Ok(()) => ScanEnqueueStatus::Queued,
        Err(TrySendError::Full(request)) => {
            if !replace_on_full {
                return ScanEnqueueStatus::DeferredFull;
            }

            match scan_rx.try_recv() {
                Ok(_) => match scan_tx.try_send(request) {
                    Ok(()) => ScanEnqueueStatus::ReplacedStale,
                    Err(TrySendError::Full(_)) => ScanEnqueueStatus::DeferredFull,
                    Err(TrySendError::Disconnected(_)) => ScanEnqueueStatus::Disconnected,
                },
                Err(TryRecvError::Empty) => ScanEnqueueStatus::DeferredFull,
                Err(TryRecvError::Disconnected) => ScanEnqueueStatus::Disconnected,
            }
        }
        Err(TrySendError::Disconnected(_)) => ScanEnqueueStatus::Disconnected,
    }
}

fn full_disk_access_status_log_message(
    status: &FullDiskAccessStatus,
    previous_state: Option<FullDiskAccessState>,
    granted_logged: bool,
) -> Option<String> {
    match status.state {
        FullDiskAccessState::Granted
            if !granted_logged || previous_state != Some(FullDiskAccessState::Granted) =>
        {
            Some(format!(
                "macOS Full Disk Access granted for sbh: {}",
                status.doctor_message()
            ))
        }
        FullDiskAccessState::Missing if previous_state != Some(FullDiskAccessState::Missing) => {
            Some(format!(
                "macOS Full Disk Access missing for sbh; grant access and re-check with `sbh doctor --pal`: {}",
                status.doctor_message()
            ))
        }
        _ => None,
    }
}

fn daemon_activity_error_code(error: &SbhError) -> String {
    error.code().to_string()
}

/// Resolve the configured behavior matrix. Config validation already rejected
/// bad custom cells, so a failure here means the file changed underneath us;
/// fall back to the built-in default rather than refusing to run.
fn behavior_table_from_config(config: &Config) -> BehaviorDispatchTable {
    match BehaviorDispatchTable::from_config(&config.behavior) {
        Ok(table) => table,
        Err(details) => {
            eprintln!("[SBH-DAEMON] behavior config rejected ({details}); using the v0.6 preset");
            BehaviorDispatchTable::default()
        }
    }
}

/// Which structural certainty a cleanup action is willing to dispatch.
///
/// `HighConfidenceCandidates` (Green/Yellow in the v0.6 matrix) deletes only
/// candidates whose structural evidence is definite; `DefiniteCandidates` and
/// `MostPromisingCandidates` (Orange) also accept `Likely`; `AnyDefiniteCandidate`
/// (Red/Critical) dispatches every `Delete` verdict. `None`/`IdentifyOnly`
/// never dispatch (their batch limit is zero), so their gate is moot.
const fn min_certainty_for(action: CleanupAction) -> ArtifactCertainty {
    match action {
        CleanupAction::None
        | CleanupAction::IdentifyOnly
        | CleanupAction::HighConfidenceCandidates => ArtifactCertainty::Definite,
        CleanupAction::DefiniteCandidates | CleanupAction::MostPromisingCandidates => {
            ArtifactCertainty::Likely
        }
        CleanupAction::AnyDefiniteCandidate => ArtifactCertainty::Unclear,
    }
}

/// Drop candidates below the behavior cell's certainty gate. Returns the kept
/// candidates and how many were held back (for the executor log line).
fn retain_dispatchable_by_certainty(
    candidates: Vec<CandidacyScore>,
    min_certainty: ArtifactCertainty,
) -> (Vec<CandidacyScore>, usize) {
    let before = candidates.len();
    let kept: Vec<CandidacyScore> = candidates
        .into_iter()
        .filter(|candidate| candidate.decision.certainty >= min_certainty)
        .collect();
    let held_back = before - kept.len();
    (kept, held_back)
}

fn behavior_allows_scan(mode: BehaviorMode) -> bool {
    mode.scan_aggressiveness != ScanAggressiveness::Skip
}

fn behavior_allows_delete_dispatch(mode: BehaviorMode) -> bool {
    !matches!(
        mode.cleanup_action,
        CleanupAction::None | CleanupAction::IdentifyOnly
    )
}

fn behavior_delete_batch_limit(mode: BehaviorMode, configured_limit: usize) -> usize {
    if behavior_allows_delete_dispatch(mode) {
        configured_limit
    } else {
        0
    }
}

fn behavior_should_release_ballast(mode: BehaviorMode) -> bool {
    matches!(
        mode.ballast_action,
        BallastAction::Release | BallastAction::ReleaseFirst
    )
}

fn behavior_mode_summary(mode: BehaviorMode) -> String {
    format!(
        "scan={:?} cleanup={:?} ballast={:?} notify={:?}",
        mode.scan_aggressiveness,
        mode.cleanup_action,
        mode.ballast_action,
        mode.notification_priority
    )
}

fn behavior_emergency_event(
    source: &str,
    transition: &BehaviorTransition,
) -> Option<NotificationEvent> {
    if transition.to_memory != MemoryPressureLevel::Critical
        || transition.to_disk != PressureLevel::Critical
        || transition.to_mode.notification_priority != NotificationPriority::Emergency
    {
        return None;
    }

    Some(NotificationEvent::BehaviorEmergency {
        source: source.to_string(),
        memory_level: format!("{:?}", transition.to_memory),
        disk_level: format!("{:?}", transition.to_disk),
        action: behavior_mode_summary(transition.to_mode),
    })
}

#[derive(Debug, Clone, Copy, Default)]
struct StatusDumpCounters {
    window_scans: u64,
    window_scan_timeouts: u64,
    window_candidates: u64,
    window_deleted: u64,
    window_failed: u64,
    window_bytes_freed: u64,
    window_freed_basis: FreedBasis,
    window_bytes_freed_observed: Option<u64>,
    scans_total: u64,
    deletions_total: u64,
    bytes_freed_total: u64,
    freed_basis_total: FreedBasis,
    bytes_freed_observed_total: Option<u64>,
    errors_total: u64,
    dropped_log_events: u64,
}

struct StatusDumpPayloadInput<'a> {
    timestamp: String,
    version: &'static str,
    pid: u32,
    uptime_seconds: u64,
    response: &'a PressureResponse,
    mount_free_pct: Option<f64>,
    mount_total_bytes: Option<u64>,
    mount_available_bytes: Option<u64>,
    ballast_available: usize,
    ballast_total: usize,
    memory_info: Option<&'a MemoryInfo>,
    policy_mode: String,
    behavior_mode: BehaviorMode,
    last_predictive_action: String,
    last_ewma_confidence: f64,
    guard: Option<&'a GuardDiagnostics>,
    counters: StatusDumpCounters,
    thread_status: &'a [ThreadStatus],
}

fn pressure_level_json(level: PressureLevel) -> String {
    format!("{level:?}").to_lowercase()
}

fn finite_f64(value: f64) -> Option<f64> {
    value.is_finite().then_some(value)
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn thread_status_json(status: &ThreadStatus) -> Value {
    match status {
        ThreadStatus::Running {
            name,
            last_heartbeat,
        } => json!({
            "name": name,
            "status": "running",
            "last_heartbeat_age_ms": duration_millis(Instant::now().saturating_duration_since(*last_heartbeat)),
        }),
        ThreadStatus::Stalled {
            name,
            stalled_since,
        } => json!({
            "name": name,
            "status": "stalled",
            "stalled_for_ms": duration_millis(Instant::now().saturating_duration_since(*stalled_since)),
        }),
        ThreadStatus::Dead {
            name,
            died_at,
            error,
        } => json!({
            "name": name,
            "status": "dead",
            "dead_for_ms": duration_millis(Instant::now().saturating_duration_since(*died_at)),
            "error": error,
        }),
    }
}

fn memory_status_json(memory: &MemoryInfo) -> Value {
    let swap_used_bytes = memory
        .swap_total_bytes
        .saturating_sub(memory.swap_free_bytes);
    json!({
        "ram_total_bytes": memory.total_bytes,
        "ram_available_bytes": memory.available_bytes,
        "ram_free_pct": finite_f64(bytes_to_pct(memory.available_bytes, memory.total_bytes)),
        "swap_total_bytes": memory.swap_total_bytes,
        "swap_free_bytes": memory.swap_free_bytes,
        "swap_used_bytes": swap_used_bytes,
        "swap_used_pct": finite_f64(bytes_to_pct(swap_used_bytes, memory.swap_total_bytes)),
        "swap_thrash_risk": is_swap_thrash_risk(memory),
    })
}

fn guard_diagnostics_json(guard: &GuardDiagnostics) -> Value {
    json!({
        "status": guard.status.to_string(),
        "observation_count": guard.observation_count,
        "median_rate_error": finite_f64(guard.median_rate_error),
        "conservative_fraction": finite_f64(guard.conservative_fraction),
        "e_process_value": finite_f64(guard.e_process_value),
        "e_process_alarm": guard.e_process_alarm,
        "consecutive_clean": guard.consecutive_clean,
        "reason": &guard.reason,
    })
}

fn build_status_dump_payload(input: &StatusDumpPayloadInput<'_>) -> Value {
    let response = input.response;
    let counters = input.counters;
    json!({
        "event": "siginfo_status",
        "version": input.version,
        "pid": input.pid,
        "timestamp": input.timestamp,
        "uptime_seconds": input.uptime_seconds,
        "pressure": {
            "overall": pressure_level_json(response.level),
            "urgency": finite_f64(response.urgency),
            "causing_mount": response.causing_mount.to_string_lossy(),
            "free_pct": input.mount_free_pct.and_then(finite_f64),
            "available_bytes": input.mount_available_bytes,
            "total_bytes": input.mount_total_bytes,
            "predicted_seconds": response.predicted_seconds.and_then(finite_f64),
            "scan_interval_ms": duration_millis(response.scan_interval),
            "release_ballast_files": response.release_ballast_files,
            "max_delete_batch": response.max_delete_batch,
            "fallback_active": response.fallback_active,
        },
        "ballast": {
            "available": input.ballast_available,
            "total": input.ballast_total,
            "released": input.ballast_total.saturating_sub(input.ballast_available),
        },
            "memory": input.memory_info.map(memory_status_json),
            "policy": {
            "mode": &input.policy_mode,
            "behavior": input.behavior_mode,
            "last_predictive_action": &input.last_predictive_action,
            "last_ewma_confidence": finite_f64(input.last_ewma_confidence),
            "guard": input.guard.map(guard_diagnostics_json),
        },
        "counters": {
            "window": {
                "scans": counters.window_scans,
                "scan_timeouts": counters.window_scan_timeouts,
                "candidates": counters.window_candidates,
                "deleted": counters.window_deleted,
                "failed": counters.window_failed,
                "bytes_freed": counters.window_bytes_freed,
                "freed_basis": counters.window_freed_basis.label(),
                "bytes_freed_observed": counters.window_bytes_freed_observed,
            },
            "total": {
                "scans": counters.scans_total,
                "deletions": counters.deletions_total,
                "bytes_freed": counters.bytes_freed_total,
                "freed_basis": counters.freed_basis_total.label(),
                "bytes_freed_observed": counters.bytes_freed_observed_total,
                "errors": counters.errors_total,
                "dropped_log_events": counters.dropped_log_events,
            },
        },
        "threads": input
            .thread_status
            .iter()
            .map(thread_status_json)
            .collect::<Vec<_>>(),
    })
}

impl MonitoringDaemon {
    /// Build and initialize the daemon from configuration.
    pub fn init(config: Config, args: &DaemonArgs) -> Result<Self> {
        Self::init_with_platform(config, args, detect_platform()?)
    }

    #[allow(clippy::too_many_lines)]
    fn init_with_platform(
        config: Config,
        args: &DaemonArgs,
        platform: Arc<dyn Platform>,
    ) -> Result<Self> {
        let start_time = Instant::now();

        // 0. Liveness lock. Taken before anything else so a second daemon on
        // the same state directory fails fast instead of racing the first
        // one for ballast pools, the scanner index, and state.json.
        let daemon_lock = DaemonLock::acquire(&config.paths.state_file)?;
        if let Some(pidfile) = &args.pidfile
            && let Err(error) = std::fs::write(pidfile, format!("{}\n", std::process::id()))
        {
            eprintln!(
                "[SBH-DAEMON] could not write pidfile {}: {error}",
                pidfile.display()
            );
        }

        // 0. One id for this run: stamped on every activity log line and
        // written to state.json, so a log can be joined to the run that
        // produced it.
        let run_id = crate::daemon::self_monitor::generate_run_id();

        // 1. Initialize logger.
        let logger_config = DualLoggerConfig {
            sqlite_path: Some(config.paths.sqlite_db.clone()),
            jsonl_config: JsonlConfig::for_daemon(config.paths.jsonl_log.clone()),
            channel_capacity: 1024,
            run_id: Some(run_id.clone()),
        };
        let (logger_handle, logger_join) = spawn_logger(logger_config)?;

        // 2. Signal handler.
        let signal_handler = SignalHandler::new();

        // 3. Watchdog. The generated unit sets WatchdogSec= but does not pass
        // --watchdog-sec, so the timeout is read from systemd's WATCHDOG_USEC.
        let watchdog_sec = resolve_watchdog_sec(
            args.watchdog_sec,
            std::env::var("WATCHDOG_USEC").ok().as_deref(),
            std::env::var("WATCHDOG_PID").ok().as_deref(),
            std::process::id(),
        );
        let watchdog = WatchdogHeartbeat::new(watchdog_sec, platform.service_manager());

        // 4. Filesystem collector.
        let fs_collector = FsStatsCollector::new(
            Arc::clone(&platform),
            Duration::from_millis(config.telemetry.fs_cache_ttl_ms),
        );

        // 5. Discover special locations.
        let special_locations = SpecialLocationRegistry::discover(
            platform.as_ref(),
            &[], // custom paths from config can be added later
        )?;

        // 6. Initialize ballast coordinator (multi-volume).
        let discovery_paths = ballast_discovery_paths(&config, &special_locations);
        let mut ballast_coordinator = BallastPoolCoordinator::discover_inner(
            &config.ballast,
            &discovery_paths,
            platform.as_ref(),
            &platform,
            Some(config.paths.ballast_dir.as_path()),
        )?;
        ballast_coordinator.set_provision_floor_rule(config.ballast_provision_floor());
        // bd-rc-master-ajg1.7.4: the daemon's own files against the mounts
        // it reclaims. Not a refusal (single-volume hosts are common), but
        // said once at startup, carried in state.json, and acted on while
        // that mount is pressured (JSONL mirrored to the RAM fallback).
        let logging_placement = {
            let mut monitored: BTreeSet<PathBuf> = BTreeSet::new();
            for path in config
                .scanner
                .root_paths
                .iter()
                .chain(special_locations.all().iter().map(|l| &l.path))
            {
                if let Ok(stats) = fs_collector.collect(path) {
                    monitored.insert(stats.mount_point);
                }
            }
            monitored.extend(
                ballast_coordinator
                    .inventory()
                    .into_iter()
                    .filter(|pool| !pool.skipped)
                    .map(|pool| pool.mount_point),
            );
            assess_logging_placement(
                |path| {
                    nearest_existing_ancestor(path)
                        .and_then(|existing| fs_collector.collect(&existing).ok())
                        .map(|stats| stats.mount_point)
                },
                &[
                    config.paths.sqlite_db.as_path(),
                    config.paths.jsonl_log.as_path(),
                    config.paths.state_file.as_path(),
                ],
                &monitored,
            )
        };
        eprintln!(
            "[SBH-DAEMON] logging.on_monitored_fs={} device={} paths=[{}]",
            logging_placement.on_monitored_fs,
            logging_placement.device,
            logging_placement.paths.join(", ")
        );
        if logging_placement.on_monitored_fs {
            logger_handle.send(ActivityEvent::Warning {
                code: "SBH-1105".to_string(),
                message: format!(
                    "the activity database, JSONL log or state file live on {}, which sbh \
                     reclaims ({}): move them to a volume sbh does not reclaim, or accept \
                     that logging degrades to the RAM fallback under pressure",
                    logging_placement.device,
                    logging_placement.paths.join(", ")
                ),
            });
        }
        // Surface the resolved ballast directories so the configured
        // `[paths] ballast_dir` is observable at startup (issue #14).
        eprintln!(
            "[SBH-DAEMON] configured ballast_dir: {}",
            config.paths.ballast_dir.display()
        );
        for inv in ballast_coordinator.inventory() {
            eprintln!(
                "[SBH-DAEMON] ballast pool on mount {} -> {}{}",
                inv.mount_point.display(),
                inv.ballast_dir.display(),
                if inv.skipped { " (skipped)" } else { "" }
            );
            for dir in &inv.unreachable_reserve {
                eprintln!(
                    "[SBH-DAEMON] ballast reserve at {} is read-only to this service and \
                     cannot be released for {} (systemd ProtectSystem=strict without it in \
                     ReadWritePaths=): grant it there, or release those files by hand",
                    dir.display(),
                    inv.mount_point.display()
                );
            }
        }

        // 7. Release controller.
        let mut release_controller =
            BallastReleaseController::new(config.ballast.replenish_cooldown_minutes);
        if let Ok(previous) = SelfMonitor::read_state(&config.paths.state_file) {
            for saved in previous.ballast_pools {
                let mount = PathBuf::from(&saved.mount);
                let Some(pool) = ballast_coordinator.pool_for_mount(&mount) else {
                    continue;
                };
                if saved.skipped {
                    continue;
                }
                if let Some(history) = saved.release_history
                    && release_controller.restore_pool_history(&mount, &pool.ballast_dir, history)
                    && let Some(efficiency) = saved.release_efficiency
                {
                    release_controller.set_release_efficiency(&mount, efficiency);
                }
            }
        }

        // 8. Scoring engine.
        let scoring_engine =
            ScoringEngine::from_config(&config.scoring, config.scanner.min_file_age_minutes);

        // 9. VOI Scheduler.
        let mut voi_scheduler = VoiScheduler::new(config.scheduler.clone());
        for root in &config.scanner.root_paths {
            voi_scheduler.register_path(root.clone());
        }

        // 10. Shared executor config (atomics for live reload propagation).
        let shared_executor_config = Arc::new(SharedExecutorConfig::new(
            config.scanner.dry_run,
            config.scanner.max_delete_batch,
            config.scoring.min_score,
            config.scanner.repeat_deletion_base_cooldown_secs,
            config.scanner.repeat_deletion_max_cooldown_secs,
            config.scanner.quarantine_enabled,
            config.scanner.quarantine_ttl_hours.saturating_mul(3600),
        ));
        shared_executor_config.set_planner(
            config.scoring.batch_risk_budget_by_level,
            config.scoring.false_positive_loss,
        );
        let compress_tier =
            CompressTier::with_first(Arc::clone(&shared_executor_config.compression_first));

        let shared_scoring_config = Arc::new(RwLock::new(config.scoring.clone()));
        let shared_scanner_config = Arc::new(RwLock::new(config.scanner.clone()));

        // Regret labels: rebuilt from the ledger so calibration survives a
        // restart.
        let regret = Arc::new(SharedRegret::new(&config));
        replay_regret_outcomes(&regret, &config.paths.sqlite_db);

        // 11. Self-monitor (writes state.json for CLI, tracks health).
        let mut self_monitor = SelfMonitor::from_telemetry_config(
            config.paths.state_file.clone(),
            Arc::clone(&platform),
            &config.telemetry,
        );
        self_monitor.set_run_id(run_id);
        self_monitor.set_logging_snapshot(logging_placement.clone());
        let process_io_history = ProcessIoHistory::load_or_new(
            ProcessIoHistory::snapshot_path_for_state_file(&config.paths.state_file),
        );
        let burst_stats = BurstStats::load_or_new(BurstStats::snapshot_path_for_state_file(
            &config.paths.state_file,
        ));

        // 12. Thread heartbeats for worker health detection.
        let scanner_heartbeat = ThreadHeartbeat::new("sbh-scanner");
        let executor_heartbeat = ThreadHeartbeat::new("sbh-executor");

        // 13. Notification manager.
        let notification_manager = NotificationManager::from_config(&config.notifications);

        // 14. Policy engine (progressive delivery gates for deletion pipeline).
        let policy_engine = Arc::new(Mutex::new(PolicyEngine::new(config.policy.clone())));
        let (control_tx, control_rx) = bounded::<MainLoopCommand>(CONTROL_CHANNEL_CAP);
        let shared_guard_diagnostics = Arc::new(RwLock::new(None));
        let behavior_state = PressureBehaviorState::new(
            behavior_table_from_config(&config),
            MemoryPressureLevel::Unknown,
            PressureLevel::Green,
        );

        let prediction_config = config.pressure.prediction.clone();
        // Q7: calibrated to the CPU already spent on startup so that work
        // (config load, ballast discovery) is not charged to the first tick.
        let cpu_budget = Arc::new(Mutex::new(
            CpuBudget::new(
                paced_pct(
                    config.telemetry.cpu_budget_pct,
                    behavior_state.mode.scan_aggressiveness,
                ),
                Instant::now(),
                self_monitor.current_cpu_secs(),
            )
            .with_burst_secs(config.telemetry.cpu_budget_burst_secs),
        ));

        Ok(Self {
            config,
            platform,
            logger_handle,
            logger_join: Some(logger_join),
            signal_handler,
            watchdog,
            cpu_budget,
            daemon_lock,
            pidfile: args.pidfile.clone(),
            fs_collector,
            mount_monitors: HashMap::new(),
            mount_controllers: HashMap::new(),
            mount_responses: Vec::new(),
            wake_next_tick: WakeSignals::default(),
            pending_recovery: HashSet::new(),
            policy_transitions_seen: 0,
            floor_limited: HashSet::new(),
            reclaim_alerts: AlertThrottle::default(),
            catalog_root_cache: HashMap::new(),
            catalog_epochs: HashMap::new(),
            emergency_mounts: HashSet::new(),
            mount_rates: HashMap::new(),
            logging_placement,
            logging_level_logged: None,
            logging_ram_checked_at: None,
            special_alerts: AlertThrottle::default(),
            last_maintenance_scan: None,
            last_quarantine_sweep: None,
            last_forecast_log: HashMap::new(),
            quarantine_held: HashMap::new(),
            special_locations,
            ballast_coordinator,
            release_controller,
            notification_manager,
            policy_engine,
            scoring_engine,
            voi_scheduler,
            last_voi_plan: None,
            shared_executor_config,
            regret,
            shared_scoring_config,
            shared_scanner_config,
            start_time,
            last_pressure_level: PressureLevel::Green,
            last_notified_pressure_level: PressureLevel::Green,
            last_pressure_notify_time: None,
            last_special_scan: HashMap::new(),
            last_special_notify: HashMap::new(),
            last_predictive_warning: None,
            last_predictive_level: None,
            last_ewma_confidence: 0.0,
            predictive_policy: PredictiveActionPolicy::from_config(prediction_config),
            last_predictive_action: PredictiveAction::Clear,
            last_tick_cleanup_ran: false,
            last_swap_thrash_warning: None,
            swap_thrash_active: false,
            last_scan_channel_warn: None,
            forced_scan_pending_since: None,
            scan_channel_warn_suppressed: 0,
            last_device_affinity_warn: None,
            attribution_reported: HashMap::new(),
            attribution_pressured_since: HashMap::new(),
            compress_tier,
            target_tier: TargetTier::default(),
            last_summary_report: Instant::now(),
            summary_scans: 0,
            summary_scan_timeouts: 0,
            summary_candidates: 0,
            summary_deleted: 0,
            summary_failed: 0,
            summary_bytes_freed: 0,
            summary_freed_basis: FreedBasis::Observed,
            summary_bytes_freed_observed: Some(0),
            last_full_disk_access_check: None,
            last_full_disk_access_state: None,
            full_disk_access_granted_logged: false,
            process_io_history,
            burst_stats,
            last_scan_completed: None,
            self_monitor,
            tick_throttle: AdaptiveTickThrottle::default(),
            control_tx,
            control_rx,
            control_server: None,
            pending_control: Vec::new(),
            pending_state_replies: Vec::new(),
            behavior_state,
            scanner_heartbeat,
            executor_heartbeat,
            shared_guard_diagnostics,
            prediction_scorecard: PredictionScorecard::new(200),
        })
    }

    fn maybe_log_full_disk_access_status(&mut self, force: bool) {
        if !force
            && self
                .last_full_disk_access_check
                .is_some_and(|checked_at| checked_at.elapsed() < FULL_DISK_ACCESS_RECHECK_INTERVAL)
        {
            return;
        }

        self.last_full_disk_access_check = Some(Instant::now());
        match self.platform.full_disk_access_status() {
            Ok(status) => {
                if let Some(message) = full_disk_access_status_log_message(
                    &status,
                    self.last_full_disk_access_state,
                    self.full_disk_access_granted_logged,
                ) {
                    self.logger_handle.send(ActivityEvent::Info { message });
                }

                self.full_disk_access_granted_logged = match status.state {
                    FullDiskAccessState::Granted => true,
                    FullDiskAccessState::Missing => false,
                    _ => self.full_disk_access_granted_logged,
                };
                self.last_full_disk_access_state = Some(status.state);
            }
            Err(error) => {
                self.logger_handle.send(ActivityEvent::Error {
                    code: daemon_activity_error_code(&error),
                    message: format!("Full Disk Access recheck failed: {error}"),
                });
            }
        }
    }

    /// bd-rc-master-ajg1.7.4: when the mount carrying the daemon's own files
    /// is a reclaim target, its level drives the JSONL mirror. Orange or
    /// worse turns the RAM mirror on, unless that RAM is itself short
    /// (bd-ffjj); Yellow or better turns it off. While pressured, the RAM
    /// headroom is re-checked every [`LOGGING_RAM_RECHECK`], so a mirror stops
    /// when swap fills and a refused one starts once RAM recovers. One log
    /// line per level or mirror change, never per tick.
    fn note_logging_mount_level(&mut self, mount: &Path, level: PressureLevel) {
        if !self.logging_placement.on_monitored_fs
            || mount.to_string_lossy() != self.logging_placement.device
        {
            return;
        }
        let pressured = matches!(
            level,
            PressureLevel::Orange | PressureLevel::Red | PressureLevel::Critical
        );
        let level_changed = self.logging_level_logged != Some(level);
        let now = Instant::now();
        if !level_changed && !logging_ram_recheck_due(pressured, self.logging_ram_checked_at, now) {
            return;
        }
        self.logging_level_logged = Some(level);
        let refusal = if pressured {
            self.logging_ram_checked_at = Some(now);
            // A margin to start, the plain floors to keep: no flapping at a
            // threshold (bd-sz85).
            let headroom = if self.logging_placement.mirroring {
                crate::monitor::ram_scratch::RamLogHeadroom::Keep
            } else {
                crate::monitor::ram_scratch::RamLogHeadroom::Start
            };
            crate::monitor::ram_scratch::ram_log_mirror_refusal_for(
                self.platform.as_ref(),
                &crate::logger::jsonl::ram_fallback_path(),
                headroom,
            )
        } else {
            self.logging_ram_checked_at = None;
            None
        };
        let mirror = pressured && refusal.is_none();
        let mirror_changed = mirror != self.logging_placement.mirroring;
        if !level_changed && !mirror_changed {
            return;
        }
        let level_name = format!("{level:?}").to_lowercase();
        self.logging_placement.level = Some(level_name.clone());
        if mirror_changed {
            self.logging_placement.mirroring = mirror;
            self.logger_handle.mirror_jsonl(mirror);
        }
        eprintln!(
            "[SBH-DAEMON] logging.on_monitored_fs=true device={} level={level_name} mirror_to_ram={}{}",
            self.logging_placement.device,
            self.logging_placement.mirroring,
            refusal.map_or_else(String::new, |reason| format!(" (not mirroring: {reason})"))
        );
        self.self_monitor
            .set_logging_snapshot(self.logging_placement.clone());
    }

    /// The reserve the mount's observed write bursts call for, and how long
    /// `present_bytes` would last at that burst rate; `None` until the mount
    /// has closed a reaction window.
    fn burst_reserve(&self, mount: &Path, present_bytes: u64) -> Option<ReserveBurst> {
        let file_size = self
            .config
            .ballast
            .effective_file_size_bytes(&mount.to_string_lossy());
        let estimate = self.burst_stats.estimate(mount, file_size)?;
        Some(ReserveBurst {
            recommended_bytes: estimate.bytes,
            q99_bytes: estimate.burst_q99_bytes,
            windows: estimate.windows,
            reaction_window_secs: estimate.window_secs,
            method: estimate.method,
            horizon_minutes: estimate.horizon_minutes(present_bytes),
        })
    }

    fn sample_process_io_history(&mut self) {
        let platform = Arc::clone(&self.platform);
        let (report, error) = self
            .process_io_history
            .maybe_sample(platform.as_ref(), Instant::now());
        if !report.sampled {
            return;
        }

        if let Some(error) = error {
            self.logger_handle.send(ActivityEvent::Error {
                code: "SBH-1102".to_string(),
                message: format!("process I/O history sample failed: {error}"),
            });
        }
    }

    fn start_memory_pressure_subscription(
        &self,
        tx: Sender<MemoryPressureEvent>,
    ) -> Option<crate::platform::types::SubscriptionHandle> {
        let callback = Box::new(move |pressure: MemoryPressure| {
            let event = MemoryPressureEvent {
                pressure,
                received_at: Instant::now(),
            };
            let _ = tx.try_send(event);
        });

        match self.platform.subscribe_memory_pressure(callback) {
            Ok(handle) => {
                self.logger_handle.send(ActivityEvent::Info {
                    message: format!("memory pressure subscription active: {}", handle.source),
                });
                Some(handle)
            }
            Err(error) => {
                self.logger_handle.send(ActivityEvent::Error {
                    code: daemon_activity_error_code(&error),
                    message: format!("memory pressure subscription unavailable: {error}"),
                });
                None
            }
        }
    }

    fn seed_memory_pressure_behavior(&mut self, disk_level: PressureLevel) {
        let memory_level = match self.platform.memory_pressure() {
            Ok(pressure) => pressure.level,
            Err(error) => {
                self.logger_handle.send(ActivityEvent::Error {
                    code: daemon_activity_error_code(&error),
                    message: format!("initial memory pressure read failed: {error}"),
                });
                MemoryPressureLevel::Unknown
            }
        };
        self.update_behavior_mode(memory_level, disk_level, "startup", Duration::ZERO);
        self.log_behavior_matrix("startup");
    }

    /// Log the effective behavior matrix so operators can see, in the journal
    /// and the activity log, which cells the daemon will act on.
    fn log_behavior_matrix(&self, source: &str) {
        let rendered = self.behavior_state.table().render();
        eprintln!("[SBH-DAEMON] {source}: {rendered}");
        self.logger_handle.send(ActivityEvent::Info {
            message: format!("{source}: {rendered}"),
        });
    }

    fn update_behavior_mode(
        &mut self,
        memory_level: MemoryPressureLevel,
        disk_level: PressureLevel,
        source: &str,
        latency: Duration,
    ) {
        let hysteresis = if source == "startup" {
            Duration::ZERO
        } else {
            Duration::from_secs(self.config.pressure.behavior_hysteresis_secs)
        };
        match self.behavior_state.update_with_hysteresis(
            memory_level,
            disk_level,
            Instant::now(),
            hysteresis,
        ) {
            BehaviorUpdate::Applied(transition) => {
                self.shared_executor_config
                    .set_min_certainty(min_certainty_for(transition.to_mode.cleanup_action));
                self.cpu_budget.lock().set_pct(paced_pct(
                    self.config.telemetry.cpu_budget_pct,
                    transition.to_mode.scan_aggressiveness,
                ));
                let message = format!(
                    "behavior mode changed source={source} latency_ms={} memory={:?}->{:?} \
                     disk={:?}->{:?} mode=({}) -> ({})",
                    latency.as_millis(),
                    transition.from_memory,
                    transition.to_memory,
                    transition.from_disk,
                    transition.to_disk,
                    behavior_mode_summary(transition.from_mode),
                    behavior_mode_summary(transition.to_mode)
                );
                eprintln!("[SBH-DAEMON] {message}");
                self.logger_handle.send(ActivityEvent::Info { message });
                if let Some(event) = behavior_emergency_event(source, &transition) {
                    self.notification_manager.notify(&event);
                }
            }
            BehaviorUpdate::Deferred {
                direction,
                remaining,
                repeated: false,
            } => {
                let message = format!(
                    "behavior mode transition deferred source={source} direction={direction:?} \
                     remaining_ms={}",
                    remaining.as_millis()
                );
                eprintln!("[SBH-DAEMON] {message}");
            }
            BehaviorUpdate::Deferred { repeated: true, .. } | BehaviorUpdate::Unchanged => {}
        }
    }

    fn drain_memory_pressure_events(
        &mut self,
        rx: &Receiver<MemoryPressureEvent>,
        disk_level: PressureLevel,
    ) {
        while let Ok(event) = rx.try_recv() {
            self.update_behavior_mode(
                event.pressure.level,
                disk_level,
                "memory_pressure",
                event.received_at.elapsed(),
            );
        }
    }

    /// Log every policy engine transition recorded since the last call as a
    /// `policy_transition` activity event (C-EVENT), in order.
    fn emit_policy_transitions(&mut self) {
        let (events, total) = {
            let policy = self.policy_engine.lock();
            let events: Vec<ActivityEvent> = policy
                .transitions_after(self.policy_transitions_seen)
                .iter()
                .map(|entry| ActivityEvent::PolicyTransition {
                    transition: entry.transition.clone(),
                    from: entry.from.clone(),
                    to: entry.to.clone(),
                    reason: entry.reason.clone(),
                })
                .collect();
            (events, policy.transitions_total())
        };
        for event in events {
            if let ActivityEvent::PolicyTransition {
                transition,
                from,
                to,
                reason,
            } = &event
            {
                eprintln!("[SBH-POLICY] {transition}: {from} -> {to}");
                self.notification_manager
                    .notify(&NotificationEvent::PolicyTransition {
                        transition: transition.clone(),
                        from: from.clone(),
                        to: to.clone(),
                        reason: reason.clone(),
                    });
            }
            self.logger_handle.send(event);
        }
        self.policy_transitions_seen = total;
    }

    /// Feed the process's CPU time to the budget, log the once-a-minute
    /// deficit line, raise the Warning after five over-budget minutes, and
    /// return how much longer this tick should sleep.
    fn observe_cpu_budget(&mut self, level: PressureLevel) -> Duration {
        let now = Instant::now();
        let cpu_secs = self.self_monitor.current_cpu_secs();
        let (tick, budget_yield, snapshot) = {
            let mut budget = self.cpu_budget.lock();
            let tick = budget.observe(now, cpu_secs);
            let cap = MAX_TICK_YIELD.min(self.watchdog.interval() / 2);
            (tick, budget.yield_for(level, cap), budget.snapshot(now))
        };
        if tick.log_exceeded {
            let message = format!(
                "cpu budget exceeded pct={} used_pct_1m={:.1} deficit_secs={:.1} level={:?} yield_ms={}",
                snapshot.pct,
                snapshot.used_pct_1m,
                snapshot.deficit_secs,
                level,
                duration_millis(budget_yield)
            );
            eprintln!("[SBH-DAEMON] {message}");
            self.logger_handle.send(ActivityEvent::Warning {
                code: "SBH-3004".to_string(),
                message,
            });
        }
        if let Some(minutes) = tick.warn_after_minutes {
            self.notification_manager
                .notify(&NotificationEvent::CpuBudgetExceeded {
                    pct: snapshot.pct,
                    used_pct_1m: snapshot.used_pct_1m,
                    minutes,
                });
        }
        budget_yield
    }

    fn sleep_with_memory_pressure_events(
        &mut self,
        rx: &Receiver<MemoryPressureEvent>,
        disk_level: PressureLevel,
        interval: Duration,
    ) {
        let deadline = Instant::now() + interval;
        loop {
            let now = Instant::now();
            if self.signal_handler.should_shutdown() {
                break;
            }
            let Some(remaining) = deadline.checked_duration_since(now) else {
                break;
            };
            if remaining.is_zero() {
                break;
            }
            if self.signal_handler.has_pending_status_dump() {
                break;
            }

            // Systemd watchdog heartbeat during long sleeps / throttle stages.
            self.watchdog
                .maybe_notify(&format!("pressure={disk_level:?} status=sleeping"));

            let wait = remaining.min(MEMORY_PRESSURE_WAKE_INTERVAL);
            // A control-socket command ends the sleep so the next tick runs
            // it at once instead of after the remaining interval.
            let control_rx = self.control_rx.clone();
            crossbeam_channel::select! {
                recv(rx) -> event => match event {
                    Ok(event) => {
                        self.update_behavior_mode(
                            event.pressure.level,
                            disk_level,
                            "memory_pressure",
                            event.received_at.elapsed(),
                        );
                        self.drain_memory_pressure_events(rx, disk_level);
                    }
                    Err(_) => break,
                },
                recv(control_rx) -> command => {
                    if let Ok(command) = command {
                        self.pending_control.push(command);
                    }
                    break;
                }
                // No new event will come for a deferred target; retry it
                // so it applies when its hysteresis window ends.
                default(wait) => {
                    if self.behavior_state.has_pending_target() {
                        self.update_behavior_mode(
                            self.behavior_state.latest_memory_level(),
                            disk_level,
                            "deferred",
                            Duration::ZERO,
                        );
                    }
                }
            }
        }
    }

    // ──────────────────── control socket (bd-rc-master-ajg1.4.9) ────────────────────

    fn start_control_server(&mut self) {
        let path = self.daemon_lock.control_socket_path().to_path_buf();
        let backend = Arc::new(DaemonControlBackend {
            signal_handler: self.signal_handler.clone(),
            control_tx: self.control_tx.clone(),
            logger: self.logger_handle.clone(),
            policy_engine: Arc::clone(&self.policy_engine),
            state_file: self.config.paths.state_file.clone(),
            sqlite_db: self.config.paths.sqlite_db.clone(),
            config_file: self.config.paths.config_file.clone(),
            started_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            start_instant: self.start_time,
        });
        match ControlServer::start(&path, self.daemon_lock.token(), backend) {
            Ok(server) => {
                eprintln!("[SBH-CONTROL] listening on {}", server.path().display());
                self.control_server = Some(server);
            }
            Err(error) => {
                eprintln!("[SBH-CONTROL] control socket unavailable: {error}");
                self.logger_handle.send(ActivityEvent::Error {
                    code: error.code().to_string(),
                    message: format!("control socket unavailable at {}: {error}", path.display()),
                });
            }
        }
    }

    /// Run everything the control socket queued for the main loop.
    fn drain_control_commands(&mut self) {
        let mut commands = std::mem::take(&mut self.pending_control);
        while let Ok(command) = self.control_rx.try_recv() {
            commands.push(command);
        }
        for command in commands {
            match command {
                MainLoopCommand::Wake => {}
                MainLoopCommand::WriteState(reply) => {
                    self.self_monitor.force_next_write();
                    self.pending_state_replies.push(reply);
                }
                MainLoopCommand::Ballast { action, reply } => {
                    let result = self.execute_ballast_action(&action);
                    let _ = reply.try_send(result);
                }
            }
        }
    }

    /// Answer the `status` requests that waited for this tick's state write.
    fn flush_state_replies(&mut self) {
        for reply in self.pending_state_replies.drain(..) {
            let _ = reply.try_send(());
        }
    }

    fn execute_ballast_action(
        &mut self,
        action: &ControlBallastAction,
    ) -> std::result::Result<Value, String> {
        let requested = match action {
            ControlBallastAction::Release { mount, .. }
            | ControlBallastAction::Replenish { mount } => mount.clone(),
        };
        let mounts: Vec<PathBuf> = requested.map_or_else(
            || {
                self.ballast_coordinator
                    .inventory()
                    .into_iter()
                    .map(|pool| pool.mount_point)
                    .collect()
            },
            |mount| vec![mount],
        );
        if mounts.is_empty() {
            return Err("no ballast pool is configured".to_string());
        }
        let mut pools = Vec::new();
        for mount in mounts {
            let pool_mount = self.pool_mount(&mount);
            if let Some(pool) = self.ballast_coordinator.pool_for_mount(&mount) {
                self.release_controller
                    .bind_pool(&pool_mount, &pool.ballast_dir);
            }
            // Operator-driven changes are logged like the daemon's own so the
            // Timeline and `sbh stats` see them; the release controller is
            // told too, so an operator's release is not refilled at once.
            let outcome = match action {
                ControlBallastAction::Release { count, .. } => {
                    match self.ballast_coordinator.release_for_mount(&mount, *count) {
                        Ok(Some(report)) => {
                            self.release_controller
                                .on_released(&pool_mount, report.files_released);
                            self.log_control_ballast_release(&mount, &report.released);
                            Ok(json!({
                                "mount": mount,
                                "released": report.files_released,
                                "bytes_freed": report.bytes_freed,
                                "warnings": report.warnings,
                                "errors": report.errors,
                            }))
                        }
                        Ok(None) => Ok(
                            json!({ "mount": mount, "released": 0, "bytes_freed": 0, "note": "no pool or nothing to release" }),
                        ),
                        Err(error) => Err(error),
                    }
                }
                ControlBallastAction::Replenish { .. } => {
                    match self.ballast_coordinator.replenish_for_mount(&mount, None) {
                        Ok(Some(report)) => {
                            if report.files_created > 0 {
                                self.release_controller
                                    .on_replenished(&pool_mount, report.files_created);
                            }
                            for (path, size_bytes) in &report.created {
                                self.logger_handle.send(ActivityEvent::BallastReplenished {
                                    path: path.display().to_string(),
                                    size_bytes: *size_bytes,
                                });
                            }
                            Ok(json!({
                                "mount": mount,
                                "created": report.files_created,
                                "skipped": report.files_skipped,
                                "skipped_for_floor": report.skipped_for_floor,
                                "bytes": report.total_bytes,
                                "errors": report.errors,
                            }))
                        }
                        Ok(None) => Ok(
                            json!({ "mount": mount, "created": 0, "note": "no pool on this mount" }),
                        ),
                        Err(error) => Err(error),
                    }
                }
            };
            match outcome {
                Ok(value) => pools.push(value),
                Err(error) => return Err(format!("{}: {error}", mount.display())),
            }
        }
        Ok(json!({ "pools": pools }))
    }

    /// Activity events for a release the operator asked for over the control
    /// socket: `pressure` says so, `free_pct` is the mount's current figure.
    fn log_control_ballast_release(&self, mount: &Path, released: &[(PathBuf, u64)]) {
        let free_pct = self
            .fs_collector
            .collect(mount)
            .map_or(0.0, |stats| stats.free_pct());
        for (path, size_bytes) in released {
            self.logger_handle.send(ActivityEvent::BallastReleased {
                path: path.display().to_string(),
                size_bytes: *size_bytes,
                pressure: "control".to_string(),
                free_pct,
            });
        }
    }

    fn emit_status_dump(&self, response: &PressureResponse) {
        let mount_stats = self.fs_collector.collect(&response.causing_mount).ok();
        let ballast_inventory = self.ballast_coordinator.inventory();
        let ballast_available = ballast_inventory
            .iter()
            .map(|entry| entry.files_available)
            .sum();
        let ballast_total = ballast_inventory
            .iter()
            .map(|entry| entry.files_total)
            .sum();
        let memory_info = self.platform.memory_info().ok();
        let health = self.self_monitor.health_snapshot(
            &[
                Arc::clone(&self.scanner_heartbeat),
                Arc::clone(&self.executor_heartbeat),
            ],
            THREAD_STALL_THRESHOLD,
            response.level,
        );
        let guard = self.shared_guard_diagnostics.read().clone();

        let payload_input = StatusDumpPayloadInput {
            timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            version: env!("CARGO_PKG_VERSION"),
            pid: std::process::id(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            response,
            mount_free_pct: mount_stats
                .as_ref()
                .map(crate::platform::pal::FsStats::free_pct),
            mount_total_bytes: mount_stats.as_ref().map(|stats| stats.total_bytes),
            mount_available_bytes: mount_stats.as_ref().map(|stats| stats.available_bytes),
            ballast_available,
            ballast_total,
            memory_info: memory_info.as_ref(),
            policy_mode: self.policy_engine.lock().mode().to_string(),
            behavior_mode: self.behavior_state.mode,
            last_predictive_action: format!("{:?}", self.last_predictive_action),
            last_ewma_confidence: self.last_ewma_confidence,
            guard: guard.as_ref(),
            counters: StatusDumpCounters {
                window_scans: self.summary_scans,
                window_scan_timeouts: self.summary_scan_timeouts,
                window_candidates: self.summary_candidates,
                window_deleted: self.summary_deleted,
                window_failed: self.summary_failed,
                window_bytes_freed: self.summary_bytes_freed,
                window_freed_basis: self.summary_freed_basis,
                window_bytes_freed_observed: self.summary_bytes_freed_observed,
                scans_total: self.self_monitor.scan_count,
                deletions_total: self.self_monitor.deletions_total,
                bytes_freed_total: self.self_monitor.bytes_freed_total,
                freed_basis_total: self.self_monitor.freed_basis,
                bytes_freed_observed_total: self.self_monitor.bytes_freed_observed_total,
                errors_total: self.self_monitor.errors_total,
                dropped_log_events: self.logger_handle.dropped_events(),
            },
            thread_status: &health.thread_status,
        };
        let payload = build_status_dump_payload(&payload_input);

        eprintln!("{payload}");
    }

    // One tick's worth of bookkeeping in program order; splitting it would
    // only scatter the state-file fields it fills.
    #[allow(clippy::too_many_lines)]
    fn maybe_write_self_monitor_state(&mut self, response: &PressureResponse) -> SelfMonitorTick {
        // Use the causing mount from the worst response so the state file
        // reflects the mount that actually drove the pressure level, not the
        // primary path which may be healthy.
        let state_path = &response.causing_mount;
        let free_pct = self
            .fs_collector
            .collect(state_path)
            .map_or(0.0, |s| s.free_pct());
        let mount_str = state_path.to_string_lossy().into_owned();
        let ballast_available = self
            .ballast_coordinator
            .inventory()
            .iter()
            .map(|i| i.files_available)
            .sum();
        let ballast_total = self
            .ballast_coordinator
            .inventory()
            .iter()
            .map(|i| i.files_total)
            .sum();
        // The per-mount inventory the dashboard lists and scopes its
        // release/replenish to; sorted so two writes agree on the order.
        let mut pools: Vec<super::self_monitor::BallastPoolState> = self
            .ballast_coordinator
            .inventory()
            .into_iter()
            .map(|pool| {
                // Bind/reset the physical observation before serializing its
                // efficiency, so a replacement cannot inherit the old eta.
                // A skipped row (an alias or excluded mount) names no pool of
                // its own; binding it would reset the history kept under the
                // pool's mount.
                let release_history = if pool.skipped {
                    None
                } else {
                    self.release_controller.pool_history(
                        &pool.mount_point,
                        &pool.ballast_dir,
                        pool.files_available,
                    )
                };
                super::self_monitor::BallastPoolState {
                    mount: pool.mount_point.display().to_string(),
                    ballast_dir: pool.ballast_dir.display().to_string(),
                    fs_type: pool.fs_type,
                    strategy: match pool.strategy {
                        super::super::ballast::coordinator::ProvisionStrategy::Fallocate => {
                            "fallocate".to_string()
                        }
                        super::super::ballast::coordinator::ProvisionStrategy::RandomData => {
                            "random_data".to_string()
                        }
                        super::super::ballast::coordinator::ProvisionStrategy::Skip => {
                            "skip".to_string()
                        }
                    },
                    available: pool.files_available,
                    total: pool.files_total,
                    releasable_bytes: pool.releasable_bytes,
                    skipped: pool.skipped,
                    skip_reason: pool.skip_reason,
                    release_efficiency: Some(
                        self.release_controller
                            .release_efficiency(&pool.mount_point),
                    ),
                    release_history,
                }
            })
            .collect();
        pools.sort_by(|a, b| a.mount.cmp(&b.mount));
        self.self_monitor.set_ballast_pools(pools);
        self.self_monitor
            .set_voi_snapshot(super::self_monitor::VoiState::from_scheduler(
                &self.config.scheduler,
                &self.voi_scheduler.calibration_summary(),
                self.voi_scheduler.is_fallback_active(),
                self.last_voi_plan.as_ref(),
            ));
        let dropped_log_events = self.logger_handle.dropped_events();
        let policy_mode = {
            let policy = self.policy_engine.lock();
            self.self_monitor.set_policy_snapshot(PolicyStateRecord {
                mode: policy.mode().to_string(),
                since_secs: policy.mode_since_secs(),
                last_fallback_reason: policy.last_fallback_reason().map(str::to_string),
                auto_recover_to: policy.config().auto_recover_to.to_string(),
                serialization_failures: policy.serialization_failures(),
            });
            policy.mode().to_string()
        };

        // Every mount's reading and control state, not only the worst mount,
        // so `sbh status` and the dashboard can show what the daemon is doing
        // on each device and why it is idle on the others.
        let mounts = self
            .mount_responses
            .iter()
            .map(|tick| MountPressure {
                path: tick.response.causing_mount.to_string_lossy().into_owned(),
                free_pct: tick.response.free_pct,
                level: format!("{:?}", tick.response.level).to_lowercase(),
                rate_bps: Some(tick.rate.bytes_per_sec),
            })
            .collect();
        let rates = self
            .mount_responses
            .iter()
            .map(|tick| {
                (
                    tick.response.causing_mount.to_string_lossy().into_owned(),
                    tick.rate.clone(),
                )
            })
            .collect();
        let now = Instant::now();
        let mut controllers: Vec<_> = self
            .mount_controllers
            .values()
            .map(|controller| controller.record(now))
            .collect();
        controllers.sort_by(|a, b| a.mount.cmp(&b.mount));
        // The reserve on each mount: what is releasable now against what
        // the configuration asks for, how long it would last at the mount's
        // fill rate, and whether the headroom floor is what keeps it short.
        let inventory = self.ballast_coordinator.inventory();
        for record in &mut controllers {
            let mount = PathBuf::from(&record.mount);
            let quarantined_bytes = self.quarantine_held.get(&mount).copied().unwrap_or(0);
            let Some(pool) = inventory
                .iter()
                .find(|item| item.mount_point == mount && !item.skipped)
            else {
                // No ballast pool here; the quarantine is still reserve.
                let burst = self.burst_reserve(&mount, quarantined_bytes);
                if quarantined_bytes > 0 || burst.is_some() {
                    record.reserve_state = Some(ReserveState {
                        present_bytes: 0,
                        target_bytes: 0,
                        horizon_minutes: None,
                        floor_limited: false,
                        quarantined_bytes,
                        burst,
                        release_efficiency: None,
                    });
                }
                continue;
            };
            let rate = self.mount_rates.get(&mount).copied().unwrap_or(0.0);
            #[allow(clippy::cast_precision_loss)]
            let horizon_minutes = (rate > 0.0).then(|| pool.releasable_bytes as f64 / rate / 60.0);
            record.reserve_state = Some(ReserveState {
                present_bytes: pool.releasable_bytes,
                target_bytes: pool.configured_bytes,
                horizon_minutes,
                floor_limited: self.floor_limited.contains(&mount),
                quarantined_bytes,
                burst: self.burst_reserve(&mount, pool.releasable_bytes + quarantined_bytes),
                release_efficiency: Some(self.release_controller.release_efficiency(&mount)),
            });
        }
        let idle_reason = daemon_idle_reason(&controllers);
        self.self_monitor.set_mount_snapshot(mounts, controllers);
        self.self_monitor
            .set_budget_snapshot(self.cpu_budget.lock().snapshot(now), idle_reason);

        // Thread health: the monitor thread is writing this, the workers are
        // judged by their heartbeats, the logger by whether its thread lives.
        let health = self.self_monitor.health_snapshot(
            &[
                Arc::clone(&self.scanner_heartbeat),
                Arc::clone(&self.executor_heartbeat),
            ],
            THREAD_STALL_THRESHOLD,
            response.level,
        );
        let worker = |index: usize| {
            health
                .thread_status
                .get(index)
                .map_or_else(ThreadState::default, ThreadState::from_status)
        };
        // The logger beats once a second from its own loop, so a thread that
        // is alive but wedged (a hung SQLite write) shows as stalled, not
        // running.
        let logger = if self
            .logger_join
            .as_ref()
            .is_some_and(|handle| !handle.is_finished())
        {
            let since = self.logger_handle.seconds_since_beat();
            ThreadState {
                status: if since.is_some_and(|s| s > THREAD_STALL_THRESHOLD.as_secs()) {
                    "stalled".to_string()
                } else {
                    "running".to_string()
                },
                seconds_since_heartbeat: since,
            }
        } else {
            ThreadState {
                status: "dead".to_string(),
                seconds_since_heartbeat: None,
            }
        };
        self.self_monitor.set_runtime_snapshot(
            rates,
            ThreadsState {
                monitor: ThreadState::running_now(),
                scanner: worker(0),
                executor: worker(1),
                logger,
            },
        );

        self.self_monitor.maybe_write_state(
            response.level,
            free_pct,
            &mount_str,
            ballast_available,
            ballast_total,
            dropped_log_events,
            &policy_mode,
        )
    }

    /// Run the monitoring loop until shutdown is requested.
    ///
    /// This is the main entry point for `sbh daemon`.
    #[allow(clippy::too_many_lines)]
    pub fn run(&mut self) -> Result<()> {
        // Log startup.
        let config_hash = self.config.stable_hash().unwrap_or_default();
        self.logger_handle.send(ActivityEvent::DaemonStarted {
            version: env!("CARGO_PKG_VERSION").to_string(),
            config_hash,
        });
        self.maybe_log_full_disk_access_status(true);
        self.notification_manager
            .notify(&NotificationEvent::DaemonStarted {
                version: env!("CARGO_PKG_VERSION").to_string(),
                volumes_monitored: self.ballast_coordinator.pool_count(),
            });

        // Provision ballast files (idempotent). This precedes READY=1, and on
        // a fresh install it writes every pool (random data on CoW
        // filesystems) at disk speed: 20 GiB took 45 s in a systemd container
        // and the unit was killed at TimeoutStartSec=30, then restarted.
        with_startup_extension(
            self.platform.service_manager(),
            "provisioning ballast",
            StartupExtension::DEFAULT,
            &self.signal_handler.shutdown_token(),
            || self.provision_ballast(),
        )?;

        // Initial pressure check.
        let initial_response = self.check_pressure()?;
        if initial_response.level != PressureLevel::Green {
            eprintln!(
                "[SBH-DAEMON] starting under pressure: {:?} (urgency={:.2})",
                initial_response.level, initial_response.urgency
            );
        }
        let startup_monitor_tick = self.maybe_write_self_monitor_state(&initial_response);
        if startup_monitor_tick.should_exit_for_rss_hard_limit() {
            return Err(self.rss_hard_limit_error(startup_monitor_tick));
        }

        let (memory_pressure_tx, memory_pressure_rx) =
            bounded::<MemoryPressureEvent>(MEMORY_PRESSURE_CHANNEL_CAP);
        self.seed_memory_pressure_behavior(initial_response.level);
        let _memory_pressure_subscription =
            self.start_memory_pressure_subscription(memory_pressure_tx);

        // Create inter-thread channels.
        let (scan_tx, scan_rx) = bounded::<ScanRequest>(SCANNER_CHANNEL_CAP);
        let (del_tx, del_rx) = bounded::<DeletionBatch>(EXECUTOR_CHANNEL_CAP);
        let (report_tx, report_rx) = bounded::<WorkerReport>(REPORT_CHANNEL_CAP);
        let (index_feedback_tx, index_feedback_rx) =
            bounded::<ScannerIndexFeedback>(EXECUTOR_CHANNEL_CAP);

        // Spawn worker threads with heartbeats.
        let mut scanner_health = ThreadHealth::new();
        let mut executor_health = ThreadHealth::new();

        let mut scanner_join: Option<thread::JoinHandle<()>> = Some(self.spawn_scanner_thread(
            scan_rx.clone(),
            del_tx.clone(),
            self.logger_handle.clone(),
            Arc::clone(&self.scanner_heartbeat),
            report_tx.clone(),
            index_feedback_rx.clone(),
        )?);
        let mut executor_join: Option<thread::JoinHandle<()>> = Some(self.spawn_executor_thread(
            del_rx.clone(),
            self.logger_handle.clone(),
            Arc::clone(&self.executor_heartbeat),
            report_tx.clone(),
            index_feedback_tx.clone(),
        )?);

        if self.config.core.control_socket_enabled {
            self.start_control_server();
        }

        // Startup is complete: workers are running and the first state file is
        // written. Type=notify units wait for this READY=1 and are killed at
        // TimeoutStartSec without it.
        if let Err(error) = self.platform.service_manager().notify_ready() {
            eprintln!("[SBH-DAEMON] sd_notify READY=1 failed: {error}");
        }
        self.watchdog.notify_now("startup complete");

        let mut last_health_check = Instant::now();
        let mut shutdown_result = Ok(());

        // ──────── main monitoring loop ────────
        loop {
            let tick_start = Instant::now();
            self.watchdog.maybe_notify("tick start");

            // 1. Check shutdown signal.
            if self.signal_handler.should_shutdown() {
                eprintln!("[SBH-DAEMON] shutdown requested");
                break;
            }
            self.drain_control_commands();

            // 2. Check config reload signal.
            if self.signal_handler.should_reload() {
                self.handle_config_reload(&scan_tx);
            }

            // 2b. Periodically re-check macOS FDA grants and log success when granted.
            self.maybe_log_full_disk_access_status(false);

            // 3. Collect filesystem stats and run pressure analysis.
            let response = match self.check_pressure() {
                Ok(r) => r,
                Err(e) => {
                    self.logger_handle.send(ActivityEvent::Error {
                        code: "SBH-2001".to_string(),
                        message: format!("pressure check failed: {e}"),
                    });
                    // On error, sleep and retry.
                    self.sleep_with_memory_pressure_events(
                        &memory_pressure_rx,
                        self.last_pressure_level,
                        Duration::from_secs(1),
                    );
                    continue;
                }
            };
            self.watchdog.maybe_notify("pressure checked");

            // 4. Log pressure transitions.
            if response.level != self.last_pressure_level {
                // Suppress oscillation noise (e.g., Green→Orange→Green→Yellow→Green→Yellow).
                // Within a 5-minute cooldown window, only notify if the new level
                // exceeds the highest level already notified. This prevents:
                // - After Green→Orange notification, repeated Green→Yellow noise
                // - After Green→Red, repeated Green→Yellow→Green→Yellow cycling
                let in_cooldown = self
                    .last_pressure_notify_time
                    .is_some_and(|t| t.elapsed() < Duration::from_mins(5));
                let should_notify = if in_cooldown {
                    // Only notify if this level exceeds what we already notified about.
                    response.level > self.last_notified_pressure_level
                } else {
                    // Cooldown expired — reset and notify any change.
                    self.last_notified_pressure_level = PressureLevel::Green;
                    true
                };
                if should_notify {
                    self.log_pressure_change(&response);
                    self.last_pressure_notify_time = Some(Instant::now());
                    if response.level > self.last_notified_pressure_level {
                        self.last_notified_pressure_level = response.level;
                    }
                }
                self.last_pressure_level = response.level;
            }

            self.update_behavior_mode(
                self.behavior_state.latest_memory_level(),
                response.level,
                "disk_pressure",
                Duration::ZERO,
            );
            self.drain_memory_pressure_events(&memory_pressure_rx, response.level);
            self.sample_process_io_history();

            // Foreground status requests should be responsive even when the
            // next cleanup/special-location pass is expensive.
            if self.signal_handler.should_dump_status() {
                self.emit_status_dump(&response);
            }

            // Check daemon memory limits before scheduling cleanup work. A hard
            // RSS breach should exit promptly for the service manager restart
            // path instead of spending another tick on scans or deletions.
            let self_monitor_tick = self.maybe_write_self_monitor_state(&response);
            self.flush_state_replies();
            // Evidence that cannot be persisted must not keep driving
            // deletions: the policy engine decides what a failed state
            // write means (`policy.serialization_failure_action`).
            if self_monitor_tick.state_write_failed {
                self.policy_engine.lock().note_serialization_failure();
            }
            if self_monitor_tick.should_exit_for_rss_hard_limit() {
                shutdown_result = Err(self.rss_hard_limit_error(self_monitor_tick));
                break;
            }
            self.watchdog.maybe_notify("io and state sampled");

            // 5. Handle pressure response per mount; the tick follows the
            //    tightest mount sbh is actually working on.
            let requested_tick = self.handle_pressure(&response, &scan_tx, &scan_rx, &del_tx);
            self.watchdog.maybe_notify("pressure handled");

            // 5b. Policy mode changes since the last tick (the engine runs
            // on the executor thread; this is the only place they are logged).
            self.emit_policy_transitions();

            // 6. Check special locations independently.
            self.check_special_locations(&scan_tx, &scan_rx);

            // 7. Detect swap-thrash conditions and alert with cooldown.
            self.check_swap_thrash();

            // 8. Watchdog heartbeat.
            self.watchdog.maybe_notify(&format!(
                "pressure={:?} urgency={:.2}",
                response.level, response.urgency
            ));

            // 7b. Drain worker reports so summaries and future state writes are current.
            while let Ok(report) = report_rx.try_recv() {
                match report {
                    WorkerReport::ScanCompleted {
                        candidates,
                        duration,
                        root_stats,
                        timed_out,
                        pressure_level,
                        background,
                    } => {
                        self.summary_scans += 1;
                        if timed_out {
                            self.summary_scan_timeouts += 1;
                        }
                        self.summary_candidates += candidates as u64;
                        self.self_monitor.record_scan(candidates, 0, duration);
                        self.last_scan_completed = Some((Instant::now(), duration));
                        let now = Instant::now();
                        #[allow(clippy::cast_possible_truncation)]
                        for stat in &root_stats {
                            self.voi_scheduler.record_scan_result(
                                &stat.path,
                                stat.potential_bytes,
                                stat.candidates_found as u32,
                                stat.false_positives as u32,
                                stat.duration.as_millis() as f64,
                                now,
                            );
                            self.voi_scheduler.record_dirty(&stat.path, stat.dirty, now);
                        }
                        self.voi_scheduler.end_window();
                        // A completed (not timed-out) pass with nothing found
                        // on a mount parks that mount's controller in Idle.
                        if !timed_out {
                            self.note_scan_pass_per_mount(
                                &root_stats,
                                pressure_level,
                                background,
                                now,
                            );
                        }
                    }
                    WorkerReport::DeletionCompleted {
                        deleted,
                        bytes_freed,
                        freed_basis,
                        bytes_freed_observed,
                        failed,
                        recovery_paths,
                        failure_alarm,
                    } => {
                        self.summary_deleted += deleted;
                        self.summary_failed += failed;
                        self.summary_bytes_freed += bytes_freed;
                        self.summary_freed_basis = self.summary_freed_basis.combine(freed_basis);
                        self.summary_bytes_freed_observed = self
                            .summary_bytes_freed_observed
                            .zip(bytes_freed_observed)
                            .map(|(sum, bytes)| sum.saturating_add(bytes));
                        self.self_monitor.record_deletions(deleted, bytes_freed);
                        self.self_monitor
                            .record_freed_basis(freed_basis, bytes_freed_observed);
                        // One reaction cycle: poll, scan, then the reclaim
                        // that followed it; it sizes the burst windows.
                        if let Some((scan_completed_at, scan_duration)) =
                            self.last_scan_completed.take()
                        {
                            let poll = Duration::from_millis(self.config.pressure.poll_interval_ms);
                            self.burst_stats
                                .record_cycle(poll + scan_duration + scan_completed_at.elapsed());
                        }
                        // Mount incidents: park the owning mounts in recovery
                        // on the next tick instead of retrying.
                        for path in &recovery_paths {
                            if let Ok(stats) = self.fs_collector.collect(path) {
                                self.pending_recovery.insert(stats.mount_point);
                            }
                        }
                        if let Some((reason, count)) = failure_alarm {
                            let message = format!(
                                "deletion failure rate alarm (e-process >= 20:1 against a <=10% \
                                 failure rate): dominant reason {reason} x{count}; see \
                                 `sbh stats` and the [SBH-EXECUTOR] skip lines"
                            );
                            self.logger_handle.send(ActivityEvent::Error {
                                code: "SBH-2005".to_string(),
                                message: message.clone(),
                            });
                            self.notification_manager.notify(&NotificationEvent::Error {
                                code: "SBH-2005".to_string(),
                                message,
                            });
                        }
                        if deleted > 0 {
                            // Best effort: we don't have the mount point here easily without tracking
                            // it through the batch. Use "primary" or "various".
                            let items_deleted = usize::try_from(deleted).unwrap_or(usize::MAX);
                            self.notification_manager.notify(
                                &NotificationEvent::CleanupCompleted {
                                    items_deleted,
                                    bytes_freed,
                                    freed_basis,
                                    mount: "various".to_string(),
                                },
                            );
                        }
                        for _ in 0..failed {
                            self.self_monitor.record_error();
                        }
                    }
                }
            }

            // 9. Forced scan signal (SIGUSR1). Also wakes idle mounts next tick.
            // A full scan queue defers it to the next tick instead of
            // dropping it.
            if self.signal_handler.should_scan() {
                if self.forced_scan_pending_since.is_none()
                    && !Self::trigger_forced_scan(
                        &self.config.scanner.root_paths,
                        &scan_tx,
                        &response,
                    )
                {
                    self.forced_scan_pending_since = Some(Instant::now());
                    eprintln!(
                        "[SBH-DAEMON] forced scan deferred (SIGUSR1): scan queue full, retrying every tick"
                    );
                }
                self.wake_next_tick.forced_scan = true;
            } else if let Some(since) = self.forced_scan_pending_since
                && Self::trigger_forced_scan(&self.config.scanner.root_paths, &scan_tx, &response)
            {
                self.forced_scan_pending_since = None;
                eprintln!(
                    "[SBH-DAEMON] deferred forced scan queued after {:.1}s",
                    since.elapsed().as_secs_f64()
                );
            }

            // 10. Thread health check.
            if last_health_check.elapsed() >= THREAD_HEALTH_CHECK_INTERVAL
                && !self.signal_handler.should_shutdown()
            {
                last_health_check = Instant::now();

                let scanner_dead = scanner_join
                    .as_ref()
                    .is_some_and(std::thread::JoinHandle::is_finished);
                if scanner_dead {
                    eprintln!("[SBH-DAEMON] scanner thread exited unexpectedly");
                    if let Some(handle) = scanner_join.take() {
                        let _ = handle.join();
                    }
                    if scanner_health.record_panic() {
                        eprintln!("[SBH-DAEMON] respawning scanner thread");
                        self.scanner_heartbeat = ThreadHeartbeat::new("sbh-scanner");
                        match self.spawn_scanner_thread(
                            scan_rx.clone(),
                            del_tx.clone(),
                            self.logger_handle.clone(),
                            Arc::clone(&self.scanner_heartbeat),
                            report_tx.clone(),
                            index_feedback_rx.clone(),
                        ) {
                            Ok(handle) => scanner_join = Some(handle),
                            Err(err) => {
                                self.logger_handle.send(ActivityEvent::Error {
                                    code: err.code().to_string(),
                                    message: format!("failed to respawn scanner thread: {err}"),
                                });
                                eprintln!("[SBH-DAEMON] scanner respawn failed: {err}");
                                break;
                            }
                        }
                    } else {
                        self.logger_handle.send(ActivityEvent::Error {
                            code: "SBH-3900".to_string(),
                            message: "scanner thread exceeded respawn limit".to_string(),
                        });
                        eprintln!("[SBH-DAEMON] scanner exceeded respawn limit, shutting down");
                        break;
                    }
                }

                let executor_dead = executor_join
                    .as_ref()
                    .is_some_and(std::thread::JoinHandle::is_finished);
                if executor_dead {
                    eprintln!("[SBH-DAEMON] executor thread exited unexpectedly");
                    if let Some(handle) = executor_join.take() {
                        let _ = handle.join();
                    }
                    if executor_health.record_panic() {
                        eprintln!("[SBH-DAEMON] respawning executor thread");
                        self.executor_heartbeat = ThreadHeartbeat::new("sbh-executor");
                        match self.spawn_executor_thread(
                            del_rx.clone(),
                            self.logger_handle.clone(),
                            Arc::clone(&self.executor_heartbeat),
                            report_tx.clone(),
                            index_feedback_tx.clone(),
                        ) {
                            Ok(handle) => executor_join = Some(handle),
                            Err(err) => {
                                self.logger_handle.send(ActivityEvent::Error {
                                    code: err.code().to_string(),
                                    message: format!("failed to respawn executor thread: {err}"),
                                });
                                eprintln!("[SBH-DAEMON] executor respawn failed: {err}");
                                break;
                            }
                        }
                    } else {
                        self.logger_handle.send(ActivityEvent::Error {
                            code: "SBH-3900".to_string(),
                            message: "executor thread exceeded respawn limit".to_string(),
                        });
                        eprintln!("[SBH-DAEMON] executor exceeded respawn limit, shutting down");
                        break;
                    }
                }
            }

            // 11. Periodic summary report (every 5 minutes).
            if self.last_summary_report.elapsed() >= Duration::from_mins(5) {
                let rss_mb = self
                    .platform
                    .self_stats()
                    .map_or(0, |stats| stats.rss_bytes / (1024 * 1024));
                let guard_diag_snapshot = self.shared_guard_diagnostics.read().clone();
                let guard_str = guard_diag_snapshot.as_ref().map_or_else(
                    || "none".to_string(),
                    |d| {
                        format!(
                            "{}(e={:.1} med_err={:.2} cons={:.0}% obs={} clean={})",
                            d.status,
                            d.e_process_value,
                            d.median_rate_error,
                            d.conservative_fraction * 100.0,
                            d.observation_count,
                            d.consecutive_clean,
                        )
                    },
                );
                let mode_str = self.policy_engine.lock().mode();
                eprintln!(
                    "[SBH-SUMMARY] scans={} timeouts={} candidates={} deleted={} \
                     failed={} freed={}B freed_basis={} observed_freed={} pressure={:?} \
                     guard={} mode={} rss={}MB uptime={}s",
                    self.summary_scans,
                    self.summary_scan_timeouts,
                    self.summary_candidates,
                    self.summary_deleted,
                    self.summary_failed,
                    self.summary_bytes_freed,
                    self.summary_freed_basis.label(),
                    self.summary_bytes_freed_observed
                        .map_or_else(|| "unknown".to_string(), |bytes| format!("{bytes}B")),
                    response.level,
                    guard_str,
                    mode_str,
                    rss_mb,
                    self.start_time.elapsed().as_secs(),
                );
                self.summary_scans = 0;
                self.summary_scan_timeouts = 0;
                self.summary_candidates = 0;
                self.summary_deleted = 0;
                self.summary_failed = 0;
                self.summary_bytes_freed = 0;
                self.summary_freed_basis = FreedBasis::Observed;
                self.summary_bytes_freed_observed = Some(0);
                self.last_summary_report = Instant::now();
            }

            let tick_duration = tick_start.elapsed();
            let throttle_decision =
                self.tick_throttle
                    .observe(requested_tick, self_monitor_tick, tick_duration);
            if throttle_decision.stage_changed {
                let message = format!(
                    "daemon tick throttle stage={:?} reason={:?} requested_ms={} effective_ms={} tick_ms={} rss_bytes={} rss_warning_bytes={}",
                    throttle_decision.stage,
                    throttle_decision.reason,
                    duration_millis(requested_tick),
                    duration_millis(throttle_decision.interval),
                    duration_millis(tick_duration),
                    self_monitor_tick.rss_bytes,
                    self_monitor_tick.rss_warning_bytes
                );
                eprintln!("[SBH-DAEMON] {message}");
                self.logger_handle.send(ActivityEvent::Info { message });
            }

            // 11b. Q7: charge this tick's CPU to the daemon-wide budget and
            // stretch the sleep while in deficit. The yield is capped below
            // the state-write interval and the watchdog cadence, so those and
            // ballast release keep running; Critical pressure never yields.
            let budget_yield = self.observe_cpu_budget(response.level);

            // 12. Sleep for the PID/self-throttle adjusted interval, but wake
            // immediately for memory-pressure transitions so behavior changes
            // are not delayed until the next disk-pressure poll.
            self.sleep_with_memory_pressure_events(
                &memory_pressure_rx,
                response.level,
                throttle_decision.interval + budget_yield,
            );
        }

        // ──────── shutdown sequence ────────
        let exit_reason = if shutdown_result.is_err() {
            "rss hard limit exceeded"
        } else {
            "clean shutdown"
        };
        self.shutdown(scan_tx, del_tx, scanner_join, executor_join, exit_reason);
        shutdown_result
    }

    // ──────────────────── helpers ────────────────────

    fn rss_hard_limit_error(&self, tick: SelfMonitorTick) -> SbhError {
        let details = format!(
            "daemon RSS hard limit exceeded: rss={} bytes hard_limit={} bytes; exiting nonzero so the service manager can restart after its throttle interval",
            tick.rss_bytes, tick.rss_hard_limit_bytes
        );
        self.logger_handle.send(ActivityEvent::Error {
            code: "SBH-3901".to_string(),
            message: details.clone(),
        });
        SbhError::Runtime { details }
    }

    // ──────────────────── pressure monitoring ────────────────────

    #[allow(clippy::too_many_lines)]
    fn check_pressure(&mut self) -> Result<crate::monitor::pid::PressureResponse> {
        // Collect stats for all root paths PLUS "/". Always monitoring "/"
        // is defensive: if a user configures scanner.root_paths to specific
        // subdirs, the root mount may still fill from non-monitored sources
        // (logs, packages, agent worktrees) and we'd miss the pressure
        // entirely. Per-mount dedup below means this is essentially free
        // when "/" is already implied by the configured paths.
        let mut paths: Vec<PathBuf> = self.config.scanner.root_paths.clone();
        if !paths.iter().any(|p| p == Path::new("/")) {
            paths.push(PathBuf::from("/"));
        }

        // Group paths by mount point to avoid redundant updates.
        let mut stats_by_mount: HashMap<PathBuf, crate::platform::pal::FsStats> = HashMap::new();

        for path in &paths {
            if let Ok(stats) = self.fs_collector.collect(path) {
                // If multiple paths share a mount, we just need one valid reading.
                stats_by_mount
                    .entry(stats.mount_point.clone())
                    .or_insert(stats);
            }
        }

        if stats_by_mount.is_empty() {
            return Err(crate::core::errors::SbhError::FsStats {
                path: paths.first().cloned().unwrap_or_else(|| PathBuf::from("/")),
                details: "no filesystem stats available for any root path".to_string(),
            });
        }

        let now = Instant::now();
        let mut worst_response: Option<crate::monitor::pid::PressureResponse> = None;
        let mut worst_guard_diag: Option<GuardDiagnostics> = None;
        // Reset per-tick predictive action so we track the worst across mounts.
        self.last_predictive_action = PredictiveAction::Clear;
        self.mount_responses.clear();

        // Update monitors for each active mount.
        for (mount_path, stats) in stats_by_mount {
            self.release_controller
                .update_effectiveness(&mount_path, stats.available_bytes, now);

            let monitor = self
                .mount_monitors
                .entry(mount_path.clone())
                .or_insert_with(|| MountMonitor::new(&self.config));

            // Update EWMA rate estimator.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let red_threshold_bytes =
                (stats.total_bytes as f64 * self.config.pressure.red_min_free_pct / 100.0) as u64;

            let rate_estimate =
                monitor
                    .rate_estimator
                    .update(stats.available_bytes, now, red_threshold_bytes);
            let guard_diag = monitor.observe_guard(
                now,
                stats.available_bytes,
                red_threshold_bytes,
                &rate_estimate,
            );

            // Predicted time to red threshold: the point estimate, and the
            // conformal lower bound the controllers act on.
            let predicted_point = if rate_estimate.seconds_to_threshold.is_finite()
                && rate_estimate.seconds_to_threshold > 0.0
            {
                Some(rate_estimate.seconds_to_threshold)
            } else {
                None
            };
            let interval = predicted_point.map(|point| monitor.forecast_interval(point));
            let predicted_seconds = interval
                .as_ref()
                .map(|i| i.lo_secs)
                .filter(|lo| lo.is_finite() && *lo >= 0.0)
                .or(predicted_point);
            let rate_estimate = calibrated_estimate(&rate_estimate, interval.as_ref());
            log_forecast(
                &mut self.last_forecast_log,
                &self.logger_handle,
                &mount_path,
                &rate_estimate,
                interval.as_ref(),
                now,
            );

            // Run PID controller. Anti-windup on actionability: a mount
            // that had no actuator last tick (observe-only, idle after an
            // empty pass, recovering from EROFS/ENOSPC) does not integrate.
            let reading = PressureReading {
                free_bytes: stats.available_bytes,
                total_bytes: stats.total_bytes,
                mount: stats.mount_point.clone(),
            };
            let frozen = self
                .mount_controllers
                .get(&mount_path)
                .is_some_and(|controller| {
                    matches!(
                        controller.state(),
                        MountState::ObserveOnly | MountState::Idle | MountState::Recovery
                    )
                });
            monitor.pressure_controller.freeze_integral(frozen);
            let response = monitor
                .pressure_controller
                .update(reading, predicted_seconds, now);

            // Evaluate predictive policy with full confidence/trend gating.
            let free_pct = stats.free_pct();
            let mut pred_action =
                self.predictive_policy
                    .evaluate(&rate_estimate, free_pct, mount_path.clone());

            // Force low-confidence predictions to Clear so they don't trigger
            // scans or other downstream actions (breaks scan saturation feedback loop).
            // The effective confidence floor is raised by the prediction scorecard
            // when false alarm rate is high — this dynamically tightens the gate
            // based on realized accuracy.
            let effective_min_conf = self
                .prediction_scorecard
                .dynamic_min_confidence(self.config.pressure.prediction.min_confidence);
            if !matches!(pred_action, PredictiveAction::Clear)
                && rate_estimate.confidence < effective_min_conf
            {
                pred_action = PredictiveAction::Clear;
            }

            if pred_action.severity() > self.last_predictive_action.severity() {
                self.last_predictive_action = pred_action;
            }

            // Keep this mount's own reading for the per-mount controllers.
            self.mount_rates
                .insert(mount_path.clone(), rate_estimate.bytes_per_second);
            // One used-bytes reading per tick feeds the reserve-sizing
            // windows (peak growth per reaction window).
            self.burst_stats.observe(
                &mount_path,
                now,
                stats.total_bytes.saturating_sub(stats.available_bytes),
            );
            self.note_logging_mount_level(&mount_path, response.level);
            self.mount_responses.push(MountTickResponse {
                response: response.clone(),
                seconds_to_red: predicted_seconds,
                prediction_confident: rate_estimate.confidence >= effective_min_conf,
                rate: MountRateState {
                    bytes_per_sec: rate_estimate.bytes_per_second,
                    accel: rate_estimate.acceleration,
                    confidence: rate_estimate.confidence,
                    seconds_to_red: predicted_seconds,
                    seconds_to_full: finite_positive(rate_estimate.seconds_to_exhaustion),
                    forecast: interval.as_ref().map(|i| {
                        ForecastSnapshot::from_interval(
                            i,
                            self.config.pressure.prediction.coverage_target,
                        )
                    }),
                },
            });

            // Track worst response (highest urgency/severity).
            match worst_response {
                None => {
                    worst_response = Some(response);
                    worst_guard_diag = Some(guard_diag);
                    self.last_ewma_confidence = rate_estimate.confidence;
                }
                Some(ref worst) => {
                    // Critical > Red > ... > Green.
                    // If levels equal, higher urgency wins.
                    if response.level > worst.level
                        || (response.level == worst.level && response.urgency > worst.urgency)
                    {
                        worst_response = Some(response);
                        worst_guard_diag = Some(guard_diag);
                        self.last_ewma_confidence = rate_estimate.confidence;
                    }
                }
            }
        }

        // Record prediction scorecard outcome: was the previous tick's prediction
        // realized? An actionable prediction (severity >= 2) is "realized" if the
        // current tick's worst pressure is at Red or above.
        // The cleanup_ran flag distinguishes successful interventions (prediction
        // triggered cleanup that prevented the problem) from false alarms (prediction
        // said danger but nothing was happening).
        if let Some(ref response) = worst_response {
            let was_actionable = self.last_predictive_action.severity() >= 2;
            let was_realized = response.level >= PressureLevel::Red;
            self.prediction_scorecard.record(
                was_actionable,
                was_realized,
                self.last_tick_cleanup_ran,
            );
        }
        // Reset cleanup flag for next tick — it gets set below when we dispatch scans/ballast.
        self.last_tick_cleanup_ran = false;

        if let Some(diag) = worst_guard_diag.as_ref() {
            let mut policy = self.policy_engine.lock();
            let pressure_level = worst_response
                .as_ref()
                .map_or(PressureLevel::Green, |r| r.level);
            policy.set_pressure_level(pressure_level);
            policy.observe_window(diag);

            // Emergency escalation: break fallback_safe deadlock when pressure
            // has been at Yellow+ for too long and recovery can't trigger.
            if let Some(ref response) = worst_response {
                let pressure_is_critical = response.level >= PressureLevel::Yellow;
                if policy.check_emergency_escalation(pressure_is_critical) {
                    let landed = policy.mode();
                    drop(policy);
                    eprintln!(
                        "[SBH-DAEMON] emergency escalation: fallback_safe → {landed} \
                         (pressure deadlock broken after sustained Yellow+)"
                    );
                }
            }
        }
        *self.shared_guard_diagnostics.write() = worst_guard_diag;

        // Clean up monitors for unmounted/disappeared volumes?
        // For now we keep them; volume churn is rare in typical operation.

        worst_response.ok_or_else(|| crate::core::errors::SbhError::FsStats {
            path: PathBuf::from("/"),
            details: "internal error: stats collected but no response generated".to_string(),
        })
    }

    fn log_pressure_change(&mut self, response: &crate::monitor::pid::PressureResponse) {
        // Use the causing mount so the log entry reflects the mount that
        // actually drove the pressure level change, not the primary path.
        let (free_pct, mount, total, free) =
            if let Ok(stats) = self.fs_collector.collect(&response.causing_mount) {
                #[allow(clippy::cast_possible_wrap)]
                (
                    stats.free_pct(),
                    stats.mount_point.to_string_lossy().to_string(),
                    stats.total_bytes as i64,
                    stats.available_bytes as i64,
                )
            } else {
                (0.0, "/".to_string(), 0, 0)
            };

        self.logger_handle.send(ActivityEvent::PressureChanged {
            from: format!("{:?}", self.last_pressure_level),
            to: format!("{:?}", response.level),
            free_pct,
            rate_bps: None,
            mount_point: mount.clone(),
            total_bytes: total,
            free_bytes: free,
            ewma_rate: None,
            pid_output: Some(response.urgency),
        });

        self.notification_manager
            .notify(&NotificationEvent::PressureChanged {
                from: format!("{:?}", self.last_pressure_level),
                to: format!("{:?}", response.level),
                mount,
                free_pct,
            });
    }

    // ──────────────────── pressure response ────────────────────

    /// Drive every mount from its own reading through its `MountController`
    /// and return the tick the daemon should sleep for.
    ///
    /// `response` is still the worst mount's reading; it feeds the predictive
    /// safety net and the Critical emergency event. Everything per mount
    /// (scan dispatch, ballast release and replenish, observe-only reporting)
    /// comes from `self.mount_responses`. The returned tick is the tightest
    /// cadence among mounts sbh is working on: a pressured mount it cannot
    /// act on is observe-only and contributes nothing, so it can no longer
    /// drag the whole daemon onto the Orange interval (the v0.5.1 hot loop).
    #[allow(clippy::too_many_lines)]
    fn handle_pressure(
        &mut self,
        response: &crate::monitor::pid::PressureResponse,
        scan_tx: &Sender<ScanRequest>,
        scan_rx: &Receiver<ScanRequest>,
        del_tx: &Sender<DeletionBatch>,
    ) -> Duration {
        // Reset min_score to config default at the start of each tick;
        // PreemptiveCleanup may lower it below.
        self.shared_executor_config
            .set_min_score(self.config.scoring.min_score);
        self.check_predictive_warning(response);

        let behavior = self.behavior_state.mode;
        let scan_allowed = behavior_allows_scan(behavior);
        let release_ballast = behavior_should_release_ballast(behavior);
        let base_poll = Duration::from_millis(self.config.pressure.poll_interval_ms.max(1));
        let now = Instant::now();
        let wake = std::mem::take(&mut self.wake_next_tick);
        let controller_config = mount_controller_config(&self.config);

        // Which configured roots live on which mount, resolved once per tick.
        let root_paths = self.config.scanner.root_paths.clone();
        let root_mounts: Vec<(PathBuf, Option<PathBuf>)> = root_paths
            .iter()
            .map(|root| {
                let mount = self
                    .fs_collector
                    .collect(root)
                    .ok()
                    .map(|stats| stats.mount_point);
                (root.clone(), mount)
            })
            .collect();
        let cross_device_fallback = self.config.scanner.cross_devices && !root_paths.is_empty();

        let responses = std::mem::take(&mut self.mount_responses);
        let mut pending_scans = Vec::new();
        let mut cadence = Vec::with_capacity(responses.len());
        let mut replenished_this_tick = false;
        let mut pressured_without_surface: Option<(PathBuf, PressureLevel)> = None;
        // Every pressured mount sbh can do nothing about, for the
        // once-per-epoch ReclaimUnavailable alert.
        let mut unprotected_mounts: HashMap<PathBuf, PressureLevel> = HashMap::new();

        for tick in &responses {
            let mount = tick.response.causing_mount.clone();
            let roots_here: Vec<PathBuf> = root_mounts
                .iter()
                .filter(|(_, root_mount)| root_mount.as_deref() == Some(mount.as_path()))
                .map(|(root, _)| root.clone())
                .collect();
            let (has_pool, releasable_ballast, ballast_dir) = self
                .ballast_coordinator
                .pool_for_mount(&mount)
                .map_or((false, false, None), |pool| {
                    (
                        true,
                        pool.available_count() > 0,
                        Some(pool.ballast_dir.clone()),
                    )
                });
            // A mount with no configured root and no cross-device fallback
            // still has a bounded surface: the known-safe caches on it.
            let catalog = if roots_here.is_empty()
                && !cross_device_fallback
                && self.config.scanner.catalog_roots_on_pressured_device
            {
                self.catalog_roots_for(&mount, now)
            } else {
                Vec::new()
            };
            let surface = MountSurface {
                configured_roots: roots_here.len(),
                catalog_roots: catalog.len(),
                ballast_pool: has_pool,
                cross_device_fallback,
            };
            let recovery_needed = self.pending_recovery.remove(&mount);
            let controller = self
                .mount_controllers
                .entry(mount.clone())
                .or_insert_with(|| MountController::new(mount.clone(), controller_config));
            let recovery_probe_ok = (controller.state() == MountState::Recovery)
                .then(|| probe_mount_writable(&mount, ballast_dir.as_deref()));
            let decision = controller.observe(MountTickInput {
                level: tick.response.level,
                urgency: tick.response.urgency,
                free_pct: tick.response.free_pct,
                seconds_to_red: tick.seconds_to_red,
                prediction_confident: tick.prediction_confident,
                surface,
                releasable_ballast,
                recovery_needed,
                recovery_probe_ok,
                wake,
                now,
            });
            cadence.push(controller.cadence(base_poll, tick.response.scan_interval));
            let idle_with_nothing_to_reclaim = decision.state == MountState::Idle
                && controller.idle_reason() == Some(IdleReason::NothingToReclaim);
            if let Some((from, to)) = decision.transition {
                let message = format!(
                    "mount {} {from} -> {to} (level={:?} urgency={:.2} surface={} idle_reason={})",
                    mount.display(),
                    tick.response.level,
                    tick.response.urgency,
                    surface.kind(),
                    controller.idle_reason().map_or("none", IdleReason::as_str),
                );
                eprintln!("[SBH-MOUNT] {message}");
                self.logger_handle.send(ActivityEvent::Info { message });
            }
            if decision
                .transition
                .is_some_and(|(_, to)| to == MountState::Recovery)
            {
                self.enter_mount_recovery(&mount, &tick.response);
            }

            // The replenish cooldown watches every tick, whatever the mount
            // is doing: an Orange excursion while reclaiming restarts it.
            // A mount idle at Yellow with nothing left to reclaim counts as
            // Green here (bd-7spb): after a release a large volume can sit at
            // Yellow for days, and a Green-only gate never rebuilt its
            // reserve. Provisioning still keeps free space above the Orange
            // floor, so a refill cannot push the mount into a release.
            let replenish_level =
                if tick.response.level == PressureLevel::Yellow && idle_with_nothing_to_reclaim {
                    PressureLevel::Green
                } else {
                    tick.response.level
                };
            self.release_controller
                .observe_level(&mount, replenish_level);

            let mut files_released = 0;
            match decision.state {
                MountState::Reclaim => {
                    if decision.release_ballast && release_ballast {
                        files_released = self.release_ballast(&mount, &tick.response).unwrap_or(0);
                        self.last_tick_cleanup_ran = true;
                    }
                    if decision.scan && scan_allowed {
                        if roots_here.is_empty() && !catalog.is_empty() {
                            // Catalog surface: one bounded catalog scan per
                            // pressure epoch, re-armed by a rising level.
                            let rescan = Duration::from_secs(
                                self.config.scanner.catalog_rescan_interval_secs.max(1),
                            );
                            let previous = self.catalog_epochs.get(&mount).copied();
                            if catalog_epoch_due(previous, tick.response.level, now, rescan) {
                                pending_scans.push((&tick.response, Vec::new(), Some(catalog)));
                            }
                        } else {
                            // A mount with no root of its own only gets here
                            // via cross_devices, where any configured root may
                            // help.
                            let paths = if roots_here.is_empty() {
                                root_paths.clone()
                            } else {
                                roots_here
                            };
                            // Under pressure the budget is the pressure
                            // level's; the scheduler only orders the roots
                            // (dirty first, then by hazard index).
                            let paths = self.voi_scheduler.rank_paths(&paths, now);
                            pending_scans.push((&tick.response, paths, None));
                        }
                    }
                }
                MountState::Maintain => {
                    // One replenished file per tick across all pools is
                    // enough; the release controller paces each mount.
                    if !replenished_this_tick
                        && self.maybe_replenish_pool(&mount, tick.response.level)
                    {
                        replenished_this_tick = true;
                    }
                }
                MountState::ObserveOnly => {
                    if tick.response.level != PressureLevel::Green {
                        unprotected_mounts.insert(mount.clone(), tick.response.level);
                        if pressured_without_surface
                            .as_ref()
                            .is_none_or(|(_, level)| tick.response.level > *level)
                        {
                            pressured_without_surface = Some((mount.clone(), tick.response.level));
                        }
                    }
                }
                MountState::Idle if replenish_level == PressureLevel::Green => {
                    if !replenished_this_tick && self.maybe_replenish_pool(&mount, replenish_level)
                    {
                        replenished_this_tick = true;
                    }
                }
                MountState::Recovery | MountState::Idle => {}
            }

            // Truthful emergency events: this mount's real free percent, the
            // files actually released, and only on entering Critical. A tick
            // that stays Critical (or an already-empty pool) is not news.
            if tick.response.level == PressureLevel::Critical {
                if self.emergency_mounts.insert(mount.clone()) {
                    self.logger_handle.send(ActivityEvent::Emergency {
                        details: format!(
                            "critical pressure on {} ({:.1}% free, urgency={:.2}): released {} \
                             ballast file(s), controller={}",
                            mount.display(),
                            tick.response.free_pct,
                            tick.response.urgency,
                            files_released,
                            decision.state,
                        ),
                        free_pct: tick.response.free_pct,
                    });
                }
            } else {
                self.emergency_mounts.remove(&mount);
            }
        }

        // Ballast has already had first priority. Refresh existing holds even
        // when compression is disabled or stopping, so live emergencies also
        // release older batches scored at a lower pressure level.
        let mount_levels: HashMap<PathBuf, PressureLevel> = self
            .mount_controllers
            .iter()
            .map(|(mount, controller)| (mount.clone(), controller.level()))
            .collect();
        self.shared_executor_config
            .compression_first
            .update_levels(&mount_levels);

        // Root probes for a new compression pass can block in native I/O.
        // Drain and enqueue emergency work before those probes, including
        // when the operator configured compression to start at Red/Critical.
        // Both sweep phases share the same maintenance cadence decision.
        let sweep_due = self.quarantine_sweep_due(now);
        let attempted_emergency_sweep = self.sweep_quarantine_entries(
            responses
                .iter()
                .filter(|tick| tick.response.level >= PressureLevel::Red),
            &root_mounts,
            sweep_due,
        );
        let (emergency_scans, pending_scans): (Vec<_>, Vec<_>) = pending_scans
            .into_iter()
            .partition(|(response, _, _)| response.level >= PressureLevel::Red);
        for (response, paths, catalog) in emergency_scans {
            if let Some(catalog) = catalog {
                self.catalog_epochs
                    .insert(response.causing_mount.clone(), (response.level, now));
                self.send_catalog_scan_request(scan_tx, scan_rx, response, catalog);
            } else {
                self.send_scan_request(scan_tx, scan_rx, response, paths);
            }
            self.last_tick_cleanup_ran = true;
        }

        // Publish Yellow/Orange holds before dispatching their cleanup. The
        // executor shares these holds, including for already queued work.
        if compress_tier_may_run(&self.config, self.policy_engine.lock().mode()) {
            self.compress_tier.tick(
                now,
                &self.config,
                &self.platform,
                &mount_levels,
                &self.logger_handle,
            );
        } else {
            self.compress_tier.stop_running_pass();
        }

        self.sweep_quarantines(
            responses
                .iter()
                .filter(|tick| tick.response.level < PressureLevel::Red),
            &root_mounts,
            now,
        );
        if sweep_due && attempted_emergency_sweep {
            self.last_quarantine_sweep = Some(now);
        }
        for (response, paths, catalog) in pending_scans {
            if self.shared_executor_config.compression_first.defers_mount(
                &response.causing_mount,
                response.level,
                Instant::now(),
            ) {
                continue;
            }
            if let Some(catalog) = catalog {
                // A held scan has not run. Leave its epoch due until dispatch.
                self.catalog_epochs
                    .insert(response.causing_mount.clone(), (response.level, now));
                self.send_catalog_scan_request(scan_tx, scan_rx, response, catalog);
            } else {
                self.send_scan_request(scan_tx, scan_rx, response, paths);
            }
            self.last_tick_cleanup_ran = true;
        }
        self.resolve_regrets();

        // Green maintenance (Q6): once per maintenance interval, a routine
        // pass over the roots the hazard-driven scheduler picks within its
        // budget. The Green behavior cell keeps it to high-confidence
        // candidates; the scanner's duty-cycle limiter still applies, the
        // empty-pass cooldown does not (the interval is its pacing); memory
        // Critical suppresses it.
        let maintenance_interval =
            Duration::from_secs(self.config.pressure.maintenance_interval_secs);
        // Maintenance is per mount state, not per worst level: a mount in
        // Maintain keeps its routine passes even while an unrelated,
        // observe-only mount is pressured (the operator-host layout).
        let maintain_tick = responses.iter().find(|tick| {
            self.mount_controllers
                .get(&tick.response.causing_mount)
                .is_some_and(|controller| controller.state() == MountState::Maintain)
        });
        if let Some(maintain_tick) = maintain_tick
            && scan_allowed
            && maintenance_interval > Duration::ZERO
            && self.behavior_state.memory_level != MemoryPressureLevel::Critical
            && self
                .last_maintenance_scan
                .is_none_or(|last| now.saturating_duration_since(last) >= maintenance_interval)
        {
            let plan = self.voi_scheduler.schedule(now);
            self.last_voi_plan = Some((chrono::Utc::now().to_rfc3339(), plan.clone()));
            // Only roots whose own mount is in Maintain: a root on a mount
            // parked in Recovery (or reclaiming, or idle after an empty
            // pass) is that mount's business, not the routine pass's.
            let entries: Vec<_> = plan
                .paths
                .iter()
                .filter(|entry| self.root_mount_in_maintain(&entry.path))
                .collect();
            let paths: Vec<PathBuf> = entries.iter().map(|entry| entry.path.clone()).collect();
            if !paths.is_empty() {
                self.last_maintenance_scan = Some(now);
                let response = &maintain_tick.response;
                let message = format!(
                    "maintenance scan: {} of {} root(s) by hazard index (budget {}, fallback={}): {}",
                    paths.len(),
                    self.config.scanner.root_paths.len(),
                    plan.budget_total,
                    plan.fallback_active,
                    entries
                        .iter()
                        .map(|entry| format!(
                            "{} (index {:.0})",
                            entry.path.display(),
                            entry.utility
                        ))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                eprintln!("[SBH-DAEMON] {message}");
                self.logger_handle.send(ActivityEvent::Info { message });
                let request = ScanRequest {
                    paths,
                    urgency: response.urgency.max(0.05),
                    pressure_level: response.level,
                    free_pct: Some(response.free_pct),
                    max_delete_batch: behavior_delete_batch_limit(
                        self.behavior_state.mode,
                        response.max_delete_batch,
                    ),
                    force_full_scan: false,
                    config_update: None,
                    catalog_roots: Vec::new(),
                    maintenance: true,
                    target_bytes: None,
                };
                let response = response.clone();
                self.enqueue_scan_logged(scan_tx, scan_rx, &response, request);
            }
        }

        // Predictive safety net on the worst mount at Green. The controllers
        // already escalate a mount whose own horizon is short; this keeps the
        // policy's min_score recommendation, the ballast release on the mount
        // it named, and the FallbackSafe recovery scans.
        if response.level == PressureLevel::Green {
            let predictive_min_score = match &self.last_predictive_action {
                PredictiveAction::PreemptiveCleanup {
                    recommended_min_score,
                    ..
                } => Some(*recommended_min_score),
                _ => None,
            };
            let predictive_ballast_mount = match &self.last_predictive_action {
                PredictiveAction::ImminentDanger { mount, .. } => Some(mount.clone()),
                _ => None,
            };
            let needs_scan = !matches!(self.last_predictive_action, PredictiveAction::Clear);

            if let Some(min_score) = predictive_min_score {
                self.shared_executor_config.set_min_score(min_score);
            }
            if let Some(ref mount) = predictive_ballast_mount {
                let _ = self.release_ballast(mount, response);
                self.last_tick_cleanup_ran = true;
            }
            // Force periodic scans when stuck in FallbackSafe at green
            // pressure so that guard windows can update and recovery can
            // trigger. Without this, FallbackSafe at green is permanent.
            let in_fallback = self.policy_engine.lock().mode() == ActiveMode::FallbackSafe;
            if scan_allowed && (needs_scan || in_fallback) {
                self.send_scan_request(scan_tx, scan_rx, response, root_paths);
                if needs_scan {
                    self.last_tick_cleanup_ran = true;
                }
            }
        }

        // A pressured mount sbh cannot act on is reported (rate-limited), not
        // spun on: it stays observe-only and never tightens the tick.
        if let Some((mount, level)) = pressured_without_surface {
            let should_warn = self
                .last_device_affinity_warn
                .is_none_or(|last| now.duration_since(last) >= DEVICE_AFFINITY_WARN_INTERVAL);
            if should_warn {
                self.last_device_affinity_warn = Some(now);
                let msg = format!(
                    "pressure on {} ({level:?}) but no root_path, ballast pool or cross_devices \
                     fallback covers that device; observing only (idle_reason={})",
                    mount.display(),
                    IdleReason::NoSurface.as_str()
                );
                eprintln!("[SBH-DAEMON] {msg}");
                self.logger_handle
                    .send(ActivityEvent::Info { message: msg });
            }
        }
        self.emit_reclaim_unavailable(&unprotected_mounts, now);
        self.report_unreclaimable_growth(now);
        if !self.config.scanner.target_only_roots.is_empty() {
            let mounts: HashMap<PathBuf, (PressureLevel, f64)> = self
                .mount_controllers
                .iter()
                .filter(|(mount, controller)| {
                    !self.shared_executor_config.compression_first.defers_mount(
                        mount,
                        controller.level(),
                        Instant::now(),
                    )
                })
                .map(|(mount, controller)| {
                    (mount.clone(), (controller.level(), controller.urgency()))
                })
                .collect();
            self.target_tier.tick(
                now,
                &self.config,
                &self.platform,
                &mounts,
                del_tx,
                &self.logger_handle,
            );
        }

        global_tick(cadence, base_poll)
    }

    /// For a mount that has stayed at Red or worse for
    /// `ATTRIBUTION_SUSTAINED_PRESSURE` (reclaim is not keeping up, whether
    /// its scans find nothing or only crumbs), name the directories that hold
    /// its bytes (SBH-2007), at most once per `ATTRIBUTION_REPORT_INTERVAL`.
    /// The bounded size probe runs on its own low-priority thread so the
    /// monitor tick never waits on it.
    fn report_unreclaimable_growth(&mut self, now: Instant) {
        let levels: Vec<(PathBuf, String)> = self
            .mount_controllers
            .iter()
            .map(|(mount, controller)| (mount.clone(), controller.record(now).level))
            .collect();
        let mut due = Vec::new();
        for (mount, level) in levels {
            if !matches!(level.as_str(), "red" | "critical") {
                self.attribution_pressured_since.remove(&mount);
                continue;
            }
            let since = *self
                .attribution_pressured_since
                .entry(mount.clone())
                .or_insert(now);
            let sustained = now.duration_since(since) >= ATTRIBUTION_SUSTAINED_PRESSURE;
            let not_recent = self
                .attribution_reported
                .get(&mount)
                .is_none_or(|last| now.duration_since(*last) >= ATTRIBUTION_REPORT_INTERVAL);
            if sustained && not_recent {
                due.push((mount, level));
            }
        }
        for (mount, level) in due {
            self.attribution_reported.insert(mount.clone(), now);
            let logger = self.logger_handle.clone();
            let spawned = std::thread::Builder::new()
                .name("sbh-attribution".to_string())
                .spawn(move || {
                    let consumers = crate::daemon::attribution::top_consumers(
                        &mount,
                        crate::daemon::attribution::PROBE_BUDGET_ENTRIES,
                        crate::daemon::attribution::REPORT_TOP,
                    );
                    if consumers.is_empty() {
                        return;
                    }
                    let message = format!(
                        "pressure {level} on {} for over {} min and reclaim is not keeping \
                         up; largest directories: {}. Next: move or clean one of these, or \
                         add a scanner.root_path covering disposable data in it",
                        mount.display(),
                        ATTRIBUTION_SUSTAINED_PRESSURE.as_secs() / 60,
                        crate::daemon::attribution::describe(&consumers)
                    );
                    eprintln!("[SBH-DAEMON] {message}");
                    logger.send(ActivityEvent::Warning {
                        code: "SBH-2007".to_string(),
                        message,
                    });
                });
            if let Err(err) = spawned {
                eprintln!("[SBH-DAEMON] growth attribution thread failed to start: {err}");
            }
        }
    }

    /// The loud version of "observing only": a notification and a warning
    /// event once per pressure epoch for every pressured mount with no
    /// reclaim surface, repeated at the special-location alert interval,
    /// escalated at once when the level rises, and cleared (logged once)
    /// when the mount recovers or gains a surface.
    fn emit_reclaim_unavailable(
        &mut self,
        unprotected: &HashMap<PathBuf, PressureLevel>,
        now: Instant,
    ) {
        let interval = Duration::from_secs(
            self.config
                .special_locations
                .alert_interval_minutes
                .saturating_mul(60),
        );
        let mounts: Vec<PathBuf> = self.mount_controllers.keys().cloned().collect();
        for mount in mounts {
            let level = unprotected.get(&mount).copied();
            let severity = match level {
                None | Some(PressureLevel::Green) => SpecialAlert::None,
                Some(PressureLevel::Yellow | PressureLevel::Orange) => SpecialAlert::Warning,
                Some(PressureLevel::Red | PressureLevel::Critical) => SpecialAlert::Critical,
            };
            if !self
                .reclaim_alerts
                .should_emit(&mount, severity, now, interval)
            {
                continue;
            }
            let Some(level) = level else {
                let message = format!(
                    "pressure on {} cleared, or sbh gained a reclaim surface there",
                    mount.display()
                );
                eprintln!("[SBH-DAEMON] {message}");
                self.logger_handle.send(ActivityEvent::Info { message });
                continue;
            };
            let level_name = format!("{level:?}").to_lowercase();
            let reason = format!(
                "no root_path, catalog root, cross_devices fallback or releasable ballast on \
                 this device (idle_reason={})",
                IdleReason::NoSurface.as_str()
            );
            let message = format!(
                "reclaim unavailable: pressure {level_name} on {} and nothing sbh can reclaim \
                 there ({reason}). Next: add a scanner.root_path on this device, set \
                 scanner.catalog_roots_on_pressured_device = true, or run `sbh ballast provision`",
                mount.display()
            );
            eprintln!("[SBH-DAEMON] {message}");
            self.logger_handle.send(ActivityEvent::Warning {
                code: "SBH-2006".to_string(),
                message,
            });
            self.notification_manager
                .notify(&NotificationEvent::ReclaimUnavailable {
                    mount: mount.to_string_lossy().into_owned(),
                    level: level_name,
                    reason,
                });
        }
    }

    /// A mount just entered `Recovery` (EROFS or ENOSPC on deletion): free
    /// what can be freed without a metadata write of our own (release every
    /// ballast file on it), tell the operator exactly what to run, and let
    /// the controller hold deletions until a probe write succeeds.
    /// Whether `root` sits on a mount whose controller is in `Maintain`
    /// (true for a mount that has no controller yet).
    fn root_mount_in_maintain(&self, root: &Path) -> bool {
        let Ok(stats) = self.fs_collector.collect(root) else {
            return true;
        };
        self.mount_controllers
            .get(&stats.mount_point)
            .is_none_or(|controller| controller.state() == MountState::Maintain)
    }

    fn enter_mount_recovery(
        &mut self,
        mount: &Path,
        response: &crate::monitor::pid::PressureResponse,
    ) {
        let pool_mount = self.pool_mount(mount);
        if let Some(pool) = self.ballast_coordinator.pool_for_mount(mount) {
            self.release_controller
                .bind_pool(&pool_mount, &pool.ballast_dir);
        }
        let fs_type = self
            .fs_collector
            .collect(mount)
            .map(|stats| stats.fs_type)
            .unwrap_or_default();
        let root_hint = self
            .config
            .scanner
            .root_paths
            .iter()
            .find(|root| {
                self.fs_collector
                    .collect(root)
                    .is_ok_and(|stats| stats.mount_point == mount)
            })
            .map_or_else(
                || mount.display().to_string(),
                |root| root.display().to_string(),
            );

        let available = self.ballast_coordinator.pool_for_mount(mount).map_or(
            0,
            super::super::ballast::coordinator::BallastPool::available_count,
        );
        let mut released = 0;
        if available > 0
            && let Ok(Some(report)) = self.ballast_coordinator.release_for_mount(mount, available)
        {
            released = report.files_released;
            self.release_controller
                .on_released(&pool_mount, report.files_released);
            self.log_ballast_releases(&report.released, response);
        }

        let mut commands = vec![format!("sudo sbh emergency {root_hint} --yes")];
        if fs_type == "btrfs" {
            commands.push(format!("sudo btrfs filesystem usage {}", mount.display()));
            commands.push(format!(
                "sudo btrfs balance start -dusage=50 {}",
                mount.display()
            ));
        }
        let message = format!(
            "mount {} ({fs_type}) refused writes (read-only or out of metadata space) at {:.1}% \
             free: released {released} ballast file(s); deletions on it are paused until a probe \
             write succeeds above red_min. Next: {}",
            mount.display(),
            response.free_pct,
            commands.join(" ; ")
        );
        eprintln!("[SBH-RECOVERY] {message}");
        self.logger_handle.send(ActivityEvent::Error {
            code: "SBH-2004".to_string(),
            message: message.clone(),
        });
        self.notification_manager.notify(&NotificationEvent::Error {
            code: "SBH-2004".to_string(),
            message,
        });
    }

    /// Feed a completed scan pass to the per-mount controllers: a mount whose
    /// roots all came back empty, with nothing left to release, goes idle
    /// with an exponential rescan backoff.
    fn note_scan_pass_per_mount(
        &mut self,
        root_stats: &[RootScanResult],
        pressure_level: PressureLevel,
        background: bool,
        now: Instant,
    ) {
        let mut found_by_mount: HashMap<PathBuf, usize> = HashMap::new();
        for stat in root_stats {
            let Ok(stats) = self.fs_collector.collect(&stat.path) else {
                continue;
            };
            *found_by_mount.entry(stats.mount_point).or_insert(0) += stat.candidates_found;
        }
        for (mount, found) in found_by_mount {
            let releasable = self
                .ballast_coordinator
                .pool_for_mount(&mount)
                .is_some_and(|pool| pool.available_count() > 0);
            let Some(controller) = self.mount_controllers.get_mut(&mount) else {
                continue;
            };
            if let Some((from, to)) =
                controller.note_pass_at_level(pressure_level, background, found, releasable, now)
            {
                let message = format!(
                    "mount {} {from} -> {to} (empty_passes={} rescan_in={}s idle_reason={})",
                    mount.display(),
                    controller.empty_passes(),
                    controller.idle_backoff().as_secs(),
                    controller
                        .idle_reason()
                        .map_or("none", crate::daemon::mount_controller::IdleReason::as_str),
                );
                eprintln!("[SBH-MOUNT] {message}");
                self.logger_handle.send(ActivityEvent::Info { message });
            }
        }
    }

    /// The mount whose pool serves `mount` (itself unless it is a
    /// same-filesystem alias). Release history, cooldowns and the floor flag
    /// are kept under this key, which is also what the state file saves.
    fn pool_mount(&self, mount: &Path) -> PathBuf {
        self.ballast_coordinator
            .pool_for_mount(mount)
            .map_or_else(|| mount.to_path_buf(), |pool| pool.mount_point.clone())
    }

    /// Replenish one released ballast file on `mount` if its pool is short and
    /// the release controller's cooldown allows it. Returns whether a file was
    /// created.
    fn maybe_replenish_pool(&mut self, mount: &Path, level: PressureLevel) -> bool {
        // An alias mount's inventory row is skipped and names its keeper's
        // default directory: pace the pool under its own mount instead.
        let pool_mount = self.pool_mount(mount);
        let Some(pool_info) = self
            .ballast_coordinator
            .inventory()
            .into_iter()
            .find(|item| item.mount_point == pool_mount && !item.skipped)
        else {
            return false;
        };
        self.release_controller
            .bind_pool(&pool_mount, &pool_info.ballast_dir);
        if !self.release_controller.is_ready_for_replenish(
            &pool_mount,
            level,
            pool_info.files_available,
            pool_info.files_total,
        ) {
            return false;
        }
        let collector = &self.fs_collector;
        let free_check = || collector.collect(mount).map_or(0.0, |s| s.free_pct());
        let Ok(Some(report)) = self
            .ballast_coordinator
            .replenish_for_mount(mount, Some(&free_check))
        else {
            return false;
        };
        if report.skipped_for_floor > 0 {
            self.floor_limited.insert(pool_mount.clone());
        } else if report.files_created > 0 {
            self.floor_limited.remove(&pool_mount);
        }
        if report.files_created == 0 {
            return false;
        }
        for (path, size_bytes) in &report.created {
            self.logger_handle.send(ActivityEvent::BallastReplenished {
                path: path.display().to_string(),
                size_bytes: *size_bytes,
            });
        }
        self.release_controller
            .on_replenished(&pool_mount, report.files_created);
        self.notification_manager
            .notify(&NotificationEvent::BallastReplenished {
                mount: mount.to_string_lossy().to_string(),
                files_replenished: report.files_created,
            });
        true
    }

    /// Helper to release ballast from the causing mount using the global controller logic.
    fn release_ballast(
        &mut self,
        mount: &std::path::Path,
        response: &crate::monitor::pid::PressureResponse,
    ) -> Result<usize> {
        let Some(pool) = self.ballast_coordinator.pool_for_mount(mount) else {
            return Ok(0);
        };
        let available = pool.available_count();
        let expected = pool.expected_count();
        // A same-filesystem alias mount shares its keeper's pool; release
        // history lives under the pool's own mount, the key it is saved and
        // restored under across restarts.
        let pool_mount = pool.mount_point.clone();
        self.release_controller
            .bind_pool(&pool_mount, &pool.ballast_dir);
        let count =
            self.release_controller
                .files_to_release(&pool_mount, response, available, expected);

        let mut released = 0;
        if count > 0 {
            let free_before = self
                .fs_collector
                .collect(mount)
                .map_or(0, |s| s.available_bytes);
            if let Some(report) = self.ballast_coordinator.release_for_mount(mount, count)? {
                for warning in &report.warnings {
                    eprintln!("[sbh] warning: {warning}");
                }

                released = report.files_released;
                self.release_controller
                    .on_released(&pool_mount, report.files_released);
                self.release_controller.record_release(
                    &pool_mount,
                    report.bytes_freed,
                    free_before,
                    Instant::now(),
                );
                self.log_ballast_releases(&report.released, response);

                self.notification_manager
                    .notify(&NotificationEvent::BallastReleased {
                        mount: mount.to_string_lossy().to_string(),
                        files_released: report.files_released,
                        bytes_freed: report.bytes_freed,
                    });
            }
        }
        Ok(released)
    }

    /// One `ballast_release` activity event per removed file, tagged with
    /// the pressure that caused it.
    fn log_ballast_releases(
        &self,
        released: &[(PathBuf, u64)],
        response: &crate::monitor::pid::PressureResponse,
    ) {
        let pressure = format!("{:?}", response.level).to_lowercase();
        for (path, size_bytes) in released {
            self.logger_handle.send(ActivityEvent::BallastReleased {
                path: path.display().to_string(),
                size_bytes: *size_bytes,
                pressure: pressure.clone(),
                free_pct: response.free_pct,
            });
        }
    }

    fn send_scan_request(
        &mut self,
        scan_tx: &Sender<ScanRequest>,
        scan_rx: &Receiver<ScanRequest>,
        response: &crate::monitor::pid::PressureResponse,
        paths: Vec<PathBuf>,
    ) {
        // Under Green/Yellow pressure, skip enqueue entirely if the channel is
        // already full — a scan is already in progress and there's no urgency.
        // This eliminates most "scan channel saturated" log noise.
        if response.level < PressureLevel::Orange && scan_tx.is_full() {
            return;
        }

        // W1 planner: the bytes that bring the pressured mount back to
        // Green, so the executor can plan the set that reaches them with the
        // least expected loss. Aiming only at Yellow parked hosts at the
        // Orange/Yellow edge: v2 does not walk at Yellow without dirty
        // roots, so the next build burst found them at Orange again with no
        // margin (fleet audit 2026-09-24: most hosts lived at 80-94% used).
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let target_bytes = (response.level >= PressureLevel::Orange)
            .then(|| self.fs_collector.collect(&response.causing_mount).ok())
            .flatten()
            .map(|stats| {
                let wanted = (stats.total_bytes as f64 * self.config.pressure.green_min_free_pct
                    / 100.0) as u64;
                wanted.saturating_sub(stats.available_bytes)
            })
            .filter(|bytes| *bytes > 0);
        let request = ScanRequest {
            paths,
            urgency: response.urgency,
            pressure_level: response.level,
            free_pct: Some(response.free_pct),
            max_delete_batch: behavior_delete_batch_limit(
                self.behavior_state.mode,
                response.max_delete_batch,
            ),
            force_full_scan: false,
            config_update: None,
            catalog_roots: Vec::new(),
            maintenance: false,
            target_bytes,
        };
        self.enqueue_scan_logged(scan_tx, scan_rx, response, request);
    }

    /// Catalog roots for `mount` (W1 catalog roots), derived from the
    /// cross-platform templates for every real user home on that device and
    /// cached for `scanner.catalog_rescan_interval_secs`. Logs the derived
    /// set once per refresh.
    fn catalog_roots_for(&mut self, mount: &Path, now: Instant) -> Vec<ExpandedCatalogRoot> {
        let ttl = Duration::from_secs(self.config.scanner.catalog_rescan_interval_secs.max(1));
        if let Some((derived_at, roots)) = self.catalog_root_cache.get(mount)
            && now.saturating_duration_since(*derived_at) < ttl
        {
            return roots.clone();
        }
        let roots = cleanup_catalog::device_of(mount).map_or_else(Vec::new, |device| {
            let homes = cleanup_catalog::user_homes(&self.platform.user_home());
            cleanup_catalog::catalog_roots_for_mount(cleanup_catalog::CATALOG_ROOTS, &homes, device)
        });
        let message = format!(
            "catalog roots for {}: {} derived ({})",
            mount.display(),
            roots.len(),
            roots
                .iter()
                .map(|root| format!("{} [{}]", root.path.display(), root.rule))
                .collect::<Vec<_>>()
                .join(", ")
        );
        eprintln!("[SBH-DAEMON] {message}");
        self.logger_handle.send(ActivityEvent::Info { message });
        self.catalog_root_cache
            .insert(mount.to_path_buf(), (now, roots.clone()));
        roots
    }

    /// Dispatch a catalog-only scan: the derived roots are the request's
    /// paths and its `catalog_roots`, so the scanner probes each as one
    /// opaque candidate unit instead of walking.
    fn send_catalog_scan_request(
        &mut self,
        scan_tx: &Sender<ScanRequest>,
        scan_rx: &Receiver<ScanRequest>,
        response: &crate::monitor::pid::PressureResponse,
        catalog_roots: Vec<ExpandedCatalogRoot>,
    ) {
        let request = ScanRequest {
            paths: catalog_roots.iter().map(|root| root.path.clone()).collect(),
            urgency: response.urgency,
            pressure_level: response.level,
            free_pct: Some(response.free_pct),
            max_delete_batch: behavior_delete_batch_limit(
                self.behavior_state.mode,
                response.max_delete_batch,
            ),
            force_full_scan: false,
            config_update: None,
            catalog_roots,
            maintenance: false,
            target_bytes: None,
        };
        self.enqueue_scan_logged(scan_tx, scan_rx, response, request);
    }

    fn enqueue_scan_logged(
        &mut self,
        scan_tx: &Sender<ScanRequest>,
        scan_rx: &Receiver<ScanRequest>,
        response: &crate::monitor::pid::PressureResponse,
        request: ScanRequest,
    ) {
        let replace_on_full = response.level >= PressureLevel::Red || response.urgency >= 0.90;
        match enqueue_scan_request(scan_tx, scan_rx, request, replace_on_full) {
            ScanEnqueueStatus::Queued => {}
            ScanEnqueueStatus::ReplacedStale | ScanEnqueueStatus::DeferredFull => {
                // Rate-limit to once per hour. Scans routinely take 300-600s
                // while monitor ticks every 60s, so this condition fires on
                // nearly every tick during active scanning — expected behavior,
                // not worth logging frequently.
                let now = Instant::now();
                let should_log = self
                    .last_scan_channel_warn
                    .is_none_or(|last| now.duration_since(last) >= Duration::from_hours(1));
                if should_log {
                    let suppressed = self.scan_channel_warn_suppressed;
                    self.scan_channel_warn_suppressed = 0;
                    self.last_scan_channel_warn = Some(now);
                    if suppressed > 0 {
                        eprintln!(
                            "[SBH-DAEMON] scan channel saturated ({suppressed} deferred requests since last log)"
                        );
                    } else {
                        eprintln!(
                            "[SBH-DAEMON] scan channel saturated (request replaced or deferred)"
                        );
                    }
                } else {
                    self.scan_channel_warn_suppressed += 1;
                }
            }
            ScanEnqueueStatus::Disconnected => {
                eprintln!("[SBH-DAEMON] scan channel disconnected, dropping scan request");
            }
        }
    }

    /// Queue the SIGUSR1 scan. `false` means the scan queue is full and the
    /// caller retries next tick; a disconnected queue is logged and given up.
    fn trigger_forced_scan(
        root_paths: &[PathBuf],
        scan_tx: &Sender<ScanRequest>,
        response: &crate::monitor::pid::PressureResponse,
    ) -> bool {
        let request = ScanRequest {
            paths: root_paths.to_vec(),
            urgency: response.urgency.max(0.5), // at least moderate urgency for forced scans
            pressure_level: response.level,
            free_pct: Some(response.free_pct),
            max_delete_batch: response.max_delete_batch,
            force_full_scan: true,
            config_update: None,
            catalog_roots: Vec::new(),
            maintenance: false,
            target_bytes: None,
        };
        // Block briefly: the scanner may be about to take the next request.
        match scan_tx.send_timeout(request, Duration::from_millis(100)) {
            Ok(()) => {
                eprintln!("[SBH-DAEMON] forced scan triggered (SIGUSR1)");
                true
            }
            Err(SendTimeoutError::Timeout(_)) => false,
            Err(SendTimeoutError::Disconnected(_)) => {
                eprintln!("[SBH-DAEMON] forced scan dropped (SIGUSR1): scan channel disconnected");
                true
            }
        }
    }

    fn check_predictive_warning(&mut self, response: &crate::monitor::pid::PressureResponse) {
        // Suppress prediction notifications at Green and Yellow pressure.
        //
        // At Green (>20% free), "disk full in 5m" is clearly an EWMA spike
        // artifact from compilation bursts — false alarms that desensitize.
        //
        // At Yellow (10-20% free), the same EWMA spikes produce false alarms
        // because burst consumption rates are transiently high. The pressure
        // system already escalates to Orange+ before real danger, and the
        // predictive policy's burst detector handles actual threat assessment.
        // Notification spam at Yellow provides no actionable signal.
        if response.level <= PressureLevel::Yellow {
            return;
        }

        // If the predictive policy (with burst/free-space/confidence gates)
        // already decided Clear, don't emit a raw notification — the policy
        // has better context than the raw seconds-to-threshold value.
        if matches!(self.last_predictive_action, PredictiveAction::Clear) {
            return;
        }

        let Some(seconds) = response.predicted_seconds else {
            // Prediction cleared — do NOT reset cooldown state here.
            // When the disk hovers at the red threshold, predicted_seconds
            // alternates between Some(tiny) and None on consecutive ticks.
            // Resetting last_predictive_level/warning on each None tick
            // defeats the 300-second cooldown, causing every-second CRIT spam.
            // The cooldown expires naturally (300s) and the level gets updated
            // when a new notification actually fires.
            return;
        };

        // Suppress bogus predictions when confidence is below the configured
        // minimum (default 70%).  Without this gate the daemon spams
        // "disk full in N minutes" warnings on healthy disks whenever the
        // EWMA estimator is in fallback mode or has insufficient data.
        if self.last_ewma_confidence < self.config.pressure.prediction.min_confidence {
            return;
        }

        let warning_horizon_secs = self.config.pressure.prediction.warning_horizon_minutes * 60.0;

        if seconds > warning_horizon_secs {
            return;
        }

        let minutes = seconds / 60.0;
        // Determine severity level to match NotificationEvent::PredictiveWarning::level():
        //   Critical  < critical_danger_minutes  (default  2 min)
        //   Red       < imminent_danger_minutes  (default  5 min)
        //   Orange    < action_horizon_minutes   (default 30 min)
        //   Warning   everything else within the warning horizon
        let current_level = if minutes < self.config.pressure.prediction.critical_danger_minutes {
            NotificationLevel::Critical
        } else if minutes < self.config.pressure.prediction.imminent_danger_minutes {
            NotificationLevel::Red
        } else if minutes < self.config.pressure.prediction.action_horizon_minutes {
            NotificationLevel::Orange
        } else {
            NotificationLevel::Warning
        };

        let now = Instant::now();
        let should_notify = match self.last_predictive_level {
            Some(last_level) => {
                // Escalate if severity increases (e.g. Warning -> Orange -> Red)
                // OR if time cooldown (5 mins) expires.
                if current_level > last_level {
                    true
                } else if let Some(last_time) = self.last_predictive_warning {
                    now.duration_since(last_time) >= Duration::from_mins(5)
                } else {
                    true
                }
            }
            None => true,
        };

        if !should_notify {
            return;
        }

        self.last_predictive_warning = Some(now);
        self.last_predictive_level = Some(current_level);
        self.notification_manager
            .notify(&NotificationEvent::PredictiveWarning {
                mount: response.causing_mount.to_string_lossy().to_string(),
                minutes_remaining: seconds / 60.0,
                confidence: self.last_ewma_confidence,
            });
    }

    fn check_swap_thrash(&mut self) {
        let Ok(memory) = self.platform.memory_info() else {
            return;
        };

        let now = Instant::now();
        let thrash_risk = is_swap_thrash_risk(&memory);
        if !thrash_risk {
            self.swap_thrash_active = false;
            return;
        }

        let should_warn = !self.swap_thrash_active
            || self
                .last_swap_thrash_warning
                .is_none_or(|last| now.duration_since(last) >= SWAP_THRASH_WARNING_COOLDOWN);
        self.swap_thrash_active = true;
        if !should_warn {
            return;
        }
        self.last_swap_thrash_warning = Some(now);

        let swap_used_bytes = memory
            .swap_total_bytes
            .saturating_sub(memory.swap_free_bytes);
        let swap_used_pct = bytes_to_pct(swap_used_bytes, memory.swap_total_bytes);
        let message = format!(
            "swap thrash risk detected: swap_used_pct={swap_used_pct:.1}, \
             swap_used_bytes={swap_used_bytes}, swap_total_bytes={}, ram_available_bytes={}",
            memory.swap_total_bytes, memory.available_bytes
        );

        self.logger_handle.send(ActivityEvent::Error {
            code: "SBH-2010".to_string(),
            message: message.clone(),
        });
        self.notification_manager.notify(&NotificationEvent::Error {
            code: "SBH-2010".to_string(),
            message,
        });
    }

    // ──────────────────── special locations ────────────────────

    #[allow(clippy::too_many_lines)]
    fn check_special_locations(
        &mut self,
        scan_tx: &Sender<ScanRequest>,
        scan_rx: &Receiver<ScanRequest>,
    ) {
        let now = Instant::now();
        let locations = self.special_locations.all().to_vec();

        let rule = HorizonRule {
            alert_horizon: Duration::from_secs(
                self.config.special_locations.alert_horizon_minutes.max(1) * 60,
            ),
            absolute_floor_bytes: self.config.special_locations.absolute_floor_bytes,
            ..HorizonRule::default()
        };
        let alert_interval =
            Duration::from_secs(self.config.special_locations.alert_interval_minutes.max(1) * 60);

        for location in &locations {
            let last_scan = self.last_special_scan.get(&location.path).copied();
            if !location.scan_due(last_scan, now) {
                continue;
            }

            let Ok(stats) = self.fs_collector.collect(&location.path) else {
                continue;
            };

            self.last_special_scan.insert(location.path.clone(), now);

            // Q2: alert on time-to-harm and real shortage of room, not on a
            // percentage alone. The write rate is the mount's EWMA; a location
            // on an unmonitored mount (typically /dev/shm) gets the floored
            // rate, and its fullness rule still applies.
            let ram_backed = self
                .platform
                .is_ram_backed(&location.path)
                .unwrap_or(matches!(
                    location.kind,
                    crate::monitor::special_locations::SpecialKind::Tmpfs
                        | crate::monitor::special_locations::SpecialKind::DevShm
                        | crate::monitor::special_locations::SpecialKind::Ramfs
                ));
            let rate = self
                .mount_rates
                .get(&stats.mount_point)
                .copied()
                .unwrap_or(0.0);
            let assessment = rule.assess(location, &stats, rate, ram_backed);
            let emit = self.special_alerts.should_emit(
                &location.path,
                assessment.alert,
                now,
                alert_interval,
            );
            if emit {
                let message = format!(
                    "special location {:?} ({}) {}: {:.1}% free, {} ({:.0}s horizon, urgency {:.2})",
                    location.kind,
                    location.path.display(),
                    assessment.alert.as_str(),
                    stats.free_pct(),
                    assessment.reason,
                    assessment.horizon_secs,
                    assessment.urgency,
                );
                eprintln!("[SBH-SPECIAL] {message}");
                match assessment.alert {
                    SpecialAlert::None => self.logger_handle.send(ActivityEvent::Info { message }),
                    SpecialAlert::Warning | SpecialAlert::Critical => {
                        self.logger_handle.send(ActivityEvent::Warning {
                            code: "SBH-2001".to_string(),
                            message,
                        });
                    }
                }
            }

            let previous = self.last_special_notify.get(&location.path).copied();
            if assessment.alert == SpecialAlert::None {
                if special_episode_over(previous, now, alert_interval) {
                    self.last_special_notify.remove(&location.path);
                }
                continue;
            }
            {
                let urgency = assessment.urgency;
                let pressure_level = match assessment.alert {
                    SpecialAlert::Critical => PressureLevel::Red,
                    _ if urgency >= 0.75 => PressureLevel::Orange,
                    _ => PressureLevel::Yellow,
                };
                let (notify_from, notified) = special_episode_step(previous, pressure_level);
                if let Some(from) = notify_from {
                    self.notification_manager
                        .notify(&NotificationEvent::PressureChanged {
                            from: format!("{from:?}"),
                            to: format!("{pressure_level:?}"),
                            mount: location.path.to_string_lossy().into_owned(),
                            free_pct: stats.free_pct(),
                        });
                }
                self.last_special_notify
                    .insert(location.path.clone(), (notified, now));

                // Trigger root filesystem scan: special location pressure (e.g. /dev/shm
                // full) indicates agent swarm activity that is likely also generating root
                // filesystem artifacts. Proactively scan to clean up before root hits capacity.
                //
                // No ballast is released here. A disk-backed location's own mount
                // releases on its own pressure level; releasing on this alert bypassed
                // that gating and drained a reserve on every write burst (a macOS /tmp
                // on the Data volume raised ~100 "filling fast" alerts a day). A RAM-backed
                // location (/dev/shm) gains nothing from freeing disk ballast at all.
                let max_delete_batch = match pressure_level {
                    PressureLevel::Red | PressureLevel::Critical => 100,
                    PressureLevel::Orange => 60,
                    _ => 40,
                };

                let mut scan_paths =
                    special_location_scan_roots(&location.path, &self.config.scanner.root_paths);
                for root in &self.config.scanner.root_paths {
                    push_unique_path(&mut scan_paths, root.clone());
                }

                let request = ScanRequest {
                    paths: scan_paths,
                    urgency,
                    pressure_level,
                    free_pct: Some(stats.free_pct()),
                    max_delete_batch,
                    force_full_scan: false,
                    config_update: None,
                    catalog_roots: Vec::new(),
                    maintenance: false,
                    target_bytes: None,
                };

                match enqueue_scan_request(scan_tx, scan_rx, request, true) {
                    ScanEnqueueStatus::Queued | ScanEnqueueStatus::ReplacedStale => {}
                    ScanEnqueueStatus::DeferredFull => {
                        eprintln!(
                            "[SBH-DAEMON] scan channel full (special location trigger), deferred"
                        );
                    }
                    ScanEnqueueStatus::Disconnected => {
                        eprintln!(
                            "[SBH-DAEMON] scan channel disconnected (special location trigger)"
                        );
                    }
                }
            }
        }
    }

    // ──────────────────── ballast ────────────────────

    fn provision_ballast(&mut self) -> Result<()> {
        if !self.config.ballast.auto_provision {
            eprintln!(
                "[SBH-DAEMON] ballast auto_provision = false; not provisioning \
                 (run `sbh ballast provision` to build the pool)"
            );
            return Ok(());
        }
        // A stop requested mid-provisioning ends it at the next file.
        let shutdown = self.signal_handler.shutdown_token();
        let report = self
            .ballast_coordinator
            .provision_all_until(self.platform.as_ref(), &shutdown)?;

        let total_files = report.total_files_created();
        let total_bytes = report.total_bytes();

        if total_files > 0 {
            eprintln!(
                "[SBH-DAEMON] provisioned {total_files} ballast files ({total_bytes} bytes total)"
            );
        }

        for (path, provision_report) in &report.per_volume {
            if provision_report.skipped_for_floor > 0 {
                self.floor_limited.insert(path.clone());
            } else {
                self.floor_limited.remove(path);
            }
            for (file, size_bytes) in &provision_report.created {
                self.logger_handle.send(ActivityEvent::BallastProvisioned {
                    path: file.display().to_string(),
                    size_bytes: *size_bytes,
                });
            }
            if provision_report.skipped_for_floor > 0 {
                let message = format!(
                    "ballast provision volume={} created={} skipped_for_floor={} floor_pct={:.1} free_after_pct={}",
                    path.display(),
                    provision_report.files_created,
                    provision_report.skipped_for_floor,
                    provision_report.floor_pct,
                    provision_report
                        .free_pct_after
                        .map_or_else(|| "unknown".to_string(), |pct| format!("{pct:.1}"))
                );
                eprintln!("[SBH-BALLAST] {message}");
                self.logger_handle.send(ActivityEvent::Info { message });
            }
            for err in &provision_report.errors {
                eprintln!(
                    "[SBH-DAEMON] ballast provision incomplete for {}: {}",
                    path.display(),
                    err
                );
            }
        }

        for (path, err) in &report.skipped_volumes {
            eprintln!(
                "[SBH-DAEMON] ballast provision skipped for {}: {}",
                path.display(),
                err
            );
        }

        Ok(())
    }

    // ──────────────────── config reload ────────────────────

    #[allow(clippy::too_many_lines)]
    fn handle_config_reload(&mut self, _scan_tx: &Sender<ScanRequest>) {
        eprintln!("[SBH-DAEMON] config reload requested (SIGHUP)");

        match Config::load(Some(&self.config.paths.config_file)) {
            Ok(new_config) => {
                let old_hash = self.config.stable_hash().unwrap_or_default();
                let new_hash = new_config.stable_hash().unwrap_or_default();

                if old_hash == new_hash {
                    eprintln!("[SBH-DAEMON] config unchanged, skipping reload");
                } else {
                    // Update components that can be reconfigured at runtime.
                    self.scoring_engine = ScoringEngine::from_config(
                        &new_config.scoring,
                        new_config.scanner.min_file_age_minutes,
                    );
                    self.release_controller
                        .set_replenish_cooldown(new_config.ballast.replenish_cooldown_minutes);
                    let discovery_paths =
                        ballast_discovery_paths(&new_config, &self.special_locations);
                    match BallastPoolCoordinator::discover_inner(
                        &new_config.ballast,
                        &discovery_paths,
                        self.platform.as_ref(),
                        &self.platform,
                        Some(new_config.paths.ballast_dir.as_path()),
                    ) {
                        Ok(coordinator) => {
                            self.ballast_coordinator = coordinator;
                            self.ballast_coordinator
                                .set_provision_floor_rule(new_config.ballast_provision_floor());
                        }
                        Err(err) => {
                            eprintln!(
                                "[SBH-DAEMON] ballast coordinator rediscovery failed during reload: {err}"
                            );
                            self.ballast_coordinator.update_config(&new_config.ballast);
                            // The kept pools still follow the new thresholds.
                            self.ballast_coordinator
                                .set_provision_floor_rule(new_config.ballast_provision_floor());
                        }
                    }

                    // Propagate pressure thresholds and EWMA params to all active monitors.
                    for monitor in self.mount_monitors.values_mut() {
                        monitor.update_config(&new_config);
                    }

                    // Propagate executor-critical settings via shared atomics.
                    self.shared_executor_config
                        .dry_run
                        .store(new_config.scanner.dry_run, Ordering::Relaxed);
                    self.shared_executor_config
                        .max_batch_size
                        .store(new_config.scanner.max_delete_batch, Ordering::Relaxed);
                    self.shared_executor_config
                        .set_min_score(new_config.scoring.min_score);
                    self.shared_executor_config.repeat_base_cooldown_secs.store(
                        new_config.scanner.repeat_deletion_base_cooldown_secs,
                        Ordering::Relaxed,
                    );
                    self.shared_executor_config.repeat_max_cooldown_secs.store(
                        new_config.scanner.repeat_deletion_max_cooldown_secs,
                        Ordering::Relaxed,
                    );
                    self.shared_executor_config
                        .quarantine_enabled
                        .store(new_config.scanner.quarantine_enabled, Ordering::Relaxed);
                    self.shared_executor_config.quarantine_ttl_secs.store(
                        new_config.scanner.quarantine_ttl_hours.saturating_mul(3600),
                        Ordering::Relaxed,
                    );
                    self.shared_executor_config.set_planner(
                        new_config.scoring.batch_risk_budget_by_level,
                        new_config.scoring.false_positive_loss,
                    );

                    // Update FS collector TTL.
                    self.fs_collector
                        .set_ttl(Duration::from_millis(new_config.telemetry.fs_cache_ttl_ms));

                    // Update VOI scheduler.
                    self.voi_scheduler
                        .update_config(new_config.scheduler.clone());
                    for root in &new_config.scanner.root_paths {
                        self.voi_scheduler.register_path(root.clone());
                    }

                    // Update shared configs for scanner thread.
                    self.regret.update_config(&new_config);
                    *self.shared_scoring_config.write() = new_config.scoring.clone();
                    *self.shared_scanner_config.write() = new_config.scanner.clone();

                    // Propagate policy config (kill_switch, budgets, loss values).
                    self.policy_engine
                        .lock()
                        .update_config(new_config.policy.clone());

                    // Rebuild the behavior matrix; re-resolve the current cell.
                    if new_config.behavior != self.config.behavior {
                        let table = behavior_table_from_config(&new_config);
                        if let Some(transition) = self.behavior_state.replace_table(table) {
                            self.shared_executor_config
                                .set_min_certainty(min_certainty_for(
                                    transition.to_mode.cleanup_action,
                                ));
                            let message = format!(
                                "behavior mode changed source=config_reload memory={:?} \
                                 disk={:?} mode=({}) -> ({})",
                                transition.to_memory,
                                transition.to_disk,
                                behavior_mode_summary(transition.from_mode),
                                behavior_mode_summary(transition.to_mode)
                            );
                            eprintln!("[SBH-DAEMON] {message}");
                            self.logger_handle.send(ActivityEvent::Info { message });
                        }
                        self.log_behavior_matrix("config_reload");
                    }

                    // Rebuild predictive policy with new thresholds.
                    self.predictive_policy =
                        PredictiveActionPolicy::from_config(new_config.pressure.prediction.clone());

                    // Propagate notification config (channels, webhook URLs, cooldowns).
                    self.notification_manager
                        .update_config(&new_config.notifications);
                    {
                        let mut budget = self.cpu_budget.lock();
                        budget.set_pct(paced_pct(
                            new_config.telemetry.cpu_budget_pct,
                            self.behavior_state.mode.scan_aggressiveness,
                        ));
                        budget.set_burst_secs(new_config.telemetry.cpu_budget_burst_secs);
                    }

                    self.logger_handle.send(ActivityEvent::ConfigReloaded {
                        details: format!("config hash: {old_hash} -> {new_hash}"),
                    });
                    self.config = new_config;
                    // Reload may change what sbh can act on: retune the
                    // per-mount controllers and wake idle mounts next tick.
                    let controller_config = mount_controller_config(&self.config);
                    for controller in self.mount_controllers.values_mut() {
                        controller.set_config(controller_config);
                    }
                    self.wake_next_tick.reload = true;
                    eprintln!("[SBH-DAEMON] config reloaded successfully");
                }
            }
            Err(e) => {
                eprintln!("[SBH-DAEMON] config reload failed: {e}");
                self.logger_handle.send(ActivityEvent::Error {
                    code: "SBH-1003".to_string(),
                    message: format!("config reload failed: {e}"),
                });
            }
        }
    }

    // ──────────────────── worker threads ────────────────────

    fn spawn_scanner_thread(
        &self,
        scan_rx: Receiver<ScanRequest>,
        del_tx: Sender<DeletionBatch>,
        logger: ActivityLoggerHandle,
        heartbeat: Arc<ThreadHeartbeat>,
        report_tx: Sender<WorkerReport>,
        index_feedback_rx: Receiver<ScannerIndexFeedback>,
    ) -> Result<thread::JoinHandle<()>> {
        let scoring_config = Arc::clone(&self.shared_scoring_config);
        let scanner_config = Arc::clone(&self.shared_scanner_config);
        let platform = Arc::clone(&self.platform);
        let shutdown = self.signal_handler.shutdown_token();
        let scanner_index_path = self.config.paths.scanner_index_file();
        let prescan_cursor_path = self.config.paths.prescan_cursor_file();
        let cpu_budget = Arc::clone(&self.cpu_budget);
        let executor_config = Arc::clone(&self.shared_executor_config);
        let regret = Arc::clone(&self.regret);
        thread::Builder::new()
            .name("sbh-scanner".to_string())
            .spawn(move || {
                scanner_thread_main(
                    &scan_rx,
                    &del_tx,
                    &logger,
                    &scoring_config,
                    &scanner_config,
                    &platform,
                    &heartbeat,
                    &report_tx,
                    &shutdown,
                    &scanner_index_path,
                    &prescan_cursor_path,
                    &index_feedback_rx,
                    &cpu_budget,
                    &executor_config,
                    &regret,
                );
            })
            .map_err(|source| SbhError::Runtime {
                details: format!("failed to spawn scanner thread: {source}"),
            })
    }

    /// Regret labels (Q4): resolve watched deletions against the filesystem
    /// and the process table, store each outcome, and feed the category
    /// calibrator the scanner reads before its next pass.
    fn resolve_regrets(&self) {
        self.resolve_regrets_with_clock(Instant::now);
    }

    /// Sample time around each observation and again when its evidence is
    /// applied. Ballast work, quarantine sweeps, and earlier observations
    /// must not backdate a later sighting or its suspension deadline.
    fn resolve_regrets_with_clock(&self, mut clock: impl FnMut() -> Instant) {
        let platform = Arc::clone(&self.platform);
        let outcomes = self
            .regret
            .detector
            .lock()
            .check_with_clock(&mut clock, |watch| {
                watch.observe(|parent| parent_in_use(platform.as_ref(), parent))
            });
        if outcomes.is_empty() {
            return;
        }
        // Record under the lock, log and ship after it: the scanner reads
        // the calibrator before every pass and must not wait on I/O.
        let effects: Vec<(f64, bool)> = {
            let mut calibrator = self.regret.calibrator.lock();
            outcomes
                .iter()
                .map(|outcome| {
                    let now = clock();
                    calibrator.record(
                        &outcome.category,
                        certainty_from_name(&outcome.certainty),
                        outcome.outcome,
                        now,
                    );
                    (
                        calibrator
                            .summary(&outcome.category)
                            .map_or(1.0, |summary| summary.calibration),
                        calibrator.suspended(&outcome.category, now),
                    )
                })
                .collect()
        };
        for (outcome, (calibration, suspended)) in outcomes.into_iter().zip(effects) {
            eprintln!(
                "[SBH-REGRET] decision={} outcome={} category={} after={}s path={} ({}); category calibration now {calibration:.3}{}",
                outcome.decision_id,
                outcome.outcome.as_str(),
                outcome.category,
                outcome.after_secs,
                outcome.path.display(),
                outcome.detail,
                if suspended {
                    ", deletions suspended"
                } else {
                    ""
                }
            );
            self.logger_handle
                .send(ActivityEvent::DecisionOutcome(Box::new(outcome)));
        }
    }

    fn quarantine_sweep_due(&self, now: Instant) -> bool {
        self.last_quarantine_sweep
            .is_none_or(|last| now.saturating_duration_since(last) >= QUARANTINE_SWEEP_INTERVAL)
    }

    /// Layer 7 sweep, subject to live policy and lossless-reclaim holds.
    /// At Orange and above, quarantine drains oldest-first before the scan
    /// dispatched on that mount. On calmer mounts, once per maintenance
    /// interval, expired entries are removed and the store is capped at
    /// `scanner.quarantine_max_bytes_pct` of the volume. Held bytes feed
    /// `state.json` even when cleanup is deferred.
    fn sweep_quarantines<'a>(
        &mut self,
        responses: impl IntoIterator<Item = &'a MountTickResponse>,
        root_mounts: &[(PathBuf, Option<PathBuf>)],
        now: Instant,
    ) {
        let sweep_due = self.quarantine_sweep_due(now);
        if self.sweep_quarantine_entries(responses, root_mounts, sweep_due) && sweep_due {
            self.last_quarantine_sweep = Some(now);
        }
    }

    fn sweep_quarantine_entries<'a>(
        &mut self,
        responses: impl IntoIterator<Item = &'a MountTickResponse>,
        root_mounts: &[(PathBuf, Option<PathBuf>)],
        sweep_due: bool,
    ) -> bool {
        let now_unix = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut attempted_sweep = false;
        for tick in responses {
            let mount = &tick.response.causing_mount;
            let level = tick.response.level;
            let pressured = matches!(
                level,
                PressureLevel::Orange | PressureLevel::Red | PressureLevel::Critical
            );
            if !pressured && !sweep_due {
                continue;
            }
            let cap_bytes = self.fs_collector.collect(mount).ok().map(|stats| {
                (stats.total_bytes / 100)
                    .saturating_mul(u64::from(self.config.scanner.quarantine_max_bytes_pct))
            });
            let mut held = 0u64;
            for (root, root_mount) in root_mounts {
                if root_mount.as_deref() != Some(mount.as_path()) {
                    continue;
                }
                let store = QuarantineStore::under(root);
                // A prior quarantine decision does not authorize irreversible
                // cleanup after the operator selects observe/dry-run or the
                // policy falls back. Inventory stays available in those modes.
                if self.config.scanner.dry_run
                    || !self.policy_engine.lock().mode().allows_deletion()
                    || self.shared_executor_config.compression_first.defers_mount(
                        mount,
                        level,
                        Instant::now(),
                    )
                {
                    if let Ok(bytes) = store.held_bytes() {
                        held = held.saturating_add(bytes);
                    }
                    continue;
                }
                let mode = if pressured {
                    QuarantineSweepMode::Pressure
                } else {
                    QuarantineSweepMode::Maintenance { cap_bytes }
                };
                attempted_sweep = true;
                match store.sweep(now_unix, mode) {
                    Ok(swept) => {
                        held = held.saturating_add(swept.held_bytes);
                        let (why, drained) = (swept.reason, swept.drained);
                        if drained.entries > 0 {
                            let count = drained.entries;
                            let bytes = drained.bytes;
                            let message = format!(
                                "quarantine under {} drained {count} entr{} ({bytes} bytes) for {why} at {level:?}",
                                root.display(),
                                if count == 1 { "y" } else { "ies" }
                            );
                            eprintln!("[SBH-QUARANTINE] {message}");
                            self.logger_handle.send(ActivityEvent::Info { message });
                        }
                        // A stuck entry is reported the first time it sticks,
                        // then goes quiet for STUCK_RETRY_SECS. Reporting it
                        // every sweep would be a line a minute, forever.
                        for failure in drained.new_failures() {
                            let message = format!(
                                "quarantine entry {} under {} will not unlink: {} ({})",
                                failure.decision_id,
                                root.display(),
                                failure.error,
                                failure.path.display()
                            );
                            eprintln!("[SBH-QUARANTINE] {message}");
                            self.logger_handle.send(ActivityEvent::Error {
                                code: failure.code.clone(),
                                message,
                            });
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "[SBH-QUARANTINE] sweep under {} failed: {e}",
                            root.display()
                        );
                    }
                }
            }
            self.quarantine_held.insert(mount.clone(), held);
        }
        attempted_sweep
    }

    fn spawn_executor_thread(
        &self,
        del_rx: Receiver<DeletionBatch>,
        logger: ActivityLoggerHandle,
        heartbeat: Arc<ThreadHeartbeat>,
        report_tx: Sender<WorkerReport>,
        index_feedback_tx: Sender<ScannerIndexFeedback>,
    ) -> Result<thread::JoinHandle<()>> {
        let shared_config = Arc::clone(&self.shared_executor_config);
        let scanner_config = Arc::clone(&self.shared_scanner_config);
        let policy_engine = Arc::clone(&self.policy_engine);
        let regret = Arc::clone(&self.regret);
        let shared_guard_diagnostics = Arc::clone(&self.shared_guard_diagnostics);
        let shutdown = self.signal_handler.shutdown_token();
        let platform_sacred_paths = self.platform.sacred_paths();

        thread::Builder::new()
            .name("sbh-executor".to_string())
            .spawn(move || {
                executor_thread_main(
                    &del_rx,
                    &logger,
                    &shared_config,
                    &scanner_config,
                    &heartbeat,
                    &report_tx,
                    &policy_engine,
                    &shared_guard_diagnostics,
                    &shutdown,
                    &index_feedback_tx,
                    &platform_sacred_paths,
                    &regret,
                );
            })
            .map_err(|source| SbhError::Runtime {
                details: format!("failed to spawn executor thread: {source}"),
            })
    }

    // ──────────────────── shutdown ────────────────────

    fn shutdown(
        &mut self,
        scan_tx: Sender<ScanRequest>,
        del_tx: Sender<DeletionBatch>,
        scanner_join: Option<thread::JoinHandle<()>>,
        executor_join: Option<thread::JoinHandle<()>>,
        exit_reason: &str,
    ) {
        let uptime_secs = self.start_time.elapsed().as_secs();

        // The control socket goes first: a client must not reach a daemon
        // that is draining, and the socket file must be gone when we exit.
        // The burst windows are a week of evidence; keep them across restarts.
        self.burst_stats.persist();
        if let Some(server) = self.control_server.take() {
            server.stop();
        }

        // 0. Tell the service manager an orderly stop has begun so it does not
        // count the exit against Restart=on-failure while workers drain.
        if let Err(error) = self.platform.service_manager().notify_stopping() {
            eprintln!("[SBH-DAEMON] sd_notify STOPPING=1 failed: {error}");
        }

        // 1. Broadcast cancellation, then drop channel senders to signal worker threads to exit.
        self.signal_handler.request_shutdown();
        self.compress_tier.stop_running_pass();
        drop(scan_tx);
        drop(del_tx);

        // 2. Join the workers within one shared budget (under the unit's
        // TimeoutStopSec). A long critical-pressure scan must not trap
        // SIGTERM behind an unbounded join: whatever has not stopped by the
        // deadline is abandoned and the process exits after the final state
        // write and logger flush.
        let join_deadline = Instant::now() + WORKER_SHUTDOWN_JOIN_BUDGET;
        if let Some(h) = scanner_join {
            join_worker_with_timeout(
                "scanner",
                h,
                join_deadline.saturating_duration_since(Instant::now()),
            );
        }
        if let Some(h) = executor_join {
            join_worker_with_timeout(
                "executor",
                h,
                join_deadline.saturating_duration_since(Instant::now()),
            );
        }

        // 3. Log shutdown and stamp the state file so readers can tell a
        //    stopped daemon from a stalled one.
        self.self_monitor.write_final_state(exit_reason);
        self.logger_handle.send(ActivityEvent::DaemonStopped {
            reason: exit_reason.to_string(),
            uptime_secs,
        });
        self.notification_manager
            .notify(&NotificationEvent::DaemonStopped {
                reason: exit_reason.to_string(),
                uptime_secs,
            });

        // 4. Shutdown logger thread.
        self.logger_handle.shutdown();
        if let Some(logger_join) = self.logger_join.take() {
            let _ = logger_join.join();
        }

        if let Some(pidfile) = self.pidfile.take() {
            // Best effort; the lock, not the pidfile, is the liveness signal.
            let _ = std::fs::remove_file(pidfile);
        }

        eprintln!("[SBH-DAEMON] shutdown complete (uptime={uptime_secs}s)");
    }
}

fn join_worker_with_timeout(name: &str, handle: thread::JoinHandle<()>, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            eprintln!(
                "[SBH-DAEMON] {name} worker did not stop within {:.1}s; continuing shutdown",
                timeout.as_secs_f64(),
            );
            return false;
        }
        thread::sleep(Duration::from_millis(50));
    }

    let stopped = matches!(handle.join(), Ok(()));
    if !stopped {
        eprintln!("[SBH-DAEMON] {name} worker panicked during shutdown");
    }
    stopped
}

// ──────────────────── scanner thread ────────────────────

/// What one scan pass has handed to the executor.
#[derive(Debug, Default)]
struct PassDispatch {
    /// Candidates dispatched this pass (the inter-pass cooldown's signal).
    count: usize,
    /// Their paths. The pre-scan and the walk can nominate the same tree in
    /// one pass; a second batch for it arrives right after the first one
    /// deleted it, and a tree recreated in between can reuse the freed inode
    /// and pass the identity check (e2e 2026-09-25: a rebuilt target under a
    /// live process was deleted twice). Within a pass, no candidate at, under
    /// or above an already dispatched path is dispatched again.
    paths: HashSet<PathBuf>,
}

fn dispatch_top_candidates(
    scored: &mut Vec<CandidacyScore>,
    request: &ScanRequest,
    del_tx: &Sender<DeletionBatch>,
    dispatched: &mut PassDispatch,
) -> bool {
    // Neither a path under a dispatched tree nor one containing it: deleting
    // an ancestor would take a subtree rebuilt since its own deletion. The
    // ancestor waits for the next pass.
    // A candidate that frees nothing is never chosen by the planner (once an
    // empty mktemp target of a live build was: ts2 2026-10-15), so it is not
    // dispatched either. Each still cost a policy evaluation, a plan and a
    // decision_log row on every pass: on ts2 at Critical (2026-10-17) that was
    // 3,479 empty bun-workspace node_modules and target dirs in 20 minutes,
    // ~250,000 rows (~0.6 GB) a day kept for 30 days.
    scored.retain(|candidate| {
        candidate.size_bytes > 0
            && !dispatched
                .paths
                .iter()
                .any(|sent| candidate.path.starts_with(sent) || sent.starts_with(&candidate.path))
    });
    if scored.is_empty() {
        return true;
    }
    if request.max_delete_batch == 0 {
        scored.clear();
        return true;
    }

    scored.sort_by(|a, b| {
        b.total_score
            .partial_cmp(&a.total_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let max_batch = request.max_delete_batch.max(1);
    let overflow = if scored.len() > max_batch {
        scored.split_off(max_batch)
    } else {
        Vec::new()
    };

    let batch = DeletionBatch {
        candidates: std::mem::replace(scored, overflow),
        pressure_level: request.pressure_level,
        urgency: request.urgency,
        target_bytes: request.target_bytes,
        target_only_root: None,
    };
    let batch_len = batch.candidates.len();
    let batch_paths: Vec<PathBuf> = batch.candidates.iter().map(|c| c.path.clone()).collect();

    // Non-blocking send preserves scanner progress and avoids deadlock when
    // executor is slow. If channel is full, re-queue candidates locally so the
    // scanner can retry later in this pass.
    match del_tx.try_send(batch) {
        Ok(()) => {
            // These candidates were handed to the deletion executor — i.e. real
            // reclaim work was started this pass. Counted so the inter-pass
            // cooldown (B6) distinguishes a *productive* pass from one that
            // surfaced candidates but dispatched none (all protected/dampened).
            dispatched.count += batch_len;
            dispatched.paths.extend(batch_paths);
            true
        }
        Err(TrySendError::Full(mut deferred)) => {
            eprintln!(
                "[SBH-SCANNER] executor channel full, deferring {} candidates",
                deferred.candidates.len()
            );
            scored.append(&mut deferred.candidates);
            true
        }
        Err(TrySendError::Disconnected(_)) => false, // Channel closed, exit
    }
}

fn drain_scanner_index_feedback(
    index: &mut ScannerCandidateIndex,
    feedback_rx: &Receiver<ScannerIndexFeedback>,
    scanner_config: &ScannerConfig,
    logger: &ActivityLoggerHandle,
) -> usize {
    let mut applied = 0usize;
    let base = Duration::from_secs(scanner_config.repeat_deletion_base_cooldown_secs);
    let max = Duration::from_secs(scanner_config.repeat_deletion_max_cooldown_secs);
    while let Ok(feedback) = feedback_rx.try_recv() {
        index.record_failure(feedback.identity, SystemTime::now(), base, max);
        applied += 1;
        logger.send(ActivityEvent::Info {
            message: format!(
                "scanner_index: failure backoff recorded for {}",
                feedback.path.display()
            ),
        });
    }
    applied
}

fn persist_scanner_index_records(
    index: &mut ScannerCandidateIndex,
    records: &mut Vec<CandidateIndexRecord>,
    scanner_index_path: &Path,
    logger: &ActivityLoggerHandle,
) {
    if records.is_empty() {
        return;
    }
    for record in records.drain(..) {
        index.upsert(record);
    }
    index.evict_stale(SystemTime::now());
    if let Err(err) = index.save_checkpoint(scanner_index_path) {
        logger.send(ActivityEvent::Error {
            code: err.code().to_string(),
            message: format!(
                "scanner_index: failed to save {}: {err}",
                scanner_index_path.display()
            ),
        });
    }
}

fn daemon_protection_reason(
    protection: &mut ProtectionRegistry,
    path: &Path,
    sacred_paths: &[crate::platform::types::SacredPath],
) -> Result<Option<String>> {
    protection.discover_ancestor_markers(path)?;
    if let Some(reason) = protection.protection_reason(path) {
        return Ok(Some(reason));
    }

    // B7: a protected verdict proved on a recent pass is reused instead of
    // re-walking the subtree. This is the hot loop fix (#N): the containment
    // scan below is a bounded but *recursive* sub-walk, and re-proving the same
    // few hundred protected `/data/tmp` candidates on every pass pegged a core
    // indefinitely on hosts whose candidates are nearly all protected. Only
    // protected verdicts are cached; "clean" is always re-proved, so a subtree
    // that gains a sacred marker can never be deleted on a stale verdict.
    if let Some(reason) = protection.cached_protected_verdict(path) {
        return Ok(Some(reason));
    }

    let overlaps = protection::find_sacred_overlaps(path, sacred_paths)?;
    let Some(first) = overlaps.first() else {
        return Ok(None);
    };
    let reason = format!("sacred path overlap: {}", first.summary());
    // A real find is a witness: the verdict then survives the churn of a busy
    // protected tree (an agent's temp dir with a live `.db` or `.beads/`)
    // instead of being re-walked on every pass. A truncated sub-walk proved
    // nothing and keeps the mtime/TTL rule.
    match overlaps
        .iter()
        .find(|overlap| overlap.pattern != protection::TRUNCATED_OVERLAP_PATTERN)
    {
        Some(found) => {
            protection.cache_witnessed_verdict(path, reason.clone(), found.matched_path.clone());
        }
        None => protection.cache_protected_verdict(path, reason.clone()),
    }
    Ok(Some(reason))
}

/// Why a replayed index record was not dispatched.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReplayDrop {
    /// The path is gone or unreadable.
    Missing,
    /// Same path, different device/inode: a recreated artifact is a new
    /// decision, not the persisted one.
    IdentityChanged,
    /// The index's event generation advanced since the record was written;
    /// the walker re-discovers it instead of trusting the stale record.
    GenerationAdvanced,
    /// Fresh evidence vetoed it (protection, `.git`, lease, open file,
    /// classification, scoring vetoes).
    Vetoed(String),
    /// Re-scored below a Delete verdict.
    NotDelete(String),
}

impl ReplayDrop {
    fn label(&self) -> String {
        match self {
            Self::Missing => "missing".to_string(),
            Self::IdentityChanged => "identity_changed".to_string(),
            Self::GenerationAdvanced => "generation_advanced".to_string(),
            Self::Vetoed(reason) => format!("vetoed:{reason}"),
            Self::NotDelete(action) => format!("not_delete:{action}"),
        }
    }
}

/// bd-1ouz: a daemon that cannot see every process (a user-scoped macOS
/// daemon) cannot know what other users' processes hold, so every candidate's
/// references are unknown, not absent, and scoring vetoes it: in v2, whose
/// opaque candidates may skip the reference probe, as in v1.
fn mark_visibility_gap(input: &mut crate::scanner::scoring::CandidateInput, gap: Option<&str>) {
    if let Some(reason) = gap {
        input.active_references.mark_incomplete(reason);
    }
}

/// Re-examine one persisted index record with fresh evidence and return the
/// candidate to dispatch, or why it must not be.
///
/// Order: generation, identity, protection/sacred, `.git`, active lease,
/// structural markers, classification, then the normal scoring engine with
/// the walker's age rule (newest of mtime, birth time and tree idleness),
/// open-file detection and the sacred-overlap pass. Only a fresh, unvetoed
/// `Delete` verdict is returned.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn replay_indexed_record(
    record: &CandidateIndexRecord,
    index_generation: u64,
    registry: &ArtifactPatternRegistry,
    engine: &ScoringEngine,
    scanner_config: &crate::core::config::ScannerConfig,
    request: &ScanRequest,
    protection: &mut ProtectionRegistry,
    sacred_paths: &[crate::platform::types::SacredPath],
    open_files: &HashSet<PathBuf>,
    visibility_gap: Option<&str>,
    logger: &ActivityLoggerHandle,
) -> std::result::Result<CandidacyScore, ReplayDrop> {
    use crate::scanner::active_lease::{ActiveLeaseState, inspect_path};
    use crate::scanner::index::{IndexedIdentity, IndexedPruneDecision};
    use crate::scanner::patterns::{ArtifactCategory, OpaqueTreeDisposition, classify_opaque_tree};
    use crate::scanner::scoring::{CandidateInput, DecisionAction};
    use crate::scanner::walker::{
        TREE_IDLE_PROBE_MAX_DEPTH, TREE_IDLE_PROBE_MAX_ENTRIES, identity_for_path,
        is_path_open_by_ancestor, opaque_context_for_path, structural_signals_for_path,
        tree_newest_mtime,
    };

    let path = &record.path;
    if record.event_generation != index_generation {
        return Err(ReplayDrop::GenerationAdvanced);
    }
    let Ok(identity) = identity_for_path(path, scanner_config.follow_symlinks) else {
        return Err(ReplayDrop::Missing);
    };
    if IndexedIdentity::from(identity) != record.identity {
        return Err(ReplayDrop::IdentityChanged);
    }
    if should_skip_protected_daemon_candidate(
        protection,
        path,
        sacred_paths,
        logger,
        "index replay",
    ) {
        return Err(ReplayDrop::Vetoed("protected".to_string()));
    }
    if path.join(".git").exists() {
        return Err(ReplayDrop::Vetoed("contains .git".to_string()));
    }
    if let Some(lease) = inspect_path(path)
        && lease.state == ActiveLeaseState::Active
    {
        return Err(ReplayDrop::Vetoed(format!(
            "active lease on {}",
            lease.leased_target.display()
        )));
    }
    let mut signals = structural_signals_for_path(path);
    if signals.has_git || signals.has_cargo_toml {
        return Err(ReplayDrop::Vetoed("source tree markers".to_string()));
    }
    // bd-8aeq: a record the walker pruned as an opaque candidate is
    // re-classified the way the walker classified it (name plus parent
    // context) and scored with the structural evidence of its subtree, not
    // with the root directory's own entries. Without this a definite cargo
    // `target/` (markers under `debug/`) replayed as `unclear` and could never
    // pass an Orange cell's certainty gate, however many times it was replayed.
    let opaque = (record.prune_decision == IndexedPruneDecision::CandidateOpaque)
        .then(|| classify_opaque_tree(path, opaque_context_for_path(path)))
        .flatten()
        .filter(|opaque| opaque.disposition == OpaqueTreeDisposition::CandidateOpaque);
    let classification = match opaque {
        Some(opaque) => {
            // The evidence the walk's subtree probe found, persisted in the
            // record; the size estimate below comes from the same probe.
            signals = record.structural_signals;
            opaque.classification
        }
        // As the walk would classify it now (bd-10yj): a tree it only
        // descends into or protects is not replayed on its name.
        None => crate::scanner::walker::classify_dir_as_walked(registry, path, signals)
            .ok_or_else(|| {
                ReplayDrop::Vetoed("the walk declines it (opaque verdict)".to_string())
            })?,
    };
    if classification.category == ArtifactCategory::Unknown {
        return Err(ReplayDrop::Vetoed(
            "no longer classifies as an artifact".to_string(),
        ));
    }
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Err(ReplayDrop::Missing);
    };
    // The walker's age rule: newest of mtime, birth time and (for
    // regenerable trees) the newest mtime inside the tree.
    let mut newest = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    if let Ok(created) = meta.created() {
        newest = newest.max(created);
    }
    if meta.is_dir() && classification.category.is_regenerable_tree() {
        let probe = tree_newest_mtime(path, TREE_IDLE_PROBE_MAX_ENTRIES, TREE_IDLE_PROBE_MAX_DEPTH);
        if let Some(tree_newest) = probe.newest_mtime {
            newest = newest.max(tree_newest);
        }
    }
    let age = SystemTime::now()
        .duration_since(newest)
        .unwrap_or(Duration::ZERO);
    #[cfg(unix)]
    let allocated = {
        use std::os::unix::fs::MetadataExt;
        meta.blocks().saturating_mul(512)
    };
    #[cfg(not(unix))]
    let allocated = meta.len();
    // Records written before 0.6.18 could carry the pre-scan's nomination
    // floor instead of a measured size; exactly the floor means "never
    // measured", so measure it now rather than dispatch and report 100 MiB.
    let size_estimate = if meta.is_dir()
        && record.size_estimate_bytes == crate::scanner::walker::OPAQUE_CANDIDATE_SIZE_FLOOR
    {
        prescan_dir_size(path, scanner_config.cross_devices, &AtomicBool::new(false))
    } else {
        record.size_estimate_bytes
    };
    let mut input = CandidateInput {
        path: path.clone(),
        size_bytes: size_estimate.max(allocated),
        age: adjusted_candidate_age(
            age,
            scanner_config.min_file_age_minutes,
            request.pressure_level,
            path,
            &classification,
        ),
        classification,
        signals,
        active_references: ActiveReferenceSummary::default(),
        is_open: is_path_open_by_ancestor(path, open_files),
        excluded: false,
    };
    mark_visibility_gap(&mut input, visibility_gap);
    let mut score = engine.score_candidate(&input, request.urgency);
    if !score.vetoed && score.decision.action == DecisionAction::Delete {
        let overlaps = protection::find_sacred_overlaps(path, sacred_paths)
            .map_err(|e| ReplayDrop::Vetoed(format!("sacred overlap check failed: {e}")))?;
        score = engine.score_candidate_with_sacred_overlaps(&input, request.urgency, &overlaps);
    }
    if score.vetoed {
        return Err(ReplayDrop::Vetoed(
            score
                .veto_reason
                .as_deref()
                .unwrap_or("scoring veto")
                .to_string(),
        ));
    }
    if score.decision.action != DecisionAction::Delete {
        return Err(ReplayDrop::NotDelete(
            format!("{:?}", score.decision.action).to_lowercase(),
        ));
    }
    score.identity = Some(identity);
    Ok(score)
}

fn should_skip_protected_daemon_candidate(
    protection: &mut ProtectionRegistry,
    path: &Path,
    sacred_paths: &[crate::platform::types::SacredPath],
    logger: &ActivityLoggerHandle,
    context: &str,
) -> bool {
    // Proved protected (and logged) on an earlier pass and still fresh:
    // skip quietly. Only protected verdicts are cached, so this is fail-safe.
    if protection.cached_protected_verdict(path).is_some() {
        return true;
    }
    match daemon_protection_reason(protection, path, sacred_paths) {
        Ok(Some(reason)) => {
            eprintln!(
                "[SBH-SAFETY] {context}: protected candidate skipped: {} ({reason})",
                path.display()
            );
            true
        }
        Ok(None) => false,
        Err(err) => {
            // A path whose protection cannot be proved is treated as
            // protected until the verdict TTL lapses or the directory
            // changes. Skipping is always safe; re-probing it every pass was
            // not free (fleet 2026-09-25: a dead FUSE mount inside an rch
            // temp dir failed with ENOTCONN and was logged on every pass).
            protection.cache_protected_verdict(path, format!("protection check failed: {err}"));
            eprintln!(
                "[SBH-SAFETY] {context}: protection check failed for {}; skipping candidate: {err}",
                path.display()
            );
            logger.send(ActivityEvent::Error {
                code: err.code().to_string(),
                message: format!(
                    "{context}: protection check failed for {}; skipped candidate: {err}",
                    path.display()
                ),
            });
            true
        }
    }
}

fn collect_active_references_for_scan(
    platform: &dyn Platform,
    paths: &[PathBuf],
    scan_config: ActiveReferenceScanConfig,
    logger: &ActivityLoggerHandle,
) -> ActiveReferenceIndex {
    let index = collect_active_reference_index_cached(platform, paths, scan_config.cache_ttl);
    if let Some(reason) = index.incomplete_reason() {
        let message = format!("active-reference visibility incomplete: {reason}");
        eprintln!("[SBH-SCANNER] info: {message}");
        logger.send(ActivityEvent::Info { message });
    }
    index
}

const ACTIVE_REFERENCE_SCAN_BUDGET_MACOS: Duration = Duration::from_secs(13);
const ACTIVE_REFERENCE_SCAN_BUDGET_DEFAULT: Duration = Duration::from_secs(5);
const ACTIVE_REFERENCE_BUDGET_SKIP_REASON: &str =
    "active-reference scan skipped because scan budget remaining was insufficient";

fn active_reference_scan_budget(platform_name: &str) -> Duration {
    if platform_name == "macos" {
        ACTIVE_REFERENCE_SCAN_BUDGET_MACOS
    } else {
        ACTIVE_REFERENCE_SCAN_BUDGET_DEFAULT
    }
}

fn has_active_reference_scan_budget(scan_deadline: Instant, reserve: Duration) -> bool {
    Instant::now()
        .checked_add(reserve)
        .is_some_and(|reserved_deadline| reserved_deadline <= scan_deadline)
}

fn mark_active_reference_budget_incomplete(input: &mut crate::scanner::scoring::CandidateInput) {
    input
        .active_references
        .mark_incomplete(ACTIVE_REFERENCE_BUDGET_SKIP_REASON);
}

/// Incremental scan cursor — persists across scan iterations within the scanner
/// thread to avoid re-walking large directory subtrees that contained zero
/// cleanup candidates on the previous pass.
///
/// After a scan that timed out, directories that were visited but yielded no
/// classified artifacts are cached as "barren". On the next scan, these are
/// injected into the walker's excluded_paths so it skips them, effectively
/// resuming from where the previous scan left off.
///
/// Entries expire after `ttl` to allow re-discovery when new artifacts appear.
struct ScanCursor {
    /// Directories confirmed barren (no classified children) on a recent pass.
    barren_dirs: HashMap<PathBuf, Instant>,
    /// How long to trust a barren classification before re-scanning.
    ttl: Duration,
    /// Maximum entries to cache (prevents unbounded growth on huge trees).
    max_entries: usize,
}

impl ScanCursor {
    fn new() -> Self {
        Self {
            barren_dirs: HashMap::new(),
            ttl: Duration::from_mins(30), // 30 minutes
            max_entries: 50_000,
        }
    }

    /// Return non-expired barren directories to exclude from the next walk.
    fn barren_exclusions(&self) -> HashSet<PathBuf> {
        let now = Instant::now();
        self.barren_dirs
            .iter()
            .filter(|&(_, &ts)| now.duration_since(ts) < self.ttl)
            .map(|(p, _)| p.clone())
            .collect()
    }

    /// Update the cache after a scan pass.
    ///
    /// `visited_dirs` — all directories the walker emitted entries for.
    /// `non_barren_dirs` — directories at or above a classified entry, or at
    /// or above ground the pass left unseen (see [`mark_non_barren`]).
    /// `timed_out` — whether the scan hit its time/entry budget.
    ///
    /// Only caches barren dirs when the scan timed out (no point caching if the
    /// scan completed — next scan should be fresh). On a full completion, the
    /// cache is cleared to allow re-discovery.
    fn update(
        &mut self,
        visited_dirs: &HashSet<PathBuf>,
        non_barren_dirs: &HashSet<PathBuf>,
        timed_out: bool,
    ) {
        if !timed_out {
            // Full scan completed — clear cache so next scan is fresh.
            self.barren_dirs.clear();
            return;
        }

        let now = Instant::now();

        // Remove dirs that turned out to have candidates (they may have been
        // cached as barren from a prior pass but gained artifacts since).
        for dir in non_barren_dirs {
            self.barren_dirs.remove(dir);
        }

        // Expire old entries.
        self.barren_dirs
            .retain(|_, ts| now.duration_since(*ts) < self.ttl);

        // Newly discovered barren dirs. They are newer than every cached one,
        // so the cap keeps them first; take no more than fit. Copying every
        // barren dir and truncating afterwards cloned ~450k paths per pass on
        // a host whose passes stop at the entry budget, the daemon's largest
        // allocation burst (ts2, 2026-10-18). A dir already cached keeps its
        // older timestamp.
        let fresh: Vec<&PathBuf> = visited_dirs
            .iter()
            .filter(|dir| !non_barren_dirs.contains(*dir) && !self.barren_dirs.contains_key(*dir))
            .take(self.max_entries)
            .collect();

        // Cap size: the newest older entries fill whatever room is left.
        let room = self.max_entries - fresh.len();
        if self.barren_dirs.len() > room {
            let mut older: Vec<_> = self.barren_dirs.drain().collect();
            older.sort_by_key(|(_, ts)| std::cmp::Reverse(*ts));
            older.truncate(room);
            self.barren_dirs = older.into_iter().collect();
        }
        for dir in fresh {
            self.barren_dirs.insert(dir.clone(), now);
        }
    }
}

/// Record that `path` and every directory above it must not be cached as
/// barren: `path` is a classified entry, or ground a budget-stopped pass left
/// unseen ([`WalkStream::unfinished_after_cancel`]). Marking only a
/// candidate's direct parent let a pass cache `/r/a` as barren for a
/// candidate at `/r/a/b/target`, and the candidate directory itself; and a
/// listed directory whose children were still queued at the stop was cached
/// with them unseen. The next pass skipped all of them for 30 minutes
/// (bd-y70k). Stops at the first ancestor already marked: its own ancestors
/// were marked with it.
fn mark_non_barren(non_barren_dirs: &mut HashSet<PathBuf>, path: &Path) {
    for dir in path.ancestors() {
        if dir.as_os_str().is_empty() || !non_barren_dirs.insert(dir.to_path_buf()) {
            break;
        }
    }
}

/// How long a budget-stopped pass waits for its walker threads to stop
/// before it gives up on knowing what they left unseen.
const WALK_STOP_WAIT: Duration = Duration::from_secs(5);

/// How often an unchanged "maintenance keep" verdict for one path is repeated.
const MAINTENANCE_KEEP_REPEAT: Duration = Duration::from_hours(1);
/// Paths whose last keep line is remembered; past this, older ones are dropped.
const MAINTENANCE_KEEP_TRACKED: usize = 65_536;

/// Rate limit for the maintenance pass's "why was this kept" lines. The same
/// entries recur on every pass: on ts1 (2026-10-15) that was 100,000 identical
/// lines a day, 95% of sbh's journal, on a host at 95% disk. A path is logged
/// when first seen, when its verdict changes, and otherwise hourly.
#[derive(Default)]
struct MaintenanceKeepLog {
    logged: HashMap<PathBuf, (String, Instant)>,
}

impl MaintenanceKeepLog {
    fn should_log(&mut self, path: &Path, verdict: String, now: Instant) -> bool {
        if let Some((last, at)) = self.logged.get(path)
            && *last == verdict
            && now.saturating_duration_since(*at) < MAINTENANCE_KEEP_REPEAT
        {
            return false;
        }
        if self.logged.len() >= MAINTENANCE_KEEP_TRACKED {
            self.logged
                .retain(|_, (_, at)| now.saturating_duration_since(*at) < MAINTENANCE_KEEP_REPEAT);
            if self.logged.len() >= MAINTENANCE_KEEP_TRACKED {
                self.logged.clear();
            }
        }
        self.logged.insert(path.to_path_buf(), (verdict, now));
        true
    }
}

/// Scanner thread: receives scan requests, walks directories, scores candidates,
/// and sends deletion batches to the executor.
///
/// Uses `DirectoryWalker` to perform parallel, depth-limited, safe traversals
/// and `ScoringEngine` to rank candidates.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn scanner_thread_main(
    scan_rx: &Receiver<ScanRequest>,
    del_tx: &Sender<DeletionBatch>,
    logger: &ActivityLoggerHandle,
    shared_scoring_config: &Arc<RwLock<crate::core::config::ScoringConfig>>,
    shared_scanner_config: &Arc<RwLock<crate::core::config::ScannerConfig>>,
    platform: &Arc<dyn Platform>,
    heartbeat: &Arc<ThreadHeartbeat>,
    report_tx: &Sender<WorkerReport>,
    shutdown: &Arc<AtomicBool>,
    scanner_index_path: &Path,
    prescan_cursor_path: &Path,
    index_feedback_rx: &Receiver<ScannerIndexFeedback>,
    cpu_budget: &Arc<Mutex<CpuBudget>>,
    executor_config: &Arc<SharedExecutorConfig>,
    regret: &Arc<SharedRegret>,
) {
    const DIR_SIZE_FLOOR: u64 = 100 * 1_048_576; // 100 MiB

    // Initialize pattern registry (default built-ins).
    let pattern_registry = ArtifactPatternRegistry::default();
    let visibility_gap =
        crate::scanner::walker::active_reference_visibility_warning(platform.as_ref());

    // Incremental scan cursor — persists across scan iterations to skip
    // barren directory subtrees that yielded no candidates on a prior pass.
    let mut scan_cursor = ScanCursor::new();
    // Resume point for the priority pre-scan. Loaded from disk so a restart
    // does not send the sweep back to the first root: a `/data/projects` too
    // large to enumerate in one pass is covered across passes.
    let mut prescan_cursor = PrescanCursor::load(prescan_cursor_path);
    // A budget-truncated pass is normal on a large tree, so the operator-facing
    // `SBH-2007` warning is rate-limited: the activity log has no retention
    // policy (its `activity.sqlite3` grows unbounded), and one warning per
    // pass on a host that passes every ~20 s would be sbh feeding the disk
    // pressure it exists to relieve. The stderr line is unthrottled — journald
    // rotates.
    let mut last_budget_warning: Option<Instant> = None;
    let mut scanner_index: Option<ScannerCandidateIndex> = None;
    let mut scanner_event_source: Option<ScannerEventSource> = None;
    // bd-rc-master-ajg1.8.8: while idle the scanner drains the event source
    // itself, so a change at Green becomes a pass scoped to its project
    // instead of waiting for the next maintenance walk. The invalidation is
    // kept until the pass that consumes it runs; the template is the last
    // request the main loop sent, which carries the roots and the level.
    let mut pending_event_invalidation: Option<EventInvalidation> = None;
    let mut last_event_poll = Instant::now();
    let mut event_request_template: Option<EventPassTemplate> = None;

    // Cache of directories known to contain .git — these are valid project
    // roots that should never be deleted. Persists across scan passes to
    // avoid re-discovering and re-rejecting the same paths every 10 minutes
    // (previously caused thousands of ContainsGit log entries per hour).
    let mut known_git_dirs: HashSet<PathBuf> = HashSet::new();
    let mut maintenance_keeps = MaintenanceKeepLog::default();
    let mut last_scanner_engine_mode: Option<ScannerEngineMode> = None;

    // B6: inter-pass cooldown. When a pass dispatches nothing reclaimable,
    // re-scanning immediately under sustained pressure just pins a core. We
    // record when the last empty pass finished and skip subsequent pressure-
    // driven passes until the (exponentially backed-off) rescan interval has
    // elapsed. `consecutive_empty_passes` grows the interval while the disk
    // stays pressured with nothing to reclaim, and resets on a productive pass.
    let mut last_empty_pass_at: Option<Instant> = None;
    let mut consecutive_empty_passes: u32 = 0;
    // Timed-out empty passes since the last conclusive one (`record_empty_pass`).
    let mut inconclusive_empty_passes: u32 = 0;
    // bd-8aeq: the executor's reclaim counter as it stood when the last
    // dispatching pass started. Confirmed at the next pass start: if the
    // counter has not moved, those dispatches reclaimed nothing (dry-run,
    // observe mode, every candidate dampened or failed) and the pass is paced
    // like an empty one instead of rescanning every tick.
    let mut unconfirmed_dispatch: Option<u64> = None;
    // Whether the last confirmed dispatch reclaimed nothing (#36). Kept across
    // requests: the request that notices arms the cooldown and is itself
    // skipped, so the verdict must reach the pass that eventually runs.
    let mut last_dispatch_reclaimed_nothing = false;
    // The level of the last completed pass: a rise since then is new
    // information and clears the pacing (`pressure_escalated`).
    let mut last_pass_level: Option<PressureLevel> = None;
    // The highest level a recent pass found nothing at (`note_empty_pass_level`).
    let mut empty_level_peak: Option<(PressureLevel, Instant)> = None;

    // #15: duty-cycle limiter. The empty-pass cooldown above only paces passes
    // that reclaimed nothing; a chronically-full host reclaims a trickle every
    // pass, resetting that counter forever and re-walking back-to-back at ~100%
    // CPU. Tracking how long the last pass took lets us owe proportional idle
    // afterwards, capping scanner CPU regardless of pressure level.
    let mut last_pass_finished_at: Option<Instant> = None;
    let mut last_pass_duration = Duration::ZERO;
    // Protected verdicts outlive the per-pass registries (see
    // `ProtectionRegistry::adopt_verdict_cache`).
    let mut carried_verdicts = protection::SacredVerdictCache::default();

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let request_from_events;
        let request = match scan_rx.recv_timeout(WORKER_SHUTDOWN_POLL_INTERVAL) {
            Ok(request) => {
                request_from_events = false;
                if request.catalog_roots.is_empty() {
                    event_request_template = Some(EventPassTemplate::from_request(&request));
                }
                request
            }
            Err(RecvTimeoutError::Timeout) => {
                // Idle is alive: "stalled" must mean stuck inside a pass,
                // not waiting for one.
                heartbeat.beat();
                let Some(request) = event_triggered_request(
                    scanner_event_source.as_mut(),
                    &mut pending_event_invalidation,
                    &mut last_event_poll,
                    event_request_template.as_ref(),
                ) else {
                    continue;
                };
                request_from_events = true;
                request
            }
            Err(RecvTimeoutError::Disconnected) => break,
        };
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Read latest config at the start of each scan.
        let current_scoring_config = shared_scoring_config.read().clone();
        let current_scanner_config = shared_scanner_config.read().clone();

        let mut dispatch_confirmed_empty = false;
        if let Some(reclaim_before) = unconfirmed_dispatch.take() {
            dispatch_confirmed_empty = executor_config.reclaim_events() == reclaim_before;
            last_dispatch_reclaimed_nothing = dispatch_confirmed_empty;
            if !dispatch_confirmed_empty {
                // A confirmed reclaim ends the streak that earlier fruitless
                // dispatches built; the empty passes that follow it start
                // from the base interval again.
                record_dispatching_pass(
                    false,
                    &mut consecutive_empty_passes,
                    &mut inconclusive_empty_passes,
                    &mut last_empty_pass_at,
                );
            }
        }
        if dispatch_confirmed_empty {
            record_empty_pass(
                &mut consecutive_empty_passes,
                &mut inconclusive_empty_passes,
                false,
            );
            last_empty_pass_at = Some(Instant::now());
            if let Some(level) = last_pass_level {
                note_empty_pass_level(&mut empty_level_peak, level, Instant::now());
            }
            eprintln!(
                "[SBH-SCANNER] the last pass dispatched candidates but nothing was reclaimed (dry-run, observe, dampened or failed); pacing it as an empty pass (consecutive={consecutive_empty_passes})"
            );
        }

        // A rise in pressure since the last pass is new information: the
        // pacing built up by routine empty passes on a calm mount (routine
        // maintenance on a healthy host saturates the backoff within hours)
        // must not hold the first Orange scan for the backed-off interval.
        if pressure_escalated(last_pass_level, &request)
            && last_empty_pass_at.is_some()
            && !rise_already_scanned_empty(empty_level_peak, request.pressure_level, Instant::now())
        {
            eprintln!(
                "[SBH-SCANNER] pressure rose to {:?} since the last pass; empty-pass backoff reset (was consecutive={consecutive_empty_passes})",
                request.pressure_level
            );
            last_empty_pass_at = None;
            consecutive_empty_passes = 0;
            inconclusive_empty_passes = 0;
        }
        let request_level = request.pressure_level;
        let request_background = request.maintenance || request_from_events;

        // B6: skip this pressure-driven pass if recent passes dispatched
        // nothing reclaimable and the (backed-off) cooldown has not elapsed.
        // Operator/forced scans, config reloads, and Red/Critical pressure
        // always run.
        // An event-triggered pass carries new information (something under a
        // project changed), so it waits out the base interval only, not the
        // exponential backoff that blind rescans earn.
        if request_from_events {
            let base = Duration::from_secs(current_scanner_config.min_rescan_interval_secs.max(1));
            if last_empty_pass_at.is_some_and(|last| last.elapsed() < base) {
                continue;
            }
        } else if empty_pass_cooldown_active(
            last_empty_pass_at,
            Instant::now(),
            effective_empty_pass_cooldown(
                current_scanner_config.min_rescan_interval_secs,
                consecutive_empty_passes,
            ),
            &request,
            consecutive_empty_passes,
        ) {
            continue;
        }

        // #15: defer while the scanner still owes idle time from the previous
        // pass. Applies under Red/Critical too — that is the case that pins a
        // core — but the debt is proportional, so cheap passes stay responsive.
        if duty_cycle_defer_active(
            last_pass_finished_at,
            last_pass_duration,
            Instant::now(),
            &request,
            current_scanner_config.max_scan_duty_cycle_pct,
        ) {
            continue;
        }

        // Q7: the daemon-wide CPU budget. A discretionary pass waits until
        // the bucket holds a CPU-second (the next tick re-requests it) and
        // then walks only as long as the bucket lasts; operator and
        // config-reload scans run regardless, and Critical is never limited.
        let budget_allowance = if request.force_full_scan || request.config_update.is_some() {
            None
        } else {
            cpu_budget.lock().pass_cpu_allowance(request.pressure_level)
        };
        if budget_allowance.is_some_and(|cpu_secs| cpu_secs <= 0.0) {
            heartbeat.beat();
            continue;
        }
        let pass_started_at = Instant::now();
        let selected_scanner_engine =
            SelectedScannerEngine::for_mode(current_scanner_config.engine);
        let scanner_engine_mode = selected_scanner_engine.mode();
        let scanner_dispatch = selected_scanner_engine.dispatch();
        let scanner_shadow_mode = selected_scanner_engine.shadow_mode();
        let scanner_opaque_pruning = selected_scanner_engine.opaque_pruning();
        let scanner_index_enabled = scanner_engine_mode == ScannerEngineMode::V2;
        let mut scanner_event_dirty_roots = BTreeSet::new();
        let mut scanner_event_stats = EventSourceStats::default();
        let scanner_index_event_generation = if scanner_index_enabled {
            // Keyed on the configured roots, not this pass's: maintenance,
            // per-mount and special-location passes each walk a different
            // subset, and a per-pass key rebuilt the index on about half the
            // passes on hz1 (2026-10-14), discarding every failure backoff, so
            // a candidate the preflight always refuses was re-planned every
            // pass. Replay is scoped to the pass's roots instead.
            let context = ScannerIndexContext::from_roots_and_config(
                &current_scanner_config.root_paths,
                &current_scanner_config,
            );
            let needs_load = scanner_index
                .as_ref()
                .is_none_or(|index| index.context() != &context);
            if needs_load {
                let (loaded, status) =
                    ScannerCandidateIndex::load_checkpoint(scanner_index_path, context);
                match status {
                    ScannerIndexLoadStatus::Loaded => logger.send(ActivityEvent::Info {
                        message: format!(
                            "scanner_index: loaded {} candidates from {}",
                            loaded.len(),
                            scanner_index_path.display()
                        ),
                    }),
                    ScannerIndexLoadStatus::Missing => {}
                    ScannerIndexLoadStatus::Stale(reason)
                    | ScannerIndexLoadStatus::Corrupt(reason) => {
                        logger.send(ActivityEvent::Info {
                            message: format!("scanner_index: rebuilt checkpoint state: {reason}"),
                        });
                    }
                }
                scanner_index = Some(loaded);
            }
            let event_config =
                EventSourceConfig::from_scanner_config(&request.paths, &current_scanner_config);
            let needs_event_source = scanner_event_source
                .as_ref()
                .is_none_or(|source| !source.matches_config(&event_config));
            if needs_event_source {
                scanner_event_source = Some(ScannerEventSource::start(event_config));
                if let Some(source) = scanner_event_source.as_ref() {
                    let capability = source.capability();
                    logger.send(ActivityEvent::Info {
                        message: format!(
                            "scanner_events: backend={} complete={} watched_dirs={} frontier_dirs={} dirty_roots={} reason={}",
                            capability.selected_backend,
                            capability.complete,
                            capability.watched_dirs,
                            capability.frontier_dirs,
                            capability.dirty_roots.len(),
                            capability.reason
                        ),
                    });
                }
            }
            if let Some(source) = scanner_event_source.as_mut() {
                let mut invalidation = source.drain();
                if let Some(pending) = pending_event_invalidation.take() {
                    invalidation.merge(pending);
                }
                scanner_event_dirty_roots.clone_from(invalidation.dirty_roots());
                scanner_event_stats = source.stats();
                if invalidation.requires_reconciliation() {
                    logger.send(ActivityEvent::Info {
                        message: format!(
                            "scanner_events: dirty_roots={} dirty_paths={} generation_bump={} \
                             overflows={} backoff_secs={} replans={} watched_dirs={} frontier_dirs={} reason={}",
                            invalidation.dirty_roots().len(),
                            invalidation.dirty_paths().len(),
                            invalidation.requires_index_generation_bump(),
                            scanner_event_stats.overflows,
                            scanner_event_stats.backoff_secs,
                            scanner_event_stats.replans,
                            scanner_event_stats.watched_dirs,
                            scanner_event_stats.frontier_dirs,
                            invalidation.reason_summary()
                        ),
                    });
                }
                if let Some(index) = scanner_index.as_mut() {
                    invalidation.apply_to_index(index);
                }
            }
            if let Some(index) = scanner_index.as_mut() {
                let applied = drain_scanner_index_feedback(
                    index,
                    index_feedback_rx,
                    &current_scanner_config,
                    logger,
                );
                if applied > 0
                    && let Err(err) = index.save_checkpoint(scanner_index_path)
                {
                    logger.send(ActivityEvent::Error {
                        code: err.code().to_string(),
                        message: format!(
                            "scanner_index: failed to save feedback backoff {}: {err}",
                            scanner_index_path.display()
                        ),
                    });
                }
            }
            scanner_index
                .as_ref()
                .map_or(0, ScannerCandidateIndex::event_generation)
        } else {
            scanner_event_source = None;
            0
        };
        let mut scanner_index_records = Vec::new();
        // A Green/Yellow pass that exists because events dirtied scan paths
        // is an event pass, whoever issued the request.
        let scan_reason = if !scanner_event_dirty_roots.is_empty()
            && !request.maintenance
            && !request.force_full_scan
            && request.config_update.is_none()
            && request.catalog_roots.is_empty()
            && matches!(
                request.pressure_level,
                PressureLevel::Green | PressureLevel::Yellow
            ) {
            "event"
        } else {
            scan_reason_for_request(&request)
        };
        // (replayed, re-vetoed) index records this pass; a Cell so the
        // telemetry closure can read what the replay block writes.
        let replay_counts = std::cell::Cell::new((0usize, 0usize));
        let scan_completion_telemetry =
            |opaque_pruned_dirs: usize,
             candidate_bytes_seen: u64,
             timed_out: bool,
             index_records: usize,
             process_cpu_micros: Option<u64>| ScanCompletionTelemetry {
                engine: scanner_engine_mode.to_string(),
                dispatch: scanner_dispatch.to_string(),
                scan_reason: scan_reason.to_string(),
                opaque_pruning: scanner_opaque_pruning,
                opaque_pruned_dirs,
                event_dirty_roots: scanner_event_dirty_roots.len(),
                event_overflows: scanner_event_stats.overflows,
                event_watch_replans: scanner_event_stats.replans,
                index_event_generation: scanner_index_event_generation,
                index_records,
                candidate_bytes_seen,
                timed_out,
                replayed_records: replay_counts.get().0,
                revetoed_records: replay_counts.get().1,
                process_cpu_micros,
            };
        if last_scanner_engine_mode != Some(scanner_engine_mode) {
            logger.send(ActivityEvent::Info {
                message: format!(
                    "scanner_engine: mode={scanner_engine_mode} dispatch={scanner_dispatch} shadow_mode={scanner_shadow_mode} opaque_pruning={scanner_opaque_pruning}"
                ),
            });
            last_scanner_engine_mode = Some(scanner_engine_mode);
        }

        let mut engine = ScoringEngine::from_config(
            &current_scoring_config,
            current_scanner_config.min_file_age_minutes,
        );
        // Regret labels (Q4): what happened to this category's past
        // deletions raises the bar for the next ones, on every engine this
        // pass scores with (the walk, the index replay, the priority
        // pre-scan).
        let regret_view = regret.scoring_view(Instant::now());
        engine.set_regret(regret_view.0.clone(), regret_view.1.clone());

        // If no paths to scan, skip.
        if request.paths.is_empty() {
            continue;
        }

        heartbeat.beat();

        let active_scan_paths = if scanner_index_enabled {
            v2_active_scan_paths(&request, &scanner_event_dirty_roots)
                .unwrap_or_else(|| request.paths.clone())
        } else {
            request.paths.clone()
        };

        if scanner_index_enabled && active_scan_paths.is_empty() {
            logger.send(ActivityEvent::ScanCompleted {
                paths_scanned: 0,
                candidates_found: 0,
                duration_ms: 0,
                telemetry: scan_completion_telemetry(
                    0,
                    0,
                    false,
                    scanner_index.as_ref().map_or(0, ScannerCandidateIndex::len),
                    None,
                ),
            });
            let root_stats = request
                .paths
                .iter()
                .map(|path| RootScanResult {
                    path: path.clone(),
                    candidates_found: 0,
                    potential_bytes: 0,
                    false_positives: 0,
                    duration: Duration::ZERO,
                    dirty: dirty_under(&scanner_event_dirty_roots, path),
                })
                .collect();
            let _ = report_tx.try_send(WorkerReport::ScanCompleted {
                candidates: 0,
                duration: Duration::ZERO,
                root_stats,
                timed_out: false,
                pressure_level: request.pressure_level,
                background: request_background,
            });
            continue;
        }

        // Truncate-in-place sweep for active append-only logs (e.g. codex-tui.log).
        // Runs before the regular scan because the FileOpen veto in the deletion
        // executor would otherwise prevent recovery of these files — the failure
        // mode that drove css/ts2/trj to 99% disk on 2026-05-13. Cheap when the
        // policy is disabled (just an enabled-check) so it's safe to call every
        // scan cycle. Uses the actual triggering free-pct when available so
        // the policy's pressure_free_pct_ceiling gate keeps its configured
        // meaning across Yellow/Orange boundary conditions.
        if current_scanner_config.log_truncation.enabled {
            let truncation_free_pct = log_truncation_free_pct_for_request(&request);
            let trunc_report = crate::scanner::log_truncator::truncate_oversized_logs(
                &current_scanner_config.log_truncation,
                truncation_free_pct,
                current_scanner_config.dry_run,
            );
            let (truncate_verb, truncate_bytes, truncate_files) = if current_scanner_config.dry_run
            {
                (
                    "would_free",
                    trunc_report.bytes_would_reclaim,
                    trunc_report.files_would_truncate,
                )
            } else {
                (
                    "freed",
                    trunc_report.bytes_reclaimed,
                    trunc_report.files_truncated,
                )
            };
            if truncate_files > 0 || !trunc_report.errors.is_empty() {
                eprintln!(
                    "[sbh-truncate] pressure={:?} {truncate_verb}={}B files={} skipped={} errors={} dur={}ms",
                    request.pressure_level,
                    truncate_bytes,
                    truncate_files,
                    trunc_report.files_skipped,
                    trunc_report.errors.len(),
                    trunc_report.duration.as_millis(),
                );
                logger.send(crate::logger::dual::ActivityEvent::Info {
                    message: format!(
                        "log_truncation: {truncate_verb} {truncate_bytes} bytes across {truncate_files} file(s) at pressure={:?}",
                        request.pressure_level,
                    ),
                });
                for (path, err) in &trunc_report.errors {
                    logger.send(crate::logger::dual::ActivityEvent::Error {
                        code: "SBH-LOGTRUNC".to_string(),
                        message: format!("log_truncation error on {}: {err}", path.display()),
                    });
                }
            }
        }

        let scan_start = Instant::now();
        let scan_start_cpu_micros = current_scan_cpu_micros();
        let scan_deadline =
            scan_start + effective_scan_budget(&current_scanner_config, request.pressure_level);
        // Q7: the CPU budget is enforced as a *measured* CPU allowance while
        // the pass runs, not as a wall deadline modelled from it. Folding it
        // into the wall deadline as `cpu_secs / parallelism` capped every
        // discretionary pass at `burst / parallelism` seconds — 0.7 s on the
        // fleet — and was the reason a big tree never got scanned at all. A
        // pass that really burns CPU is still stopped at the same cost; an
        // I/O-bound walk now runs to `scanner.scan_time_budget_secs`.
        let mut limits = PassLimits::new(
            scan_start,
            scan_deadline,
            Duration::from_secs(current_scanner_config.prescan_time_budget_secs),
            PassCpuGuard::new(budget_allowance, scan_start, current_scan_cpu_secs),
        );

        // Track total candidates found (priority pre-scan + general walker).
        let mut candidates_found = 0;
        // Track candidates actually dispatched to the deletion executor this
        // pass — the signal for whether the pass made reclaim progress (drives
        // the B6 empty-pass cooldown). A pass can surface many candidates yet
        // dispatch zero when they are all protected/dampened.
        let mut dispatched_this_pass = PassDispatch::default();
        let reclaim_at_pass_start = executor_config.reclaim_events();
        let mut scanner_should_exit = false;
        let mut scan_timed_out = false;
        let v2_candidate_byte_target = if scanner_index_enabled {
            v2_pressure_candidate_byte_target(&request)
        } else {
            None
        };
        let mut v2_candidate_bytes_seen = 0u64;
        // bd-8aeq: the behavior cell's certainty gate, applied here as well as
        // in the executor. A candidate the executor would only hold back must
        // not be dispatched, must not count toward the pressure byte target
        // (otherwise the walk stops on it and never reaches a dispatchable
        // root), and must not make the pass look productive to the B6
        // cooldown. Measured before this: 574 zero-duration replay passes in
        // five minutes, each re-dispatching the same two `unclear` records.
        let pass_min_certainty = executor_config.min_certainty();
        // Counted once per path: the index replay, the priority pre-scan and
        // the walk can each hold the same directory in one pass.
        let mut held_paths: BTreeSet<PathBuf> = BTreeSet::new();
        let mut held_by_certainty: usize = 0;

        if scanner_index_enabled
            && request.pressure_level >= PressureLevel::Orange
            && request.max_delete_batch > 0
            && let Some(index) = scanner_index.as_mut()
        {
            // Persisted records are hints: each one is re-stat'ed and re-scored
            // with fresh vetoes (protection, .git, lease, open files, current
            // classification and age) before it may be dispatched. Anything
            // the fresh evidence rejects is backed off in the index.
            let replay_now = SystemTime::now();
            let records =
                index.ranked_records_within(&request.paths, replay_now, request.max_delete_batch);
            let index_generation = index.event_generation();
            let mut indexed_candidates: Vec<CandidacyScore> = Vec::with_capacity(records.len());
            let mut revetoed = 0usize;
            if !records.is_empty() {
                let replay_open_files = collect_open_path_ancestors_cached(
                    &active_scan_paths,
                    Duration::from_secs(current_scanner_config.active_reference_cache_ttl_secs),
                )
                .0;
                let mut replay_protection =
                    match ProtectionRegistry::new(Some(&current_scanner_config.protected_paths)) {
                        Ok(p) => p,
                        Err(e) => {
                            logger.send(ActivityEvent::Error {
                                code: "SBH-1001".to_string(),
                                message: format!("protection registry init failed: {e}"),
                            });
                            continue;
                        }
                    };
                replay_protection.adopt_verdict_cache(carried_verdicts.clone());
                let mut replay_sacred = platform.sacred_paths();
                replay_sacred.extend(protection::sacred_paths_from_protected_patterns(
                    &current_scanner_config.protected_paths,
                ));
                let mut replay_engine = ScoringEngine::from_config(
                    &current_scoring_config,
                    current_scanner_config.min_file_age_minutes,
                );
                replay_engine.set_regret(regret_view.0.clone(), regret_view.1.clone());
                for record in &records {
                    match replay_indexed_record(
                        record,
                        index_generation,
                        &pattern_registry,
                        &replay_engine,
                        &current_scanner_config,
                        &request,
                        &mut replay_protection,
                        &replay_sacred,
                        &replay_open_files,
                        visibility_gap,
                        logger,
                    ) {
                        Ok(score) => {
                            // bd-8aeq: a record the executor would only hold
                            // back is not re-dispatched; it stays in the index
                            // (no cooldown) for a cell that accepts it.
                            if score.decision.certainty < pass_min_certainty {
                                if held_paths.insert(record.path.clone()) {
                                    held_by_certainty += 1;
                                }
                                eprintln!(
                                    "[SBH-SCANNER] index replay path={} generation={} verdict=held certainty={} below {pass_min_certainty}",
                                    record.path.display(),
                                    record.event_generation,
                                    score.decision.certainty.label()
                                );
                                continue;
                            }
                            eprintln!(
                                "[SBH-SCANNER] index replay path={} generation={} verdict=dispatch score={:.3} certainty={}",
                                record.path.display(),
                                record.event_generation,
                                score.total_score,
                                score.decision.certainty.label()
                            );
                            indexed_candidates.push(score);
                        }
                        Err(drop) => {
                            revetoed += 1;
                            eprintln!(
                                "[SBH-SCANNER] index replay path={} generation={} verdict=drop reason={}",
                                record.path.display(),
                                record.event_generation,
                                drop.label()
                            );
                            if matches!(drop, ReplayDrop::Missing | ReplayDrop::IdentityChanged) {
                                // Deleted (often by this daemon) or replaced:
                                // there is nothing left to back off.
                                index.forget(record.identity);
                            } else if drop != ReplayDrop::GenerationAdvanced {
                                index.record_failure(
                                    record.identity,
                                    replay_now,
                                    Duration::from_secs(
                                        current_scanner_config.repeat_deletion_base_cooldown_secs,
                                    ),
                                    Duration::from_secs(
                                        current_scanner_config.repeat_deletion_max_cooldown_secs,
                                    ),
                                );
                            }
                        }
                    }
                }
                carried_verdicts = replay_protection.verdict_cache_snapshot();
            }
            replay_counts.set((records.len(), revetoed));
            let indexed_bytes = indexed_candidates
                .iter()
                .map(|candidate| candidate.size_bytes)
                .sum::<u64>();
            let indexed_count = indexed_candidates.len();
            if indexed_count > 0 {
                let indexed_before_dispatch = indexed_candidates.len();
                if !dispatch_top_candidates(
                    &mut indexed_candidates,
                    &request,
                    del_tx,
                    &mut dispatched_this_pass,
                ) {
                    break;
                }
                let indexed_dispatched =
                    indexed_before_dispatch.saturating_sub(indexed_candidates.len());
                candidates_found += indexed_count;
                if indexed_dispatched > 0 {
                    v2_candidate_bytes_seen = v2_candidate_bytes_seen.saturating_add(indexed_bytes);
                }
                if v2_candidate_byte_target.is_some_and(|target| v2_candidate_bytes_seen >= target)
                {
                    logger.send(ActivityEvent::ScanCompleted {
                        paths_scanned: 0,
                        candidates_found,
                        duration_ms: 0,
                        telemetry: scan_completion_telemetry(
                            0,
                            v2_candidate_bytes_seen,
                            false,
                            index.len(),
                            None,
                        ),
                    });
                    let root_stats = active_scan_paths
                        .iter()
                        .enumerate()
                        .map(|(index, path)| RootScanResult {
                            path: path.clone(),
                            candidates_found: if index == 0 { candidates_found } else { 0 },
                            potential_bytes: if index == 0 { indexed_bytes } else { 0 },
                            false_positives: 0,
                            duration: Duration::ZERO,
                            dirty: dirty_under(&scanner_event_dirty_roots, path),
                        })
                        .collect();
                    let _ = report_tx.try_send(WorkerReport::ScanCompleted {
                        candidates: candidates_found,
                        duration: Duration::ZERO,
                        root_stats,
                        timed_out: false,
                        pressure_level: request.pressure_level,
                        background: request_background,
                    });
                    if held_by_certainty > 0 {
                        logger.send(ActivityEvent::Info {
                            message: format!(
                                "scanner certainty gate held {held_by_certainty} candidate(s) below {pass_min_certainty} (pressure={:?}); not dispatched, not counted toward the reclaim byte target",
                                request.pressure_level
                            ),
                        });
                    }
                    unconfirmed_dispatch = Some(reclaim_at_pass_start);
                    continue;
                }
            }
        }

        let active_reference_scan = ActiveReferenceScanConfig::new(
            Duration::from_secs(current_scanner_config.active_reference_cache_ttl_secs),
            current_scanner_config.active_reference_min_size_bytes,
        );
        let active_reference_probe_budget = active_reference_scan_budget(platform.name());
        let mut open_files_joined: Option<std::collections::HashSet<std::path::PathBuf>> = None;
        let mut active_reference_joined: Option<ActiveReferenceIndex> = None;
        let mut sacred_paths = platform.sacred_paths();
        sacred_paths.extend(protection::sacred_paths_from_protected_patterns(
            &current_scanner_config.protected_paths,
        ));

        // Build protection before priority pre-scan. The normal walker also
        // enforces this, but priority pre-scan can dispatch deletion candidates
        // before walker traversal has a chance to discover marker files.
        let mut protection =
            match ProtectionRegistry::new(Some(&current_scanner_config.protected_paths)) {
                Ok(p) => p,
                Err(e) => {
                    logger.send(ActivityEvent::Error {
                        code: "SBH-1001".to_string(),
                        message: format!("protection registry init failed: {e}"),
                    });
                    continue;
                }
            };
        protection.adopt_verdict_cache(carried_verdicts.clone());

        // ── Priority pre-scan pass ──
        // Before the general walker, do a shallow (depth 1-3) scan of each root
        // for known high-value cleanup targets. This ensures multi-GB dirs like
        // `target/`, `node_modules/`, `rch_target_*` are found in seconds, not
        // after 500K small files exhaust the entry budget.
        //
        // The sweep is *resumable*: `prescan_cursor` remembers the root and
        // depth-1 entry the last pass finished, and this one carries on from
        // there. Without it a root the pre-scan cannot enumerate inside one
        // budget is re-examined from its first entry forever — the fleet's
        // `0 entries, 0 candidates` passes.
        let mut priority_candidates: Vec<CandidacyScore> = Vec::new();
        let mut prescan_stop: Option<PassStop> = None;
        let mut prescan_entries: usize = 0;
        if request.force_full_scan {
            // An operator asked for the whole tree; do not resume mid-way.
            prescan_cursor.reset();
        }
        // A pass the v2 engine scoped to the dirty project directories covers
        // those roots, not the configured ones. Letting it move the resume
        // point would send the *full* sweep back to the start on every Green
        // file-change event, so a scoped pass gets a throwaway cursor.
        let prescan_uses_cursor = active_scan_paths == request.paths;
        let prescan_cursor_before = prescan_cursor.clone();
        let mut scratch_cursor = PrescanCursor::new();
        let prescan_resume;
        {
            let cursor: &mut PrescanCursor = if prescan_uses_cursor {
                &mut prescan_cursor
            } else {
                &mut scratch_cursor
            };
            let mut prescan_engine = ScoringEngine::from_config(
                &current_scoring_config,
                current_scanner_config.min_file_age_minutes,
            );
            prescan_engine.set_regret(regret_view.0.clone(), regret_view.1.clone());
            let prescan_root_order: Vec<PathBuf> = cursor
                .root_order(&active_scan_paths)
                .into_iter()
                .map(Path::to_path_buf)
                .collect();
            'priority_roots: for root in &prescan_root_order {
                let root = root.as_path();
                if shutdown.load(Ordering::Relaxed) {
                    scanner_should_exit = true;
                    break;
                }
                if let Some(stop) = limits.prescan_stop() {
                    prescan_stop = Some(stop);
                    break;
                }
                let Ok(root_entries) = cursor.entries_to_visit(root) else {
                    // An unreadable root must not pin the cursor: move on so
                    // the next root gets its turn.
                    cursor.complete_root(&active_scan_paths, root);
                    continue;
                };
                for path in root_entries {
                    if shutdown.load(Ordering::Relaxed) {
                        scanner_should_exit = true;
                        break 'priority_roots;
                    }
                    if let Some(stop) = limits.prescan_stop() {
                        prescan_stop = Some(stop);
                        break 'priority_roots;
                    }
                    prescan_entries += 1;
                    // Record the entry as covered up front rather than at
                    // each of the body's many early exits (`continue` on a
                    // protected path, a git repo, a non-directory, ...), all
                    // of which mean "nothing more to do here". A budget that
                    // trips inside the depth-2/3 sweep rewinds to
                    // `cursor_before_entry` so the entry is retried whole.
                    let cursor_before_entry = cursor.clone();
                    cursor.advance(root, &path);
                    if !path.is_dir() {
                        continue;
                    }
                    let _ = protection.discover_ancestor_markers(&path);
                    if protection.is_protected(&path) {
                        continue;
                    }
                    // Track whether depth-1 dir is a git repo (project root).
                    // Project roots themselves must never be deletion candidates,
                    // but we still need to check their children for artifacts
                    // like `target/` and `node_modules/`.
                    let is_git_repo = known_git_dirs.contains(&path) || path.join(".git").exists();
                    if is_git_repo {
                        known_git_dirs.insert(path.clone());
                    }
                    let classification =
                        pattern_registry.classify(&path, StructuralSignals::default());
                    let depth1_is_artifact = !is_git_repo
                        && classification.category
                            != crate::scanner::patterns::ArtifactCategory::Unknown;
                    // Start with depth-1 dir only if it is itself an artifact
                    // (not a git repo).
                    let mut to_score = if depth1_is_artifact {
                        vec![path.clone()]
                    } else {
                        Vec::new()
                    };
                    // Always check depth-2 children for nested targets
                    // (e.g., /data/projects/myproject/target).
                    if let Ok(sub_entries) = std::fs::read_dir(&path) {
                        for sub_entry in sub_entries.flatten() {
                            if shutdown.load(Ordering::Relaxed) {
                                scanner_should_exit = true;
                                break 'priority_roots;
                            }
                            if let Some(stop) = limits.prescan_stop() {
                                prescan_stop = Some(stop);
                                // Stopped part-way through this entry:
                                // retry it next pass rather than record
                                // it as covered. The exception is the
                                // pass's first entry — rewinding there
                                // would repeat it forever.
                                if prescan_entries > 1 {
                                    *cursor = cursor_before_entry.clone();
                                }
                                break 'priority_roots;
                            }
                            let sub_path = sub_entry.path();
                            if sub_path.is_dir() {
                                let _ = protection.discover_ancestor_markers(&sub_path);
                                if protection.is_protected(&sub_path) {
                                    continue;
                                }
                                if known_git_dirs.contains(&sub_path)
                                    || sub_path.join(".git").exists()
                                {
                                    known_git_dirs.insert(sub_path);
                                    continue;
                                }
                                let sub_class = pattern_registry
                                    .classify(&sub_path, StructuralSignals::default());
                                if sub_class.category
                                    == crate::scanner::patterns::ArtifactCategory::Unknown
                                {
                                    // Depth 3: check children of Unknown depth-2 dirs
                                    // (catches workspace patterns like crates/foo/target).
                                    if let Ok(d3_entries) = std::fs::read_dir(&sub_path) {
                                        for d3_entry in d3_entries.flatten() {
                                            if shutdown.load(Ordering::Relaxed) {
                                                scanner_should_exit = true;
                                                break 'priority_roots;
                                            }
                                            if let Some(stop) = limits.prescan_stop() {
                                                prescan_stop = Some(stop);
                                                if prescan_entries > 1 {
                                                    *cursor = cursor_before_entry.clone();
                                                }
                                                break 'priority_roots;
                                            }
                                            let d3_path = d3_entry.path();
                                            if d3_path.is_dir() {
                                                let _ =
                                                    protection.discover_ancestor_markers(&d3_path);
                                                if protection.is_protected(&d3_path) {
                                                    continue;
                                                }
                                                if known_git_dirs.contains(&d3_path)
                                                    || d3_path.join(".git").exists()
                                                {
                                                    known_git_dirs.insert(d3_path);
                                                    continue;
                                                }
                                                let d3_class = pattern_registry.classify(
                                                    &d3_path,
                                                    StructuralSignals::default(),
                                                );
                                                if d3_class.category
                                                    != crate::scanner::patterns::ArtifactCategory::Unknown
                                                {
                                                    to_score.push(d3_path);
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    to_score.push(sub_path);
                                }
                            }
                        }
                    }

                    if to_score.is_empty() {
                        continue;
                    }

                    for candidate_path in to_score {
                        // Each candidate's protection check can walk its tree
                        // for sacred markers; one entry with dozens of
                        // candidates (a repo's `.rch-tmp/.tmp*` dirs on fmd,
                        // 2026-09-28) held a pass for 16+ minutes past its
                        // budget. Stop like the sub-entry loops do: the entry
                        // is retried next pass (unless it is the first), and
                        // candidates already proved protected are cached.
                        if let Some(stop) = limits.prescan_stop() {
                            prescan_stop = Some(stop);
                            if prescan_entries > 1 {
                                *cursor = cursor_before_entry.clone();
                            }
                            break 'priority_roots;
                        }
                        if should_skip_protected_daemon_candidate(
                            &mut protection,
                            &candidate_path,
                            &sacred_paths,
                            logger,
                            "priority pre-scan",
                        ) {
                            continue;
                        }
                        // One read_dir of the candidate gives the pre-scan
                        // the walk's structural evidence (CACHEDIR.TAG,
                        // deps/, incremental/), so its certainty is the
                        // walk's: a definite target is dispatched here
                        // instead of being held as `unclear` (which, at
                        // Orange and above, held everything the pre-scan
                        // nominated and left the dispatch to the walk).
                        let candidate_signals =
                            crate::scanner::walker::structural_signals_for_path(&candidate_path);
                        // As the walk would classify it (bd-10yj): the
                        // walker's opaque verdict first, so a tree it only
                        // descends into or protects is not nominated here on
                        // its name (a plain `target` inside an hfdt store).
                        let Some(candidate_class) = crate::scanner::walker::classify_dir_as_walked(
                            &pattern_registry,
                            &candidate_path,
                            candidate_signals,
                        ) else {
                            continue;
                        };
                        if candidate_class.category
                            == crate::scanner::patterns::ArtifactCategory::Unknown
                        {
                            continue;
                        }
                        let age = prescan_age(&candidate_path);
                        // For directories, metadata().len() only returns the
                        // dir entry size (~4KB), not the recursive contents.
                        // Use a heuristic floor: known artifact dirs (target/,
                        // node_modules/) are typically 100MB+, so using 100MB
                        // prevents the size factor from penalizing them.
                        // The general walker will compute precise recursive
                        // sizes if these candidates survive to that stage.
                        let raw_size = candidate_path.metadata().map_or(0, |m| m.len());
                        let size = if candidate_path.is_dir() {
                            raw_size.max(DIR_SIZE_FLOOR)
                        } else {
                            raw_size
                        };
                        let mut input = crate::scanner::scoring::CandidateInput {
                            path: candidate_path.clone(),
                            size_bytes: size,
                            age: adjusted_candidate_age(
                                age,
                                current_scanner_config.min_file_age_minutes,
                                request.pressure_level,
                                &candidate_path,
                                &candidate_class,
                            ),
                            classification: candidate_class,
                            signals: candidate_signals,
                            active_references: ActiveReferenceSummary::default(),
                            is_open: false,
                            excluded: false,
                        };
                        mark_visibility_gap(&mut input, visibility_gap);
                        let mut score = prescan_engine.score_candidate(&input, request.urgency);
                        // Nomination keeps the floor in the size factor; only a
                        // directory that would be deleted pays for a real size
                        // probe, and that measured size is what the planner
                        // ranks and the executor reports.
                        let measured_size = (score.decision.action
                            == crate::scanner::scoring::DecisionAction::Delete
                            && !score.vetoed
                            && candidate_path.is_dir())
                        .then(|| {
                            prescan_dir_size(
                                &candidate_path,
                                current_scanner_config.cross_devices,
                                shutdown,
                            )
                        });
                        if score.decision.action == crate::scanner::scoring::DecisionAction::Delete
                            && !score.vetoed
                            && active_reference_scan
                                .should_probe_candidate(size, score.classification.category)
                        {
                            if has_active_reference_scan_budget(
                                scan_deadline,
                                active_reference_probe_budget,
                            ) {
                                let open_files = open_files_joined.get_or_insert_with(|| {
                                    collect_open_path_ancestors_cached(
                                        &active_scan_paths,
                                        active_reference_scan.cache_ttl,
                                    )
                                    .0
                                });
                                let active_references =
                                    active_reference_joined.get_or_insert_with(|| {
                                        collect_active_references_for_scan(
                                            platform.as_ref(),
                                            &active_scan_paths,
                                            active_reference_scan,
                                            logger,
                                        )
                                    });
                                if let Ok(identity) = crate::scanner::walker::identity_for_path(
                                    &candidate_path,
                                    current_scanner_config.follow_symlinks,
                                ) {
                                    input.active_references =
                                        active_references.summary_for_identity(identity);
                                }
                                input.is_open = !input.active_references.is_empty()
                                    || crate::scanner::walker::is_path_open_by_ancestor(
                                        &candidate_path,
                                        open_files,
                                    );
                            } else {
                                mark_active_reference_budget_incomplete(&mut input);
                            }
                            score = prescan_engine.score_candidate(&input, request.urgency);
                        }
                        if score.decision.action == crate::scanner::scoring::DecisionAction::Delete
                            && !score.vetoed
                        {
                            let sacred_overlaps = match protection::find_sacred_overlaps(
                                &candidate_path,
                                &sacred_paths,
                            ) {
                                Ok(overlaps) => overlaps,
                                Err(err) => {
                                    logger.send(ActivityEvent::Error {
                                        code: err.code().to_string(),
                                        message: format!(
                                            "sacred overlap check failed for {}: {err}",
                                            candidate_path.display()
                                        ),
                                    });
                                    continue;
                                }
                            };
                            score = prescan_engine.score_candidate_with_sacred_overlaps(
                                &input,
                                request.urgency,
                                &sacred_overlaps,
                            );
                        }
                        if score.decision.action == crate::scanner::scoring::DecisionAction::Delete
                        {
                            score.identity = crate::scanner::walker::identity_for_path(
                                &candidate_path,
                                current_scanner_config.follow_symlinks,
                            )
                            .ok();
                            // Before the index record is made: the record's
                            // size is what every later replay dispatches and
                            // reports. Recording the 100 MiB nomination floor
                            // made fmd log 73 GB "freed" for a few MB of tiny
                            // node_modules (2026-09-29), and the byte target
                            // counted that fiction as progress.
                            if let Some(measured) = measured_size {
                                score.size_bytes = measured;
                            }
                            let mut scanner_index_backoff_active = false;
                            if scanner_index_enabled {
                                match CandidateIndexRecord::from_candidate_score(
                                    &score,
                                    None,
                                    input.signals,
                                    scanner_index_event_generation,
                                ) {
                                    Ok(Some(record)) => {
                                        scanner_index_backoff_active =
                                            scanner_index.as_ref().is_some_and(|index| {
                                                index.candidate_in_cooldown(
                                                    &record,
                                                    SystemTime::now(),
                                                )
                                            });
                                        scanner_index_records.push(record);
                                    }
                                    Ok(None) => {}
                                    Err(err) => logger.send(ActivityEvent::Error {
                                        code: err.code().to_string(),
                                        message: format!(
                                            "scanner_index: failed to record {}: {err}",
                                            candidate_path.display()
                                        ),
                                    }),
                                }
                            }
                            if score.decision.certainty < pass_min_certainty {
                                // bd-8aeq: same gate as the walk below.
                                if held_paths.insert(candidate_path.clone()) {
                                    held_by_certainty += 1;
                                }
                            } else if !scanner_index_backoff_active {
                                if let Some(measured) = measured_size {
                                    score.size_bytes = measured;
                                }
                                priority_candidates.push(score);
                            }
                        }
                    }
                }
                // Enumerated to the end: the next pass starts at the next
                // root (wrapping round), not at this one again.
                cursor.complete_root(&active_scan_paths, root);
            }
            prescan_resume = cursor.describe();
        }
        if scanner_should_exit {
            break;
        }
        if let Some(stop) = prescan_stop {
            if stop.ends_pass() {
                scan_timed_out = true;
            }
            eprintln!(
                "[SBH-SCANNER] priority pre-scan stopped by {} after {prescan_entries} entries \
                 ({:.1}s); resuming at {prescan_resume}",
                stop.label(),
                limits.elapsed().as_secs_f64(),
            );
            if claim_budget_warning(&mut last_budget_warning, Instant::now()) {
                logger.send(ActivityEvent::Warning {
                    code: "SBH-2007".to_string(),
                    message: format!(
                        "priority pre-scan stopped by {} after {prescan_entries} entries in \
                         {:.1}s; next pass resumes at {prescan_resume}",
                        stop.label(),
                        limits.elapsed().as_secs_f64(),
                    ),
                });
            }
        }
        // Only a pass over the configured roots owns the resume point, and
        // only a moved cursor is worth a write: this daemon exists to keep
        // disks quiet.
        if prescan_uses_cursor
            && prescan_cursor != prescan_cursor_before
            && let Err(err) = prescan_cursor.save(prescan_cursor_path)
        {
            logger.send(ActivityEvent::Info {
                message: format!(
                    "prescan_cursor: could not persist {}: {err}",
                    prescan_cursor_path.display()
                ),
            });
        }

        // Dispatch priority candidates immediately if any found.
        if !priority_candidates.is_empty() {
            let count = priority_candidates.len();
            priority_candidates.sort_by(|a, b| {
                b.total_score
                    .partial_cmp(&a.total_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            let priority_dispatch_bytes = if request.max_delete_batch == 0 {
                0
            } else {
                priority_candidates
                    .iter()
                    .take(request.max_delete_batch)
                    .map(|candidate| candidate.size_bytes)
                    .sum()
            };
            // Build pattern frequency breakdown for the log line.
            let mut pattern_counts: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();
            for c in &priority_candidates {
                let label =
                    crate::scanner::patterns::extract_pattern_label(&c.path.to_string_lossy());
                *pattern_counts.entry(label).or_insert(0) += 1;
            }
            let mut breakdown: Vec<_> = pattern_counts.into_iter().collect();
            breakdown.sort_by_key(|e| std::cmp::Reverse(e.1));
            let breakdown_str: String = breakdown
                .iter()
                .map(|(label, n)| format!("{label}\u{00d7}{n}"))
                .collect::<Vec<_>>()
                .join(", ");

            if request.max_delete_batch == 0 {
                candidates_found += count;
                eprintln!(
                    "[SBH-SCANNER] priority pre-scan identified {count} candidates without cleanup ({breakdown_str})"
                );
            } else {
                let remaining_before_dispatch = priority_candidates.len();
                if dispatch_top_candidates(
                    &mut priority_candidates,
                    &request,
                    del_tx,
                    &mut dispatched_this_pass,
                ) {
                    let dispatched_count =
                        remaining_before_dispatch.saturating_sub(priority_candidates.len());
                    candidates_found += count;
                    if dispatched_count > 0 {
                        v2_candidate_bytes_seen =
                            v2_candidate_bytes_seen.saturating_add(priority_dispatch_bytes);
                        eprintln!(
                            "[SBH-SCANNER] priority pre-scan dispatched {dispatched_count}/{count} candidates ({breakdown_str})"
                        );
                    } else {
                        eprintln!(
                            "[SBH-SCANNER] priority pre-scan deferred {count} candidates ({breakdown_str})"
                        );
                    }
                } else {
                    scanner_should_exit = true;
                }
            }
        }
        if scanner_should_exit {
            break;
        }
        if scan_timed_out {
            let duration = scan_start.elapsed();
            let root_stats: Vec<RootScanResult> = active_scan_paths
                .iter()
                .enumerate()
                .map(|(index, path)| RootScanResult {
                    path: path.clone(),
                    candidates_found: if index == 0 { candidates_found } else { 0 },
                    potential_bytes: 0,
                    false_positives: 0,
                    duration,
                    dirty: dirty_under(&scanner_event_dirty_roots, path),
                })
                .collect();
            let _ = report_tx.send(WorkerReport::ScanCompleted {
                candidates: candidates_found,
                duration,
                root_stats,
                timed_out: true,
                pressure_level: request.pressure_level,
                background: request_background,
            });
            eprintln!(
                "[SBH-SCANNER] scan complete: {prescan_entries} entries, \
                 {candidates_found} candidates, {:.1}s (timed out in the priority pre-scan)",
                duration.as_secs_f64()
            );
            if scanner_index_enabled && let Some(index) = scanner_index.as_mut() {
                persist_scanner_index_records(
                    index,
                    &mut scanner_index_records,
                    scanner_index_path,
                    logger,
                );
            }
            let process_cpu_micros = scan_start_cpu_micros
                .zip(current_scan_cpu_micros())
                .map(|(start, end)| end.saturating_sub(start));
            logger.send(ActivityEvent::ScanCompleted {
                paths_scanned: prescan_entries,
                candidates_found,
                duration_ms: duration.as_millis().try_into().unwrap_or(u64::MAX),
                telemetry: scan_completion_telemetry(
                    0,
                    v2_candidate_bytes_seen,
                    true,
                    scanner_index.as_ref().map_or(0, ScannerCandidateIndex::len),
                    process_cpu_micros,
                ),
            });
            // bd-os02: a pass cut short in the priority pre-scan is a
            // timed-out pass like any other. Skipping the accounting below
            // left the empty-pass cooldown unarmed and the duty cycle blind, so
            // a large $TMPDIR, walked one ~4,000-entry cursor slice per pass,
            // was rescanned every ~20 s at the CPU-budget ceiling for as long
            // as anything under it changed (mac-studio: 36 of the daemon's 60
            // CPU-minutes in 6.4 h, nothing to reclaim).
            if dispatched_this_pass.count == 0 {
                record_empty_pass(
                    &mut consecutive_empty_passes,
                    &mut inconclusive_empty_passes,
                    true,
                );
                last_empty_pass_at = Some(Instant::now());
                note_empty_pass_level(&mut empty_level_peak, request_level, Instant::now());
            } else {
                record_dispatching_pass(
                    last_dispatch_reclaimed_nothing,
                    &mut consecutive_empty_passes,
                    &mut inconclusive_empty_passes,
                    &mut last_empty_pass_at,
                );
                unconfirmed_dispatch = Some(reclaim_at_pass_start);
            }
            last_pass_duration = pass_started_at.elapsed();
            last_pass_finished_at = Some(Instant::now());
            last_pass_level = Some(request_level);
            continue;
        }
        if let Some(target_bytes) = v2_candidate_byte_target
            && v2_candidate_bytes_seen >= target_bytes
        {
            let duration = scan_start.elapsed();
            if scanner_index_enabled && let Some(index) = scanner_index.as_mut() {
                persist_scanner_index_records(
                    index,
                    &mut scanner_index_records,
                    scanner_index_path,
                    logger,
                );
            }
            let process_cpu_micros = scan_start_cpu_micros
                .zip(current_scan_cpu_micros())
                .map(|(start, end)| end.saturating_sub(start));
            logger.send(ActivityEvent::ScanCompleted {
                paths_scanned: 0,
                candidates_found,
                duration_ms: duration.as_millis().try_into().unwrap_or(u64::MAX),
                telemetry: scan_completion_telemetry(
                    0,
                    v2_candidate_bytes_seen,
                    false,
                    scanner_index.as_ref().map_or(0, ScannerCandidateIndex::len),
                    process_cpu_micros,
                ),
            });
            let root_stats = active_scan_paths
                .iter()
                .enumerate()
                .map(|(index, path)| RootScanResult {
                    path: path.clone(),
                    candidates_found: if index == 0 { candidates_found } else { 0 },
                    potential_bytes: if index == 0 {
                        v2_candidate_bytes_seen
                    } else {
                        0
                    },
                    false_positives: 0,
                    duration,
                    dirty: dirty_under(&scanner_event_dirty_roots, path),
                })
                .collect();
            let _ = report_tx.try_send(WorkerReport::ScanCompleted {
                candidates: candidates_found,
                duration,
                root_stats,
                timed_out: false,
                pressure_level: request.pressure_level,
                background: request_background,
            });
            if held_by_certainty > 0 {
                logger.send(ActivityEvent::Info {
                    message: format!(
                        "scanner certainty gate held {held_by_certainty} candidate(s) below {pass_min_certainty} (pressure={:?}); not dispatched, not counted toward the reclaim byte target",
                        request.pressure_level
                    ),
                });
            }
            // The pre-scan alone met the byte target: a productive pass, which
            // still owes the duty cycle its cost (bd-os02).
            record_dispatching_pass(
                last_dispatch_reclaimed_nothing,
                &mut consecutive_empty_passes,
                &mut inconclusive_empty_passes,
                &mut last_empty_pass_at,
            );
            unconfirmed_dispatch = Some(reclaim_at_pass_start);
            last_pass_duration = pass_started_at.elapsed();
            last_pass_finished_at = Some(Instant::now());
            last_pass_level = Some(request_level);
            continue;
        }

        // Configure walker.
        let walker_config = WalkerConfig {
            root_paths: active_scan_paths.clone(),
            max_depth: current_scanner_config.max_depth,
            follow_symlinks: current_scanner_config.follow_symlinks,
            cross_devices: current_scanner_config.cross_devices,
            parallelism: if scanner_index_enabled {
                v2_effective_parallelism(&current_scanner_config, request.pressure_level)
            } else {
                current_scanner_config.parallelism
            },
            opaque_pruning: scanner_opaque_pruning,
            excluded_paths: {
                let mut excluded: HashSet<PathBuf> = current_scanner_config
                    .excluded_paths
                    .iter()
                    .cloned()
                    .collect();
                // Merge barren directories from the incremental scan cursor.
                // These are subtrees that yielded zero candidates on a prior
                // timed-out pass — skipping them lets the walker explore new
                // territory instead of re-walking known-empty subtrees.
                let barren = scan_cursor.barren_exclusions();
                if !barren.is_empty() {
                    eprintln!(
                        "[SBH-SCANNER] incremental cursor: skipping {} barren dirs from prior pass",
                        barren.len()
                    );
                }
                excluded.extend(barren);
                excluded
            },
        };

        carried_verdicts = protection.verdict_cache_snapshot();

        // Catalog-only requests do not walk: each derived root is one opaque
        // candidate unit, sized and dated by a bounded probe, and flows
        // through the same classification, scoring, vetoes and dispatch below.
        let (mut rx, cancel_token) = if request.catalog_roots.is_empty() {
            // Only classified entries use a walked directory's size, and they
            // read it below (bd-gh0x).
            let walker = DirectoryWalker::new(walker_config, protection)
                .without_file_sizes()
                .with_heartbeat({
                    let hb = Arc::clone(heartbeat);
                    move || hb.beat()
                });
            let cancel_token = walker.cancel_token();

            // Perform the walk (streaming).
            match walker.stream() {
                Ok(r) => (r, cancel_token),
                Err(e) => {
                    logger.send(ActivityEvent::Error {
                        code: e.code().to_string(),
                        message: format!("walker failed: {e}"),
                    });
                    continue;
                }
            }
        } else {
            drop(walker_config);
            drop(protection);
            let (entries, skipped_young) = catalog_walk_entries(&request.catalog_roots);
            let message = format!(
                "catalog scan: {} root(s) probed, {} skipped as recently used, {} candidate unit(s): {}",
                request.catalog_roots.len(),
                skipped_young,
                entries.len(),
                entries
                    .iter()
                    .map(|entry| entry.path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            eprintln!("[SBH-SCANNER] {message}");
            logger.send(ActivityEvent::Info { message });
            (
                WalkStream::from_entries(entries),
                Arc::new(AtomicBool::new(false)),
            )
        };

        let mut paths_scanned = 0;
        // Which limit ended the general walk, if any.
        let mut walk_stop: Option<PassStop> = None;
        let mut opaque_pruned_dirs = 0usize;
        let mut scored: Vec<CandidacyScore> = Vec::with_capacity(1024);

        // Track directories for the incremental scan cursor.
        let mut visited_dirs: HashSet<PathBuf> = HashSet::new();
        let mut non_barren_dirs: HashSet<PathBuf> = HashSet::new();
        let dispatch_threshold = request
            .max_delete_batch
            .max(1)
            .saturating_mul(EARLY_DISPATCH_MULTIPLIER);
        let mut next_dispatch_deadline = scan_start + EARLY_DISPATCH_MAX_WAIT;

        // Initialize per-root stats.
        let mut root_stats_map: HashMap<PathBuf, RootScanResult> = HashMap::new();
        for root in &active_scan_paths {
            root_stats_map.insert(
                root.clone(),
                RootScanResult {
                    path: root.clone(),
                    candidates_found: 0,
                    potential_bytes: 0,
                    false_positives: 0,
                    duration: Duration::ZERO,
                    dirty: dirty_under(&scanner_event_dirty_roots, root),
                },
            );
        }

        // Process entries with timeout to handle walker deadlocks.
        // The walker can deadlock when both worker threads block on a full work queue
        // (bounded channel). Using recv_timeout ensures the budget check fires even
        // when no entries are flowing.
        loop {
            if shutdown.load(Ordering::Relaxed) {
                cancel_token.store(true, Ordering::Relaxed);
                scanner_should_exit = true;
                break;
            }
            let mut entry = match rx.recv_timeout(Duration::from_secs(2)) {
                Ok(entry) => entry,
                Err(RecvTimeoutError::Timeout) => {
                    if shutdown.load(Ordering::Relaxed) {
                        cancel_token.store(true, Ordering::Relaxed);
                        scanner_should_exit = true;
                        break;
                    }
                    // No entries for 2 seconds — check if budget is exhausted.
                    if let Some(stop) = limits.walk_stop() {
                        cancel_token.store(true, Ordering::Relaxed);
                        scan_timed_out = true;
                        walk_stop = Some(stop);
                        eprintln!(
                            "[SBH-SCANNER] scan stopped by {} ({paths_scanned} entries, \
                             {candidates_found} candidates, {:.1}s) — cancelling walker threads",
                            stop.label(),
                            limits.elapsed().as_secs_f64()
                        );
                        break;
                    }
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => break,
            };
            if shutdown.load(Ordering::Relaxed) {
                cancel_token.store(true, Ordering::Relaxed);
                scanner_should_exit = true;
                break;
            }
            paths_scanned += 1;
            if paths_scanned % SCANNER_BEAT_EVERY_ENTRIES == 0 {
                heartbeat.beat();
            }

            // Budget check: stop processing if we've exceeded entry count or time limits.
            let entry_budget_reached = paths_scanned >= SCAN_ENTRY_BUDGET;
            let stop = if entry_budget_reached {
                None
            } else {
                limits.walk_stop()
            };
            if entry_budget_reached || stop.is_some() {
                cancel_token.store(true, Ordering::Relaxed);
                scan_timed_out = true;
                walk_stop = stop;
                eprintln!(
                    "[SBH-SCANNER] scan budget reached ({paths_scanned} entries, \
                     {candidates_found} candidates, {:.1}s, limit={}) — cancelling walker threads",
                    limits.elapsed().as_secs_f64(),
                    stop.map_or("scan entry budget", PassStop::label),
                );
                break;
            }

            // Track visited directories for the incremental scan cursor.
            if entry.metadata.is_dir {
                visited_dirs.insert(entry.path.clone());
            }

            // Skip directories already known to contain .git (project roots).
            if entry.metadata.is_dir && known_git_dirs.contains(&entry.path) {
                continue;
            }

            // Classify.
            let classification = if let Some(opaque_tree) = &entry.opaque_tree {
                match opaque_tree.disposition {
                    OpaqueTreeDisposition::CandidateOpaque => {
                        opaque_pruned_dirs += 1;
                        logger.send(ActivityEvent::Info {
                            message: format!(
                                "opaque_prune: disposition=CandidateOpaque reason={} path={}",
                                opaque_tree.reason,
                                entry.path.display()
                            ),
                        });
                        opaque_tree.classification.clone()
                    }
                    OpaqueTreeDisposition::SignalOnly | OpaqueTreeDisposition::ProtectedOpaque => {
                        continue;
                    }
                }
            } else {
                pattern_registry.classify(&entry.path, entry.structural_signals)
            };
            // Age means idleness of the whole tree for regenerable categories:
            // the opaque probe recorded the newest mtime for pruned trees, and
            // a bounded sample covers v1-walked build/cache directories.
            let age = entry
                .effective_age_timestamp(classification.category.is_regenerable_tree())
                .elapsed()
                .unwrap_or(Duration::ZERO);

            // Skip unknown artifacts to save scoring cycles.
            if classification.category == crate::scanner::patterns::ArtifactCategory::Unknown {
                continue;
            }

            // Check for .git before scoring — project roots should never be
            // deletion candidates. This catches cases the priority pre-scan
            // missed (deeper directories, newly created repos).
            if entry.metadata.is_dir && entry.path.join(".git").exists() {
                known_git_dirs.insert(entry.path.clone());
                continue;
            }

            // This entry is classified: the scan cursor must not cache it or
            // any directory above it as barren.
            mark_non_barren(&mut non_barren_dirs, &entry.path);
            // The walk did not stat files (bd-gh0x); a classified walked
            // directory reads its own now. Catalog units carry their probe's
            // whole-tree size and are left alone.
            if request.catalog_roots.is_empty() {
                entry.measure_immediate_files();
            }

            let mut input = crate::scanner::scoring::CandidateInput {
                path: entry.path.clone(), // Clone needed for input
                size_bytes: entry.metadata.content_size_bytes,
                age: adjusted_candidate_age(
                    age,
                    current_scanner_config.min_file_age_minutes,
                    request.pressure_level,
                    &entry.path,
                    &classification,
                ),
                classification,
                signals: entry.structural_signals,
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false, // Walker already filters excluded paths.
            };
            mark_visibility_gap(&mut input, visibility_gap);

            let mut score = engine.score_candidate(&input, request.urgency);
            // A maintenance pass's point is to reclaim what is definitely
            // stale, so say why a classified entry was not: once per verdict,
            // then hourly, since the same entries recur on every pass.
            if request.maintenance
                && score.decision.action != crate::scanner::scoring::DecisionAction::Delete
                && maintenance_keeps.should_log(
                    &entry.path,
                    format!(
                        "{:?} {} {} {}",
                        score.decision.action,
                        score.decision.certainty.label(),
                        score.vetoed,
                        score.veto_reason.as_deref().unwrap_or("-"),
                    ),
                    Instant::now(),
                )
            {
                eprintln!(
                    "[SBH-SCANNER] maintenance keep: {} action={:?} total={:.2} posterior={:.2} \
                     certainty={} floor_applied={} age={}s vetoed={} reason={}",
                    entry.path.display(),
                    score.decision.action,
                    score.total_score,
                    score.decision.posterior_abandoned,
                    score.decision.certainty.label(),
                    score.decision.posterior_floor_applied,
                    input.age.as_secs(),
                    score.vetoed,
                    score.veto_reason.as_deref().unwrap_or("-"),
                );
            }
            // A walked (not opaque-measured) directory carries only its
            // immediate files' size, a lower bound: a 36 GB target dir read as
            // ~3 KB and skipped the running-executable / mmap / open-file
            // probes, the only guard for a binary a process is running.
            let probe_size = if entry.metadata.is_dir && entry.opaque_tree.is_none() {
                u64::MAX
            } else {
                entry.metadata.content_size_bytes
            };
            if score.decision.action == crate::scanner::scoring::DecisionAction::Delete
                && !score.vetoed
                && active_reference_scan
                    .should_probe_candidate(probe_size, input.classification.category)
            {
                if has_active_reference_scan_budget(scan_deadline, active_reference_probe_budget) {
                    let open_files = open_files_joined.get_or_insert_with(|| {
                        collect_open_path_ancestors_cached(
                            &active_scan_paths,
                            active_reference_scan.cache_ttl,
                        )
                        .0
                    });
                    let active_references = active_reference_joined.get_or_insert_with(|| {
                        collect_active_references_for_scan(
                            platform.as_ref(),
                            &active_scan_paths,
                            active_reference_scan,
                            logger,
                        )
                    });
                    input.active_references =
                        active_references.summary_for_identity(entry.metadata.identity());
                    input.is_open = !input.active_references.is_empty()
                        || crate::scanner::walker::is_path_open_by_ancestor(
                            &entry.path,
                            open_files,
                        );
                } else {
                    mark_active_reference_budget_incomplete(&mut input);
                }
                score = engine.score_candidate(&input, request.urgency);
            }
            if score.decision.action == crate::scanner::scoring::DecisionAction::Delete
                && !score.vetoed
            {
                let sacred_overlaps =
                    match protection::find_sacred_overlaps(&entry.path, &sacred_paths) {
                        Ok(overlaps) => overlaps,
                        Err(err) => {
                            logger.send(ActivityEvent::Error {
                                code: err.code().to_string(),
                                message: format!(
                                    "sacred overlap check failed for {}: {err}",
                                    entry.path.display()
                                ),
                            });
                            continue;
                        }
                    };
                score = engine.score_candidate_with_sacred_overlaps(
                    &input,
                    request.urgency,
                    &sacred_overlaps,
                );
            }

            // A walked (not opaque-measured) directory carries only its
            // immediate files' size. Measure one that is about to be recorded
            // and dispatched, as the pre-scan does (bd-3rlm): on hz2 two such
            // candidates, 4 KiB each on paper, freed 2.5 GB, and a byte target
            // counted in paper bytes is never met, so the pass kept choosing.
            if score.decision.action == crate::scanner::scoring::DecisionAction::Delete
                && !score.vetoed
                && entry.metadata.is_dir
                && entry.opaque_tree.is_none()
            {
                score.size_bytes = score.size_bytes.max(prescan_dir_size(
                    &entry.path,
                    current_scanner_config.cross_devices,
                    shutdown,
                ));
            }

            score.identity = Some(entry.metadata.identity());
            let mut scanner_index_backoff_active = false;
            if scanner_index_enabled {
                match CandidateIndexRecord::from_candidate_score(
                    &score,
                    entry.opaque_tree.as_ref(),
                    entry.structural_signals,
                    scanner_index_event_generation,
                ) {
                    Ok(Some(record)) => {
                        scanner_index_backoff_active =
                            scanner_index.as_ref().is_some_and(|index| {
                                index.candidate_in_cooldown(&record, SystemTime::now())
                            });
                        scanner_index_records.push(record);
                    }
                    Ok(None) => {}
                    Err(err) => logger.send(ActivityEvent::Error {
                        code: err.code().to_string(),
                        message: format!(
                            "scanner_index: failed to record {}: {err}",
                            entry.path.display()
                        ),
                    }),
                }
            }

            // Attribute to root.
            let root_path = active_scan_paths.iter().find(|r| entry.path.starts_with(r));

            if scanner_index_backoff_active {
                continue;
            }

            let deletable = score.decision.action
                == crate::scanner::scoring::DecisionAction::Delete
                && !score.vetoed;
            if deletable && score.decision.certainty < pass_min_certainty {
                // bd-8aeq: indexed above (a cell that accepts this certainty
                // can replay it) but neither dispatched nor counted toward
                // the byte target, so the walk keeps looking for a root the
                // current cell would actually delete.
                if held_paths.insert(entry.path.clone()) {
                    held_by_certainty += 1;
                }
            } else if deletable {
                candidates_found += 1;
                let potential_bytes = score.size_bytes;
                v2_candidate_bytes_seen = v2_candidate_bytes_seen.saturating_add(potential_bytes);
                scored.push(score);
                if let Some(root) = root_path
                    && let Some(stat) = root_stats_map.get_mut(root)
                {
                    stat.candidates_found += 1;
                    stat.potential_bytes += potential_bytes;
                }
            } else if score.vetoed
                && let Some(root) = root_path
                && let Some(stat) = root_stats_map.get_mut(root)
            {
                stat.false_positives += 1;
            }

            // Do not wait for full walk completion before sending the first deletion batch.
            // On very large trees this starts reclaim work earlier and avoids long periods with
            // zero deletion progress while the scanner is still traversing.
            let should_dispatch = !scored.is_empty()
                && (scored.len() >= dispatch_threshold || Instant::now() >= next_dispatch_deadline);
            if should_dispatch {
                if !dispatch_top_candidates(
                    &mut scored,
                    &request,
                    del_tx,
                    &mut dispatched_this_pass,
                ) {
                    scanner_should_exit = true;
                    break;
                }
                next_dispatch_deadline = Instant::now() + EARLY_DISPATCH_MAX_WAIT;
            }
            if let Some(target_bytes) = v2_candidate_byte_target
                && v2_candidate_bytes_seen >= target_bytes
            {
                if !dispatch_top_candidates(
                    &mut scored,
                    &request,
                    del_tx,
                    &mut dispatched_this_pass,
                ) {
                    scanner_should_exit = true;
                }
                cancel_token.store(true, Ordering::Relaxed);
                break;
            }
        }

        // A pass stopped by its budget left part of the tree unseen: nothing
        // at or above that ground may be cached as barren (bd-y70k). If the
        // walker threads do not stop in time, what they left is unknown, and
        // the pass caches nothing new.
        if scan_timed_out {
            let unfinished = rx.unfinished_after_cancel(WALK_STOP_WAIT);
            for path in unfinished.iter().flatten() {
                mark_non_barren(&mut non_barren_dirs, path);
            }
            if unfinished.is_none() {
                eprintln!(
                    "[SBH-SCANNER] walker threads still running {}s after the stop; \
                     the scan cursor caches nothing from this pass",
                    WALK_STOP_WAIT.as_secs()
                );
                visited_dirs.clear();
            }
        }

        // Distribute total scan duration across roots so the VOI scheduler gets
        // non-zero IO cost estimates.  The walker interleaves entries from all
        // roots, so per-root wall time is not available; dividing evenly is an
        // acceptable approximation that the EWMA smooths over time.
        let total_scan_duration = scan_start.elapsed();
        let num_roots = root_stats_map.len().max(1);
        let per_root_divisor = u32::try_from(num_roots).unwrap_or(u32::MAX);
        let per_root_duration = total_scan_duration / per_root_divisor;
        for stat in root_stats_map.values_mut() {
            stat.duration = per_root_duration;
        }

        #[allow(clippy::cast_possible_truncation)]
        let scan_duration_ms = total_scan_duration.as_millis() as u64;

        let pass_cpu_secs = limits.cpu.finish();
        eprintln!(
            "[SBH-SCANNER] scan complete: {paths_scanned} entries, \
             {candidates_found} candidates, {:.1}s, cpu={pass_cpu_secs:.2}s{}",
            total_scan_duration.as_secs_f64(),
            if scan_timed_out { " (timed out)" } else { "" },
        );
        if scan_timed_out {
            // Operator-visible: a pass that ends on a budget has left part of
            // the tree unexamined, and which limit it was decides the fix
            // (raise `scanner.scan_time_budget_secs`, raise
            // `telemetry.cpu_budget_pct`/`cpu_budget_burst_secs`, or accept
            // the multi-pass sweep). The entry count says how far it got.
            if claim_budget_warning(&mut last_budget_warning, Instant::now()) {
                logger.send(ActivityEvent::Warning {
                    code: "SBH-2007".to_string(),
                    message: format!(
                        "scan pass stopped by {} after {paths_scanned} entries \
                         ({candidates_found} candidates, {:.1}s wall, {pass_cpu_secs:.2}s cpu); \
                         the pre-scan resumes at {prescan_resume}",
                        walk_stop.map_or("scan entry budget", PassStop::label),
                        total_scan_duration.as_secs_f64(),
                    ),
                });
            }
        }

        // Update the incremental scan cursor. On timeout, barren dirs are
        // cached so the next pass skips them. On full completion, cache is
        // cleared for a fresh scan.
        scan_cursor.update(&visited_dirs, &non_barren_dirs, scan_timed_out);

        // Persist v2 candidate-index state before reporting completion.
        if scanner_index_enabled && let Some(index) = scanner_index.as_mut() {
            persist_scanner_index_records(
                index,
                &mut scanner_index_records,
                scanner_index_path,
                logger,
            );
        }

        // Log scan completion.
        let process_cpu_micros = scan_start_cpu_micros
            .zip(current_scan_cpu_micros())
            .map(|(start, end)| end.saturating_sub(start));

        logger.send(ActivityEvent::ScanCompleted {
            paths_scanned,
            candidates_found,
            duration_ms: scan_duration_ms,
            telemetry: scan_completion_telemetry(
                opaque_pruned_dirs,
                v2_candidate_bytes_seen,
                scan_timed_out,
                scanner_index.as_ref().map_or(0, ScannerCandidateIndex::len),
                process_cpu_micros,
            ),
        });

        // Report scan stats back to main loop for SelfMonitor counters.
        let _ = report_tx.try_send(WorkerReport::ScanCompleted {
            candidates: candidates_found,
            duration: total_scan_duration,
            root_stats: root_stats_map.into_values().collect(),
            timed_out: scan_timed_out,
            pressure_level: request.pressure_level,
            background: request_background,
        });

        // Flush remaining candidates in bounded batches.
        // Hard cap: never spend more than 30s flushing after the scan loop ends.
        let flush_deadline = Instant::now() + Duration::from_secs(30);
        while !scored.is_empty() {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            if Instant::now() >= flush_deadline {
                eprintln!(
                    "[SBH-SCANNER] flush deadline reached; {} candidates will be rediscovered on next pass",
                    scored.len()
                );
                break;
            }
            let pending_before = scored.len();
            if !dispatch_top_candidates(&mut scored, &request, del_tx, &mut dispatched_this_pass) {
                scanner_should_exit = true;
                break;
            }
            // No progress means executor channel stayed full; avoid busy-loop.
            if scored.len() >= pending_before {
                eprintln!(
                    "[SBH-SCANNER] executor backlog persisted at scan end; {} candidates will be rediscovered on next pass",
                    scored.len()
                );
                break;
            }
        }

        // B6: arm/clear the inter-pass cooldown. A pass that completed (not
        // timed out) yet *dispatched nothing* to the deletion executor made no
        // reclaim progress — either it surfaced no candidates, or (the hot-loop
        // case) it surfaced candidates that were all protected/dampened. Either
        // way, immediately re-scanning under the same sustained pressure just
        // re-walks the same tree and pins a core, so arm the cooldown and grow
        // the backoff. A productive pass (≥1 dispatched) resets it.
        //
        // This accounting MUST run after the final flush above: a pass whose
        // dispatches all happen at flush time (nothing dispatched early during
        // the walk) is still productive, and judging `dispatched_this_pass`
        // before the flush would misclassify it as empty and wrongly arm the
        // backoff (#15).
        //
        // A single *timed-out* pass with nothing dispatched is inconclusive for
        // the exponential streak (the budget may simply have expired before
        // the walker reached reclaimable files), but it still arms the base
        // cooldown timestamp, and every TERMINAL_IDLE_EMPTY_PASSES of them in
        // a row count as one empty pass (`record_empty_pass`, bd-qxrh). The
        // old behavior of fully resetting on timeout meant a tree big enough
        // to exhaust the scan budget on every pass could never back off at all
        // and re-walked back-to-back forever (~95% CPU at 82% disk, #15 case
        // 1); never counting timeouts kept Red/Critical out of terminal idle.
        //
        // NOTE: keying on dispatched-count, not candidates_found, is the fix for
        // the perpetual-Yellow hot-loop where every candidate is a sacred-marker
        // fixture (`*.sqlite-wal`/`.git`/`.beads`): candidates_found stays high
        // while deleted/freed stays 0, so the old `candidates_found == 0` gate
        // never armed.
        if held_by_certainty > 0 {
            logger.send(ActivityEvent::Info {
                message: format!(
                    "scanner certainty gate held {held_by_certainty} candidate(s) below {pass_min_certainty} (pressure={:?}); not dispatched, not counted toward the reclaim byte target",
                    request.pressure_level
                ),
            });
        }
        if dispatched_this_pass.count == 0 {
            record_empty_pass(
                &mut consecutive_empty_passes,
                &mut inconclusive_empty_passes,
                scan_timed_out,
            );
            last_empty_pass_at = Some(Instant::now());
            note_empty_pass_level(&mut empty_level_peak, request_level, Instant::now());
            let next_secs = effective_empty_pass_cooldown(
                current_scanner_config.min_rescan_interval_secs,
                consecutive_empty_passes,
            )
            .as_secs();
            if next_secs > 0 {
                eprintln!(
                    "[SBH-SCANNER] no reclaimable progress this pass ({candidates_found} candidates, {held_by_certainty} held below {pass_min_certainty}, 0 dispatched, timed_out={scan_timed_out}); backing off rescans (consecutive={consecutive_empty_passes}, next pressure-driven scan in ≥{next_secs}s)"
                );
            }
        } else {
            record_dispatching_pass(
                last_dispatch_reclaimed_nothing,
                &mut consecutive_empty_passes,
                &mut inconclusive_empty_passes,
                &mut last_empty_pass_at,
            );
            unconfirmed_dispatch = Some(reclaim_at_pass_start);
        }

        // #15: record this pass's cost so the next pressure-driven pass owes
        // proportional idle. Recorded for productive AND unproductive passes —
        // the productive case is the one that used to pin a core.
        last_pass_duration = pass_started_at.elapsed();
        last_pass_finished_at = Some(Instant::now());
        last_pass_level = Some(request_level);

        if scanner_should_exit {
            break;
        }
    }
}

// ──────────────────── repeat deletion dampening ────────────────────

/// Tracks a single path's deletion history for repeat-deletion dampening.
struct DeletionRecord {
    last_deleted: Instant,
    cycle_count: u32,
}

/// Exponential-backoff tracker that dampens re-deletion of paths that keep reappearing.
///
/// When an agent builds to a default target dir without `CARGO_TARGET_DIR`, sbh deletes
/// it, the agent rebuilds, sbh deletes again — creating a cleanup loop. This tracker
/// applies increasing cooldowns to break the cycle while still allowing deletion after
/// enough time passes.
///
/// Red/Critical pressure bypasses all dampening (disk safety always wins).
struct RepeatDeletionTracker {
    history: HashMap<PathBuf, DeletionRecord>,
    base_cooldown: Duration,
    max_cooldown: Duration,
}

impl RepeatDeletionTracker {
    fn new(base_cooldown: Duration, max_cooldown: Duration) -> Self {
        Self {
            history: HashMap::new(),
            base_cooldown,
            max_cooldown,
        }
    }

    /// Update cooldown parameters from reloaded config without dropping history.
    fn update_cooldowns(&mut self, base_cooldown: Duration, max_cooldown: Duration) {
        self.base_cooldown = base_cooldown;
        self.max_cooldown = max_cooldown;
    }

    /// Remaining cooldown for a path, or `None` if no cooldown applies.
    ///
    /// Formula: `base_cooldown * 2^(cycle_count - 1)`, capped at `max_cooldown`.
    /// First deletion (cycle_count == 0 or no record) has no cooldown.
    fn cooldown_for(&self, path: &Path) -> Option<Duration> {
        let record = self.history.get(path)?;
        if record.cycle_count == 0 {
            return None;
        }
        let multiplier = 1u64
            .checked_shl(record.cycle_count.saturating_sub(1))
            .unwrap_or(u64::MAX);
        let cooldown = self
            .base_cooldown
            .saturating_mul(multiplier.try_into().unwrap_or(u32::MAX));
        let cooldown = cooldown.min(self.max_cooldown);
        let elapsed = record.last_deleted.elapsed();
        if elapsed >= cooldown {
            None
        } else {
            cooldown.checked_sub(elapsed)
        }
    }

    /// Record that the given paths were just deleted. Increments cycle_count for repeats.
    fn record_deletions(&mut self, paths: &[PathBuf]) {
        let now = Instant::now();
        for path in paths {
            let entry = self.history.entry(path.clone()).or_insert(DeletionRecord {
                last_deleted: now,
                cycle_count: 0,
            });
            entry.last_deleted = now;
            entry.cycle_count = entry.cycle_count.saturating_add(1);
        }
    }

    /// Split candidates into (approved, dampened).
    ///
    /// Bypass conditions (no dampening applied):
    /// - Pressure is Red or Critical (disk safety always wins).
    /// - Urgency >= 0.85 even at lower pressure levels — the predictive
    ///   controller has flagged that Red is imminent within the action
    ///   horizon. On high-throughput build machines disk can drop from
    ///   Yellow (14% free) to Critical (~0%) in a single poll interval,
    ///   which is faster than the dampener's per-path cooldown can
    ///   sensibly resolve. Without this bypass, sbh sits idle at Yellow
    ///   while disk fills (the failure mode that hit ts1 on 2026-04-30).
    fn filter_candidates(
        &self,
        candidates: Vec<CandidacyScore>,
        pressure: PressureLevel,
        urgency: f64,
    ) -> (Vec<CandidacyScore>, Vec<CandidacyScore>) {
        if pressure >= PressureLevel::Red || urgency >= 0.85 {
            return (candidates, Vec::new());
        }
        let mut approved = Vec::with_capacity(candidates.len());
        let mut dampened = Vec::new();
        for candidate in candidates {
            if self.cooldown_for(&candidate.path).is_some() {
                dampened.push(candidate);
            } else {
                approved.push(candidate);
            }
        }
        (approved, dampened)
    }

    /// Remove entries whose last deletion is older than max_cooldown.
    fn prune_expired(&mut self) {
        self.history
            .retain(|_, record| record.last_deleted.elapsed() < self.max_cooldown);
    }
}

// ──────────────────── executor thread ────────────────────

/// The operator's `protected_paths` as the executor applies them to a batch.
/// A target-only batch (bd-232u) goes without the patterns that protect its
/// root as a whole, which is why the tier exists; one naming something inside
/// the root still applies. `.sbh-protect` markers are checked separately and
/// always apply.
fn batch_protected_paths(
    batch: &DeletionBatch,
    scanner: &crate::core::config::ScannerConfig,
) -> Vec<String> {
    batch.target_only_root.as_deref().map_or_else(
        || scanner.protected_paths.clone(),
        |root| {
            scanner
                .protected_paths
                .iter()
                .filter(|pattern| !protection::pattern_covers_subtree(pattern, root))
                .cloned()
                .collect()
        },
    )
}

/// Keep only the candidates a target-only batch may hold: strictly inside its
/// root, with the identity the tier recorded when it surveyed them, and
/// still pure now (`target_tier::still_pure`). Returns how many were dropped;
/// an ordinary batch is left as it is.
fn retain_target_only_candidates(batch: &mut DeletionBatch) -> usize {
    let Some(root) = &batch.target_only_root else {
        return 0;
    };
    let before = batch.candidates.len();
    batch
        .candidates
        .retain(|candidate| authorize_target_only_candidate(candidate, Some(root)).is_ok());
    before - batch.candidates.len()
}

/// Renew the narrowly scoped protection exception at the mutation boundary.
/// A directory keeps its inode when an agent adds a trace or log to it, so
/// identity revalidation alone cannot establish that it is still pure output.
fn authorize_target_only_candidate(
    candidate: &CandidacyScore,
    root: Option<&Path>,
) -> std::result::Result<(), SkipReason> {
    let Some(root) = root else {
        return Ok(());
    };
    if candidate.identity.is_none() {
        return Err(SkipReason::IdentityUnavailable);
    }
    if candidate.path == root
        || !candidate.path.starts_with(root)
        || !crate::daemon::target_tier::still_pure(&candidate.path)
    {
        return Err(SkipReason::SacredStowaway);
    }
    Ok(())
}

/// Drop candidates with nothing to reclaim. The planner never chooses an
/// item that frees no bytes (an empty mktemp target of a live remote build
/// was taken at Critical on ts2, 2026-10-15), so evaluating them only re-ran
/// the policy engine every pass and wrote an approved, never-executed delete
/// to the decision ledger each time: on ts2 99 hardlinked bun trees were
/// "approved 99/99 ... planner chose none" pass after pass. Returns how many
/// were dropped.
fn drop_zero_byte_candidates(batch: &mut DeletionBatch) -> usize {
    let before = batch.candidates.len();
    batch
        .candidates
        .retain(|candidate| candidate.size_bytes > 0);
    before - batch.candidates.len()
}

/// How often the executor reports the zero-byte candidates it dropped: one
/// line with the running count, not one per batch.
const ZERO_BYTE_DROP_LOG_EVERY: Duration = Duration::from_mins(10);

/// Executor thread: receives deletion batches and safely removes artifacts.
///
/// Gates all deletions through the `PolicyEngine` before execution. In Observe
/// or FallbackSafe modes, the policy engine blocks all deletions. In Canary mode,
/// a capped subset is allowed. In Enforce mode, all scored candidates proceed.
///
/// Reads `dry_run`, `max_batch_size`, and `min_score` from shared atomics on each
/// batch, so config reloads (SIGHUP) take effect without respawning the thread.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn executor_thread_main(
    del_rx: &Receiver<DeletionBatch>,
    logger: &ActivityLoggerHandle,
    shared_config: &Arc<SharedExecutorConfig>,
    shared_scanner_config: &Arc<RwLock<crate::core::config::ScannerConfig>>,
    heartbeat: &Arc<ThreadHeartbeat>,
    report_tx: &Sender<WorkerReport>,
    policy_engine: &Arc<Mutex<PolicyEngine>>,
    shared_guard_diagnostics: &Arc<RwLock<Option<GuardDiagnostics>>>,
    shutdown: &Arc<AtomicBool>,
    index_feedback_tx: &Sender<ScannerIndexFeedback>,
    platform_sacred_paths: &[crate::platform::types::SacredPath],
    regret: &Arc<SharedRegret>,
) {
    let mut tracker = RepeatDeletionTracker::new(
        Duration::from_secs(shared_config.repeat_base_cooldown_secs()),
        Duration::from_secs(shared_config.repeat_max_cooldown_secs()),
    );
    let mut batch_count: u64 = 0;
    let mut last_circuit_breaker_trip: Option<Instant> = None;
    let base_circuit_breaker_cooldown = DeletionConfig::default().circuit_breaker_cooldown;
    let mut circuit_breaker_cooldown = base_circuit_breaker_cooldown;
    let max_circuit_breaker_cooldown = Duration::from_mins(5); // 5 minutes cap
    let mut last_policy_reject_log: Option<Instant> = None;
    let mut last_cb_cooldown_log: Option<Instant> = None;
    let mut zero_byte_dropped: usize = 0;
    let mut last_zero_byte_log: Option<Instant> = None;
    // Rate-limit the NotWritable systemd-misconfig warning to once per hour
    // per executor thread. The condition is persistent until the operator
    // fixes the unit file, so logging on every batch would flood journals.
    let mut last_not_writable_warning: Option<Instant> = None;
    // Q8: anytime-valid monitor over this thread's success/failure stream.
    let mut failure_monitor = DeletionFailureMonitor::with_defaults();
    let mut failure_alarm_raised = false;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let mut batch = match del_rx.recv_timeout(WORKER_SHUTDOWN_POLL_INTERVAL) {
            Ok(batch) => batch,
            Err(RecvTimeoutError::Timeout) => {
                // Idle is alive: "stalled" must mean stuck inside a batch,
                // not waiting for one.
                heartbeat.beat();
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        };
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        heartbeat.beat();
        batch_count += 1;

        let outside = retain_target_only_candidates(&mut batch);
        if outside > 0 {
            let message = format!(
                "dropped {outside} target-only candidate(s) outside {}, without an identity, \
                 or no longer pure",
                batch
                    .target_only_root
                    .as_deref()
                    .unwrap_or_else(|| Path::new("?"))
                    .display()
            );
            eprintln!("[SBH-EXECUTOR] {message}");
            logger.send(ActivityEvent::Info { message });
            if batch.candidates.is_empty() {
                continue;
            }
        }

        let empty = drop_zero_byte_candidates(&mut batch);
        if empty > 0 {
            zero_byte_dropped = zero_byte_dropped.saturating_add(empty);
            if last_zero_byte_log.is_none_or(|at| at.elapsed() >= ZERO_BYTE_DROP_LOG_EVERY) {
                let message = format!(
                    "dropped {zero_byte_dropped} zero-byte candidate(s) before the policy \
                     engine: nothing to reclaim, so the planner would never choose them"
                );
                eprintln!("[SBH-EXECUTOR] {message}");
                logger.send(ActivityEvent::Info { message });
                zero_byte_dropped = 0;
                last_zero_byte_log = Some(Instant::now());
            }
            if batch.candidates.is_empty() {
                continue;
            }
        }

        // Enforce circuit breaker cooldown from a previous trip. If the breaker
        // tripped recently, skip this batch entirely and drain the channel.
        if let Some(trip_time) = last_circuit_breaker_trip {
            if trip_time.elapsed() < circuit_breaker_cooldown {
                // Rate-limit this message: log once per 60s during cooldown
                let should_log =
                    last_cb_cooldown_log.is_none_or(|t| t.elapsed() >= Duration::from_mins(1));
                if should_log {
                    eprintln!(
                        "[SBH-EXECUTOR] circuit breaker cooldown active ({:.0}s remaining), skipping batches",
                        circuit_breaker_cooldown.as_secs_f64() - trip_time.elapsed().as_secs_f64(),
                    );
                    last_cb_cooldown_log = Some(Instant::now());
                }
                continue;
            }
            // Cooldown expired, reset.
            last_circuit_breaker_trip = None;
            last_cb_cooldown_log = None;
        }

        // Pick up live config reloads for repeat-deletion dampening.
        tracker.update_cooldowns(
            Duration::from_secs(shared_config.repeat_base_cooldown_secs()),
            Duration::from_secs(shared_config.repeat_max_cooldown_secs()),
        );

        // Gate candidates through the policy engine. The lock is held only for
        // the duration of evaluate() (pure computation, no I/O).
        let decision = {
            let guard_snapshot = shared_guard_diagnostics.read().clone();
            let guard_for_policy = guard_snapshot
                .as_ref()
                .filter(|diag| diag.status != GuardStatus::Unknown);
            policy_engine
                .lock()
                .evaluate(&batch.candidates, guard_for_policy)
        };
        // Every decision goes to the evidence ledger (SQLite decision_log +
        // JSONL `decision` lines) whether or not it is executed, so
        // `sbh explain --id` can answer for keeps and vetoes too.
        for record in &decision.records {
            logger.send(ActivityEvent::DecisionRecorded(Box::new(record.clone())));
        }
        let (approved_candidates, policy_mode) = (decision.approved_for_deletion, decision.mode);

        if !approved_candidates.is_empty() {
            eprintln!(
                "[SBH-EXECUTOR] policy engine approved {}/{} candidates (mode={})",
                approved_candidates.len(),
                batch.candidates.len(),
                policy_mode,
            );
        }

        if approved_candidates.is_empty() {
            // Rate-limit this message to once per 30 minutes. On machines with
            // permanent guard drift alarm, the same rejection logs every scan
            // cycle (~5 min) indefinitely — pure noise. 30 min still surfaces
            // the issue without flooding the journal.
            let now = Instant::now();
            let should_log = last_policy_reject_log
                .is_none_or(|last| now.duration_since(last) >= Duration::from_mins(30));
            if should_log {
                last_policy_reject_log = Some(now);
                eprintln!(
                    "[SBH-EXECUTOR] policy rejected {}/{} candidates (mode={})",
                    batch.candidates.len(),
                    batch.candidates.len(),
                    policy_mode,
                );
            }
            continue;
        }

        // Apply repeat-deletion dampening (Red/Critical or high-urgency bypasses).
        let (approved_candidates, dampened) =
            tracker.filter_candidates(approved_candidates, batch.pressure_level, batch.urgency);

        if !dampened.is_empty() {
            eprintln!(
                "[SBH-EXECUTOR] dampened {}/{} repeat-deletion candidates",
                dampened.len(),
                dampened.len() + approved_candidates.len(),
            );
        }

        if approved_candidates.is_empty() {
            if !dampened.is_empty() {
                eprintln!(
                    "[SBH-EXECUTOR] all {} approved candidates were dampened (pressure={:?})",
                    dampened.len(),
                    batch.pressure_level,
                );
            }
            continue;
        }

        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Read latest config from shared atomics (updated by config reload).
        let dry_run = shared_config.dry_run.load(Ordering::Relaxed);
        let max_batch_size = shared_config.max_batch_size.load(Ordering::Relaxed);
        let min_score = shared_config.min_score();

        // Behavior-cell certainty gate (v0.6 matrix): Green/Yellow cells dispatch
        // only structurally definite artifacts; Orange adds likely ones; Red and
        // Critical dispatch every Delete verdict.
        let min_certainty = shared_config.min_certainty();
        let (approved_candidates, held_back_by_certainty) =
            retain_dispatchable_by_certainty(approved_candidates, min_certainty);
        if held_back_by_certainty > 0 {
            let message = format!(
                "certainty gate held back {held_back_by_certainty} candidate(s) below \
                 {min_certainty} (pressure={:?})",
                batch.pressure_level
            );
            eprintln!("[SBH-EXECUTOR] {message}");
            logger.send(ActivityEvent::Info { message });
        }
        if approved_candidates.is_empty() {
            continue;
        }

        let pre_plan_count = approved_candidates.len();
        // W1 planner (G16): of the approved candidates, the set that reaches
        // the pass's byte target with the least expected loss inside the
        // level's risk budget, instead of the top-N by score.
        let (approved_candidates, batch_plan) = {
            let (table, false_positive_loss) = *shared_config.planner.read();
            plan_batch(
                approved_candidates,
                &PlanRequest {
                    level: batch.pressure_level,
                    target_bytes: batch.target_bytes,
                    max_items: max_batch_size,
                    risk_budget: table.budget(batch.pressure_level, false_positive_loss),
                    false_positive_loss,
                    include_review: false,
                },
            )
        };
        if !batch_plan.chosen.is_empty() || !batch_plan.skipped_for_budget.is_empty() {
            let line = batch_plan.summary_line();
            eprintln!("[SBH-PLANNER] {line}");
            logger.send(ActivityEvent::Info {
                message: format!(
                    "planner {line} json={}",
                    serde_json::to_string(&batch_plan).unwrap_or_default()
                ),
            });
        }
        if approved_candidates.is_empty() {
            eprintln!(
                "[SBH-EXECUTOR] planner chose none of {pre_plan_count} approved candidate(s) within the risk budget"
            );
            continue;
        }
        // The executor's pre-flight sacred rail sees the same catalog the
        // scoring stage does: platform builtins plus operator patterns.
        let operator_protected_paths = batch_protected_paths(&batch, &shared_scanner_config.read());
        let executor_sacred_paths = {
            let mut catalog = platform_sacred_paths.to_vec();
            catalog.extend(protection::sacred_paths_from_protected_patterns(
                &operator_protected_paths,
            ));
            catalog
        };
        let executor = DeletionExecutor::new(
            DeletionConfig {
                max_batch_size,
                dry_run,
                min_score,
                check_open_files: true,
                // A target-only batch is pinned to the inodes the tier
                // surveyed, whatever the engine.
                require_identity: batch.target_only_root.is_some()
                    || matches!(shared_scanner_config.read().engine, ScannerEngineMode::V2),
                sacred_paths: executor_sacred_paths,
                // Layer 7: at Green there is time to keep the bytes around,
                // so the batch quarantines; from Yellow up the space is
                // needed and candidates are removed for good.
                mode: if shared_config.quarantine_enabled.load(Ordering::Relaxed)
                    && batch.pressure_level == PressureLevel::Green
                {
                    DeletionMode::Quarantine
                } else {
                    DeletionMode::Unlink
                },
                quarantine_ttl: Duration::from_secs(
                    shared_config.quarantine_ttl_secs.load(Ordering::Relaxed),
                ),
                quarantine_roots: shared_scanner_config.read().root_paths.clone(),
                ..Default::default()
            },
            Some(logger.clone()),
        );

        let mut plan = executor.plan(approved_candidates);
        // Execute in the planner's order (best reclaim per unit of risk
        // first), not by composite score.
        plan.candidates.sort_by_key(|candidate| {
            batch_plan
                .chosen
                .iter()
                .position(|item| item.path == candidate.path)
                .unwrap_or(usize::MAX)
        });

        if plan.candidates.is_empty() {
            eprintln!(
                "[SBH-EXECUTOR] plan() filtered all {pre_plan_count} approved candidates \
                 (min_score={min_score:.2}, dry_run={dry_run}; refused: {})",
                plan.refusal_summary(),
            );
            // `execute` is skipped, so hand the scanner its backoff here;
            // without it the same refusals were re-proposed every pass (css
            // 2026-09-25: 10 of 27 batches refused whole).
            if shared_scanner_config.read().engine == ScannerEngineMode::V2 {
                for candidate in plan.refusals_to_back_off() {
                    let Some(identity) = candidate.identity else {
                        continue;
                    };
                    let _ = index_feedback_tx.try_send(ScannerIndexFeedback {
                        identity: IndexedIdentity::from(identity),
                        path: candidate.path.clone(),
                    });
                }
            }
            continue;
        }

        let scanner_config = shared_scanner_config.read().clone();
        // Markers always protect; the operator's patterns, as above, not for
        // a target-only batch.
        let protection = match ProtectionRegistry::new(Some(&operator_protected_paths)) {
            Ok(registry) => Mutex::new(registry),
            Err(err) => {
                eprintln!(
                    "[SBH-SAFETY] executor: protection registry init failed; skipping deletion batch: {err}"
                );
                logger.send(ActivityEvent::Error {
                    code: "SBH-1001".to_string(),
                    message: format!(
                        "executor: protection registry init failed; skipped deletion batch: {err}"
                    ),
                });
                continue;
            }
        };
        let sacred_paths =
            protection::sacred_paths_from_protected_patterns(&operator_protected_paths);
        let skip_protected = |path: &Path| {
            if shutdown.load(Ordering::Relaxed) {
                return Some(SkipReason::ShuttingDown);
            }
            // Runs once per candidate: a long batch keeps beating.
            heartbeat.beat();
            let mut protection = protection.lock();
            // A proved or unprovable (fail-closed) protection refusal.
            should_skip_protected_daemon_candidate(
                &mut protection,
                path,
                &sacred_paths,
                logger,
                "executor preflight",
            )
            .then_some(SkipReason::SacredStowaway)
        };

        // Regret labels (Q4): the entry identity (parent device and inode,
        // name) survives the deletion, so capture it now. Only removals for
        // good are watched: a quarantined entry is restorable and its
        // recreation is not a regret signal.
        let watch_identities: HashMap<PathBuf, EntryIdentity> = if plan.mode == DeletionMode::Unlink
        {
            plan.candidates
                .iter()
                .filter_map(|candidate| {
                    EntryIdentity::of(&candidate.path)
                        .map(|identity| (candidate.path.clone(), identity))
                })
                .collect()
        } else {
            HashMap::new()
        };

        let authorize_candidate = |candidate: &CandidacyScore| {
            // A batch planned as a dry-run cannot mutate and still owes its
            // preview counts. Real batches must obey newly restrictive policy.
            if !dry_run {
                // Renew the filesystem exception before the cheap live gates:
                // a large purity probe must not hide a policy change while it
                // runs or outlive a newly published compression hold.
                authorize_target_only_candidate(candidate, batch.target_only_root.as_deref())?;
                shared_config.authorize_mutation(policy_mode, policy_engine.lock().mode())?;
                shared_config.authorize_compression_first(candidate, batch.pressure_level)?;
            }
            regret.authorize_deletion(candidate, logger)
        };
        let on_unlinked = |candidate: &CandidacyScore, completed_at: Instant| {
            if let Some(identity) = watch_identities.get(&candidate.path) {
                regret.watch_unlinked(candidate, identity, completed_at);
            }
        };
        let report = executor.execute_with_hooks(
            &plan,
            Some(&skip_protected),
            Some(&authorize_candidate),
            Some(&on_unlinked),
        );

        if scanner_config.engine == ScannerEngineMode::V2 {
            for candidate in &report.backoff_candidates {
                let Some(identity) = candidate.identity else {
                    continue;
                };
                let _ = index_feedback_tx.try_send(ScannerIndexFeedback {
                    identity: IndexedIdentity::from(identity),
                    path: candidate.path.clone(),
                });
            }
        }

        // If preflight failed any candidates with NotWritable, the daemon's
        // sandbox doesn't include those paths. This is almost always a
        // misconfigured systemd unit (ProtectSystem=strict + a stale
        // ReadWritePaths whitelist). Surface a single actionable warning
        // per hour rather than silently piling up [SBH-EXECUTOR] skip lines
        // that the operator has no way to interpret. Without this signal,
        // sbh appears to "do nothing" while disks fill — exactly the
        // failure mode that hit ts1 on 2026-04-30.
        if !report.not_writable_paths.is_empty() {
            let should_warn =
                last_not_writable_warning.is_none_or(|t| t.elapsed() >= Duration::from_hours(1));
            if should_warn {
                last_not_writable_warning = Some(Instant::now());
                let example = report
                    .not_writable_paths
                    .first()
                    .map_or_else(String::new, |p| p.display().to_string());
                eprintln!(
                    "[SBH-CONFIG-WARNING] {} candidate(s) skipped this batch \
                     because the daemon cannot write to their parent directory \
                     (e.g. {example}). This usually means the systemd unit's \
                     ReadWritePaths= list does not include the parent mount. \
                     Re-run `sudo sbh install --systemd --auto` to regenerate \
                     the unit from the current scanner.root_paths config (or \
                     `sbh install --systemd --user --auto` for user scope), \
                     or edit the unit and remove ProtectSystem=strict, then \
                     `systemctl daemon-reload && systemctl restart sbh`.",
                    report.not_writable_paths.len(),
                );
                logger.send(ActivityEvent::Error {
                    code: "SBH-CONFIG-NOTWRITABLE".to_string(),
                    message: format!(
                        "{} skip(s) due to ReadWritePaths sandbox; first={example}",
                        report.not_writable_paths.len(),
                    ),
                });
            }
        }

        // Canary budget counts executed deletions, not approvals.
        if !report.dry_run {
            policy_engine
                .lock()
                .note_executed_deletions(report.deleted_paths.len());
        }

        // Record deletions for repeat-deletion dampening.
        tracker.record_deletions(&report.deleted_paths);
        if !report.dry_run && report.items_deleted > 0 {
            shared_config.note_reclaim();
        }

        if report.dry_run {
            if report.items_would_delete > 0 || report.items_failed > 0 {
                eprintln!(
                    "[SBH-EXECUTOR] dry-run would_delete={} failed={} skipped={} would_free={}B ({:?})",
                    report.items_would_delete,
                    report.items_failed,
                    report.items_skipped,
                    report.bytes_would_free,
                    report.duration,
                );
            }
        } else if report.items_deleted > 0 || report.items_failed > 0 {
            eprintln!(
                "[SBH-EXECUTOR] deleted={} failed={} skipped={} freed={}B observed_freed={} sacred_scans={} sacred_ms={} ({:?}) freed_at_commit={}B{}",
                report.items_deleted,
                report.items_failed,
                report.items_skipped,
                report.bytes_freed,
                report
                    .bytes_freed_observed
                    .map_or_else(|| "unknown".to_string(), |bytes| format!("{bytes}B")),
                report.sacred_scans,
                report.sacred_scan_ms,
                report.duration,
                report.bytes_freed_at_commit,
                if report.freed_at_commit_on_btrfs {
                    " (btrfs: upper bound)"
                } else {
                    ""
                },
            );
        }

        // A read-only mount is an incident for the mount controller, not a
        // sandbox misconfiguration: say so once per batch and hand the paths
        // to the main loop, which parks the mount in recovery.
        if !report.read_only_paths.is_empty() || !report.no_space_paths.is_empty() {
            eprintln!(
                "[SBH-EXECUTOR] mount needs recovery: read_only={} no_space={} (first: {})",
                report.read_only_paths.len(),
                report.no_space_paths.len(),
                report
                    .recovery_paths()
                    .next()
                    .map_or_else(String::new, |p| p.display().to_string()),
            );
        }

        // Q8: feed the failure monitor. Safety refusals are not failures;
        // delete errors and mount incidents are.
        if !report.dry_run {
            for _ in 0..report.items_deleted {
                failure_monitor.observe_success();
            }
            for _ in 0..report.read_only_paths.len() {
                failure_monitor.observe_failure(
                    crate::scanner::deletion::SkipReason::FilesystemReadOnly.as_str(),
                );
            }
            for _ in 0..report.no_space_paths.len() {
                failure_monitor.observe_failure("no_space");
            }
            let plain_errors = report
                .items_failed
                .saturating_sub(report.no_space_paths.len())
                .saturating_sub(
                    report
                        .errors
                        .iter()
                        .filter(|e| report.read_only_paths.contains(&e.path))
                        .count(),
                );
            for _ in 0..plain_errors {
                failure_monitor.observe_failure("delete_error");
            }
        }
        let failure_alarm = if failure_monitor.alarm() && !failure_alarm_raised {
            failure_alarm_raised = true;
            let dominant = failure_monitor.dominant_reason();
            let (successes, failures) = failure_monitor.counts();
            eprintln!(
                "[SBH-EXECUTOR] deletion failure alarm: evidence={:.1} successes={successes} failures={failures} dominant={:?}",
                failure_monitor.evidence(),
                dominant,
            );
            dominant
        } else {
            if !failure_monitor.alarm() {
                failure_alarm_raised = false;
            }
            None
        };

        // Report deletion stats back to main loop for SelfMonitor counters.
        // What the filesystem gained where every removal was measured and it
        // frees blocks at once; the scanner's estimate (a lower bound for
        // truncated probes, or a 100 MiB floor) where it frees them at commit
        // or a removal could not be measured, marked as such (bd-oj33).
        let (bytes_freed, freed_basis) = report.reported_freed();
        let _ = report_tx.try_send(WorkerReport::DeletionCompleted {
            deleted: report.items_deleted as u64,
            bytes_freed,
            freed_basis,
            bytes_freed_observed: report.bytes_freed_observed,
            failed: report.items_failed as u64,
            recovery_paths: report.recovery_paths().cloned().collect(),
            failure_alarm,
        });

        if report.circuit_breaker_tripped {
            last_circuit_breaker_trip = Some(Instant::now());
            // Exponential backoff: double cooldown on each consecutive trip,
            // capped at max. Reset to base on successful batch (below).
            // Double BEFORE logging so the logged value matches what's enforced.
            circuit_breaker_cooldown =
                (circuit_breaker_cooldown * 2).min(max_circuit_breaker_cooldown);
            logger.send(ActivityEvent::Error {
                code: "SBH-2003".to_string(),
                message: format!(
                    "executor circuit breaker tripped, cooldown {:.0}s (exponential backoff)",
                    circuit_breaker_cooldown.as_secs_f64(),
                ),
            });
        } else if report.items_deleted > 0 {
            // Successful deletion — reset exponential backoff to base.
            circuit_breaker_cooldown = base_circuit_breaker_cooldown;
        }

        // Periodic pruning of expired dampening entries.
        if batch_count.is_multiple_of(10) {
            tracker.prune_expired();
        }
    }
}

// ──────────────────── tests ────────────────────

/// bd-ffjj: whether the logging mount's RAM headroom is due for a re-check at
/// an unchanged level. Only while pressured, and at most every
/// [`LOGGING_RAM_RECHECK`].
fn logging_ram_recheck_due(pressured: bool, last_check: Option<Instant>, now: Instant) -> bool {
    pressured
        && last_check.is_none_or(|at| now.saturating_duration_since(at) >= LOGGING_RAM_RECHECK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::Config;
    use crate::daemon::policy::NotificationPriority;
    use crate::monitor::pid::PressureLevel;
    use crate::monitor::special_locations::{
        SpecialKind, SpecialLocation, SpecialLocationRegistry,
    };
    use crate::platform::pal::{MemoryInfo, MockPlatform};
    use crate::platform::types::PalError;
    use crate::scanner::patterns::{ArtifactCategory, ArtifactClassification};
    use crate::scanner::scoring::{DecisionAction, DecisionOutcome, EvidenceLedger, ScoreFactors};
    use std::path::Path;
    use std::time::Duration;

    /// An initialized daemon with all writes under a temporary directory
    /// and platform observations supplied by the regular mock PAL. No
    /// monitoring, scanner, or executor thread is started.
    #[cfg(unix)]
    struct RegretDaemonFixture {
        daemon: MonitoringDaemon,
        directory: tempfile::TempDir,
    }

    #[cfg(unix)]
    impl RegretDaemonFixture {
        fn new() -> Self {
            use crate::core::config::PathsConfig;
            use crate::platform::types::{OpenFile, OpenFileKind, OpenFileMode};

            let directory = tempfile::tempdir().unwrap();
            let root = directory.path();
            let paths = PathsConfig {
                config_file: root.join("config.toml"),
                ballast_dir: root.join("ballast"),
                state_file: root.join("state.json"),
                sqlite_db: root.join("activity.sqlite3"),
                jsonl_log: root.join("activity.jsonl"),
            };
            let mut config = Config::with_paths(paths);
            let project = root.join("project");
            std::fs::create_dir(&project).unwrap();
            config.scanner.root_paths = vec![project.clone()];
            config.ballast.auto_provision = false;
            config.scoring.regret_window_minutes = 1;
            let platform = MockPlatform::healthy()
                .with_home(root)
                .with_temp_dirs(Vec::new())
                .with_cache_roots(Vec::new())
                .with_open_file(OpenFile {
                    pid: 42,
                    path: project.join("Cargo.toml"),
                    fd: Some(3),
                    kind: OpenFileKind::Regular,
                    mode: OpenFileMode::Read,
                });
            let daemon = MonitoringDaemon::init_with_platform(
                config,
                &DaemonArgs::default(),
                Arc::new(platform),
            )
            .unwrap();
            Self { daemon, directory }
        }

        fn flush_logger(&mut self) {
            self.daemon.logger_handle.shutdown();
            if let Some(logger) = self.daemon.logger_join.take() {
                logger.join().unwrap();
            }
        }
    }

    #[cfg(unix)]
    impl Drop for RegretDaemonFixture {
        fn drop(&mut self) {
            self.daemon.logger_handle.shutdown();
            if let Some(logger) = self.daemon.logger_join.take() {
                let _ = logger.join();
            }
        }
    }

    #[cfg(unix)]
    fn quarantine_tick(level: PressureLevel, mount: &Path) -> MountTickResponse {
        MountTickResponse {
            response: crate::monitor::pid::PressureResponse {
                level,
                urgency: 0.7,
                scan_interval: Duration::from_secs(1),
                release_ballast_files: 0,
                max_delete_batch: 10,
                fallback_active: false,
                causing_mount: mount.to_path_buf(),
                free_pct: 12.0,
                predicted_seconds: None,
            },
            seconds_to_red: None,
            prediction_confident: false,
            rate: MountRateState::default(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_sweeps_preserve_payloads_in_observe_fallback_and_dry_run() {
        use crate::daemon::policy::PolicyConfig;

        for level in [
            PressureLevel::Green,
            PressureLevel::Orange,
            PressureLevel::Critical,
        ] {
            let mut fixture = RegretDaemonFixture::new();
            let root = fixture.directory.path().join("project");
            let candidate = root.join("target");
            std::fs::create_dir(&candidate).unwrap();
            std::fs::write(candidate.join("artifact.o"), b"recoverable").unwrap();
            let store = QuarantineStore::under(&root);
            let record = store
                .quarantine(&candidate, "held", 11, Duration::ZERO, None)
                .unwrap();
            let mount = PathBuf::from("/");
            let roots = vec![(root, Some(mount.clone()))];
            let ticks = vec![quarantine_tick(level, &mount)];
            for (mode, dry_run) in [
                (ActiveMode::Observe, false),
                (ActiveMode::FallbackSafe, false),
                (ActiveMode::Enforce, true),
            ] {
                let daemon = &mut fixture.daemon;
                *daemon.policy_engine.lock() = PolicyEngine::new(PolicyConfig {
                    initial_mode: mode,
                    ..PolicyConfig::default()
                });
                daemon.config.scanner.dry_run = dry_run;
                daemon.sweep_quarantines(&ticks, &roots, Instant::now());
                assert_eq!(
                    std::fs::read(record.quarantine_path.join("artifact.o")).unwrap(),
                    b"recoverable",
                    "{level:?} {mode:?} dry_run={dry_run}",
                );
                assert!(store.record("held").unwrap().is_some());
                assert_eq!(daemon.quarantine_held.get(&mount), Some(&11));
                assert!(daemon.last_quarantine_sweep.is_none());
            }

            // Positive control: the expired same entry is purged immediately
            // when live policy permits it, including maintenance at Green.
            let daemon = &mut fixture.daemon;
            daemon.config.scanner.dry_run = false;
            daemon.sweep_quarantines(&ticks, &roots, Instant::now());
            assert!(!record.quarantine_path.exists());
            assert!(store.record("held").unwrap().is_none());
            assert_eq!(daemon.quarantine_held.get(&mount), Some(&0));
            assert!(daemon.last_quarantine_sweep.is_some());
        }
    }

    #[cfg(unix)]
    #[test]
    fn executor_live_policy_stops_a_previously_approved_batch_without_backoff() {
        use crate::daemon::policy::PolicyConfig;

        for (mode, dry_run) in [
            (ActiveMode::Observe, false),
            (ActiveMode::FallbackSafe, false),
            (ActiveMode::Canary, false),
            (ActiveMode::Enforce, true),
        ] {
            let fixture = RegretDaemonFixture::new();
            let candidates_dir = tempfile::tempdir_in("/tmp").unwrap();
            let project = candidates_dir.path().join("project");
            std::fs::create_dir(&project).unwrap();
            let first = project.join("target");
            let held = project.join("node_modules");
            let mut candidates = Vec::new();
            for (path, score) in [(&first, 2.0), (&held, 1.0)] {
                std::fs::create_dir(path).unwrap();
                std::fs::write(path.join("artifact.o"), [7_u8; 16]).unwrap();
                let mut candidate = test_candidate(&path.to_string_lossy(), score);
                candidate.identity =
                    Some(crate::scanner::walker::identity_for_path(path, false).unwrap());
                candidate.size_bytes = 16;
                candidates.push(candidate);
            }
            let executor = DeletionExecutor::new(
                DeletionConfig {
                    dry_run: false,
                    min_score: 0.0,
                    check_open_files: true,
                    require_identity: true,
                    ..Default::default()
                },
                Some(fixture.daemon.logger_handle.clone()),
            )
            .with_platform(Arc::clone(&fixture.daemon.platform));
            let plan = executor.plan(candidates);
            assert_eq!(plan.candidates.len(), 2);
            let shared = &fixture.daemon.shared_executor_config;
            let policy = &fixture.daemon.policy_engine;
            let authorize = |_candidate: &CandidacyScore| {
                // Previously approved work must obey a live operator pause
                // or fallback before its next mutation.
                shared.authorize_mutation(ActiveMode::Enforce, policy.lock().mode())
            };
            let pause_after_unlink = |candidate: &CandidacyScore, _: Instant| {
                assert_eq!(candidate.path, first);
                assert!(!first.exists());
                *policy.lock() = PolicyEngine::new(PolicyConfig {
                    initial_mode: mode,
                    ..PolicyConfig::default()
                });
                shared.dry_run.store(dry_run, Ordering::Relaxed);
            };
            let report = executor.execute_with_hooks(
                &plan,
                None,
                Some(&authorize),
                Some(&pause_after_unlink),
            );
            assert_eq!(report.deleted_paths, vec![first.clone()]);
            assert_eq!(report.skipped_by_reason.get("policy_changed"), Some(&1));
            assert_eq!(report.items_failed, 0);
            assert!(report.backoff_candidates.is_empty());
            assert_eq!(std::fs::read(held.join("artifact.o")).unwrap(), [7_u8; 16]);

            *policy.lock() = PolicyEngine::new(PolicyConfig {
                initial_mode: ActiveMode::Enforce,
                ..PolicyConfig::default()
            });
            shared.dry_run.store(false, Ordering::Relaxed);
            let retry = executor.plan(vec![plan.candidates[1].clone()]);
            let released = executor.execute_with_guard(&retry, None, Some(&authorize));
            assert_eq!(released.items_deleted, 1, "{mode:?} dry_run={dry_run}");
            assert!(!held.exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_waits_for_lossless_first_chance_but_never_for_emergency() {
        use crate::daemon::compress_tier::RootStatus;

        let mut fixture = RegretDaemonFixture::new();
        let root = fixture.directory.path().join("project");
        let candidate = root.join("target");
        std::fs::create_dir(&candidate).unwrap();
        std::fs::write(candidate.join("artifact.o"), b"recoverable").unwrap();
        let store = QuarantineStore::under(&root);
        let record = store
            .quarantine(&candidate, "held", 11, Duration::from_hours(24), None)
            .unwrap();
        let mount = PathBuf::from("/");
        fixture
            .daemon
            .shared_executor_config
            .compression_first
            .begin(
                &[RootStatus {
                    root: root.clone(),
                    btrfs: true,
                    level: Some(PressureLevel::Orange),
                    mount_point: Some(mount.clone()),
                    device_id: Some(record.device_id),
                }],
                &[],
                Instant::now(),
                Duration::from_secs(30),
            );
        let roots = vec![(root, Some(mount.clone()))];
        fixture.daemon.sweep_quarantines(
            &[quarantine_tick(PressureLevel::Orange, &mount)],
            &roots,
            Instant::now(),
        );
        assert_eq!(
            std::fs::read(record.quarantine_path.join("artifact.o")).unwrap(),
            b"recoverable",
        );
        assert_eq!(fixture.daemon.quarantine_held.get(&mount), Some(&11));
        assert_eq!(fixture.daemon.last_quarantine_sweep, None);
        fixture.daemon.sweep_quarantines(
            &[quarantine_tick(PressureLevel::Critical, &mount)],
            &roots,
            Instant::now(),
        );
        assert!(!record.quarantine_path.exists());
        assert_eq!(fixture.daemon.quarantine_held.get(&mount), Some(&0));
        assert!(fixture.daemon.last_quarantine_sweep.is_some());
    }

    #[cfg(unix)]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn emergency_cleanup_dispatch_precedes_compression_root_probes() {
        use crate::platform::pal::{
            FsStats, MemoryInfo, MountPoint, PlatformPaths, ServiceManager,
        };
        use std::sync::atomic::AtomicUsize;

        struct ProbeAfterEmergency {
            base: Arc<dyn Platform>,
            probe_root: PathBuf,
            scan_root: PathBuf,
            quarantine_path: PathBuf,
            scans: Receiver<ScanRequest>,
            probes: Arc<AtomicUsize>,
        }

        impl Platform for ProbeAfterEmergency {
            fn fs_stats(&self, path: &Path) -> crate::core::errors::Result<FsStats> {
                if path == self.probe_root.as_path() {
                    assert!(
                        !self.quarantine_path.exists(),
                        "emergency quarantine must drain before compression root I/O",
                    );
                    let scan = self
                        .scans
                        .try_recv()
                        .expect("emergency scan must be queued before compression root I/O");
                    assert_eq!(scan.pressure_level, PressureLevel::Critical);
                    assert!(scan.paths.contains(&self.scan_root));
                    self.probes.fetch_add(1, Ordering::Relaxed);
                }
                let mut stats = self.base.fs_stats(path)?;
                // Exercise startup admission without launching a native worker.
                stats.fs_type = "ext4".into();
                Ok(stats)
            }

            fn mount_points(&self) -> crate::core::errors::Result<Vec<MountPoint>> {
                self.base.mount_points()
            }

            fn is_ram_backed(&self, path: &Path) -> crate::core::errors::Result<bool> {
                self.base.is_ram_backed(path)
            }

            fn default_paths(&self) -> PlatformPaths {
                self.base.default_paths()
            }

            fn memory_info(&self) -> crate::core::errors::Result<MemoryInfo> {
                self.base.memory_info()
            }

            fn service_manager(&self) -> Box<dyn ServiceManager> {
                self.base.service_manager()
            }
        }

        let mut fixture = RegretDaemonFixture::new();
        let root = fixture.directory.path().join("project");
        let candidate = root.join("target");
        std::fs::create_dir(&candidate).unwrap();
        std::fs::write(candidate.join("artifact.o"), b"recoverable").unwrap();
        let store = QuarantineStore::under(&root);
        let record = store
            .quarantine(&candidate, "held", 11, Duration::from_hours(24), None)
            .unwrap();
        assert!(record.quarantine_path.exists());
        let probe_root = fixture.directory.path().join("compression-probe");
        std::fs::create_dir(&probe_root).unwrap();
        let (scan_tx, scan_rx) = bounded::<ScanRequest>(4);
        let (del_tx, _del_rx) = bounded::<DeletionBatch>(4);
        let probes = Arc::new(AtomicUsize::new(0));
        let daemon = &mut fixture.daemon;
        daemon.config.compress.enabled = true;
        daemon.config.compress.start_level = "critical".into();
        daemon.config.compress.roots = vec![probe_root.clone()];
        // A fake "/" mount can discover foreign ballast. Disable ballast
        // actions explicitly while retaining real emergency scan dispatch.
        daemon.behavior_state.mode = mock_behavior_mode(
            ScanAggressiveness::Aggressive,
            CleanupAction::AnyDefiniteCandidate,
            BallastAction::None,
            NotificationPriority::Low,
        );
        // Keep the collector's original mock; only compression's direct root
        // probe observes the queue, after ordinary monitor stats collection.
        daemon.platform = Arc::new(ProbeAfterEmergency {
            base: Arc::clone(&daemon.platform),
            probe_root,
            scan_root: root,
            quarantine_path: record.quarantine_path.clone(),
            scans: scan_rx.clone(),
            probes: Arc::clone(&probes),
        });
        let tick = quarantine_tick(PressureLevel::Critical, Path::new("/"));
        let response = tick.response.clone();
        daemon.mount_responses = vec![tick];

        daemon.handle_pressure(&response, &scan_tx, &scan_rx, &del_tx);

        assert_eq!(
            probes.load(Ordering::Relaxed),
            1,
            "Critical start levels must still reach compression admission",
        );
        assert!(!record.quarantine_path.exists());
        assert!(store.record("held").unwrap().is_none());
    }

    /// A special-location alert episode notifies once when it starts and again
    /// only when it escalates; a level that wobbles inside it stays quiet, and
    /// the episode ends only after a whole alert interval without an alert.
    #[test]
    fn special_location_episodes_notify_on_start_and_escalation_only() {
        let t0 = Instant::now();
        let interval = Duration::from_mins(15);

        assert_eq!(
            special_episode_step(None, PressureLevel::Yellow),
            (Some(PressureLevel::Green), PressureLevel::Yellow)
        );
        let yellow = Some((PressureLevel::Yellow, t0));
        assert_eq!(
            special_episode_step(yellow, PressureLevel::Yellow),
            (None, PressureLevel::Yellow)
        );
        assert_eq!(
            special_episode_step(yellow, PressureLevel::Orange),
            (Some(PressureLevel::Yellow), PressureLevel::Orange)
        );
        // Back down to Yellow inside an Orange episode: quiet, Orange is kept.
        let orange = Some((PressureLevel::Orange, t0));
        assert_eq!(
            special_episode_step(orange, PressureLevel::Yellow),
            (None, PressureLevel::Orange)
        );

        assert!(special_episode_over(None, t0, interval));
        assert!(!special_episode_over(
            orange,
            t0 + Duration::from_mins(5),
            interval
        ));
        assert!(special_episode_over(orange, t0 + interval, interval));
    }

    /// A special location under pressure queues a scan but releases no
    /// ballast. Its own mount releases on its own pressure level; before, an
    /// Orange "filling fast" alert on a disk-backed /tmp released the whole
    /// pool on every write burst, so a macOS Data volume never kept a reserve.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn special_location_alert_scans_but_never_releases_ballast() {
        use crate::core::config::PathsConfig;
        use crate::monitor::special_locations::{
            SpecialKind, SpecialLocation, SpecialLocationRegistry,
        };
        use crate::platform::pal::{FsStats, MemoryInfo, MountPoint, PlatformPaths};

        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let paths = PathsConfig {
            config_file: root.join("config.toml"),
            ballast_dir: root.join("ballast"),
            state_file: root.join("state.json"),
            sqlite_db: root.join("activity.sqlite3"),
            jsonl_log: root.join("activity.jsonl"),
        };
        let mut config = Config::with_paths(paths);
        let tmp = root.join("tmp");
        std::fs::create_dir(&tmp).unwrap();
        config.scanner.root_paths = vec![tmp.clone()];
        config.ballast.auto_provision = false;
        config.ballast.file_count = 2;
        config.ballast.file_size_bytes = 8192;
        config.notifications.enabled = false;

        // 1 TB volume with 10 GB available: under the special-location floor.
        let mount = PathBuf::from("/");
        let stats = FsStats {
            total_bytes: 1_000_000_000_000,
            free_bytes: 10_000_000_000,
            available_bytes: 10_000_000_000,
            fs_type: "mockfs".to_string(),
            mount_point: mount.clone(),
            is_readonly: false,
        };
        let mut platform = MockPlatform::new(
            vec![MountPoint {
                path: mount.clone(),
                device: "mockdev".to_string(),
                fs_type: "mockfs".to_string(),
                is_ram_backed: false,
            }],
            HashMap::from([(mount.clone(), stats)]),
            MemoryInfo {
                total_bytes: 64 << 30,
                available_bytes: 32 << 30,
                swap_total_bytes: 0,
                swap_free_bytes: 0,
            },
            PlatformPaths::default(),
        )
        .with_home(root)
        .with_temp_dirs(Vec::new())
        .with_cache_roots(Vec::new());
        // MockPlatform reports no blocks unless told: 8192-byte files are 16.
        for index in 1..=2 {
            platform = platform.with_block_count(
                root.join("ballast")
                    .join(format!("SBH_BALLAST_FILE_{index:05}.dat")),
                16,
            );
        }
        let platform = Arc::new(platform);
        let mut daemon = MonitoringDaemon::init_with_platform(
            config,
            &DaemonArgs::default(),
            Arc::clone(&platform) as Arc<dyn Platform>,
        )
        .unwrap();
        // What the daemon itself counts as releasable on this mount, stranded
        // files included: release_ballast spends those first.
        let available = |daemon: &MonitoringDaemon| {
            daemon
                .ballast_coordinator
                .pool_for_mount(&mount)
                .map_or(0, crate::ballast::coordinator::BallastPool::available_count)
        };
        // The mock mount is "/", and stranded-reserve discovery reads the real
        // legacy locations (/root, /home/*, /Users/*, /var/lib/sbh) on that
        // device. A host with a reserve there would put real files in this
        // pool, and the control below would release them. Skip on such a host.
        let foreign = available(&daemon);
        if foreign > 0 {
            eprintln!(
                "skipped: {foreign} ballast file(s) from a real reserve on this device are visible to the fixture's pool"
            );
            daemon.logger_handle.shutdown();
            if let Some(logger) = daemon.logger_join.take() {
                logger.join().unwrap();
            }
            return;
        }
        daemon.ballast_coordinator.set_provision_floor(0.0);
        let provisioned = daemon
            .ballast_coordinator
            .provision_all(platform.as_ref())
            .unwrap();
        assert_eq!(provisioned.total_files_created(), 2, "{provisioned:?}");
        assert_eq!(available(&daemon), 2);

        daemon.special_locations = SpecialLocationRegistry::new(vec![SpecialLocation {
            path: tmp.clone(),
            kind: SpecialKind::UserTmp,
            buffer_pct: 15,
            scan_interval: Duration::from_secs(5),
            priority: 160,
        }]);
        // Filling fast: 10 GB at 100 MB/s is 100 s from full, urgency ~0.94,
        // which the release controller answers with every file in the pool.
        daemon.mount_rates.insert(mount.clone(), 100_000_000.0);
        let (scan_tx, scan_rx) = crossbeam_channel::bounded(4);
        daemon.check_special_locations(&scan_tx, &scan_rx);

        assert_eq!(
            available(&daemon),
            2,
            "a special-location alert must not release ballast"
        );
        let request = scan_rx.try_recv().expect("the alert still queues a scan");
        assert_eq!(request.pressure_level, PressureLevel::Orange);
        assert!(request.paths.contains(&tmp), "{:?}", request.paths);

        // Control: the call this path used to make, with the alert's Orange
        // response at urgency ~0.94, empties this very pool, so the kept files
        // above are not an artifact of the fixture.
        let old_alert_response = crate::monitor::pid::PressureResponse {
            level: PressureLevel::Orange,
            urgency: 0.94,
            scan_interval: Duration::from_secs(0),
            release_ballast_files: 0,
            max_delete_batch: 60,
            fallback_active: false,
            causing_mount: mount.clone(),
            free_pct: 1.0,
            predicted_seconds: None,
        };
        assert_eq!(
            daemon.release_ballast(&mount, &old_alert_response).unwrap(),
            2
        );
        assert_eq!(available(&daemon), 0);

        daemon.logger_handle.shutdown();
        if let Some(logger) = daemon.logger_join.take() {
            logger.join().unwrap();
        }
    }

    #[cfg(unix)]
    fn regret_watch_for_test(id: &str, path: &Path, category: &str, now: Instant) -> Watch {
        Watch {
            decision_id: id.to_string(),
            path: path.to_path_buf(),
            identity: EntryIdentity::of(path).unwrap(),
            category: category.to_string(),
            certainty: ArtifactCertainty::Definite,
            deleted_at: now,
        }
    }

    #[cfg(unix)]
    #[test]
    fn daemon_regret_observation_keeps_failed_and_replaced_parents_out_of_evidence() {
        let mut fixture = RegretDaemonFixture::new();
        let root = fixture.directory.path();
        let live = root.join("project/target");
        let absent = root.join("project/absent");
        let replaced_parent = root.join("replaced");
        let unreadable_parent = root.join("unreadable");
        std::fs::create_dir(&replaced_parent).unwrap();
        std::fs::create_dir(&unreadable_parent).unwrap();
        let replaced = replaced_parent.join("target");
        let unreadable = unreadable_parent.join("target");
        let now = Instant::now();
        for (id, path, category) in [
            ("live", &live, "live"),
            ("absent", &absent, "absent"),
            ("replaced", &replaced, "unknown"),
            ("unreadable", &unreadable, "unknown"),
        ] {
            fixture
                .daemon
                .regret
                .detector
                .lock()
                .watch(regret_watch_for_test(id, path, category, now));
        }
        std::fs::create_dir(&live).unwrap();
        std::fs::rename(&replaced_parent, root.join("original-replaced")).unwrap();
        std::fs::create_dir(&replaced_parent).unwrap();
        std::fs::rename(&unreadable_parent, root.join("original-unreadable")).unwrap();
        std::fs::write(&unreadable_parent, b"parent is no longer a directory").unwrap();

        fixture
            .daemon
            .resolve_regrets_with_clock(|| now + Duration::from_secs(30));
        assert_eq!(fixture.daemon.regret.detector.lock().pending(), 3);
        assert_eq!(
            fixture
                .daemon
                .regret
                .calibrator
                .lock()
                .summary("live")
                .unwrap()
                .regrets,
            1
        );
        assert!(
            fixture
                .daemon
                .regret
                .calibrator
                .lock()
                .summary("unknown")
                .is_none()
        );

        fixture
            .daemon
            .resolve_regrets_with_clock(|| now + Duration::from_secs(60));
        assert_eq!(fixture.daemon.regret.detector.lock().pending(), 0);
        assert_eq!(
            fixture
                .daemon
                .regret
                .calibrator
                .lock()
                .summary("absent")
                .unwrap()
                .decisions,
            1
        );
        assert!(
            fixture
                .daemon
                .regret
                .calibrator
                .lock()
                .summary("unknown")
                .is_none()
        );
        fixture.flush_logger();
        let ledger = crate::logger::sqlite::SqliteLogger::open_read_only(
            &fixture.daemon.config.paths.sqlite_db,
        )
        .unwrap();
        for (id, expected) in [
            ("live", "regret"),
            ("absent", "clean"),
            ("replaced", "unknown"),
            ("unreadable", "unknown"),
        ] {
            let outcomes = ledger.outcomes_for_decision(id).unwrap();
            assert_eq!(outcomes.len(), 1, "{id}");
            assert_eq!(outcomes[0].outcome, expected, "{id}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn daemon_regret_observation_uses_completion_time_for_each_watched_path() {
        let mut fixture = RegretDaemonFixture::new();
        let now = Instant::now();
        let project = fixture.directory.path().join("project");
        for id in ["first", "later"] {
            let path = project.join(id);
            fixture
                .daemon
                .regret
                .detector
                .lock()
                .watch(regret_watch_for_test(id, &path, "timed", now));
            std::fs::create_dir(&path).unwrap();
        }
        // Each pair brackets a real filesystem/process observation. The
        // first begins before expiry but completes after it; the second
        // begins later still. The last two samples timestamp calibration.
        let mut seconds = [59, 61, 61, 63, 64, 65].into_iter();
        fixture.daemon.resolve_regrets_with_clock(|| {
            now + Duration::from_secs(seconds.next().expect("bounded clock samples"))
        });
        assert!(seconds.next().is_none());
        assert_eq!(fixture.daemon.regret.detector.lock().pending(), 0);
        assert!(
            fixture
                .daemon
                .regret
                .calibrator
                .lock()
                .summary("timed")
                .is_none()
        );
        fixture.flush_logger();
        let ledger = crate::logger::sqlite::SqliteLogger::open_read_only(
            &fixture.daemon.config.paths.sqlite_db,
        )
        .unwrap();
        for (id, after_secs) in [("first", 61), ("later", 63)] {
            let outcomes = ledger.outcomes_for_decision(id).unwrap();
            assert_eq!(outcomes.len(), 1);
            assert_eq!(outcomes[0].outcome, "unknown");
            assert_eq!(outcomes[0].after_secs, after_secs);
        }
    }

    #[cfg(unix)]
    #[test]
    fn daemon_regret_alarm_uses_fresh_calibration_time_for_its_full_suspension() {
        let fixture = RegretDaemonFixture::new();
        let now = Instant::now();
        let project = fixture.directory.path().join("project");
        let mut config = fixture.daemon.config.clone();
        config.scoring.regret_suspend_minutes = 1;
        fixture.daemon.regret.update_config(&config);
        for id in ["first", "second", "third"] {
            let path = project.join(id);
            fixture
                .daemon
                .regret
                .detector
                .lock()
                .watch(regret_watch_for_test(id, &path, "timed", now));
            std::fs::create_dir(&path).unwrap();
        }
        // All three recreations are observed inside the 60-second window.
        // Applying their evidence happens later, with the third raising the
        // alarm at +50s. Its 60-second suspension must last until +110s.
        let mut seconds = [1, 2, 3, 4, 5, 6, 40, 45, 50].into_iter();
        fixture.daemon.resolve_regrets_with_clock(|| {
            now + Duration::from_secs(seconds.next().expect("bounded clock samples"))
        });
        assert!(seconds.next().is_none());
        let calibrator = fixture.daemon.regret.calibrator.lock();
        let summary = calibrator.summary("timed").unwrap();
        assert_eq!(summary.decisions, 3);
        assert_eq!(summary.regrets, 3);
        assert!(calibrator.suspended("timed", now + Duration::from_secs(109)));
        assert!(!calibrator.suspended("timed", now + Duration::from_secs(110)));
        drop(calibrator);
    }

    #[cfg(unix)]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn daemon_config_reload_updates_regret_settings_and_preserves_pending_deadlines() {
        let mut fixture = RegretDaemonFixture::new();
        let now = Instant::now();
        let project = fixture.directory.path().join("project");
        let daemon = &mut fixture.daemon;
        daemon.regret.detector.lock().watch(regret_watch_for_test(
            "old-window",
            &project.join("old"),
            "old-window",
            now,
        ));
        {
            let mut calibrator = daemon.regret.calibrator.lock();
            calibrator.record(
                "definite",
                ArtifactCertainty::Definite,
                Outcome::Regret,
                now,
            );
            calibrator.record("likely", ArtifactCertainty::Likely, Outcome::Regret, now);
            for _ in 0..3 {
                calibrator.record(
                    "suspended",
                    ArtifactCertainty::Definite,
                    Outcome::Regret,
                    now,
                );
            }
        }
        let mut updated = daemon.config.clone();
        updated.scoring.regret_window_minutes = 3;
        updated.scoring.regret_alpha_definite = 0.04;
        updated.scoring.regret_alpha_likely = 0.01;
        updated.scoring.regret_suspend_minutes = 2;
        std::fs::write(
            &updated.paths.config_file,
            toml::to_string(&updated).unwrap(),
        )
        .unwrap();
        let (scan_tx, _scan_rx) = bounded(1);
        daemon.handle_config_reload(&scan_tx);
        assert!(daemon.wake_next_tick.reload);
        assert_eq!(daemon.config.scoring.regret_window_minutes, 3);
        {
            let calibrator = daemon.regret.calibrator.lock();
            assert_eq!(calibrator.config(), &regret_config(&updated));
            for (category, alpha, decisions) in [
                ("definite", 0.04, 1),
                ("likely", 0.01, 1),
                ("suspended", 0.04, 3),
            ] {
                let summary = calibrator.summary(category).unwrap();
                assert_eq!(summary.alpha, alpha);
                assert_eq!(summary.decisions, decisions);
                assert_eq!(summary.regrets, decisions);
                assert_eq!(summary.e_value, 1.0);
            }
            assert!(calibrator.suspended("suspended", now + Duration::from_mins(3)));
            drop(calibrator);
        }
        daemon.regret.detector.lock().watch(regret_watch_for_test(
            "new-window",
            &project.join("new"),
            "new-window",
            now,
        ));

        // A rejected reload must leave the live feedback settings and the
        // two existing watches untouched.
        std::fs::write(&updated.paths.config_file, "[scoring\n").unwrap();
        daemon.handle_config_reload(&scan_tx);
        assert_eq!(
            daemon.regret.calibrator.lock().config(),
            &regret_config(&updated)
        );
        assert_eq!(daemon.regret.detector.lock().pending(), 2);

        daemon.resolve_regrets_with_clock(|| now + Duration::from_secs(60));
        assert_eq!(daemon.regret.detector.lock().pending(), 1);
        assert_eq!(
            daemon
                .regret
                .calibrator
                .lock()
                .summary("old-window")
                .unwrap()
                .decisions,
            1
        );
        assert!(
            daemon
                .regret
                .calibrator
                .lock()
                .summary("new-window")
                .is_none()
        );
        daemon.resolve_regrets_with_clock(|| now + Duration::from_secs(180));
        assert_eq!(daemon.regret.detector.lock().pending(), 0);
        assert_eq!(
            daemon
                .regret
                .calibrator
                .lock()
                .summary("new-window")
                .unwrap()
                .decisions,
            1
        );
    }

    /// A fresh heartbeat for a `scanner_thread_main` test.
    fn heartbeat_for_test() -> Arc<ThreadHeartbeat> {
        ThreadHeartbeat::new("test-scanner")
    }

    /// The two on-disk scanner checkpoints a `scanner_thread_main` test
    /// needs: the v2 candidate index and the priority pre-scan's resume
    /// cursor.
    /// A scratch dir outside every temp root. Inside one every recognized
    /// artifact is `definite` by rule, which changes what a scanner test
    /// sees; `tempfile::tempdir()` is a temp root on a Mac (`$TMPDIR`) and a
    /// plain tempdir only on the rch workers (their `TMPDIR` is `.rch-tmp`).
    /// The cargo target directory is neither temp nor source, unless the
    /// build itself runs from a temp root, in which case the user cache
    /// directory stands in.
    fn non_temp_scratch_dir() -> tempfile::TempDir {
        let scratch_base = [
            std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from),
            Some(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target")),
            std::env::var_os("HOME")
                .map(|home| PathBuf::from(home).join(".cache").join("sbh-test-scratch")),
        ]
        .into_iter()
        .flatten()
        .find(|base| !crate::scanner::scoring::is_volatile_temp_path(base))
        .expect("a scratch base outside every temp root");
        std::fs::create_dir_all(&scratch_base).unwrap();
        tempfile::tempdir_in(&scratch_base).unwrap()
    }

    /// A scratch dir inside a temp root, wherever the runner's `TMPDIR`
    /// points: the counterpart of `non_temp_scratch_dir`. A scanner test whose
    /// fixture is an artifact only because it sits in temp storage must not
    /// inherit `TMPDIR`. The rch workers set it to `<project>/.rch-tmp`, a
    /// temp root only when the project was synced under `/data/tmp` and not
    /// when it runs from `/data/projects`, so the same test passed on one
    /// worker and failed every time on the next (#31).
    fn temp_root_scratch_dir() -> tempfile::TempDir {
        if is_tmp_like_path(&std::env::temp_dir()) {
            tempfile::tempdir().unwrap()
        } else {
            tempfile::tempdir_in("/tmp").unwrap()
        }
    }

    /// The `CACHEDIR.TAG` cargo writes into every target dir. Without it a
    /// fixture target has no structural evidence, and whether it scores
    /// `Delete` or `Review` then depends on where the test runs (it passed on
    /// the rch workers and failed natively on Linux and macOS, 2026-09-25).
    fn write_cargo_cachedir_tag(target: &Path) {
        std::fs::write(
            target.join("CACHEDIR.TAG"),
            "Signature: 8a477f597d28d172789f06886806bc55\n\
             # This file is a cache directory tag created by cargo.\n",
        )
        .unwrap();
    }

    /// bd-3rlm: a directory the walk recognises only by its CACHEDIR.TAG is
    /// not pruned and measured as an opaque tree, so it carried just its
    /// immediate files' size: on hz2 two candidates of 4 KiB each on paper
    /// freed 2.5 GB. The size the planner and the executor see is measured.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_walked_directory_candidate_is_measured_before_dispatch() {
        let temp = temp_root_scratch_dir();
        let root = temp.path().join("scan-root");
        let cache = root.join("srw");
        let deep = cache.join("a").join("b");
        std::fs::create_dir_all(&deep).unwrap();
        write_cargo_cachedir_tag(&cache);
        let payload = vec![7_u8; 512 * 1024];
        std::fs::write(deep.join("blob.bin"), &payload).unwrap();
        // Old enough to be abandoned by its real age.
        let old = SystemTime::now() - Duration::from_hours(6);
        for path in [
            deep.join("blob.bin"),
            cache.join("CACHEDIR.TAG"),
            deep.clone(),
            cache.join("a"),
            cache.clone(),
        ] {
            std::fs::File::open(&path)
                .unwrap()
                .set_modified(old)
                .unwrap();
        }

        let mut config = Config::default();
        config.scanner.root_paths = vec![root.clone()];
        config.scanner.min_file_age_minutes = 0;
        config.scanner.active_reference_min_size_bytes = u64::MAX;
        config.validate().expect("the tuned config stays valid");
        let (scanner_index_path, prescan_cursor_path) = scanner_state_paths(temp.path());
        let scoring = Arc::new(RwLock::new(config.scoring.clone()));
        let scanner_cfg = Arc::new(RwLock::new(config.scanner));
        let platform: Arc<dyn Platform> = Arc::new(MockPlatform::healthy());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (logger, logger_join) = spawn_logger(DualLoggerConfig {
            sqlite_path: None,
            jsonl_config: crate::logger::jsonl::JsonlConfig {
                path: temp.path().join("activity.jsonl"),
                fallback_path: None,
                max_size_bytes: 1_048_576,
                max_rotated_files: 0,
                fsync_interval_secs: 0,
            },
            channel_capacity: 1024,
            run_id: None,
        })
        .unwrap();
        let (scan_tx, scan_rx) = bounded::<ScanRequest>(1);
        let (del_tx, del_rx) = bounded::<DeletionBatch>(64);
        let (report_tx, _report_rx) = bounded::<WorkerReport>(64);
        let (_feedback_tx, feedback_rx) = bounded::<ScannerIndexFeedback>(1);
        scan_tx
            .send(ScanRequest {
                paths: vec![root],
                urgency: 0.9,
                pressure_level: PressureLevel::Orange,
                free_pct: Some(9.0),
                max_delete_batch: 10,
                force_full_scan: false,
                config_update: None,
                catalog_roots: Vec::new(),
                maintenance: false,
                target_bytes: None,
            })
            .unwrap();
        drop(scan_tx);
        scanner_thread_main(
            &scan_rx,
            &del_tx,
            &logger,
            &scoring,
            &scanner_cfg,
            &platform,
            &heartbeat_for_test(),
            &report_tx,
            &shutdown,
            &scanner_index_path,
            &prescan_cursor_path,
            &feedback_rx,
            &Arc::new(Mutex::new(CpuBudget::new(0, Instant::now(), 0.0))),
            &Arc::new(SharedExecutorConfig::new(
                false, 10, 0.0, 60, 3600, false, 0,
            )),
            &Arc::new(SharedRegret::new(&Config::default())),
        );
        logger.shutdown();
        logger_join.join().unwrap();

        let mut dispatched = Vec::new();
        while let Ok(batch) = del_rx.try_recv() {
            dispatched.extend(batch.candidates);
        }
        let candidate = dispatched
            .iter()
            .find(|candidate| candidate.path == cache)
            .unwrap_or_else(|| panic!("the tagged cache is dispatched: {dispatched:?}"));
        assert_eq!(
            candidate.classification.pattern_name, "cachedir-tagged-cache",
            "{candidate:?}"
        );
        assert!(
            candidate.size_bytes >= payload.len() as u64,
            "measured, not the directory's own entries: {} bytes",
            candidate.size_bytes
        );
    }

    /// A cache is probed for in-use evidence whatever its size. A small cache
    /// under a live build was approved because only candidates over
    /// `active_reference_min_size_bytes` (100 MiB) were probed; the same
    /// cache with nobody in it is still dispatched.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_small_cache_in_use_is_held_and_an_idle_one_is_dispatched() {
        let run = |busy: bool| -> Vec<PathBuf> {
            let temp = temp_root_scratch_dir();
            let root = temp.path().join("scan-root");
            let cache = root.join("srw");
            let deep = cache.join("a").join("b");
            std::fs::create_dir_all(&deep).unwrap();
            write_cargo_cachedir_tag(&cache);
            std::fs::write(deep.join("blob.bin"), vec![7_u8; 512 * 1024]).unwrap();
            let old = SystemTime::now() - Duration::from_hours(6);
            for path in [
                deep.join("blob.bin"),
                cache.join("CACHEDIR.TAG"),
                deep.clone(),
                cache.join("a"),
                cache.clone(),
            ] {
                std::fs::File::open(&path)
                    .unwrap()
                    .set_modified(old)
                    .unwrap();
            }
            let mut config = Config::default();
            config.scanner.root_paths = vec![root.clone()];
            config.scanner.min_file_age_minutes = 0;
            // The default size floor: the cache is far below it.
            assert!(config.scanner.active_reference_min_size_bytes > 512 * 1024);
            config.validate().expect("the tuned config stays valid");
            let (scanner_index_path, prescan_cursor_path) = scanner_state_paths(temp.path());
            let mut mock = MockPlatform::healthy();
            if busy {
                // rustc compiling from inside the cache, nothing held open.
                mock = mock.with_process(crate::platform::types::ProcessInfo {
                    pid: 4242,
                    parent_pid: None,
                    name: "rustc".to_string(),
                    command_line: Vec::new(),
                    executable: None,
                    cwd: Some(deep),
                    start_time_unix_ms: None,
                    virtual_memory_bytes: None,
                    resident_memory_bytes: None,
                    cpu_user_micros: None,
                    cpu_system_micros: None,
                });
            }
            let platform: Arc<dyn Platform> = Arc::new(mock);
            let (logger, logger_join) = spawn_logger(DualLoggerConfig {
                sqlite_path: None,
                jsonl_config: crate::logger::jsonl::JsonlConfig {
                    path: temp.path().join("activity.jsonl"),
                    fallback_path: None,
                    max_size_bytes: 1_048_576,
                    max_rotated_files: 0,
                    fsync_interval_secs: 0,
                },
                channel_capacity: 1024,
                run_id: None,
            })
            .unwrap();
            let (scan_tx, scan_rx) = bounded::<ScanRequest>(1);
            let (del_tx, del_rx) = bounded::<DeletionBatch>(64);
            let (report_tx, _report_rx) = bounded::<WorkerReport>(64);
            let (_feedback_tx, feedback_rx) = bounded::<ScannerIndexFeedback>(1);
            scan_tx
                .send(ScanRequest {
                    paths: vec![root],
                    urgency: 0.9,
                    pressure_level: PressureLevel::Orange,
                    free_pct: Some(9.0),
                    max_delete_batch: 10,
                    force_full_scan: false,
                    config_update: None,
                    catalog_roots: Vec::new(),
                    maintenance: false,
                    target_bytes: None,
                })
                .unwrap();
            drop(scan_tx);
            scanner_thread_main(
                &scan_rx,
                &del_tx,
                &logger,
                &Arc::new(RwLock::new(config.scoring.clone())),
                &Arc::new(RwLock::new(config.scanner)),
                &platform,
                &heartbeat_for_test(),
                &report_tx,
                &Arc::new(AtomicBool::new(false)),
                &scanner_index_path,
                &prescan_cursor_path,
                &feedback_rx,
                &Arc::new(Mutex::new(CpuBudget::new(0, Instant::now(), 0.0))),
                &Arc::new(SharedExecutorConfig::new(
                    false, 10, 0.0, 60, 3600, false, 0,
                )),
                &Arc::new(SharedRegret::new(&Config::default())),
            );
            logger.shutdown();
            logger_join.join().unwrap();
            let mut dispatched = Vec::new();
            while let Ok(batch) = del_rx.try_recv() {
                dispatched.extend(batch.candidates.into_iter().map(|c| c.path));
            }
            dispatched.retain(|path| path == &cache);
            dispatched
        };
        assert!(
            run(true).is_empty(),
            "a cache a live build works in is held"
        );
        assert_eq!(run(false).len(), 1, "an idle cache is still dispatched");
    }

    fn scanner_state_paths(dir: &Path) -> (PathBuf, PathBuf) {
        (
            dir.join("scanner-index-v2.json"),
            dir.join("prescan-cursor.json"),
        )
    }

    /// Persisted index records are hints: the replay must re-examine the
    /// path and refuse anything fresh evidence rejects, whatever score the
    /// checkpoint carried.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn index_replay_rescores_records_with_fresh_vetoes() {
        use crate::scanner::index::{
            CandidateIndexRecord, CandidateSafetyState, IndexedPruneDecision,
        };
        use crate::scanner::walker::identity_for_path;

        let temp = tempfile::tempdir().unwrap();
        let (logger, logger_join) = spawn_logger(DualLoggerConfig {
            sqlite_path: None,
            jsonl_config: crate::logger::jsonl::JsonlConfig {
                path: temp.path().join("activity.jsonl"),
                fallback_path: None,
                max_size_bytes: 1_048_576,
                max_rotated_files: 0,
                fsync_interval_secs: 0,
            },
            channel_capacity: 64,
            run_id: None,
        })
        .unwrap();

        let target = temp.path().join("proj").join("target");
        for sub in [
            "debug/deps",
            "debug/incremental",
            "debug/build",
            "debug/.fingerprint",
        ] {
            std::fs::create_dir_all(target.join(sub)).unwrap();
        }
        std::fs::write(target.join("debug/deps/libfoo.rlib"), vec![0u8; 8192]).unwrap();
        // Beside its manifest, as a project's target is: replay classifies
        // it as the walk does (bd-10yj), and the walk takes a target whole
        // there or under a temp root (TMPDIR may be neither).
        std::fs::write(
            temp.path().join("proj/Cargo.toml"),
            "[package]\nname = \"p\"\n",
        )
        .unwrap();

        let mut config = Config::default();
        config.scanner.min_file_age_minutes = 0;
        config.scanner.root_paths = vec![temp.path().to_path_buf()];
        let registry = ArtifactPatternRegistry::default();
        let engine = ScoringEngine::from_config(&config.scoring, 0);
        let mut protection =
            ProtectionRegistry::new(Some(&config.scanner.protected_paths)).unwrap();
        let sacred: Vec<crate::platform::types::SacredPath> = Vec::new();
        let open_files: HashSet<PathBuf> = HashSet::new();
        let request = ScanRequest {
            paths: vec![temp.path().to_path_buf()],
            urgency: 0.7,
            pressure_level: PressureLevel::Orange,
            free_pct: Some(8.0),
            max_delete_batch: 4,
            force_full_scan: false,
            config_update: None,
            catalog_roots: Vec::new(),
            maintenance: false,
            target_bytes: None,
        };
        let identity = identity_for_path(&target, false).unwrap();
        let record = |generation: u64| CandidateIndexRecord {
            path: target.clone(),
            identity: identity.into(),
            parent_identity: None,
            parent_mtime_nanos: None,
            candidate_mtime_nanos: 0,
            candidate_ctime_nanos: None,
            size_estimate_bytes: 200 * 1_048_576,
            prune_decision: IndexedPruneDecision::CandidateOpaque,
            score: Some(0.95),
            safety_state: CandidateSafetyState::Safe,
            fail_count: 0,
            cooldown_until_nanos: None,
            event_generation: generation,
            structural_signals: StructuralSignals::default(),
        };
        let replay = |record: &CandidateIndexRecord,
                      generation: u64,
                      protection: &mut ProtectionRegistry| {
            replay_indexed_record(
                record,
                generation,
                &registry,
                &engine,
                &config.scanner,
                &request,
                protection,
                &sacred,
                &open_files,
                None,
                &logger,
            )
        };

        // An intact artifact reaches the scoring layer: the verdict comes
        // from fresh evidence, not from the persisted 0.95.
        let verdict = replay(&record(3), 3, &mut protection);
        assert!(
            matches!(verdict, Ok(_) | Err(ReplayDrop::NotDelete(_))),
            "intact artifact is re-scored, not vetoed: {verdict:?}"
        );
        if let Ok(score) = &verdict {
            assert_eq!(score.identity, Some(identity));
            assert!(!score.vetoed);
        }

        // A stale generation is never trusted; the walker re-discovers it.
        assert_eq!(
            replay(&record(2), 3, &mut protection).unwrap_err(),
            ReplayDrop::GenerationAdvanced
        );

        // bd-1ouz: a daemon that cannot see every process vetoes the same
        // intact artifact; its references are unknown, not absent.
        let gap = crate::scanner::walker::MACOS_USER_SCOPE_ACTIVE_REFERENCE_WARNING;
        let blind = replay_indexed_record(
            &record(3),
            3,
            &registry,
            &engine,
            &config.scanner,
            &request,
            &mut protection,
            &sacred,
            &open_files,
            Some(gap),
            &logger,
        );
        assert_eq!(blind.unwrap_err(), ReplayDrop::Vetoed(gap.to_string()));

        // Planted after the checkpoint: a .git, then a Cargo.toml.
        std::fs::create_dir_all(target.join(".git")).unwrap();
        assert_eq!(
            replay(&record(3), 3, &mut protection).unwrap_err(),
            ReplayDrop::Vetoed("contains .git".to_string())
        );
        std::fs::remove_dir_all(target.join(".git")).unwrap();
        std::fs::write(target.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
        assert_eq!(
            replay(&record(3), 3, &mut protection).unwrap_err(),
            ReplayDrop::Vetoed("source tree markers".to_string())
        );
        std::fs::remove_file(target.join("Cargo.toml")).unwrap();

        // Same path, new inode: a recreated artifact is not the old decision.
        let stale = record(3);
        std::fs::rename(&target, temp.path().join("proj").join("target.old")).unwrap();
        std::fs::create_dir_all(target.join("debug").join("deps")).unwrap();
        assert_eq!(
            replay(&stale, 3, &mut protection).unwrap_err(),
            ReplayDrop::IdentityChanged
        );

        // Gone entirely.
        let missing = CandidateIndexRecord {
            path: temp.path().join("nope"),
            ..record(3)
        };
        assert_eq!(
            replay(&missing, 3, &mut protection).unwrap_err(),
            ReplayDrop::Missing
        );

        logger.shutdown();
        let _ = logger_join.join();
    }

    fn test_candidate(path: &str, total_score: f64) -> CandidacyScore {
        CandidacyScore {
            path: PathBuf::from(path),
            identity: None,
            total_score,
            factors: ScoreFactors {
                location: 0.0,
                name: 0.0,
                age: 0.0,
                size: 0.0,
                structure: 0.0,
                pressure_multiplier: 1.0,
            },
            vetoed: false,
            veto_reason: None,
            classification: ArtifactClassification::unknown(),
            size_bytes: 1,
            age: Duration::from_mins(1),
            decision: DecisionOutcome {
                action: DecisionAction::Delete,
                posterior_abandoned: 0.9,
                expected_loss_keep: 0.9,
                expected_loss_delete: 0.1,
                calibration_score: 1.0,
                fallback_active: false,
                certainty: crate::scanner::scoring::ArtifactCertainty::Definite,
                posterior_floor_applied: false,
                regret_calibration: 1.0,
                category_suspended: false,
            },
            ledger: EvidenceLedger {
                terms: Vec::new(),
                summary: "test".to_string(),
            },
        }
    }

    const fn test_self_monitor_tick(rss_bytes: u64, rss_warning_bytes: u64) -> SelfMonitorTick {
        SelfMonitorTick {
            rss_bytes,
            rss_warning_bytes,
            rss_hard_limit_bytes: u64::MAX,
            rss_hard_limit_exceeded: false,
            state_write_failed: false,
        }
    }

    #[test]
    fn adaptive_tick_throttle_requires_sustained_rss_pressure() {
        let mut throttle = AdaptiveTickThrottle::default();
        let requested = Duration::from_secs(15);
        let pressured_tick = test_self_monitor_tick(257 * 1024 * 1024, 256 * 1024 * 1024);

        let first = throttle.observe(requested, pressured_tick, Duration::from_millis(20));
        let second = throttle.observe(requested, pressured_tick, Duration::from_millis(20));
        let third = throttle.observe(requested, pressured_tick, Duration::from_millis(20));

        assert_eq!(first.stage, TickThrottleStage::Normal);
        assert_eq!(first.interval, requested);
        assert_eq!(second.stage, TickThrottleStage::Normal);
        assert_eq!(third.stage, TickThrottleStage::Backoff30s);
        assert_eq!(third.interval, Duration::from_secs(30));
        assert_eq!(third.reason, Some(TickThrottleReason::RssWarning));
        assert!(third.stage_changed);
    }

    #[test]
    fn adaptive_tick_throttle_escalates_on_slow_ticks_and_resets_when_clear() {
        let mut throttle = AdaptiveTickThrottle::default();
        let requested = Duration::from_secs(15);
        let healthy_tick = test_self_monitor_tick(128 * 1024 * 1024, 256 * 1024 * 1024);
        let mut decision = throttle.observe(
            requested,
            healthy_tick,
            TICK_THROTTLE_SLOW_TICK_THRESHOLD + Duration::from_millis(1),
        );

        for _ in 1..TICK_THROTTLE_ESCALATE_TICKS {
            decision = throttle.observe(
                requested,
                healthy_tick,
                TICK_THROTTLE_SLOW_TICK_THRESHOLD + Duration::from_millis(1),
            );
        }

        assert_eq!(decision.stage, TickThrottleStage::Backoff60s);
        assert_eq!(decision.interval, Duration::from_mins(1));
        assert_eq!(decision.reason, Some(TickThrottleReason::SlowTick));

        let clear = throttle.observe(requested, healthy_tick, Duration::from_millis(20));

        assert_eq!(clear.stage, TickThrottleStage::Normal);
        assert_eq!(clear.interval, requested);
        assert_eq!(clear.reason, None);
        assert!(clear.stage_changed);
    }

    /// A small complete tree is planned at its measured size, not the 100 MiB
    /// floor the pre-scan used to apply to every directory.
    #[test]
    fn prescan_measures_small_directory_candidates() {
        let temp = tempfile::tempdir().unwrap();
        let cache = temp.path().join(".ruff_cache");
        std::fs::create_dir_all(cache.join("0.6")).unwrap();
        std::fs::write(cache.join("0.6").join("blob"), vec![7u8; 2 * 1_048_576]).unwrap();
        let cancel = AtomicBool::new(false);

        let size = prescan_dir_size(&cache, false, &cancel);

        assert!(size >= 2 * 1_048_576, "{size}");
        assert!(
            size < crate::scanner::walker::OPAQUE_CANDIDATE_SIZE_FLOOR,
            "a complete 2 MiB tree must not be floored to 100 MiB: {size}"
        );
    }

    /// css 2026-09-25: busy agent temp dirs holding a live `.db` were re-walked
    /// on every pass because each pass changed their mtime. The daemon now
    /// caches the find itself as the witness, so churn does not force a
    /// re-walk while the `.db` is still there.
    #[test]
    fn found_sacred_path_keeps_a_busy_tree_protected_without_rewalking() {
        let temp = tempfile::tempdir().unwrap();
        let candidate = temp.path().join("claude-1000");
        let db = candidate.join("lh").join("router").join("actions.db");
        std::fs::create_dir_all(db.parent().unwrap()).unwrap();
        std::fs::write(&db, b"db").unwrap();
        // The built-in `*.db` stowaway marker, as in the css log.
        let sacred = vec![crate::platform::types::SacredPath {
            pattern: "*.db".to_string(),
            kind: crate::platform::types::SacredPathKind::StowawayMarker,
            reason: "Database files commonly hold application or project state.".to_string(),
            source: crate::platform::types::SacredPathSource::Builtin,
        }];
        let mut registry = ProtectionRegistry::marker_only();

        let reason = daemon_protection_reason(&mut registry, &candidate, &sacred)
            .unwrap()
            .expect("a *.db inside must protect the tree");
        assert!(reason.contains("actions.db"), "{reason}");

        std::fs::create_dir(candidate.join("new-session")).unwrap();
        let later =
            std::fs::metadata(&candidate).unwrap().modified().unwrap() + Duration::from_secs(1);
        std::fs::File::open(&candidate)
            .unwrap()
            .set_modified(later)
            .unwrap();
        assert_eq!(
            registry.cached_protected_verdict(&candidate).as_deref(),
            Some(reason.as_str()),
            "churn must not drop a verdict whose witness still exists"
        );

        std::fs::remove_file(&db).unwrap();
        assert!(registry.cached_protected_verdict(&candidate).is_none());
        assert_eq!(
            daemon_protection_reason(&mut registry, &candidate, &sacred).unwrap(),
            None,
            "with the .db gone the tree is re-proved and is no longer protected"
        );
    }

    /// A candidate whose protection cannot be proved is skipped, and stays
    /// skipped on later passes without being re-probed and re-logged.
    #[test]
    fn unprovable_candidate_is_remembered_as_protected() {
        let temp = tempfile::tempdir().unwrap();
        let (logger, logger_join) = spawn_logger(DualLoggerConfig {
            sqlite_path: None,
            jsonl_config: crate::logger::jsonl::JsonlConfig {
                path: temp.path().join("activity.jsonl"),
                fallback_path: None,
                max_size_bytes: 1_048_576,
                max_rotated_files: 0,
                fsync_interval_secs: 0,
            },
            channel_capacity: 64,
            run_id: None,
        })
        .unwrap();
        // A path through a regular file: the marker probe fails with ENOTDIR,
        // which is neither "absent" nor "protected".
        let file = temp.path().join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        let candidate = file.join("target");
        let mut registry = ProtectionRegistry::marker_only();

        assert!(daemon_protection_reason(&mut registry, &candidate, &[]).is_err());
        assert!(should_skip_protected_daemon_candidate(
            &mut registry,
            &candidate,
            &[],
            &logger,
            "test"
        ));
        let cached = registry.cached_protected_verdict(&candidate);
        assert!(
            cached
                .as_deref()
                .is_some_and(|reason| reason.starts_with("protection check failed")),
            "{cached:?}"
        );
        assert!(should_skip_protected_daemon_candidate(
            &mut registry,
            &candidate,
            &[],
            &logger,
            "test"
        ));

        logger.shutdown();
        logger_join.join().unwrap();
    }

    #[test]
    fn daemon_protection_reason_detects_marker_ancestor_without_walker() {
        let temp = tempfile::tempdir().unwrap();
        let protected = temp.path().join("repo").join("tools");
        let candidate = protected.join("rust_fuzz_target");
        std::fs::create_dir_all(&candidate).unwrap();
        protection::create_marker(&protected, None).unwrap();

        let mut registry = ProtectionRegistry::marker_only();
        let sacred_paths = Vec::new();

        let reason = daemon_protection_reason(&mut registry, &candidate, &sacred_paths)
            .unwrap()
            .unwrap();

        assert!(reason.contains(protection::MARKER_FILENAME));
        assert!(
            registry.is_protected(&candidate),
            "direct daemon candidate checks must cache marker ancestors"
        );
    }

    #[test]
    fn daemon_protection_reason_detects_config_candidate_and_parent() {
        let temp = tempfile::tempdir().unwrap();
        let protected = temp
            .path()
            .join("asupersync_ansi_c")
            .join("tools")
            .join("rust_fuzz_target");
        std::fs::create_dir_all(&protected).unwrap();
        let parent = protected.parent().unwrap().to_path_buf();
        let patterns = vec![protected.to_string_lossy().to_string()];
        let sacred_paths = protection::sacred_paths_from_protected_patterns(&patterns);
        let mut registry = ProtectionRegistry::new(Some(&patterns)).unwrap();

        let protected_reason = daemon_protection_reason(&mut registry, &protected, &sacred_paths)
            .unwrap()
            .unwrap();
        let parent_reason = daemon_protection_reason(&mut registry, &parent, &sacred_paths)
            .unwrap()
            .unwrap();

        assert!(protected_reason.contains("config pattern"));
        assert!(
            parent_reason.contains("contains sacred path"),
            "executor defense must skip a parent whose deletion would remove a protected child"
        );
    }

    #[test]
    fn maintenance_keep_lines_repeat_only_on_change_or_hourly() {
        let mut log = MaintenanceKeepLog::default();
        let start = Instant::now();
        let path = Path::new("/tmp/project/target");
        let keep = || "Keep likely false -".to_string();
        assert!(log.should_log(path, keep(), start));
        // Every later pass within the hour stays quiet...
        assert!(!log.should_log(path, keep(), start + Duration::from_mins(5)));
        assert!(!log.should_log(path, keep(), start + Duration::from_mins(59)));
        // ...unless the verdict changes, which restarts the hour.
        let review = "Review possible false -".to_string();
        assert!(log.should_log(path, review.clone(), start + Duration::from_mins(59)));
        assert!(!log.should_log(path, review, start + Duration::from_mins(60)));
        // Other paths are independent, and an unchanged verdict repeats hourly.
        assert!(log.should_log(
            Path::new("/tmp/other"),
            keep(),
            start + Duration::from_mins(60)
        ));
        assert!(log.should_log(path, keep(), start + Duration::from_mins(60)));
        assert!(log.should_log(path, keep(), start + Duration::from_mins(121)));
    }

    fn scan_cursor(max_entries: usize, cached: &[(&str, u64)]) -> ScanCursor {
        let now = Instant::now();
        ScanCursor {
            barren_dirs: cached
                .iter()
                .map(|&(path, age_mins)| {
                    let at = now.checked_sub(Duration::from_mins(age_mins)).unwrap();
                    (PathBuf::from(path), at)
                })
                .collect(),
            ttl: Duration::from_mins(30),
            max_entries,
        }
    }

    fn path_set(paths: &[&str]) -> HashSet<PathBuf> {
        paths.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn a_candidate_keeps_itself_and_every_ancestor_out_of_the_barren_cache() {
        let mut cursor = scan_cursor(100, &[("/r/a", 1)]);
        let visited = path_set(&["/r/a", "/r/a/b", "/r/a/b/target", "/r/x", "/r/x/y"]);
        let mut candidates = HashSet::new();
        mark_non_barren(&mut candidates, Path::new("/r/a/b/target"));
        // A second candidate under the same tree stops at the marked parent.
        mark_non_barren(&mut candidates, Path::new("/r/a/b/node_modules"));

        cursor.update(&visited, &candidates, true);

        let mut kept: Vec<&str> = cursor
            .barren_dirs
            .keys()
            .map(|dir| dir.to_str().unwrap())
            .collect();
        kept.sort_unstable();
        // /r/a was cached by an earlier pass and gained a candidate below it.
        assert_eq!(kept, ["/r/x", "/r/x/y"]);
        for marked in ["/r/a/b/target", "/r/a/b", "/r/a", "/r", "/"] {
            assert!(candidates.contains(Path::new(marked)), "{marked}");
        }
        assert!(candidates.contains(Path::new("/r/a/b/node_modules")));
    }

    /// bd-y70k: a pass that stops on its budget must not cache a listed
    /// directory as barren while ground below it is unseen. One worker walks
    /// breadth-first, so a pass that stops after the top level has listed
    /// every top-level directory and seen nothing below; the next pass must
    /// still reach a directory two levels down. The old rule (visited minus
    /// candidates) cached every top-level directory and never reached it.
    #[test]
    fn the_pass_after_a_budget_stop_reaches_ground_the_stopped_pass_never_saw() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for top in 0..8 {
            for mid in 0..3 {
                std::fs::create_dir_all(root.join(format!("t{top}/m{mid}"))).unwrap();
            }
        }
        let deep = root.join("t5/m1/target");
        std::fs::create_dir_all(&deep).unwrap();
        let config = |excluded: HashSet<PathBuf>| WalkerConfig {
            root_paths: vec![root.to_path_buf()],
            max_depth: 10,
            follow_symlinks: false,
            cross_devices: false,
            parallelism: 1,
            excluded_paths: excluded,
            opaque_pruning: false,
        };

        // Pass 1 stops after the eight top-level directories.
        let walker =
            DirectoryWalker::new(config(HashSet::new()), ProtectionRegistry::marker_only());
        let cancel = walker.cancel_token();
        let mut stream = walker.stream().unwrap();
        let visited: HashSet<PathBuf> = stream.by_ref().take(8).map(|entry| entry.path).collect();
        cancel.store(true, Ordering::Relaxed);
        assert!(visited.iter().all(|dir| dir.parent() == Some(root)));
        let mut non_barren = HashSet::new();
        for path in stream.unfinished_after_cancel(WALK_STOP_WAIT).unwrap() {
            mark_non_barren(&mut non_barren, &path);
        }
        let mut cursor = ScanCursor::new();
        cursor.update(&visited, &non_barren, true);
        let mut old_rule = ScanCursor::new();
        old_rule.update(&visited, &HashSet::new(), true);

        let second_pass = |cursor: &ScanCursor| -> Vec<PathBuf> {
            DirectoryWalker::new(
                config(cursor.barren_exclusions()),
                ProtectionRegistry::marker_only(),
            )
            .walk()
            .unwrap()
            .into_iter()
            .map(|entry| entry.path)
            .collect()
        };
        assert!(second_pass(&cursor).contains(&deep));
        assert!(!second_pass(&old_rule).contains(&deep));
    }

    #[test]
    fn scan_cursor_keeps_only_fresh_barren_dirs_when_they_fill_the_cap() {
        let mut cursor = scan_cursor(3, &[("/old/a", 1), ("/old/b", 2)]);
        let visited: HashSet<PathBuf> = (1..=10)
            .map(|n| PathBuf::from(format!("/new/{n}")))
            .collect();

        cursor.update(&visited, &path_set(&["/new/1"]), true);

        assert_eq!(cursor.barren_dirs.len(), 3);
        for dir in cursor.barren_dirs.keys() {
            assert!(
                dir.starts_with("/new"),
                "older entry kept: {}",
                dir.display()
            );
            assert_ne!(
                dir,
                Path::new("/new/1"),
                "a dir with candidates is never barren"
            );
        }
    }

    #[test]
    fn scan_cursor_fills_spare_room_with_the_newest_cached_dirs() {
        let mut cursor = scan_cursor(
            4,
            &[
                ("/old/1", 1),
                ("/old/2", 2),
                ("/old/3", 3),
                ("/old/4", 4),
                ("/old/expired", 40),
            ],
        );
        // /old/2 was walked again and is still barren; /old/3 gained candidates.
        let visited = path_set(&["/new/a", "/new/b", "/old/2", "/cand"]);

        cursor.update(&visited, &path_set(&["/cand", "/old/3"]), true);

        let mut kept: Vec<&str> = cursor
            .barren_dirs
            .keys()
            .map(|dir| dir.to_str().unwrap())
            .collect();
        kept.sort_unstable();
        assert_eq!(kept, ["/new/a", "/new/b", "/old/1", "/old/2"]);
        assert!(
            cursor.barren_dirs[Path::new("/old/2")] < cursor.barren_dirs[Path::new("/new/a")],
            "a dir already cached keeps its older timestamp"
        );

        // A pass that completes forgets everything.
        cursor.update(&visited, &HashSet::new(), false);
        assert!(cursor.barren_dirs.is_empty());
    }

    #[test]
    fn executor_preflight_skips_config_protected_daemon_candidate() {
        // Under /tmp, never the default temp dir: on rch workers that sits
        // inside the synced /data/projects tree, where the earlier
        // hardcoded-source-tree veto skips the candidate first (bd-c47s).
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let protected = temp
            .path()
            .join("asupersync_ansi_c")
            .join("tools")
            .join("rust_fuzz_target");
        std::fs::create_dir_all(&protected).unwrap();

        let patterns = vec![protected.to_string_lossy().to_string()];
        let sacred_paths = protection::sacred_paths_from_protected_patterns(&patterns);
        let protection = Mutex::new(ProtectionRegistry::new(Some(&patterns)).unwrap());
        let skip_protected = |path: &Path| {
            let mut protection = protection.lock();
            daemon_protection_reason(&mut protection, path, &sacred_paths)
                .unwrap()
                .map(|_| SkipReason::SacredStowaway)
        };

        let executor = DeletionExecutor::new(
            DeletionConfig {
                dry_run: true,
                min_score: 0.0,
                check_open_files: false,
                ..Default::default()
            },
            None,
        );
        let candidate_path = protected.to_string_lossy();
        let plan = executor.plan(vec![test_candidate(&candidate_path, 1.2)]);
        let report = executor.execute(&plan, Some(&skip_protected));

        assert_eq!(report.items_deleted, 0);
        assert_eq!(report.items_skipped, 1);
        assert_eq!(
            report.skipped_by_reason.get("sacred_stowaway"),
            Some(&1),
            "skipped for another reason first: {:?}",
            report.skipped_by_reason
        );
        assert!(
            protected.exists(),
            "protected candidate must remain present after executor preflight"
        );
    }

    /// bd-232u: a pattern protecting the whole root stops an ordinary batch
    /// but not a target-only one; a pattern naming a dir inside the root and
    /// a `.sbh-protect` marker above the target stop both; a target-only batch never reaches
    /// outside its root or deletes a candidate without an identity. The
    /// executor is composed in the test as `executor_thread_main` composes it
    /// (`retain_target_only_candidates`, `batch_protected_paths`), not run on
    /// its thread, and with the mock platform's open-file evidence: in a
    /// non-root test the real /proc sweep is incomplete and holds every
    /// candidate, whatever its protection.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn executor_lifts_only_root_wide_protection_for_target_only_batches() {
        use crate::scanner::walker::{FsEntryKind, FsIdentity};
        use std::os::unix::fs::MetadataExt;

        // Under /tmp, as above (bd-c47s).
        let scratch = tempfile::tempdir_in("/tmp").unwrap();
        let root = scratch.path().join("claude-501");
        let ordinary = root.join("a/target-ordinary");
        let target_only = root.join("b/target-only");
        let marked = root.join("c/target-marked");
        let named = root.join("d/target-named");
        let no_identity = root.join("e/target-no-identity");
        let outside = scratch.path().join("elsewhere/target-outside");
        for dir in [
            &ordinary,
            &target_only,
            &marked,
            &named,
            &no_identity,
            &outside,
        ] {
            std::fs::create_dir_all(dir.join("debug")).unwrap();
            std::fs::write(dir.join("debug/libdemo.rlib"), [7u8; 64]).unwrap();
        }
        // On the target's parent, inside the root: the target itself stays
        // pure (a marker at its own top level would make it impure, and the
        // purity re-check would drop it before the marker check ran).
        protection::create_marker(marked.parent().unwrap(), None).unwrap();
        let scanner = crate::core::config::ScannerConfig {
            protected_paths: vec![
                root.to_string_lossy().into_owned(),
                named.to_string_lossy().into_owned(),
            ],
            ..Default::default()
        };
        let platform: Arc<dyn Platform> = Arc::new(MockPlatform::healthy());

        let candidate = |path: &PathBuf| {
            let meta = std::fs::symlink_metadata(path).unwrap();
            let mut candidate = test_candidate(&path.to_string_lossy(), 3.0);
            candidate.size_bytes = 64;
            candidate.identity = Some(FsIdentity {
                device_id: meta.dev(),
                inode: meta.ino(),
                kind: FsEntryKind::Directory,
            });
            candidate
        };
        let run = |paths: &[&PathBuf], target_only_root: Option<&Path>| {
            let mut batch = DeletionBatch {
                candidates: paths
                    .iter()
                    .map(|path| {
                        let mut candidate = candidate(path);
                        if *path == &no_identity {
                            candidate.identity = None;
                        }
                        candidate
                    })
                    .collect(),
                pressure_level: PressureLevel::Critical,
                urgency: 0.9,
                target_bytes: None,
                target_only_root: target_only_root.map(Path::to_path_buf),
            };
            let dropped = retain_target_only_candidates(&mut batch);
            let patterns = batch_protected_paths(&batch, &scanner);
            let skip_sacred = protection::sacred_paths_from_protected_patterns(&patterns);
            let mut catalog = platform.sacred_paths();
            catalog.extend(skip_sacred.iter().cloned());
            let registry = Mutex::new(ProtectionRegistry::new(Some(&patterns)).unwrap());
            let skip_protected = |path: &Path| {
                let mut registry = registry.lock();
                daemon_protection_reason(&mut registry, path, &skip_sacred)
                    .unwrap()
                    .map(|_| SkipReason::SacredStowaway)
            };
            let executor = DeletionExecutor::new(
                DeletionConfig {
                    dry_run: false,
                    min_score: 0.0,
                    check_open_files: true,
                    require_identity: true,
                    sacred_paths: catalog,
                    mode: DeletionMode::Unlink,
                    ..Default::default()
                },
                None,
            )
            .with_platform(Arc::clone(&platform));
            let plan = executor.plan(batch.candidates);
            (dropped, executor.execute(&plan, Some(&skip_protected)))
        };

        let (dropped, report) = run(&[&ordinary], None);
        assert_eq!(dropped, 0);
        assert_eq!(
            report.skipped_by_reason.get("sacred_stowaway"),
            Some(&1),
            "{:?}",
            report.skipped_by_reason
        );
        assert!(ordinary.exists(), "protected_paths stop an ordinary batch");

        let (dropped, report) = run(
            &[&target_only, &marked, &named, &no_identity, &outside],
            Some(&root),
        );
        assert_eq!(dropped, 2, "outside the root, and without an identity");
        assert_eq!(report.items_deleted, 1, "{:?}", report.skipped_by_reason);
        assert_eq!(report.skipped_by_reason.get("sacred_stowaway"), Some(&2));
        assert!(
            !target_only.exists(),
            "a target-only batch is not stopped by a pattern covering its root"
        );
        assert!(marked.exists(), "a marker stops a target-only batch");
        assert!(
            named.exists(),
            "a pattern naming a dir inside the root still applies"
        );
        assert!(no_identity.exists());
        assert!(
            outside.exists(),
            "a target-only batch stays inside its root"
        );
    }

    /// A target-only batch can outlive the purity observation that admitted
    /// it. Adding user data preserves the directory inode, so the exception
    /// must be renewed for each candidate after the expensive preflight.
    #[cfg(unix)]
    #[test]
    fn target_only_batch_rechecks_purity_before_each_mutation() {
        use std::cell::Cell;

        let scratch = tempfile::tempdir_in("/tmp").unwrap();
        let root = scratch.path().join("claude-501");
        let first = root.join("s1/target-first");
        let held = root.join("s2/target-held");
        let mut candidates = Vec::new();
        for (path, score) in [(&first, 2.0), (&held, 1.0)] {
            std::fs::create_dir_all(path.join("debug")).unwrap();
            std::fs::write(path.join("debug/libdemo.rlib"), [7u8; 64]).unwrap();
            std::fs::write(path.join(".rustc_info.json"), b"{}").unwrap();
            let mut candidate = test_candidate(&path.to_string_lossy(), score);
            candidate.identity =
                Some(crate::scanner::walker::identity_for_path(path, false).unwrap());
            candidate.size_bytes = 66;
            candidates.push(candidate);
        }
        let held_identity = candidates[1].identity;
        let mut batch = DeletionBatch {
            candidates,
            pressure_level: PressureLevel::Critical,
            urgency: 0.9,
            target_bytes: None,
            target_only_root: Some(root.clone()),
        };
        assert_eq!(retain_target_only_candidates(&mut batch), 0);
        let scanner = crate::core::config::ScannerConfig {
            protected_paths: vec![root.to_string_lossy().into_owned()],
            ..Default::default()
        };
        let patterns = batch_protected_paths(&batch, &scanner);
        assert!(
            patterns.is_empty(),
            "the batch lifts the root-wide protection"
        );
        let platform: Arc<dyn Platform> = Arc::new(MockPlatform::healthy());
        let mut sacred_paths = platform.sacred_paths();
        sacred_paths.extend(protection::sacred_paths_from_protected_patterns(&patterns));
        let executor = DeletionExecutor::new(
            DeletionConfig {
                dry_run: false,
                min_score: 0.0,
                check_open_files: true,
                require_identity: true,
                sacred_paths,
                mode: DeletionMode::Unlink,
                ..Default::default()
            },
            None,
        )
        .with_platform(platform);
        let plan = executor.plan(std::mem::take(&mut batch.candidates));
        assert_eq!(plan.candidates.len(), 2);
        let authorizations = Cell::new(0);
        let authorize = |candidate: &CandidacyScore| {
            authorizations.set(authorizations.get() + 1);
            authorize_target_only_candidate(candidate, batch.target_only_root.as_deref())
        };
        let add_user_data = |candidate: &CandidacyScore, _: Instant| {
            assert_eq!(candidate.path, first);
            assert!(!first.exists());
            std::fs::create_dir(held.join("trace")).unwrap();
            std::fs::write(held.join("trace/notes.txt"), b"operator evidence").unwrap();
        };
        let report =
            executor.execute_with_hooks(&plan, None, Some(&authorize), Some(&add_user_data));
        assert_eq!(
            authorizations.get(),
            2,
            "both candidates reached the live guard"
        );
        assert_eq!(report.deleted_paths, vec![first]);
        assert_eq!(report.items_failed, 0);
        assert_eq!(report.bytes_freed, 66);
        assert_eq!(report.skipped_by_reason.get("sacred_stowaway"), Some(&1));
        assert_eq!(
            Some(crate::scanner::walker::identity_for_path(&held, false).unwrap()),
            held_identity,
            "the protected content appeared without replacing the directory",
        );
        assert_eq!(
            std::fs::read(held.join("trace/notes.txt")).unwrap(),
            b"operator evidence",
        );
        assert!(authorize_target_only_candidate(&plan.candidates[1], None).is_ok());
    }

    /// bd-232u gap (b): a target dir the tier surveyed as pure that gained a
    /// non-cargo entry before its batch reached the executor (a trace dir, a
    /// log) is dropped; one that stayed pure goes on, as does an ordinary
    /// batch, which this re-check does not touch.
    #[cfg(unix)]
    #[test]
    fn a_target_only_candidate_that_turned_impure_since_its_survey_is_dropped() {
        use crate::scanner::walker::{FsEntryKind, FsIdentity};
        use std::os::unix::fs::MetadataExt;

        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("claude-501");
        let still_pure = root.join("s1/target-a");
        let turned = root.join("s2/target-b");
        for dir in [&still_pure, &turned] {
            std::fs::create_dir_all(dir.join("debug")).unwrap();
            std::fs::write(dir.join("debug/libdemo.rlib"), [7u8; 64]).unwrap();
            std::fs::write(dir.join(".rustc_info.json"), b"{}").unwrap();
        }
        let candidates = || {
            [&still_pure, &turned]
                .into_iter()
                .map(|path| {
                    let meta = std::fs::symlink_metadata(path).unwrap();
                    let mut candidate = test_candidate(&path.to_string_lossy(), 3.0);
                    candidate.identity = Some(FsIdentity {
                        device_id: meta.dev(),
                        inode: meta.ino(),
                        kind: FsEntryKind::Directory,
                    });
                    candidate
                })
                .collect::<Vec<_>>()
        };
        let batch = |target_only_root: Option<PathBuf>| DeletionBatch {
            candidates: candidates(),
            pressure_level: PressureLevel::Critical,
            urgency: 0.9,
            target_bytes: None,
            target_only_root,
        };

        let mut before = batch(Some(root.clone()));
        assert_eq!(retain_target_only_candidates(&mut before), 0, "both pure");

        // Written into the target after the survey: the same inode, now work.
        std::fs::create_dir(turned.join("trace")).unwrap();
        let mut after = batch(Some(root));
        assert_eq!(retain_target_only_candidates(&mut after), 1);
        let kept: Vec<&Path> = after.candidates.iter().map(|c| c.path.as_path()).collect();
        assert_eq!(kept, [still_pure.as_path()]);

        let mut ordinary = batch(None);
        assert_eq!(retain_target_only_candidates(&mut ordinary), 0);
        assert_eq!(ordinary.candidates.len(), 2);
    }

    /// bd-232u, through the executor thread itself (`spawn_executor_thread`):
    /// a target-only batch's candidate outside its root is dropped before the
    /// policy engine, so it never reaches the decision ledger, while the one
    /// inside does. What the thread then deletes depends on the host's /proc
    /// sweep (incomplete without root, which holds everything), so deletion
    /// is not asserted.
    #[cfg(unix)]
    #[test]
    fn executor_thread_drops_target_only_candidates_outside_their_root() {
        use crate::scanner::walker::{FsEntryKind, FsIdentity};
        use std::os::unix::fs::MetadataExt;

        let mut fixture = RegretDaemonFixture::new();
        let base = fixture.directory.path().to_path_buf();
        let root = base.join("claude-501");
        let inside = root.join("s1/target-inside");
        let outside = base.join("elsewhere/target-outside");
        let candidates = [&inside, &outside]
            .into_iter()
            .map(|path| {
                std::fs::create_dir_all(path.join("debug")).unwrap();
                std::fs::write(path.join("debug/libdemo.rlib"), [7u8; 64]).unwrap();
                let meta = std::fs::symlink_metadata(path).unwrap();
                let mut candidate = test_candidate(&path.to_string_lossy(), 3.0);
                candidate.size_bytes = 64;
                candidate.identity = Some(FsIdentity {
                    device_id: meta.dev(),
                    inode: meta.ino(),
                    kind: FsEntryKind::Directory,
                });
                candidate
            })
            .collect();
        let (del_tx, del_rx) = crossbeam_channel::bounded(1);
        let (report_tx, _report_rx) = crossbeam_channel::bounded(16);
        let (index_tx, _index_rx) = crossbeam_channel::bounded(16);
        let executor = fixture
            .daemon
            .spawn_executor_thread(
                del_rx,
                fixture.daemon.logger_handle.clone(),
                ThreadHeartbeat::new("sbh-executor"),
                report_tx,
                index_tx,
            )
            .unwrap();
        del_tx
            .send(DeletionBatch {
                candidates,
                pressure_level: PressureLevel::Critical,
                urgency: 0.9,
                target_bytes: None,
                target_only_root: Some(root),
            })
            .unwrap();
        // The thread handles the batch, then stops on the closed channel.
        drop(del_tx);
        executor.join().unwrap();
        fixture.flush_logger();

        let log = std::fs::read_to_string(&fixture.daemon.config.paths.jsonl_log).unwrap();
        assert!(
            log.contains("dropped 1 target-only candidate(s) outside"),
            "{log}"
        );
        assert!(
            log.contains(inside.to_string_lossy().as_ref()),
            "the candidate inside the root reaches the ledger: {log}"
        );
        assert!(
            !log.contains(outside.to_string_lossy().as_ref()),
            "the one outside never does"
        );
        assert!(outside.join("debug/libdemo.rlib").exists());
    }

    /// Through the executor thread itself: a candidate with nothing to
    /// reclaim is dropped before the policy engine, so no decision is recorded
    /// for it and its tree is untouched, while a sized sibling in the same
    /// batch reaches the ledger as before.
    #[cfg(unix)]
    #[test]
    fn executor_thread_drops_zero_byte_candidates_before_the_policy_engine() {
        let mut fixture = RegretDaemonFixture::new();
        let base = fixture.directory.path().join("project");
        let sized = base.join("sized/target");
        let empty = base.join("hardlinked/node_modules");
        let candidates = [(&sized, 64_u64), (&empty, 0)]
            .into_iter()
            .map(|(path, bytes)| {
                std::fs::create_dir_all(path).unwrap();
                std::fs::write(path.join("payload"), [7u8; 64]).unwrap();
                let mut candidate = test_candidate(&path.to_string_lossy(), 3.0);
                candidate.size_bytes = bytes;
                candidate
            })
            .collect();
        let (del_tx, del_rx) = crossbeam_channel::bounded(1);
        let (report_tx, _report_rx) = crossbeam_channel::bounded(16);
        let (index_tx, _index_rx) = crossbeam_channel::bounded(16);
        let executor = fixture
            .daemon
            .spawn_executor_thread(
                del_rx,
                fixture.daemon.logger_handle.clone(),
                ThreadHeartbeat::new("sbh-executor"),
                report_tx,
                index_tx,
            )
            .unwrap();
        del_tx
            .send(DeletionBatch {
                candidates,
                pressure_level: PressureLevel::Critical,
                urgency: 0.9,
                target_bytes: None,
                target_only_root: None,
            })
            .unwrap();
        drop(del_tx);
        executor.join().unwrap();
        fixture.flush_logger();

        let log = std::fs::read_to_string(&fixture.daemon.config.paths.jsonl_log).unwrap();
        assert!(
            log.contains("dropped 1 zero-byte candidate(s) before the policy engine"),
            "{log}"
        );
        assert!(
            log.contains(sized.to_string_lossy().as_ref()),
            "the sized candidate reaches the ledger: {log}"
        );
        assert!(
            !log.contains(empty.to_string_lossy().as_ref()),
            "the zero-byte one never does"
        );
        assert!(empty.join("payload").exists());
    }

    #[test]
    fn zero_byte_candidates_are_dropped_and_counted() {
        let mut batch = DeletionBatch {
            candidates: vec![
                test_candidate("/data/tmp/a/node_modules", 2.0),
                test_candidate("/data/tmp/b/target", 2.5),
                test_candidate("/data/tmp/c/node_modules", 1.5),
            ],
            pressure_level: PressureLevel::Critical,
            urgency: 0.9,
            target_bytes: None,
            target_only_root: None,
        };
        batch.candidates[0].size_bytes = 0;
        batch.candidates[1].size_bytes = 4096;
        batch.candidates[2].size_bytes = 0;
        assert_eq!(drop_zero_byte_candidates(&mut batch), 2);
        assert_eq!(batch.candidates.len(), 1);
        assert_eq!(batch.candidates[0].path, Path::new("/data/tmp/b/target"));
        assert_eq!(drop_zero_byte_candidates(&mut batch), 0);
    }

    #[cfg(unix)]
    #[test]
    fn executor_compression_guard_holds_queued_work_without_poisoning_its_retry() {
        use crate::daemon::compress_tier::RootStatus;

        let fixture = RegretDaemonFixture::new();
        let candidates_dir = tempfile::tempdir_in("/tmp").unwrap();
        let project = candidates_dir.path().join("project");
        let path = project.join("target");
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("artifact.o"), [7_u8; 16]).unwrap();
        let mut candidate = test_candidate(&path.to_string_lossy(), 1.0);
        candidate.identity = Some(crate::scanner::walker::identity_for_path(&path, false).unwrap());
        candidate.size_bytes = 16;
        let executor = DeletionExecutor::new(
            DeletionConfig {
                dry_run: false,
                min_score: 0.0,
                check_open_files: true,
                require_identity: true,
                ..Default::default()
            },
            Some(fixture.daemon.logger_handle.clone()),
        )
        .with_platform(Arc::clone(&fixture.daemon.platform));
        // The plan already exists before the lossless pass publishes its hold.
        let plan = executor.plan(vec![candidate.clone()]);
        assert_eq!(plan.candidates.len(), 1);
        let shared = &fixture.daemon.shared_executor_config;
        shared.compression_first.begin(
            &[RootStatus {
                root: project,
                btrfs: true,
                level: Some(PressureLevel::Orange),
                mount_point: Some(PathBuf::from("/")),
                device_id: candidate.identity.map(|identity| identity.device_id),
            }],
            &[],
            Instant::now(),
            Duration::from_secs(30),
        );
        let authorize = |candidate: &CandidacyScore| {
            shared.authorize_compression_first(candidate, PressureLevel::Orange)
        };
        let held = executor.execute_with_guard(&plan, None, Some(&authorize));
        assert_eq!(held.items_deleted, 0);
        assert_eq!(held.items_failed, 0);
        assert_eq!(held.skipped_by_reason.get("compression_first"), Some(&1));
        assert!(
            held.backoff_candidates.is_empty(),
            "a temporary hold is not a path fault"
        );
        assert_eq!(std::fs::read(path.join("artifact.o")).unwrap(), [7_u8; 16]);
        let emergency = |candidate: &CandidacyScore| {
            shared.authorize_compression_first(candidate, PressureLevel::Red)
        };
        let released = executor.execute_with_guard(&plan, None, Some(&emergency));
        assert_eq!(
            released.items_deleted, 1,
            "{:?}",
            released.skipped_by_reason
        );
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn executor_regret_guard_stops_queued_category_after_a_midbatch_alarm() {
        use std::cell::Cell;

        let mut fixture = RegretDaemonFixture::new();
        let project = fixture.directory.path().join("project");
        let first = project.join("first/target");
        let held = project.join("held/target");
        let other = project.join("other/node_modules");
        let mut candidates = Vec::new();
        for (path, category, score) in [
            (&first, ArtifactCategory::RustTarget, 3.0),
            (&held, ArtifactCategory::RustTarget, 2.0),
            (&other, ArtifactCategory::NodeModules, 1.0),
        ] {
            std::fs::create_dir_all(path).unwrap();
            std::fs::write(path.join("artifact.o"), [0u8; 16]).unwrap();
            let mut candidate = test_candidate(&path.to_string_lossy(), score);
            candidate.classification.category = category;
            candidate.size_bytes = 16;
            assert!(!candidate.decision.category_suspended);
            candidates.push(candidate);
        }
        let executor = DeletionExecutor::new(
            DeletionConfig {
                dry_run: false,
                min_score: 0.0,
                check_open_files: true,
                ..Default::default()
            },
            Some(fixture.daemon.logger_handle.clone()),
        )
        .with_platform(Arc::clone(&fixture.daemon.platform));
        let plan = executor.plan(candidates);
        assert_eq!(plan.candidates.len(), 3);
        let checks = Cell::new(0);
        let authorize = |candidate: &CandidacyScore| {
            checks.set(checks.get() + 1);
            if candidate.path == held {
                // The queued scores were all made before this alarm. Raise
                // it only after a real deletion in this batch has completed.
                assert!(!first.exists());
                assert!(other.exists());
                let mut calibrator = fixture.daemon.regret.calibrator.lock();
                for _ in 0..3 {
                    calibrator.record(
                        "RustTarget",
                        ArtifactCertainty::Definite,
                        Outcome::Regret,
                        Instant::now(),
                    );
                }
            }
            fixture
                .daemon
                .regret
                .authorize_deletion(candidate, &fixture.daemon.logger_handle)
        };
        let report = executor.execute_with_guard(&plan, None, Some(&authorize));

        assert_eq!(checks.get(), 3);
        assert_eq!(report.items_deleted, 2);
        assert_eq!(report.items_skipped, 1);
        assert_eq!(report.items_failed, 0);
        assert_eq!(report.bytes_freed, 32);
        assert_eq!(report.deleted_paths, vec![first.clone(), other.clone()]);
        assert_eq!(report.skipped_by_reason.get("category_suspended"), Some(&1));
        assert!(report.backoff_candidates.is_empty());
        assert!(report.errors.is_empty());
        assert!(!report.circuit_breaker_tripped);
        assert!(!first.exists());
        assert!(held.join("artifact.o").exists());
        assert!(!other.exists());
        fixture.flush_logger();
        let log = std::fs::read_to_string(&fixture.daemon.config.paths.jsonl_log).unwrap();
        assert!(log.contains("regret category RustTarget is suspended; skipped "));
        assert!(log.contains(held.to_string_lossy().as_ref()));
    }

    #[cfg(unix)]
    #[test]
    fn executor_regret_guard_allows_an_expired_category_suspension() {
        let fixture = RegretDaemonFixture::new();
        let path = fixture.directory.path().join("project/target");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("artifact.o"), [0u8; 16]).unwrap();
        // A zero-duration suspension expires at its alarm timestamp, so
        // this exercises expiry without a sleep or wall-clock tolerance.
        let mut config = fixture.daemon.config.clone();
        config.scoring.regret_suspend_minutes = 0;
        fixture.daemon.regret.update_config(&config);
        {
            let mut calibrator = fixture.daemon.regret.calibrator.lock();
            for _ in 0..3 {
                calibrator.record(
                    "RustTarget",
                    ArtifactCertainty::Definite,
                    Outcome::Regret,
                    Instant::now(),
                );
            }
            let summary = calibrator.summary("RustTarget").unwrap();
            assert_eq!(summary.regrets, 3);
            assert_eq!(summary.e_value, 1.0, "the alarm resets its likelihood");
            assert!(!calibrator.suspended("RustTarget", Instant::now()));
            drop(calibrator);
        }
        let mut candidate = test_candidate(&path.to_string_lossy(), 1.0);
        candidate.classification.category = ArtifactCategory::RustTarget;
        let executor = DeletionExecutor::new(
            DeletionConfig {
                dry_run: false,
                min_score: 0.0,
                check_open_files: true,
                ..Default::default()
            },
            Some(fixture.daemon.logger_handle.clone()),
        )
        .with_platform(Arc::clone(&fixture.daemon.platform));
        let plan = executor.plan(vec![candidate]);
        let authorize = |candidate: &CandidacyScore| {
            fixture
                .daemon
                .regret
                .authorize_deletion(candidate, &fixture.daemon.logger_handle)
        };
        let report = executor.execute_with_guard(&plan, None, Some(&authorize));
        assert_eq!(report.items_deleted, 1);
        assert_eq!(report.items_skipped, 0);
        assert_eq!(report.items_failed, 0);
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn executor_watches_each_unlink_before_the_next_candidate_and_keeps_its_deadline() {
        use std::cell::Cell;

        for (after_secs, expected_outcome) in [(59, "regret"), (60, "unknown")] {
            let mut fixture = RegretDaemonFixture::new();
            let project = fixture.directory.path().join("project");
            let first = project.join("target");
            let later = project.join("node_modules");
            let mut candidates = Vec::new();
            for (path, category, score) in [
                (&first, ArtifactCategory::RustTarget, 2.0),
                (&later, ArtifactCategory::NodeModules, 1.0),
            ] {
                std::fs::create_dir(path).unwrap();
                std::fs::write(path.join("artifact.o"), [0u8; 16]).unwrap();
                let mut candidate = test_candidate(&path.to_string_lossy(), score);
                candidate.classification.category = category;
                candidate.size_bytes = 16;
                candidates.push(candidate);
            }
            let executor = DeletionExecutor::new(
                DeletionConfig {
                    dry_run: false,
                    min_score: 0.0,
                    check_open_files: true,
                    ..Default::default()
                },
                Some(fixture.daemon.logger_handle.clone()),
            )
            .with_platform(Arc::clone(&fixture.daemon.platform));
            let plan = executor.plan(candidates);
            assert_eq!(plan.candidates.len(), 2);
            let identities: HashMap<_, _> = plan
                .candidates
                .iter()
                .map(|candidate| {
                    (
                        candidate.path.clone(),
                        EntryIdentity::of(&candidate.path).unwrap(),
                    )
                })
                .collect();
            let first_completed = Cell::new(None);
            let later_completed = Cell::new(None);
            let authorize = |candidate: &CandidacyScore| {
                if candidate.path == later {
                    let completed_at = first_completed
                        .get()
                        .expect("first unlink completes before the next authorization");
                    assert_eq!(fixture.daemon.regret.detector.lock().pending(), 1);
                    assert!(!first.exists());
                    assert!(later.exists());
                    // A recreation is observable while the same batch is
                    // still running. Resolve it against the actual first
                    // unlink timestamp, including the exact 60s boundary.
                    std::fs::create_dir(&first).unwrap();
                    fixture.daemon.resolve_regrets_with_clock(|| {
                        completed_at + Duration::from_secs(after_secs)
                    });
                    assert_eq!(fixture.daemon.regret.detector.lock().pending(), 0);
                }
                fixture
                    .daemon
                    .regret
                    .authorize_deletion(candidate, &fixture.daemon.logger_handle)
            };
            let on_unlinked = |candidate: &CandidacyScore, completed_at: Instant| {
                assert!(!candidate.path.exists());
                fixture.daemon.regret.watch_unlinked(
                    candidate,
                    &identities[&candidate.path],
                    completed_at,
                );
                if candidate.path == first {
                    first_completed.set(Some(completed_at));
                } else {
                    assert_eq!(candidate.path, later);
                    later_completed.set(Some(completed_at));
                }
            };
            let report =
                executor.execute_with_hooks(&plan, None, Some(&authorize), Some(&on_unlinked));

            assert_eq!(report.items_deleted, 2);
            assert_eq!(report.items_skipped, 0);
            assert_eq!(report.items_failed, 0);
            assert!(
                first.exists(),
                "the first path was recreated during the batch"
            );
            assert!(!later.exists());
            assert_eq!(fixture.daemon.regret.detector.lock().pending(), 1);
            let completed_at = later_completed.get().expect("later unlink observed");
            fixture
                .daemon
                .resolve_regrets_with_clock(|| completed_at + Duration::from_secs(60));
            assert_eq!(fixture.daemon.regret.detector.lock().pending(), 0);

            fixture.flush_logger();
            let ledger = crate::logger::sqlite::SqliteLogger::open_read_only(
                &fixture.daemon.config.paths.sqlite_db,
            )
            .unwrap();
            for (candidate, expected, age) in [
                (&plan.candidates[0], expected_outcome, after_secs),
                (&plan.candidates[1], "clean", 60),
            ] {
                let id = crate::scanner::decision_record::stable_decision_id(
                    &candidate.path,
                    candidate.identity,
                    candidate.size_bytes,
                );
                let outcomes = ledger.outcomes_for_decision(&id).unwrap();
                assert_eq!(outcomes.len(), 1);
                assert_eq!(outcomes[0].outcome, expected);
                assert_eq!(outcomes[0].after_secs, age);
            }
        }
    }

    #[test]
    fn scanner_prescan_does_not_dispatch_protected_rust_fuzz_target() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("scan-root");
        let repo = root.join("asupersync_ansi_c");
        let tools = repo.join("tools");
        let candidate = tools.join("rust_fuzz_target");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(candidate.join("src")).unwrap();
        protection::create_marker(&tools, None).unwrap();

        let mut config = Config::default();
        config.scanner.root_paths = vec![root.clone()];
        config.scanner.protected_paths = vec![
            tools.to_string_lossy().to_string(),
            candidate.to_string_lossy().to_string(),
        ];
        config.scanner.min_file_age_minutes = 0;
        config.scanner.active_reference_min_size_bytes = u64::MAX;

        let log_path = temp.path().join("activity.jsonl");
        let (logger, logger_join) = spawn_logger(DualLoggerConfig {
            sqlite_path: None,
            jsonl_config: crate::logger::jsonl::JsonlConfig {
                path: log_path,
                fallback_path: None,
                max_size_bytes: 1_048_576,
                max_rotated_files: 0,
                fsync_interval_secs: 0,
            },
            channel_capacity: 64,
            run_id: None,
        })
        .unwrap();
        let (scan_tx, scan_rx) = bounded::<ScanRequest>(1);
        let (del_tx, del_rx) = bounded::<DeletionBatch>(1);
        let (report_tx, report_rx) = bounded::<WorkerReport>(1);
        let (_index_feedback_tx, index_feedback_rx) = bounded::<ScannerIndexFeedback>(1);
        let cpu_budget = Arc::new(Mutex::new(CpuBudget::new(0, Instant::now(), 0.0)));
        let heartbeat = Arc::new(ThreadHeartbeat::new("test-scanner"));
        let shared_scoring_config = Arc::new(RwLock::new(config.scoring));
        let shared_scanner_config = Arc::new(RwLock::new(config.scanner));
        let platform: Arc<dyn Platform> = Arc::new(MockPlatform::healthy());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (scanner_index_path, prescan_cursor_path) = scanner_state_paths(temp.path());

        scan_tx
            .send(ScanRequest {
                paths: vec![root],
                urgency: 0.9,
                pressure_level: PressureLevel::Orange,
                free_pct: Some(9.0),
                max_delete_batch: 10,
                force_full_scan: false,
                config_update: None,
                catalog_roots: Vec::new(),
                maintenance: false,
                target_bytes: None,
            })
            .unwrap();
        drop(scan_tx);

        scanner_thread_main(
            &scan_rx,
            &del_tx,
            &logger,
            &shared_scoring_config,
            &shared_scanner_config,
            &platform,
            &heartbeat,
            &report_tx,
            &shutdown,
            &scanner_index_path,
            &prescan_cursor_path,
            &index_feedback_rx,
            &cpu_budget,
            &Arc::new(SharedExecutorConfig::new(
                false, 10, 0.0, 60, 3600, false, 0,
            )),
            &Arc::new(SharedRegret::new(&Config::default())),
        );

        assert!(
            del_rx.try_recv().is_err(),
            "protected rust_fuzz_target must not be dispatched by daemon priority pre-scan"
        );
        assert!(
            candidate.exists(),
            "scanner pre-scan must leave protected rust_fuzz_target on disk"
        );
        let report = report_rx
            .try_recv()
            .expect("scanner should report completion");
        match report {
            WorkerReport::ScanCompleted { candidates, .. } => assert_eq!(
                candidates, 0,
                "protected rust_fuzz_target must not count as a daemon deletion candidate"
            ),
            WorkerReport::DeletionCompleted { .. } => panic!("expected scanner completion report"),
        }

        logger.shutdown();
        logger_join.join().unwrap();
    }

    /// A pre-scan phase that runs out of *its own* wall budget must hand the
    /// pass over to the general walker, not end it.
    ///
    /// Before 0.6.2 there was one deadline for both, so the pre-scan tripping
    /// it aborted the whole pass — the walker (and its incremental cursor)
    /// never ran at all on any host whose tree the pre-scan could not
    /// enumerate.
    #[test]
    fn prescan_phase_budget_hands_over_to_the_walker_instead_of_ending_the_pass() {
        let start = Instant::now();
        let mut limits = PassLimits::new(
            start,
            start + Duration::from_mins(15),
            Duration::from_nanos(1),
            PassCpuGuard::unlimited(start),
        );
        let stop = limits.prescan_stop().expect("the phase budget is spent");
        assert_eq!(stop, PassStop::PrescanPhase);
        assert!(
            !stop.ends_pass(),
            "the phase budget must not mark the pass as timed out"
        );
        assert!(
            limits.walk_stop().is_none(),
            "the walker still has its whole wall budget"
        );

        // The pass's own wall budget, by contrast, ends everything.
        let mut spent = PassLimits::new(
            start,
            start,
            Duration::from_secs(60),
            PassCpuGuard::unlimited(start),
        );
        assert_eq!(spent.prescan_stop(), Some(PassStop::Wall));
        assert_eq!(spent.walk_stop(), Some(PassStop::Wall));
        assert!(PassStop::Wall.ends_pass() && PassStop::Cpu.ends_pass());
    }

    /// The pre-scan stops at its share of the pass's CPU allowance and hands
    /// the rest to the walk; with the budget off it has no CPU share at all.
    #[test]
    fn prescan_spends_only_its_share_of_the_pass_cpu() {
        let start = Instant::now();
        let cpu = Arc::new(Mutex::new(0.0_f64));
        let handle = Arc::clone(&cpu);
        let guard = PassCpuGuard::new(Some(4.0), start, move || Some(*handle.lock()))
            .with_sample_interval(Duration::ZERO);
        let mut limits = PassLimits::new(
            start,
            start + Duration::from_mins(15),
            Duration::from_mins(15),
            guard,
        );
        *cpu.lock() = 1.9;
        assert_eq!(limits.prescan_stop(), None);
        *cpu.lock() = 2.0;
        let stop = limits.prescan_stop().expect("half the allowance is spent");
        assert_eq!(stop, PassStop::PrescanCpuShare);
        assert!(!stop.ends_pass(), "the walk gets the other half");
        assert_eq!(limits.walk_stop(), None);
        *cpu.lock() = 4.0;
        assert_eq!(limits.walk_stop(), Some(PassStop::Cpu));
        assert_eq!(limits.prescan_stop(), Some(PassStop::Cpu));

        let mut unlimited = PassLimits::new(
            start,
            start + Duration::from_mins(15),
            Duration::from_mins(15),
            PassCpuGuard::unlimited(start),
        );
        assert_eq!(unlimited.prescan_stop(), None);
    }

    /// A spent CPU allowance ends the pass; an unspent one does not, however
    /// long the pass has been running in wall time. This is the invariant the
    /// old `cpu_secs / parallelism` wall conversion got backwards.
    #[test]
    fn pass_limits_stop_on_measured_cpu_not_on_modelled_wall_time() {
        let start = Instant::now();
        let cpu = Arc::new(Mutex::new(0.0_f64));
        let handle = Arc::clone(&cpu);
        let guard = PassCpuGuard::new(Some(2.0), start, move || Some(*handle.lock()))
            .with_sample_interval(Duration::ZERO);
        let mut limits = PassLimits::new(
            start,
            start + Duration::from_mins(15),
            Duration::from_mins(15),
            guard,
        );
        assert!(
            limits.walk_stop().is_none(),
            "an I/O-bound pass that has spent no CPU keeps going"
        );
        *cpu.lock() = 3.0;
        assert_eq!(limits.walk_stop(), Some(PassStop::Cpu));
    }

    /// The `SBH-2007` budget warning is rate-limited, because a truncated pass
    /// is the normal steady state on a large tree and the activity log has no
    /// retention policy.
    #[test]
    fn budget_warnings_are_rate_limited() {
        let t0 = Instant::now();
        let mut last = None;
        assert!(
            claim_budget_warning(&mut last, t0),
            "the first one goes out"
        );
        let just_short = BUDGET_WARNING_INTERVAL
            .checked_sub(Duration::from_secs(1))
            .expect("the interval is longer than a second");
        assert!(!claim_budget_warning(&mut last, t0 + just_short));
        assert!(claim_budget_warning(
            &mut last,
            t0 + BUDGET_WARNING_INTERVAL
        ));
        assert!(!claim_budget_warning(
            &mut last,
            t0 + BUDGET_WARNING_INTERVAL + Duration::from_secs(1)
        ));
    }

    /// The resume cursor belongs to the *full* sweep, and the guard that
    /// protects it is `active_scan_paths == request.paths`.
    ///
    /// With the default V2 engine a Green pass is scoped to the dirty project
    /// directories, so its roots are not the configured ones. If such a pass
    /// moved the cursor, every file-change event on an idle host would send
    /// the full sweep back to the start — the same "never gets past the first
    /// directories" failure the cursor exists to prevent.
    #[test]
    fn a_scoped_v2_pass_is_not_a_full_root_sweep() {
        let configured = vec![PathBuf::from("/data/projects")];
        let request = |level| ScanRequest {
            paths: configured.clone(),
            urgency: 0.2,
            pressure_level: level,
            free_pct: Some(30.0),
            max_delete_batch: 4,
            force_full_scan: false,
            config_update: None,
            catalog_roots: Vec::new(),
            maintenance: false,
            target_bytes: None,
        };
        let dirty: BTreeSet<PathBuf> =
            std::iter::once(PathBuf::from("/data/projects/one")).collect();

        let scoped = v2_active_scan_paths(&request(PressureLevel::Green), &dirty)
            .expect("Green scopes the pass to the dirty roots");
        assert_ne!(
            scoped, configured,
            "a scoped pass must fail the `active_scan_paths == request.paths` guard"
        );

        // Orange and above sweep the configured roots, and do own the cursor.
        assert!(
            v2_active_scan_paths(&request(PressureLevel::Orange), &dirty).is_none(),
            "a pressured pass is a full sweep"
        );
        assert!(
            v2_active_scan_paths(
                &ScanRequest {
                    force_full_scan: true,
                    ..request(PressureLevel::Green)
                },
                &dirty,
            )
            .is_none(),
            "an operator's forced scan is a full sweep"
        );
    }

    /// The pre-scan must resume where the last pass stopped, not restart at
    /// the first entry of the first root.
    ///
    /// The fleet symptom this fixes: with a sub-second budget the pre-scan
    /// re-examined the same leading directories on every pass and logged
    /// `0 entries, 0 candidates` forever while the disk filled.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn prescan_resumes_from_the_persisted_cursor_instead_of_restarting() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("scan-root");
        for name in ["aaa_repo", "zzz_repo"] {
            let repo = root.join(name);
            std::fs::create_dir_all(repo.join(".git")).unwrap();
            // A Rust repo: the pre-scan classifies its target as the walk
            // does, and the walk takes a marked target whole only beside its
            // manifest or under a temp root (TMPDIR may be neither).
            std::fs::write(repo.join("Cargo.toml"), "[package]\nname = \"r\"\n").unwrap();
            let debug = repo.join("target").join("debug");
            std::fs::create_dir_all(debug.join("deps")).unwrap();
            std::fs::write(debug.join("artifact.o"), b"mock object file").unwrap();
            write_cargo_cachedir_tag(&repo.join("target"));
        }

        let mut config = Config::default();
        config.scanner.root_paths = vec![root.clone()];
        config.scanner.min_file_age_minutes = 0;
        config.scanner.active_reference_min_size_bytes = u64::MAX;

        let (scanner_index_path, prescan_cursor_path) = scanner_state_paths(temp.path());
        // The state a previous pass would have left behind after covering
        // `aaa_repo` and being cut off.
        let mut seeded = PrescanCursor::new();
        seeded.advance(&root, &root.join("aaa_repo"));
        seeded.save(&prescan_cursor_path).unwrap();

        let (logger, logger_join) = spawn_logger(DualLoggerConfig {
            sqlite_path: None,
            jsonl_config: crate::logger::jsonl::JsonlConfig {
                path: temp.path().join("activity.jsonl"),
                fallback_path: None,
                max_size_bytes: 1_048_576,
                max_rotated_files: 0,
                fsync_interval_secs: 0,
            },
            channel_capacity: 64,
            run_id: None,
        })
        .unwrap();
        let (scan_tx, scan_rx) = bounded::<ScanRequest>(1);
        let (del_tx, del_rx) = bounded::<DeletionBatch>(4);
        let (report_tx, report_rx) = bounded::<WorkerReport>(4);
        let (_index_feedback_tx, index_feedback_rx) = bounded::<ScannerIndexFeedback>(1);
        let cpu_budget = Arc::new(Mutex::new(CpuBudget::new(0, Instant::now(), 0.0)));
        let heartbeat = Arc::new(ThreadHeartbeat::new("test-scanner"));
        let shared_scoring_config = Arc::new(RwLock::new(config.scoring));
        let shared_scanner_config = Arc::new(RwLock::new(config.scanner));
        let platform: Arc<dyn Platform> = Arc::new(MockPlatform::healthy());
        let shutdown = Arc::new(AtomicBool::new(false));

        scan_tx
            .send(ScanRequest {
                paths: vec![root.clone()],
                urgency: 0.9,
                pressure_level: PressureLevel::Orange,
                free_pct: Some(9.0),
                max_delete_batch: 10,
                force_full_scan: false,
                config_update: None,
                catalog_roots: Vec::new(),
                maintenance: false,
                target_bytes: None,
            })
            .unwrap();
        drop(scan_tx);

        scanner_thread_main(
            &scan_rx,
            &del_tx,
            &logger,
            &shared_scoring_config,
            &shared_scanner_config,
            &platform,
            &heartbeat,
            &report_tx,
            &shutdown,
            &scanner_index_path,
            &prescan_cursor_path,
            &index_feedback_rx,
            &cpu_budget,
            &Arc::new(SharedExecutorConfig::new(
                false, 10, 0.0, 60, 3600, false, 0,
            )),
            &Arc::new(SharedRegret::new(&Config::default())),
        );

        // The pre-scan's batch is dispatched first. The walk may follow with
        // its own: on macOS the FSEvents startup replan marks the roots dirty
        // and the walk reconciles everything, the cursor's prefix included.
        let prescan_paths: Vec<PathBuf> = del_rx
            .try_recv()
            .map(|batch| batch.candidates.into_iter().map(|c| c.path).collect())
            .unwrap_or_default();
        while del_rx.try_recv().is_ok() {}
        assert!(
            !prescan_paths.is_empty(),
            "the resumed pre-scan must still find the targets after the cursor"
        );
        assert!(
            prescan_paths
                .iter()
                .any(|path| path.starts_with(root.join("zzz_repo"))),
            "the pre-scan must reach the entries after the cursor: {prescan_paths:?}"
        );
        assert!(
            !prescan_paths
                .iter()
                .any(|path| path.starts_with(root.join("aaa_repo"))),
            "the pre-scan must not re-examine the prefix the cursor already covered: \
             {prescan_paths:?}"
        );
        while report_rx.try_recv().is_ok() {}

        logger.shutdown();
        logger_join.join().unwrap();
    }

    /// End-to-end: a synthetic tree far larger than one pre-scan budget must
    /// still dispatch the candidates it did find, and two consecutive passes
    /// must not tread the same ground.
    ///
    /// The budget is deliberately the smallest the config allows (1 s). On a
    /// slow host the pre-scan is truncated and the cursor carries the sweep
    /// forward; on a very fast host it finishes the root and the cursor wraps.
    /// Both are correct, and both are asserted — what must never happen, in
    /// either regime, is the pre-1.32 behaviour of an empty result set and a
    /// cursor pinned at the first entry.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn prescan_over_a_large_tree_yields_candidates_and_moves_the_cursor() {
        struct PassObservation {
            dispatched: Vec<PathBuf>,
            candidates: usize,
            indexed: std::collections::BTreeSet<PathBuf>,
            walker_entries: usize,
            walker_targets: usize,
            replayed: usize,
        }
        let temp = temp_root_scratch_dir();
        let root = temp.path().join("scan-root");
        // 600 repositories, each with a nested `target/debug` the pre-scan
        // must classify: several thousand directories in total.
        for index in 0..600 {
            let repo = root.join(format!("repo-{index:04}"));
            std::fs::create_dir_all(repo.join(".git")).unwrap();
            let debug = repo.join("target").join("debug");
            std::fs::create_dir_all(debug.join("deps")).unwrap();
            std::fs::write(debug.join("artifact.o"), b"mock object file").unwrap();
            write_cargo_cachedir_tag(&repo.join("target"));
        }

        let mut config = Config::default();
        config.scanner.root_paths = vec![root.clone()];
        config.scanner.min_file_age_minutes = 0;
        config.scanner.active_reference_min_size_bytes = u64::MAX;
        config.scanner.prescan_time_budget_secs = 1;
        config.validate().expect("the tuned config stays valid");

        let (scanner_index_path, prescan_cursor_path) = scanner_state_paths(temp.path());
        let scoring = Arc::new(RwLock::new(config.scoring.clone()));
        let scanner_cfg = Arc::new(RwLock::new(config.scanner));
        let platform: Arc<dyn Platform> = Arc::new(MockPlatform::healthy());
        let shutdown = Arc::new(AtomicBool::new(false));

        let run_pass = |pass: usize| -> PassObservation {
            let (logger, logger_join) = spawn_logger(DualLoggerConfig {
                sqlite_path: None,
                jsonl_config: crate::logger::jsonl::JsonlConfig {
                    path: temp.path().join(format!("activity-{pass}.jsonl")),
                    fallback_path: None,
                    max_size_bytes: 1_048_576,
                    max_rotated_files: 0,
                    fsync_interval_secs: 0,
                },
                channel_capacity: 1024,
                run_id: None,
            })
            .unwrap();
            let (scan_tx, scan_rx) = bounded::<ScanRequest>(1);
            let (del_tx, del_rx) = bounded::<DeletionBatch>(64);
            let (report_tx, report_rx) = bounded::<WorkerReport>(64);
            let (_feedback_tx, feedback_rx) = bounded::<ScannerIndexFeedback>(1);
            scan_tx
                .send(ScanRequest {
                    paths: vec![root.clone()],
                    urgency: 0.9,
                    pressure_level: PressureLevel::Orange,
                    free_pct: Some(9.0),
                    max_delete_batch: 10,
                    force_full_scan: false,
                    config_update: None,
                    catalog_roots: Vec::new(),
                    maintenance: false,
                    target_bytes: None,
                })
                .unwrap();
            drop(scan_tx);
            scanner_thread_main(
                &scan_rx,
                &del_tx,
                &logger,
                &scoring,
                &scanner_cfg,
                &platform,
                &heartbeat_for_test(),
                &report_tx,
                &shutdown,
                &scanner_index_path,
                &prescan_cursor_path,
                &feedback_rx,
                &Arc::new(Mutex::new(CpuBudget::new(0, Instant::now(), 0.0))),
                &Arc::new(SharedExecutorConfig::new(
                    false, 10, 0.0, 60, 3600, false, 0,
                )),
                &Arc::new(SharedRegret::new(&Config::default())),
            );
            let mut dispatched = Vec::new();
            while let Ok(batch) = del_rx.try_recv() {
                dispatched.extend(batch.candidates.into_iter().map(|c| c.path));
            }
            let mut candidates_found = 0;
            let mut timed_out = false;
            while let Ok(report) = report_rx.try_recv() {
                if let WorkerReport::ScanCompleted {
                    candidates,
                    timed_out: pass_timed_out,
                    ..
                } = report
                {
                    candidates_found += candidates;
                    timed_out |= pass_timed_out;
                }
            }
            logger.shutdown();
            logger_join.join().unwrap();
            let checkpoint: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&scanner_index_path).unwrap()).unwrap();
            let completion_log =
                std::fs::read_to_string(temp.path().join(format!("activity-{pass}.jsonl")))
                    .unwrap();
            let completions: Vec<serde_json::Value> = completion_log
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .filter(|event: &serde_json::Value| event["event"] == "scan_complete")
                .collect();
            assert_eq!(completions.len(), 1, "one request completes exactly once");
            let details = completions[0]["details"].as_str().unwrap();
            let field = |name: &str| {
                details
                    .split_whitespace()
                    .find_map(|part| part.split_once('=').filter(|(key, _)| *key == name))
                    .unwrap()
                    .1
            };
            assert_eq!(
                field("candidates").parse::<usize>().unwrap(),
                candidates_found
            );
            assert_eq!(field("timed_out").parse::<bool>().unwrap(), timed_out);
            let records: Vec<CandidateIndexRecord> =
                serde_json::from_value(checkpoint["records"].clone()).unwrap();
            let indexed: std::collections::BTreeSet<_> =
                records.iter().map(|record| record.path.clone()).collect();
            assert_eq!(indexed.len(), records.len(), "no duplicate indexed paths");
            PassObservation {
                dispatched,
                candidates: candidates_found,
                indexed,
                walker_entries: field("paths_scanned").parse().unwrap(),
                walker_targets: field("opaque_pruned_dirs").parse().unwrap(),
                replayed: field("replayed_records").parse().unwrap(),
            }
        };

        let first = run_pass(1);
        assert!(
            !first.dispatched.is_empty(),
            "a pre-scan must dispatch what it found, never an empty set"
        );
        assert!(
            first.candidates > 0,
            "a pre-scan must report the candidates it reached, timed out or not"
        );
        let after_first = PrescanCursor::load(&prescan_cursor_path);
        assert_ne!(
            after_first,
            PrescanCursor::new(),
            "the pre-scan must record where it stopped"
        );

        let second = run_pass(2);
        let after_second = PrescanCursor::load(&prescan_cursor_path);
        assert!(second.candidates > 0, "the second pass must also find work");
        match after_first.position() {
            (_, Some(resume_point)) => {
                // Pass 1 was truncated: pass 2's pre-scan picks up strictly
                // after it, so its own cursor ends further on (or wraps once
                // the root is done). A pre-scan restarting from the first
                // entry would stop at or before the old resume point again.
                // Pass 2 may still dispatch earlier targets: pass 1's walk
                // indexed the whole root, and the index replay re-offers the
                // targets nothing has deleted, ahead of the pre-scan's batch.
                // The exact no-restart contract is pinned deterministically by
                // `prescan_resumes_from_the_persisted_cursor_instead_of_restarting`.
                let resume_point = resume_point.to_path_buf();
                match after_second.position() {
                    (_, Some(second_point)) => assert!(
                        second_point > resume_point.as_path(),
                        "pass 2 must resume after pass 1 ({}), not restart: stopped at {}",
                        resume_point.display(),
                        second_point.display()
                    ),
                    (second_root, None) => assert_eq!(second_root, Some(root.as_path())),
                }
                if resume_point.as_path() < root.join("repo-0599").as_path() {
                    assert!(
                        second
                            .dispatched
                            .iter()
                            .any(|path| path.as_path() > resume_point.as_path()),
                        "pass 2 must dispatch targets beyond pass 1's resume point ({}): \
                         {:?}",
                        resume_point.display(),
                        second.dispatched
                    );
                }
            }
            (root_after, None) => {
                // Pass 1 covered the whole root: it must have found every
                // target, and the cursor wrapped back to the root's start.
                let expected_paths: std::collections::BTreeSet<_> = (0..600)
                    .map(|index| root.join(format!("repo-{index:04}/target")))
                    .collect();
                assert_eq!(
                    first.indexed, expected_paths,
                    "every distinct target is indexed"
                );
                assert_eq!(
                    first.replayed, 0,
                    "a fresh index cannot replay prior records"
                );
                // Reconciliation is a runtime decision on either OS. With
                // this fixture a walk visits one repo and one opaque target
                // per repository, and counts the same targets a second time.
                if first.walker_entries == 0 {
                    assert_eq!(first.walker_targets, 0);
                } else {
                    assert_eq!(
                        first.walker_entries, 1200,
                        "the walk covers the entire fixture"
                    );
                    assert_eq!(
                        first.walker_targets, 600,
                        "the walk sees every opaque target"
                    );
                }
                assert_eq!(
                    first.candidates,
                    600 + first.walker_targets,
                    "candidate observations equal the pre-scan plus the actual walk"
                );
                assert_eq!(root_after, Some(root.as_path()));
            }
        }
    }

    /// `size_estimate_bytes` of the scanner-index record for `path`,
    /// wherever it sits in the persisted JSON.
    fn recorded_size(value: &serde_json::Value, path: &str) -> Option<u64> {
        match value {
            serde_json::Value::Object(map) => {
                if map.get("path").and_then(serde_json::Value::as_str) == Some(path) {
                    return map
                        .get("size_estimate_bytes")
                        .and_then(serde_json::Value::as_u64);
                }
                map.values().find_map(|v| recorded_size(v, path))
            }
            serde_json::Value::Array(items) => items.iter().find_map(|v| recorded_size(v, path)),
            _ => None,
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one end-to-end scanner pass
    fn scanner_prescan_discovers_target_in_repo_with_beads_tracker() {
        let temp = temp_root_scratch_dir();
        let root = temp.path().join("scan-root");
        let repo = root.join("my_beads_project");
        let beads_dir = repo.join(".beads");
        let target_dir = repo.join("target");
        let debug_dir = target_dir.join("debug");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(&beads_dir).unwrap();
        std::fs::write(beads_dir.join("issues.jsonl"), "{}").unwrap();
        std::fs::create_dir_all(&debug_dir).unwrap();
        std::fs::write(debug_dir.join("dummy_artifact.o"), b"mock object file").unwrap();

        let mut config = Config::default();
        config.scanner.root_paths = vec![root.clone()];
        config.scanner.min_file_age_minutes = 0;
        config.scanner.active_reference_min_size_bytes = u64::MAX;

        let log_path = temp.path().join("activity.jsonl");
        let (logger, logger_join) = spawn_logger(DualLoggerConfig {
            sqlite_path: None,
            jsonl_config: crate::logger::jsonl::JsonlConfig {
                path: log_path,
                fallback_path: None,
                max_size_bytes: 1_048_576,
                max_rotated_files: 0,
                fsync_interval_secs: 0,
            },
            channel_capacity: 64,
            run_id: None,
        })
        .unwrap();
        let (scan_tx, scan_rx) = bounded::<ScanRequest>(1);
        let (del_tx, del_rx) = bounded::<DeletionBatch>(1);
        let (report_tx, report_rx) = bounded::<WorkerReport>(1);
        let (_index_feedback_tx, index_feedback_rx) = bounded::<ScannerIndexFeedback>(1);
        let cpu_budget = Arc::new(Mutex::new(CpuBudget::new(0, Instant::now(), 0.0)));
        let heartbeat = Arc::new(ThreadHeartbeat::new("test-scanner"));
        let shared_scoring_config = Arc::new(RwLock::new(config.scoring));
        let shared_scanner_config = Arc::new(RwLock::new(config.scanner));
        let platform: Arc<dyn Platform> = Arc::new(MockPlatform::healthy());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (scanner_index_path, prescan_cursor_path) = scanner_state_paths(temp.path());

        scan_tx
            .send(ScanRequest {
                paths: vec![root],
                urgency: 0.9,
                pressure_level: PressureLevel::Orange,
                free_pct: Some(9.0),
                max_delete_batch: 10,
                force_full_scan: false,
                config_update: None,
                catalog_roots: Vec::new(),
                maintenance: false,
                target_bytes: None,
            })
            .unwrap();
        drop(scan_tx);

        scanner_thread_main(
            &scan_rx,
            &del_tx,
            &logger,
            &shared_scoring_config,
            &shared_scanner_config,
            &platform,
            &heartbeat,
            &report_tx,
            &shutdown,
            &scanner_index_path,
            &prescan_cursor_path,
            &index_feedback_rx,
            &cpu_budget,
            &Arc::new(SharedExecutorConfig::new(
                false, 10, 0.0, 60, 3600, false, 0,
            )),
            &Arc::new(SharedRegret::new(&Config::default())),
        );

        let report = report_rx
            .try_recv()
            .expect("scanner should report completion");
        match report {
            WorkerReport::ScanCompleted { candidates, .. } => {
                assert!(
                    candidates >= 1,
                    "target in beads-enabled project must be found as candidate (found {candidates})"
                );
            }
            WorkerReport::DeletionCompleted { .. } => panic!("expected scanner completion report"),
        }

        // The target candidate was dispatched to the executor channel:
        let batch = del_rx.try_recv().expect("target should be dispatched");
        assert!(
            batch.candidates.iter().any(|c| c.path == target_dir),
            "batch must contain target_dir"
        );
        assert!(
            !batch
                .candidates
                .iter()
                .any(|c| c.path == repo || c.path == beads_dir),
            "batch must never contain repo root or .beads dir"
        );
        // The dispatched size is measured, not the 100 MiB nomination floor.
        let target = batch
            .candidates
            .iter()
            .find(|c| c.path == target_dir)
            .unwrap();
        assert!(
            target.size_bytes < crate::scanner::walker::OPAQUE_CANDIDATE_SIZE_FLOOR,
            "a near-empty target must be planned at its real size: {}",
            target.size_bytes
        );
        // So is the index record every later replay dispatches from: it was
        // written with the floor, and fmd reported 73 GB freed for a few MB.
        let index: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&scanner_index_path).unwrap()).unwrap();
        let recorded = recorded_size(&index, &target_dir.to_string_lossy())
            .expect("the target is recorded in the scanner index");
        assert!(
            recorded < crate::scanner::walker::OPAQUE_CANDIDATE_SIZE_FLOOR,
            "the index must record the measured size, not the nomination floor: {recorded}"
        );

        logger.shutdown();
        logger_join.join().unwrap();
    }

    #[test]
    fn daemon_idle_reason_is_the_dominant_reason_only_when_every_mount_is_idle() {
        fn record(mount: &str, state: MountState, reason: Option<IdleReason>) -> MountStateRecord {
            MountStateRecord {
                mount: mount.to_string(),
                state,
                idle_reason: reason,
                surface: crate::daemon::mount_controller::SurfaceKind::Configured,
                level: "green".to_string(),
                urgency: 0.0,
                rescan_in_secs: None,
                reclaim_capability: crate::daemon::mount_controller::ReclaimCapability::Configured,
                reserve_state: None,
            }
        }
        assert_eq!(daemon_idle_reason(&[]), None);
        let all_idle = [
            record("/", MountState::ObserveOnly, Some(IdleReason::NoSurface)),
            record(
                "/data",
                MountState::Idle,
                Some(IdleReason::NothingToReclaim),
            ),
            record("/srv", MountState::ObserveOnly, Some(IdleReason::NoSurface)),
        ];
        assert_eq!(
            daemon_idle_reason(&all_idle).as_deref(),
            Some("no_root_path_on_device")
        );
        let one_working = [
            record("/", MountState::ObserveOnly, Some(IdleReason::NoSurface)),
            record("/data", MountState::Maintain, None),
        ];
        assert_eq!(daemon_idle_reason(&one_working), None);
        let recovering = [record(
            "/data",
            MountState::Recovery,
            Some(IdleReason::WriteFailure),
        )];
        assert_eq!(daemon_idle_reason(&recovering), None);
    }

    /// A cargo target created just now whose mtimes were set five hours back
    /// is young by the walker's rule (birth time). The priority pre-scan must
    /// measure it the same way and hold it behind `min_file_age_minutes`.
    #[test]
    #[allow(clippy::too_many_lines)]
    // The whole behavior is the bd-awc5 birth-time contract, which macOS
    // does not satisfy yet (the pre-scan dispatches the young tree).
    #[cfg(target_os = "linux")]
    fn scanner_prescan_holds_a_young_tree_with_old_mtimes() {
        fn set_mtime_recursive(path: &Path, mtime: filetime::FileTime) {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    set_mtime_recursive(&entry.path(), mtime);
                }
            }
            let _ = filetime::set_file_mtime(path, mtime);
        }

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("scan-root");
        let target = root.join("proj").join("target");
        let debug = target.join("debug");
        for sub in ["deps", "incremental", "build", ".fingerprint"] {
            std::fs::create_dir_all(debug.join(sub)).unwrap();
        }
        std::fs::write(
            target.join("CACHEDIR.TAG"),
            "Signature: 8a477f597d28d172789f06886806bc55\n# cargo\n",
        )
        .unwrap();
        std::fs::write(debug.join("deps").join("libx.rlib"), vec![0xA5u8; 4096]).unwrap();
        let old = filetime::FileTime::from_system_time(SystemTime::now() - Duration::from_hours(5));
        set_mtime_recursive(&target, old);
        if std::fs::metadata(&target)
            .and_then(|m| m.created())
            .is_err()
        {
            eprintln!("filesystem reports no birth time; the rule has nothing to hold on to here");
            return;
        }
        // Linux-proven; macOS prescan birth-time parity is bd-awc5 (a
        // just-created tree must not age by its reset mtimes).
        if cfg!(target_os = "linux") {
            assert!(
                prescan_age(&target) < Duration::from_secs(60),
                "a just-created tree is young whatever its mtimes say"
            );
        }
        assert!(
            prescan_age(&debug.join("deps").join("libx.rlib")) >= Duration::from_hours(4),
            "files still age by mtime"
        );

        let mut config = Config::default();
        config.scanner.root_paths = vec![root.clone()];
        config.scanner.min_file_age_minutes = 1;
        config.scanner.active_reference_min_size_bytes = u64::MAX;

        let log_path = temp.path().join("activity.jsonl");
        let (logger, logger_join) = spawn_logger(DualLoggerConfig {
            sqlite_path: None,
            jsonl_config: crate::logger::jsonl::JsonlConfig {
                path: log_path,
                fallback_path: None,
                max_size_bytes: 1_048_576,
                max_rotated_files: 0,
                fsync_interval_secs: 0,
            },
            channel_capacity: 64,
            run_id: None,
        })
        .unwrap();
        let (scan_tx, scan_rx) = bounded::<ScanRequest>(1);
        let (del_tx, del_rx) = bounded::<DeletionBatch>(1);
        let (report_tx, report_rx) = bounded::<WorkerReport>(1);
        let (_index_feedback_tx, index_feedback_rx) = bounded::<ScannerIndexFeedback>(1);
        let cpu_budget = Arc::new(Mutex::new(CpuBudget::new(0, Instant::now(), 0.0)));
        let heartbeat = Arc::new(ThreadHeartbeat::new("test-scanner"));
        let shared_scoring_config = Arc::new(RwLock::new(config.scoring));
        let shared_scanner_config = Arc::new(RwLock::new(config.scanner));
        let platform: Arc<dyn Platform> = Arc::new(MockPlatform::healthy());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (scanner_index_path, prescan_cursor_path) = scanner_state_paths(temp.path());

        scan_tx
            .send(ScanRequest {
                paths: vec![root],
                urgency: 0.9,
                pressure_level: PressureLevel::Orange,
                free_pct: Some(9.0),
                max_delete_batch: 10,
                force_full_scan: false,
                config_update: None,
                catalog_roots: Vec::new(),
                maintenance: false,
                target_bytes: None,
            })
            .unwrap();
        drop(scan_tx);

        scanner_thread_main(
            &scan_rx,
            &del_tx,
            &logger,
            &shared_scoring_config,
            &shared_scanner_config,
            &platform,
            &heartbeat,
            &report_tx,
            &shutdown,
            &scanner_index_path,
            &prescan_cursor_path,
            &index_feedback_rx,
            &cpu_budget,
            &Arc::new(SharedExecutorConfig::new(
                false, 10, 0.0, 60, 3600, false, 0,
            )),
            &Arc::new(SharedRegret::new(&Config::default())),
        );

        assert!(
            del_rx.try_recv().is_err(),
            "a target younger than min_file_age_minutes must not be dispatched by the pre-scan"
        );
        assert!(target.exists());
        let _ = report_rx.try_recv();
        logger.shutdown();
        logger_join.join().unwrap();
    }

    /// bd-awc5 diagnostic: on macOS the prescan reported a just-created tree
    /// (mtimes reset 5 h back) as hours old. This probe always passes; it
    /// prints the measured metadata facts into the CI log so the birth-time
    /// gap can be fixed against numbers instead of inference. When the fix
    /// lands, the non-Linux arm turns into the Linux assertion.
    #[test]
    fn prescan_birth_time_probe_reports_measured_facts() {
        fn set_mtime_recursive(path: &Path, mtime: filetime::FileTime) {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    set_mtime_recursive(&entry.path(), mtime);
                }
            }
            let _ = filetime::set_file_mtime(path, mtime);
        }

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("proj").join("target");
        std::fs::create_dir_all(target.join("debug").join("deps")).unwrap();
        std::fs::write(
            target.join("debug").join("deps").join("libx.rlib"),
            [0xA5u8; 4096],
        )
        .unwrap();
        let old = filetime::FileTime::from_system_time(SystemTime::now() - Duration::from_hours(5));
        set_mtime_recursive(&target, old);

        let meta = std::fs::metadata(&target).unwrap();
        let entry = crate::scanner::walker::entry_metadata(&meta);
        let age = prescan_age(&target);
        eprintln!(
            "bd-awc5 probe: prescan_age={age:?} std_created={:?} std_modified={:?} \
             entry_created={:?} entry_modified={:?} entry_is_dir={}",
            meta.created(),
            meta.modified(),
            entry.created,
            entry.modified,
            entry.is_dir,
        );
        if cfg!(target_os = "linux") {
            assert!(
                age < Duration::from_secs(60),
                "linux contract: a just-created tree is young (age {age:?})"
            );
        }
    }

    /// A slow startup step keeps asking for more time and stops once it
    /// returns; a hung step stops being extended at `max`, so the service
    /// manager's own timeout still fails the start.
    #[test]
    fn startup_extension_repeats_while_the_step_runs_and_stops_after() {
        use crate::platform::pal::ServiceManager;

        #[derive(Clone, Default)]
        struct Recorder(Arc<Mutex<Vec<(Duration, String)>>>);
        impl ServiceManager for Recorder {
            fn install(&self) -> Result<()> {
                Ok(())
            }
            fn uninstall(&self) -> Result<()> {
                Ok(())
            }
            fn status(&self) -> Result<String> {
                Ok("active".to_string())
            }
            fn notify_extend_startup(&self, extend_by: Duration, status: &str) -> Result<()> {
                self.0.lock().push((extend_by, status.to_string()));
                Ok(())
            }
        }

        let extension = StartupExtension {
            extend_by: Duration::from_secs(30),
            every: Duration::from_millis(20),
            max: Duration::from_mins(1),
        };
        let recorder = Recorder::default();
        let never = AtomicBool::new(false);
        let value = with_startup_extension(
            Box::new(recorder.clone()),
            "provisioning ballast",
            extension,
            &never,
            || {
                std::thread::sleep(Duration::from_millis(110));
                7
            },
        );
        assert_eq!(value, 7);
        let calls = recorder.0.lock().len();
        assert!(calls >= 2, "extensions while the step ran: {calls}");
        assert!(
            recorder
                .0
                .lock()
                .iter()
                .all(|(by, status)| *by == Duration::from_secs(30)
                    && status == "provisioning ballast")
        );
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(
            recorder.0.lock().len(),
            calls,
            "none after the step returned"
        );

        let hung = Recorder::default();
        with_startup_extension(
            Box::new(hung.clone()),
            "hung",
            StartupExtension {
                max: Duration::from_millis(50),
                ..extension
            },
            &never,
            || std::thread::sleep(Duration::from_millis(200)),
        );
        let calls = hung.0.lock().len();
        assert!(
            (1..=4).contains(&calls),
            "extensions for a hung step: {calls}"
        );

        // A stop request ends the extensions while the step still runs, so
        // the service manager's stop timeout applies again.
        let stopping = Recorder::default();
        let stop = AtomicBool::new(false);
        with_startup_extension(
            Box::new(stopping.clone()),
            "provisioning ballast",
            extension,
            &stop,
            || {
                std::thread::sleep(Duration::from_millis(50));
                stop.store(true, Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(40));
                let at_stop = stopping.0.lock().len();
                std::thread::sleep(Duration::from_millis(150));
                assert!(
                    stopping.0.lock().len() <= at_stop + 1,
                    "extensions continued after the stop request"
                );
            },
        );
    }

    /// A failure backoff outlives a pass over other roots. hz1, 2026-10-14:
    /// maintenance, per-mount and special-location passes each walk a
    /// different subset of the configured roots, the index was keyed on the
    /// subset and rebuilt on about half the passes, and `~/.cache/uv` (always
    /// refused by the deletion preflight: it holds git checkouts) was planned
    /// 40 times in two hours.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn failure_backoff_survives_a_pass_over_other_roots() {
        use crate::scanner::walker::identity_for_path;

        fn run_pass(
            temp: &Path,
            roots: &[PathBuf],
            pass_root: &Path,
            feedback: Option<ScannerIndexFeedback>,
            label: &str,
        ) -> bool {
            let mut config = Config::default();
            config.scanner.root_paths = roots.to_vec();
            config.scanner.min_file_age_minutes = 0;
            config.scanner.active_reference_min_size_bytes = u64::MAX;

            let (logger, logger_join) = spawn_logger(DualLoggerConfig {
                sqlite_path: None,
                jsonl_config: crate::logger::jsonl::JsonlConfig {
                    path: temp.join(format!("activity-{label}.jsonl")),
                    fallback_path: None,
                    max_size_bytes: 1_048_576,
                    max_rotated_files: 0,
                    fsync_interval_secs: 0,
                },
                channel_capacity: 64,
                run_id: None,
            })
            .unwrap();
            let (scan_tx, scan_rx) = bounded::<ScanRequest>(1);
            let (del_tx, del_rx) = bounded::<DeletionBatch>(4);
            let (report_tx, _report_rx) = bounded::<WorkerReport>(4);
            let (index_feedback_tx, index_feedback_rx) = bounded::<ScannerIndexFeedback>(1);
            if let Some(feedback) = feedback {
                index_feedback_tx.send(feedback).unwrap();
            }
            let executor_config = Arc::new(SharedExecutorConfig::new(
                false, 10, 0.0, 60, 3600, false, 0,
            ));
            executor_config.set_min_certainty(ArtifactCertainty::Likely);
            scan_tx
                .send(ScanRequest {
                    paths: vec![pass_root.to_path_buf()],
                    urgency: 0.9,
                    pressure_level: PressureLevel::Orange,
                    free_pct: Some(9.0),
                    max_delete_batch: 10,
                    force_full_scan: false,
                    config_update: None,
                    catalog_roots: Vec::new(),
                    maintenance: false,
                    target_bytes: None,
                })
                .unwrap();
            drop(scan_tx);

            scanner_thread_main(
                &scan_rx,
                &del_tx,
                &logger,
                &Arc::new(RwLock::new(config.scoring)),
                &Arc::new(RwLock::new(config.scanner)),
                &(Arc::new(MockPlatform::healthy()) as Arc<dyn Platform>),
                &ThreadHeartbeat::new("test-scanner"),
                &report_tx,
                &Arc::new(AtomicBool::new(false)),
                &temp.join("scanner-index.json"),
                &temp.join("prescan-cursor.json"),
                &index_feedback_rx,
                &Arc::new(Mutex::new(CpuBudget::new(0, Instant::now(), 0.0))),
                &executor_config,
                &Arc::new(SharedRegret::new(&Config::default())),
            );
            logger.shutdown();
            logger_join.join().unwrap();
            del_rx.try_recv().is_ok()
        }

        let temp = non_temp_scratch_dir();
        let root_a = temp.path().join("root-a");
        let root_b = temp.path().join("root-b");
        std::fs::create_dir_all(&root_b).unwrap();
        // A definite cargo target: dispatched at Orange on its first walk.
        let project = root_a.join("crate");
        let debug = project.join("target").join("debug");
        for sub in ["deps", "incremental", ".fingerprint"] {
            std::fs::create_dir_all(debug.join(sub)).unwrap();
        }
        std::fs::write(project.join("Cargo.toml"), "[package]\nname = \"crate\"\n").unwrap();
        std::fs::write(
            project.join("target").join("CACHEDIR.TAG"),
            "Signature: 8a477f597d28d172789f06886806bc55\n# cargo\n",
        )
        .unwrap();
        std::fs::write(debug.join("deps").join("libcrate.rlib"), vec![0xA5u8; 8192]).unwrap();
        std::fs::write(debug.join("incremental").join("unit-0"), b"x").unwrap();
        std::fs::write(debug.join(".fingerprint").join("lib-crate"), b"x").unwrap();
        let roots = vec![root_a.clone(), root_b.clone()];

        assert!(
            run_pass(temp.path(), &roots, &root_a, None, "first"),
            "precondition: the target is dispatched on its first walk"
        );
        // The executor refused it (e.g. a preflight veto); the feedback lands
        // while the daemon is relieving a different root.
        let identity = identity_for_path(&project.join("target"), false).unwrap();
        let feedback = ScannerIndexFeedback {
            identity: identity.into(),
            path: project.join("target"),
        };
        assert!(!run_pass(
            temp.path(),
            &roots,
            &root_b,
            Some(feedback),
            "other-root"
        ));
        assert!(
            !run_pass(temp.path(), &roots, &root_a, None, "again"),
            "a refused candidate is not re-dispatched while its backoff runs"
        );
    }

    /// bd-8aeq: a `Delete` verdict below the behavior cell's certainty gate is
    /// not dispatched by the scanner, does not count as a candidate, and leaves
    /// the pass unproductive so the empty-pass cooldown arms. Measured before
    /// the fix: a daemon at Orange re-dispatched the same two `unclear` records
    /// twice a second for five minutes while the executor held them back.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn scanner_certainty_gate_holds_unclear_candidates_and_arms_the_backoff() {
        struct Outcome {
            dispatched: bool,
            reports: Vec<usize>,
            log: String,
        }

        fn run_scan(
            temp: &Path,
            root: &Path,
            min_certainty: ArtifactCertainty,
            requests: usize,
            index_name: &str,
        ) -> Outcome {
            let mut config = Config::default();
            config.scanner.root_paths = vec![root.to_path_buf()];
            config.scanner.min_file_age_minutes = 0;
            config.scanner.active_reference_min_size_bytes = u64::MAX;

            let log_path = temp.join(format!("activity-{index_name}-{requests}.jsonl"));
            let (logger, logger_join) = spawn_logger(DualLoggerConfig {
                sqlite_path: None,
                jsonl_config: crate::logger::jsonl::JsonlConfig {
                    path: log_path.clone(),
                    fallback_path: None,
                    max_size_bytes: 1_048_576,
                    max_rotated_files: 0,
                    fsync_interval_secs: 0,
                },
                channel_capacity: 64,
                run_id: None,
            })
            .unwrap();
            let (scan_tx, scan_rx) = bounded::<ScanRequest>(requests);
            let (del_tx, del_rx) = bounded::<DeletionBatch>(4);
            let (report_tx, report_rx) = bounded::<WorkerReport>(4);
            let (_index_feedback_tx, index_feedback_rx) = bounded::<ScannerIndexFeedback>(1);
            let cpu_budget = Arc::new(Mutex::new(CpuBudget::new(0, Instant::now(), 0.0)));
            let heartbeat = Arc::new(ThreadHeartbeat::new("test-scanner"));
            let shared_scoring_config = Arc::new(RwLock::new(config.scoring));
            let shared_scanner_config = Arc::new(RwLock::new(config.scanner));
            let platform: Arc<dyn Platform> = Arc::new(MockPlatform::healthy());
            let shutdown = Arc::new(AtomicBool::new(false));
            let scanner_index_path = temp.join(index_name);
            let prescan_cursor_path = temp.join("prescan-cursor.json");
            let executor_config = Arc::new(SharedExecutorConfig::new(
                false, 10, 0.0, 60, 3600, false, 0,
            ));
            executor_config.set_min_certainty(min_certainty);

            for _ in 0..requests {
                scan_tx
                    .send(ScanRequest {
                        paths: vec![root.to_path_buf()],
                        urgency: 0.9,
                        pressure_level: PressureLevel::Orange,
                        free_pct: Some(9.0),
                        max_delete_batch: 10,
                        force_full_scan: false,
                        config_update: None,
                        catalog_roots: Vec::new(),
                        maintenance: false,
                        target_bytes: None,
                    })
                    .unwrap();
            }
            drop(scan_tx);

            scanner_thread_main(
                &scan_rx,
                &del_tx,
                &logger,
                &shared_scoring_config,
                &shared_scanner_config,
                &platform,
                &heartbeat,
                &report_tx,
                &shutdown,
                &scanner_index_path,
                &prescan_cursor_path,
                &index_feedback_rx,
                &cpu_budget,
                &executor_config,
                &Arc::new(SharedRegret::new(&Config::default())),
            );
            logger.shutdown();
            logger_join.join().unwrap();

            let dispatched = del_rx.try_recv().is_ok();
            let reports = report_rx
                .try_iter()
                .map(|report| match report {
                    WorkerReport::ScanCompleted { candidates, .. } => candidates,
                    WorkerReport::DeletionCompleted { .. } => {
                        panic!("expected scanner completion reports")
                    }
                })
                .collect();
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            Outcome {
                dispatched,
                reports,
                log,
            }
        }

        let temp = non_temp_scratch_dir();
        let root = temp.path().join("scan-root");
        // `node_modules` beside a package manifest is an opaque candidate whose
        // certainty is `unclear` outside a temp root: no structural marker can
        // prove it, so the verdict is `Delete` at `unclear`.
        let project = root.join("proj");
        let module = project.join("node_modules").join("left-pad");
        std::fs::create_dir_all(&module).unwrap();
        std::fs::write(project.join("package.json"), "{\"name\":\"proj\"}\n").unwrap();
        std::fs::write(module.join("index.js"), vec![b'/'; 8192]).unwrap();

        // Gate open (Red/Critical cells accept `unclear`): the fixture is a
        // dispatchable candidate, which is the precondition for the rest.
        let open = run_scan(
            temp.path(),
            &root,
            ArtifactCertainty::Unclear,
            1,
            "index-open.json",
        );
        assert!(
            open.dispatched,
            "precondition: the fixture must be dispatched when the gate accepts unclear: reports={:?}",
            open.reports
        );
        // The pre-scan and the walk each count the tree once.
        assert!(
            open.reports.len() == 1 && open.reports[0] >= 1,
            "{:?}",
            open.reports
        );

        // Orange cell (`likely` or better): the same tree dispatches nothing,
        // counts no candidate, and the second request is absorbed by the
        // empty-pass cooldown instead of re-walking.
        let held = run_scan(
            temp.path(),
            &root,
            ArtifactCertainty::Likely,
            2,
            "index-held.json",
        );
        assert!(
            !held.dispatched,
            "an unclear candidate must not reach the executor below the gate"
        );
        assert_eq!(
            held.reports,
            vec![0],
            "one unproductive pass, then the cooldown swallows the second request"
        );
        assert!(
            held.log.contains(
                "scanner certainty gate held 1 candidate(s) below likely (pressure=Orange)"
            ),
            "the held count is logged once per path (the pre-scan and the walk both see it): {}",
            held.log
        );

        // The next daemon holds the same tree too. Its event source revokes
        // the record the open run persisted, so the root is reconciled.
        let replayed = run_scan(
            temp.path(),
            &root,
            ArtifactCertainty::Likely,
            1,
            "index-open.json",
        );
        assert!(!replayed.dispatched);
        assert_eq!(replayed.reports, vec![0]);
        assert!(
            replayed.log.contains(
                "scanner certainty gate held 1 candidate(s) below likely (pressure=Orange)"
            ),
            "the pre-scan and the walk hold one path: {}",
            replayed.log
        );

        // The second half of the bug: a definite cargo target (markers under
        // `debug/`, `CACHEDIR.TAG`) is walked as an opaque candidate, and its
        // index replay must keep that evidence. Before the fix the replay
        // re-classified the root from its own entries, came out `unclear`,
        // and the Orange cell held it forever.
        let cargo_root = temp.path().join("cargo-root");
        let cargo_project = cargo_root.join("crate");
        let target = cargo_project.join("target");
        let debug = target.join("debug");
        for sub in ["deps", "incremental", ".fingerprint"] {
            std::fs::create_dir_all(debug.join(sub)).unwrap();
        }
        std::fs::write(
            cargo_project.join("Cargo.toml"),
            "[package]\nname = \"crate\"\n",
        )
        .unwrap();
        std::fs::write(
            target.join("CACHEDIR.TAG"),
            "Signature: 8a477f597d28d172789f06886806bc55\n# cargo\n",
        )
        .unwrap();
        std::fs::write(debug.join("deps").join("libcrate.rlib"), vec![0xA5u8; 8192]).unwrap();
        std::fs::write(debug.join("incremental").join("unit-0"), b"x").unwrap();
        std::fs::write(debug.join(".fingerprint").join("lib-crate"), b"x").unwrap();

        let walked = run_scan(
            temp.path(),
            &cargo_root,
            ArtifactCertainty::Likely,
            1,
            "index-cargo.json",
        );
        assert!(
            walked.dispatched,
            "a definite target passes the Orange gate on the walk: {:?}",
            walked.reports
        );
        let replayed_target = run_scan(
            temp.path(),
            &cargo_root,
            ArtifactCertainty::Likely,
            1,
            "index-cargo.json",
        );
        // A fresh event source revokes the evidence saved before it started
        // (`BackendRestart` on Linux, the FSEvents startup replan on macOS;
        // by design, see README "What feeds the index"), so a new daemon
        // reconciles the root instead of replaying the record. The certainty
        // assertions below hold either way.
        if cfg!(target_os = "linux") {
            assert!(
                replayed_target.log.contains("replayed_records=0")
                    && replayed_target.log.contains("reason=BackendRestart"),
                "a fresh daemon revokes evidence saved before it started instead of replaying it: {}",
                replayed_target.log
            );
        }
        assert!(
            replayed_target.dispatched,
            "the target keeps its definite certainty on the next daemon's pass and is dispatched again: {}",
            replayed_target.log
        );
        assert!(
            !replayed_target.log.contains("scanner certainty gate held "),
            "{}",
            replayed_target.log
        );

        // Dispatch without reclaim is not progress: nothing bumps the
        // executor's reclaim counter here (as in dry-run or observe mode),
        // so the second request is paced as if the first pass were empty.
        let paced = run_scan(
            temp.path(),
            &cargo_root,
            ArtifactCertainty::Likely,
            2,
            "index-cargo.json",
        );
        assert!(paced.dispatched);
        assert_eq!(
            paced.reports.len(),
            1,
            "the unconfirmed dispatch arms the cooldown: {:?}",
            paced.reports
        );
    }

    #[test]
    fn forced_v2_green_scan_walks_roots_and_logs_telemetry() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("scan-root").join("demo");
        let target = root.join("target");
        std::fs::create_dir_all(target.join("debug").join("deps").join("crate_000")).unwrap();
        std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
        std::fs::write(
            target
                .join("debug")
                .join("deps")
                .join("crate_000")
                .join("libdemo.rlib"),
            b"fake artifact\n",
        )
        .unwrap();

        let mut config = Config::default();
        config.scanner.engine = ScannerEngineMode::V2;
        config.scanner.root_paths = vec![root.clone()];
        config.scanner.min_file_age_minutes = 0;
        config.scanner.parallelism = 1;
        config.scanner.active_reference_min_size_bytes = u64::MAX;

        let log_path = temp.path().join("activity.jsonl");
        let (logger, logger_join) = spawn_logger(DualLoggerConfig {
            sqlite_path: None,
            jsonl_config: JsonlConfig {
                path: log_path.clone(),
                fallback_path: None,
                max_size_bytes: 1_048_576,
                max_rotated_files: 0,
                fsync_interval_secs: 0,
            },
            channel_capacity: 64,
            run_id: None,
        })
        .unwrap();
        let (scan_tx, scan_rx) = bounded::<ScanRequest>(1);
        let (del_tx, _del_rx) = bounded::<DeletionBatch>(1);
        let (report_tx, report_rx) = bounded::<WorkerReport>(1);
        let (_index_feedback_tx, index_feedback_rx) = bounded::<ScannerIndexFeedback>(1);
        let cpu_budget = Arc::new(Mutex::new(CpuBudget::new(0, Instant::now(), 0.0)));
        let heartbeat = Arc::new(ThreadHeartbeat::new("test-scanner"));
        let shared_scoring_config = Arc::new(RwLock::new(config.scoring));
        let shared_scanner_config = Arc::new(RwLock::new(config.scanner));
        let platform: Arc<dyn Platform> = Arc::new(MockPlatform::healthy());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (scanner_index_path, prescan_cursor_path) = scanner_state_paths(temp.path());

        scan_tx
            .send(ScanRequest {
                paths: vec![root],
                urgency: 0.5,
                pressure_level: PressureLevel::Green,
                free_pct: Some(50.0),
                max_delete_batch: 10,
                force_full_scan: true,
                config_update: None,
                catalog_roots: Vec::new(),
                maintenance: false,
                target_bytes: None,
            })
            .unwrap();
        drop(scan_tx);

        scanner_thread_main(
            &scan_rx,
            &del_tx,
            &logger,
            &shared_scoring_config,
            &shared_scanner_config,
            &platform,
            &heartbeat,
            &report_tx,
            &shutdown,
            &scanner_index_path,
            &prescan_cursor_path,
            &index_feedback_rx,
            &cpu_budget,
            &Arc::new(SharedExecutorConfig::new(
                false, 10, 0.0, 60, 3600, false, 0,
            )),
            &Arc::new(SharedRegret::new(&Config::default())),
        );

        let report = report_rx
            .try_recv()
            .expect("forced v2 scan should report completion");
        assert!(
            matches!(&report, WorkerReport::ScanCompleted {
                root_stats,
                pressure_level: PressureLevel::Green,
                ..
            } if root_stats.len() == 1),
            "forced Green scan reports one root at Green: {report:?}"
        );

        logger.shutdown();
        logger_join.join().unwrap();

        let contents = std::fs::read_to_string(log_path).unwrap();
        assert!(contents.contains("\"event\":\"scan_complete\""));
        assert!(contents.contains("engine=v2"));
        assert!(contents.contains("reason=forced"));
        assert!(contents.contains("opaque_pruning=true"));
        assert!(contents.contains("opaque_pruned_dirs=1"));
    }

    #[test]
    fn behavior_state_updates_memory_and_disk_matrix_cells() {
        let mut state = PressureBehaviorState::new(
            BehaviorDispatchTable::default(),
            MemoryPressureLevel::Normal,
            PressureLevel::Green,
        );
        assert_eq!(state.mode.scan_aggressiveness, ScanAggressiveness::Normal);

        let memory_transition = state
            .update(MemoryPressureLevel::Warn, PressureLevel::Green)
            .expect("warn memory should change behavior");
        assert_eq!(memory_transition.from_memory, MemoryPressureLevel::Normal);
        assert_eq!(memory_transition.to_memory, MemoryPressureLevel::Warn);
        assert_eq!(state.mode.scan_aggressiveness, ScanAggressiveness::Light);
        // Memory pressure lowers scanning, never the cleanup posture (v0.6 rule).
        assert_eq!(
            state.mode.cleanup_action,
            CleanupAction::HighConfidenceCandidates
        );

        let disk_transition = state
            .update(MemoryPressureLevel::Warn, PressureLevel::Red)
            .expect("red disk should change behavior");
        assert_eq!(disk_transition.from_disk, PressureLevel::Green);
        assert_eq!(disk_transition.to_disk, PressureLevel::Red);
        assert_eq!(
            state.mode.cleanup_action,
            CleanupAction::AnyDefiniteCandidate
        );
        assert_eq!(state.mode.ballast_action, BallastAction::ReleaseFirst);
    }

    #[test]
    fn critical_memory_and_disk_transition_builds_emergency_notification() {
        let mut state = PressureBehaviorState::new(
            BehaviorDispatchTable::default(),
            MemoryPressureLevel::Warn,
            PressureLevel::Yellow,
        );
        let transition = state
            .update(MemoryPressureLevel::Critical, PressureLevel::Critical)
            .expect("critical memory plus critical disk should enter emergency cell");

        let event = behavior_emergency_event("memory_pressure", &transition)
            .expect("critical+critical behavior transition should notify");

        assert_eq!(event.level(), NotificationLevel::Critical);
        assert_eq!(event.type_key(), "behavior_emergency");
        let summary = event.summary();
        assert!(summary.contains("memory=Critical"));
        assert!(summary.contains("disk=Critical"));
        assert!(summary.contains("ReleaseFirst"));
    }

    #[test]
    fn non_emergency_behavior_transition_does_not_build_notification() {
        let mut state = PressureBehaviorState::new(
            BehaviorDispatchTable::default(),
            MemoryPressureLevel::Normal,
            PressureLevel::Green,
        );
        let transition = state
            .update(MemoryPressureLevel::Warn, PressureLevel::Yellow)
            .expect("warning behavior should transition");

        assert!(behavior_emergency_event("memory_pressure", &transition).is_none());
    }

    #[test]
    fn behavior_hysteresis_defers_repeated_escalations() {
        let t0 = Instant::now();
        let hysteresis = Duration::from_secs(5);
        let mut state = PressureBehaviorState::new(
            BehaviorDispatchTable::default(),
            MemoryPressureLevel::Normal,
            PressureLevel::Green,
        );

        match state.update_with_hysteresis(
            MemoryPressureLevel::Warn,
            PressureLevel::Green,
            t0,
            hysteresis,
        ) {
            BehaviorUpdate::Applied(transition) => {
                assert_eq!(transition.to_memory, MemoryPressureLevel::Warn);
            }
            other => panic!("first escalation should apply immediately: {other:?}"),
        }

        match state.update_with_hysteresis(
            MemoryPressureLevel::Critical,
            PressureLevel::Green,
            t0 + Duration::from_secs(1),
            hysteresis,
        ) {
            BehaviorUpdate::Deferred {
                direction,
                remaining,
                repeated,
            } => {
                assert_eq!(direction, BehaviorTransitionDirection::Escalating);
                assert_eq!(remaining, Duration::from_secs(4));
                assert!(!repeated, "a new target's deferral is logged");
            }
            other => panic!("second escalation should be deferred: {other:?}"),
        }
        assert_eq!(state.memory_level, MemoryPressureLevel::Warn);

        match state.update_with_hysteresis(
            MemoryPressureLevel::Critical,
            PressureLevel::Green,
            t0 + hysteresis,
            hysteresis,
        ) {
            BehaviorUpdate::Applied(transition) => {
                assert_eq!(transition.from_memory, MemoryPressureLevel::Warn);
                assert_eq!(transition.to_memory, MemoryPressureLevel::Critical);
            }
            other => panic!("deferred escalation should apply after hysteresis: {other:?}"),
        }
        assert_eq!(state.memory_level, MemoryPressureLevel::Critical);
    }

    #[test]
    fn behavior_hysteresis_defers_repeated_recoveries() {
        let t0 = Instant::now();
        let hysteresis = Duration::from_secs(5);
        let mut state = PressureBehaviorState::new(
            BehaviorDispatchTable::default(),
            MemoryPressureLevel::Critical,
            PressureLevel::Critical,
        );

        match state.update_with_hysteresis(
            MemoryPressureLevel::Warn,
            PressureLevel::Critical,
            t0,
            hysteresis,
        ) {
            BehaviorUpdate::Applied(transition) => {
                assert_eq!(transition.to_memory, MemoryPressureLevel::Warn);
                assert_eq!(transition.to_disk, PressureLevel::Critical);
            }
            other => panic!("first recovery should apply immediately: {other:?}"),
        }

        match state.update_with_hysteresis(
            MemoryPressureLevel::Normal,
            PressureLevel::Green,
            t0 + Duration::from_secs(1),
            hysteresis,
        ) {
            BehaviorUpdate::Deferred {
                direction,
                remaining,
                repeated,
            } => {
                assert_eq!(direction, BehaviorTransitionDirection::Recovering);
                assert_eq!(remaining, Duration::from_secs(4));
                assert!(!repeated, "a new target's deferral is logged");
            }
            other => panic!("second recovery should be deferred: {other:?}"),
        }
        assert_eq!(state.memory_level, MemoryPressureLevel::Warn);
        assert_eq!(state.disk_level, PressureLevel::Critical);

        match state.update_with_hysteresis(
            MemoryPressureLevel::Normal,
            PressureLevel::Green,
            t0 + hysteresis,
            hysteresis,
        ) {
            BehaviorUpdate::Applied(transition) => {
                assert_eq!(transition.from_memory, MemoryPressureLevel::Warn);
                assert_eq!(transition.to_memory, MemoryPressureLevel::Normal);
                assert_eq!(transition.to_disk, PressureLevel::Green);
            }
            other => panic!("deferred recovery should apply after hysteresis: {other:?}"),
        }
    }

    #[test]
    fn behavior_hysteresis_cancels_stale_pending_target() {
        let t0 = Instant::now();
        let hysteresis = Duration::from_secs(5);
        let mut state = PressureBehaviorState::new(
            BehaviorDispatchTable::default(),
            MemoryPressureLevel::Normal,
            PressureLevel::Green,
        );

        assert!(
            state
                .update_with_hysteresis(
                    MemoryPressureLevel::Warn,
                    PressureLevel::Green,
                    t0,
                    hysteresis,
                )
                .into_transition()
                .is_some()
        );

        match state.update_with_hysteresis(
            MemoryPressureLevel::Critical,
            PressureLevel::Green,
            t0 + Duration::from_secs(1),
            hysteresis,
        ) {
            BehaviorUpdate::Deferred {
                direction,
                remaining,
                repeated,
            } => {
                assert_eq!(direction, BehaviorTransitionDirection::Escalating);
                assert_eq!(remaining, Duration::from_secs(4));
                assert!(!repeated, "a new target's deferral is logged");
            }
            other => panic!("second escalation should be deferred: {other:?}"),
        }

        match state.update_with_hysteresis(
            MemoryPressureLevel::Warn,
            PressureLevel::Green,
            t0 + hysteresis,
            hysteresis,
        ) {
            BehaviorUpdate::Unchanged => {}
            other => {
                panic!("current observed pressure should cancel stale pending target: {other:?}")
            }
        }
        assert_eq!(state.memory_level, MemoryPressureLevel::Warn);
        assert_eq!(state.disk_level, PressureLevel::Green);

        assert!(matches!(
            state.update_with_hysteresis(
                MemoryPressureLevel::Warn,
                PressureLevel::Green,
                t0 + hysteresis + Duration::from_secs(1),
                hysteresis,
            ),
            BehaviorUpdate::Unchanged
        ));
        assert_eq!(state.memory_level, MemoryPressureLevel::Warn);
    }

    #[test]
    fn a_deferred_memory_target_survives_disk_ticks_until_its_window_ends() {
        let t0 = Instant::now();
        let hysteresis = Duration::from_secs(5);
        let mut state = PressureBehaviorState::new(
            BehaviorDispatchTable::default(),
            MemoryPressureLevel::Normal,
            PressureLevel::Green,
        );
        assert!(matches!(
            state.update_with_hysteresis(
                MemoryPressureLevel::Warn,
                PressureLevel::Green,
                t0,
                hysteresis,
            ),
            BehaviorUpdate::Applied(_)
        ));
        assert!(matches!(
            state.update_with_hysteresis(
                MemoryPressureLevel::Critical,
                PressureLevel::Green,
                t0 + Duration::from_secs(1),
                hysteresis,
            ),
            BehaviorUpdate::Deferred {
                repeated: false,
                ..
            }
        ));
        assert_eq!(state.latest_memory_level(), MemoryPressureLevel::Critical);

        // A disk tick inside the window re-defers without logging again and
        // keeps the target the subscription will not report a second time.
        assert!(matches!(
            state.update_with_hysteresis(
                state.latest_memory_level(),
                PressureLevel::Green,
                t0 + Duration::from_secs(2),
                hysteresis,
            ),
            BehaviorUpdate::Deferred { repeated: true, .. }
        ));
        assert_eq!(state.memory_level, MemoryPressureLevel::Warn);
        assert_eq!(state.latest_memory_level(), MemoryPressureLevel::Critical);

        // So does a matrix reload.
        assert!(
            state
                .replace_table(BehaviorDispatchTable::default())
                .is_none()
        );
        assert_eq!(state.latest_memory_level(), MemoryPressureLevel::Critical);

        match state.update_with_hysteresis(
            state.latest_memory_level(),
            PressureLevel::Green,
            t0 + hysteresis,
            hysteresis,
        ) {
            BehaviorUpdate::Applied(transition) => {
                assert_eq!(transition.from_memory, MemoryPressureLevel::Warn);
                assert_eq!(transition.to_memory, MemoryPressureLevel::Critical);
            }
            other => panic!("the first tick after the window should apply it: {other:?}"),
        }
        assert!(!state.has_pending_target());
    }

    #[cfg(unix)]
    #[test]
    fn the_sleep_loop_applies_a_deferred_memory_transition_without_a_new_event() {
        // A signal raised by another test would end the sleep early.
        let _serial = crate::daemon::signals::process_signal_test_guard();
        let mut fixture = RegretDaemonFixture::new();
        let daemon = &mut fixture.daemon;
        daemon.config.pressure.behavior_hysteresis_secs = 1;
        daemon.behavior_state = PressureBehaviorState::new(
            behavior_table_from_config(&daemon.config),
            MemoryPressureLevel::Normal,
            PressureLevel::Green,
        );
        let disk = PressureLevel::Green;
        daemon.update_behavior_mode(
            MemoryPressureLevel::Warn,
            disk,
            "memory_pressure",
            Duration::ZERO,
        );
        daemon.update_behavior_mode(
            MemoryPressureLevel::Critical,
            disk,
            "memory_pressure",
            Duration::ZERO,
        );
        assert_eq!(
            daemon.behavior_state.memory_level,
            MemoryPressureLevel::Warn,
            "a second escalation inside the window waits"
        );

        // The subscription reports a level once, so no event follows.
        let (_tx, rx) = bounded::<MemoryPressureEvent>(1);
        daemon.sleep_with_memory_pressure_events(&rx, disk, Duration::from_millis(1_500));
        assert_eq!(
            daemon.behavior_state.memory_level,
            MemoryPressureLevel::Critical
        );
        assert!(!daemon.behavior_state.has_pending_target());
    }

    fn mock_memory_pressure(level: MemoryPressureLevel) -> MemoryPressure {
        MemoryPressure {
            level,
            free_pages: None,
            used_pages: None,
            page_size_bytes: None,
            compressor_used_bytes: None,
            swap_total_bytes: None,
            swap_used_bytes: None,
            linux_psi_avg10: None,
        }
    }

    struct MockMatrixCase {
        memory: MemoryPressureLevel,
        disk: PressureLevel,
        mode: BehaviorMode,
        allows_scan: bool,
        delete_limit: usize,
        releases_ballast: bool,
    }

    fn mock_behavior_mode(
        scan_aggressiveness: ScanAggressiveness,
        cleanup_action: CleanupAction,
        ballast_action: BallastAction,
        notification_priority: NotificationPriority,
    ) -> BehaviorMode {
        BehaviorMode {
            scan_aggressiveness,
            cleanup_action,
            ballast_action,
            notification_priority,
        }
    }

    fn assert_mock_matrix_case(
        state: &mut PressureBehaviorState,
        tx: &Sender<MemoryPressureEvent>,
        rx: &Receiver<MemoryPressureEvent>,
        case: &MockMatrixCase,
        configured_limit: usize,
    ) {
        tx.try_send(MemoryPressureEvent {
            pressure: mock_memory_pressure(case.memory),
            received_at: Instant::now(),
        })
        .expect("mock event channel should accept event");
        let event = rx.try_recv().expect("mock event should be queued");
        let transition = state
            .update(event.pressure.level, case.disk)
            .expect("mock pressure event should change the behavior cell");

        assert_eq!(transition.to_memory, case.memory);
        assert_eq!(transition.to_disk, case.disk);
        assert_eq!(transition.to_mode, state.mode);
        assert_eq!(state.mode, case.mode);
        assert_eq!(behavior_allows_scan(state.mode), case.allows_scan);
        assert_eq!(
            behavior_delete_batch_limit(state.mode, configured_limit),
            case.delete_limit
        );
        assert_eq!(
            behavior_should_release_ballast(state.mode),
            case.releases_ballast
        );
    }

    #[test]
    fn mock_memory_pressure_events_drive_matrix_actions() {
        use BallastAction::{None as NoBallast, ReleaseFirst};
        use CleanupAction::{AnyDefiniteCandidate, HighConfidenceCandidates};
        use MemoryPressureLevel::{Critical as MemoryCritical, Normal as MemoryNormal, Warn};
        use NotificationPriority::{Emergency, High, Low, Normal as NotifyNormal};
        use PressureLevel::{Critical as DiskCritical, Green, Yellow};
        use ScanAggressiveness::{Aggressive, DefiniteOnly, Light, Skip};

        let (tx, rx) = bounded::<MemoryPressureEvent>(8);
        let mut state = PressureBehaviorState::new(
            BehaviorDispatchTable::default(),
            MemoryPressureLevel::Normal,
            PressureLevel::Green,
        );
        let configured_limit = 17;
        let cases = [
            MockMatrixCase {
                memory: Warn,
                disk: Green,
                mode: mock_behavior_mode(Light, HighConfidenceCandidates, NoBallast, Low),
                allows_scan: true,
                delete_limit: configured_limit,
                releases_ballast: false,
            },
            MockMatrixCase {
                memory: Warn,
                disk: Yellow,
                mode: mock_behavior_mode(Light, HighConfidenceCandidates, NoBallast, NotifyNormal),
                allows_scan: true,
                delete_limit: configured_limit,
                releases_ballast: false,
            },
            MockMatrixCase {
                memory: MemoryCritical,
                disk: Yellow,
                mode: mock_behavior_mode(DefiniteOnly, HighConfidenceCandidates, NoBallast, High),
                allows_scan: true,
                delete_limit: configured_limit,
                releases_ballast: false,
            },
            MockMatrixCase {
                memory: MemoryCritical,
                disk: DiskCritical,
                mode: mock_behavior_mode(
                    DefiniteOnly,
                    AnyDefiniteCandidate,
                    ReleaseFirst,
                    Emergency,
                ),
                allows_scan: true,
                delete_limit: configured_limit,
                releases_ballast: true,
            },
            MockMatrixCase {
                memory: MemoryCritical,
                disk: Green,
                // Scanning is skipped; the cleanup posture still never drops
                // below the normal-memory row.
                mode: mock_behavior_mode(Skip, HighConfidenceCandidates, NoBallast, NotifyNormal),
                allows_scan: false,
                delete_limit: configured_limit,
                releases_ballast: false,
            },
            MockMatrixCase {
                memory: MemoryNormal,
                disk: Yellow,
                mode: mock_behavior_mode(Aggressive, HighConfidenceCandidates, NoBallast, Low),
                allows_scan: true,
                delete_limit: configured_limit,
                releases_ballast: false,
            },
        ];

        for case in &cases {
            assert_mock_matrix_case(&mut state, &tx, &rx, case, configured_limit);
        }
    }

    #[test]
    fn behavior_delete_batch_limit_blocks_identify_only_cleanup() {
        // The v0.5 rollback preset keeps Yellow/Orange identify-only.
        let legacy =
            BehaviorDispatchTable::from_preset(crate::daemon::policy::BehaviorPreset::V0_5);
        let identify_only = legacy.mode_for(MemoryPressureLevel::Normal, PressureLevel::Orange);
        assert_eq!(identify_only.cleanup_action, CleanupAction::IdentifyOnly);
        assert_eq!(behavior_delete_batch_limit(identify_only, 5), 0);

        let cleanup = legacy.mode_for(MemoryPressureLevel::Warn, PressureLevel::Red);
        assert_eq!(cleanup.cleanup_action, CleanupAction::DefiniteCandidates);
        assert_eq!(behavior_delete_batch_limit(cleanup, 20), 20);

        // The v0.6 default dispatches at Orange: this is the whole point of the
        // preset change (the daemon used to identify-only until Red).
        let current = BehaviorDispatchTable::default();
        let orange = current.mode_for(MemoryPressureLevel::Normal, PressureLevel::Orange);
        assert_eq!(behavior_delete_batch_limit(orange, 5), 5);
        assert!(behavior_should_release_ballast(orange));
    }

    #[test]
    fn certainty_gate_follows_the_behavior_cell_and_holds_back_uncertain_candidates() {
        // Cell -> minimum certainty mapping.
        assert_eq!(
            min_certainty_for(CleanupAction::HighConfidenceCandidates),
            ArtifactCertainty::Definite
        );
        assert_eq!(
            min_certainty_for(CleanupAction::DefiniteCandidates),
            ArtifactCertainty::Likely
        );
        assert_eq!(
            min_certainty_for(CleanupAction::MostPromisingCandidates),
            ArtifactCertainty::Likely
        );
        assert_eq!(
            min_certainty_for(CleanupAction::AnyDefiniteCandidate),
            ArtifactCertainty::Unclear
        );
        let table = BehaviorDispatchTable::default();
        for (disk, expected) in [
            (PressureLevel::Green, ArtifactCertainty::Definite),
            (PressureLevel::Yellow, ArtifactCertainty::Definite),
            (PressureLevel::Orange, ArtifactCertainty::Likely),
            (PressureLevel::Red, ArtifactCertainty::Unclear),
            (PressureLevel::Critical, ArtifactCertainty::Unclear),
        ] {
            let cell = table.mode_for(MemoryPressureLevel::Normal, disk);
            assert_eq!(min_certainty_for(cell.cleanup_action), expected, "{disk:?}");
        }

        // The shared config carries the gate to the executor thread.
        let shared = SharedExecutorConfig::new(false, 10, 0.5, 300, 3600, true, 86_400);
        assert_eq!(shared.min_certainty(), ArtifactCertainty::Unclear);
        shared.set_min_certainty(ArtifactCertainty::Likely);
        assert_eq!(shared.min_certainty(), ArtifactCertainty::Likely);

        // Filtering keeps order and counts what was held back.
        let mut definite = test_candidate("/tmp/definite", 2.0);
        definite.decision.certainty = ArtifactCertainty::Definite;
        let mut likely = test_candidate("/tmp/likely", 1.5);
        likely.decision.certainty = ArtifactCertainty::Likely;
        let mut unclear = test_candidate("/tmp/unclear", 1.2);
        unclear.decision.certainty = ArtifactCertainty::Unclear;
        let batch = vec![definite.clone(), likely.clone(), unclear];

        let (kept, held) =
            retain_dispatchable_by_certainty(batch.clone(), ArtifactCertainty::Definite);
        assert_eq!(held, 2);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].path, definite.path);

        let (kept, held) =
            retain_dispatchable_by_certainty(batch.clone(), ArtifactCertainty::Likely);
        assert_eq!(held, 1);
        assert_eq!(
            kept.iter().map(|c| c.path.clone()).collect::<Vec<_>>(),
            vec![definite.path, likely.path]
        );

        let (kept, held) = retain_dispatchable_by_certainty(batch, ArtifactCertainty::Unclear);
        assert_eq!(held, 0);
        assert_eq!(kept.len(), 3);
    }

    #[test]
    fn dispatch_top_candidates_identifies_without_deletion_when_batch_limit_is_zero() {
        let (del_tx, del_rx) = bounded::<DeletionBatch>(1);
        let request = ScanRequest {
            paths: vec![PathBuf::from("/tmp")],
            urgency: 0.5,
            pressure_level: PressureLevel::Yellow,
            free_pct: None,
            max_delete_batch: 0,
            force_full_scan: false,
            config_update: None,
            catalog_roots: Vec::new(),
            maintenance: false,
            target_bytes: None,
        };
        let mut scored = vec![test_candidate("/tmp/a", 0.4), test_candidate("/tmp/b", 0.6)];

        assert!(dispatch_top_candidates(
            &mut scored,
            &request,
            &del_tx,
            &mut PassDispatch::default()
        ));
        assert!(
            scored.is_empty(),
            "expected no scored candidates, got {}",
            scored.len()
        );
        assert!(del_rx.try_recv().is_err());
    }

    /// Empty candidates are never sent to the executor: the planner never
    /// chooses them, and each one cost a policy evaluation and a decision_log
    /// row per pass (ts2 2026-10-17: ~250,000 rows a day at Critical).
    #[test]
    fn dispatch_top_candidates_drops_candidates_that_free_nothing() {
        let (del_tx, del_rx) = bounded::<DeletionBatch>(2);
        let request = ScanRequest {
            paths: vec![PathBuf::from("/tmp")],
            urgency: 1.0,
            pressure_level: PressureLevel::Critical,
            free_pct: None,
            max_delete_batch: 10,
            force_full_scan: false,
            config_update: None,
            catalog_roots: Vec::new(),
            maintenance: false,
            target_bytes: None,
        };
        let empty = |path: &str| CandidacyScore {
            size_bytes: 0,
            ..test_candidate(path, 0.9)
        };

        let mut scored = vec![empty("/tmp/empty-a"), empty("/tmp/empty-b")];
        assert!(dispatch_top_candidates(
            &mut scored,
            &request,
            &del_tx,
            &mut PassDispatch::default()
        ));
        assert!(scored.is_empty());
        assert!(
            del_rx.try_recv().is_err(),
            "a batch of only empty candidates is not sent"
        );

        let mut scored = vec![empty("/tmp/empty-c"), test_candidate("/tmp/full", 0.5)];
        assert!(dispatch_top_candidates(
            &mut scored,
            &request,
            &del_tx,
            &mut PassDispatch::default()
        ));
        let batch = del_rx.try_recv().expect("the non-empty candidate is sent");
        let paths: Vec<_> = batch.candidates.iter().map(|c| c.path.clone()).collect();
        assert_eq!(paths, vec![PathBuf::from("/tmp/full")]);
    }

    #[derive(Debug, serde::Serialize)]
    struct PressureLatencyValidationArtifact {
        schema_version: u32,
        scenario: &'static str,
        memory_pressure_wake_interval_ms: u128,
        transition_latency_budget_ms: u128,
        meets_budget: bool,
    }

    #[test]
    fn memory_pressure_wake_interval_meets_transition_latency_budget() {
        assert!(MEMORY_PRESSURE_WAKE_INTERVAL <= Duration::from_millis(500));
    }

    #[test]
    fn pressure_latency_validation_artifact_is_machine_readable() {
        let budget = Duration::from_millis(500);
        let artifact = PressureLatencyValidationArtifact {
            schema_version: 1,
            scenario: "memory-pressure-transition",
            memory_pressure_wake_interval_ms: MEMORY_PRESSURE_WAKE_INTERVAL.as_millis(),
            transition_latency_budget_ms: budget.as_millis(),
            meets_budget: MEMORY_PRESSURE_WAKE_INTERVAL <= budget,
        };
        let payload = serde_json::to_value(&artifact).unwrap();

        assert_eq!(payload["schema_version"].as_u64(), Some(1));
        assert_eq!(
            payload["scenario"].as_str(),
            Some("memory-pressure-transition")
        );
        assert!(artifact.meets_budget);
        eprintln!(
            "scanner_v2_pressure_latency_validation_artifact={}",
            serde_json::to_string(&artifact).unwrap()
        );
    }

    #[test]
    fn thread_health_allows_initial_respawns() {
        let mut health = ThreadHealth::new();
        assert!(health.record_panic());
        assert!(health.record_panic());
        assert!(health.record_panic());
        assert!(!health.record_panic()); // 4th panic exceeds limit
    }

    #[test]
    fn full_disk_access_grant_transition_logs_success_once() {
        let status = FullDiskAccessStatus {
            state: FullDiskAccessState::Granted,
            probe_path: Some(PathBuf::from(
                "/Users/me/Library/Mail/V10/MailData/Envelope Index",
            )),
            detail: "Mail Envelope Index was readable".to_string(),
            cache_ttl_seconds: 60,
            cached: false,
        };

        let first = full_disk_access_status_log_message(&status, None, false)
            .expect("initial granted state should log");
        assert!(first.contains("Full Disk Access granted"));

        assert!(
            full_disk_access_status_log_message(&status, Some(FullDiskAccessState::Granted), true,)
                .is_none(),
            "unchanged granted state should not spam logs"
        );
    }

    #[test]
    fn full_disk_access_missing_logs_recheck_guidance_once() {
        let status = FullDiskAccessStatus {
            state: FullDiskAccessState::Missing,
            probe_path: Some(PathBuf::from(
                "/Users/me/Library/Mail/V10/MailData/Envelope Index",
            )),
            detail: "permission denied while reading Mail Envelope Index".to_string(),
            cache_ttl_seconds: 60,
            cached: false,
        };

        let first = full_disk_access_status_log_message(&status, None, false)
            .expect("initial missing state should log");
        assert!(first.contains("sbh doctor --pal"));

        assert!(
            full_disk_access_status_log_message(
                &status,
                Some(FullDiskAccessState::Missing),
                false,
            )
            .is_none(),
            "unchanged missing state should not spam logs"
        );
    }

    #[test]
    fn daemon_activity_error_code_uses_actual_error_variant() {
        let pal_error = SbhError::from(PalError::method_failed(
            "macos",
            "memory_pressure",
            "host_statistics64 failed",
        ));
        assert_eq!(daemon_activity_error_code(&pal_error), "SBH-1102");

        let unsupported = SbhError::UnsupportedPlatform {
            details: "unsupported operating system 'plan9'".to_string(),
        };
        assert_eq!(daemon_activity_error_code(&unsupported), "SBH-1101");
    }

    #[test]
    fn scan_request_serializes_correctly() {
        let request = ScanRequest {
            paths: vec![PathBuf::from("/tmp"), PathBuf::from("/data/projects")],
            urgency: 0.7,
            pressure_level: PressureLevel::Orange,
            free_pct: Some(8.5),
            max_delete_batch: 10,
            force_full_scan: false,
            config_update: None,
            catalog_roots: Vec::new(),
            maintenance: false,
            target_bytes: None,
        };
        assert_eq!(request.paths.len(), 2);
        assert_eq!(request.urgency.to_bits(), 0.7_f64.to_bits());
        assert_eq!(request.free_pct, Some(8.5));
    }

    #[test]
    fn fallback_log_truncation_free_pct_is_conservative_before_orange() {
        assert_eq!(
            fallback_log_truncation_free_pct(PressureLevel::Green).to_bits(),
            100.0_f64.to_bits()
        );
        assert_eq!(
            fallback_log_truncation_free_pct(PressureLevel::Yellow).to_bits(),
            100.0_f64.to_bits()
        );
        assert_eq!(
            fallback_log_truncation_free_pct(PressureLevel::Orange).to_bits(),
            10.0_f64.to_bits()
        );
        assert_eq!(
            fallback_log_truncation_free_pct(PressureLevel::Critical).to_bits(),
            0.0_f64.to_bits()
        );
    }

    #[test]
    fn log_truncation_free_pct_prefers_actual_scan_pressure() {
        let request = ScanRequest {
            paths: vec![PathBuf::from("/tmp")],
            urgency: 0.4,
            pressure_level: PressureLevel::Yellow,
            free_pct: Some(18.0),
            max_delete_batch: 0,
            force_full_scan: false,
            config_update: None,
            catalog_roots: Vec::new(),
            maintenance: false,
            target_bytes: None,
        };
        assert_eq!(
            log_truncation_free_pct_for_request(&request).to_bits(),
            18.0_f64.to_bits()
        );

        let missing_free_pct = ScanRequest {
            free_pct: None,
            ..request
        };
        assert_eq!(
            log_truncation_free_pct_for_request(&missing_free_pct).to_bits(),
            100.0_f64.to_bits()
        );
    }

    #[test]
    fn daemon_args_default() {
        let args = DaemonArgs::default();
        assert!(args.foreground);
        assert!(args.pidfile.is_none());
        assert_eq!(args.watchdog_sec, 0);
    }

    /// SIGUSR1 used to `send_timeout` and ignore the result: with the scan
    /// queue full the forced scan was dropped while the log said triggered.
    #[test]
    fn a_forced_scan_reports_a_full_queue_and_queues_once_there_is_room() {
        let response = PressureResponse {
            level: PressureLevel::Green,
            urgency: 0.0,
            scan_interval: Duration::from_secs(3),
            release_ballast_files: 0,
            max_delete_batch: 7,
            fallback_active: false,
            causing_mount: PathBuf::from("/"),
            free_pct: 60.0,
            predicted_seconds: None,
        };
        let roots = [PathBuf::from("/data/tmp")];
        let (scan_tx, scan_rx) = bounded::<ScanRequest>(1);
        assert!(MonitoringDaemon::trigger_forced_scan(
            &roots, &scan_tx, &response
        ));
        assert!(!MonitoringDaemon::trigger_forced_scan(
            &roots, &scan_tx, &response
        ));
        let queued = scan_rx.try_recv().unwrap();
        assert!(queued.force_full_scan);
        assert_eq!(queued.paths, roots);
        assert!(
            scan_rx.try_recv().is_err(),
            "the full-queue attempt queued nothing"
        );
        assert!(MonitoringDaemon::trigger_forced_scan(
            &roots, &scan_tx, &response
        ));
        assert_eq!(
            scan_reason_for_request(&scan_rx.try_recv().unwrap()),
            "forced"
        );
        drop(scan_rx);
        // Disconnected: given up (true) rather than retried forever.
        assert!(MonitoringDaemon::trigger_forced_scan(
            &roots, &scan_tx, &response
        ));
    }

    #[test]
    fn siginfo_status_dump_payload_serializes_as_single_json_object() {
        let response = PressureResponse {
            level: PressureLevel::Yellow,
            urgency: 0.42,
            scan_interval: Duration::from_secs(3),
            release_ballast_files: 1,
            max_delete_batch: 7,
            fallback_active: false,
            causing_mount: PathBuf::from("/"),
            free_pct: 12.5,
            predicted_seconds: Some(120.0),
        };
        let memory = MemoryInfo {
            total_bytes: 16,
            available_bytes: 8,
            swap_total_bytes: 4,
            swap_free_bytes: 3,
        };
        let thread_status = vec![ThreadStatus::Running {
            name: "sbh-scanner".to_string(),
            last_heartbeat: Instant::now(),
        }];
        let behavior_mode = BehaviorDispatchTable::default()
            .mode_for(MemoryPressureLevel::Normal, PressureLevel::Yellow);

        let payload_input = StatusDumpPayloadInput {
            timestamp: "2026-05-07T21:22:00.000Z".to_string(),
            version: "test-version",
            pid: 42,
            uptime_seconds: 9,
            response: &response,
            mount_free_pct: Some(50.0),
            mount_total_bytes: Some(16),
            mount_available_bytes: Some(8),
            ballast_available: 2,
            ballast_total: 5,
            memory_info: Some(&memory),
            policy_mode: "enforce".to_string(),
            behavior_mode,
            last_predictive_action: "Clear".to_string(),
            last_ewma_confidence: 0.75,
            guard: None,
            counters: StatusDumpCounters {
                window_scans: 1,
                window_candidates: 3,
                scans_total: 4,
                dropped_log_events: 2,
                ..StatusDumpCounters::default()
            },
            thread_status: &thread_status,
        };
        let payload = build_status_dump_payload(&payload_input);

        let rendered = serde_json::to_string(&payload).expect("status dump should serialize");
        let parsed: Value =
            serde_json::from_str(&rendered).expect("status dump should be valid JSON");
        assert_eq!(parsed["event"], "siginfo_status");
        assert_eq!(parsed["pressure"]["overall"], "yellow");
        assert_eq!(parsed["pressure"]["causing_mount"], "/");
        assert_eq!(parsed["ballast"]["released"], 3);
        assert_eq!(parsed["memory"]["ram_free_pct"], 50.0);
        assert_eq!(
            parsed["policy"]["behavior"]["scan_aggressiveness"],
            "aggressive"
        );
        // v0.6 matrix: Yellow at normal memory deletes high-confidence candidates.
        assert_eq!(
            parsed["policy"]["behavior"]["cleanup_action"],
            "high_confidence_candidates"
        );
        assert_eq!(parsed["threads"][0]["status"], "running");
    }

    #[test]
    fn scanner_and_executor_channel_integration() {
        // Test that scanner → executor channel works correctly.
        let (scan_tx, scan_rx) = bounded::<ScanRequest>(SCANNER_CHANNEL_CAP);
        let (del_tx, del_rx) = bounded::<DeletionBatch>(EXECUTOR_CHANNEL_CAP);

        // Send a scan request.
        let request = ScanRequest {
            paths: vec![],
            urgency: 0.5,
            pressure_level: PressureLevel::Orange,
            free_pct: None,
            max_delete_batch: 10,
            force_full_scan: false,
            config_update: None,
            catalog_roots: Vec::new(),
            maintenance: false,
            target_bytes: None,
        };
        // With capacity 0, send blocks until recv is called.
        // We use thread to unblock.
        std::thread::spawn(move || {
            scan_tx.send(request).unwrap();
        });

        let received = scan_rx.recv().unwrap();
        assert_eq!(received.urgency.to_bits(), 0.5_f64.to_bits());

        // Send a deletion batch.
        let batch = DeletionBatch {
            candidates: Vec::new(),
            pressure_level: PressureLevel::Orange,
            urgency: 0.5,
            target_bytes: None,
            target_only_root: None,
        };
        del_tx.send(batch).unwrap();
        let received_batch = del_rx.recv().unwrap();
        assert_eq!(received_batch.urgency.to_bits(), 0.5_f64.to_bits());
    }

    /// Validates the pressure mapping logic used when special location pressure
    /// triggers a root filesystem scan (bd-2iby fix #3).
    #[test]
    fn special_location_pressure_maps_to_scan_urgency() {
        // priority 255 (e.g. /dev/shm) → urgency = 1.0
        assert_eq!((f64::from(255_u8) / 255.0).to_bits(), 1.0_f64.to_bits());

        // priority 128 → urgency ~0.5
        let urgency = f64::from(128_u8) / 255.0;
        assert!(urgency > 0.49 && urgency < 0.51);

        // free_ratio mapping: free 3% with buffer 20% → ratio 0.15 → Red
        let free_ratio = 3.0 / 20.0;
        assert!(free_ratio < 0.25);
        let level = if free_ratio < 0.25 {
            PressureLevel::Red
        } else if free_ratio < 0.5 {
            PressureLevel::Orange
        } else {
            PressureLevel::Yellow
        };
        assert!(matches!(level, PressureLevel::Red));

        // free_ratio: free 8% with buffer 20% → ratio 0.4 → Orange
        let free_ratio = 8.0 / 20.0;
        assert!((0.25..0.5).contains(&free_ratio));
        let level = if free_ratio < 0.25 {
            PressureLevel::Red
        } else if free_ratio < 0.5 {
            PressureLevel::Orange
        } else {
            PressureLevel::Yellow
        };
        assert!(matches!(level, PressureLevel::Orange));

        // free_ratio: free 15% with buffer 20% → ratio 0.75 → Yellow
        let free_ratio = 15.0 / 20.0;
        assert!(free_ratio >= 0.5);
        let level = if free_ratio < 0.25 {
            PressureLevel::Red
        } else if free_ratio < 0.5 {
            PressureLevel::Orange
        } else {
            PressureLevel::Yellow
        };
        assert!(matches!(level, PressureLevel::Yellow));
    }

    #[test]
    fn special_location_scan_roots_prefer_configured_subtree() {
        let configured = vec![PathBuf::from("/tmp/sbh-run/scan-root")];
        let roots = special_location_scan_roots(Path::new("/tmp"), &configured);

        assert_eq!(roots, configured);
        assert!(!roots.iter().any(|root| root == Path::new("/tmp")));
    }

    #[test]
    fn special_location_scan_roots_keep_default_tmp_root() {
        let configured = vec![PathBuf::from("/tmp"), PathBuf::from("/data/projects")];
        let roots = special_location_scan_roots(Path::new("/tmp"), &configured);

        assert_eq!(roots, vec![PathBuf::from("/tmp")]);
    }

    #[test]
    fn special_location_scan_roots_keep_independent_special_location() {
        let configured = vec![PathBuf::from("/data/projects")];
        let roots = special_location_scan_roots(Path::new("/dev/shm"), &configured);

        assert_eq!(roots, vec![PathBuf::from("/dev/shm")]);
    }

    #[test]
    fn effective_scan_budget_applies_pressure_extension_once() {
        let config = ScannerConfig {
            scan_time_budget_secs: 5,
            ..ScannerConfig::default()
        };

        assert_eq!(
            effective_scan_budget(&config, PressureLevel::Green),
            Duration::from_secs(5)
        );
        assert_eq!(
            effective_scan_budget(&config, PressureLevel::Critical),
            Duration::from_secs(10)
        );

        // Pressure must never *shorten* the pass. With the shipped default
        // (900 s) the old `.min(600)` clamp did exactly that.
        let shipped = ScannerConfig::default();
        let green = effective_scan_budget(&shipped, PressureLevel::Green);
        for level in [
            PressureLevel::Orange,
            PressureLevel::Red,
            PressureLevel::Critical,
        ] {
            assert!(
                effective_scan_budget(&shipped, level) >= green,
                "{level:?} must get at least the Green budget"
            );
        }
        assert_eq!(
            effective_scan_budget(&shipped, PressureLevel::Critical),
            Duration::from_secs(shipped.scan_time_budget_secs * 2)
        );
        // And the extension is bounded.
        let huge = ScannerConfig {
            scan_time_budget_secs: MAX_SCAN_TIME_BUDGET_SECS,
            ..ScannerConfig::default()
        };
        assert_eq!(
            effective_scan_budget(&huge, PressureLevel::Red),
            Duration::from_secs(MAX_SCAN_TIME_BUDGET_SECS)
        );
    }

    #[test]
    fn v2_pressure_candidate_byte_target_only_applies_under_cleanup_pressure() {
        let mut request = ScanRequest {
            paths: vec![PathBuf::from("/tmp")],
            urgency: 0.5,
            pressure_level: PressureLevel::Yellow,
            free_pct: Some(15.0),
            max_delete_batch: 4,
            force_full_scan: false,
            config_update: None,
            catalog_roots: Vec::new(),
            maintenance: false,
            target_bytes: None,
        };

        assert_eq!(v2_pressure_candidate_byte_target(&request), None);

        request.pressure_level = PressureLevel::Orange;
        assert_eq!(
            v2_pressure_candidate_byte_target(&request),
            Some(4 * 256 * 1_048_576)
        );

        request.max_delete_batch = 0;
        assert_eq!(v2_pressure_candidate_byte_target(&request), None);
    }

    #[test]
    fn v2_active_scan_paths_skip_green_yellow_without_dirty_roots() {
        let mut request = ScanRequest {
            paths: vec![PathBuf::from("/tmp"), PathBuf::from("/var/tmp")],
            urgency: 0.0,
            pressure_level: PressureLevel::Green,
            free_pct: Some(50.0),
            max_delete_batch: 10,
            force_full_scan: false,
            config_update: None,
            catalog_roots: Vec::new(),
            maintenance: false,
            target_bytes: None,
        };
        let mut dirty = BTreeSet::new();

        assert_eq!(v2_active_scan_paths(&request, &dirty), Some(Vec::new()));

        dirty.insert(PathBuf::from("/tmp"));
        request.pressure_level = PressureLevel::Yellow;
        assert_eq!(
            v2_active_scan_paths(&request, &dirty),
            Some(vec![PathBuf::from("/tmp")])
        );

        request.pressure_level = PressureLevel::Orange;
        assert_eq!(v2_active_scan_paths(&request, &dirty), None);
    }

    #[test]
    fn v2_active_scan_paths_do_not_skip_forced_green_scan() {
        let request = ScanRequest {
            paths: vec![PathBuf::from("/tmp"), PathBuf::from("/var/tmp")],
            urgency: 0.5,
            pressure_level: PressureLevel::Green,
            free_pct: Some(50.0),
            max_delete_batch: 10,
            force_full_scan: true,
            config_update: None,
            catalog_roots: Vec::new(),
            maintenance: false,
            target_bytes: None,
        };
        let dirty = BTreeSet::new();

        assert_eq!(scan_reason_for_request(&request), "forced");
        assert_eq!(v2_active_scan_paths(&request, &dirty), None);
    }

    /// Catalog scans run once per pressure epoch: a rising level or the
    /// rescan interval re-arms them, repeated ticks at the same level do not.
    #[test]
    fn catalog_epoch_is_due_once_per_level_and_after_the_interval() {
        let now = Instant::now();
        let interval = Duration::from_mins(15);
        assert!(catalog_epoch_due(
            None,
            PressureLevel::Orange,
            now,
            interval
        ));
        let dispatched = Some((PressureLevel::Orange, now));
        assert!(!catalog_epoch_due(
            dispatched,
            PressureLevel::Orange,
            now + Duration::from_secs(10),
            interval
        ));
        assert!(!catalog_epoch_due(
            dispatched,
            PressureLevel::Yellow,
            now + Duration::from_secs(10),
            interval
        ));
        assert!(catalog_epoch_due(
            dispatched,
            PressureLevel::Red,
            now + Duration::from_secs(10),
            interval
        ));
        assert!(catalog_epoch_due(
            dispatched,
            PressureLevel::Orange,
            now + interval,
            interval
        ));
    }

    /// The B5 device-affinity gate became per-mount state (W1.1): a pressured
    /// mount with no surface is observe-only and contributes nothing to the
    /// tick, while every other mount keeps its own cadence.
    #[test]
    fn pressured_mount_without_surface_is_observe_only_and_never_tightens_the_tick() {
        use crate::daemon::mount_controller::{MountSurface, WakeSignals};
        let now = Instant::now();
        let base = Duration::from_secs(60);
        let config = mount_controller_config(&Config::default());
        let no_surface = MountSurface::default();
        let with_root = MountSurface {
            configured_roots: 1,
            ..MountSurface::default()
        };
        let tick = |level: PressureLevel, surface: MountSurface| MountTickInput {
            level,
            urgency: 0.6,
            free_pct: 12.0,
            seconds_to_red: None,
            prediction_confident: false,
            surface,
            releasable_ballast: false,
            recovery_needed: false,
            recovery_probe_ok: None,
            wake: WakeSignals::default(),
            now,
        };

        let mut root_mount = MountController::new(PathBuf::from("/"), config);
        let decision = root_mount.observe(tick(PressureLevel::Orange, no_surface));
        assert_eq!(decision.state, MountState::ObserveOnly);
        assert!(!decision.scan);
        assert_eq!(root_mount.cadence(base, Duration::from_secs(15)), None);

        let mut data_mount = MountController::new(PathBuf::from("/data"), config);
        let decision = data_mount.observe(tick(PressureLevel::Green, with_root));
        assert_eq!(decision.state, MountState::Maintain);
        assert_eq!(
            global_tick(
                [
                    root_mount.cadence(base, Duration::from_secs(15)),
                    data_mount.cadence(base, Duration::from_secs(15)),
                ],
                base
            ),
            base,
            "an observe-only Orange mount must not drag the tick to the Orange interval"
        );

        // cross_devices gives the rootless mount a surface again.
        let cross = MountSurface {
            cross_device_fallback: true,
            ..MountSurface::default()
        };
        let decision = root_mount.observe(tick(PressureLevel::Orange, cross));
        assert_eq!(decision.state, MountState::Reclaim);
        assert!(decision.scan);
    }

    fn cooldown_request(pressure: PressureLevel) -> ScanRequest {
        ScanRequest {
            paths: vec![PathBuf::from("/tmp")],
            urgency: 0.5,
            pressure_level: pressure,
            free_pct: Some(10.0),
            max_delete_batch: 10,
            force_full_scan: false,
            config_update: None,
            catalog_roots: Vec::new(),
            maintenance: false,
            target_bytes: None,
        }
    }

    #[test]
    fn empty_pass_cooldown_blocks_immediate_rescan() {
        let now = Instant::now();
        let last_empty = Some(now);
        let request = cooldown_request(PressureLevel::Orange);
        // Just finished an empty pass; cooldown not elapsed → skip.
        assert!(empty_pass_cooldown_active(
            last_empty,
            now,
            Duration::from_secs(90),
            &request,
            1,
        ));
    }

    #[test]
    fn empty_pass_cooldown_expires_after_interval() {
        let start = Instant::now();
        let later = start + Duration::from_secs(120);
        let request = cooldown_request(PressureLevel::Orange);
        // 120s elapsed > 90s cooldown → allow.
        assert!(!empty_pass_cooldown_active(
            Some(start),
            later,
            Duration::from_secs(90),
            &request,
            1,
        ));
    }

    #[test]
    fn empty_pass_cooldown_inactive_without_prior_empty_pass() {
        let now = Instant::now();
        let request = cooldown_request(PressureLevel::Orange);
        assert!(!empty_pass_cooldown_active(
            None,
            now,
            Duration::from_secs(90),
            &request,
            0,
        ));
    }

    #[test]
    fn empty_pass_cooldown_disabled_when_interval_zero() {
        let now = Instant::now();
        let request = cooldown_request(PressureLevel::Orange);
        assert!(!empty_pass_cooldown_active(
            Some(now),
            now,
            Duration::ZERO,
            &request,
            5,
        ));
    }

    /// #36: a dispatch that is followed by another dispatch, with nothing
    /// reclaimed in between, must not reset the streak, or the backoff never
    /// grows past its first step.
    #[test]
    fn dispatches_that_reclaim_nothing_keep_growing_the_empty_pass_streak() {
        let (mut consecutive, mut inconclusive, mut last_empty) = (0_u32, 0_u32, None);
        for expected in 1..=4 {
            // Pass start: the previous dispatch reclaimed nothing.
            record_empty_pass(&mut consecutive, &mut inconclusive, false);
            last_empty = Some(Instant::now());
            // This pass dispatches again.
            record_dispatching_pass(true, &mut consecutive, &mut inconclusive, &mut last_empty);
            assert_eq!(consecutive, expected);
            assert!(last_empty.is_some(), "the cooldown stays armed");
        }
        assert_eq!(
            effective_empty_pass_cooldown(5, consecutive),
            Duration::from_secs(40)
        );
        // A dispatch after one that did reclaim starts a fresh streak.
        record_dispatching_pass(false, &mut consecutive, &mut inconclusive, &mut last_empty);
        assert_eq!((consecutive, inconclusive, last_empty), (0, 0, None));
    }

    #[test]
    fn effective_empty_pass_cooldown_backs_off_exponentially_and_caps() {
        // Base of 0 disables the cooldown regardless of the streak length.
        assert_eq!(effective_empty_pass_cooldown(0, 5), Duration::ZERO);
        // The first empty pass (consecutive == 1) waits exactly the base interval.
        assert_eq!(
            effective_empty_pass_cooldown(90, 1),
            Duration::from_secs(90)
        );
        // consecutive == 0 is treated as the first pass (1×), never underflows.
        assert_eq!(
            effective_empty_pass_cooldown(90, 0),
            Duration::from_secs(90)
        );
        // Each consecutive empty pass doubles the interval.
        assert_eq!(
            effective_empty_pass_cooldown(90, 2),
            Duration::from_secs(180)
        );
        assert_eq!(
            effective_empty_pass_cooldown(90, 3),
            Duration::from_secs(360)
        );
        assert_eq!(
            effective_empty_pass_cooldown(90, 4),
            Duration::from_mins(12)
        );
        // The shift caps at 5 → 32× the base (48 min at a 90s base), and stays
        // there for longer streaks.
        assert_eq!(
            effective_empty_pass_cooldown(90, 6),
            Duration::from_mins(48)
        );
        assert_eq!(
            effective_empty_pass_cooldown(90, 100),
            Duration::from_mins(48)
        );
        // Extreme inputs saturate instead of panicking on overflow.
        let _ = effective_empty_pass_cooldown(u64::MAX, u32::MAX);
    }

    #[test]
    fn empty_pass_cooldown_bypassed_for_red_pressure() {
        let now = Instant::now();
        let request = cooldown_request(PressureLevel::Red);
        // Rising danger overrides pacing.
        assert!(!empty_pass_cooldown_active(
            Some(now),
            now,
            Duration::from_secs(90),
            &request,
            1,
        ));
    }

    #[test]
    fn pressure_escalation_is_a_rise_over_the_last_completed_pass() {
        let orange = cooldown_request(PressureLevel::Orange);
        assert!(pressure_escalated(Some(PressureLevel::Green), &orange));
        assert!(pressure_escalated(Some(PressureLevel::Yellow), &orange));
        assert!(!pressure_escalated(Some(PressureLevel::Orange), &orange));
        assert!(!pressure_escalated(Some(PressureLevel::Red), &orange));
        assert!(
            !pressure_escalated(None, &orange),
            "nothing to compare against"
        );
        let mut maintenance = cooldown_request(PressureLevel::Orange);
        maintenance.maintenance = true;
        assert!(
            !pressure_escalated(Some(PressureLevel::Green), &maintenance),
            "maintenance passes carry no pressure signal"
        );
    }

    #[test]
    fn a_return_to_a_level_scanned_empty_minutes_ago_is_not_an_escalation() {
        let start = Instant::now();
        let mut peak = None;
        note_empty_pass_level(&mut peak, PressureLevel::Red, start);
        // Free space flapping at the Red line: an empty Orange pass in
        // between neither erases the Red pass nor makes Red new again.
        let orange_at = start + Duration::from_secs(90);
        note_empty_pass_level(&mut peak, PressureLevel::Orange, orange_at);
        assert_eq!(peak, Some((PressureLevel::Red, start)));
        let back_to_red = start + Duration::from_secs(100);
        assert!(rise_already_scanned_empty(
            peak,
            PressureLevel::Red,
            back_to_red
        ));
        assert!(rise_already_scanned_empty(
            peak,
            PressureLevel::Orange,
            back_to_red
        ));
        // A level above anything scanned empty is new information.
        assert!(!rise_already_scanned_empty(
            peak,
            PressureLevel::Critical,
            back_to_red
        ));
        // Another empty Red pass refreshes the window.
        let red_again = start + Duration::from_secs(200);
        note_empty_pass_level(&mut peak, PressureLevel::Red, red_again);
        assert_eq!(peak, Some((PressureLevel::Red, red_again)));
        // Once the window has passed, a return to Red clears the pacing again.
        let later = red_again + ESCALATION_HYSTERESIS;
        assert!(!rise_already_scanned_empty(peak, PressureLevel::Red, later));
        note_empty_pass_level(&mut peak, PressureLevel::Orange, later);
        assert_eq!(peak, Some((PressureLevel::Orange, later)));
        assert!(!rise_already_scanned_empty(None, PressureLevel::Red, later));
    }

    #[test]
    fn empty_pass_cooldown_bypassed_for_maintenance_passes() {
        let now = Instant::now();
        let mut request = cooldown_request(PressureLevel::Green);
        request.maintenance = true;
        // Maintenance is paced by its own interval, not by the rescan cooldown.
        assert!(!empty_pass_cooldown_active(
            Some(now),
            now,
            Duration::from_secs(90),
            &request,
            TERMINAL_IDLE_EMPTY_PASSES,
        ));
        request.maintenance = false;
        assert!(empty_pass_cooldown_active(
            Some(now),
            now,
            Duration::from_secs(90),
            &request,
            TERMINAL_IDLE_EMPTY_PASSES,
        ));
    }

    #[test]
    fn empty_pass_cooldown_red_bypass_ends_at_terminal_idle() {
        let now = Instant::now();
        let request = cooldown_request(PressureLevel::Red);
        let cooldown = Duration::from_secs(90);

        // Below the terminal-idle streak, Red still bypasses the cooldown.
        assert!(!empty_pass_cooldown_active(
            Some(now),
            now,
            cooldown,
            &request,
            TERMINAL_IDLE_EMPTY_PASSES - 1,
        ));

        // At the terminal-idle streak, Red waits like everyone else (#15):
        // re-walking a tree with zero reclaimable candidates cannot free
        // bytes no matter how red the disk is.
        assert!(empty_pass_cooldown_active(
            Some(now),
            now,
            cooldown,
            &request,
            TERMINAL_IDLE_EMPTY_PASSES,
        ));

        // Critical behaves the same as Red.
        let critical = cooldown_request(PressureLevel::Critical);
        assert!(empty_pass_cooldown_active(
            Some(now),
            now,
            cooldown,
            &critical,
            TERMINAL_IDLE_EMPTY_PASSES,
        ));
    }

    #[test]
    fn timed_out_empty_passes_still_reach_terminal_idle_under_red() {
        // bd-qxrh: when the CPU bucket cuts every pass short, no pass is
        // "complete", the streak used to stay at 0, and Red bypassed the
        // cooldown forever with nothing to reclaim.
        let now = Instant::now();
        let request = cooldown_request(PressureLevel::Red);
        let cooldown = Duration::from_secs(90);
        let (mut streak, mut inconclusive) = (0u32, 0u32);
        let mut passes = 0;
        while !empty_pass_cooldown_active(Some(now), now, cooldown, &request, streak) {
            record_empty_pass(&mut streak, &mut inconclusive, true);
            passes += 1;
            assert!(
                passes <= 100,
                "timed-out empty passes never reached terminal idle"
            );
        }
        assert_eq!(
            passes,
            TERMINAL_IDLE_EMPTY_PASSES * TERMINAL_IDLE_EMPTY_PASSES
        );
        assert_eq!(streak, TERMINAL_IDLE_EMPTY_PASSES);
    }

    #[test]
    fn a_few_timed_out_empty_passes_stay_inconclusive() {
        let (mut streak, mut inconclusive) = (0u32, 0u32);
        for _ in 1..TERMINAL_IDLE_EMPTY_PASSES {
            record_empty_pass(&mut streak, &mut inconclusive, true);
        }
        assert_eq!(streak, 0, "a budget that ran out early proves nothing yet");
        // A completed empty pass counts at once and clears the inconclusive run.
        record_empty_pass(&mut streak, &mut inconclusive, false);
        assert_eq!((streak, inconclusive), (1, 0));
    }

    #[test]
    fn empty_pass_cooldown_terminal_idle_red_wake_is_capped() {
        let start = Instant::now();
        let request = cooldown_request(PressureLevel::Red);
        // Fully backed-off interval: 32 × 90s = 48 min.
        let backed_off = effective_empty_pass_cooldown(90, 10);
        assert!(backed_off > TERMINAL_IDLE_PRESSURED_RESCAN_CAP);

        // Under Red pressure the terminal-idle wait is capped at the
        // pressured rescan cap, so the daemon re-checks on a long-timer wake
        // instead of sleeping the better part of an hour mid-emergency.
        let just_past_cap = start + TERMINAL_IDLE_PRESSURED_RESCAN_CAP + Duration::from_secs(1);
        assert!(!empty_pass_cooldown_active(
            Some(start),
            just_past_cap,
            backed_off,
            &request,
            10,
        ));

        // But within the cap the pass is still skipped.
        let within_cap =
            start + TERMINAL_IDLE_PRESSURED_RESCAN_CAP.saturating_sub(Duration::from_secs(1));
        assert!(empty_pass_cooldown_active(
            Some(start),
            within_cap,
            backed_off,
            &request,
            10,
        ));

        // Off-pressure levels keep honoring the full backed-off interval.
        let orange = cooldown_request(PressureLevel::Orange);
        assert!(empty_pass_cooldown_active(
            Some(start),
            just_past_cap,
            backed_off,
            &orange,
            10,
        ));
    }

    #[test]
    fn empty_pass_cooldown_fresh_state_scans_immediately_at_any_level() {
        // Restart/trigger path: with no prior empty pass recorded, the first
        // pressure-driven pass always runs, at every pressure level.
        let now = Instant::now();
        for level in [
            PressureLevel::Green,
            PressureLevel::Yellow,
            PressureLevel::Orange,
            PressureLevel::Red,
            PressureLevel::Critical,
        ] {
            let request = cooldown_request(level);
            assert!(
                !empty_pass_cooldown_active(None, now, Duration::from_secs(90), &request, 0),
                "fresh state must allow the first pass at {level:?}"
            );
        }
    }

    #[test]
    fn empty_pass_cooldown_boundary_exact_interval_allows_rescan() {
        // Boundary values: strictly inside the window skips; exactly at the
        // boundary the comparison is `<`, so the rescan is allowed.
        let start = Instant::now();
        let cooldown = Duration::from_secs(90);
        let request = cooldown_request(PressureLevel::Yellow);
        assert!(empty_pass_cooldown_active(
            Some(start),
            start + cooldown.saturating_sub(Duration::from_nanos(1)),
            cooldown,
            &request,
            1,
        ));
        assert!(!empty_pass_cooldown_active(
            Some(start),
            start + cooldown,
            cooldown,
            &request,
            1,
        ));
    }

    #[test]
    fn empty_pass_cooldown_restart_below_clear_settles_into_idle() {
        // Restart with the disk already below the clear threshold (#15 case 2):
        // fresh scanner state must allow the first pass, then settle into an
        // exponentially backed-off idle when passes keep making no progress —
        // never a hot-loop of back-to-back rescans.
        let base_secs = 90;
        let request = cooldown_request(PressureLevel::Orange);
        let mut now = Instant::now();
        let mut last_empty_pass_at: Option<Instant> = None;
        let mut consecutive: u32 = 0;

        for pass in 1..=8u32 {
            // The pass runs only once the backed-off cooldown has elapsed.
            assert!(
                !empty_pass_cooldown_active(
                    last_empty_pass_at,
                    now,
                    effective_empty_pass_cooldown(base_secs, consecutive),
                    &request,
                    consecutive,
                ),
                "pass {pass} should be allowed after its cooldown elapsed"
            );

            // The pass finds nothing reclaimable: arm the cooldown, grow the
            // streak (mirrors the accounting in `scanner_thread_main`).
            consecutive += 1;
            last_empty_pass_at = Some(now);

            let cooldown = effective_empty_pass_cooldown(base_secs, consecutive);
            // An immediate retry (the hot-loop) is always skipped.
            assert!(
                empty_pass_cooldown_active(
                    last_empty_pass_at,
                    now + Duration::from_millis(1),
                    cooldown,
                    &request,
                    consecutive,
                ),
                "immediate rescan after empty pass {pass} must be skipped"
            );

            now += cooldown + Duration::from_secs(1);
        }

        // After the streak the wait has decayed to the 32× cap (48 min at the
        // 90s base): the scanner is parked, waking at most once per capped
        // interval.
        assert_eq!(
            effective_empty_pass_cooldown(base_secs, consecutive),
            Duration::from_mins(48)
        );
    }

    /// The regression this limiter exists for: a PRODUCTIVE pass under Red.
    ///
    /// `empty_pass_cooldown_active` returns false here (the empty-pass counter
    /// is 0 because the pass reclaimed something), which is precisely how the
    /// daemon used to re-walk back-to-back at ~100% CPU on a chronically-full
    /// host. The duty-cycle limiter must still defer.
    #[test]
    fn duty_cycle_defers_productive_red_passes_that_cooldown_ignores() {
        let now = Instant::now();
        let request = cooldown_request(PressureLevel::Red);

        // Baseline: the empty-pass cooldown does NOT gate this.
        assert!(!empty_pass_cooldown_active(
            Some(now),
            now,
            Duration::from_secs(90),
            &request,
            0,
        ));

        // A 20s pass at 25% owes 60s of idle; 10s in we must still defer.
        let finished = now
            .checked_sub(Duration::from_secs(10))
            .expect("test clock is more than 10s past process start");
        assert!(duty_cycle_defer_active(
            Some(finished),
            Duration::from_secs(20),
            now,
            &request,
            25,
        ));
        // Once the debt is paid, the pass runs.
        let finished = now
            .checked_sub(Duration::from_secs(61))
            .expect("test clock is more than 61s past process start");
        assert!(!duty_cycle_defer_active(
            Some(finished),
            Duration::from_secs(20),
            now,
            &request,
            25,
        ));
    }

    #[test]
    fn duty_cycle_idle_debt_bounds_cpu_share() {
        // 25% duty => 3x the pass duration of idle.
        assert_eq!(
            duty_cycle_idle_debt(Duration::from_secs(20), 25),
            Duration::from_secs(60)
        );
        // 50% duty => 1x.
        assert_eq!(
            duty_cycle_idle_debt(Duration::from_secs(20), 50),
            Duration::from_secs(20)
        );
        // Cheap passes fall back to the absolute floor rather than ~0.
        assert_eq!(
            duty_cycle_idle_debt(Duration::from_millis(10), 25),
            DUTY_CYCLE_MIN_PASS_GAP
        );
        // Disabled / nonsensical settings opt out entirely.
        assert!(duty_cycle_idle_debt(Duration::from_secs(60), 0).is_zero());
        assert!(duty_cycle_idle_debt(Duration::from_secs(60), 100).is_zero());
        assert!(duty_cycle_idle_debt(Duration::from_secs(60), 200).is_zero());
    }

    /// A pass that exhausts `scan_time_budget_secs` (default 900) would owe 45
    /// minutes unclamped — long enough for a filling disk to blow through Red
    /// before the scanner looks again. Trading the hot-loop for that would be a
    /// worse bug, so the debt is capped.
    #[test]
    fn duty_cycle_debt_is_capped_so_reclaim_cannot_stall() {
        let budget_exhausting = Duration::from_mins(15);
        let unclamped = budget_exhausting * 3; // 45 min at pct=25
        assert!(unclamped > DUTY_CYCLE_MAX_DEBT, "premise of this test");
        assert_eq!(
            duty_cycle_idle_debt(budget_exhausting, 25),
            DUTY_CYCLE_MAX_DEBT
        );
        // Even a pathological pass length cannot exceed the ceiling.
        assert_eq!(
            duty_cycle_idle_debt(Duration::from_hours(24), 1),
            DUTY_CYCLE_MAX_DEBT
        );
        // The floor and ceiling are ordered, so `clamp` cannot panic.
        assert!(DUTY_CYCLE_MIN_PASS_GAP <= DUTY_CYCLE_MAX_DEBT);
    }

    #[test]
    fn duty_cycle_never_blocks_operator_or_config_scans() {
        let now = Instant::now();
        let just_finished = Some(now);
        let expensive = Duration::from_secs(600);

        let mut forced = cooldown_request(PressureLevel::Green);
        forced.force_full_scan = true;
        assert!(!duty_cycle_defer_active(
            just_finished,
            expensive,
            now,
            &forced,
            25
        ));

        let mut reload = cooldown_request(PressureLevel::Green);
        reload.config_update = Some((
            crate::core::config::ScoringConfig::default(),
            crate::core::config::ScannerConfig::default(),
        ));
        assert!(!duty_cycle_defer_active(
            just_finished,
            expensive,
            now,
            &reload,
            25
        ));

        let mut synthetic = cooldown_request(PressureLevel::Green);
        synthetic.free_pct = None;
        assert!(!duty_cycle_defer_active(
            just_finished,
            expensive,
            now,
            &synthetic,
            25
        ));
    }

    #[test]
    fn duty_cycle_first_pass_is_never_deferred() {
        let now = Instant::now();
        let request = cooldown_request(PressureLevel::Critical);
        // No previous pass recorded → nothing owed.
        assert!(!duty_cycle_defer_active(
            None,
            Duration::ZERO,
            now,
            &request,
            25
        ));
    }

    #[test]
    fn duty_cycle_disabled_setting_matches_legacy_behavior() {
        let now = Instant::now();
        let request = cooldown_request(PressureLevel::Red);
        assert!(!duty_cycle_defer_active(
            Some(now),
            Duration::from_secs(600),
            now,
            &request,
            0,
        ));
    }

    #[test]
    fn empty_pass_cooldown_bypassed_for_forced_and_config_and_synthetic() {
        let now = Instant::now();
        let cooldown = Duration::from_secs(90);

        let mut forced = cooldown_request(PressureLevel::Orange);
        forced.force_full_scan = true;
        assert!(!empty_pass_cooldown_active(
            Some(now),
            now,
            cooldown,
            &forced,
            5,
        ));

        let mut reload = cooldown_request(PressureLevel::Orange);
        reload.config_update = Some((
            crate::core::config::ScoringConfig::default(),
            crate::core::config::ScannerConfig::default(),
        ));
        assert!(!empty_pass_cooldown_active(
            Some(now),
            now,
            cooldown,
            &reload,
            5,
        ));

        let mut synthetic = cooldown_request(PressureLevel::Orange);
        synthetic.free_pct = None;
        assert!(!empty_pass_cooldown_active(
            Some(now),
            now,
            cooldown,
            &synthetic,
            5,
        ));
    }

    /// bd-rxq5: the compression tier rewrites files, so the policy modes that
    /// change nothing (observe, fallback-safe, which the kill switch forces)
    /// and dry-run keep it from starting a pass.
    #[test]
    fn compress_tier_runs_only_where_the_policy_may_change_the_filesystem() {
        let mut config = Config::default();
        config.compress.enabled = true;
        for mode in [ActiveMode::Enforce, ActiveMode::Canary] {
            assert!(compress_tier_may_run(&config, mode), "{mode}");
        }
        for mode in [ActiveMode::Observe, ActiveMode::FallbackSafe] {
            assert!(!compress_tier_may_run(&config, mode), "{mode}");
        }
        config.scanner.dry_run = true;
        assert!(!compress_tier_may_run(&config, ActiveMode::Enforce));
        config.scanner.dry_run = false;
        config.compress.enabled = false;
        assert!(!compress_tier_may_run(&config, ActiveMode::Enforce));
    }

    #[test]
    fn v2_effective_parallelism_caps_low_pressure_refreshes() {
        let mut config = ScannerConfig {
            parallelism: 16,
            ..ScannerConfig::default()
        };

        assert_eq!(v2_effective_parallelism(&config, PressureLevel::Green), 1);
        assert_eq!(v2_effective_parallelism(&config, PressureLevel::Yellow), 1);
        assert_eq!(v2_effective_parallelism(&config, PressureLevel::Orange), 2);
        assert_eq!(v2_effective_parallelism(&config, PressureLevel::Red), 4);

        config.parallelism = 1;
        assert_eq!(
            v2_effective_parallelism(&config, PressureLevel::Critical),
            1
        );
    }

    #[test]
    fn active_reference_probe_respects_scan_deadline() {
        assert_eq!(
            active_reference_scan_budget("macos"),
            Duration::from_secs(13)
        );
        assert_eq!(
            active_reference_scan_budget("linux"),
            Duration::from_secs(5)
        );

        assert!(!has_active_reference_scan_budget(
            Instant::now() + Duration::from_secs(1),
            active_reference_scan_budget("macos")
        ));
        assert!(has_active_reference_scan_budget(
            Instant::now() + Duration::from_secs(20),
            active_reference_scan_budget("macos")
        ));
    }

    #[test]
    fn scanner_channel_defers_when_full_without_replacement() {
        let (tx, rx) = bounded::<ScanRequest>(SCANNER_CHANNEL_CAP);

        let make_request = |urgency: f64| ScanRequest {
            paths: vec![],
            urgency,
            pressure_level: PressureLevel::Critical,
            free_pct: None,
            max_delete_batch: 40,
            force_full_scan: false,
            config_update: None,
            catalog_roots: Vec::new(),
            maintenance: false,
            target_bytes: None,
        };

        // Fill the channel to capacity.
        tx.try_send(make_request(0.1)).unwrap();
        tx.try_send(make_request(0.2)).unwrap();

        let status = enqueue_scan_request(&tx, &rx, make_request(0.95), false);
        assert_eq!(status, ScanEnqueueStatus::DeferredFull);

        // Queue should retain the original oldest request.
        let first = rx.recv().unwrap();
        assert_eq!(first.urgency.to_bits(), 0.1_f64.to_bits());
    }

    #[test]
    fn scanner_channel_replaces_stale_request_when_priority() {
        let (tx, rx) = bounded::<ScanRequest>(SCANNER_CHANNEL_CAP);

        let make_request = |urgency: f64| ScanRequest {
            paths: vec![],
            urgency,
            pressure_level: PressureLevel::Critical,
            free_pct: None,
            max_delete_batch: 40,
            force_full_scan: false,
            config_update: None,
            catalog_roots: Vec::new(),
            maintenance: false,
            target_bytes: None,
        };

        // Fill queue with stale requests.
        tx.try_send(make_request(0.1))
            .expect("should buffer within capacity");
        tx.try_send(make_request(0.2))
            .expect("should buffer within capacity");

        // Priority enqueue should evict oldest and queue new request.
        let status = enqueue_scan_request(&tx, &rx, make_request(1.0), true);
        assert_eq!(status, ScanEnqueueStatus::ReplacedStale);

        let queued_first = rx.recv().unwrap();
        let queued_second = rx.recv().unwrap();
        assert_eq!(queued_first.urgency.to_bits(), 0.2_f64.to_bits());
        assert_eq!(queued_second.urgency.to_bits(), 1.0_f64.to_bits());
    }

    #[test]
    fn ballast_discovery_paths_include_special_and_runtime_mount_hints() {
        let mut cfg = Config::default();
        cfg.scanner.root_paths = vec![PathBuf::from("/data/projects"), PathBuf::from("/tmp")];
        cfg.paths.state_file = PathBuf::from("/var/lib/sbh/state.json");
        cfg.paths.ballast_dir = PathBuf::from("/var/lib/sbh/ballast");

        let special = SpecialLocationRegistry::new(vec![
            SpecialLocation {
                path: PathBuf::from("/dev/shm"),
                kind: SpecialKind::DevShm,
                buffer_pct: 20,
                scan_interval: Duration::from_secs(3),
                priority: 255,
            },
            // Duplicate root should be deduped.
            SpecialLocation {
                path: PathBuf::from("/tmp"),
                kind: SpecialKind::Tmpfs,
                buffer_pct: 15,
                scan_interval: Duration::from_secs(5),
                priority: 200,
            },
        ]);

        let paths = ballast_discovery_paths(&cfg, &special);
        assert!(paths.contains(&PathBuf::from("/data/projects")));
        assert!(paths.contains(&PathBuf::from("/tmp")));
        assert!(paths.contains(&PathBuf::from("/dev/shm")));
        assert!(paths.contains(&PathBuf::from("/var/lib/sbh")));
        assert_eq!(
            paths
                .iter()
                .filter(|path| path.as_path() == Path::new("/tmp"))
                .count(),
            1
        );
    }

    #[test]
    fn scanner_channel_reports_full_via_try_send_for_raw_channel_behavior() {
        let (tx, _rx) = bounded::<ScanRequest>(SCANNER_CHANNEL_CAP);
        let make_request = || ScanRequest {
            paths: vec![],
            urgency: 0.9,
            pressure_level: PressureLevel::Critical,
            free_pct: None,
            max_delete_batch: 40,
            force_full_scan: false,
            config_update: None,
            catalog_roots: Vec::new(),
            maintenance: false,
            target_bytes: None,
        };
        for _ in 0..SCANNER_CHANNEL_CAP {
            tx.try_send(make_request())
                .expect("should buffer within capacity");
        }

        let result = tx.try_send(make_request());
        assert!(matches!(result, Err(TrySendError::Full(_))));
    }

    #[test]
    fn dispatch_top_candidates_retains_overflow_after_send() {
        let request = ScanRequest {
            paths: vec![PathBuf::from("/tmp")],
            urgency: 1.0,
            pressure_level: PressureLevel::Critical,
            free_pct: None,
            max_delete_batch: 1,
            force_full_scan: false,
            config_update: None,
            catalog_roots: Vec::new(),
            maintenance: false,
            target_bytes: None,
        };
        let (del_tx, del_rx) = bounded::<DeletionBatch>(4);
        let mut scored = vec![
            test_candidate("/tmp/low", 0.1),
            test_candidate("/tmp/high", 0.9),
            test_candidate("/tmp/mid", 0.5),
        ];

        assert!(dispatch_top_candidates(
            &mut scored,
            &request,
            &del_tx,
            &mut PassDispatch::default()
        ));
        let batch = del_rx.recv().expect("batch should be dispatched");
        assert_eq!(batch.candidates.len(), 1);
        assert_eq!(batch.candidates[0].path, Path::new("/tmp/high"));
        assert_eq!(scored.len(), 2);
        assert!(scored.iter().any(|c| c.path == Path::new("/tmp/mid")));
        assert!(scored.iter().any(|c| c.path == Path::new("/tmp/low")));
    }

    #[test]
    fn dispatch_top_candidates_requeues_when_executor_full() {
        let request = ScanRequest {
            paths: vec![PathBuf::from("/tmp")],
            urgency: 1.0,
            pressure_level: PressureLevel::Critical,
            free_pct: None,
            max_delete_batch: 1,
            force_full_scan: false,
            config_update: None,
            catalog_roots: Vec::new(),
            maintenance: false,
            target_bytes: None,
        };
        let (del_tx, del_rx) = bounded::<DeletionBatch>(1);
        del_tx
            .send(DeletionBatch {
                candidates: vec![test_candidate("/tmp/already-queued", 0.2)],
                pressure_level: PressureLevel::Critical,
                urgency: 0.5,
                target_bytes: None,
                target_only_root: None,
            })
            .expect("prefill channel");

        let mut scored = vec![test_candidate("/tmp/a", 0.4), test_candidate("/tmp/b", 0.6)];
        let before = scored.len();
        assert!(dispatch_top_candidates(
            &mut scored,
            &request,
            &del_tx,
            &mut PassDispatch::default()
        ));

        // Channel remained full, so scanner should still retain all candidates.
        assert_eq!(scored.len(), before);
        assert!(scored.iter().any(|c| c.path == Path::new("/tmp/a")));
        assert!(scored.iter().any(|c| c.path == Path::new("/tmp/b")));

        // Existing queued batch should still be the one currently in the channel.
        let queued = del_rx.recv().expect("prefilled batch still queued");
        assert_eq!(queued.candidates[0].path, Path::new("/tmp/already-queued"));
    }

    /// The pre-scan and the walk nominated the same target in one pass; the
    /// second batch deleted the tree a build had just recreated (the freed
    /// inode was reused, so the identity check passed). A path, or anything
    /// under it, is dispatched at most once per pass.
    #[test]
    fn a_pass_never_dispatches_the_same_tree_twice() {
        let request = ScanRequest {
            paths: vec![PathBuf::from("/tmp")],
            urgency: 0.9,
            pressure_level: PressureLevel::Orange,
            free_pct: None,
            max_delete_batch: 10,
            force_full_scan: false,
            config_update: None,
            catalog_roots: Vec::new(),
            maintenance: false,
            target_bytes: None,
        };
        let (del_tx, del_rx) = bounded::<DeletionBatch>(4);
        let mut pass = PassDispatch::default();

        let mut prescan = vec![test_candidate("/tmp/proj/target", 0.9)];
        assert!(dispatch_top_candidates(
            &mut prescan,
            &request,
            &del_tx,
            &mut pass
        ));
        assert_eq!(del_rx.try_recv().unwrap().candidates.len(), 1);

        let mut walk = vec![
            test_candidate("/tmp/proj/target", 0.9),
            test_candidate("/tmp/proj/target/debug", 0.8),
            test_candidate("/tmp/other/target", 0.7),
        ];
        assert!(dispatch_top_candidates(
            &mut walk, &request, &del_tx, &mut pass
        ));
        let second = del_rx.try_recv().unwrap();
        let paths: Vec<_> = second.candidates.iter().map(|c| c.path.clone()).collect();
        assert_eq!(paths, vec![PathBuf::from("/tmp/other/target")]);

        // Nor an ancestor of a dispatched tree: deleting `/tmp/other` would
        // take whatever was rebuilt in `/tmp/other/target` since.
        let mut ancestor = vec![test_candidate("/tmp/other", 0.9)];
        assert!(dispatch_top_candidates(
            &mut ancestor,
            &request,
            &del_tx,
            &mut pass
        ));
        assert!(del_rx.try_recv().is_err());
        assert_eq!(pass.count, 2);

        // Nothing new: no batch at all.
        let mut again = vec![test_candidate("/tmp/proj/target", 0.9)];
        assert!(dispatch_top_candidates(
            &mut again, &request, &del_tx, &mut pass
        ));
        assert!(del_rx.try_recv().is_err());
    }

    /// bd-1ouz: an opaque v2 candidate small enough to skip the reference
    /// probe is still vetoed when the daemon cannot see every process (a
    /// user-scoped macOS daemon), as v1 vetoes it; without the gap it is
    /// scored on its merits.
    #[test]
    fn visibility_gap_vetoes_a_candidate_that_skips_the_reference_probe() {
        use crate::scanner::scoring::{CandidateInput, DecisionAction, ScoringEngine};
        let engine = ScoringEngine::from_config(&Config::default().scoring, 0);
        let candidate = || CandidateInput {
            path: PathBuf::from("/tmp/proj/target"),
            size_bytes: 64 * 1024,
            age: Duration::from_hours(5),
            classification: ArtifactClassification {
                pattern_name: "opaque-cargo-target".into(),
                category: ArtifactCategory::RustTarget,
                name_confidence: 0.93,
                structural_confidence: 1.0,
                combined_confidence: 0.93,
            },
            signals: StructuralSignals::default(),
            active_references: ActiveReferenceSummary::default(),
            is_open: false,
            excluded: false,
        };

        let mut seen = candidate();
        mark_visibility_gap(&mut seen, None);
        assert!(!engine.score_candidate(&seen, 0.9).vetoed);

        let gap = crate::scanner::walker::MACOS_USER_SCOPE_ACTIVE_REFERENCE_WARNING;
        let mut blind = candidate();
        mark_visibility_gap(&mut blind, Some(gap));
        let score = engine.score_candidate(&blind, 0.9);
        assert!(score.vetoed);
        assert_eq!(score.decision.action, DecisionAction::Keep);
        assert_eq!(score.veto_reason.as_deref(), Some(gap));
    }

    #[test]
    fn temp_artifact_age_fast_track_applies_under_red_pressure() {
        let classification = ArtifactClassification {
            pattern_name: "agent-ft-suffix".into(),
            category: ArtifactCategory::AgentWorkspace,
            name_confidence: 0.90,
            structural_confidence: 0.70,
            combined_confidence: 0.84,
        };
        let adjusted = adjusted_candidate_age_after_arrival(
            Duration::from_mins(5),
            30,
            PressureLevel::Red,
            Path::new("/tmp/green-ft"),
            &classification,
            || Some(Duration::from_hours(48)),
        );
        assert_eq!(adjusted, Duration::from_mins(30));
    }

    /// bd-macg (JE's policy, 2026-10-14): a tree that arrived less than the
    /// minimum age ago keeps its real age under pressure. fmd deleted a fresh
    /// copy of relocated scratch five minutes after it was made, recorded at
    /// the 600 s minimum. An old tree with fresh contents is still
    /// fast-tracked, and an unknown arrival keeps the real age.
    #[test]
    fn a_tree_that_just_arrived_is_not_age_fast_tracked() {
        let scratch = ArtifactClassification {
            pattern_name: "mktemp-scratch".into(),
            category: ArtifactCategory::TempDir,
            name_confidence: 0.90,
            structural_confidence: 0.70,
            combined_confidence: 0.84,
        };
        let path = Path::new("/data/tmp/tmpfs-relocated-20261014/tmp/x/tmp.B9bB76Il49");
        let adjusted = |arrival: Option<Duration>| {
            adjusted_candidate_age_after_arrival(
                Duration::from_mins(5),
                10,
                PressureLevel::Orange,
                path,
                &scratch,
                || arrival,
            )
        };
        assert_eq!(
            adjusted(Some(Duration::from_mins(5))),
            Duration::from_mins(5)
        );
        assert_eq!(adjusted(None), Duration::from_mins(5));
        assert_eq!(
            adjusted(Some(Duration::from_hours(48))),
            Duration::from_mins(10)
        );

        // A directory created just now has just arrived.
        let fresh = tempfile::tempdir().unwrap();
        let arrived = candidate_arrival_age(fresh.path()).unwrap();
        assert!(arrived < Duration::from_mins(1), "{arrived:?}");
        assert!(candidate_arrival_age(&fresh.path().join("missing")).is_none());
    }

    /// bd-d1kt: on hz2 at Red, the registry/ and git/ of a cargo home that a
    /// running `cargo test` was compiling from were 5 and 8 minutes old,
    /// recorded as 1800 s and deleted. A CACHEDIR.TAG says a directory is
    /// regenerable, not that it is abandoned: it must be its real age.
    #[test]
    fn no_cache_or_cargo_home_is_age_fast_tracked() {
        let class = |pattern_name: &'static str, category| ArtifactClassification {
            pattern_name: pattern_name.into(),
            category,
            name_confidence: 0.9,
            structural_confidence: 1.0,
            combined_confidence: 0.9,
        };
        let observed = Duration::from_secs(174);
        let cases = [
            // The macOS proof: a default ~/.cargo under a temp home.
            (
                "/private/tmp/proof/home/.cargo/registry/src",
                class("opaque-cargo-cache", ArtifactCategory::CacheDir),
            ),
            (
                "/data/tmp/rch-cargo-cache-hz4/registry",
                class("cachedir-tagged-cache", ArtifactCategory::CacheDir),
            ),
            (
                "/data/tmp/job/go-build",
                class("opaque-go-build-cache", ArtifactCategory::GoCache),
            ),
            (
                "/data/tmp/cargo-home-x",
                class("cargo-home-prefix", ArtifactCategory::TempDir),
            ),
            (
                "/tmp/rch-cargo-home-1",
                class("rch-cargo-home", ArtifactCategory::TempDir),
            ),
        ];
        for (path, classification) in &cases {
            for level in [
                PressureLevel::Orange,
                PressureLevel::Red,
                PressureLevel::Critical,
            ] {
                assert_eq!(
                    adjusted_candidate_age(observed, 5, level, Path::new(path), classification),
                    observed,
                    "{path} at {level:?}"
                );
            }
        }
        // Build output in temp storage still is.
        assert_eq!(
            adjusted_candidate_age_after_arrival(
                observed,
                5,
                PressureLevel::Red,
                Path::new("/data/tmp/job/target"),
                &class("opaque-cargo-target", ArtifactCategory::RustTarget),
                || Some(Duration::from_hours(48)),
            ),
            Duration::from_mins(5)
        );
    }

    #[test]
    fn a_cachedir_tagged_cache_is_never_age_fast_tracked() {
        let tagged = ArtifactClassification {
            pattern_name: "cachedir-tagged-cache".into(),
            category: ArtifactCategory::CacheDir,
            name_confidence: 0.75,
            structural_confidence: 0.0,
            combined_confidence: 0.75,
        };
        let registry = Path::new("/data/tmp/ftcairo-1013/cargo-home/registry");
        for level in [
            PressureLevel::Orange,
            PressureLevel::Red,
            PressureLevel::Critical,
        ] {
            for observed in [Duration::from_mins(5), Duration::from_mins(8)] {
                assert_eq!(
                    adjusted_candidate_age(observed, 30, level, registry, &tagged),
                    observed,
                    "{level:?}"
                );
            }
        }
        // A cache old enough by its real age is unaffected.
        assert_eq!(
            adjusted_candidate_age(
                Duration::from_mins(45),
                30,
                PressureLevel::Red,
                registry,
                &tagged
            ),
            Duration::from_mins(45)
        );
        // A named build target beside it is still fast-tracked.
        let target = ArtifactClassification {
            pattern_name: "target".into(),
            category: ArtifactCategory::RustTarget,
            name_confidence: 0.95,
            structural_confidence: 0.9,
            combined_confidence: 0.93,
        };
        assert_eq!(
            adjusted_candidate_age_after_arrival(
                Duration::from_mins(5),
                30,
                PressureLevel::Red,
                Path::new("/data/tmp/ftcairo-1013/target"),
                &target,
                || Some(Duration::from_hours(48)),
            ),
            Duration::from_mins(30)
        );
    }

    #[test]
    fn temp_artifact_age_fast_track_skips_non_tmp_or_low_pressure() {
        let classification = ArtifactClassification {
            pattern_name: "agent-ft-suffix".into(),
            category: ArtifactCategory::AgentWorkspace,
            name_confidence: 0.90,
            structural_confidence: 0.70,
            combined_confidence: 0.84,
        };
        let base_age = Duration::from_mins(2);

        let low_pressure = adjusted_candidate_age(
            base_age,
            30,
            PressureLevel::Yellow,
            Path::new("/tmp/green-ft"),
            &classification,
        );
        assert_eq!(low_pressure, base_age);

        let non_tmp = adjusted_candidate_age(
            base_age,
            30,
            PressureLevel::Red,
            Path::new("/data/projects/green-ft"),
            &classification,
        );
        assert_eq!(non_tmp, base_age);
    }

    #[test]
    fn rch_in_tree_target_fast_tracks_outside_tmp_under_red_pressure() {
        // The bare in-tree `.rch-target/` sitting under /data/projects/...
        // is the case that left vmi1167313 stuck at 100% disk: not under
        // /tmp, mtime bumped continuously by active builds. With its
        // explicit pattern in the in-tree allowlist it should now have
        // its age veto bypassed under Red pressure.
        let classification = ArtifactClassification {
            pattern_name: "rch-target-bare-dot".into(),
            category: ArtifactCategory::RustTarget,
            name_confidence: 0.95,
            structural_confidence: 0.70,
            combined_confidence: 0.88,
        };
        let adjusted = adjusted_candidate_age_after_arrival(
            Duration::from_mins(5),
            30,
            PressureLevel::Red,
            Path::new("/data/projects/franken_engine/crates/franken-engine/.rch-target"),
            &classification,
            || Some(Duration::from_hours(48)),
        );
        assert_eq!(adjusted, Duration::from_mins(30));
    }

    #[test]
    fn rch_in_tree_target_does_not_fast_track_below_orange_pressure() {
        // Same in-tree path, but under Yellow (low) pressure: respect the
        // observed age. We only relax the gate when disk is genuinely tight.
        // `observed` is well above TEMP_FAST_TRACK_MIN_OBSERVED_AGE (2 min)
        // so the assertion isolates the pressure gate from the
        // observed-age threshold.
        let classification = ArtifactClassification {
            pattern_name: "rch-target-bare-dot".into(),
            category: ArtifactCategory::RustTarget,
            name_confidence: 0.95,
            structural_confidence: 0.70,
            combined_confidence: 0.88,
        };
        let observed = Duration::from_mins(5);
        let adjusted = adjusted_candidate_age(
            observed,
            30,
            PressureLevel::Yellow,
            Path::new("/data/projects/franken_engine/crates/franken-engine/.rch-target"),
            &classification,
        );
        assert_eq!(adjusted, observed);
    }

    #[test]
    fn unrelated_in_tree_target_still_blocked_outside_tmp() {
        // Belt-and-suspenders: a generic `target-suffix` match on an
        // in-tree path must not get fast-tracked — only the bare rch
        // patterns are special-cased.
        let classification = ArtifactClassification {
            pattern_name: "target-suffix".into(),
            category: ArtifactCategory::RustTarget,
            name_confidence: 0.88,
            structural_confidence: 0.70,
            combined_confidence: 0.83,
        };
        let observed = Duration::from_mins(2);
        let adjusted = adjusted_candidate_age(
            observed,
            30,
            PressureLevel::Red,
            Path::new("/data/projects/some_repo/cargo-target"),
            &classification,
        );
        assert_eq!(adjusted, observed);
    }

    #[test]
    fn temp_artifact_age_fast_track_accepts_high_confidence_patterns() {
        let classification = ArtifactClassification {
            pattern_name: "unknown-temp-pattern".into(),
            category: ArtifactCategory::AgentWorkspace,
            name_confidence: 0.90,
            structural_confidence: 0.30,
            combined_confidence: 0.60,
        };
        let adjusted = adjusted_candidate_age_after_arrival(
            Duration::from_mins(5),
            30,
            PressureLevel::Red,
            Path::new("/tmp/random-agent-build-cache"),
            &classification,
            || Some(Duration::from_hours(48)),
        );
        assert_eq!(adjusted, Duration::from_mins(30));
    }

    #[test]
    fn temp_artifact_age_fast_track_keeps_very_fresh_paths() {
        let classification = ArtifactClassification {
            pattern_name: "agent-ft-suffix".into(),
            category: ArtifactCategory::AgentWorkspace,
            name_confidence: 0.90,
            structural_confidence: 0.70,
            combined_confidence: 0.84,
        };
        let fresh_age = Duration::from_secs(30);
        let adjusted = adjusted_candidate_age(
            fresh_age,
            30,
            PressureLevel::Red,
            Path::new("/tmp/green-ft"),
            &classification,
        );
        assert_eq!(adjusted, fresh_age);
    }

    #[test]
    fn temp_artifact_age_fast_track_skips_node_modules_and_pycache() {
        let node_modules = ArtifactClassification {
            pattern_name: "node-modules".into(),
            category: ArtifactCategory::NodeModules,
            name_confidence: 0.97,
            structural_confidence: 0.80,
            combined_confidence: 0.92,
        };
        let pycache = ArtifactClassification {
            pattern_name: "python-pycache".into(),
            category: ArtifactCategory::PythonCache,
            name_confidence: 0.96,
            structural_confidence: 0.75,
            combined_confidence: 0.89,
        };
        let age = Duration::from_mins(5);

        let adjusted_node = adjusted_candidate_age(
            age,
            30,
            PressureLevel::Red,
            Path::new("/tmp/node_modules"),
            &node_modules,
        );
        assert_eq!(adjusted_node, age);

        let adjusted_pycache = adjusted_candidate_age(
            age,
            30,
            PressureLevel::Red,
            Path::new("/tmp/__pycache__"),
            &pycache,
        );
        assert_eq!(adjusted_pycache, age);
    }

    #[test]
    fn swap_thrash_risk_requires_high_swap_and_low_ram() {
        // High swap + ample RAM → NOT risky (cold pages swapped out, normal Linux behavior).
        let not_risky = MemoryInfo {
            total_bytes: 128 * 1024 * 1024 * 1024,
            available_bytes: 24 * 1024 * 1024 * 1024,
            swap_total_bytes: 64 * 1024 * 1024 * 1024,
            swap_free_bytes: 8 * 1024 * 1024 * 1024,
        };
        assert!(!is_swap_thrash_risk_inner(&not_risky, false));

        // Low swap usage → NOT risky regardless of RAM.
        let low_swap = MemoryInfo {
            swap_free_bytes: 40 * 1024 * 1024 * 1024,
            ..not_risky
        };
        assert!(!is_swap_thrash_risk_inner(&low_swap, false));

        // High swap + low RAM → RISKY (genuine memory exhaustion with active paging).
        let risky = MemoryInfo {
            available_bytes: 2 * 1024 * 1024 * 1024,
            ..not_risky
        };
        assert!(is_swap_thrash_risk_inner(&risky, false));
    }

    // ──────────────────── repeat deletion dampening ────────────────────

    #[test]
    fn repeat_dampening_new_path_no_dampening() {
        let tracker = RepeatDeletionTracker::new(Duration::from_mins(5), Duration::from_hours(1));
        let candidates = vec![test_candidate("/tmp/target/debug", 0.9)];
        let (approved, dampened) =
            tracker.filter_candidates(candidates, PressureLevel::Orange, 0.0);
        assert_eq!(approved.len(), 1);
        assert!(
            dampened.is_empty(),
            "expected no dampened candidates, got {}",
            dampened.len()
        );
    }

    #[test]
    fn repeat_dampening_within_cooldown_dampened() {
        let mut tracker =
            RepeatDeletionTracker::new(Duration::from_mins(5), Duration::from_hours(1));
        let path = PathBuf::from("/tmp/target/debug");
        tracker.record_deletions(std::slice::from_ref(&path));

        let candidates = vec![test_candidate("/tmp/target/debug", 0.9)];
        let (approved, dampened) =
            tracker.filter_candidates(candidates, PressureLevel::Orange, 0.0);
        assert!(
            approved.is_empty(),
            "expected the dampener to hold back every candidate, approved {}",
            approved.len()
        );
        assert_eq!(dampened.len(), 1);
    }

    #[test]
    fn repeat_dampening_after_cooldown_allowed() {
        let mut tracker = RepeatDeletionTracker::new(
            Duration::from_secs(0), // zero cooldown for test
            Duration::from_hours(1),
        );
        let path = PathBuf::from("/tmp/target/debug");
        tracker.record_deletions(std::slice::from_ref(&path));

        // With base_cooldown=0, the cooldown should already be expired.
        let candidates = vec![test_candidate("/tmp/target/debug", 0.9)];
        let (approved, dampened) =
            tracker.filter_candidates(candidates, PressureLevel::Orange, 0.0);
        assert_eq!(approved.len(), 1);
        assert!(
            dampened.is_empty(),
            "expected no dampened candidates, got {}",
            dampened.len()
        );
    }

    #[test]
    fn repeat_dampening_exponential_backoff_growth() {
        let mut tracker =
            RepeatDeletionTracker::new(Duration::from_mins(5), Duration::from_hours(1));
        let path = PathBuf::from("/tmp/target/debug");

        // 1st deletion: cycle_count becomes 1, cooldown = 300s
        tracker.record_deletions(std::slice::from_ref(&path));
        let cd1 = tracker.cooldown_for(&path).expect("should have cooldown");

        // 2nd deletion: cycle_count becomes 2, cooldown = 600s
        tracker.record_deletions(std::slice::from_ref(&path));
        let cd2 = tracker.cooldown_for(&path).expect("should have cooldown");

        // 3rd deletion: cycle_count becomes 3, cooldown = 1200s
        tracker.record_deletions(std::slice::from_ref(&path));
        let cd3 = tracker.cooldown_for(&path).expect("should have cooldown");

        // Each should be roughly double (within timing tolerance).
        assert!(cd2 > cd1, "cd2 ({cd2:?}) should be > cd1 ({cd1:?})");
        assert!(cd3 > cd2, "cd3 ({cd3:?}) should be > cd2 ({cd2:?})");
    }

    #[test]
    fn repeat_dampening_max_cooldown_cap() {
        let mut tracker =
            RepeatDeletionTracker::new(Duration::from_mins(5), Duration::from_hours(1));
        let path = PathBuf::from("/tmp/target/debug");

        // Record many deletions to push past max.
        for _ in 0..20 {
            tracker.record_deletions(std::slice::from_ref(&path));
        }

        let cooldown = tracker.cooldown_for(&path).expect("should have cooldown");
        // Cooldown should not exceed max_cooldown (3600s).
        assert!(
            cooldown <= Duration::from_hours(1),
            "cooldown {cooldown:?} should be <= 3600s"
        );
    }

    #[test]
    fn repeat_dampening_red_pressure_bypasses() {
        let mut tracker =
            RepeatDeletionTracker::new(Duration::from_mins(5), Duration::from_hours(1));
        let path = PathBuf::from("/tmp/target/debug");
        tracker.record_deletions(std::slice::from_ref(&path));

        let candidates = vec![test_candidate("/tmp/target/debug", 0.9)];
        let (approved, dampened) = tracker.filter_candidates(candidates, PressureLevel::Red, 0.0);
        assert_eq!(approved.len(), 1);
        assert!(
            dampened.is_empty(),
            "expected no dampened candidates, got {}",
            dampened.len()
        );
    }

    #[test]
    fn repeat_dampening_critical_pressure_bypasses() {
        let mut tracker =
            RepeatDeletionTracker::new(Duration::from_mins(5), Duration::from_hours(1));
        let path = PathBuf::from("/tmp/target/debug");
        tracker.record_deletions(std::slice::from_ref(&path));

        let candidates = vec![test_candidate("/tmp/target/debug", 0.9)];
        let (approved, dampened) =
            tracker.filter_candidates(candidates, PressureLevel::Critical, 0.0);
        assert_eq!(approved.len(), 1);
        assert!(
            dampened.is_empty(),
            "expected no dampened candidates, got {}",
            dampened.len()
        );
    }

    #[test]
    fn repeat_dampening_high_urgency_bypasses_at_yellow() {
        // Regression: ts1 sat at Yellow while disk filled because the
        // dampener had cooldowns on the same paths from previous attempts
        // and bypass only triggered at Red. High urgency means the
        // predictor expects Red imminently; we should act now.
        let mut tracker =
            RepeatDeletionTracker::new(Duration::from_mins(5), Duration::from_hours(1));
        let path = PathBuf::from("/tmp/target/debug");
        tracker.record_deletions(std::slice::from_ref(&path));

        let candidates = vec![test_candidate("/tmp/target/debug", 0.9)];
        let (approved, dampened) =
            tracker.filter_candidates(candidates, PressureLevel::Yellow, 0.95);
        assert_eq!(approved.len(), 1, "high urgency should bypass dampener");
        assert!(
            dampened.is_empty(),
            "expected no dampened candidates, got {}",
            dampened.len()
        );
    }

    #[test]
    fn repeat_dampening_low_urgency_at_yellow_still_dampens() {
        // Sanity: without urgency boost, Yellow still respects dampening.
        let mut tracker =
            RepeatDeletionTracker::new(Duration::from_mins(5), Duration::from_hours(1));
        let path = PathBuf::from("/tmp/target/debug");
        tracker.record_deletions(std::slice::from_ref(&path));

        let candidates = vec![test_candidate("/tmp/target/debug", 0.9)];
        let (approved, dampened) =
            tracker.filter_candidates(candidates, PressureLevel::Yellow, 0.5);
        assert!(
            approved.is_empty(),
            "expected the dampener to hold back every candidate, approved {}",
            approved.len()
        );
        assert_eq!(dampened.len(), 1);
    }

    #[test]
    fn repeat_dampening_mixed_paths() {
        let mut tracker =
            RepeatDeletionTracker::new(Duration::from_mins(5), Duration::from_hours(1));
        // Only record deletion for one path.
        tracker.record_deletions(&[PathBuf::from("/tmp/target/debug")]);

        let candidates = vec![
            test_candidate("/tmp/target/debug", 0.9),
            test_candidate("/tmp/node_modules", 0.8),
            test_candidate("/data/projects/build", 0.7),
        ];
        let (approved, dampened) =
            tracker.filter_candidates(candidates, PressureLevel::Orange, 0.0);
        assert_eq!(approved.len(), 2);
        assert_eq!(dampened.len(), 1);
        assert_eq!(dampened[0].path, Path::new("/tmp/target/debug"));
    }

    #[test]
    fn repeat_dampening_prune_removes_expired() {
        let mut tracker = RepeatDeletionTracker::new(
            Duration::from_mins(5),
            Duration::from_secs(0), // max_cooldown=0 so everything is instantly expired
        );
        tracker.record_deletions(&[PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")]);
        assert_eq!(tracker.history.len(), 2);

        // With max_cooldown=0 all entries are "expired" since elapsed > 0.
        std::thread::sleep(Duration::from_millis(1));
        tracker.prune_expired();
        assert!(tracker.history.is_empty());
    }

    #[test]
    fn repeat_dampening_cycle_count_increments() {
        let mut tracker =
            RepeatDeletionTracker::new(Duration::from_mins(5), Duration::from_hours(1));
        let path = PathBuf::from("/tmp/target/debug");

        tracker.record_deletions(std::slice::from_ref(&path));
        assert_eq!(tracker.history[&path].cycle_count, 1);

        tracker.record_deletions(std::slice::from_ref(&path));
        assert_eq!(tracker.history[&path].cycle_count, 2);

        tracker.record_deletions(std::slice::from_ref(&path));
        assert_eq!(tracker.history[&path].cycle_count, 3);
    }

    #[test]
    fn test_swap_thrash_logic_correct_behavior() {
        use crate::platform::pal::MemoryInfo;
        // High swap (80%), High RAM (16GB) → NOT risky.
        // On Linux, cold pages are swapped out even with ample RAM. This is
        // normal operation, not thrashing.
        let cold_pages = MemoryInfo {
            total_bytes: 32 * 1024 * 1024 * 1024,
            available_bytes: 16 * 1024 * 1024 * 1024, // 16 GB
            swap_total_bytes: 10 * 1024 * 1024 * 1024,
            swap_free_bytes: 2 * 1024 * 1024 * 1024, // 80% used
        };
        assert!(
            !super::is_swap_thrash_risk_inner(&cold_pages, false),
            "High swap with ample free RAM is cold-page swap, not thrashing"
        );

        // High swap (80%), Low RAM (100MB) → RISKY.
        // RAM is exhausted and swap is heavily used — genuine thrash risk.
        let genuine_thrash = MemoryInfo {
            total_bytes: 32 * 1024 * 1024 * 1024,
            available_bytes: 100 * 1024 * 1024, // 100 MB
            swap_total_bytes: 10 * 1024 * 1024 * 1024,
            swap_free_bytes: 2 * 1024 * 1024 * 1024, // 80% used
        };
        assert!(
            super::is_swap_thrash_risk_inner(&genuine_thrash, false),
            "High swap with exhausted RAM is genuine thrash risk"
        );

        // Zram-backed, High swap (80%), High RAM (50% free) → suppressed.
        assert!(
            !super::is_swap_thrash_risk_inner(&cold_pages, true),
            "High zram swap with plenty of free RAM should be suppressed"
        );

        // Zram-backed, High swap (80%), Low RAM (100MB) → RISKY.
        // Even with zram, if RAM is exhausted, real paging is happening.
        assert!(
            super::is_swap_thrash_risk_inner(&genuine_thrash, true),
            "Low RAM with high zram swap is genuine thrash risk"
        );
    }

    #[test]
    fn logging_ram_headroom_is_rechecked_only_while_pressured_and_at_most_every_30s() {
        let now = Instant::now();
        let earlier = |secs| now.checked_sub(Duration::from_secs(secs)).unwrap();
        // First pressured tick checks; an unpressured level never does.
        assert!(super::logging_ram_recheck_due(true, None, now));
        assert!(!super::logging_ram_recheck_due(false, None, now));
        assert!(!super::logging_ram_recheck_due(
            false,
            Some(earlier(600)),
            now
        ));
        // While pressured: not before the interval, then again after it.
        assert!(!super::logging_ram_recheck_due(
            true,
            Some(earlier(29)),
            now
        ));
        assert!(super::logging_ram_recheck_due(true, Some(earlier(30)), now));
        assert!(super::logging_ram_recheck_due(
            true,
            Some(earlier(300)),
            now
        ));
    }
}
