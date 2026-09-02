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

use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, TryRecvError, TrySendError, bounded};
use parking_lot::{Mutex, RwLock};
use serde_json::{Value, json};

use crate::ballast::coordinator::BallastPoolCoordinator;
use crate::ballast::release::BallastReleaseController;
use crate::core::config::{Config, ScannerConfig, ScannerEngineMode};
use crate::core::errors::{Result, SbhError};
use crate::daemon::cpu_budget::{CpuBudget, MAX_TICK_YIELD};
use crate::daemon::mount_controller::{
    IdleReason, MountController, MountControllerConfig, MountState, MountStateRecord, MountSurface,
    MountTickInput, ReserveState, WakeSignals, global_tick,
};
use crate::daemon::notifications::{NotificationEvent, NotificationLevel, NotificationManager};
use crate::daemon::policy::{
    ActiveMode, BallastAction, BehaviorDispatchTable, BehaviorMode, BehaviorPressureLevel,
    CleanupAction, NotificationPriority, PolicyEngine, ScanAggressiveness,
};
use crate::daemon::process_io_history::ProcessIoHistory;
use crate::daemon::self_monitor::{
    DaemonLock, MountPressure, MountRateState, PolicyStateRecord, SelfMonitor, SelfMonitorTick,
    ThreadHeartbeat, ThreadState, ThreadStatus, ThreadsState,
};
use crate::daemon::signals::{SignalHandler, WatchdogHeartbeat, resolve_watchdog_sec};
use crate::logger::dual::{
    ActivityEvent, ActivityLoggerHandle, DualLoggerConfig, ScanCompletionTelemetry, spawn_logger,
};
use crate::logger::jsonl::JsonlConfig;
use crate::monitor::ewma::{DiskRateEstimator, RateEstimate};
use crate::monitor::fs_stats::FsStatsCollector;
use crate::monitor::guardrails::{
    AdaptiveGuard, CalibrationObservation, DeletionFailureMonitor, GuardDiagnostics, GuardStatus,
    PredictionScorecard,
};
use crate::monitor::pid::{
    PidPressureController, PressureLevel, PressureReading, PressureResponse,
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
use crate::scanner::deletion::{DeletionConfig, DeletionExecutor};
use crate::scanner::engine::{ScannerEngine, SelectedScannerEngine};
use crate::scanner::events::{EventSourceConfig, ScannerEventSource};
use crate::scanner::index::{
    CandidateIndexRecord, IndexedIdentity, ScannerCandidateIndex, ScannerIndexContext,
    ScannerIndexLoadStatus,
};
use crate::scanner::patterns::{
    ArtifactCategory, ArtifactClassification, ArtifactPatternRegistry, OpaqueTreeDisposition,
    StructuralSignals,
};
use crate::scanner::protection::{self, ProtectionRegistry};
use crate::scanner::scoring::{
    ActiveReferenceSummary, ArtifactCertainty, CandidacyScore, ScoringEngine,
};
use crate::scanner::walker::{
    ActiveReferenceIndex, ActiveReferenceScanConfig, DirectoryWalker, WalkEntry, WalkerConfig,
    collect_active_reference_index_cached, collect_open_path_ancestors_cached,
};

// ──────────────────── channel capacities ────────────────────

/// Monitor → Scanner: bounded(2). Allows one buffered request while scanner
/// processes another. Under urgent pressure we replace one stale queued request
/// with the latest signal so high-priority actions are not starved.
const SCANNER_CHANNEL_CAP: usize = 2;
/// Scanner → Executor: bounded(64). Natural backpressure — scanner blocks on send.
const EXECUTOR_CHANNEL_CAP: usize = 64;
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
/// Cooldown between repeated swap-thrash warnings while pressure remains.
const SWAP_THRASH_WARNING_COOLDOWN: Duration = Duration::from_mins(15);
/// B5: minimum interval between "pressured device has no root_path" warnings.
const DEVICE_AFFINITY_WARN_INTERVAL: Duration = Duration::from_mins(15);
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
const MEMORY_PRESSURE_CHANNEL_CAP: usize = 16;
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
/// `state.json` and `sbh status`. Distinct from the health-check cadence:
/// a scan pass or a large deletion may legitimately run for tens of
/// seconds between beats.
const THREAD_STALL_THRESHOLD: Duration = Duration::from_secs(60);

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
}

impl SharedExecutorConfig {
    fn new(
        dry_run: bool,
        max_batch_size: usize,
        min_score: f64,
        repeat_base_cooldown: u64,
        repeat_max_cooldown: u64,
    ) -> Self {
        Self {
            dry_run: AtomicBool::new(dry_run),
            max_batch_size: AtomicUsize::new(max_batch_size),
            min_score_bits: AtomicU64::new(min_score.to_bits()),
            repeat_base_cooldown_secs: AtomicU64::new(repeat_base_cooldown),
            repeat_max_cooldown_secs: AtomicU64::new(repeat_max_cooldown),
            min_certainty_rank: AtomicU8::new(ArtifactCertainty::Unclear.rank()),
        }
    }

    fn min_certainty(&self) -> ArtifactCertainty {
        ArtifactCertainty::from_rank(self.min_certainty_rank.load(Ordering::Relaxed))
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

    fn repeat_base_cooldown_secs(&self) -> u64 {
        self.repeat_base_cooldown_secs.load(Ordering::Relaxed)
    }

    fn repeat_max_cooldown_secs(&self) -> u64 {
        self.repeat_max_cooldown_secs.load(Ordering::Relaxed)
    }
}

// ──────────────────── thread panic tracking ────────────────────

const MAX_RESPAWNS: u32 = 3;
const RESPAWN_WINDOW: Duration = Duration::from_mins(5);
const THREAD_HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(10);

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
    },
    /// Executor completed a deletion batch.
    DeletionCompleted {
        deleted: u64,
        bytes_freed: u64,
        failed: u64,
        /// Candidates whose filesystem answered EROFS or ENOSPC: their
        /// mounts need recovery, not another attempt.
        recovery_paths: Vec<PathBuf>,
        /// Set when the deletion-failure e-process crossed its alarm
        /// threshold on this batch: the dominant failure reason and count.
        failure_alarm: Option<(&'static str, u64)>,
    },
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
    /// hysteresis (the pressure levels did not change; the policy did).
    fn replace_table(&mut self, table: BehaviorDispatchTable) -> Option<BehaviorTransition> {
        self.table = table;
        self.pending_target = None;
        let next_mode = self.table.mode_for(self.memory_level, self.disk_level);
        if next_mode == self.mode {
            return None;
        }
        Some(self.apply_behavior_transition(self.memory_level, self.disk_level, next_mode))
    }

    fn table(&self) -> &BehaviorDispatchTable {
        &self.table
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
            self.pending_target = Some(PendingBehaviorTarget {
                memory_level,
                disk_level,
                mode: next_mode,
            });
            return BehaviorUpdate::Deferred {
                direction,
                remaining,
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
const REPORT_CHANNEL_CAP: usize = 64;

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

/// Entry budget for sizing one catalog root. A catalog scan probes every
/// derived root (a hundred or more under one home), so the per-root budget
/// is what bounds the whole pass: a truncated probe reports a size lower
/// bound and the tree's newest sampled mtime, which is enough to rank and
/// gate the root.
const CATALOG_PROBE_MAX_ENTRIES: usize = 50_000;
/// Depth budget for the catalog root probe.
const CATALOG_PROBE_MAX_DEPTH: usize = 5;

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
            0.25,  // kp
            0.08,  // ki
            0.02,  // kd
            100.0, // integral_cap
            config.pressure.green_min_free_pct,
            1.0, // hysteresis_pct
            config.pressure.green_min_free_pct,
            config.pressure.yellow_min_free_pct,
            config.pressure.orange_min_free_pct,
            config.pressure.red_min_free_pct,
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
        }
    }

    fn update_config(&mut self, config: &Config) {
        self.rate_estimator.update_params(
            config.telemetry.ewma_base_alpha,
            config.telemetry.ewma_min_alpha,
            config.telemetry.ewma_max_alpha,
            config.telemetry.ewma_min_samples,
        );

        self.pressure_controller
            .set_target_free_pct(config.pressure.green_min_free_pct);
        self.pressure_controller.set_pressure_thresholds(
            config.pressure.green_min_free_pct,
            config.pressure.yellow_min_free_pct,
            config.pressure.orange_min_free_pct,
            config.pressure.red_min_free_pct,
        );
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
    _daemon_lock: DaemonLock,
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
    /// Per-location alert throttle for the special-location horizon rule.
    special_alerts: AlertThrottle,
    /// When the last Green maintenance pass was dispatched.
    last_maintenance_scan: Option<Instant>,
    special_locations: SpecialLocationRegistry,
    ballast_coordinator: BallastPoolCoordinator,
    release_controller: BallastReleaseController,
    notification_manager: NotificationManager,
    scoring_engine: ScoringEngine,
    voi_scheduler: VoiScheduler,
    shared_executor_config: Arc<SharedExecutorConfig>,
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
    /// Per-special-location notification cooldown: tracks (highest notified level, last notify time).
    /// Prevents the same oscillation spam that the main pressure loop suppresses.
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
    /// Rate-limit for the B5 "pressured device has no root_path" warning so the
    /// back-off path does not spam logs on every tick.
    last_device_affinity_warn: Option<Instant>,
    last_summary_report: Instant,
    summary_scans: u64,
    summary_scan_timeouts: u64,
    summary_candidates: u64,
    summary_deleted: u64,
    summary_failed: u64,
    summary_bytes_freed: u64,
    last_full_disk_access_check: Option<Instant>,
    last_full_disk_access_state: Option<FullDiskAccessState>,
    full_disk_access_granted_logged: bool,
    process_io_history: ProcessIoHistory,
    self_monitor: SelfMonitor,
    tick_throttle: AdaptiveTickThrottle,
    policy_engine: Arc<Mutex<PolicyEngine>>,
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
    if !should_fast_track_temp_age(pressure_level, path, classification) {
        return observed_age;
    }
    if observed_age < TEMP_FAST_TRACK_MIN_OBSERVED_AGE {
        return observed_age;
    }

    let min_age = Duration::from_secs(min_file_age_minutes.saturating_mul(60));
    observed_age.max(min_age)
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
            base_budget_secs.saturating_mul(2).min(600)
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

fn scan_deadline_reached(scan_start: Instant, scan_deadline: Instant, phase: &str) -> bool {
    if Instant::now() < scan_deadline {
        return false;
    }
    eprintln!(
        "[SBH-SCANNER] {phase} budget reached ({:.1}s) — cancelling scan pass",
        scan_start.elapsed().as_secs_f64()
    );
    true
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
    scans_total: u64,
    deletions_total: u64,
    bytes_freed_total: u64,
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
            },
            "total": {
                "scans": counters.scans_total,
                "deletions": counters.deletions_total,
                "bytes_freed": counters.bytes_freed_total,
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
    #[allow(clippy::too_many_lines)]
    pub fn init(config: Config, args: &DaemonArgs) -> Result<Self> {
        let platform = detect_platform()?;
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
            jsonl_config: JsonlConfig {
                path: config.paths.jsonl_log.clone(),
                fallback_path: None,
                max_size_bytes: 50 * 1024 * 1024,
                max_rotated_files: 5,
                fsync_interval_secs: 30,
            },
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
        ballast_coordinator.set_provision_floor(config.ballast_provision_floor_pct());
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
        }

        // 7. Release controller.
        let release_controller =
            BallastReleaseController::new(config.ballast.replenish_cooldown_minutes);

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
        ));

        let shared_scoring_config = Arc::new(RwLock::new(config.scoring.clone()));
        let shared_scanner_config = Arc::new(RwLock::new(config.scanner.clone()));

        // 11. Self-monitor (writes state.json for CLI, tracks health).
        let mut self_monitor = SelfMonitor::from_telemetry_config(
            config.paths.state_file.clone(),
            Arc::clone(&platform),
            &config.telemetry,
        );
        self_monitor.set_run_id(run_id);
        let process_io_history = ProcessIoHistory::load_or_new(
            ProcessIoHistory::snapshot_path_for_state_file(&config.paths.state_file),
        );

        // 12. Thread heartbeats for worker health detection.
        let scanner_heartbeat = ThreadHeartbeat::new("sbh-scanner");
        let executor_heartbeat = ThreadHeartbeat::new("sbh-executor");

        // 13. Notification manager.
        let notification_manager = NotificationManager::from_config(&config.notifications);

        // 14. Policy engine (progressive delivery gates for deletion pipeline).
        let policy_engine = Arc::new(Mutex::new(PolicyEngine::new(config.policy.clone())));
        let shared_guard_diagnostics = Arc::new(RwLock::new(None));
        let behavior_state = PressureBehaviorState::new(
            behavior_table_from_config(&config),
            MemoryPressureLevel::Unknown,
            PressureLevel::Green,
        );

        let prediction_config = config.pressure.prediction.clone();
        // Q7: calibrated to the CPU already spent on startup so that work
        // (config load, ballast discovery) is not charged to the first tick.
        let cpu_budget = Arc::new(Mutex::new(CpuBudget::new(
            config.telemetry.cpu_budget_pct,
            Instant::now(),
            self_monitor.current_cpu_secs(),
        )));

        Ok(Self {
            config,
            platform,
            logger_handle,
            logger_join: Some(logger_join),
            signal_handler,
            watchdog,
            cpu_budget,
            _daemon_lock: daemon_lock,
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
            special_alerts: AlertThrottle::default(),
            last_maintenance_scan: None,
            special_locations,
            ballast_coordinator,
            release_controller,
            notification_manager,
            policy_engine,
            scoring_engine,
            voi_scheduler,
            shared_executor_config,
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
            scan_channel_warn_suppressed: 0,
            last_device_affinity_warn: None,
            last_summary_report: Instant::now(),
            summary_scans: 0,
            summary_scan_timeouts: 0,
            summary_candidates: 0,
            summary_deleted: 0,
            summary_failed: 0,
            summary_bytes_freed: 0,
            last_full_disk_access_check: None,
            last_full_disk_access_state: None,
            full_disk_access_granted_logged: false,
            process_io_history,
            self_monitor,
            tick_throttle: AdaptiveTickThrottle::default(),
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
            } => {
                let message = format!(
                    "behavior mode transition deferred source={source} direction={direction:?} \
                     remaining_ms={}",
                    remaining.as_millis()
                );
                eprintln!("[SBH-DAEMON] {message}");
            }
            BehaviorUpdate::Unchanged => {}
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

            let wait = remaining.min(MEMORY_PRESSURE_WAKE_INTERVAL);
            match rx.recv_timeout(wait) {
                Ok(event) => {
                    self.update_behavior_mode(
                        event.pressure.level,
                        disk_level,
                        "memory_pressure",
                        event.received_at.elapsed(),
                    );
                    self.drain_memory_pressure_events(rx, disk_level);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
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
                scans_total: self.self_monitor.scan_count,
                deletions_total: self.self_monitor.deletions_total,
                bytes_freed_total: self.self_monitor.bytes_freed_total,
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
            let Some(pool) = inventory
                .iter()
                .find(|item| item.mount_point == mount && !item.skipped)
            else {
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

        // Provision ballast files (idempotent).
        self.provision_ballast()?;

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

        // Startup is complete: workers are running and the first state file is
        // written. Type=notify units wait for this READY=1 and are killed at
        // TimeoutStartSec without it.
        if let Err(error) = self.platform.service_manager().notify_ready() {
            eprintln!("[SBH-DAEMON] sd_notify READY=1 failed: {error}");
        }

        let mut last_health_check = Instant::now();
        let mut shutdown_result = Ok(());

        // ──────── main monitoring loop ────────
        loop {
            let tick_start = Instant::now();

            // 1. Check shutdown signal.
            if self.signal_handler.should_shutdown() {
                eprintln!("[SBH-DAEMON] shutdown requested");
                break;
            }

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
                self.behavior_state.memory_level,
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

            // 5. Handle pressure response per mount; the tick follows the
            //    tightest mount sbh is actually working on.
            let requested_tick = self.handle_pressure(&response, &scan_tx, &scan_rx);

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
                    } => {
                        self.summary_scans += 1;
                        if timed_out {
                            self.summary_scan_timeouts += 1;
                        }
                        self.summary_candidates += candidates as u64;
                        self.self_monitor.record_scan(candidates, 0, duration);
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
                            self.note_scan_pass_per_mount(&root_stats, now);
                        }
                    }
                    WorkerReport::DeletionCompleted {
                        deleted,
                        bytes_freed,
                        failed,
                        recovery_paths,
                        failure_alarm,
                    } => {
                        self.summary_deleted += deleted;
                        self.summary_failed += failed;
                        self.summary_bytes_freed += bytes_freed;
                        self.self_monitor.record_deletions(deleted, bytes_freed);
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
            if self.signal_handler.should_scan() {
                self.trigger_forced_scan(&scan_tx, &response);
                self.wake_next_tick.forced_scan = true;
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
                     failed={} freed={}B pressure={:?} guard={} mode={} rss={}MB uptime={}s",
                    self.summary_scans,
                    self.summary_scan_timeouts,
                    self.summary_candidates,
                    self.summary_deleted,
                    self.summary_failed,
                    self.summary_bytes_freed,
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

            // Predicted time to red threshold.
            let predicted_seconds = if rate_estimate.seconds_to_threshold.is_finite()
                && rate_estimate.seconds_to_threshold > 0.0
            {
                Some(rate_estimate.seconds_to_threshold)
            } else {
                None
            };

            // Run PID controller.
            let reading = PressureReading {
                free_bytes: stats.available_bytes,
                total_bytes: stats.total_bytes,
                mount: stats.mount_point.clone(),
            };
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
                    eprintln!(
                        "[SBH-DAEMON] emergency escalation: fallback_safe → enforce \
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
            self.release_controller
                .observe_level(&mount, tick.response.level);

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
                                self.catalog_epochs
                                    .insert(mount.clone(), (tick.response.level, now));
                                self.send_catalog_scan_request(
                                    scan_tx,
                                    scan_rx,
                                    &tick.response,
                                    catalog,
                                );
                                self.last_tick_cleanup_ran = true;
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
                            self.send_scan_request(scan_tx, scan_rx, &tick.response, paths);
                            self.last_tick_cleanup_ran = true;
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

        global_tick(cadence, base_poll)
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
                .on_released(mount, report.files_released);
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
    fn note_scan_pass_per_mount(&mut self, root_stats: &[RootScanResult], now: Instant) {
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
            if let Some((from, to)) = controller.note_pass(found, releasable, now) {
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

    /// Replenish one released ballast file on `mount` if its pool is short and
    /// the release controller's cooldown allows it. Returns whether a file was
    /// created.
    fn maybe_replenish_pool(&mut self, mount: &Path, level: PressureLevel) -> bool {
        let Some(pool_info) = self
            .ballast_coordinator
            .inventory()
            .into_iter()
            .find(|item| item.mount_point == mount)
        else {
            return false;
        };
        if !self.release_controller.is_ready_for_replenish(
            mount,
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
            self.floor_limited.insert(mount.to_path_buf());
        } else if report.files_created > 0 {
            self.floor_limited.remove(mount);
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
            .on_replenished(mount, report.files_created);
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
        let count = self
            .release_controller
            .files_to_release(mount, response, available, expected);

        let mut released = 0;
        if count > 0
            && let Some(report) = self.ballast_coordinator.release_for_mount(mount, count)?
        {
            for warning in &report.warnings {
                eprintln!("[sbh] warning: {warning}");
            }

            released = report.files_released;
            self.release_controller
                .on_released(mount, report.files_released);
            self.log_ballast_releases(&report.released, response);

            self.notification_manager
                .notify(&NotificationEvent::BallastReleased {
                    mount: mount.to_string_lossy().to_string(),
                    files_released: report.files_released,
                    bytes_freed: report.bytes_freed,
                });
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

    fn trigger_forced_scan(
        &self,
        scan_tx: &Sender<ScanRequest>,
        response: &crate::monitor::pid::PressureResponse,
    ) {
        eprintln!("[SBH-DAEMON] forced scan triggered (SIGUSR1)");
        let request = ScanRequest {
            paths: self.config.scanner.root_paths.clone(),
            urgency: response.urgency.max(0.5), // at least moderate urgency for forced scans
            pressure_level: response.level,
            free_pct: Some(response.free_pct),
            max_delete_batch: response.max_delete_batch,
            force_full_scan: true,
            config_update: None,
            catalog_roots: Vec::new(),
            maintenance: false,
        };
        // For forced scans, block briefly to ensure delivery.
        let _ = scan_tx.send_timeout(request, Duration::from_millis(100));
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

            if assessment.alert == SpecialAlert::None {
                self.last_special_notify.remove(&location.path);
                continue;
            }
            {
                let urgency = assessment.urgency;
                let pressure_level = match assessment.alert {
                    SpecialAlert::Critical => PressureLevel::Red,
                    _ if urgency >= 0.75 => PressureLevel::Orange,
                    _ => PressureLevel::Yellow,
                };
                // Notify on a level change for this location; the same level
                // does not re-fire (the condition has not changed).
                let should_notify_special = self
                    .last_special_notify
                    .get(&location.path)
                    .is_none_or(|(prev_level, _)| pressure_level != *prev_level);

                if should_notify_special {
                    self.notification_manager
                        .notify(&NotificationEvent::PressureChanged {
                            from: "Green".to_string(),
                            to: format!("{pressure_level:?}"),
                            mount: location.path.to_string_lossy().into_owned(),
                            free_pct: stats.free_pct(),
                        });
                    self.last_special_notify
                        .insert(location.path.clone(), (pressure_level, now));
                }

                // Trigger root filesystem scan: special location pressure (e.g. /dev/shm
                // full) indicates agent swarm activity that is likely also generating root
                // filesystem artifacts. Proactively scan to clean up before root hits capacity.
                let max_delete_batch = match pressure_level {
                    PressureLevel::Red | PressureLevel::Critical => 100,
                    PressureLevel::Orange => 60,
                    _ => 40,
                };

                // Try immediate ballast release for the pressured mount.
                // If that mount has no pool (common for /dev/shm tmpfs), fall back to the
                // non-empty pool with highest releasable bytes to buy recovery time.
                let release_mount = if self.ballast_coordinator.has_pool(&stats.mount_point) {
                    Some(stats.mount_point.clone())
                } else {
                    self.ballast_coordinator
                        .inventory()
                        .into_iter()
                        .filter(|item| !item.skipped && item.files_available > 0)
                        .max_by_key(|item| item.releasable_bytes)
                        .map(|item| item.mount_point)
                };

                if let Some(mount) = release_mount {
                    let release_response = crate::monitor::pid::PressureResponse {
                        level: pressure_level,
                        urgency,
                        scan_interval: Duration::from_secs(0),
                        release_ballast_files: 0,
                        max_delete_batch,
                        fallback_active: false,
                        causing_mount: mount.clone(),
                        free_pct: stats.free_pct(),
                        predicted_seconds: None,
                    };
                    let _ = self.release_ballast(&mount, &release_response);
                }

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
        let report = self
            .ballast_coordinator
            .provision_all(self.platform.as_ref())?;

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
                    self.release_controller = BallastReleaseController::new(
                        new_config.ballast.replenish_cooldown_minutes,
                    );
                    self.release_controller.reset();
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
                                .set_provision_floor(new_config.ballast_provision_floor_pct());
                        }
                        Err(err) => {
                            eprintln!(
                                "[SBH-DAEMON] ballast coordinator rediscovery failed during reload: {err}"
                            );
                            self.ballast_coordinator.update_config(&new_config.ballast);
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
                    self.cpu_budget
                        .lock()
                        .set_pct(new_config.telemetry.cpu_budget_pct);

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
        let cpu_budget = Arc::clone(&self.cpu_budget);
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
                    &index_feedback_rx,
                    &cpu_budget,
                );
            })
            .map_err(|source| SbhError::Runtime {
                details: format!("failed to spawn scanner thread: {source}"),
            })
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

        // 0. Tell the service manager an orderly stop has begun so it does not
        // count the exit against Restart=on-failure while workers drain.
        if let Err(error) = self.platform.service_manager().notify_stopping() {
            eprintln!("[SBH-DAEMON] sd_notify STOPPING=1 failed: {error}");
        }

        // 1. Broadcast cancellation, then drop channel senders to signal worker threads to exit.
        self.signal_handler.request_shutdown();
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

fn dispatch_top_candidates(
    scored: &mut Vec<CandidacyScore>,
    request: &ScanRequest,
    del_tx: &Sender<DeletionBatch>,
    dispatched: &mut usize,
) -> bool {
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
    };
    let batch_len = batch.candidates.len();

    // Non-blocking send preserves scanner progress and avoids deadlock when
    // executor is slow. If channel is full, re-queue candidates locally so the
    // scanner can retry later in this pass.
    match del_tx.try_send(batch) {
        Ok(()) => {
            // These candidates were handed to the deletion executor — i.e. real
            // reclaim work was started this pass. Counted so the inter-pass
            // cooldown (B6) distinguishes a *productive* pass from one that
            // surfaced candidates but dispatched none (all protected/dampened).
            *dispatched += batch_len;
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
    let reason = overlaps
        .first()
        .map(|overlap| format!("sacred path overlap: {}", overlap.summary()));
    if let Some(reason) = reason.as_ref() {
        protection.cache_protected_verdict(path, reason.clone());
    }
    Ok(reason)
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
    logger: &ActivityLoggerHandle,
) -> std::result::Result<CandidacyScore, ReplayDrop> {
    use crate::scanner::active_lease::{ActiveLeaseState, inspect_path};
    use crate::scanner::index::IndexedIdentity;
    use crate::scanner::patterns::ArtifactCategory;
    use crate::scanner::scoring::{CandidateInput, DecisionAction};
    use crate::scanner::walker::{
        TREE_IDLE_PROBE_MAX_DEPTH, TREE_IDLE_PROBE_MAX_ENTRIES, identity_for_path,
        is_path_open_by_ancestor, structural_signals_for_path, tree_newest_mtime,
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
    let signals = structural_signals_for_path(path);
    if signals.has_git || signals.has_cargo_toml {
        return Err(ReplayDrop::Vetoed("source tree markers".to_string()));
    }
    let classification = registry.classify(path, signals);
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
    let input = CandidateInput {
        path: path.clone(),
        size_bytes: record.size_estimate_bytes.max(allocated),
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
    /// `dirs_with_candidates` — directories that had at least one classified child.
    /// `timed_out` — whether the scan hit its time/entry budget.
    ///
    /// Only caches barren dirs when the scan timed out (no point caching if the
    /// scan completed — next scan should be fresh). On a full completion, the
    /// cache is cleared to allow re-discovery.
    fn update(
        &mut self,
        visited_dirs: &HashSet<PathBuf>,
        dirs_with_candidates: &HashSet<PathBuf>,
        timed_out: bool,
    ) {
        if !timed_out {
            // Full scan completed — clear cache so next scan is fresh.
            self.barren_dirs.clear();
            return;
        }

        let now = Instant::now();

        // Add newly discovered barren dirs.
        for dir in visited_dirs {
            if !dirs_with_candidates.contains(dir) {
                self.barren_dirs.entry(dir.clone()).or_insert(now);
            }
        }

        // Remove dirs that turned out to have candidates (they may have been
        // cached as barren from a prior pass but gained artifacts since).
        for dir in dirs_with_candidates {
            self.barren_dirs.remove(dir);
        }

        // Expire old entries.
        self.barren_dirs
            .retain(|_, ts| now.duration_since(*ts) < self.ttl);

        // Cap size: if over limit, drop oldest entries.
        if self.barren_dirs.len() > self.max_entries {
            let mut entries: Vec<_> = self.barren_dirs.drain().collect();
            entries.sort_by_key(|(_, ts)| std::cmp::Reverse(*ts));
            entries.truncate(self.max_entries);
            self.barren_dirs = entries.into_iter().collect();
        }
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
    index_feedback_rx: &Receiver<ScannerIndexFeedback>,
    cpu_budget: &Arc<Mutex<CpuBudget>>,
) {
    const DIR_SIZE_FLOOR: u64 = 100 * 1_048_576; // 100 MiB

    // Initialize pattern registry (default built-ins).
    let pattern_registry = ArtifactPatternRegistry::default();

    // Incremental scan cursor — persists across scan iterations to skip
    // barren directory subtrees that yielded no candidates on a prior pass.
    let mut scan_cursor = ScanCursor::new();
    let mut scanner_index: Option<ScannerCandidateIndex> = None;
    let mut scanner_event_source: Option<ScannerEventSource> = None;

    // Cache of directories known to contain .git — these are valid project
    // roots that should never be deleted. Persists across scan passes to
    // avoid re-discovering and re-rejecting the same paths every 10 minutes
    // (previously caused thousands of ContainsGit log entries per hour).
    let mut known_git_dirs: HashSet<PathBuf> = HashSet::new();
    let mut last_scanner_engine_mode: Option<ScannerEngineMode> = None;

    // B6: inter-pass cooldown. When a pass dispatches nothing reclaimable,
    // re-scanning immediately under sustained pressure just pins a core. We
    // record when the last empty pass finished and skip subsequent pressure-
    // driven passes until the (exponentially backed-off) rescan interval has
    // elapsed. `consecutive_empty_passes` grows the interval while the disk
    // stays pressured with nothing to reclaim, and resets on a productive pass.
    let mut last_empty_pass_at: Option<Instant> = None;
    let mut consecutive_empty_passes: u32 = 0;

    // #15: duty-cycle limiter. The empty-pass cooldown above only paces passes
    // that reclaimed nothing; a chronically-full host reclaims a trickle every
    // pass, resetting that counter forever and re-walking back-to-back at ~100%
    // CPU. Tracking how long the last pass took lets us owe proportional idle
    // afterwards, capping scanner CPU regardless of pressure level.
    let mut last_pass_finished_at: Option<Instant> = None;
    let mut last_pass_duration = Duration::ZERO;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let request = match scan_rx.recv_timeout(WORKER_SHUTDOWN_POLL_INTERVAL) {
            Ok(request) => request,
            Err(RecvTimeoutError::Timeout) => {
                // Idle is alive: "stalled" must mean stuck inside a pass,
                // not waiting for one.
                heartbeat.beat();
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        };
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Read latest config at the start of each scan.
        let current_scoring_config = shared_scoring_config.read().clone();
        let current_scanner_config = shared_scanner_config.read().clone();

        // B6: skip this pressure-driven pass if recent passes dispatched
        // nothing reclaimable and the (backed-off) cooldown has not elapsed.
        // Operator/forced scans, config reloads, and Red/Critical pressure
        // always run.
        if empty_pass_cooldown_active(
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
            cpu_budget
                .lock()
                .pass_allowance(request.pressure_level, current_scanner_config.parallelism)
        };
        if budget_allowance == Some(Duration::ZERO) {
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
        let scanner_index_event_generation = if scanner_index_enabled {
            let context =
                ScannerIndexContext::from_roots_and_config(&request.paths, &current_scanner_config);
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
                            "scanner_events: backend={} complete={} watched_dirs={} dirty_roots={} reason={}",
                            capability.selected_backend,
                            capability.complete,
                            capability.watched_dirs,
                            capability.dirty_roots.len(),
                            capability.reason
                        ),
                    });
                }
            }
            if let Some(source) = scanner_event_source.as_mut() {
                let invalidation = source.drain();
                scanner_event_dirty_roots.clone_from(invalidation.dirty_roots());
                if invalidation.requires_reconciliation() {
                    logger.send(ActivityEvent::Info {
                        message: format!(
                            "scanner_events: dirty_roots={} dirty_paths={} generation_bump={} reason={}",
                            invalidation.dirty_roots().len(),
                            invalidation.dirty_paths().len(),
                            invalidation.requires_index_generation_bump(),
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
        let scan_reason = scan_reason_for_request(&request);
        // (replayed, re-vetoed) index records this pass; a Cell so the
        // telemetry closure can read what the replay block writes.
        let replay_counts = std::cell::Cell::new((0usize, 0usize));
        let scan_completion_telemetry =
            |opaque_pruned_dirs: usize,
             candidate_bytes_seen: u64,
             timed_out: bool,
             index_records: usize| ScanCompletionTelemetry {
                engine: scanner_engine_mode.to_string(),
                dispatch: scanner_dispatch.to_string(),
                scan_reason: scan_reason.to_string(),
                opaque_pruning: scanner_opaque_pruning,
                opaque_pruned_dirs,
                event_dirty_roots: scanner_event_dirty_roots.len(),
                index_event_generation: scanner_index_event_generation,
                index_records,
                candidate_bytes_seen,
                timed_out,
                replayed_records: replay_counts.get().0,
                revetoed_records: replay_counts.get().1,
            };
        if last_scanner_engine_mode != Some(scanner_engine_mode) {
            logger.send(ActivityEvent::Info {
                message: format!(
                    "scanner_engine: mode={scanner_engine_mode} dispatch={scanner_dispatch} shadow_mode={scanner_shadow_mode} opaque_pruning={scanner_opaque_pruning}"
                ),
            });
            last_scanner_engine_mode = Some(scanner_engine_mode);
        }

        let engine = ScoringEngine::from_config(
            &current_scoring_config,
            current_scanner_config.min_file_age_minutes,
        );

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
                    dirty: scanner_event_dirty_roots.contains(path),
                })
                .collect();
            let _ = report_tx.try_send(WorkerReport::ScanCompleted {
                candidates: 0,
                duration: Duration::ZERO,
                root_stats,
                timed_out: false,
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
        let mut scan_deadline =
            scan_start + effective_scan_budget(&current_scanner_config, request.pressure_level);
        // Q7: the walker's deadline checks end the pass when the CPU budget
        // runs out (it then reports as timed out; partial results still
        // dispatch).
        if let Some(allowance) = budget_allowance {
            scan_deadline = scan_deadline.min(scan_start + allowance);
        }

        // Track total candidates found (priority pre-scan + general walker).
        let mut candidates_found = 0;
        // Track candidates actually dispatched to the deletion executor this
        // pass — the signal for whether the pass made reclaim progress (drives
        // the B6 empty-pass cooldown). A pass can surface many candidates yet
        // dispatch zero when they are all protected/dampened.
        let mut dispatched_this_pass: usize = 0;
        let mut scanner_should_exit = false;
        let mut scan_timed_out = false;
        let v2_candidate_byte_target = if scanner_index_enabled {
            v2_pressure_candidate_byte_target(&request)
        } else {
            None
        };
        let mut v2_candidate_bytes_seen = 0u64;

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
            let records = index.ranked_records(replay_now, request.max_delete_batch);
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
                let mut replay_sacred = platform.sacred_paths();
                replay_sacred.extend(protection::sacred_paths_from_protected_patterns(
                    &current_scanner_config.protected_paths,
                ));
                let replay_engine = ScoringEngine::from_config(
                    &current_scoring_config,
                    current_scanner_config.min_file_age_minutes,
                );
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
                        logger,
                    ) {
                        Ok(score) => {
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
                            if drop != ReplayDrop::GenerationAdvanced {
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
                            dirty: scanner_event_dirty_roots.contains(path),
                        })
                        .collect();
                    let _ = report_tx.try_send(WorkerReport::ScanCompleted {
                        candidates: candidates_found,
                        duration: Duration::ZERO,
                        root_stats,
                        timed_out: false,
                    });
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

        // ── Priority pre-scan pass ──
        // Before the general walker, do a shallow (depth 1-2) scan of each root
        // for known high-value cleanup targets. This ensures multi-GB dirs like
        // `target/`, `node_modules/`, `rch_target_*` are found in seconds, not
        // after 500K small files exhaust the entry budget.
        let mut priority_candidates: Vec<CandidacyScore> = Vec::new();
        {
            let prescan_engine = ScoringEngine::from_config(
                &current_scoring_config,
                current_scanner_config.min_file_age_minutes,
            );
            'priority_roots: for root in &active_scan_paths {
                if shutdown.load(Ordering::Relaxed) {
                    scanner_should_exit = true;
                    break;
                }
                if scan_deadline_reached(scan_start, scan_deadline, "priority pre-scan") {
                    scan_timed_out = true;
                    break;
                }
                if let Ok(entries) = std::fs::read_dir(root) {
                    for entry in entries.flatten() {
                        if shutdown.load(Ordering::Relaxed) {
                            scanner_should_exit = true;
                            break 'priority_roots;
                        }
                        if scan_deadline_reached(scan_start, scan_deadline, "priority pre-scan") {
                            scan_timed_out = true;
                            break 'priority_roots;
                        }
                        let path = entry.path();
                        if !path.is_dir() {
                            continue;
                        }
                        if should_skip_protected_daemon_candidate(
                            &mut protection,
                            &path,
                            &sacred_paths,
                            logger,
                            "priority pre-scan",
                        ) {
                            continue;
                        }
                        // Track whether depth-1 dir is a git repo (project root).
                        // Project roots themselves must never be deletion candidates,
                        // but we still need to check their children for artifacts
                        // like `target/` and `node_modules/`.
                        let is_git_repo =
                            known_git_dirs.contains(&path) || path.join(".git").exists();
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
                                if scan_deadline_reached(
                                    scan_start,
                                    scan_deadline,
                                    "priority pre-scan",
                                ) {
                                    scan_timed_out = true;
                                    break 'priority_roots;
                                }
                                let sub_path = sub_entry.path();
                                if sub_path.is_dir() {
                                    if should_skip_protected_daemon_candidate(
                                        &mut protection,
                                        &sub_path,
                                        &sacred_paths,
                                        logger,
                                        "priority pre-scan",
                                    ) {
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
                                                if scan_deadline_reached(
                                                    scan_start,
                                                    scan_deadline,
                                                    "priority pre-scan",
                                                ) {
                                                    scan_timed_out = true;
                                                    break 'priority_roots;
                                                }
                                                let d3_path = d3_entry.path();
                                                if d3_path.is_dir() {
                                                    if should_skip_protected_daemon_candidate(
                                                        &mut protection,
                                                        &d3_path,
                                                        &sacred_paths,
                                                        logger,
                                                        "priority pre-scan",
                                                    ) {
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
                            if should_skip_protected_daemon_candidate(
                                &mut protection,
                                &candidate_path,
                                &sacred_paths,
                                logger,
                                "priority pre-scan",
                            ) {
                                continue;
                            }
                            let candidate_class = pattern_registry
                                .classify(&candidate_path, StructuralSignals::default());
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
                                signals: StructuralSignals::default(),
                                active_references: ActiveReferenceSummary::default(),
                                is_open: false,
                                excluded: false,
                            };
                            let mut score = prescan_engine.score_candidate(&input, request.urgency);
                            if score.decision.action
                                == crate::scanner::scoring::DecisionAction::Delete
                                && !score.vetoed
                                && active_reference_scan.should_probe(size)
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
                                    let active_references = active_reference_joined
                                        .get_or_insert_with(|| {
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
                            if score.decision.action
                                == crate::scanner::scoring::DecisionAction::Delete
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
                            if score.decision.action
                                == crate::scanner::scoring::DecisionAction::Delete
                            {
                                score.identity = crate::scanner::walker::identity_for_path(
                                    &candidate_path,
                                    current_scanner_config.follow_symlinks,
                                )
                                .ok();
                                let mut scanner_index_backoff_active = false;
                                if scanner_index_enabled {
                                    match CandidateIndexRecord::from_candidate_score(
                                        &score,
                                        None,
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
                                if !scanner_index_backoff_active {
                                    priority_candidates.push(score);
                                }
                            }
                        }
                    }
                }
            }
        }
        if scanner_should_exit {
            break;
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
                    dirty: scanner_event_dirty_roots.contains(path),
                })
                .collect();
            let _ = report_tx.send(WorkerReport::ScanCompleted {
                candidates: candidates_found,
                duration,
                root_stats,
                timed_out: true,
            });
            eprintln!(
                "[SBH-SCANNER] scan complete: 0 entries, {candidates_found} candidates, {:.1}s (timed out)",
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
            logger.send(ActivityEvent::ScanCompleted {
                paths_scanned: 0,
                candidates_found,
                duration_ms: duration.as_millis().try_into().unwrap_or(u64::MAX),
                telemetry: scan_completion_telemetry(
                    0,
                    v2_candidate_bytes_seen,
                    true,
                    scanner_index.as_ref().map_or(0, ScannerCandidateIndex::len),
                ),
            });
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
            logger.send(ActivityEvent::ScanCompleted {
                paths_scanned: 0,
                candidates_found,
                duration_ms: duration.as_millis().try_into().unwrap_or(u64::MAX),
                telemetry: scan_completion_telemetry(
                    0,
                    v2_candidate_bytes_seen,
                    false,
                    scanner_index.as_ref().map_or(0, ScannerCandidateIndex::len),
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
                    dirty: scanner_event_dirty_roots.contains(path),
                })
                .collect();
            let _ = report_tx.try_send(WorkerReport::ScanCompleted {
                candidates: candidates_found,
                duration,
                root_stats,
                timed_out: false,
            });
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

        // Catalog-only requests do not walk: each derived root is one opaque
        // candidate unit, sized and dated by a bounded probe, and flows
        // through the same classification, scoring, vetoes and dispatch below.
        let (rx, cancel_token) = if request.catalog_roots.is_empty() {
            let walker = DirectoryWalker::new(walker_config, protection).with_heartbeat({
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
            let (tx, rx) = crossbeam_channel::unbounded::<WalkEntry>();
            for entry in entries {
                let _ = tx.send(entry);
            }
            drop(tx);
            (rx, Arc::new(AtomicBool::new(false)))
        };

        let mut paths_scanned = 0;
        let mut opaque_pruned_dirs = 0usize;
        let mut scored: Vec<CandidacyScore> = Vec::with_capacity(1024);

        // Track directories for the incremental scan cursor.
        let mut visited_dirs: HashSet<PathBuf> = HashSet::new();
        let mut dirs_with_candidates: HashSet<PathBuf> = HashSet::new();
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
                    dirty: scanner_event_dirty_roots.contains(root),
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
            let entry = match rx.recv_timeout(Duration::from_secs(2)) {
                Ok(entry) => entry,
                Err(RecvTimeoutError::Timeout) => {
                    if shutdown.load(Ordering::Relaxed) {
                        cancel_token.store(true, Ordering::Relaxed);
                        scanner_should_exit = true;
                        break;
                    }
                    // No entries for 2 seconds — check if budget is exhausted.
                    if Instant::now() >= scan_deadline {
                        cancel_token.store(true, Ordering::Relaxed);
                        scan_timed_out = true;
                        eprintln!(
                            "[SBH-SCANNER] scan timed out ({paths_scanned} entries, \
                             {candidates_found} candidates, {:.1}s) — cancelling walker threads",
                            scan_start.elapsed().as_secs_f64()
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
            if paths_scanned >= SCAN_ENTRY_BUDGET || Instant::now() >= scan_deadline {
                cancel_token.store(true, Ordering::Relaxed);
                scan_timed_out = true;
                eprintln!(
                    "[SBH-SCANNER] scan budget reached ({paths_scanned} entries, \
                     {candidates_found} candidates, {:.1}s) — cancelling walker threads",
                    scan_start.elapsed().as_secs_f64()
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

            // This entry is classified — mark its parent as having candidates
            // so the scan cursor knows NOT to cache it as barren.
            if let Some(parent) = entry.path.parent() {
                dirs_with_candidates.insert(parent.to_path_buf());
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

            let mut score = engine.score_candidate(&input, request.urgency);
            // A maintenance pass is rare and its point is to reclaim what is
            // definitely stale, so say why a classified entry was not.
            if request.maintenance
                && score.decision.action != crate::scanner::scoring::DecisionAction::Delete
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
            if score.decision.action == crate::scanner::scoring::DecisionAction::Delete
                && !score.vetoed
                && active_reference_scan.should_probe(entry.metadata.content_size_bytes)
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

            score.identity = Some(entry.metadata.identity());
            let mut scanner_index_backoff_active = false;
            if scanner_index_enabled {
                match CandidateIndexRecord::from_candidate_score(
                    &score,
                    entry.opaque_tree.as_ref(),
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

            if score.decision.action == crate::scanner::scoring::DecisionAction::Delete
                && !score.vetoed
            {
                candidates_found += 1;
                v2_candidate_bytes_seen = v2_candidate_bytes_seen.saturating_add(score.size_bytes);
                scored.push(score);
                if let Some(root) = root_path
                    && let Some(stat) = root_stats_map.get_mut(root)
                {
                    stat.candidates_found += 1;
                    stat.potential_bytes += input.size_bytes;
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

        eprintln!(
            "[SBH-SCANNER] scan complete: {paths_scanned} entries, \
             {candidates_found} candidates, {:.1}s{}",
            total_scan_duration.as_secs_f64(),
            if scan_timed_out { " (timed out)" } else { "" },
        );

        // Update the incremental scan cursor. On timeout, barren dirs are
        // cached so the next pass skips them. On full completion, cache is
        // cleared for a fresh scan.
        scan_cursor.update(&visited_dirs, &dirs_with_candidates, scan_timed_out);

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
        logger.send(ActivityEvent::ScanCompleted {
            paths_scanned,
            candidates_found,
            duration_ms: scan_duration_ms,
            telemetry: scan_completion_telemetry(
                opaque_pruned_dirs,
                v2_candidate_bytes_seen,
                scan_timed_out,
                scanner_index.as_ref().map_or(0, ScannerCandidateIndex::len),
            ),
        });

        // Report scan stats back to main loop for SelfMonitor counters.
        let _ = report_tx.try_send(WorkerReport::ScanCompleted {
            candidates: candidates_found,
            duration: total_scan_duration,
            root_stats: root_stats_map.into_values().collect(),
            timed_out: scan_timed_out,
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
        // A *timed-out* pass with nothing dispatched is inconclusive for the
        // exponential streak (the budget may simply have expired before the
        // walker reached reclaimable files), so it does not grow the counter —
        // but it still arms the base cooldown timestamp. The old behavior of
        // fully resetting on timeout meant a tree big enough to exhaust the
        // scan budget on every pass could never back off at all and re-walked
        // back-to-back forever (~95% CPU at 82% disk, #15 case 1).
        //
        // NOTE: keying on dispatched-count, not candidates_found, is the fix for
        // the perpetual-Yellow hot-loop where every candidate is a sacred-marker
        // fixture (`*.sqlite-wal`/`.git`/`.beads`): candidates_found stays high
        // while deleted/freed stays 0, so the old `candidates_found == 0` gate
        // never armed.
        if dispatched_this_pass == 0 {
            if !scan_timed_out {
                consecutive_empty_passes = consecutive_empty_passes.saturating_add(1);
            }
            last_empty_pass_at = Some(Instant::now());
            let next_secs = effective_empty_pass_cooldown(
                current_scanner_config.min_rescan_interval_secs,
                consecutive_empty_passes,
            )
            .as_secs();
            if next_secs > 0 {
                eprintln!(
                    "[SBH-SCANNER] no reclaimable progress this pass ({candidates_found} candidates, 0 dispatched, timed_out={scan_timed_out}); backing off rescans (consecutive={consecutive_empty_passes}, next pressure-driven scan in ≥{next_secs}s)"
                );
            }
        } else {
            consecutive_empty_passes = 0;
            last_empty_pass_at = None;
        }

        // #15: record this pass's cost so the next pressure-driven pass owes
        // proportional idle. Recorded for productive AND unproductive passes —
        // the productive case is the one that used to pin a core.
        last_pass_duration = pass_started_at.elapsed();
        last_pass_finished_at = Some(Instant::now());

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

        let batch = match del_rx.recv_timeout(WORKER_SHUTDOWN_POLL_INTERVAL) {
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
        // The executor's pre-flight sacred rail sees the same catalog the
        // scoring stage does: platform builtins plus operator patterns.
        let executor_sacred_paths = {
            let mut catalog = platform_sacred_paths.to_vec();
            catalog.extend(protection::sacred_paths_from_protected_patterns(
                &shared_scanner_config.read().protected_paths,
            ));
            catalog
        };
        let executor = DeletionExecutor::new(
            DeletionConfig {
                max_batch_size,
                dry_run,
                min_score,
                check_open_files: true,
                require_identity: matches!(
                    shared_scanner_config.read().engine,
                    ScannerEngineMode::V2
                ),
                sacred_paths: executor_sacred_paths,
                ..Default::default()
            },
            Some(logger.clone()),
        );

        let plan = executor.plan(approved_candidates);

        if plan.candidates.is_empty() {
            eprintln!(
                "[SBH-EXECUTOR] plan() filtered all {pre_plan_count} approved candidates \
                 (min_score={min_score:.2}, dry_run={dry_run})",
            );
            continue;
        }

        let scanner_config = shared_scanner_config.read().clone();
        let protection = match ProtectionRegistry::new(Some(&scanner_config.protected_paths)) {
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
            protection::sacred_paths_from_protected_patterns(&scanner_config.protected_paths);
        let skip_protected = |path: &Path| {
            if shutdown.load(Ordering::Relaxed) {
                return true;
            }
            // Runs once per candidate: a long batch keeps beating.
            heartbeat.beat();
            let mut protection = protection.lock();
            should_skip_protected_daemon_candidate(
                &mut protection,
                path,
                &sacred_paths,
                logger,
                "executor preflight",
            )
        };

        let report = executor.execute(&plan, Some(&skip_protected));

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

        // Record deletions for repeat-deletion dampening.
        tracker.record_deletions(&report.deleted_paths);

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
                "[SBH-EXECUTOR] deleted={} failed={} skipped={} freed={}B sacred_scans={} sacred_ms={} ({:?})",
                report.items_deleted,
                report.items_failed,
                report.items_skipped,
                report.bytes_freed,
                report.sacred_scans,
                report.sacred_scan_ms,
                report.duration,
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
        let _ = report_tx.try_send(WorkerReport::DeletionCompleted {
            deleted: report.items_deleted as u64,
            bytes_freed: report.bytes_freed,
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
    fn executor_preflight_skips_config_protected_daemon_candidate() {
        let temp = tempfile::tempdir().unwrap();
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
                .is_some()
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
        assert!(
            protected.exists(),
            "protected candidate must remain present after executor preflight"
        );
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
        let scanner_index_path = temp.path().join("scanner-index-v2.json");

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
            &index_feedback_rx,
            &cpu_budget,
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
        assert!(
            prescan_age(&target) < Duration::from_secs(60),
            "a just-created tree is young whatever its mtimes say"
        );
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
        let scanner_index_path = temp.path().join("scanner-index-v2.json");

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
            &index_feedback_rx,
            &cpu_budget,
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
        let scanner_index_path = temp.path().join("scanner-index-v2.json");

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
            &index_feedback_rx,
            &cpu_budget,
        );

        let report = report_rx
            .try_recv()
            .expect("forced v2 scan should report completion");
        match report {
            WorkerReport::ScanCompleted { root_stats, .. } => {
                assert_eq!(root_stats.len(), 1);
            }
            WorkerReport::DeletionCompleted { .. } => panic!("expected scanner completion report"),
        }

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
            } => {
                assert_eq!(direction, BehaviorTransitionDirection::Escalating);
                assert_eq!(remaining, Duration::from_secs(4));
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
            } => {
                assert_eq!(direction, BehaviorTransitionDirection::Recovering);
                assert_eq!(remaining, Duration::from_secs(4));
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
            } => {
                assert_eq!(direction, BehaviorTransitionDirection::Escalating);
                assert_eq!(remaining, Duration::from_secs(4));
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
        let shared = SharedExecutorConfig::new(false, 10, 0.5, 300, 3600);
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
        };
        let mut scored = vec![test_candidate("/tmp/a", 0.4), test_candidate("/tmp/b", 0.6)];

        assert!(dispatch_top_candidates(
            &mut scored,
            &request,
            &del_tx,
            &mut 0usize
        ));
        assert!(
            scored.is_empty(),
            "expected no scored candidates, got {}",
            scored.len()
        );
        assert!(del_rx.try_recv().is_err());
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
            &mut 0usize
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
        };
        let (del_tx, del_rx) = bounded::<DeletionBatch>(1);
        del_tx
            .send(DeletionBatch {
                candidates: vec![test_candidate("/tmp/already-queued", 0.2)],
                pressure_level: PressureLevel::Critical,
                urgency: 0.5,
            })
            .expect("prefill channel");

        let mut scored = vec![test_candidate("/tmp/a", 0.4), test_candidate("/tmp/b", 0.6)];
        let before = scored.len();
        assert!(dispatch_top_candidates(
            &mut scored,
            &request,
            &del_tx,
            &mut 0usize
        ));

        // Channel remained full, so scanner should still retain all candidates.
        assert_eq!(scored.len(), before);
        assert!(scored.iter().any(|c| c.path == Path::new("/tmp/a")));
        assert!(scored.iter().any(|c| c.path == Path::new("/tmp/b")));

        // Existing queued batch should still be the one currently in the channel.
        let queued = del_rx.recv().expect("prefilled batch still queued");
        assert_eq!(queued.candidates[0].path, Path::new("/tmp/already-queued"));
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
        let adjusted = adjusted_candidate_age(
            Duration::from_mins(5),
            30,
            PressureLevel::Red,
            Path::new("/tmp/green-ft"),
            &classification,
        );
        assert_eq!(adjusted, Duration::from_mins(30));
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
        let adjusted = adjusted_candidate_age(
            Duration::from_mins(5),
            30,
            PressureLevel::Red,
            Path::new("/data/projects/franken_engine/crates/franken-engine/.rch-target"),
            &classification,
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
        let adjusted = adjusted_candidate_age(
            Duration::from_mins(5),
            30,
            PressureLevel::Red,
            Path::new("/tmp/random-agent-build-cache"),
            &classification,
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
}
