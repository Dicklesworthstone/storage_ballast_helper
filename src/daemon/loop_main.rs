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

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, TryRecvError, TrySendError, bounded};
use parking_lot::{Mutex, RwLock};

use crate::ballast::coordinator::BallastPoolCoordinator;
use crate::ballast::release::BallastReleaseController;
use crate::core::config::Config;
use crate::core::errors::{Result, SbhError};
use crate::daemon::notifications::{NotificationEvent, NotificationManager};
use crate::daemon::policy::PolicyEngine;
use crate::daemon::self_monitor::{SelfMonitor, ThreadHeartbeat};
use crate::daemon::signals::{SignalHandler, WatchdogHeartbeat};
use crate::logger::dual::{ActivityEvent, ActivityLoggerHandle, DualLoggerConfig, spawn_logger};
use crate::logger::jsonl::JsonlConfig;
use crate::monitor::ewma::DiskRateEstimator;
use crate::monitor::fs_stats::FsStatsCollector;
use crate::monitor::pid::{PidPressureController, PressureLevel, PressureReading};
use crate::monitor::special_locations::SpecialLocationRegistry;
use crate::monitor::voi_scheduler::VoiScheduler;
use crate::platform::pal::{Platform, detect_platform};
use crate::scanner::deletion::{DeletionConfig, DeletionExecutor};
use crate::scanner::patterns::ArtifactPatternRegistry;
use crate::scanner::protection::ProtectionRegistry;
use crate::scanner::scoring::{CandidacyScore, ScoringEngine};
use crate::scanner::walker::{DirectoryWalker, WalkerConfig};

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
const SCAN_ENTRY_BUDGET: usize = 100_000;

/// Maximum wall-clock time for a single scan pass (seconds).
/// After this deadline, the scanner processes accumulated candidates and returns.
const SCAN_TIME_BUDGET_SECS: u64 = 60;

// ──────────────────── shared executor config ────────────────────

/// Config shared between main thread and executor via atomics.
/// Updated by config reload, read by executor at batch start.
struct SharedExecutorConfig {
    dry_run: AtomicBool,
    max_batch_size: AtomicUsize,
    /// f64 stored as u64 bits (to_bits/from_bits).
    min_score_bits: AtomicU64,
}

impl SharedExecutorConfig {
    fn new(dry_run: bool, max_batch_size: usize, min_score: f64) -> Self {
        Self {
            dry_run: AtomicBool::new(dry_run),
            max_batch_size: AtomicUsize::new(max_batch_size),
            min_score_bits: AtomicU64::new(min_score.to_bits()),
        }
    }

    fn min_score(&self) -> f64 {
        f64::from_bits(self.min_score_bits.load(Ordering::Relaxed))
    }

    fn set_min_score(&self, val: f64) {
        self.min_score_bits.store(val.to_bits(), Ordering::Relaxed);
    }
}

// ──────────────────── thread panic tracking ────────────────────

const MAX_RESPAWNS: u32 = 3;
const RESPAWN_WINDOW: Duration = Duration::from_secs(300);
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

// ──────────────────── inter-thread messages ────────────────────

/// Message from monitor to scanner: "scan these paths at this urgency level."
#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub paths: Vec<PathBuf>,
    pub urgency: f64,
    pub pressure_level: PressureLevel,
    pub max_delete_batch: usize,
    /// When config is reloaded, this carries the updated scoring and scanner config.
    pub config_update: Option<(
        crate::core::config::ScoringConfig,
        crate::core::config::ScannerConfig,
    )>,
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
}

#[derive(Debug)]
enum WorkerReport {
    /// Scanner completed a scan pass.
    ScanCompleted {
        candidates: usize,
        duration: Duration,
        root_stats: Vec<RootScanResult>,
    },
    /// Executor completed a deletion batch.
    DeletionCompleted {
        deleted: u64,
        bytes_freed: u64,
        failed: u64,
    },
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
}

impl MountMonitor {
    fn new(config: &Config) -> Self {
        let rate_estimator = DiskRateEstimator::new(
            config.telemetry.ewma_base_alpha,
            config.telemetry.ewma_min_alpha,
            config.telemetry.ewma_max_alpha,
            config.telemetry.ewma_min_samples,
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

        Self {
            rate_estimator,
            pressure_controller,
        }
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
    fs_collector: FsStatsCollector,
    mount_monitors: HashMap<PathBuf, MountMonitor>,
    special_locations: SpecialLocationRegistry,
    ballast_coordinator: BallastPoolCoordinator,
    release_controller: BallastReleaseController,
    notification_manager: NotificationManager,
    scoring_engine: ScoringEngine,
    voi_scheduler: VoiScheduler,
    shared_executor_config: Arc<SharedExecutorConfig>,
    shared_scoring_config: Arc<RwLock<crate::core::config::ScoringConfig>>,
    shared_scanner_config: Arc<RwLock<crate::core::config::ScannerConfig>>,
    cached_primary_path: PathBuf,
    start_time: Instant,
    last_pressure_level: PressureLevel,
    last_special_scan: HashMap<PathBuf, Instant>,
    last_predictive_warning: Option<Instant>,
    self_monitor: SelfMonitor,
    policy_engine: Arc<Mutex<PolicyEngine>>,
    scanner_heartbeat: Arc<ThreadHeartbeat>,
    executor_heartbeat: Arc<ThreadHeartbeat>,
}

fn compute_primary_path(config: &Config) -> PathBuf {
    config
        .scanner
        .root_paths
        .first()
        .cloned()
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn push_unique_path(paths: &mut Vec<PathBuf>, candidate: PathBuf) {
    if !paths.iter().any(|existing| existing == &candidate) {
        paths.push(candidate);
    }
}

fn ballast_discovery_paths(
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

impl MonitoringDaemon {
    /// Build and initialize the daemon from configuration.
    #[allow(clippy::too_many_lines)]
    pub fn init(config: Config, args: &DaemonArgs) -> Result<Self> {
        let platform = detect_platform()?;
        let start_time = Instant::now();

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
        };
        let (logger_handle, logger_join) = spawn_logger(logger_config)?;

        // 2. Signal handler.
        let signal_handler = SignalHandler::new();

        // 3. Watchdog.
        let watchdog = if args.watchdog_sec > 0 {
            WatchdogHeartbeat::new(args.watchdog_sec)
        } else {
            WatchdogHeartbeat::disabled()
        };

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
        let ballast_coordinator =
            BallastPoolCoordinator::discover(&config.ballast, &discovery_paths, platform.as_ref())?;

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
        ));

        let shared_scoring_config = Arc::new(RwLock::new(config.scoring.clone()));
        let shared_scanner_config = Arc::new(RwLock::new(config.scanner.clone()));

        // 11. Self-monitor (writes state.json for CLI, tracks health).
        let self_monitor = SelfMonitor::new(config.paths.state_file.clone());

        // 12. Thread heartbeats for worker health detection.
        let scanner_heartbeat = ThreadHeartbeat::new("sbh-scanner");
        let executor_heartbeat = ThreadHeartbeat::new("sbh-executor");

        // 13. Notification manager.
        let notification_manager = NotificationManager::from_config(&config.notifications);

        // 14. Policy engine (progressive delivery gates for deletion pipeline).
        let policy_engine = Arc::new(Mutex::new(PolicyEngine::new(config.policy.clone())));

        let cached_primary_path = compute_primary_path(&config);

        Ok(Self {
            config,
            cached_primary_path,
            platform,
            logger_handle,
            logger_join: Some(logger_join),
            signal_handler,
            watchdog,
            fs_collector,
            mount_monitors: HashMap::new(),
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
            last_special_scan: HashMap::new(),
            last_predictive_warning: None,
            self_monitor,
            scanner_heartbeat,
            executor_heartbeat,
        })
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

        // Create inter-thread channels.
        let (scan_tx, scan_rx) = bounded::<ScanRequest>(SCANNER_CHANNEL_CAP);
        let (del_tx, del_rx) = bounded::<DeletionBatch>(EXECUTOR_CHANNEL_CAP);
        let (report_tx, report_rx) = bounded::<WorkerReport>(REPORT_CHANNEL_CAP);

        // Spawn worker threads with heartbeats.
        let mut scanner_health = ThreadHealth::new();
        let mut executor_health = ThreadHealth::new();

        let mut scanner_join: Option<thread::JoinHandle<()>> = Some(self.spawn_scanner_thread(
            scan_rx.clone(),
            del_tx.clone(),
            self.logger_handle.clone(),
            Arc::clone(&self.scanner_heartbeat),
            report_tx.clone(),
        )?);
        let mut executor_join: Option<thread::JoinHandle<()>> = Some(self.spawn_executor_thread(
            del_rx.clone(),
            self.logger_handle.clone(),
            Arc::clone(&self.executor_heartbeat),
            report_tx.clone(),
        )?);

        let mut last_health_check = Instant::now();

        // ──────── main monitoring loop ────────
        loop {
            // 1. Check shutdown signal.
            if self.signal_handler.should_shutdown() {
                eprintln!("[SBH-DAEMON] shutdown requested");
                break;
            }

            // 2. Check config reload signal.
            if self.signal_handler.should_reload() {
                self.handle_config_reload(&scan_tx);
            }

            // 3. Collect filesystem stats and run pressure analysis.
            let response = match self.check_pressure() {
                Ok(r) => r,
                Err(e) => {
                    self.logger_handle.send(ActivityEvent::Error {
                        code: "SBH-2001".to_string(),
                        message: format!("pressure check failed: {e}"),
                    });
                    // On error, sleep and retry.
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
            };

            // 4. Log pressure transitions.
            if response.level != self.last_pressure_level {
                self.log_pressure_change(&response);
                self.last_pressure_level = response.level;
            }

            // 5. Handle pressure response.
            self.handle_pressure(&response, &scan_tx, &scan_rx);

            // 6. Check special locations independently.
            self.check_special_locations(&scan_tx, &scan_rx);

            // 7. Watchdog heartbeat.
            self.watchdog.maybe_notify(&format!(
                "pressure={:?} urgency={:.2}",
                response.level, response.urgency
            ));

            // 7b. Drain worker reports so counters are current for state write.
            while let Ok(report) = report_rx.try_recv() {
                match report {
                    WorkerReport::ScanCompleted {
                        candidates,
                        duration,
                        root_stats,
                    } => {
                        self.self_monitor.record_scan(candidates, 0, duration);
                        let now = Instant::now();
                        #[allow(clippy::cast_possible_truncation)]
                        for stat in root_stats {
                            self.voi_scheduler.record_scan_result(
                                &stat.path,
                                stat.potential_bytes,
                                stat.candidates_found as u32,
                                stat.false_positives as u32,
                                stat.duration.as_millis() as f64,
                                now,
                            );
                        }
                        self.voi_scheduler.end_window();
                    }
                    WorkerReport::DeletionCompleted {
                        deleted,
                        bytes_freed,
                        failed,
                    } => {
                        self.self_monitor.record_deletions(deleted, bytes_freed);
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

            // 7c. Self-monitoring: write state file + check RSS.
            {
                let primary_path = self.primary_path();
                let free_pct = self
                    .fs_collector
                    .collect(primary_path)
                    .map(|s| s.free_pct())
                    .unwrap_or(0.0);
                let mount_str = primary_path.to_string_lossy().into_owned();
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

                let policy_mode = self.policy_engine.lock().mode().to_string();
                self.self_monitor.maybe_write_state(
                    response.level,
                    free_pct,
                    &mount_str,
                    ballast_available,
                    ballast_total,
                    dropped_log_events,
                    &policy_mode,
                );
            }

            // 8. Forced scan signal (SIGUSR1).
            if self.signal_handler.should_scan() {
                self.trigger_forced_scan(&scan_tx, &response);
            }

            // 9. Thread health check.
            if last_health_check.elapsed() >= THREAD_HEALTH_CHECK_INTERVAL {
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

            // 10. Sleep for the PID-adjusted interval.
            thread::sleep(response.scan_interval);
        }

        // ──────── shutdown sequence ────────
        self.shutdown(scan_tx, del_tx, scanner_join, executor_join);
        Ok(())
    }

    // ──────────────────── helpers ────────────────────

    /// Return the first configured root path, or `/` as fallback.
    fn primary_path(&self) -> &Path {
        &self.cached_primary_path
    }

    // ──────────────────── pressure monitoring ────────────────────

    fn check_pressure(&mut self) -> Result<crate::monitor::pid::PressureResponse> {
        // Collect stats for all root paths.
        let default_paths;
        let paths = if self.config.scanner.root_paths.is_empty() {
            default_paths = [PathBuf::from("/")];
            &default_paths[..]
        } else {
            &self.config.scanner.root_paths
        };

        // Group paths by mount point to avoid redundant updates.
        let mut stats_by_mount: HashMap<PathBuf, crate::platform::pal::FsStats> = HashMap::new();

        for path in paths {
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

            // Track worst response (highest urgency/severity).
            match worst_response {
                None => worst_response = Some(response),
                Some(ref worst) => {
                    // Critical > Red > ... > Green.
                    // If levels equal, higher urgency wins.
                    if response.level > worst.level
                        || (response.level == worst.level && response.urgency > worst.urgency)
                    {
                        worst_response = Some(response);
                    }
                }
            }
        }

        // Clean up monitors for unmounted/disappeared volumes?
        // For now we keep them; volume churn is rare in typical operation.

        worst_response.ok_or_else(|| crate::core::errors::SbhError::FsStats {
            path: PathBuf::from("/"),
            details: "internal error: stats collected but no response generated".to_string(),
        })
    }

    fn log_pressure_change(&mut self, response: &crate::monitor::pid::PressureResponse) {
        let primary_path = self.primary_path();
        // Best-effort: collect fresh stats for the log entry.
        let (free_pct, mount, total, free) =
            if let Ok(stats) = self.fs_collector.collect(primary_path) {
                #[allow(clippy::cast_possible_wrap)]
                (
                    stats.free_pct(),
                    stats.mount_point.to_string_lossy().to_string(),
                    stats.total_bytes as i64,
                    stats.free_bytes as i64,
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

    fn handle_pressure(
        &mut self,
        response: &crate::monitor::pid::PressureResponse,
        scan_tx: &Sender<ScanRequest>,
        scan_rx: &Receiver<ScanRequest>,
    ) {
        self.check_predictive_warning(response);

        // Determine scan targets: routine maintenance (Green) scans everything;
        // elevated pressure targets only the causing volume to maximize ROI.
        let scan_paths = if response.level == PressureLevel::Green {
            self.config.scanner.root_paths.clone()
        } else {
            let collector = &self.fs_collector;
            let target = &response.causing_mount;
            self.config
                .scanner
                .root_paths
                .iter()
                .filter(|p| {
                    collector
                        .collect(p)
                        .ok()
                        .is_some_and(|s| s.mount_point == *target)
                })
                .cloned()
                .collect()
        };

        // Fallback to all paths if filtering somehow yielded nothing (e.g. config drift).
        let paths_to_scan = if scan_paths.is_empty() {
            self.config.scanner.root_paths.clone()
        } else {
            scan_paths
        };

        match response.level {
            PressureLevel::Green => {
                // Maybe replenish ballast.
                // We must find a pool that needs replenishment.
                // Iterating all pools and trying to replenish one is safe because
                // ReleaseController enforces global rate limits.
                let collector = &self.fs_collector;
                let inventory = self.ballast_coordinator.inventory();

                for pool_info in inventory {
                    let mount_path = pool_info.mount_point.clone();
                    if self.release_controller.is_ready_for_replenish(
                        &mount_path,
                        response.level,
                        pool_info.files_available,
                        pool_info.files_total,
                    ) {
                        let free_check = || {
                            collector
                                .collect(&mount_path)
                                .map(|s| s.free_pct())
                                .unwrap_or(0.0)
                        };

                        // Try to replenish this pool.
                        if let Ok(Some(report)) = self
                            .ballast_coordinator
                            .replenish_for_mount(&mount_path, Some(&free_check))
                            && report.files_created > 0
                        {
                            self.release_controller
                                .on_replenished(&mount_path, report.files_created);
                            self.notification_manager.notify(
                                &NotificationEvent::BallastReplenished {
                                    mount: mount_path.to_string_lossy().to_string(),
                                    files_replenished: report.files_created,
                                },
                            );
                            // One file replenished globally per tick is sufficient.
                            break;
                        }
                    }
                }

                // Predictive Safety Net: if urgency is high (prediction says we will crash soon),
                // we MUST start scanning even if the current static level is Green.
                // 0.8 corresponds to ~high urgency threshold (e.g. < 5 mins to saturation).
                if response.urgency > 0.8 {
                    self.send_scan_request(scan_tx, scan_rx, response, paths_to_scan);
                }
            }
            PressureLevel::Yellow => {
                // Increase scan frequency (handled by PID interval).
                // Light scanning.
                if response.release_ballast_files > 0 {
                    let _ = self.release_ballast(&response.causing_mount, response);
                }
                self.send_scan_request(scan_tx, scan_rx, response, paths_to_scan);
            }
            PressureLevel::Orange => {
                // Start scanning + gentle cleanup + early ballast release.
                let _ = self.release_ballast(&response.causing_mount, response);
                self.send_scan_request(scan_tx, scan_rx, response, paths_to_scan);
            }
            PressureLevel::Red => {
                // Release ballast + aggressive scan + delete.
                let _ = self.release_ballast(&response.causing_mount, response);
                self.send_scan_request(scan_tx, scan_rx, response, paths_to_scan);
            }
            PressureLevel::Critical => {
                // Emergency: release all ballast + delete everything safe.
                let _ = self.release_ballast(&response.causing_mount, response);
                self.send_scan_request(scan_tx, scan_rx, response, paths_to_scan);

                let primary = self.primary_path();
                let actual_free_pct = self
                    .fs_collector
                    .collect(primary)
                    .map_or(0.0, |s| s.free_pct());
                self.logger_handle.send(ActivityEvent::Emergency {
                    details: format!(
                        "critical pressure: urgency={:.2}, releasing all ballast",
                        response.urgency
                    ),
                    free_pct: actual_free_pct,
                });
            }
        }
    }

    /// Helper to release ballast from the causing mount using the global controller logic.
    fn release_ballast(
        &mut self,
        mount: &std::path::Path,
        response: &crate::monitor::pid::PressureResponse,
    ) -> Result<()> {
        let Some(pool) = self.ballast_coordinator.pool_for_mount(mount) else {
            return Ok(());
        };
        let available = pool.available_count();
        let count = self
            .release_controller
            .files_to_release(mount, response, available);

        if count > 0
            && let Some(report) = self.ballast_coordinator.release_for_mount(mount, count)?
        {
            self.release_controller
                .on_released(mount, report.files_released);

            self.notification_manager
                .notify(&NotificationEvent::BallastReleased {
                    mount: mount.to_string_lossy().to_string(),
                    files_released: report.files_released,
                    bytes_freed: report.bytes_freed,
                });
        }
        Ok(())
    }

    #[allow(clippy::unused_self)]
    fn send_scan_request(
        &self,
        scan_tx: &Sender<ScanRequest>,
        scan_rx: &Receiver<ScanRequest>,
        response: &crate::monitor::pid::PressureResponse,
        paths: Vec<PathBuf>,
    ) {
        let request = ScanRequest {
            paths,
            urgency: response.urgency,
            pressure_level: response.level,
            max_delete_batch: response.max_delete_batch,
            config_update: None,
        };

        let replace_on_full = response.level >= PressureLevel::Red || response.urgency >= 0.90;
        match enqueue_scan_request(scan_tx, scan_rx, request, replace_on_full) {
            ScanEnqueueStatus::Queued => {}
            ScanEnqueueStatus::ReplacedStale => {
                eprintln!(
                    "[SBH-DAEMON] scan channel saturated, replaced stale queued request with urgent update"
                );
            }
            ScanEnqueueStatus::DeferredFull => {
                eprintln!("[SBH-DAEMON] scan channel full, request deferred to next tick");
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
            max_delete_batch: response.max_delete_batch,
            config_update: None,
        };
        // For forced scans, block briefly to ensure delivery.
        let _ = scan_tx.send_timeout(request, Duration::from_millis(100));
    }

    fn check_predictive_warning(&mut self, response: &crate::monitor::pid::PressureResponse) {
        let Some(seconds) = response.predicted_seconds else {
            return;
        };

        let warning_horizon_secs = self.config.pressure.prediction.warning_horizon_minutes * 60.0;

        if seconds > warning_horizon_secs {
            return;
        }

        let now = Instant::now();
        if let Some(last) = self.last_predictive_warning
            && now.duration_since(last) < Duration::from_secs(300)
        {
            return;
        }

        self.last_predictive_warning = Some(now);
        self.notification_manager
            .notify(&NotificationEvent::PredictiveWarning {
                mount: response.causing_mount.to_string_lossy().to_string(),
                minutes_remaining: seconds / 60.0,
                confidence: 0.0, // Placeholder as PressureResponse doesn't carry confidence yet
            });
    }

    // ──────────────────── special locations ────────────────────

    fn check_special_locations(
        &mut self,
        scan_tx: &Sender<ScanRequest>,
        scan_rx: &Receiver<ScanRequest>,
    ) {
        let now = Instant::now();
        let locations = self.special_locations.all().to_vec();

        for location in &locations {
            let last_scan = self.last_special_scan.get(&location.path).copied();
            if !location.scan_due(last_scan, now) {
                continue;
            }

            let Ok(stats) = self.fs_collector.collect(&location.path) else {
                continue;
            };

            self.last_special_scan.insert(location.path.clone(), now);

            if location.needs_attention(&stats) {
                self.logger_handle.send(ActivityEvent::Error {
                    code: "SBH-2001".to_string(),
                    message: format!(
                        "special location {:?} ({}) at {:.1}% free (buffer={}%)",
                        location.kind,
                        location.path.display(),
                        stats.free_pct(),
                        location.buffer_pct,
                    ),
                });
                self.notification_manager.notify(&NotificationEvent::Error {
                    code: "SBH-2001".to_string(),
                    message: format!(
                        "special location {:?} ({}) at {:.1}% free (buffer={}%)",
                        location.kind,
                        location.path.display(),
                        stats.free_pct(),
                        location.buffer_pct,
                    ),
                });

                // Trigger root filesystem scan: special location pressure (e.g. /dev/shm
                // full) indicates agent swarm activity that is likely also generating root
                // filesystem artifacts. Proactively scan to clean up before root hits capacity.
                let urgency = f64::from(location.priority) / 255.0;
                let free_ratio = stats.free_pct() / f64::from(location.buffer_pct);
                let pressure_level = if free_ratio < 0.25 {
                    PressureLevel::Red
                } else if free_ratio < 0.5 {
                    PressureLevel::Orange
                } else {
                    PressureLevel::Yellow
                };
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
                        predicted_seconds: None,
                    };
                    let _ = self.release_ballast(&mount, &release_response);
                }

                let mut scan_paths = Vec::with_capacity(self.config.scanner.root_paths.len() + 1);
                scan_paths.push(location.path.clone());
                for root in &self.config.scanner.root_paths {
                    if root != &location.path {
                        scan_paths.push(root.clone());
                    }
                }

                let request = ScanRequest {
                    paths: scan_paths,
                    urgency,
                    pressure_level,
                    max_delete_batch,
                    config_update: None,
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
                    match BallastPoolCoordinator::discover(
                        &new_config.ballast,
                        &discovery_paths,
                        self.platform.as_ref(),
                    ) {
                        Ok(coordinator) => {
                            self.ballast_coordinator = coordinator;
                        }
                        Err(err) => {
                            eprintln!(
                                "[SBH-DAEMON] ballast coordinator rediscovery failed during reload: {err}"
                            );
                            self.ballast_coordinator.update_config(&new_config.ballast);
                        }
                    }

                    // Propagate pressure thresholds to all active PID controllers.
                    for monitor in self.mount_monitors.values_mut() {
                        monitor
                            .pressure_controller
                            .set_target_free_pct(new_config.pressure.green_min_free_pct);
                        monitor.pressure_controller.set_pressure_thresholds(
                            new_config.pressure.green_min_free_pct,
                            new_config.pressure.yellow_min_free_pct,
                            new_config.pressure.orange_min_free_pct,
                            new_config.pressure.red_min_free_pct,
                        );
                        if new_config.pressure.prediction.enabled {
                            monitor.pressure_controller.set_action_horizon_minutes(
                                new_config.pressure.prediction.action_horizon_minutes,
                            );
                        }
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

                    self.logger_handle.send(ActivityEvent::ConfigReloaded {
                        details: format!("config hash: {old_hash} -> {new_hash}"),
                    });
                    self.config = new_config;
                    self.cached_primary_path = compute_primary_path(&self.config);
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
    ) -> Result<thread::JoinHandle<()>> {
        let scoring_config = Arc::clone(&self.shared_scoring_config);
        let scanner_config = Arc::clone(&self.shared_scanner_config);

        thread::Builder::new()
            .name("sbh-scanner".to_string())
            .spawn(move || {
                scanner_thread_main(
                    &scan_rx,
                    &del_tx,
                    &logger,
                    &scoring_config,
                    &scanner_config,
                    &heartbeat,
                    &report_tx,
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
    ) -> Result<thread::JoinHandle<()>> {
        let shared_config = Arc::clone(&self.shared_executor_config);
        let policy_engine = Arc::clone(&self.policy_engine);

        thread::Builder::new()
            .name("sbh-executor".to_string())
            .spawn(move || {
                executor_thread_main(
                    &del_rx,
                    &logger,
                    &shared_config,
                    &heartbeat,
                    &report_tx,
                    &policy_engine,
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
    ) {
        let uptime_secs = self.start_time.elapsed().as_secs();

        // 1. Drop channel senders to signal worker threads to exit.
        drop(scan_tx);
        drop(del_tx);

        // 2. Wait for worker threads.
        if let Some(h) = scanner_join {
            let _ = h.join();
        }
        if let Some(h) = executor_join {
            let _ = h.join();
        }

        // 3. Log shutdown.
        self.logger_handle.send(ActivityEvent::DaemonStopped {
            reason: "clean shutdown".to_string(),
            uptime_secs,
        });
        self.notification_manager
            .notify(&NotificationEvent::DaemonStopped {
                reason: "clean shutdown".to_string(),
                uptime_secs,
            });

        // 4. Shutdown logger thread.
        self.logger_handle.shutdown();
        if let Some(logger_join) = self.logger_join.take() {
            let _ = logger_join.join();
        }

        eprintln!("[SBH-DAEMON] shutdown complete (uptime={uptime_secs}s)");
    }
}

// ──────────────────── scanner thread ────────────────────

fn dispatch_top_candidates(
    scored: &mut Vec<CandidacyScore>,
    request: &ScanRequest,
    del_tx: &Sender<DeletionBatch>,
) -> bool {
    if scored.is_empty() {
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

    // Non-blocking send preserves scanner progress and avoids deadlock when
    // executor is slow. If channel is full, re-queue candidates locally so the
    // scanner can retry later in this pass.
    match del_tx.try_send(batch) {
        Ok(()) => true,
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

/// Scanner thread: receives scan requests, walks directories, scores candidates,
/// and sends deletion batches to the executor.
///
/// Uses `DirectoryWalker` to perform parallel, depth-limited, safe traversals
/// and `ScoringEngine` to rank candidates.
#[allow(clippy::too_many_lines)]
fn scanner_thread_main(
    scan_rx: &Receiver<ScanRequest>,
    del_tx: &Sender<DeletionBatch>,
    logger: &ActivityLoggerHandle,
    shared_scoring_config: &Arc<RwLock<crate::core::config::ScoringConfig>>,
    shared_scanner_config: &Arc<RwLock<crate::core::config::ScannerConfig>>,
    heartbeat: &Arc<ThreadHeartbeat>,
    report_tx: &Sender<WorkerReport>,
) {
    // Initialize pattern registry (default built-ins).
    let pattern_registry = ArtifactPatternRegistry::default();

    while let Ok(request) = scan_rx.recv() {
        // Read latest config at the start of each scan.
        let current_scoring_config = shared_scoring_config.read().clone();
        let current_scanner_config = shared_scanner_config.read().clone();

        let engine = ScoringEngine::from_config(
            &current_scoring_config,
            current_scanner_config.min_file_age_minutes,
        );

        // If no paths to scan, skip.
        if request.paths.is_empty() {
            continue;
        }

        heartbeat.beat();
        let scan_start = Instant::now();

        // Configure walker.
        let walker_config = WalkerConfig {
            root_paths: request.paths.clone(),
            max_depth: current_scanner_config.max_depth,
            follow_symlinks: current_scanner_config.follow_symlinks,
            cross_devices: current_scanner_config.cross_devices,
            parallelism: current_scanner_config.parallelism,
            excluded_paths: current_scanner_config
                .excluded_paths
                .iter()
                .cloned()
                .collect(),
        };

        // Initialize protection registry (reload from config + markers are discovered during walk).
        let protection =
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

        let walker = DirectoryWalker::new(walker_config, protection).with_heartbeat({
            let hb = Arc::clone(heartbeat);
            move || hb.beat()
        });

        // Perform the walk (streaming).
        let rx = match walker.stream() {
            Ok(r) => r,
            Err(e) => {
                logger.send(ActivityEvent::Error {
                    code: e.code().to_string(),
                    message: format!("walker failed: {e}"),
                });
                continue;
            }
        };

        let mut paths_scanned = 0;
        let mut candidates_found = 0;
        let mut scored: Vec<CandidacyScore> = Vec::with_capacity(1024);
        let mut scanner_should_exit = false;
        let dispatch_threshold = request
            .max_delete_batch
            .max(1)
            .saturating_mul(EARLY_DISPATCH_MULTIPLIER);
        let mut next_dispatch_deadline = scan_start + EARLY_DISPATCH_MAX_WAIT;

        // Snapshot open files in a background thread so the ~5s /proc scan
        // overlaps with the walker's initial directory reads instead of
        // blocking the scanner thread.
        let open_files_paths = request.paths.clone();
        let mut open_files_handle: Option<std::thread::JoinHandle<_>> = std::thread::Builder::new()
            .name("sbh-open-files".into())
            .spawn(move || crate::scanner::walker::collect_open_path_ancestors(&open_files_paths))
            .ok();
        // Join lazily — we only need results when classifying candidates.
        let mut open_files_joined: Option<std::collections::HashSet<std::path::PathBuf>> = None;

        // Initialize per-root stats.
        let mut root_stats_map: HashMap<PathBuf, RootScanResult> = HashMap::new();
        for root in &request.paths {
            root_stats_map.insert(
                root.clone(),
                RootScanResult {
                    path: root.clone(),
                    candidates_found: 0,
                    potential_bytes: 0,
                    false_positives: 0,
                    duration: Duration::ZERO,
                },
            );
        }

        // Scan budget: absolute deadline for this scan pass.
        let scan_deadline = scan_start + Duration::from_secs(SCAN_TIME_BUDGET_SECS);

        // Process entries with timeout to handle walker deadlocks.
        // The walker can deadlock when both worker threads block on a full work queue
        // (bounded channel). Using recv_timeout ensures the budget check fires even
        // when no entries are flowing.
        loop {
            let entry = match rx.recv_timeout(Duration::from_secs(2)) {
                Ok(entry) => entry,
                Err(RecvTimeoutError::Timeout) => {
                    // No entries for 2 seconds — check if budget is exhausted.
                    if Instant::now() >= scan_deadline {
                        eprintln!(
                            "[SBH-SCANNER] scan timed out ({paths_scanned} entries, \
                             {candidates_found} candidates, {:.1}s) — walker may be stuck",
                            scan_start.elapsed().as_secs_f64()
                        );
                        break;
                    }
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => break,
            };
            paths_scanned += 1;

            // Budget check: stop processing if we've exceeded entry count or time limits.
            if paths_scanned >= SCAN_ENTRY_BUDGET || Instant::now() >= scan_deadline {
                eprintln!(
                    "[SBH-SCANNER] scan budget reached ({paths_scanned} entries, \
                     {candidates_found} candidates, {:.1}s) — dispatching partial results",
                    scan_start.elapsed().as_secs_f64()
                );
                break;
            }

            let age = entry
                .metadata
                .effective_age_timestamp()
                .elapsed()
                .unwrap_or(Duration::ZERO);

            // Classify.
            let classification = pattern_registry.classify(&entry.path, entry.structural_signals);

            // Skip unknown artifacts to save scoring cycles.
            if classification.category == crate::scanner::patterns::ArtifactCategory::Unknown {
                continue;
            }

            // Lazy-join the /proc scan thread on first classified entry.
            // This gives the /proc scan the full walker startup period to run
            // in parallel instead of blocking the scanner up front.
            let open_files = open_files_joined.get_or_insert_with(|| {
                open_files_handle
                    .take()
                    .and_then(|h| h.join().ok())
                    .unwrap_or_default()
            });
            let is_open = crate::scanner::walker::is_path_open_by_ancestor(&entry.path, open_files);

            let input = crate::scanner::scoring::CandidateInput {
                path: entry.path.clone(), // Clone needed for input
                size_bytes: entry.metadata.content_size_bytes,
                age,
                classification,
                signals: entry.structural_signals,
                is_open,
                excluded: false, // Walker already filters excluded paths.
            };

            let score = engine.score_candidate(&input, request.urgency);

            // Attribute to root.
            let root_path = request.paths.iter().find(|r| entry.path.starts_with(r));

            if score.decision.action == crate::scanner::scoring::DecisionAction::Delete
                && !score.vetoed
            {
                candidates_found += 1;
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
                if !dispatch_top_candidates(&mut scored, &request, del_tx) {
                    scanner_should_exit = true;
                    break;
                }
                next_dispatch_deadline = Instant::now() + EARLY_DISPATCH_MAX_WAIT;
            }
        }

        #[allow(clippy::cast_possible_truncation)]
        let scan_duration_ms = scan_start.elapsed().as_millis() as u64;

        eprintln!(
            "[SBH-SCANNER] scan complete: {paths_scanned} entries, \
             {candidates_found} candidates, {:.1}s",
            scan_start.elapsed().as_secs_f64()
        );

        // Log scan completion.
        logger.send(ActivityEvent::ScanCompleted {
            paths_scanned,
            candidates_found,
            duration_ms: scan_duration_ms,
        });

        // Report scan stats back to main loop for SelfMonitor counters.
        let _ = report_tx.try_send(WorkerReport::ScanCompleted {
            candidates: candidates_found,
            duration: scan_start.elapsed(),
            root_stats: root_stats_map.into_values().collect(),
        });

        // Flush remaining candidates in bounded batches.
        while !scored.is_empty() {
            let pending_before = scored.len();
            if !dispatch_top_candidates(&mut scored, &request, del_tx) {
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

        if scanner_should_exit {
            break;
        }
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
fn executor_thread_main(
    del_rx: &Receiver<DeletionBatch>,
    logger: &ActivityLoggerHandle,
    shared_config: &Arc<SharedExecutorConfig>,
    heartbeat: &Arc<ThreadHeartbeat>,
    report_tx: &Sender<WorkerReport>,
    policy_engine: &Arc<Mutex<PolicyEngine>>,
) {
    while let Ok(batch) = del_rx.recv() {
        heartbeat.beat();

        // Gate candidates through the policy engine. The lock is held only for
        // the duration of evaluate() (pure computation, no I/O).
        let approved_candidates = {
            let mut policy = policy_engine.lock();
            let decision = policy.evaluate(&batch.candidates, None);
            if !decision.approved_for_deletion.is_empty() {
                eprintln!(
                    "[SBH-EXECUTOR] policy engine approved {}/{} candidates (mode={})",
                    decision.approved_for_deletion.len(),
                    batch.candidates.len(),
                    decision.mode,
                );
            }
            decision.approved_for_deletion
        };

        if approved_candidates.is_empty() {
            continue;
        }

        // Read latest config from shared atomics (updated by config reload).
        let dry_run = shared_config.dry_run.load(Ordering::Relaxed);
        let max_batch_size = shared_config.max_batch_size.load(Ordering::Relaxed);
        let min_score = shared_config.min_score();

        let executor = DeletionExecutor::new(
            DeletionConfig {
                max_batch_size,
                dry_run,
                min_score,
                check_open_files: true,
                ..Default::default()
            },
            Some(logger.clone()),
        );

        let plan = executor.plan(approved_candidates);

        if plan.candidates.is_empty() {
            continue;
        }

        let report = executor.execute(&plan, None);

        if report.items_deleted > 0 || report.items_failed > 0 {
            eprintln!(
                "[SBH-EXECUTOR] deleted={} failed={} skipped={} freed={}B ({:?})",
                report.items_deleted,
                report.items_failed,
                report.items_skipped,
                report.bytes_freed,
                report.duration,
            );
        }

        // Report deletion stats back to main loop for SelfMonitor counters.
        let _ = report_tx.try_send(WorkerReport::DeletionCompleted {
            deleted: report.items_deleted as u64,
            bytes_freed: report.bytes_freed,
            failed: report.items_failed as u64,
        });

        if report.circuit_breaker_tripped {
            logger.send(ActivityEvent::Error {
                code: "SBH-2003".to_string(),
                message: "executor circuit breaker tripped".to_string(),
            });
        }
    }
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::Config;
    use crate::monitor::pid::PressureLevel;
    use crate::monitor::special_locations::{
        SpecialKind, SpecialLocation, SpecialLocationRegistry,
    };
    use crate::scanner::patterns::ArtifactClassification;
    use crate::scanner::scoring::{DecisionAction, DecisionOutcome, EvidenceLedger, ScoreFactors};
    use std::path::Path;
    use std::time::Duration;

    fn test_candidate(path: &str, total_score: f64) -> CandidacyScore {
        CandidacyScore {
            path: PathBuf::from(path),
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
            age: Duration::from_secs(60),
            decision: DecisionOutcome {
                action: DecisionAction::Delete,
                posterior_abandoned: 0.9,
                expected_loss_keep: 0.9,
                expected_loss_delete: 0.1,
                calibration_score: 1.0,
                fallback_active: false,
            },
            ledger: EvidenceLedger {
                terms: Vec::new(),
                summary: "test".to_string(),
            },
        }
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
    fn scan_request_serializes_correctly() {
        let request = ScanRequest {
            paths: vec![PathBuf::from("/tmp"), PathBuf::from("/data/projects")],
            urgency: 0.7,
            pressure_level: PressureLevel::Orange,
            max_delete_batch: 10,
            config_update: None,
        };
        assert_eq!(request.paths.len(), 2);
        assert_eq!(request.urgency.to_bits(), 0.7_f64.to_bits());
    }

    #[test]
    fn daemon_args_default() {
        let args = DaemonArgs::default();
        assert!(args.foreground);
        assert!(args.pidfile.is_none());
        assert_eq!(args.watchdog_sec, 0);
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
            max_delete_batch: 10,
            config_update: None,
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
    fn scanner_channel_defers_when_full_without_replacement() {
        let (tx, rx) = bounded::<ScanRequest>(SCANNER_CHANNEL_CAP);

        let make_request = |urgency: f64| ScanRequest {
            paths: vec![],
            urgency,
            pressure_level: PressureLevel::Critical,
            max_delete_batch: 40,
            config_update: None,
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
            max_delete_batch: 40,
            config_update: None,
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
            max_delete_batch: 40,
            config_update: None,
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
            max_delete_batch: 1,
            config_update: None,
        };
        let (del_tx, del_rx) = bounded::<DeletionBatch>(4);
        let mut scored = vec![
            test_candidate("/tmp/low", 0.1),
            test_candidate("/tmp/high", 0.9),
            test_candidate("/tmp/mid", 0.5),
        ];

        assert!(dispatch_top_candidates(&mut scored, &request, &del_tx));
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
            max_delete_batch: 1,
            config_update: None,
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
        assert!(dispatch_top_candidates(&mut scored, &request, &del_tx));

        // Channel remained full, so scanner should still retain all candidates.
        assert_eq!(scored.len(), before);
        assert!(scored.iter().any(|c| c.path == Path::new("/tmp/a")));
        assert!(scored.iter().any(|c| c.path == Path::new("/tmp/b")));

        // Existing queued batch should still be the one currently in the channel.
        let queued = del_rx.recv().expect("prefilled batch still queued");
        assert_eq!(queued.candidates[0].path, Path::new("/tmp/already-queued"));
    }
}
