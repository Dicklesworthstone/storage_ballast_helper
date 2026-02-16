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
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};

use crate::ballast::manager::BallastManager;
use crate::ballast::release::BallastReleaseController;
use crate::core::config::Config;
use crate::core::errors::{Result, SbhError};
use crate::daemon::self_monitor::{SelfMonitor, ThreadHeartbeat};
use crate::daemon::signals::{SignalHandler, WatchdogHeartbeat};
use crate::logger::dual::{ActivityEvent, ActivityLoggerHandle, DualLoggerConfig, spawn_logger};
use crate::logger::jsonl::JsonlConfig;
use crate::monitor::ewma::DiskRateEstimator;
use crate::monitor::fs_stats::FsStatsCollector;
use crate::monitor::pid::{PidPressureController, PressureLevel, PressureReading};
use crate::monitor::special_locations::SpecialLocationRegistry;
use crate::platform::pal::{Platform, detect_platform};
use crate::scanner::deletion::{DeletionConfig, DeletionExecutor};
use crate::scanner::patterns::ArtifactPatternRegistry;
use crate::scanner::protection::ProtectionRegistry;
use crate::scanner::scoring::{CandidacyScore, ScoringEngine};
use crate::scanner::walker::{DirectoryWalker, WalkerConfig};

// ──────────────────── channel capacities ────────────────────

/// Monitor → Scanner: bounded(16). If scanner falls behind, old events are dropped (latest-wins).
const SCANNER_CHANNEL_CAP: usize = 16;
/// Scanner → Executor: bounded(64). Natural backpressure — scanner blocks on send.
const EXECUTOR_CHANNEL_CAP: usize = 64;

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
    rate_estimator: DiskRateEstimator,
    pressure_controller: PidPressureController,
    special_locations: SpecialLocationRegistry,
    ballast_manager: BallastManager,
    release_controller: BallastReleaseController,
    scoring_engine: ScoringEngine,
    start_time: Instant,
    last_pressure_level: PressureLevel,
    last_special_scan: HashMap<PathBuf, Instant>,
    self_monitor: SelfMonitor,
    scanner_heartbeat: Arc<ThreadHeartbeat>,
    executor_heartbeat: Arc<ThreadHeartbeat>,
}

impl MonitoringDaemon {
    /// Build and initialize the daemon from configuration.
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

        // 5. EWMA rate estimator.
        let rate_estimator = DiskRateEstimator::new(
            config.telemetry.ewma_base_alpha,
            config.telemetry.ewma_min_alpha,
            config.telemetry.ewma_max_alpha,
            config.telemetry.ewma_min_samples,
        );

        // 6. PID pressure controller.
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

        // 7. Discover special locations.
        let special_locations = SpecialLocationRegistry::discover(
            platform.as_ref(),
            &[], // custom paths from config can be added later
        )?;

        // 8. Initialize ballast manager.
        let ballast_manager =
            BallastManager::new(config.paths.ballast_dir.clone(), config.ballast.clone())?;

        // 9. Release controller.
        let release_controller =
            BallastReleaseController::new(config.ballast.replenish_cooldown_minutes);

        // 10. Scoring engine.
        let scoring_engine =
            ScoringEngine::from_config(&config.scoring, config.scanner.min_file_age_minutes);

        // 11. Self-monitor (writes state.json for CLI, tracks health).
        let self_monitor = SelfMonitor::new(config.paths.state_file.clone());

        // 12. Thread heartbeats for worker health detection.
        let scanner_heartbeat = ThreadHeartbeat::new("sbh-scanner");
        let executor_heartbeat = ThreadHeartbeat::new("sbh-executor");

        Ok(Self {
            config,
            platform,
            logger_handle,
            logger_join: Some(logger_join),
            signal_handler,
            watchdog,
            fs_collector,
            rate_estimator,
            pressure_controller,
            special_locations,
            ballast_manager,
            release_controller,
            scoring_engine,
            start_time,
            last_pressure_level: PressureLevel::Green,
            last_special_scan: HashMap::new(),
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

        // Spawn worker threads with heartbeats.
        let mut scanner_health = ThreadHealth::new();
        let mut executor_health = ThreadHealth::new();

        let mut scanner_join: Option<thread::JoinHandle<()>> = Some(self.spawn_scanner_thread(
            scan_rx.clone(),
            del_tx.clone(),
            self.logger_handle.clone(),
            Arc::clone(&self.scanner_heartbeat),
        )?);
        let mut executor_join: Option<thread::JoinHandle<()>> = Some(self.spawn_executor_thread(
            del_rx.clone(),
            self.logger_handle.clone(),
            Arc::clone(&self.executor_heartbeat),
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
            self.handle_pressure(&response, &scan_tx);

            // 6. Check special locations independently.
            self.check_special_locations();

            // 7. Watchdog heartbeat.
            self.watchdog.maybe_notify(&format!(
                "pressure={:?} urgency={:.2}",
                response.level, response.urgency
            ));

            // 7b. Self-monitoring: write state file + check RSS.
            {
                let primary_path = self.primary_path();
                let free_pct = self
                    .fs_collector
                    .collect(&primary_path)
                    .map(|s| s.free_pct())
                    .unwrap_or(0.0);
                let mount_str = primary_path.to_string_lossy();
                let ballast_available = self.ballast_manager.available_count();
                let ballast_total = self.ballast_manager.inventory().len();
                let dropped_log_events = self.logger_handle.dropped_events();

                self.self_monitor.maybe_write_state(
                    response.level,
                    free_pct,
                    &mount_str,
                    ballast_available,
                    ballast_total,
                    dropped_log_events,
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
    fn primary_path(&self) -> PathBuf {
        self.config
            .scanner
            .root_paths
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("/"))
    }

    // ──────────────────── pressure monitoring ────────────────────

    fn check_pressure(&mut self) -> Result<crate::monitor::pid::PressureResponse> {
        // Collect stats for all root paths and find the most-pressured volume.
        let paths = if self.config.scanner.root_paths.is_empty() {
            vec![PathBuf::from("/")]
        } else {
            self.config.scanner.root_paths.clone()
        };

        let mut worst_stats = None;
        let mut worst_free_pct = f64::MAX;

        for path in &paths {
            if let Ok(stats) = self.fs_collector.collect(path) {
                let pct = stats.free_pct();
                if pct < worst_free_pct {
                    worst_free_pct = pct;
                    worst_stats = Some(stats);
                }
            }
        }

        let stats = worst_stats.ok_or_else(|| crate::core::errors::SbhError::FsStats {
            path: paths.first().cloned().unwrap_or_else(|| PathBuf::from("/")),
            details: "no filesystem stats available for any root path".to_string(),
        })?;

        // Update EWMA rate estimator.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let red_threshold_bytes =
            (stats.total_bytes as f64 * self.config.pressure.red_min_free_pct / 100.0) as u64;
        let now = Instant::now();
        let rate_estimate =
            self.rate_estimator
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
        };
        let response = self
            .pressure_controller
            .update(reading, predicted_seconds, now);

        Ok(response)
    }

    fn log_pressure_change(&self, response: &crate::monitor::pid::PressureResponse) {
        let primary_path = self.primary_path();
        // Best-effort: collect fresh stats for the log entry.
        let (free_pct, mount, total, free) =
            if let Ok(stats) = self.fs_collector.collect(&primary_path) {
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
            mount_point: mount,
            total_bytes: total,
            free_bytes: free,
            ewma_rate: None,
            pid_output: Some(response.urgency),
        });
    }

    // ──────────────────── pressure response ────────────────────

    fn handle_pressure(
        &mut self,
        response: &crate::monitor::pid::PressureResponse,
        scan_tx: &Sender<ScanRequest>,
    ) {
        match response.level {
            PressureLevel::Green => {
                // Maybe replenish ballast.
                let primary_path = self.primary_path();
                let collector = &self.fs_collector;
                let _ = self.release_controller.maybe_replenish(
                    &mut self.ballast_manager,
                    response.level,
                    &|| {
                        collector
                            .collect(&primary_path)
                            .map(|s| s.free_pct())
                            .unwrap_or(0.0)
                    },
                );

                // Predictive Safety Net: if urgency is high (prediction says we will crash soon),
                // we MUST start scanning even if the current static level is Green.
                // 0.8 corresponds to ~high urgency threshold (e.g. < 5 mins to saturation).
                if response.urgency > 0.8 {
                    self.send_scan_request(scan_tx, response);
                }
            }
            PressureLevel::Yellow => {
                // Increase scan frequency (handled by PID interval).
                // Light scanning.
                if response.release_ballast_files > 0 {
                    let _ = self
                        .release_controller
                        .maybe_release(&mut self.ballast_manager, response);
                }
                self.send_scan_request(scan_tx, response);
            }
            PressureLevel::Orange => {
                // Start scanning + gentle cleanup + early ballast release.
                let _ = self
                    .release_controller
                    .maybe_release(&mut self.ballast_manager, response);
                self.send_scan_request(scan_tx, response);
            }
            PressureLevel::Red => {
                // Release ballast + aggressive scan + delete.
                let _ = self
                    .release_controller
                    .maybe_release(&mut self.ballast_manager, response);
                self.send_scan_request(scan_tx, response);
            }
            PressureLevel::Critical => {
                // Emergency: release all ballast + delete everything safe.
                let _ = self
                    .release_controller
                    .maybe_release(&mut self.ballast_manager, response);
                self.send_scan_request(scan_tx, response);

                let primary = self.primary_path();
                let actual_free_pct = self
                    .fs_collector
                    .collect(&primary)
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

    fn send_scan_request(
        &self,
        scan_tx: &Sender<ScanRequest>,
        response: &crate::monitor::pid::PressureResponse,
    ) {
        let request = ScanRequest {
            paths: self.config.scanner.root_paths.clone(),
            urgency: response.urgency,
            pressure_level: response.level,
            max_delete_batch: response.max_delete_batch,
            config_update: None,
        };

        // Latest-wins: if the channel is full, drop old events.
        if let Err(TrySendError::Full(_)) = scan_tx.try_send(request) {
            // Scanner is behind. The latest pressure state will be sent next iteration.
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

    // ──────────────────── special locations ────────────────────

    fn check_special_locations(&mut self) {
        let now = Instant::now();

        for location in self.special_locations.all() {
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
            }
        }
    }

    // ──────────────────── ballast ────────────────────

    fn provision_ballast(&mut self) -> Result<()> {
        let primary_path = self.primary_path();
        let collector = &self.fs_collector;
        let report = self.ballast_manager.provision(Some(&|| {
            collector
                .collect(&primary_path)
                .map(|s| s.free_pct())
                .unwrap_or(0.0)
        }))?;

        if report.files_created > 0 {
            eprintln!(
                "[SBH-DAEMON] provisioned {} ballast files ({} bytes total)",
                report.files_created, report.total_bytes
            );
        }

        if !report.errors.is_empty() {
            for err in &report.errors {
                eprintln!("[SBH-DAEMON] ballast provision warning: {err}");
            }
        }

        Ok(())
    }

    // ──────────────────── config reload ────────────────────

    fn handle_config_reload(&mut self, scan_tx: &Sender<ScanRequest>) {
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

                    // Propagate pressure thresholds to PID controller.
                    // Target must be green_min (the recovery level), consistent with init.
                    self.pressure_controller
                        .set_target_free_pct(new_config.pressure.green_min_free_pct);
                    self.pressure_controller.set_pressure_thresholds(
                        new_config.pressure.green_min_free_pct,
                        new_config.pressure.yellow_min_free_pct,
                        new_config.pressure.orange_min_free_pct,
                        new_config.pressure.red_min_free_pct,
                    );
                    if new_config.pressure.prediction.enabled {
                        self.pressure_controller.set_action_horizon_minutes(
                            new_config.pressure.prediction.action_horizon_minutes,
                        );
                    }

                    // Propagate scoring and scanner config to scanner thread.
                    let config_update = ScanRequest {
                        paths: Vec::new(),
                        urgency: 0.0,
                        pressure_level: PressureLevel::Green,
                        max_delete_batch: 0,
                        config_update: Some((
                            new_config.scoring.clone(),
                            new_config.scanner.clone(),
                        )),
                    };
                    let _ = scan_tx.try_send(config_update);

                    self.logger_handle.send(ActivityEvent::ConfigReloaded {
                        details: format!("config hash: {old_hash} -> {new_hash}"),
                    });
                    self.config = new_config;
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
    ) -> Result<thread::JoinHandle<()>> {
        let scoring_config = self.config.scoring.clone();
        let scanner_config = self.config.scanner.clone();

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
    ) -> Result<thread::JoinHandle<()>> {
        let dry_run = self.config.scanner.dry_run;
        let max_batch = self.config.scanner.max_delete_batch;
        let min_score = self.config.scoring.min_score;

        thread::Builder::new()
            .name("sbh-executor".to_string())
            .spawn(move || {
                executor_thread_main(&del_rx, &logger, dry_run, max_batch, min_score, &heartbeat);
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

        // 4. Shutdown logger thread.
        self.logger_handle.shutdown();
        if let Some(logger_join) = self.logger_join.take() {
            let _ = logger_join.join();
        }

        eprintln!("[SBH-DAEMON] shutdown complete (uptime={uptime_secs}s)");
    }
}

// ──────────────────── scanner thread ────────────────────

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
    scoring_config: &crate::core::config::ScoringConfig,
    scanner_config: &crate::core::config::ScannerConfig,
    heartbeat: &Arc<ThreadHeartbeat>,
) {
    let mut current_scoring_config = scoring_config.clone();
    let mut current_scanner_config = scanner_config.clone();

    // Initialize scoring engine.
    let mut engine = ScoringEngine::from_config(
        &current_scoring_config,
        current_scanner_config.min_file_age_minutes,
    );
    // Initialize pattern registry (default built-ins).
    let pattern_registry = ArtifactPatternRegistry::default();

    while let Ok(request) = scan_rx.recv() {
        // Handle config updates.
        if let Some((new_scoring, new_scanner)) = request.config_update {
            current_scoring_config = new_scoring;
            current_scanner_config = new_scanner;
            engine = ScoringEngine::from_config(
                &current_scoring_config,
                current_scanner_config.min_file_age_minutes,
            );
        }

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

        let walker = DirectoryWalker::new(walker_config, protection);

        // Perform the walk (blocking).
        // TODO: For very large trees, this might block too long without heartbeats.
        // Consider making walker yield periodically or run in chunks.
        let entries = match walker.walk() {
            Ok(e) => e,
            Err(e) => {
                logger.send(ActivityEvent::Error {
                    code: e.code().to_string(),
                    message: format!("walker failed: {e}"),
                });
                continue;
            }
        };

        let paths_scanned = entries.len();
        let mut candidates_found = 0;
        let mut scored: Vec<CandidacyScore> = Vec::with_capacity(paths_scanned / 10);

        // Snapshot open files once per scan for fast filtering.
        let open_files = crate::scanner::walker::collect_open_files();

        // Process entries.
        for entry in entries {
            let age = entry.metadata.modified.elapsed().unwrap_or(Duration::ZERO);

            // Classify.
            let classification = pattern_registry.classify(&entry.path, entry.structural_signals);

            // Skip unknown artifacts to save scoring cycles.
            if classification.category == crate::scanner::patterns::ArtifactCategory::Unknown {
                continue;
            }

            let is_open = crate::scanner::walker::is_path_open(&entry.path, &open_files);

            let input = crate::scanner::scoring::CandidateInput {
                path: entry.path,
                size_bytes: entry.metadata.size_bytes,
                age,
                classification,
                signals: entry.structural_signals,
                is_open,
                excluded: false, // Walker already filters excluded paths.
            };

            let score = engine.score_candidate(&input, request.urgency);
            if score.decision.action == crate::scanner::scoring::DecisionAction::Delete
                && !score.vetoed
            {
                candidates_found += 1;
                scored.push(score);
            }
        }

        #[allow(clippy::cast_possible_truncation)]
        let scan_duration_ms = scan_start.elapsed().as_millis() as u64;

        // Log scan completion.
        logger.send(ActivityEvent::ScanCompleted {
            paths_scanned,
            candidates_found,
            duration_ms: scan_duration_ms,
        });

        // Send scored candidates to executor.
        if !scored.is_empty() {
            // Sort by score descending.
            scored.sort_by(|a, b| {
                b.total_score
                    .partial_cmp(&a.total_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            // Limit to max_delete_batch.
            scored.truncate(request.max_delete_batch);

            let batch = DeletionBatch {
                candidates: scored,
                pressure_level: request.pressure_level,
                urgency: request.urgency,
            };

            // This blocks if executor is slow — correct behavior (backpressure).
            if del_tx.send(batch).is_err() {
                // Channel closed, exit.
                break;
            }
        }
    }
}

// ──────────────────── executor thread ────────────────────

/// Executor thread: receives deletion batches and safely removes artifacts.
fn executor_thread_main(
    del_rx: &Receiver<DeletionBatch>,
    logger: &ActivityLoggerHandle,
    dry_run: bool,
    max_batch_size: usize,
    min_score: f64,
    heartbeat: &Arc<ThreadHeartbeat>,
) {
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

    while let Ok(batch) = del_rx.recv() {
        heartbeat.beat();
        let plan = executor.plan(batch.candidates);

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
    use crate::monitor::pid::PressureLevel;

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
        scan_tx.send(request).unwrap();
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

    #[test]
    fn scanner_channel_latest_wins_on_full() {
        let (tx, _rx) = bounded::<ScanRequest>(2);

        // Fill the channel.
        for _ in 0..2 {
            tx.try_send(ScanRequest {
                paths: vec![],
                urgency: 0.1,
                pressure_level: PressureLevel::Green,
                max_delete_batch: 5,
                config_update: None,
            })
            .unwrap();
        }

        // Third send should fail (full).
        let result = tx.try_send(ScanRequest {
            paths: vec![],
            urgency: 0.9,
            pressure_level: PressureLevel::Critical,
            max_delete_batch: 40,
            config_update: None,
        });
        assert!(matches!(result, Err(TrySendError::Full(_))));
    }
}
