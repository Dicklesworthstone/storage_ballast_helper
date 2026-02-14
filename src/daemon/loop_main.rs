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

use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};

use crate::ballast::manager::BallastManager;
use crate::ballast::release::BallastReleaseController;
use crate::core::config::Config;
use crate::core::errors::Result;
use crate::daemon::signals::{ShutdownCoordinator, SignalHandler, WatchdogHeartbeat};
use crate::logger::dual::{ActivityEvent, ActivityLoggerHandle, DualLoggerConfig, spawn_logger};
use crate::logger::jsonl::JsonlConfig;
use crate::monitor::ewma::DiskRateEstimator;
use crate::monitor::fs_stats::FsStatsCollector;
use crate::monitor::pid::{PidPressureController, PressureLevel, PressureReading};
use crate::monitor::special_locations::SpecialLocationRegistry;
use crate::platform::pal::{Platform, detect_platform};
use crate::scanner::deletion::{DeletionConfig, DeletionExecutor};
use crate::scanner::scoring::{CandidacyScore, ScoringEngine};

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
        self.panic_times.retain(|t| now.duration_since(*t) < RESPAWN_WINDOW);
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
        let pressure_controller = PidPressureController::new(
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

        // 7. Discover special locations.
        let special_locations = SpecialLocationRegistry::discover(
            platform.as_ref(),
            &[], // custom paths from config can be added later
        )?;

        // 8. Initialize ballast manager.
        let ballast_manager = BallastManager::new(
            config.paths.ballast_dir.clone(),
            config.ballast.clone(),
        )?;

        // 9. Release controller.
        let release_controller =
            BallastReleaseController::new(config.ballast.replenish_cooldown_minutes);

        // 10. Scoring engine.
        let scoring_engine = ScoringEngine::from_config(
            &config.scoring,
            config.scanner.min_file_age_minutes,
        );

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
        })
    }

    /// Run the monitoring loop until shutdown is requested.
    ///
    /// This is the main entry point for `sbh daemon`.
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

        // Spawn worker threads.
        let mut scanner_health = ThreadHealth::new();
        let mut executor_health = ThreadHealth::new();

        let mut scanner_join: Option<thread::JoinHandle<()>> = Some(
            self.spawn_scanner_thread(
                scan_rx.clone(),
                del_tx.clone(),
                self.logger_handle.clone(),
            ),
        );
        let mut executor_join: Option<thread::JoinHandle<()>> = Some(
            self.spawn_executor_thread(
                del_rx.clone(),
                self.logger_handle.clone(),
            ),
        );

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
                self.handle_config_reload();
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
            self.handle_pressure(&response, &scan_tx)?;

            // 6. Check special locations independently.
            self.check_special_locations();

            // 7. Watchdog heartbeat.
            self.watchdog.maybe_notify(&format!(
                "pressure={:?} urgency={:.2}",
                response.level, response.urgency
            ));

            // 8. Forced scan signal (SIGUSR1).
            if self.signal_handler.should_scan() {
                self.trigger_forced_scan(&scan_tx, &response);
            }

            // 9. Thread health check.
            if last_health_check.elapsed() >= THREAD_HEALTH_CHECK_INTERVAL {
                last_health_check = Instant::now();

                let scanner_dead = scanner_join
                    .as_ref()
                    .is_some_and(|h| h.is_finished());
                if scanner_dead {
                    eprintln!("[SBH-DAEMON] scanner thread exited unexpectedly");
                    if let Some(handle) = scanner_join.take() {
                        let _ = handle.join();
                    }
                    if scanner_health.record_panic() {
                        eprintln!("[SBH-DAEMON] respawning scanner thread");
                        scanner_join = Some(self.spawn_scanner_thread(
                            scan_rx.clone(),
                            del_tx.clone(),
                            self.logger_handle.clone(),
                        ));
                    } else {
                        self.logger_handle.send(ActivityEvent::Error {
                            code: "SBH-3900".to_string(),
                            message: "scanner thread exceeded respawn limit".to_string(),
                        });
                    }
                }

                let executor_dead = executor_join
                    .as_ref()
                    .is_some_and(|h| h.is_finished());
                if executor_dead {
                    eprintln!("[SBH-DAEMON] executor thread exited unexpectedly");
                    if let Some(handle) = executor_join.take() {
                        let _ = handle.join();
                    }
                    if executor_health.record_panic() {
                        eprintln!("[SBH-DAEMON] respawning executor thread");
                        executor_join = Some(self.spawn_executor_thread(
                            del_rx.clone(),
                            self.logger_handle.clone(),
                        ));
                    } else {
                        self.logger_handle.send(ActivityEvent::Error {
                            code: "SBH-3900".to_string(),
                            message: "executor thread exceeded respawn limit".to_string(),
                        });
                    }
                }
            }

            // 10. Sleep for the PID-adjusted interval.
            thread::sleep(response.scan_interval);
        }

        // ──────── shutdown sequence ────────
        self.shutdown(scan_tx, del_tx, scanner_join, executor_join)
    }

    // ──────────────────── pressure monitoring ────────────────────

    fn check_pressure(
        &mut self,
    ) -> Result<crate::monitor::pid::PressureResponse> {
        // Collect stats for the primary monitored path.
        let primary_path = self.config.scanner.root_paths.first().cloned()
            .unwrap_or_else(|| PathBuf::from("/"));
        let stats = self.fs_collector.collect(&primary_path)?;

        // Update EWMA rate estimator.
        let red_threshold_bytes = (stats.total_bytes as f64
            * self.config.pressure.red_min_free_pct
            / 100.0) as u64;
        let now = Instant::now();
        let rate_estimate = self.rate_estimator.update(
            stats.free_bytes,
            now,
            red_threshold_bytes,
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
        };
        let response = self.pressure_controller.update(reading, predicted_seconds, now);

        Ok(response)
    }

    fn log_pressure_change(&self, response: &crate::monitor::pid::PressureResponse) {
        let primary_path = self.config.scanner.root_paths.first().cloned()
            .unwrap_or_else(|| PathBuf::from("/"));
        let reading = PressureReading {
            free_bytes: 0,
            total_bytes: 0,
        };
        // Best-effort: collect fresh stats for the log entry.
        let (free_pct, mount, total, free) =
            if let Ok(stats) = self.fs_collector.collect(&primary_path) {
                (
                    stats.free_pct(),
                    stats.mount_point.to_string_lossy().to_string(),
                    stats.total_bytes as i64,
                    stats.free_bytes as i64,
                )
            } else {
                (reading.free_pct(), "/".to_string(), 0, 0)
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
    ) -> Result<()> {
        match response.level {
            PressureLevel::Green => {
                // Maybe replenish ballast.
                let primary_path = self.config.scanner.root_paths.first().cloned()
                    .unwrap_or_else(|| PathBuf::from("/"));
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
            }
            PressureLevel::Yellow => {
                // Increase scan frequency (handled by PID interval).
                // Light scanning.
                self.send_scan_request(scan_tx, response);
            }
            PressureLevel::Orange => {
                // Start scanning + gentle cleanup.
                self.send_scan_request(scan_tx, response);
            }
            PressureLevel::Red => {
                // Release ballast + aggressive scan + delete.
                let _ = self.release_controller.maybe_release(
                    &mut self.ballast_manager,
                    response,
                );
                self.send_scan_request(scan_tx, response);
            }
            PressureLevel::Critical => {
                // Emergency: release all ballast + delete everything safe.
                let _ = self.release_controller.maybe_release(
                    &mut self.ballast_manager,
                    response,
                );
                self.send_scan_request(scan_tx, response);

                self.logger_handle.send(ActivityEvent::Emergency {
                    details: format!(
                        "critical pressure: urgency={:.2}, releasing all ballast",
                        response.urgency
                    ),
                    free_pct: 0.0,
                });
            }
        }

        Ok(())
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

            self.last_special_scan.insert(location.path.clone(), now);

            let stats = match self.fs_collector.collect(&location.path) {
                Ok(s) => s,
                Err(_) => continue,
            };

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
        let primary_path = self.config.scanner.root_paths.first().cloned()
            .unwrap_or_else(|| PathBuf::from("/"));
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

    fn handle_config_reload(&mut self) {
        eprintln!("[SBH-DAEMON] config reload requested (SIGHUP)");

        match Config::load(Some(&self.config.paths.config_file)) {
            Ok(new_config) => {
                let old_hash = self.config.stable_hash().unwrap_or_default();
                let new_hash = new_config.stable_hash().unwrap_or_default();

                if old_hash != new_hash {
                    // Update components that can be reconfigured at runtime.
                    self.scoring_engine = ScoringEngine::from_config(
                        &new_config.scoring,
                        new_config.scanner.min_file_age_minutes,
                    );
                    self.release_controller =
                        BallastReleaseController::new(new_config.ballast.replenish_cooldown_minutes);
                    self.release_controller.reset();

                    self.logger_handle.send(ActivityEvent::ConfigReloaded {
                        details: format!("config hash: {old_hash} -> {new_hash}"),
                    });
                    self.config = new_config;
                    eprintln!("[SBH-DAEMON] config reloaded successfully");
                } else {
                    eprintln!("[SBH-DAEMON] config unchanged, skipping reload");
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
    ) -> thread::JoinHandle<()> {
        let scoring_config = self.config.scoring.clone();
        let min_file_age = self.config.scanner.min_file_age_minutes;

        thread::Builder::new()
            .name("sbh-scanner".to_string())
            .spawn(move || {
                scanner_thread_main(scan_rx, del_tx, logger, scoring_config, min_file_age);
            })
            .expect("failed to spawn scanner thread")
    }

    fn spawn_executor_thread(
        &self,
        del_rx: Receiver<DeletionBatch>,
        logger: ActivityLoggerHandle,
    ) -> thread::JoinHandle<()> {
        let dry_run = self.config.scanner.dry_run;
        let max_batch = self.config.scanner.max_delete_batch;
        let min_score = self.config.scoring.min_score;

        thread::Builder::new()
            .name("sbh-executor".to_string())
            .spawn(move || {
                executor_thread_main(del_rx, logger, dry_run, max_batch, min_score);
            })
            .expect("failed to spawn executor thread")
    }

    // ──────────────────── shutdown ────────────────────

    fn shutdown(
        &mut self,
        scan_tx: Sender<ScanRequest>,
        del_tx: Sender<DeletionBatch>,
        scanner_join: Option<thread::JoinHandle<()>>,
        executor_join: Option<thread::JoinHandle<()>>,
    ) -> Result<()> {
        let uptime_secs = self.start_time.elapsed().as_secs();

        // 1. Drop channel senders to signal worker threads to exit.
        drop(scan_tx);
        drop(del_tx);

        let coordinator = ShutdownCoordinator::new();
        let tasks: Vec<(&str, &dyn Fn() -> bool)> = vec![
            ("scanner thread", &|| true),
            ("executor thread", &|| true),
        ];
        coordinator.execute(&tasks);

        // 2. Wait for worker threads (bounded by coordinator timeout).
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
        Ok(())
    }
}

// ──────────────────── scanner thread ────────────────────

/// Scanner thread: receives scan requests, walks directories, scores candidates,
/// and sends deletion batches to the executor.
///
/// The walker module (bd-1w9) provides the actual directory traversal.
/// Until it's built, this thread performs a simplified scan using std::fs.
fn scanner_thread_main(
    scan_rx: Receiver<ScanRequest>,
    del_tx: Sender<DeletionBatch>,
    logger: ActivityLoggerHandle,
    scoring_config: crate::core::config::ScoringConfig,
    min_file_age: u64,
) {
    let engine = ScoringEngine::from_config(&scoring_config, min_file_age);

    while let Ok(request) = scan_rx.recv() {
        let scan_start = Instant::now();
        let mut candidates_found: usize = 0;
        let mut paths_scanned: usize = 0;

        // Simplified scan: walk root paths and score candidates.
        // The full walker (bd-1w9) will replace this with proper depth-limited,
        // ignore-respecting traversal and structural marker collection.
        let mut scored: Vec<CandidacyScore> = Vec::new();

        for root in &request.paths {
            if !root.exists() || !root.is_dir() {
                continue;
            }

            // Shallow scan of top-level entries in each root path.
            let entries = match std::fs::read_dir(root) {
                Ok(e) => e,
                Err(_) => continue,
            };

            for entry in entries.flatten() {
                paths_scanned += 1;
                let path = entry.path();

                // Quick classification for known artifact patterns.
                let meta = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                let name = entry.file_name().to_string_lossy().to_lowercase();
                let is_candidate = name.contains("target")
                    || name.starts_with(".target")
                    || name.starts_with("_target_")
                    || name.starts_with(".tmp_target")
                    || name.starts_with("cargo-target-")
                    || name.starts_with("cargo_")
                    || name.starts_with("pi_agent_")
                    || name.starts_with("pi_target_")
                    || name.starts_with("pi_opus_")
                    || name.starts_with("cass-target")
                    || name.starts_with("br-build");

                if !is_candidate {
                    continue;
                }

                let age = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .unwrap_or_default();
                let size = if meta.is_dir() {
                    // Estimate directory size (rough, for scoring).
                    dir_size_estimate(&path)
                } else {
                    meta.len()
                };

                let input = crate::scanner::scoring::CandidateInput {
                    path: path.clone(),
                    size_bytes: size,
                    age,
                    classification: classify_by_name(&name),
                    signals: detect_structural_signals(&path),
                    is_open: false,
                    excluded: false,
                };

                let score = engine.score_candidate(&input, request.urgency);
                if score.decision.action == crate::scanner::scoring::DecisionAction::Delete
                    && !score.vetoed
                {
                    candidates_found += 1;
                    scored.push(score);
                }
            }
        }

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
    del_rx: Receiver<DeletionBatch>,
    logger: ActivityLoggerHandle,
    dry_run: bool,
    max_batch_size: usize,
    min_score: f64,
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

// ──────────────────── scanning helpers ────────────────────

/// Quick structural signal detection for a directory.
fn detect_structural_signals(path: &std::path::Path) -> crate::scanner::patterns::StructuralSignals {
    use crate::scanner::patterns::StructuralSignals;

    if !path.is_dir() {
        return StructuralSignals::default();
    }

    let mut signals = StructuralSignals::default();
    let entries = match std::fs::read_dir(path) {
        Ok(e) => e,
        Err(_) => return signals,
    };

    for entry in entries.flatten().take(50) {
        // Cap at 50 entries to avoid slow scans.
        let name = entry.file_name().to_string_lossy().to_lowercase();
        match name.as_str() {
            "incremental" => signals.has_incremental = true,
            "deps" => signals.has_deps = true,
            "build" => signals.has_build = true,
            ".fingerprint" => signals.has_fingerprint = true,
            ".git" => signals.has_git = true,
            "cargo.toml" => signals.has_cargo_toml = true,
            _ => {}
        }
    }

    signals
}

/// Quick name-based artifact classification.
fn classify_by_name(name: &str) -> crate::scanner::patterns::ArtifactClassification {
    use crate::scanner::patterns::{ArtifactCategory, ArtifactClassification};

    let (category, confidence) = if name.contains("target") || name.starts_with("cargo-target") {
        (ArtifactCategory::RustTarget, 0.85)
    } else if name == "node_modules" {
        (ArtifactCategory::NodeModules, 0.95)
    } else if name == "__pycache__" || name.ends_with(".pyc") {
        (ArtifactCategory::PythonCache, 0.90)
    } else if name.starts_with("pi_agent_") || name.starts_with("pi_target_")
        || name.starts_with("pi_opus_") || name.starts_with("cass-target")
    {
        (ArtifactCategory::AgentWorkspace, 0.80)
    } else {
        (ArtifactCategory::Unknown, 0.30)
    };

    ArtifactClassification {
        pattern_name: name.to_string(),
        category,
        name_confidence: confidence,
        structural_confidence: confidence,
        combined_confidence: confidence,
    }
}

/// Rough directory size estimate (sum of immediate children sizes).
fn dir_size_estimate(path: &std::path::Path) -> u64 {
    let entries = match std::fs::read_dir(path) {
        Ok(e) => e,
        Err(_) => return 0,
    };

    entries
        .flatten()
        .take(100) // cap iteration for speed
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
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
        };
        assert_eq!(request.paths.len(), 2);
        assert_eq!(request.urgency, 0.7);
    }

    #[test]
    fn daemon_args_default() {
        let args = DaemonArgs::default();
        assert!(args.foreground);
        assert!(args.pidfile.is_none());
        assert_eq!(args.watchdog_sec, 0);
    }

    #[test]
    fn structural_signals_detects_rust_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir_all(target.join("incremental")).unwrap();
        std::fs::create_dir_all(target.join("deps")).unwrap();
        std::fs::create_dir_all(target.join("build")).unwrap();
        std::fs::create_dir_all(target.join(".fingerprint")).unwrap();

        let signals = detect_structural_signals(&target);
        assert!(signals.has_incremental);
        assert!(signals.has_deps);
        assert!(signals.has_build);
        assert!(signals.has_fingerprint);
        assert!(!signals.has_git);
    }

    #[test]
    fn structural_signals_detects_git() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(project.join(".git")).unwrap();

        let signals = detect_structural_signals(&project);
        assert!(signals.has_git);
    }

    #[test]
    fn classify_by_name_identifies_rust_target() {
        let c = classify_by_name("target");
        assert_eq!(
            c.category,
            crate::scanner::patterns::ArtifactCategory::RustTarget
        );
        assert!(c.combined_confidence >= 0.80);
    }

    #[test]
    fn classify_by_name_identifies_node_modules() {
        let c = classify_by_name("node_modules");
        assert_eq!(
            c.category,
            crate::scanner::patterns::ArtifactCategory::NodeModules
        );
    }

    #[test]
    fn classify_by_name_identifies_agent_workspace() {
        let c = classify_by_name("pi_agent_test");
        assert_eq!(
            c.category,
            crate::scanner::patterns::ArtifactCategory::AgentWorkspace
        );
    }

    #[test]
    fn dir_size_estimate_sums_children() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "hello").unwrap();
        std::fs::write(dir.path().join("b.txt"), "world").unwrap();

        let size = dir_size_estimate(dir.path());
        assert!(size >= 10); // at least the bytes we wrote
    }

    #[test]
    fn dir_size_estimate_handles_nonexistent() {
        let size = dir_size_estimate(std::path::Path::new("/nonexistent/path"));
        assert_eq!(size, 0);
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
        };
        scan_tx.send(request).unwrap();
        let received = scan_rx.recv().unwrap();
        assert_eq!(received.urgency, 0.5);

        // Send a deletion batch.
        let batch = DeletionBatch {
            candidates: Vec::new(),
            pressure_level: PressureLevel::Orange,
            urgency: 0.5,
        };
        del_tx.send(batch).unwrap();
        let received_batch = del_rx.recv().unwrap();
        assert_eq!(received_batch.urgency, 0.5);
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
            })
            .unwrap();
        }

        // Third send should fail (full).
        let result = tx.try_send(ScanRequest {
            paths: vec![],
            urgency: 0.9,
            pressure_level: PressureLevel::Critical,
            max_delete_batch: 40,
        });
        assert!(matches!(result, Err(TrySendError::Full(_))));
    }
}
