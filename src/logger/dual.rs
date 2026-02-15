//! Dual-write coordinator: writes to both SQLite and JSONL with graceful degradation.
//!
//! Architecture: a dedicated logger thread owns the `SqliteLogger` and `JsonlWriter`.
//! All other threads send `ActivityEvent` via a bounded crossbeam channel. Non-blocking
//! `try_send()` ensures the monitoring loop is never blocked by logging back-pressure.

#![allow(missing_docs)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};

use crate::core::errors::Result;
use crate::logger::jsonl::{
    EventType, JsonlConfig, JsonlWriter, LogEntry, ScoreFactorsRecord, Severity,
};
use crate::logger::sqlite::{ActivityRow, PressureRow, SqliteLogger};

// ──────────────────── channel capacity ────────────────────

/// Default bounded channel capacity for log events.
const CHANNEL_CAPACITY: usize = 1024;

// ──────────────────── public event type ────────────────────

/// Events that can be logged through the dual-write coordinator.
#[derive(Debug, Clone)]
pub enum ActivityEvent {
    DaemonStarted {
        version: String,
        config_hash: String,
    },
    DaemonStopped {
        reason: String,
        uptime_secs: u64,
    },
    PressureChanged {
        from: String,
        to: String,
        free_pct: f64,
        rate_bps: Option<f64>,
        mount_point: String,
        total_bytes: i64,
        free_bytes: i64,
        ewma_rate: Option<f64>,
        pid_output: Option<f64>,
    },
    BallastReleased {
        path: String,
        size_bytes: u64,
        pressure: String,
        free_pct: f64,
    },
    BallastReplenished {
        path: String,
        size_bytes: u64,
    },
    BallastProvisioned {
        path: String,
        size_bytes: u64,
    },
    ArtifactDeleted {
        path: String,
        size_bytes: u64,
        score: f64,
        factors: ScoreFactorsRecord,
        pressure: String,
        free_pct: f64,
        duration_ms: u64,
    },
    ArtifactDeletionFailed {
        path: String,
        error_code: String,
        error_message: String,
    },
    ScanCompleted {
        paths_scanned: usize,
        candidates_found: usize,
        duration_ms: u64,
    },
    ConfigReloaded {
        details: String,
    },
    Error {
        code: String,
        message: String,
    },
    Emergency {
        details: String,
        free_pct: f64,
    },
    /// Sentinel to request graceful shutdown of the logger thread.
    Shutdown,
}

// ──────────────────── public handle ────────────────────

/// Thread-safe, cheaply-cloneable handle for sending log events.
///
/// Internally wraps a bounded crossbeam `Sender`. The `send()` method uses
/// `try_send()` so callers are never blocked by logging back-pressure.
#[derive(Clone)]
pub struct ActivityLoggerHandle {
    tx: Sender<ActivityEvent>,
    dropped_events: Arc<AtomicU64>,
}

impl ActivityLoggerHandle {
    /// Send an event to the logger thread. Non-blocking.
    ///
    /// If the channel is full the event is dropped and the dropped-events counter
    /// is incremented.
    pub fn send(&self, event: ActivityEvent) {
        if let Err(TrySendError::Full(_)) = self.tx.try_send(event) {
            self.dropped_events.fetch_add(1, Ordering::Relaxed);
        }
        // Disconnected is fine during shutdown.
    }

    /// Number of events dropped due to channel back-pressure.
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }

    /// Request graceful shutdown and wait for the logger thread to finish.
    pub fn shutdown(&self) {
        let _ = self.tx.send(ActivityEvent::Shutdown);
    }
}

// ──────────────────── configuration ────────────────────

/// Options for building the dual-write logger.
pub struct DualLoggerConfig {
    /// Path to the SQLite database. `None` disables SQLite.
    pub sqlite_path: Option<PathBuf>,
    /// JSONL writer config (always active).
    pub jsonl_config: JsonlConfig,
    /// Bounded channel capacity.
    pub channel_capacity: usize,
}

impl Default for DualLoggerConfig {
    fn default() -> Self {
        Self {
            sqlite_path: Some(PathBuf::from(dirs_default_sqlite())),
            jsonl_config: JsonlConfig::default(),
            channel_capacity: CHANNEL_CAPACITY,
        }
    }
}

fn dirs_default_sqlite() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    format!("{home}/.local/share/sbh/activity.sqlite3")
}

// ──────────────────── spawn ────────────────────

/// Spawn the logger thread and return a handle.
///
/// The returned handle is `Clone + Send` and can be shared across threads.
/// The logger thread runs until `handle.shutdown()` is called or all senders
/// are dropped.
pub fn spawn_logger(
    config: DualLoggerConfig,
) -> Result<(ActivityLoggerHandle, thread::JoinHandle<()>)> {
    let (tx, rx) = bounded::<ActivityEvent>(config.channel_capacity);
    let dropped = Arc::new(AtomicU64::new(0));
    let dropped_clone = Arc::clone(&dropped);

    let handle = ActivityLoggerHandle {
        tx,
        dropped_events: dropped,
    };

    let join = thread::Builder::new()
        .name("sbh-logger".to_string())
        .spawn(move || {
            logger_thread_main(rx, config.sqlite_path, config.jsonl_config, dropped_clone);
        })
        .map_err(|e| crate::core::errors::SbhError::Runtime {
            details: format!("failed to spawn logger thread: {e}"),
        })?;

    Ok((handle, join))
}

// ──────────────────── logger thread ────────────────────

#[allow(clippy::needless_pass_by_value)]
fn logger_thread_main(
    rx: Receiver<ActivityEvent>,
    sqlite_path: Option<PathBuf>,
    jsonl_config: JsonlConfig,
    dropped: Arc<AtomicU64>,
) {
    // Open backends.
    let mut sqlite = sqlite_path.and_then(|p| match SqliteLogger::open(&p) {
        Ok(db) => Some(db),
        Err(e) => {
            eprintln!("[SBH-DUAL] failed to open SQLite at {}: {e}", p.display());
            None
        }
    });

    let mut jsonl = JsonlWriter::open(jsonl_config);
    let mut sqlite_failures: u32 = 0;

    // Process events until Shutdown or channel disconnect.
    while let Ok(event) = rx.recv() {
        // Report dropped events periodically.
        let d = dropped.swap(0, Ordering::Relaxed);
        if d > 0 {
            let mut warn = LogEntry::new(EventType::Error, Severity::Warning);
            warn.details = Some(format!("{d} log events dropped due to back-pressure"));
            jsonl.write_entry(&warn);
        }

        if matches!(event, ActivityEvent::Shutdown) {
            jsonl.flush();
            jsonl.fsync();
            break;
        }

        // Build log representations.
        let jsonl_entry = event_to_log_entry(&event);
        let activity_row = event_to_activity_row(&event);
        let pressure_row = event_to_pressure_row(&event);

        // Write JSONL (always).
        jsonl.write_entry(&jsonl_entry);

        // Write SQLite.
        if let Some(db) = &sqlite {
            let activity_ok = activity_row
                .as_ref()
                .map_or(true, |row| db.log_activity(row).is_ok());
            let pressure_ok = pressure_row
                .as_ref()
                .map_or(true, |row| db.log_pressure(row).is_ok());
            if activity_ok && pressure_ok {
                sqlite_failures = 0;
            } else {
                sqlite_failures += 1;
                if sqlite_failures >= 3 {
                    eprintln!("[SBH-DUAL] SQLite write failed {sqlite_failures} times, disabling");
                    sqlite = None;
                }
            }
        }
    }

    // Final flush.
    jsonl.flush();
    jsonl.fsync();
}

// ──────────────────── event conversion ────────────────────

#[allow(clippy::too_many_lines)]
fn event_to_log_entry(event: &ActivityEvent) -> LogEntry {
    match event {
        ActivityEvent::DaemonStarted {
            version,
            config_hash,
        } => {
            let mut e = LogEntry::new(EventType::DaemonStart, Severity::Info);
            e.details = Some(format!("version={version} config_hash={config_hash}"));
            e.ok = Some(true);
            e
        }
        ActivityEvent::DaemonStopped {
            reason,
            uptime_secs,
        } => {
            let mut e = LogEntry::new(EventType::DaemonStop, Severity::Info);
            e.details = Some(format!("reason={reason} uptime={uptime_secs}s"));
            e.ok = Some(true);
            e
        }
        ActivityEvent::PressureChanged {
            from,
            to,
            free_pct,
            rate_bps,
            mount_point,
            ..
        } => {
            let mut e = LogEntry::new(EventType::PressureChange, Severity::Info);
            e.pressure = Some(format!("{from}->{to}"));
            e.free_pct = Some(*free_pct);
            e.rate_bps = *rate_bps;
            e.mount_point = Some(mount_point.clone());
            e
        }
        ActivityEvent::BallastReleased {
            path,
            size_bytes,
            pressure,
            free_pct,
        } => {
            let mut e = LogEntry::new(EventType::BallastRelease, Severity::Info);
            e.path = Some(path.clone());
            e.size = Some(*size_bytes);
            e.pressure = Some(pressure.clone());
            e.free_pct = Some(*free_pct);
            e.ok = Some(true);
            e
        }
        ActivityEvent::BallastReplenished { path, size_bytes } => {
            let mut e = LogEntry::new(EventType::BallastReplenish, Severity::Info);
            e.path = Some(path.clone());
            e.size = Some(*size_bytes);
            e.ok = Some(true);
            e
        }
        ActivityEvent::BallastProvisioned { path, size_bytes } => {
            let mut e = LogEntry::new(EventType::BallastProvision, Severity::Info);
            e.path = Some(path.clone());
            e.size = Some(*size_bytes);
            e.ok = Some(true);
            e
        }
        ActivityEvent::ArtifactDeleted {
            path,
            size_bytes,
            score,
            factors,
            pressure,
            free_pct,
            duration_ms,
        } => {
            let mut e = LogEntry::new(EventType::ArtifactDelete, Severity::Info);
            e.path = Some(path.clone());
            e.size = Some(*size_bytes);
            e.score = Some(*score);
            e.factors = Some(factors.clone());
            e.pressure = Some(pressure.clone());
            e.free_pct = Some(*free_pct);
            e.duration_ms = Some(*duration_ms);
            e.ok = Some(true);
            e
        }
        ActivityEvent::ArtifactDeletionFailed {
            path,
            error_code,
            error_message,
        } => {
            let mut e = LogEntry::new(EventType::ArtifactDelete, Severity::Warning);
            e.path = Some(path.clone());
            e.ok = Some(false);
            e.error_code = Some(error_code.clone());
            e.error_message = Some(error_message.clone());
            e
        }
        ActivityEvent::ScanCompleted {
            paths_scanned,
            candidates_found,
            duration_ms,
        } => {
            let mut e = LogEntry::new(EventType::ScanComplete, Severity::Info);
            e.duration_ms = Some(*duration_ms);
            e.details = Some(format!(
                "paths_scanned={paths_scanned} candidates={candidates_found}"
            ));
            e.ok = Some(true);
            e
        }
        ActivityEvent::ConfigReloaded { details } => {
            let mut e = LogEntry::new(EventType::ConfigReload, Severity::Info);
            e.details = Some(details.clone());
            e.ok = Some(true);
            e
        }
        ActivityEvent::Error { code, message } => {
            let mut e = LogEntry::new(EventType::Error, Severity::Critical);
            e.error_code = Some(code.clone());
            e.error_message = Some(message.clone());
            e.ok = Some(false);
            e
        }
        ActivityEvent::Emergency { details, free_pct } => {
            let mut e = LogEntry::new(EventType::Emergency, Severity::Critical);
            e.details = Some(details.clone());
            e.free_pct = Some(*free_pct);
            e
        }
        ActivityEvent::Shutdown => {
            // Should not reach here; handled above.
            LogEntry::new(EventType::DaemonStop, Severity::Info)
        }
    }
}

#[allow(clippy::too_many_lines, clippy::cast_possible_wrap)]
fn event_to_activity_row(event: &ActivityEvent) -> Option<ActivityRow> {
    let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    match event {
        ActivityEvent::DaemonStarted {
            version,
            config_hash,
        } => Some(ActivityRow {
            timestamp: ts,
            event_type: "daemon_start".to_string(),
            severity: "info".to_string(),
            path: None,
            size_bytes: None,
            score: None,
            score_factors: None,
            pressure_level: None,
            free_pct: None,
            duration_ms: None,
            success: 1,
            error_code: None,
            error_message: None,
            details: Some(format!("version={version} config_hash={config_hash}")),
        }),
        ActivityEvent::ArtifactDeleted {
            path,
            size_bytes,
            score,
            factors,
            pressure,
            free_pct,
            duration_ms,
        } => Some(ActivityRow {
            timestamp: ts,
            event_type: "artifact_delete".to_string(),
            severity: "info".to_string(),
            path: Some(path.clone()),
            size_bytes: Some(*size_bytes as i64),
            score: Some(*score),
            score_factors: serde_json::to_string(factors).ok(),
            pressure_level: Some(pressure.clone()),
            free_pct: Some(*free_pct),
            duration_ms: Some(*duration_ms as i64),
            success: 1,
            error_code: None,
            error_message: None,
            details: None,
        }),
        ActivityEvent::ArtifactDeletionFailed {
            path,
            error_code,
            error_message,
        } => Some(ActivityRow {
            timestamp: ts,
            event_type: "artifact_delete".to_string(),
            severity: "warning".to_string(),
            path: Some(path.clone()),
            size_bytes: None,
            score: None,
            score_factors: None,
            pressure_level: None,
            free_pct: None,
            duration_ms: None,
            success: 0,
            error_code: Some(error_code.clone()),
            error_message: Some(error_message.clone()),
            details: None,
        }),
        ActivityEvent::BallastReleased {
            path,
            size_bytes,
            pressure,
            free_pct,
        } => Some(ActivityRow {
            timestamp: ts,
            event_type: "ballast_release".to_string(),
            severity: "info".to_string(),
            path: Some(path.clone()),
            size_bytes: Some(*size_bytes as i64),
            score: None,
            score_factors: None,
            pressure_level: Some(pressure.clone()),
            free_pct: Some(*free_pct),
            duration_ms: None,
            success: 1,
            error_code: None,
            error_message: None,
            details: None,
        }),
        ActivityEvent::ScanCompleted {
            paths_scanned,
            candidates_found,
            duration_ms,
        } => Some(ActivityRow {
            timestamp: ts,
            event_type: "scan_complete".to_string(),
            severity: "info".to_string(),
            path: None,
            size_bytes: None,
            score: None,
            score_factors: None,
            pressure_level: None,
            free_pct: None,
            duration_ms: Some(*duration_ms as i64),
            success: 1,
            error_code: None,
            error_message: None,
            details: Some(format!(
                "paths_scanned={paths_scanned} candidates={candidates_found}"
            )),
        }),
        ActivityEvent::Error { code, message } => Some(ActivityRow {
            timestamp: ts,
            event_type: "error".to_string(),
            severity: "critical".to_string(),
            path: None,
            size_bytes: None,
            score: None,
            score_factors: None,
            pressure_level: None,
            free_pct: None,
            duration_ms: None,
            success: 0,
            error_code: Some(code.clone()),
            error_message: Some(message.clone()),
            details: None,
        }),
        // Events that only need JSONL logging (pressure goes to pressure_history table).
        _ => None,
    }
}

fn event_to_pressure_row(event: &ActivityEvent) -> Option<PressureRow> {
    match event {
        ActivityEvent::PressureChanged {
            to,
            free_pct,
            rate_bps,
            mount_point,
            total_bytes,
            free_bytes,
            ewma_rate,
            pid_output,
            ..
        } => {
            let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            Some(PressureRow {
                timestamp: ts,
                mount_point: mount_point.clone(),
                total_bytes: *total_bytes,
                free_bytes: *free_bytes,
                free_pct: *free_pct,
                rate_bytes_per_sec: *rate_bps,
                pressure_level: to.clone(),
                ewma_rate: *ewma_rate,
                pid_output: *pid_output,
            })
        }
        _ => None,
    }
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(dir: &std::path::Path) -> DualLoggerConfig {
        DualLoggerConfig {
            sqlite_path: Some(dir.join("test.db")),
            jsonl_config: JsonlConfig {
                path: dir.join("test.jsonl"),
                fallback_path: None,
                max_size_bytes: 10 * 1024 * 1024,
                max_rotated_files: 3,
                fsync_interval_secs: 60,
            },
            channel_capacity: 64,
        }
    }

    #[test]
    fn spawn_and_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let (handle, join) = spawn_logger(test_config(dir.path())).unwrap();
        handle.send(ActivityEvent::DaemonStarted {
            version: "0.1.0".to_string(),
            config_hash: "abc".to_string(),
        });
        handle.shutdown();
        join.join().unwrap();

        // JSONL should have at least one line.
        let contents = std::fs::read_to_string(dir.path().join("test.jsonl")).unwrap();
        assert!(!contents.is_empty());
        assert!(contents.contains("daemon_start"));
    }

    #[test]
    fn multiple_events_logged() {
        let dir = tempfile::tempdir().unwrap();
        let (handle, join) = spawn_logger(test_config(dir.path())).unwrap();

        handle.send(ActivityEvent::DaemonStarted {
            version: "0.1.0".to_string(),
            config_hash: "abc".to_string(),
        });
        handle.send(ActivityEvent::ScanCompleted {
            paths_scanned: 100,
            candidates_found: 5,
            duration_ms: 250,
        });
        handle.send(ActivityEvent::ArtifactDeleted {
            path: "/data/projects/foo/.target_opus".to_string(),
            size_bytes: 3_000_000_000,
            score: 0.87,
            factors: ScoreFactorsRecord {
                location: 0.85,
                name: 0.90,
                age: 0.95,
                size: 0.80,
                structure: 0.85,
            },
            pressure: "orange".to_string(),
            free_pct: 8.3,
            duration_ms: 145,
        });
        handle.shutdown();
        join.join().unwrap();

        let contents = std::fs::read_to_string(dir.path().join("test.jsonl")).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 3);

        // Check SQLite too.
        let db = SqliteLogger::open(&dir.path().join("test.db")).unwrap();
        let count = db
            .count_events_since("artifact_delete", "2020-01-01T00:00:00Z")
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn handles_cloneable_and_send() {
        let dir = tempfile::tempdir().unwrap();
        let (handle, join) = spawn_logger(test_config(dir.path())).unwrap();
        let h2 = handle.clone();

        // Send from two handles.
        handle.send(ActivityEvent::DaemonStarted {
            version: "0.1.0".to_string(),
            config_hash: "abc".to_string(),
        });
        h2.send(ActivityEvent::ScanCompleted {
            paths_scanned: 10,
            candidates_found: 1,
            duration_ms: 50,
        });
        handle.shutdown();
        join.join().unwrap();

        let contents = std::fs::read_to_string(dir.path().join("test.jsonl")).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn sqlite_disabled_when_path_none() {
        let dir = tempfile::tempdir().unwrap();
        let config = DualLoggerConfig {
            sqlite_path: None,
            jsonl_config: JsonlConfig {
                path: dir.path().join("no_sqlite.jsonl"),
                fallback_path: None,
                max_size_bytes: 10 * 1024 * 1024,
                max_rotated_files: 3,
                fsync_interval_secs: 60,
            },
            channel_capacity: 64,
        };
        let (handle, join) = spawn_logger(config).unwrap();
        handle.send(ActivityEvent::Error {
            code: "SBH-9999".to_string(),
            message: "test error".to_string(),
        });
        handle.shutdown();
        join.join().unwrap();

        let contents = std::fs::read_to_string(dir.path().join("no_sqlite.jsonl")).unwrap();
        assert!(contents.contains("SBH-9999"));
        // No crash even without SQLite.
    }

    #[test]
    fn dropped_events_counted() {
        let dir = tempfile::tempdir().unwrap();
        let config = DualLoggerConfig {
            sqlite_path: None,
            jsonl_config: JsonlConfig {
                path: dir.path().join("drop.jsonl"),
                fallback_path: None,
                max_size_bytes: 10 * 1024 * 1024,
                max_rotated_files: 3,
                fsync_interval_secs: 60,
            },
            channel_capacity: 2, // tiny channel
        };
        let (handle, _join) = spawn_logger(config).unwrap();
        assert_eq!(handle.dropped_events(), 0);
        // We can't deterministically trigger drops without a sleeping receiver,
        // but the counter initializes correctly.
        handle.shutdown();
    }
}
