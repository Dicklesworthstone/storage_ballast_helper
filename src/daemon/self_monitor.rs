//! Daemon self-monitoring: RSS tracking, thread health checks, state file for CLI,
//! and sd_notify STATUS updates.
//!
//! The state file (`state.json`) is the primary mechanism for CLI-to-daemon communication.
//! Written atomically (write to `.tmp`, then `rename()`) every `DAEMON_STATE_WRITE_INTERVAL_SECS`
//! seconds so `sbh status`
//! can always read a consistent snapshot.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::monitor::pid::PressureLevel;

// ──────────────────── constants ────────────────────

/// How often the daemon writes `state.json` (seconds).
pub const DAEMON_STATE_WRITE_INTERVAL_SECS: u64 = 30;

/// Floor for treating `state.json` as stale (seconds).
///
/// Must be `>= 2 × DAEMON_STATE_WRITE_INTERVAL_SECS` so that CLI commands
/// (`sbh status`, `sbh check`, `read_daemon_prediction`) never report the
/// daemon as absent simply because a write cycle hasn't completed yet.
pub const DAEMON_STATE_STALE_THRESHOLD_SECS: u64 = 90;

// ──────────────────── state file schema ────────────────────

/// Top-level state written to `state.json` for CLI consumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonState {
    pub version: String,
    pub pid: u32,
    pub started_at: String,
    pub uptime_seconds: u64,
    pub last_updated: String,
    pub pressure: PressureState,
    pub ballast: BallastState,
    pub last_scan: LastScanState,
    pub counters: Counters,
    pub memory_rss_bytes: u64,
}

/// Current pressure across monitored mounts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PressureState {
    pub overall: String,
    pub mounts: Vec<MountPressure>,
}

/// Pressure info for a single mount.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountPressure {
    pub path: String,
    pub free_pct: f64,
    pub level: String,
    pub rate_bps: Option<f64>,
}

/// Current ballast file state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BallastState {
    pub available: usize,
    pub total: usize,
    pub released: usize,
}

/// Last scan summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastScanState {
    pub at: Option<String>,
    pub candidates: usize,
    pub deleted: usize,
}

/// Cumulative counters since daemon start.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Counters {
    pub scans: u64,
    pub deletions: u64,
    pub bytes_freed: u64,
    pub errors: u64,
}

// ──────────────────── health tracking ────────────────────

/// Thread health status for monitoring.
#[derive(Debug, Clone)]
pub enum ThreadStatus {
    Running {
        name: String,
        last_heartbeat: Instant,
    },
    Stalled {
        name: String,
        stalled_since: Instant,
    },
    Dead {
        name: String,
        died_at: Instant,
        error: String,
    },
}

impl ThreadStatus {
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Running { name, .. } | Self::Stalled { name, .. } | Self::Dead { name, .. } => {
                name
            }
        }
    }

    #[must_use]
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Running { .. })
    }
}

/// Atomic heartbeat timestamp for thread health detection.
///
/// Each worker thread increments this periodically. The self-monitor
/// checks for staleness (> 60s without update → stalled).
#[derive(Debug)]
pub struct ThreadHeartbeat {
    /// Epoch-relative tick counter (monotonic, not wall clock).
    last_beat_epoch_ms: AtomicU64,
    name: String,
}

impl ThreadHeartbeat {
    /// Create a new heartbeat tracker for a named thread.
    #[must_use]
    pub fn new(name: &str) -> Arc<Self> {
        Arc::new(Self {
            last_beat_epoch_ms: AtomicU64::new(epoch_ms()),
            name: name.to_string(),
        })
    }

    /// Record a heartbeat (called by the worker thread).
    pub fn beat(&self) {
        self.last_beat_epoch_ms.store(epoch_ms(), Ordering::Relaxed);
    }

    /// Check thread status based on heartbeat staleness.
    #[must_use]
    pub fn status(&self, stall_threshold: Duration) -> ThreadStatus {
        let last = self.last_beat_epoch_ms.load(Ordering::Relaxed);
        let now = epoch_ms();
        let elapsed_ms = now.saturating_sub(last);

        #[allow(clippy::cast_possible_truncation)]
        let threshold_ms = stall_threshold.as_millis() as u64;
        let approx_instant = Instant::now()
            .checked_sub(Duration::from_millis(elapsed_ms))
            .unwrap_or_else(Instant::now);

        if elapsed_ms > threshold_ms {
            ThreadStatus::Stalled {
                name: self.name.clone(),
                stalled_since: approx_instant,
            }
        } else {
            ThreadStatus::Running {
                name: self.name.clone(),
                last_heartbeat: approx_instant,
            }
        }
    }
}

/// Milliseconds since an arbitrary process-local epoch.
fn epoch_ms() -> u64 {
    use std::time::SystemTime;
    #[allow(clippy::cast_possible_truncation)]
    let ms = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    ms
}

// ──────────────────── daemon health ────────────────────

/// Aggregate health snapshot for the daemon.
#[derive(Debug, Clone)]
pub struct DaemonHealth {
    pub uptime: Duration,
    pub memory_rss_bytes: u64,
    pub scan_count: u64,
    pub avg_scan_duration: Duration,
    pub last_scan_at: Option<Instant>,
    pub deletions_total: u64,
    pub bytes_freed_total: u64,
    pub errors_total: u64,
    pub thread_status: Vec<ThreadStatus>,
    pub last_pressure_level: PressureLevel,
}

// ──────────────────── self-monitor ────────────────────

/// Periodic self-monitoring: writes state file, checks RSS, reports status.
pub struct SelfMonitor {
    state_file_path: PathBuf,
    start_time: Instant,
    started_at_iso: String,
    write_interval: Duration,
    last_write: Option<Instant>,
    rss_limit_bytes: u64,

    // Mutable counters updated by the main loop.
    pub scan_count: u64,
    pub last_scan_at: Option<String>,
    pub last_scan_candidates: usize,
    pub last_scan_deleted: usize,
    pub deletions_total: u64,
    pub bytes_freed_total: u64,
    pub errors_total: u64,
    /// Cumulative scan duration for averaging.
    scan_duration_total: Duration,
}

impl SelfMonitor {
    /// Create a new self-monitor.
    pub fn new(state_file_path: PathBuf) -> Self {
        let now = chrono::Utc::now();
        Self {
            state_file_path,
            start_time: Instant::now(),
            started_at_iso: now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            write_interval: Duration::from_secs(DAEMON_STATE_WRITE_INTERVAL_SECS),
            last_write: None,
            rss_limit_bytes: 256 * 1024 * 1024, // 256 MB

            scan_count: 0,
            last_scan_at: None,
            last_scan_candidates: 0,
            last_scan_deleted: 0,
            deletions_total: 0,
            bytes_freed_total: 0,
            errors_total: 0,
            scan_duration_total: Duration::ZERO,
        }
    }

    /// Check if it's time to write the state file. If so, write it.
    ///
    /// Returns the current RSS in bytes (0 if unavailable).
    pub fn maybe_write_state(
        &mut self,
        pressure_level: PressureLevel,
        free_pct: f64,
        mount_path: &str,
        ballast_available: usize,
        ballast_total: usize,
    ) -> u64 {
        let now = Instant::now();
        if let Some(last) = self.last_write
            && now.duration_since(last) < self.write_interval
        {
            return 0;
        }

        self.last_write = Some(now);
        let rss = read_rss_bytes();

        // Check RSS limit.
        if rss > self.rss_limit_bytes {
            eprintln!(
                "[SBH-SELFMON] WARNING: RSS {} MB exceeds limit {} MB",
                rss / (1024 * 1024),
                self.rss_limit_bytes / (1024 * 1024),
            );
        }

        let state = DaemonState {
            version: env!("CARGO_PKG_VERSION").to_string(),
            pid: std::process::id(),
            started_at: self.started_at_iso.clone(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            last_updated: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            pressure: PressureState {
                overall: format!("{pressure_level:?}").to_lowercase(),
                mounts: vec![MountPressure {
                    path: mount_path.to_string(),
                    free_pct,
                    level: format!("{pressure_level:?}").to_lowercase(),
                    rate_bps: None,
                }],
            },
            ballast: BallastState {
                available: ballast_available,
                total: ballast_total,
                released: ballast_total.saturating_sub(ballast_available),
            },
            last_scan: LastScanState {
                at: self.last_scan_at.clone(),
                candidates: self.last_scan_candidates,
                deleted: self.last_scan_deleted,
            },
            counters: Counters {
                scans: self.scan_count,
                deletions: self.deletions_total,
                bytes_freed: self.bytes_freed_total,
                errors: self.errors_total,
            },
            memory_rss_bytes: rss,
        };

        if let Err(e) = write_state_atomic(&self.state_file_path, &state) {
            eprintln!("[SBH-SELFMON] failed to write state file: {e}");
        }

        rss
    }

    /// Build a status string suitable for sd_notify STATUS.
    #[must_use]
    pub fn status_line(
        &self,
        pressure_level: PressureLevel,
        free_pct: f64,
        mount_path: &str,
    ) -> String {
        let rss_mb = read_rss_bytes() / (1024 * 1024);
        let gb_freed = self.bytes_freed_total as f64 / 1_073_741_824.0;
        format!(
            "{pressure_level:?} {free_pct:.1}% free on {mount_path} | \
             {deletions} deletions ({gb_freed:.1} GB freed) | RSS {rss_mb} MB",
            deletions = self.deletions_total,
        )
    }

    /// Record a completed scan with its duration.
    pub fn record_scan(&mut self, candidates: usize, deleted: usize, duration: Duration) {
        self.scan_count += 1;
        self.scan_duration_total += duration;
        self.last_scan_at =
            Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
        self.last_scan_candidates = candidates;
        self.last_scan_deleted = deleted;
    }

    /// Average scan duration across all recorded scans.
    #[must_use]
    pub fn avg_scan_duration(&self) -> Duration {
        if self.scan_count == 0 {
            return Duration::ZERO;
        }
        let total_nanos = self.scan_duration_total.as_nanos();
        let avg_nanos = total_nanos / u128::from(self.scan_count);
        Duration::from_nanos(u64::try_from(avg_nanos).unwrap_or(u64::MAX))
    }

    /// Build a health snapshot from current state plus thread heartbeats.
    #[must_use]
    pub fn health_snapshot(
        &self,
        heartbeats: &[Arc<ThreadHeartbeat>],
        stall_threshold: Duration,
        pressure_level: PressureLevel,
    ) -> DaemonHealth {
        DaemonHealth {
            uptime: self.start_time.elapsed(),
            memory_rss_bytes: read_rss_bytes(),
            scan_count: self.scan_count,
            avg_scan_duration: self.avg_scan_duration(),
            last_scan_at: self
                .last_scan_at
                .as_deref()
                .and_then(parse_last_scan_instant),
            deletions_total: self.deletions_total,
            bytes_freed_total: self.bytes_freed_total,
            errors_total: self.errors_total,
            thread_status: heartbeats
                .iter()
                .map(|hb| hb.status(stall_threshold))
                .collect(),
            last_pressure_level: pressure_level,
        }
    }

    /// Record deletion results.
    pub fn record_deletions(&mut self, count: u64, bytes: u64) {
        self.deletions_total += count;
        self.bytes_freed_total += bytes;
    }

    /// Record an error.
    pub fn record_error(&mut self) {
        self.errors_total += 1;
    }

    /// Read the state file (for `sbh status` CLI command).
    pub fn read_state(path: &Path) -> std::result::Result<DaemonState, String> {
        let raw = fs::read_to_string(path).map_err(|e| format!("cannot read state file: {e}"))?;
        let state: DaemonState =
            serde_json::from_str(&raw).map_err(|e| format!("invalid state file: {e}"))?;

        // Check staleness.
        if let Ok(updated) = chrono::DateTime::parse_from_rfc3339(&state.last_updated) {
            let age = chrono::Utc::now().signed_duration_since(updated);
            if age.num_seconds() > 60 {
                eprintln!(
                    "[SBH-STATUS] WARNING: state file is {}s old — daemon may be stalled",
                    age.num_seconds()
                );
            }
        }

        Ok(state)
    }
}

fn parse_last_scan_instant(timestamp: &str) -> Option<Instant> {
    let parsed = chrono::DateTime::parse_from_rfc3339(timestamp).ok()?;
    let now = chrono::Utc::now();
    let age = now.signed_duration_since(parsed.with_timezone(&chrono::Utc));
    if age <= chrono::Duration::zero() {
        return Some(Instant::now());
    }
    let age_std = age.to_std().ok()?;
    Some(
        Instant::now()
            .checked_sub(age_std)
            .unwrap_or_else(Instant::now),
    )
}

// ──────────────────── atomic state file write ────────────────────

/// Write state.json atomically: write to .tmp, then rename.
///
/// Sets 0o600 permissions on the temp file (Unix only) so the final
/// state.json is owner-only readable, preventing information leak on
/// multi-user systems.
fn write_state_atomic(path: &Path, state: &DaemonState) -> std::io::Result<()> {
    let tmp_path = path.with_extension("json.tmp");

    // Ensure parent directory exists.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(state).map_err(std::io::Error::other)?;
    {
        use std::io::Write;
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp_path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(&tmp_path, path)?;

    Ok(())
}

// ──────────────────── RSS reading ────────────────────

/// Read current process RSS in bytes from /proc/self/status.
///
/// Returns 0 on non-Linux or if reading fails.
fn read_rss_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        read_rss_linux()
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

#[cfg(target_os = "linux")]
fn read_rss_linux() -> u64 {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return 0;
    };

    for line in status.lines() {
        if line.starts_with("VmRSS:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2
                && let Ok(kb) = parts[1].parse::<u64>()
            {
                return kb * 1024; // kB to bytes
            }
        }
    }

    0
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_state_serializes_correctly() {
        let state = DaemonState {
            version: "0.1.0".to_string(),
            pid: 12345,
            started_at: "2026-02-14T10:00:00.000Z".to_string(),
            uptime_seconds: 3600,
            last_updated: "2026-02-14T11:00:00.000Z".to_string(),
            pressure: PressureState {
                overall: "green".to_string(),
                mounts: vec![MountPressure {
                    path: "/data".to_string(),
                    free_pct: 23.4,
                    level: "green".to_string(),
                    rate_bps: Some(-12_400_000.0),
                }],
            },
            ballast: BallastState {
                available: 8,
                total: 10,
                released: 2,
            },
            last_scan: LastScanState {
                at: Some("2026-02-14T10:59:55.000Z".to_string()),
                candidates: 3,
                deleted: 0,
            },
            counters: Counters {
                scans: 1542,
                deletions: 312,
                bytes_freed: 467_800_000_000,
                errors: 2,
            },
            memory_rss_bytes: 44_040_192,
        };

        let json = serde_json::to_string_pretty(&state).unwrap();
        assert!(json.contains("\"version\": \"0.1.0\""));
        assert!(json.contains("\"pid\": 12345"));
        assert!(json.contains("\"overall\": \"green\""));
        assert!(json.contains("\"available\": 8"));
        assert!(json.contains("\"scans\": 1542"));

        // Roundtrip.
        let parsed: DaemonState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.pid, 12345);
        assert_eq!(parsed.counters.bytes_freed, 467_800_000_000);
    }

    #[test]
    fn atomic_write_creates_state_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");

        let state = DaemonState {
            version: "0.1.0".to_string(),
            pid: 1,
            started_at: "2026-01-01T00:00:00.000Z".to_string(),
            uptime_seconds: 100,
            last_updated: "2026-01-01T00:01:40.000Z".to_string(),
            pressure: PressureState {
                overall: "green".to_string(),
                mounts: vec![],
            },
            ballast: BallastState {
                available: 5,
                total: 5,
                released: 0,
            },
            last_scan: LastScanState {
                at: None,
                candidates: 0,
                deleted: 0,
            },
            counters: Counters {
                scans: 0,
                deletions: 0,
                bytes_freed: 0,
                errors: 0,
            },
            memory_rss_bytes: 0,
        };

        write_state_atomic(&path, &state).unwrap();
        assert!(path.exists());

        // No temp file left behind.
        assert!(!dir.path().join("state.json.tmp").exists());

        // Readable.
        let read_back: DaemonState =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(read_back.uptime_seconds, 100);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");

        let state = DaemonState {
            version: "0.1.0".to_string(),
            pid: 1,
            started_at: "2026-01-01T00:00:00.000Z".to_string(),
            uptime_seconds: 0,
            last_updated: "2026-01-01T00:00:00.000Z".to_string(),
            pressure: PressureState {
                overall: "green".to_string(),
                mounts: vec![],
            },
            ballast: BallastState {
                available: 0,
                total: 0,
                released: 0,
            },
            last_scan: LastScanState {
                at: None,
                candidates: 0,
                deleted: 0,
            },
            counters: Counters {
                scans: 0,
                deletions: 0,
                bytes_freed: 0,
                errors: 0,
            },
            memory_rss_bytes: 0,
        };

        write_state_atomic(&path, &state).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "state.json should be owner-only (0600), got {mode:o}"
        );
    }

    #[test]
    fn self_monitor_write_interval() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut monitor = SelfMonitor::new(path.clone());
        monitor.write_interval = Duration::from_millis(50);

        // First write always happens.
        let _rss = monitor.maybe_write_state(PressureLevel::Green, 25.0, "/data", 10, 10);
        assert!(path.exists());

        // Immediate second write is skipped (within interval).
        let content_before = fs::read_to_string(&path).unwrap();
        monitor.maybe_write_state(PressureLevel::Green, 25.0, "/data", 10, 10);
        let content_after = fs::read_to_string(&path).unwrap();
        // Content should be identical (no rewrite).
        assert_eq!(content_before, content_after);

        // After interval, write happens again.
        std::thread::sleep(Duration::from_millis(60));
        monitor.maybe_write_state(PressureLevel::Yellow, 12.0, "/data", 8, 10);
        let updated = fs::read_to_string(&path).unwrap();
        assert!(updated.contains("yellow"));
    }

    #[test]
    fn read_state_parses_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut monitor = SelfMonitor::new(path.clone());
        monitor.scan_count = 42;
        monitor.deletions_total = 7;
        monitor.bytes_freed_total = 1_000_000;
        monitor.record_scan(5, 3, Duration::from_millis(200));

        monitor.maybe_write_state(PressureLevel::Green, 30.0, "/data", 10, 10);

        let state = SelfMonitor::read_state(&path).unwrap();
        assert_eq!(state.counters.scans, 43);
        assert_eq!(state.counters.deletions, 7);
        assert!(state.last_scan.at.is_some());
        assert_eq!(state.last_scan.candidates, 5);
        assert_eq!(state.last_scan.deleted, 3);
    }

    #[test]
    fn record_counters_accumulate() {
        let dir = tempfile::tempdir().unwrap();
        let mut monitor = SelfMonitor::new(dir.path().join("state.json"));

        monitor.record_scan(10, 3, Duration::from_millis(100));
        assert_eq!(monitor.scan_count, 1);
        assert_eq!(monitor.last_scan_candidates, 10);
        assert_eq!(monitor.last_scan_deleted, 3);

        monitor.record_scan(5, 2, Duration::from_millis(300));
        assert_eq!(monitor.scan_count, 2);
        assert_eq!(monitor.last_scan_candidates, 5);

        // Average scan duration: (100ms + 300ms) / 2 = 200ms.
        let avg = monitor.avg_scan_duration();
        assert_eq!(avg, Duration::from_millis(200));

        monitor.record_deletions(3, 5000);
        monitor.record_deletions(2, 3000);
        assert_eq!(monitor.deletions_total, 5);
        assert_eq!(monitor.bytes_freed_total, 8000);

        monitor.record_error();
        monitor.record_error();
        assert_eq!(monitor.errors_total, 2);
    }

    #[test]
    fn status_line_format() {
        let dir = tempfile::tempdir().unwrap();
        let mut monitor = SelfMonitor::new(dir.path().join("state.json"));
        monitor.deletions_total = 312;
        monitor.bytes_freed_total = 502_000_000_000;

        let line = monitor.status_line(PressureLevel::Green, 23.4, "/data");
        assert!(line.contains("Green"));
        assert!(line.contains("23.4%"));
        assert!(line.contains("312 deletions"));
        assert!(line.contains("/data"));
    }

    #[test]
    fn thread_heartbeat_detects_stall() {
        let hb = ThreadHeartbeat::new("test-thread");

        // Fresh heartbeat should be healthy.
        let status = hb.status(Duration::from_secs(60));
        assert!(status.is_healthy());
        assert_eq!(status.name(), "test-thread");

        // With a sub-millisecond threshold after a brief sleep, the heartbeat is stale.
        std::thread::sleep(Duration::from_millis(2));
        let status = hb.status(Duration::from_millis(1));
        assert!(!status.is_healthy());
    }

    #[test]
    fn thread_heartbeat_beat_resets_timer() {
        let hb = ThreadHeartbeat::new("worker");

        // Wait a bit, then beat.
        std::thread::sleep(Duration::from_millis(10));
        hb.beat();

        // Should still be healthy with reasonable threshold.
        let status = hb.status(Duration::from_secs(60));
        assert!(status.is_healthy());
    }

    #[test]
    fn avg_scan_duration_zero_when_no_scans() {
        let dir = tempfile::tempdir().unwrap();
        let monitor = SelfMonitor::new(dir.path().join("state.json"));
        assert_eq!(monitor.avg_scan_duration(), Duration::ZERO);
    }

    #[test]
    fn health_snapshot_includes_thread_status() {
        let dir = tempfile::tempdir().unwrap();
        let mut monitor = SelfMonitor::new(dir.path().join("state.json"));
        monitor.record_scan(10, 2, Duration::from_millis(150));
        monitor.record_deletions(2, 5000);

        let hb1 = ThreadHeartbeat::new("scanner");
        let hb2 = ThreadHeartbeat::new("executor");
        hb1.beat();
        hb2.beat();

        let health = monitor.health_snapshot(
            &[Arc::clone(&hb1), Arc::clone(&hb2)],
            Duration::from_secs(60),
            PressureLevel::Green,
        );

        assert_eq!(health.scan_count, 1);
        assert_eq!(health.avg_scan_duration, Duration::from_millis(150));
        assert_eq!(health.deletions_total, 2);
        assert_eq!(health.bytes_freed_total, 5000);
        assert_eq!(health.thread_status.len(), 2);
        assert!(health.thread_status.iter().all(ThreadStatus::is_healthy));
        assert!(matches!(health.last_pressure_level, PressureLevel::Green));
    }

    #[test]
    fn health_snapshot_detects_stalled_thread() {
        let dir = tempfile::tempdir().unwrap();
        let monitor = SelfMonitor::new(dir.path().join("state.json"));

        let hb = ThreadHeartbeat::new("stalled-worker");
        // Don't beat — with 1ms threshold after sleeping, it's stale.
        std::thread::sleep(Duration::from_millis(5));

        let health = monitor.health_snapshot(
            &[Arc::clone(&hb)],
            Duration::from_millis(1),
            PressureLevel::Yellow,
        );

        assert_eq!(health.thread_status.len(), 1);
        assert!(!health.thread_status[0].is_healthy());
        assert_eq!(health.thread_status[0].name(), "stalled-worker");
    }

    #[test]
    fn health_snapshot_restores_last_scan_age_from_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let mut monitor = SelfMonitor::new(dir.path().join("state.json"));
        monitor.last_scan_at = Some(
            (chrono::Utc::now() - chrono::Duration::seconds(120))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        );

        let health = monitor.health_snapshot(&[], Duration::from_secs(60), PressureLevel::Green);
        let elapsed = health
            .last_scan_at
            .expect("last_scan_at should parse")
            .elapsed();
        assert!(elapsed >= Duration::from_secs(100));
    }

    #[test]
    fn dead_thread_status_carries_error() {
        let status = ThreadStatus::Dead {
            name: "worker".to_string(),
            died_at: Instant::now(),
            error: "panicked at division by zero".to_string(),
        };
        assert!(!status.is_healthy());
        assert_eq!(status.name(), "worker");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_rss_returns_nonzero() {
        let rss = read_rss_bytes();
        assert!(rss > 0, "RSS should be > 0 on Linux");
    }
}
