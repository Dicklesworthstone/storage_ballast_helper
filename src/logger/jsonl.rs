//! JSONL logger: append-only line-delimited JSON for agent-friendly log consumption.
//!
//! Each line is a self-contained JSON object. Lines are assembled in memory and
//! written atomically via `write_all` to prevent interleaved partial lines when
//! the file is being tailed by another process.
//!
//! Four-level fallback chain:
//! 1. Primary file path
//! 2. Fallback path (e.g. `/dev/shm/sbh.jsonl` for RAM-backed fallback)
//! 3. stderr with `[SBH-JSONL]` prefix
//! 4. Silent discard (daemon must never crash for logging failures)

#![allow(missing_docs)]

use std::fs::{self, File, OpenOptions, rename};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::core::errors::{Result, SbhError};

/// Severity level for log events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// Log event types matching the sbh activity model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    ArtifactDelete,
    BallastRelease,
    BallastReplenish,
    BallastProvision,
    PressureChange,
    ScanComplete,
    DaemonStart,
    DaemonStop,
    ConfigReload,
    Error,
    Emergency,
}

/// A single JSONL log entry — all fields optional except `ts`, `event`, `severity`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// ISO 8601 UTC timestamp.
    pub ts: String,
    /// Event type identifier.
    pub event: EventType,
    /// Severity level.
    pub severity: Severity,
    /// Affected filesystem path (when applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Size in bytes of affected item.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Candidacy score at time of action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    /// Individual scoring factor values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub factors: Option<ScoreFactorsRecord>,
    /// Current pressure level label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pressure: Option<String>,
    /// Free percentage at time of event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free_pct: Option<f64>,
    /// EWMA consumption rate in bytes/sec.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_bps: Option<f64>,
    /// Duration of the action in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Whether the action succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    /// SBH error code if action failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Human-readable error message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    /// Mount point involved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mount_point: Option<String>,
    /// Freeform details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Scoring factor values recorded in the log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreFactorsRecord {
    pub location: f64,
    pub name: f64,
    pub age: f64,
    pub size: f64,
    pub structure: f64,
}

impl LogEntry {
    /// Create a new entry stamped with the current UTC time.
    pub fn new(event: EventType, severity: Severity) -> Self {
        Self {
            ts: format_utc_now(),
            event,
            severity,
            path: None,
            size: None,
            score: None,
            factors: None,
            pressure: None,
            free_pct: None,
            rate_bps: None,
            duration_ms: None,
            ok: None,
            error_code: None,
            error_message: None,
            mount_point: None,
            details: None,
        }
    }
}

/// Degradation state of the JSONL writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriterState {
    /// Writing to primary path.
    Normal,
    /// Primary failed, writing to fallback path.
    Fallback,
    /// Both files failed, writing to stderr.
    Stderr,
    /// Everything failed, silently discarding.
    Discard,
}

/// Configuration for the JSONL writer.
#[derive(Debug, Clone)]
pub struct JsonlConfig {
    /// Primary log file path.
    pub path: PathBuf,
    /// Optional fallback path (e.g. on a different filesystem).
    pub fallback_path: Option<PathBuf>,
    /// Maximum file size before rotation (bytes). Default: 100 MiB.
    pub max_size_bytes: u64,
    /// Number of rotated files to keep. Default: 5.
    pub max_rotated_files: u32,
    /// Seconds between forced fsync calls. Default: 10.
    pub fsync_interval_secs: u64,
}

impl Default for JsonlConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/var/lib/sbh/activity.jsonl"),
            fallback_path: Some(PathBuf::from("/dev/shm/sbh.jsonl")),
            max_size_bytes: 100 * 1024 * 1024, // 100 MiB
            max_rotated_files: 5,
            fsync_interval_secs: 10,
        }
    }
}

/// Append-only JSONL log writer with rotation and multi-level fallback.
pub struct JsonlWriter {
    config: JsonlConfig,
    writer: Option<BufWriter<File>>,
    state: WriterState,
    bytes_written: u64,
    last_fsync: SystemTime,
    last_recover_attempt: SystemTime,
    last_rotate_attempt: SystemTime,
    lines_since_fsync: u64,
}

impl JsonlWriter {
    /// Open the JSONL log file. Falls through the degradation chain on failure.
    pub fn open(config: JsonlConfig) -> Self {
        let mut w = Self {
            config,
            writer: None,
            state: WriterState::Discard,
            bytes_written: 0,
            last_fsync: SystemTime::now(),
            last_recover_attempt: UNIX_EPOCH,
            last_rotate_attempt: UNIX_EPOCH,
            lines_since_fsync: 0,
        };
        w.try_open_primary();
        w
    }

    /// Write a single log entry as one atomic JSONL line.
    pub fn write_entry(&mut self, entry: &LogEntry) {
        let line = match serde_json::to_string(entry) {
            Ok(mut json) => {
                json.push('\n');
                json
            }
            Err(e) => {
                // Serialization failure is a programming error; log to stderr and bail.
                let _ = writeln!(io::stderr(), "[SBH-JSONL] serialize error: {e}");
                return;
            }
        };

        self.write_line(&line);
    }

    /// Flush buffers.
    pub fn flush(&mut self) {
        if let Some(w) = self.writer.as_mut() {
            let _ = w.flush();
        }
    }

    /// Force an fsync on the underlying file.
    pub fn fsync(&mut self) {
        if let Some(w) = self.writer.as_mut() {
            let _ = w.flush();
            let _ = w.get_ref().sync_data();
            self.last_fsync = SystemTime::now();
            self.lines_since_fsync = 0;
        }
    }

    /// Current degradation state.
    pub fn state(&self) -> &str {
        match self.state {
            WriterState::Normal => "normal",
            WriterState::Fallback => "fallback",
            WriterState::Stderr => "stderr",
            WriterState::Discard => "discard",
        }
    }

    /// Number of bytes written to the current file.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    // ──────────────────────── internals ────────────────────────

    fn write_line(&mut self, line: &str) {
        self.maybe_try_recover();

        // Check if rotation is needed before writing.
        if self.bytes_written + line.len() as u64 > self.config.max_size_bytes
            && matches!(self.state, WriterState::Normal | WriterState::Fallback)
            && self
                .last_rotate_attempt
                .elapsed()
                .unwrap_or(Duration::ZERO)
                .as_secs()
                > 10
        {
            self.rotate();
        }

        match self.state {
            WriterState::Normal | WriterState::Fallback => {
                if let Some(w) = self.writer.as_mut() {
                    if w.write_all(line.as_bytes()).is_err() {
                        self.degrade();
                        self.write_line(line); // retry at next level
                        return;
                    }
                    self.bytes_written += line.len() as u64;
                    self.lines_since_fsync += 1;
                    self.maybe_fsync();
                } else {
                    self.degrade();
                    self.write_line(line);
                }
            }
            WriterState::Stderr => {
                let _ = write!(io::stderr(), "[SBH-JSONL] {line}");
            }
            WriterState::Discard => {
                // Silently drop.
            }
        }
    }

    fn maybe_fsync(&mut self) {
        let elapsed = SystemTime::now()
            .duration_since(self.last_fsync)
            .unwrap_or(Duration::ZERO);
        if elapsed.as_secs() >= self.config.fsync_interval_secs {
            self.fsync();
        }
    }

    fn maybe_try_recover(&mut self) {
        if self.state == WriterState::Normal {
            return;
        }
        let now = SystemTime::now();
        let elapsed = now
            .duration_since(self.last_recover_attempt)
            .unwrap_or(Duration::ZERO);
        if elapsed < Duration::from_secs(30) {
            return;
        }
        self.last_recover_attempt = now;
        self.try_recover();
    }

    fn try_open_primary(&mut self) {
        match open_append(&self.config.path) {
            Ok((file, size)) => {
                self.writer = Some(BufWriter::with_capacity(64 * 1024, file));
                self.state = WriterState::Normal;
                self.bytes_written = size;
            }
            Err(_) => {
                self.try_open_fallback();
            }
        }
    }

    fn try_open_fallback(&mut self) {
        if let Some(fb) = &self.config.fallback_path {
            if let Ok((file, size)) = open_append(fb) {
                let _ = writeln!(
                    io::stderr(),
                    "[SBH-JSONL] primary path failed, using fallback: {}",
                    fb.display()
                );
                self.writer = Some(BufWriter::with_capacity(64 * 1024, file));
                self.state = WriterState::Fallback;
                self.bytes_written = size;
            } else {
                self.state = WriterState::Stderr;
                let _ = writeln!(
                    io::stderr(),
                    "[SBH-JSONL] both primary and fallback paths failed, using stderr"
                );
            }
        } else {
            self.state = WriterState::Stderr;
            let _ = writeln!(
                io::stderr(),
                "[SBH-JSONL] primary path failed and no fallback configured, using stderr"
            );
        }
    }

    fn degrade(&mut self) {
        self.writer = None;
        match self.state {
            WriterState::Normal => {
                self.try_open_fallback();
            }
            WriterState::Fallback => {
                self.state = WriterState::Stderr;
                let _ = writeln!(
                    io::stderr(),
                    "[SBH-JSONL] fallback write failed, using stderr"
                );
            }
            WriterState::Stderr => {
                self.state = WriterState::Discard;
            }
            WriterState::Discard => {}
        }
    }

    fn rotate(&mut self) {
        self.last_rotate_attempt = SystemTime::now();

        // Flush and drop current file.
        if let Some(w) = self.writer.as_mut() {
            let _ = w.flush();
        }
        self.writer = None;

        let base = match self.state {
            WriterState::Normal => &self.config.path,
            WriterState::Fallback => match &self.config.fallback_path {
                Some(p) => p,
                None => return,
            },
            _ => return,
        };

        // Delete the oldest rotation first, then shift: .4→.5, .3→.4, …, .1→.2.
        // Deleting before shifting prevents silent overwrite of the oldest file.
        let oldest = rotated_name(base, self.config.max_rotated_files);
        let _ = fs::remove_file(&oldest);

        for i in (1..self.config.max_rotated_files).rev() {
            let from = rotated_name(base, i);
            let to = rotated_name(base, i + 1);
            let _ = rename(&from, &to);
        }

        // Rename current → .1
        let _ = rename(base, rotated_name(base, 1));

        // Reopen a fresh file.
        match open_append(base) {
            Ok((file, _)) => {
                self.writer = Some(BufWriter::with_capacity(64 * 1024, file));
                self.bytes_written = 0;
            }
            Err(_) => {
                self.degrade();
            }
        }
    }
}

/// Attempt recovery: try reopening the primary path.
/// Call periodically (e.g. every 60s) when degraded to return to normal.
impl JsonlWriter {
    pub fn try_recover(&mut self) {
        if self.state == WriterState::Normal {
            return;
        }
        if let Ok((file, size)) = open_append(&self.config.path) {
            self.writer = Some(BufWriter::with_capacity(64 * 1024, file));
            self.state = WriterState::Normal;
            self.bytes_written = size;
            let _ = writeln!(
                io::stderr(),
                "[SBH-JSONL] recovered to primary path: {}",
                self.config.path.display()
            );
        }
    }
}

// ──────────────────────── helpers ────────────────────────

/// Open or create a file for appending. Returns `(File, current_size)`.
fn open_append(path: &Path) -> Result<(File, u64)> {
    // Ensure parent directory exists.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| SbhError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let file = {
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        opts.open(path)
            .map_err(|source| SbhError::io(path, source))?
    };
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    Ok((file, size))
}

/// Build a rotated filename: `foo.jsonl` → `foo.jsonl.3`.
fn rotated_name(base: &Path, index: u32) -> PathBuf {
    let mut name = base.as_os_str().to_owned();
    name.push(format!(".{index}"));
    PathBuf::from(name)
}

/// Format current UTC time as ISO 8601.
fn format_utc_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

// ──────────────────────── tests ────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_entry_produces_valid_json_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.jsonl");
        let config = JsonlConfig {
            path: path.clone(),
            fallback_path: None,
            max_size_bytes: 1024 * 1024,
            max_rotated_files: 3,
            fsync_interval_secs: 60,
        };
        let mut writer = JsonlWriter::open(config);

        let entry = LogEntry::new(EventType::DaemonStart, Severity::Info);
        writer.write_entry(&entry);
        writer.flush();

        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed["event"], "daemon_start");
        assert_eq!(parsed["severity"], "info");
    }

    #[test]
    fn multiple_entries_are_separate_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("multi.jsonl");
        let config = JsonlConfig {
            path: path.clone(),
            fallback_path: None,
            max_size_bytes: 1024 * 1024,
            max_rotated_files: 3,
            fsync_interval_secs: 60,
        };
        let mut writer = JsonlWriter::open(config);

        for _ in 0..5 {
            writer.write_entry(&LogEntry::new(EventType::ScanComplete, Severity::Info));
        }
        writer.flush();

        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 5);
        for line in lines {
            let _: serde_json::Value = serde_json::from_str(line).unwrap();
        }
    }

    #[test]
    fn rotation_shifts_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rot.jsonl");
        let config = JsonlConfig {
            path: path.clone(),
            fallback_path: None,
            max_size_bytes: 100, // tiny: force rotation after ~1 entry
            max_rotated_files: 3,
            fsync_interval_secs: 60,
        };
        let mut writer = JsonlWriter::open(config);

        // Write enough entries to trigger multiple rotations.
        for _ in 0..10 {
            writer.write_entry(&LogEntry::new(EventType::ScanComplete, Severity::Info));
        }
        writer.flush();

        // Primary file should exist with recent data.
        assert!(path.exists());
        // At least one rotated file should exist.
        assert!(rotated_name(&path, 1).exists());
    }

    #[test]
    fn fallback_when_primary_dir_unwritable() {
        let dir = tempfile::tempdir().unwrap();
        let bad_primary = PathBuf::from("/nonexistent_sbh_test_dir_12345/primary.jsonl");
        let fallback = dir.path().join("fallback.jsonl");
        let config = JsonlConfig {
            path: bad_primary,
            fallback_path: Some(fallback.clone()),
            max_size_bytes: 1024 * 1024,
            max_rotated_files: 3,
            fsync_interval_secs: 60,
        };
        let mut writer = JsonlWriter::open(config);

        assert_eq!(writer.state(), "fallback");
        writer.write_entry(&LogEntry::new(EventType::Error, Severity::Warning));
        writer.flush();

        let contents = fs::read_to_string(&fallback).unwrap();
        assert!(!contents.is_empty());
    }

    #[test]
    fn state_reports_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let config = JsonlConfig {
            path: dir.path().join("ok.jsonl"),
            fallback_path: None,
            max_size_bytes: 1024 * 1024,
            max_rotated_files: 3,
            fsync_interval_secs: 60,
        };
        let writer = JsonlWriter::open(config);
        assert_eq!(writer.state(), "normal");
    }

    #[test]
    fn entry_optional_fields_omitted_when_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sparse.jsonl");
        let config = JsonlConfig {
            path: path.clone(),
            fallback_path: None,
            max_size_bytes: 1024 * 1024,
            max_rotated_files: 3,
            fsync_interval_secs: 60,
        };
        let mut writer = JsonlWriter::open(config);

        let entry = LogEntry::new(EventType::DaemonStart, Severity::Info);
        writer.write_entry(&entry);
        writer.flush();

        let line = fs::read_to_string(&path).unwrap();
        // None-valued fields should NOT appear in the JSON.
        assert!(!line.contains("\"path\""));
        assert!(!line.contains("\"size\""));
        assert!(!line.contains("\"score\""));
    }

    #[test]
    fn degraded_writer_attempts_and_applies_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let recovery_path = dir.path().join("recovered.jsonl");
        let config = JsonlConfig {
            path: PathBuf::from("/nonexistent_sbh_test_dir_12345/primary.jsonl"),
            fallback_path: None,
            max_size_bytes: 1024 * 1024,
            max_rotated_files: 3,
            fsync_interval_secs: 60,
        };
        let mut writer = JsonlWriter::open(config);

        assert_ne!(writer.state(), "normal");

        writer.config.path = recovery_path.clone();
        writer.last_recover_attempt = UNIX_EPOCH;

        writer.write_entry(&LogEntry::new(EventType::ScanComplete, Severity::Info));
        writer.flush();

        assert_eq!(writer.state(), "normal");
        assert!(recovery_path.exists());
    }
}
