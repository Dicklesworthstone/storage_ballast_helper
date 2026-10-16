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
//!
//! RAM fallback and mirror destinations require fresh headroom evidence before
//! opening, writing, or flushing. Refusal discards pending RAM-destination
//! buffers without flushing them; the primary and stderr routes remain usable.

#![allow(missing_docs)]

use std::fs::{self, File, OpenOptions, rename};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    Info,
    Error,
    Emergency,
    /// A cleanup decision (the full `DecisionRecord` is in `details`).
    Decision,
    /// A policy engine mode change (`details`: `kind: from -> to`).
    PolicyTransition,
    /// What became of a deletion (`regret`, `clean`, `unknown`), keyed by
    /// `decision_id`.
    DecisionOutcome,
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
    /// Stable decision id linking this event to a ledger decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    /// `artifact_delete` only: the candidate was moved into quarantine
    /// (restorable with `sbh undo`) rather than unlinked; no bytes freed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantined: Option<bool>,
    /// Freeform details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// C-EVENT schema version of the line; absent on lines written before
    /// 0.5.2, which readers treat as v1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<u32>,
    /// The daemon run that wrote the line (`state.json` `run_id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
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
            decision_id: None,
            quarantined: None,
            details: None,
            schema_version: None,
            run_id: None,
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

/// The daemon's JSONL rotation size (bd-rc-master-ajg1.7.2).
///
/// These constants are the single source the README quotes: rotation at
/// 50 MiB keeping 5 files, fsync every 30 s (a pressured disk must not take
/// an fsync every 10 s), and a RAM-backed fallback that is capped rather
/// than rotated.
pub const DAEMON_MAX_SIZE_BYTES: u64 = 50 * 1024 * 1024;
pub const DAEMON_MAX_ROTATED_FILES: u32 = 5;
pub const DAEMON_FSYNC_INTERVAL_SECS: u64 = 30;
/// The fallback file lives in RAM: it is never rotated and is truncated
/// when it would exceed this size, so a long outage of the primary path
/// cannot fill `/dev/shm`.
pub const FALLBACK_MAX_BYTES: u64 = 16 * 1024 * 1024;

impl JsonlConfig {
    /// The daemon's configuration for the activity log at `path`.
    #[must_use]
    pub fn for_daemon(path: PathBuf) -> Self {
        Self {
            path,
            fallback_path: Some(ram_fallback_path()),
            max_size_bytes: DAEMON_MAX_SIZE_BYTES,
            max_rotated_files: DAEMON_MAX_ROTATED_FILES,
            fsync_interval_secs: DAEMON_FSYNC_INTERVAL_SECS,
        }
    }
}

/// Where the RAM-backed fallback lives: `/dev/shm/sbh-<uid>.jsonl` on
/// Linux (per user, so a user-scope and a system-scope daemon never share
/// one file), the temp directory elsewhere (`$TMPDIR` on macOS).
#[must_use]
pub fn ram_fallback_path() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        let shm = Path::new("/dev/shm");
        if shm.is_dir() {
            return shm.join(format!("sbh-{}.jsonl", nix::unistd::getuid()));
        }
    }
    std::env::temp_dir().join("sbh.jsonl")
}

/// Append-only JSONL log writer with rotation and multi-level fallback.
pub struct JsonlWriter {
    config: JsonlConfig,
    writer: Option<BufWriter<File>>,
    state: WriterState,
    bytes_written: u64,
    last_fsync: SystemTime,
    last_recover_attempt: SystemTime,
    lines_since_fsync: u64,
    /// fsyncs performed so far (the idle timer test reads it).
    fsync_count: u64,
    /// While the primary's volume is pressured, every line is also written
    /// here (the RAM fallback), so the log survives the primary filling up
    /// (bd-rc-master-ajg1.7.4).
    mirror: Option<BufWriter<File>>,
    mirror_bytes: u64,
    /// Stamped on every line (C-EVENT `run_id`) when set.
    run_id: Option<String>,
    /// Read-only admission check. Injected per writer so lifecycle tests do
    /// not depend on the build host's current RAM or swap pressure.
    destination_check: fn(&Path) -> Option<String>,
    last_destination_warning: Option<Instant>,
    /// When the RAM route last passed `destination_check`, and how long that
    /// verdict stands before a line checks again (bd-sz85).
    destination_ok_at: Option<Instant>,
    destination_recheck: Duration,
}

/// How long a healthy RAM-route verdict stands. The check reads
/// `/proc/meminfo` and `statvfs`, and it ran for every line while mirroring
/// (bd-sz85); a refusal still acts on the line that observes it. Tests swap
/// the check between lines, so they re-check every line.
#[cfg(not(test))]
const DESTINATION_RECHECK: Duration = Duration::from_secs(1);
#[cfg(test)]
const DESTINATION_RECHECK: Duration = Duration::ZERO;

impl JsonlWriter {
    /// Open the JSONL log file. Falls through the degradation chain on failure.
    pub fn open(config: JsonlConfig) -> Self {
        Self::open_with_destination_check(config, check_ram_log_destination)
    }

    fn open_with_destination_check(
        config: JsonlConfig,
        destination_check: fn(&Path) -> Option<String>,
    ) -> Self {
        let mut w = Self {
            config,
            writer: None,
            state: WriterState::Discard,
            bytes_written: 0,
            last_fsync: SystemTime::now(),
            last_recover_attempt: UNIX_EPOCH,
            lines_since_fsync: 0,
            fsync_count: 0,
            mirror: None,
            mirror_bytes: 0,
            run_id: None,
            destination_check,
            last_destination_warning: None,
            destination_ok_at: None,
            destination_recheck: DESTINATION_RECHECK,
        };
        w.try_open_primary();
        w
    }

    /// The daemon run every subsequent line is attributed to.
    pub fn set_run_id(&mut self, run_id: String) {
        self.run_id = Some(run_id);
    }

    /// Write a single log entry as one atomic JSONL line, stamped with the
    /// C-EVENT schema version and this run's id unless the entry already
    /// carries them.
    pub fn write_entry(&mut self, entry: &LogEntry) {
        let mut stamped;
        let entry = if entry.schema_version.is_some() && entry.run_id.is_some() {
            entry
        } else {
            stamped = entry.clone();
            stamped
                .schema_version
                .get_or_insert(crate::logger::schema::SCHEMA_VERSION);
            if stamped.run_id.is_none() {
                stamped.run_id.clone_from(&self.run_id);
            }
            &stamped
        };
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

    /// Flush buffers, refusing pending writes to a newly pressured RAM route.
    pub fn flush(&mut self) {
        self.enforce_destination_health();
        if let Some(w) = self.writer.as_mut() {
            let _ = w.flush();
        }
        if let Some(mirror) = self.mirror.as_mut() {
            let _ = mirror.flush();
        }
    }

    /// Force an fsync on the underlying file.
    pub fn fsync(&mut self) {
        self.fsync_at(SystemTime::now());
    }

    fn fsync_at(&mut self, now: SystemTime) {
        self.enforce_destination_health();
        if let Some(w) = self.writer.as_mut() {
            let _ = w.flush();
            let _ = w.get_ref().sync_data();
            self.last_fsync = now;
            self.lines_since_fsync = 0;
            self.fsync_count += 1;
        }
    }

    /// The idle timer: fsync lines written since the last fsync once the
    /// interval has elapsed, even when no further line arrives to trigger
    /// it. The logger thread calls this once a second while idle.
    pub fn tick(&mut self, now: SystemTime) {
        self.enforce_destination_health();
        if self.lines_since_fsync == 0 {
            return;
        }
        let elapsed = now
            .duration_since(self.last_fsync)
            .unwrap_or(Duration::ZERO);
        if elapsed.as_secs() >= self.config.fsync_interval_secs {
            self.fsync_at(now);
        }
    }

    /// fsyncs performed since the writer was opened.
    #[must_use]
    pub fn fsync_count(&self) -> u64 {
        self.fsync_count
    }

    /// Mirror every line to the fallback as well (`on`), or stop. RAM-backed
    /// destinations require current headroom. The primary keeps being written;
    /// a writer already running on the fallback has nothing to mirror to.
    pub fn set_mirror(&mut self, on: bool) {
        self.enforce_destination_health();
        if !on {
            if let Some(mut mirror) = self.mirror.take() {
                let _ = mirror.flush();
                // Do not retry a failed flush implicitly in BufWriter::drop.
                let _ = mirror.into_parts();
            }
            self.mirror_bytes = 0;
            return;
        }
        if self.mirror.is_some() || self.state != WriterState::Normal {
            return;
        }
        let Some(path) = self.config.fallback_path.clone() else {
            return;
        };
        if let Some(reason) = self.fallback_refusal() {
            self.warn_destination_refusal(&reason);
            return;
        }
        match open_append(&path) {
            Ok((file, size)) => {
                self.mirror = Some(BufWriter::with_capacity(64 * 1024, file));
                self.mirror_bytes = size;
                let _ = writeln!(
                    io::stderr(),
                    "[SBH-JSONL] mirroring the log to {} while its volume is pressured",
                    path.display()
                );
            }
            Err(e) => {
                let _ = writeln!(
                    io::stderr(),
                    "[SBH-JSONL] cannot open the mirror {}: {e}",
                    path.display()
                );
            }
        }
    }

    /// Whether lines are currently mirrored to the RAM fallback.
    #[must_use]
    pub fn mirroring(&self) -> bool {
        self.mirror.is_some()
    }

    fn write_mirror(&mut self, line: &str) {
        // An oversized line must not bypass the cap on an empty mirror.
        if line.len() as u64 > FALLBACK_MAX_BYTES {
            return;
        }
        let Some(mirror) = self.mirror.as_mut() else {
            return;
        };
        if self.mirror_bytes.saturating_add(line.len() as u64) > FALLBACK_MAX_BYTES {
            if mirror.flush().is_err() || mirror.get_ref().set_len(0).is_err() {
                self.discard_mirror();
                return;
            }
            self.mirror_bytes = 0;
        }
        if mirror.write_all(line.as_bytes()).is_ok() {
            self.mirror_bytes += line.len() as u64;
        } else {
            self.discard_mirror();
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

    fn fallback_refusal(&self) -> Option<String> {
        self.config
            .fallback_path
            .as_deref()
            .and_then(self.destination_check)
    }

    fn warn_destination_refusal(&mut self, reason: &str) {
        let now = Instant::now();
        if self
            .last_destination_warning
            .is_some_and(|last| now.duration_since(last) < Duration::from_secs(30))
        {
            return;
        }
        self.last_destination_warning = Some(now);
        let _ = writeln!(
            io::stderr(),
            "[SBH-JSONL] fallback/mirror refused: {reason}; pending RAM-route buffers discarded; primary/stderr remain available"
        );
    }

    fn discard_mirror(&mut self) {
        if let Some(mirror) = self.mirror.take() {
            // Dropping BufWriter directly would flush into the refused mount.
            let _ = mirror.into_parts();
        }
        self.mirror_bytes = 0;
    }

    fn enforce_destination_health(&mut self) {
        if self.state != WriterState::Fallback && self.mirror.is_none() {
            return;
        }
        if self
            .destination_ok_at
            .is_some_and(|at| at.elapsed() < self.destination_recheck)
        {
            return;
        }
        let Some(reason) = self.fallback_refusal() else {
            self.destination_ok_at = Some(Instant::now());
            return;
        };
        self.destination_ok_at = None;
        self.discard_mirror();
        if self.state == WriterState::Fallback {
            if let Some(writer) = self.writer.take() {
                let _ = writer.into_parts();
            }
            self.state = WriterState::Stderr;
            self.bytes_written = 0;
            self.lines_since_fsync = 0;
            self.last_recover_attempt = SystemTime::now();
        }
        self.warn_destination_refusal(&reason);
    }

    fn write_line(&mut self, line: &str) {
        self.maybe_try_recover();
        self.enforce_destination_health();

        if self.state == WriterState::Normal
            && self.bytes_written.saturating_add(line.len() as u64) > self.config.max_size_bytes
            && self.bytes_written > 0
        {
            self.rotate();
            // Rotation may have failed over to an existing, nearly full RAM
            // file. Apply the same admission and cap checks as any fallback.
            self.enforce_destination_health();
        }
        if self.state == WriterState::Fallback {
            // The primary may retain a large event; the RAM fallback may not.
            if line.len() as u64 > FALLBACK_MAX_BYTES {
                let _ = write!(io::stderr(), "[SBH-JSONL] {line}");
                return;
            }
            if self.bytes_written.saturating_add(line.len() as u64) > FALLBACK_MAX_BYTES {
                self.truncate_fallback();
            }
        }

        match self.state {
            WriterState::Normal | WriterState::Fallback => {
                if let Some(w) = self.writer.as_mut() {
                    if w.write_all(line.as_bytes()).is_err() {
                        self.degrade();
                        self.write_line(line); // retry at next level
                        return;
                    }
                    self.bytes_written = self.bytes_written.saturating_add(line.len() as u64);
                    self.lines_since_fsync += 1;
                    self.maybe_fsync();
                    // Mirror only after this line was accepted. If primary
                    // admission failed, the fallback retry owns the line once.
                    if self.state == WriterState::Normal {
                        self.write_mirror(line);
                    }
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

    /// Start the fallback file over: the primary has been unavailable long
    /// enough to fill the RAM cap, and old fallback lines are worth less
    /// than the memory they hold.
    fn truncate_fallback(&mut self) {
        let Some(w) = self.writer.as_mut() else {
            return;
        };
        if w.flush().is_ok() && w.get_ref().set_len(0).is_ok() {
            self.bytes_written = 0;
            let _ = writeln!(
                io::stderr(),
                "[SBH-JSONL] fallback log reached {FALLBACK_MAX_BYTES} bytes; truncated"
            );
        } else {
            self.degrade();
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
        if let Some(reason) = self.fallback_refusal() {
            self.state = WriterState::Stderr;
            self.bytes_written = 0;
            self.warn_destination_refusal(&reason);
            return;
        }
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
        let failed_state = self.state;
        // A mirror and fallback share a path. Close the mirror before opening
        // the fallback, and never flush it after its headroom was refused.
        self.set_mirror(false);
        if let Some(writer) = self.writer.take() {
            let _ = writer.into_parts();
        }
        self.bytes_written = 0;
        self.lines_since_fsync = 0;
        // set_mirror can independently move an unsafe fallback to stderr.
        // Base this transition on the failed sink, not that intermediate state,
        // so a fallback failure never skips the stderr retry and discards data.
        match failed_state {
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

        // Delete the oldest rotation first.
        let oldest = rotated_name(base, self.config.max_rotated_files);
        if oldest.exists()
            && let Err(e) = fs::remove_file(&oldest)
        {
            let _ = writeln!(
                io::stderr(),
                "[SBH-JSONL] rotation warning: failed to delete oldest log {}: {e}",
                oldest.display(),
            );
        }

        for i in (1..self.config.max_rotated_files).rev() {
            let from = rotated_name(base, i);
            let to = rotated_name(base, i + 1);
            if from.exists() {
                // Ensure target is gone before rename (essential for Windows).
                if to.exists() {
                    let _ = fs::remove_file(&to);
                }
                if let Err(e) = rename(&from, &to) {
                    let _ = writeln!(
                        io::stderr(),
                        "[SBH-JSONL] rotation warning: failed to shift {} -> {}: {}",
                        from.display(),
                        to.display(),
                        e
                    );
                }
            }
        }

        // Rename current → .1
        let target = rotated_name(base, 1);
        if target.exists() {
            let _ = fs::remove_file(&target);
        }
        if let Err(e) = rename(base, &target) {
            let _ = writeln!(
                io::stderr(),
                "[SBH-JSONL] rotation warning: failed to rotate primary {} -> {}: {}",
                base.display(),
                target.display(),
                e
            );
        }

        if let Err(e) = sync_parent_directory(base) {
            let _ = writeln!(
                io::stderr(),
                "[SBH-JSONL] rotation warning: failed to sync parent directory for {}: {}",
                base.display(),
                e
            );
        }

        // Reopen a fresh file.
        match open_append(base) {
            Ok((file, _)) => {
                self.writer = Some(BufWriter::with_capacity(64 * 1024, file));
                self.bytes_written = 0;
            }
            Err(e) => {
                let _ = writeln!(
                    io::stderr(),
                    "[SBH-JSONL] critical: failed to reopen log after rotation: {e}",
                );
                self.degrade();
            }
        }
    }
}

/// Attempt recovery: try reopening the primary path.
/// Call periodically (e.g. every 60s) when degraded to return to normal.
impl JsonlWriter {
    pub fn try_recover(&mut self) {
        // Recovery must not implicitly flush an old, now-unsafe RAM buffer.
        self.enforce_destination_health();
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
            return;
        }

        // Do not reopen an already active fallback and reset its byte count
        // from metadata while its buffered lines have not reached the file.
        if self.state == WriterState::Fallback {
            return;
        }
        if let Some(reason) = self.fallback_refusal() {
            self.warn_destination_refusal(&reason);
            return;
        }
        if let Some(fallback) = &self.config.fallback_path
            && let Ok((file, size)) = open_append(fallback)
        {
            self.writer = Some(BufWriter::with_capacity(64 * 1024, file));
            self.state = WriterState::Fallback;
            self.bytes_written = size;
            let _ = writeln!(
                io::stderr(),
                "[SBH-JSONL] recovered to fallback path: {}",
                fallback.display()
            );
        }
    }
}

impl Drop for JsonlWriter {
    fn drop(&mut self) {
        self.flush();
        // Explicitly disassemble both buffers: Drop must not bypass refusal
        // or retry a failed flush behind the admission check's back.
        if let Some(writer) = self.writer.take() {
            let _ = writer.into_parts();
        }
        self.discard_mirror();
    }
}

// ──────────────────────── helpers ────────────────────────

fn check_ram_log_destination(path: &Path) -> Option<String> {
    // Reuse the PAL's bounded mount-table cache on the logger thread. Memory
    // and filesystem capacity are still read for each admission; creating a
    // fresh PAL per line would throw away the cache and reparse every mount.
    std::thread_local! {
        static PLATFORM: Box<dyn crate::platform::pal::Platform> =
            Box::new(crate::platform::current());
    }
    PLATFORM.with(|platform| {
        crate::monitor::ram_scratch::ram_log_mirror_refusal(platform.as_ref(), path)
    })
}

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
    let size = file.metadata().map_or(0, |m| m.len());
    Ok((file, size))
}

/// Build a rotated filename: `foo.jsonl` → `foo.jsonl.3`.
fn rotated_name(base: &Path, index: u32) -> PathBuf {
    let mut name = base.as_os_str().to_owned();
    name.push(format!(".{index}"));
    PathBuf::from(name)
}

fn sync_parent_directory(path: &Path) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    #[cfg(unix)]
    {
        File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
    }
    Ok(())
}

/// Format current UTC time as ISO 8601.
fn format_utc_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

// ──────────────────────── tests ────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Callback fixtures retain the production admission-check signature.
    #[allow(clippy::unnecessary_wraps)]
    fn allow_destination(_: &Path) -> Option<String> {
        None
    }

    #[allow(clippy::unnecessary_wraps)]
    fn refuse_destination(_: &Path) -> Option<String> {
        Some("fixture: RAM headroom unavailable".to_owned())
    }

    // File/rotation tests supply healthy admission independently of the test
    // host. The refusal tests below exercise the same production state machine.
    fn open_writer(config: JsonlConfig) -> JsonlWriter {
        JsonlWriter::open_with_destination_check(config, allow_destination)
    }

    /// bd-rc-master-ajg1.7.2: the daemon's settings are the documented chain.
    #[test]
    fn daemon_config_is_the_documented_chain() {
        let config = JsonlConfig::for_daemon(PathBuf::from("/var/lib/sbh/activity.jsonl"));
        assert_eq!(config.max_size_bytes, 50 * 1024 * 1024);
        assert_eq!(config.max_rotated_files, 5);
        assert_eq!(config.fsync_interval_secs, 30);
        let fallback = config.fallback_path.expect("RAM fallback enabled");
        assert_eq!(fallback, ram_fallback_path());
        if cfg!(target_os = "linux") && Path::new("/dev/shm").is_dir() {
            assert!(fallback.starts_with("/dev/shm"), "{}", fallback.display());
            assert_eq!(fallback.extension().and_then(|e| e.to_str()), Some("jsonl"));
            assert!(
                fallback
                    .file_stem()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("sbh-")),
                "{}",
                fallback.display()
            );
        } else {
            assert!(fallback.starts_with(std::env::temp_dir()));
        }
    }

    /// bd-rc-master-ajg1.7.2: one line, then silence; the idle timer fsyncs
    /// it exactly once after the interval and never again without new lines.
    #[test]
    fn idle_tick_fsyncs_once_after_the_interval() {
        let dir = tempfile::tempdir().unwrap();
        let t0 = SystemTime::now();
        let mut writer = open_writer(JsonlConfig {
            path: dir.path().join("activity.jsonl"),
            fallback_path: None,
            max_size_bytes: 1024 * 1024,
            max_rotated_files: 1,
            fsync_interval_secs: 30,
        });
        writer.write_entry(&LogEntry::new(EventType::DaemonStart, Severity::Info));
        assert_eq!(writer.fsync_count(), 0);
        writer.tick(t0 + Duration::from_secs(29));
        assert_eq!(writer.fsync_count(), 0);
        writer.tick(t0 + Duration::from_secs(31));
        assert_eq!(writer.fsync_count(), 1);
        // Nothing new: the timer stays quiet however long it runs.
        writer.tick(t0 + Duration::from_secs(32));
        writer.tick(t0 + Duration::from_secs(120));
        assert_eq!(writer.fsync_count(), 1);
        // A new line after a long quiet spell: the interval since the last
        // fsync has long elapsed, so the next tick makes it durable.
        writer.write_entry(&LogEntry::new(EventType::DaemonStop, Severity::Info));
        assert_eq!(writer.fsync_count(), 1, "the write itself is not an fsync");
        writer.tick(t0 + Duration::from_secs(121));
        assert_eq!(writer.fsync_count(), 2);
    }

    /// bd-rc-master-ajg1.7.2: the RAM-backed fallback is capped, not rotated.
    #[test]
    fn fallback_is_truncated_at_its_cap_instead_of_rotated() {
        let dir = tempfile::tempdir().unwrap();
        let fallback = dir.path().join("fallback.jsonl");
        let mut writer = open_writer(JsonlConfig {
            path: uncreatable_path(dir.path(), "primary.jsonl"),
            fallback_path: Some(fallback.clone()),
            max_size_bytes: 1024,
            max_rotated_files: 3,
            fsync_interval_secs: 3600,
        });
        assert_eq!(writer.state(), "fallback");
        let mut entry = LogEntry::new(EventType::Info, Severity::Info);
        entry.details = Some("x".repeat(4000));
        let line_bytes = serde_json::to_string(&entry).unwrap().len() as u64 + 1;
        let lines = FALLBACK_MAX_BYTES / line_bytes + 3;
        for _ in 0..lines {
            writer.write_entry(&entry);
        }
        writer.flush();
        assert_eq!(writer.state(), "fallback");
        let size = fs::metadata(&fallback).unwrap().len();
        assert!(size < FALLBACK_MAX_BYTES, "fallback grew to {size}");
        assert!(size > 0, "fallback must keep writing after truncation");
        assert!(
            !rotated_name(&fallback, 1).exists(),
            "the fallback must never be rotated"
        );
        assert!(!rotated_name(&fallback, 2).exists());
    }

    /// bd-rc-master-ajg1.7.4: while mirroring, every line lands in both the
    /// primary and the RAM fallback; the mirror is capped, and switching it
    /// off leaves the primary untouched.
    #[test]
    fn mirror_writes_every_line_to_the_fallback_while_on() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("activity.jsonl");
        let fallback = dir.path().join("fallback.jsonl");
        let mut writer = open_writer(JsonlConfig {
            path: primary.clone(),
            fallback_path: Some(fallback.clone()),
            max_size_bytes: 1024 * 1024,
            max_rotated_files: 1,
            fsync_interval_secs: 3600,
        });
        assert!(!writer.mirroring());
        writer.write_entry(&LogEntry::new(EventType::DaemonStart, Severity::Info));
        writer.set_mirror(true);
        assert!(writer.mirroring());
        writer.write_entry(&LogEntry::new(EventType::ScanComplete, Severity::Info));
        writer.write_entry(&LogEntry::new(EventType::ArtifactDelete, Severity::Info));
        writer.set_mirror(false);
        assert!(!writer.mirroring());
        writer.write_entry(&LogEntry::new(EventType::DaemonStop, Severity::Info));
        writer.flush();

        let primary_text = fs::read_to_string(&primary).unwrap();
        let fallback_text = fs::read_to_string(&fallback).unwrap();
        assert_eq!(primary_text.lines().count(), 4);
        assert_eq!(fallback_text.lines().count(), 2, "{fallback_text}");
        assert!(fallback_text.contains("scan_complete"));
        assert!(fallback_text.contains("artifact_delete"));
        assert!(!fallback_text.contains("daemon_stop"));
        assert_eq!(writer.state(), "normal");

        // A writer without a fallback path has nothing to mirror to.
        let mut lone = open_writer(JsonlConfig {
            path: dir.path().join("lone.jsonl"),
            fallback_path: None,
            max_size_bytes: 1024 * 1024,
            max_rotated_files: 1,
            fsync_interval_secs: 3600,
        });
        lone.set_mirror(true);
        assert!(!lone.mirroring());
    }

    /// A path no process can create — root included: its parent is a regular
    /// FILE inside the tempdir, so `create_dir_all` fails with `ENOTDIR`
    /// instead of succeeding for a privileged uid. This keeps the
    /// "primary path unavailable" fixtures hermetic (nothing is ever created
    /// outside the tempdir, so a root-run suite leaves no litter at `/`) and
    /// valid regardless of who runs the tests.
    fn uncreatable_path(dir: &Path, leaf: &str) -> PathBuf {
        let blocker = dir.join("not-a-directory");
        if !blocker.exists() {
            fs::write(&blocker, b"regular file standing in for an unwritable dir").unwrap();
        }
        blocker.join(leaf)
    }

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
        let mut writer = open_writer(config);

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
        let mut writer = open_writer(config);

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
        let mut writer = open_writer(config);

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
        let bad_primary = uncreatable_path(dir.path(), "primary.jsonl");
        let fallback = dir.path().join("fallback.jsonl");
        let config = JsonlConfig {
            path: bad_primary,
            fallback_path: Some(fallback.clone()),
            max_size_bytes: 1024 * 1024,
            max_rotated_files: 3,
            fsync_interval_secs: 60,
        };
        let mut writer = open_writer(config);

        assert_eq!(writer.state(), "fallback");
        writer.write_entry(&LogEntry::new(EventType::Error, Severity::Warning));
        writer.flush();

        let contents = fs::read_to_string(&fallback).unwrap();
        assert!(
            !contents.is_empty(),
            "expected at least one JSONL entry in the fallback file"
        );
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
        let writer = open_writer(config);
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
        let mut writer = open_writer(config);

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
            path: uncreatable_path(dir.path(), "primary.jsonl"),
            fallback_path: None,
            max_size_bytes: 1024 * 1024,
            max_rotated_files: 3,
            fsync_interval_secs: 60,
        };
        let mut writer = open_writer(config);

        assert_ne!(writer.state(), "normal");

        writer.config.path = recovery_path.clone();
        writer.last_recover_attempt = UNIX_EPOCH;

        writer.write_entry(&LogEntry::new(EventType::ScanComplete, Severity::Info));
        writer.flush();

        assert_eq!(writer.state(), "normal");
        assert!(recovery_path.exists());
    }

    // ──────── failure-injection tests ────────

    #[test]
    fn full_degradation_chain_primary_to_discard() {
        // Inject: primary bad, no fallback.
        // Expect: degrades through stderr to discard without panic.
        let dir = tempfile::tempdir().unwrap();
        let config = JsonlConfig {
            path: uncreatable_path(dir.path(), "bad.jsonl"),
            fallback_path: None,
            max_size_bytes: 1024 * 1024,
            max_rotated_files: 3,
            fsync_interval_secs: 60,
        };
        let mut writer = open_writer(config);

        // With no fallback configured, should go straight to stderr.
        assert_eq!(writer.state(), "stderr");

        // Writing should not panic even in stderr mode.
        writer.write_entry(&LogEntry::new(EventType::Error, Severity::Critical));
        writer.flush();

        // State remains stderr (no further degradation from successful stderr write).
        assert_eq!(writer.state(), "stderr");
    }

    #[test]
    fn fallback_to_stderr_when_both_paths_fail() {
        // Inject: both primary and fallback paths are non-creatable.
        // Expect: degrades to stderr.
        let dir = tempfile::tempdir().unwrap();
        let config = JsonlConfig {
            path: uncreatable_path(dir.path(), "primary/log.jsonl"),
            fallback_path: Some(uncreatable_path(dir.path(), "fallback/log.jsonl")),
            max_size_bytes: 1024 * 1024,
            max_rotated_files: 3,
            fsync_interval_secs: 60,
        };
        let mut writer = open_writer(config);
        assert_eq!(writer.state(), "stderr");

        // Events written to stderr don't accumulate bytes_written.
        writer.write_entry(&LogEntry::new(EventType::DaemonStart, Severity::Info));
        assert_eq!(writer.bytes_written(), 0);
    }

    #[test]
    fn recovery_from_fallback_to_primary() {
        // Step 1: Start with bad primary → goes to fallback.
        let dir = tempfile::tempdir().unwrap();
        let primary_path = dir.path().join("primary.jsonl");
        let fallback_path = dir.path().join("fallback.jsonl");

        // Intentionally make primary directory non-creatable at first.
        let config = JsonlConfig {
            path: uncreatable_path(dir.path(), "primary.jsonl"),
            fallback_path: Some(fallback_path.clone()),
            max_size_bytes: 1024 * 1024,
            max_rotated_files: 3,
            fsync_interval_secs: 60,
        };
        let mut writer = open_writer(config);
        assert_eq!(writer.state(), "fallback");

        // Write an event to fallback.
        writer.write_entry(&LogEntry::new(EventType::Error, Severity::Warning));
        writer.flush();
        assert!(fallback_path.exists());

        // Step 2: "Fix" the primary path and trigger recovery.
        writer.config.path = primary_path.clone();
        writer.last_recover_attempt = UNIX_EPOCH; // Force recovery attempt.
        writer.write_entry(&LogEntry::new(EventType::ScanComplete, Severity::Info));
        writer.flush();

        // Should have recovered to primary.
        assert_eq!(writer.state(), "normal");
        assert!(primary_path.exists());
    }

    #[test]
    fn recovery_from_stderr_to_primary() {
        // Start in stderr state (no creatable paths).
        let dir = tempfile::tempdir().unwrap();
        let primary_path = dir.path().join("recovered_from_stderr.jsonl");

        let config = JsonlConfig {
            path: uncreatable_path(dir.path(), "bad.jsonl"),
            fallback_path: None,
            max_size_bytes: 1024 * 1024,
            max_rotated_files: 3,
            fsync_interval_secs: 60,
        };
        let mut writer = open_writer(config);
        assert_eq!(writer.state(), "stderr");

        // "Fix" the primary path and trigger recovery.
        writer.config.path = primary_path.clone();
        writer.last_recover_attempt = UNIX_EPOCH;

        writer.write_entry(&LogEntry::new(EventType::DaemonStart, Severity::Info));
        writer.flush();

        assert_eq!(writer.state(), "normal");
        assert!(primary_path.exists());
        let contents = fs::read_to_string(&primary_path).unwrap();
        assert!(contents.contains("daemon_start"));
    }

    #[test]
    fn recovery_from_stderr_to_fallback_when_primary_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let fallback_path = dir.path().join("recovered_fallback.jsonl");

        let config = JsonlConfig {
            path: uncreatable_path(dir.path(), "primary.jsonl"),
            fallback_path: Some(uncreatable_path(dir.path(), "fallback.jsonl")),
            max_size_bytes: 1024 * 1024,
            max_rotated_files: 3,
            fsync_interval_secs: 60,
        };
        let mut writer = open_writer(config);
        assert_eq!(writer.state(), "stderr");

        // Keep primary unavailable, but make fallback available.
        writer.config.fallback_path = Some(fallback_path.clone());
        writer.last_recover_attempt = UNIX_EPOCH;

        writer.write_entry(&LogEntry::new(EventType::Error, Severity::Warning));
        writer.flush();

        assert_eq!(writer.state(), "fallback");
        assert!(fallback_path.exists());
    }

    #[test]
    fn rotation_preserves_data_across_files() {
        // Inject: tiny max_size to force multiple rotations.
        // Verify: data exists in rotated files, no data loss.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rotation_test.jsonl");
        let config = JsonlConfig {
            path: path.clone(),
            fallback_path: None,
            max_size_bytes: 200, // ~1-2 entries before rotation
            max_rotated_files: 5,
            fsync_interval_secs: 60,
        };
        let mut writer = open_writer(config);

        // Write enough entries to trigger several rotations.
        for _ in 0..20 {
            writer.write_entry(&LogEntry::new(EventType::PressureChange, Severity::Info));
        }
        writer.flush();

        // Primary should exist.
        assert!(path.exists(), "primary log file must exist after rotation");

        // Count total lines across all rotation files.
        let mut total_lines = 0;
        let primary_content = fs::read_to_string(&path).unwrap_or_default();
        total_lines += primary_content.lines().count();

        for i in 1..=5 {
            let rotated = rotated_name(&path, i);
            if rotated.exists() {
                let content = fs::read_to_string(&rotated).unwrap_or_default();
                total_lines += content.lines().count();
            }
        }

        // We wrote 20 entries but oldest rotations may be deleted (max 5 rotated files).
        // Must have retained a reasonable number.
        assert!(
            total_lines >= 10,
            "expected at least 10 lines across rotation files, got {total_lines}"
        );
    }

    #[test]
    fn rotation_happens_without_backoff_delay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rapid_rotation.jsonl");
        let config = JsonlConfig {
            path: path.clone(),
            fallback_path: None,
            max_size_bytes: 180,
            max_rotated_files: 4,
            fsync_interval_secs: 60,
        };
        let mut writer = open_writer(config);

        for _ in 0..30 {
            writer.write_entry(&LogEntry::new(EventType::PressureChange, Severity::Info));
        }
        writer.flush();

        assert!(rotated_name(&path, 1).exists());
        assert!(
            rotated_name(&path, 2).exists(),
            "expected back-to-back rotations to create .2 quickly"
        );
    }

    #[test]
    fn bytes_written_tracks_accurately() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tracking.jsonl");
        let config = JsonlConfig {
            path: path.clone(),
            fallback_path: None,
            max_size_bytes: 10 * 1024 * 1024,
            max_rotated_files: 3,
            fsync_interval_secs: 60,
        };
        let mut writer = open_writer(config);
        assert_eq!(writer.bytes_written(), 0);

        writer.write_entry(&LogEntry::new(EventType::DaemonStart, Severity::Info));
        writer.flush();

        let actual_size = fs::metadata(&path).unwrap().len();
        assert_eq!(
            writer.bytes_written(),
            actual_size,
            "tracked bytes must match actual file size"
        );
    }

    #[test]
    fn all_event_types_serialize_to_valid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("all_events.jsonl");
        let config = JsonlConfig {
            path: path.clone(),
            fallback_path: None,
            max_size_bytes: 10 * 1024 * 1024,
            max_rotated_files: 3,
            fsync_interval_secs: 60,
        };
        let mut writer = open_writer(config);

        let event_types = [
            EventType::ArtifactDelete,
            EventType::BallastRelease,
            EventType::BallastReplenish,
            EventType::BallastProvision,
            EventType::PressureChange,
            EventType::ScanComplete,
            EventType::DaemonStart,
            EventType::DaemonStop,
            EventType::ConfigReload,
            EventType::Info,
            EventType::Error,
            EventType::Emergency,
            EventType::Decision,
        ];

        for et in &event_types {
            writer.write_entry(&LogEntry::new(et.clone(), Severity::Info));
        }
        writer.flush();

        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), event_types.len());

        // Every line must be valid JSON.
        for (i, line) in lines.iter().enumerate() {
            let parsed: std::result::Result<serde_json::Value, _> = serde_json::from_str(line);
            assert!(parsed.is_ok(), "line {i} failed to parse as JSON: {line}");
        }
    }

    fn guarded_config(dir: &Path, primary_available: bool) -> JsonlConfig {
        JsonlConfig {
            path: if primary_available {
                dir.join("primary.jsonl")
            } else {
                uncreatable_path(dir, "primary.jsonl")
            },
            fallback_path: Some(dir.join("fallback.jsonl")),
            max_size_bytes: u64::MAX,
            max_rotated_files: 1,
            fsync_interval_secs: 3600,
        }
    }

    #[test]
    fn refused_fallback_is_not_created_by_open_or_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let fallback = dir.path().join("fallback.jsonl");
        let mut writer = JsonlWriter::open_with_destination_check(
            guarded_config(dir.path(), false),
            refuse_destination,
        );
        assert_eq!(writer.state(), "stderr");
        assert!(!fallback.exists());
        writer.try_recover();
        writer.write_line("{\"refused\":true}\n");
        writer.flush();
        assert_eq!(writer.state(), "stderr");
        assert!(!fallback.exists());

        writer.destination_check = allow_destination;
        writer.try_recover();
        writer.write_line("{\"recovered\":true}\n");
        writer.flush();
        assert_eq!(writer.state(), "fallback");
        assert_eq!(
            fs::read_to_string(fallback).unwrap(),
            "{\"recovered\":true}\n"
        );
    }

    static COUNTED_CHECKS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn counted_allow(_: &Path) -> Option<String> {
        COUNTED_CHECKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        None
    }

    /// A healthy RAM-route verdict stands for `destination_recheck`, so a
    /// line on the RAM route does not re-read meminfo and statvfs; once the
    /// verdict lapses a refusal still acts on the next line (bd-sz85).
    #[test]
    fn a_healthy_ram_route_is_not_rechecked_on_every_line() {
        let dir = tempfile::tempdir().unwrap();
        let mut writer = JsonlWriter::open_with_destination_check(
            guarded_config(dir.path(), false),
            counted_allow,
        );
        writer.destination_recheck = Duration::from_secs(3600);
        assert_eq!(writer.state(), "fallback");
        let before = COUNTED_CHECKS.load(std::sync::atomic::Ordering::Relaxed);
        for index in 0..50 {
            writer.write_line(&format!("{{\"line\":{index}}}\n"));
        }
        let checks = COUNTED_CHECKS.load(std::sync::atomic::Ordering::Relaxed) - before;
        assert_eq!(checks, 1, "one check for 50 lines");
        writer.destination_check = refuse_destination;
        writer.destination_ok_at = None;
        writer.write_line("{\"refused\":true}\n");
        assert_eq!(writer.state(), "stderr");
    }

    #[test]
    fn fallback_refusal_does_not_block_primary_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let mut writer = JsonlWriter::open_with_destination_check(
            guarded_config(dir.path(), false),
            refuse_destination,
        );
        let primary = dir.path().join("primary.jsonl");
        writer.config.path = primary.clone();
        writer.try_recover();
        writer.write_line("{\"primary\":true}\n");
        writer.flush();
        assert_eq!(writer.state(), "normal");
        assert_eq!(fs::read_to_string(primary).unwrap(), "{\"primary\":true}\n");
        assert!(!dir.path().join("fallback.jsonl").exists());
    }

    #[test]
    fn pressure_after_buffering_never_flushes_fallback_on_any_exit_path() {
        for operation in ["write", "flush", "fsync", "tick", "recover", "drop"] {
            let dir = tempfile::tempdir().unwrap();
            let fallback = dir.path().join("fallback.jsonl");
            let mut writer = open_writer(guarded_config(dir.path(), false));
            writer.write_line("{\"buffered\":true}\n");
            assert_eq!(fs::metadata(&fallback).unwrap().len(), 0);
            writer.destination_check = refuse_destination;
            match operation {
                "write" => writer.write_line("{\"refused\":true}\n"),
                "flush" => writer.flush(),
                "fsync" => writer.fsync(),
                "tick" => writer.tick(SystemTime::now() + Duration::from_secs(7200)),
                "recover" => writer.try_recover(),
                "drop" => {}
                _ => unreachable!(),
            }
            if operation != "drop" {
                assert_eq!(writer.state(), "stderr", "{operation}");
                assert_eq!(writer.bytes_written(), 0, "{operation}");
            }
            drop(writer);
            assert_eq!(fs::metadata(fallback).unwrap().len(), 0, "{operation}");
        }
    }

    #[test]
    fn pressured_mirror_stops_without_losing_primary_and_can_be_reenabled() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("primary.jsonl");
        let fallback = dir.path().join("fallback.jsonl");
        let mut writer = open_writer(guarded_config(dir.path(), true));
        writer.set_mirror(true);
        writer.write_line("{\"before\":true}\n");
        assert!(writer.mirroring());
        assert_eq!(fs::metadata(&fallback).unwrap().len(), 0);
        writer.destination_check = refuse_destination;
        writer.write_line("{\"during\":true}\n");
        writer.set_mirror(true);
        writer.flush();
        assert!(!writer.mirroring());
        assert_eq!(writer.state(), "normal");
        assert_eq!(fs::metadata(&fallback).unwrap().len(), 0);
        assert_eq!(fs::read_to_string(&primary).unwrap().lines().count(), 2);

        writer.destination_check = allow_destination;
        writer.set_mirror(true);
        writer.write_line("{\"after\":true}\n");
        writer.flush();
        assert_eq!(fs::read_to_string(fallback).unwrap(), "{\"after\":true}\n");
        assert_eq!(fs::read_to_string(primary).unwrap().lines().count(), 3);
    }

    #[test]
    fn stopping_or_dropping_a_pressured_mirror_does_not_flush_it() {
        for stop_explicitly in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let mut writer = open_writer(guarded_config(dir.path(), true));
            writer.set_mirror(true);
            writer.write_line("{\"primary_only\":true}\n");
            writer.destination_check = refuse_destination;
            if stop_explicitly {
                writer.set_mirror(false);
            }
            drop(writer);
            assert_eq!(
                fs::metadata(dir.path().join("fallback.jsonl"))
                    .unwrap()
                    .len(),
                0
            );
            assert_eq!(
                fs::read_to_string(dir.path().join("primary.jsonl")).unwrap(),
                "{\"primary_only\":true}\n"
            );
        }
    }

    #[test]
    fn fallback_recovery_preserves_buffered_byte_accounting() {
        let dir = tempfile::tempdir().unwrap();
        let mut writer = open_writer(guarded_config(dir.path(), false));
        writer.write_line("{\"buffered\":true}\n");
        let bytes = writer.bytes_written();
        assert!(bytes > 0);
        assert_eq!(
            fs::metadata(dir.path().join("fallback.jsonl"))
                .unwrap()
                .len(),
            0
        );
        writer.try_recover();
        assert_eq!(writer.bytes_written(), bytes);
        writer.flush();
        assert_eq!(
            fs::metadata(dir.path().join("fallback.jsonl"))
                .unwrap()
                .len(),
            bytes
        );
    }

    #[test]
    fn oversized_mirror_line_cannot_bypass_the_cap_on_an_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut writer = open_writer(guarded_config(dir.path(), true));
        writer.set_mirror(true);
        let line = "x".repeat(usize::try_from(FALLBACK_MAX_BYTES).unwrap() + 1);
        writer.write_line(&line);
        writer.flush();
        assert_eq!(
            fs::metadata(dir.path().join("fallback.jsonl"))
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            fs::metadata(dir.path().join("primary.jsonl"))
                .unwrap()
                .len(),
            line.len() as u64
        );
        writer.write_line("\n{\"small\":true}\n");
        writer.flush();
        assert_eq!(
            fs::read_to_string(dir.path().join("fallback.jsonl")).unwrap(),
            "\n{\"small\":true}\n"
        );
    }

    #[test]
    fn mirror_truncation_failure_stops_the_mirror_instead_of_appending() {
        let dir = tempfile::tempdir().unwrap();
        let fallback = dir.path().join("fallback.jsonl");
        fs::write(&fallback, "existing\n").unwrap();
        let mut writer = open_writer(guarded_config(dir.path(), true));
        // A real read-only descriptor makes truncation fail even under root.
        writer.mirror = Some(BufWriter::new(File::open(&fallback).unwrap()));
        writer.mirror_bytes = FALLBACK_MAX_BYTES;
        writer.write_line("{\"primary\":true}\n");
        writer.flush();
        assert!(!writer.mirroring());
        assert_eq!(writer.state(), "normal");
        assert_eq!(fs::read_to_string(fallback).unwrap(), "existing\n");
        assert_eq!(
            fs::read_to_string(dir.path().join("primary.jsonl")).unwrap(),
            "{\"primary\":true}\n"
        );
    }

    #[test]
    fn rotation_failure_applies_the_cap_to_the_new_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let fallback = dir.path().join("fallback.jsonl");
        File::create(&fallback)
            .unwrap()
            .set_len(FALLBACK_MAX_BYTES)
            .unwrap();
        let mut writer = open_writer(guarded_config(dir.path(), true));
        writer.config.path = uncreatable_path(dir.path(), "rotating.jsonl");
        writer.config.max_size_bytes = 1;
        writer.bytes_written = 1;
        let line = "{\"after_rotation\":true}\n";
        writer.write_line(line);
        writer.flush();
        assert_eq!(writer.state(), "fallback");
        assert_eq!(fs::read_to_string(&fallback).unwrap(), line);
        assert_eq!(writer.bytes_written(), line.len() as u64);
        assert!(!rotated_name(&fallback, 1).exists());
    }

    #[test]
    fn primary_failure_hands_over_mirror_without_duplicate_records() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("primary.jsonl");
        let fallback = dir.path().join("fallback.jsonl");
        let mut writer = open_writer(guarded_config(dir.path(), true));
        writer.set_mirror(true);
        let before = "{\"before\":true}\n";
        writer.write_line(before);
        // Replacing this handle flushes the healthy primary's earlier line.
        // The next large write fails on a real read-only descriptor.
        writer.writer = Some(BufWriter::new(File::open(&primary).unwrap()));
        writer.last_recover_attempt = SystemTime::now();
        let failed_line = format!("{{\"payload\":\"{}\"}}\n", "x".repeat(65_536));
        writer.write_line(&failed_line);
        writer.flush();
        assert_eq!(writer.state(), "fallback");
        assert!(!writer.mirroring());
        assert_eq!(fs::read_to_string(primary).unwrap(), before);
        assert_eq!(
            fs::read_to_string(&fallback).unwrap(),
            format!("{before}{failed_line}")
        );
        assert_eq!(
            writer.bytes_written(),
            fs::metadata(fallback).unwrap().len()
        );
    }

    #[test]
    fn fallback_failure_during_pressure_transition_does_not_skip_stderr() {
        let dir = tempfile::tempdir().unwrap();
        let mut writer = open_writer(guarded_config(dir.path(), false));
        writer.write_line("{\"pending\":true}\n");
        writer.destination_check = refuse_destination;
        writer.degrade();
        assert_eq!(writer.state(), "stderr");
        drop(writer);
        assert_eq!(
            fs::metadata(dir.path().join("fallback.jsonl"))
                .unwrap()
                .len(),
            0
        );
    }
}
