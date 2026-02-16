//! Telemetry hook scaffolding and read-only query adapters for TUI panes.
//!
//! Two complementary concerns live here:
//!
//! 1. **Recording** (`TelemetrySample`, `TelemetryHook`) — ingesting runtime
//!    instrumentation events. These are used by the runtime for internal metrics.
//!
//! 2. **Querying** (`TelemetryQueryAdapter` and implementations) — read-only
//!    adapters that surface activity events, decision evidence, and pressure
//!    history from the existing logger backends (SQLite + JSONL). These feed the
//!    timeline (S2) and explainability (S3) dashboard screens.
//!
//! **Design contract (bd-xzt.2.4):**
//! - No changes to critical logging write paths.
//! - Read-only SQLite connections (separate from the logger thread).
//! - Graceful degradation: each query returns [`TelemetryResult`] with partial
//!   data and health indicators.
//! - Adapter errors never propagate up as panics; callers always get a usable
//!   (possibly empty) result plus diagnostics.

#![allow(missing_docs)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

// ──────────────────── recording (existing scaffold) ────────────────────

/// Minimal telemetry sample used by early runtime instrumentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetrySample {
    pub source: String,
    pub kind: String,
    pub detail: String,
}

impl TelemetrySample {
    #[must_use]
    pub fn new(
        source: impl Into<String>,
        kind: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            source: source.into(),
            kind: kind.into(),
            detail: detail.into(),
        }
    }
}

/// Hook point for ingesting runtime telemetry events.
pub trait TelemetryHook {
    fn record(&mut self, sample: TelemetrySample);
}

/// No-op telemetry hook used in scaffold mode.
#[derive(Debug, Default)]
pub struct NullTelemetryHook;

impl TelemetryHook for NullTelemetryHook {
    fn record(&mut self, _sample: TelemetrySample) {}
}

// ──────────────────── typed views for TUI screens ────────────────────

/// A single event in the timeline view (S2).
///
/// Provides a stable, screen-friendly projection of data that may originate
/// from either SQLite (`ActivityRow`) or JSONL (`LogEntry`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineEvent {
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Canonical event type (e.g. "artifact_delete", "pressure_change").
    pub event_type: String,
    /// Severity: info, warning, critical.
    pub severity: String,
    /// Affected path, if applicable.
    pub path: Option<String>,
    /// Size in bytes, if applicable.
    pub size_bytes: Option<u64>,
    /// Candidacy score, if applicable.
    pub score: Option<f64>,
    /// Pressure level at event time.
    pub pressure_level: Option<String>,
    /// Free-space percentage at event time.
    pub free_pct: Option<f64>,
    /// Whether the action succeeded (None for non-action events).
    pub success: Option<bool>,
    /// Error code if the action failed.
    pub error_code: Option<String>,
    /// Human-readable error message.
    pub error_message: Option<String>,
    /// Duration of the action in milliseconds.
    pub duration_ms: Option<u64>,
    /// Freeform details.
    pub details: Option<String>,
}

/// Evidence payload for the explainability screen (S3).
///
/// This is a read-friendly projection of `DecisionRecord` fields. The full
/// `DecisionRecord` is available via JSON roundtrip in the `raw_json` field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionEvidence {
    /// Monotonic decision identifier.
    pub decision_id: u64,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Candidate artifact path.
    pub path: String,
    /// Size of the candidate in bytes.
    pub size_bytes: u64,
    /// Age in seconds at decision time.
    pub age_secs: u64,
    /// The selected action (keep, delete, review).
    pub action: String,
    /// The effective action after policy enforcement.
    pub effective_action: Option<String>,
    /// Policy mode (live, shadow, canary, dry-run).
    pub policy_mode: String,
    /// Individual factor scores.
    pub factors: FactorBreakdown,
    /// Total weighted score.
    pub total_score: f64,
    /// Bayesian posterior P(abandoned).
    pub posterior_abandoned: f64,
    /// Expected loss of keeping.
    pub expected_loss_keep: f64,
    /// Expected loss of deleting.
    pub expected_loss_delete: f64,
    /// Calibration quality.
    pub calibration_score: f64,
    /// Whether a hard veto was applied.
    pub vetoed: bool,
    /// Veto reason.
    pub veto_reason: Option<String>,
    /// Guard status summary.
    pub guard_status: Option<String>,
    /// Human-readable summary.
    pub summary: String,
    /// Full serialized record for L3 explain.
    pub raw_json: Option<String>,
}

/// Individual factor scores for the explainability breakdown.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FactorBreakdown {
    pub location: f64,
    pub name: f64,
    pub age: f64,
    pub size: f64,
    pub structure: f64,
    pub pressure_multiplier: f64,
}

/// A single pressure sample for time-series rendering.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PressurePoint {
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Mount point path.
    pub mount_point: String,
    /// Free-space percentage.
    pub free_pct: f64,
    /// Pressure level label.
    pub pressure_level: String,
    /// EWMA consumption rate (bytes/sec).
    pub ewma_rate: Option<f64>,
    /// PID controller output.
    pub pid_output: Option<f64>,
}

// ──────────────────── severity filter ────────────────────

/// Filter for timeline event queries.
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    /// Only return events matching these severity levels.
    pub severities: Vec<String>,
    /// Only return events matching these event types.
    pub event_types: Vec<String>,
}

impl EventFilter {
    /// Returns `true` when the filter is empty (matches everything).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.severities.is_empty() && self.event_types.is_empty()
    }

    /// Check if an event matches the filter. Empty filter matches everything.
    #[must_use]
    pub fn matches(&self, severity: &str, event_type: &str) -> bool {
        let severity_ok =
            self.severities.is_empty() || self.severities.iter().any(|s| s == severity);
        let event_ok =
            self.event_types.is_empty() || self.event_types.iter().any(|e| e == event_type);
        severity_ok && event_ok
    }
}

// ──────────────────── health / result types ────────────────────

/// Health status of a telemetry backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendHealth {
    /// Backend is available and responding.
    Available,
    /// Backend is degraded (responding slowly or with partial data).
    Degraded,
    /// Backend is unavailable.
    Unavailable,
}

/// Aggregate health of the telemetry adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryHealth {
    pub sqlite: BackendHealth,
    pub jsonl: BackendHealth,
    /// Human-readable diagnostics message (empty when healthy).
    pub diagnostics: String,
}

impl TelemetryHealth {
    /// All backends are available.
    #[must_use]
    pub fn healthy() -> Self {
        Self {
            sqlite: BackendHealth::Available,
            jsonl: BackendHealth::Available,
            diagnostics: String::new(),
        }
    }

    /// Whether at least one backend is available.
    #[must_use]
    pub fn any_available(&self) -> bool {
        self.sqlite == BackendHealth::Available || self.jsonl == BackendHealth::Available
    }
}

/// Result wrapper that includes partial-data indicators alongside the payload.
///
/// Callers should check `source` and `partial` to decide how to render the
/// data and whether to show degradation indicators in the UI.
#[derive(Debug, Clone)]
pub struct TelemetryResult<T> {
    /// The payload (possibly empty or partial).
    pub data: T,
    /// Which backend sourced this data.
    pub source: DataSource,
    /// Whether the result is known to be incomplete.
    pub partial: bool,
    /// Diagnostic message for the UI (empty when fully healthy).
    pub diagnostics: String,
}

impl<T: Default> TelemetryResult<T> {
    /// An empty result indicating no backend was available.
    #[must_use]
    pub fn unavailable(diagnostics: String) -> Self {
        Self {
            data: T::default(),
            source: DataSource::None,
            partial: true,
            diagnostics,
        }
    }
}

/// Which backend sourced a query result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataSource {
    /// Data came from SQLite.
    Sqlite,
    /// Data came from JSONL fallback.
    Jsonl,
    /// No backend available.
    None,
}

// ──────────────────── adapter trait ────────────────────

/// Read-only query interface for telemetry data.
///
/// Implementations open their own connections/handles, separate from the
/// logger thread's write path. All methods return [`TelemetryResult`] with
/// graceful degradation — callers always get a usable response.
pub trait TelemetryQueryAdapter {
    /// Query recent activity events for the timeline screen.
    fn recent_events(
        &self,
        limit: usize,
        filter: &EventFilter,
    ) -> TelemetryResult<Vec<TimelineEvent>>;

    /// Query decision evidence for the explainability screen.
    fn recent_decisions(&self, limit: usize) -> TelemetryResult<Vec<DecisionEvidence>>;

    /// Query pressure history for a mount point.
    fn pressure_history(
        &self,
        mount: &str,
        since: &str,
        limit: usize,
    ) -> TelemetryResult<Vec<PressurePoint>>;

    /// Report the health of underlying backends.
    fn health(&self) -> TelemetryHealth;
}

// ──────────────────── null adapter (scaffold) ────────────────────

/// No-op adapter for use when telemetry backends aren't configured.
#[derive(Debug, Default)]
pub struct NullTelemetryAdapter;

impl TelemetryQueryAdapter for NullTelemetryAdapter {
    fn recent_events(
        &self,
        _limit: usize,
        _filter: &EventFilter,
    ) -> TelemetryResult<Vec<TimelineEvent>> {
        TelemetryResult::unavailable("telemetry not configured".to_string())
    }

    fn recent_decisions(&self, _limit: usize) -> TelemetryResult<Vec<DecisionEvidence>> {
        TelemetryResult::unavailable("telemetry not configured".to_string())
    }

    fn pressure_history(
        &self,
        _mount: &str,
        _since: &str,
        _limit: usize,
    ) -> TelemetryResult<Vec<PressurePoint>> {
        TelemetryResult::unavailable("telemetry not configured".to_string())
    }

    fn health(&self) -> TelemetryHealth {
        TelemetryHealth {
            sqlite: BackendHealth::Unavailable,
            jsonl: BackendHealth::Unavailable,
            diagnostics: "telemetry not configured".to_string(),
        }
    }
}

// ──────────────────── SQLite adapter ────────────────────

/// Read-only telemetry adapter backed by the existing SQLite activity database.
///
/// Opens a **separate read-only connection** to the same database file used
/// by the logger thread. WAL mode supports concurrent readers, so this never
/// interferes with the write path.
#[cfg(feature = "sqlite")]
pub struct SqliteTelemetryAdapter {
    conn: rusqlite::Connection,
    _path: PathBuf,
}

#[cfg(feature = "sqlite")]
impl SqliteTelemetryAdapter {
    /// Open a read-only connection to the SQLite activity database.
    ///
    /// Returns `None` if the file doesn't exist or can't be opened.
    pub fn open(path: &Path) -> Option<Self> {
        if !path.exists() {
            return None;
        }
        let conn = rusqlite::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .ok()?;
        // Enable WAL read mode and mmap for read performance.
        let _ = conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA mmap_size=67108864;");
        Some(Self {
            conn,
            _path: path.to_path_buf(),
        })
    }

    fn query_recent_activity(
        &self,
        limit: usize,
        filter: &EventFilter,
    ) -> std::result::Result<Vec<TimelineEvent>, rusqlite::Error> {
        use std::fmt::Write as _;

        // Build query with optional filters.
        let mut sql = String::from(
            "SELECT timestamp, event_type, severity, path, size_bytes, score,
                    score_factors, pressure_level, free_pct, duration_ms,
                    success, error_code, error_message, details
             FROM activity_log",
        );

        let mut conditions = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if !filter.severities.is_empty() {
            let placeholders: Vec<String> = filter
                .severities
                .iter()
                .enumerate()
                .map(|(i, _)| format!("?{}", params.len() + i + 1))
                .collect();
            conditions.push(format!("severity IN ({})", placeholders.join(",")));
            for s in &filter.severities {
                params.push(Box::new(s.clone()));
            }
        }

        if !filter.event_types.is_empty() {
            let placeholders: Vec<String> = filter
                .event_types
                .iter()
                .enumerate()
                .map(|(i, _)| format!("?{}", params.len() + i + 1))
                .collect();
            conditions.push(format!("event_type IN ({})", placeholders.join(",")));
            for e in &filter.event_types {
                params.push(Box::new(e.clone()));
            }
        }

        if !conditions.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&conditions.join(" AND "));
        }

        write!(sql, " ORDER BY id DESC LIMIT ?{}", params.len() + 1).unwrap();
        #[allow(clippy::cast_possible_wrap)]
        params.push(Box::new(limit as i64));

        let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| &**p).collect();

        let mut stmt = self.conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(param_refs.as_slice(), |row| {
            let success_int: i32 = row.get(10)?;
            let size_i64: Option<i64> = row.get(4)?;
            let duration_i64: Option<i64> = row.get(9)?;
            Ok(TimelineEvent {
                timestamp: row.get(0)?,
                event_type: row.get(1)?,
                severity: row.get(2)?,
                path: row.get(3)?,
                size_bytes: size_i64.map(|v| v.max(0).cast_unsigned()),
                score: row.get(5)?,
                pressure_level: row.get(7)?,
                free_pct: row.get(8)?,
                success: Some(success_int != 0),
                error_code: row.get(11)?,
                error_message: row.get(12)?,
                duration_ms: duration_i64.map(|v| v.max(0).cast_unsigned()),
                details: row.get(13)?,
            })
        })?;

        rows.collect()
    }

    fn query_pressure_history(
        &self,
        mount: &str,
        since: &str,
        limit: usize,
    ) -> std::result::Result<Vec<PressurePoint>, rusqlite::Error> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT timestamp, mount_point, free_pct, pressure_level, ewma_rate, pid_output
             FROM pressure_history
             WHERE mount_point = ?1 AND timestamp >= ?2
             ORDER BY id DESC LIMIT ?3",
        )?;

        #[allow(clippy::cast_possible_wrap)]
        let limit_i64 = limit as i64;
        let rows = stmt.query_map(rusqlite::params![mount, since, limit_i64], |row| {
            Ok(PressurePoint {
                timestamp: row.get(0)?,
                mount_point: row.get(1)?,
                free_pct: row.get(2)?,
                pressure_level: row.get(3)?,
                ewma_rate: row.get(4)?,
                pid_output: row.get(5)?,
            })
        })?;

        rows.collect()
    }
}

#[cfg(feature = "sqlite")]
impl TelemetryQueryAdapter for SqliteTelemetryAdapter {
    fn recent_events(
        &self,
        limit: usize,
        filter: &EventFilter,
    ) -> TelemetryResult<Vec<TimelineEvent>> {
        match self.query_recent_activity(limit, filter) {
            Ok(events) => TelemetryResult {
                data: events,
                source: DataSource::Sqlite,
                partial: false,
                diagnostics: String::new(),
            },
            Err(e) => TelemetryResult {
                data: Vec::new(),
                source: DataSource::Sqlite,
                partial: true,
                diagnostics: format!("SQLite query failed: {e}"),
            },
        }
    }

    fn recent_decisions(&self, limit: usize) -> TelemetryResult<Vec<DecisionEvidence>> {
        // Decision records are stored in the activity_log as event_type="artifact_delete"
        // or "artifact_skip" with score_factors JSON. We extract what we can.
        let filter = EventFilter {
            severities: Vec::new(),
            event_types: vec!["artifact_delete".to_string()],
        };
        match self.query_recent_activity(limit, &filter) {
            Ok(events) => {
                let evidence: Vec<DecisionEvidence> = events
                    .into_iter()
                    .enumerate()
                    .map(|(i, ev)| timeline_to_evidence(i as u64, &ev))
                    .collect();
                TelemetryResult {
                    data: evidence,
                    source: DataSource::Sqlite,
                    partial: false,
                    diagnostics: String::new(),
                }
            }
            Err(e) => TelemetryResult {
                data: Vec::new(),
                source: DataSource::Sqlite,
                partial: true,
                diagnostics: format!("SQLite decision query failed: {e}"),
            },
        }
    }

    fn pressure_history(
        &self,
        mount: &str,
        since: &str,
        limit: usize,
    ) -> TelemetryResult<Vec<PressurePoint>> {
        match self.query_pressure_history(mount, since, limit) {
            Ok(points) => TelemetryResult {
                data: points,
                source: DataSource::Sqlite,
                partial: false,
                diagnostics: String::new(),
            },
            Err(e) => TelemetryResult {
                data: Vec::new(),
                source: DataSource::Sqlite,
                partial: true,
                diagnostics: format!("SQLite pressure query failed: {e}"),
            },
        }
    }

    fn health(&self) -> TelemetryHealth {
        let sqlite_ok = self
            .conn
            .prepare("SELECT 1")
            .and_then(|mut s| s.query_row([], |_| Ok(())))
            .is_ok();

        TelemetryHealth {
            sqlite: if sqlite_ok {
                BackendHealth::Available
            } else {
                BackendHealth::Degraded
            },
            jsonl: BackendHealth::Unavailable,
            diagnostics: if sqlite_ok {
                String::new()
            } else {
                "SQLite read connection unhealthy".to_string()
            },
        }
    }
}

// ──────────────────── JSONL adapter ────────────────────

/// Read-only telemetry adapter that parses the JSONL activity log.
///
/// Used as a fallback when SQLite is unavailable (disk full, corruption, etc.).
/// Reads the file from the end (tail) for recent events.
pub struct JsonlTelemetryAdapter {
    path: PathBuf,
}

#[derive(Debug)]
enum ParseOutcome {
    Exact(crate::logger::jsonl::LogEntry),
    Recovered(crate::logger::jsonl::LogEntry),
    Dropped,
}

#[derive(Debug, Default)]
struct TailEntries {
    entries: Vec<crate::logger::jsonl::LogEntry>,
    recovered_lines: usize,
    dropped_lines: usize,
}

impl JsonlTelemetryAdapter {
    /// Create a new adapter for the given JSONL log file.
    ///
    /// Returns `None` if the file doesn't exist.
    pub fn open(path: &Path) -> Option<Self> {
        if !path.exists() {
            return None;
        }
        Some(Self {
            path: path.to_path_buf(),
        })
    }

    /// Read the last `n` lines from the JSONL file and parse them.
    fn tail_entries(&self, n: usize) -> TailEntries {
        let Ok(file) = std::fs::File::open(&self.path) else {
            return TailEntries::default();
        };

        let reader = BufReader::new(file);
        let mut all_lines: Vec<String> = Vec::new();
        for line in reader.lines() {
            match line {
                Ok(l) if !l.trim().is_empty() => all_lines.push(l),
                _ => {}
            }
        }

        // Take last n lines.
        let start = all_lines.len().saturating_sub(n);
        let tail = &all_lines[start..];

        let mut entries = Vec::with_capacity(tail.len());
        let mut recovered_lines = 0;
        let mut dropped_lines = 0;
        for line in tail.iter().rev() {
            match parse_jsonl_entry_with_schema_shield(line) {
                ParseOutcome::Exact(entry) => entries.push(entry),
                ParseOutcome::Recovered(entry) => {
                    recovered_lines += 1;
                    entries.push(entry);
                }
                ParseOutcome::Dropped => {
                    dropped_lines += 1;
                }
            }
        }
        TailEntries {
            entries,
            recovered_lines,
            dropped_lines,
        }
    }
}

impl TelemetryQueryAdapter for JsonlTelemetryAdapter {
    fn recent_events(
        &self,
        limit: usize,
        filter: &EventFilter,
    ) -> TelemetryResult<Vec<TimelineEvent>> {
        // Read more than limit to account for filtering.
        let read_count = if filter.is_empty() { limit } else { limit * 4 };
        let entries = self.tail_entries(read_count);
        let diagnostics = schema_shield_diagnostics(entries.recovered_lines, entries.dropped_lines);
        let partial = entries.dropped_lines > 0;

        let events: Vec<TimelineEvent> = entries
            .entries
            .into_iter()
            .filter(|entry| {
                let sev = format!("{:?}", entry.severity).to_lowercase();
                let evt = serde_json::to_string(&entry.event)
                    .unwrap_or_default()
                    .trim_matches('"')
                    .to_string();
                filter.matches(&sev, &evt)
            })
            .take(limit)
            .map(|entry| logentry_to_timeline(&entry))
            .collect();

        TelemetryResult {
            partial,
            source: DataSource::Jsonl,
            diagnostics,
            data: events,
        }
    }

    fn recent_decisions(&self, limit: usize) -> TelemetryResult<Vec<DecisionEvidence>> {
        let entries = self.tail_entries(limit * 4);
        let diagnostics = schema_shield_diagnostics(entries.recovered_lines, entries.dropped_lines);
        let partial = entries.dropped_lines > 0;
        let evidence: Vec<DecisionEvidence> = entries
            .entries
            .into_iter()
            .filter(|e| matches!(e.event, crate::logger::jsonl::EventType::ArtifactDelete))
            .take(limit)
            .enumerate()
            .map(|(i, entry)| {
                let timeline = logentry_to_timeline(&entry);
                timeline_to_evidence(i as u64, &timeline)
            })
            .collect();

        TelemetryResult {
            data: evidence,
            source: DataSource::Jsonl,
            partial,
            diagnostics,
        }
    }

    fn pressure_history(
        &self,
        mount: &str,
        _since: &str,
        limit: usize,
    ) -> TelemetryResult<Vec<PressurePoint>> {
        let entries = self.tail_entries(limit * 4);
        let diagnostics = schema_shield_diagnostics(entries.recovered_lines, entries.dropped_lines);
        let partial = entries.dropped_lines > 0;
        let points: Vec<PressurePoint> = entries
            .entries
            .into_iter()
            .filter(|e| {
                matches!(e.event, crate::logger::jsonl::EventType::PressureChange)
                    && e.mount_point.as_deref() == Some(mount)
            })
            .take(limit)
            .map(|entry| PressurePoint {
                timestamp: entry.ts,
                mount_point: entry.mount_point.unwrap_or_default(),
                free_pct: entry.free_pct.unwrap_or(0.0),
                pressure_level: entry.pressure.unwrap_or_default(),
                ewma_rate: entry.rate_bps,
                pid_output: None,
            })
            .collect();

        TelemetryResult {
            data: points,
            source: DataSource::Jsonl,
            partial,
            diagnostics,
        }
    }

    fn health(&self) -> TelemetryHealth {
        let jsonl_ok = self.path.exists();
        TelemetryHealth {
            sqlite: BackendHealth::Unavailable,
            jsonl: if jsonl_ok {
                BackendHealth::Available
            } else {
                BackendHealth::Unavailable
            },
            diagnostics: if jsonl_ok {
                String::new()
            } else {
                format!("JSONL file not found: {}", self.path.display())
            },
        }
    }
}

// ──────────────────── composite adapter ────────────────────

/// Composite adapter that tries SQLite first, falls back to JSONL.
///
/// This is the default adapter for the TUI runtime. It provides the best
/// available data from whichever backend is healthy.
pub struct CompositeTelemetryAdapter {
    #[cfg(feature = "sqlite")]
    sqlite: Option<SqliteTelemetryAdapter>,
    jsonl: Option<JsonlTelemetryAdapter>,
}

impl CompositeTelemetryAdapter {
    /// Build from configured paths. Tolerant of missing files.
    #[must_use]
    pub fn new(sqlite_path: Option<&Path>, jsonl_path: Option<&Path>) -> Self {
        Self {
            #[cfg(feature = "sqlite")]
            sqlite: sqlite_path.and_then(SqliteTelemetryAdapter::open),
            jsonl: jsonl_path.and_then(JsonlTelemetryAdapter::open),
        }
    }

    #[cfg(feature = "sqlite")]
    #[allow(dead_code)] // Will be used when composite adapter wires to UI panes.
    fn has_sqlite(&self) -> bool {
        self.sqlite.is_some()
    }

    #[cfg(not(feature = "sqlite"))]
    #[allow(dead_code)]
    fn has_sqlite(&self) -> bool {
        false
    }
}

impl TelemetryQueryAdapter for CompositeTelemetryAdapter {
    fn recent_events(
        &self,
        limit: usize,
        filter: &EventFilter,
    ) -> TelemetryResult<Vec<TimelineEvent>> {
        // Try SQLite first.
        #[cfg(feature = "sqlite")]
        if let Some(ref sqlite) = self.sqlite {
            let result = sqlite.recent_events(limit, filter);
            if !result.partial {
                return result;
            }
        }

        // Fall back to JSONL.
        if let Some(ref jsonl) = self.jsonl {
            return jsonl.recent_events(limit, filter);
        }

        TelemetryResult::unavailable("no telemetry backend available".to_string())
    }

    fn recent_decisions(&self, limit: usize) -> TelemetryResult<Vec<DecisionEvidence>> {
        #[cfg(feature = "sqlite")]
        if let Some(ref sqlite) = self.sqlite {
            let result = sqlite.recent_decisions(limit);
            if !result.partial {
                return result;
            }
        }

        if let Some(ref jsonl) = self.jsonl {
            return jsonl.recent_decisions(limit);
        }

        TelemetryResult::unavailable("no telemetry backend available".to_string())
    }

    fn pressure_history(
        &self,
        mount: &str,
        since: &str,
        limit: usize,
    ) -> TelemetryResult<Vec<PressurePoint>> {
        #[cfg(feature = "sqlite")]
        if let Some(ref sqlite) = self.sqlite {
            let result = sqlite.pressure_history(mount, since, limit);
            if !result.partial {
                return result;
            }
        }

        if let Some(ref jsonl) = self.jsonl {
            return jsonl.pressure_history(mount, since, limit);
        }

        TelemetryResult::unavailable("no telemetry backend available".to_string())
    }

    fn health(&self) -> TelemetryHealth {
        let mut health = TelemetryHealth {
            sqlite: BackendHealth::Unavailable,
            jsonl: BackendHealth::Unavailable,
            diagnostics: String::new(),
        };

        #[cfg(feature = "sqlite")]
        if let Some(ref sqlite) = self.sqlite {
            health.sqlite = sqlite.health().sqlite;
        }

        if let Some(ref jsonl) = self.jsonl {
            health.jsonl = jsonl.health().jsonl;
        }

        if !health.any_available() {
            health.diagnostics = "no telemetry backend available".to_string();
        }

        health
    }
}

fn parse_jsonl_entry_with_schema_shield(line: &str) -> ParseOutcome {
    if let Ok(entry) = serde_json::from_str::<crate::logger::jsonl::LogEntry>(line) {
        return ParseOutcome::Exact(entry);
    }

    let Ok(value) = serde_json::from_str::<Value>(line) else {
        return ParseOutcome::Dropped;
    };
    let Some(object) = value.as_object() else {
        return ParseOutcome::Dropped;
    };

    let Some(ts) = read_string_field(object, &["ts", "timestamp", "time"]) else {
        return ParseOutcome::Dropped;
    };

    let raw_event = read_string_field(object, &["event", "event_type", "kind"]);
    let event = raw_event
        .as_deref()
        .and_then(parse_event_type)
        .unwrap_or(crate::logger::jsonl::EventType::Error);
    let severity = read_string_field(object, &["severity", "level"])
        .as_deref()
        .and_then(parse_severity)
        .unwrap_or(crate::logger::jsonl::Severity::Warning);

    let mut details = read_string_field(object, &["details", "summary", "message"]);
    if let Some(raw) = raw_event.filter(|token| parse_event_type(token).is_none()) {
        details = Some(match details {
            Some(existing) => format!("schema-shield unknown-event={raw}; {existing}"),
            None => format!("schema-shield unknown-event={raw}"),
        });
    }

    ParseOutcome::Recovered(crate::logger::jsonl::LogEntry {
        ts,
        event,
        severity,
        path: read_string_field(object, &["path", "target_path"]),
        size: read_u64_field(object, &["size", "size_bytes"]),
        score: read_f64_field(object, &["score", "total_score"]),
        factors: None,
        pressure: read_string_field(object, &["pressure", "pressure_level"]),
        free_pct: read_f64_field(object, &["free_pct", "free_percent"]),
        rate_bps: read_f64_field(object, &["rate_bps", "ewma_rate"]),
        duration_ms: read_u64_field(object, &["duration_ms", "durationMillis"]),
        ok: read_bool_field(object, &["ok", "success"]),
        error_code: read_string_field(object, &["error_code"]),
        error_message: read_string_field(object, &["error_message", "error"]),
        mount_point: read_string_field(object, &["mount_point", "mount"]),
        details,
    })
}

fn schema_shield_diagnostics(recovered: usize, dropped: usize) -> String {
    if recovered == 0 && dropped == 0 {
        return String::new();
    }
    format!("jsonl schema-shield recovered={recovered} dropped={dropped}")
}

fn parse_event_type(input: &str) -> Option<crate::logger::jsonl::EventType> {
    let normalized = normalize_token(input);
    let compact = normalized.replace('_', "");
    match normalized.as_str() {
        "artifact_delete" => Some(crate::logger::jsonl::EventType::ArtifactDelete),
        "ballast_release" => Some(crate::logger::jsonl::EventType::BallastRelease),
        "ballast_replenish" => Some(crate::logger::jsonl::EventType::BallastReplenish),
        "ballast_provision" => Some(crate::logger::jsonl::EventType::BallastProvision),
        "pressure_change" => Some(crate::logger::jsonl::EventType::PressureChange),
        "scan_complete" => Some(crate::logger::jsonl::EventType::ScanComplete),
        "daemon_start" => Some(crate::logger::jsonl::EventType::DaemonStart),
        "daemon_stop" => Some(crate::logger::jsonl::EventType::DaemonStop),
        "config_reload" => Some(crate::logger::jsonl::EventType::ConfigReload),
        "error" => Some(crate::logger::jsonl::EventType::Error),
        "emergency" => Some(crate::logger::jsonl::EventType::Emergency),
        _ => match compact.as_str() {
            "artifactdelete" => Some(crate::logger::jsonl::EventType::ArtifactDelete),
            "ballastrelease" => Some(crate::logger::jsonl::EventType::BallastRelease),
            "ballastreplenish" => Some(crate::logger::jsonl::EventType::BallastReplenish),
            "ballastprovision" => Some(crate::logger::jsonl::EventType::BallastProvision),
            "pressurechange" => Some(crate::logger::jsonl::EventType::PressureChange),
            "scancomplete" => Some(crate::logger::jsonl::EventType::ScanComplete),
            "daemonstart" => Some(crate::logger::jsonl::EventType::DaemonStart),
            "daemonstop" => Some(crate::logger::jsonl::EventType::DaemonStop),
            "configreload" => Some(crate::logger::jsonl::EventType::ConfigReload),
            _ => None,
        },
    }
}

fn parse_severity(input: &str) -> Option<crate::logger::jsonl::Severity> {
    match normalize_token(input).as_str() {
        "info" => Some(crate::logger::jsonl::Severity::Info),
        "warning" | "warn" => Some(crate::logger::jsonl::Severity::Warning),
        "critical" | "error" | "fatal" => Some(crate::logger::jsonl::Severity::Critical),
        _ => None,
    }
}

fn normalize_token(input: &str) -> String {
    input.trim().to_ascii_lowercase().replace(['-', ' '], "_")
}

fn read_value<'a>(object: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| object.get(*key))
}

fn read_string_field(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    read_value(object, keys).and_then(|value| match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    })
}

fn read_u64_field(object: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    read_value(object, keys).and_then(|value| match value {
        Value::Number(number) => number
            .as_u64()
            .or_else(|| {
                number
                    .as_i64()
                    .and_then(|signed| u64::try_from(signed).ok())
            })
            .or_else(|| {
                number.as_f64().and_then(|float| {
                    if float.is_sign_negative() || !float.is_finite() {
                        None
                    } else {
                        Some(float.round() as u64)
                    }
                })
            }),
        Value::String(text) => text.parse::<u64>().ok(),
        _ => None,
    })
}

fn read_f64_field(object: &Map<String, Value>, keys: &[&str]) -> Option<f64> {
    read_value(object, keys).and_then(|value| match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.parse::<f64>().ok(),
        _ => None,
    })
}

fn read_bool_field(object: &Map<String, Value>, keys: &[&str]) -> Option<bool> {
    read_value(object, keys).and_then(|value| match value {
        Value::Bool(flag) => Some(*flag),
        Value::String(text) => match normalize_token(text).as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        },
        _ => None,
    })
}

// ──────────────────── conversion helpers ────────────────────

/// Convert a JSONL `LogEntry` to a `TimelineEvent`.
fn logentry_to_timeline(entry: &crate::logger::jsonl::LogEntry) -> TimelineEvent {
    let severity = match entry.severity {
        crate::logger::jsonl::Severity::Info => "info",
        crate::logger::jsonl::Severity::Warning => "warning",
        crate::logger::jsonl::Severity::Critical => "critical",
    };

    let event_type = serde_json::to_string(&entry.event)
        .unwrap_or_default()
        .trim_matches('"')
        .to_string();

    TimelineEvent {
        timestamp: entry.ts.clone(),
        event_type,
        severity: severity.to_string(),
        path: entry.path.clone(),
        size_bytes: entry.size,
        score: entry.score,
        pressure_level: entry.pressure.clone(),
        free_pct: entry.free_pct,
        success: entry.ok,
        error_code: entry.error_code.clone(),
        error_message: entry.error_message.clone(),
        duration_ms: entry.duration_ms,
        details: entry.details.clone(),
    }
}

/// Synthesize a `DecisionEvidence` from a `TimelineEvent`.
///
/// Full decision records live in a separate ledger; this provides a best-effort
/// projection from the activity log for basic explainability display.
fn timeline_to_evidence(id: u64, ev: &TimelineEvent) -> DecisionEvidence {
    DecisionEvidence {
        decision_id: id,
        timestamp: ev.timestamp.clone(),
        path: ev.path.clone().unwrap_or_default(),
        size_bytes: ev.size_bytes.unwrap_or(0),
        age_secs: 0, // Not available in activity log.
        action: if ev.success == Some(true) {
            "delete".to_string()
        } else {
            "keep".to_string()
        },
        effective_action: None,
        policy_mode: "live".to_string(),
        factors: FactorBreakdown {
            location: 0.0,
            name: 0.0,
            age: 0.0,
            size: 0.0,
            structure: 0.0,
            pressure_multiplier: 1.0,
        },
        total_score: ev.score.unwrap_or(0.0),
        posterior_abandoned: 0.0,
        expected_loss_keep: 0.0,
        expected_loss_delete: 0.0,
        calibration_score: 0.0,
        vetoed: false,
        veto_reason: None,
        guard_status: None,
        summary: ev.details.clone().unwrap_or_default(),
        raw_json: None,
    }
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Recording scaffold (existing) ──

    #[test]
    fn null_hook_accepts_samples_without_panicking() {
        let mut hook = NullTelemetryHook;
        hook.record(TelemetrySample::new("runtime", "tick", "ok"));
    }

    // ── EventFilter ──

    #[test]
    fn empty_filter_matches_everything() {
        let filter = EventFilter::default();
        assert!(filter.is_empty());
        assert!(filter.matches("info", "artifact_delete"));
        assert!(filter.matches("critical", "pressure_change"));
    }

    #[test]
    fn severity_filter_restricts_correctly() {
        let filter = EventFilter {
            severities: vec!["critical".to_string(), "warning".to_string()],
            event_types: Vec::new(),
        };
        assert!(filter.matches("critical", "anything"));
        assert!(filter.matches("warning", "anything"));
        assert!(!filter.matches("info", "anything"));
    }

    #[test]
    fn event_type_filter_restricts_correctly() {
        let filter = EventFilter {
            severities: Vec::new(),
            event_types: vec!["artifact_delete".to_string()],
        };
        assert!(filter.matches("info", "artifact_delete"));
        assert!(!filter.matches("info", "pressure_change"));
    }

    #[test]
    fn combined_filter_requires_both() {
        let filter = EventFilter {
            severities: vec!["critical".to_string()],
            event_types: vec!["artifact_delete".to_string()],
        };
        assert!(filter.matches("critical", "artifact_delete"));
        assert!(!filter.matches("info", "artifact_delete"));
        assert!(!filter.matches("critical", "pressure_change"));
    }

    // ── NullTelemetryAdapter ──

    #[test]
    fn null_adapter_returns_unavailable() {
        let adapter = NullTelemetryAdapter;
        let result = adapter.recent_events(10, &EventFilter::default());
        assert!(result.data.is_empty());
        assert!(result.partial);
        assert_eq!(result.source, DataSource::None);
    }

    #[test]
    fn null_adapter_health_is_unavailable() {
        let adapter = NullTelemetryAdapter;
        let health = adapter.health();
        assert_eq!(health.sqlite, BackendHealth::Unavailable);
        assert_eq!(health.jsonl, BackendHealth::Unavailable);
        assert!(!health.any_available());
    }

    // ── TelemetryHealth ──

    #[test]
    fn healthy_telemetry_has_both_available() {
        let health = TelemetryHealth::healthy();
        assert!(health.any_available());
        assert!(health.diagnostics.is_empty());
    }

    #[test]
    fn any_available_is_true_with_single_backend() {
        let health = TelemetryHealth {
            sqlite: BackendHealth::Unavailable,
            jsonl: BackendHealth::Available,
            diagnostics: String::new(),
        };
        assert!(health.any_available());
    }

    // ── TelemetryResult ──

    #[test]
    fn unavailable_result_is_partial_with_empty_data() {
        let result: TelemetryResult<Vec<TimelineEvent>> =
            TelemetryResult::unavailable("test".to_string());
        assert!(result.data.is_empty());
        assert!(result.partial);
        assert_eq!(result.source, DataSource::None);
        assert_eq!(result.diagnostics, "test");
    }

    // ── Conversion helpers ──

    #[test]
    fn logentry_to_timeline_preserves_fields() {
        let entry = crate::logger::jsonl::LogEntry {
            ts: "2026-02-16T00:00:00Z".to_string(),
            event: crate::logger::jsonl::EventType::ArtifactDelete,
            severity: crate::logger::jsonl::Severity::Info,
            path: Some("/tmp/target".to_string()),
            size: Some(4096),
            score: Some(0.85),
            factors: None,
            pressure: Some("yellow".to_string()),
            free_pct: Some(18.5),
            rate_bps: None,
            duration_ms: Some(42),
            ok: Some(true),
            error_code: None,
            error_message: None,
            mount_point: None,
            details: Some("test deletion".to_string()),
        };

        let timeline = logentry_to_timeline(&entry);
        assert_eq!(timeline.timestamp, "2026-02-16T00:00:00Z");
        assert_eq!(timeline.event_type, "artifact_delete");
        assert_eq!(timeline.severity, "info");
        assert_eq!(timeline.path.as_deref(), Some("/tmp/target"));
        assert_eq!(timeline.size_bytes, Some(4096));
        assert_eq!(timeline.score, Some(0.85));
        assert_eq!(timeline.pressure_level.as_deref(), Some("yellow"));
        assert_eq!(timeline.success, Some(true));
        assert_eq!(timeline.duration_ms, Some(42));
    }

    #[test]
    fn timeline_to_evidence_uses_defaults_for_missing_fields() {
        let ev = TimelineEvent {
            timestamp: "2026-02-16T00:00:00Z".to_string(),
            event_type: "artifact_delete".to_string(),
            severity: "info".to_string(),
            path: Some("/tmp/build".to_string()),
            size_bytes: Some(1024),
            score: Some(0.75),
            pressure_level: None,
            free_pct: None,
            success: Some(true),
            error_code: None,
            error_message: None,
            duration_ms: None,
            details: Some("cleanup".to_string()),
        };

        let evidence = timeline_to_evidence(42, &ev);
        assert_eq!(evidence.decision_id, 42);
        assert_eq!(evidence.path, "/tmp/build");
        assert_eq!(evidence.action, "delete");
        assert_eq!(evidence.total_score, 0.75);
        assert_eq!(evidence.age_secs, 0);
        assert!(!evidence.vetoed);
        assert_eq!(evidence.summary, "cleanup");
    }

    #[test]
    fn timeline_to_evidence_failed_action_maps_to_keep() {
        let ev = TimelineEvent {
            timestamp: "2026-02-16T00:00:00Z".to_string(),
            event_type: "artifact_delete".to_string(),
            severity: "warning".to_string(),
            path: None,
            size_bytes: None,
            score: None,
            pressure_level: None,
            free_pct: None,
            success: Some(false),
            error_code: Some("SBH-2003".to_string()),
            error_message: Some("veto".to_string()),
            duration_ms: None,
            details: None,
        };

        let evidence = timeline_to_evidence(0, &ev);
        assert_eq!(evidence.action, "keep");
    }

    // ── JSONL adapter ──

    #[test]
    fn jsonl_adapter_returns_none_for_missing_file() {
        assert!(JsonlTelemetryAdapter::open(Path::new("/nonexistent/activity.jsonl")).is_none());
    }

    #[test]
    fn jsonl_adapter_reads_entries_from_file() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("activity.jsonl");

        let entries = vec![
            crate::logger::jsonl::LogEntry {
                ts: "2026-02-16T00:00:01Z".to_string(),
                event: crate::logger::jsonl::EventType::DaemonStart,
                severity: crate::logger::jsonl::Severity::Info,
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
                details: Some("started".to_string()),
            },
            crate::logger::jsonl::LogEntry {
                ts: "2026-02-16T00:00:02Z".to_string(),
                event: crate::logger::jsonl::EventType::ArtifactDelete,
                severity: crate::logger::jsonl::Severity::Info,
                path: Some("/tmp/target".to_string()),
                size: Some(4096),
                score: Some(0.9),
                factors: None,
                pressure: Some("yellow".to_string()),
                free_pct: Some(18.0),
                rate_bps: None,
                duration_ms: Some(10),
                ok: Some(true),
                error_code: None,
                error_message: None,
                mount_point: None,
                details: None,
            },
            crate::logger::jsonl::LogEntry {
                ts: "2026-02-16T00:00:03Z".to_string(),
                event: crate::logger::jsonl::EventType::Error,
                severity: crate::logger::jsonl::Severity::Critical,
                path: None,
                size: None,
                score: None,
                factors: None,
                pressure: None,
                free_pct: None,
                rate_bps: None,
                duration_ms: None,
                ok: Some(false),
                error_code: Some("SBH-3002".to_string()),
                error_message: Some("IO failure".to_string()),
                mount_point: None,
                details: None,
            },
        ];

        let mut content = String::new();
        for entry in &entries {
            content.push_str(&serde_json::to_string(entry).expect("serialize"));
            content.push('\n');
        }
        std::fs::write(&path, content).expect("write jsonl");

        let adapter = JsonlTelemetryAdapter::open(&path).expect("open");

        // Unfiltered: all 3 events, newest first.
        let result = adapter.recent_events(10, &EventFilter::default());
        assert!(!result.partial);
        assert_eq!(result.source, DataSource::Jsonl);
        assert_eq!(result.data.len(), 3);
        assert_eq!(result.data[0].timestamp, "2026-02-16T00:00:03Z");
        assert_eq!(result.data[2].timestamp, "2026-02-16T00:00:01Z");

        // Filtered by severity.
        let critical_filter = EventFilter {
            severities: vec!["critical".to_string()],
            event_types: Vec::new(),
        };
        let result = adapter.recent_events(10, &critical_filter);
        assert_eq!(result.data.len(), 1);
        assert_eq!(result.data[0].severity, "critical");
    }

    #[test]
    fn jsonl_schema_shield_recovers_legacy_alias_fields() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("activity.jsonl");
        let content = [
            r#"{"timestamp":"2026-02-16T00:00:10Z","event_type":"artifact_delete","level":"warning","target_path":"/tmp/legacy","size_bytes":1234,"total_score":0.42,"pressure_level":"orange","free_percent":11.5,"ewma_rate":128.0,"durationMillis":21,"success":false,"mount":"/","message":"legacy schema line"}"#,
            r#"{"ts":"2026-02-16T00:00:11Z","event":"daemon_start","severity":"info","details":"normal line"}"#,
        ]
        .join("\n");
        std::fs::write(&path, content).expect("write jsonl");

        let adapter = JsonlTelemetryAdapter::open(&path).expect("open");
        let result = adapter.recent_events(10, &EventFilter::default());

        assert_eq!(result.source, DataSource::Jsonl);
        assert_eq!(result.data.len(), 2);
        assert!(result.diagnostics.contains("recovered=1"));
        assert!(!result.partial);

        let recovered = result
            .data
            .iter()
            .find(|event| event.path.as_deref() == Some("/tmp/legacy"))
            .expect("recovered legacy event");
        assert_eq!(recovered.event_type, "artifact_delete");
        assert_eq!(recovered.severity, "warning");
        assert_eq!(recovered.size_bytes, Some(1234));
    }

    #[test]
    fn jsonl_schema_shield_marks_partial_when_lines_are_dropped() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("activity.jsonl");
        let content = [
            r#"{"ts":"2026-02-16T00:00:11Z","event":"daemon_start","severity":"info","details":"normal line"}"#,
            r#"{"timestamp":"missing-event-and-severity-only"}"#,
            "not-json-at-all",
        ]
        .join("\n");
        std::fs::write(&path, content).expect("write jsonl");

        let adapter = JsonlTelemetryAdapter::open(&path).expect("open");
        let result = adapter.recent_events(10, &EventFilter::default());

        assert_eq!(result.data.len(), 2);
        assert!(result.partial);
        assert!(result.diagnostics.contains("recovered=1"));
        assert!(result.diagnostics.contains("dropped=1"));
    }

    #[test]
    fn jsonl_adapter_recent_decisions_filters_deletes() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("activity.jsonl");

        let entries = vec![
            crate::logger::jsonl::LogEntry {
                ts: "2026-02-16T00:00:01Z".to_string(),
                event: crate::logger::jsonl::EventType::DaemonStart,
                severity: crate::logger::jsonl::Severity::Info,
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
            },
            crate::logger::jsonl::LogEntry {
                ts: "2026-02-16T00:00:02Z".to_string(),
                event: crate::logger::jsonl::EventType::ArtifactDelete,
                severity: crate::logger::jsonl::Severity::Info,
                path: Some("/tmp/target".to_string()),
                size: Some(4096),
                score: Some(0.9),
                factors: None,
                pressure: None,
                free_pct: None,
                rate_bps: None,
                duration_ms: None,
                ok: Some(true),
                error_code: None,
                error_message: None,
                mount_point: None,
                details: None,
            },
        ];

        let mut content = String::new();
        for entry in &entries {
            content.push_str(&serde_json::to_string(entry).expect("serialize"));
            content.push('\n');
        }
        std::fs::write(&path, content).expect("write jsonl");

        let adapter = JsonlTelemetryAdapter::open(&path).expect("open");
        let result = adapter.recent_decisions(10);
        assert_eq!(result.data.len(), 1);
        assert_eq!(result.data[0].path, "/tmp/target");
        assert_eq!(result.data[0].action, "delete");
    }

    #[test]
    fn jsonl_adapter_pressure_history_filters_by_mount() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("activity.jsonl");

        let entries = vec![
            crate::logger::jsonl::LogEntry {
                ts: "2026-02-16T00:00:01Z".to_string(),
                event: crate::logger::jsonl::EventType::PressureChange,
                severity: crate::logger::jsonl::Severity::Info,
                path: None,
                size: None,
                score: None,
                factors: None,
                pressure: Some("yellow".to_string()),
                free_pct: Some(18.0),
                rate_bps: Some(1024.0),
                duration_ms: None,
                ok: None,
                error_code: None,
                error_message: None,
                mount_point: Some("/".to_string()),
                details: None,
            },
            crate::logger::jsonl::LogEntry {
                ts: "2026-02-16T00:00:02Z".to_string(),
                event: crate::logger::jsonl::EventType::PressureChange,
                severity: crate::logger::jsonl::Severity::Info,
                path: None,
                size: None,
                score: None,
                factors: None,
                pressure: Some("orange".to_string()),
                free_pct: Some(12.0),
                rate_bps: Some(2048.0),
                duration_ms: None,
                ok: None,
                error_code: None,
                error_message: None,
                mount_point: Some("/data".to_string()),
                details: None,
            },
        ];

        let mut content = String::new();
        for entry in &entries {
            content.push_str(&serde_json::to_string(entry).expect("serialize"));
            content.push('\n');
        }
        std::fs::write(&path, content).expect("write jsonl");

        let adapter = JsonlTelemetryAdapter::open(&path).expect("open");

        // Filter by mount "/".
        let result = adapter.pressure_history("/", "", 10);
        assert_eq!(result.data.len(), 1);
        assert_eq!(result.data[0].mount_point, "/");
        assert_eq!(result.data[0].pressure_level, "yellow");

        // Filter by mount "/data".
        let result = adapter.pressure_history("/data", "", 10);
        assert_eq!(result.data.len(), 1);
        assert_eq!(result.data[0].mount_point, "/data");
    }

    #[test]
    fn jsonl_adapter_health_checks_file_existence() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("activity.jsonl");
        std::fs::write(&path, "").expect("write empty");

        let adapter = JsonlTelemetryAdapter::open(&path).expect("open");
        let health = adapter.health();
        assert_eq!(health.jsonl, BackendHealth::Available);
        assert_eq!(health.sqlite, BackendHealth::Unavailable);
    }

    // ── Composite adapter ──

    #[test]
    fn composite_with_no_backends_returns_unavailable() {
        let adapter = CompositeTelemetryAdapter::new(None, None);
        let result = adapter.recent_events(10, &EventFilter::default());
        assert!(result.partial);
        assert_eq!(result.source, DataSource::None);
    }

    #[test]
    fn composite_falls_back_to_jsonl_when_sqlite_missing() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let jsonl_path = tmp.path().join("activity.jsonl");

        let entry = crate::logger::jsonl::LogEntry {
            ts: "2026-02-16T00:00:01Z".to_string(),
            event: crate::logger::jsonl::EventType::DaemonStart,
            severity: crate::logger::jsonl::Severity::Info,
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
            details: Some("started".to_string()),
        };

        std::fs::write(
            &jsonl_path,
            serde_json::to_string(&entry).expect("serialize") + "\n",
        )
        .expect("write jsonl");

        let adapter = CompositeTelemetryAdapter::new(None, Some(&jsonl_path));
        let result = adapter.recent_events(10, &EventFilter::default());
        assert!(!result.partial);
        assert_eq!(result.source, DataSource::Jsonl);
        assert_eq!(result.data.len(), 1);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_adapter_returns_none_for_missing_db() {
        assert!(SqliteTelemetryAdapter::open(Path::new("/nonexistent/activity.db")).is_none());
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_adapter_opens_and_queries_empty_db() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let db_path = tmp.path().join("activity.db");

        // Create a minimal DB with schema using the write logger.
        {
            let _logger = crate::logger::sqlite::SqliteLogger::open(&db_path).expect("create db");
        }

        let adapter = SqliteTelemetryAdapter::open(&db_path).expect("open read-only");
        let result = adapter.recent_events(10, &EventFilter::default());
        assert!(!result.partial);
        assert_eq!(result.source, DataSource::Sqlite);
        assert!(result.data.is_empty());
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_adapter_queries_inserted_activity() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let db_path = tmp.path().join("activity.db");

        // Insert test data via the write logger.
        {
            let logger = crate::logger::sqlite::SqliteLogger::open(&db_path).expect("create db");
            logger
                .log_activity(&crate::logger::sqlite::ActivityRow {
                    timestamp: "2026-02-16T00:00:01Z".to_string(),
                    event_type: "artifact_delete".to_string(),
                    severity: "info".to_string(),
                    path: Some("/tmp/target".to_string()),
                    size_bytes: Some(4096),
                    score: Some(0.85),
                    score_factors: None,
                    pressure_level: Some("yellow".to_string()),
                    free_pct: Some(18.0),
                    duration_ms: Some(42),
                    success: 1,
                    error_code: None,
                    error_message: None,
                    details: Some("test".to_string()),
                })
                .expect("insert");
            logger
                .log_activity(&crate::logger::sqlite::ActivityRow {
                    timestamp: "2026-02-16T00:00:02Z".to_string(),
                    event_type: "pressure_change".to_string(),
                    severity: "warning".to_string(),
                    path: None,
                    size_bytes: None,
                    score: None,
                    score_factors: None,
                    pressure_level: Some("orange".to_string()),
                    free_pct: Some(12.0),
                    duration_ms: None,
                    success: 1,
                    error_code: None,
                    error_message: None,
                    details: None,
                })
                .expect("insert");
        }

        let adapter = SqliteTelemetryAdapter::open(&db_path).expect("open read-only");

        // Unfiltered.
        let result = adapter.recent_events(10, &EventFilter::default());
        assert!(!result.partial);
        assert_eq!(result.data.len(), 2);
        // Newest first.
        assert_eq!(result.data[0].event_type, "pressure_change");
        assert_eq!(result.data[1].event_type, "artifact_delete");

        // Filtered.
        let filter = EventFilter {
            severities: vec!["warning".to_string()],
            event_types: Vec::new(),
        };
        let result = adapter.recent_events(10, &filter);
        assert_eq!(result.data.len(), 1);
        assert_eq!(result.data[0].severity, "warning");
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_adapter_queries_pressure_history() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let db_path = tmp.path().join("activity.db");

        {
            let logger = crate::logger::sqlite::SqliteLogger::open(&db_path).expect("create db");
            logger
                .log_pressure(&crate::logger::sqlite::PressureRow {
                    timestamp: "2026-02-16T00:00:01Z".to_string(),
                    mount_point: "/".to_string(),
                    total_bytes: 100_000_000,
                    free_bytes: 20_000_000,
                    free_pct: 20.0,
                    rate_bytes_per_sec: Some(1024.0),
                    pressure_level: "yellow".to_string(),
                    ewma_rate: Some(900.0),
                    pid_output: Some(0.3),
                })
                .expect("insert pressure");
        }

        let adapter = SqliteTelemetryAdapter::open(&db_path).expect("open read-only");
        let result = adapter.pressure_history("/", "2026-02-15T00:00:00Z", 10);
        assert!(!result.partial);
        assert_eq!(result.data.len(), 1);
        assert_eq!(result.data[0].mount_point, "/");
        assert!((result.data[0].free_pct - 20.0).abs() < 0.01);
        assert_eq!(result.data[0].ewma_rate, Some(900.0));
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_adapter_health_returns_available_for_good_db() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let db_path = tmp.path().join("activity.db");
        {
            let _logger = crate::logger::sqlite::SqliteLogger::open(&db_path).expect("create db");
        }

        let adapter = SqliteTelemetryAdapter::open(&db_path).expect("open");
        let health = adapter.health();
        assert_eq!(health.sqlite, BackendHealth::Available);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_adapter_recent_decisions_extracts_delete_events() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let db_path = tmp.path().join("activity.db");

        {
            let logger = crate::logger::sqlite::SqliteLogger::open(&db_path).expect("create db");
            logger
                .log_activity(&crate::logger::sqlite::ActivityRow {
                    timestamp: "2026-02-16T00:00:01Z".to_string(),
                    event_type: "artifact_delete".to_string(),
                    severity: "info".to_string(),
                    path: Some("/tmp/target".to_string()),
                    size_bytes: Some(8192),
                    score: Some(0.92),
                    score_factors: None,
                    pressure_level: Some("orange".to_string()),
                    free_pct: Some(12.0),
                    duration_ms: Some(15),
                    success: 1,
                    error_code: None,
                    error_message: None,
                    details: Some("scored delete".to_string()),
                })
                .expect("insert");
            // Non-delete event should be excluded.
            logger
                .log_activity(&crate::logger::sqlite::ActivityRow {
                    timestamp: "2026-02-16T00:00:02Z".to_string(),
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
                    details: None,
                })
                .expect("insert");
        }

        let adapter = SqliteTelemetryAdapter::open(&db_path).expect("open");
        let result = adapter.recent_decisions(10);
        assert_eq!(result.data.len(), 1);
        assert_eq!(result.data[0].path, "/tmp/target");
        assert_eq!(result.data[0].total_score, 0.92);
        assert_eq!(result.data[0].action, "delete");
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn composite_prefers_sqlite_over_jsonl() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let db_path = tmp.path().join("activity.db");
        let jsonl_path = tmp.path().join("activity.jsonl");

        // Set up SQLite with one event.
        {
            let logger = crate::logger::sqlite::SqliteLogger::open(&db_path).expect("create db");
            logger
                .log_activity(&crate::logger::sqlite::ActivityRow {
                    timestamp: "2026-02-16T00:00:01Z".to_string(),
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
                    details: Some("sqlite source".to_string()),
                })
                .expect("insert");
        }

        // Set up JSONL with a different event.
        let jsonl_entry = crate::logger::jsonl::LogEntry {
            ts: "2026-02-16T00:00:02Z".to_string(),
            event: crate::logger::jsonl::EventType::DaemonStop,
            severity: crate::logger::jsonl::Severity::Info,
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
            details: Some("jsonl source".to_string()),
        };
        std::fs::write(
            &jsonl_path,
            serde_json::to_string(&jsonl_entry).expect("serialize") + "\n",
        )
        .expect("write jsonl");

        let adapter = CompositeTelemetryAdapter::new(Some(&db_path), Some(&jsonl_path));
        let result = adapter.recent_events(10, &EventFilter::default());

        // Should come from SQLite.
        assert_eq!(result.source, DataSource::Sqlite);
        assert_eq!(result.data.len(), 1);
        assert_eq!(result.data[0].details.as_deref(), Some("sqlite source"));
    }
}
