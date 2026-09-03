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

use std::io::{BufRead, BufReader, Seek, SeekFrom};
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
    /// Stable id of the ledger decision behind an `artifact_delete`
    /// (bd-rc-master-ajg1.3.3): from the JSONL line, or joined from
    /// `decision_log` for SQLite rows. Absent for other events.
    #[serde(default)]
    pub decision_id: Option<String>,
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
impl DecisionEvidence {
    /// The ledger's stable decision id (`DecisionRecord::id`), read from the
    /// full record kept in `raw_json`; absent for evidence synthesized from
    /// the activity log.
    #[must_use]
    pub fn stable_id(&self) -> Option<String> {
        let raw = self.raw_json.as_deref()?;
        let value: Value = serde_json::from_str(raw).ok()?;
        value
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .map(str::to_string)
    }
}

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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DataSource {
    /// Data came from SQLite.
    Sqlite,
    /// Data came from JSONL fallback.
    Jsonl,
    /// No backend available.
    #[default]
    None,
}

// ──────────────────── adapter trait ────────────────────

/// One page of Log Search results (bd-rc-master-ajg1.4.10), newest first.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LogSearchPage {
    pub events: Vec<TimelineEvent>,
    pub page: usize,
    pub page_size: usize,
    /// A later page exists.
    pub has_more: bool,
}

/// A Log Search query as typed on the screen's query line.
///
/// Free words must all appear (case-insensitively) in an entry's path,
/// event type, severity, error message, error code, pressure level or
/// details. Tokens: `type:<event>`, `level:<info|warning|critical>` (a
/// minimum), `path:<prefix>`, `id:<decision-id>`, `since:<15m|1h|24h|7d>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogSearchQuery {
    /// Lower-cased free words.
    pub words: Vec<String>,
    pub event_type: Option<String>,
    pub min_severity: Option<String>,
    pub path_prefix: Option<String>,
    pub decision_id: Option<String>,
    /// Inclusive timestamp floor, in the log's own `YYYY-MM-DDTHH:MM:SSZ`.
    pub since: Option<String>,
    pub page: usize,
    pub page_size: usize,
    /// Tokens that looked typed but did not parse (shown to the operator).
    pub unknown_tokens: Vec<String>,
}

impl LogSearchQuery {
    /// Parse a query line; `since:` is resolved against the current time.
    #[must_use]
    pub fn parse(line: &str) -> Self {
        Self::parse_at(line, chrono::Utc::now())
    }

    /// Parse a query line, resolving `since:` against `now`.
    #[must_use]
    pub fn parse_at(line: &str, now: chrono::DateTime<chrono::Utc>) -> Self {
        let mut query = Self {
            page_size: 50,
            ..Self::default()
        };
        for token in line.split_whitespace() {
            let lower = token.to_ascii_lowercase();
            if let Some(value) = lower.strip_prefix("type:") {
                query.event_type = Some(value.to_string());
            } else if let Some(value) = lower.strip_prefix("level:") {
                if severity_rank(value).is_some() {
                    query.min_severity = Some(value.to_string());
                } else {
                    query.unknown_tokens.push(token.to_string());
                }
            } else if let Some(value) = token.strip_prefix("path:") {
                query.path_prefix = Some(value.to_string());
            } else if let Some(value) = token.strip_prefix("id:") {
                query.decision_id = Some(value.to_string());
            } else if let Some(value) = lower.strip_prefix("since:") {
                match parse_since(value) {
                    Some(window) => {
                        query.since = Some((now - window).format("%Y-%m-%dT%H:%M:%SZ").to_string());
                    }
                    None => query.unknown_tokens.push(token.to_string()),
                }
            } else {
                query.words.push(lower);
            }
        }
        query
    }

    /// No words and no filters: the newest entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
            && self.event_type.is_none()
            && self.min_severity.is_none()
            && self.path_prefix.is_none()
            && self.decision_id.is_none()
            && self.since.is_none()
    }

    /// Whether `event` satisfies every word and filter.
    #[must_use]
    pub fn matches(&self, event: &TimelineEvent) -> bool {
        if let Some(wanted) = &self.event_type
            && !event.event_type.eq_ignore_ascii_case(wanted)
        {
            return false;
        }
        if let Some(min) = &self.min_severity
            && severity_rank(&event.severity).unwrap_or(0) < severity_rank(min).unwrap_or(0)
        {
            return false;
        }
        if let Some(prefix) = &self.path_prefix
            && !event
                .path
                .as_deref()
                .is_some_and(|p| p.starts_with(prefix.as_str()))
        {
            return false;
        }
        if let Some(id) = &self.decision_id
            && event.decision_id.as_deref() != Some(id.as_str())
        {
            return false;
        }
        if let Some(since) = &self.since
            && event.timestamp.as_str() < since.as_str()
        {
            return false;
        }
        if self.words.is_empty() {
            return true;
        }
        let haystack = [
            event.path.as_deref().unwrap_or(""),
            event.event_type.as_str(),
            event.severity.as_str(),
            event.error_message.as_deref().unwrap_or(""),
            event.error_code.as_deref().unwrap_or(""),
            event.pressure_level.as_deref().unwrap_or(""),
            event.details.as_deref().unwrap_or(""),
        ]
        .join("\n")
        .to_ascii_lowercase();
        self.words
            .iter()
            .all(|word| haystack.contains(word.as_str()))
    }

    /// The active filters for the screen header (`type=x level≥y …`).
    #[must_use]
    pub fn describe_filters(&self) -> String {
        let mut parts = Vec::new();
        if let Some(t) = &self.event_type {
            parts.push(format!("type={t}"));
        }
        if let Some(l) = &self.min_severity {
            parts.push(format!("level\u{2265}{l}"));
        }
        if let Some(p) = &self.path_prefix {
            parts.push(format!("path={p}"));
        }
        if let Some(id) = &self.decision_id {
            parts.push(format!("id={id}"));
        }
        if let Some(s) = &self.since {
            parts.push(format!("since={s}"));
        }
        parts.join(" ")
    }
}

/// `info` < `warning` < `critical` (with the spellings the logs use).
#[must_use]
pub fn severity_rank(severity: &str) -> Option<u8> {
    match severity.to_ascii_lowercase().as_str() {
        "info" | "debug" | "trace" => Some(0),
        "warning" | "warn" => Some(1),
        "critical" | "error" => Some(2),
        _ => None,
    }
}

/// `15m`, `2h`, `7d` → a duration.
#[must_use]
pub fn parse_since(value: &str) -> Option<chrono::Duration> {
    let (digits, unit) = value.split_at(
        value
            .trim_end_matches(|c: char| c.is_ascii_alphabetic())
            .len(),
    );
    let amount: i64 = digits.parse().ok().filter(|n| *n > 0)?;
    match unit {
        "m" => Some(chrono::Duration::minutes(amount)),
        "h" => Some(chrono::Duration::hours(amount)),
        "d" => Some(chrono::Duration::days(amount)),
        _ => None,
    }
}

/// The requested page of an already-filtered, newest-first list.
#[must_use]
pub fn page_of(matched: Vec<TimelineEvent>, page: usize, page_size: usize) -> LogSearchPage {
    let page_size = page_size.max(1);
    let start = page.saturating_mul(page_size);
    let has_more = matched.len() > start.saturating_add(page_size);
    LogSearchPage {
        events: matched.into_iter().skip(start).take(page_size).collect(),
        page,
        page_size,
        has_more,
    }
}

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

    /// One page of entries matching `query`, newest first. The default
    /// filters a bounded window of recent events in memory (enough for
    /// the page asked for, times eight); backends with an index override it.
    fn search_events(&self, query: &LogSearchQuery) -> TelemetryResult<LogSearchPage> {
        let page_size = query.page_size.max(1);
        let needed = (query.page + 1).saturating_mul(page_size).saturating_add(1);
        let scan = needed.saturating_mul(8).max(200);
        let filter = EventFilter {
            severities: Vec::new(),
            event_types: query.event_type.iter().cloned().collect(),
        };
        let result = self.recent_events(scan, &filter);
        let matched: Vec<TimelineEvent> = result
            .data
            .into_iter()
            .filter(|event| query.matches(event))
            .collect();
        TelemetryResult {
            data: page_of(matched, query.page, page_size),
            source: result.source,
            partial: result.partial,
            diagnostics: result.diagnostics,
        }
    }
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
    /// The database carries the decision ledger (`decision_log`); older
    /// files without it degrade to deletions projected from the activity log.
    has_decision_log: bool,
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
        let has_decision_log = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'decision_log'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .is_ok_and(|count| count > 0);
        Some(Self {
            conn,
            _path: path.to_path_buf(),
            has_decision_log,
        })
    }

    /// Whether the decision ledger is present in this database.
    #[must_use]
    pub fn has_decision_log(&self) -> bool {
        self.has_decision_log
    }

    /// Recent ledger decisions, newest first, as the explainability screen
    /// shows them.
    fn query_decision_log(
        &self,
        limit: usize,
    ) -> std::result::Result<Vec<DecisionEvidence>, rusqlite::Error> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT record FROM decision_log ORDER BY id DESC LIMIT ?1")?;
        #[allow(clippy::cast_possible_wrap)]
        let rows = stmt.query_map([limit as i64], |row| row.get::<_, String>(0))?;
        Ok(rows
            .filter_map(std::result::Result::ok)
            .filter_map(|json| {
                serde_json::from_str::<crate::scanner::decision_record::DecisionRecord>(&json)
                    .ok()
                    .map(|record| record_to_evidence(&record, json))
            })
            .collect())
    }

    fn query_recent_activity(
        &self,
        limit: usize,
        filter: &EventFilter,
    ) -> std::result::Result<Vec<TimelineEvent>, rusqlite::Error> {
        use std::fmt::Write as _;

        // Build query with optional filters.
        // A deletion links to the ledger decision that approved it: the
        // newest decision on the same path made no later than the event
        // (bd-rc-master-ajg1.3.3). Databases without the ledger get NULL.
        let decision_column = if self.has_decision_log {
            "(SELECT d.decision_id FROM decision_log d
               WHERE activity_log.event_type = 'artifact_delete'
                 AND d.path = activity_log.path
                 AND d.timestamp <= activity_log.timestamp
               ORDER BY d.id DESC LIMIT 1)"
        } else {
            "NULL"
        };
        let mut sql = format!(
            "SELECT timestamp, event_type, severity, path, size_bytes, score,
                    score_factors, pressure_level, free_pct, duration_ms,
                    success, error_code, error_message, details,
                    {decision_column} AS decision_id
             FROM activity_log"
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
        let rows = stmt.query_map(param_refs.as_slice(), activity_row_to_event)?;

        rows.collect()
    }

    /// The Log Search query against `activity_log`: filters become WHERE
    /// clauses (`LIKE` with escaped wildcards for words and the path
    /// prefix, `timestamp >=` for `since:`), the page is `LIMIT/OFFSET`,
    /// and one extra row tells whether a later page exists.
    fn query_activity_search(
        &self,
        query: &LogSearchQuery,
    ) -> std::result::Result<LogSearchPage, rusqlite::Error> {
        use std::fmt::Write as _;

        let decision_column = if self.has_decision_log {
            "(SELECT d.decision_id FROM decision_log d
               WHERE activity_log.event_type = 'artifact_delete'
                 AND d.path = activity_log.path
                 AND d.timestamp <= activity_log.timestamp
               ORDER BY d.id DESC LIMIT 1)"
        } else {
            "NULL"
        };
        let mut sql = format!(
            "SELECT timestamp, event_type, severity, path, size_bytes, score,
                    score_factors, pressure_level, free_pct, duration_ms,
                    success, error_code, error_message, details,
                    {decision_column} AS decision_id
             FROM activity_log"
        );
        let mut conditions = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let bind = |params: &mut Vec<Box<dyn rusqlite::types::ToSql>>, value: String| {
            params.push(Box::new(value));
            format!("?{}", params.len())
        };
        if let Some(event_type) = &query.event_type {
            let p = bind(&mut params, event_type.clone());
            conditions.push(format!("lower(event_type) = {p}"));
        }
        if let Some(min) = query.min_severity.as_deref().and_then(severity_rank) {
            let allowed: Vec<String> = ["info", "warning", "critical"]
                .into_iter()
                .filter(|s| severity_rank(s).unwrap_or(0) >= min)
                .map(|s| bind(&mut params, s.to_string()))
                .collect();
            conditions.push(format!("lower(severity) IN ({})", allowed.join(",")));
        }
        if let Some(prefix) = &query.path_prefix {
            let p = bind(&mut params, format!("{}%", like_escape(prefix)));
            conditions.push(format!("path LIKE {p} ESCAPE '\\'"));
        }
        if let Some(since) = &query.since {
            let p = bind(&mut params, since.clone());
            conditions.push(format!("timestamp >= {p}"));
        }
        for word in &query.words {
            let p = bind(&mut params, format!("%{}%", like_escape(word)));
            conditions.push(format!(
                "(lower(coalesce(path, '')) LIKE {p} ESCAPE '\\'
                  OR lower(event_type) LIKE {p} ESCAPE '\\'
                  OR lower(severity) LIKE {p} ESCAPE '\\'
                  OR lower(coalesce(error_message, '')) LIKE {p} ESCAPE '\\'
                  OR lower(coalesce(error_code, '')) LIKE {p} ESCAPE '\\'
                  OR lower(coalesce(pressure_level, '')) LIKE {p} ESCAPE '\\'
                  OR lower(coalesce(details, '')) LIKE {p} ESCAPE '\\')"
            ));
        }
        if !conditions.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&conditions.join(" AND "));
        }
        let page_size = query.page_size.max(1);
        let limit = bind(&mut params, (page_size + 1).to_string());
        let offset = bind(
            &mut params,
            query.page.saturating_mul(page_size).to_string(),
        );
        let _ = write!(sql, " ORDER BY id DESC LIMIT {limit} OFFSET {offset}");

        let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| &**p).collect();
        let mut stmt = self.conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(param_refs.as_slice(), activity_row_to_event)?;
        let mut events: Vec<TimelineEvent> = rows.collect::<std::result::Result<_, _>>()?;
        // `id:` matches the derived ledger link, filtered after the fetch.
        if let Some(id) = &query.decision_id {
            events.retain(|event| event.decision_id.as_deref() == Some(id.as_str()));
        }
        let has_more = events.len() > page_size;
        events.truncate(page_size);
        Ok(LogSearchPage {
            events,
            page: query.page,
            page_size,
            has_more,
        })
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

/// One `activity_log` row (the SELECT list both queries share) as an event.
#[cfg(feature = "sqlite")]
fn activity_row_to_event(
    row: &rusqlite::Row<'_>,
) -> std::result::Result<TimelineEvent, rusqlite::Error> {
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
        decision_id: row.get(14)?,
    })
}

/// Escape `%`, `_` and `\` for a `LIKE … ESCAPE '\'` pattern.
#[cfg(feature = "sqlite")]
fn like_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(feature = "sqlite")]
impl TelemetryQueryAdapter for SqliteTelemetryAdapter {
    fn search_events(&self, query: &LogSearchQuery) -> TelemetryResult<LogSearchPage> {
        match self.query_activity_search(query) {
            Ok(page) => TelemetryResult {
                data: page,
                source: DataSource::Sqlite,
                partial: false,
                diagnostics: String::new(),
            },
            Err(e) => TelemetryResult {
                data: LogSearchPage::default(),
                source: DataSource::Sqlite,
                partial: true,
                diagnostics: format!("SQLite search failed: {e}"),
            },
        }
    }

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
        // The decision ledger (bd-rc-master-ajg1.3.3): every keep, delete,
        // review and veto with its factor contributions. A database from
        // before the ledger degrades to the deletions in the activity log,
        // flagged partial so the screen says so.
        let mut ledger_error = None;
        let mut ledger_empty = false;
        if self.has_decision_log {
            match self.query_decision_log(limit) {
                Ok(evidence) if evidence.is_empty() => ledger_empty = true,
                Ok(evidence) => {
                    return TelemetryResult {
                        data: evidence,
                        source: DataSource::Sqlite,
                        partial: false,
                        diagnostics: String::new(),
                    };
                }
                Err(e) => ledger_error = Some(e.to_string()),
            }
        }
        let degraded = ledger_error.map_or_else(
            || {
                if ledger_empty {
                    "decision_log has no records: showing deletions from activity_log".to_string()
                } else {
                    "decision_log absent: showing deletions from activity_log".to_string()
                }
            },
            |e| format!("decision_log query failed ({e}): showing deletions from activity_log"),
        );
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
                // An empty ledger over an empty activity log is simply a
                // fresh database, not a degraded one.
                let partial = !(ledger_empty && evidence.is_empty());
                TelemetryResult {
                    data: evidence,
                    source: DataSource::Sqlite,
                    partial,
                    diagnostics: if partial { degraded } else { String::new() },
                }
            }
            Err(e) => TelemetryResult {
                data: Vec::new(),
                source: DataSource::Sqlite,
                partial: true,
                diagnostics: format!("{degraded}; SQLite decision query failed: {e}"),
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
    truncated_tail_window: bool,
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
        let Ok(mut file) = std::fs::File::open(&self.path) else {
            return TailEntries::default();
        };

        let len = file.metadata().map_or(0, |m| m.len());
        let chunk_size = 256 * 1024; // 256KB buffer
        let start_pos = len.saturating_sub(chunk_size);

        if start_pos > 0 && file.seek(SeekFrom::Start(start_pos)).is_err() {
            return TailEntries::default();
        }

        let reader = BufReader::new(file);
        let mut raw_lines: Vec<String> = Vec::with_capacity(128);

        for line in reader.lines() {
            match line {
                Ok(l) if !l.trim().is_empty() => raw_lines.push(l),
                _ => {}
            }
        }

        // If we seeked, the first line is likely partial; discard it.
        if start_pos > 0 && !raw_lines.is_empty() {
            raw_lines.remove(0);
        }
        let truncated_tail_window = start_pos > 0 && raw_lines.len() < n;

        // Take last n lines.
        let start = raw_lines.len().saturating_sub(n);
        let tail = &raw_lines[start..];

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
            truncated_tail_window,
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
        let diagnostics = schema_shield_diagnostics(
            entries.recovered_lines,
            entries.dropped_lines,
            entries.truncated_tail_window,
        );
        let partial = entries.dropped_lines > 0 || entries.truncated_tail_window;

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
        let diagnostics = schema_shield_diagnostics(
            entries.recovered_lines,
            entries.dropped_lines,
            entries.truncated_tail_window,
        );
        let partial = entries.dropped_lines > 0 || entries.truncated_tail_window;
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
        let diagnostics = schema_shield_diagnostics(
            entries.recovered_lines,
            entries.dropped_lines,
            entries.truncated_tail_window,
        );
        let partial = entries.dropped_lines > 0 || entries.truncated_tail_window;
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
    #[cfg(feature = "sqlite")]
    sqlite_path: Option<PathBuf>,
    jsonl: Option<JsonlTelemetryAdapter>,
    jsonl_path: Option<PathBuf>,
}

impl CompositeTelemetryAdapter {
    /// Build from configured paths. Tolerant of missing files.
    #[must_use]
    pub fn new(sqlite_path: Option<&Path>, jsonl_path: Option<&Path>) -> Self {
        #[cfg(feature = "sqlite")]
        let sqlite_path = sqlite_path.map(Path::to_path_buf);
        let jsonl_path = jsonl_path.map(Path::to_path_buf);

        Self {
            #[cfg(feature = "sqlite")]
            sqlite: sqlite_path
                .as_deref()
                .and_then(SqliteTelemetryAdapter::open),
            #[cfg(feature = "sqlite")]
            sqlite_path,
            jsonl: jsonl_path.as_deref().and_then(JsonlTelemetryAdapter::open),
            jsonl_path,
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
    fn search_events(&self, query: &LogSearchQuery) -> TelemetryResult<LogSearchPage> {
        // SQLite's indexed search first, then the bounded JSONL tail scan.
        #[cfg(feature = "sqlite")]
        {
            let sqlite_result = self
                .sqlite
                .as_ref()
                .map(|sqlite| sqlite.search_events(query))
                .or_else(|| {
                    self.sqlite_path
                        .as_deref()
                        .and_then(SqliteTelemetryAdapter::open)
                        .map(|sqlite| sqlite.search_events(query))
                });
            if let Some(result) = sqlite_result
                && !result.partial
            {
                return result;
            }
        }
        if let Some(ref jsonl) = self.jsonl {
            return jsonl.search_events(query);
        }
        if let Some(jsonl) = self
            .jsonl_path
            .as_deref()
            .and_then(JsonlTelemetryAdapter::open)
        {
            return jsonl.search_events(query);
        }
        TelemetryResult::unavailable("no telemetry backend available".to_string())
    }

    fn recent_events(
        &self,
        limit: usize,
        filter: &EventFilter,
    ) -> TelemetryResult<Vec<TimelineEvent>> {
        // Try SQLite first.
        #[cfg(feature = "sqlite")]
        {
            let sqlite_result = self
                .sqlite
                .as_ref()
                .map(|sqlite| sqlite.recent_events(limit, filter))
                .or_else(|| {
                    self.sqlite_path
                        .as_deref()
                        .and_then(SqliteTelemetryAdapter::open)
                        .map(|sqlite| sqlite.recent_events(limit, filter))
                });
            if let Some(result) = sqlite_result
                && !result.partial
            {
                return result;
            }
        }

        // Fall back to JSONL.
        if let Some(ref jsonl) = self.jsonl {
            return jsonl.recent_events(limit, filter);
        }
        if let Some(jsonl) = self
            .jsonl_path
            .as_deref()
            .and_then(JsonlTelemetryAdapter::open)
        {
            return jsonl.recent_events(limit, filter);
        }

        TelemetryResult::unavailable("no telemetry backend available".to_string())
    }

    fn recent_decisions(&self, limit: usize) -> TelemetryResult<Vec<DecisionEvidence>> {
        #[cfg(feature = "sqlite")]
        {
            let sqlite_result = self
                .sqlite
                .as_ref()
                .map(|sqlite| sqlite.recent_decisions(limit))
                .or_else(|| {
                    self.sqlite_path
                        .as_deref()
                        .and_then(SqliteTelemetryAdapter::open)
                        .map(|sqlite| sqlite.recent_decisions(limit))
                });
            if let Some(result) = sqlite_result
                && !result.partial
            {
                return result;
            }
        }

        if let Some(ref jsonl) = self.jsonl {
            return jsonl.recent_decisions(limit);
        }
        if let Some(jsonl) = self
            .jsonl_path
            .as_deref()
            .and_then(JsonlTelemetryAdapter::open)
        {
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
        {
            let sqlite_result = self
                .sqlite
                .as_ref()
                .map(|sqlite| sqlite.pressure_history(mount, since, limit))
                .or_else(|| {
                    self.sqlite_path
                        .as_deref()
                        .and_then(SqliteTelemetryAdapter::open)
                        .map(|sqlite| sqlite.pressure_history(mount, since, limit))
                });
            if let Some(result) = sqlite_result
                && !result.partial
            {
                return result;
            }
        }

        if let Some(ref jsonl) = self.jsonl {
            return jsonl.pressure_history(mount, since, limit);
        }
        if let Some(jsonl) = self
            .jsonl_path
            .as_deref()
            .and_then(JsonlTelemetryAdapter::open)
        {
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
        {
            if let Some(ref sqlite) = self.sqlite {
                health.sqlite = sqlite.health().sqlite;
            } else if let Some(sqlite) = self
                .sqlite_path
                .as_deref()
                .and_then(SqliteTelemetryAdapter::open)
            {
                health.sqlite = sqlite.health().sqlite;
            }
        }

        if let Some(ref jsonl) = self.jsonl {
            health.jsonl = jsonl.health().jsonl;
        } else if let Some(jsonl) = self
            .jsonl_path
            .as_deref()
            .and_then(JsonlTelemetryAdapter::open)
        {
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
        details = Some(details.map_or_else(
            || format!("schema-shield unknown-event={raw}"),
            |existing| format!("schema-shield unknown-event={raw}; {existing}"),
        ));
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
        decision_id: read_string_field(object, &["decision_id"]),
        quarantined: read_bool_field(object, &["quarantined"]),
        details,
        schema_version: read_u64_field(object, &["schema_version"])
            .and_then(|v| u32::try_from(v).ok()),
        run_id: read_string_field(object, &["run_id"]),
    })
}

fn schema_shield_diagnostics(recovered: usize, dropped: usize, tail_truncated: bool) -> String {
    if recovered == 0 && dropped == 0 && !tail_truncated {
        return String::new();
    }
    let mut diagnostics = format!("jsonl schema-shield recovered={recovered} dropped={dropped}");
    if tail_truncated {
        diagnostics.push_str(" tail-window-truncated");
    }
    diagnostics
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
        "info" => Some(crate::logger::jsonl::EventType::Info),
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
            "info" => Some(crate::logger::jsonl::EventType::Info),
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
                        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
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
        decision_id: entry.decision_id.clone(),
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

/// The explainability projection of a ledger record; `raw_json` keeps the
/// full record (its stable id, factor contributions, regret calibration and
/// summary) for the detail pane.
fn record_to_evidence(
    record: &crate::scanner::decision_record::DecisionRecord,
    raw_json: String,
) -> DecisionEvidence {
    let action_name = |action: &crate::scanner::decision_record::ActionRecord| {
        serde_json::to_value(action)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| format!("{action:?}").to_lowercase())
    };
    let policy_mode = serde_json::to_value(record.policy_mode)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{:?}", record.policy_mode).to_lowercase());
    let guard_status = record.guard_status.as_ref().map(|guard| {
        serde_json::to_value(guard)
            .ok()
            .and_then(|v| v.get("status").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_else(|| format!("{guard:?}"))
    });
    DecisionEvidence {
        decision_id: record.decision_id,
        timestamp: record.timestamp.clone(),
        path: record.path.to_string_lossy().into_owned(),
        size_bytes: record.size_bytes,
        age_secs: record.age_secs,
        action: action_name(&record.action),
        effective_action: record.effective_action.as_ref().map(action_name),
        policy_mode,
        factors: FactorBreakdown {
            location: record.factors.location,
            name: record.factors.name,
            age: record.factors.age,
            size: record.factors.size,
            structure: record.factors.structure,
            pressure_multiplier: record.factors.pressure_multiplier,
        },
        total_score: record.total_score,
        posterior_abandoned: record.posterior_abandoned,
        expected_loss_keep: record.expected_loss_keep,
        expected_loss_delete: record.expected_loss_delete,
        calibration_score: record.calibration_score,
        vetoed: record.vetoed,
        veto_reason: record.veto_reason.clone(),
        guard_status,
        summary: record.summary.clone(),
        raw_json: Some(raw_json),
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
            decision_id: None,
            quarantined: None,
            details: Some("test deletion".to_string()),
            schema_version: None,
            run_id: None,
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
            decision_id: None,
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
        assert!((evidence.total_score - 0.75).abs() < f64::EPSILON);
        assert_eq!(evidence.age_secs, 0);
        assert!(!evidence.vetoed);
        assert_eq!(evidence.summary, "cleanup");
    }

    #[test]
    fn timeline_to_evidence_failed_action_maps_to_keep() {
        let ev = TimelineEvent {
            decision_id: None,
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
                decision_id: None,
                quarantined: None,
                details: Some("started".to_string()),
                schema_version: None,
                run_id: None,
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
                decision_id: None,
                quarantined: None,
                details: None,
                schema_version: None,
                run_id: None,
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
                decision_id: None,
                quarantined: None,
                details: None,
                schema_version: None,
                run_id: None,
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
    fn jsonl_tail_window_truncation_marks_partial() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("activity.jsonl");

        let mut content = String::new();
        for i in 0..120_u64 {
            let entry = crate::logger::jsonl::LogEntry {
                ts: format!("2026-02-16T00:00:{i:02}Z"),
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
                decision_id: None,
                quarantined: None,
                details: Some("x".repeat(8192)),
                schema_version: None,
                run_id: None,
            };
            content.push_str(&serde_json::to_string(&entry).expect("serialize"));
            content.push('\n');
        }
        std::fs::write(&path, content).expect("write jsonl");
        assert!(
            std::fs::metadata(&path).expect("metadata").len() > 256 * 1024,
            "fixture must exceed tail chunk size",
        );

        let adapter = JsonlTelemetryAdapter::open(&path).expect("open");
        let result = adapter.recent_events(80, &EventFilter::default());

        assert!(result.partial);
        assert!(result.diagnostics.contains("tail-window-truncated"));
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
                decision_id: None,
                quarantined: None,
                details: None,
                schema_version: None,
                run_id: None,
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
                decision_id: None,
                quarantined: None,
                details: None,
                schema_version: None,
                run_id: None,
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
                decision_id: None,
                quarantined: None,
                details: None,
                schema_version: None,
                run_id: None,
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
                decision_id: None,
                quarantined: None,
                details: None,
                schema_version: None,
                run_id: None,
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
            decision_id: None,
            quarantined: None,
            details: Some("started".to_string()),
            schema_version: None,
            run_id: None,
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

    #[test]
    fn composite_retries_jsonl_open_when_file_appears_later() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let jsonl_path = tmp.path().join("activity-late.jsonl");

        let adapter = CompositeTelemetryAdapter::new(None, Some(&jsonl_path));
        let first = adapter.recent_events(10, &EventFilter::default());
        assert_eq!(first.source, DataSource::None);
        assert!(first.partial);

        let entry = crate::logger::jsonl::LogEntry {
            ts: "2026-02-16T00:00:03Z".to_string(),
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
            decision_id: None,
            quarantined: None,
            details: Some("late file".to_string()),
            schema_version: None,
            run_id: None,
        };
        std::fs::write(
            &jsonl_path,
            serde_json::to_string(&entry).expect("serialize") + "\n",
        )
        .expect("write jsonl");

        let second = adapter.recent_events(10, &EventFilter::default());
        assert_eq!(second.source, DataSource::Jsonl);
        assert_eq!(second.data.len(), 1);
        assert_eq!(second.data[0].details.as_deref(), Some("late file"));
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
    /// A real ledger record, scored by the engine and built the way the
    /// executor builds them, for `path` with `size_bytes`.
    fn ledger_record(
        builder: &mut crate::scanner::decision_record::DecisionRecordBuilder,
        path: &str,
        size_bytes: u64,
    ) -> crate::scanner::decision_record::DecisionRecord {
        use crate::scanner::patterns::{ArtifactCategory, ArtifactClassification};
        use crate::scanner::scoring::{ActiveReferenceSummary, CandidateInput, ScoringEngine};
        let engine = ScoringEngine::from_config(&crate::core::config::ScoringConfig::default(), 0);
        let score = engine.score_candidate(
            &CandidateInput {
                path: PathBuf::from(path),
                size_bytes,
                age: std::time::Duration::from_hours(72),
                classification: ArtifactClassification {
                    pattern_name: std::borrow::Cow::Borrowed("cargo-target"),
                    category: ArtifactCategory::RustTarget,
                    name_confidence: 0.9,
                    structural_confidence: 0.9,
                    combined_confidence: 0.92,
                },
                signals: crate::scanner::patterns::StructuralSignals::default(),
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            },
            0.9,
        );
        builder.build(
            &score,
            crate::scanner::decision_record::PolicyMode::DryRun,
            None,
            None,
            None,
        )
    }

    fn activity_delete(timestamp: &str, path: &str) -> crate::logger::sqlite::ActivityRow {
        crate::logger::sqlite::ActivityRow {
            timestamp: timestamp.to_string(),
            event_type: "artifact_delete".to_string(),
            severity: "info".to_string(),
            path: Some(path.to_string()),
            size_bytes: Some(4096),
            score: Some(0.9),
            score_factors: None,
            pressure_level: Some("orange".to_string()),
            free_pct: Some(9.0),
            duration_ms: Some(3),
            success: 1,
            error_code: None,
            error_message: None,
            details: None,
        }
    }

    /// bd-rc-master-ajg1.3.3: the explainability data comes from the
    /// decision ledger (newest first, with the stable id, factors and veto
    /// state of the real record), and a deletion in the timeline links to
    /// the decision that approved it.
    fn search_event(
        timestamp: &str,
        event_type: &str,
        severity: &str,
        path: &str,
    ) -> TimelineEvent {
        TimelineEvent {
            timestamp: timestamp.to_string(),
            event_type: event_type.to_string(),
            severity: severity.to_string(),
            path: Some(path.to_string()),
            size_bytes: None,
            score: None,
            pressure_level: Some("orange".to_string()),
            free_pct: None,
            success: Some(true),
            error_code: None,
            error_message: Some("disk pressure".to_string()),
            duration_ms: None,
            details: None,
            decision_id: Some("dec-7".to_string()),
        }
    }

    /// bd-rc-master-ajg1.4.10: the query grammar and in-memory matching.
    #[test]
    fn log_search_query_parses_tokens_and_matches_events() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-03T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let loose = LogSearchQuery::parse("Target bogus:x");
        assert_eq!(
            loose.words,
            vec!["target", "bogus:x"],
            "an unknown prefix is just a word"
        );
        let query = LogSearchQuery::parse_at(
            "Target type:artifact_delete level:warning path:/work id:dec-7 since:1h level:nope",
            now,
        );
        assert_eq!(query.words, vec!["target"]);
        assert_eq!(query.event_type.as_deref(), Some("artifact_delete"));
        assert_eq!(query.min_severity.as_deref(), Some("warning"));
        assert_eq!(query.path_prefix.as_deref(), Some("/work"));
        assert_eq!(query.decision_id.as_deref(), Some("dec-7"));
        assert_eq!(query.since.as_deref(), Some("2026-09-03T11:00:00Z"));
        assert_eq!(query.unknown_tokens, vec!["level:nope"]);
        assert!(!query.is_empty());
        assert!(LogSearchQuery::parse("").is_empty());
        assert!(query.describe_filters().contains("type=artifact_delete"));
        assert!(query.describe_filters().contains("level\u{2265}warning"));

        let hit = search_event(
            "2026-09-03T11:30:00Z",
            "artifact_delete",
            "warning",
            "/work/alpha/target",
        );
        assert!(query.matches(&hit));
        let too_old = search_event(
            "2026-09-03T10:00:00Z",
            "artifact_delete",
            "warning",
            "/work/alpha/target",
        );
        assert!(!query.matches(&too_old));
        let too_quiet = search_event(
            "2026-09-03T11:30:00Z",
            "artifact_delete",
            "info",
            "/work/alpha/target",
        );
        assert!(!query.matches(&too_quiet));
        let other_path = search_event(
            "2026-09-03T11:30:00Z",
            "artifact_delete",
            "critical",
            "/home/alpha/target",
        );
        assert!(!query.matches(&other_path));
        let other_type = search_event(
            "2026-09-03T11:30:00Z",
            "ballast_release",
            "critical",
            "/work/alpha/target",
        );
        assert!(!query.matches(&other_type));

        // Free words match the message and pressure level too, case-insensitively.
        let words = LogSearchQuery::parse("PRESSURE orange");
        assert!(words.matches(&hit));
        assert!(!LogSearchQuery::parse("pressure nothere").matches(&hit));

        let page = page_of(
            (0..7)
                .map(|i| {
                    search_event(
                        &format!("2026-09-03T11:0{i}:00Z"),
                        "scan_complete",
                        "info",
                        "/x",
                    )
                })
                .collect(),
            1,
            3,
        );
        assert_eq!(page.events.len(), 3);
        assert_eq!(page.events[0].timestamp, "2026-09-03T11:03:00Z");
        assert!(page.has_more, "7 events, page 1 of 3: one more page");
        let last = page_of(
            (0..7)
                .map(|i| search_event(&format!("t{i}"), "scan_complete", "info", "/x"))
                .collect(),
            2,
            3,
        );
        assert_eq!(last.events.len(), 1);
        assert!(!last.has_more);
        assert_eq!(parse_since("15m"), Some(chrono::Duration::minutes(15)));
        assert_eq!(parse_since("7d"), Some(chrono::Duration::days(7)));
        assert_eq!(parse_since("0h"), None);
        assert_eq!(parse_since("soon"), None);
    }

    /// SQLite answers a search with WHERE clauses and LIMIT/OFFSET paging;
    /// the words search every text column and LIKE wildcards are literal.
    #[test]
    fn sqlite_adapter_searches_the_activity_log() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let db_path = tmp.path().join("activity.db");
        {
            let logger = crate::logger::sqlite::SqliteLogger::open(&db_path).expect("create db");
            for i in 0..5 {
                logger
                    .log_activity(&activity_delete(
                        &format!("2099-01-01T00:00:0{i}Z"),
                        &format!("/work/proj{i}/target"),
                    ))
                    .unwrap();
            }
            logger
                .log_activity(&crate::logger::sqlite::ActivityRow {
                    event_type: "ballast_release".to_string(),
                    severity: "warning".to_string(),
                    path: Some("/data/.sbh/ballast/SBH_BALLAST_FILE_0001".to_string()),
                    error_message: Some("100%_full".to_string()),
                    ..activity_delete("2099-01-01T00:00:10Z", "/unused")
                })
                .unwrap();
        }
        let adapter = SqliteTelemetryAdapter::open(&db_path).expect("open adapter");

        // Paging over the deletions, newest first.
        let mut query = LogSearchQuery::parse("type:artifact_delete");
        query.page_size = 2;
        let first = adapter.search_events(&query);
        assert_eq!(first.source, DataSource::Sqlite);
        assert!(!first.partial, "{}", first.diagnostics);
        assert_eq!(first.data.events.len(), 2);
        assert_eq!(
            first.data.events[0].path.as_deref(),
            Some("/work/proj4/target")
        );
        assert!(first.data.has_more);
        query.page = 2;
        let third = adapter.search_events(&query);
        assert_eq!(third.data.events.len(), 1);
        assert!(!third.data.has_more);

        // Words search the message; a `%` in the query is a literal percent.
        let percent = adapter.search_events(&LogSearchQuery::parse("100%_full"));
        assert_eq!(percent.data.events.len(), 1);
        assert_eq!(percent.data.events[0].event_type, "ballast_release");
        // "10%full" would match "100%_full" only if `%` were a wildcard, and
        // "100%xfull" only if `_` were a one-character wildcard.
        let wildcard_abuse = adapter.search_events(&LogSearchQuery::parse("10%full"));
        assert!(
            wildcard_abuse.data.events.is_empty(),
            "`%` must not act as a wildcard"
        );
        let underscore_abuse = adapter.search_events(&LogSearchQuery::parse("100%xfull"));
        assert!(
            underscore_abuse.data.events.is_empty(),
            "`_` in stored text is not a wildcard for the query's `x`"
        );

        // Minimum level and path prefix.
        let warnings = adapter.search_events(&LogSearchQuery::parse("level:warning"));
        assert_eq!(warnings.data.events.len(), 1);
        let under_work = adapter.search_events(&LogSearchQuery::parse("path:/work/proj1"));
        assert_eq!(under_work.data.events.len(), 1);
        let none = adapter.search_events(&LogSearchQuery::parse("id:not-a-decision"));
        assert!(none.data.events.is_empty());
        let everything = adapter.search_events(&LogSearchQuery::parse(""));
        assert_eq!(everything.data.events.len(), 6);
    }

    /// Without SQLite the default search filters the JSONL tail in memory,
    /// and the composite adapter reports that source.
    #[test]
    fn jsonl_and_composite_adapters_search_the_tail() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("activity.jsonl");
        let mut lines = String::new();
        for i in 0..4 {
            let event = if i == 2 {
                crate::logger::jsonl::EventType::BallastRelease
            } else {
                crate::logger::jsonl::EventType::ArtifactDelete
            };
            let mut entry =
                crate::logger::jsonl::LogEntry::new(event, crate::logger::jsonl::Severity::Info);
            entry.ts = format!("2026-02-16T00:00:0{i}Z");
            entry.path = Some(format!("/tmp/target{i}"));
            entry.size = Some(4096);
            entry.pressure = Some("yellow".to_string());
            entry.ok = Some(true);
            lines.push_str(&serde_json::to_string(&entry).unwrap());
            lines.push('\n');
        }
        std::fs::write(&path, lines).unwrap();

        let jsonl = JsonlTelemetryAdapter::open(&path).expect("open jsonl");
        let releases = jsonl.search_events(&LogSearchQuery::parse("type:ballast_release"));
        assert_eq!(releases.source, DataSource::Jsonl);
        assert_eq!(releases.data.events.len(), 1);
        assert_eq!(
            releases.data.events[0].path.as_deref(),
            Some("/tmp/target2")
        );
        let by_path = jsonl.search_events(&LogSearchQuery::parse("target3"));
        assert_eq!(by_path.data.events.len(), 1);

        let composite = CompositeTelemetryAdapter::new(None, Some(&path));
        let via_composite = composite.search_events(&LogSearchQuery::parse("yellow"));
        assert_eq!(via_composite.source, DataSource::Jsonl);
        assert_eq!(via_composite.data.events.len(), 4);
        let nothing = CompositeTelemetryAdapter::new(None, None);
        let unavailable = nothing.search_events(&LogSearchQuery::parse("x"));
        assert_eq!(unavailable.source, DataSource::None);
        assert!(unavailable.partial);
    }

    #[test]
    fn sqlite_adapter_reads_the_decision_ledger_and_links_deletions() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let db_path = tmp.path().join("activity.db");
        let mut builder = crate::scanner::decision_record::DecisionRecordBuilder::new();
        let first = ledger_record(&mut builder, "/work/alpha/target", 3 << 30);
        let second = ledger_record(&mut builder, "/work/beta/target", 1 << 20);
        {
            let logger = crate::logger::sqlite::SqliteLogger::open(&db_path).expect("create db");
            logger.log_decision(&first).unwrap();
            logger.log_decision(&second).unwrap();
            // The deletion happened after the first decision, on its path.
            logger
                .log_activity(&activity_delete(
                    "2099-01-01T00:00:10Z",
                    "/work/alpha/target",
                ))
                .unwrap();
            logger
                .log_activity(&activity_delete(
                    "2099-01-01T00:00:11Z",
                    "/work/never/target",
                ))
                .unwrap();
        }
        let adapter = SqliteTelemetryAdapter::open(&db_path).expect("open adapter");
        assert!(adapter.has_decision_log());

        let decisions = adapter.recent_decisions(10);
        assert!(!decisions.partial, "{}", decisions.diagnostics);
        assert_eq!(decisions.data.len(), 2);
        let newest = &decisions.data[0];
        assert_eq!(newest.decision_id, second.decision_id);
        assert_eq!(newest.path, "/work/beta/target");
        assert_eq!(newest.stable_id().as_deref(), Some(second.id.as_str()));
        assert_eq!(newest.policy_mode, "dry_run");
        assert!((newest.total_score - second.total_score).abs() < 1e-12);
        assert!((newest.factors.location - second.factors.location).abs() < 1e-12);
        assert_eq!(newest.vetoed, second.vetoed);
        assert_eq!(newest.summary, second.summary);
        assert!(
            newest
                .raw_json
                .as_deref()
                .is_some_and(|j| j.contains(&second.id))
        );
        assert_eq!(decisions.data[1].path, "/work/alpha/target");

        let events = adapter.recent_events(10, &EventFilter::default());
        let alpha = events
            .data
            .iter()
            .find(|e| e.path.as_deref() == Some("/work/alpha/target"))
            .unwrap();
        assert_eq!(alpha.decision_id.as_deref(), Some(first.id.as_str()));
        let never = events
            .data
            .iter()
            .find(|e| e.path.as_deref() == Some("/work/never/target"))
            .unwrap();
        assert_eq!(never.decision_id, None, "no decision on that path");
    }

    /// bd-rc-master-ajg1.3.3: a database from before the ledger degrades to
    /// the activity-log projection and says so.
    #[test]
    fn sqlite_adapter_without_the_ledger_degrades_to_activity_deletions() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let db_path = tmp.path().join("activity.db");
        {
            let logger = crate::logger::sqlite::SqliteLogger::open(&db_path).expect("create db");
            logger
                .log_activity(&activity_delete(
                    "2099-01-01T00:00:10Z",
                    "/work/alpha/target",
                ))
                .unwrap();
        }
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute_batch("DROP TABLE decision_log").unwrap();
        }
        let adapter = SqliteTelemetryAdapter::open(&db_path).expect("open adapter");
        assert!(!adapter.has_decision_log());
        let decisions = adapter.recent_decisions(10);
        assert!(decisions.partial);
        assert!(
            decisions.diagnostics.contains("decision_log absent"),
            "{}",
            decisions.diagnostics
        );
        assert_eq!(decisions.data.len(), 1);
        assert_eq!(decisions.data[0].path, "/work/alpha/target");
        assert_eq!(decisions.data[0].stable_id(), None);
        let events = adapter.recent_events(10, &EventFilter::default());
        assert!(!events.partial);
        assert_eq!(events.data[0].decision_id, None);
    }

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
        assert!((result.data[0].total_score - 0.92).abs() < f64::EPSILON);
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
            decision_id: None,
            quarantined: None,
            details: Some("jsonl source".to_string()),
            schema_version: None,
            run_id: None,
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
