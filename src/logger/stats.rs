//! Stats query engine: aggregation queries over logged events for the stats command.
//!
//! Provides time-window aggregation across `activity_log`, `pressure_history`,
//! and `ballast_inventory` tables. All queries operate on a borrowed `SqliteLogger`
//! connection — the stats engine is a read-only view over the logging database.

#![allow(missing_docs)]

use serde::Serialize;
use std::collections::HashMap;
use std::time::Duration;

use rusqlite::params;

use crate::core::errors::{Result, SbhError};
use crate::logger::sqlite::SqliteLogger;

// ──────────────────── standard time windows ────────────────────

/// The standard time windows used for aggregation.
pub const STANDARD_WINDOWS: &[Duration] = &[
    Duration::from_mins(10),   // 10 minutes
    Duration::from_mins(30),   // 30 minutes
    Duration::from_hours(1),   // 1 hour
    Duration::from_hours(6),   // 6 hours
    Duration::from_hours(24),  // 24 hours
    Duration::from_hours(72),  // 3 days
    Duration::from_hours(168), // 7 days
];

// ──────────────────── stat types ────────────────────

/// Aggregated statistics for a single time window.
#[derive(Debug, Clone)]
pub struct WindowStats {
    pub window: Duration,
    pub deletions: DeletionStats,
    pub ballast: BallastStats,
    pub pressure: PressureStats,
    pub policy: PolicyStats,
}

/// Deletion activity within a time window.
#[derive(Debug, Clone, Default)]
pub struct DeletionStats {
    pub count: u64,
    /// Estimated bytes released by unlinks and finalized quarantine purges.
    /// Quarantine moves themselves release no bytes.
    pub total_bytes_freed: u64,
    /// Of `count`, deletions that went into quarantine (Layer 7).
    pub quarantined_count: u64,
    /// Bytes held in quarantine by those deletions at decision time.
    pub quarantined_bytes: u64,
    /// Completed permanent quarantine removals, separate from the original
    /// cleanup decisions counted by `count`.
    pub purged_count: u64,
    /// Recorded byte estimates released by those completed finalizations.
    pub purged_bytes: u64,
    pub avg_size: u64,
    pub median_size: u64,
    pub largest_deletion: Option<PathInfo>,
    pub most_common_category: Option<String>,
    pub avg_score: f64,
    pub avg_age_hours: f64,
    pub failures: u64,
    /// Failed deletions grouped by error code, most frequent first.
    pub failures_by_reason: Vec<FailureReason>,
}

/// One day's empirical coverage of the conformal time-to-red bound.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ForecastCoverageDay {
    /// `YYYY-MM-DD` (UTC).
    pub day: String,
    /// Mean of the `coverage=` values logged that day.
    pub coverage: f64,
    /// The largest calibration window reported that day.
    pub samples: u64,
    /// Forecast lines aggregated.
    pub lines: u64,
}

/// One day's scanner cost, aggregated from `scan_complete` events.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ScannerDayStat {
    /// `YYYY-MM-DD` (UTC).
    pub day: String,
    /// Scan passes completed that day.
    pub passes: u64,
    /// CPU seconds (user+system) across those passes.
    pub cpu_seconds: f64,
    /// Entries visited by the walker across those passes.
    pub entries_scanned: u64,
    /// Opaque trees pruned from those passes.
    pub opaque_pruned_dirs: u64,
    /// Passes whose rows predate the `process_cpu_micros=` telemetry key.
    pub passes_without_cpu_evidence: u64,
}

/// Failed deletions sharing one error code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureReason {
    /// `SBH-xxxx`, or `unknown` for rows without a code.
    pub code: String,
    pub count: u64,
}

/// Policy engine activity in the window, from `policy_transition` rows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyStats {
    /// Mode transitions logged in the window.
    pub transitions: u64,
    /// The latest transition (`kind: from -> to`), if any.
    pub last_transition: Option<String>,
}

/// Info about a specific deleted path (for "largest deletion" reporting).
#[derive(Debug, Clone)]
pub struct PathInfo {
    pub path: String,
    pub size_bytes: u64,
}

/// Ballast file statistics (point-in-time from inventory).
#[derive(Debug, Clone, Default)]
pub struct BallastStats {
    pub files_released: u64,
    pub files_replenished: u64,
    pub current_inventory: u64,
    pub bytes_available: u64,
}

/// Pressure statistics within a time window.
#[derive(Debug, Clone)]
pub struct PressureStats {
    pub time_in_green_pct: f64,
    pub time_in_yellow_pct: f64,
    pub time_in_orange_pct: f64,
    pub time_in_red_pct: f64,
    pub time_in_critical_pct: f64,
    pub transitions: u64,
    pub worst_level_reached: PressureLevel,
    pub current_level: PressureLevel,
    pub current_free_pct: f64,
}

impl Default for PressureStats {
    fn default() -> Self {
        Self {
            time_in_green_pct: 100.0,
            time_in_yellow_pct: 0.0,
            time_in_orange_pct: 0.0,
            time_in_red_pct: 0.0,
            time_in_critical_pct: 0.0,
            transitions: 0,
            worst_level_reached: PressureLevel::Green,
            current_level: PressureLevel::Green,
            current_free_pct: 100.0,
        }
    }
}

/// Pressure severity levels, ordered from least to most severe.
/// Explicit discriminants ensure `Unknown` sorts below `Green`
/// so it never accidentally registers as worst-level-reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum PressureLevel {
    Unknown = 0,
    Green = 1,
    Yellow = 2,
    Orange = 3,
    Red = 4,
    Critical = 5,
}

impl PressureLevel {
    fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "green" => Self::Green,
            "yellow" => Self::Yellow,
            "orange" => Self::Orange,
            "red" => Self::Red,
            "critical" => Self::Critical,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Yellow => "yellow",
            Self::Orange => "orange",
            Self::Red => "red",
            Self::Critical => "critical",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for PressureLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A pattern with its deletion count.
#[derive(Debug, Clone)]
pub struct PatternStat {
    pub pattern: String,
    pub count: u64,
    pub total_bytes: u64,
}

/// Detail about a single deletion event (for top-N queries).
#[derive(Debug, Clone)]
pub struct DeletionDetail {
    pub path: String,
    pub size_bytes: u64,
    pub score: f64,
    pub timestamp: String,
}

// ──────────────────── RAM-scratch notices ────────────────────

const RAM_SCRATCH_NOTICE_SCHEMA: &str = "sbh.ram_scratch.observation.v1";
const RAM_SCRATCH_NOTICE_MAX_ROWS: usize = 4096;
const RAM_SCRATCH_NOTICE_MAX_DETAIL_BYTES: usize = 4 * 1024 * 1024;
const RAM_SCRATCH_NOTICE_MAX_PAYLOAD_BYTES: usize = 128 * 1024;

/// Whether the logged notice and any supplied observation time are recent.
/// This describes age, independently of whether resource accounting is complete.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RamScratchFreshness {
    Recent,
    Stale,
    Unknown,
}

/// The latest recorded RAM-scratch notice, including coverage and evidence age.
///
/// Unchanged warnings are coalesced and healthy observations are silent, so a
/// logged notice is not a heartbeat or a fresh inspection of current headroom.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RamScratchNotice {
    /// When the daemon logged it (RFC 3339).
    pub logged_at: String,
    /// `warning`, `incomplete` or `recovered`.
    pub state: String,
    /// Explicit coverage from the payload; older notices may not supply it.
    pub complete: Option<bool>,
    /// Distinct reasons that evidence is missing, without parsing prose.
    pub issue_kinds: Vec<String>,
    /// When the probe began; failed or stalled probes may have no timestamp.
    pub observed_at: Option<String>,
    /// Whether the observer omitted details to stay within its payload budget.
    pub details_truncated: bool,
    /// Explanation from a failed, stalled, or truncated observer notice.
    pub detail: Option<String>,
    /// Elapsed whole seconds since logging, unknown for invalid/future times.
    pub notice_age_seconds: Option<u64>,
    /// Elapsed whole seconds since probing, unknown when missing/invalid/future.
    pub observation_age_seconds: Option<u64>,
    /// Age of the available evidence, separate from diagnostic completeness.
    pub freshness: RamScratchFreshness,
    /// Occupied tmpfs bytes, one sample per filesystem.
    pub tmpfs_used_bytes: Option<u64>,
    /// Swap the visible processes hold (their `VmSwap`).
    pub process_swap_bytes: Option<u64>,
    pub swap_free_bytes: Option<u64>,
    pub swap_total_bytes: Option<u64>,
    /// Why it warned, e.g. `low_swap_tmpfs_exceeds_process_swap`.
    pub reasons: Vec<String>,
    /// The largest trees it attributed, largest first (at most five).
    pub largest: Vec<RamScratchTree>,
}

/// One tmpfs tree the RAM-scratch observer attributed.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RamScratchTree {
    pub path: String,
    pub allocated_bytes: u64,
    /// Hours since anything in it changed; `None` when the walk was cut short.
    pub idle_hours: Option<u64>,
}

impl RamScratchNotice {
    /// The notice in an observer activity payload; `None` for anything else.
    #[must_use]
    pub fn from_details(logged_at: &str, details: &str) -> Option<Self> {
        let value = serde_json::from_str(details).ok()?;
        Self::from_value(logged_at, &value)
    }

    fn from_value(logged_at: &str, value: &serde_json::Value) -> Option<Self> {
        use serde_json::Value;
        if value.get("schema")?.as_str()? != RAM_SCRATCH_NOTICE_SCHEMA {
            return None;
        }
        let state = value.get("state")?.as_str()?.to_string();
        if !matches!(state.as_str(), "warning" | "incomplete" | "recovered") {
            return None;
        }
        let mut complete = optional_notice_field::<bool>(value.get("complete")).ok()?;
        let mut issue_kinds: Vec<String> = match value.get("issue_kinds") {
            Some(Value::Array(kinds)) => kinds
                .iter()
                .map(|kind| kind.as_str().map(str::to_string))
                .collect::<Option<_>>()?,
            None | Some(Value::Null) => Vec::new(),
            _ => return None,
        };
        issue_kinds.sort();
        issue_kinds.dedup();
        let details_truncated = optional_notice_field::<bool>(value.get("details_truncated"))
            .ok()?
            .unwrap_or(false);
        let observed_at = optional_notice_field::<String>(
            value
                .pointer("/observation/observed_at")
                .filter(|at| !at.is_null())
                .or_else(|| value.get("observed_at")),
        )
        .ok()?;
        let detail = optional_notice_field::<String>(value.get("detail")).ok()?;
        let assessment = value.pointer("/observation/host/assessment");
        if assessment.is_some_and(|assessment| !assessment.is_object() && !assessment.is_null()) {
            return None;
        }
        let host_complete =
            optional_notice_field::<bool>(value.pointer("/observation/host/complete")).ok()?;
        let process_complete = optional_notice_field::<bool>(
            value.pointer("/observation/host/assessment/process_swap/complete"),
        )
        .ok()?;
        if state == "incomplete"
            || !issue_kinds.is_empty()
            || details_truncated
            || host_complete == Some(false)
            || process_complete == Some(false)
            || assessment.is_some_and(Value::is_null)
        {
            complete = Some(false);
        }
        if complete == Some(true)
            && (host_complete != Some(true)
                || process_complete != Some(true)
                || !complete_ram_scratch_counters(assessment))
        {
            return None;
        }
        let number = |pointer: &str| {
            assessment
                .and_then(|a| a.pointer(pointer))
                .and_then(Value::as_u64)
        };
        let reasons = assessment
            .and_then(|a| a.get("reasons"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|reason| reason.as_str().map(str::to_string))
            .collect();
        Some(Self {
            logged_at: logged_at.to_string(),
            state,
            complete,
            issue_kinds,
            observed_at,
            details_truncated,
            detail,
            notice_age_seconds: None,
            observation_age_seconds: None,
            freshness: RamScratchFreshness::Unknown,
            tmpfs_used_bytes: number("/tmpfs_used_bytes"),
            process_swap_bytes: number("/process_swap/bytes"),
            swap_free_bytes: number("/memory/swap_free_bytes"),
            swap_total_bytes: number("/memory/swap_total_bytes"),
            reasons,
            largest: largest_ram_scratch_trees(value),
        })
    }

    /// Evaluate ages against one clock reading. An explicit invalid or future
    /// timestamp cannot become recent evidence by rounding its age to zero.
    pub fn refresh_freshness(&mut self, now: chrono::DateTime<chrono::Utc>, max_age: Duration) {
        let notice_age = notice_timestamp_age(&self.logged_at, now);
        let observation_age = self
            .observed_at
            .as_deref()
            .and_then(|at| notice_timestamp_age(at, now));
        self.notice_age_seconds = notice_age.map(|age| age.as_secs());
        self.observation_age_seconds = observation_age.map(|age| age.as_secs());
        self.freshness =
            if notice_age.is_none() || (self.observed_at.is_some() && observation_age.is_none()) {
                RamScratchFreshness::Unknown
            } else if notice_age
                .into_iter()
                .chain(observation_age)
                .any(|age| age > max_age)
            {
                RamScratchFreshness::Stale
            } else {
                RamScratchFreshness::Recent
            };
    }
}

fn complete_ram_scratch_counters(assessment: Option<&serde_json::Value>) -> bool {
    let number = |pointer| {
        assessment
            .and_then(|assessment| assessment.pointer(pointer))
            .and_then(serde_json::Value::as_u64)
    };
    match (
        number("/tmpfs_used_bytes"),
        number("/process_swap/bytes"),
        number("/memory/swap_free_bytes"),
        number("/memory/swap_total_bytes"),
    ) {
        (Some(_), Some(_), Some(free), Some(total)) => free <= total,
        _ => false,
    }
}

fn largest_ram_scratch_trees(value: &serde_json::Value) -> Vec<RamScratchTree> {
    use serde_json::Value;
    let mut largest: Vec<RamScratchTree> = value
        .pointer("/observation/attribution")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|mount| mount.get("entries").and_then(Value::as_array))
        .flatten()
        .filter_map(|entry| {
            Some(RamScratchTree {
                path: entry.get("path")?.as_str()?.to_string(),
                allocated_bytes: entry.get("observed_allocated_bytes")?.as_u64()?,
                idle_hours: entry.get("idle_hours").and_then(Value::as_u64),
            })
        })
        .collect();
    largest.sort_by(|a, b| {
        b.allocated_bytes
            .cmp(&a.allocated_bytes)
            .then_with(|| a.path.cmp(&b.path))
    });
    largest.truncate(5);
    largest
}

fn optional_notice_field<T: serde::de::DeserializeOwned>(
    value: Option<&serde_json::Value>,
) -> serde_json::Result<Option<T>> {
    value.map_or(Ok(None), serde::Deserialize::deserialize)
}

fn notice_timestamp_age(at: &str, now: chrono::DateTime<chrono::Utc>) -> Option<Duration> {
    let at = chrono::DateTime::parse_from_rfc3339(at).ok()?;
    now.signed_duration_since(at).to_std().ok()
}

fn ram_scratch_notice_error(details: &str) -> SbhError {
    SbhError::Runtime {
        details: format!("RAM-scratch notice query incomplete: {details}"),
    }
}

// ──────────────────── stats engine ────────────────────

/// Read-only query engine over the sbh activity database.
pub struct StatsEngine<'a> {
    db: &'a SqliteLogger,
}

impl<'a> StatsEngine<'a> {
    /// Create a stats engine backed by the given SQLite logger.
    pub fn new(db: &'a SqliteLogger) -> Self {
        Self { db }
    }

    /// Get stats for all standard time windows.
    pub fn summary(&self) -> Result<Vec<WindowStats>> {
        STANDARD_WINDOWS
            .iter()
            .map(|&w| self.window_stats(w))
            .collect()
    }

    /// The latest RAM-scratch notice in append order, including stale evidence.
    /// `max_age` classifies freshness; it never filters away the latest notice.
    /// A bounded query that cannot establish the latest notice returns an error.
    pub fn ram_scratch_notice(&self, max_age: Duration) -> Result<Option<RamScratchNotice>> {
        self.ram_scratch_notice_at(max_age, chrono::Utc::now())
    }

    fn ram_scratch_notice_at(
        &self,
        max_age: Duration,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<RamScratchNotice>> {
        let conn = self.db.connection();
        // CAST to BLOB makes substr's bound bytes, not Unicode code points.
        // One extra row distinguishes an exhausted search from an empty one;
        // one extra byte distinguishes an oversized payload from a full one.
        let mut statement = conn.prepare_cached(
            "SELECT timestamp, substr(CAST(details AS BLOB), 1, ?1),
                    coalesce(error_code IN ('SBH-RAM-SCRATCH', 'SBH-RAM-SCRATCH-INCOMPLETE'), 0)
             FROM activity_log WHERE event_type = 'info'
             ORDER BY id DESC LIMIT ?2",
        )?;
        let mut rows = statement.query(params![
            i64::try_from(RAM_SCRATCH_NOTICE_MAX_PAYLOAD_BYTES + 1)
                .map_err(|_| ram_scratch_notice_error("invalid query byte budget"))?,
            i64::try_from(RAM_SCRATCH_NOTICE_MAX_ROWS + 1)
                .map_err(|_| ram_scratch_notice_error("invalid query row budget"))?,
        ])?;
        let mut examined = 0;
        let mut detail_bytes = 0_usize;
        while let Some(row) = rows.next()? {
            if examined == RAM_SCRATCH_NOTICE_MAX_ROWS {
                return Err(ram_scratch_notice_error(
                    "info-row inspection budget exhausted",
                ));
            }
            examined += 1;
            let observer_code: bool = row.get(2)?;
            let Some(details) = row.get::<_, Option<Vec<u8>>>(1)? else {
                if observer_code {
                    return Err(ram_scratch_notice_error("missing observer payload"));
                }
                continue;
            };
            if details.len() > RAM_SCRATCH_NOTICE_MAX_PAYLOAD_BYTES {
                return Err(ram_scratch_notice_error(
                    "activity payload byte budget exhausted",
                ));
            }
            detail_bytes = detail_bytes.saturating_add(details.len());
            if detail_bytes > RAM_SCRATCH_NOTICE_MAX_DETAIL_BYTES {
                return Err(ram_scratch_notice_error(
                    "total detail byte budget exhausted",
                ));
            }
            let value: serde_json::Value = match serde_json::from_slice(&details) {
                Ok(value) => value,
                Err(error) => {
                    if observer_code
                        || details
                            .windows(b"sbh.ram_scratch".len())
                            .any(|part| part == b"sbh.ram_scratch")
                    {
                        return Err(ram_scratch_notice_error(&format!(
                            "malformed observer payload: {error}"
                        )));
                    }
                    continue;
                }
            };
            let schema = value.get("schema").and_then(serde_json::Value::as_str);
            if schema != Some(RAM_SCRATCH_NOTICE_SCHEMA) {
                if observer_code
                    || schema
                        .is_some_and(|schema| schema.starts_with("sbh.ram_scratch.observation."))
                {
                    return Err(ram_scratch_notice_error(
                        "missing or unsupported observer payload schema",
                    ));
                }
                continue;
            }
            let logged_at: String = row.get(0)?;
            let mut notice = RamScratchNotice::from_value(&logged_at, &value)
                .ok_or_else(|| ram_scratch_notice_error("malformed observer payload fields"))?;
            notice.refresh_freshness(now, max_age);
            return Ok(Some(notice));
        }
        Ok(None)
    }

    /// Get stats for a specific time window.
    pub fn window_stats(&self, window: Duration) -> Result<WindowStats> {
        let since = since_timestamp(window);
        Ok(WindowStats {
            window,
            deletions: self.deletion_stats(&since)?,
            ballast: self.ballast_stats(&since)?,
            pressure: self.pressure_stats(&since)?,
            policy: self.policy_stats(&since)?,
        })
    }

    /// Policy engine transitions in the window, from the rows the daemon
    /// logs on every mode change.
    #[allow(clippy::cast_sign_loss)]
    fn policy_stats(&self, since: &str) -> Result<PolicyStats> {
        let conn = self.db.connection();
        let transitions: i64 = conn.query_row(
            "SELECT COUNT(*) FROM activity_log
             WHERE event_type = 'policy_transition' AND timestamp >= ?1",
            params![since],
            |row| row.get(0),
        )?;
        let last_transition = conn
            .query_row(
                "SELECT details FROM activity_log
                 WHERE event_type = 'policy_transition' AND timestamp >= ?1
                 ORDER BY id DESC LIMIT 1",
                params![since],
                |row| row.get::<_, Option<String>>(0),
            )
            .ok()
            .flatten();
        Ok(PolicyStats {
            transitions: transitions.max(0) as u64,
            last_transition,
        })
    }

    /// Empirical coverage of the conformal time-to-red bound per day, from
    /// the daemon's `forecast mount=..` info lines (one per filling mount
    /// per minute): the field audit of `pressure.prediction.coverage_target`.
    #[allow(clippy::cast_precision_loss)]
    pub fn forecast_coverage_by_day(&self, window: Duration) -> Result<Vec<ForecastCoverageDay>> {
        let since = since_timestamp(window);
        let conn = self.db.connection();
        let mut stmt = conn.prepare(
            "SELECT timestamp, details FROM activity_log
             WHERE event_type = 'info' AND details LIKE 'forecast mount=%'
               AND timestamp >= ?1
             ORDER BY timestamp ASC",
        )?;
        let rows = stmt.query_map(params![since], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut days: Vec<ForecastCoverageDay> = Vec::new();
        for row in rows {
            let (timestamp, details) = row?;
            let field = |name: &str| {
                details
                    .split_whitespace()
                    .find_map(|kv| kv.strip_prefix(name))
                    .and_then(|v| v.parse::<f64>().ok())
            };
            let Some(coverage) = field("coverage=") else {
                continue;
            };
            let samples = field("samples=").unwrap_or(0.0);
            let day = timestamp.chars().take(10).collect::<String>();
            match days.last_mut() {
                Some(last) if last.day == day => {
                    last.lines += 1;
                    last.coverage += (coverage - last.coverage) / last.lines as f64;
                    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                    {
                        last.samples = last.samples.max(samples.max(0.0) as u64);
                    }
                }
                _ => days.push(ForecastCoverageDay {
                    day,
                    coverage,
                    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                    samples: samples.max(0.0) as u64,
                    lines: 1,
                }),
            }
        }
        Ok(days)
    }

    #[allow(clippy::cast_sign_loss)]
    pub fn top_patterns(&self, n: usize, window: Duration) -> Result<Vec<PatternStat>> {
        let since = since_timestamp(window);
        let conn = self.db.connection();
        let mut stmt = conn.prepare(
            "SELECT
                extract_pattern(path) AS pattern,
                COUNT(*) as count,
                SUM(COALESCE(size_bytes, 0)) as total_bytes
             FROM activity_log
             WHERE event_type = 'artifact_delete' AND success = 1
               AND timestamp >= ?1 AND path IS NOT NULL
             GROUP BY pattern
             ORDER BY count DESC
             LIMIT ?2",
        )?;

        let limit = i64::try_from(n).unwrap_or(i64::MAX);
        let patterns = stmt
            .query_map(params![since, limit], |row| {
                Ok(PatternStat {
                    pattern: row.get(0)?,
                    count: sqlite_nonnegative_i64_to_u64(row.get(1)?),
                    total_bytes: sqlite_nonnegative_i64_to_u64(row.get::<_, i64>(2).unwrap_or(0)),
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(patterns)
    }

    #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
    pub fn top_deletions(&self, n: usize, window: Duration) -> Result<Vec<DeletionDetail>> {
        let since = since_timestamp(window);
        let conn = self.db.connection();
        let mut stmt = conn.prepare(
            "SELECT path, size_bytes, score, timestamp FROM activity_log
             WHERE event_type = 'artifact_delete' AND success = 1
               AND timestamp >= ?1 AND path IS NOT NULL
             ORDER BY COALESCE(size_bytes, 0) DESC LIMIT ?2",
        )?;

        let limit = i64::try_from(n).unwrap_or(i64::MAX);
        let details = stmt
            .query_map(params![since, limit], |row| {
                Ok(DeletionDetail {
                    path: row.get(0)?,
                    size_bytes: row.get::<_, i64>(1).map_or(0, |v| v as u64),
                    score: row.get::<_, f64>(2).unwrap_or(0.0),
                    timestamp: row.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(details)
    }

    /// Export all standard-window stats as JSON for agent consumption.
    pub fn export_json(&self) -> Result<serde_json::Value> {
        let windows = self.summary()?;
        let json_windows: Vec<serde_json::Value> = windows
            .iter()
            .map(|w| {
                serde_json::json!({
                    "window_secs": w.window.as_secs(),
                    "window_label": window_label(w.window),
                    "deletions": {
                        "count": w.deletions.count,
                        "total_bytes_freed": w.deletions.total_bytes_freed,
                        "quarantined_count": w.deletions.quarantined_count,
                        "quarantined_bytes": w.deletions.quarantined_bytes,
                        "purged_count": w.deletions.purged_count,
                        "purged_bytes": w.deletions.purged_bytes,
                        "avg_size": w.deletions.avg_size,
                        "median_size": w.deletions.median_size,
                        "largest_deletion": w.deletions.largest_deletion.as_ref().map(|p| {
                            serde_json::json!({"path": p.path, "size_bytes": p.size_bytes})
                        }),
                        "most_common_category": w.deletions.most_common_category,
                        "avg_score": w.deletions.avg_score,
                        "avg_age_hours": w.deletions.avg_age_hours,
                        "failures": w.deletions.failures,
                        "failures_by_reason": w
                            .deletions
                            .failures_by_reason
                            .iter()
                            .map(|f| serde_json::json!({ "code": f.code, "count": f.count }))
                            .collect::<Vec<_>>(),
                    },
                    "ballast": {
                        "files_released": w.ballast.files_released,
                        "files_replenished": w.ballast.files_replenished,
                        "current_inventory": w.ballast.current_inventory,
                        "bytes_available": w.ballast.bytes_available,
                    },
                    "policy": {
                        "transitions": w.policy.transitions,
                        "last_transition": w.policy.last_transition,
                    },
                    "pressure": {
                        "green_pct": w.pressure.time_in_green_pct,
                        "yellow_pct": w.pressure.time_in_yellow_pct,
                        "orange_pct": w.pressure.time_in_orange_pct,
                        "red_pct": w.pressure.time_in_red_pct,
                        "critical_pct": w.pressure.time_in_critical_pct,
                        "transitions": w.pressure.transitions,
                        "worst_level": w.pressure.worst_level_reached.as_str(),
                        "current_level": w.pressure.current_level.as_str(),
                        "current_free_pct": w.pressure.current_free_pct,
                    },
                })
            })
            .collect();

        let coverage_by_day = self
            .forecast_coverage_by_day(Duration::from_hours(24 * 30))
            .unwrap_or_default();
        let scanner_days = self
            .scanner_stats(Duration::from_hours(24 * 7))
            .unwrap_or_default();
        Ok(serde_json::json!({
            "windows": json_windows,
            "forecast": { "coverage_by_day": coverage_by_day },
            "scanner": scanner_json(&scanner_days),
        }))
    }

    /// Scanner cost per UTC day over the window, from `scan_complete` events.
    ///
    /// CPU seconds come from the `process_cpu_micros=` key in the event
    /// details; entries and pruning from `paths_scanned=` /
    /// `opaque_pruned_dirs=`. Rows written before the CPU key existed count
    /// toward `passes_without_cpu_evidence` instead of the CPU total.
    pub fn scanner_stats(&self, window: Duration) -> Result<Vec<ScannerDayStat>> {
        let since = since_timestamp(window);
        let conn = self.db.connection();
        let mut stmt = conn.prepare(
            "SELECT timestamp, details FROM activity_log
             WHERE event_type = 'scan_complete' AND timestamp >= ?1
             ORDER BY timestamp ASC",
        )?;
        let rows = stmt.query_map(params![since], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
        })?;
        let mut days: Vec<ScannerDayStat> = Vec::new();
        for row in rows {
            let (timestamp, details) = row?;
            let parsed = parse_scan_details(details.as_deref());
            let day = timestamp.get(..10).unwrap_or(&timestamp).to_string();
            let bucket = if let Some(last) = days.last_mut()
                && last.day == day
            {
                last
            } else if let Some(existing) = days.iter_mut().find(|d| d.day == day) {
                existing
            } else {
                days.push(ScannerDayStat {
                    day,
                    passes: 0,
                    cpu_seconds: 0.0,
                    entries_scanned: 0,
                    opaque_pruned_dirs: 0,
                    passes_without_cpu_evidence: 0,
                });
                days.last_mut().expect("day bucket was just pushed")
            };
            merge_scan_day(bucket, &parsed);
        }
        Ok(days)
    }

    // ──────────────────── private helpers ────────────────────

    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    fn deletion_stats(&self, since: &str) -> Result<DeletionStats> {
        let conn = self.db.connection();

        // Aggregate successful deletions.
        let (count, total, avg_size, avg_score): (i64, i64, f64, f64) = conn.query_row(
            "SELECT
                COUNT(*),
                COALESCE(SUM(size_bytes), 0),
                COALESCE(AVG(size_bytes), 0),
                COALESCE(AVG(score), 0)
             FROM activity_log
             WHERE event_type = 'artifact_delete' AND success = 1
               AND timestamp >= ?1",
            params![since],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;

        // Quarantined deletions (Layer 7) are successes that freed nothing.
        let (quarantined_count, quarantined_bytes): (i64, i64) = conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(size_bytes), 0)
             FROM activity_log
             WHERE event_type = 'artifact_delete' AND success = 1
               AND details LIKE '%quarantined%'
               AND timestamp >= ?1",
            params![since],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

        // A later purge releases the held payload. Keep this phase separate
        // from the original cleanup decision so a rename-plus-purge lifecycle
        // does not inflate decision counts or the original size distribution.
        let (purged_count, purged_bytes): (i64, i64) = conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(size_bytes), 0)
             FROM activity_log
             WHERE event_type = 'quarantine_purge' AND success = 1
               AND timestamp >= ?1",
            params![since],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

        // Median via OFFSET/LIMIT (efficient for sorted data with index).
        let median_size = if count > 0 {
            let offset = count / 2;
            conn.query_row(
                "SELECT COALESCE(size_bytes, 0) FROM activity_log
                 WHERE event_type = 'artifact_delete' AND success = 1
                   AND timestamp >= ?1
                 ORDER BY size_bytes ASC
                 LIMIT 1 OFFSET ?2",
                params![since, offset],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0) as u64
        } else {
            0
        };

        // Largest deletion.
        let largest = conn
            .query_row(
                "SELECT path, size_bytes FROM activity_log
                 WHERE event_type = 'artifact_delete' AND success = 1
                   AND timestamp >= ?1 AND path IS NOT NULL
                 ORDER BY size_bytes DESC LIMIT 1",
                params![since],
                |row| {
                    Ok(PathInfo {
                        path: row.get(0)?,
                        size_bytes: row.get::<_, i64>(1).map_or(0, |v| v as u64),
                    })
                },
            )
            .ok();

        // Most common category (extract from path directory name).
        let most_common = self.most_common_deleted_pattern(since)?;

        // Failed deletions, and the same rows grouped by error code.
        let failures: i64 = conn.query_row(
            "SELECT COUNT(*) FROM activity_log
             WHERE event_type = 'artifact_delete' AND success = 0
               AND timestamp >= ?1",
            params![since],
            |row| row.get(0),
        )?;
        let failures_by_reason = conn
            .prepare(
                "SELECT COALESCE(error_code, 'unknown') AS code, COUNT(*) AS n
                 FROM activity_log
                 WHERE event_type = 'artifact_delete' AND success = 0
                   AND timestamp >= ?1
                 GROUP BY code ORDER BY n DESC, code ASC",
            )?
            .query_map(params![since], |row| {
                Ok(FailureReason {
                    code: row.get(0)?,
                    count: row.get::<_, i64>(1).map_or(0, |n| n.max(0) as u64),
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        // Age at deletion comes from the evidence ledger: the decision that
        // approved each deletion recorded the candidate's age.
        let avg_age_hours: f64 = conn
            .query_row(
                "SELECT COALESCE(AVG(json_extract(record, '$.age_secs')), 0.0)
                 FROM decision_log
                 WHERE timestamp >= ?1
                   AND UPPER(COALESCE(effective_action, action)) = 'DELETE'",
                params![since],
                |row| row.get(0),
            )
            .unwrap_or(0.0)
            / 3600.0;

        Ok(DeletionStats {
            count: count.max(0) as u64,
            total_bytes_freed: (total.saturating_sub(quarantined_bytes).max(0) as u64)
                .saturating_add(purged_bytes.max(0) as u64),
            quarantined_count: quarantined_count.max(0) as u64,
            quarantined_bytes: quarantined_bytes.max(0) as u64,
            purged_count: purged_count.max(0) as u64,
            purged_bytes: purged_bytes.max(0) as u64,
            avg_size: avg_size as u64,
            median_size,
            largest_deletion: largest,
            most_common_category: most_common,
            avg_score,
            avg_age_hours,
            failures: failures.max(0) as u64,
            failures_by_reason,
        })
    }

    fn most_common_deleted_pattern(&self, since: &str) -> Result<Option<String>> {
        let conn = self.db.connection();
        match conn.query_row(
            "SELECT extract_pattern(path) AS pattern, COUNT(*) AS count
             FROM activity_log
             WHERE event_type = 'artifact_delete' AND success = 1
               AND timestamp >= ?1 AND path IS NOT NULL
             GROUP BY pattern
             ORDER BY count DESC
             LIMIT 1",
            params![since],
            |row| row.get(0),
        ) {
            Ok(pattern) => Ok(Some(pattern)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(crate::core::errors::SbhError::from(e)),
        }
    }

    #[allow(clippy::cast_sign_loss)]
    fn ballast_stats(&self, since: &str) -> Result<BallastStats> {
        let conn = self.db.connection();

        // Ballast release events in window.
        let released: i64 = conn.query_row(
            "SELECT COUNT(*) FROM activity_log
             WHERE event_type = 'ballast_release' AND success = 1
               AND timestamp >= ?1",
            params![since],
            |row| row.get(0),
        )?;

        // Ballast replenish events in window.
        let replenished: i64 = conn.query_row(
            "SELECT COUNT(*) FROM activity_log
             WHERE event_type = 'ballast_replenish' AND success = 1
               AND timestamp >= ?1",
            params![since],
            |row| row.get(0),
        )?;

        // Current inventory from ballast_inventory table (point-in-time).
        let (inventory, bytes): (i64, i64) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM ballast_inventory
                 WHERE released_at IS NULL",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap_or((0, 0));

        Ok(BallastStats {
            files_released: released as u64,
            files_replenished: replenished as u64,
            current_inventory: inventory as u64,
            bytes_available: bytes as u64,
        })
    }

    fn pressure_stats(&self, since: &str) -> Result<PressureStats> {
        let conn = self.db.connection();

        // On multi-mount systems, pressure samples from different mount points
        // are interleaved.  Pick the mount with the most samples in the window
        // (the "primary" monitored volume) so percentages are coherent.
        let primary_mount: Option<String> = conn
            .query_row(
                "SELECT mount_point FROM pressure_history
                 WHERE timestamp >= ?1
                 GROUP BY mount_point ORDER BY COUNT(*) DESC LIMIT 1",
                params![since],
                |row| row.get(0),
            )
            .ok();

        // Get pressure history samples ordered by time, filtered to primary mount.
        let mut stmt = conn.prepare(
            "SELECT timestamp, pressure_level, free_pct FROM pressure_history
             WHERE timestamp >= ?1 AND (?2 IS NULL OR mount_point = ?2)
             ORDER BY timestamp ASC",
        )?;

        let mount_param = primary_mount.as_deref();
        let samples: Vec<(String, String, f64)> = stmt
            .query_map(params![since, mount_param], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        if samples.is_empty() {
            return Ok(PressureStats::default());
        }

        // Compute time-in-level by assuming each sample represents the state
        // until the next sample (step-function interpolation).
        let mut level_time: HashMap<PressureLevel, f64> = HashMap::new();
        let mut transitions: u64 = 0;
        let mut worst = PressureLevel::Green;
        let mut prev_level = PressureLevel::from_str(&samples[0].1);

        for i in 0..samples.len().saturating_sub(1) {
            let current_level = PressureLevel::from_str(&samples[i].1);
            if let Some(dt) = timestamp_delta_secs(&samples[i].0, &samples[i + 1].0) {
                *level_time.entry(current_level).or_insert(0.0) += dt;
            }

            let next_level = PressureLevel::from_str(&samples[i + 1].1);
            if next_level != current_level {
                transitions += 1;
            }
            if current_level > worst {
                worst = current_level;
            }
            prev_level = next_level;
        }

        // Count the last sample's level too for worst.
        if prev_level > worst {
            worst = prev_level;
        }

        // Account for time from last sample to now (M7).
        let now_str = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        if let Some(last_dt) = timestamp_delta_secs(&samples[samples.len() - 1].0, &now_str)
            && last_dt > 0.0
        {
            *level_time.entry(prev_level).or_insert(0.0) += last_dt;
        }

        let total_time: f64 = level_time.values().sum();

        let pct = |level: PressureLevel| -> f64 {
            if total_time <= 0.0 {
                if level == PressureLevel::Green {
                    100.0
                } else {
                    0.0
                }
            } else {
                level_time.get(&level).copied().unwrap_or(0.0) / total_time * 100.0
            }
        };

        // Current state: last sample.
        let last = &samples[samples.len() - 1];
        let current_level = PressureLevel::from_str(&last.1);
        let current_free_pct = last.2;

        Ok(PressureStats {
            time_in_green_pct: pct(PressureLevel::Green),
            time_in_yellow_pct: pct(PressureLevel::Yellow),
            time_in_orange_pct: pct(PressureLevel::Orange),
            time_in_red_pct: pct(PressureLevel::Red),
            time_in_critical_pct: pct(PressureLevel::Critical),
            transitions,
            worst_level_reached: worst,
            current_level,
            current_free_pct,
        })
    }
}

fn sqlite_nonnegative_i64_to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

/// `scan_complete` metrics parsed out of the `key=value` details string.
#[derive(Debug, Default)]
struct ParsedScanDetails {
    cpu_micros: Option<u64>,
    paths_scanned: u64,
    opaque_pruned_dirs: u64,
}

fn parse_scan_details(details: Option<&str>) -> ParsedScanDetails {
    let mut parsed = ParsedScanDetails::default();
    let Some(details) = details else {
        return parsed;
    };
    for token in details.split_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        let Ok(number) = value.parse::<u64>() else {
            continue;
        };
        match key {
            "process_cpu_micros" => parsed.cpu_micros = Some(number),
            "paths_scanned" => parsed.paths_scanned = number,
            "opaque_pruned_dirs" => parsed.opaque_pruned_dirs = number,
            _ => {}
        }
    }
    parsed
}

#[allow(clippy::cast_precision_loss)]
fn merge_scan_day(day: &mut ScannerDayStat, parsed: &ParsedScanDetails) {
    day.passes += 1;
    if let Some(micros) = parsed.cpu_micros {
        day.cpu_seconds += micros as f64 / 1_000_000.0;
    } else {
        day.passes_without_cpu_evidence += 1;
    }
    day.entries_scanned = day.entries_scanned.saturating_add(parsed.paths_scanned);
    day.opaque_pruned_dirs = day
        .opaque_pruned_dirs
        .saturating_add(parsed.opaque_pruned_dirs);
}

/// The `scanner` block of `stats --json`: per-day CPU cost plus totals.
fn scanner_json(days: &[ScannerDayStat]) -> serde_json::Value {
    serde_json::json!({
        "window": "7d",
        "cpu_seconds_by_day": days,
        "passes": days.iter().map(|d| d.passes).sum::<u64>(),
        "entries_scanned": days.iter().map(|d| d.entries_scanned).sum::<u64>(),
        "opaque_pruned_dirs": days.iter().map(|d| d.opaque_pruned_dirs).sum::<u64>(),
        // `+ 0.0` normalizes the IEEE `-0.0` an empty fold can surface.
        "cpu_seconds_total": days.iter().map(|d| d.cpu_seconds).sum::<f64>() + 0.0,
    })
}

// ──────────────────── utility functions ────────────────────

/// Compute an ISO 8601 timestamp for "now minus duration".
#[allow(clippy::cast_possible_wrap)]
fn since_timestamp(window: Duration) -> String {
    let now = chrono::Utc::now();
    let since = now - chrono::Duration::from_std(window).unwrap_or(chrono::Duration::MAX);
    since.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Compute approximate seconds between two ISO 8601 timestamps.
#[allow(clippy::cast_precision_loss)]
fn timestamp_delta_secs(a: &str, b: &str) -> Option<f64> {
    let ta = chrono::DateTime::parse_from_rfc3339(a).ok()?;
    let tb = chrono::DateTime::parse_from_rfc3339(b).ok()?;
    Some((tb - ta).num_milliseconds() as f64 / 1000.0)
}

/// Human-readable label for a duration.
pub fn window_label(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 3600 {
        format!("{} min", secs / 60)
    } else if secs < 86400 {
        let h = secs / 3600;
        if h == 1 {
            "1 hour".to_string()
        } else {
            format!("{h} hours")
        }
    } else {
        let d = secs / 86400;
        if d == 1 {
            "1 day".to_string()
        } else {
            format!("{d} days")
        }
    }
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logger::sqlite::{ActivityRow, BallastRow, PressureRow, SqliteLogger};
    use crate::scanner::patterns::extract_pattern_label as extract_pattern;

    fn temp_db() -> (tempfile::TempDir, SqliteLogger) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("stats_test.db");
        let logger = SqliteLogger::open(&db_path).unwrap();
        (dir, logger)
    }

    fn ts(minutes_ago: i64) -> String {
        let now = chrono::Utc::now();
        let t = now - chrono::Duration::minutes(minutes_ago);
        t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }

    #[test]
    fn empty_database_returns_defaults() {
        let (_dir, db) = temp_db();
        let engine = StatsEngine::new(&db);
        let stats = engine.summary().unwrap();
        assert_eq!(stats.len(), STANDARD_WINDOWS.len());

        for ws in &stats {
            assert_eq!(ws.deletions.count, 0);
            assert_eq!(ws.deletions.failures, 0);
            assert_eq!(ws.ballast.current_inventory, 0);
            assert_eq!(ws.pressure.transitions, 0);
        }
    }

    /// bd-paeg: return the latest notice with its largest trees, preserving an
    /// old notice as stale instead of confusing age with absent evidence.
    #[test]
    fn ram_scratch_notice_reads_the_observers_latest_notice() {
        let (_dir, db) = temp_db();
        let payload = |state: &str, trees: u64| {
            let entries: Vec<serde_json::Value> = (0..trees)
                .map(|i| {
                    // The walk of the first tree was cut short: no idle age.
                    let idle = if i == 0 {
                        serde_json::Value::Null
                    } else {
                        serde_json::Value::from(i * 10)
                    };
                    serde_json::json!({
                        "path": format!("/tmp/tree-{i}"),
                        "observed_allocated_bytes": (i + 1) * 1_000_000_000,
                        "idle_hours": idle,
                    })
                })
                .collect();
            serde_json::json!({
                "schema": "sbh.ram_scratch.observation.v1",
                "state": state,
                "observation": {
                    "host": {"assessment": {
                        "tmpfs_used_bytes": 34_146_168_832_u64,
                        "process_swap": {"bytes": 17_808_011_264_u64, "complete": true},
                        "memory": {
                            "swap_free_bytes": 2_491_097_088_u64,
                            "swap_total_bytes": 68_719_472_640_u64,
                        },
                        "reasons": ["low_swap_tmpfs_exceeds_process_swap"],
                    }},
                    "attribution": [{"entries": entries}],
                },
            })
            .to_string()
        };
        let row = |minutes_ago: i64, code: Option<&str>, details: String| ActivityRow {
            timestamp: ts(minutes_ago),
            event_type: "info".to_string(),
            severity: if code.is_some() { "warning" } else { "info" }.to_string(),
            path: None,
            size_bytes: None,
            score: None,
            score_factors: None,
            pressure_level: None,
            free_pct: None,
            duration_ms: None,
            success: 1,
            error_code: code.map(str::to_string),
            error_message: None,
            details: Some(details),
        };
        let window = Duration::from_mins(35);
        let engine = StatsEngine::new(&db);
        assert_eq!(engine.ram_scratch_notice(window).unwrap(), None);

        db.log_activity(&row(50, Some("SBH-RAM-SCRATCH"), payload("warning", 1)))
            .unwrap();
        let stale = engine.ram_scratch_notice(window).unwrap().unwrap();
        assert_eq!(stale.state, "warning");
        assert_eq!(stale.freshness, RamScratchFreshness::Stale);
        assert_eq!(
            stale.complete, None,
            "legacy payload does not prove coverage"
        );

        db.log_activity(&row(10, Some("SBH-RAM-SCRATCH"), payload("warning", 7)))
            .unwrap();
        db.log_activity(&row(5, None, r#"{"schema":"other"}"#.to_string()))
            .unwrap();
        let notice = engine
            .ram_scratch_notice(window)
            .unwrap()
            .expect("the warning 10 minutes ago");
        assert_eq!(notice.state, "warning");
        assert_eq!(notice.freshness, RamScratchFreshness::Recent);
        assert_eq!(notice.tmpfs_used_bytes, Some(34_146_168_832));
        assert_eq!(notice.process_swap_bytes, Some(17_808_011_264));
        assert_eq!(notice.swap_free_bytes, Some(2_491_097_088));
        assert_eq!(notice.reasons, ["low_swap_tmpfs_exceeds_process_swap"]);
        assert_eq!(notice.largest.len(), 5);
        assert_eq!(notice.largest[0].path, "/tmp/tree-6");
        assert_eq!(notice.largest[0].idle_hours, Some(60));

        db.log_activity(&row(1, None, payload("recovered", 0)))
            .unwrap();
        let latest = engine.ram_scratch_notice(window).unwrap().unwrap();
        assert_eq!(latest.state, "recovered");
        assert!(latest.largest.is_empty());
        assert_eq!(RamScratchNotice::from_details("t", "not json"), None);
    }

    fn ram_scratch_now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-11-04T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    fn ram_scratch_payload(state: &str) -> serde_json::Value {
        let reasons = if state == "warning" {
            vec!["tmpfs_exceeds_half_ram"]
        } else {
            Vec::new()
        };
        serde_json::json!({
            "schema": RAM_SCRATCH_NOTICE_SCHEMA,
            "state": state,
            "complete": state != "incomplete",
            "issue_kinds": [],
            "details_truncated": false,
            "observation": {
                "observed_at": "2026-11-04T11:59:00Z",
                "host": {
                    "complete": state != "incomplete",
                    "assessment": {
                        "tmpfs_used_bytes": if state == "warning" { 600 } else { 40 },
                        "process_swap": {"bytes": 20, "complete": true},
                        "memory": {"swap_free_bytes": 900, "swap_total_bytes": 1000},
                        "reasons": reasons,
                    },
                },
                "attribution": [],
            },
        })
    }

    fn insert_notice_rows(db: &SqliteLogger, at: &str, details: &str, count: usize) {
        let transaction = db.connection().unchecked_transaction().unwrap();
        {
            let mut statement = transaction
                .prepare(
                    "INSERT INTO activity_log (timestamp, event_type, severity, success, details)
                     VALUES (?1, 'info', 'info', 1, ?2)",
                )
                .unwrap();
            for _ in 0..count {
                statement.execute(params![at, details]).unwrap();
            }
        }
        transaction.commit().unwrap();
    }

    #[test]
    fn ram_scratch_notice_retains_incomplete_pressure_evidence() {
        let mut payload = ram_scratch_payload("warning");
        payload["issue_kinds"] =
            serde_json::json!(["permission_denied", "mount_covered", "mount_covered"]);
        let notice =
            RamScratchNotice::from_details("2026-11-04T11:59:30Z", &payload.to_string()).unwrap();
        assert_eq!(notice.state, "warning");
        assert_eq!(notice.complete, Some(false));
        assert_eq!(notice.issue_kinds, ["mount_covered", "permission_denied"]);
        assert_eq!(notice.tmpfs_used_bytes, Some(600));
        assert_eq!(notice.process_swap_bytes, Some(20));
        assert_eq!(notice.reasons, ["tmpfs_exceeds_half_ram"]);
        assert_eq!(notice.observed_at.as_deref(), Some("2026-11-04T11:59:00Z"));
        assert!(!notice.details_truncated);
        let json = serde_json::to_value(notice).unwrap();
        assert_eq!(json["complete"], false);
        assert_eq!(json["freshness"], "unknown");
        assert!(json["notice_age_seconds"].is_null());
    }

    #[test]
    fn ram_scratch_notice_preserves_stalls_truncation_and_missing_assessments() {
        for (kind, truncated) in [
            ("probe_stalled", false),
            ("activity_payload_budget_exhausted", true),
        ] {
            let payload = serde_json::json!({
                "schema": RAM_SCRATCH_NOTICE_SCHEMA,
                "state": if truncated { "warning" } else { "incomplete" },
                "complete": false,
                "issue_kinds": [kind],
                "details_truncated": truncated,
                "observed_at": if truncated { Some("2026-11-04T11:58:00Z") } else { None },
                "detail": "fresh accounting is unavailable; run sbh check --ram-scratch",
            });
            let mut notice =
                RamScratchNotice::from_details("2026-11-04T11:59:30Z", &payload.to_string())
                    .unwrap();
            notice.refresh_freshness(ram_scratch_now(), Duration::from_mins(35));
            assert_eq!(notice.complete, Some(false));
            assert_eq!(notice.issue_kinds, [kind]);
            assert_eq!(notice.details_truncated, truncated);
            assert_eq!(notice.tmpfs_used_bytes, None);
            assert_eq!(notice.process_swap_bytes, None);
            assert!(
                notice
                    .detail
                    .as_deref()
                    .unwrap()
                    .contains("fresh accounting")
            );
            assert_eq!(notice.notice_age_seconds, Some(30));
            assert_eq!(notice.observation_age_seconds, truncated.then_some(120));
            assert_eq!(notice.freshness, RamScratchFreshness::Recent);
        }
        let mut payload = ram_scratch_payload("recovered");
        payload["observation"]["host"]["assessment"] = serde_json::Value::Null;
        let notice = RamScratchNotice::from_details("t", &payload.to_string()).unwrap();
        assert_eq!(
            notice.complete,
            Some(false),
            "absent assessment cannot prove recovery"
        );
        assert_eq!(notice.tmpfs_used_bytes, None);
        assert_eq!(notice.swap_total_bytes, None);
    }

    #[test]
    fn ram_scratch_notice_does_not_invent_legacy_completeness() {
        let mut payload = ram_scratch_payload("warning");
        payload.as_object_mut().unwrap().remove("complete");
        let notice = RamScratchNotice::from_details("t", &payload.to_string()).unwrap();
        assert_eq!(notice.complete, None);
        assert!(notice.issue_kinds.is_empty());
        let json = serde_json::to_value(notice).unwrap();
        assert!(json["complete"].is_null());

        payload["observation"]["host"]["complete"] = serde_json::json!(false);
        let notice = RamScratchNotice::from_details("t", &payload.to_string()).unwrap();
        assert_eq!(
            notice.complete,
            Some(false),
            "explicit incomplete host evidence is retained"
        );
    }

    #[test]
    fn ram_scratch_notice_freshness_rejects_invalid_and_future_times() {
        let now = ram_scratch_now();
        let maximum = Duration::from_mins(35);
        for bad_time in ["invalid", "2026-11-04T12:00:00.001Z"] {
            let mut notice = RamScratchNotice::from_details(
                bad_time,
                &ram_scratch_payload("recovered").to_string(),
            )
            .unwrap();
            notice.refresh_freshness(now, maximum);
            assert_eq!(notice.notice_age_seconds, None, "{bad_time}");
            assert_eq!(notice.observation_age_seconds, Some(60));
            assert_eq!(notice.freshness, RamScratchFreshness::Unknown);

            let mut payload = ram_scratch_payload("recovered");
            payload["observation"]["observed_at"] = serde_json::json!(bad_time);
            let mut notice =
                RamScratchNotice::from_details("2026-11-04T11:59:30Z", &payload.to_string())
                    .unwrap();
            notice.refresh_freshness(now, maximum);
            assert_eq!(notice.notice_age_seconds, Some(30));
            assert_eq!(notice.observation_age_seconds, None, "{bad_time}");
            assert_eq!(notice.freshness, RamScratchFreshness::Unknown);
        }
        let mut payload = ram_scratch_payload("recovered");
        payload["observation"]["observed_at"] = serde_json::json!("2026-11-04T11:25:00Z");
        let mut notice =
            RamScratchNotice::from_details("2026-11-04T11:59:30Z", &payload.to_string()).unwrap();
        notice.refresh_freshness(now, maximum);
        assert_eq!(notice.freshness, RamScratchFreshness::Recent);
        assert_eq!(notice.observation_age_seconds, Some(2100));
        notice.observed_at = Some("2026-11-04T11:24:59.999Z".into());
        notice.refresh_freshness(now, maximum);
        assert_eq!(notice.freshness, RamScratchFreshness::Stale);
        assert_eq!(notice.observation_age_seconds, Some(2100));
    }

    #[test]
    fn ram_scratch_notice_keeps_latest_append_after_clock_rollback_and_json_whitespace() {
        let (_dir, db) = temp_db();
        insert_notice_rows(
            &db,
            "2026-11-04T11:59:30Z",
            &ram_scratch_payload("recovered").to_string(),
            1,
        );
        let mut payload = ram_scratch_payload("incomplete");
        payload["issue_kinds"] = serde_json::json!(["mount_covered"]);
        payload["observation"]["observed_at"] = serde_json::json!("2026-11-04T10:59:00Z");
        insert_notice_rows(
            &db,
            "2026-11-04T11:00:00Z",
            &serde_json::to_string_pretty(&payload).unwrap(),
            1,
        );
        insert_notice_rows(&db, "2026-11-04T12:00:00Z", "ordinary unrelated info", 1);
        let notice = StatsEngine::new(&db)
            .ram_scratch_notice_at(Duration::from_mins(35), ram_scratch_now())
            .unwrap()
            .unwrap();
        assert_eq!(notice.state, "incomplete");
        assert_eq!(notice.complete, Some(false));
        assert_eq!(notice.issue_kinds, ["mount_covered"]);
        assert_eq!(notice.logged_at, "2026-11-04T11:00:00Z");
        assert_eq!(notice.notice_age_seconds, Some(3600));
        assert_eq!(notice.observation_age_seconds, Some(3660));
        assert_eq!(notice.freshness, RamScratchFreshness::Stale);
    }

    #[test]
    fn ram_scratch_notice_malformed_newest_payload_blocks_older_complete_evidence() {
        for malformed in [
            r#"{"schema" : "sbh.ram_scratch.observation.v1", "state":"incomplete""#,
            r#"{"schema":"sbh.ram_scratch.observation.v1","state":"warning","complete":"true"}"#,
            r#"{"schema":"sbh.ram_scratch.observation.v1","state":"invalid"}"#,
            r#"{"schema":"sbh.ram_scratch.observation.v2","state":"recovered"}"#,
        ] {
            let (_dir, db) = temp_db();
            insert_notice_rows(
                &db,
                "2026-11-04T11:59:30Z",
                &ram_scratch_payload("recovered").to_string(),
                1,
            );
            insert_notice_rows(&db, "2026-11-04T11:59:45Z", malformed, 1);
            let error = StatsEngine::new(&db)
                .ram_scratch_notice_at(Duration::from_mins(35), ram_scratch_now())
                .unwrap_err();
            assert!(error.to_string().contains("observer payload"), "{error}");
        }
    }

    #[test]
    fn ram_scratch_notice_coded_corruption_cannot_expose_an_older_recovery() {
        for code in ["SBH-RAM-SCRATCH", "SBH-RAM-SCRATCH-INCOMPLETE"] {
            for details in [
                None,
                Some("not json"),
                Some(r#"{"complete":false}"#),
                Some(r#"{"schema":"other","complete":false}"#),
            ] {
                let (_dir, db) = temp_db();
                insert_notice_rows(
                    &db,
                    "2026-11-04T11:59:00Z",
                    &ram_scratch_payload("recovered").to_string(),
                    1,
                );
                db.connection()
                    .execute(
                        "INSERT INTO activity_log
                         (timestamp, event_type, severity, success, error_code, details)
                         VALUES ('2026-11-04T11:59:30Z', 'info', 'warning', 1, ?1, ?2)",
                        params![code, details],
                    )
                    .unwrap();
                let error = StatsEngine::new(&db)
                    .ram_scratch_notice_at(Duration::from_mins(35), ram_scratch_now())
                    .unwrap_err();
                assert!(
                    error.to_string().contains("observer payload"),
                    "{code}: {error}"
                );
            }
        }
    }

    #[test]
    fn ram_scratch_notice_complete_claim_requires_usable_assessment_evidence() {
        for defect in [
            "empty_assessment",
            "host_complete_string",
            "process_complete_string",
            "missing_process_complete",
            "missing_counter",
            "inconsistent_swap",
        ] {
            let mut payload = ram_scratch_payload("recovered");
            match defect {
                "empty_assessment" => {
                    payload["observation"]["host"]["assessment"] = serde_json::json!({});
                }
                "host_complete_string" => {
                    payload["observation"]["host"]["complete"] = serde_json::json!("false");
                }
                "process_complete_string" => {
                    payload["observation"]["host"]["assessment"]["process_swap"]["complete"] =
                        serde_json::json!("false");
                }
                "missing_process_complete" => {
                    payload["observation"]["host"]["assessment"]["process_swap"]
                        .as_object_mut()
                        .unwrap()
                        .remove("complete");
                }
                "missing_counter" => {
                    payload["observation"]["host"]["assessment"]
                        .as_object_mut()
                        .unwrap()
                        .remove("tmpfs_used_bytes");
                }
                "inconsistent_swap" => {
                    payload["observation"]["host"]["assessment"]["memory"]["swap_free_bytes"] =
                        serde_json::json!(1001);
                }
                _ => unreachable!(),
            }
            let (_dir, db) = temp_db();
            insert_notice_rows(
                &db,
                "2026-11-04T11:59:00Z",
                &ram_scratch_payload("recovered").to_string(),
                1,
            );
            insert_notice_rows(&db, "2026-11-04T11:59:30Z", &payload.to_string(), 1);
            let error = StatsEngine::new(&db)
                .ram_scratch_notice_at(Duration::from_mins(35), ram_scratch_now())
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("malformed observer payload fields"),
                "{defect}: {error}"
            );
        }
        let mut payload = ram_scratch_payload("recovered");
        payload["observation"]["host"]["assessment"]["process_swap"]["complete"] =
            serde_json::json!(false);
        let notice = RamScratchNotice::from_details("t", &payload.to_string()).unwrap();
        assert_eq!(
            notice.complete,
            Some(false),
            "partial process coverage cannot claim recovery"
        );
    }

    #[test]
    fn ram_scratch_notice_row_budget_does_not_publish_an_older_healthy_notice() {
        let (_dir, db) = temp_db();
        insert_notice_rows(
            &db,
            "2026-11-04T11:59:00Z",
            &ram_scratch_payload("recovered").to_string(),
            1,
        );
        insert_notice_rows(
            &db,
            "2026-11-04T11:59:30Z",
            "{}",
            RAM_SCRATCH_NOTICE_MAX_ROWS - 1,
        );
        let engine = StatsEngine::new(&db);
        let notice = engine
            .ram_scratch_notice_at(Duration::from_mins(35), ram_scratch_now())
            .unwrap()
            .unwrap();
        assert_eq!(notice.complete, Some(true));
        insert_notice_rows(&db, "2026-11-04T11:59:45Z", "{}", 1);
        let error = engine
            .ram_scratch_notice_at(Duration::from_mins(35), ram_scratch_now())
            .unwrap_err();
        assert!(
            error.to_string().contains("info-row inspection budget"),
            "{error}"
        );
    }

    #[test]
    fn ram_scratch_notice_total_byte_budget_blocks_an_older_healthy_notice() {
        let (_dir, db) = temp_db();
        insert_notice_rows(
            &db,
            "2026-11-04T11:59:00Z",
            &ram_scratch_payload("recovered").to_string(),
            1,
        );
        let unrelated = serde_json::json!({
            "padding": "x".repeat(RAM_SCRATCH_NOTICE_MAX_PAYLOAD_BYTES - 14),
        })
        .to_string();
        assert_eq!(unrelated.len(), RAM_SCRATCH_NOTICE_MAX_PAYLOAD_BYTES);
        let whole_rows = RAM_SCRATCH_NOTICE_MAX_DETAIL_BYTES / unrelated.len();
        insert_notice_rows(&db, "2026-11-04T11:59:30Z", &unrelated, whole_rows - 1);
        let engine = StatsEngine::new(&db);
        assert!(
            engine
                .ram_scratch_notice_at(Duration::from_mins(35), ram_scratch_now())
                .unwrap()
                .is_some()
        );
        insert_notice_rows(&db, "2026-11-04T11:59:45Z", &unrelated, 1);
        let error = engine
            .ram_scratch_notice_at(Duration::from_mins(35), ram_scratch_now())
            .unwrap_err();
        assert!(
            error.to_string().contains("total detail byte budget"),
            "{error}"
        );
    }

    #[test]
    fn ram_scratch_notice_payload_budget_is_bytes_and_keeps_the_exact_boundary() {
        let (_dir, db) = temp_db();
        let mut payload = ram_scratch_payload("recovered");
        payload["detail"] = serde_json::json!("");
        let overhead = payload.to_string().len();
        payload["detail"] =
            serde_json::json!("x".repeat(RAM_SCRATCH_NOTICE_MAX_PAYLOAD_BYTES - overhead));
        let exact = payload.to_string();
        assert_eq!(exact.len(), RAM_SCRATCH_NOTICE_MAX_PAYLOAD_BYTES);
        insert_notice_rows(&db, "2026-11-04T11:59:30Z", &exact, 1);
        let engine = StatsEngine::new(&db);
        assert!(
            engine
                .ram_scratch_notice_at(Duration::from_mins(35), ram_scratch_now())
                .unwrap()
                .is_some()
        );
        payload["detail"] = serde_json::json!("é".repeat(RAM_SCRATCH_NOTICE_MAX_PAYLOAD_BYTES / 2));
        let oversized = payload.to_string();
        assert!(oversized.chars().count() < RAM_SCRATCH_NOTICE_MAX_PAYLOAD_BYTES);
        assert!(oversized.len() > RAM_SCRATCH_NOTICE_MAX_PAYLOAD_BYTES);
        insert_notice_rows(&db, "2026-11-04T11:59:45Z", &oversized, 1);
        let error = engine
            .ram_scratch_notice_at(Duration::from_mins(35), ram_scratch_now())
            .unwrap_err();
        assert!(
            error.to_string().contains("activity payload byte budget"),
            "{error}"
        );
    }

    fn scan_complete_row(timestamp: String, details: Option<String>) -> ActivityRow {
        ActivityRow {
            timestamp,
            event_type: "scan_complete".to_string(),
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
            details,
        }
    }

    #[test]
    fn scanner_stats_aggregates_cpu_by_day() {
        let (_dir, db) = temp_db();
        let now = chrono::Utc::now();
        let fmt = |t: chrono::DateTime<chrono::Utc>| {
            t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        };
        db.log_activity(&scan_complete_row(
            fmt(now),
            Some("paths_scanned=10 candidates=0 process_cpu_micros=1000000".to_string()),
        ))
        .unwrap();
        db.log_activity(&scan_complete_row(
            fmt(now),
            Some(
                "paths_scanned=5 candidates=0 process_cpu_micros=500000 opaque_pruned_dirs=2"
                    .to_string(),
            ),
        ))
        .unwrap();
        db.log_activity(&scan_complete_row(
            fmt(now),
            Some("paths_scanned=3 candidates=0".to_string()),
        ))
        .unwrap();
        db.log_activity(&scan_complete_row(
            fmt(now - chrono::Duration::hours(25)),
            Some("paths_scanned=7 candidates=0 process_cpu_micros=2000000".to_string()),
        ))
        .unwrap();
        db.log_activity(&scan_complete_row(
            fmt(now - chrono::Duration::hours(24 * 30)),
            Some("paths_scanned=99 candidates=0 process_cpu_micros=1".to_string()),
        ))
        .unwrap();

        let engine = StatsEngine::new(&db);
        let days = engine.scanner_stats(Duration::from_hours(24 * 7)).unwrap();
        assert_eq!(days.len(), 2, "{days:?}");

        let older = &days[0];
        assert_eq!(older.passes, 1);
        assert!(
            (older.cpu_seconds - 2.0).abs() < 1e-9,
            "{}",
            older.cpu_seconds
        );
        assert_eq!(older.entries_scanned, 7);

        let today = &days[1];
        assert_eq!(today.passes, 3);
        assert!(
            (today.cpu_seconds - 1.5).abs() < 1e-9,
            "{}",
            today.cpu_seconds
        );
        assert_eq!(today.entries_scanned, 18);
        assert_eq!(today.opaque_pruned_dirs, 2);
        assert_eq!(today.passes_without_cpu_evidence, 1);
    }
    #[test]
    fn deletion_stats_computed_correctly() {
        let (_dir, db) = temp_db();
        // Insert 5 successful deletions in the last 5 minutes.
        let samples = [
            (1_i64, 1_000_000_i64, 0.80_f64),
            (2, 2_000_000, 0.82),
            (3, 3_000_000, 0.84),
            (4, 4_000_000, 0.86),
            (5, 5_000_000, 0.88),
        ];
        for &(minutes_ago, size, score) in &samples {
            db.log_activity(&ActivityRow {
                timestamp: ts(minutes_ago),
                event_type: "artifact_delete".to_string(),
                severity: "info".to_string(),
                path: Some(format!("/data/p{minutes_ago}/.target_opus")),
                size_bytes: Some(size),
                score: Some(score),
                score_factors: None,
                pressure_level: Some("orange".to_string()),
                free_pct: Some(8.0),
                duration_ms: Some(100),
                success: 1,
                error_code: None,
                error_message: None,
                details: None,
            })
            .unwrap();
        }
        // 1 failed deletion.
        db.log_activity(&ActivityRow {
            timestamp: ts(1),
            event_type: "artifact_delete".to_string(),
            severity: "warning".to_string(),
            path: Some("/data/fail/target".to_string()),
            size_bytes: None,
            score: None,
            score_factors: None,
            pressure_level: None,
            free_pct: None,
            duration_ms: None,
            success: 0,
            error_code: Some("SBH-2100".to_string()),
            error_message: Some("permission denied".to_string()),
            details: None,
        })
        .unwrap();

        let engine = StatsEngine::new(&db);
        let ws = engine.window_stats(Duration::from_mins(10)).unwrap();

        assert_eq!(ws.deletions.count, 5);
        assert_eq!(ws.deletions.total_bytes_freed, 15_000_000);
        assert_eq!(ws.deletions.avg_size, 3_000_000);
        assert_eq!(ws.deletions.median_size, 3_000_000);
        assert_eq!(ws.deletions.failures, 1);
        assert!(ws.deletions.largest_deletion.is_some());
        assert_eq!(
            ws.deletions.largest_deletion.as_ref().unwrap().size_bytes,
            5_000_000
        );
        assert_eq!(
            ws.deletions.most_common_category.as_deref(),
            Some(".target*")
        );
    }

    #[test]
    fn quarantine_finalization_frees_bytes_without_counting_a_second_decision() {
        use crate::logger::dual::ActivityEvent;
        use crate::scanner::quarantine::{QuarantineCompletion, QuarantineRecord};
        use std::time::SystemTime;

        let (_dir, db) = temp_db();
        for (path, bytes, details) in [
            ("/cache/unlinked", 256, None),
            (
                "/cache/held",
                4096,
                Some("decision_id=0123456789ab;quarantined"),
            ),
        ] {
            db.log_activity(&ActivityRow {
                timestamp: ts(5),
                event_type: "artifact_delete".to_string(),
                severity: "info".to_string(),
                path: Some(path.to_string()),
                size_bytes: Some(bytes),
                score: Some(0.97),
                score_factors: None,
                pressure_level: None,
                free_pct: None,
                duration_ms: None,
                success: 1,
                error_code: None,
                error_message: None,
                details: details.map(str::to_string),
            })
            .unwrap();
        }
        let purge = |path: &str, size_bytes, completed_at| {
            ActivityEvent::QuarantinePurged(Box::new(QuarantineCompletion {
                record: QuarantineRecord {
                    decision_id: "0123456789ab".to_string(),
                    original_path: path.into(),
                    quarantine_path: "/quarantine/0123456789ab/held".into(),
                    device_id: 7,
                    inode: 11,
                    size_bytes,
                    quarantined_at: 1,
                    expires_at: 2,
                    decision: None,
                },
                completed_at,
            }))
        };
        let now = SystemTime::now();
        for event in [
            purge("/cache/held", 4096, now - Duration::from_mins(3)),
            purge("/cache/zero", 0, now - Duration::from_mins(2)),
            // Logging an older completion now must not move it into this window.
            purge("/cache/old", 8192, now - Duration::from_hours(48)),
        ] {
            db.log_activity_event(&event).unwrap();
        }
        let mut failed =
            crate::logger::dual::event_to_activity_row(&purge("/cache/failed", 1_000_000, now))
                .unwrap();
        failed.success = 0;
        db.log_activity(&failed).unwrap();

        let engine = StatsEngine::new(&db);
        let stats = engine.window_stats(Duration::from_mins(10)).unwrap();
        assert_eq!(stats.deletions.count, 2);
        assert_eq!(stats.deletions.quarantined_count, 1);
        assert_eq!(stats.deletions.quarantined_bytes, 4096);
        assert_eq!(stats.deletions.purged_count, 2);
        assert_eq!(stats.deletions.purged_bytes, 4096);
        assert_eq!(stats.deletions.total_bytes_freed, 4352);
        assert_eq!(stats.deletions.avg_size, 2176);
        assert_eq!(stats.deletions.failures, 0);
        let exported = engine.export_json().unwrap();
        let deletions = &exported["windows"][0]["deletions"];
        assert_eq!(deletions["count"], 2);
        assert_eq!(deletions["purged_count"], 2);
        assert_eq!(deletions["purged_bytes"], 4096);
        assert_eq!(deletions["total_bytes_freed"], 4352);
    }

    /// Policy transitions, failures by reason and the age at deletion all
    /// come from rows the daemon writes, not from placeholders.
    #[test]
    fn policy_failures_and_age_come_from_real_rows() {
        let dir = tempfile::tempdir().unwrap();
        let db = SqliteLogger::open(&dir.path().join("stats.db")).unwrap();
        let now = chrono::Utc::now();
        let ts = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let failure = |code: Option<&str>| ActivityRow {
            timestamp: ts.clone(),
            event_type: "artifact_delete".to_string(),
            severity: "warning".to_string(),
            path: Some("/p/target".to_string()),
            size_bytes: None,
            score: None,
            score_factors: None,
            pressure_level: None,
            free_pct: None,
            duration_ms: None,
            success: 0,
            error_code: code.map(str::to_string),
            error_message: None,
            details: None,
        };
        db.log_activity(&failure(Some("SBH-2003"))).unwrap();
        db.log_activity(&failure(Some("SBH-2003"))).unwrap();
        db.log_activity(&failure(Some("SBH-3002"))).unwrap();
        db.log_activity(&failure(None)).unwrap();
        for (i, details) in ["promote: observe -> canary", "promote: canary -> enforce"]
            .iter()
            .enumerate()
        {
            db.log_activity(&ActivityRow {
                timestamp: (now
                    + chrono::Duration::milliseconds(i64::try_from(i).unwrap_or(i64::MAX)))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                event_type: "policy_transition".to_string(),
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
                details: Some((*details).to_string()),
            })
            .unwrap();
        }
        // Two approved deletions aged 1 h and 3 h, one keep that must not count.
        for (id, action, age_secs) in [
            ("d1", "DELETE", 3600),
            ("d2", "DELETE", 10800),
            ("d3", "KEEP", 99999),
        ] {
            db.connection()
                .execute(
                    "INSERT INTO decision_log (decision_id, timestamp, path, action, policy_mode, \
                     total_score, posterior_abandoned, expected_loss_keep, expected_loss_delete, record) \
                     VALUES (?1, ?2, '/p', ?3, 'enforce', 0.9, 0.9, 1.0, 0.1, ?4)",
                    params![id, ts, action, format!(r#"{{"age_secs":{age_secs}}}"#)],
                )
                .unwrap();
        }

        let engine = StatsEngine::new(&db);
        let ws = engine.window_stats(Duration::from_hours(1)).unwrap();
        assert_eq!(ws.deletions.failures, 4);
        assert_eq!(
            ws.deletions.failures_by_reason,
            vec![
                FailureReason {
                    code: "SBH-2003".to_string(),
                    count: 2
                },
                FailureReason {
                    code: "SBH-3002".to_string(),
                    count: 1
                },
                FailureReason {
                    code: "unknown".to_string(),
                    count: 1
                },
            ]
        );
        assert!(
            (ws.deletions.avg_age_hours - 2.0).abs() < 1e-9,
            "{}",
            ws.deletions.avg_age_hours
        );
        assert_eq!(ws.policy.transitions, 2);
        assert_eq!(
            ws.policy.last_transition.as_deref(),
            Some("promote: canary -> enforce")
        );
    }

    #[test]
    fn ballast_stats_from_inventory() {
        let (_dir, db) = temp_db();
        // 3 ballast files: 2 available, 1 released.
        for i in 1..=3 {
            db.upsert_ballast(&BallastRow {
                file_index: i,
                path: format!("/var/lib/sbh/ballast/SBH_BALLAST_FILE_{i:05}.dat"),
                size_bytes: 1_073_741_824,
                created_at: ts(60),
                released_at: if i == 3 { Some(ts(5)) } else { None },
                replenished_at: None,
                integrity_hash: None,
            })
            .unwrap();
        }

        // 1 release event and 1 replenish event.
        db.log_activity(&ActivityRow {
            timestamp: ts(5),
            event_type: "ballast_release".to_string(),
            severity: "info".to_string(),
            path: Some("/var/lib/sbh/ballast/SBH_BALLAST_FILE_00003.dat".to_string()),
            size_bytes: Some(1_073_741_824),
            score: None,
            score_factors: None,
            pressure_level: Some("red".to_string()),
            free_pct: Some(4.0),
            duration_ms: None,
            success: 1,
            error_code: None,
            error_message: None,
            details: None,
        })
        .unwrap();

        let engine = StatsEngine::new(&db);
        let ws = engine.window_stats(Duration::from_hours(1)).unwrap();

        assert_eq!(ws.ballast.files_released, 1);
        assert_eq!(ws.ballast.current_inventory, 2);
        assert_eq!(ws.ballast.bytes_available, 2 * 1_073_741_824);
    }

    #[test]
    fn pressure_stats_time_in_level() {
        let (_dir, db) = temp_db();
        // Simulate: green for 5 min, then orange for 3 min, then green for 2 min.
        let samples = [
            (8_i64, "green", 25.0_f64, 125_000_000_000_i64),
            (3, "orange", 7.0, 35_000_000_000),
            (1, "green", 22.0, 110_000_000_000),
        ];
        for &(mins_ago, level, free_pct, free_bytes) in &samples {
            db.log_pressure(&PressureRow {
                timestamp: ts(mins_ago),
                mount_point: "/data".to_string(),
                total_bytes: 500_000_000_000,
                free_bytes,
                free_pct,
                rate_bytes_per_sec: None,
                pressure_level: level.to_string(),
                ewma_rate: None,
                pid_output: None,
            })
            .unwrap();
        }

        let engine = StatsEngine::new(&db);
        let ws = engine.window_stats(Duration::from_mins(10)).unwrap();

        // 2 transitions: green->orange, orange->green.
        assert_eq!(ws.pressure.transitions, 2);
        assert_eq!(ws.pressure.worst_level_reached, PressureLevel::Orange);
        assert_eq!(ws.pressure.current_level, PressureLevel::Green);

        // Time proportions: green ~5min, orange ~2min out of 7min total.
        // (ts(8)->ts(3) = 5min green, ts(3)->ts(1) = 2min orange)
        let green = ws.pressure.time_in_green_pct;
        let orange = ws.pressure.time_in_orange_pct;
        assert!(green > 60.0, "green={green} should be >60%");
        assert!(orange > 20.0, "orange={orange} should be >20%");
        assert!((green + orange - 100.0).abs() < 1.0);
    }

    #[test]
    fn top_patterns_ranking() {
        let (_dir, db) = temp_db();
        // 3 .target* deletions, 2 target/ deletions, 1 cargo-target-*.
        let paths = [
            "/data/p1/.target_opus",
            "/data/p2/.target_a",
            "/data/p3/.target_b",
            "/data/p4/target",
            "/data/p5/target",
            "/data/p6/cargo-target-foo",
        ];
        for (minutes_ago, path) in (1_i64..).zip(paths.iter()) {
            db.log_activity(&ActivityRow {
                timestamp: ts(minutes_ago),
                event_type: "artifact_delete".to_string(),
                severity: "info".to_string(),
                path: Some(path.to_string()),
                size_bytes: Some(1_000_000),
                score: Some(0.85),
                score_factors: None,
                pressure_level: None,
                free_pct: None,
                duration_ms: None,
                success: 1,
                error_code: None,
                error_message: None,
                details: None,
            })
            .unwrap();
        }

        let engine = StatsEngine::new(&db);
        let patterns = engine.top_patterns(3, Duration::from_hours(1)).unwrap();

        assert_eq!(patterns.len(), 3);
        assert_eq!(patterns[0].pattern, ".target*");
        assert_eq!(patterns[0].count, 3);
        assert_eq!(patterns[1].pattern, "target/");
        assert_eq!(patterns[1].count, 2);
        assert_eq!(patterns[2].pattern, "cargo-target-*");
        assert_eq!(patterns[2].count, 1);
    }

    #[test]
    fn top_deletions_by_size() {
        let (_dir, db) = temp_db();
        for i in 0_i64..5_i64 {
            db.log_activity(&ActivityRow {
                timestamp: ts(i + 1),
                event_type: "artifact_delete".to_string(),
                severity: "info".to_string(),
                path: Some(format!("/data/p{i}/target")),
                size_bytes: Some(1_000_000 * (i + 1)),
                score: Some(0.8),
                score_factors: None,
                pressure_level: None,
                free_pct: None,
                duration_ms: None,
                success: 1,
                error_code: None,
                error_message: None,
                details: None,
            })
            .unwrap();
        }

        let engine = StatsEngine::new(&db);
        let top = engine.top_deletions(3, Duration::from_hours(1)).unwrap();

        assert_eq!(top.len(), 3);
        assert_eq!(top[0].size_bytes, 5_000_000);
        assert_eq!(top[1].size_bytes, 4_000_000);
        assert_eq!(top[2].size_bytes, 3_000_000);
    }

    #[test]
    fn export_json_well_formed() {
        let (_dir, db) = temp_db();
        let engine = StatsEngine::new(&db);
        let json = engine.export_json().unwrap();
        let windows = json.get("windows").unwrap().as_array().unwrap();
        assert_eq!(windows.len(), STANDARD_WINDOWS.len());
        // Each window has the expected fields.
        let first = &windows[0];
        assert!(first.get("window_secs").is_some());
        assert!(first.get("window_label").is_some());
        assert!(first.get("deletions").is_some());
        assert!(first.get("ballast").is_some());
        assert!(first.get("pressure").is_some());
    }

    #[test]
    fn window_label_formatting() {
        assert_eq!(window_label(Duration::from_mins(10)), "10 min");
        assert_eq!(window_label(Duration::from_mins(30)), "30 min");
        assert_eq!(window_label(Duration::from_hours(1)), "1 hour");
        assert_eq!(window_label(Duration::from_hours(6)), "6 hours");
        assert_eq!(window_label(Duration::from_hours(24)), "1 day");
        assert_eq!(window_label(Duration::from_hours(72)), "3 days");
        assert_eq!(window_label(Duration::from_hours(168)), "7 days");
    }

    #[test]
    fn extract_pattern_known_names() {
        assert_eq!(extract_pattern("/data/foo/target"), "target/");
        assert_eq!(extract_pattern("/data/foo/target-bar"), "target/");
        assert_eq!(extract_pattern("/data/foo/.target_opus"), ".target*");
        assert_eq!(extract_pattern("/data/foo/_target_old"), ".target*");
        assert_eq!(
            extract_pattern("/data/foo/cargo-target-baz"),
            "cargo-target-*"
        );
        assert_eq!(extract_pattern("/data/foo/pi_agent_1"), "pi_*");
        assert_eq!(extract_pattern("/data/foo/node_modules"), "node_modules/");
        assert_eq!(extract_pattern("/data/foo/random_dir"), "random_dir");
    }
}
