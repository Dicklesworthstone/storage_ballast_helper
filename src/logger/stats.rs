//! Stats query engine: aggregation queries over logged events for the stats command.
//!
//! Provides time-window aggregation across `activity_log`, `pressure_history`,
//! and `ballast_inventory` tables. All queries operate on a borrowed `SqliteLogger`
//! connection — the stats engine is a read-only view over the logging database.

#![allow(missing_docs)]

use std::collections::HashMap;
use std::time::Duration;

use rusqlite::params;

use crate::core::errors::Result;
use crate::logger::sqlite::SqliteLogger;

// ──────────────────── standard time windows ────────────────────

/// The standard time windows used for aggregation.
pub const STANDARD_WINDOWS: &[Duration] = &[
    Duration::from_secs(10 * 60),          // 10 minutes
    Duration::from_secs(30 * 60),          // 30 minutes
    Duration::from_secs(60 * 60),          // 1 hour
    Duration::from_secs(6 * 60 * 60),      // 6 hours
    Duration::from_secs(24 * 60 * 60),     // 24 hours
    Duration::from_secs(3 * 24 * 60 * 60), // 3 days
    Duration::from_secs(7 * 24 * 60 * 60), // 7 days
];

// ──────────────────── stat types ────────────────────

/// Aggregated statistics for a single time window.
#[derive(Debug, Clone)]
pub struct WindowStats {
    pub window: Duration,
    pub deletions: DeletionStats,
    pub ballast: BallastStats,
    pub pressure: PressureStats,
}

/// Deletion activity within a time window.
#[derive(Debug, Clone, Default)]
pub struct DeletionStats {
    pub count: u64,
    pub total_bytes_freed: u64,
    pub avg_size: u64,
    pub median_size: u64,
    pub largest_deletion: Option<PathInfo>,
    pub most_common_category: Option<String>,
    pub avg_score: f64,
    pub avg_age_hours: f64,
    pub failures: u64,
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

    /// Get stats for a specific time window.
    pub fn window_stats(&self, window: Duration) -> Result<WindowStats> {
        let since = since_timestamp(window);
        Ok(WindowStats {
            window,
            deletions: self.deletion_stats(&since)?,
            ballast: self.ballast_stats(&since)?,
            pressure: self.pressure_stats(&since)?,
        })
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
                    count: row.get(1)?,
                    total_bytes: row.get::<_, i64>(2).unwrap_or(0) as u64,
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
                    size_bytes: row.get::<_, i64>(1).map(|v| v as u64).unwrap_or(0),
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
                        "avg_size": w.deletions.avg_size,
                        "median_size": w.deletions.median_size,
                        "largest_deletion": w.deletions.largest_deletion.as_ref().map(|p| {
                            serde_json::json!({"path": p.path, "size_bytes": p.size_bytes})
                        }),
                        "most_common_category": w.deletions.most_common_category,
                        "avg_score": w.deletions.avg_score,
                        "failures": w.deletions.failures,
                    },
                    "ballast": {
                        "files_released": w.ballast.files_released,
                        "files_replenished": w.ballast.files_replenished,
                        "current_inventory": w.ballast.current_inventory,
                        "bytes_available": w.ballast.bytes_available,
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

        Ok(serde_json::json!({ "windows": json_windows }))
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
                        size_bytes: row.get::<_, i64>(1).map(|v| v as u64).unwrap_or(0),
                    })
                },
            )
            .ok();

        // Most common category (extract from path directory name).
        let most_common = self.most_common_deleted_pattern(since)?;

        // Failed deletions.
        let failures: i64 = conn.query_row(
            "SELECT COUNT(*) FROM activity_log
             WHERE event_type = 'artifact_delete' AND success = 0
               AND timestamp >= ?1",
            params![since],
            |row| row.get(0),
        )?;

        Ok(DeletionStats {
            count: count.max(0) as u64,
            total_bytes_freed: total.max(0) as u64,
            avg_size: avg_size as u64,
            median_size,
            largest_deletion: largest,
            most_common_category: most_common,
            avg_score,
            avg_age_hours: 0.0, // Age at deletion not stored in current schema
            failures: failures.max(0) as u64,
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

        // Get pressure history samples ordered by time.
        let mut stmt = conn.prepare(
            "SELECT timestamp, pressure_level, free_pct FROM pressure_history
             WHERE timestamp >= ?1
             ORDER BY timestamp ASC",
        )?;

        let samples: Vec<(String, String, f64)> = stmt
            .query_map(params![since], |row| {
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
            let dt = timestamp_delta_secs(&samples[i].0, &samples[i + 1].0);

            *level_time.entry(current_level).or_insert(0.0) += dt;

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
        let last_dt = timestamp_delta_secs(&samples[samples.len() - 1].0, &now_str);
        if last_dt > 0.0 {
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

// ──────────────────── utility functions ────────────────────

/// Compute an ISO 8601 timestamp for "now minus duration".
#[allow(clippy::cast_possible_wrap)]
fn since_timestamp(window: Duration) -> String {
    let now = chrono::Utc::now();
    let since = now - chrono::Duration::from_std(window).unwrap_or(chrono::Duration::max_value());
    since.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Compute approximate seconds between two ISO 8601 timestamps.
#[allow(clippy::cast_precision_loss)]
fn timestamp_delta_secs(a: &str, b: &str) -> f64 {
    let parse = |s: &str| chrono::DateTime::parse_from_rfc3339(s).ok();
    match (parse(a), parse(b)) {
        (Some(ta), Some(tb)) => (tb - ta).num_milliseconds() as f64 / 1000.0,
        _ => 0.0,
    }
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
        let ws = engine.window_stats(Duration::from_secs(10 * 60)).unwrap();

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
        let ws = engine.window_stats(Duration::from_secs(60 * 60)).unwrap();

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
        let ws = engine.window_stats(Duration::from_secs(10 * 60)).unwrap();

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
        let patterns = engine
            .top_patterns(3, Duration::from_secs(60 * 60))
            .unwrap();

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
        let top = engine
            .top_deletions(3, Duration::from_secs(60 * 60))
            .unwrap();

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
        assert_eq!(window_label(Duration::from_secs(600)), "10 min");
        assert_eq!(window_label(Duration::from_secs(1800)), "30 min");
        assert_eq!(window_label(Duration::from_secs(3600)), "1 hour");
        assert_eq!(window_label(Duration::from_secs(21600)), "6 hours");
        assert_eq!(window_label(Duration::from_secs(86400)), "1 day");
        assert_eq!(window_label(Duration::from_secs(259_200)), "3 days");
        assert_eq!(window_label(Duration::from_secs(604_800)), "7 days");
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
