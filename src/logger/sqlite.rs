//! SQLite logger: WAL-mode database for structured event storage and querying.
//!
//! Uses Write-Ahead Logging for concurrent read/write, prepared statements for
//! insert throughput, and graceful degradation when the disk is too full to write.

#![allow(missing_docs)]

use std::path::{Path, PathBuf};

use rusqlite::functions::FunctionFlags;
use rusqlite::{Connection, OpenFlags, params};

use crate::core::errors::{Result, SbhError};
use crate::scanner::decision_record::DecisionRecord;

/// SQLite activity logger with WAL mode and prepared-statement patterns.
pub struct SqliteLogger {
    conn: Connection,
    path: PathBuf,
}

/// A row of `decision_outcome`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct StoredOutcome {
    pub decision_id: String,
    pub path: String,
    pub category: String,
    pub certainty: String,
    pub outcome: String,
    /// RFC 3339.
    pub observed_at: String,
    pub after_secs: u64,
    pub detail: String,
}

fn stored_outcome_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredOutcome> {
    Ok(StoredOutcome {
        decision_id: row.get(0)?,
        path: row.get(1)?,
        category: row.get(2)?,
        certainty: row.get(3)?,
        outcome: row.get(4)?,
        observed_at: row.get(5)?,
        after_secs: u64::try_from(row.get::<_, i64>(6)?).unwrap_or(0),
        detail: row.get(7)?,
    })
}

impl SqliteLogger {
    /// Open (or create) the database at `path`, applying schema and PRAGMAs.
    pub fn open(path: &Path) -> Result<Self> {
        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| SbhError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        // Register custom functions.
        conn.create_scalar_function(
            "extract_pattern",
            1,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
            move |ctx| {
                let path: String = ctx.get(0)?;
                Ok(crate::scanner::patterns::extract_pattern_label(&path))
            },
        )?;

        // Opening does not change an existing file's size; a new database is
        // still empty here, so it gets `auto_vacuum = FULL` before its schema.
        let db_bytes = std::fs::metadata(path).map_or(0, |m| m.len());
        apply_pragmas(&conn, db_bytes)?;
        apply_schema(&conn)?;

        Ok(Self {
            conn,
            path: path.to_path_buf(),
        })
    }

    /// Open an existing database read-only for CLI queries (`stats`, `status`,
    /// `tune`, `explain`).
    ///
    /// Read-side commands must never open the daemon's database with
    /// `READ_WRITE | CREATE`: an unprivileged `sbh stats` against a root-owned
    /// database then fails with "attempt to write a readonly database", and a
    /// typo'd path silently creates an empty database. This opener creates
    /// nothing, applies no schema, and sets `query_only` so a query that tries
    /// to write fails loudly.
    pub fn open_read_only(path: &Path) -> Result<Self> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        conn.create_scalar_function(
            "extract_pattern",
            1,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
            move |ctx| {
                let path: String = ctx.get(0)?;
                Ok(crate::scanner::patterns::extract_pattern_label(&path))
            },
        )?;
        conn.pragma_update(None, "query_only", 1)?;

        Ok(Self {
            conn,
            path: path.to_path_buf(),
        })
    }

    /// Path to the database file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    // ──────────────────── activity_log ────────────────────

    /// Insert a row into `activity_log`.
    pub fn log_activity(&self, row: &ActivityRow) -> Result<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO activity_log (
                timestamp, event_type, severity, path, size_bytes, score,
                score_factors, pressure_level, free_pct, duration_ms,
                success, error_code, error_message, details
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            )?
            .execute(params![
                row.timestamp,
                row.event_type,
                row.severity,
                row.path,
                row.size_bytes,
                row.score,
                row.score_factors,
                row.pressure_level,
                row.free_pct,
                row.duration_ms,
                row.success,
                row.error_code,
                row.error_message,
                row.details,
            ])?;
        Ok(())
    }

    /// Query recent activity entries, newest first.
    pub fn recent_activity(&self, limit: u32) -> Result<Vec<ActivityRow>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT timestamp, event_type, severity, path, size_bytes, score,
                    score_factors, pressure_level, free_pct, duration_ms,
                    success, error_code, error_message, details
             FROM activity_log ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit], |row| {
                Ok(ActivityRow {
                    timestamp: row.get(0)?,
                    event_type: row.get(1)?,
                    severity: row.get(2)?,
                    path: row.get(3)?,
                    size_bytes: row.get(4)?,
                    score: row.get(5)?,
                    score_factors: row.get(6)?,
                    pressure_level: row.get(7)?,
                    free_pct: row.get(8)?,
                    duration_ms: row.get(9)?,
                    success: row.get(10)?,
                    error_code: row.get(11)?,
                    error_message: row.get(12)?,
                    details: row.get(13)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // ──────────────────── pressure_history ────────────────────

    /// Insert a pressure sample.
    pub fn log_pressure(&self, row: &PressureRow) -> Result<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO pressure_history (
                timestamp, mount_point, total_bytes, free_bytes, free_pct,
                rate_bytes_per_sec, pressure_level, ewma_rate, pid_output
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            )?
            .execute(params![
                row.timestamp,
                row.mount_point,
                row.total_bytes,
                row.free_bytes,
                row.free_pct,
                row.rate_bytes_per_sec,
                row.pressure_level,
                row.ewma_rate,
                row.pid_output,
            ])?;
        Ok(())
    }

    /// Query pressure history for a mount point, newest first.
    pub fn pressure_since(
        &self,
        mount_point: &str,
        since: &str,
        limit: u32,
    ) -> Result<Vec<PressureRow>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT timestamp, mount_point, total_bytes, free_bytes, free_pct,
                    rate_bytes_per_sec, pressure_level, ewma_rate, pid_output
             FROM pressure_history
             WHERE mount_point = ?1 AND timestamp >= ?2
             ORDER BY id DESC LIMIT ?3",
        )?;
        let rows = stmt
            .query_map(params![mount_point, since, limit], |row| {
                Ok(PressureRow {
                    timestamp: row.get(0)?,
                    mount_point: row.get(1)?,
                    total_bytes: row.get(2)?,
                    free_bytes: row.get(3)?,
                    free_pct: row.get(4)?,
                    rate_bytes_per_sec: row.get(5)?,
                    pressure_level: row.get(6)?,
                    ewma_rate: row.get(7)?,
                    pid_output: row.get(8)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Delete pressure_history rows older than `retention_days`.
    ///
    /// Returns the number of rows deleted. Should be called periodically
    /// (e.g., once per hour) to prevent unbounded table growth.
    pub fn prune_pressure_history(&self, retention_days: u32) -> Result<usize> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(i64::from(retention_days));
        let cutoff_str = cutoff.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let deleted = self.conn.execute(
            "DELETE FROM pressure_history WHERE timestamp < ?1",
            params![cutoff_str],
        )?;
        Ok(deleted)
    }

    /// Delete activity_log rows older than `retention_days`.
    pub fn prune_activity_log(&self, retention_days: u32) -> Result<usize> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(i64::from(retention_days));
        let cutoff_str = cutoff.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let deleted = self.conn.execute(
            "DELETE FROM activity_log WHERE timestamp < ?1",
            params![cutoff_str],
        )?;
        Ok(deleted)
    }

    // ──────────────────── decision_log (evidence ledger) ────────────────────

    /// Append a decision record to the evidence ledger.
    ///
    /// Indexed columns are denormalized for querying; `record` holds the
    /// full JSON so `sbh explain` can render every level from one row.
    pub fn log_decision(&self, record: &DecisionRecord) -> Result<()> {
        let payload = serde_json::to_string(record).map_err(|e| SbhError::Serialization {
            context: "decision record",
            details: e.to_string(),
        })?;
        self.conn
            .prepare_cached(
                "INSERT INTO decision_log (
                    decision_id, timestamp, path, action, effective_action, policy_mode,
                    total_score, posterior_abandoned, expected_loss_keep,
                    expected_loss_delete, vetoed, veto_reason, record
                ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            )?
            .execute(params![
                record.id,
                record.timestamp,
                record.path.to_string_lossy().to_string(),
                record.action.to_string(),
                record.effective_action.as_ref().map(ToString::to_string),
                record.policy_mode.to_string(),
                record.total_score,
                record.posterior_abandoned,
                record.expected_loss_keep,
                record.expected_loss_delete,
                i32::from(record.vetoed),
                record.veto_reason,
                payload,
            ])?;
        Ok(())
    }

    /// Record what became of a deletion (regret label).
    pub fn log_outcome(&self, outcome: &crate::scanner::regret::DecisionOutcome) -> Result<()> {
        let observed_at =
            chrono::DateTime::from_timestamp(i64::try_from(outcome.observed_at).unwrap_or(0), 0)
                .unwrap_or_default()
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.conn
            .prepare_cached(
                "INSERT INTO decision_outcome (
                    decision_id, path, category, certainty, outcome, observed_at, after_secs, detail
                ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            )?
            .execute(params![
                outcome.decision_id,
                outcome.path.to_string_lossy().to_string(),
                outcome.category,
                outcome.certainty,
                outcome.outcome.as_str(),
                observed_at,
                i64::try_from(outcome.after_secs).unwrap_or(i64::MAX),
                outcome.detail,
            ])?;
        Ok(())
    }

    /// The outcomes recorded for a decision id, oldest first.
    pub fn outcomes_for_decision(&self, decision_id: &str) -> Result<Vec<StoredOutcome>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT decision_id, path, category, certainty, outcome, observed_at, after_secs, detail
             FROM decision_outcome WHERE decision_id = ?1 ORDER BY id ASC",
        )?;
        let rows = stmt.query_map(params![decision_id], stored_outcome_from_row)?;
        Ok(rows.filter_map(std::result::Result::ok).collect())
    }

    /// Every outcome observed at or after `since` (RFC 3339), oldest first.
    pub fn outcomes_since(&self, since: &str) -> Result<Vec<StoredOutcome>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT decision_id, path, category, certainty, outcome, observed_at, after_secs, detail
             FROM decision_outcome WHERE observed_at >= ?1 ORDER BY id ASC",
        )?;
        let rows = stmt.query_map(params![since], stored_outcome_from_row)?;
        Ok(rows.filter_map(std::result::Result::ok).collect())
    }

    /// The most recent decision with this stable id, plus how many records
    /// share it (an unchanged artifact re-decided over time).
    pub fn decision_by_id(&self, decision_id: &str) -> Result<Option<(DecisionRecord, usize)>> {
        let count: usize = self.conn.query_row(
            "SELECT COUNT(*) FROM decision_log WHERE decision_id = ?1",
            params![decision_id],
            |row| {
                row.get::<_, i64>(0)
                    .map(|n| usize::try_from(n).unwrap_or(0))
            },
        )?;
        if count == 0 {
            return Ok(None);
        }
        let mut stmt = self.conn.prepare_cached(
            "SELECT record FROM decision_log WHERE decision_id = ?1 ORDER BY id DESC LIMIT 1",
        )?;
        let record = stmt
            .query_row(params![decision_id], |row| row.get::<_, String>(0))
            .ok()
            .and_then(|json| serde_json::from_str::<DecisionRecord>(&json).ok());
        Ok(record.map(|record| (record, count)))
    }

    /// The `limit` most recent decisions, newest first.
    pub fn recent_decisions(&self, limit: u32) -> Result<Vec<DecisionRecord>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT record FROM decision_log ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map(params![limit], |row| row.get::<_, String>(0))?;
        Ok(rows
            .filter_map(std::result::Result::ok)
            .filter_map(|json| serde_json::from_str(&json).ok())
            .collect())
    }

    /// Decisions recorded for exactly this path, newest first.
    pub fn decisions_for_path(&self, path: &str, limit: u32) -> Result<Vec<DecisionRecord>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT record FROM decision_log WHERE path = ?1 ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![path, limit], |row| row.get::<_, String>(0))?;
        Ok(rows
            .filter_map(std::result::Result::ok)
            .filter_map(|json| serde_json::from_str(&json).ok())
            .collect())
    }

    /// Decisions with a timestamp at or after `since` (RFC 3339), newest first.
    pub fn decisions_since(&self, since: &str, limit: u32) -> Result<Vec<DecisionRecord>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT record FROM decision_log WHERE timestamp >= ?1 ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![since, limit], |row| row.get::<_, String>(0))?;
        Ok(rows
            .filter_map(std::result::Result::ok)
            .filter_map(|json| serde_json::from_str(&json).ok())
            .collect())
    }

    /// Delete decision_log rows older than `retention_days`.
    pub fn prune_decision_log(&self, retention_days: u32) -> Result<usize> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(i64::from(retention_days));
        self.prune_decision_log_before(&cutoff.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
    }

    /// Delete decision_log rows whose timestamp sorts before `cutoff`
    /// (RFC 3339 UTC, as the records are written), returning the count.
    pub fn prune_decision_log_before(&self, cutoff: &str) -> Result<usize> {
        let deleted = self.conn.execute(
            "DELETE FROM decision_log WHERE timestamp < ?1",
            params![cutoff],
        )?;
        Ok(deleted)
    }

    // ──────────────────── ballast_inventory ────────────────────

    /// Upsert a ballast file record.
    pub fn upsert_ballast(&self, row: &BallastRow) -> Result<()> {
        self.conn
            .prepare_cached(
                "INSERT OR REPLACE INTO ballast_inventory (
                file_index, path, size_bytes, created_at, released_at,
                replenished_at, integrity_hash
            ) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            )?
            .execute(params![
                row.file_index,
                row.path,
                row.size_bytes,
                row.created_at,
                row.released_at,
                row.replenished_at,
                row.integrity_hash,
            ])?;
        Ok(())
    }

    /// Mark a ballast file as released. A file the inventory never saw
    /// (a pool provisioned before the daemon logged inventory rows) gets a
    /// row with only its release recorded, so counts stay truthful.
    pub fn mark_ballast_released(&self, path: &str, released_at: &str) -> Result<()> {
        let updated = self
            .conn
            .prepare_cached("UPDATE ballast_inventory SET released_at = ?1 WHERE path = ?2")?
            .execute(params![released_at, path])?;
        if updated == 0 {
            self.upsert_ballast(&BallastRow {
                file_index: ballast_index_from_path(path),
                path: path.to_string(),
                size_bytes: 0,
                created_at: released_at.to_string(),
                released_at: Some(released_at.to_string()),
                replenished_at: None,
                integrity_hash: None,
            })?;
        }
        Ok(())
    }

    /// Get all ballast file records.
    pub fn ballast_inventory(&self) -> Result<Vec<BallastRow>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT file_index, path, size_bytes, created_at, released_at,
                    replenished_at, integrity_hash
             FROM ballast_inventory ORDER BY file_index ASC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(BallastRow {
                    file_index: row.get(0)?,
                    path: row.get(1)?,
                    size_bytes: row.get(2)?,
                    created_at: row.get(3)?,
                    released_at: row.get(4)?,
                    replenished_at: row.get(5)?,
                    integrity_hash: row.get(6)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // ──────────────────── aggregate helpers ────────────────────

    /// Count activity entries of a given event_type since a timestamp.
    pub fn count_events_since(&self, event_type: &str, since: &str) -> Result<i64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM activity_log WHERE event_type = ?1 AND timestamp >= ?2",
            params![event_type, since],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Sum of bytes freed (size_bytes where success=1) for a given event_type since a timestamp.
    pub fn bytes_freed_since(&self, event_type: &str, since: &str) -> Result<i64> {
        let total: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM activity_log
             WHERE event_type = ?1 AND timestamp >= ?2 AND success = 1",
            params![event_type, since],
            |row| row.get(0),
        )?;
        Ok(total)
    }

    /// Borrow the underlying connection (for stats/query engines).
    /// `sbh undo`: the decision's entry left quarantine and is back at its
    /// original path. Returns the number of ledger rows updated.
    pub fn mark_decision_restored(&self, decision_id: &str) -> Result<usize> {
        Ok(self.connection().execute(
            "UPDATE decision_log SET effective_action = 'restored' WHERE decision_id = ?1",
            params![decision_id],
        )?)
    }

    pub(crate) fn connection(&self) -> &rusqlite::Connection {
        &self.conn
    }

    /// Check that WAL mode is active (for diagnostics).
    pub fn is_wal_mode(&self) -> bool {
        self.conn
            .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
            .is_ok_and(|mode| mode.eq_ignore_ascii_case("wal"))
    }
}

// ──────────────────── row types ────────────────────

/// Row for the `activity_log` table.
#[derive(Debug, Clone)]
pub struct ActivityRow {
    pub timestamp: String,
    pub event_type: String,
    pub severity: String,
    pub path: Option<String>,
    pub size_bytes: Option<i64>,
    pub score: Option<f64>,
    pub score_factors: Option<String>,
    pub pressure_level: Option<String>,
    pub free_pct: Option<f64>,
    pub duration_ms: Option<i64>,
    pub success: i32,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub details: Option<String>,
}

/// Row for the `pressure_history` table.
#[derive(Debug, Clone)]
pub struct PressureRow {
    pub timestamp: String,
    pub mount_point: String,
    pub total_bytes: i64,
    pub free_bytes: i64,
    pub free_pct: f64,
    pub rate_bytes_per_sec: Option<f64>,
    pub pressure_level: String,
    pub ewma_rate: Option<f64>,
    pub pid_output: Option<f64>,
}

/// The index a ballast file name carries (`SBH_BALLAST_FILE_00007.dat` is
/// 7); 0 when the name has none.
#[must_use]
pub fn ballast_index_from_path(path: &str) -> i32 {
    let name = path.rsplit('/').next().unwrap_or(path);
    let stem = name.strip_suffix(".dat").unwrap_or(name);
    let digits: String = stem
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    digits.parse().unwrap_or(0)
}

/// Row for the `ballast_inventory` table.
#[derive(Debug, Clone)]
pub struct BallastRow {
    pub file_index: i32,
    pub path: String,
    pub size_bytes: i64,
    pub created_at: String,
    pub released_at: Option<String>,
    pub replenished_at: Option<String>,
    pub integrity_hash: Option<String>,
}

// ──────────────────── schema & pragmas ────────────────────

/// Databases at or below this size keep whatever `auto_vacuum` they have.
///
/// Converting them costs a full rewrite for nothing worth reclaiming, and a
/// new database gets `auto_vacuum = FULL` before its first table anyway.
pub const VACUUM_MIN_BYTES: u64 = 64 * 1024 * 1024;

fn apply_pragmas(conn: &Connection, db_bytes: u64) -> Result<()> {
    // auto_vacuum can only be changed before the first table is created.
    // For an existing database the PRAGMA alone is silently ignored, so a
    // mismatch needs a VACUUM to convert; that rewrite is only worth it
    // once the file is large enough for page frees to matter
    // (bd-rc-master-ajg1.7.2). This must happen before setting WAL mode
    // because VACUUM resets journal_mode.
    let current_av: i32 = conn.query_row("PRAGMA auto_vacuum", [], |row| row.get(0))?;
    if current_av != 1 && (db_bytes == 0 || db_bytes > VACUUM_MIN_BYTES) {
        // 1 = FULL.  Setting it and running VACUUM converts the database
        // in-place so future page frees actually reclaim space.
        if conn
            .execute_batch("PRAGMA auto_vacuum = FULL; VACUUM;")
            .is_err()
        {
            eprintln!("[SBH-SQLITE] WARNING: failed to enable auto_vacuum (current={current_av})");
        }
    }

    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA cache_size = -8000;
         PRAGMA mmap_size = 67108864;
         PRAGMA temp_store = MEMORY;
         PRAGMA busy_timeout = 5000;",
    )?;

    // Verify WAL mode is active (I12).
    let mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        eprintln!("[SBH-SQLITE] WARNING: requested WAL mode but got '{mode}'");
    }
    Ok(())
}

fn apply_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            path TEXT,
            size_bytes INTEGER,
            score REAL,
            score_factors TEXT,
            pressure_level TEXT,
            free_pct REAL,
            duration_ms INTEGER,
            success INTEGER NOT NULL DEFAULT 1,
            error_code TEXT,
            error_message TEXT,
            details TEXT
        );

        CREATE TABLE IF NOT EXISTS pressure_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            mount_point TEXT NOT NULL,
            total_bytes INTEGER NOT NULL,
            free_bytes INTEGER NOT NULL,
            free_pct REAL NOT NULL,
            rate_bytes_per_sec REAL,
            pressure_level TEXT NOT NULL,
            ewma_rate REAL,
            pid_output REAL
        );

        CREATE TABLE IF NOT EXISTS ballast_inventory (
            file_index INTEGER PRIMARY KEY,
            path TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            released_at TEXT,
            replenished_at TEXT,
            integrity_hash TEXT
        );

        CREATE TABLE IF NOT EXISTS decision_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            decision_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            path TEXT NOT NULL,
            action TEXT NOT NULL,
            effective_action TEXT,
            policy_mode TEXT NOT NULL,
            total_score REAL NOT NULL,
            posterior_abandoned REAL NOT NULL,
            expected_loss_keep REAL NOT NULL,
            expected_loss_delete REAL NOT NULL,
            vetoed INTEGER NOT NULL DEFAULT 0,
            veto_reason TEXT,
            record TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS decision_outcome (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            decision_id TEXT NOT NULL,
            path TEXT NOT NULL,
            category TEXT NOT NULL,
            certainty TEXT NOT NULL,
            outcome TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            after_secs INTEGER NOT NULL,
            detail TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_outcome_decision_id ON decision_outcome(decision_id);
        CREATE INDEX IF NOT EXISTS idx_outcome_observed_at ON decision_outcome(observed_at);
        CREATE INDEX IF NOT EXISTS idx_decision_id ON decision_log(decision_id);
        CREATE INDEX IF NOT EXISTS idx_decision_path ON decision_log(path);
        CREATE INDEX IF NOT EXISTS idx_decision_timestamp ON decision_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON activity_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_activity_event_type ON activity_log(event_type);
        CREATE INDEX IF NOT EXISTS idx_activity_type_time ON activity_log(event_type, timestamp);
        CREATE INDEX IF NOT EXISTS idx_pressure_timestamp ON pressure_history(timestamp);
        CREATE INDEX IF NOT EXISTS idx_pressure_mount ON pressure_history(mount_point);
        CREATE INDEX IF NOT EXISTS idx_pressure_mount_timestamp
            ON pressure_history(mount_point, timestamp);",
    )?;
    Ok(())
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A database created outside the logger with `auto_vacuum = NONE` and
    /// roughly `payload_bytes` of rows, closed cleanly.
    fn legacy_db(path: &Path, payload_bytes: usize) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "PRAGMA auto_vacuum = NONE;
             CREATE TABLE filler (blob BLOB);",
        )
        .unwrap();
        let chunk = vec![0x5Au8; 1024 * 1024];
        let chunks = payload_bytes.div_ceil(chunk.len());
        for _ in 0..chunks {
            conn.execute("INSERT INTO filler (blob) VALUES (?1)", [&chunk])
                .unwrap();
        }
        let av: i32 = conn
            .query_row("PRAGMA auto_vacuum", [], |row| row.get(0))
            .unwrap();
        assert_eq!(av, 0, "fixture must start without auto_vacuum");
    }

    fn auto_vacuum(logger: &SqliteLogger) -> i32 {
        logger
            .conn
            .query_row("PRAGMA auto_vacuum", [], |row| row.get(0))
            .unwrap()
    }

    /// bd-rc-master-ajg1.7.2: a mismatched `auto_vacuum` is converted with
    /// one VACUUM only above the 64 MiB floor; a small database keeps its
    /// setting, and a new one starts out FULL.
    #[test]
    fn vacuum_converts_only_databases_above_the_size_floor() {
        let dir = tempfile::tempdir().unwrap();

        let small = dir.path().join("small.db");
        legacy_db(&small, 1024 * 1024);
        let before = std::fs::metadata(&small).unwrap().len();
        assert!(before <= VACUUM_MIN_BYTES, "{before}");
        let logger = SqliteLogger::open(&small).unwrap();
        assert_eq!(auto_vacuum(&logger), 0, "small database left alone");
        drop(logger);

        let large = dir.path().join("large.db");
        legacy_db(&large, 65 * 1024 * 1024);
        let before = std::fs::metadata(&large).unwrap().len();
        assert!(before > VACUUM_MIN_BYTES, "{before}");
        let logger = SqliteLogger::open(&large).unwrap();
        assert_eq!(auto_vacuum(&logger), 1, "large database converted to FULL");
        // Converting is idempotent: reopening finds FULL and leaves it.
        drop(logger);
        let logger = SqliteLogger::open(&large).unwrap();
        assert_eq!(auto_vacuum(&logger), 1);

        let fresh = dir.path().join("fresh.db");
        let logger = SqliteLogger::open(&fresh).unwrap();
        assert_eq!(auto_vacuum(&logger), 1, "new database starts FULL");
    }

    fn temp_db() -> (tempfile::TempDir, SqliteLogger) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let logger = SqliteLogger::open(&db_path).unwrap();
        (dir, logger)
    }

    #[test]
    fn schema_created_and_wal_active() {
        let (_dir, logger) = temp_db();
        assert!(logger.is_wal_mode());
    }

    #[test]
    fn insert_and_query_activity() {
        let (_dir, logger) = temp_db();
        let row = ActivityRow {
            timestamp: "2026-02-14T16:30:00Z".to_string(),
            event_type: "artifact_delete".to_string(),
            severity: "info".to_string(),
            path: Some("/data/projects/foo/.target_opus".to_string()),
            size_bytes: Some(3_456_789_012),
            score: Some(0.87),
            score_factors: Some(
                r#"{"location":0.85,"name":0.9,"age":0.95,"size":0.8,"structure":0.85}"#
                    .to_string(),
            ),
            pressure_level: Some("orange".to_string()),
            free_pct: Some(8.3),
            duration_ms: Some(145),
            success: 1,
            error_code: None,
            error_message: None,
            details: None,
        };
        logger.log_activity(&row).unwrap();

        let results = logger.recent_activity(10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event_type, "artifact_delete");
        assert_eq!(results[0].size_bytes, Some(3_456_789_012));
    }

    #[test]
    fn insert_and_query_pressure() {
        let (_dir, logger) = temp_db();
        let row = PressureRow {
            timestamp: "2026-02-14T16:30:00Z".to_string(),
            mount_point: "/data".to_string(),
            total_bytes: 500_000_000_000,
            free_bytes: 25_000_000_000,
            free_pct: 5.0,
            rate_bytes_per_sec: Some(-50_000_000.0),
            pressure_level: "red".to_string(),
            ewma_rate: Some(-45_000_000.0),
            pid_output: Some(0.85),
        };
        logger.log_pressure(&row).unwrap();

        let results = logger
            .pressure_since("/data", "2026-02-14T00:00:00Z", 10)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pressure_level, "red");
    }

    #[test]
    fn upsert_and_query_ballast() {
        let (_dir, logger) = temp_db();
        let row = BallastRow {
            file_index: 1,
            path: "/var/lib/sbh/ballast/SBH_BALLAST_FILE_00001.dat".to_string(),
            size_bytes: 1_073_741_824,
            created_at: "2026-02-14T10:00:00Z".to_string(),
            released_at: None,
            replenished_at: None,
            integrity_hash: Some("abc123".to_string()),
        };
        logger.upsert_ballast(&row).unwrap();

        let inv = logger.ballast_inventory().unwrap();
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0].file_index, 1);
        assert!(inv[0].released_at.is_none());

        // Upsert with updated released_at.
        let updated = BallastRow {
            released_at: Some("2026-02-14T16:00:00Z".to_string()),
            ..row
        };
        logger.upsert_ballast(&updated).unwrap();

        let inv = logger.ballast_inventory().unwrap();
        assert_eq!(inv.len(), 1);
        assert!(inv[0].released_at.is_some());
    }

    #[test]
    fn aggregate_counts() {
        let (_dir, logger) = temp_db();
        for i in 0..5 {
            logger
                .log_activity(&ActivityRow {
                    timestamp: format!("2026-02-14T16:3{i}:00Z"),
                    event_type: "artifact_delete".to_string(),
                    severity: "info".to_string(),
                    path: Some(format!("/data/t{i}")),
                    size_bytes: Some(1_000_000 * i64::from(i + 1)),
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
                .unwrap();
        }

        let count = logger
            .count_events_since("artifact_delete", "2026-02-14T00:00:00Z")
            .unwrap();
        assert_eq!(count, 5);

        let freed = logger
            .bytes_freed_since("artifact_delete", "2026-02-14T00:00:00Z")
            .unwrap();
        assert_eq!(freed, 15_000_000); // 1+2+3+4+5 million
    }

    #[test]
    fn rapid_inserts_no_data_loss() {
        let (_dir, logger) = temp_db();
        for i in 0..1000 {
            logger
                .log_activity(&ActivityRow {
                    timestamp: format!("2026-02-14T16:00:{:03}Z", i % 60),
                    event_type: "scan_complete".to_string(),
                    severity: "info".to_string(),
                    path: None,
                    size_bytes: None,
                    score: None,
                    score_factors: None,
                    pressure_level: None,
                    free_pct: None,
                    duration_ms: Some(i),
                    success: 1,
                    error_code: None,
                    error_message: None,
                    details: None,
                })
                .unwrap();
        }
        let count = logger
            .count_events_since("scan_complete", "2026-01-01T00:00:00Z")
            .unwrap();
        assert_eq!(count, 1000);
    }

    #[test]
    fn open_read_only_queries_but_never_writes_or_creates() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("ro.db");
        {
            let logger = SqliteLogger::open(&db_path).unwrap();
            logger
                .conn
                .execute(
                    "INSERT INTO activity_log (timestamp, event_type, severity, details) VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params!["2026-09-02T00:00:00Z", "pressure_change", "info", "{}"],
                )
                .unwrap();
        }

        let ro = SqliteLogger::open_read_only(&db_path).unwrap();
        let rows: i64 = ro
            .conn
            .query_row("SELECT COUNT(*) FROM activity_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 1, "read-only handle must see existing rows");

        let write = ro.conn.execute(
            "INSERT INTO activity_log (timestamp, event_type, severity) VALUES ('t', 'x', 'info')",
            [],
        );
        assert!(
            write.is_err(),
            "read-only handle must refuse writes, got {write:?}"
        );

        // A read-side open must never manufacture a database.
        let missing = dir.path().join("does-not-exist").join("activity.sqlite3");
        assert!(SqliteLogger::open_read_only(&missing).is_err());
        assert!(
            !missing.exists(),
            "read-only open created {}",
            missing.display()
        );
    }

    #[test]
    fn idempotent_schema_creation() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("idempotent.db");
        // Open twice — should not fail.
        let _ = SqliteLogger::open(&db_path).unwrap();
        let logger = SqliteLogger::open(&db_path).unwrap();
        assert!(logger.is_wal_mode());
    }
}
