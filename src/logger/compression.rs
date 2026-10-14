//! Compression outcomes in the shared activity stream (bd-rxq5).
//!
//! The durable compression journal remains the recovery authority. Activity
//! records are projections for log readers, not proof of journal durability or
//! immediately reusable free space. Both backends use the existing `info`
//! envelope with a versioned, structured `details` payload; deletion and ballast
//! counters must never consume compression's logical length or referenced savings.

use std::io;
use std::path::Path;

use crate::logger::jsonl::{EventType, LogEntry, Severity};
use crate::scanner::compression::CompressionFileReport;

/// Schema of the JSON object stored in the activity entry's `details` string.
pub const ACTIVITY_SCHEMA: &str = "sbh.compression.activity.v1";
/// Discriminator inside `details`, distinct from diagnostic messages.
pub const ACTIVITY_KIND: &str = "compression_outcome";
const MAX_DETAILS_BYTES: usize = 128 * 1024;

/// Validated, already-serialized projection of one prepared compression input.
///
/// Construct after the file's outcome-journal write was attempted, including
/// failed writes. Serialization failures are explicit and cannot silently turn
/// into empty activity entries. The type performs no filesystem I/O.
#[derive(Debug, Clone)]
pub struct CompressionActivity {
    entry: LogEntry,
}

impl CompressionActivity {
    /// Project an outcome without changing its measurements or uncertainty.
    /// `journal_outcome_recorded` describes the synchronous outcome write, not
    /// the asynchronous activity logger's delivery state.
    pub fn new(
        report: &CompressionFileReport,
        journal_path: &Path,
        journal_outcome_recorded: bool,
    ) -> io::Result<Self> {
        let id = report
            .operation_id
            .as_deref()
            .filter(|id| !id.is_empty() && id.len() <= 256)
            .ok_or_else(|| invalid("compression activity requires a prepared operation ID"))?;
        if !matches!(report.outcome.as_str(), "compressed" | "partial" | "failed") {
            return Err(invalid("preview and discovery are not compression outcomes"));
        }
        let hash_matches = report.sha256_before.as_ref().is_some_and(|before| {
            before.len() == 64
                && before.bytes().all(|byte| byte.is_ascii_hexdigit())
                && report.sha256_after.as_ref() == Some(before)
        });
        if report.content_verified && (!report.mutation_attempted || !hash_matches) {
            return Err(invalid("content verification lacks matching pre/post hashes"));
        }
        if report.outcome == "compressed"
            && (!report.content_verified
                || report.processed_bytes != report.logical_bytes
                || report.physical_data_bytes_after.is_none()
                || report.accounting_error.is_some())
        {
            return Err(invalid("successful compression activity has incomplete evidence"));
        }
        let complete = report.outcome == "compressed" && journal_outcome_recorded;
        let mut entry = LogEntry::new(
            EventType::Info,
            if complete { Severity::Info } else { Severity::Warning },
        );
        entry.path = Some(report.path.to_string_lossy().into_owned());
        entry.ok = Some(complete);
        // Deliberately leave size, score, pressure, and deletion decision_id
        // unset. All byte quantities below retain their original meanings.
        let details = serde_json::json!({
            "schema": ACTIVITY_SCHEMA,
            "kind": ACTIVITY_KIND,
            "operation_id": format!("compress:{id}"),
            "observed_at": entry.ts,
            "journal_path": journal_path.to_string_lossy(),
            "journal_outcome_recorded": journal_outcome_recorded,
            "native_path_hex": crate::core::hex_lower(report.path.as_os_str().as_encoded_bytes()),
            "result": report,
        });
        let details = serde_json::to_string(&details).map_err(io::Error::other)?;
        if details.len() > MAX_DETAILS_BYTES {
            return Err(invalid("compression activity exceeds its 128 KiB payload budget"));
        }
        entry.details = Some(details);
        if !complete {
            entry.error_code = Some(if journal_outcome_recorded {
                "SBH-COMPRESSION-INCOMPLETE"
            } else {
                "SBH-COMPRESSION-AUDIT"
            }.to_string());
            entry.error_message = Some(report.detail.clone());
        }
        Ok(Self { entry })
    }

    /// JSONL representation using the existing C-EVENT envelope. Its writer
    /// supplies the normal run ID/schema stamp and fallback policy.
    #[must_use]
    pub fn to_log_entry(&self) -> LogEntry {
        self.entry.clone()
    }

    /// SQLite representation of the same observation, timestamp, and payload.
    /// No data is written to `decision_log`, `decision_outcome`, or ballast
    /// inventory. Physical byte values remain unsigned integers inside JSON.
    #[cfg(feature = "sqlite")]
    #[must_use]
    pub fn to_activity_row(&self) -> crate::logger::sqlite::ActivityRow {
        crate::logger::sqlite::ActivityRow {
            timestamp: self.entry.ts.clone(),
            event_type: "info".to_string(),
            severity: if self.entry.severity == Severity::Info { "info" } else { "warning" }.to_string(),
            path: self.entry.path.clone(),
            size_bytes: None,
            score: None,
            score_factors: None,
            pressure_level: None,
            free_pct: None,
            duration_ms: None,
            success: if self.entry.ok == Some(true) { 1 } else { 0 },
            error_code: self.entry.error_code.clone(),
            error_message: self.entry.error_message.clone(),
            details: self.entry.details.clone(),
        }
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

#[cfg(test)]
mod tests;
