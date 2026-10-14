use super::*;
use crate::scanner::compression::CompressionReclaimReport;

fn result() -> CompressionFileReport {
    CompressionFileReport {
        path: "/archive/cold.bin".into(),
        operation_id: Some("abc-42-0:1".to_string()),
        outcome: "compressed".to_string(),
        detail: "content verified; allocation reuse can be delayed".to_string(),
        logical_bytes: 131_072,
        physical_data_bytes_before: Some(131_072),
        physical_data_bytes_after: Some(4096),
        processed_bytes: 131_072,
        mutation_attempted: true,
        sha256_before: Some("ab".repeat(32)),
        sha256_after: Some("ab".repeat(32)),
        content_verified: true,
        reclaim: Some(CompressionReclaimReport {
            referenced_bytes_saved: 126_976,
            referenced_bytes_added: 0,
            old_data_bytes_pending: 131_072,
            old_data_bytes_released: 0,
            new_data_bytes_allocated: 4096,
            confirmed_data_bytes_reclaimed: 0,
        }),
        accounting_error: None,
    }
}

fn projection(report: &CompressionFileReport, durable: bool) -> CompressionActivity {
    CompressionActivity::new(
        report,
        Path::new("/state/compression-journal/abc-42-0.jsonl"),
        durable,
    )
    .unwrap()
}

#[test]
fn referenced_savings_are_not_promoted_to_freed_bytes_or_deletion_decisions() {
    let activity = projection(&result(), true);
    let mut entry = activity.to_log_entry();
    assert_eq!(entry.event, EventType::Info);
    assert_eq!(entry.severity, Severity::Info);
    assert_eq!(entry.ok, Some(true));
    assert!(entry.size.is_none());
    assert!(entry.decision_id.is_none());
    assert!(entry.quarantined.is_none());
    let details: serde_json::Value = serde_json::from_str(entry.details.as_ref().unwrap()).unwrap();
    assert_eq!(details["schema"], ACTIVITY_SCHEMA);
    assert_eq!(details["kind"], ACTIVITY_KIND);
    assert_eq!(details["operation_id"], "compress:abc-42-0:1");
    assert_eq!(details["observed_at"], entry.ts);
    assert_eq!(details["journal_outcome_recorded"], true);
    assert_eq!(
        details["result"]["reclaim"]["referenced_bytes_saved"],
        126_976
    );
    assert_eq!(
        details["result"]["reclaim"]["confirmed_data_bytes_reclaimed"],
        0
    );
    entry.run_id = Some("activity-run".to_string());
    entry.schema_version = Some(crate::logger::schema::SCHEMA_VERSION);
    crate::logger::schema::validate_value(&serde_json::to_value(entry).unwrap()).unwrap();
}

#[test]
fn partial_work_and_failed_journal_writes_remain_distinguishable() {
    let mut report = result();
    report.outcome = "partial".to_string();
    report.processed_bytes = 65_536;
    report.physical_data_bytes_after = None;
    report.reclaim = None;
    report.accounting_error = Some("extent query timed out".to_string());
    for durable in [false, true] {
        let entry = projection(&report, durable).to_log_entry();
        assert_eq!(entry.severity, Severity::Warning);
        assert_eq!(entry.ok, Some(false));
        let details: serde_json::Value =
            serde_json::from_str(entry.details.as_ref().unwrap()).unwrap();
        assert_eq!(details["journal_outcome_recorded"], durable);
        assert!(details["result"]["reclaim"].is_null());
        assert!(details["result"]["physical_data_bytes_after"].is_null());
        assert_eq!(details["result"]["processed_bytes"], 65_536);
    }
    let complete_without_audit = projection(&result(), false).to_log_entry();
    assert_eq!(complete_without_audit.ok, Some(false));
    assert_eq!(
        complete_without_audit.error_code.as_deref(),
        Some("SBH-COMPRESSION-AUDIT")
    );
}

#[test]
fn unsigned_measurements_are_preserved_without_signed_saturation() {
    let mut report = result();
    report.physical_data_bytes_before = Some(u64::MAX);
    let activity = projection(&report, true);
    let entry = activity.to_log_entry();
    let details: serde_json::Value = serde_json::from_str(entry.details.as_ref().unwrap()).unwrap();
    assert_eq!(
        details["result"]["physical_data_bytes_before"].as_u64(),
        Some(u64::MAX)
    );
    #[cfg(feature = "sqlite")]
    assert!(activity.to_activity_row().size_bytes.is_none());
}

#[test]
fn previews_and_contradictory_success_cannot_become_audit_success() {
    let journal = Path::new("/state/compression-journal/run.jsonl");
    let mut report = result();
    report.operation_id = None;
    assert!(CompressionActivity::new(&report, journal, true).is_err());
    report = result();
    report.outcome = "eligible".to_string();
    assert!(CompressionActivity::new(&report, journal, true).is_err());
    report = result();
    report.sha256_after = Some("cd".repeat(32));
    assert!(CompressionActivity::new(&report, journal, true).is_err());
    report = result();
    report.processed_bytes -= 1;
    assert!(CompressionActivity::new(&report, journal, true).is_err());
    report = result();
    report.detail = "x".repeat(MAX_DETAILS_BYTES);
    assert!(CompressionActivity::new(&report, journal, true).is_err());
}

#[cfg(unix)]
#[test]
fn native_path_bytes_survive_display_replacement_characters() {
    use std::os::unix::ffi::OsStringExt;
    let mut report = result();
    let bytes = b"/archive/invalid-\xff.bin";
    report.path = std::ffi::OsString::from_vec(bytes.to_vec()).into();
    let entry = projection(&report, true).to_log_entry();
    let details: serde_json::Value = serde_json::from_str(entry.details.as_ref().unwrap()).unwrap();
    assert_eq!(details["native_path_hex"], crate::core::hex_lower(bytes));
    assert_eq!(
        details["result"]["path"],
        report.path.to_string_lossy().as_ref()
    );
}

#[cfg(feature = "sqlite")]
#[test]
fn both_backends_receive_identical_payloads_without_deletion_accounting() {
    let activity = projection(&result(), true);
    let entry = activity.to_log_entry();
    let row = activity.to_activity_row();
    assert_eq!(row.timestamp, entry.ts);
    assert_eq!(row.details, entry.details);
    assert_eq!(row.path, entry.path);
    assert!(row.size_bytes.is_none());
    assert_eq!(row.event_type, "info");
    let temp = tempfile::tempdir().unwrap();
    let db =
        crate::logger::sqlite::SqliteLogger::open(&temp.path().join("activity.sqlite3")).unwrap();
    db.log_activity(&row).unwrap();
    let stored = db.recent_activity(10).unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].details, entry.details);
    assert_eq!(
        db.count_events_since("artifact_delete", "2000-01-01T00:00:00Z")
            .unwrap(),
        0
    );
    assert!(db.recent_decisions(10).unwrap().is_empty());
    assert!(db.ballast_inventory().unwrap().is_empty());
}
