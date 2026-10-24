//! Shared-log transport regressions. Fixtures model outcomes, not Btrfs proof.

use std::path::Path;

use storage_ballast_helper::logger::compression::CompressionActivity;
use storage_ballast_helper::logger::dual::{
    ActivityEvent, DualLoggerConfig, LoggerShutdownStatus, spawn_logger,
};
use storage_ballast_helper::logger::jsonl::JsonlConfig;
use storage_ballast_helper::scanner::compression::{
    self, CompressionFileReport, CompressionMode, CompressionPolicy,
};

fn result(index: usize) -> CompressionFileReport {
    CompressionFileReport {
        path: format!("/fixture/cold-{index}.bin").into(),
        operation_id: Some(format!("fixture-42-0:{}", index * 2 + 1)),
        outcome: "partial".to_string(),
        detail: "fixture: postflight accounting unavailable".to_string(),
        logical_bytes: 131_072,
        physical_data_bytes_before: Some(131_072),
        physical_data_bytes_after: None,
        processed_bytes: 65_536,
        mutation_attempted: true,
        sha256_before: Some("ab".repeat(32)),
        sha256_after: Some("ab".repeat(32)),
        content_verified: true,
        reclaim: None,
        accounting_error: Some("fixture accounting failure".to_string()),
    }
}

fn config(root: &Path) -> DualLoggerConfig {
    DualLoggerConfig {
        sqlite_path: cfg!(feature = "sqlite").then(|| root.join("activity.sqlite3")),
        jsonl_config: JsonlConfig {
            path: root.join("activity.jsonl"),
            fallback_path: None,
            max_size_bytes: 1024 * 1024,
            max_rotated_files: 1,
            fsync_interval_secs: 60,
        },
        channel_capacity: 128,
        run_id: Some("compression-activity-fixture".to_string()),
    }
}

#[test]
fn a_large_compression_pass_is_not_throttled_as_repetitive_diagnostics() {
    let temp = tempfile::tempdir().unwrap();
    let (handle, join) = spawn_logger(config(temp.path())).unwrap();
    let journal = temp.path().join("compression-journal/fixture-42-0.jsonl");
    // More than both the per-template and per-severity diagnostic ceilings.
    for index in 0..80 {
        let activity = CompressionActivity::new(&result(index), &journal, true).unwrap();
        handle.send(ActivityEvent::CompressionRecorded(Box::new(activity)));
    }
    handle.shutdown();
    join.join().unwrap();
    assert_eq!(handle.shutdown_status(), LoggerShutdownStatus::WriterExited);
    assert_eq!(handle.dropped_events(), 0);
    assert_eq!(handle.suppressed_diagnostics(), 0);
    let text = std::fs::read_to_string(temp.path().join("activity.jsonl")).unwrap();
    let lines: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 80);
    for line in &lines {
        storage_ballast_helper::logger::schema::validate_value(line).unwrap();
        assert_eq!(line["event"], "info");
        assert_eq!(line["severity"], "warning");
        assert_eq!(line["ok"], false);
        assert!(line.get("size").is_none());
        assert!(line.get("decision_id").is_none());
        let details: serde_json::Value =
            serde_json::from_str(line["details"].as_str().unwrap()).unwrap();
        assert_eq!(details["schema"], "sbh.compression.activity.v1");
        assert!(details["result"]["reclaim"].is_null());
    }
    #[cfg(feature = "sqlite")]
    {
        use std::collections::BTreeSet;
        use storage_ballast_helper::logger::sqlite::SqliteLogger;
        let db = SqliteLogger::open_read_only(&temp.path().join("activity.sqlite3")).unwrap();
        let rows = db.recent_activity(100).unwrap();
        assert_eq!(rows.len(), 80);
        assert!(
            rows.iter()
                .all(|row| row.event_type == "info" && row.size_bytes.is_none())
        );
        let jsonl_details: BTreeSet<_> = lines
            .iter()
            .map(|line| line["details"].as_str().unwrap().to_string())
            .collect();
        let sqlite_details: BTreeSet<_> =
            rows.into_iter().map(|row| row.details.unwrap()).collect();
        assert_eq!(jsonl_details, sqlite_details);
        assert_eq!(
            db.count_events_since("artifact_delete", "2000-01-01T00:00:00Z")
                .unwrap(),
            0
        );
        assert!(db.recent_decisions(10).unwrap().is_empty());
        assert!(db.ballast_inventory().unwrap().is_empty());
    }
}

#[test]
fn compression_uses_the_existing_jsonl_fallback_without_claiming_durability() {
    let temp = tempfile::tempdir().unwrap();
    let blocker = temp.path().join("not-a-directory");
    std::fs::write(&blocker, b"keep this fixture").unwrap();
    let fallback = temp.path().join("fallback.jsonl");
    let mut options = config(temp.path());
    options.sqlite_path = None;
    options.jsonl_config.path = blocker.join("activity.jsonl");
    options.jsonl_config.fallback_path = Some(fallback.clone());
    let (handle, join) = spawn_logger(options).unwrap();
    let activity =
        CompressionActivity::new(&result(0), Path::new("/journal/fixture.jsonl"), false).unwrap();
    handle.send(ActivityEvent::CompressionRecorded(Box::new(activity)));
    handle.shutdown();
    join.join().unwrap();
    let line: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(fallback).unwrap()).unwrap();
    assert_eq!(line["error_code"], "SBH-COMPRESSION-AUDIT");
    let details: serde_json::Value =
        serde_json::from_str(line["details"].as_str().unwrap()).unwrap();
    assert_eq!(details["journal_outcome_recorded"], false);
    assert_eq!(std::fs::read(blocker).unwrap(), b"keep this fixture");
}

#[test]
fn rejected_requests_never_invoke_the_observer() {
    let error = compression::run_observed(
        &[],
        &CompressionPolicy::default(),
        CompressionMode::default(),
        &storage_ballast_helper::core::config::Config::default(),
        &storage_ballast_helper::platform::current(),
        &mut |_| panic!("invalid request reached observer"),
    )
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn observations_arrive_before_the_next_file_is_inspected_and_do_not_create_journals() {
    let temp = tempfile::tempdir().unwrap();
    let first = temp.path().join("first.bin");
    let next = temp.path().join("next.bin");
    let retained = temp.path().join("retained.bin");
    std::fs::write(&first, b"small first file").unwrap();
    std::fs::write(&next, b"small second file").unwrap();
    let mut config = storage_ballast_helper::core::config::Config::default();
    config.paths.state_file = temp.path().join("state.json");
    let mut observed = Vec::new();
    let report = compression::run_observed(
        &[first, next.clone()],
        &CompressionPolicy::default(),
        CompressionMode::default(),
        &config,
        &storage_ballast_helper::platform::current(),
        &mut |observation| {
            assert!(observation.journal_path.is_none());
            assert!(!observation.journal_outcome_recorded);
            assert!(!observation.file.mutation_attempted);
            if observed.is_empty() {
                // Retain the next fixture under a different name. Its later
                // NotFound result proves callbacks are not deferred to pass end.
                std::fs::rename(&next, &retained).unwrap();
            }
            observed.push(observation.file.outcome.clone());
        },
    )
    .unwrap();
    assert_eq!(observed, ["skipped", "failed"]);
    assert_eq!(report.files.len(), 2);
    assert_eq!(report.exit_code, 2);
    assert_eq!(std::fs::read(retained).unwrap(), b"small second file");
    assert!(!temp.path().join("compression-journal").exists());
    assert!(!config.paths.state_file.exists());
}
