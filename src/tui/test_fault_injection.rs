//! Failure-injection test suite for dashboard data adapters (bd-xzt.4.14).
//!
//! Verifies deterministic, non-panicking degradation and recovery for:
//! - **State adapter**: missing / stale / malformed / incompatible-schema state files
//! - **Telemetry source**: JSONL corruption, schema-shield recovery, no-backend fallback
//! - **Preferences**: corrupt payloads, permission-denied saves, atomic-write interruption
//! - **Model transitions**: degraded-mode entry/exit, notification flow, recovery indicators
//!
//! Every scenario asserts that errors surface as operator-visible degradation
//! indicators rather than panics. Recovery transitions are validated end-to-end.

#![allow(clippy::too_many_lines)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use filetime::{FileTime, set_file_mtime};
use tempfile::TempDir;

use super::adapters::{DashboardStateAdapter, SchemaWarnings, SnapshotSource, StateFreshness};
use super::model::Screen;
use super::preferences::{self, DebouncedWriter, LoadOutcome, UserPreferences};
use super::telemetry::{
    BackendHealth, CompositeTelemetryAdapter, DataSource, EventFilter, JsonlTelemetryAdapter,
    NullTelemetryAdapter, TelemetryQueryAdapter,
};
use super::test_harness::{DashboardHarness, HarnessStep, sample_healthy_state};
use crate::daemon::self_monitor::{
    BallastState, Counters, DaemonState, LastScanState, MountPressure, PressureState,
};
use crate::platform::pal::{FsStats, MemoryInfo, MockPlatform, MountPoint, PlatformPaths};

// ══════════════════════════════════════════════════════════════════
//  Helpers
// ══════════════════════════════════════════════════════════════════

fn mock_platform() -> Arc<dyn crate::platform::pal::Platform> {
    let mount = MountPoint {
        path: PathBuf::from("/tmp"),
        device: "tmpfs".to_string(),
        fs_type: "tmpfs".to_string(),
        is_ram_backed: true,
    };
    let stats = FsStats {
        total_bytes: 100,
        free_bytes: 70,
        available_bytes: 70,
        fs_type: "tmpfs".to_string(),
        mount_point: PathBuf::from("/tmp"),
        is_readonly: false,
    };
    Arc::new(MockPlatform::new(
        vec![mount.clone()],
        HashMap::from([(mount.path, stats)]),
        MemoryInfo {
            total_bytes: 1,
            available_bytes: 1,
            swap_total_bytes: 0,
            swap_free_bytes: 0,
        },
        PlatformPaths::default(),
    ))
}

fn make_adapter(stale_secs: u64) -> DashboardStateAdapter {
    DashboardStateAdapter::new(
        mock_platform(),
        Duration::from_secs(stale_secs),
        Duration::from_secs(1),
    )
}

fn write_state(path: &Path, state: &DaemonState) {
    let json = serde_json::to_string(state).expect("serialize state");
    std::fs::write(path, json).expect("write state file");
}

fn sample_state() -> DaemonState {
    DaemonState {
        version: "0.1.0".to_string(),
        pid: 42,
        started_at: "2026-02-16T00:00:00Z".to_string(),
        uptime_seconds: 60,
        last_updated: "2026-02-16T00:01:00Z".to_string(),
        pressure: PressureState {
            overall: "yellow".to_string(),
            mounts: vec![MountPressure {
                path: "/".to_string(),
                free_pct: 42.0,
                level: "yellow".to_string(),
                rate_bps: Some(1024.0),
            }],
        },
        ballast: BallastState {
            available: 9,
            total: 10,
            released: 1,
        },
        last_scan: LastScanState {
            at: Some("2026-02-16T00:00:30Z".to_string()),
            candidates: 7,
            deleted: 3,
        },
        counters: Counters {
            scans: 13,
            deletions: 5,
            bytes_freed: 4096,
            errors: 0,
            dropped_log_events: 0,
        },
        policy_mode: "enforce".into(),
        memory_rss_bytes: 1_048_576,
    }
}

fn write_jsonl_entries(path: &Path, entries: &[crate::logger::jsonl::LogEntry]) {
    let mut content = String::new();
    for entry in entries {
        content.push_str(&serde_json::to_string(entry).expect("serialize"));
        content.push('\n');
    }
    std::fs::write(path, content).expect("write jsonl");
}

fn make_log_entry(
    ts: &str,
    event: crate::logger::jsonl::EventType,
    severity: crate::logger::jsonl::Severity,
) -> crate::logger::jsonl::LogEntry {
    crate::logger::jsonl::LogEntry {
        ts: ts.to_string(),
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

// ══════════════════════════════════════════════════════════════════
//  F1: State adapter — file absent / unreadable
// ══════════════════════════════════════════════════════════════════

#[test]
fn state_missing_file_yields_fallback_mounts() {
    let tmp = TempDir::new().unwrap();
    let adapter = make_adapter(90);
    let snap = adapter.load_snapshot(
        &tmp.path().join("nonexistent.json"),
        &[PathBuf::from("/tmp/work")],
    );
    assert_eq!(snap.freshness, StateFreshness::Missing);
    assert!(snap.daemon_state.is_none());
    assert!(
        snap.source == SnapshotSource::FilesystemFallback
            || snap.source == SnapshotSource::Unavailable
    );
}

#[test]
fn state_empty_file_yields_malformed() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("state.json");
    std::fs::write(&path, "").unwrap();

    let adapter = make_adapter(90);
    let snap = adapter.load_snapshot(&path, &[PathBuf::from("/tmp/work")]);
    assert_eq!(snap.freshness, StateFreshness::Malformed);
    assert!(snap.daemon_state.is_none());
}

#[test]
fn state_binary_garbage_yields_malformed() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("state.json");
    std::fs::write(&path, [0xFF, 0xFE, 0x00, 0x01, 0x80]).unwrap();

    let adapter = make_adapter(90);
    let snap = adapter.load_snapshot(&path, &[]);
    assert_eq!(snap.freshness, StateFreshness::Malformed);
}

#[test]
fn state_truncated_json_yields_malformed() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("state.json");
    let full = serde_json::to_string(&sample_state()).unwrap();
    // Truncate to half the JSON.
    let half = &full[..full.len() / 2];
    std::fs::write(&path, half).unwrap();

    let adapter = make_adapter(90);
    let snap = adapter.load_snapshot(&path, &[PathBuf::from("/tmp/work")]);
    assert_eq!(snap.freshness, StateFreshness::Malformed);
    assert!(snap.daemon_state.is_none());
    // Fallback mounts should still be available.
    assert!(!snap.mounts.is_empty() || snap.source == SnapshotSource::Unavailable);
}

// ══════════════════════════════════════════════════════════════════
//  F2: State adapter — staleness detection
// ══════════════════════════════════════════════════════════════════

#[test]
fn state_stale_falls_back_with_daemon_state_preserved() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("state.json");
    write_state(&path, &sample_state());

    // Make file 2 hours old.
    let stale =
        FileTime::from_system_time(std::time::SystemTime::now() - Duration::from_secs(7200));
    set_file_mtime(&path, stale).unwrap();

    let adapter = make_adapter(90);
    let snap = adapter.load_snapshot(&path, &[PathBuf::from("/tmp/work")]);

    match snap.freshness {
        StateFreshness::Stale { age } => assert!(age.as_secs() >= 7000),
        other => panic!("expected Stale, got {other:?}"),
    }
    // daemon_state is preserved even when stale.
    assert!(snap.daemon_state.is_some());
    assert_eq!(snap.source, SnapshotSource::FilesystemFallback);
}

#[test]
fn state_barely_fresh_is_not_stale() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("state.json");
    write_state(&path, &sample_state());

    // 80 seconds old with 90-second threshold → fresh.
    let mtime = FileTime::from_system_time(std::time::SystemTime::now() - Duration::from_secs(80));
    set_file_mtime(&path, mtime).unwrap();

    let adapter = make_adapter(90);
    let snap = adapter.load_snapshot(&path, &[]);
    assert_eq!(snap.freshness, StateFreshness::Fresh);
    assert_eq!(snap.source, SnapshotSource::DaemonState);
}

// ══════════════════════════════════════════════════════════════════
//  F3: State adapter — schema drift (forward/backward compat)
// ══════════════════════════════════════════════════════════════════

#[test]
fn state_future_schema_fields_detected_but_load_succeeds() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("state.json");

    let mut value = serde_json::to_value(sample_state()).unwrap();
    let obj = value.as_object_mut().unwrap();
    obj.insert("v2_telemetry".to_string(), serde_json::json!({"alpha": 1}));
    obj.insert("v2_prediction".to_string(), serde_json::json!(true));
    std::fs::write(&path, serde_json::to_string(&value).unwrap()).unwrap();

    let adapter = make_adapter(90);
    let snap = adapter.load_snapshot(&path, &[]);

    assert_eq!(snap.freshness, StateFreshness::Fresh);
    assert!(snap.daemon_state.is_some());
    assert!(snap.warnings.has_drift());
    assert!(
        snap.warnings
            .unknown_fields
            .contains(&"v2_telemetry".to_string())
    );
    assert!(
        snap.warnings
            .unknown_fields
            .contains(&"v2_prediction".to_string())
    );
}

#[test]
fn state_minimal_empty_object_parses_with_all_defaults() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("state.json");
    std::fs::write(&path, "{}").unwrap();

    let adapter = make_adapter(90);
    let snap = adapter.load_snapshot(&path, &[]);

    assert!(snap.daemon_state.is_some());
    let state = snap.daemon_state.unwrap();
    assert_eq!(state.version, "");
    assert_eq!(state.pid, 0);
    assert_eq!(state.pressure.mounts.len(), 0);
    assert!(snap.warnings.has_drift());
    // All expected keys should be missing.
    assert!(!snap.warnings.missing_fields.is_empty());
}

#[test]
fn state_json_array_yields_malformed() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("state.json");
    std::fs::write(&path, "[1, 2, 3]").unwrap();

    let adapter = make_adapter(90);
    let snap = adapter.load_snapshot(&path, &[]);
    assert_eq!(snap.freshness, StateFreshness::Malformed);
}

#[test]
fn state_json_string_yields_malformed() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("state.json");
    std::fs::write(&path, r#""just a string""#).unwrap();

    let adapter = make_adapter(90);
    let snap = adapter.load_snapshot(&path, &[]);
    assert_eq!(snap.freshness, StateFreshness::Malformed);
}

// ══════════════════════════════════════════════════════════════════
//  F4: State adapter — recovery transitions
// ══════════════════════════════════════════════════════════════════

#[test]
fn state_recovery_from_missing_to_fresh() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("state.json");
    let adapter = make_adapter(90);

    // Phase 1: missing.
    let snap = adapter.load_snapshot(&path, &[PathBuf::from("/tmp/work")]);
    assert_eq!(snap.freshness, StateFreshness::Missing);
    assert!(snap.daemon_state.is_none());

    // Phase 2: file appears.
    write_state(&path, &sample_state());
    let snap = adapter.load_snapshot(&path, &[PathBuf::from("/tmp/work")]);
    assert_eq!(snap.freshness, StateFreshness::Fresh);
    assert!(snap.daemon_state.is_some());
    assert_eq!(snap.source, SnapshotSource::DaemonState);
}

#[test]
fn state_recovery_from_malformed_to_fresh() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("state.json");
    let adapter = make_adapter(90);

    // Phase 1: malformed.
    std::fs::write(&path, "not-json").unwrap();
    let snap = adapter.load_snapshot(&path, &[]);
    assert_eq!(snap.freshness, StateFreshness::Malformed);

    // Phase 2: daemon writes valid state.
    write_state(&path, &sample_state());
    let snap = adapter.load_snapshot(&path, &[]);
    assert_eq!(snap.freshness, StateFreshness::Fresh);
    assert!(snap.daemon_state.is_some());
}

// ══════════════════════════════════════════════════════════════════
//  F5: Telemetry — JSONL corruption and schema-shield recovery
// ══════════════════════════════════════════════════════════════════

#[test]
fn telemetry_jsonl_all_lines_corrupt_marks_partial() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("activity.jsonl");
    std::fs::write(&path, "not-json\nalso-not-json\n{}\n").unwrap();

    let adapter = JsonlTelemetryAdapter::open(&path).unwrap();
    let result = adapter.recent_events(10, &EventFilter::default());

    // All lines are either dropped or recovered with minimal fields.
    assert!(result.partial || result.data.is_empty());
}

#[test]
fn telemetry_jsonl_mixed_corrupt_and_valid() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("activity.jsonl");

    let valid = make_log_entry(
        "2026-02-16T00:00:01Z",
        crate::logger::jsonl::EventType::DaemonStart,
        crate::logger::jsonl::Severity::Info,
    );
    let valid_json = serde_json::to_string(&valid).unwrap();
    let content = format!("{valid_json}\nnot-json-at-all\n{valid_json}\n");
    std::fs::write(&path, content).unwrap();

    let adapter = JsonlTelemetryAdapter::open(&path).unwrap();
    let result = adapter.recent_events(10, &EventFilter::default());

    // 2 valid lines parsed, 1 dropped.
    assert_eq!(result.data.len(), 2);
    assert!(result.partial); // dropped > 0
    assert!(result.diagnostics.contains("dropped=1"));
}

#[test]
fn telemetry_jsonl_legacy_field_aliases_recovered() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("activity.jsonl");
    // Legacy format using "timestamp" and "event_type" instead of "ts" and "event".
    let legacy = r#"{"timestamp":"2026-02-16T00:00:05Z","event_type":"artifact_delete","level":"warning","target_path":"/old/build","size_bytes":999}"#;
    std::fs::write(&path, format!("{legacy}\n")).unwrap();

    let adapter = JsonlTelemetryAdapter::open(&path).unwrap();
    let result = adapter.recent_events(10, &EventFilter::default());

    assert_eq!(result.data.len(), 1);
    assert!(result.diagnostics.contains("recovered=1"));
    assert_eq!(result.data[0].path.as_deref(), Some("/old/build"));
    assert_eq!(result.data[0].severity, "warning");
}

#[test]
fn telemetry_jsonl_empty_file_returns_empty_non_partial() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("activity.jsonl");
    std::fs::write(&path, "").unwrap();

    let adapter = JsonlTelemetryAdapter::open(&path).unwrap();
    let result = adapter.recent_events(10, &EventFilter::default());

    assert!(result.data.is_empty());
    assert!(!result.partial);
    assert_eq!(result.source, DataSource::Jsonl);
}

#[test]
fn telemetry_jsonl_missing_file_returns_none() {
    assert!(JsonlTelemetryAdapter::open(Path::new("/nonexistent/activity.jsonl")).is_none());
}

// ══════════════════════════════════════════════════════════════════
//  F6: Telemetry — composite fallback chain
// ══════════════════════════════════════════════════════════════════

#[test]
fn telemetry_composite_no_backends_returns_unavailable() {
    let adapter = CompositeTelemetryAdapter::new(None, None);
    let result = adapter.recent_events(10, &EventFilter::default());

    assert!(result.partial);
    assert_eq!(result.source, DataSource::None);
    assert!(!result.diagnostics.is_empty());
}

#[test]
fn telemetry_composite_sqlite_missing_falls_through_to_jsonl() {
    let tmp = TempDir::new().unwrap();
    let jsonl_path = tmp.path().join("activity.jsonl");
    let entry = make_log_entry(
        "2026-02-16T00:00:01Z",
        crate::logger::jsonl::EventType::DaemonStart,
        crate::logger::jsonl::Severity::Info,
    );
    write_jsonl_entries(&jsonl_path, &[entry]);

    let adapter = CompositeTelemetryAdapter::new(None, Some(&jsonl_path));
    let result = adapter.recent_events(10, &EventFilter::default());

    assert!(!result.partial);
    assert_eq!(result.source, DataSource::Jsonl);
    assert_eq!(result.data.len(), 1);
}

#[test]
fn telemetry_health_both_unavailable() {
    let adapter = CompositeTelemetryAdapter::new(None, None);
    let health = adapter.health();

    assert_eq!(health.sqlite, BackendHealth::Unavailable);
    assert_eq!(health.jsonl, BackendHealth::Unavailable);
    assert!(!health.any_available());
    assert!(!health.diagnostics.is_empty());
}

#[test]
fn telemetry_health_jsonl_only() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("activity.jsonl");
    std::fs::write(&path, "").unwrap();

    let adapter = CompositeTelemetryAdapter::new(None, Some(&path));
    let health = adapter.health();

    assert_eq!(health.sqlite, BackendHealth::Unavailable);
    assert_eq!(health.jsonl, BackendHealth::Available);
    assert!(health.any_available());
}

#[test]
fn telemetry_null_adapter_all_methods_return_unavailable() {
    let adapter = NullTelemetryAdapter;

    let events = adapter.recent_events(10, &EventFilter::default());
    assert!(events.partial);
    assert!(events.data.is_empty());

    let decisions = adapter.recent_decisions(10);
    assert!(decisions.partial);
    assert!(decisions.data.is_empty());

    let pressure = adapter.pressure_history("/", "", 10);
    assert!(pressure.partial);
    assert!(pressure.data.is_empty());

    let health = adapter.health();
    assert!(!health.any_available());
}

// ══════════════════════════════════════════════════════════════════
//  F7: Preferences — load failures
// ══════════════════════════════════════════════════════════════════

#[test]
fn prefs_load_missing_returns_missing() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("prefs.json");
    match preferences::load(&path) {
        LoadOutcome::Missing => {}
        other => panic!("expected Missing, got {other:?}"),
    }
}

#[test]
fn prefs_load_corrupt_json_returns_corrupt_with_defaults() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("prefs.json");
    std::fs::write(&path, "not-json{{{").unwrap();

    match preferences::load(&path) {
        LoadOutcome::Corrupt { details, defaults } => {
            assert!(!details.is_empty());
            assert_eq!(defaults, UserPreferences::default());
        }
        other => panic!("expected Corrupt, got {other:?}"),
    }
}

#[test]
fn prefs_load_empty_file_returns_corrupt() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("prefs.json");
    std::fs::write(&path, "").unwrap();

    match preferences::load(&path) {
        LoadOutcome::Corrupt { .. } => {}
        other => panic!("expected Corrupt, got {other:?}"),
    }
}

#[test]
fn prefs_load_binary_garbage_returns_corrupt() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("prefs.json");
    std::fs::write(&path, [0xFF, 0xFE, 0x00, 0x80, 0x90]).unwrap();

    match preferences::load(&path) {
        LoadOutcome::Corrupt { .. } => {}
        other => panic!("expected Corrupt, got {other:?}"),
    }
}

#[test]
fn prefs_load_future_schema_version_warns_but_loads() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("prefs.json");
    let prefs = UserPreferences {
        schema_version: 999,
        ..UserPreferences::default()
    };
    preferences::save(&prefs, &path).unwrap();

    match preferences::load(&path) {
        LoadOutcome::Loaded { prefs, report } => {
            assert_eq!(prefs.schema_version, 999);
            assert!(!report.is_clean());
            assert!(report.warnings.iter().any(|w| w.contains("schema")));
        }
        other => panic!("expected Loaded with warning, got {other:?}"),
    }
}

#[test]
fn prefs_load_unknown_fields_ignored() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("prefs.json");
    let json = r#"{"schema_version": 1, "density": "compact", "unknown_future_field": 42}"#;
    std::fs::write(&path, json).unwrap();

    match preferences::load(&path) {
        LoadOutcome::Loaded { prefs, report } => {
            assert_eq!(prefs.density, preferences::DensityMode::Compact);
            assert!(report.is_clean());
        }
        other => panic!("expected Loaded, got {other:?}"),
    }
}

// ══════════════════════════════════════════════════════════════════
//  F8: Preferences — save failures
// ══════════════════════════════════════════════════════════════════

#[test]
fn prefs_save_to_readonly_dir_fails_gracefully() {
    // /proc is read-only on Linux.
    let path = PathBuf::from("/proc/sbh-test/prefs.json");
    let result = preferences::save(&UserPreferences::default(), &path);
    assert!(result.is_err());
}

#[test]
fn prefs_save_creates_parent_dirs() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("deep").join("nested").join("prefs.json");
    let result = preferences::save(&UserPreferences::default(), &path);
    assert!(result.is_ok());
    assert!(path.exists());
}

#[test]
fn prefs_save_atomic_no_tmp_leftover() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("prefs.json");
    preferences::save(&UserPreferences::default(), &path).unwrap();

    let tmp_path = path.with_extension("json.tmp");
    assert!(!tmp_path.exists(), "temp file should not remain after save");
    assert!(path.exists());
}

#[test]
fn prefs_save_then_load_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("prefs.json");

    let prefs = UserPreferences {
        density: preferences::DensityMode::Compact,
        hint_verbosity: preferences::HintVerbosity::Minimal,
        notification_timeout_secs: 15,
        ..Default::default()
    };

    preferences::save(&prefs, &path).unwrap();
    match preferences::load(&path) {
        LoadOutcome::Loaded {
            prefs: loaded,
            report,
        } => {
            assert_eq!(loaded, prefs);
            assert!(report.is_clean());
        }
        other => panic!("expected Loaded, got {other:?}"),
    }
}

// ══════════════════════════════════════════════════════════════════
//  F9: Preferences — debounced writer edge cases
// ══════════════════════════════════════════════════════════════════

#[test]
fn debounced_writer_no_pending_returns_none() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("prefs.json");
    let mut writer = DebouncedWriter::new(path);
    assert!(writer.try_flush(&UserPreferences::default()).is_none());
    assert!(!writer.is_pending());
}

#[test]
fn debounced_writer_immediate_first_write() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("prefs.json");
    let mut writer = DebouncedWriter::new(path.clone()).with_debounce(Duration::ZERO);

    writer.request_save();
    assert!(writer.is_pending());

    let result = writer.try_flush(&UserPreferences::default());
    assert!(result.is_some());
    assert!(result.unwrap().is_ok());
    assert!(path.exists());
    assert!(!writer.is_pending());
}

#[test]
fn debounced_writer_suppresses_during_debounce_window() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("prefs.json");
    let mut writer = DebouncedWriter::new(path).with_debounce(Duration::from_secs(60));

    // First write goes through.
    writer.request_save();
    assert!(writer.try_flush(&UserPreferences::default()).is_some());

    // Second write within debounce is suppressed.
    writer.request_save();
    assert!(writer.try_flush(&UserPreferences::default()).is_none());
    assert!(writer.is_pending()); // Still pending.
}

#[test]
fn debounced_writer_force_flush_bypasses_debounce() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("prefs.json");
    let mut writer = DebouncedWriter::new(path).with_debounce(Duration::from_secs(60));

    // First write.
    writer.request_save();
    assert!(writer.try_flush(&UserPreferences::default()).is_some());

    // Force flush bypasses debounce.
    writer.request_save();
    let result = writer.force_flush(&UserPreferences::default());
    assert!(result.is_some());
    assert!(result.unwrap().is_ok());
    assert!(!writer.is_pending());
}

#[test]
fn debounced_writer_force_flush_no_pending_is_noop() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("prefs.json");
    let mut writer = DebouncedWriter::new(path);
    assert!(writer.force_flush(&UserPreferences::default()).is_none());
}

// ══════════════════════════════════════════════════════════════════
//  F10: Model transitions — degraded mode lifecycle
// ══════════════════════════════════════════════════════════════════

#[test]
fn model_starts_degraded_recovers_on_data_update() {
    let mut h = DashboardHarness::default();
    assert!(h.is_degraded());

    h.feed_state(sample_healthy_state());
    assert!(!h.is_degraded());
}

#[test]
fn model_enters_degraded_on_unavailable_update() {
    let mut h = DashboardHarness::default();
    h.feed_state(sample_healthy_state());
    assert!(!h.is_degraded());

    h.feed_unavailable();
    assert!(h.is_degraded());
    h.last_frame().assert_contains("DEGRADED");
}

#[test]
fn model_recovers_from_degraded_on_fresh_data() {
    let mut h = DashboardHarness::default();

    // Start → degraded → data → healthy → unavailable → degraded → data → healthy
    h.feed_unavailable();
    assert!(h.is_degraded());

    h.feed_state(sample_healthy_state());
    assert!(!h.is_degraded());

    h.feed_unavailable();
    assert!(h.is_degraded());

    h.feed_state(sample_healthy_state());
    assert!(!h.is_degraded());
}

#[test]
fn model_multiple_unavailable_does_not_stack() {
    let mut h = DashboardHarness::default();
    h.feed_unavailable();
    h.feed_unavailable();
    h.feed_unavailable();

    assert!(h.is_degraded());
    assert_eq!(h.notification_count(), 0); // No extra notifications from data updates.
}

// ══════════════════════════════════════════════════════════════════
//  F11: Model transitions — error notifications
// ══════════════════════════════════════════════════════════════════

#[test]
fn model_error_creates_notification() {
    let mut h = DashboardHarness::default();
    h.inject_error("state file read failed", "adapter");
    assert_eq!(h.notification_count(), 1);
    h.last_frame().assert_contains("state file read failed");
}

#[test]
fn model_error_notifications_evict_oldest_beyond_max() {
    let mut h = DashboardHarness::default();
    h.inject_error("error 1", "adapter");
    h.inject_error("error 2", "telemetry");
    h.inject_error("error 3", "preferences");
    assert_eq!(h.notification_count(), 3);

    h.inject_error("error 4", "adapter");
    assert_eq!(h.notification_count(), 3); // Max 3, oldest evicted.
}

#[test]
fn model_error_does_not_affect_degraded_state() {
    let mut h = DashboardHarness::default();
    h.feed_state(sample_healthy_state());
    assert!(!h.is_degraded());

    // Error notification does NOT trigger degraded mode.
    h.inject_error("telemetry query failed", "telemetry");
    assert!(!h.is_degraded());
    assert_eq!(h.notification_count(), 1);
}

// ══════════════════════════════════════════════════════════════════
//  F12: Model transitions — navigation during degraded
// ══════════════════════════════════════════════════════════════════

#[test]
fn navigation_works_during_degraded_mode() {
    let mut h = DashboardHarness::default();
    assert!(h.is_degraded());

    // Should be able to navigate even in degraded mode.
    h.navigate_to_number(3);
    assert_eq!(h.screen(), Screen::Explainability);
    h.navigate_to_number(5);
    assert_eq!(h.screen(), Screen::Ballast);
    h.inject_keycode(ftui_core::event::KeyCode::Escape);
    assert_eq!(h.screen(), Screen::Explainability);
}

#[test]
fn resize_during_degraded_mode_updates_dimensions() {
    let mut h = DashboardHarness::default();
    assert!(h.is_degraded());

    h.resize(200, 50);
    h.last_frame().assert_contains("200x50");
}

// ══════════════════════════════════════════════════════════════════
//  F13: Mixed-fault scenarios
// ══════════════════════════════════════════════════════════════════

#[test]
fn scripted_fault_sequence_maintains_determinism() {
    let script = vec![
        HarnessStep::Tick,
        HarnessStep::FeedHealthyState,
        HarnessStep::Char('3'),       // Navigate to Explainability
        HarnessStep::FeedUnavailable, // Daemon goes down
        HarnessStep::Error {
            message: "sqlite locked".to_string(),
            source: "telemetry".to_string(),
        },
        HarnessStep::FeedHealthyState, // Daemon comes back
        HarnessStep::Error {
            message: "preference save failed".to_string(),
            source: "preferences".to_string(),
        },
        HarnessStep::FeedUnavailable,  // Daemon goes down again
        HarnessStep::FeedHealthyState, // Final recovery
    ];

    let mut h1 = DashboardHarness::default();
    let mut h2 = DashboardHarness::default();
    h1.run_script(&script);
    h2.run_script(&script);

    // Identical scripts must produce identical state.
    assert_eq!(h1.trace_digest(), h2.trace_digest());
    assert_eq!(h1.screen(), h2.screen());
    assert_eq!(h1.is_degraded(), h2.is_degraded());
    assert!(!h1.is_degraded()); // Final state is recovered.
}

#[test]
fn rapid_degraded_recovery_cycling() {
    let mut h = DashboardHarness::default();

    for _ in 0..10 {
        h.feed_unavailable();
        assert!(h.is_degraded());
        h.feed_state(sample_healthy_state());
        assert!(!h.is_degraded());
    }

    // After 10 cycles, model should be in a clean healthy state.
    assert!(!h.is_degraded());
    assert_eq!(h.screen(), Screen::Overview);
}

#[test]
fn error_notifications_during_recovery_cycle() {
    let mut h = DashboardHarness::default();

    h.feed_unavailable();
    h.inject_error("adapter timeout", "adapter");
    assert!(h.is_degraded());
    assert_eq!(h.notification_count(), 1);

    h.feed_state(sample_healthy_state());
    assert!(!h.is_degraded());
    // Notification persists after recovery (auto-dismiss is timer-based).
    assert_eq!(h.notification_count(), 1);
}

// ══════════════════════════════════════════════════════════════════
//  F14: Preferences — validation under fault conditions
// ══════════════════════════════════════════════════════════════════

#[test]
fn prefs_validation_clamps_excessive_timeout() {
    let prefs = UserPreferences {
        notification_timeout_secs: 9999,
        ..Default::default()
    };
    let (fixed, report) = preferences::validate(prefs);
    assert_eq!(fixed.notification_timeout_secs, 300);
    assert!(!report.is_clean());
}

#[test]
fn prefs_load_outcome_into_prefs_graceful_on_all_variants() {
    let missing = LoadOutcome::Missing.into_prefs();
    assert_eq!(missing, UserPreferences::default());

    let corrupt = LoadOutcome::Corrupt {
        details: "bad".to_string(),
        defaults: UserPreferences::default(),
    }
    .into_prefs();
    assert_eq!(corrupt, UserPreferences::default());

    let io_err = LoadOutcome::IoError {
        details: "permission denied".to_string(),
        defaults: UserPreferences::default(),
    }
    .into_prefs();
    assert_eq!(io_err, UserPreferences::default());
}

// ══════════════════════════════════════════════════════════════════
//  F15: State adapter — fallback mount deduplication
// ══════════════════════════════════════════════════════════════════

#[test]
fn fallback_mounts_deduplicated_under_fault() {
    let tmp = TempDir::new().unwrap();
    let adapter = make_adapter(90);

    // Multiple monitor paths on same mount → deduplicated.
    let snap = adapter.load_snapshot(
        &tmp.path().join("missing.json"),
        &[
            PathBuf::from("/tmp/work-a"),
            PathBuf::from("/tmp/work-b"),
            PathBuf::from("/tmp/work-c"),
        ],
    );
    assert_eq!(snap.freshness, StateFreshness::Missing);
    // All /tmp/work-* resolve to /tmp mount → 1 deduped entry.
    assert_eq!(snap.mounts.len(), 1);
    assert_eq!(snap.mounts[0].path, "/tmp");
    assert_eq!(snap.mounts[0].source, SnapshotSource::FilesystemFallback);
}

// ══════════════════════════════════════════════════════════════════
//  F16: Telemetry — JSONL pressure history under fault
// ══════════════════════════════════════════════════════════════════

#[test]
fn telemetry_jsonl_pressure_history_no_matching_mount() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("activity.jsonl");
    let entry = crate::logger::jsonl::LogEntry {
        mount_point: Some("/data".to_string()),
        ..make_log_entry(
            "2026-02-16T00:00:01Z",
            crate::logger::jsonl::EventType::PressureChange,
            crate::logger::jsonl::Severity::Info,
        )
    };
    write_jsonl_entries(&path, &[entry]);

    let adapter = JsonlTelemetryAdapter::open(&path).unwrap();
    // Query for a different mount.
    let result = adapter.pressure_history("/nonexistent", "", 10);
    assert!(result.data.is_empty());
}

// ══════════════════════════════════════════════════════════════════
//  F17: Schema warnings — no drift is the clean baseline
// ══════════════════════════════════════════════════════════════════

#[test]
fn schema_warnings_default_is_clean() {
    let w = SchemaWarnings::default();
    assert!(!w.has_drift());
    assert!(w.unknown_fields.is_empty());
    assert!(w.missing_fields.is_empty());
}

#[test]
fn schema_warnings_with_fields_has_drift() {
    let w = SchemaWarnings {
        unknown_fields: vec!["future_v3".to_string()],
        missing_fields: vec![],
    };
    assert!(w.has_drift());

    let w = SchemaWarnings {
        unknown_fields: vec![],
        missing_fields: vec!["counters".to_string()],
    };
    assert!(w.has_drift());
}
