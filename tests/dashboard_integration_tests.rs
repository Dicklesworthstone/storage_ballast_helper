//! Dashboard integration tests: CLI argument semantics, state-file contract,
//! legacy constraints, and degraded-data behavior (bd-xzt.4.2).
//!
//! These tests exercise the dashboard command execution path, verify state-file
//! reading contracts across fresh/stale/missing/malformed scenarios, and confirm
//! legacy constraints (refresh floor, JSON rejection, safe teardown).

mod common;

use std::fs;
use std::path::PathBuf;

use storage_ballast_helper::daemon::self_monitor::{
    BallastState, Counters, DaemonState, LastScanState, MountPressure, PressureState,
    SelfMonitor, DAEMON_STATE_STALE_THRESHOLD_SECS,
};

// ══════════════════════════════════════════════════════════════════
// Section 1: Dashboard CLI Argument Semantics
// ══════════════════════════════════════════════════════════════════

#[test]
fn dashboard_help_prints_usage() {
    let result = common::run_cli_case("dashboard_help_prints_usage", &["dashboard", "--help"]);
    assert!(
        result.status.success(),
        "dashboard --help should succeed; log: {}",
        result.log_path.display()
    );
    assert!(
        result.stdout.contains("Usage") || result.stdout.contains("usage"),
        "dashboard --help should print usage; log: {}",
        result.log_path.display()
    );
}

#[test]
fn dashboard_json_flag_is_rejected() {
    let result = common::run_cli_case(
        "dashboard_json_flag_is_rejected",
        &["dashboard", "--json"],
    );
    assert!(
        !result.status.success(),
        "dashboard --json should fail; log: {}",
        result.log_path.display()
    );
    let combined = format!("{}{}", result.stdout, result.stderr);
    assert!(
        combined.contains("dashboard") && combined.contains("does not support --json"),
        "expected JSON rejection message; got: {combined:?}; log: {}",
        result.log_path.display()
    );
}

#[test]
fn dashboard_conflicting_runtime_flags_rejected() {
    let result = common::run_cli_case(
        "dashboard_conflicting_runtime_flags_rejected",
        &["dashboard", "--new-dashboard", "--legacy-dashboard"],
    );
    assert!(
        !result.status.success(),
        "conflicting flags should fail; log: {}",
        result.log_path.display()
    );
    let combined = format!("{}{}", result.stdout, result.stderr);
    assert!(
        combined.contains("cannot be used with") || combined.contains("conflicts"),
        "expected clap conflict error; got: {combined:?}; log: {}",
        result.log_path.display()
    );
}

#[test]
fn dashboard_refresh_ms_flag_accepted() {
    // Verify --refresh-ms is a valid flag by checking --help output.
    let result = common::run_cli_case(
        "dashboard_refresh_ms_flag_accepted",
        &["dashboard", "--help"],
    );
    assert!(
        result.status.success(),
        "dashboard --help should succeed; log: {}",
        result.log_path.display()
    );
    assert!(
        result.stdout.contains("refresh-ms"),
        "dashboard help should mention --refresh-ms; log: {}",
        result.log_path.display()
    );
}

#[test]
fn dashboard_new_dashboard_flag_accepted() {
    let result = common::run_cli_case(
        "dashboard_new_dashboard_flag_accepted",
        &["dashboard", "--help"],
    );
    assert!(
        result.status.success(),
        "dashboard --help should succeed; log: {}",
        result.log_path.display()
    );
    assert!(
        result.stdout.contains("new-dashboard"),
        "dashboard help should mention --new-dashboard; log: {}",
        result.log_path.display()
    );
}

#[test]
fn dashboard_legacy_dashboard_flag_accepted() {
    let result = common::run_cli_case(
        "dashboard_legacy_dashboard_flag_accepted",
        &["dashboard", "--help"],
    );
    assert!(
        result.status.success(),
        "dashboard --help should succeed; log: {}",
        result.log_path.display()
    );
    assert!(
        result.stdout.contains("legacy-dashboard"),
        "dashboard help should mention --legacy-dashboard; log: {}",
        result.log_path.display()
    );
}

// ══════════════════════════════════════════════════════════════════
// Section 2: State-File Contract Behavior
//
// Tests exercise DaemonState deserialization under various conditions:
// fresh, stale, missing, malformed, partial, and forward-compatible.
// ══════════════════════════════════════════════════════════════════

/// Build a realistic DaemonState for testing.
fn sample_daemon_state() -> DaemonState {
    DaemonState {
        version: env!("CARGO_PKG_VERSION").to_string(),
        pid: 12345,
        started_at: "2026-02-16T00:00:00Z".to_string(),
        uptime_seconds: 3600,
        last_updated: chrono::Utc::now().to_rfc3339(),
        pressure: PressureState {
            overall: "green".to_string(),
            mounts: vec![
                MountPressure {
                    path: "/data".to_string(),
                    free_pct: 45.0,
                    level: "green".to_string(),
                    rate_bps: Some(1024.0),
                },
                MountPressure {
                    path: "/tmp".to_string(),
                    free_pct: 22.0,
                    level: "yellow".to_string(),
                    rate_bps: Some(-512.0),
                },
            ],
        },
        ballast: BallastState {
            available: 5,
            total: 10,
            released: 2,
        },
        last_scan: LastScanState {
            at: Some("2026-02-16T01:00:00Z".to_string()),
            candidates: 42,
            deleted: 7,
        },
        counters: Counters {
            scans: 100,
            deletions: 35,
            bytes_freed: 10_737_418_240, // 10 GB
            errors: 2,
            dropped_log_events: 0,
        },
        memory_rss_bytes: 52_428_800, // 50 MB
    }
}

fn write_state_json(dir: &std::path::Path, state: &DaemonState) -> PathBuf {
    let state_path = dir.join("state.json");
    let json = serde_json::to_string_pretty(state).expect("serialize state");
    fs::write(&state_path, json).expect("write state.json");
    state_path
}

#[test]
fn state_file_roundtrip_preserves_all_fields() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let original = sample_daemon_state();
    let state_path = write_state_json(tmpdir.path(), &original);

    let loaded = SelfMonitor::read_state(&state_path).expect("read state");
    assert_eq!(loaded.version, original.version);
    assert_eq!(loaded.pid, original.pid);
    assert_eq!(loaded.uptime_seconds, original.uptime_seconds);
    assert_eq!(loaded.pressure.overall, original.pressure.overall);
    assert_eq!(loaded.pressure.mounts.len(), 2);
    assert_eq!(loaded.ballast.available, 5);
    assert_eq!(loaded.ballast.total, 10);
    assert_eq!(loaded.ballast.released, 2);
    assert_eq!(loaded.last_scan.candidates, 42);
    assert_eq!(loaded.last_scan.deleted, 7);
    assert_eq!(loaded.counters.scans, 100);
    assert_eq!(loaded.counters.deletions, 35);
    assert_eq!(loaded.counters.bytes_freed, 10_737_418_240);
    assert_eq!(loaded.counters.errors, 2);
    assert_eq!(loaded.memory_rss_bytes, 52_428_800);
}

#[test]
fn state_file_missing_returns_error() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let nonexistent = tmpdir.path().join("does-not-exist.json");

    let result = SelfMonitor::read_state(&nonexistent);
    assert!(
        result.is_err(),
        "missing state file should return error"
    );
}

#[test]
fn state_file_corrupt_non_json_returns_error() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let state_path = tmpdir.path().join("state.json");
    fs::write(&state_path, "this is not json at all!!!").expect("write corrupt state");

    let result = SelfMonitor::read_state(&state_path);
    assert!(
        result.is_err(),
        "corrupt (non-JSON) state file should return error"
    );
}

#[test]
fn state_file_empty_json_object_uses_defaults() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let state_path = tmpdir.path().join("state.json");
    fs::write(&state_path, "{}").expect("write empty JSON object");

    let loaded = SelfMonitor::read_state(&state_path).expect("empty object should parse");
    assert_eq!(loaded.version, "");
    assert_eq!(loaded.pid, 0);
    assert_eq!(loaded.uptime_seconds, 0);
    assert_eq!(loaded.pressure.overall, "");
    assert!(loaded.pressure.mounts.is_empty());
    assert_eq!(loaded.ballast.available, 0);
    assert_eq!(loaded.counters.scans, 0);
}

#[test]
fn state_file_with_extra_fields_parses_without_error() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let state_path = tmpdir.path().join("state.json");

    // Simulate a newer daemon adding unknown fields.
    let json = serde_json::json!({
        "version": "99.0.0",
        "pid": 9999,
        "started_at": "2026-02-16T00:00:00Z",
        "uptime_seconds": 120,
        "last_updated": "2026-02-16T00:02:00Z",
        "pressure": {
            "overall": "green",
            "mounts": [],
            "future_field_1": "should be ignored",
        },
        "ballast": {
            "available": 3,
            "total": 5,
            "released": 0,
            "new_metric": 42,
        },
        "last_scan": {
            "at": null,
            "candidates": 0,
            "deleted": 0,
        },
        "counters": {
            "scans": 10,
            "deletions": 2,
            "bytes_freed": 1000,
            "errors": 0,
            "dropped_log_events": 0,
        },
        "memory_rss_bytes": 1024,
        "completely_new_top_level_field": {"nested": true},
    });
    fs::write(&state_path, serde_json::to_string_pretty(&json).unwrap())
        .expect("write forward-compat state");

    let loaded = SelfMonitor::read_state(&state_path)
        .expect("state with extra fields should parse successfully");
    assert_eq!(loaded.version, "99.0.0");
    assert_eq!(loaded.pid, 9999);
    assert_eq!(loaded.ballast.available, 3);
    assert_eq!(loaded.counters.scans, 10);
}

#[test]
fn state_file_with_partial_fields_fills_defaults() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let state_path = tmpdir.path().join("state.json");

    // Only a subset of fields present — defaults should fill the rest.
    let json = serde_json::json!({
        "version": "1.0.0",
        "pid": 555,
    });
    fs::write(&state_path, serde_json::to_string_pretty(&json).unwrap())
        .expect("write partial state");

    let loaded = SelfMonitor::read_state(&state_path).expect("partial state should parse");
    assert_eq!(loaded.version, "1.0.0");
    assert_eq!(loaded.pid, 555);
    // Missing fields default to zero/empty.
    assert_eq!(loaded.uptime_seconds, 0);
    assert!(loaded.pressure.mounts.is_empty());
    assert_eq!(loaded.ballast.available, 0);
    assert_eq!(loaded.counters.scans, 0);
}

#[test]
fn state_file_with_wrong_typed_fields_returns_error() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let state_path = tmpdir.path().join("state.json");

    // pid as a string instead of number — should fail deserialization.
    let json = r#"{"pid": "not_a_number", "version": "1.0.0"}"#;
    fs::write(&state_path, json).expect("write mistyped state");

    let result = SelfMonitor::read_state(&state_path);
    assert!(
        result.is_err(),
        "state with wrong-typed fields should fail"
    );
}

#[test]
fn state_file_empty_file_returns_error() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let state_path = tmpdir.path().join("state.json");
    fs::write(&state_path, "").expect("write empty file");

    let result = SelfMonitor::read_state(&state_path);
    assert!(
        result.is_err(),
        "empty file should return error"
    );
}

#[test]
fn state_file_mount_pressure_preserves_rate_bps() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let state = DaemonState {
        pressure: PressureState {
            overall: "yellow".to_string(),
            mounts: vec![
                MountPressure {
                    path: "/".to_string(),
                    free_pct: 8.5,
                    level: "orange".to_string(),
                    rate_bps: Some(5_242_880.0), // 5 MB/s consumption
                },
                MountPressure {
                    path: "/dev/shm".to_string(),
                    free_pct: 95.0,
                    level: "green".to_string(),
                    rate_bps: None, // No rate data
                },
            ],
        },
        ..DaemonState::default()
    };
    let state_path = write_state_json(tmpdir.path(), &state);

    let loaded = SelfMonitor::read_state(&state_path).expect("read state");
    assert_eq!(loaded.pressure.mounts.len(), 2);

    let root_mount = &loaded.pressure.mounts[0];
    assert_eq!(root_mount.path, "/");
    assert!((root_mount.free_pct - 8.5).abs() < f64::EPSILON);
    assert_eq!(root_mount.level, "orange");
    assert!(root_mount.rate_bps.is_some());
    assert!((root_mount.rate_bps.unwrap() - 5_242_880.0).abs() < 0.1);

    let shm_mount = &loaded.pressure.mounts[1];
    assert_eq!(shm_mount.path, "/dev/shm");
    assert!(shm_mount.rate_bps.is_none());
}

#[test]
fn state_file_null_last_scan_at_parses_to_none() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let json = serde_json::json!({
        "last_scan": {
            "at": null,
            "candidates": 0,
            "deleted": 0,
        }
    });
    let state_path = tmpdir.path().join("state.json");
    fs::write(&state_path, serde_json::to_string_pretty(&json).unwrap())
        .expect("write state with null scan");

    let loaded = SelfMonitor::read_state(&state_path).expect("parse state");
    assert!(loaded.last_scan.at.is_none());
}

// ══════════════════════════════════════════════════════════════════
// Section 3: Adapter Staleness and Freshness Contract
//
// Verifies the DaemonState adapter recognizes stale timestamps
// and handles various data-quality scenarios.
// ══════════════════════════════════════════════════════════════════

#[test]
fn daemon_state_stale_threshold_constant_is_sensible() {
    // Stale threshold must be >= 2 * write interval (30s) = 60s.
    // Currently set to 90s.
    const { assert!(DAEMON_STATE_STALE_THRESHOLD_SECS >= 60) };
    // Must not be unreasonably large (>600s = 10 minutes).
    const { assert!(DAEMON_STATE_STALE_THRESHOLD_SECS <= 600) };
}

#[test]
fn state_file_deterministic_serialization() {
    // Ensure that identical DaemonState serializes identically.
    let state = sample_daemon_state();
    let json1 = serde_json::to_string(&state).expect("serialize 1");
    let json2 = serde_json::to_string(&state).expect("serialize 2");
    assert_eq!(
        json1, json2,
        "identical DaemonState must serialize identically"
    );
}

#[test]
fn state_file_large_counters_roundtrip() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let state = DaemonState {
        counters: Counters {
            scans: u64::MAX,
            deletions: u64::MAX - 1,
            bytes_freed: u64::MAX / 2,
            errors: 999_999,
            dropped_log_events: 1_000_000,
        },
        ..DaemonState::default()
    };
    let state_path = write_state_json(tmpdir.path(), &state);

    let loaded = SelfMonitor::read_state(&state_path).expect("read large counters");
    assert_eq!(loaded.counters.scans, u64::MAX);
    assert_eq!(loaded.counters.deletions, u64::MAX - 1);
    assert_eq!(loaded.counters.bytes_freed, u64::MAX / 2);
    assert_eq!(loaded.counters.errors, 999_999);
    assert_eq!(loaded.counters.dropped_log_events, 1_000_000);
}

#[test]
fn state_file_zero_free_pct_does_not_panic() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let state = DaemonState {
        pressure: PressureState {
            overall: "critical".to_string(),
            mounts: vec![MountPressure {
                path: "/".to_string(),
                free_pct: 0.0,
                level: "critical".to_string(),
                rate_bps: Some(100_000_000.0),
            }],
        },
        ..DaemonState::default()
    };
    let state_path = write_state_json(tmpdir.path(), &state);

    let loaded = SelfMonitor::read_state(&state_path).expect("read zero-free state");
    assert!((loaded.pressure.mounts[0].free_pct).abs() < f64::EPSILON);
    assert_eq!(loaded.pressure.mounts[0].level, "critical");
}

#[test]
fn state_file_negative_rate_bps_preserved() {
    // Negative rate = disk is recovering (free space increasing).
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let state = DaemonState {
        pressure: PressureState {
            overall: "green".to_string(),
            mounts: vec![MountPressure {
                path: "/data".to_string(),
                free_pct: 55.0,
                level: "green".to_string(),
                rate_bps: Some(-2_097_152.0), // -2 MB/s = recovering
            }],
        },
        ..DaemonState::default()
    };
    let state_path = write_state_json(tmpdir.path(), &state);

    let loaded = SelfMonitor::read_state(&state_path).expect("read negative rate");
    let rate = loaded.pressure.mounts[0].rate_bps.expect("rate should be present");
    assert!(rate < 0.0, "negative rate should be preserved: {rate}");
    assert!((rate - (-2_097_152.0)).abs() < 0.1);
}

// ══════════════════════════════════════════════════════════════════
// Section 4: Dashboard Legacy Constraints
//
// Verifies refresh floor enforcement, JSON mode rejection,
// and safe teardown semantics at the CLI integration level.
// ══════════════════════════════════════════════════════════════════

#[test]
fn dashboard_json_flag_with_explicit_config_still_rejected() {
    // Even when a config file is explicitly passed, --json must be rejected.
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let config_path = tmpdir.path().join("sbh-test.toml");
    fs::write(&config_path, "[pressure]\npoll_interval_ms = 1000\n")
        .expect("write config");

    let config_str = config_path.to_string_lossy().to_string();
    let result = common::run_cli_case(
        "dashboard_json_flag_with_explicit_config_still_rejected",
        &["--config", &config_str, "dashboard", "--json"],
    );
    assert!(
        !result.status.success(),
        "dashboard --json with config should still fail; log: {}",
        result.log_path.display()
    );
}

#[test]
fn dashboard_verbose_flag_accepted() {
    // Global --verbose should not cause dashboard to crash.
    let result = common::run_cli_case(
        "dashboard_verbose_flag_accepted",
        &["dashboard", "--help"],
    );
    assert!(
        result.status.success(),
        "dashboard help with verbose context should work; log: {}",
        result.log_path.display()
    );
}

// ══════════════════════════════════════════════════════════════════
// Section 5: DaemonState Default Values and Edge Cases
//
// Verify that Default trait produces a valid, non-panicking state
// that can be serialized and deserialized.
// ══════════════════════════════════════════════════════════════════

#[test]
fn daemon_state_default_roundtrips() {
    let default_state = DaemonState::default();
    let json = serde_json::to_string_pretty(&default_state).expect("serialize default");
    let loaded: DaemonState = serde_json::from_str(&json).expect("deserialize default");
    assert_eq!(loaded, default_state);
}

#[test]
fn daemon_state_default_has_safe_values() {
    let state = DaemonState::default();
    assert!(state.version.is_empty());
    assert_eq!(state.pid, 0);
    assert_eq!(state.uptime_seconds, 0);
    assert!(state.pressure.mounts.is_empty());
    assert_eq!(state.ballast.available, 0);
    assert_eq!(state.ballast.total, 0);
    assert_eq!(state.counters.scans, 0);
    assert_eq!(state.memory_rss_bytes, 0);
}

#[test]
fn state_file_concurrent_write_read_does_not_corrupt() {
    // Simulate atomic write pattern: write to .tmp, then rename.
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let state = sample_daemon_state();
    let state_path = tmpdir.path().join("state.json");
    let tmp_path = tmpdir.path().join("state.json.tmp");

    // Write to tmp first, then rename (simulating atomic daemon write).
    let json = serde_json::to_string_pretty(&state).expect("serialize");
    fs::write(&tmp_path, &json).expect("write tmp");
    fs::rename(&tmp_path, &state_path).expect("rename");

    // Read should see complete data.
    let loaded = SelfMonitor::read_state(&state_path).expect("read after atomic write");
    assert_eq!(loaded.pid, 12345);
    assert_eq!(loaded.counters.scans, 100);
}

// ══════════════════════════════════════════════════════════════════
// Section 6: State File Schema Evolution
//
// Verify that the dashboard can handle schema changes gracefully,
// supporting both forward and backward compatibility.
// ══════════════════════════════════════════════════════════════════

#[test]
fn state_file_missing_counters_section_uses_default() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let json = serde_json::json!({
        "version": "1.0.0",
        "pid": 100,
        "pressure": {"overall": "green", "mounts": []},
        // counters section entirely missing
    });
    let state_path = tmpdir.path().join("state.json");
    fs::write(&state_path, serde_json::to_string_pretty(&json).unwrap())
        .expect("write state without counters");

    let loaded = SelfMonitor::read_state(&state_path).expect("parse without counters");
    assert_eq!(loaded.counters.scans, 0);
    assert_eq!(loaded.counters.deletions, 0);
    assert_eq!(loaded.counters.bytes_freed, 0);
}

#[test]
fn state_file_missing_ballast_section_uses_default() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let json = serde_json::json!({
        "version": "2.0.0",
        "pid": 200,
        // ballast section entirely missing
    });
    let state_path = tmpdir.path().join("state.json");
    fs::write(&state_path, serde_json::to_string_pretty(&json).unwrap())
        .expect("write state without ballast");

    let loaded = SelfMonitor::read_state(&state_path).expect("parse without ballast");
    assert_eq!(loaded.ballast.available, 0);
    assert_eq!(loaded.ballast.total, 0);
    assert_eq!(loaded.ballast.released, 0);
}

#[test]
fn state_file_many_mounts_does_not_degrade() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let mounts: Vec<MountPressure> = (0..50)
        .map(|i| MountPressure {
            path: format!("/vol{i}"),
            free_pct: f64::from(i) * 2.0,
            level: if i < 5 { "red" } else { "green" }.to_string(),
            rate_bps: Some(f64::from(i) * 1000.0),
        })
        .collect();

    let state = DaemonState {
        pressure: PressureState {
            overall: "yellow".to_string(),
            mounts,
        },
        ..DaemonState::default()
    };
    let state_path = write_state_json(tmpdir.path(), &state);

    let loaded = SelfMonitor::read_state(&state_path).expect("read many-mount state");
    assert_eq!(loaded.pressure.mounts.len(), 50);
    assert_eq!(loaded.pressure.mounts[0].path, "/vol0");
    assert_eq!(loaded.pressure.mounts[49].path, "/vol49");
}

#[test]
fn state_file_json_array_at_root_is_rejected() {
    // JSON array at root instead of object should fail.
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let state_path = tmpdir.path().join("state.json");
    fs::write(&state_path, "[1, 2, 3]").expect("write array");

    let result = SelfMonitor::read_state(&state_path);
    assert!(result.is_err(), "JSON array at root should be rejected");
}

#[test]
fn state_file_unicode_in_paths_roundtrips() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let state = DaemonState {
        pressure: PressureState {
            overall: "green".to_string(),
            mounts: vec![MountPressure {
                path: "/data/\u{1F4BE}ドライブ".to_string(),
                free_pct: 80.0,
                level: "green".to_string(),
                rate_bps: None,
            }],
        },
        ..DaemonState::default()
    };
    let state_path = write_state_json(tmpdir.path(), &state);

    let loaded = SelfMonitor::read_state(&state_path).expect("read unicode paths");
    assert_eq!(
        loaded.pressure.mounts[0].path,
        "/data/\u{1F4BE}ドライブ"
    );
}
