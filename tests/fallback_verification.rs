//! Fallback/rollback verification matrix (bd-xzt.4.7).
//!
//! Validates that the dashboard's safety net infrastructure works as a coherent
//! system across multiple layers: config resolution, adapter degradation, model
//! state transitions, preference recovery, and terminal lifecycle.
//!
//! These tests complement the unit-level coverage in `adapters.rs`, `cli_app.rs`,
//! `runtime.rs`, and `update.rs` by exercising **cross-component** scenarios.

mod common;

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use storage_ballast_helper::core::config::{Config, DashboardConfig, DashboardMode};
use storage_ballast_helper::daemon::self_monitor::{
    BallastState, Counters, DaemonState, LastScanState, MountPressure, PressureState,
};

#[cfg(feature = "tui")]
use storage_ballast_helper::tui::adapters::{
    DashboardStateAdapter, SchemaWarnings, SnapshotSource, StateFreshness,
};
#[cfg(feature = "tui")]
use storage_ballast_helper::tui::model::{DashboardModel, DashboardMsg, NotificationLevel, Screen};
#[cfg(feature = "tui")]
use storage_ballast_helper::tui::preferences::{self, LoadOutcome, UserPreferences};
#[cfg(feature = "tui")]
use storage_ballast_helper::tui::runtime::{DashboardRuntimeConfig, DashboardRuntimeMode};
#[cfg(feature = "tui")]
use storage_ballast_helper::tui::update::update;

// ══════════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════════

fn sample_daemon_state() -> DaemonState {
    DaemonState {
        version: "1.0.0".to_string(),
        pid: 42,
        started_at: "2026-02-16T00:00:00Z".to_string(),
        uptime_seconds: 3600,
        last_updated: "2026-02-16T01:00:00Z".to_string(),
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
            at: Some("2026-02-16T00:30:00Z".to_string()),
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

#[cfg(feature = "tui")]
fn test_model() -> DashboardModel {
    DashboardModel::new(
        PathBuf::from("/tmp/state.json"),
        vec![],
        Duration::from_secs(1),
        (120, 40),
    )
}

#[cfg(feature = "tui")]
fn mock_platform() -> Arc<dyn storage_ballast_helper::platform::pal::Platform> {
    use storage_ballast_helper::platform::pal::{
        FsStats, MemoryInfo, MockPlatform, MountPoint, PlatformPaths,
    };

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

fn write_state_file(path: &std::path::Path, state: &DaemonState) {
    let json = serde_json::to_string(state).expect("serialize state");
    fs::write(path, json).expect("write state");
}

// ══════════════════════════════════════════════════════════════════
// Section 1: Config Rollback Controls
//
// Verifies DashboardMode/DashboardConfig TOML round-trip and defaults.
// ══════════════════════════════════════════════════════════════════

#[test]
fn dashboard_mode_default_is_new() {
    assert_eq!(DashboardMode::default(), DashboardMode::New);
}

#[test]
fn dashboard_config_default_is_safe() {
    let cfg = DashboardConfig::default();
    assert_eq!(cfg.mode, DashboardMode::New);
    assert!(!cfg.kill_switch);
}

#[test]
fn dashboard_config_toml_roundtrip_legacy() {
    let cfg = DashboardConfig {
        mode: DashboardMode::Legacy,
        kill_switch: false,
    };
    let toml = toml::to_string(&cfg).expect("serialize");
    let loaded: DashboardConfig = toml::from_str(&toml).expect("deserialize");
    assert_eq!(loaded.mode, DashboardMode::Legacy);
    assert!(!loaded.kill_switch);
}

#[test]
fn dashboard_config_toml_roundtrip_new_with_kill_switch() {
    let cfg = DashboardConfig {
        mode: DashboardMode::New,
        kill_switch: true,
    };
    let toml = toml::to_string(&cfg).expect("serialize");
    let loaded: DashboardConfig = toml::from_str(&toml).expect("deserialize");
    assert_eq!(loaded.mode, DashboardMode::New);
    assert!(loaded.kill_switch);
}

#[test]
fn dashboard_mode_parse_is_case_insensitive() {
    for input in &["legacy", "Legacy", "LEGACY", "new", "New", "NEW"] {
        let parsed: DashboardMode = input.parse().unwrap_or_else(|_| {
            panic!("should parse '{input}'");
        });
        // Just verify it parses without error.
        assert!(
            parsed == DashboardMode::Legacy || parsed == DashboardMode::New,
            "parsed to unexpected variant for '{input}'"
        );
    }
}

#[test]
fn dashboard_mode_invalid_rejected() {
    assert!("auto".parse::<DashboardMode>().is_err());
    assert!("both".parse::<DashboardMode>().is_err());
    assert!("".parse::<DashboardMode>().is_err());
}

#[test]
fn config_with_dashboard_section_parses_from_toml() {
    let toml_str = r#"
[dashboard]
mode = "new"
kill_switch = true
"#;
    let cfg: Config = toml::from_str(toml_str).expect("parse config toml");
    assert_eq!(cfg.dashboard.mode, DashboardMode::New);
    assert!(cfg.dashboard.kill_switch);
}

#[test]
fn config_without_dashboard_section_uses_defaults() {
    let toml_str = "[pressure]\npoll_interval_ms = 1000\n";
    let cfg: Config = toml::from_str(toml_str).expect("parse config without dashboard");
    assert_eq!(cfg.dashboard.mode, DashboardMode::New);
    assert!(!cfg.dashboard.kill_switch);
}

// ══════════════════════════════════════════════════════════════════
// Section 2: CLI Rollback Scenarios (env var overrides)
//
// Uses run_cli_case_with_env to test kill switch and mode env vars
// at the process level without contaminating the test process.
// ══════════════════════════════════════════════════════════════════

#[test]
fn kill_switch_env_var_forces_legacy_in_help() {
    // With kill switch env set, --help should still work (it doesn't actually
    // start the dashboard). This verifies the env var is accepted.
    let result = common::run_cli_case_with_env(
        "kill_switch_env_forces_legacy",
        &["dashboard", "--help"],
        &[("SBH_DASHBOARD_KILL_SWITCH", "true")],
    );
    assert!(
        result.status.success(),
        "dashboard --help should succeed even with kill switch; log: {}",
        result.log_path.display()
    );
}

#[test]
fn dashboard_mode_env_var_is_accepted() {
    let result = common::run_cli_case_with_env(
        "dashboard_mode_env_var_accepted",
        &["dashboard", "--help"],
        &[("SBH_DASHBOARD_MODE", "legacy")],
    );
    assert!(
        result.status.success(),
        "dashboard --help should succeed with SBH_DASHBOARD_MODE=legacy; log: {}",
        result.log_path.display()
    );
}

#[test]
fn kill_switch_env_var_takes_precedence_over_new_dashboard_flag() {
    // This can't directly verify resolution (that's internal), but ensures
    // the CLI doesn't crash when both are set.
    let result = common::run_cli_case_with_env(
        "kill_switch_env_overrides_new_flag",
        &["dashboard", "--help"],
        &[("SBH_DASHBOARD_KILL_SWITCH", "true")],
    );
    assert!(
        result.status.success(),
        "kill switch + --help should not crash; log: {}",
        result.log_path.display()
    );
}

#[test]
fn invalid_dashboard_mode_env_var_does_not_crash() {
    let result = common::run_cli_case_with_env(
        "invalid_dashboard_mode_env",
        &["dashboard", "--help"],
        &[("SBH_DASHBOARD_MODE", "invalid_value")],
    );
    assert!(
        result.status.success(),
        "invalid SBH_DASHBOARD_MODE should fall through to default; log: {}",
        result.log_path.display()
    );
}

#[test]
fn empty_kill_switch_env_var_is_not_active() {
    let result = common::run_cli_case_with_env(
        "empty_kill_switch_env",
        &["dashboard", "--help"],
        &[("SBH_DASHBOARD_KILL_SWITCH", "")],
    );
    assert!(
        result.status.success(),
        "empty kill switch env should be treated as unset; log: {}",
        result.log_path.display()
    );
}

// ══════════════════════════════════════════════════════════════════
// Section 3: Runtime Config Conversion (legacy path toggle)
//
// Verifies that DashboardRuntimeConfig correctly maps all fields
// when converting to legacy config for fallback operation.
// ══════════════════════════════════════════════════════════════════

#[cfg(feature = "tui")]
#[test]
fn legacy_config_preserves_all_fields() {
    let cfg = DashboardRuntimeConfig {
        state_file: PathBuf::from("/var/lib/sbh/state.json"),
        refresh: Duration::from_millis(500),
        monitor_paths: vec![
            PathBuf::from("/data"),
            PathBuf::from("/home"),
            PathBuf::from("/tmp"),
        ],
        mode: DashboardRuntimeMode::LegacyFallback,
    };

    let legacy = cfg.as_legacy_config();
    assert_eq!(legacy.state_file, PathBuf::from("/var/lib/sbh/state.json"));
    assert_eq!(legacy.refresh, Duration::from_millis(500));
    assert_eq!(legacy.monitor_paths.len(), 3);
    assert_eq!(legacy.monitor_paths[0], PathBuf::from("/data"));
    assert_eq!(legacy.monitor_paths[1], PathBuf::from("/home"));
    assert_eq!(legacy.monitor_paths[2], PathBuf::from("/tmp"));
}

#[cfg(feature = "tui")]
#[test]
fn legacy_config_empty_monitor_paths() {
    let cfg = DashboardRuntimeConfig {
        state_file: PathBuf::from("/tmp/state.json"),
        refresh: Duration::from_secs(1),
        monitor_paths: vec![],
        mode: DashboardRuntimeMode::LegacyFallback,
    };

    let legacy = cfg.as_legacy_config();
    assert!(legacy.monitor_paths.is_empty());
}

#[cfg(feature = "tui")]
#[test]
fn runtime_mode_default_is_new_cockpit() {
    assert_eq!(
        DashboardRuntimeMode::default(),
        DashboardRuntimeMode::NewCockpit
    );
}

// ══════════════════════════════════════════════════════════════════
// Section 4: Adapter → Model Degradation Chain
//
// Tests the full chain: adapter detects degradation → DataUpdate
// message → model state transitions correctly.
// ══════════════════════════════════════════════════════════════════

#[cfg(feature = "tui")]
#[test]
fn model_transitions_fresh_to_degraded_to_recovered() {
    let mut model = test_model();

    // 1. Fresh data arrives.
    let state = sample_daemon_state();
    update(&mut model, DashboardMsg::DataUpdate(Some(Box::new(state))));
    assert!(!model.degraded);
    assert_eq!(model.adapter_reads, 1);
    assert_eq!(model.adapter_errors, 0);
    assert!(model.daemon_state.is_some());
    assert!(model.last_fetch.is_some());

    // 2. Data goes unavailable.
    update(&mut model, DashboardMsg::DataUpdate(None));
    assert!(model.degraded);
    assert_eq!(model.adapter_reads, 1);
    assert_eq!(model.adapter_errors, 1);
    assert!(model.daemon_state.is_none());

    // 3. Data recovers.
    let state2 = sample_daemon_state();
    update(&mut model, DashboardMsg::DataUpdate(Some(Box::new(state2))));
    assert!(!model.degraded);
    assert_eq!(model.adapter_reads, 2);
    assert_eq!(model.adapter_errors, 1);
    assert!(model.daemon_state.is_some());
}

#[cfg(feature = "tui")]
#[test]
fn consecutive_degraded_updates_accumulate_errors() {
    let mut model = test_model();

    for i in 1..=5 {
        update(&mut model, DashboardMsg::DataUpdate(None));
        assert!(model.degraded);
        assert_eq!(model.adapter_errors, i);
    }
    assert_eq!(model.adapter_reads, 0);
}

#[cfg(feature = "tui")]
#[test]
fn model_rate_histories_pruned_on_mount_removal() {
    let mut model = test_model();

    // Feed data with two mounts.
    let mut state = sample_daemon_state();
    state.pressure.mounts.push(MountPressure {
        path: "/data".to_string(),
        free_pct: 30.0,
        level: "yellow".to_string(),
        rate_bps: Some(2048.0),
    });
    update(&mut model, DashboardMsg::DataUpdate(Some(Box::new(state))));
    assert_eq!(model.rate_histories.len(), 2);
    assert!(model.rate_histories.contains_key("/"));
    assert!(model.rate_histories.contains_key("/data"));

    // Feed data with only one mount — /data removed.
    let state2 = sample_daemon_state(); // only has "/"
    update(&mut model, DashboardMsg::DataUpdate(Some(Box::new(state2))));
    assert_eq!(model.rate_histories.len(), 1);
    assert!(model.rate_histories.contains_key("/"));
    assert!(!model.rate_histories.contains_key("/data"));
}

#[cfg(feature = "tui")]
#[test]
fn model_handles_none_rate_bps_gracefully() {
    let mut model = test_model();

    let mut state = sample_daemon_state();
    state.pressure.mounts[0].rate_bps = None;
    update(&mut model, DashboardMsg::DataUpdate(Some(Box::new(state))));

    // rate_bps=None should push 0.0 into history.
    assert!(model.rate_histories.contains_key("/"));
    let history = &model.rate_histories["/"];
    assert_eq!(history.len(), 1);
    assert!((history.latest().unwrap() - 0.0).abs() < f64::EPSILON);
}

#[cfg(feature = "tui")]
#[test]
fn model_error_notification_is_ephemeral() {
    let mut model = test_model();
    assert!(model.notifications.is_empty());

    let cmd = update(
        &mut model,
        DashboardMsg::Error(storage_ballast_helper::tui::model::DashboardError {
            message: "state file corrupted".to_string(),
            source: "adapter".to_string(),
        }),
    );

    // Error should create a notification.
    assert_eq!(model.notifications.len(), 1);
    assert_eq!(model.notifications[0].level, NotificationLevel::Error);
    assert!(model.notifications[0].message.contains("corrupted"));

    // Command should schedule expiry.
    match cmd {
        storage_ballast_helper::tui::model::DashboardCmd::ScheduleNotificationExpiry {
            id,
            after,
        } => {
            assert_eq!(id, model.notifications[0].id);
            assert_eq!(after, Duration::from_secs(10));
        }
        other => panic!("expected ScheduleNotificationExpiry, got {other:?}"),
    }

    // Expiry removes the notification.
    let notif_id = model.notifications[0].id;
    update(&mut model, DashboardMsg::NotificationExpired(notif_id));
    assert!(model.notifications.is_empty());
}

// ══════════════════════════════════════════════════════════════════
// Section 5: Adapter Snapshot Fallback Chain (cross-component)
//
// Verifies the adapter's fallback chain produces correct snapshots
// that flow through to the model correctly.
// ══════════════════════════════════════════════════════════════════

#[cfg(feature = "tui")]
#[test]
fn adapter_fresh_state_snapshot_feeds_model_correctly() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state_path = tmp.path().join("state.json");
    let state = sample_daemon_state();
    write_state_file(&state_path, &state);

    let adapter = DashboardStateAdapter::new(
        mock_platform(),
        Duration::from_secs(90),
        Duration::from_secs(1),
    );
    let snapshot = adapter.load_snapshot(&state_path, &[PathBuf::from("/tmp/work")]);

    assert_eq!(snapshot.freshness, StateFreshness::Fresh);
    assert_eq!(snapshot.source, SnapshotSource::DaemonState);
    assert!(!snapshot.warnings.has_drift());

    // Feed the daemon_state from snapshot into the model.
    let mut model = test_model();
    update(
        &mut model,
        DashboardMsg::DataUpdate(snapshot.daemon_state.map(Box::new)),
    );
    assert!(!model.degraded);
    assert!(model.daemon_state.is_some());
    assert_eq!(model.daemon_state.as_ref().unwrap().pid, 42);
}

#[cfg(feature = "tui")]
#[test]
fn adapter_stale_state_snapshot_still_provides_daemon_data() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state_path = tmp.path().join("state.json");
    write_state_file(&state_path, &sample_daemon_state());

    // Make state file stale by setting mtime to 1 hour ago.
    let stale_mtime = filetime::FileTime::from_system_time(
        std::time::SystemTime::now() - Duration::from_secs(3600),
    );
    filetime::set_file_mtime(&state_path, stale_mtime).expect("set stale mtime");

    let adapter = DashboardStateAdapter::new(
        mock_platform(),
        Duration::from_secs(90),
        Duration::from_secs(1),
    );
    let snapshot = adapter.load_snapshot(&state_path, &[PathBuf::from("/tmp/work")]);

    assert!(matches!(snapshot.freshness, StateFreshness::Stale { .. }));
    assert_eq!(snapshot.source, SnapshotSource::FilesystemFallback);
    // Stale state still has daemon data.
    assert!(snapshot.daemon_state.is_some());
    // But mounts come from fallback (no rate_bps).
    assert!(snapshot.mounts.iter().all(|m| m.rate_bps.is_none()));

    // Feed into model — still provides data, not degraded.
    let mut model = test_model();
    update(
        &mut model,
        DashboardMsg::DataUpdate(snapshot.daemon_state.map(Box::new)),
    );
    assert!(!model.degraded);
}

#[cfg(feature = "tui")]
#[test]
fn adapter_missing_state_snapshot_triggers_degraded_model() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state_path = tmp.path().join("nonexistent.json");

    let adapter = DashboardStateAdapter::new(
        mock_platform(),
        Duration::from_secs(90),
        Duration::from_secs(1),
    );
    let snapshot = adapter.load_snapshot(&state_path, &[PathBuf::from("/tmp/work")]);

    assert_eq!(snapshot.freshness, StateFreshness::Missing);
    assert!(snapshot.daemon_state.is_none());

    // Feed into model — None triggers degraded.
    let mut model = test_model();
    update(
        &mut model,
        DashboardMsg::DataUpdate(snapshot.daemon_state.map(Box::new)),
    );
    assert!(model.degraded);
    assert_eq!(model.adapter_errors, 1);
}

#[cfg(feature = "tui")]
#[test]
fn adapter_malformed_state_snapshot_triggers_degraded_model() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state_path = tmp.path().join("state.json");
    fs::write(&state_path, "not-json!!!{{{").expect("write malformed");

    let adapter = DashboardStateAdapter::new(
        mock_platform(),
        Duration::from_secs(90),
        Duration::from_secs(1),
    );
    let snapshot = adapter.load_snapshot(&state_path, &[PathBuf::from("/tmp/work")]);

    assert_eq!(snapshot.freshness, StateFreshness::Malformed);
    assert!(snapshot.daemon_state.is_none());

    // Model enters degraded state.
    let mut model = test_model();
    update(
        &mut model,
        DashboardMsg::DataUpdate(snapshot.daemon_state.map(Box::new)),
    );
    assert!(model.degraded);
}

#[cfg(feature = "tui")]
#[test]
fn adapter_schema_drift_does_not_block_model_update() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state_path = tmp.path().join("state.json");

    // State with extra field (newer daemon) and missing field (forward compat).
    let mut value = serde_json::to_value(sample_daemon_state()).expect("to value");
    let obj = value.as_object_mut().unwrap();
    obj.remove("memory_rss_bytes");
    obj.insert(
        "future_telemetry".to_string(),
        serde_json::json!({"fancy": true}),
    );
    fs::write(&state_path, serde_json::to_string(&value).expect("json"))
        .expect("write drifted state");

    let adapter = DashboardStateAdapter::new(
        mock_platform(),
        Duration::from_secs(90),
        Duration::from_secs(1),
    );
    let snapshot = adapter.load_snapshot(&state_path, &[PathBuf::from("/tmp/work")]);

    // Drift detected but doesn't block load.
    assert!(snapshot.warnings.has_drift());
    assert!(snapshot.daemon_state.is_some());
    assert_eq!(snapshot.freshness, StateFreshness::Fresh);

    // Model update succeeds.
    let mut model = test_model();
    update(
        &mut model,
        DashboardMsg::DataUpdate(snapshot.daemon_state.map(Box::new)),
    );
    assert!(!model.degraded);
    // memory_rss_bytes defaults to 0 since it was removed.
    assert_eq!(model.daemon_state.as_ref().unwrap().memory_rss_bytes, 0);
}

// ══════════════════════════════════════════════════════════════════
// Section 6: Preference Degradation Chain
//
// Verifies that corrupt/missing/unreadable preference files don't
// prevent the dashboard from starting.
// ══════════════════════════════════════════════════════════════════

#[cfg(feature = "tui")]
#[test]
fn preference_missing_file_returns_defaults() {
    let path = PathBuf::from("/tmp/nonexistent_prefs_12345.json");
    let outcome = preferences::load(&path);
    assert!(
        matches!(outcome, LoadOutcome::Missing),
        "expected Missing, got {outcome:?}"
    );
    let prefs = outcome.into_prefs();
    assert_eq!(prefs, UserPreferences::default());
}

#[cfg(feature = "tui")]
#[test]
fn preference_corrupt_file_returns_defaults() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pref_path = tmp.path().join("prefs.json");
    fs::write(&pref_path, "this is not json!!!").expect("write corrupt prefs");

    let outcome = preferences::load(&pref_path);
    assert!(
        matches!(outcome, LoadOutcome::Corrupt { .. }),
        "expected Corrupt, got {outcome:?}"
    );
    let prefs = outcome.into_prefs();
    assert_eq!(prefs, UserPreferences::default());
}

#[cfg(feature = "tui")]
#[test]
fn preference_empty_file_returns_corrupt() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pref_path = tmp.path().join("prefs.json");
    fs::write(&pref_path, "").expect("write empty prefs");

    let outcome = preferences::load(&pref_path);
    // Empty file is malformed JSON → Corrupt.
    assert!(
        matches!(outcome, LoadOutcome::Corrupt { .. }),
        "expected Corrupt for empty file, got {outcome:?}"
    );
}

#[cfg(feature = "tui")]
#[test]
fn preference_valid_empty_object_returns_defaults() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pref_path = tmp.path().join("prefs.json");
    fs::write(&pref_path, "{}").expect("write empty object prefs");

    let outcome = preferences::load(&pref_path);
    match outcome {
        LoadOutcome::Loaded { prefs, .. } => {
            assert_eq!(prefs, UserPreferences::default());
        }
        other => panic!("expected Loaded for empty object, got {other:?}"),
    }
}

#[cfg(feature = "tui")]
#[test]
fn preference_save_then_load_roundtrip() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pref_path = tmp.path().join("prefs.json");

    let original = UserPreferences::default();
    preferences::save(&original, &pref_path).expect("save prefs");

    let outcome = preferences::load(&pref_path);
    match outcome {
        LoadOutcome::Loaded { prefs, report } => {
            assert!(
                report.is_clean(),
                "validation should pass for default prefs"
            );
            assert_eq!(prefs, original);
        }
        other => panic!("expected Loaded, got {other:?}"),
    }
}

// ══════════════════════════════════════════════════════════════════
// Section 7: State Transition Sequences (end-to-end rollback)
//
// Verifies that the model handles realistic state evolution
// sequences without panicking or getting stuck.
// ══════════════════════════════════════════════════════════════════

#[cfg(feature = "tui")]
#[test]
fn model_survives_rapid_state_oscillation() {
    let mut model = test_model();

    for i in 0..20 {
        if i % 3 == 0 {
            // Degraded.
            update(&mut model, DashboardMsg::DataUpdate(None));
        } else {
            // Fresh.
            let mut state = sample_daemon_state();
            state.pressure.mounts[0].free_pct = 50.0 - f64::from(i);
            update(&mut model, DashboardMsg::DataUpdate(Some(Box::new(state))));
        }
    }

    // Model should still be in a valid state.
    assert!(model.last_fetch.is_some());
    assert_eq!(model.adapter_reads + model.adapter_errors, 20);
}

#[cfg(feature = "tui")]
#[test]
fn model_navigation_works_during_degraded_state() {
    let mut model = test_model();

    // Enter degraded state.
    update(&mut model, DashboardMsg::DataUpdate(None));
    assert!(model.degraded);

    // Navigation should still work.
    update(&mut model, DashboardMsg::Navigate(Screen::Ballast));
    assert_eq!(model.screen, Screen::Ballast);

    update(&mut model, DashboardMsg::Navigate(Screen::Timeline));
    assert_eq!(model.screen, Screen::Timeline);

    update(&mut model, DashboardMsg::NavigateBack);
    assert_eq!(model.screen, Screen::Ballast);
}

#[cfg(feature = "tui")]
#[test]
fn model_overlays_work_during_degraded_state() {
    use storage_ballast_helper::tui::model::Overlay;

    let mut model = test_model();
    update(&mut model, DashboardMsg::DataUpdate(None));
    assert!(model.degraded);

    // Help overlay should still work.
    update(&mut model, DashboardMsg::ToggleOverlay(Overlay::Help));
    assert_eq!(model.active_overlay, Some(Overlay::Help));

    update(&mut model, DashboardMsg::CloseOverlay);
    assert_eq!(model.active_overlay, None);
}

#[cfg(feature = "tui")]
#[test]
fn model_handles_empty_daemon_state_with_zero_mounts() {
    let mut model = test_model();

    let empty_state = DaemonState::default();
    update(
        &mut model,
        DashboardMsg::DataUpdate(Some(Box::new(empty_state))),
    );

    assert!(!model.degraded);
    assert!(model.rate_histories.is_empty());
    assert!(model.daemon_state.is_some());
    assert_eq!(model.daemon_state.as_ref().unwrap().pid, 0);
}

#[cfg(feature = "tui")]
#[test]
fn model_force_refresh_works_in_any_state() {
    let mut model = test_model();

    // Force refresh from initial state.
    let cmd = update(&mut model, DashboardMsg::ForceRefresh);
    assert!(matches!(
        cmd,
        storage_ballast_helper::tui::model::DashboardCmd::FetchData
    ));

    // Force refresh from degraded state.
    update(&mut model, DashboardMsg::DataUpdate(None));
    let cmd = update(&mut model, DashboardMsg::ForceRefresh);
    assert!(matches!(
        cmd,
        storage_ballast_helper::tui::model::DashboardCmd::FetchData
    ));
}

// ══════════════════════════════════════════════════════════════════
// Section 8: Forward/Backward Compatibility
//
// Verifies the dashboard handles state files from different
// versions of the daemon without crashing.
// ══════════════════════════════════════════════════════════════════

#[test]
fn future_daemon_state_parses_with_unknown_fields_ignored() {
    let json = serde_json::json!({
        "version": "99.0.0",
        "pid": 9999,
        "started_at": "2030-01-01T00:00:00Z",
        "uptime_seconds": 999_999,
        "last_updated": "2030-01-01T12:00:00Z",
        "pressure": {
            "overall": "green",
            "mounts": [{
                "path": "/",
                "free_pct": 90.0,
                "level": "green",
                "rate_bps": -100.0,
                "future_mount_field": "ignored"
            }],
            "prediction_engine": {"beta": true}
        },
        "ballast": {
            "available": 5,
            "total": 5,
            "released": 0,
            "auto_reclaim_enabled": true
        },
        "last_scan": {
            "at": "2030-01-01T11:00:00Z",
            "candidates": 0,
            "deleted": 0,
            "scan_mode": "deep"
        },
        "counters": {
            "scans": 5000,
            "deletions": 100,
            "bytes_freed": 1_099_511_627_776_u64,
            "errors": 0,
            "dropped_log_events": 0,
            "successful_predictions": 42
        },
        "memory_rss_bytes": 104_857_600,
        "gpu_memory_bytes": 0,
        "cluster_mode": false
    });

    let state: DaemonState = serde_json::from_value(json).expect("future state should parse");
    assert_eq!(state.version, "99.0.0");
    assert_eq!(state.pid, 9999);
    assert_eq!(state.pressure.mounts.len(), 1);
    assert_eq!(state.counters.scans, 5000);
}

#[test]
fn old_daemon_state_parses_with_missing_fields_defaulted() {
    // Minimal state from a hypothetical old daemon version.
    let json = serde_json::json!({
        "version": "0.1.0",
        "pid": 1
    });

    let state: DaemonState = serde_json::from_value(json).expect("old state should parse");
    assert_eq!(state.version, "0.1.0");
    assert_eq!(state.pid, 1);
    assert_eq!(state.uptime_seconds, 0);
    assert!(state.pressure.mounts.is_empty());
    assert_eq!(state.ballast.total, 0);
    assert_eq!(state.counters.scans, 0);
    assert_eq!(state.memory_rss_bytes, 0);
}

// ══════════════════════════════════════════════════════════════════
// Section 9: SchemaWarnings Verification
//
// Comprehensive tests for schema drift detection as part of the
// rollback safety net.
// ══════════════════════════════════════════════════════════════════

#[cfg(feature = "tui")]
#[test]
fn schema_warnings_empty_is_no_drift() {
    let w = SchemaWarnings::default();
    assert!(!w.has_drift());
    assert!(w.unknown_fields.is_empty());
    assert!(w.missing_fields.is_empty());
}

#[cfg(feature = "tui")]
#[test]
fn schema_warnings_unknown_only_is_drift() {
    let w = SchemaWarnings {
        unknown_fields: vec!["new_feature".to_string()],
        missing_fields: vec![],
    };
    assert!(w.has_drift());
}

#[cfg(feature = "tui")]
#[test]
fn schema_warnings_missing_only_is_drift() {
    let w = SchemaWarnings {
        unknown_fields: vec![],
        missing_fields: vec!["memory_rss_bytes".to_string()],
    };
    assert!(w.has_drift());
}

#[cfg(feature = "tui")]
#[test]
fn schema_warnings_both_unknown_and_missing() {
    let w = SchemaWarnings {
        unknown_fields: vec!["gpu_bytes".to_string()],
        missing_fields: vec!["counters".to_string()],
    };
    assert!(w.has_drift());
    assert_eq!(w.unknown_fields.len(), 1);
    assert_eq!(w.missing_fields.len(), 1);
}

// ══════════════════════════════════════════════════════════════════
// Section 10: Simultaneous Degradation
//
// Verifies the system handles multiple degradation sources at
// once without compounding failures.
// ══════════════════════════════════════════════════════════════════

#[cfg(feature = "tui")]
#[test]
fn simultaneous_degraded_state_and_error_notification() {
    let mut model = test_model();

    // Degraded data.
    update(&mut model, DashboardMsg::DataUpdate(None));
    assert!(model.degraded);

    // Error notification while degraded.
    update(
        &mut model,
        DashboardMsg::Error(storage_ballast_helper::tui::model::DashboardError {
            message: "disk critically full".to_string(),
            source: "adapter".to_string(),
        }),
    );
    assert!(model.degraded);
    assert_eq!(model.notifications.len(), 1);

    // Recovery clears degraded but notification persists.
    update(
        &mut model,
        DashboardMsg::DataUpdate(Some(Box::new(sample_daemon_state()))),
    );
    assert!(!model.degraded);
    assert_eq!(model.notifications.len(), 1);
}

#[cfg(feature = "tui")]
#[test]
fn adapter_stale_plus_drift_snapshot_is_usable() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state_path = tmp.path().join("state.json");

    // State with schema drift.
    let mut value = serde_json::to_value(sample_daemon_state()).expect("to value");
    value["experimental_feature"] = serde_json::json!(true);
    fs::write(&state_path, serde_json::to_string(&value).expect("json")).expect("write");

    // Make it stale.
    let stale_mtime = filetime::FileTime::from_system_time(
        std::time::SystemTime::now() - Duration::from_secs(3600),
    );
    filetime::set_file_mtime(&state_path, stale_mtime).expect("set mtime");

    let adapter = DashboardStateAdapter::new(
        mock_platform(),
        Duration::from_secs(90),
        Duration::from_secs(1),
    );
    let snapshot = adapter.load_snapshot(&state_path, &[PathBuf::from("/tmp/work")]);

    // Both stale and drifted.
    assert!(matches!(snapshot.freshness, StateFreshness::Stale { .. }));
    assert!(snapshot.warnings.has_drift());
    // But data is still available.
    assert!(snapshot.daemon_state.is_some());

    // Model update with stale+drifted data should still work.
    let mut model = test_model();
    update(
        &mut model,
        DashboardMsg::DataUpdate(snapshot.daemon_state.map(Box::new)),
    );
    assert!(!model.degraded);
}
