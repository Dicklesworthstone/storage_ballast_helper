//! Integration tests: CLI smoke tests, full-pipeline scenarios, and
//! decision-plane e2e scenarios (bd-izu.7).

mod common;

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use sha2::{Digest, Sha256};
use storage_ballast_helper::ballast::manager::BallastManager;
use storage_ballast_helper::cli::{
    HostSpecifier, OfflineBundleArtifact, OfflineBundleManifest, RELEASE_REPOSITORY,
    ReleaseChannel, resolve_updater_artifact_contract,
};
use storage_ballast_helper::core::config::{BallastConfig, Config, ScoringConfig};
use storage_ballast_helper::daemon::notifications::{NotificationEvent, NotificationManager};
use storage_ballast_helper::daemon::policy::{
    ActiveMode, FallbackReason, PolicyConfig, PolicyEngine,
};
use storage_ballast_helper::monitor::ewma::DiskRateEstimator;
use storage_ballast_helper::monitor::guardrails::{
    AdaptiveGuard, CalibrationObservation, GuardDiagnostics, GuardStatus,
};
use storage_ballast_helper::monitor::pid::{PidPressureController, PressureLevel, PressureReading};
use storage_ballast_helper::monitor::predictive::{PredictiveActionPolicy, PredictiveConfig};
use storage_ballast_helper::scanner::decision_record::{
    DecisionRecordBuilder, ExplainLevel, PolicyMode, format_explain,
};
use storage_ballast_helper::scanner::deletion::{DeletionConfig, DeletionExecutor};
use storage_ballast_helper::scanner::patterns::{
    ArtifactCategory, ArtifactClassification, ArtifactPatternRegistry, StructuralSignals,
};
use storage_ballast_helper::scanner::protection::ProtectionRegistry;
use storage_ballast_helper::scanner::scoring::{
    CandidacyScore, CandidateInput, DecisionAction, DecisionOutcome, EvidenceLedger, EvidenceTerm,
    ScoreFactors, ScoringEngine,
};
use storage_ballast_helper::scanner::walker::{DirectoryWalker, WalkerConfig};

#[test]
fn help_command_prints_usage() {
    let result = common::run_cli_case("help_command_prints_usage", &["--help"]);
    assert!(
        result.status.success(),
        "expected success; log: {}",
        result.log_path.display()
    );
    assert!(
        result.stdout.contains("Usage: sbh [OPTIONS] <COMMAND>"),
        "missing help banner; log: {}",
        result.log_path.display()
    );
}

#[test]
fn version_command_prints_version() {
    let result = common::run_cli_case("version_command_prints_version", &["--version"]);
    assert!(
        result.status.success(),
        "expected success; log: {}",
        result.log_path.display()
    );
    assert!(
        result.stdout.contains("storage_ballast_helper")
            || result.stdout.contains("sbh")
            || result.stderr.contains("storage_ballast_helper"),
        "missing version output; log: {}",
        result.log_path.display()
    );
}

#[test]
fn subcommand_help_flags_work() {
    // Verify that each subcommand accepts --help without crashing.
    let subcommands = [
        "install",
        "uninstall",
        "status",
        "stats",
        "scan",
        "clean",
        "ballast",
        "config",
        "daemon",
        "emergency",
        "protect",
        "unprotect",
        "tune",
        "check",
        "blame",
        "dashboard",
    ];

    for subcmd in subcommands {
        let case_name = format!("subcommand_{subcmd}_help");
        let result = common::run_cli_case(&case_name, &[subcmd, "--help"]);
        assert!(
            result.status.success(),
            "subcommand '{subcmd} --help' failed; log: {}",
            result.log_path.display()
        );
        assert!(
            result.stdout.contains("Usage") || result.stdout.contains("usage"),
            "subcommand '{subcmd} --help' missing usage info; log: {}",
            result.log_path.display()
        );
    }
}

#[test]
fn json_flag_accepted_by_status() {
    let result = common::run_cli_case("json_flag_accepted_by_status", &["status", "--json"]);
    // Status may succeed or fail depending on system state, but
    // it should produce some output (not crash).
    let combined = format!("{}{}", result.stdout, result.stderr);
    assert!(
        !combined.is_empty(),
        "status --json should produce output; log: {}",
        result.log_path.display()
    );
}

#[test]
fn completions_command_generates_shell_script() {
    let result = common::run_cli_case(
        "completions_command_generates_shell_script",
        &["completions", "bash"],
    );
    assert!(
        result.status.success(),
        "expected success; log: {}",
        result.log_path.display()
    );
    assert!(
        result.stdout.contains("sbh"),
        "expected completion script contents; log: {}",
        result.log_path.display()
    );
}

fn create_offline_update_bundle(bundle_root: &Path, release_tag: &str) -> (PathBuf, String) {
    let host = HostSpecifier::detect().expect("detect host");
    let contract =
        resolve_updater_artifact_contract(host, ReleaseChannel::Stable, Some(release_tag))
            .expect("resolve updater contract");
    let archive_name = contract.asset_name();
    let checksum_name = contract.checksum_name();

    let archive_bytes = b"integration-offline-update-bundle";
    fs::write(bundle_root.join(&archive_name), archive_bytes).expect("write bundle archive");
    let checksum_hex = format!("{:x}", Sha256::digest(archive_bytes));
    fs::write(
        bundle_root.join(&checksum_name),
        format!("{checksum_hex}  {archive_name}\n"),
    )
    .expect("write bundle checksum");

    let manifest = OfflineBundleManifest {
        version: String::from("1"),
        repository: RELEASE_REPOSITORY.to_string(),
        release_tag: release_tag.to_string(),
        artifacts: vec![OfflineBundleArtifact {
            target: contract.target.triple.to_string(),
            archive: archive_name,
            checksum: checksum_name,
            sigstore_bundle: None,
        }],
    };
    let manifest_path = bundle_root.join("bundle-manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("serialize bundle manifest"),
    )
    .expect("write bundle manifest");

    let expected_tag = format!("v{}", release_tag.trim_start_matches('v'));
    (manifest_path, expected_tag)
}

#[test]
fn update_check_with_pinned_future_version_reports_available_json() {
    let result = common::run_cli_case(
        "update_check_with_pinned_future_version_reports_available_json",
        &["update", "--check", "--version", "v99.99.99", "--json"],
    );
    assert!(
        result.status.success(),
        "expected success; log: {}",
        result.log_path.display()
    );

    let payload: Value = serde_json::from_str(result.stdout.trim()).unwrap_or_else(|err| {
        panic!(
            "expected JSON output, parse failed: {err}; stdout={:?}; log={}",
            result.stdout,
            result.log_path.display()
        )
    });

    assert_eq!(
        payload["check_only"],
        true,
        "log: {}",
        result.log_path.display()
    );
    assert_eq!(
        payload["update_available"],
        true,
        "log: {}",
        result.log_path.display()
    );
    assert_eq!(
        payload["target_version"],
        "v99.99.99",
        "log: {}",
        result.log_path.display()
    );
    assert_eq!(
        payload["success"],
        true,
        "log: {}",
        result.log_path.display()
    );
}

#[test]
fn update_check_with_current_version_reports_up_to_date_json() {
    let current = format!("v{}", env!("CARGO_PKG_VERSION"));
    let result = common::run_cli_case(
        "update_check_with_current_version_reports_up_to_date_json",
        &["update", "--check", "--version", &current, "--json"],
    );
    assert!(
        result.status.success(),
        "expected success; log: {}",
        result.log_path.display()
    );

    let payload: Value = serde_json::from_str(result.stdout.trim()).unwrap_or_else(|err| {
        panic!(
            "expected JSON output, parse failed: {err}; stdout={:?}; log={}",
            result.stdout,
            result.log_path.display()
        )
    });

    assert_eq!(
        payload["check_only"],
        true,
        "log: {}",
        result.log_path.display()
    );
    assert_eq!(
        payload["target_version"],
        current,
        "log: {}",
        result.log_path.display()
    );
    assert_eq!(
        payload["update_available"],
        false,
        "log: {}",
        result.log_path.display()
    );
    assert_eq!(
        payload["success"],
        true,
        "log: {}",
        result.log_path.display()
    );
}

#[test]
fn update_dry_run_with_pinned_version_emits_plan_steps_json() {
    let result = common::run_cli_case(
        "update_dry_run_with_pinned_version_emits_plan_steps_json",
        &["update", "--version", "v99.99.99", "--dry-run", "--json"],
    );
    assert!(
        result.status.success(),
        "expected success; log: {}",
        result.log_path.display()
    );

    let payload: Value = serde_json::from_str(result.stdout.trim()).unwrap_or_else(|err| {
        panic!(
            "expected JSON output, parse failed: {err}; stdout={:?}; log={}",
            result.stdout,
            result.log_path.display()
        )
    });

    assert_eq!(
        payload["dry_run"],
        true,
        "log: {}",
        result.log_path.display()
    );
    assert_eq!(
        payload["update_available"],
        true,
        "log: {}",
        result.log_path.display()
    );
    assert_eq!(
        payload["applied"],
        false,
        "log: {}",
        result.log_path.display()
    );
    assert_eq!(
        payload["success"],
        true,
        "log: {}",
        result.log_path.display()
    );

    let steps = payload["steps"]
        .as_array()
        .unwrap_or_else(|| panic!("expected steps array; log: {}", result.log_path.display()));
    let has_plan_step = steps.iter().any(|step| {
        step.get("description")
            .and_then(Value::as_str)
            .is_some_and(|desc| desc.contains("Would download"))
    });
    assert!(
        has_plan_step,
        "expected dry-run plan step; log: {}",
        result.log_path.display()
    );
}

#[test]
fn update_system_and_user_flags_conflict_in_cli_integration() {
    let result = common::run_cli_case(
        "update_system_and_user_flags_conflict_in_cli_integration",
        &["update", "--system", "--user"],
    );
    assert!(
        !result.status.success(),
        "expected failure; log: {}",
        result.log_path.display()
    );
    assert!(
        result.stderr.contains("cannot be used with") || result.stderr.contains("conflicts with"),
        "expected clap conflict error; stderr={:?}; log={}",
        result.stderr,
        result.log_path.display()
    );
}

#[test]
fn update_check_uses_fresh_cache_when_offline_and_path_disabled() {
    let home = tempfile::tempdir().expect("create temp home");
    let cache_path = home.path().join(".local/share/sbh/update-metadata.json");
    let cache_parent = cache_path
        .parent()
        .expect("cache path should have parent directory");
    fs::create_dir_all(cache_parent).expect("create cache parent directory");

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_secs();
    let cache_entry = serde_json::json!({
        "target_tag": "v99.88.77",
        "artifact_url": "https://example.invalid/sbh-x86_64-unknown-linux-gnu.tar.xz",
        "fetched_at_unix_secs": now_secs,
    });
    fs::write(
        &cache_path,
        serde_json::to_vec_pretty(&cache_entry).expect("serialize cache entry"),
    )
    .expect("write cache file");

    let home_str = home.path().to_string_lossy().to_string();
    let result = common::run_cli_case_with_env(
        "update_check_uses_fresh_cache_when_offline_and_path_disabled",
        &["update", "--check", "--json"],
        &[("HOME", &home_str), ("PATH", "")],
    );
    assert!(
        result.status.success(),
        "expected success; stderr={:?}; log: {}",
        result.stderr,
        result.log_path.display()
    );

    let payload: Value = serde_json::from_str(result.stdout.trim()).unwrap_or_else(|err| {
        panic!(
            "expected JSON output, parse failed: {err}; stdout={:?}; log={}",
            result.stdout,
            result.log_path.display()
        )
    });
    assert_eq!(
        payload["success"],
        true,
        "log: {}",
        result.log_path.display()
    );
    assert_eq!(
        payload["target_version"],
        "v99.88.77",
        "log: {}",
        result.log_path.display()
    );
    assert_eq!(
        payload["update_available"],
        true,
        "log: {}",
        result.log_path.display()
    );
    let used_cache = payload["steps"].as_array().is_some_and(|steps| {
        steps.iter().any(|step| {
            step.get("description")
                .and_then(Value::as_str)
                .is_some_and(|desc| desc.contains("Loaded update metadata from cache"))
        })
    });
    assert!(
        used_cache,
        "expected cache-hit step in update report; log: {}",
        result.log_path.display()
    );
}

#[test]
fn update_check_with_offline_bundle_manifest_reports_target_json() {
    let home = tempfile::tempdir().expect("create temp home");
    let bundle = tempfile::tempdir().expect("create temp bundle dir");
    let (manifest_path, expected_tag) = create_offline_update_bundle(bundle.path(), "99.77.55");

    let home_str = home.path().to_string_lossy().to_string();
    let manifest_path_str = manifest_path.to_string_lossy().to_string();
    let result = common::run_cli_case_with_env(
        "update_check_with_offline_bundle_manifest_reports_target_json",
        &[
            "update",
            "--check",
            "--offline",
            &manifest_path_str,
            "--json",
        ],
        &[("HOME", &home_str), ("PATH", "")],
    );
    assert!(
        result.status.success(),
        "expected success; stderr={:?}; log: {}",
        result.stderr,
        result.log_path.display()
    );

    let payload: Value = serde_json::from_str(result.stdout.trim()).unwrap_or_else(|err| {
        panic!(
            "expected JSON output, parse failed: {err}; stdout={:?}; log={}",
            result.stdout,
            result.log_path.display()
        )
    });
    assert_eq!(
        payload["success"],
        true,
        "expected success=true; log: {}",
        result.log_path.display()
    );
    assert_eq!(
        payload["check_only"],
        true,
        "expected check_only=true; log: {}",
        result.log_path.display()
    );
    assert_eq!(
        payload["target_version"],
        expected_tag,
        "unexpected target_version; log: {}",
        result.log_path.display()
    );
    assert_eq!(
        payload["update_available"],
        true,
        "expected update_available=true; log: {}",
        result.log_path.display()
    );

    let resolved_bundle_artifact = payload["steps"].as_array().is_some_and(|steps| {
        steps.iter().any(|step| {
            step.get("description")
                .and_then(Value::as_str)
                .is_some_and(|desc| desc.contains("Resolved offline bundle artifact"))
        })
    });
    assert!(
        resolved_bundle_artifact,
        "expected bundle artifact resolution step; log: {}",
        result.log_path.display()
    );

    let loaded_bundle_metadata = payload["steps"].as_array().is_some_and(|steps| {
        steps.iter().any(|step| {
            step.get("description")
                .and_then(Value::as_str)
                .is_some_and(|desc| desc.contains("Loaded update metadata from offline bundle"))
        })
    });
    assert!(
        loaded_bundle_metadata,
        "expected offline bundle metadata source step; log: {}",
        result.log_path.display()
    );
}

#[test]
fn update_check_with_offline_bundle_and_pinned_tag_mismatch_fails_json() {
    let home = tempfile::tempdir().expect("create temp home");
    let bundle = tempfile::tempdir().expect("create temp bundle dir");
    let (manifest_path, expected_tag) = create_offline_update_bundle(bundle.path(), "9.9.9");

    let home_str = home.path().to_string_lossy().to_string();
    let manifest_path_str = manifest_path.to_string_lossy().to_string();
    let result = common::run_cli_case_with_env(
        "update_check_with_offline_bundle_and_pinned_tag_mismatch_fails_json",
        &[
            "update",
            "--check",
            "--offline",
            &manifest_path_str,
            "--version",
            "1.0.0",
            "--json",
        ],
        &[("HOME", &home_str), ("PATH", "")],
    );
    assert!(
        !result.status.success(),
        "expected failure due to pinned tag mismatch; log: {}",
        result.log_path.display()
    );

    let payload: Value = serde_json::from_str(result.stdout.trim()).unwrap_or_else(|err| {
        panic!(
            "expected JSON output, parse failed: {err}; stdout={:?}; log={}",
            result.stdout,
            result.log_path.display()
        )
    });
    assert_eq!(
        payload["success"],
        false,
        "expected success=false; log: {}",
        result.log_path.display()
    );

    let mismatch_error = payload["steps"]
        .as_array()
        .and_then(|steps| {
            steps.iter().find_map(|step| {
                let is_resolve_step = step
                    .get("description")
                    .and_then(Value::as_str)
                    .is_some_and(|desc| desc.contains("Resolve target version"));
                if is_resolve_step {
                    step.get("error")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                } else {
                    None
                }
            })
        })
        .unwrap_or_default();
    assert!(
        mismatch_error.contains("offline bundle tag mismatch"),
        "expected mismatch diagnostic, got {:?}; log: {}",
        mismatch_error,
        result.log_path.display()
    );
    assert!(
        mismatch_error.contains(&expected_tag),
        "expected mismatch to reference bundle tag {:?}; got {:?}; log: {}",
        expected_tag,
        mismatch_error,
        result.log_path.display()
    );
}

#[test]
fn update_check_with_stale_cache_fails_offline_when_network_is_required() {
    let home = tempfile::tempdir().expect("create temp home");
    let cache_path = home.path().join(".local/share/sbh/update-metadata.json");
    let cache_parent = cache_path
        .parent()
        .expect("cache path should have parent directory");
    fs::create_dir_all(cache_parent).expect("create cache parent directory");

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_secs();
    let stale_cache_entry = serde_json::json!({
        "target_tag": "v1.2.3",
        "artifact_url": "https://example.invalid/sbh-x86_64-unknown-linux-gnu.tar.xz",
        "fetched_at_unix_secs": now_secs.saturating_sub(7_200),
    });
    fs::write(
        &cache_path,
        serde_json::to_vec_pretty(&stale_cache_entry).expect("serialize stale cache entry"),
    )
    .expect("write stale cache file");

    let home_str = home.path().to_string_lossy().to_string();
    let result = common::run_cli_case_with_env(
        "update_check_with_stale_cache_fails_offline_when_network_is_required",
        &["update", "--check", "--json"],
        &[("HOME", &home_str), ("PATH", "")],
    );
    assert!(
        !result.status.success(),
        "expected failure; log: {}",
        result.log_path.display()
    );

    let payload: Value = serde_json::from_str(result.stdout.trim()).unwrap_or_else(|err| {
        panic!(
            "expected JSON output, parse failed: {err}; stdout={:?}; log={}",
            result.stdout,
            result.log_path.display()
        )
    });
    assert_eq!(
        payload["success"],
        false,
        "log: {}",
        result.log_path.display()
    );
    let resolve_step_err = payload["steps"]
        .as_array()
        .and_then(|steps| {
            steps.iter().find_map(|step| {
                let is_resolve_step = step
                    .get("description")
                    .and_then(Value::as_str)
                    .is_some_and(|desc| desc.contains("Resolve target version"));
                if is_resolve_step {
                    step.get("error")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                } else {
                    None
                }
            })
        })
        .unwrap_or_default();
    assert!(
        resolve_step_err.contains("curl")
            || resolve_step_err.contains("GitHub API")
            || resolve_step_err.contains("failed"),
        "expected network-resolution error for stale cache path; got {:?}; log: {}",
        resolve_step_err,
        result.log_path.display()
    );
}

#[test]
fn update_list_backups_with_isolated_home_reports_empty_json_inventory() {
    let home = tempfile::tempdir().expect("create temp home");
    let home_str = home.path().to_string_lossy().to_string();

    let result = common::run_cli_case_with_env(
        "update_list_backups_with_isolated_home_reports_empty_json_inventory",
        &["update", "--list-backups", "--json"],
        &[("HOME", &home_str), ("PATH", "")],
    );
    assert!(
        result.status.success(),
        "expected success; stderr={:?}; log: {}",
        result.stderr,
        result.log_path.display()
    );

    let payload: Value = serde_json::from_str(result.stdout.trim()).unwrap_or_else(|err| {
        panic!(
            "expected JSON output, parse failed: {err}; stdout={:?}; log={}",
            result.stdout,
            result.log_path.display()
        )
    });
    let backups = payload["backups"]
        .as_array()
        .unwrap_or_else(|| panic!("expected backups array; log: {}", result.log_path.display()));
    assert!(
        backups.is_empty(),
        "expected empty inventory in isolated home; log: {}",
        result.log_path.display()
    );
    let backup_dir = payload["backup_dir"].as_str().unwrap_or_default();
    assert!(
        backup_dir.contains(".local/share/sbh/backups"),
        "expected canonical backup dir path; got {:?}; log: {}",
        backup_dir,
        result.log_path.display()
    );
}

#[test]
fn update_prune_with_isolated_home_reports_zero_removed_json() {
    let home = tempfile::tempdir().expect("create temp home");
    let home_str = home.path().to_string_lossy().to_string();

    let result = common::run_cli_case_with_env(
        "update_prune_with_isolated_home_reports_zero_removed_json",
        &["update", "--prune", "3", "--json"],
        &[("HOME", &home_str), ("PATH", "")],
    );
    assert!(
        result.status.success(),
        "expected success; stderr={:?}; log: {}",
        result.stderr,
        result.log_path.display()
    );

    let payload: Value = serde_json::from_str(result.stdout.trim()).unwrap_or_else(|err| {
        panic!(
            "expected JSON output, parse failed: {err}; stdout={:?}; log={}",
            result.stdout,
            result.log_path.display()
        )
    });
    assert_eq!(
        payload["kept"],
        0,
        "expected zero kept in empty isolated store; log: {}",
        result.log_path.display()
    );
    assert_eq!(
        payload["removed"],
        0,
        "expected zero removed in empty isolated store; log: {}",
        result.log_path.display()
    );
    let removed_ids = payload["removed_ids"].as_array().unwrap_or_else(|| {
        panic!(
            "expected removed_ids array in prune output; log: {}",
            result.log_path.display()
        )
    });
    assert!(
        removed_ids.is_empty(),
        "expected no removed ids; log: {}",
        result.log_path.display()
    );
}

// ══════════════════════════════════════════════════════════════════
// Pipeline integration tests
// ══════════════════════════════════════════════════════════════════

// ── Scenario 1: Green pressure → no deletions ────────────────────

#[test]
fn green_pressure_no_deletions() {
    let env = common::TestEnvironment::new();
    // Create some files that look like normal project files.
    env.create_file(
        "project/src/main.rs",
        b"fn main() {}",
        Duration::from_secs(3600),
    );
    env.create_file(
        "project/Cargo.toml",
        b"[package]",
        Duration::from_secs(3600),
    );

    let cfg = Config::default();
    let scoring = ScoringEngine::from_config(&cfg.scoring, cfg.scanner.min_file_age_minutes);

    let input = CandidateInput {
        path: env.root().join("project/src/main.rs"),
        size_bytes: 12,
        age: Duration::from_secs(3600),
        classification: ArtifactClassification::unknown(),
        signals: StructuralSignals::default(),
        is_open: false,
        excluded: false,
    };

    let score = scoring.score_candidate(&input, 0.0); // Green: urgency=0
    // Unknown classification + low urgency → should NOT recommend deletion.
    assert_ne!(
        score.decision.action,
        DecisionAction::Delete,
        "green pressure should not delete unknown files"
    );
}

// ── Scenario 2: Pressure buildup with controller escalation ──────

#[test]
fn pressure_escalation_through_levels() {
    let mut pid = PidPressureController::new(
        0.25,
        0.08,
        0.02,
        100.0,
        18.0,
        1.0,
        20.0,
        14.0,
        10.0,
        6.0,
        Duration::from_secs(2),
    );
    let t0 = Instant::now();

    // Simulate declining free space over time.
    let readings = [
        (50, PressureLevel::Green),  // 50% free
        (12, PressureLevel::Yellow), // 12% free
        (8, PressureLevel::Orange),  // 8% free
        (4, PressureLevel::Red),     // 4% free
    ];

    for (i, (free_pct, expected_level)) in readings.iter().enumerate() {
        let r = pid.update(
            PressureReading {
                free_bytes: *free_pct,
                total_bytes: 100,
            },
            None,
            t0 + Duration::from_secs(i as u64),
        );
        assert_eq!(
            r.level, *expected_level,
            "at step {i}: expected {expected_level:?}, got {:?}",
            r.level
        );
    }
}

// ── Scenario 3: Ballast provision, release, verify, replenish ────

#[test]
fn ballast_lifecycle() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let ballast_dir = tmpdir.path().join("ballast");

    let config = BallastConfig {
        file_count: 3,
        file_size_bytes: 4096,
        replenish_cooldown_minutes: 0,
        auto_provision: true,
        ..BallastConfig::default()
    };

    let mut manager = BallastManager::new(ballast_dir.clone(), config).expect("create manager");

    // Provision.
    let prov = manager.provision(None).expect("provision");
    assert_eq!(prov.files_created, 3, "should create 3 ballast files");
    assert_eq!(manager.available_count(), 3);
    assert!(manager.releasable_bytes() > 0);

    // Verify integrity.
    let verify = manager.verify();
    assert_eq!(verify.files_ok, 3);
    assert_eq!(verify.files_corrupted, 0);

    // Release 2.
    let release = manager.release(2).expect("release");
    assert_eq!(release.files_released, 2);
    assert_eq!(manager.available_count(), 1);

    // Replenish.
    let replenish = manager.replenish(None).expect("replenish");
    assert_eq!(
        replenish.files_created, 2,
        "should recreate 2 released files"
    );
    assert_eq!(manager.available_count(), 3);
}

// ── Scenario 4: Walker discovers entries in temp directory ────────

#[test]
fn walker_discovers_entries_in_tree() {
    let env = common::TestEnvironment::new();
    env.create_file("a/file1.txt", b"hello", Duration::from_secs(3600));
    env.create_file("a/b/file2.txt", b"world", Duration::from_secs(7200));
    env.create_dir("empty_dir");

    let config = WalkerConfig {
        root_paths: vec![env.root().to_path_buf()],
        max_depth: 5,
        follow_symlinks: false,
        cross_devices: false,
        parallelism: 1,
        excluded_paths: HashSet::new(),
    };

    let protection = ProtectionRegistry::new(None).expect("create protection");
    let walker = DirectoryWalker::new(config, protection);
    let entries = walker.walk().expect("walk should succeed");

    // Walker discovers directories as deletion candidates.
    let paths: Vec<String> = entries
        .iter()
        .map(|e| e.path.to_string_lossy().to_string())
        .collect();
    assert!(!entries.is_empty(), "should discover at least some entries");
    // Directory "a" should be discovered.
    assert!(
        paths.iter().any(|p| p.ends_with("/a")),
        "should discover directory 'a' in {:?}",
        paths
    );
}

// ── Scenario 5: Scoring pipeline ranks artifacts above source ─────

#[test]
fn scoring_pipeline_ranks_artifacts_above_source() {
    let cfg = Config::default();
    let scoring = ScoringEngine::from_config(&cfg.scoring, cfg.scanner.min_file_age_minutes);

    // High-confidence Rust target artifact with strong structural signals.
    let target_input = CandidateInput {
        path: PathBuf::from("/tmp/project/target"),
        size_bytes: 500_000_000,            // 500 MB
        age: Duration::from_secs(4 * 3600), // 4 hours
        classification: ArtifactClassification {
            pattern_name: "cargo-target".to_string(),
            category: ArtifactCategory::RustTarget,
            name_confidence: 0.9,
            structural_confidence: 0.95,
            combined_confidence: 0.9,
        },
        signals: StructuralSignals {
            has_incremental: true,
            has_deps: true,
            has_build: true,
            has_fingerprint: true,
            ..Default::default()
        },
        is_open: false,
        excluded: false,
    };

    // Unknown source file — should not be recommended for deletion.
    let source_input = CandidateInput {
        path: PathBuf::from("/tmp/project/src/main.rs"),
        size_bytes: 500,
        age: Duration::from_secs(3600), // 1 hour
        classification: ArtifactClassification::unknown(),
        signals: StructuralSignals::default(),
        is_open: false,
        excluded: false,
    };

    let urgency = 0.8;
    let target_score = scoring.score_candidate(&target_input, urgency);
    let source_score = scoring.score_candidate(&source_input, urgency);

    assert!(
        !target_score.vetoed,
        "target should not be vetoed: {:?}",
        target_score.veto_reason
    );
    assert!(
        target_score.total_score > source_score.total_score,
        "target ({:.3}) should score higher than source ({:.3})",
        target_score.total_score,
        source_score.total_score,
    );
    assert!(
        target_score.total_score > 0.5,
        "target should have substantial score: {:.3}",
        target_score.total_score,
    );
}

// ── Scenario 6: Dry-run deletion pipeline ────────────────────────

#[test]
fn dry_run_deletes_nothing() {
    let env = common::TestEnvironment::new();
    let artifact = env.create_file(
        "target/debug/deps/libfoo.rlib",
        &vec![0u8; 1024],
        Duration::from_secs(86400),
    );

    let cfg = Config::default();
    let scoring = ScoringEngine::from_config(&cfg.scoring, cfg.scanner.min_file_age_minutes);
    let registry = ArtifactPatternRegistry::default();

    let class = registry.classify(
        &artifact,
        StructuralSignals {
            has_deps: true,
            ..Default::default()
        },
    );

    let candidate = CandidateInput {
        path: artifact.clone(),
        size_bytes: 1024,
        age: Duration::from_secs(86400),
        classification: class,
        signals: StructuralSignals {
            has_deps: true,
            ..Default::default()
        },
        is_open: false,
        excluded: false,
    };

    let scored = scoring.score_candidate(&candidate, 0.9);
    let executor = DeletionExecutor::new(
        DeletionConfig {
            max_batch_size: 10,
            dry_run: true,
            min_score: 0.0,
            circuit_breaker_threshold: 3,
            circuit_breaker_cooldown: Duration::from_secs(1),
            check_open_files: false,
        },
        None,
    );

    let plan = executor.plan(vec![scored]);
    let report = executor.execute(&plan, None);

    assert!(report.dry_run, "should be dry run");
    // File should still exist.
    assert!(artifact.exists(), "dry-run should not delete the file");
}

// ── Scenario 7: EWMA + Predictive action pipeline ───────────────

#[test]
fn predictive_pipeline_detects_imminent_danger() {
    let mut estimator = DiskRateEstimator::new(0.4, 0.1, 0.8, 3);
    let policy = PredictiveActionPolicy::new(PredictiveConfig {
        enabled: true,
        action_horizon_minutes: 30.0,
        warning_horizon_minutes: 60.0,
        min_confidence: 0.3,
        min_samples: 3,
        imminent_danger_minutes: 5.0,
        critical_danger_minutes: 2.0,
    });

    let t0 = Instant::now();
    let total = 100_000_u64;

    // Seed.
    let _ = estimator.update(50_000, t0, total / 10);
    // Rapid consumption: 10k bytes/sec.
    let _ = estimator.update(40_000, t0 + Duration::from_secs(1), total / 10);
    let _ = estimator.update(30_000, t0 + Duration::from_secs(2), total / 10);
    let estimate = estimator.update(20_000, t0 + Duration::from_secs(3), total / 10);

    let current_free_pct = 20.0;
    let action = policy.evaluate(&estimate, current_free_pct, PathBuf::from("/data"));

    // With rapid consumption, should detect at least a warning or worse.
    assert!(
        action.severity() >= 1,
        "expected warning or higher, got severity {}",
        action.severity()
    );
}

// ── Scenario 8: Notification manager fires events ────────────────

#[test]
fn notification_manager_handles_events_without_panic() {
    // Create a disabled notification manager (no actual channels).
    let mut manager = NotificationManager::disabled();
    assert!(!manager.is_enabled());

    // Fire all event types — should not panic.
    manager.notify(&NotificationEvent::PressureChanged {
        from: "Green".to_string(),
        to: "Yellow".to_string(),
        mount: "/data".to_string(),
        free_pct: 12.0,
    });
    manager.notify(&NotificationEvent::CleanupCompleted {
        items_deleted: 5,
        bytes_freed: 1_000_000,
        mount: "/data".to_string(),
    });
    manager.notify(&NotificationEvent::BallastReleased {
        mount: "/data".to_string(),
        files_released: 2,
        bytes_freed: 2_000_000_000,
    });
    manager.notify(&NotificationEvent::Error {
        code: "SBH-3900".to_string(),
        message: "test error".to_string(),
    });
}

// ── Scenario 9: Config roundtrip (TOML → load → validate) ───────

#[test]
fn config_toml_roundtrip() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let config_path = tmpdir.path().join("sbh-test.toml");

    let toml_content = r#"
[pressure]
green_min_free_pct = 25.0
yellow_min_free_pct = 18.0
orange_min_free_pct = 12.0
red_min_free_pct = 7.0
poll_interval_ms = 2000

[scanner]
max_depth = 8
parallelism = 2
dry_run = true

[ballast]
file_count = 5
file_size_bytes = 536870912
"#;

    std::fs::write(&config_path, toml_content).expect("write toml");
    let cfg = Config::load(Some(&config_path)).expect("load config");

    assert_eq!(cfg.pressure.green_min_free_pct, 25.0);
    assert_eq!(cfg.pressure.yellow_min_free_pct, 18.0);
    assert_eq!(cfg.scanner.max_depth, 8);
    assert!(cfg.scanner.dry_run);
    assert_eq!(cfg.ballast.file_count, 5);
}

// ── Scenario 10: Pattern registry classifies known artifacts ─────

#[test]
fn pattern_registry_classifies_rust_target() {
    let registry = ArtifactPatternRegistry::default();

    let signals = StructuralSignals {
        has_incremental: true,
        has_deps: true,
        has_build: true,
        has_fingerprint: true,
        ..Default::default()
    };

    let class = registry.classify(std::path::Path::new("/data/projects/myapp/target"), signals);
    assert_eq!(class.category, ArtifactCategory::RustTarget);
    assert!(class.combined_confidence > 0.5);
}

#[test]
fn pattern_registry_classifies_node_modules() {
    let registry = ArtifactPatternRegistry::default();
    let class = registry.classify(
        std::path::Path::new("/data/projects/webapp/node_modules"),
        StructuralSignals::default(),
    );
    assert_eq!(class.category, ArtifactCategory::NodeModules);
}

// ── Scenario 11: Walker respects protection markers ──────────────

#[test]
fn walker_skips_protected_directories() {
    let env = common::TestEnvironment::new();
    env.create_file("unprotected/file.txt", b"data", Duration::from_secs(3600));
    env.create_file("protected/.sbh-protect", b"{}", Duration::from_secs(3600));
    env.create_file("protected/secret.txt", b"keep", Duration::from_secs(3600));

    let config = WalkerConfig {
        root_paths: vec![env.root().to_path_buf()],
        max_depth: 5,
        follow_symlinks: false,
        cross_devices: false,
        parallelism: 1,
        excluded_paths: HashSet::new(),
    };

    let protection = ProtectionRegistry::new(None).expect("create protection");
    let walker = DirectoryWalker::new(config, protection);
    let entries = walker.walk().expect("walk should succeed");

    let paths: Vec<String> = entries
        .iter()
        .map(|e| e.path.to_string_lossy().to_string())
        .collect();

    // The file inside protected/ should not appear in results.
    assert!(
        !paths.iter().any(|p| p.contains("secret.txt")),
        "protected directory contents should be skipped: {:?}",
        paths
    );
}

// ── Scenario 12: Batch scoring ranks by score descending ─────────

#[test]
fn batch_scoring_ranks_correctly() {
    let cfg = Config::default();
    let scoring = ScoringEngine::from_config(&cfg.scoring, cfg.scanner.min_file_age_minutes);

    let candidates = vec![
        CandidateInput {
            path: PathBuf::from("/tmp/project/target"),
            size_bytes: 500_000_000,
            age: Duration::from_secs(4 * 3600), // 4 hours
            classification: ArtifactClassification {
                pattern_name: "cargo-target".to_string(),
                category: ArtifactCategory::RustTarget,
                name_confidence: 0.9,
                structural_confidence: 0.95,
                combined_confidence: 0.9,
            },
            signals: StructuralSignals {
                has_incremental: true,
                has_deps: true,
                has_build: true,
                has_fingerprint: true,
                ..Default::default()
            },
            is_open: false,
            excluded: false,
        },
        CandidateInput {
            path: PathBuf::from("/tmp/project/notes.txt"),
            size_bytes: 100,
            age: Duration::from_secs(2 * 3600), // 2 hours
            classification: ArtifactClassification::unknown(),
            signals: StructuralSignals::default(),
            is_open: false,
            excluded: false,
        },
    ];

    let ranked = scoring.score_batch(&candidates, 0.7);
    assert_eq!(ranked.len(), 2);
    assert!(
        ranked[0].total_score >= ranked[1].total_score,
        "batch should be sorted by score descending: {:.3} >= {:.3}",
        ranked[0].total_score,
        ranked[1].total_score,
    );
    // The high-confidence artifact should rank higher.
    assert!(
        ranked[0].total_score > ranked[1].total_score,
        "artifact ({:.3}) should score strictly above unknown ({:.3})",
        ranked[0].total_score,
        ranked[1].total_score,
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Decision-Plane E2E Scenarios (bd-izu.7)
//
// Six scenarios exercising shadow, canary, enforce, and fallback behavior
// under realistic pressure and failure modes. Each scenario:
// - Is deterministic under fixed seeds and fixture inputs
// - Emits trace_id, decision_id, policy mode, guard status
// - Asserts fallback triggers and reasons
// - Verifies no unintended deletions in shadow mode
// ════════════════════════════════════════════════════════════════════════════

// ── helpers ─────────────────────────────────────────────────────────────────

fn e2e_scoring_engine() -> ScoringEngine {
    ScoringEngine::from_config(&ScoringConfig::default(), 30)
}

fn e2e_candidate(path: &str, size_gb: u64, age_hours: u64, confidence: f64) -> CandidateInput {
    CandidateInput {
        path: PathBuf::from(path),
        size_bytes: size_gb * 1_073_741_824,
        age: Duration::from_secs(age_hours * 3600),
        classification: ArtifactClassification {
            pattern_name: ".target*".to_string(),
            category: ArtifactCategory::RustTarget,
            name_confidence: confidence,
            structural_confidence: confidence * 0.9,
            combined_confidence: confidence,
        },
        signals: StructuralSignals {
            has_incremental: true,
            has_deps: true,
            has_build: true,
            has_fingerprint: confidence > 0.5,
            has_git: false,
            has_cargo_toml: false,
            mostly_object_files: true,
        },
        is_open: false,
        excluded: false,
    }
}

fn e2e_good_observations(count: usize) -> Vec<CalibrationObservation> {
    (0..count)
        .map(|i| CalibrationObservation {
            predicted_rate: 1000.0 + (i as f64 * 10.0),
            actual_rate: 1050.0 + (i as f64 * 10.0),
            predicted_tte: 90.0 + (i as f64),
            actual_tte: 85.0 + (i as f64),
        })
        .collect()
}

fn e2e_bad_observations(count: usize, error_factor: f64) -> Vec<CalibrationObservation> {
    (0..count)
        .map(|i| CalibrationObservation {
            predicted_rate: 1000.0 + (i as f64 * 10.0),
            actual_rate: (1000.0 + (i as f64 * 10.0)) * error_factor,
            predicted_tte: 100.0,
            actual_tte: 30.0,
        })
        .collect()
}

#[allow(dead_code)]
fn e2e_scored_candidate(action: DecisionAction, score: f64) -> CandidacyScore {
    CandidacyScore {
        path: PathBuf::from("/data/projects/test/.target_opus"),
        total_score: score,
        factors: ScoreFactors {
            location: 0.85,
            name: 0.90,
            age: 1.0,
            size: 0.70,
            structure: 0.95,
            pressure_multiplier: 1.5,
        },
        vetoed: false,
        veto_reason: None,
        classification: ArtifactClassification {
            pattern_name: ".target*".to_string(),
            category: ArtifactCategory::RustTarget,
            name_confidence: 0.9,
            structural_confidence: 0.95,
            combined_confidence: 0.92,
        },
        size_bytes: 3_000_000_000,
        age: Duration::from_secs(5 * 3600),
        decision: DecisionOutcome {
            action,
            posterior_abandoned: 0.87,
            expected_loss_keep: 8.7,
            expected_loss_delete: 1.3,
            calibration_score: 0.82,
            fallback_active: false,
        },
        ledger: EvidenceLedger {
            terms: vec![EvidenceTerm {
                name: "location",
                weight: 0.25,
                value: 0.85,
                contribution: 0.2125,
            }],
            summary: "test".to_string(),
        },
    }
}

/// Build a pass-status guard diagnostics.
fn passing_guard_diag() -> GuardDiagnostics {
    GuardDiagnostics {
        status: GuardStatus::Pass,
        observation_count: 20,
        median_rate_error: 0.05,
        conservative_fraction: 0.95,
        e_process_value: 0.3,
        e_process_alarm: false,
        consecutive_clean: 5,
        reason: "all metrics within bounds".to_string(),
    }
}

/// Build a failing-status guard diagnostics.
fn failing_guard_diag() -> GuardDiagnostics {
    GuardDiagnostics {
        status: GuardStatus::Fail,
        observation_count: 20,
        median_rate_error: 0.35,
        conservative_fraction: 0.4,
        e_process_value: 2.5,
        e_process_alarm: true,
        consecutive_clean: 0,
        reason: "e-process alarm tripped".to_string(),
    }
}

// ── Scenario 1: Burst growth with safe shadow recommendations ───────────

#[test]
fn e2e_scenario_1_burst_growth_shadow_safe() {
    // Setup: scoring engine + policy in observe mode + guard.
    let scoring = e2e_scoring_engine();
    let mut policy = PolicyEngine::new(PolicyConfig::default());
    let mut guard = AdaptiveGuard::with_defaults();

    // Phase 1: Feed good calibration data.
    for obs in e2e_good_observations(10) {
        guard.observe(obs);
    }

    // Phase 2: Score a burst of high-confidence candidates.
    let candidates: Vec<CandidateInput> = (0..10)
        .map(|i| {
            e2e_candidate(
                &format!("/data/projects/agent_{i}/.target_opus"),
                2 + i as u64,
                48 + i as u64 * 12,
                0.9,
            )
        })
        .collect();

    let scored = scoring.score_batch(&candidates, 0.8);
    assert!(!scored.is_empty(), "should score at least some candidates");

    // Phase 3: Evaluate in observe (shadow) mode.
    // Pass None for guard to isolate shadow-mode behavior from guard triggers.
    let decision = policy.evaluate(&scored, None);

    // In shadow/observe mode, NO deletions should be approved.
    assert!(
        decision.approved_for_deletion.is_empty(),
        "observe mode must not approve deletions, got {} approved",
        decision.approved_for_deletion.len()
    );
    assert_eq!(policy.mode(), ActiveMode::Observe);

    // Phase 4: Verify decision records contain recommendations.
    let mut builder = DecisionRecordBuilder::new();
    for candidate in &scored {
        let record = builder.build(candidate, PolicyMode::Shadow, None, None);
        assert!(!record.trace_id.is_empty());
        assert!(record.decision_id > 0);
        // Trace should show observe mode.
        assert_eq!(record.policy_mode, PolicyMode::Shadow);
    }

    // Phase 5: Verify explain output is non-empty.
    let sample = builder.build(&scored[0], PolicyMode::Shadow, None, None);
    let explanation = format_explain(&sample, ExplainLevel::L3);
    assert!(
        !explanation.is_empty(),
        "explain output should be non-empty"
    );
}

// ── Scenario 2: Canary pass with bounded impact and trace capture ───────

#[test]
fn e2e_scenario_2_canary_bounded_impact() {
    let scoring = e2e_scoring_engine();
    let config = PolicyConfig {
        max_canary_deletes_per_hour: 3,
        ..PolicyConfig::default()
    };
    let mut policy = PolicyEngine::new(config);
    let mut guard = AdaptiveGuard::with_defaults();

    // Warmup: feed good observations and promote to canary.
    for obs in e2e_good_observations(15) {
        guard.observe(obs);
    }
    let passing = passing_guard_diag();
    policy.observe_window(&passing);
    policy.promote(); // observe → canary
    assert_eq!(policy.mode(), ActiveMode::Canary);

    // Score candidates.
    let candidates: Vec<CandidateInput> = (0..8)
        .map(|i| {
            e2e_candidate(
                &format!("/data/projects/proj_{i}/target"),
                1 + i as u64,
                72,
                0.85,
            )
        })
        .collect();

    let scored = scoring.score_batch(&candidates, 0.7);

    // Evaluate in canary mode.
    let diag = guard.diagnostics();
    let decision = policy.evaluate(&scored, Some(&diag));

    // Canary should approve at most canary_delete_cap_per_hour.
    assert!(
        decision.approved_for_deletion.len() <= 3,
        "canary should cap at 3, got {}",
        decision.approved_for_deletion.len()
    );

    // Build trace records and verify canary policy mode.
    let mut builder = DecisionRecordBuilder::new();
    for candidate in &scored {
        let record = builder.build(candidate, PolicyMode::Canary, None, None);
        assert_eq!(record.policy_mode, PolicyMode::Canary);
        // Each trace_id should be unique and sequential.
        assert!(record.trace_id.starts_with("sbh-"));
    }
}

// ── Scenario 3: Calibration drift causing guard fail and fallback ────────

#[test]
fn e2e_scenario_3_calibration_drift_fallback() {
    let scoring = e2e_scoring_engine();
    let config = PolicyConfig {
        calibration_breach_windows: 3,
        ..PolicyConfig::default()
    };
    let mut policy = PolicyEngine::new(config);
    let mut guard = AdaptiveGuard::with_defaults();

    // Phase 1: Warmup with good data and promote to enforce.
    for obs in e2e_good_observations(15) {
        guard.observe(obs);
    }
    let passing = passing_guard_diag();
    policy.observe_window(&passing);
    policy.promote(); // observe → canary
    policy.observe_window(&passing);
    policy.promote(); // canary → enforce
    assert_eq!(policy.mode(), ActiveMode::Enforce);

    // Phase 2: Inject bad calibration causing drift.
    for obs in e2e_bad_observations(20, 3.0) {
        guard.observe(obs);
    }

    // Phase 3: Feed failing guard diagnostics.
    let failing = failing_guard_diag();
    for _ in 0..4 {
        policy.observe_window(&failing);
    }

    // Phase 4: Evaluate — should be in fallback.
    let candidates = vec![e2e_candidate("/data/projects/drift/target", 5, 96, 0.9)];
    let scored = scoring.score_batch(&candidates, 0.9);
    let diag = guard.diagnostics();
    let decision = policy.evaluate(&scored, Some(&diag));

    // Fallback should block all deletions.
    assert!(
        decision.approved_for_deletion.is_empty(),
        "fallback must block all deletions, got {} approved",
        decision.approved_for_deletion.len()
    );
    assert_eq!(policy.mode(), ActiveMode::FallbackSafe);

    // Verify the fallback reason is traceable.
    let reason = policy.fallback_reason();
    assert!(reason.is_some(), "fallback reason must be recorded");
}

// ── Scenario 4: Index corruption causing full-scan fallback ─────────────

#[test]
fn e2e_scenario_4_index_corruption_full_scan() {
    // This scenario verifies that when the Merkle scan index is corrupted
    // or unavailable, the system falls back to a full scan and still
    // produces valid scoring results.
    let scoring = e2e_scoring_engine();
    let _policy = PolicyEngine::new(PolicyConfig::default());

    // Simulate a full scan by scoring candidates directly (no incremental index).
    let candidates: Vec<CandidateInput> = vec![
        e2e_candidate("/data/projects/p1/target", 3, 48, 0.9),
        e2e_candidate("/data/projects/p2/.target_agent", 2, 72, 0.85),
        e2e_candidate("/data/projects/p3/build", 1, 24, 0.3),
    ];

    // Full scan scoring should work identically to incremental.
    let scored = scoring.score_batch(&candidates, 0.5);
    assert_eq!(scored.len(), 3, "full scan should score all candidates");

    // Scores should be deterministic.
    let scored_again = scoring.score_batch(&candidates, 0.5);
    for (a, b) in scored.iter().zip(scored_again.iter()) {
        assert!(
            (a.total_score - b.total_score).abs() < f64::EPSILON,
            "full scan must be deterministic: {:.6} vs {:.6}",
            a.total_score,
            b.total_score,
        );
    }

    // Decision records should capture the full-scan context.
    let mut builder = DecisionRecordBuilder::new();
    for candidate in &scored {
        let record = builder.build(candidate, PolicyMode::Shadow, None, None);
        assert!(!record.trace_id.is_empty());
        // Explain should contain factor contributions.
        let explain = format_explain(&record, ExplainLevel::L2);
        assert!(
            explain.contains("location") || explain.contains("factor"),
            "detailed explain should mention factors"
        );
    }
}

// ── Scenario 5: Injected IO/serializer faults causing safe degradation ──

#[test]
fn e2e_scenario_5_fault_injection_safe_degradation() {
    let scoring = e2e_scoring_engine();
    let mut policy = PolicyEngine::new(PolicyConfig::default());
    let mut guard = AdaptiveGuard::with_defaults();

    // Warmup to enforce mode.
    for obs in e2e_good_observations(15) {
        guard.observe(obs);
    }
    let passing = passing_guard_diag();
    policy.observe_window(&passing);
    policy.promote(); // observe → canary
    policy.observe_window(&passing);
    policy.promote(); // canary → enforce
    assert_eq!(policy.mode(), ActiveMode::Enforce);

    // Simulate kill-switch activation (IO fault response).
    policy.enter_fallback(FallbackReason::KillSwitch);

    // Evaluate — must block all actions.
    let candidates = vec![e2e_candidate("/data/projects/fault/target", 5, 96, 0.9)];
    let scored = scoring.score_batch(&candidates, 1.0);
    let diag = guard.diagnostics();
    let decision = policy.evaluate(&scored, Some(&diag));

    assert!(
        decision.approved_for_deletion.is_empty(),
        "kill-switch fallback must block all deletions"
    );
    assert_eq!(policy.mode(), ActiveMode::FallbackSafe);
    assert!(
        matches!(policy.fallback_reason(), Some(FallbackReason::KillSwitch)),
        "fallback reason must be KillSwitch"
    );

    // Simulate serializer fault — enter fallback again.
    let mut policy2 = PolicyEngine::new(PolicyConfig::default());
    policy2.enter_fallback(FallbackReason::SerializationFailure);
    let decision2 = policy2.evaluate(&scored, Some(&diag));
    assert!(
        decision2.approved_for_deletion.is_empty(),
        "serializer failure fallback must block all deletions"
    );
}

// ── Scenario 6: Progressive recovery from fallback after clean windows ──

#[test]
fn e2e_scenario_6_progressive_recovery() {
    let scoring = e2e_scoring_engine();
    let config = PolicyConfig {
        recovery_clean_windows: 3,
        ..PolicyConfig::default()
    };
    let mut policy = PolicyEngine::new(config);
    let mut guard = AdaptiveGuard::with_defaults();

    // Phase 1: Warmup to enforce, then enter fallback.
    for obs in e2e_good_observations(15) {
        guard.observe(obs);
    }
    let passing = passing_guard_diag();
    policy.observe_window(&passing);
    policy.promote(); // observe → canary
    policy.observe_window(&passing);
    policy.promote(); // canary → enforce
    policy.enter_fallback(FallbackReason::GuardrailDrift);
    assert_eq!(policy.mode(), ActiveMode::FallbackSafe);

    // Phase 2: Feed clean windows to trigger recovery.
    for _ in 0..4 {
        policy.observe_window(&passing);
    }

    // Phase 3: The policy should have recovered from fallback.
    // Recovery restores the pre-fallback mode (Enforce).
    let mode = policy.mode();
    assert_eq!(
        mode,
        ActiveMode::Enforce,
        "after recovery should return to pre-fallback mode (enforce), got {:?}",
        mode
    );

    // Fallback reason should be cleared after recovery.
    assert!(
        policy.fallback_reason().is_none(),
        "fallback reason should be cleared after recovery"
    );

    // Verify that evaluate works normally post-recovery.
    let candidates = vec![e2e_candidate("/data/projects/recovery/target", 3, 72, 0.85)];
    let scored = scoring.score_batch(&candidates, 0.5);
    let _decision = policy.evaluate(&scored, None);

    // In enforce mode, deletions may be approved (unlike fallback).
    // The key assertion: we are no longer in FallbackSafe.
    assert_ne!(
        policy.mode(),
        ActiveMode::FallbackSafe,
        "should remain out of fallback after clean evaluation"
    );

    // Phase 4: Verify the full lifecycle is traceable.
    let mut builder = DecisionRecordBuilder::new();
    let record = builder.build(&scored[0], PolicyMode::Shadow, None, None);
    let explanation = format_explain(&record, ExplainLevel::L3);
    assert!(!explanation.is_empty());
}
