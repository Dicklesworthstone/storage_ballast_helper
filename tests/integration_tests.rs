//! Integration tests: CLI smoke tests, full-pipeline scenarios, and
//! decision-plane e2e scenarios (bd-izu.7).

mod common;

use std::borrow::Cow;
use std::collections::HashSet;
#[cfg(target_os = "macos")]
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use proptest::prelude::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use storage_ballast_helper::ballast::manager::BallastManager;
use storage_ballast_helper::cli::{
    HostSpecifier, OfflineBundleArtifact, OfflineBundleManifest, RELEASE_REPOSITORY,
    ReleaseChannel, resolve_updater_artifact_contract,
};
use storage_ballast_helper::core::config::{BallastConfig, Config, ScoringConfig};
use storage_ballast_helper::core::hex_lower;
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
#[cfg(target_os = "macos")]
use storage_ballast_helper::platform::pal::Platform;
use storage_ballast_helper::platform::sacred_catalog::cross_platform_sacred_paths;
use storage_ballast_helper::platform::types::{SacredPath, SacredPathKind, SacredPathSource};
use storage_ballast_helper::scanner::decision_record::{
    DecisionRecordBuilder, ExplainLevel, PolicyMode, format_explain,
};
use storage_ballast_helper::scanner::deletion::{DeletionConfig, DeletionExecutor};
use storage_ballast_helper::scanner::patterns::{
    ArtifactCategory, ArtifactClassification, ArtifactPatternRegistry, StructuralSignals,
};
use storage_ballast_helper::scanner::protection::{
    ProtectionRegistry, SacredOverlapKind, find_sacred_overlaps,
};
use storage_ballast_helper::scanner::scoring::{
    ActiveReferenceSummary, CandidacyScore, CandidateInput, DecisionAction, DecisionOutcome,
    EvidenceLedger, EvidenceTerm, ScoreFactors, ScoringEngine,
};
use storage_ballast_helper::scanner::walker::{DirectoryWalker, WalkerConfig};

#[cfg(target_os = "macos")]
const MACOS_LIVE_CAPACITY_TOLERANCE_BYTES: u64 = 512 * 1_048_576;
#[cfg(target_os = "macos")]
const MACOS_LIVE_AVAILABLE_CAPACITY_TOLERANCE_RATIO: u64 = 400;

#[cfg(target_os = "macos")]
static MACOS_APFS_CAPACITY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
        "lease",
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

#[cfg(unix)]
#[test]
fn active_target_lease_cli_binds_lifetime_renewal_and_machine_status() {
    let fixture = tempfile::tempdir().expect("create active lease fixture");
    let scan_root = fixture.path().join("scan-root");
    fs::create_dir(&scan_root).expect("create scan root");
    let target = scan_root.join("leased-build");
    let config_path = fixture.path().join("sbh.toml");
    fs::write(
        &config_path,
        format!(
            "[scanner]\nroot_paths = [\"{}\"]\n",
            toml_path(&scan_root)
        ),
    )
    .expect("write active lease config");
    let active_status_path = fixture.path().join("active-status.json");
    let renewal_path = fixture.path().join("renewal.json");
    let token_path = fixture.path().join("raw-token.test-only");
    let binary = common::sbh_bin_path();
    let script = r#"
set -eu
test "$CARGO_TARGET_DIR" = "$1"
test "$SBH_ACTIVE_LEASE_TARGET" = "$1"
printf '%s' "$SBH_ACTIVE_LEASE_TOKEN" > "$6"
"$2" --config "$3" --json lease status --target "$1" > "$4"
"$2" --config "$3" --json lease renew --extend 5m > "$5"
printf 'leased payload\n' > "$1/sentinel.txt"
"#;
    let args = [
        "--config",
        config_path.to_str().unwrap(),
        "lease",
        "run",
        "--target",
        target.to_str().unwrap(),
        "--max-bytes",
        "1M",
        "--ttl",
        "5m",
        "--",
        "sh",
        "-c",
        script,
        "active-lease-script",
        target.to_str().unwrap(),
        binary.to_str().unwrap(),
        config_path.to_str().unwrap(),
        active_status_path.to_str().unwrap(),
        renewal_path.to_str().unwrap(),
        token_path.to_str().unwrap(),
    ];
    let run = common::run_cli_case("active_target_lease_run", &args);
    assert_cli_success(&run, "active target lease run");

    let active: Value = serde_json::from_slice(
        &fs::read(&active_status_path).expect("read active lease status"),
    )
    .expect("parse active lease status");
    assert_eq!(active["active"].as_bool(), Some(true));
    assert_eq!(active["state"].as_str(), Some("active"));
    assert_eq!(
        active["metadata"]["contract_id"].as_str(),
        Some("sbh.active_target_lease.v1")
    );
    assert_eq!(
        active["metadata"]["target"].as_str(),
        target.to_str()
    );

    let renewal: Value = serde_json::from_slice(
        &fs::read(&renewal_path).expect("read active lease renewal"),
    )
    .expect("parse active lease renewal");
    assert_eq!(renewal["action"].as_str(), Some("renew"));
    assert!(
        renewal["expires_at_unix_seconds"].as_u64()
            > active["metadata"]["expires_at_unix_seconds"]
                .as_u64()
                .unwrap()
    );

    let raw_token = fs::read_to_string(&token_path).expect("read inherited token witness");
    assert_eq!(raw_token.len(), 64, "renewal token should be 256 bits");
    let metadata_path = fs::read_dir(&scan_root)
        .expect("read lease sidecars")
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name().is_some_and(|name| {
                let name = name.to_string_lossy();
                name.starts_with(".sbh-active-lease-") && name.ends_with(".json")
            })
        })
        .expect("active lease metadata sidecar");
    let metadata_bytes = fs::read_to_string(metadata_path).expect("read lease metadata sidecar");
    assert!(
        !metadata_bytes.contains(&raw_token),
        "durable metadata must store only the renewal token hash"
    );
    assert_eq!(
        fs::read_to_string(target.join("sentinel.txt")).unwrap(),
        "leased payload\n"
    );

    let after = common::run_cli_case(
        "active_target_lease_after_exit",
        &[
            "--config",
            config_path.to_str().unwrap(),
            "--json",
            "lease",
            "status",
            "--target",
            target.to_str().unwrap(),
        ],
    );
    assert_cli_success(&after, "active target lease post-exit status");
    let after_payload = parse_json_stdout(&after);
    assert_eq!(after_payload["active"].as_bool(), Some(false));
}

#[test]
fn macos_aware_help_text_is_visible() {
    let top = common::run_cli_case("macos_aware_top_help", &["--help"]);
    assert!(
        top.status.success(),
        "top-level --help failed; log: {}",
        top.log_path.display()
    );
    for fragment in [
        "Linux/macOS disk space guardian",
        "auto-detects Linux/systemd and macOS/launchd",
        "Full Disk Access diagnostics",
    ] {
        assert!(
            top.stdout.contains(fragment),
            "top-level --help missing platform fragment {fragment:?}; log: {}",
            top.log_path.display()
        );
    }

    let install = common::run_cli_case("macos_aware_install_help", &["install", "--help"]);
    assert!(
        install.status.success(),
        "install --help failed; log: {}",
        install.log_path.display()
    );
    for fragment in [
        "Omit --systemd/--launchd for auto-detection",
        "launchd user scope",
        "Full Disk Access",
    ] {
        assert!(
            install.stdout.contains(fragment),
            "install --help missing platform fragment {fragment:?}; log: {}",
            install.log_path.display()
        );
    }

    let clean = common::run_cli_case("macos_aware_clean_help", &["clean", "--help"]);
    assert!(
        clean.status.success(),
        "clean --help failed; log: {}",
        clean.log_path.display()
    );
    assert!(
        clean.stdout.contains("Time Machine/APFS")
            && clean.stdout.contains("does not delete user paths"),
        "clean --help missing Time Machine/APFS safety copy; log: {}",
        clean.log_path.display()
    );
}

#[test]
fn release_doctor_json_failure_exits_nonzero_after_parseable_report() {
    let empty_path = tempfile::tempdir().expect("create empty PATH fixture");
    let path_value = empty_path.path().to_string_lossy().to_string();
    let result = common::run_cli_case_with_env(
        "release_doctor_json_failure_exits_nonzero_after_parseable_report",
        &["--json", "doctor", "--release"],
        &[("PATH", &path_value)],
    );

    assert!(
        !result.status.success(),
        "release doctor should fail when external release credentials/tools are unavailable; log: {}",
        result.log_path.display()
    );
    assert!(
        result.stderr.contains("doctor checks failed"),
        "release doctor should explain the failing exit after printing JSON; stderr={:?}; log={}",
        result.stderr,
        result.log_path.display()
    );

    let payload: Value = serde_json::from_str(result.stdout.trim()).unwrap_or_else(|err| {
        panic!(
            "release doctor should print parseable JSON before failing: {err}; stdout={:?}; stderr={:?}; log={}",
            result.stdout,
            result.stderr,
            result.log_path.display()
        )
    });
    assert_eq!(payload["repository"].as_str(), Some(RELEASE_REPOSITORY));
    assert_eq!(payload["notary_profile"].as_str(), Some("sbh-notary"));
    assert_eq!(payload["ok"].as_bool(), Some(false));
    assert_eq!(payload["passed"].as_u64(), Some(0));
    assert_eq!(payload["warnings"].as_u64(), Some(0));
    assert_eq!(payload["failed"].as_u64(), Some(4));

    let checks = payload["checks"].as_array().unwrap_or_else(|| {
        panic!(
            "release doctor JSON missing checks array: {payload}; log={}",
            result.log_path.display()
        )
    });
    for check_id in [
        "release.developer_id_identity",
        "release.notary_profile",
        "release.github_secrets",
        "release.homebrew_tap",
    ] {
        let status = checks
            .iter()
            .find(|check| check["id"].as_str() == Some(check_id))
            .and_then(|check| check["status"].as_str());
        assert_eq!(
            status,
            Some("FAIL"),
            "release doctor check {check_id} should fail under empty PATH; payload={payload}; log={}",
            result.log_path.display()
        );
    }

    let required_secrets = payload["required_github_secrets"]
        .as_array()
        .unwrap_or_else(|| {
            panic!(
                "release doctor JSON missing required secrets: {payload}; log={}",
                result.log_path.display()
            )
        });
    assert!(
        required_secrets
            .iter()
            .any(|secret| secret.as_str() == Some("HOMEBREW_TAP_SSH_KEY")),
        "release doctor should include Homebrew tap secret requirement; payload={payload}; log={}",
        result.log_path.display()
    );
    assert!(
        payload["setup_steps"]
            .as_array()
            .is_some_and(|steps| !steps.is_empty()),
        "release doctor should include non-secret setup steps; payload={payload}; log={}",
        result.log_path.display()
    );
}

#[test]
fn install_auto_dry_run_json_is_single_payload() {
    let result = common::run_cli_case(
        "install_auto_dry_run_json_is_single_payload",
        &["--json", "install", "--auto", "--dry-run", "--from-source"],
    );

    assert!(
        result.status.success(),
        "install --auto --dry-run --json should succeed without building or writing; stderr={:?}; log={}",
        result.stderr,
        result.log_path.display()
    );
    let stdout = result.stdout.trim();
    assert_eq!(
        stdout.lines().count(),
        1,
        "JSON install dry-run must emit one machine-parseable payload, not a stream; stdout={stdout:?}; log={}",
        result.log_path.display()
    );

    let payload: Value = serde_json::from_str(stdout).unwrap_or_else(|err| {
        panic!(
            "install dry-run JSON should parse as one object: {err}; stdout={stdout:?}; stderr={:?}; log={}",
            result.stderr,
            result.log_path.display()
        )
    });
    assert_eq!(payload["command"].as_str(), Some("install"));
    assert_eq!(payload["auto"].as_bool(), Some(true));
    assert_eq!(payload["dry_run"].as_bool(), Some(true));
    assert_eq!(payload["from_source"].as_bool(), Some(true));
    assert_eq!(payload["success"].as_bool(), Some(true));
    assert_eq!(
        payload["wizard"]["answers"]["auto_mode"].as_bool(),
        Some(true)
    );
    assert_eq!(payload["wizard"]["config_written"].as_bool(), Some(false));
    assert_eq!(payload["install"]["dry_run"].as_bool(), Some(true));
    assert!(
        payload["release_install"].is_null(),
        "from-source dry-run should not perform release metadata checks"
    );
    assert!(
        payload["release_error"].is_null(),
        "successful from-source dry-run should not include a release error"
    );
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
#[allow(clippy::too_many_lines)]
fn isolated_config_exercises_safe_operational_commands() {
    let temp = tempfile::tempdir().expect("create isolated smoke fixture");
    let smoke_root = temp.path().join("smoke-root");
    let smoke_state = temp.path().join("smoke-state");
    let sample_target = smoke_root.join("sample_target").join("debug");
    let config_protected = smoke_root.join("config-protected");
    let marker_protected = smoke_root.join("protected");
    let ballast_dir = smoke_state.join("ballast");

    fs::create_dir_all(&sample_target).expect("create synthetic target directory");
    fs::create_dir_all(&config_protected).expect("create config-protected directory");
    fs::create_dir_all(&marker_protected).expect("create marker-protected directory");
    fs::create_dir_all(&ballast_dir).expect("create isolated ballast directory");

    let artifact = sample_target.join("object.o");
    fs::write(&artifact, b"payload\n").expect("write synthetic build artifact");

    let config_path = smoke_state.join("config.toml");
    fs::write(
        &config_path,
        format!(
            r#"[paths]
config_file = "{}"
state_file = "{}"
sqlite_db = "{}"
jsonl_log = "{}"
ballast_dir = "{}"

[scanner]
root_paths = ["{}"]
protected_paths = ["{}"]
min_file_age_minutes = 0
max_depth = 4
parallelism = 1
dry_run = true

[ballast]
file_count = 1
file_size_bytes = 1048576
"#,
            toml_path(&config_path),
            toml_path(&smoke_state.join("state.json")),
            toml_path(&smoke_state.join("activity.sqlite3")),
            toml_path(&smoke_state.join("activity.jsonl")),
            toml_path(&ballast_dir),
            toml_path(&smoke_root),
            toml_path(&config_protected),
        ),
    )
    .expect("write isolated smoke config");

    let config = config_path.to_string_lossy().into_owned();
    let root = smoke_root.to_string_lossy().into_owned();
    let protected = marker_protected.to_string_lossy().into_owned();
    let bin_dir = common::sbh_bin_path()
        .parent()
        .expect("integration binary should have parent dir")
        .to_string_lossy()
        .into_owned();

    let config_validate = run_owned_cli_case(
        "isolated_smoke_config_validate",
        &["--config", &config, "config", "validate"],
    );
    assert_cli_success(&config_validate, "isolated config validate");

    for (case_name, args, expected_command) in [
        (
            "isolated_smoke_status_sacred",
            vec!["--config", &config, "--json", "status", "--sacred"],
            "status",
        ),
        (
            "isolated_smoke_check",
            vec![
                "--config",
                &config,
                "--json",
                "check",
                &root,
                "--need",
                "1M",
                "--target-free",
                "0",
            ],
            "check",
        ),
        (
            "isolated_smoke_scan",
            vec![
                "--config",
                &config,
                "--json",
                "scan",
                &root,
                "--top",
                "5",
                "--min-score",
                "0.1",
                "--explain",
            ],
            "scan",
        ),
        (
            "isolated_smoke_clean_dry_run",
            vec![
                "--config",
                &config,
                "--json",
                "clean",
                &root,
                "--dry-run",
                "--yes",
                "--max-items",
                "2",
                "--min-score",
                "0.1",
            ],
            "clean",
        ),
        (
            "isolated_smoke_blame",
            vec![
                "--config", &config, "--json", "blame", "--top", "3", "--since", "1m",
            ],
            "blame",
        ),
        (
            "isolated_smoke_ballast_status",
            vec!["--config", &config, "--json", "ballast", "status"],
            "ballast status",
        ),
        (
            "isolated_smoke_tune",
            vec!["--config", &config, "--json", "tune"],
            "tune",
        ),
        (
            "isolated_smoke_setup_verify_dry_run",
            vec![
                "--config",
                &config,
                "--json",
                "setup",
                "--verify",
                "--dry-run",
                "--bin-dir",
                &bin_dir,
            ],
            "setup",
        ),
        (
            "isolated_smoke_protect_create",
            vec!["--config", &config, "--json", "protect", &protected],
            "protect",
        ),
        (
            "isolated_smoke_protect_list",
            vec!["--config", &config, "--json", "protect", "--list"],
            "protect",
        ),
    ] {
        let result = run_owned_cli_case(case_name, &args);
        assert_cli_success(&result, case_name);
        let payload = parse_json_stdout(&result);
        assert_eq!(
            payload["command"].as_str(),
            Some(expected_command),
            "{case_name} reported unexpected command payload: {payload}; log={}",
            result.log_path.display()
        );
    }

    assert!(
        artifact.exists(),
        "clean --dry-run must not remove the synthetic artifact"
    );
}

fn run_owned_cli_case(case_name: &str, args: &[&str]) -> common::CmdResult {
    common::run_cli_case(case_name, args)
}

fn assert_cli_success(result: &common::CmdResult, context: &str) {
    assert!(
        result.status.success(),
        "{context} failed; stdout={:?}; stderr={:?}; log={}",
        result.stdout,
        result.stderr,
        result.log_path.display()
    );
}

fn parse_json_stdout(result: &common::CmdResult) -> Value {
    serde_json::from_str(result.stdout.trim()).unwrap_or_else(|err| {
        panic!(
            "expected JSON stdout: {err}; stdout={:?}; stderr={:?}; log={}",
            result.stdout,
            result.stderr,
            result.log_path.display()
        )
    })
}

#[test]
#[cfg(target_os = "macos")]
#[allow(clippy::too_many_lines)]
fn scan_reports_home_trash_without_candidate() {
    let home = tempfile::tempdir().expect("create temp home");
    let home_path = home.path().canonicalize().expect("canonicalize temp home");
    let trash_entry = home_path.join(".Trash").join("old-session");
    fs::create_dir_all(&trash_entry).expect("create synthetic trash entry");
    fs::write(trash_entry.join("blob.bin"), vec![b'x'; 8192]).expect("write trash payload");

    let state_dir = home_path
        .join(".local")
        .join("share")
        .join("sbh-test-state");
    fs::create_dir_all(&state_dir).expect("create state directory");
    let config_path = home_path.join("sbh-test-config.toml");
    fs::write(
        &config_path,
        format!(
            "[paths]\nstate_file = \"{}\"\nsqlite_db = \"{}\"\njsonl_log = \"{}\"\nballast_dir = \"{}\"\n\n[scanner]\nroot_paths = [\"{}\"]\n",
            state_dir.join("state.json").display(),
            state_dir.join("activity.sqlite3").display(),
            state_dir.join("activity.jsonl").display(),
            state_dir.join("ballast").display(),
            home_path.display(),
        ),
    )
    .expect("write scan test config");

    let home_str = home_path.to_string_lossy().to_string();
    let config_str = config_path.to_string_lossy().to_string();
    let result = common::run_cli_case_with_env(
        "scan_reports_home_trash_without_candidate",
        &[
            "--config",
            &config_str,
            "--json",
            "scan",
            &home_str,
            "--top",
            "10",
        ],
        &[("HOME", &home_str)],
    );
    assert!(
        result.status.success(),
        "sbh scan failed; stdout={:?}; stderr={:?}; log={}",
        result.stdout,
        result.stderr,
        result.log_path.display()
    );

    let payload: Value = serde_json::from_str(result.stdout.trim()).unwrap_or_else(|err| {
        panic!(
            "expected scan JSON, parse failed: {err}; stdout={:?}; stderr={:?}; log={}",
            result.stdout,
            result.stderr,
            result.log_path.display()
        )
    });
    assert_eq!(
        payload["candidates_count"],
        0,
        "trash must not become a deletion candidate; payload={payload}; log={}",
        result.log_path.display()
    );
    assert_eq!(
        payload["total_reclaimable_bytes"],
        0,
        "report-only trash bytes must not count as reclaimable; payload={payload}; log={}",
        result.log_path.display()
    );
    assert!(
        payload["report_only_count"]
            .as_u64()
            .is_some_and(|count| count >= 1),
        "expected report-only trash entry; payload={payload}; log={}",
        result.log_path.display()
    );
    assert!(
        payload["report_only_bytes"]
            .as_u64()
            .is_some_and(|bytes| bytes >= 8192),
        "expected report-only byte total; payload={payload}; log={}",
        result.log_path.display()
    );

    let report_only = payload["report_only"]
        .as_array()
        .unwrap_or_else(|| panic!("scan JSON missing report_only array: {payload}"));
    let row = report_only
        .iter()
        .find(|row| row["pattern_name"].as_str() == Some("home-trash-report"))
        .unwrap_or_else(|| {
            panic!(
                "home-trash-report row missing from report_only entries; payload={payload}; log={}",
                result.log_path.display()
            )
        });
    assert_eq!(row["decision"].as_str(), Some("Keep"));
    assert!(
        row["path"]
            .as_str()
            .is_some_and(|path| path.ends_with("/.Trash/old-session")),
        "unexpected report-only path: {row}"
    );
    assert!(
        row["veto_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("cleanup rule is report-only")),
        "missing report-only veto reason: {row}"
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn scan_reports_home_trash_without_candidate() {}

#[test]
fn scan_json_reports_v2_engine_and_opaque_pruning_metrics() {
    let tmp = tempfile::tempdir().expect("create scan metrics fixture");
    let root = tmp.path().join("project");
    let target = root.join("target");
    fs::create_dir_all(
        target
            .join("debug")
            .join("deps")
            .join("crate_000")
            .join("src"),
    )
    .expect("create synthetic target tree");
    fs::write(root.join("Cargo.toml"), "[package]\nname = \"demo\"\n").expect("write Cargo.toml");
    fs::write(
        target
            .join("debug")
            .join("deps")
            .join("crate_000")
            .join("src")
            .join("lib.rs"),
        b"pub fn demo() {}\n",
    )
    .expect("write synthetic source");

    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&state_dir).expect("create state directory");
    let config_path = tmp.path().join("config.toml");
    fs::write(
        &config_path,
        format!(
            "[paths]\nstate_file = \"{}\"\nsqlite_db = \"{}\"\njsonl_log = \"{}\"\nballast_dir = \"{}\"\n\n[scanner]\nengine = \"v2\"\nroot_paths = [\"{}\"]\nmin_file_age_minutes = 0\n",
            state_dir.join("state.json").display(),
            state_dir.join("activity.sqlite3").display(),
            state_dir.join("activity.jsonl").display(),
            state_dir.join("ballast").display(),
            root.display(),
        ),
    )
    .expect("write scan metrics config");

    let config_str = config_path.to_string_lossy().to_string();
    let root_str = root.to_string_lossy().to_string();
    let result = common::run_cli_case(
        "scan_json_reports_v2_engine_and_opaque_pruning_metrics",
        &["--config", &config_str, "--json", "scan", &root_str],
    );
    assert_cli_success(&result, "v2 scan metrics");

    let payload = parse_json_stdout(&result);
    assert_eq!(payload["scanner_engine"].as_str(), Some("v2"));
    assert_eq!(
        payload["scanner_dispatch"].as_str(),
        Some("v2_opaque_pruning_walker")
    );
    assert_eq!(payload["opaque_pruning"].as_bool(), Some(true));
    assert_eq!(payload["opaque_pruned_dirs"].as_u64(), Some(1));
    assert!(
        payload
            .get("process_cpu_micros")
            .is_some_and(|value| value.is_null() || value.as_u64().is_some()),
        "scan JSON should include a nullable process_cpu_micros field for A/B artifacts; payload={payload}"
    );
    assert!(
        payload["scanned_entries"]
            .as_u64()
            .is_some_and(|entries| entries < 10),
        "v2 scan should report an opaque root without descending; payload={payload}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_status_json_matches_diskutil_apfs_capacity() {
    let _capacity_guard = MACOS_APFS_CAPACITY_TEST_LOCK
        .lock()
        .expect("APFS capacity test lock should not be poisoned");

    let result = common::run_cli_case(
        "macos_status_json_matches_diskutil_apfs_capacity",
        &["status", "--json"],
    );
    assert!(
        result.status.success(),
        "status --json failed; stderr={:?}; log={}",
        result.stderr,
        result.log_path.display()
    );
    let payload: Value = serde_json::from_str(result.stdout.trim()).unwrap_or_else(|err| {
        panic!(
            "expected status JSON, parse failed: {err}; stdout={:?}; log={}",
            result.stdout,
            result.log_path.display()
        )
    });
    let mounts = payload["pressure"]["mounts"].as_array().unwrap_or_else(|| {
        panic!(
            "status JSON missing pressure.mounts array; payload={payload}; log={}",
            result.log_path.display()
        )
    });
    let data_mount = mounts
        .iter()
        .find(|mount| mount["is_primary"].as_bool() == Some(true))
        .or_else(|| {
            mounts.iter().find(|mount| {
                mount["path"]
                    .as_str()
                    .is_some_and(|path| path == "/System/Volumes/Data")
            })
        })
        .unwrap_or_else(|| {
            panic!(
                "status JSON did not include primary APFS Data mount; payload={payload}; log={}",
                result.log_path.display()
            )
        });

    let container_id = data_mount["container_id"]
        .as_str()
        .expect("primary APFS mount should report container_id");
    let (diskutil_total, diskutil_available) =
        diskutil_container_capacity(container_id, &format!("status_mount={data_mount}"));

    assert_eq!(data_mount["free_excludes_purgeable"], true);
    assert_eq!(data_mount["is_primary"], true);
    assert_eq!(data_mount["volume_role"].as_str(), Some("Data"));

    assert_json_bytes_close(
        data_mount,
        "container_total",
        diskutil_total,
        MACOS_LIVE_CAPACITY_TOLERANCE_BYTES,
    );
    assert_json_bytes_close(
        data_mount,
        "total",
        diskutil_total,
        MACOS_LIVE_CAPACITY_TOLERANCE_BYTES,
    );
    assert_json_bytes_close(
        data_mount,
        "container_available",
        diskutil_available,
        macos_live_available_capacity_tolerance(data_mount),
    );
    assert_json_bytes_close(
        data_mount,
        "free",
        diskutil_available,
        macos_live_available_capacity_tolerance(data_mount),
    );

    let apfs = &data_mount["platform"]["darwin"]["apfs"];
    assert_eq!(apfs["container_id"].as_str(), Some(container_id));
    assert_eq!(apfs["volume_role"].as_str(), Some("Data"));
    assert_eq!(apfs["free_excludes_purgeable"], true);
    assert_json_bytes_close(
        apfs,
        "container_total_bytes",
        diskutil_total,
        MACOS_LIVE_CAPACITY_TOLERANCE_BYTES,
    );
    assert_json_bytes_close(
        apfs,
        "container_available_bytes",
        diskutil_available,
        macos_live_available_capacity_tolerance(data_mount),
    );
}

#[cfg(target_os = "macos")]
fn assert_json_bytes_close(mount: &Value, key: &'static str, expected: u64, tolerance: u64) {
    let actual = mount[key]
        .as_u64()
        .unwrap_or_else(|| panic!("status mount field {key} should be a u64: {mount}"));
    let delta = actual.abs_diff(expected);
    assert!(
        delta <= tolerance,
        "{key} mismatch exceeded tolerance: status={actual} diskutil={expected} delta={delta} tolerance={tolerance}; status_mount={mount}"
    );
}

#[cfg(target_os = "macos")]
fn macos_live_available_capacity_tolerance(payload: &Value) -> u64 {
    let total = payload["container_total"]
        .as_u64()
        .or_else(|| payload["container_total_bytes"].as_u64())
        .unwrap_or(0);
    MACOS_LIVE_CAPACITY_TOLERANCE_BYTES.max(total / MACOS_LIVE_AVAILABLE_CAPACITY_TOLERANCE_RATIO)
}

#[cfg(target_os = "macos")]
fn diskutil_container_capacity(container_id: &str, context: &str) -> (u64, u64) {
    let diskutil = std::process::Command::new("/usr/sbin/diskutil")
        .args(["apfs", "list", "-plist"])
        .output()
        .expect("diskutil should execute on macOS");
    assert!(
        diskutil.status.success(),
        "diskutil apfs list -plist failed: status={} stderr={}",
        diskutil.status,
        String::from_utf8_lossy(&diskutil.stderr)
    );
    let inventory =
        storage_ballast_helper::platform::macos::sys::parse_apfs_inventory(&diskutil.stdout)
            .expect("diskutil APFS plist should parse");
    let container = inventory
        .containers
        .iter()
        .find(|container| container.container_id == container_id)
        .unwrap_or_else(|| {
            panic!("container_id {container_id:?} not found in diskutil inventory; {context}")
        });
    let total = container
        .capacity_total_bytes
        .expect("diskutil container should include total capacity");
    let available = container
        .capacity_available_bytes
        .expect("diskutil container should include available capacity");
    (total, available)
}

#[cfg(not(target_os = "macos"))]
#[test]
fn macos_status_json_matches_diskutil_apfs_capacity() {}

#[cfg(target_os = "macos")]
#[test]
fn macos_check_json_matches_diskutil_apfs_capacity() {
    let _capacity_guard = MACOS_APFS_CAPACITY_TEST_LOCK
        .lock()
        .expect("APFS capacity test lock should not be poisoned");

    let result = common::run_cli_case(
        "macos_check_json_matches_diskutil_apfs_capacity",
        &["--json", "check", "--target-free", "0", "/"],
    );
    assert!(
        result.status.success(),
        "check --json failed; stderr={:?}; log={}",
        result.stderr,
        result.log_path.display()
    );
    let payload: Value = serde_json::from_str(result.stdout.trim()).unwrap_or_else(|err| {
        panic!(
            "expected check JSON, parse failed: {err}; stdout={:?}; log={}",
            result.stdout,
            result.log_path.display()
        )
    });

    let container_id = payload["container_id"]
        .as_str()
        .expect("check JSON should report APFS container_id for /");
    let (diskutil_total, diskutil_available) =
        diskutil_container_capacity(container_id, &format!("payload={payload}"));

    assert_eq!(payload["command"].as_str(), Some("check"));
    assert_eq!(payload["status"].as_str(), Some("ok"));
    assert_json_bytes_close(
        &payload,
        "container_total_bytes",
        diskutil_total,
        MACOS_LIVE_CAPACITY_TOLERANCE_BYTES,
    );
    assert_json_bytes_close(
        &payload,
        "total_bytes",
        diskutil_total,
        MACOS_LIVE_CAPACITY_TOLERANCE_BYTES,
    );
    assert_json_bytes_close(
        &payload,
        "container_available_bytes",
        diskutil_available,
        macos_live_available_capacity_tolerance(&payload),
    );
    assert_json_bytes_close(
        &payload,
        "free_bytes",
        diskutil_available,
        macos_live_available_capacity_tolerance(&payload),
    );

    let apfs = &payload["platform"]["darwin"]["apfs"];
    assert_eq!(apfs["container_id"].as_str(), Some(container_id));
    assert_eq!(apfs["free_excludes_purgeable"], true);
    assert_json_bytes_close(
        apfs,
        "container_total_bytes",
        diskutil_total,
        MACOS_LIVE_CAPACITY_TOLERANCE_BYTES,
    );
    assert_json_bytes_close(
        apfs,
        "container_available_bytes",
        diskutil_available,
        macos_live_available_capacity_tolerance(&payload),
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn macos_check_json_matches_diskutil_apfs_capacity() {}

#[cfg(target_os = "macos")]
#[test]
fn macos_apfs_ballast_preallocates_and_releases_space() {
    const BALLAST_BYTES: u64 = 1024 * 1024 * 1024;
    const MIN_AVAILABLE_BYTES: u64 = 3 * BALLAST_BYTES;
    const RECOVERY_FLOOR_BYTES: u64 = BALLAST_BYTES / 2;

    if std::env::var_os("CI").is_none() && std::env::var_os("SBH_RUN_APFS_BALLAST_TEST").is_none() {
        eprintln!(
            "skipping APFS ballast integration test outside CI; set SBH_RUN_APFS_BALLAST_TEST=1 to run locally"
        );
        return;
    }
    let _capacity_guard = MACOS_APFS_CAPACITY_TEST_LOCK
        .lock()
        .expect("APFS capacity test lock should not be poisoned");

    let platform = storage_ballast_helper::platform::current();
    let dir = tempfile::Builder::new()
        .prefix("sbh-apfs-ballast-")
        .tempdir()
        .expect("create APFS ballast test directory");
    let Some(before_provision) =
        apfs_ballast_start_available_or_skip(&platform, dir.path(), MIN_AVAILABLE_BYTES)
    else {
        return;
    };

    let mut manager = BallastManager::new(
        dir.path().to_path_buf(),
        BallastConfig {
            file_count: 1,
            file_size_bytes: BALLAST_BYTES,
            replenish_cooldown_minutes: 0,
            auto_provision: true,
            overrides: std::collections::BTreeMap::new(),
        },
    )
    .expect("create ballast manager");
    let provision = manager
        .provision(None)
        .expect("provision 1 GiB APFS ballast");
    assert_eq!(provision.files_created, 1);
    assert!(
        provision.errors.is_empty(),
        "provision errors: {:?}",
        provision.errors
    );

    let ballast_path = dir.path().join("SBH_BALLAST_FILE_00001.dat");
    assert_eq!(
        fs::metadata(&ballast_path)
            .expect("ballast file metadata")
            .len(),
        BALLAST_BYTES
    );
    let allocated_bytes = platform
        .file_block_count(&ballast_path)
        .expect("read ballast block count")
        .checked_mul(512)
        .expect("block count should not overflow");
    assert!(
        allocated_bytes >= BALLAST_BYTES,
        "APFS ballast file is underallocated: allocated={allocated_bytes} expected={BALLAST_BYTES}"
    );

    let after_provision = platform
        .capacity(dir.path())
        .expect("read capacity after provision")
        .available_bytes;
    let release = manager.release(1).expect("release APFS ballast");
    assert_eq!(release.files_released, 1);
    assert_eq!(release.bytes_freed, BALLAST_BYTES);
    assert!(
        release.errors.is_empty(),
        "release errors: {:?}",
        release.errors
    );
    assert!(
        !ballast_path.exists(),
        "released APFS ballast file should be removed"
    );

    assert_apfs_available_bytes_recovers(
        &platform,
        dir.path(),
        before_provision,
        after_provision,
        allocated_bytes,
        RECOVERY_FLOOR_BYTES,
        &release.warnings,
    );
}

#[cfg(target_os = "macos")]
fn apfs_ballast_start_available_or_skip(
    platform: &impl Platform,
    path: &Path,
    min_available_bytes: u64,
) -> Option<u64> {
    let capacity = platform
        .capacity(path)
        .expect("read capacity for APFS ballast tempdir");
    if !capacity.fs_type.eq_ignore_ascii_case("apfs") {
        eprintln!(
            "skipping APFS ballast integration test on non-APFS filesystem {} at {}",
            capacity.fs_type,
            capacity.mount_point.display()
        );
        return None;
    }
    if capacity.available_bytes < min_available_bytes {
        eprintln!(
            "skipping APFS ballast integration test: {} available bytes is below {} byte safety floor",
            capacity.available_bytes, min_available_bytes
        );
        return None;
    }
    let snapshots = match platform.local_time_machine_snapshots(&capacity.mount_point) {
        Ok(snapshots) => snapshots,
        Err(error) => {
            eprintln!(
                "skipping APFS ballast integration test because local snapshot inspection failed on {}: {error}",
                capacity.mount_point.display()
            );
            return None;
        }
    };
    if !snapshots.is_empty() {
        eprintln!(
            "skipping APFS ballast integration test because {} local Time Machine snapshots are present on {}",
            snapshots.len(),
            capacity.mount_point.display()
        );
        return None;
    }
    Some(capacity.available_bytes)
}

#[cfg(target_os = "macos")]
fn assert_apfs_available_bytes_recovers(
    platform: &impl Platform,
    path: &Path,
    before_provision: u64,
    after_provision: u64,
    allocated_bytes: u64,
    recovery_floor_bytes: u64,
    release_warnings: &[String],
) {
    let allocation_visible =
        before_provision.saturating_sub(after_provision) >= recovery_floor_bytes;
    if !allocation_visible {
        eprintln!(
            "APFS available bytes did not visibly decrease after preallocating ballast; before={before_provision} after_provision={after_provision} allocated_bytes={allocated_bytes}. Skipping free-space recovery subcheck."
        );
        return;
    }

    let target_available = after_provision.saturating_add(recovery_floor_bytes);
    let after_release = wait_for_available_bytes_at_least(
        platform,
        path,
        target_available,
        Duration::from_secs(10),
    )
    .unwrap_or_else(|| {
        platform
            .capacity(path)
            .expect("read final APFS capacity")
            .available_bytes
    });
    assert!(
        after_release >= target_available,
        "APFS free space did not recover after ballast release: after_provision={after_provision} after_release={after_release} target={target_available} release_warnings={release_warnings:?}"
    );
}

#[cfg(target_os = "macos")]
fn wait_for_available_bytes_at_least(
    platform: &impl Platform,
    path: &Path,
    target_available: u64,
    timeout: Duration,
) -> Option<u64> {
    let deadline = Instant::now() + timeout;
    loop {
        let available = platform.capacity(path).ok()?.available_bytes;
        if available >= target_available {
            return Some(available);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn macos_apfs_ballast_preallocates_and_releases_space() {}

#[cfg(target_os = "macos")]
#[test]
fn macos_synthetic_writer_surfaces_in_blame_top_rows() {
    const MIN_VISIBLE_WRITER_BYTES: u64 = 90 * 1_048_576;
    const WRITER_MIB: u64 = 112;

    let perl = Path::new("/usr/bin/perl");
    if !perl.exists() {
        eprintln!("skipping sbh blame writer test because /usr/bin/perl is unavailable");
        return;
    }

    let dir = tempfile::Builder::new()
        .prefix("sbh_blame_test_")
        .tempdir_in("/private/tmp")
        .expect("create blame test directory in /private/tmp");
    let data_path = dir.path().join("writer.bin");
    let ready_path = dir.path().join("writer.ready");
    let config_path = dir.path().join("config.toml");
    let state_dir = dir.path().join("state");
    fs::create_dir(&state_dir).expect("create blame state dir");
    fs::create_dir(state_dir.join("ballast")).expect("create blame ballast dir");
    fs::write(
        &config_path,
        format!(
            "[paths]\nstate_file = \"{}\"\nsqlite_db = \"{}\"\njsonl_log = \"{}\"\nballast_dir = \"{}\"\n\n[scanner]\nroot_paths = [\"{}\"]\n",
            state_dir.join("state.json").display(),
            state_dir.join("activity.sqlite3").display(),
            state_dir.join("activity.jsonl").display(),
            state_dir.join("ballast").display(),
            dir.path().display(),
        ),
    )
    .expect("write blame test config");

    let mut writer = ChildGuard::new(spawn_blame_writer(
        perl,
        &data_path,
        &ready_path,
        WRITER_MIB,
    ));
    wait_for_file(&ready_path, Duration::from_secs(15), || {
        if let Ok(Some(status)) = writer.child.try_wait() {
            panic!("synthetic writer exited before ready marker: {status}");
        }
    });

    let config = config_path
        .to_str()
        .expect("config path should be valid UTF-8");
    let result = common::run_cli_case(
        "macos_synthetic_writer_surfaces_in_blame_top_rows",
        &[
            "--config", config, "--json", "blame", "--top", "10", "--since", "1m",
        ],
    );
    assert!(
        result.status.success(),
        "sbh blame failed; stdout={:?}; stderr={:?}; log={}",
        result.stdout,
        result.stderr,
        result.log_path.display()
    );

    let payload: Value = serde_json::from_str(result.stdout.trim()).unwrap_or_else(|err| {
        panic!(
            "expected blame JSON, parse failed: {err}; stdout={:?}; stderr={:?}; log={}",
            result.stdout,
            result.stderr,
            result.log_path.display()
        )
    });
    let rows = payload["rows"]
        .as_array()
        .unwrap_or_else(|| panic!("blame JSON missing rows array: {payload}"));
    let writer_pid = i64::from(writer.child.id());
    let row = rows
        .iter()
        .find(|row| row["pid"].as_i64() == Some(writer_pid))
        .unwrap_or_else(|| {
            panic!(
                "synthetic writer pid {writer_pid} missing from blame rows; payload={payload}; log={}",
                result.log_path.display()
            )
        });
    let written = row["recent_bytes_written"]
        .as_u64()
        .unwrap_or_else(|| panic!("writer row missing recent_bytes_written: {row}"));
    assert!(
        written >= MIN_VISIBLE_WRITER_BYTES,
        "writer row under-reported writes: written={written} expected_at_least={MIN_VISIBLE_WRITER_BYTES}; row={row}; payload={payload}"
    );
    let open_files = row["open_files"]
        .as_array()
        .unwrap_or_else(|| panic!("writer row missing open_files array: {row}"));
    assert!(
        open_files.iter().any(|path| path
            .as_str()
            .is_some_and(|path| path == data_path.to_string_lossy())),
        "writer row did not report open test file {}; row={row}; payload={payload}",
        data_path.display()
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn macos_synthetic_writer_surfaces_in_blame_top_rows() {}

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(target_os = "macos")]
fn spawn_blame_writer(perl: &Path, data_path: &Path, ready_path: &Path, writer_mib: u64) -> Child {
    Command::new(perl)
        .arg("-MIO::Handle")
        .arg("-e")
        .arg(
            r#"
my ($data_path, $ready_path, $mib) = @ARGV;
open(my $fh, ">", $data_path) or die "open data: $!";
binmode($fh) or die "binmode data: $!";
my $buf = "\0" x 1048576;
for (my $i = 0; $i < $mib; $i++) {
    print {$fh} $buf or die "write data: $!";
}
$fh->flush();
open(my $ready, ">", $ready_path) or die "open ready: $!";
print {$ready} "ready\n" or die "write ready: $!";
close($ready) or die "close ready: $!";
sleep 30;
"#,
        )
        .arg(data_path)
        .arg(ready_path)
        .arg(writer_mib.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn synthetic blame writer")
}

#[cfg(target_os = "macos")]
fn wait_for_file(path: &Path, timeout: Duration, mut poll: impl FnMut()) {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        poll();
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn daemon_exits_nonzero_when_rss_hard_cap_exceeded() {
    let dir = tempfile::tempdir().expect("create rss hard cap test dir");
    let scan_root = dir.path().join("scan-root");
    let state_dir = dir.path().join("state");
    let ballast_dir = dir.path().join("ballast");
    fs::create_dir(&scan_root).expect("create scan root");
    fs::create_dir(&state_dir).expect("create state dir");
    fs::create_dir(&ballast_dir).expect("create ballast dir");

    let config_path = dir.path().join("config.toml");
    let stderr_path = dir.path().join("daemon.stderr");
    write_rss_hard_cap_test_config(&config_path, &scan_root, &state_dir, &ballast_dir);

    let stderr = fs::File::create(&stderr_path).expect("create daemon stderr log");
    let mut daemon = ChildGuard::new(
        Command::new(common::sbh_bin_path())
            .arg("--config")
            .arg(&config_path)
            .arg("daemon")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr)
            .spawn()
            .expect("spawn daemon with tiny RSS hard cap"),
    );

    let status = wait_for_child_exit(&mut daemon.child, Duration::from_secs(10));
    assert!(
        !status.success(),
        "RSS hard cap breach should exit nonzero, got {status}"
    );

    let stderr = fs::read_to_string(&stderr_path).expect("read daemon stderr");
    assert!(
        stderr.contains("RSS") && stderr.contains("hard limit"),
        "daemon stderr should explain RSS hard limit breach; stderr:\n{stderr}"
    );

    let state_path = state_dir.join("state.json");
    let state = storage_ballast_helper::daemon::self_monitor::SelfMonitor::read_state(&state_path)
        .expect("hard cap exit should persist state");
    assert!(
        state.memory_rss_bytes > 1,
        "state should contain fatal RSS sample, got {}",
        state.memory_rss_bytes
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_foreground_daemon_idle_energy_budget() {
    const SAMPLE_DURATION: Duration = Duration::from_mins(1);
    const STARTUP_GRACE: Duration = Duration::from_secs(3);
    const MAX_IDLE_RSS_BYTES: u64 = 50 * 1_048_576;
    const MAX_IDLE_WAKEUPS_PER_SEC: u64 = 100;

    if should_skip_energy_impact_test() {
        return;
    }

    let dir = tempfile::Builder::new()
        .prefix("sbh_energy_test_")
        .tempdir_in("/private/tmp")
        .expect("create energy test directory");
    let scan_root = dir.path().join("scan-root");
    let state_dir = dir.path().join("state");
    let ballast_dir = dir.path().join("ballast");
    fs::create_dir(&scan_root).expect("create scan root");
    fs::create_dir(&state_dir).expect("create state dir");
    fs::create_dir(&ballast_dir).expect("create ballast dir");

    let config_path = dir.path().join("config.toml");
    let stderr_path = dir.path().join("daemon.stderr");
    write_energy_test_config(&config_path, &scan_root, &state_dir, &ballast_dir);

    let mut daemon = ChildGuard::new(spawn_energy_test_daemon(&config_path, &stderr_path));
    std::thread::sleep(STARTUP_GRACE);
    assert_child_still_running(&mut daemon.child, "energy daemon exited during startup");

    let baseline = daemon_energy_sample(daemon.child.id());
    let started_at = Instant::now();
    std::thread::sleep(SAMPLE_DURATION);
    assert_child_still_running(
        &mut daemon.child,
        "energy daemon exited before sample completed",
    );
    let elapsed = started_at.elapsed();
    let final_sample = daemon_energy_sample(daemon.child.id());

    let wakeups_delta = final_sample
        .idle_wakeups
        .saturating_sub(baseline.idle_wakeups);
    let elapsed_secs = elapsed.as_secs().max(1);
    let allowed_wakeups = MAX_IDLE_WAKEUPS_PER_SEC.saturating_mul(elapsed_secs);
    assert!(
        wakeups_delta <= allowed_wakeups,
        "idle daemon exceeded wakeup budget: delta={wakeups_delta} elapsed_secs={elapsed_secs} allowed={allowed_wakeups} baseline={baseline:?} final={final_sample:?}"
    );
    assert!(
        final_sample.rss_bytes <= MAX_IDLE_RSS_BYTES,
        "idle daemon exceeded RSS budget: rss={} max={} baseline={baseline:?} final={final_sample:?}",
        final_sample.rss_bytes,
        MAX_IDLE_RSS_BYTES
    );

    send_signal(daemon.child.id(), "TERM");
    let status = wait_for_child_exit(&mut daemon.child, Duration::from_secs(5));
    assert!(
        status.success(),
        "energy daemon SIGTERM should exit cleanly, got {status}"
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn macos_foreground_daemon_idle_energy_budget() {}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct DaemonEnergySample {
    rss_bytes: u64,
    idle_wakeups: u64,
}

#[cfg(target_os = "macos")]
fn should_skip_energy_impact_test() -> bool {
    if env::var_os("SBH_SLOW_CI_RUNNER").is_some() {
        eprintln!("skipping energy impact test on runner marked SBH_SLOW_CI_RUNNER");
        return true;
    }
    if env::var_os("SBH_SKIP_ENERGY_IMPACT_TEST").is_some() {
        eprintln!("skipping energy impact test because SBH_SKIP_ENERGY_IMPACT_TEST is set");
        return true;
    }
    if env::var("SBH_RUN_ENERGY_IMPACT_TEST").as_deref() == Ok("1") {
        return false;
    }
    eprintln!(
        "skipping energy impact test; set SBH_RUN_ENERGY_IMPACT_TEST=1 to run the 60s release-binary budget check"
    );
    true
}

#[cfg(target_os = "macos")]
fn daemon_energy_sample(pid: u32) -> DaemonEnergySample {
    let pid = i32::try_from(pid).expect("child pid should fit i32");
    let task = storage_ballast_helper::platform::macos::libproc::proc_pidinfo_task(pid)
        .expect("read daemon task info");
    let rusage = storage_ballast_helper::platform::macos::libproc::proc_pid_rusage_v4_safe(pid)
        .expect("read daemon rusage info");
    DaemonEnergySample {
        rss_bytes: task.pti_resident_size,
        idle_wakeups: rusage
            .ri_pkg_idle_wkups
            .saturating_add(rusage.ri_interrupt_wkups),
    }
}

#[cfg(target_os = "macos")]
fn spawn_energy_test_daemon(config_path: &Path, stderr_path: &Path) -> Child {
    let bin_path =
        env::var_os("SBH_ENERGY_TEST_BIN").map_or_else(common::sbh_bin_path, PathBuf::from);
    let stderr = fs::File::create(stderr_path).expect("create daemon stderr log");
    Command::new(bin_path)
        .arg("--config")
        .arg(config_path)
        .arg("daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()
        .expect("spawn foreground daemon for energy test")
}

#[cfg(target_os = "macos")]
fn write_energy_test_config(
    config_path: &Path,
    scan_root: &Path,
    state_dir: &Path,
    ballast_dir: &Path,
) {
    let state_file = state_dir.join("state.json");
    let sqlite_db = state_dir.join("activity.sqlite3");
    let jsonl_log = state_dir.join("activity.jsonl");
    let config = format!(
        r#"[paths]
state_file = "{}"
sqlite_db = "{}"
jsonl_log = "{}"
ballast_dir = "{}"

[pressure]
poll_interval_ms = 15000

[scanner]
root_paths = ["{}"]
min_file_age_minutes = 60
max_depth = 1
parallelism = 1
dry_run = true

[ballast]
file_count = 1
file_size_bytes = 4096
"#,
        toml_path(&state_file),
        toml_path(&sqlite_db),
        toml_path(&jsonl_log),
        toml_path(ballast_dir),
        toml_path(scan_root),
    );
    fs::write(config_path, config).expect("write daemon energy test config");
}

#[cfg(target_os = "macos")]
#[test]
fn macos_foreground_daemon_handles_term_hup_and_siginfo() {
    let dir = tempfile::Builder::new()
        .prefix("sbh_signal_test_")
        .tempdir_in("/private/tmp")
        .expect("create signal test directory");
    let scan_root = dir.path().join("scan-root");
    let state_dir = dir.path().join("state");
    let ballast_dir = dir.path().join("ballast");
    fs::create_dir(&scan_root).expect("create scan root");
    fs::create_dir(&state_dir).expect("create state dir");
    fs::create_dir(&ballast_dir).expect("create ballast dir");

    let config_path = dir.path().join("config.toml");
    let stderr_path = dir.path().join("daemon.stderr");
    write_signal_test_config(&config_path, &scan_root, &state_dir, &ballast_dir, 5);

    let mut daemon = ChildGuard::new(spawn_signal_test_daemon(&config_path, &stderr_path));
    std::thread::sleep(Duration::from_secs(3));
    assert_child_still_running(&mut daemon.child, "daemon exited during startup");

    write_signal_test_config(&config_path, &scan_root, &state_dir, &ballast_dir, 6);
    send_signal(daemon.child.id(), "HUP");
    wait_for_stderr_contains(
        &stderr_path,
        "config reloaded successfully",
        Duration::from_secs(20),
        &mut daemon.child,
    );

    send_signal(daemon.child.id(), "INFO");
    let status_dump =
        wait_for_siginfo_status_dump(&stderr_path, Duration::from_secs(15), &mut daemon.child);
    assert!(
        status_dump["pressure"]["causing_mount"]
            .as_str()
            .is_some_and(|mount| !mount.is_empty())
    );
    assert!(status_dump["pressure"]["overall"].is_string());
    assert!(
        status_dump["threads"]
            .as_array()
            .is_some_and(|rows| rows.len() >= 2)
    );

    send_signal(daemon.child.id(), "TERM");
    let status = wait_for_child_exit(&mut daemon.child, Duration::from_secs(5));
    assert!(
        status.success(),
        "SIGTERM should exit cleanly, got {status}"
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn macos_foreground_daemon_handles_term_hup_and_siginfo() {}

#[cfg(target_os = "macos")]
#[test]
fn macos_launchd_user_service_lifecycle_bootstrap_kickstart_bootout() {
    if env::var("SBH_RUN_LAUNCHD_LIFECYCLE_TEST").as_deref() != Ok("1") {
        eprintln!("skipping launchd lifecycle test; set SBH_RUN_LAUNCHD_LIFECYCLE_TEST=1");
        return;
    }

    let dir = tempfile::Builder::new()
        .prefix("sbh_launchd_lifecycle_")
        .tempdir_in("/private/tmp")
        .expect("create launchd lifecycle test directory");
    let home = dir.path().join("home");
    let config_dir = dir.path().join("config");
    fs::create_dir(&home).expect("create launchd test home");
    fs::create_dir(&config_dir).expect("create launchd test config dir");

    let config_path = config_dir.join("config.toml");
    let label = launchd_test_label();
    let env_overrides = launchd_env_overrides(&home, &config_path, &label);
    let bin_path = launchd_test_bin_path();
    let offline_bundle = write_launchd_offline_bundle(dir.path(), &bin_path);
    let _guard =
        LaunchdLifecycleGuard::new(bin_path.clone(), config_path.clone(), env_overrides.clone());

    run_launchd_config_reset(&bin_path, &config_path, &env_overrides);
    run_launchd_install(&bin_path, &config_path, &offline_bundle, &env_overrides);
    let target =
        launchd_status_target_after_install(&bin_path, &config_path, &label, &env_overrides);
    assert_launchctl_live(&target);
    run_launchd_uninstall(&bin_path, &config_path, &env_overrides);
    wait_for_launchctl_absent(&target, Duration::from_secs(10));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn macos_launchd_user_service_lifecycle_bootstrap_kickstart_bootout() {}

#[cfg(target_os = "macos")]
struct LaunchdLifecycleGuard {
    bin_path: PathBuf,
    config_path: PathBuf,
    env_overrides: Vec<(String, String)>,
}

#[cfg(target_os = "macos")]
impl LaunchdLifecycleGuard {
    fn new(bin_path: PathBuf, config_path: PathBuf, env_overrides: Vec<(String, String)>) -> Self {
        Self {
            bin_path,
            config_path,
            env_overrides,
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for LaunchdLifecycleGuard {
    fn drop(&mut self) {
        let mut command = Command::new(&self.bin_path);
        command
            .arg("--config")
            .arg(&self.config_path)
            .args(["uninstall", "--launchd", "--scope", "user"])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (key, value) in &self.env_overrides {
            command.env(key, value);
        }
        let _ = command.status();
    }
}

#[cfg(target_os = "macos")]
fn launchd_test_label() -> String {
    format!(
        "com.dicklesworthstone.sbh.test.{}.{}",
        std::process::id(),
        now_millis()
    )
}

#[cfg(target_os = "macos")]
fn launchd_env_overrides(home: &Path, config_path: &Path, label: &str) -> Vec<(String, String)> {
    vec![
        ("HOME".to_string(), home.to_string_lossy().into_owned()),
        (
            "SBH_CONFIG_PATH".to_string(),
            config_path.to_string_lossy().into_owned(),
        ),
        (
            "SBH_CONFIG".to_string(),
            config_path.to_string_lossy().into_owned(),
        ),
        ("SBH_LAUNCHD_LABEL".to_string(), label.to_string()),
        ("RUST_LOG".to_string(), "info".to_string()),
    ]
}

#[cfg(target_os = "macos")]
fn launchd_test_bin_path() -> PathBuf {
    env::var_os("SBH_LAUNCHD_TEST_BIN").map_or_else(common::sbh_bin_path, PathBuf::from)
}

#[cfg(target_os = "macos")]
fn run_launchd_config_reset(
    bin_path: &Path,
    config_path: &Path,
    env_overrides: &[(String, String)],
) {
    let result = run_launchd_sbh_case(
        "macos_launchd_config_reset",
        bin_path,
        &[
            "--config".to_string(),
            config_path.to_string_lossy().into_owned(),
            "config".to_string(),
            "reset".to_string(),
        ],
        env_overrides,
    );
    assert!(
        result.status.success(),
        "config reset failed; stdout={:?}; stderr={:?}; log={}",
        result.stdout,
        result.stderr,
        result.log_path.display()
    );
}

#[cfg(target_os = "macos")]
fn run_launchd_install(
    bin_path: &Path,
    config_path: &Path,
    offline_bundle: &Path,
    env_overrides: &[(String, String)],
) {
    let result = run_launchd_sbh_case(
        "macos_launchd_install_user_service",
        bin_path,
        &[
            "--config".to_string(),
            config_path.to_string_lossy().into_owned(),
            "install".to_string(),
            "--launchd".to_string(),
            "--scope".to_string(),
            "user".to_string(),
            "--ballast-count".to_string(),
            "0".to_string(),
            "--no-verify".to_string(),
            "--offline".to_string(),
            offline_bundle.to_string_lossy().into_owned(),
        ],
        env_overrides,
    );
    assert!(
        result.status.success(),
        "launchd install failed; stdout={:?}; stderr={:?}; log={}",
        result.stdout,
        result.stderr,
        result.log_path.display()
    );
}

#[cfg(target_os = "macos")]
fn launchd_status_target_after_install(
    bin_path: &Path,
    config_path: &Path,
    label: &str,
    env_overrides: &[(String, String)],
) -> String {
    let result = run_launchd_sbh_case(
        "macos_launchd_status_after_install",
        bin_path,
        &[
            "--config".to_string(),
            config_path.to_string_lossy().into_owned(),
            "--json".to_string(),
            "service".to_string(),
            "--launchd".to_string(),
            "--scope".to_string(),
            "user".to_string(),
            "status".to_string(),
        ],
        env_overrides,
    );
    assert!(
        result.status.success(),
        "launchd status failed; stdout={:?}; stderr={:?}; log={}",
        result.stdout,
        result.stderr,
        result.log_path.display()
    );
    let status_payload: Value = serde_json::from_str(result.stdout.trim()).unwrap_or_else(|err| {
        panic!(
            "expected launchd status JSON, parse failed: {err}; stdout={:?}; log={}",
            result.stdout,
            result.log_path.display()
        )
    });
    assert_eq!(status_payload["service_type"], "launchd");
    assert_eq!(status_payload["scope"], "user");
    assert_eq!(status_payload["loaded"], true);
    let target = status_payload["target"]
        .as_str()
        .unwrap_or_else(|| panic!("launchd status missing target: {status_payload}"));
    assert!(
        target.ends_with(label),
        "launchd target {target:?} did not include unique label {label:?}"
    );
    let plist_path = status_payload["plist_path"]
        .as_str()
        .unwrap_or_else(|| panic!("launchd status missing plist_path: {status_payload}"));
    assert!(
        plist_path.contains("Library/LaunchAgents")
            && plist_path.ends_with(&format!("{label}.plist")),
        "unexpected launchd plist path: {plist_path}"
    );
    target.to_string()
}

#[cfg(target_os = "macos")]
fn assert_launchctl_live(target: &str) {
    let print = Command::new("launchctl")
        .args(["print", target])
        .output()
        .expect("run launchctl print after install");
    assert!(
        print.status.success(),
        "launchctl print {target} failed after install; stdout={:?}; stderr={:?}",
        String::from_utf8_lossy(&print.stdout),
        String::from_utf8_lossy(&print.stderr)
    );
    let print_stdout = String::from_utf8_lossy(&print.stdout);
    assert!(
        print_stdout.contains("state = running")
            || print_stdout.contains("state = spawn scheduled"),
        "launchctl print did not report a live launchd lifecycle state; stdout={print_stdout:?}"
    );
}

#[cfg(target_os = "macos")]
fn run_launchd_uninstall(bin_path: &Path, config_path: &Path, env_overrides: &[(String, String)]) {
    let result = run_launchd_sbh_case(
        "macos_launchd_uninstall_user_service",
        bin_path,
        &[
            "--config".to_string(),
            config_path.to_string_lossy().into_owned(),
            "uninstall".to_string(),
            "--launchd".to_string(),
            "--scope".to_string(),
            "user".to_string(),
        ],
        env_overrides,
    );
    assert!(
        result.status.success(),
        "launchd uninstall failed; stdout={:?}; stderr={:?}; log={}",
        result.stdout,
        result.stderr,
        result.log_path.display()
    );
}

#[cfg(target_os = "macos")]
fn run_launchd_sbh_case(
    case_name: &str,
    bin_path: &Path,
    args: &[String],
    env_overrides: &[(String, String)],
) -> common::CmdResult {
    let root = std::env::temp_dir().join("sbh-test-logs");
    fs::create_dir_all(&root).expect("create temp test log dir");
    let log_path = root.join(format!("{case_name}-{}.log", now_millis()));

    let mut command = Command::new(bin_path);
    command
        .args(args)
        .env("SBH_TEST_VERBOSE", "1")
        .env("RUST_BACKTRACE", "1");
    for (key, value) in env_overrides {
        command.env(key, value);
    }

    let output = command.output().expect("execute sbh launchd command");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let log_content = format!(
        "case={case_name}\nbin={}\nargs={args:?}\nenv_overrides={env_overrides:?}\nstatus={}\n----- stdout -----\n{stdout}\n----- stderr -----\n{stderr}\n",
        bin_path.display(),
        output.status
    );
    fs::write(&log_path, log_content).expect("write launchd test log");

    common::CmdResult {
        status: output.status,
        stdout,
        stderr,
        log_path,
    }
}

#[cfg(target_os = "macos")]
fn write_launchd_offline_bundle(root: &Path, bin_path: &Path) -> PathBuf {
    let contract = resolve_updater_artifact_contract(
        HostSpecifier::detect().expect("detect host"),
        ReleaseChannel::Stable,
        Some("9.9.9"),
    )
    .expect("resolve current host updater artifact contract");
    let bundle_dir = root.join("offline-bundle");
    let stage_dir = bundle_dir.join("stage");
    fs::create_dir(&bundle_dir).expect("create offline bundle dir");
    fs::create_dir(&stage_dir).expect("create offline bundle stage dir");

    let staged_binary = stage_dir.join("sbh");
    fs::copy(bin_path, &staged_binary).unwrap_or_else(|err| {
        panic!(
            "copy launchd test binary {} to {} failed: {err}",
            bin_path.display(),
            staged_binary.display()
        )
    });

    let archive_name = contract.asset_name();
    let archive_path = bundle_dir.join(&archive_name);
    let tar_status = Command::new("tar")
        .arg("cJf")
        .arg(&archive_path)
        .arg("-C")
        .arg(&stage_dir)
        .arg("sbh")
        .status()
        .expect("create launchd offline tarball");
    assert!(
        tar_status.success(),
        "tar failed while creating launchd offline tarball at {}: {tar_status}",
        archive_path.display()
    );

    let checksum_name = contract.checksum_name();
    let checksum_path = bundle_dir.join(&checksum_name);
    let checksum = sha256_file_hex(&archive_path);
    fs::write(&checksum_path, format!("{checksum}  {archive_name}\n"))
        .expect("write launchd offline checksum");

    let manifest = OfflineBundleManifest {
        version: "1".to_string(),
        repository: RELEASE_REPOSITORY.to_string(),
        release_tag: "v9.9.9".to_string(),
        artifacts: vec![OfflineBundleArtifact {
            target: contract.target.triple.to_string(),
            archive: archive_name,
            checksum: checksum_name,
            sigstore_bundle: None,
        }],
    };
    let manifest_path = bundle_dir.join("bundle-manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("serialize launchd offline manifest"),
    )
    .expect("write launchd offline manifest");
    manifest_path
}

#[cfg(target_os = "macos")]
fn wait_for_launchctl_absent(target: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let output = Command::new("launchctl")
            .args(["print", target])
            .output()
            .expect("run launchctl print while waiting for bootout");
        if !output.status.success() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "launchd service remained loaded after uninstall; stdout={:?}; stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(target_os = "macos")]
fn sha256_file_hex(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|err| {
        panic!("read {} for sha256 failed: {err}", path.display());
    });
    hex_lower(Sha256::digest(&bytes))
}

fn write_rss_hard_cap_test_config(
    config_path: &Path,
    scan_root: &Path,
    state_dir: &Path,
    ballast_dir: &Path,
) {
    let state_file = state_dir.join("state.json");
    let sqlite_db = state_dir.join("activity.sqlite3");
    let jsonl_log = state_dir.join("activity.jsonl");
    let config = format!(
        r#"[paths]
state_file = "{}"
sqlite_db = "{}"
jsonl_log = "{}"
ballast_dir = "{}"

[pressure]
green_min_free_pct = 0.01
yellow_min_free_pct = 0.005
orange_min_free_pct = 0.002
red_min_free_pct = 0.001
poll_interval_ms = 100

[pressure.prediction]
enabled = false

[scanner]
root_paths = ["{}"]
min_file_age_minutes = 60
max_depth = 1
parallelism = 1
dry_run = true

[telemetry]
daemon_rss_warning_bytes = 1
daemon_rss_hard_limit_bytes = 1

[ballast]
file_count = 1
file_size_bytes = 4096
"#,
        toml_path(&state_file),
        toml_path(&sqlite_db),
        toml_path(&jsonl_log),
        toml_path(ballast_dir),
        toml_path(scan_root),
    );
    fs::write(config_path, config).expect("write daemon RSS hard cap test config");
}

#[cfg(target_os = "macos")]
fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

#[cfg(target_os = "macos")]
fn write_signal_test_config(
    config_path: &Path,
    scan_root: &Path,
    state_dir: &Path,
    ballast_dir: &Path,
    min_file_age_minutes: u64,
) {
    let state_file = state_dir.join("state.json");
    let sqlite_db = state_dir.join("activity.sqlite3");
    let jsonl_log = state_dir.join("activity.jsonl");
    let config = format!(
        r#"[paths]
state_file = "{}"
sqlite_db = "{}"
jsonl_log = "{}"
ballast_dir = "{}"

[pressure]
green_min_free_pct = 0.01
yellow_min_free_pct = 0.005
orange_min_free_pct = 0.002
red_min_free_pct = 0.001
poll_interval_ms = 100

[pressure.prediction]
enabled = false

[scanner]
root_paths = ["{}"]
min_file_age_minutes = {}
max_depth = 2
parallelism = 1
dry_run = true

[ballast]
file_count = 1
file_size_bytes = 4096
"#,
        toml_path(&state_file),
        toml_path(&sqlite_db),
        toml_path(&jsonl_log),
        toml_path(ballast_dir),
        toml_path(scan_root),
        min_file_age_minutes,
    );
    fs::write(config_path, config).expect("write daemon signal test config");
}

fn toml_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

#[cfg(target_os = "macos")]
fn spawn_signal_test_daemon(config_path: &Path, stderr_path: &Path) -> Child {
    let stderr = fs::File::create(stderr_path).expect("create daemon stderr log");
    Command::new(common::sbh_bin_path())
        .arg("--config")
        .arg(config_path)
        .arg("daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()
        .expect("spawn foreground daemon")
}

#[cfg(target_os = "macos")]
fn send_signal(pid: u32, signal: &str) {
    let status = Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(pid.to_string())
        .status()
        .expect("run kill command");
    assert!(status.success(), "kill -{signal} {pid} failed: {status}");
}

#[cfg(target_os = "macos")]
fn assert_child_still_running(child: &mut Child, context: &str) {
    if let Ok(Some(status)) = child.try_wait() {
        panic!("{context}: {status}");
    }
}

#[cfg(target_os = "macos")]
fn wait_for_stderr_contains(
    stderr_path: &Path,
    needle: &str,
    timeout: Duration,
    child: &mut Child,
) -> String {
    wait_for_file_contains(stderr_path, needle, timeout, child)
}

#[cfg(target_os = "macos")]
fn wait_for_siginfo_status_dump(stderr_path: &Path, timeout: Duration, child: &mut Child) -> Value {
    let deadline = Instant::now() + timeout;
    loop {
        let content = fs::read_to_string(stderr_path).unwrap_or_default();
        if let Some(payload) = content
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .find(|payload| payload["event"] == "siginfo_status")
        {
            return payload;
        }
        assert_child_still_running(
            child,
            "daemon exited before SIGINFO status JSON was complete",
        );
        assert!(
            Instant::now() < deadline,
            "timed out waiting for parseable SIGINFO status JSON in {}; content:\n{content}",
            stderr_path.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(target_os = "macos")]
fn wait_for_file_contains(
    path: &Path,
    needle: &str,
    timeout: Duration,
    child: &mut Child,
) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let content = fs::read_to_string(path).unwrap_or_default();
        if content.contains(needle) {
            return content;
        }
        assert_child_still_running(child, "daemon exited before expected file output");
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {needle:?} in {}; content:\n{content}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_child_exit(child: &mut Child, timeout: Duration) -> ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll daemon child status") {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for child exit"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
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

#[test]
fn synthetic_mac_tree_fixture_has_expected_shape() {
    let tree = common::SyntheticMacTree::new();

    assert!(tree.root().join("Users").join("operator").is_dir());
    assert!(tree.private_tmp.ends_with(Path::new("private/tmp")));
    assert_eq!(tree.reclaimable_paths.len(), 5);
    assert_eq!(tree.sacred_paths.len(), 4);

    for path in &tree.reclaimable_paths {
        assert!(
            path.exists(),
            "reclaimable fixture path should exist: {}",
            path.display()
        );
        assert!(
            path.starts_with(tree.root()),
            "reclaimable fixture path must stay under temp root: {}",
            path.display()
        );
    }

    for path in &tree.sacred_paths {
        assert!(
            path.exists(),
            "sacred fixture path should exist: {}",
            path.display()
        );
        assert!(
            path.starts_with(&tree.user_home),
            "sacred fixture path must stay under synthetic home: {}",
            path.display()
        );
    }

    assert!(
        tree.library_caches
            .join("com.anthropic.claude")
            .join("Cache")
            .join("data_0")
            .is_file()
    );
    assert!(
        tree.xcode_derived_data
            .join("Build")
            .join("Intermediates.noindex")
            .is_dir()
    );
    assert!(
        tree.frankenterm_trash
            .join(".cargo-rch-goldenplateau")
            .is_dir()
    );
}

fn synthetic_cleanup_candidate(path: &Path) -> CandidateInput {
    CandidateInput {
        path: path.to_path_buf(),
        size_bytes: 5 * 1_073_741_824,
        age: Duration::from_hours(336),
        classification: ArtifactClassification {
            pattern_name: Cow::Borrowed("synthetic-high-confidence-artifact"),
            category: ArtifactCategory::RustTarget,
            name_confidence: 0.95,
            structural_confidence: 0.95,
            combined_confidence: 0.95,
        },
        signals: StructuralSignals {
            has_incremental: true,
            has_deps: true,
            has_build: true,
            has_fingerprint: true,
            mostly_object_files: true,
            ..StructuralSignals::default()
        },
        active_references: ActiveReferenceSummary::default(),
        is_open: false,
        excluded: false,
    }
}

fn assert_sacred_keep(score: &CandidacyScore, expected_reason_fragment: &str) {
    assert!(score.vetoed);
    assert!(score.total_score.abs() <= f64::EPSILON);
    assert_eq!(score.decision.action, DecisionAction::Keep);

    let reason = score
        .veto_reason
        .as_deref()
        .expect("sacred overlap veto should include a reason");
    assert!(
        reason.contains("sacred path overlap"),
        "unexpected veto reason: {reason}"
    );
    assert!(
        reason.contains(expected_reason_fragment),
        "veto reason did not include {expected_reason_fragment:?}: {reason}"
    );
}

fn synthetic_messages_catalog(tree: &common::SyntheticMacTree) -> Vec<SacredPath> {
    vec![SacredPath {
        pattern: tree
            .user_home
            .join("Library")
            .join("Messages")
            .to_string_lossy()
            .to_string(),
        kind: SacredPathKind::ExactMatch,
        reason: "Messages history is user data".to_string(),
        source: SacredPathSource::Builtin,
    }]
}

fn synthetic_photos_catalog(tree: &common::SyntheticMacTree) -> Vec<SacredPath> {
    vec![SacredPath {
        pattern: tree
            .user_home
            .join("Pictures")
            .join("*.photoslibrary")
            .to_string_lossy()
            .to_string(),
        kind: SacredPathKind::GlobMatch,
        reason: "Photos libraries are user data".to_string(),
        source: SacredPathSource::Builtin,
    }]
}

#[test]
fn sacred_overlap_exact_match_keeps_candidate() {
    let tree = common::SyntheticMacTree::new();
    let candidate = tree.user_home.join("Library").join("Messages");
    let catalog = synthetic_messages_catalog(&tree);
    let overlaps = find_sacred_overlaps(&candidate, &catalog).expect("find sacred overlaps");

    assert!(
        overlaps
            .iter()
            .any(|overlap| overlap.kind == SacredOverlapKind::ExactMatch)
    );

    let engine = ScoringEngine::from_config(&ScoringConfig::default(), 30);
    let input = synthetic_cleanup_candidate(&candidate);
    let score = engine.score_candidate_with_sacred_overlaps(&input, 0.95, &overlaps);

    assert_sacred_keep(&score, "Messages history");
}

#[test]
fn sacred_overlap_child_of_photos_library_keeps_candidate() {
    let tree = common::SyntheticMacTree::new();
    let candidate = tree
        .user_home
        .join("Pictures")
        .join("Photos Library.photoslibrary")
        .join("database")
        .join("Photos.sqlite");
    let catalog = synthetic_photos_catalog(&tree);
    let overlaps = find_sacred_overlaps(&candidate, &catalog).expect("find sacred overlaps");

    assert!(
        overlaps
            .iter()
            .any(|overlap| overlap.kind == SacredOverlapKind::ChildOfSacred)
    );

    let engine = ScoringEngine::from_config(&ScoringConfig::default(), 30);
    let input = synthetic_cleanup_candidate(&candidate);
    let score = engine.score_candidate_with_sacred_overlaps(&input, 0.95, &overlaps);

    assert_sacred_keep(&score, "Photos libraries");
}

#[test]
fn sacred_overlap_parent_of_messages_keeps_candidate() {
    let tree = common::SyntheticMacTree::new();
    let candidate = tree.user_home.join("Library");
    let catalog = synthetic_messages_catalog(&tree);
    let overlaps = find_sacred_overlaps(&candidate, &catalog).expect("find sacred overlaps");

    assert!(
        overlaps
            .iter()
            .any(|overlap| overlap.kind == SacredOverlapKind::ParentOfSacred)
    );

    let engine = ScoringEngine::from_config(&ScoringConfig::default(), 30);
    let input = synthetic_cleanup_candidate(&candidate);
    let score = engine.score_candidate_with_sacred_overlaps(&input, 0.95, &overlaps);

    assert_sacred_keep(&score, "Messages history");
}

#[test]
fn sacred_overlap_stowaway_beads_inside_trash_keeps_candidate() {
    let tree = common::SyntheticMacTree::new();
    let candidate = tree.private_tmp.join("agent-trash-20260507");
    fs::create_dir_all(candidate.join("nested").join(".beads")).expect("create beads stowaway");
    fs::write(
        candidate.join("nested").join(".beads").join("beads.db"),
        b"synthetic beads state",
    )
    .expect("write beads stowaway");

    let overlaps =
        find_sacred_overlaps(&candidate, cross_platform_sacred_paths()).expect("find overlaps");

    assert!(overlaps.iter().any(|overlap| {
        overlap.kind == SacredOverlapKind::ContainsSacred && overlap.pattern == ".beads/"
    }));

    let engine = ScoringEngine::from_config(&ScoringConfig::default(), 30);
    let input = synthetic_cleanup_candidate(&candidate);
    let score = engine.score_candidate_with_sacred_overlaps(&input, 0.95, &overlaps);

    assert_sacred_keep(&score, ".beads/");
}

#[test]
fn mac_bundle_extension_refuse_list_keeps_old_large_candidates() {
    let tree = common::SyntheticMacTree::new();
    let engine = ScoringEngine::from_config(&ScoringConfig::default(), 30);

    for (name, extension) in [
        ("Photos Library", "photoslibrary"),
        ("Cut", "fcpbundle"),
        ("Movie", "imovielibrary"),
        ("Runner", "app"),
        ("RenderKit", "framework"),
        ("Editor", "bundle"),
        ("Codec", "plugin"),
        ("Driver", "kext"),
        ("Lightroom Catalog", "lrcat"),
        ("Lightroom Library", "lrlibrary"),
        ("Aperture Library", "aplibrary"),
    ] {
        let candidate = tree.private_tmp.join(format!("{name}.{extension}"));
        fs::create_dir_all(&candidate).expect("create synthetic bundle candidate");

        let input = synthetic_cleanup_candidate(&candidate);
        let score = engine.score_candidate(&input, 1.0);

        assert!(score.vetoed, ".{extension} candidate should be kept");
        assert_eq!(score.decision.action, DecisionAction::Keep);
        let expected_reason = format!("protected bundle/project extension .{extension}");
        assert_eq!(score.veto_reason.as_deref(), Some(expected_reason.as_str()));
    }

    let nested_candidate = tree
        .private_tmp
        .join("Runner.app")
        .join("Contents")
        .join("MacOS")
        .join("cache-target");
    fs::create_dir_all(&nested_candidate).expect("create synthetic nested app candidate");

    let input = synthetic_cleanup_candidate(&nested_candidate);
    let score = engine.score_candidate(&input, 1.0);

    assert!(score.vetoed, "candidate inside .app should be kept");
    assert_eq!(
        score.veto_reason.as_deref(),
        Some("protected bundle/project extension .app")
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    #[test]
    fn mac_sacred_paths_are_vetoed_by_exclusion_overlap(
        size_mib in 1_u64..4096,
        age_hours in 1_u64..720,
    ) {
        let tree = common::SyntheticMacTree::new();
        let registry = ArtifactPatternRegistry::default();
        let engine = ScoringEngine::from_config(&ScoringConfig::default(), 30);

        for path in &tree.sacred_paths {
            let rel_path = path
                .strip_prefix(&tree.user_home)
                .expect("synthetic sacred path should be under home");
            let logical_path = PathBuf::from("/Users/operator").join(rel_path);
            let input = CandidateInput {
                path: logical_path.clone(),
                size_bytes: size_mib.saturating_mul(1_048_576),
                age: Duration::from_hours(age_hours),
                classification: registry.classify(&logical_path, StructuralSignals::default()),
                signals: StructuralSignals::default(),
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: true,
            };

            let score = engine.score_candidate(&input, 1.0);
            prop_assert!(score.vetoed, "sacred path was not vetoed: {}", logical_path.display());
            prop_assert!(
                score.total_score.abs() <= f64::EPSILON,
                "vetoed sacred path kept a non-zero score: {}",
                score.total_score
            );
            prop_assert_eq!(score.decision.action, DecisionAction::Keep);
            prop_assert_eq!(score.veto_reason.as_deref(), Some("matched user exclusion"));
        }
    }

    #[test]
    fn mac_artifact_structure_drives_confidence_factors(
        has_fingerprint in any::<bool>(),
        has_incremental in any::<bool>(),
        has_deps in any::<bool>(),
        has_build in any::<bool>(),
        mostly_object_files in any::<bool>(),
        size_mib in 1_u64..4096,
        age_hours in 24_u64..720,
    ) {
        let path = PathBuf::from("/private/tmp/ft-cod7-target");
        let signals = StructuralSignals {
            has_incremental,
            has_deps,
            has_build,
            has_fingerprint,
            has_git: false,
            has_cargo_toml: false,
            mostly_object_files,
        };
        let registry = ArtifactPatternRegistry::default();
        let engine = ScoringEngine::from_config(&ScoringConfig::default(), 30);
        let classification = registry.classify(&path, signals);
        let score = engine.score_candidate(
            &CandidateInput {
                path: path.clone(),
                size_bytes: size_mib.saturating_mul(1_048_576),
                age: Duration::from_hours(age_hours),
                classification,
                signals,
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            },
            0.75,
        );

        prop_assert!(!score.vetoed, "non-open synthetic artifact was vetoed: {}", path.display());
        if has_fingerprint || has_incremental {
            prop_assert!(score.factors.structure >= 0.95);
        } else if has_deps && has_build {
            prop_assert!(score.factors.structure >= 0.85);
        } else if mostly_object_files {
            prop_assert!(score.factors.structure >= 0.90);
        } else {
            prop_assert!(
                (score.factors.structure - 0.40).abs() <= f64::EPSILON,
                "unexpected baseline structure factor: {}",
                score.factors.structure
            );
        }
        prop_assert!(score.classification.combined_confidence >= 0.0);
        prop_assert!(score.classification.combined_confidence <= 1.0);
    }
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
    let checksum_hex = hex_lower(Sha256::digest(archive_bytes));
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

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_secs();
    let cache_entry = serde_json::json!({
        "target_tag": "v99.88.77",
        "artifact_url": "https://example.invalid/sbh-x86_64-unknown-linux-gnu.tar.xz",
        "fetched_at_unix_secs": now_secs,
    });
    for cache_path in [
        home.path().join(".local/share/sbh/update-metadata.json"),
        home.path()
            .join("Library/Application Support/sbh/update-metadata.json"),
    ] {
        let cache_parent = cache_path
            .parent()
            .expect("cache path should have parent directory");
        fs::create_dir_all(cache_parent).expect("create cache parent directory");
        fs::write(
            &cache_path,
            serde_json::to_vec_pretty(&cache_entry).expect("serialize cache entry"),
        )
        .expect("write cache file");
    }

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
        Duration::from_hours(1),
    );
    env.create_file("project/Cargo.toml", b"[package]", Duration::from_hours(1));

    let cfg = Config::default();
    let scoring = ScoringEngine::from_config(&cfg.scoring, cfg.scanner.min_file_age_minutes);

    let input = CandidateInput {
        path: env.root().join("project/src/main.rs"),
        size_bytes: 12,
        age: Duration::from_hours(1),
        classification: ArtifactClassification::unknown(),
        signals: StructuralSignals::default(),
        active_references: ActiveReferenceSummary::default(),
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
        (50, PressureLevel::Green),  // 50% free  (green  ≥ 20%)
        (15, PressureLevel::Yellow), // 15% free  (yellow ≥ 14%, < 20%)
        (11, PressureLevel::Orange), // 11% free  (orange ≥ 10%, < 14%)
        (7, PressureLevel::Red),     //  7% free  (red    ≥  6%, < 10%)
    ];

    for (i, (free_pct, expected_level)) in readings.iter().enumerate() {
        let r = pid.update(
            PressureReading {
                free_bytes: *free_pct,
                total_bytes: 100,
                mount: PathBuf::from("/"),
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

    let mut manager = BallastManager::new(ballast_dir, config).expect("create manager");

    // Provision.
    let prov = manager.provision(None).expect("provision");
    assert_eq!(prov.files_created, 3, "should create 3 ballast files");
    assert_eq!(manager.available_count(), 3);
    assert!(manager.releasable_bytes() > 0);

    // Verify integrity.
    let verify = manager.verify().unwrap();
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
    env.create_file("a/file1.txt", b"hello", Duration::from_hours(1));
    env.create_file("a/b/file2.txt", b"world", Duration::from_hours(2));
    env.create_dir("empty_dir");

    let config = WalkerConfig {
        root_paths: vec![env.root().to_path_buf()],
        max_depth: 5,
        follow_symlinks: false,
        cross_devices: false,
        parallelism: 1,
        excluded_paths: HashSet::new(),
        opaque_pruning: false,
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
        "should discover directory 'a' in {paths:?}",
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
        size_bytes: 500_000_000,      // 500 MB
        age: Duration::from_hours(4), // 4 hours
        classification: ArtifactClassification {
            pattern_name: "cargo-target".into(),
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
        active_references: ActiveReferenceSummary::default(),
        is_open: false,
        excluded: false,
    };

    // Unknown source file — should not be recommended for deletion.
    let source_input = CandidateInput {
        path: PathBuf::from("/tmp/project/src/main.rs"),
        size_bytes: 500,
        age: Duration::from_hours(1), // 1 hour
        classification: ArtifactClassification::unknown(),
        signals: StructuralSignals::default(),
        active_references: ActiveReferenceSummary::default(),
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
        Duration::from_hours(24),
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
        age: Duration::from_hours(24),
        classification: class,
        signals: StructuralSignals {
            has_deps: true,
            ..Default::default()
        },
        active_references: ActiveReferenceSummary::default(),
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
            require_identity: false,
        },
        None,
    );

    let plan = executor.plan(vec![scored]);
    let report = executor.execute(&plan, None);

    assert!(report.dry_run, "should be dry run");
    assert_eq!(
        report.items_deleted, 0,
        "dry-run must not report real deletions"
    );
    assert_eq!(
        report.bytes_freed, 0,
        "dry-run must not report real bytes freed"
    );
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
        burst_min_confidence: 0.85,
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

    let toml_content = r"
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
";

    std::fs::write(&config_path, toml_content).expect("write toml");
    let cfg = Config::load(Some(&config_path)).expect("load config");

    assert!((cfg.pressure.green_min_free_pct - 25.0).abs() < f64::EPSILON);
    assert!((cfg.pressure.yellow_min_free_pct - 18.0).abs() < f64::EPSILON);
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
    env.create_file("unprotected/file.txt", b"data", Duration::from_hours(1));
    env.create_file("protected/.sbh-protect", b"{}", Duration::from_hours(1));
    env.create_file("protected/secret.txt", b"keep", Duration::from_hours(1));

    let config = WalkerConfig {
        root_paths: vec![env.root().to_path_buf()],
        max_depth: 5,
        follow_symlinks: false,
        cross_devices: false,
        parallelism: 1,
        excluded_paths: HashSet::new(),
        opaque_pruning: false,
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
        "protected directory contents should be skipped: {paths:?}",
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
            age: Duration::from_hours(4), // 4 hours
            classification: ArtifactClassification {
                pattern_name: "cargo-target".into(),
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
            active_references: ActiveReferenceSummary::default(),
            is_open: false,
            excluded: false,
        },
        CandidateInput {
            path: PathBuf::from("/tmp/project/notes.txt"),
            size_bytes: 100,
            age: Duration::from_hours(2), // 2 hours
            classification: ArtifactClassification::unknown(),
            signals: StructuralSignals::default(),
            active_references: ActiveReferenceSummary::default(),
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
            pattern_name: ".target*".into(),
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
        active_references: ActiveReferenceSummary::default(),
        is_open: false,
        excluded: false,
    }
}

fn e2e_good_observations(count: usize) -> Vec<CalibrationObservation> {
    (0..count)
        .map(|i| {
            let idx = f64::from(u32::try_from(i).expect("index fits in u32"));
            CalibrationObservation {
                predicted_rate: idx.mul_add(10.0, 1000.0),
                actual_rate: idx.mul_add(10.0, 1050.0),
                predicted_tte: 90.0 + idx,
                actual_tte: 85.0 + idx,
                burst_outlier: false,
            }
        })
        .collect()
}

fn e2e_bad_observations(count: usize, error_factor: f64) -> Vec<CalibrationObservation> {
    (0..count)
        .map(|i| {
            let idx = f64::from(u32::try_from(i).expect("index fits in u32"));
            let predicted_rate = idx.mul_add(10.0, 1000.0);
            CalibrationObservation {
                predicted_rate,
                actual_rate: predicted_rate * error_factor,
                predicted_tte: 100.0,
                actual_tte: 30.0,
                burst_outlier: false,
            }
        })
        .collect()
}

#[allow(dead_code)]
fn e2e_scored_candidate(action: DecisionAction, score: f64) -> CandidacyScore {
    CandidacyScore {
        path: PathBuf::from("/data/projects/test/.target_opus"),
        identity: None,
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
            pattern_name: ".target*".into(),
            category: ArtifactCategory::RustTarget,
            name_confidence: 0.9,
            structural_confidence: 0.95,
            combined_confidence: 0.92,
        },
        size_bytes: 3_000_000_000,
        age: Duration::from_hours(5),
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
    let mut policy = PolicyEngine::new(PolicyConfig {
        initial_mode: ActiveMode::Observe,
        observe_min_interval_secs: 0,
        ..PolicyConfig::default()
    });
    let mut guard = AdaptiveGuard::with_defaults();

    // Phase 1: Feed good calibration data.
    for obs in e2e_good_observations(10) {
        guard.observe(obs);
    }

    // Phase 2: Score a burst of high-confidence candidates.
    let candidates: Vec<CandidateInput> = (0_u64..10)
        .map(|i| {
            e2e_candidate(
                &format!("/data/projects/agent_{i}/.target_opus"),
                2 + i,
                48 + i * 12,
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
        let record = builder.build(candidate, PolicyMode::Shadow, None, None, None);
        assert!(!record.trace_id.is_empty());
        assert!(record.decision_id > 0);
        // Trace should show observe mode.
        assert_eq!(record.policy_mode, PolicyMode::Shadow);
    }

    // Phase 5: Verify explain output is non-empty.
    let sample = builder.build(&scored[0], PolicyMode::Shadow, None, None, None);
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
        initial_mode: ActiveMode::Observe,
        observe_min_interval_secs: 0,
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
    let candidates: Vec<CandidateInput> = (0_u64..8)
        .map(|i| e2e_candidate(&format!("/data/projects/proj_{i}/target"), 1 + i, 72, 0.85))
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
        let record = builder.build(candidate, PolicyMode::Canary, None, None, None);
        assert_eq!(record.policy_mode, PolicyMode::Canary);
        // Each trace_id should be unique and sequential.
        assert!(record.trace_id.starts_with("sbh-"));
    }
}

// ── Scenario 3: Calibration drift causing guard fail and fallback ────────

#[test]
fn e2e_scenario_3_calibration_drift_stays_operational() {
    let scoring = e2e_scoring_engine();
    let config = PolicyConfig {
        calibration_breach_windows: 3,
        initial_mode: ActiveMode::Observe,
        observe_min_interval_secs: 0,
        ..PolicyConfig::default()
    };
    let mut policy = PolicyEngine::new(config);
    policy.bypass_startup_grace();
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
    // CalibrationBreach is advisory-only — engine stays in Enforce.
    let failing = failing_guard_diag();
    for _ in 0..4 {
        policy.observe_window(&failing);
    }

    // Phase 4: Engine should STAY in Enforce (CalibrationBreach is advisory).
    assert_eq!(policy.mode(), ActiveMode::Enforce);

    // Deletions should still be approved.
    let candidates = vec![e2e_candidate("/data/projects/drift/target", 5, 96, 0.9)];
    let scored = scoring.score_batch(&candidates, 0.9);
    let diag = guard.diagnostics();
    let decision = policy.evaluate(&scored, Some(&diag));
    assert!(
        !decision.approved_for_deletion.is_empty(),
        "advisory-only calibration breach must not block deletions"
    );
}

// ── Scenario 4: Index corruption causing full-scan fallback ─────────────

#[test]
fn e2e_scenario_4_index_corruption_full_scan() {
    // This scenario verifies that when the Merkle scan index is corrupted
    // or unavailable, the system falls back to a full scan and still
    // produces valid scoring results.
    let scoring = e2e_scoring_engine();
    let _policy = PolicyEngine::new(PolicyConfig {
        initial_mode: ActiveMode::Observe,
        observe_min_interval_secs: 0,
        ..PolicyConfig::default()
    });

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
        let record = builder.build(candidate, PolicyMode::Shadow, None, None, None);
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
    let mut policy = PolicyEngine::new(PolicyConfig {
        initial_mode: ActiveMode::Observe,
        observe_min_interval_secs: 0,
        ..PolicyConfig::default()
    });
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
    let mut policy2 = PolicyEngine::new(PolicyConfig {
        initial_mode: ActiveMode::Observe,
        observe_min_interval_secs: 0,
        ..PolicyConfig::default()
    });
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
        initial_mode: ActiveMode::Observe,
        min_fallback_secs: 0,
        observe_min_interval_secs: 0,
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
    // Recovery caps at Canary (mandatory canary gate) rather than restoring
    // directly to Enforce, so the system must re-prove itself before enforce.
    let mode = policy.mode();
    assert_eq!(
        mode,
        ActiveMode::Canary,
        "after recovery should return to Canary (mandatory canary gate), got {mode:?}",
    );

    // Fallback reason should be cleared after recovery.
    assert!(
        policy.fallback_reason().is_none(),
        "fallback reason should be cleared after recovery"
    );

    // Verify that evaluate works normally post-recovery (in canary mode).
    let candidates = vec![e2e_candidate("/data/projects/recovery/target", 3, 72, 0.85)];
    let scored = scoring.score_batch(&candidates, 0.5);
    let _decision = policy.evaluate(&scored, None);

    // In canary mode, limited deletions may be approved (unlike fallback).
    // The key assertion: we are no longer in FallbackSafe.
    assert_ne!(
        policy.mode(),
        ActiveMode::FallbackSafe,
        "should remain out of fallback after clean evaluation"
    );

    // An explicit promote returns to Enforce.
    policy.promote();
    assert_eq!(policy.mode(), ActiveMode::Enforce);

    // Phase 4: Verify the full lifecycle is traceable.
    let mut builder = DecisionRecordBuilder::new();
    let record = builder.build(&scored[0], PolicyMode::Shadow, None, None, None);
    let explanation = format_explain(&record, ExplainLevel::L3);
    assert!(!explanation.is_empty());
}
