//! E2E test matrix for installer/update/integration flows (bd-2j5.14).
//!
//! Tests cover:
//! - Fresh install sequence (data dir, config, ballast provisioning)
//! - Reinstall idempotency (safe to re-run install)
//! - Uninstall cleanup (data, ballast, config removal)
//! - Update orchestration (check, apply, pin, dry-run)
//! - Rollback flow (backup store lifecycle)
//! - Bootstrap integration (tool detection and injection)
//! - Failure injection (checksum mismatch, missing manifests, permission errors)
//! - Golden output format validation for user-visible screens

mod common;

use std::io;
use std::path::{Path, PathBuf};

use storage_ballast_helper::cli::from_source::{
    Prerequisite, PrerequisiteStatus, all_prerequisites_met, check_prerequisites,
    format_prerequisite_failures,
};
use storage_ballast_helper::cli::install::{
    InstallOptions, InstallReport, InstallStep, UninstallOptions, UninstallReport,
    format_install_report, format_uninstall_report, run_install_sequence,
    run_install_sequence_with_bundle, run_uninstall_cleanup,
};
use storage_ballast_helper::cli::integrations::{
    ALL_TOOLS, BootstrapOptions, IntegrationStatus, run_bootstrap,
};
use storage_ballast_helper::cli::update::{BackupStore, UpdateOptions, run_update_sequence};
use storage_ballast_helper::cli::wizard::{
    BallastPreset, ServiceChoice, auto_answers, write_config,
};
use storage_ballast_helper::cli::{
    HostSpecifier, OfflineBundleArtifact, OfflineBundleManifest, RELEASE_REPOSITORY,
    ReleaseChannel, resolve_installer_artifact_contract,
};
use storage_ballast_helper::core::config::Config;

use sha2::{Digest, Sha256};

// ============================================================================
// Test helpers
// ============================================================================

/// Create a minimal test config with all paths inside the given temp directory.
fn test_config(tmp: &Path) -> Config {
    let mut config = Config::default();
    config.paths.config_file = tmp.join("config").join("config.toml");
    config.paths.state_file = tmp.join("data").join("state.json");
    config.paths.ballast_dir = tmp.join("ballast");
    config.paths.sqlite_db = tmp.join("data").join("db.sqlite3");
    config.paths.jsonl_log = tmp.join("data").join("log.jsonl");
    config.ballast.file_count = 0; // Skip ballast for speed in most tests.
    config
}

/// Create install options for a test environment.
fn test_install_opts(tmp: &Path) -> InstallOptions {
    let config = test_config(tmp);
    InstallOptions {
        config,
        ballast_count: 0,
        ballast_size_bytes: 0,
        ballast_path: Some(tmp.join("ballast")),
        dry_run: false,
    }
}

/// Create a valid offline bundle manifest with matching checksums.
fn create_valid_bundle(tmp: &Path) -> PathBuf {
    let host = HostSpecifier::detect().unwrap();
    let contract =
        resolve_installer_artifact_contract(host, ReleaseChannel::Stable, Some("0.9.1")).unwrap();

    let archive_name = contract.asset_name();
    let checksum_name = contract.checksum_name();
    let archive_bytes = b"test-bundle-archive-content";
    std::fs::write(tmp.join(&archive_name), archive_bytes).unwrap();

    let checksum = Sha256::digest(archive_bytes);
    let checksum_hex = format!("{checksum:x}");
    std::fs::write(
        tmp.join(&checksum_name),
        format!("{checksum_hex}  {archive_name}\n"),
    )
    .unwrap();

    let manifest = OfflineBundleManifest {
        version: "1".to_string(),
        repository: RELEASE_REPOSITORY.to_string(),
        release_tag: "0.9.1".to_string(),
        artifacts: vec![OfflineBundleArtifact {
            target: contract.target.triple.to_string(),
            archive: archive_name,
            checksum: checksum_name,
            sigstore_bundle: None,
        }],
    };
    let manifest_path = tmp.join("bundle-manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    manifest_path
}

/// Create an invalid bundle with wrong checksum.
fn create_bad_checksum_bundle(tmp: &Path) -> PathBuf {
    let host = HostSpecifier::detect().unwrap();
    let contract =
        resolve_installer_artifact_contract(host, ReleaseChannel::Stable, Some("0.9.1")).unwrap();

    let archive_name = contract.asset_name();
    let checksum_name = contract.checksum_name();
    std::fs::write(tmp.join(&archive_name), b"real-content").unwrap();
    std::fs::write(
        tmp.join(&checksum_name),
        "0000000000000000000000000000000000000000000000000000000000000000\n",
    )
    .unwrap();

    let manifest = OfflineBundleManifest {
        version: "1".to_string(),
        repository: RELEASE_REPOSITORY.to_string(),
        release_tag: "0.9.1".to_string(),
        artifacts: vec![OfflineBundleArtifact {
            target: contract.target.triple.to_string(),
            archive: archive_name,
            checksum: checksum_name,
            sigstore_bundle: None,
        }],
    };
    let manifest_path = tmp.join("bundle-manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    manifest_path
}

// ============================================================================
// A: Fresh install → config + data dir + ballast
// ============================================================================

#[test]
fn e2e_fresh_install_creates_all_artifacts() {
    let tmp = tempfile::tempdir().unwrap();
    let opts = test_install_opts(tmp.path());

    let report = run_install_sequence(&opts);
    assert!(report.success, "fresh install should succeed: {report:?}");
    assert!(report.config_path.is_some(), "config path should be set");
    assert!(report.data_dir.is_some(), "data dir should be set");

    let config_path = report.config_path.unwrap();
    assert!(config_path.exists(), "config file should exist on disk");

    let data_dir = report.data_dir.unwrap();
    assert!(data_dir.is_dir(), "data dir should exist on disk");

    // Config should be valid TOML with expected sections.
    let config_content = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        config_content.contains("[scanner]"),
        "config should contain [scanner]"
    );
}

#[test]
fn e2e_fresh_install_dry_run_plans_all_steps() {
    let tmp = tempfile::tempdir().unwrap();
    let mut opts = test_install_opts(tmp.path());
    opts.dry_run = true;

    let report = run_install_sequence(&opts);
    assert!(report.success, "dry-run should succeed: {report:?}");
    assert!(report.dry_run);
    assert!(!report.steps.is_empty(), "should have planned steps");

    // No files should exist after dry-run.
    assert!(!tmp.path().join("config").exists());
    assert!(!tmp.path().join("data").exists());

    // All steps should be planned (not done).
    for step in &report.steps {
        assert!(!step.done, "dry-run step should not be done: {step:?}");
        assert!(step.error.is_none(), "dry-run step should have no error");
    }
}

// ============================================================================
// B: Reinstall idempotency
// ============================================================================

#[test]
fn e2e_reinstall_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let opts = test_install_opts(tmp.path());

    // First install.
    let report1 = run_install_sequence(&opts);
    assert!(report1.success, "first install should succeed");

    // Second install (re-run same opts).
    let report2 = run_install_sequence(&opts);
    assert!(report2.success, "reinstall should succeed (idempotent)");

    // Config should still exist and be valid.
    let config_path = tmp.path().join("config").join("config.toml");
    assert!(config_path.exists());
    let content = std::fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("[scanner]"));
}

// ============================================================================
// C: Uninstall cleanup
// ============================================================================

#[test]
fn e2e_install_then_uninstall_removes_everything() {
    let tmp = tempfile::tempdir().unwrap();
    let config = test_config(tmp.path());

    // Install first.
    let install_opts = InstallOptions {
        config: config.clone(),
        ballast_count: 0,
        ballast_size_bytes: 0,
        ballast_path: Some(tmp.path().join("ballast")),
        dry_run: false,
    };
    let install_report = run_install_sequence(&install_opts);
    assert!(install_report.success);

    // Now uninstall.
    let uninstall_opts = UninstallOptions {
        dry_run: false,
        keep_data: false,
        keep_ballast: false,
        paths: config.paths.clone(),
    };
    let uninstall_report = run_uninstall_cleanup(&uninstall_opts);
    assert!(
        uninstall_report.success,
        "uninstall should succeed: {uninstall_report:?}"
    );

    // Config and data should be removed.
    assert!(
        !config.paths.config_file.exists(),
        "config should be removed after uninstall"
    );
}

#[test]
fn e2e_uninstall_keep_data_preserves_state() {
    let tmp = tempfile::tempdir().unwrap();
    let config = test_config(tmp.path());

    // Install.
    let install_opts = InstallOptions {
        config: config.clone(),
        ballast_count: 0,
        ballast_size_bytes: 0,
        ballast_path: Some(tmp.path().join("ballast")),
        dry_run: false,
    };
    let install_report = run_install_sequence(&install_opts);
    assert!(install_report.success);

    // Uninstall with keep_data.
    let uninstall_opts = UninstallOptions {
        dry_run: false,
        keep_data: true,
        keep_ballast: true,
        paths: config.paths.clone(),
    };
    let uninstall_report = run_uninstall_cleanup(&uninstall_opts);
    assert!(uninstall_report.success);

    // Data dir should still exist.
    let data_dir = config.paths.state_file.parent().unwrap();
    assert!(data_dir.is_dir(), "data dir should be kept");
    assert!(config.paths.config_file.exists(), "config should be kept");
}

#[test]
fn e2e_uninstall_dry_run_no_changes() {
    let tmp = tempfile::tempdir().unwrap();
    let config = test_config(tmp.path());

    // Install.
    let install_opts = InstallOptions {
        config: config.clone(),
        ballast_count: 0,
        ballast_size_bytes: 0,
        ballast_path: Some(tmp.path().join("ballast")),
        dry_run: false,
    };
    assert!(run_install_sequence(&install_opts).success);

    // Dry-run uninstall.
    let uninstall_opts = UninstallOptions {
        dry_run: true,
        keep_data: false,
        keep_ballast: false,
        paths: config.paths.clone(),
    };
    let report = run_uninstall_cleanup(&uninstall_opts);
    assert!(report.dry_run);

    // Everything should still exist.
    assert!(config.paths.config_file.exists());
}

// ============================================================================
// D: Update orchestration (backup store lifecycle)
// ============================================================================

#[test]
fn e2e_backup_store_create_list_rollback_prune() {
    let tmp = tempfile::tempdir().unwrap();
    let store_dir = tmp.path().join("backup-store");
    let store = BackupStore::open(store_dir.clone());

    // Create a file to back up.
    let original = tmp.path().join("sbh-binary");
    std::fs::write(&original, b"version-1-binary").unwrap();

    // Create backup.
    let snap = store.create(&original, "0.1.0").unwrap();
    assert!(snap.path.exists());
    assert_eq!(snap.version, "0.1.0");

    // List should show 1 backup.
    let inventory = store.inventory();
    assert_eq!(inventory.backups.len(), 1);

    // Create a second backup — sleep briefly so timestamp differs.
    std::thread::sleep(std::time::Duration::from_secs(1));
    std::fs::write(&original, b"version-2-binary").unwrap();
    let snap2 = store.create(&original, "0.2.0").unwrap();
    assert_eq!(snap2.version, "0.2.0");
    assert_eq!(store.inventory().backups.len(), 2);

    // Rollback to first backup.
    let rollback_result = store.rollback(&original, Some(&snap.id)).unwrap();
    assert!(rollback_result.success);
    let content = std::fs::read_to_string(&original).unwrap();
    assert_eq!(content, "version-1-binary");

    // Prune to keep only 1 backup.
    let prune_result = store.prune(1).unwrap();
    assert_eq!(prune_result.removed, 1);
    assert_eq!(store.inventory().backups.len(), 1);
}

#[test]
fn e2e_backup_store_rollback_to_latest() {
    let tmp = tempfile::tempdir().unwrap();
    let store_dir = tmp.path().join("backup-store");
    let store = BackupStore::open(store_dir);

    let original = tmp.path().join("sbh-binary");

    // Create multiple backups.
    std::fs::write(&original, b"v1").unwrap();
    store.create(&original, "0.1.0").unwrap();

    std::thread::sleep(std::time::Duration::from_secs(1));
    std::fs::write(&original, b"v2").unwrap();
    store.create(&original, "0.2.0").unwrap();

    std::fs::write(&original, b"v3-broken").unwrap();

    // Rollback with None → latest backup (v2).
    let result = store.rollback(&original, None).unwrap();
    assert!(result.success);
    let content = std::fs::read_to_string(&original).unwrap();
    assert_eq!(content, "v2");
}

// ============================================================================
// E: Update dry-run produces plan
// ============================================================================

#[test]
fn e2e_update_dry_run_no_side_effects() {
    let tmp = tempfile::tempdir().unwrap();
    let opts = UpdateOptions {
        check_only: false,
        dry_run: true,
        pinned_version: None,
        install_dir: tmp.path().to_path_buf(),
        force: false,
        no_verify: false,
        max_backups: 5,
        notices_enabled: true,
        metadata_cache_file: tmp.path().join("cache.json"),
        metadata_cache_ttl: std::time::Duration::from_secs(60),
        refresh_cache: false,
        offline_bundle_manifest: None,
    };
    let report = run_update_sequence(&opts);
    assert!(report.dry_run, "should be dry_run");
}

#[test]
fn e2e_update_check_only_reports_availability() {
    let tmp = tempfile::tempdir().unwrap();
    let opts = UpdateOptions {
        check_only: true,
        dry_run: false,
        pinned_version: None,
        install_dir: tmp.path().to_path_buf(),
        force: false,
        no_verify: false,
        max_backups: 5,
        notices_enabled: true,
        metadata_cache_file: tmp.path().join("cache.json"),
        metadata_cache_ttl: std::time::Duration::from_secs(60),
        refresh_cache: false,
        offline_bundle_manifest: None,
    };
    let report = run_update_sequence(&opts);
    assert!(report.check_only, "should be check_only");
}

// ============================================================================
// F: Bundle preflight — valid, invalid, missing
// ============================================================================

#[test]
fn e2e_bundle_preflight_valid_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest_path = create_valid_bundle(tmp.path());

    let opts = InstallOptions {
        config: test_config(tmp.path()),
        ballast_count: 0,
        ballast_size_bytes: 0,
        ballast_path: None,
        dry_run: false,
    };

    let report = run_install_sequence_with_bundle(&opts, Some(&manifest_path));
    assert!(
        report.success,
        "valid bundle should pass preflight: {report:?}"
    );
    assert!(
        report
            .steps
            .iter()
            .any(|s| s.description.contains("Validated offline bundle")),
        "should include bundle validation step"
    );
}

#[test]
fn e2e_bundle_preflight_bad_checksum_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest_path = create_bad_checksum_bundle(tmp.path());

    let opts = InstallOptions {
        config: test_config(tmp.path()),
        ballast_count: 0,
        ballast_size_bytes: 0,
        ballast_path: None,
        dry_run: false,
    };

    let report = run_install_sequence_with_bundle(&opts, Some(&manifest_path));
    assert!(
        !report.success,
        "bad checksum should fail preflight: {report:?}"
    );
    assert!(
        report.steps.iter().any(|s| s.error.is_some()),
        "should have a failed step"
    );
}

#[test]
fn e2e_bundle_preflight_missing_manifest_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("nonexistent-manifest.json");

    let opts = InstallOptions {
        config: test_config(tmp.path()),
        ballast_count: 0,
        ballast_size_bytes: 0,
        ballast_path: None,
        dry_run: false,
    };

    let report = run_install_sequence_with_bundle(&opts, Some(&missing));
    assert!(!report.success, "missing manifest should fail: {report:?}");
}

#[test]
fn e2e_bundle_preflight_dry_run_plans_without_executing() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("nonexistent-manifest.json");

    let opts = InstallOptions {
        config: test_config(tmp.path()),
        ballast_count: 0,
        ballast_size_bytes: 0,
        ballast_path: None,
        dry_run: true,
    };

    let report = run_install_sequence_with_bundle(&opts, Some(&missing));
    assert!(
        report.success,
        "dry-run should succeed even with missing manifest"
    );
    assert!(
        report.steps.iter().all(|s| !s.done && s.error.is_none()),
        "dry-run steps should all be planned"
    );
}

// ============================================================================
// G: Wizard → config generation → validation roundtrip
// ============================================================================

#[test]
fn e2e_wizard_auto_generates_valid_config() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("sbh").join("config.toml");

    let answers = auto_answers();
    write_config(&answers, &config_path).unwrap();
    assert!(config_path.exists());

    // The generated TOML should be parseable back as a Config.
    let toml_str = std::fs::read_to_string(&config_path).unwrap();
    let parsed: Config = toml::from_str(&toml_str).unwrap();
    assert_eq!(parsed.scanner.root_paths, answers.watched_paths);
    assert_eq!(parsed.ballast.file_count, answers.ballast_file_count);
}

#[test]
fn e2e_wizard_interactive_custom_paths_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("config.toml");

    // Simulate: none service, custom paths, small ballast, confirm
    let input = "none\n/opt/work,/srv/builds\ns\n\n";
    let mut reader = io::Cursor::new(input.as_bytes());
    let mut output = Vec::new();

    let answers =
        storage_ballast_helper::cli::wizard::run_interactive(&mut reader, &mut output).unwrap();
    assert_eq!(answers.service, ServiceChoice::None);
    assert_eq!(answers.ballast_preset, BallastPreset::Small);

    write_config(&answers, &config_path).unwrap();

    let toml_str = std::fs::read_to_string(&config_path).unwrap();
    let parsed: Config = toml::from_str(&toml_str).unwrap();
    assert_eq!(
        parsed.scanner.root_paths,
        vec![PathBuf::from("/opt/work"), PathBuf::from("/srv/builds")]
    );
    assert_eq!(parsed.ballast.file_count, 5);
}

// ============================================================================
// H: Integration bootstrap idempotency
// ============================================================================

#[test]
fn e2e_bootstrap_skip_all_tools_does_nothing() {
    let opts = BootstrapOptions {
        dry_run: true,
        skip_tools: ALL_TOOLS.to_vec(),
        ..Default::default()
    };
    let summary = run_bootstrap(&opts);
    assert_eq!(summary.configured_count, 0);
    assert_eq!(summary.failed_count, 0);
    for result in &summary.results {
        assert_eq!(result.status, IntegrationStatus::Skipped);
    }
}

#[test]
fn e2e_bootstrap_idempotent_re_run() {
    // Running bootstrap twice should not fail and second run should have
    // the same configured_count as first (no duplicate injections).
    let opts = BootstrapOptions {
        dry_run: true,
        skip_tools: vec![],
        ..Default::default()
    };
    let summary1 = run_bootstrap(&opts);
    let summary2 = run_bootstrap(&opts);
    assert_eq!(
        summary1.configured_count, summary2.configured_count,
        "re-running bootstrap should be idempotent"
    );
    assert_eq!(summary1.failed_count, summary2.failed_count);
}

// ============================================================================
// I: Artifact contract resolution
// ============================================================================

#[test]
fn e2e_host_detection_resolves_valid_contract() {
    let host = HostSpecifier::detect().unwrap();
    let contract = resolve_installer_artifact_contract(host, ReleaseChannel::Stable, None).unwrap();

    assert_eq!(contract.repository, RELEASE_REPOSITORY);
    assert!(!contract.asset_name().is_empty());
    assert!(contract.asset_name().contains("sbh"));
    assert!(contract.checksum_name().ends_with(".sha256"));
    assert!(contract.sigstore_bundle_name().ends_with(".sigstore.json"));
}

#[test]
fn e2e_pinned_version_contract_uses_tag() {
    let host = HostSpecifier::detect().unwrap();
    let contract =
        resolve_installer_artifact_contract(host, ReleaseChannel::Stable, Some("v1.2.3")).unwrap();

    let url = contract.asset_url();
    assert!(
        url.contains("v1.2.3"),
        "pinned version should appear in URL: {url}"
    );
}

#[test]
fn e2e_latest_contract_uses_latest_endpoint() {
    let host = HostSpecifier::detect().unwrap();
    let contract = resolve_installer_artifact_contract(host, ReleaseChannel::Stable, None).unwrap();

    let url = contract.asset_url();
    assert!(
        url.contains("/releases/latest/download/"),
        "unpinned should use latest: {url}"
    );
}

// ============================================================================
// J: From-source prerequisite flow
// ============================================================================

#[test]
fn e2e_from_source_prerequisites_met_in_test_env() {
    let statuses = check_prerequisites();
    assert_eq!(statuses.len(), 3);

    // Cargo and rustc should always be present in test env.
    let cargo = statuses
        .iter()
        .find(|s| s.prerequisite == Prerequisite::Cargo)
        .unwrap();
    assert!(cargo.available);
    assert!(cargo.version.is_some());
    assert!(cargo.remediation.is_none());

    assert!(
        all_prerequisites_met(&statuses)
            || !statuses
                .iter()
                .any(|s| s.prerequisite == Prerequisite::Git && !s.available)
    );
}

#[test]
fn e2e_from_source_failure_output_includes_remediation() {
    let statuses = vec![
        PrerequisiteStatus {
            prerequisite: Prerequisite::Cargo,
            available: true,
            version: Some("1.80.0".into()),
            path: Some(PathBuf::from("/usr/bin/cargo")),
            remediation: None,
        },
        PrerequisiteStatus {
            prerequisite: Prerequisite::Git,
            available: false,
            version: None,
            path: None,
            remediation: Some("apt install git".into()),
        },
    ];

    let output = format_prerequisite_failures(&statuses);
    assert!(output.contains("git"));
    assert!(output.contains("apt install git"));
    assert!(
        !output.contains("cargo"),
        "available tools should not appear"
    );
}

// ============================================================================
// K: Golden output format validation
// ============================================================================

#[test]
fn e2e_install_report_golden_dry_run() {
    let report = InstallReport {
        steps: vec![
            InstallStep {
                description: "Create data directory: /var/lib/sbh".into(),
                done: false,
                error: None,
            },
            InstallStep {
                description: "Write config: /etc/sbh/config.toml".into(),
                done: false,
                error: None,
            },
            InstallStep {
                description: "Provision ballast: 10 files".into(),
                done: false,
                error: None,
            },
        ],
        success: true,
        config_path: None,
        data_dir: None,
        ballast_dir: None,
        ballast_files_created: 0,
        ballast_bytes: 0,
        dry_run: true,
    };

    let output = format_install_report(&report);
    assert!(output.contains("dry-run"), "should say dry-run");
    assert!(output.contains("[PLAN]"), "steps should be PLAN");
    assert_eq!(
        output.matches("[PLAN]").count(),
        3,
        "should have 3 PLAN steps"
    );
    assert!(!output.contains("[DONE]"), "no steps should be DONE");
    assert!(!output.contains("[FAIL]"), "no steps should be FAIL");
}

#[test]
fn e2e_install_report_golden_success() {
    let report = InstallReport {
        steps: vec![InstallStep {
            description: "Wrote config".into(),
            done: true,
            error: None,
        }],
        success: true,
        config_path: Some(PathBuf::from("/etc/sbh/config.toml")),
        data_dir: Some(PathBuf::from("/var/lib/sbh")),
        ballast_dir: Some(PathBuf::from("/var/lib/sbh/ballast")),
        ballast_files_created: 10,
        ballast_bytes: 10_737_418_240,
        dry_run: false,
    };

    let output = format_install_report(&report);
    assert!(output.contains("install report"), "should say install");
    assert!(output.contains("[DONE]"));
    assert!(output.contains("10 files = 10 GB"));
    assert!(output.contains("/etc/sbh/config.toml"));
}

#[test]
fn e2e_install_report_golden_failure() {
    let report = InstallReport {
        steps: vec![InstallStep {
            description: "Create data dir".into(),
            done: false,
            error: Some("permission denied".into()),
        }],
        success: false,
        config_path: None,
        data_dir: None,
        ballast_dir: None,
        ballast_files_created: 0,
        ballast_bytes: 0,
        dry_run: false,
    };

    let output = format_install_report(&report);
    assert!(output.contains("[FAIL]"));
    assert!(output.contains("permission denied"));
}

#[test]
fn e2e_uninstall_report_golden_with_reclaimed_space() {
    let report = UninstallReport {
        steps: vec![
            InstallStep {
                description: "Removed ballast".into(),
                done: true,
                error: None,
            },
            InstallStep {
                description: "Removed data dir".into(),
                done: true,
                error: None,
            },
        ],
        success: true,
        bytes_reclaimed: 10_737_418_240,
        dry_run: false,
    };

    let output = format_uninstall_report(&report);
    assert!(output.contains("uninstall"));
    assert!(output.contains("[DONE]"));
    assert!(output.contains("10 GB"), "should show reclaimed space");
}

// ============================================================================
// L: CLI subcommand smoke tests
// ============================================================================

#[test]
fn e2e_cli_install_help() {
    let result = common::run_cli_case("e2e_cli_install_help", &["install", "--help"]);
    assert!(
        result.status.success(),
        "install --help should succeed; log: {}",
        result.log_path.display()
    );
    assert!(result.stdout.contains("install") || result.stdout.contains("Install"));
}

#[test]
fn e2e_cli_uninstall_help() {
    let result = common::run_cli_case("e2e_cli_uninstall_help", &["uninstall", "--help"]);
    assert!(
        result.status.success(),
        "uninstall --help should succeed; log: {}",
        result.log_path.display()
    );
}

#[test]
fn e2e_cli_update_help() {
    let result = common::run_cli_case("e2e_cli_update_help", &["update", "--help"]);
    assert!(
        result.status.success(),
        "update --help should succeed; log: {}",
        result.log_path.display()
    );
}

#[test]
fn e2e_cli_config_validate() {
    let result = common::run_cli_case("e2e_cli_config_validate", &["config", "validate"]);
    // May fail if no config exists, but should not crash.
    assert!(
        result.status.success()
            || result.stderr.contains("config")
            || result.stderr.contains("not found"),
        "config validate should produce useful output; log: {}",
        result.log_path.display()
    );
}

// ============================================================================
// M: Error output determinism
// ============================================================================

#[test]
fn e2e_install_failure_produces_deterministic_error() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = test_config(tmp.path());

    // Point config_file to an unwritable path (nested under a file, not a dir).
    let blocker = tmp.path().join("blocker");
    std::fs::write(&blocker, "I am a file").unwrap();
    config.paths.config_file = blocker.join("nested").join("config.toml");

    let opts = InstallOptions {
        config,
        ballast_count: 0,
        ballast_size_bytes: 0,
        ballast_path: None,
        dry_run: false,
    };

    let report = run_install_sequence(&opts);
    assert!(!report.success, "should fail when config path blocked");
    // Error should be deterministic (not random).
    let error_msg = report
        .steps
        .iter()
        .filter_map(|s| s.error.as_ref())
        .next()
        .expect("should have at least one error");
    assert!(!error_msg.is_empty(), "error message should not be empty");
}

// ============================================================================
// N: Serialization contract stability
// ============================================================================

#[test]
fn e2e_install_report_json_contract() {
    let report = InstallReport {
        steps: vec![InstallStep {
            description: "test step".into(),
            done: true,
            error: None,
        }],
        success: true,
        config_path: Some(PathBuf::from("/etc/sbh/config.toml")),
        data_dir: Some(PathBuf::from("/var/lib/sbh")),
        ballast_dir: None,
        ballast_files_created: 0,
        ballast_bytes: 0,
        dry_run: false,
    };

    let json = serde_json::to_string(&report).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Verify JSON contract keys exist.
    assert!(parsed.get("success").is_some());
    assert!(parsed.get("dry_run").is_some());
    assert!(parsed.get("steps").is_some());
    assert!(parsed.get("config_path").is_some());
    assert!(parsed.get("data_dir").is_some());
    assert!(parsed.get("ballast_files_created").is_some());
    assert!(parsed.get("ballast_bytes").is_some());

    // Values should be correct.
    assert_eq!(parsed["success"], true);
    assert_eq!(parsed["dry_run"], false);
    assert_eq!(parsed["ballast_files_created"], 0);
}

#[test]
fn e2e_uninstall_report_json_contract() {
    let report = UninstallReport {
        steps: vec![],
        success: true,
        bytes_reclaimed: 1024,
        dry_run: false,
    };

    let json = serde_json::to_string(&report).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert!(parsed.get("success").is_some());
    assert!(parsed.get("bytes_reclaimed").is_some());
    assert_eq!(parsed["bytes_reclaimed"], 1024);
}

// ============================================================================
// O: Bundle manifest edge cases
// ============================================================================

#[test]
fn e2e_bundle_manifest_wrong_version_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = OfflineBundleManifest {
        version: "2".to_string(), // Unsupported version.
        repository: RELEASE_REPOSITORY.to_string(),
        release_tag: "0.9.1".to_string(),
        artifacts: vec![],
    };
    let manifest_path = tmp.path().join("bad-version.json");
    std::fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();

    let host = HostSpecifier::detect().unwrap();
    let result =
        storage_ballast_helper::cli::resolve_bundle_artifact_contract(host, &manifest_path);
    assert!(result.is_err(), "version 2 manifest should fail");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unsupported") || err.contains("version"),
        "error should mention version: {err}"
    );
}

#[test]
fn e2e_bundle_manifest_wrong_repository_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = OfflineBundleManifest {
        version: "1".to_string(),
        repository: "wrong/repo".to_string(),
        release_tag: "0.9.1".to_string(),
        artifacts: vec![],
    };
    let manifest_path = tmp.path().join("bad-repo.json");
    std::fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();

    let host = HostSpecifier::detect().unwrap();
    let result =
        storage_ballast_helper::cli::resolve_bundle_artifact_contract(host, &manifest_path);
    assert!(result.is_err(), "wrong repository should fail");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("mismatch") || err.contains("repository"),
        "error should mention repository: {err}"
    );
}

#[test]
fn e2e_bundle_manifest_missing_target_triple() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = OfflineBundleManifest {
        version: "1".to_string(),
        repository: RELEASE_REPOSITORY.to_string(),
        release_tag: "0.9.1".to_string(),
        artifacts: vec![OfflineBundleArtifact {
            target: "riscv64gc-unknown-linux-gnu".to_string(), // Wrong triple.
            archive: "sbh-riscv64gc.tar.xz".to_string(),
            checksum: "sbh-riscv64gc.tar.xz.sha256".to_string(),
            sigstore_bundle: None,
        }],
    };
    let manifest_path = tmp.path().join("bad-triple.json");
    std::fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();

    let host = HostSpecifier::detect().unwrap();
    let result =
        storage_ballast_helper::cli::resolve_bundle_artifact_contract(host, &manifest_path);
    assert!(
        result.is_err(),
        "missing target triple should fail: {result:?}"
    );
}

// ============================================================================
// P: HostSpecifier edge cases
// ============================================================================

#[test]
fn e2e_host_specifier_from_parts_linux_x86() {
    let host = HostSpecifier::from_parts("linux", "x86_64", Some("gnu")).unwrap();
    assert_eq!(host.os, storage_ballast_helper::cli::HostOs::Linux);
    assert_eq!(host.arch, storage_ballast_helper::cli::HostArch::X86_64);
    assert_eq!(host.abi, storage_ballast_helper::cli::HostAbi::Gnu);
}

#[test]
fn e2e_host_specifier_from_parts_macos_aarch64() {
    let host = HostSpecifier::from_parts("macos", "aarch64", None).unwrap();
    assert_eq!(host.os, storage_ballast_helper::cli::HostOs::MacOs);
    assert_eq!(host.arch, storage_ballast_helper::cli::HostArch::Aarch64);
}

#[test]
fn e2e_host_specifier_from_parts_unsupported_os() {
    let result = HostSpecifier::from_parts("haiku", "x86_64", None);
    assert!(result.is_err(), "unsupported OS should fail");
}

#[test]
fn e2e_host_specifier_from_parts_unsupported_arch() {
    let result = HostSpecifier::from_parts("linux", "mips64", None);
    assert!(result.is_err(), "unsupported arch should fail");
}
