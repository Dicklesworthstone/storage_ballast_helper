//! E2E test matrix for installer/update flows (bd-2j5.14).
//!
//! Tests cover:
//! - Fresh install sequence (data dir, config, ballast provisioning)
//! - Reinstall idempotency (safe to re-run install)
//! - Uninstall cleanup (data, ballast, config removal)
//! - Update orchestration (check, apply, pin, dry-run)
//! - Rollback flow (backup store lifecycle)
//! - Failure injection (checksum mismatch, missing manifests, permission errors)
//! - Golden output format validation for user-visible screens

mod common;

use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use storage_ballast_helper::cli::from_source::{
    Prerequisite, PrerequisiteStatus, all_prerequisites_met, check_prerequisites,
    format_prerequisite_failures,
};
use storage_ballast_helper::cli::install::{
    InstallOptions, InstallReport, InstallStep, format_install_report, run_install_sequence,
    run_install_sequence_with_bundle,
};
use storage_ballast_helper::cli::uninstall::{
    CleanupMode, KeptItem, RemovalAction, RemovalCategory, UninstallOptions, UninstallReport,
    execute_uninstall, format_report_human as format_uninstall_report, plan_uninstall,
};
use storage_ballast_helper::cli::update::{BackupStore, UpdateOptions, run_update_sequence};
use storage_ballast_helper::cli::wizard::{
    BallastPreset, ServiceChoice, auto_answers, write_config,
};
use storage_ballast_helper::cli::{
    HostSpecifier, OfflineBundleArtifact, OfflineBundleManifest, RELEASE_REPOSITORY,
    ReleaseChannel, resolve_installer_artifact_contract, resolve_updater_artifact_contract,
};
use storage_ballast_helper::core::config::Config;
use storage_ballast_helper::core::hex_lower;

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
    let checksum_hex = hex_lower(checksum);
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

/// Create an offline update bundle manifest for updater-path E2E tests.
fn create_update_bundle(tmp: &Path, valid_checksum: bool) -> PathBuf {
    let host = HostSpecifier::detect().unwrap();
    let contract =
        resolve_updater_artifact_contract(host, ReleaseChannel::Stable, Some("99.99.99")).unwrap();

    let archive_name = contract.asset_name();
    let checksum_name = contract.checksum_name();
    let archive_bytes = b"offline-update-bundle-archive";
    std::fs::write(tmp.join(&archive_name), archive_bytes).unwrap();

    let checksum_hex = if valid_checksum {
        hex_lower(Sha256::digest(archive_bytes))
    } else {
        "0000000000000000000000000000000000000000000000000000000000000000".to_string()
    };
    std::fs::write(
        tmp.join(&checksum_name),
        format!("{checksum_hex}  {archive_name}\n"),
    )
    .unwrap();

    let manifest = OfflineBundleManifest {
        version: "1".to_string(),
        repository: RELEASE_REPOSITORY.to_string(),
        release_tag: "99.99.99".to_string(),
        artifacts: vec![OfflineBundleArtifact {
            target: contract.target.triple.to_string(),
            archive: archive_name,
            checksum: checksum_name,
            sigstore_bundle: None,
        }],
    };
    let manifest_path = tmp.join("update-bundle-manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    manifest_path
}

fn update_sequence_test_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
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

/// Uninstall options scoped to a test config: user scope, no home-based
/// discovery (so nothing outside the temp dir can ever be planned).
fn test_uninstall_opts(config: &Config, mode: CleanupMode, dry_run: bool) -> UninstallOptions {
    UninstallOptions {
        mode,
        dry_run,
        backup_dir: None,
        binary_path: None,
        paths: config.paths.clone(),
        user_scope: true,
        home: None,
    }
}

/// A full user-data footprint: config, state, database, log, asset cache,
/// ballast pool. Returns the data dir.
fn write_data_footprint(config: &Config) -> PathBuf {
    let data_dir = config.paths.state_file.parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(config.paths.config_file.parent().unwrap()).unwrap();
    std::fs::write(&config.paths.config_file, "[scanner]\n").unwrap();
    std::fs::write(&config.paths.state_file, "{}").unwrap();
    std::fs::write(&config.paths.sqlite_db, b"sqlite").unwrap();
    std::fs::write(&config.paths.jsonl_log, "{}\n").unwrap();
    std::fs::create_dir_all(data_dir.join("assets")).unwrap();
    std::fs::write(data_dir.join("assets").join("manifest.json"), "{}").unwrap();
    std::fs::create_dir_all(&config.paths.ballast_dir).unwrap();
    std::fs::write(config.paths.ballast_dir.join("ballast-0.bin"), [0u8; 4096]).unwrap();
    data_dir
}

fn categories(items: impl Iterator<Item = RemovalCategory>) -> Vec<RemovalCategory> {
    let mut out: Vec<RemovalCategory> = items.collect();
    out.sort_by_key(std::string::ToString::to_string);
    out.dedup();
    out
}

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
    let data_dir = write_data_footprint(&config);

    // Purge: everything goes, config and database are backed up first.
    let report = execute_uninstall(&test_uninstall_opts(&config, CleanupMode::Purge, false));
    assert_eq!(report.failed_count, 0, "purge should succeed: {report:?}");
    assert!(
        !config.paths.config_file.exists(),
        "config should be removed after uninstall"
    );
    assert!(!data_dir.exists(), "data dir should be removed by purge");
    assert!(
        !config.paths.ballast_dir.exists(),
        "ballast pool should be removed by purge"
    );
    for category in [RemovalCategory::ConfigFile, RemovalCategory::SqliteDb] {
        let backup = report
            .actions
            .iter()
            .find(|action| action.category == category)
            .and_then(|action| action.backup_path.clone())
            .unwrap_or_else(|| panic!("{category} is removed backup-first: {report:?}"));
        assert!(
            backup.is_file(),
            "{category} backup exists: {}",
            backup.display()
        );
    }
}

#[test]
fn e2e_uninstall_keep_data_preserves_state() {
    let tmp = tempfile::tempdir().unwrap();
    let config = test_config(tmp.path());
    let data_dir = write_data_footprint(&config);

    let report = execute_uninstall(&test_uninstall_opts(&config, CleanupMode::KeepData, false));
    assert_eq!(report.failed_count, 0, "{report:?}");

    // README matrix, KeepData row: data/logs kept; config, assets, ballast removed.
    assert!(data_dir.is_dir(), "data dir should be kept");
    assert!(config.paths.state_file.exists(), "state kept");
    assert!(config.paths.sqlite_db.exists(), "database kept");
    assert!(config.paths.jsonl_log.exists(), "log kept");
    assert!(!config.paths.config_file.exists(), "config removed");
    assert!(!data_dir.join("assets").exists(), "asset cache removed");
    assert!(!config.paths.ballast_dir.exists(), "ballast removed");
}

#[test]
fn e2e_uninstall_conservative_keeps_user_data() {
    let tmp = tempfile::tempdir().unwrap();
    let config = test_config(tmp.path());
    let data_dir = write_data_footprint(&config);

    let report = execute_uninstall(&test_uninstall_opts(
        &config,
        CleanupMode::Conservative,
        false,
    ));
    assert_eq!(report.failed_count, 0, "{report:?}");
    assert!(
        report.actions.is_empty(),
        "with no home-based footprint, conservative mode removes nothing: {report:?}"
    );
    assert!(config.paths.config_file.exists());
    assert!(data_dir.join("assets").exists());
    assert!(config.paths.ballast_dir.exists());
    assert_eq!(
        categories(report.kept.iter().map(|kept| kept.category)),
        categories(
            [
                RemovalCategory::ConfigFile,
                RemovalCategory::StateFile,
                RemovalCategory::SqliteDb,
                RemovalCategory::JsonlLog,
                RemovalCategory::AssetCache,
                RemovalCategory::BallastPool,
            ]
            .into_iter()
        )
    );
}

/// The README "Uninstall and Cleanup Modes" matrix, row by row, against a
/// full footprint. Planning only; nothing is removed.
#[test]
fn e2e_uninstall_plan_matches_readme_matrix() {
    use RemovalCategory as C;
    let tmp = tempfile::tempdir().unwrap();
    let config = test_config(tmp.path());
    write_data_footprint(&config);

    let data = [C::StateFile, C::SqliteDb, C::JsonlLog];
    let all = [
        C::ConfigFile,
        C::StateFile,
        C::SqliteDb,
        C::JsonlLog,
        C::AssetCache,
        C::BallastPool,
    ];
    let expect = |removed: &[C], kept: &[C]| {
        (
            categories(removed.iter().copied()),
            categories(kept.iter().copied()),
        )
    };
    let rows = [
        (CleanupMode::Conservative, expect(&[], &all)),
        (
            CleanupMode::KeepData,
            expect(&[C::ConfigFile, C::AssetCache, C::BallastPool], &data),
        ),
        (
            CleanupMode::KeepConfig,
            expect(
                &[
                    C::StateFile,
                    C::SqliteDb,
                    C::JsonlLog,
                    C::AssetCache,
                    C::BallastPool,
                ],
                &[C::ConfigFile],
            ),
        ),
        (
            CleanupMode::KeepAssets,
            expect(
                &[
                    C::ConfigFile,
                    C::StateFile,
                    C::SqliteDb,
                    C::JsonlLog,
                    C::BallastPool,
                ],
                &[C::AssetCache],
            ),
        ),
        (
            CleanupMode::Purge,
            expect(
                &[
                    C::ConfigFile,
                    C::StateFile,
                    C::SqliteDb,
                    C::JsonlLog,
                    C::AssetCache,
                    C::BallastPool,
                    C::DataDirectory,
                ],
                &[],
            ),
        ),
    ];
    for (mode, (removed, kept)) in rows {
        let report = plan_uninstall(&test_uninstall_opts(&config, mode, true));
        assert!(report.dry_run);
        assert_eq!(
            categories(report.actions.iter().map(|action| action.category)),
            removed,
            "{mode}: removed categories"
        );
        assert_eq!(
            categories(report.kept.iter().map(|kept| kept.category)),
            kept,
            "{mode}: kept categories"
        );
        assert!(
            report.actions.iter().all(|action| !action.executed),
            "{mode}: a plan executes nothing"
        );
    }
    assert!(
        config.paths.config_file.exists(),
        "planning changed nothing"
    );
}

/// User scope plans the home footprint (binary, unit, completions, PATH
/// line) and nothing outside the fixture home: on a host with a system
/// install (`/usr/local/bin/sbh`, `/etc/systemd/system/sbh.service`) a
/// scoping bug would show up here as an out-of-tree target.
#[cfg(unix)]
#[test]
fn e2e_uninstall_user_scope_never_plans_outside_its_home() {
    let tmp = tempfile::tempdir().unwrap();
    let config = test_config(tmp.path());
    write_data_footprint(&config);
    let home = tmp.path().join("home");
    let local_bin = home.join(".local").join("bin");
    std::fs::create_dir_all(&local_bin).unwrap();
    std::fs::write(local_bin.join("sbh"), "#!/bin/sh\n").unwrap();
    let unit_dir = home.join(".config").join("systemd").join("user");
    std::fs::create_dir_all(&unit_dir).unwrap();
    std::fs::write(unit_dir.join("sbh.service"), "[Unit]\n").unwrap();
    std::fs::create_dir_all(home.join(".zfunc")).unwrap();
    std::fs::write(home.join(".zfunc").join("_sbh"), "#compdef sbh\n").unwrap();
    std::fs::write(
        home.join(".zshrc"),
        "export PATH=\"$HOME/.local/bin:$PATH\"  # sbh\n",
    )
    .unwrap();

    let opts = UninstallOptions {
        home: Some(home.clone()),
        ..test_uninstall_opts(&config, CleanupMode::Conservative, true)
    };
    let report = plan_uninstall(&opts);
    let planned = categories(report.actions.iter().map(|action| action.category));
    assert_eq!(
        planned,
        categories(
            [
                RemovalCategory::Binary,
                RemovalCategory::SystemdUnit,
                RemovalCategory::ShellCompletion,
                RemovalCategory::ShellProfileEntry,
            ]
            .into_iter()
        ),
        "conservative user-scope plan: {report:?}"
    );
    for action in &report.actions {
        assert!(
            action.path.starts_with(tmp.path()),
            "user scope planned a target outside the fixture: {}",
            action.path.display()
        );
    }

    // System scope with no home: never the user's files.
    let system_opts = UninstallOptions {
        user_scope: false,
        home: Some(home),
        ..test_uninstall_opts(&config, CleanupMode::Conservative, true)
    };
    let system_report = plan_uninstall(&system_opts);
    assert!(
        system_report
            .actions
            .iter()
            .all(|action| !action.path.starts_with(tmp.path().join("home"))),
        "system scope must not plan the user's home footprint: {system_report:?}"
    );
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
    let data_dir = write_data_footprint(&config);

    // Dry-run purge plans everything and touches nothing.
    let report = execute_uninstall(&test_uninstall_opts(&config, CleanupMode::Purge, true));
    assert!(report.dry_run);
    assert!(!report.actions.is_empty());
    assert_eq!(report.removed_count, 0);
    assert!(
        report
            .actions
            .iter()
            .all(|action| action.backup_path.is_none())
    );

    // Everything should still exist.
    assert!(config.paths.config_file.exists());
    assert!(config.paths.state_file.exists());
    assert!(data_dir.join("assets").exists());
    assert!(config.paths.ballast_dir.exists());
}

// ============================================================================
// D: Update orchestration (backup store lifecycle)
// ============================================================================

#[test]
fn e2e_backup_store_create_list_rollback_prune() {
    let tmp = tempfile::tempdir().unwrap();
    let store_dir = tmp.path().join("backup-store");
    let store = BackupStore::open(store_dir);

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
        metadata_cache_ttl: std::time::Duration::from_mins(1),
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
        metadata_cache_ttl: std::time::Duration::from_mins(1),
        refresh_cache: false,
        offline_bundle_manifest: None,
    };
    let report = run_update_sequence(&opts);
    assert!(report.check_only, "should be check_only");
}

#[test]
fn e2e_update_offline_bundle_bad_checksum_fails_without_network_download() {
    let _guard = update_sequence_test_lock();
    let tmp = tempfile::tempdir().unwrap();
    let manifest_path = create_update_bundle(tmp.path(), false);

    let opts = UpdateOptions {
        check_only: false,
        dry_run: false,
        pinned_version: None,
        install_dir: tmp.path().join("bin"),
        force: false,
        no_verify: false,
        max_backups: 5,
        notices_enabled: true,
        metadata_cache_file: tmp.path().join("cache.json"),
        metadata_cache_ttl: std::time::Duration::from_mins(1),
        refresh_cache: false,
        offline_bundle_manifest: Some(manifest_path),
    };

    let report = run_update_sequence(&opts);
    assert!(
        !report.success,
        "bad bundle checksum should fail offline update: {report:?}"
    );
    assert!(
        report
            .steps
            .iter()
            .any(|s| s.description.contains("Loaded bundle artifact")),
        "offline update should load bundle artifact before verification failure"
    );
    assert!(
        report
            .steps
            .iter()
            .any(|s| s.description.contains("Loaded bundle checksum")),
        "offline update should load bundle checksum before verification failure"
    );
    assert!(
        report
            .steps
            .iter()
            .any(|s| { s.description == "Integrity verification" && s.error.as_deref().is_some() }),
        "integrity step should fail for checksum mismatch"
    );
    assert!(
        !report
            .steps
            .iter()
            .any(|s| s.description.contains("Download artifact")
                || s.description.contains("Download checksum")),
        "offline update must not fall back to network downloads"
    );
}

#[test]
fn e2e_update_offline_bundle_missing_manifest_fails_without_network_download() {
    let tmp = tempfile::tempdir().unwrap();
    let missing_manifest = tmp.path().join("missing-update-bundle.json");

    let opts = UpdateOptions {
        check_only: true,
        dry_run: false,
        pinned_version: None,
        install_dir: tmp.path().join("bin"),
        force: false,
        no_verify: false,
        max_backups: 5,
        notices_enabled: true,
        metadata_cache_file: tmp.path().join("cache.json"),
        metadata_cache_ttl: std::time::Duration::from_mins(1),
        refresh_cache: false,
        offline_bundle_manifest: Some(missing_manifest),
    };

    let report = run_update_sequence(&opts);
    assert!(
        !report.success,
        "missing update bundle manifest should fail: {report:?}"
    );
    assert!(
        report
            .steps
            .iter()
            .any(|s| s.description == "Resolve offline bundle contract"
                && s.error.as_deref().is_some()),
        "should fail while resolving offline bundle contract"
    );
    assert!(
        !report
            .steps
            .iter()
            .any(|s| s.description.contains("Download")),
        "offline update must not attempt network download when manifest is missing"
    );
}

#[test]
fn e2e_update_offline_bundle_unsupported_target_fails_without_network_download() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest_path = create_update_bundle(tmp.path(), true);

    let mut manifest: OfflineBundleManifest =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest.artifacts[0].target = "riscv64gc-unknown-linux-gnu".to_string();
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let opts = UpdateOptions {
        check_only: true,
        dry_run: false,
        pinned_version: None,
        install_dir: tmp.path().join("bin"),
        force: false,
        no_verify: false,
        max_backups: 5,
        notices_enabled: true,
        metadata_cache_file: tmp.path().join("cache.json"),
        metadata_cache_ttl: std::time::Duration::from_mins(1),
        refresh_cache: false,
        offline_bundle_manifest: Some(manifest_path),
    };

    let report = run_update_sequence(&opts);
    assert!(
        !report.success,
        "unsupported bundle target should fail offline update: {report:?}"
    );
    assert!(
        report
            .steps
            .iter()
            .any(|s| s.description == "Resolve offline bundle contract"
                && s.error.as_deref().is_some()),
        "unsupported target should fail while resolving offline bundle contract"
    );
    assert!(
        !report
            .steps
            .iter()
            .any(|s| s.description.contains("Download")),
        "offline update must not attempt network download when target is unsupported"
    );
}

#[test]
fn e2e_update_offline_bundle_blocked_install_path_fails_deterministically() {
    let _guard = update_sequence_test_lock();
    let tmp = tempfile::tempdir().unwrap();
    let manifest_path = create_update_bundle(tmp.path(), true);

    let blocked_install_parent = tmp.path().join("blocked-install-parent");
    std::fs::write(&blocked_install_parent, "not-a-directory").unwrap();

    let opts = UpdateOptions {
        check_only: false,
        dry_run: false,
        pinned_version: None,
        install_dir: blocked_install_parent,
        force: false,
        no_verify: false,
        max_backups: 5,
        notices_enabled: true,
        metadata_cache_file: tmp.path().join("cache.json"),
        metadata_cache_ttl: std::time::Duration::from_mins(1),
        refresh_cache: false,
        offline_bundle_manifest: Some(manifest_path),
    };

    let report = run_update_sequence(&opts);
    assert!(
        !report.success,
        "blocked install path should fail deterministic offline update: {report:?}"
    );
    assert!(
        report
            .steps
            .iter()
            .any(|s| s.description == "Install binary" && s.error.as_deref().is_some()),
        "install step should fail when install parent path is blocked"
    );
    assert!(
        !report
            .steps
            .iter()
            .any(|s| s.description.contains("Download artifact")
                || s.description.contains("Download checksum")),
        "offline update must not fall back to network downloads"
    );
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
// H: Artifact contract resolution
// ============================================================================

#[test]
fn e2e_host_detection_resolves_valid_contract() {
    let host = HostSpecifier::detect().unwrap();
    let contract = resolve_installer_artifact_contract(host, ReleaseChannel::Stable, None).unwrap();

    assert_eq!(contract.repository, RELEASE_REPOSITORY);
    assert_ne!(contract.asset_name(), "");
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
        mode: CleanupMode::Purge,
        dry_run: false,
        timestamp: "0".into(),
        actions: vec![
            RemovalAction {
                category: RemovalCategory::BallastPool,
                path: PathBuf::from("/tmp/sbh/ballast"),
                is_directory: true,
                backup_first: false,
                executed: true,
                backup_path: None,
                error: None,
                reason: "remove ballast pool directory".into(),
            },
            RemovalAction {
                category: RemovalCategory::ConfigFile,
                path: PathBuf::from("/tmp/sbh/config.toml"),
                is_directory: false,
                backup_first: true,
                executed: true,
                backup_path: Some(PathBuf::from("/tmp/sbh/config.toml.sbh-uninstall-backup-0")),
                error: None,
                reason: "remove config file".into(),
            },
        ],
        kept: vec![KeptItem {
            category: RemovalCategory::StateFile,
            path: PathBuf::from("/tmp/sbh/state.json"),
            reason: "kept by purge mode".into(),
        }],
        removed_count: 2,
        failed_count: 0,
        bytes_freed: 10_737_418_240,
    };

    let output = format_uninstall_report(&report);
    assert!(output.contains("Uninstall report (mode: purge)"));
    assert!(output.contains("[DONE] ballast-pool: /tmp/sbh/ballast"));
    assert!(output.contains("backup: /tmp/sbh/config.toml.sbh-uninstall-backup-0"));
    assert!(output.contains("[KEEP] state-file"));
    assert!(
        output.contains("2 removed, 0 failed, 10737418240 bytes freed"),
        "should show reclaimed space: {output}"
    );
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
        .find_map(|s| s.error.as_ref())
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
        mode: CleanupMode::KeepData,
        dry_run: false,
        timestamp: "0".into(),
        actions: vec![],
        kept: vec![],
        removed_count: 0,
        failed_count: 0,
        bytes_freed: 1024,
    };

    let json = serde_json::to_string(&report).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    for key in [
        "mode",
        "dry_run",
        "timestamp",
        "actions",
        "kept",
        "removed_count",
        "failed_count",
        "bytes_freed",
    ] {
        assert!(parsed.get(key).is_some(), "uninstall report exposes {key}");
    }
    assert_eq!(parsed["mode"], "KeepData");
    assert_eq!(parsed["bytes_freed"], 1024);
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

// ============================================================================
// H: Updater against a fake release (loopback HTTP; real curl, tar, install)
// ============================================================================
//
// Every v0.5.x updater 404'd because it guessed one asset name. These cases
// publish a release on a local `python3 -m http.server` and drive the real
// `sbh update` binary at it through the `SBH_TEST_MODE=1` base-URL hooks, so
// the layout resolution, checksum handling, download, extraction, and
// atomic install run exactly as they do against GitHub.

/// `python3 -m http.server` rooted at `root`, killed when dropped.
struct FakeReleaseServer {
    child: std::process::Child,
    base_url: String,
}

impl FakeReleaseServer {
    /// `None` when `python3` cannot be spawned; the caller skips loudly.
    fn start(root: &Path) -> Option<Self> {
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))
            .ok()?
            .local_addr()
            .ok()?
            .port();
        let mut child = std::process::Command::new("python3")
            .args(["-m", "http.server", &port.to_string()])
            .args(["--bind", "127.0.0.1", "--directory"])
            .arg(root)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Some(Self {
                    child,
                    base_url: format!("http://127.0.0.1:{port}"),
                });
            }
            if let Ok(Some(status)) = child.try_wait() {
                panic!("fake release server exited before accepting connections: {status}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = child.kill();
        panic!("fake release server never listened on 127.0.0.1:{port}");
    }
}

impl Drop for FakeReleaseServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One published release under the fake server's document root, laid out
/// the way the GitHub API and download URLs expect.
struct FakeRelease {
    tag: String,
    api_file: PathBuf,
    download_dir: PathBuf,
    stage_dir: PathBuf,
    assets: Vec<String>,
}

impl FakeRelease {
    fn new(root: &Path, tag: &str) -> Self {
        let api_dir = root
            .join("repos")
            .join(RELEASE_REPOSITORY)
            .join("releases")
            .join("tags");
        let download_dir = root
            .join(RELEASE_REPOSITORY)
            .join("releases")
            .join("download")
            .join(tag);
        let stage_dir = root.join("stage").join(tag);
        for dir in [&api_dir, &download_dir, &stage_dir] {
            std::fs::create_dir_all(dir).unwrap();
        }
        Self {
            tag: tag.to_string(),
            api_file: api_dir.join(tag),
            download_dir,
            stage_dir,
            assets: Vec::new(),
        }
    }

    /// The executable a release of this tag ships: a script whose output
    /// names the tag, so an installed copy proves which asset was used.
    fn fake_binary(&self) -> Vec<u8> {
        format!("#!/bin/sh\nprintf 'sbh fake %s\\n' '{}'\n", self.tag).into_bytes()
    }

    fn publish(&mut self, name: &str, bytes: &[u8]) {
        std::fs::write(self.download_dir.join(name), bytes).unwrap();
        self.assets.push(name.to_string());
    }

    /// List `name` in the API response without serving the file.
    fn announce_only(&mut self, name: &str) {
        self.assets.push(name.to_string());
    }

    /// A `.tar.xz` holding `sbh`, plus its `<name>.sha256` sidecar.
    fn publish_archive(&mut self, name: &str, valid_checksum: bool) {
        let binary = self.stage_dir.join("sbh");
        std::fs::write(&binary, self.fake_binary()).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        let archive = self.download_dir.join(name);
        let status = std::process::Command::new("tar")
            .arg("-C")
            .arg(&self.stage_dir)
            .arg("-cJf")
            .arg(&archive)
            .arg("sbh")
            .status()
            .expect("tar is available");
        assert!(status.success(), "tar -cJf failed for {name}");
        let digest = if valid_checksum {
            hex_lower(Sha256::digest(std::fs::read(&archive).unwrap()))
        } else {
            "0".repeat(64)
        };
        self.assets.push(name.to_string());
        self.publish(
            &format!("{name}.sha256"),
            format!("{digest}  {name}\n").as_bytes(),
        );
    }

    /// A raw executable plus an aggregate `SHA256SUMS` that also lists a
    /// decoy entry, so the updater must select the right line.
    fn publish_raw(&mut self, name: &str, valid_checksum: bool) {
        let bytes = self.fake_binary();
        let digest = if valid_checksum {
            hex_lower(Sha256::digest(&bytes))
        } else {
            "0".repeat(64)
        };
        self.publish(name, &bytes);
        let manifest = format!(
            "{}  sbh_windows_amd64.exe\n{digest}  {name}\n",
            "f".repeat(64)
        );
        self.publish("SHA256SUMS", manifest.as_bytes());
    }

    /// Write the `releases/tags/<tag>` API document listing every asset.
    fn finish(&self) {
        let assets: Vec<serde_json::Value> = self
            .assets
            .iter()
            .map(|name| serde_json::json!({ "name": name }))
            .collect();
        let doc = serde_json::json!({ "tag_name": self.tag, "assets": assets });
        std::fs::write(&self.api_file, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
    }
}

/// Outcome of one `sbh update` run against the fake server.
struct FakeUpdateRun {
    status: std::process::ExitStatus,
    report: serde_json::Value,
    base_url: String,
    installed: PathBuf,
    seeded: FileIdentity,
    stderr: String,
}

/// Enough to prove a file is the very same one that was seeded: the
/// updater installs by renaming the old binary aside and copying a new one
/// in, which changes the inode.
#[derive(Debug, PartialEq, Eq)]
struct FileIdentity {
    inode: u64,
    len: u64,
    modified: std::time::SystemTime,
}

fn file_identity(path: &Path) -> FileIdentity {
    let metadata = std::fs::metadata(path).unwrap();
    FileIdentity {
        inode: metadata.ino(),
        len: metadata.len(),
        modified: metadata.modified().unwrap(),
    }
}

impl FakeUpdateRun {
    fn steps(&self) -> Vec<(String, Option<String>)> {
        self.report["steps"]
            .as_array()
            .map(|steps| {
                steps
                    .iter()
                    .map(|step| {
                        (
                            step["description"].as_str().unwrap_or("").to_string(),
                            step["error"].as_str().map(str::to_string),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn step_mentioning(&self, needle: &str) -> Option<(String, Option<String>)> {
        self.steps()
            .into_iter()
            .find(|(description, _)| description.contains(needle))
    }

    fn failed_step(&self) -> Option<(String, String)> {
        self.steps()
            .into_iter()
            .find_map(|(description, error)| error.map(|error| (description, error)))
    }

    fn installed_identity(&self) -> FileIdentity {
        file_identity(&self.installed)
    }

    fn assert_applied(&self, release: &FakeRelease, expected_asset: &str, expected_layout: &str) {
        assert_eq!(
            self.report["applied"],
            serde_json::Value::Bool(true),
            "{}: update must be applied; steps: {:?}\nstderr: {}",
            release.tag,
            self.steps(),
            self.stderr
        );
        assert!(
            self.failed_step().is_none(),
            "{}: no step may fail: {:?}",
            release.tag,
            self.failed_step()
        );
        assert_eq!(
            std::fs::read(&self.installed).unwrap(),
            release.fake_binary(),
            "{}: the installed binary must be the published one",
            release.tag
        );
        let metadata = std::fs::metadata(&self.installed).unwrap();
        assert_eq!(
            metadata.permissions().mode() & 0o111,
            0o111,
            "{}: installed binary must be executable",
            release.tag
        );
        assert_eq!(
            self.report["artifact_url"].as_str(),
            Some(
                format!(
                    "{}/{RELEASE_REPOSITORY}/releases/download/{}/{expected_asset}",
                    self.base_url, release.tag
                )
                .as_str()
            ),
            "{}: artifact URL must point at the resolved asset",
            release.tag
        );
        let resolved = self
            .step_mentioning("Resolved release asset")
            .unwrap_or_else(|| panic!("{}: no asset resolution step", release.tag));
        assert!(
            resolved.0.contains(expected_layout),
            "{}: expected {expected_layout} layout, got {}",
            release.tag,
            resolved.0
        );
        assert_ne!(
            self.report["service_restart"]["status"].as_str(),
            Some("restarted"),
            "{}: a test install must never restart a service",
            release.tag
        );
        // Whether the (skipped or failed) service restart flips `success` is
        // a property of the host, not of the release contract under test.
    }

    fn assert_denied(&self, release: &FakeRelease, failed_step: &str, error_fragment: &str) {
        assert!(
            !self.status.success(),
            "{}: `sbh update` must exit non-zero; stderr: {}",
            release.tag,
            self.stderr
        );
        assert_eq!(
            self.report["applied"],
            serde_json::Value::Bool(false),
            "{}: nothing may be applied",
            release.tag
        );
        assert_eq!(
            self.report["success"],
            serde_json::Value::Bool(false),
            "{}: the report must not claim success",
            release.tag
        );
        let (description, error) = self
            .failed_step()
            .unwrap_or_else(|| panic!("{}: expected a failed step", release.tag));
        assert_eq!(
            description, failed_step,
            "{}: wrong failing step",
            release.tag
        );
        assert!(
            error.contains(error_fragment),
            "{}: error {error:?} should mention {error_fragment:?}",
            release.tag
        );
        assert_eq!(
            self.installed_identity(),
            self.seeded,
            "{}: the installed binary must be untouched after a denial",
            release.tag
        );
    }
}

/// Copy the real `sbh` into a private bin dir (the updater installs next to
/// the running executable) and run `sbh update --user --version <tag>`
/// against the fake server, with HOME and the metadata cache isolated.
fn run_fake_update(tmp: &Path, server: &FakeReleaseServer, release: &FakeRelease) -> FakeUpdateRun {
    let case_dir = tmp.join("case").join(&release.tag);
    let bin_dir = case_dir.join("bin");
    let home = case_dir.join("home");
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let installed = bin_dir.join("sbh");
    // A hard link is enough to seed the bin dir (the updater renames it
    // aside rather than writing through it); fall back to a copy across
    // filesystems.
    if std::fs::hard_link(common::sbh_bin_path(), &installed).is_err() {
        std::fs::copy(common::sbh_bin_path(), &installed).unwrap();
    }
    let seeded = file_identity(&installed);

    let config_path = case_dir.join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "[update]\nmetadata_cache_file = \"{}\"\nmetadata_cache_ttl_seconds = 60\n",
            case_dir.join("cache.json").display()
        ),
    )
    .unwrap();

    let started = Instant::now();
    let output = std::process::Command::new(&installed)
        .arg("--config")
        .arg(&config_path)
        .args(["--json", "update", "--user", "--version", &release.tag])
        .env("HOME", &home)
        .env("SBH_TEST_MODE", "1")
        .env("SBH_RELEASE_API_BASE", &server.base_url)
        .env("SBH_RELEASE_DOWNLOAD_BASE", &server.base_url)
        .output()
        .expect("spawn sbh update");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    eprintln!(
        "[{}] sbh update exited {} after {:?}\n--- stderr ---\n{stderr}",
        release.tag,
        output.status,
        started.elapsed()
    );
    let json_line = stdout
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .unwrap_or_else(|| {
            panic!(
                "{}: no JSON report on stdout:\n{stdout}\n{stderr}",
                release.tag
            )
        });
    let report: serde_json::Value = serde_json::from_str(json_line).unwrap();
    FakeUpdateRun {
        status: output.status,
        report,
        base_url: server.base_url.clone(),
        installed,
        seeded,
        stderr,
    }
}

#[test]
fn e2e_update_resolves_every_release_layout_against_a_fake_release_server() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("www");
    std::fs::create_dir_all(&root).unwrap();
    let Some(server) = FakeReleaseServer::start(&root) else {
        eprintln!("SKIP: python3 is not available to serve a fake release");
        return;
    };
    let host = HostSpecifier::detect().unwrap();
    let contract =
        resolve_updater_artifact_contract(host, ReleaseChannel::Stable, Some("v9.9.0")).unwrap();
    let raw_name = contract
        .raw_binary_name()
        .expect("linux/macos hosts have a raw asset name");
    let versioned = |tag: &str| contract.asset_name_for_tag(tag);
    let legacy = contract.release_asset_candidates("v9.9.0")[1]
        .asset_name
        .clone();

    // Tarball-only (the release workflow's layout).
    let mut tarball_only = FakeRelease::new(&root, "v9.9.1");
    tarball_only.publish_archive(&versioned("v9.9.1"), true);
    tarball_only.finish();
    let run = run_fake_update(tmp.path(), &server, &tarball_only);
    run.assert_applied(&tarball_only, &versioned("v9.9.1"), "VersionedArchive");
    assert_eq!(
        run.report["target_version"].as_str(),
        Some("v9.9.1"),
        "pinned tag is the target"
    );

    // Raw-only (the hand-published v0.5.x layout).
    let mut raw_only = FakeRelease::new(&root, "v9.9.2");
    raw_only.publish_raw(&raw_name, true);
    raw_only.finish();
    let run = run_fake_update(tmp.path(), &server, &raw_only);
    run.assert_applied(&raw_only, &raw_name, "RawBinary");
    assert!(
        run.step_mentioning("selected the")
            .is_some_and(|(step, _)| step.contains("SHA256SUMS") && step.contains(&raw_name)),
        "raw layout takes its digest from the manifest entry: {:?}",
        run.steps()
    );

    // Mixed: the versioned tarball wins over the raw binary.
    let mut mixed = FakeRelease::new(&root, "v9.9.3");
    mixed.publish_raw(&raw_name, true);
    mixed.publish_archive(&versioned("v9.9.3"), true);
    mixed.finish();
    let run = run_fake_update(tmp.path(), &server, &mixed);
    run.assert_applied(&mixed, &versioned("v9.9.3"), "VersionedArchive");

    // Legacy unversioned tarball still installs.
    let mut legacy_only = FakeRelease::new(&root, "v9.9.4");
    legacy_only.publish_archive(&legacy, true);
    legacy_only.finish();
    let run = run_fake_update(tmp.path(), &server, &legacy_only);
    run.assert_applied(&legacy_only, &legacy, "LegacyArchive");

    // Checksum mismatch in the manifest: denied, binary untouched.
    let mut bad_manifest = FakeRelease::new(&root, "v9.9.5");
    bad_manifest.publish_raw(&raw_name, false);
    bad_manifest.finish();
    let run = run_fake_update(tmp.path(), &server, &bad_manifest);
    run.assert_denied(&bad_manifest, "Integrity verification", "denied");

    // Checksum mismatch in a sidecar: denied, binary untouched.
    let mut bad_sidecar = FakeRelease::new(&root, "v9.9.6");
    bad_sidecar.publish_archive(&versioned("v9.9.6"), false);
    bad_sidecar.finish();
    let run = run_fake_update(tmp.path(), &server, &bad_sidecar);
    run.assert_denied(&bad_sidecar, "Integrity verification", "denied");

    // A release with no layout this host understands names what it found.
    let mut foreign = FakeRelease::new(&root, "v9.9.7");
    foreign.publish("sbh_windows_amd64.exe", b"MZ");
    foreign.publish("SHA256SUMS", b"");
    foreign.finish();
    let run = run_fake_update(tmp.path(), &server, &foreign);
    run.assert_denied(&foreign, "Resolve release asset", "sbh_windows_amd64.exe");

    // Listed but not served: the download step fails, nothing is installed.
    let mut ghost = FakeRelease::new(&root, "v9.9.8");
    ghost.announce_only(&versioned("v9.9.8"));
    ghost.announce_only(&format!("{}.sha256", versioned("v9.9.8")));
    ghost.finish();
    let run = run_fake_update(tmp.path(), &server, &ghost);
    run.assert_denied(&ghost, "Download artifact", "download failed");
}

/// Without `SBH_TEST_MODE=1` the base-URL variables are inert, so a stray
/// environment can never redirect a real update.
#[test]
fn e2e_update_ignores_release_base_overrides_outside_test_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let output = std::process::Command::new(common::sbh_bin_path())
        .args(["--json", "update", "--check", "--version", "v9.9.9"])
        .env("HOME", &home)
        .env_remove("SBH_TEST_MODE")
        .env("SBH_RELEASE_API_BASE", "http://127.0.0.1:9")
        .env("SBH_RELEASE_DOWNLOAD_BASE", "http://127.0.0.1:9")
        .output()
        .expect("spawn sbh update");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = stdout
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .map(|line| serde_json::from_str(line).unwrap())
        .expect("JSON report");
    let url = report["artifact_url"].as_str().unwrap_or_default();
    assert!(
        url.starts_with("https://github.com/"),
        "real GitHub host must be used outside test mode: {url}"
    );
}

/// The shell installer and the Rust contract must agree on every asset
/// name they probe for, for every published target.
#[test]
fn e2e_install_script_probes_the_same_asset_names_as_the_rust_contract() {
    let installer = include_str!("../scripts/install.sh");
    for (os, arch, abi) in [
        ("linux", "x86_64", Some("gnu")),
        ("linux", "aarch64", Some("gnu")),
        ("macos", "x86_64", None),
        ("macos", "aarch64", None),
    ] {
        let host = HostSpecifier::from_parts(os, arch, abi).unwrap();
        let contract =
            resolve_updater_artifact_contract(host, ReleaseChannel::Stable, Some("v1.2.3"))
                .unwrap();
        let triple = contract.target.triple;
        let candidates = contract.release_asset_candidates("v1.2.3");
        assert_eq!(
            candidates[0].asset_name,
            format!("sbh-v1.2.3-{triple}.tar.xz"),
            "versioned archive name for {triple}"
        );
        assert_eq!(
            candidates[1].asset_name,
            format!("sbh-{triple}.tar.xz"),
            "legacy archive name for {triple}"
        );
        let raw = candidates[2].asset_name.replacen("sbh", "${PROGRAM}", 1);
        assert!(
            installer.contains(&format!("{triple})")) && installer.contains(&raw),
            "install.sh must map {triple} to the raw asset {raw}"
        );
        assert_eq!(candidates[2].checksum_name, "SHA256SUMS");
    }
    for fragment in [
        "versioned_archive_name=\"${PROGRAM}-${RELEASE_LOCATOR}-${TARGET_TRIPLE}.tar.xz\"",
        "local versioned_archive_checksum=\"${versioned_archive_name}.sha256\"",
        "local archive_name=\"${PROGRAM}-${TARGET_TRIPLE}.tar.xz\"",
        "for candidate in \"SHA256SUMS\" \"SHA256SUMS.txt\"; do",
    ] {
        assert!(
            installer.contains(fragment),
            "install.sh must keep the contract fragment: {fragment}"
        );
    }
}

/// `scripts/changelog_check.sh` gates a release on its CHANGELOG entry: a
/// tag needs exactly one heading, carrying `**[release]**` iff the tag has
/// release assets. The release workflow runs it with `--expect-release`.
#[test]
fn e2e_changelog_check_script_enforces_headings_and_release_markers() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = repo.join("scripts").join("changelog_check.sh");
    let tmp = tempfile::tempdir().unwrap();
    let changelog = tmp.path().join("CHANGELOG.md");
    std::fs::write(
        &changelog,
        "# Changelog\n\n## v1.2.3 **[release]**\n\nreleased\n\n## [v1.2.2] -- 2026-01-01\n\ntagged only\n\n## v1.2.30 **[release]**\n\nprefix trap\n",
    )
    .unwrap();
    let run = |args: &[&str]| {
        let output = std::process::Command::new("bash")
            .arg(&script)
            .arg("--changelog")
            .arg(&changelog)
            .args(args)
            .output()
            .expect("run changelog_check.sh");
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    };

    // Positive paths: marker state matches the asset count, and the tag
    // being published has its marked heading (v1.2.3 must not also match
    // v1.2.30).
    assert_eq!(run(&["--tag", "v1.2.3", "--assets", "5"]).0, Some(0));
    assert_eq!(run(&["--tag", "v1.2.3", "--expect-release"]).0, Some(0));
    assert_eq!(run(&["--tag", "v1.2.2", "--assets", "0"]).0, Some(0));

    // Heading without the marker while the tag has assets.
    let (code, stderr) = run(&["--tag", "v1.2.2", "--assets", "2"]);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("lacks the **[release]** marker"),
        "{stderr}"
    );
    let (code, stderr) = run(&["--tag", "v1.2.2", "--expect-release"]);
    assert_eq!(code, Some(1), "{stderr}");

    // Marker without assets.
    let (code, stderr) = run(&["--tag", "v1.2.3", "--assets", "0"]);
    assert_eq!(code, Some(1));
    assert!(stderr.contains("no release assets"), "{stderr}");

    // No heading at all.
    let (code, stderr) = run(&["--tag", "v9.9.9", "--expect-release"]);
    assert_eq!(code, Some(1));
    assert!(stderr.contains("has no heading"), "{stderr}");

    // Usage errors are distinguishable from mismatches.
    assert_eq!(run(&["--tag", "v1.2.3", "--assets", "many"]).0, Some(2));
    assert_eq!(run(&[]).0, Some(2));

    // The real changelog carries a marked heading for the crate version,
    // which is what the release workflow will demand when it is tagged.
    let output = std::process::Command::new("bash")
        .arg(&script)
        .args([
            "--tag",
            concat!("v", env!("CARGO_PKG_VERSION")),
            "--expect-release",
        ])
        .current_dir(repo)
        .output()
        .expect("run changelog_check.sh");
    assert!(
        output.status.success(),
        "CHANGELOG.md lacks a marked heading for v{}: {}",
        env!("CARGO_PKG_VERSION"),
        String::from_utf8_lossy(&output.stderr)
    );
}
