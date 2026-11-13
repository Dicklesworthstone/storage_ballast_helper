//! Install/uninstall orchestration for `sbh install` and `sbh uninstall`.
//!
//! Coordinates the multi-step install sequence: config generation, data
//! directory creation, ballast provisioning, service registration, and
//! post-install verification. The uninstall path reverses these steps
//! with optional data/ballast retention.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::{
    HostSpecifier, IntegrityDecision, VerificationMode, resolve_bundle_artifact_contract,
    sigstore_policy_and_probe_for_bundle, verify_artifact_supply_chain,
};
use crate::ballast::manager::BallastManager;
use crate::core::config::Config;
#[cfg(test)]
use crate::core::hex_lower;
// errors module available but not directly used in this module.

// ---------------------------------------------------------------------------
// Install plan
// ---------------------------------------------------------------------------

/// A single step in the install sequence.
#[derive(Debug, Clone, Serialize)]
pub struct InstallStep {
    /// Human-readable description.
    pub description: String,
    /// Whether this step completed successfully.
    pub done: bool,
    /// Error message if the step failed.
    pub error: Option<String>,
}

/// Structured report from an install run.
#[derive(Debug, Clone, Serialize)]
pub struct InstallReport {
    /// Ordered list of steps attempted.
    pub steps: Vec<InstallStep>,
    /// Overall success.
    pub success: bool,
    /// Path to the config file (if written or preserved).
    pub config_path: Option<PathBuf>,
    /// Path to the data directory (if created).
    pub data_dir: Option<PathBuf>,
    /// Path to the ballast directory (if provisioned).
    pub ballast_dir: Option<PathBuf>,
    /// Number of ballast files created.
    pub ballast_files_created: usize,
    /// Total ballast bytes provisioned.
    pub ballast_bytes: u64,
    /// Whether this was a dry run.
    pub dry_run: bool,
}

impl InstallReport {
    fn new(dry_run: bool) -> Self {
        Self {
            steps: Vec::new(),
            success: false,
            config_path: None,
            data_dir: None,
            ballast_dir: None,
            ballast_files_created: 0,
            ballast_bytes: 0,
            dry_run,
        }
    }

    fn step_ok(&mut self, description: impl Into<String>) {
        self.steps.push(InstallStep {
            description: description.into(),
            done: true,
            error: None,
        });
    }

    fn step_fail(&mut self, description: impl Into<String>, error: impl Into<String>) {
        self.steps.push(InstallStep {
            description: description.into(),
            done: false,
            error: Some(error.into()),
        });
    }

    fn step_plan(&mut self, description: impl Into<String>) {
        self.steps.push(InstallStep {
            description: description.into(),
            done: false,
            error: None,
        });
    }
}

// ---------------------------------------------------------------------------
// Install options
// ---------------------------------------------------------------------------

/// Options controlling the install orchestration.
#[derive(Debug, Clone)]
pub struct InstallOptions {
    /// Effective configuration to write or use with the preserved file.
    pub config: Config,
    /// Number of ballast files to create.
    pub ballast_count: usize,
    /// Size of each ballast file in bytes.
    pub ballast_size_bytes: u64,
    /// Override ballast directory path.
    pub ballast_path: Option<PathBuf>,
    /// Keep the existing config file byte-for-byte instead of rewriting it.
    /// Ballast overrides must match `config` while preservation is enabled.
    pub preserve_existing_config: bool,
    /// Show plan without executing.
    pub dry_run: bool,
}

impl Default for InstallOptions {
    fn default() -> Self {
        let config = Config::default();
        Self {
            ballast_count: config.ballast.file_count,
            ballast_size_bytes: config.ballast.file_size_bytes,
            ballast_path: None,
            preserve_existing_config: false,
            dry_run: false,
            config,
        }
    }
}

// ---------------------------------------------------------------------------
// Install orchestration
// ---------------------------------------------------------------------------

/// Run the install sequence. Returns a structured report.
///
/// Steps:
/// 1. Create data directory.
/// 2. Write or preserve the config file.
/// 3. Provision ballast files.
///
/// Service registration (systemd/launchd) is handled separately in `cli_app.rs`.
pub fn run_install_sequence(opts: &InstallOptions) -> InstallReport {
    run_install_sequence_with_bundle(opts, None)
}

/// Run install sequence with optional offline bundle preflight.
///
/// When `bundle_manifest_path` is provided, this validates the host-specific
/// bundle contract and verifies artifact integrity before continuing.
pub fn run_install_sequence_with_bundle(
    opts: &InstallOptions,
    bundle_manifest_path: Option<&Path>,
) -> InstallReport {
    let mut report = InstallReport::new(opts.dry_run);

    let config = match resolve_install_config(opts) {
        Ok(config) => config,
        Err(error) => {
            report.step_fail("Validate install configuration", error.to_string());
            return report;
        }
    };
    let paths = &config.paths;

    if !run_bundle_preflight(bundle_manifest_path, opts.dry_run, &mut report) {
        return report;
    }

    // Step 1: Create data directory.
    let data_dir = paths
        .state_file
        .parent()
        .unwrap_or_else(|| Path::new("/tmp"))
        .to_path_buf();

    if opts.dry_run {
        report.step_plan(format!("Create data directory: {}", data_dir.display()));
    } else {
        match std::fs::create_dir_all(&data_dir) {
            Ok(()) => {
                report.step_ok(format!("Created data directory: {}", data_dir.display()));
                report.data_dir = Some(data_dir);
            }
            Err(e) => {
                report.step_fail(
                    format!("Create data directory: {}", data_dir.display()),
                    e.to_string(),
                );
                return report;
            }
        }
    }

    // Step 2: Persist the configuration used for provisioning and daemon startup.
    let config_path = &paths.config_file;
    if opts.preserve_existing_config {
        let description = format!("Preserve existing config: {}", config_path.display());
        if opts.dry_run {
            report.step_plan(description);
        } else {
            report.step_ok(description);
            report.config_path = Some(config_path.clone());
        }
    } else if opts.dry_run {
        report.step_plan(format!("Write config: {}", config_path.display()));
    } else {
        match write_config(&config, config_path) {
            Ok(()) => {
                report.step_ok(format!("Wrote config: {}", config_path.display()));
                report.config_path = Some(config_path.clone());
            }
            Err(e) => {
                report.step_fail(
                    format!("Write config: {}", config_path.display()),
                    e.to_string(),
                );
                return report;
            }
        }
    }

    // Step 3: Provision only when the effective configuration enables it.
    provision_install_ballast(&config, opts.dry_run, &mut report);

    report.success = report.steps.iter().all(|s| s.error.is_none());
    report
}

fn resolve_install_config(opts: &InstallOptions) -> crate::core::errors::Result<Config> {
    use crate::core::errors::SbhError;

    if opts.preserve_existing_config
        && (opts.ballast_count != opts.config.ballast.file_count
            || opts.ballast_size_bytes != opts.config.ballast.file_size_bytes
            || opts
                .ballast_path
                .as_ref()
                .is_some_and(|path| path != &opts.config.paths.ballast_dir))
    {
        return Err(SbhError::InvalidConfig {
            details: "preserving an existing config cannot apply unpersisted ballast overrides"
                .to_string(),
        });
    }
    let mut config = opts.config.clone();
    config.ballast.file_count = opts.ballast_count;
    config.ballast.file_size_bytes = opts.ballast_size_bytes;
    if let Some(ballast_path) = &opts.ballast_path {
        config.paths.ballast_dir.clone_from(ballast_path);
    }
    config.validate()?;
    if opts.preserve_existing_config {
        // Check before creating data directories, including for a dry run.
        // Preserve comments and operator-authored values instead of freezing
        // this process's environment overrides into the persisted file.
        let path = &config.paths.config_file;
        let metadata = std::fs::metadata(path).map_err(|error| SbhError::io(path, error))?;
        if !metadata.is_file() {
            return Err(SbhError::InvalidConfig {
                details: format!(
                    "configuration to preserve {} is not a regular file",
                    path.display()
                ),
            });
        }
        std::fs::read_to_string(path).map_err(|error| SbhError::io(path, error))?;
    }
    Ok(config)
}

fn provision_install_ballast(config: &Config, dry_run: bool, report: &mut InstallReport) {
    if !config.ballast.auto_provision {
        let description = "Skip ballast provisioning (ballast.auto_provision=false)";
        if dry_run {
            report.step_plan(description);
        } else {
            report.step_ok(description);
        }
        return;
    }

    let ballast_dir = &config.paths.ballast_dir;
    if dry_run {
        let total_gb = (config.ballast.file_count as u64)
            .saturating_mul(config.ballast.file_size_bytes)
            / 1_073_741_824;
        report.step_plan(format!(
            "Provision ballast: {} files x {} MB = {} GB in {}",
            config.ballast.file_count,
            config.ballast.file_size_bytes / (1024 * 1024),
            total_gb,
            ballast_dir.display()
        ));
        return;
    }

    let mut manager = match BallastManager::new(ballast_dir.clone(), config.ballast.clone()) {
        Ok(manager) => manager,
        Err(error) => {
            report.step_fail(
                format!("Initialize ballast manager in {}", ballast_dir.display()),
                error.to_string(),
            );
            return;
        }
    };
    manager.set_provision_floor_rule(config.ballast_provision_floor());
    match manager.provision(None) {
        Ok(provisioned) => {
            report.step_ok(format!(
                "Provisioned ballast: {} files ({} bytes) in {}",
                provisioned.files_created,
                provisioned.total_bytes,
                ballast_dir.display()
            ));
            report.ballast_dir = Some(ballast_dir.clone());
            report.ballast_files_created = provisioned.files_created;
            report.ballast_bytes = provisioned.total_bytes;
        }
        Err(error) => {
            report.step_fail(
                format!("Provision ballast in {}", ballast_dir.display()),
                error.to_string(),
            );
        }
    }
}

fn run_bundle_preflight(
    bundle_manifest_path: Option<&Path>,
    dry_run: bool,
    report: &mut InstallReport,
) -> bool {
    let Some(manifest_path) = bundle_manifest_path else {
        return true;
    };

    if dry_run {
        report.step_plan(format!(
            "Validate offline bundle manifest: {}",
            manifest_path.display()
        ));
        report.step_plan("Verify offline bundle artifact integrity");
        return true;
    }

    let host = match HostSpecifier::detect() {
        Ok(host) => host,
        Err(error) => {
            report.step_fail("Detect host for offline bundle", error.to_string());
            return false;
        }
    };

    let resolution = match resolve_bundle_artifact_contract(host, manifest_path) {
        Ok(resolution) => {
            report.step_ok(format!(
                "Validated offline bundle for target {}",
                resolution.contract.target.triple
            ));
            resolution
        }
        Err(error) => {
            report.step_fail("Validate offline bundle manifest", error.to_string());
            return false;
        }
    };

    let expected_checksum = match std::fs::read_to_string(&resolution.checksum_path) {
        Ok(value) => value,
        Err(error) => {
            report.step_fail(
                "Read offline bundle checksum",
                format!("{}: {error}", resolution.checksum_path.display()),
            );
            return false;
        }
    };

    let (sigstore_policy, sigstore_probe) = sigstore_policy_and_probe_for_bundle(
        &resolution.archive_path,
        resolution.sigstore_bundle_path.as_deref(),
    );
    match verify_artifact_supply_chain(
        &resolution.archive_path,
        &expected_checksum,
        VerificationMode::Enforce,
        sigstore_policy,
        sigstore_probe,
    ) {
        Ok(outcome) if matches!(outcome.decision, IntegrityDecision::Allow) => {
            report.step_ok(format!(
                "Verified offline bundle artifact: {}",
                resolution.archive_path.display()
            ));
            true
        }
        Ok(outcome) => {
            report.step_fail(
                "Verify offline bundle artifact integrity",
                format!("denied: {:?}", outcome.reason_codes),
            );
            false
        }
        Err(error) => {
            report.step_fail(
                "Verify offline bundle artifact integrity",
                error.to_string(),
            );
            false
        }
    }
}

fn write_config(config: &Config, path: &Path) -> std::io::Result<()> {
    let toml_str = toml::to_string_pretty(config).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("config serialization failed: {e}"),
        )
    })?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Atomic write: temp file + rename prevents partial config on crash.
    let tmp_path = path.with_extension("toml.tmp");
    std::fs::write(&tmp_path, toml_str)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Human formatting
// ---------------------------------------------------------------------------

/// Format an install report for terminal output.
#[must_use]
pub fn format_install_report(report: &InstallReport) -> String {
    let mut out = String::new();

    let mode = if report.dry_run { "dry-run" } else { "install" };
    let _ = writeln!(out, "sbh {mode} report:\n");

    for step in &report.steps {
        let icon = if step.error.is_some() {
            "FAIL"
        } else if step.done {
            "DONE"
        } else {
            "PLAN"
        };
        let _ = writeln!(out, "  [{icon}] {}", step.description);
        if let Some(err) = &step.error {
            let _ = writeln!(out, "         error: {err}");
        }
    }

    if !report.dry_run && report.success {
        out.push('\n');
        if let Some(ref config) = report.config_path {
            let _ = writeln!(out, "  Config:  {}", config.display());
        }
        if let Some(ref data) = report.data_dir {
            let _ = writeln!(out, "  Data:    {}", data.display());
        }
        if report.ballast_files_created > 0 {
            let gb = report.ballast_bytes / 1_073_741_824;
            let _ = writeln!(
                out,
                "  Ballast: {} files = {} GB reclaimable",
                report.ballast_files_created, gb
            );
        }
    }

    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    use crate::cli::{
        HostSpecifier, OfflineBundleArtifact, OfflineBundleManifest, RELEASE_REPOSITORY,
        ReleaseChannel, resolve_installer_artifact_contract,
    };

    #[test]
    fn install_dry_run_generates_plan() {
        let opts = InstallOptions {
            dry_run: true,
            ..Default::default()
        };
        let report = run_install_sequence(&opts);
        assert!(report.dry_run);
        assert!(report.success);
        assert!(!report.steps.is_empty());
        // All steps should be planned (not done).
        for step in &report.steps {
            assert!(!step.done);
            assert!(step.error.is_none());
        }
    }

    #[test]
    fn install_creates_config_and_data_dir() {
        let tmp = TempDir::new().unwrap();
        let config_path = tmp.path().join("config").join("config.toml");
        let data_dir = tmp.path().join("data");
        let ballast_dir = tmp.path().join("ballast");

        let mut config = Config::default();
        config.paths.config_file = config_path.clone();
        config.paths.state_file = data_dir.join("state.json");
        config.paths.ballast_dir = ballast_dir.clone();
        config.ballast.auto_provision = false;

        let opts = InstallOptions {
            ballast_count: config.ballast.file_count,
            ballast_size_bytes: config.ballast.file_size_bytes,
            config,
            ballast_path: Some(ballast_dir),
            preserve_existing_config: false,
            dry_run: false,
        };

        let report = run_install_sequence(&opts);
        assert!(report.success, "install should succeed: {report:?}");
        assert!(config_path.exists(), "config should be written");
        assert!(data_dir.exists(), "data dir should be created");
    }

    #[test]
    fn install_report_format_dry_run() {
        let report = InstallReport {
            steps: vec![
                InstallStep {
                    description: "Create data directory".into(),
                    done: false,
                    error: None,
                },
                InstallStep {
                    description: "Write config".into(),
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
        assert!(output.contains("dry-run"));
        assert!(output.contains("[PLAN]"));
    }

    #[test]
    fn install_report_format_success() {
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
        assert!(output.contains("[DONE]"));
        assert!(output.contains("10 files = 10 GB"));
        assert!(output.contains("/etc/sbh/config.toml"));
    }

    #[test]
    fn install_report_format_failure() {
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
    fn report_serializes_to_json() {
        let report = InstallReport::new(false);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"success\":false"));
        assert!(json.contains("\"dry_run\":false"));
    }

    #[test]
    fn install_options_default_matches_config() {
        let opts = InstallOptions::default();
        let config = Config::default();
        assert_eq!(opts.ballast_count, config.ballast.file_count);
        assert_eq!(opts.ballast_size_bytes, config.ballast.file_size_bytes);
    }

    #[test]
    fn install_sequence_with_bundle_preflight_validates_integrity() {
        let tmp = TempDir::new().unwrap();
        let host = HostSpecifier::detect().unwrap();
        let contract =
            resolve_installer_artifact_contract(host, ReleaseChannel::Stable, Some("0.9.1"))
                .unwrap();

        let archive_name = contract.asset_name();
        let checksum_name = contract.checksum_name();
        let archive_path = tmp.path().join(&archive_name);
        let archive_bytes = b"offline-bundle-archive";
        std::fs::write(&archive_path, archive_bytes).unwrap();

        let checksum = Sha256::digest(archive_bytes);
        let checksum_hex = hex_lower(checksum);
        std::fs::write(
            tmp.path().join(&checksum_name),
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
        let manifest_path = tmp.path().join("bundle-manifest.json");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let mut config = Config::default();
        config.paths.config_file = tmp.path().join("config").join("config.toml");
        config.paths.state_file = tmp.path().join("data").join("state.json");
        config.paths.ballast_dir = tmp.path().join("ballast");
        config.ballast.auto_provision = false;

        let opts = InstallOptions {
            ballast_count: config.ballast.file_count,
            ballast_size_bytes: config.ballast.file_size_bytes,
            config,
            ballast_path: None,
            preserve_existing_config: false,
            dry_run: false,
        };

        let report = run_install_sequence_with_bundle(&opts, Some(&manifest_path));
        assert!(
            report.success,
            "bundle preflight should succeed: {report:?}"
        );
        assert!(
            report
                .steps
                .iter()
                .any(|step| step.description.contains("Validated offline bundle")),
            "report should include bundle validation step"
        );
        assert!(
            report.steps.iter().any(|step| step
                .description
                .contains("Verified offline bundle artifact")),
            "report should include bundle integrity verification step"
        );
    }

    /// bd-ncxh: the ballast an install is told to provision is the ballast
    /// the written config tells the daemon to keep.
    #[test]
    fn install_writes_the_requested_ballast_into_the_config() {
        let tmp = TempDir::new().unwrap();
        let mut config = Config::default();
        config.paths.config_file = tmp.path().join("config").join("config.toml");
        config.paths.state_file = tmp.path().join("data").join("state.json");
        config.paths.ballast_dir = tmp.path().join("ballast");
        let requested_ballast_dir = tmp.path().join("custom-reserve");
        assert_ne!(config.ballast.file_count, 2);
        let opts = InstallOptions {
            config: config.clone(),
            ballast_count: 2,
            ballast_size_bytes: 1024 * 1024,
            ballast_path: Some(requested_ballast_dir.clone()),
            preserve_existing_config: false,
            dry_run: false,
        };

        let report = run_install_sequence(&opts);
        assert!(report.success, "{report:?}");
        let written: Config =
            toml::from_str(&std::fs::read_to_string(&config.paths.config_file).unwrap()).unwrap();
        written.validate().unwrap();
        assert_eq!(written.ballast.file_count, 2);
        assert_eq!(written.ballast.file_size_bytes, 1024 * 1024);
        assert_eq!(written.paths.ballast_dir, requested_ballast_dir);
        assert_eq!(
            report.ballast_dir.as_deref(),
            Some(requested_ballast_dir.as_path())
        );
        assert!(
            !config.paths.ballast_dir.exists(),
            "the overridden default directory must not be provisioned"
        );
    }

    #[test]
    fn disabled_ballast_is_skipped_and_its_effective_settings_are_persisted() {
        let tmp = TempDir::new().unwrap();
        let mut config = Config::default();
        config.paths.config_file = tmp.path().join("config").join("config.toml");
        config.paths.state_file = tmp.path().join("data").join("state.json");
        config.paths.ballast_dir = tmp.path().join("default-ballast");
        config.ballast.auto_provision = false;
        let requested_ballast_dir = tmp.path().join("custom-reserve");
        let mut opts = InstallOptions {
            config: config.clone(),
            ballast_count: 3,
            ballast_size_bytes: 4096,
            ballast_path: Some(requested_ballast_dir.clone()),
            preserve_existing_config: false,
            dry_run: true,
        };

        for dry_run in [true, false] {
            opts.dry_run = dry_run;
            let report = run_install_sequence(&opts);
            assert!(report.success, "{report:?}");
            assert_eq!(report.ballast_files_created, 0);
            assert_eq!(report.ballast_bytes, 0);
            assert!(report.ballast_dir.is_none());
            assert!(!config.paths.ballast_dir.exists());
            assert!(!requested_ballast_dir.exists());
            let skipped = report
                .steps
                .iter()
                .find(|step| {
                    step.description == "Skip ballast provisioning (ballast.auto_provision=false)"
                })
                .expect("disabled provisioning must be explicit in the report");
            assert_eq!(skipped.done, !dry_run);
            assert!(skipped.error.is_none());
            assert!(!report.steps.iter().any(|step| {
                step.description.starts_with("Provision ballast:")
                    || step.description.starts_with("Provisioned ballast:")
            }));
            if dry_run {
                assert!(!config.paths.config_file.exists());
                assert!(!config.paths.state_file.parent().unwrap().exists());
                assert!(report.steps.iter().all(|step| !step.done));
            }
        }

        let written: Config =
            toml::from_str(&std::fs::read_to_string(&config.paths.config_file).unwrap()).unwrap();
        written.validate().unwrap();
        assert!(!written.ballast.auto_provision);
        assert_eq!(written.ballast.file_count, 3);
        assert_eq!(written.ballast.file_size_bytes, 4096);
        assert_eq!(written.paths.ballast_dir, requested_ballast_dir);
        assert_eq!(opts.config.paths.ballast_dir, config.paths.ballast_dir);
    }

    #[test]
    fn install_preserves_existing_config_bytes() {
        let tmp = TempDir::new().unwrap();
        let mut config = Config::default();
        config.paths.config_file = tmp.path().join("config.toml");
        config.paths.state_file = tmp.path().join("data/state.json");
        config.paths.ballast_dir = tmp.path().join("ballast");
        config.ballast.auto_provision = false;
        let original = format!(
            "# Keep this operator comment and formatting.\n\n{}\n",
            toml::to_string_pretty(&config).unwrap()
        );
        std::fs::write(&config.paths.config_file, &original).unwrap();
        let mut opts = InstallOptions {
            ballast_count: config.ballast.file_count,
            ballast_size_bytes: config.ballast.file_size_bytes,
            config: config.clone(),
            ballast_path: None,
            preserve_existing_config: true,
            dry_run: true,
        };

        for dry_run in [true, false] {
            opts.dry_run = dry_run;
            let report = run_install_sequence(&opts);
            assert!(report.success, "{report:?}");
            assert_eq!(
                std::fs::read_to_string(&config.paths.config_file).unwrap(),
                original
            );
            let preserved = report
                .steps
                .iter()
                .find(|step| step.description.starts_with("Preserve existing config:"))
                .expect("report must name the preserved config");
            assert_eq!(preserved.done, !dry_run);
            assert_eq!(report.config_path.is_some(), !dry_run);
            assert!(!config.paths.ballast_dir.exists());
            if dry_run {
                assert!(!config.paths.state_file.parent().unwrap().exists());
            }
        }
    }

    #[test]
    fn preserve_requires_a_readable_existing_config_before_creating_data() {
        for directory_instead_of_file in [false, true] {
            for dry_run in [true, false] {
                let tmp = TempDir::new().unwrap();
                let mut config = Config::default();
                config.paths.config_file = tmp.path().join("config.toml");
                config.paths.state_file = tmp.path().join("data/state.json");
                config.paths.ballast_dir = tmp.path().join("ballast");
                config.ballast.auto_provision = false;
                if directory_instead_of_file {
                    std::fs::create_dir(&config.paths.config_file).unwrap();
                }
                let opts = InstallOptions {
                    ballast_count: config.ballast.file_count,
                    ballast_size_bytes: config.ballast.file_size_bytes,
                    config: config.clone(),
                    ballast_path: None,
                    preserve_existing_config: true,
                    dry_run,
                };

                let report = run_install_sequence(&opts);
                assert!(!report.success, "{report:?}");
                assert_eq!(report.steps.len(), 1);
                assert!(report.steps[0].error.is_some());
                assert!(report.config_path.is_none());
                assert!(!config.paths.state_file.parent().unwrap().exists());
                assert!(!config.paths.ballast_dir.exists());
                assert_eq!(config.paths.config_file.is_dir(), directory_instead_of_file);
            }
        }
    }

    #[test]
    fn preserve_rejects_unpersisted_ballast_overrides() {
        let tmp = TempDir::new().unwrap();
        let mut config = Config::default();
        config.paths.config_file = tmp.path().join("config.toml");
        config.paths.state_file = tmp.path().join("data/state.json");
        config.paths.ballast_dir = tmp.path().join("ballast");
        config.ballast.auto_provision = false;
        let original = toml::to_string_pretty(&config).unwrap();
        std::fs::write(&config.paths.config_file, &original).unwrap();
        let base = InstallOptions {
            ballast_count: config.ballast.file_count,
            ballast_size_bytes: config.ballast.file_size_bytes,
            config: config.clone(),
            ballast_path: None,
            preserve_existing_config: true,
            dry_run: false,
        };
        let overrides = [
            InstallOptions {
                ballast_count: 2,
                ..base.clone()
            },
            InstallOptions {
                ballast_size_bytes: 4096,
                ..base.clone()
            },
            InstallOptions {
                ballast_path: Some(tmp.path().join("other-ballast")),
                ..base
            },
        ];
        for opts in overrides {
            let report = run_install_sequence(&opts);
            assert!(!report.success, "{report:?}");
            assert!(
                report.steps[0]
                    .error
                    .as_deref()
                    .is_some_and(|error| { error.contains("unpersisted ballast overrides") })
            );
            assert_eq!(
                std::fs::read_to_string(&config.paths.config_file).unwrap(),
                original
            );
            assert!(!config.paths.state_file.parent().unwrap().exists());
            assert!(!config.paths.ballast_dir.exists());
            assert!(!tmp.path().join("other-ballast").exists());
        }
    }

    #[test]
    fn invalid_effective_install_settings_cannot_overwrite_config_or_create_data() {
        for (count, size) in [(0, 4096), (1, 0), (1, 4095), (100_001, 4096)] {
            for dry_run in [true, false] {
                let tmp = TempDir::new().unwrap();
                let mut config = Config::default();
                config.paths.config_file = tmp.path().join("config.toml");
                config.paths.state_file = tmp.path().join("data").join("state.json");
                config.paths.ballast_dir = tmp.path().join("default-ballast");
                config.ballast.auto_provision = false;
                config.validate().unwrap();
                let original = toml::to_string_pretty(&config).unwrap();
                std::fs::write(&config.paths.config_file, &original).unwrap();
                let requested_ballast_dir = tmp.path().join("custom-reserve");
                let opts = InstallOptions {
                    config: config.clone(),
                    ballast_count: count,
                    ballast_size_bytes: size,
                    ballast_path: Some(requested_ballast_dir.clone()),
                    preserve_existing_config: false,
                    dry_run,
                };

                let report = run_install_sequence(&opts);
                assert!(!report.success, "{report:?}");
                assert_eq!(report.steps.len(), 1);
                assert_eq!(
                    report.steps[0].description,
                    "Validate install configuration"
                );
                assert!(report.steps[0].error.is_some());
                assert!(report.config_path.is_none());
                assert!(report.data_dir.is_none());
                assert!(report.ballast_dir.is_none());
                assert_eq!(
                    std::fs::read_to_string(&config.paths.config_file).unwrap(),
                    original
                );
                assert!(!config.paths.state_file.parent().unwrap().exists());
                assert!(!config.paths.ballast_dir.exists());
                assert!(!requested_ballast_dir.exists());
            }
        }
    }

    #[test]
    fn install_sequence_with_bundle_preflight_requires_sigstore_when_bundle_present() {
        let tmp = TempDir::new().unwrap();
        let host = HostSpecifier::detect().unwrap();
        let contract =
            resolve_installer_artifact_contract(host, ReleaseChannel::Stable, Some("0.9.1"))
                .unwrap();

        let archive_name = contract.asset_name();
        let checksum_name = contract.checksum_name();
        let sigstore_name = contract.sigstore_bundle_name();
        let archive_path = tmp.path().join(&archive_name);
        let archive_bytes = b"offline-bundle-archive";
        std::fs::write(&archive_path, archive_bytes).unwrap();
        std::fs::write(tmp.path().join(&sigstore_name), "{\"invalid\":true}\n").unwrap();

        let checksum = Sha256::digest(archive_bytes);
        let checksum_hex = hex_lower(checksum);
        std::fs::write(
            tmp.path().join(&checksum_name),
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
                sigstore_bundle: Some(sigstore_name),
            }],
        };
        let manifest_path = tmp.path().join("bundle-manifest.json");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let mut config = Config::default();
        config.paths.config_file = tmp.path().join("config").join("config.toml");
        config.paths.state_file = tmp.path().join("data").join("state.json");
        config.paths.ballast_dir = tmp.path().join("ballast");
        config.ballast.auto_provision = false;

        let opts = InstallOptions {
            ballast_count: config.ballast.file_count,
            ballast_size_bytes: config.ballast.file_size_bytes,
            config,
            ballast_path: None,
            preserve_existing_config: false,
            dry_run: false,
        };

        let report = run_install_sequence_with_bundle(&opts, Some(&manifest_path));
        assert!(
            !report.success,
            "sigstore bundle should be enforced in preflight: {report:?}"
        );
        assert!(
            report.steps.iter().any(|step| step
                .description
                .contains("Verify offline bundle artifact integrity")
                && step
                    .error
                    .as_deref()
                    .is_some_and(|err| err.contains("sigstore_required_"))),
            "report should include required sigstore integrity denial"
        );
    }

    #[test]
    fn install_sequence_with_bundle_preflight_rejects_bad_checksum() {
        let tmp = TempDir::new().unwrap();
        let host = HostSpecifier::detect().unwrap();
        let contract =
            resolve_installer_artifact_contract(host, ReleaseChannel::Stable, Some("0.9.1"))
                .unwrap();

        let archive_name = contract.asset_name();
        let checksum_name = contract.checksum_name();
        std::fs::write(tmp.path().join(&archive_name), b"offline-bundle-archive").unwrap();
        std::fs::write(
            tmp.path().join(&checksum_name),
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
        let manifest_path = tmp.path().join("bundle-manifest.json");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let mut config = Config::default();
        config.paths.config_file = tmp.path().join("config").join("config.toml");
        config.paths.state_file = tmp.path().join("data").join("state.json");
        config.paths.ballast_dir = tmp.path().join("ballast");
        config.ballast.auto_provision = false;

        let opts = InstallOptions {
            ballast_count: config.ballast.file_count,
            ballast_size_bytes: config.ballast.file_size_bytes,
            config,
            ballast_path: None,
            preserve_existing_config: false,
            dry_run: false,
        };

        let report = run_install_sequence_with_bundle(&opts, Some(&manifest_path));
        assert!(!report.success, "bundle preflight should fail: {report:?}");
        assert!(
            report.steps.iter().any(|step| step
                .description
                .contains("Verify offline bundle artifact integrity")
                && step.error.is_some()),
            "report should include failed integrity verification step"
        );
    }

    #[test]
    fn install_sequence_with_bundle_preflight_dry_run_is_plan_only() {
        let opts = InstallOptions {
            dry_run: true,
            ..Default::default()
        };
        let missing_manifest = PathBuf::from("/tmp/does-not-exist-bundle-manifest.json");

        let report = run_install_sequence_with_bundle(&opts, Some(&missing_manifest));
        assert!(report.success, "dry-run should stay successful: {report:?}");
        assert!(
            report.steps.iter().any(|step| step
                .description
                .contains("Validate offline bundle manifest")),
            "dry-run should include bundle validation plan step"
        );
        assert!(
            report
                .steps
                .iter()
                .all(|step| !step.done && step.error.is_none()),
            "dry-run should not execute steps"
        );
    }

    #[test]
    fn install_sequence_with_bundle_preflight_fails_on_missing_manifest() {
        let tmp = TempDir::new().unwrap();
        let mut config = Config::default();
        config.paths.config_file = tmp.path().join("config").join("config.toml");
        config.paths.state_file = tmp.path().join("data").join("state.json");
        config.paths.ballast_dir = tmp.path().join("ballast");
        config.ballast.auto_provision = false;

        let opts = InstallOptions {
            ballast_count: config.ballast.file_count,
            ballast_size_bytes: config.ballast.file_size_bytes,
            config,
            ballast_path: None,
            preserve_existing_config: false,
            dry_run: false,
        };
        let missing_manifest = tmp.path().join("missing-bundle-manifest.json");

        let report = run_install_sequence_with_bundle(&opts, Some(&missing_manifest));
        assert!(!report.success, "missing bundle manifest should fail");
        assert!(
            report.steps.iter().any(
                |step| step.description == "Validate offline bundle manifest"
                    && step.error.is_some()
            ),
            "report should include missing manifest failure"
        );
    }
}
