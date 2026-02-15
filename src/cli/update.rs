//! Update orchestration for `sbh update`.
//!
//! Shares artifact resolution and verification logic with the installer
//! (`resolve_updater_artifact_contract`, `verify_artifact_supply_chain`)
//! so install and update paths cannot drift.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

use super::{
    HostSpecifier, IntegrityDecision, ReleaseArtifactContract, ReleaseChannel, SigstorePolicy,
    VerificationMode, resolve_updater_artifact_contract, verify_artifact_supply_chain,
};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Options controlling the update orchestration.
#[derive(Debug, Clone)]
pub struct UpdateOptions {
    /// Only check, do not apply.
    pub check_only: bool,
    /// Pinned version (e.g. "v0.2.1"). None = latest.
    pub pinned_version: Option<String>,
    /// Force re-download even when versions match.
    pub force: bool,
    /// Target install directory.
    pub install_dir: PathBuf,
    /// Skip integrity verification.
    pub no_verify: bool,
    /// Dry-run mode.
    pub dry_run: bool,
}

/// Structured report from an update check or apply.
#[derive(Debug, Clone, Serialize)]
pub struct UpdateReport {
    pub current_version: String,
    pub target_version: Option<String>,
    pub update_available: bool,
    pub applied: bool,
    pub check_only: bool,
    pub dry_run: bool,
    pub artifact_url: Option<String>,
    pub install_path: Option<PathBuf>,
    pub steps: Vec<UpdateStep>,
    pub success: bool,
    pub follow_up: Vec<String>,
}

/// A single step in the update sequence.
#[derive(Debug, Clone, Serialize)]
pub struct UpdateStep {
    pub description: String,
    pub done: bool,
    pub error: Option<String>,
}

impl UpdateReport {
    fn new(current_version: &str, check_only: bool, dry_run: bool) -> Self {
        Self {
            current_version: current_version.to_string(),
            target_version: None,
            update_available: false,
            applied: false,
            check_only,
            dry_run,
            artifact_url: None,
            install_path: None,
            steps: Vec::new(),
            success: false,
            follow_up: Vec::new(),
        }
    }

    fn step_ok(&mut self, description: impl Into<String>) {
        self.steps.push(UpdateStep {
            description: description.into(),
            done: true,
            error: None,
        });
    }

    fn step_fail(&mut self, description: impl Into<String>, error: impl Into<String>) {
        self.steps.push(UpdateStep {
            description: description.into(),
            done: false,
            error: Some(error.into()),
        });
    }

    fn step_plan(&mut self, description: impl Into<String>) {
        self.steps.push(UpdateStep {
            description: description.into(),
            done: false,
            error: None,
        });
    }
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/// Run the full update sequence and return a structured report.
pub fn run_update_sequence(opts: &UpdateOptions) -> UpdateReport {
    let current = current_version();
    let mut report = UpdateReport::new(&current, opts.check_only, opts.dry_run);

    // Step 1: Resolve host platform.
    let host = match HostSpecifier::detect() {
        Ok(h) => {
            report.step_ok(format!("Detected platform: {}/{}", h.os, h.arch));
            h
        }
        Err(e) => {
            report.step_fail("Detect platform", e.to_string());
            return report;
        }
    };

    // Step 2: Resolve artifact contract (shared with installer).
    let contract = match resolve_updater_artifact_contract(
        host,
        ReleaseChannel::Stable,
        opts.pinned_version.as_deref(),
    ) {
        Ok(c) => {
            report.step_ok(format!("Resolved artifact: {}", c.asset_name()));
            report.artifact_url = Some(c.asset_url());
            c
        }
        Err(e) => {
            report.step_fail("Resolve artifact contract", e.to_string());
            return report;
        }
    };

    // Step 3: Resolve target version tag.
    let target_tag = match resolve_target_tag(&contract, opts.pinned_version.as_deref()) {
        Ok(tag) => {
            report.target_version = Some(tag.clone());
            report.step_ok(format!("Target version: {tag}"));
            tag
        }
        Err(e) => {
            report.step_fail("Resolve target version", e.to_string());
            return report;
        }
    };

    // Step 4: Compare versions.
    let current_tag = format!("v{current}");
    if current_tag == target_tag && !opts.force {
        report.update_available = false;
        report.step_ok(format!("Already at {target_tag}, no update needed"));
        report.success = true;
        return report;
    }
    report.update_available = true;
    report.step_ok(format!("Update available: {current_tag} -> {target_tag}"));

    if opts.check_only {
        report.success = true;
        return report;
    }

    // Step 5: Determine install path.
    let install_path = opts.install_dir.join("sbh");
    report.install_path = Some(install_path.clone());

    if opts.dry_run {
        report.step_plan(format!("Would download {}", contract.asset_url()));
        report.step_plan(format!("Would install to {}", install_path.display()));
        report.step_plan(format!(
            "Would verify integrity: {}",
            if opts.no_verify { "skip" } else { "sha256" }
        ));
        report.success = true;
        report
            .follow_up
            .push("After update, restart the sbh service.".to_string());
        return report;
    }

    // Step 6: Download artifact + checksum via curl.
    let tmp_dir = match tempdir_for_update() {
        Ok(d) => d,
        Err(e) => {
            report.step_fail("Create temp directory", e.to_string());
            return report;
        }
    };

    let archive_path = tmp_dir.join(contract.asset_name());
    let checksum_path = tmp_dir.join(contract.checksum_name());
    let archive_url = contract.asset_url();
    let checksum_url = format!("{archive_url}.sha256");

    if let Err(e) = curl_download(&archive_url, &archive_path) {
        report.step_fail("Download artifact", e.to_string());
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return report;
    }
    report.step_ok(format!("Downloaded {}", contract.asset_name()));

    if let Err(e) = curl_download(&checksum_url, &checksum_path) {
        report.step_fail("Download checksum", e.to_string());
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return report;
    }
    report.step_ok(format!("Downloaded {}", contract.checksum_name()));

    // Step 7: Verify integrity (shared code path with installer).
    let verification_mode = if opts.no_verify {
        VerificationMode::BypassNoVerify
    } else {
        VerificationMode::Enforce
    };

    let expected_checksum = match std::fs::read_to_string(&checksum_path) {
        Ok(s) => s,
        Err(e) => {
            report.step_fail("Read checksum file", e.to_string());
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return report;
        }
    };

    match verify_artifact_supply_chain(
        &archive_path,
        &expected_checksum,
        verification_mode,
        SigstorePolicy::Disabled,
        None,
    ) {
        Ok(outcome) => {
            if matches!(outcome.decision, IntegrityDecision::Allow) {
                report.step_ok("Integrity verification passed");
            } else {
                report.step_fail(
                    "Integrity verification",
                    format!("denied: {:?}", outcome.reason_codes),
                );
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return report;
            }
        }
        Err(e) => {
            report.step_fail("Integrity verification", e.to_string());
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return report;
        }
    }

    // Step 8: Extract and install with backup + rollback.
    match extract_and_install(&archive_path, &install_path) {
        Ok(()) => {
            report.step_ok(format!("Installed to {}", install_path.display()));
            report.applied = true;
        }
        Err(e) => {
            report.step_fail("Install binary", e.to_string());
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return report;
        }
    }

    let _ = std::fs::remove_dir_all(&tmp_dir);
    report.success = true;
    report.follow_up.push(format!(
        "Updated {current_tag} -> {target_tag}. Restart the sbh service to use the new version.",
    ));
    report
}

/// Format update report for terminal output.
#[must_use]
pub fn format_update_report(report: &UpdateReport) -> String {
    let mut out = String::new();

    for step in &report.steps {
        let icon = if step.done && step.error.is_none() {
            "[ OK ]"
        } else if step.error.is_some() {
            "[FAIL]"
        } else {
            "[PLAN]"
        };
        let _ = writeln!(out, "  {icon} {}", step.description);
        if let Some(err) = &step.error {
            let _ = writeln!(out, "         {err}");
        }
    }

    let _ = writeln!(out);
    if report.check_only {
        if report.update_available {
            if let Some(target) = &report.target_version {
                let _ = writeln!(
                    out,
                    "Update available: v{} -> {target}",
                    report.current_version
                );
                let _ = writeln!(out, "Run `sbh update` to apply.");
            }
        } else {
            let _ = writeln!(out, "Already up to date (v{}).", report.current_version);
        }
    } else if report.applied {
        let _ = writeln!(out, "Update applied successfully.");
    } else if report.dry_run {
        let _ = writeln!(out, "Dry-run complete. No changes were made.");
    } else if !report.success {
        let _ = writeln!(out, "Update failed. See errors above.");
    }

    for action in &report.follow_up {
        let _ = writeln!(out, "  -> {action}");
    }

    out
}

/// Resolve the default install directory.
pub fn default_install_dir(system: bool) -> PathBuf {
    if system {
        PathBuf::from("/usr/local/bin")
    } else {
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                return parent.to_path_buf();
            }
        }
        std::env::var_os("HOME")
            .map_or_else(|| PathBuf::from("/usr/local/bin"), PathBuf::from)
            .join(".local/bin")
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn current_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Resolve target tag: pinned version or latest from GitHub API.
fn resolve_target_tag(
    contract: &ReleaseArtifactContract,
    pinned: Option<&str>,
) -> std::result::Result<String, String> {
    if let Some(version) = pinned {
        let tag = if version.starts_with('v') {
            version.to_string()
        } else {
            format!("v{version}")
        };
        return Ok(tag);
    }

    // Query GitHub latest release via curl.
    let api_url = format!(
        "https://api.github.com/repos/{}/releases/latest",
        contract.repository
    );

    let output = Command::new("curl")
        .args(["-sL", "-H", "Accept: application/json", &api_url])
        .output()
        .map_err(|e| format!("curl not found or failed: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "GitHub API request failed (status {})",
            output.status
        ));
    }

    let body = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("failed to parse API response: {e}"))?;

    json.get("tag_name")
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| "no tag_name in GitHub API response".to_string())
}

/// Download a URL to a local path using curl.
fn curl_download(url: &str, dest: &Path) -> std::result::Result<(), String> {
    let status = Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(dest)
        .arg(url)
        .status()
        .map_err(|e| format!("curl not found or failed: {e}"))?;

    if !status.success() {
        return Err(format!("download failed (status {status})"));
    }

    Ok(())
}

/// Extract binary from tar.xz and install with backup + rollback.
fn extract_and_install(archive_path: &Path, install_path: &Path) -> std::result::Result<(), String> {
    let extract_dir = archive_path.with_extension("extract");
    std::fs::create_dir_all(&extract_dir)
        .map_err(|e| format!("failed to create extract dir: {e}"))?;

    let tar_status = Command::new("tar")
        .args(["xJf"])
        .arg(archive_path)
        .arg("-C")
        .arg(&extract_dir)
        .status()
        .map_err(|e| format!("failed to run tar: {e}"))?;

    if !tar_status.success() {
        let _ = std::fs::remove_dir_all(&extract_dir);
        return Err("tar extraction failed".to_string());
    }

    let new_binary = extract_dir.join("sbh");
    if !new_binary.exists() {
        let _ = std::fs::remove_dir_all(&extract_dir);
        return Err("extracted archive does not contain sbh binary".to_string());
    }

    // Ensure install directory exists.
    if let Some(parent) = install_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create install dir: {e}"))?;
    }

    // Backup current binary.
    let backup_path = install_path.with_extension("old");
    if install_path.exists() {
        std::fs::copy(install_path, &backup_path)
            .map_err(|e| format!("failed to backup current binary: {e}"))?;
    }

    // Replace binary (copy, not rename, to handle cross-filesystem).
    if let Err(e) = std::fs::copy(&new_binary, install_path) {
        // Rollback.
        if backup_path.exists() {
            let _ = std::fs::copy(&backup_path, install_path);
        }
        let _ = std::fs::remove_dir_all(&extract_dir);
        return Err(format!("failed to install new binary (rolled back): {e}"));
    }

    // Set executable permissions on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(install_path, std::fs::Permissions::from_mode(0o755));
    }

    let _ = std::fs::remove_dir_all(&extract_dir);
    Ok(())
}

/// Create a temporary directory for the update download.
fn tempdir_for_update() -> std::result::Result<PathBuf, String> {
    let base = std::env::temp_dir().join("sbh_update");
    std::fs::create_dir_all(&base).map_err(|e| format!("failed to create temp dir: {e}"))?;

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let dir = base.join(format!("{ts}"));
    std::fs::create_dir_all(&dir).map_err(|e| format!("failed to create temp subdir: {e}"))?;

    Ok(dir)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_version_is_not_empty() {
        let ver = current_version();
        assert!(!ver.is_empty());
    }

    #[test]
    fn default_install_dir_system() {
        assert_eq!(default_install_dir(true), PathBuf::from("/usr/local/bin"));
    }

    #[test]
    fn default_install_dir_user_resolves() {
        let dir = default_install_dir(false);
        assert!(!dir.to_string_lossy().is_empty());
    }

    #[test]
    fn report_step_tracking() {
        let mut report = UpdateReport::new("0.1.0", false, false);
        report.step_ok("Step 1");
        report.step_fail("Step 2", "error");
        report.step_plan("Step 3");
        assert_eq!(report.steps.len(), 3);
        assert!(report.steps[0].done);
        assert!(!report.steps[1].done);
        assert!(report.steps[1].error.is_some());
        assert!(!report.steps[2].done);
        assert!(report.steps[2].error.is_none());
    }

    #[test]
    fn format_check_only_up_to_date() {
        let mut report = UpdateReport::new("0.1.0", true, false);
        report.update_available = false;
        report.success = true;
        let output = format_update_report(&report);
        assert!(output.contains("up to date"));
    }

    #[test]
    fn format_check_only_update_available() {
        let mut report = UpdateReport::new("0.1.0", true, false);
        report.update_available = true;
        report.target_version = Some("v0.2.0".to_string());
        report.success = true;
        let output = format_update_report(&report);
        assert!(output.contains("Update available"));
        assert!(output.contains("v0.2.0"));
    }

    #[test]
    fn format_applied() {
        let mut report = UpdateReport::new("0.1.0", false, false);
        report.applied = true;
        report.success = true;
        let output = format_update_report(&report);
        assert!(output.contains("applied successfully"));
    }

    #[test]
    fn format_dry_run() {
        let mut report = UpdateReport::new("0.1.0", false, true);
        report.success = true;
        report.step_plan("Would download artifact");
        let output = format_update_report(&report);
        assert!(output.contains("Dry-run"));
        assert!(output.contains("[PLAN]"));
    }

    #[test]
    fn format_follow_up() {
        let mut report = UpdateReport::new("0.1.0", false, false);
        report.applied = true;
        report.success = true;
        report.follow_up.push("Restart the service".to_string());
        let output = format_update_report(&report);
        assert!(output.contains("Restart the service"));
    }

    #[test]
    fn pinned_version_resolved_directly() {
        let contract = resolve_updater_artifact_contract(
            HostSpecifier {
                os: super::super::HostOs::Linux,
                arch: super::super::HostArch::X86_64,
                abi: super::super::HostAbi::Gnu,
            },
            ReleaseChannel::Stable,
            Some("0.2.0"),
        )
        .unwrap();

        let tag = resolve_target_tag(&contract, Some("0.2.0")).unwrap();
        assert_eq!(tag, "v0.2.0");
    }

    #[test]
    fn pinned_version_with_v_prefix() {
        let contract = resolve_updater_artifact_contract(
            HostSpecifier {
                os: super::super::HostOs::Linux,
                arch: super::super::HostArch::X86_64,
                abi: super::super::HostAbi::Gnu,
            },
            ReleaseChannel::Stable,
            Some("v0.3.0"),
        )
        .unwrap();

        let tag = resolve_target_tag(&contract, Some("v0.3.0")).unwrap();
        assert_eq!(tag, "v0.3.0");
    }
}
