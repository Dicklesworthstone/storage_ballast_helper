//! Update orchestration for `sbh update`.
//!
//! Shares artifact resolution and verification logic with the installer
//! (`resolve_updater_artifact_contract`, `verify_artifact_supply_chain`)
//! so install and update paths cannot drift.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::random;
use serde::Serialize;

use crate::core::update_cache::{CachedUpdateMetadata, UpdateMetadataCache};

use super::{
    HostSpecifier, IntegrityDecision, ReleaseArtifactContract, ReleaseChannel, ReleaseLocator,
    SigstorePolicy, VerificationMode, resolve_bundle_artifact_contract,
    resolve_updater_artifact_contract, sigstore_policy_and_probe_for_bundle,
    verify_artifact_supply_chain,
};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Options controlling the update orchestration.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
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
    /// Maximum number of backups to retain after update.
    pub max_backups: usize,
    /// Path to update metadata cache.
    pub metadata_cache_file: PathBuf,
    /// TTL for update metadata cache entries.
    pub metadata_cache_ttl: Duration,
    /// Force refresh of metadata cache before checking.
    pub refresh_cache: bool,
    /// Emit update notices/follow-up prompts in human output.
    pub notices_enabled: bool,
    /// Optional offline bundle manifest path for airgapped updates.
    pub offline_bundle_manifest: Option<PathBuf>,
}

/// A single backup snapshot of a previous binary version.
#[derive(Debug, Clone, Serialize)]
pub struct BackupSnapshot {
    /// Unique identifier (timestamp-based directory name).
    pub id: String,
    /// Version string from metadata, or "unknown".
    pub version: String,
    /// Unix timestamp when the backup was created.
    pub timestamp: u64,
    /// Path to the backed-up binary file.
    pub path: PathBuf,
    /// Size of the backed-up binary in bytes.
    pub binary_size: u64,
}

/// Result of a backup inventory scan.
#[derive(Debug, Clone, Serialize)]
pub struct BackupInventory {
    pub backups: Vec<BackupSnapshot>,
    pub backup_dir: PathBuf,
}

/// Result of a rollback operation.
#[derive(Debug, Clone, Serialize)]
pub struct RollbackResult {
    pub success: bool,
    pub snapshot_id: String,
    pub restored_version: String,
    pub install_path: PathBuf,
    pub error: Option<String>,
}

/// Result of a prune operation.
#[derive(Debug, Clone, Serialize)]
pub struct PruneResult {
    pub kept: usize,
    pub removed: usize,
    pub removed_ids: Vec<String>,
}

/// Structured report from an update check or apply.
#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct UpdateReport {
    pub current_version: String,
    pub target_version: Option<String>,
    pub update_available: bool,
    pub applied: bool,
    pub check_only: bool,
    pub dry_run: bool,
    pub artifact_url: Option<String>,
    pub notices_enabled: bool,
    pub install_path: Option<PathBuf>,
    pub backup_id: Option<String>,
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
    fn new(current_version: &str, check_only: bool, dry_run: bool, notices_enabled: bool) -> Self {
        Self {
            current_version: current_version.to_string(),
            target_version: None,
            update_available: false,
            applied: false,
            check_only,
            dry_run,
            artifact_url: None,
            notices_enabled,
            install_path: None,
            backup_id: None,
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
// Backup store
// ---------------------------------------------------------------------------

/// Manages the backup store directory for update rollbacks.
///
/// Each backup is a timestamped directory containing the binary and a
/// `backup.json` metadata file.
#[derive(Debug, Clone)]
pub struct BackupStore {
    dir: PathBuf,
}

impl BackupStore {
    /// Open backup store at the default location (`~/.local/share/sbh/backups/`).
    pub fn open_default() -> Self {
        Self::open(default_backup_dir())
    }

    /// Open backup store at a specific directory (useful for tests).
    pub fn open(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Directory used by this store.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Create a backup of the binary at `install_path`, tagged with `version`.
    pub fn create(
        &self,
        install_path: &Path,
        version: &str,
    ) -> std::result::Result<BackupSnapshot, String> {
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| format!("failed to create backup dir: {e}"))?;

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let id = format!("{ts}");

        let entry_dir = self.dir.join(&id);
        std::fs::create_dir_all(&entry_dir)
            .map_err(|e| format!("failed to create backup entry dir: {e}"))?;

        let dest = entry_dir.join("sbh");
        std::fs::copy(install_path, &dest)
            .map_err(|e| format!("failed to copy binary for backup: {e}"))?;

        let binary_size = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);

        let meta = serde_json::json!({
            "version": version,
            "timestamp": ts,
            "binary_size": binary_size,
        });
        let meta_path = entry_dir.join("backup.json");
        std::fs::write(
            &meta_path,
            serde_json::to_string_pretty(&meta).unwrap_or_default(),
        )
        .map_err(|e| format!("failed to write backup metadata: {e}"))?;

        Ok(BackupSnapshot {
            id,
            version: version.to_string(),
            timestamp: ts,
            binary_size,
            path: dest,
        })
    }

    /// List all backup entries, sorted newest-first.
    pub fn list(&self) -> Vec<BackupSnapshot> {
        let mut entries = Vec::new();

        let Ok(read_dir) = std::fs::read_dir(&self.dir) else {
            return entries;
        };

        for dir_entry in read_dir.flatten() {
            let entry_path = dir_entry.path();
            if !entry_path.is_dir() {
                continue;
            }
            let binary_path = entry_path.join("sbh");
            if !binary_path.exists() {
                continue;
            }

            let id = dir_entry.file_name().to_string_lossy().into_owned();
            let meta_path = entry_path.join("backup.json");

            if let Ok(meta_str) = std::fs::read_to_string(&meta_path)
                && let Ok(meta) = serde_json::from_str::<serde_json::Value>(&meta_str)
            {
                let version = meta
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let timestamp = meta
                    .get("timestamp")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                let binary_size = meta
                    .get("binary_size")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);

                entries.push(BackupSnapshot {
                    id,
                    version,
                    timestamp,
                    binary_size,
                    path: binary_path,
                });
                continue;
            }

            // Fallback: no valid metadata file.
            let binary_size = std::fs::metadata(&binary_path)
                .map(|m| m.len())
                .unwrap_or(0);
            entries.push(BackupSnapshot {
                id: id.clone(),
                version: "unknown".to_string(),
                timestamp: id.parse::<u64>().unwrap_or(0),
                binary_size,
                path: binary_path,
            });
        }

        entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        entries
    }

    /// Build a full inventory with the store directory path.
    pub fn inventory(&self) -> BackupInventory {
        BackupInventory {
            backups: self.list(),
            backup_dir: self.dir.clone(),
        }
    }

    /// Roll back to the most recent backup, or a specific one by `backup_id`.
    pub fn rollback(
        &self,
        install_path: &Path,
        backup_id: Option<&str>,
    ) -> std::result::Result<RollbackResult, String> {
        let entries = self.list();
        if entries.is_empty() {
            return Err("no backups available for rollback".to_string());
        }

        let snap = if let Some(id) = backup_id {
            entries
                .iter()
                .find(|e| e.id == id)
                .ok_or_else(|| format!("backup '{id}' not found"))?
        } else {
            &entries[0]
        };

        if !snap.path.exists() {
            return Ok(RollbackResult {
                success: false,
                snapshot_id: snap.id.clone(),
                restored_version: snap.version.clone(),
                install_path: install_path.to_path_buf(),
                error: Some(format!("backup binary missing: {}", snap.path.display())),
            });
        }

        if let Some(parent) = install_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create install dir: {e}"))?;
        }

        std::fs::copy(&snap.path, install_path)
            .map_err(|e| format!("failed to restore backup: {e}"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(install_path, std::fs::Permissions::from_mode(0o755));
        }

        Ok(RollbackResult {
            success: true,
            snapshot_id: snap.id.clone(),
            restored_version: snap.version.clone(),
            install_path: install_path.to_path_buf(),
            error: None,
        })
    }

    /// Prune old backups, keeping only the `keep` most recent entries.
    pub fn prune(&self, keep: usize) -> std::result::Result<PruneResult, String> {
        let entries = self.list();
        let mut removed_ids = Vec::new();

        if entries.len() <= keep {
            return Ok(PruneResult {
                kept: entries.len(),
                removed: 0,
                removed_ids,
            });
        }

        for entry in &entries[keep..] {
            let entry_dir = self.dir.join(&entry.id);
            if entry_dir.exists() {
                std::fs::remove_dir_all(&entry_dir)
                    .map_err(|e| format!("failed to remove backup {}: {e}", entry.id))?;
                removed_ids.push(entry.id.clone());
            }
        }

        Ok(PruneResult {
            kept: keep,
            removed: removed_ids.len(),
            removed_ids,
        })
    }
}

/// Default backup directory.
fn default_backup_dir() -> PathBuf {
    std::env::var_os("HOME").map_or_else(
        || PathBuf::from("/var/lib/sbh/backups"),
        |home| PathBuf::from(home).join(".local/share/sbh/backups"),
    )
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/// Run the full update sequence and return a structured report.
#[allow(clippy::too_many_lines)]
pub fn run_update_sequence(opts: &UpdateOptions) -> UpdateReport {
    let current = current_version();
    let mut report = UpdateReport::new(
        &current,
        opts.check_only,
        opts.dry_run,
        opts.notices_enabled,
    );

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

    // Step 2: Resolve artifact contract (shared with installer) or offline bundle contract.
    let mut bundle_archive_path = None;
    let mut bundle_checksum_path = None;
    let mut bundle_sigstore_path = None;
    let contract = if let Some(bundle_manifest_path) = opts.offline_bundle_manifest.as_deref() {
        match resolve_bundle_artifact_contract(host, bundle_manifest_path) {
            Ok(resolution) => {
                report.step_ok(format!(
                    "Resolved offline bundle artifact: {}",
                    resolution.contract.asset_name()
                ));
                bundle_archive_path = Some(resolution.archive_path.clone());
                bundle_checksum_path = Some(resolution.checksum_path.clone());
                bundle_sigstore_path.clone_from(&resolution.sigstore_bundle_path);
                resolution.contract
            }
            Err(e) => {
                report.step_fail("Resolve offline bundle contract", e.to_string());
                return report;
            }
        }
    } else {
        match resolve_updater_artifact_contract(
            host,
            ReleaseChannel::Stable,
            opts.pinned_version.as_deref(),
        ) {
            Ok(c) => {
                report.step_ok(format!("Resolved artifact: {}", c.asset_name()));
                c
            }
            Err(e) => {
                report.step_fail("Resolve artifact contract", e.to_string());
                return report;
            }
        }
    };

    // Step 3: Resolve target version tag.
    let target = if opts.offline_bundle_manifest.is_some() {
        if opts.refresh_cache {
            report.step_ok("Ignored --refresh-cache in offline bundle mode");
        }

        let target_tag = match &contract.locator {
            ReleaseLocator::Tag(tag) => tag.clone(),
            ReleaseLocator::Latest => {
                report.step_fail(
                    "Resolve target version",
                    "offline bundle contract must pin a release tag",
                );
                return report;
            }
        };

        if let Some(pinned) = opts.pinned_version.as_deref() {
            let normalized = normalize_tag(pinned);
            if normalized != target_tag {
                report.step_fail(
                    "Resolve target version",
                    format!(
                        "offline bundle tag mismatch: requested '{normalized}', bundle provides '{target_tag}'"
                    ),
                );
                return report;
            }
        }

        TargetMetadata {
            target_tag,
            artifact_url: bundle_archive_path.as_ref().map_or_else(
                || String::from("<bundle-archive>"),
                |path| path.display().to_string(),
            ),
            source: TargetMetadataSource::OfflineBundle,
            bundle_archive_path,
            bundle_checksum_path,
            bundle_sigstore_path,
        }
    } else {
        let cache =
            UpdateMetadataCache::new(opts.metadata_cache_file.clone(), opts.metadata_cache_ttl);
        match resolve_target_metadata_with_cache(
            &contract,
            opts.pinned_version.as_deref(),
            &cache,
            opts.refresh_cache,
            SystemTime::now(),
            |release_contract| resolve_target_tag(release_contract, None),
        ) {
            Ok(target) => target,
            Err(e) => {
                report.step_fail("Resolve target version", e);
                return report;
            }
        }
    };

    match target.source {
        TargetMetadataSource::Pinned => {}
        TargetMetadataSource::Cache => {
            report.step_ok("Loaded update metadata from cache");
        }
        TargetMetadataSource::Network => {
            if opts.refresh_cache {
                report.step_ok("Refreshed update metadata from network");
            } else {
                report.step_ok("Fetched update metadata from network");
            }
        }
        TargetMetadataSource::OfflineBundle => {
            report.step_ok("Loaded update metadata from offline bundle");
        }
    }
    report.target_version = Some(target.target_tag.clone());
    report.artifact_url = Some(target.artifact_url.clone());
    report.step_ok(format!("Target version: {}", target.target_tag));

    // Step 4: Compare versions.
    let current_tag = format!("v{current}");
    if current_tag == target.target_tag && !opts.force {
        report.update_available = false;
        report.step_ok(format!(
            "Already at {}, no update needed",
            target.target_tag
        ));
        report.success = true;
        return report;
    }
    report.update_available = true;
    report.step_ok(format!(
        "Update available: {current_tag} -> {}",
        target.target_tag
    ));

    if opts.check_only {
        report.success = true;
        return report;
    }

    // Step 5: Determine install path.
    let install_path = opts.install_dir.join("sbh");
    report.install_path = Some(install_path.clone());

    if opts.dry_run {
        if matches!(target.source, TargetMetadataSource::OfflineBundle) {
            report.step_plan(format!(
                "Would use offline bundle artifact {}",
                target.artifact_url
            ));
        } else {
            report.step_plan(format!("Would download {}", target.artifact_url));
        }
        report.step_plan(format!("Would install to {}", install_path.display()));
        report.step_plan(format!(
            "Would verify integrity: {}",
            if opts.no_verify { "skip" } else { "sha256" }
        ));
        report.success = true;
        if opts.notices_enabled {
            report
                .follow_up
                .push("After update, restart the sbh service.".to_string());
        }
        return report;
    }

    // Step 6: Download artifact + checksum via curl.
    let tmp_dir = match tempdir_for_update() {
        Ok(d) => d,
        Err(e) => {
            report.step_fail("Create temp directory", e);
            return report;
        }
    };

    let archive_path = tmp_dir.join(contract.asset_name());
    let checksum_path = tmp_dir.join(contract.checksum_name());
    if let (Some(source_archive), Some(source_checksum)) = (
        target.bundle_archive_path.as_ref(),
        target.bundle_checksum_path.as_ref(),
    ) {
        if let Err(e) = std::fs::copy(source_archive, &archive_path) {
            report.step_fail("Load offline bundle artifact", e.to_string());
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return report;
        }
        report.step_ok(format!(
            "Loaded bundle artifact {}",
            source_archive.display()
        ));

        if let Err(e) = std::fs::copy(source_checksum, &checksum_path) {
            report.step_fail("Load offline bundle checksum", e.to_string());
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return report;
        }
        report.step_ok(format!(
            "Loaded bundle checksum {}",
            source_checksum.display()
        ));
    } else {
        let archive_url = target.artifact_url;
        let checksum_url = format!("{archive_url}.sha256");

        if let Err(e) = curl_download(&archive_url, &archive_path) {
            report.step_fail("Download artifact", e);
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return report;
        }
        report.step_ok(format!("Downloaded {}", contract.asset_name()));

        if let Err(e) = curl_download(&checksum_url, &checksum_path) {
            report.step_fail("Download checksum", e);
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return report;
        }
        report.step_ok(format!("Downloaded {}", contract.checksum_name()));
    }

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
    let (sigstore_policy, sigstore_probe) = if verification_mode == VerificationMode::Enforce {
        sigstore_policy_and_probe_for_bundle(&archive_path, target.bundle_sigstore_path.as_deref())
    } else {
        (SigstorePolicy::Disabled, None)
    };

    match verify_artifact_supply_chain(
        &archive_path,
        &expected_checksum,
        verification_mode,
        sigstore_policy,
        sigstore_probe,
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

    // Step 8: Backup current binary before replacement.
    if install_path.exists() {
        let store = BackupStore::open_default();
        match store.create(&install_path, &current) {
            Ok(snap) => {
                report.backup_id = Some(snap.id.clone());
                report.step_ok(format!("Backed up v{} as {}", current, snap.id));
                let _ = store.prune(opts.max_backups);
            }
            Err(e) => {
                report.step_fail("Backup current binary", e);
            }
        }
    }

    // Step 9: Extract and install with atomic rollback.
    match extract_and_install(&archive_path, &install_path) {
        Ok(()) => {
            report.step_ok(format!("Installed to {}", install_path.display()));
            report.applied = true;
        }
        Err(e) => {
            report.step_fail("Install binary", e);
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return report;
        }
    }

    let _ = std::fs::remove_dir_all(&tmp_dir);
    report.success = true;
    if opts.notices_enabled {
        report.follow_up.push(format!(
            "Updated {current_tag} -> {}. Restart the sbh service to use the new version.",
            target.target_tag
        ));
    }
    report
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

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
                if report.notices_enabled {
                    let _ = writeln!(out, "Run `sbh update` to apply.");
                }
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

/// Format backup inventory as a human-readable table.
#[must_use]
pub fn format_backup_list(inventory: &BackupInventory) -> String {
    let mut out = String::new();

    if inventory.backups.is_empty() {
        let _ = writeln!(out, "No backups found.");
        let _ = writeln!(out, "Backup directory: {}", inventory.backup_dir.display());
        return out;
    }

    let _ = writeln!(out, "{:<14} {:<10} {:>10}", "ID", "VERSION", "SIZE");
    let _ = writeln!(out, "{}", "-".repeat(38));

    for snap in &inventory.backups {
        let _ = writeln!(
            out,
            "{:<14} {:<10} {:>10}",
            snap.id,
            snap.version,
            format_size(snap.binary_size)
        );
    }

    let _ = writeln!(
        out,
        "\n{} backup(s) in {}",
        inventory.backups.len(),
        inventory.backup_dir.display()
    );
    out
}

/// Format a rollback result for terminal output.
#[must_use]
pub fn format_rollback_result(result: &RollbackResult) -> String {
    let mut out = String::new();
    if result.success {
        let _ = writeln!(
            out,
            "Rolled back to v{} (backup {}).",
            result.restored_version, result.snapshot_id
        );
        let _ = writeln!(out, "Restart the sbh service to use this version.");
    } else if let Some(err) = &result.error {
        let _ = writeln!(out, "Rollback failed: {err}");
    }
    out
}

/// Format a prune result for terminal output.
#[must_use]
pub fn format_prune_result(result: &PruneResult) -> String {
    let mut out = String::new();
    if result.removed == 0 {
        let _ = writeln!(out, "No backups needed pruning ({} total).", result.kept);
    } else {
        for id in &result.removed_ids {
            let _ = writeln!(out, "  Removed backup {id}");
        }
        let _ = writeln!(
            out,
            "Pruned {} backup(s). {} remaining.",
            result.removed, result.kept
        );
    }
    out
}

#[allow(clippy::cast_precision_loss)]
fn format_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

/// Resolve the default install directory.
pub fn default_install_dir(system: bool) -> PathBuf {
    if system {
        PathBuf::from("/usr/local/bin")
    } else {
        if let Ok(exe) = std::env::current_exe()
            && let Some(parent) = exe.parent()
        {
            return parent.to_path_buf();
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetMetadataSource {
    Pinned,
    Cache,
    Network,
    OfflineBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TargetMetadata {
    target_tag: String,
    artifact_url: String,
    source: TargetMetadataSource,
    bundle_archive_path: Option<PathBuf>,
    bundle_checksum_path: Option<PathBuf>,
    bundle_sigstore_path: Option<PathBuf>,
}

fn resolve_target_metadata_with_cache<F>(
    contract: &ReleaseArtifactContract,
    pinned: Option<&str>,
    cache: &UpdateMetadataCache,
    refresh_cache: bool,
    now: SystemTime,
    mut fetch_latest_tag: F,
) -> std::result::Result<TargetMetadata, String>
where
    F: FnMut(&ReleaseArtifactContract) -> std::result::Result<String, String>,
{
    if let Some(version) = pinned {
        let tag = normalize_tag(version);
        return Ok(TargetMetadata {
            target_tag: tag.clone(),
            artifact_url: artifact_url_for_tag(contract, &tag),
            source: TargetMetadataSource::Pinned,
            bundle_archive_path: None,
            bundle_checksum_path: None,
            bundle_sigstore_path: None,
        });
    }

    if !refresh_cache && let Ok(Some(entry)) = cache.load_fresh(now) {
        return Ok(TargetMetadata {
            target_tag: entry.target_tag,
            artifact_url: entry.artifact_url,
            source: TargetMetadataSource::Cache,
            bundle_archive_path: None,
            bundle_checksum_path: None,
            bundle_sigstore_path: None,
        });
    }

    let target_tag = fetch_latest_tag(contract)?;
    let artifact_url = artifact_url_for_tag(contract, &target_tag);
    let cache_entry = CachedUpdateMetadata {
        target_tag: target_tag.clone(),
        artifact_url: artifact_url.clone(),
        fetched_at_unix_secs: unix_seconds(now),
    };
    let _ = cache.store(&cache_entry);

    Ok(TargetMetadata {
        target_tag,
        artifact_url,
        source: TargetMetadataSource::Network,
        bundle_archive_path: None,
        bundle_checksum_path: None,
        bundle_sigstore_path: None,
    })
}

fn artifact_url_for_tag(contract: &ReleaseArtifactContract, target_tag: &str) -> String {
    format!(
        "https://github.com/{}/releases/download/{}/{}",
        contract.repository,
        target_tag,
        contract.asset_name()
    )
}

fn normalize_tag(version: &str) -> String {
    if version.starts_with('v') {
        version.to_string()
    } else {
        format!("v{version}")
    }
}

fn unix_seconds(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn resolve_target_tag(
    contract: &ReleaseArtifactContract,
    pinned: Option<&str>,
) -> std::result::Result<String, String> {
    if let Some(version) = pinned {
        return Ok(normalize_tag(version));
    }

    resolve_latest_release_tag(contract)
}

fn resolve_latest_release_tag(
    contract: &ReleaseArtifactContract,
) -> std::result::Result<String, String> {
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
        .map(normalize_tag)
        .ok_or_else(|| "no tag_name in GitHub API response".to_string())
}

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

fn extract_and_install(
    archive_path: &Path,
    install_path: &Path,
) -> std::result::Result<(), String> {
    let extract_dir = archive_path.with_extension("extract");
    std::fs::create_dir_all(&extract_dir)
        .map_err(|e| format!("failed to create extract dir: {e}"))?;

    // Use 'xf' for auto-detection of compression format (xz, gz, etc).
    let tar_status = Command::new("tar")
        .args(["xf"])
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

    if let Some(parent) = install_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create install dir: {e}"))?;
    }

    // Keep a `.old` safety net in addition to the backup store snapshot.
    // Use a unique name to avoid collisions and allow Windows self-update
    // (renaming a running binary is allowed, but overwriting/renaming-over is not).
    let nonce = random::<u32>();
    let backup_path = install_path.with_extension(format!("old.{nonce}"));

    if install_path.exists() {
        // Must rename (move) the current binary. Copying leaves the locked binary
        // in place on Windows, causing the subsequent install rename to fail.
        std::fs::rename(install_path, &backup_path)
            .map_err(|e| format!("failed to move current binary to backup location: {e}"))?;
    }

    // Atomic install: copy to .new alongside target, then rename.
    // This ensures we are on the same filesystem for the final rename.
    let temp_install_path = install_path.with_extension("new");
    if let Err(e) = std::fs::copy(&new_binary, &temp_install_path) {
        let _ = std::fs::remove_dir_all(&extract_dir);
        // Try to restore backup if we moved it.
        if backup_path.exists() {
            let _ = std::fs::rename(&backup_path, install_path);
        }
        return Err(format!("failed to copy new binary to temp location: {e}"));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ =
            std::fs::set_permissions(&temp_install_path, std::fs::Permissions::from_mode(0o755));
    }

    // Verify the new binary works *before* moving it into place (check noexec, library linkage).
    if let Err(e) = verify_binary_execution(&temp_install_path) {
        let _ = std::fs::remove_file(&temp_install_path);
        let _ = std::fs::remove_dir_all(&extract_dir);
        // Restore backup if we moved it.
        if backup_path.exists() {
            let _ = std::fs::rename(&backup_path, install_path);
        }
        return Err(format!("new binary failed self-test: {e}"));
    }

    if let Err(e) = std::fs::rename(&temp_install_path, install_path) {
        // Rollback: restore from backup if it exists.
        if backup_path.exists() {
            let _ = std::fs::rename(&backup_path, install_path);
        }
        let _ = std::fs::remove_file(&temp_install_path);
        let _ = std::fs::remove_dir_all(&extract_dir);
        return Err(format!(
            "failed to atomically replace binary (rolled back): {e}"
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(install_path, std::fs::Permissions::from_mode(0o755));
    }

    // Best-effort cleanup of the running-binary backup.
    // On Windows this will fail because the process is still running from this file.
    // That's acceptable; it's a temp file in the bin dir.
    let _ = std::fs::remove_file(&backup_path);
    let _ = std::fs::remove_dir_all(&extract_dir);
    Ok(())
}

fn verify_binary_execution(path: &Path) -> std::result::Result<(), String> {
    let output = Command::new(path)
        .arg("--version")
        .output()
        .map_err(|e| format!("failed to execute binary: {e}"))?;

    if !output.status.success() {
        return Err(format!("binary exited with status {}", output.status));
    }
    Ok(())
}

fn tempdir_for_update() -> std::result::Result<PathBuf, String> {
    let base = std::env::temp_dir();
    let pid = std::process::id();

    for _attempt in 0..32 {
        let nonce = random::<u128>();
        let dir = base.join(format!("sbh_update-{pid}-{nonce:032x}"));
        match std::fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(err) => {
                return Err(format!(
                    "failed to create temp update dir {}: {err}",
                    dir.display()
                ));
            }
        }
    }

    Err("failed to allocate unique temp update directory after 32 attempts".to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    use super::super::{OfflineBundleArtifact, OfflineBundleManifest, RELEASE_REPOSITORY};

    fn test_store(name: &str) -> (BackupStore, PathBuf) {
        let base = std::env::temp_dir()
            .join("sbh_test_backups")
            .join(name)
            .join(format!(
                "{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        let store_dir = base.join("store");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&store_dir).unwrap();
        (BackupStore::open(store_dir), base)
    }

    fn create_fake_binary(dir: &Path) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join("sbh");
        std::fs::write(&path, b"fake-binary-content-for-testing").unwrap();
        path
    }

    fn test_contract() -> ReleaseArtifactContract {
        resolve_updater_artifact_contract(
            HostSpecifier {
                os: super::super::HostOs::Linux,
                arch: super::super::HostArch::X86_64,
                abi: super::super::HostAbi::Gnu,
            },
            ReleaseChannel::Stable,
            None,
        )
        .unwrap()
    }

    fn write_offline_bundle_manifest(
        root: &Path,
        contract: &ReleaseArtifactContract,
        release_tag: &str,
        archive_bytes: &[u8],
    ) -> PathBuf {
        write_offline_bundle_manifest_with_sigstore(
            root,
            contract,
            release_tag,
            archive_bytes,
            None,
        )
    }

    fn write_offline_bundle_manifest_with_sigstore(
        root: &Path,
        contract: &ReleaseArtifactContract,
        release_tag: &str,
        archive_bytes: &[u8],
        sigstore_bundle_contents: Option<&[u8]>,
    ) -> PathBuf {
        let archive_name = contract.asset_name();
        let checksum_name = contract.checksum_name();
        let sigstore_name = contract.sigstore_bundle_name();
        let archive_path = root.join(&archive_name);
        std::fs::write(&archive_path, archive_bytes).unwrap();
        let checksum_hex = format!("{:x}", Sha256::digest(archive_bytes));
        std::fs::write(
            root.join(&checksum_name),
            format!("{checksum_hex}  {archive_name}\n"),
        )
        .unwrap();
        let sigstore_bundle = sigstore_bundle_contents.map(|contents| {
            std::fs::write(root.join(&sigstore_name), contents).unwrap();
            sigstore_name
        });

        let manifest = OfflineBundleManifest {
            version: "1".to_string(),
            repository: RELEASE_REPOSITORY.to_string(),
            release_tag: release_tag.to_string(),
            artifacts: vec![OfflineBundleArtifact {
                target: contract.target.triple.to_string(),
                archive: archive_name,
                checksum: checksum_name,
                sigstore_bundle,
            }],
        };
        let manifest_path = root.join("bundle-manifest.json");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        manifest_path
    }

    #[test]
    fn tempdir_for_update_creates_unique_directories() {
        let one = tempdir_for_update().unwrap();
        let two = tempdir_for_update().unwrap();

        assert_ne!(one, two);
        assert!(one.exists());
        assert!(two.exists());

        let _ = std::fs::remove_dir_all(&one);
        let _ = std::fs::remove_dir_all(&two);
    }

    #[test]
    fn current_version_is_not_empty() {
        assert!(!current_version().is_empty());
    }

    #[test]
    fn default_install_dir_system() {
        assert_eq!(default_install_dir(true), PathBuf::from("/usr/local/bin"));
    }

    #[test]
    fn default_install_dir_user_resolves() {
        assert!(!default_install_dir(false).to_string_lossy().is_empty());
    }

    #[test]
    fn report_step_tracking() {
        let mut r = UpdateReport::new("0.1.0", false, false, true);
        r.step_ok("Step 1");
        r.step_fail("Step 2", "error");
        r.step_plan("Step 3");
        assert_eq!(r.steps.len(), 3);
        assert!(r.steps[0].done);
        assert!(r.steps[1].error.is_some());
        assert!(!r.steps[2].done && r.steps[2].error.is_none());
    }

    #[test]
    fn format_check_only_up_to_date() {
        let mut r = UpdateReport::new("0.1.0", true, false, true);
        r.update_available = false;
        r.success = true;
        assert!(format_update_report(&r).contains("up to date"));
    }

    #[test]
    fn format_check_only_update_available() {
        let mut r = UpdateReport::new("0.1.0", true, false, true);
        r.update_available = true;
        r.target_version = Some("v0.2.0".to_string());
        r.success = true;
        let out = format_update_report(&r);
        assert!(out.contains("Update available"));
        assert!(out.contains("v0.2.0"));
        assert!(out.contains("Run `sbh update` to apply."));
    }

    #[test]
    fn format_check_only_update_available_notice_suppressed() {
        let mut r = UpdateReport::new("0.1.0", true, false, false);
        r.update_available = true;
        r.target_version = Some("v0.2.0".to_string());
        r.success = true;
        let out = format_update_report(&r);
        assert!(out.contains("Update available"));
        assert!(!out.contains("Run `sbh update` to apply."));
    }

    #[test]
    fn format_applied() {
        let mut r = UpdateReport::new("0.1.0", false, false, true);
        r.applied = true;
        r.success = true;
        assert!(format_update_report(&r).contains("applied successfully"));
    }

    #[test]
    fn format_dry_run() {
        let mut r = UpdateReport::new("0.1.0", false, true, true);
        r.success = true;
        r.step_plan("Would download artifact");
        let out = format_update_report(&r);
        assert!(out.contains("Dry-run"));
        assert!(out.contains("[PLAN]"));
    }

    #[test]
    fn format_follow_up() {
        let mut r = UpdateReport::new("0.1.0", false, false, true);
        r.applied = true;
        r.success = true;
        r.follow_up.push("Restart the service".to_string());
        assert!(format_update_report(&r).contains("Restart the service"));
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
        assert_eq!(
            resolve_target_tag(&contract, Some("0.2.0")).unwrap(),
            "v0.2.0"
        );
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
        assert_eq!(
            resolve_target_tag(&contract, Some("v0.3.0")).unwrap(),
            "v0.3.0"
        );
    }

    #[test]
    fn target_metadata_uses_cache_when_refresh_disabled() {
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = UpdateMetadataCache::new(
            cache_dir.path().join("update-metadata.json"),
            Duration::from_secs(300),
        );
        let now = UNIX_EPOCH + Duration::from_secs(2_000);
        let cached = CachedUpdateMetadata {
            target_tag: "v0.9.0".to_string(),
            artifact_url: "https://example.invalid/v0.9.0/sbh.tar.xz".to_string(),
            fetched_at_unix_secs: 1_900,
        };
        cache.store(&cached).unwrap();

        let mut fetch_calls = 0usize;
        let metadata =
            resolve_target_metadata_with_cache(&test_contract(), None, &cache, false, now, |_| {
                fetch_calls += 1;
                Ok("v9.9.9".to_string())
            })
            .unwrap();

        assert_eq!(metadata.source, TargetMetadataSource::Cache);
        assert_eq!(metadata.target_tag, "v0.9.0");
        assert_eq!(
            metadata.artifact_url,
            "https://example.invalid/v0.9.0/sbh.tar.xz"
        );
        assert_eq!(fetch_calls, 0);
    }

    #[test]
    fn target_metadata_refresh_bypasses_cache_and_writes_new_entry() {
        let contract = test_contract();
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = UpdateMetadataCache::new(
            cache_dir.path().join("update-metadata.json"),
            Duration::from_secs(300),
        );
        let now = UNIX_EPOCH + Duration::from_secs(5_000);
        cache
            .store(&CachedUpdateMetadata {
                target_tag: "v0.1.0".to_string(),
                artifact_url: "https://example.invalid/old.tar.xz".to_string(),
                fetched_at_unix_secs: 4_900,
            })
            .unwrap();

        let mut fetch_calls = 0usize;
        let metadata =
            resolve_target_metadata_with_cache(&contract, None, &cache, true, now, |_| {
                fetch_calls += 1;
                Ok("v1.2.3".to_string())
            })
            .unwrap();

        assert_eq!(metadata.source, TargetMetadataSource::Network);
        assert_eq!(metadata.target_tag, "v1.2.3");
        assert_eq!(
            metadata.artifact_url,
            artifact_url_for_tag(&contract, "v1.2.3")
        );
        assert_eq!(fetch_calls, 1);

        let cached = cache
            .load_fresh(now)
            .unwrap()
            .expect("fresh cache expected");
        assert_eq!(cached.target_tag, "v1.2.3");
        assert_eq!(
            cached.artifact_url,
            artifact_url_for_tag(&contract, "v1.2.3")
        );
    }

    #[test]
    fn run_update_sequence_check_only_uses_offline_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let host = HostSpecifier::detect().unwrap();
        let contract =
            resolve_updater_artifact_contract(host, ReleaseChannel::Stable, Some("9.9.9")).unwrap();
        let manifest_path = write_offline_bundle_manifest(
            tmp.path(),
            &contract,
            "9.9.9",
            b"offline-update-archive",
        );

        let opts = UpdateOptions {
            check_only: true,
            pinned_version: None,
            force: false,
            install_dir: default_install_dir(false),
            no_verify: false,
            dry_run: false,
            max_backups: 5,
            metadata_cache_file: tmp.path().join("update-cache.json"),
            metadata_cache_ttl: Duration::from_secs(60),
            refresh_cache: false,
            notices_enabled: true,
            offline_bundle_manifest: Some(manifest_path),
        };

        let report = run_update_sequence(&opts);
        assert!(
            report.success,
            "offline check-only should succeed: {report:?}"
        );
        assert!(
            report.update_available,
            "bundle target should be newer than current"
        );
        assert!(
            report.steps.iter().any(|step| step
                .description
                .contains("Resolved offline bundle artifact")),
            "report should show offline bundle contract resolution"
        );
        assert!(
            report.steps.iter().any(|step| step
                .description
                .contains("Loaded update metadata from offline bundle")),
            "report should indicate offline metadata source"
        );
    }

    #[test]
    fn run_update_sequence_offline_bundle_requires_sigstore_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let host = HostSpecifier::detect().unwrap();
        let contract =
            resolve_updater_artifact_contract(host, ReleaseChannel::Stable, Some("9.9.9")).unwrap();
        let manifest_path = write_offline_bundle_manifest_with_sigstore(
            tmp.path(),
            &contract,
            "9.9.9",
            b"offline-update-archive",
            Some(b"{\"invalid\":true}\n"),
        );

        let opts = UpdateOptions {
            check_only: false,
            pinned_version: None,
            force: true,
            install_dir: tmp.path().join("bin"),
            no_verify: false,
            dry_run: false,
            max_backups: 5,
            metadata_cache_file: tmp.path().join("update-cache.json"),
            metadata_cache_ttl: Duration::from_secs(60),
            refresh_cache: false,
            notices_enabled: true,
            offline_bundle_manifest: Some(manifest_path),
        };

        let report = run_update_sequence(&opts);
        assert!(
            !report.success,
            "offline update should fail when required sigstore verification fails: {report:?}"
        );
        assert!(
            report
                .steps
                .iter()
                .any(|step| step.description.contains("Integrity verification")
                    && step
                        .error
                        .as_deref()
                        .is_some_and(|err| err.contains("sigstore_required_"))),
            "report should include required sigstore integrity denial"
        );
    }

    #[test]
    fn run_update_sequence_no_verify_skips_sigstore_probe_for_offline_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let host = HostSpecifier::detect().unwrap();
        let contract =
            resolve_updater_artifact_contract(host, ReleaseChannel::Stable, Some("9.9.9")).unwrap();
        let manifest_path = write_offline_bundle_manifest_with_sigstore(
            tmp.path(),
            &contract,
            "9.9.9",
            b"offline-update-archive",
            Some(b"{\"invalid\":true}\n"),
        );

        let opts = UpdateOptions {
            check_only: false,
            pinned_version: None,
            force: true,
            install_dir: tmp.path().join("bin"),
            no_verify: true,
            dry_run: false,
            max_backups: 5,
            metadata_cache_file: tmp.path().join("update-cache.json"),
            metadata_cache_ttl: Duration::from_secs(60),
            refresh_cache: false,
            notices_enabled: true,
            offline_bundle_manifest: Some(manifest_path),
        };

        let report = run_update_sequence(&opts);
        assert!(
            report
                .steps
                .iter()
                .any(|step| step.description == "Integrity verification passed"),
            "--no-verify should bypass sigstore/checksum enforcement"
        );
        assert!(
            !report
                .steps
                .iter()
                .filter_map(|step| step.error.as_deref())
                .any(|err| err.contains("sigstore_required_")),
            "--no-verify path should not surface required sigstore failures"
        );
    }

    #[test]
    fn run_update_sequence_offline_bundle_rejects_pinned_tag_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let host = HostSpecifier::detect().unwrap();
        let contract =
            resolve_updater_artifact_contract(host, ReleaseChannel::Stable, Some("9.9.9")).unwrap();
        let manifest_path = write_offline_bundle_manifest(
            tmp.path(),
            &contract,
            "9.9.9",
            b"offline-update-archive",
        );

        let opts = UpdateOptions {
            check_only: true,
            pinned_version: Some("1.0.0".to_string()),
            force: false,
            install_dir: default_install_dir(false),
            no_verify: false,
            dry_run: false,
            max_backups: 5,
            metadata_cache_file: tmp.path().join("update-cache.json"),
            metadata_cache_ttl: Duration::from_secs(60),
            refresh_cache: false,
            notices_enabled: true,
            offline_bundle_manifest: Some(manifest_path),
        };

        let report = run_update_sequence(&opts);
        assert!(
            !report.success,
            "mismatched pinned version should fail in offline bundle mode"
        );
        assert!(
            report
                .steps
                .iter()
                .any(|step| step.description.contains("Resolve target version")
                    && step
                        .error
                        .as_deref()
                        .is_some_and(|err| err.contains("offline bundle tag mismatch"))),
            "report should include offline bundle pin mismatch diagnostic"
        );
    }

    #[test]
    fn run_update_sequence_offline_bundle_dry_run_ignores_refresh_and_suppresses_notices() {
        let tmp = tempfile::tempdir().unwrap();
        let host = HostSpecifier::detect().unwrap();
        let contract =
            resolve_updater_artifact_contract(host, ReleaseChannel::Stable, Some("9.9.9")).unwrap();
        let manifest_path = write_offline_bundle_manifest(
            tmp.path(),
            &contract,
            "9.9.9",
            b"offline-update-archive",
        );

        let opts = UpdateOptions {
            check_only: false,
            pinned_version: None,
            force: false,
            install_dir: default_install_dir(false),
            no_verify: false,
            dry_run: true,
            max_backups: 5,
            metadata_cache_file: tmp.path().join("update-cache.json"),
            metadata_cache_ttl: Duration::from_secs(60),
            refresh_cache: true,
            notices_enabled: false,
            offline_bundle_manifest: Some(manifest_path),
        };

        let report = run_update_sequence(&opts);
        assert!(report.success, "offline dry-run should succeed: {report:?}");
        assert!(report.update_available);
        assert!(report.follow_up.is_empty(), "notices should be suppressed");
        assert!(report.steps.iter().any(|step| {
            step.description
                .contains("Ignored --refresh-cache in offline bundle mode")
        }));
        assert!(report.steps.iter().any(|step| {
            step.description
                .contains("Would use offline bundle artifact")
        }));
        assert!(!report.steps.iter().any(|step| {
            step.description
                .contains("Fetched update metadata from network")
        }));
        assert!(!report.steps.iter().any(|step| {
            step.description
                .contains("Refreshed update metadata from network")
        }));
    }

    #[test]
    fn run_update_sequence_check_only_offline_bundle_same_version_is_up_to_date() {
        let tmp = tempfile::tempdir().unwrap();
        let host = HostSpecifier::detect().unwrap();
        let current = current_version();
        let contract =
            resolve_updater_artifact_contract(host, ReleaseChannel::Stable, Some(&current))
                .unwrap();
        let manifest_path = write_offline_bundle_manifest(
            tmp.path(),
            &contract,
            &current,
            b"offline-update-archive",
        );

        let opts = UpdateOptions {
            check_only: true,
            pinned_version: None,
            force: false,
            install_dir: default_install_dir(false),
            no_verify: false,
            dry_run: false,
            max_backups: 5,
            metadata_cache_file: tmp.path().join("update-cache.json"),
            metadata_cache_ttl: Duration::from_secs(60),
            refresh_cache: false,
            notices_enabled: true,
            offline_bundle_manifest: Some(manifest_path),
        };

        let report = run_update_sequence(&opts);
        assert!(
            report.success,
            "same-version offline check-only should succeed: {report:?}"
        );
        assert!(!report.update_available);
        assert_eq!(report.target_version, Some(format!("v{current}")));
        assert!(
            report
                .steps
                .iter()
                .any(|step| step.description.contains("no update needed"))
        );
    }

    // -----------------------------------------------------------------------
    // BackupStore tests
    // -----------------------------------------------------------------------

    #[test]
    fn backup_create_and_list() {
        let (store, dir) = test_store("create_list");
        let bin = create_fake_binary(&dir.join("install"));

        let snap = store.create(&bin, "0.1.0").unwrap();
        assert_eq!(snap.version, "0.1.0");
        assert!(snap.binary_size > 0);
        assert!(snap.path.exists());

        let entries = store.list();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, snap.id);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backup_list_empty() {
        let (store, dir) = test_store("list_empty");
        assert!(store.list().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backup_list_sorted_newest_first() {
        let (store, dir) = test_store("sorted");
        let bin = create_fake_binary(&dir.join("install"));

        for (id, ver) in [("1000", "0.1.0"), ("3000", "0.3.0"), ("2000", "0.2.0")] {
            let ed = store.dir().join(id);
            std::fs::create_dir_all(&ed).unwrap();
            std::fs::copy(&bin, ed.join("sbh")).unwrap();
            std::fs::write(
                ed.join("backup.json"),
                serde_json::to_string(&serde_json::json!({
                    "version": ver,
                    "timestamp": id.parse::<u64>().unwrap(),
                    "binary_size": 31
                }))
                .unwrap(),
            )
            .unwrap();
        }

        let entries = store.list();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].id, "3000");
        assert_eq!(entries[1].id, "2000");
        assert_eq!(entries[2].id, "1000");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backup_rollback_latest() {
        let (store, dir) = test_store("rollback_latest");
        let bin = create_fake_binary(&dir.join("install"));

        store.create(&bin, "0.1.0").unwrap();
        std::fs::write(&bin, b"updated-binary").unwrap();

        let result = store.rollback(&bin, None).unwrap();
        assert!(result.success);
        assert_eq!(result.restored_version, "0.1.0");
        assert_eq!(
            std::fs::read(&bin).unwrap(),
            b"fake-binary-content-for-testing"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backup_rollback_by_id() {
        let (store, dir) = test_store("rollback_by_id");
        let bin = create_fake_binary(&dir.join("install"));

        for (id, ver, content) in [
            ("1000", "0.1.0", &b"old-ver"[..]),
            ("2000", "0.2.0", &b"new-ver"[..]),
        ] {
            let ed = store.dir().join(id);
            std::fs::create_dir_all(&ed).unwrap();
            std::fs::write(ed.join("sbh"), content).unwrap();
            std::fs::write(
                ed.join("backup.json"),
                format!(
                    r#"{{"version":"{}","timestamp":{},"binary_size":{}}}"#,
                    ver,
                    id,
                    content.len()
                ),
            )
            .unwrap();
        }

        let result = store.rollback(&bin, Some("1000")).unwrap();
        assert!(result.success);
        assert_eq!(result.restored_version, "0.1.0");
        assert_eq!(std::fs::read(&bin).unwrap(), b"old-ver");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backup_rollback_no_backups() {
        let (store, dir) = test_store("rollback_none");
        let err = store
            .rollback(&dir.join("install/sbh"), Some("9999"))
            .unwrap_err();
        assert!(err.contains("no backups"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backup_prune_keeps_n_most_recent() {
        let (store, dir) = test_store("prune");
        let bin = create_fake_binary(&dir.join("install"));

        for id in ["1000", "2000", "3000", "4000", "5000"] {
            let ed = store.dir().join(id);
            std::fs::create_dir_all(&ed).unwrap();
            std::fs::copy(&bin, ed.join("sbh")).unwrap();
            std::fs::write(
                ed.join("backup.json"),
                serde_json::to_string(&serde_json::json!({
                    "version": format!("0.{id}.0"),
                    "timestamp": id.parse::<u64>().unwrap(),
                    "binary_size": 31
                }))
                .unwrap(),
            )
            .unwrap();
        }

        let result = store.prune(2).unwrap();
        assert_eq!(result.kept, 2);
        assert_eq!(result.removed, 3);

        let remaining = store.list();
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].id, "5000");
        assert_eq!(remaining[1].id, "4000");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backup_prune_noop_when_under_limit() {
        let (store, dir) = test_store("prune_noop");
        let bin = create_fake_binary(&dir.join("install"));
        store.create(&bin, "0.1.0").unwrap();

        let result = store.prune(5).unwrap();
        assert_eq!(result.removed, 0);
        assert_eq!(store.list().len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backup_inventory() {
        let (store, dir) = test_store("inventory");
        let bin = create_fake_binary(&dir.join("install"));
        store.create(&bin, "0.1.0").unwrap();

        let inv = store.inventory();
        assert_eq!(inv.backups.len(), 1);
        assert_eq!(inv.backup_dir, *store.dir());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Formatting tests
    // -----------------------------------------------------------------------

    #[test]
    fn fmt_backup_list_empty() {
        let inv = BackupInventory {
            backups: vec![],
            backup_dir: PathBuf::from("/tmp/t"),
        };
        assert!(format_backup_list(&inv).contains("No backups found"));
    }

    #[test]
    fn fmt_backup_list_with_entries() {
        let inv = BackupInventory {
            backups: vec![
                BackupSnapshot {
                    id: "2000".into(),
                    version: "0.2.0".into(),
                    timestamp: 2000,
                    binary_size: 5 * 1024 * 1024,
                    path: "/tmp/b/2000/sbh".into(),
                },
                BackupSnapshot {
                    id: "1000".into(),
                    version: "0.1.0".into(),
                    timestamp: 1000,
                    binary_size: 512 * 1024,
                    path: "/tmp/b/1000/sbh".into(),
                },
            ],
            backup_dir: "/tmp/b".into(),
        };
        let out = format_backup_list(&inv);
        assert!(out.contains("0.2.0"));
        assert!(out.contains("0.1.0"));
        assert!(out.contains("2 backup(s)"));
        assert!(out.contains("5.0 MiB"));
    }

    #[test]
    fn fmt_rollback_success() {
        let r = RollbackResult {
            success: true,
            snapshot_id: "1000".into(),
            restored_version: "0.1.0".into(),
            install_path: "/usr/local/bin/sbh".into(),
            error: None,
        };
        let out = format_rollback_result(&r);
        assert!(out.contains("Rolled back to v0.1.0"));
        assert!(out.contains("Restart"));
    }

    #[test]
    fn fmt_prune_with_removals() {
        let r = PruneResult {
            kept: 2,
            removed: 3,
            removed_ids: vec!["1".into(), "2".into(), "3".into()],
        };
        let out = format_prune_result(&r);
        assert!(out.contains("Pruned 3"));
        assert!(out.contains("2 remaining"));
    }

    #[test]
    fn fmt_prune_noop() {
        let r = PruneResult {
            kept: 2,
            removed: 0,
            removed_ids: vec![],
        };
        assert!(format_prune_result(&r).contains("No backups needed pruning"));
    }

    #[test]
    fn fmt_size_values() {
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(1536), "1.5 KiB");
        assert_eq!(format_size(5 * 1024 * 1024), "5.0 MiB");
    }
}
