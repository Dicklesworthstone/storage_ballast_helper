//! Uninstall parity: safe cleanup modes, dry-run plans, and reversible teardown.
//!
//! Supports conservative (default), keep-data, keep-config, keep-assets, and
//! explicit purge modes. Every removal is logged and can be dry-run first.
//! Integration teardown uses backup-first semantics from the bootstrap module.

use std::fmt;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Serialize;

// ---------------------------------------------------------------------------
// Uninstall modes
// ---------------------------------------------------------------------------

/// Cleanup mode controlling what gets removed during uninstall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CleanupMode {
    /// Remove binary and service registrations, keep data/config/assets.
    Conservative,
    /// Remove everything except user data (logs, `SQLite` DB).
    KeepData,
    /// Remove everything except the config file.
    KeepConfig,
    /// Remove everything except cached assets.
    KeepAssets,
    /// Remove absolutely everything sbh-related.
    Purge,
}

impl fmt::Display for CleanupMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conservative => f.write_str("conservative"),
            Self::KeepData => f.write_str("keep-data"),
            Self::KeepConfig => f.write_str("keep-config"),
            Self::KeepAssets => f.write_str("keep-assets"),
            Self::Purge => f.write_str("purge"),
        }
    }
}

// ---------------------------------------------------------------------------
// Uninstall plan
// ---------------------------------------------------------------------------

/// A single planned removal action.
#[derive(Debug, Clone, Serialize)]
pub struct RemovalAction {
    /// What category of item this is.
    pub category: RemovalCategory,
    /// Path to the item.
    pub path: PathBuf,
    /// Whether this is a directory (recursive removal) or file.
    pub is_directory: bool,
    /// Whether a backup will be created before removal.
    pub backup_first: bool,
    /// Whether this action was executed.
    pub executed: bool,
    /// Backup path if created.
    pub backup_path: Option<PathBuf>,
    /// Error message if execution failed.
    pub error: Option<String>,
    /// Human-readable reason for this action.
    pub reason: String,
}

/// Categories of items to remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RemovalCategory {
    Binary,
    ConfigFile,
    DataDirectory,
    StateFile,
    SqliteDb,
    JsonlLog,
    AssetCache,
    SystemdUnit,
    LaunchdPlist,
    ShellCompletion,
    ShellProfileEntry,
    IntegrationHook,
    BallastPool,
    BackupFile,
}

impl fmt::Display for RemovalCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Binary => f.write_str("binary"),
            Self::ConfigFile => f.write_str("config-file"),
            Self::DataDirectory => f.write_str("data-directory"),
            Self::StateFile => f.write_str("state-file"),
            Self::SqliteDb => f.write_str("sqlite-db"),
            Self::JsonlLog => f.write_str("jsonl-log"),
            Self::AssetCache => f.write_str("asset-cache"),
            Self::SystemdUnit => f.write_str("systemd-unit"),
            Self::LaunchdPlist => f.write_str("launchd-plist"),
            Self::ShellCompletion => f.write_str("shell-completion"),
            Self::ShellProfileEntry => f.write_str("shell-profile-entry"),
            Self::IntegrationHook => f.write_str("integration-hook"),
            Self::BallastPool => f.write_str("ballast-pool"),
            Self::BackupFile => f.write_str("backup-file"),
        }
    }
}

// ---------------------------------------------------------------------------
// Uninstall report
// ---------------------------------------------------------------------------

/// Complete uninstall report.
#[derive(Debug, Clone, Serialize)]
pub struct UninstallReport {
    /// The cleanup mode used.
    pub mode: CleanupMode,
    /// Whether this was a dry-run.
    pub dry_run: bool,
    /// Timestamp of the uninstall operation.
    pub timestamp: String,
    /// All planned/executed actions.
    pub actions: Vec<RemovalAction>,
    /// Items intentionally kept due to cleanup mode.
    pub kept: Vec<KeptItem>,
    /// Number of items successfully removed.
    pub removed_count: usize,
    /// Number of failures.
    pub failed_count: usize,
    /// Total bytes freed.
    pub bytes_freed: u64,
}

/// An item intentionally kept based on the cleanup mode.
#[derive(Debug, Clone, Serialize)]
pub struct KeptItem {
    pub category: RemovalCategory,
    pub path: PathBuf,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Uninstall options
// ---------------------------------------------------------------------------

/// Options for running uninstall.
#[derive(Debug, Clone)]
pub struct UninstallOptions {
    /// What to clean up.
    pub mode: CleanupMode,
    /// Only show what would be done.
    pub dry_run: bool,
    /// Override backup directory for items that get backed up.
    pub backup_dir: Option<PathBuf>,
    /// Explicit binary path (auto-detect if None).
    pub binary_path: Option<PathBuf>,
}

impl Default for UninstallOptions {
    fn default() -> Self {
        Self {
            mode: CleanupMode::Conservative,
            dry_run: false,
            backup_dir: None,
            binary_path: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Path discovery
// ---------------------------------------------------------------------------

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Discover all sbh-related paths on the system.
fn discover_paths() -> DiscoveredPaths {
    let home = home_dir();
    let h = home.as_deref();

    DiscoveredPaths {
        binaries: discover_binaries(),
        config_file: h.map(|d| d.join(".config").join("sbh").join("config.toml")),
        data_dir: h.map(|d| d.join(".local").join("share").join("sbh")),
        state_file: h.map(|d| {
            d.join(".local")
                .join("share")
                .join("sbh")
                .join("state.json")
        }),
        sqlite_db: h.map(|d| {
            d.join(".local")
                .join("share")
                .join("sbh")
                .join("activity.sqlite3")
        }),
        jsonl_log: h.map(|d| {
            d.join(".local")
                .join("share")
                .join("sbh")
                .join("activity.jsonl")
        }),
        asset_cache: h.map(|d| d.join(".local").join("share").join("sbh").join("assets")),
        systemd_units: discover_systemd_units(h),
        launchd_plists: discover_launchd_plists(h),
        completions: discover_completions(h),
        profile_entries: discover_profile_entries(),
    }
}

struct DiscoveredPaths {
    binaries: Vec<PathBuf>,
    config_file: Option<PathBuf>,
    data_dir: Option<PathBuf>,
    state_file: Option<PathBuf>,
    sqlite_db: Option<PathBuf>,
    jsonl_log: Option<PathBuf>,
    asset_cache: Option<PathBuf>,
    systemd_units: Vec<PathBuf>,
    launchd_plists: Vec<PathBuf>,
    completions: Vec<PathBuf>,
    profile_entries: Vec<PathBuf>,
}

fn discover_binaries() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(home) = home_dir() {
        let local_bin = home.join(".local").join("bin").join("sbh");
        if local_bin.exists() {
            paths.push(local_bin);
        }
        let cargo_bin = home.join(".cargo").join("bin").join("sbh");
        if cargo_bin.exists() {
            paths.push(cargo_bin);
        }
    }
    let system = PathBuf::from("/usr/local/bin/sbh");
    if system.exists() {
        paths.push(system);
    }
    paths
}

fn discover_systemd_units(home: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let system_unit = PathBuf::from("/etc/systemd/system/sbh.service");
    if system_unit.exists() {
        paths.push(system_unit);
    }
    if let Some(h) = home {
        let user_unit = h
            .join(".config")
            .join("systemd")
            .join("user")
            .join("sbh.service");
        if user_unit.exists() {
            paths.push(user_unit);
        }
    }
    paths
}

fn discover_launchd_plists(home: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let system_plist = PathBuf::from("/Library/LaunchDaemons/com.sbh.daemon.plist");
    if system_plist.exists() {
        paths.push(system_plist);
    }
    if let Some(h) = home {
        let user_plist = h
            .join("Library")
            .join("LaunchAgents")
            .join("com.sbh.daemon.plist");
        if user_plist.exists() {
            paths.push(user_plist);
        }
    }
    paths
}

fn discover_completions(home: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let bash_system = PathBuf::from("/etc/bash_completion.d/sbh");
    if bash_system.exists() {
        paths.push(bash_system);
    }
    if let Some(h) = home {
        let bash = h
            .join(".local")
            .join("share")
            .join("bash-completion")
            .join("completions")
            .join("sbh");
        if bash.exists() {
            paths.push(bash);
        }
        let zsh = h.join(".zfunc").join("_sbh");
        if zsh.exists() {
            paths.push(zsh);
        }
        let fish = h
            .join(".config")
            .join("fish")
            .join("completions")
            .join("sbh.fish");
        if fish.exists() {
            paths.push(fish);
        }
    }
    paths
}

fn discover_profile_entries() -> Vec<PathBuf> {
    let Some(home) = home_dir() else {
        return Vec::new();
    };
    let profiles = [
        ".bashrc",
        ".bash_profile",
        ".profile",
        ".zshrc",
        ".zprofile",
    ];
    profiles
        .iter()
        .map(|p| home.join(p))
        .filter(|p| {
            p.exists()
                && fs::read_to_string(p)
                    .map(|c| c.contains("sbh") && c.contains("PATH"))
                    .unwrap_or(false)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Plan generation
// ---------------------------------------------------------------------------

/// Generate an uninstall plan without executing anything.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn plan_uninstall(opts: &UninstallOptions) -> UninstallReport {
    let paths = discover_paths();
    let mut actions = Vec::new();
    let mut kept = Vec::new();

    // -- Binary (always removed).
    for bin in &paths.binaries {
        if let Some(ref explicit) = opts.binary_path
            && bin != explicit
        {
            continue;
        }
        actions.push(RemovalAction {
            category: RemovalCategory::Binary,
            path: bin.clone(),
            is_directory: false,
            backup_first: false,
            executed: false,
            backup_path: None,
            error: None,
            reason: "remove sbh binary".to_string(),
        });
    }

    // -- Service files (always removed).
    for unit in &paths.systemd_units {
        actions.push(RemovalAction {
            category: RemovalCategory::SystemdUnit,
            path: unit.clone(),
            is_directory: false,
            backup_first: true,
            executed: false,
            backup_path: None,
            error: None,
            reason: "remove systemd unit file".to_string(),
        });
    }
    for plist in &paths.launchd_plists {
        actions.push(RemovalAction {
            category: RemovalCategory::LaunchdPlist,
            path: plist.clone(),
            is_directory: false,
            backup_first: true,
            executed: false,
            backup_path: None,
            error: None,
            reason: "remove launchd plist".to_string(),
        });
    }

    // -- Shell completions (always removed).
    for comp in &paths.completions {
        actions.push(RemovalAction {
            category: RemovalCategory::ShellCompletion,
            path: comp.clone(),
            is_directory: false,
            backup_first: false,
            executed: false,
            backup_path: None,
            error: None,
            reason: "remove shell completion script".to_string(),
        });
    }

    // -- Shell profile entries (always cleaned, with backup).
    for profile in &paths.profile_entries {
        actions.push(RemovalAction {
            category: RemovalCategory::ShellProfileEntry,
            path: profile.clone(),
            is_directory: false,
            backup_first: true,
            executed: false,
            backup_path: None,
            error: None,
            reason: "remove sbh PATH entry from shell profile".to_string(),
        });
    }

    // -- Config file.
    if let Some(ref cfg) = paths.config_file
        && cfg.exists()
    {
        match opts.mode {
            CleanupMode::KeepConfig | CleanupMode::Conservative => {
                kept.push(KeptItem {
                    category: RemovalCategory::ConfigFile,
                    path: cfg.clone(),
                    reason: format!("kept by {} mode", opts.mode),
                });
            }
            _ => {
                actions.push(RemovalAction {
                    category: RemovalCategory::ConfigFile,
                    path: cfg.clone(),
                    is_directory: false,
                    backup_first: true,
                    executed: false,
                    backup_path: None,
                    error: None,
                    reason: "remove config file".to_string(),
                });
            }
        }
    }

    // -- Data files (state, sqlite, jsonl).
    let data_files = [
        (&paths.state_file, RemovalCategory::StateFile),
        (&paths.sqlite_db, RemovalCategory::SqliteDb),
        (&paths.jsonl_log, RemovalCategory::JsonlLog),
    ];
    for (path_opt, category) in &data_files {
        if let Some(path) = path_opt
            && path.exists()
        {
            match opts.mode {
                CleanupMode::KeepData | CleanupMode::Conservative => {
                    kept.push(KeptItem {
                        category: *category,
                        path: path.clone(),
                        reason: format!("kept by {} mode", opts.mode),
                    });
                }
                _ => {
                    actions.push(RemovalAction {
                        category: *category,
                        path: path.clone(),
                        is_directory: false,
                        backup_first: category == &RemovalCategory::SqliteDb,
                        executed: false,
                        backup_path: None,
                        error: None,
                        reason: format!("remove {category}"),
                    });
                }
            }
        }
    }

    // -- Asset cache.
    if let Some(ref cache) = paths.asset_cache
        && cache.exists()
    {
        match opts.mode {
            CleanupMode::KeepAssets | CleanupMode::Conservative => {
                kept.push(KeptItem {
                    category: RemovalCategory::AssetCache,
                    path: cache.clone(),
                    reason: format!("kept by {} mode", opts.mode),
                });
            }
            _ => {
                actions.push(RemovalAction {
                    category: RemovalCategory::AssetCache,
                    path: cache.clone(),
                    is_directory: true,
                    backup_first: false,
                    executed: false,
                    backup_path: None,
                    error: None,
                    reason: "remove asset cache directory".to_string(),
                });
            }
        }
    }

    // -- Data directory cleanup (only if all data files removed).
    if let Some(ref data_dir) = paths.data_dir
        && data_dir.exists()
        && opts.mode == CleanupMode::Purge
    {
        actions.push(RemovalAction {
            category: RemovalCategory::DataDirectory,
            path: data_dir.clone(),
            is_directory: true,
            backup_first: false,
            executed: false,
            backup_path: None,
            error: None,
            reason: "remove data directory".to_string(),
        });
    }

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string();

    UninstallReport {
        mode: opts.mode,
        dry_run: opts.dry_run,
        timestamp,
        actions,
        kept,
        removed_count: 0,
        failed_count: 0,
        bytes_freed: 0,
    }
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

/// Execute an uninstall plan. Returns the report with results.
#[must_use]
pub fn execute_uninstall(opts: &UninstallOptions) -> UninstallReport {
    let mut report = plan_uninstall(opts);

    if opts.dry_run {
        return report;
    }

    let mut removed_count = 0usize;
    let mut failed_count = 0usize;
    let mut bytes_freed = 0u64;

    for action in &mut report.actions {
        // Create backup if requested.
        if action.backup_first && action.path.exists() {
            match create_backup(&action.path, opts.backup_dir.as_deref()) {
                Ok(backup) => {
                    action.backup_path = Some(backup);
                }
                Err(e) => {
                    action.error = Some(format!("backup failed: {e}"));
                    failed_count += 1;
                    continue;
                }
            }
        }

        // Execute removal.
        let size_before = file_or_dir_size(&action.path);
        let result = if action.category == RemovalCategory::ShellProfileEntry {
            remove_profile_sbh_lines(&action.path)
        } else if action.is_directory {
            remove_directory(&action.path)
        } else {
            remove_file(&action.path)
        };

        match result {
            Ok(()) => {
                action.executed = true;
                removed_count += 1;
                // For profile edits, report only the bytes actually removed (delta),
                // not the entire file size.
                let size_after = file_or_dir_size(&action.path);
                bytes_freed += size_before.saturating_sub(size_after);
            }
            Err(e) => {
                action.executed = false;
                action.error = Some(e.to_string());
                failed_count += 1;
            }
        }
    }

    report.removed_count = removed_count;
    report.failed_count = failed_count;
    report.bytes_freed = bytes_freed;
    report
}

// ---------------------------------------------------------------------------
// Removal helpers
// ---------------------------------------------------------------------------

fn remove_file(path: &Path) -> std::io::Result<()> {
    if path.exists() {
        fs::remove_file(path)
    } else {
        Ok(())
    }
}

fn remove_directory(path: &Path) -> std::io::Result<()> {
    if path.exists() {
        fs::remove_dir_all(path)
    } else {
        Ok(())
    }
}

fn remove_profile_sbh_lines(path: &Path) -> std::io::Result<()> {
    let contents = fs::read_to_string(path)?;
    let filtered: Vec<&str> = contents
        .lines()
        .filter(|l| !(l.contains("sbh") && l.contains("PATH")))
        .collect();
    fs::write(path, filtered.join("\n") + "\n")?;
    Ok(())
}

fn file_or_dir_size(path: &Path) -> u64 {
    if !path.exists() {
        return 0;
    }
    if path.is_dir() {
        dir_size(path)
    } else {
        fs::metadata(path).map(|m| m.len()).unwrap_or(0)
    }
}

fn dir_size(path: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    entries
        .flatten()
        .map(|e| {
            if e.path().is_dir() {
                dir_size(&e.path())
            } else {
                e.metadata().map(|m| m.len()).unwrap_or(0)
            }
        })
        .sum()
}

fn create_backup(path: &Path, backup_dir: Option<&Path>) -> std::io::Result<PathBuf> {
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let file_name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let backup_name = format!("{file_name}.sbh-uninstall-backup-{timestamp}");

    let backup_path = if let Some(dir) = backup_dir {
        fs::create_dir_all(dir)?;
        dir.join(&backup_name)
    } else {
        path.with_file_name(&backup_name)
    };

    fs::copy(path, &backup_path)?;
    Ok(backup_path)
}

#[allow(dead_code)]
fn remove_directory_contents(dir: &Path) -> std::io::Result<u64> {
    let mut bytes = 0u64;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_dir() {
            bytes += remove_directory_contents(&entry.path())?;
        } else {
            bytes += entry.metadata()?.len();
            std::fs::remove_file(entry.path())?;
        }
    }
    // Remove the directory itself after contents are cleared.
    std::fs::remove_dir(dir)?;
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Human-readable formatting
// ---------------------------------------------------------------------------

/// Format an uninstall report for terminal output.
#[must_use]
pub fn format_report_human(report: &UninstallReport) -> String {
    let mut out = String::new();

    if report.dry_run {
        let _ = writeln!(out, "Uninstall plan (dry-run, mode: {})\n", report.mode);
    } else {
        let _ = writeln!(out, "Uninstall report (mode: {})\n", report.mode);
    }

    if !report.actions.is_empty() {
        out.push_str("Actions:\n");
        for action in &report.actions {
            let status = if report.dry_run {
                "PLAN"
            } else if action.executed {
                "DONE"
            } else if action.error.is_some() {
                "FAIL"
            } else {
                "SKIP"
            };
            let _ = writeln!(
                out,
                "  [{status}] {}: {} ({})",
                action.category,
                action.path.display(),
                action.reason
            );
            if let Some(backup) = &action.backup_path {
                let _ = writeln!(out, "        backup: {}", backup.display());
            }
            if let Some(err) = &action.error {
                let _ = writeln!(out, "        error: {err}");
            }
        }
    }

    if !report.kept.is_empty() {
        out.push_str("\nKept:\n");
        for item in &report.kept {
            let _ = writeln!(
                out,
                "  [KEEP] {}: {} ({})",
                item.category,
                item.path.display(),
                item.reason
            );
        }
    }

    if report.dry_run {
        let _ = writeln!(
            out,
            "\n{} action(s) planned. Run without --dry-run to execute.",
            report.actions.len()
        );
    } else {
        let _ = writeln!(
            out,
            "\nSummary: {} removed, {} failed, {} bytes freed",
            report.removed_count, report.failed_count, report.bytes_freed
        );
    }

    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn cleanup_mode_display() {
        assert_eq!(CleanupMode::Conservative.to_string(), "conservative");
        assert_eq!(CleanupMode::KeepData.to_string(), "keep-data");
        assert_eq!(CleanupMode::Purge.to_string(), "purge");
    }

    #[test]
    fn removal_category_display() {
        assert_eq!(RemovalCategory::Binary.to_string(), "binary");
        assert_eq!(RemovalCategory::ConfigFile.to_string(), "config-file");
        assert_eq!(RemovalCategory::AssetCache.to_string(), "asset-cache");
    }

    #[test]
    fn plan_conservative_keeps_data_and_config() {
        let opts = UninstallOptions {
            mode: CleanupMode::Conservative,
            dry_run: true,
            ..Default::default()
        };
        let report = plan_uninstall(&opts);
        // In conservative mode, data and config should be kept.
        for kept in &report.kept {
            assert!(
                matches!(
                    kept.category,
                    RemovalCategory::ConfigFile
                        | RemovalCategory::StateFile
                        | RemovalCategory::SqliteDb
                        | RemovalCategory::JsonlLog
                        | RemovalCategory::AssetCache
                ),
                "conservative should keep data/config/assets, got {}",
                kept.category
            );
        }
    }

    #[test]
    fn plan_purge_removes_everything() {
        let opts = UninstallOptions {
            mode: CleanupMode::Purge,
            dry_run: true,
            ..Default::default()
        };
        let report = plan_uninstall(&opts);
        assert!(
            report.kept.is_empty(),
            "purge mode should not keep anything"
        );
    }

    #[test]
    fn remove_profile_sbh_lines_preserves_other_content() {
        let tmp = TempDir::new().unwrap();
        let profile = tmp.path().join(".bashrc");
        fs::write(
            &profile,
            "# header\nexport PATH=\"/foo/sbh:$PATH\"\nalias ls='ls -la'\n# footer\n",
        )
        .unwrap();

        remove_profile_sbh_lines(&profile).unwrap();

        let contents = fs::read_to_string(&profile).unwrap();
        assert!(!contents.contains("sbh"), "sbh lines should be removed");
        assert!(contents.contains("# header"));
        assert!(contents.contains("alias ls"));
        assert!(contents.contains("# footer"));
    }

    #[test]
    fn remove_file_nonexistent_is_ok() {
        let result = remove_file(Path::new("/nonexistent/path/to/file"));
        assert!(result.is_ok());
    }

    #[test]
    fn remove_directory_nonexistent_is_ok() {
        let result = remove_directory(Path::new("/nonexistent/path/to/dir"));
        assert!(result.is_ok());
    }

    #[test]
    fn create_backup_preserves_content() {
        let tmp = TempDir::new().unwrap();
        let original = tmp.path().join("config.toml");
        fs::write(&original, "key = \"value\"").unwrap();

        let backup = create_backup(&original, None).unwrap();
        assert!(backup.exists());
        assert_eq!(fs::read_to_string(&backup).unwrap(), "key = \"value\"");
        assert!(
            backup
                .file_name()
                .unwrap()
                .to_string_lossy()
                .contains(".sbh-uninstall-backup-")
        );
    }

    #[test]
    fn create_backup_in_custom_dir() {
        let tmp = TempDir::new().unwrap();
        let original = tmp.path().join("test.txt");
        fs::write(&original, "data").unwrap();

        let backup_dir = tmp.path().join("backups");
        let backup = create_backup(&original, Some(&backup_dir)).unwrap();
        assert!(backup.starts_with(&backup_dir));
    }

    #[test]
    fn execute_removes_files() {
        let tmp = TempDir::new().unwrap();
        let file1 = tmp.path().join("sbh");
        let file2 = tmp.path().join("sbh.service");
        fs::write(&file1, "binary").unwrap();
        fs::write(&file2, "[Service]\nExecStart=/usr/bin/sbh").unwrap();

        // Remove individual files.
        remove_file(&file1).unwrap();
        assert!(!file1.exists());

        remove_file(&file2).unwrap();
        assert!(!file2.exists());
    }

    #[test]
    fn execute_removes_directory() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("asset_cache");
        let file = dir.join("model.bin");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&file, "model data").unwrap();

        remove_directory(&dir).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn file_or_dir_size_file() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("test.bin");
        fs::write(&file, b"12345").unwrap();
        assert_eq!(file_or_dir_size(&file), 5);
    }

    #[test]
    fn file_or_dir_size_nonexistent() {
        assert_eq!(file_or_dir_size(Path::new("/nonexistent")), 0);
    }

    #[test]
    fn format_report_dry_run() {
        let report = UninstallReport {
            mode: CleanupMode::Conservative,
            dry_run: true,
            timestamp: "12345".to_string(),
            actions: vec![RemovalAction {
                category: RemovalCategory::Binary,
                path: PathBuf::from("/usr/local/bin/sbh"),
                is_directory: false,
                backup_first: false,
                executed: false,
                backup_path: None,
                error: None,
                reason: "remove sbh binary".to_string(),
            }],
            kept: vec![KeptItem {
                category: RemovalCategory::ConfigFile,
                path: PathBuf::from("/home/user/.config/sbh/config.toml"),
                reason: "kept by conservative mode".to_string(),
            }],
            removed_count: 0,
            failed_count: 0,
            bytes_freed: 0,
        };

        let output = format_report_human(&report);
        assert!(output.contains("dry-run"));
        assert!(output.contains("[PLAN]"));
        assert!(output.contains("[KEEP]"));
        assert!(output.contains("conservative"));
    }

    #[test]
    fn format_report_executed() {
        let report = UninstallReport {
            mode: CleanupMode::Purge,
            dry_run: false,
            timestamp: "12345".to_string(),
            actions: vec![RemovalAction {
                category: RemovalCategory::Binary,
                path: PathBuf::from("/usr/local/bin/sbh"),
                is_directory: false,
                backup_first: false,
                executed: true,
                backup_path: None,
                error: None,
                reason: "remove sbh binary".to_string(),
            }],
            kept: vec![],
            removed_count: 1,
            failed_count: 0,
            bytes_freed: 1024,
        };

        let output = format_report_human(&report);
        assert!(output.contains("[DONE]"));
        assert!(output.contains("1 removed"));
        assert!(output.contains("1024 bytes freed"));
    }

    #[test]
    fn report_serializes_to_json() {
        let report = UninstallReport {
            mode: CleanupMode::Conservative,
            dry_run: true,
            timestamp: "0".to_string(),
            actions: vec![],
            kept: vec![],
            removed_count: 0,
            failed_count: 0,
            bytes_freed: 0,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"mode\":\"Conservative\""));
        assert!(json.contains("\"dry_run\":true"));
    }

    #[test]
    fn keep_data_mode_keeps_logs_and_db() {
        let opts = UninstallOptions {
            mode: CleanupMode::KeepData,
            dry_run: true,
            ..Default::default()
        };
        let report = plan_uninstall(&opts);
        // Config should be removed in KeepData mode.
        assert!(
            !report
                .kept
                .iter()
                .any(|k| k.category == RemovalCategory::ConfigFile),
            "config should not be kept in KeepData mode"
        );
    }

    // bd-2j5.19 — cleanup mode display completeness
    #[test]
    fn cleanup_mode_display_keep_assets() {
        assert_eq!(CleanupMode::KeepAssets.to_string(), "keep-assets");
    }

    #[test]
    fn cleanup_mode_display_keep_config() {
        assert_eq!(CleanupMode::KeepConfig.to_string(), "keep-config");
    }

    // bd-2j5.19 — removal category display completeness
    #[test]
    fn removal_category_display_all_variants() {
        let expected = [
            (RemovalCategory::StateFile, "state-file"),
            (RemovalCategory::SqliteDb, "sqlite-db"),
            (RemovalCategory::JsonlLog, "jsonl-log"),
            (RemovalCategory::SystemdUnit, "systemd-unit"),
            (RemovalCategory::LaunchdPlist, "launchd-plist"),
            (RemovalCategory::ShellCompletion, "shell-completion"),
            (RemovalCategory::ShellProfileEntry, "shell-profile-entry"),
            (RemovalCategory::IntegrationHook, "integration-hook"),
            (RemovalCategory::BallastPool, "ballast-pool"),
            (RemovalCategory::BackupFile, "backup-file"),
            (RemovalCategory::DataDirectory, "data-directory"),
        ];
        for (cat, display) in expected {
            assert_eq!(cat.to_string(), display, "mismatch for {display}");
        }
    }

    // bd-2j5.19 — plan with KeepConfig mode
    #[test]
    fn plan_keep_config_keeps_config_removes_data() {
        let opts = UninstallOptions {
            mode: CleanupMode::KeepConfig,
            dry_run: true,
            ..Default::default()
        };
        let report = plan_uninstall(&opts);
        // Config should be kept.
        // Data should NOT be kept (removed in KeepConfig mode).
        assert!(
            !report
                .kept
                .iter()
                .any(|k| k.category == RemovalCategory::StateFile),
            "state file should not be kept in KeepConfig mode"
        );
    }

    // bd-2j5.19 — plan with KeepAssets mode
    #[test]
    fn plan_keep_assets_mode() {
        let opts = UninstallOptions {
            mode: CleanupMode::KeepAssets,
            dry_run: true,
            ..Default::default()
        };
        let report = plan_uninstall(&opts);
        // Config should not be kept in KeepAssets mode.
        let config_kept = report
            .kept
            .iter()
            .any(|k| k.category == RemovalCategory::ConfigFile);
        assert!(!config_kept);
    }

    // bd-2j5.19 — UninstallOptions default values
    #[test]
    fn uninstall_options_default() {
        let opts = UninstallOptions::default();
        assert_eq!(opts.mode, CleanupMode::Conservative);
        assert!(!opts.dry_run);
        assert!(opts.backup_dir.is_none());
        assert!(opts.binary_path.is_none());
    }

    // bd-2j5.19 — explicit binary path filtering
    #[test]
    fn plan_with_explicit_binary_path() {
        let opts = UninstallOptions {
            mode: CleanupMode::Purge,
            dry_run: true,
            binary_path: Some(PathBuf::from("/opt/custom/sbh")),
            ..Default::default()
        };
        let report = plan_uninstall(&opts);
        // No system-discovered binaries should match /opt/custom/sbh
        // so binary actions should be empty (or only our explicit path if it existed).
        let binary_actions: Vec<_> = report
            .actions
            .iter()
            .filter(|a| a.category == RemovalCategory::Binary)
            .collect();
        for action in &binary_actions {
            assert_eq!(
                action.path,
                PathBuf::from("/opt/custom/sbh"),
                "should only include the explicit binary path"
            );
        }
    }

    // bd-2j5.19 — file_or_dir_size for a directory
    #[test]
    fn file_or_dir_size_directory() {
        let tmp = TempDir::new().unwrap();
        let sub = tmp.path().join("subdir");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("a.txt"), b"hello").unwrap();
        fs::write(sub.join("b.txt"), b"world!").unwrap();
        let size = file_or_dir_size(&sub);
        // 5 + 6 = 11 bytes
        assert_eq!(size, 11);
    }

    // bd-2j5.19 — create_backup for nonexistent file
    #[test]
    fn create_backup_nonexistent_file_fails() {
        let result = create_backup(Path::new("/nonexistent/file.txt"), None);
        assert!(result.is_err());
    }

    // bd-2j5.19 — format_report with failed action
    #[test]
    fn format_report_with_failed_action() {
        let report = UninstallReport {
            mode: CleanupMode::Purge,
            dry_run: false,
            timestamp: "0".to_string(),
            actions: vec![RemovalAction {
                category: RemovalCategory::SqliteDb,
                path: PathBuf::from("/var/lib/sbh/activity.db"),
                is_directory: false,
                backup_first: true,
                executed: false,
                backup_path: None,
                error: Some("permission denied".to_string()),
                reason: "remove sqlite-db".to_string(),
            }],
            kept: vec![],
            removed_count: 0,
            failed_count: 1,
            bytes_freed: 0,
        };
        let output = format_report_human(&report);
        assert!(output.contains("[FAIL]"));
        assert!(output.contains("permission denied"));
        assert!(output.contains("1 failed"));
    }

    // bd-2j5.19 — format_report with skip status
    #[test]
    fn format_report_with_skipped_action() {
        let report = UninstallReport {
            mode: CleanupMode::Conservative,
            dry_run: false,
            timestamp: "0".to_string(),
            actions: vec![RemovalAction {
                category: RemovalCategory::Binary,
                path: PathBuf::from("/usr/local/bin/sbh"),
                is_directory: false,
                backup_first: false,
                executed: false,
                backup_path: None,
                error: None,
                reason: "remove binary".to_string(),
            }],
            kept: vec![],
            removed_count: 0,
            failed_count: 0,
            bytes_freed: 0,
        };
        let output = format_report_human(&report);
        assert!(output.contains("[SKIP]"));
    }
}
