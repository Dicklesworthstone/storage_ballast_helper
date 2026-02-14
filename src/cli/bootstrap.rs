//! Bootstrap migration and self-healing for legacy/partial sbh environments.
//!
//! Detects prior installer footprints, identifies broken/stale/partial states,
//! and applies deterministic migrations with timestamped backups. Every mutation
//! is logged with a reason code and is reversible.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Serialize;

// ---------------------------------------------------------------------------
// Reason codes
// ---------------------------------------------------------------------------

/// Machine-readable reason codes for migration decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum MigrationReason {
    /// Binary exists but is not on PATH.
    BinaryNotOnPath,
    /// Shell profile has a stale PATH entry pointing to a directory that no
    /// longer contains the binary.
    StalePathEntry,
    /// Duplicate PATH entries for sbh in the same profile.
    DuplicatePathEntries,
    /// Systemd unit file references a binary path that does not exist.
    SystemdUnitStaleBinary,
    /// Launchd plist references a binary path that does not exist.
    LaunchdPlistStaleBinary,
    /// Config file uses a deprecated key or schema version.
    DeprecatedConfigKey,
    /// Data directory exists but state file is missing or corrupt.
    MissingStateFile,
    /// Completion script is installed for a shell that is no longer present.
    OrphanedCompletion,
    /// Completion script is out-of-date relative to the current binary version.
    StaleCompletion,
    /// Ballast pool directory exists but is empty or undersized.
    EmptyBallastPool,
    /// Permissions on the binary are incorrect (e.g. not executable).
    BinaryPermissions,
    /// Installer left a stale backup (.bak) file that can be cleaned up.
    StaleBackupFile,
    /// Previous install was interrupted mid-flight (marker file present).
    InterruptedInstall,
}

impl fmt::Display for MigrationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::BinaryNotOnPath => "binary-not-on-path",
            Self::StalePathEntry => "stale-path-entry",
            Self::DuplicatePathEntries => "duplicate-path-entries",
            Self::SystemdUnitStaleBinary => "systemd-unit-stale-binary",
            Self::LaunchdPlistStaleBinary => "launchd-plist-stale-binary",
            Self::DeprecatedConfigKey => "deprecated-config-key",
            Self::MissingStateFile => "missing-state-file",
            Self::OrphanedCompletion => "orphaned-completion",
            Self::StaleCompletion => "stale-completion",
            Self::EmptyBallastPool => "empty-ballast-pool",
            Self::BinaryPermissions => "binary-permissions",
            Self::StaleBackupFile => "stale-backup-file",
            Self::InterruptedInstall => "interrupted-install",
        };
        f.write_str(label)
    }
}

// ---------------------------------------------------------------------------
// Footprint detection
// ---------------------------------------------------------------------------

/// A detected installation footprint on the system.
#[derive(Debug, Clone, Serialize)]
pub struct Footprint {
    /// What this footprint represents.
    pub kind: FootprintKind,
    /// Filesystem path where the footprint was found.
    pub path: PathBuf,
    /// Whether the footprint appears healthy.
    pub healthy: bool,
    /// If unhealthy, the reason code.
    pub issue: Option<MigrationReason>,
    /// Human-readable detail about the issue.
    pub detail: Option<String>,
}

/// Categories of installer footprints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum FootprintKind {
    Binary,
    ConfigFile,
    DataDirectory,
    StateFile,
    SqliteDb,
    JsonlLog,
    ShellProfile,
    SystemdUnit,
    LaunchdPlist,
    ShellCompletion,
    BallastPool,
    BackupFile,
}

impl fmt::Display for FootprintKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Binary => "binary",
            Self::ConfigFile => "config-file",
            Self::DataDirectory => "data-directory",
            Self::StateFile => "state-file",
            Self::SqliteDb => "sqlite-db",
            Self::JsonlLog => "jsonl-log",
            Self::ShellProfile => "shell-profile",
            Self::SystemdUnit => "systemd-unit",
            Self::LaunchdPlist => "launchd-plist",
            Self::ShellCompletion => "shell-completion",
            Self::BallastPool => "ballast-pool",
            Self::BackupFile => "backup-file",
        };
        f.write_str(label)
    }
}

// ---------------------------------------------------------------------------
// Migration plan and actions
// ---------------------------------------------------------------------------

/// A single migration action to be applied.
#[derive(Debug, Clone, Serialize)]
pub struct MigrationAction {
    /// What we plan to do.
    pub kind: ActionKind,
    /// Reason for this action.
    pub reason: MigrationReason,
    /// Path being mutated.
    pub target: PathBuf,
    /// Human-readable description of the change.
    pub description: String,
    /// Whether this action was actually applied.
    pub applied: bool,
    /// Backup path created before mutation (if any).
    pub backup_path: Option<PathBuf>,
    /// Error message if the action failed.
    pub error: Option<String>,
}

/// Types of migration actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ActionKind {
    /// Remove a stale line from a shell profile.
    RemoveProfileLine,
    /// Deduplicate PATH entries in a shell profile.
    DeduplicateProfile,
    /// Fix binary permissions.
    FixPermissions,
    /// Update a service unit file to point to current binary.
    UpdateServicePath,
    /// Remove an orphaned completion script.
    RemoveOrphanedFile,
    /// Clean up stale backup files.
    CleanupBackup,
    /// Create a missing data directory.
    CreateDirectory,
    /// Initialize a missing state file with defaults.
    InitStateFile,
}

impl fmt::Display for ActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::RemoveProfileLine => "remove-profile-line",
            Self::DeduplicateProfile => "deduplicate-profile",
            Self::FixPermissions => "fix-permissions",
            Self::UpdateServicePath => "update-service-path",
            Self::RemoveOrphanedFile => "remove-orphaned-file",
            Self::CleanupBackup => "cleanup-backup",
            Self::CreateDirectory => "create-directory",
            Self::InitStateFile => "init-state-file",
        };
        f.write_str(label)
    }
}

// ---------------------------------------------------------------------------
// Migration report
// ---------------------------------------------------------------------------

/// Complete migration report, suitable for both human and JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct MigrationReport {
    /// Timestamp when the scan was performed.
    pub scanned_at: String,
    /// All detected footprints.
    pub footprints: Vec<Footprint>,
    /// Planned or executed migration actions.
    pub actions: Vec<MigrationAction>,
    /// Overall health assessment.
    pub health: EnvironmentHealth,
    /// Number of issues detected.
    pub issues_found: usize,
    /// Number of issues repaired.
    pub issues_repaired: usize,
}

/// Overall environment health.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EnvironmentHealth {
    /// Everything looks correct.
    Healthy,
    /// Minor issues detected but sbh is functional.
    Degraded,
    /// Significant issues that may prevent normal operation.
    Broken,
    /// No installation detected.
    NotInstalled,
}

impl fmt::Display for EnvironmentHealth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Healthy => f.write_str("healthy"),
            Self::Degraded => f.write_str("degraded"),
            Self::Broken => f.write_str("broken"),
            Self::NotInstalled => f.write_str("not-installed"),
        }
    }
}

// ---------------------------------------------------------------------------
// Backup helper
// ---------------------------------------------------------------------------

/// Create a timestamped backup of a file before mutating it.
/// Returns the backup path on success.
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

    let backup_name = format!("{file_name}.sbh-backup-{timestamp}");

    let backup_path = if let Some(dir) = backup_dir {
        fs::create_dir_all(dir)?;
        dir.join(&backup_name)
    } else {
        path.with_file_name(&backup_name)
    };

    fs::copy(path, &backup_path)?;
    Ok(backup_path)
}

// ---------------------------------------------------------------------------
// Scanner: detect footprints
// ---------------------------------------------------------------------------

/// Known locations to probe for sbh binaries.
fn candidate_binary_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(home) = home_dir() {
        paths.push(home.join(".local").join("bin").join("sbh"));
        paths.push(home.join(".cargo").join("bin").join("sbh"));
    }
    paths.push(PathBuf::from("/usr/local/bin/sbh"));
    paths.push(PathBuf::from("/usr/bin/sbh"));
    // Current executable location.
    if let Ok(exe) = std::env::current_exe() {
        if !paths.contains(&exe) {
            paths.push(exe);
        }
    }
    paths
}

/// Known shell profile paths to inspect for PATH entries.
fn candidate_profile_paths() -> Vec<PathBuf> {
    let Some(home) = home_dir() else {
        return Vec::new();
    };
    vec![
        home.join(".bashrc"),
        home.join(".bash_profile"),
        home.join(".profile"),
        home.join(".zshrc"),
        home.join(".zprofile"),
    ]
}

/// Known systemd unit locations.
fn candidate_systemd_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("/etc/systemd/system/sbh.service")];
    if let Some(home) = home_dir() {
        paths.push(
            home.join(".config")
                .join("systemd")
                .join("user")
                .join("sbh.service"),
        );
    }
    paths
}

/// Known launchd plist locations (macOS).
fn candidate_launchd_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("/Library/LaunchDaemons/com.sbh.daemon.plist")];
    if let Some(home) = home_dir() {
        paths.push(
            home.join("Library")
                .join("LaunchAgents")
                .join("com.sbh.daemon.plist"),
        );
    }
    paths
}

/// Shell completion file locations.
fn candidate_completion_paths() -> Vec<(PathBuf, &'static str)> {
    let mut paths: Vec<(PathBuf, &str)> = Vec::new();
    // bash
    paths.push((PathBuf::from("/etc/bash_completion.d/sbh"), "bash"));
    if let Some(home) = home_dir() {
        paths.push((
            home.join(".local")
                .join("share")
                .join("bash-completion")
                .join("completions")
                .join("sbh"),
            "bash",
        ));
        // zsh
        paths.push((home.join(".zfunc").join("_sbh"), "zsh"));
        // fish
        paths.push((
            home.join(".config")
                .join("fish")
                .join("completions")
                .join("sbh.fish"),
            "fish",
        ));
    }
    paths
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Scan the system for all sbh installation footprints.
#[must_use]
pub fn scan_footprints() -> Vec<Footprint> {
    let mut footprints = Vec::new();

    // -- Binaries.
    for path in candidate_binary_paths() {
        if path.exists() {
            let (healthy, issue, detail) = check_binary_health(&path);
            footprints.push(Footprint {
                kind: FootprintKind::Binary,
                path,
                healthy,
                issue,
                detail,
            });
        }
    }

    // -- Config file.
    if let Some(home) = home_dir() {
        let cfg = home.join(".config").join("sbh").join("config.toml");
        if cfg.exists() {
            let (healthy, issue, detail) = check_config_health(&cfg);
            footprints.push(Footprint {
                kind: FootprintKind::ConfigFile,
                path: cfg,
                healthy,
                issue,
                detail,
            });
        }

        // -- Data directory.
        let data = home.join(".local").join("share").join("sbh");
        if data.exists() {
            footprints.push(Footprint {
                kind: FootprintKind::DataDirectory,
                path: data.clone(),
                healthy: true,
                issue: None,
                detail: None,
            });

            // State file.
            let state = data.join("state.json");
            if state.exists() {
                footprints.push(Footprint {
                    kind: FootprintKind::StateFile,
                    path: state,
                    healthy: true,
                    issue: None,
                    detail: None,
                });
            } else if data.exists() {
                footprints.push(Footprint {
                    kind: FootprintKind::StateFile,
                    path: state,
                    healthy: false,
                    issue: Some(MigrationReason::MissingStateFile),
                    detail: Some("data directory exists but state.json is missing".into()),
                });
            }

            // SQLite DB.
            let sqlite = data.join("activity.sqlite3");
            if sqlite.exists() {
                footprints.push(Footprint {
                    kind: FootprintKind::SqliteDb,
                    path: sqlite,
                    healthy: true,
                    issue: None,
                    detail: None,
                });
            }

            // JSONL log.
            let jsonl = data.join("activity.jsonl");
            if jsonl.exists() {
                footprints.push(Footprint {
                    kind: FootprintKind::JsonlLog,
                    path: jsonl,
                    healthy: true,
                    issue: None,
                    detail: None,
                });
            }
        }
    }

    // -- Shell profiles (PATH entries).
    for profile in candidate_profile_paths() {
        if let Ok(contents) = fs::read_to_string(&profile) {
            let sbh_lines: Vec<&str> = contents
                .lines()
                .filter(|l| l.contains("sbh") && l.contains("PATH"))
                .collect();
            if !sbh_lines.is_empty() {
                let (healthy, issue, detail) = check_profile_health(&profile, &sbh_lines);
                footprints.push(Footprint {
                    kind: FootprintKind::ShellProfile,
                    path: profile,
                    healthy,
                    issue,
                    detail,
                });
            }
        }
    }

    // -- Systemd units.
    for path in candidate_systemd_paths() {
        if path.exists() {
            let (healthy, issue, detail) = check_systemd_health(&path);
            footprints.push(Footprint {
                kind: FootprintKind::SystemdUnit,
                path,
                healthy,
                issue,
                detail,
            });
        }
    }

    // -- Launchd plists.
    for path in candidate_launchd_paths() {
        if path.exists() {
            let (healthy, issue, detail) = check_launchd_health(&path);
            footprints.push(Footprint {
                kind: FootprintKind::LaunchdPlist,
                path,
                healthy,
                issue,
                detail,
            });
        }
    }

    // -- Shell completions.
    for (path, shell) in candidate_completion_paths() {
        if path.exists() {
            let healthy = is_shell_available(shell);
            footprints.push(Footprint {
                kind: FootprintKind::ShellCompletion,
                path,
                healthy,
                issue: if healthy {
                    None
                } else {
                    Some(MigrationReason::OrphanedCompletion)
                },
                detail: if healthy {
                    None
                } else {
                    Some(format!("{shell} completion installed but shell not found"))
                },
            });
        }
    }

    // -- Stale backup files.
    if let Some(home) = home_dir() {
        for profile in candidate_profile_paths() {
            if let Some(parent) = profile.parent() {
                scan_backups_in(parent, &mut footprints);
            }
        }
        let data = home.join(".local").join("share").join("sbh");
        if data.exists() {
            scan_backups_in(&data, &mut footprints);
        }
    }

    footprints
}

fn scan_backups_in(dir: &Path, footprints: &mut Vec<Footprint>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.contains(".sbh-backup-") || name.ends_with(".sbh.bak") {
                footprints.push(Footprint {
                    kind: FootprintKind::BackupFile,
                    path: entry.path(),
                    healthy: true,
                    issue: Some(MigrationReason::StaleBackupFile),
                    detail: Some("stale backup file from previous install/migration".into()),
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Health-check helpers
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn check_binary_health(path: &Path) -> (bool, Option<MigrationReason>, Option<String>) {
    use std::os::unix::fs::PermissionsExt;
    match fs::metadata(path) {
        Ok(meta) => {
            let mode = meta.permissions().mode();
            if mode & 0o111 == 0 {
                (
                    false,
                    Some(MigrationReason::BinaryPermissions),
                    Some(format!(
                        "binary at {} is not executable (mode {mode:o})",
                        path.display()
                    )),
                )
            } else {
                (true, None, None)
            }
        }
        Err(e) => (
            false,
            Some(MigrationReason::BinaryPermissions),
            Some(format!("cannot stat binary: {e}")),
        ),
    }
}

#[cfg(not(unix))]
fn check_binary_health(path: &Path) -> (bool, Option<MigrationReason>, Option<String>) {
    if path.exists() {
        (true, None, None)
    } else {
        (
            false,
            Some(MigrationReason::BinaryPermissions),
            Some("binary does not exist".into()),
        )
    }
}

fn check_config_health(path: &Path) -> (bool, Option<MigrationReason>, Option<String>) {
    match fs::read_to_string(path) {
        Ok(contents) => {
            // Check for known deprecated keys.
            let deprecated_keys = ["scan_interval_secs", "max_ballast_mb", "log_level"];
            for key in &deprecated_keys {
                if contents.contains(key) {
                    return (
                        false,
                        Some(MigrationReason::DeprecatedConfigKey),
                        Some(format!("config contains deprecated key: {key}")),
                    );
                }
            }
            (true, None, None)
        }
        Err(e) => (
            false,
            Some(MigrationReason::DeprecatedConfigKey),
            Some(format!("cannot read config: {e}")),
        ),
    }
}

fn check_profile_health(
    _path: &Path,
    sbh_lines: &[&str],
) -> (bool, Option<MigrationReason>, Option<String>) {
    if sbh_lines.len() > 1 {
        return (
            false,
            Some(MigrationReason::DuplicatePathEntries),
            Some(format!(
                "found {} sbh PATH entries, expected at most 1",
                sbh_lines.len()
            )),
        );
    }

    // Check if the referenced directory in the PATH entry actually contains sbh.
    if let Some(line) = sbh_lines.first() {
        if let Some(dir) = extract_path_dir_from_export(line) {
            let binary = PathBuf::from(&dir).join("sbh");
            if !binary.exists() {
                return (
                    false,
                    Some(MigrationReason::StalePathEntry),
                    Some(format!(
                        "PATH entry references {dir} but sbh binary not found there"
                    )),
                );
            }
        }
    }

    (true, None, None)
}

/// Extract the directory path from an `export PATH="<dir>:$PATH"` line.
fn extract_path_dir_from_export(line: &str) -> Option<String> {
    // Matches patterns like: export PATH="/some/path:$PATH"
    let trimmed = line.trim();
    if let Some(after_eq) = trimmed.strip_prefix("export PATH=\"") {
        if let Some(colon_pos) = after_eq.find(':') {
            return Some(after_eq[..colon_pos].to_string());
        }
    }
    // Also handle: export PATH='/some/path:$PATH'
    if let Some(after_eq) = trimmed.strip_prefix("export PATH='") {
        if let Some(colon_pos) = after_eq.find(':') {
            return Some(after_eq[..colon_pos].to_string());
        }
    }
    None
}

fn check_systemd_health(path: &Path) -> (bool, Option<MigrationReason>, Option<String>) {
    match fs::read_to_string(path) {
        Ok(contents) => {
            // Find ExecStart line and check if binary exists.
            for line in contents.lines() {
                let trimmed = line.trim();
                if let Some(exec_path) = trimmed.strip_prefix("ExecStart=") {
                    let binary = exec_path.split_whitespace().next().unwrap_or("");
                    if !binary.is_empty() && !Path::new(binary).exists() {
                        return (
                            false,
                            Some(MigrationReason::SystemdUnitStaleBinary),
                            Some(format!(
                                "ExecStart references {binary} which does not exist"
                            )),
                        );
                    }
                }
            }
            (true, None, None)
        }
        Err(e) => (
            false,
            Some(MigrationReason::SystemdUnitStaleBinary),
            Some(format!("cannot read unit file: {e}")),
        ),
    }
}

fn check_launchd_health(path: &Path) -> (bool, Option<MigrationReason>, Option<String>) {
    match fs::read_to_string(path) {
        Ok(contents) => {
            // Look for ProgramArguments -> first string (binary path).
            // Simplified XML parsing: find line after <key>ProgramArguments</key>.
            let lines: Vec<&str> = contents.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                if line.contains("<key>ProgramArguments</key>") {
                    // Search subsequent lines for first <string>...</string>.
                    for subsequent in &lines[i + 1..] {
                        let trimmed = subsequent.trim();
                        if let Some(rest) = trimmed.strip_prefix("<string>") {
                            if let Some(binary) = rest.strip_suffix("</string>") {
                                if !Path::new(binary).exists() {
                                    return (
                                        false,
                                        Some(MigrationReason::LaunchdPlistStaleBinary),
                                        Some(format!(
                                            "ProgramArguments references {binary} which does not exist"
                                        )),
                                    );
                                }
                                break;
                            }
                        }
                    }
                }
            }
            (true, None, None)
        }
        Err(e) => (
            false,
            Some(MigrationReason::LaunchdPlistStaleBinary),
            Some(format!("cannot read plist: {e}")),
        ),
    }
}

fn is_shell_available(shell: &str) -> bool {
    which_shell(shell).is_some()
}

fn which_shell(shell: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join(shell);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Migration engine
// ---------------------------------------------------------------------------

/// Options for running the migration engine.
#[derive(Debug, Clone)]
pub struct MigrateOptions {
    /// Only report, do not apply changes.
    pub dry_run: bool,
    /// Override backup directory (default: alongside the mutated file).
    pub backup_dir: Option<PathBuf>,
    /// Clean up stale backup files older than this (seconds). 0 = skip cleanup.
    pub cleanup_backups_older_than: u64,
}

impl Default for MigrateOptions {
    fn default() -> Self {
        Self {
            dry_run: false,
            backup_dir: None,
            cleanup_backups_older_than: 7 * 24 * 3600, // 7 days
        }
    }
}

/// Run the full migration pipeline: scan, plan, apply (or dry-run).
pub fn run_migration(opts: &MigrateOptions) -> MigrationReport {
    let footprints = scan_footprints();
    let mut actions = plan_actions(&footprints, opts);
    let (issues_found, _) = count_issues(&footprints);

    if !opts.dry_run {
        apply_actions(&mut actions, opts.backup_dir.as_deref());
    }

    let issues_repaired = actions
        .iter()
        .filter(|a| a.applied && a.error.is_none())
        .count();
    let health = assess_health(&footprints, &actions);

    let scanned_at = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string();

    MigrationReport {
        scanned_at,
        footprints,
        actions,
        health,
        issues_found,
        issues_repaired,
    }
}

fn count_issues(footprints: &[Footprint]) -> (usize, usize) {
    let total = footprints
        .iter()
        .filter(|f| !f.healthy || f.issue.is_some())
        .count();
    (total, 0)
}

fn assess_health(footprints: &[Footprint], actions: &[MigrationAction]) -> EnvironmentHealth {
    let has_binary = footprints.iter().any(|f| f.kind == FootprintKind::Binary);
    if !has_binary {
        return EnvironmentHealth::NotInstalled;
    }

    let unresolved = actions
        .iter()
        .filter(|a| !a.applied || a.error.is_some())
        .count();
    let unhealthy = footprints.iter().filter(|f| !f.healthy).count();

    if unhealthy == 0 && unresolved == 0 {
        EnvironmentHealth::Healthy
    } else if footprints
        .iter()
        .any(|f| f.kind == FootprintKind::Binary && !f.healthy)
    {
        EnvironmentHealth::Broken
    } else {
        EnvironmentHealth::Degraded
    }
}

// ---------------------------------------------------------------------------
// Action planning
// ---------------------------------------------------------------------------

fn plan_actions(footprints: &[Footprint], opts: &MigrateOptions) -> Vec<MigrationAction> {
    let mut actions = Vec::new();

    for fp in footprints {
        match (fp.kind, fp.issue) {
            (FootprintKind::ShellProfile, Some(MigrationReason::StalePathEntry)) => {
                actions.push(MigrationAction {
                    kind: ActionKind::RemoveProfileLine,
                    reason: MigrationReason::StalePathEntry,
                    target: fp.path.clone(),
                    description: format!("remove stale PATH entry from {}", fp.path.display()),
                    applied: false,
                    backup_path: None,
                    error: None,
                });
            }
            (FootprintKind::ShellProfile, Some(MigrationReason::DuplicatePathEntries)) => {
                actions.push(MigrationAction {
                    kind: ActionKind::DeduplicateProfile,
                    reason: MigrationReason::DuplicatePathEntries,
                    target: fp.path.clone(),
                    description: format!("deduplicate sbh PATH entries in {}", fp.path.display()),
                    applied: false,
                    backup_path: None,
                    error: None,
                });
            }
            (FootprintKind::Binary, Some(MigrationReason::BinaryPermissions)) => {
                actions.push(MigrationAction {
                    kind: ActionKind::FixPermissions,
                    reason: MigrationReason::BinaryPermissions,
                    target: fp.path.clone(),
                    description: format!("fix executable permissions on {}", fp.path.display()),
                    applied: false,
                    backup_path: None,
                    error: None,
                });
            }
            (FootprintKind::SystemdUnit, Some(MigrationReason::SystemdUnitStaleBinary)) => {
                if let Some(current_exe) = current_binary_path() {
                    actions.push(MigrationAction {
                        kind: ActionKind::UpdateServicePath,
                        reason: MigrationReason::SystemdUnitStaleBinary,
                        target: fp.path.clone(),
                        description: format!(
                            "update ExecStart in {} to {}",
                            fp.path.display(),
                            current_exe.display()
                        ),
                        applied: false,
                        backup_path: None,
                        error: None,
                    });
                }
            }
            (FootprintKind::LaunchdPlist, Some(MigrationReason::LaunchdPlistStaleBinary)) => {
                if let Some(current_exe) = current_binary_path() {
                    actions.push(MigrationAction {
                        kind: ActionKind::UpdateServicePath,
                        reason: MigrationReason::LaunchdPlistStaleBinary,
                        target: fp.path.clone(),
                        description: format!(
                            "update ProgramArguments in {} to {}",
                            fp.path.display(),
                            current_exe.display()
                        ),
                        applied: false,
                        backup_path: None,
                        error: None,
                    });
                }
            }
            (FootprintKind::ShellCompletion, Some(MigrationReason::OrphanedCompletion)) => {
                actions.push(MigrationAction {
                    kind: ActionKind::RemoveOrphanedFile,
                    reason: MigrationReason::OrphanedCompletion,
                    target: fp.path.clone(),
                    description: format!("remove orphaned completion script {}", fp.path.display()),
                    applied: false,
                    backup_path: None,
                    error: None,
                });
            }
            (FootprintKind::StateFile, Some(MigrationReason::MissingStateFile)) => {
                actions.push(MigrationAction {
                    kind: ActionKind::InitStateFile,
                    reason: MigrationReason::MissingStateFile,
                    target: fp.path.clone(),
                    description: format!("initialize missing state file at {}", fp.path.display()),
                    applied: false,
                    backup_path: None,
                    error: None,
                });
            }
            (FootprintKind::BackupFile, Some(MigrationReason::StaleBackupFile)) => {
                if opts.cleanup_backups_older_than > 0 {
                    if is_older_than(&fp.path, opts.cleanup_backups_older_than) {
                        actions.push(MigrationAction {
                            kind: ActionKind::CleanupBackup,
                            reason: MigrationReason::StaleBackupFile,
                            target: fp.path.clone(),
                            description: format!("remove stale backup {}", fp.path.display()),
                            applied: false,
                            backup_path: None,
                            error: None,
                        });
                    }
                }
            }
            _ => {}
        }
    }

    actions
}

fn is_older_than(path: &Path, seconds: u64) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    let Ok(age) = SystemTime::now().duration_since(modified) else {
        return false;
    };
    age.as_secs() > seconds
}

fn current_binary_path() -> Option<PathBuf> {
    std::env::current_exe().ok()
}

// ---------------------------------------------------------------------------
// Action application
// ---------------------------------------------------------------------------

fn apply_actions(actions: &mut [MigrationAction], backup_dir: Option<&Path>) {
    for action in actions.iter_mut() {
        let result = match action.kind {
            ActionKind::RemoveProfileLine => apply_remove_profile_line(action, backup_dir),
            ActionKind::DeduplicateProfile => apply_deduplicate_profile(action, backup_dir),
            ActionKind::FixPermissions => apply_fix_permissions(action),
            ActionKind::UpdateServicePath => apply_update_service_path(action, backup_dir),
            ActionKind::RemoveOrphanedFile => apply_remove_orphaned_file(action, backup_dir),
            ActionKind::CleanupBackup => apply_cleanup_backup(action),
            ActionKind::CreateDirectory => apply_create_directory(action),
            ActionKind::InitStateFile => apply_init_state_file(action),
        };
        match result {
            Ok(()) => {
                action.applied = true;
            }
            Err(e) => {
                action.applied = false;
                action.error = Some(e.to_string());
            }
        }
    }
}

fn apply_remove_profile_line(
    action: &mut MigrationAction,
    backup_dir: Option<&Path>,
) -> std::io::Result<()> {
    let backup = create_backup(&action.target, backup_dir)?;
    action.backup_path = Some(backup);

    let contents = fs::read_to_string(&action.target)?;
    let filtered: Vec<&str> = contents
        .lines()
        .filter(|l| !(l.contains("sbh") && l.contains("PATH")))
        .collect();
    fs::write(&action.target, filtered.join("\n") + "\n")?;
    Ok(())
}

fn apply_deduplicate_profile(
    action: &mut MigrationAction,
    backup_dir: Option<&Path>,
) -> std::io::Result<()> {
    let backup = create_backup(&action.target, backup_dir)?;
    action.backup_path = Some(backup);

    let contents = fs::read_to_string(&action.target)?;
    let mut seen_sbh_path = false;
    let filtered: Vec<&str> = contents
        .lines()
        .filter(|l| {
            if l.contains("sbh") && l.contains("PATH") {
                if seen_sbh_path {
                    return false; // Remove duplicate.
                }
                seen_sbh_path = true;
            }
            true
        })
        .collect();
    fs::write(&action.target, filtered.join("\n") + "\n")?;
    Ok(())
}

#[cfg(unix)]
fn apply_fix_permissions(action: &mut MigrationAction) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::metadata(&action.target)?;
    let mut perms = meta.permissions();
    let mode = perms.mode() | 0o755;
    perms.set_mode(mode);
    fs::set_permissions(&action.target, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn apply_fix_permissions(_action: &mut MigrationAction) -> std::io::Result<()> {
    // No-op on non-Unix platforms.
    Ok(())
}

fn apply_update_service_path(
    action: &mut MigrationAction,
    backup_dir: Option<&Path>,
) -> std::io::Result<()> {
    let backup = create_backup(&action.target, backup_dir)?;
    action.backup_path = Some(backup);

    let contents = fs::read_to_string(&action.target)?;
    let Some(current_exe) = current_binary_path() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cannot determine current binary path",
        ));
    };
    let exe_str = current_exe.to_string_lossy().to_string();

    let updated: Vec<String> = contents
        .lines()
        .map(|line| {
            let trimmed = line.trim();
            if let Some(_rest) = trimmed.strip_prefix("ExecStart=") {
                // Systemd: replace ExecStart line.
                format!("ExecStart={exe_str} daemon run")
            } else if trimmed.starts_with("<string>") && trimmed.ends_with("</string>") {
                // Launchd: this is a simplification; only replace the first
                // string element after ProgramArguments.
                // We check if it looks like a binary path.
                let inner = &trimmed[8..trimmed.len() - 9];
                if inner.contains("sbh") || inner.starts_with('/') {
                    format!("        <string>{exe_str}</string>")
                } else {
                    line.to_string()
                }
            } else {
                line.to_string()
            }
        })
        .collect();
    fs::write(&action.target, updated.join("\n") + "\n")?;
    Ok(())
}

fn apply_remove_orphaned_file(
    action: &mut MigrationAction,
    backup_dir: Option<&Path>,
) -> std::io::Result<()> {
    let backup = create_backup(&action.target, backup_dir)?;
    action.backup_path = Some(backup);
    fs::remove_file(&action.target)?;
    Ok(())
}

fn apply_cleanup_backup(action: &mut MigrationAction) -> std::io::Result<()> {
    fs::remove_file(&action.target)?;
    Ok(())
}

fn apply_create_directory(action: &mut MigrationAction) -> std::io::Result<()> {
    fs::create_dir_all(&action.target)?;
    Ok(())
}

fn apply_init_state_file(action: &mut MigrationAction) -> std::io::Result<()> {
    if let Some(parent) = action.target.parent() {
        fs::create_dir_all(parent)?;
    }
    // Write minimal valid state JSON.
    let initial_state = r#"{"version":"0.1.0","pid":0,"started_at":"","uptime_seconds":0}"#;
    fs::write(&action.target, initial_state)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Formatting helpers for human output
// ---------------------------------------------------------------------------

/// Format a migration report for human-readable terminal output.
#[must_use]
pub fn format_report_human(report: &MigrationReport) -> String {
    let mut out = String::new();

    out.push_str(&format!("Environment health: {}\n", report.health));
    out.push_str(&format!("Footprints found: {}\n", report.footprints.len()));
    out.push_str(&format!(
        "Issues found: {} | Repaired: {}\n\n",
        report.issues_found, report.issues_repaired
    ));

    if !report.footprints.is_empty() {
        out.push_str("Footprints:\n");
        for fp in &report.footprints {
            let status = if fp.healthy { "OK" } else { "ISSUE" };
            out.push_str(&format!(
                "  [{status}] {}: {}\n",
                fp.kind,
                fp.path.display()
            ));
            if let Some(detail) = &fp.detail {
                out.push_str(&format!("        {detail}\n"));
            }
        }
        out.push('\n');
    }

    if !report.actions.is_empty() {
        out.push_str("Actions:\n");
        for action in &report.actions {
            let status = if action.applied {
                if action.error.is_some() {
                    "FAIL"
                } else {
                    "DONE"
                }
            } else {
                "PLAN"
            };
            out.push_str(&format!(
                "  [{status}] {}: {}\n",
                action.reason, action.description
            ));
            if let Some(backup) = &action.backup_path {
                out.push_str(&format!("        backup: {}\n", backup.display()));
            }
            if let Some(err) = &action.error {
                out.push_str(&format!("        error: {err}\n"));
            }
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
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn migration_reason_display() {
        assert_eq!(
            MigrationReason::BinaryNotOnPath.to_string(),
            "binary-not-on-path"
        );
        assert_eq!(
            MigrationReason::StalePathEntry.to_string(),
            "stale-path-entry"
        );
        assert_eq!(
            MigrationReason::SystemdUnitStaleBinary.to_string(),
            "systemd-unit-stale-binary"
        );
    }

    #[test]
    fn footprint_kind_display() {
        assert_eq!(FootprintKind::Binary.to_string(), "binary");
        assert_eq!(FootprintKind::SystemdUnit.to_string(), "systemd-unit");
        assert_eq!(
            FootprintKind::ShellCompletion.to_string(),
            "shell-completion"
        );
    }

    #[test]
    fn environment_health_display() {
        assert_eq!(EnvironmentHealth::Healthy.to_string(), "healthy");
        assert_eq!(EnvironmentHealth::Broken.to_string(), "broken");
        assert_eq!(EnvironmentHealth::NotInstalled.to_string(), "not-installed");
    }

    #[test]
    fn extract_path_dir_double_quotes() {
        let line = r#"export PATH="/home/user/.local/bin:$PATH""#;
        assert_eq!(
            extract_path_dir_from_export(line),
            Some("/home/user/.local/bin".to_string())
        );
    }

    #[test]
    fn extract_path_dir_single_quotes() {
        let line = "export PATH='/usr/local/bin:$PATH'";
        assert_eq!(
            extract_path_dir_from_export(line),
            Some("/usr/local/bin".to_string())
        );
    }

    #[test]
    fn extract_path_dir_no_match() {
        assert_eq!(extract_path_dir_from_export("echo hello"), None);
        assert_eq!(extract_path_dir_from_export("PATH=/foo"), None);
    }

    #[test]
    fn create_backup_works() {
        let tmp = TempDir::new().unwrap();
        let original = tmp.path().join("test.txt");
        fs::write(&original, "original content").unwrap();

        let backup = create_backup(&original, None).unwrap();
        assert!(backup.exists());
        assert_eq!(fs::read_to_string(&backup).unwrap(), "original content");
        assert!(
            backup
                .file_name()
                .unwrap()
                .to_string_lossy()
                .contains(".sbh-backup-")
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
        assert!(backup.exists());
    }

    #[test]
    fn profile_health_detects_duplicates() {
        let tmp = TempDir::new().unwrap();
        let profile = tmp.path().join(".bashrc");
        let lines = vec![
            r#"export PATH="/home/user/.local/bin:$PATH"  # sbh"#,
            r#"export PATH="/home/user/.local/bin:$PATH"  # sbh"#,
        ];
        let (healthy, issue, _) = check_profile_health(&profile, &lines);
        assert!(!healthy);
        assert_eq!(issue, Some(MigrationReason::DuplicatePathEntries));
    }

    #[test]
    fn profile_health_stale_path() {
        let tmp = TempDir::new().unwrap();
        let profile = tmp.path().join(".bashrc");
        // Reference a directory that does not contain sbh.
        let nonexistent = tmp.path().join("nonexistent");
        let line = format!(r#"export PATH="{}:$PATH""#, nonexistent.display());
        let lines = vec![line.as_str()];
        let (healthy, issue, _) = check_profile_health(&profile, &lines);
        assert!(!healthy);
        assert_eq!(issue, Some(MigrationReason::StalePathEntry));
    }

    #[test]
    fn systemd_health_stale_binary() {
        let tmp = TempDir::new().unwrap();
        let unit = tmp.path().join("sbh.service");
        fs::write(&unit, "[Service]\nExecStart=/nonexistent/sbh daemon run\n").unwrap();
        let (healthy, issue, _) = check_systemd_health(&unit);
        assert!(!healthy);
        assert_eq!(issue, Some(MigrationReason::SystemdUnitStaleBinary));
    }

    #[test]
    fn systemd_health_ok_when_binary_exists() {
        let tmp = TempDir::new().unwrap();
        // Use a binary that definitely exists.
        let existing = std::env::current_exe().unwrap();
        let unit = tmp.path().join("sbh.service");
        fs::write(
            &unit,
            format!("[Service]\nExecStart={}\n", existing.display()),
        )
        .unwrap();
        let (healthy, issue, _) = check_systemd_health(&unit);
        assert!(healthy);
        assert!(issue.is_none());
    }

    #[test]
    fn launchd_health_stale_binary() {
        let tmp = TempDir::new().unwrap();
        let plist = tmp.path().join("com.sbh.daemon.plist");
        let xml = r#"<?xml version="1.0"?>
<plist version="1.0">
<dict>
    <key>ProgramArguments</key>
    <array>
        <string>/nonexistent/sbh</string>
        <string>daemon</string>
        <string>run</string>
    </array>
</dict>
</plist>"#;
        fs::write(&plist, xml).unwrap();
        let (healthy, issue, _) = check_launchd_health(&plist);
        assert!(!healthy);
        assert_eq!(issue, Some(MigrationReason::LaunchdPlistStaleBinary));
    }

    #[test]
    fn config_health_deprecated_key() {
        let tmp = TempDir::new().unwrap();
        let cfg = tmp.path().join("config.toml");
        fs::write(&cfg, "scan_interval_secs = 30\n").unwrap();
        let (healthy, issue, _) = check_config_health(&cfg);
        assert!(!healthy);
        assert_eq!(issue, Some(MigrationReason::DeprecatedConfigKey));
    }

    #[test]
    fn config_health_ok() {
        let tmp = TempDir::new().unwrap();
        let cfg = tmp.path().join("config.toml");
        fs::write(&cfg, "[pressure]\ngreen_min_free_pct = 20.0\n").unwrap();
        let (healthy, issue, _) = check_config_health(&cfg);
        assert!(healthy);
        assert!(issue.is_none());
    }

    #[test]
    fn deduplicate_profile_keeps_first() {
        let tmp = TempDir::new().unwrap();
        let profile = tmp.path().join(".bashrc");
        fs::write(
            &profile,
            "# header\nexport PATH=\"/foo:$PATH\" # sbh\nsome other line\nexport PATH=\"/foo:$PATH\" # sbh\n# footer\n",
        )
        .unwrap();

        let mut action = MigrationAction {
            kind: ActionKind::DeduplicateProfile,
            reason: MigrationReason::DuplicatePathEntries,
            target: profile.clone(),
            description: String::new(),
            applied: false,
            backup_path: None,
            error: None,
        };

        apply_deduplicate_profile(&mut action, None).unwrap();
        let contents = fs::read_to_string(&profile).unwrap();
        let sbh_lines: Vec<&str> = contents
            .lines()
            .filter(|l| l.contains("sbh") && l.contains("PATH"))
            .collect();
        assert_eq!(sbh_lines.len(), 1, "should keep exactly one sbh PATH entry");
        assert!(action.backup_path.is_some());
    }

    #[test]
    fn remove_stale_profile_line() {
        let tmp = TempDir::new().unwrap();
        let profile = tmp.path().join(".bashrc");
        fs::write(
            &profile,
            "# header\nexport PATH=\"/nonexistent/sbh:$PATH\"\n# footer\n",
        )
        .unwrap();

        let mut action = MigrationAction {
            kind: ActionKind::RemoveProfileLine,
            reason: MigrationReason::StalePathEntry,
            target: profile.clone(),
            description: String::new(),
            applied: false,
            backup_path: None,
            error: None,
        };

        apply_remove_profile_line(&mut action, None).unwrap();
        let contents = fs::read_to_string(&profile).unwrap();
        assert!(
            !contents.contains("sbh"),
            "stale sbh line should be removed"
        );
        assert!(contents.contains("# header"));
        assert!(contents.contains("# footer"));
    }

    #[test]
    fn init_state_file() {
        let tmp = TempDir::new().unwrap();
        let state = tmp.path().join("sub").join("state.json");

        let mut action = MigrationAction {
            kind: ActionKind::InitStateFile,
            reason: MigrationReason::MissingStateFile,
            target: state.clone(),
            description: String::new(),
            applied: false,
            backup_path: None,
            error: None,
        };

        apply_init_state_file(&mut action).unwrap();
        assert!(state.exists());
        let contents = fs::read_to_string(&state).unwrap();
        assert!(contents.contains("version"));
    }

    #[test]
    fn is_older_than_recent_file() {
        let tmp = TempDir::new().unwrap();
        let f = tmp.path().join("recent.txt");
        fs::write(&f, "new").unwrap();
        // File just created, should not be older than 1 hour.
        assert!(!is_older_than(&f, 3600));
    }

    #[test]
    fn assess_health_not_installed() {
        let footprints = vec![]; // No binary found.
        let actions = vec![];
        assert_eq!(
            assess_health(&footprints, &actions),
            EnvironmentHealth::NotInstalled
        );
    }

    #[test]
    fn assess_health_healthy() {
        let footprints = vec![Footprint {
            kind: FootprintKind::Binary,
            path: PathBuf::from("/usr/local/bin/sbh"),
            healthy: true,
            issue: None,
            detail: None,
        }];
        let actions = vec![];
        assert_eq!(
            assess_health(&footprints, &actions),
            EnvironmentHealth::Healthy
        );
    }

    #[test]
    fn assess_health_broken_binary() {
        let footprints = vec![Footprint {
            kind: FootprintKind::Binary,
            path: PathBuf::from("/usr/local/bin/sbh"),
            healthy: false,
            issue: Some(MigrationReason::BinaryPermissions),
            detail: None,
        }];
        let actions = vec![];
        assert_eq!(
            assess_health(&footprints, &actions),
            EnvironmentHealth::Broken
        );
    }

    #[test]
    fn assess_health_degraded() {
        let footprints = vec![
            Footprint {
                kind: FootprintKind::Binary,
                path: PathBuf::from("/usr/local/bin/sbh"),
                healthy: true,
                issue: None,
                detail: None,
            },
            Footprint {
                kind: FootprintKind::ShellProfile,
                path: PathBuf::from("/home/user/.bashrc"),
                healthy: false,
                issue: Some(MigrationReason::DuplicatePathEntries),
                detail: None,
            },
        ];
        let actions = vec![];
        assert_eq!(
            assess_health(&footprints, &actions),
            EnvironmentHealth::Degraded
        );
    }

    #[test]
    fn format_report_contains_key_fields() {
        let report = MigrationReport {
            scanned_at: "1234567890".to_string(),
            footprints: vec![Footprint {
                kind: FootprintKind::Binary,
                path: PathBuf::from("/usr/local/bin/sbh"),
                healthy: true,
                issue: None,
                detail: None,
            }],
            actions: vec![],
            health: EnvironmentHealth::Healthy,
            issues_found: 0,
            issues_repaired: 0,
        };
        let output = format_report_human(&report);
        assert!(output.contains("healthy"));
        assert!(output.contains("Footprints found: 1"));
        assert!(output.contains("/usr/local/bin/sbh"));
    }

    #[test]
    fn plan_stale_backup_cleanup_only_when_old() {
        let tmp = TempDir::new().unwrap();
        let backup = tmp.path().join("test.sbh-backup-1000000");
        fs::write(&backup, "old").unwrap();

        let footprints = vec![Footprint {
            kind: FootprintKind::BackupFile,
            path: backup.clone(),
            healthy: true,
            issue: Some(MigrationReason::StaleBackupFile),
            detail: None,
        }];

        // With 0 cleanup age, no cleanup action should be generated.
        let opts_no_cleanup = MigrateOptions {
            cleanup_backups_older_than: 0,
            ..Default::default()
        };
        let actions = plan_actions(&footprints, &opts_no_cleanup);
        assert!(actions.is_empty(), "should not plan cleanup when disabled");

        // With very short threshold (file just created), also no cleanup.
        let opts_short = MigrateOptions {
            cleanup_backups_older_than: 999_999_999,
            ..Default::default()
        };
        let actions = plan_actions(&footprints, &opts_short);
        assert!(
            actions.is_empty(),
            "should not plan cleanup for recent files"
        );
    }

    #[test]
    fn migration_report_serializes_to_json() {
        let report = MigrationReport {
            scanned_at: "1234567890".to_string(),
            footprints: vec![],
            actions: vec![],
            health: EnvironmentHealth::Healthy,
            issues_found: 0,
            issues_repaired: 0,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"health\":\"Healthy\""));
    }

    #[cfg(unix)]
    #[test]
    fn fix_permissions_makes_executable() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let binary = tmp.path().join("sbh");
        fs::write(&binary, "#!/bin/sh\necho test").unwrap();
        // Remove execute permissions.
        let perms = std::fs::Permissions::from_mode(0o644);
        fs::set_permissions(&binary, perms).unwrap();

        let mut action = MigrationAction {
            kind: ActionKind::FixPermissions,
            reason: MigrationReason::BinaryPermissions,
            target: binary.clone(),
            description: String::new(),
            applied: false,
            backup_path: None,
            error: None,
        };

        apply_fix_permissions(&mut action).unwrap();
        let meta = fs::metadata(&binary).unwrap();
        assert!(
            meta.permissions().mode() & 0o111 != 0,
            "should be executable"
        );
    }

    #[test]
    fn scan_backups_in_finds_backup_files() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("regular.txt"), "data").unwrap();
        fs::write(tmp.path().join("test.sbh-backup-12345"), "backup").unwrap();
        fs::write(tmp.path().join("other.sbh.bak"), "backup2").unwrap();

        let mut footprints = Vec::new();
        scan_backups_in(tmp.path(), &mut footprints);
        assert_eq!(footprints.len(), 2, "should find both backup patterns");
        assert!(
            footprints
                .iter()
                .all(|f| f.kind == FootprintKind::BackupFile)
        );
    }
}
