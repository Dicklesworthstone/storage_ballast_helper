//! Top-level CLI definition and dispatch.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(unix)]
use std::process::{Command as ProcessCommand, Stdio};

use clap::{ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell as CompletionShell, generate};
use colored::control;
use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;

use storage_ballast_helper::ballast::manager::{
    BallastAvailability, BallastHealth, BallastManager,
};
use storage_ballast_helper::cli::RELEASE_REPOSITORY;
use storage_ballast_helper::cli::update::{UpdateReport, UpdateServiceRestart};
use storage_ballast_helper::core::config::{
    Config, PathsConfig, ScannerEngineMode, load_sacred_config, sacred_config_path_for,
    write_sacred_config,
};
use storage_ballast_helper::daemon::loop_main::{
    DaemonArgs as RuntimeDaemonArgs, MonitoringDaemon,
};
use storage_ballast_helper::daemon::mount_controller::{MountStateRecord, unprotected_pressure};
use storage_ballast_helper::daemon::process_io_history::ProcessIoHistory;
use storage_ballast_helper::daemon::self_monitor::{
    DAEMON_STATE_STALE_THRESHOLD_SECS, assess_logging_placement, detect_daemon_liveness,
};
use storage_ballast_helper::daemon::service::{
    LAUNCHD_LABEL_ENV, LaunchdConfig, LaunchdServiceManager, LaunchdStatusReport,
    ServiceActionResult, SystemdServiceManager, launchd_labels_for_discovery,
    launchd_system_plist_path_for_label, launchd_user_plist_path_for_label,
};
use storage_ballast_helper::logger::sqlite::SqliteLogger;
use storage_ballast_helper::logger::stats::{StatsEngine, window_label};
use storage_ballast_helper::monitor::burst::BurstStats;
use storage_ballast_helper::monitor::fs_stats::FsStatsCollector;
use storage_ballast_helper::monitor::pid::{PressureLevel, classify_level};
use storage_ballast_helper::platform::pal::{
    BlockDeviceInfo, MemoryInfo, Platform, ServiceManager, detect_platform,
};
use storage_ballast_helper::platform::types::{
    Capacity, FullDiskAccessState, FullDiskAccessStatus, MemoryPressure, MemoryPressureLevel,
    ProcessInfo, ProcessIo, ServiceKind,
};
#[cfg(unix)]
use storage_ballast_helper::scanner::active_lease::{
    self, ACTIVE_LEASE_TARGET_ENV, ACTIVE_LEASE_TOKEN_ENV, ActiveLease, LeasePolicy,
};
use storage_ballast_helper::scanner::deletion::{
    DeletionConfig, DeletionExecutor, DeletionMode, DeletionPlan,
};
use storage_ballast_helper::scanner::engine::{ScannerEngine, SelectedScannerEngine};
use storage_ballast_helper::scanner::patterns::{
    ArtifactCategory, ArtifactPatternRegistry, OpaqueTreeDisposition,
};
use storage_ballast_helper::scanner::planner::{BatchPlan, PlanRequest, plan_batch};
use storage_ballast_helper::scanner::protection::{self, ProtectionRegistry};
use storage_ballast_helper::scanner::quarantine::QuarantineStore;
use storage_ballast_helper::scanner::scoring::{
    ActiveReferenceSummary, CandidacyScore, CandidateInput, ScoringEngine,
};
use storage_ballast_helper::scanner::walker::{
    ActiveReferenceIndex, ActiveReferenceScanConfig, DirectoryWalker, FsIdentity, WalkerConfig,
    collect_active_reference_index_cached, collect_open_path_ancestors,
    collect_open_path_ancestors_cached, is_path_open_by_ancestor,
};

const LIVE_REFRESH_MIN_MS: u64 = 100;
const STATUS_WATCH_REFRESH_MS: u64 = 1_000;
const LOCAL_SNAPSHOT_THIN_AMOUNT_BYTES: u64 = 9_999_999_999_999_999;
const LOCAL_SNAPSHOT_THIN_URGENCY: u8 = 4;

/// Storage Ballast Helper — prevents disk-full scenarios from coding agent swarms.
#[derive(Debug, Parser)]
#[command(
    name = "sbh",
    author,
    version,
    about = "Storage Ballast Helper - Linux/macOS disk space guardian",
    after_long_help = "Platform behavior:\n  sbh auto-detects Linux/systemd and macOS/launchd when service flags are omitted.\n  macOS runs use launchd, APFS-aware ballast checks, Time Machine snapshot warnings,\n  and Full Disk Access diagnostics where relevant.\n\nExit codes (C-EXIT):\n  0  ok (including `clean`/`emergency` with nothing to reclaim)\n  1  user error, or a pressure condition (`check` below threshold or --need unmet)\n  2  runtime or I/O failure\n  3  internal error\n  4  partial success (some deletions or setup steps failed)\nHuman reports go to stdout, diagnostics and warnings to stderr; --json reports carry exit_code.",
    long_about = None,
    arg_required_else_help = true,
    max_term_width = 100
)]
#[allow(clippy::struct_excessive_bools)]
pub struct Cli {
    /// Override config file path.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Force JSON output mode.
    #[arg(long, global = true)]
    json: bool,
    /// Disable colored output.
    #[arg(long, global = true)]
    no_color: bool,
    /// Increase verbosity.
    #[arg(short, long, global = true, conflicts_with = "quiet")]
    verbose: bool,
    /// Quiet mode (errors only).
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    quiet: bool,
    /// Subcommand to execute.
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Subcommand)]
enum Command {
    /// Run the monitoring daemon.
    Daemon(DaemonArgs),
    /// Show or change the running daemon's policy mode over the control socket.
    Policy(PolicyArgs),
    /// Install sbh as a system service.
    Install(InstallArgs),
    /// Remove sbh system integration.
    Uninstall(UninstallArgs),
    /// Show current health and pressure status.
    Status(StatusArgs),
    /// Inspect and control the installed service.
    Service(ServiceArgs),
    /// Show aggregated historical statistics.
    Stats(StatsArgs),
    /// Run a manual scan for reclaim candidates.
    Scan(ScanArgs),
    /// Run a manual cleanup pass.
    Clean(CleanArgs),
    /// Restore quarantined entries to their original paths.
    Undo(UndoArgs),
    /// Manage ballast pools and files.
    Ballast(BallastArgs),
    /// View and update configuration state.
    Config(ConfigArgs),
    /// Show version and optional build metadata.
    Version(VersionArgs),
    /// Emergency zero-write recovery mode.
    Emergency(EmergencyArgs),
    /// Protect a path subtree from sbh cleanup.
    Protect(ProtectArgs),
    /// Remove protection marker from a path.
    Unprotect(UnprotectArgs),
    /// Run and renew bounded, process-scoped active-target leases.
    Lease(LeaseArgs),
    /// Internal watchdog for a process-scoped active-target lease.
    #[command(name = "__lease-watch", hide = true)]
    LeaseWatch(LeaseWatchArgs),
    /// Show/apply tuning recommendations.
    Tune(TuneArgs),
    /// Pre-build disk pressure check.
    Check(CheckArgs),
    /// Attribute disk pressure by process/agent.
    Blame(BlameArgs),
    /// Explain recorded cleanup decisions from the evidence ledger.
    Explain(ExplainArgs),
    /// Live TUI-style dashboard.
    Dashboard(DashboardArgs),
    /// Generated documentation: the document as JSON, or render/check the
    /// marked regions of a file (README tables come from here).
    Docs(DocsArgs),
    /// Run diagnostics.
    Doctor(DoctorArgs),
    /// Print the daemon's Prometheus textfile export (`metrics.prom`).
    Metrics,
    /// Generate shell completions.
    Completions(CompletionsArgs),
    /// Check for and apply updates.
    Update(UpdateArgs),

    /// Post-install setup: PATH, completions, and verification.
    Setup(SetupArgs),
    /// Scan the install footprint and repair stale PATH lines, unit paths,
    /// permissions, legacy paths, and missing state (backups first).
    Bootstrap(BootstrapArgs),
    /// View activity log entries.
    Log(LogArgs),
    /// Truncate active append-only logs in place (e.g. agent codex-tui.log).
    TruncateLogs(TruncateLogsArgs),
}

#[derive(Debug, Clone, Args, Serialize, Default)]
struct BootstrapArgs {
    /// Report what would be repaired without changing anything.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Clone, Args, Serialize, Default)]
struct TruncateLogsArgs {
    /// Print what would be truncated without writing.
    #[arg(long)]
    dry_run: bool,
    /// Override the configured `min_size_bytes` threshold for this run.
    #[arg(long, value_name = "BYTES")]
    min_size: Option<u64>,
    /// Bypass the configured age gate (treat as under-pressure).
    #[arg(long)]
    force: bool,
    /// Run even if `[scanner.log_truncation].enabled = false` in config.
    #[arg(long)]
    enable_anyway: bool,
}

#[derive(Debug, Clone, Args, Serialize, Default)]
struct DaemonArgs {
    /// Run detached from terminal.
    #[arg(long)]
    background: bool,
    /// Optional pidfile path for non-service usage.
    #[arg(long, value_name = "PATH")]
    pidfile: Option<PathBuf>,
    /// Systemd watchdog timeout in seconds (0 disables).
    #[arg(long, default_value_t = 0, value_name = "SECONDS")]
    watchdog_sec: u64,
    /// Talk to the running daemon over its control socket instead of
    /// starting one.
    #[command(subcommand)]
    action: Option<DaemonAction>,
}

/// Requests for a running daemon (`control.sock` beside `state.json`).
#[derive(Debug, Clone, Subcommand, Serialize)]
enum DaemonAction {
    /// Liveness: pid, start time, version, uptime, policy mode.
    Ping,
    /// Queue a forced scan of the configured roots on the next tick.
    #[command(name = "scan-now")]
    ScanNow,
    /// Re-read the config file (the SIGHUP path).
    Reload,
    /// Ask the daemon to stop cleanly.
    Shutdown,
}

/// `sbh policy`: the policy engine's mode, live from the daemon.
#[derive(Debug, Clone, Args, Serialize)]
struct PolicyArgs {
    #[command(subcommand)]
    action: PolicyCliAction,
}

#[derive(Debug, Clone, Copy, Subcommand, Serialize)]
enum PolicyCliAction {
    /// Show the active mode (observe, canary, enforce).
    Status,
    /// observe -> canary, canary -> enforce; persisted to `[policy] initial_mode`.
    Promote,
    /// enforce -> canary, canary -> observe; persisted to `[policy] initial_mode`.
    Demote,
}

#[derive(Debug, Clone, Args, Serialize, Default)]
#[command(
    after_long_help = "Platform notes:\n  Omit --systemd/--launchd for auto-detection.\n  On macOS, --auto selects launchd user scope and native Application Support paths.\n  Use sbh doctor --pal after install to verify launchd, APFS, and Full Disk Access state."
)]
#[allow(clippy::struct_excessive_bools)]
struct InstallArgs {
    /// Install systemd service units (Linux).
    #[arg(long, conflicts_with = "launchd")]
    systemd: bool,
    /// Install launchd service plist (macOS).
    #[arg(long, conflicts_with = "systemd")]
    launchd: bool,
    /// Install in user service scope (same as --scope user).
    #[arg(long, conflicts_with = "scope")]
    user: bool,
    /// Service scope for systemd or launchd installation.
    #[arg(long, value_enum, value_name = "SCOPE", conflicts_with = "user")]
    scope: Option<InstallScopeArg>,
    /// Build and install from source (requires cargo + git).
    #[arg(long)]
    from_source: bool,
    /// Git tag or version to build when using --from-source. Defaults to HEAD.
    #[arg(long, requires = "from_source", value_name = "TAG")]
    tag: Option<String>,
    /// Installation prefix for the binary (--from-source). Defaults to ~/.local.
    #[arg(long, requires = "from_source", value_name = "PATH")]
    prefix: Option<PathBuf>,
    /// Run guided first-run setup wizard.
    #[arg(long)]
    wizard: bool,
    /// Non-interactive mode: apply smart defaults without prompts.
    #[arg(long, conflicts_with = "wizard")]
    auto: bool,
    /// Number of ballast files to create.
    #[arg(long, default_value_t = 10, value_name = "N")]
    ballast_count: usize,
    /// Size of each ballast file in MB.
    #[arg(long, default_value_t = 1024, value_name = "MB")]
    ballast_size: u64,
    /// Directory for ballast files.
    #[arg(long, value_name = "PATH")]
    ballast_path: Option<PathBuf>,
    /// Use offline bundle manifest for airgapped preflight checks.
    #[arg(long, value_name = "PATH")]
    offline: Option<PathBuf>,
    /// Skip release binary artifact verification (unsafe; for debugging only).
    #[arg(long)]
    no_verify: bool,
    /// Show what would be done without executing.
    #[arg(long)]
    dry_run: bool,
    /// Skip the install-time bootstrap repairs (stale PATH lines, unit paths,
    /// permissions, missing state).
    #[arg(long)]
    no_bootstrap: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
enum InstallScopeArg {
    User,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResolvedInstallService {
    kind: ServiceKind,
    user_scope: bool,
}

impl ResolvedInstallService {
    const fn scope_name(self) -> &'static str {
        if self.user_scope { "user" } else { "system" }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResolvedServiceControl {
    kind: ServiceKind,
    user_scope: bool,
}

impl ResolvedServiceControl {
    const fn scope_name(self) -> &'static str {
        if self.user_scope { "user" } else { "system" }
    }
}

#[derive(Debug, Clone, Args, Serialize, Default)]
#[command(
    after_long_help = "Platform notes:\n  Omit --systemd/--launchd for auto-detection.\n  On macOS, launchd plist discovery checks both user and system scopes before removal."
)]
#[allow(clippy::struct_excessive_bools)]
struct UninstallArgs {
    /// Remove systemd service units (Linux).
    #[arg(long, conflicts_with = "launchd")]
    systemd: bool,
    /// Remove launchd service plist (macOS).
    #[arg(long, conflicts_with = "systemd")]
    launchd: bool,
    /// Remove from user service scope (same as --scope user).
    #[arg(long, conflicts_with = "scope")]
    user: bool,
    /// Service scope for systemd or launchd removal.
    #[arg(long, value_enum, value_name = "SCOPE", conflicts_with = "user")]
    scope: Option<InstallScopeArg>,
    /// Remove everything: binary, service, config, data/logs, cached assets,
    /// ballast pool (config and database are backed up first).
    #[arg(long)]
    purge: bool,
    /// Remove everything except the config file.
    #[arg(long, conflicts_with_all = ["purge", "keep_data", "keep_assets"])]
    keep_config: bool,
    /// Remove everything except state, logs, and the activity database.
    #[arg(long, conflicts_with_all = ["purge", "keep_config", "keep_assets"])]
    keep_data: bool,
    /// Remove everything except the cached release assets.
    #[arg(long, conflicts_with_all = ["purge", "keep_config", "keep_data"])]
    keep_assets: bool,
    /// Print the removal plan without unloading the service or deleting anything.
    #[arg(long)]
    dry_run: bool,
    /// Directory for backups of files removed backup-first (default: next to each file).
    #[arg(long, value_name = "DIR")]
    backup_dir: Option<PathBuf>,
    /// Confirm a data-removing mode (--purge, --keep-*) without a prompt.
    #[arg(long, short = 'y')]
    yes: bool,
}

impl UninstallArgs {
    /// Cleanup mode selected by the flags; none of them means the
    /// conservative default (binary + service only).
    fn cleanup_mode(&self) -> storage_ballast_helper::cli::uninstall::CleanupMode {
        use storage_ballast_helper::cli::uninstall::CleanupMode;
        if self.purge {
            CleanupMode::Purge
        } else if self.keep_config {
            CleanupMode::KeepConfig
        } else if self.keep_data {
            CleanupMode::KeepData
        } else if self.keep_assets {
            CleanupMode::KeepAssets
        } else {
            CleanupMode::Conservative
        }
    }
}

#[derive(Debug, Clone, Args, Serialize, Default)]
struct StatusArgs {
    /// Continuously refresh status output.
    #[arg(long)]
    watch: bool,
    /// Show protected paths, sacred catalog entries, and current sacred overlap counts.
    #[arg(long)]
    sacred: bool,
}

#[derive(Debug, Clone, Args, Serialize)]
#[command(
    after_long_help = "Platform notes:\n  Omit --systemd/--launchd for auto-detection.\n  On macOS, service status uses launchctl and reports the launchd target plus plist path."
)]
#[allow(clippy::struct_excessive_bools)]
struct ServiceArgs {
    /// Use systemd service controls.
    #[arg(long, conflicts_with = "launchd")]
    systemd: bool,
    /// Use launchd service controls.
    #[arg(long, conflicts_with = "systemd")]
    launchd: bool,
    /// Use user service scope (same as --scope user).
    #[arg(long, conflicts_with = "scope")]
    user: bool,
    /// Service scope to inspect/control.
    #[arg(long, value_enum, value_name = "SCOPE", conflicts_with = "user")]
    scope: Option<InstallScopeArg>,
    /// Service operation to run.
    #[command(subcommand)]
    command: ServiceCommand,
}

#[derive(Debug, Clone, Subcommand, Serialize)]
enum ServiceCommand {
    /// Show loaded/running state and service metadata.
    Status,
    /// Restart the service.
    Restart,
    /// Print recent service log lines.
    Logs(ServiceLogsArgs),
    /// Replace the installed systemd unit with the one sbh generates
    /// (timestamped backup beside it; drop-ins are kept unless purged).
    ReinstallUnit(ReinstallUnitArgs),
}

#[derive(Debug, Clone, Args, Serialize, Default)]
struct ReinstallUnitArgs {
    /// Move every drop-in (`sbh.service.d/*.conf`, `system.control`) aside
    /// into the backup directory instead of leaving it in effect.
    #[arg(long)]
    purge_dropins: bool,
}

#[derive(Debug, Clone, Args, Serialize)]
struct ServiceLogsArgs {
    /// Number of recent log lines to print.
    #[arg(long, short = 'n', default_value_t = 80, value_name = "N")]
    tail: usize,
}

#[derive(Debug, Clone, Args, Serialize, Default)]
#[command(
    group = clap::ArgGroup::new("selector").required(true).multiple(false),
    after_long_help = "Levels:\n  0  one-line verdict\n  1  weighted factor table\n  2  posterior, expected loss, calibration, guards (default)\n  3  full serialized trace\n\nSources: the daemon's SQLite decision_log (read-only), falling back to `decision` lines in the JSONL activity log.\nIds are stable per artifact version (path + inode + size) and appear in `scan --json`, `clean --json`, and artifact_delete events."
)]
struct ExplainArgs {
    /// Decision id (12 hex chars) as printed by scan/clean and activity events.
    #[arg(long, value_name = "ID", group = "selector")]
    id: Option<String>,
    /// Show the N most recent decisions.
    #[arg(long, value_name = "N", group = "selector")]
    last: Option<usize>,
    /// Decisions recorded for exactly this path, newest first.
    #[arg(long, value_name = "PATH", group = "selector")]
    path: Option<PathBuf>,
    /// Decisions newer than a window (e.g. 30m, 2h, 1d), newest first.
    #[arg(long, value_name = "WINDOW", group = "selector")]
    since: Option<String>,
    /// Score this path now, run the deletion preflight, and say what keeps
    /// it from being reclaimed (protection, veto, preflight, or score gap).
    #[arg(long, value_name = "PATH", group = "selector")]
    why_not: Option<PathBuf>,
    /// Re-score a recorded decision's inputs with the current code and
    /// config and report factor/posterior/action drift.
    #[arg(long, value_name = "ID", group = "selector")]
    replay: Option<String>,
    /// With --why-not: the smallest single change (age, size, or pressure)
    /// that would flip the outcome to Delete.
    #[arg(long, requires = "why_not")]
    counterfactual: bool,
    /// Detail level 0-3.
    #[arg(long, default_value_t = 2, value_name = "LEVEL")]
    level: u8,
    /// Maximum records for --path and --since.
    #[arg(long, default_value_t = 20, value_name = "N")]
    limit: usize,
}

#[derive(Debug, Clone, Args, Serialize, Default)]
#[command(
    after_long_help = "Platform notes:\n  Use --pal for platform diagnostics.\n  Use --system for host tuning checks (kernel writeback / dirty-page limits on Linux).\n  Use --env for a read-only install-footprint scan (PATH lines, unit paths, permissions, state).\n  Use --release for macOS release signing/notarization/Homebrew readiness.\n  On macOS --pal includes launchd, APFS, codesign/notarization, and Full Disk Access checks."
)]
#[allow(clippy::struct_excessive_bools)]
struct DoctorArgs {
    /// Probe the Platform Abstraction Layer implementation.
    #[arg(long)]
    pal: bool,
    /// Probe macOS release signing, notarization, and Homebrew CI readiness.
    #[arg(long)]
    release: bool,
    /// Check host-level tuning (kernel writeback / dirty-page limits).
    #[arg(long)]
    system: bool,
    /// Check the install footprint (PATH entries, unit files, permissions,
    /// legacy paths, state) without changing anything.
    #[arg(long)]
    env: bool,
    /// Compare the installed service unit (systemd) or plist (launchd)
    /// with what sbh generates: hardening directives, process type,
    /// foreign drop-ins, and condition gates that keep it from starting.
    #[arg(long)]
    service: bool,
    /// With --service: check the user-scope unit instead of the system one.
    #[arg(long, requires = "service")]
    user: bool,
}

#[derive(Debug, Clone, Args, Serialize, Default)]
struct StatsArgs {
    /// Time window (for example: `15m`, `24h`, `7d`). Omit for all standard windows.
    #[arg(long, value_name = "WINDOW")]
    window: Option<String>,
    /// Show top N most-deleted artifact patterns.
    #[arg(long, default_value_t = 0, value_name = "N")]
    top_patterns: usize,
    /// Show top N largest individual deletions.
    #[arg(long, default_value_t = 0, value_name = "N")]
    top_deletions: usize,
    /// Show pressure level timeline.
    #[arg(long)]
    pressure_history: bool,
}

#[derive(Debug, Clone, Args, Serialize, Default)]
struct ScanArgs {
    /// Paths to scan (falls back to configured watched paths when omitted).
    #[arg(value_name = "PATH")]
    paths: Vec<PathBuf>,
    /// Maximum number of candidates to display.
    #[arg(long, default_value_t = 20, value_name = "N")]
    top: usize,
    /// Minimum score to include in output.
    #[arg(long, default_value_t = 0.7, value_name = "SCORE")]
    min_score: f64,
    /// Include protected paths in output report.
    #[arg(long)]
    show_protected: bool,
    /// Include per-candidate confidence and safety-check traces.
    #[arg(long)]
    explain: bool,
    /// Preview the catalog roots the daemon would scan on MOUNT (default /)
    /// when that device is under pressure and has no configured root_path:
    /// known-safe caches (~/.cache/pip, cargo registry caches, npm _cacache,
    /// Trash, /var/tmp/*, ...) with their size and idle time. No scoring.
    #[arg(long, value_name = "MOUNT", num_args = 0..=1, default_missing_value = "/")]
    catalog: Option<PathBuf>,
}

#[derive(Debug, Clone, Args, Serialize)]
#[command(
    after_long_help = "Platform notes:\n  On macOS, --thin-local-snapshots asks Time Machine/APFS to reclaim local snapshot space.\n  It does not delete user paths and may require sudo/root."
)]
#[allow(clippy::struct_excessive_bools)]
struct CleanArgs {
    /// Paths to clean (falls back to configured watched paths when omitted).
    #[arg(value_name = "PATH")]
    paths: Vec<PathBuf>,
    /// Thin macOS Time Machine local snapshots instead of deleting file candidates.
    #[arg(long)]
    thin_local_snapshots: bool,
    /// Mount to pass to tmutil when thinning local snapshots.
    #[arg(long, value_name = "MOUNT")]
    local_snapshot_mount: Option<PathBuf>,
    /// Target free percentage to recover.
    #[arg(long, value_name = "PERCENT")]
    target_free: Option<f64>,
    /// Minimum score to include in deletion candidates.
    #[arg(long, default_value_t = 0.7, value_name = "SCORE")]
    min_score: f64,
    /// Maximum number of items to delete.
    #[arg(long, value_name = "N")]
    max_items: Option<usize>,
    /// Print candidates and planned actions without deleting.
    #[arg(long)]
    dry_run: bool,
    /// Skip interactive confirmation prompt.
    #[arg(long)]
    yes: bool,
    /// Remove candidates for good instead of moving them into
    /// `<root>/.sbh/quarantine` (Layer 7; restorable with `sbh undo`).
    #[arg(long)]
    no_quarantine: bool,
}

impl Default for CleanArgs {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            thin_local_snapshots: false,
            local_snapshot_mount: None,
            target_free: None,
            min_score: 0.7,
            max_items: None,
            dry_run: false,
            yes: false,
            no_quarantine: false,
        }
    }
}

/// `sbh undo`: restore quarantined entries (Layer 7).
#[derive(Debug, Clone, Args, Serialize, Default)]
#[command(
    after_long_help = "Quarantine:\n  At Green, and for `sbh clean`, candidates are moved into \
`<root>/.sbh/quarantine/<decision-id>/` instead of removed; the decision id is printed on the \
`[SBH-QUARANTINE]` line and by `sbh explain`. Entries expire after scanner.quarantine_ttl_hours and \
are drained oldest-first when the mount reaches Orange."
)]
struct UndoArgs {
    /// Decision id of the entry to restore.
    #[arg(value_name = "DECISION_ID", conflicts_with_all = ["path", "all_since", "list"])]
    id: Option<String>,
    /// Restore the entry whose original path is PATH.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["all_since", "list"])]
    path: Option<PathBuf>,
    /// Restore every entry quarantined within WINDOW (e.g. 30m, 2h, 1d).
    #[arg(long, value_name = "WINDOW", conflicts_with = "list")]
    all_since: Option<String>,
    /// List held entries and stop.
    #[arg(long)]
    list: bool,
    /// When the original path exists again, restore beside it as
    /// `<name>.restored-<decision-id>` instead of refusing.
    #[arg(long)]
    force_suffix: bool,
    /// Scan roots whose quarantine to search (default: scanner.root_paths).
    #[arg(long = "root", value_name = "PATH")]
    roots: Vec<PathBuf>,
}

#[derive(Debug, Clone, Args, Serialize, Default)]
#[command(
    after_long_help = "Platform notes:\n  On macOS, ballast provisioning uses APFS-aware preallocation and verifies allocated blocks.\n  Ballast release warns when Time Machine local snapshots may retain released bytes."
)]
struct BallastArgs {
    /// Ballast operation to run.
    #[command(subcommand)]
    command: Option<BallastCommand>,
}

#[derive(Debug, Clone, Subcommand, Serialize)]
enum BallastCommand {
    /// Show ballast inventory and reclaimable totals.
    Status,
    /// Create/rebuild ballast files.
    Provision,
    /// Release N ballast files.
    Release(ReleaseBallastArgs),
    /// Replenish previously released ballast.
    Replenish,
    /// Verify ballast integrity.
    Verify,
}

#[derive(Debug, Clone, Args, Serialize)]
struct ReleaseBallastArgs {
    /// Number of ballast files to release.
    #[arg(value_name = "COUNT")]
    count: usize,
}

#[derive(Debug, Clone, Args, Serialize, Default)]
struct ConfigArgs {
    /// Config operation to run.
    #[command(subcommand)]
    command: Option<ConfigCommand>,
}

#[derive(Debug, Clone, Subcommand, Serialize)]
enum ConfigCommand {
    /// Print resolved config file path.
    Path,
    /// Print effective merged configuration.
    Show,
    /// Validate configuration and exit.
    Validate(ConfigValidateArgs),
    /// Show effective-vs-default config diff.
    Diff,
    /// Reset to generated defaults.
    Reset,
    /// Set a specific config key.
    Set(ConfigSetArgs),
}

#[derive(Debug, Clone, Args, Serialize)]
struct ConfigSetArgs {
    /// Dot-path config key to set.
    key: String,
    /// New value to apply.
    value: String,
}

#[derive(Debug, Clone, Args, Serialize, Default)]
struct ConfigValidateArgs {
    /// Fail when the file contains keys no section declares
    /// (also implied by `[core] strict_config = true`).
    #[arg(long)]
    strict: bool,
}

#[derive(Debug, Clone, Args, Serialize, Default)]
struct VersionArgs {
    /// Include additional build metadata fields.
    #[arg(long)]
    verbose: bool,
}

#[derive(Debug, Clone, Args, Serialize)]
struct EmergencyArgs {
    /// Paths to target for emergency recovery.
    #[arg(value_name = "PATH")]
    paths: Vec<PathBuf>,
    /// Target free percentage to recover immediately.
    #[arg(long, default_value_t = 10.0, value_name = "PERCENT")]
    target_free: f64,
    /// Skip confirmation prompt.
    #[arg(long)]
    yes: bool,
    /// Leave artifacts modified within this many minutes alone (0 reclaims
    /// fresh builds too). Emergency mode reads no config, so this is the
    /// only age floor it has.
    #[arg(long, default_value_t = 5, value_name = "MINUTES")]
    min_age: u64,
}

impl Default for EmergencyArgs {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            target_free: 10.0,
            yes: false,
            min_age: 5,
        }
    }
}

#[derive(Debug, Clone, Args, Serialize)]
#[command(group(
    ArgGroup::new("protect_target")
        .required(true)
        .args(["path", "list"])
))]
struct ProtectArgs {
    /// Path to protect (creates `.sbh-protect` marker).
    #[arg(value_name = "PATH", conflicts_with = "list")]
    path: Option<PathBuf>,
    /// List all protections from marker files + config.
    #[arg(long, conflicts_with = "path")]
    list: bool,
}

#[derive(Debug, Clone, Args, Serialize)]
struct UnprotectArgs {
    /// Path to unprotect (removes `.sbh-protect` marker).
    #[arg(value_name = "PATH")]
    path: PathBuf,
}

#[derive(Debug, Clone, Args)]
struct LeaseArgs {
    #[command(subcommand)]
    action: LeaseAction,
}

#[derive(Debug, Clone, Subcommand)]
enum LeaseAction {
    /// Create a fresh target and replace sbh with the leased command.
    Run(LeaseRunArgs),
    /// Extend the soft deadline of the current inherited lease.
    Renew(LeaseRenewArgs),
    /// Inspect whether a target or descendant is protected by a live lease.
    Status(LeaseStatusArgs),
}

#[derive(Debug, Clone, Args)]
struct LeaseRunArgs {
    /// Fresh absent target directory, immediately beneath a configured scan root.
    #[arg(long, value_name = "PATH")]
    target: PathBuf,
    /// Maximum allocated target bytes (for example 32G).
    #[arg(long, value_name = "SIZE", value_parser = parse_byte_count)]
    max_bytes: u64,
    /// Renewable soft lifetime (for example 45m or 2h; hard cap is 8h).
    #[arg(long = "ttl", default_value = "2h", value_name = "DURATION", value_parser = parse_lease_duration_seconds)]
    ttl_seconds: u64,
    /// Command and arguments. `CARGO_TARGET_DIR` and renewal variables are injected.
    #[arg(last = true, required = true, num_args = 1..)]
    command: Vec<String>,
}

#[derive(Debug, Clone, Args)]
struct LeaseRenewArgs {
    /// Leased target. Defaults to `SBH_ACTIVE_LEASE_TARGET` inherited from `lease run`.
    #[arg(long, value_name = "PATH")]
    target: Option<PathBuf>,
    /// Amount to extend the current soft deadline (bounded by the original hard deadline).
    #[arg(long = "extend", default_value = "1h", value_name = "DURATION", value_parser = parse_lease_duration_seconds)]
    extend_seconds: u64,
}

#[derive(Debug, Clone, Args)]
struct LeaseStatusArgs {
    /// Target or descendant to inspect. Defaults to the inherited lease target.
    #[arg(long, value_name = "PATH")]
    target: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
struct LeaseWatchArgs {
    /// Exact target watched by the internal cancellation process.
    #[arg(long, value_name = "PATH")]
    target: PathBuf,
    /// Exact process group created by `lease run`.
    #[arg(long, value_name = "PGID")]
    process_group_id: i32,
}

#[derive(Debug, Clone, Args, Serialize, Default)]
#[allow(clippy::struct_excessive_bools)]
struct TuneArgs {
    /// Apply recommended tuning changes.
    #[arg(long)]
    apply: bool,
    /// Skip interactive confirmation when applying.
    #[arg(long, requires = "apply")]
    yes: bool,
    /// Revert kernel writeback tuning: restore the most recent backup of the
    /// sbh sysctl.d snippet (or remove it) and reload. Requires root.
    #[arg(long, conflicts_with = "apply")]
    revert_writeback: bool,
    /// Skip the on-volume bandwidth micro-benchmark when applying kernel
    /// writeback tuning; use the device-class heuristic instead.
    #[arg(long)]
    no_benchmark: bool,
}

#[derive(Debug, Clone, Args, Serialize, Default)]
struct CheckArgs {
    /// Path to evaluate (defaults to cwd).
    #[arg(value_name = "PATH")]
    path: Option<PathBuf>,
    /// Desired minimum free percentage.
    #[arg(long, value_name = "PERCENT")]
    target_free: Option<f64>,
    /// Minimum required free space. Accepts bytes or K/M/G/T suffixes, e.g. 5G.
    #[arg(long, value_name = "SIZE", value_parser = parse_byte_count)]
    need: Option<u64>,
    /// Predict if space will last for this many minutes (requires running daemon).
    #[arg(long, value_name = "MINUTES")]
    predict: Option<u64>,
    /// Do not fail when the target mount is at Orange or worse and the
    /// daemon has nothing to reclaim there (exit 0 with a warning instead of
    /// exit 1 `unprotected_pressure`).
    #[arg(long)]
    allow_unprotected: bool,
}

#[derive(Debug, Clone, Args, Serialize)]
struct BlameArgs {
    /// Maximum rows to return.
    #[arg(long, default_value_t = 25, value_name = "N")]
    top: usize,
    /// Attribution window (for example: `1m`, `15m`, `1h`).
    #[arg(long, default_value = "15m", value_name = "DURATION")]
    since: String,
    /// Render parent-child process tree in human output.
    #[arg(long)]
    tree: bool,
}

impl Default for BlameArgs {
    fn default() -> Self {
        Self {
            top: 25,
            since: "15m".to_string(),
            tree: false,
        }
    }
}

#[derive(Debug, Clone, Args, Serialize)]
struct DocsArgs {
    /// Print one section's Markdown instead of the JSON document
    /// (env-vars, commands, dashboard-screens, dashboard-keymap,
    /// dashboard-palette, dashboard-playbook).
    #[arg(long, value_name = "SECTION", conflicts_with_all = ["render", "check"])]
    section: Option<String>,

    /// Rewrite the `<!-- sbh-docs:begin <section> -->` … `<!-- sbh-docs:end -->`
    /// regions of these files in place.
    #[arg(long, value_name = "FILE", num_args = 1.., conflicts_with = "check")]
    render: Vec<PathBuf>,

    /// Report the regions of these files that differ from the code; exit 1
    /// on drift (the CI docs-drift check).
    #[arg(long, value_name = "FILE", num_args = 1..)]
    check: Vec<PathBuf>,
}

#[derive(Debug, Clone, Args, Serialize)]
struct DashboardArgs {
    /// Refresh interval for live view.
    #[arg(long, default_value_t = 1_000, value_name = "MILLISECONDS")]
    refresh_ms: u64,

    /// Route through the new canonical dashboard runtime (canary path).
    #[arg(long, conflicts_with = "legacy_dashboard")]
    new_dashboard: bool,

    /// Force legacy dashboard behavior during migration or incident fallback.
    #[arg(long, conflicts_with = "new_dashboard")]
    legacy_dashboard: bool,

    /// Open the cockpit on this screen for the session (overview, timeline,
    /// explainability, candidates, ballast, log_search, diagnostics, remember).
    #[arg(long, value_name = "SCREEN")]
    start_screen: Option<String>,

    /// Replay a captured activity log (JSONL) instead of the live daemon:
    /// the cockpit shows the log's events and a reconstructed state as time
    /// runs; Space pauses, `,`/`.` step, Home/End seek; actions are disabled.
    #[arg(
        long,
        value_name = "ACTIVITY_JSONL",
        conflicts_with = "legacy_dashboard"
    )]
    replay: Option<PathBuf>,

    /// With --replay: start at the first event at or after this RFC 3339
    /// timestamp.
    #[arg(long, value_name = "TIMESTAMP", requires = "replay")]
    from: Option<String>,

    /// With --replay: how fast log time runs (1x, 10x, or max = all at once).
    #[arg(long, value_name = "SPEED", default_value = "1x", requires = "replay")]
    speed: String,
}

impl Default for DashboardArgs {
    fn default() -> Self {
        Self {
            refresh_ms: 1_000,
            start_screen: None,
            replay: None,
            from: None,
            speed: "1x".to_string(),
            new_dashboard: false,
            legacy_dashboard: false,
        }
    }
}

#[derive(Debug, Clone, Args)]
struct CompletionsArgs {
    /// Shell to generate completion script for.
    #[arg(value_enum)]
    shell: CompletionShell,
}

#[derive(Debug, Clone, Args, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct UpdateArgs {
    /// Check only, don't apply updates.
    #[arg(long)]
    check: bool,
    /// Pin to a specific version tag (e.g. "0.2.1" or "v0.2.1").
    #[arg(long, value_name = "VERSION")]
    version: Option<String>,
    /// Force re-download even if already at the target version.
    #[arg(long)]
    force: bool,
    /// Install to system-wide location (requires root/sudo).
    #[arg(long, conflicts_with = "user")]
    system: bool,
    /// Install to user-local location (~/.local/bin). Default on non-root.
    #[arg(long, conflicts_with = "system")]
    user: bool,
    /// Skip integrity verification (unsafe; for debugging only).
    #[arg(long)]
    no_verify: bool,
    /// Print what would be done without making changes.
    #[arg(long)]
    dry_run: bool,
    /// Bypass local metadata cache and fetch fresh update metadata.
    #[arg(long)]
    refresh_cache: bool,
    /// Use offline bundle manifest for airgapped updates.
    #[arg(long, value_name = "PATH")]
    offline: Option<PathBuf>,
    /// Roll back to the most recent backup (or a specific backup by ID).
    #[allow(clippy::option_option)]
    #[arg(long, value_name = "BACKUP_ID")]
    rollback: Option<Option<String>>,
    /// List available backup snapshots.
    #[arg(long)]
    list_backups: bool,
    /// Prune old backups, keeping only the N most recent.
    #[arg(long, value_name = "N")]
    prune: Option<usize>,
    /// Maximum number of backups to retain (default: 5).
    #[arg(long, default_value_t = 5, value_name = "N")]
    max_backups: usize,
}

impl Default for UpdateArgs {
    fn default() -> Self {
        Self {
            check: false,
            version: None,
            force: false,
            system: false,
            user: false,
            no_verify: false,
            dry_run: false,
            refresh_cache: false,
            offline: None,
            rollback: None,
            list_backups: false,
            prune: None,
            max_backups: 5,
        }
    }
}

#[derive(Debug, Clone, Args)]
#[allow(clippy::struct_excessive_bools)]
struct SetupArgs {
    /// Add sbh to shell PATH (appends to profile if not already present).
    #[arg(long)]
    path: bool,
    /// Install shell completion scripts for the given shell(s).
    #[arg(long, value_enum, value_delimiter = ',')]
    completions: Vec<CompletionShell>,
    /// Run post-install verification (sbh --version check).
    #[arg(long)]
    verify: bool,
    /// Run all setup steps (PATH + completions + verify).
    #[arg(long)]
    all: bool,
    /// Shell profile to modify for PATH setup (auto-detected if omitted).
    #[arg(long, value_name = "PATH")]
    profile: Option<PathBuf>,
    /// Directory containing the sbh binary (auto-detected if omitted).
    #[arg(long, value_name = "DIR")]
    bin_dir: Option<PathBuf>,
    /// Print what would be done without making changes.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Clone, Args, Serialize, Default)]
struct LogArgs {
    /// Number of recent log entries to display (default 50).
    #[arg(long, short = 'n', default_value_t = 50, value_name = "N")]
    tail: usize,
    /// Follow the log file for new entries (like `tail -f`).
    #[arg(long, short = 'f')]
    follow: bool,
    /// Filter by event type (deletion, scan, pressure, error).
    #[arg(long, value_name = "TYPE")]
    r#type: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputMode {
    Human,
    Json,
}

/// CLI error type with explicit exit-code mapping.
#[derive(Debug, Error)]
pub enum CliError {
    /// Invalid user input at runtime.
    #[error("{0}")]
    User(String),
    /// Environment/runtime failure.
    #[error("{0}")]
    Runtime(String),
    /// Internal bug or invariant violation.
    #[error("{0}")]
    #[allow(dead_code)] // scaffolding for invariant-violation error paths
    Internal(String),
    /// Operation partially succeeded.
    #[error("{0}")]
    Partial(String),
    /// JSON serialization failed.
    #[error("failed to serialize output: {0}")]
    Json(#[from] serde_json::Error),
    /// Output write failed.
    #[error("failed to write output: {0}")]
    Io(#[from] io::Error),
}

impl CliError {
    /// Process exit code contract for the CLI.
    /// The exit-code contract (C-EXIT), the single mapping every command
    /// goes through:
    ///
    /// | code | meaning | examples |
    /// |------|---------|----------|
    /// | 0 | ok | `clean`/`emergency` with nothing to reclaim, `check` above threshold |
    /// | 1 | user error or pressure condition | bad arguments, `check` below threshold or `--need` unmet, predicted full |
    /// | 2 | runtime or I/O failure | cannot stat a path, config unreadable |
    /// | 3 | internal error | invariant violation, JSON encoding failure |
    /// | 4 | partial success | `clean`/`emergency` with failed deletions, `ballast`/`setup` with failed steps |
    ///
    /// Vetoes and skips are never an exit-code class; they appear in the
    /// report. Human reports go to stdout, diagnostics to stderr.
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::User(_) => 1,
            Self::Runtime(_) | Self::Io(_) => 2,
            Self::Internal(_) | Self::Json(_) => 3,
            Self::Partial(_) => 4,
        }
    }
}

/// Dispatch CLI commands.
pub fn run(cli: &Cli) -> Result<(), CliError> {
    if cli.no_color {
        control::set_override(false);
    }

    match &cli.command {
        Command::Daemon(args) => run_daemon(cli, args),
        Command::Policy(args) => run_policy(cli, args),
        Command::Install(args) => run_install(cli, args),
        Command::Uninstall(args) => run_uninstall(cli, args),
        Command::Status(args) => run_status(cli, args),
        Command::Service(args) => run_service(cli, args),
        Command::Stats(args) => run_stats(cli, args),
        Command::Scan(args) => run_scan(cli, args),
        Command::Clean(args) => run_clean(cli, args),
        Command::Undo(args) => run_undo(cli, args),
        Command::Ballast(args) => run_ballast(cli, args),
        Command::Config(args) => run_config(cli, args),
        Command::Version(args) => emit_version(cli, args),
        Command::Emergency(args) => run_emergency(cli, args),
        Command::Protect(args) => run_protect(cli, args),
        Command::Unprotect(args) => run_unprotect(cli, args),
        Command::Lease(args) => run_lease(cli, args),
        Command::LeaseWatch(args) => run_lease_watch(args),
        Command::Tune(args) => run_tune(cli, args),
        Command::Check(args) => run_check(cli, args),
        Command::Blame(args) => run_blame(cli, args),
        Command::Dashboard(args) => run_dashboard(cli, args),
        Command::Doctor(args) => run_doctor(cli, args),
        Command::Metrics => run_metrics(cli),
        Command::Docs(args) => run_docs(cli, args),
        Command::Completions(args) => {
            let mut command = Cli::command();
            let binary_name = command.get_name().to_string();
            generate(args.shell, &mut command, binary_name, &mut io::stdout());
            Ok(())
        }
        Command::Update(args) => run_update(cli, args),
        Command::Setup(args) => run_setup(cli, args),
        Command::Bootstrap(args) => run_bootstrap(cli, args),
        Command::Explain(args) => run_explain(cli, args),
        Command::Log(args) => run_log(cli, args),
        Command::TruncateLogs(args) => run_truncate_logs(cli, args),
    }
}

/// Which decisions `sbh explain` should render.
enum ExplainSelector {
    Id(String),
    Last(usize),
    Path(PathBuf),
    Since(std::time::Duration),
}

/// Where `sbh explain` reads decisions from: the daemon's SQLite ledger
/// (read-only) or, when that is absent or unreadable, the `decision` lines of
/// the JSONL activity log.
enum ExplainSource {
    Sqlite(SqliteLogger),
    Jsonl(Vec<storage_ballast_helper::scanner::decision_record::DecisionRecord>),
}

impl ExplainSource {
    fn label(&self) -> &'static str {
        match self {
            Self::Sqlite(_) => "sqlite",
            Self::Jsonl(_) => "jsonl",
        }
    }

    /// Records matching the selector, newest first, plus (for `--id`) how
    /// many ledger rows share that id.
    fn select(
        &self,
        selector: &ExplainSelector,
        limit: u32,
    ) -> Result<
        (
            Vec<storage_ballast_helper::scanner::decision_record::DecisionRecord>,
            Option<usize>,
        ),
        CliError,
    > {
        let runtime = |e: storage_ballast_helper::core::errors::SbhError| {
            CliError::Runtime(format!("decision ledger query failed: {e}"))
        };
        match self {
            Self::Sqlite(db) => Ok(match selector {
                ExplainSelector::Id(id) => db
                    .decision_by_id(id)
                    .map_err(runtime)?
                    .map_or((Vec::new(), Some(0)), |(record, count)| {
                        (vec![record], Some(count))
                    }),
                ExplainSelector::Last(n) => (
                    db.recent_decisions(u32::try_from(*n).unwrap_or(u32::MAX).max(1))
                        .map_err(runtime)?,
                    None,
                ),
                ExplainSelector::Path(path) => (
                    db.decisions_for_path(&path.to_string_lossy(), limit)
                        .map_err(runtime)?,
                    None,
                ),
                ExplainSelector::Since(window) => {
                    let since = (chrono::Utc::now()
                        - chrono::Duration::from_std(*window).unwrap_or(chrono::Duration::MAX))
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                    (db.decisions_since(&since, limit).map_err(runtime)?, None)
                }
            }),
            Self::Jsonl(records) => {
                // `records` are oldest-first as written; render newest first.
                let newest_first = records.iter().rev();
                Ok(match selector {
                    ExplainSelector::Id(id) => {
                        let matching: Vec<_> = newest_first
                            .filter(|record| &record.id == id)
                            .cloned()
                            .collect();
                        let count = matching.len();
                        (matching.into_iter().take(1).collect(), Some(count))
                    }
                    ExplainSelector::Last(n) => {
                        (newest_first.take((*n).max(1)).cloned().collect(), None)
                    }
                    ExplainSelector::Path(path) => (
                        newest_first
                            .filter(|record| &record.path == path)
                            .take(usize::try_from(limit).unwrap_or(usize::MAX))
                            .cloned()
                            .collect(),
                        None,
                    ),
                    ExplainSelector::Since(window) => {
                        let since = (chrono::Utc::now()
                            - chrono::Duration::from_std(*window).unwrap_or(chrono::Duration::MAX))
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                        (
                            newest_first
                                .filter(|record| record.timestamp >= since)
                                .take(usize::try_from(limit).unwrap_or(usize::MAX))
                                .cloned()
                                .collect(),
                            None,
                        )
                    }
                })
            }
        }
    }

    /// The most recent ids, for the "no match" hint.
    fn recent_ids(&self, n: u32) -> Vec<String> {
        match self {
            Self::Sqlite(db) => db
                .recent_decisions(n)
                .unwrap_or_default()
                .into_iter()
                .map(|record| record.id)
                .collect(),
            Self::Jsonl(records) => records
                .iter()
                .rev()
                .take(usize::try_from(n).unwrap_or(usize::MAX))
                .map(|record| record.id.clone())
                .collect(),
        }
    }
}

/// Parse the `decision` lines of a JSONL activity log into records
/// (oldest first). Lines that are not decisions, or fail to parse, are
/// skipped: the JSONL log is append-only and may hold older schemas.
fn decisions_from_jsonl(
    path: &Path,
) -> Option<Vec<storage_ballast_helper::scanner::decision_record::DecisionRecord>> {
    let contents = std::fs::read_to_string(path).ok()?;
    Some(
        contents
            .lines()
            .filter(|line| line.contains("\"event\":\"decision\""))
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|entry| entry["event"] == "decision")
            .filter_map(|entry| {
                entry["details"].as_str().and_then(
                    storage_ballast_helper::scanner::decision_record::parse_decision_from_details,
                )
            })
            .collect(),
    )
}

fn open_explain_source(cli: &Cli, config: &Config) -> Result<ExplainSource, CliError> {
    let db_path = &config.paths.sqlite_db;
    if db_path.exists()
        && let Ok(db) = SqliteLogger::open_read_only(db_path)
    {
        return Ok(ExplainSource::Sqlite(db));
    }
    if let Some(records) = decisions_from_jsonl(&config.paths.jsonl_log) {
        if cli.verbose {
            eprintln!(
                "[SBH-EXPLAIN] decision ledger {} unavailable; reading {} decision line(s) from {}",
                db_path.display(),
                records.len(),
                config.paths.jsonl_log.display()
            );
        }
        return Ok(ExplainSource::Jsonl(records));
    }
    // Neither source is readable: emit the standard permission-aware hint.
    open_activity_db_for_reading(cli, "explain", config)?.map_or_else(
        || {
            Err(CliError::User(format!(
                "no decision ledger is readable: {} and {} are missing or unreadable",
                db_path.display(),
                config.paths.jsonl_log.display()
            )))
        },
        |db| Ok(ExplainSource::Sqlite(db)),
    )
}

#[allow(clippy::too_many_lines)]
fn run_explain(cli: &Cli, args: &ExplainArgs) -> Result<(), CliError> {
    use storage_ballast_helper::scanner::decision_record::{
        ExplainLevel, format_explain, is_decision_id,
    };

    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;
    let level = ExplainLevel::from_int(args.level.min(3));
    if let Some(path) = &args.why_not {
        return run_explain_why_not(cli, &config, path, args.counterfactual, level);
    }
    if let Some(id) = &args.replay {
        return run_explain_replay(cli, &config, id);
    }
    let limit = u32::try_from(args.limit.max(1)).unwrap_or(u32::MAX);
    let selector = if let Some(id) = &args.id {
        let id = id.trim().to_ascii_lowercase();
        if !is_decision_id(&id) {
            return Err(CliError::User(format!(
                "{id:?} is not a decision id (12 hex characters); find ids with `sbh explain --last 20`"
            )));
        }
        ExplainSelector::Id(id)
    } else if let Some(n) = args.last {
        ExplainSelector::Last(n)
    } else if let Some(path) = &args.path {
        ExplainSelector::Path(path.canonicalize().unwrap_or_else(|_| path.clone()))
    } else if let Some(window) = &args.since {
        ExplainSelector::Since(parse_window_duration(window)?)
    } else {
        return Err(CliError::User(
            "specify one of --id, --last, --path, or --since".to_string(),
        ));
    };

    let source = open_explain_source(cli, &config)?;
    let (records, shared_count) = source.select(&selector, limit)?;
    if records.is_empty() {
        let recent = source.recent_ids(3);
        let hint = if recent.is_empty() {
            "the ledger has no decisions yet (the daemon records one per evaluated candidate; `sbh clean` records its plan)".to_string()
        } else {
            format!("recent ids: {}", recent.join(", "))
        };
        let what = match &selector {
            ExplainSelector::Id(id) => format!("no decision with id {id}"),
            ExplainSelector::Last(_) => "no decisions recorded".to_string(),
            ExplainSelector::Path(path) => format!("no decision for path {}", path.display()),
            ExplainSelector::Since(_) => "no decisions in that window".to_string(),
        };
        if output_mode(cli) == OutputMode::Json {
            write_json_line(&json!({
                "command": "explain",
                "error": "no_matching_decision",
                "source": source.label(),
                "recent_ids": recent,
            }))?;
        }
        return Err(CliError::User(format!("{what} ({hint})")));
    }
    if cli.verbose {
        trace_explain_records(&records, args.level.min(3), source.label());
    }

    match output_mode(cli) {
        OutputMode::Json => {
            let mut payload = json!({
                "command": "explain",
                "source": source.label(),
                "level": args.level.min(3),
                "count": records.len(),
                "decisions": records
                    .iter()
                    .map(|record| {
                        let mut value = record.to_json_at_level(level);
                        if let ExplainSource::Sqlite(db) = &source {
                            value["outcomes"] =
                                json!(db.outcomes_for_decision(&record.id).unwrap_or_default());
                            value["plans"] = json!(
                                db.planner_events_for_decision(&record.id)
                                    .unwrap_or_default()
                                    .iter()
                                    .filter_map(|line| planner_explanation(line, &record.id))
                                    .collect::<Vec<_>>()
                            );
                        }
                        value
                    })
                    .collect::<Vec<_>>(),
            });
            if let Some(count) = shared_count {
                payload["records_with_id"] = json!(count);
            }
            write_json_line(&payload)?;
        }
        OutputMode::Human => {
            for (index, record) in records.iter().enumerate() {
                if index > 0 {
                    println!();
                }
                let shared = match shared_count {
                    Some(count) if count > 1 => {
                        format!(" ({count} records share this id; newest shown)")
                    }
                    _ => String::new(),
                };
                println!(
                    "Decision {}  {}  mode={}  source={}{shared}",
                    record.id,
                    record.timestamp,
                    record.policy_mode,
                    source.label()
                );
                print!("{}", format_explain(record, level));
                if let ExplainSource::Sqlite(db) = &source {
                    for outcome in db.outcomes_for_decision(&record.id).unwrap_or_default() {
                        println!(
                            "  Outcome: {} at {} ({} after the decision): {}",
                            outcome.outcome,
                            outcome.observed_at,
                            format_duration(Duration::from_secs(outcome.after_secs)),
                            outcome.detail
                        );
                    }
                    for line in db
                        .planner_events_for_decision(&record.id)
                        .unwrap_or_default()
                    {
                        if let Some(text) = planner_explanation(&line, &record.id) {
                            println!("  Plan: {text}");
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// One `[SBH-EXPLAIN]` stderr line per record under `--verbose`, so a
/// scripted explain leaves a trace naming the id, level, and ledger source.
fn trace_explain_records(
    records: &[storage_ballast_helper::scanner::decision_record::DecisionRecord],
    level: u8,
    source: &str,
) {
    for record in records {
        eprintln!(
            "[SBH-EXPLAIN] decision_id={} level={level} source={source} path={}",
            record.id,
            record.path.display()
        );
    }
}

// ──────────────────── explain --why-not / --counterfactual / --replay ────────────────────

/// One single-factor change that would flip a scoring outcome to Delete.
#[derive(Debug, Clone, Serialize)]
struct Counterfactual {
    factor: &'static str,
    current: String,
    needed: Option<String>,
    /// The same threshold as a number: seconds of age, bytes, or urgency.
    needed_value: Option<f64>,
    action_after: Option<&'static str>,
    note: Option<String>,
}

/// What `sbh explain --why-not` learned about one path, in the order the
/// rails run: protection, scanner visibility, scoring vetoes, deletion
/// preflight, then the score and decision.
struct WhyNotReport {
    path: PathBuf,
    verdict: String,
    protection: Option<String>,
    excluded: bool,
    scanner_note: Option<String>,
    trace: Option<ScanTrace>,
    preflight: Option<std::result::Result<(), &'static str>>,
    open_scan_complete: bool,
    min_score: f64,
    record: Option<storage_ballast_helper::scanner::decision_record::DecisionRecord>,
    counterfactuals: Vec<Counterfactual>,
}

fn run_explain_why_not(
    cli: &Cli,
    config: &Config,
    path: &Path,
    counterfactual: bool,
    level: storage_ballast_helper::scanner::decision_record::ExplainLevel,
) -> Result<(), CliError> {
    let path = path
        .canonicalize()
        .map_err(|e| CliError::User(format!("{}: {e}", path.display())))?;
    let report = why_not_report(config, &path, counterfactual)?;
    match output_mode(cli) {
        OutputMode::Json => write_json_line(&why_not_json(&report, level))?,
        OutputMode::Human => print!("{}", format_why_not(&report, level)),
    }
    Ok(())
}

/// The batch planner's explanation of one decision from a
/// `planner ... json=...` activity line (`None` when the line does not
/// name the decision).
fn planner_explanation(line: &str, decision_id: &str) -> Option<String> {
    let json = line.split_once(" json=")?.1;
    let plan: BatchPlan = serde_json::from_str(json).ok()?;
    if let Some(item) = plan
        .chosen
        .iter()
        .find(|item| item.decision_id == decision_id)
    {
        return plan.explain_choice(item.rank);
    }
    plan.skipped_for_budget
        .iter()
        .find(|item| item.decision_id == decision_id)
        .map(|item| {
            format!(
                "skipped for budget: {} at posterior {:.2} (loss {:.1}) did not fit the remaining budget of {} at {}",
                format_bytes(item.bytes),
                item.posterior,
                item.expected_loss,
                plan.risk_budget
                    .map_or_else(|| "unbounded".to_string(), |b| format!("{b:.1}")),
                plan.level
            )
        })
}

/// The pressure level of the mount under the first root and, for a
/// `--target-free` percentage, the bytes that reach it (`None` when the
/// mount already has them).
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
fn clean_plan_target(
    config: &Config,
    root_paths: &[PathBuf],
    target_free: Option<f64>,
) -> (PressureLevel, Option<u64>) {
    let Some(root) = root_paths.first() else {
        return (PressureLevel::Green, None);
    };
    let Ok(platform) = detect_platform() else {
        return (PressureLevel::Green, None);
    };
    let collector = FsStatsCollector::new(platform, Duration::from_millis(500));
    let Ok(stats) = collector.collect(root) else {
        return (PressureLevel::Green, None);
    };
    let pressure = &config.pressure;
    let level = classify_level(
        stats.free_pct(),
        pressure.green_min_free_pct,
        pressure.yellow_min_free_pct,
        pressure.orange_min_free_pct,
        pressure.red_min_free_pct,
    );
    let target = target_free
        .map(|pct| {
            ((stats.total_bytes as f64 * pct / 100.0) as u64).saturating_sub(stats.available_bytes)
        })
        .filter(|bytes| *bytes > 0);
    (level, target)
}

/// A manual clean's plan request: the mount's level sets the risk budget.
fn cli_plan_request(
    config: &Config,
    level: PressureLevel,
    target_bytes: Option<u64>,
    max_items: usize,
) -> PlanRequest {
    PlanRequest {
        level,
        target_bytes,
        max_items,
        risk_budget: config
            .scoring
            .batch_risk_budget_by_level
            .budget(level, config.scoring.false_positive_loss),
        false_positive_loss: config.scoring.false_positive_loss,
        include_review: false,
    }
}

/// Reorder an executor plan into the batch planner's order.
fn order_by_plan(plan: &mut DeletionPlan, batch_plan: &BatchPlan) {
    plan.candidates.sort_by_key(|candidate| {
        batch_plan
            .chosen
            .iter()
            .position(|item| item.path == candidate.path)
            .unwrap_or(usize::MAX)
    });
}

/// The per-category regret calibration factors the last 30 days of stored
/// outcomes imply (empty when the ledger is missing or unreadable).
fn ledger_regret_calibrations(config: &Config) -> HashMap<String, f64> {
    use storage_ballast_helper::scanner::regret::{
        Outcome, RegretCalibrator, RegretConfig, certainty_from_name,
    };
    let Ok(db) = SqliteLogger::open_read_only(&config.paths.sqlite_db) else {
        return HashMap::new();
    };
    let since = (chrono::Utc::now() - chrono::Duration::days(30))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let Ok(outcomes) = db.outcomes_since(&since) else {
        return HashMap::new();
    };
    let mut calibrator = RegretCalibrator::new(RegretConfig {
        window: Duration::from_secs(config.scoring.regret_window_minutes.saturating_mul(60)),
        alpha_definite: config.scoring.regret_alpha_definite,
        alpha_likely: config.scoring.regret_alpha_likely,
        suspend: Duration::from_secs(config.scoring.regret_suspend_minutes.saturating_mul(60)),
        ..RegretConfig::default()
    });
    calibrator.replay(
        outcomes.into_iter().filter_map(|stored| {
            Outcome::from_name(&stored.outcome).map(|outcome| {
                (
                    stored.category,
                    certainty_from_name(&stored.certainty),
                    outcome,
                )
            })
        }),
        std::time::Instant::now(),
    );
    calibrator.calibrations()
}

/// The scanner's own view of one directory: walk its parent one level with
/// the configured walker and pick the entry out, so classification, sizes,
/// and age are exactly what a scan would compute.
fn walk_single_entry(
    config: &Config,
    protection: ProtectionRegistry,
    path: &Path,
) -> Result<Option<storage_ballast_helper::scanner::walker::WalkEntry>, CliError> {
    let Some(parent) = path.parent() else {
        return Err(CliError::User(
            "cannot explain the filesystem root; name a directory under a scan root".to_string(),
        ));
    };
    let selected_scanner_engine = SelectedScannerEngine::for_mode(config.scanner.engine);
    let walker = DirectoryWalker::new(
        WalkerConfig {
            root_paths: vec![parent.to_path_buf()],
            max_depth: 1,
            follow_symlinks: config.scanner.follow_symlinks,
            cross_devices: config.scanner.cross_devices,
            parallelism: 1,
            excluded_paths: config
                .scanner
                .excluded_paths
                .iter()
                .cloned()
                .collect::<HashSet<_>>(),
            opaque_pruning: selected_scanner_engine.opaque_pruning(),
        },
        protection,
    );
    let entries = walker
        .walk()
        .map_err(|e| CliError::Runtime(e.to_string()))?;
    Ok(entries.into_iter().find(|entry| entry.path == path))
}

#[allow(clippy::too_many_lines)]
fn why_not_report(
    config: &Config,
    path: &Path,
    with_counterfactuals: bool,
) -> Result<WhyNotReport, CliError> {
    use storage_ballast_helper::scanner::decision_record::{DecisionRecordBuilder, PolicyMode};
    use storage_ballast_helper::scanner::scoring::DecisionAction;

    let min_score = config.scoring.min_score;
    let protection_patterns = if config.scanner.protected_paths.is_empty() {
        None
    } else {
        Some(config.scanner.protected_paths.as_slice())
    };
    let mut protection = ProtectionRegistry::new(protection_patterns)
        .map_err(|e| CliError::Runtime(e.to_string()))?;
    // A marker inside the directory protects it; so does one on any ancestor.
    let _ = protection.discover_markers(path, 1);
    let _ = protection.discover_ancestor_markers(path);
    let protection_reason = protection.protection_reason(path);
    // The walker excludes exact directories, not prefixes (the default list
    // holds `/`, which would otherwise cover everything).
    let excluded = config
        .scanner
        .excluded_paths
        .iter()
        .any(|excluded| excluded == path);

    let mut report = WhyNotReport {
        path: path.to_path_buf(),
        verdict: String::new(),
        protection: protection_reason.clone(),
        excluded,
        scanner_note: None,
        trace: None,
        preflight: None,
        open_scan_complete: true,
        min_score,
        record: None,
        counterfactuals: Vec::new(),
    };

    let Some(entry) = walk_single_entry(config, protection, path)? else {
        report.scanner_note = Some(if !path.is_dir() {
            "the scanner scores directories, and this is a file: explain its directory instead"
                .to_string()
        } else if let Some(reason) = &protection_reason {
            format!("not visited: {reason}")
        } else if excluded {
            "not visited: under scanner.excluded_paths".to_string()
        } else {
            "not visited by the walker (a symlink, another device with cross_devices = false, or the interior of an opaque tree)".to_string()
        });
        report.verdict = report.scanner_note.clone().unwrap_or_default();
        return Ok(report);
    };

    let registry = ArtifactPatternRegistry::default();
    let classification = if let Some(opaque_tree) = &entry.opaque_tree {
        match opaque_tree.disposition {
            OpaqueTreeDisposition::CandidateOpaque => opaque_tree.classification.clone(),
            OpaqueTreeDisposition::SignalOnly | OpaqueTreeDisposition::ProtectedOpaque => {
                report.scanner_note = Some(format!(
                    "part of an opaque tree ({:?}): the scanner scores the tree as a whole, not this directory",
                    opaque_tree.disposition
                ));
                report.verdict = report.scanner_note.clone().unwrap_or_default();
                return Ok(report);
            }
        }
    } else {
        registry.classify(&entry.path, entry.structural_signals)
    };
    let now = SystemTime::now();
    let age = now
        .duration_since(
            entry.effective_age_timestamp(classification.category.is_regenerable_tree()),
        )
        .unwrap_or_default();
    let mut candidate = CandidateInput {
        path: entry.path.clone(),
        size_bytes: entry.metadata.content_size_bytes,
        age,
        classification,
        signals: entry.structural_signals,
        active_references: ActiveReferenceSummary::default(),
        is_open: false,
        excluded: false,
    };

    // Open files and active references, always (a scan only checks them for
    // candidates above the threshold; here the question is exactly why not).
    let scan_roots = vec![
        path.parent()
            .map_or_else(|| path.to_path_buf(), Path::to_path_buf),
    ];
    let active_reference_scan = active_reference_scan_config(config);
    let mut open_paths = None;
    let mut active_reference_index = None;
    candidate.is_open = open_status_for_candidate(
        &mut open_paths,
        &scan_roots,
        active_reference_scan,
        &entry.path,
        entry.metadata.content_size_bytes,
    );
    let (active_references, active_reference_checked) = active_references_for_candidate(
        &mut active_reference_index,
        &scan_roots,
        active_reference_scan,
        &entry.path,
        Some(entry.metadata.identity()),
        entry.metadata.content_size_bytes,
    );
    candidate.active_references = active_references;

    let mut engine =
        ScoringEngine::from_config(&config.scoring, config.scanner.min_file_age_minutes);
    // Regret labels (Q4): the ledger's outcomes raise the bar the same way
    // they do in the daemon, so the explanation names the threshold the
    // daemon would apply now (suspensions are daemon runtime state and are
    // not replayed here).
    engine.set_regret(ledger_regret_calibrations(config), HashSet::new());
    let sacred_paths = active_sacred_paths(config)?;
    let (mut score, sacred_overlaps) =
        score_candidate_with_deferred_sacred_check(&engine, &candidate, 0.0, &sacred_paths, |_| {
            true
        });
    score.identity = Some(entry.metadata.identity());
    let min_file_age_seconds = config.scanner.min_file_age_minutes.saturating_mul(60);
    report.trace = Some(build_scan_trace(
        &candidate,
        &score,
        min_file_age_seconds,
        active_reference_checked,
        &sacred_overlaps,
    ));

    // The executor's own preflight, with the open-file set it would use.
    let (open_set, open_scan_complete) =
        collect_open_path_ancestors(std::slice::from_ref(&report.path));
    report.open_scan_complete = open_scan_complete;
    let executor = DeletionExecutor::new(
        DeletionConfig {
            min_score,
            check_open_files: true,
            require_identity: matches!(config.scanner.engine, ScannerEngineMode::V2),
            sacred_paths,
            ..Default::default()
        },
        None,
    );
    let preflight = executor
        .explain_preflight(&score, Some(&open_set))
        .map_err(storage_ballast_helper::scanner::deletion::SkipReason::as_str);
    report.preflight = Some(preflight);

    if with_counterfactuals {
        report.counterfactuals = explain_counterfactuals(&engine, &candidate, &score);
    }

    let record = DecisionRecordBuilder::new().build(&score, PolicyMode::DryRun, None, None, None);
    report.verdict = if let Some(reason) = &report.protection {
        format!("protected: {reason}")
    } else if excluded {
        "excluded by scanner.excluded_paths".to_string()
    } else if score.vetoed {
        format!(
            "vetoed by scoring: {}",
            score.veto_reason.as_deref().unwrap_or("unspecified")
        )
    } else if let Some(Err(reason)) = &report.preflight {
        format!("refused by the deletion preflight: {reason}")
    } else if score.total_score < min_score {
        format!(
            "score {:.2} is below scoring.min_score {min_score:.2}",
            score.total_score
        )
    } else {
        match score.decision.action {
            DecisionAction::Keep => format!(
                "decided Keep: posterior abandoned {:.2}, expected loss keep {:.2} vs delete {:.2}",
                score.decision.posterior_abandoned,
                score.decision.expected_loss_keep,
                score.decision.expected_loss_delete
            ),
            DecisionAction::Review => format!(
                "decided Review: the keep-vs-delete margin ({:.2}) is inside the review band; `sbh clean` holds it, `sbh emergency` may act",
                (score.decision.expected_loss_keep - score.decision.expected_loss_delete).abs()
            ),
            DecisionAction::Delete => format!(
                "nothing keeps it: Delete at score {:.2} (a scan or the daemon would list it)",
                score.total_score
            ),
        }
    };
    report.record = Some(record);
    Ok(report)
}

/// Smallest `x` in `[lo, hi]` for which `flips(x)` holds, assuming the flip
/// is monotonic in `x` (more age, more bytes, or more pressure never makes
/// an artifact look less abandoned): a bisection between the endpoints.
fn smallest_flip(lo: u64, hi: u64, flips: impl Fn(u64) -> bool) -> Option<u64> {
    if lo > hi || !flips(hi) {
        return None;
    }
    if flips(lo) {
        return Some(lo);
    }
    let (mut bad, mut good) = (lo, hi);
    while good - bad > 1 {
        let mid = bad + (good - bad) / 2;
        if flips(mid) {
            good = mid;
        } else {
            bad = mid;
        }
    }
    Some(good)
}

/// For a candidate that is not Delete, the smallest single change of age,
/// size, or pressure urgency that would make the current engine say Delete.
/// A vetoed candidate has no such change: vetoes are hard rails.
#[allow(clippy::cast_precision_loss)]
fn explain_counterfactuals(
    engine: &ScoringEngine,
    input: &CandidateInput,
    current: &CandidacyScore,
) -> Vec<Counterfactual> {
    use storage_ballast_helper::scanner::scoring::DecisionAction;

    if current.vetoed {
        return vec![Counterfactual {
            factor: "veto",
            current: current
                .veto_reason
                .as_deref()
                .unwrap_or("unspecified")
                .to_string(),
            needed: None,
            needed_value: None,
            action_after: None,
            note: Some("not flippable by scoring: a veto is a hard rail".to_string()),
        }];
    }
    if current.decision.action == DecisionAction::Delete {
        return vec![Counterfactual {
            factor: "none",
            current: "Delete".to_string(),
            needed: None,
            needed_value: None,
            action_after: Some("Delete"),
            note: Some("already Delete".to_string()),
        }];
    }
    let deletes = |modified: &CandidateInput, urgency: f64| {
        engine.score_candidate(modified, urgency).decision.action == DecisionAction::Delete
    };

    let mut out = Vec::new();
    let year = 365 * 24 * 60 * 60;
    let age_needed = smallest_flip(input.age.as_secs().saturating_add(1), year, |secs| {
        let mut modified = input.clone();
        modified.age = std::time::Duration::from_secs(secs);
        deletes(&modified, 0.0)
    });
    out.push(Counterfactual {
        factor: "age",
        current: format_duration(input.age),
        needed: age_needed.map(|secs| format_duration(std::time::Duration::from_secs(secs))),
        needed_value: age_needed.map(|secs| secs as f64),
        action_after: age_needed.map(|_| "Delete"),
        note: age_needed
            .is_none()
            .then(|| "age alone cannot flip it within a year".to_string()),
    });

    let tebibyte = 1u64 << 40;
    let size_needed = smallest_flip(input.size_bytes.saturating_add(1), tebibyte, |bytes| {
        let mut modified = input.clone();
        modified.size_bytes = bytes;
        deletes(&modified, 0.0)
    });
    out.push(Counterfactual {
        factor: "size",
        current: format_bytes(input.size_bytes),
        needed: size_needed.map(format_bytes),
        needed_value: size_needed.map(|bytes| bytes as f64),
        action_after: size_needed.map(|_| "Delete"),
        note: size_needed
            .is_none()
            .then(|| "size alone cannot flip it below 1 TiB".to_string()),
    });

    let urgency_of = |hundredths: u64| f64::from(u32::try_from(hundredths).unwrap_or(100)) / 100.0;
    let urgency_needed = smallest_flip(0, 100, |hundredths| deletes(input, urgency_of(hundredths)));
    out.push(Counterfactual {
        factor: "pressure",
        current: "urgency 0.00 (Green)".to_string(),
        needed: urgency_needed.map(|hundredths| format!("urgency {:.2}", urgency_of(hundredths))),
        needed_value: urgency_needed.map(urgency_of),
        action_after: urgency_needed.map(|_| "Delete"),
        note: urgency_needed
            .is_none()
            .then(|| "pressure alone cannot flip it, even at Critical".to_string()),
    });
    out
}

fn why_not_json(
    report: &WhyNotReport,
    level: storage_ballast_helper::scanner::decision_record::ExplainLevel,
) -> Value {
    let preflight = report.preflight.as_ref().map(|outcome| match outcome {
        Ok(()) => json!({ "ok": true, "reason": Value::Null }),
        Err(reason) => json!({ "ok": false, "reason": reason }),
    });
    let trace = report.trace.as_ref().map(|trace| {
        json!({
            "pattern_name": trace.pattern_name,
            "category": trace.category,
            "mtime_check": trace.mtime_check,
            "fd_check": trace.fd_check,
            "exec_check": trace.exec_check,
            "mmap_check": trace.mmap_check,
            "sacred_overlap_check": trace.sacred_overlap_check,
            "final_confidence": trace.final_confidence,
            "final_action": trace.final_action,
            "veto_reason": trace.veto_reason,
        })
    });
    json!({
        "command": "explain",
        "mode": "why_not",
        "path": report.path.to_string_lossy(),
        "verdict": report.verdict,
        "protection": report.protection,
        "excluded": report.excluded,
        "scanner_note": report.scanner_note,
        "trace": trace,
        "preflight": preflight,
        "open_file_scan_complete": report.open_scan_complete,
        "min_score": report.min_score,
        "decision": report.record.as_ref().map(|record| record.to_json_at_level(level)),
        "counterfactuals": report.counterfactuals,
    })
}

fn format_why_not(
    report: &WhyNotReport,
    level: storage_ballast_helper::scanner::decision_record::ExplainLevel,
) -> String {
    use std::fmt::Write as _;
    use storage_ballast_helper::scanner::decision_record::format_explain;

    let mut out = String::new();
    let _ = writeln!(out, "Why not: {}", report.path.display());
    let _ = writeln!(out, "  verdict:    {}", report.verdict);
    let _ = writeln!(
        out,
        "  protection: {}",
        report.protection.as_deref().unwrap_or("none")
    );
    let _ = writeln!(
        out,
        "  excluded:   {}",
        if report.excluded {
            "yes (scanner.excluded_paths)"
        } else {
            "no"
        }
    );
    if let Some(note) = &report.scanner_note {
        let _ = writeln!(out, "  scanner:    {note}");
        return out;
    }
    if let Some(trace) = &report.trace {
        let _ = writeln!(
            out,
            "  scanner:    {} ({}, confidence {:.2})",
            trace.category, trace.pattern_name, trace.final_confidence
        );
        let _ = writeln!(out, "  age gate:   {}", trace.mtime_check);
        let _ = writeln!(out, "  open files: {}", trace.fd_check);
        let _ = writeln!(out, "  executing:  {}", trace.exec_check);
        let _ = writeln!(out, "  mmap:       {}", trace.mmap_check);
        let _ = writeln!(out, "  sacred:     {}", trace.sacred_overlap_check);
    }
    match &report.preflight {
        Some(Ok(())) => {
            let _ = writeln!(out, "  preflight:  ok");
        }
        Some(Err(reason)) => {
            let _ = writeln!(out, "  preflight:  refused ({reason})");
        }
        None => {}
    }
    if !report.open_scan_complete {
        let _ = writeln!(
            out,
            "  note:       the open-file scan was incomplete; a real batch would refuse the whole batch"
        );
    }
    if let Some(record) = &report.record {
        let _ = writeln!(
            out,
            "  score:      {:.2} (scoring.min_score {:.2}), action {}, id {}",
            record.total_score, report.min_score, record.action, record.id
        );
        let _ = writeln!(out);
        out.push_str(&format_explain(record, level));
    }
    if !report.counterfactuals.is_empty() {
        let _ = writeln!(
            out,
            "\nCounterfactuals (smallest single change that flips to Delete):"
        );
        for item in &report.counterfactuals {
            match (&item.needed, &item.note) {
                (Some(needed), _) => {
                    let _ = writeln!(
                        out,
                        "  {:<9} {} -> needs {} ({})",
                        item.factor,
                        item.current,
                        needed,
                        item.action_after.unwrap_or("Delete")
                    );
                }
                (None, Some(note)) => {
                    let _ = writeln!(out, "  {:<9} {} -> {note}", item.factor, item.current);
                }
                (None, None) => {
                    let _ = writeln!(out, "  {:<9} {}", item.factor, item.current);
                }
            }
        }
    }
    out
}

/// A recorded decision re-scored by the current engine.
struct ReplayReport {
    id: String,
    path: PathBuf,
    recorded_at: String,
    urgency: f64,
    rows: Vec<(&'static str, f64, f64)>,
    stored_action: String,
    replayed_action: String,
    stored_vetoed: bool,
    replayed_veto: Option<String>,
    drift: bool,
    approximations: Vec<String>,
}

fn run_explain_replay(cli: &Cli, config: &Config, id: &str) -> Result<(), CliError> {
    use storage_ballast_helper::scanner::decision_record::is_decision_id;

    let id = id.trim().to_ascii_lowercase();
    if !is_decision_id(&id) {
        return Err(CliError::User(format!(
            "{id:?} is not a decision id (12 hex characters); find ids with `sbh explain --last 20`"
        )));
    }
    let source = open_explain_source(cli, config)?;
    let (records, _) = source.select(&ExplainSelector::Id(id.clone()), 1)?;
    let Some(record) = records.into_iter().next() else {
        return Err(CliError::User(format!(
            "no decision with id {id} in the {} ledger",
            source.label()
        )));
    };
    let replay = replay_decision(config, &record)?;
    match output_mode(cli) {
        OutputMode::Json => write_json_line(&json!({
            "command": "explain",
            "mode": "replay",
            "id": replay.id,
            "path": replay.path.to_string_lossy(),
            "recorded_at": replay.recorded_at,
            "urgency": replay.urgency,
            "stored_action": replay.stored_action,
            "replayed_action": replay.replayed_action,
            "stored_vetoed": replay.stored_vetoed,
            "replayed_veto": replay.replayed_veto,
            "factors": replay
                .rows
                .iter()
                .map(|(name, stored, replayed)| json!({
                    "name": name,
                    "stored": stored,
                    "replayed": replayed,
                    "delta": replayed - stored,
                }))
                .collect::<Vec<_>>(),
            "drift": replay.drift,
            "approximations": replay.approximations,
        }))?,
        OutputMode::Human => {
            println!(
                "Replay {}  recorded {}  {}",
                replay.id,
                replay.recorded_at,
                replay.path.display()
            );
            println!(
                "  action: stored {} -> replayed {}   drift: {}",
                replay.stored_action,
                replay.replayed_action,
                if replay.drift { "YES" } else { "no" }
            );
            if replay.stored_vetoed || replay.replayed_veto.is_some() {
                println!(
                    "  veto:   stored {} -> replayed {}",
                    if replay.stored_vetoed { "yes" } else { "no" },
                    replay.replayed_veto.as_deref().unwrap_or("no")
                );
            }
            println!("  urgency replayed: {:.2}", replay.urgency);
            println!(
                "  {:<22} {:>9} {:>9} {:>9}",
                "factor", "stored", "replayed", "delta"
            );
            for (name, stored, replayed) in &replay.rows {
                println!(
                    "  {name:<22} {stored:>9.3} {replayed:>9.3} {:>+9.3}",
                    replayed - stored
                );
            }
            if !replay.approximations.is_empty() {
                println!("  approximations:");
                for note in &replay.approximations {
                    println!("    - {note}");
                }
            }
        }
    }
    Ok(())
}

/// Rebuild the scoring input from a record and score it with the current
/// engine and config. Inputs the ledger does not persist are approximated
/// and every approximation is named in the report.
fn replay_decision(
    config: &Config,
    record: &storage_ballast_helper::scanner::decision_record::DecisionRecord,
) -> Result<ReplayReport, CliError> {
    use storage_ballast_helper::scanner::decision_record::ActionRecord;
    use storage_ballast_helper::scanner::patterns::{ArtifactClassification, StructuralSignals};
    use storage_ballast_helper::scanner::scoring::urgency_for_pressure_multiplier;
    use storage_ballast_helper::scanner::walker::structural_signals_for_path;

    let category: ArtifactCategory = record
        .classification
        .category
        .parse()
        .map_err(CliError::User)?;
    let mut approximations = Vec::new();
    let combined = record.classification.combined_confidence;
    let name_confidence = record.classification.name_confidence.unwrap_or_else(|| {
        approximations.push("name_confidence was not stored; combined_confidence used".to_string());
        combined
    });
    let structural_confidence = record
        .classification
        .structural_confidence
        .unwrap_or_else(|| {
            approximations
                .push("structural_confidence was not stored; combined_confidence used".to_string());
            combined
        });
    let signals = if record.path.is_dir() {
        structural_signals_for_path(&record.path)
    } else {
        approximations.push(
            "the path is gone and structural signals are not persisted; structure scored from no signals"
                .to_string(),
        );
        StructuralSignals::default()
    };
    approximations.push(
        "open-file and active-reference evidence is not persisted; replayed as none".to_string(),
    );
    let urgency = urgency_for_pressure_multiplier(record.factors.pressure_multiplier);

    let input = CandidateInput {
        path: record.path.clone(),
        size_bytes: record.size_bytes,
        age: std::time::Duration::from_secs(record.age_secs),
        classification: ArtifactClassification {
            pattern_name: std::borrow::Cow::Owned(record.classification.pattern_name.clone()),
            category,
            name_confidence,
            structural_confidence,
            combined_confidence: combined,
        },
        signals,
        active_references: ActiveReferenceSummary::default(),
        is_open: false,
        excluded: false,
    };
    let engine = ScoringEngine::from_config(&config.scoring, config.scanner.min_file_age_minutes);
    let replayed = engine.score_candidate(&input, urgency);

    let rows = replay_rows(record, &replayed);
    let replayed_action = ActionRecord::from(replayed.decision.action);
    let drift = record.action != replayed_action
        || record.vetoed != replayed.vetoed
        || (record.total_score - replayed.total_score).abs() > 0.005;
    Ok(ReplayReport {
        id: record.id.clone(),
        path: record.path.clone(),
        recorded_at: record.timestamp.clone(),
        urgency,
        rows,
        stored_action: record.action.to_string(),
        replayed_action: replayed_action.to_string(),
        stored_vetoed: record.vetoed,
        replayed_veto: replayed.veto_reason.as_ref().map(ToString::to_string),
        drift,
        approximations,
    })
}

/// `(name, stored, replayed)` for every number a replay compares.
fn replay_rows(
    record: &storage_ballast_helper::scanner::decision_record::DecisionRecord,
    replayed: &CandidacyScore,
) -> Vec<(&'static str, f64, f64)> {
    vec![
        (
            "location",
            record.factors.location,
            replayed.factors.location,
        ),
        ("name", record.factors.name, replayed.factors.name),
        ("age", record.factors.age, replayed.factors.age),
        ("size", record.factors.size, replayed.factors.size),
        (
            "structure",
            record.factors.structure,
            replayed.factors.structure,
        ),
        (
            "pressure_multiplier",
            record.factors.pressure_multiplier,
            replayed.factors.pressure_multiplier,
        ),
        ("total_score", record.total_score, replayed.total_score),
        (
            "posterior_abandoned",
            record.posterior_abandoned,
            replayed.decision.posterior_abandoned,
        ),
        (
            "expected_loss_keep",
            record.expected_loss_keep,
            replayed.decision.expected_loss_keep,
        ),
        (
            "expected_loss_delete",
            record.expected_loss_delete,
            replayed.decision.expected_loss_delete,
        ),
        (
            "calibration_score",
            record.calibration_score,
            replayed.decision.calibration_score,
        ),
    ]
}

fn run_bootstrap(cli: &Cli, args: &BootstrapArgs) -> Result<(), CliError> {
    use storage_ballast_helper::cli::bootstrap::{
        EnvironmentHealth, MigrateOptions, format_report_human, run_migration,
    };

    let report = run_migration(&MigrateOptions {
        dry_run: args.dry_run,
        ..MigrateOptions::default()
    });

    match output_mode(cli) {
        OutputMode::Json => write_json_line(&json!({
            "command": "bootstrap",
            "dry_run": args.dry_run,
            "report": report,
        }))?,
        OutputMode::Human => {
            if args.dry_run {
                println!("Bootstrap dry run (nothing changed):\n");
            }
            print!("{}", format_report_human(&report));
        }
    }

    let unresolved = report
        .actions
        .iter()
        .filter(|action| action.error.is_some())
        .count();
    if !args.dry_run && (report.health == EnvironmentHealth::Broken || unresolved > 0) {
        return Err(CliError::Partial(format!(
            "bootstrap left the environment {} with {unresolved} action(s) failed; see the report above",
            report.health
        )));
    }
    Ok(())
}

/// Run the install-time subset of bootstrap repairs (stale PATH lines, unit
/// paths, permissions, missing dirs/state) before the service is registered.
/// Prints one summary line; details are available via `sbh bootstrap --dry-run`.
fn run_install_bootstrap(cli: &Cli, args: &InstallArgs) {
    use storage_ballast_helper::cli::bootstrap::{
        MigrateOptions, install_time_safe_actions, run_migration,
    };

    if args.no_bootstrap {
        return;
    }
    let report = run_migration(&MigrateOptions {
        dry_run: args.dry_run,
        allowed_actions: Some(install_time_safe_actions().to_vec()),
        ..MigrateOptions::default()
    });
    let deferred = report
        .actions
        .iter()
        .filter(|action| !action.applied && action.error.is_none())
        .count();
    let failed = report
        .actions
        .iter()
        .filter(|action| action.error.is_some())
        .count();
    if output_mode(cli) == OutputMode::Human {
        println!(
            "Bootstrap: environment {}; {} issue(s) found, {} repaired, {} deferred to `sbh bootstrap`, {} failed{}",
            report.health,
            report.issues_found,
            report.issues_repaired,
            deferred,
            failed,
            if args.dry_run { " (dry run)" } else { "" }
        );
    }
    if cli.verbose {
        for action in &report.actions {
            eprintln!(
                "[SBH-INSTALL] bootstrap {}: {} ({}{})",
                if action.applied { "applied" } else { "planned" },
                action.description,
                action.reason,
                action
                    .error
                    .as_deref()
                    .map_or(String::new(), |e| format!(", error: {e}"))
            );
        }
    }
}

fn run_truncate_logs(cli: &Cli, args: &TruncateLogsArgs) -> Result<(), CliError> {
    use storage_ballast_helper::scanner::log_truncator::{
        LogTruncationReport, truncate_oversized_logs,
    };

    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;
    let mut policy = config.scanner.log_truncation;
    if args.enable_anyway {
        policy.enabled = true;
    }
    if let Some(size) = args.min_size {
        policy.min_size_bytes = size;
    }
    if !policy.enabled {
        eprintln!(
            "[sbh] scanner.log_truncation.enabled = false. Pass --enable-anyway to override, \
             or edit /etc/sbh/config.toml to enable persistently."
        );
        return Ok(());
    }

    // Force-mode collapses the age gate by reporting critical pressure.
    let synthetic_free_pct = if args.force { 0.0 } else { 100.0 };

    let report: LogTruncationReport =
        truncate_oversized_logs(&policy, synthetic_free_pct, args.dry_run);

    let verb = if args.dry_run { "would free" } else { "freed" };
    let bytes = if args.dry_run {
        report.bytes_would_reclaim
    } else {
        report.bytes_reclaimed
    };
    let files = if args.dry_run {
        report.files_would_truncate
    } else {
        report.files_truncated
    };
    println!(
        "[sbh] log truncation pass {verb} {bytes} bytes across {n} file(s); skipped {sk}; {e} error(s); took {ms} ms",
        n = files,
        sk = report.files_skipped,
        e = report.errors.len(),
        ms = report.duration.as_millis(),
    );
    for (path, err) in &report.errors {
        eprintln!("  error: {} — {err}", path.display());
    }
    Ok(())
}

fn to_runtime_daemon_args(args: &DaemonArgs) -> RuntimeDaemonArgs {
    RuntimeDaemonArgs {
        foreground: !args.background,
        pidfile: args.pidfile.clone(),
        watchdog_sec: args.watchdog_sec,
    }
}

fn run_daemon(cli: &Cli, args: &DaemonArgs) -> Result<(), CliError> {
    if let Some(action) = &args.action {
        return run_daemon_control(cli, action);
    }
    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;
    // A key nobody reads is a setting the operator believes is in force.
    // Say so at startup; refuse under strict mode.
    for key in &config.unknown_keys {
        eprintln!("[SBH-CONFIG] {key}");
    }
    if config.core.strict_config && !config.unknown_keys.is_empty() {
        return Err(CliError::User(format!(
            "refusing to start: {} unknown config key(s) in {} and [core] strict_config = true (see `sbh config validate`)",
            config.unknown_keys.len(),
            config.paths.config_file.display()
        )));
    }
    // Injected filesystem statistics are for the e2e runner only: a unit
    // that inherited SBH_TEST_MODE must not act on fiction.
    storage_ballast_helper::platform::test_overlay::refuse_under_service_manager()
        .map_err(|e| CliError::Runtime(e.to_string()))?;
    let runtime_args = to_runtime_daemon_args(args);
    let mut daemon = MonitoringDaemon::init(config, &runtime_args)
        .map_err(|e| CliError::Runtime(format!("failed to initialize daemon: {e}")))?;
    daemon
        .run()
        .map_err(|e| CliError::Runtime(format!("daemon runtime failure: {e}")))
}

/// One request to the running daemon's control socket. Errors name the
/// socket path so "no daemon" and "wrong state dir" are distinguishable.
fn control_request(
    cli: &Cli,
    cmd: &str,
    args: &Value,
) -> Result<
    (
        PathBuf,
        storage_ballast_helper::daemon::control::ControlResponse,
    ),
    CliError,
> {
    use storage_ballast_helper::daemon::control::{read_endpoint, request};

    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;
    let Some(endpoint) = read_endpoint(&config.paths.state_file) else {
        return Err(CliError::User(format!(
            "no running daemon: the lock beside {} is free or carries no control token (is the daemon running with [core] control_socket_enabled = true, and readable by this user?)",
            config.paths.state_file.display()
        )));
    };
    let socket = endpoint.socket;
    if !socket.exists() {
        return Err(CliError::User(format!(
            "the daemon holds its lock but its control socket {} is absent: [core] control_socket_enabled = false, or the socket failed to bind (see the daemon log)",
            socket.display()
        )));
    }
    let response = request(&socket, &endpoint.token, cmd, args)
        .map_err(|e| CliError::Runtime(format!("control socket {}: {e}", socket.display())))?;
    Ok((socket, response))
}

/// Print a control response the way the rest of the CLI does and turn a
/// refused request into a non-zero exit.
fn report_control_response(
    cli: &Cli,
    command: &str,
    socket: &Path,
    response: &storage_ballast_helper::daemon::control::ControlResponse,
) -> Result<(), CliError> {
    match output_mode(cli) {
        OutputMode::Json => {
            let payload = json!({
                "command": command,
                "socket": socket,
                "ok": response.ok,
                "result": response.result,
                "error": response.error,
            });
            write_json_line(&payload)?;
        }
        OutputMode::Human => {
            if response.ok {
                println!("{command}: ok");
                if let Some(object) = response.result.as_object() {
                    for (key, value) in object {
                        println!("  {key}: {value}");
                    }
                } else if !response.result.is_null() {
                    println!("  {}", response.result);
                }
            } else if let Some(error) = &response.error {
                eprintln!("sbh: {command}: {} ({})", error.message, error.code);
            }
        }
    }
    if response.ok {
        Ok(())
    } else {
        Err(CliError::User(format!(
            "{command} refused by the daemon: {}",
            response
                .error
                .as_ref()
                .map_or_else(|| "unknown error".to_string(), |e| e.message.clone())
        )))
    }
}

fn run_daemon_control(cli: &Cli, action: &DaemonAction) -> Result<(), CliError> {
    let cmd = match action {
        DaemonAction::Ping => "ping",
        DaemonAction::ScanNow => "scan-now",
        DaemonAction::Reload => "reload",
        DaemonAction::Shutdown => "shutdown",
    };
    let (socket, response) = control_request(cli, cmd, &json!({}))?;
    report_control_response(cli, &format!("daemon {cmd}"), &socket, &response)
}

fn run_policy(cli: &Cli, args: &PolicyArgs) -> Result<(), CliError> {
    let action = match args.action {
        PolicyCliAction::Status => "status",
        PolicyCliAction::Promote => "promote",
        PolicyCliAction::Demote => "demote",
    };
    let (socket, response) = control_request(cli, "policy", &json!({ "action": action }))?;
    report_control_response(cli, &format!("policy {action}"), &socket, &response)
}

/// `sbh metrics`: print the daemon's Prometheus textfile export verbatim.
/// The daemon writes it beside `state.json` with every state write; this
/// command only reads it, so it says why when there is nothing to read.
/// `sbh docs`: the generated document as JSON (the default, and `--json`),
/// one section's Markdown (`--section`), or the marked regions of files
/// rewritten (`--render`) or verified (`--check`, exit 1 on drift).
fn run_docs(cli: &Cli, args: &DocsArgs) -> Result<(), CliError> {
    use storage_ballast_helper::cli::docs::{DocsDocument, check_file, render_file};

    let document = DocsDocument::build(&Cli::command());

    if !args.check.is_empty() {
        let mut drifted: Vec<(PathBuf, Vec<String>)> = Vec::new();
        for path in &args.check {
            let changed = check_file(path, &document).map_err(|e| CliError::User(e.to_string()))?;
            if !changed.is_empty() {
                drifted.push((path.clone(), changed));
            }
        }
        if output_mode(cli) == OutputMode::Json {
            let payload = json!({
                "command": "docs",
                "check": args.check,
                "drifted": drifted.iter().map(|(path, sections)| json!({ "path": path, "sections": sections })).collect::<Vec<_>>(),
                "ok": drifted.is_empty(),
            });
            write_json_line(&payload)?;
        } else if drifted.is_empty() {
            println!(
                "docs: generated regions match the code in {}",
                args.check
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        } else {
            for (path, sections) in &drifted {
                eprintln!(
                    "docs: {} has drifted in: {}",
                    path.display(),
                    sections.join(", ")
                );
            }
        }
        if drifted.is_empty() {
            return Ok(());
        }
        return Err(CliError::User(format!(
            "generated documentation regions have drifted; run `sbh docs --render {}`",
            drifted
                .iter()
                .map(|(path, _)| path.display().to_string())
                .collect::<Vec<_>>()
                .join(" ")
        )));
    }

    if !args.render.is_empty() {
        let mut report = Vec::new();
        for path in &args.render {
            let changed =
                render_file(path, &document).map_err(|e| CliError::User(e.to_string()))?;
            report.push((path.clone(), changed));
        }
        if output_mode(cli) == OutputMode::Json {
            let payload = json!({
                "command": "docs",
                "rendered": report.iter().map(|(path, sections)| json!({ "path": path, "changed": sections })).collect::<Vec<_>>(),
            });
            write_json_line(&payload)?;
        } else {
            for (path, changed) in &report {
                if changed.is_empty() {
                    println!("docs: {} already matched the code", path.display());
                } else {
                    println!(
                        "docs: {} rewritten ({})",
                        path.display(),
                        changed.join(", ")
                    );
                }
            }
        }
        return Ok(());
    }

    if let Some(section) = args.section.as_deref() {
        let markdown = document.render_section(section).ok_or_else(|| {
            CliError::User(format!(
                "unknown docs section {section:?}; this build renders: {}",
                document.section_names().join(", ")
            ))
        })?;
        print!("{markdown}");
        return Ok(());
    }

    write_json_line(&document.to_json())
}

fn run_metrics(cli: &Cli) -> Result<(), CliError> {
    use storage_ballast_helper::daemon::metrics::metrics_file_path;

    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;
    let path = metrics_file_path(&config.paths.state_file);
    let text = std::fs::read_to_string(&path).map_err(|e| {
        CliError::User(format!(
            "no metrics export at {}: {e} (the daemon writes it with every state write while [telemetry] metrics_enabled = true)",
            path.display()
        ))
    })?;
    if output_mode(cli) == OutputMode::Json {
        let payload = json!({
            "command": "metrics",
            "path": path,
            "text": text,
        });
        write_json_line(&payload)?;
    } else {
        print!("{text}");
    }
    Ok(())
}

fn install_requests_service(args: &InstallArgs) -> bool {
    args.systemd
        || args.launchd
        || args.user
        || args.scope.is_some()
        || args.auto
        || args.wizard
        || !args.from_source
}

fn service_kind_name(kind: ServiceKind) -> &'static str {
    match kind {
        ServiceKind::Systemd => "systemd",
        ServiceKind::Launchd => "launchd",
        ServiceKind::None => "none",
    }
}

fn running_as_root() -> bool {
    #[cfg(unix)]
    {
        nix::unistd::geteuid().is_root()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }

    if value.chars().all(|ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-' | ':' | '@' | '%' | '+')
    }) {
        return value.to_string();
    }

    format!("'{}'", value.replace('\'', "'\\''"))
}

fn env_value(name: &str) -> Option<String> {
    std::env::var_os(name)
        .map(|value| value.to_string_lossy().into_owned())
        .filter(|value| !value.is_empty())
}

fn launchd_uninstall_plist_paths(
    home: &Path,
    configured_label: Option<&str>,
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let labels = launchd_labels_for_discovery(configured_label);
    let system_paths = labels
        .iter()
        .map(|label| launchd_system_plist_path_for_label(label))
        .collect();
    let user_paths = labels
        .iter()
        .map(|label| launchd_user_plist_path_for_label(home, label))
        .collect();
    (system_paths, user_paths)
}

fn paths_exist(paths: &[PathBuf]) -> bool {
    paths.iter().any(|path| path.exists())
}

fn push_sudo_env(envs: &mut Vec<(&'static str, String)>, name: &'static str, value: String) {
    if !envs.iter().any(|(existing, _)| *existing == name) {
        envs.push((name, value));
    }
}

fn sudo_env_assignments(cli: &Cli, kind: ServiceKind) -> Vec<(&'static str, String)> {
    let mut envs = Vec::new();

    if kind == ServiceKind::Launchd
        && let Some(home) = env_value("HOME")
    {
        push_sudo_env(&mut envs, "HOME", home);
    }
    if kind == ServiceKind::Launchd
        && let Some(label) = env_value(LAUNCHD_LABEL_ENV)
    {
        push_sudo_env(&mut envs, LAUNCHD_LABEL_ENV, label);
    }

    if let Some(config) = &cli.config {
        let config_path = config.to_string_lossy().into_owned();
        push_sudo_env(&mut envs, "SBH_CONFIG", config_path.clone());
        push_sudo_env(&mut envs, "SBH_CONFIG_PATH", config_path);
    } else {
        if let Some(config) = env_value("SBH_CONFIG") {
            push_sudo_env(&mut envs, "SBH_CONFIG", config);
        }
        if let Some(config_path) = env_value("SBH_CONFIG_PATH") {
            push_sudo_env(&mut envs, "SBH_CONFIG_PATH", config_path);
        }
    }

    if let Some(rust_log) = env_value("RUST_LOG") {
        push_sudo_env(&mut envs, "RUST_LOG", rust_log);
    }

    envs
}

fn format_sudo_rerun_command_from_args(cli: &Cli, kind: ServiceKind, argv: &[String]) -> String {
    let mut parts = vec!["sudo".to_string()];
    let envs = sudo_env_assignments(cli, kind);

    if !envs.is_empty() {
        parts.push("env".to_string());
        for (name, value) in envs {
            parts.push(format!("{name}={}", shell_quote(&value)));
        }
    }

    if argv.is_empty() {
        parts.push("sbh".to_string());
    } else {
        parts.extend(argv.iter().map(|arg| shell_quote(arg)));
    }

    parts.join(" ")
}

fn format_sudo_rerun_command(cli: &Cli, kind: ServiceKind) -> String {
    let argv: Vec<String> = std::env::args_os()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    format_sudo_rerun_command_from_args(cli, kind, &argv)
}

fn service_system_scope_root_message(
    action: &str,
    kind: ServiceKind,
    sudo_command: &str,
) -> String {
    let service_name = service_kind_name(kind);
    let user_scope_hint = match action {
        "install" => "For a user service instead, run `sbh install --scope user` without sudo.",
        "uninstall" => "For a user service instead, run `sbh uninstall --scope user` without sudo.",
        _ => "For user-scope service work, pass `--scope user` without sudo.",
    };

    format!(
        "Error: system-scope {service_name} {action} requires root.\nRun:\n  {sudo_command}\n{user_scope_hint}"
    )
}

fn resolve_install_service(
    args: &InstallArgs,
    detected_kind: ServiceKind,
    is_root: bool,
    sudo_command: &str,
) -> Result<Option<ResolvedInstallService>, CliError> {
    if !install_requests_service(args) {
        return Ok(None);
    }

    if args.systemd && detected_kind != ServiceKind::Systemd {
        return Err(CliError::User(format!(
            "Error: --systemd is only supported on Linux/systemd hosts. Detected {} on this platform; omit the service flag for auto-detection.",
            service_kind_name(detected_kind)
        )));
    }
    if args.launchd && detected_kind != ServiceKind::Launchd {
        return Err(CliError::User(format!(
            "Error: --launchd is only supported on macOS/launchd hosts. Detected {} on this platform; omit the service flag for auto-detection.",
            service_kind_name(detected_kind)
        )));
    }

    let kind = if args.systemd {
        ServiceKind::Systemd
    } else if args.launchd {
        ServiceKind::Launchd
    } else {
        detected_kind
    };

    if kind == ServiceKind::None {
        return Err(CliError::User(
            "automatic service installation is not supported on this platform".to_string(),
        ));
    }

    let user_scope = match args.scope {
        Some(InstallScopeArg::User) => true,
        Some(InstallScopeArg::System) => false,
        None if args.user || args.auto || args.wizard => true,
        None => kind == ServiceKind::Launchd,
    };

    if !user_scope && !is_root {
        return Err(CliError::User(service_system_scope_root_message(
            "install",
            kind,
            sudo_command,
        )));
    }

    Ok(Some(ResolvedInstallService { kind, user_scope }))
}

fn resolve_wizard_install_service(
    answers: &storage_ballast_helper::cli::wizard::WizardAnswers,
    detected_kind: ServiceKind,
    is_root: bool,
    sudo_command: &str,
) -> Result<Option<ResolvedInstallService>, CliError> {
    use storage_ballast_helper::cli::wizard::ServiceChoice;

    let kind = match answers.service {
        ServiceChoice::Systemd => ServiceKind::Systemd,
        ServiceChoice::Launchd => ServiceKind::Launchd,
        ServiceChoice::None => return Ok(None),
    };

    if kind != detected_kind {
        return Err(CliError::User(format!(
            "Error: wizard selected {}, but this platform uses {}. Rerun the wizard and choose the detected service backend.",
            service_kind_name(kind),
            service_kind_name(detected_kind)
        )));
    }

    if !answers.user_scope && !is_root {
        return Err(CliError::User(service_system_scope_root_message(
            "install",
            kind,
            sudo_command,
        )));
    }

    Ok(Some(ResolvedInstallService {
        kind,
        user_scope: answers.user_scope,
    }))
}

fn apply_resolved_service_to_wizard_answers(
    answers: &mut storage_ballast_helper::cli::wizard::WizardAnswers,
    service: Option<ResolvedInstallService>,
) {
    use storage_ballast_helper::cli::wizard::ServiceChoice;

    if let Some(service) = service {
        answers.service = ServiceChoice::from_service_kind(service.kind);
        answers.user_scope = service.user_scope;
    } else {
        answers.service = ServiceChoice::None;
    }
}

fn run_install_auto_dry_run_json(cli: &Cli, args: &InstallArgs) -> Result<(), CliError> {
    use storage_ballast_helper::cli::install::{InstallOptions, run_install_sequence_with_bundle};
    use storage_ballast_helper::cli::update::run_update_sequence;
    use storage_ballast_helper::cli::wizard::{WizardSummary, auto_answers_for_platform};

    let platform = detect_platform().map_err(|e| CliError::Runtime(e.to_string()))?;
    let service_kind = platform.service_kind();
    let sudo_command = format_sudo_rerun_command(cli, service_kind);
    let service = resolve_install_service(args, service_kind, running_as_root(), &sudo_command)?;

    let mut answers = auto_answers_for_platform(platform.as_ref());
    apply_resolved_service_to_wizard_answers(&mut answers, service);
    let config = answers.to_config();
    let summary = WizardSummary {
        config_path: config.paths.config_file.clone(),
        config_written: false,
        answers,
        warnings: vec![],
    };

    let release_install = if service_kind == ServiceKind::Launchd && !args.from_source {
        let opts = build_macos_release_install_options(args, &config, service);
        let report = run_update_sequence(&opts);
        let install_path = report.install_path.clone();
        let validation = validate_macos_release_install_report(args, &report, install_path);
        Some((report, validation))
    } else {
        None
    };

    let auto_answers = &summary.answers;
    let install_report = run_install_sequence_with_bundle(
        &InstallOptions {
            config,
            ballast_count: auto_answers.ballast_file_count,
            ballast_size_bytes: auto_answers.ballast_file_size_bytes,
            ballast_path: args.ballast_path.clone(),
            dry_run: true,
        },
        args.offline.as_deref(),
    );

    let release_success = release_install
        .as_ref()
        .is_none_or(|(report, validation)| report.success && validation.is_ok());
    let success = release_success && install_report.success;
    let release_error = release_install
        .as_ref()
        .and_then(|(_, validation)| validation.as_ref().err())
        .map(ToString::to_string);
    let release_report = release_install.as_ref().map(|(report, _)| report);
    let payload = build_install_auto_dry_run_json_payload(
        args,
        service,
        &summary,
        release_report,
        release_error.as_deref(),
        &install_report,
        success,
    )?;
    write_json_line(&payload)?;

    if success {
        Ok(())
    } else {
        Err(CliError::Runtime("install dry-run failed".to_string()))
    }
}

fn build_install_auto_dry_run_json_payload(
    args: &InstallArgs,
    service: Option<ResolvedInstallService>,
    summary: &storage_ballast_helper::cli::wizard::WizardSummary,
    release_report: Option<&UpdateReport>,
    release_error: Option<&str>,
    install_report: &storage_ballast_helper::cli::install::InstallReport,
    success: bool,
) -> std::result::Result<Value, serde_json::Error> {
    let release_payload = release_report.map(serde_json::to_value).transpose()?;

    Ok(json!({
        "command": "install",
        "dry_run": true,
        "auto": true,
        "from_source": args.from_source,
        "service": service.map(|service| {
            json!({
                "kind": service_kind_name(service.kind),
                "scope": service.scope_name(),
            })
        }),
        "wizard": summary,
        "release_install": release_payload,
        "release_error": release_error,
        "install": install_report,
        "success": success,
    }))
}

fn resolve_uninstall_kind(
    args: &UninstallArgs,
    detected_kind: ServiceKind,
) -> Result<ServiceKind, CliError> {
    if args.systemd && detected_kind != ServiceKind::Systemd {
        return Err(CliError::User(format!(
            "Error: --systemd is only supported on Linux/systemd hosts. Detected {} on this platform; omit the service flag for auto-detection.",
            service_kind_name(detected_kind)
        )));
    }
    if args.launchd && detected_kind != ServiceKind::Launchd {
        return Err(CliError::User(format!(
            "Error: --launchd is only supported on macOS/launchd hosts. Detected {} on this platform; omit the service flag for auto-detection.",
            service_kind_name(detected_kind)
        )));
    }

    let kind = if args.systemd {
        ServiceKind::Systemd
    } else if args.launchd {
        ServiceKind::Launchd
    } else {
        detected_kind
    };

    if kind == ServiceKind::None {
        return Err(CliError::User(
            "automatic service uninstall is not supported on this platform".to_string(),
        ));
    }

    Ok(kind)
}

fn macos_install_dir_for_service(service: Option<ResolvedInstallService>) -> PathBuf {
    if service.is_some_and(|service| !service.user_scope) {
        return PathBuf::from("/usr/local/bin");
    }

    std::env::var_os("HOME").map_or_else(
        || PathBuf::from("/usr/local/bin"),
        |home| PathBuf::from(home).join(".local/bin"),
    )
}

fn install_default_paths_for_service(service: Option<ResolvedInstallService>) -> PathsConfig {
    service.map_or_else(PathsConfig::default, |service| {
        PathsConfig::for_service_scope(service.user_scope)
    })
}

fn load_install_config(cli: &Cli, service: Option<ResolvedInstallService>) -> Config {
    let default_paths = install_default_paths_for_service(service);
    let loaded = service.map_or_else(
        || Config::load(cli.config.as_deref()),
        |service| Config::load_for_service_scope(cli.config.as_deref(), service.user_scope),
    );

    loaded.unwrap_or_else(|_| Config::with_paths(default_paths))
}

fn build_macos_release_install_options(
    args: &InstallArgs,
    config: &Config,
    service: Option<ResolvedInstallService>,
) -> storage_ballast_helper::cli::update::UpdateOptions {
    storage_ballast_helper::cli::update::UpdateOptions {
        check_only: false,
        pinned_version: None,
        force: true,
        install_dir: macos_install_dir_for_service(service),
        no_verify: args.no_verify,
        dry_run: args.dry_run,
        max_backups: 5,
        metadata_cache_file: config.update.metadata_cache_file.clone(),
        metadata_cache_ttl: std::time::Duration::from_secs(
            config.update.metadata_cache_ttl_seconds,
        ),
        refresh_cache: false,
        notices_enabled: config.update.notices_enabled,
        offline_bundle_manifest: args.offline.clone(),
    }
}

fn run_macos_release_binary_install(
    cli: &Cli,
    args: &InstallArgs,
    config: &Config,
    service: Option<ResolvedInstallService>,
) -> Result<Option<PathBuf>, CliError> {
    use storage_ballast_helper::cli::update::{format_update_report, run_update_sequence};

    let opts = build_macos_release_install_options(args, config, service);
    let report = run_update_sequence(&opts);
    let install_path = report.install_path.clone();

    match output_mode(cli) {
        OutputMode::Human => {
            print!("{}", format_update_report(&report));
        }
        OutputMode::Json => {
            let payload = serde_json::to_value(&report)?;
            write_json_line(&payload)?;
        }
    }

    validate_macos_release_install_report(args, &report, install_path)
}

fn validate_macos_release_install_report(
    args: &InstallArgs,
    report: &UpdateReport,
    install_path: Option<PathBuf>,
) -> Result<Option<PathBuf>, CliError> {
    if !report.success {
        return Err(CliError::Runtime(
            "macOS release binary install failed".to_string(),
        ));
    }

    if !args.dry_run && install_path.is_none() {
        return Err(CliError::Runtime(
            "macOS release binary install did not produce an installed binary path; latest published release may be older than the running binary. Re-run with --from-source or install from a published release artifact.".to_string(),
        ));
    }

    Ok(install_path)
}

fn resolve_service_control(
    args: &ServiceArgs,
    detected_kind: ServiceKind,
) -> Result<ResolvedServiceControl, CliError> {
    if args.systemd && detected_kind != ServiceKind::Systemd {
        return Err(CliError::User(format!(
            "Error: --systemd is only supported on Linux/systemd hosts. Detected {} on this platform; omit the service flag for auto-detection.",
            service_kind_name(detected_kind)
        )));
    }
    if args.launchd && detected_kind != ServiceKind::Launchd {
        return Err(CliError::User(format!(
            "Error: --launchd is only supported on macOS/launchd hosts. Detected {} on this platform; omit the service flag for auto-detection.",
            service_kind_name(detected_kind)
        )));
    }

    let kind = if args.systemd {
        ServiceKind::Systemd
    } else if args.launchd {
        ServiceKind::Launchd
    } else {
        detected_kind
    };
    if kind == ServiceKind::None {
        return Err(CliError::User(
            "service controls are not supported on this platform".to_string(),
        ));
    }

    let user_scope = match args.scope {
        Some(InstallScopeArg::User) => true,
        Some(InstallScopeArg::System) => false,
        None if args.user => true,
        None => kind == ServiceKind::Launchd,
    };

    Ok(ResolvedServiceControl { kind, user_scope })
}

fn resolve_update_service_control(
    args: &UpdateArgs,
    detected_kind: ServiceKind,
) -> Option<ResolvedServiceControl> {
    if detected_kind == ServiceKind::None {
        return None;
    }

    let user_scope = if args.user {
        true
    } else if args.system {
        false
    } else {
        detected_kind == ServiceKind::Launchd
    };

    Some(ResolvedServiceControl {
        kind: detected_kind,
        user_scope,
    })
}

fn ensure_privileged_service_action(
    cli: &Cli,
    service: ResolvedServiceControl,
    action: &str,
) -> Result<(), CliError> {
    if service.user_scope || running_as_root() {
        return Ok(());
    }
    Err(CliError::User(service_system_scope_root_message(
        action,
        service.kind,
        &format_sudo_rerun_command(cli, service.kind),
    )))
}

fn resolve_uninstall_user_scope(
    args: &UninstallArgs,
    system_artifact_exists: bool,
    user_artifact_exists: bool,
    absent_default_user_scope: bool,
) -> bool {
    match args.scope {
        Some(InstallScopeArg::User) => true,
        Some(InstallScopeArg::System) => false,
        None if args.user => true,
        None if system_artifact_exists => false,
        None if user_artifact_exists => true,
        None => absent_default_user_scope,
    }
}

/// Best-effort kernel-writeback tuning during install.
///
/// Host-level (not service-specific) and never fatal: a failure here must not
/// fail an otherwise-successful install. When run as root it applies + persists
/// the bandwidth-scaled limits; otherwise it prints a hint to run
/// `sudo sbh tune --apply --yes`. The daemon never applies these at runtime.
fn maybe_apply_writeback_on_install(cli: &Cli, config: &Config) {
    let cfg = &config.system_tuning;
    if !cfg.writeback_enabled || !cfg.writeback_auto_apply_on_install {
        return;
    }
    let Ok(platform) = detect_platform() else {
        return;
    };
    let is_root = running_as_root();
    // Benchmark only when we can actually apply (root); otherwise heuristic.
    let Some(tuning) = build_writeback_tuning(config, platform.as_ref(), is_root) else {
        return; // disabled, not applicable on this platform, or already healthy
    };
    let human = output_mode(cli) == OutputMode::Human;

    if is_root {
        match apply_writeback_tuning(config, platform.as_ref(), &tuning.plan) {
            Ok(report) => {
                if human {
                    println!(
                        "Applied kernel writeback tuning: vm.dirty_bytes={}, \
                         vm.dirty_background_bytes={}.",
                        tuning.plan.dirty_bytes, tuning.plan.dirty_background_bytes,
                    );
                    println!("  persisted: {}", report.sysctl_path.display());
                    if let Some(backup) = &report.backup {
                        println!("  backup: {}", backup.display());
                    }
                    for conflict in &report.conflicts {
                        println!("  warning: {}", writeback_conflict_note(conflict));
                    }
                } else {
                    let _ = write_json_line(&json!({
                        "command": "install",
                        "step": "writeback_tuning",
                        "applied": true,
                        "vm.dirty_bytes": tuning.plan.dirty_bytes,
                        "vm.dirty_background_bytes": tuning.plan.dirty_background_bytes,
                        "sysctl_path": report.sysctl_path.to_string_lossy(),
                    }));
                }
            }
            Err(e) if human => {
                eprintln!("Note: could not apply kernel writeback tuning: {e}");
            }
            Err(_) => {}
        }
    } else if human {
        println!(
            "Recommended kernel writeback tuning (vm.dirty_bytes≈{}); run \
             `sudo sbh tune --apply --yes` to apply.",
            storage_ballast_helper::tuning::writeback::human_bytes(tuning.plan.dirty_bytes),
        );
    }
}

#[allow(clippy::too_many_lines)]
fn run_install(cli: &Cli, args: &InstallArgs) -> Result<(), CliError> {
    if args.auto && args.dry_run && output_mode(cli) == OutputMode::Json {
        return run_install_auto_dry_run_json(cli, args);
    }

    // -- early platform gates -------------------------------------------------
    // Validate service flags against the current platform BEFORE any expensive
    // work (config loading, ballast provisioning, from-source builds).
    let platform = detect_platform().map_err(|e| CliError::Runtime(e.to_string()))?;
    let service_kind = platform.service_kind();
    let sudo_command = format_sudo_rerun_command(cli, service_kind);
    let mut service =
        resolve_install_service(args, service_kind, running_as_root(), &sudo_command)?;
    let guided_install = if args.wizard {
        use storage_ballast_helper::cli::wizard::{
            WizardSummary, format_summary, run_interactive_for_platform, write_config,
        };

        let stdin = io::stdin();
        let mut reader = stdin.lock();
        let mut writer = io::stderr();
        let answers = run_interactive_for_platform(&mut reader, &mut writer, platform.as_ref())
            .map_err(|e| CliError::User(format!("wizard cancelled: {e}")))?;
        drop(reader);

        service = resolve_wizard_install_service(
            &answers,
            service_kind,
            running_as_root(),
            &sudo_command,
        )?;
        let config = answers.to_config();
        let config_path = config.paths.config_file.clone();
        let config_written = if args.dry_run {
            config_path
        } else {
            write_config(&answers, &config_path)
                .map_err(|e| CliError::Runtime(format!("failed to write config: {e}")))?
        };
        let summary = WizardSummary {
            answers,
            config_path: config_written,
            config_written: !args.dry_run,
            warnings: vec![],
        };

        match output_mode(cli) {
            OutputMode::Human => {
                print!("{}", format_summary(&summary));
            }
            OutputMode::Json => {
                let payload = serde_json::to_value(&summary)?;
                write_json_line(&payload)?;
            }
        }

        Some((summary, config))
    } else if args.auto {
        use storage_ballast_helper::cli::wizard::{
            WizardSummary, auto_answers_for_platform, format_summary, write_config,
        };

        let mut answers = auto_answers_for_platform(platform.as_ref());
        apply_resolved_service_to_wizard_answers(&mut answers, service);
        let config = answers.to_config();
        let config_path = config.paths.config_file.clone();
        let config_written = if args.dry_run {
            config_path
        } else {
            write_config(&answers, &config_path)
                .map_err(|e| CliError::Runtime(format!("failed to write config: {e}")))?
        };
        let summary = WizardSummary {
            answers,
            config_path: config_written,
            config_written: !args.dry_run,
            warnings: vec![],
        };

        match output_mode(cli) {
            OutputMode::Human => {
                print!("{}", format_summary(&summary));
            }
            OutputMode::Json => {
                let payload = serde_json::to_value(&summary)?;
                write_json_line(&payload)?;
            }
        }

        Some((summary, config))
    } else {
        None
    };
    let config = guided_install.as_ref().map_or_else(
        || load_install_config(cli, service),
        |(_, config)| config.clone(),
    );
    let mut installed_binary_path = if service_kind == ServiceKind::Launchd && !args.from_source {
        run_macos_release_binary_install(cli, args, &config, service)?
    } else {
        None
    };

    // -- from-source build ----------------------------------------------------
    if args.from_source {
        use storage_ballast_helper::cli::from_source::{
            self, SourceCheckout, SourceInstallConfig, all_prerequisites_met,
            format_prerequisite_failures, format_result_human,
        };

        let checkout = args.tag.as_ref().map_or(SourceCheckout::Head, |tag| {
            let normalized = if tag.starts_with('v') {
                tag.clone()
            } else {
                format!("v{tag}")
            };
            SourceCheckout::Tag(normalized)
        });

        let config = SourceInstallConfig::new(checkout, args.prefix.clone());

        // Pre-flight prerequisite check with early exit and remediation.
        let prereqs = from_source::check_prerequisites();
        if !all_prerequisites_met(&prereqs) {
            match output_mode(cli) {
                OutputMode::Human => {
                    eprint!("{}", format_prerequisite_failures(&prereqs));
                }
                OutputMode::Json => {
                    let payload = serde_json::to_value(&prereqs)?;
                    write_json_line(&payload)?;
                }
            }
            return Err(CliError::User(
                "missing prerequisites for --from-source build".to_string(),
            ));
        }

        let result = from_source::install_from_source(&config);

        match output_mode(cli) {
            OutputMode::Human => {
                print!("{}", format_result_human(&result));
            }
            OutputMode::Json => {
                let payload = serde_json::to_value(&result)?;
                write_json_line(&payload)?;
            }
        }

        if !result.success {
            return Err(CliError::Runtime(
                result
                    .error
                    .unwrap_or_else(|| "from-source build failed".to_string()),
            ));
        }
        if let Some(binary_path) = result.binary_path {
            installed_binary_path = Some(binary_path);
        }

        // From-source-only installs stop after the binary install. Passing a
        // service flag or scope asks for service registration after the build.
        if service.is_none() {
            return Ok(());
        }
        // Otherwise, fall through to service installation below.
    }

    // -- install orchestration (data dir, config, ballast) ----------------------
    {
        use storage_ballast_helper::cli::install::{
            InstallOptions, format_install_report, run_install_sequence_with_bundle,
        };

        let auto_answers = guided_install.as_ref().map(|(summary, _)| &summary.answers);
        let ballast_count =
            auto_answers.map_or(args.ballast_count, |answers| answers.ballast_file_count);
        let ballast_size_bytes = if let Some(answers) = auto_answers {
            answers.ballast_file_size_bytes
        } else {
            args.ballast_size.checked_mul(1024 * 1024).ok_or_else(|| {
                CliError::User(format!(
                    "ballast size {} MB overflows u64 when converted to bytes",
                    args.ballast_size
                ))
            })?
        };

        let opts = InstallOptions {
            config: config.clone(),
            ballast_count,
            ballast_size_bytes,
            ballast_path: args.ballast_path.clone(),
            dry_run: args.dry_run,
        };

        let report = run_install_sequence_with_bundle(&opts, args.offline.as_deref());

        match output_mode(cli) {
            OutputMode::Human => {
                print!("{}", format_install_report(&report));
            }
            OutputMode::Json => {
                let payload = serde_json::to_value(&report)?;
                write_json_line(&payload)?;
            }
        }

        if !report.success {
            return Err(CliError::Runtime(
                "install orchestration failed".to_string(),
            ));
        }

        if args.dry_run {
            return Ok(());
        }
    }

    // -- install-time bootstrap repairs (safe subset, backups first) ----------
    run_install_bootstrap(cli, args);

    // -- host-level kernel writeback tuning (best-effort, host-wide) -----------
    maybe_apply_writeback_on_install(cli, &config);

    // -- service registration -------------------------------------------------
    let Some(service) = service else {
        // No service registration requested; orchestration-only install is done.
        return Ok(());
    };

    if service.kind == ServiceKind::Launchd {
        let mut launchd_config = LaunchdConfig::from_env(service.user_scope)
            .map_err(|e| CliError::Runtime(e.to_string()))?;
        if let Some(binary_path) = installed_binary_path.clone() {
            launchd_config.binary_path = binary_path;
        }
        launchd_config
            .config_path
            .clone_from(&config.paths.config_file);
        launchd_config.working_directory = config
            .paths
            .state_file
            .parent()
            .map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
        let mgr = LaunchdServiceManager::new(launchd_config);
        let plist_path = mgr.config().plist_path();
        let scope = service.scope_name();

        match mgr.install() {
            Ok(()) => {
                let result = ServiceActionResult {
                    action: "install",
                    service_type: "launchd",
                    scope,
                    unit_path: plist_path.clone(),
                    success: true,
                    error: None,
                };

                match output_mode(cli) {
                    OutputMode::Human => {
                        println!("Installed launchd service ({scope} scope).");
                        println!("  Plist: {}", plist_path.display());
                        println!("  Service loaded. Check with:");
                        println!("    launchctl list | grep sbh");
                    }
                    OutputMode::Json => {
                        let payload = serde_json::to_value(&result)?;
                        write_json_line(&payload)?;
                    }
                }
                return Ok(());
            }
            Err(e) => {
                let result = ServiceActionResult {
                    action: "install",
                    service_type: "launchd",
                    scope,
                    unit_path: plist_path,
                    success: false,
                    error: Some(e.to_string()),
                };

                match output_mode(cli) {
                    OutputMode::Human => {
                        eprintln!("Failed to install launchd service: {e}");
                    }
                    OutputMode::Json => {
                        let payload = serde_json::to_value(&result)?;
                        write_json_line(&payload)?;
                    }
                }
                return Err(CliError::Runtime(format!("install failed: {e}")));
            }
        }
    }

    // -- systemd install --------------------------------------------------
    // The sandbox (`ProtectSystem=strict` + `ReadWritePaths=`) is derived from
    // the config the service will run with: scan roots, special locations,
    // every ballast dir, and the daemon's own data/config/log directories.
    let mut systemd_config = storage_ballast_helper::daemon::service::SystemdConfig::from_config(
        &config,
        service.user_scope,
    )
    .map_err(|e| CliError::Runtime(e.to_string()))?;
    if let Some(binary_path) = installed_binary_path {
        systemd_config.binary_path = binary_path;
    }

    let mgr = SystemdServiceManager::new(systemd_config);
    let unit_path = mgr.config().unit_path();
    let scope = service.scope_name();

    match mgr.install() {
        Ok(()) => {
            let result = ServiceActionResult {
                action: "install",
                service_type: "systemd",
                scope,
                unit_path: unit_path.clone(),
                success: true,
                error: None,
            };

            match output_mode(cli) {
                OutputMode::Human => {
                    println!("Installed systemd service ({scope} scope).");
                    println!("  Unit file: {}", unit_path.display());
                    println!("  Service enabled. Start with:");
                    if service.user_scope {
                        println!("    systemctl --user start sbh.service");
                    } else {
                        println!("    sudo systemctl start sbh.service");
                    }
                }
                OutputMode::Json => {
                    let payload = serde_json::to_value(&result)?;
                    write_json_line(&payload)?;
                }
            }
            Ok(())
        }
        Err(e) => {
            let result = ServiceActionResult {
                action: "install",
                service_type: "systemd",
                scope,
                unit_path,
                success: false,
                error: Some(e.to_string()),
            };

            match output_mode(cli) {
                OutputMode::Human => {
                    eprintln!("Failed to install systemd service: {e}");
                }
                OutputMode::Json => {
                    let payload = serde_json::to_value(&result)?;
                    write_json_line(&payload)?;
                }
            }
            Err(CliError::Runtime(format!("install failed: {e}")))
        }
    }
}

#[allow(clippy::too_many_lines)]
/// The service registration `sbh uninstall` is about to remove, resolved to
/// a scope before anything is touched so the cleanup plan can be shown (and
/// confirmed) first.
enum UninstallServiceTarget {
    Launchd(LaunchdServiceManager),
    Systemd(SystemdServiceManager),
}

impl UninstallServiceTarget {
    fn service_type(&self) -> &'static str {
        match self {
            Self::Launchd(_) => "launchd",
            Self::Systemd(_) => "systemd",
        }
    }

    fn user_scope(&self) -> bool {
        match self {
            Self::Launchd(mgr) => mgr.config().user_scope,
            Self::Systemd(mgr) => mgr.config().user_scope,
        }
    }

    fn scope(&self) -> &'static str {
        if self.user_scope() { "user" } else { "system" }
    }

    fn unit_path(&self) -> PathBuf {
        match self {
            Self::Launchd(mgr) => mgr.config().plist_path(),
            Self::Systemd(mgr) => mgr.config().unit_path(),
        }
    }

    fn uninstall(&self) -> storage_ballast_helper::core::errors::Result<()> {
        match self {
            Self::Launchd(mgr) => mgr.uninstall(),
            Self::Systemd(mgr) => mgr.uninstall(),
        }
    }
}

/// Resolve which service registration (kind + scope) to remove. System scope
/// needs root unless this is a dry run, which only prints a plan.
fn resolve_uninstall_target(
    cli: &Cli,
    args: &UninstallArgs,
    service_kind: ServiceKind,
) -> Result<UninstallServiceTarget, CliError> {
    let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
    if service_kind == ServiceKind::Launchd {
        // Check system plists first, then user agents. Include both the
        // production label and a configured CI/test label.
        let (system_plists, user_plists) =
            launchd_uninstall_plist_paths(&home, env_value(LAUNCHD_LABEL_ENV).as_deref());
        let launchd_user = resolve_uninstall_user_scope(
            args,
            paths_exist(&system_plists),
            paths_exist(&user_plists),
            true,
        );
        if !launchd_user && !running_as_root() && !args.dry_run {
            return Err(CliError::User(service_system_scope_root_message(
                "uninstall",
                ServiceKind::Launchd,
                &format_sudo_rerun_command(cli, ServiceKind::Launchd),
            )));
        }
        let mgr = LaunchdServiceManager::from_env(launchd_user)
            .map_err(|e| CliError::Runtime(e.to_string()))?;
        return Ok(UninstallServiceTarget::Launchd(mgr));
    }

    // systemd: system scope is the default unless only a user unit exists.
    let system_path = PathBuf::from("/etc/systemd/system/sbh.service");
    let user_path = home.join(".config/systemd/user/sbh.service");
    let user_scope =
        resolve_uninstall_user_scope(args, system_path.exists(), user_path.exists(), false);
    if !user_scope && !running_as_root() && !args.dry_run {
        return Err(CliError::User(service_system_scope_root_message(
            "uninstall",
            ServiceKind::Systemd,
            &format_sudo_rerun_command(cli, ServiceKind::Systemd),
        )));
    }
    let mgr = SystemdServiceManager::from_env(user_scope)
        .map_err(|e| CliError::Runtime(e.to_string()))?;
    Ok(UninstallServiceTarget::Systemd(mgr))
}

/// Paths of the install being removed: the loaded config's `[paths]`, or the
/// scope defaults when no config can be read (already removed, or unreadable).
fn uninstall_paths_for(cli: &Cli, user_scope: bool) -> PathsConfig {
    Config::load(cli.config.as_deref()).map_or_else(
        |_| PathsConfig::for_service_scope(user_scope),
        |config| config.paths,
    )
}

/// Ask on the terminal before a data-removing uninstall. Anything but an
/// explicit `y`/`yes` aborts.
fn confirm_uninstall_on_tty(planned: usize, mode: impl std::fmt::Display) -> bool {
    print!("Proceed with `sbh uninstall --{mode}` ({planned} removal(s))? [y/N] ");
    let _ = io::stdout().flush();
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[allow(clippy::too_many_lines)]
fn run_uninstall(cli: &Cli, args: &UninstallArgs) -> Result<(), CliError> {
    use storage_ballast_helper::cli::uninstall::{
        CleanupMode, UninstallOptions, execute_uninstall, format_report_human, plan_uninstall,
    };

    let platform = detect_platform().map_err(|e| CliError::Runtime(e.to_string()))?;
    let service_kind = resolve_uninstall_kind(args, platform.service_kind())?;
    let target = resolve_uninstall_target(cli, args, service_kind)?;
    let mode = args.cleanup_mode();

    // 1. Plan the file cleanup for this scope before touching anything.
    let opts = UninstallOptions {
        mode,
        dry_run: args.dry_run,
        backup_dir: args.backup_dir.clone(),
        binary_path: None,
        paths: uninstall_paths_for(cli, target.user_scope()),
        user_scope: target.user_scope(),
        home: std::env::var_os("HOME").map(PathBuf::from),
    };
    let plan = plan_uninstall(&opts);

    // 2. Data-removing modes are confirmed before the service goes away:
    //    a prompt on a terminal, `--yes` otherwise.
    if !args.dry_run && mode != CleanupMode::Conservative && !args.yes {
        if !io::stdout().is_terminal() {
            if output_mode(cli) == OutputMode::Json {
                write_json_line(&json!({
                    "action": "uninstall",
                    "error": "non_interactive_without_yes",
                    "mode": mode.to_string(),
                    "planned_actions": plan.actions.len(),
                }))?;
            }
            return Err(CliError::User(format!(
                "`sbh uninstall --{mode}` removes data; pass --yes to confirm in non-interactive mode, or --dry-run to preview"
            )));
        }
        println!(
            "{} service ({} scope): {}",
            target.service_type(),
            target.scope(),
            target.unit_path().display()
        );
        for action in &plan.actions {
            println!("  [PLAN] {}: {}", action.category, action.path.display());
        }
        if !confirm_uninstall_on_tty(plan.actions.len(), mode) {
            return Err(CliError::User("uninstall aborted".to_string()));
        }
    }

    // 3. Service teardown (skipped on dry run), then file cleanup.
    let unit_path = target.unit_path();
    let unit_existed = unit_path.exists();
    let service_error = if args.dry_run {
        None
    } else {
        target.uninstall().err().map(|e| e.to_string())
    };
    let service_result = ServiceActionResult {
        action: "uninstall",
        service_type: target.service_type(),
        scope: target.scope(),
        unit_path: unit_path.clone(),
        success: service_error.is_none(),
        error: service_error.clone(),
    };
    let report = if args.dry_run || service_error.is_some() {
        plan
    } else {
        execute_uninstall(&opts)
    };

    // 4. One report: service result plus the cleanup plan/results.
    match output_mode(cli) {
        OutputMode::Human => {
            let scope = target.scope();
            let service_type = target.service_type();
            match (&service_error, args.dry_run) {
                (Some(e), _) => eprintln!("Failed to uninstall {service_type} service: {e}"),
                (None, true) => println!(
                    "Would uninstall {service_type} service ({scope} scope): {}",
                    unit_path.display()
                ),
                (None, false) => {
                    println!("Uninstalled {service_type} service ({scope} scope).");
                    if unit_existed {
                        println!("  Removed: {}", unit_path.display());
                    } else {
                        println!("  Already absent: {}", unit_path.display());
                    }
                }
            }
            println!();
            print!("{}", format_report_human(&report));
        }
        OutputMode::Json => {
            let mut payload = serde_json::to_value(&service_result)?;
            payload["dry_run"] = json!(args.dry_run);
            payload["cleanup"] = if service_error.is_some() {
                Value::Null
            } else {
                serde_json::to_value(&report)?
            };
            write_json_line(&payload)?;
        }
    }

    if let Some(e) = service_error {
        return Err(CliError::Runtime(format!("uninstall failed: {e}")));
    }
    if report.failed_count > 0 {
        return Err(CliError::Partial(format!(
            "{} of {} removal(s) failed; see the report above",
            report.failed_count,
            report.actions.len()
        )));
    }
    Ok(())
}

fn run_service(cli: &Cli, args: &ServiceArgs) -> Result<(), CliError> {
    let platform = detect_platform().map_err(|e| CliError::Runtime(e.to_string()))?;
    let service = resolve_service_control(args, platform.service_kind())?;

    match &args.command {
        ServiceCommand::Status => run_service_status(cli, service),
        ServiceCommand::Restart => run_service_restart(cli, service),
        ServiceCommand::Logs(logs_args) => run_service_logs(cli, service, logs_args),
        ServiceCommand::ReinstallUnit(reinstall) => {
            run_service_reinstall_unit(cli, service, reinstall)
        }
    }
}

/// `doctor --service`: the installed unit against what sbh generates.
fn service_doctor_checks(user_scope_requested: bool) -> Result<Vec<DoctorCheck>, CliError> {
    use storage_ballast_helper::daemon::service::SystemdServiceManager;

    let platform = detect_platform().map_err(|e| CliError::Runtime(e.to_string()))?;
    match platform.service_kind() {
        ServiceKind::Systemd => {}
        ServiceKind::Launchd => return Ok(launchd_doctor_checks(user_scope_requested)),
        ServiceKind::None => {
            return Ok(vec![doctor_check(
                "service-unit-present",
                "Service unit",
                "WARN",
                "no service manager on this platform; nothing to compare",
                None,
            )]);
        }
    }

    // The system unit is what runs on an installed host; fall back to the
    // user unit when only that exists, or when asked for it.
    let user_scope = if user_scope_requested {
        true
    } else {
        let system =
            SystemdServiceManager::from_env(false).map_err(|e| CliError::Runtime(e.to_string()))?;
        !system.config().unit_path().exists()
            && SystemdServiceManager::from_env(true)
                .is_ok_and(|user| user.config().unit_path().exists())
    };
    let manager = SystemdServiceManager::from_env(user_scope)
        .map_err(|e| CliError::Runtime(e.to_string()))?;
    let unit_path = manager.config().unit_path();
    let reinstall = if user_scope {
        "sbh service --systemd --user reinstall-unit".to_string()
    } else {
        "sudo sbh service --systemd reinstall-unit".to_string()
    };
    let install = if user_scope {
        "sbh install --user"
    } else {
        "sudo sbh install --scope system"
    };

    let drift = match manager.drift_report() {
        Ok(drift) => drift,
        Err(error) => {
            return Ok(vec![doctor_check(
                "service-unit-present",
                "Service unit",
                "FAIL",
                format!("no unit at {}: {error}", unit_path.display()),
                Some(install.to_string()),
            )]);
        }
    };

    Ok(unit_drift_checks(
        &drift,
        &unit_path,
        user_scope,
        &manager.config().binary_path,
        &reinstall,
    ))
}

/// The `doctor --service` checks for a computed drift: unit present,
/// hardening, binary, gates, then drop-ins and everything else.
fn unit_drift_checks(
    drift: &storage_ballast_helper::daemon::service::UnitDrift,
    unit_path: &Path,
    user_scope: bool,
    binary_path: &Path,
    reinstall: &str,
) -> Vec<DoctorCheck> {
    let mut checks = vec![doctor_check(
        "service-unit-present",
        "Service unit",
        "PASS",
        format!(
            "{} ({} scope)",
            unit_path.display(),
            if user_scope { "user" } else { "system" }
        ),
        None,
    )];

    let gaps = drift.hardening_gaps();
    checks.push(if gaps.is_empty() {
        doctor_check(
            "service-unit-hardening",
            "Hardening directives",
            "PASS",
            "process type, priority, sandbox and resource caps match the generated unit",
            None,
        )
    } else {
        doctor_check(
            "service-unit-hardening",
            "Hardening directives",
            "FAIL",
            format!("missing or changed: {}", gaps.join(", ")),
            Some(reinstall.to_string()),
        )
    });

    checks.push(if drift.exec_start_matches {
        doctor_check(
            "service-unit-execstart",
            "ExecStart binary",
            "PASS",
            "runs this sbh binary",
            None,
        )
    } else {
        doctor_check(
            "service-unit-execstart",
            "ExecStart binary",
            "FAIL",
            format!("runs a different binary than {}", binary_path.display()),
            Some(reinstall.to_string()),
        )
    });

    let blocking = drift.blocking_gates();
    checks.push(if !blocking.is_empty() {
        let gates: Vec<String> = blocking
            .iter()
            .map(|gate| format!("{} ({})", gate.directive, gate.source.display()))
            .collect();
        doctor_check(
            "service-unit-gates",
            "Condition gates",
            "FAIL",
            format!("the unit cannot start: {}", gates.join("; ")),
            Some(format!(
                "remove the gating path or the drop-in that sets it, or `{reinstall} --purge-dropins` to move every drop-in aside"
            )),
        )
    } else if drift.condition_gates.is_empty() {
        doctor_check("service-unit-gates", "Condition gates", "PASS", "none", None)
    } else {
        let gates: Vec<String> = drift
            .condition_gates
            .iter()
            .map(|gate| format!("{} ({})", gate.directive, gate.source.display()))
            .collect();
        doctor_check(
            "service-unit-gates",
            "Condition gates",
            "WARN",
            format!("present but currently passing: {}", gates.join("; ")),
            None,
        )
    });

    checks.extend(unit_drift_extra_checks(drift, reinstall));
    checks
}

/// Drop-ins and non-hardening differences: warnings, unless a drop-in
/// overrides a hardening directive.
fn unit_drift_extra_checks(
    drift: &storage_ballast_helper::daemon::service::UnitDrift,
    reinstall: &str,
) -> Vec<DoctorCheck> {
    let gaps = drift.hardening_gaps();
    let mut checks = Vec::new();
    checks.push(if drift.foreign_dropins.is_empty() {
        doctor_check("service-unit-dropins", "Drop-ins", "PASS", "none", None)
    } else {
        let listed: Vec<String> = drift
            .foreign_dropins
            .iter()
            .map(|d| format!("{} sets {}", d.path.display(), d.directives.join(", ")))
            .collect();
        let overrides = drift.foreign_dropins.iter().any(|d| d.overrides_hardening);
        doctor_check(
            "service-unit-dropins",
            "Drop-ins",
            if overrides { "FAIL" } else { "WARN" },
            format!(
                "{}{}",
                if overrides {
                    "a drop-in overrides a hardening directive: "
                } else {
                    "sbh did not write these: "
                },
                listed.join("; ")
            ),
            Some(format!("{reinstall} --purge-dropins")),
        )
    });

    let other: Vec<String> = drift
        .changed_directives
        .iter()
        .filter(|change| !change.hardening)
        .map(|change| {
            format!(
                "{} is {} (generated {})",
                change.directive,
                change.installed.join(" "),
                change.generated.join(" ")
            )
        })
        .chain(
            drift
                .missing_directives
                .iter()
                .filter(|d| !gaps.contains(d))
                .map(|d| format!("{d} missing")),
        )
        .chain(
            drift
                .extra_directives
                .iter()
                .map(|d| format!("{d} not generated by sbh")),
        )
        .collect();
    checks.push(if other.is_empty() {
        doctor_check(
            "service-unit-other",
            "Other directives",
            "PASS",
            "identical",
            None,
        )
    } else {
        doctor_check(
            "service-unit-other",
            "Other directives",
            "WARN",
            other.join("; "),
            Some(reinstall.to_string()),
        )
    });
    checks
}

/// `doctor --service` on macOS: the installed plist against the generated one.
fn launchd_doctor_checks(user_scope: bool) -> Vec<DoctorCheck> {
    let manager = match LaunchdServiceManager::from_env_for_control(user_scope) {
        Ok(manager) => manager,
        Err(error) => {
            return vec![doctor_check(
                "service-unit-present",
                "Launchd plist",
                "FAIL",
                format!("cannot resolve the launchd service: {error}"),
                None,
            )];
        }
    };
    let plist_path = manager.config().plist_path();
    let Ok(installed) = std::fs::read_to_string(&plist_path) else {
        return vec![doctor_check(
            "service-unit-present",
            "Launchd plist",
            "FAIL",
            format!("no plist at {}", plist_path.display()),
            Some(if user_scope {
                "sbh install --user".to_string()
            } else {
                "sudo sbh install --scope system".to_string()
            }),
        )];
    };
    let normalize = |text: &str| -> Vec<String> {
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToString::to_string)
            .collect()
    };
    let installed_lines = normalize(&installed);
    let generated_lines = normalize(&manager.generate_plist());
    let mut checks = vec![doctor_check(
        "service-unit-present",
        "Launchd plist",
        "PASS",
        plist_path.display().to_string(),
        None,
    )];
    checks.push(if installed_lines == generated_lines {
        doctor_check(
            "service-unit-hardening",
            "Plist contents",
            "PASS",
            "matches the generated plist",
            None,
        )
    } else {
        let differing = installed_lines
            .iter()
            .filter(|line| !generated_lines.contains(line))
            .count()
            + generated_lines
                .iter()
                .filter(|line| !installed_lines.contains(line))
                .count();
        doctor_check(
            "service-unit-hardening",
            "Plist contents",
            "WARN",
            format!("{differing} line(s) differ from the generated plist"),
            Some("sbh install (rewrites the plist)".to_string()),
        )
    });
    checks
}

fn run_service_reinstall_unit(
    cli: &Cli,
    service: ResolvedServiceControl,
    args: &ReinstallUnitArgs,
) -> Result<(), CliError> {
    if service.kind != ServiceKind::Systemd {
        return Err(CliError::User(
            "reinstall-unit rewrites a systemd unit; on launchd run `sbh install` to rewrite the plist"
                .to_string(),
        ));
    }
    ensure_privileged_service_action(cli, service, "reinstall-unit")?;
    let manager = SystemdServiceManager::from_env(service.user_scope)
        .map_err(|e| CliError::Runtime(e.to_string()))?;
    let before = manager.drift_report().ok().map(|drift| drift.severity());
    let report = manager
        .reinstall_unit(args.purge_dropins)
        .map_err(|e| CliError::Runtime(e.to_string()))?;
    let after = manager
        .drift_report()
        .map_err(|e| CliError::Runtime(e.to_string()))?;

    match output_mode(cli) {
        OutputMode::Json => write_json_line(&json!({
            "command": "service reinstall-unit",
            "scope": service.scope_name(),
            "unit_path": report.unit_path.to_string_lossy(),
            "backup_path": report.backup_path.as_ref().map(|p| p.to_string_lossy().to_string()),
            "changed": report.changed,
            "daemon_reloaded": report.daemon_reloaded,
            "dropins_kept": report.dropins_kept.iter().map(|p| p.to_string_lossy().to_string()).collect::<Vec<_>>(),
            "dropins_moved": report.dropins_moved.iter().map(|(from, to)| json!({ "from": from.to_string_lossy(), "to": to.to_string_lossy() })).collect::<Vec<_>>(),
            "drift_before": before,
            "drift_after": after.severity(),
            "remaining_gates": after.blocking_gates().iter().map(|g| format!("{} ({})", g.directive, g.source.display())).collect::<Vec<_>>(),
        }))?,
        OutputMode::Human => {
            println!(
                "{} {} ({} scope)",
                if report.changed {
                    "Rewrote"
                } else {
                    "Refreshed (unchanged)"
                },
                report.unit_path.display(),
                service.scope_name()
            );
            if let Some(backup) = &report.backup_path {
                println!("  backup: {}", backup.display());
            }
            for path in &report.dropins_kept {
                println!("  kept drop-in: {}", path.display());
            }
            for (from, to) in &report.dropins_moved {
                println!("  moved drop-in: {} -> {}", from.display(), to.display());
            }
            println!(
                "  daemon-reload: {}",
                if report.daemon_reloaded {
                    "done"
                } else {
                    "skipped"
                }
            );
            println!(
                "  drift: {} -> {}",
                before.map_or_else(
                    || "no unit".to_string(),
                    |s| format!("{s:?}").to_uppercase()
                ),
                format!("{:?}", after.severity()).to_uppercase()
            );
            for gate in after.blocking_gates() {
                println!(
                    "  still gated: {} ({})",
                    gate.directive,
                    gate.source.display()
                );
            }
            if !report.daemon_reloaded {
                println!("  run `systemctl daemon-reload` before restarting the service");
            }
        }
    }
    Ok(())
}

fn run_service_status(cli: &Cli, service: ResolvedServiceControl) -> Result<(), CliError> {
    match service.kind {
        ServiceKind::Launchd => {
            let manager = LaunchdServiceManager::from_env_for_control(service.user_scope)
                .map_err(|e| CliError::Runtime(e.to_string()))?;
            let report = manager
                .status_report()
                .map_err(|e| CliError::Runtime(e.to_string()))?;
            match output_mode(cli) {
                OutputMode::Human => print_launchd_status(&report),
                OutputMode::Json => {
                    let payload = serde_json::to_value(&report)?;
                    write_json_line(&payload)?;
                }
            }
            Ok(())
        }
        ServiceKind::Systemd => {
            let manager = SystemdServiceManager::from_env(service.user_scope)
                .map_err(|e| CliError::Runtime(e.to_string()))?;
            let status = manager
                .status()
                .map_err(|e| CliError::Runtime(e.to_string()))?;
            let logs_path = manager
                .logs_path()
                .map_err(|e| CliError::Runtime(e.to_string()))?;
            match output_mode(cli) {
                OutputMode::Human => {
                    println!("Service: systemd ({})", service.scope_name());
                    println!("Unit: sbh.service");
                    println!("Status: {status}");
                    if let Some(path) = logs_path {
                        println!("Logs: {}", path.display());
                    } else if service.user_scope {
                        println!("Logs: journalctl --user -u sbh.service");
                    } else {
                        println!("Logs: journalctl -u sbh.service");
                    }
                }
                OutputMode::Json => {
                    let payload = json!({
                        "service_type": "systemd",
                        "scope": service.scope_name(),
                        "unit": "sbh.service",
                        "status": status,
                        "logs_path": logs_path.map(|path| path.display().to_string()),
                    });
                    write_json_line(&payload)?;
                }
            }
            Ok(())
        }
        ServiceKind::None => Err(CliError::User(
            "service controls are not supported on this platform".to_string(),
        )),
    }
}

fn run_service_restart(cli: &Cli, service: ResolvedServiceControl) -> Result<(), CliError> {
    ensure_privileged_service_action(cli, service, "restart")?;
    let manager = service_manager_for_control(service)?;
    manager
        .restart()
        .map_err(|e| CliError::Runtime(e.to_string()))?;

    match output_mode(cli) {
        OutputMode::Human => {
            println!(
                "Restarted {} service ({} scope).",
                service_kind_name(service.kind),
                service.scope_name()
            );
        }
        OutputMode::Json => {
            let payload = json!({
                "action": "restart",
                "service_type": service_kind_name(service.kind),
                "scope": service.scope_name(),
                "success": true,
            });
            write_json_line(&payload)?;
        }
    }
    Ok(())
}

fn run_service_logs(
    cli: &Cli,
    service: ResolvedServiceControl,
    args: &ServiceLogsArgs,
) -> Result<(), CliError> {
    let manager = service_manager_for_control(service)?;
    let Some(path) = manager
        .logs_path()
        .map_err(|e| CliError::Runtime(e.to_string()))?
    else {
        return Err(CliError::User(format!(
            "{} service logs are available via the platform journal, not a fixed log file",
            service_kind_name(service.kind)
        )));
    };

    let lines = read_plain_tail_lines(&path, args.tail)?;
    match output_mode(cli) {
        OutputMode::Human => {
            if lines.is_empty() {
                println!("No service log lines in {}", path.display());
            } else {
                for line in &lines {
                    println!("{line}");
                }
            }
        }
        OutputMode::Json => {
            let payload = json!({
                "service_type": service_kind_name(service.kind),
                "scope": service.scope_name(),
                "path": path.display().to_string(),
                "tail": args.tail,
                "lines": lines,
            });
            write_json_line(&payload)?;
        }
    }
    Ok(())
}

fn service_manager_for_control(
    service: ResolvedServiceControl,
) -> Result<Box<dyn ServiceManager>, CliError> {
    match service.kind {
        ServiceKind::Launchd => Ok(Box::new(
            LaunchdServiceManager::from_env_for_control(service.user_scope)
                .map_err(|e| CliError::Runtime(e.to_string()))?,
        )),
        ServiceKind::Systemd => Ok(Box::new(
            SystemdServiceManager::from_env(service.user_scope)
                .map_err(|e| CliError::Runtime(e.to_string()))?,
        )),
        ServiceKind::None => Err(CliError::User(
            "service controls are not supported on this platform".to_string(),
        )),
    }
}

fn print_launchd_status(report: &LaunchdStatusReport) {
    println!("Service: launchd ({})", report.scope);
    println!("Target: {}", report.target);
    println!("Loaded: {}", yes_no(report.loaded));
    println!("Running: {}", yes_no(report.running));
    println!("State: {}", report.state.as_deref().unwrap_or("unknown"));
    println!(
        "PID: {}",
        report
            .pid
            .map_or_else(|| "none".to_string(), |pid| pid.to_string())
    );
    println!("Uptime: {}", report.uptime.as_deref().unwrap_or("unknown"));
    println!(
        "Active count: {}",
        report
            .active_count
            .map_or_else(|| "unknown".to_string(), |count| count.to_string())
    );
    println!(
        "Last exit: {}",
        report
            .last_exit_status
            .map_or_else(|| "unknown".to_string(), |status| status.to_string())
    );
    println!("Plist: {}", report.plist_path.display());
    println!(
        "Stdout: {} ({})",
        report.stdout_log.display(),
        format_optional_bytes(report.stdout_bytes)
    );
    println!(
        "Stderr: {} ({})",
        report.stderr_log.display(),
        format_optional_bytes(report.stderr_bytes)
    );
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn format_optional_bytes(value: Option<u64>) -> String {
    value.map_or_else(|| "missing".to_string(), |bytes| format!("{bytes} bytes"))
}

fn read_plain_tail_lines(path: &Path, count: usize) -> Result<Vec<String>, CliError> {
    use io::{Read, Seek};

    const MAX_TAIL_BYTES: u64 = 1024 * 1024;
    let mut file = std::fs::File::open(path).map_err(|e| {
        CliError::Runtime(format!(
            "failed to open service log {}: {e}",
            path.display()
        ))
    })?;
    let len = file
        .metadata()
        .map_err(|e| CliError::Runtime(format!("failed to stat service log: {e}")))?
        .len();
    let window = len.min(MAX_TAIL_BYTES);
    file.seek(io::SeekFrom::Start(len.saturating_sub(window)))
        .map_err(|e| CliError::Runtime(format!("failed to seek service log: {e}")))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .map_err(|e| CliError::Runtime(format!("failed to read service log: {e}")))?;
    let content = String::from_utf8_lossy(&buf);
    let lines: Vec<String> = content.lines().map(ToOwned::to_owned).collect();
    let start = lines.len().saturating_sub(count);
    Ok(lines[start..].to_vec())
}

fn parse_window_duration(s: &str) -> Result<std::time::Duration, CliError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(CliError::User("empty window string".to_string()));
    }
    let (digits, suffix) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = digits
        .parse()
        .map_err(|_| CliError::User(format!("invalid window value: {s}")))?;
    let multiplier = match suffix {
        "s" | "sec" => 1,
        "m" | "min" | "" => 60, // bare number defaults to minutes
        "h" | "hr" => 3600,
        "d" | "day" => 86400,
        _ => return Err(CliError::User(format!("unknown window suffix: {suffix}"))),
    };
    Ok(std::time::Duration::from_secs(n * multiplier))
}

/// Where a system-scope daemon keeps its activity database when this
/// invocation would read a different file: the platform system data dir, or
/// root's XDG data dir for older installs. `None` when running as root (the
/// configured path is already the daemon's) or when no such file exists.
fn daemon_activity_db_hint(db_path: &Path) -> Option<PathBuf> {
    if running_as_root() {
        return None;
    }
    let name = db_path.file_name()?;
    [
        storage_ballast_helper::core::config::system_data_dir().join(name),
        Path::new("/root/.local/share/sbh").join(name),
    ]
    .into_iter()
    .find(|candidate| candidate != db_path && candidate.exists())
}

/// Open the activity database read-only for a CLI query command, or explain
/// why it cannot be read and return `Ok(None)`.
///
/// Read-side commands never create or migrate the database. Two failure modes
/// are expected in normal operation and are reported as structured payloads
/// rather than raw SQLite errors: the file does not exist under this user's
/// data dir (the daemon runs as another user), or it exists but is not
/// readable by this user. Both name the daemon's database when it can be
/// found and point at `sudo`.
fn open_activity_db_for_reading(
    cli: &Cli,
    command: &str,
    config: &Config,
) -> Result<Option<SqliteLogger>, CliError> {
    let db_path = &config.paths.sqlite_db;
    let hint = daemon_activity_db_hint(db_path);

    let permission_denied = db_path.exists()
        && matches!(
            std::fs::File::open(db_path),
            Err(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied
        );

    if !db_path.exists() || permission_denied {
        let error = if permission_denied {
            "permission_denied"
        } else {
            "no_database"
        };
        match output_mode(cli) {
            OutputMode::Human => {
                if permission_denied {
                    println!(
                        "Activity database {} is not readable by this user (it belongs to the daemon's user).",
                        db_path.display()
                    );
                } else {
                    println!("No activity database found at {}.", db_path.display());
                }
                if let Some(path) = &hint {
                    println!("  The daemon's database is at {}.", path.display());
                }
                if permission_denied || hint.is_some() {
                    println!("  The daemon runs as another user — try: sudo sbh {command}");
                } else {
                    println!("  Run the daemon to start collecting statistics.");
                }
            }
            OutputMode::Json => {
                let mut payload = json!({
                    "command": command,
                    "error": error,
                    "db_path": db_path.to_string_lossy(),
                });
                if permission_denied || hint.is_some() {
                    payload["hint"] =
                        json!("daemon database belongs to another user; retry with sudo");
                }
                if let Some(path) = &hint {
                    payload["root_db_path"] = json!(path.to_string_lossy());
                }
                write_json_line(&payload)?;
            }
        }
        return Ok(None);
    }

    SqliteLogger::open_read_only(db_path)
        .map(Some)
        .map_err(|e| CliError::Runtime(format!("open {command} database: {e}")))
}

#[allow(clippy::too_many_lines)]
fn run_stats(cli: &Cli, args: &StatsArgs) -> Result<(), CliError> {
    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;

    let Some(db) = open_activity_db_for_reading(cli, "stats", &config)? else {
        return Ok(());
    };
    let engine = StatsEngine::new(&db);

    // Determine which window(s) to query.
    let specific_window = args
        .window
        .as_deref()
        .map(parse_window_duration)
        .transpose()?;

    // JSON mode: delegate to export_json or build custom payload.
    if output_mode(cli) == OutputMode::Json {
        return run_stats_json(&engine, args, specific_window);
    }

    // Human output.
    if let Some(window) = specific_window {
        let ws = engine
            .window_stats(window)
            .map_err(|e| CliError::Runtime(e.to_string()))?;

        println!("Statistics — last {}", window_label(window));
        println!();
        print_window_stats_human(&ws);
    } else {
        let windows = engine
            .summary()
            .map_err(|e| CliError::Runtime(e.to_string()))?;

        println!("Statistics — all standard windows");
        println!();

        for ws in &windows {
            println!("── {} ──", window_label(ws.window));
            print_window_stats_human(ws);
            println!();
        }
    }

    // Top patterns.
    if args.top_patterns > 0 {
        let window = specific_window.unwrap_or(std::time::Duration::from_hours(24));
        let patterns = engine
            .top_patterns(args.top_patterns, window)
            .map_err(|e| CliError::Runtime(e.to_string()))?;

        println!(
            "Top {} Patterns (last {}):",
            args.top_patterns,
            window_label(window)
        );
        if patterns.is_empty() {
            println!("  (none)");
        } else {
            println!("  {:<25}  {:>6}  {:>10}", "Pattern", "Count", "Bytes");
            println!("  {}", "-".repeat(45));
            for p in &patterns {
                println!(
                    "  {:<25}  {:>6}  {:>10}",
                    p.pattern,
                    p.count,
                    format_bytes(p.total_bytes),
                );
            }
        }
        println!();
    }

    // Top deletions.
    if args.top_deletions > 0 {
        let window = specific_window.unwrap_or(std::time::Duration::from_hours(24));
        let deletions = engine
            .top_deletions(args.top_deletions, window)
            .map_err(|e| CliError::Runtime(e.to_string()))?;

        println!(
            "Top {} Largest Deletions (last {}):",
            args.top_deletions,
            window_label(window),
        );
        if deletions.is_empty() {
            println!("  (none)");
        } else {
            println!("  {:>10}  {:>6}  {:<40}  When", "Size", "Score", "Path");
            println!("  {}", "-".repeat(75));
            for d in &deletions {
                println!(
                    "  {:>10}  {:>5.2}  {:<40}  {}",
                    format_bytes(d.size_bytes),
                    d.score,
                    truncate_path(Path::new(&d.path), 40),
                    &d.timestamp[..19.min(d.timestamp.len())],
                );
            }
        }
        println!();
    }

    // Pressure history.
    if args.pressure_history {
        let window = specific_window.unwrap_or(std::time::Duration::from_hours(24));
        let ws = engine
            .window_stats(window)
            .map_err(|e| CliError::Runtime(e.to_string()))?;

        println!("Pressure History (last {}):", window_label(window));
        println!(
            "  Current:     {} ({:.1}% free)",
            ws.pressure.current_level, ws.pressure.current_free_pct
        );
        println!("  Worst:       {}", ws.pressure.worst_level_reached);
        println!("  Transitions: {}", ws.pressure.transitions);
        println!();
        println!("  Time in level:");
        print_pressure_bar("green", ws.pressure.time_in_green_pct);
        print_pressure_bar("yellow", ws.pressure.time_in_yellow_pct);
        print_pressure_bar("orange", ws.pressure.time_in_orange_pct);
        print_pressure_bar("red", ws.pressure.time_in_red_pct);
        print_pressure_bar("critical", ws.pressure.time_in_critical_pct);
        println!();
    }

    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run_stats_json(
    engine: &StatsEngine<'_>,
    args: &StatsArgs,
    specific_window: Option<std::time::Duration>,
) -> Result<(), CliError> {
    let mut payload = if let Some(window) = specific_window {
        let ws = engine
            .window_stats(window)
            .map_err(|e| CliError::Runtime(e.to_string()))?;
        let full = engine
            .export_json()
            .map_err(|e| CliError::Runtime(e.to_string()))?;
        // Filter to just the requested window.
        let windows = full
            .get("windows")
            .and_then(|w| w.as_array())
            .cloned()
            .unwrap_or_default();
        let matched: Vec<_> = windows
            .into_iter()
            .filter(|w| w.get("window_secs").and_then(Value::as_u64) == Some(window.as_secs()))
            .collect();
        if matched.is_empty() {
            // Build from the queried stats directly.
            json!({
                "command": "stats",
                "window_secs": window.as_secs(),
                "window_label": window_label(window),
                "deletions": {
                    "count": ws.deletions.count,
                    "total_bytes_freed": ws.deletions.total_bytes_freed,
                    "avg_size": ws.deletions.avg_size,
                    "median_size": ws.deletions.median_size,
                    "failures": ws.deletions.failures,
                    "failures_by_reason": ws
                        .deletions
                        .failures_by_reason
                        .iter()
                        .map(|f| json!({ "code": f.code, "count": f.count }))
                        .collect::<Vec<_>>(),
                    "avg_age_hours": ws.deletions.avg_age_hours,
                },
                "ballast": {
                    "files_released": ws.ballast.files_released,
                    "files_replenished": ws.ballast.files_replenished,
                    "current_inventory": ws.ballast.current_inventory,
                    "bytes_available": ws.ballast.bytes_available,
                },
                "policy": {
                    "transitions": ws.policy.transitions,
                    "last_transition": ws.policy.last_transition,
                },
                "pressure": {
                    "current_level": ws.pressure.current_level.as_str(),
                    "worst_level": ws.pressure.worst_level_reached.as_str(),
                    "current_free_pct": ws.pressure.current_free_pct,
                    "transitions": ws.pressure.transitions,
                },
            })
        } else {
            json!({
                "command": "stats",
                "windows": matched,
            })
        }
    } else {
        let mut full = engine
            .export_json()
            .map_err(|e| CliError::Runtime(e.to_string()))?;
        if let Some(obj) = full.as_object_mut() {
            obj.insert("command".to_string(), json!("stats"));
        }
        full
    };

    // Attach top_patterns if requested.
    if args.top_patterns > 0 {
        let window = specific_window.unwrap_or(std::time::Duration::from_hours(24));
        let patterns = engine
            .top_patterns(args.top_patterns, window)
            .map_err(|e| CliError::Runtime(e.to_string()))?;
        let patterns_json: Vec<Value> = patterns
            .iter()
            .map(|p| json!({"pattern": p.pattern, "count": p.count, "total_bytes": p.total_bytes}))
            .collect();
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("top_patterns".to_string(), json!(patterns_json));
        }
    }

    // Attach top_deletions if requested.
    if args.top_deletions > 0 {
        let window = specific_window.unwrap_or(std::time::Duration::from_hours(24));
        let deletions = engine
            .top_deletions(args.top_deletions, window)
            .map_err(|e| CliError::Runtime(e.to_string()))?;
        let deletions_json: Vec<Value> = deletions
            .iter()
            .map(|d| {
                json!({
                    "path": d.path,
                    "size_bytes": d.size_bytes,
                    "score": d.score,
                    "timestamp": d.timestamp,
                })
            })
            .collect();
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("top_deletions".to_string(), json!(deletions_json));
        }
    }

    write_json_line(&payload)?;
    Ok(())
}

fn print_window_stats_human(ws: &storage_ballast_helper::logger::stats::WindowStats) {
    println!("  Deletions:");
    println!("    Count:       {}", ws.deletions.count);
    println!(
        "    Bytes freed: {}",
        format_bytes(ws.deletions.total_bytes_freed)
    );
    if ws.deletions.count > 0 {
        println!("    Avg size:    {}", format_bytes(ws.deletions.avg_size));
        println!(
            "    Median size: {}",
            format_bytes(ws.deletions.median_size)
        );
        println!("    Avg score:   {:.2}", ws.deletions.avg_score);
        if let Some(largest) = &ws.deletions.largest_deletion {
            println!(
                "    Largest:     {} ({})",
                truncate_path(Path::new(&largest.path), 50),
                format_bytes(largest.size_bytes),
            );
        }
        if let Some(cat) = &ws.deletions.most_common_category {
            println!("    Top pattern: {cat}");
        }
    }
    if ws.deletions.failures > 0 {
        println!("    Failures:    {}", ws.deletions.failures);
        for reason in &ws.deletions.failures_by_reason {
            println!("      {:<12} {}", reason.code, reason.count);
        }
    }
    if ws.deletions.avg_age_hours > 0.0 {
        println!("    Avg age:     {:.1} h", ws.deletions.avg_age_hours);
    }

    println!("  Ballast:");
    println!("    Released:    {}", ws.ballast.files_released);
    println!("    Replenished: {}", ws.ballast.files_replenished);
    println!("    Inventory:   {} files", ws.ballast.current_inventory);
    println!(
        "    Available:   {}",
        format_bytes(ws.ballast.bytes_available)
    );

    println!("  Pressure:");
    println!(
        "    Current:     {} ({:.1}% free)",
        ws.pressure.current_level, ws.pressure.current_free_pct,
    );
    println!("    Worst:       {}", ws.pressure.worst_level_reached);
    println!("    Transitions: {}", ws.pressure.transitions);

    println!("  Policy:");
    println!("    Transitions: {}", ws.policy.transitions);
    if let Some(last) = &ws.policy.last_transition {
        println!("    Last:        {last}");
    }
}

#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn print_pressure_bar(label: &str, pct: f64) {
    let bar_width = 30;
    let filled = ((pct / 100.0) * bar_width as f64).round() as usize;
    let bar: String = "#".repeat(filled.min(bar_width));
    println!("    {label:<9} {pct:>5.1}% |{bar:<bar_width$}|");
}

#[derive(Debug, Clone)]
struct BlameReport {
    rows: Vec<BlameRow>,
    since: Duration,
    process_count: usize,
    io_error_count: usize,
    open_file_error_count: usize,
    open_file_roots: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BlameRow {
    pid: i32,
    parent_pid: Option<i32>,
    name: String,
    command: String,
    executable: Option<PathBuf>,
    cwd: Option<PathBuf>,
    recent_read_bytes: u64,
    recent_written_bytes: u64,
    open_files: Vec<PathBuf>,
}

fn run_blame(cli: &Cli, args: &BlameArgs) -> Result<(), CliError> {
    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;
    let since = parse_window_duration(&args.since)?;
    let platform = detect_platform().map_err(|e| CliError::Runtime(e.to_string()))?;
    let history = ProcessIoHistory::load_or_new(ProcessIoHistory::snapshot_path_for_state_file(
        &config.paths.state_file,
    ));
    let start = std::time::Instant::now();
    let report = collect_blame_report_at(
        &config,
        platform.as_ref(),
        &history,
        since,
        args.top,
        unix_time_ms_for_cli(),
    )?;
    let elapsed = start.elapsed();

    match output_mode(cli) {
        OutputMode::Human => {
            println!(
                "Process I/O blame - last {} (sampled in {:.1}s):",
                window_label(report.since),
                elapsed.as_secs_f64(),
            );
            println!();

            if report.rows.is_empty() {
                println!("  No process I/O attribution data found.");
            } else {
                print_blame_human(&report, args.tree);
            }

            if report.io_error_count > 0 || report.open_file_error_count > 0 {
                println!();
                println!(
                    "  Partial attribution: {} process I/O read errors, {} open-file root errors",
                    report.io_error_count, report.open_file_error_count,
                );
            }
        }
        OutputMode::Json => {
            let rows_json: Vec<Value> = report
                .rows
                .iter()
                .map(|row| {
                    json!({
                        "pid": row.pid,
                        "parent_pid": row.parent_pid,
                        "name": row.name,
                        "command": row.command,
                        "executable": row.executable.as_ref().map(|path| path.display().to_string()),
                        "cwd": row.cwd.as_ref().map(|path| path.display().to_string()),
                        "recent_bytes_written": row.recent_written_bytes,
                        "recent_bytes_read": row.recent_read_bytes,
                        "open_files": row.open_files.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
                    })
                })
                .collect();

            let payload = json!({
                "command": "blame",
                "since_secs": report.since.as_secs(),
                "since_label": window_label(report.since),
                "tree_mode": args.tree,
                "rows": rows_json,
                "elapsed_ms": u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                "processes_scanned": report.process_count,
                "io_error_count": report.io_error_count,
                "open_file_error_count": report.open_file_error_count,
                "open_file_roots": report.open_file_roots.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
            });
            write_json_line(&payload)?;
        }
    }

    Ok(())
}

fn collect_blame_report_at(
    config: &Config,
    platform: &dyn Platform,
    history: &ProcessIoHistory,
    since: Duration,
    top: usize,
    collected_at_unix_ms: i64,
) -> Result<BlameReport, CliError> {
    let processes = platform
        .process_list()
        .map_err(|error| CliError::Runtime(error.to_string()))?;
    let open_file_roots = canonical_blame_roots(config);
    let (open_files_by_pid, open_file_error_count) =
        collect_blame_open_files(platform, &open_file_roots);
    let mut io_error_count = 0;
    let mut rows = Vec::with_capacity(processes.len());

    for process in &processes {
        let io = platform.process_io(process.pid).unwrap_or_else(|_| {
            io_error_count += 1;
            ProcessIo {
                pid: process.pid,
                bytes_read_total: 0,
                bytes_written_total: 0,
                bytes_read_recent_15m: None,
                bytes_written_recent_15m: None,
            }
        });
        let recent = blame_recent_totals(history, process, &io, since, collected_at_unix_ms);
        let mut open_files = open_files_by_pid
            .get(&process.pid)
            .cloned()
            .unwrap_or_default();
        open_files.sort();

        rows.push(BlameRow {
            pid: process.pid,
            parent_pid: process.parent_pid,
            name: process.name.clone(),
            command: process_command(process),
            executable: process.executable.clone(),
            cwd: process.cwd.clone(),
            recent_read_bytes: recent.0,
            recent_written_bytes: recent.1,
            open_files,
        });
    }

    rows.sort_by(|left, right| {
        right
            .recent_written_bytes
            .cmp(&left.recent_written_bytes)
            .then_with(|| right.recent_read_bytes.cmp(&left.recent_read_bytes))
            .then_with(|| right.open_files.len().cmp(&left.open_files.len()))
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.pid.cmp(&right.pid))
    });
    rows.truncate(top);

    Ok(BlameReport {
        rows,
        since,
        process_count: processes.len(),
        io_error_count,
        open_file_error_count,
        open_file_roots,
    })
}

fn blame_recent_totals(
    history: &ProcessIoHistory,
    process: &ProcessInfo,
    io: &ProcessIo,
    since: Duration,
    collected_at_unix_ms: i64,
) -> (u64, u64) {
    if let Some(recent) = history.recent_totals_for_process(
        io,
        process.start_time_unix_ms,
        collected_at_unix_ms,
        since,
    ) {
        return (recent.bytes_read, recent.bytes_written);
    }

    if since == Duration::from_mins(15)
        && let (Some(read), Some(written)) = (io.bytes_read_recent_15m, io.bytes_written_recent_15m)
    {
        return (read, written);
    }

    (0, 0)
}

fn canonical_blame_roots(config: &Config) -> Vec<PathBuf> {
    config
        .scanner
        .root_paths
        .iter()
        .filter_map(|path| path.canonicalize().ok())
        .collect()
}

fn collect_blame_open_files(
    platform: &dyn Platform,
    roots: &[PathBuf],
) -> (HashMap<i32, Vec<PathBuf>>, usize) {
    let mut by_pid: HashMap<i32, BTreeSet<PathBuf>> = HashMap::new();
    let mut errors = 0;

    for root in roots {
        match platform.open_files_under(root) {
            Ok(open_files) => {
                for open_file in open_files {
                    by_pid
                        .entry(open_file.pid)
                        .or_default()
                        .insert(open_file.path);
                }
            }
            Err(_) => errors += 1,
        }
    }

    (
        by_pid
            .into_iter()
            .map(|(pid, paths)| (pid, paths.into_iter().collect()))
            .collect(),
        errors,
    )
}

fn process_command(process: &ProcessInfo) -> String {
    if process.command_line.is_empty() {
        process.name.clone()
    } else {
        process.command_line.join(" ")
    }
}

fn print_blame_human(report: &BlameReport, tree: bool) {
    println!(
        "  {:>7}  {:>7}  {:>12}  {:>12}  {:>5}  Command",
        "PID", "PPID", "Written", "Read", "Open"
    );
    println!("  {}", "-".repeat(68));

    if tree {
        for (index, depth) in blame_tree_order(&report.rows) {
            print_blame_row_human(&report.rows[index], depth);
        }
    } else {
        for row in &report.rows {
            print_blame_row_human(row, 0);
        }
    }
}

fn print_blame_row_human(row: &BlameRow, depth: usize) {
    let indent = "  ".repeat(depth);
    println!(
        "  {indent}{:>7}  {:>7}  {:>12}  {:>12}  {:>5}  {}",
        row.pid,
        row.parent_pid
            .map_or_else(|| "-".to_string(), |pid| pid.to_string()),
        format_bytes(row.recent_written_bytes),
        format_bytes(row.recent_read_bytes),
        row.open_files.len(),
        row.command,
    );
    if let Some(executable) = &row.executable {
        println!("  {indent}         exe: {}", executable.display());
    }
    if let Some(cwd) = &row.cwd {
        println!("  {indent}         cwd: {}", cwd.display());
    }
    if !row.open_files.is_empty() {
        let open_files = row
            .open_files
            .iter()
            .take(5)
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let suffix = if row.open_files.len() > 5 {
            format!(", +{} more", row.open_files.len() - 5)
        } else {
            String::new()
        };
        println!("  {indent}         open: {open_files}{suffix}");
    }
}

fn blame_tree_order(rows: &[BlameRow]) -> Vec<(usize, usize)> {
    let by_pid: HashMap<i32, usize> = rows
        .iter()
        .enumerate()
        .map(|(index, row)| (row.pid, index))
        .collect();
    let mut children: HashMap<Option<i32>, Vec<usize>> = HashMap::new();
    for (index, row) in rows.iter().enumerate() {
        let parent = row.parent_pid.filter(|pid| by_pid.contains_key(pid));
        children.entry(parent).or_default().push(index);
    }

    let mut order = Vec::with_capacity(rows.len());
    let mut visited = HashSet::new();
    append_blame_tree_children(None, 0, rows, &children, &mut visited, &mut order);
    for index in 0..rows.len() {
        if visited.insert(index) {
            order.push((index, 0));
        }
    }
    order
}

fn append_blame_tree_children(
    parent: Option<i32>,
    depth: usize,
    rows: &[BlameRow],
    children: &HashMap<Option<i32>, Vec<usize>>,
    visited: &mut HashSet<usize>,
    order: &mut Vec<(usize, usize)>,
) {
    let Some(indices) = children.get(&parent) else {
        return;
    };
    for index in indices {
        if !visited.insert(*index) {
            continue;
        }
        order.push((*index, depth));
        append_blame_tree_children(
            Some(rows[*index].pid),
            depth + 1,
            rows,
            children,
            visited,
            order,
        );
    }
}

fn unix_time_ms_for_cli() -> i64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
        })
}

// ──────────────────── tuning engine ────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TuningCategory {
    Ballast,
    Threshold,
    Scoring,
    KernelWriteback,
}

impl std::fmt::Display for TuningCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ballast => f.write_str("Ballast"),
            Self::Threshold => f.write_str("Threshold"),
            Self::Scoring => f.write_str("Scoring"),
            Self::KernelWriteback => f.write_str("KernelWriteback"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TuningRisk {
    Low,
    Medium,
    #[allow(dead_code)] // scaffolding for PID-tuning recommendations
    High,
}

impl std::fmt::Display for TuningRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => f.write_str("low"),
            Self::Medium => f.write_str("medium"),
            Self::High => f.write_str("high"),
        }
    }
}

#[derive(Debug, Clone)]
struct Recommendation {
    category: TuningCategory,
    config_key: String,
    current_value: String,
    suggested_value: String,
    rationale: String,
    confidence: f64,
    risk: TuningRisk,
}

#[allow(
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn generate_recommendations(
    config: &Config,
    stats: &[storage_ballast_helper::logger::stats::WindowStats],
) -> Vec<Recommendation> {
    let mut recs = Vec::new();

    // Use the 24-hour window for most analysis (index 4 in STANDARD_WINDOWS).
    let day_stats = stats.iter().find(|ws| ws.window.as_secs() == 86_400);
    // Use the 7-day window for trend analysis.
    let week_stats = stats.iter().find(|ws| ws.window.as_secs() == 604_800);
    // Use the 1-hour window for recent activity.
    let hour_stats = stats.iter().find(|ws| ws.window.as_secs() == 3_600);

    // ── Ballast sizing recommendations ──
    if let Some(ws) = day_stats {
        let ballast = &ws.ballast;

        // If ballast was exhausted (all released, none left) during pressure events.
        if ballast.files_released > 0 && ballast.current_inventory == 0 {
            let suggested = (config.ballast.file_count as f64 * 1.5).ceil() as usize;
            recs.push(Recommendation {
                category: TuningCategory::Ballast,
                config_key: "ballast.file_count".to_string(),
                current_value: config.ballast.file_count.to_string(),
                suggested_value: suggested.to_string(),
                rationale: format!(
                    "Ballast exhausted — all {} files released with no reserve. \
                     Increasing to {suggested} provides buffer for sustained pressure.",
                    config.ballast.file_count,
                ),
                confidence: 0.85,
                risk: TuningRisk::Low,
            });
        }

        // If ballast was never used in 7 days and there were pressure events.
        if let Some(week) = week_stats
            && week.ballast.files_released == 0
            && week.pressure.transitions > 0
            && config.ballast.file_count > 3
        {
            let pool_gb =
                ballast_total_pool_bytes(config.ballast.file_count, config.ballast.file_size_bytes)
                    as f64
                    / 1_073_741_824.0;
            let suggested = (config.ballast.file_count / 2).max(3);
            recs.push(Recommendation {
                category: TuningCategory::Ballast,
                config_key: "ballast.file_count".to_string(),
                current_value: config.ballast.file_count.to_string(),
                suggested_value: suggested.to_string(),
                rationale: format!(
                    "Ballast never released in 7 days despite {} pressure transitions. \
                         {pool_gb:.1} GB is reserved but unused. Reducing to {suggested} files \
                         frees {:.1} GB.",
                    week.pressure.transitions,
                    ballast_total_pool_bytes(
                        config.ballast.file_count.saturating_sub(suggested),
                        config.ballast.file_size_bytes,
                    ) as f64
                        / 1_073_741_824.0,
                ),
                confidence: 0.7,
                risk: TuningRisk::Medium,
            });
        }
    }

    // ── Threshold recommendations ──
    if let Some(ws) = day_stats {
        let pressure = &ws.pressure;

        // If we spend >40% of the day in elevated pressure.
        let elevated_pct = pressure.time_in_yellow_pct
            + pressure.time_in_orange_pct
            + pressure.time_in_red_pct
            + pressure.time_in_critical_pct;
        if elevated_pct > 40.0 {
            let suggested = (config.pressure.green_min_free_pct - 3.0).max(8.0);
            recs.push(Recommendation {
                category: TuningCategory::Threshold,
                config_key: "pressure.green_min_free_pct".to_string(),
                current_value: format!("{:.1}", config.pressure.green_min_free_pct),
                suggested_value: format!("{suggested:.1}"),
                rationale: format!(
                    "System spent {elevated_pct:.0}% of the past 24h in elevated pressure. \
                     Lowering green threshold from {:.1}% to {suggested:.1}% reduces false alarms \
                     while still providing early warning.",
                    config.pressure.green_min_free_pct,
                ),
                confidence: 0.75,
                risk: TuningRisk::Medium,
            });
        }

        // If oscillating between levels (>10 transitions/day).
        if pressure.transitions > 10 {
            recs.push(Recommendation {
                category: TuningCategory::Threshold,
                config_key: "pressure.yellow_min_free_pct".to_string(),
                current_value: format!("{:.1}", config.pressure.yellow_min_free_pct),
                suggested_value: format!(
                    "{:.1}",
                    (config.pressure.yellow_min_free_pct - 2.0).max(5.0)
                ),
                rationale: format!(
                    "Detected {} pressure transitions in 24h — likely oscillation. \
                     Widening the gap between thresholds adds hysteresis.",
                    pressure.transitions,
                ),
                confidence: 0.7,
                risk: TuningRisk::Low,
            });
        }
    }

    // ── Scoring recommendations ──
    if let Some(ws) = hour_stats {
        // If deletions have very low avg score, the min_score threshold may be too low.
        if ws.deletions.count > 5 && ws.deletions.avg_score < 0.5 {
            let suggested = (config.scoring.min_score + 0.1).min(0.9);
            recs.push(Recommendation {
                category: TuningCategory::Scoring,
                config_key: "scoring.min_score".to_string(),
                current_value: format!("{:.2}", config.scoring.min_score),
                suggested_value: format!("{suggested:.2}"),
                rationale: format!(
                    "Average deletion score is only {:.2} across {} recent deletions. \
                     Raising min_score to {suggested:.2} avoids deleting marginal candidates.",
                    ws.deletions.avg_score, ws.deletions.count,
                ),
                confidence: 0.65,
                risk: TuningRisk::Medium,
            });
        }

        // If failure rate is high.
        if ws.deletions.count > 0 {
            let fail_rate =
                ws.deletions.failures as f64 / (ws.deletions.count + ws.deletions.failures) as f64;
            if fail_rate > 0.2 {
                let suggested = config.scanner.min_file_age_minutes.max(45);
                if suggested > config.scanner.min_file_age_minutes {
                    recs.push(Recommendation {
                        category: TuningCategory::Scoring,
                        config_key: "scanner.min_file_age_minutes".to_string(),
                        current_value: config.scanner.min_file_age_minutes.to_string(),
                        suggested_value: suggested.to_string(),
                        rationale: format!(
                            "{:.0}% of deletion attempts failed (likely in-use files). \
                             Increasing min_file_age to {suggested} minutes gives builds \
                             more time to complete.",
                            fail_rate * 100.0,
                        ),
                        confidence: 0.8,
                        risk: TuningRisk::Low,
                    });
                }
            }
        }
    }

    // Sort by confidence descending.
    recs.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    recs
}

/// Computed kernel-writeback tuning for the current host: the sized plan plus
/// the display recommendations derived from it.
struct WritebackTuning {
    plan: storage_ballast_helper::tuning::writeback::WritebackPlan,
    recommendations: Vec<Recommendation>,
}

/// Pick the directory to size/benchmark writeback against: prefer the ballast
/// volume (where sbh's own and most build writes land), then its parent, then
/// the first existing scan root, then `/`.
fn writeback_probe_path(config: &Config) -> std::path::PathBuf {
    let ballast = &config.paths.ballast_dir;
    if ballast.exists() {
        return ballast.clone();
    }
    if let Some(parent) = ballast.parent()
        && parent.exists()
    {
        return parent.to_path_buf();
    }
    if let Some(root) = config.scanner.root_paths.iter().find(|path| path.exists()) {
        return root.clone();
    }
    std::path::PathBuf::from("/")
}

/// Estimate device write bandwidth for sizing: micro-benchmark when `measure`
/// (and config) allow it, otherwise the device-class heuristic.
fn estimate_writeback_bandwidth(
    cfg: &storage_ballast_helper::core::config::SystemTuningConfig,
    probe_path: &std::path::Path,
    device: Option<&BlockDeviceInfo>,
    measure: bool,
) -> (
    u64,
    storage_ballast_helper::tuning::bandwidth::BandwidthSource,
) {
    use storage_ballast_helper::tuning::bandwidth;
    if measure
        && cfg.writeback_benchmark_enabled
        && let Ok(bps) = bandwidth::measure_bytes_per_sec(probe_path, cfg.writeback_benchmark_bytes)
    {
        return (bps, bandwidth::BandwidthSource::Measured);
    }
    device.map_or_else(
        || bandwidth::heuristic_bytes_per_sec(None, ""),
        |info| bandwidth::heuristic_bytes_per_sec(info.rotational, &info.device),
    )
}

fn current_background_bytes(
    state: &storage_ballast_helper::tuning::writeback::WritebackState,
) -> u64 {
    if let Some(bytes) = state.dirty_background_bytes.filter(|&b| b > 0) {
        return bytes;
    }
    let ratio = u128::from(state.dirty_background_ratio.unwrap_or(0));
    u64::try_from(u128::from(state.total_ram_bytes) * ratio / 100).unwrap_or(u64::MAX)
}

/// Build the kernel-writeback tuning for this host, or `None` when tuning is
/// disabled, unsupported on this platform, or the kernel is already healthy.
/// `measure` runs the on-volume bandwidth micro-benchmark for a precise estimate.
fn build_writeback_tuning(
    config: &Config,
    platform: &dyn Platform,
    measure: bool,
) -> Option<WritebackTuning> {
    use storage_ballast_helper::tuning::writeback;

    let cfg = &config.system_tuning;
    if !cfg.writeback_enabled {
        return None;
    }
    let state = platform.writeback_state().ok()?;

    let probe_path = writeback_probe_path(config);
    // Never benchmark a RAM-backed path (tmpfs/ramfs): it would measure memory,
    // not disk, bandwidth and massively oversize the limits. Use the device-class
    // heuristic there instead.
    let probe_ram_backed = platform.is_ram_backed(&probe_path).unwrap_or(false);
    let device = platform.block_device_for(&probe_path).ok();
    let fs_type = device
        .as_ref()
        .map_or_else(String::new, |info| info.fs_type.clone());

    // Decide *whether* tuning is needed with the zero-write heuristic first, so a
    // healthy host never triggers the benchmark. Only once tuning is warranted do
    // we (optionally) measure bandwidth to refine the values.
    let (heuristic_bps, heuristic_source) =
        estimate_writeback_bandwidth(cfg, &probe_path, device.as_ref(), false);
    let heuristic_plan = writeback::plan_from_bandwidth(heuristic_bps, heuristic_source, cfg);
    let assessment = writeback::assess(&state, &heuristic_plan, cfg, &fs_type);
    if !assessment.needs_tuning {
        return None;
    }

    // Benchmark only when applying on real, non-RAM storage that has the headroom
    // to absorb the probe write — a disk-pressure tool must not push a low-on-space
    // volume closer to full (and `fs_stats` failure fails safe to the heuristic).
    let benchmark = measure
        && !probe_ram_backed
        && platform.fs_stats(&probe_path).is_ok_and(|stats| {
            stats.available_bytes >= cfg.writeback_benchmark_bytes.saturating_mul(2)
        });
    let plan = if benchmark {
        let (bps, source) = estimate_writeback_bandwidth(cfg, &probe_path, device.as_ref(), true);
        writeback::plan_from_bandwidth(bps, source, cfg)
    } else {
        heuristic_plan
    };

    let current_hard = state.effective_dirty_pool_bytes();
    let current_background = current_background_bytes(&state);
    let rationale = assessment.reasons.join(" ");

    let recommendations = vec![
        Recommendation {
            category: TuningCategory::KernelWriteback,
            config_key: "vm.dirty_bytes".to_string(),
            current_value: writeback::human_bytes(current_hard),
            // Display-only (the apply path uses `plan` directly, not this string);
            // keep it human-readable to match current_value. Exact bytes are in the
            // rationale and the apply JSON's raw `writeback` object.
            suggested_value: writeback::human_bytes(plan.dirty_bytes),
            rationale: format!(
                "{rationale} Set vm.dirty_bytes={} ({}) for continuous, gentle writeback \
                 instead of multi-GB bursts.",
                plan.dirty_bytes,
                writeback::human_bytes(plan.dirty_bytes),
            ),
            confidence: 0.9,
            risk: TuningRisk::Medium,
        },
        Recommendation {
            category: TuningCategory::KernelWriteback,
            config_key: "vm.dirty_background_bytes".to_string(),
            current_value: writeback::human_bytes(current_background),
            suggested_value: writeback::human_bytes(plan.dirty_background_bytes),
            rationale: format!(
                "Begin background writeback at {} ({}); sized from a {}/s estimate ({}) \
                 with a {:.1}s drain target.",
                plan.dirty_background_bytes,
                writeback::human_bytes(plan.dirty_background_bytes),
                writeback::human_bytes(plan.bandwidth_bytes_per_sec),
                plan.bandwidth_source,
                cfg.writeback_target_drain_secs,
            ),
            confidence: 0.9,
            risk: TuningRisk::Medium,
        },
    ];

    Some(WritebackTuning {
        plan,
        recommendations,
    })
}

/// Outcome of applying kernel-writeback tuning, for reporting.
struct WritebackApplyReport {
    sysctl_path: std::path::PathBuf,
    backup: Option<std::path::PathBuf>,
    reload_ok: bool,
    reload_detail: String,
    conflicts: Vec<std::path::PathBuf>,
}

/// Apply + persist kernel writeback limits. Requires root (caller verifies).
fn apply_writeback_tuning(
    config: &Config,
    platform: &dyn Platform,
    plan: &storage_ballast_helper::tuning::writeback::WritebackPlan,
) -> Result<WritebackApplyReport, CliError> {
    use storage_ballast_helper::tuning::writeback;

    let cfg = &config.system_tuning;

    // 1. Persist FIRST (backup-first) to sysctl.d. Persistence is the durable
    //    intent; doing it before touching the running kernel keeps a partial
    //    failure recoverable. (If we applied the runtime first and persistence
    //    then failed, the host would be byte-mode at runtime with no file — and a
    //    re-run, seeing byte-mode, would report "healthy" and never retry the
    //    persistence, so the tuning would silently revert on reboot.)
    let sysctl_path = cfg.writeback_sysctl_path.clone();
    let backup = backup_existing_file(&sysctl_path)?;
    if let Some(parent) = sysctl_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| CliError::Runtime(format!("create {}: {e}", parent.display())))?;
    }
    let note = format!("generated {}", chrono::Utc::now().to_rfc3339());
    let body = writeback::render_sysctl_conf(plan, cfg.writeback_target_drain_secs, &note);
    // Write atomically (temp + rename) so a mid-write failure (e.g. ENOSPC on a
    // full disk — exactly the conditions this tool operates under) can never leave
    // a truncated, sysctl-loadable file behind. The ".conf.tmp" suffix is ignored
    // by both sysctl (loads only "*.conf") and our conflict scan.
    let tmp_path = sysctl_path.with_extension("conf.tmp");
    std::fs::write(&tmp_path, body)
        .map_err(|e| CliError::Runtime(format!("write {}: {e}", tmp_path.display())))?;
    if let Err(e) = std::fs::rename(&tmp_path, &sysctl_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(CliError::Runtime(format!(
            "install {}: {e}",
            sysctl_path.display()
        )));
    }

    // 2. Apply to the running kernel. The file is already persisted, so even if
    //    this fails the tuning takes effect on the next boot/reload.
    platform
        .apply_writeback_runtime(plan.dirty_bytes, plan.dirty_background_bytes)
        .map_err(|e| {
            CliError::Runtime(format!(
                "persisted {} but could not apply it at runtime (it will take effect on reboot): {e}",
                sysctl_path.display()
            ))
        })?;

    // 3. Validate by reloading just our file (re-applies the same values).
    let (reload_ok, reload_detail) = sysctl_reload(&["-p".to_string(), display_path(&sysctl_path)]);

    // 4. Warn about later-loading files that override our byte limits with ratios.
    let conflicts = scan_sysctl_conflicts(&sysctl_path);

    Ok(WritebackApplyReport {
        sysctl_path,
        backup,
        reload_ok,
        reload_detail,
        conflicts,
    })
}

fn display_path(path: &std::path::Path) -> String {
    path.display().to_string()
}

/// Actionable warning when another `sysctl.d` file would override our byte limits.
///
/// The runtime values are applied directly and unaffected; the conflict only
/// matters on the next full reload (`sysctl --system`) or reboot, where the
/// later-loading file's ratio re-zeros our byte limits.
fn writeback_conflict_note(conflict: &std::path::Path) -> String {
    format!(
        "{} loads after the sbh snippet and sets vm.dirty_ratio, so it will override the byte \
         limits on the next `sysctl --system`/reboot. Remove the vm.dirty_ratio / \
         vm.dirty_background_ratio lines from it, or set system_tuning.writeback_sysctl_path to a \
         filename that sorts after it.",
        conflict.display()
    )
}

fn backup_existing_file(path: &std::path::Path) -> Result<Option<std::path::PathBuf>, CliError> {
    if !path.exists() {
        return Ok(None);
    }
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let backup = path.with_file_name(format!("{name}.bak-{stamp}"));
    std::fs::copy(path, &backup)
        .map_err(|e| CliError::Runtime(format!("backup {}: {e}", path.display())))?;
    Ok(Some(backup))
}

fn sysctl_reload(args: &[String]) -> (bool, String) {
    match std::process::Command::new("sysctl").args(args).output() {
        Ok(out) => {
            let detail = if out.status.success() {
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            } else {
                String::from_utf8_lossy(&out.stderr).trim().to_string()
            };
            (out.status.success(), detail)
        }
        Err(e) => (false, format!("sysctl not run: {e}")),
    }
}

fn scan_sysctl_conflicts(our_path: &std::path::Path) -> Vec<std::path::PathBuf> {
    use storage_ballast_helper::tuning::writeback;
    let Some(dir) = our_path.parent() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut snippets = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("conf") {
            continue;
        }
        if let Ok(contents) = std::fs::read_to_string(&path) {
            snippets.push((path, contents));
        }
    }
    writeback::conflicting_sysctl_files(our_path, &snippets)
}

fn latest_backup(path: &std::path::Path) -> Option<std::path::PathBuf> {
    let dir = path.parent()?;
    let prefix = format!("{}.bak-", path.file_name()?.to_string_lossy());
    let mut backups: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|candidate| {
            candidate
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(&prefix))
        })
        .collect();
    backups.sort();
    backups.pop()
}

/// Revert kernel writeback tuning: restore the latest backup (or remove the sbh
/// snippet) and reload sysctl. Requires root.
fn run_writeback_revert(cli: &Cli, config: &Config) -> Result<(), CliError> {
    if !running_as_root() {
        return Err(CliError::User(
            "reverting kernel writeback tuning requires root; re-run with sudo".to_string(),
        ));
    }
    let path = &config.system_tuning.writeback_sysctl_path;
    let restored_from = latest_backup(path);
    let action = if let Some(ref backup) = restored_from {
        std::fs::copy(backup, path)
            .map_err(|e| CliError::Runtime(format!("restore {}: {e}", path.display())))?;
        format!("restored {} from {}", path.display(), backup.display())
    } else if path.exists() {
        std::fs::remove_file(path)
            .map_err(|e| CliError::Runtime(format!("remove {}: {e}", path.display())))?;
        format!("removed sbh writeback snippet {}", path.display())
    } else {
        format!("no sbh writeback snippet found at {}", path.display())
    };
    let (reload_ok, reload_detail) = sysctl_reload(&["--system".to_string()]);

    match output_mode(cli) {
        OutputMode::Human => {
            println!("Reverted kernel writeback tuning:");
            println!("  {action}");
            if reload_ok {
                println!("  reloaded system sysctl settings");
            } else {
                println!("  note: `sysctl --system` reported: {reload_detail}");
            }
            if restored_from.is_none() {
                println!(
                    "  runtime vm.dirty_bytes may persist until another sysctl sets \
                     vm.dirty_ratio or until reboot"
                );
            }
        }
        OutputMode::Json => {
            let payload = json!({
                "command": "tune",
                "action": "revert-writeback",
                "detail": action,
                "reload_ok": reload_ok,
                "restored_from": restored_from.as_ref().map(|p| p.to_string_lossy()),
            });
            write_json_line(&payload)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run_tune(cli: &Cli, args: &TuneArgs) -> Result<(), CliError> {
    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;

    if args.revert_writeback {
        return run_writeback_revert(cli, &config);
    }

    let platform = detect_platform().map_err(|e| CliError::Runtime(e.to_string()))?;

    // Open stats database (read-only; history only refines recommendations).
    let db = if config.paths.sqlite_db.exists() {
        match SqliteLogger::open_read_only(&config.paths.sqlite_db) {
            Ok(db) => Some(db),
            Err(e) => {
                eprintln!(
                    "[SBH-TUNE] activity database {} is not readable ({e}); recommendations use live samples only",
                    config.paths.sqlite_db.display()
                );
                None
            }
        }
    } else {
        None
    };

    let mut recs = if let Some(ref db) = db {
        let engine = StatsEngine::new(db);
        let stats = engine
            .summary()
            .map_err(|e| CliError::Runtime(e.to_string()))?;
        generate_recommendations(&config, &stats)
    } else {
        Vec::new()
    };

    // Append kernel-writeback recommendation(s). Run the bandwidth micro-benchmark
    // only when we are actually about to apply (root + --yes, not opted out); every
    // read-only path — `sbh tune`, the `--apply` confirmation preview, and a
    // non-root `--apply` — uses the zero-write device-class heuristic instead.
    let measure_bandwidth = args.apply && args.yes && !args.no_benchmark && running_as_root();
    let writeback = build_writeback_tuning(&config, platform.as_ref(), measure_bandwidth);
    if let Some(ref tuning) = writeback {
        recs.extend(tuning.recommendations.clone());
    }
    // bd-rc-master-ajg1.2.18: pool sizes from the daemon's burst windows.
    let bursts = BurstStats::load_or_new(BurstStats::snapshot_path_for_state_file(
        &config.paths.state_file,
    ));
    recs.extend(burst_reserve_recommendations(
        &config,
        &bursts,
        &reserve_pools(cli, &config),
    ));
    recs.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if !args.apply {
        // Display recommendations.
        match output_mode(cli) {
            OutputMode::Human => {
                if recs.is_empty() {
                    if db.is_none() {
                        println!("No activity database found. Run the daemon to collect data.");
                    } else {
                        println!("No tuning recommendations at this time.");
                        println!("  Insufficient data or configuration is already well-tuned.");
                    }
                } else {
                    println!("Tuning Recommendations ({} found):", recs.len());
                    println!();
                    for (i, rec) in recs.iter().enumerate() {
                        println!(
                            "  {}. [{}] {} (risk: {}, confidence: {:.0}%)",
                            i + 1,
                            rec.category,
                            rec.config_key,
                            rec.risk,
                            rec.confidence * 100.0,
                        );
                        println!("     Current: {}", rec.current_value);
                        println!("     Suggest: {}", rec.suggested_value);
                        println!("     {}", rec.rationale);
                        println!();
                    }
                    println!("  Run `sbh tune --apply` to apply these changes.");
                }
            }
            OutputMode::Json => {
                let recs_json: Vec<Value> = recs
                    .iter()
                    .map(|r| {
                        json!({
                            "category": r.category.to_string(),
                            "config_key": r.config_key,
                            "current_value": r.current_value,
                            "suggested_value": r.suggested_value,
                            "rationale": r.rationale,
                            "confidence": r.confidence,
                            "risk": r.risk.to_string(),
                        })
                    })
                    .collect();
                let payload = json!({
                    "command": "tune",
                    "recommendations": recs_json,
                    "has_database": db.is_some(),
                });
                write_json_line(&payload)?;
            }
        }
        return Ok(());
    }

    // Apply mode.
    if recs.is_empty() {
        match output_mode(cli) {
            OutputMode::Human => {
                println!("No recommendations to apply.");
            }
            OutputMode::Json => {
                let payload = json!({
                    "command": "tune",
                    "action": "apply",
                    "applied": 0,
                });
                write_json_line(&payload)?;
            }
        }
        return Ok(());
    }

    // Show what will be applied.
    // I25: Always require --yes for --apply, regardless of output mode.
    if !args.yes {
        if output_mode(cli) == OutputMode::Human {
            println!("The following changes will be applied:");
            println!();
            for rec in &recs {
                println!(
                    "  {} = {} -> {} ({})",
                    rec.config_key, rec.current_value, rec.suggested_value, rec.risk,
                );
            }
            println!();
            println!("  Config file: {}", config.paths.config_file.display());
            if writeback.is_some() {
                println!(
                    "  Kernel writeback (vm.dirty_*) changes require root and write to {} \
                     (backup-first, reversible via `sbh tune --revert-writeback`).",
                    config.system_tuning.writeback_sysctl_path.display(),
                );
            }
            println!();
        }
        return Err(CliError::User(
            "use --yes to confirm, or review recommendations with `sbh tune` first".to_string(),
        ));
    }

    // Split config-file recommendations from kernel-writeback ones: they apply
    // through entirely different paths (config.toml vs /proc/sys + sysctl.d).
    let config_recs: Vec<&Recommendation> = recs
        .iter()
        .filter(|rec| rec.category != TuningCategory::KernelWriteback)
        .collect();

    // Apply config-file recommendations.
    let config_path = cli.config.clone().unwrap_or_else(Config::default_path);
    if !config_recs.is_empty() {
        let mut toml_value: toml::Value = if config_path.exists() {
            let raw = std::fs::read_to_string(&config_path)
                .map_err(|e| CliError::Runtime(format!("read config: {e}")))?;
            toml::from_str(&raw).map_err(|e| CliError::Runtime(format!("parse config: {e}")))?
        } else {
            toml::Value::Table(toml::map::Map::new())
        };
        for rec in &config_recs {
            set_toml_value(&mut toml_value, &rec.config_key, &rec.suggested_value)?;
        }
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| CliError::Runtime(format!("create config dir: {e}")))?;
        }
        let toml_str = toml::to_string_pretty(&toml_value)
            .map_err(|e| CliError::Runtime(format!("serialize config: {e}")))?;
        std::fs::write(&config_path, &toml_str)
            .map_err(|e| CliError::Runtime(format!("write config: {e}")))?;
    }

    // Apply kernel-writeback tuning (root-gated; never touches config.toml).
    let mut writeback_report: Option<WritebackApplyReport> = None;
    let mut writeback_skipped: Option<String> = None;
    if let Some(ref tuning) = writeback {
        if running_as_root() {
            writeback_report = Some(apply_writeback_tuning(
                &config,
                platform.as_ref(),
                &tuning.plan,
            )?);
        } else {
            writeback_skipped = Some(
                "kernel writeback tuning requires root; re-run `sudo sbh tune --apply --yes`"
                    .to_string(),
            );
        }
    }

    match output_mode(cli) {
        OutputMode::Human => {
            if !config_recs.is_empty() {
                println!("Applied {} config recommendation(s):", config_recs.len());
                for rec in &config_recs {
                    println!(
                        "  {} = {} (was {})",
                        rec.config_key, rec.suggested_value, rec.current_value,
                    );
                }
                println!("Config updated: {}", config_path.display());
            }
            if let Some(report) = &writeback_report {
                println!("Applied kernel writeback tuning:");
                if let Some(ref tuning) = writeback {
                    println!(
                        "  vm.dirty_bytes = {}  vm.dirty_background_bytes = {}",
                        tuning.plan.dirty_bytes, tuning.plan.dirty_background_bytes,
                    );
                }
                println!("  persisted: {}", report.sysctl_path.display());
                if let Some(backup) = &report.backup {
                    println!("  backup: {}", backup.display());
                }
                if report.reload_ok {
                    println!("  validated with `sysctl -p`");
                } else {
                    println!(
                        "  note: `sysctl -p` validation did not run cleanly ({}); the limits \
                         were still applied directly and persisted",
                        report.reload_detail
                    );
                }
                for conflict in &report.conflicts {
                    println!("  warning: {}", writeback_conflict_note(conflict));
                }
            }
            if let Some(message) = &writeback_skipped {
                println!("Skipped kernel writeback tuning: {message}");
            }
        }
        OutputMode::Json => {
            let changes: Vec<Value> = config_recs
                .iter()
                .map(|r| {
                    json!({
                        "config_key": r.config_key,
                        "old_value": r.current_value,
                        "new_value": r.suggested_value,
                    })
                })
                .collect();
            let writeback_json = writeback_report.as_ref().map(|report| {
                json!({
                    "applied": true,
                    "vm.dirty_bytes": writeback.as_ref().map(|t| t.plan.dirty_bytes),
                    "vm.dirty_background_bytes":
                        writeback.as_ref().map(|t| t.plan.dirty_background_bytes),
                    "sysctl_path": report.sysctl_path.to_string_lossy(),
                    "backup": report.backup.as_ref().map(|p| p.to_string_lossy()),
                    "reload_ok": report.reload_ok,
                    "conflicts": report
                        .conflicts
                        .iter()
                        .map(|p| p.to_string_lossy())
                        .collect::<Vec<_>>(),
                })
            });
            let payload = json!({
                "command": "tune",
                "action": "apply",
                "applied": changes.len(),
                "changes": changes,
                "config_path": config_path.to_string_lossy(),
                "writeback": writeback_json,
                "writeback_skipped": writeback_skipped,
            });
            write_json_line(&payload)?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run_config(cli: &Cli, args: &ConfigArgs) -> Result<(), CliError> {
    match &args.command {
        None | Some(ConfigCommand::Path) => {
            // The same resolver `Config::load` uses, so `config path` and
            // `config validate`/`show` can never name different files.
            let resolved = Config::resolve_config_path(cli.config.as_deref());

            match output_mode(cli) {
                OutputMode::Human => {
                    println!("{}", resolved.path.display());
                    println!("  Source: {} ({})", resolved.source, resolved.reason);
                    if let Some(shadowed) = &resolved.shadowed_user_config {
                        println!(
                            "  Ignored: {} (root reads the system config; pass --config to read this one)",
                            shadowed.display()
                        );
                    }
                    if !resolved.exists {
                        println!("  (file does not exist; defaults will be used)");
                    }
                }
                OutputMode::Json => {
                    let mut payload = serde_json::to_value(&resolved)?;
                    payload["command"] = json!("config path");
                    write_json_line(&payload)?;
                }
            }
            Ok(())
        }
        Some(ConfigCommand::Show) => {
            let config = Config::load(cli.config.as_deref())
                .map_err(|e| CliError::Runtime(e.to_string()))?;

            match output_mode(cli) {
                OutputMode::Human => {
                    let toml_str = toml::to_string_pretty(&config)
                        .map_err(|e| CliError::Runtime(format!("serialize config: {e}")))?;
                    println!("{toml_str}");
                }
                OutputMode::Json => {
                    let value = serde_json::to_value(&config)?;
                    let payload = json!({
                        "command": "config show",
                        "config": value,
                    });
                    write_json_line(&payload)?;
                }
            }
            Ok(())
        }
        Some(ConfigCommand::Validate(validate)) => match Config::load(cli.config.as_deref()) {
            Ok(config) => {
                let hash = config
                    .stable_hash()
                    .map_err(|e| CliError::Runtime(e.to_string()))?;
                // Unknown keys never stop a load (the rest of the file still
                // applies) but they are the most common way a config is
                // silently wrong, so validate always lists them and fails on
                // them under --strict / [core] strict_config.
                let strict = validate.strict || config.core.strict_config;
                let unknown = &config.unknown_keys;
                let valid = unknown.is_empty() || !strict;

                match output_mode(cli) {
                    OutputMode::Human => {
                        if unknown.is_empty() {
                            println!("Configuration is valid.");
                        } else if strict {
                            println!(
                                "Configuration is INVALID under strict mode: {} unknown key(s).",
                                unknown.len()
                            );
                        } else {
                            println!(
                                "Configuration is valid, with {} unknown key(s) that are ignored:",
                                unknown.len()
                            );
                        }
                        for key in unknown {
                            println!("  - {key}");
                        }
                        if !unknown.is_empty() && !strict {
                            println!(
                                "  (pass --strict or set [core] strict_config = true to fail on these)"
                            );
                        }
                        println!("  Source: {}", config.paths.config_file.display());
                        println!("  Hash: {hash}");
                    }
                    OutputMode::Json => {
                        let payload = json!({
                            "command": "config validate",
                            "valid": valid,
                            "strict": strict,
                            "path": config.paths.config_file.to_string_lossy(),
                            "hash": hash,
                            "unknown_keys": unknown,
                        });
                        write_json_line(&payload)?;
                    }
                }
                if valid {
                    Ok(())
                } else {
                    Err(CliError::User(format!(
                        "invalid config: {} unknown key(s) under strict mode",
                        unknown.len()
                    )))
                }
            }
            Err(e) => {
                match output_mode(cli) {
                    OutputMode::Human => {
                        eprintln!("Configuration is INVALID: {e}");
                    }
                    OutputMode::Json => {
                        let payload = json!({
                            "command": "config validate",
                            "valid": false,
                            "error": e.to_string(),
                        });
                        write_json_line(&payload)?;
                    }
                }
                Err(CliError::User(format!("invalid config: {e}")))
            }
        },
        Some(ConfigCommand::Diff) => {
            let effective = Config::load(cli.config.as_deref())
                .map_err(|e| CliError::Runtime(e.to_string()))?;
            let defaults = Config::default();

            match output_mode(cli) {
                OutputMode::Human => {
                    if effective == defaults {
                        println!("No differences from defaults.");
                    } else {
                        let eff_json = serde_json::to_value(&effective)?;
                        let def_json = serde_json::to_value(&defaults)?;

                        println!("--- defaults");
                        println!("+++ effective ({})", effective.paths.config_file.display());
                        println!();
                        print_json_diff("", &def_json, &eff_json);
                    }
                }
                OutputMode::Json => {
                    let eff_value = serde_json::to_value(&effective)?;
                    let def_value = serde_json::to_value(&defaults)?;
                    let payload = json!({
                        "command": "config diff",
                        "has_differences": effective != defaults,
                        "effective": eff_value,
                        "defaults": def_value,
                    });
                    write_json_line(&payload)?;
                }
            }
            Ok(())
        }
        Some(ConfigCommand::Reset) => {
            let defaults = Config::default();
            let config_path = cli.config.clone().unwrap_or_else(Config::default_path);

            if let Some(parent) = config_path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| CliError::Runtime(format!("create config dir: {e}")))?;
            }

            let toml_str = toml::to_string_pretty(&defaults)
                .map_err(|e| CliError::Runtime(format!("serialize default config: {e}")))?;
            std::fs::write(&config_path, &toml_str)
                .map_err(|e| CliError::Runtime(format!("write config: {e}")))?;

            match output_mode(cli) {
                OutputMode::Human => {
                    println!("Reset config to defaults: {}", config_path.display());
                }
                OutputMode::Json => {
                    let payload = json!({
                        "command": "config reset",
                        "path": config_path.to_string_lossy(),
                    });
                    write_json_line(&payload)?;
                }
            }
            Ok(())
        }
        Some(ConfigCommand::Set(set_args)) => {
            let config_path = cli.config.clone().unwrap_or_else(Config::default_path);

            // Read existing TOML or start from empty table.
            let mut toml_value: toml::Value = if config_path.exists() {
                let raw = std::fs::read_to_string(&config_path)
                    .map_err(|e| CliError::Runtime(format!("read config: {e}")))?;
                toml::from_str(&raw).map_err(|e| CliError::Runtime(format!("parse config: {e}")))?
            } else {
                toml::Value::Table(toml::map::Map::new())
            };

            // Navigate dot-path and set value.
            set_toml_value(&mut toml_value, &set_args.key, &set_args.value)?;

            let toml_str = toml::to_string_pretty(&toml_value)
                .map_err(|e| CliError::Runtime(format!("serialize config: {e}")))?;

            // Validate BEFORE writing: write to a temp file, validate from it,
            // then atomically rename to the real path.  This prevents a race
            // where a daemon SIGHUP reload picks up an invalid config between
            // the write and the validate step.
            if let Some(parent) = config_path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| CliError::Runtime(format!("create config dir: {e}")))?;
            }
            let tmp_path = config_path.with_extension("toml.tmp");
            std::fs::write(&tmp_path, &toml_str)
                .map_err(|e| CliError::Runtime(format!("write temp config: {e}")))?;

            if let Err(e) = Config::load(Some(&tmp_path)) {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(CliError::User(format!(
                    "refusing to write invalid config: {e}"
                )));
            }

            // Validation passed — atomically replace the real config.
            std::fs::rename(&tmp_path, &config_path)
                .map_err(|e| CliError::Runtime(format!("rename config: {e}")))?;

            // A changed root/ballast/data path must also be writable inside
            // the systemd sandbox, or the daemon will report every deletion
            // as "parent directory not writable".
            let unit_update = sync_systemd_sandbox_after_config_change(cli, &config_path);

            match output_mode(cli) {
                OutputMode::Human => {
                    println!(
                        "Set {} = {} in {}",
                        set_args.key,
                        set_args.value,
                        config_path.display()
                    );
                    if let Some(note) = &unit_update {
                        println!("  {note}");
                    }
                }
                OutputMode::Json => {
                    let payload = json!({
                        "command": "config set",
                        "key": set_args.key,
                        "value": set_args.value,
                        "path": config_path.to_string_lossy(),
                        "valid": true,
                        "systemd_unit": unit_update,
                    });
                    write_json_line(&payload)?;
                }
            }
            Ok(())
        }
    }
}

/// After a config write, keep the systemd unit's `ReadWritePaths=` in step
/// with the paths the daemon now needs. Rewrites the unit (and
/// `daemon-reload`s) when this process may write it; otherwise returns the
/// hint to run bootstrap. `None` when there is no unit or nothing is missing.
fn sync_systemd_sandbox_after_config_change(cli: &Cli, config_path: &Path) -> Option<String> {
    use storage_ballast_helper::daemon::service::SystemdConfig;

    let config = Config::load(Some(config_path)).ok()?;
    let mut notes = Vec::new();
    for user_scope in [false, true] {
        let Ok(systemd) = SystemdConfig::from_env(user_scope) else {
            continue;
        };
        let unit_path = systemd.unit_path();
        let Ok(contents) = std::fs::read_to_string(&unit_path) else {
            continue;
        };
        let required = SystemdConfig::read_write_paths_for(&config, user_scope);
        let missing = SystemdConfig::missing_read_write_paths(&contents, &required);
        if missing.is_empty() {
            continue;
        }
        let listed = missing
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let can_write = user_scope || running_as_root();
        let patched = can_write
            .then(|| SystemdConfig::patch_read_write_paths(&contents, &required))
            .flatten()
            .and_then(|updated| std::fs::write(&unit_path, updated).ok());
        if patched.is_some() {
            let scope_flag: &[&str] = if user_scope { &["--user"] } else { &[] };
            let reloaded = std::process::Command::new("systemctl")
                .args(scope_flag)
                .arg("daemon-reload")
                .status()
                .is_ok_and(|status| status.success());
            notes.push(format!(
                "systemd unit {} now grants ReadWritePaths for {listed}{}",
                unit_path.display(),
                if reloaded {
                    " (daemon-reload done; restart the service to apply)"
                } else {
                    " (run `systemctl daemon-reload` and restart the service)"
                }
            ));
        } else {
            notes.push(format!(
                "systemd unit {} does not grant ReadWritePaths for {listed}; run `sudo sbh bootstrap` to update it",
                unit_path.display()
            ));
        }
        if cli.verbose {
            eprintln!("[SBH-CONFIG] {}", notes.last().map_or("", String::as_str));
        }
    }
    (!notes.is_empty()).then(|| notes.join("; "))
}

/// Set a value in a TOML table using a dot-separated path.
fn set_toml_value(root: &mut toml::Value, dot_path: &str, raw_value: &str) -> Result<(), CliError> {
    let parts: Vec<&str> = dot_path.split('.').collect();
    if parts.is_empty() {
        return Err(CliError::User("empty config key".to_string()));
    }

    let mut current = root;
    for &part in &parts[..parts.len() - 1] {
        current = current
            .as_table_mut()
            .ok_or_else(|| CliError::User(format!("key path component is not a table: {part}")))?
            .entry(part)
            .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    }

    let table = current
        .as_table_mut()
        .ok_or_else(|| CliError::User("parent is not a table".to_string()))?;
    let key = &parts[parts.len() - 1];
    table.insert((*key).to_string(), parse_toml_value(raw_value));

    Ok(())
}

/// Parse a raw string into a TOML value, guessing the type.
fn parse_toml_value(raw: &str) -> toml::Value {
    if let Ok(b) = raw.parse::<bool>() {
        return toml::Value::Boolean(b);
    }
    if let Ok(i) = raw.parse::<i64>() {
        return toml::Value::Integer(i);
    }
    if let Ok(f) = raw.parse::<f64>() {
        return toml::Value::Float(f);
    }
    toml::Value::String(raw.to_string())
}

/// Print a recursive diff of two JSON values.
fn print_json_diff(prefix: &str, default: &Value, effective: &Value) {
    match (default, effective) {
        (Value::Object(def_map), Value::Object(eff_map)) => {
            let mut all_keys: Vec<&String> = def_map.keys().chain(eff_map.keys()).collect();
            all_keys.sort();
            all_keys.dedup();

            for key in all_keys {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };

                match (def_map.get(key), eff_map.get(key)) {
                    (Some(d), Some(e)) if d != e => {
                        print_json_diff(&path, d, e);
                    }
                    (Some(_d), Some(_e)) => {
                        // Equal, skip.
                    }
                    (Some(d), None) => {
                        println!("- {path}: {d}");
                    }
                    (None, Some(e)) => {
                        println!("+ {path}: {e}");
                    }
                    (None, None) => {}
                }
            }
        }
        _ => {
            if default != effective {
                println!("- {prefix}: {default}");
                println!("+ {prefix}: {effective}");
            }
        }
    }
}

/// Every pool the daemon would manage for this config, observed read-only:
/// the same mount selection and skip reasons as the daemon (scan roots,
/// special locations, state and ballast dirs), including the per-mount
/// `<mount>/.sbh/ballast` pools the configured directory alone never shows.
/// Empty when the platform cannot be probed (mentioned in verbose mode).
fn ballast_volume_inventory(
    cli: &Cli,
    config: &Config,
) -> Vec<storage_ballast_helper::ballast::coordinator::PoolInventory> {
    use storage_ballast_helper::ballast::coordinator::BallastPoolCoordinator;
    use storage_ballast_helper::daemon::loop_main::ballast_discovery_paths;
    use storage_ballast_helper::monitor::special_locations::SpecialLocationRegistry;

    let note = |what: &str, err: &dyn std::fmt::Display| {
        if cli.verbose {
            eprintln!("[SBH-BALLAST] volume enumeration skipped: {what}: {err}");
        }
    };
    let platform = match detect_platform() {
        Ok(platform) => platform,
        Err(e) => {
            note("platform", &e);
            return Vec::new();
        }
    };
    let special = match SpecialLocationRegistry::discover(platform.as_ref(), &[]) {
        Ok(registry) => registry,
        Err(e) => {
            note("special locations", &e);
            return Vec::new();
        }
    };
    let paths = ballast_discovery_paths(config, &special);
    match BallastPoolCoordinator::inventory_for_config(
        &config.ballast,
        &paths,
        platform.as_ref(),
        Some(config.paths.ballast_dir.as_path()),
    ) {
        Ok(volumes) => volumes,
        Err(e) => {
            note("mount discovery", &e);
            Vec::new()
        }
    }
}

fn ballast_volume_json(
    volume: &storage_ballast_helper::ballast::coordinator::PoolInventory,
) -> Value {
    json!({
        "mount_point": volume.mount_point.to_string_lossy(),
        "ballast_dir": volume.ballast_dir.to_string_lossy(),
        "fs_type": volume.fs_type,
        "strategy": format!("{:?}", volume.strategy).to_lowercase(),
        "files_available": volume.files_available,
        "files_total": volume.files_total,
        "releasable_bytes": volume.releasable_bytes,
        "health": volume.health.as_str(),
        "orphans": volume
            .orphans
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect::<Vec<_>>(),
        "skipped": volume.skipped,
        "skip_reason": volume.skip_reason,
    })
}

#[allow(clippy::too_many_lines)]
fn run_ballast(cli: &Cli, args: &BallastArgs) -> Result<(), CliError> {
    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;

    let mut manager = BallastManager::new(config.paths.ballast_dir.clone(), config.ballast.clone())
        .map_err(|e| CliError::Runtime(e.to_string()))?;
    manager.set_provision_floor(config.ballast_provision_floor_pct());

    match &args.command {
        None | Some(BallastCommand::Status) => {
            // Read-only: opening the manager neither creates the pool dir
            // nor prunes orphans; volumes are observed without managers.
            let inventory = manager.inventory().to_vec();
            let available = manager.available_count();
            let releasable = manager.releasable_bytes();
            let orphans = manager.orphans();
            let volumes = ballast_volume_inventory(cli, &config);

            match output_mode(cli) {
                OutputMode::Human => {
                    println!("Ballast Pool Status");
                    println!("  Directory: {}", config.paths.ballast_dir.display());
                    println!(
                        "  Configured: {} files x {}",
                        config.ballast.file_count,
                        format_bytes(config.ballast.file_size_bytes)
                    );
                    println!(
                        "  Total pool: {}",
                        format_bytes(ballast_total_pool_bytes(
                            config.ballast.file_count,
                            config.ballast.file_size_bytes,
                        ))
                    );
                    println!(
                        "  Available: {available} files ({} releasable)",
                        format_bytes(releasable)
                    );
                    println!(
                        "  Missing: {} files",
                        config.ballast.file_count.saturating_sub(inventory.len())
                    );
                    println!("  Health: {}", manager.health());
                    if manager.health() == BallastHealth::Empty {
                        println!(
                            "  WARNING: configured reserve is not releasable (0 files present). \
                             Run: sbh ballast provision"
                        );
                    }

                    if !inventory.is_empty() {
                        println!(
                            "\n  {:>5}  {:>10}  {:>10}  {:<10}",
                            "Index", "Size", "Integrity", "Created"
                        );
                        println!("  {}", "-".repeat(45));
                        for file in &inventory {
                            let integrity = if file.integrity_ok { "OK" } else { "CORRUPT" };
                            let created = if file.created_at.is_empty() {
                                "unknown".to_string()
                            } else {
                                file.created_at.chars().take(10).collect()
                            };
                            println!(
                                "  {:>5}  {:>10}  {:>10}  {:<10}",
                                file.index,
                                format_bytes(file.size),
                                integrity,
                                created,
                            );
                        }
                    }
                    if !orphans.is_empty() {
                        println!(
                            "\n  Orphans ({} file(s) outside the configured index range; removed by the next provision/replenish):",
                            orphans.len()
                        );
                        for orphan in &orphans {
                            println!("    {}", orphan.display());
                        }
                    }
                    if !volumes.is_empty() {
                        println!(
                            "\nVolumes ({} the daemon considers for ballast):",
                            volumes.len()
                        );
                        for volume in &volumes {
                            if volume.skipped {
                                println!(
                                    "  {:<24} skipped: {}",
                                    volume.mount_point.display(),
                                    volume.skip_reason.as_deref().unwrap_or("unknown")
                                );
                            } else {
                                println!(
                                    "  {:<24} {:<10} {}/{} files, {} releasable, {}",
                                    volume.mount_point.display(),
                                    volume.health,
                                    volume.files_available,
                                    volume.files_total,
                                    format_bytes(volume.releasable_bytes),
                                    volume.ballast_dir.display()
                                );
                                for orphan in &volume.orphans {
                                    println!("      orphan: {}", orphan.display());
                                }
                            }
                        }
                    }
                }
                OutputMode::Json => {
                    let files: Vec<Value> = inventory
                        .iter()
                        .map(|f| {
                            json!({
                                "index": f.index,
                                "size": f.size,
                                "integrity_ok": f.integrity_ok,
                                "created_at": f.created_at,
                                "path": f.path.to_string_lossy(),
                            })
                        })
                        .collect();

                    let payload = json!({
                        "command": "ballast status",
                        "directory": config.paths.ballast_dir.to_string_lossy(),
                        "configured_count": config.ballast.file_count,
                        "configured_size_bytes": config.ballast.file_size_bytes,
                        "total_pool_bytes": ballast_total_pool_bytes(
                            config.ballast.file_count,
                            config.ballast.file_size_bytes,
                        ),
                        "available_count": available,
                        "releasable_bytes": releasable,
                        "missing_count":
                            config.ballast.file_count.saturating_sub(inventory.len()),
                        "health": manager.health().as_str(),
                        "files": files,
                        "orphans": orphans
                            .iter()
                            .map(|p| p.to_string_lossy().to_string())
                            .collect::<Vec<_>>(),
                        "volumes": volumes.iter().map(ballast_volume_json).collect::<Vec<_>>(),
                    });
                    write_json_line(&payload)?;
                }
            }
            Ok(())
        }
        Some(BallastCommand::Provision) => {
            let platform = detect_platform().map_err(|e| CliError::Runtime(e.to_string()))?;
            let collector = FsStatsCollector::new(platform, std::time::Duration::from_millis(500));
            #[allow(clippy::redundant_clone)]
            let ballast_dir = config.paths.ballast_dir.clone();
            #[allow(clippy::cast_precision_loss)]
            let free_check = move || -> f64 {
                collector.collect(&ballast_dir).map_or(0.0, |s| {
                    if s.total_bytes == 0 {
                        0.0
                    } else {
                        s.available_bytes as f64 / s.total_bytes as f64 * 100.0
                    }
                })
            };
            let report = manager
                .provision(Some(&free_check))
                .map_err(|e| CliError::Runtime(e.to_string()))?;

            match output_mode(cli) {
                OutputMode::Human => {
                    println!("Ballast provision complete:");
                    println!("  Ballast dir: {}", config.paths.ballast_dir.display());
                    println!("  Config: {}", config.paths.config_file.display());
                    println!("  Files created: {}", report.files_created);
                    println!("  Files skipped (existing): {}", report.files_skipped);
                    if report.skipped_for_floor > 0 {
                        println!(
                            "  Files skipped (headroom floor {:.1}% free; volume now {}): {}",
                            report.floor_pct,
                            report
                                .free_pct_after
                                .map_or_else(|| "unknown".to_string(), |pct| format!("{pct:.1}%")),
                            report.skipped_for_floor
                        );
                    }
                    println!(
                        "  Total bytes allocated: {}",
                        format_bytes(report.total_bytes)
                    );
                    if !report.errors.is_empty() {
                        println!("  Errors:");
                        for err in &report.errors {
                            eprintln!("    {err}");
                        }
                    }
                }
                OutputMode::Json => {
                    let payload = json!({
                        "command": "ballast provision",
                        "ballast_dir": config.paths.ballast_dir.to_string_lossy(),
                        "config_path": config.paths.config_file.to_string_lossy(),
                        "files_created": report.files_created,
                        "files_skipped": report.files_skipped,
                        "skipped_for_floor": report.skipped_for_floor,
                        "floor_pct": report.floor_pct,
                        "free_pct_after": report.free_pct_after,
                        "total_bytes": report.total_bytes,
                        "errors": report.errors,
                    });
                    write_json_line(&payload)?;
                }
            }

            if report.errors.is_empty() {
                Ok(())
            } else {
                Err(CliError::Partial(format!(
                    "{} errors during provisioning",
                    report.errors.len()
                )))
            }
        }
        Some(BallastCommand::Release(release_args)) => {
            let count = release_args.count;
            let available = manager.available_count();

            if count == 0 {
                return Err(CliError::User("release count must be > 0".to_string()));
            }
            if available == 0 {
                return Err(CliError::User(
                    "no ballast files available to release".to_string(),
                ));
            }

            let report = manager
                .release(count)
                .map_err(|e| CliError::Runtime(e.to_string()))?;

            match output_mode(cli) {
                OutputMode::Human => {
                    println!("Ballast release complete:");
                    println!(
                        "  Files released: {} of {} requested",
                        report.files_released, count
                    );
                    println!("  Bytes freed: {}", format_bytes(report.bytes_freed));
                    println!("  Remaining: {} files", manager.available_count());
                    if !report.warnings.is_empty() {
                        println!("  Warnings:");
                        for warning in &report.warnings {
                            eprintln!("    {warning}");
                        }
                    }
                    if !report.errors.is_empty() {
                        println!("  Errors:");
                        for err in &report.errors {
                            eprintln!("    {err}");
                        }
                    }
                }
                OutputMode::Json => {
                    let payload = json!({
                        "command": "ballast release",
                        "requested": count,
                        "files_released": report.files_released,
                        "bytes_freed": report.bytes_freed,
                        "remaining": manager.available_count(),
                        "warnings": report.warnings,
                        "errors": report.errors,
                    });
                    write_json_line(&payload)?;
                }
            }

            if report.errors.is_empty() {
                Ok(())
            } else {
                Err(CliError::Partial(format!(
                    "{} errors during release",
                    report.errors.len()
                )))
            }
        }
        Some(BallastCommand::Replenish) => {
            let platform = detect_platform().map_err(|e| CliError::Runtime(e.to_string()))?;
            let collector = FsStatsCollector::new(platform, std::time::Duration::from_millis(500));
            #[allow(clippy::redundant_clone)]
            let ballast_dir = config.paths.ballast_dir.clone();
            #[allow(clippy::cast_precision_loss)]
            let free_check = move || -> f64 {
                collector.collect(&ballast_dir).map_or(0.0, |s| {
                    if s.total_bytes == 0 {
                        0.0
                    } else {
                        s.available_bytes as f64 / s.total_bytes as f64 * 100.0
                    }
                })
            };
            let report = manager
                .replenish(Some(&free_check))
                .map_err(|e| CliError::Runtime(e.to_string()))?;

            match output_mode(cli) {
                OutputMode::Human => {
                    println!("Ballast replenish complete:");
                    println!("  Files recreated: {}", report.files_created);
                    println!("  Files skipped (existing): {}", report.files_skipped);
                    if report.skipped_for_floor > 0 {
                        println!(
                            "  Files skipped (headroom floor {:.1}% free; volume now {}): {}",
                            report.floor_pct,
                            report
                                .free_pct_after
                                .map_or_else(|| "unknown".to_string(), |pct| format!("{pct:.1}%")),
                            report.skipped_for_floor
                        );
                    }
                    println!(
                        "  Total bytes allocated: {}",
                        format_bytes(report.total_bytes)
                    );
                    if !report.errors.is_empty() {
                        println!("  Errors:");
                        for err in &report.errors {
                            eprintln!("    {err}");
                        }
                    }
                }
                OutputMode::Json => {
                    let payload = json!({
                        "command": "ballast replenish",
                        "files_created": report.files_created,
                        "files_skipped": report.files_skipped,
                        "skipped_for_floor": report.skipped_for_floor,
                        "floor_pct": report.floor_pct,
                        "free_pct_after": report.free_pct_after,
                        "total_bytes": report.total_bytes,
                        "errors": report.errors,
                    });
                    write_json_line(&payload)?;
                }
            }

            if report.errors.is_empty() {
                Ok(())
            } else {
                Err(CliError::Partial(format!(
                    "{} errors during replenish",
                    report.errors.len()
                )))
            }
        }
        Some(BallastCommand::Verify) => {
            let report = manager
                .verify()
                .map_err(|e| CliError::Runtime(e.to_string()))?;

            match output_mode(cli) {
                OutputMode::Human => {
                    println!("Ballast verification:");
                    println!("  Files checked: {}", report.files_checked);
                    println!("  OK: {}", report.files_ok);
                    println!("  Corrupted: {}", report.files_corrupted);
                    println!("  Missing: {}", report.files_missing);

                    if !report.details.is_empty() {
                        println!("\n  Details:");
                        for detail in &report.details {
                            println!("    {detail}");
                        }
                    }

                    if report.files_corrupted > 0 || report.files_missing > 0 {
                        println!(
                            "\n  Run 'sbh ballast provision' to recreate missing/corrupted files."
                        );
                    }
                }
                OutputMode::Json => {
                    let payload = json!({
                        "command": "ballast verify",
                        "files_checked": report.files_checked,
                        "files_ok": report.files_ok,
                        "files_corrupted": report.files_corrupted,
                        "files_missing": report.files_missing,
                        "details": report.details,
                    });
                    write_json_line(&payload)?;
                }
            }

            if report.files_corrupted > 0 {
                Err(CliError::Partial(format!(
                    "{} corrupted ballast files",
                    report.files_corrupted
                )))
            } else {
                Ok(())
            }
        }
    }
}

const fn normalize_refresh_ms(refresh_ms: u64) -> u64 {
    if refresh_ms < LIVE_REFRESH_MIN_MS {
        LIVE_REFRESH_MIN_MS
    } else {
        refresh_ms
    }
}

fn validate_live_mode_output(
    mode: OutputMode,
    command: &str,
    allow_json_live: bool,
) -> Result<(), CliError> {
    if mode == OutputMode::Json && !allow_json_live {
        return Err(CliError::User(format!(
            "{command}: live mode does not support --json; use `sbh status --json` for snapshots"
        )));
    }
    Ok(())
}

fn run_live_status_loop(
    cli: &Cli,
    refresh_ms: u64,
    command: &str,
    allow_json_live: bool,
) -> Result<(), CliError> {
    let mode = output_mode(cli);
    validate_live_mode_output(mode, command, allow_json_live)?;
    let refresh_ms = normalize_refresh_ms(refresh_ms);

    loop {
        if mode == OutputMode::Json {
            render_status(cli)?;
        } else {
            print!("\x1B[2J\x1B[H");
            io::stdout().flush()?;
            render_status(cli)?;
            println!("\nRefreshing every {refresh_ms}ms (Ctrl-C to exit)");
        }
        io::stdout().flush()?;
        std::thread::sleep(std::time::Duration::from_millis(refresh_ms));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DashboardRuntimeSelection {
    Legacy,
    New,
}

/// Explains *why* a particular runtime was selected (for diagnostics / verbose output).
#[derive(Debug, Clone, PartialEq, Eq)]
enum DashboardSelectionReason {
    KillSwitchEnv,
    KillSwitchConfig,
    CliFlagLegacy,
    CliFlagNew,
    EnvVarMode,
    ConfigFileMode,
    HardcodedDefault,
}

impl std::fmt::Display for DashboardSelectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KillSwitchEnv => f.write_str("SBH_DASHBOARD_KILL_SWITCH=true (env)"),
            Self::KillSwitchConfig => f.write_str("dashboard.kill_switch=true (config)"),
            Self::CliFlagLegacy => f.write_str("--legacy-dashboard (CLI flag)"),
            Self::CliFlagNew => f.write_str("--new-dashboard (CLI flag)"),
            Self::EnvVarMode => f.write_str("SBH_DASHBOARD_MODE (env)"),
            Self::ConfigFileMode => f.write_str("dashboard.mode (config)"),
            Self::HardcodedDefault => f.write_str("hardcoded default (new)"),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct DashboardRuntimeRequest {
    refresh_ms: u64,
    state_file: PathBuf,
    monitor_paths: Vec<PathBuf>,
    selection: DashboardRuntimeSelection,
    reason: DashboardSelectionReason,
    sqlite_db: Option<PathBuf>,
    jsonl_log: Option<PathBuf>,
    /// `--start-screen`, validated by the cockpit runtime (it is the only
    /// consumer, and a lean build refuses it with the feature message).
    start_screen: Option<String>,
    /// `[ballast]` settings and the provisioning floor: what the cockpit
    /// needs to release or replenish a pool itself when no daemon holds it.
    ballast: storage_ballast_helper::core::config::BallastConfig,
    provision_floor_pct: f64,
    /// `--replay <file>`, `--from`, `--speed`: validated by the cockpit runtime.
    replay: Option<PathBuf>,
    replay_from: Option<String>,
    replay_speed: String,
}

/// Resolve dashboard runtime using priority chain:
///
/// 1. `SBH_DASHBOARD_KILL_SWITCH=true` env var → Legacy
/// 2. `dashboard.kill_switch=true` config field → Legacy
/// 3. `--legacy-dashboard` CLI flag → Legacy
/// 4. `--new-dashboard` CLI flag → New
/// 5. `SBH_DASHBOARD_MODE` env var → parsed mode
/// 6. `dashboard.mode` config field → configured mode
/// 7. Hardcoded default → New
fn resolve_dashboard_runtime(
    args: &DashboardArgs,
    config: &Config,
) -> (DashboardRuntimeSelection, DashboardSelectionReason) {
    use storage_ballast_helper::core::config::DashboardMode;

    // 1. Env var kill switch (highest priority — emergency override).
    if std::env::var("SBH_DASHBOARD_KILL_SWITCH")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .and_then(|v| v.parse::<bool>().ok())
        .unwrap_or(false)
    {
        return (
            DashboardRuntimeSelection::Legacy,
            DashboardSelectionReason::KillSwitchEnv,
        );
    }

    // 2. Config kill switch.
    if config.dashboard.kill_switch {
        return (
            DashboardRuntimeSelection::Legacy,
            DashboardSelectionReason::KillSwitchConfig,
        );
    }

    // 3. CLI flag: --legacy-dashboard.
    if args.legacy_dashboard {
        return (
            DashboardRuntimeSelection::Legacy,
            DashboardSelectionReason::CliFlagLegacy,
        );
    }

    // 4. CLI flag: --new-dashboard.
    if args.new_dashboard {
        return (
            DashboardRuntimeSelection::New,
            DashboardSelectionReason::CliFlagNew,
        );
    }

    // 5. Env var mode override (checked at config load time but re-check raw env here
    //    to distinguish source from config-file).
    if let Ok(raw) = std::env::var("SBH_DASHBOARD_MODE")
        && let Ok(mode) = raw.parse::<DashboardMode>()
    {
        let selection = match mode {
            DashboardMode::Legacy => DashboardRuntimeSelection::Legacy,
            DashboardMode::New => DashboardRuntimeSelection::New,
        };
        return (selection, DashboardSelectionReason::EnvVarMode);
    }

    // 6. Config file mode.
    let selection = match config.dashboard.mode {
        DashboardMode::Legacy => DashboardRuntimeSelection::Legacy,
        DashboardMode::New => DashboardRuntimeSelection::New,
    };
    // Distinguish config-file from hardcoded default by checking if the config
    // actually has a dashboard section that differs from the default.
    if config.dashboard.mode != DashboardMode::default() {
        return (selection, DashboardSelectionReason::ConfigFileMode);
    }

    // 7. Hardcoded default.
    (
        DashboardRuntimeSelection::New,
        DashboardSelectionReason::HardcodedDefault,
    )
}

fn run_dashboard_runtime(cli: &Cli, request: &DashboardRuntimeRequest) -> Result<(), CliError> {
    match request.selection {
        DashboardRuntimeSelection::Legacy => {
            run_live_status_loop(cli, request.refresh_ms, "dashboard", false)
        }
        DashboardRuntimeSelection::New => run_new_dashboard_runtime(cli, request),
    }
}

#[cfg(feature = "tui")]
fn run_new_dashboard_runtime(cli: &Cli, request: &DashboardRuntimeRequest) -> Result<(), CliError> {
    use storage_ballast_helper::tui::{
        self, DashboardRuntimeConfig as NewDashboardRuntimeConfig, DashboardRuntimeMode,
    };

    if cli.verbose {
        eprintln!("[dashboard] starting cockpit runtime ({})", request.reason);
    }

    let start_screen = request
        .start_screen
        .as_deref()
        .map(str::parse::<tui::preferences::StartScreen>)
        .transpose()
        .map_err(CliError::User)?;
    let replay = request
        .replay
        .as_ref()
        .map(|path| -> Result<tui::ReplayConfig, CliError> {
            let speed = request
                .replay_speed
                .parse::<tui::ReplaySpeed>()
                .map_err(CliError::User)?;
            if let Some(from) = request.replay_from.as_deref()
                && chrono::DateTime::parse_from_rfc3339(from).is_err()
            {
                return Err(CliError::User(format!(
                    "--from {from:?} is not an RFC 3339 timestamp (example: 2026-08-30T10:00:00Z)"
                )));
            }
            if !path.is_file() {
                return Err(CliError::User(format!(
                    "--replay {}: not a readable file",
                    path.display()
                )));
            }
            Ok(tui::ReplayConfig {
                path: path.clone(),
                from: request.replay_from.clone(),
                speed,
            })
        })
        .transpose()?;

    // The cockpit takes over the terminal; a pipe or a file gets the plain
    // live status view instead, unless the cockpit was asked for by name.
    if !io::stdout().is_terminal() {
        let explicit = matches!(request.reason, DashboardSelectionReason::CliFlagNew)
            || start_screen.is_some()
            || replay.is_some();
        if explicit {
            return Err(CliError::Runtime(
                "the cockpit needs an interactive terminal: stdout is not a TTY. Drop \
                 --new-dashboard/--start-screen for the live status view, or use `sbh status`"
                    .to_string(),
            ));
        }
        eprintln!(
            "[SBH-DASHBOARD] stdout is not a terminal; showing the live status view (the cockpit needs a TTY)"
        );
        return run_live_status_loop(cli, request.refresh_ms, "dashboard", false);
    }

    let config = NewDashboardRuntimeConfig {
        state_file: request.state_file.clone(),
        refresh: std::time::Duration::from_millis(request.refresh_ms),
        monitor_paths: request.monitor_paths.clone(),
        mode: DashboardRuntimeMode::NewCockpit,
        sqlite_db: request.sqlite_db.clone(),
        jsonl_log: request.jsonl_log.clone(),
        start_screen,
        ballast: Some(tui::BallastFallback {
            config: request.ballast.clone(),
            provision_floor_pct: request.provision_floor_pct,
        }),
        replay,
    };
    tui::run_dashboard(&config)
        .map_err(|e| CliError::Runtime(format!("dashboard runtime failure: {e}")))
}

/// Without the `tui` feature the cockpit cannot run. An explicit
/// `--new-dashboard` is an error the operator asked for; every other route to
/// the new runtime (default, config, env) degrades to the live status view so
/// `sbh dashboard` on a lean build still shows something useful.
#[cfg(not(feature = "tui"))]
fn run_new_dashboard_runtime(cli: &Cli, request: &DashboardRuntimeRequest) -> Result<(), CliError> {
    if let Some(error) = lean_build_dashboard_refusal(&request.reason) {
        return Err(error);
    }
    if request.start_screen.is_some() || request.replay.is_some() {
        return Err(CliError::Runtime(
            "TUI feature not enabled. --start-screen and --replay need the cockpit; rebuild with --features tui"
                .to_string(),
        ));
    }
    eprintln!(
        "[SBH-DASHBOARD] this binary was built without the tui feature; showing the live status view (rebuild with --features tui for the cockpit)"
    );
    run_live_status_loop(cli, request.refresh_ms, "dashboard", false)
}

/// The one case a lean build refuses outright: the operator explicitly
/// asked for the cockpit with `--new-dashboard`.
#[cfg(not(feature = "tui"))]
fn lean_build_dashboard_refusal(reason: &DashboardSelectionReason) -> Option<CliError> {
    matches!(reason, DashboardSelectionReason::CliFlagNew).then(|| {
        CliError::Runtime(
            "TUI feature not enabled. Rebuild with --features tui, or omit --new-dashboard to use the live status view"
                .to_string(),
        )
    })
}

fn run_dashboard(cli: &Cli, args: &DashboardArgs) -> Result<(), CliError> {
    let mode = output_mode(cli);
    validate_live_mode_output(mode, "dashboard", false)?;

    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;
    let (selection, reason) = resolve_dashboard_runtime(args, &config);

    if cli.verbose {
        eprintln!("[dashboard] runtime={selection:?}, reason={reason}");
    }

    let provision_floor_pct = config.ballast_provision_floor_pct();
    let request = DashboardRuntimeRequest {
        refresh_ms: normalize_refresh_ms(args.refresh_ms),
        state_file: config.paths.state_file.clone(),
        monitor_paths: config.scanner.root_paths,
        selection,
        reason,
        sqlite_db: Some(config.paths.sqlite_db.clone()),
        jsonl_log: Some(config.paths.jsonl_log),
        start_screen: args.start_screen.clone(),
        provision_floor_pct,
        ballast: config.ballast,
        replay: args.replay.clone(),
        replay_from: args.from.clone(),
        replay_speed: args.speed.clone(),
    };

    run_dashboard_runtime(cli, &request)
}

#[derive(Debug, Clone, Serialize)]
struct PalDoctorReport {
    platform: String,
    implemented: usize,
    not_implemented: usize,
    failed: usize,
    skipped: usize,
    checks: Vec<DoctorCheck>,
    methods: Vec<PalDoctorProbe>,
    follow_up: Vec<PalDoctorFollowUp>,
}

#[derive(Debug, Clone, Serialize)]
struct ReleaseDoctorReport {
    ok: bool,
    passed: usize,
    warnings: usize,
    failed: usize,
    repository: &'static str,
    notary_profile: &'static str,
    required_github_secrets: Vec<&'static str>,
    checks: Vec<DoctorCheck>,
    setup_steps: Vec<ReleaseDoctorSetupStep>,
}

#[derive(Debug, Clone, Serialize)]
struct ReleaseDoctorSetupStep {
    id: &'static str,
    title: &'static str,
    reason: &'static str,
    docs: &'static str,
    commands: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorCheck {
    id: &'static str,
    title: &'static str,
    status: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PalDoctorProbe {
    method: &'static str,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    bead: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PalDoctorFollowUp {
    id: &'static str,
    title: &'static str,
    severity: &'static str,
    message: String,
    docs: &'static str,
    recheck_command: &'static str,
    steps: Vec<String>,
}

/// Human `doctor` output: each requested report in order, blank-line
/// separated.
fn print_doctor_reports(
    pal_report: Option<&PalDoctorReport>,
    release_report: Option<&ReleaseDoctorReport>,
    system_checks: Option<&[DoctorCheck]>,
    env_checks: Option<&[DoctorCheck]>,
    service_checks: Option<&[DoctorCheck]>,
) {
    let mut printed = false;
    let separate = |printed: &mut bool| {
        if *printed {
            println!();
        }
        *printed = true;
    };
    if let Some(report) = pal_report {
        separate(&mut printed);
        print_pal_doctor_report(report);
    }
    if let Some(report) = release_report {
        separate(&mut printed);
        print_release_doctor_report(report);
    }
    for (title, checks) in [
        ("System tuning checks:", system_checks),
        ("Install footprint checks:", env_checks),
        ("Service unit checks:", service_checks),
    ] {
        if let Some(checks) = checks {
            separate(&mut printed);
            println!("{title}");
            print_doctor_checks(checks);
        }
    }
}

fn run_doctor(cli: &Cli, args: &DoctorArgs) -> Result<(), CliError> {
    if !args.pal && !args.release && !args.system && !args.env && !args.service {
        return Err(CliError::User(
            "specify a diagnostic target, for example: sbh doctor --pal, --system, --env, --service, or --release"
                .to_string(),
        ));
    }
    let env_checks = args.env.then(env_doctor_checks);
    let service_checks = if args.service {
        Some(service_doctor_checks(args.user)?)
    } else {
        None
    };

    let pal_report = if args.pal {
        let platform = detect_platform().map_err(|e| CliError::Runtime(e.to_string()))?;
        Some(pal_doctor_report(platform.as_ref()))
    } else {
        None
    };
    let release_report = args.release.then(release_doctor_report);
    let system_checks = if args.system {
        let platform = detect_platform().map_err(|e| CliError::Runtime(e.to_string()))?;
        let config =
            Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;
        let pools = reserve_pools(cli, &config);
        let bursts = BurstStats::load_or_new(BurstStats::snapshot_path_for_state_file(
            &config.paths.state_file,
        ));
        Some(system_doctor_checks(
            platform.as_ref(),
            &config,
            &bursts,
            &pools,
        ))
    } else {
        None
    };

    match output_mode(cli) {
        OutputMode::Json => {
            // Preserve the single-target top-level shapes; nest only when targets
            // are combined.
            let payload = match (args.pal, args.release, args.system, args.env, args.service) {
                (true, false, false, false, false) => serde_json::to_value(&pal_report)?,
                (false, true, false, false, false) => serde_json::to_value(&release_report)?,
                (false, false, true, false, false) => {
                    json!({ "system": { "checks": system_checks } })
                }
                (false, false, false, true, false) => json!({ "env": { "checks": env_checks } }),
                (false, false, false, false, true) => {
                    json!({ "service": { "checks": service_checks } })
                }
                _ => {
                    let mut obj = serde_json::Map::new();
                    if let Some(report) = &pal_report {
                        obj.insert("pal".to_string(), serde_json::to_value(report)?);
                    }
                    if let Some(report) = &release_report {
                        obj.insert("release".to_string(), serde_json::to_value(report)?);
                    }
                    if let Some(checks) = &system_checks {
                        obj.insert("system".to_string(), json!({ "checks": checks }));
                    }
                    if let Some(checks) = &env_checks {
                        obj.insert("env".to_string(), json!({ "checks": checks }));
                    }
                    if let Some(checks) = &service_checks {
                        obj.insert("service".to_string(), json!({ "checks": checks }));
                    }
                    Value::Object(obj)
                }
            };
            write_json_line(&payload)?;
        }
        OutputMode::Human => print_doctor_reports(
            pal_report.as_ref(),
            release_report.as_ref(),
            system_checks.as_deref(),
            env_checks.as_deref(),
            service_checks.as_deref(),
        ),
    }

    let failed = pal_report
        .as_ref()
        .is_some_and(|report| doctor_checks_have_failures(&report.checks))
        || release_report
            .as_ref()
            .is_some_and(|report| doctor_checks_have_failures(&report.checks))
        || system_checks
            .as_ref()
            .is_some_and(|checks| doctor_checks_have_failures(checks))
        || env_checks
            .as_ref()
            .is_some_and(|checks| doctor_checks_have_failures(checks))
        || service_checks
            .as_ref()
            .is_some_and(|checks| doctor_checks_have_failures(checks));
    if failed {
        return Err(CliError::User(
            "doctor checks failed; inspect the report above for remediation steps".to_string(),
        ));
    }

    Ok(())
}

/// Host-level tuning diagnostics (kernel writeback / dirty-page limits) plus
/// emergency-reserve integrity.
fn system_doctor_checks(
    platform: &dyn Platform,
    config: &Config,
    bursts: &BurstStats,
    pools: &[ReservePool],
) -> Vec<DoctorCheck> {
    let mut checks = vec![
        writeback_doctor_check(platform, config),
        ballast_reserve_doctor_check(config),
    ];
    checks.extend(reserve_coverage_doctor_checks(config, bursts, pools));
    checks.push(logging_placement_doctor_check(platform, config, pools));
    checks.extend(reclaim_capability_doctor_checks(config));
    checks
}

/// bd-rc-master-ajg1.7.4: the activity database, JSONL log and state file
/// against the mounts sbh reclaims (scan roots, special locations, ballast
/// pools). WARN when they share a mount, FAIL when that mount is at Orange
/// or worse right now (from a fresh daemon state), PASS otherwise.
fn logging_placement_doctor_check(
    platform: &dyn Platform,
    config: &Config,
    pools: &[ReservePool],
) -> DoctorCheck {
    use storage_ballast_helper::monitor::special_locations::SpecialLocationRegistry;
    let mount_of = |path: &Path| {
        platform
            .fs_stats(&nearest_existing_ancestor(path))
            .ok()
            .map(|stats| stats.mount_point)
    };
    let mut monitored: std::collections::BTreeSet<PathBuf> = config
        .scanner
        .root_paths
        .iter()
        .filter_map(|root| mount_of(root))
        .collect();
    if let Ok(special) = SpecialLocationRegistry::discover(platform, &[]) {
        monitored.extend(special.all().iter().filter_map(|l| mount_of(&l.path)));
    }
    monitored.extend(pools.iter().map(|pool| pool.mount.clone()));
    let placement = assess_logging_placement(
        mount_of,
        &[
            config.paths.sqlite_db.as_path(),
            config.paths.jsonl_log.as_path(),
            config.paths.state_file.as_path(),
        ],
        &monitored,
    );
    if !placement.on_monitored_fs {
        return doctor_check(
            "logging.on_monitored_fs",
            "Daemon files off the reclaimed volumes",
            "PASS",
            format!(
                "activity database, JSONL log and state file are on {}, which sbh does not reclaim",
                placement.device
            ),
            None,
        );
    }
    let level = read_fresh_daemon_state(&config.paths.state_file)
        .and_then(|state| {
            let records: Vec<MountStateRecord> =
                serde_json::from_value(state.get("mount_controllers").cloned()?).ok()?;
            records
                .into_iter()
                .find(|record| record.mount == placement.device)
                .map(|record| record.level)
        })
        .unwrap_or_else(|| "unknown".to_string());
    let pressured = matches!(level.as_str(), "orange" | "red" | "critical");
    doctor_check(
        "logging.on_monitored_fs",
        "Daemon files off the reclaimed volumes",
        if pressured { "FAIL" } else { "WARN" },
        format!(
            "{} share {} with a reclaim target (level {level}): a full volume breaks the \
             logger exactly when it matters{}",
            placement.paths.join(", "),
            placement.device,
            if pressured {
                "; the daemon mirrors JSONL to the RAM fallback while it stays pressured"
            } else {
                ""
            }
        ),
        Some(format!(
            "Move {} to a volume sbh does not reclaim (`[paths]` in the config), or accept \
             degraded logging under pressure.",
            placement.paths.join(", ")
        )),
    )
}

/// A ballast pool as the reserve-sizing checks see it: the mount and what
/// is releasable there right now.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReservePool {
    mount: PathBuf,
    releasable_bytes: u64,
}

/// Every pool the daemon would manage, reduced to what reserve sizing needs.
fn reserve_pools(cli: &Cli, config: &Config) -> Vec<ReservePool> {
    ballast_volume_inventory(cli, config)
        .into_iter()
        .filter(|volume| !volume.skipped)
        .map(|volume| ReservePool {
            mount: volume.mount_point,
            releasable_bytes: volume.releasable_bytes,
        })
        .collect()
}

/// bd-rc-master-ajg1.2.18: each pool's releasable bytes against the reserve
/// the mount's observed write bursts require. FAIL below full coverage; a
/// mount without burst windows yet passes with a note.
fn reserve_coverage_doctor_checks(
    config: &Config,
    bursts: &BurstStats,
    pools: &[ReservePool],
) -> Vec<DoctorCheck> {
    if pools.is_empty() {
        return vec![doctor_check(
            "ballast.reserve_coverage",
            "Reserve covers observed write bursts",
            "PASS",
            "no ballast pool to size (see ballast.reserve)",
            None,
        )];
    }
    pools
        .iter()
        .map(|pool| {
            let mount_key = pool.mount.to_string_lossy();
            let file_size = config.ballast.effective_file_size_bytes(&mount_key);
            let Some(estimate) = bursts.estimate(&pool.mount, file_size) else {
                return doctor_check(
                    "ballast.reserve_coverage",
                    "Reserve covers observed write bursts",
                    "PASS",
                    format!(
                        "{mount_key}: no reaction windows observed yet; the daemon sizes the \
                         reserve after its first {}-second window",
                        bursts.reaction_window().secs().round()
                    ),
                    None,
                );
            };
            #[allow(clippy::cast_precision_loss)]
            let coverage = if estimate.bytes == 0 {
                1.0
            } else {
                pool.releasable_bytes as f64 / estimate.bytes as f64
            };
            let detail = format!(
                "{mount_key}: {} releasable vs {} required ({} bursts of at most {} per {:.0} s \
                 window, {} windows, {} estimate): coverage {coverage:.2}",
                format_bytes(pool.releasable_bytes),
                format_bytes(estimate.bytes),
                "99% of",
                format_bytes(estimate.burst_q99_bytes),
                estimate.window_secs,
                estimate.windows,
                estimate.method.as_str(),
            );
            if coverage >= 1.0 {
                doctor_check(
                    "ballast.reserve_coverage",
                    "Reserve covers observed write bursts",
                    "PASS",
                    detail,
                    None,
                )
            } else {
                doctor_check(
                    "ballast.reserve_coverage",
                    "Reserve covers observed write bursts",
                    "FAIL",
                    detail,
                    Some(format!(
                        "Raise the pool to {} files of {} (`sbh tune` recommends it; `sbh tune \
                         --apply --yes` writes it), then `sbh ballast provision`.",
                        estimate.file_count(file_size),
                        format_bytes(file_size),
                    )),
                )
            }
        })
        .collect()
}

/// bd-rc-master-ajg1.2.18: `file_count` per pool from the observed bursts,
/// `ceil(reserve / file_size)`, when it differs from the configured count.
/// One pool without an override is tuned through `ballast.file_count`; any
/// other pool through its `ballast.overrides` entry. A mount whose path
/// contains a dot cannot be addressed by the dotted key `tune --apply`
/// writes, so it is left to the operator.
fn burst_reserve_recommendations(
    config: &Config,
    bursts: &BurstStats,
    pools: &[ReservePool],
) -> Vec<Recommendation> {
    let mut recs = Vec::new();
    for pool in pools {
        let mount_key = pool.mount.to_string_lossy().into_owned();
        let file_size = config.ballast.effective_file_size_bytes(&mount_key);
        let Some(estimate) = bursts.estimate(&pool.mount, file_size) else {
            continue;
        };
        if file_size == 0 {
            continue;
        }
        let current = config.ballast.effective_file_count(&mount_key) as u64;
        let suggested = estimate.file_count(file_size);
        if suggested == current {
            continue;
        }
        let has_override = config
            .ballast
            .overrides
            .contains_key(mount_key.trim_end_matches('/'));
        let config_key = if pools.len() == 1 && !has_override {
            "ballast.file_count".to_string()
        } else if mount_key.contains('.') {
            continue;
        } else {
            format!(
                "ballast.overrides.{}.file_count",
                mount_key.trim_end_matches('/')
            )
        };
        let confidence = match estimate.method {
            storage_ballast_helper::monitor::burst::ReserveMethod::Quantile => 0.8,
            storage_ballast_helper::monitor::burst::ReserveMethod::Tail => 0.55,
            storage_ballast_helper::monitor::burst::ReserveMethod::Floor => 0.3,
        };
        recs.push(Recommendation {
            category: TuningCategory::Ballast,
            config_key,
            current_value: current.to_string(),
            suggested_value: suggested.to_string(),
            rationale: format!(
                "{mount_key}: 99% of {:.0}-second reaction windows grew by at most {} ({} windows, \
                 {} estimate); the reserve should hold {} = {suggested} files of {}",
                estimate.window_secs,
                format_bytes(estimate.burst_q99_bytes),
                estimate.windows,
                estimate.method.as_str(),
                format_bytes(estimate.bytes),
                format_bytes(file_size),
            ),
            confidence,
            risk: if suggested > current {
                TuningRisk::Low
            } else {
                TuningRisk::Medium
            },
        });
    }
    recs
}

/// #16: fail loudly when a ballast reserve is configured but not actually
/// releasable. A dashboard reading configured totals alone can believe a full
/// reserve exists after every file has been released or lost — exactly when
/// the reserve is needed most.
fn ballast_reserve_doctor_check(config: &Config) -> DoctorCheck {
    let availability = BallastAvailability::observe(&config.paths.ballast_dir, &config.ballast);
    match availability.health {
        BallastHealth::Unconfigured => doctor_check(
            "ballast.reserve",
            "Ballast emergency reserve",
            "PASS",
            "no ballast reserve configured (ballast.file_count or file_size_bytes is 0)",
            None,
        ),
        BallastHealth::Ok => doctor_check(
            "ballast.reserve",
            "Ballast emergency reserve",
            "PASS",
            format!(
                "{} of {} configured files present ({} releasable)",
                availability.available_count,
                availability.configured_count,
                format_bytes(availability.releasable_bytes),
            ),
            None,
        ),
        BallastHealth::Degraded => doctor_check(
            "ballast.reserve",
            "Ballast emergency reserve",
            "WARN",
            format!(
                "only {} of {} configured files present ({} releasable of {} configured)",
                availability.available_count,
                availability.configured_count,
                format_bytes(availability.releasable_bytes),
                format_bytes(availability.configured_pool_bytes),
            ),
            Some(format!(
                "Run `sbh ballast replenish` (or `sbh ballast provision`); files are created \
                 one at a time while the volume stays above the {:.1}% headroom floor.",
                config.ballast_provision_floor_pct()
            )),
        ),
        BallastHealth::Empty => doctor_check(
            "ballast.reserve",
            "Ballast emergency reserve",
            "FAIL",
            format!(
                "a {} reserve is configured but 0 bytes are releasable — the emergency \
                 reserve does not exist",
                format_bytes(availability.configured_pool_bytes),
            ),
            Some(format!(
                "Run `sbh ballast provision`; files are created one at a time while the \
                 volume stays above the {:.1}% headroom floor, so even a low volume gets a \
                 partial reserve. Until then the daemon has no instant-release reserve for \
                 ENOSPC recovery.",
                config.ballast_provision_floor_pct()
            )),
        ),
        // Deliberately WARN, not FAIL: we could not read the pool, so we do not
        // know whether the reserve exists. Reporting FAIL/"empty" here is what
        // the old code effectively did, and it scared operators into rebuilding
        // a reserve that was already present and releasable by the daemon.
        BallastHealth::Indeterminate => doctor_check(
            "ballast.reserve",
            "Ballast emergency reserve",
            "WARN",
            format!(
                "could not inspect {} of {} configured ballast files in {} — reserve state \
                 is unknown, not necessarily missing",
                availability.unreadable_count,
                availability.configured_count,
                config.paths.ballast_dir.display(),
            ),
            Some(format!(
                "The ballast directory is usually root-owned (mode 700), so an unprivileged \
                 caller cannot stat it. Re-run as root to get an authoritative answer: \
                 `sudo sbh ballast status`. The daemon runs as root and is unaffected by \
                 this — it can still see and release {} files.",
                availability.configured_count,
            )),
        ),
    }
}

fn writeback_doctor_check(platform: &dyn Platform, config: &Config) -> DoctorCheck {
    use storage_ballast_helper::tuning::{bandwidth, writeback};

    let cfg = &config.system_tuning;
    if !cfg.writeback_enabled {
        return doctor_check(
            "system.writeback_tuning",
            "Kernel writeback limits",
            "PASS",
            "writeback tuning disabled (system_tuning.writeback_enabled=false)",
            None,
        );
    }
    let Ok(state) = platform.writeback_state() else {
        return doctor_check(
            "system.writeback_tuning",
            "Kernel writeback limits",
            "PASS",
            "not applicable on this platform (kernel writeback limits are not tunable here)",
            None,
        );
    };

    // Doctor is read-only: use the zero-write device-class heuristic, never the
    // bandwidth micro-benchmark.
    let probe_path = writeback_probe_path(config);
    let device = platform.block_device_for(&probe_path).ok();
    let fs_type = device
        .as_ref()
        .map_or_else(String::new, |info| info.fs_type.clone());
    let (bandwidth_bps, source) = device.as_ref().map_or_else(
        || bandwidth::heuristic_bytes_per_sec(None, ""),
        |info| bandwidth::heuristic_bytes_per_sec(info.rotational, &info.device),
    );
    let plan = writeback::plan_from_bandwidth(bandwidth_bps, source, cfg);
    let assessment = writeback::assess(&state, &plan, cfg, &fs_type);

    if assessment.needs_tuning {
        doctor_check(
            "system.writeback_tuning",
            "Kernel writeback limits",
            "WARN",
            format!(
                "{} (current effective dirty pool ≈ {})",
                assessment.reasons.join(" "),
                writeback::human_bytes(assessment.current_pool_bytes),
            ),
            Some(format!(
                "Run `sudo sbh tune --apply --yes` to set vm.dirty_bytes≈{} / \
                 vm.dirty_background_bytes≈{} (backup-first, reversible via \
                 `sbh tune --revert-writeback`).",
                writeback::human_bytes(plan.dirty_bytes),
                writeback::human_bytes(plan.dirty_background_bytes),
            )),
        )
    } else {
        doctor_check(
            "system.writeback_tuning",
            "Kernel writeback limits",
            "PASS",
            format!(
                "dirty-page limits are healthy (effective pool ≈ {})",
                writeback::human_bytes(assessment.current_pool_bytes),
            ),
            None,
        )
    }
}

fn doctor_checks_have_failures(checks: &[DoctorCheck]) -> bool {
    checks.iter().any(|check| check.status == "FAIL")
}

fn doctor_check_status_count(checks: &[DoctorCheck], status: &str) -> usize {
    checks.iter().filter(|check| check.status == status).count()
}

fn print_pal_doctor_report(report: &PalDoctorReport) {
    println!("PAL doctor: {}", report.platform);
    println!(
        "  implemented={} not_implemented={} failed={} skipped={}",
        report.implemented, report.not_implemented, report.failed, report.skipped
    );
    if !report.checks.is_empty() {
        println!("\nPlatform checks:");
        print_doctor_checks(&report.checks);
        println!();
    }
    for method in &report.methods {
        match (&method.bead, &method.message) {
            (Some(bead), Some(message)) => {
                println!(
                    "  {:<28} {:<16} {:<12} {}",
                    method.method, method.status, bead, message
                );
            }
            (Some(bead), None) => {
                println!("  {:<28} {:<16} {bead}", method.method, method.status);
            }
            (None, Some(message)) => {
                println!("  {:<28} {:<16} {}", method.method, method.status, message);
            }
            (None, None) => {
                println!("  {:<28} {}", method.method, method.status);
            }
        }
    }
    if !report.follow_up.is_empty() {
        println!("\nFollow-up:");
        for item in &report.follow_up {
            println!("  {} ({})", item.title, item.severity);
            println!("    {}", item.message);
            println!("    Docs: {}", item.docs);
            for (index, step) in item.steps.iter().enumerate() {
                println!("    {}. {}", index + 1, step);
            }
            println!("    Re-check: {}", item.recheck_command);
        }
    }
}

fn print_release_doctor_report(report: &ReleaseDoctorReport) {
    println!("Release doctor: {}", report.repository);
    println!(
        "  readiness={} passed={} warnings={} failed={}",
        release_readiness_label(report),
        report.passed,
        report.warnings,
        report.failed
    );
    println!("  notary_profile={}", report.notary_profile);
    println!(
        "  required_github_secrets={}",
        report.required_github_secrets.join(", ")
    );
    println!("\nRelease checks:");
    print_doctor_checks(&report.checks);
    println!("\nCredential setup plan:");
    for step in &report.setup_steps {
        println!("  {}: {}", step.title, step.reason);
        println!("    Docs: {}", step.docs);
        for command in &step.commands {
            println!("    $ {command}");
        }
    }
}

fn print_doctor_checks(checks: &[DoctorCheck]) {
    for check in checks {
        println!(
            "  [{:<4}] {:<28} {}",
            check.status, check.title, check.message
        );
        if let Some(remediation) = &check.remediation {
            println!("         fix: {remediation}");
        }
    }
}

fn release_readiness_label(report: &ReleaseDoctorReport) -> &'static str {
    if report.failed > 0 {
        "blocked"
    } else if report.warnings > 0 {
        "attention"
    } else {
        "ready"
    }
}

const RELEASE_DOCTOR_NOTARY_PROFILE: &str = "sbh-notary";
const RELEASE_HOMEBREW_TAP_REPOSITORY: &str = "Dicklesworthstone/homebrew-sbh";
const RELEASE_SECRET_PRESENT_ENV_PREFIX: &str = "SBH_RELEASE_SECRET_";
const RELEASE_SECRET_PRESENT_ENV_SUFFIX: &str = "_PRESENT";
const RELEASE_DOCTOR_REQUIRED_GITHUB_SECRETS: &[&str] = &[
    "APPLE_DEVELOPER_ID_CERTIFICATE_P12_BASE64",
    "APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD",
    "APPLE_DEVELOPER_ID_IDENTITY",
    "APPLE_NOTARY_KEY_P8_BASE64",
    "APPLE_NOTARY_KEY_ID",
    "APPLE_NOTARY_ISSUER_ID",
    "HOMEBREW_TAP_SSH_KEY",
];

fn release_doctor_report() -> ReleaseDoctorReport {
    release_doctor_report_with_command_runner_and_env(&run_doctor_command, &release_doctor_env_var)
}

#[cfg(test)]
fn release_doctor_report_with_command_runner<F>(run_command: &F) -> ReleaseDoctorReport
where
    F: Fn(&str, &[String]) -> std::io::Result<DoctorCommandOutcome>,
{
    release_doctor_report_with_command_runner_and_env(run_command, &|_| None)
}

fn release_doctor_report_with_command_runner_and_env<F, E>(
    run_command: &F,
    read_env: &E,
) -> ReleaseDoctorReport
where
    F: Fn(&str, &[String]) -> std::io::Result<DoctorCommandOutcome>,
    E: Fn(&str) -> Option<String>,
{
    let checks = vec![
        release_developer_id_identity_check(run_command, read_env),
        release_notary_profile_check(run_command),
        release_github_secrets_check(run_command, read_env),
        release_homebrew_tap_check(run_command),
    ];
    let failed = doctor_check_status_count(&checks, "FAIL");
    let warnings = doctor_check_status_count(&checks, "WARN");

    ReleaseDoctorReport {
        ok: failed == 0 && warnings == 0,
        passed: doctor_check_status_count(&checks, "PASS"),
        warnings,
        failed,
        repository: RELEASE_REPOSITORY,
        notary_profile: RELEASE_DOCTOR_NOTARY_PROFILE,
        required_github_secrets: RELEASE_DOCTOR_REQUIRED_GITHUB_SECRETS.to_vec(),
        setup_steps: release_doctor_setup_steps(),
        checks,
    }
}

fn release_doctor_env_var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn release_developer_id_identity_check<F, E>(run_command: &F, read_env: &E) -> DoctorCheck
where
    F: Fn(&str, &[String]) -> std::io::Result<DoctorCommandOutcome>,
    E: Fn(&str) -> Option<String>,
{
    let args = vec![
        "find-identity".to_string(),
        "-v".to_string(),
        "-p".to_string(),
        "codesigning".to_string(),
    ];
    let configured_identity = read_env("APPLE_DEVELOPER_ID_IDENTITY")
        .map(|identity| identity.trim().to_string())
        .filter(|identity| !identity.is_empty());

    match run_command("security", &args) {
        Ok(outcome) if outcome.success => {
            let output = command_text(&outcome);
            if let Some(identity) = &configured_identity
                && !output.contains(identity)
            {
                return doctor_check(
                    "release.developer_id_identity",
                    "Developer ID identity",
                    "FAIL",
                    format!(
                        "configured APPLE_DEVELOPER_ID_IDENTITY was not found in available signing identities: {}",
                        command_detail(&outcome)
                    ),
                    Some("Import the matching Developer ID Application certificate or update APPLE_DEVELOPER_ID_IDENTITY before cutting a release.".to_string()),
                );
            }

            if output.contains("Developer ID Application") {
                let message = configured_identity.as_ref().map_or_else(
                    || "found a Developer ID Application signing identity".to_string(),
                    |identity| {
                        format!(
                            "found configured Developer ID Application signing identity: {identity}"
                        )
                    },
                );
                return doctor_check(
                    "release.developer_id_identity",
                    "Developer ID identity",
                    "PASS",
                    message,
                    None,
                );
            }

            doctor_check(
                "release.developer_id_identity",
                "Developer ID identity",
                "FAIL",
                format!(
                    "no Developer ID Application signing identity is available: {}",
                    command_detail(&outcome)
                ),
                Some("Create a Developer ID Application certificate in the Apple Developer portal, export it as a password-protected .p12 with the private key, and set the release workflow secrets documented in docs/macos.md.".to_string()),
            )
        }
        Ok(outcome) => doctor_check(
            "release.developer_id_identity",
            "Developer ID identity",
            "FAIL",
            format!(
                "no Developer ID Application signing identity is available: {}",
                command_detail(&outcome)
            ),
            Some("Create a Developer ID Application certificate in the Apple Developer portal, export it as a password-protected .p12 with the private key, and set the release workflow secrets documented in docs/macos.md.".to_string()),
        ),
        Err(error) => doctor_check(
            "release.developer_id_identity",
            "Developer ID identity",
            "FAIL",
            format!("failed to run security find-identity: {error}"),
            Some("Run this check on macOS with Xcode Command Line Tools installed.".to_string()),
        ),
    }
}

fn release_notary_profile_check<F>(run_command: &F) -> DoctorCheck
where
    F: Fn(&str, &[String]) -> std::io::Result<DoctorCommandOutcome>,
{
    let args = vec![
        "notarytool".to_string(),
        "history".to_string(),
        "--keychain-profile".to_string(),
        RELEASE_DOCTOR_NOTARY_PROFILE.to_string(),
        "--output-format".to_string(),
        "json".to_string(),
    ];

    match run_command("xcrun", &args) {
        Ok(outcome) if outcome.success => doctor_check(
            "release.notary_profile",
            "Notary profile",
            "PASS",
            format!("notarytool keychain profile '{RELEASE_DOCTOR_NOTARY_PROFILE}' is usable"),
            None,
        ),
        Ok(outcome) => doctor_check(
            "release.notary_profile",
            "Notary profile",
            "FAIL",
            format!(
                "notarytool profile '{}' is not usable: {}",
                RELEASE_DOCTOR_NOTARY_PROFILE,
                command_detail(&outcome)
            ),
            Some(format!(
                "Create the profile with `xcrun notarytool store-credentials {RELEASE_DOCTOR_NOTARY_PROFILE}` using the App Store Connect API key from docs/macos.md.",
            )),
        ),
        Err(error) => doctor_check(
            "release.notary_profile",
            "Notary profile",
            "FAIL",
            format!("failed to run xcrun notarytool: {error}"),
            Some(
                "Install Xcode Command Line Tools and configure notarytool credentials."
                    .to_string(),
            ),
        ),
    }
}

fn release_github_secrets_check<F, E>(run_command: &F, read_env: &E) -> DoctorCheck
where
    F: Fn(&str, &[String]) -> std::io::Result<DoctorCommandOutcome>,
    E: Fn(&str) -> Option<String>,
{
    match release_secret_names_from_presence_env(read_env) {
        Ok(Some(secret_names)) => {
            return release_secret_names_check(
                &secret_names,
                "CI secret presence flags reported all required release secrets are configured",
                "CI secret presence flags reported missing required secrets",
                "Set the missing secrets on the release repository, then rerun CI and sbh doctor --release.",
            );
        }
        Ok(None) => {}
        Err(error) => {
            return doctor_check(
                "release.github_secrets",
                "GitHub release secrets",
                "FAIL",
                format!("CI release secret presence flags are invalid: {error}"),
                Some(
                    "Fix the SBH_RELEASE_SECRET_*_PRESENT environment values in the CI release doctor diagnostic step."
                        .to_string(),
                ),
            );
        }
    }

    let args = vec![
        "secret".to_string(),
        "list".to_string(),
        "-R".to_string(),
        RELEASE_REPOSITORY.to_string(),
        "--json".to_string(),
        "name".to_string(),
    ];

    match run_command("gh", &args) {
        Ok(outcome) if outcome.success => {
            let secret_names = match parse_github_secret_names(&outcome.stdout) {
                Ok(names) => names,
                Err(error) => {
                    return doctor_check(
                        "release.github_secrets",
                        "GitHub release secrets",
                        "FAIL",
                        format!("could not parse gh secret list output: {error}"),
                        Some("Re-run `gh secret list --json name` and check GitHub CLI authentication.".to_string()),
                    );
                }
            };
            let secret_names = secret_names.iter().map(String::as_str).collect::<Vec<_>>();
            release_secret_names_check(
                &secret_names,
                "all required release secrets are configured",
                "missing required secrets",
                &format!(
                    "Set the missing secrets on {RELEASE_REPOSITORY} with the commands documented in docs/macos.md."
                ),
            )
        }
        Ok(outcome) => doctor_check(
            "release.github_secrets",
            "GitHub release secrets",
            "FAIL",
            format!("gh secret list failed: {}", command_detail(&outcome)),
            Some("Authenticate GitHub CLI with secret-read access to the repository, then re-run sbh doctor --release.".to_string()),
        ),
        Err(error) => doctor_check(
            "release.github_secrets",
            "GitHub release secrets",
            "FAIL",
            format!("failed to run gh secret list: {error}"),
            Some("Install GitHub CLI and authenticate before checking release secrets.".to_string()),
        ),
    }
}

fn release_secret_names_from_presence_env<E>(
    read_env: &E,
) -> Result<Option<Vec<&'static str>>, String>
where
    E: Fn(&str) -> Option<String>,
{
    let mut observed_any = false;
    let mut present = Vec::new();

    for secret in RELEASE_DOCTOR_REQUIRED_GITHUB_SECRETS {
        let env_key = release_secret_presence_env_key(secret);
        let Some(value) = read_env(&env_key) else {
            continue;
        };
        observed_any = true;
        match parse_release_secret_presence_flag(&value) {
            Some(true) => present.push(*secret),
            Some(false) => {}
            None => {
                return Err(format!("{env_key} must be true or false, got {value:?}"));
            }
        }
    }

    Ok(observed_any.then_some(present))
}

fn release_secret_presence_env_key(secret: &str) -> String {
    format!("{RELEASE_SECRET_PRESENT_ENV_PREFIX}{secret}{RELEASE_SECRET_PRESENT_ENV_SUFFIX}")
}

fn parse_release_secret_presence_flag(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Some(true),
        "0" | "false" | "no" | "" => Some(false),
        _ => None,
    }
}

fn release_secret_names_check(
    secret_names: &[&str],
    pass_message: &str,
    missing_prefix: &str,
    remediation: &str,
) -> DoctorCheck {
    let missing = RELEASE_DOCTOR_REQUIRED_GITHUB_SECRETS
        .iter()
        .copied()
        .filter(|secret| !secret_names.iter().any(|name| name == secret))
        .collect::<Vec<_>>();

    if missing.is_empty() {
        doctor_check(
            "release.github_secrets",
            "GitHub release secrets",
            "PASS",
            pass_message,
            None,
        )
    } else {
        doctor_check(
            "release.github_secrets",
            "GitHub release secrets",
            "FAIL",
            format!("{missing_prefix}: {}", missing.join(", ")),
            Some(remediation.to_string()),
        )
    }
}

fn release_homebrew_tap_check<F>(run_command: &F) -> DoctorCheck
where
    F: Fn(&str, &[String]) -> std::io::Result<DoctorCommandOutcome>,
{
    let repo_args = vec![
        "repo".to_string(),
        "view".to_string(),
        RELEASE_HOMEBREW_TAP_REPOSITORY.to_string(),
        "--json".to_string(),
        "nameWithOwner,defaultBranchRef".to_string(),
    ];

    match run_command("gh", &repo_args) {
        Ok(outcome) if outcome.success => {
            let default_branch = match parse_homebrew_tap_default_branch(&outcome.stdout) {
                Ok(branch) => branch,
                Err(error) => {
                    return doctor_check(
                        "release.homebrew_tap",
                        "Homebrew tap formula",
                        "FAIL",
                        format!(
                            "Homebrew tap repository metadata could not be verified: {error}"
                        ),
                        Some(
                            "Re-run `gh repo view Dicklesworthstone/homebrew-sbh --json nameWithOwner,defaultBranchRef` and confirm the tap repository uses main."
                                .to_string(),
                        ),
                    );
                }
            };
            if default_branch != "main" {
                return doctor_check(
                    "release.homebrew_tap",
                    "Homebrew tap formula",
                    "FAIL",
                    format!(
                        "{RELEASE_HOMEBREW_TAP_REPOSITORY} default branch is {default_branch}, expected main"
                    ),
                    Some("Change the Homebrew tap default branch to main before cutting a macOS release.".to_string()),
                );
            }

            let formula_args = vec![
                "api".to_string(),
                format!("repos/{RELEASE_HOMEBREW_TAP_REPOSITORY}/contents/Formula/sbh.rb"),
                "--jq".to_string(),
                ".name".to_string(),
            ];

            match run_command("gh", &formula_args) {
                Ok(formula) if formula.success => doctor_check(
                    "release.homebrew_tap",
                    "Homebrew tap formula",
                    "PASS",
                    format!("{RELEASE_HOMEBREW_TAP_REPOSITORY} publishes Formula/sbh.rb"),
                    None,
                ),
                Ok(formula) => doctor_check(
                    "release.homebrew_tap",
                    "Homebrew tap formula",
                    "WARN",
                    format!(
                        "{RELEASE_HOMEBREW_TAP_REPOSITORY} is reachable, but Formula/sbh.rb is not published yet: {}",
                        command_detail(&formula)
                    ),
                    Some("After the first signed release, verify that the Homebrew tap update creates Formula/sbh.rb and brew install works from the tap.".to_string()),
                ),
                Err(error) => doctor_check(
                    "release.homebrew_tap",
                    "Homebrew tap formula",
                    "WARN",
                    format!(
                        "{RELEASE_HOMEBREW_TAP_REPOSITORY} is reachable, but Formula/sbh.rb could not be checked: {error}"
                    ),
                    Some("Re-run with GitHub CLI network access, then verify the release workflow's Homebrew tap update.".to_string()),
                ),
            }
        }
        Ok(outcome) => doctor_check(
            "release.homebrew_tap",
            "Homebrew tap formula",
            "FAIL",
            format!(
                "Homebrew tap repository {RELEASE_HOMEBREW_TAP_REPOSITORY} is not accessible: {}",
                command_detail(&outcome)
            ),
            Some("Create or grant access to the Homebrew tap repository before cutting a macOS release.".to_string()),
        ),
        Err(error) => doctor_check(
            "release.homebrew_tap",
            "Homebrew tap formula",
            "FAIL",
            format!("failed to run gh repo view for Homebrew tap: {error}"),
            Some("Install GitHub CLI and authenticate before checking Homebrew tap readiness."
                .to_string()),
        ),
    }
}

fn parse_homebrew_tap_default_branch(raw: &str) -> std::result::Result<String, String> {
    let value = serde_json::from_str::<Value>(raw).map_err(|error| error.to_string())?;
    let name_with_owner = value
        .get("nameWithOwner")
        .and_then(Value::as_str)
        .ok_or_else(|| "repository metadata missing string field 'nameWithOwner'".to_string())?;
    if name_with_owner != RELEASE_HOMEBREW_TAP_REPOSITORY {
        return Err(format!(
            "expected repository {RELEASE_HOMEBREW_TAP_REPOSITORY}, got {name_with_owner}"
        ));
    }

    value
        .get("defaultBranchRef")
        .and_then(|branch| branch.get("name"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            "repository metadata missing string field 'defaultBranchRef.name'".to_string()
        })
}

fn parse_github_secret_names(raw: &str) -> std::result::Result<HashSet<String>, String> {
    let value = serde_json::from_str::<Value>(raw).map_err(|error| error.to_string())?;
    let entries = value
        .as_array()
        .ok_or_else(|| "expected top-level JSON array".to_string())?;
    let mut names = HashSet::with_capacity(entries.len());
    for entry in entries {
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| "secret entry missing string field 'name'".to_string())?;
        names.insert(name.to_string());
    }
    Ok(names)
}

fn release_doctor_setup_steps() -> Vec<ReleaseDoctorSetupStep> {
    vec![
        ReleaseDoctorSetupStep {
            id: "developer_id_csr",
            title: "Developer ID certificate request",
            reason: "Create the local keychain-backed CSR that Apple uses to issue the Developer ID Application certificate.",
            docs: "docs/macos.md#code-signing-and-hardened-runtime",
            commands: vec![
                "export CSR_PATH=\"$HOME/Desktop/sbh-developer-id.certSigningRequest\"".to_string(),
                "certtool r \"$CSR_PATH\" u".to_string(),
                "certtool V \"$CSR_PATH\"".to_string(),
                "open https://developer.apple.com/account/resources/certificates/add".to_string(),
            ],
        },
        ReleaseDoctorSetupStep {
            id: "developer_id_certificate",
            title: "Developer ID certificate",
            reason: "Install/export the issued Developer ID Application identity and store the signing secrets for tagged macOS releases.",
            docs: "docs/macos.md#code-signing-and-hardened-runtime",
            commands: vec![
                "security find-identity -v -p codesigning".to_string(),
                format!(
                    "base64 < \"$P12_PATH\" | gh secret set APPLE_DEVELOPER_ID_CERTIFICATE_P12_BASE64 -R {RELEASE_REPOSITORY}",
                ),
                format!(
                    "printf '%s' \"$P12_PASSWORD\" | gh secret set APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD -R {RELEASE_REPOSITORY}",
                ),
                format!(
                    "printf '%s' \"$DEVELOPER_ID_IDENTITY\" | gh secret set APPLE_DEVELOPER_ID_IDENTITY -R {RELEASE_REPOSITORY}",
                ),
            ],
        },
        ReleaseDoctorSetupStep {
            id: "notary_credentials",
            title: "Notary credentials",
            reason: "Create the local notarytool profile used by release readiness checks and store App Store Connect API key secrets for CI notarization.",
            docs: "docs/macos.md#release-readiness-diagnostics",
            commands: vec![
                format!(
                    "xcrun notarytool store-credentials {RELEASE_DOCTOR_NOTARY_PROFILE} --key \"$APPLE_NOTARY_KEY_PATH\" --key-id \"$APPLE_NOTARY_KEY_ID\" --issuer \"$APPLE_NOTARY_ISSUER_ID\"",
                ),
                format!(
                    "base64 < \"$APPLE_NOTARY_KEY_PATH\" | gh secret set APPLE_NOTARY_KEY_P8_BASE64 -R {RELEASE_REPOSITORY}",
                ),
                format!(
                    "printf '%s' \"$APPLE_NOTARY_KEY_ID\" | gh secret set APPLE_NOTARY_KEY_ID -R {RELEASE_REPOSITORY}",
                ),
                format!(
                    "printf '%s' \"$APPLE_NOTARY_ISSUER_ID\" | gh secret set APPLE_NOTARY_ISSUER_ID -R {RELEASE_REPOSITORY}",
                ),
            ],
        },
        ReleaseDoctorSetupStep {
            id: "homebrew_tap_deploy_key",
            title: "Homebrew tap deploy key",
            reason: "Store the repository-scoped deploy key that lets the release workflow publish formula updates to the Homebrew tap.",
            docs: "docs/macos.md#homebrew-and-install-paths",
            commands: vec![
                "ssh-keygen -t ed25519 -C \"sbh Homebrew tap release\" -f \"$HOME/.ssh/sbh-homebrew-tap-release\" -N \"\"".to_string(),
                "gh api -X POST repos/Dicklesworthstone/homebrew-sbh/keys -f title=\"sbh release workflow\" -f key=\"$(cat \"$HOME/.ssh/sbh-homebrew-tap-release.pub\")\" -F read_only=false".to_string(),
                format!(
                    "gh secret set HOMEBREW_TAP_SSH_KEY -R {RELEASE_REPOSITORY} < \"$HOME/.ssh/sbh-homebrew-tap-release\"",
                ),
                format!("gh secret list -R {RELEASE_REPOSITORY} --json name,updatedAt,visibility",),
                "sbh doctor --release --json".to_string(),
            ],
        },
    ]
}

fn pal_doctor_report(platform: &dyn Platform) -> PalDoctorReport {
    pal_doctor_report_with_command_runner(platform, &run_doctor_command)
}

fn pal_doctor_report_with_command_runner<F>(
    platform: &dyn Platform,
    run_command: &F,
) -> PalDoctorReport
where
    F: Fn(&str, &[String]) -> std::io::Result<DoctorCommandOutcome>,
{
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let current_pid = i32::try_from(std::process::id()).unwrap_or(i32::MAX);
    let current_exe = std::env::current_exe().unwrap_or_else(|_| cwd.clone());
    let home = platform.user_home();
    let full_disk_access = platform.full_disk_access_status();
    let checks = macos_doctor_checks(
        platform,
        &current_exe,
        &home,
        &full_disk_access,
        run_command,
    );
    let follow_up = full_disk_access
        .as_ref()
        .ok()
        .and_then(|status| full_disk_access_follow_up(status, &home, &current_exe))
        .into_iter()
        .collect();
    let callback = || -> storage_ballast_helper::core::errors::Result<_> {
        platform.subscribe_memory_pressure(Box::new(|_| {}))
    };

    let mut methods = vec![
        pal_probe_result("fs_stats", platform.fs_stats(&cwd)),
        pal_probe_result("mount_points", platform.mount_points()),
        pal_probe_result("is_ram_backed", platform.is_ram_backed(&cwd)),
        pal_probe_value("default_paths", platform.default_paths()),
        pal_probe_result("memory_info", platform.memory_info()),
        pal_probe_result(
            "service_manager.status",
            platform.service_manager().status(),
        ),
        pal_probe_result("capacity", platform.capacity(&cwd)),
        pal_probe_result("mounts", platform.mounts()),
        pal_probe_result("memory_pressure", platform.memory_pressure()),
        pal_probe_full_disk_access(full_disk_access),
        pal_probe_result("subscribe_memory_pressure", callback()),
        pal_probe_result("process_list", platform.process_list()),
        pal_probe_result("process_io", platform.process_io(current_pid)),
        pal_probe_result("open_files_under", platform.open_files_under(&cwd)),
        pal_probe_result("executables_under", platform.executables_under(&cwd)),
        pal_probe_result("mmap_regions_under", platform.mmap_regions_under(&cwd)),
        pal_probe_result("self_stats", platform.self_stats()),
        pal_probe_skipped(
            "preallocate_file",
            "requires an explicit writable target and is skipped by read-only doctor",
        ),
        pal_probe_result("file_block_count", platform.file_block_count(&current_exe)),
        pal_probe_value("user_home", platform.user_home()),
        pal_probe_value("temp_dirs", platform.temp_dirs()),
        pal_probe_value("cache_roots", platform.cache_roots()),
        pal_probe_value("sacred_paths", platform.sacred_paths()),
        pal_probe_value("service_kind", platform.service_kind()),
    ];
    methods.sort_by_key(|probe| probe.method);

    let implemented = methods
        .iter()
        .filter(|probe| probe.status == "implemented")
        .count();
    let not_implemented = methods
        .iter()
        .filter(|probe| probe.status == "not_implemented")
        .count();
    let failed = methods
        .iter()
        .filter(|probe| probe.status == "failed")
        .count();
    let skipped = methods
        .iter()
        .filter(|probe| probe.status == "skipped")
        .count();

    PalDoctorReport {
        platform: platform.name().to_string(),
        implemented,
        not_implemented,
        failed,
        skipped,
        checks,
        methods,
        follow_up,
    }
}

#[derive(Debug, Clone)]
struct DoctorCommandOutcome {
    success: bool,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run_doctor_command(program: &str, args: &[String]) -> std::io::Result<DoctorCommandOutcome> {
    let output = std::process::Command::new(program).args(args).output()?;
    Ok(DoctorCommandOutcome {
        success: output.status.success(),
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

fn macos_doctor_checks<F>(
    platform: &dyn Platform,
    current_exe: &Path,
    home: &Path,
    full_disk_access: &storage_ballast_helper::core::errors::Result<FullDiskAccessStatus>,
    run_command: &F,
) -> Vec<DoctorCheck>
where
    F: Fn(&str, &[String]) -> std::io::Result<DoctorCommandOutcome>,
{
    if platform.name() != "macos" {
        return Vec::new();
    }

    vec![
        macos_codesign_check(current_exe, run_command),
        macos_spctl_check(current_exe, run_command),
        macos_launchd_check(platform),
        macos_full_disk_access_check(full_disk_access),
        macos_apfs_check(platform),
        macos_state_free_space_check(platform, home),
    ]
}

/// Read-only install-footprint diagnostics: a dry-run bootstrap scan rendered
/// as doctor checks. Reasons that stop sbh from working (a non-executable
/// binary, a unit pointing at a missing binary, an interrupted install, a
/// missing state file) are FAIL; drift that only degrades it is WARN.
fn env_doctor_checks() -> Vec<DoctorCheck> {
    use storage_ballast_helper::cli::bootstrap::{
        EnvironmentHealth, MigrateOptions, MigrationReason, run_migration,
    };

    let report = run_migration(&MigrateOptions {
        dry_run: true,
        ..MigrateOptions::default()
    });
    let mut checks = Vec::new();
    let summary_status = match report.health {
        EnvironmentHealth::Healthy => "PASS",
        EnvironmentHealth::Degraded | EnvironmentHealth::NotInstalled => "WARN",
        EnvironmentHealth::Broken => "FAIL",
    };
    checks.push(doctor_check(
        "env.health",
        "Install footprint",
        summary_status,
        format!(
            "environment {}: {} footprint(s), {} issue(s), {} repair action(s) planned",
            report.health,
            report.footprints.len(),
            report.issues_found,
            report.actions.len()
        ),
        (!report.actions.is_empty())
            .then(|| "Run `sbh bootstrap --dry-run` to review, then `sbh bootstrap` to repair with backups.".to_string()),
    ));
    for action in &report.actions {
        let status = match action.reason {
            MigrationReason::BinaryPermissions
            | MigrationReason::SystemdUnitStaleBinary
            | MigrationReason::LaunchdPlistStaleBinary
            | MigrationReason::InterruptedInstall
            | MigrationReason::MissingStateFile => "FAIL",
            _ => "WARN",
        };
        checks.push(doctor_check(
            "env.migration",
            "Repair action",
            status,
            format!(
                "{} — {} ({})",
                action.reason,
                action.description,
                action.target.display()
            ),
            Some(format!("planned action: {}", action.kind)),
        ));
    }
    checks
}

fn doctor_check(
    id: &'static str,
    title: &'static str,
    status: &'static str,
    message: impl Into<String>,
    remediation: Option<String>,
) -> DoctorCheck {
    DoctorCheck {
        id,
        title,
        status,
        message: message.into(),
        remediation,
    }
}

fn macos_codesign_check<F>(current_exe: &Path, run_command: &F) -> DoctorCheck
where
    F: Fn(&str, &[String]) -> std::io::Result<DoctorCommandOutcome>,
{
    let args = vec!["-dv".to_string(), current_exe.display().to_string()];
    match run_command("codesign", &args) {
        Ok(outcome) if outcome.success => doctor_check(
            "macos.codesign",
            "Code signature",
            "PASS",
            format!("codesign accepted {}", current_exe.display()),
            None,
        ),
        Ok(outcome) => doctor_check(
            "macos.codesign",
            "Code signature",
            "WARN",
            format!(
                "codesign rejected {}: {}",
                current_exe.display(),
                command_detail(&outcome)
            ),
            Some(
                "Install a signed release artifact or re-sign the binary before service install."
                    .to_string(),
            ),
        ),
        Err(error) => doctor_check(
            "macos.codesign",
            "Code signature",
            "FAIL",
            format!("failed to run codesign: {error}"),
            Some("Install Xcode Command Line Tools so /usr/bin/codesign is available.".to_string()),
        ),
    }
}

fn macos_spctl_check<F>(current_exe: &Path, run_command: &F) -> DoctorCheck
where
    F: Fn(&str, &[String]) -> std::io::Result<DoctorCommandOutcome>,
{
    let args = vec![
        "-a".to_string(),
        "-vv".to_string(),
        current_exe.display().to_string(),
    ];
    match run_command("spctl", &args) {
        Ok(outcome) if outcome.success => doctor_check(
            "macos.spctl",
            "Gatekeeper assessment",
            "PASS",
            format!("spctl accepted {}", current_exe.display()),
            None,
        ),
        Ok(outcome) => doctor_check(
            "macos.spctl",
            "Gatekeeper assessment",
            "WARN",
            format!(
                "spctl did not accept {}: {}",
                current_exe.display(),
                command_detail(&outcome)
            ),
            Some("Use a notarized release artifact before distributing this binary.".to_string()),
        ),
        Err(error) => doctor_check(
            "macos.spctl",
            "Gatekeeper assessment",
            "FAIL",
            format!("failed to run spctl: {error}"),
            Some(
                "Run on macOS with /usr/sbin/spctl available, or verify notarization separately."
                    .to_string(),
            ),
        ),
    }
}

fn macos_launchd_check(platform: &dyn Platform) -> DoctorCheck {
    if platform.service_kind() != ServiceKind::Launchd {
        return doctor_check(
            "macos.launchd",
            "launchd service",
            "WARN",
            format!("platform service kind is {:?}", platform.service_kind()),
            Some(
                "Install as a launchd service with sbh install --launchd --scope user.".to_string(),
            ),
        );
    }

    match platform.service_manager().status() {
        Ok(status) if matches!(status.as_str(), "active" | "loaded" | "running") => doctor_check(
            "macos.launchd",
            "launchd service",
            "PASS",
            format!("launchctl reports {status}"),
            None,
        ),
        Ok(status) => doctor_check(
            "macos.launchd",
            "launchd service",
            "WARN",
            format!("launchctl reports {status}"),
            Some("Bootstrap the service with sbh install --launchd --scope user, then re-run sbh doctor --pal.".to_string()),
        ),
        Err(error) => doctor_check(
            "macos.launchd",
            "launchd service",
            "FAIL",
            format!("launchctl status failed: {error}"),
            Some("Run sbh service --launchd status for the exact launchctl error and plist path."
                .to_string()),
        ),
    }
}

fn macos_full_disk_access_check(
    full_disk_access: &storage_ballast_helper::core::errors::Result<FullDiskAccessStatus>,
) -> DoctorCheck {
    match full_disk_access {
        Ok(status) => match status.state {
            FullDiskAccessState::Granted => doctor_check(
                "macos.full_disk_access",
                "Full Disk Access",
                "PASS",
                status.doctor_message(),
                None,
            ),
            FullDiskAccessState::Missing => doctor_check(
                "macos.full_disk_access",
                "Full Disk Access",
                "FAIL",
                status.doctor_message(),
                Some("Grant Full Disk Access in System Settings > Privacy & Security, then re-run sbh doctor --pal.".to_string()),
            ),
            FullDiskAccessState::NotConfigured
            | FullDiskAccessState::NotApplicable
            | FullDiskAccessState::Unknown => doctor_check(
                "macos.full_disk_access",
                "Full Disk Access",
                "WARN",
                status.doctor_message(),
                Some("Verify Full Disk Access manually if cleanup scans need protected user data."
                    .to_string()),
            ),
        },
        Err(error) => doctor_check(
            "macos.full_disk_access",
            "Full Disk Access",
            "FAIL",
            format!("Full Disk Access probe failed: {error}"),
            Some("Re-run sbh doctor --pal after checking filesystem permissions.".to_string()),
        ),
    }
}

fn macos_apfs_check(platform: &dyn Platform) -> DoctorCheck {
    match platform.mounts() {
        Ok(mounts) => {
            let primary_apfs = mounts.iter().find(|mount| {
                mount.fs_type.eq_ignore_ascii_case("apfs")
                    && (mount.is_apfs_data_volume
                        || mount.mount_point == Path::new("/")
                        || mount.mount_point == Path::new("/System/Volumes/Data"))
            });
            primary_apfs.map_or_else(
                || {
                    doctor_check(
                        "macos.apfs",
                        "APFS inventory",
                        "WARN",
                        "no primary APFS Data mount was reported",
                        Some("Run sbh status --json and diskutil apfs list -plist to compare APFS inventory.".to_string()),
                    )
                },
                |mount| {
                    doctor_check(
                        "macos.apfs",
                        "APFS inventory",
                        "PASS",
                        format!(
                            "found APFS mount {} ({})",
                            mount.mount_point.display(),
                            mount.container_id.as_deref().unwrap_or("container unknown")
                        ),
                        None,
                    )
                },
            )
        }
        Err(error) => doctor_check(
            "macos.apfs",
            "APFS inventory",
            "FAIL",
            format!("APFS mount discovery failed: {error}"),
            Some("Check diskutil apfs list -plist and filesystem permissions.".to_string()),
        ),
    }
}

fn macos_state_free_space_check(platform: &dyn Platform, home: &Path) -> DoctorCheck {
    const MIN_STATE_AVAILABLE_BYTES: u64 = 1024 * 1024 * 1024;

    let state_file = platform.default_paths().state_file;
    let state_dir = state_file.parent().unwrap_or(home);
    let probe_path = nearest_existing_ancestor(state_dir);
    match platform.capacity(&probe_path) {
        Ok(capacity) if capacity.available_bytes >= MIN_STATE_AVAILABLE_BYTES => doctor_check(
            "macos.state_free_space",
            "State volume space",
            "PASS",
            format!(
                "{} available for state path {}",
                format_bytes(capacity.available_bytes),
                state_dir.display()
            ),
            None,
        ),
        Ok(capacity) => doctor_check(
            "macos.state_free_space",
            "State volume space",
            "WARN",
            format!(
                "only {} available for state path {}",
                format_bytes(capacity.available_bytes),
                state_dir.display()
            ),
            Some("Free space on the state volume or move sbh paths.state_file to a healthier volume."
                .to_string()),
        ),
        Err(error) => doctor_check(
            "macos.state_free_space",
            "State volume space",
            "FAIL",
            format!("could not measure state path {}: {error}", state_dir.display()),
            Some("Create the state directory or fix permissions, then re-run sbh doctor --pal."
                .to_string()),
        ),
    }
}

fn nearest_existing_ancestor(path: &Path) -> PathBuf {
    let mut candidate = path.to_path_buf();
    loop {
        if candidate.exists() {
            return candidate;
        }
        if !candidate.pop() {
            return PathBuf::from("/");
        }
    }
}

fn command_detail(outcome: &DoctorCommandOutcome) -> String {
    let stderr = outcome.stderr.trim();
    if !stderr.is_empty() {
        return stderr.to_string();
    }
    let stdout = outcome.stdout.trim();
    if !stdout.is_empty() {
        return stdout.to_string();
    }
    format!("exit {:?}", outcome.exit_code)
}

fn command_text(outcome: &DoctorCommandOutcome) -> String {
    let mut text = String::with_capacity(outcome.stdout.len() + outcome.stderr.len() + 1);
    text.push_str(&outcome.stdout);
    text.push('\n');
    text.push_str(&outcome.stderr);
    text
}

fn full_disk_access_follow_up(
    status: &FullDiskAccessStatus,
    home: &Path,
    current_exe: &Path,
) -> Option<PalDoctorFollowUp> {
    if status.state != FullDiskAccessState::Missing {
        return None;
    }

    let installed_binary = home.join(".local/bin/sbh");
    Some(PalDoctorFollowUp {
        id: "macos_full_disk_access",
        title: "Grant Full Disk Access",
        severity: "action_required",
        message: "macOS denied sbh access to Mail-protected data. Grant Full Disk Access before relying on macOS cleanup scans.".to_string(),
        docs: "docs/macos-full-disk-access.md",
        recheck_command: "sbh doctor --pal",
        steps: vec![
            "Open System Settings.".to_string(),
            "Open Privacy & Security, then Full Disk Access.".to_string(),
            "Click the + button and authenticate if macOS asks.".to_string(),
            format!(
                "Select the installed sbh binary at {}.",
                installed_binary.display()
            ),
            format!(
                "If you are testing a different binary, add this running executable too: {}.",
                current_exe.display()
            ),
            "Turn sbh on in the Full Disk Access list.".to_string(),
            "Restart the sbh launchd service or rerun the command that needs disk access.".to_string(),
            "Run sbh doctor --pal until full_disk_access_status reports granted.".to_string(),
        ],
    })
}

fn pal_probe_value<T>(method: &'static str, _value: T) -> PalDoctorProbe {
    PalDoctorProbe {
        method,
        status: "implemented",
        bead: None,
        message: None,
    }
}

fn pal_probe_skipped(method: &'static str, message: impl Into<String>) -> PalDoctorProbe {
    PalDoctorProbe {
        method,
        status: "skipped",
        bead: None,
        message: Some(message.into()),
    }
}

fn pal_probe_full_disk_access(
    result: storage_ballast_helper::core::errors::Result<FullDiskAccessStatus>,
) -> PalDoctorProbe {
    match result {
        Ok(status) => PalDoctorProbe {
            method: "full_disk_access_status",
            status: "implemented",
            bead: None,
            message: Some(status.doctor_message()),
        },
        Err(error) => pal_probe_result::<()>("full_disk_access_status", Err(error)),
    }
}

fn pal_probe_result<T>(
    method: &'static str,
    result: storage_ballast_helper::core::errors::Result<T>,
) -> PalDoctorProbe {
    match result {
        Ok(_) => pal_probe_value(method, ()),
        Err(storage_ballast_helper::core::errors::SbhError::Pal { source }) => {
            let status = match source {
                storage_ballast_helper::platform::types::PalError::NotImplemented { .. } => {
                    "not_implemented"
                }
                storage_ballast_helper::platform::types::PalError::MethodFailed { .. } => "failed",
            };
            PalDoctorProbe {
                method,
                status,
                bead: source.bead().map(str::to_string),
                message: Some(source.to_string()),
            }
        }
        Err(error) => PalDoctorProbe {
            method,
            status: "failed",
            bead: None,
            message: Some(error.to_string()),
        },
    }
}

#[derive(Debug, Clone, Serialize)]
struct SacredProtectionView {
    path: String,
    source: String,
    metadata: Option<protection::ProtectionMetadata>,
}

#[derive(Debug, Clone, Serialize)]
struct SacredStatusReport {
    command: &'static str,
    action: &'static str,
    sacred_config_path: String,
    protection_count: usize,
    marker_count: usize,
    config_pattern_count: usize,
    sacred_catalog_count: usize,
    scan_candidate_count: usize,
    sacred_overlap_candidate_count: usize,
    protections: Vec<SacredProtectionView>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
struct ProcessAttributionVisibility {
    scope: &'static str,
    all_processes: bool,
    requires_root_for_all_users: bool,
    detail: &'static str,
}

fn run_status(cli: &Cli, args: &StatusArgs) -> Result<(), CliError> {
    if args.sacred {
        if args.watch {
            return Err(CliError::User(
                "status --sacred does not support --watch; run a snapshot status instead"
                    .to_string(),
            ));
        }
        render_sacred_status(cli)
    } else if args.watch {
        run_live_status_loop(cli, STATUS_WATCH_REFRESH_MS, "status --watch", true)
    } else {
        render_status(cli)
    }
}

fn render_sacred_status(cli: &Cli) -> Result<(), CliError> {
    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;
    let report = collect_sacred_status_report(&config)?;

    match output_mode(cli) {
        OutputMode::Human => {
            println!("Sacred Protection Status");
            println!("  Config: {}", report.sacred_config_path);
            println!("  Active protections: {}", report.protection_count);
            println!("    Markers: {}", report.marker_count);
            println!("    Config patterns: {}", report.config_pattern_count);
            println!("  Sacred catalog entries: {}", report.sacred_catalog_count);
            println!(
                "  Current scan candidates overlapping sacred paths: {} / {}",
                report.sacred_overlap_candidate_count, report.scan_candidate_count
            );

            if report.protections.is_empty() {
                println!("\n  No protections configured.");
            } else {
                println!("\n  Protected paths:");
                for entry in &report.protections {
                    match &entry.metadata {
                        Some(meta) if meta.reason.is_some() => println!(
                            "    {} ({}, reason: {})",
                            entry.path,
                            entry.source,
                            meta.reason.as_deref().unwrap_or_default()
                        ),
                        _ => println!("    {} ({})", entry.path, entry.source),
                    }
                }
            }
        }
        OutputMode::Json => {
            let payload = serde_json::to_value(&report)?;
            write_json_line(&payload)?;
        }
    }

    Ok(())
}

fn collect_sacred_status_report(config: &Config) -> Result<SacredStatusReport, CliError> {
    let sacred_config_path = sacred_config_path_for(&config.paths.config_file);
    let protection_patterns = if config.scanner.protected_paths.is_empty() {
        None
    } else {
        Some(config.scanner.protected_paths.as_slice())
    };
    let mut registry = ProtectionRegistry::new(protection_patterns)
        .map_err(|e| CliError::Runtime(e.to_string()))?;

    let root_paths = canonical_scan_roots(config);
    for root in &root_paths {
        let _ = registry.discover_markers(root, 3);
    }

    let protections = registry.list_protections();
    let marker_count = protections
        .iter()
        .filter(|entry| matches!(entry.source, protection::ProtectionSource::MarkerFile))
        .count();
    let config_pattern_count = protections.len().saturating_sub(marker_count);
    let protection_views = protections
        .iter()
        .map(protection_entry_view)
        .collect::<Vec<_>>();

    let sacred_paths = active_sacred_paths(config)?;
    let (scan_candidate_count, sacred_overlap_candidate_count) =
        count_sacred_scan_overlaps(config, root_paths, registry, &sacred_paths)?;

    Ok(SacredStatusReport {
        command: "status",
        action: "sacred",
        sacred_config_path: sacred_config_path.to_string_lossy().to_string(),
        protection_count: protection_views.len(),
        marker_count,
        config_pattern_count,
        sacred_catalog_count: sacred_paths.len(),
        scan_candidate_count,
        sacred_overlap_candidate_count,
        protections: protection_views,
    })
}

fn canonical_scan_roots(config: &Config) -> Vec<PathBuf> {
    config
        .scanner
        .root_paths
        .iter()
        .filter_map(|path| path.canonicalize().ok())
        .collect()
}

fn active_sacred_paths(
    config: &Config,
) -> Result<Vec<storage_ballast_helper::platform::types::SacredPath>, CliError> {
    let mut sacred_paths = detect_platform()
        .map_err(|e| CliError::Runtime(e.to_string()))?
        .sacred_paths();
    sacred_paths.extend(protection::sacred_paths_from_protected_patterns(
        &config.scanner.protected_paths,
    ));
    Ok(sacred_paths)
}

fn protection_entry_view(entry: &protection::ProtectionEntry) -> SacredProtectionView {
    let source = match &entry.source {
        protection::ProtectionSource::MarkerFile => "marker".to_string(),
        protection::ProtectionSource::ConfigPattern(pattern) => format!("config:{pattern}"),
    };
    SacredProtectionView {
        path: entry.path.to_string_lossy().to_string(),
        source,
        metadata: entry.metadata.clone(),
    }
}

fn count_sacred_scan_overlaps(
    config: &Config,
    root_paths: Vec<PathBuf>,
    registry: ProtectionRegistry,
    sacred_paths: &[storage_ballast_helper::platform::types::SacredPath],
) -> Result<(usize, usize), CliError> {
    if root_paths.is_empty() {
        return Ok((0, 0));
    }

    let walker_config = WalkerConfig {
        root_paths,
        max_depth: config.scanner.max_depth,
        follow_symlinks: config.scanner.follow_symlinks,
        cross_devices: config.scanner.cross_devices,
        parallelism: config.scanner.parallelism,
        excluded_paths: config
            .scanner
            .excluded_paths
            .iter()
            .cloned()
            .collect::<HashSet<_>>(),
        opaque_pruning: matches!(config.scanner.engine, ScannerEngineMode::V2),
    };
    let walker = DirectoryWalker::new(walker_config, registry);
    let entries = walker
        .walk()
        .map_err(|e| CliError::Runtime(e.to_string()))?;
    let patterns = ArtifactPatternRegistry::default();

    let mut candidate_count = 0usize;
    let mut overlap_count = 0usize;
    for entry in entries.iter().filter(|entry| entry.metadata.is_dir) {
        let classification = patterns.classify(&entry.path, entry.structural_signals);
        if classification.category == ArtifactCategory::Unknown {
            continue;
        }
        candidate_count += 1;
        let overlaps = protection::find_sacred_overlaps(&entry.path, sacred_paths)
            .map_err(|e| CliError::Runtime(e.to_string()))?;
        if !overlaps.is_empty() {
            overlap_count += 1;
        }
    }

    Ok((candidate_count, overlap_count))
}

#[allow(clippy::too_many_lines)]
fn render_status(cli: &Cli) -> Result<(), CliError> {
    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;
    let platform = detect_platform().map_err(|e| CliError::Runtime(e.to_string()))?;
    let version = env!("CARGO_PKG_VERSION");

    // Gather filesystem stats for all root paths + standard mounts.
    let mounts = platform
        .mount_points()
        .map_err(|e| CliError::Runtime(e.to_string()))?;

    // Read daemon state.json for EWMA predictions (optional).
    let daemon_state = std::fs::read_to_string(&config.paths.state_file)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());

    // Liveness: the daemon's exclusive lock next to state.json is
    // authoritative; state-file age and the service manager's view of the
    // unit are the fallbacks for daemons that predate the lock. (The former
    // `/proc/*/cmdline` substring scan reported any shell mentioning
    // "sbh daemon" as a running daemon.)
    let service_active = platform
        .service_manager()
        .status()
        .ok()
        .filter(|state| state != "unknown")
        .map(|state| state == "active");
    let liveness = detect_daemon_liveness(&config.paths.state_file, service_active);
    let daemon_running = liveness.running;
    // bd-rc-master-ajg1.4.9: a running daemon rewrites state.json on request,
    // so the rest of this report reads a fresh file instead of one up to a
    // write interval old. The state file stays the source when the socket
    // is absent, unreadable, or refuses.
    let status_source = {
        use storage_ballast_helper::daemon::control::{read_endpoint, request};
        let refreshed = daemon_running
            && read_endpoint(&config.paths.state_file).is_some_and(|endpoint| {
                endpoint.socket.exists()
                    && request(&endpoint.socket, &endpoint.token, "status", &json!({}))
                        .is_ok_and(|reply| reply.ok)
            });
        if refreshed { "socket" } else { "state_file" }
    };

    // Open SQLite database for recent activity (optional, read-only).
    let db_stats = if config.paths.sqlite_db.exists() {
        SqliteLogger::open_read_only(&config.paths.sqlite_db)
            .ok()
            .and_then(|db| {
                let engine = StatsEngine::new(&db);
                engine.window_stats(std::time::Duration::from_hours(1)).ok()
            })
    } else {
        None
    };
    let memory_info = platform.memory_info().ok();
    let memory_pressure = platform.memory_pressure().ok();
    let process_visibility = process_attribution_visibility(platform.name());

    match output_mode(cli) {
        OutputMode::Human => {
            println!("Storage Ballast Helper v{version}");
            println!("  Config: {}", config.paths.config_file.display());
            if daemon_running {
                match &liveness.lock {
                    Some(lock) => println!(
                        "  Daemon: running (pid {}, since {}, {})",
                        lock.pid, lock.started_at, liveness.reason
                    ),
                    None => println!("  Daemon: running ({})", liveness.reason),
                }
            } else {
                let age = liveness.state_age_secs.map_or_else(
                    || "no state file".to_string(),
                    |s| format!("state {s}s old"),
                );
                println!(
                    "  Daemon: NOT running ({}, {age}) — degraded mode",
                    liveness.reason
                );
            }

            // Pressure status table.
            println!("\nPressure Status:");
            println!(
                "  {:<20}  {:>10}  {:>10}  {:>7}  {:<10}",
                "Mount Point", "Total", "Free", "Free %", "Level"
            );
            println!("  {}", "-".repeat(65));

            let mut overall_level = "green";
            let mut snapshot_warnings = Vec::new();
            let mut purgeable_notices = Vec::new();
            for mount in &mounts {
                let Ok(capacity) = platform.capacity(&mount.path) else {
                    continue;
                };

                // Skip pseudo/virtual/read-only filesystems (squashfs snap
                // mounts, proc, sysfs, etc.) — they can't fill up and don't
                // represent actionable storage pressure.
                if capacity.total_bytes == 0 || capacity.is_readonly || mount.is_ram_backed {
                    continue;
                }

                let free_pct = capacity_free_pct(&capacity);
                let level = pressure_level_str(free_pct, &config);
                if pressure_severity(level) > pressure_severity(overall_level) {
                    overall_level = level;
                }
                if let Some(warning) = local_snapshot_warning(&capacity) {
                    snapshot_warnings.push(warning);
                }
                if let Some(notice) = purgeable_storage_notice(&capacity) {
                    purgeable_notices.push(notice);
                }

                let ram_note = if platform.is_ram_backed(&mount.path).unwrap_or(false) {
                    " (tmpfs)"
                } else {
                    ""
                };

                println!(
                    "  {:<20}  {:>10}  {:>10}  {:>6.1}%  {:<10}",
                    format!("{}{ram_note}", mount.path.display()),
                    format_bytes(capacity.total_bytes),
                    format_bytes(capacity.available_bytes),
                    free_pct,
                    level.to_uppercase(),
                );
            }

            if !snapshot_warnings.is_empty() {
                println!("\nLocal Snapshots:");
                for warning in snapshot_warnings {
                    println!("  {warning}");
                }
            }

            if !purgeable_notices.is_empty() {
                println!("\nPurgeable Storage:");
                for notice in purgeable_notices {
                    println!("  {notice}");
                }
                println!(
                    "  sbh reports purgeable storage separately and does not count it as free space for pressure decisions."
                );
            }

            if let Some(memory) = &memory_info {
                println!("\nMemory:");
                let ram_free_pct = bytes_to_pct(memory.available_bytes, memory.total_bytes);
                println!(
                    "  RAM:  {:>10} free / {:>10} total ({:>5.1}% free)",
                    format_bytes(memory.available_bytes),
                    format_bytes(memory.total_bytes),
                    ram_free_pct
                );

                if memory.swap_total_bytes > 0 {
                    let swap_used_bytes = memory
                        .swap_total_bytes
                        .saturating_sub(memory.swap_free_bytes);
                    let swap_used_pct = bytes_to_pct(swap_used_bytes, memory.swap_total_bytes);
                    let thrash_risk = is_swap_thrash_risk(memory);
                    let risk_note = if thrash_risk { "  [THRASH-RISK]" } else { "" };
                    println!(
                        "  Swap: {:>10} used / {:>10} total ({:>5.1}% used){risk_note}",
                        format_bytes(swap_used_bytes),
                        format_bytes(memory.swap_total_bytes),
                        swap_used_pct
                    );
                    if thrash_risk {
                        println!(
                            "  Hint: high swap use with substantial free RAM can indicate swap thrashing."
                        );
                    }
                } else {
                    println!("  Swap: disabled");
                }
            }

            if let Some(visibility) = process_visibility {
                println!("\nProcess Attribution:");
                println!("  Visibility: {}", visibility.detail);
            }

            // Rate estimates from daemon state (v2 `rates`): fill rate,
            // acceleration, confidence and the red horizon per mount.
            if let Some(state) = &daemon_state
                && let Some(rates) = state.get("rates").and_then(Value::as_object)
                && !rates.is_empty()
            {
                println!("\nRate Estimates:");
                let min_confidence = config.pressure.prediction.min_confidence;
                for (mount, rate_obj) in rates {
                    if let Some(forecast) = MountForecast::from_rate(rate_obj) {
                        println!("{}", rate_line(mount, &forecast, min_confidence));
                    }
                }
            }

            // Per-mount control state from the daemon: what it is doing on
            // each device and why it is idle on the others.
            if let Some(state) = &daemon_state
                && let Some(controllers) = state.get("mount_controllers").and_then(Value::as_array)
                && !controllers.is_empty()
            {
                if let Some(budget) = daemon_state
                    .as_ref()
                    .and_then(|state| state.get("cpu_budget"))
                {
                    let pct = budget.get("pct").and_then(Value::as_u64).unwrap_or(0);
                    let used = budget
                        .get("used_pct_1m")
                        .and_then(Value::as_f64)
                        .unwrap_or(0.0);
                    let deficit = budget
                        .get("deficit_secs")
                        .and_then(Value::as_f64)
                        .unwrap_or(0.0);
                    let minutes = budget
                        .get("over_budget_minutes")
                        .and_then(Value::as_u64)
                        .unwrap_or(0);
                    let idle = daemon_state
                        .as_ref()
                        .and_then(|state| state.get("idle_reason"))
                        .and_then(Value::as_str)
                        .map_or_else(String::new, |reason| format!(", idle: {reason}"));
                    if pct == 0 {
                        println!("  CPU budget: off (used {used:.1}% of a core last minute{idle})");
                    } else if deficit > 0.0 {
                        println!(
                            "  CPU budget: {pct}% of a core, OVER by {deficit:.1} s (used {used:.1}% last minute, {minutes} min over{idle})"
                        );
                    } else {
                        println!(
                            "  CPU budget: {pct}% of a core (used {used:.1}% last minute{idle})"
                        );
                    }
                }
                // bd-rc-master-ajg1.7.4: the daemon's own files on a volume
                // it reclaims.
                if let Some(logging) = daemon_state.as_ref().and_then(|state| state.get("logging"))
                    && logging.get("on_monitored_fs") == Some(&Value::Bool(true))
                {
                    let device = logging.get("device").and_then(Value::as_str).unwrap_or("?");
                    let level = logging
                        .get("level")
                        .and_then(Value::as_str)
                        .map_or_else(String::new, |level| format!(", now {level}"));
                    let mirror = if logging.get("mirroring") == Some(&Value::Bool(true)) {
                        "; JSONL is being mirrored to the RAM fallback"
                    } else {
                        ""
                    };
                    println!(
                        "  WARNING: the activity database/JSONL/state live on {device}, which \
                         sbh reclaims{level}{mirror}. Move [paths] to a volume sbh does not \
                         reclaim, or accept degraded logging under pressure."
                    );
                }
                if let Some(policy) = daemon_state
                    .as_ref()
                    .and_then(|state| state.get("policy"))
                    .filter(|p| {
                        p.get("mode")
                            .and_then(Value::as_str)
                            .is_some_and(|m| !m.is_empty())
                    })
                {
                    let field = |key: &str| policy.get(key).and_then(Value::as_str).unwrap_or("-");
                    let since = policy
                        .get("since_secs")
                        .and_then(Value::as_u64)
                        .unwrap_or(0);
                    let mut line = format!(
                        "  Policy: {} (since {}, auto_recover_to {})",
                        field("mode"),
                        format_eta(f64::from(u32::try_from(since).unwrap_or(u32::MAX))),
                        field("auto_recover_to")
                    );
                    if let Some(reason) = policy.get("last_fallback_reason").and_then(Value::as_str)
                    {
                        line.push_str(", last fallback: ");
                        line.push_str(reason);
                    }
                    println!("{line}");
                }
                println!("\nMount Control:");
                let (h_mount, h_state, h_level, h_reclaim, h_reserve) =
                    ("Mount Point", "State", "Level", "Reclaim", "Reserve");
                println!(
                    "  {h_mount:<20}  {h_state:<12}  {h_level:<8}  {h_reclaim:<12}  {h_reserve:<22}  Note"
                );
                for controller in controllers {
                    let field = |key: &str| {
                        controller
                            .get(key)
                            .and_then(Value::as_str)
                            .unwrap_or("-")
                            .to_string()
                    };
                    let mut note = field("idle_reason");
                    if let Some(secs) = controller.get("rescan_in_secs").and_then(Value::as_u64) {
                        note = format!("{note} (rescan in {secs}s)");
                    }
                    if note == "-" {
                        note.clear();
                    }
                    let reserve = controller.get("reserve_state").map_or_else(
                        || "-".to_string(),
                        |reserve| {
                            let present = reserve
                                .get("present_bytes")
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                            let target = reserve
                                .get("target_bytes")
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                            let mut text =
                                format!("{}/{}", format_bytes(present), format_bytes(target));
                            if let Some(minutes) =
                                reserve.get("horizon_minutes").and_then(Value::as_f64)
                            {
                                text = format!("{text} ({minutes:.0} min)");
                            }
                            if reserve.get("floor_limited") == Some(&Value::Bool(true)) {
                                text.push_str(" floor");
                            }
                            // bd-rc-master-ajg1.2.18: what the observed
                            // bursts say the reserve should be.
                            if let Some(burst) = reserve.get("burst") {
                                let recommended = burst
                                    .get("recommended_bytes")
                                    .and_then(Value::as_u64)
                                    .unwrap_or(0);
                                let windows =
                                    burst.get("windows").and_then(Value::as_u64).unwrap_or(0);
                                let method = burst
                                    .get("method")
                                    .and_then(Value::as_str)
                                    .unwrap_or("floor");
                                text = format!(
                                    "{text} need {} ({method}, {windows} windows)",
                                    format_bytes(recommended)
                                );
                            }
                            text
                        },
                    );
                    let record: Option<MountStateRecord> =
                        serde_json::from_value(controller.clone()).ok();
                    if record.as_ref().is_some_and(unprotected_pressure) {
                        note = if note.is_empty() {
                            "UNPROTECTED".to_string()
                        } else {
                            format!("UNPROTECTED, {note}")
                        };
                    }
                    println!(
                        "  {:<20}  {:<12}  {:<8}  {:<12}  {reserve:<22}  {note}",
                        field("mount"),
                        field("state"),
                        field("level"),
                        field("reclaim_capability"),
                    );
                }
            }

            // Ballast info: configured pool vs actually releasable reserve (#16).
            let ballast = BallastAvailability::observe(&config.paths.ballast_dir, &config.ballast);
            println!("\nBallast:");
            println!(
                "  Configured: {} files x {}",
                config.ballast.file_count,
                format_bytes(config.ballast.file_size_bytes),
            );
            println!(
                "  Total pool: {}",
                format_bytes(ballast_total_pool_bytes(
                    config.ballast.file_count,
                    config.ballast.file_size_bytes,
                )),
            );
            // Include the unreadable tally when non-zero: without it the line
            // reads "0 files (0 B), 0 missing" for a 10-file pool, and the
            // numbers visibly fail to add up to the configured count.
            if ballast.is_authoritative() {
                println!(
                    "  Releasable: {} files ({}), {} missing",
                    ballast.available_count,
                    format_bytes(ballast.releasable_bytes),
                    ballast.missing_count,
                );
            } else {
                println!(
                    "  Releasable: {} files ({}), {} missing, {} unreadable",
                    ballast.available_count,
                    format_bytes(ballast.releasable_bytes),
                    ballast.missing_count,
                    ballast.unreadable_count,
                );
            }
            println!("  Health: {}", ballast.health);
            if ballast.health == BallastHealth::Empty {
                println!(
                    "  WARNING: a {} reserve is configured but 0 bytes are releasable — \
                     the emergency reserve does not exist. Run: sbh ballast provision",
                    format_bytes(ballast.configured_pool_bytes),
                );
            }
            if !ballast.is_authoritative() {
                println!(
                    "  NOTE: {} of {} ballast files could not be inspected (permission \
                     denied or I/O error), so the counts above are not authoritative. \
                     The ballast dir is normally root-owned mode 700; re-run as \
                     `sudo sbh ballast status` for the real state.",
                    ballast.unreadable_count, ballast.configured_count,
                );
            }

            // Recent activity from database.
            if let Some(stats) = &db_stats {
                println!("\nRecent Activity (last hour):");
                println!(
                    "  Deletions: {} items, {} freed",
                    stats.deletions.count,
                    format_bytes(stats.deletions.total_bytes_freed),
                );
                if let Some(cat) = &stats.deletions.most_common_category {
                    println!("  Most common: {cat}");
                }
                if stats.deletions.failures > 0 {
                    println!("  Failures: {}", stats.deletions.failures);
                }
            } else {
                println!("\nRecent Activity: no database available");
            }
        }
        OutputMode::Json => {
            // #16: actual ballast availability, not just configured totals.
            let ballast_availability =
                BallastAvailability::observe(&config.paths.ballast_dir, &config.ballast);
            let mut mounts_json: Vec<Value> = Vec::new();
            let mut overall_level = "green";

            for mount in &mounts {
                let Ok(capacity) = platform.capacity(&mount.path) else {
                    continue;
                };
                // Skip pseudo/virtual/read-only filesystems.
                if capacity.total_bytes == 0 || capacity.is_readonly || mount.is_ram_backed {
                    continue;
                }
                let free_pct = capacity_free_pct(&capacity);
                let level = pressure_level_str(free_pct, &config);
                if pressure_severity(level) > pressure_severity(overall_level) {
                    overall_level = level;
                }

                mounts_json.push(status_mount_json(&capacity, level, free_pct));
            }

            let recent = db_stats.as_ref().map(|s| {
                json!({
                    "deletions": s.deletions.count,
                    "bytes_freed": s.deletions.total_bytes_freed,
                    "failures": s.deletions.failures,
                    "most_common_category": s.deletions.most_common_category,
                })
            });

            let payload = json!({
                "command": "status",
                "schema_version": 2,
                "version": version,
                "daemon_running": daemon_running,
                "source": status_source,
                "daemon_state_reason": liveness.reason,
                "daemon_pid": liveness.lock.as_ref().map(|l| l.pid),
                "state_age_secs": liveness.state_age_secs,
                "state_stale": liveness.state_stale,
                // The daemon's per-mount forecast (state.json v2 `rates`)
                // with the warming flag resolved against this config.
                "rates": daemon_state
                    .as_ref()
                    .and_then(|state| state.get("rates"))
                    .and_then(Value::as_object)
                    .map(|rates| {
                        let min_confidence = config.pressure.prediction.min_confidence;
                        Value::Object(
                            rates
                                .iter()
                                .filter_map(|(mount, rate)| {
                                    MountForecast::from_rate(rate)
                                        .map(|f| (mount.clone(), f.to_json(min_confidence)))
                                })
                                .collect(),
                        )
                    }),
                // Q7: the daemon's own accounting from state.json (absent
                // when no state file is readable).
                "daemon": daemon_state.as_ref().map(|state| json!({
                    "run_id": state.get("run_id").cloned().unwrap_or(Value::Null),
                    "cpu_secs_total": state.get("cpu_secs_total").cloned().unwrap_or(Value::Null),
                    "cpu_budget": state.get("cpu_budget").cloned().unwrap_or(Value::Null),
                    "idle_reason": state.get("idle_reason").cloned().unwrap_or(Value::Null),
                    "threads": state.get("threads").cloned().unwrap_or(Value::Null),
                    "stopped_at": state.get("stopped_at").cloned().unwrap_or(Value::Null),
                    "exit_reason": state.get("exit_reason").cloned().unwrap_or(Value::Null),
                })),
                // The policy engine: mode, since, last fallback reason and
                // where automatic recovery lands.
                "policy": daemon_state
                    .as_ref()
                    .and_then(|state| state.get("policy").cloned())
                    .unwrap_or(Value::Null),
            "config_path": config.paths.config_file.to_string_lossy(),
            "pressure": {
                "mounts": mounts_json,
                "overall": overall_level,
                "mount_controllers": daemon_state
                    .as_ref()
                    .and_then(|state| state.get("mount_controllers").cloned())
                    .unwrap_or_else(|| json!([])),
            },
                "ballast": {
                    "file_count": config.ballast.file_count,
                    "file_size_bytes": config.ballast.file_size_bytes,
                    "total_pool_bytes": ballast_total_pool_bytes(
                        config.ballast.file_count,
                        config.ballast.file_size_bytes,
                    ),
                    // #16: actual inventory state, so automation can tell a
                    // configured reserve from a releasable one.
                    "available_count": ballast_availability.available_count,
                    "releasable_bytes": ballast_availability.releasable_bytes,
                    "missing_count": ballast_availability.missing_count,
                    // Non-zero means this snapshot is NOT authoritative — the
                    // usual cause is an unprivileged caller against a root-owned
                    // mode-700 ballast dir. Automation must not read
                    // `missing_count` as a real absence while this is > 0.
                    "unreadable_count": ballast_availability.unreadable_count,
                    "authoritative": ballast_availability.is_authoritative(),
                    "health": ballast_availability.health.as_str(),
                },
                "memory": memory_info.as_ref().map(|memory| {
                    let swap_used_bytes = memory.swap_total_bytes.saturating_sub(memory.swap_free_bytes);
                    json!({
                        "ram_total_bytes": memory.total_bytes,
                        "ram_available_bytes": memory.available_bytes,
                        "ram_free_pct": bytes_to_pct(memory.available_bytes, memory.total_bytes),
                        "swap_total_bytes": memory.swap_total_bytes,
                        "swap_free_bytes": memory.swap_free_bytes,
                        "swap_used_bytes": swap_used_bytes,
                        "swap_used_pct": bytes_to_pct(swap_used_bytes, memory.swap_total_bytes),
                        "swap_thrash_risk": is_swap_thrash_risk(memory),
                    })
                }),
                "memory_pressure": memory_pressure.as_ref().map(status_memory_pressure_json),
                "process_attribution": {
                    "visibility": process_visibility.as_ref().map(process_attribution_visibility_json),
                },
                "recent_hour": recent,
                "policy_mode": daemon_state.as_ref().and_then(|s| s.get("policy_mode")).and_then(|v| v.as_str()),
            });
            write_json_line(&payload)?;
        }
    }

    Ok(())
}

fn run_log(cli: &Cli, args: &LogArgs) -> Result<(), CliError> {
    use io::{BufRead, Seek};

    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;
    let log_path = &config.paths.jsonl_log;

    // Read-side command on a system install: the daemon's log usually lives
    // in the system data dir and belongs to another user. Say so instead of
    // failing with a bare "not found"/EACCES.
    let permission_denied = log_path.exists()
        && matches!(
            std::fs::File::open(log_path),
            Err(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied
        );
    if !log_path.exists() || permission_denied {
        let hint = daemon_activity_db_hint(log_path);
        let error = if permission_denied {
            "permission_denied"
        } else {
            "no_log_file"
        };
        match output_mode(cli) {
            OutputMode::Human => {
                if permission_denied {
                    eprintln!(
                        "Activity log {} is not readable by this user (it belongs to the daemon's user).",
                        log_path.display()
                    );
                } else {
                    eprintln!("No activity log found at {}.", log_path.display());
                }
                if let Some(path) = &hint {
                    eprintln!("  The daemon's log is at {}.", path.display());
                }
                if permission_denied || hint.is_some() {
                    eprintln!("  The daemon runs as another user — try: sudo sbh log");
                } else {
                    eprintln!("  Run the daemon to start collecting activity.");
                }
            }
            OutputMode::Json => {
                let mut payload = json!({
                    "command": "log",
                    "error": error,
                    "log_path": log_path.to_string_lossy(),
                });
                if permission_denied || hint.is_some() {
                    payload["hint"] = json!("daemon log belongs to another user; retry with sudo");
                }
                if let Some(path) = &hint {
                    payload["root_log_path"] = json!(path.to_string_lossy());
                }
                write_json_line(&payload)?;
            }
        }
        return Err(CliError::Runtime(format!(
            "{}: {}",
            if permission_denied {
                "log file is not readable by this user"
            } else {
                "log file not found"
            },
            log_path.display()
        )));
    }

    // Always print the tail first, whether following or not.
    print_tail_lines(log_path, args.tail, args.r#type.as_deref())?;

    if args.follow {
        // Follow mode: watch for new lines after the initial tail.
        let file = std::fs::File::open(log_path)
            .map_err(|e| CliError::Runtime(format!("failed to open log: {e}")))?;
        let mut reader = io::BufReader::new(file);

        // Seek to end.
        reader
            .seek(io::SeekFrom::End(0))
            .map_err(|e| CliError::Runtime(format!("seek error: {e}")))?;

        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    // No new data; sleep briefly and retry.
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
                Ok(_) => {
                    let trimmed = line.trim_end();
                    if !trimmed.is_empty() && matches_type_filter(trimmed, args.r#type.as_deref()) {
                        println!("{}", format_log_line(trimmed));
                    }
                }
                Err(e) => {
                    return Err(CliError::Runtime(format!("read error: {e}")));
                }
            }
        }
    }

    Ok(())
}

fn print_tail_lines(path: &Path, count: usize, type_filter: Option<&str>) -> Result<(), CliError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| CliError::Runtime(format!("failed to read log: {e}")))?;

    let lines: Vec<&str> = content
        .lines()
        .filter(|line| !line.trim().is_empty() && matches_type_filter(line, type_filter))
        .collect();

    let start = lines.len().saturating_sub(count);
    for line in &lines[start..] {
        println!("{}", format_log_line(line));
    }

    Ok(())
}

fn matches_type_filter(line: &str, type_filter: Option<&str>) -> bool {
    let Some(filter) = type_filter else {
        return true;
    };
    let filter_lower = filter.to_lowercase();
    // Match against the "event" field in the JSONL line.
    // Common event types: "deletion", "scan_started", "scan_completed",
    // "pressure_changed", "error", "ballast_released", etc.
    if let Ok(v) = serde_json::from_str::<Value>(line)
        && let Some(event) = v.get("event").and_then(|e| e.as_str())
    {
        let event_lower = event.to_lowercase();
        return event_lower.contains(&filter_lower);
    }
    // Fallback: substring match on the raw line.
    line.to_lowercase().contains(&filter_lower)
}

fn format_log_line(line: &str) -> String {
    // Try to parse as JSON and format nicely; fall back to raw output.
    serde_json::from_str::<Value>(line).map_or_else(
        |_| line.to_string(),
        |v| {
            let ts = v
                .get("timestamp")
                .or_else(|| v.get("ts"))
                .and_then(|t| t.as_str())
                .unwrap_or("?");
            let event = v.get("event").and_then(|e| e.as_str()).unwrap_or("?");

            // Build a compact summary from common fields.
            let detail = v
                .get("message")
                .and_then(|m| m.as_str())
                .or_else(|| v.get("path").and_then(|p| p.as_str()))
                .or_else(|| v.get("mount").and_then(|m| m.as_str()))
                .unwrap_or("");

            if detail.is_empty() {
                format!("{ts}  {event}")
            } else {
                format!("{ts}  {event:<20}  {detail}")
            }
        },
    )
}

/// Map free percentage to pressure level string.
fn pressure_level_str(free_pct: f64, config: &Config) -> &'static str {
    if free_pct >= config.pressure.green_min_free_pct {
        "green"
    } else if free_pct >= config.pressure.yellow_min_free_pct {
        "yellow"
    } else if free_pct >= config.pressure.orange_min_free_pct {
        "orange"
    } else if free_pct >= config.pressure.red_min_free_pct {
        "red"
    } else {
        "critical"
    }
}

/// Severity ordering for pressure levels.
fn pressure_severity(level: &str) -> u8 {
    match level {
        "yellow" => 1,
        "orange" => 2,
        "red" => 3,
        "critical" => 4,
        _ => 0,
    }
}

fn capacity_free_pct(capacity: &Capacity) -> f64 {
    bytes_to_pct(capacity.available_bytes, capacity.total_bytes)
}

/// One mount of `status --json`. `free` is `available_bytes` on every
/// family; the APFS-only keys (container accounting, purgeable and snapshot
/// bytes, `free_excludes_purgeable`) appear only when the capacity was
/// measured on APFS, so a Linux consumer never sees a null APFS field.
fn status_mount_json(capacity: &Capacity, level: &str, free_pct: f64) -> Value {
    let mut mount = json!({
        "path": capacity.mount_point.to_string_lossy(),
        "total": capacity.total_bytes,
        "free": capacity.available_bytes,
        "free_pct": free_pct,
        "level": level,
        "fs_type": capacity.fs_type,
        "volume_total": capacity.volume_total_bytes,
        "volume_available": capacity.volume_available_bytes,
        "platform": capacity_platform_json(capacity),
    });
    if capacity_is_apfs(capacity)
        && let Some(object) = mount.as_object_mut()
    {
        object.insert("container_id".into(), json!(capacity.container_id));
        object.insert(
            "container_total".into(),
            json!(capacity.container_total_bytes),
        );
        object.insert(
            "container_available".into(),
            json!(capacity.container_available_bytes),
        );
        object.insert("volume_role".into(), json!(capacity.volume_role));
        object.insert("shared_volumes".into(), json!(capacity.shared_volumes));
        object.insert("is_primary".into(), json!(capacity.is_primary));
        object.insert("purgeable_bytes".into(), json!(capacity.purgeable_bytes));
        object.insert("free_excludes_purgeable".into(), json!(true));
        object.insert(
            "local_snapshot_bytes".into(),
            json!(capacity.local_snapshot_bytes),
        );
        object.insert(
            "local_snapshot_reclaim_command".into(),
            json!(local_snapshot_reclaim_command(capacity)),
        );
    }
    mount
}

/// Whether a mount's capacity came from APFS container accounting, where
/// `free` already excludes purgeable space and the container fields mean
/// something.
fn capacity_is_apfs(capacity: &Capacity) -> bool {
    capacity.fs_type.eq_ignore_ascii_case("apfs")
}

/// The per-family `platform` block: APFS container accounting under
/// `darwin.apfs`, the filesystem facts sbh has for a Linux mount under
/// `linux`, and an empty object for anything else. A Linux mount never
/// carries a null APFS block.
fn capacity_platform_json(capacity: &Capacity) -> Value {
    if capacity_is_apfs(capacity) {
        return json!({
            "darwin": {
                "apfs": {
                    "container_id": capacity.container_id.as_deref(),
                    "container_total_bytes": capacity.container_total_bytes,
                    "container_available_bytes": capacity.container_available_bytes,
                    "volume_total_bytes": capacity.volume_total_bytes,
                    "volume_available_bytes": capacity.volume_available_bytes,
                    "volume_role": capacity.volume_role.as_deref(),
                    "shared_volumes": &capacity.shared_volumes,
                    "is_primary": capacity.is_primary,
                    "purgeable_bytes": capacity.purgeable_bytes,
                    "local_snapshot_bytes": capacity.local_snapshot_bytes,
                    "free_excludes_purgeable": true,
                }
            }
        });
    }
    linux_platform_json(capacity)
}

/// The `linux` family block: the filesystem type, whether it is RAM-backed
/// (reclaiming there frees memory, not disk), the read-only flag, and the
/// device id of the mount point (null when the path cannot be stat'ed).
#[cfg(target_os = "linux")]
fn linux_platform_json(capacity: &Capacity) -> Value {
    use std::os::unix::fs::MetadataExt as _;

    let device_id = std::fs::metadata(&capacity.mount_point)
        .ok()
        .map(|metadata| metadata.dev());
    json!({
        "linux": {
            "fs_type": capacity.fs_type,
            "is_ram_backed": storage_ballast_helper::platform::linux::disk::is_ram_fs(&capacity.fs_type),
            "is_readonly": capacity.is_readonly,
            "device_id": device_id,
        }
    })
}

/// Families sbh has no extra facts for get an empty `platform` block.
#[cfg(not(target_os = "linux"))]
fn linux_platform_json(_capacity: &Capacity) -> Value {
    json!({})
}

fn process_attribution_visibility(platform_name: &str) -> Option<ProcessAttributionVisibility> {
    process_attribution_visibility_for(platform_name, effective_user_is_root())
}

fn process_attribution_visibility_for(
    platform_name: &str,
    is_root: bool,
) -> Option<ProcessAttributionVisibility> {
    if !platform_name.eq_ignore_ascii_case("macos") {
        return None;
    }

    if is_root {
        Some(ProcessAttributionVisibility {
            scope: "all_processes",
            all_processes: true,
            requires_root_for_all_users: false,
            detail: "all processes (running as root/LaunchDaemon)",
        })
    } else {
        Some(ProcessAttributionVisibility {
            scope: "own_user_processes",
            all_processes: false,
            requires_root_for_all_users: true,
            detail: "own-user processes only; run sbh as a root LaunchDaemon for all-user process I/O attribution",
        })
    }
}

#[cfg(unix)]
fn effective_user_is_root() -> bool {
    nix::unistd::Uid::effective().is_root()
}

#[cfg(not(unix))]
fn effective_user_is_root() -> bool {
    false
}

fn process_attribution_visibility_json(visibility: &ProcessAttributionVisibility) -> Value {
    json!({
        "scope": visibility.scope,
        "all_processes": visibility.all_processes,
        "requires_root_for_all_users": visibility.requires_root_for_all_users,
        "detail": visibility.detail,
    })
}

fn purgeable_storage_notice(capacity: &Capacity) -> Option<String> {
    let bytes = capacity.purgeable_bytes.filter(|bytes| *bytes > 0)?;
    Some(format!(
        "{} reports {} purgeable APFS storage",
        capacity.mount_point.display(),
        format_bytes(bytes)
    ))
}

fn local_snapshot_warning(capacity: &Capacity) -> Option<String> {
    let bytes = capacity.local_snapshot_bytes.filter(|bytes| *bytes > 0)?;
    Some(format!(
        "{} has approximately {} retained by local Time Machine snapshots. Reclaim via: {}",
        capacity.mount_point.display(),
        format_bytes(bytes),
        local_snapshot_reclaim_command(capacity)?
    ))
}

fn local_snapshot_reclaim_command(capacity: &Capacity) -> Option<String> {
    capacity.local_snapshot_bytes.filter(|bytes| *bytes > 0)?;
    Some(local_snapshot_thin_shell_command(&capacity.mount_point))
}

fn local_snapshot_thin_shell_command(mount: &Path) -> String {
    format!(
        "sudo tmutil thinlocalsnapshots {} {} {}",
        shell_quote(&mount.to_string_lossy()),
        LOCAL_SNAPSHOT_THIN_AMOUNT_BYTES,
        LOCAL_SNAPSHOT_THIN_URGENCY
    )
}

fn bytes_to_pct(value: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        #[allow(clippy::cast_precision_loss)]
        {
            (value as f64 * 100.0) / total as f64
        }
    }
}

fn is_swap_thrash_risk(memory: &MemoryInfo) -> bool {
    const THRASH_SWAP_USED_PCT: f64 = 70.0;
    const MIN_AVAILABLE_RAM_BYTES: u64 = 8 * 1024 * 1024 * 1024;

    if memory.swap_total_bytes == 0 {
        return false;
    }

    let swap_used_bytes = memory
        .swap_total_bytes
        .saturating_sub(memory.swap_free_bytes);
    let swap_used_pct = bytes_to_pct(swap_used_bytes, memory.swap_total_bytes);

    if swap_used_pct < THRASH_SWAP_USED_PCT {
        return false;
    }

    // Suppress false positive on zram: high swap usage with ample free RAM
    // is normal when swap is backed by zram (compressed memory, not disk).
    if Path::new("/sys/block/zram0").exists() {
        #[allow(clippy::cast_precision_loss)]
        let free_ram_pct =
            (memory.available_bytes as f64 * 100.0) / memory.total_bytes.max(1) as f64;
        if free_ram_pct > 40.0 {
            return false;
        }
    }

    // Thrash risk requires RAM to be low. If the system still has plenty of
    // available RAM, swap usage alone doesn't indicate thrashing — the kernel
    // simply swapped out cold pages, which is normal Linux behavior.
    memory.available_bytes < MIN_AVAILABLE_RAM_BYTES
}

fn status_memory_pressure_json(pressure: &MemoryPressure) -> Value {
    json!({
        "level": memory_pressure_level_label(pressure.level),
        "free_pages": pressure.free_pages,
        "used_pages": pressure.used_pages,
        "page_size_bytes": pressure.page_size_bytes,
        "free_bytes": pressure.free_pages.zip(pressure.page_size_bytes).map(|(pages, page_size)| pages.saturating_mul(page_size)),
        "used_bytes": pressure.used_pages.zip(pressure.page_size_bytes).map(|(pages, page_size)| pages.saturating_mul(page_size)),
        "compressor_used_bytes": pressure.compressor_used_bytes,
        "swap_total_bytes": pressure.swap_total_bytes,
        "swap_used_bytes": pressure.swap_used_bytes,
        "linux_psi_avg10": pressure.linux_psi_avg10,
    })
}

fn memory_pressure_level_label(level: MemoryPressureLevel) -> &'static str {
    match level {
        MemoryPressureLevel::Normal => "normal",
        MemoryPressureLevel::Warn => "warn",
        MemoryPressureLevel::Critical => "critical",
        MemoryPressureLevel::Unknown => "unknown",
    }
}

fn ballast_total_pool_bytes(file_count: usize, file_size_bytes: u64) -> u64 {
    u64::try_from(file_count)
        .ok()
        .and_then(|count| count.checked_mul(file_size_bytes))
        .unwrap_or(u64::MAX)
}

fn default_protection_metadata() -> protection::ProtectionMetadata {
    protection::ProtectionMetadata {
        reason: None,
        protected_by: std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .ok()
            .filter(|name| !name.trim().is_empty()),
        protected_at: Some(chrono::Utc::now().to_rfc3339()),
    }
}

fn add_sacred_protected_path(config: &Config, path: &Path) -> Result<(PathBuf, bool), CliError> {
    let sacred_config_path = sacred_config_path_for(&config.paths.config_file);
    let mut sacred =
        load_sacred_config(&sacred_config_path).map_err(|e| CliError::Runtime(e.to_string()))?;
    let changed = sacred.add_protected_path(path.to_string_lossy().to_string());
    if changed || !sacred_config_path.exists() {
        write_sacred_config(&sacred_config_path, &sacred)
            .map_err(|e| CliError::Runtime(e.to_string()))?;
    }
    Ok((sacred_config_path, changed))
}

fn remove_sacred_protected_path(config: &Config, path: &Path) -> Result<(PathBuf, bool), CliError> {
    let sacred_config_path = sacred_config_path_for(&config.paths.config_file);
    if !sacred_config_path.exists() {
        return Ok((sacred_config_path, false));
    }

    let mut sacred =
        load_sacred_config(&sacred_config_path).map_err(|e| CliError::Runtime(e.to_string()))?;
    let protected_path = path.to_string_lossy().to_string();
    let removed = sacred.remove_protected_path(&protected_path);
    if removed {
        write_sacred_config(&sacred_config_path, &sacred)
            .map_err(|e| CliError::Runtime(e.to_string()))?;
    }
    Ok((sacred_config_path, removed))
}

fn run_protect(cli: &Cli, args: &ProtectArgs) -> Result<(), CliError> {
    if args.list {
        run_protect_list(cli)
    } else if let Some(path) = &args.path {
        run_protect_create(cli, path)
    } else {
        Ok(())
    }
}

fn run_protect_list(cli: &Cli) -> Result<(), CliError> {
    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;

    let protection_patterns = if config.scanner.protected_paths.is_empty() {
        None
    } else {
        Some(config.scanner.protected_paths.as_slice())
    };
    let mut registry = ProtectionRegistry::new(protection_patterns)
        .map_err(|e| CliError::Runtime(e.to_string()))?;

    for root in &config.scanner.root_paths {
        let _ = registry.discover_markers(root, 3);
    }

    let protections = registry.list_protections();

    match output_mode(cli) {
        OutputMode::Human => {
            if protections.is_empty() {
                println!("No protections configured.");
            } else {
                println!("Protected paths ({}):\n", protections.len());
                for entry in &protections {
                    let source = match &entry.source {
                        protection::ProtectionSource::MarkerFile => "marker",
                        protection::ProtectionSource::ConfigPattern(p) => p.as_str(),
                    };
                    println!("  {} ({})", entry.path.display(), source);
                }
            }
        }
        OutputMode::Json => {
            let entries: Vec<Value> = protections
                .iter()
                .map(|entry| {
                    let view = protection_entry_view(entry);
                    json!({
                        "path": view.path,
                        "source": view.source,
                        "metadata": view.metadata,
                    })
                })
                .collect();
            let payload = json!({
                "command": "protect",
                "action": "list",
                "protections": entries,
            });
            write_json_line(&payload)?;
        }
    }

    Ok(())
}

fn run_protect_create(cli: &Cli, path: &Path) -> Result<(), CliError> {
    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;
    let canonical = path
        .canonicalize()
        .map_err(|e| CliError::User(format!("cannot resolve path {}: {e}", path.display())))?;

    if !canonical.is_dir() {
        return Err(CliError::User(format!(
            "path is not a directory: {}",
            canonical.display(),
        )));
    }

    let metadata = default_protection_metadata();
    protection::create_marker(&canonical, Some(&metadata))
        .map_err(|e| CliError::Runtime(e.to_string()))?;
    let (sacred_config_path, sacred_added) = add_sacred_protected_path(&config, &canonical)?;

    match output_mode(cli) {
        OutputMode::Human => {
            println!(
                "Protected: {} (created {})",
                canonical.display(),
                canonical.join(protection::MARKER_FILENAME).display(),
            );
            if sacred_added {
                println!(
                    "  Added persistent protection: {}",
                    sacred_config_path.display()
                );
            } else {
                println!(
                    "  Persistent protection already present: {}",
                    sacred_config_path.display()
                );
            }
        }
        OutputMode::Json => {
            let payload = json!({
                "command": "protect",
                "action": "create",
                "path": canonical.to_string_lossy(),
                "marker": canonical.join(protection::MARKER_FILENAME).to_string_lossy(),
                "sacred_config": sacred_config_path.to_string_lossy(),
                "sacred_config_added": sacred_added,
            });
            write_json_line(&payload)?;
        }
    }

    Ok(())
}

fn run_unprotect(cli: &Cli, args: &UnprotectArgs) -> Result<(), CliError> {
    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;

    // Canonicalize to resolve symlinks and relative components.
    let canonical = args
        .path
        .canonicalize()
        .map_err(|e| CliError::User(format!("cannot resolve path {}: {e}", args.path.display())))?;

    let removed =
        protection::remove_marker(&canonical).map_err(|e| CliError::Runtime(e.to_string()))?;
    let (sacred_config_path, sacred_removed) = remove_sacred_protected_path(&config, &canonical)?;

    match output_mode(cli) {
        OutputMode::Human => {
            if removed {
                println!("Unprotected: {} (marker removed)", canonical.display());
            } else {
                println!(
                    "No protection marker found at {}",
                    canonical.join(protection::MARKER_FILENAME).display(),
                );
            }
            if sacred_removed {
                println!(
                    "  Removed persistent protection: {}",
                    sacred_config_path.display()
                );
            } else {
                println!(
                    "  No persistent protection found in {}",
                    sacred_config_path.display()
                );
            }
        }
        OutputMode::Json => {
            let payload = json!({
                "command": "unprotect",
                "path": canonical.to_string_lossy(),
                "removed": removed,
                "sacred_config": sacred_config_path.to_string_lossy(),
                "sacred_config_removed": sacred_removed,
            });
            write_json_line(&payload)?;
        }
    }

    Ok(())
}

#[cfg(unix)]
fn run_lease(cli: &Cli, args: &LeaseArgs) -> Result<(), CliError> {
    match &args.action {
        LeaseAction::Run(run) => run_lease_command(cli, run),
        LeaseAction::Renew(renew) => run_lease_renew(cli, renew),
        LeaseAction::Status(status) => run_lease_status(cli, status),
    }
}

#[cfg(not(unix))]
fn run_lease(_cli: &Cli, _args: &LeaseArgs) -> Result<(), CliError> {
    Err(CliError::User(
        "active target leases currently require Linux or macOS".to_string(),
    ))
}

#[cfg(unix)]
fn run_lease_command(cli: &Cli, args: &LeaseRunArgs) -> Result<(), CliError> {
    let config = Config::load(cli.config.as_deref())
        .map_err(|error| CliError::Runtime(error.to_string()))?;

    // Give the leased command and all descendants their own process group so
    // the watchdog can cancel the whole build without touching the caller's
    // shell or unrelated jobs.
    nix::unistd::setpgid(nix::unistd::Pid::from_raw(0), nix::unistd::Pid::from_raw(0)).map_err(
        |error| CliError::Runtime(format!("create active lease process group: {error}")),
    )?;

    let lease = ActiveLease::acquire(
        &config.scanner.root_paths,
        &args.target,
        Duration::from_secs(args.ttl_seconds),
        args.max_bytes,
    )
    .map_err(|error| CliError::User(error.to_string()))?;

    let current_exe = std::env::current_exe()
        .map_err(|error| CliError::Runtime(format!("resolve sbh executable: {error}")))?;
    let mut watchdog = ProcessCommand::new(&current_exe);
    watchdog
        .arg("__lease-watch")
        .arg("--target")
        .arg(&lease.metadata().target)
        .arg("--process-group-id")
        .arg(lease.metadata().process_group_id.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .process_group(0);
    watchdog
        .spawn()
        .map_err(|error| CliError::Runtime(format!("start active lease watchdog: {error}")))?;

    lease
        .retain_lock_across_exec()
        .map_err(|error| CliError::Runtime(error.to_string()))?;
    if !cli.quiet {
        eprintln!(
            "[SBH-ACTIVE-LEASE] active target={} max_bytes={} expires_at={} hard_expires_at={}",
            lease.metadata().target.display(),
            lease.metadata().max_bytes,
            lease.metadata().expires_at_unix_seconds,
            lease.metadata().hard_expires_at_unix_seconds,
        );
    }

    let (program, command_args) = args
        .command
        .split_first()
        .ok_or_else(|| CliError::User("lease run requires a command after --".to_string()))?;
    let mut command = ProcessCommand::new(program);
    command
        .args(command_args)
        .env("CARGO_TARGET_DIR", &lease.metadata().target)
        .env(ACTIVE_LEASE_TARGET_ENV, &lease.metadata().target)
        .env(ACTIVE_LEASE_TOKEN_ENV, lease.renewal_token());
    let error = command.exec();
    Err(CliError::Runtime(format!(
        "exec leased command {program:?}: {error}"
    )))
}

#[cfg(unix)]
fn run_lease_renew(cli: &Cli, args: &LeaseRenewArgs) -> Result<(), CliError> {
    let target = args
        .target
        .clone()
        .or_else(|| std::env::var_os(ACTIVE_LEASE_TARGET_ENV).map(PathBuf::from))
        .ok_or_else(|| {
            CliError::User(format!(
                "lease renew needs --target or inherited {ACTIVE_LEASE_TARGET_ENV}"
            ))
        })?;
    let token = std::env::var(ACTIVE_LEASE_TOKEN_ENV).map_err(|_| {
        CliError::User(format!(
            "lease renew must run beneath lease run with inherited {ACTIVE_LEASE_TOKEN_ENV}"
        ))
    })?;
    let expires_at = active_lease::renew(&target, &token, Duration::from_secs(args.extend_seconds))
        .map_err(|error| CliError::User(error.to_string()))?;

    match output_mode(cli) {
        OutputMode::Human => println!(
            "Renewed active target lease: {} (expires_at_unix_seconds={expires_at})",
            target.display()
        ),
        OutputMode::Json => write_json_line(&json!({
            "command": "lease",
            "action": "renew",
            "target": target.to_string_lossy(),
            "expires_at_unix_seconds": expires_at,
        }))?,
    }
    Ok(())
}

#[cfg(unix)]
fn run_lease_status(cli: &Cli, args: &LeaseStatusArgs) -> Result<(), CliError> {
    let target = args
        .target
        .clone()
        .or_else(|| std::env::var_os(ACTIVE_LEASE_TARGET_ENV).map(PathBuf::from))
        .ok_or_else(|| {
            CliError::User(format!(
                "lease status needs --target or inherited {ACTIVE_LEASE_TARGET_ENV}"
            ))
        })?;
    let inspection = active_lease::inspect_path(&target);
    match output_mode(cli) {
        OutputMode::Human => {
            if let Some(inspection) = inspection {
                println!(
                    "Active target lease: {} ({:?}; {})",
                    inspection.leased_target.display(),
                    inspection.state,
                    inspection.detail
                );
            } else {
                println!("No active target lease: {}", target.display());
            }
        }
        OutputMode::Json => {
            let payload = inspection.map_or_else(
                || {
                    json!({
                        "command": "lease",
                        "action": "status",
                        "target": target.to_string_lossy(),
                        "active": false,
                    })
                },
                |inspection| {
                    json!({
                        "command": "lease",
                        "action": "status",
                        "target": target.to_string_lossy(),
                        "active": true,
                        "leased_target": inspection.leased_target.to_string_lossy(),
                        "state": inspection.state,
                        "detail": inspection.detail,
                        "metadata": inspection.metadata,
                    })
                },
            );
            write_json_line(&payload)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn run_lease_watch(args: &LeaseWatchArgs) -> Result<(), CliError> {
    active_lease::watch(&args.target, args.process_group_id, LeasePolicy::default())
        .map_err(|error| CliError::Runtime(error.to_string()))
}

#[cfg(not(unix))]
fn run_lease_watch(_args: &LeaseWatchArgs) -> Result<(), CliError> {
    Err(CliError::User(
        "active target lease watchdog requires Linux or macOS".to_string(),
    ))
}

#[derive(Debug, Clone)]
struct ScoredScanEntry {
    score: CandidacyScore,
    trace: ScanTrace,
}

#[derive(Debug, Clone)]
struct ScanTrace {
    pattern_name: String,
    category: String,
    mtime_check: String,
    fd_check: String,
    exec_check: String,
    mmap_check: String,
    sacred_overlap_check: String,
    final_confidence: f64,
    final_action: String,
    veto_reason: Option<String>,
}

fn build_scan_trace(
    input: &CandidateInput,
    score: &CandidacyScore,
    min_file_age_seconds: u64,
    active_reference_checked: bool,
    sacred_overlaps: &[protection::SacredOverlap],
) -> ScanTrace {
    let open_fd_count = input
        .active_references
        .processes
        .iter()
        .map(|process| process.open_file_descriptors)
        .sum::<usize>();
    let running_exec_count = input
        .active_references
        .processes
        .iter()
        .filter(|process| process.running_executable)
        .count();
    let mmap_region_count = input
        .active_references
        .processes
        .iter()
        .map(|process| process.mmap_regions)
        .sum::<usize>();
    let active_reference_incomplete = input.active_references.incomplete_reason.as_deref();

    ScanTrace {
        pattern_name: input.classification.pattern_name.to_string(),
        category: format!("{:?}", input.classification.category),
        mtime_check: if input.age.as_secs() < min_file_age_seconds {
            format!(
                "age {}s below minimum {}s",
                input.age.as_secs(),
                min_file_age_seconds
            )
        } else {
            format!(
                "age {}s meets minimum {}s",
                input.age.as_secs(),
                min_file_age_seconds
            )
        },
        fd_check: if !active_reference_checked {
            "skipped below active-reference size threshold".to_string()
        } else if open_fd_count > 0 {
            format!("{open_fd_count} open file descriptor(s)")
        } else if input.is_open {
            "open file detected by fallback scanner".to_string()
        } else if let Some(reason) = active_reference_incomplete {
            reason.to_string()
        } else {
            "clear".to_string()
        },
        exec_check: if !active_reference_checked {
            "skipped below active-reference size threshold".to_string()
        } else if running_exec_count > 0 {
            format!("{running_exec_count} running executable(s)")
        } else {
            "clear".to_string()
        },
        mmap_check: if !active_reference_checked {
            "skipped below active-reference size threshold".to_string()
        } else if mmap_region_count > 0 {
            format!("{mmap_region_count} mmap region(s)")
        } else {
            "clear".to_string()
        },
        sacred_overlap_check: sacred_overlap_check_trace(input, sacred_overlaps),
        final_confidence: score.decision.posterior_abandoned,
        final_action: format!("{:?}", score.decision.action),
        veto_reason: score.veto_reason.as_ref().map(ToString::to_string),
    }
}

fn sacred_overlap_check_trace(
    input: &CandidateInput,
    sacred_overlaps: &[protection::SacredOverlap],
) -> String {
    sacred_overlaps.first().map_or_else(
        || {
            if input.excluded {
                "matched protection or exclusion".to_string()
            } else if input.signals.has_git {
                "contains .git".to_string()
            } else {
                "clear".to_string()
            }
        },
        |overlap| {
            let extra = sacred_overlaps.len().saturating_sub(1);
            if extra == 0 {
                overlap.summary()
            } else {
                format!("{}; and {extra} more sacred overlap(s)", overlap.summary())
            }
        },
    )
}

fn score_candidate_with_deferred_sacred_check<F>(
    engine: &ScoringEngine,
    input: &CandidateInput,
    urgency: f64,
    sacred_paths: &[storage_ballast_helper::platform::types::SacredPath],
    should_check: F,
) -> (CandidacyScore, Vec<protection::SacredOverlap>)
where
    F: FnOnce(&CandidacyScore) -> bool,
{
    let base_score = engine.score_candidate(input, urgency);
    if !should_check(&base_score) {
        return (base_score, Vec::new());
    }

    match protection::find_sacred_overlaps(&input.path, sacred_paths) {
        Ok(overlaps) => {
            let score = engine.score_candidate_with_sacred_overlaps(input, urgency, &overlaps);
            (score, overlaps)
        }
        Err(err) => (
            engine.hard_veto(input, format!("sacred overlap check failed: {err}")),
            Vec::new(),
        ),
    }
}

fn scan_trace_json(trace: &ScanTrace) -> Value {
    json!({
        "pattern_name": &trace.pattern_name,
        "category": &trace.category,
        "mtime_check": &trace.mtime_check,
        "fd_check": &trace.fd_check,
        "exec_check": &trace.exec_check,
        "mmap_check": &trace.mmap_check,
        "sacred_overlap_check": &trace.sacred_overlap_check,
        "final_confidence": trace.final_confidence,
        "final_action": &trace.final_action,
        "veto_reason": trace.veto_reason.as_deref(),
    })
}

fn print_scan_trace(entry: &ScoredScanEntry) {
    println!("    {}", entry.score.path.display());
    println!(
        "      pattern: {} ({})",
        entry.trace.pattern_name, entry.trace.category
    );
    println!("      mtime: {}", entry.trace.mtime_check);
    println!("      fd: {}", entry.trace.fd_check);
    println!("      exec: {}", entry.trace.exec_check);
    println!("      mmap: {}", entry.trace.mmap_check);
    println!("      sacred: {}", entry.trace.sacred_overlap_check);
    println!(
        "      final: action={}, confidence={:.3}, score={:.2}",
        entry.trace.final_action, entry.trace.final_confidence, entry.score.total_score
    );
    if let Some(reason) = &entry.trace.veto_reason {
        println!("      veto: {reason}");
    }
}

fn truncate_str(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        return value.to_string();
    }

    let keep = max_len.saturating_sub(3);
    let mut truncated = value.chars().take(keep).collect::<String>();
    truncated.push_str("...");
    truncated
}

fn is_report_only_scan_entry(entry: &ScoredScanEntry) -> bool {
    entry
        .score
        .veto_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("cleanup rule is report-only"))
}

fn scan_entry_json(entry: &ScoredScanEntry, explain: bool) -> Value {
    let candidate = &entry.score;
    let mut item = json!({
        "path": candidate.path.to_string_lossy(),
        "size_bytes": candidate.size_bytes,
        "age_seconds": candidate.age.as_secs(),
        "total_score": candidate.total_score,
        "category": format!("{:?}", candidate.classification.category),
        "pattern_name": candidate.classification.pattern_name.as_ref(),
        "confidence": candidate.classification.combined_confidence,
        "decision": format!("{:?}", candidate.decision.action),
        "decision_id": storage_ballast_helper::scanner::decision_record::stable_decision_id(
            &candidate.path,
            candidate.identity,
            candidate.size_bytes,
        ),
        "certainty": candidate.decision.certainty.label(),
        "posterior_floor_applied": candidate.decision.posterior_floor_applied,
        "veto_reason": candidate.veto_reason.as_deref(),
        "factors": {
            "location": candidate.factors.location,
            "name": candidate.factors.name,
            "age": candidate.factors.age,
            "size": candidate.factors.size,
            "structure": candidate.factors.structure,
            "pressure_multiplier": candidate.factors.pressure_multiplier,
        },
    });
    if explain && let Some(obj) = item.as_object_mut() {
        obj.insert("explanation".to_string(), scan_trace_json(&entry.trace));
    }
    item
}

fn current_process_cpu_micros() -> Option<u64> {
    let stats = detect_platform().ok()?.self_stats().ok()?;
    Some(
        stats
            .cpu_user_micros
            .saturating_add(stats.cpu_system_micros),
    )
}

#[allow(clippy::too_many_lines)]
/// `sbh scan --catalog [MOUNT]`: the same derivation the daemon runs for a
/// pressured device with no configured root, so an operator can see which
/// known-safe caches would be considered, how large they are and how long
/// they have been idle. Nothing is scored or deleted.
fn render_catalog_preview(cli: &Cli, config: &Config, mount: &Path) -> Result<(), CliError> {
    use storage_ballast_helper::platform::cleanup_catalog;
    use storage_ballast_helper::scanner::walker::tree_newest_mtime;

    struct Row {
        path: PathBuf,
        rule: &'static str,
        confidence: &'static str,
        min_age_hours: u64,
        allocated_bytes: u64,
        size_complete: bool,
        idle_secs: u64,
        eligible: bool,
    }

    let platform = detect_platform().map_err(|e| CliError::Runtime(e.to_string()))?;
    let mount = mount
        .canonicalize()
        .map_err(|e| CliError::User(format!("invalid mount {}: {e}", mount.display())))?;
    let Some(device) = cleanup_catalog::device_of(&mount) else {
        return Err(CliError::Runtime(format!(
            "cannot stat {} to determine its device",
            mount.display()
        )));
    };
    let homes = cleanup_catalog::user_homes(&platform.user_home());
    let roots =
        cleanup_catalog::catalog_roots_for_mount(cleanup_catalog::CATALOG_ROOTS, &homes, device);
    let now = std::time::SystemTime::now();

    let rows: Vec<Row> = roots
        .iter()
        .map(|root| {
            let probe = tree_newest_mtime(&root.path, 200_000, 6);
            let newest = probe
                .newest_mtime
                .or_else(|| {
                    std::fs::metadata(&root.path)
                        .and_then(|m| m.modified())
                        .ok()
                })
                .unwrap_or(std::time::UNIX_EPOCH);
            let idle = now.duration_since(newest).unwrap_or_default();
            Row {
                path: root.path.clone(),
                rule: root.rule,
                confidence: root.confidence.label(),
                min_age_hours: root.min_age.as_secs() / 3600,
                allocated_bytes: probe.allocated_bytes,
                size_complete: probe.complete,
                idle_secs: idle.as_secs(),
                eligible: idle >= root.min_age,
            }
        })
        .collect();

    match output_mode(cli) {
        OutputMode::Human => {
            println!(
                "Catalog roots on {} (device {device}), {} user home(s), catalog scans {}:",
                mount.display(),
                homes.len(),
                if config.scanner.catalog_roots_on_pressured_device {
                    "enabled"
                } else {
                    "disabled by scanner.catalog_roots_on_pressured_device"
                }
            );
            if rows.is_empty() {
                println!("  (none: no known-safe cache location exists on this device)");
            } else {
                let (h_path, h_rule, h_conf, h_size, h_idle) =
                    ("Path", "Rule", "Conf", "Size", "Idle");
                println!(
                    "  {h_path:<44}  {h_rule:<32}  {h_conf:<8}  {h_size:>10}  {h_idle:>9}  Eligible"
                );
                for row in &rows {
                    println!(
                        "  {:<44}  {:<32}  {:<8}  {:>10}{}  {:>8}h  {}",
                        row.path.display(),
                        row.rule,
                        row.confidence,
                        format_bytes(row.allocated_bytes),
                        if row.size_complete { " " } else { "+" },
                        row.idle_secs / 3600,
                        if row.eligible {
                            "yes"
                        } else {
                            "no (min idle not reached)"
                        },
                    );
                }
                println!(
                    "  A '+' after a size means the probe hit its budget and the tree is larger. \
                     Eligible roots still pass scoring and every pre-flight veto before deletion."
                );
            }
        }
        OutputMode::Json => {
            let payload = json!({
                "command": "scan",
                "mode": "catalog",
                "mount": mount.to_string_lossy(),
                "device": device,
                "enabled": config.scanner.catalog_roots_on_pressured_device,
                "rescan_interval_secs": config.scanner.catalog_rescan_interval_secs,
                "homes": homes.iter().map(|h| h.to_string_lossy().into_owned()).collect::<Vec<_>>(),
                "roots": rows.iter().map(|row| json!({
                    "path": row.path.to_string_lossy(),
                    "rule": row.rule,
                    "confidence": row.confidence,
                    "min_age_hours": row.min_age_hours,
                    "allocated_bytes": row.allocated_bytes,
                    "size_complete": row.size_complete,
                    "idle_secs": row.idle_secs,
                    "eligible": row.eligible,
                })).collect::<Vec<_>>(),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload)
                    .map_err(|e| CliError::Runtime(e.to_string()))?
            );
        }
    }
    Ok(())
}

// The scan pipeline reads top to bottom: walk, score, rank, render. Splitting
// it would scatter the state each stage hands to the next.
#[allow(clippy::too_many_lines)]
fn run_scan(cli: &Cli, args: &ScanArgs) -> Result<(), CliError> {
    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;
    if let Some(mount) = &args.catalog {
        return render_catalog_preview(cli, &config, mount);
    }
    let cpu_start_micros = current_process_cpu_micros();
    let start = std::time::Instant::now();

    // Determine scan roots: CLI paths or configured watched paths.
    // Canonicalize to ensure absolute paths for system protection checks.
    let raw_roots = if args.paths.is_empty() {
        config.scanner.root_paths.clone()
    } else {
        args.paths.clone()
    };

    let root_paths: Vec<PathBuf> = raw_roots
        .into_iter()
        .filter_map(|p| match p.canonicalize() {
            Ok(abs) => Some(abs),
            Err(e) => {
                if output_mode(cli) == OutputMode::Human {
                    eprintln!("Warning: skipping invalid path {}: {}", p.display(), e);
                }
                None
            }
        })
        .collect();

    if root_paths.is_empty() {
        return Err(CliError::User("no valid scan paths found".to_string()));
    }
    let scan_roots = root_paths.clone();
    let selected_scanner_engine = SelectedScannerEngine::for_mode(config.scanner.engine);
    let scanner_engine_mode = selected_scanner_engine.mode();
    let scanner_dispatch = selected_scanner_engine.dispatch();
    let scanner_opaque_pruning = selected_scanner_engine.opaque_pruning();

    // Build protection registry from config patterns.
    let protection_patterns = if config.scanner.protected_paths.is_empty() {
        None
    } else {
        Some(config.scanner.protected_paths.as_slice())
    };
    let protection = ProtectionRegistry::new(protection_patterns)
        .map_err(|e| CliError::Runtime(e.to_string()))?;

    // Build walker.
    let walker_config = WalkerConfig {
        root_paths: root_paths.clone(),
        max_depth: config.scanner.max_depth,
        follow_symlinks: config.scanner.follow_symlinks,
        cross_devices: config.scanner.cross_devices,
        parallelism: config.scanner.parallelism,
        excluded_paths: config
            .scanner
            .excluded_paths
            .iter()
            .cloned()
            .collect::<HashSet<_>>(),
        opaque_pruning: scanner_opaque_pruning,
    };
    let walker = DirectoryWalker::new(walker_config, protection);

    // Walk the filesystem.
    let entries = walker
        .walk()
        .map_err(|e| CliError::Runtime(e.to_string()))?;
    let dir_count = entries.len();

    // Classify and score each entry with active-reference evidence attached.
    let registry = ArtifactPatternRegistry::default();
    let engine = ScoringEngine::from_config(&config.scoring, config.scanner.min_file_age_minutes);
    let sacred_paths = active_sacred_paths(&config)?;
    let now = SystemTime::now();
    let active_reference_scan = active_reference_scan_config(&config);
    let mut open_paths = None;
    let mut active_reference_index = None;
    let min_file_age_seconds = config.scanner.min_file_age_minutes.saturating_mul(60);
    let opaque_pruned_dirs = entries
        .iter()
        .filter(|entry| {
            entry.opaque_tree.as_ref().is_some_and(|opaque_tree| {
                opaque_tree.disposition == OpaqueTreeDisposition::CandidateOpaque
            })
        })
        .count();

    let scored_entries = entries
        .iter()
        .filter_map(|entry| {
            let classification = if let Some(opaque_tree) = &entry.opaque_tree {
                match opaque_tree.disposition {
                    OpaqueTreeDisposition::CandidateOpaque => opaque_tree.classification.clone(),
                    OpaqueTreeDisposition::SignalOnly | OpaqueTreeDisposition::ProtectedOpaque => {
                        return None;
                    }
                }
            } else {
                registry.classify(&entry.path, entry.structural_signals)
            };
            let age = now
                .duration_since(
                    entry.effective_age_timestamp(classification.category.is_regenerable_tree()),
                )
                .unwrap_or_default();
            let mut candidate = CandidateInput {
                path: entry.path.clone(),
                size_bytes: entry.metadata.content_size_bytes,
                age,
                classification,
                signals: entry.structural_signals,
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            };

            let cheap_score = engine.score_candidate(&candidate, 0.0);
            let should_collect_active_references =
                args.explain && (!cheap_score.vetoed && cheap_score.total_score >= args.min_score);
            let active_reference_checked = if should_collect_active_references {
                candidate.is_open = open_status_for_candidate(
                    &mut open_paths,
                    &scan_roots,
                    active_reference_scan,
                    &entry.path,
                    entry.metadata.content_size_bytes,
                );
                let (active_references, checked) = active_references_for_candidate(
                    &mut active_reference_index,
                    &scan_roots,
                    active_reference_scan,
                    &entry.path,
                    Some(entry.metadata.identity()),
                    entry.metadata.content_size_bytes,
                );
                candidate.active_references = active_references;
                checked
            } else {
                false
            };

            let (mut score, sacred_overlaps) = score_candidate_with_deferred_sacred_check(
                &engine,
                &candidate,
                0.0,
                &sacred_paths,
                |_| args.explain,
            );
            score.identity = Some(entry.metadata.identity());
            let trace = build_scan_trace(
                &candidate,
                &score,
                min_file_age_seconds,
                active_reference_checked,
                &sacred_overlaps,
            );
            Some(ScoredScanEntry { score, trace })
        })
        .collect::<Vec<_>>();

    let mut candidates = scored_entries
        .iter()
        .filter(|entry| !entry.score.vetoed && entry.score.total_score >= args.min_score)
        .collect::<Vec<_>>();
    candidates.sort_by(|a, b| {
        b.score
            .total_score
            .partial_cmp(&a.score.total_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    if candidates.len() > args.top {
        candidates.truncate(args.top);
    }

    let mut report_only = scored_entries
        .iter()
        .filter(|entry| is_report_only_scan_entry(entry))
        .collect::<Vec<_>>();
    report_only.sort_by_key(|entry| std::cmp::Reverse(entry.score.size_bytes));
    if report_only.len() > args.top {
        report_only.truncate(args.top);
    }

    let mut rejected = if args.explain {
        scored_entries
            .iter()
            .filter(|entry| entry.score.vetoed && !is_report_only_scan_entry(entry))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    rejected.sort_by(|a, b| a.score.path.cmp(&b.score.path));
    if rejected.len() > args.top {
        rejected.truncate(args.top);
    }

    let elapsed = start.elapsed();
    let process_cpu_micros = cpu_start_micros
        .zip(current_process_cpu_micros())
        .map(|(start, end)| end.saturating_sub(start));
    let total_reclaimable: u64 = candidates.iter().map(|entry| entry.score.size_bytes).sum();
    let total_reported: u64 = report_only.iter().map(|entry| entry.score.size_bytes).sum();

    match output_mode(cli) {
        OutputMode::Human => {
            println!(
                "Build Artifact Scan Results\n  Engine: {} ({}, opaque_pruning={}, opaque_pruned_dirs={})\n  Scanned: {} entries in {:.1}s\n  Candidates found: {} (above threshold {:.2})\n",
                scanner_engine_mode,
                scanner_dispatch,
                scanner_opaque_pruning,
                opaque_pruned_dirs,
                dir_count,
                elapsed.as_secs_f64(),
                candidates.len(),
                args.min_score,
            );

            if candidates.is_empty() {
                println!("  No candidates found above threshold.");
            } else {
                println!(
                    "  {:>3}  {:<50}  {:>10}  {:>10}  {:>6}  {:<12}",
                    "#", "Path", "Size", "Age", "Score", "Type"
                );
                println!("  {}", "-".repeat(100));

                for (i, entry) in candidates.iter().enumerate() {
                    let candidate = &entry.score;
                    let age = candidate.age;
                    let age_str = format_duration(age);
                    let size_str = format_bytes(candidate.size_bytes);
                    let type_str = format!("{:?}", candidate.classification.category);
                    let path_str = truncate_path(&candidate.path, 50);

                    println!(
                        "  {:>3}  {:<50}  {:>10}  {:>10}  {:>6.2}  {:<12}  id {}",
                        i + 1,
                        path_str,
                        size_str,
                        age_str,
                        candidate.total_score,
                        type_str,
                        candidate_decision_id(candidate),
                    );
                }
                println!();
                println!("  Total reclaimable: {}", format_bytes(total_reclaimable));
                println!(
                    "  Use 'sbh clean' to delete these candidates; 'sbh explain --id <id>' explains one, 'sbh explain --why-not <path>' explains an absence."
                );
            }

            if !report_only.is_empty() {
                println!("\n  Report-only locations (not auto-deleted):");
                println!(
                    "  {:>3}  {:<50}  {:>10}  {:<24}",
                    "#", "Path", "Size", "Reason"
                );
                println!("  {}", "-".repeat(92));

                for (i, entry) in report_only.iter().enumerate() {
                    let candidate = &entry.score;
                    let size_str = format_bytes(candidate.size_bytes);
                    let path_str = truncate_path(&candidate.path, 50);
                    let reason = candidate.veto_reason.as_deref().unwrap_or("report-only");

                    println!(
                        "  {:>3}  {:<50}  {:>10}  {:<24}",
                        i + 1,
                        path_str,
                        size_str,
                        truncate_str(reason, 24),
                    );
                }
                println!("  Report-only total: {}", format_bytes(total_reported));
            }

            if args.explain {
                if !candidates.is_empty() {
                    println!("\n  Confidence trace:");
                    for entry in &candidates {
                        print_scan_trace(entry);
                    }
                }
                if !rejected.is_empty() {
                    println!("\n  Safety rejections:");
                    for entry in &rejected {
                        print_scan_trace(entry);
                    }
                }
            }

            // Show protected paths if requested.
            if args.show_protected {
                let protections = {
                    let prot = walker.protection().read();
                    prot.list_protections()
                };
                if !protections.is_empty() {
                    println!("\n  Protected paths ({}):", protections.len());
                    for entry in &protections {
                        let source = match &entry.source {
                            storage_ballast_helper::scanner::protection::ProtectionSource::MarkerFile => "marker",
                            storage_ballast_helper::scanner::protection::ProtectionSource::ConfigPattern(p) => p.as_str(),
                        };
                        println!("    [PROTECTED] {} ({})", entry.path.display(), source);
                    }
                }
            }
        }
        OutputMode::Json => {
            let entries_json: Vec<Value> = candidates
                .iter()
                .map(|entry| scan_entry_json(entry, args.explain))
                .collect();
            let report_only_json: Vec<Value> = report_only
                .iter()
                .map(|entry| scan_entry_json(entry, args.explain))
                .collect();

            // W1 planner: the batch the daemon would execute from these
            // candidates at the mount's current level.
            let (scan_level, _) = clean_plan_target(&config, &root_paths, None);
            let (_, scan_plan) = plan_batch(
                candidates.iter().map(|entry| entry.score.clone()).collect(),
                &cli_plan_request(&config, scan_level, None, config.scanner.max_delete_batch),
            );
            let mut payload = json!({
                "command": "scan",
                "plan": scan_plan,
                "scanner_engine": scanner_engine_mode.to_string(),
                "scanner_dispatch": scanner_dispatch.to_string(),
                "opaque_pruning": scanner_opaque_pruning,
                "opaque_pruned_dirs": opaque_pruned_dirs,
                "scanned_directories": dir_count,
                "scanned_entries": dir_count,
                "elapsed_seconds": elapsed.as_secs_f64(),
                "process_cpu_micros": process_cpu_micros,
                "min_score": args.min_score,
                "candidates_count": entries_json.len(),
                "total_reclaimable_bytes": total_reclaimable,
                "report_only_count": report_only_json.len(),
                "report_only_bytes": total_reported,
                "candidates": entries_json,
                "report_only": report_only_json,
            });

            if args.explain {
                let rejected_json = rejected
                    .iter()
                    .map(|entry| {
                        json!({
                            "path": entry.score.path.to_string_lossy(),
                            "veto_reason": entry.score.veto_reason.as_deref(),
                            "explanation": scan_trace_json(&entry.trace),
                        })
                    })
                    .collect::<Vec<_>>();
                if let Some(obj) = payload.as_object_mut() {
                    obj.insert("rejected".to_string(), json!(rejected_json));
                }
            }

            if args.show_protected {
                let protections = {
                    let prot = walker.protection().read();
                    prot.list_protections()
                };
                let protected_json: Vec<Value> = protections
                    .iter()
                    .map(|e| {
                        let source = match &e.source {
                            storage_ballast_helper::scanner::protection::ProtectionSource::MarkerFile => "marker",
                            storage_ballast_helper::scanner::protection::ProtectionSource::ConfigPattern(p) => p.as_str(),
                        };
                        json!({
                            "path": e.path.to_string_lossy(),
                            "source": source,
                        })
                    })
                    .collect();
                if let Some(obj) = payload.as_object_mut() {
                    obj.insert("protected_paths".to_string(), json!(protected_json));
                }
            }

            write_json_line(&payload)?;
        }
    }

    Ok(())
}

/// Record the CLI's cleanup decisions in the evidence ledger (SQLite
/// `decision_log`) so `sbh explain` can answer for `sbh clean` runs, not only
/// for the daemon. Best effort: a ledger that cannot be opened (typically a
/// root-owned daemon database) is mentioned in verbose mode and skipped.
/// Returns the number of records written.
fn record_cli_decisions(
    cli: &Cli,
    config: &Config,
    candidates: &[CandidacyScore],
    dry_run: bool,
) -> usize {
    use storage_ballast_helper::scanner::decision_record::{DecisionRecordBuilder, PolicyMode};

    if candidates.is_empty() {
        return 0;
    }
    let db = match SqliteLogger::open(&config.paths.sqlite_db) {
        Ok(db) => db,
        Err(e) => {
            if cli.verbose {
                eprintln!(
                    "[SBH-CLEAN] decision ledger {} not writable, decisions not recorded: {e}",
                    config.paths.sqlite_db.display()
                );
            }
            return 0;
        }
    };
    let mode = if dry_run {
        PolicyMode::DryRun
    } else {
        PolicyMode::Live
    };
    let mut builder = DecisionRecordBuilder::new();
    candidates
        .iter()
        .map(|candidate| builder.build(candidate, mode, None, None, None))
        .filter(|record| db.log_decision(record).is_ok())
        .count()
}

#[allow(clippy::too_many_lines)]
/// Record a manual clean's batch plan as the same `planner ... json=...`
/// activity row the daemon writes, so `sbh explain --id` can quote it.
fn record_cli_plan(cli: &Cli, config: &Config, batch_plan: &BatchPlan) {
    use storage_ballast_helper::logger::sqlite::ActivityRow;

    if batch_plan.chosen.is_empty() && batch_plan.skipped_for_budget.is_empty() {
        return;
    }
    let db = match SqliteLogger::open(&config.paths.sqlite_db) {
        Ok(db) => db,
        Err(e) => {
            if cli.verbose {
                eprintln!(
                    "[SBH-CLEAN] decision ledger {} not writable, plan not recorded: {e}",
                    config.paths.sqlite_db.display()
                );
            }
            return;
        }
    };
    let row = ActivityRow {
        timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        event_type: "info".to_string(),
        severity: "info".to_string(),
        path: None,
        size_bytes: None,
        score: None,
        score_factors: None,
        pressure_level: None,
        free_pct: None,
        duration_ms: None,
        success: 1,
        error_code: None,
        error_message: None,
        details: Some(format!(
            "planner {} json={}",
            batch_plan.summary_line(),
            serde_json::to_string(batch_plan).unwrap_or_default()
        )),
    };
    if let Err(e) = db.log_activity(&row)
        && cli.verbose
    {
        eprintln!("[SBH-CLEAN] plan not recorded: {e}");
    }
}

/// `sbh undo`: put quarantined entries back (Layer 7).
#[allow(clippy::too_many_lines)]
fn run_undo(cli: &Cli, args: &UndoArgs) -> Result<(), CliError> {
    use storage_ballast_helper::scanner::quarantine::QuarantineRecord;

    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;
    let roots: Vec<PathBuf> = if args.roots.is_empty() {
        config.scanner.root_paths.clone()
    } else {
        args.roots.clone()
    };
    // Every held record across the roots' stores, oldest first.
    let mut held: Vec<(QuarantineStore, QuarantineRecord)> = Vec::new();
    for root in &roots {
        let store = QuarantineStore::under(root);
        let records = store
            .records()
            .map_err(|e| CliError::Runtime(e.to_string()))?;
        held.extend(records.into_iter().map(|record| (store.clone(), record)));
    }
    held.sort_by(|a, b| {
        a.1.quarantined_at
            .cmp(&b.1.quarantined_at)
            .then_with(|| a.1.decision_id.cmp(&b.1.decision_id))
    });
    let held_bytes = held
        .iter()
        .map(|(_, record)| record.size_bytes)
        .fold(0u64, u64::saturating_add);
    let now_unix = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    if args.list {
        match output_mode(cli) {
            OutputMode::Json => write_json_line(&json!({
                "command": "undo",
                "roots": roots,
                "held_bytes": held_bytes,
                "held": held.iter().map(|(store, record)| json!({
                    "decision_id": record.decision_id,
                    "original_path": record.original_path,
                    "quarantine_path": record.quarantine_path,
                    "size_bytes": record.size_bytes,
                    "quarantined_at": record.quarantined_at,
                    "expires_at": record.expires_at,
                    "store": store.root(),
                })).collect::<Vec<_>>(),
            }))?,
            OutputMode::Human => {
                if held.is_empty() {
                    println!(
                        "Quarantine is empty ({} root{} checked).",
                        roots.len(),
                        if roots.len() == 1 { "" } else { "s" }
                    );
                } else {
                    println!(
                        "Quarantined entries ({} held; restore with `sbh undo <decision-id>`):",
                        format_bytes(held_bytes)
                    );
                    for (_, record) in &held {
                        let left = record.expires_at.saturating_sub(now_unix);
                        println!(
                            "  {}  {:>10}  {}  (expires in {})",
                            record.decision_id,
                            format_bytes(record.size_bytes),
                            record.original_path.display(),
                            format_duration(Duration::from_secs(left))
                        );
                    }
                }
            }
        }
        return Ok(());
    }

    let selected: Vec<&(QuarantineStore, QuarantineRecord)> = if let Some(id) = &args.id {
        let id = id.trim().to_ascii_lowercase();
        held.iter().filter(|(_, r)| r.decision_id == id).collect()
    } else if let Some(path) = &args.path {
        let path = if path.is_absolute() {
            path.clone()
        } else {
            std::env::current_dir().map_or_else(|_| path.clone(), |cwd| cwd.join(path))
        };
        held.iter()
            .filter(|(_, r)| r.original_path == path)
            .collect()
    } else if let Some(window) = &args.all_since {
        let since = parse_window_duration(window)?;
        let cutoff = now_unix.saturating_sub(since.as_secs());
        held.iter()
            .filter(|(_, r)| r.quarantined_at >= cutoff)
            .collect()
    } else {
        return Err(CliError::User(
            "specify a decision id, --path, --all-since, or --list".to_string(),
        ));
    };
    if selected.is_empty() {
        return Err(CliError::User(format!(
            "no quarantined entry matches ({} held under {} root{}; see `sbh undo --list`)",
            held.len(),
            roots.len(),
            if roots.len() == 1 { "" } else { "s" }
        )));
    }

    let ledger = SqliteLogger::open(&config.paths.sqlite_db).ok();
    let mut restored = Vec::new();
    let mut failed = Vec::new();
    for (store, record) in selected {
        match store.restore(&record.decision_id, args.force_suffix) {
            Ok(outcome) => {
                eprintln!(
                    "[SBH-UNDO] restored {} -> {} (decision {}, {})",
                    record.original_path.display(),
                    outcome.restored_to.display(),
                    outcome.decision_id,
                    format_bytes(outcome.size_bytes)
                );
                if let Some(ledger) = &ledger
                    && let Err(e) = ledger.mark_decision_restored(&outcome.decision_id)
                {
                    eprintln!(
                        "[SBH-UNDO] ledger not updated for {}: {e}",
                        outcome.decision_id
                    );
                }
                restored.push(outcome);
            }
            Err(e) => {
                eprintln!("[SBH-UNDO] {} not restored: {e}", record.decision_id);
                failed.push((record.decision_id.clone(), e.to_string()));
            }
        }
    }
    let restored_bytes = restored
        .iter()
        .map(|o| o.size_bytes)
        .fold(0u64, u64::saturating_add);
    match output_mode(cli) {
        OutputMode::Json => write_json_line(&json!({
            "command": "undo",
            "restored": restored.iter().map(|o| json!({
                "decision_id": o.decision_id,
                "restored_to": o.restored_to,
                "size_bytes": o.size_bytes,
            })).collect::<Vec<_>>(),
            "restored_bytes": restored_bytes,
            "failed": failed.iter().map(|(id, error)| json!({
                "decision_id": id,
                "error": error,
            })).collect::<Vec<_>>(),
        }))?,
        OutputMode::Human => {
            println!(
                "Restored {} entr{} ({}).",
                restored.len(),
                if restored.len() == 1 { "y" } else { "ies" },
                format_bytes(restored_bytes)
            );
            for (id, error) in &failed {
                println!("  {id}: {error}");
            }
        }
    }
    if failed.is_empty() {
        Ok(())
    } else if restored.is_empty() {
        Err(CliError::Runtime(format!(
            "{} entr{} not restored",
            failed.len(),
            if failed.len() == 1 {
                "y was"
            } else {
                "ies were"
            }
        )))
    } else {
        Err(CliError::Partial(format!(
            "{} of {} entries not restored",
            failed.len(),
            failed.len() + restored.len()
        )))
    }
}

#[allow(clippy::too_many_lines)]
fn run_clean(cli: &Cli, args: &CleanArgs) -> Result<(), CliError> {
    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;

    if args.local_snapshot_mount.is_some() && !args.thin_local_snapshots {
        return Err(CliError::User(
            "--local-snapshot-mount requires --thin-local-snapshots".to_string(),
        ));
    }

    if args.thin_local_snapshots {
        return run_local_snapshot_thin(cli, args);
    }

    let start = std::time::Instant::now();

    // Determine scan roots: CLI paths or configured watched paths.
    // Canonicalize to ensure absolute paths for system protection checks.
    let raw_roots = if args.paths.is_empty() {
        config.scanner.root_paths.clone()
    } else {
        args.paths.clone()
    };

    let root_paths: Vec<PathBuf> = raw_roots
        .into_iter()
        .filter_map(|p| match p.canonicalize() {
            Ok(abs) => Some(abs),
            Err(e) => {
                if output_mode(cli) == OutputMode::Human {
                    eprintln!("Warning: skipping invalid path {}: {}", p.display(), e);
                }
                None
            }
        })
        .collect();

    if root_paths.is_empty() {
        return Err(CliError::User("no valid scan paths found".to_string()));
    }

    // Build protection registry.
    let protection_patterns = if config.scanner.protected_paths.is_empty() {
        None
    } else {
        Some(config.scanner.protected_paths.as_slice())
    };
    let protection = ProtectionRegistry::new(protection_patterns)
        .map_err(|e| CliError::Runtime(e.to_string()))?;

    // Walk the filesystem.
    let walker_config = WalkerConfig {
        root_paths: root_paths.clone(),
        max_depth: config.scanner.max_depth,
        follow_symlinks: config.scanner.follow_symlinks,
        cross_devices: config.scanner.cross_devices,
        parallelism: config.scanner.parallelism,
        excluded_paths: config
            .scanner
            .excluded_paths
            .iter()
            .cloned()
            .collect::<HashSet<_>>(),
        opaque_pruning: matches!(config.scanner.engine, ScannerEngineMode::V2),
    };
    let walker = DirectoryWalker::new(walker_config, protection);
    let entries = walker
        .walk()
        .map_err(|e| CliError::Runtime(e.to_string()))?;
    let dir_count = entries.len();

    // Count protected directories encountered.
    let protected_count = walker.protection().read().list_protections().len();

    // Classify and score each entry with active-reference evidence already
    // attached, so in-use artifacts are vetoed before the deletion plan.
    // Also apply CLI min_score override to the engine config.
    let registry = ArtifactPatternRegistry::default();
    let mut scoring_config = config.scoring.clone();
    scoring_config.min_score = args.min_score;
    let engine = ScoringEngine::from_config(&scoring_config, config.scanner.min_file_age_minutes);
    let sacred_paths = active_sacred_paths(&config)?;
    let now = SystemTime::now();
    let active_reference_scan = active_reference_scan_config(&config);
    let mut open_paths = None;
    let mut active_reference_index = None;

    let scored: Vec<CandidacyScore> = entries
        .iter()
        .map(|entry| {
            let classification = registry.classify(&entry.path, entry.structural_signals);
            let age = now
                .duration_since(
                    entry.effective_age_timestamp(classification.category.is_regenerable_tree()),
                )
                .unwrap_or_default();
            let mut candidate = CandidateInput {
                path: entry.path.clone(),
                size_bytes: entry.metadata.content_size_bytes,
                age,
                classification,
                signals: entry.structural_signals,
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            };
            let cheap_score = engine.score_candidate(&candidate, 0.0);
            if !cheap_score.vetoed && cheap_score.total_score >= args.min_score {
                candidate.is_open = open_status_for_candidate(
                    &mut open_paths,
                    &root_paths,
                    active_reference_scan,
                    &entry.path,
                    entry.metadata.content_size_bytes,
                );
                let (active_references, _) = active_references_for_candidate(
                    &mut active_reference_index,
                    &root_paths,
                    active_reference_scan,
                    &entry.path,
                    Some(entry.metadata.identity()),
                    entry.metadata.content_size_bytes,
                );
                candidate.active_references = active_references;
            }
            let (mut score, _) = score_candidate_with_deferred_sacred_check(
                &engine,
                &candidate,
                0.0,
                &sacred_paths,
                |base_score| !base_score.vetoed && base_score.total_score >= args.min_score,
            );
            score.identity = Some(entry.metadata.identity());
            score
        })
        .filter(|score| !score.vetoed && score.total_score >= args.min_score)
        .collect();

    let scan_elapsed = start.elapsed();

    // Build deletion plan.
    let deletion_config = DeletionConfig {
        max_batch_size: args.max_items.unwrap_or(config.scanner.max_delete_batch),
        dry_run: args.dry_run,
        min_score: args.min_score,
        check_open_files: true,
        require_identity: matches!(config.scanner.engine, ScannerEngineMode::V2),
        sacred_paths,
        // Layer 7: a manual clean has time to keep the bytes around.
        mode: if args.no_quarantine || !config.scanner.quarantine_enabled {
            DeletionMode::Unlink
        } else {
            DeletionMode::Quarantine
        },
        quarantine_ttl: Duration::from_secs(
            config.scanner.quarantine_ttl_hours.saturating_mul(3600),
        ),
        quarantine_roots: root_paths.clone(),
        ..Default::default()
    };
    let executor = DeletionExecutor::new(deletion_config, None);
    // Record every scored, non-vetoed candidate (keep, review and delete
    // verdicts alike) before planning, so `sbh explain` can also answer
    // "why was this kept?" for CLI runs.
    let recorded_decisions = record_cli_decisions(cli, &config, &scored, args.dry_run);
    // W1 planner: the set that reaches --target-free with the least expected
    // loss inside the mount's risk budget, in that order.
    let (level, target_bytes) = clean_plan_target(&config, &root_paths, args.target_free);
    let (chosen, batch_plan) = plan_batch(
        scored,
        &cli_plan_request(
            &config,
            level,
            target_bytes,
            args.max_items.unwrap_or(config.scanner.max_delete_batch),
        ),
    );
    eprintln!("[SBH-PLANNER] {}", batch_plan.summary_line());
    record_cli_plan(cli, &config, &batch_plan);
    let mut plan = executor.plan(chosen);
    order_by_plan(&mut plan, &batch_plan);
    if cli.verbose && recorded_decisions > 0 {
        eprintln!(
            "[SBH-CLEAN] recorded {recorded_decisions} decision(s) in {} (see `sbh explain --last {recorded_decisions}`)",
            config.paths.sqlite_db.display()
        );
    }

    if plan.candidates.is_empty() {
        match output_mode(cli) {
            OutputMode::Human => {
                println!(
                    "Scanned {dir_count} directories in {:.1}s — no cleanup candidates found above threshold {:.2}.",
                    scan_elapsed.as_secs_f64(),
                    args.min_score
                );
                if protected_count > 0 {
                    println!(
                        "  {protected_count} directories protected (use 'sbh protect --list' to see)."
                    );
                }
            }
            OutputMode::Json => {
                // Same key set as every other clean/emergency completion report
                // so a parser never has to treat these as optional.
                let payload = json!({
                    "command": "clean",
                    "scanned_directories": dir_count,
                    "elapsed_seconds": scan_elapsed.as_secs_f64(),
                    "candidates_count": 0,
                    "items_deleted": 0,
                    "items_would_delete": 0,
                    "items_skipped": 0,
                    "items_failed": 0,
                    "bytes_freed": 0,
                    "bytes_would_free": 0,
                    "dry_run": args.dry_run,
                    "protected_count": protected_count,
                    "skipped_by_reason": json!({}),
                    "stalled": false,
                });
                write_json_line(&payload)?;
            }
        }
        return Ok(());
    }

    // Display the plan.
    if output_mode(cli) == OutputMode::Human {
        println!("The following items will be deleted:\n");
        print_deletion_plan(&plan);
        println!(
            "\nTotal: {} items, {}",
            plan.estimated_items,
            format_bytes(plan.total_reclaimable_bytes)
        );
        if protected_count > 0 {
            println!(
                "  {protected_count} directories protected (use 'sbh protect --list' to see)."
            );
        }
        println!();
    }

    // Decide execution mode.
    if args.dry_run {
        // Dry-run: show plan, execute in dry-run mode for the report.
        let report = executor.execute(&plan, None);
        match output_mode(cli) {
            OutputMode::Human => {
                println!(
                    "Dry run complete: {} items ({}) would be freed.",
                    report.items_would_delete,
                    format_bytes(report.bytes_would_free),
                );
            }
            OutputMode::Json => {
                emit_clean_report_json(
                    &plan,
                    &report,
                    dir_count,
                    scan_elapsed,
                    protected_count,
                    "clean",
                    Some(&batch_plan),
                )?;
            }
        }
    } else if !io::stdout().is_terminal() && !args.yes {
        // Non-TTY without --yes: refuse to delete silently.
        match output_mode(cli) {
            OutputMode::Human => {
                eprintln!("sbh: refusing to delete in non-interactive mode without --yes");
            }
            OutputMode::Json => {
                let payload = json!({
                    "command": "clean",
                    "error": "non_interactive_without_yes",
                    "candidates_count": plan.estimated_items,
                });
                write_json_line(&payload)?;
            }
        }
        return Err(CliError::User(
            "pass --yes to confirm deletion in non-interactive mode".to_string(),
        ));
    } else if args.yes || !io::stdout().is_terminal() {
        // Automatic mode: confirmed via --yes.
        let platform = detect_platform().map_err(|e| CliError::Runtime(e.to_string()))?;
        let collector = std::sync::Arc::new(FsStatsCollector::new(
            platform,
            std::time::Duration::from_millis(500),
        ));
        let pressure_check = build_pressure_check(args.target_free, collector);
        let report = executor.execute(
            &plan,
            pressure_check
                .as_ref()
                .map(|f| f as &dyn Fn(&std::path::Path) -> bool),
        );

        match output_mode(cli) {
            OutputMode::Human => {
                print_clean_summary(&report);
            }
            OutputMode::Json => {
                emit_clean_report_json(
                    &plan,
                    &report,
                    dir_count,
                    scan_elapsed,
                    protected_count,
                    "clean",
                    Some(&batch_plan),
                )?;
            }
        }
        // C-EXIT: failed deletions are a partial success (4), reported after
        // the summary so the operator sees what did and did not happen.
        if report.items_failed > 0 {
            return Err(CliError::Partial(format!(
                "{} of {} deletion(s) failed",
                report.items_failed,
                report.items_failed + report.items_deleted
            )));
        }
    } else {
        // Interactive mode.
        run_interactive_clean(
            cli,
            &executor,
            &plan,
            args,
            &root_paths,
            dir_count,
            scan_elapsed,
            protected_count,
        )?;
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct LocalSnapshotThinExecution {
    stdout: String,
    stderr: String,
}

fn run_local_snapshot_thin(cli: &Cli, args: &CleanArgs) -> Result<(), CliError> {
    if !args.paths.is_empty() {
        return Err(CliError::User(
            "--thin-local-snapshots does not accept file cleanup paths".to_string(),
        ));
    }

    let mount = args
        .local_snapshot_mount
        .as_deref()
        .unwrap_or_else(|| Path::new("/"));
    let command = local_snapshot_thin_shell_command(mount);
    let estimated_reclaimable_bytes = local_snapshot_estimate_for_mount(mount);

    if args.dry_run {
        match output_mode(cli) {
            OutputMode::Human => {
                print_local_snapshot_thin_dry_run(mount, &command, estimated_reclaimable_bytes);
            }
            OutputMode::Json => emit_local_snapshot_thin_json(
                mount,
                &command,
                estimated_reclaimable_bytes,
                true,
                None,
                None,
            )?,
        }
        return Ok(());
    }

    if !local_snapshot_thinning_supported() {
        return Err(CliError::User(
            "--thin-local-snapshots is only supported on macOS".to_string(),
        ));
    }

    if !running_as_root() {
        return Err(CliError::User(format!(
            "Time Machine local snapshot thinning requires sudo/root. Run `sudo sbh clean --thin-local-snapshots --yes` or run `{command}` directly."
        )));
    }

    if !io::stdout().is_terminal() && !args.yes {
        if output_mode(cli) == OutputMode::Json {
            let payload = json!({
                "command": "clean",
                "action": "thin_local_snapshots",
                "error": "non_interactive_without_yes",
                "mount": mount.to_string_lossy(),
                "thin_command": command,
            });
            write_json_line(&payload)?;
        }
        return Err(CliError::User(
            "pass --yes to confirm Time Machine local snapshot thinning in non-interactive mode"
                .to_string(),
        ));
    }

    if !args.yes && !confirm_local_snapshot_thinning(mount, &command, estimated_reclaimable_bytes)?
    {
        if output_mode(cli) == OutputMode::Human {
            println!("Skipped Time Machine local snapshot thinning.");
        }
        return Ok(());
    }

    if output_mode(cli) == OutputMode::Human {
        println!(
            "Thinning Time Machine local snapshots on {}. This can take 30+ seconds...",
            mount.display()
        );
    }
    let started = std::time::Instant::now();
    let execution = execute_local_snapshot_thinning(mount)?;
    let elapsed = started.elapsed();

    match output_mode(cli) {
        OutputMode::Human => {
            println!(
                "Time Machine local snapshot thinning complete in {:.1}s.",
                elapsed.as_secs_f64()
            );
            print_tmutil_streams(&execution);
        }
        OutputMode::Json => emit_local_snapshot_thin_json(
            mount,
            &command,
            estimated_reclaimable_bytes,
            false,
            Some(elapsed),
            Some(&execution),
        )?,
    }

    Ok(())
}

fn print_local_snapshot_thin_dry_run(
    mount: &Path,
    command: &str,
    estimated_reclaimable_bytes: Option<u64>,
) {
    println!(
        "Would thin local Time Machine snapshots on {}.",
        mount.display()
    );
    if let Some(bytes) = estimated_reclaimable_bytes {
        println!("Estimated reclaimable: {}", format_bytes(bytes));
    } else {
        println!("Estimated reclaimable: unknown until macOS reports snapshot retention.");
    }
    println!("Command: {command}");
    println!("This can take 30+ seconds and requires sudo/root for system-wide thinning.");
}

fn confirm_local_snapshot_thinning(
    mount: &Path,
    command: &str,
    estimated_reclaimable_bytes: Option<u64>,
) -> Result<bool, CliError> {
    print_local_snapshot_thin_dry_run(mount, command, estimated_reclaimable_bytes);
    print!("Proceed with Time Machine snapshot thinning? [y/N] ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(matches!(
        input.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn emit_local_snapshot_thin_json(
    mount: &Path,
    command: &str,
    estimated_reclaimable_bytes: Option<u64>,
    dry_run: bool,
    elapsed: Option<std::time::Duration>,
    execution: Option<&LocalSnapshotThinExecution>,
) -> Result<(), CliError> {
    let payload = json!({
        "command": "clean",
        "action": "thin_local_snapshots",
        "mount": mount.to_string_lossy(),
        "dry_run": dry_run,
        "thin_command": command,
        "estimated_reclaimable_bytes": estimated_reclaimable_bytes,
        "requires_sudo": true,
        "elapsed_seconds": elapsed.map(|duration| duration.as_secs_f64()),
        "tmutil_stdout": execution.map(|report| report.stdout.as_str()),
        "tmutil_stderr": execution.map(|report| report.stderr.as_str()),
    });
    write_json_line(&payload)
}

fn print_tmutil_streams(execution: &LocalSnapshotThinExecution) {
    let stdout = execution.stdout.trim();
    if !stdout.is_empty() {
        println!("{stdout}");
    }
    let stderr = execution.stderr.trim();
    if !stderr.is_empty() {
        eprintln!("{stderr}");
    }
}

fn local_snapshot_estimate_for_mount(mount: &Path) -> Option<u64> {
    detect_platform()
        .ok()
        .and_then(|platform| platform.capacity(mount).ok())
        .and_then(|capacity| capacity.local_snapshot_bytes)
        .filter(|bytes| *bytes > 0)
}

#[cfg(target_os = "macos")]
const fn local_snapshot_thinning_supported() -> bool {
    true
}

#[cfg(not(target_os = "macos"))]
const fn local_snapshot_thinning_supported() -> bool {
    false
}

#[cfg(target_os = "macos")]
fn execute_local_snapshot_thinning(mount: &Path) -> Result<LocalSnapshotThinExecution, CliError> {
    use storage_ballast_helper::platform::macos::sys;

    let report = sys::thin_local_time_machine_snapshots(mount)
        .map_err(|error| CliError::Runtime(error.to_string()))?;
    Ok(LocalSnapshotThinExecution {
        stdout: report.stdout,
        stderr: report.stderr,
    })
}

#[cfg(not(target_os = "macos"))]
fn execute_local_snapshot_thinning(_mount: &Path) -> Result<LocalSnapshotThinExecution, CliError> {
    Err(CliError::User(
        "--thin-local-snapshots is only supported on macOS".to_string(),
    ))
}

/// Print the deletion plan in a numbered table.
fn print_deletion_plan(plan: &DeletionPlan) {
    for (i, candidate) in plan.candidates.iter().enumerate() {
        let age_str = format_duration(candidate.age);
        let size_str = format_bytes(candidate.size_bytes);
        let path_str = truncate_path(&candidate.path, 60);

        println!(
            "  {:>3}. {} ({}, score {:.2}, {} old, id {})",
            i + 1,
            path_str,
            size_str,
            candidate.total_score,
            age_str,
            candidate_decision_id(candidate),
        );
    }
}

/// The stable decision id `sbh explain --id` resolves for a candidate.
fn candidate_decision_id(candidate: &CandidacyScore) -> String {
    storage_ballast_helper::scanner::decision_record::stable_decision_id(
        &candidate.path,
        candidate.identity,
        candidate.size_bytes,
    )
}

/// Build a pressure check closure if --target-free was specified.
#[allow(clippy::type_complexity)]
fn build_pressure_check(
    target_free: Option<f64>,
    collector: std::sync::Arc<FsStatsCollector>,
) -> Option<Box<dyn Fn(&Path) -> bool>> {
    let target = target_free?;
    Some(Box::new(move |path: &Path| {
        collector
            .collect(path)
            .is_ok_and(|stats| stats.free_pct() >= target)
    }))
}

fn active_reference_scan_config(config: &Config) -> ActiveReferenceScanConfig {
    ActiveReferenceScanConfig::new(
        Duration::from_secs(config.scanner.active_reference_cache_ttl_secs),
        config.scanner.active_reference_min_size_bytes,
    )
}

fn collect_active_reference_index_best_effort(
    root_paths: &[PathBuf],
    cache_ttl: Duration,
) -> ActiveReferenceIndex {
    detect_platform()
        .ok()
        .map_or_else(ActiveReferenceIndex::empty, |platform| {
            collect_active_reference_index_cached(platform.as_ref(), root_paths, cache_ttl)
        })
}

fn active_references_for_candidate(
    active_reference_index: &mut Option<ActiveReferenceIndex>,
    root_paths: &[PathBuf],
    scan_config: ActiveReferenceScanConfig,
    path: &Path,
    identity: Option<FsIdentity>,
    size_bytes: u64,
) -> (ActiveReferenceSummary, bool) {
    if !scan_config.should_probe(size_bytes) {
        return (ActiveReferenceSummary::default(), false);
    }

    let index = active_reference_index.get_or_insert_with(|| {
        collect_active_reference_index_best_effort(root_paths, scan_config.cache_ttl)
    });
    let summary = identity.map_or_else(
        || index.summary_for(path),
        |id| index.summary_for_identity(id),
    );
    (summary, true)
}

fn open_status_for_candidate(
    open_paths: &mut Option<HashSet<PathBuf>>,
    root_paths: &[PathBuf],
    scan_config: ActiveReferenceScanConfig,
    path: &Path,
    size_bytes: u64,
) -> bool {
    if !scan_config.should_probe(size_bytes) {
        return false;
    }

    let open_paths = open_paths.get_or_insert_with(|| {
        collect_open_path_ancestors_cached(root_paths, scan_config.cache_ttl).0
    });
    is_path_open_by_ancestor(path, open_paths)
}

/// Interactive clean: prompt user for each candidate.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn run_interactive_clean(
    cli: &Cli,
    executor: &DeletionExecutor,
    plan: &DeletionPlan,
    args: &CleanArgs,
    _root_paths: &[PathBuf],
    dir_count: usize,
    scan_elapsed: std::time::Duration,
    protected_count: usize,
) -> Result<(), CliError> {
    let stdin = io::stdin();
    let mut input = String::new();
    let mut items_deleted: usize = 0;
    let mut skips = InteractiveSkips::default();
    let mut bytes_freed: u64 = 0;
    let mut bytes_quarantined: u64 = 0;
    let mut delete_all = false;

    let platform = detect_platform().map_err(|e| CliError::Runtime(e.to_string()))?;
    // Interactive mode is slow enough that we can use short TTL or no cache,
    // but FsStatsCollector handles mount resolution which is what we need.
    let collector = std::sync::Arc::new(FsStatsCollector::new(
        platform,
        std::time::Duration::from_millis(500),
    ));

    println!("Proceed with deletion? [y/N/a(ll)/s(kip)/q(uit)]");
    println!("  y - delete this item    a - delete all remaining");
    println!("  n - skip this item      s - skip all remaining");
    println!("  q - quit\n");

    for (i, candidate) in plan.candidates.iter().enumerate() {
        // Check target_free skip condition.
        if let Some(target) = args.target_free
            && let Ok(stats) = collector.collect(&candidate.path)
            && stats.free_pct() >= target
        {
            println!(
                "  Target free space ({target:.1}%) achieved on {}. Skipping.",
                stats.mount_point.display()
            );
            skips.record(storage_ballast_helper::scanner::deletion::SkipReason::TargetFreeReached);
            continue;
        }

        let action = if delete_all {
            'y'
        } else {
            let path_str = truncate_path(&candidate.path, 60);
            let size_str = format_bytes(candidate.size_bytes);
            print!(
                "  [{}/{}] {} ({}, score {:.2})? ",
                i + 1,
                plan.candidates.len(),
                path_str,
                size_str,
                candidate.total_score,
            );
            io::stdout().flush()?;

            input.clear();
            stdin
                .read_line(&mut input)
                .map_err(|e| CliError::Runtime(e.to_string()))?;
            match input.trim().to_lowercase().as_str() {
                "y" | "yes" => 'y',
                "a" | "all" => {
                    delete_all = true;
                    'y'
                }
                "s" | "skip" => {
                    println!("  Skipping all remaining items.");
                    break;
                }
                "q" | "quit" => {
                    println!("  Quitting without further deletions.");
                    break;
                }
                _ => 'n', // Default to skip.
            }
        };

        if action == 'y' {
            // Collect a fresh open-file index for this candidate, then route
            // through the executor's full pre-flight veto stack. A "y" (or
            // "a") answer is consent, not a bypass: every safety rail that
            // protects the --yes batch path applies here too.
            let (fresh_open_paths, complete) =
                collect_open_path_ancestors(std::slice::from_ref(&candidate.path));
            // clippy::if_not_else is deliberately allowed here. The negative-first
            // form is load-bearing: it puts the fail-safe (skip) branch ahead of the
            // destructive branch (delete), so the guard is visible before the action
            // when auditing this path. Inverting it to satisfy the lint would bury
            // the safety rail below the deletion it protects.
            #[allow(clippy::if_not_else)]
            if !complete {
                // Fail safe, mirroring the batch executor: if we cannot see
                // which paths are open we cannot prove this one is closed.
                eprintln!(
                    "    Skipped (open-file scan incomplete): {}",
                    candidate.path.display()
                );
                skips.record(storage_ballast_helper::scanner::deletion::SkipReason::FileOpen);
            } else {
                match executor.delete_candidate_checked(candidate, Some(&fresh_open_paths)) {
                    Ok(storage_ballast_helper::scanner::deletion::CheckedDeletion::Deleted) => {
                        items_deleted += 1;
                        bytes_freed += candidate.size_bytes;
                        if !delete_all {
                            println!("    Deleted.");
                        }
                    }
                    Ok(storage_ballast_helper::scanner::deletion::CheckedDeletion::Quarantined) => {
                        items_deleted += 1;
                        bytes_quarantined += candidate.size_bytes;
                        if !delete_all {
                            println!("    Quarantined (restore with `sbh undo`).");
                        }
                    }
                    Ok(storage_ballast_helper::scanner::deletion::CheckedDeletion::Skipped(
                        skip,
                    )) => {
                        eprintln!(
                            "    Skipped ({}): {}",
                            skip.explanation(),
                            candidate.path.display()
                        );
                        skips.record(skip);
                    }
                    Err(e) => {
                        eprintln!("    Failed to delete {}: {e}", candidate.path.display());
                    }
                }
            }
        } else {
            skips.record(storage_ballast_helper::scanner::deletion::SkipReason::UserDeclined);
        }
    }

    match output_mode(cli) {
        OutputMode::Human => {
            println!("\nCleanup complete:");
            println!(
                "  Deleted: {items_deleted} items, {} freed",
                format_bytes(bytes_freed)
            );
            if skips.total > 0 {
                println!("  Skipped: {} items", skips.total);
            }
        }
        OutputMode::Json => {
            let payload = json!({
                "command": "clean",
                "scanned_directories": dir_count,
                "elapsed_seconds": scan_elapsed.as_secs_f64(),
                "candidates_count": plan.estimated_items,
                "items_deleted": items_deleted,
                "bytes_quarantined": bytes_quarantined,
                "items_skipped": skips.total,
                "skipped_by_reason": skips_json(&skips.by_reason),
                // Mirrors DeletionReport::stalled(): work was queued, nothing freed.
                "stalled": items_deleted == 0 && bytes_freed == 0 && skips.total > 0,
                "bytes_freed": bytes_freed,
                "dry_run": false,
                "protected_count": protected_count,
            });
            write_json_line(&payload)?;
        }
    }

    Ok(())
}

/// Interactive skip bookkeeping.
///
/// The interactive flows do not go through `DeletionExecutor::execute`, so they
/// keep their own counters. They still owe the same `skipped_by_reason` /
/// `stalled` JSON contract as the batch paths, and this keeps the count and the
/// histogram incremented together at one place.
#[derive(Default)]
struct InteractiveSkips {
    total: usize,
    by_reason: std::collections::BTreeMap<&'static str, usize>,
}

impl InteractiveSkips {
    fn record(&mut self, reason: storage_ballast_helper::scanner::deletion::SkipReason) {
        self.total += 1;
        *self.by_reason.entry(reason.as_str()).or_insert(0) += 1;
    }
}

/// Map a `skipped_by_reason` key back to its operator-facing explanation.
///
/// Delegates to `SkipReason::from_key` so the JSON contract and the human
/// output render from one list; there is no second copy to drift.
fn skip_reason_explanation(key: &str) -> &'static str {
    use storage_ballast_helper::scanner::deletion::SkipReason as R;
    R::from_key(key).map_or("unknown skip reason", R::explanation)
}

/// Render a `skipped_by_reason` histogram as a JSON object.
///
/// Always emitted — including when empty — so every clean/emergency JSON path
/// has the same shape and a parser never has to treat the key as optional.
fn skips_json(skipped_by_reason: &std::collections::BTreeMap<&'static str, usize>) -> Value {
    Value::Object(
        skipped_by_reason
            .iter()
            .map(|(reason, count)| ((*reason).to_string(), json!(count)))
            .collect(),
    )
}

/// Print a human-readable cleanup summary from a DeletionReport.
fn print_clean_summary(report: &storage_ballast_helper::scanner::deletion::DeletionReport) {
    if report.dry_run {
        println!(
            "Dry run: {} items ({}) would be freed.",
            report.items_would_delete,
            format_bytes(report.bytes_would_free),
        );
    } else {
        println!("Cleanup complete:");
        println!(
            "  Deleted: {} items, {} freed in {:.1}s",
            report.items_deleted,
            format_bytes(report.bytes_freed),
            report.duration.as_secs_f64(),
        );
        if report.items_quarantined > 0 {
            println!(
                "  Quarantined: {} of those ({}) held under .sbh/quarantine, restorable with `sbh undo <decision-id>` (`sbh undo --list`)",
                report.items_quarantined,
                format_bytes(report.bytes_quarantined),
            );
        }
        if report.quarantine_unavailable > 0 {
            println!(
                "  Quarantine unavailable for {} item(s): removed for good (reasons on stderr)",
                report.quarantine_unavailable
            );
        }
        if report.items_skipped > 0 {
            println!("  Skipped: {} items", report.items_skipped);
            // Always attribute skips. An unexplained skip count on a full disk
            // is indistinguishable from a malfunction, even when every skip was
            // a deliberate safety refusal.
            for (reason, count) in &report.skipped_by_reason {
                println!(
                    "    {count:>6}  {reason}  ({})",
                    skip_reason_explanation(reason)
                );
            }
        }
        if report.stalled() {
            println!();
            println!(
                "  Nothing was freed. {} candidate(s) were found but every one was skipped.",
                report.items_skipped + report.items_failed
            );
            if let Some((reason, count)) = report.dominant_skip_reason() {
                println!(
                    "  Dominant reason: {reason} ({count}) — {}",
                    skip_reason_explanation(reason)
                );
                if reason == "hardcoded_source_tree" {
                    println!(
                        "  This is the carnage-prevention floor protecting source trees; it \
                         cannot be disabled by config. Point --paths at a build/cache directory."
                    );
                } else if reason == "not_writable" {
                    println!(
                        "  Check the systemd unit's ReadWritePaths= whitelist for these paths."
                    );
                } else if reason == "target_free_reached" {
                    // The trap this message exists for: every candidate sits on a
                    // mount that is already comfortable (commonly a tmpfs /tmp),
                    // while the mount actually under pressure has no candidates.
                    // Deleting would have been pointless, but "221 skipped, 0
                    // freed" reads as a malfunction rather than as that finding.
                    println!(
                        "  Every candidate is on a mount that ALREADY has at least the target \
                         free space, so removing them would not relieve the mount you care about."
                    );
                    println!(
                        "  Re-run scoped to the mount under pressure, e.g. \
                         `sbh emergency --target-free <pct> /path/on/the/full/mount`, \
                         and check `sbh status` for which mount is actually critical."
                    );
                }
            }
        }
        if report.items_failed > 0 {
            println!("  Failed: {} items", report.items_failed);
            for err in &report.errors {
                eprintln!("    {}: {}", err.path.display(), err.error);
            }
        }
        if report.circuit_breaker_tripped {
            println!("  Warning: circuit breaker was tripped due to consecutive failures.");
        }
    }
}

/// Emit the clean report in JSON format.
fn emit_clean_report_json(
    plan: &DeletionPlan,
    report: &storage_ballast_helper::scanner::deletion::DeletionReport,
    dir_count: usize,
    scan_elapsed: std::time::Duration,
    protected_count: usize,
    command: &str,
    batch_plan: Option<&BatchPlan>,
) -> Result<(), CliError> {
    let errors: Vec<Value> = report
        .errors
        .iter()
        .map(|e| {
            json!({
                "path": e.path.to_string_lossy(),
                "error": e.error,
                "error_code": e.error_code,
                "recoverable": e.recoverable,
            })
        })
        .collect();

    // The plan the report acted on, each with the id `sbh explain --id`
    // resolves (emergency runs with no ledger, so stdout is the only trail).
    let candidates: Vec<Value> = plan
        .candidates
        .iter()
        .map(|candidate| {
            json!({
                "path": candidate.path.to_string_lossy(),
                "size_bytes": candidate.size_bytes,
                "total_score": candidate.total_score,
                "decision": format!("{:?}", candidate.decision.action),
                "decision_id": candidate_decision_id(candidate),
            })
        })
        .collect();

    let payload = json!({
        "command": command,
        "scanned_directories": dir_count,
        "elapsed_seconds": scan_elapsed.as_secs_f64(),
        "candidates_count": plan.estimated_items,
        "candidates": candidates,
        "items_deleted": report.items_deleted,
        "items_would_delete": report.items_would_delete,
        "items_skipped": report.items_skipped,
        "items_failed": report.items_failed,
        "bytes_freed": report.bytes_freed,
        "items_quarantined": report.items_quarantined,
        "bytes_quarantined": report.bytes_quarantined,
        "plan": batch_plan,
        "quarantine_unavailable": report.quarantine_unavailable,
        "bytes_would_free": report.bytes_would_free,
        "duration_seconds": report.duration.as_secs_f64(),
        "dry_run": report.dry_run,
        "circuit_breaker_tripped": report.circuit_breaker_tripped,
        "protected_count": protected_count,
        // Why nothing (or less than expected) was removed. Sums to items_skipped.
        "skipped_by_reason": skips_json(&report.skipped_by_reason),
        // True when candidates existed but nothing was freed — the shape that
        // reads as "sbh is broken" and previously carried no explanation.
        "stalled": report.stalled(),
        "errors": errors,
    });
    write_json_line(&payload)
}

#[allow(
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn run_check(cli: &Cli, args: &CheckArgs) -> Result<(), CliError> {
    let platform = detect_platform().map_err(|e| CliError::Runtime(e.to_string()))?;

    // Determine check path: CLI arg, or cwd.
    let check_path = args
        .path
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")));

    let capacity = platform
        .capacity(&check_path)
        .map_err(|e| CliError::Runtime(e.to_string()))?;

    let free_pct = capacity_free_pct(&capacity);
    let config = Config::load(cli.config.as_deref()).unwrap_or_default();
    let threshold_pct = args
        .target_free
        .unwrap_or(config.pressure.yellow_min_free_pct);

    // Check 1: absolute free space requirement.
    if let Some(need_bytes) = args.need
        && capacity.available_bytes < need_bytes
    {
        match output_mode(cli) {
            OutputMode::Human => {
                println!(
                    "sbh: {} has {} free but {} required. Run: sbh emergency {}",
                    capacity.mount_point.display(),
                    format_bytes(capacity.available_bytes),
                    format_bytes(need_bytes),
                    check_path.display(),
                );
            }
            OutputMode::Json => {
                let payload = json!({
                    "command": "check",
                "schema_version": 2,
                    "status": "critical",
                    "path": check_path.to_string_lossy(),
                    "mount_point": capacity.mount_point.to_string_lossy(),
                    "free_bytes": capacity.available_bytes,
                    "total_bytes": capacity.total_bytes,
                    "need_bytes": need_bytes,
                    "free_pct": free_pct,
                    "container_id": capacity.container_id.as_deref(),
                    "container_total_bytes": capacity.container_total_bytes,
                    "container_available_bytes": capacity.container_available_bytes,
                    "volume_total_bytes": capacity.volume_total_bytes,
                    "volume_available_bytes": capacity.volume_available_bytes,
                    "volume_role": capacity.volume_role.as_deref(),
                    "free_excludes_purgeable": true,
                    "platform": capacity_platform_json(&capacity),
                    "exit_code": 1,
                });
                write_json_line(&payload)?;
            }
        }
        // C-EXIT: a pressure condition is exit 1, distinct from an I/O failure.
        return Err(CliError::User("insufficient disk space".to_string()));
    }

    // What the daemon could reclaim on this mount, when it is pressured and
    // the answer is nothing: reported with every outcome below, and a
    // failure of its own once the plain threshold passes (Check 2.7).
    let unprotected = unprotected_pressure_at(&config.paths.state_file, &capacity.mount_point);
    let unprotected_json = unprotected.as_ref().map_or(Value::Null, |u| {
        json!({
            "reason": UNPROTECTED_PRESSURE,
            "level": u.level,
            "reclaim_capability": u.capability,
            "allowed": args.allow_unprotected,
        })
    });

    // Check 2: percentage threshold.
    if free_pct < threshold_pct {
        match output_mode(cli) {
            OutputMode::Human => {
                println!(
                    "sbh: {} has {} free ({:.1}%). Run: sbh emergency {}{}",
                    capacity.mount_point.display(),
                    format_bytes(capacity.available_bytes),
                    free_pct,
                    check_path.display(),
                    unprotected.as_ref().map_or_else(String::new, |u| format!(
                        " (the daemon has nothing to reclaim there: reclaim_capability={})",
                        u.capability
                    )),
                );
            }
            OutputMode::Json => {
                let payload = json!({
                    "command": "check",
                "schema_version": 2,
                    "status": "critical",
                    "path": check_path.to_string_lossy(),
                    "mount_point": capacity.mount_point.to_string_lossy(),
                    "free_bytes": capacity.available_bytes,
                    "total_bytes": capacity.total_bytes,
                    "free_pct": free_pct,
                    "threshold_pct": threshold_pct,
                    "unprotected": unprotected_json,
                    "container_id": capacity.container_id.as_deref(),
                    "container_total_bytes": capacity.container_total_bytes,
                    "container_available_bytes": capacity.container_available_bytes,
                    "volume_total_bytes": capacity.volume_total_bytes,
                    "volume_available_bytes": capacity.volume_available_bytes,
                    "volume_role": capacity.volume_role.as_deref(),
                    "free_excludes_purgeable": true,
                    "platform": capacity_platform_json(&capacity),
                    "exit_code": 1,
                });
                write_json_line(&payload)?;
            }
        }
        // C-EXIT: a pressure condition is exit 1, distinct from an I/O failure.
        return Err(CliError::User("disk space below threshold".to_string()));
    }

    // Check 2.7: unprotected pressure. The daemon reports, per mount, what
    // it could reclaim; a mount at Orange or worse where that is nothing is
    // a pressure condition `check` must not wave through (C-EXIT 1,
    // reason `unprotected_pressure`) unless the caller says so.
    if let Some(unprotected) = &unprotected {
        let line = format!(
            "{} is at {} and the daemon has nothing to reclaim there (reclaim_capability={}). \
             Next: add a scanner.root_path on this device, set \
             scanner.catalog_roots_on_pressured_device = true, or run `sbh ballast provision`",
            capacity.mount_point.display(),
            unprotected.level,
            unprotected.capability,
        );
        if args.allow_unprotected {
            if output_mode(cli) == OutputMode::Human {
                eprintln!("sbh: warning: {line}");
            }
        } else {
            match output_mode(cli) {
                OutputMode::Human => println!("sbh: {line}"),
                OutputMode::Json => {
                    let payload = json!({
                        "command": "check",
                        "schema_version": 2,
                        "status": "unprotected",
                        "reason": UNPROTECTED_PRESSURE,
                        "path": check_path.to_string_lossy(),
                        "mount_point": capacity.mount_point.to_string_lossy(),
                        "free_bytes": capacity.available_bytes,
                        "total_bytes": capacity.total_bytes,
                        "free_pct": free_pct,
                        "level": unprotected.level,
                        "reclaim_capability": unprotected.capability,
                        "unprotected": unprotected_json,
                        "platform": capacity_platform_json(&capacity),
                        "exit_code": 1,
                    });
                    write_json_line(&payload)?;
                }
            }
            return Err(CliError::User(UNPROTECTED_PRESSURE.to_string()));
        }
    }

    // Check 2.5: warn if state.json is stale (daemon may not be running).
    if let Ok(meta) = std::fs::metadata(&config.paths.state_file)
        && let Ok(modified) = meta.modified()
    {
        let age = SystemTime::now()
            .duration_since(modified)
            .unwrap_or_default();
        let stale_threshold = std::time::Duration::from_secs(DAEMON_STATE_STALE_THRESHOLD_SECS);
        if age > stale_threshold && output_mode(cli) == OutputMode::Human {
            eprintln!(
                "sbh: warning: state.json is {:.0}s old (daemon may not be running)",
                age.as_secs_f64(),
            );
        }
    }

    // Check 2.6 (#16): warn when a configured ballast reserve is not actually
    // releasable — the emergency reserve does not exist when it may be needed.
    let ballast = BallastAvailability::observe(&config.paths.ballast_dir, &config.ballast);
    if output_mode(cli) == OutputMode::Human {
        if ballast.health == BallastHealth::Empty {
            eprintln!(
                "sbh: warning: ballast reserve is empty ({} configured, 0 releasable). Run: sbh ballast provision",
                format_bytes(ballast.configured_pool_bytes),
            );
        } else if !ballast.is_authoritative() {
            // Don't go silent here. Before the readability fix this path emitted
            // a bogus "reserve is empty"; the fix must replace that with an
            // honest "couldn't tell", not with nothing at all.
            eprintln!(
                "sbh: note: could not inspect {} of {} ballast files (permission denied or \
                 I/O error); reserve state unknown. Re-run as `sudo sbh ballast status`.",
                ballast.unreadable_count, ballast.configured_count,
            );
        }
    }

    // Check 3: the daemon's forecast (`--predict N`): the mount's
    // `seconds_to_red` from state.json v2, or the rate against the check's
    // own threshold when the daemon has no red horizon yet. A missing or
    // stale state file is reported as unknown, never as a number.
    let mut forecast_json = Value::Null;
    if let Some(predict_minutes) = args.predict {
        let window_secs = predict_minutes as f64 * 60.0;
        let min_confidence = config.pressure.prediction.min_confidence;
        let read = read_daemon_forecast(&config.paths.state_file, &capacity.mount_point);
        match &read {
            ForecastRead::Fresh(Some(forecast)) => {
                forecast_json = forecast.to_json(min_confidence);
                let seconds_left = forecast.acting_seconds_to_red().or_else(|| {
                    (forecast.bytes_per_sec > 0.0).then(|| {
                        let bytes_until_threshold = capacity.available_bytes.saturating_sub(
                            (threshold_pct / 100.0 * capacity.total_bytes as f64) as u64,
                        );
                        bytes_until_threshold as f64 / forecast.bytes_per_sec
                    })
                });
                if let Some(seconds_left) = seconds_left
                    && seconds_left < window_secs
                {
                    let minutes_left = seconds_left / 60.0;
                    match output_mode(cli) {
                        OutputMode::Human => {
                            println!(
                                "sbh: {} has {} free but predicted red in {} (need {} min; rate {}/s, confidence {:.2}{})",
                                capacity.mount_point.display(),
                                format_bytes(capacity.available_bytes),
                                format_eta(seconds_left),
                                predict_minutes,
                                format_bytes(forecast.bytes_per_sec.max(0.0) as u64),
                                forecast.confidence,
                                if forecast.warming(min_confidence) {
                                    ", warming"
                                } else {
                                    ""
                                },
                            );
                        }
                        OutputMode::Json => {
                            let payload = json!({
                                "command": "check",
                                "schema_version": 2,
                                "status": "warning",
                                "path": check_path.to_string_lossy(),
                                "mount_point": capacity.mount_point.to_string_lossy(),
                                "free_bytes": capacity.available_bytes,
                                "total_bytes": capacity.total_bytes,
                                "free_pct": free_pct,
                                "rate_bytes_per_sec": forecast.bytes_per_sec,
                                "seconds_to_red": seconds_left,
                                "minutes_until_red": minutes_left,
                                "predict_minutes": predict_minutes,
                                "forecast": forecast_json,
                                "container_id": capacity.container_id.as_deref(),
                                "container_total_bytes": capacity.container_total_bytes,
                                "container_available_bytes": capacity.container_available_bytes,
                                "volume_total_bytes": capacity.volume_total_bytes,
                                "volume_available_bytes": capacity.volume_available_bytes,
                                "volume_role": capacity.volume_role.as_deref(),
                                "free_excludes_purgeable": true,
                                "platform": capacity_platform_json(&capacity),
                                "exit_code": 1,
                            });
                            write_json_line(&payload)?;
                        }
                    }
                    return Err(CliError::User(
                        "predicted disk full within window".to_string(),
                    ));
                }
            }
            other => {
                // No usable forecast: say so instead of pretending. Not an
                // error; `check` still answers from the live statistics.
                let reason = other.unknown_reason().unwrap_or_default();
                forecast_json = Value::String(reason.clone());
                if output_mode(cli) == OutputMode::Human {
                    eprintln!("sbh: warning: no forecast for --predict: {reason}");
                }
            }
        }
    }

    // All checks passed — silent success on human mode.
    if output_mode(cli) == OutputMode::Json {
        let payload = json!({
            "command": "check",
            "schema_version": 2,
            "status": "ok",
            "path": check_path.to_string_lossy(),
            "mount_point": capacity.mount_point.to_string_lossy(),
            "free_bytes": capacity.available_bytes,
            "total_bytes": capacity.total_bytes,
            "free_pct": free_pct,
            "container_id": capacity.container_id.as_deref(),
            "container_total_bytes": capacity.container_total_bytes,
            "container_available_bytes": capacity.container_available_bytes,
            "volume_total_bytes": capacity.volume_total_bytes,
            "volume_available_bytes": capacity.volume_available_bytes,
            "volume_role": capacity.volume_role.as_deref(),
            "free_excludes_purgeable": true,
            "platform": capacity_platform_json(&capacity),
            // The daemon's forecast when `--predict` asked for one: the rate
            // object, or a string saying why none was usable.
            "forecast": forecast_json,
            // Set when the mount is under pressure with nothing to reclaim
            // and `--allow-unprotected` let the check pass.
            "unprotected": unprotected_json,
            // #16: machine-readable reserve state so automation can flag a
            // configured-but-empty emergency reserve.
            "ballast": {
                "configured_pool_bytes": ballast.configured_pool_bytes,
                "releasable_bytes": ballast.releasable_bytes,
                "available_count": ballast.available_count,
                "missing_count": ballast.missing_count,
                // Non-zero means this snapshot is NOT authoritative (usually an
                // unprivileged caller against a root-owned, mode-700 dir).
                // Automation must not treat `missing_count` as a real absence
                // while this is > 0.
                "unreadable_count": ballast.unreadable_count,
                "authoritative": ballast.is_authoritative(),
                "health": ballast.health.as_str(),
            },
            "exit_code": 0,
        });
        write_json_line(&payload)?;
    }

    Ok(())
}

/// Reason slug `check` exits 1 with when the target mount is pressured and
/// the daemon can reclaim nothing there.
const UNPROTECTED_PRESSURE: &str = "unprotected_pressure";

/// A pressured mount the daemon reports no reclaim capability for.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UnprotectedMount {
    level: String,
    capability: String,
}

/// `state.json` parsed, but only while it is fresh: a stale file describes
/// a daemon that is gone, and nothing in it should gate anything.
fn read_fresh_daemon_state(state_path: &Path) -> Option<Value> {
    let age_secs = std::fs::metadata(state_path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .map_or(u64::MAX, |age| age.as_secs());
    if age_secs > DAEMON_STATE_STALE_THRESHOLD_SECS {
        return None;
    }
    serde_json::from_str(&std::fs::read_to_string(state_path).ok()?).ok()
}

/// The daemon's per-mount control records from a fresh `state.json`.
fn fresh_mount_records(state_path: &Path) -> Vec<MountStateRecord> {
    read_fresh_daemon_state(state_path)
        .and_then(|state| state.get("mount_controllers").cloned())
        .and_then(|records| serde_json::from_value(records).ok())
        .unwrap_or_default()
}

/// Whether the daemon reports `mount` as pressured (Orange or worse) with
/// nothing to reclaim. A missing, stale or silent state file gates nothing.
fn unprotected_pressure_at(state_path: &Path, mount: &Path) -> Option<UnprotectedMount> {
    let wanted = mount.to_string_lossy();
    fresh_mount_records(state_path)
        .into_iter()
        .find(|record| record.mount == wanted.as_ref())
        .filter(|record| {
            matches!(record.level.as_str(), "orange" | "red" | "critical")
                && unprotected_pressure(record)
        })
        .map(|record| UnprotectedMount {
            level: record.level,
            capability: record.reclaim_capability.as_str().to_string(),
        })
}

/// `doctor --system`: every mount the daemon reports at Yellow or worse
/// must have a reclaim surface and a reserve; each failing mount is its own
/// FAIL with the exact remediation. Without a fresh state file the check
/// is a WARN, since nothing is known.
fn reclaim_capability_doctor_checks(config: &Config) -> Vec<DoctorCheck> {
    let Some(state) = read_fresh_daemon_state(&config.paths.state_file) else {
        return vec![doctor_check(
            "reclaim.capability",
            "Reclaim capability under pressure",
            "WARN",
            format!(
                "no fresh daemon state at {} (daemon not running, or state older than {}s): \
                 per-mount reclaim capability is unknown",
                config.paths.state_file.display(),
                DAEMON_STATE_STALE_THRESHOLD_SECS
            ),
            Some(
                "Start the daemon (`sbh install` / `systemctl start sbh`) and re-run.".to_string(),
            ),
        )];
    };
    let records: Vec<MountStateRecord> = state
        .get("mount_controllers")
        .cloned()
        .and_then(|records| serde_json::from_value(records).ok())
        .unwrap_or_default();
    let mut checks = Vec::new();
    let mut pressured = 0usize;
    for record in &records {
        if record.level == "green" {
            continue;
        }
        pressured += 1;
        if unprotected_pressure(record) {
            checks.push(doctor_check(
                "reclaim.capability",
                "Reclaim capability under pressure",
                "FAIL",
                format!(
                    "{} is at {} and sbh can reclaim nothing there (reclaim_capability={})",
                    record.mount,
                    record.level,
                    record.reclaim_capability.as_str()
                ),
                Some(format!(
                    "Give the daemon a surface on {}: add a `scanner.root_paths` entry on that \
                     device, set `scanner.catalog_roots_on_pressured_device = true` to clean \
                     known-safe caches there, or run `sbh ballast provision` for an \
                     instant-release reserve.",
                    record.mount
                )),
            ));
            continue;
        }
        if let Some(reserve) = record.reserve_state
            && reserve.target_bytes > 0
            && reserve.present_bytes == 0
        {
            checks.push(doctor_check(
                "reclaim.reserve",
                "Ballast reserve under pressure",
                "FAIL",
                format!(
                    "{} is at {} with an empty ballast reserve ({} configured{})",
                    record.mount,
                    record.level,
                    format_bytes(reserve.target_bytes),
                    if reserve.floor_limited {
                        ", provisioning stopped at the headroom floor"
                    } else {
                        ""
                    }
                ),
                Some(
                    "Run `sbh ballast provision`; files are created one at a time while the \
                     volume stays above the headroom floor."
                        .to_string(),
                ),
            ));
        }
    }
    if checks.is_empty() {
        checks.push(doctor_check(
            "reclaim.capability",
            "Reclaim capability under pressure",
            "PASS",
            if pressured == 0 {
                format!(
                    "no mount under pressure ({} mount(s) reported by the daemon)",
                    records.len()
                )
            } else {
                format!(
                    "{pressured} mount(s) under pressure, each with a reclaim surface and a \
                     reserve"
                )
            },
            None,
        ));
    }
    checks
}

/// The daemon's forecast for one mount, as `state.json` v2 `rates` carries it.
#[derive(Debug, Clone, PartialEq)]
struct MountForecast {
    bytes_per_sec: f64,
    accel: f64,
    confidence: f64,
    seconds_to_red: Option<f64>,
    seconds_to_full: Option<f64>,
    /// The conformal lower bound on `seconds_to_red` (`rates.<mount>.forecast.tte_lo_s`).
    tte_lo: Option<f64>,
    /// The daemon's calibration block, passed through to JSON.
    forecast: Option<Value>,
}

impl MountForecast {
    fn from_rate(rate: &Value) -> Option<Self> {
        Some(Self {
            bytes_per_sec: rate.get("bytes_per_sec")?.as_f64()?,
            accel: rate.get("accel").and_then(Value::as_f64).unwrap_or(0.0),
            confidence: rate
                .get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or(0.0),
            seconds_to_red: rate.get("seconds_to_red").and_then(Value::as_f64),
            seconds_to_full: rate.get("seconds_to_full").and_then(Value::as_f64),
            tte_lo: rate
                .get("forecast")
                .and_then(|f| f.get("tte_lo_s"))
                .and_then(Value::as_f64),
            forecast: rate.get("forecast").cloned().filter(|f| !f.is_null()),
        })
    }

    /// The seconds-to-red a decision should use: the conformal lower bound
    /// when the daemon published one, else the point estimate.
    fn acting_seconds_to_red(&self) -> Option<f64> {
        self.tte_lo.or(self.seconds_to_red)
    }

    /// Below the configured confidence the estimator is still warming up:
    /// the numbers are shown but not acted on.
    fn warming(&self, min_confidence: f64) -> bool {
        self.confidence < min_confidence
    }

    fn to_json(&self, min_confidence: f64) -> Value {
        json!({
            "bytes_per_sec": self.bytes_per_sec,
            "accel": self.accel,
            "confidence": self.confidence,
            "seconds_to_red": self.seconds_to_red,
            "seconds_to_red_lo": self.tte_lo,
            "forecast": self.forecast,
            "seconds_to_full": self.seconds_to_full,
            "warming": self.warming(min_confidence),
        })
    }
}

/// What the CLI found when it looked for the daemon's forecast.
#[derive(Debug, Clone, PartialEq)]
enum ForecastRead {
    /// No state file, or one that does not parse.
    Missing,
    /// A state file older than the staleness threshold: its numbers are
    /// history, not a forecast.
    Stale { age_secs: u64 },
    /// Fresh state; `None` when the daemon has no rate entry for the mount.
    Fresh(Option<MountForecast>),
}

impl ForecastRead {
    /// Why there is no usable forecast, for reports.
    fn unknown_reason(&self) -> Option<String> {
        match self {
            Self::Missing => Some("unknown (daemon state missing)".to_string()),
            Self::Stale { age_secs } => Some(format!(
                "unknown (daemon state stale: {age_secs}s old, threshold {DAEMON_STATE_STALE_THRESHOLD_SECS}s)"
            )),
            Self::Fresh(None) => Some("unknown (daemon has no rate for this mount)".to_string()),
            Self::Fresh(Some(_)) => None,
        }
    }
}

/// Read the daemon's forecast for `mount_point` from `state.json` v2.
fn read_daemon_forecast(state_path: &Path, mount_point: &Path) -> ForecastRead {
    let Ok(content) = std::fs::read_to_string(state_path) else {
        return ForecastRead::Missing;
    };
    let age_secs = std::fs::metadata(state_path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .map_or(u64::MAX, |age| age.as_secs());
    if age_secs > DAEMON_STATE_STALE_THRESHOLD_SECS {
        return ForecastRead::Stale { age_secs };
    }
    let Ok(state) = serde_json::from_str::<Value>(&content) else {
        return ForecastRead::Missing;
    };
    let mount_key = mount_point.to_string_lossy();
    ForecastRead::Fresh(
        state
            .get("rates")
            .and_then(Value::as_object)
            .and_then(|rates| rates.get(mount_key.as_ref()))
            .and_then(MountForecast::from_rate),
    )
}

/// One human status line for a mount's forecast.
fn rate_line(mount: &str, forecast: &MountForecast, min_confidence: f64) -> String {
    let bps = forecast.bytes_per_sec;
    let trend = if bps > 0.0 {
        "filling"
    } else if bps < 0.0 {
        "recovering"
    } else {
        "stable"
    };
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let rate_str = if bps.abs() > 0.0 {
        format!(
            "{}{}/s",
            if bps > 0.0 { "+" } else { "-" },
            format_bytes(bps.abs() as u64)
        )
    } else {
        "0 B/s".to_string()
    };
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let accel_str = if forecast.accel.abs() > 0.0 {
        format!(
            "{}{}/s\u{b2}",
            if forecast.accel > 0.0 { "+" } else { "-" },
            format_bytes(forecast.accel.abs() as u64)
        )
    } else {
        "0 B/s\u{b2}".to_string()
    };
    let horizon = match (forecast.tte_lo, forecast.seconds_to_red) {
        (Some(lo), Some(point)) if lo.is_finite() && point.is_finite() && lo < point => {
            format!("red in >={} (point {})", format_eta(lo), format_eta(point))
        }
        (_, Some(secs)) if secs.is_finite() => format!("red in {}", format_eta(secs)),
        _ => "no red horizon".to_string(),
    };
    let status = if forecast.warming(min_confidence) {
        format!(
            "warming (confidence {:.2} < {min_confidence:.2})",
            forecast.confidence
        )
    } else {
        format!("confidence {:.2}", forecast.confidence)
    };
    format!("  {mount:<20}  {rate_str:<12} {trend:<10} accel {accel_str:<12} {horizon}, {status}")
}

/// `42s`, `7m`, `3h 10m`, `2d 4h`.
fn format_eta(secs: f64) -> String {
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let total = secs.max(0.0).round() as u64;
    if total < 60 {
        format!("{total}s")
    } else if total < 3600 {
        format!("{}m", total / 60)
    } else if total < 86_400 {
        format!("{}h {}m", total / 3600, (total % 3600) / 60)
    } else {
        format!("{}d {}h", total / 86_400, (total % 86_400) / 3600)
    }
}

fn parse_lease_duration_seconds(raw: &str) -> std::result::Result<u64, String> {
    let input = raw.trim();
    if input.is_empty() {
        return Err("lease duration must not be empty".to_string());
    }
    let split = input
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(input.len());
    let (number, suffix) = input.split_at(split);
    let value = number
        .parse::<u64>()
        .map_err(|_| "lease duration must begin with a positive integer".to_string())?;
    if value == 0 {
        return Err("lease duration must be positive".to_string());
    }
    let multiplier = match suffix.trim().to_ascii_lowercase().as_str() {
        "s" | "sec" | "secs" | "second" | "seconds" => 1,
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "h" | "hr" | "hrs" | "hour" | "hours" => 60 * 60,
        _ => return Err("lease duration suffix must be seconds, minutes, or hours".to_string()),
    };
    value
        .checked_mul(multiplier)
        .ok_or_else(|| "lease duration is too large".to_string())
}

fn parse_byte_count(raw: &str) -> std::result::Result<u64, String> {
    let input = raw.trim();
    if input.is_empty() {
        return Err("byte count must not be empty".to_string());
    }

    let split = input
        .find(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .unwrap_or(input.len());
    let (number, suffix) = input.split_at(split);
    let suffix = suffix.trim().to_ascii_lowercase();
    let multiplier = match suffix.as_str() {
        "" | "b" | "byte" | "bytes" => 1,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024_u64.pow(2),
        "g" | "gb" | "gib" => 1024_u64.pow(3),
        "t" | "tb" | "tib" => 1024_u64.pow(4),
        _ => {
            return Err(
                "byte count suffix must be one of B, K, M, G, T, KiB, MiB, GiB, or TiB".to_string(),
            );
        }
    };

    parse_decimal_byte_count(number, multiplier)
}

fn parse_decimal_byte_count(number: &str, multiplier: u64) -> std::result::Result<u64, String> {
    if number.is_empty() {
        return Err("byte count is missing a number".to_string());
    }
    if number.bytes().filter(|byte| *byte == b'.').count() > 1 {
        return Err("byte count contains more than one decimal point".to_string());
    }

    let (whole, fractional) = number
        .split_once('.')
        .map_or((number, None), |(whole, fractional)| {
            (whole, Some(fractional))
        });

    if whole.is_empty() && fractional.is_none_or(str::is_empty) {
        return Err("byte count is missing a number".to_string());
    }
    if !whole.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("byte count contains invalid digits".to_string());
    }

    let whole_value = if whole.is_empty() {
        0
    } else {
        whole
            .parse::<u128>()
            .map_err(|_| "byte count is too large".to_string())?
    };
    let multiplier = u128::from(multiplier);
    let mut total = whole_value
        .checked_mul(multiplier)
        .ok_or_else(|| "byte count is too large".to_string())?;

    if let Some(fractional) = fractional
        && !fractional.is_empty()
    {
        if !fractional.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("byte count contains invalid fractional digits".to_string());
        }
        let scale_power = u32::try_from(fractional.len())
            .map_err(|_| "byte count has too many fractional digits".to_string())?;
        let scale = 10_u128
            .checked_pow(scale_power)
            .ok_or_else(|| "byte count has too many fractional digits".to_string())?;
        let fractional_value = fractional
            .parse::<u128>()
            .map_err(|_| "byte count fractional part is too large".to_string())?;
        let fractional_bytes = fractional_value
            .checked_mul(multiplier)
            .ok_or_else(|| "byte count is too large".to_string())?
            / scale;
        total = total
            .checked_add(fractional_bytes)
            .ok_or_else(|| "byte count is too large".to_string())?;
    }

    u64::try_from(total).map_err(|_| "byte count is too large".to_string())
}

#[allow(clippy::too_many_lines)]
fn run_emergency(cli: &Cli, args: &EmergencyArgs) -> Result<(), CliError> {
    let start = std::time::Instant::now();

    // Emergency mode: ZERO disk writes. Use defaults only — no config file.
    let config = Config::default();

    // Determine scan roots: CLI paths, then fall back to defaults.
    // Canonicalize to ensure absolute paths for system protection checks.
    let raw_roots = if args.paths.is_empty() {
        config.scanner.root_paths.clone()
    } else {
        args.paths.clone()
    };

    let root_paths: Vec<PathBuf> = raw_roots
        .into_iter()
        .filter_map(|p| match p.canonicalize() {
            Ok(abs) => Some(abs),
            Err(e) => {
                if output_mode(cli) == OutputMode::Human {
                    eprintln!("Warning: skipping invalid path {}: {}", p.display(), e);
                }
                None
            }
        })
        .collect();

    if root_paths.is_empty() {
        return Err(CliError::User("no valid scan paths found".to_string()));
    }

    // Layer 7: the quarantine is already-decided space. On a critically
    // full disk it goes first, before anything is scanned or scored.
    for root in &root_paths {
        match QuarantineStore::under(root).drain_all() {
            Ok((count, bytes)) if count > 0 => eprintln!(
                "[SBH-EMERGENCY] drained {count} quarantined entr{} ({}) under {}",
                if count == 1 { "y" } else { "ies" },
                format_bytes(bytes),
                root.display()
            ),
            Ok(_) => {}
            Err(e) => eprintln!(
                "[SBH-EMERGENCY] quarantine under {} not drained: {e}",
                root.display()
            ),
        }
    }

    // Marker-only protection: honors .sbh-protect files on disk, no config patterns.
    let protection = ProtectionRegistry::marker_only();

    let walker_config = WalkerConfig {
        root_paths: root_paths.clone(),
        max_depth: config.scanner.max_depth,
        follow_symlinks: false,
        cross_devices: false,
        parallelism: config.scanner.parallelism,
        excluded_paths: config
            .scanner
            .excluded_paths
            .iter()
            .cloned()
            .collect::<HashSet<_>>(),
        opaque_pruning: matches!(config.scanner.engine, ScannerEngineMode::V2),
    };
    let walker = DirectoryWalker::new(walker_config, protection);
    let entries = walker
        .walk()
        .map_err(|e| CliError::Runtime(e.to_string()))?;
    let dir_count = entries.len();

    // Collect active-reference evidence lazily so tiny emergency candidates do
    // not force a global process/fd/mmap probe.
    let active_reference_scan = active_reference_scan_config(&config);
    let mut open_paths = None;
    let mut active_reference_index = None;

    // Classify and score using default weights; the age floor is the flag's,
    // since no config is read.
    let registry = ArtifactPatternRegistry::default();
    let engine = ScoringEngine::from_config(&config.scoring, args.min_age);
    let sacred_paths = active_sacred_paths(&config)?;
    let now = SystemTime::now();

    let scored: Vec<CandidacyScore> = entries
        .iter()
        .map(|entry| {
            let classification = registry.classify(&entry.path, entry.structural_signals);
            let age = now
                .duration_since(
                    entry.effective_age_timestamp(classification.category.is_regenerable_tree()),
                )
                .unwrap_or_default();
            let mut candidate = CandidateInput {
                path: entry.path.clone(),
                size_bytes: entry.metadata.content_size_bytes,
                age,
                classification,
                signals: entry.structural_signals,
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            };
            let cheap_score = engine.score_candidate(&candidate, 0.8);
            if !cheap_score.vetoed && cheap_score.total_score >= config.scoring.min_score {
                candidate.is_open = open_status_for_candidate(
                    &mut open_paths,
                    &root_paths,
                    active_reference_scan,
                    &entry.path,
                    entry.metadata.content_size_bytes,
                );
                let (active_references, _) = active_references_for_candidate(
                    &mut active_reference_index,
                    &root_paths,
                    active_reference_scan,
                    &entry.path,
                    Some(entry.metadata.identity()),
                    entry.metadata.content_size_bytes,
                );
                candidate.active_references = active_references;
            }
            let (mut score, _) = score_candidate_with_deferred_sacred_check(
                &engine,
                &candidate,
                0.8,
                &sacred_paths,
                |base_score| {
                    !base_score.vetoed && base_score.total_score >= config.scoring.min_score
                },
            );
            score.identity = Some(entry.metadata.identity());
            score
        })
        .filter(|score| !score.vetoed)
        .collect();

    let scan_elapsed = start.elapsed();

    // Build deletion plan — no circuit breaker, no logger.
    let deletion_config = DeletionConfig {
        max_batch_size: usize::MAX, // No batch limit in emergency.
        dry_run: false,
        min_score: config.scoring.min_score,
        check_open_files: true,
        require_identity: matches!(config.scanner.engine, ScannerEngineMode::V2),
        circuit_breaker_threshold: u32::MAX, // Effectively disabled.
        // Emergency escalation (#18): also act on `Review`-classified
        // candidates. On a critically full disk a corpus that is 100% Review
        // must not turn the last line of defence into a no-op; the operator
        // still confirms (interactively or via --yes) and every hard safety
        // rail (vetoes, markers, .git/manifest/source/open-file pre-flight)
        // still applies.
        include_review: true,
        sacred_paths,
        ..Default::default()
    };
    let executor = DeletionExecutor::new(deletion_config, None);
    let plan = executor.plan(scored);

    if plan.candidates.is_empty() {
        match output_mode(cli) {
            OutputMode::Human => {
                println!(
                    "Emergency scan: scanned {} directories in {:.1}s — no cleanup candidates found.",
                    dir_count,
                    scan_elapsed.as_secs_f64(),
                );
                eprintln!(
                    "Config-level protections are not active in emergency mode. Only .sbh-protect marker files are honored."
                );
            }
            OutputMode::Json => {
                // Same key set as every other clean/emergency payload so a
                // parser never has to special-case the no-candidate path.
                let payload = json!({
                    "command": "emergency",
                    "scanned_directories": dir_count,
                    "elapsed_seconds": scan_elapsed.as_secs_f64(),
                    "candidates_count": 0,
                    "items_deleted": 0,
                    "items_skipped": 0,
                    "items_failed": 0,
                    "bytes_freed": 0,
                    "dry_run": false,
                    "skipped_by_reason": json!({}),
                    "stalled": false,
                });
                write_json_line(&payload)?;
            }
        }
        // C-EXIT: nothing to reclaim is a successful outcome, as for `clean`.
        return Ok(());
    }

    // Display candidates: the report goes to stdout, the mode banner and
    // its caveats to stderr.
    if output_mode(cli) == OutputMode::Human {
        eprintln!("EMERGENCY MODE — zero-write recovery");
        println!(
            "Scanned {} directories in {:.1}s\n",
            dir_count,
            scan_elapsed.as_secs_f64(),
        );
        eprintln!(
            "Config-level protections are not active in emergency mode. Only .sbh-protect marker files are honored."
        );
        eprintln!(
            "Emergency escalation: Review-classified candidates are eligible for deletion (clean would hold them for manual review).\n"
        );
        println!("Candidates for deletion:\n");
        print_deletion_plan(&plan);
        println!(
            "\nTotal: {} items, {}",
            plan.estimated_items,
            format_bytes(plan.total_reclaimable_bytes),
        );
        println!();
    }

    // Execute based on flags.
    // Non-interactive (piped/cron) MUST pass --yes explicitly to avoid silent mass-deletion.
    if !args.yes && !io::stdout().is_terminal() {
        return Err(CliError::User(
            "emergency mode in non-interactive context requires --yes flag".to_string(),
        ));
    }
    if args.yes {
        let platform = detect_platform().map_err(|e| CliError::Runtime(e.to_string()))?;
        let collector = std::sync::Arc::new(FsStatsCollector::new(
            platform,
            std::time::Duration::from_millis(500),
        ));
        let pressure_check = build_pressure_check(Some(args.target_free), collector);
        let report = executor.execute(
            &plan,
            pressure_check
                .as_ref()
                .map(|f| f as &dyn Fn(&std::path::Path) -> bool),
        );

        match output_mode(cli) {
            OutputMode::Human => {
                print_clean_summary(&report);
                eprintln!(
                    "\nConsider installing sbh for ongoing protection: {}",
                    ongoing_protection_install_hint()
                );
            }
            OutputMode::Json => {
                emit_clean_report_json(
                    &plan,
                    &report,
                    dir_count,
                    scan_elapsed,
                    0,
                    "emergency",
                    None,
                )?;
            }
        }
        // C-EXIT: failed deletions are a partial success (4).
        if report.items_failed > 0 {
            return Err(CliError::Partial(format!(
                "{} of {} deletion(s) failed",
                report.items_failed,
                report.items_failed + report.items_deleted
            )));
        }
    } else {
        // Interactive emergency cleanup.
        run_interactive_emergency(
            cli,
            &executor,
            &plan,
            args,
            &root_paths,
            dir_count,
            scan_elapsed,
        )?;
    }

    Ok(())
}

fn ongoing_protection_install_hint() -> &'static str {
    "sbh install --auto"
}

/// Interactive emergency cleanup — like interactive clean but with emergency messaging.
#[allow(clippy::too_many_lines)]
fn run_interactive_emergency(
    cli: &Cli,
    executor: &DeletionExecutor,
    plan: &DeletionPlan,
    args: &EmergencyArgs,
    _root_paths: &[PathBuf],
    dir_count: usize,
    scan_elapsed: std::time::Duration,
) -> Result<(), CliError> {
    let stdin = io::stdin();
    let mut input = String::new();
    let mut items_deleted: usize = 0;
    let mut skips = InteractiveSkips::default();
    let mut bytes_freed: u64 = 0;
    let mut bytes_quarantined: u64 = 0;
    let mut delete_all = false;

    let platform = detect_platform().map_err(|e| CliError::Runtime(e.to_string()))?;
    let collector = FsStatsCollector::new(platform, std::time::Duration::from_millis(500));

    eprintln!("Proceed with deletion? [y/N/a(ll)/s(kip)/q(uit)]");

    for (i, candidate) in plan.candidates.iter().enumerate() {
        // Check target_free stop condition using the candidate's actual mount point.
        if let Ok(stats) = collector.collect(&candidate.path)
            && stats.free_pct() >= args.target_free
        {
            eprintln!(
                "  Target free space ({:.1}%) achieved. Stopping.",
                args.target_free,
            );
            break;
        }

        let action = if delete_all {
            'y'
        } else {
            let path_str = truncate_path(&candidate.path, 60);
            let size_str = format_bytes(candidate.size_bytes);
            eprint!(
                "  [{}/{}] {} ({}, score {:.2})? ",
                i + 1,
                plan.candidates.len(),
                path_str,
                size_str,
                candidate.total_score,
            );
            io::stderr().flush()?;

            input.clear();
            stdin
                .read_line(&mut input)
                .map_err(|e| CliError::Runtime(e.to_string()))?;
            match input.trim().to_lowercase().as_str() {
                "y" | "yes" => 'y',
                "a" | "all" => {
                    delete_all = true;
                    'y'
                }
                "s" | "skip" => {
                    eprintln!("  Skipping all remaining items.");
                    break;
                }
                "q" | "quit" => {
                    eprintln!("  Quitting.");
                    break;
                }
                _ => 'n',
            }
        };

        if action == 'y' {
            // Route through the executor's full pre-flight veto stack, exactly
            // like the --yes batch path. Emergency escalation (#18) makes
            // Review-classified candidates *eligible*; it promises that every
            // hard safety rail still applies, and this is where the interactive
            // path keeps that promise (source-tree floor, active leases,
            // .git/manifest/source markers, identity, open files).
            let (fresh_open_paths, complete) =
                collect_open_path_ancestors(std::slice::from_ref(&candidate.path));
            // clippy::if_not_else is deliberately allowed here. The negative-first
            // form is load-bearing: it puts the fail-safe (skip) branch ahead of the
            // destructive branch (delete), so the guard is visible before the action
            // when auditing this path. Inverting it to satisfy the lint would bury
            // the safety rail below the deletion it protects.
            #[allow(clippy::if_not_else)]
            if !complete {
                // Fail safe, mirroring the batch executor: if we cannot see
                // which paths are open we cannot prove this one is closed.
                eprintln!(
                    "    Skipped (open-file scan incomplete): {}",
                    candidate.path.display()
                );
                skips.record(storage_ballast_helper::scanner::deletion::SkipReason::FileOpen);
            } else {
                match executor.delete_candidate_checked(candidate, Some(&fresh_open_paths)) {
                    Ok(storage_ballast_helper::scanner::deletion::CheckedDeletion::Deleted) => {
                        items_deleted += 1;
                        bytes_freed += candidate.size_bytes;
                        if !delete_all {
                            eprintln!("    Deleted.");
                        }
                    }
                    Ok(storage_ballast_helper::scanner::deletion::CheckedDeletion::Quarantined) => {
                        items_deleted += 1;
                        bytes_quarantined += candidate.size_bytes;
                        if !delete_all {
                            eprintln!("    Quarantined (restore with `sbh undo`).");
                        }
                    }
                    Ok(storage_ballast_helper::scanner::deletion::CheckedDeletion::Skipped(
                        skip,
                    )) => {
                        eprintln!(
                            "    Skipped ({}): {}",
                            skip.explanation(),
                            candidate.path.display()
                        );
                        skips.record(skip);
                    }
                    Err(e) => {
                        eprintln!("    Failed: {e}");
                    }
                }
            }
        } else {
            skips.record(storage_ballast_helper::scanner::deletion::SkipReason::UserDeclined);
        }
    }

    match output_mode(cli) {
        OutputMode::Human => {
            eprintln!("\nEmergency cleanup complete:");
            eprintln!(
                "  Deleted: {items_deleted} items, {} freed",
                format_bytes(bytes_freed),
            );
            if skips.total > 0 {
                eprintln!("  Skipped: {} items", skips.total);
            }
            eprintln!(
                "\nConsider installing sbh for ongoing protection: {}",
                ongoing_protection_install_hint()
            );
        }
        OutputMode::Json => {
            let payload = json!({
                "command": "emergency",
                "scanned_directories": dir_count,
                "elapsed_seconds": scan_elapsed.as_secs_f64(),
                "candidates_count": plan.estimated_items,
                "items_deleted": items_deleted,
                "bytes_quarantined": bytes_quarantined,
                "items_skipped": skips.total,
                "skipped_by_reason": skips_json(&skips.by_reason),
                // Mirrors DeletionReport::stalled(): work was queued, nothing freed.
                "stalled": items_deleted == 0 && bytes_freed == 0 && skips.total > 0,
                "bytes_freed": bytes_freed,
            });
            write_json_line(&payload)?;
        }
    }

    if items_deleted == 0 {
        return Err(CliError::User(
            "user cancelled — no items deleted".to_string(),
        ));
    }

    Ok(())
}

#[allow(clippy::cast_precision_loss)]
fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    const TIB: u64 = 1024 * GIB;

    if bytes >= TIB {
        format!("{:.1} TiB", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn format_duration(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}

fn truncate_path(path: &std::path::Path, max_len: usize) -> String {
    let s = path.to_string_lossy();
    if s.len() <= max_len {
        s.to_string()
    } else {
        let tail_len = max_len.saturating_sub(3);
        // Find the nearest char boundary from the right.
        let mut start = s.len().saturating_sub(tail_len);
        while start < s.len() && !s.is_char_boundary(start) {
            start += 1;
        }
        format!("...{}", &s[start..])
    }
}

/// The first build-time value that exists, else `unknown`
/// (bd-rc-master-ajg1.5.4): `build.rs` sets the `SBH_BUILD_*` names in
/// every build path it can (git checkout, packager environment,
/// `SOURCE_DATE_EPOCH`); the older names stay honored.
fn build_field<'a>(candidates: &[Option<&'a str>]) -> &'a str {
    candidates
        .iter()
        .flatten()
        .map(|value| value.trim())
        .find(|value| !value.is_empty())
        .unwrap_or("unknown")
}

fn emit_version(cli: &Cli, args: &VersionArgs) -> Result<(), CliError> {
    let version = env!("CARGO_PKG_VERSION");
    let package = env!("CARGO_PKG_NAME");
    let target = build_field(&[option_env!("SBH_BUILD_TARGET"), option_env!("TARGET")]);
    let profile = build_field(&[option_env!("SBH_BUILD_PROFILE"), option_env!("PROFILE")]);
    let git_sha = build_field(&[
        option_env!("SBH_BUILD_GIT_SHA"),
        option_env!("VERGEN_GIT_SHA"),
        option_env!("GIT_SHA"),
    ]);
    let build_timestamp = build_field(&[
        option_env!("SBH_BUILD_TIMESTAMP"),
        option_env!("VERGEN_BUILD_TIMESTAMP"),
        option_env!("BUILD_TIMESTAMP"),
    ]);

    match output_mode(cli) {
        OutputMode::Human => {
            println!("sbh {version}");
            if args.verbose {
                println!("package: {package}");
                println!("target: {target}");
                println!("profile: {profile}");
                println!("git_sha: {git_sha}");
                println!("build_timestamp: {build_timestamp}");
            }
        }
        OutputMode::Json => {
            let payload = json!({
                "binary": "sbh",
                "version": version,
                "package": package,
                "build": {
                    "target": target,
                    "profile": profile,
                    "git_sha": git_sha,
                    "timestamp": build_timestamp,
                }
            });
            write_json_line(&payload)?;
        }
    }
    Ok(())
}

fn write_json_line(payload: &Value) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, payload)?;
    writeln!(stdout)?;
    Ok(())
}

fn output_mode(cli: &Cli) -> OutputMode {
    let env_mode = std::env::var("SBH_OUTPUT_FORMAT").ok();
    resolve_output_mode(cli.json, env_mode.as_deref(), io::stdout().is_terminal())
}

fn resolve_output_mode(json_flag: bool, env_mode: Option<&str>, stdout_is_tty: bool) -> OutputMode {
    if json_flag {
        return OutputMode::Json;
    }

    let fallback = if stdout_is_tty {
        OutputMode::Human
    } else {
        OutputMode::Json
    };

    match env_mode
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("json") => OutputMode::Json,
        Some("human") => OutputMode::Human,
        _ => fallback,
    }
}

// ---------------------------------------------------------------------------
// Update command
// ---------------------------------------------------------------------------

fn build_update_options(
    args: &UpdateArgs,
    config: &Config,
    install_dir: PathBuf,
) -> storage_ballast_helper::cli::update::UpdateOptions {
    storage_ballast_helper::cli::update::UpdateOptions {
        check_only: args.check,
        pinned_version: args.version.clone(),
        force: args.force,
        install_dir,
        no_verify: args.no_verify,
        dry_run: args.dry_run,
        max_backups: args.max_backups,
        metadata_cache_file: config.update.metadata_cache_file.clone(),
        metadata_cache_ttl: std::time::Duration::from_secs(
            config.update.metadata_cache_ttl_seconds,
        ),
        refresh_cache: args.refresh_cache,
        notices_enabled: config.update.notices_enabled,
        offline_bundle_manifest: args.offline.clone(),
    }
}

fn run_update(cli: &Cli, args: &UpdateArgs) -> Result<(), CliError> {
    use storage_ballast_helper::cli::update::{
        BackupStore, default_install_dir, format_backup_list, format_prune_result,
        format_rollback_result, format_update_report, run_update_sequence,
    };

    let install_dir = if args.system {
        default_install_dir(true)
    } else {
        default_install_dir(false)
    };

    let store = BackupStore::open_default();

    // Handle --list-backups.
    if args.list_backups {
        let inventory = store.inventory();
        match output_mode(cli) {
            OutputMode::Human => print!("{}", format_backup_list(&inventory)),
            OutputMode::Json => {
                let payload = serde_json::to_value(&inventory)?;
                write_json_line(&payload)?;
            }
        }
        return Ok(());
    }

    // Handle --rollback.
    if let Some(ref rollback_arg) = args.rollback {
        let snap_id = rollback_arg.as_deref();
        let install_path = install_dir.join("sbh");
        match store.rollback(&install_path, snap_id) {
            Ok(result) => {
                match output_mode(cli) {
                    OutputMode::Human => print!("{}", format_rollback_result(&result)),
                    OutputMode::Json => {
                        let payload = serde_json::to_value(&result)?;
                        write_json_line(&payload)?;
                    }
                }
                if result.success {
                    return Ok(());
                }
                return Err(CliError::Runtime("rollback failed".to_string()));
            }
            Err(e) => return Err(CliError::Runtime(e)),
        }
    }

    // Handle --prune.
    if let Some(keep) = args.prune {
        match store.prune(keep) {
            Ok(result) => {
                match output_mode(cli) {
                    OutputMode::Human => print!("{}", format_prune_result(&result)),
                    OutputMode::Json => {
                        let payload = serde_json::to_value(&result)?;
                        write_json_line(&payload)?;
                    }
                }
                return Ok(());
            }
            Err(e) => return Err(CliError::Runtime(e)),
        }
    }

    // Normal update flow.
    let config = Config::load(cli.config.as_deref()).unwrap_or_default();
    let opts = build_update_options(args, &config, install_dir);

    let mut report = run_update_sequence(&opts);
    maybe_restart_service_after_update(cli, args, &mut report);

    match output_mode(cli) {
        OutputMode::Human => {
            print!("{}", format_update_report(&report));
        }
        OutputMode::Json => {
            let payload = serde_json::to_value(&report)?;
            write_json_line(&payload)?;
        }
    }

    if report.success {
        Ok(())
    } else if report.applied {
        Err(CliError::Runtime(
            "update applied but service restart failed".to_string(),
        ))
    } else {
        Err(CliError::Runtime("update failed".to_string()))
    }
}

fn maybe_restart_service_after_update(cli: &Cli, args: &UpdateArgs, report: &mut UpdateReport) {
    if !report.applied || !report.success {
        return;
    }

    let platform = match detect_platform() {
        Ok(platform) => platform,
        Err(error) => {
            record_update_service_restart_failure(
                report,
                ServiceKind::None,
                "unknown",
                format!("failed to detect service backend after update: {error}"),
            );
            return;
        }
    };

    let Some(service) = resolve_update_service_control(args, platform.service_kind()) else {
        return;
    };

    let manager = match service_manager_for_control(service) {
        Ok(manager) => manager,
        Err(error) => {
            record_update_service_restart_failure(
                report,
                service.kind,
                service.scope_name(),
                error.to_string(),
            );
            return;
        }
    };

    let sudo_command = format_sudo_rerun_command(cli, service.kind);
    let privilege_error = service_system_scope_root_message("restart", service.kind, &sudo_command);
    restart_loaded_service_after_update(
        report,
        service,
        manager.as_ref(),
        running_as_root(),
        &privilege_error,
    );
}

fn restart_loaded_service_after_update(
    report: &mut UpdateReport,
    service: ResolvedServiceControl,
    manager: &dyn ServiceManager,
    running_as_root: bool,
    privilege_error: &str,
) {
    let service_type = service_kind_name(service.kind);
    let scope = service.scope_name();

    match manager.is_loaded() {
        Ok(false) => {
            report.record_service_restart(UpdateServiceRestart::skipped(
                service_type,
                scope,
                "service is not loaded",
            ));
        }
        Ok(true) => {
            if !service.user_scope && !running_as_root {
                record_update_service_restart_failure(
                    report,
                    service.kind,
                    scope,
                    privilege_error.to_string(),
                );
                return;
            }

            match manager.restart() {
                Ok(()) => report
                    .record_service_restart(UpdateServiceRestart::restarted(service_type, scope)),
                Err(error) => record_update_service_restart_failure(
                    report,
                    service.kind,
                    scope,
                    error.to_string(),
                ),
            }
        }
        Err(error) => record_update_service_restart_failure(
            report,
            service.kind,
            scope,
            format!("failed to determine whether service is loaded: {error}"),
        ),
    }
}

fn record_update_service_restart_failure(
    report: &mut UpdateReport,
    service_kind: ServiceKind,
    scope: &str,
    error: String,
) {
    if report.notices_enabled {
        report
            .follow_up
            .push(format!("Service restart failed after update: {error}"));
    }
    report.record_service_restart(UpdateServiceRestart::failed(
        service_kind_name(service_kind),
        scope,
        error,
    ));
    report.success = false;
}

// ---------------------------------------------------------------------------
// Setup command: PATH, completions, verification
// ---------------------------------------------------------------------------

fn run_setup(cli: &Cli, args: &SetupArgs) -> Result<(), CliError> {
    let mode = output_mode(cli);
    let do_path = args.path || args.all;
    let do_completions = !args.completions.is_empty() || args.all;
    let do_verify = args.verify || args.all;

    if !do_path && !do_completions && !do_verify {
        return Err(CliError::User(
            "specify at least one setup step: --path, --completions <shell>, --verify, or --all"
                .to_string(),
        ));
    }

    let bin_dir = resolve_bin_dir(args)?;
    let mut results: Vec<SetupStepResult> = Vec::new();

    // PATH setup.
    if do_path {
        let result = setup_path(&bin_dir, args, mode);
        results.push(result);
    }

    // Completions install.
    if do_completions {
        let shells = if args.all {
            detect_available_shells()
        } else {
            args.completions.clone()
        };
        for shell in &shells {
            let result = setup_completions(*shell, &bin_dir, args.dry_run, mode);
            results.push(result);
        }
    }

    // Verification.
    if do_verify {
        let result = setup_verify(&bin_dir, mode);
        results.push(result);
    }

    // Output results.
    let all_ok = results.iter().all(|r| r.success);
    if mode == OutputMode::Json {
        let output = json!({
            "command": "setup",
            "success": all_ok,
            "dry_run": args.dry_run,
            "bin_dir": bin_dir.to_string_lossy(),
            "steps": results,
        });
        write_json_line(&output)?;
    } else {
        println!();
        if all_ok {
            println!("Setup complete. All steps succeeded.");
        } else {
            let failed: Vec<&str> = results
                .iter()
                .filter(|r| !r.success)
                .map(|r| r.step.as_str())
                .collect();
            println!("Setup completed with errors in: {}", failed.join(", "));
        }
    }

    if all_ok {
        Ok(())
    } else {
        Err(CliError::Partial("some setup steps failed".to_string()))
    }
}

#[derive(Debug, Serialize)]
struct SetupStepResult {
    step: String,
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    remediation: Option<String>,
}

fn resolve_bin_dir(args: &SetupArgs) -> Result<PathBuf, CliError> {
    if let Some(dir) = &args.bin_dir {
        return Ok(dir.clone());
    }

    // Auto-detect from current executable path.
    if let Ok(exe) = std::env::current_exe()
        && let Some(parent) = exe.parent()
    {
        return Ok(parent.to_path_buf());
    }

    // Fallback to ~/.local/bin on Unix.
    #[cfg(unix)]
    {
        if let Ok(home) = std::env::var("HOME") {
            return Ok(PathBuf::from(home).join(".local/bin"));
        }
    }

    Err(CliError::Runtime(
        "cannot determine binary directory; use --bin-dir to specify".to_string(),
    ))
}

#[allow(clippy::too_many_lines)]
fn setup_path(bin_dir: &Path, args: &SetupArgs, mode: OutputMode) -> SetupStepResult {
    let profile_path = args
        .profile
        .as_ref()
        .map_or_else(detect_shell_profile, Clone::clone);

    if mode == OutputMode::Human {
        println!("PATH setup: checking {}", profile_path.display());
    }

    // Check if already in PATH.
    if let Ok(path_var) = std::env::var("PATH") {
        let bin_str = bin_dir.to_string_lossy();
        let already_in_path = path_var
            .split(':')
            .any(|entry| entry.trim_end_matches('/') == bin_str.trim_end_matches('/'));
        if already_in_path {
            if mode == OutputMode::Human {
                println!("  {} is already in PATH", bin_dir.display());
            }
            return SetupStepResult {
                step: "path".to_string(),
                success: true,
                message: format!("{} is already in PATH", bin_dir.display()),
                remediation: None,
            };
        }
    }

    let export_line = format!(
        "\n# Added by sbh setup\nexport PATH=\"{}:$PATH\"\n",
        bin_dir.display()
    );

    if args.dry_run {
        if mode == OutputMode::Human {
            println!(
                "  Would append to {}: {}",
                profile_path.display(),
                export_line.trim()
            );
        }
        return SetupStepResult {
            step: "path".to_string(),
            success: true,
            message: format!(
                "dry-run: would append PATH entry to {}",
                profile_path.display()
            ),
            remediation: None,
        };
    }

    // Check if the profile already contains this exact line (idempotent).
    if let Ok(contents) = std::fs::read_to_string(&profile_path)
        && contents.contains(&format!("export PATH=\"{}:$PATH\"", bin_dir.display()))
    {
        if mode == OutputMode::Human {
            println!("  PATH entry already present in {}", profile_path.display());
        }
        return SetupStepResult {
            step: "path".to_string(),
            success: true,
            message: format!("PATH entry already present in {}", profile_path.display()),
            remediation: None,
        };
    }

    // Back up existing profile.
    let backup_path = profile_path.with_extension("sbh-backup");
    if profile_path.exists() {
        if let Err(e) = std::fs::copy(&profile_path, &backup_path) {
            return SetupStepResult {
                step: "path".to_string(),
                success: false,
                message: format!("failed to back up {}: {e}", profile_path.display()),
                remediation: Some(format!(
                    "Manually add to your shell profile:\n  {}",
                    export_line.trim()
                )),
            };
        }
        if mode == OutputMode::Human {
            println!(
                "  Backed up {} to {}",
                profile_path.display(),
                backup_path.display()
            );
        }
    }

    // Append PATH entry.
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&profile_path)
    {
        Ok(mut file) => {
            if let Err(e) = write!(file, "{export_line}") {
                return SetupStepResult {
                    step: "path".to_string(),
                    success: false,
                    message: format!("failed to write to {}: {e}", profile_path.display()),
                    remediation: Some(format!(
                        "Manually add to your shell profile:\n  {}",
                        export_line.trim()
                    )),
                };
            }
            if mode == OutputMode::Human {
                println!(
                    "  Added {} to PATH in {}",
                    bin_dir.display(),
                    profile_path.display()
                );
                println!(
                    "  Run `source {}` or open a new shell to activate",
                    profile_path.display()
                );
            }
            SetupStepResult {
                step: "path".to_string(),
                success: true,
                message: format!(
                    "added {} to PATH in {}",
                    bin_dir.display(),
                    profile_path.display()
                ),
                remediation: None,
            }
        }
        Err(e) => SetupStepResult {
            step: "path".to_string(),
            success: false,
            message: format!("cannot open {}: {e}", profile_path.display()),
            remediation: Some(format!(
                "Manually add to your shell profile:\n  {}",
                export_line.trim()
            )),
        },
    }
}

fn setup_completions(
    shell: CompletionShell,
    _bin_dir: &Path,
    dry_run: bool,
    mode: OutputMode,
) -> SetupStepResult {
    let step_name = format!("completions-{shell:?}");

    let Some(completion_dir) = shell_completion_dir(shell) else {
        return SetupStepResult {
            step: step_name,
            success: false,
            message: format!("cannot determine completion directory for {shell:?}"),
            remediation: Some(format!(
                "Generate completions manually:\n  sbh completions {shell:?} > <completion-dir>/sbh",
            )),
        };
    };

    let completion_file = match shell {
        CompletionShell::Zsh => completion_dir.join("_sbh"),
        CompletionShell::Fish => completion_dir.join("sbh.fish"),
        _ => completion_dir.join("sbh"),
    };

    if mode == OutputMode::Human {
        println!(
            "Completions ({shell:?}): target {}",
            completion_file.display()
        );
    }

    if dry_run {
        if mode == OutputMode::Human {
            println!(
                "  Would write completion script to {}",
                completion_file.display()
            );
        }
        return SetupStepResult {
            step: step_name,
            success: true,
            message: format!("dry-run: would write to {}", completion_file.display()),
            remediation: None,
        };
    }

    // Generate completion script.
    let mut command = Cli::command();
    let binary_name = command.get_name().to_string();
    let mut buf = Vec::new();
    generate(shell, &mut command, binary_name, &mut buf);

    // Create directory if needed.
    if let Some(parent) = completion_file.parent()
        && !parent.exists()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        return SetupStepResult {
            step: step_name,
            success: false,
            message: format!(
                "cannot create completion directory {}: {e}",
                parent.display()
            ),
            remediation: Some(format!(
                "Generate completions manually:\n  sbh completions {shell:?} > {}",
                completion_file.display()
            )),
        };
    }

    match std::fs::write(&completion_file, &buf) {
        Ok(()) => {
            if mode == OutputMode::Human {
                println!(
                    "  Installed completion script to {}",
                    completion_file.display()
                );
            }
            SetupStepResult {
                step: step_name,
                success: true,
                message: format!(
                    "installed completion script to {}",
                    completion_file.display()
                ),
                remediation: None,
            }
        }
        Err(e) => SetupStepResult {
            step: step_name,
            success: false,
            message: format!(
                "cannot write completion script to {}: {e}",
                completion_file.display()
            ),
            remediation: Some(format!(
                "Generate completions manually:\n  sbh completions {shell:?} > {}",
                completion_file.display()
            )),
        },
    }
}

fn setup_verify(bin_dir: &Path, mode: OutputMode) -> SetupStepResult {
    let binary = bin_dir.join("sbh");

    if mode == OutputMode::Human {
        println!("Verification: checking sbh binary");
    }

    // Check binary exists.
    if !binary.exists() {
        // Try with .exe on Windows.
        let binary_exe = bin_dir.join("sbh.exe");
        if !binary_exe.exists() {
            return SetupStepResult {
                step: "verify".to_string(),
                success: false,
                message: format!("sbh binary not found at {}", binary.display()),
                remediation: Some(format!(
                    "Ensure sbh is installed at {} or specify --bin-dir",
                    bin_dir.display()
                )),
            };
        }
    }

    // Try running sbh --version.
    match std::process::Command::new(&binary)
        .arg("--version")
        .output()
    {
        Ok(output) => {
            if output.status.success() {
                let version_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if mode == OutputMode::Human {
                    println!("  Binary OK: {version_str}");
                }
                SetupStepResult {
                    step: "verify".to_string(),
                    success: true,
                    message: format!("binary verified: {version_str}"),
                    remediation: None,
                }
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                SetupStepResult {
                    step: "verify".to_string(),
                    success: false,
                    message: format!(
                        "sbh --version exited with code {}: {stderr}",
                        output.status.code().unwrap_or(-1)
                    ),
                    remediation: Some(
                        "The binary may be corrupted. Re-run the installer.".to_string(),
                    ),
                }
            }
        }
        Err(e) => SetupStepResult {
            step: "verify".to_string(),
            success: false,
            message: format!("failed to execute sbh: {e}"),
            remediation: Some(format!(
                "Ensure sbh is executable and at {}",
                binary.display()
            )),
        },
    }
}

fn detect_shell_profile() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/root"));
    let home = PathBuf::from(home);

    // Check current SHELL env to pick the right profile.
    let shell = std::env::var("SHELL").unwrap_or_default();

    if shell.ends_with("/zsh") {
        let zdotdir = std::env::var("ZDOTDIR").map_or_else(|_| home.clone(), PathBuf::from);
        return zdotdir.join(".zshrc");
    }

    if shell.ends_with("/fish") {
        return home.join(".config/fish/config.fish");
    }

    // Default to bash: prefer .bashrc (interactive), fall back to .bash_profile.
    let bashrc = home.join(".bashrc");
    if bashrc.exists() {
        return bashrc;
    }
    home.join(".bash_profile")
}

fn detect_available_shells() -> Vec<CompletionShell> {
    let mut shells = Vec::new();

    // Always include bash as fallback.
    shells.push(CompletionShell::Bash);

    if std::process::Command::new("zsh")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        shells.push(CompletionShell::Zsh);
    }

    if std::process::Command::new("fish")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        shells.push(CompletionShell::Fish);
    }

    shells
}

fn shell_completion_dir(shell: CompletionShell) -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let home = PathBuf::from(home);

    match shell {
        CompletionShell::Bash => {
            // User completions in ~/.local/share/bash-completion/completions/.
            Some(home.join(".local/share/bash-completion/completions"))
        }
        CompletionShell::Zsh => {
            // User completions in ~/.local/share/zsh/site-functions/ or first fpath entry.
            Some(home.join(".local/share/zsh/site-functions"))
        }
        CompletionShell::Fish => {
            // User completions in ~/.config/fish/completions/.
            Some(home.join(".config/fish/completions"))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use storage_ballast_helper::core::config::SacredConfig;
    use storage_ballast_helper::platform::pal::{FsStats, MockPlatform, MountPoint, PlatformPaths};
    use storage_ballast_helper::platform::types::{
        FullDiskAccessState, FullDiskAccessStatus, OpenFile, OpenFileKind, OpenFileMode,
        ProcessInfo, ProcessIo,
    };
    use tempfile::TempDir;

    struct FakeServiceManager {
        loaded: std::result::Result<bool, &'static str>,
        restart: std::result::Result<(), &'static str>,
        restart_calls: AtomicUsize,
    }

    impl FakeServiceManager {
        fn new(
            loaded: std::result::Result<bool, &'static str>,
            restart: std::result::Result<(), &'static str>,
        ) -> Self {
            Self {
                loaded,
                restart,
                restart_calls: AtomicUsize::new(0),
            }
        }

        fn restart_calls(&self) -> usize {
            self.restart_calls.load(Ordering::SeqCst)
        }
    }

    impl ServiceManager for FakeServiceManager {
        fn install(&self) -> storage_ballast_helper::core::errors::Result<()> {
            Ok(())
        }

        fn uninstall(&self) -> storage_ballast_helper::core::errors::Result<()> {
            Ok(())
        }

        fn status(&self) -> storage_ballast_helper::core::errors::Result<String> {
            Ok("test".to_string())
        }

        fn restart(&self) -> storage_ballast_helper::core::errors::Result<()> {
            self.restart_calls.fetch_add(1, Ordering::SeqCst);
            self.restart.map_err(|details| {
                storage_ballast_helper::core::errors::SbhError::Runtime {
                    details: details.to_string(),
                }
            })
        }

        fn is_loaded(&self) -> storage_ballast_helper::core::errors::Result<bool> {
            self.loaded.map_err(
                |details| storage_ballast_helper::core::errors::SbhError::Runtime {
                    details: details.to_string(),
                },
            )
        }
    }

    fn applied_update_report() -> UpdateReport {
        UpdateReport {
            current_version: "0.1.0".to_string(),
            target_version: Some("v0.2.0".to_string()),
            update_available: true,
            applied: true,
            check_only: false,
            dry_run: false,
            artifact_url: None,
            notices_enabled: true,
            install_path: None,
            backup_id: None,
            steps: Vec::new(),
            success: true,
            follow_up: Vec::new(),
            service_restart: None,
        }
    }

    fn blame_process(
        pid: i32,
        parent_pid: Option<i32>,
        name: &str,
        command_line: Vec<&str>,
        start_time_unix_ms: Option<i64>,
    ) -> ProcessInfo {
        ProcessInfo {
            pid,
            parent_pid,
            name: name.to_string(),
            command_line: command_line.into_iter().map(str::to_string).collect(),
            executable: Some(PathBuf::from(format!("/usr/bin/{name}"))),
            cwd: Some(PathBuf::from(format!("/tmp/{name}"))),
            start_time_unix_ms,
            virtual_memory_bytes: None,
            resident_memory_bytes: None,
            cpu_user_micros: None,
            cpu_system_micros: None,
        }
    }

    fn blame_io(pid: i32, bytes_read_total: u64, bytes_written_total: u64) -> ProcessIo {
        ProcessIo {
            pid,
            bytes_read_total,
            bytes_written_total,
            bytes_read_recent_15m: None,
            bytes_written_recent_15m: None,
        }
    }

    #[test]
    fn parses_global_flags_before_and_after_subcommand() {
        let before = Cli::try_parse_from([
            "sbh",
            "--config",
            "/tmp/sbh.toml",
            "--json",
            "--no-color",
            "-v",
            "status",
        ]);
        assert!(before.is_ok());

        let after = Cli::try_parse_from(["sbh", "status", "--json", "--no-color", "-v"]);
        assert!(after.is_ok());
    }

    #[test]
    fn parses_extended_subcommands() {
        let cases = [
            vec!["sbh", "emergency", "/data", "--target-free", "12", "--yes"],
            vec!["sbh", "protect", "--list"],
            vec!["sbh", "protect", "/data/projects/critical"],
            vec!["sbh", "unprotect", "/data/projects/critical"],
            vec![
                "sbh",
                "lease",
                "run",
                "--target",
                "/data/tmp/leased-build",
                "--max-bytes",
                "32G",
                "--ttl",
                "45m",
                "--",
                "cargo",
                "test",
            ],
            vec!["sbh", "lease", "renew", "--extend", "30m"],
            vec![
                "sbh",
                "lease",
                "status",
                "--target",
                "/data/tmp/leased-build",
            ],
            vec!["sbh", "tune", "--apply"],
            vec!["sbh", "check", "/data", "--target-free", "20"],
            vec!["sbh", "scan", "/tmp", "--explain", "--top", "5"],
            vec!["sbh", "blame", "--top", "10"],
            vec!["sbh", "dashboard", "--refresh-ms", "250"],
            vec!["sbh", "dashboard", "--new-dashboard"],
            vec!["sbh", "dashboard", "--legacy-dashboard"],
            vec!["sbh", "doctor", "--pal"],
            vec!["sbh", "doctor", "--release"],
            vec!["sbh", "doctor", "--pal", "--release"],
            vec!["sbh", "service", "status"],
            vec!["sbh", "service", "--launchd", "--scope", "user", "status"],
            vec![
                "sbh",
                "service",
                "--systemd",
                "--scope",
                "system",
                "restart",
            ],
            vec!["sbh", "service", "logs", "-n", "10"],
            vec!["sbh", "ballast", "status"],
            vec!["sbh", "ballast", "release", "2"],
            vec!["sbh", "config", "path"],
            vec!["sbh", "config", "set", "policy.mode", "observe"],
            vec!["sbh", "version", "--verbose"],
        ];

        for case in &cases {
            let parsed = Cli::try_parse_from(case.iter().copied());
            assert!(parsed.is_ok(), "failed to parse case: {case:?}");
        }
    }

    #[test]
    fn check_command_parses_documented_need_suffixes() {
        let parsed = Cli::try_parse_from(["sbh", "check", "/tmp", "--need", "5G"])
            .expect("documented --need suffix should parse");

        let Command::Check(args) = parsed.command else {
            panic!("expected check command");
        };
        assert_eq!(args.need, Some(5 * 1024_u64.pow(3)));
    }

    #[test]
    fn parse_byte_count_accepts_binary_suffixes_and_decimals() {
        let cases = [
            ("0", 0),
            ("1024", 1024),
            ("1K", 1024),
            ("1kb", 1024),
            ("1KiB", 1024),
            ("2M", 2 * 1024_u64.pow(2)),
            ("1.5G", 1_610_612_736),
            ("5 GB", 5 * 1024_u64.pow(3)),
            ("2TiB", 2 * 1024_u64.pow(4)),
        ];

        for (input, expected) in cases {
            let parsed = parse_byte_count(input).unwrap_or_else(|err| panic!("{input:?}: {err}"));
            assert_eq!(parsed, expected, "input={input:?}");
        }
    }

    #[test]
    fn parse_byte_count_rejects_invalid_inputs() {
        for input in [
            "",
            "G",
            "1XB",
            "1.2.3G",
            "1G extra",
            "18446744073709551616T",
        ] {
            assert!(
                parse_byte_count(input).is_err(),
                "input should be rejected: {input:?}"
            );
        }
    }

    #[test]
    fn parse_lease_duration_is_exact_and_bounded_arithmetically() {
        assert_eq!(parse_lease_duration_seconds("45m").unwrap(), 2700);
        assert_eq!(parse_lease_duration_seconds("2 hours").unwrap(), 7200);
        assert_eq!(parse_lease_duration_seconds("30s").unwrap(), 30);
        for invalid in ["", "0m", "1", "1d", "1.5h", "18446744073709551615h"] {
            assert!(
                parse_lease_duration_seconds(invalid).is_err(),
                "invalid duration accepted: {invalid}"
            );
        }
    }

    #[test]
    fn lease_run_requires_a_fresh_target_budget_and_command_boundary() {
        assert!(
            Cli::try_parse_from([
                "sbh",
                "lease",
                "run",
                "--target",
                "/data/tmp/leased-build",
                "--max-bytes",
                "4G",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "sbh",
                "lease",
                "run",
                "--target",
                "/data/tmp/leased-build",
                "--max-bytes",
                "0",
                "--",
                "cargo",
                "check",
            ])
            .is_ok(),
            "clap accepts the shape; the product policy rejects a zero reservation"
        );
    }

    #[test]
    fn pal_doctor_report_includes_full_disk_access_status_detail() {
        let platform = MockPlatform::healthy().with_full_disk_access_status(FullDiskAccessStatus {
            state: FullDiskAccessState::Missing,
            probe_path: Some("/Users/me/Library/Mail/V10/MailData/Envelope Index".into()),
            detail: "permission denied while reading Mail Envelope Index".to_string(),
            cache_ttl_seconds: 60,
            cached: true,
        });

        let report = pal_doctor_report(&platform);
        let probe = report
            .methods
            .iter()
            .find(|probe| probe.method == "full_disk_access_status")
            .expect("FDA probe should be reported");

        assert_eq!(probe.status, "implemented");
        assert!(probe.message.as_deref().is_some_and(|message| {
            message.contains("missing") && message.contains("cached: true")
        }));
        assert_eq!(report.follow_up.len(), 1);
        assert_eq!(report.follow_up[0].id, "macos_full_disk_access");
        assert!(
            report.follow_up[0]
                .steps
                .iter()
                .any(|step| step.contains(".local/bin/sbh"))
        );
    }

    #[test]
    fn pal_doctor_report_omits_full_disk_access_follow_up_when_granted() {
        let platform = MockPlatform::healthy().with_full_disk_access_status(FullDiskAccessStatus {
            state: FullDiskAccessState::Granted,
            probe_path: Some("/Users/me/Library/Mail/V10/MailData/Envelope Index".into()),
            detail: "Mail Envelope Index was readable".to_string(),
            cache_ttl_seconds: 60,
            cached: false,
        });

        let report = pal_doctor_report(&platform);

        assert!(report.follow_up.is_empty());
    }

    fn macos_doctor_mock(available_bytes: u64, fda_state: FullDiskAccessState) -> MockPlatform {
        let mount = PathBuf::from("/");
        let stats = FsStats {
            total_bytes: 2 * 1024 * 1024 * 1024,
            free_bytes: available_bytes,
            available_bytes,
            fs_type: "apfs".to_string(),
            mount_point: mount.clone(),
            is_readonly: false,
        };
        let mut stats_by_mount = HashMap::new();
        stats_by_mount.insert(mount.clone(), stats);
        MockPlatform::new(
            vec![MountPoint {
                path: mount,
                device: "/dev/disk3s5".to_string(),
                fs_type: "apfs".to_string(),
                is_ram_backed: false,
            }],
            stats_by_mount,
            MemoryInfo {
                total_bytes: 8 * 1024 * 1024 * 1024,
                available_bytes: 4 * 1024 * 1024 * 1024,
                swap_total_bytes: 1024 * 1024 * 1024,
                swap_free_bytes: 1024 * 1024 * 1024,
            },
            PlatformPaths {
                ballast_dir: PathBuf::from("/Users/me/Library/Application Support/sbh/ballast.bin"),
                state_file: PathBuf::from("/Users/me/Library/Application Support/sbh/state.json"),
                sqlite_db: PathBuf::from(
                    "/Users/me/Library/Application Support/sbh/activity.sqlite3",
                ),
                jsonl_log: PathBuf::from(
                    "/Users/me/Library/Application Support/sbh/activity.jsonl",
                ),
            },
        )
        .with_name("macos")
        .with_service_kind(ServiceKind::Launchd)
        .with_home("/Users/me")
        .with_full_disk_access_status(FullDiskAccessStatus {
            state: fda_state,
            probe_path: Some("/Users/me/Library/Mail/V10/MailData/Envelope Index".into()),
            detail: "test FDA detail".to_string(),
            cache_ttl_seconds: 60,
            cached: false,
        })
    }

    fn check_by_id<'a>(report: &'a PalDoctorReport, id: &str) -> &'a DoctorCheck {
        report
            .checks
            .iter()
            .find(|check| check.id == id)
            .expect("doctor check should be present")
    }

    fn release_check_by_id<'a>(report: &'a ReleaseDoctorReport, id: &str) -> &'a DoctorCheck {
        report
            .checks
            .iter()
            .find(|check| check.id == id)
            .expect("release doctor check should be present")
    }

    #[test]
    fn writeback_tuning_none_when_platform_unsupported() {
        // MockPlatform inherits the trait default for writeback_state (returns a
        // not-implemented PAL error), so no recommendation should be produced.
        let platform = MockPlatform::healthy();
        let config = Config::default();
        assert!(build_writeback_tuning(&config, &platform, false).is_none());
    }

    #[test]
    fn writeback_doctor_check_not_applicable_on_unsupported_platform() {
        let platform = MockPlatform::healthy();
        let config = Config::default();
        let check = writeback_doctor_check(&platform, &config);
        assert_eq!(check.id, "system.writeback_tuning");
        assert_eq!(check.status, "PASS");
        assert!(check.message.contains("not applicable"));
    }

    #[test]
    fn writeback_doctor_check_reports_disabled() {
        let platform = MockPlatform::healthy();
        let mut config = Config::default();
        config.system_tuning.writeback_enabled = false;
        let check = writeback_doctor_check(&platform, &config);
        assert_eq!(check.status, "PASS");
        assert!(check.message.contains("disabled"));
    }

    fn args_start_with(args: &[String], prefix: &[&str]) -> bool {
        args.len() >= prefix.len()
            && args
                .iter()
                .zip(prefix.iter())
                .all(|(arg, expected)| arg.as_str() == *expected)
    }

    #[test]
    fn pal_doctor_report_includes_macos_specific_checks() {
        let platform = macos_doctor_mock(2 * 1024 * 1024 * 1024, FullDiskAccessState::Granted);
        let passing_command = |_program: &str, _args: &[String]| {
            Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: "accepted".to_string(),
                stderr: String::new(),
            })
        };

        let report = pal_doctor_report_with_command_runner(&platform, &passing_command);

        assert_eq!(report.checks.len(), 6);
        assert_eq!(check_by_id(&report, "macos.codesign").status, "PASS");
        assert_eq!(check_by_id(&report, "macos.spctl").status, "PASS");
        assert_eq!(
            check_by_id(&report, "macos.full_disk_access").status,
            "PASS"
        );
        assert_eq!(check_by_id(&report, "macos.apfs").status, "PASS");
        assert_eq!(
            check_by_id(&report, "macos.state_free_space").status,
            "PASS"
        );
        assert_eq!(check_by_id(&report, "macos.launchd").status, "WARN");
        assert!(
            check_by_id(&report, "macos.launchd")
                .remediation
                .as_deref()
                .is_some_and(|message| message.contains("sbh install --launchd"))
        );
    }

    #[test]
    fn pal_doctor_report_flags_macos_remediation_failures() {
        let platform = macos_doctor_mock(512 * 1024 * 1024, FullDiskAccessState::Missing);
        let rejected_command = |_program: &str, _args: &[String]| {
            Ok(DoctorCommandOutcome {
                success: false,
                exit_code: Some(1),
                stdout: String::new(),
                stderr: "rejected".to_string(),
            })
        };

        let report = pal_doctor_report_with_command_runner(&platform, &rejected_command);

        assert_eq!(check_by_id(&report, "macos.codesign").status, "WARN");
        assert_eq!(check_by_id(&report, "macos.spctl").status, "WARN");
        assert_eq!(
            check_by_id(&report, "macos.full_disk_access").status,
            "FAIL"
        );
        assert_eq!(
            check_by_id(&report, "macos.state_free_space").status,
            "WARN"
        );
        assert!(
            check_by_id(&report, "macos.full_disk_access")
                .remediation
                .as_deref()
                .is_some_and(|message| message.contains("Full Disk Access"))
        );
    }

    #[test]
    fn release_doctor_report_passes_when_credentials_are_present() {
        let secrets = RELEASE_DOCTOR_REQUIRED_GITHUB_SECRETS
            .iter()
            .map(|name| json!({ "name": name }))
            .collect::<Vec<_>>();
        let secrets_json = serde_json::to_string(&secrets).unwrap();
        let command = |program: &str, args: &[String]| match program {
            "security" => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: "1) ABCDEF \"Developer ID Application: Example LLC (TEAMID)\"".to_string(),
                stderr: String::new(),
            }),
            "xcrun" => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: "{\"history\":[]}".to_string(),
                stderr: String::new(),
            }),
            "gh" if args_start_with(args, &["secret", "list"]) => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: secrets_json.clone(),
                stderr: String::new(),
            }),
            "gh" if args_start_with(args, &["repo", "view"]) => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: json!({
                    "nameWithOwner": RELEASE_HOMEBREW_TAP_REPOSITORY,
                    "defaultBranchRef": { "name": "main" }
                })
                .to_string(),
                stderr: String::new(),
            }),
            "gh" if args_start_with(args, &["api"]) => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: "sbh.rb\n".to_string(),
                stderr: String::new(),
            }),
            other => panic!("unexpected release doctor command: {other}"),
        };

        let report = release_doctor_report_with_command_runner(&command);

        assert!(report.ok);
        assert_eq!(report.passed, 4);
        assert_eq!(report.warnings, 0);
        assert_eq!(report.failed, 0);
        assert_eq!(release_readiness_label(&report), "ready");
        assert_eq!(report.repository, RELEASE_REPOSITORY);
        assert_eq!(report.notary_profile, RELEASE_DOCTOR_NOTARY_PROFILE);
        assert!(report.checks.iter().all(|check| check.status == "PASS"));
        let setup_ids = report
            .setup_steps
            .iter()
            .map(|step| step.id)
            .collect::<Vec<_>>();
        assert_eq!(
            setup_ids,
            vec![
                "developer_id_csr",
                "developer_id_certificate",
                "notary_credentials",
                "homebrew_tap_deploy_key"
            ]
        );
    }

    #[test]
    fn release_doctor_report_flags_missing_external_credentials() {
        let command = |program: &str, args: &[String]| match program {
            "security" => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: "0 valid identities found".to_string(),
                stderr: String::new(),
            }),
            "xcrun" => Ok(DoctorCommandOutcome {
                success: false,
                exit_code: Some(1),
                stdout: String::new(),
                stderr: "No Keychain password item found for profile: sbh-notary".to_string(),
            }),
            "gh" if args_start_with(args, &["secret", "list"]) => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: "[]".to_string(),
                stderr: String::new(),
            }),
            "gh" if args_start_with(args, &["repo", "view"]) => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: json!({
                    "nameWithOwner": RELEASE_HOMEBREW_TAP_REPOSITORY,
                    "defaultBranchRef": { "name": "main" }
                })
                .to_string(),
                stderr: String::new(),
            }),
            "gh" if args_start_with(args, &["api"]) => Ok(DoctorCommandOutcome {
                success: false,
                exit_code: Some(1),
                stdout: String::new(),
                stderr: "Not Found".to_string(),
            }),
            other => panic!("unexpected release doctor command: {other}"),
        };

        let report = release_doctor_report_with_command_runner(&command);

        assert!(!report.ok);
        assert_eq!(report.passed, 0);
        assert_eq!(report.warnings, 1);
        assert_eq!(report.failed, 3);
        assert_eq!(release_readiness_label(&report), "blocked");
        assert_eq!(
            release_check_by_id(&report, "release.developer_id_identity").status,
            "FAIL"
        );
        assert!(
            release_check_by_id(&report, "release.developer_id_identity")
                .message
                .contains("0 valid identities found")
        );
        assert_eq!(
            release_check_by_id(&report, "release.notary_profile").status,
            "FAIL"
        );
        assert!(
            release_check_by_id(&report, "release.notary_profile")
                .message
                .contains("No Keychain password item")
        );
        let secrets = release_check_by_id(&report, "release.github_secrets");
        assert_eq!(secrets.status, "FAIL");
        assert!(
            secrets
                .message
                .contains("APPLE_DEVELOPER_ID_CERTIFICATE_P12_BASE64")
        );
        assert!(secrets.message.contains("APPLE_NOTARY_KEY_P8_BASE64"));
        assert!(secrets.message.contains("HOMEBREW_TAP_SSH_KEY"));
        let tap = release_check_by_id(&report, "release.homebrew_tap");
        assert_eq!(tap.status, "WARN");
        assert!(
            tap.message.contains("Formula/sbh.rb is not published yet"),
            "tap warning should explain missing formula: {}",
            tap.message
        );
    }

    #[test]
    fn release_doctor_report_fails_when_configured_developer_id_identity_is_absent() {
        let secrets = RELEASE_DOCTOR_REQUIRED_GITHUB_SECRETS
            .iter()
            .map(|name| json!({ "name": name }))
            .collect::<Vec<_>>();
        let secrets_json = serde_json::to_string(&secrets).unwrap();
        let command = |program: &str, args: &[String]| match program {
            "security" => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: "1) ABCDEF \"Developer ID Application: Other LLC (OTHERID)\"".to_string(),
                stderr: String::new(),
            }),
            "xcrun" => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: "{\"history\":[]}".to_string(),
                stderr: String::new(),
            }),
            "gh" if args_start_with(args, &["secret", "list"]) => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: secrets_json.clone(),
                stderr: String::new(),
            }),
            "gh" if args_start_with(args, &["repo", "view"]) => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: json!({
                    "nameWithOwner": RELEASE_HOMEBREW_TAP_REPOSITORY,
                    "defaultBranchRef": { "name": "main" }
                })
                .to_string(),
                stderr: String::new(),
            }),
            "gh" if args_start_with(args, &["api"]) => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: "sbh.rb\n".to_string(),
                stderr: String::new(),
            }),
            other => panic!("unexpected release doctor command: {other}"),
        };

        let report = release_doctor_report_with_command_runner_and_env(&command, &|key| {
            (key == "APPLE_DEVELOPER_ID_IDENTITY")
                .then(|| "Developer ID Application: Example LLC (TEAMID)".to_string())
        });

        assert!(!report.ok);
        assert_eq!(report.passed, 3);
        assert_eq!(report.warnings, 0);
        assert_eq!(report.failed, 1);
        assert_eq!(release_readiness_label(&report), "blocked");
        let identity = release_check_by_id(&report, "release.developer_id_identity");
        assert_eq!(identity.status, "FAIL");
        assert!(
            identity
                .message
                .contains("configured APPLE_DEVELOPER_ID_IDENTITY"),
            "identity failure should name the mismatched configured identity: {}",
            identity.message
        );
    }

    #[test]
    fn release_doctor_report_uses_ci_secret_presence_flags_before_gh_secret_list() {
        let mut env = RELEASE_DOCTOR_REQUIRED_GITHUB_SECRETS
            .iter()
            .map(|secret| (release_secret_presence_env_key(secret), "true".to_string()))
            .collect::<HashMap<_, _>>();
        env.insert(
            release_secret_presence_env_key("HOMEBREW_TAP_SSH_KEY"),
            "false".to_string(),
        );

        let command = |program: &str, args: &[String]| match program {
            "security" => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: "1) ABCDEF \"Developer ID Application: Example LLC (TEAMID)\"".to_string(),
                stderr: String::new(),
            }),
            "xcrun" => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: "{\"history\":[]}".to_string(),
                stderr: String::new(),
            }),
            "gh" if args_start_with(args, &["secret", "list"]) => {
                panic!("CI secret presence flags should avoid gh secret list")
            }
            "gh" if args_start_with(args, &["repo", "view"]) => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: json!({
                    "nameWithOwner": RELEASE_HOMEBREW_TAP_REPOSITORY,
                    "defaultBranchRef": { "name": "main" }
                })
                .to_string(),
                stderr: String::new(),
            }),
            "gh" if args_start_with(args, &["api"]) => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: "sbh.rb\n".to_string(),
                stderr: String::new(),
            }),
            other => panic!("unexpected release doctor command: {other}"),
        };

        let report = release_doctor_report_with_command_runner_and_env(&command, &|key| {
            env.get(key).cloned()
        });

        assert!(!report.ok);
        assert_eq!(report.passed, 3);
        assert_eq!(report.warnings, 0);
        assert_eq!(report.failed, 1);
        let secrets = release_check_by_id(&report, "release.github_secrets");
        assert_eq!(secrets.status, "FAIL");
        assert!(secrets.message.contains("CI secret presence flags"));
        assert!(secrets.message.contains("HOMEBREW_TAP_SSH_KEY"));
    }

    #[test]
    fn release_doctor_report_rejects_invalid_ci_secret_presence_flags() {
        let env = std::iter::once((
            release_secret_presence_env_key("HOMEBREW_TAP_SSH_KEY"),
            "maybe".to_string(),
        ))
        .collect::<HashMap<_, _>>();

        let command = |program: &str, args: &[String]| match program {
            "security" => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: "1) ABCDEF \"Developer ID Application: Example LLC (TEAMID)\"".to_string(),
                stderr: String::new(),
            }),
            "xcrun" => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: "{\"history\":[]}".to_string(),
                stderr: String::new(),
            }),
            "gh" if args_start_with(args, &["secret", "list"]) => {
                panic!("invalid CI secret presence flags should avoid gh secret list")
            }
            "gh" if args_start_with(args, &["repo", "view"]) => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: json!({
                    "nameWithOwner": RELEASE_HOMEBREW_TAP_REPOSITORY,
                    "defaultBranchRef": { "name": "main" }
                })
                .to_string(),
                stderr: String::new(),
            }),
            "gh" if args_start_with(args, &["api"]) => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: "sbh.rb\n".to_string(),
                stderr: String::new(),
            }),
            other => panic!("unexpected release doctor command: {other}"),
        };

        let report = release_doctor_report_with_command_runner_and_env(&command, &|key| {
            env.get(key).cloned()
        });

        assert!(!report.ok);
        let secrets = release_check_by_id(&report, "release.github_secrets");
        assert_eq!(secrets.status, "FAIL");
        assert!(secrets.message.contains("must be true or false"));
    }

    #[test]
    fn release_doctor_report_marks_missing_homebrew_formula_as_attention() {
        let secrets = RELEASE_DOCTOR_REQUIRED_GITHUB_SECRETS
            .iter()
            .map(|name| json!({ "name": name }))
            .collect::<Vec<_>>();
        let secrets_json = serde_json::to_string(&secrets).unwrap();
        let command = |program: &str, args: &[String]| match program {
            "security" => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: "1) ABCDEF \"Developer ID Application: Example LLC (TEAMID)\"".to_string(),
                stderr: String::new(),
            }),
            "xcrun" => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: "{\"history\":[]}".to_string(),
                stderr: String::new(),
            }),
            "gh" if args_start_with(args, &["secret", "list"]) => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: secrets_json.clone(),
                stderr: String::new(),
            }),
            "gh" if args_start_with(args, &["repo", "view"]) => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: json!({
                    "nameWithOwner": RELEASE_HOMEBREW_TAP_REPOSITORY,
                    "defaultBranchRef": { "name": "main" }
                })
                .to_string(),
                stderr: String::new(),
            }),
            "gh" if args_start_with(args, &["api"]) => Ok(DoctorCommandOutcome {
                success: false,
                exit_code: Some(1),
                stdout: String::new(),
                stderr: "Not Found".to_string(),
            }),
            other => panic!("unexpected release doctor command: {other}"),
        };

        let report = release_doctor_report_with_command_runner(&command);

        assert!(!report.ok);
        assert_eq!(report.passed, 3);
        assert_eq!(report.warnings, 1);
        assert_eq!(report.failed, 0);
        assert_eq!(release_readiness_label(&report), "attention");
        let tap = release_check_by_id(&report, "release.homebrew_tap");
        assert_eq!(tap.status, "WARN");
        assert!(
            tap.message.contains("Formula/sbh.rb is not published yet"),
            "tap warning should explain missing formula: {}",
            tap.message
        );
    }

    #[test]
    fn release_doctor_report_fails_when_homebrew_tap_default_branch_is_not_main() {
        let secrets = RELEASE_DOCTOR_REQUIRED_GITHUB_SECRETS
            .iter()
            .map(|name| json!({ "name": name }))
            .collect::<Vec<_>>();
        let secrets_json = serde_json::to_string(&secrets).unwrap();
        let command = |program: &str, args: &[String]| match program {
            "security" => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: "1) ABCDEF \"Developer ID Application: Example LLC (TEAMID)\"".to_string(),
                stderr: String::new(),
            }),
            "xcrun" => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: "{\"history\":[]}".to_string(),
                stderr: String::new(),
            }),
            "gh" if args_start_with(args, &["secret", "list"]) => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: secrets_json.clone(),
                stderr: String::new(),
            }),
            "gh" if args_start_with(args, &["repo", "view"]) => Ok(DoctorCommandOutcome {
                success: true,
                exit_code: Some(0),
                stdout: json!({
                    "nameWithOwner": RELEASE_HOMEBREW_TAP_REPOSITORY,
                    "defaultBranchRef": { "name": "legacy-default" }
                })
                .to_string(),
                stderr: String::new(),
            }),
            "gh" if args_start_with(args, &["api"]) => {
                panic!("formula check should not run after a default-branch failure")
            }
            other => panic!("unexpected release doctor command: {other}"),
        };

        let report = release_doctor_report_with_command_runner(&command);

        assert!(!report.ok);
        assert_eq!(report.passed, 3);
        assert_eq!(report.warnings, 0);
        assert_eq!(report.failed, 1);
        assert_eq!(release_readiness_label(&report), "blocked");
        let tap = release_check_by_id(&report, "release.homebrew_tap");
        assert_eq!(tap.status, "FAIL");
        assert!(
            tap.message
                .contains("default branch is legacy-default, expected main"),
            "tap failure should explain default branch mismatch: {}",
            tap.message
        );
    }

    #[test]
    fn doctor_checks_have_failures_detects_fail_status_only() {
        let checks = vec![
            doctor_check("doctor.pass", "Passing check", "PASS", "ok", None),
            doctor_check("doctor.warn", "Warning check", "WARN", "warn", None),
        ];
        assert!(!doctor_checks_have_failures(&checks));

        let checks = vec![
            doctor_check("doctor.pass", "Passing check", "PASS", "ok", None),
            doctor_check("doctor.fail", "Failing check", "FAIL", "fail", None),
        ];
        assert!(doctor_checks_have_failures(&checks));
    }

    #[test]
    fn release_doctor_setup_plan_uses_stdin_secrets_and_rechecks() {
        let steps = release_doctor_setup_steps();
        let all_commands = steps
            .iter()
            .flat_map(|step| step.commands.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");

        for required in [
            "export CSR_PATH=\"$HOME/Desktop/sbh-developer-id.certSigningRequest\"",
            "certtool r \"$CSR_PATH\" u",
            "certtool V \"$CSR_PATH\"",
            "open https://developer.apple.com/account/resources/certificates/add",
            "security find-identity -v -p codesigning",
            "base64 < \"$P12_PATH\" | gh secret set APPLE_DEVELOPER_ID_CERTIFICATE_P12_BASE64",
            "printf '%s' \"$P12_PASSWORD\" | gh secret set APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD",
            "printf '%s' \"$DEVELOPER_ID_IDENTITY\" | gh secret set APPLE_DEVELOPER_ID_IDENTITY",
            "xcrun notarytool store-credentials sbh-notary",
            "base64 < \"$APPLE_NOTARY_KEY_PATH\" | gh secret set APPLE_NOTARY_KEY_P8_BASE64",
            "printf '%s' \"$APPLE_NOTARY_KEY_ID\" | gh secret set APPLE_NOTARY_KEY_ID",
            "printf '%s' \"$APPLE_NOTARY_ISSUER_ID\" | gh secret set APPLE_NOTARY_ISSUER_ID",
            "ssh-keygen -t ed25519 -C \"sbh Homebrew tap release\"",
            "gh api -X POST repos/Dicklesworthstone/homebrew-sbh/keys",
            "gh secret set HOMEBREW_TAP_SSH_KEY",
            "gh secret list -R Dicklesworthstone/storage_ballast_helper --json name,updatedAt,visibility",
            "sbh doctor --release --json",
        ] {
            assert!(
                all_commands.contains(required),
                "release doctor setup plan must include safe handoff command fragment: {required}"
            );
        }

        assert!(
            steps
                .iter()
                .all(|step| step.docs.starts_with("docs/macos.md#")),
            "each release setup step should point at the macOS guide"
        );
    }

    #[test]
    fn service_control_defaults_to_launchd_user_scope_on_macos() {
        let args = ServiceArgs {
            systemd: false,
            launchd: false,
            user: false,
            scope: None,
            command: ServiceCommand::Status,
        };

        let service =
            resolve_service_control(&args, ServiceKind::Launchd).expect("launchd should resolve");

        assert_eq!(service.kind, ServiceKind::Launchd);
        assert!(service.user_scope);
        assert_eq!(service.scope_name(), "user");
    }

    #[test]
    fn service_control_defaults_to_systemd_system_scope_on_linux() {
        let args = ServiceArgs {
            systemd: false,
            launchd: false,
            user: false,
            scope: None,
            command: ServiceCommand::Status,
        };

        let service =
            resolve_service_control(&args, ServiceKind::Systemd).expect("systemd should resolve");

        assert_eq!(service.kind, ServiceKind::Systemd);
        assert!(!service.user_scope);
        assert_eq!(service.scope_name(), "system");
    }

    #[test]
    fn service_control_rejects_wrong_explicit_backend() {
        let args = ServiceArgs {
            systemd: true,
            launchd: false,
            user: false,
            scope: None,
            command: ServiceCommand::Status,
        };

        let err = resolve_service_control(&args, ServiceKind::Launchd)
            .expect_err("explicit wrong backend should fail");

        assert!(err.to_string().contains("--systemd"));
        assert!(err.to_string().contains("launchd"));
    }

    #[test]
    fn update_service_control_defaults_to_platform_scope() {
        let args = UpdateArgs::default();

        let launchd = resolve_update_service_control(&args, ServiceKind::Launchd)
            .expect("launchd service should resolve");
        let systemd = resolve_update_service_control(&args, ServiceKind::Systemd)
            .expect("systemd service should resolve");

        assert!(launchd.user_scope);
        assert_eq!(launchd.scope_name(), "user");
        assert!(!systemd.user_scope);
        assert_eq!(systemd.scope_name(), "system");
    }

    #[test]
    fn update_service_control_honors_explicit_user_scope() {
        let args = UpdateArgs {
            user: true,
            ..UpdateArgs::default()
        };

        let service = resolve_update_service_control(&args, ServiceKind::Systemd)
            .expect("systemd service should resolve");

        assert_eq!(service.kind, ServiceKind::Systemd);
        assert!(service.user_scope);
    }

    #[test]
    fn update_restart_restarts_loaded_service() {
        let manager = FakeServiceManager::new(Ok(true), Ok(()));
        let service = ResolvedServiceControl {
            kind: ServiceKind::Launchd,
            user_scope: true,
        };
        let mut report = applied_update_report();

        restart_loaded_service_after_update(&mut report, service, &manager, false, "sudo needed");

        assert!(report.success);
        assert_eq!(manager.restart_calls(), 1);
        assert_eq!(
            report
                .service_restart
                .as_ref()
                .map(|restart| &restart.status),
            Some(&storage_ballast_helper::cli::update::UpdateServiceRestartStatus::Restarted)
        );
    }

    #[test]
    fn update_restart_skips_unloaded_service() {
        let manager = FakeServiceManager::new(Ok(false), Ok(()));
        let service = ResolvedServiceControl {
            kind: ServiceKind::Launchd,
            user_scope: true,
        };
        let mut report = applied_update_report();

        restart_loaded_service_after_update(&mut report, service, &manager, false, "sudo needed");

        assert!(report.success);
        assert_eq!(manager.restart_calls(), 0);
        assert_eq!(
            report
                .service_restart
                .as_ref()
                .map(|restart| &restart.status),
            Some(&storage_ballast_helper::cli::update::UpdateServiceRestartStatus::Skipped)
        );
    }

    #[test]
    fn update_restart_marks_failure_when_system_scope_needs_root() {
        let manager = FakeServiceManager::new(Ok(true), Ok(()));
        let service = ResolvedServiceControl {
            kind: ServiceKind::Systemd,
            user_scope: false,
        };
        let mut report = applied_update_report();

        restart_loaded_service_after_update(
            &mut report,
            service,
            &manager,
            false,
            "rerun with sudo",
        );

        assert!(!report.success);
        assert_eq!(manager.restart_calls(), 0);
        assert!(
            report
                .follow_up
                .iter()
                .any(|message| message.contains("rerun with sudo"))
        );
        assert_eq!(
            report
                .service_restart
                .as_ref()
                .map(|restart| &restart.status),
            Some(&storage_ballast_helper::cli::update::UpdateServiceRestartStatus::Failed)
        );
    }

    #[test]
    fn service_logs_tail_reads_recent_plain_lines() {
        let mut file = tempfile::NamedTempFile::new().expect("temp log should create");
        writeln!(file, "one").expect("line should write");
        writeln!(file, "two").expect("line should write");
        writeln!(file, "three").expect("line should write");

        let lines = read_plain_tail_lines(file.path(), 2).expect("tail should read");

        assert_eq!(lines, vec!["two".to_string(), "three".to_string()]);
    }

    #[test]
    fn scan_trace_reports_active_reference_checks() {
        let path = PathBuf::from("/tmp/cargo-target-active");
        let mut active_references =
            storage_ballast_helper::scanner::scoring::ActiveReferenceSummary::default();
        active_references.add_open_file_descriptor(42, Some("rustc".to_string()));
        active_references.add_running_executable(42, Some("rustc".to_string()));
        active_references.add_mmap_region(42, Some("rustc".to_string()));

        let input = CandidateInput {
            path: path.clone(),
            size_bytes: 1_073_741_824,
            age: std::time::Duration::from_hours(2),
            classification: ArtifactPatternRegistry::default().classify(
                &path,
                storage_ballast_helper::scanner::patterns::StructuralSignals::default(),
            ),
            signals: storage_ballast_helper::scanner::patterns::StructuralSignals::default(),
            active_references,
            is_open: false,
            excluded: false,
        };
        let engine = ScoringEngine::from_config(
            &storage_ballast_helper::core::config::ScoringConfig::default(),
            30,
        );
        let score = engine.score_candidate(&input, 0.0);
        let trace = build_scan_trace(&input, &score, 1_800, true, &[]);

        assert_eq!(trace.fd_check, "1 open file descriptor(s)");
        assert_eq!(trace.exec_check, "1 running executable(s)");
        assert_eq!(trace.mmap_check, "1 mmap region(s)");
        assert!(trace.veto_reason.as_deref().is_some_and(|reason| {
            reason.contains("Cannot reclaim safely") && reason.contains("pid 42 (rustc)")
        }));
    }

    #[test]
    fn scan_trace_reports_skipped_active_reference_probe() {
        let path = PathBuf::from("/tmp/small-cache");
        let input = CandidateInput {
            path: path.clone(),
            size_bytes: 4096,
            age: std::time::Duration::from_hours(2),
            classification: ArtifactPatternRegistry::default().classify(
                &path,
                storage_ballast_helper::scanner::patterns::StructuralSignals::default(),
            ),
            signals: storage_ballast_helper::scanner::patterns::StructuralSignals::default(),
            active_references:
                storage_ballast_helper::scanner::scoring::ActiveReferenceSummary::default(),
            is_open: false,
            excluded: false,
        };
        let engine = ScoringEngine::from_config(
            &storage_ballast_helper::core::config::ScoringConfig::default(),
            30,
        );
        let score = engine.score_candidate(&input, 0.0);
        let trace = build_scan_trace(&input, &score, 1_800, false, &[]);

        assert_eq!(
            trace.fd_check,
            "skipped below active-reference size threshold"
        );
        assert_eq!(
            trace.exec_check,
            "skipped below active-reference size threshold"
        );
        assert_eq!(
            trace.mmap_check,
            "skipped below active-reference size threshold"
        );
    }

    #[test]
    fn scan_trace_reports_incomplete_active_reference_visibility() {
        let path = PathBuf::from("/tmp/cargo-target-active");
        let mut active_references =
            storage_ballast_helper::scanner::scoring::ActiveReferenceSummary::default();
        active_references.mark_incomplete("fd check incomplete: other-user processes not visible");
        let input = CandidateInput {
            path: path.clone(),
            size_bytes: 1_073_741_824,
            age: std::time::Duration::from_hours(2),
            classification: ArtifactPatternRegistry::default().classify(
                &path,
                storage_ballast_helper::scanner::patterns::StructuralSignals::default(),
            ),
            signals: storage_ballast_helper::scanner::patterns::StructuralSignals::default(),
            active_references,
            is_open: false,
            excluded: false,
        };
        let engine = ScoringEngine::from_config(
            &storage_ballast_helper::core::config::ScoringConfig::default(),
            30,
        );
        let score = engine.score_candidate(&input, 0.0);
        let trace = build_scan_trace(&input, &score, 1_800, true, &[]);

        assert_eq!(
            trace.fd_check,
            "fd check incomplete: other-user processes not visible"
        );
        assert_eq!(
            trace.veto_reason.as_deref(),
            Some("fd check incomplete: other-user processes not visible")
        );
    }

    #[test]
    fn daemon_args_convert_to_runtime_daemon_args() {
        let args = DaemonArgs {
            background: true,
            pidfile: Some(PathBuf::from("/tmp/sbh.pid")),
            watchdog_sec: 42,
            action: None,
        };
        let runtime = to_runtime_daemon_args(&args);
        assert!(!runtime.foreground);
        assert_eq!(runtime.pidfile, Some(PathBuf::from("/tmp/sbh.pid")));
        assert_eq!(runtime.watchdog_sec, 42);

        let runtime_default = to_runtime_daemon_args(&DaemonArgs::default());
        assert!(runtime_default.foreground);
        assert_eq!(runtime_default.pidfile, None);
        assert_eq!(runtime_default.watchdog_sec, 0);
    }

    #[test]
    fn install_command_parses_auto_and_explicit_service_flags() {
        for case in [
            vec!["sbh", "install"],
            vec!["sbh", "install", "--launchd"],
            vec!["sbh", "install", "--systemd"],
            vec!["sbh", "install", "--scope", "user"],
            vec!["sbh", "install", "--scope", "system"],
            vec!["sbh", "install", "--from-source"],
            vec!["sbh", "install", "--from-source", "--scope", "user"],
            vec!["sbh", "install", "--offline", "/tmp/bundle-manifest.json"],
            vec![
                "sbh",
                "install",
                "--no-verify",
                "--offline",
                "/tmp/bundle-manifest.json",
            ],
        ] {
            let parsed = Cli::try_parse_from(case.iter().copied());
            assert!(parsed.is_ok(), "failed to parse install case: {case:?}");
        }

        assert!(Cli::try_parse_from(["sbh", "install", "--scope", "user", "--user"]).is_err());
        assert!(Cli::try_parse_from(["sbh", "install", "--systemd", "--launchd"]).is_err());
    }

    /// C-EXIT: the single mapping every command's error goes through.
    #[test]
    fn unprotected_pressure_gate_reads_fresh_state_only() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let write = |controllers: &str| {
            std::fs::write(
                &state_path,
                format!(r#"{{"schema_version":2,"mount_controllers":{controllers}}}"#),
            )
            .unwrap();
        };
        // No state: nothing gates.
        assert_eq!(unprotected_pressure_at(&state_path, Path::new("/")), None);

        write(
            r#"[{"mount":"/","state":"observe_only","idle_reason":"no_root_path_on_device","surface":"none","level":"orange","urgency":0.9,"reclaim_capability":"none"},
                {"mount":"/data","state":"reclaim","surface":"configured","level":"orange","urgency":0.9,"reclaim_capability":"configured"},
                {"mount":"/srv","state":"observe_only","surface":"none","level":"yellow","urgency":0.3,"reclaim_capability":"none"},
                {"mount":"/pool","state":"reclaim","surface":"ballast_only","level":"red","urgency":0.95,"reclaim_capability":"ballast_only","reserve_state":{"present_bytes":0,"target_bytes":1048576,"floor_limited":true}}]"#,
        );
        let table = [
            ("/", Some(("orange", "none"))),
            ("/data", None),
            ("/srv", None), // Yellow is not a check failure.
            ("/pool", Some(("red", "ballast_only"))),
            ("/nope", None),
        ];
        for (mount, want) in table {
            let got = unprotected_pressure_at(&state_path, Path::new(mount));
            assert_eq!(
                got,
                want.map(|(level, capability)| UnprotectedMount {
                    level: level.to_string(),
                    capability: capability.to_string(),
                }),
                "{mount}"
            );
        }

        // doctor --system: one FAIL per unprotected pressured mount, an
        // empty-reserve FAIL for the ballast-only mount, Yellow counts too.
        let mut config = Config::default();
        config.paths.state_file.clone_from(&state_path);
        let checks = reclaim_capability_doctor_checks(&config);
        let fails: Vec<(&str, &str)> = checks
            .iter()
            .filter(|c| c.status == "FAIL")
            .map(|c| (c.id, c.message.as_str()))
            .collect();
        assert_eq!(fails.len(), 3, "{checks:?}");
        assert!(
            fails
                .iter()
                .any(|(id, m)| *id == "reclaim.capability" && m.starts_with("/ is at orange"))
        );
        assert!(
            fails
                .iter()
                .any(|(id, m)| *id == "reclaim.capability" && m.starts_with("/srv is at yellow"))
        );
        assert!(
            fails
                .iter()
                .any(|(id, m)| *id == "reclaim.capability" && m.starts_with("/pool is at red"))
        );
        assert!(
            checks
                .iter()
                .all(|c| c.status != "FAIL" || c.remediation.is_some())
        );
        let json = serde_json::to_value(&checks).unwrap();
        assert_eq!(json[0]["id"], "reclaim.capability");

        // Stale state gates nothing and doctor says it cannot tell.
        let old = SystemTime::now()
            - std::time::Duration::from_secs(DAEMON_STATE_STALE_THRESHOLD_SECS + 100);
        filetime::set_file_mtime(&state_path, filetime::FileTime::from_system_time(old)).unwrap();
        assert_eq!(unprotected_pressure_at(&state_path, Path::new("/")), None);
        let stale = reclaim_capability_doctor_checks(&config);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].status, "WARN");
    }

    #[test]
    fn forecast_read_distinguishes_fresh_stale_and_missing_state() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let mount = Path::new("/data");
        assert_eq!(
            read_daemon_forecast(&state_path, mount),
            ForecastRead::Missing
        );

        std::fs::write(
            &state_path,
            r#"{"schema_version":2,"rates":{"/data":{"bytes_per_sec":2048.5,"accel":1.5,"confidence":0.8,"seconds_to_red":1200.0,"seconds_to_full":4000.0}}}"#,
        )
        .unwrap();
        let fresh = read_daemon_forecast(&state_path, mount);
        assert_eq!(
            fresh,
            ForecastRead::Fresh(Some(MountForecast {
                bytes_per_sec: 2048.5,
                accel: 1.5,
                confidence: 0.8,
                seconds_to_red: Some(1200.0),
                seconds_to_full: Some(4000.0),
                tte_lo: None,
                forecast: None,
            }))
        );
        assert_eq!(fresh.unknown_reason(), None);
        // A mount the daemon has no rate for is "fresh, nothing".
        let none = read_daemon_forecast(&state_path, Path::new("/srv"));
        assert_eq!(none, ForecastRead::Fresh(None));
        assert!(none.unknown_reason().unwrap().contains("no rate"));

        // Older than the staleness threshold: the numbers are history.
        let old = SystemTime::now()
            - std::time::Duration::from_secs(DAEMON_STATE_STALE_THRESHOLD_SECS + 100);
        filetime::set_file_mtime(&state_path, filetime::FileTime::from_system_time(old)).unwrap();
        match read_daemon_forecast(&state_path, mount) {
            ForecastRead::Stale { age_secs } => {
                assert!(age_secs > DAEMON_STATE_STALE_THRESHOLD_SECS);
            }
            other => panic!("expected stale, got {other:?}"),
        }
        assert!(
            ForecastRead::Stale { age_secs: 500 }
                .unknown_reason()
                .unwrap()
                .contains("stale: 500s old")
        );
    }

    #[test]
    fn rate_line_shows_the_horizon_and_marks_warming_below_min_confidence() {
        let confident = MountForecast {
            bytes_per_sec: 1_048_576.0,
            accel: 2048.0,
            confidence: 0.9,
            seconds_to_red: Some(2520.0),
            seconds_to_full: None,
            tte_lo: None,
            forecast: None,
        };
        let line = rate_line("/data", &confident, 0.6);
        assert!(line.contains("/data"), "{line}");
        assert!(line.contains("filling"), "{line}");
        assert!(line.contains("red in 42m"), "{line}");
        assert!(line.contains("confidence 0.90"), "{line}");
        assert!(!line.contains("warming"), "{line}");

        let warming = MountForecast {
            confidence: 0.2,
            seconds_to_red: None,
            ..confident.clone()
        };
        let line = rate_line("/data", &warming, 0.6);
        assert!(line.contains("warming (confidence 0.20 < 0.60)"), "{line}");
        assert!(line.contains("no red horizon"), "{line}");
        assert!(warming.to_json(0.6)["warming"].as_bool().unwrap());
        assert!(!confident.to_json(0.6)["warming"].as_bool().unwrap());

        assert_eq!(format_eta(42.0), "42s");
        assert_eq!(format_eta(3_900.0), "1h 5m");
        assert_eq!(format_eta(200_000.0), "2d 7h");
    }

    #[test]
    fn exit_code_contract_maps_every_error_class() {
        assert_eq!(CliError::User("x".into()).exit_code(), 1);
        assert_eq!(CliError::Runtime("x".into()).exit_code(), 2);
        assert_eq!(
            CliError::Io(std::io::Error::other("x")).exit_code(),
            2,
            "I/O failures share the runtime class"
        );
        assert_eq!(CliError::Internal("x".into()).exit_code(), 3);
        assert_eq!(CliError::Partial("x".into()).exit_code(), 4);
        // The documented contract (`sbh docs --section exit-codes`) lists
        // exactly the classes above, and the help epilog says the same.
        let documented: Vec<i32> = storage_ballast_helper::cli::docs::EXIT_CODES
            .iter()
            .map(|row| row.code)
            .collect();
        assert_eq!(documented, vec![0, 1, 2, 3, 4]);
        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("Exit codes (C-EXIT):"));
        for row in storage_ballast_helper::cli::docs::EXIT_CODES {
            let line = format!("{}  {}", row.code, row.meaning);
            assert!(help.contains(&line), "help epilog lacks {line:?}");
        }
    }

    #[test]
    fn explain_command_requires_exactly_one_selector() {
        for case in [
            vec!["sbh", "explain", "--id", "0123456789ab"],
            vec!["sbh", "explain", "--last", "5"],
            vec!["sbh", "explain", "--path", "/data/projects/foo/target"],
            vec!["sbh", "explain", "--since", "2h", "--limit", "5"],
            vec!["sbh", "explain", "--id", "0123456789ab", "--level", "3"],
        ] {
            let parsed = Cli::try_parse_from(case.iter().copied());
            assert!(parsed.is_ok(), "failed to parse explain case: {case:?}");
        }
        let parsed = Cli::try_parse_from(["sbh", "explain", "--last", "3"]).expect("parse");
        match parsed.command {
            Command::Explain(args) => {
                assert_eq!(args.last, Some(3));
                assert_eq!(args.level, 2, "level 2 is the documented default");
                assert_eq!(args.limit, 20);
            }
            other => panic!("expected explain, got {other:?}"),
        }
        assert!(
            Cli::try_parse_from(["sbh", "explain"]).is_err(),
            "a selector is required"
        );
        assert!(
            Cli::try_parse_from(["sbh", "explain", "--id", "0123456789ab", "--last", "2"]).is_err(),
            "selectors are mutually exclusive"
        );
    }

    #[test]
    fn bootstrap_command_and_install_time_repair_flags_parse() {
        use storage_ballast_helper::cli::bootstrap::{ActionKind, install_time_safe_actions};

        let parsed = Cli::try_parse_from(["sbh", "bootstrap"]).expect("bare bootstrap parses");
        assert!(matches!(
            parsed.command,
            Command::Bootstrap(BootstrapArgs { dry_run: false })
        ));
        let parsed =
            Cli::try_parse_from(["sbh", "bootstrap", "--dry-run"]).expect("dry-run parses");
        assert!(matches!(
            parsed.command,
            Command::Bootstrap(BootstrapArgs { dry_run: true })
        ));
        assert!(
            Cli::try_parse_from(["sbh", "bootstrap", "--apply"]).is_err(),
            "bootstrap has no --apply flag; applying is the default"
        );

        let parsed = Cli::try_parse_from(["sbh", "install", "--no-bootstrap"])
            .expect("install --no-bootstrap parses");
        match parsed.command {
            Command::Install(args) => assert!(args.no_bootstrap),
            other => panic!("expected install, got {other:?}"),
        }
        let parsed = Cli::try_parse_from(["sbh", "install"]).expect("install parses");
        match parsed.command {
            Command::Install(args) => assert!(!args.no_bootstrap, "bootstrap runs by default"),
            other => panic!("expected install, got {other:?}"),
        }

        let parsed = Cli::try_parse_from(["sbh", "doctor", "--env"]).expect("doctor --env parses");
        match parsed.command {
            Command::Doctor(args) => assert!(args.env && !args.pal && !args.system),
            other => panic!("expected doctor, got {other:?}"),
        }

        // Install may only self-apply repairs that fix the install it is
        // producing. Anything that copies or removes operator data is deferred.
        let safe = install_time_safe_actions();
        for kind in [
            ActionKind::RemoveProfileLine,
            ActionKind::DeduplicateProfile,
            ActionKind::FixPermissions,
            ActionKind::UpdateServicePath,
            ActionKind::CreateDirectory,
            ActionKind::InitStateFile,
        ] {
            assert!(safe.contains(&kind), "{kind} is safe at install time");
        }
        for kind in [
            ActionKind::CopyLegacyConfig,
            ActionKind::CopyLegacyState,
            ActionKind::RemoveOrphanedFile,
            ActionKind::CleanupBackup,
        ] {
            assert!(
                !safe.contains(&kind),
                "{kind} moves or removes operator data and must stay behind `sbh bootstrap`"
            );
        }
    }

    #[test]
    fn install_auto_selects_launchd_user_scope_on_macos() {
        let args = InstallArgs::default();
        let service = resolve_install_service(
            &args,
            ServiceKind::Launchd,
            false,
            "sudo sbh install --scope system",
        )
        .expect("plain install should resolve")
        .expect("plain install should request service");

        assert_eq!(service.kind, ServiceKind::Launchd);
        assert!(service.user_scope);
        assert_eq!(service.scope_name(), "user");
    }

    #[test]
    fn macos_release_install_defaults_to_user_local_bin() {
        let args = InstallArgs::default();
        let mut config = Config::default();
        config.update.metadata_cache_ttl_seconds = 42;
        config.update.metadata_cache_file = PathBuf::from("/tmp/sbh-install-cache.json");
        let service = Some(ResolvedInstallService {
            kind: ServiceKind::Launchd,
            user_scope: true,
        });

        let opts = build_macos_release_install_options(&args, &config, service);

        assert!(opts.force);
        assert!(!opts.no_verify);
        assert_eq!(opts.metadata_cache_ttl, std::time::Duration::from_secs(42));
        assert_eq!(
            opts.metadata_cache_file,
            PathBuf::from("/tmp/sbh-install-cache.json")
        );
        assert!(opts.install_dir.ends_with(".local/bin"));
    }

    #[test]
    fn macos_release_install_can_explicitly_bypass_verification() {
        let args = InstallArgs {
            no_verify: true,
            ..InstallArgs::default()
        };
        let config = Config::default();
        let service = Some(ResolvedInstallService {
            kind: ServiceKind::Launchd,
            user_scope: true,
        });

        let opts = build_macos_release_install_options(&args, &config, service);

        assert!(
            opts.no_verify,
            "install --no-verify must forward the explicit unsafe bypass into the release binary install path"
        );
    }

    #[test]
    fn macos_release_install_system_scope_uses_usr_local_bin() {
        let args = InstallArgs::default();
        let config = Config::default();
        let service = Some(ResolvedInstallService {
            kind: ServiceKind::Launchd,
            user_scope: false,
        });

        let opts = build_macos_release_install_options(&args, &config, service);

        assert_eq!(opts.install_dir, PathBuf::from("/usr/local/bin"));
    }

    #[test]
    fn macos_release_install_rejects_non_dry_run_without_binary_path() {
        let args = InstallArgs {
            dry_run: false,
            ..InstallArgs::default()
        };
        let report = UpdateReport {
            current_version: "0.4.7".to_string(),
            target_version: Some("v0.4.6".to_string()),
            update_available: false,
            applied: false,
            check_only: false,
            dry_run: false,
            artifact_url: None,
            notices_enabled: true,
            install_path: None,
            backup_id: None,
            steps: Vec::new(),
            success: true,
            follow_up: Vec::new(),
            service_restart: None,
        };

        let err = validate_macos_release_install_report(&args, &report, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("did not produce an installed binary path"),
            "non-dry-run install should not continue to service registration without a binary path: {err}"
        );
    }

    #[test]
    fn macos_release_install_dry_run_allows_no_binary_path() {
        let args = InstallArgs {
            dry_run: true,
            ..InstallArgs::default()
        };
        let report = UpdateReport {
            current_version: "0.4.7".to_string(),
            target_version: Some("v0.4.6".to_string()),
            update_available: false,
            applied: false,
            check_only: false,
            dry_run: true,
            artifact_url: None,
            notices_enabled: true,
            install_path: None,
            backup_id: None,
            steps: Vec::new(),
            success: true,
            follow_up: Vec::new(),
            service_restart: None,
        };

        let path = validate_macos_release_install_report(&args, &report, None).unwrap();
        assert_eq!(path, None);
    }

    #[test]
    fn install_auto_dry_run_json_payload_nests_macos_release_report() {
        let args = InstallArgs {
            auto: true,
            dry_run: true,
            ..InstallArgs::default()
        };
        let service = Some(ResolvedInstallService {
            kind: ServiceKind::Launchd,
            user_scope: true,
        });
        let mut answers = storage_ballast_helper::cli::wizard::auto_answers();
        apply_resolved_service_to_wizard_answers(&mut answers, service);
        let summary = storage_ballast_helper::cli::wizard::WizardSummary {
            config_path: answers.to_config().paths.config_file,
            config_written: false,
            answers,
            warnings: Vec::new(),
        };
        let release_report = UpdateReport {
            current_version: "0.4.7".to_string(),
            target_version: Some("v0.4.8".to_string()),
            update_available: true,
            applied: false,
            check_only: false,
            dry_run: true,
            artifact_url: Some("https://example.invalid/sbh-macos-arm64.tar.gz".to_string()),
            notices_enabled: true,
            install_path: Some(PathBuf::from("/Users/jane/.local/bin/sbh")),
            backup_id: None,
            steps: Vec::new(),
            success: true,
            follow_up: Vec::new(),
            service_restart: None,
        };
        let install_report = storage_ballast_helper::cli::install::InstallReport {
            steps: Vec::new(),
            success: true,
            config_path: None,
            data_dir: None,
            ballast_dir: None,
            ballast_files_created: 0,
            ballast_bytes: 0,
            dry_run: true,
        };

        let payload = build_install_auto_dry_run_json_payload(
            &args,
            service,
            &summary,
            Some(&release_report),
            None,
            &install_report,
            true,
        )
        .expect("payload should serialize");

        assert_eq!(payload["command"].as_str(), Some("install"));
        assert_eq!(payload["service"]["kind"].as_str(), Some("launchd"));
        assert_eq!(payload["service"]["scope"].as_str(), Some("user"));
        assert_eq!(payload["wizard"]["config_written"].as_bool(), Some(false));
        assert_eq!(
            payload["wizard"]["answers"]["service"].as_str(),
            Some("Launchd")
        );
        assert_eq!(
            payload["wizard"]["answers"]["user_scope"].as_bool(),
            Some(true)
        );
        assert_eq!(
            payload["wizard"]["answers"]["auto_mode"].as_bool(),
            Some(true)
        );
        assert_eq!(payload["release_install"]["dry_run"].as_bool(), Some(true));
        assert_eq!(
            payload["release_install"]["install_path"].as_str(),
            Some("/Users/jane/.local/bin/sbh")
        );
        assert_eq!(payload["install"]["dry_run"].as_bool(), Some(true));
        assert!(payload["release_error"].is_null());
        assert_eq!(payload["success"].as_bool(), Some(true));
    }

    #[test]
    fn install_default_paths_follow_service_scope() {
        let system_paths = install_default_paths_for_service(Some(ResolvedInstallService {
            kind: ServiceKind::Launchd,
            user_scope: false,
        }));

        assert_eq!(system_paths, PathsConfig::system_default());

        #[cfg(target_os = "macos")]
        assert_eq!(
            system_paths.ballast_dir,
            PathBuf::from("/private/var/sbh/ballast.bin")
        );

        #[cfg(target_os = "linux")]
        assert_eq!(
            system_paths.ballast_dir,
            PathBuf::from("/var/lib/sbh/ballast")
        );
    }

    #[test]
    fn install_auto_selects_systemd_system_scope_on_linux() {
        let args = InstallArgs::default();
        let service = resolve_install_service(
            &args,
            ServiceKind::Systemd,
            true,
            "sudo sbh install --scope system",
        )
        .expect("plain install should resolve")
        .expect("plain install should request service");

        assert_eq!(service.kind, ServiceKind::Systemd);
        assert!(!service.user_scope);
        assert_eq!(service.scope_name(), "system");
    }

    #[test]
    fn install_auto_flag_selects_user_scope_on_all_supported_service_kinds() {
        let args = InstallArgs {
            auto: true,
            ..InstallArgs::default()
        };

        let linux = resolve_install_service(
            &args,
            ServiceKind::Systemd,
            false,
            "sudo sbh install --scope system",
        )
        .expect("--auto should not require root for systemd user scope")
        .expect("--auto should request service installation");
        assert_eq!(linux.kind, ServiceKind::Systemd);
        assert!(linux.user_scope);

        let macos = resolve_install_service(
            &args,
            ServiceKind::Launchd,
            false,
            "sudo sbh install --scope system",
        )
        .expect("--auto should resolve launchd")
        .expect("--auto should request service installation");
        assert_eq!(macos.kind, ServiceKind::Launchd);
        assert!(macos.user_scope);
    }

    #[test]
    fn install_auto_from_source_still_requests_detected_user_service() {
        let args = InstallArgs {
            auto: true,
            from_source: true,
            ..InstallArgs::default()
        };

        let service = resolve_install_service(
            &args,
            ServiceKind::Systemd,
            false,
            "sudo sbh install --scope system",
        )
        .expect("--from-source --auto should resolve")
        .expect("--auto should request service registration after source install");

        assert_eq!(service.kind, ServiceKind::Systemd);
        assert!(service.user_scope);
    }

    #[test]
    fn install_auto_explicit_system_scope_still_requires_root() {
        let args = InstallArgs {
            auto: true,
            scope: Some(InstallScopeArg::System),
            ..InstallArgs::default()
        };
        let err = resolve_install_service(
            &args,
            ServiceKind::Launchd,
            false,
            "sudo sbh install --scope system",
        )
        .expect_err("explicit system-scope auto install should still require root");

        assert!(err.to_string().contains("requires root"));
    }

    #[test]
    fn auto_wizard_answers_follow_resolved_service_for_config_paths() {
        let mut answers = storage_ballast_helper::cli::wizard::auto_answers();
        apply_resolved_service_to_wizard_answers(
            &mut answers,
            Some(ResolvedInstallService {
                kind: ServiceKind::Launchd,
                user_scope: false,
            }),
        );
        let config = answers.to_config();

        assert_eq!(
            answers.service,
            storage_ballast_helper::cli::wizard::ServiceChoice::Launchd
        );
        assert!(!answers.user_scope);
        assert_eq!(config.paths, PathsConfig::system_default());
    }

    #[test]
    fn install_from_source_only_does_not_request_service() {
        let args = InstallArgs {
            from_source: true,
            ..InstallArgs::default()
        };

        assert!(
            resolve_install_service(
                &args,
                ServiceKind::Launchd,
                false,
                "sudo sbh install --scope system",
            )
            .expect("from-source-only should resolve")
            .is_none()
        );
    }

    #[test]
    fn install_from_source_with_scope_requests_detected_service() {
        let args = InstallArgs {
            from_source: true,
            scope: Some(InstallScopeArg::User),
            ..InstallArgs::default()
        };
        let service = resolve_install_service(
            &args,
            ServiceKind::Launchd,
            false,
            "sudo sbh install --scope system",
        )
        .expect("scoped from-source install should resolve")
        .expect("scope should request service");

        assert_eq!(service.kind, ServiceKind::Launchd);
        assert!(service.user_scope);
    }

    #[test]
    fn install_explicit_wrong_service_errors() {
        let args = InstallArgs {
            systemd: true,
            ..InstallArgs::default()
        };
        let err = resolve_install_service(
            &args,
            ServiceKind::Launchd,
            true,
            "sudo sbh install --scope system",
        )
        .expect_err("--systemd should fail on launchd hosts");

        assert!(err.to_string().contains("--systemd"));
        assert!(err.to_string().contains("launchd"));
    }

    #[test]
    fn install_system_scope_requires_root() {
        let args = InstallArgs {
            scope: Some(InstallScopeArg::System),
            ..InstallArgs::default()
        };
        let err = resolve_install_service(
            &args,
            ServiceKind::Launchd,
            false,
            "sudo sbh install --scope system",
        )
        .expect_err("system-scope launchd should require root");

        assert!(err.to_string().contains("requires root"));
        assert!(err.to_string().contains("--scope user"));
        assert!(err.to_string().contains("sudo sbh install --scope system"));
    }

    fn test_wizard_answers(
        service: storage_ballast_helper::cli::wizard::ServiceChoice,
        user_scope: bool,
    ) -> storage_ballast_helper::cli::wizard::WizardAnswers {
        storage_ballast_helper::cli::wizard::WizardAnswers {
            service,
            user_scope,
            initial_mode: storage_ballast_helper::daemon::policy::ActiveMode::Enforce,
            watched_paths: vec![PathBuf::from("/tmp")],
            ballast_preset: storage_ballast_helper::cli::wizard::BallastPreset::Medium,
            ballast_file_count: 10,
            ballast_file_size_bytes: 1_073_741_824,
            auto_mode: false,
        }
    }

    #[test]
    fn wizard_selected_launchd_resolves_service_registration() {
        let answers = test_wizard_answers(
            storage_ballast_helper::cli::wizard::ServiceChoice::Launchd,
            true,
        );

        let service = resolve_wizard_install_service(
            &answers,
            ServiceKind::Launchd,
            false,
            "sudo sbh install --scope system",
        )
        .expect("wizard launchd selection should resolve")
        .expect("launchd selection should request service registration");

        assert_eq!(service.kind, ServiceKind::Launchd);
        assert!(service.user_scope);
    }

    #[test]
    fn wizard_selected_none_skips_service_registration() {
        let answers = test_wizard_answers(
            storage_ballast_helper::cli::wizard::ServiceChoice::None,
            true,
        );

        assert!(
            resolve_wizard_install_service(
                &answers,
                ServiceKind::Launchd,
                false,
                "sudo sbh install --scope system",
            )
            .expect("wizard none selection should resolve")
            .is_none()
        );
    }

    #[test]
    fn wizard_selected_wrong_service_errors_before_installing() {
        let answers = test_wizard_answers(
            storage_ballast_helper::cli::wizard::ServiceChoice::Systemd,
            true,
        );

        let err = resolve_wizard_install_service(
            &answers,
            ServiceKind::Launchd,
            false,
            "sudo sbh install --scope system",
        )
        .expect_err("wizard should reject a service backend for a different platform");

        assert!(err.to_string().contains("wizard selected systemd"));
        assert!(err.to_string().contains("platform uses launchd"));
    }

    #[test]
    fn wizard_system_scope_still_requires_root() {
        let answers = test_wizard_answers(
            storage_ballast_helper::cli::wizard::ServiceChoice::Launchd,
            false,
        );

        let err = resolve_wizard_install_service(
            &answers,
            ServiceKind::Launchd,
            false,
            "sudo sbh install --scope system",
        )
        .expect_err("wizard system-scope launchd should require root");

        assert!(err.to_string().contains("requires root"));
        assert!(err.to_string().contains("sudo sbh install --scope system"));
    }

    #[test]
    fn sudo_rerun_command_preserves_launchd_config_env_and_argv() {
        let config_path = "/Users/jane/Library/Application Support/sbh/config.toml";
        let cli = Cli::try_parse_from([
            "sbh",
            "--config",
            config_path,
            "install",
            "--launchd",
            "--scope",
            "system",
        ])
        .expect("scoped install should parse");
        let argv = [
            "sbh",
            "--config",
            config_path,
            "install",
            "--launchd",
            "--scope",
            "system",
        ]
        .map(ToString::to_string);
        let command = format_sudo_rerun_command_from_args(&cli, ServiceKind::Launchd, &argv);

        assert!(command.starts_with("sudo env "));
        assert!(
            command
                .contains("SBH_CONFIG='/Users/jane/Library/Application Support/sbh/config.toml'")
        );
        assert!(
            command.contains(
                "SBH_CONFIG_PATH='/Users/jane/Library/Application Support/sbh/config.toml'"
            )
        );
        assert!(command.contains(
            "sbh --config '/Users/jane/Library/Application Support/sbh/config.toml' install --launchd --scope system"
        ));
    }

    #[test]
    fn system_scope_uninstall_root_message_includes_sudo_rerun() {
        let message = service_system_scope_root_message(
            "uninstall",
            ServiceKind::Launchd,
            "sudo env HOME=/Users/jane sbh uninstall --launchd --scope system",
        );

        assert!(message.contains("system-scope launchd uninstall requires root"));
        assert!(message.contains("sudo env HOME=/Users/jane sbh uninstall"));
        assert!(message.contains("sbh uninstall --scope user"));
    }

    #[test]
    fn uninstall_command_parses_scope_flags() {
        for case in [
            vec!["sbh", "uninstall"],
            vec!["sbh", "uninstall", "--launchd"],
            vec!["sbh", "uninstall", "--launchd", "--scope", "user"],
            vec!["sbh", "uninstall", "--launchd", "--scope", "system"],
            vec!["sbh", "uninstall", "--systemd", "--user"],
            vec!["sbh", "uninstall", "--systemd", "--purge"],
            vec!["sbh", "uninstall", "--dry-run"],
            vec!["sbh", "uninstall", "--keep-data", "--yes"],
            vec!["sbh", "uninstall", "--keep-config", "-y"],
            vec!["sbh", "uninstall", "--keep-assets", "--dry-run"],
            vec![
                "sbh",
                "uninstall",
                "--purge",
                "--backup-dir",
                "/tmp/sbh-backups",
            ],
        ] {
            let parsed = Cli::try_parse_from(case.iter().copied());
            assert!(parsed.is_ok(), "failed to parse uninstall case: {case:?}");
        }

        assert!(
            Cli::try_parse_from(["sbh", "uninstall", "--launchd", "--user", "--scope", "user"])
                .is_err()
        );
        assert!(Cli::try_parse_from(["sbh", "uninstall", "--systemd", "--launchd"]).is_err());
        // Cleanup modes are mutually exclusive.
        for case in [
            ["sbh", "uninstall", "--purge", "--keep-data"],
            ["sbh", "uninstall", "--keep-data", "--keep-config"],
            ["sbh", "uninstall", "--keep-config", "--keep-assets"],
            ["sbh", "uninstall", "--keep-assets", "--purge"],
        ] {
            assert!(
                Cli::try_parse_from(case).is_err(),
                "cleanup modes must conflict: {case:?}"
            );
        }
    }

    #[test]
    fn uninstall_flags_map_to_cleanup_modes() {
        use storage_ballast_helper::cli::uninstall::CleanupMode;
        let mode_of = |argv: &[&str]| match Cli::try_parse_from(argv).expect("parse").command {
            Command::Uninstall(args) => args.cleanup_mode(),
            other => panic!("expected uninstall, got {other:?}"),
        };
        assert_eq!(
            mode_of(&["sbh", "uninstall"]),
            CleanupMode::Conservative,
            "no flag means the documented conservative default"
        );
        assert_eq!(
            mode_of(&["sbh", "uninstall", "--purge"]),
            CleanupMode::Purge
        );
        assert_eq!(
            mode_of(&["sbh", "uninstall", "--keep-data"]),
            CleanupMode::KeepData
        );
        assert_eq!(
            mode_of(&["sbh", "uninstall", "--keep-config"]),
            CleanupMode::KeepConfig
        );
        assert_eq!(
            mode_of(&["sbh", "uninstall", "--keep-assets"]),
            CleanupMode::KeepAssets
        );
    }

    #[test]
    fn uninstall_auto_selects_detected_service_kind() {
        let args = UninstallArgs::default();

        assert_eq!(
            resolve_uninstall_kind(&args, ServiceKind::Launchd).expect("launchd should resolve"),
            ServiceKind::Launchd
        );
        assert_eq!(
            resolve_uninstall_kind(&args, ServiceKind::Systemd).expect("systemd should resolve"),
            ServiceKind::Systemd
        );
    }

    #[test]
    fn uninstall_auto_errors_on_unsupported_service_kind() {
        let err = resolve_uninstall_kind(&UninstallArgs::default(), ServiceKind::None)
            .expect_err("unsupported platform should fail auto uninstall");

        assert!(
            err.to_string()
                .contains("automatic service uninstall is not supported")
        );
    }

    #[test]
    fn uninstall_explicit_wrong_service_errors() {
        let args = UninstallArgs {
            systemd: true,
            ..UninstallArgs::default()
        };
        let err = resolve_uninstall_kind(&args, ServiceKind::Launchd)
            .expect_err("--systemd should fail on launchd hosts");

        assert!(err.to_string().contains("--systemd"));
        assert!(err.to_string().contains("launchd"));
    }

    #[test]
    fn uninstall_launchd_defaults_to_user_when_no_plist_exists() {
        let args = UninstallArgs {
            launchd: true,
            ..UninstallArgs::default()
        };

        assert!(resolve_uninstall_user_scope(&args, false, false, true));
    }

    #[test]
    fn uninstall_scope_prefers_existing_system_artifact() {
        let args = UninstallArgs {
            launchd: true,
            ..UninstallArgs::default()
        };

        assert!(!resolve_uninstall_user_scope(&args, true, true, true));
    }

    #[test]
    fn uninstall_explicit_scope_overrides_artifact_detection() {
        let args = UninstallArgs {
            launchd: true,
            scope: Some(InstallScopeArg::System),
            ..UninstallArgs::default()
        };

        assert!(!resolve_uninstall_user_scope(&args, false, true, true));
    }

    #[test]
    fn uninstall_systemd_defaults_to_system_when_no_unit_exists() {
        let args = UninstallArgs {
            systemd: true,
            ..UninstallArgs::default()
        };

        assert!(!resolve_uninstall_user_scope(&args, false, false, false));
    }

    #[test]
    fn uninstall_launchd_plist_paths_include_configured_label() {
        let (system_paths, user_paths) =
            launchd_uninstall_plist_paths(Path::new("/Users/tester"), Some("com.example.sbh.test"));

        assert_eq!(
            system_paths,
            vec![
                PathBuf::from("/Library/LaunchDaemons/com.sbh.daemon.plist"),
                PathBuf::from("/Library/LaunchDaemons/com.example.sbh.test.plist")
            ]
        );
        assert_eq!(
            user_paths,
            vec![
                PathBuf::from("/Users/tester/Library/LaunchAgents/com.sbh.daemon.plist"),
                PathBuf::from("/Users/tester/Library/LaunchAgents/com.example.sbh.test.plist")
            ]
        );
    }

    #[test]
    fn normalize_refresh_ms_enforces_minimum_floor() {
        assert_eq!(normalize_refresh_ms(0), LIVE_REFRESH_MIN_MS);
        assert_eq!(
            normalize_refresh_ms(LIVE_REFRESH_MIN_MS - 1),
            LIVE_REFRESH_MIN_MS
        );
        assert_eq!(
            normalize_refresh_ms(LIVE_REFRESH_MIN_MS),
            LIVE_REFRESH_MIN_MS
        );
        assert_eq!(normalize_refresh_ms(2_500), 2_500);
    }

    #[test]
    fn ballast_total_pool_bytes_returns_product_for_normal_values() {
        assert_eq!(ballast_total_pool_bytes(3, 1024), 3072);
    }

    #[test]
    fn ballast_total_pool_bytes_saturates_on_overflow() {
        assert_eq!(ballast_total_pool_bytes(usize::MAX, u64::MAX), u64::MAX);
    }

    #[test]
    fn validate_live_mode_output_allows_status_watch_json_streaming() {
        let result = validate_live_mode_output(OutputMode::Json, "status --watch", true);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_live_mode_output_rejects_dashboard_json_live_mode() {
        let result = validate_live_mode_output(OutputMode::Json, "dashboard", false);
        assert!(result.is_err());
        let err_text = result.err().map_or_else(String::new, |e| e.to_string());
        assert!(err_text.contains("dashboard"));
        assert!(err_text.contains("does not support --json"));
    }

    /// A lean build (no `tui` feature) must only refuse when the operator
    /// explicitly asked for the cockpit; every implicit route degrades to the
    /// live status view instead of exiting 2.
    #[cfg(not(feature = "tui"))]
    #[test]
    fn lean_build_refuses_only_explicit_new_dashboard_flag() {
        let refusal = lean_build_dashboard_refusal(&DashboardSelectionReason::CliFlagNew)
            .expect("explicit --new-dashboard must be refused without tui");
        assert!(
            refusal.to_string().contains("TUI feature not enabled"),
            "refusal must name the feature gate, got {refusal}"
        );
        for reason in [
            DashboardSelectionReason::HardcodedDefault,
            DashboardSelectionReason::EnvVarMode,
            DashboardSelectionReason::ConfigFileMode,
        ] {
            assert!(
                lean_build_dashboard_refusal(&reason).is_none(),
                "{reason:?} must fall back to the live status view"
            );
        }
    }

    #[test]
    fn dashboard_runtime_flags_conflict() {
        assert!(
            Cli::try_parse_from(["sbh", "dashboard", "--new-dashboard", "--legacy-dashboard"])
                .is_err()
        );
    }

    #[test]
    fn resolve_dashboard_runtime_prefers_explicit_flags() {
        let cfg = Config::default();

        let defaults = DashboardArgs::default();
        let (sel, reason) = resolve_dashboard_runtime(&defaults, &cfg);
        assert_eq!(sel, DashboardRuntimeSelection::New);
        assert_eq!(reason, DashboardSelectionReason::HardcodedDefault);

        let new_args = DashboardArgs {
            new_dashboard: true,
            ..DashboardArgs::default()
        };
        let (sel, reason) = resolve_dashboard_runtime(&new_args, &cfg);
        assert_eq!(sel, DashboardRuntimeSelection::New);
        assert_eq!(reason, DashboardSelectionReason::CliFlagNew);

        let legacy_args = DashboardArgs {
            legacy_dashboard: true,
            ..DashboardArgs::default()
        };
        let (sel, reason) = resolve_dashboard_runtime(&legacy_args, &cfg);
        assert_eq!(sel, DashboardRuntimeSelection::Legacy);
        assert_eq!(reason, DashboardSelectionReason::CliFlagLegacy);
    }

    /// Every `sbh <command>` the README's Command Reference lists exists in
    /// clap (bd-rc-master-ajg1.12.3's first check), and the README's
    /// generated regions match this build (`sbh docs --check README.md`).
    #[test]
    fn readme_commands_exist_and_generated_regions_are_current() {
        use storage_ballast_helper::cli::docs::{DocsDocument, check_file};

        let readme_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md");
        let readme = std::fs::read_to_string(&readme_path).expect("README.md");
        let root = Cli::command();
        let known: std::collections::BTreeSet<String> =
            storage_ballast_helper::cli::docs::command_docs(&root)
                .into_iter()
                .map(|c| c.path)
                .collect();

        let missing = storage_ballast_helper::cli::docs::undocumented_commands(
            &readme,
            "## Command Reference",
            &known,
        );
        assert!(
            missing.is_empty(),
            "README documents commands that do not exist: {missing:#?}"
        );

        let document = DocsDocument::build(&root);
        for name in ["README.md", "AGENTS.md"] {
            let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(name);
            let drifted = check_file(&path, &document).expect("generated regions render");
            assert!(
                drifted.is_empty(),
                "{name} generated regions drifted: {drifted:?}; run `sbh docs --render {name}`"
            );
        }
    }

    /// Doc contract (bd-rc-master-ajg1.12.3): the command tables in README
    /// and AGENTS.md name only commands and `--flags` clap has, and every
    /// backticked `src/…`, `docs/…`, `scripts/…`, `tests/…`, `.github/…`
    /// path in README, AGENTS.md and docs/*.md exists.
    #[test]
    fn documented_commands_flags_and_file_references_resolve() {
        use storage_ballast_helper::cli::docs::{
            command_docs, missing_file_references, undocumented_commands, undocumented_flags,
        };
        let root_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let cli = Cli::command();
        let known: std::collections::BTreeSet<String> =
            command_docs(&cli).into_iter().map(|c| c.path).collect();

        let mut findings = Vec::new();
        for (file, section) in [
            ("README.md", "## Command Reference"),
            ("AGENTS.md", "## CLI Command Reference"),
        ] {
            let text = std::fs::read_to_string(root_dir.join(file)).expect(file);
            for row in undocumented_commands(&text, section, &known) {
                findings.push(format!("{file}: unknown command in {row}"));
            }
            for row in undocumented_flags(&text, section, &cli) {
                findings.push(format!("{file}: unknown flag in {row}"));
            }
        }

        let mut doc_files = vec![
            root_dir.join("README.md"),
            root_dir.join("AGENTS.md"),
            root_dir.join("CHANGELOG.md"),
        ];
        let mut docs: Vec<_> = std::fs::read_dir(root_dir.join("docs"))
            .expect("docs/")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "md"))
            .collect();
        docs.sort();
        doc_files.extend(docs);
        for path in doc_files {
            let text = std::fs::read_to_string(&path).expect("doc file");
            for finding in missing_file_references(&text, root_dir) {
                findings.push(format!(
                    "{}: missing file {finding}",
                    path.strip_prefix(root_dir).unwrap_or(&path).display()
                ));
            }
        }
        assert!(
            findings.is_empty(),
            "doc contract violations:\n{}",
            findings.join("\n")
        );
    }

    /// `--start-screen` rides along as the raw name; the cockpit runtime is
    /// the one place it is validated, so the clap layer accepts any string.
    #[test]
    fn dashboard_start_screen_flag_is_carried_verbatim() {
        let cli = Cli::try_parse_from(["sbh", "dashboard", "--start-screen", "ballast"])
            .expect("--start-screen parses");
        let Command::Dashboard(args) = cli.command else {
            panic!("expected the dashboard command");
        };
        assert_eq!(args.start_screen.as_deref(), Some("ballast"));
        assert!(!args.new_dashboard && !args.legacy_dashboard);
        assert_eq!(DashboardArgs::default().start_screen, None);
    }

    /// `--replay FILE [--from TS] [--speed S]` parse together; `--from` and
    /// `--speed` need `--replay`, and `--replay` excludes the legacy view.
    #[test]
    fn dashboard_replay_flags_parse_and_require_each_other() {
        let cli = Cli::try_parse_from([
            "sbh",
            "dashboard",
            "--replay",
            "/var/lib/sbh/activity.jsonl",
            "--from",
            "2026-08-30T10:00:00Z",
            "--speed",
            "10x",
        ])
        .expect("replay flags parse");
        let Command::Dashboard(args) = cli.command else {
            panic!("expected the dashboard command");
        };
        assert_eq!(
            args.replay.as_deref(),
            Some(Path::new("/var/lib/sbh/activity.jsonl"))
        );
        assert_eq!(args.from.as_deref(), Some("2026-08-30T10:00:00Z"));
        assert_eq!(args.speed, "10x");
        assert!(Cli::try_parse_from(["sbh", "dashboard", "--speed", "max"]).is_err());
        assert!(
            Cli::try_parse_from(["sbh", "dashboard", "--from", "2026-08-30T10:00:00Z"]).is_err()
        );
        assert!(
            Cli::try_parse_from([
                "sbh",
                "dashboard",
                "--replay",
                "x.jsonl",
                "--legacy-dashboard"
            ])
            .is_err()
        );
        assert_eq!(DashboardArgs::default().speed, "1x");
    }

    #[cfg(feature = "tui")]
    #[test]
    fn dashboard_start_screen_names_match_the_cockpit_parser() {
        use storage_ballast_helper::tui::preferences::StartScreen;
        for name in StartScreen::NAMES {
            assert!(name.parse::<StartScreen>().is_ok(), "{name}");
        }
        let err = "settings".parse::<StartScreen>().unwrap_err();
        assert!(err.contains("unknown start screen"), "{err}");
    }

    #[test]
    fn resolve_dashboard_runtime_config_mode_legacy() {
        use storage_ballast_helper::core::config::{DashboardConfig, DashboardMode};
        let cfg = Config {
            dashboard: DashboardConfig {
                mode: DashboardMode::Legacy,
                kill_switch: false,
            },
            ..Config::default()
        };
        let args = DashboardArgs::default();
        let (sel, reason) = resolve_dashboard_runtime(&args, &cfg);
        assert_eq!(sel, DashboardRuntimeSelection::Legacy);
        assert_eq!(reason, DashboardSelectionReason::ConfigFileMode);
    }

    #[test]
    fn resolve_dashboard_runtime_kill_switch_overrides_new_flag() {
        use storage_ballast_helper::core::config::DashboardConfig;
        let cfg = Config {
            dashboard: DashboardConfig {
                kill_switch: true,
                ..DashboardConfig::default()
            },
            ..Config::default()
        };
        let args = DashboardArgs {
            new_dashboard: true,
            ..DashboardArgs::default()
        };
        let (sel, reason) = resolve_dashboard_runtime(&args, &cfg);
        assert_eq!(sel, DashboardRuntimeSelection::Legacy);
        assert_eq!(reason, DashboardSelectionReason::KillSwitchConfig);
    }

    #[test]
    fn resolve_dashboard_runtime_kill_switch_overrides_config_mode() {
        use storage_ballast_helper::core::config::{DashboardConfig, DashboardMode};
        let cfg = Config {
            dashboard: DashboardConfig {
                mode: DashboardMode::New,
                kill_switch: true,
            },
            ..Config::default()
        };
        let args = DashboardArgs::default();
        let (sel, reason) = resolve_dashboard_runtime(&args, &cfg);
        assert_eq!(sel, DashboardRuntimeSelection::Legacy);
        assert_eq!(reason, DashboardSelectionReason::KillSwitchConfig);
    }

    #[test]
    fn resolve_dashboard_runtime_cli_flag_overrides_config() {
        use storage_ballast_helper::core::config::{DashboardConfig, DashboardMode};
        let cfg = Config {
            dashboard: DashboardConfig {
                mode: DashboardMode::New,
                kill_switch: false,
            },
            ..Config::default()
        };
        let args = DashboardArgs {
            legacy_dashboard: true,
            ..DashboardArgs::default()
        };
        let (sel, reason) = resolve_dashboard_runtime(&args, &cfg);
        assert_eq!(sel, DashboardRuntimeSelection::Legacy);
        assert_eq!(reason, DashboardSelectionReason::CliFlagLegacy);
    }

    #[test]
    fn dashboard_selection_reason_display() {
        assert_eq!(
            DashboardSelectionReason::KillSwitchEnv.to_string(),
            "SBH_DASHBOARD_KILL_SWITCH=true (env)"
        );
        assert_eq!(
            DashboardSelectionReason::HardcodedDefault.to_string(),
            "hardcoded default (new)"
        );
    }

    // TUI is always compiled in — no feature-gated fallback test needed.

    #[test]
    fn protect_requires_path_or_list() {
        assert!(Cli::try_parse_from(["sbh", "protect"]).is_err());
        assert!(Cli::try_parse_from(["sbh", "protect", "--list"]).is_ok());
        assert!(Cli::try_parse_from(["sbh", "protect", "/tmp/work"]).is_ok());
        assert!(Cli::try_parse_from(["sbh", "protect", "/tmp/work", "--list"]).is_err());
        assert!(Cli::try_parse_from(["sbh", "status", "--sacred"]).is_ok());
    }

    #[test]
    fn protect_command_writes_marker_and_sacred_config() {
        let tmp = TempDir::new().unwrap();
        let config_path = tmp.path().join("config.toml");
        let protected = tmp.path().join("critical-build");
        std::fs::create_dir_all(&protected).unwrap();
        std::fs::write(
            &config_path,
            format!(
                "[scanner]\nroot_paths = [\"{}\"]\n",
                tmp.path().to_string_lossy()
            ),
        )
        .unwrap();

        let cli = Cli::try_parse_from([
            "sbh",
            "--config",
            config_path.to_str().unwrap(),
            "protect",
            protected.to_str().unwrap(),
        ])
        .unwrap();
        run(&cli).unwrap();

        let marker_path = protected.join(protection::MARKER_FILENAME);
        assert!(marker_path.exists());
        let marker = std::fs::read_to_string(&marker_path).unwrap();
        assert!(marker.contains("protected_at"));

        let sacred_path = sacred_config_path_for(&config_path);
        let sacred = load_sacred_config(&sacred_path).unwrap();
        let protected_config_path = std::fs::canonicalize(&protected)
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert_eq!(sacred.protected_paths, vec![protected_config_path.clone()]);

        let loaded = Config::load(Some(&config_path)).unwrap();
        assert!(
            loaded
                .scanner
                .protected_paths
                .contains(&protected_config_path)
        );
    }

    #[test]
    fn unprotect_command_removes_marker_and_sacred_config_entry() {
        let tmp = TempDir::new().unwrap();
        let config_path = tmp.path().join("config.toml");
        let protected = tmp.path().join("critical-build");
        std::fs::create_dir_all(&protected).unwrap();
        std::fs::write(
            &config_path,
            format!(
                "[scanner]\nroot_paths = [\"{}\"]\n",
                tmp.path().to_string_lossy()
            ),
        )
        .unwrap();

        let sacred_path = sacred_config_path_for(&config_path);
        let mut sacred = SacredConfig::default();
        sacred.add_protected_path(protected.to_string_lossy().to_string());
        write_sacred_config(&sacred_path, &sacred).unwrap();
        protection::create_marker(&protected, None).unwrap();

        let cli = Cli::try_parse_from([
            "sbh",
            "--config",
            config_path.to_str().unwrap(),
            "unprotect",
            protected.to_str().unwrap(),
        ])
        .unwrap();
        run(&cli).unwrap();

        assert!(!protected.join(protection::MARKER_FILENAME).exists());
        let sacred = load_sacred_config(&sacred_path).unwrap();
        assert!(
            sacred.protected_paths.is_empty(),
            "unprotect must leave no protected paths, got {:?}",
            sacred.protected_paths
        );
    }

    #[test]
    fn sacred_status_report_lists_config_protections() {
        let tmp = TempDir::new().unwrap();
        let config_path = tmp.path().join("config.toml");
        let protected = tmp.path().join("critical-build");
        std::fs::create_dir_all(&protected).unwrap();
        std::fs::write(
            &config_path,
            format!(
                "[scanner]\nroot_paths = [\"{}\"]\nprotected_paths = [\"{}\"]\n",
                tmp.path().to_string_lossy(),
                protected.to_string_lossy()
            ),
        )
        .unwrap();

        let config = Config::load(Some(&config_path)).unwrap();
        let report = collect_sacred_status_report(&config).unwrap();

        assert_eq!(report.protection_count, 1);
        assert_eq!(report.config_pattern_count, 1);
        assert!(report.sacred_catalog_count > 0);
    }

    #[test]
    fn sacred_status_report_counts_config_protected_child_overlap() {
        let tmp = TempDir::new().unwrap();
        let config_path = tmp.path().join("config.toml");
        let candidate = tmp.path().join("old-target");
        let protected = candidate.join("critical-data");
        std::fs::create_dir_all(&protected).unwrap();
        std::fs::write(
            &config_path,
            format!(
                "[scanner]\nroot_paths = [\"{}\"]\nprotected_paths = [\"{}\"]\n",
                tmp.path().to_string_lossy(),
                protected.to_string_lossy()
            ),
        )
        .unwrap();

        let config = Config::load(Some(&config_path)).unwrap();
        let report = collect_sacred_status_report(&config).unwrap();

        assert!(report.scan_candidate_count >= 1);
        assert!(
            report.sacred_overlap_candidate_count >= 1,
            "configured protected child should make its artifact-looking parent sacred"
        );
    }

    #[test]
    fn completions_support_bash_zsh_and_fish() {
        for shell in ["bash", "zsh", "fish"] {
            let parsed = Cli::try_parse_from(["sbh", "completions", shell]);
            assert!(parsed.is_ok(), "failed shell parse for {shell}");
        }
    }

    /// Every counterfactual the explainer suggests must actually flip the
    /// engine's verdict when applied, and a vetoed candidate gets none.
    #[test]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::too_many_lines
    )]
    fn counterfactual_suggestions_flip_the_decision_when_applied() {
        use storage_ballast_helper::scanner::patterns::{
            ArtifactPatternRegistry, StructuralSignals,
        };
        use storage_ballast_helper::scanner::scoring::{
            ActiveReferenceSummary, CandidateInput, DecisionAction, ScoringEngine,
        };

        let config = Config::default();
        let engine = ScoringEngine::from_config(&config.scoring, 0);
        let registry = ArtifactPatternRegistry::default();
        let candidate = |path: &str, signals: StructuralSignals, size_bytes: u64| CandidateInput {
            path: PathBuf::from(path),
            size_bytes,
            age: std::time::Duration::from_secs(60),
            classification: registry.classify(Path::new(path), signals),
            signals,
            active_references: ActiveReferenceSummary::default(),
            is_open: false,
            excluded: false,
        };
        // A minute-old Definite target is deleted even at Green, and the
        // weakest evidence cannot be flipped by any single knob. Take the
        // first candidate in between: not Delete now, flippable by something.
        let rust_markers = StructuralSignals {
            has_incremental: true,
            has_deps: true,
            has_build: true,
            has_fingerprint: true,
            ..StructuralSignals::default()
        };
        let attempts = [
            candidate("/data/tmp/fixture-proj/target", rust_markers, 256 * 1024),
            candidate("/data/tmp/fixture-proj/target", rust_markers, 4096),
            candidate(
                "/data/tmp/fixture-proj/target",
                StructuralSignals {
                    has_deps: true,
                    ..StructuralSignals::default()
                },
                64 * 1024 * 1024,
            ),
            candidate(
                "/data/tmp/fixture-proj/node_modules",
                StructuralSignals::default(),
                64 * 1024 * 1024,
            ),
            candidate(
                "/data/tmp/fixture-proj/build",
                StructuralSignals {
                    has_build: true,
                    ..StructuralSignals::default()
                },
                64 * 1024 * 1024,
            ),
        ];
        let mut chosen = None;
        let mut seen = Vec::new();
        for input in &attempts {
            let current = engine.score_candidate(input, 0.0);
            if current.decision.action == DecisionAction::Delete {
                seen.push(format!("{}: already Delete", input.path.display()));
                continue;
            }
            let suggestions = super::explain_counterfactuals(&engine, input, &current);
            if suggestions.iter().any(|s| s.needed.is_some()) {
                chosen = Some((input.clone(), current, suggestions));
                break;
            }
            seen.push(format!(
                "{}: {:?} with no single-factor flip",
                input.path.display(),
                current.decision.action
            ));
        }
        let (input, _current, suggestions) =
            chosen.unwrap_or_else(|| panic!("no flippable non-Delete candidate among {seen:?}"));
        let factors: Vec<&str> = suggestions.iter().map(|s| s.factor).collect();
        assert_eq!(factors, ["age", "size", "pressure"]);
        let mut flipped = 0;
        for suggestion in &suggestions {
            let Some(needed) = &suggestion.needed else {
                assert!(suggestion.note.is_some(), "{suggestion:?}");
                continue;
            };
            assert_eq!(suggestion.action_after, Some("Delete"));
            flipped += 1;
            let value = suggestion
                .needed_value
                .unwrap_or_else(|| panic!("{needed} has no numeric value: {suggestion:?}"));
            let mut modified = input.clone();
            let urgency = match suggestion.factor {
                "age" => {
                    modified.age = std::time::Duration::from_secs_f64(value);
                    0.0
                }
                "size" => {
                    modified.size_bytes = value.round() as u64;
                    0.0
                }
                "pressure" => value,
                other => panic!("unexpected factor {other}"),
            };
            assert_eq!(
                engine.score_candidate(&modified, urgency).decision.action,
                DecisionAction::Delete,
                "{} -> {needed} must flip to Delete",
                suggestion.factor
            );
        }
        assert!(
            flipped > 0,
            "at least one factor flips a Definite target: {suggestions:?}"
        );

        let vetoed = engine.hard_veto(&input, "test veto");
        let none = super::explain_counterfactuals(&engine, &input, &vetoed);
        assert_eq!(none.len(), 1);
        assert_eq!(none[0].factor, "veto");
        assert!(none[0].needed.is_none());
    }

    #[test]
    fn output_mode_resolution_honors_precedence() {
        assert_eq!(
            resolve_output_mode(true, Some("human"), true),
            OutputMode::Json
        );
        assert_eq!(
            resolve_output_mode(false, Some("json"), true),
            OutputMode::Json
        );
        assert_eq!(
            resolve_output_mode(false, Some("human"), false),
            OutputMode::Human
        );
        assert_eq!(
            resolve_output_mode(false, Some("auto"), true),
            OutputMode::Human
        );
        assert_eq!(resolve_output_mode(false, None, false), OutputMode::Json);
    }

    #[test]
    fn parse_window_duration_valid_inputs() {
        let cases = [
            ("10m", 600),
            ("30m", 1_800),
            ("1h", 3_600),
            ("24h", 86_400),
            ("7d", 604_800),
            ("90s", 90),
            ("15min", 900),
            ("2hr", 7_200),
            ("1day", 86_400),
            ("60", 3_600), // bare number defaults to minutes
        ];
        for (input, expected_secs) in cases {
            let d = parse_window_duration(input).unwrap_or_else(|e| {
                panic!("failed to parse {input:?}: {e}");
            });
            assert_eq!(
                d.as_secs(),
                expected_secs,
                "input={input:?} expected={expected_secs}s got={}s",
                d.as_secs(),
            );
        }
    }

    #[test]
    fn parse_window_duration_rejects_invalid() {
        assert!(parse_window_duration("").is_err());
        assert!(parse_window_duration("abc").is_err());
        assert!(parse_window_duration("10x").is_err());
    }

    #[test]
    fn blame_command_parses_since_and_tree_flags() {
        let parsed = Cli::try_parse_from(["sbh", "blame", "--top", "5", "--since", "1h", "--tree"])
            .expect("blame flags should parse");

        let Command::Blame(args) = parsed.command else {
            panic!("expected blame command");
        };
        assert_eq!(args.top, 5);
        assert_eq!(args.since, "1h");
        assert!(args.tree);
    }

    #[test]
    fn blame_report_ranks_processes_by_recent_writes_and_open_files() {
        let dir = TempDir::new().expect("temp dir should be created");
        let raw_root = dir.path().join("work");
        std::fs::create_dir(&raw_root).expect("root should be created");
        let root = raw_root.canonicalize().expect("root should canonicalize");
        let now = 1_700_000_000_000;
        let old_start = Some(now - (60 * 60 * 1_000));
        let mut config = Config::default();
        config.scanner.root_paths = vec![root.clone()];
        config.paths.state_file = dir.path().join("state.json");

        let mut history = ProcessIoHistory::new(dir.path().join("io_history.bin"));
        let _ = history.record_process_sample_at(
            blame_io(42, 1_000, 2_000),
            old_start,
            now - (10 * 60 * 1_000),
        );

        let open_path = root.join("target/debug/object.o");
        let platform = MockPlatform::healthy()
            .with_process(blame_process(
                42,
                Some(7),
                "rustc",
                vec!["rustc", "--crate-name", "demo"],
                old_start,
            ))
            .with_process_io(blame_io(42, 1_500, 102_000))
            .with_process(blame_process(
                7,
                None,
                "cargo",
                vec!["cargo", "test"],
                old_start,
            ))
            .with_process_io(blame_io(7, 10, 20))
            .with_open_file(OpenFile {
                pid: 42,
                path: open_path.clone(),
                fd: Some(3),
                kind: OpenFileKind::Regular,
                mode: OpenFileMode::ReadWrite,
            });

        let report = collect_blame_report_at(
            &config,
            &platform,
            &history,
            Duration::from_mins(15),
            10,
            now,
        )
        .expect("blame report should collect");

        assert_eq!(report.rows[0].pid, 42);
        assert_eq!(report.rows[0].recent_written_bytes, 100_000);
        assert_eq!(report.rows[0].recent_read_bytes, 500);
        assert_eq!(report.rows[0].open_files, vec![open_path]);
    }

    #[test]
    fn blame_tree_order_places_children_under_selected_parents() {
        let rows = vec![
            BlameRow {
                pid: 7,
                parent_pid: None,
                name: "cargo".to_string(),
                command: "cargo test".to_string(),
                executable: None,
                cwd: None,
                recent_read_bytes: 0,
                recent_written_bytes: 20,
                open_files: Vec::new(),
            },
            BlameRow {
                pid: 42,
                parent_pid: Some(7),
                name: "rustc".to_string(),
                command: "rustc".to_string(),
                executable: None,
                cwd: None,
                recent_read_bytes: 0,
                recent_written_bytes: 10,
                open_files: Vec::new(),
            },
        ];

        assert_eq!(blame_tree_order(&rows), vec![(0, 0), (1, 1)]);
    }

    #[test]
    fn stats_command_parses_with_all_flags() {
        let cases = [
            vec!["sbh", "stats"],
            vec!["sbh", "stats", "--window", "1h"],
            vec!["sbh", "stats", "--top-patterns", "10"],
            vec!["sbh", "stats", "--top-deletions", "5"],
            vec!["sbh", "stats", "--pressure-history"],
            vec![
                "sbh",
                "stats",
                "--window",
                "7d",
                "--top-patterns",
                "10",
                "--top-deletions",
                "5",
                "--pressure-history",
            ],
        ];
        for case in &cases {
            let parsed = Cli::try_parse_from(case.iter().copied());
            assert!(parsed.is_ok(), "failed to parse stats case: {case:?}");
        }
    }

    #[test]
    fn tune_command_parses_with_flags() {
        let cases = [
            vec!["sbh", "tune"],
            vec!["sbh", "tune", "--apply"],
            vec!["sbh", "tune", "--apply", "--yes"],
        ];
        for case in &cases {
            let parsed = Cli::try_parse_from(case.iter().copied());
            assert!(parsed.is_ok(), "failed to parse tune case: {case:?}");
        }
        // --yes without --apply should fail.
        assert!(Cli::try_parse_from(["sbh", "tune", "--yes"]).is_err());
    }

    #[test]
    fn clean_time_machine_snapshot_flags_parse() {
        let parsed = Cli::try_parse_from([
            "sbh",
            "clean",
            "--thin-local-snapshots",
            "--local-snapshot-mount",
            "/System/Volumes/Data",
            "--dry-run",
        ])
        .expect("Time Machine thinning flags should parse");

        let Command::Clean(args) = parsed.command else {
            panic!("expected clean command");
        };
        assert!(args.thin_local_snapshots);
        assert_eq!(
            args.local_snapshot_mount.as_deref(),
            Some(Path::new("/System/Volumes/Data"))
        );
        assert!(args.dry_run);
    }

    #[test]
    fn clean_local_snapshot_mount_requires_thin_flag_at_runtime() {
        let tmp = TempDir::new().unwrap();
        let config_path = tmp.path().join("config.toml");
        std::fs::write(
            &config_path,
            format!(
                "[scanner]\nroot_paths = [\"{}\"]\n",
                tmp.path().to_string_lossy()
            ),
        )
        .unwrap();

        let parsed = Cli::try_parse_from([
            "sbh",
            "--config",
            config_path.to_str().unwrap(),
            "clean",
            "--local-snapshot-mount",
            "/",
        ])
        .unwrap();

        let error = run(&parsed).expect_err("mount flag without thinning should fail");
        assert!(
            error
                .to_string()
                .contains("--local-snapshot-mount requires --thin-local-snapshots")
        );
    }

    #[test]
    fn local_snapshot_thin_shell_command_uses_force_thin_contract() {
        assert_eq!(
            local_snapshot_thin_shell_command(Path::new("/System/Volumes/Data")),
            "sudo tmutil thinlocalsnapshots /System/Volumes/Data 9999999999999999 4"
        );
        assert_eq!(
            local_snapshot_thin_shell_command(Path::new("/Volumes/Build Cache")),
            "sudo tmutil thinlocalsnapshots '/Volumes/Build Cache' 9999999999999999 4"
        );
    }

    #[test]
    fn generate_recommendations_empty_stats_returns_none() {
        let config = Config::default();
        let recs = generate_recommendations(&config, &[]);
        assert!(recs.is_empty());
    }

    /// bd-rc-master-ajg1.2.18: the pool size follows the observed bursts and
    /// the doctor check compares what is releasable against it.
    #[test]
    fn burst_windows_size_the_pool_and_gate_the_doctor_check() {
        let dir = tempfile::tempdir().unwrap();
        let mut bursts = BurstStats::new(dir.path().join("burst_stats.bin"));
        let mount = PathBuf::from("/data");
        let mut config = Config::default();
        config.ballast.file_count = 4;
        config.ballast.file_size_bytes = 64 << 20;
        let file_size = config.ballast.effective_file_size_bytes("/data");
        assert_eq!(file_size, 64 << 20);
        let pools = vec![ReservePool {
            mount: mount.clone(),
            releasable_bytes: 4 * file_size,
        }];

        // No windows yet: nothing to recommend, the doctor passes with a note.
        assert!(burst_reserve_recommendations(&config, &bursts, &pools).is_empty());
        let checks = reserve_coverage_doctor_checks(&config, &bursts, &pools);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].status, "PASS");
        assert!(
            checks[0].message.contains("no reaction windows"),
            "{:?}",
            checks[0]
        );

        // Sixty windows: fifty-nine quiet, one 1 GiB burst; q99 lands on it.
        for _ in 0..59 {
            bursts.mount_mut(&mount).push_sample(1e6);
        }
        bursts.mount_mut(&mount).push_sample(f64::from(1u32 << 30));
        let recs = burst_reserve_recommendations(&config, &bursts, &pools);
        assert_eq!(recs.len(), 1, "{recs:?}");
        let rec = &recs[0];
        assert_eq!(rec.config_key, "ballast.file_count");
        assert_eq!(rec.category, TuningCategory::Ballast);
        assert_eq!(rec.current_value, "4");
        // 1 GiB / 64 MiB = 16 files.
        assert_eq!(rec.suggested_value, "16");
        assert!(
            rec.rationale.contains("reaction windows"),
            "{}",
            rec.rationale
        );
        assert!(rec.confidence > 0.7);
        assert_eq!(rec.risk, TuningRisk::Low);

        let checks = reserve_coverage_doctor_checks(&config, &bursts, &pools);
        assert_eq!(checks[0].status, "FAIL", "{:?}", checks[0]);
        assert!(
            checks[0].message.contains("coverage 0.25"),
            "{}",
            checks[0].message
        );
        assert!(
            checks[0]
                .remediation
                .as_deref()
                .is_some_and(|r| r.contains("16 files")),
            "{:?}",
            checks[0].remediation
        );

        // A pool holding the recommendation passes; per-mount keys are used
        // once a second pool exists.
        let covered = vec![
            ReservePool {
                mount: mount.clone(),
                releasable_bytes: 16 * file_size,
            },
            ReservePool {
                mount: PathBuf::from("/home"),
                releasable_bytes: 0,
            },
        ];
        let checks = reserve_coverage_doctor_checks(&config, &bursts, &covered);
        assert_eq!(checks[0].status, "PASS", "{:?}", checks[0]);
        let recs = burst_reserve_recommendations(&config, &bursts, &covered);
        assert_eq!(recs.len(), 1, "{recs:?}");
        assert_eq!(recs[0].config_key, "ballast.overrides./data.file_count");
        // No pools at all: one PASS check saying so.
        let none = reserve_coverage_doctor_checks(&config, &bursts, &[]);
        assert_eq!(none.len(), 1);
        assert!(none[0].message.contains("no ballast pool"));
    }

    /// bd-rc-master-ajg1.7.4: the doctor names the shared mount and grades it
    /// WARN without a fresh daemon state, PASS when nothing is reclaimed there.
    #[test]
    fn logging_placement_doctor_check_grades_the_shared_mount() {
        use std::collections::HashMap;
        use storage_ballast_helper::platform::pal::{
            FsStats, MemoryInfo, MockPlatform, MountPoint, PlatformPaths,
        };
        // Two mounts: "/" (where the special locations live) and "/state"
        // for the daemon's own files.
        let stats = |mount: &str| FsStats {
            total_bytes: 1_000_000_000_000,
            free_bytes: 500_000_000_000,
            available_bytes: 500_000_000_000,
            fs_type: "mockfs".to_string(),
            mount_point: PathBuf::from(mount),
            is_readonly: false,
        };
        let mount = |path: &str| MountPoint {
            path: PathBuf::from(path),
            device: format!("mock{path}"),
            fs_type: "mockfs".to_string(),
            is_ram_backed: false,
        };
        // The files' mount is a real directory, because paths resolve
        // through their nearest existing ancestor before the mock lookup.
        let dir = tempfile::tempdir().unwrap();
        let state_mount = dir.path().to_string_lossy().into_owned();
        let mut stats_by_mount = HashMap::new();
        stats_by_mount.insert(PathBuf::from("/"), stats("/"));
        stats_by_mount.insert(dir.path().to_path_buf(), stats(&state_mount));
        let platform = MockPlatform::new(
            vec![mount("/"), mount(&state_mount)],
            stats_by_mount,
            MemoryInfo {
                total_bytes: 64 << 30,
                available_bytes: 32 << 30,
                swap_total_bytes: 0,
                swap_free_bytes: 0,
            },
            PlatformPaths::default(),
        );
        let mut config = Config::default();
        config.paths.state_file = dir.path().join("sbh").join("state.json");
        config.paths.sqlite_db = dir.path().join("sbh").join("activity.sqlite3");
        config.paths.jsonl_log = dir.path().join("sbh").join("activity.jsonl");
        config.scanner.root_paths = vec![PathBuf::from("/")];

        // Scan root and special locations on "/", the files on their own mount.
        let clear = logging_placement_doctor_check(&platform, &config, &[]);
        assert_eq!(clear.id, "logging.on_monitored_fs");
        assert_eq!(clear.status, "PASS", "{clear:?}");
        assert!(clear.message.contains(&state_mount), "{}", clear.message);

        // A scan root on the files' mount: WARN without a fresh daemon
        // state (the level is unknown), never FAIL.
        let work = dir.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        config.scanner.root_paths = vec![work];
        let shared = logging_placement_doctor_check(&platform, &config, &[]);
        assert_eq!(shared.status, "WARN", "{shared:?}");
        assert!(
            shared.message.contains("level unknown"),
            "{}",
            shared.message
        );
        assert!(
            shared.message.contains("activity.jsonl"),
            "{}",
            shared.message
        );
        assert!(shared.remediation.is_some());

        // A ballast pool on the mount counts as a reclaim target too.
        config.scanner.root_paths = vec![PathBuf::from("/")];
        let pools = vec![ReservePool {
            mount: dir.path().to_path_buf(),
            releasable_bytes: 0,
        }];
        let pooled = logging_placement_doctor_check(&platform, &config, &pools);
        assert_eq!(pooled.status, "WARN", "{pooled:?}");
    }

    /// bd-rc-master-ajg1.5.4: the first present value wins, blanks are
    /// skipped, and nothing at all is "unknown", never a panic.
    #[test]
    fn build_field_prefers_the_first_present_value() {
        assert_eq!(build_field(&[None, None]), "unknown");
        assert_eq!(build_field(&[]), "unknown");
        assert_eq!(build_field(&[Some(""), Some("  "), Some("abc")]), "abc");
        assert_eq!(build_field(&[Some("first"), Some("second")]), "first");
        assert_eq!(build_field(&[None, Some(" deadbeef ")]), "deadbeef");
    }

    /// bd-rc-master-ajg1.5.4: a repository build carries real metadata from
    /// build.rs: a git sha (optionally `-dirty`), a target triple, the
    /// profile, and an RFC 3339 UTC timestamp.
    #[test]
    fn repository_builds_carry_real_build_metadata() {
        let sha: &str = option_env!("SBH_BUILD_GIT_SHA").unwrap_or("");
        // build.rs asks `git rev-parse --short=12 HEAD`. Where that fails at
        // test time as well (a mirror without .git objects, such as an rch
        // worker) the sha is legitimately absent; the git-free fields are
        // still checked.
        let git_answers = std::process::Command::new("git")
            .args(["rev-parse", "--short=12", "HEAD"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .is_ok_and(|output| output.status.success());
        if git_answers {
            assert!(!sha.is_empty(), "build.rs sets the sha in a checkout");
            let hex = sha.trim_end_matches("-dirty");
            assert!(
                hex.len() >= 7 && hex.chars().all(|c| c.is_ascii_hexdigit()),
                "{sha}"
            );
        } else {
            println!("SKIP: git cannot resolve HEAD here; sha check skipped (sha={sha:?})");
        }
        let target: &str = option_env!("SBH_BUILD_TARGET").unwrap_or("");
        assert!(
            target.contains('-'),
            "build.rs re-exports TARGET: {target:?}"
        );
        let profile: &str = option_env!("SBH_BUILD_PROFILE").unwrap_or("");
        assert!(
            matches!(profile, "debug" | "release"),
            "build.rs re-exports PROFILE: {profile:?}"
        );
        let stamp: &str = option_env!("SBH_BUILD_TIMESTAMP").unwrap_or("");
        assert_eq!(stamp.len(), 20, "build.rs sets the timestamp: {stamp:?}");
        assert!(
            stamp.ends_with('Z') && stamp.as_bytes()[10] == b'T',
            "{stamp}"
        );
        assert!(stamp.starts_with("20"), "{stamp}");
    }

    #[test]
    fn generate_recommendations_ballast_exhaustion() {
        use storage_ballast_helper::logger::stats::*;

        let config = Config::default();
        let ws = WindowStats {
            policy: storage_ballast_helper::logger::stats::PolicyStats::default(),
            window: std::time::Duration::from_hours(24),
            deletions: DeletionStats::default(),
            ballast: BallastStats {
                files_released: 10,
                files_replenished: 0,
                current_inventory: 0,
                bytes_available: 0,
            },
            pressure: PressureStats::default(),
        };

        let recs = generate_recommendations(&config, &[ws]);
        assert!(
            recs.iter()
                .any(|r| r.config_key == "ballast.file_count"
                    && r.category == TuningCategory::Ballast),
            "expected ballast file_count recommendation",
        );
    }

    #[test]
    fn generate_recommendations_high_oscillation() {
        use storage_ballast_helper::logger::stats::*;

        let config = Config::default();
        let ws = WindowStats {
            policy: storage_ballast_helper::logger::stats::PolicyStats::default(),
            window: std::time::Duration::from_hours(24),
            deletions: DeletionStats::default(),
            ballast: BallastStats::default(),
            pressure: PressureStats {
                time_in_green_pct: 50.0,
                time_in_yellow_pct: 30.0,
                time_in_orange_pct: 15.0,
                time_in_red_pct: 5.0,
                time_in_critical_pct: 0.0,
                transitions: 15,
                worst_level_reached: PressureLevel::Red,
                current_level: PressureLevel::Green,
                current_free_pct: 22.0,
            },
        };

        let recs = generate_recommendations(&config, &[ws]);
        // Should have threshold recommendations for elevated time and oscillation.
        assert!(
            recs.iter().any(|r| r.category == TuningCategory::Threshold),
            "expected threshold recommendation for oscillation/elevated pressure",
        );
    }

    #[test]
    fn generate_recommendations_high_failure_rate() {
        use storage_ballast_helper::logger::stats::*;

        let mut config = Config::default();
        config.scanner.min_file_age_minutes = 15; // Low value to trigger recommendation.

        let ws = WindowStats {
            policy: storage_ballast_helper::logger::stats::PolicyStats::default(),
            window: std::time::Duration::from_hours(1),
            deletions: DeletionStats {
                count: 10,
                total_bytes_freed: 1_000_000,
                quarantined_count: 0,
                quarantined_bytes: 0,
                avg_size: 100_000,
                median_size: 80_000,
                largest_deletion: None,
                most_common_category: None,
                avg_score: 0.85,
                avg_age_hours: 1.0,
                failures: 5,
                failures_by_reason: Vec::new(),
            },
            ballast: BallastStats::default(),
            pressure: PressureStats::default(),
        };

        let recs = generate_recommendations(&config, &[ws]);
        assert!(
            recs.iter()
                .any(|r| r.config_key == "scanner.min_file_age_minutes"),
            "expected min_file_age recommendation for high failure rate",
        );
    }

    #[test]
    fn setup_command_parses_with_flags() {
        let cases = [
            vec!["sbh", "setup", "--all"],
            vec!["sbh", "setup", "--path"],
            vec!["sbh", "setup", "--verify"],
            vec!["sbh", "setup", "--completions", "bash"],
            vec!["sbh", "setup", "--completions", "bash,zsh,fish"],
            vec!["sbh", "setup", "--path", "--verify", "--dry-run"],
            vec![
                "sbh",
                "setup",
                "--all",
                "--profile",
                "/home/user/.bashrc",
                "--bin-dir",
                "/usr/local/bin",
                "--dry-run",
            ],
        ];
        for case in &cases {
            let parsed = Cli::try_parse_from(case.iter().copied());
            assert!(parsed.is_ok(), "failed to parse setup case: {case:?}");
        }
    }

    #[test]
    fn help_includes_new_command_surface() {
        let mut cmd = Cli::command();
        let help = cmd.render_long_help().to_string();
        for keyword in [
            "emergency",
            "protect",
            "unprotect",
            "tune",
            "check",
            "blame",
            "dashboard",
            "completions",
            "update",
            "setup",
        ] {
            assert!(
                help.contains(keyword),
                "help output missing command: {keyword}"
            );
        }
    }

    fn render_subcommand_long_help(name: &str) -> String {
        let mut cmd = Cli::command();
        cmd.find_subcommand_mut(name)
            .unwrap_or_else(|| panic!("missing subcommand {name}"))
            .render_long_help()
            .to_string()
    }

    #[test]
    fn help_mentions_platform_autodetection_and_macos_behavior() {
        let mut cmd = Cli::command();
        let top_help = cmd.render_long_help().to_string();
        for fragment in [
            "Linux/macOS disk space guardian",
            "auto-detects Linux/systemd and macOS/launchd",
            "APFS-aware ballast checks",
            "Full Disk Access diagnostics",
        ] {
            assert!(
                top_help.contains(fragment),
                "top-level help missing platform fragment: {fragment}"
            );
        }

        let cases: &[(&str, &[&str])] = &[
            (
                "install",
                &[
                    "Omit --systemd/--launchd for auto-detection",
                    "launchd user scope",
                    "Full Disk Access",
                ],
            ),
            (
                "uninstall",
                &[
                    "Omit --systemd/--launchd for auto-detection",
                    "launchd plist discovery",
                ],
            ),
            (
                "service",
                &[
                    "Omit --systemd/--launchd for auto-detection",
                    "launchctl",
                    "plist path",
                ],
            ),
            (
                "doctor",
                &[
                    "launchd",
                    "APFS",
                    "codesign/notarization",
                    "Full Disk Access",
                ],
            ),
            (
                "clean",
                &["Time Machine/APFS", "does not delete user paths"],
            ),
            (
                "ballast",
                &["APFS-aware preallocation", "Time Machine local snapshots"],
            ),
        ];

        for (subcommand, fragments) in cases {
            let help = render_subcommand_long_help(subcommand);
            for fragment in *fragments {
                assert!(
                    help.contains(fragment),
                    "{subcommand} help missing platform fragment: {fragment}"
                );
            }
        }
    }

    #[test]
    fn emergency_install_hint_uses_auto_detected_install() {
        let hint = ongoing_protection_install_hint();
        assert_eq!(hint, "sbh install --auto");
        assert!(
            !hint.contains("--systemd"),
            "emergency hint must not recommend Linux-only service flags"
        );
    }

    #[test]
    fn update_command_parses_with_flags() {
        let cases = [
            vec!["sbh", "update", "--check"],
            vec!["sbh", "update", "--check", "--json"],
            vec!["sbh", "update", "--version", "v0.2.0"],
            vec!["sbh", "update", "--version", "0.2.0", "--force"],
            vec!["sbh", "update", "--dry-run"],
            vec!["sbh", "update", "--offline", "/tmp/bundle-manifest.json"],
            vec!["sbh", "update", "--refresh-cache", "--check"],
            vec!["sbh", "update", "--no-verify", "--force"],
            vec!["sbh", "update", "--system"],
            vec!["sbh", "update", "--user"],
            vec![
                "sbh",
                "update",
                "--version",
                "v1.0.0",
                "--dry-run",
                "--user",
            ],
            vec!["sbh", "update", "--list-backups"],
            vec!["sbh", "update", "--rollback"],
            vec!["sbh", "update", "--rollback", "1000000-v0.1.0"],
            vec!["sbh", "update", "--prune", "3"],
            vec!["sbh", "update", "--max-backups", "10"],
        ];
        for case in &cases {
            let parsed = Cli::try_parse_from(case.iter().copied());
            assert!(parsed.is_ok(), "failed to parse update case: {case:?}");
        }
    }

    #[test]
    fn update_system_and_user_conflict() {
        assert!(Cli::try_parse_from(["sbh", "update", "--system", "--user"]).is_err());
    }

    #[test]
    fn update_args_default_is_check_false() {
        let args = UpdateArgs::default();
        assert!(!args.check);
        assert!(!args.force);
        assert!(!args.no_verify);
        assert!(!args.dry_run);
        assert!(!args.refresh_cache);
        assert!(args.offline.is_none());
        assert!(!args.system);
        assert!(!args.user);
        assert!(args.version.is_none());
        assert!(args.rollback.is_none());
        assert!(!args.list_backups);
        assert!(args.prune.is_none());
        assert_eq!(args.max_backups, 5);
    }

    #[test]
    fn update_options_include_cache_and_notice_config() {
        let mut config = Config::default();
        config.update.metadata_cache_ttl_seconds = 42;
        config.update.metadata_cache_file = PathBuf::from("/tmp/custom-update-cache.json");
        config.update.notices_enabled = false;

        let args = UpdateArgs {
            check: true,
            force: true,
            refresh_cache: true,
            offline: Some(PathBuf::from("/tmp/offline-bundle.json")),
            version: Some("v1.2.3".to_string()),
            ..UpdateArgs::default()
        };

        let install_dir = PathBuf::from("/tmp/bin");
        let opts = build_update_options(&args, &config, install_dir.clone());

        assert!(opts.check_only);
        assert_eq!(opts.pinned_version, Some("v1.2.3".to_string()));
        assert!(opts.force);
        assert_eq!(opts.install_dir, install_dir);
        assert!(opts.refresh_cache);
        assert_eq!(
            opts.offline_bundle_manifest,
            Some(PathBuf::from("/tmp/offline-bundle.json"))
        );
        assert_eq!(
            opts.metadata_cache_file,
            PathBuf::from("/tmp/custom-update-cache.json")
        );
        assert_eq!(opts.metadata_cache_ttl, std::time::Duration::from_secs(42));
        assert!(!opts.notices_enabled);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn bytes_to_pct_handles_zero_total() {
        assert_eq!(bytes_to_pct(100, 0), 0.0);
        assert_eq!(bytes_to_pct(50, 200), 25.0);
    }

    #[test]
    fn capacity_free_pct_uses_effective_capacity_totals() {
        let capacity = Capacity {
            mount_point: PathBuf::from("/System/Volumes/Data"),
            fs_type: "apfs".to_string(),
            total_bytes: 1_000,
            free_bytes: 250,
            available_bytes: 250,
            is_readonly: false,
            container_id: Some("/dev/disk3".to_string()),
            container_total_bytes: Some(1_000),
            container_available_bytes: Some(250),
            volume_total_bytes: Some(400),
            volume_available_bytes: Some(100),
            volume_role: Some("Data".to_string()),
            shared_volumes: vec!["Macintosh HD".to_string(), "VM".to_string()],
            is_primary: true,
            purgeable_bytes: None,
            local_snapshot_bytes: None,
        };

        assert!((capacity_free_pct(&capacity) - 25.0).abs() < f64::EPSILON);
    }

    #[test]
    fn capacity_free_pct_excludes_purgeable_capacity() {
        let capacity = Capacity {
            mount_point: PathBuf::from("/System/Volumes/Data"),
            fs_type: "apfs".to_string(),
            total_bytes: 1_000,
            free_bytes: 100,
            available_bytes: 100,
            is_readonly: false,
            container_id: Some("/dev/disk3".to_string()),
            container_total_bytes: Some(1_000),
            container_available_bytes: Some(100),
            volume_total_bytes: Some(400),
            volume_available_bytes: Some(100),
            volume_role: Some("Data".to_string()),
            shared_volumes: Vec::new(),
            is_primary: true,
            purgeable_bytes: Some(500),
            local_snapshot_bytes: None,
        };

        assert!((capacity_free_pct(&capacity) - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn status_mount_json_exposes_apfs_container_metadata() {
        let capacity = Capacity {
            mount_point: PathBuf::from("/System/Volumes/Data"),
            fs_type: "apfs".to_string(),
            total_bytes: 1_000,
            free_bytes: 250,
            available_bytes: 250,
            is_readonly: false,
            container_id: Some("/dev/disk3".to_string()),
            container_total_bytes: Some(1_000),
            container_available_bytes: Some(250),
            volume_total_bytes: Some(400),
            volume_available_bytes: Some(100),
            volume_role: Some("Data".to_string()),
            shared_volumes: vec!["Macintosh HD".to_string(), "VM".to_string()],
            is_primary: true,
            purgeable_bytes: Some(32),
            local_snapshot_bytes: Some(64),
        };

        let payload = status_mount_json(&capacity, "yellow", 25.0);

        assert_eq!(payload["path"], "/System/Volumes/Data");
        assert_eq!(payload["total"], 1_000);
        assert_eq!(payload["free"], 250);
        assert_eq!(payload["container_id"], "/dev/disk3");
        assert_eq!(payload["container_total"], 1_000);
        assert_eq!(payload["container_available"], 250);
        assert_eq!(payload["volume_total"], 400);
        assert_eq!(payload["volume_available"], 100);
        assert_eq!(payload["volume_role"], "Data");
        assert_eq!(payload["shared_volumes"], json!(["Macintosh HD", "VM"]));
        assert_eq!(payload["is_primary"], true);
        assert_eq!(payload["purgeable_bytes"], 32);
        assert_eq!(payload["free_excludes_purgeable"], true);
        assert_eq!(payload["local_snapshot_bytes"], 64);
        assert_eq!(
            payload["local_snapshot_reclaim_command"],
            "sudo tmutil thinlocalsnapshots /System/Volumes/Data 9999999999999999 4"
        );

        let apfs = &payload["platform"]["darwin"]["apfs"];
        assert_eq!(apfs["container_id"], "/dev/disk3");
        assert_eq!(apfs["container_total_bytes"], 1_000);
        assert_eq!(apfs["container_available_bytes"], 250);
        assert_eq!(apfs["volume_total_bytes"], 400);
        assert_eq!(apfs["volume_available_bytes"], 100);
        assert_eq!(apfs["volume_role"], "Data");
        assert_eq!(apfs["shared_volumes"], json!(["Macintosh HD", "VM"]));
        assert_eq!(apfs["is_primary"], true);
        assert_eq!(apfs["purgeable_bytes"], 32);
        assert_eq!(apfs["local_snapshot_bytes"], 64);
        assert_eq!(apfs["free_excludes_purgeable"], true);
        assert!(payload["platform"].get("linux").is_none());
    }

    #[test]
    fn status_mount_json_keys_the_platform_block_by_filesystem_family() {
        let capacity = Capacity {
            mount_point: PathBuf::from("/"),
            fs_type: "ext4".to_string(),
            total_bytes: 1_000,
            free_bytes: 250,
            available_bytes: 250,
            is_readonly: false,
            container_id: None,
            container_total_bytes: None,
            container_available_bytes: None,
            volume_total_bytes: None,
            volume_available_bytes: None,
            volume_role: None,
            shared_volumes: Vec::new(),
            is_primary: false,
            purgeable_bytes: None,
            local_snapshot_bytes: None,
        };

        let payload = status_mount_json(&capacity, "green", 25.0);
        assert_eq!(payload["fs_type"], "ext4");
        assert_eq!(payload["free"], 250);
        for apfs_only in [
            "container_id",
            "container_total",
            "container_available",
            "volume_role",
            "shared_volumes",
            "is_primary",
            "purgeable_bytes",
            "free_excludes_purgeable",
            "local_snapshot_bytes",
            "local_snapshot_reclaim_command",
        ] {
            assert!(
                payload.get(apfs_only).is_none(),
                "{apfs_only} must not appear on a non-APFS mount"
            );
        }
        assert!(payload["platform"].get("darwin").is_none());
        let platform = capacity_platform_json(&capacity);
        if cfg!(target_os = "linux") {
            assert_eq!(platform["linux"]["fs_type"], "ext4");
            assert_eq!(platform["linux"]["is_ram_backed"], false);
            assert_eq!(platform["linux"]["is_readonly"], false);
            assert!(
                platform["linux"]["device_id"].is_u64(),
                "the root mount can always be stat'ed: {platform}"
            );
            let shm = Capacity {
                mount_point: PathBuf::from("/nonexistent-sbh-mount"),
                fs_type: "tmpfs".to_string(),
                ..capacity
            };
            let platform = capacity_platform_json(&shm);
            assert_eq!(platform["linux"]["is_ram_backed"], true);
            assert!(platform["linux"]["device_id"].is_null());
        } else {
            assert_eq!(platform, json!({}));
        }
    }

    #[test]
    fn macos_process_attribution_visibility_reports_user_scope_without_root() {
        let visibility = process_attribution_visibility_for("macos", false)
            .expect("macOS should report process attribution visibility");
        let payload = process_attribution_visibility_json(&visibility);

        assert_eq!(visibility.scope, "own_user_processes");
        assert!(!visibility.all_processes);
        assert!(visibility.requires_root_for_all_users);
        assert_eq!(payload["scope"], "own_user_processes");
        assert_eq!(payload["all_processes"], false);
        assert_eq!(payload["requires_root_for_all_users"], true);
        assert!(
            payload["detail"]
                .as_str()
                .is_some_and(|detail| detail.contains("own-user processes only"))
        );
    }

    #[test]
    fn macos_process_attribution_visibility_reports_all_processes_as_root() {
        let visibility = process_attribution_visibility_for("macos", true)
            .expect("macOS should report process attribution visibility");
        let payload = process_attribution_visibility_json(&visibility);

        assert_eq!(visibility.scope, "all_processes");
        assert!(visibility.all_processes);
        assert!(!visibility.requires_root_for_all_users);
        assert_eq!(payload["scope"], "all_processes");
        assert_eq!(payload["all_processes"], true);
        assert_eq!(payload["requires_root_for_all_users"], false);
        assert!(
            payload["detail"]
                .as_str()
                .is_some_and(|detail| detail.contains("root/LaunchDaemon"))
        );
    }

    #[test]
    fn process_attribution_visibility_is_macos_specific() {
        assert!(process_attribution_visibility_for("linux", false).is_none());
    }

    fn cli_app_snapshot_settings(assertion: impl FnOnce()) {
        let mut settings = insta::Settings::clone_current();
        settings.set_snapshot_path("../tests/snapshots");
        settings.set_prepend_module_to_snapshot(false);
        settings.set_omit_expression(true);
        settings.bind(assertion);
    }

    #[test]
    fn status_memory_pressure_json_matches_snapshot() {
        let pressure = MemoryPressure {
            level: MemoryPressureLevel::Warn,
            free_pages: Some(1_234),
            used_pages: Some(5_678),
            page_size_bytes: Some(4_096),
            compressor_used_bytes: Some(987_654_321),
            swap_total_bytes: Some(2_147_483_648),
            swap_used_bytes: Some(1_073_741_824),
            linux_psi_avg10: None,
        };
        let payload = status_memory_pressure_json(&pressure);
        let rendered = serde_json::to_string_pretty(&payload).expect("snapshot JSON renders");

        cli_app_snapshot_settings(|| {
            insta::assert_snapshot!("status_memory_pressure_json", rendered);
        });
    }

    #[test]
    fn purgeable_storage_notice_reports_bytes_separately() {
        let capacity = Capacity {
            mount_point: PathBuf::from("/"),
            fs_type: "apfs".to_string(),
            total_bytes: 1_000,
            free_bytes: 250,
            available_bytes: 250,
            is_readonly: false,
            container_id: Some("/dev/disk3".to_string()),
            container_total_bytes: Some(1_000),
            container_available_bytes: Some(250),
            volume_total_bytes: Some(400),
            volume_available_bytes: Some(100),
            volume_role: Some("Data".to_string()),
            shared_volumes: Vec::new(),
            is_primary: true,
            purgeable_bytes: Some(64),
            local_snapshot_bytes: None,
        };

        let notice = purgeable_storage_notice(&capacity).expect("notice should be present");

        assert!(notice.contains("/ reports 64 B purgeable APFS storage"));
    }

    #[test]
    fn local_snapshot_warning_includes_reclaim_command() {
        let capacity = Capacity {
            mount_point: PathBuf::from("/"),
            fs_type: "apfs".to_string(),
            total_bytes: 1_000,
            free_bytes: 250,
            available_bytes: 250,
            is_readonly: false,
            container_id: Some("/dev/disk3".to_string()),
            container_total_bytes: Some(1_000),
            container_available_bytes: Some(250),
            volume_total_bytes: Some(400),
            volume_available_bytes: Some(100),
            volume_role: Some("Data".to_string()),
            shared_volumes: Vec::new(),
            is_primary: true,
            purgeable_bytes: None,
            local_snapshot_bytes: Some(64),
        };

        let warning = local_snapshot_warning(&capacity).expect("warning should be present");

        assert!(warning.contains("64 B retained by local Time Machine snapshots"));
        assert!(warning.contains("sudo tmutil thinlocalsnapshots / 9999999999999999 4"));
    }

    #[test]
    fn swap_thrash_risk_requires_high_swap_and_low_ram() {
        // High swap + ample RAM → NOT risky (cold pages swapped, normal).
        let cold_pages = MemoryInfo {
            total_bytes: 128 * 1024 * 1024 * 1024,
            available_bytes: 64 * 1024 * 1024 * 1024,
            swap_total_bytes: 72 * 1024 * 1024 * 1024,
            swap_free_bytes: 10 * 1024 * 1024 * 1024,
        };
        assert!(!is_swap_thrash_risk(&cold_pages));

        // High swap + low RAM → RISKY (genuine memory exhaustion).
        let thrashing = MemoryInfo {
            total_bytes: 128 * 1024 * 1024 * 1024,
            available_bytes: 2 * 1024 * 1024 * 1024,
            swap_total_bytes: 72 * 1024 * 1024 * 1024,
            swap_free_bytes: 10 * 1024 * 1024 * 1024,
        };
        assert!(is_swap_thrash_risk(&thrashing));
    }

    #[test]
    fn swap_thrash_risk_ignores_no_swap_or_low_usage() {
        let no_swap = MemoryInfo {
            total_bytes: 64 * 1024 * 1024 * 1024,
            available_bytes: 16 * 1024 * 1024 * 1024,
            swap_total_bytes: 0,
            swap_free_bytes: 0,
        };
        assert!(!is_swap_thrash_risk(&no_swap));

        let low_swap = MemoryInfo {
            total_bytes: 64 * 1024 * 1024 * 1024,
            available_bytes: 32 * 1024 * 1024 * 1024,
            swap_total_bytes: 32 * 1024 * 1024 * 1024,
            swap_free_bytes: 16 * 1024 * 1024 * 1024,
        };
        assert!(!is_swap_thrash_risk(&low_swap));
    }
}
