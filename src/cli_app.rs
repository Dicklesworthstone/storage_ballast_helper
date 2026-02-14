//! Top-level CLI definition and dispatch.

use std::collections::HashSet;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use clap::{ArgGroup, Args, CommandFactory, Parser, Subcommand};
use clap_complete::{Shell as CompletionShell, generate};
use colored::control;
use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;

use storage_ballast_helper::ballast::manager::BallastManager;
use storage_ballast_helper::core::config::Config;
use storage_ballast_helper::daemon::service::{
    LaunchdServiceManager, ServiceActionResult, SystemdServiceManager,
};
use storage_ballast_helper::logger::sqlite::SqliteLogger;
use storage_ballast_helper::logger::stats::{StatsEngine, window_label};
use storage_ballast_helper::platform::pal::{LinuxPlatform, Platform, ServiceManager};
use storage_ballast_helper::scanner::deletion::{DeletionConfig, DeletionExecutor, DeletionPlan};
use storage_ballast_helper::scanner::patterns::ArtifactPatternRegistry;
use storage_ballast_helper::scanner::protection::{self, ProtectionRegistry};
use storage_ballast_helper::scanner::scoring::{CandidacyScore, CandidateInput, ScoringEngine};
use storage_ballast_helper::scanner::walker::{
    DirectoryWalker, WalkerConfig, collect_open_files, is_path_open,
};

/// Storage Ballast Helper — prevents disk-full scenarios from coding agent swarms.
#[derive(Debug, Parser)]
#[command(
    name = "sbh",
    author,
    version,
    about = "Storage Ballast Helper - Disk Space Guardian",
    long_about = None,
    arg_required_else_help = true
)]
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
    /// Install sbh as a system service.
    Install(InstallArgs),
    /// Remove sbh system integration.
    Uninstall(UninstallArgs),
    /// Show current health and pressure status.
    Status(StatusArgs),
    /// Show aggregated historical statistics.
    Stats(StatsArgs),
    /// Run a manual scan for reclaim candidates.
    Scan(ScanArgs),
    /// Run a manual cleanup pass.
    Clean(CleanArgs),
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
    /// Show/apply tuning recommendations.
    Tune(TuneArgs),
    /// Pre-build disk pressure check.
    Check(CheckArgs),
    /// Attribute disk pressure by process/agent.
    Blame(BlameArgs),
    /// Live TUI-style dashboard.
    Dashboard(DashboardArgs),
    /// Generate shell completions.
    Completions(CompletionsArgs),
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
}

#[derive(Debug, Clone, Args, Serialize, Default)]
struct InstallArgs {
    /// Install systemd service units (Linux).
    #[arg(long, conflicts_with = "launchd")]
    systemd: bool,
    /// Install launchd service plist (macOS).
    #[arg(long, conflicts_with = "systemd")]
    launchd: bool,
    /// Install in user service scope.
    #[arg(long)]
    user: bool,
}

#[derive(Debug, Clone, Args, Serialize, Default)]
struct UninstallArgs {
    /// Remove systemd service units (Linux).
    #[arg(long, conflicts_with = "launchd")]
    systemd: bool,
    /// Remove launchd service plist (macOS).
    #[arg(long, conflicts_with = "systemd")]
    launchd: bool,
    /// Remove all generated state and logs.
    #[arg(long)]
    purge: bool,
}

#[derive(Debug, Clone, Args, Serialize, Default)]
struct StatusArgs {
    /// Continuously refresh status output.
    #[arg(long)]
    watch: bool,
}

#[derive(Debug, Clone, Args, Serialize)]
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

impl Default for StatsArgs {
    fn default() -> Self {
        Self {
            window: None,
            top_patterns: 0,
            top_deletions: 0,
            pressure_history: false,
        }
    }
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
}

#[derive(Debug, Clone, Args, Serialize)]
struct CleanArgs {
    /// Paths to clean (falls back to configured watched paths when omitted).
    #[arg(value_name = "PATH")]
    paths: Vec<PathBuf>,
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
}

impl Default for CleanArgs {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            target_free: None,
            min_score: 0.7,
            max_items: None,
            dry_run: false,
            yes: false,
        }
    }
}

#[derive(Debug, Clone, Args, Serialize, Default)]
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
    Validate,
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
}

impl Default for EmergencyArgs {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            target_free: 10.0,
            yes: false,
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

#[derive(Debug, Clone, Args, Serialize, Default)]
struct TuneArgs {
    /// Apply recommended tuning changes.
    #[arg(long)]
    apply: bool,
    /// Skip interactive confirmation when applying.
    #[arg(long, requires = "apply")]
    yes: bool,
}

#[derive(Debug, Clone, Args, Serialize)]
struct CheckArgs {
    /// Path to evaluate (defaults to cwd).
    #[arg(value_name = "PATH")]
    path: Option<PathBuf>,
    /// Desired minimum free percentage.
    #[arg(long, value_name = "PERCENT")]
    target_free: Option<f64>,
    /// Minimum required free space in bytes (e.g. 5000000000 for ~5GB).
    #[arg(long, value_name = "BYTES")]
    need: Option<u64>,
    /// Predict if space will last for this many minutes (requires running daemon).
    #[arg(long, value_name = "MINUTES")]
    predict: Option<u64>,
}

impl Default for CheckArgs {
    fn default() -> Self {
        Self {
            path: None,
            target_free: None,
            need: None,
            predict: None,
        }
    }
}

#[derive(Debug, Clone, Args, Serialize)]
struct BlameArgs {
    /// Maximum rows to return.
    #[arg(long, default_value_t = 25, value_name = "N")]
    top: usize,
}

impl Default for BlameArgs {
    fn default() -> Self {
        Self { top: 25 }
    }
}

#[derive(Debug, Clone, Args, Serialize)]
struct DashboardArgs {
    /// Refresh interval for live view.
    #[arg(long, default_value_t = 1_000, value_name = "MILLISECONDS")]
    refresh_ms: u64,
}

impl Default for DashboardArgs {
    fn default() -> Self {
        Self { refresh_ms: 1_000 }
    }
}

#[derive(Debug, Clone, Args)]
struct CompletionsArgs {
    /// Shell to generate completion script for.
    #[arg(value_enum)]
    shell: CompletionShell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputMode {
    Human,
    Json,
}

/// CLI error type with explicit exit-code mapping.
#[derive(Debug, Error)]
#[allow(dead_code)] // scaffolding: runtime command implementations will construct all variants
pub enum CliError {
    /// Invalid user input at runtime.
    #[error("{0}")]
    User(String),
    /// Environment/runtime failure.
    #[error("{0}")]
    Runtime(String),
    /// Internal bug or invariant violation.
    #[error("{0}")]
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
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::User(_) => 1,
            Self::Runtime(_) | Self::Io(_) => 2,
            Self::Internal(_) | Self::Json(_) => 3,
            Self::Partial(_) => 4,
        }
    }
}

/// Dispatch CLI commands. Command bodies are still scaffold stubs; this bead only
/// establishes the full parser + output contract.
pub fn run(cli: &Cli) -> Result<(), CliError> {
    if cli.no_color {
        control::set_override(false);
    }

    match &cli.command {
        Command::Daemon(args) => emit_stub_with_args(cli, "daemon", args),
        Command::Install(args) => run_install(cli, args),
        Command::Uninstall(args) => run_uninstall(cli, args),
        Command::Status(args) => run_status(cli, args),
        Command::Stats(args) => run_stats(cli, args),
        Command::Scan(args) => run_scan(cli, args),
        Command::Clean(args) => run_clean(cli, args),
        Command::Ballast(args) => run_ballast(cli, args),
        Command::Config(args) => run_config(cli, args),
        Command::Version(args) => emit_version(cli, args),
        Command::Emergency(args) => run_emergency(cli, args),
        Command::Protect(args) => run_protect(cli, args),
        Command::Unprotect(args) => run_unprotect(cli, args),
        Command::Tune(args) => run_tune(cli, args),
        Command::Check(args) => run_check(cli, args),
        Command::Blame(args) => run_blame(cli, args),
        Command::Dashboard(args) => emit_stub_with_args(cli, "dashboard", args),
        Command::Completions(args) => {
            let mut command = Cli::command();
            let binary_name = command.get_name().to_string();
            generate(args.shell, &mut command, binary_name, &mut io::stdout());
            Ok(())
        }
    }
}

fn ballast_command_label(args: &BallastArgs) -> &'static str {
    match args.command {
        None => "ballast",
        Some(BallastCommand::Status) => "ballast status",
        Some(BallastCommand::Provision) => "ballast provision",
        Some(BallastCommand::Release(_)) => "ballast release",
        Some(BallastCommand::Replenish) => "ballast replenish",
        Some(BallastCommand::Verify) => "ballast verify",
    }
}

fn config_command_label(args: &ConfigArgs) -> &'static str {
    match args.command {
        None => "config",
        Some(ConfigCommand::Path) => "config path",
        Some(ConfigCommand::Show) => "config show",
        Some(ConfigCommand::Validate) => "config validate",
        Some(ConfigCommand::Diff) => "config diff",
        Some(ConfigCommand::Reset) => "config reset",
        Some(ConfigCommand::Set(_)) => "config set",
    }
}

fn run_install(cli: &Cli, args: &InstallArgs) -> Result<(), CliError> {
    if !args.systemd && !args.launchd {
        return Err(CliError::User("specify --systemd or --launchd".to_string()));
    }

    if args.launchd {
        let mgr = LaunchdServiceManager::from_env(args.user)
            .map_err(|e| CliError::Runtime(e.to_string()))?;
        let plist_path = mgr.config().plist_path();
        let scope = if args.user { "user" } else { "system" };

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
                    unit_path: plist_path.clone(),
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
    let mgr =
        SystemdServiceManager::from_env(args.user).map_err(|e| CliError::Runtime(e.to_string()))?;
    let unit_path = mgr.config().unit_path();
    let scope = if args.user { "user" } else { "system" };

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
                    if args.user {
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
                unit_path: unit_path.clone(),
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

fn run_uninstall(cli: &Cli, args: &UninstallArgs) -> Result<(), CliError> {
    if !args.systemd && !args.launchd {
        return Err(CliError::User("specify --systemd or --launchd".to_string()));
    }

    if args.launchd {
        // Determine scope: check system plist first, then user agent.
        let system_plist = PathBuf::from("/Library/LaunchDaemons/com.sbh.daemon.plist");
        let launchd_user = if system_plist.exists() {
            false
        } else {
            let home =
                std::env::var_os("HOME").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
            let user_plist = home.join("Library/LaunchAgents/com.sbh.daemon.plist");
            user_plist.exists()
        };

        let mgr = LaunchdServiceManager::from_env(launchd_user)
            .map_err(|e| CliError::Runtime(e.to_string()))?;
        let plist_path = mgr.config().plist_path();
        let scope = if launchd_user { "user" } else { "system" };

        match mgr.uninstall() {
            Ok(()) => {
                let result = ServiceActionResult {
                    action: "uninstall",
                    service_type: "launchd",
                    scope,
                    unit_path: plist_path.clone(),
                    success: true,
                    error: None,
                };

                match output_mode(cli) {
                    OutputMode::Human => {
                        println!("Uninstalled launchd service ({scope} scope).");
                        println!("  Removed: {}", plist_path.display());
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
                    action: "uninstall",
                    service_type: "launchd",
                    scope,
                    unit_path: plist_path.clone(),
                    success: false,
                    error: Some(e.to_string()),
                };

                match output_mode(cli) {
                    OutputMode::Human => {
                        eprintln!("Failed to uninstall launchd service: {e}");
                    }
                    OutputMode::Json => {
                        let payload = serde_json::to_value(&result)?;
                        write_json_line(&payload)?;
                    }
                }
                return Err(CliError::Runtime(format!("uninstall failed: {e}")));
            }
        }
    }

    // -- systemd uninstall ------------------------------------------------
    // Determine scope from whether the unit file exists.
    // System scope is the default unless the system unit doesn't exist and
    // a user-scope one does.
    let system_path = std::path::PathBuf::from("/etc/systemd/system/sbh.service");
    let user_scope = if system_path.exists() {
        false
    } else {
        // Check if user-scope unit exists.
        let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
        let user_path = home.join(".config/systemd/user/sbh.service");
        user_path.exists()
    };

    let mgr = SystemdServiceManager::from_env(user_scope)
        .map_err(|e| CliError::Runtime(e.to_string()))?;
    let unit_path = mgr.config().unit_path();
    let scope = if user_scope { "user" } else { "system" };

    match mgr.uninstall() {
        Ok(()) => {
            let result = ServiceActionResult {
                action: "uninstall",
                service_type: "systemd",
                scope,
                unit_path: unit_path.clone(),
                success: true,
                error: None,
            };

            match output_mode(cli) {
                OutputMode::Human => {
                    println!("Uninstalled systemd service ({scope} scope).");
                    println!("  Removed: {}", unit_path.display());
                    if args.purge {
                        println!("  Note: --purge removes state/logs (not yet implemented).");
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
                action: "uninstall",
                service_type: "systemd",
                scope,
                unit_path: unit_path.clone(),
                success: false,
                error: Some(e.to_string()),
            };

            match output_mode(cli) {
                OutputMode::Human => {
                    eprintln!("Failed to uninstall systemd service: {e}");
                }
                OutputMode::Json => {
                    let payload = serde_json::to_value(&result)?;
                    write_json_line(&payload)?;
                }
            }
            Err(CliError::Runtime(format!("uninstall failed: {e}")))
        }
    }
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
        "m" | "min" => 60,
        "h" | "hr" => 3600,
        "d" | "day" => 86400,
        "" => 60, // bare number defaults to minutes
        _ => return Err(CliError::User(format!("unknown window suffix: {suffix}"))),
    };
    Ok(std::time::Duration::from_secs(n * multiplier))
}

fn run_stats(cli: &Cli, args: &StatsArgs) -> Result<(), CliError> {
    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;

    if !config.paths.sqlite_db.exists() {
        match output_mode(cli) {
            OutputMode::Human => {
                println!(
                    "No activity database found at {}.",
                    config.paths.sqlite_db.display()
                );
                println!("  Run the daemon to start collecting statistics.");
            }
            OutputMode::Json => {
                let payload = json!({
                    "command": "stats",
                    "error": "no_database",
                    "db_path": config.paths.sqlite_db.to_string_lossy(),
                });
                write_json_line(&payload)?;
            }
        }
        return Ok(());
    }

    let db = SqliteLogger::open(&config.paths.sqlite_db)
        .map_err(|e| CliError::Runtime(format!("open stats database: {e}")))?;
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
        let window = specific_window.unwrap_or(std::time::Duration::from_secs(24 * 3600));
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
        let window = specific_window.unwrap_or(std::time::Duration::from_secs(24 * 3600));
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
            println!(
                "  {:>10}  {:>6}  {:<40}  {}",
                "Size", "Score", "Path", "When"
            );
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
        let window = specific_window.unwrap_or(std::time::Duration::from_secs(24 * 3600));
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
            .filter(|w| w.get("window_secs").and_then(|s| s.as_u64()) == Some(window.as_secs()))
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
                },
                "ballast": {
                    "files_released": ws.ballast.files_released,
                    "files_replenished": ws.ballast.files_replenished,
                    "current_inventory": ws.ballast.current_inventory,
                    "bytes_available": ws.ballast.bytes_available,
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
        let window = specific_window.unwrap_or(std::time::Duration::from_secs(24 * 3600));
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
        let window = specific_window.unwrap_or(std::time::Duration::from_secs(24 * 3600));
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
}

fn print_pressure_bar(label: &str, pct: f64) {
    let bar_width = 30;
    let filled = ((pct / 100.0) * bar_width as f64).round() as usize;
    let bar: String = "#".repeat(filled.min(bar_width));
    println!(
        "    {:<9} {:>5.1}% |{:<width$}|",
        label,
        pct,
        bar,
        width = bar_width
    );
}

/// Information about a running process for blame attribution.
#[derive(Debug, Clone)]
struct ProcessBlameInfo {
    pid: u32,
    comm: String,
    cwd: PathBuf,
}

/// A group of artifacts attributed to a single process or "orphaned".
#[derive(Debug, Clone)]
struct BlameGroup {
    label: String,
    pid: Option<u32>,
    build_dirs: Vec<PathBuf>,
    total_bytes: u64,
    oldest: Option<SystemTime>,
    newest: Option<SystemTime>,
}

fn collect_process_info() -> Vec<ProcessBlameInfo> {
    let mut procs = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let Ok(proc_dir) = std::fs::read_dir("/proc") else {
            return procs;
        };

        for entry in proc_dir {
            let Ok(entry) = entry else {
                continue;
            };
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if !name_str.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let Ok(pid) = name_str.parse::<u32>() else {
                continue;
            };

            let proc_path = entry.path();

            // Read cwd symlink.
            let Ok(cwd) = std::fs::read_link(proc_path.join("cwd")) else {
                continue;
            };
            if !cwd.is_absolute() {
                continue;
            }

            // Read comm (process name).
            let comm = std::fs::read_to_string(proc_path.join("comm"))
                .unwrap_or_default()
                .trim()
                .to_string();

            if comm.is_empty() {
                continue;
            }

            procs.push(ProcessBlameInfo { pid, comm, cwd });
        }
    }

    procs
}

fn run_blame(cli: &Cli, args: &BlameArgs) -> Result<(), CliError> {
    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;
    let start = std::time::Instant::now();

    // Collect process information.
    let processes = collect_process_info();

    // Walk the configured roots for build artifacts.
    let root_paths = config.scanner.root_paths.clone();
    let protection_patterns = if config.scanner.protected_paths.is_empty() {
        None
    } else {
        Some(config.scanner.protected_paths.as_slice())
    };
    let protection = ProtectionRegistry::new(protection_patterns)
        .map_err(|e| CliError::Runtime(e.to_string()))?;

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
    };
    let walker = DirectoryWalker::new(walker_config, protection);

    let entries = walker
        .walk()
        .map_err(|e| CliError::Runtime(e.to_string()))?;

    // Only consider directories (build artifact roots).
    let dir_entries: Vec<_> = entries.iter().filter(|e| e.metadata.is_dir).collect();

    // Build a map: process label → BlameGroup.
    let mut groups: std::collections::HashMap<String, BlameGroup> =
        std::collections::HashMap::new();
    let now = SystemTime::now();

    for entry in &dir_entries {
        // Find the process whose CWD is a prefix of this artifact's path.
        let owner = processes.iter().find(|p| entry.path.starts_with(&p.cwd));

        let (label, pid) = match owner {
            Some(proc) => (format!("{} (PID {})", proc.comm, proc.pid), Some(proc.pid)),
            None => ("(orphaned)".to_string(), None),
        };

        let group = groups.entry(label.clone()).or_insert_with(|| BlameGroup {
            label,
            pid,
            build_dirs: Vec::new(),
            total_bytes: 0,
            oldest: None,
            newest: None,
        });

        group.build_dirs.push(entry.path.clone());
        group.total_bytes += entry.metadata.size_bytes;

        let mtime = entry.metadata.modified;
        group.oldest = Some(match group.oldest {
            Some(prev) => prev.min(mtime),
            None => mtime,
        });
        group.newest = Some(match group.newest {
            Some(prev) => prev.max(mtime),
            None => mtime,
        });
    }

    // Sort groups by total size descending.
    let mut sorted_groups: Vec<BlameGroup> = groups.into_values().collect();
    sorted_groups.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes));
    sorted_groups.truncate(args.top);

    let total_dirs: usize = sorted_groups.iter().map(|g| g.build_dirs.len()).sum();
    let total_bytes: u64 = sorted_groups.iter().map(|g| g.total_bytes).sum();
    let elapsed = start.elapsed();

    match output_mode(cli) {
        OutputMode::Human => {
            println!(
                "Disk Usage by Agent/Process (scanned in {:.1}s):",
                elapsed.as_secs_f64()
            );
            println!();

            if sorted_groups.is_empty() {
                println!("  No build artifacts found.");
            } else {
                println!(
                    "  {:<30}  {:>10}  {:>10}  {:>10}  {:>10}",
                    "Agent/Process", "Build Dirs", "Total Size", "Oldest", "Newest"
                );
                println!("  {}", "-".repeat(76));

                for group in &sorted_groups {
                    let oldest_str = group
                        .oldest
                        .and_then(|t| now.duration_since(t).ok())
                        .map_or_else(
                            || "-".to_string(),
                            |d| format!("{} ago", format_duration(d)),
                        );
                    let newest_str = group
                        .newest
                        .and_then(|t| now.duration_since(t).ok())
                        .map_or_else(
                            || "-".to_string(),
                            |d| format!("{} ago", format_duration(d)),
                        );

                    println!(
                        "  {:<30}  {:>10}  {:>10}  {:>10}  {:>10}",
                        group.label,
                        group.build_dirs.len(),
                        format_bytes(group.total_bytes),
                        oldest_str,
                        newest_str,
                    );
                }

                println!();
                println!(
                    "  Total: {} build dirs, {}",
                    total_dirs,
                    format_bytes(total_bytes),
                );

                let orphaned_bytes: u64 = sorted_groups
                    .iter()
                    .filter(|g| g.pid.is_none())
                    .map(|g| g.total_bytes)
                    .sum();
                if orphaned_bytes > 0 {
                    println!(
                        "  Orphaned dirs (no running process) are the safest to clean: {}",
                        format_bytes(orphaned_bytes),
                    );
                }
            }
        }
        OutputMode::Json => {
            let groups_json: Vec<Value> = sorted_groups
                .iter()
                .map(|g| {
                    let oldest_age = g
                        .oldest
                        .and_then(|t| now.duration_since(t).ok())
                        .map(|d| d.as_secs());
                    let newest_age = g
                        .newest
                        .and_then(|t| now.duration_since(t).ok())
                        .map(|d| d.as_secs());

                    json!({
                        "label": g.label,
                        "pid": g.pid,
                        "build_dirs": g.build_dirs.len(),
                        "total_bytes": g.total_bytes,
                        "oldest_age_secs": oldest_age,
                        "newest_age_secs": newest_age,
                    })
                })
                .collect();

            let payload = json!({
                "command": "blame",
                "groups": groups_json,
                "total_dirs": total_dirs,
                "total_bytes": total_bytes,
                "elapsed_ms": elapsed.as_millis() as u64,
                "processes_scanned": processes.len(),
            });
            write_json_line(&payload)?;
        }
    }

    Ok(())
}

// ──────────────────── tuning engine ────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TuningCategory {
    Ballast,
    Threshold,
    Scoring,
}

impl std::fmt::Display for TuningCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ballast => f.write_str("Ballast"),
            Self::Threshold => f.write_str("Threshold"),
            Self::Scoring => f.write_str("Scoring"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // High is scaffolding for PID-tuning recommendations
enum TuningRisk {
    Low,
    Medium,
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

fn generate_recommendations(
    config: &Config,
    stats: &[storage_ballast_helper::logger::stats::WindowStats],
) -> Vec<Recommendation> {
    let mut recs = Vec::new();

    // Use the 24-hour window for most analysis (index 4 in STANDARD_WINDOWS).
    let day_stats = stats.iter().find(|ws| ws.window.as_secs() == 86400);
    // Use the 7-day window for trend analysis.
    let week_stats = stats.iter().find(|ws| ws.window.as_secs() == 604800);
    // Use the 1-hour window for recent activity.
    let hour_stats = stats.iter().find(|ws| ws.window.as_secs() == 3600);

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
        if let Some(week) = week_stats {
            if week.ballast.files_released == 0
                && week.pressure.transitions > 0
                && config.ballast.file_count > 3
            {
                let pool_gb = (config.ballast.file_count as u64 * config.ballast.file_size_bytes)
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
                        ((config.ballast.file_count - suggested) as u64
                            * config.ballast.file_size_bytes) as f64
                            / 1_073_741_824.0,
                    ),
                    confidence: 0.7,
                    risk: TuningRisk::Medium,
                });
            }
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

fn run_tune(cli: &Cli, args: &TuneArgs) -> Result<(), CliError> {
    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;

    // Open stats database.
    let db = if config.paths.sqlite_db.exists() {
        Some(
            SqliteLogger::open(&config.paths.sqlite_db)
                .map_err(|e| CliError::Runtime(format!("open stats database: {e}")))?,
        )
    } else {
        None
    };

    let recs = if let Some(ref db) = db {
        let engine = StatsEngine::new(db);
        let stats = engine
            .summary()
            .map_err(|e| CliError::Runtime(e.to_string()))?;
        generate_recommendations(&config, &stats)
    } else {
        Vec::new()
    };

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
    if !args.yes && output_mode(cli) == OutputMode::Human {
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
        println!();

        // Non-interactive: require --yes.
        return Err(CliError::User(
            "use --yes to confirm, or review recommendations with `sbh tune` first".to_string(),
        ));
    }

    // Read existing config TOML.
    let config_path = cli.config.clone().unwrap_or_else(Config::default_path);

    let mut toml_value: toml::Value = if config_path.exists() {
        let raw = std::fs::read_to_string(&config_path)
            .map_err(|e| CliError::Runtime(format!("read config: {e}")))?;
        toml::from_str(&raw).map_err(|e| CliError::Runtime(format!("parse config: {e}")))?
    } else {
        toml::Value::Table(toml::map::Map::new())
    };

    // Apply each recommendation.
    let mut applied = Vec::new();
    for rec in &recs {
        set_toml_value(&mut toml_value, &rec.config_key, &rec.suggested_value)?;
        applied.push(rec);
    }

    // Write back.
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| CliError::Runtime(format!("create config dir: {e}")))?;
    }
    let toml_str = toml::to_string_pretty(&toml_value)
        .map_err(|e| CliError::Runtime(format!("serialize config: {e}")))?;
    std::fs::write(&config_path, &toml_str)
        .map_err(|e| CliError::Runtime(format!("write config: {e}")))?;

    match output_mode(cli) {
        OutputMode::Human => {
            println!("Applied {} recommendation(s):", applied.len());
            for rec in &applied {
                println!(
                    "  {} = {} (was {})",
                    rec.config_key, rec.suggested_value, rec.current_value,
                );
            }
            println!("\nConfig updated: {}", config_path.display());
        }
        OutputMode::Json => {
            let changes: Vec<Value> = applied
                .iter()
                .map(|r| {
                    json!({
                        "config_key": r.config_key,
                        "old_value": r.current_value,
                        "new_value": r.suggested_value,
                    })
                })
                .collect();
            let payload = json!({
                "command": "tune",
                "action": "apply",
                "applied": changes.len(),
                "changes": changes,
                "config_path": config_path.to_string_lossy(),
            });
            write_json_line(&payload)?;
        }
    }

    Ok(())
}

fn run_config(cli: &Cli, args: &ConfigArgs) -> Result<(), CliError> {
    match &args.command {
        None | Some(ConfigCommand::Path) => {
            let path = cli.config.clone().unwrap_or_else(Config::default_path);
            let exists = path.exists();

            match output_mode(cli) {
                OutputMode::Human => {
                    println!("{}", path.display());
                    if !exists {
                        println!("  (file does not exist; defaults will be used)");
                    }
                }
                OutputMode::Json => {
                    let payload = json!({
                        "command": "config path",
                        "path": path.to_string_lossy(),
                        "exists": exists,
                    });
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
        Some(ConfigCommand::Validate) => match Config::load(cli.config.as_deref()) {
            Ok(config) => {
                let hash = config
                    .stable_hash()
                    .map_err(|e| CliError::Runtime(e.to_string()))?;

                match output_mode(cli) {
                    OutputMode::Human => {
                        println!("Configuration is valid.");
                        println!("  Source: {}", config.paths.config_file.display());
                        println!("  Hash: {hash}");
                    }
                    OutputMode::Json => {
                        let payload = json!({
                            "command": "config validate",
                            "valid": true,
                            "path": config.paths.config_file.to_string_lossy(),
                            "hash": hash,
                        });
                        write_json_line(&payload)?;
                    }
                }
                Ok(())
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

            // Write back.
            if let Some(parent) = config_path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| CliError::Runtime(format!("create config dir: {e}")))?;
            }
            let toml_str = toml::to_string_pretty(&toml_value)
                .map_err(|e| CliError::Runtime(format!("serialize config: {e}")))?;
            std::fs::write(&config_path, &toml_str)
                .map_err(|e| CliError::Runtime(format!("write config: {e}")))?;

            // Validate the resulting config.
            match Config::load(Some(&config_path)) {
                Ok(_) => {
                    match output_mode(cli) {
                        OutputMode::Human => {
                            println!(
                                "Set {} = {} in {}",
                                set_args.key,
                                set_args.value,
                                config_path.display()
                            );
                        }
                        OutputMode::Json => {
                            let payload = json!({
                                "command": "config set",
                                "key": set_args.key,
                                "value": set_args.value,
                                "path": config_path.to_string_lossy(),
                                "valid": true,
                            });
                            write_json_line(&payload)?;
                        }
                    }
                    Ok(())
                }
                Err(e) => {
                    match output_mode(cli) {
                        OutputMode::Human => {
                            println!(
                                "Set {} = {} in {}",
                                set_args.key,
                                set_args.value,
                                config_path.display()
                            );
                            eprintln!("Warning: resulting configuration is invalid: {e}");
                        }
                        OutputMode::Json => {
                            let payload = json!({
                                "command": "config set",
                                "key": set_args.key,
                                "value": set_args.value,
                                "path": config_path.to_string_lossy(),
                                "valid": false,
                                "validation_error": e.to_string(),
                            });
                            write_json_line(&payload)?;
                        }
                    }
                    Err(CliError::Partial(format!(
                        "value set but config invalid: {e}"
                    )))
                }
            }
        }
    }
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
    let key = parts.last().unwrap();
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

fn run_ballast(cli: &Cli, args: &BallastArgs) -> Result<(), CliError> {
    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;

    let mut manager = BallastManager::new(config.paths.ballast_dir.clone(), config.ballast.clone())
        .map_err(|e| CliError::Runtime(e.to_string()))?;

    match &args.command {
        None | Some(BallastCommand::Status) => {
            let inventory = manager.inventory().to_vec();
            let available = manager.available_count();
            let releasable = manager.releasable_bytes();

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
                        format_bytes(
                            config.ballast.file_count as u64 * config.ballast.file_size_bytes
                        )
                    );
                    println!(
                        "  Available: {available} files ({} releasable)",
                        format_bytes(releasable)
                    );
                    println!(
                        "  Missing: {} files",
                        config.ballast.file_count - inventory.len()
                    );

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
                        "total_pool_bytes":
                            config.ballast.file_count as u64
                                * config.ballast.file_size_bytes,
                        "available_count": available,
                        "releasable_bytes": releasable,
                        "missing_count":
                            config.ballast.file_count - inventory.len(),
                        "files": files,
                    });
                    write_json_line(&payload)?;
                }
            }
            Ok(())
        }
        Some(BallastCommand::Provision) => {
            let report = manager
                .provision(None)
                .map_err(|e| CliError::Runtime(e.to_string()))?;

            match output_mode(cli) {
                OutputMode::Human => {
                    println!("Ballast provision complete:");
                    println!("  Files created: {}", report.files_created);
                    println!("  Files skipped (existing): {}", report.files_skipped);
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
                        "files_created": report.files_created,
                        "files_skipped": report.files_skipped,
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
            let report = manager
                .replenish(None)
                .map_err(|e| CliError::Runtime(e.to_string()))?;

            match output_mode(cli) {
                OutputMode::Human => {
                    println!("Ballast replenish complete:");
                    println!("  Files recreated: {}", report.files_created);
                    println!("  Files skipped (existing): {}", report.files_skipped);
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
            let report = manager.verify();

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

fn run_status(cli: &Cli, _args: &StatusArgs) -> Result<(), CliError> {
    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;
    let platform = LinuxPlatform::new();
    let version = env!("CARGO_PKG_VERSION");

    // Gather filesystem stats for all root paths + standard mounts.
    let mounts = platform
        .mount_points()
        .map_err(|e| CliError::Runtime(e.to_string()))?;

    // Read daemon state.json for EWMA predictions (optional).
    let daemon_state = std::fs::read_to_string(&config.paths.state_file)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());

    let daemon_running = daemon_state.is_some();

    // Open SQLite database for recent activity (optional).
    let db_stats = if config.paths.sqlite_db.exists() {
        SqliteLogger::open(&config.paths.sqlite_db)
            .ok()
            .map(|db| {
                let engine = StatsEngine::new(&db);
                engine
                    .window_stats(std::time::Duration::from_secs(3600))
                    .ok()
            })
            .flatten()
    } else {
        None
    };

    match output_mode(cli) {
        OutputMode::Human => {
            println!("Storage Ballast Helper v{version}");
            println!("  Config: {}", config.paths.config_file.display(),);
            if daemon_running {
                println!("  Daemon: running");
            } else {
                println!("  Daemon: not running (degraded mode)");
            }

            // Pressure status table.
            println!("\nPressure Status:");
            println!(
                "  {:<20}  {:>10}  {:>10}  {:>7}  {:<10}",
                "Mount Point", "Total", "Free", "Free %", "Level"
            );
            println!("  {}", "-".repeat(65));

            let mut overall_level = "green";
            for mount in &mounts {
                let stats = match platform.fs_stats(&mount.path) {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                let free_pct = stats.free_pct();
                let level = pressure_level_str(free_pct, &config);
                if pressure_severity(level) > pressure_severity(overall_level) {
                    overall_level = level;
                }

                let ram_note = if platform.is_ram_backed(&mount.path).unwrap_or(false) {
                    " (tmpfs)"
                } else {
                    ""
                };

                println!(
                    "  {:<20}  {:>10}  {:>10}  {:>6.1}%  {:<10}",
                    format!("{}{ram_note}", mount.path.display()),
                    format_bytes(stats.total_bytes),
                    format_bytes(stats.available_bytes),
                    free_pct,
                    level.to_uppercase(),
                );
            }

            // Rate estimates from daemon state.
            if let Some(state) = &daemon_state {
                if let Some(rates) = state.get("rates").and_then(|r| r.as_object()) {
                    if !rates.is_empty() {
                        println!("\nRate Estimates:");
                        for (mount, rate_obj) in rates {
                            let bps = rate_obj
                                .get("bytes_per_sec")
                                .and_then(|v| v.as_f64())
                                .unwrap_or(0.0);
                            let trend = if bps > 0.0 {
                                "filling"
                            } else if bps < 0.0 {
                                "recovering"
                            } else {
                                "stable"
                            };
                            let rate_str = if bps.abs() > 0.0 {
                                format!("{}/s", format_bytes(bps.abs() as u64))
                            } else {
                                "0 B/s".to_string()
                            };
                            let sign = if bps > 0.0 { "+" } else { "" };
                            println!("  {mount:<20}  {sign}{rate_str:<15} ({trend})");
                        }
                    }
                }
            }

            // Ballast info.
            println!("\nBallast:");
            println!(
                "  Configured: {} files x {}",
                config.ballast.file_count,
                format_bytes(config.ballast.file_size_bytes),
            );
            println!(
                "  Total pool: {}",
                format_bytes(config.ballast.file_count as u64 * config.ballast.file_size_bytes),
            );

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
            let mut mounts_json: Vec<Value> = Vec::new();
            let mut overall_level = "green";

            for mount in &mounts {
                let stats = match platform.fs_stats(&mount.path) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let free_pct = stats.free_pct();
                let level = pressure_level_str(free_pct, &config);
                if pressure_severity(level) > pressure_severity(overall_level) {
                    overall_level = level;
                }

                mounts_json.push(json!({
                    "path": mount.path.to_string_lossy(),
                    "total": stats.total_bytes,
                    "free": stats.available_bytes,
                    "free_pct": free_pct,
                    "level": level,
                    "fs_type": stats.fs_type,
                }));
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
                "version": version,
                "daemon_running": daemon_running,
                "config_path": config.paths.config_file.to_string_lossy(),
                "pressure": {
                    "mounts": mounts_json,
                    "overall": overall_level,
                },
                "ballast": {
                    "file_count": config.ballast.file_count,
                    "file_size_bytes": config.ballast.file_size_bytes,
                    "total_pool_bytes": config.ballast.file_count as u64 * config.ballast.file_size_bytes,
                },
                "recent_hour": recent,
            });
            write_json_line(&payload)?;
        }
    }

    Ok(())
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
        "green" => 0,
        "yellow" => 1,
        "orange" => 2,
        "red" => 3,
        "critical" => 4,
        _ => 0,
    }
}

fn run_protect(cli: &Cli, args: &ProtectArgs) -> Result<(), CliError> {
    if args.list {
        // List all protections (markers + config patterns).
        let config =
            Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;

        let protection_patterns = if config.scanner.protected_paths.is_empty() {
            None
        } else {
            Some(config.scanner.protected_paths.as_slice())
        };
        let mut registry = ProtectionRegistry::new(protection_patterns)
            .map_err(|e| CliError::Runtime(e.to_string()))?;

        // Discover markers in configured root paths.
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
                    .map(|e| {
                        let source = match &e.source {
                            protection::ProtectionSource::MarkerFile => "marker".to_string(),
                            protection::ProtectionSource::ConfigPattern(p) => {
                                format!("config:{p}")
                            }
                        };
                        json!({
                            "path": e.path.to_string_lossy(),
                            "source": source,
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
    } else if let Some(path) = &args.path {
        // Create a .sbh-protect marker.
        if !path.is_dir() {
            return Err(CliError::User(format!(
                "path is not a directory: {}",
                path.display(),
            )));
        }

        protection::create_marker(path, None).map_err(|e| CliError::Runtime(e.to_string()))?;

        match output_mode(cli) {
            OutputMode::Human => {
                println!(
                    "Protected: {} (created {})",
                    path.display(),
                    path.join(protection::MARKER_FILENAME).display(),
                );
            }
            OutputMode::Json => {
                let payload = json!({
                    "command": "protect",
                    "action": "create",
                    "path": path.to_string_lossy(),
                    "marker": path.join(protection::MARKER_FILENAME).to_string_lossy(),
                });
                write_json_line(&payload)?;
            }
        }
    }

    Ok(())
}

fn run_unprotect(cli: &Cli, args: &UnprotectArgs) -> Result<(), CliError> {
    let removed =
        protection::remove_marker(&args.path).map_err(|e| CliError::Runtime(e.to_string()))?;

    match output_mode(cli) {
        OutputMode::Human => {
            if removed {
                println!("Unprotected: {} (marker removed)", args.path.display());
            } else {
                println!(
                    "No protection marker found at {}",
                    args.path.join(protection::MARKER_FILENAME).display(),
                );
            }
        }
        OutputMode::Json => {
            let payload = json!({
                "command": "unprotect",
                "path": args.path.to_string_lossy(),
                "removed": removed,
            });
            write_json_line(&payload)?;
        }
    }

    Ok(())
}

fn run_scan(cli: &Cli, args: &ScanArgs) -> Result<(), CliError> {
    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;
    let start = std::time::Instant::now();

    // Determine scan roots: CLI paths or configured watched paths.
    let root_paths = if args.paths.is_empty() {
        config.scanner.root_paths.clone()
    } else {
        args.paths.clone()
    };

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
    };
    let walker = DirectoryWalker::new(walker_config, protection);

    // Walk the filesystem.
    let entries = walker
        .walk()
        .map_err(|e| CliError::Runtime(e.to_string()))?;
    let dir_count = entries.len();

    // Collect open files for is_open detection.
    let open_files = collect_open_files();

    // Classify and score each entry.
    let registry = ArtifactPatternRegistry::default();
    let engine = ScoringEngine::from_config(&config.scoring, config.scanner.min_file_age_minutes);
    let now = SystemTime::now();

    let mut candidates: Vec<_> = entries
        .iter()
        .map(|entry| {
            let classification = registry.classify(&entry.path, entry.structural_signals);
            let age = now
                .duration_since(entry.metadata.modified)
                .unwrap_or_default();
            let candidate = CandidateInput {
                path: entry.path.clone(),
                size_bytes: entry.metadata.size_bytes,
                age,
                classification,
                signals: entry.structural_signals,
                is_open: is_path_open(&entry.path, &open_files),
                excluded: false,
            };
            engine.score_candidate(&candidate, 0.0) // No pressure urgency for manual scan.
        })
        .filter(|score| !score.vetoed && score.total_score >= args.min_score)
        .collect();

    candidates.sort_by(|a, b| {
        b.total_score
            .partial_cmp(&a.total_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    candidates.truncate(args.top);

    let elapsed = start.elapsed();
    let total_reclaimable: u64 = candidates.iter().map(|c| c.size_bytes).sum();

    match output_mode(cli) {
        OutputMode::Human => {
            println!(
                "Build Artifact Scan Results\n  Scanned: {} directories in {:.1}s\n  Candidates found: {} (above threshold {:.2})\n",
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

                for (i, candidate) in candidates.iter().enumerate() {
                    let age = candidate.age;
                    let age_str = format_duration(age);
                    let size_str = format_bytes(candidate.size_bytes);
                    let type_str = format!("{:?}", candidate.classification.category);
                    let path_str = truncate_path(&candidate.path, 50);

                    println!(
                        "  {:>3}  {:<50}  {:>10}  {:>10}  {:>6.2}  {:<12}",
                        i + 1,
                        path_str,
                        size_str,
                        age_str,
                        candidate.total_score,
                        type_str,
                    );
                }
                println!();
                println!("  Total reclaimable: {}", format_bytes(total_reclaimable));
                println!("  Use 'sbh clean' to delete these candidates.");
            }

            // Show protected paths if requested.
            if args.show_protected {
                let prot = walker.protection().read();
                let protections = prot.list_protections();
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
                .map(|c| {
                    json!({
                        "path": c.path.to_string_lossy(),
                        "size_bytes": c.size_bytes,
                        "age_seconds": c.age.as_secs(),
                        "total_score": c.total_score,
                        "category": format!("{:?}", c.classification.category),
                        "pattern_name": c.classification.pattern_name,
                        "confidence": c.classification.combined_confidence,
                        "decision": format!("{:?}", c.decision.action),
                        "factors": {
                            "location": c.factors.location,
                            "name": c.factors.name,
                            "age": c.factors.age,
                            "size": c.factors.size,
                            "structure": c.factors.structure,
                            "pressure_multiplier": c.factors.pressure_multiplier,
                        },
                    })
                })
                .collect();

            let payload = json!({
                "command": "scan",
                "scanned_directories": dir_count,
                "elapsed_seconds": elapsed.as_secs_f64(),
                "min_score": args.min_score,
                "candidates_count": entries_json.len(),
                "total_reclaimable_bytes": total_reclaimable,
                "candidates": entries_json,
            });
            write_json_line(&payload)?;
        }
    }

    Ok(())
}

fn run_clean(cli: &Cli, args: &CleanArgs) -> Result<(), CliError> {
    let config =
        Config::load(cli.config.as_deref()).map_err(|e| CliError::Runtime(e.to_string()))?;
    let start = std::time::Instant::now();

    // Determine scan roots: CLI paths or configured watched paths.
    let root_paths = if args.paths.is_empty() {
        config.scanner.root_paths.clone()
    } else {
        args.paths.clone()
    };

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
    };
    let walker = DirectoryWalker::new(walker_config, protection);
    let entries = walker
        .walk()
        .map_err(|e| CliError::Runtime(e.to_string()))?;
    let dir_count = entries.len();

    // Count protected directories encountered.
    let protected_count = walker.protection().read().list_protections().len();

    // Collect open files for is_open detection.
    let open_files = collect_open_files();

    // Classify and score each entry.
    let registry = ArtifactPatternRegistry::default();
    let engine = ScoringEngine::from_config(&config.scoring, config.scanner.min_file_age_minutes);
    let now = SystemTime::now();

    let scored: Vec<CandidacyScore> = entries
        .iter()
        .map(|entry| {
            let classification = registry.classify(&entry.path, entry.structural_signals);
            let age = now
                .duration_since(entry.metadata.modified)
                .unwrap_or_default();
            let candidate = CandidateInput {
                path: entry.path.clone(),
                size_bytes: entry.metadata.size_bytes,
                age,
                classification,
                signals: entry.structural_signals,
                is_open: is_path_open(&entry.path, &open_files),
                excluded: false,
            };
            engine.score_candidate(&candidate, 0.0)
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
        ..Default::default()
    };
    let executor = DeletionExecutor::new(deletion_config, None);
    let plan = executor.plan(scored);

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
                let payload = json!({
                    "command": "clean",
                    "scanned_directories": dir_count,
                    "elapsed_seconds": scan_elapsed.as_secs_f64(),
                    "candidates_count": 0,
                    "items_deleted": 0,
                    "bytes_freed": 0,
                    "dry_run": args.dry_run,
                    "protected_count": protected_count,
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
                    report.items_deleted,
                    format_bytes(report.bytes_freed),
                );
            }
            OutputMode::Json => {
                emit_clean_report_json(&plan, &report, dir_count, scan_elapsed, protected_count)?;
            }
        }
    } else if args.yes || !io::stdout().is_terminal() {
        // Automatic mode: no confirmation.
        let pressure_check = build_pressure_check(args.target_free, &root_paths);
        let report = executor.execute(
            &plan,
            pressure_check.as_ref().map(|f| f as &dyn Fn() -> bool),
        );

        match output_mode(cli) {
            OutputMode::Human => {
                print_clean_summary(&report);
            }
            OutputMode::Json => {
                emit_clean_report_json(&plan, &report, dir_count, scan_elapsed, protected_count)?;
            }
        }
    } else {
        // Interactive mode.
        run_interactive_clean(
            cli,
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

/// Print the deletion plan in a numbered table.
fn print_deletion_plan(plan: &DeletionPlan) {
    for (i, candidate) in plan.candidates.iter().enumerate() {
        let age_str = format_duration(candidate.age);
        let size_str = format_bytes(candidate.size_bytes);
        let path_str = truncate_path(&candidate.path, 60);

        println!(
            "  {:>3}. {} ({}, score {:.2}, {} old)",
            i + 1,
            path_str,
            size_str,
            candidate.total_score,
            age_str,
        );
    }
}

/// Build a pressure check closure if --target-free was specified.
fn build_pressure_check(
    target_free: Option<f64>,
    root_paths: &[PathBuf],
) -> Option<Box<dyn Fn() -> bool>> {
    let target = target_free?;
    let check_path = root_paths.first()?.clone();
    Some(Box::new(move || {
        let platform = LinuxPlatform::new();
        platform
            .fs_stats(&check_path)
            .map(|stats| stats.free_pct() >= target)
            .unwrap_or(false)
    }))
}

/// Interactive clean: prompt user for each candidate.
#[allow(clippy::too_many_arguments)]
fn run_interactive_clean(
    cli: &Cli,
    plan: &DeletionPlan,
    args: &CleanArgs,
    root_paths: &[PathBuf],
    dir_count: usize,
    scan_elapsed: std::time::Duration,
    protected_count: usize,
) -> Result<(), CliError> {
    let stdin = io::stdin();
    let mut input = String::new();
    let mut items_deleted: usize = 0;
    let mut items_skipped: usize = 0;
    let mut bytes_freed: u64 = 0;
    let mut delete_all = false;

    let platform = LinuxPlatform::new();

    println!("Proceed with deletion? [y/N/a(ll)/s(kip)/q(uit)]");
    println!("  y - delete this item    a - delete all remaining");
    println!("  n - skip this item      s - skip all remaining");
    println!("  q - quit\n");

    for (i, candidate) in plan.candidates.iter().enumerate() {
        // Check target_free stop condition.
        if let Some(target) = args.target_free {
            if let Some(first_root) = root_paths.first() {
                if let Ok(stats) = platform.fs_stats(first_root) {
                    if stats.free_pct() >= target {
                        println!("  Target free space ({target:.1}%) achieved. Stopping.");
                        break;
                    }
                }
            }
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
            match delete_single_candidate(candidate) {
                Ok(()) => {
                    items_deleted += 1;
                    bytes_freed += candidate.size_bytes;
                    if !delete_all {
                        println!("    Deleted.");
                    }
                }
                Err(e) => {
                    eprintln!("    Failed to delete {}: {e}", candidate.path.display());
                }
            }
        } else {
            items_skipped += 1;
        }
    }

    match output_mode(cli) {
        OutputMode::Human => {
            println!("\nCleanup complete:");
            println!(
                "  Deleted: {items_deleted} items, {} freed",
                format_bytes(bytes_freed)
            );
            if items_skipped > 0 {
                println!("  Skipped: {items_skipped} items");
            }
        }
        OutputMode::Json => {
            let payload = json!({
                "command": "clean",
                "scanned_directories": dir_count,
                "elapsed_seconds": scan_elapsed.as_secs_f64(),
                "candidates_count": plan.estimated_items,
                "items_deleted": items_deleted,
                "items_skipped": items_skipped,
                "bytes_freed": bytes_freed,
                "dry_run": false,
                "protected_count": protected_count,
            });
            write_json_line(&payload)?;
        }
    }

    Ok(())
}

/// Delete a single candidate path (file or directory).
fn delete_single_candidate(candidate: &CandidacyScore) -> std::result::Result<(), String> {
    if candidate.path.is_dir() {
        std::fs::remove_dir_all(&candidate.path).map_err(|e| e.to_string())
    } else {
        std::fs::remove_file(&candidate.path).map_err(|e| e.to_string())
    }
}

/// Print a human-readable cleanup summary from a DeletionReport.
fn print_clean_summary(report: &storage_ballast_helper::scanner::deletion::DeletionReport) {
    if report.dry_run {
        println!(
            "Dry run: {} items ({}) would be freed.",
            report.items_deleted,
            format_bytes(report.bytes_freed),
        );
    } else {
        println!("Cleanup complete:");
        println!(
            "  Deleted: {} items, {} freed in {:.1}s",
            report.items_deleted,
            format_bytes(report.bytes_freed),
            report.duration.as_secs_f64(),
        );
        if report.items_skipped > 0 {
            println!("  Skipped: {} items", report.items_skipped);
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

    let payload = json!({
        "command": "clean",
        "scanned_directories": dir_count,
        "elapsed_seconds": scan_elapsed.as_secs_f64(),
        "candidates_count": plan.estimated_items,
        "items_deleted": report.items_deleted,
        "items_skipped": report.items_skipped,
        "items_failed": report.items_failed,
        "bytes_freed": report.bytes_freed,
        "duration_seconds": report.duration.as_secs_f64(),
        "dry_run": report.dry_run,
        "circuit_breaker_tripped": report.circuit_breaker_tripped,
        "protected_count": protected_count,
        "errors": errors,
    });
    write_json_line(&payload)
}

fn run_check(cli: &Cli, args: &CheckArgs) -> Result<(), CliError> {
    let platform = LinuxPlatform::new();

    // Determine check path: CLI arg, or cwd.
    let check_path = args
        .path
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")));

    let stats = platform
        .fs_stats(&check_path)
        .map_err(|e| CliError::Runtime(e.to_string()))?;

    let free_pct = stats.free_pct();
    let default_config = Config::default();
    let threshold_pct = args
        .target_free
        .unwrap_or(default_config.pressure.yellow_min_free_pct);

    // Check 1: absolute free space requirement.
    if let Some(need_bytes) = args.need {
        if stats.available_bytes < need_bytes {
            match output_mode(cli) {
                OutputMode::Human => {
                    eprintln!(
                        "sbh: {} has {} free but {} required. Run: sbh emergency {}",
                        stats.mount_point.display(),
                        format_bytes(stats.available_bytes),
                        format_bytes(need_bytes),
                        check_path.display(),
                    );
                }
                OutputMode::Json => {
                    let payload = json!({
                        "command": "check",
                        "status": "critical",
                        "path": check_path.to_string_lossy(),
                        "mount_point": stats.mount_point.to_string_lossy(),
                        "free_bytes": stats.available_bytes,
                        "need_bytes": need_bytes,
                        "free_pct": free_pct,
                        "exit_code": 2,
                    });
                    write_json_line(&payload)?;
                }
            }
            return Err(CliError::Runtime("insufficient disk space".to_string()));
        }
    }

    // Check 2: percentage threshold.
    if free_pct < threshold_pct {
        match output_mode(cli) {
            OutputMode::Human => {
                eprintln!(
                    "sbh: {} has {} free ({:.1}%). Run: sbh emergency {}",
                    stats.mount_point.display(),
                    format_bytes(stats.available_bytes),
                    free_pct,
                    check_path.display(),
                );
            }
            OutputMode::Json => {
                let payload = json!({
                    "command": "check",
                    "status": "critical",
                    "path": check_path.to_string_lossy(),
                    "mount_point": stats.mount_point.to_string_lossy(),
                    "free_bytes": stats.available_bytes,
                    "total_bytes": stats.total_bytes,
                    "free_pct": free_pct,
                    "threshold_pct": threshold_pct,
                    "exit_code": 2,
                });
                write_json_line(&payload)?;
            }
        }
        return Err(CliError::Runtime("disk space below threshold".to_string()));
    }

    // Check 3: prediction from daemon state.json (if available and --predict requested).
    if let Some(predict_minutes) = args.predict {
        match read_daemon_prediction(&default_config.paths.state_file, &stats.mount_point) {
            Some(rate_bps) if rate_bps > 0.0 => {
                // Positive rate means filling; estimate time to threshold.
                let bytes_until_threshold = stats
                    .available_bytes
                    .saturating_sub((threshold_pct / 100.0 * stats.total_bytes as f64) as u64);
                let seconds_left = bytes_until_threshold as f64 / rate_bps;
                let minutes_left = seconds_left / 60.0;

                if minutes_left < predict_minutes as f64 {
                    match output_mode(cli) {
                        OutputMode::Human => {
                            eprintln!(
                                "sbh: {} has {} free but predicted full in {:.0} min (need {} min)",
                                stats.mount_point.display(),
                                format_bytes(stats.available_bytes),
                                minutes_left,
                                predict_minutes,
                            );
                        }
                        OutputMode::Json => {
                            let payload = json!({
                                "command": "check",
                                "status": "warning",
                                "path": check_path.to_string_lossy(),
                                "mount_point": stats.mount_point.to_string_lossy(),
                                "free_bytes": stats.available_bytes,
                                "free_pct": free_pct,
                                "rate_bytes_per_sec": rate_bps,
                                "minutes_until_full": minutes_left,
                                "predict_minutes": predict_minutes,
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
            _ => {
                // No prediction available — daemon not running or not filling.
                // This is not an error, just degraded mode.
            }
        }
    }

    // All checks passed — silent success on human mode.
    if output_mode(cli) == OutputMode::Json {
        let payload = json!({
            "command": "check",
            "status": "ok",
            "path": check_path.to_string_lossy(),
            "mount_point": stats.mount_point.to_string_lossy(),
            "free_bytes": stats.available_bytes,
            "total_bytes": stats.total_bytes,
            "free_pct": free_pct,
            "exit_code": 0,
        });
        write_json_line(&payload)?;
    }

    Ok(())
}

/// Read EWMA rate prediction from daemon state.json if available and fresh.
fn read_daemon_prediction(state_path: &Path, mount_point: &Path) -> Option<f64> {
    let content = std::fs::read_to_string(state_path).ok()?;

    // Check freshness: file modified within last 30 seconds.
    let meta = std::fs::metadata(state_path).ok()?;
    let modified = meta.modified().ok()?;
    let age = SystemTime::now().duration_since(modified).ok()?;
    if age.as_secs() > 30 {
        return None; // Stale state, daemon likely not running.
    }

    let state: serde_json::Value = serde_json::from_str(&content).ok()?;

    // Look for rate prediction matching the mount point.
    let rates = state.get("rates")?.as_object()?;
    let mount_key = mount_point.to_string_lossy();
    let rate_obj = rates.get(mount_key.as_ref())?;
    rate_obj.get("bytes_per_sec")?.as_f64()
}

fn run_emergency(cli: &Cli, args: &EmergencyArgs) -> Result<(), CliError> {
    let start = std::time::Instant::now();

    // Emergency mode: ZERO disk writes. Use defaults only — no config file.
    let config = Config::default();

    // Determine scan roots: CLI paths, then fall back to defaults.
    let root_paths = if args.paths.is_empty() {
        config.scanner.root_paths.clone()
    } else {
        args.paths.clone()
    };

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
    };
    let walker = DirectoryWalker::new(walker_config, protection);
    let entries = walker
        .walk()
        .map_err(|e| CliError::Runtime(e.to_string()))?;
    let dir_count = entries.len();

    // Collect open files.
    let open_files = collect_open_files();

    // Classify and score using default weights.
    let registry = ArtifactPatternRegistry::default();
    let engine = ScoringEngine::from_config(&config.scoring, config.scanner.min_file_age_minutes);
    let now = SystemTime::now();

    let scored: Vec<CandidacyScore> = entries
        .iter()
        .map(|entry| {
            let classification = registry.classify(&entry.path, entry.structural_signals);
            let age = now
                .duration_since(entry.metadata.modified)
                .unwrap_or_default();
            let candidate = CandidateInput {
                path: entry.path.clone(),
                size_bytes: entry.metadata.size_bytes,
                age,
                classification,
                signals: entry.structural_signals,
                is_open: is_path_open(&entry.path, &open_files),
                excluded: false,
            };
            // High urgency (0.8) for emergency mode — aggressive scoring.
            engine.score_candidate(&candidate, 0.8)
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
        circuit_breaker_threshold: u32::MAX, // Effectively disabled.
        ..Default::default()
    };
    let executor = DeletionExecutor::new(deletion_config, None);
    let plan = executor.plan(scored);

    if plan.candidates.is_empty() {
        match output_mode(cli) {
            OutputMode::Human => {
                eprintln!(
                    "Emergency scan: scanned {} directories in {:.1}s — no cleanup candidates found.",
                    dir_count,
                    scan_elapsed.as_secs_f64(),
                );
                eprintln!(
                    "Config-level protections are not active in emergency mode. Only .sbh-protect marker files are honored."
                );
            }
            OutputMode::Json => {
                let payload = json!({
                    "command": "emergency",
                    "scanned_directories": dir_count,
                    "elapsed_seconds": scan_elapsed.as_secs_f64(),
                    "candidates_count": 0,
                    "items_deleted": 0,
                    "bytes_freed": 0,
                });
                write_json_line(&payload)?;
            }
        }
        return Err(CliError::User("no cleanup candidates found".to_string()));
    }

    // Display candidates.
    if output_mode(cli) == OutputMode::Human {
        eprintln!("EMERGENCY MODE — zero-write recovery");
        eprintln!(
            "Scanned {} directories in {:.1}s\n",
            dir_count,
            scan_elapsed.as_secs_f64(),
        );
        eprintln!(
            "Config-level protections are not active in emergency mode. Only .sbh-protect marker files are honored.\n"
        );
        eprintln!("Candidates for deletion:\n");
        print_deletion_plan(&plan);
        eprintln!(
            "\nTotal: {} items, {}",
            plan.estimated_items,
            format_bytes(plan.total_reclaimable_bytes),
        );
        eprintln!();
    }

    // Execute based on flags.
    if args.yes || !io::stdout().is_terminal() {
        let pressure_check = build_pressure_check(Some(args.target_free), &root_paths);
        let report = executor.execute(
            &plan,
            pressure_check.as_ref().map(|f| f as &dyn Fn() -> bool),
        );

        match output_mode(cli) {
            OutputMode::Human => {
                print_clean_summary(&report);
                eprintln!(
                    "\nConsider installing sbh for ongoing protection: sbh install --systemd --user"
                );
            }
            OutputMode::Json => {
                emit_clean_report_json(&plan, &report, dir_count, scan_elapsed, 0)?;
            }
        }
    } else {
        // Interactive emergency cleanup.
        run_interactive_emergency(cli, &plan, args, &root_paths, dir_count, scan_elapsed)?;
    }

    Ok(())
}

/// Interactive emergency cleanup — like interactive clean but with emergency messaging.
fn run_interactive_emergency(
    cli: &Cli,
    plan: &DeletionPlan,
    args: &EmergencyArgs,
    root_paths: &[PathBuf],
    dir_count: usize,
    scan_elapsed: std::time::Duration,
) -> Result<(), CliError> {
    let stdin = io::stdin();
    let mut input = String::new();
    let mut items_deleted: usize = 0;
    let mut items_skipped: usize = 0;
    let mut bytes_freed: u64 = 0;
    let mut delete_all = false;

    let platform = LinuxPlatform::new();

    eprintln!("Proceed with deletion? [y/N/a(ll)/s(kip)/q(uit)]");

    for (i, candidate) in plan.candidates.iter().enumerate() {
        // Check target_free stop condition.
        if let Some(first_root) = root_paths.first() {
            if let Ok(stats) = platform.fs_stats(first_root) {
                if stats.free_pct() >= args.target_free {
                    eprintln!(
                        "  Target free space ({:.1}%) achieved. Stopping.",
                        args.target_free,
                    );
                    break;
                }
            }
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
            match delete_single_candidate(candidate) {
                Ok(()) => {
                    items_deleted += 1;
                    bytes_freed += candidate.size_bytes;
                    if !delete_all {
                        eprintln!("    Deleted.");
                    }
                }
                Err(e) => {
                    eprintln!("    Failed: {e}");
                }
            }
        } else {
            items_skipped += 1;
        }
    }

    match output_mode(cli) {
        OutputMode::Human => {
            eprintln!("\nEmergency cleanup complete:");
            eprintln!(
                "  Deleted: {items_deleted} items, {} freed",
                format_bytes(bytes_freed),
            );
            if items_skipped > 0 {
                eprintln!("  Skipped: {items_skipped} items");
            }
            eprintln!(
                "\nConsider installing sbh for ongoing protection: sbh install --systemd --user"
            );
        }
        OutputMode::Json => {
            let payload = json!({
                "command": "emergency",
                "scanned_directories": dir_count,
                "elapsed_seconds": scan_elapsed.as_secs_f64(),
                "candidates_count": plan.estimated_items,
                "items_deleted": items_deleted,
                "items_skipped": items_skipped,
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

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    const TIB: u64 = 1024 * GIB;

    if bytes >= TIB {
        format!("{:.1} TB", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.1} GB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KB", bytes as f64 / KIB as f64)
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
        format!("...{}", &s[s.len() - (max_len - 3)..])
    }
}

fn emit_stub_with_args<T: Serialize>(cli: &Cli, command: &str, args: &T) -> Result<(), CliError> {
    let message = format!("{command}: not yet implemented");
    match output_mode(cli) {
        OutputMode::Human => {
            println!("{message}");
        }
        OutputMode::Json => {
            let payload = json!({
                "command": command,
                "status": "not_implemented",
                "message": message,
                "args": serde_json::to_value(args)?,
            });
            write_json_line(&payload)?;
        }
    }
    Ok(())
}

fn emit_version(cli: &Cli, args: &VersionArgs) -> Result<(), CliError> {
    let version = env!("CARGO_PKG_VERSION");
    let package = env!("CARGO_PKG_NAME");
    let target = option_env!("TARGET").unwrap_or("unknown");
    let profile = option_env!("PROFILE").unwrap_or("unknown");
    let git_sha = option_env!("VERGEN_GIT_SHA")
        .or(option_env!("GIT_SHA"))
        .unwrap_or("unknown");
    let build_timestamp = option_env!("VERGEN_BUILD_TIMESTAMP")
        .or(option_env!("BUILD_TIMESTAMP"))
        .unwrap_or("unknown");

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
        Some("auto") | None => fallback,
        Some(_) => fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            vec!["sbh", "tune", "--apply"],
            vec!["sbh", "check", "/data", "--target-free", "20"],
            vec!["sbh", "blame", "--top", "10"],
            vec!["sbh", "dashboard", "--refresh-ms", "250"],
            vec!["sbh", "ballast", "status"],
            vec!["sbh", "ballast", "release", "2"],
            vec!["sbh", "config", "path"],
            vec!["sbh", "config", "set", "policy.mode", "observe"],
            vec!["sbh", "version", "--verbose"],
        ];

        for case in cases {
            let parsed = Cli::try_parse_from(case.clone());
            assert!(parsed.is_ok(), "failed to parse case: {case:?}");
        }
    }

    #[test]
    fn protect_requires_path_or_list() {
        assert!(Cli::try_parse_from(["sbh", "protect"]).is_err());
        assert!(Cli::try_parse_from(["sbh", "protect", "--list"]).is_ok());
        assert!(Cli::try_parse_from(["sbh", "protect", "/tmp/work"]).is_ok());
        assert!(Cli::try_parse_from(["sbh", "protect", "/tmp/work", "--list"]).is_err());
    }

    #[test]
    fn completions_support_bash_zsh_and_fish() {
        for shell in ["bash", "zsh", "fish"] {
            let parsed = Cli::try_parse_from(["sbh", "completions", shell]);
            assert!(parsed.is_ok(), "failed shell parse for {shell}");
        }
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
            ("30m", 1800),
            ("1h", 3600),
            ("24h", 86400),
            ("7d", 604800),
            ("90s", 90),
            ("15min", 900),
            ("2hr", 7200),
            ("1day", 86400),
            ("60", 3600), // bare number defaults to minutes
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
        for case in cases {
            let parsed = Cli::try_parse_from(case.clone());
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
        for case in cases {
            let parsed = Cli::try_parse_from(case.clone());
            assert!(parsed.is_ok(), "failed to parse tune case: {case:?}");
        }
        // --yes without --apply should fail.
        assert!(Cli::try_parse_from(["sbh", "tune", "--yes"]).is_err());
    }

    #[test]
    fn generate_recommendations_empty_stats_returns_none() {
        let config = Config::default();
        let recs = generate_recommendations(&config, &[]);
        assert!(recs.is_empty());
    }

    #[test]
    fn generate_recommendations_ballast_exhaustion() {
        use storage_ballast_helper::logger::stats::*;

        let config = Config::default();
        let ws = WindowStats {
            window: std::time::Duration::from_secs(86400),
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
            window: std::time::Duration::from_secs(86400),
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
            window: std::time::Duration::from_secs(3600),
            deletions: DeletionStats {
                count: 10,
                total_bytes_freed: 1_000_000,
                avg_size: 100_000,
                median_size: 80_000,
                largest_deletion: None,
                most_common_category: None,
                avg_score: 0.85,
                avg_age_hours: 1.0,
                failures: 5,
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
        ] {
            assert!(
                help.contains(keyword),
                "help output missing command: {keyword}"
            );
        }
    }
}
