//! Guided first-run install wizard and non-interactive `--auto` mode.
//!
//! The wizard collects user preferences for watched paths, ballast sizing,
//! and service registration, then generates a validated config file. The
//! `--auto` path applies documented defaults without any prompts, making it
//! safe for CI/agent automation.

use std::fmt::{self, Write as _};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::core::config::Config;

// ---------------------------------------------------------------------------
// Wizard choices
// ---------------------------------------------------------------------------

/// Service manager selection for the wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ServiceChoice {
    /// Install as a systemd service.
    Systemd,
    /// Install as a launchd service.
    Launchd,
    /// Skip service installation (manual start).
    None,
}

impl fmt::Display for ServiceChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Systemd => f.write_str("systemd"),
            Self::Launchd => f.write_str("launchd"),
            Self::None => f.write_str("none"),
        }
    }
}

/// Ballast sizing preset for the wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum BallastPreset {
    /// 5 GB (small workstation).
    Small,
    /// 10 GB (typical workstation, default).
    Medium,
    /// 20 GB (large server).
    Large,
    /// User-specified custom values.
    Custom,
}

impl BallastPreset {
    /// File count for this preset.
    #[must_use]
    pub const fn file_count(self) -> usize {
        match self {
            Self::Small => 5,
            Self::Medium | Self::Custom => 10,
            Self::Large => 20,
        }
    }

    /// Per-file size in bytes for this preset.
    #[must_use]
    pub const fn file_size_bytes(self) -> u64 {
        // 1 GiB per file for all presets.
        1_073_741_824
    }

    /// Total ballast size for display.
    #[must_use]
    pub const fn total_gb(self) -> usize {
        match self {
            Self::Small => 5,
            Self::Medium => 10,
            Self::Large => 20,
            Self::Custom => 0,
        }
    }
}

impl fmt::Display for BallastPreset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Small => f.write_str("small (5 GB)"),
            Self::Medium => f.write_str("medium (10 GB)"),
            Self::Large => f.write_str("large (20 GB)"),
            Self::Custom => f.write_str("custom"),
        }
    }
}

// ---------------------------------------------------------------------------
// Wizard output
// ---------------------------------------------------------------------------

/// Collected wizard answers ready for config generation.
#[derive(Debug, Clone, Serialize)]
pub struct WizardAnswers {
    /// Service manager to install.
    pub service: ServiceChoice,
    /// Whether to install as user service (vs system).
    pub user_scope: bool,
    /// Paths to watch for build artifacts.
    pub watched_paths: Vec<PathBuf>,
    /// Ballast sizing preset.
    pub ballast_preset: BallastPreset,
    /// Ballast file count (may differ from preset for Custom).
    pub ballast_file_count: usize,
    /// Ballast file size in bytes.
    pub ballast_file_size_bytes: u64,
    /// Whether the wizard ran in auto mode.
    pub auto_mode: bool,
}

impl WizardAnswers {
    /// Build a `Config` from the wizard answers.
    #[must_use]
    pub fn to_config(&self) -> Config {
        let mut config = Config::default();

        // Override scanner root paths with wizard selections.
        config.scanner.root_paths.clone_from(&self.watched_paths);

        // Override ballast settings.
        config.ballast.file_count = self.ballast_file_count;
        config.ballast.file_size_bytes = self.ballast_file_size_bytes;

        config
    }
}

/// Summary of the wizard run for display.
#[derive(Debug, Clone, Serialize)]
pub struct WizardSummary {
    /// Answers collected.
    pub answers: WizardAnswers,
    /// Path where config was (or would be) written.
    pub config_path: PathBuf,
    /// Whether config was actually written (false in dry-run).
    pub config_written: bool,
    /// Any warnings generated.
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Auto mode
// ---------------------------------------------------------------------------

/// Run the wizard in non-interactive `--auto` mode.
///
/// Applies smart defaults without prompting:
/// - Service: systemd on Linux, launchd on macOS, none on Windows.
/// - Watched paths: `/data/projects`, `/tmp`, and `$HOME` if set.
/// - Ballast: medium preset (10 GB).
/// - Scope: user service.
#[must_use]
pub fn auto_answers() -> WizardAnswers {
    let service = auto_detect_service();
    let watched = auto_detect_watched_paths();
    let preset = BallastPreset::Medium;

    WizardAnswers {
        service,
        user_scope: true,
        watched_paths: watched,
        ballast_preset: preset,
        ballast_file_count: preset.file_count(),
        ballast_file_size_bytes: preset.file_size_bytes(),
        auto_mode: true,
    }
}

fn auto_detect_service() -> ServiceChoice {
    if cfg!(target_os = "macos") {
        ServiceChoice::Launchd
    } else if cfg!(target_os = "linux") {
        ServiceChoice::Systemd
    } else {
        ServiceChoice::None
    }
}

fn auto_detect_watched_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // Standard defaults.
    let data_projects = PathBuf::from("/data/projects");
    if data_projects.is_dir() {
        paths.push(data_projects);
    }

    let tmp = PathBuf::from("/tmp");
    if tmp.is_dir() {
        paths.push(tmp);
    }

    // User home directory.
    if let Some(home) = std::env::var_os("HOME") {
        let home_path = PathBuf::from(home);
        if home_path.is_dir() && !paths.contains(&home_path) {
            paths.push(home_path);
        }
    }

    // Guarantee at least the defaults if nothing exists.
    if paths.is_empty() {
        paths.push(PathBuf::from("/data/projects"));
        paths.push(PathBuf::from("/tmp"));
    }

    paths
}

// ---------------------------------------------------------------------------
// Interactive wizard
// ---------------------------------------------------------------------------

/// Run the interactive wizard, reading from `reader` and writing prompts to `writer`.
///
/// This is parameterized over I/O for testability.
pub fn run_interactive<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> io::Result<WizardAnswers> {
    let _ = writeln!(writer, "\n  Storage Ballast Helper — First-Run Setup\n");
    let _ = writeln!(writer, "  This wizard will configure sbh for your system.\n");

    // Step 1: Service manager.
    let service = prompt_service(reader, writer)?;

    // Step 2: User vs system scope.
    let user_scope = if service == ServiceChoice::None {
        true
    } else {
        prompt_user_scope(reader, writer)?
    };

    // Step 3: Watched paths.
    let watched_paths = prompt_watched_paths(reader, writer)?;

    // Step 4: Ballast sizing.
    let (preset, file_count, file_size) = prompt_ballast(reader, writer)?;

    // Step 5: Confirmation.
    let answers = WizardAnswers {
        service,
        user_scope,
        watched_paths,
        ballast_preset: preset,
        ballast_file_count: file_count,
        ballast_file_size_bytes: file_size,
        auto_mode: false,
    };

    let _ = writeln!(writer);
    display_summary(writer, &answers);

    let confirmed = prompt_confirm(reader, writer, "Proceed with this configuration?")?;
    if !confirmed {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "wizard cancelled by user",
        ));
    }

    Ok(answers)
}

fn prompt_service<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> io::Result<ServiceChoice> {
    let _ = writeln!(writer, "  [1/4] Service manager");

    let default = if cfg!(target_os = "macos") {
        "launchd"
    } else if cfg!(target_os = "linux") {
        "systemd"
    } else {
        "none"
    };

    let _ = writeln!(writer, "    Options: systemd, launchd, none");
    let _ = write!(writer, "    Choice [{default}]: ");
    writer.flush()?;

    let input = read_line(reader)?;
    let choice = if input.is_empty() { default } else { &input };

    match choice.trim().to_ascii_lowercase().as_str() {
        "systemd" | "s" => Ok(ServiceChoice::Systemd),
        "launchd" | "l" => Ok(ServiceChoice::Launchd),
        "none" | "n" => Ok(ServiceChoice::None),
        _ => {
            let _ = writeln!(writer, "    Unrecognized, using default: {default}");
            match default {
                "launchd" => Ok(ServiceChoice::Launchd),
                "systemd" => Ok(ServiceChoice::Systemd),
                _ => Ok(ServiceChoice::None),
            }
        }
    }
}

fn prompt_user_scope<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> io::Result<bool> {
    let _ = writeln!(writer);
    let _ = writeln!(writer, "  [1b] Service scope");
    let _ = write!(writer, "    Install as user service? [Y/n]: ");
    writer.flush()?;

    let input = read_line(reader)?;
    Ok(!input.trim().eq_ignore_ascii_case("n"))
}

fn prompt_watched_paths<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> io::Result<Vec<PathBuf>> {
    let defaults = auto_detect_watched_paths();
    let default_display: Vec<String> = defaults
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    let _ = writeln!(writer);
    let _ = writeln!(writer, "  [2/4] Watched paths for artifact scanning");
    let _ = writeln!(writer, "    Defaults: {}", default_display.join(", "));
    let _ = write!(
        writer,
        "    Enter paths (comma-separated) or press Enter for defaults: "
    );
    writer.flush()?;

    let input = read_line(reader)?;
    if input.trim().is_empty() {
        return Ok(defaults);
    }

    let paths: Vec<PathBuf> = input
        .split(',')
        .map(|s| PathBuf::from(s.trim()))
        .filter(|p| !p.as_os_str().is_empty())
        .collect();

    if paths.is_empty() {
        Ok(defaults)
    } else {
        Ok(paths)
    }
}

fn prompt_ballast<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> io::Result<(BallastPreset, usize, u64)> {
    let _ = writeln!(writer);
    let _ = writeln!(writer, "  [3/4] Ballast pool sizing");
    let _ = writeln!(writer, "    Presets:");
    let _ = writeln!(writer, "      s) Small  —  5 GB (5 x 1 GB files)");
    let _ = writeln!(writer, "      m) Medium — 10 GB (10 x 1 GB files) [default]");
    let _ = writeln!(writer, "      l) Large  — 20 GB (20 x 1 GB files)");
    let _ = write!(writer, "    Choice [m]: ");
    writer.flush()?;

    let input = read_line(reader)?;
    let choice = input.trim().to_ascii_lowercase();

    let preset = match choice.as_str() {
        "s" | "small" => BallastPreset::Small,
        "l" | "large" => BallastPreset::Large,
        "" | "m" | "medium" => BallastPreset::Medium,
        _ => {
            let _ = writeln!(writer, "    Unrecognized, using medium.");
            BallastPreset::Medium
        }
    };

    Ok((preset, preset.file_count(), preset.file_size_bytes()))
}

fn prompt_confirm<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    message: &str,
) -> io::Result<bool> {
    let _ = write!(writer, "  {message} [Y/n]: ");
    writer.flush()?;

    let input = read_line(reader)?;
    Ok(!input.trim().eq_ignore_ascii_case("n"))
}

fn display_summary<W: Write>(writer: &mut W, answers: &WizardAnswers) {
    let _ = writeln!(writer, "  [4/4] Configuration summary");
    let _ = writeln!(writer, "    Service: {}", answers.service);
    if answers.service != ServiceChoice::None {
        let scope = if answers.user_scope { "user" } else { "system" };
        let _ = writeln!(writer, "    Scope: {scope}");
    }
    let _ = writeln!(writer, "    Watched paths:");
    for path in &answers.watched_paths {
        let _ = writeln!(writer, "      - {}", path.display());
    }
    let _ = writeln!(writer, "    Ballast: {} ({} x {} GB files)",
        answers.ballast_preset,
        answers.ballast_file_count,
        answers.ballast_file_size_bytes / 1_073_741_824,
    );
}

fn read_line<R: BufRead>(reader: &mut R) -> io::Result<String> {
    let mut line = String::new();
    reader.read_line(&mut line)?;
    Ok(line.trim_end_matches('\n').trim_end_matches('\r').to_string())
}

// ---------------------------------------------------------------------------
// Config generation
// ---------------------------------------------------------------------------

/// Generate and write the config file from wizard answers.
///
/// Returns the path where config was written.
pub fn write_config(answers: &WizardAnswers, config_path: &Path) -> io::Result<PathBuf> {
    let config = answers.to_config();
    let toml_str = toml::to_string_pretty(&config).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to serialize config: {e}"),
        )
    })?;

    // Create parent directories.
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(config_path, toml_str)?;
    Ok(config_path.to_path_buf())
}

/// Format wizard summary for human-readable output.
#[must_use]
pub fn format_summary(summary: &WizardSummary) -> String {
    let mut out = String::new();

    let mode = if summary.answers.auto_mode {
        "auto"
    } else {
        "interactive"
    };
    let _ = writeln!(out, "Install wizard completed ({mode} mode).\n");
    let _ = writeln!(out, "  Service: {}", summary.answers.service);
    if summary.answers.service != ServiceChoice::None {
        let scope = if summary.answers.user_scope {
            "user"
        } else {
            "system"
        };
        let _ = writeln!(out, "  Scope: {scope}");
    }

    let _ = writeln!(out, "  Watched paths:");
    for path in &summary.answers.watched_paths {
        let _ = writeln!(out, "    - {}", path.display());
    }

    let _ = writeln!(
        out,
        "  Ballast: {} files x {} GB",
        summary.answers.ballast_file_count,
        summary.answers.ballast_file_size_bytes / 1_073_741_824,
    );

    let _ = writeln!(out, "  Config: {}", summary.config_path.display());
    if summary.config_written {
        out.push_str("  Status: config written successfully\n");
    } else {
        out.push_str("  Status: dry-run (config not written)\n");
    }

    for warning in &summary.warnings {
        let _ = writeln!(out, "  Warning: {warning}");
    }

    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_choice_display() {
        assert_eq!(ServiceChoice::Systemd.to_string(), "systemd");
        assert_eq!(ServiceChoice::Launchd.to_string(), "launchd");
        assert_eq!(ServiceChoice::None.to_string(), "none");
    }

    #[test]
    fn ballast_preset_display() {
        assert_eq!(BallastPreset::Small.to_string(), "small (5 GB)");
        assert_eq!(BallastPreset::Medium.to_string(), "medium (10 GB)");
        assert_eq!(BallastPreset::Large.to_string(), "large (20 GB)");
        assert_eq!(BallastPreset::Custom.to_string(), "custom");
    }

    #[test]
    fn ballast_preset_sizing() {
        assert_eq!(BallastPreset::Small.file_count(), 5);
        assert_eq!(BallastPreset::Medium.file_count(), 10);
        assert_eq!(BallastPreset::Large.file_count(), 20);
        assert_eq!(BallastPreset::Small.total_gb(), 5);
        assert_eq!(BallastPreset::Medium.total_gb(), 10);
        assert_eq!(BallastPreset::Large.total_gb(), 20);
    }

    #[test]
    fn auto_answers_uses_smart_defaults() {
        let answers = auto_answers();
        assert!(answers.auto_mode);
        assert!(answers.user_scope);
        assert!(!answers.watched_paths.is_empty());
        assert_eq!(answers.ballast_preset, BallastPreset::Medium);
        assert_eq!(answers.ballast_file_count, 10);
        assert_eq!(answers.ballast_file_size_bytes, 1_073_741_824);
    }

    #[test]
    fn auto_answers_detects_platform_service() {
        let answers = auto_answers();
        if cfg!(target_os = "linux") {
            assert_eq!(answers.service, ServiceChoice::Systemd);
        } else if cfg!(target_os = "macos") {
            assert_eq!(answers.service, ServiceChoice::Launchd);
        } else {
            assert_eq!(answers.service, ServiceChoice::None);
        }
    }

    #[test]
    fn wizard_answers_to_config() {
        let answers = WizardAnswers {
            service: ServiceChoice::Systemd,
            user_scope: true,
            watched_paths: vec![PathBuf::from("/home/user/projects")],
            ballast_preset: BallastPreset::Small,
            ballast_file_count: 5,
            ballast_file_size_bytes: 1_073_741_824,
            auto_mode: false,
        };

        let config = answers.to_config();
        assert_eq!(config.scanner.root_paths, vec![PathBuf::from("/home/user/projects")]);
        assert_eq!(config.ballast.file_count, 5);
        assert_eq!(config.ballast.file_size_bytes, 1_073_741_824);
    }

    #[test]
    fn interactive_wizard_accepts_defaults() {
        // Simulate pressing Enter for every prompt (accept all defaults).
        let input = "\n\n\n\n\n";
        let mut reader = io::Cursor::new(input.as_bytes());
        let mut output = Vec::new();

        let answers = run_interactive(&mut reader, &mut output).unwrap();

        // Should have selected platform-appropriate service.
        if cfg!(target_os = "linux") {
            assert_eq!(answers.service, ServiceChoice::Systemd);
        }
        assert!(answers.user_scope);
        assert!(!answers.watched_paths.is_empty());
        assert_eq!(answers.ballast_preset, BallastPreset::Medium);
        assert!(!answers.auto_mode);
    }

    #[test]
    fn interactive_wizard_selects_systemd() {
        let input = "systemd\n\n\n\n\n";
        let mut reader = io::Cursor::new(input.as_bytes());
        let mut output = Vec::new();

        let answers = run_interactive(&mut reader, &mut output).unwrap();
        assert_eq!(answers.service, ServiceChoice::Systemd);
    }

    #[test]
    fn interactive_wizard_selects_none_service() {
        // "none" skips service scope prompt.
        let input = "none\n\n\n\n";
        let mut reader = io::Cursor::new(input.as_bytes());
        let mut output = Vec::new();

        let answers = run_interactive(&mut reader, &mut output).unwrap();
        assert_eq!(answers.service, ServiceChoice::None);
    }

    #[test]
    fn interactive_wizard_custom_paths() {
        let input = "none\n/opt/work,/srv/builds\n\n\n";
        let mut reader = io::Cursor::new(input.as_bytes());
        let mut output = Vec::new();

        let answers = run_interactive(&mut reader, &mut output).unwrap();
        assert_eq!(
            answers.watched_paths,
            vec![PathBuf::from("/opt/work"), PathBuf::from("/srv/builds")]
        );
    }

    #[test]
    fn interactive_wizard_selects_small_ballast() {
        let input = "none\n\ns\n\n";
        let mut reader = io::Cursor::new(input.as_bytes());
        let mut output = Vec::new();

        let answers = run_interactive(&mut reader, &mut output).unwrap();
        assert_eq!(answers.ballast_preset, BallastPreset::Small);
        assert_eq!(answers.ballast_file_count, 5);
    }

    #[test]
    fn interactive_wizard_selects_large_ballast() {
        let input = "none\n\nlarge\n\n";
        let mut reader = io::Cursor::new(input.as_bytes());
        let mut output = Vec::new();

        let answers = run_interactive(&mut reader, &mut output).unwrap();
        assert_eq!(answers.ballast_preset, BallastPreset::Large);
        assert_eq!(answers.ballast_file_count, 20);
    }

    #[test]
    fn interactive_wizard_cancel() {
        let input = "none\n\n\nn\n";
        let mut reader = io::Cursor::new(input.as_bytes());
        let mut output = Vec::new();

        let result = run_interactive(&mut reader, &mut output);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
    }

    #[test]
    fn write_config_creates_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config_path = tmp.path().join("sbh").join("config.toml");

        let answers = auto_answers();
        let written = write_config(&answers, &config_path).unwrap();
        assert_eq!(written, config_path);
        assert!(config_path.exists());

        let contents = std::fs::read_to_string(&config_path).unwrap();
        assert!(contents.contains("[scanner]"), "should contain scanner section");
        assert!(contents.contains("[ballast]"), "should contain ballast section");
    }

    #[test]
    fn write_config_creates_parent_dirs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config_path = tmp.path().join("deep").join("nested").join("config.toml");

        let answers = auto_answers();
        write_config(&answers, &config_path).unwrap();
        assert!(config_path.exists());
    }

    #[test]
    fn format_summary_auto_mode() {
        let summary = WizardSummary {
            answers: auto_answers(),
            config_path: PathBuf::from("/home/user/.config/sbh/config.toml"),
            config_written: true,
            warnings: vec![],
        };
        let output = format_summary(&summary);
        assert!(output.contains("auto mode"));
        assert!(output.contains("config written successfully"));
    }

    #[test]
    fn format_summary_interactive_mode() {
        let summary = WizardSummary {
            answers: WizardAnswers {
                service: ServiceChoice::Systemd,
                user_scope: false,
                watched_paths: vec![PathBuf::from("/opt")],
                ballast_preset: BallastPreset::Large,
                ballast_file_count: 20,
                ballast_file_size_bytes: 1_073_741_824,
                auto_mode: false,
            },
            config_path: PathBuf::from("/etc/sbh/config.toml"),
            config_written: false,
            warnings: vec!["Ballast pool requires 20 GB free space".into()],
        };
        let output = format_summary(&summary);
        assert!(output.contains("interactive mode"));
        assert!(output.contains("system"));
        assert!(output.contains("dry-run"));
        assert!(output.contains("20 GB free space"));
    }

    #[test]
    fn summary_serializes_to_json() {
        let summary = WizardSummary {
            answers: auto_answers(),
            config_path: PathBuf::from("/tmp/config.toml"),
            config_written: false,
            warnings: vec![],
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"auto_mode\":true"));
        assert!(json.contains("\"config_written\":false"));
    }

    #[test]
    fn auto_detect_watched_paths_not_empty() {
        let paths = auto_detect_watched_paths();
        assert!(!paths.is_empty(), "should always return at least default paths");
    }

    #[test]
    fn wizard_output_contains_prompts() {
        let input = "\n\n\n\n";
        let mut reader = io::Cursor::new(input.as_bytes());
        let mut output = Vec::new();

        let _ = run_interactive(&mut reader, &mut output);

        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("First-Run Setup"), "should show header");
        assert!(text.contains("Service manager"), "should prompt for service");
        assert!(text.contains("Watched paths"), "should prompt for paths");
        assert!(text.contains("Ballast"), "should prompt for ballast");
    }
}
