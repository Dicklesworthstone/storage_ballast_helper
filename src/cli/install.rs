//! Install/uninstall orchestration for `sbh install` and `sbh uninstall`.
//!
//! Coordinates the multi-step install sequence: config generation, data
//! directory creation, ballast provisioning, service registration, and
//! post-install verification. The uninstall path reverses these steps
//! with optional data/ballast retention.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::ballast::manager::BallastManager;
use crate::core::config::{BallastConfig, Config, PathsConfig};
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
    /// Path to the config file (if written).
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
    /// Config to write.
    pub config: Config,
    /// Number of ballast files to create.
    pub ballast_count: usize,
    /// Size of each ballast file in bytes.
    pub ballast_size_bytes: u64,
    /// Override ballast directory path.
    pub ballast_path: Option<PathBuf>,
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
/// 2. Write config file.
/// 3. Provision ballast files.
///
/// Service registration (systemd/launchd) is handled separately in `cli_app.rs`.
pub fn run_install_sequence(opts: &InstallOptions) -> InstallReport {
    let mut report = InstallReport::new(opts.dry_run);
    let paths = &opts.config.paths;

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

    // Step 2: Write config file.
    let config_path = &paths.config_file;
    if opts.dry_run {
        report.step_plan(format!("Write config: {}", config_path.display()));
    } else {
        match write_config(&opts.config, config_path) {
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

    // Step 3: Provision ballast files.
    let ballast_dir = opts
        .ballast_path
        .clone()
        .unwrap_or_else(|| paths.ballast_dir.clone());

    let ballast_config = BallastConfig {
        file_count: opts.ballast_count,
        file_size_bytes: opts.ballast_size_bytes,
        ..opts.config.ballast.clone()
    };

    if opts.dry_run {
        let total_gb = (opts.ballast_count as u64 * opts.ballast_size_bytes) / 1_073_741_824;
        report.step_plan(format!(
            "Provision ballast: {} files x {} MB = {} GB in {}",
            opts.ballast_count,
            opts.ballast_size_bytes / (1024 * 1024),
            total_gb,
            ballast_dir.display()
        ));
    } else {
        match BallastManager::new(ballast_dir.clone(), ballast_config) {
            Ok(mut mgr) => match mgr.provision(None) {
                Ok(prov_report) => {
                    report.step_ok(format!(
                        "Provisioned ballast: {} files ({} bytes) in {}",
                        prov_report.files_created,
                        prov_report.total_bytes,
                        ballast_dir.display()
                    ));
                    report.ballast_dir = Some(ballast_dir);
                    report.ballast_files_created = prov_report.files_created;
                    report.ballast_bytes = prov_report.total_bytes;
                }
                Err(e) => {
                    report.step_fail(
                        format!("Provision ballast in {}", ballast_dir.display()),
                        e.to_string(),
                    );
                    // Ballast failure is non-fatal; install can proceed.
                }
            },
            Err(e) => {
                report.step_fail(
                    format!("Initialize ballast manager in {}", ballast_dir.display()),
                    e.to_string(),
                );
            }
        }
    }

    // Mark overall success: config was written (or dry-run planned).
    report.success = report.steps.iter().all(|s| s.error.is_none());
    report
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

    std::fs::write(path, toml_str)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Uninstall options and report
// ---------------------------------------------------------------------------

/// Options for uninstall.
#[derive(Debug, Clone, Default)]
pub struct UninstallOptions {
    /// Keep the data directory and logs.
    pub keep_data: bool,
    /// Keep ballast files (don't reclaim space).
    pub keep_ballast: bool,
    /// Show plan without executing.
    pub dry_run: bool,
    /// Paths config for locating artifacts.
    pub paths: PathsConfig,
}

/// Structured report from an uninstall run.
#[derive(Debug, Clone, Serialize)]
pub struct UninstallReport {
    /// Steps attempted.
    pub steps: Vec<InstallStep>,
    /// Overall success.
    pub success: bool,
    /// Bytes reclaimed from ballast removal.
    pub bytes_reclaimed: u64,
    /// Whether this was a dry run.
    pub dry_run: bool,
}

/// Run the uninstall data/ballast cleanup sequence.
///
/// Service unregistration (systemd/launchd) is handled separately in `cli_app.rs`.
pub fn run_uninstall_cleanup(opts: &UninstallOptions) -> UninstallReport {
    let mut report = UninstallReport {
        steps: Vec::new(),
        success: true,
        bytes_reclaimed: 0,
        dry_run: opts.dry_run,
    };

    if !opts.keep_ballast {
        cleanup_ballast(&opts.paths.ballast_dir, opts.dry_run, &mut report);
    }

    if !opts.keep_data {
        let data_dir = opts
            .paths
            .state_file
            .parent()
            .unwrap_or_else(|| Path::new("/tmp"));
        cleanup_directory(data_dir, "data directory", opts.dry_run, &mut report);
        cleanup_file(&opts.paths.config_file, "config", opts.dry_run, &mut report);
    }

    report
}

fn cleanup_ballast(ballast_dir: &Path, dry_run: bool, report: &mut UninstallReport) {
    if dry_run {
        report.steps.push(InstallStep {
            description: format!("Remove ballast directory: {}", ballast_dir.display()),
            done: false,
            error: None,
        });
    } else if ballast_dir.is_dir() {
        match remove_directory_contents(ballast_dir) {
            Ok(bytes) => {
                report.steps.push(InstallStep {
                    description: format!(
                        "Removed ballast files in {} ({bytes} bytes reclaimed)",
                        ballast_dir.display()
                    ),
                    done: true,
                    error: None,
                });
                report.bytes_reclaimed = bytes;
            }
            Err(e) => {
                report.steps.push(InstallStep {
                    description: format!("Remove ballast directory: {}", ballast_dir.display()),
                    done: false,
                    error: Some(e.to_string()),
                });
                report.success = false;
            }
        }
    } else {
        report.steps.push(InstallStep {
            description: format!("Ballast directory not found: {}", ballast_dir.display()),
            done: true,
            error: None,
        });
    }
}

fn cleanup_directory(dir: &Path, label: &str, dry_run: bool, report: &mut UninstallReport) {
    if dry_run {
        report.steps.push(InstallStep {
            description: format!("Remove {label}: {}", dir.display()),
            done: false,
            error: None,
        });
    } else if dir.is_dir() {
        match std::fs::remove_dir_all(dir) {
            Ok(()) => {
                report.steps.push(InstallStep {
                    description: format!("Removed {label}: {}", dir.display()),
                    done: true,
                    error: None,
                });
            }
            Err(e) => {
                report.steps.push(InstallStep {
                    description: format!("Remove {label}: {}", dir.display()),
                    done: false,
                    error: Some(e.to_string()),
                });
                report.success = false;
            }
        }
    } else {
        report.steps.push(InstallStep {
            description: format!("{label} not found: {}", dir.display()),
            done: true,
            error: None,
        });
    }
}

fn cleanup_file(path: &Path, label: &str, dry_run: bool, report: &mut UninstallReport) {
    if dry_run {
        report.steps.push(InstallStep {
            description: format!("Remove {label}: {}", path.display()),
            done: false,
            error: None,
        });
    } else if path.is_file() {
        match std::fs::remove_file(path) {
            Ok(()) => {
                report.steps.push(InstallStep {
                    description: format!("Removed {label}: {}", path.display()),
                    done: true,
                    error: None,
                });
            }
            Err(e) => {
                report.steps.push(InstallStep {
                    description: format!("Remove {label}: {}", path.display()),
                    done: false,
                    error: Some(e.to_string()),
                });
                report.success = false;
            }
        }
    }
}

fn remove_directory_contents(dir: &Path) -> std::io::Result<u64> {
    let mut bytes = 0u64;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.is_file() {
            bytes += meta.len();
            std::fs::remove_file(entry.path())?;
        }
    }
    // Remove the directory itself after contents are cleared.
    std::fs::remove_dir(dir)?;
    Ok(bytes)
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

/// Format an uninstall report for terminal output.
#[must_use]
pub fn format_uninstall_report(report: &UninstallReport) -> String {
    let mut out = String::new();

    let mode = if report.dry_run {
        "dry-run"
    } else {
        "uninstall"
    };
    let _ = writeln!(out, "sbh {mode} cleanup report:\n");

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

    if report.bytes_reclaimed > 0 {
        let gb = report.bytes_reclaimed / 1_073_741_824;
        let mb = (report.bytes_reclaimed % 1_073_741_824) / (1024 * 1024);
        let _ = writeln!(out, "\n  Space reclaimed: {gb} GB {mb} MB");
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
        config.ballast.file_count = 0; // skip ballast for fast test

        let opts = InstallOptions {
            config,
            ballast_count: 0,
            ballast_size_bytes: 0,
            ballast_path: Some(ballast_dir),
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
    fn uninstall_dry_run() {
        let tmp = TempDir::new().unwrap();
        let opts = UninstallOptions {
            dry_run: true,
            paths: PathsConfig {
                config_file: tmp.path().join("config.toml"),
                ballast_dir: tmp.path().join("ballast"),
                state_file: tmp.path().join("data").join("state.json"),
                sqlite_db: tmp.path().join("data").join("db.sqlite3"),
                jsonl_log: tmp.path().join("data").join("log.jsonl"),
            },
            ..Default::default()
        };
        let report = run_uninstall_cleanup(&opts);
        assert!(report.dry_run);
        // Steps should all be planned.
        for step in &report.steps {
            assert!(!step.done);
        }
    }

    #[test]
    fn uninstall_removes_ballast_and_data() {
        let tmp = TempDir::new().unwrap();
        let ballast_dir = tmp.path().join("ballast");
        let data_dir = tmp.path().join("data");
        let config_path = tmp.path().join("config.toml");

        // Create test artifacts.
        std::fs::create_dir_all(&ballast_dir).unwrap();
        std::fs::write(ballast_dir.join("file.dat"), vec![0u8; 1024]).unwrap();
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(data_dir.join("state.json"), "{}").unwrap();
        std::fs::write(&config_path, "[pressure]\n").unwrap();

        let opts = UninstallOptions {
            dry_run: false,
            keep_data: false,
            keep_ballast: false,
            paths: PathsConfig {
                config_file: config_path.clone(),
                ballast_dir: ballast_dir.clone(),
                state_file: data_dir.join("state.json"),
                sqlite_db: data_dir.join("db.sqlite3"),
                jsonl_log: data_dir.join("log.jsonl"),
            },
        };

        let report = run_uninstall_cleanup(&opts);
        assert!(report.success, "uninstall should succeed: {report:?}");
        assert!(!ballast_dir.exists(), "ballast dir should be removed");
        assert!(!data_dir.exists(), "data dir should be removed");
        assert!(!config_path.exists(), "config should be removed");
        assert!(report.bytes_reclaimed > 0);
    }

    #[test]
    fn uninstall_keeps_data_when_requested() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("data");
        let config_path = tmp.path().join("config.toml");

        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(data_dir.join("state.json"), "{}").unwrap();
        std::fs::write(&config_path, "[pressure]\n").unwrap();

        let opts = UninstallOptions {
            dry_run: false,
            keep_data: true,
            keep_ballast: true,
            paths: PathsConfig {
                config_file: config_path.clone(),
                ballast_dir: tmp.path().join("ballast"),
                state_file: data_dir.join("state.json"),
                sqlite_db: data_dir.join("db.sqlite3"),
                jsonl_log: data_dir.join("log.jsonl"),
            },
        };

        let report = run_uninstall_cleanup(&opts);
        assert!(report.success);
        assert!(data_dir.exists(), "data dir should be kept");
        assert!(config_path.exists(), "config should be kept");
    }

    #[test]
    fn uninstall_report_format() {
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
        assert!(output.contains("10 GB"));
    }

    #[test]
    fn report_serializes_to_json() {
        let report = InstallReport::new(false);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"success\":false"));
        assert!(json.contains("\"dry_run\":false"));
    }

    #[test]
    fn uninstall_report_serializes_to_json() {
        let report = UninstallReport {
            steps: vec![],
            success: true,
            bytes_reclaimed: 0,
            dry_run: true,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"dry_run\":true"));
    }

    #[test]
    fn install_options_default_matches_config() {
        let opts = InstallOptions::default();
        let config = Config::default();
        assert_eq!(opts.ballast_count, config.ballast.file_count);
        assert_eq!(opts.ballast_size_bytes, config.ballast.file_size_bytes);
    }

    #[test]
    fn uninstall_handles_missing_dirs_gracefully() {
        let tmp = TempDir::new().unwrap();
        let opts = UninstallOptions {
            dry_run: false,
            keep_data: false,
            keep_ballast: false,
            paths: PathsConfig {
                config_file: tmp.path().join("nonexistent_config.toml"),
                ballast_dir: tmp.path().join("nonexistent_ballast"),
                state_file: tmp.path().join("nonexistent_data").join("state.json"),
                sqlite_db: tmp.path().join("nonexistent_data").join("db.sqlite3"),
                jsonl_log: tmp.path().join("nonexistent_data").join("log.jsonl"),
            },
        };
        let report = run_uninstall_cleanup(&opts);
        assert!(report.success, "should handle missing dirs gracefully");
    }
}
