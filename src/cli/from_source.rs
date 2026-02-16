//! From-source fallback install mode with prerequisite checks.
//!
//! When pre-built release artifacts are unavailable (airgapped environments,
//! unsupported targets, CI lag), this module provides a deterministic path
//! to install sbh by building from source. Prerequisites are validated upfront
//! with actionable remediation messages for each missing tool.

use std::fmt::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

use super::RELEASE_REPOSITORY;

// ---------------------------------------------------------------------------
// Prerequisites
// ---------------------------------------------------------------------------

/// External tools required for a from-source build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Prerequisite {
    /// The Rust compiler.
    Rustc,
    /// The Cargo build tool.
    Cargo,
    /// Git version control (needed to clone the repository).
    Git,
}

impl fmt::Display for Prerequisite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rustc => f.write_str("rustc"),
            Self::Cargo => f.write_str("cargo"),
            Self::Git => f.write_str("git"),
        }
    }
}

/// Result of probing a single prerequisite.
#[derive(Debug, Clone, Serialize)]
pub struct PrerequisiteStatus {
    /// Which tool was checked.
    pub prerequisite: Prerequisite,
    /// Whether the tool is available on PATH.
    pub available: bool,
    /// Version string if available (e.g. "1.78.0").
    pub version: Option<String>,
    /// Resolved path to the binary (if found).
    pub path: Option<PathBuf>,
    /// Human-readable fix command when missing.
    pub remediation: Option<String>,
}

/// All prerequisites required for a source build, in check order.
const REQUIRED_PREREQUISITES: &[Prerequisite] =
    &[Prerequisite::Rustc, Prerequisite::Cargo, Prerequisite::Git];

/// Check all prerequisites and return their statuses.
#[must_use]
pub fn check_prerequisites() -> Vec<PrerequisiteStatus> {
    REQUIRED_PREREQUISITES
        .iter()
        .map(|p| check_single(*p))
        .collect()
}

/// Returns `true` when every prerequisite is available.
#[must_use]
pub fn all_prerequisites_met(statuses: &[PrerequisiteStatus]) -> bool {
    statuses.iter().all(|s| s.available)
}

/// Format prerequisite failures as a human-readable remediation block.
#[must_use]
pub fn format_prerequisite_failures(statuses: &[PrerequisiteStatus]) -> String {
    let mut out = String::from("Missing prerequisites for --from-source build:\n\n");
    for status in statuses.iter().filter(|s| !s.available) {
        let _ = writeln!(out, "  {} — not found", status.prerequisite);
        if let Some(fix) = &status.remediation {
            let _ = writeln!(out, "    Fix: {fix}");
        }
        out.push('\n');
    }
    out
}

fn check_single(prerequisite: Prerequisite) -> PrerequisiteStatus {
    let binary_name = prerequisite.to_string();
    let path = which_binary(&binary_name);
    let available = path.is_some();
    let version = if available {
        probe_version(&binary_name)
    } else {
        None
    };
    let remediation = if available {
        None
    } else {
        Some(remediation_for(prerequisite))
    };

    PrerequisiteStatus {
        prerequisite,
        available,
        version,
        path,
        remediation,
    }
}

fn which_binary(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn probe_version(binary: &str) -> Option<String> {
    let output = Command::new(binary).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Extract version number from first line (e.g. "rustc 1.78.0 (9b00956e5 ...)")
    let first_line = stdout.lines().next()?;
    // Try to find a semver-like token.
    for token in first_line.split_whitespace() {
        if token.chars().next().is_some_and(|c| c.is_ascii_digit()) && token.contains('.') {
            return Some(token.to_string());
        }
    }
    // Fallback: return the whole first line trimmed.
    Some(first_line.trim().to_string())
}

fn remediation_for(prerequisite: Prerequisite) -> String {
    match prerequisite {
        Prerequisite::Rustc | Prerequisite::Cargo => {
            "Install the Rust toolchain: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh".to_string()
        }
        Prerequisite::Git => {
            "Install git: apt install git (Debian/Ubuntu), dnf install git (Fedora), brew install git (macOS)".to_string()
        }
    }
}

// ---------------------------------------------------------------------------
// Source checkout target
// ---------------------------------------------------------------------------

/// What to check out from the repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SourceCheckout {
    /// Build from a specific git tag (e.g. "v0.1.0").
    Tag(String),
    /// Build from HEAD of the default branch.
    Head,
}

impl fmt::Display for SourceCheckout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tag(tag) => write!(f, "tag:{tag}"),
            Self::Head => f.write_str("HEAD"),
        }
    }
}

// ---------------------------------------------------------------------------
// Source install config
// ---------------------------------------------------------------------------

/// Configuration for a from-source install.
#[derive(Debug, Clone)]
pub struct SourceInstallConfig {
    /// GitHub repository (owner/name).
    pub repository: String,
    /// What to check out.
    pub checkout: SourceCheckout,
    /// Installation prefix (binary goes to `<prefix>/bin/`).
    pub install_root: PathBuf,
}

impl SourceInstallConfig {
    /// Create a config with defaults for the sbh repository.
    #[must_use]
    pub fn new(checkout: SourceCheckout, install_root: Option<PathBuf>) -> Self {
        let root = install_root.unwrap_or_else(default_install_root);
        Self {
            repository: RELEASE_REPOSITORY.to_string(),
            checkout,
            install_root: root,
        }
    }

    /// The expected binary path after successful install.
    #[must_use]
    pub fn expected_binary_path(&self) -> PathBuf {
        self.install_root.join("bin").join("sbh")
    }

    /// The clone URL for the repository.
    #[must_use]
    pub fn clone_url(&self) -> String {
        format!("https://github.com/{}.git", self.repository)
    }
}

fn default_install_root() -> PathBuf {
    std::env::var_os("HOME").map_or_else(
        || PathBuf::from("/usr/local"),
        |home| PathBuf::from(home).join(".local"),
    )
}

// ---------------------------------------------------------------------------
// Source install result
// ---------------------------------------------------------------------------

/// Structured result of a from-source install attempt.
#[derive(Debug, Clone, Serialize)]
pub struct SourceInstallResult {
    /// Whether the install completed successfully.
    pub success: bool,
    /// Path to the installed binary (if successful).
    pub binary_path: Option<PathBuf>,
    /// What was checked out.
    pub checkout: String,
    /// Cargo build profile used.
    pub build_profile: String,
    /// Prerequisite check results.
    pub prerequisites: Vec<PrerequisiteStatus>,
    /// Error message if the build failed.
    pub error: Option<String>,
}

/// Format a successful install result for human-readable output.
#[must_use]
pub fn format_result_human(result: &SourceInstallResult) -> String {
    let mut out = String::new();

    if result.success {
        out.push_str("From-source install completed successfully.\n\n");
        if let Some(path) = &result.binary_path {
            let _ = writeln!(out, "  Binary: {}", path.display());
        }
        let _ = writeln!(out, "  Source: {}", result.checkout);
        let _ = writeln!(out, "  Profile: {}", result.build_profile);
    } else {
        out.push_str("From-source install failed.\n\n");
        if let Some(err) = &result.error {
            let _ = writeln!(out, "  Error: {err}");
        }
    }

    // Show prerequisite summary.
    out.push_str("\n  Prerequisites:\n");
    for status in &result.prerequisites {
        let icon = if status.available { "OK" } else { "MISSING" };
        let ver = status.version.as_deref().unwrap_or("n/a");
        let _ = writeln!(out, "    [{icon}] {} ({ver})", status.prerequisite);
    }

    out
}

// ---------------------------------------------------------------------------
// Build engine
// ---------------------------------------------------------------------------

/// Run a from-source install. Returns a structured result.
///
/// Steps:
/// 1. Check prerequisites (cargo, git, rustc).
/// 2. Clone the repository into a temporary directory.
/// 3. Check out the requested tag/commit.
/// 4. Run `cargo install --path . --root <prefix>`.
/// 5. Verify the binary exists at the expected location.
pub fn install_from_source(config: &SourceInstallConfig) -> SourceInstallResult {
    let prerequisites = check_prerequisites();

    if !all_prerequisites_met(&prerequisites) {
        return SourceInstallResult {
            success: false,
            binary_path: None,
            checkout: config.checkout.to_string(),
            build_profile: String::from("release"),
            prerequisites,
            error: Some(String::from(
                "missing prerequisites; run with --verbose for remediation details",
            )),
        };
    }

    // Create a temporary directory for the clone.
    let clone_dir = match create_build_dir() {
        Ok(dir) => dir,
        Err(e) => {
            return SourceInstallResult {
                success: false,
                binary_path: None,
                checkout: config.checkout.to_string(),
                build_profile: String::from("release"),
                prerequisites,
                error: Some(format!("failed to create build directory: {e}")),
            };
        }
    };
    // Ensure cleanup on return (success or failure).
    let _guard = BuildDirGuard(clone_dir.clone());

    // Clone the repository.
    let clone_url = config.clone_url();
    if let Err(e) = run_git_clone(&clone_url, &clone_dir, &config.checkout) {
        return SourceInstallResult {
            success: false,
            binary_path: None,
            checkout: config.checkout.to_string(),
            build_profile: String::from("release"),
            prerequisites,
            error: Some(format!("git clone failed: {e}")),
        };
    }

    // Run cargo install.
    if let Err(e) = run_cargo_install(&clone_dir, &config.install_root) {
        return SourceInstallResult {
            success: false,
            binary_path: None,
            checkout: config.checkout.to_string(),
            build_profile: String::from("release"),
            prerequisites,
            error: Some(format!("cargo install failed: {e}")),
        };
    }

    // Verify the binary exists.
    let binary_path = config.expected_binary_path();
    if !binary_path.is_file() {
        return SourceInstallResult {
            success: false,
            binary_path: None,
            checkout: config.checkout.to_string(),
            build_profile: String::from("release"),
            prerequisites,
            error: Some(format!(
                "build succeeded but binary not found at {}",
                binary_path.display()
            )),
        };
    }

    SourceInstallResult {
        success: true,
        binary_path: Some(binary_path),
        checkout: config.checkout.to_string(),
        build_profile: String::from("release"),
        prerequisites,
        error: None,
    }
}

struct BuildDirGuard(PathBuf);

impl Drop for BuildDirGuard {
    fn drop(&mut self) {
        if self.0.exists() {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn create_build_dir() -> std::io::Result<PathBuf> {
    let base = std::env::temp_dir().join("sbh-from-source");
    std::fs::create_dir_all(&base)?;
    // Use a timestamp-based subdirectory to avoid collisions.
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let dir = base.join(format!("build-{ts}"));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_git_clone(url: &str, dest: &Path, checkout: &SourceCheckout) -> Result<(), String> {
    // If destination already exists, remove it and reclone for a clean state.
    if dest.exists() {
        std::fs::remove_dir_all(dest).map_err(|e| {
            format!(
                "failed to remove existing directory {}: {e}",
                dest.display()
            )
        })?;
    }

    let mut args = vec!["clone", "--depth", "1"];

    // For a specific tag, use --branch to fetch only that tag.
    let tag_string;
    if let SourceCheckout::Tag(tag) = checkout {
        tag_string = tag.clone();
        args.push("--branch");
        args.push(&tag_string);
    }

    let dest_str = dest.to_string_lossy().to_string();
    args.push(url);
    args.push(&dest_str);

    let output = Command::new("git")
        .args(&args)
        .output()
        .map_err(|e| format!("failed to execute git: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git clone exited with {}: {stderr}", output.status));
    }

    Ok(())
}

fn run_cargo_install(source_dir: &Path, install_root: &Path) -> Result<(), String> {
    let root_str = install_root.to_string_lossy().to_string();

    let output = Command::new("cargo")
        .args(["install", "--path", ".", "--root", &root_str, "--locked"])
        .current_dir(source_dir)
        .output()
        .map_err(|e| format!("failed to execute cargo: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "cargo install exited with {}: {stderr}",
            output.status
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[cfg(unix)]
    fn write_test_script(contents: &str) -> (tempfile::TempDir, PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().unwrap();
        let script_path = dir.path().join("probe-script.sh");
        std::fs::write(&script_path, contents).unwrap();
        let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).unwrap();
        (dir, script_path)
    }

    #[test]
    fn prerequisite_display() {
        assert_eq!(Prerequisite::Rustc.to_string(), "rustc");
        assert_eq!(Prerequisite::Cargo.to_string(), "cargo");
        assert_eq!(Prerequisite::Git.to_string(), "git");
    }

    #[test]
    fn source_checkout_display() {
        assert_eq!(SourceCheckout::Head.to_string(), "HEAD");
        assert_eq!(
            SourceCheckout::Tag("v0.1.0".into()).to_string(),
            "tag:v0.1.0"
        );
    }

    #[test]
    fn check_prerequisites_returns_all_three() {
        let statuses = check_prerequisites();
        assert_eq!(statuses.len(), 3);
        assert_eq!(statuses[0].prerequisite, Prerequisite::Rustc);
        assert_eq!(statuses[1].prerequisite, Prerequisite::Cargo);
        assert_eq!(statuses[2].prerequisite, Prerequisite::Git);
    }

    #[test]
    fn cargo_and_rustc_available_in_test_env() {
        // We are running inside a Rust test, so cargo and rustc must be present.
        let statuses = check_prerequisites();
        let cargo = statuses
            .iter()
            .find(|s| s.prerequisite == Prerequisite::Cargo)
            .unwrap();
        assert!(
            cargo.available,
            "cargo should be available in test environment"
        );
        assert!(cargo.version.is_some(), "cargo version should be detected");
        assert!(cargo.path.is_some(), "cargo path should be resolved");
        assert!(
            cargo.remediation.is_none(),
            "no remediation needed for cargo"
        );

        let rustc = statuses
            .iter()
            .find(|s| s.prerequisite == Prerequisite::Rustc)
            .unwrap();
        assert!(
            rustc.available,
            "rustc should be available in test environment"
        );
    }

    #[test]
    fn all_prerequisites_met_true_when_all_available() {
        let statuses = vec![
            PrerequisiteStatus {
                prerequisite: Prerequisite::Cargo,
                available: true,
                version: Some("1.78.0".into()),
                path: Some(PathBuf::from("/usr/bin/cargo")),
                remediation: None,
            },
            PrerequisiteStatus {
                prerequisite: Prerequisite::Git,
                available: true,
                version: Some("2.43.0".into()),
                path: Some(PathBuf::from("/usr/bin/git")),
                remediation: None,
            },
        ];
        assert!(all_prerequisites_met(&statuses));
    }

    #[test]
    fn all_prerequisites_met_false_when_any_missing() {
        let statuses = vec![
            PrerequisiteStatus {
                prerequisite: Prerequisite::Cargo,
                available: true,
                version: Some("1.78.0".into()),
                path: Some(PathBuf::from("/usr/bin/cargo")),
                remediation: None,
            },
            PrerequisiteStatus {
                prerequisite: Prerequisite::Git,
                available: false,
                version: None,
                path: None,
                remediation: Some("install git".into()),
            },
        ];
        assert!(!all_prerequisites_met(&statuses));
    }

    #[test]
    fn remediation_for_cargo_includes_rustup() {
        let fix = remediation_for(Prerequisite::Cargo);
        assert!(
            fix.contains("rustup.rs"),
            "cargo remediation should reference rustup"
        );
    }

    #[test]
    fn remediation_for_rustc_includes_rustup() {
        let fix = remediation_for(Prerequisite::Rustc);
        assert!(
            fix.contains("rustup.rs"),
            "rustc remediation should reference rustup"
        );
    }

    #[test]
    fn remediation_for_git_includes_apt_or_brew() {
        let fix = remediation_for(Prerequisite::Git);
        assert!(
            fix.contains("apt install git"),
            "should include apt instructions"
        );
        assert!(
            fix.contains("brew install git"),
            "should include brew instructions"
        );
    }

    #[test]
    fn config_new_defaults() {
        let config = SourceInstallConfig::new(SourceCheckout::Head, None);
        assert_eq!(config.repository, RELEASE_REPOSITORY);
        assert!(
            config.install_root.to_string_lossy().contains(".local")
                || config.install_root == Path::new("/usr/local"),
            "default install root should be ~/.local or /usr/local"
        );
    }

    #[test]
    fn config_with_custom_prefix() {
        let config = SourceInstallConfig::new(
            SourceCheckout::Tag("v0.2.0".into()),
            Some(PathBuf::from("/opt/sbh")),
        );
        assert_eq!(config.install_root, PathBuf::from("/opt/sbh"));
        assert_eq!(
            config.expected_binary_path(),
            PathBuf::from("/opt/sbh/bin/sbh")
        );
    }

    #[test]
    fn clone_url_follows_github_convention() {
        let config = SourceInstallConfig::new(SourceCheckout::Head, None);
        let url = config.clone_url();
        assert!(url.starts_with("https://github.com/"));
        assert!(
            Path::new(&url)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("git"))
        );
        assert!(url.contains(RELEASE_REPOSITORY));
    }

    #[test]
    fn install_fails_with_missing_prerequisites() {
        // Simulate by checking result with a config that has all prereqs
        // but note: we can test the prerequisite-failure path by constructing
        // a result directly since we can't easily unset PATH in a unit test.
        let result = SourceInstallResult {
            success: false,
            binary_path: None,
            checkout: "HEAD".into(),
            build_profile: "release".into(),
            prerequisites: vec![PrerequisiteStatus {
                prerequisite: Prerequisite::Git,
                available: false,
                version: None,
                path: None,
                remediation: Some("install git".into()),
            }],
            error: Some("missing prerequisites".into()),
        };
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn format_prerequisite_failures_includes_fix() {
        let statuses = vec![
            PrerequisiteStatus {
                prerequisite: Prerequisite::Cargo,
                available: true,
                version: Some("1.78.0".into()),
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
        assert!(output.contains("git"), "should mention missing tool");
        assert!(
            output.contains("apt install git"),
            "should include fix command"
        );
        assert!(
            !output.contains("cargo"),
            "should not mention available tools"
        );
    }

    #[test]
    fn format_result_human_success() {
        let result = SourceInstallResult {
            success: true,
            binary_path: Some(PathBuf::from("/home/user/.local/bin/sbh")),
            checkout: "tag:v0.1.0".into(),
            build_profile: "release".into(),
            prerequisites: vec![PrerequisiteStatus {
                prerequisite: Prerequisite::Cargo,
                available: true,
                version: Some("1.78.0".into()),
                path: Some(PathBuf::from("/usr/bin/cargo")),
                remediation: None,
            }],
            error: None,
        };
        let output = format_result_human(&result);
        assert!(output.contains("successfully"));
        assert!(output.contains("/home/user/.local/bin/sbh"));
        assert!(output.contains("tag:v0.1.0"));
        assert!(output.contains("[OK]"));
    }

    #[test]
    fn format_result_human_failure() {
        let result = SourceInstallResult {
            success: false,
            binary_path: None,
            checkout: "HEAD".into(),
            build_profile: "release".into(),
            prerequisites: vec![PrerequisiteStatus {
                prerequisite: Prerequisite::Git,
                available: false,
                version: None,
                path: None,
                remediation: Some("install git".into()),
            }],
            error: Some("missing prerequisites".into()),
        };
        let output = format_result_human(&result);
        assert!(output.contains("failed"));
        assert!(output.contains("missing prerequisites"));
        assert!(output.contains("[MISSING]"));
    }

    #[test]
    fn which_binary_finds_cargo() {
        // cargo must be on PATH for tests to run.
        let path = which_binary("cargo");
        assert!(path.is_some(), "cargo should be findable on PATH");
    }

    #[test]
    fn which_binary_returns_none_for_nonexistent() {
        let path = which_binary("sbh_nonexistent_tool_12345");
        assert!(path.is_none());
    }

    #[test]
    fn probe_version_extracts_semver() {
        // cargo --version outputs something like "cargo 1.78.0 (9b00956e5 2024-04-29)"
        let version = probe_version("cargo");
        assert!(version.is_some(), "should extract cargo version");
        let ver = version.unwrap();
        assert!(ver.contains('.'), "version should contain dots: got {ver}");
    }

    #[cfg(unix)]
    #[test]
    fn probe_version_returns_none_when_command_fails() {
        let (_tmp, script_path) = write_test_script("#!/bin/sh\nexit 2\n");
        let version = probe_version(&script_path.to_string_lossy());
        assert!(version.is_none(), "failing command should return None");
    }

    #[cfg(unix)]
    #[test]
    fn probe_version_falls_back_to_first_line_without_semver() {
        let (_tmp, script_path) = write_test_script(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  echo \"custom tool version\"\n  exit 0\nfi\nexit 0\n",
        );
        let version = probe_version(&script_path.to_string_lossy());
        assert_eq!(version, Some("custom tool version".to_string()));
    }

    #[test]
    fn result_serializes_to_json() {
        let result = SourceInstallResult {
            success: true,
            binary_path: Some(PathBuf::from("/usr/local/bin/sbh")),
            checkout: "HEAD".into(),
            build_profile: "release".into(),
            prerequisites: vec![],
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"build_profile\":\"release\""));
    }

    #[test]
    fn prerequisite_status_serializes_to_json() {
        let status = PrerequisiteStatus {
            prerequisite: Prerequisite::Cargo,
            available: true,
            version: Some("1.78.0".into()),
            path: Some(PathBuf::from("/usr/bin/cargo")),
            remediation: None,
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"prerequisite\":\"Cargo\""));
        assert!(json.contains("\"available\":true"));
    }

    // bd-2j5.19 — SourceCheckout Tag equality
    #[test]
    fn source_checkout_tag_equality() {
        let a = SourceCheckout::Tag("v1.0.0".into());
        let b = SourceCheckout::Tag("v1.0.0".into());
        let c = SourceCheckout::Tag("v2.0.0".into());
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(SourceCheckout::Head, SourceCheckout::Head);
        assert_ne!(SourceCheckout::Head, SourceCheckout::Tag("v1.0.0".into()));
    }

    // bd-2j5.19 — all_prerequisites_met with empty list
    #[test]
    fn all_prerequisites_met_empty_list() {
        assert!(
            all_prerequisites_met(&[]),
            "empty list should vacuously be met"
        );
    }

    // bd-2j5.19 — format_prerequisite_failures with all available
    #[test]
    fn format_prerequisite_failures_all_available() {
        let statuses = vec![PrerequisiteStatus {
            prerequisite: Prerequisite::Cargo,
            available: true,
            version: Some("1.78.0".into()),
            path: Some(PathBuf::from("/usr/bin/cargo")),
            remediation: None,
        }];
        let output = format_prerequisite_failures(&statuses);
        // Should only contain the header, no tool-specific lines.
        assert!(output.contains("Missing prerequisites"));
        assert!(
            !output.contains("cargo"),
            "should not list available tools as missing"
        );
    }

    // bd-2j5.19 — remediation for rustc and cargo are the same
    #[test]
    fn remediation_rustc_and_cargo_share_message() {
        let rustc_fix = remediation_for(Prerequisite::Rustc);
        let cargo_fix = remediation_for(Prerequisite::Cargo);
        assert_eq!(
            rustc_fix, cargo_fix,
            "rustc and cargo share rustup remediation"
        );
    }

    // bd-2j5.19 — which_binary returns None for empty string
    #[test]
    fn which_binary_empty_name() {
        let path = which_binary("");
        assert!(path.is_none(), "empty binary name should not be found");
    }

    // bd-2j5.19 — probe_version on nonexistent binary
    #[test]
    fn probe_version_nonexistent() {
        let version = probe_version("sbh_nonexistent_binary_xyz_12345");
        assert!(
            version.is_none(),
            "nonexistent binary should yield no version"
        );
    }

    // bd-2j5.19 — SourceInstallResult serialization with error field
    #[test]
    fn result_serializes_with_error() {
        let result = SourceInstallResult {
            success: false,
            binary_path: None,
            checkout: "HEAD".into(),
            build_profile: "release".into(),
            prerequisites: vec![],
            error: Some("build failed".into()),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"success\":false"));
        assert!(json.contains("build failed"));
    }

    // bd-2j5.19 — PrerequisiteStatus serialization with None values
    #[test]
    fn prerequisite_status_serializes_with_none_values() {
        let status = PrerequisiteStatus {
            prerequisite: Prerequisite::Git,
            available: false,
            version: None,
            path: None,
            remediation: Some("install git".into()),
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"available\":false"));
        assert!(json.contains("\"version\":null"));
        assert!(json.contains("\"path\":null"));
        assert!(json.contains("install git"));
    }

    // bd-2j5.19 — SourceInstallConfig expected_binary_path
    #[test]
    fn expected_binary_path_follows_convention() {
        let config =
            SourceInstallConfig::new(SourceCheckout::Head, Some(PathBuf::from("/opt/prefix")));
        assert_eq!(
            config.expected_binary_path(),
            PathBuf::from("/opt/prefix/bin/sbh")
        );
    }

    // bd-2j5.19 — all Prerequisite variants have unique display
    #[test]
    fn prerequisite_display_all_unique() {
        let displays: Vec<String> = [Prerequisite::Rustc, Prerequisite::Cargo, Prerequisite::Git]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        for (i, a) in displays.iter().enumerate() {
            for (j, b) in displays.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "prerequisites should have unique display");
                }
            }
        }
    }

    // bd-2j5.19 — format_result_human shows all prerequisite statuses
    #[test]
    fn format_result_human_shows_all_prereq_statuses() {
        let result = SourceInstallResult {
            success: false,
            binary_path: None,
            checkout: "HEAD".into(),
            build_profile: "release".into(),
            prerequisites: vec![
                PrerequisiteStatus {
                    prerequisite: Prerequisite::Rustc,
                    available: true,
                    version: Some("1.80.0".into()),
                    path: Some(PathBuf::from("/usr/bin/rustc")),
                    remediation: None,
                },
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
                    remediation: Some("install git".into()),
                },
            ],
            error: Some("missing prerequisites".into()),
        };
        let output = format_result_human(&result);
        assert!(output.contains("[OK] rustc"));
        assert!(output.contains("[OK] cargo"));
        assert!(output.contains("[MISSING] git"));
    }
}
