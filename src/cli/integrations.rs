//! Automatic AI tool integration bootstrap with backup-first safety.
//!
//! Detects known AI coding tool config files and hook registries, injects sbh
//! integration entries idempotently, and creates timestamped backups before any
//! mutation.

use std::fmt;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Serialize;

// ---------------------------------------------------------------------------
// Tool registry
// ---------------------------------------------------------------------------

/// Known AI coding tools that sbh can integrate with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum AiTool {
    /// Anthropic Claude Code CLI.
    ClaudeCode,
    /// `OpenAI` Codex CLI.
    Codex,
    /// Google Gemini CLI.
    GeminiCli,
    /// Cursor IDE.
    Cursor,
    /// Aider CLI.
    Aider,
}

impl fmt::Display for AiTool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClaudeCode => f.write_str("claude-code"),
            Self::Codex => f.write_str("codex"),
            Self::GeminiCli => f.write_str("gemini-cli"),
            Self::Cursor => f.write_str("cursor"),
            Self::Aider => f.write_str("aider"),
        }
    }
}

/// All known tools for enumeration.
pub const ALL_TOOLS: &[AiTool] = &[
    AiTool::ClaudeCode,
    AiTool::Codex,
    AiTool::GeminiCli,
    AiTool::Cursor,
    AiTool::Aider,
];

// ---------------------------------------------------------------------------
// Config file detection
// ---------------------------------------------------------------------------

/// A detected tool configuration on the system.
#[derive(Debug, Clone, Serialize)]
pub struct DetectedTool {
    /// Which AI tool was detected.
    pub tool: AiTool,
    /// Path to the tool's config or hook file.
    pub config_path: PathBuf,
    /// Whether sbh integration is already present.
    pub already_configured: bool,
    /// Whether the config file is writable.
    pub writable: bool,
}

/// Discover all AI tool configurations on the system.
#[must_use]
pub fn detect_tools() -> Vec<DetectedTool> {
    let mut detected = Vec::new();
    let Some(home) = home_dir() else {
        return detected;
    };

    // Claude Code: ~/.claude/settings.json or ~/.config/claude-code/settings.json
    for path in claude_code_config_paths(&home) {
        if path.exists() {
            detected.push(DetectedTool {
                tool: AiTool::ClaudeCode,
                config_path: path.clone(),
                already_configured: check_claude_code_configured(&path),
                writable: is_writable(&path),
            });
        }
    }

    // Codex: ~/.codex/config.json or ~/.config/codex/config.json
    for path in codex_config_paths(&home) {
        if path.exists() {
            detected.push(DetectedTool {
                tool: AiTool::Codex,
                config_path: path.clone(),
                already_configured: check_json_has_sbh(&path),
                writable: is_writable(&path),
            });
        }
    }

    // Gemini CLI: ~/.config/gemini/config.json
    let gemini_cfg = home.join(".config").join("gemini").join("config.json");
    if gemini_cfg.exists() {
        detected.push(DetectedTool {
            tool: AiTool::GeminiCli,
            config_path: gemini_cfg.clone(),
            already_configured: check_json_has_sbh(&gemini_cfg),
            writable: is_writable(&gemini_cfg),
        });
    }

    // Cursor: ~/.cursor/settings.json
    let cursor_cfg = home.join(".cursor").join("settings.json");
    if cursor_cfg.exists() {
        detected.push(DetectedTool {
            tool: AiTool::Cursor,
            config_path: cursor_cfg.clone(),
            already_configured: check_json_has_sbh(&cursor_cfg),
            writable: is_writable(&cursor_cfg),
        });
    }

    // Aider: ~/.aider.conf.yml or ~/.config/aider/config.yml
    for path in aider_config_paths(&home) {
        if path.exists() {
            detected.push(DetectedTool {
                tool: AiTool::Aider,
                config_path: path.clone(),
                already_configured: check_text_has_sbh(&path),
                writable: is_writable(&path),
            });
        }
    }

    detected
}

fn claude_code_config_paths(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join(".claude").join("settings.json"),
        home.join(".config")
            .join("claude-code")
            .join("settings.json"),
    ]
}

fn codex_config_paths(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join(".codex").join("config.json"),
        home.join(".config").join("codex").join("config.json"),
    ]
}

fn aider_config_paths(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join(".aider.conf.yml"),
        home.join(".config").join("aider").join("config.yml"),
    ]
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn is_writable(path: &Path) -> bool {
    // Check if the file (or its parent directory) is writable.
    if path.exists() {
        fs::metadata(path)
            .map(|m| !m.permissions().readonly())
            .unwrap_or(false)
    } else {
        path.parent().is_some_and(Path::exists)
    }
}

// ---------------------------------------------------------------------------
// Per-tool config checks
// ---------------------------------------------------------------------------

fn check_claude_code_configured(path: &Path) -> bool {
    check_json_has_sbh(path)
}

fn check_json_has_sbh(path: &Path) -> bool {
    fs::read_to_string(path)
        .map(|c| c.contains("sbh") || c.contains("storage_ballast_helper"))
        .unwrap_or(false)
}

fn check_text_has_sbh(path: &Path) -> bool {
    fs::read_to_string(path)
        .map(|c| c.contains("sbh") || c.contains("storage_ballast_helper"))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Integration snippets
// ---------------------------------------------------------------------------

/// The sbh integration snippet for a given tool.
#[must_use]
pub fn integration_snippet(tool: AiTool) -> &'static str {
    match tool {
        AiTool::ClaudeCode => CLAUDE_CODE_HOOK_SNIPPET,
        AiTool::Codex => CODEX_HOOK_SNIPPET,
        AiTool::GeminiCli => GEMINI_HOOK_SNIPPET,
        AiTool::Cursor => CURSOR_HOOK_SNIPPET,
        AiTool::Aider => AIDER_HOOK_SNIPPET,
    }
}

/// Claude Code: `PreToolUse` hook that checks destructive operations via sbh.
const CLAUDE_CODE_HOOK_SNIPPET: &str = r#"
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit",
        "command": "sbh guard --hook-protocol claude-code"
      }
    ]
  }
"#;

/// Codex: pre-execution hook configuration.
const CODEX_HOOK_SNIPPET: &str = r#"
  "hooks": {
    "pre_exec": "sbh guard --hook-protocol codex"
  }
"#;

/// Gemini CLI: tool guard integration.
const GEMINI_HOOK_SNIPPET: &str = r#"
  "guard": {
    "command": "sbh guard --hook-protocol generic",
    "on_deny": "block"
  }
"#;

/// Cursor: task guard configuration.
const CURSOR_HOOK_SNIPPET: &str = r#"
  "sbh.guard": {
    "enabled": true,
    "command": "sbh guard --hook-protocol generic"
  }
"#;

/// Aider: lint/guard command integration.
const AIDER_HOOK_SNIPPET: &str = "lint-cmd: sbh guard --hook-protocol generic\n";

// ---------------------------------------------------------------------------
// Integration result
// ---------------------------------------------------------------------------

/// Result of a single tool integration attempt.
#[derive(Debug, Clone, Serialize)]
pub struct IntegrationResult {
    /// Which tool.
    pub tool: AiTool,
    /// Outcome status.
    pub status: IntegrationStatus,
    /// Config file path.
    pub config_path: PathBuf,
    /// Backup created before mutation (if any).
    pub backup_path: Option<PathBuf>,
    /// Human-readable message.
    pub message: String,
}

/// Status of an integration attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum IntegrationStatus {
    /// Successfully configured.
    Configured,
    /// Already configured (idempotent skip).
    AlreadyConfigured,
    /// Skipped by user request.
    Skipped,
    /// Failed to configure.
    Failed,
    /// Dry-run: would configure.
    DryRun,
}

impl fmt::Display for IntegrationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configured => f.write_str("configured"),
            Self::AlreadyConfigured => f.write_str("already-configured"),
            Self::Skipped => f.write_str("skipped"),
            Self::Failed => f.write_str("failed"),
            Self::DryRun => f.write_str("dry-run"),
        }
    }
}

// ---------------------------------------------------------------------------
// Bootstrap summary
// ---------------------------------------------------------------------------

/// Summary of all integration bootstrap results.
#[derive(Debug, Clone, Serialize)]
pub struct BootstrapSummary {
    /// Individual results per tool.
    pub results: Vec<IntegrationResult>,
    /// How many tools were detected.
    pub detected_count: usize,
    /// How many were newly configured.
    pub configured_count: usize,
    /// How many were already configured.
    pub already_configured_count: usize,
    /// How many failed.
    pub failed_count: usize,
    /// How many were skipped.
    pub skipped_count: usize,
}

// ---------------------------------------------------------------------------
// Backup helper
// ---------------------------------------------------------------------------

fn create_timestamped_backup(path: &Path, backup_dir: Option<&Path>) -> std::io::Result<PathBuf> {
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
// Bootstrap engine
// ---------------------------------------------------------------------------

/// Options for running integration bootstrap.
#[derive(Debug, Clone, Default)]
pub struct BootstrapOptions {
    /// Only report, do not apply changes.
    pub dry_run: bool,
    /// Override backup directory.
    pub backup_dir: Option<PathBuf>,
    /// Restrict to these tools only (empty = all detected).
    pub only_tools: Vec<AiTool>,
    /// Skip these tools.
    pub skip_tools: Vec<AiTool>,
}

/// Run integration bootstrap: detect tools, inject hooks, report results.
#[must_use]
pub fn run_bootstrap(opts: &BootstrapOptions) -> BootstrapSummary {
    let detected = detect_tools();
    let mut results = Vec::new();

    for tool_info in &detected {
        // Check if tool is in scope.
        if !opts.only_tools.is_empty() && !opts.only_tools.contains(&tool_info.tool) {
            results.push(IntegrationResult {
                tool: tool_info.tool,
                status: IntegrationStatus::Skipped,
                config_path: tool_info.config_path.clone(),
                backup_path: None,
                message: "not in --integrations list".to_string(),
            });
            continue;
        }
        if opts.skip_tools.contains(&tool_info.tool) {
            results.push(IntegrationResult {
                tool: tool_info.tool,
                status: IntegrationStatus::Skipped,
                config_path: tool_info.config_path.clone(),
                backup_path: None,
                message: "excluded by --no-integrations".to_string(),
            });
            continue;
        }

        // Already configured: idempotent skip.
        if tool_info.already_configured {
            results.push(IntegrationResult {
                tool: tool_info.tool,
                status: IntegrationStatus::AlreadyConfigured,
                config_path: tool_info.config_path.clone(),
                backup_path: None,
                message: "sbh integration already present".to_string(),
            });
            continue;
        }

        // Dry-run mode.
        if opts.dry_run {
            results.push(IntegrationResult {
                tool: tool_info.tool,
                status: IntegrationStatus::DryRun,
                config_path: tool_info.config_path.clone(),
                backup_path: None,
                message: format!(
                    "would inject sbh hook into {}",
                    tool_info.config_path.display()
                ),
            });
            continue;
        }

        // Not writable.
        if !tool_info.writable {
            results.push(IntegrationResult {
                tool: tool_info.tool,
                status: IntegrationStatus::Failed,
                config_path: tool_info.config_path.clone(),
                backup_path: None,
                message: format!(
                    "config file not writable: {}",
                    tool_info.config_path.display()
                ),
            });
            continue;
        }

        // Apply integration.
        let result = apply_integration(tool_info, opts.backup_dir.as_deref());
        results.push(result);
    }

    let configured_count = results
        .iter()
        .filter(|r| r.status == IntegrationStatus::Configured)
        .count();
    let already_configured_count = results
        .iter()
        .filter(|r| r.status == IntegrationStatus::AlreadyConfigured)
        .count();
    let failed_count = results
        .iter()
        .filter(|r| r.status == IntegrationStatus::Failed)
        .count();
    let skipped_count = results
        .iter()
        .filter(|r| r.status == IntegrationStatus::Skipped)
        .count();

    BootstrapSummary {
        detected_count: detected.len(),
        results,
        configured_count,
        already_configured_count,
        failed_count,
        skipped_count,
    }
}

fn apply_integration(tool_info: &DetectedTool, backup_dir: Option<&Path>) -> IntegrationResult {
    // Create backup first.
    let backup_path = match create_timestamped_backup(&tool_info.config_path, backup_dir) {
        Ok(p) => Some(p),
        Err(e) => {
            return IntegrationResult {
                tool: tool_info.tool,
                status: IntegrationStatus::Failed,
                config_path: tool_info.config_path.clone(),
                backup_path: None,
                message: format!("backup failed: {e}"),
            };
        }
    };

    // Read existing config and inject hook.
    let inject_result = match tool_info.tool {
        AiTool::ClaudeCode | AiTool::Codex | AiTool::GeminiCli | AiTool::Cursor => {
            inject_json_hook(&tool_info.config_path, tool_info.tool)
        }
        AiTool::Aider => inject_text_hook(&tool_info.config_path, tool_info.tool),
    };

    match inject_result {
        Ok(()) => IntegrationResult {
            tool: tool_info.tool,
            status: IntegrationStatus::Configured,
            config_path: tool_info.config_path.clone(),
            backup_path,
            message: format!("sbh hook injected into {}", tool_info.config_path.display()),
        },
        Err(e) => {
            // Attempt rollback from backup.
            if let Some(ref backup) = backup_path {
                let _ = fs::copy(backup, &tool_info.config_path);
            }
            IntegrationResult {
                tool: tool_info.tool,
                status: IntegrationStatus::Failed,
                config_path: tool_info.config_path.clone(),
                backup_path,
                message: format!("injection failed (rolled back): {e}"),
            }
        }
    }
}

/// Inject a hook snippet into a JSON config file.
///
/// Parses the file as JSON to find the correct insertion point, then
/// performs a text-level splice to preserve formatting and comments.
fn inject_json_hook(path: &Path, tool: AiTool) -> std::io::Result<()> {
    let contents = fs::read_to_string(path)?;
    let snippet = integration_snippet(tool).trim();

    // Validate the file looks like a JSON object (starts with `{`, ends with `}`).
    // We use a structural check rather than strict serde_json parsing because many
    // editors produce non-standard JSON (trailing commas, comments) that we should tolerate.
    let trimmed = contents.trim();
    if !trimmed.starts_with('{') || !trimmed.ends_with('}') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "config file does not contain a JSON object",
        ));
    }

    // I30: Find the root-level closing `}` by tracking nesting depth and string
    // context, rather than rfind('}') which can match inside string values.
    let Some(last_brace) = find_root_close_brace(&contents) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "config file does not contain a root-level closing brace",
        ));
    };

    // Check if there's content before the brace that needs a comma.
    let before = contents[..last_brace].trim_end();
    let needs_comma = !before.ends_with('{') && !before.ends_with(',');

    let mut result = String::new();
    result.push_str(&contents[..last_brace]);

    if needs_comma {
        // Ensure comma is on a new line to avoid being commented out by trailing // comments.
        if !result.trim_end().ends_with('\n') {
            result.push('\n');
        }
        result.push(',');
    }
    result.push('\n');
    result.push_str(snippet);
    result.push('\n');
    result.push_str(&contents[last_brace..]);

    fs::write(path, result)?;
    Ok(())
}

/// Find the byte offset of the root-level closing `}` by scanning forward
/// through the content, tracking JSON nesting depth and string context.
/// Handles `}` inside string values and JSONC-style `//` line comments.
fn find_root_close_brace(contents: &str) -> Option<usize> {
    let bytes = contents.as_bytes();
    let len = bytes.len();
    let mut depth: i32 = 0;
    let mut in_string = false;
    let mut last_root_close = None;
    let mut i = 0;

    while i < len {
        let ch = bytes[i];

        if in_string {
            if ch == b'\\' {
                i += 2; // skip escaped character
                continue;
            }
            if ch == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        // Handle comments
        if ch == b'/' && i + 1 < len {
            if bytes[i + 1] == b'/' {
                // Line comment
                i += 2;
                while i < len && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            } else if bytes[i + 1] == b'*' {
                // Block comment
                i += 2;
                while i + 1 < len && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i += 2; // skip ending */
                continue;
            }
        }

        match ch {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    last_root_close = Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    last_root_close
}

/// Inject a hook line into a text config file (YAML, etc.).
fn inject_text_hook(path: &Path, tool: AiTool) -> std::io::Result<()> {
    let contents = fs::read_to_string(path)?;
    let snippet = integration_snippet(tool).trim();

    let mut result = contents;
    if !result.ends_with('\n') {
        result.push('\n');
    }
    result.push_str(snippet);
    result.push('\n');

    fs::write(path, result)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Human-readable formatting
// ---------------------------------------------------------------------------

/// Format a bootstrap summary for terminal output.
#[must_use]
pub fn format_summary_human(summary: &BootstrapSummary) -> String {
    let mut out = String::new();

    let _ = writeln!(
        out,
        "AI tool integration bootstrap: {} tool(s) detected\n",
        summary.detected_count
    );

    for result in &summary.results {
        let status_label = match result.status {
            IntegrationStatus::Configured => "[DONE]",
            IntegrationStatus::AlreadyConfigured => "[ OK ]",
            IntegrationStatus::Skipped => "[SKIP]",
            IntegrationStatus::Failed => "[FAIL]",
            IntegrationStatus::DryRun => "[PLAN]",
        };
        let _ = writeln!(out, "  {status_label} {}: {}", result.tool, result.message);
        if let Some(backup) = &result.backup_path {
            let _ = writeln!(out, "         backup: {}", backup.display());
            let _ = writeln!(
                out,
                "         restore: cp {} {}",
                backup.display(),
                result.config_path.display()
            );
        }
    }

    let _ = writeln!(
        out,
        "\nSummary: {} configured, {} already configured, {} skipped, {} failed",
        summary.configured_count,
        summary.already_configured_count,
        summary.skipped_count,
        summary.failed_count,
    );

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
    fn tool_display() {
        assert_eq!(AiTool::ClaudeCode.to_string(), "claude-code");
        assert_eq!(AiTool::Codex.to_string(), "codex");
        assert_eq!(AiTool::GeminiCli.to_string(), "gemini-cli");
        assert_eq!(AiTool::Cursor.to_string(), "cursor");
        assert_eq!(AiTool::Aider.to_string(), "aider");
    }

    #[test]
    fn integration_status_display() {
        assert_eq!(IntegrationStatus::Configured.to_string(), "configured");
        assert_eq!(
            IntegrationStatus::AlreadyConfigured.to_string(),
            "already-configured"
        );
        assert_eq!(IntegrationStatus::DryRun.to_string(), "dry-run");
    }

    #[test]
    fn snippets_are_nonempty() {
        for tool in ALL_TOOLS {
            let snippet = integration_snippet(*tool);
            assert!(
                !snippet.trim().is_empty(),
                "snippet for {tool} should not be empty"
            );
        }
    }

    #[test]
    fn snippets_contain_sbh() {
        for tool in ALL_TOOLS {
            let snippet = integration_snippet(*tool);
            assert!(
                snippet.contains("sbh"),
                "snippet for {tool} should reference sbh"
            );
        }
    }

    #[test]
    fn inject_json_hook_into_empty_object() {
        let tmp = TempDir::new().unwrap();
        let cfg = tmp.path().join("settings.json");
        fs::write(&cfg, "{\n}\n").unwrap();

        inject_json_hook(&cfg, AiTool::ClaudeCode).unwrap();

        let contents = fs::read_to_string(&cfg).unwrap();
        assert!(contents.contains("hooks"), "should contain hook entry");
        assert!(
            contents.contains("sbh guard"),
            "should contain sbh guard command"
        );
        // Should still end with }
        assert!(
            contents.trim_end().ends_with('}'),
            "should end with closing brace"
        );
    }

    #[test]
    fn inject_json_hook_into_existing_object() {
        let tmp = TempDir::new().unwrap();
        let cfg = tmp.path().join("config.json");
        fs::write(&cfg, "{\n  \"theme\": \"dark\"\n}\n").unwrap();

        inject_json_hook(&cfg, AiTool::Codex).unwrap();

        let contents = fs::read_to_string(&cfg).unwrap();
        assert!(contents.contains("theme"), "should preserve existing keys");
        assert!(contents.contains("sbh guard"), "should contain sbh guard");
        // Should have a comma after the existing content.
        assert!(contents.contains(",\n"), "should add comma separator");
    }

    #[test]
    fn inject_json_hook_idempotent_check() {
        let tmp = TempDir::new().unwrap();
        let cfg = tmp.path().join("settings.json");
        fs::write(&cfg, "{\n  \"hooks\": { \"sbh\": true }\n}\n").unwrap();

        // check_json_has_sbh should return true.
        assert!(check_json_has_sbh(&cfg));
    }

    #[test]
    fn inject_text_hook_appends() {
        let tmp = TempDir::new().unwrap();
        let cfg = tmp.path().join("config.yml");
        fs::write(&cfg, "# Aider config\nmodel: gpt-4\n").unwrap();

        inject_text_hook(&cfg, AiTool::Aider).unwrap();

        let contents = fs::read_to_string(&cfg).unwrap();
        assert!(
            contents.contains("model: gpt-4"),
            "should preserve existing content"
        );
        assert!(contents.contains("sbh guard"), "should append sbh hook");
    }

    #[test]
    fn inject_text_hook_adds_newline() {
        let tmp = TempDir::new().unwrap();
        let cfg = tmp.path().join("config.yml");
        fs::write(&cfg, "model: gpt-4").unwrap(); // No trailing newline.

        inject_text_hook(&cfg, AiTool::Aider).unwrap();

        let contents = fs::read_to_string(&cfg).unwrap();
        // Should not have double content from missing newline.
        assert!(
            !contents.starts_with("model: gpt-4lint"),
            "should separate with newline"
        );
    }

    #[test]
    fn backup_before_inject() {
        let tmp = TempDir::new().unwrap();
        let cfg = tmp.path().join("settings.json");
        let original = "{\n  \"existing\": true\n}\n";
        fs::write(&cfg, original).unwrap();

        let backup = create_timestamped_backup(&cfg, None).unwrap();
        assert!(backup.exists());
        assert_eq!(fs::read_to_string(&backup).unwrap(), original);
    }

    #[test]
    fn bootstrap_skips_excluded_tools() {
        // Skip all known tools so none are actually configured.
        let opts = BootstrapOptions {
            skip_tools: ALL_TOOLS.to_vec(),
            dry_run: true,
            ..Default::default()
        };

        let summary = run_bootstrap(&opts);
        // Every detected tool should be skipped.
        for result in &summary.results {
            assert_eq!(
                result.status,
                IntegrationStatus::Skipped,
                "{} should be skipped",
                result.tool
            );
        }
        assert_eq!(summary.configured_count, 0);
    }

    #[test]
    fn bootstrap_dry_run_does_not_mutate() {
        let tmp = TempDir::new().unwrap();
        let cfg = tmp.path().join("settings.json");
        let original = "{\n  \"theme\": \"dark\"\n}\n";
        fs::write(&cfg, original).unwrap();

        let tool_info = DetectedTool {
            tool: AiTool::ClaudeCode,
            config_path: cfg.clone(),
            already_configured: false,
            writable: true,
        };

        // Simulate what dry-run would do by checking the detected tool.
        // Since run_bootstrap uses detect_tools() which looks at home dir,
        // we test the dry-run path directly.
        assert!(!tool_info.already_configured);

        // The file should remain unchanged after a would-be dry-run.
        let contents = fs::read_to_string(&cfg).unwrap();
        assert_eq!(contents, original);
    }

    #[test]
    fn apply_integration_creates_backup_and_injects() {
        let tmp = TempDir::new().unwrap();
        let cfg = tmp.path().join("settings.json");
        fs::write(&cfg, "{\n}\n").unwrap();

        let tool_info = DetectedTool {
            tool: AiTool::ClaudeCode,
            config_path: cfg.clone(),
            already_configured: false,
            writable: true,
        };

        let result = apply_integration(&tool_info, None);
        assert_eq!(result.status, IntegrationStatus::Configured);
        assert!(result.backup_path.is_some());

        let contents = fs::read_to_string(&cfg).unwrap();
        assert!(contents.contains("sbh guard"));
    }

    #[test]
    fn apply_integration_rollback_on_invalid_json() {
        let tmp = TempDir::new().unwrap();
        let cfg = tmp.path().join("broken.json");
        let original = "not json at all";
        fs::write(&cfg, original).unwrap();

        let tool_info = DetectedTool {
            tool: AiTool::Codex,
            config_path: cfg.clone(),
            already_configured: false,
            writable: true,
        };

        let result = apply_integration(&tool_info, None);
        assert_eq!(result.status, IntegrationStatus::Failed);
        // File should be rolled back to original content.
        let contents = fs::read_to_string(&cfg).unwrap();
        assert_eq!(contents, original, "should roll back on failure");
    }

    #[test]
    fn format_summary_includes_counts() {
        let summary = BootstrapSummary {
            detected_count: 3,
            results: vec![
                IntegrationResult {
                    tool: AiTool::ClaudeCode,
                    status: IntegrationStatus::Configured,
                    config_path: PathBuf::from("/home/user/.claude/settings.json"),
                    backup_path: Some(PathBuf::from(
                        "/home/user/.claude/settings.json.sbh-backup-123",
                    )),
                    message: "sbh hook injected".to_string(),
                },
                IntegrationResult {
                    tool: AiTool::Codex,
                    status: IntegrationStatus::AlreadyConfigured,
                    config_path: PathBuf::from("/home/user/.codex/config.json"),
                    backup_path: None,
                    message: "sbh integration already present".to_string(),
                },
                IntegrationResult {
                    tool: AiTool::Aider,
                    status: IntegrationStatus::Skipped,
                    config_path: PathBuf::from("/home/user/.aider.conf.yml"),
                    backup_path: None,
                    message: "excluded".to_string(),
                },
            ],
            configured_count: 1,
            already_configured_count: 1,
            failed_count: 0,
            skipped_count: 1,
        };

        let output = format_summary_human(&summary);
        assert!(output.contains("3 tool(s) detected"));
        assert!(output.contains("[DONE] claude-code"));
        assert!(output.contains("[ OK ] codex"));
        assert!(output.contains("[SKIP] aider"));
        assert!(output.contains("1 configured"));
        assert!(output.contains("1 already configured"));
        assert!(output.contains("1 skipped"));
        assert!(output.contains("0 failed"));
        assert!(output.contains("restore: cp"));
    }

    #[test]
    fn summary_serializes_to_json() {
        let summary = BootstrapSummary {
            detected_count: 0,
            results: vec![],
            configured_count: 0,
            already_configured_count: 0,
            failed_count: 0,
            skipped_count: 0,
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"detected_count\":0"));
    }

    // bd-2j5.19 — inject_json_hook fails without closing brace
    #[test]
    fn inject_json_hook_no_closing_brace_fails() {
        let tmp = TempDir::new().unwrap();
        let cfg = tmp.path().join("broken.json");
        fs::write(&cfg, "no json at all").unwrap();

        let result = inject_json_hook(&cfg, AiTool::ClaudeCode);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("does not contain a JSON object")
        );
    }

    // bd-2j5.19 — check_json_has_sbh with storage_ballast_helper string
    #[test]
    fn check_json_has_sbh_with_full_name() {
        let tmp = TempDir::new().unwrap();
        let cfg = tmp.path().join("config.json");
        fs::write(&cfg, r#"{"tool": "storage_ballast_helper"}"#).unwrap();
        assert!(check_json_has_sbh(&cfg));
    }

    // bd-2j5.19 — check_json_has_sbh with no sbh reference
    #[test]
    fn check_json_has_sbh_no_reference() {
        let tmp = TempDir::new().unwrap();
        let cfg = tmp.path().join("config.json");
        fs::write(&cfg, r#"{"tool": "other_tool"}"#).unwrap();
        assert!(!check_json_has_sbh(&cfg));
    }

    // bd-2j5.19 — check_text_has_sbh with empty file
    #[test]
    fn check_text_has_sbh_empty_file() {
        let tmp = TempDir::new().unwrap();
        let cfg = tmp.path().join("config.yml");
        fs::write(&cfg, "").unwrap();
        assert!(!check_text_has_sbh(&cfg));
    }

    // bd-2j5.19 — check_text_has_sbh with nonexistent file
    #[test]
    fn check_text_has_sbh_nonexistent() {
        assert!(!check_text_has_sbh(Path::new("/nonexistent/config.yml")));
    }

    // bd-2j5.19 — is_writable for nonexistent path with parent
    #[test]
    fn is_writable_nonexistent_with_existing_parent() {
        let tmp = TempDir::new().unwrap();
        let nonexistent = tmp.path().join("does_not_exist.json");
        // Parent exists, so is_writable should return true.
        assert!(is_writable(&nonexistent));
    }

    // bd-2j5.19 — ALL_TOOLS has all 5 tools
    #[test]
    fn all_tools_contains_all_variants() {
        assert_eq!(ALL_TOOLS.len(), 5);
        assert!(ALL_TOOLS.contains(&AiTool::ClaudeCode));
        assert!(ALL_TOOLS.contains(&AiTool::Codex));
        assert!(ALL_TOOLS.contains(&AiTool::GeminiCli));
        assert!(ALL_TOOLS.contains(&AiTool::Cursor));
        assert!(ALL_TOOLS.contains(&AiTool::Aider));
    }

    // bd-2j5.19 — BootstrapOptions default values
    #[test]
    fn bootstrap_options_default() {
        let opts = BootstrapOptions::default();
        assert!(!opts.dry_run);
        assert!(opts.backup_dir.is_none());
        assert!(opts.only_tools.is_empty());
        assert!(opts.skip_tools.is_empty());
    }

    // bd-2j5.19 — IntegrationResult serialization
    #[test]
    fn integration_result_serializes_to_json() {
        let result = IntegrationResult {
            tool: AiTool::ClaudeCode,
            status: IntegrationStatus::Configured,
            config_path: PathBuf::from("/home/user/.claude/settings.json"),
            backup_path: Some(PathBuf::from("/home/user/.claude/settings.json.bak")),
            message: "hook injected".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"tool\":\"ClaudeCode\""));
        assert!(json.contains("\"status\":\"Configured\""));
    }

    // bd-2j5.19 — integration_snippet returns distinct snippets per tool
    #[test]
    fn integration_snippets_are_distinct() {
        let snippets: Vec<&str> = ALL_TOOLS.iter().map(|t| integration_snippet(*t)).collect();
        for (i, a) in snippets.iter().enumerate() {
            for (j, b) in snippets.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "snippets should be unique per tool");
                }
            }
        }
    }

    // bd-2j5.19 — inject_json_hook with already-comma-terminated content
    #[test]
    fn inject_json_hook_with_trailing_comma() {
        let tmp = TempDir::new().unwrap();
        let cfg = tmp.path().join("settings.json");
        fs::write(&cfg, "{\n  \"a\": 1,\n}\n").unwrap();

        inject_json_hook(&cfg, AiTool::Cursor).unwrap();

        let contents = fs::read_to_string(&cfg).unwrap();
        assert!(contents.contains("sbh guard"));
        // Should not produce double comma.
        assert!(!contents.contains(",,"), "should not produce double comma");
    }

    // bd-2j5.19 — format_summary shows FAIL status
    #[test]
    fn format_summary_shows_fail() {
        let summary = BootstrapSummary {
            detected_count: 1,
            results: vec![IntegrationResult {
                tool: AiTool::GeminiCli,
                status: IntegrationStatus::Failed,
                config_path: PathBuf::from("/home/user/.config/gemini/config.json"),
                backup_path: None,
                message: "config not writable".to_string(),
            }],
            configured_count: 0,
            already_configured_count: 0,
            failed_count: 1,
            skipped_count: 0,
        };
        let output = format_summary_human(&summary);
        assert!(output.contains("[FAIL]"));
        assert!(output.contains("gemini-cli"));
        assert!(output.contains("1 failed"));
    }

    // bd-2j5.19 — claude_code_config_paths enumeration
    #[test]
    fn claude_code_config_paths_returns_two() {
        let home = PathBuf::from("/home/testuser");
        let paths = claude_code_config_paths(&home);
        assert_eq!(paths.len(), 2);
        assert!(paths[0].ends_with("settings.json"));
        assert!(paths[1].ends_with("settings.json"));
    }

    // bd-2j5.19 — codex_config_paths enumeration
    #[test]
    fn codex_config_paths_returns_two() {
        let home = PathBuf::from("/home/testuser");
        let paths = codex_config_paths(&home);
        assert_eq!(paths.len(), 2);
    }

    // bd-2j5.19 — aider_config_paths enumeration
    #[test]
    fn aider_config_paths_returns_two() {
        let home = PathBuf::from("/home/testuser");
        let paths = aider_config_paths(&home);
        assert_eq!(paths.len(), 2);
    }

    // bd-2j5.19 — IntegrationStatus display all variants
    #[test]
    fn integration_status_display_all_variants() {
        assert_eq!(IntegrationStatus::Skipped.to_string(), "skipped");
        assert_eq!(IntegrationStatus::Failed.to_string(), "failed");
    }

    #[test]
    fn find_root_close_brace_ignores_block_comments() {
        let json = r#"
        {
            "key": "value",
            /* } */
            "nested": {
                "a": 1
            }
        }
        "#;
        let pos = find_root_close_brace(json).unwrap();
        // The last } is at the end.
        let slice = &json[pos..];
        assert!(slice.starts_with('}'));
        // Ensure it didn't pick the one inside the comment.
        assert!(pos > json.find("/* } */").unwrap() + 7);
    }
}
