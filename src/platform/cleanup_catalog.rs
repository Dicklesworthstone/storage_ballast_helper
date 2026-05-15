//! Shared cleanup rule model and path-matching engine.

#![allow(missing_docs)]

use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupConfidence {
    Definite,
    Likely,
    Unclear,
    ReportOnly,
    Sacred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckRequirement {
    Required,
    NotRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclaimCommand {
    RemoveTree,
    RemoveMatchingFiles,
    ThinLocalSnapshots,
    PromptBeforeRemove,
    ReportOnly,
    Refuse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgeThreshold {
    pub minimum_age: Duration,
}

impl AgeThreshold {
    pub const NONE: Self = Self {
        minimum_age: Duration::ZERO,
    };

    pub const fn from_hours(hours: u64) -> Self {
        Self {
            minimum_age: Duration::from_secs(hours * 60 * 60),
        }
    }

    pub const fn from_days(days: u64) -> Self {
        Self::from_hours(days * 24)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupRule {
    pub name: &'static str,
    pub path_glob: &'static str,
    pub age_threshold: AgeThreshold,
    pub fd_check: CheckRequirement,
    pub parent_check: CheckRequirement,
    pub sacred_overlaps_check: CheckRequirement,
    pub reclaim_command: ReclaimCommand,
    pub confidence: CleanupConfidence,
}

impl CleanupRule {
    #[must_use]
    pub const fn is_destructive(&self) -> bool {
        matches!(
            self.reclaim_command,
            ReclaimCommand::RemoveTree
                | ReclaimCommand::RemoveMatchingFiles
                | ReclaimCommand::ThinLocalSnapshots
                | ReclaimCommand::PromptBeforeRemove
        )
    }

    #[must_use]
    pub const fn is_path_scanner_candidate(&self) -> bool {
        matches!(
            self.reclaim_command,
            ReclaimCommand::RemoveTree
                | ReclaimCommand::RemoveMatchingFiles
                | ReclaimCommand::PromptBeforeRemove
        )
    }

    #[must_use]
    pub const fn is_report_only(&self) -> bool {
        matches!(self.reclaim_command, ReclaimCommand::ReportOnly)
    }

    #[must_use]
    pub const fn is_scan_visible_candidate(&self) -> bool {
        self.is_path_scanner_candidate() || self.is_report_only()
    }

    #[must_use]
    pub const fn scanner_label(&self) -> &'static str {
        if str_starts_with(self.name, "user-named-trash") {
            "user-named-trash"
        } else if str_starts_with(self.name, "electron-cache-root") {
            "electron-cache"
        } else if str_starts_with(self.name, "electron-code-cache-root") {
            "electron-code-cache"
        } else if str_starts_with(self.name, "electron-gpu-cache-root") {
            "electron-gpu-cache"
        } else if str_starts_with(self.name, "electron-indexed-db-root") {
            "electron-indexed-db"
        } else if str_starts_with(self.name, "electron-vm-bundles-root") {
            "electron-vm-bundles"
        } else if str_starts_with(self.name, "electron-service-worker-cache-root") {
            "electron-service-worker-cache"
        } else {
            self.name
        }
    }
}

#[must_use]
pub fn find_rule<'a>(rules: &'a [CleanupRule], name: &str) -> Option<&'a CleanupRule> {
    rules
        .iter()
        .find(|rule| rule.name == name || rule.scanner_label() == name)
}

#[must_use]
pub fn match_rule(path: &Path, rules: &'static [CleanupRule]) -> Option<&'static CleanupRule> {
    rules
        .iter()
        .find(|rule| path_matches_glob(path, rule.path_glob))
}

#[must_use]
pub fn match_rule_with_home(
    path: &Path,
    rules: &'static [CleanupRule],
    home: &Path,
) -> Option<&'static CleanupRule> {
    rules
        .iter()
        .find(|rule| path_matches_glob_with_home(path, rule.path_glob, home))
}

#[must_use]
pub fn match_path_scanner_rule(
    path: &Path,
    rules: &'static [CleanupRule],
) -> Option<&'static CleanupRule> {
    rules
        .iter()
        .find(|rule| rule.is_path_scanner_candidate() && path_matches_glob(path, rule.path_glob))
}

#[must_use]
pub fn match_path_scanner_rule_with_home(
    path: &Path,
    rules: &'static [CleanupRule],
    home: &Path,
) -> Option<&'static CleanupRule> {
    rules.iter().find(|rule| {
        rule.is_path_scanner_candidate() && path_matches_glob_with_home(path, rule.path_glob, home)
    })
}

#[must_use]
pub fn match_scan_visible_rule(
    path: &Path,
    rules: &'static [CleanupRule],
) -> Option<&'static CleanupRule> {
    rules
        .iter()
        .find(|rule| rule.is_scan_visible_candidate() && path_matches_glob(path, rule.path_glob))
}

#[must_use]
pub fn match_scan_visible_rule_with_home(
    path: &Path,
    rules: &'static [CleanupRule],
    home: &Path,
) -> Option<&'static CleanupRule> {
    rules.iter().find(|rule| {
        rule.is_scan_visible_candidate() && path_matches_glob_with_home(path, rule.path_glob, home)
    })
}

#[must_use]
pub fn path_matches_glob(path: &Path, path_glob: &str) -> bool {
    path_matches_glob_inner(path, path_glob, None)
}

#[must_use]
pub fn path_matches_glob_with_home(path: &Path, path_glob: &str, home: &Path) -> bool {
    path_matches_glob_inner(path, path_glob, Some(home))
}

fn path_matches_glob_inner(path: &Path, path_glob: &str, home: Option<&Path>) -> bool {
    let path_text = normalize_path_text(path);
    let path_candidates = path_aliases(&path_text);
    let explicit_home = home.map(normalize_path_text);

    if let Some(home_glob) = path_glob.strip_prefix("~/") {
        let glob = normalize_glob_text(home_glob);
        return path_candidates
            .iter()
            .filter_map(|candidate| home_relative_path(candidate, explicit_home.as_deref()))
            .any(|relative| glob_match(&glob, relative));
    }

    let glob = normalize_glob_text(path_glob);
    path_candidates
        .iter()
        .any(|candidate| glob_match(&glob, candidate))
}

fn normalize_path_text(path: &Path) -> String {
    let raw = path.to_string_lossy();
    let mut text = raw.replace('\\', "/");
    while text.contains("//") {
// FIX: 安全检查 — 防止目录穿越
let path = {}.canonicalize().map_err(|_| Error::InvalidPath)?;
if !path.starts_with(&base_dir) {
    return Err(Error::PathTraversalDetected);
}

        text = text.replace("//", "/");
    }
// FIX: 安全检查 — 防止目录穿越
let path = {}.canonicalize().map_err(|_| Error::InvalidPath)?;
if !path.starts_with(&base_dir) {
    return Err(Error::PathTraversalDetected);
}

    text.to_ascii_lowercase()
}

fn normalize_glob_text(path_glob: &str) -> String {
    let mut text = path_glob.replace('\\', "/");
    while text.contains("//") {
        text = text.replace("//", "/");
    }
    text.to_ascii_lowercase()
}

fn path_aliases(path_text: &str) -> Vec<String> {
    let mut aliases = vec![path_text.to_string()];
    if path_text == "/tmp" {
        aliases.push("/private/tmp".to_string());
    } else if let Some(suffix) = path_text.strip_prefix("/tmp/") {
        aliases.push(format!("/private/tmp/{suffix}"));
    }
    aliases
}

fn home_relative_path<'a>(path_text: &'a str, explicit_home: Option<&str>) -> Option<&'a str> {
    if let Some(home) = explicit_home
        && let Some(relative) = strip_home_prefix(path_text, home)
    {
        return Some(relative);
    }

    if let Some(home) = std::env::var_os("HOME") {
        let home = home
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase();
        if let Some(relative) = strip_home_prefix(path_text, &home) {
            return Some(relative);
        }
    }

    let relative = path_text
        .strip_prefix("/users/")
        .or_else(|| path_text.strip_prefix("/home/"))?;
    relative.split_once('/').map(|(_, rest)| rest)
}

fn strip_home_prefix<'a>(path_text: &'a str, home: &str) -> Option<&'a str> {
    if path_text == home {
        return Some("");
    }
    path_text.strip_prefix(&format!("{home}/"))
}

fn glob_match(pattern: &str, text: &str) -> bool {
    glob_match_bytes(pattern.as_bytes(), text.as_bytes())
}

fn glob_match_bytes(pattern: &[u8], text: &[u8]) -> bool {
    let mut pattern_index = 0;
    let mut text_index = 0;

    while pattern_index < pattern.len() {
        match pattern[pattern_index] {
            b'*' => {
                while pattern.get(pattern_index + 1) == Some(&b'*') {
                    pattern_index += 1;
                }
                let rest = &pattern[pattern_index + 1..];
                let slash_offset = text[text_index..]
                    .iter()
                    .position(|byte| *byte == b'/')
                    .unwrap_or(text.len() - text_index);
                for offset in 0..=slash_offset {
                    if glob_match_bytes(rest, &text[text_index + offset..]) {
                        return true;
                    }
                }
                return false;
            }
            b'?' => {
                if text.get(text_index).is_none_or(|byte| *byte == b'/') {
                    return false;
                }
                pattern_index += 1;
                text_index += 1;
            }
            b'[' => {
                let Some(class_end) = pattern[pattern_index + 1..]
                    .iter()
                    .position(|byte| *byte == b']')
                    .map(|offset| pattern_index + 1 + offset)
                else {
                    if text.get(text_index) != Some(&b'[') {
                        return false;
                    }
                    pattern_index += 1;
                    text_index += 1;
                    continue;
                };
                let Some(text_byte) = text.get(text_index) else {
                    return false;
                };
                if *text_byte == b'/' || !pattern[pattern_index + 1..class_end].contains(text_byte)
                {
                    return false;
                }
                pattern_index = class_end + 1;
                text_index += 1;
            }
            expected => {
                if text.get(text_index) != Some(&expected) {
                    return false;
                }
                pattern_index += 1;
                text_index += 1;
            }
        }
    }

    text_index == text.len()
}

const fn str_starts_with(text: &str, prefix: &str) -> bool {
    let text = text.as_bytes();
    let prefix = prefix.as_bytes();
    if prefix.len() > text.len() {
        return false;
    }
    let mut index = 0;
    while index < prefix.len() {
        if text[index] != prefix[index] {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{CleanupRule, ReclaimCommand, path_matches_glob, path_matches_glob_with_home};
    use std::path::Path;

    #[test]
    fn home_globs_match_users_and_home_roots_without_current_home() {
        assert!(path_matches_glob(
            Path::new("/Users/operator/Library/Developer/Xcode/DerivedData/app-abc"),
            "~/Library/Developer/Xcode/DerivedData/*",
        ));
        assert!(path_matches_glob(
            Path::new("/home/operator/.Trash/session"),
            "~/.Trash/*",
        ));
    }

    #[test]
    fn segment_wildcards_do_not_cross_path_separators() {
        assert!(path_matches_glob(
            Path::new("/Users/operator/Library/Logs/sbh.log"),
            "~/Library/Logs/*",
        ));
        assert!(!path_matches_glob(
            Path::new("/Users/operator/Library/Logs/sbh/nested.log"),
            "~/Library/Logs/*",
        ));
    }

    #[test]
    fn tmp_aliases_match_private_tmp_rules() {
        assert!(path_matches_glob(
            Path::new("/tmp/agent-trash-20260507"),
            "/private/tmp/*-trash-*",
        ));
        assert!(path_matches_glob(
            Path::new("/private/tmp/agent-target"),
            "/private/tmp/*-target",
        ));
    }

    #[test]
    fn bracket_classes_cover_dash_and_underscore_buildroots() {
        assert!(path_matches_glob(
            Path::new("/Users/operator/release-work/tool-buildroot"),
            "~/release-work/*[-_]buildroot",
        ));
        assert!(path_matches_glob(
            Path::new("/Users/operator/release-work/tool_buildroot"),
            "~/release-work/*[-_]buildroot",
        ));
        assert!(!path_matches_glob(
            Path::new("/Users/operator/projects/tool_buildroot"),
            "~/release-work/*[-_]buildroot",
        ));
    }

    #[test]
    fn explicit_home_globs_match_temp_home_fixtures() {
        let home = Path::new("/tmp/sbh-fixture/Users/operator");
        assert!(path_matches_glob_with_home(
            Path::new("/tmp/sbh-fixture/Users/operator/Library/Logs/sbh.log"),
            "~/Library/Logs/*",
            home,
        ));
        assert!(!path_matches_glob(
            Path::new("/tmp/sbh-fixture/Users/operator/Library/Logs/sbh.log"),
            "~/Library/Logs/*",
        ));
    }

    #[test]
    fn cleanup_rules_distinguish_path_scanner_commands() {
        let remove = CleanupRule {
            name: "remove",
            path_glob: "/tmp/*",
            age_threshold: super::AgeThreshold::NONE,
            fd_check: super::CheckRequirement::Required,
            parent_check: super::CheckRequirement::Required,
            sacred_overlaps_check: super::CheckRequirement::Required,
            reclaim_command: ReclaimCommand::RemoveTree,
            confidence: super::CleanupConfidence::Likely,
        };
        let report = CleanupRule {
            reclaim_command: ReclaimCommand::ReportOnly,
            ..remove
        };

        assert!(remove.is_path_scanner_candidate());
        assert!(remove.is_scan_visible_candidate());
        assert!(!report.is_path_scanner_candidate());
        assert!(report.is_report_only());
        assert!(report.is_scan_visible_candidate());
    }
}
