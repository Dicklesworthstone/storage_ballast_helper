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

// ──────────────────── catalog roots ────────────────────

/// A known-safe cache location the daemon may scan on a pressured device that
/// has no configured `root_path` (W1 catalog roots).
///
/// Each expanded root becomes one opaque candidate unit: sized and dated by a
/// bounded probe, classified with `confidence` as its name evidence, and run
/// through every existing veto and the executor pre-flight like any other
/// candidate. Templates may start with `$HOME` (expanded for every real user
/// home on the device) and may end in a single `*` component, which is
/// resolved one level deep and never recursed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogRoot {
    /// Stable rule name (the candidate's pattern name in scans and events).
    pub name: &'static str,
    /// Path template: `$HOME/...` or absolute, optional trailing `*`.
    pub template: &'static str,
    /// Idle time the whole tree must show before it is a candidate.
    pub min_age: AgeThreshold,
    /// Name-evidence confidence for scoring.
    pub confidence: CleanupConfidence,
}

/// One concrete catalog root on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedCatalogRoot {
    pub path: std::path::PathBuf,
    pub rule: &'static str,
    pub confidence: CleanupConfidence,
    pub min_age: Duration,
}

impl CleanupConfidence {
    /// The name-evidence weight a catalog rule contributes to scoring.
    #[must_use]
    pub const fn as_name_confidence(self) -> f64 {
        match self {
            Self::Definite => 0.95,
            Self::Likely => 0.8,
            Self::Unclear => 0.5,
            Self::ReportOnly | Self::Sacred => 0.0,
        }
    }

    /// Lowercase label for output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Definite => "definite",
            Self::Likely => "likely",
            Self::Unclear => "unclear",
            Self::ReportOnly => "report_only",
            Self::Sacred => "sacred",
        }
    }
}

const fn catalog_root(
    name: &'static str,
    template: &'static str,
    min_age: AgeThreshold,
    confidence: CleanupConfidence,
) -> CatalogRoot {
    CatalogRoot {
        name,
        template,
        min_age,
        confidence,
    }
}

/// Known-safe cache locations, most specific first.
///
/// Specific rules win over the one-level `$HOME/.cache/*` catch-all for the
/// same path. Toolchains (`~/.rustup/toolchains`), project trees and anything
/// not listed here are never derived.
pub const CATALOG_ROOTS: &[CatalogRoot] = &[
    catalog_root(
        "catalog-pip-cache",
        "$HOME/.cache/pip",
        AgeThreshold::from_days(7),
        CleanupConfidence::Likely,
    ),
    catalog_root(
        "catalog-go-build-cache",
        "$HOME/.cache/go-build",
        AgeThreshold::from_days(7),
        CleanupConfidence::Likely,
    ),
    catalog_root(
        "catalog-cargo-registry-cache",
        "$HOME/.cargo/registry/cache",
        AgeThreshold::from_days(7),
        CleanupConfidence::Likely,
    ),
    catalog_root(
        "catalog-cargo-registry-src",
        "$HOME/.cargo/registry/src",
        AgeThreshold::from_days(7),
        CleanupConfidence::Likely,
    ),
    catalog_root(
        "catalog-cargo-git-checkouts",
        "$HOME/.cargo/git/checkouts",
        AgeThreshold::from_days(7),
        CleanupConfidence::Likely,
    ),
    catalog_root(
        "catalog-npm-cacache",
        "$HOME/.npm/_cacache",
        AgeThreshold::from_days(7),
        CleanupConfidence::Likely,
    ),
    catalog_root(
        "catalog-yarn-cache",
        "$HOME/.cache/yarn",
        AgeThreshold::from_days(7),
        CleanupConfidence::Likely,
    ),
    catalog_root(
        "catalog-pnpm-store",
        "$HOME/.local/share/pnpm/store",
        AgeThreshold::from_days(7),
        CleanupConfidence::Unclear,
    ),
    catalog_root(
        "catalog-user-trash",
        "$HOME/.local/share/Trash/files",
        AgeThreshold::from_days(3),
        CleanupConfidence::Likely,
    ),
    catalog_root(
        "catalog-homebrew-cache",
        "$HOME/Library/Caches/Homebrew",
        AgeThreshold::from_days(7),
        CleanupConfidence::Likely,
    ),
    catalog_root(
        "catalog-user-cache-entry",
        "$HOME/.cache/*",
        AgeThreshold::from_days(14),
        CleanupConfidence::Unclear,
    ),
    catalog_root(
        "catalog-user-library-cache-entry",
        "$HOME/Library/Caches/*",
        AgeThreshold::from_days(7),
        CleanupConfidence::Unclear,
    ),
    catalog_root(
        "catalog-var-tmp-entry",
        "/var/tmp/*",
        AgeThreshold::from_days(7),
        CleanupConfidence::Unclear,
    ),
    catalog_root(
        "catalog-apt-archive-entry",
        "/var/cache/apt/archives/*",
        AgeThreshold::from_days(7),
        CleanupConfidence::Unclear,
    ),
];

/// Real user homes to expand `$HOME` templates for.
///
/// The daemon's own home plus, on Unix, every `/etc/passwd` account with
/// UID >= 1000 whose home directory exists. Homes the process cannot read
/// simply expand to nothing.
#[must_use]
pub fn user_homes(current_home: &Path) -> Vec<std::path::PathBuf> {
    let mut homes = vec![current_home.to_path_buf()];
    #[cfg(unix)]
    if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 6 {
                continue;
            }
            let Ok(uid) = fields[2].parse::<u32>() else {
                continue;
            };
            if uid < 1000 || uid == 65534 {
                continue;
            }
            let home = std::path::PathBuf::from(fields[5]);
            if home.is_dir() && !homes.contains(&home) {
                homes.push(home);
            }
        }
    }
    homes.retain(|home| home.is_dir() && home != Path::new("/"));
    homes
}

/// Expand every template for every home into existing directories.
///
/// A template's trailing `*` is resolved one level (directories only); a
/// path already produced by an earlier (more specific) rule is not produced
/// again by a later one.
#[must_use]
pub fn expand_catalog_roots(
    roots: &[CatalogRoot],
    homes: &[std::path::PathBuf],
) -> Vec<ExpandedCatalogRoot> {
    let mut expanded: Vec<ExpandedCatalogRoot> = Vec::new();
    let mut push = |path: std::path::PathBuf, root: &CatalogRoot| {
        if path.is_dir() && !expanded.iter().any(|seen| seen.path == path) {
            expanded.push(ExpandedCatalogRoot {
                path,
                rule: root.name,
                confidence: root.confidence,
                min_age: root.min_age.minimum_age,
            });
        }
    };
    for root in roots {
        let bases: Vec<std::path::PathBuf> = root.template.strip_prefix("$HOME/").map_or_else(
            || vec![std::path::PathBuf::from(root.template)],
            |rest| homes.iter().map(|home| home.join(rest)).collect(),
        );
        for base in bases {
            if base.file_name().is_some_and(|name| name == "*") {
                let Some(parent) = base.parent() else {
                    continue;
                };
                let Ok(entries) = std::fs::read_dir(parent) else {
                    continue;
                };
                let mut children: Vec<std::path::PathBuf> = entries
                    .filter_map(Result::ok)
                    .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
                    .map(|entry| entry.path())
                    .collect();
                children.sort();
                for child in children {
                    push(child, root);
                }
            } else {
                push(base, root);
            }
        }
    }
    expanded
}

/// Catalog roots that live on the device `mount_device` (as reported by
/// `stat` for the mount point), so a scan for a pressured mount never
/// touches another volume.
#[must_use]
pub fn catalog_roots_for_mount(
    roots: &[CatalogRoot],
    homes: &[std::path::PathBuf],
    mount_device: u64,
) -> Vec<ExpandedCatalogRoot> {
    expand_catalog_roots(roots, homes)
        .into_iter()
        .filter(|root| device_of(&root.path) == Some(mount_device))
        .collect()
}

/// Device id of a path, for same-volume checks.
#[must_use]
pub fn device_of(path: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(path).ok().map(|meta| meta.dev())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
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
        text = text.replace("//", "/");
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
mod catalog_root_tests {
    use super::{
        AgeThreshold, CATALOG_ROOTS, CatalogRoot, CleanupConfidence, catalog_roots_for_mount,
        device_of, expand_catalog_roots, user_homes,
    };
    use std::fs;
    use std::path::Path;

    fn fixture_home() -> tempfile::TempDir {
        let home = tempfile::tempdir().unwrap();
        for rel in [
            ".cache/pip",
            ".cache/go-build",
            ".cache/somethingelse",
            ".cargo/registry/cache",
            ".cargo/registry/src",
            ".npm/_cacache",
            ".rustup/toolchains/stable",
            "projects/foo/src",
        ] {
            fs::create_dir_all(home.path().join(rel)).unwrap();
        }
        fs::write(home.path().join("projects/foo/Cargo.toml"), "[package]").unwrap();
        fs::write(home.path().join(".cache/loose-file"), b"x").unwrap();
        home
    }

    #[test]
    fn expansion_returns_only_existing_catalog_dirs_and_never_projects_or_toolchains() {
        let home = fixture_home();
        let roots = expand_catalog_roots(CATALOG_ROOTS, &[home.path().to_path_buf()]);
        let paths: Vec<&Path> = roots.iter().map(|r| r.path.as_path()).collect();

        for expected in [
            ".cache/pip",
            ".cache/go-build",
            ".cargo/registry/cache",
            ".cargo/registry/src",
            ".npm/_cacache",
            ".cache/somethingelse",
        ] {
            assert!(
                paths.contains(&home.path().join(expected).as_path()),
                "missing {expected} in {paths:?}"
            );
        }
        for forbidden in [
            "projects",
            "projects/foo",
            ".rustup",
            ".rustup/toolchains",
            ".rustup/toolchains/stable",
            ".cache/loose-file",
            ".cargo/git/checkouts",
        ] {
            assert!(
                !paths.contains(&home.path().join(forbidden).as_path()),
                "{forbidden} must not be derived: {paths:?}"
            );
        }

        // Specific rules win over the `.cache/*` catch-all for the same path.
        let pip = roots
            .iter()
            .find(|r| r.path == home.path().join(".cache/pip"))
            .unwrap();
        assert_eq!(pip.rule, "catalog-pip-cache");
        assert_eq!(pip.confidence, CleanupConfidence::Likely);
        let other = roots
            .iter()
            .find(|r| r.path == home.path().join(".cache/somethingelse"))
            .unwrap();
        assert_eq!(other.rule, "catalog-user-cache-entry");
        assert_eq!(other.confidence, CleanupConfidence::Unclear);
        assert_eq!(
            other.min_age,
            AgeThreshold::from_days(14).minimum_age,
            "catch-all entries need two weeks of idleness"
        );
        assert!(
            roots.iter().all(|r| r.path.is_dir()),
            "only existing directories are roots"
        );
    }

    #[test]
    fn expansion_covers_every_home_and_the_glob_stays_one_level_deep() {
        let a = fixture_home();
        let b = tempfile::tempdir().unwrap();
        fs::create_dir_all(b.path().join(".cache/deep/deeper")).unwrap();
        let homes = vec![a.path().to_path_buf(), b.path().to_path_buf()];
        let roots = expand_catalog_roots(CATALOG_ROOTS, &homes);
        assert!(roots.iter().any(|r| r.path == a.path().join(".cache/pip")));
        assert!(roots.iter().any(|r| r.path == b.path().join(".cache/deep")));
        assert!(
            !roots
                .iter()
                .any(|r| r.path == b.path().join(".cache/deep/deeper")),
            "a trailing * resolves one level only"
        );
        // Paths are unique across rules and homes.
        let mut seen = std::collections::HashSet::new();
        assert!(roots.iter().all(|r| seen.insert(r.path.clone())));
    }

    #[test]
    fn mount_filter_keeps_only_roots_on_that_device() {
        let home = fixture_home();
        let device = device_of(home.path()).expect("device id");
        let same = catalog_roots_for_mount(CATALOG_ROOTS, &[home.path().to_path_buf()], device);
        assert!(!same.is_empty(), "fixture roots live on the home's device");
        let other = catalog_roots_for_mount(
            CATALOG_ROOTS,
            &[home.path().to_path_buf()],
            device.wrapping_add(1),
        );
        assert!(
            other.is_empty(),
            "roots on another device are never derived"
        );
    }

    #[test]
    fn user_homes_includes_the_current_home_and_only_existing_dirs() {
        let home = tempfile::tempdir().unwrap();
        let homes = user_homes(home.path());
        assert_eq!(
            homes.first().map(std::path::PathBuf::as_path),
            Some(home.path())
        );
        assert!(homes.iter().all(|h| h.is_dir()));
        assert!(!homes.iter().any(|h| h == Path::new("/")));
        assert!(
            user_homes(Path::new("/nonexistent-home-xyz"))
                .iter()
                .all(|h| h.is_dir())
        );
    }

    #[test]
    fn catalog_templates_are_well_formed() {
        for root in CATALOG_ROOTS {
            assert!(
                root.template.starts_with("$HOME/") || root.template.starts_with('/'),
                "{}",
                root.template
            );
            let star_components = root.template.matches('*').count();
            assert!(star_components <= 1, "{}", root.template);
            if star_components == 1 {
                assert!(root.template.ends_with("/*"), "{}", root.template);
            }
            assert!(
                !root.template.contains("rustup"),
                "toolchains are never roots"
            );
            assert!(
                !root.template.contains("projects"),
                "project trees are never roots"
            );
            assert!(root.min_age.minimum_age >= AgeThreshold::from_days(3).minimum_age);
        }
        let _: &CatalogRoot = &CATALOG_ROOTS[0];
        assert!((CleanupConfidence::Likely.as_name_confidence() - 0.8).abs() < f64::EPSILON);
    }
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
