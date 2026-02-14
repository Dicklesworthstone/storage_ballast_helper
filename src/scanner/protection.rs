//! Project protection: `.sbh-protect` marker files and config-level glob patterns.
//!
//! Two modes of operation:
//! - **Full mode** (with config): reads `scanner.protected_paths` from config AND discovers
//!   `.sbh-protect` marker files during walker traversal.
//! - **Marker-only mode** (without config): only discovers `.sbh-protect` marker files.
//!   Used by emergency recovery mode which operates without a config file.

#![allow(missing_docs)]

use std::collections::HashSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::core::errors::{Result, SbhError};

/// Filename placed in directories to protect them from sbh cleanup.
pub const MARKER_FILENAME: &str = ".sbh-protect";

/// Optional metadata stored inside a `.sbh-protect` file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectionMetadata {
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub protected_by: Option<String>,
    #[serde(default)]
    pub protected_at: Option<String>,
}

/// A single protection entry for listing purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionEntry {
    pub path: PathBuf,
    pub source: ProtectionSource,
    pub metadata: Option<ProtectionMetadata>,
}

/// How a path became protected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectionSource {
    /// Protected by a `.sbh-protect` marker file.
    MarkerFile,
    /// Protected by a config-level glob pattern.
    ConfigPattern(String),
}

/// Compiled glob pattern for path matching.
#[derive(Debug, Clone)]
struct GlobPattern {
    original: String,
    compiled: Regex,
}

/// Registry of protected paths from marker files and config-level glob patterns.
///
/// The registry supports two modes:
/// - **Full**: config patterns + marker files (normal operation)
/// - **Marker-only**: just marker files (emergency mode, no config available)
#[derive(Debug)]
pub struct ProtectionRegistry {
    marker_paths: HashSet<PathBuf>,
    config_patterns: Vec<GlobPattern>,
}

impl ProtectionRegistry {
    /// Create a new registry from optional config-level protected path patterns.
    ///
    /// When `config_patterns` is `None`, operates in marker-only mode.
    /// Patterns use shell-style globs: `*` matches within a path component,
    /// `**` matches across path components, `?` matches a single character.
    pub fn new(config_patterns: Option<&[String]>) -> Result<Self> {
        let compiled = match config_patterns {
            Some(patterns) => patterns
                .iter()
                .map(|pat| {
                    let re = glob_to_regex(pat)?;
                    Ok(GlobPattern {
                        original: pat.clone(),
                        compiled: re,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            None => Vec::new(),
        };

        Ok(Self {
            marker_paths: HashSet::new(),
            config_patterns: compiled,
        })
    }

    /// Create an empty marker-only registry (for emergency mode).
    pub fn marker_only() -> Self {
        Self {
            marker_paths: HashSet::new(),
            config_patterns: Vec::new(),
        }
    }

    /// Check whether a path is protected by any mechanism (marker or config pattern).
    ///
    /// A path is protected if:
    /// - It is a known marker path, OR
    /// - Any ancestor directory is a known marker path, OR
    /// - It matches a config-level glob pattern.
    pub fn is_protected(&self, path: &Path) -> bool {
        self.matches_marker(path) || self.matches_config_pattern(path)
    }

    /// Return the reason a path is protected, or `None` if not protected.
    pub fn protection_reason(&self, path: &Path) -> Option<String> {
        // Check marker files first (more specific).
        if let Some(marker_dir) = self.find_marker_ancestor(path) {
            let metadata = read_marker_metadata(&marker_dir.join(MARKER_FILENAME));
            return Some(match metadata {
                Some(meta) if meta.reason.is_some() => {
                    format!(
                        "protected by {} marker: {}",
                        MARKER_FILENAME,
                        meta.reason.as_ref().unwrap()
                    )
                }
                _ => format!("protected by {MARKER_FILENAME} in {}", marker_dir.display()),
            });
        }

        // Check config patterns.
        let path_str = path.to_string_lossy();
        for pattern in &self.config_patterns {
            if pattern.compiled.is_match(&path_str) {
                return Some(format!(
                    "protected by config pattern: {}",
                    pattern.original
                ));
            }
        }

        None
    }

    /// Walk `root` (non-recursively for each directory level) to discover
    /// `.sbh-protect` marker files. Returns the number of new markers found.
    ///
    /// This performs a breadth-first traversal up to `max_depth` levels.
    /// Protected directories are recorded but NOT descended into further
    /// (we already know the entire subtree is protected).
    pub fn discover_markers(&mut self, root: &Path, max_depth: usize) -> Result<usize> {
        let mut found = 0usize;
        let mut queue: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];

        while let Some((dir, depth)) = queue.pop() {
            let marker_path = dir.join(MARKER_FILENAME);
            if marker_path.exists() {
                if self.marker_paths.insert(dir.clone()) {
                    found += 1;
                }
                // Don't descend into protected subtrees during discovery —
                // we already know the whole subtree is protected.
                continue;
            }

            if depth >= max_depth {
                continue;
            }

            // Read directory entries, skipping permission errors gracefully.
            let entries = match fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(err) if err.kind() == ErrorKind::PermissionDenied => continue,
                Err(err) if err.kind() == ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(SbhError::Io {
                        path: dir,
                        source: err,
                    });
                }
            };

            for entry_result in entries {
                let Ok(entry) = entry_result else {
                    continue;
                };
                let Ok(ft) = entry.file_type() else {
                    continue;
                };
                if ft.is_dir() {
                    queue.push((entry.path(), depth + 1));
                }
            }
        }

        Ok(found)
    }

    /// Register a single marker directory (used when walker encounters a marker
    /// during normal traversal, without full discovery).
    pub fn register_marker(&mut self, dir: &Path) -> bool {
        self.marker_paths.insert(dir.to_path_buf())
    }

    /// List all currently known protections.
    pub fn list_protections(&self) -> Vec<ProtectionEntry> {
        let mut entries = Vec::new();

        for marker_dir in &self.marker_paths {
            let marker_file = marker_dir.join(MARKER_FILENAME);
            let metadata = read_marker_metadata(&marker_file);
            entries.push(ProtectionEntry {
                path: marker_dir.clone(),
                source: ProtectionSource::MarkerFile,
                metadata,
            });
        }

        for pattern in &self.config_patterns {
            entries.push(ProtectionEntry {
                path: PathBuf::from(&pattern.original),
                source: ProtectionSource::ConfigPattern(pattern.original.clone()),
                metadata: None,
            });
        }

        entries.sort_by(|a, b| a.path.cmp(&b.path));
        entries
    }

    /// Number of known marker paths.
    pub fn marker_count(&self) -> usize {
        self.marker_paths.len()
    }

    /// Number of config-level patterns.
    pub fn pattern_count(&self) -> usize {
        self.config_patterns.len()
    }

    fn matches_marker(&self, path: &Path) -> bool {
        self.find_marker_ancestor(path).is_some()
    }

    fn find_marker_ancestor(&self, path: &Path) -> Option<&PathBuf> {
        // Check exact path first.
        if let Some(found) = self.marker_paths.get(&path.to_path_buf()) {
            return Some(found);
        }
        // Walk ancestors.
        let mut current = path.parent();
        while let Some(ancestor) = current {
            if let Some(found) = self.marker_paths.get(&ancestor.to_path_buf()) {
                return Some(found);
            }
            current = ancestor.parent();
        }
        None
    }

    fn matches_config_pattern(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        self.config_patterns
            .iter()
            .any(|pat| pat.compiled.is_match(&path_str))
    }
}

/// Create a `.sbh-protect` marker file at the given directory path.
///
/// If `metadata` is provided, writes it as JSON. Otherwise creates an empty file.
pub fn create_marker(dir: &Path, metadata: Option<&ProtectionMetadata>) -> Result<()> {
    let marker_path = dir.join(MARKER_FILENAME);
    let content = match metadata {
        Some(meta) => serde_json::to_string_pretty(meta)?,
        None => String::new(),
    };
    fs::write(&marker_path, content).map_err(|source| SbhError::Io {
        path: marker_path,
        source,
    })
}

/// Remove a `.sbh-protect` marker file from the given directory.
pub fn remove_marker(dir: &Path) -> Result<bool> {
    let marker_path = dir.join(MARKER_FILENAME);
    match fs::remove_file(&marker_path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(source) => Err(SbhError::Io {
            path: marker_path,
            source,
        }),
    }
}

/// Read optional metadata from a `.sbh-protect` marker file.
///
/// Returns `None` if the file is empty, doesn't exist, or isn't valid JSON.
fn read_marker_metadata(marker_path: &Path) -> Option<ProtectionMetadata> {
    let content = fs::read_to_string(marker_path).ok()?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return None;
    }
    serde_json::from_str(trimmed).ok()
}

/// Convert a shell-style glob pattern to a regex.
///
/// Supports:
/// - `**` → matches any path (including separators)
/// - `*`  → matches anything except `/`
/// - `?`  → matches a single character except `/`
fn glob_to_regex(pattern: &str) -> Result<Regex> {
    let mut regex_str = String::with_capacity(pattern.len() * 2);
    regex_str.push('^');

    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            '*' if i + 1 < chars.len() && chars[i + 1] == '*' => {
                regex_str.push_str(".*");
                i += 2;
                // Skip trailing slash after ** if present.
                if i < chars.len() && chars[i] == '/' {
                    regex_str.push_str("/?");
                    i += 1;
                }
            }
            '*' => {
                regex_str.push_str("[^/]*");
                i += 1;
            }
            '?' => {
                regex_str.push_str("[^/]");
                i += 1;
            }
            '.' | '+' | '(' | ')' | '{' | '}' | '[' | ']' | '^' | '$' | '|' | '\\' => {
                regex_str.push('\\');
                regex_str.push(chars[i]);
                i += 1;
            }
            c => {
                regex_str.push(c);
                i += 1;
            }
        }
    }

    regex_str.push('$');

    Regex::new(&regex_str).map_err(|err| SbhError::InvalidConfig {
        details: format!("invalid glob pattern {pattern:?}: {err}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn marker_only_registry_starts_empty() {
        let reg = ProtectionRegistry::marker_only();
        assert_eq!(reg.marker_count(), 0);
        assert_eq!(reg.pattern_count(), 0);
        assert!(!reg.is_protected(Path::new("/data/projects/foo")));
    }

    #[test]
    fn registry_with_config_patterns() {
        let patterns = vec![
            "/data/projects/production-*".to_string(),
            "/home/*/critical-builds".to_string(),
        ];
        let reg = ProtectionRegistry::new(Some(&patterns)).unwrap();
        assert_eq!(reg.pattern_count(), 2);

        assert!(reg.is_protected(Path::new("/data/projects/production-app")));
        assert!(reg.is_protected(Path::new("/data/projects/production-v2")));
        assert!(!reg.is_protected(Path::new("/data/projects/staging-app")));

        assert!(reg.is_protected(Path::new("/home/jeff/critical-builds")));
        assert!(reg.is_protected(Path::new("/home/alice/critical-builds")));
        assert!(!reg.is_protected(Path::new("/home/jeff/other-builds")));
    }

    #[test]
    fn none_config_creates_marker_only_mode() {
        let reg = ProtectionRegistry::new(None).unwrap();
        assert_eq!(reg.pattern_count(), 0);
        assert!(!reg.is_protected(Path::new("/data/projects/anything")));
    }

    #[test]
    fn register_marker_makes_path_protected() {
        let mut reg = ProtectionRegistry::marker_only();
        reg.register_marker(Path::new("/data/projects/critical-app"));

        assert!(reg.is_protected(Path::new("/data/projects/critical-app")));
        assert!(reg.is_protected(Path::new("/data/projects/critical-app/target")));
        assert!(reg.is_protected(Path::new(
            "/data/projects/critical-app/target/debug/build"
        )));
        assert!(!reg.is_protected(Path::new("/data/projects/other-app")));
    }

    #[test]
    fn protection_reason_for_marker() {
        let mut reg = ProtectionRegistry::marker_only();
        reg.register_marker(Path::new("/data/projects/critical"));

        let reason = reg
            .protection_reason(Path::new("/data/projects/critical/target"))
            .unwrap();
        assert!(reason.contains(MARKER_FILENAME));
        assert!(reason.contains("/data/projects/critical"));
    }

    #[test]
    fn protection_reason_for_config_pattern() {
        let patterns = vec!["/data/projects/production-*".to_string()];
        let reg = ProtectionRegistry::new(Some(&patterns)).unwrap();

        let reason = reg
            .protection_reason(Path::new("/data/projects/production-app"))
            .unwrap();
        assert!(reason.contains("config pattern"));
        assert!(reason.contains("production-*"));
    }

    #[test]
    fn unprotected_path_returns_none() {
        let reg = ProtectionRegistry::marker_only();
        assert!(reg
            .protection_reason(Path::new("/data/projects/foo"))
            .is_none());
    }

    #[test]
    fn create_empty_marker_file() {
        let tmp = TempDir::new().unwrap();
        create_marker(tmp.path(), None).unwrap();

        let marker = tmp.path().join(MARKER_FILENAME);
        assert!(marker.exists());
        let content = fs::read_to_string(&marker).unwrap();
        assert!(content.is_empty());
    }

    #[test]
    fn create_marker_with_metadata() {
        let tmp = TempDir::new().unwrap();
        let meta = ProtectionMetadata {
            reason: Some("Production build - 6 hour compile".to_string()),
            protected_by: Some("jeff".to_string()),
            protected_at: Some("2026-02-14T10:00:00Z".to_string()),
        };
        create_marker(tmp.path(), Some(&meta)).unwrap();

        let marker = tmp.path().join(MARKER_FILENAME);
        let content = fs::read_to_string(&marker).unwrap();
        let parsed: ProtectionMetadata = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed, meta);
    }

    #[test]
    fn remove_existing_marker() {
        let tmp = TempDir::new().unwrap();
        create_marker(tmp.path(), None).unwrap();
        assert!(tmp.path().join(MARKER_FILENAME).exists());

        let removed = remove_marker(tmp.path()).unwrap();
        assert!(removed);
        assert!(!tmp.path().join(MARKER_FILENAME).exists());
    }

    #[test]
    fn remove_nonexistent_marker_returns_false() {
        let tmp = TempDir::new().unwrap();
        let removed = remove_marker(tmp.path()).unwrap();
        assert!(!removed);
    }

    #[test]
    fn discover_markers_in_tree() {
        let tmp = TempDir::new().unwrap();

        // Create directory structure:
        // root/
        //   a/
        //     .sbh-protect
        //     child/
        //   b/
        //     deep/
        //       .sbh-protect
        //   c/
        let a = tmp.path().join("a");
        let a_child = a.join("child");
        let b_deep = tmp.path().join("b").join("deep");
        let c = tmp.path().join("c");

        fs::create_dir_all(&a_child).unwrap();
        fs::create_dir_all(&b_deep).unwrap();
        fs::create_dir_all(&c).unwrap();

        create_marker(&a, None).unwrap();
        create_marker(&b_deep, None).unwrap();

        let mut reg = ProtectionRegistry::marker_only();
        let count = reg.discover_markers(tmp.path(), 10).unwrap();

        assert_eq!(count, 2);
        assert_eq!(reg.marker_count(), 2);
        assert!(reg.is_protected(&a));
        assert!(reg.is_protected(&a_child)); // child of protected dir
        assert!(reg.is_protected(&b_deep));
        assert!(!reg.is_protected(&c));
    }

    #[test]
    fn discover_does_not_descend_into_protected() {
        let tmp = TempDir::new().unwrap();

        // root/
        //   protected/
        //     .sbh-protect
        //     nested/
        //       .sbh-protect   <-- should NOT be separately discovered
        let protected = tmp.path().join("protected");
        let nested = protected.join("nested");
        fs::create_dir_all(&nested).unwrap();
        create_marker(&protected, None).unwrap();
        create_marker(&nested, None).unwrap();

        let mut reg = ProtectionRegistry::marker_only();
        let count = reg.discover_markers(tmp.path(), 10).unwrap();

        // Only the top-level marker should be found since we don't descend.
        assert_eq!(count, 1);
        assert!(reg.is_protected(&protected));
        // Nested is still protected because it's a child of a protected dir.
        assert!(reg.is_protected(&nested));
    }

    #[test]
    fn discover_respects_max_depth() {
        let tmp = TempDir::new().unwrap();

        // root/a/b/c/.sbh-protect — at depth 3 from root
        let deep = tmp.path().join("a").join("b").join("c");
        fs::create_dir_all(&deep).unwrap();
        create_marker(&deep, None).unwrap();

        let mut reg = ProtectionRegistry::marker_only();
        let count = reg.discover_markers(tmp.path(), 2).unwrap();
        assert_eq!(count, 0); // Too deep to find

        let mut reg2 = ProtectionRegistry::marker_only();
        let count2 = reg2.discover_markers(tmp.path(), 4).unwrap();
        assert_eq!(count2, 1);
    }

    #[test]
    fn list_protections_includes_both_sources() {
        let patterns = vec!["/data/projects/production-*".to_string()];
        let mut reg = ProtectionRegistry::new(Some(&patterns)).unwrap();
        reg.register_marker(Path::new("/data/projects/critical"));

        let list = reg.list_protections();
        assert_eq!(list.len(), 2);

        let sources: Vec<_> = list.iter().map(|e| &e.source).collect();
        assert!(sources.iter().any(|s| matches!(s, ProtectionSource::MarkerFile)));
        assert!(sources
            .iter()
            .any(|s| matches!(s, ProtectionSource::ConfigPattern(_))));
    }

    #[test]
    fn glob_star_matches_within_component() {
        let patterns = vec!["/tmp/cargo-target-*".to_string()];
        let reg = ProtectionRegistry::new(Some(&patterns)).unwrap();

        assert!(reg.is_protected(Path::new("/tmp/cargo-target-abc")));
        assert!(reg.is_protected(Path::new("/tmp/cargo-target-xyz123")));
        assert!(!reg.is_protected(Path::new("/tmp/cargo-target-abc/sub")));
        assert!(!reg.is_protected(Path::new("/tmp/other")));
    }

    #[test]
    fn glob_double_star_matches_across_components() {
        let patterns = vec!["/data/**/target".to_string()];
        let reg = ProtectionRegistry::new(Some(&patterns)).unwrap();

        assert!(reg.is_protected(Path::new("/data/projects/foo/target")));
        assert!(reg.is_protected(Path::new("/data/target")));
        assert!(!reg.is_protected(Path::new("/data/projects/foo/targets")));
    }

    #[test]
    fn glob_question_mark_matches_single_char() {
        let patterns = vec!["/tmp/build-?".to_string()];
        let reg = ProtectionRegistry::new(Some(&patterns)).unwrap();

        assert!(reg.is_protected(Path::new("/tmp/build-A")));
        assert!(reg.is_protected(Path::new("/tmp/build-1")));
        assert!(!reg.is_protected(Path::new("/tmp/build-AB")));
        assert!(!reg.is_protected(Path::new("/tmp/build-")));
    }

    #[test]
    fn marker_file_with_json_metadata_is_read() {
        let tmp = TempDir::new().unwrap();
        let meta = ProtectionMetadata {
            reason: Some("Critical production build".to_string()),
            protected_by: Some("admin".to_string()),
            protected_at: None,
        };
        create_marker(tmp.path(), Some(&meta)).unwrap();

        let mut reg = ProtectionRegistry::marker_only();
        reg.discover_markers(tmp.path(), 1).unwrap();

        let entries = reg.list_protections();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert!(entry.metadata.is_some());
        assert_eq!(
            entry.metadata.as_ref().unwrap().reason,
            Some("Critical production build".to_string())
        );
    }

    #[test]
    fn empty_marker_file_works() {
        let tmp = TempDir::new().unwrap();
        create_marker(tmp.path(), None).unwrap();

        let mut reg = ProtectionRegistry::marker_only();
        reg.discover_markers(tmp.path(), 1).unwrap();

        assert_eq!(reg.marker_count(), 1);
        let entries = reg.list_protections();
        assert!(entries[0].metadata.is_none());
    }

    #[test]
    fn brackets_in_glob_are_literal() {
        // The glob converter escapes all regex metacharacters, so brackets
        // are treated as literal characters (not regex character classes).
        let patterns = vec!["/tmp/[build]".to_string()];
        let reg = ProtectionRegistry::new(Some(&patterns)).unwrap();
        assert!(reg.is_protected(Path::new("/tmp/[build]")));
        assert!(!reg.is_protected(Path::new("/tmp/b")));
    }

    #[test]
    fn read_marker_metadata_handles_garbage() {
        let tmp = TempDir::new().unwrap();
        let marker = tmp.path().join(MARKER_FILENAME);
        fs::write(&marker, "not json at all").unwrap();

        let meta = read_marker_metadata(&marker);
        assert!(meta.is_none());
    }

    #[test]
    fn read_marker_metadata_handles_missing() {
        let meta = read_marker_metadata(Path::new("/nonexistent/.sbh-protect"));
        assert!(meta.is_none());
    }

    #[test]
    fn duplicate_register_returns_false() {
        let mut reg = ProtectionRegistry::marker_only();
        assert!(reg.register_marker(Path::new("/data/projects/foo")));
        assert!(!reg.register_marker(Path::new("/data/projects/foo")));
        assert_eq!(reg.marker_count(), 1);
    }

    #[test]
    fn protection_metadata_optional_fields() {
        let meta: ProtectionMetadata = serde_json::from_str("{}").unwrap();
        assert!(meta.reason.is_none());
        assert!(meta.protected_by.is_none());
        assert!(meta.protected_at.is_none());
    }

    #[test]
    fn marker_prefers_over_config_pattern_in_reason() {
        let patterns = vec!["/data/projects/*".to_string()];
        let mut reg = ProtectionRegistry::new(Some(&patterns)).unwrap();
        reg.register_marker(Path::new("/data/projects/critical"));

        // Marker should take precedence in reason string.
        let reason = reg
            .protection_reason(Path::new("/data/projects/critical"))
            .unwrap();
        assert!(reason.contains(MARKER_FILENAME));
    }
}
