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
use crate::platform::types::{SacredPath, SacredPathKind, SacredPathSource};

/// Filename placed in directories to protect them from sbh cleanup.
pub const MARKER_FILENAME: &str = ".sbh-protect";
pub const DEFAULT_STOWAWAY_SCAN_DEPTH: usize = 3;

/// Upper bound on directory entries *name-checked* during a single stowaway
/// (sacred-marker containment) sub-walk.
///
/// The containment scan exists only to answer an *existence* question — "does
/// this subtree contain a sacred marker (`*.db`, `.beads/`, `*.db-wal`, …)?".
/// Without a cap, a candidate that is itself a giant artifact tree (a cargo
/// `target/`, an `ntm-go-tmp` test fixture with thousands of `*.db` files, …)
/// forces a full enumeration of up to `max_depth` levels on *every* scan pass —
/// the CPU hot-loop observed on trj.
///
/// This budget is deliberately large because name-checking is now nearly free:
/// entries are matched inline from the `read_dir` iterator using the `d_type`
/// already carried by `DirEntry`, so a checked entry costs no syscall. The
/// syscall-bearing unit of work is *opening* a directory, which is bounded
/// separately by [`DEFAULT_STOWAWAY_SCAN_MAX_DIRS`].
///
/// When this cap is reached before a marker is found, the scan is reported as
/// **truncated**. Truncation is treated as *fail-closed*: the candidate is
/// considered protected (see `find_sacred_overlaps_with_config`). A bounded
/// search must never make a protected subtree look reclaimable.
pub const DEFAULT_STOWAWAY_SCAN_MAX_ENTRIES: usize = 2_000_000;

/// Upper bound on directories *opened* (`read_dir` calls) during a single
/// stowaway sub-walk.
///
/// This is the real cost centre: one `read_dir` per directory, versus a free
/// `d_type` name check per entry. Bounding directories rather than entries is
/// what makes the walk cheap enough to actually finish on artifact trees.
///
/// Sizing: a cargo `target/` at `max_depth` 3 holds a few thousand directories
/// (`debug/.fingerprint/<crate>`, `debug/incremental/<unit>`, `debug/build/…`)
/// against millions of *files*. Budgeting directories lets such a tree complete
/// and be correctly reported marker-free, where an entry budget truncated it
/// and pinned it as protected forever.
pub const DEFAULT_STOWAWAY_SCAN_MAX_DIRS: usize = 50_000;

/// Optional metadata stored inside a `.sbh-protect` file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectionMetadata {
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default, rename = "added_by", alias = "protected_by")]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StowawayScanConfig {
    pub max_depth: usize,
    pub stop_after_first: bool,
    /// Maximum directory entries to name-check before aborting the sub-walk.
    ///
    /// `0` means "unbounded" (historical behavior, used by some tests). The
    /// daemon/CLI paths always set a positive bound. When the bound is reached
    /// before a marker is found, the scan is reported as truncated and the
    /// candidate is treated as protected (fail-closed).
    ///
    /// Name checks are syscall-free (see [`DEFAULT_STOWAWAY_SCAN_MAX_ENTRIES`]);
    /// this is a runaway guard for a pathological single directory, not the
    /// primary throttle. That role belongs to [`Self::max_dirs`].
    pub max_entries: usize,
    /// Maximum directories to open (`read_dir`) before aborting the sub-walk.
    ///
    /// `0` means "unbounded". This is the primary cost throttle: it bounds
    /// syscalls rather than names, so an artifact tree with millions of files
    /// but few directories completes instead of truncating into fail-closed
    /// protection.
    pub max_dirs: usize,
}

impl Default for StowawayScanConfig {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_STOWAWAY_SCAN_DEPTH,
            stop_after_first: true,
            max_entries: DEFAULT_STOWAWAY_SCAN_MAX_ENTRIES,
            max_dirs: DEFAULT_STOWAWAY_SCAN_MAX_DIRS,
        }
    }
}

/// Result of a bounded stowaway sub-walk.
#[derive(Debug, Clone)]
pub struct StowawayScanResult {
    pub matches: Vec<StowawayMatch>,
    /// `true` when the entry budget (`max_entries`) was exhausted before the
    /// subtree was fully examined and no definitive marker had been found.
    /// Callers MUST treat a truncated result as "possibly protected".
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StowawayMatch {
    pub path: PathBuf,
    pub depth: usize,
    pub pattern: String,
    pub kind: SacredPathKind,
    pub source: SacredPathSource,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SacredOverlapKind {
    ExactMatch,
    GlobMatch,
    ChildOfSacred,
    ParentOfSacred,
    ContainsSacred,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SacredOverlap {
    pub candidate_path: PathBuf,
    pub matched_path: PathBuf,
    pub pattern: String,
    pub kind: SacredOverlapKind,
    pub source: SacredPathSource,
    pub reason: String,
}

impl SacredOverlap {
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{}: pattern {} matched {} ({})",
            sacred_overlap_kind_label(self.kind),
            self.pattern,
            self.matched_path.display(),
            self.reason
        )
    }
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
                    let normalized = normalize_protected_pattern_for_matching(pat);
                    let re = glob_to_regex(&normalized)?;
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
                Some(meta) if meta.reason.is_some() => format!(
                    "protected by {} marker: {}",
                    MARKER_FILENAME,
                    meta.reason.as_deref().unwrap_or_default()
                ),
                _ => format!("protected by {MARKER_FILENAME} in {}", marker_dir.display()),
            });
        }

        // Check config patterns.
        for p_str in path_match_texts(path) {
            for pattern in &self.config_patterns {
                if pattern.compiled.is_match(&p_str) {
                    return Some(format!("protected by config pattern: {}", pattern.original));
                }
            }
        }

        None
    }

    /// Walk `root` (non-recursively for each directory level) to discover
    /// `.sbh-protect` marker files. Returns the number of new markers found.
    ///
    /// This performs a depth-first traversal up to `max_depth` levels.
    /// Protected directories are recorded but NOT descended into further
    /// (we already know the entire subtree is protected).
    pub fn discover_markers(&mut self, root: &Path, max_depth: usize) -> Result<usize> {
        let mut found = 0usize;
        let mut queue: Vec<(PathBuf, usize)> = vec![(normalize_path_for_protection(root), 0)];

        while let Some((dir, depth)) = queue.pop() {
            let marker_path = dir.join(MARKER_FILENAME);
            if fs::symlink_metadata(&marker_path).is_ok() {
                let marker_dir = normalize_path_for_protection(&dir);
                if self.marker_paths.insert(marker_dir) {
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

    /// Discover `.sbh-protect` markers in `path` and its ancestors.
    ///
    /// This is a cheap safety check for code paths that evaluate a single
    /// deletion candidate without going through `DirectoryWalker`. It preserves
    /// the same subtree semantics as walker-discovered markers: once an
    /// ancestor has a marker, the candidate and all descendants are protected.
    pub fn discover_ancestor_markers(&mut self, path: &Path) -> Result<usize> {
        let normalized = normalize_path_for_protection(path);
        let mut found = 0usize;

        for ancestor in normalized.ancestors() {
            let marker_path = ancestor.join(MARKER_FILENAME);
            match fs::symlink_metadata(&marker_path) {
                Ok(_) => {
                    if self
                        .marker_paths
                        .insert(normalize_path_for_protection(ancestor))
                    {
                        found += 1;
                    }
                }
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                    return Err(SbhError::PermissionDenied { path: marker_path });
                }
                Err(source) => {
                    return Err(SbhError::Io {
                        path: marker_path,
                        source,
                    });
                }
            }
        }

        Ok(found)
    }

    /// Register a single marker directory (used when walker encounters a marker
    /// during normal traversal, without full discovery).
    pub fn register_marker(&mut self, dir: &Path) -> bool {
        self.marker_paths.insert(normalize_path_for_protection(dir))
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
        let normalized = normalize_path_for_protection(path);

        // Check exact path first.
        if let Some(found) = self.marker_paths.get(&normalized) {
            return Some(found);
        }
        // Walk ancestors.
        let mut current = normalized.parent();
        while let Some(ancestor) = current {
            if let Some(found) = self.marker_paths.get(ancestor) {
                return Some(found);
            }
            current = ancestor.parent();
        }
        None
    }

    fn matches_config_pattern(&self, path: &Path) -> bool {
        if self.config_patterns.is_empty() {
            return false;
        }
        // Check the path itself and all its ancestor prefixes so that
        // a pattern protecting "/data/projects/production-app" also
        // protects "/data/projects/production-app/target/debug".
        for p_str in path_match_texts(path) {
            if self
                .config_patterns
                .iter()
                .any(|pat| pat.compiled.is_match(&p_str))
            {
                return true;
            }
        }
        false
    }
}

/// Create a `.sbh-protect` marker file at the given directory path.
///
/// If `metadata` is provided, writes it as TOML. Otherwise creates an empty file.
pub fn create_marker(dir: &Path, metadata: Option<&ProtectionMetadata>) -> Result<()> {
    let marker_path = normalize_path_for_protection(dir).join(MARKER_FILENAME);
    let content = match metadata {
        Some(meta) => toml::to_string_pretty(meta).map_err(|source| SbhError::Serialization {
            context: "toml",
            details: source.to_string(),
        })?,
        None => String::new(),
    };
    fs::write(&marker_path, content).map_err(|source| SbhError::Io {
        path: marker_path,
        source,
    })
}

/// Remove a `.sbh-protect` marker file from the given directory.
pub fn remove_marker(dir: &Path) -> Result<bool> {
    let marker_path = normalize_path_for_protection(dir).join(MARKER_FILENAME);
    match fs::remove_file(&marker_path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(source) => Err(SbhError::Io {
            path: marker_path,
            source,
        }),
    }
}

pub fn scan_stowaways(root: &Path, catalog: &[SacredPath]) -> Result<Vec<StowawayMatch>> {
    scan_stowaways_with_config(root, catalog, StowawayScanConfig::default())
}

pub fn find_sacred_overlaps(
    candidate: &Path,
    catalog: &[SacredPath],
) -> Result<Vec<SacredOverlap>> {
    find_sacred_overlaps_with_config(candidate, catalog, StowawayScanConfig::default())
}

#[must_use]
pub fn sacred_paths_from_protected_patterns(patterns: &[String]) -> Vec<SacredPath> {
    let mut seen = HashSet::new();
    patterns
        .iter()
        .filter_map(|pattern| {
            let pattern = pattern.trim();
            if pattern.is_empty() || !seen.insert(pattern.to_string()) {
                return None;
            }
            let kind = if contains_glob_metachar(pattern) {
                SacredPathKind::GlobMatch
            } else {
                SacredPathKind::ExactMatch
            };
            Some(SacredPath {
                pattern: pattern.to_string(),
                kind,
                reason: "User-configured protected path must never be reclaimed.".to_string(),
                source: SacredPathSource::UserConfig,
            })
        })
        .collect()
}

pub fn find_sacred_overlaps_with_config(
    candidate: &Path,
    catalog: &[SacredPath],
    stowaway_config: StowawayScanConfig,
) -> Result<Vec<SacredOverlap>> {
    let candidate_path = normalize_path_for_protection(candidate);
    let mut overlaps = Vec::new();

    for entry in catalog {
        overlaps.extend(direct_sacred_overlaps(&candidate_path, entry)?);
    }

    let stowaway = scan_stowaways_bounded(&candidate_path, catalog, stowaway_config)?;
    for matched in stowaway.matches {
        overlaps.push(SacredOverlap {
            candidate_path: candidate_path.clone(),
            matched_path: matched.path,
            pattern: matched.pattern,
            kind: SacredOverlapKind::ContainsSacred,
            source: matched.source,
            reason: matched.reason,
        });
    }

    // FAIL-CLOSED INVARIANT (B4): if the bounded sub-walk could not finish
    // (entry budget exhausted before proving the subtree marker-free), we do
    // NOT know whether a sacred marker lurks deeper. Treat the candidate as
    // protected by synthesizing a `ContainsSacred` overlap. Reporting "no
    // overlaps" here would let the caller delete a possibly-protected tree —
    // exactly the deletion-safety regression a naive bound would introduce.
    if stowaway.truncated {
        let reason = format!(
            "sacred-marker containment scan truncated after {} entries (depth {}); \
             treating subtree as protected (fail-closed)",
            stowaway_config.max_entries, stowaway_config.max_depth
        );
        overlaps.push(SacredOverlap {
            candidate_path: candidate_path.clone(),
            matched_path: candidate_path,
            pattern: "<containment-scan-truncated>".to_string(),
            kind: SacredOverlapKind::ContainsSacred,
            source: SacredPathSource::Builtin,
            reason,
        });
    }

    overlaps.sort_by(|left, right| {
        left.matched_path
            .cmp(&right.matched_path)
            .then_with(|| left.pattern.cmp(&right.pattern))
            .then_with(|| {
                sacred_overlap_kind_label(left.kind).cmp(sacred_overlap_kind_label(right.kind))
            })
    });
    overlaps.dedup_by(|left, right| {
        left.matched_path == right.matched_path
            && left.pattern == right.pattern
            && left.kind == right.kind
            && left.source == right.source
    });

    Ok(overlaps)
}

pub fn scan_stowaways_with_config(
    root: &Path,
    catalog: &[SacredPath],
    config: StowawayScanConfig,
) -> Result<Vec<StowawayMatch>> {
    Ok(scan_stowaways_bounded(root, catalog, config)?.matches)
}

/// Bounded sacred-marker containment sub-walk.
///
/// Walks `root` up to `config.max_depth` levels looking for sacred markers.
/// The walk is bounded three ways over:
///
/// 1. **Depth** — never descends past `config.max_depth` (B4: the old call
///    sites used an effectively-unbounded depth that descended into million-
///    file artifact trees on every pass).
/// 2. **Directory budget** — never opens more than `config.max_dirs`
///    directories (`0` = unbounded). This is the primary throttle.
/// 3. **Entry budget** — never name-checks more than `config.max_entries`
///    entries (`0` = unbounded); a runaway guard for a single pathological
///    directory. When either budget is exhausted before the subtree is fully
///    walked, `truncated` is set.
///
/// COST MODEL: entries are matched *inline* from the `read_dir` iterator using
/// the file type `DirEntry` already carries (`d_type` on Linux/macOS), so a
/// name check costs no syscall and only directories are ever queued. The old
/// implementation pushed every entry onto a stack and re-`lstat`ed it on pop —
/// one syscall per file — which is why a 20k *entry* cap was needed and why
/// every large artifact tree truncated into permanent fail-closed protection.
/// Budgeting directories instead lets those trees finish and be correctly
/// reported marker-free.
///
/// TRAVERSAL ORDER: breadth-first. Sacred markers live shallow (`.git`,
/// `.beads`, `.sbh-protect` at a project root), so BFS both finds them sooner
/// and makes the bound meaningful — a LIFO stack could burn the entire budget
/// descending one `debug/incremental/**` branch without ever examining a
/// sibling at depth 1.
///
/// EARLY-EXIT: with `stop_after_first` (the default), the walk returns as soon
/// as the first marker is found — an existence check needs no full enumeration.
///
/// FAIL-CLOSED INVARIANT: a `truncated` result means "we could not prove the
/// absence of a marker". Callers MUST treat that as *protected*, never as
/// reclaimable. Bounding the search must not weaken deletion safety.
pub fn scan_stowaways_bounded(
    root: &Path,
    catalog: &[SacredPath],
    config: StowawayScanConfig,
) -> Result<StowawayScanResult> {
    let rules = build_stowaway_rules(catalog)?;
    let mut matches = Vec::new();
    let root = normalize_path_for_protection(root);

    let entry_budget = config.max_entries; // 0 == unbounded
    let dir_budget = config.max_dirs; // 0 == unbounded
    let mut entries_examined: usize = 0;
    let mut dirs_opened: usize = 0;

    // Test one entry against every rule, recording a match. Returns `true` when
    // the caller should stop the whole walk (definitive positive under
    // `stop_after_first`).
    let record_match =
        |path: &Path, depth: usize, is_dir: bool, matches: &mut Vec<StowawayMatch>| -> bool {
            let file_name = path
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_default();
            let relative_path = normalized_relative_path(&root, path);
            for rule in &rules {
                if rule.matches(&file_name, &relative_path, is_dir) {
                    matches.push(StowawayMatch {
                        path: path.to_path_buf(),
                        depth,
                        pattern: rule.pattern.clone(),
                        kind: rule.kind,
                        source: rule.source,
                        reason: rule.reason.clone(),
                    });
                    return config.stop_after_first;
                }
            }
            false
        };

    // The root is the one entry we have no `DirEntry` for, so it costs the
    // walk's single unavoidable `lstat`.
    let root_type = match fs::symlink_metadata(&root) {
        Ok(metadata) => metadata.file_type(),
        Err(err)
            if err.kind() == ErrorKind::NotFound || err.kind() == ErrorKind::PermissionDenied =>
        {
            return Ok(StowawayScanResult {
                matches,
                truncated: false,
            });
        }
        Err(source) => return Err(SbhError::Io { path: root, source }),
    };
    entries_examined = entries_examined.saturating_add(1);
    if record_match(&root, 0, root_type.is_dir(), &mut matches) {
        return Ok(StowawayScanResult {
            matches,
            truncated: false,
        });
    }

    // Only directories are queued; files are matched inline below.
    let mut queue = std::collections::VecDeque::new();
    if root_type.is_dir() && !root_type.is_symlink() && config.max_depth > 0 {
        queue.push_back((root.clone(), 0usize));
    }

    while let Some((dir, depth)) = queue.pop_front() {
        // Budget guards. Unexplored work is still queued, so we cannot prove the
        // subtree is marker-free → report truncation and let the caller fail
        // closed.
        if (dir_budget != 0 && dirs_opened >= dir_budget)
            || (entry_budget != 0 && entries_examined >= entry_budget)
        {
            return Ok(StowawayScanResult {
                matches,
                truncated: true,
            });
        }

        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == ErrorKind::NotFound => continue,
            Err(err) if err.kind() == ErrorKind::PermissionDenied => continue,
            Err(source) => return Err(SbhError::Io { path: dir, source }),
        };
        dirs_opened = dirs_opened.saturating_add(1);
        let child_depth = depth + 1;

        for entry_result in entries {
            let Ok(entry) = entry_result else {
                continue;
            };

            // Guard inside the loop too: a single directory can hold millions of
            // entries, and abandoning it mid-iteration is still a truncation.
            if entry_budget != 0 && entries_examined >= entry_budget {
                return Ok(StowawayScanResult {
                    matches,
                    truncated: true,
                });
            }
            entries_examined = entries_examined.saturating_add(1);

            // `DirEntry::file_type` is `d_type` off the already-read directory
            // block on Linux/macOS — no syscall. It only falls back to an
            // `lstat` on filesystems that report DT_UNKNOWN. Like
            // `symlink_metadata`, it does not follow symlinks.
            let (is_dir, is_symlink) = match entry.file_type() {
                Ok(file_type) => (file_type.is_dir(), file_type.is_symlink()),
                Err(_) => match fs::symlink_metadata(entry.path()) {
                    Ok(metadata) => (
                        metadata.file_type().is_dir(),
                        metadata.file_type().is_symlink(),
                    ),
                    Err(_) => continue,
                },
            };

            let path = entry.path();
            if record_match(&path, child_depth, is_dir, &mut matches) {
                return Ok(StowawayScanResult {
                    matches,
                    truncated: false,
                });
            }

            if is_dir && !is_symlink && child_depth < config.max_depth {
                queue.push_back((path, child_depth));
            }
        }
    }

    Ok(StowawayScanResult {
        matches,
        truncated: false,
    })
}

/// Read optional metadata from a `.sbh-protect` marker file.
///
/// Returns `None` if the file is empty, doesn't exist, or isn't valid TOML/JSON.
fn read_marker_metadata(marker_path: &Path) -> Option<ProtectionMetadata> {
    let content = fs::read_to_string(marker_path).ok()?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return None;
    }
    parse_marker_metadata(trimmed)
}

fn parse_marker_metadata(raw: &str) -> Option<ProtectionMetadata> {
    toml::from_str(raw)
        .or_else(|_| serde_json::from_str(raw))
        .ok()
}

/// Validate that a glob pattern can be compiled.
///
/// Returns `Ok(())` if the pattern is valid, or an error describing why it is not.
pub fn validate_glob_pattern(pattern: &str) -> Result<()> {
    glob_to_regex(pattern).map(|_| ())
}

/// Convert a shell-style glob pattern to a regex.
///
/// Supports:
/// - `**` → matches any path (including separators)
/// - `*`  → matches anything except `/`
/// - `?`  → matches a single character except `/`
fn glob_to_regex(pattern: &str) -> Result<Regex> {
    let normalized_pattern = pattern.replace('\\', "/");
    let mut regex_str = String::with_capacity(pattern.len() * 2);
    regex_str.push('^');

    let chars: Vec<char> = normalized_pattern.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            '*' if i + 1 < chars.len() && chars[i + 1] == '*' => {
                if i + 2 < chars.len() && chars[i + 2] == '/' {
                    regex_str.push_str("(?:.*/)?");
                    i += 3;
                } else {
                    regex_str.push_str(".*");
                    i += 2;
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

fn normalize_path_for_matching(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn path_match_texts(path: &Path) -> Vec<String> {
    let mut texts = Vec::new();
    push_text_and_ancestors(&mut texts, normalize_path_for_matching(path));
    push_text_and_ancestors(
        &mut texts,
        normalize_path_for_matching(&normalize_path_for_protection(path)),
    );
    texts
}

fn push_text_and_ancestors(texts: &mut Vec<String>, mut text: String) {
    loop {
        if !text.is_empty() && !texts.contains(&text) {
            texts.push(text.clone());
        }

        let Some(index) = text.rfind('/') else {
            break;
        };
        if index == 0 {
            if !texts.iter().any(|existing| existing == "/") {
                texts.push("/".to_string());
            }
            break;
        }
        text.truncate(index);
    }
}

fn normalize_protected_pattern_for_matching(pattern: &str) -> String {
    let expanded = expand_home_pattern(pattern);
    let normalized = expanded.replace('\\', "/");
    let path = Path::new(&normalized);
    if !path.is_absolute() {
        return normalized;
    }

    if !contains_glob_metachar(&normalized) {
        return normalize_path_for_matching(&normalize_path_for_protection(path));
    }

    let Some(prefix) = literal_glob_prefix_path(&normalized) else {
        return normalized;
    };
    let prefix_text = normalize_path_for_matching(&prefix);
    let Some(suffix) = normalized.strip_prefix(&prefix_text) else {
        return normalized;
    };
    let resolved_prefix = normalize_path_for_matching(&normalize_path_for_protection(&prefix));
    format!("{resolved_prefix}{suffix}")
}

fn normalize_path_for_protection(path: &Path) -> PathBuf {
    crate::core::paths::resolve_absolute_path(path)
}

fn direct_sacred_overlaps(candidate: &Path, entry: &SacredPath) -> Result<Vec<SacredOverlap>> {
    match entry.kind {
        SacredPathKind::ExactMatch => Ok(exact_sacred_overlaps(candidate, entry)),
        SacredPathKind::GlobMatch => glob_sacred_overlaps(candidate, entry),
        SacredPathKind::ContainsAny | SacredPathKind::StowawayMarker => Ok(Vec::new()),
    }
}

fn exact_sacred_overlaps(candidate: &Path, entry: &SacredPath) -> Vec<SacredOverlap> {
    let sacred_path =
        normalize_path_for_protection(&PathBuf::from(expand_home_pattern(&entry.pattern)));
    path_overlap_kind(candidate, &sacred_path).map_or_else(Vec::new, |kind| {
        vec![SacredOverlap {
            candidate_path: candidate.to_path_buf(),
            matched_path: sacred_path,
            pattern: entry.pattern.clone(),
            kind,
            source: entry.source,
            reason: entry.reason.clone(),
        }]
    })
}

fn glob_sacred_overlaps(candidate: &Path, entry: &SacredPath) -> Result<Vec<SacredOverlap>> {
    let normalized = normalize_protected_pattern_for_matching(&entry.pattern);
    let regex = glob_to_regex(&normalized)?;
    let candidate_text = normalize_path_for_matching(candidate);
    let mut overlaps = Vec::new();

    if regex.is_match(&candidate_text) {
        overlaps.push(SacredOverlap {
            candidate_path: candidate.to_path_buf(),
            matched_path: candidate.to_path_buf(),
            pattern: entry.pattern.clone(),
            kind: SacredOverlapKind::GlobMatch,
            source: entry.source,
            reason: entry.reason.clone(),
        });
    }

    let mut ancestor = candidate.parent();
    while let Some(path) = ancestor {
        if regex.is_match(&normalize_path_for_matching(path)) {
            overlaps.push(SacredOverlap {
                candidate_path: candidate.to_path_buf(),
                matched_path: path.to_path_buf(),
                pattern: entry.pattern.clone(),
                kind: SacredOverlapKind::ChildOfSacred,
                source: entry.source,
                reason: entry.reason.clone(),
            });
            break;
        }
        ancestor = path.parent();
    }

    if let Some(prefix) = literal_glob_prefix_path(&normalized) {
        let sacred_parent = normalize_path_for_protection(&prefix);
        if sacred_parent.starts_with(candidate) {
            overlaps.push(SacredOverlap {
                candidate_path: candidate.to_path_buf(),
                matched_path: sacred_parent,
                pattern: entry.pattern.clone(),
                kind: SacredOverlapKind::ParentOfSacred,
                source: entry.source,
                reason: entry.reason.clone(),
            });
        }
    }

    Ok(overlaps)
}

fn path_overlap_kind(candidate: &Path, sacred_path: &Path) -> Option<SacredOverlapKind> {
    if candidate == sacred_path {
        Some(SacredOverlapKind::ExactMatch)
    } else if candidate.starts_with(sacred_path) {
        Some(SacredOverlapKind::ChildOfSacred)
    } else if sacred_path.starts_with(candidate) {
        Some(SacredOverlapKind::ParentOfSacred)
    } else {
        None
    }
}

fn expand_home_pattern(pattern: &str) -> String {
    let Some(home) = std::env::var_os("HOME") else {
        return pattern.to_string();
    };
    let home = PathBuf::from(home).to_string_lossy().replace('\\', "/");
    if pattern == "~" {
        home
    } else if let Some(rest) = pattern.strip_prefix("~/") {
        format!("{home}/{rest}")
    } else {
        pattern.to_string()
    }
}

fn literal_glob_prefix_path(pattern: &str) -> Option<PathBuf> {
    let glob_index = pattern.find(['*', '?'])?;
    let prefix = &pattern[..glob_index];
    let parent = prefix.rsplit_once('/').map_or("", |(parent, _)| parent);
    if parent.is_empty() {
        None
    } else {
        Some(PathBuf::from(parent))
    }
}

fn sacred_overlap_kind_label(kind: SacredOverlapKind) -> &'static str {
    match kind {
        SacredOverlapKind::ExactMatch => "exact sacred path",
        SacredOverlapKind::GlobMatch => "sacred glob match",
        SacredOverlapKind::ChildOfSacred => "inside sacred path",
        SacredOverlapKind::ParentOfSacred => "contains sacred path",
        SacredOverlapKind::ContainsSacred => "contains sacred marker",
    }
}

#[derive(Debug)]
struct StowawayRule {
    pattern: String,
    kind: SacredPathKind,
    source: SacredPathSource,
    reason: String,
    matcher: StowawayMatcher,
}

#[derive(Debug)]
enum StowawayMatcher {
    ContainsDirName(String),
    ContainsRelativePath(String),
    ExactName(String),
    GlobPath(Regex),
}

impl StowawayRule {
    fn matches(&self, file_name: &str, relative_path: &str, is_dir: bool) -> bool {
        match &self.matcher {
            StowawayMatcher::ContainsDirName(name) => is_dir && file_name == name,
            StowawayMatcher::ContainsRelativePath(path) => {
                is_dir && path_suffix_matches(relative_path, path)
            }
            StowawayMatcher::ExactName(name) => {
                file_name == name || path_suffix_matches(relative_path, name)
            }
            StowawayMatcher::GlobPath(regex) => {
                regex.is_match(file_name) || regex.is_match(relative_path)
            }
        }
    }
}

fn build_stowaway_rules(catalog: &[SacredPath]) -> Result<Vec<StowawayRule>> {
    let mut rules = catalog
        .iter()
        .filter_map(stowaway_rule_from_sacred_path)
        .collect::<Result<Vec<_>>>()?;
    rules.push(StowawayRule {
        pattern: MARKER_FILENAME.to_string(),
        kind: SacredPathKind::StowawayMarker,
        source: SacredPathSource::Marker,
        reason: "Protection marker present inside cleanup candidate.".to_string(),
        matcher: StowawayMatcher::ExactName(MARKER_FILENAME.to_string()),
    });
    Ok(rules)
}

fn stowaway_rule_from_sacred_path(entry: &SacredPath) -> Option<Result<StowawayRule>> {
    let pattern = normalized_sacred_pattern(&entry.pattern);
    let matcher = match entry.kind {
        SacredPathKind::ContainsAny if pattern.contains('/') => {
            StowawayMatcher::ContainsRelativePath(pattern)
        }
        SacredPathKind::ContainsAny => StowawayMatcher::ContainsDirName(pattern),
        SacredPathKind::StowawayMarker if contains_glob_metachar(&pattern) => {
            match glob_to_regex(&pattern) {
                Ok(regex) => StowawayMatcher::GlobPath(regex),
                Err(error) => return Some(Err(error)),
            }
        }
        SacredPathKind::StowawayMarker => StowawayMatcher::ExactName(pattern),
        SacredPathKind::ExactMatch | SacredPathKind::GlobMatch => return None,
    };

    Some(Ok(StowawayRule {
        pattern: entry.pattern.clone(),
        kind: entry.kind,
        source: entry.source,
        reason: entry.reason.clone(),
        matcher,
    }))
}

fn normalized_sacred_pattern(pattern: &str) -> String {
    pattern.replace('\\', "/").trim_end_matches('/').to_string()
}

fn contains_glob_metachar(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?')
}

fn normalized_relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .ok()
        .map(normalize_path_for_matching)
        .filter(|path| !path.is_empty())
        .unwrap_or_default()
}

fn path_suffix_matches(path: &str, suffix: &str) -> bool {
    path == suffix || path.ends_with(&format!("/{suffix}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::sacred_catalog::cross_platform_sacred_paths;
    use crate::platform::types::{SacredPath, SacredPathKind, SacredPathSource};
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
        assert!(reg.is_protected(Path::new("/data/projects/critical-app/target/debug/build")));
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
        assert!(
            reg.protection_reason(Path::new("/data/projects/foo"))
                .is_none()
        );
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
        assert!(content.contains("reason = \"Production build - 6 hour compile\""));
        assert!(content.contains("added_by = \"jeff\""));
        let parsed: ProtectionMetadata = toml::from_str(&content).unwrap();
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
    fn ancestor_marker_discovery_protects_direct_candidate_checks() {
        let tmp = TempDir::new().unwrap();
        let protected = tmp.path().join("repo").join("tools");
        let candidate = protected.join("rust_fuzz_target");
        fs::create_dir_all(&candidate).unwrap();
        create_marker(&protected, None).unwrap();

        let mut reg = ProtectionRegistry::marker_only();
        assert_eq!(reg.marker_count(), 0);
        assert!(!reg.is_protected(&candidate));

        let discovered = reg.discover_ancestor_markers(&candidate).unwrap();

        assert_eq!(discovered, 1);
        assert!(reg.is_protected(&candidate));
        assert!(
            reg.protection_reason(&candidate)
                .unwrap()
                .contains(MARKER_FILENAME)
        );
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
        assert!(
            sources
                .iter()
                .any(|s| matches!(s, ProtectionSource::MarkerFile))
        );
        assert!(
            sources
                .iter()
                .any(|s| matches!(s, ProtectionSource::ConfigPattern(_)))
        );
    }

    #[test]
    fn glob_star_matches_within_component() {
        let patterns = vec!["/tmp/cargo-target-*".to_string()];
        let reg = ProtectionRegistry::new(Some(&patterns)).unwrap();

        assert!(reg.is_protected(Path::new("/tmp/cargo-target-abc")));
        assert!(reg.is_protected(Path::new("/tmp/cargo-target-xyz123")));
        // Subtree protection: children of a matched pattern are also protected.
        assert!(reg.is_protected(Path::new("/tmp/cargo-target-abc/sub")));
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
    fn glob_matches_windows_style_paths_after_normalization() {
        let patterns = vec![r"C:\Users\*\critical-builds".to_string()];
        let reg = ProtectionRegistry::new(Some(&patterns)).unwrap();

        assert!(reg.is_protected(Path::new(r"C:\Users\alice\critical-builds")));
        assert!(!reg.is_protected(Path::new(r"C:\Users\alice\other-builds")));
    }

    #[test]
    fn marker_file_with_json_metadata_is_read() {
        let tmp = TempDir::new().unwrap();
        let marker = tmp.path().join(MARKER_FILENAME);
        fs::write(
            &marker,
            r#"{
  "reason": "Critical production build",
  "protected_by": "admin"
}"#,
        )
        .unwrap();

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
        assert_eq!(
            entry.metadata.as_ref().unwrap().protected_by,
            Some("admin".to_string())
        );
    }

    #[test]
    fn marker_file_with_toml_metadata_is_read() {
        let tmp = TempDir::new().unwrap();
        let marker = tmp.path().join(MARKER_FILENAME);
        fs::write(
            &marker,
            r#"
reason = "year-end backup"
added_by = "jemanuel"
protected_at = "2026-05-07T03:50:00Z"
"#,
        )
        .unwrap();

        let mut reg = ProtectionRegistry::marker_only();
        reg.discover_markers(tmp.path(), 1).unwrap();

        let entries = reg.list_protections();
        assert_eq!(entries.len(), 1);
        let metadata = entries[0].metadata.as_ref().unwrap();
        assert_eq!(metadata.reason.as_deref(), Some("year-end backup"));
        assert_eq!(metadata.protected_by.as_deref(), Some("jemanuel"));
        assert_eq!(
            metadata.protected_at.as_deref(),
            Some("2026-05-07T03:50:00Z")
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
    fn protected_patterns_become_user_config_sacred_paths() {
        let tmp = TempDir::new().unwrap();
        let protected = tmp.path().join("critical");
        let glob_parent = tmp.path().join("Pictures");
        let glob = glob_parent
            .join("*.photoslibrary")
            .to_string_lossy()
            .to_string();
        let patterns = vec![
            protected.to_string_lossy().to_string(),
            glob,
            protected.to_string_lossy().to_string(),
        ];

        let catalog = sacred_paths_from_protected_patterns(&patterns);

        assert_eq!(catalog.len(), 2);
        assert_eq!(catalog[0].kind, SacredPathKind::ExactMatch);
        assert_eq!(catalog[0].source, SacredPathSource::UserConfig);
        assert_eq!(catalog[1].kind, SacredPathKind::GlobMatch);

        let parent_overlap = find_sacred_overlaps(tmp.path(), &catalog).unwrap();
        assert!(parent_overlap.iter().any(|overlap| {
            overlap.kind == SacredOverlapKind::ParentOfSacred
                && overlap.source == SacredPathSource::UserConfig
        }));

        let child_overlap =
            find_sacred_overlaps(&glob_parent.join("Family.photoslibrary/database"), &catalog)
                .unwrap();
        assert!(
            child_overlap
                .iter()
                .any(|overlap| overlap.kind == SacredOverlapKind::ChildOfSacred)
        );
    }

    #[cfg(unix)]
    #[test]
    fn protected_patterns_match_through_existing_parent_aliases() {
        let tmp = TempDir::new().unwrap();
        let real = tmp.path().join("real");
        fs::create_dir(&real).unwrap();
        let alias = tmp.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();

        let patterns = vec![alias.join("critical").to_string_lossy().to_string()];
        let reg = ProtectionRegistry::new(Some(&patterns)).unwrap();

        assert!(reg.is_protected(&real.join("critical")));
        assert!(reg.is_protected(&real.join("critical").join("target")));
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

        let meta: ProtectionMetadata = toml::from_str("").unwrap();
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

    #[cfg(unix)]
    #[test]
    fn register_marker_canonicalizes_symlink_aliases() {
        let tmp = TempDir::new().unwrap();
        let real = tmp.path().join("real");
        let alias = tmp.path().join("alias");
        fs::create_dir_all(real.join("nested")).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();

        let mut reg = ProtectionRegistry::marker_only();
        reg.register_marker(&alias);

        assert!(reg.is_protected(&real));
        assert!(reg.is_protected(&real.join("nested")));
        assert!(reg.is_protected(&alias.join("nested")));
    }

    #[cfg(unix)]
    #[test]
    fn remove_marker_resolves_symlink_aliases() {
        let tmp = TempDir::new().unwrap();
        let real = tmp.path().join("real");
        let alias = tmp.path().join("alias");
        fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();

        create_marker(&real, None).unwrap();
        assert!(real.join(MARKER_FILENAME).exists());

        let removed = remove_marker(&alias).unwrap();
        assert!(removed);
        assert!(!real.join(MARKER_FILENAME).exists());
    }

    #[test]
    fn scan_stowaways_finds_cross_platform_markers() {
        let tmp = TempDir::new().unwrap();
        let candidate = tmp.path().join("old-trash");
        fs::create_dir_all(candidate.join("nested").join(".beads")).unwrap();
        fs::write(
            candidate.join("nested").join(".beads").join("beads.db"),
            b"db",
        )
        .unwrap();
        fs::write(candidate.join("state.sqlite3"), b"sqlite").unwrap();

        let matches = scan_stowaways_with_config(
            &candidate,
            cross_platform_sacred_paths(),
            StowawayScanConfig {
                max_depth: 3,
                stop_after_first: false,
                max_entries: DEFAULT_STOWAWAY_SCAN_MAX_ENTRIES,
                max_dirs: DEFAULT_STOWAWAY_SCAN_MAX_DIRS,
            },
        )
        .unwrap();
        let patterns = matches
            .iter()
            .map(|matched| matched.pattern.as_str())
            .collect::<HashSet<_>>();

        assert!(patterns.contains(".beads/"));
        assert!(patterns.contains("beads.db"));
        assert!(patterns.contains("*.sqlite3"));
    }

    #[test]
    fn scan_stowaways_short_circuits_by_default() {
        let tmp = TempDir::new().unwrap();
        let candidate = tmp.path().join("cache");
        fs::create_dir_all(candidate.join(".git")).unwrap();
        fs::write(candidate.join("state.sqlite3"), b"sqlite").unwrap();

        let matches = scan_stowaways(&candidate, cross_platform_sacred_paths()).unwrap();

        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn bounded_scan_truncates_when_entry_budget_exhausted() {
        // Build a flat dir with many marker-free entries. With a tiny entry
        // budget the walk must report truncation rather than walking it all.
        let tmp = TempDir::new().unwrap();
        let candidate = tmp.path().join("huge");
        fs::create_dir_all(&candidate).unwrap();
        for i in 0..50 {
            fs::write(candidate.join(format!("file_{i}.txt")), b"x").unwrap();
        }

        let result = scan_stowaways_bounded(
            &candidate,
            cross_platform_sacred_paths(),
            StowawayScanConfig {
                max_depth: 3,
                stop_after_first: true,
                max_entries: 5,
                max_dirs: DEFAULT_STOWAWAY_SCAN_MAX_DIRS,
            },
        )
        .unwrap();

        assert!(
            result.truncated,
            "small entry budget over a large dir must truncate"
        );
        assert!(
            result.matches.is_empty(),
            "no markers present, so no definitive matches"
        );
    }

    /// REGRESSION (2026-07-24, hz2): a wide artifact tree — millions of files
    /// but few directories — must complete and be reported *reclaimable*.
    ///
    /// The legacy 20_000-*entry* budget truncated exactly the trees most worth
    /// reclaiming: a 223G cargo `target/` on hz2 blew the cap, failed closed,
    /// and became permanently un-reclaimable while the host filled to 100%.
    /// Budgeting directories instead of entries is what fixes it.
    #[test]
    fn wide_artifact_tree_past_legacy_entry_cap_stays_reclaimable() {
        const LEGACY_ENTRY_CAP: usize = 20_000;

        let tmp = TempDir::new().unwrap();
        let candidate = tmp.path().join("cargo-target");
        // Shape mirrors a real cargo target: a handful of directories holding a
        // very large number of marker-free files.
        let deps = candidate.join("debug").join("deps");
        fs::create_dir_all(&deps).unwrap();
        for i in 0..(LEGACY_ENTRY_CAP + 500) {
            fs::write(deps.join(format!("dep_{i}.o")), b"").unwrap();
        }

        let result = scan_stowaways_bounded(
            &candidate,
            cross_platform_sacred_paths(),
            StowawayScanConfig::default(),
        )
        .unwrap();

        assert!(
            !result.truncated,
            "a wide, marker-free artifact tree must not truncate under the default \
             budget — truncation pins it as protected forever"
        );
        assert!(result.matches.is_empty(), "no sacred markers were planted");

        // The whole point: it must read as reclaimable, not fail-closed.
        let overlaps = find_sacred_overlaps_with_config(
            &candidate,
            cross_platform_sacred_paths(),
            StowawayScanConfig::default(),
        )
        .unwrap();
        assert!(
            overlaps.is_empty(),
            "marker-free artifact tree must report no sacred overlap, got: {overlaps:?}"
        );
    }

    /// Entries are matched inline from the `read_dir` iterator, so a marker
    /// sitting directly in the candidate is found without opening a single
    /// subdirectory — even when the directory budget allows only the root.
    #[test]
    fn shallow_marker_is_found_without_descending() {
        let tmp = TempDir::new().unwrap();
        let candidate = tmp.path().join("project");
        // A bulky sibling subtree that a depth-first walk could dive into first.
        let bulk = candidate.join("bulk");
        fs::create_dir_all(&bulk).unwrap();
        for i in 0..200 {
            fs::write(bulk.join(format!("obj_{i}.o")), b"").unwrap();
        }
        fs::write(candidate.join("beads.db"), b"db").unwrap();

        let result = scan_stowaways_bounded(
            &candidate,
            cross_platform_sacred_paths(),
            StowawayScanConfig {
                max_depth: 3,
                stop_after_first: true,
                max_entries: DEFAULT_STOWAWAY_SCAN_MAX_ENTRIES,
                // Only the candidate itself may be opened.
                max_dirs: 1,
            },
        )
        .unwrap();

        assert!(
            !result.truncated,
            "finding a marker is a definitive answer, never a truncation"
        );
        assert_eq!(result.matches.len(), 1, "expected the shallow marker");
    }

    /// The directory budget is the throttle that can still truncate: a tree
    /// that is *deep and branchy* (rather than merely wide) exhausts it and
    /// must fail closed, preserving the safety invariant.
    #[test]
    fn directory_budget_still_truncates_branchy_trees() {
        let tmp = TempDir::new().unwrap();
        let candidate = tmp.path().join("branchy");
        for i in 0..40 {
            fs::create_dir_all(candidate.join(format!("d_{i}")).join("nested")).unwrap();
        }

        let result = scan_stowaways_bounded(
            &candidate,
            cross_platform_sacred_paths(),
            StowawayScanConfig {
                max_depth: 3,
                stop_after_first: true,
                max_entries: DEFAULT_STOWAWAY_SCAN_MAX_ENTRIES,
                max_dirs: 5,
            },
        )
        .unwrap();

        assert!(
            result.truncated,
            "exhausting the directory budget must still fail closed"
        );
    }

    #[test]
    fn truncated_containment_scan_fails_closed_to_protected() {
        // FAIL-CLOSED INVARIANT (B4): a deep marker that the bound never reaches
        // must NOT make the candidate look reclaimable. find_sacred_overlaps
        // must report an overlap (protected) when the sub-walk is truncated.
        let tmp = TempDir::new().unwrap();
        let candidate = tmp.path().join("artifact");
        fs::create_dir_all(&candidate).unwrap();
        // Many marker-free entries so a small budget is exhausted first.
        for i in 0..50 {
            fs::write(candidate.join(format!("obj_{i}.o")), b"x").unwrap();
        }
        // A real sacred marker exists, but the tiny budget will truncate before
        // necessarily reaching it. Either way the result must be "protected".
        fs::write(candidate.join("beads.db"), b"db").unwrap();

        let overlaps = find_sacred_overlaps_with_config(
            &candidate,
            cross_platform_sacred_paths(),
            StowawayScanConfig {
                max_depth: 3,
                stop_after_first: true,
                max_entries: 3,
                max_dirs: DEFAULT_STOWAWAY_SCAN_MAX_DIRS,
            },
        )
        .unwrap();

        assert!(
            !overlaps.is_empty(),
            "truncated containment scan must fail closed (treat as protected)"
        );
    }

    #[test]
    fn bounded_scan_does_not_truncate_when_marker_found_within_budget() {
        // Finding a marker within budget is a *definitive* answer, never a
        // truncation. The candidate dir holds only the marker file, so a small
        // budget (root + marker = 2 entries) still reaches it.
        let tmp = TempDir::new().unwrap();
        let candidate = tmp.path().join("cache");
        fs::create_dir_all(&candidate).unwrap();
        fs::write(candidate.join("state.sqlite3"), b"sqlite").unwrap();

        let result = scan_stowaways_bounded(
            &candidate,
            cross_platform_sacred_paths(),
            StowawayScanConfig {
                max_depth: 3,
                stop_after_first: true,
                max_entries: 8,
                max_dirs: DEFAULT_STOWAWAY_SCAN_MAX_DIRS,
            },
        )
        .unwrap();

        assert!(!result.truncated);
        assert_eq!(result.matches.len(), 1);
    }

    #[test]
    fn bounded_scan_clean_small_tree_is_not_truncated() {
        // A small, fully-walkable, marker-free tree is a definitive negative.
        let tmp = TempDir::new().unwrap();
        let candidate = tmp.path().join("clean");
        fs::create_dir_all(candidate.join("sub")).unwrap();
        fs::write(candidate.join("a.txt"), b"x").unwrap();
        fs::write(candidate.join("sub").join("b.txt"), b"x").unwrap();

        let result = scan_stowaways_bounded(
            &candidate,
            cross_platform_sacred_paths(),
            StowawayScanConfig::default(),
        )
        .unwrap();

        assert!(!result.truncated);
        assert!(result.matches.is_empty());
    }

    #[test]
    fn scan_stowaways_respects_max_depth() {
        let tmp = TempDir::new().unwrap();
        let candidate = tmp.path().join("cache");
        let deep = candidate.join("a").join("b").join("c").join("d");
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("beads.db"), b"db").unwrap();

        let shallow = scan_stowaways_with_config(
            &candidate,
            cross_platform_sacred_paths(),
            StowawayScanConfig {
                max_depth: 3,
                stop_after_first: false,
                max_entries: DEFAULT_STOWAWAY_SCAN_MAX_ENTRIES,
                max_dirs: DEFAULT_STOWAWAY_SCAN_MAX_DIRS,
            },
        )
        .unwrap();
        assert!(shallow.is_empty());

        let deep = scan_stowaways_with_config(
            &candidate,
            cross_platform_sacred_paths(),
            StowawayScanConfig {
                max_depth: 5,
                stop_after_first: false,
                max_entries: DEFAULT_STOWAWAY_SCAN_MAX_ENTRIES,
                max_dirs: DEFAULT_STOWAWAY_SCAN_MAX_DIRS,
            },
        )
        .unwrap();
        assert_eq!(deep.len(), 1);
        assert_eq!(deep[0].pattern, "beads.db");
    }

    #[test]
    fn scan_stowaways_detects_protection_marker_without_catalog_entry() {
        let tmp = TempDir::new().unwrap();
        let candidate = tmp.path().join("cache");
        fs::create_dir_all(&candidate).unwrap();
        create_marker(&candidate, None).unwrap();

        let matches = scan_stowaways_with_config(
            &candidate,
            &[],
            StowawayScanConfig {
                max_depth: 1,
                stop_after_first: false,
                max_entries: DEFAULT_STOWAWAY_SCAN_MAX_ENTRIES,
                max_dirs: DEFAULT_STOWAWAY_SCAN_MAX_DIRS,
            },
        )
        .unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern, MARKER_FILENAME);
        assert_eq!(matches[0].source, SacredPathSource::Marker);
    }

    #[cfg(unix)]
    #[test]
    fn scan_stowaways_does_not_follow_symlinks() {
        let tmp = TempDir::new().unwrap();
        let candidate = tmp.path().join("cache");
        let outside = tmp.path().join("outside");
        fs::create_dir_all(outside.join(".git")).unwrap();
        fs::create_dir_all(&candidate).unwrap();
        std::os::unix::fs::symlink(&outside, candidate.join("linked-outside")).unwrap();

        let matches = scan_stowaways_with_config(
            &candidate,
            cross_platform_sacred_paths(),
            StowawayScanConfig {
                max_depth: 3,
                stop_after_first: false,
                max_entries: DEFAULT_STOWAWAY_SCAN_MAX_ENTRIES,
                max_dirs: DEFAULT_STOWAWAY_SCAN_MAX_DIRS,
            },
        )
        .unwrap();

        assert!(matches.is_empty());
    }

    #[test]
    fn sacred_overlaps_cover_exact_parent_and_child_relationships() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join("Users").join("operator");
        let sacred = home.join("Library").join("Messages");
        fs::create_dir_all(sacred.join("Archive")).unwrap();
        let catalog = vec![SacredPath {
            pattern: sacred.to_string_lossy().to_string(),
            kind: SacredPathKind::ExactMatch,
            reason: "Messages history is user data".to_string(),
            source: SacredPathSource::Builtin,
        }];

        let exact = find_sacred_overlaps(&sacred, &catalog).unwrap();
        assert_eq!(exact[0].kind, SacredOverlapKind::ExactMatch);

        let child = find_sacred_overlaps(&sacred.join("Archive"), &catalog).unwrap();
        assert_eq!(child[0].kind, SacredOverlapKind::ChildOfSacred);

        let parent = find_sacred_overlaps(&home, &catalog).unwrap();
        assert_eq!(parent[0].kind, SacredOverlapKind::ParentOfSacred);
    }

    #[test]
    fn sacred_overlaps_cover_glob_match_child_and_parent_relationships() {
        let tmp = TempDir::new().unwrap();
        let pictures = tmp.path().join("Pictures");
        let library = pictures.join("Family.photoslibrary");
        let database = library.join("database").join("Photos.sqlite");
        fs::create_dir_all(database.parent().unwrap()).unwrap();
        fs::write(&database, b"sqlite").unwrap();
        let catalog = vec![SacredPath {
            pattern: pictures
                .join("*.photoslibrary")
                .to_string_lossy()
                .to_string(),
            kind: SacredPathKind::GlobMatch,
            reason: "Photos libraries are user data".to_string(),
            source: SacredPathSource::Builtin,
        }];

        let exact = find_sacred_overlaps(&library, &catalog).unwrap();
        assert_eq!(exact[0].kind, SacredOverlapKind::GlobMatch);

        let child = find_sacred_overlaps(&database, &catalog).unwrap();
        assert_eq!(child[0].kind, SacredOverlapKind::ChildOfSacred);

        let parent = find_sacred_overlaps(&pictures, &catalog).unwrap();
        assert_eq!(parent[0].kind, SacredOverlapKind::ParentOfSacred);
    }

    #[cfg(unix)]
    #[test]
    fn sacred_glob_overlaps_match_through_existing_parent_aliases() {
        let tmp = TempDir::new().unwrap();
        let real = tmp.path().join("real");
        fs::create_dir(&real).unwrap();
        let alias = tmp.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();

        let pictures = real.join("Pictures");
        let library = pictures.join("Family.photoslibrary");
        let database = library.join("database").join("Photos.sqlite");
        fs::create_dir_all(database.parent().unwrap()).unwrap();
        fs::write(&database, b"sqlite").unwrap();
        let catalog = vec![SacredPath {
            pattern: alias
                .join("Pictures")
                .join("*.photoslibrary")
                .to_string_lossy()
                .to_string(),
            kind: SacredPathKind::GlobMatch,
            reason: "Photos libraries are user data".to_string(),
            source: SacredPathSource::Builtin,
        }];

        let exact = find_sacred_overlaps(&library, &catalog).unwrap();
        assert_eq!(exact[0].kind, SacredOverlapKind::GlobMatch);

        let child = find_sacred_overlaps(&database, &catalog).unwrap();
        assert_eq!(child[0].kind, SacredOverlapKind::ChildOfSacred);

        let parent = find_sacred_overlaps(&pictures, &catalog).unwrap();
        assert_eq!(parent[0].kind, SacredOverlapKind::ParentOfSacred);
    }

    #[test]
    fn sacred_overlaps_include_stowaway_matches() {
        let tmp = TempDir::new().unwrap();
        let candidate = tmp.path().join("old-cache");
        fs::create_dir_all(candidate.join("nested").join(".beads")).unwrap();

        let overlaps = find_sacred_overlaps(&candidate, cross_platform_sacred_paths()).unwrap();

        assert_eq!(overlaps.len(), 1);
        assert_eq!(overlaps[0].kind, SacredOverlapKind::ContainsSacred);
        assert_eq!(overlaps[0].pattern, ".beads/");
    }

    #[test]
    fn absolute_root_guards_fire_independent_of_home() {
        let catalog = cross_platform_sacred_paths();

        // Sensitive root dirs (and their descendants) are sacred-vetoed by the
        // absolute /root guards, so even the loosened /root is_system_path can
        // never expose them.
        for path in [
            "/root/.ssh",
            "/root/.ssh/id_ed25519",
            "/root/.gnupg",
            "/root/.rustup",
            "/root/.rustup/toolchains/nightly/bin/rustc",
            "/root/.config",
            "/root/.local",
            "/root/.local/bin/rch",
            "/root/.cargo/config.toml",
            "/root/.cargo/credentials.toml",
        ] {
            let overlaps = find_sacred_overlaps(Path::new(path), catalog).unwrap();
            assert!(
                !overlaps.is_empty(),
                "{path} must be protected by an absolute sacred guard"
            );
            assert_eq!(overlaps[0].source, SacredPathSource::Builtin);
        }

        // The backstop's target: a stranded target dir under /root is NOT
        // sacred-protected, so the loosened is_system_path can reclaim it.
        assert!(
            find_sacred_overlaps(Path::new("/root/cass-ft-target"), catalog)
                .unwrap()
                .is_empty(),
            "the reclaimable /root target must not be sacred-protected"
        );

        // Surgical .cargo: the regenerable registry/git caches (classified
        // opaque-cargo-cache) stay reclaimable — only config/credentials are
        // guarded.
        for path in ["/root/.cargo/registry", "/root/.cargo/git"] {
            assert!(
                find_sacred_overlaps(Path::new(path), catalog)
                    .unwrap()
                    .is_empty(),
                "{path} (opaque-cargo-cache) must stay reclaimable"
            );
        }

        // HOME-independence is structural: the guards are ABSOLUTE patterns, so
        // `expand_home_pattern` returns them verbatim for ANY $HOME (it only
        // rewrites `~` / `~/`-prefixed patterns). This is why they hold for a
        // systemd *system* service where $HOME may not be /root.
        for pat in ["/root/.ssh", "/root/.rustup", "/root/.cargo/config.toml"] {
            assert!(pat.starts_with('/'));
            assert_eq!(expand_home_pattern(pat), pat);
        }
    }
}
