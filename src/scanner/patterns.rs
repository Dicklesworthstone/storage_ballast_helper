//! Artifact pattern registry: regex-based name matching with structural marker verification.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::borrow::Cow;
use std::path::Path;

use crate::platform::cleanup_catalog::{self, CleanupConfidence, CleanupRule, ReclaimCommand};

/// High-level artifact category used by the scorer and CLI reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactCategory {
    RustTarget,
    NodeModules,
    PythonCache,
    BuildOutput,
    CacheDir,
    /// Go toolchain caches: `GOCACHE` build cache and `GOMODCACHE` module
    /// cache. Detected structurally (name-independent) and removed with
    /// permission-defeating deletion because the Go tool writes every cache
    /// directory `0555` and every cache file `0444`, which defeats a plain
    /// `remove_dir_all`.
    GoCache,
    TempDir,
    AgentWorkspace,
    Unknown,
}

impl ArtifactCategory {
    /// Categories whose members are directory trees that tools regenerate,
    /// where "age" must mean idleness of the whole tree (a compiler writes to
    /// `target/debug/deps/`, not to `target/`). The scanner takes a bounded
    /// idle probe for these before scoring; `Unknown` directories keep the
    /// cheap directory-level timestamps.
    #[must_use]
    pub const fn is_regenerable_tree(self) -> bool {
        !matches!(self, Self::Unknown)
    }

    /// Every category, in declaration order; the decision ledger stores the
    /// `Debug` name, and [`std::str::FromStr`] maps it back.
    pub const ALL: [Self; 9] = [
        Self::RustTarget,
        Self::NodeModules,
        Self::PythonCache,
        Self::BuildOutput,
        Self::CacheDir,
        Self::GoCache,
        Self::TempDir,
        Self::AgentWorkspace,
        Self::Unknown,
    ];
}

impl std::str::FromStr for ArtifactCategory {
    type Err = String;

    /// Parse the `Debug` name a decision record stores (`"RustTarget"`).
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|category| format!("{category:?}") == name)
            .ok_or_else(|| format!("unknown artifact category {name:?}"))
    }
}

/// Structural features collected from a directory tree.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StructuralSignals {
    pub has_incremental: bool,
    pub has_deps: bool,
    pub has_build: bool,
    pub has_fingerprint: bool,
    pub has_git: bool,
    pub has_cargo_toml: bool,
    pub mostly_object_files: bool,
    /// A validated `CACHEDIR.TAG` file (per the Cache Directory Tagging
    /// Standard, <https://bford.info/cachedir/>) sits at this directory's root.
    /// Cargo, restic, borg, and many other tools write it precisely so that
    /// cache reclaimers can find regenerable build/cache trees regardless of
    /// the directory's *name*. This is the definitive, name-independent,
    /// root-level signal the daemon uses to reclaim arbitrarily-named build
    /// caches (e.g. `srw`, `p4-verify`, the shared `cargo-target`) that never
    /// matched the old `rch_target_*` name predicate.
    pub has_cachedir_tag: bool,
}

impl StructuralSignals {
    /// Returns true if the signals strongly indicate a build artifact directory
    /// (e.g., Rust target with incremental/deps/fingerprint markers, or mostly
    /// object files).
    #[must_use]
    pub fn has_strong_signal(&self) -> bool {
        // A validated CACHEDIR.TAG is a definitive, name-independent marker of a
        // regenerable cache directory — on its own it is a strong signal.
        if self.has_cachedir_tag {
            return true;
        }
        // Two or more Rust-specific markers = strong signal.
        let rust_markers = u8::from(self.has_incremental)
            + u8::from(self.has_deps)
            + u8::from(self.has_fingerprint);
        rust_markers >= 2 || self.mostly_object_files || (self.has_build && self.has_deps)
    }
}

/// Pre-descent disposition for a directory that may be expensive or unsafe to walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpaqueTreeDisposition {
    /// Score the directory itself as one cleanup candidate and do not descend.
    CandidateOpaque,
    /// Never score or descend into this subtree.
    ProtectedOpaque,
    /// Record the signal but keep normal traversal; the directory itself is not a candidate.
    SignalOnly,
}

/// Classification output for one path.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactClassification {
    pub pattern_name: Cow<'static, str>,
    pub category: ArtifactCategory,
    pub name_confidence: f64,
    pub structural_confidence: f64,
    pub combined_confidence: f64,
}

impl ArtifactClassification {
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            pattern_name: Cow::Borrowed("unknown"),
            category: ArtifactCategory::Unknown,
            name_confidence: 0.0,
            structural_confidence: 0.0,
            combined_confidence: 0.0,
        }
    }
}

/// Opaque-tree classification output.
#[derive(Debug, Clone, PartialEq)]
pub struct OpaqueTreeClassification {
    pub disposition: OpaqueTreeDisposition,
    pub reason: Cow<'static, str>,
    pub classification: ArtifactClassification,
}

impl OpaqueTreeClassification {
    fn candidate(
        reason: &'static str,
        pattern_name: &'static str,
        category: ArtifactCategory,
        confidence: f64,
    ) -> Self {
        Self {
            disposition: OpaqueTreeDisposition::CandidateOpaque,
            reason: Cow::Borrowed(reason),
            classification: ArtifactClassification {
                pattern_name: Cow::Borrowed(pattern_name),
                category,
                name_confidence: confidence,
                structural_confidence: 1.0,
                combined_confidence: confidence,
            },
        }
    }

    fn protected(reason: &'static str) -> Self {
        Self {
            disposition: OpaqueTreeDisposition::ProtectedOpaque,
            reason: Cow::Borrowed(reason),
            classification: ArtifactClassification::unknown(),
        }
    }

    fn signal_only(reason: &'static str) -> Self {
        Self {
            disposition: OpaqueTreeDisposition::SignalOnly,
            reason: Cow::Borrowed(reason),
            classification: ArtifactClassification::unknown(),
        }
    }
}

/// Parent/path evidence available before deciding whether to descend.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OpaqueTreeContext {
    pub parent_has_cargo_toml: bool,
    pub parent_has_node_manifest: bool,
}

/// Classify a directory before descent for the v2 opaque-tree scanner path.
#[must_use]
pub fn classify_opaque_tree(
    path: &Path,
    context: OpaqueTreeContext,
) -> Option<OpaqueTreeClassification> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();

    if name == ".git" {
        return Some(OpaqueTreeClassification::protected(
            "git metadata is always protected opaque",
        ));
    }

    // Anything strictly inside cargo's own stores (`registry/src`,
    // `registry/cache`, `registry/index`, `git/checkouts`, `git/db`) is
    // cargo-managed content — unpacked crate SOURCE, `.crate` archives, index
    // clones — never a build output. It must be checked before any name rule:
    // crates such as `target-triple-1.0.0` / `target-lexicon-0.13.5` unpack to
    // directories whose names satisfy the broad `target-` prefix, and a store
    // that lives under a temp-like `CARGO_HOME` would otherwise be promoted to
    // a 0.93 `opaque-cargo-target` candidate purely on that name. The store
    // roots themselves are excluded here so `.cargo/registry` / `.cargo/git`
    // remain the opaque reclaim unit handled below.
    if is_cargo_registry_internal_path(path) {
        return Some(OpaqueTreeClassification::protected(
            "cargo registry/git store content is crate source, never a build target",
        ));
    }

    // Go toolchain caches (GOCACHE build cache / GOMODCACHE module cache).
    // Detected structurally because on the fleet they sit under arbitrarily
    // named roots in /data/tmp that no name pattern matches. The cheap
    // `go`/`mod` substring pre-filter keeps the extra `read_dir` to plausibly-Go
    // directories — real roots are `go-build`, `*go*cache*`, `mod`, `*modcache*`
    // — while `detect_go_cache` is the authoritative structural test. Scored as
    // one opaque candidate (no descent) so a 100k-file cache costs a single probe.
    if (name.contains("go") || name.contains("mod"))
        && let Some(kind) = detect_go_cache(path)
    {
        let (reason, label) = match kind {
            GoCacheKind::Build => (
                "go build cache (GOCACHE) root: regenerable, toolchain-readonly",
                "opaque-go-build-cache",
            ),
            GoCacheKind::Module => (
                "go module cache (GOMODCACHE) root: regenerable, toolchain-readonly",
                "opaque-go-mod-cache",
            ),
        };
        return Some(OpaqueTreeClassification::candidate(
            reason,
            label,
            ArtifactCategory::GoCache,
            0.93,
        ));
    }

    let tmp_like = is_tmp_like_path(path);
    if is_context_gated_dependency_tree_name(&name) {
        return Some(OpaqueTreeClassification::signal_only(
            "dependency tree requires stronger context before opaque cleanup",
        ));
    }

    if is_cargo_target_name(&name) {
        // The broad `target-<x>` / `target_<x>` PREFIX forms are the only
        // target-like shapes that ordinary crate and project names also
        // satisfy (`target-triple`, `target_spec`), so temp-like placement
        // alone is not enough to promote them: the tree must additionally
        // carry a cargo build marker at its root. Every other shape keeps the
        // plain temp-context promotion.
        let tmp_promotes =
            tmp_like && (!has_broad_target_prefix(&name) || has_cargo_target_root_markers(path));
        if (name == "target" && context.parent_has_cargo_toml)
            || tmp_promotes
            || is_agent_build_target_name(&name)
            // Descriptive `<prefix>-target` / `<prefix>_target` names (e.g.
            // `cass-ft-target`) are a strong stand-alone signal of a
            // `CARGO_TARGET_DIR` output, so V2 nominates them as a single
            // opaque candidate even without tmp/agent/parent-cargo context.
            // This is what lets a stranded `/root/cass-ft-target` be reclaimed.
            // The broad `target-`/`target_` PREFIX forms are intentionally NOT
            // promoted here (see `has_descriptive_target_suffix`): they stay
            // SignalOnly in a source context, matching the conservative
            // `opaque_tree_does_not_promote_broad_target_like_names_in_source_context`
            // guarantee. All downstream deletion vetoes still apply.
            || has_descriptive_target_suffix(&name)
        {
            return Some(OpaqueTreeClassification::candidate(
                "cargo/build target with regenerable context",
                "opaque-cargo-target",
                ArtifactCategory::RustTarget,
                0.93,
            ));
        }
        return Some(OpaqueTreeClassification::signal_only(if tmp_like {
            "target-prefixed name under temp storage lacks cargo build markers"
        } else {
            "target-like directory lacks cargo/temp context"
        }));
    }

    if name == "node_modules" {
        if context.parent_has_node_manifest || tmp_like {
            return Some(OpaqueTreeClassification::candidate(
                "node_modules with package manifest or temp context",
                "opaque-node-modules",
                ArtifactCategory::NodeModules,
                0.94,
            ));
        }
        return Some(OpaqueTreeClassification::signal_only(
            "node_modules lacks package/temp context",
        ));
    }

    if is_cargo_cache_root(path) {
        return Some(OpaqueTreeClassification::candidate(
            "cargo registry/cache root",
            "opaque-cargo-cache",
            ArtifactCategory::CacheDir,
            0.92,
        ));
    }

    if matches!(name.as_str(), ".next" | "dist" | "build")
        && (context.parent_has_node_manifest || tmp_like)
    {
        return Some(OpaqueTreeClassification::candidate(
            "build output with project/temp context",
            "opaque-build-output",
            ArtifactCategory::BuildOutput,
            0.88,
        ));
    }

    None
}

fn is_context_gated_dependency_tree_name(name: &str) -> bool {
    matches!(
        name,
        "vendor" | "site-packages" | ".venv" | "venv" | "env" | ".pnpm-store" | ".yarn" | ".cargo"
    )
}

fn is_cargo_target_name(name: &str) -> bool {
    name == "target"
        || name.starts_with(".target")
        || name.starts_with("_target_")
        || name.starts_with("target-")
        || name.starts_with("target_")
        || name.ends_with("-target")
        || name.ends_with("_target")
        || name.starts_with("cargo-target-")
        || name.starts_with("rch_target_")
        || name.starts_with(".rch_target_")
        || name.starts_with("rch-target-")
        || name.starts_with(".rch-target-")
        || matches!(
            name,
            ".rch-target" | ".rch_target" | "rch-target" | "rch_target"
        )
}

fn is_agent_build_target_name(name: &str) -> bool {
    name.starts_with("rch_target_")
        || name.starts_with(".rch_target_")
        || name.starts_with("rch-target-")
        || name.starts_with(".rch-target-")
        || matches!(
            name,
            ".rch-target" | ".rch_target" | "rch-target" | "rch_target"
        )
}

/// True when `name` is `<prefix>-target` or `<prefix>_target` with a non-empty
/// `<prefix>` before the separator — the shape cargo produces when
/// `CARGO_TARGET_DIR` is set to a descriptive name (`cass-ft-target`,
/// `hfdt-release-target`, `foo_target`).
///
/// A bare `target` (handled by the exact list in
/// [`is_obvious_build_artifact_basename`]) and a leading-separator `-target` /
/// `_target` (empty prefix) are deliberately excluded so this never widens the
/// match beyond names that carry a real descriptive prefix.
pub(crate) fn has_descriptive_target_suffix(name: &str) -> bool {
    name.strip_suffix("-target")
        .or_else(|| name.strip_suffix("_target"))
        .is_some_and(|prefix| !prefix.is_empty())
}

/// Returns true if the candidate's basename clearly identifies it as a
/// disposable build/cache artifact that's safe to delete even when located
/// inside a protected source-tree root (or, via the `is_system_path`
/// backstop, directly under a worker's `/root`).
///
/// This is the "carve-out" that keeps sbh useful inside `/data/projects/`,
/// `/home/<user>/projects/`, and `/Users/<user>/projects/`: the broad
/// hardcoded-source-tree refusal would otherwise block all cleanup there,
/// including the wizard's main intended use case (clearing `target/`,
/// `node_modules/`, etc. under operator-configured source roots).
///
/// The list is intentionally narrow — only basenames we are confident
/// represent disposable build/cache directories. Anything not on this list
/// stays vetoed under protected roots, preserving the carnage-prevention
/// guarantee for arbitrary unknown names.
///
/// If you ever expand this list, the new entries are additive — they only
/// ever LOOSEN the refusal for the matched basename. Existing protections
/// for unmatched basenames are unchanged.
///
/// Matching is case-sensitive (real build-artifact dir names are lowercase).
pub(crate) fn is_obvious_build_artifact_basename(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };

    // Exact-match basenames (alphabetized for ease of audit). Bare rch
    // target dir names without a job-suffix are included here so the prefix
    // matchers below can safely require a separator (`-` or `_`) — this
    // prevents `.rch-targetfoo` style false positives.
    let exact_artifacts: &[&str] = &[
        ".cargo-target",
        ".next",
        ".nuxt",
        ".parcel-cache",
        ".pytest_cache",
        ".rch-target",
        ".rch_target",
        ".target",
        ".tox",
        ".turbo",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "rch-target",
        "rch_target",
        "target",
        "venv",
    ];
    if exact_artifacts.contains(&name) {
        return true;
    }

    // Prefix-match basenames — match per-job/per-config suffixes produced
    // by cargo (`target-foo`, `target_bar`) and rch (`.rch-target-job-42`,
    // `rch-target-…`, `rch_target_…`, `.cargo-target-rusticmill`). Each
    // prefix REQUIRES the separator (`-` or `_`) so we never match unrelated
    // names that happen to start with `target` or `.rch-target`.
    if name.starts_with("target-")
        || name.starts_with("target_")
        || name.starts_with(".rch-target-")
        || name.starts_with(".rch_target_")
        || name.starts_with("rch-target-")
        || name.starts_with("rch_target_")
        || name.starts_with(".cargo-target-")
    {
        return true;
    }

    // Suffix-match basenames — descriptive `CARGO_TARGET_DIR` names such as
    // `cass-ft-target`, `hfdt-release-target`, `foo_target`. Requires a
    // non-empty prefix before the `-target` / `_target` separator, so a bare
    // `target` (already handled above) and a leading-separator `-target`
    // never match, and `mytarget` (no separator) is excluded. This mirrors the
    // `target-suffix` (0.88) / `underscore-target-suffix` (0.92) patterns in
    // the artifact registry.
    has_descriptive_target_suffix(name)
}

/// The broad `target-<x>` / `target_<x>` prefix shapes: the one target-like
/// family that legitimate crate and project names routinely share.
fn has_broad_target_prefix(name: &str) -> bool {
    name.starts_with("target-") || name.starts_with("target_")
}

/// Cheap root-level structural corroboration that a directory is a cargo
/// build output: a validated `CACHEDIR.TAG` (cargo writes one at every target
/// root), cargo's `.rustc_info.json`, or one of the profile / fingerprint
/// subdirectories only cargo produces. One `read_dir`, no descent.
fn has_cargo_target_root_markers(path: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(path) else {
        return false;
    };
    for entry in entries.flatten() {
        let name_os = entry.file_name();
        let Some(name) = name_os.to_str() else {
            continue;
        };
        let is_dir = || entry.file_type().is_ok_and(|ft| ft.is_dir());
        let marker = match name {
            "CACHEDIR.TAG" => crate::scanner::walker::is_valid_cachedir_tag(&entry.path()),
            ".rustc_info.json" => entry.file_type().is_ok_and(|ft| ft.is_file()),
            "debug" | "release" | ".fingerprint" | "deps" | "incremental" => is_dir(),
            _ => false,
        };
        if marker {
            return true;
        }
    }
    false
}

/// True when `path` lies strictly inside one of cargo's home stores.
///
/// The stores are `registry/src`, `registry/cache`, `registry/index`,
/// `git/checkouts` and `git/db` (any `CARGO_HOME`, not only `~/.cargo`).
/// Everything below those directories is cargo-managed content: unpacked
/// crate source, `.crate` archives, index clones, git checkouts. None of it
/// is a build output, so no name pattern may nominate it and the deletion
/// scorer vetoes it outright. The store directories themselves (and the
/// `registry` / `git` roots above them) are deliberately NOT matched: those
/// remain the opaque, whole-store reclaim unit (`opaque-cargo-cache` / the
/// cleanup catalog).
#[must_use]
pub fn is_cargo_registry_internal_path(path: &Path) -> bool {
    // `ancestors()` yields `path` first; the store dir must be a STRICT
    // ancestor, so start from the parent.
    path.ancestors().skip(1).any(|dir| {
        let Some(name) = dir.file_name().and_then(|n| n.to_str()) else {
            return false;
        };
        let Some(parent) = dir
            .parent()
            .and_then(Path::file_name)
            .and_then(|n| n.to_str())
        else {
            return false;
        };
        matches!(
            (parent, name),
            ("registry", "src" | "cache" | "index") | ("git", "checkouts" | "db")
        )
    })
}

fn is_tmp_like_path(path: &Path) -> bool {
    ["/tmp", "/var/tmp", "/data/tmp", "/private/tmp"]
        .iter()
        .any(|root| {
            let root = Path::new(root);
            path == root || path.starts_with(root)
        })
}

fn is_cargo_cache_root(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if !matches!(name, "registry" | "git") {
        return false;
    }
    path.parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .is_some_and(|parent| parent == ".cargo")
}

/// On-disk kind of a detected Go toolchain cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GoCacheKind {
    /// `GOCACHE` build cache (default `~/.cache/go-build`).
    Build,
    /// `GOMODCACHE` module cache (default `~/go/pkg/mod`).
    Module,
}

/// Detect a Go toolchain cache by its on-disk structure, independent of the
/// directory's name.
///
/// Why structural and not name-based: on the build fleet these caches live
/// under arbitrarily-named `GOCACHE`/`GOMODCACHE` roots in `/data/tmp` (e.g.
/// `lumera_go_buildcache_taskstore`, `lumera_ai_go_cache`), so the name
/// patterns in `builtin_patterns()` never match them and they accumulate to
/// tens of GB unreclaimed. Their layout, however, is unmistakable:
///
///   * GOCACHE (build): a `trim.txt` file at the root alongside two-hex-char
///     shard directories (`00`..`ff`); entries are `<actionID>-d` / `<hash>-a`
///     files written `0444`.
///   * GOMODCACHE (module): a `cache/download/` directory at the root (where
///     `go mod download` stores module zips + sumdb); extracted module trees
///     (`<host>/<path>@<version>/`) are written `0555`.
///
/// Both are 100% regenerable (`go clean -cache` / `-modcache`, or simply the
/// next build), which is why a positive match upgrades the directory to a
/// high-confidence opaque cleanup candidate and (in the deletion executor)
/// unlocks read-only-defeating removal.
///
/// Cost: a single `read_dir` of the root plus, for the module case, one
/// `stat`. Callers gate this behind a cheap name pre-filter (see
/// `classify_opaque_tree`) so it runs only for plausibly-Go directories rather
/// than for every directory in a scan.
fn detect_go_cache(path: &Path) -> Option<GoCacheKind> {
    let Ok(entries) = std::fs::read_dir(path) else {
        return None;
    };

    let mut has_trim_txt = false;
    let mut has_hex_shard = false;

    for entry in entries.flatten() {
        let name_os = entry.file_name();
        let Some(name) = name_os.to_str() else {
            continue;
        };

        if name == "trim.txt" {
            has_trim_txt = true;
        } else if name == "cache" {
            // GOMODCACHE marker: a `cache/download/` directory (where `go mod
            // download` stores module zips + sumdb). Required to be a real
            // directory and used as the *sole* marker — `cache/lock` alone is
            // too generic. Precision matters because the GoCache classification
            // bypasses the source-code deletion veto.
            if entry.path().join("download").is_dir() {
                return Some(GoCacheKind::Module);
            }
        } else if is_two_hex_char(name) && entry.file_type().is_ok_and(|ft| ft.is_dir()) {
            has_hex_shard = true;
        }

        // The build-cache signature needs both markers; short-circuit once met.
        if has_trim_txt && has_hex_shard {
            return Some(GoCacheKind::Build);
        }
    }

    None
}

/// True for a two-character lowercase-hex directory name (`00`..`ff`) — the
/// shard layout GOCACHE uses to fan out cache entries. Deliberately excludes
/// uppercase so it cannot match unrelated short names.
fn is_two_hex_char(name: &str) -> bool {
    name.len() == 2
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchKind {
    Exact(&'static str),
    Prefix(&'static str),
    #[allow(dead_code)] // variant exists for future pattern use
    Suffix(&'static str),
    #[allow(dead_code)] // match arm exists but no patterns use this variant yet
    Contains(&'static str),
}

#[derive(Debug, Clone)]
struct ArtifactPattern {
    name: &'static str,
    kind: MatchKind,
    confidence: f64,
    category: ArtifactCategory,
}

/// User-provided pattern extension.
#[derive(Debug, Clone, PartialEq)]
pub struct CustomPattern {
    pub name: String,
    pub needle: String,
    pub confidence: f64,
    pub category: ArtifactCategory,
}

#[derive(Debug, Clone)]
struct NormalizedCustomPattern {
    pattern: CustomPattern,
    lowercase_needle: String,
}

/// Registry of built-in and custom patterns.
#[derive(Debug, Clone)]
pub struct ArtifactPatternRegistry {
    builtins: Vec<ArtifactPattern>,
    custom: Vec<NormalizedCustomPattern>,
}

impl Default for ArtifactPatternRegistry {
    fn default() -> Self {
        Self {
            builtins: builtin_patterns(),
            custom: Vec::new(),
        }
    }
}

impl ArtifactPatternRegistry {
    #[must_use]
    pub fn with_custom(mut self, custom: Vec<CustomPattern>) -> Self {
        self.custom = custom
            .into_iter()
            .map(|pattern| NormalizedCustomPattern {
                lowercase_needle: pattern.needle.to_lowercase(),
                pattern,
            })
            .collect();
        self
    }

    /// Classify one path name with optional structural evidence.
    #[must_use]
    pub fn classify(&self, path: &Path, signals: StructuralSignals) -> ArtifactClassification {
        self.classify_with_cleanup_rules(path, signals, platform_cleanup_rules())
    }

    /// Classify one path name against an explicit cleanup catalog.
    #[must_use]
    pub fn classify_with_cleanup_rules(
        &self,
        path: &Path,
        signals: StructuralSignals,
        cleanup_rules: &'static [CleanupRule],
    ) -> ArtifactClassification {
        self.classify_with_cleanup_rules_inner(path, signals, cleanup_rules, None)
    }

    /// Classify one path against an explicit cleanup catalog and synthetic home root.
    #[must_use]
    pub fn classify_with_cleanup_rules_and_home(
        &self,
        path: &Path,
        signals: StructuralSignals,
        cleanup_rules: &'static [CleanupRule],
        home: &Path,
    ) -> ArtifactClassification {
        self.classify_with_cleanup_rules_inner(path, signals, cleanup_rules, Some(home))
    }

    fn classify_with_cleanup_rules_inner(
        &self,
        path: &Path,
        signals: StructuralSignals,
        cleanup_rules: &'static [CleanupRule],
        home: Option<&Path>,
    ) -> ArtifactClassification {
        let Some(name_os) = path.file_name() else {
            return ArtifactClassification::unknown();
        };
        // Crate source unpacked under a cargo store is never an artifact,
        // whatever its basename looks like (`target-triple-1.0.0`).
        if is_cargo_registry_internal_path(path) {
            return ArtifactClassification::unknown();
        }
        let normalized = name_os.to_string_lossy().to_lowercase();

        let catalog_classification = cleanup_catalog_path_classification(path, cleanup_rules, home);
        let mut best = catalog_classification
            .clone()
            .unwrap_or_else(ArtifactClassification::unknown);
        for pattern in &self.builtins {
            if matches_builtin(pattern.kind, &normalized)
                && pattern.confidence > best.name_confidence
            {
                best = ArtifactClassification {
                    pattern_name: Cow::Borrowed(pattern.name),
                    category: pattern.category,
                    name_confidence: pattern.confidence,
                    structural_confidence: 0.0,
                    combined_confidence: pattern.confidence,
                };
            }
        }

        for custom in &self.custom {
            if normalized.contains(&custom.lowercase_needle)
                && custom.pattern.confidence > best.name_confidence
            {
                best = ArtifactClassification {
                    pattern_name: Cow::Owned(custom.pattern.name.clone()),
                    category: custom.pattern.category,
                    name_confidence: custom.pattern.confidence,
                    structural_confidence: 0.0,
                    combined_confidence: custom.pattern.confidence,
                };
            }
        }

        if let Some(classification) = catalog_classification {
            best = classification;
        }

        // Structural rescue path: name is ambiguous but layout screams "Rust target".
        // Graduated confidence based on how many cargo-specific markers are present:
        // only cargo build output directories have .fingerprint + deps + incremental +
        // build together, so 3+ markers is definitive and warrants higher confidence.
        if best.category == ArtifactCategory::Unknown
            && (signals.has_fingerprint || (signals.has_incremental && signals.has_deps))
        {
            let marker_count = u8::from(signals.has_fingerprint)
                + u8::from(signals.has_incremental)
                + u8::from(signals.has_deps)
                + u8::from(signals.has_build);
            let rescue_confidence = if marker_count >= 3 { 0.75 } else { 0.55 };

            best = ArtifactClassification {
                pattern_name: Cow::Borrowed("structural-rust-target"),
                category: ArtifactCategory::RustTarget,
                name_confidence: rescue_confidence,
                structural_confidence: 0.0,
                combined_confidence: rescue_confidence,
            };
        } else if best.category == ArtifactCategory::Unknown && signals.has_cachedir_tag {
            // Name-agnostic rescue: the directory carries a validated
            // CACHEDIR.TAG at its root (per the Cache Directory Tagging
            // Standard) but its *name* matched no artifact pattern — exactly
            // the arbitrarily-named build caches (`srw`, `p4-verify`, a shared
            // `cargo-target` whose deps/incremental/.fingerprint markers live
            // one level down under debug/ and release/) that the old
            // `rch_target_*` name predicate could never see. The tag is the
            // canonical "regenerable cache, safe to reclaim" marker, so treat
            // it as a definitive CacheDir. The remaining safety gates (`.git`,
            // held fds, minimum age, and the multi-factor decision layer) still
            // apply on top of this classification.
            best = ArtifactClassification {
                pattern_name: Cow::Borrowed("cachedir-tagged-cache"),
                category: ArtifactCategory::CacheDir,
                name_confidence: 0.75,
                structural_confidence: 0.0,
                combined_confidence: 0.75,
            };
        }

        let structural = structural_score(best.category, signals);
        let mut combined = 0.70f64
            .mul_add(best.name_confidence, 0.30 * structural)
            .clamp(0.0, 1.0);

        // Structural safety override: if the structural score is very low (indicating
        // a project root signal like Cargo.toml or .git), we must severely penalize
        // the combined score to prevent deletion, even if the name matches a pattern.
        if structural < 0.1 {
            combined *= 0.1;
        }

        ArtifactClassification {
            structural_confidence: structural,
            combined_confidence: combined,
            ..best
        }
    }
}

#[must_use]
pub fn platform_cleanup_rules() -> &'static [CleanupRule] {
    #[cfg(target_os = "macos")]
    {
        crate::platform::macos::cleanup_catalog::cleanup_rules()
    }
    #[cfg(target_os = "linux")]
    {
        crate::platform::linux::cleanup_catalog::cleanup_rules()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        &[]
    }
}

fn matches_builtin(kind: MatchKind, normalized: &str) -> bool {
    match kind {
        MatchKind::Exact(token) => normalized == token,
        MatchKind::Prefix(token) => normalized.starts_with(token),
        MatchKind::Suffix(token) => normalized.ends_with(token),
        MatchKind::Contains(token) => normalized.contains(token),
    }
}

fn cleanup_catalog_path_classification(
    path: &Path,
    cleanup_rules: &'static [CleanupRule],
    home: Option<&Path>,
) -> Option<ArtifactClassification> {
    let rule = home.map_or_else(
        || cleanup_catalog::match_scan_visible_rule(path, cleanup_rules),
        |home| cleanup_catalog::match_scan_visible_rule_with_home(path, cleanup_rules, home),
    )?;
    let confidence = cleanup_rule_name_confidence(rule);
    Some(ArtifactClassification {
        pattern_name: Cow::Borrowed(rule.scanner_label()),
        category: cleanup_rule_category(rule),
        name_confidence: confidence,
        structural_confidence: 0.0,
        combined_confidence: confidence,
    })
}

fn cleanup_rule_name_confidence(rule: &CleanupRule) -> f64 {
    match rule.confidence {
        CleanupConfidence::Definite => 0.96,
        CleanupConfidence::Likely => 0.92,
        CleanupConfidence::Unclear => 0.56,
        CleanupConfidence::ReportOnly | CleanupConfidence::Sacred => 0.0,
    }
}

fn cleanup_rule_category(rule: &CleanupRule) -> ArtifactCategory {
    let name = rule.name;
    if name.contains("target") {
        ArtifactCategory::RustTarget
    } else if name.starts_with("electron")
        || name.contains("cache")
        || name.contains("logs")
        || name.contains("ipsw")
    {
        ArtifactCategory::CacheDir
    } else if name.contains("derived-data") || name.contains("buildroot") {
        ArtifactCategory::BuildOutput
    } else if rule.reclaim_command == ReclaimCommand::PromptBeforeRemove {
        ArtifactCategory::TempDir
    } else {
        ArtifactCategory::Unknown
    }
}

fn structural_score(category: ArtifactCategory, signals: StructuralSignals) -> f64 {
    if signals.has_git {
        return 0.0;
    }
    // A validated CACHEDIR.TAG at the root is a definitive, name-independent
    // marker that the directory is a regenerable cache — score it strongly
    // regardless of category so arbitrarily-named build caches are reclaimable.
    if signals.has_cachedir_tag {
        return 0.95;
    }
    match category {
        ArtifactCategory::RustTarget => {
            if signals.has_fingerprint {
                0.98
            } else if signals.has_incremental && signals.has_deps {
                0.92
            } else if signals.has_build && signals.has_deps {
                0.85
            } else if signals.has_cargo_toml {
                0.05
            } else if signals.mostly_object_files {
                0.90
            } else {
                0.40
            }
        }
        ArtifactCategory::NodeModules => 0.80,
        ArtifactCategory::PythonCache => 0.75,
        ArtifactCategory::BuildOutput | ArtifactCategory::CacheDir | ArtifactCategory::TempDir => {
            if signals.mostly_object_files {
                0.80
            } else {
                0.40
            }
        }
        // GoCache is only ever produced by structural detection (GOCACHE /
        // GOMODCACHE markers), so the directory IS the artifact — give it a
        // strong, signal-independent structural score.
        ArtifactCategory::GoCache => 0.90,
        ArtifactCategory::AgentWorkspace => 0.78,
        ArtifactCategory::Unknown => {
            if signals.has_fingerprint || (signals.has_incremental && signals.has_deps) {
                0.75
            } else {
                0.0
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
fn builtin_patterns() -> Vec<ArtifactPattern> {
    vec![
        ArtifactPattern {
            name: "cargo-target",
            kind: MatchKind::Exact("target"),
            confidence: 0.70,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "dot-target-prefix",
            kind: MatchKind::Prefix(".target"),
            confidence: 0.92,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "underscore-target-prefix",
            kind: MatchKind::Prefix("_target_"),
            confidence: 0.88,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "cargo-target-prefix",
            kind: MatchKind::Prefix("cargo-target-"),
            confidence: 0.94,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "target-prefix",
            kind: MatchKind::Prefix("target-"),
            confidence: 0.82,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "target-underscore-prefix",
            kind: MatchKind::Prefix("target_"),
            confidence: 0.82,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "target-suffix",
            kind: MatchKind::Suffix("-target"),
            confidence: 0.88,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "tmp-target-prefix",
            kind: MatchKind::Prefix(".tmp_target"),
            confidence: 0.90,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "tmp-cargo-home",
            kind: MatchKind::Prefix(".tmp_cargo_home_"),
            confidence: 0.90,
            category: ArtifactCategory::TempDir,
        },
        ArtifactPattern {
            name: "tmp-codex",
            kind: MatchKind::Prefix(".tmp-codex-"),
            confidence: 0.86,
            category: ArtifactCategory::AgentWorkspace,
        },
        ArtifactPattern {
            name: "tmp-pijs",
            kind: MatchKind::Prefix(".tmp-pijs-"),
            confidence: 0.86,
            category: ArtifactCategory::AgentWorkspace,
        },
        ArtifactPattern {
            name: "tmp-ext",
            kind: MatchKind::Prefix(".tmp-ext-"),
            confidence: 0.82,
            category: ArtifactCategory::AgentWorkspace,
        },
        ArtifactPattern {
            name: "pi-agent",
            kind: MatchKind::Prefix("pi_agent_"),
            confidence: 0.85,
            category: ArtifactCategory::AgentWorkspace,
        },
        ArtifactPattern {
            name: "pi-target",
            kind: MatchKind::Prefix("pi_target_"),
            confidence: 0.85,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "pi-opus",
            kind: MatchKind::Prefix("pi_opus_"),
            confidence: 0.84,
            category: ArtifactCategory::AgentWorkspace,
        },
        ArtifactPattern {
            name: "br-build",
            kind: MatchKind::Prefix("br-build"),
            confidence: 0.82,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "frankenterm-prefix",
            kind: MatchKind::Prefix("frankenterm-"),
            confidence: 0.90,
            category: ArtifactCategory::AgentWorkspace,
        },
        ArtifactPattern {
            name: "cargo-home-prefix",
            kind: MatchKind::Prefix("cargo-home-"),
            confidence: 0.88,
            category: ArtifactCategory::TempDir,
        },
        // rch (remote compilation helper) creates isolated CARGO_HOME staging
        // dirs named `rch-cargo-home-<host>-<pid>-<uuid>`. As of rch 1.0.38
        // these land under `$TMPDIR`/`/data/tmp` (not just `/tmp`), and a dead
        // build can leave them behind. Because the basename starts with `rch-`,
        // neither `cargo-home-prefix` ("cargo-home-") nor `tmp-cargo-home`
        // (".tmp_cargo_home_") fires — this dedicated prefix is the backstop.
        // The trailing hyphen in the needle keeps it from ever matching a repo
        // or source dir; matching is by basename so it works regardless of the
        // parent dir. Mirrors `cargo-home-prefix`: regenerable temp/cache dir.
        ArtifactPattern {
            name: "rch-cargo-home",
            kind: MatchKind::Prefix("rch-cargo-home-"),
            confidence: 0.92,
            category: ArtifactCategory::TempDir,
        },
        ArtifactPattern {
            name: "dot-cargo-prefix",
            kind: MatchKind::Prefix(".cargo_"),
            confidence: 0.86,
            category: ArtifactCategory::CacheDir,
        },
        ArtifactPattern {
            name: "agent-ft-suffix",
            kind: MatchKind::Suffix("-ft"),
            confidence: 0.65,
            category: ArtifactCategory::AgentWorkspace,
        },
        ArtifactPattern {
            name: "cass-target",
            kind: MatchKind::Prefix("cass-target"),
            // Must stay above `cass-prefix-hyphen` (0.86) below so a name
            // like `cass-target-thatlilac` keeps its RustTarget label and
            // the cargo-marker structural boost (0.92–0.98) instead of
            // collapsing to the flat 0.78 AgentWorkspace score.
            confidence: 0.94,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "node-modules",
            kind: MatchKind::Exact("node_modules"),
            confidence: 0.97,
            category: ArtifactCategory::NodeModules,
        },
        ArtifactPattern {
            name: "next-build",
            kind: MatchKind::Exact(".next"),
            confidence: 0.90,
            category: ArtifactCategory::BuildOutput,
        },
        ArtifactPattern {
            name: "python-pycache",
            kind: MatchKind::Exact("__pycache__"),
            confidence: 0.96,
            category: ArtifactCategory::PythonCache,
        },
        ArtifactPattern {
            name: "python-venv",
            kind: MatchKind::Exact(".venv"),
            confidence: 0.85,
            category: ArtifactCategory::PythonCache,
        },
        ArtifactPattern {
            name: "pytest-cache",
            kind: MatchKind::Exact(".pytest_cache"),
            confidence: 0.84,
            category: ArtifactCategory::PythonCache,
        },
        ArtifactPattern {
            name: "generic-cache-prefix-hyphen",
            kind: MatchKind::Prefix("cache-"),
            confidence: 0.45,
            category: ArtifactCategory::CacheDir,
        },
        ArtifactPattern {
            name: "generic-cache-prefix-underscore",
            kind: MatchKind::Prefix("cache_"),
            confidence: 0.45,
            category: ArtifactCategory::CacheDir,
        },
        ArtifactPattern {
            name: "generic-cache-exact",
            kind: MatchKind::Exact("cache"),
            confidence: 0.45,
            category: ArtifactCategory::CacheDir,
        },
        ArtifactPattern {
            name: "dot-cache",
            kind: MatchKind::Prefix(".cache"),
            confidence: 0.62,
            category: ArtifactCategory::CacheDir,
        },
        ArtifactPattern {
            name: "generic-tmp-prefix-hyphen",
            kind: MatchKind::Prefix("tmp-"),
            confidence: 0.45,
            category: ArtifactCategory::TempDir,
        },
        ArtifactPattern {
            name: "generic-tmp-prefix-underscore",
            kind: MatchKind::Prefix("tmp_"),
            confidence: 0.45,
            category: ArtifactCategory::TempDir,
        },
        ArtifactPattern {
            name: "generic-tmp-exact",
            kind: MatchKind::Exact("tmp"),
            confidence: 0.45,
            category: ArtifactCategory::TempDir,
        },
        ArtifactPattern {
            name: "dot-tmp",
            kind: MatchKind::Prefix(".tmp"),
            confidence: 0.60,
            category: ArtifactCategory::TempDir,
        },
        // rch (remote compilation helper) build artifacts — can be 70+ GB.
        ArtifactPattern {
            name: "rch-target-underscore",
            kind: MatchKind::Prefix("rch_target_"),
            confidence: 0.92,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "rch-target-dot",
            kind: MatchKind::Prefix(".rch_target_"),
            confidence: 0.92,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "rch-target-hyphen",
            kind: MatchKind::Prefix("rch-target-"),
            confidence: 0.92,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "dot-rch-target-hyphen",
            kind: MatchKind::Prefix(".rch-target-"),
            confidence: 0.92,
            category: ArtifactCategory::RustTarget,
        },
        // Bare in-tree shared rch target dirs. rch creates a directory
        // literally named `.rch-target/` (no trailing identifier) in the
        // project root as the default `CARGO_TARGET_DIR` when no per-job
        // override is supplied; on a heavily used worker this can grow
        // to 100+ GB. Without these exact matches the bare names only
        // hit the generic suffix rules — `target-suffix` (0.88) for the
        // hyphen variants and `underscore-target-suffix` (0.92) for the
        // underscore variants — and the dir's mtime gets bumped
        // continuously by active builds, so the age veto fires forever
        // and the disk runs out. Explicit, high-confidence patterns
        // both stabilize classification and unlock the in-tree
        // pressure-based age fast-track in `daemon/loop_main.rs`.
        // Confidences are set above BOTH conflicting suffix matchers
        // (0.88 and 0.92) so `classify()` deterministically picks the
        // specific rch pattern over the generic suffix fallback.
        ArtifactPattern {
            name: "rch-target-bare-dot",
            kind: MatchKind::Exact(".rch-target"),
            confidence: 0.95,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "rch-target-bare-dot-underscore",
            kind: MatchKind::Exact(".rch_target"),
            confidence: 0.94,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "rch-target-bare-hyphen",
            kind: MatchKind::Exact("rch-target"),
            confidence: 0.93,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "rch-target-bare-underscore",
            kind: MatchKind::Exact("rch_target"),
            confidence: 0.93,
            category: ArtifactCategory::RustTarget,
        },
        // codex agent build artifacts.
        ArtifactPattern {
            name: "target-codex",
            kind: MatchKind::Prefix("target_codex"),
            confidence: 0.88,
            category: ArtifactCategory::RustTarget,
        },
        // Claude Code session caches — can grow to 100+ GB in /tmp/claude-<uid>/.
        ArtifactPattern {
            name: "claude-session-cache",
            kind: MatchKind::Prefix("claude-"),
            confidence: 0.88,
            category: ArtifactCategory::CacheDir,
        },
        // cass (Cross-Agent Session Search) bench/profile/scratch dirs.
        // Observed in the wild filling /tmp with 100+ GB of `cass_*_target`
        // (cargo target dirs), `cass_*_bench`, `cass_*_profile`, plus many
        // small per-mode `cass_*.txt`/`.log` artifacts. Both underscore
        // (canonical) and hyphen forms.
        ArtifactPattern {
            name: "cass-prefix-underscore",
            kind: MatchKind::Prefix("cass_"),
            confidence: 0.86,
            category: ArtifactCategory::AgentWorkspace,
        },
        ArtifactPattern {
            name: "cass-prefix-hyphen",
            kind: MatchKind::Prefix("cass-"),
            confidence: 0.86,
            category: ArtifactCategory::AgentWorkspace,
        },
        // Underscore-`_target` cargo build dirs — a sibling shape to the
        // existing `-target` suffix pattern. cass_*_target, pi_*_target,
        // and similar agent-prefixed patterns produce these.
        //
        // Confidence intentionally above the cass-/frankentui- workspace
        // prefixes (0.86, 0.90) so a name like `cass_append_baseline_target`
        // — which matches BOTH `cass_` (workspace) and `_target` (RustTarget)
        // — classifies as the more specific RustTarget. Both lead to the
        // same cleanup outcome; the distinction matters for stats and for
        // the structural-score boost RustTarget gets when cargo markers
        // are present.
        ArtifactPattern {
            name: "underscore-target-suffix",
            kind: MatchKind::Suffix("_target"),
            confidence: 0.92,
            category: ArtifactCategory::RustTarget,
        },
        // FrankenTUI (sibling project to FrankenTerm) — codex bead
        // workspace dirs `frankentui-codex-bd-<id>-*`, profile/sweep
        // outputs `frankentui_profile_*`. Observed in the wild at
        // multiple GB per workspace.
        ArtifactPattern {
            name: "frankentui-prefix-hyphen",
            kind: MatchKind::Prefix("frankentui-"),
            confidence: 0.90,
            category: ArtifactCategory::AgentWorkspace,
        },
        ArtifactPattern {
            name: "frankentui-prefix-underscore",
            kind: MatchKind::Prefix("frankentui_"),
            confidence: 0.90,
            category: ArtifactCategory::AgentWorkspace,
        },
    ]
}

/// Extract a recognizable pattern label from a path string.
///
/// Used by stats aggregation to group deleted items by pattern.
/// Returns a simplified pattern string like "target/" or ".target*".
pub fn extract_pattern_label(path: &str) -> String {
    extract_pattern_label_with_cleanup_rules(path, platform_cleanup_rules())
}

#[must_use]
pub fn extract_pattern_label_with_cleanup_rules(
    path: &str,
    cleanup_rules: &'static [CleanupRule],
) -> String {
    extract_pattern_label_with_cleanup_context(path, cleanup_rules, None)
}

#[must_use]
pub fn extract_pattern_label_with_cleanup_rules_and_home(
    path: &str,
    cleanup_rules: &'static [CleanupRule],
    home: &Path,
) -> String {
    extract_pattern_label_with_cleanup_context(path, cleanup_rules, Some(home))
}

fn extract_pattern_label_with_cleanup_context(
    path: &str,
    cleanup_rules: &'static [CleanupRule],
    home: Option<&Path>,
) -> String {
    let p = Path::new(path);
    let cleanup_rule = home.map_or_else(
        || cleanup_catalog::match_scan_visible_rule(p, cleanup_rules),
        |home| cleanup_catalog::match_scan_visible_rule_with_home(p, cleanup_rules, home),
    );
    if let Some(rule) = cleanup_rule {
        return rule.scanner_label().to_string();
    }

    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("unknown");

    // Match known artifact patterns.
    let lower = name.to_ascii_lowercase();
    if lower == "target" || lower.starts_with("target-") {
        return "target/".to_string();
    }
    // rch's bare in-tree targets (`.rch-target`, `.rch_target`,
    // `rch-target`, `rch_target`) are checked here — before the
    // generic `*-target` suffix branch — so they group with their
    // per-job siblings (`rch_target_*`) in stats output instead of
    // being lumped under the generic `*-target` bucket.
    if lower == "rch_target"
        || lower == ".rch_target"
        || lower == "rch-target"
        || lower == ".rch-target"
    {
        return "rch_target_*".to_string();
    }
    if lower.ends_with("-target") {
        return "*-target".to_string();
    }
    if lower.starts_with(".target") || lower.starts_with("_target_") {
        return ".target*".to_string();
    }
    if lower.starts_with("cargo-target") || lower.starts_with("cargo_target") {
        return "cargo-target-*".to_string();
    }
    if lower.starts_with("pi_agent")
        || lower.starts_with("pi_target")
        || lower.starts_with("pi_opus")
    {
        return "pi_*".to_string();
    }
    if lower.starts_with("cass-target") {
        return "cass-target*".to_string();
    }
    if lower.starts_with("br-build") {
        return "br-build*".to_string();
    }
    if lower.starts_with("rch_target_")
        || lower.starts_with(".rch_target_")
        || lower.starts_with("rch-target-")
        || lower.starts_with(".rch-target-")
    {
        return "rch_target_*".to_string();
    }
    if lower.starts_with("rch-cargo-home-") {
        return "rch-cargo-home-*".to_string();
    }
    if lower.starts_with("target_codex") {
        return "target_codex*".to_string();
    }
    if lower.starts_with("target_") {
        return "target_*".to_string();
    }
    if lower.starts_with("frankenterm-") {
        return "frankenterm-*".to_string();
    }
    if lower.starts_with("cargo-home-") {
        return "cargo-home-*".to_string();
    }
    if lower.starts_with(".cargo_") {
        return ".cargo_*".to_string();
    }
    if lower.ends_with("-ft") {
        return "*-ft".to_string();
    }
    if lower.starts_with(".tmp_target") {
        return ".tmp_target*".to_string();
    }
    if lower.starts_with("claude-") {
        return "claude-*".to_string();
    }
    // `*_target` checked BEFORE `cass_*` so `cass_append_baseline_target`
    // groups under the more-specific RustTarget label, not the generic
    // cass workspace label. Mirrors the confidence ordering in
    // `builtin_patterns()` (underscore-target-suffix at 0.92 above
    // cass-prefix at 0.86).
    if lower.ends_with("_target") {
        return "*_target".to_string();
    }
    if lower.starts_with("cass_") || lower.starts_with("cass-") {
        return "cass_*".to_string();
    }
    if lower.starts_with("frankentui-") || lower.starts_with("frankentui_") {
        return "frankentui-*".to_string();
    }
    if lower == "node_modules" {
        return "node_modules/".to_string();
    }

    // Fallback: use the directory name.
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactCategory, ArtifactClassification, ArtifactPatternRegistry, CustomPattern,
        OpaqueTreeContext, OpaqueTreeDisposition, StructuralSignals, classify_opaque_tree,
        extract_pattern_label, extract_pattern_label_with_cleanup_rules,
        has_descriptive_target_suffix, is_cargo_registry_internal_path,
        is_obvious_build_artifact_basename, structural_score,
    };
    use crate::platform::{linux, macos};
    use std::path::Path;

    fn classify_macos(
        registry: &ArtifactPatternRegistry,
        path: &Path,
        signals: StructuralSignals,
    ) -> ArtifactClassification {
        registry.classify_with_cleanup_rules(path, signals, macos::cleanup_catalog::cleanup_rules())
    }

    fn extract_macos_pattern_label(path: &str) -> String {
        extract_pattern_label_with_cleanup_rules(path, macos::cleanup_catalog::cleanup_rules())
    }

    fn classify_linux(
        registry: &ArtifactPatternRegistry,
        path: &Path,
        signals: StructuralSignals,
    ) -> ArtifactClassification {
        registry.classify_with_cleanup_rules(path, signals, linux::cleanup_catalog::cleanup_rules())
    }

    #[test]
    fn rust_target_with_markers_gets_high_confidence() {
        let registry = ArtifactPatternRegistry::default();
        let classification = registry.classify(
            Path::new(".target_opus_main"),
            StructuralSignals {
                has_incremental: true,
                has_deps: true,
                has_fingerprint: true,
                ..StructuralSignals::default()
            },
        );
        assert_eq!(classification.category, ArtifactCategory::RustTarget);
        assert!(classification.combined_confidence > 0.90);
    }

    #[test]
    fn ambiguous_target_without_markers_stays_lower_confidence() {
        let registry = ArtifactPatternRegistry::default();
        let classification = registry.classify(Path::new("target"), StructuralSignals::default());
        assert_eq!(classification.category, ArtifactCategory::RustTarget);
        assert!(classification.combined_confidence < 0.80);
    }

    #[test]
    fn cachedir_tag_alone_is_a_strong_signal() {
        let signals = StructuralSignals {
            has_cachedir_tag: true,
            ..StructuralSignals::default()
        };
        assert!(signals.has_strong_signal());
        // Even next to a Cargo.toml (contrived), the tag keeps it strong so the
        // "Cargo.toml without build markers" veto does not fire on a tagged cache.
        let with_manifest = StructuralSignals {
            has_cachedir_tag: true,
            has_cargo_toml: true,
            ..StructuralSignals::default()
        };
        assert!(with_manifest.has_strong_signal());
    }

    #[test]
    fn cachedir_tag_rescues_arbitrarily_named_dir_as_cachedir() {
        let registry = ArtifactPatternRegistry::default();
        // A name that matches no artifact pattern, but the dir carries a
        // validated root CACHEDIR.TAG (marker set by the walker).
        let classification = registry.classify(
            Path::new("/data/tmp/srw"),
            StructuralSignals {
                has_cachedir_tag: true,
                ..StructuralSignals::default()
            },
        );
        assert_eq!(classification.pattern_name, "cachedir-tagged-cache");
        assert_eq!(classification.category, ArtifactCategory::CacheDir);
        assert!(classification.structural_confidence > 0.90);
        assert!(classification.combined_confidence > 0.70);
    }

    #[test]
    fn cachedir_tag_does_not_override_a_matched_name() {
        let registry = ArtifactPatternRegistry::default();
        // node_modules matches by name; the tag must not downgrade it to CacheDir.
        let classification = registry.classify(
            Path::new("node_modules"),
            StructuralSignals {
                has_cachedir_tag: true,
                ..StructuralSignals::default()
            },
        );
        assert_eq!(classification.category, ArtifactCategory::NodeModules);
    }

    #[test]
    fn cachedir_tag_gives_high_structural_score() {
        assert!(
            structural_score(
                ArtifactCategory::CacheDir,
                StructuralSignals {
                    has_cachedir_tag: true,
                    ..StructuralSignals::default()
                }
            ) > 0.90
        );
        // But .git still wins — never score a checkout as reclaimable.
        assert_eq!(
            structural_score(
                ArtifactCategory::CacheDir,
                StructuralSignals {
                    has_cachedir_tag: true,
                    has_git: true,
                    ..StructuralSignals::default()
                }
            ),
            0.0
        );
    }

    #[test]
    fn target_underscore_prefix_classifies_as_rust_target() {
        let registry = ArtifactPatternRegistry::default();
        let classification = registry.classify(
            Path::new("target_rust_fuzz_42"),
            StructuralSignals::default(),
        );

        assert_eq!(classification.pattern_name, "target-underscore-prefix");
        assert_eq!(classification.category, ArtifactCategory::RustTarget);
        assert_eq!(
            extract_pattern_label("/data/projects/target_rust_fuzz_42"),
            "target_*"
        );
    }

    #[test]
    fn node_modules_is_classified_correctly() {
        let registry = ArtifactPatternRegistry::default();
        let classification =
            registry.classify(Path::new("node_modules"), StructuralSignals::default());
        assert_eq!(classification.category, ArtifactCategory::NodeModules);
        assert!(classification.combined_confidence > 0.60);
    }

    #[test]
    fn opaque_tree_marks_git_as_protected() {
        let opaque = classify_opaque_tree(Path::new("/repo/.git"), OpaqueTreeContext::default())
            .expect(".git should be opaque");

        assert_eq!(opaque.disposition, OpaqueTreeDisposition::ProtectedOpaque);
        assert_eq!(opaque.classification.category, ArtifactCategory::Unknown);
        assert!(opaque.reason.contains("protected"));
    }

    #[test]
    fn opaque_tree_promotes_contextual_target_candidate() {
        let opaque = classify_opaque_tree(
            Path::new("/repo/target"),
            OpaqueTreeContext {
                parent_has_cargo_toml: true,
                parent_has_node_manifest: false,
            },
        )
        .expect("target should be classified");

        assert_eq!(opaque.disposition, OpaqueTreeDisposition::CandidateOpaque);
        assert_eq!(opaque.classification.category, ArtifactCategory::RustTarget);
        assert_eq!(opaque.classification.pattern_name, "opaque-cargo-target");
    }

    #[test]
    fn opaque_tree_does_not_promote_broad_target_like_names_in_source_context() {
        for path in ["/repo/target_docs", "/repo/target-dev", "/repo/build"] {
            let opaque = classify_opaque_tree(
                Path::new(path),
                OpaqueTreeContext {
                    parent_has_cargo_toml: true,
                    parent_has_node_manifest: false,
                },
            );

            assert_ne!(
                opaque.map(|opaque| opaque.disposition),
                Some(OpaqueTreeDisposition::CandidateOpaque),
                "{path} must not become an opaque source-tree candidate"
            );
        }
    }

    #[test]
    fn cargo_registry_internal_paths_are_detected_strictly_inside_stores() {
        for p in [
            "/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/target-triple-1.0.0",
            "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/target-lexicon-0.13.5/src",
            "/data/tmp/rch-cargo-home-abc/registry/cache/index.crates.io-1949cf8c6b5b557f/x.crate",
            "/root/.cargo/registry/index/index.crates.io-1949cf8c6b5b557f/.cache",
            "/root/.cargo/git/checkouts/foo-1234abcd/deadbeef/target-thing",
            "/root/.cargo/git/db/foo-1234abcd/objects",
        ] {
            assert!(is_cargo_registry_internal_path(Path::new(p)), "{p}");
        }
        // The stores and their roots stay outside: they are the reclaim unit.
        for p in [
            "/root/.cargo",
            "/root/.cargo/registry",
            "/root/.cargo/registry/src",
            "/root/.cargo/registry/cache",
            "/root/.cargo/git",
            "/root/.cargo/git/checkouts",
            "/data/projects/app/target",
            "/data/projects/registry/target-x",
            "/repo/.git/objects",
        ] {
            assert!(!is_cargo_registry_internal_path(Path::new(p)), "{p}");
        }
    }

    #[test]
    fn opaque_tree_protects_crate_source_under_cargo_stores() {
        // Regression: `target-triple-1.0.0` unpacked under a temp-like
        // CARGO_HOME used to be promoted to a 0.93 RustTarget candidate on its
        // name alone. Store content is protected opaque regardless of name.
        for p in [
            "/data/tmp/rch-cargo-home-abc/registry/src/index.crates.io-1949cf8c6b5b557f/target-triple-1.0.0",
            "/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/target-lexicon-0.13.5",
            "/tmp/ch/git/checkouts/foo-1234abcd/deadbeef/cass-ft-target",
            "/tmp/ch/registry/src/index.crates.io-1949cf8c6b5b557f/node_modules",
        ] {
            let opaque = classify_opaque_tree(
                Path::new(p),
                OpaqueTreeContext {
                    parent_has_cargo_toml: true,
                    parent_has_node_manifest: true,
                },
            )
            .unwrap_or_else(|| panic!("{p} should be classified"));
            assert_eq!(
                opaque.disposition,
                OpaqueTreeDisposition::ProtectedOpaque,
                "{p}"
            );
            assert_eq!(opaque.classification.category, ArtifactCategory::Unknown);
        }

        // The store root is still the whole-store cache candidate.
        let root = classify_opaque_tree(
            Path::new("/root/.cargo/registry"),
            OpaqueTreeContext::default(),
        )
        .expect("registry root should be classified");
        assert_eq!(root.disposition, OpaqueTreeDisposition::CandidateOpaque);
        assert_eq!(root.classification.pattern_name, "opaque-cargo-cache");
    }

    #[test]
    fn name_registry_never_classifies_crate_source_under_cargo_stores() {
        let registry = ArtifactPatternRegistry::default();
        let classification = registry.classify(
            Path::new(
                "/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/target-triple-1.0.0",
            ),
            StructuralSignals::default(),
        );
        assert_eq!(classification.category, ArtifactCategory::Unknown);
        assert_eq!(classification.combined_confidence, 0.0);

        // Same basename outside a store still hits the name rule.
        let outside = registry.classify(
            Path::new("/data/tmp/target-triple-1.0.0"),
            StructuralSignals::default(),
        );
        assert_eq!(outside.pattern_name, "target-prefix");
    }

    #[test]
    fn opaque_tree_broad_target_prefix_under_tmp_requires_cargo_root_markers() {
        // `/tmp` is temp-like on every platform sbh supports (it stays a
        // `/tmp`-prefixed string even where it is a symlink).
        let base = tempfile::tempdir_in("/tmp").expect("tempdir under /tmp");

        // A crate-like tree that merely starts with `target-`: SignalOnly.
        let source = base.path().join("target-triple-1.0.0");
        std::fs::create_dir_all(source.join("src")).unwrap();
        std::fs::write(source.join("Cargo.toml"), "[package]\nname = \"t\"\n").unwrap();
        std::fs::write(source.join("src/lib.rs"), "").unwrap();
        let opaque = classify_opaque_tree(&source, OpaqueTreeContext::default())
            .expect("target-prefixed name is still target-like");
        assert_eq!(opaque.disposition, OpaqueTreeDisposition::SignalOnly);
        assert!(opaque.reason.contains("lacks cargo build markers"));

        // The same prefix with a validated CACHEDIR.TAG at the root: candidate.
        let tagged = base.path().join("target-ci-1");
        std::fs::create_dir_all(&tagged).unwrap();
        std::fs::write(
            tagged.join("CACHEDIR.TAG"),
            "Signature: 8a477f597d28d172789f06886806bc55\n# cargo\n",
        )
        .unwrap();
        let opaque = classify_opaque_tree(&tagged, OpaqueTreeContext::default())
            .expect("tagged target should be classified");
        assert_eq!(opaque.disposition, OpaqueTreeDisposition::CandidateOpaque);
        assert_eq!(opaque.classification.pattern_name, "opaque-cargo-target");

        // A forged tag (wrong signature) does not count; a `debug/` profile
        // directory does.
        let forged = base.path().join("target_forged");
        std::fs::create_dir_all(&forged).unwrap();
        std::fs::write(forged.join("CACHEDIR.TAG"), "nope\n").unwrap();
        let opaque = classify_opaque_tree(&forged, OpaqueTreeContext::default()).unwrap();
        assert_eq!(opaque.disposition, OpaqueTreeDisposition::SignalOnly);
        std::fs::create_dir_all(forged.join("debug")).unwrap();
        let opaque = classify_opaque_tree(&forged, OpaqueTreeContext::default()).unwrap();
        assert_eq!(opaque.disposition, OpaqueTreeDisposition::CandidateOpaque);

        // Non-broad shapes keep the plain temp promotion (no markers needed).
        let descriptive = base.path().join("cass-ft-target");
        std::fs::create_dir_all(&descriptive).unwrap();
        let opaque = classify_opaque_tree(&descriptive, OpaqueTreeContext::default()).unwrap();
        assert_eq!(opaque.disposition, OpaqueTreeDisposition::CandidateOpaque);
        let plain = base.path().join("target");
        std::fs::create_dir_all(&plain).unwrap();
        let opaque = classify_opaque_tree(&plain, OpaqueTreeContext::default()).unwrap();
        assert_eq!(opaque.disposition, OpaqueTreeDisposition::CandidateOpaque);
    }

    #[test]
    fn opaque_tree_promotes_descriptive_target_suffix_under_root() {
        // The backstop: `/root/cass-ft-target` is nominated as a single opaque
        // RustTarget candidate (was SignalOnly) even with no tmp/agent context.
        let opaque = classify_opaque_tree(
            Path::new("/root/cass-ft-target"),
            OpaqueTreeContext::default(),
        )
        .expect("descriptive -target suffix should be classified");
        assert_eq!(opaque.disposition, OpaqueTreeDisposition::CandidateOpaque);
        assert_eq!(opaque.classification.category, ArtifactCategory::RustTarget);
        assert_eq!(opaque.classification.pattern_name, "opaque-cargo-target");

        // `_target` suffix works the same way.
        let underscore =
            classify_opaque_tree(Path::new("/root/foo_target"), OpaqueTreeContext::default())
                .expect("descriptive _target suffix should be classified");
        assert_eq!(
            underscore.disposition,
            OpaqueTreeDisposition::CandidateOpaque
        );
    }

    #[test]
    fn opaque_tree_does_not_promote_sensitive_root_dirs() {
        // Sacred/system-protected root dirs must never be nominated as opaque
        // candidates by the classifier.
        assert!(
            classify_opaque_tree(Path::new("/root/.rustup"), OpaqueTreeContext::default())
                .is_none()
        );
        assert!(
            classify_opaque_tree(Path::new("/root/.ssh"), OpaqueTreeContext::default()).is_none()
        );
    }

    #[test]
    fn descriptive_target_suffix_requires_nonempty_prefix() {
        assert!(has_descriptive_target_suffix("cass-ft-target"));
        assert!(has_descriptive_target_suffix("foo_target"));
        assert!(has_descriptive_target_suffix("hfdt-release-target"));
        assert!(has_descriptive_target_suffix("my-target"));
        // Empty prefix / no separator / bare word must not match.
        assert!(!has_descriptive_target_suffix("-target"));
        assert!(!has_descriptive_target_suffix("_target"));
        assert!(!has_descriptive_target_suffix("target"));
        assert!(!has_descriptive_target_suffix("mytarget"));
        assert!(!has_descriptive_target_suffix("targets"));
    }

    #[test]
    fn is_obvious_build_artifact_basename_covers_suffix_but_not_secrets() {
        for name in [
            "cass-ft-target",
            "foo_target",
            "hfdt-release-target",
            "target",
        ] {
            assert!(
                is_obvious_build_artifact_basename(Path::new(name)),
                "{name}"
            );
        }
        for name in [".ssh", ".rustup", ".cargo", ".config", ".local", "mytarget"] {
            assert!(
                !is_obvious_build_artifact_basename(Path::new(name)),
                "{name}"
            );
        }
    }

    #[test]
    fn opaque_tree_does_not_promote_ambiguous_dependency_dirs() {
        for path in [
            "/repo/vendor",
            "/repo/site-packages",
            "/repo/.venv",
            "/repo/.pnpm-store",
        ] {
            let opaque =
                classify_opaque_tree(Path::new(path), OpaqueTreeContext::default()).unwrap();
            assert_eq!(opaque.disposition, OpaqueTreeDisposition::SignalOnly);
            assert_eq!(opaque.classification.category, ArtifactCategory::Unknown);
        }
    }

    #[test]
    fn opaque_tree_requires_context_for_node_modules() {
        let ambiguous = classify_opaque_tree(
            Path::new("/repo/node_modules"),
            OpaqueTreeContext::default(),
        )
        .unwrap();
        assert_eq!(ambiguous.disposition, OpaqueTreeDisposition::SignalOnly);

        let contextual = classify_opaque_tree(
            Path::new("/repo/node_modules"),
            OpaqueTreeContext {
                parent_has_cargo_toml: false,
                parent_has_node_manifest: true,
            },
        )
        .unwrap();
        assert_eq!(
            contextual.disposition,
            OpaqueTreeDisposition::CandidateOpaque
        );
        assert_eq!(
            contextual.classification.category,
            ArtifactCategory::NodeModules
        );
    }

    #[test]
    fn custom_patterns_are_honored() {
        let registry = ArtifactPatternRegistry::default().with_custom(vec![CustomPattern {
            name: "my-cache".to_string(),
            needle: "mytool-cache".to_string(),
            confidence: 0.88,
            category: ArtifactCategory::CacheDir,
        }]);
        let classification =
            registry.classify(Path::new("mytool-cache-prod"), StructuralSignals::default());
        assert_eq!(classification.pattern_name, "my-cache");
        assert_eq!(classification.category, ArtifactCategory::CacheDir);
        assert!(classification.combined_confidence > 0.60);
    }

    #[test]
    fn xcode_derived_data_project_root_is_build_output() {
        let registry = ArtifactPatternRegistry::default();
        let path = Path::new("/Users/operator/Library/Developer/Xcode/DerivedData/sbh-demo-abc123");
        let classification = classify_macos(
            &registry,
            path,
            StructuralSignals {
                has_build: true,
                mostly_object_files: true,
                ..StructuralSignals::default()
            },
        );

        assert_eq!(classification.pattern_name, "xcode-derived-data");
        assert_eq!(classification.category, ArtifactCategory::BuildOutput);
        assert!(classification.combined_confidence > 0.80);
        assert_eq!(
            extract_macos_pattern_label(path.to_str().unwrap()),
            "xcode-derived-data"
        );
    }

    #[test]
    fn xcode_derived_data_root_itself_is_not_the_cleanup_candidate() {
        let registry = ArtifactPatternRegistry::default();
        let classification = classify_macos(
            &registry,
            Path::new("/Users/operator/Library/Developer/Xcode/DerivedData"),
            StructuralSignals::default(),
        );

        assert_ne!(classification.pattern_name, "xcode-derived-data");
    }

    #[test]
    fn core_simulator_caches_are_classified_but_devices_are_not() {
        let registry = ArtifactPatternRegistry::default();
        let cache_path =
            Path::new("/Users/operator/Library/Developer/CoreSimulator/Caches/device-cache");
        let cache_classification =
            classify_macos(&registry, cache_path, StructuralSignals::default());

        assert_eq!(cache_classification.pattern_name, "core-simulator-caches");
        assert_eq!(cache_classification.category, ArtifactCategory::CacheDir);
        assert!(cache_classification.combined_confidence > 0.75);
        assert_eq!(
            extract_macos_pattern_label(cache_path.to_str().unwrap()),
            "core-simulator-caches"
        );

        let device_path = Path::new(
            "/Users/operator/Library/Developer/CoreSimulator/Devices/ABCDEF/data/Library/Caches",
        );
        let device_classification =
            classify_macos(&registry, device_path, StructuralSignals::default());

        assert_ne!(device_classification.pattern_name, "core-simulator-caches");
        assert_ne!(
            extract_macos_pattern_label(device_path.to_str().unwrap()),
            "core-simulator-caches"
        );
    }

    #[test]
    fn electron_application_support_cache_shapes_are_classified() {
        let registry = ArtifactPatternRegistry::default();
        let cases = [
            (
                "/Users/operator/Library/Application Support/Claude/Cache",
                "electron-cache",
            ),
            (
                "/Users/operator/Library/Application Support/Slack/Service Worker/CacheStorage/session",
                "electron-service-worker-cache",
            ),
            (
                "/Users/operator/Library/Application Support/Code/Code Cache/js",
                "electron-code-cache",
            ),
            (
                "/Users/operator/Library/Application Support/Discord/GPUCache",
                "electron-gpu-cache",
            ),
            (
                "/Users/operator/Library/Application Support/Cursor/IndexedDB",
                "electron-indexed-db",
            ),
            (
                "/Users/operator/Library/Application Support/Claude/vm_bundles/claudevm.bundle",
                "electron-vm-bundles",
            ),
        ];

        for (path, expected_pattern) in cases {
            let classification =
                classify_macos(&registry, Path::new(path), StructuralSignals::default());
            assert_eq!(
                classification.pattern_name, expected_pattern,
                "unexpected pattern for {path}"
            );
            assert_eq!(classification.category, ArtifactCategory::CacheDir);
            assert!(classification.combined_confidence > 0.70);
            assert_eq!(extract_macos_pattern_label(path), expected_pattern);
        }
    }

    #[test]
    fn application_support_app_root_is_not_an_electron_cache_candidate() {
        let registry = ArtifactPatternRegistry::default();
        let classification = classify_macos(
            &registry,
            Path::new("/Users/operator/Library/Application Support/Claude"),
            StructuralSignals::default(),
        );

        assert_ne!(classification.pattern_name, "electron-cache");
        assert_ne!(classification.pattern_name, "electron-service-worker-cache");
    }

    #[test]
    fn release_work_buildroot_shapes_are_classified() {
        let registry = ArtifactPatternRegistry::default();
        for path in [
            "/Users/operator/release-work/mcp_agent_mail_rust_buildroot",
            "/Users/operator/release-work/mcp-agent-mail-rust-buildroot",
        ] {
            let classification =
                classify_macos(&registry, Path::new(path), StructuralSignals::default());

            assert_eq!(classification.pattern_name, "release-work-buildroot");
            assert_eq!(classification.category, ArtifactCategory::BuildOutput);
            assert!(classification.combined_confidence > 0.70);
            assert_eq!(extract_macos_pattern_label(path), "release-work-buildroot");
        }
    }

    #[test]
    fn ipsw_updates_are_classified_only_in_software_updates_dir() {
        let registry = ArtifactPatternRegistry::default();
        let firmware =
            Path::new("/Users/operator/Library/iTunes/iPhone Software Updates/iPhone_17.ipsw");
        let classification = classify_macos(&registry, firmware, StructuralSignals::default());

        assert_eq!(classification.pattern_name, "ipsw-software-updates");
        assert_eq!(classification.category, ArtifactCategory::CacheDir);
        assert!(classification.combined_confidence > 0.75);
        assert_eq!(
            extract_macos_pattern_label(firmware.to_str().unwrap()),
            "ipsw-software-updates"
        );

        let downloads = Path::new("/Users/operator/Downloads/iPhone_17.ipsw");
        let downloads_classification =
            classify_macos(&registry, downloads, StructuralSignals::default());

        assert_ne!(
            downloads_classification.pattern_name,
            "ipsw-software-updates"
        );
        assert_ne!(
            extract_macos_pattern_label(downloads.to_str().unwrap()),
            "ipsw-software-updates"
        );
    }

    #[test]
    fn buildroot_outside_release_work_is_not_the_release_work_pattern() {
        let registry = ArtifactPatternRegistry::default();
        for path in [
            "/Users/operator/projects/app-buildroot",
            "/Users/operator/projects/app_buildroot",
        ] {
            let classification =
                classify_macos(&registry, Path::new(path), StructuralSignals::default());

            assert_ne!(classification.pattern_name, "release-work-buildroot");
        }
    }

    #[test]
    fn volatile_user_named_trash_shapes_are_review_candidates() {
        let registry = ArtifactPatternRegistry::default();
        for path in [
            "/private/tmp/trash",
            "/private/tmp/trashed",
            "/private/tmp/frankenterm-trash-20260503",
            "/tmp/agent-trash-20260507",
        ] {
            let classification =
                classify_macos(&registry, Path::new(path), StructuralSignals::default());

            assert_eq!(
                classification.pattern_name, "user-named-trash",
                "unexpected pattern for {path}"
            );
            assert_eq!(classification.category, ArtifactCategory::TempDir);
            assert_eq!(extract_macos_pattern_label(path), "user-named-trash");
        }
    }

    #[test]
    fn project_trash_name_is_not_a_cleanup_pattern() {
        let registry = ArtifactPatternRegistry::default();
        let classification = classify_macos(
            &registry,
            Path::new("/data/projects/app/trash"),
            StructuralSignals::default(),
        );

        assert_ne!(classification.pattern_name, "user-named-trash");
    }

    #[test]
    fn linux_temp_target_catalog_uses_shared_classification() {
        let registry = ArtifactPatternRegistry::default();
        let path = Path::new("/data/tmp/cass_append_baseline_target");
        let classification = classify_linux(&registry, path, StructuralSignals::default());

        assert_eq!(
            classification.pattern_name,
            "linux-data-tmp-underscore-target"
        );
        assert_eq!(classification.category, ArtifactCategory::RustTarget);
        assert_eq!(
            extract_pattern_label_with_cleanup_rules(
                path.to_str().unwrap(),
                linux::cleanup_catalog::cleanup_rules(),
            ),
            "linux-data-tmp-underscore-target"
        );
    }

    #[test]
    fn cargo_toml_presence_penalizes_score() {
        let registry = ArtifactPatternRegistry::default();
        // A name that would normally get 0.94 confidence ("cargo-target-...")
        let classification = registry.classify(
            Path::new("cargo-target-project"),
            StructuralSignals {
                has_cargo_toml: true,
                ..StructuralSignals::default()
            },
        );
        // Should be crushed to < 0.1 despite the name match.
        assert!(
            classification.combined_confidence < 0.1,
            "score {} was not penalized enough",
            classification.combined_confidence
        );
    }

    #[test]
    fn underscore_target_source_root_is_penalized_by_cargo_toml() {
        let registry = ArtifactPatternRegistry::default();
        let classification = registry.classify(
            Path::new("/data/projects/asupersync_ansi_c/tools/rust_fuzz_target"),
            StructuralSignals {
                has_cargo_toml: true,
                ..StructuralSignals::default()
            },
        );

        assert_eq!(classification.pattern_name, "underscore-target-suffix");
        assert_eq!(classification.category, ArtifactCategory::RustTarget);
        assert!(
            classification.combined_confidence < 0.1,
            "Cargo.toml source root should crush *_target confidence, got {}",
            classification.combined_confidence
        );
    }

    #[test]
    fn structural_rescue_with_few_markers_gets_base_confidence() {
        let registry = ArtifactPatternRegistry::default();
        // Only fingerprint present (1 marker) — should get base rescue confidence.
        let classification = registry.classify(
            Path::new("debug"),
            StructuralSignals {
                has_fingerprint: true,
                ..StructuralSignals::default()
            },
        );
        assert_eq!(classification.category, ArtifactCategory::RustTarget);
        assert_eq!(classification.pattern_name, "structural-rust-target");
        // combined = 0.70 * 0.55 + 0.30 * structural ≈ 0.68
        assert!(
            classification.combined_confidence < 0.72,
            "few markers should yield moderate confidence, got {:.3}",
            classification.combined_confidence
        );
    }

    #[test]
    fn structural_rescue_with_many_markers_gets_boosted_confidence() {
        let registry = ArtifactPatternRegistry::default();
        // Three cargo markers present — should get boosted rescue confidence.
        let classification = registry.classify(
            Path::new("debug"),
            StructuralSignals {
                has_fingerprint: true,
                has_incremental: true,
                has_deps: true,
                ..StructuralSignals::default()
            },
        );
        assert_eq!(classification.category, ArtifactCategory::RustTarget);
        assert_eq!(classification.pattern_name, "structural-rust-target");
        // combined = 0.70 * 0.75 + 0.30 * 0.98 ≈ 0.82
        assert!(
            classification.combined_confidence > 0.80,
            "3+ markers should yield high confidence, got {:.3}",
            classification.combined_confidence
        );
    }

    #[test]
    fn structural_rescue_with_all_markers_gets_boosted_confidence() {
        let registry = ArtifactPatternRegistry::default();
        // All four cargo markers — definitive evidence.
        let classification = registry.classify(
            Path::new("release"),
            StructuralSignals {
                has_fingerprint: true,
                has_incremental: true,
                has_deps: true,
                has_build: true,
                ..StructuralSignals::default()
            },
        );
        assert_eq!(classification.category, ArtifactCategory::RustTarget);
        assert!(
            classification.combined_confidence > 0.80,
            "all markers should yield high confidence, got {:.3}",
            classification.combined_confidence
        );
    }

    #[test]
    fn structural_rescue_does_not_fire_without_markers() {
        let registry = ArtifactPatternRegistry::default();
        // A directory named "debug" with NO cargo markers — should NOT be rescued.
        let classification = registry.classify(Path::new("debug"), StructuralSignals::default());
        assert_eq!(classification.category, ArtifactCategory::Unknown);
    }

    #[test]
    fn dot_rch_target_hyphen_is_classified() {
        let registry = ArtifactPatternRegistry::default();
        let classification = registry.classify(
            Path::new(".rch-target-quietwillow"),
            StructuralSignals::default(),
        );
        assert_eq!(classification.category, ArtifactCategory::RustTarget);
        assert!(classification.combined_confidence > 0.60);
    }

    #[test]
    fn dot_rch_target_bare_is_classified() {
        let registry = ArtifactPatternRegistry::default();
        let classification =
            registry.classify(Path::new(".rch-target"), StructuralSignals::default());
        assert_eq!(classification.category, ArtifactCategory::RustTarget);
        assert_eq!(classification.pattern_name, "rch-target-bare-dot");
        assert!(classification.combined_confidence > 0.60);
    }

    #[test]
    fn rch_target_bare_variants_all_classify_as_rust_target() {
        let registry = ArtifactPatternRegistry::default();
        for (name, expected_pattern) in [
            (".rch-target", "rch-target-bare-dot"),
            (".rch_target", "rch-target-bare-dot-underscore"),
            ("rch-target", "rch-target-bare-hyphen"),
            ("rch_target", "rch-target-bare-underscore"),
        ] {
            let classification = registry.classify(Path::new(name), StructuralSignals::default());
            assert_eq!(
                classification.category,
                ArtifactCategory::RustTarget,
                "{name} should classify as RustTarget"
            );
            assert_eq!(
                classification.pattern_name, expected_pattern,
                "{name} should match {expected_pattern}"
            );
        }
    }

    #[test]
    fn rch_target_bare_label_groups_with_other_rch_variants() {
        use super::extract_pattern_label;
        for name in [".rch-target", "rch-target", ".rch_target", "rch_target"] {
            assert_eq!(extract_pattern_label(name), "rch_target_*");
        }
    }

    #[test]
    fn tmp_agent_and_cache_patterns_from_real_world_dirs() {
        let registry = ArtifactPatternRegistry::default();
        let cases = [
            ("green-ft", ArtifactCategory::AgentWorkspace),
            ("frankenterm-build-1234", ArtifactCategory::AgentWorkspace),
            ("cargo-home-pearlstone", ArtifactCategory::TempDir),
            (".cargo_cache_runner", ArtifactCategory::CacheDir),
            ("work-target", ArtifactCategory::RustTarget),
        ];

        for (name, expected) in cases {
            let classification = registry.classify(Path::new(name), StructuralSignals::default());
            assert_eq!(
                classification.category, expected,
                "unexpected classification for {name}"
            );
            assert!(
                classification.combined_confidence > 0.55,
                "low confidence {:.2} for {name}",
                classification.combined_confidence
            );
        }
    }

    #[test]
    fn rch_cargo_home_dirs_classify_as_tempdir() {
        // rch creates isolated CARGO_HOME staging dirs named
        // `rch-cargo-home-<host>-<pid>-<uuid>`. They start with `rch-`, so
        // neither `cargo-home-prefix` ("cargo-home-") nor `tmp-cargo-home`
        // (".tmp_cargo_home_") fires — the dedicated `rch-cargo-home` prefix
        // is the backstop. Matching is by basename, so it works under any
        // parent dir (/tmp vs /data/tmp vs an arbitrary $TMPDIR).
        let registry = ArtifactPatternRegistry::default();
        for path in [
            "rch-cargo-home-ts2-12345-abcdef",
            "/tmp/rch-cargo-home-ts2-12345-abcdef",
            "/data/tmp/rch-cargo-home-vmi1234-987-deadbeef",
        ] {
            let classification = registry.classify(Path::new(path), StructuralSignals::default());
            assert_eq!(
                classification.pattern_name, "rch-cargo-home",
                "unexpected pattern for {path}"
            );
            assert_eq!(
                classification.category,
                ArtifactCategory::TempDir,
                "unexpected category for {path}"
            );
            assert_eq!(
                extract_pattern_label(path),
                "rch-cargo-home-*",
                "unexpected label for {path}"
            );
        }

        // Negative cases: the new prefix must NOT swallow other rch dirs or
        // source-shaped names, and the plain `cargo-home-` family must keep
        // matching its OWN (`cargo-home-prefix`) rule — not this one.
        let cargo_home = registry.classify(
            Path::new("cargo-home-pearlstone"),
            StructuralSignals::default(),
        );
        assert_eq!(cargo_home.pattern_name, "cargo-home-prefix");
        assert_eq!(cargo_home.category, ArtifactCategory::TempDir);

        let rch_target = registry.classify(
            Path::new("rch-target-thatlilac"),
            StructuralSignals::default(),
        );
        assert_ne!(rch_target.pattern_name, "rch-cargo-home");
        assert_eq!(rch_target.category, ArtifactCategory::RustTarget);

        // A real project name must never match the rch-cargo-home prefix.
        let project = registry.classify(Path::new("my-project"), StructuralSignals::default());
        assert_ne!(project.pattern_name, "rch-cargo-home");
    }

    #[test]
    fn cass_workspace_patterns_real_world_dirs() {
        // Real /tmp dir names observed during a recent agent session that
        // filled the tmpfs with 100+ GB of leftover cass dirs. Only the
        // `cass_*`/`cass-*` workspace shape — the cargo-target sibling
        // `cass-target-*` is asserted separately below since it has its
        // own (more specific) pattern that must keep winning.
        let registry = ArtifactPatternRegistry::default();
        let cases = [
            "cass_next_profile",          // 1.4 GB profile dir
            "cass_batch20_bench",         // 4 GB cargo target
            "cass_append_sqlcache_bench", // 4 GB cargo target
            "cass_swarm",                 // small scratch
            "cass_orchestrator",          // small scratch
            "cass_marching_orders.txt",   // small text artifact
        ];

        for name in cases {
            let classification = registry.classify(Path::new(name), StructuralSignals::default());
            assert_ne!(
                classification.category,
                ArtifactCategory::Unknown,
                "{name} should be classified, not Unknown"
            );
            assert!(
                classification.combined_confidence > 0.55,
                "low confidence {:.2} for {name}",
                classification.combined_confidence
            );
        }
    }

    #[test]
    fn cass_target_prefix_not_shadowed_by_cass_workspace_prefix() {
        // Regression guard: `cass-target-*` names match BOTH the pre-existing
        // `cass-target` Prefix pattern (RustTarget) and the broader new
        // `cass-prefix-hyphen` Prefix pattern (AgentWorkspace). The more
        // specific one must win — otherwise these dirs lose the cargo-marker
        // structural boost (0.92–0.98) and collapse to the flat 0.78
        // AgentWorkspace score, which can drop them below the deletion
        // confidence floor on machines without populated cargo signals.
        let registry = ArtifactPatternRegistry::default();
        for name in ["cass-target-thatlilac", "cass-target", "cass-target-foo"] {
            let classification = registry.classify(Path::new(name), StructuralSignals::default());
            assert_eq!(
                classification.category,
                ArtifactCategory::RustTarget,
                "{name} should classify as RustTarget, got {:?}",
                classification.category
            );
            assert_eq!(
                classification.pattern_name.as_ref(),
                "cass-target",
                "{name} should match the cass-target pattern, got {}",
                classification.pattern_name
            );
        }
    }

    #[test]
    fn underscore_target_suffix_classifies_as_rust_target() {
        // `cass_append_baseline_target`, `pi_agent_rust_target`, and any
        // future agent-prefixed `..._target` cargo dir.
        let registry = ArtifactPatternRegistry::default();
        for name in [
            "cass_append_baseline_target",
            "cass_append_patch_target",
            "build_target",
            "release_target",
        ] {
            let classification = registry.classify(Path::new(name), StructuralSignals::default());
            assert_eq!(
                classification.category,
                ArtifactCategory::RustTarget,
                "{name} should classify as RustTarget"
            );
        }
    }

    #[test]
    fn frankentui_workspace_patterns_real_world_dirs() {
        // Codex bead workspace dirs: 3.7 GB each, observed in /tmp.
        let registry = ArtifactPatternRegistry::default();
        let cases = [
            "frankentui-codex-bd-2vr05-10-2-workspace",
            "frankentui-codex-bd-2vr05-10-3-workspace",
            "frankentui-codex-bd-2vr05-10-4-workspace",
            "frankentui-codex-bd-2vr05-6-text-corpus",
            "frankentui-bd-2vr05-10-4-fuzz-pass3",
            "frankentui_profile_sweep_view.data",
            "frankentui_git_clone_stderr",
        ];

        for name in cases {
            let classification = registry.classify(Path::new(name), StructuralSignals::default());
            assert_eq!(
                classification.category,
                ArtifactCategory::AgentWorkspace,
                "{name} should classify as AgentWorkspace"
            );
            assert!(
                classification.combined_confidence > 0.55,
                "low confidence {:.2} for {name}",
                classification.combined_confidence
            );
        }
    }

    #[test]
    fn frankentui_does_not_collide_with_frankenterm() {
        // The pre-existing `frankenterm-` pattern still wins for its own
        // names; the new `frankentui-` does not steal them.
        let registry = ArtifactPatternRegistry::default();
        let frankenterm = registry.classify(
            Path::new("frankenterm-build-1234"),
            StructuralSignals::default(),
        );
        assert_eq!(frankenterm.category, ArtifactCategory::AgentWorkspace);
        let frankentui = registry.classify(
            Path::new("frankentui-codex-bd-2vr05-4"),
            StructuralSignals::default(),
        );
        assert_eq!(frankentui.category, ArtifactCategory::AgentWorkspace);
    }

    #[test]
    fn extract_pattern_label_groups_new_families() {
        use super::extract_pattern_label;
        // cass family (NOT cass-target — that has its own pre-existing
        // `cass-target*` label which is more specific and should win).
        assert_eq!(extract_pattern_label("/tmp/cass_next_profile"), "cass_*");
        assert_eq!(extract_pattern_label("/tmp/cass_swarm"), "cass_*");
        assert_eq!(extract_pattern_label("/tmp/cass-orchestrator"), "cass_*");
        // The pre-existing cass-target family is unchanged.
        assert_eq!(
            extract_pattern_label("/tmp/cass-target-thatlilac"),
            "cass-target*"
        );
        // _target suffix family.
        assert_eq!(
            extract_pattern_label("/data/projects/cass_append_baseline_target"),
            "*_target"
        );
        assert_eq!(
            extract_pattern_label("/data/projects/build_target"),
            "*_target"
        );
        // frankentui family — both forms collapse.
        assert_eq!(
            extract_pattern_label("/tmp/frankentui-codex-bd-2vr05-10-2-workspace"),
            "frankentui-*"
        );
        assert_eq!(
            extract_pattern_label("/tmp/frankentui_profile_sweep_view.data"),
            "frankentui-*"
        );
    }

    #[test]
    fn detects_go_build_cache_structurally_under_arbitrary_name() {
        let dir = tempfile::tempdir().unwrap();
        // A real GOCACHE never matches a name pattern when relocated like this.
        let root = dir.path().join("lumera_go_buildcache_taskstore");
        std::fs::create_dir_all(root.join("a1")).unwrap();
        std::fs::create_dir_all(root.join("ff")).unwrap();
        std::fs::write(root.join("trim.txt"), "v1\n").unwrap();
        std::fs::write(root.join("a1/abcdef0123-d"), "entry").unwrap();

        let opaque = classify_opaque_tree(&root, OpaqueTreeContext::default())
            .expect("go build cache should be an opaque candidate");
        assert_eq!(opaque.disposition, OpaqueTreeDisposition::CandidateOpaque);
        assert_eq!(opaque.classification.category, ArtifactCategory::GoCache);
        assert_eq!(opaque.classification.pattern_name, "opaque-go-build-cache");
    }

    #[test]
    fn detects_go_module_cache_structurally_under_arbitrary_name() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("lumera_ai_go_cache");
        std::fs::create_dir_all(root.join("cache/download/sumdb")).unwrap();
        let module = root.join("github.com/foo/bar@v1.2.3");
        std::fs::create_dir_all(&module).unwrap();
        std::fs::write(module.join("go.mod"), "module bar\n").unwrap();

        let opaque = classify_opaque_tree(&root, OpaqueTreeContext::default())
            .expect("go module cache should be an opaque candidate");
        assert_eq!(opaque.disposition, OpaqueTreeDisposition::CandidateOpaque);
        assert_eq!(opaque.classification.category, ArtifactCategory::GoCache);
        assert_eq!(opaque.classification.pattern_name, "opaque-go-mod-cache");
    }

    #[test]
    fn non_go_dir_whose_name_contains_go_is_not_a_go_cache() {
        let dir = tempfile::tempdir().unwrap();
        // Name passes the cheap pre-filter ("mongo" contains "go") but the
        // structural probe must reject it — no trim.txt/hex shards/cache.
        let root = dir.path().join("mongo-data");
        std::fs::create_dir_all(root.join("collection-0")).unwrap();
        std::fs::write(root.join("WiredTiger.wt"), "x").unwrap();

        let category = classify_opaque_tree(&root, OpaqueTreeContext::default())
            .map(|o| o.classification.category);
        assert_ne!(category, Some(ArtifactCategory::GoCache));
    }

    #[test]
    fn two_hex_char_name_predicate() {
        assert!(super::is_two_hex_char("00"));
        assert!(super::is_two_hex_char("ff"));
        assert!(super::is_two_hex_char("a1"));
        assert!(!super::is_two_hex_char("FF")); // uppercase excluded
        assert!(!super::is_two_hex_char("g0")); // non-hex
        assert!(!super::is_two_hex_char("abc")); // too long
        assert!(!super::is_two_hex_char("a")); // too short
    }
}
