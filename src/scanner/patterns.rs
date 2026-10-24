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
///
/// Serialized into the scanner index so a replayed opaque candidate is scored
/// with the evidence the walk found under it, not with the root's own entries.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
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
    /// A `pyvenv.cfg` at the root: the directory is a Python virtual
    /// environment. uv writes a `CACHEDIR.TAG` into every venv it creates (so
    /// that backup tools skip it), which does not make a venv a regenerable
    /// cache (see [`Self::regenerable_cache_tag`]).
    pub has_pyvenv_cfg: bool,
}

impl StructuralSignals {
    /// A `CACHEDIR.TAG` that marks a regenerable cache: not a venv's. On trj
    /// (2026-10-14) sbh quarantined three uv venvs a running release gate was
    /// using, at Green, as `cachedir-tagged-cache`; the gate's next step
    /// failed with `ModuleNotFoundError`.
    #[must_use]
    pub fn regenerable_cache_tag(&self) -> bool {
        self.has_cachedir_tag && !self.has_pyvenv_cfg
    }

    /// Returns true if the signals strongly indicate a build artifact directory
    /// (e.g., Rust target with incremental/deps/fingerprint markers, or mostly
    /// object files).
    #[must_use]
    pub fn has_strong_signal(&self) -> bool {
        // A validated CACHEDIR.TAG is a definitive, name-independent marker of a
        // regenerable cache directory — on its own it is a strong signal.
        if self.regenerable_cache_tag() {
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

    if let Some(opaque) = classify_code_sign_clone_area(path) {
        return Some(opaque);
    }

    // Anything strictly inside cargo's own stores (`registry/src`,
    // `registry/cache`, `registry/index`, `git/checkouts`, `git/db`) is
    // cargo-managed content — unpacked crate SOURCE, `.crate` archives, index
    // clones — never a build output. It must be checked before any name rule:
    // crates such as `target-triple-1.0.0` / `target-lexicon-0.13.5` unpack to
    // directories whose names satisfy the broad `target-` prefix, and a store
    // that lives under a temp-like `CARGO_HOME` would otherwise be promoted to
    // a 0.93 `opaque-cargo-target` candidate purely on that name. The stores
    // themselves are excluded here: they are the opaque reclaim unit handled
    // below (a cargo home's `registry` / `git` roots above them are kept).
    if is_cargo_registry_internal_path(path) {
        return Some(OpaqueTreeClassification::protected(
            "cargo registry/git store content is crate source, never a build target",
        ));
    }
    if is_uv_cache_internal_path(path) {
        return Some(OpaqueTreeClassification::protected(
            "uv cache entry content is installed packages, managed by uv",
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
        return Some(classify_cargo_target_name(path, &name, context, tmp_like));
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

    // A cargo home's `registry` and `git` themselves must survive: rch's per-job
    // CARGO_HOME symlinks them, and a removed root leaves the link dangling so
    // every crates.io download fails with EEXIST (hz4, 2026-09-26: a release
    // lost 33 min). Descend and reclaim the stores inside instead.
    if is_cargo_home_store_root(path) {
        return Some(OpaqueTreeClassification::signal_only(
            "cargo registry/git root is kept; its stores are the reclaim unit",
        ));
    }
    if is_cargo_cache_store(path) {
        return Some(OpaqueTreeClassification::candidate(
            "cargo registry/git store",
            "opaque-cargo-cache",
            ArtifactCategory::CacheDir,
            0.92,
        ));
    }

    if matches!(name.as_str(), ".next" | "dist" | "build")
        && (context.parent_has_node_manifest || tmp_like)
    {
        return Some(classify_build_output_name(path, &name, context));
    }

    None
}

/// Chromium browsers on macOS (Chrome, Canary, Edge, Brave, Opera) keep an
/// APFS clone of their app bundle, made at every launch and removed only when
/// the browser exits normally. Killed headless browsers left 1,027 of them on
/// mac-studio (2026-10-16, bd-39da). Only the clones are candidates, and
/// nothing else in the clone area is walked; the active-reference index marks
/// the clones a running browser may own (`walker::code_sign_clones`).
fn classify_code_sign_clone_area(path: &Path) -> Option<OpaqueTreeClassification> {
    Some(match darwin_code_sign_clone_level(path)? {
        CodeSignCloneLevel::CloneDir => OpaqueTreeClassification::candidate(
            "browser code-sign clone: a per-launch app copy its browser did not remove",
            "opaque-browser-code-sign-clone",
            ArtifactCategory::TempDir,
            0.93,
        ),
        CodeSignCloneLevel::Container => OpaqueTreeClassification::signal_only(
            "browser code-sign clone container: only the clones inside are candidates",
        ),
        CodeSignCloneLevel::Other => OpaqueTreeClassification::protected(
            "macOS code-sign clone area: only browser clones are candidates",
        ),
    })
}

/// A directory whose name is target-like ([`is_cargo_target_name`]).
///
/// The broad `target-<x>` / `target_<x>` PREFIX forms are the only
/// target-like shapes that ordinary crate and project names also satisfy
/// (`target-triple`, `target_spec`), so temp-like placement alone is not
/// enough to promote them: the tree must additionally carry a cargo build
/// marker at its root. Descriptive `<prefix>-target` / `<prefix>_target`
/// names need the same corroboration: release-evidence and fixture trees name
/// directories `invalid_target` or `ambient-target` on purpose, and on ts2
/// (2026-09-25) eight such directories inside non-git hfdt evidence bundles
/// were deleted on the name alone. A plain `target` with no Cargo manifest
/// beside it needs them too: hfdt stores keep a `target/` of their own
/// (store-doctor undo data), and on ts2 the daemon deleted two agent store
/// copies' `target` (2026-09-29) and nominated a 4.8 GB `target/doctor-undo`
/// on the name alone (2026-10-20, bd-u9ua). Cargo writes CACHEDIR.TAG and
/// .rustc_info.json into every target dir it builds in.
fn classify_cargo_target_name(
    path: &Path,
    name: &str,
    context: OpaqueTreeContext,
    tmp_like: bool,
) -> OpaqueTreeClassification {
    let needs_markers = has_broad_target_prefix(name)
        || has_descriptive_target_suffix(name)
        || (name == "target" && !context.parent_has_cargo_toml);
    let has_markers = needs_markers && has_cargo_target_root_markers(path);
    let tmp_promotes = tmp_like && (!needs_markers || has_markers);
    if (name == "target" && context.parent_has_cargo_toml)
        || tmp_promotes
        || is_agent_build_target_name(name)
        // A descriptive suffix name WITH cargo's root markers is a
        // `CARGO_TARGET_DIR` output, so V2 nominates it as a single opaque
        // candidate even without tmp/agent/parent-cargo context. This is
        // what lets a stranded `/root/cass-ft-target` be reclaimed. The
        // broad `target-`/`target_` PREFIX forms stay SignalOnly in a
        // source context, matching the conservative
        // `opaque_tree_does_not_promote_broad_target_like_names_in_source_context`
        // guarantee. All downstream deletion vetoes still apply.
        || (has_descriptive_target_suffix(name) && has_markers)
    {
        return OpaqueTreeClassification::candidate(
            "cargo/build target with regenerable context",
            "opaque-cargo-target",
            ArtifactCategory::RustTarget,
            0.93,
        );
    }
    OpaqueTreeClassification::signal_only(if tmp_like {
        "target-like name under temp storage lacks cargo build markers"
    } else {
        "target-like directory lacks cargo/temp context"
    })
}

/// `build` and `dist` also name source directories and the shipped code of
/// installed packages. They are output only beside the manifest of a tool that
/// writes them. On ts2 (2026-10-16) temp placement alone deleted tracked
/// `scripts/build/*.mjs` and golden-test fixtures from repo copies under
/// /data/tmp, and a `package.json` beside them deleted the `dist/` code of
/// packages in a bun install cache (bd-8nol).
fn classify_build_output_name(
    path: &Path,
    name: &str,
    context: OpaqueTreeContext,
) -> OpaqueTreeClassification {
    if name != ".next" {
        if installed_package_content(path) {
            return OpaqueTreeClassification::signal_only(
                "build/dist inside an installed or cached package is its shipped code",
            );
        }
        if !context.parent_has_node_manifest && !beside_producing_manifest(path, name) {
            return OpaqueTreeClassification::signal_only(
                "build/dist name without a manifest beside it whose tool writes it",
            );
        }
    }
    OpaqueTreeClassification::candidate(
        "build output with project/temp context",
        "opaque-build-output",
        ArtifactCategory::BuildOutput,
        0.88,
    )
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
/// Returns true if the directory name matches an obvious build/cache artifact directory.
pub(crate) fn is_obvious_artifact_name(name: &str) -> bool {
    is_exact_or_prefix_artifact_name(name) || has_descriptive_target_suffix(name)
}

/// The exact and prefix forms of [`is_obvious_artifact_name`], which name build
/// output on their own.
fn is_exact_or_prefix_artifact_name(name: &str) -> bool {
    // Exact-match basenames (alphabetized for ease of audit). Bare rch
    // target dir names without a job-suffix are included here so the prefix
    // matchers below can safely require a separator (`-` or `_`) — this
    // prevents `.rch-targetfoo` style false positives.
    let exact_artifacts: &[&str] = &[
        ".astro",
        ".cargo-target",
        ".dart_tool",
        ".docusaurus",
        ".gradle",
        ".mypy_cache",
        ".next",
        ".nuxt",
        ".parcel-cache",
        ".pytest_cache",
        ".rch-target",
        ".rch_target",
        ".ruff_cache",
        ".svelte-kit",
        ".target",
        ".tox",
        ".turbo",
        ".venv",
        ".vite",
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
    false
}

/// A name that is an artifact name only through the descriptive suffix
/// (`cass-ft-target`, `foo_target`, but also `invalid_target`).
fn is_suffix_only_artifact_name(name: &str) -> bool {
    has_descriptive_target_suffix(name) && !is_exact_or_prefix_artifact_name(name)
}

/// Whether the directory `path` named `name` is build output by its name.
/// A suffix-only name (`<x>-target`, `<x>_target`) names data as often as a
/// `CARGO_TARGET_DIR`, so it counts only with cargo's own target-root
/// markers; every other artifact name stands on its own.
fn is_corroborated_artifact_dir(path: &Path, name: &str) -> bool {
    !is_suffix_only_artifact_name(name) || has_cargo_target_root_markers(path)
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
    is_obvious_build_artifact_basename_given(path, false)
}

/// [`is_obvious_build_artifact_basename`], where `cargo_evidence` (the
/// walker's structural signals for this candidate, which the scorer already
/// holds) can stand in for reading a suffix-only name's root markers.
pub(crate) fn is_obvious_build_artifact_basename_given(path: &Path, cargo_evidence: bool) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };

    if is_obvious_artifact_name(name) {
        return cargo_evidence || is_corroborated_artifact_dir(path, name);
    }

    // Build-profile, output, and target-triple subdirectories produced by cargo or
    // other build tools are obvious build artifacts when nested under an
    // obvious build artifact directory (e.g. `target/debug`, `target/release`,
    // `target/doc`, `target/package`, `target/criterion`,
    // `.cargo-target/debug`, `build/debug`,
    // `target/x86_64-unknown-linux-gnu`, `target/x86_64-unknown-linux-gnu/debug`).
    if matches!(
        name,
        "debug" | "release" | "doc" | "package" | "criterion" | "bench" | "test" | "dev" | "tmp"
    ) || is_target_triple_basename(name)
    {
        return path.ancestors().skip(1).any(|ancestor| {
            ancestor
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| {
                    is_obvious_artifact_name(n) && is_corroborated_artifact_dir(ancestor, n)
                })
        });
    }

    false
}

/// Returns true if `name` matches a standard cross-compilation target triple
/// (e.g. `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`).
pub(crate) fn is_target_triple_basename(name: &str) -> bool {
    let parts: Vec<&str> = name.split('-').collect();
    if parts.len() < 3 {
        return false;
    }
    let arch = parts[0];
    let known_arch = matches!(
        arch,
        "x86_64"
            | "aarch64"
            | "i686"
            | "i586"
            | "arm"
            | "armv7"
            | "armv7a"
            | "armv6"
            | "riscv64"
            | "riscv64gc"
            | "wasm32"
            | "wasm64"
    );
    if !known_arch {
        return false;
    }
    parts.iter().skip(1).any(|p| {
        matches!(
            *p,
            "linux" | "darwin" | "apple" | "windows" | "musl" | "gnu" | "msvc" | "wasi" | "unknown"
        )
    })
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

/// A directory the Claude Code harness itself runs out of.
///
/// That is the per-user session root `claude-<uid>` (every live session's
/// scratchpads and background-task output) and the
/// `claude-mcp-browser-bridge-*` bridge. The broad `claude-` prefix rule
/// nominated both whole; on a Mac the daemon
/// deleted the bridge and tried the session root three times (2026-09-27),
/// stopped only by the open-file check. Artifacts inside stay reclaimable.
#[must_use]
pub fn is_agent_harness_dir_name(lowercase_name: &str) -> bool {
    lowercase_name.strip_prefix("claude-").is_some_and(|rest| {
        (!rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
            || rest.starts_with("mcp-browser-bridge")
    })
}

/// True when `path` lies strictly inside one of cargo's home stores.
///
/// The stores are `registry/src`, `registry/cache`, `registry/index`,
/// `git/checkouts` and `git/db` (any `CARGO_HOME`, not only `~/.cargo`).
/// Everything below those directories is cargo-managed content: unpacked
/// crate source, `.crate` archives, index clones, git checkouts. None of it
/// is a build output, so no name pattern may nominate it and the deletion
/// scorer vetoes it outright. The store directories themselves are
/// deliberately NOT matched: they are the opaque, whole-store reclaim unit
/// (`opaque-cargo-cache` / the cleanup catalog). The `registry` / `git`
/// roots above them are never nominated: `classify_opaque_tree` keeps them
/// signal-only for every cargo home it recognises (`is_cargo_home`), because
/// rch symlinks them. Sacred protection does not cover them; the classifier
/// does.
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

/// True when `path` lies strictly inside an entry of uv's unpacked-package or
/// tool-environment buckets, `uv/archive-vN/<entry>/` or
/// `uv/environments-vN/<entry>/`.
///
/// Those are installed packages that running interpreters import from. On
/// css (2026-10-16) sbh nominated 397 `__pycache__` directories inside them
/// on the name alone and the executor refused each one as open, 300-600
/// times an hour (bd-p9fw). The uv cache as a whole stays a reclaim unit.
#[must_use]
pub fn is_uv_cache_internal_path(path: &Path) -> bool {
    let is_bucket = |name: &str| {
        ["archive-v", "environments-v"].iter().any(|prefix| {
            name.strip_prefix(prefix).is_some_and(|version| {
                !version.is_empty() && version.bytes().all(|b| b.is_ascii_digit())
            })
        })
    };
    // The entry must be a STRICT ancestor: the entry itself is uv's unit.
    path.ancestors().skip(1).any(|entry| {
        let mut above = entry.ancestors().skip(1).map(Path::file_name);
        matches!(
            (above.next().flatten().and_then(|n| n.to_str()), above.next().flatten()),
            (Some(bucket), Some(uv)) if is_bucket(bucket) && uv == "uv"
        )
    })
}

/// Name-only rules for agent scratch (`cass_*`, `frankenterm-*`, `pi_agent_*`,
/// `claude-*`, ...) describe directories an agent creates directly in a temp
/// root. Deeper, the same names are someone's data: the fleet deleted
/// checked-in fuzz corpora (`<clone>/fuzz/corpus/cass_import_jsonl`), backups
/// (`/tmp/backup_repo_files/frankentui_untracked`) and rch run mirrors
/// (`/tmp/rch-run/frankenterm-<hash>`) on name alone (2026-09-15..27).
fn is_temp_root_scoped(pattern: &ArtifactPattern) -> bool {
    pattern.category == ArtifactCategory::AgentWorkspace || pattern.name == "claude-session-cache"
}

/// A temp root itself (not a path inside one).
fn is_temp_root_dir(path: &Path) -> bool {
    [
        "/tmp",
        "/var/tmp",
        "/data/tmp",
        "/private/tmp",
        "/private/var/tmp",
    ]
    .iter()
    .any(|root| path == Path::new(root))
        || (path.file_name().is_some_and(|name| name == "T")
            && is_darwin_user_temp_path(&path.join("entry")))
}

fn is_tmp_like_path(path: &Path) -> bool {
    ["/tmp", "/var/tmp", "/data/tmp", "/private/tmp"]
        .iter()
        .any(|root| {
            let root = Path::new(root);
            path == root || path.starts_with(root)
        })
        || is_darwin_user_temp_path(path)
}

/// Anything inside a macOS per-user temp dir, `$TMPDIR` =
/// `/var/folders/<xx>/<hash>/T` (or its `/private/var/...` spelling).
///
/// It is the Mac equivalent of `/tmp` for everything that honours `TMPDIR`
/// (cargo test fixtures, build scratch), yet no temp-root list knew it, so a
/// target there scored `Review` where the same target in `/tmp` scored
/// `Delete` (first native macOS test run, 2026-09-25). Only `T` counts: `C`
/// is the per-user cache dir and `0` belongs to the system.
#[must_use]
pub fn is_darwin_user_temp_path(path: &Path) -> bool {
    matches!(
        darwin_per_user_folder_names(path).as_deref(),
        Some(["T", _, ..])
    )
}

/// The names below a macOS per-user folder, `/var/folders/<xx>/<hash>/` (or
/// its `/private/var/...` spelling): `["T", "entry"]` for an entry in the
/// temp dir. Only plain names count: a `.` or `..` could step out of the
/// folder while still matching the pattern textually.
fn darwin_per_user_folder_names(path: &Path) -> Option<Vec<&str>> {
    use std::path::Component;
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return None;
    }
    let names: Vec<&str> = components
        .map(|part| match part {
            Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect::<Option<_>>()?;
    let names = names.strip_prefix(&["private"]).unwrap_or(&names);
    match names {
        ["var", "folders", _, _, below @ ..] => Some(below.to_vec()),
        _ => None,
    }
}

/// Where a path sits in a macOS per-user code-sign clone area,
/// `/var/folders/<xx>/<hash>/X`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodeSignCloneLevel {
    /// `X/<bundle-id>.code_sign_clone`: one browser's clones.
    Container,
    /// `X/<bundle-id>.code_sign_clone/code_sign_clone.XXXXXX`: one clone.
    CloneDir,
    /// Anything else directly in `X` or in a container.
    Other,
}

fn darwin_code_sign_clone_level(path: &Path) -> Option<CodeSignCloneLevel> {
    let is_container = |name: &str| {
        name.strip_suffix(".code_sign_clone")
            .is_some_and(|bundle_id| !bundle_id.is_empty())
    };
    match darwin_per_user_folder_names(path)?.as_slice() {
        ["X", name] if is_container(name) => Some(CodeSignCloneLevel::Container),
        ["X", container, name] if is_container(container) && is_code_sign_clone_name(name) => {
            Some(CodeSignCloneLevel::CloneDir)
        }
        ["X", _] => Some(CodeSignCloneLevel::Other),
        ["X", container, _] if is_container(container) => Some(CodeSignCloneLevel::Other),
        _ => None,
    }
}

/// One browser's app clone,
/// `/var/folders/<xx>/<hash>/X/<bundle-id>.code_sign_clone/code_sign_clone.XXXXXX`.
#[must_use]
pub fn is_browser_code_sign_clone(path: &Path) -> bool {
    darwin_code_sign_clone_level(path) == Some(CodeSignCloneLevel::CloneDir)
}

/// `code_sign_clone.XXXXXX`, the `mkdtemp` name Chromium gives each clone.
fn is_code_sign_clone_name(name: &str) -> bool {
    name.strip_prefix("code_sign_clone.").is_some_and(|suffix| {
        suffix.len() == 6 && suffix.bytes().all(|b| b.is_ascii_alphanumeric())
    })
}

/// The code-sign clone area beside a macOS per-user temp dir root: `X` for
/// `/var/folders/<xx>/<hash>/T`. Scanning a user's temp dir includes the
/// clones their browsers leave there; see [`classify_opaque_tree`].
#[must_use]
pub fn darwin_code_sign_clone_area_for_temp_root(root: &Path) -> Option<std::path::PathBuf> {
    matches!(darwin_per_user_folder_names(root).as_deref(), Some(["T"]))
        .then(|| root.with_file_name("X"))
}

/// `registry` or `git` directly inside a cargo home (see [`is_cargo_home`]).
fn is_cargo_home_store_root(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, "registry" | "git"))
        && path.parent().is_some_and(is_cargo_home)
}

/// A directory cargo uses as `CARGO_HOME`: `.cargo`, rch's shared
/// `rch-cargo-cache-<host>` stores, or any directory holding cargo's
/// `.package-cache` lock file.
///
/// Recognising only `.cargo` left the rch stores' `registry`/`git` roots to
/// the CACHEDIR.TAG rescue, which nominated them whole: on csd (2026-10-23)
/// Green event passes quarantined `rch-cargo-cache-csd/{git,registry}`
/// hourly while builds re-created them, the root removal the hz4 guard
/// below exists to prevent.
fn is_cargo_home(dir: &Path) -> bool {
    dir.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == ".cargo" || name.starts_with("rch-cargo-cache"))
        || dir.join(".package-cache").is_file()
}

/// A regenerable store directly inside a cargo-home root:
/// `<cargo home>/registry/{cache,src,index}` or `<cargo home>/git/{checkouts,db}`.
fn is_cargo_cache_store(path: &Path) -> bool {
    let (Some(name), Some(root)) = (
        path.file_name().and_then(|name| name.to_str()),
        path.parent(),
    ) else {
        return false;
    };
    is_cargo_home_store_root(root)
        && match root.file_name().and_then(|name| name.to_str()) {
            Some("registry") => matches!(name, "cache" | "src" | "index"),
            Some("git") => matches!(name, "checkouts" | "db"),
            _ => false,
        }
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
        // whatever its basename looks like (`target-triple-1.0.0`), and
        // neither is a package uv unpacked or installed in its cache.
        if is_cargo_registry_internal_path(path) || is_uv_cache_internal_path(path) {
            return ArtifactClassification::unknown();
        }
        let normalized = name_os.to_string_lossy().to_lowercase();
        if is_agent_harness_dir_name(&normalized) {
            return ArtifactClassification::unknown();
        }

        let catalog_classification = cleanup_catalog_path_classification(path, cleanup_rules, home);
        let mut best = catalog_classification
            .clone()
            .unwrap_or_else(ArtifactClassification::unknown);
        let in_temp_root = path.parent().is_some_and(is_temp_root_dir);
        for pattern in &self.builtins {
            if matches_builtin(pattern.kind, &normalized)
                && pattern.confidence > best.name_confidence
                && (in_temp_root || !is_temp_root_scoped(pattern))
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

        if best.category == ArtifactCategory::Unknown
            && is_tmp_like_path(path)
            && is_mktemp_scratch_name(&name_os.to_string_lossy())
            && !inside_project_tree(path)
        {
            best = ArtifactClassification {
                pattern_name: Cow::Borrowed("mktemp-scratch"),
                category: ArtifactCategory::TempDir,
                name_confidence: 0.70,
                structural_confidence: 0.0,
                combined_confidence: 0.70,
            };
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
        } else if best.category == ArtifactCategory::Unknown && signals.regenerable_cache_tag() {
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

/// A `mktemp -d -t <prefix>.XXXXXXXX` name: a prefix, a dot, and 6-16 random
/// alphanumerics that mix upper and lower case (`fsfs-quickstart.ZH7Q3npF`,
/// plain `mktemp -d`'s `tmp.AbC123xyz`). No name pattern knew them, so test
/// scratch made this way was never nominated: 14 of them held 53 GB in
/// ts1's `/data/tmp/bl` at Critical pressure (2026-09-29). Requiring both
/// cases keeps words and extensions (`archive.backup1`, `site.config`) out,
/// and rejecting digit-free suffixes with a run of 4+ lowercase letters keeps
/// out the CamelCase app dirs in a macOS `$TMPDIR` (`com.apple.WindowManager`,
/// `com.openai.sky.CUAService`). A few random suffixes fail one of these and
/// stay unnominated, which is the safe direction.
fn is_mktemp_scratch_name(name: &str) -> bool {
    let Some((prefix, suffix)) = name.rsplit_once('.') else {
        return false;
    };
    let longest_lowercase_run = suffix
        .split(|c: char| !c.is_ascii_lowercase())
        .map(str::len)
        .max()
        .unwrap_or(0);
    !prefix.is_empty()
        && (6..=16).contains(&suffix.len())
        && suffix.bytes().all(|b| b.is_ascii_alphanumeric())
        && suffix.bytes().any(|b| b.is_ascii_uppercase())
        && suffix.bytes().any(|b| b.is_ascii_lowercase())
        && (suffix.bytes().any(|b| b.is_ascii_digit()) || longest_lowercase_run < 4)
}

/// True when a directory between `path` and its temp root is a project:
/// clones and build copies live in temp trees too (dsr's `/var/tmp/dsr-build-*`),
/// and a repo's checked-in fixtures can carry mktemp-shaped names (beads_rust's
/// `sample_beads_db_files/repro_beadsrust_import_write.M6eaGY`). Only reached
/// for names that already look like mktemp scratch.
fn inside_project_tree(path: &Path) -> bool {
    const MARKERS: &[&str] = &[
        ".git",
        "Cargo.toml",
        "package.json",
        "pyproject.toml",
        "go.mod",
    ];
    path.ancestors()
        .skip(1)
        .take(8)
        .take_while(|dir| !is_temp_root_dir(dir))
        .any(|dir| {
            // A marker that cannot be checked counts as present: being wrong
            // here keeps scratch, being wrong the other way deletes a project.
            MARKERS.iter().any(|marker| {
                !matches!(
                    dir.join(marker).symlink_metadata(),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound
                )
            })
        })
}

/// Whether the manifest of a tool that writes `name` sits beside it. Python
/// and JS packaging write `dist/`; CMake, Make, Meson, Gradle, Python and JS
/// builds write `build/`. Cargo, Go and a bare repo write neither, and a Rust
/// repo can track its own `dist/` beside `Cargo.toml` (franken_manim).
fn beside_producing_manifest(path: &Path, name: &str) -> bool {
    const DIST: &[&str] = &["package.json", "pyproject.toml", "setup.cfg", "setup.py"];
    const BUILD: &[&str] = &[
        "CMakeLists.txt",
        "Makefile",
        "build.gradle",
        "build.gradle.kts",
        "meson.build",
        "package.json",
        "pyproject.toml",
        "setup.py",
    ];
    let markers = if name == "dist" { DIST } else { BUILD };
    path.parent().is_some_and(|parent| {
        markers
            .iter()
            .any(|marker| parent.join(marker).metadata().is_ok())
    })
}

/// Inside `node_modules` or a package manager's cache, a `dist/` or `build/`
/// beside `package.json` is the published package's code, not output of a
/// build on this host. Bun's install cache names entries
/// `<name>@<version>@@@<n>`; Deno's npm cache sits under `registry.npmjs.org`.
fn installed_package_content(path: &Path) -> bool {
    path.parent().is_some_and(|parent| {
        parent.components().any(|component| {
            component.as_os_str().to_str().is_some_and(|part| {
                part == "node_modules" || part == "registry.npmjs.org" || part.contains("@@@")
            })
        })
    })
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
    if signals.regenerable_cache_tag() {
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
            name: "nuxt-build",
            kind: MatchKind::Exact(".nuxt"),
            confidence: 0.90,
            category: ArtifactCategory::BuildOutput,
        },
        ArtifactPattern {
            name: "astro-build",
            kind: MatchKind::Exact(".astro"),
            confidence: 0.88,
            category: ArtifactCategory::BuildOutput,
        },
        ArtifactPattern {
            name: "svelte-kit-build",
            kind: MatchKind::Exact(".svelte-kit"),
            confidence: 0.88,
            category: ArtifactCategory::BuildOutput,
        },
        ArtifactPattern {
            name: "docusaurus-build",
            kind: MatchKind::Exact(".docusaurus"),
            confidence: 0.88,
            category: ArtifactCategory::BuildOutput,
        },
        ArtifactPattern {
            name: "vite-cache",
            kind: MatchKind::Exact(".vite"),
            confidence: 0.86,
            category: ArtifactCategory::BuildOutput,
        },
        ArtifactPattern {
            name: "dart-tool-cache",
            kind: MatchKind::Exact(".dart_tool"),
            confidence: 0.86,
            category: ArtifactCategory::BuildOutput,
        },
        ArtifactPattern {
            name: "gradle-cache",
            kind: MatchKind::Exact(".gradle"),
            confidence: 0.86,
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
            name: "mypy-cache",
            kind: MatchKind::Exact(".mypy_cache"),
            confidence: 0.84,
            category: ArtifactCategory::PythonCache,
        },
        ArtifactPattern {
            name: "ruff-cache",
            kind: MatchKind::Exact(".ruff_cache"),
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
        has_descriptive_target_suffix, is_cargo_cache_store, is_cargo_registry_internal_path,
        is_obvious_build_artifact_basename, is_obvious_build_artifact_basename_given,
        structural_score,
    };
    use crate::platform::{linux, macos};
    use std::path::Path;

    #[test]
    fn darwin_user_temp_dir_is_a_temp_root() {
        use super::is_darwin_user_temp_path as temp;
        for inside in [
            "/var/folders/vt/n2xyn_s51b97_j3yh2qbqcnc0000gn/T/.tmp6ktZ0Q/proj/target",
            "/private/var/folders/vt/n2xyn_s51b97_j3yh2qbqcnc0000gn/T/build",
        ] {
            assert!(temp(Path::new(inside)), "{inside}");
        }
        for outside in [
            // $TMPDIR itself is never a candidate.
            "/var/folders/vt/n2xyn_s51b97_j3yh2qbqcnc0000gn/T",
            // The per-user cache dir and the system-owned dir are not temp.
            "/var/folders/vt/n2xyn_s51b97_j3yh2qbqcnc0000gn/C/com.apple.x",
            "/var/folders/vt/n2xyn_s51b97_j3yh2qbqcnc0000gn/0/state",
            "/var/folders/vt/T/short",
            "/Users/op/var/folders/vt/hash/T/lookalike",
            // Relative, or stepping out with `..`: never a temp root.
            "var/folders/vt/n2xyn_s51b97_j3yh2qbqcnc0000gn/T/rel",
            "/var/folders/vt/n2xyn_s51b97_j3yh2qbqcnc0000gn/T/../../../../etc",
        ] {
            assert!(!temp(Path::new(outside)), "{outside}");
        }
        // The scoring side agrees: a target there is in a volatile temp root.
        assert!(crate::scanner::scoring::is_volatile_temp_path(Path::new(
            "/var/folders/vt/n2xyn_s51b97_j3yh2qbqcnc0000gn/T/proj/target"
        )));
    }

    #[test]
    fn browser_code_sign_clones_are_the_only_candidates_in_the_clone_area() {
        let classify =
            |path: &str| classify_opaque_tree(Path::new(path), OpaqueTreeContext::default());
        let x = "/private/var/folders/vt/n2xy/X";
        for clone in [
            format!("{x}/com.google.Chrome.code_sign_clone/code_sign_clone.R3PMRk"),
            "/var/folders/vt/n2xy/X/com.brave.Browser.code_sign_clone/code_sign_clone.a1B2c3"
                .to_string(),
        ] {
            let opaque = classify(&clone).unwrap();
            assert_eq!(
                opaque.disposition,
                OpaqueTreeDisposition::CandidateOpaque,
                "{clone}"
            );
            assert_eq!(opaque.classification.category, ArtifactCategory::TempDir);
            assert_eq!(
                opaque.classification.pattern_name,
                "opaque-browser-code-sign-clone"
            );
        }
        // A browser's container is walked for its clones, never scored.
        let container = classify(&format!("{x}/com.google.Chrome.code_sign_clone")).unwrap();
        assert_eq!(container.disposition, OpaqueTreeDisposition::SignalOnly);
        // Nothing else in the area is walked or scored.
        for other in [
            format!("{x}/com.example.Other"),
            format!("{x}/.code_sign_clone"),
            format!("{x}/com.google.Chrome.code_sign_clone/code_sign_clone.R3PMR"),
            format!("{x}/com.google.Chrome.code_sign_clone/code_sign_clone.R3PMRk7"),
            format!("{x}/com.google.Chrome.code_sign_clone/code_sign_clone.R3-MRk"),
            format!("{x}/com.google.Chrome.code_sign_clone/Google Chrome.app"),
        ] {
            let opaque = classify(&other).unwrap();
            assert_eq!(
                opaque.disposition,
                OpaqueTreeDisposition::ProtectedOpaque,
                "{other}"
            );
        }
        // The same names anywhere else get no special treatment.
        for elsewhere in [
            "/private/var/folders/vt/n2xy/T/com.google.Chrome.code_sign_clone/code_sign_clone.R3PMRk",
            "/tmp/X/com.google.Chrome.code_sign_clone/code_sign_clone.R3PMRk",
            "/private/var/folders/vt/X/com.google.Chrome.code_sign_clone/code_sign_clone.R3PMRk",
            "/private/var/folders/vt/n2xy/X/com.google.Chrome.code_sign_clone/code_sign_clone.R3PMRk/Google Chrome.app.bundle",
            "/private/var/folders/vt/n2xy/X/../X/com.google.Chrome.code_sign_clone/code_sign_clone.R3PMRk",
        ] {
            assert!(classify(elsewhere).is_none(), "{elsewhere}");
        }
    }

    #[test]
    fn the_clone_area_sits_beside_a_user_temp_dir_root_only() {
        use super::darwin_code_sign_clone_area_for_temp_root as area;
        use std::path::PathBuf;
        for (root, want) in [
            (
                "/private/var/folders/vt/n2xy/T",
                "/private/var/folders/vt/n2xy/X",
            ),
            ("/var/folders/vt/n2xy/T/", "/var/folders/vt/n2xy/X"),
        ] {
            assert_eq!(area(Path::new(root)), Some(PathBuf::from(want)), "{root}");
        }
        for root in [
            "/private/var/folders/vt/n2xy/T/.tmpAbc",
            "/private/var/folders/vt/n2xy/C",
            "/private/var/folders/vt/n2xy",
            "/private/var/folders",
            "/private/tmp",
        ] {
            assert_eq!(area(Path::new(root)), None, "{root}");
        }
    }

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

    /// uv writes a CACHEDIR.TAG into every venv. On trj (2026-10-14) three
    /// venvs of a running release gate were quarantined at Green as
    /// `cachedir-tagged-cache`, and the gate's next step failed.
    #[test]
    fn a_venvs_cachedir_tag_does_not_make_it_a_cache() {
        let registry = ArtifactPatternRegistry::default();
        let venv = StructuralSignals {
            has_cachedir_tag: true,
            has_pyvenv_cfg: true,
            ..StructuralSignals::default()
        };
        assert!(!venv.regenerable_cache_tag());
        assert!(!venv.has_strong_signal());
        let classification = registry.classify(
            Path::new("/data/tmp/relwave-pane4-fsci-rprime/venv-noscipy-3.13"),
            venv,
        );
        assert_eq!(classification.category, ArtifactCategory::Unknown);
        assert_ne!(classification.pattern_name, "cachedir-tagged-cache");
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
    fn temp_build_and_dist_names_inside_a_project_copy_stay_source() {
        use std::fs;
        // Under a temp root, like the /data/tmp verify checkouts, partial
        // exports and bun install cache that lost source or package code on
        // ts2 (bd-8nol).
        let dir = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
        let tree = |root: &str, dirs: &[&str], files: &[&str]| {
            let base = dir.path().join(root);
            for sub in dirs {
                fs::create_dir_all(base.join(sub)).unwrap();
            }
            for file in files {
                fs::write(base.join(file), b"{}\n").unwrap();
            }
            base
        };
        let node = tree(
            "verify-af880e0",
            &[
                "scripts/build",
                "src/dist",
                "build",
                "app/.next",
                "frontend/dist",
            ],
            &[
                "package.json",
                "scripts/build/cjs-shim.mjs",
                "frontend/package.json",
            ],
        );
        // A partial export: source directories, no manifest anywhere.
        let partial = tree(
            "tealforest-kmk",
            &["scripts/build", "tests/golden/build"],
            &[],
        );
        // A Cargo-only copy: Cargo writes neither build/ nor dist/.
        let cargo = tree(
            "hfdt-clean-export",
            &["build", "dist", "crates/hfdt-cli/src/cmd/build"],
            &["Cargo.toml", "crates/hfdt-cli/Cargo.toml"],
        );
        let cmake = tree("cmake-copy", &["build"], &["CMakeLists.txt"]);
        let python = tree("py-copy", &["dist", "build"], &["pyproject.toml"]);
        // Published packages: a bun install-cache entry and an installed
        // dependency, each with package.json beside its dist/.
        let bun = tree(
            "bun-install-cache/sharp@0.35.4@@@1",
            &["dist"],
            &["package.json"],
        );
        let installed = tree("app/node_modules/unenv", &["dist"], &["package.json"]);
        let disposition = |path: &Path, beside_node_manifest: bool| {
            classify_opaque_tree(
                path,
                OpaqueTreeContext {
                    parent_has_node_manifest: beside_node_manifest,
                    ..OpaqueTreeContext::default()
                },
            )
            .map(|opaque| opaque.disposition)
        };

        for (source, beside_node_manifest) in [
            (node.join("scripts/build"), false),
            (node.join("src/dist"), false),
            (partial.join("scripts/build"), false),
            (partial.join("tests/golden/build"), false),
            (cargo.join("build"), false),
            (cargo.join("dist"), false),
            (cargo.join("crates/hfdt-cli/src/cmd/build"), false),
            (bun.join("dist"), true),
            (installed.join("dist"), true),
        ] {
            assert_eq!(
                disposition(&source, beside_node_manifest),
                Some(OpaqueTreeDisposition::SignalOnly),
                "{}",
                source.display()
            );
        }
        // Beside the manifest of a tool that writes it, and `.next`
        // anywhere, it is still output.
        for (output, beside_node_manifest) in [
            (node.join("build"), true),
            (node.join("frontend/dist"), true),
            (node.join("app/.next"), false),
            (cmake.join("build"), false),
            (python.join("dist"), false),
            (python.join("build"), false),
        ] {
            assert_eq!(
                disposition(&output, beside_node_manifest),
                Some(OpaqueTreeDisposition::CandidateOpaque),
                "{}",
                output.display()
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

    /// csd 2026-10-23: rch's shared store `rch-cargo-cache-csd` was not a
    /// recognised cargo home, so its `git`/`registry` roots were nominated
    /// whole. Every cargo home keeps its roots and offers its stores instead.
    #[test]
    fn every_cargo_home_keeps_its_roots_and_offers_its_stores() {
        let classify = |path: &Path| classify_opaque_tree(path, OpaqueTreeContext::default());
        let marked = tempfile::tempdir().unwrap();
        let marked_home = marked.path().join("job-7-cargo");
        std::fs::create_dir(&marked_home).unwrap();
        std::fs::write(marked_home.join(".package-cache"), b"").unwrap();

        for home in [
            PathBuf::from("/root/.cargo"),
            PathBuf::from("/data/ssd/tmp/rch-cargo-cache-csd"),
            PathBuf::from("/scratch/tmp/rch-cargo-cache-timeout-worker"),
            marked_home.clone(),
        ] {
            for root in ["registry", "git"] {
                let path = home.join(root);
                assert_eq!(
                    classify(&path).map(|opaque| opaque.disposition),
                    Some(OpaqueTreeDisposition::SignalOnly),
                    "{}",
                    path.display()
                );
            }
            for store in ["registry/src", "registry/cache", "registry/index", "git/db"] {
                let path = home.join(store);
                let opaque = classify(&path).unwrap();
                assert_eq!(
                    opaque.disposition,
                    OpaqueTreeDisposition::CandidateOpaque,
                    "{}",
                    path.display()
                );
                assert_eq!(opaque.classification.pattern_name, "opaque-cargo-cache");
            }
        }

        // A `registry` or `git` that is not in a cargo home gets no cargo verdict.
        let plain = marked.path().join("project");
        for path in [plain.join("registry"), plain.join("git")] {
            assert!(
                classify(&path).is_none_or(|opaque| opaque.classification.pattern_name
                    != "opaque-cargo-cache"
                    && opaque.disposition != OpaqueTreeDisposition::SignalOnly),
                "{}",
                path.display()
            );
        }
    }

    #[test]
    fn uv_cache_entry_content_is_never_walked_or_named_a_candidate() {
        use super::is_uv_cache_internal_path as internal;
        let registry = ArtifactPatternRegistry::default();
        for inside in [
            "/home/ubuntu/.cache/uv/archive-v0/SSbRqQhYGRnnG2bz/lib/python3.12/site-packages/torch/nn/utils/__pycache__",
            "/home/ubuntu/.cache/uv/archive-v0/qGMYdM4VKIJ2H-It/lib",
            "/root/.cache/uv/environments-v2/ruff-1a2b/lib/python3.12/site-packages/__pycache__",
        ] {
            let path = Path::new(inside);
            assert!(internal(path), "{inside}");
            assert_eq!(
                registry
                    .classify(path, StructuralSignals::default())
                    .category,
                ArtifactCategory::Unknown,
                "{inside}"
            );
            assert_eq!(
                classify_opaque_tree(path, OpaqueTreeContext::default())
                    .unwrap()
                    .disposition,
                OpaqueTreeDisposition::ProtectedOpaque,
                "{inside}"
            );
        }
        // uv's own units, its other buckets and other caches are unchanged.
        for outside in [
            "/home/ubuntu/.cache/uv",
            "/home/ubuntu/.cache/uv/archive-v0",
            "/home/ubuntu/.cache/uv/archive-v0/SSbRqQhYGRnnG2bz",
            "/home/ubuntu/.cache/uv/wheels-v5/pypi/__pycache__",
            "/home/ubuntu/.cache/uv/archive-vx/entry/__pycache__",
            "/home/ubuntu/.cache/pip/archive-v0/entry/__pycache__",
            "/home/ubuntu/project/__pycache__",
        ] {
            assert!(!internal(Path::new(outside)), "{outside}");
        }
        assert_eq!(
            registry
                .classify(
                    Path::new("/home/ubuntu/project/__pycache__"),
                    StructuralSignals::default()
                )
                .category,
            ArtifactCategory::PythonCache
        );
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

        // The roots are kept (rch symlinks them); the stores inside are the
        // whole-store cache candidates.
        for root in ["/root/.cargo/registry", "/home/ubuntu/.cargo/git"] {
            let opaque = classify_opaque_tree(Path::new(root), OpaqueTreeContext::default())
                .expect("cargo root should be classified");
            assert_eq!(
                opaque.disposition,
                OpaqueTreeDisposition::SignalOnly,
                "{root}"
            );
        }
        for store in [
            "/root/.cargo/registry/cache",
            "/root/.cargo/registry/src",
            "/root/.cargo/registry/index",
            "/home/ubuntu/.cargo/git/checkouts",
            "/home/ubuntu/.cargo/git/db",
        ] {
            let opaque = classify_opaque_tree(Path::new(store), OpaqueTreeContext::default())
                .expect("cargo store should be classified");
            assert_eq!(
                opaque.disposition,
                OpaqueTreeDisposition::CandidateOpaque,
                "{store}"
            );
            assert_eq!(opaque.classification.pattern_name, "opaque-cargo-cache");
        }
        // Nor may the name classifier (the daemon pre-scan) nominate a root.
        let names = ArtifactPatternRegistry::default();
        for root in ["/home/ubuntu/.cargo/registry", "/home/ubuntu/.cargo/git"] {
            let class = names.classify(Path::new(root), StructuralSignals::default());
            assert_eq!(
                class.category,
                ArtifactCategory::Unknown,
                "{root}: {class:?}"
            );
        }
        // A same-named dir outside a cargo home is not a cargo store.
        assert!(!is_cargo_cache_store(Path::new(
            "/data/proj/registry/cache"
        )));
        assert!(!is_cargo_cache_store(Path::new(
            "/root/.cargo/registry/other"
        )));
    }

    #[test]
    fn agent_scratch_name_rules_apply_only_directly_under_a_temp_root() {
        let registry = ArtifactPatternRegistry::default();
        // Real fleet deletions (2026-09-15..27) that were someone's data.
        for path in [
            "/data/tmp/ee_triage0924/fuzz/corpus/cass_import_jsonl",
            "/tmp/backup_repo_files/frankentui_untracked",
            "/tmp/backup_repo_files/cass_untracked",
            "/tmp/rch-run/frankenterm-9bf541b87e260846",
            "/tmp/rch-run/pi_agent_rust-61c0a642eeb896ae",
            "/home/ubuntu/.cache/claude-cli-nodejs",
            "/data/projects/pi_agent_rust",
        ] {
            let class = registry.classify(Path::new(path), StructuralSignals::default());
            assert_eq!(
                class.category,
                ArtifactCategory::Unknown,
                "{path}: {class:?}"
            );
        }
        // Agent scratch created directly in a temp root is still reclaimable.
        for (path, pattern) in [
            ("/data/tmp/cass-self-update.lQLsJD", "cass-prefix-hyphen"),
            (
                "/tmp/frankenterm-guardian-socket-authority-sPJzLf",
                "frankenterm-prefix",
            ),
            ("/data/tmp/pi_agent_rust_cargo", "pi-agent"),
            ("/private/tmp/claude-idprobe.7k5d0J", "claude-session-cache"),
            (
                "/var/folders/vt/n2xy/T/frankentui-snapshot-1",
                "frankentui-prefix-hyphen",
            ),
        ] {
            let class = registry.classify(Path::new(path), StructuralSignals::default());
            assert_eq!(class.pattern_name, pattern, "{path}");
        }
        // Artifact rules are not scoped: a cargo target deep in a clone stays one.
        let nested_target = registry.classify(
            Path::new("/data/tmp/some-clone/crates/cass_core_target"),
            StructuralSignals::default(),
        );
        assert_eq!(nested_target.category, ArtifactCategory::RustTarget);
    }

    #[test]
    fn mktemp_scratch_in_temp_trees_is_a_temp_dir() {
        let registry = ArtifactPatternRegistry::default();
        for path in [
            "/data/tmp/bl/fsfs-quickstart.ZH7Q3npF",
            "/tmp/tmp.AbC123xyzQ",
            "/var/tmp/build.Xy9kLmNo",
            "/tmp/com.google.Chrome.LiO3XR",
            "/private/tmp/TemporaryDirectory.QLWPkT",
            "/tmp/com.openai.codex.RdtJFb",
        ] {
            let class = registry.classify(Path::new(path), StructuralSignals::default());
            assert_eq!(class.pattern_name, "mktemp-scratch", "{path}");
            assert_eq!(class.category, ArtifactCategory::TempDir, "{path}");
        }
        for path in [
            // Outside a temp tree the same name is someone's data.
            "/data/projects/app/fsfs-quickstart.ZH7Q3npF",
            // Words and extensions are not random suffixes.
            "/tmp/archive.backup1",
            "/tmp/site.config",
            "/tmp/notes.ABCDEFG",
            "/tmp/x.Ab1",
            // CamelCase app dirs in a macOS $TMPDIR are words, not random.
            "/tmp/com.apple.WindowManager",
            "/tmp/com.apple.AppSSOAgent",
            "/tmp/com.openai.sky.CUAService",
            "/tmp/com.dicklesworthstone.frankenterm.savedState",
        ] {
            let class = registry.classify(Path::new(path), StructuralSignals::default());
            assert_eq!(class.category, ArtifactCategory::Unknown, "{path}");
        }
        // Named rules keep precedence: tempfile's `.tmpXXXXXX` stays dot-tmp.
        let dot_tmp = registry.classify(
            Path::new("/data/tmp/bl/.tmpETepM0"),
            StructuralSignals::default(),
        );
        assert_eq!(dot_tmp.pattern_name, "dot-tmp");
        // A repository checked out into mktemp scratch is not reclaimable.
        let with_git = registry.classify(
            Path::new("/tmp/tmp.AbC123xyzQ"),
            StructuralSignals {
                has_git: true,
                ..StructuralSignals::default()
            },
        );
        assert!(with_git.combined_confidence < 0.1);
    }

    #[test]
    fn mktemp_shaped_fixtures_inside_a_project_are_not_scratch() {
        let registry = ArtifactPatternRegistry::default();
        let base = tempfile::tempdir_in("/tmp").expect("tempdir under /tmp");
        let clone = base.path().join("clone");
        let fixture = clone.join("fixtures/repro_import_write.M6eaGY");
        std::fs::create_dir_all(&fixture).unwrap();
        std::fs::write(clone.join("Cargo.toml"), "[package]\n").unwrap();
        let scratch = base.path().join("bl/fsfs-quickstart.ZH7Q3npF");
        std::fs::create_dir_all(&scratch).unwrap();

        let class = registry.classify(&fixture, StructuralSignals::default());
        assert_eq!(class.category, ArtifactCategory::Unknown);
        let class = registry.classify(&scratch, StructuralSignals::default());
        assert_eq!(class.pattern_name, "mktemp-scratch");
    }

    #[test]
    fn stale_mktemp_scratch_is_reclaimed_but_fresh_scratch_is_kept() {
        use crate::core::config::ScoringConfig;
        use crate::scanner::scoring::{
            ActiveReferenceSummary, CandidateInput, DecisionAction, ScoringEngine,
        };
        use std::time::Duration;
        let registry = ArtifactPatternRegistry::default();
        let engine = ScoringEngine::from_config(&ScoringConfig::default(), 30);
        let path = Path::new("/data/tmp/bl/fsfs-quickstart.ZH7Q3npF");
        let candidate = |age| CandidateInput {
            path: path.to_path_buf(),
            size_bytes: 3_900_000_000,
            age,
            classification: registry.classify(path, StructuralSignals::default()),
            signals: StructuralSignals::default(),
            active_references: ActiveReferenceSummary::default(),
            is_open: false,
            excluded: false,
        };
        let stale = engine.score_candidate(&candidate(Duration::from_hours(48)), 0.95);
        assert_eq!(stale.decision.action, DecisionAction::Delete, "{stale:?}");
        let fresh = engine.score_candidate(&candidate(Duration::from_mins(10)), 0.95);
        assert_eq!(fresh.decision.action, DecisionAction::Keep, "{fresh:?}");
    }

    #[test]
    fn claude_harness_dirs_are_never_artifacts_but_their_contents_can_be() {
        let registry = ArtifactPatternRegistry::default();
        for path in [
            "/tmp/claude-501",
            "/private/tmp/claude-501",
            "/data/tmp/claude-1000",
            "/tmp/claude-mcp-browser-bridge-jemanuel",
        ] {
            let class = registry.classify(Path::new(path), StructuralSignals::default());
            assert_eq!(
                class.category,
                ArtifactCategory::Unknown,
                "{path}: {class:?}"
            );
        }
        // Agent-made scratch under the same prefix is still a cache.
        let scratch = registry.classify(
            Path::new("/data/tmp/claude-idprobe.7k5d0J"),
            StructuralSignals::default(),
        );
        assert_eq!(scratch.pattern_name, "claude-session-cache");
        // An artifact inside a session scratchpad is still reclaimable.
        let pycache = registry.classify(
            Path::new("/tmp/claude-501/-Users-x-proj/0f2c/scratchpad/__pycache__"),
            StructuralSignals::default(),
        );
        assert_eq!(pycache.category, ArtifactCategory::PythonCache);
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

        // Descriptive suffix shapes need the same markers (issue #34), and so
        // does a plain `target` without a Cargo manifest beside it.
        let descriptive = base.path().join("cass-ft-target");
        std::fs::create_dir_all(&descriptive).unwrap();
        let opaque = classify_opaque_tree(&descriptive, OpaqueTreeContext::default()).unwrap();
        assert_eq!(opaque.disposition, OpaqueTreeDisposition::SignalOnly);
        std::fs::write(descriptive.join(".rustc_info.json"), "{}").unwrap();
        let opaque = classify_opaque_tree(&descriptive, OpaqueTreeContext::default()).unwrap();
        assert_eq!(opaque.disposition, OpaqueTreeDisposition::CandidateOpaque);
        let plain = base.path().join("target");
        std::fs::create_dir_all(&plain).unwrap();
        let opaque = classify_opaque_tree(&plain, OpaqueTreeContext::default()).unwrap();
        assert_eq!(opaque.disposition, OpaqueTreeDisposition::SignalOnly);
        std::fs::write(plain.join(".rustc_info.json"), "{}").unwrap();
        let opaque = classify_opaque_tree(&plain, OpaqueTreeContext::default()).unwrap();
        assert_eq!(opaque.disposition, OpaqueTreeDisposition::CandidateOpaque);
    }

    /// An hfdt store keeps a `target/` of its own (store-doctor undo data).
    /// Under a temp root, with no Cargo manifest beside it and no cargo
    /// marker inside, it is not a build target; beside a Cargo.toml it still
    /// is, as before.
    #[test]
    fn an_hfdt_store_target_under_tmp_is_not_a_cargo_target() {
        let base = tempfile::tempdir_in("/tmp").expect("tempdir under /tmp");
        let store = base.path().join("freshstore_built");
        std::fs::create_dir_all(store.join("target/doctor-undo/10726d")).unwrap();
        std::fs::write(store.join("hfdt.sqlite"), b"SQLite format 3\0").unwrap();
        std::fs::write(store.join("target/doctor-undo/10726d/page.bin"), [7u8; 64]).unwrap();

        let opaque =
            classify_opaque_tree(&store.join("target"), OpaqueTreeContext::default()).unwrap();
        assert_eq!(opaque.disposition, OpaqueTreeDisposition::SignalOnly);

        let beside_manifest = classify_opaque_tree(
            &store.join("target"),
            OpaqueTreeContext {
                parent_has_cargo_toml: true,
                parent_has_node_manifest: false,
            },
        )
        .unwrap();
        assert_eq!(
            beside_manifest.disposition,
            OpaqueTreeDisposition::CandidateOpaque
        );
    }

    /// A non-temp scratch parent inside the checkout (`tmp/` is gitignored and
    /// is not a temp root to sbh, unlike `/tmp` or `$TMPDIR`).
    fn non_temp_scratch() -> tempfile::TempDir {
        let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("tmp");
        std::fs::create_dir_all(&parent).unwrap();
        tempfile::tempdir_in(parent).unwrap()
    }

    #[test]
    fn opaque_tree_promotes_a_descriptive_target_suffix_only_with_cargo_markers() {
        // Issue #34: on ts2 sbh deleted `invalid_target` and `ambient-target`
        // fixtures inside non-git release-evidence bundles on the name alone.
        let base = non_temp_scratch();
        for (name, fixture) in [
            ("invalid_target", "expected-rejection.json"),
            ("ambient-target", "probe.log"),
            ("cargo-target", "README"),
        ] {
            let dir = base.path().join("publish-gates-v1").join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(fixture), "evidence").unwrap();
            let opaque = classify_opaque_tree(&dir, OpaqueTreeContext::default()).unwrap();
            assert_eq!(
                opaque.disposition,
                OpaqueTreeDisposition::SignalOnly,
                "{name}"
            );
            assert!(!is_obvious_build_artifact_basename(&dir), "{name}");
        }
        // Nothing readable at the root is no evidence either.
        let unread = classify_opaque_tree(
            Path::new("/root/cass-ft-target"),
            OpaqueTreeContext::default(),
        )
        .unwrap();
        assert_eq!(unread.disposition, OpaqueTreeDisposition::SignalOnly);

        // A real `CARGO_TARGET_DIR` (the stranded /root/cass-ft-target case)
        // carries cargo's root markers and is nominated outside temp storage.
        let real = base.path().join("cass-ft-target");
        std::fs::create_dir_all(real.join("debug")).unwrap();
        std::fs::write(
            real.join("CACHEDIR.TAG"),
            "Signature: 8a477f597d28d172789f06886806bc55\n# cargo\n",
        )
        .unwrap();
        let opaque = classify_opaque_tree(&real, OpaqueTreeContext::default()).unwrap();
        assert_eq!(opaque.disposition, OpaqueTreeDisposition::CandidateOpaque);
        assert_eq!(opaque.classification.category, ArtifactCategory::RustTarget);
        assert_eq!(opaque.classification.pattern_name, "opaque-cargo-target");
        assert!(is_obvious_build_artifact_basename(&real));
        assert!(is_obvious_build_artifact_basename(&real.join("debug")));
        let underscore = base.path().join("foo_target");
        std::fs::create_dir_all(&underscore).unwrap();
        std::fs::write(underscore.join(".rustc_info.json"), "{}").unwrap();
        let opaque = classify_opaque_tree(&underscore, OpaqueTreeContext::default()).unwrap();
        assert_eq!(opaque.disposition, OpaqueTreeDisposition::CandidateOpaque);
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
        assert!(is_obvious_build_artifact_basename(Path::new("target")));
        // A suffix-only name needs cargo's root markers; the scorer can supply
        // the walker's structural evidence instead.
        let base = non_temp_scratch();
        for name in ["cass-ft-target", "foo_target", "hfdt-release-target"] {
            let dir = base.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            assert!(!is_obvious_build_artifact_basename(&dir), "{name}");
            assert!(
                is_obvious_build_artifact_basename_given(&dir, true),
                "{name}"
            );
            std::fs::create_dir_all(dir.join(".fingerprint")).unwrap();
            assert!(is_obvious_build_artifact_basename(&dir), "{name}");
        }
        for name in [".ssh", ".rustup", ".cargo", ".config", ".local", "mytarget"] {
            assert!(
                !is_obvious_build_artifact_basename(Path::new(name)),
                "{name}"
            );
        }
    }

    #[test]
    fn is_obvious_build_artifact_basename_recognizes_nested_debug_and_release() {
        for path in [
            "target/debug",
            "target/release",
            "target/doc",
            "target/package",
            "target/criterion",
            "target/bench",
            "target/test",
            "target/dev",
            "target/x86_64-unknown-linux-gnu",
            "target/aarch64-apple-darwin",
            "/data/projects/foo/target/debug",
            "/data/projects/foo/target/release",
            "/data/projects/foo/target/doc",
            "/data/projects/foo/target/package",
            "/data/projects/foo/target/x86_64-unknown-linux-gnu",
            "/data/projects/foo/target/x86_64-unknown-linux-gnu/debug",
            "/data/projects/foo/.cargo-target/debug",
            "/data/projects/foo/build/debug",
            "/data/projects/foo/build/release",
            "/root/target/debug",
            ".mypy_cache",
            ".ruff_cache",
            ".astro",
            ".svelte-kit",
            ".docusaurus",
            ".dart_tool",
            ".gradle",
            "/data/projects/foo/.mypy_cache",
            "/data/projects/foo/.astro",
        ] {
            assert!(
                is_obvious_build_artifact_basename(Path::new(path)),
                "expected `{path}` to be recognized as build artifact"
            );
        }

        for path in [
            "debug",
            "release",
            "doc",
            "package",
            "criterion",
            "bench",
            "x86_64-unknown-linux-gnu",
            "/data/projects/foo/debug",
            "/data/projects/foo/release",
            "/data/projects/foo/doc",
            "/data/projects/foo/src/debug",
            "/data/projects/foo/crates/debug",
            "/data/projects/foo/x86_64-unknown-linux-gnu",
            "/root/debug",
        ] {
            assert!(
                !is_obvious_build_artifact_basename(Path::new(path)),
                "expected `{path}` to NOT be recognized as build artifact without artifact parent"
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
            // IndexedDB, CacheStorage and vm_bundles keep their labels but are
            // report-only application storage (a6b0a61; covered by the
            // catalog's `report_only_rules_never_delete`), so only the
            // regenerable HTTP/code/GPU caches carry actionable confidence.
            let report_only = matches!(
                expected_pattern,
                "electron-service-worker-cache" | "electron-indexed-db" | "electron-vm-bundles"
            );
            assert_eq!(
                classification.combined_confidence > 0.70,
                !report_only,
                "confidence for {path}"
            );
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

        // Observed directly under /tmp; agent-scratch rules are scoped there.
        for (name, expected) in cases {
            let path = Path::new("/tmp").join(name);
            let classification = registry.classify(&path, StructuralSignals::default());
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
            let path = Path::new("/tmp").join(name);
            let classification = registry.classify(&path, StructuralSignals::default());
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
            let path = Path::new("/tmp").join(name);
            let classification = registry.classify(&path, StructuralSignals::default());
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
            Path::new("/tmp/frankenterm-build-1234"),
            StructuralSignals::default(),
        );
        assert_eq!(frankenterm.category, ArtifactCategory::AgentWorkspace);
        let frankentui = registry.classify(
            Path::new("/tmp/frankentui-codex-bd-2vr05-4"),
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
