//! Daemon tier: target-only reclaim inside protected roots (bd-232u).
//!
//! An agent's session scratch (`/private/tmp/claude-<uid>` on macOS) holds
//! temp clones with unpushed commits and evidence, so operators exclude and
//! protect it as a whole. Agents also build there with `CARGO_TARGET_DIR`,
//! and those target dirs are pure build output: on one 3.6 TB Mac, about
//! 151 GB of them sat untouched for over a day while the volume reached 99%,
//! and sbh, which could see none of them, released nothing.
//!
//! Under each `scanner.target_only_roots` root whose mount is at Yellow or
//! above, a pass on its own `sbh-targets` thread nominates a directory only if
//! it passes every check:
//!
//! 1. cargo structure at its top: `CACHEDIR.TAG` or `.rustc_info.json`;
//! 2. pure: its top level holds only what cargo writes there (`debug`,
//!    `release`, `release-*` profiles holding a build, `doc`, an empty
//!    `tmp`, `package`, a target triple such as `wasm32-wasip1`, the two
//!    marker files and cargo's lock and report files) plus the macOS
//!    `.DS_Store` and `.metadata_never_index`; anything else, benchmark
//!    baselines included, makes it work, not output;
//! 3. no `.sbh-protect` marker in it, inside it or in a directory between it
//!    and the root, no `.git` inside it, and not at or below one of
//!    `scanner.excluded_paths`;
//! 4. within `scanner.target_only_idle_hours`, the directory was neither
//!    created nor modified (the walker's age rule) and nothing inside it was
//!    modified;
//! 5. no process holds a file open in it or works inside it.
//!
//! The survivors are scored like any candidate and reach the executor as a
//! target-only batch pinned to the inodes surveyed: the policy mode, the
//! decision ledger, dampening, the certainty gate, the planner and every
//! executor check still apply, and the executor drops any candidate outside
//! the root. Only the `protected_paths` patterns that protect the root as a
//! whole are not applied; one naming something inside it still is.
//! Everything else under the root stays untouchable, and with no roots
//! configured the tier never reads the disk.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use crossbeam_channel::Sender;

use crate::core::config::{Config, ScannerConfig};
use crate::core::paths::resolve_absolute_path;
use crate::daemon::loop_main::DeletionBatch;
use crate::logger::dual::{ActivityEvent, ActivityLoggerHandle};
use crate::monitor::pid::PressureLevel;
use crate::platform::pal::Platform;
use crate::scanner::patterns::{ArtifactCategory, ArtifactPatternRegistry};
use crate::scanner::protection::MARKER_FILENAME;
use crate::scanner::scoring::{CandidacyScore, CandidateInput, DecisionAction, ScoringEngine};
use crate::scanner::walker::{
    FsEntryKind, FsIdentity, collect_active_reference_index, structural_signals_for_path,
};
use crate::tuning::writeback::human_bytes;

/// The lowest pressure a pass runs at. Below it the executor would only
/// quarantine, and nothing needs the space.
const START_LEVEL: PressureLevel = PressureLevel::Yellow;
/// Shortest gap between two passes.
pub const PASS_INTERVAL: Duration = Duration::from_mins(10);
/// Deepest candidate below a root. Agent scratch nests a target at
/// `<root>/<project>/<session>/scratchpad/<target>`, depth 4.
const MAX_DEPTH: usize = 6;
/// Directories one discovery may read.
const MAX_DIRECTORIES: usize = 50_000;
/// Entries discovery reads from one directory; a larger listing is skipped
/// and leaves the root uncovered.
const MAX_LISTING_ENTRIES: usize = 65_536;
/// Wall time of one discovery.
const DISCOVERY_BUDGET: Duration = Duration::from_secs(30);
/// Entries one candidate's survey may visit before it fails closed.
const SURVEY_MAX_ENTRIES: u64 = 2_000_000;
/// Wall time for surveying all of one root's candidates.
const SURVEY_BUDGET: Duration = Duration::from_secs(120);
/// Shortest gap between two checks of whether any root is due, so the main
/// loop does not expand the root patterns on every tick.
const PROBE_INTERVAL: Duration = Duration::from_mins(1);

/// What one pass found under one root.
#[derive(Debug, Default)]
pub struct Selection {
    /// Scored, unvetoed candidates, largest first.
    pub candidates: Vec<CandidacyScore>,
    /// Target dirs found by discovery.
    pub discovered: usize,
    /// Why the others were left alone, by reason.
    pub left: BTreeMap<&'static str, usize>,
    /// False when a budget stopped discovery before the root was covered.
    pub complete: bool,
}

impl Selection {
    fn leave(&mut self, reason: &'static str) {
        *self.left.entry(reason).or_default() += 1;
    }

    /// One log line: what was found, what goes to the executor, what stays.
    #[must_use]
    pub fn summary(&self, root: &Path) -> String {
        let bytes = self
            .candidates
            .iter()
            .map(|candidate| candidate.size_bytes)
            .fold(0u64, u64::saturating_add);
        let left = self
            .left
            .iter()
            .map(|(reason, count)| format!("{reason}={count}"))
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "root={} target dirs={}{} nominated={} ({}) left: {}",
            root.display(),
            self.discovered,
            if self.complete {
                ""
            } else {
                " (walk budget hit)"
            },
            self.candidates.len(),
            human_bytes(bytes),
            if left.is_empty() { "none" } else { &left },
        )
    }
}

/// The directories a root pattern names now (`*` inside a segment matches
/// direct children, as in `log_truncation.paths`); symlinks are not roots.
#[must_use]
pub fn expand_roots(patterns: &[PathBuf]) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for pattern in patterns {
        let mut matched = Vec::new();
        if let Err(error) = crate::scanner::log_truncator::expand_pattern(pattern, &mut matched) {
            eprintln!(
                "[SBH-TARGETS] root pattern {} not expanded: {error}",
                pattern.display()
            );
            continue;
        }
        roots.extend(
            matched
                .into_iter()
                .filter(|path| fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir())),
        );
    }
    roots.sort();
    roots.dedup();
    roots
}

/// Whether `name` is something cargo itself writes at the top of a target
/// dir, or a file macOS drops into any directory.
/// The operator's reclaim script (`reclaim-build-targets.sh`) settled on this
/// set; its benchmark and test-report dirs (`criterion`, `nextest`) stay out:
/// they hold baselines and evidence, not just build output.
fn is_cargo_entry(name: &str, is_dir: bool) -> bool {
    if is_dir {
        matches!(name, "debug" | "release" | "doc" | "tmp" | "package")
            || is_release_profile(name)
            || is_target_triple(name)
    } else {
        matches!(
            name,
            "CACHEDIR.TAG"
                | ".rustc_info.json"
                | ".rustdoc_fingerprint.json"
                | ".future-incompat-report.json"
                | ".cargo-lock"
                | ".DS_Store"
                | ".metadata_never_index"
        )
    }
}

/// A custom profile derived from release, such as `release-lto`, by name;
/// [`holds_what_cargo_writes`] also checks its contents.
fn is_release_profile(name: &str) -> bool {
    name.strip_prefix("release-").is_some_and(|profile| {
        !profile.is_empty()
            && profile
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

/// A rustc target triple such as `x86_64-unknown-linux-gnu`,
/// `aarch64-apple-darwin` or `wasm32-wasip1`: cargo's output dir for
/// `--target`. Its second part must be a vendor or OS rustc uses, so an
/// agent's `x86_64-trace` or `arm-e2e` is not one, nor is a custom profile
/// dir (`release-lto`). A custom target spec's dir is not recognized, which
/// keeps its target dir.
fn is_target_triple(name: &str) -> bool {
    const VENDORS_AND_SYSTEMS: &[&str] = &[
        "unknown", "apple", "pc", "none", "linux", "wasi", "wasip1", "wasip2", "uwp", "fortanix",
        "nvidia", "sun", "ibm", "esp", "esp32", "kmc", "sony", "nintendo", "win7", "wrs",
        "unikraft", "lynx", "amd", "openwrt", "fuchsia",
    ];
    const ARCHES: &[&str] = &[
        "x86_64",
        "i386",
        "i586",
        "i686",
        "aarch64",
        "aarch64_be",
        "arm64",
        "arm64e",
        "arm",
        "wasm32",
        "wasm32v1",
        "wasm64",
        "s390x",
        "loongarch64",
        "sparc64",
        "sparcv9",
        "nvptx64",
        "powerpc",
        "powerpc64",
        "powerpc64le",
        "mips",
        "mipsel",
        "mips64",
        "mips64el",
    ];
    let mut parts = name.split('-');
    let arch = parts.next().unwrap_or_default();
    let rest: Vec<&str> = parts.collect();
    let known_arch = ARCHES.contains(&arch)
        || ["armv", "thumbv", "riscv32", "riscv64"]
            .iter()
            .any(|prefix| arch.starts_with(prefix));
    known_arch
        && rest
            .first()
            .is_some_and(|second| VENDORS_AND_SYSTEMS.contains(second))
        && rest.iter().all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.')
        })
}

/// Whether a top-level directory cargo's name allows also holds what cargo
/// puts there. `tmp` is `CARGO_TARGET_TMPDIR`, where integration tests may
/// leave output someone wants, so it counts only while empty; a `release-*`
/// name must hold a build (`deps`, `build`, `.fingerprint` or `incremental`),
/// so `release-notes` does not pass for a profile.
fn holds_what_cargo_writes(dir: &Path, name: &str) -> std::io::Result<bool> {
    if name == "tmp" {
        return Ok(fs::read_dir(dir)?.next().is_none());
    }
    if is_release_profile(name) {
        return Ok(["deps", "build", ".fingerprint", "incremental"]
            .iter()
            .any(|inner| fs::symlink_metadata(dir.join(inner)).is_ok_and(|meta| meta.is_dir())));
    }
    Ok(true)
}

/// Whether `dir`'s top level still holds only what cargo writes.
///
/// The executor asks when accepting a batch and immediately before each
/// mutation: the survey or batch may be minutes old, and a trace dir or log
/// written into the target since then makes it work, not output. An
/// unreadable or budget-truncated listing is not pure.
pub fn still_pure(dir: &Path) -> bool {
    matches!(first_impurity(dir, MAX_LISTING_ENTRIES), Ok(None))
}

/// The first top-level entry of `dir` that cargo did not write, or an error
/// when the listing cannot be completed within its entry budget (which
/// keeps the directory). A live mutation guard must not walk an unbounded
/// number of top-level entries just to renew a protection exception.
fn first_impurity(dir: &Path, max_entries: usize) -> std::io::Result<Option<String>> {
    for (index, entry) in fs::read_dir(dir)?.enumerate() {
        if index >= max_entries {
            return Err(std::io::Error::other(
                "target purity listing exceeded its entry budget",
            ));
        }
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let file_type = entry.file_type()?;
        let pure = !file_type.is_symlink()
            && is_cargo_entry(&name, file_type.is_dir())
            && (!file_type.is_dir() || holds_what_cargo_writes(&entry.path(), &name)?);
        if !pure {
            return Ok(Some(name));
        }
    }
    Ok(None)
}

/// Why a survey keeps its directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kept {
    /// A `.sbh-protect` marker inside.
    Marker,
    /// A `.git` entry inside.
    Git,
    /// The directory or an entry changed after the idle cutoff, or is dated
    /// in the future.
    Recent,
    /// A budget, another device or an unreadable entry ended the walk.
    Unsurveyed,
}

impl Kept {
    const fn reason(self) -> &'static str {
        match self {
            Self::Marker => "protect_marker",
            Self::Git => "git",
            Self::Recent => "recent",
            Self::Unsurveyed => "unsurveyed",
        }
    }
}

/// What a walk of one candidate found.
#[derive(Debug)]
struct Survey {
    /// The directory the walk started from, as the executor must find it.
    identity: Option<FsIdentity>,
    newest: Option<SystemTime>,
    bytes: u64,
    /// `None` only when the walk covered the whole directory and found
    /// nothing that keeps it.
    kept: Option<Kept>,
}

/// When the candidate itself arrived or last changed: the later of its
/// modification and birth times, the walker's age rule, so a target copied
/// in with preserved mtimes (`cp -a`, `rsync -a`, `tar x`) is not idle at
/// once. Entries inside count by modification time.
fn touched_at(meta: &fs::Metadata) -> Option<SystemTime> {
    let modified = meta.modified().ok();
    let created = meta.created().ok();
    modified.max(created)
}

/// Walk `dir` without following symlinks or leaving its device. Stops at the
/// first marker, `.git` or entry touched after `idle_cutoff`; a budget,
/// another device or an unreadable entry leaves the survey incomplete, which
/// keeps the directory.
fn survey(dir: &Path, idle_cutoff: SystemTime, deadline: Instant) -> Survey {
    let mut found = Survey {
        identity: None,
        newest: None,
        bytes: 0,
        kept: Some(Kept::Unsurveyed),
    };
    let Ok(top) = fs::symlink_metadata(dir) else {
        return found;
    };
    if !top.is_dir() {
        return found;
    }
    found.identity = identity_of(&top);
    let device = device_of(&top);
    found.newest = touched_at(&top);
    if found.newest.is_some_and(|touched| touched > idle_cutoff) {
        found.kept = Some(Kept::Recent);
        return found;
    }
    let mut entries = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(listing) = fs::read_dir(&current) else {
            return found;
        };
        for entry in listing {
            entries += 1;
            if entries > SURVEY_MAX_ENTRIES || Instant::now() >= deadline {
                return found;
            }
            let Ok(entry) = entry else {
                return found;
            };
            let name = entry.file_name();
            if name == MARKER_FILENAME {
                found.kept = Some(Kept::Marker);
                return found;
            }
            if name == ".git" {
                found.kept = Some(Kept::Git);
                return found;
            }
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                return found;
            };
            if let Ok(touched) = meta.modified() {
                if touched > idle_cutoff {
                    found.kept = Some(Kept::Recent);
                    return found;
                }
                found.newest = Some(found.newest.map_or(touched, |newest| newest.max(touched)));
            }
            found.bytes = found.bytes.saturating_add(allocated_bytes(&meta));
            if meta.is_dir() {
                if device_of(&meta) != device {
                    return found;
                }
                stack.push(path);
            }
        }
    }
    found.kept = None;
    found
}

/// The device holding an entry; `None` off Unix, where no device crossing is
/// detected.
#[cfg_attr(unix, allow(clippy::unnecessary_wraps))]
fn device_of(meta: &fs::Metadata) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(meta.dev())
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        None
    }
}

fn allocated_bytes(meta: &fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.blocks().saturating_mul(512)
    }
    #[cfg(not(unix))]
    {
        meta.len()
    }
}

/// A directory's identity for the executor's check before removal; `None`
/// off Unix, which keeps the candidate.
#[cfg_attr(unix, allow(clippy::unnecessary_wraps))]
fn identity_of(meta: &fs::Metadata) -> Option<FsIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(FsIdentity {
            device_id: meta.dev(),
            inode: meta.ino(),
            kind: FsEntryKind::Directory,
        })
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        None
    }
}

/// The identity of the directory at `path` now, without following a final
/// symlink; `None` when it is gone, not a directory, or off Unix.
fn current_identity(path: &Path) -> Option<FsIdentity> {
    fs::symlink_metadata(path)
        .ok()
        .filter(fs::Metadata::is_dir)
        .as_ref()
        .and_then(identity_of)
}

/// Names a listing holds that steer discovery.
#[derive(Debug, Default)]
struct Markers {
    protect: bool,
    git: bool,
    cargo: bool,
}

/// Why a directory's listing gave discovery nothing to go on.
enum Unlisted {
    /// Unreadable: skipped, as the walker skips it.
    Unreadable,
    /// Over [`MAX_LISTING_ENTRIES`] or past the deadline: skipped, and the
    /// root counts as not covered.
    Budget,
}

fn markers_in(dir: &Path, deadline: Instant) -> Result<(Markers, Vec<PathBuf>), Unlisted> {
    let mut markers = Markers::default();
    let mut children = Vec::new();
    let listing = fs::read_dir(dir).map_err(|_| Unlisted::Unreadable)?;
    for (index, entry) in listing.enumerate() {
        if index >= MAX_LISTING_ENTRIES || Instant::now() >= deadline {
            return Err(Unlisted::Budget);
        }
        let entry = entry.map_err(|_| Unlisted::Unreadable)?;
        let name = entry.file_name();
        if name == MARKER_FILENAME {
            markers.protect = true;
        } else if name == ".git" {
            markers.git = true;
        } else if name == "CACHEDIR.TAG" || name == ".rustc_info.json" {
            markers.cargo = true;
        }
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            children.push(entry.path());
        }
    }
    children.sort();
    Ok((markers, children))
}

/// Directories under `root` with cargo structure at their top, shallowest
/// first. Never the root itself, and never at or below a candidate, a marker,
/// a `.git` entry, one of `excluded` (exact paths, as the walker takes
/// `scanner.excluded_paths`), another device or an unreadable directory.
/// Returns whether the walk covered the root.
fn discover(root: &Path, excluded: &[PathBuf], found: &mut Vec<PathBuf>) -> bool {
    let deadline = Instant::now() + DISCOVERY_BUDGET;
    let Ok(root_meta) = fs::symlink_metadata(root) else {
        return false;
    };
    if excluded.iter().any(|path| path == root) {
        return true;
    }
    let device = device_of(&root_meta);
    let mut covered = true;
    let mut queue = VecDeque::from([(root.to_path_buf(), 0usize)]);
    let mut read = 0usize;
    while let Some((dir, depth)) = queue.pop_front() {
        read += 1;
        if read > MAX_DIRECTORIES || Instant::now() >= deadline {
            return false;
        }
        let (markers, children) = match markers_in(&dir, deadline) {
            Ok(listing) => listing,
            Err(Unlisted::Unreadable) => continue,
            Err(Unlisted::Budget) => {
                covered = false;
                continue;
            }
        };
        if markers.protect || markers.git {
            continue;
        }
        if depth > 0 && markers.cargo {
            found.push(dir);
            continue;
        }
        if depth == MAX_DEPTH {
            continue;
        }
        for child in children {
            if !excluded.contains(&child)
                && fs::symlink_metadata(&child).is_ok_and(|meta| device_of(&meta) == device)
            {
                queue.push_back((child, depth + 1));
            }
        }
    }
    covered
}

/// A discovered directory that passed the purity check and its survey.
struct Checked {
    /// Resolved: the reference index keys resolved paths, so a parent symlink
    /// must not hide a process working inside the candidate.
    path: PathBuf,
    bytes: u64,
    age: Duration,
    identity: FsIdentity,
}

/// Purity, survey and identity checks for one discovered directory: the
/// directory, or why it stays.
fn check(
    dir: &Path,
    idle_cutoff: SystemTime,
    now: SystemTime,
    deadline: Instant,
) -> std::result::Result<Checked, &'static str> {
    match first_impurity(dir, MAX_LISTING_ENTRIES) {
        Ok(None) => {}
        Ok(Some(_)) => return Err("impure"),
        Err(_) => return Err("unreadable"),
    }
    let facts = survey(dir, idle_cutoff, deadline);
    if let Some(kept) = facts.kept {
        return Err(kept.reason());
    }
    if facts.bytes == 0 {
        return Err("empty");
    }
    let (Some(identity), Some(age)) = (
        facts.identity,
        facts
            .newest
            .and_then(|newest| now.duration_since(newest).ok()),
    ) else {
        return Err("unreadable");
    };
    // The resolved path must still be the directory surveyed.
    let path = resolve_absolute_path(dir);
    if current_identity(&path) != Some(identity) {
        return Err("changed");
    }
    Ok(Checked {
        path,
        bytes: facts.bytes,
        age,
        identity,
    })
}

/// Find, check and score target-only candidates under one root.
#[must_use]
pub fn select(
    root: &Path,
    config: &Config,
    platform: &dyn Platform,
    urgency: f64,
    now: SystemTime,
) -> Selection {
    let mut selection = Selection::default();
    let mut found = Vec::new();
    selection.complete = discover(root, &config.scanner.excluded_paths, &mut found);
    selection.discovered = found.len();

    let idle = Duration::from_secs(config.scanner.target_only_idle_hours.saturating_mul(3600));
    let idle_cutoff = now.checked_sub(idle).unwrap_or(SystemTime::UNIX_EPOCH);
    let deadline = Instant::now() + SURVEY_BUDGET;
    let mut checked = Vec::new();
    for dir in found {
        match check(&dir, idle_cutoff, now, deadline) {
            Ok(candidate) => checked.push(candidate),
            Err(reason) => selection.leave(reason),
        }
    }
    if checked.is_empty() {
        return selection;
    }

    let paths: Vec<PathBuf> = checked
        .iter()
        .map(|candidate| candidate.path.clone())
        .collect();
    let references = collect_active_reference_index(platform, &paths);
    let registry = ArtifactPatternRegistry::default();
    let engine = ScoringEngine::from_config(&config.scoring, config.scanner.min_file_age_minutes);
    for Checked {
        path: dir,
        bytes,
        age,
        identity,
    } in checked
    {
        // The batch pins the surveyed inode, which the executor checks again
        // before removal; a directory swapped since the survey is left.
        if current_identity(&dir) != Some(identity) {
            selection.leave("changed");
            continue;
        }
        // An agent's target dir has any name (`target-wasm`, `cargo-target`):
        // with a valid CACHEDIR.TAG the classifier calls it a tagged cache.
        let signals = structural_signals_for_path(&dir);
        let classification = registry.classify(&dir, signals);
        if !matches!(
            classification.category,
            ArtifactCategory::RustTarget | ArtifactCategory::CacheDir
        ) {
            selection.leave("not_build_output");
            continue;
        }
        let input = CandidateInput {
            active_references: references.summary_for(&dir),
            path: dir,
            size_bytes: bytes,
            age,
            classification,
            signals,
            is_open: false,
            excluded: false,
        };
        let mut score = engine.score_candidate(&input, urgency);
        if score.vetoed {
            selection.leave("vetoed");
            continue;
        }
        // The executor plans Delete verdicts only.
        if score.decision.action != DecisionAction::Delete {
            selection.leave("scored_keep");
            continue;
        }
        score.identity = Some(identity);
        selection.candidates.push(score);
    }
    selection.candidates.sort_by(|a, b| {
        b.size_bytes
            .cmp(&a.size_bytes)
            .then_with(|| a.path.cmp(&b.path))
    });
    selection
}

/// A root due for a pass, with its mount's pressure.
#[derive(Debug, Clone, PartialEq)]
pub struct DueRoot {
    /// A directory a `scanner.target_only_roots` pattern names.
    pub root: PathBuf,
    /// Pressure of the mount holding it; the batch carries it.
    pub level: PressureLevel,
    /// That mount's urgency, for scoring and the executor's dampening.
    pub urgency: f64,
}

/// Revocable authority for the protection exception carried by a target-only
/// batch. The root and scanner settings are those that admitted its survey;
/// an old worker cannot acquire new authority from a later configuration.
#[derive(Debug, Clone)]
pub struct TargetOnlyConsent {
    root: PathBuf,
    scanner: ScannerConfig,
    revoked: Arc<AtomicBool>,
}

impl TargetOnlyConsent {
    pub(super) fn new(root: &Path, scanner: &ScannerConfig, revoked: Arc<AtomicBool>) -> Self {
        Self {
            root: root.to_path_buf(),
            scanner: scanner.clone(),
            revoked,
        }
    }

    pub(super) fn permits(&self, root: &Path, scanner: &ScannerConfig) -> bool {
        !self.revoked.load(Ordering::Acquire)
            && self.root == root
            && !scanner.target_only_roots.is_empty()
            && crate::daemon::loop_main::scanner_mutation_scope_matches(
                &self.scanner,
                scanner,
                true,
            )
    }
}

/// Scheduling state of the tier: at most one pass in flight.
#[derive(Debug, Default)]
pub struct TargetTier {
    running: Arc<AtomicBool>,
    last_start: Option<Instant>,
    /// When the roots were last expanded to see whether one is due.
    last_probe: Option<Instant>,
    /// A configuration change permanently revokes this generation, including
    /// batches already queued for the executor. Re-enabling cannot revive it.
    revoked: Arc<AtomicBool>,
    scanner: Option<ScannerConfig>,
}

impl TargetTier {
    /// Called at reload, even when the target-only roots become empty. No
    /// filesystem I/O or waiting: a blocked old worker keeps its slot but loses
    /// authority to submit or execute work under its previous configuration.
    pub fn update_config(&mut self, scanner: &ScannerConfig) {
        if self.scanner.as_ref().is_some_and(|previous| {
            !crate::daemon::loop_main::scanner_mutation_scope_matches(previous, scanner, true)
        }) {
            self.revoked.store(true, Ordering::Release);
            self.revoked = Arc::new(AtomicBool::new(false));
            self.last_probe = None;
            self.last_start = None;
        }
        self.scanner = Some(scanner.clone());
    }

    /// Start a pass on its own thread when one is due. `mounts` maps each
    /// monitored mount to its pressure level and urgency.
    pub fn tick(
        &mut self,
        now: Instant,
        config: &Config,
        platform: &Arc<dyn Platform>,
        mounts: &HashMap<PathBuf, (PressureLevel, f64)>,
        del_tx: &Sender<DeletionBatch>,
        logger: &ActivityLoggerHandle,
    ) {
        self.update_config(&config.scanner);
        if config.scanner.target_only_roots.is_empty()
            || self.running.load(Ordering::Acquire)
            || self
                .last_start
                .is_some_and(|last| now.saturating_duration_since(last) < PASS_INTERVAL)
            || self
                .last_probe
                .is_some_and(|last| now.saturating_duration_since(last) < PROBE_INTERVAL)
        {
            return;
        }
        self.last_probe = Some(now);
        let due: Vec<DueRoot> = expand_roots(&config.scanner.target_only_roots)
            .into_iter()
            .filter_map(|root| {
                let stats = platform.fs_stats(&root).ok()?;
                let &(level, urgency) = mounts.get(&stats.mount_point)?;
                (level >= START_LEVEL).then_some(DueRoot {
                    root,
                    level,
                    urgency,
                })
            })
            .collect();
        if due.is_empty() {
            return;
        }
        self.last_start = Some(now);
        self.running.store(true, Ordering::Release);
        let guard = RunningGuard(Arc::clone(&self.running));
        let config = config.clone();
        let platform = Arc::clone(platform);
        let del_tx = del_tx.clone();
        let logger = logger.clone();
        let revoked = Arc::clone(&self.revoked);
        let spawned = std::thread::Builder::new()
            .name("sbh-targets".to_string())
            .spawn(move || {
                let _guard = guard;
                for root in due {
                    if revoked.load(Ordering::Acquire) {
                        break;
                    }
                    let message = run_root(
                        &root,
                        &config,
                        platform.as_ref(),
                        &del_tx,
                        SystemTime::now(),
                        &revoked,
                    );
                    eprintln!("[SBH-TARGETS] {message}");
                    logger.send(ActivityEvent::Info { message });
                }
            });
        if let Err(error) = spawned {
            // The closure, and with it the guard, was dropped: running is clear.
            eprintln!("[SBH-TARGETS] pass thread failed to start: {error}");
        }
    }
}

/// One root: select, then hand the candidates to the executor as a
/// target-only batch. Returns the summary line.
fn run_root(
    due: &DueRoot,
    config: &Config,
    platform: &dyn Platform,
    del_tx: &Sender<DeletionBatch>,
    now: SystemTime,
    revoked: &Arc<AtomicBool>,
) -> String {
    if revoked.load(Ordering::Acquire) {
        return format!("root={} target-only consent revoked", due.root.display());
    }
    let selection = select(&due.root, config, platform, due.urgency, now);
    let summary = selection.summary(&due.root);
    if revoked.load(Ordering::Acquire) {
        return format!("{summary}; target-only consent revoked; no batch submitted");
    }
    if selection.candidates.is_empty() {
        return summary;
    }
    let root = resolve_absolute_path(&due.root);
    let batch = DeletionBatch {
        candidates: selection.candidates,
        pressure_level: due.level,
        urgency: due.urgency,
        target_bytes: None,
        // Resolved like the candidates' paths, so the executor's containment
        // check compares like with like.
        target_only_root: Some(root.clone()),
        target_only_consent: Some(TargetOnlyConsent::new(
            &root,
            &config.scanner,
            Arc::clone(revoked),
        )),
    };
    match del_tx.try_send(batch) {
        Ok(()) => format!("{summary}; sent to the executor (level={:?})", due.level),
        Err(_) => format!("{summary}; executor queue full, next pass retries"),
    }
}

/// Clears `running` when the pass ends, however it ends.
struct RunningGuard(Arc<AtomicBool>);

impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    use filetime::{FileTime, set_symlink_file_times};

    use super::*;
    use crate::platform::pal::MockPlatform;
    use crate::platform::types::{OpenFile, OpenFileKind, OpenFileMode, ProcessInfo};

    const TAG: &str = "Signature: 8a477f597d28d172789f06886806bc55\n\
                       # This file is a cache directory tag created by cargo.\n";

    /// A cargo target dir as cargo leaves it: the tag, rustc's cache file and
    /// a debug build holding a 1 MiB rlib.
    fn cargo_target(dir: &Path) {
        fs::create_dir_all(dir.join("debug/deps")).unwrap();
        fs::write(dir.join("CACHEDIR.TAG"), TAG).unwrap();
        fs::write(dir.join(".rustc_info.json"), "{}").unwrap();
        fs::write(dir.join("debug/deps/libdemo.rlib"), vec![7u8; 1 << 20]).unwrap();
    }

    /// Set `dir` and everything under it to `hours` ago.
    fn age(dir: &Path, hours: u64) {
        let then =
            FileTime::from_system_time(SystemTime::now() - Duration::from_secs(hours * 3600));
        let mut stack = vec![dir.to_path_buf()];
        while let Some(current) = stack.pop() {
            let meta = fs::symlink_metadata(&current).unwrap();
            if meta.is_dir() {
                for entry in fs::read_dir(&current).unwrap() {
                    stack.push(entry.unwrap().path());
                }
            }
            set_symlink_file_times(&current, then, then).unwrap();
        }
    }

    /// A scratch root under /tmp: on rch workers the default temp dir sits
    /// inside the synced /data/projects tree, which the scorer treats as
    /// source (bd-c47s).
    fn scratch_root() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let root = temp.path().join("claude-501");
        fs::create_dir(&root).unwrap();
        (temp, root)
    }

    /// The clock the tests select at. A directory's birth time cannot be set
    /// back, and the tier counts a candidate's own birth time, so the tests
    /// move the clock forward past the 24 h idle window instead: what `age`
    /// set back 48 h, and anything created during the test, is idle then.
    fn later() -> SystemTime {
        SystemTime::now() + Duration::from_hours(25)
    }

    /// Set `path`'s times to `hours` after now (inside the window as seen
    /// from [`later`]).
    fn touch_ahead(path: &Path, hours: u64) {
        let ahead = FileTime::from_system_time(SystemTime::now() + Duration::from_hours(hours));
        set_symlink_file_times(path, ahead, ahead).unwrap();
    }

    fn select_in(root: &Path, platform: &MockPlatform) -> Selection {
        select(root, &Config::default(), platform, 0.5, later())
    }

    fn names(selection: &Selection) -> Vec<String> {
        let mut names: Vec<String> = selection
            .candidates
            .iter()
            .map(|candidate| {
                candidate
                    .path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn purity_requires_a_complete_readable_listing() {
        let (_temp, root) = scratch_root();
        let target = root.join("target");
        cargo_target(&target);
        assert!(still_pure(&target));
        // Even when every entry observed so far is cargo output, an unseen
        // suffix cannot authorize the root-wide protection exception.
        assert!(first_impurity(&target, 1).is_err());
        assert!(!still_pure(&root.join("missing-target")));
        fs::write(target.join("session-notes.txt"), b"keep this evidence").unwrap();
        assert!(!still_pure(&target));
    }

    #[test]
    fn pure_idle_targets_are_nominated_with_macos_files_and_a_wasm_triple() {
        let (_temp, root) = scratch_root();
        let plain = root.join("-proj/session-1/scratchpad/target-plain");
        let mac = root.join("-proj/session-2/scratchpad/target-mac");
        let wasm = root.join("-proj/session-3/cargo-target");
        for dir in [&plain, &mac, &wasm] {
            cargo_target(dir);
        }
        fs::write(mac.join(".DS_Store"), b"x").unwrap();
        fs::write(mac.join(".metadata_never_index"), b"").unwrap();
        fs::create_dir_all(plain.join("release-lto/deps")).unwrap();
        fs::write(plain.join(".cargo-lock"), b"").unwrap();
        fs::create_dir_all(wasm.join("wasm32-wasip1/debug")).unwrap();
        fs::write(wasm.join("wasm32-wasip1/debug/demo.wasm"), vec![1u8; 4096]).unwrap();
        age(&root, 48);

        let selection = select_in(&root, &MockPlatform::healthy());
        assert_eq!(
            names(&selection),
            ["cargo-target", "target-mac", "target-plain"],
            "{}",
            selection.summary(&root)
        );
        assert!(selection.complete);
        assert_eq!(selection.discovered, 3);
        for candidate in &selection.candidates {
            assert!(candidate.identity.is_some());
            assert!(candidate.size_bytes >= 1 << 20);
            assert!(!candidate.vetoed);
            assert_eq!(candidate.decision.action, DecisionAction::Delete);
        }
    }

    #[test]
    fn impure_recent_and_marked_targets_and_other_dirs_are_left_alone() {
        let (_temp, root) = scratch_root();
        let impure = [
            root.join("s1/target-trace"),
            root.join("s2/target-e2e"),
            root.join("s3/target-replay"),
            root.join("s4/target-bench"),
        ];
        for dir in &impure {
            cargo_target(dir);
        }
        fs::create_dir(impure[0].join("trace")).unwrap();
        fs::create_dir(impure[1].join("e2e-logs")).unwrap();
        fs::write(impure[2].join("replay.jsonl"), b"{}\n").unwrap();
        // Benchmark baselines are evidence, not build output.
        fs::create_dir(impure[3].join("criterion")).unwrap();
        let marked_inside = root.join("s5/target-marked-inside");
        cargo_target(&marked_inside);
        fs::write(marked_inside.join("debug/.sbh-protect"), b"").unwrap();
        let marked_self = root.join("s6/target-marked-self");
        cargo_target(&marked_self);
        fs::write(marked_self.join(".sbh-protect"), b"").unwrap();
        cargo_target(&root.join("s7/keep/target-under-marker"));
        fs::write(root.join("s7/.sbh-protect"), b"").unwrap();
        // Not targets of their own: a clone with its target, notes.
        fs::create_dir_all(root.join("s8/clone/.git")).unwrap();
        cargo_target(&root.join("s8/clone/target"));
        fs::create_dir_all(root.join("s9/notes")).unwrap();
        fs::write(root.join("s9/notes/plan.md"), b"# plan\n").unwrap();
        age(&root, 48);
        // Touched within the idle window: one file deep inside.
        let recent = root.join("s10/target-recent");
        cargo_target(&recent);
        age(&recent, 48);
        fs::write(recent.join("debug/deps/fresh.d"), b"x").unwrap();
        touch_ahead(&recent.join("debug/deps/fresh.d"), 2);

        let selection = select_in(&root, &MockPlatform::healthy());
        assert!(
            selection.candidates.is_empty(),
            "{}",
            selection.summary(&root)
        );
        assert_eq!(selection.left.get("impure"), Some(&4));
        // A marker in the dir itself, or between it and the root, hides it
        // from discovery; one deeper inside is found by the survey.
        assert_eq!(selection.left.get("protect_marker"), Some(&1));
        assert_eq!(selection.left.get("recent"), Some(&1));
        // The four impure ones, the one marked inside and the recent one.
        assert_eq!(selection.discovered, 6);
    }

    #[cfg(unix)]
    #[test]
    fn git_symlinks_future_times_and_non_cargo_contents_keep_a_target() {
        let (_temp, root) = scratch_root();
        for name in [
            "target-git",
            "target-symlink",
            "target-future",
            "target-release-notes",
            "target-tmp-output",
            "target-empty-tmp",
        ] {
            cargo_target(&root.join("s").join(name));
        }
        let dir = |name: &str| root.join("s").join(name);
        fs::create_dir_all(dir("target-git").join("debug/vendored/.git")).unwrap();
        std::os::unix::fs::symlink("debug", dir("target-symlink").join("debug-link")).unwrap();
        fs::create_dir(dir("target-release-notes").join("release-notes")).unwrap();
        fs::write(
            dir("target-release-notes").join("release-notes/0.2.md"),
            b"# notes\n",
        )
        .unwrap();
        fs::create_dir(dir("target-tmp-output").join("tmp")).unwrap();
        fs::write(dir("target-tmp-output").join("tmp/report.json"), b"{}").unwrap();
        fs::create_dir(dir("target-empty-tmp").join("tmp")).unwrap();
        age(&root, 48);
        // In the future even as seen from `later`: fails closed.
        touch_ahead(&dir("target-future").join("debug/deps/libdemo.rlib"), 48);

        let selection = select_in(&root, &MockPlatform::healthy());
        assert_eq!(
            names(&selection),
            ["target-empty-tmp"],
            "{}",
            selection.summary(&root)
        );
        assert_eq!(selection.left.get("impure"), Some(&3));
        assert_eq!(selection.left.get("git"), Some(&1));
        assert_eq!(selection.left.get("recent"), Some(&1));
    }

    #[test]
    fn excluded_paths_are_not_walked() {
        let (_temp, root) = scratch_root();
        cargo_target(&root.join("s1/target"));
        cargo_target(&root.join("s2/target"));
        age(&root, 48);
        let mut config = Config::default();
        config.scanner.excluded_paths.push(root.join("s1"));

        let selection = select(&root, &config, &MockPlatform::healthy(), 0.5, later());
        assert_eq!(selection.discovered, 1);
        assert_eq!(selection.candidates.len(), 1);
        assert!(selection.candidates[0].path.ends_with("s2/target"));
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_replaced_after_its_survey_no_longer_matches_its_identity() {
        let (_temp, root) = scratch_root();
        let target = root.join("s1/target");
        cargo_target(&target);
        age(&root, 48);
        let idle_cutoff = later() - Duration::from_hours(24);
        let surveyed = survey(&target, idle_cutoff, Instant::now() + SURVEY_BUDGET);
        assert_eq!(surveyed.kept, None);
        assert_eq!(current_identity(&target), surveyed.identity);

        // Swapped for another directory, or for a symlink to one.
        fs::rename(&target, root.join("s1/moved")).unwrap();
        cargo_target(&target);
        assert!(surveyed.identity.is_some());
        assert_ne!(current_identity(&target), surveyed.identity);
        fs::remove_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(root.join("s1/moved"), &target).unwrap();
        assert_eq!(current_identity(&target), None, "a symlink is not the dir");
    }

    #[test]
    fn a_due_root_sends_one_target_only_batch_pinned_to_its_root() {
        let (_temp, root) = scratch_root();
        cargo_target(&root.join("s1/target"));
        age(&root, 48);
        let (del_tx, del_rx) = crossbeam_channel::bounded(1);
        let due = DueRoot {
            root: root.clone(),
            level: PressureLevel::Red,
            urgency: 0.8,
        };
        let mut config = Config::default();
        config.scanner.target_only_roots = vec![root.clone()];

        let summary = run_root(
            &due,
            &config,
            &MockPlatform::healthy(),
            &del_tx,
            later(),
            &Arc::new(AtomicBool::new(false)),
        );
        let batch = del_rx
            .try_recv()
            .unwrap_or_else(|_| panic!("no batch: {summary}"));
        assert_eq!(batch.target_only_root, Some(resolve_absolute_path(&root)));
        assert_eq!(batch.pressure_level, PressureLevel::Red);
        assert_eq!(batch.candidates.len(), 1);
        let candidate = &batch.candidates[0];
        assert!(candidate.path.starts_with(resolve_absolute_path(&root)));
        assert!(candidate.identity.is_some());
        assert!(
            batch
                .target_only_consent
                .as_ref()
                .unwrap()
                .permits(batch.target_only_root.as_ref().unwrap(), &config.scanner,)
        );
    }

    #[test]
    fn material_reloads_permanently_revoke_old_target_only_consent() {
        type ScopeChange = fn(&mut ScannerConfig);
        let cases: [(&str, ScopeChange); 10] = [
            ("disabled", |scanner| scanner.target_only_roots.clear()),
            ("different roots", |scanner| {
                scanner.target_only_roots = vec!["/different".into()]
            }),
            ("idle window", |scanner| scanner.target_only_idle_hours += 1),
            ("minimum age", |scanner| scanner.min_file_age_minutes += 1),
            ("excluded path", |scanner| {
                scanner.excluded_paths.push("/scratch/new-work".into())
            }),
            ("protected path", |scanner| {
                scanner.protected_paths.push("/scratch/new-work/**".into())
            }),
            ("scanner roots", |scanner| {
                scanner.root_paths.push("/new-scan-root".into())
            }),
            ("source permission", |scanner| {
                scanner.allow_source_tree_roots = !scanner.allow_source_tree_roots
            }),
            ("symlinks", |scanner| {
                scanner.follow_symlinks = !scanner.follow_symlinks
            }),
            ("devices", |scanner| {
                scanner.cross_devices = !scanner.cross_devices
            }),
        ];
        let root = Path::new("/scratch");
        let scanner = ScannerConfig {
            target_only_roots: vec![root.into()],
            ..Default::default()
        };
        for (label, change) in cases {
            let mut tier = TargetTier::default();
            tier.update_config(&scanner);
            let old = TargetOnlyConsent::new(root, &scanner, Arc::clone(&tier.revoked));
            assert!(old.permits(root, &scanner), "{label}");
            tier.running.store(true, Ordering::Release);
            let guard = RunningGuard(Arc::clone(&tier.running));
            tier.last_start = Some(Instant::now());
            tier.last_probe = Some(Instant::now());

            let mut replacement = scanner.clone();
            change(&mut replacement);
            tier.update_config(&replacement);
            assert!(!old.permits(root, &replacement), "{label}");
            assert!(
                !old.permits(root, &scanner),
                "{label}: old authority is revoked"
            );
            assert!(
                tier.running.load(Ordering::Acquire),
                "{label}: worker keeps its slot"
            );
            assert!(tier.last_start.is_none(), "{label}");
            assert!(tier.last_probe.is_none(), "{label}");

            tier.update_config(&scanner);
            assert!(
                !old.permits(root, &scanner),
                "{label}: re-enabling cannot revive old work"
            );
            let current = TargetOnlyConsent::new(root, &scanner, Arc::clone(&tier.revoked));
            assert!(
                current.permits(root, &scanner),
                "{label}: future work has fresh consent"
            );
            assert!(
                !current.permits(Path::new("/other-root"), &scanner),
                "{label}"
            );
            drop(guard);
        }
    }

    #[test]
    fn event_and_worker_tuning_preserve_target_only_consent() {
        let root = Path::new("/scratch");
        let mut scanner = ScannerConfig {
            target_only_roots: vec![root.into()],
            ..Default::default()
        };
        let mut tier = TargetTier::default();
        tier.update_config(&scanner);
        let consent = TargetOnlyConsent::new(root, &scanner, Arc::clone(&tier.revoked));
        scanner.parallelism += 1;
        scanner.event_watch_budget += 1;
        scanner.event_source = crate::core::config::ScannerEventSourceMode::ReconciliationOnly;
        tier.update_config(&scanner);
        assert!(consent.permits(root, &scanner));
    }

    #[test]
    fn queued_target_only_batch_stays_revoked_after_disable_and_reenable() {
        let (_temp, root) = scratch_root();
        cargo_target(&root.join("s1/target"));
        age(&root, 48);
        let mut config = Config::default();
        config.scanner.target_only_roots = vec![root.clone()];
        let mut tier = TargetTier::default();
        tier.update_config(&config.scanner);
        let old_token = Arc::clone(&tier.revoked);
        let due = DueRoot {
            root,
            level: PressureLevel::Red,
            urgency: 0.8,
        };
        let (send, receive) = crossbeam_channel::bounded(1);
        let summary = run_root(
            &due,
            &config,
            &MockPlatform::healthy(),
            &send,
            later(),
            &old_token,
        );
        let batch = receive.try_recv().unwrap_or_else(|_| panic!("{summary}"));
        let witness = batch.target_only_consent.as_ref().unwrap();
        let bound_root = batch.target_only_root.as_ref().unwrap();
        assert!(witness.permits(bound_root, &config.scanner));

        let mut disabled = config.scanner.clone();
        disabled.target_only_roots.clear();
        tier.update_config(&disabled);
        tier.update_config(&config.scanner);
        assert!(!witness.permits(bound_root, &config.scanner));
        let summary = run_root(
            &due,
            &config,
            &MockPlatform::healthy(),
            &send,
            later(),
            &old_token,
        );
        assert!(summary.contains("consent revoked"));
        assert!(
            receive.try_recv().is_err(),
            "old worker cannot submit another root"
        );
    }

    #[test]
    fn an_open_file_or_a_working_directory_inside_keeps_the_target() {
        let (_temp, root) = scratch_root();
        let open = root.join("s1/target-open");
        let cwd = root.join("s2/target-cwd");
        let idle = root.join("s3/target-idle");
        for dir in [&open, &cwd, &idle] {
            cargo_target(dir);
        }
        age(&root, 48);
        let platform = MockPlatform::healthy()
            .with_open_file(OpenFile {
                pid: 4242,
                path: open.join("debug/deps/libdemo.rlib"),
                fd: Some(3),
                kind: OpenFileKind::Regular,
                mode: OpenFileMode::Read,
            })
            .with_process(ProcessInfo {
                pid: 4343,
                parent_pid: None,
                name: "cargo".to_string(),
                command_line: Vec::new(),
                executable: None,
                cwd: Some(cwd.join("debug")),
                start_time_unix_ms: None,
                virtual_memory_bytes: None,
                resident_memory_bytes: None,
                cpu_user_micros: None,
                cpu_system_micros: None,
            });

        let selection = select_in(&root, &platform);
        assert_eq!(
            names(&selection),
            ["target-idle"],
            "{}",
            selection.summary(&root)
        );
        assert_eq!(selection.left.get("vetoed"), Some(&2));
    }

    #[test]
    fn the_root_itself_is_never_a_candidate_and_a_marked_root_is_not_walked() {
        let (_temp, root) = scratch_root();
        cargo_target(&root);
        cargo_target(&root.join("s1/target-inner"));
        age(&root, 48);
        // The root's own cargo files do not make it a candidate, and
        // discovery still walks below it.
        let selection = select_in(&root, &MockPlatform::healthy());
        assert_eq!(names(&selection), ["target-inner"]);

        fs::write(root.join(".sbh-protect"), b"").unwrap();
        let selection = select_in(&root, &MockPlatform::healthy());
        assert!(selection.candidates.is_empty());
        assert_eq!(selection.discovered, 0);
    }

    #[test]
    fn root_patterns_expand_to_matching_directories_only() {
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        for name in ["claude-501", "claude-502", "other"] {
            fs::create_dir(temp.path().join(name)).unwrap();
        }
        fs::write(temp.path().join("claude-file"), b"").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(temp.path().join("other"), temp.path().join("claude-link"))
            .unwrap();

        let roots = expand_roots(&[temp.path().join("claude-*")]);
        assert_eq!(
            roots,
            [
                temp.path().join("claude-501"),
                temp.path().join("claude-502")
            ]
        );
        assert!(expand_roots(&[temp.path().join("absent-*")]).is_empty());
    }

    #[test]
    fn release_profiles_and_target_triples_are_cargo_output() {
        for profile in ["release-lto", "release-with-debug", "release-2"] {
            assert!(is_cargo_entry(profile, true), "{profile}");
        }
        for other in [
            "release-",
            "release_lto",
            "Release-LTO",
            "criterion",
            "nextest",
        ] {
            assert!(!is_cargo_entry(other, true), "{other}");
        }
        // Names cargo uses for files are not cargo's when they are directories.
        assert!(is_cargo_entry(".cargo-lock", false));
        assert!(!is_cargo_entry(".cargo-lock", true));
        assert!(!is_cargo_entry("debug", false));
    }

    #[test]
    fn target_triples_are_recognized_and_custom_profiles_are_not() {
        for triple in [
            "x86_64-unknown-linux-gnu",
            "aarch64-apple-darwin",
            "wasm32-wasip1",
            "wasm32-unknown-unknown",
            "armv7-unknown-linux-gnueabihf",
            "thumbv7em-none-eabihf",
            "riscv64gc-unknown-linux-gnu",
            "wasm32v1-none",
            "aarch64-linux-android",
        ] {
            assert!(is_target_triple(triple), "{triple}");
        }
        for other in [
            "release-lto",
            "debug",
            "trace",
            "e2e-logs",
            "x86_64",
            "wasm32-",
            "notes",
            // An architecture and an agent's own word are not a triple.
            "x86_64-trace",
            "arm-e2e",
            "wasm32-replay",
        ] {
            assert!(!is_target_triple(other), "{other}");
        }
    }

    #[test]
    fn a_tier_with_no_roots_never_starts_a_pass() {
        let mut tier = TargetTier::default();
        let mut config = Config::default();
        config.scanner.target_only_roots.clear();
        let platform: Arc<dyn Platform> = Arc::new(MockPlatform::healthy());
        let (del_tx, del_rx) = crossbeam_channel::bounded(1);
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let (logger, join) =
            crate::logger::dual::spawn_logger(crate::logger::dual::DualLoggerConfig {
                sqlite_path: None,
                jsonl_config: crate::logger::jsonl::JsonlConfig {
                    path: temp.path().join("activity.jsonl"),
                    fallback_path: None,
                    max_size_bytes: 1_048_576,
                    max_rotated_files: 0,
                    fsync_interval_secs: 0,
                },
                channel_capacity: 64,
                run_id: None,
            })
            .unwrap();
        tier.tick(
            Instant::now(),
            &config,
            &platform,
            &HashMap::new(),
            &del_tx,
            &logger,
        );
        assert!(tier.last_start.is_none());
        assert!(del_rx.try_recv().is_err());
        logger.shutdown();
        join.join().unwrap();
    }
}
