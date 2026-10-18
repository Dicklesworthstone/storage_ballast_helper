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
//!    `release`, `release-*` profiles, `doc`, `tmp`, `package`, a target
//!    triple such as `wasm32-wasip1`, the two marker files and cargo's lock
//!    and report files) plus the macOS `.DS_Store` and
//!    `.metadata_never_index`; anything else, benchmark baselines included,
//!    makes it work, not output;
//! 3. no `.sbh-protect` marker in it, inside it or in a directory between it
//!    and the root, and no `.git` inside it;
//! 4. nothing inside it modified within `scanner.target_only_idle_hours`;
//! 5. no process holds a file open in it or works inside it.
//!
//! The survivors are scored like any candidate and reach the executor as a
//! target-only batch: the policy mode, the decision ledger, dampening, the
//! certainty gate, the planner and every executor check still apply. Only
//! the operator's `protected_paths` patterns are not applied to these paths.
//! Everything else under the root stays untouchable, and with no roots
//! configured the tier never reads the disk.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use crossbeam_channel::Sender;

use crate::core::config::Config;
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
/// Wall time of one discovery.
const DISCOVERY_BUDGET: Duration = Duration::from_secs(30);
/// Entries one candidate's survey may visit before it fails closed.
const SURVEY_MAX_ENTRIES: u64 = 2_000_000;
/// Wall time for surveying all of one pass's candidates.
const SURVEY_BUDGET: Duration = Duration::from_secs(120);

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

/// A custom profile derived from release, such as `release-lto`.
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
/// `--target`. A custom profile dir (`release-lto`) is not one.
fn is_target_triple(name: &str) -> bool {
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
        && !rest.is_empty()
        && rest.iter().all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.')
        })
}

/// The first top-level entry of `dir` that cargo did not write, or an error
/// when the listing cannot be read (which keeps the directory).
fn first_impurity(dir: &Path) -> std::io::Result<Option<String>> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let file_type = entry.file_type()?;
        let pure = !file_type.is_symlink() && is_cargo_entry(&name, file_type.is_dir());
        if !pure {
            return Ok(Some(name));
        }
    }
    Ok(None)
}

/// What a walk of one candidate found.
#[derive(Debug, Default)]
struct Survey {
    newest: Option<SystemTime>,
    bytes: u64,
    marker: bool,
    git: bool,
    complete: bool,
}

/// Walk `dir` without following symlinks or leaving its device. Stops at the
/// first marker or `.git`; a budget, another device or an unreadable entry
/// leaves the survey incomplete, which keeps the directory.
fn survey(dir: &Path, deadline: Instant) -> Survey {
    let mut found = Survey::default();
    let Ok(top) = fs::symlink_metadata(dir) else {
        return found;
    };
    let device = device_of(&top);
    found.newest = top.modified().ok();
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
                found.marker = true;
                return found;
            }
            if name == ".git" {
                found.git = true;
                return found;
            }
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                return found;
            };
            if let Ok(modified) = meta.modified() {
                found.newest = Some(found.newest.map_or(modified, |newest| newest.max(modified)));
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
    found.complete = true;
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

/// Names a listing holds that steer discovery.
#[derive(Debug, Default)]
struct Markers {
    protect: bool,
    git: bool,
    cargo: bool,
}

fn markers_in(dir: &Path) -> Option<(Markers, Vec<PathBuf>)> {
    let mut markers = Markers::default();
    let mut children = Vec::new();
    for entry in fs::read_dir(dir).ok()? {
        let entry = entry.ok()?;
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
    Some((markers, children))
}

/// Directories under `root` with cargo structure at their top, shallowest
/// first. Never the root itself, and never below a candidate, a marker, a
/// `.git` entry, another device or an unreadable directory. Returns whether
/// the walk covered the root.
fn discover(root: &Path, found: &mut Vec<PathBuf>) -> bool {
    let deadline = Instant::now() + DISCOVERY_BUDGET;
    let Ok(root_meta) = fs::symlink_metadata(root) else {
        return false;
    };
    let device = device_of(&root_meta);
    let mut queue = VecDeque::from([(root.to_path_buf(), 0usize)]);
    let mut read = 0usize;
    while let Some((dir, depth)) = queue.pop_front() {
        read += 1;
        if read > MAX_DIRECTORIES || Instant::now() >= deadline {
            return false;
        }
        let Some((markers, children)) = markers_in(&dir) else {
            continue;
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
            if fs::symlink_metadata(&child).is_ok_and(|meta| device_of(&meta) == device) {
                queue.push_back((child, depth + 1));
            }
        }
    }
    true
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
    selection.complete = discover(root, &mut found);
    selection.discovered = found.len();

    let idle = Duration::from_secs(config.scanner.target_only_idle_hours.saturating_mul(3600));
    let deadline = Instant::now() + SURVEY_BUDGET;
    let mut checked = Vec::new();
    for dir in found {
        match first_impurity(&dir) {
            Ok(None) => {}
            Ok(Some(_)) => {
                selection.leave("impure");
                continue;
            }
            Err(_) => {
                selection.leave("unreadable");
                continue;
            }
        }
        let facts = survey(&dir, deadline);
        let reason = if facts.marker {
            Some("protect_marker")
        } else if facts.git {
            Some("git")
        } else if !facts.complete {
            Some("unsurveyed")
        } else if facts.bytes == 0 {
            Some("empty")
        } else {
            None
        };
        if let Some(reason) = reason {
            selection.leave(reason);
            continue;
        }
        let age = facts
            .newest
            .and_then(|newest| now.duration_since(newest).ok());
        match age {
            // The reference index keys resolved paths: a parent symlink
            // must not hide a process working inside the candidate.
            Some(age) if age >= idle => {
                checked.push((resolve_absolute_path(&dir), facts.bytes, age));
            }
            _ => selection.leave("recent"),
        }
    }
    if checked.is_empty() {
        return selection;
    }

    let paths: Vec<PathBuf> = checked.iter().map(|(dir, _, _)| dir.clone()).collect();
    let references = collect_active_reference_index(platform, &paths);
    let registry = ArtifactPatternRegistry::default();
    let engine = ScoringEngine::from_config(&config.scoring, config.scanner.min_file_age_minutes);
    for (dir, bytes, age) in checked {
        let Some(identity) = fs::symlink_metadata(&dir)
            .ok()
            .as_ref()
            .and_then(identity_of)
        else {
            selection.leave("unreadable");
            continue;
        };
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

/// Scheduling state of the tier: at most one pass in flight.
#[derive(Debug, Default)]
pub struct TargetTier {
    running: Arc<AtomicBool>,
    last_start: Option<Instant>,
}

impl TargetTier {
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
        if config.scanner.target_only_roots.is_empty()
            || self.running.load(Ordering::Acquire)
            || self
                .last_start
                .is_some_and(|last| now.saturating_duration_since(last) < PASS_INTERVAL)
        {
            return;
        }
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
        let spawned = std::thread::Builder::new()
            .name("sbh-targets".to_string())
            .spawn(move || {
                let _guard = guard;
                for root in due {
                    let message = run_root(&root, &config, platform.as_ref(), &del_tx);
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
) -> String {
    let selection = select(&due.root, config, platform, due.urgency, SystemTime::now());
    let summary = selection.summary(&due.root);
    if selection.candidates.is_empty() {
        return summary;
    }
    let batch = DeletionBatch {
        candidates: selection.candidates,
        pressure_level: due.level,
        urgency: due.urgency,
        target_bytes: None,
        target_only: true,
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

    fn select_in(root: &Path, platform: &MockPlatform) -> Selection {
        select(root, &Config::default(), platform, 0.5, SystemTime::now())
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
