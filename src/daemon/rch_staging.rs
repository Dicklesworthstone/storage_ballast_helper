//! Daemon tier: rch staging trees.
//!
//! An rch worker keeps a copy of every project it builds under its staging
//! base (`transfer.remote_base`, `/data/tmp/rch` on this fleet), one tree per
//! `<base>/<project>/<tree>`. Those trees are project source, so the scanner
//! rightly keeps them, and nothing in sbh released them. On 2026-11-02 the
//! fleet's workers sat at 96-99% full with their ballast spent while about
//! 140 GB of these trees, idle for days, waited for an operator to run
//! `rch cache clean` by hand; they refilled within hours.
//!
//! rch owns the trees and has its own reaper: `rch cache clean` keeps any tree
//! modified within `--older` (its in-flight guard) and validates each path
//! before removing it. It knows nothing of `.sbh-protect` markers, protected
//! paths or the processes sbh can see, so this tier never hands it a whole
//! base. While a base's mount is at Orange or worse, a pass on its own
//! `sbh-rch-staging` thread:
//!
//! 1. asks rch, in a dry run, which trees it would prune at the level's age
//!    (Orange 72 h, Red 48 h, Critical 24 h);
//! 2. for each project directory holding one, largest first, runs a fresh
//!    dry run for that project alone and checks every tree rch would prune,
//!    or could by the time it runs: a real directory, not at or below an
//!    `excluded_paths` entry or a source tree, no `.sbh-protect` at it, above
//!    it or anywhere inside it (a walk that runs out of budget counts as a
//!    marker), no overlap with `protected_paths`, and no process holding a
//!    file open in it or working inside it;
//! 3. only when every such tree passes, has rch prune that project
//!    (`--project=<name> --execute`).
//!
//! The pass runs only in Enforce mode and never under `scanner.dry_run`, and
//! the `rch` it runs must be owned, together with every directory above it,
//! by root or the daemon's user and be writable by no one else.

use std::collections::{BTreeMap, HashMap};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::core::config::Config;
use crate::daemon::policy::ActiveMode;
use crate::logger::dual::{ActivityEvent, ActivityLoggerHandle};
use crate::monitor::pid::PressureLevel;
use crate::platform::pal::Platform;
use crate::scanner::protection::{
    self, MARKER_FILENAME, StowawayScanConfig, TRUNCATED_OVERLAP_PATTERN,
};
use crate::scanner::walker::collect_active_reference_index;
use crate::tuning::writeback::human_bytes;

/// Shortest gap between two passes over one base.
pub const BASE_INTERVAL: Duration = Duration::from_mins(30);
/// Shortest gap between two checks of whether a base is due.
const PROBE_INTERVAL: Duration = Duration::from_mins(1);
/// Longest one rch invocation may run before it is killed.
const RCH_TIMEOUT: Duration = Duration::from_mins(10);
/// Wall time of one pass; the projects it did not reach wait for the next.
const PASS_BUDGET: Duration = Duration::from_mins(30);
/// Projects one pass over one base may prune.
const MAX_PROJECTS: usize = 128;
/// Output kept from one rch invocation; more is a failed run.
const MAX_OUTPUT_BYTES: usize = 16 << 20;
/// A tree rch keeps as recent is checked too when it is this close to the
/// age at which rch would prune it, so a tree that ages past the line between
/// the check and the prune was still checked.
const RECHECK_MARGIN: Duration = Duration::from_hours(1);
/// Depth of the marker walk inside a tree; its directory budget bounds it.
const MARKER_SCAN_DEPTH: usize = 64;
/// Shortest gap between two notes that no usable rch was found.
const UNAVAILABLE_NOTE_INTERVAL: Duration = Duration::from_hours(24);
/// Where rch is looked for when `scanner.rch_binary` is unset.
const SYSTEM_BINARIES: [&str; 4] = [
    "/usr/local/bin/rch",
    "/usr/bin/rch",
    "/root/.local/bin/rch",
    "/root/.cargo/bin/rch",
];
/// The child's whole `PATH`.
const CHILD_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
/// Activity-log code of a failed rch run.
const WARNING_CODE: &str = "SBH-RCH-STAGING";

/// How long a tree must have been idle before the tier prunes it at `level`;
/// `None` below Orange, where the tier does not run.
#[must_use]
pub const fn min_idle_for(level: PressureLevel) -> Option<Duration> {
    match level {
        PressureLevel::Critical => Some(Duration::from_hours(24)),
        PressureLevel::Red => Some(Duration::from_hours(48)),
        PressureLevel::Orange => Some(Duration::from_hours(72)),
        PressureLevel::Green | PressureLevel::Yellow => None,
    }
}

/// Whether a file or directory with this owner and mode may be trusted by a
/// daemon running as `euid`: owned by root or by `euid`, and writable by
/// neither its group nor others.
#[must_use]
const fn trusted_owner_and_mode(owner: u32, mode: u32, euid: u32) -> bool {
    (owner == 0 || owner == euid) && mode & 0o022 == 0
}

/// The owner and mode of a file; `None` off Unix, where nothing is trusted.
#[cfg(unix)]
#[allow(clippy::unnecessary_wraps)]
fn owner_and_mode(meta: &fs::Metadata) -> Option<(u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    Some((meta.uid(), meta.mode()))
}

#[cfg(not(unix))]
fn owner_and_mode(_meta: &fs::Metadata) -> Option<(u32, u32)> {
    None
}

fn effective_uid() -> u32 {
    #[cfg(unix)]
    {
        nix::unistd::geteuid().as_raw()
    }
    #[cfg(not(unix))]
    {
        u32::MAX
    }
}

/// `path` resolved, when it is an executable regular file that it and every
/// directory above it pass [`trusted_owner_and_mode`]; otherwise why not.
fn trusted_binary(path: &Path, euid: u32) -> Result<PathBuf, String> {
    let resolved =
        fs::canonicalize(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let meta =
        fs::metadata(&resolved).map_err(|error| format!("{}: {error}", resolved.display()))?;
    let Some((_, mode)) = owner_and_mode(&meta) else {
        return Err("ownership cannot be checked on this platform".to_string());
    };
    if !meta.is_file() || mode & 0o111 == 0 {
        return Err(format!("{} is not an executable file", resolved.display()));
    }
    for item in resolved.ancestors() {
        let meta = fs::metadata(item).map_err(|error| format!("{}: {error}", item.display()))?;
        let (owner, mode) = owner_and_mode(&meta)
            .ok_or_else(|| "ownership cannot be checked on this platform".to_string())?;
        if !trusted_owner_and_mode(owner, mode, euid) {
            return Err(format!(
                "{} belongs to uid {owner} with mode {:o}",
                item.display(),
                mode & 0o7777
            ));
        }
    }
    Ok(resolved)
}

/// How the tier runs rch: a trusted binary with a cleared environment.
#[derive(Debug, Clone)]
struct RchRunner {
    binary: PathBuf,
    /// The child's `HOME`, where rch reads its configuration.
    home: PathBuf,
    timeout: Duration,
}

impl RchRunner {
    /// The configured binary, or the first system one that exists; it must be
    /// trusted ([`trusted_binary`]).
    fn resolve(config: &Config) -> Result<Self, String> {
        let euid = effective_uid();
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|home| home.is_absolute())
            .unwrap_or_else(|| PathBuf::from(if euid == 0 { "/root" } else { "/" }));
        let candidates: Vec<PathBuf> = config.scanner.rch_binary.as_ref().map_or_else(
            || {
                let mut candidates: Vec<PathBuf> =
                    SYSTEM_BINARIES.iter().map(PathBuf::from).collect();
                if euid != 0 {
                    candidates.push(home.join(".local/bin/rch"));
                    candidates.push(home.join(".cargo/bin/rch"));
                }
                candidates
            },
            |binary| vec![binary.clone()],
        );
        let mut refused = Vec::new();
        for candidate in &candidates {
            if fs::symlink_metadata(candidate).is_err() {
                continue;
            }
            match trusted_binary(candidate, euid) {
                Ok(binary) => {
                    return Ok(Self {
                        binary,
                        home,
                        timeout: RCH_TIMEOUT,
                    });
                }
                Err(why) => refused.push(why),
            }
        }
        Err(if refused.is_empty() {
            let looked = candidates
                .iter()
                .map(|candidate| candidate.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            format!("no rch binary at {looked}")
        } else {
            format!("no trusted rch binary: {}", refused.join("; "))
        })
    }

    /// Run rch with `args`; its stdout, or why the run failed. A set `stop`
    /// kills it.
    fn run(&self, args: &[OsString], stop: &AtomicBool) -> Result<Vec<u8>, String> {
        let mut child = Command::new(&self.binary)
            .args(args)
            .env_clear()
            .env("PATH", CHILD_PATH)
            .env("HOME", &self.home)
            .env("LC_ALL", "C")
            .env("RCH_NO_SELF_HEALING", "1")
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("cannot start {}: {error}", self.binary.display()))?;
        let deadline = Instant::now() + self.timeout;
        let stdout = drain(child.stdout.take());
        let stderr = drain(child.stderr.take());
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline && !stop.load(Ordering::Acquire) => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                waited => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(match waited {
                        Err(error) => format!("waiting for rch failed: {error}"),
                        _ if stop.load(Ordering::Acquire) => {
                            "rch stopped with the pass".to_string()
                        }
                        _ => format!("rch timed out after {} s", self.timeout.as_secs()),
                    });
                }
            }
        };
        let collect = |pipe: mpsc::Receiver<(Vec<u8>, bool)>| {
            pipe.recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_default()
        };
        let (out, out_truncated) = collect(stdout);
        let (err, _) = collect(stderr);
        if !status.success() {
            return Err(format!("rch exited with {status}: {}", tail(&err)));
        }
        if out_truncated {
            return Err(format!("rch wrote over {MAX_OUTPUT_BYTES} bytes"));
        }
        Ok(out)
    }
}

/// Read a pipe to its end on a thread, keeping the first
/// `MAX_OUTPUT_BYTES`; the flag says whether more was discarded. Draining
/// keeps the child from blocking on a full pipe.
fn drain(pipe: Option<impl Read + Send + 'static>) -> mpsc::Receiver<(Vec<u8>, bool)> {
    let (tx, rx) = mpsc::sync_channel(1);
    let Some(mut pipe) = pipe else {
        let _ = tx.send((Vec::new(), false));
        return rx;
    };
    // When the thread cannot start, the sender goes with the closure and the
    // receiver reads nothing.
    let _ = std::thread::Builder::new()
        .name("sbh-rch-pipe".to_string())
        .spawn(move || {
            let mut kept = Vec::new();
            let mut truncated = false;
            let mut buffer = vec![0u8; 64 * 1024];
            loop {
                match pipe.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        let room = MAX_OUTPUT_BYTES.saturating_sub(kept.len());
                        truncated |= count > room;
                        kept.extend_from_slice(&buffer[..count.min(room)]);
                    }
                    Err(error) if error.kind() == ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            let _ = tx.send((kept, truncated));
        });
    rx
}

/// The last line of rch's stderr, for a log line.
fn tail(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let line = text.lines().rev().find(|line| !line.trim().is_empty());
    line.map_or_else(
        || "(no stderr)".to_string(),
        |line| line.trim().chars().take(300).collect(),
    )
}

/// rch's JSON envelope.
#[derive(Debug, Deserialize)]
struct Envelope<T> {
    success: bool,
    data: Option<T>,
    #[serde(default)]
    error: Option<serde_json::Value>,
}

/// One tree of an `rch cache clean` dry run.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct PlanEntry {
    path: PathBuf,
    size_bytes: u64,
    age_secs: u64,
    /// `prune`, `keep_recent` or `keep_unsafe_path`.
    action: String,
}

impl PlanEntry {
    fn prunes(&self) -> bool {
        self.action == "prune"
    }

    /// Whether rch prunes the tree now or could by the time it runs.
    fn at_risk(&self, min_idle: Duration) -> bool {
        self.prunes()
            || (self.action == "keep_recent"
                && Duration::from_secs(self.age_secs) + RECHECK_MARGIN >= min_idle)
    }

    /// The project directory's name (`<base>/<project>/<tree>`).
    fn project(&self) -> Option<&OsStr> {
        self.path.parent()?.file_name()
    }
}

/// An `rch cache clean` dry run.
#[derive(Debug, Deserialize)]
struct Plan {
    entries: Vec<PlanEntry>,
}

/// An `rch cache clean --execute` run.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
struct Outcome {
    removed_count: u64,
    removed_bytes: u64,
    #[serde(default)]
    failed: Vec<String>,
}

/// The `data` of a successful rch JSON envelope.
fn parse<T: DeserializeOwned>(stdout: &[u8]) -> Result<T, String> {
    let envelope: Envelope<T> = serde_json::from_slice(stdout)
        .map_err(|error| format!("rch output is not its JSON envelope: {error}"))?;
    if !envelope.success {
        return Err(format!(
            "rch reported failure: {}",
            envelope
                .error
                .map_or_else(|| "no detail".to_string(), |error| error.to_string())
        ));
    }
    envelope
        .data
        .ok_or_else(|| "rch output carries no data".to_string())
}

/// `rch --json cache clean --older=<h>h --base=<base>`, plus `extra`.
fn clean_args(base: &Path, min_idle: Duration, extra: &[OsString]) -> Vec<OsString> {
    let mut base_arg = OsString::from("--base=");
    base_arg.push(base.as_os_str());
    let mut args: Vec<OsString> = ["--json", "cache", "clean"]
        .into_iter()
        .map(OsString::from)
        .collect();
    args.push(format!("--older={}h", min_idle.as_secs() / 3600).into());
    args.push(base_arg);
    args.extend_from_slice(extra);
    args
}

/// Why sbh leaves the trees rch would prune, or `Ok` when nothing keeps any
/// of them.
fn check_trees<'a>(
    paths: impl IntoIterator<Item = &'a Path>,
    config: &Config,
    platform: &dyn Platform,
) -> Result<(), &'static str> {
    let catalog = protection::sacred_paths_from_protected_patterns(&config.scanner.protected_paths);
    let resolved = paths
        .into_iter()
        .map(|path| check_on_disk(path, config, &catalog))
        .collect::<Result<Vec<_>, _>>()?;
    if resolved.is_empty() {
        return Ok(());
    }
    // One process scan for the project; it keys what it finds by the
    // resolved paths.
    let references = collect_active_reference_index(platform, &resolved);
    if resolved
        .iter()
        .any(|path| !references.summary_for(path).is_empty())
    {
        return Err("in_use");
    }
    Ok(())
}

/// The checks that read only the tree and the paths above it; the tree's
/// resolved path when it passes them.
fn check_on_disk(
    path: &Path,
    config: &Config,
    catalog: &[crate::platform::types::SacredPath],
) -> Result<PathBuf, &'static str> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Err("not_a_directory"),
        Err(_) => return Err("unreadable"),
    }
    let resolved = fs::canonicalize(path).map_err(|_| "unreadable")?;
    if super::target_tier::is_excluded(&resolved, &config.scanner.excluded_paths) {
        return Err("excluded");
    }
    if crate::scanner::deletion::is_hardcoded_source_tree(&resolved) {
        return Err("source_tree");
    }
    // Any marker entry protects, even a dangling symlink or one that cannot
    // be read.
    for ancestor in resolved.ancestors() {
        match fs::symlink_metadata(ancestor.join(MARKER_FILENAME)) {
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            _ => return Err("protected"),
        }
    }
    let overlaps = protection::find_sacred_overlaps_with_config(
        &resolved,
        catalog,
        StowawayScanConfig {
            max_depth: MARKER_SCAN_DEPTH,
            ..StowawayScanConfig::default()
        },
    )
    .map_err(|_| "unreadable")?;
    if overlaps
        .iter()
        .any(|overlap| overlap.pattern == TRUNCATED_OVERLAP_PATTERN)
    {
        return Err("scan_budget");
    }
    if !overlaps.is_empty() {
        return Err("protected");
    }
    Ok(resolved)
}

/// What one pass over one base found and did.
#[derive(Debug, Default)]
struct BaseReport {
    /// Trees rch listed.
    trees: usize,
    /// Trees rch would prune, and their bytes.
    prunable: usize,
    prunable_bytes: u64,
    /// Projects rch pruned, and what it removed.
    projects: usize,
    removed_count: u64,
    removed_bytes: u64,
    /// Trees rch failed to remove.
    failed_trees: usize,
    /// Projects left, by reason.
    left: BTreeMap<&'static str, usize>,
    /// The first rch run that failed.
    error: Option<String>,
}

impl BaseReport {
    fn leave(&mut self, reason: &'static str) {
        *self.left.entry(reason).or_default() += 1;
    }

    /// One log line for the pass.
    #[must_use]
    fn summary(&self, base: &Path, level: PressureLevel, min_idle: Duration) -> String {
        let left = self
            .left
            .iter()
            .map(|(reason, count)| format!("{reason}={count}"))
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "base={} level={level:?} older={}h: rch listed {} trees, {} prunable ({}); \
             pruned {} trees in {} projects, reclaimed {}{}; projects left: {}",
            base.display(),
            min_idle.as_secs() / 3600,
            self.trees,
            self.prunable,
            human_bytes(self.prunable_bytes),
            self.removed_count,
            self.projects,
            human_bytes(self.removed_bytes),
            if self.failed_trees == 0 {
                String::new()
            } else {
                format!(" ({} failed)", self.failed_trees)
            },
            if left.is_empty() { "none" } else { &left },
        )
    }
}

/// One pass over one base. `stop` ends it between projects.
fn run_base(
    base: &Path,
    min_idle: Duration,
    config: &Config,
    platform: &dyn Platform,
    runner: &RchRunner,
    stop: &AtomicBool,
) -> BaseReport {
    let deadline = Instant::now() + PASS_BUDGET;
    let mut report = BaseReport::default();
    let plan = match runner
        .run(&clean_args(base, min_idle, &[]), stop)
        .and_then(|stdout| parse::<Plan>(&stdout))
    {
        Ok(plan) => plan,
        Err(error) => {
            report.error = Some(error);
            return report;
        }
    };
    report.trees = plan.entries.len();
    let mut projects: HashMap<OsString, u64> = HashMap::new();
    for entry in plan.entries.iter().filter(|entry| entry.prunes()) {
        report.prunable += 1;
        report.prunable_bytes = report.prunable_bytes.saturating_add(entry.size_bytes);
        match entry.project() {
            Some(project) => {
                let bytes = projects.entry(project.to_os_string()).or_default();
                *bytes = bytes.saturating_add(entry.size_bytes);
            }
            None => report.leave("no_project"),
        }
    }
    let mut projects: Vec<(OsString, u64)> = projects.into_iter().collect();
    projects.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    for (index, (project, _)) in projects.iter().enumerate() {
        if index >= MAX_PROJECTS || stop.load(Ordering::Acquire) || Instant::now() >= deadline {
            report.leave("next_pass");
            continue;
        }
        let mut project_arg = OsString::from("--project=");
        project_arg.push(project);
        let fresh = match runner
            .run(
                &clean_args(base, min_idle, std::slice::from_ref(&project_arg)),
                stop,
            )
            .and_then(|stdout| parse::<Plan>(&stdout))
        {
            Ok(plan) => plan,
            Err(error) => {
                report.leave("rch_failed");
                report.error.get_or_insert(error);
                continue;
            }
        };
        if !fresh.entries.iter().any(PlanEntry::prunes) {
            report.leave("now_recent");
            continue;
        }
        let at_risk = fresh
            .entries
            .iter()
            .filter(|entry| entry.at_risk(min_idle))
            .map(|entry| entry.path.as_path());
        if let Err(reason) = check_trees(at_risk, config, platform) {
            report.leave(reason);
            continue;
        }
        let outcome = runner
            .run(
                &clean_args(base, min_idle, &[project_arg, OsString::from("--execute")]),
                stop,
            )
            .and_then(|stdout| parse::<Outcome>(&stdout));
        match outcome {
            Ok(outcome) => {
                report.projects += 1;
                report.removed_count = report.removed_count.saturating_add(outcome.removed_count);
                report.removed_bytes = report.removed_bytes.saturating_add(outcome.removed_bytes);
                report.failed_trees += outcome.failed.len();
            }
            Err(error) => {
                report.leave("rch_failed");
                report.error.get_or_insert(error);
            }
        }
    }
    report
}

/// Scheduling state of the tier: at most one pass in flight.
#[derive(Debug, Default)]
pub struct RchStagingTier {
    running: Arc<AtomicBool>,
    /// Set when the tier may no longer run; the pass in flight stops before
    /// its next project.
    stop: Arc<AtomicBool>,
    last_run: HashMap<PathBuf, Instant>,
    last_probe: Option<Instant>,
    last_unavailable_note: Option<Instant>,
}

impl RchStagingTier {
    /// Start a pass on its own thread when a base is due. `mounts` maps each
    /// monitored mount to its pressure level and urgency.
    pub fn tick(
        &mut self,
        now: Instant,
        config: &Config,
        platform: &Arc<dyn Platform>,
        mounts: &HashMap<PathBuf, (PressureLevel, f64)>,
        mode: ActiveMode,
        logger: &ActivityLoggerHandle,
    ) {
        if config.scanner.rch_staging_bases.is_empty()
            || config.scanner.dry_run
            || mode != ActiveMode::Enforce
        {
            self.stop.store(true, Ordering::Release);
            return;
        }
        if self.running.load(Ordering::Acquire)
            || self
                .last_probe
                .is_some_and(|last| now.saturating_duration_since(last) < PROBE_INTERVAL)
        {
            return;
        }
        self.last_probe = Some(now);
        let due: Vec<(PathBuf, PressureLevel, Duration)> = config
            .scanner
            .rch_staging_bases
            .iter()
            .filter(|base| {
                self.last_run
                    .get(*base)
                    .is_none_or(|last| now.saturating_duration_since(*last) >= BASE_INTERVAL)
                    && base.is_dir()
            })
            .filter_map(|base| {
                let stats = platform.fs_stats(base).ok()?;
                let &(level, _) = mounts.get(&stats.mount_point)?;
                Some((base.clone(), level, min_idle_for(level)?))
            })
            .collect();
        if due.is_empty() {
            return;
        }
        let runner = match RchRunner::resolve(config) {
            Ok(runner) => runner,
            Err(why) => {
                if self.last_unavailable_note.is_none_or(|last| {
                    now.saturating_duration_since(last) >= UNAVAILABLE_NOTE_INTERVAL
                }) {
                    self.last_unavailable_note = Some(now);
                    let message = format!(
                        "rch staging bases under pressure but {why}; set scanner.rch_binary \
                         or scanner.rch_staging_bases = []"
                    );
                    eprintln!("[SBH-RCH] {message}");
                    logger.send(ActivityEvent::Info { message });
                }
                return;
            }
        };
        for (base, _, _) in &due {
            self.last_run.insert(base.clone(), now);
        }
        self.stop = Arc::new(AtomicBool::new(false));
        self.running.store(true, Ordering::Release);
        let guard = RunningGuard(Arc::clone(&self.running));
        let stop = Arc::clone(&self.stop);
        let config = config.clone();
        let platform = Arc::clone(platform);
        let logger = logger.clone();
        let spawned = std::thread::Builder::new()
            .name("sbh-rch-staging".to_string())
            .spawn(move || {
                let _guard = guard;
                for (base, level, min_idle) in due {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    let report =
                        run_base(&base, min_idle, &config, platform.as_ref(), &runner, &stop);
                    let summary = report.summary(&base, level, min_idle);
                    eprintln!("[SBH-RCH] {summary}");
                    match report.error {
                        Some(error) => logger.send(ActivityEvent::Warning {
                            code: WARNING_CODE.to_string(),
                            message: format!("{summary}; rch run failed: {error}"),
                        }),
                        None => logger.send(ActivityEvent::Info { message: summary }),
                    }
                }
            });
        if let Err(error) = spawned {
            // The closure, and with it the guard, was dropped: running is clear.
            eprintln!("[SBH-RCH] pass thread failed to start: {error}");
        }
    }

    /// Stop the pass in flight: its rch run is killed and no further project
    /// is pruned.
    pub fn stop_running_pass(&self) {
        self.stop.store(true, Ordering::Release);
    }

    /// Whether a pass over `base` started at `now` or later.
    #[cfg(test)]
    fn started_since(&self, base: &Path, now: Instant) -> bool {
        self.last_run.get(base).is_some_and(|last| *last >= now)
    }
}

/// Clears `running` when the pass ends, however it ends.
#[derive(Debug)]
struct RunningGuard(Arc<AtomicBool>);

impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use serde_json::json;

    use super::*;
    use crate::platform::pal::MockPlatform;
    use crate::platform::types::{OpenFile, OpenFileKind, OpenFileMode};

    /// A scratch directory, resolved so the paths rch would print match the
    /// ones sbh resolves.
    fn scratch() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        (temp, root)
    }

    /// A stand-in for rch: it logs its arguments to `calls.log` and prints
    /// `plan.json`, `plan-<project>.json` or `outcome-<project>.json` from its
    /// directory, as `rch --json cache clean` would.
    fn fake_rch(dir: &Path) -> RchRunner {
        let script = format!(
            "#!/bin/sh\n\
             echo \"$*\" >> '{dir}/calls.log'\n\
             project=''; execute=0\n\
             for arg in \"$@\"; do\n\
               case \"$arg\" in --project=*) project=\"${{arg#--project=}}\";; --execute) execute=1;; esac\n\
             done\n\
             if [ \"$execute\" = 1 ]; then exec cat '{dir}/outcome-'\"$project\"'.json'; fi\n\
             if [ -n \"$project\" ]; then exec cat '{dir}/plan-'\"$project\"'.json'; fi\n\
             exec cat '{dir}/plan.json'\n",
            dir = dir.display()
        );
        script_runner(dir, &script)
    }

    fn script_runner(dir: &Path, script: &str) -> RchRunner {
        let binary = dir.join("fake-rch");
        fs::write(&binary, script).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        RchRunner {
            binary,
            home: dir.to_path_buf(),
            timeout: Duration::from_secs(10),
        }
    }

    fn envelope(data: &serde_json::Value) -> String {
        json!({
            "api_version": "1.0",
            "timestamp": 0,
            "command": "cache clean",
            "success": true,
            "data": data,
        })
        .to_string()
    }

    fn plan(entries: &[(&Path, u64, u64, &str)]) -> String {
        let entries: Vec<_> = entries
            .iter()
            .map(|(path, size, age_hours, action)| {
                json!({
                    "path": path,
                    "size_bytes": size,
                    "age_secs": age_hours * 3600,
                    "action": action,
                    "reason": "",
                })
            })
            .collect();
        envelope(&json!({
            "entries": entries,
            "prunable_bytes": 0,
            "prunable_count": 0,
            "total_bytes": 0,
        }))
    }

    /// A staging tree holding one file.
    fn tree(path: &Path) {
        fs::create_dir_all(path.join("repo/src")).unwrap();
        fs::write(path.join("repo/src/lib.rs"), "pub fn f() {}\n").unwrap();
    }

    fn calls(dir: &Path) -> Vec<String> {
        fs::read_to_string(dir.join("calls.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn the_age_rch_may_prune_at_shrinks_with_pressure_and_stops_below_orange() {
        let hours = |level| min_idle_for(level).map(|idle| idle.as_secs() / 3600);
        assert_eq!(hours(PressureLevel::Green), None);
        assert_eq!(hours(PressureLevel::Yellow), None);
        assert_eq!(hours(PressureLevel::Orange), Some(72));
        assert_eq!(hours(PressureLevel::Red), Some(48));
        assert_eq!(hours(PressureLevel::Critical), Some(24));
    }

    #[test]
    fn only_root_or_the_daemon_user_may_own_what_it_runs_and_nobody_else_may_write_it() {
        assert!(trusted_owner_and_mode(0, 0o755, 1000));
        assert!(trusted_owner_and_mode(1000, 0o700, 1000));
        assert!(trusted_owner_and_mode(0, 0o1755, 0));
        assert!(!trusted_owner_and_mode(1001, 0o755, 1000), "another user");
        assert!(
            !trusted_owner_and_mode(1001, 0o755, 0),
            "another user, root daemon"
        );
        assert!(!trusted_owner_and_mode(0, 0o775, 1000), "group-writable");
        assert!(!trusted_owner_and_mode(0, 0o757, 1000), "world-writable");
        assert!(
            !trusted_owner_and_mode(0, 0o1777, 0),
            "a sticky /tmp is still writable"
        );

        let euid = nix::unistd::geteuid().as_raw();
        assert!(trusted_binary(Path::new("/bin/sh"), euid).is_ok());
        // A script under /tmp, which anyone can write to, is never run.
        let (_temp, root) = scratch();
        let runner = fake_rch(&root);
        let refused = trusted_binary(&runner.binary, euid).unwrap_err();
        assert!(refused.contains("mode"), "{refused}");
        // Nor is a file that is not executable.
        assert!(trusted_binary(Path::new("/etc/hosts"), euid).is_err());
    }

    #[test]
    fn only_a_successful_envelope_with_data_parses() {
        let ok = plan(&[(Path::new("/data/tmp/rch/p/t"), 5, 80, "prune")]);
        let parsed: Plan = parse(ok.as_bytes()).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert!(parsed.entries[0].prunes());
        assert_eq!(parsed.entries[0].project(), Some(OsStr::new("p")));

        let outcome: Outcome = parse(
            envelope(&json!({"removed_count": 2, "removed_bytes": 9, "failed": ["/x"]})).as_bytes(),
        )
        .unwrap();
        assert_eq!(
            outcome,
            Outcome {
                removed_count: 2,
                removed_bytes: 9,
                failed: vec!["/x".to_string()],
            }
        );

        let failed = json!({"success": false, "error": {"code": "E1"}}).to_string();
        assert!(parse::<Plan>(failed.as_bytes()).unwrap_err().contains("E1"));
        assert!(parse::<Plan>(br#"{"success": true}"#).is_err());
        assert!(parse::<Plan>(b"Dry run over 1 base(s)").is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_pass_prunes_only_projects_whose_every_tree_passes_sbhs_checks() {
        let (_temp, root) = scratch();
        let base = root.join("rch");
        let min_idle = Duration::from_hours(48);
        let tree_of = |project: &str| base.join(project).join("projects");
        let names = [
            "clean", "deep", "above", "guarded", "excluded", "busy", "near", "fresh",
        ];
        for name in names {
            tree(&tree_of(name));
        }
        // A marker copied deep inside the tree, one on the project directory,
        // a protected path, an excluded path and an open file.
        fs::write(tree_of("deep").join("repo/src/.sbh-protect"), "").unwrap();
        fs::write(base.join("above/.sbh-protect"), "").unwrap();
        // `near` holds a second tree that rch keeps as recent now but would
        // prune within the margin, and it carries a marker.
        let near_second = base.join("near/second");
        tree(&near_second);
        fs::write(near_second.join(".sbh-protect"), "").unwrap();

        let mut config = Config::default();
        config.scanner.protected_paths = vec![base.join("guarded").display().to_string()];
        // Added to the default exclusions, which name `/` and must not keep
        // the rest.
        config.scanner.excluded_paths.push(base.join("excluded"));
        let platform = MockPlatform::healthy().with_open_file(OpenFile {
            pid: 4242,
            path: tree_of("busy").join("repo/src/lib.rs"),
            fd: Some(3),
            kind: OpenFileKind::Regular,
            mode: OpenFileMode::Read,
        });

        let runner = fake_rch(&root);
        let trees: Vec<PathBuf> = names.iter().map(|name| tree_of(name)).collect();
        let everything: Vec<(&Path, u64, u64, &str)> = trees
            .iter()
            .map(|path| (path.as_path(), 1 << 30, 100, "prune"))
            .collect();
        fs::write(root.join("plan.json"), plan(&everything)).unwrap();
        for (name, path) in names.iter().zip(&trees) {
            let own = match *name {
                "near" => plan(&[
                    (path.as_path(), 1 << 30, 100, "prune"),
                    (near_second.as_path(), 1 << 20, 47, "keep_recent"),
                ]),
                // Touched again since the first dry run.
                "fresh" => plan(&[(path.as_path(), 1 << 30, 0, "keep_recent")]),
                _ => plan(&[(path.as_path(), 1 << 30, 100, "prune")]),
            };
            fs::write(root.join(format!("plan-{name}.json")), own).unwrap();
        }
        fs::write(
            root.join("outcome-clean.json"),
            envelope(&json!({"removed_count": 1, "removed_bytes": 1u64 << 30, "failed": []})),
        )
        .unwrap();

        let report = run_base(
            &base,
            min_idle,
            &config,
            &platform,
            &runner,
            &AtomicBool::new(false),
        );
        let summary = report.summary(&base, PressureLevel::Red, min_idle);
        assert_eq!(report.error, None, "{summary}");
        assert_eq!(report.trees, names.len());
        assert_eq!(report.prunable, names.len());
        assert_eq!(report.projects, 1, "{summary}");
        assert_eq!(report.removed_count, 1);
        assert_eq!(report.removed_bytes, 1 << 30);
        let left: Vec<(&str, usize)> = report.left.iter().map(|(k, v)| (*k, *v)).collect();
        assert_eq!(
            left,
            [
                ("excluded", 1),
                ("in_use", 1),
                ("now_recent", 1),
                ("protected", 4),
            ],
            "{summary}"
        );

        let calls = calls(&root);
        assert_eq!(
            calls[0],
            format!("--json cache clean --older=48h --base={}", base.display())
        );
        let executed: Vec<&String> = calls.iter().filter(|c| c.contains("--execute")).collect();
        assert_eq!(executed.len(), 1, "{calls:#?}");
        assert!(
            executed[0].ends_with("--project=clean --execute"),
            "{executed:?}"
        );
        // Nothing sbh checked was touched: rch, not sbh, removes the trees.
        for name in names {
            assert!(tree_of(name).join("repo/src/lib.rs").exists(), "{name}");
        }
    }

    #[test]
    fn a_failed_or_unreadable_dry_run_prunes_nothing() {
        let (_temp, root) = scratch();
        let base = root.join("rch");
        tree(&base.join("p/t"));
        let runner = fake_rch(&root);
        let run = |runner: &RchRunner| {
            run_base(
                &base,
                Duration::from_hours(24),
                &Config::default(),
                &MockPlatform::healthy(),
                runner,
                &AtomicBool::new(false),
            )
        };

        // No plan.json: the stand-in exits non-zero.
        let report = run(&runner);
        assert!(
            report.error.as_deref().unwrap().contains("exited"),
            "{report:?}"
        );
        assert_eq!(report.projects, 0);

        fs::write(
            root.join("plan.json"),
            json!({"success": false, "error": "config"}).to_string(),
        )
        .unwrap();
        let report = run(&runner);
        assert!(
            report.error.as_deref().unwrap().contains("failure"),
            "{report:?}"
        );

        // The project's own dry run fails: it is left, nothing is executed.
        let tree_path = base.join("p/t");
        fs::write(
            root.join("plan.json"),
            plan(&[(tree_path.as_path(), 10, 100, "prune")]),
        )
        .unwrap();
        let report = run(&runner);
        assert_eq!(report.left.get("rch_failed"), Some(&1), "{report:?}");
        assert!(calls(&root).iter().all(|call| !call.contains("--execute")));
    }

    #[test]
    fn a_hung_stopped_or_flooding_rch_is_cut_off() {
        let (_temp, root) = scratch();
        let mut runner = script_runner(&root, "#!/bin/sh\nexec sleep 30\n");
        runner.timeout = Duration::from_millis(300);
        let started = Instant::now();
        let error = runner.run(&[], &AtomicBool::new(false)).unwrap_err();
        assert!(error.contains("timed out"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(10));

        runner.timeout = Duration::from_secs(30);
        let stop = Arc::new(AtomicBool::new(false));
        let stopper = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(200));
                stop.store(true, Ordering::Release);
            })
        };
        let started = Instant::now();
        let error = runner.run(&[], &stop).unwrap_err();
        stopper.join().unwrap();
        assert!(error.contains("stopped"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(10));

        let flood = format!(
            "#!/bin/sh\nexec head -c {} /dev/zero\n",
            MAX_OUTPUT_BYTES + 1
        );
        let runner = script_runner(&root, &flood);
        let error = runner.run(&[], &AtomicBool::new(false)).unwrap_err();
        assert!(error.contains("over"), "{error}");
    }

    struct Logger {
        handle: ActivityLoggerHandle,
        join: Option<std::thread::JoinHandle<()>>,
        _dir: tempfile::TempDir,
    }

    impl Logger {
        fn new() -> Self {
            let dir = tempfile::tempdir_in("/tmp").unwrap();
            let (handle, join) =
                crate::logger::dual::spawn_logger(crate::logger::dual::DualLoggerConfig {
                    sqlite_path: None,
                    jsonl_config: crate::logger::jsonl::JsonlConfig {
                        path: dir.path().join("activity.jsonl"),
                        fallback_path: None,
                        max_size_bytes: 1_048_576,
                        max_rotated_files: 0,
                        fsync_interval_secs: 0,
                    },
                    channel_capacity: 64,
                    run_id: None,
                })
                .unwrap();
            Self {
                handle,
                join: Some(join),
                _dir: dir,
            }
        }
    }

    impl Drop for Logger {
        fn drop(&mut self) {
            self.handle.shutdown();
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    #[test]
    fn a_pass_starts_only_in_enforce_mode_under_pressure_with_a_trusted_rch() {
        let (_temp, root) = scratch();
        let base = root.join("rch");
        fs::create_dir(&base).unwrap();
        let logger = Logger::new();
        let platform: Arc<dyn Platform> = Arc::new(MockPlatform::healthy());
        let red = HashMap::from([(PathBuf::from("/"), (PressureLevel::Red, 0.8))]);
        let yellow = HashMap::from([(PathBuf::from("/"), (PressureLevel::Yellow, 0.3))]);
        let mut config = Config::default();
        config.scanner.rch_staging_bases = vec![base.clone()];
        // Trusted and present everywhere; as rch it fails, which is enough to
        // see a pass start.
        config.scanner.rch_binary = Some(PathBuf::from("/usr/bin/false"));

        let starts = |config: &Config, mounts: &HashMap<_, _>, mode| {
            let mut tier = RchStagingTier::default();
            let now = Instant::now();
            tier.tick(now, config, &platform, mounts, mode, &logger.handle);
            tier.started_since(&base, now)
        };
        assert!(starts(&config, &red, ActiveMode::Enforce));
        assert!(
            !starts(&config, &yellow, ActiveMode::Enforce),
            "below Orange"
        );
        for mode in [
            ActiveMode::Observe,
            ActiveMode::Canary,
            ActiveMode::FallbackSafe,
        ] {
            assert!(!starts(&config, &red, mode), "{mode:?}");
        }
        let mut dry = config.clone();
        dry.scanner.dry_run = true;
        assert!(!starts(&dry, &red, ActiveMode::Enforce), "dry run");
        let mut absent = config.clone();
        absent.scanner.rch_staging_bases = vec![root.join("missing")];
        assert!(!starts(&absent, &red, ActiveMode::Enforce), "no base");
        let mut untrusted = config.clone();
        untrusted.scanner.rch_binary = Some(fake_rch(&root).binary);
        assert!(
            !starts(&untrusted, &red, ActiveMode::Enforce),
            "untrusted rch"
        );

        // One pass per base per interval, however often the loop ticks.
        let mut tier = RchStagingTier::default();
        let first = Instant::now();
        tier.tick(
            first,
            &config,
            &platform,
            &red,
            ActiveMode::Enforce,
            &logger.handle,
        );
        assert!(tier.started_since(&base, first));
        let deadline = Instant::now() + Duration::from_secs(20);
        while tier.running.load(Ordering::Acquire) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!tier.running.load(Ordering::Acquire));
        let later = first + PROBE_INTERVAL;
        tier.tick(
            later,
            &config,
            &platform,
            &red,
            ActiveMode::Enforce,
            &logger.handle,
        );
        assert!(!tier.started_since(&base, later));
        let due = first + BASE_INTERVAL;
        tier.tick(
            due,
            &config,
            &platform,
            &red,
            ActiveMode::Enforce,
            &logger.handle,
        );
        assert!(tier.started_since(&base, due));
    }
}
