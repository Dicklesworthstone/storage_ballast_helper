//! Read-only inventory of Claude Code session scratch, including trees that
//! intentionally do not qualify as regenerable scanner artifacts (bd-jnp9).
//!
//! A quiet session is an investigation lead, never deletion authority. Both
//! its complete tree and its transcript must be old, and the process sweep
//! must be complete and find no references. Allocated blocks can be shared
//! through reflinks or hardlinks, so this report never promises reclaim bytes.

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat, statat};
use serde::{Serialize, Serializer};

use crate::platform::pal::Platform;
use crate::scanner::protection::{MARKER_FILENAME, ProtectionRegistry};
use crate::scanner::quarantine::open_beneath;
use crate::scanner::walker::{ActiveReferenceIndex, collect_active_reference_index};

const MAX_SESSIONS: usize = 2048;
const MAX_ISSUES: usize = 16;

/// Work and output limits for one read-only inventory.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Required inactivity of both the tree and the matching transcript.
    pub min_idle_days: u32,
    /// Shared cooperative deadline for discovery, tree walks and process evidence.
    pub timeout: Duration,
    /// Maximum directory entries examined, including discovery and exclusions.
    pub max_entries: usize,
    /// Maximum traversal depth within each session.
    pub max_depth: usize,
    /// Maximum sessions returned, ordered by observed allocated bytes.
    pub top: usize,
}

/// Days a session's tree and transcript must stay unchanged before the
/// report calls the session idle (`--min-idle-days` overrides it).
pub const DEFAULT_MIN_IDLE_DAYS: u32 = 7;

impl Default for Limits {
    fn default() -> Self {
        Self {
            min_idle_days: DEFAULT_MIN_IDLE_DAYS,
            timeout: Duration::from_secs(30),
            max_entries: 2_000_000,
            max_depth: 64,
            top: 25,
        }
    }
}

impl Limits {
    fn validate(self) -> io::Result<()> {
        if !(1..=3650).contains(&self.min_idle_days)
            || self.timeout.is_zero()
            || self.timeout > Duration::from_mins(2)
            || !(1..=5_000_000).contains(&self.max_entries)
            || !(1..=64).contains(&self.max_depth)
            || !(1..=MAX_SESSIONS).contains(&self.top)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "agent scratch requires idle days 1..3650, timeout (0,120] seconds, entries 1..5000000, depth 1..64, and top 1..2048",
            ));
        }
        Ok(())
    }
}

/// What the evidence establishes about a session at inspection time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// A live process holds the scratch tree or transcript.
    Active,
    /// The tree or transcript has changed within the requested window.
    Recent,
    /// Missing, changing, or incomplete evidence prevents an idle conclusion.
    Unknown,
    /// Complete observations meet the inactivity window; manual review only.
    Idle,
}

/// One recognized `<tmp>/claude-<uid>/<project>/<session-uuid>` directory.
#[derive(Debug, Clone, Serialize)]
pub struct Session {
    /// Display pathname; not an executor input.
    #[serde(serialize_with = "display_path")]
    pub path: PathBuf,
    /// Native pathname bytes, so non-UTF-8 names remain distinguishable.
    pub native_path_hex: String,
    /// UID encoded by the enclosing Claude scratch directory.
    pub owner_uid: u32,
    /// Encoded project directory name used to locate the transcript.
    pub project: String,
    /// Full session UUID.
    pub session_id: String,
    /// Expected transcript path, when its owner's home can be resolved.
    #[serde(serialize_with = "display_optional_path")]
    pub transcript: Option<PathBuf>,
    /// Distinct regular-file logical bytes observed in this session.
    pub observed_logical_bytes: u64,
    /// Distinct inode blocks observed, including directories; shared extents
    /// can appear in other trees too. Partial walks are lower bounds.
    pub observed_allocated_bytes: u64,
    /// Always unknown: stat blocks do not establish exclusive reclaim.
    pub reclaimable_bytes: Option<u64>,
    /// Hours since the newest observed mtime/ctime, only after a complete walk.
    pub tree_idle_hours: Option<u64>,
    /// Hours since the matching transcript's newest mtime/ctime.
    pub transcript_idle_hours: Option<u64>,
    /// Inactivity classification, not a cleanup verdict.
    pub state: SessionState,
    /// Positive references or the reason inactivity could not be established.
    pub reasons: Vec<String>,
    /// Protection or source-control markers observed during the tree walk.
    pub protections: Vec<String>,
    /// Whether tree, transcript and process observations were all complete.
    pub complete: bool,
}

/// Bounded report independent of daemon state, logs or cleanup policy.
#[derive(Debug, Serialize)]
pub struct Report {
    /// Stable machine-readable report contract.
    pub schema: &'static str,
    /// This operation never creates, moves, truncates or removes files.
    pub read_only: bool,
    /// All discovered sessions were fully examined within the budgets.
    pub complete: bool,
    /// Window used to classify inactivity.
    pub min_idle_days: u32,
    /// Total recognized sessions, before the output limit.
    pub sessions_found: usize,
    /// Sessions whose complete evidence establishes the requested inactivity.
    pub idle_sessions: usize,
    /// Rows omitted by the requested output limit (not unexamined sessions).
    pub omitted_sessions: usize,
    /// Entries inspected across discovery and metadata traversal.
    pub entries_examined: usize,
    /// Largest observed sessions, with explicit active/recent/unknown states.
    pub sessions: Vec<Session>,
    /// Bounded diagnostics for incomplete discovery or process visibility.
    pub issues: Vec<String>,
    /// 0 for a complete report, 4 for partial observations.
    pub exit_code: i32,
}

struct Budget {
    remaining: usize,
    initial: usize,
    deadline: Instant,
}

impl Budget {
    fn check(&self) -> io::Result<()> {
        if self.remaining == 0 || Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "agent scratch entry/time budget exhausted",
            ));
        }
        Ok(())
    }

    fn take(&mut self) -> io::Result<()> {
        self.check()?;
        self.remaining -= 1;
        Ok(())
    }
}

struct FoundSession {
    path: PathBuf,
    uid: u32,
    project: OsString,
    session_id: String,
    anchor: Arc<File>,
    identity: (u64, u64),
    transcript: Option<PathBuf>,
}

/// Inspect explicit scratch roots (or `claude-<uid>` roots).
///
/// Transcripts are
/// resolved through the UID's home, or an explicit `.claude/projects` root.
/// No transcript contents are read, and no deletion candidates are emitted.
pub fn inspect(
    platform: Arc<dyn Platform>,
    roots: &[PathBuf],
    transcript_root: Option<&Path>,
    protected_paths: &[String],
    limits: Limits,
) -> io::Result<Report> {
    inspect_at(
        platform,
        roots,
        transcript_root,
        protected_paths,
        limits,
        SystemTime::now(),
    )
}

fn inspect_at(
    platform: Arc<dyn Platform>,
    roots: &[PathBuf],
    transcript_root: Option<&Path>,
    protected_paths: &[String],
    limits: Limits,
    now: SystemTime,
) -> io::Result<Report> {
    limits.validate()?;
    if roots.is_empty() || roots.len() > 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "supply 1..64 scratch roots",
        ));
    }
    let mut protection =
        ProtectionRegistry::new(Some(protected_paths)).map_err(io::Error::other)?;
    let mut budget = Budget {
        remaining: limits.max_entries,
        initial: limits.max_entries,
        deadline: Instant::now() + limits.timeout,
    };
    let mut issues = Vec::new();
    let found = discover(roots, transcript_root, &mut budget, &mut issues);
    let mut reference_roots: Vec<_> = found.iter().map(|entry| entry.path.clone()).collect();
    reference_roots.extend(found.iter().filter_map(|entry| entry.transcript.clone()));
    // Process inspection can block on platform calls. A timed-out collector
    // supplies unknown evidence, never an empty/complete index. It owns no
    // report files or mutations and cannot delay the CLI past its receive bound.
    let (send, receive) = mpsc::sync_channel(1);
    let collector = std::thread::Builder::new()
        .name("sbh-session-refs".into())
        .spawn(move || {
            let index = collect_active_reference_index(platform.as_ref(), &reference_roots);
            let _ = send.send(index);
        });
    if let Err(error) = collector {
        issue(
            &mut issues,
            format!("cannot collect process evidence: {error}"),
        );
    }
    let mut sessions: Vec<_> = found
        .into_iter()
        .map(|entry| survey(entry, &mut budget, &mut protection, limits, now))
        .collect();
    let index = receive
        .recv_timeout(budget.deadline.saturating_duration_since(Instant::now()))
        .unwrap_or_else(|_| {
            ActiveReferenceIndex::incomplete(
                "process evidence unavailable within the report deadline",
            )
        });
    if let Some(reason) = index.incomplete_reason() {
        issue(&mut issues, reason.to_owned());
    }
    for session in &mut sessions {
        classify(session, &index, limits.min_idle_days);
    }
    let complete = issues.is_empty() && sessions.iter().all(|session| session.complete);
    let sessions_found = sessions.len();
    let idle_sessions = sessions
        .iter()
        .filter(|session| session.state == SessionState::Idle)
        .count();
    sessions.sort_by(|left, right| {
        right
            .observed_allocated_bytes
            .cmp(&left.observed_allocated_bytes)
            .then_with(|| left.path.cmp(&right.path))
    });
    sessions.truncate(limits.top);
    Ok(Report {
        schema: "sbh.agent_scratch.v1",
        read_only: true,
        complete,
        min_idle_days: limits.min_idle_days,
        sessions_found,
        idle_sessions,
        omitted_sessions: sessions_found.saturating_sub(sessions.len()),
        entries_examined: budget.initial - budget.remaining,
        sessions,
        issues,
        exit_code: if complete { 0 } else { 4 },
    })
}

fn issue(issues: &mut Vec<String>, message: String) {
    if issues.len() < MAX_ISSUES && !issues.contains(&message) {
        issues.push(message);
    }
}

fn display_path<S: Serializer>(path: &Path, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&path.to_string_lossy())
}

#[allow(clippy::ref_option)] // serde's serialize_with callback borrows the optional field.
fn display_optional_path<S: Serializer>(
    path: &Option<PathBuf>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    path.as_ref()
        .map(|path| path.to_string_lossy())
        .serialize(serializer)
}

fn open_root(path: &Path) -> io::Result<(PathBuf, File)> {
    // Resolve caller-supplied roots once (macOS /tmp is normally an alias).
    // Every descent after this point is descriptor-relative and no-follow.
    let path = path.canonicalize()?;
    let file = File::from(rustix::fs::open(
        &path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    Ok((path, file))
}

fn open_child(parent: &File, name: &OsStr) -> io::Result<File> {
    let file = File::from(open_beneath(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
    )?);
    if file.metadata()?.dev() != parent.metadata()?.dev() {
        return Err(io::Error::from_raw_os_error(libc::EXDEV));
    }
    Ok(file)
}

fn child_names(directory: &File, budget: &mut Budget) -> io::Result<Vec<OsString>> {
    let mut names = Vec::new();
    let mut entries = Dir::read_from(directory)?;
    loop {
        budget.take()?;
        let Some(entry) = entries.next() else { break };
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            names.push(OsStr::from_bytes(name).to_owned());
        }
    }
    names.sort();
    Ok(names)
}

fn claude_uid(name: &OsStr) -> Option<u32> {
    let digits = name.to_str()?.strip_prefix("claude-")?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn session_uuid(name: &OsStr) -> Option<String> {
    let name = name.to_str()?;
    if name.len() != 36
        || !name.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return None;
    }
    Some(name.to_owned())
}

fn discover(
    roots: &[PathBuf],
    transcript_root: Option<&Path>,
    budget: &mut Budget,
    issues: &mut Vec<String>,
) -> Vec<FoundSession> {
    let mut found = Vec::new();
    let mut seen_roots = HashSet::new();
    let mut seen_users = HashSet::new();
    for root in roots {
        let result = (|| -> io::Result<()> {
            budget.check()?;
            let (path, directory) = open_root(root)?;
            if !seen_roots.insert(path.clone()) {
                return Ok(());
            }
            if let Some(uid) = path.file_name().and_then(claude_uid) {
                if !seen_users.insert(path.clone()) {
                    return Ok(());
                }
                budget.take()?;
                discover_user(
                    &path,
                    &directory,
                    uid,
                    transcript_root,
                    budget,
                    &mut found,
                    issues,
                )?;
            } else {
                budget.take()?;
                for name in child_names(&directory, budget)? {
                    budget.check()?;
                    if let Some(uid) = claude_uid(&name) {
                        let child_path = path.join(&name);
                        // Explicit user roots and aliased/overlapping tmp
                        // roots must not spend the session or walk budget
                        // repeatedly on the same canonical directory.
                        if seen_users.contains(&child_path) {
                            continue;
                        }
                        let result = open_child(&directory, &name).and_then(|child| {
                            seen_users.insert(child_path.clone());
                            discover_user(
                                &child_path,
                                &child,
                                uid,
                                transcript_root,
                                budget,
                                &mut found,
                                issues,
                            )
                        });
                        if let Err(error) = result {
                            issue(issues, format!("{}: {error}", child_path.display()));
                            if error.kind() == io::ErrorKind::TimedOut
                                || found.len() >= MAX_SESSIONS
                            {
                                return Err(error);
                            }
                        }
                    }
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            issue(issues, format!("{}: {error}", root.display()));
            if error.kind() == io::ErrorKind::TimedOut || found.len() >= MAX_SESSIONS {
                break;
            }
        }
    }
    found.sort_by(|left, right| left.path.cmp(&right.path));
    found
}

fn discover_user(
    path: &Path,
    directory: &File,
    uid: u32,
    transcript_root: Option<&Path>,
    budget: &mut Budget,
    found: &mut Vec<FoundSession>,
    issues: &mut Vec<String>,
) -> io::Result<()> {
    let transcripts = transcript_root
        .map(Path::to_path_buf)
        .or_else(|| {
            nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
                .ok()
                .flatten()
                .map(|user| user.dir.join(".claude/projects"))
        })
        .map(|root| crate::core::paths::resolve_absolute_path(&root));
    // Keep one descriptor per user scratch root, not one per session: a
    // large inventory must not exhaust the process's descriptor limit.
    let anchor = Arc::new(directory.try_clone()?);
    for project in child_names(directory, budget)? {
        budget.check()?;
        let project_path = path.join(&project);
        let result = (|| -> io::Result<()> {
            let metadata = statat(directory, &project, AtFlags::SYMLINK_NOFOLLOW)?;
            let file_type = FileType::from_raw_mode(metadata.st_mode);
            if file_type == FileType::Symlink {
                return Err(io::Error::other("project symlink not inspected"));
            }
            if file_type != FileType::Directory {
                return Ok(());
            }
            let project_dir = open_child(directory, &project)?;
            for name in child_names(&project_dir, budget)? {
                budget.check()?;
                let Some(session_id) = session_uuid(&name) else {
                    continue;
                };
                if found.len() >= MAX_SESSIONS {
                    return Err(io::Error::other("agent scratch session limit reached"));
                }
                let session_path = project_path.join(&name);
                let metadata =
                    match open_child(&project_dir, &name).and_then(|session| session.metadata()) {
                        Ok(metadata) => metadata,
                        Err(error) => {
                            // A vanished or unsafe session is an incomplete
                            // observation, not a reason to hide its siblings.
                            issue(issues, format!("{}: {error}", session_path.display()));
                            continue;
                        }
                    };
                found.push(FoundSession {
                    path: session_path,
                    uid,
                    project: project.clone(),
                    transcript: transcripts
                        .as_ref()
                        .map(|root| root.join(&project).join(format!("{session_id}.jsonl"))),
                    session_id,
                    anchor: Arc::clone(&anchor),
                    identity: (metadata.dev(), metadata.ino()),
                });
            }
            Ok(())
        })();
        if let Err(error) = result {
            issue(issues, format!("{}: {error}", project_path.display()));
            if error.kind() == io::ErrorKind::TimedOut || found.len() >= MAX_SESSIONS {
                return Err(error);
            }
        }
    }
    Ok(())
}

#[derive(Default)]
struct TreeObservation {
    logical: u64,
    allocated: u64,
    newest: i128,
    seen: HashSet<(u64, u64)>,
    issues: Vec<String>,
    protections: Vec<String>,
}

fn changed(stat: &Stat) -> i128 {
    let mtime = i128::from(stat.st_mtime) * 1_000_000_000 + i128::from(stat.st_mtime_nsec);
    let ctime = i128::from(stat.st_ctime) * 1_000_000_000 + i128::from(stat.st_ctime_nsec);
    mtime.max(ctime)
}

fn idle_hours(newest: i128, now: SystemTime) -> Option<u64> {
    let now = i128::try_from(now.duration_since(UNIX_EPOCH).ok()?.as_nanos()).ok()?;
    let age = now.checked_sub(newest)?;
    u64::try_from(age / 3_600_000_000_000)
        .ok()
        .filter(|_| age >= 0)
}

#[allow(clippy::unnecessary_cast, clippy::cast_sign_loss)] // dev_t differs across Unix targets.
fn observe_stat(stat: &Stat, observation: &mut TreeObservation) {
    observation.newest = observation.newest.max(changed(stat));
    if !observation
        .seen
        .insert((stat.st_dev as u64, stat.st_ino as u64))
    {
        return;
    }
    let bytes = u64::try_from(stat.st_blocks)
        .ok()
        .and_then(|blocks| blocks.checked_mul(512));
    let total = bytes.and_then(|bytes| observation.allocated.checked_add(bytes));
    if let Some(total) = total {
        observation.allocated = total;
    } else {
        issue(
            &mut observation.issues,
            "allocated-byte accounting overflow".into(),
        );
    }
    if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile {
        let total = u64::try_from(stat.st_size)
            .ok()
            .and_then(|bytes| observation.logical.checked_add(bytes));
        if let Some(total) = total {
            observation.logical = total;
        } else {
            issue(
                &mut observation.issues,
                "logical-byte accounting overflow".into(),
            );
        }
    }
}

fn walk(
    directory: &File,
    depth: usize,
    budget: &mut Budget,
    limits: Limits,
    observation: &mut TreeObservation,
) -> io::Result<()> {
    budget.take()?;
    let before = rustix::fs::fstat(directory)?;
    observe_stat(&before, observation);
    if depth >= limits.max_depth {
        return Err(io::Error::other("session traversal depth limit reached"));
    }
    let mut children = Dir::read_from(directory)?;
    loop {
        budget.take()?;
        let Some(entry) = children.next() else { break };
        let entry = entry?;
        let name = OsStr::from_bytes(entry.file_name().to_bytes());
        if name == OsStr::new(".") || name == OsStr::new("..") {
            continue;
        }
        let stat = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
        if name == OsStr::new(MARKER_FILENAME) || name == OsStr::new(".git") {
            issue(
                &mut observation.protections,
                format!("contains {}", name.to_string_lossy()),
            );
        }
        // Lease sidecars are evidence to review, never opened for write or
        // lock-probed by a metadata-only diagnostic.
        if name.as_bytes().starts_with(b".sbh-active-lease-") {
            issue(
                &mut observation.protections,
                "contains active-lease metadata".into(),
            );
        }
        if stat.st_dev != before.st_dev {
            issue(&mut observation.issues, "nested filesystem omitted".into());
            continue;
        }
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => {
                let result = open_child(directory, name).and_then(|child| {
                    let pinned = rustix::fs::fstat(&child)?;
                    if pinned.st_dev != stat.st_dev || pinned.st_ino != stat.st_ino {
                        return Err(io::Error::other(
                            "session directory replaced during inspection",
                        ));
                    }
                    walk(&child, depth + 1, budget, limits, observation)
                });
                if let Err(error) = result {
                    issue(&mut observation.issues, error.to_string());
                    if error.kind() == io::ErrorKind::TimedOut {
                        return Err(error);
                    }
                }
            }
            FileType::RegularFile => observe_stat(&stat, observation),
            FileType::Symlink => {
                observe_stat(&stat, observation);
                issue(
                    &mut observation.issues,
                    "symlink target not inspected".into(),
                );
            }
            _ => issue(
                &mut observation.issues,
                "special file prevents a complete inactivity assessment".into(),
            ),
        }
    }
    let after = rustix::fs::fstat(directory)?;
    if changed(&before) != changed(&after) || before.st_size != after.st_size {
        return Err(io::Error::other(
            "session directory changed during inspection",
        ));
    }
    Ok(())
}

fn transcript_age(path: &Path, now: SystemTime) -> io::Result<u64> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("transcript parent unavailable"))?;
    let project = parent
        .file_name()
        .ok_or_else(|| io::Error::other("transcript project unavailable"))?;
    let root = parent
        .parent()
        .ok_or_else(|| io::Error::other("transcript root unavailable"))?;
    let (_, directory) = open_root(root)?;
    let project = open_child(&directory, project)?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("transcript name unavailable"))?;
    let stat = statat(&project, name, AtFlags::SYMLINK_NOFOLLOW)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(io::Error::other("transcript is not a regular file"));
    }
    idle_hours(changed(&stat), now)
        .ok_or_else(|| io::Error::other("transcript timestamp is in the future"))
}

fn survey(
    entry: FoundSession,
    budget: &mut Budget,
    protection: &mut ProtectionRegistry,
    limits: Limits,
    now: SystemTime,
) -> Session {
    let mut observation = TreeObservation::default();
    // Reopen only through the pinned user-root descriptor, then prove that
    // this is the directory discovered earlier. A renamed/replaced project
    // or session cannot redirect the inventory through a symlink.
    let directory = budget
        .check()
        .and_then(|()| open_child(&entry.anchor, &entry.project))
        .and_then(|project| open_child(&project, OsStr::new(&entry.session_id)))
        .and_then(|session| {
            let metadata = session.metadata()?;
            if (metadata.dev(), metadata.ino()) != entry.identity {
                return Err(io::Error::other("session identity changed since discovery"));
            }
            if metadata.uid() != entry.uid {
                issue(
                    &mut observation.issues,
                    "session owner differs from its claude-UID directory".into(),
                );
            }
            walk(&session, 0, budget, limits, &mut observation)?;
            Ok(session)
        });
    if let Err(error) = directory {
        issue(&mut observation.issues, error.to_string());
    }
    let tree_idle_hours = if observation.issues.is_empty() {
        idle_hours(observation.newest, now)
    } else {
        None
    };
    if tree_idle_hours.is_none() && observation.issues.is_empty() {
        issue(
            &mut observation.issues,
            "tree timestamp is in the future".into(),
        );
    }
    // Once the shared budget expires, remaining discovered sessions still
    // get Unknown rows, but must not start more filesystem probes.
    let metadata = (|| -> io::Result<u64> {
        budget.check()?;
        if !fs::symlink_metadata(&entry.path)
            .is_ok_and(|named| entry.identity == (named.dev(), named.ino()))
        {
            issue(
                &mut observation.issues,
                "session pathname changed during inspection".into(),
            );
        }
        budget.check()?;
        if let Err(error) = protection.discover_ancestor_markers(&entry.path) {
            issue(
                &mut observation.issues,
                format!("ancestor protection unavailable: {error}"),
            );
        }
        // The diagnostic needs only the protection verdict. Reading optional
        // marker metadata would follow a marker symlink or block on a FIFO.
        if protection.is_protected(&entry.path) {
            issue(
                &mut observation.protections,
                "protected by an ancestor marker or configured path".into(),
            );
        }
        budget.check()?;
        let path = entry
            .transcript
            .as_deref()
            .ok_or_else(|| io::Error::other("transcript owner home unavailable"))?;
        transcript_age(path, now)
    })();
    let transcript_idle_hours = match metadata {
        Ok(age) => Some(age),
        Err(error) => {
            issue(
                &mut observation.issues,
                format!("transcript unavailable: {error}"),
            );
            None
        }
    };
    Session {
        native_path_hex: crate::core::hex_lower(entry.path.as_os_str().as_bytes()),
        path: entry.path,
        owner_uid: entry.uid,
        project: entry.project.to_string_lossy().into_owned(),
        session_id: entry.session_id,
        transcript: entry.transcript,
        observed_logical_bytes: observation.logical,
        observed_allocated_bytes: observation.allocated,
        reclaimable_bytes: None,
        tree_idle_hours,
        transcript_idle_hours,
        state: SessionState::Unknown,
        complete: observation.issues.is_empty(),
        reasons: observation.issues,
        protections: observation.protections,
    }
}

fn classify(session: &mut Session, index: &ActiveReferenceIndex, min_idle_days: u32) {
    let mut references = vec![index.summary_for(&session.path)];
    if let Some(transcript) = &session.transcript {
        references.push(index.summary_for(transcript));
    }
    let active = references
        .iter()
        .any(|summary| summary.processes.iter().any(|process| !process.is_empty()));
    let complete = references
        .iter()
        .all(|summary| summary.incomplete_reason.is_none());
    for summary in &references {
        if let Some(reason) = summary.safe_reclaim_reason() {
            issue(&mut session.reasons, reason.into_owned());
        }
    }
    session.complete &= complete;
    let window = u64::from(min_idle_days) * 24;
    let recent = session.tree_idle_hours.is_some_and(|age| age < window)
        || session
            .transcript_idle_hours
            .is_some_and(|age| age < window);
    session.state = if active {
        SessionState::Active
    } else if recent {
        SessionState::Recent
    } else if session.complete
        && session.tree_idle_hours.is_some()
        && session.transcript_idle_hours.is_some()
    {
        SessionState::Idle
    } else {
        SessionState::Unknown
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::pal::MockPlatform;
    use crate::platform::types::{MappedRegion, ProcessInfo};
    use filetime::FileTime;

    const IDLE: &str = "11111111-1111-4111-8111-111111111111";
    const LIVE: &str = "22222222-2222-4222-8222-222222222222";
    const RECENT: &str = "33333333-3333-4333-8333-333333333333";
    const PROJECT: &str = "-data-projects-fixture";

    struct Fixture {
        _temp: tempfile::TempDir,
        root: PathBuf,
        transcripts: PathBuf,
        now: SystemTime,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap().join("tmp");
            let transcripts = temp.path().canonicalize().unwrap().join("projects");
            fs::create_dir_all(&root).unwrap();
            fs::create_dir_all(transcripts.join(PROJECT)).unwrap();
            Self {
                _temp: temp,
                root,
                transcripts,
                // ctime cannot be backdated. Advance the observation clock
                // instead, and use explicit future mtime for recent controls.
                now: SystemTime::now() + Duration::from_hours(9 * 24),
            }
        }

        fn session(&self, id: &str) -> PathBuf {
            let path = self
                .root
                .join(format!("claude-{}", nix::unistd::Uid::effective()))
                .join(PROJECT)
                .join(id);
            fs::create_dir_all(&path).unwrap();
            fs::write(path.join("work.bin"), [42_u8; 8192]).unwrap();
            fs::write(
                self.transcripts.join(PROJECT).join(format!("{id}.jsonl")),
                b"transcript fixture",
            )
            .unwrap();
            path
        }

        fn run(&self, platform: MockPlatform, limits: Limits) -> Report {
            inspect_at(
                Arc::new(platform),
                std::slice::from_ref(&self.root),
                Some(&self.transcripts),
                &[],
                limits,
                self.now,
            )
            .unwrap()
        }

        fn recent(&self, path: &Path) {
            let time = FileTime::from_system_time(self.now - Duration::from_hours(1));
            filetime::set_file_mtime(path, time).unwrap();
        }
    }

    fn process(cwd: PathBuf) -> ProcessInfo {
        ProcessInfo {
            pid: 424_242,
            parent_pid: None,
            name: "agent-fixture".into(),
            command_line: Vec::new(),
            executable: None,
            cwd: Some(cwd),
            start_time_unix_ms: None,
            virtual_memory_bytes: None,
            resident_memory_bytes: None,
            cpu_user_micros: None,
            cpu_system_micros: None,
        }
    }

    #[test]
    fn only_the_idle_session_with_complete_evidence_is_reported_idle() {
        let fixture = Fixture::new();
        let idle = fixture.session(IDLE);
        let live = fixture.session(LIVE);
        let recent = fixture.session(RECENT);
        fs::create_dir(recent.join("deep")).unwrap();
        fs::write(recent.join("deep/new-output"), b"fresh").unwrap();
        fixture.recent(&recent.join("deep/new-output"));
        let report = fixture.run(
            MockPlatform::healthy().with_process(process(live.clone())),
            Limits::default(),
        );
        assert!(report.complete, "{report:#?}");
        assert_eq!(report.sessions_found, 3);
        assert_eq!(report.idle_sessions, 1);
        for (path, state) in [
            (idle, SessionState::Idle),
            (live, SessionState::Active),
            (recent, SessionState::Recent),
        ] {
            let session = report
                .sessions
                .iter()
                .find(|session| session.path == path)
                .unwrap();
            assert_eq!(session.state, state, "{session:#?}");
            assert!(path.join("work.bin").exists());
            assert_eq!(session.reclaimable_bytes, None);
        }
    }

    #[test]
    fn recent_transcript_holds_an_old_tree_and_missing_transcript_is_unknown() {
        let fixture = Fixture::new();
        fixture.session(IDLE);
        fixture.session(RECENT);
        fixture.recent(
            &fixture
                .transcripts
                .join(PROJECT)
                .join(format!("{RECENT}.jsonl")),
        );
        // Moving the idle transcript simulates an absent history without
        // asking the reporter to create or repair it.
        fs::rename(
            fixture
                .transcripts
                .join(PROJECT)
                .join(format!("{IDLE}.jsonl")),
            fixture.transcripts.join("saved.jsonl"),
        )
        .unwrap();
        let report = fixture.run(MockPlatform::healthy(), Limits::default());
        assert_eq!(report.idle_sessions, 0);
        assert_eq!(report.exit_code, 4);
        assert_eq!(
            report
                .sessions
                .iter()
                .find(|session| session.session_id == IDLE)
                .unwrap()
                .state,
            SessionState::Unknown
        );
        assert_eq!(
            report
                .sessions
                .iter()
                .find(|session| session.session_id == RECENT)
                .unwrap()
                .state,
            SessionState::Recent
        );
    }

    #[test]
    fn incomplete_process_visibility_never_becomes_idle_but_keeps_positive_evidence() {
        let fixture = Fixture::new();
        fixture.session(IDLE);
        let live = fixture.session(LIVE);
        let platform = MockPlatform::healthy()
            .with_open_files_complete(false)
            .with_mmap_region(MappedRegion {
                pid: 424_243,
                path: live.join("work.bin"),
                start_address: None,
                end_address: None,
                protection: None,
            });
        let report = fixture.run(platform, Limits::default());
        assert_eq!(report.idle_sessions, 0);
        assert!(!report.complete);
        assert_eq!(
            report
                .sessions
                .iter()
                .find(|session| session.session_id == IDLE)
                .unwrap()
                .state,
            SessionState::Unknown
        );
        assert_eq!(
            report
                .sessions
                .iter()
                .find(|session| session.session_id == LIVE)
                .unwrap()
                .state,
            SessionState::Active
        );
    }

    #[test]
    fn partial_walks_do_not_infer_inactivity() {
        let fixture = Fixture::new();
        let path = fixture.session(IDLE);
        fs::create_dir_all(path.join("a/b/c")).unwrap();
        fs::write(path.join("a/b/c/unseen"), b"payload").unwrap();
        for limits in [
            Limits {
                max_depth: 1,
                ..Limits::default()
            },
            Limits {
                max_entries: 1,
                ..Limits::default()
            },
        ] {
            let report = fixture.run(MockPlatform::healthy(), limits);
            assert!(!report.complete, "{report:#?}");
            assert_eq!(report.idle_sessions, 0);
            assert_eq!(report.exit_code, 4);
            assert!(
                report
                    .sessions
                    .iter()
                    .all(|session| session.state == SessionState::Unknown)
            );
        }
    }

    #[test]
    fn symlinks_are_never_followed_and_hardlinks_are_not_double_counted() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let path = fixture.session(IDLE);
        fs::hard_link(path.join("work.bin"), path.join("same-data")).unwrap();
        let outside = fixture.root.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("private"), vec![99_u8; 65_536]).unwrap();
        symlink(&outside, path.join("outside-link")).unwrap();
        let report = fixture.run(MockPlatform::healthy(), Limits::default());
        assert_eq!(report.sessions[0].observed_logical_bytes, 8192);
        assert_eq!(report.sessions[0].state, SessionState::Unknown);
        assert_eq!(
            fs::read(outside.join("private")).unwrap(),
            vec![99_u8; 65_536]
        );
        assert_eq!(fs::read(path.join("work.bin")).unwrap(), vec![42_u8; 8192]);
        assert!(
            report.sessions[0]
                .reasons
                .iter()
                .any(|reason| reason.contains("symlink"))
        );
    }

    #[test]
    fn reports_protection_without_turning_idle_observations_into_cleanup_authority() {
        let fixture = Fixture::new();
        let path = fixture.session(IDLE);
        fs::write(path.join(MARKER_FILENAME), b"").unwrap();
        fs::create_dir(path.join(".git")).unwrap();
        let report = fixture.run(MockPlatform::healthy(), Limits::default());
        assert_eq!(report.sessions[0].state, SessionState::Idle);
        assert!(
            report.sessions[0]
                .protections
                .iter()
                .any(|reason| reason.contains(MARKER_FILENAME))
        );
        assert!(
            report.sessions[0]
                .protections
                .iter()
                .any(|reason| reason.contains(".git"))
        );
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["read_only"], true);
        assert!(json["sessions"][0]["reclaimable_bytes"].is_null());
        assert!(path.join(MARKER_FILENAME).exists());
        assert!(path.join(".git").exists());
    }

    #[test]
    fn fifo_protection_markers_cannot_block_metadata_only_inventory() {
        use std::os::unix::fs::FileTypeExt;
        use std::process::{Child, Command, Stdio};

        struct RunningChild(Child);
        impl Drop for RunningChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        if std::env::var_os("SBH_TEST_AGENT_SCRATCH_FIFO_CHILD").is_some() {
            let fixture = Fixture::new();
            let path = fixture.session(IDLE);
            let marker = path.parent().unwrap().join(MARKER_FILENAME);
            nix::unistd::mkfifo(
                &marker,
                nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
            )
            .unwrap();
            let report = fixture.run(MockPlatform::healthy(), Limits::default());
            assert!(report.complete, "{report:#?}");
            assert_eq!(report.sessions[0].state, SessionState::Idle);
            assert!(
                report.sessions[0]
                    .protections
                    .iter()
                    .any(|reason| reason.contains("protected"))
            );
            assert_eq!(report.sessions[0].reclaimable_bytes, None);
            assert!(fs::symlink_metadata(&marker).unwrap().file_type().is_fifo());
            assert_eq!(fs::read(path.join("work.bin")).unwrap(), vec![42_u8; 8192]);
            return;
        }

        // Run the real no-writer FIFO case in a killable child, so a future
        // accidental marker read cannot hang the test suite indefinitely.
        let mut child = RunningChild(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "monitor::agent_scratch::tests::fifo_protection_markers_cannot_block_metadata_only_inventory",
                    "--nocapture",
                ])
                .env("SBH_TEST_AGENT_SCRATCH_FIFO_CHILD", "1")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success(), "FIFO inventory child failed: {status}");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "inventory blocked on a FIFO protection marker"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn discovery_keeps_sibling_sessions_and_projects_after_an_unsafe_session() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let first = fixture.session(IDLE);
        let other = fixture.session(LIVE);
        let project = first.parent().unwrap();
        let bad = project.join("00000000-0000-4000-8000-000000000000");
        symlink(&fixture.transcripts, &bad).unwrap();
        let other_project = project.parent().unwrap().join("zz-second-project");
        fs::create_dir(&other_project).unwrap();
        let second = other_project.join(LIVE);
        fs::rename(&other, &second).unwrap();
        let other_transcripts = fixture.transcripts.join("zz-second-project");
        fs::create_dir(&other_transcripts).unwrap();
        fs::rename(
            fixture
                .transcripts
                .join(PROJECT)
                .join(format!("{LIVE}.jsonl")),
            other_transcripts.join(format!("{LIVE}.jsonl")),
        )
        .unwrap();

        let report = fixture.run(MockPlatform::healthy(), Limits::default());
        assert!(!report.complete);
        assert_eq!(report.exit_code, 4);
        assert_eq!(report.sessions_found, 2, "{report:#?}");
        assert_eq!(report.idle_sessions, 2);
        assert!(report.sessions.iter().any(|session| session.path == first));
        assert!(report.sessions.iter().any(|session| session.path == second));
        assert!(
            report
                .issues
                .iter()
                .any(|reason| reason.contains("00000000-0000"))
        );
        assert!(fs::symlink_metadata(bad).unwrap().file_type().is_symlink());
    }

    #[test]
    fn discovery_marks_project_symlinks_partial_and_keeps_valid_siblings() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let valid = fixture.session(IDLE);
        let outside_project = fixture.root.with_file_name("outside-project");
        let outside_session = outside_project.join(LIVE);
        fs::create_dir_all(&outside_session).unwrap();
        fs::write(outside_session.join("private.bin"), [99_u8; 16_384]).unwrap();
        // The rejected project sorts before the valid one, proving discovery
        // continues with siblings while leaving the linked tree untouched.
        let rejected = valid
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("-aaa-linked-project");
        symlink(&outside_project, &rejected).unwrap();

        let report = fixture.run(MockPlatform::healthy(), Limits::default());
        assert!(!report.complete);
        assert_eq!(report.exit_code, 4);
        assert_eq!(report.sessions_found, 1, "{report:#?}");
        assert_eq!(report.idle_sessions, 1);
        assert_eq!(report.sessions[0].path, valid);
        assert_eq!(report.sessions[0].observed_logical_bytes, 8192);
        assert!(report.issues.iter().any(|reason| {
            reason.contains("-aaa-linked-project") && reason.contains("symlink")
        }));
        assert!(
            fs::symlink_metadata(rejected)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read(outside_session.join("private.bin")).unwrap(),
            vec![99_u8; 16_384]
        );
        assert_eq!(fs::read(valid.join("work.bin")).unwrap(), vec![42_u8; 8192]);
    }

    #[test]
    fn discovery_keeps_other_user_roots_after_an_unsafe_user_root() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let original = fixture.session(IDLE);
        let original_user = original.parent().unwrap().parent().unwrap();
        // Fixed names make the rejected symlink sort before the valid user
        // regardless of the UID running the test (including root).
        let valid_user = fixture.root.join("claude-9");
        if original_user != valid_user {
            fs::rename(original_user, &valid_user).unwrap();
        }
        let rejected = fixture.root.join("claude-0");
        symlink(&fixture.transcripts, &rejected).unwrap();

        let report = fixture.run(MockPlatform::healthy(), Limits::default());
        assert!(!report.complete);
        assert_eq!(report.sessions_found, 1, "{report:#?}");
        assert_eq!(report.sessions[0].path, valid_user.join(PROJECT).join(IDLE));
        assert!(
            report
                .issues
                .iter()
                .any(|reason| reason.contains("claude-0"))
        );
        assert!(
            valid_user
                .join(PROJECT)
                .join(IDLE)
                .join("work.bin")
                .exists()
        );
    }

    #[test]
    fn aliases_preserve_transcript_process_references() {
        use crate::platform::types::{OpenFile, OpenFileKind, OpenFileMode};
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let path = fixture.session(IDLE);
        let root_alias = fixture.root.with_file_name("tmp-alias");
        let transcript_alias = fixture.transcripts.with_file_name("transcript-alias");
        symlink(&fixture.root, &root_alias).unwrap();
        symlink(&fixture.transcripts, &transcript_alias).unwrap();
        let transcript = fixture
            .transcripts
            .join(PROJECT)
            .join(format!("{IDLE}.jsonl"));
        let platform = MockPlatform::healthy().with_open_file(OpenFile {
            pid: 424_244,
            path: transcript.clone(),
            fd: Some(9),
            kind: OpenFileKind::Regular,
            mode: OpenFileMode::ReadWrite,
        });
        let report = inspect_at(
            Arc::new(platform),
            &[root_alias],
            Some(&transcript_alias),
            &[],
            Limits::default(),
            fixture.now,
        )
        .unwrap();
        assert!(report.complete, "{report:#?}");
        assert_eq!(report.sessions[0].path, path);
        assert_eq!(report.sessions[0].transcript, Some(transcript));
        assert_eq!(report.sessions[0].state, SessionState::Active);
        assert_eq!(report.idle_sessions, 0);
    }

    #[test]
    fn reopening_rejects_a_replaced_session_before_observing_its_files() {
        let fixture = Fixture::new();
        let path = fixture.session(IDLE);
        let limits = Limits::default();
        let mut budget = Budget {
            remaining: limits.max_entries,
            initial: limits.max_entries,
            deadline: Instant::now() + limits.timeout,
        };
        let mut issues = Vec::new();
        let mut found = discover(
            std::slice::from_ref(&fixture.root),
            Some(&fixture.transcripts),
            &mut budget,
            &mut issues,
        );
        assert!(issues.is_empty());
        assert_eq!(found.len(), 1);
        let preserved = fixture.root.join("original-session");
        fs::rename(&path, &preserved).unwrap();
        fs::create_dir(&path).unwrap();
        fs::write(path.join("replacement.bin"), vec![99_u8; 65_536]).unwrap();

        let mut session = survey(
            found.pop().unwrap(),
            &mut budget,
            &mut ProtectionRegistry::marker_only(),
            limits,
            fixture.now,
        );
        classify(
            &mut session,
            &ActiveReferenceIndex::empty(),
            limits.min_idle_days,
        );
        assert!(!session.complete);
        assert_eq!(session.state, SessionState::Unknown);
        assert_eq!(session.observed_logical_bytes, 0);
        assert!(
            session
                .reasons
                .iter()
                .any(|reason| reason.contains("identity changed"))
        );
        assert_eq!(
            fs::read(preserved.join("work.bin")).unwrap(),
            vec![42_u8; 8192]
        );
        assert_eq!(
            fs::read(path.join("replacement.bin")).unwrap(),
            vec![99_u8; 65_536]
        );
    }

    #[test]
    fn exhausted_budgets_skip_later_session_metadata_probes() {
        let fixture = Fixture::new();
        let path = fixture.session(IDLE);
        fs::write(path.join(MARKER_FILENAME), b"").unwrap();
        let limits = Limits::default();
        for exhaust_entries in [true, false] {
            let mut budget = Budget {
                remaining: limits.max_entries,
                initial: limits.max_entries,
                deadline: Instant::now() + limits.timeout,
            };
            let mut issues = Vec::new();
            let mut found = discover(
                std::slice::from_ref(&fixture.root),
                Some(&fixture.transcripts),
                &mut budget,
                &mut issues,
            );
            assert!(issues.is_empty());
            assert_eq!(found.len(), 1);
            if exhaust_entries {
                budget.remaining = 0;
            } else {
                budget.deadline = Instant::now();
            }

            let mut session = survey(
                found.pop().unwrap(),
                &mut budget,
                &mut ProtectionRegistry::marker_only(),
                limits,
                fixture.now,
            );
            classify(
                &mut session,
                &ActiveReferenceIndex::empty(),
                limits.min_idle_days,
            );

            assert!(!session.complete);
            assert_eq!(session.state, SessionState::Unknown);
            assert_eq!(session.observed_logical_bytes, 0);
            assert_eq!(session.observed_allocated_bytes, 0);
            assert_eq!(session.tree_idle_hours, None);
            assert_eq!(session.transcript_idle_hours, None);
            assert!(session.protections.is_empty());
            assert!(
                session
                    .reasons
                    .iter()
                    .all(|reason| reason.contains("budget exhausted"))
            );
        }
        assert!(path.join(MARKER_FILENAME).exists());
        assert!(path.join("work.bin").exists());
    }

    #[test]
    fn output_limit_does_not_change_total_idle_count_and_duplicate_roots_do_not_duplicate_sessions()
    {
        let fixture = Fixture::new();
        let idle = fixture.session(IDLE);
        fixture.session(LIVE);
        let report = inspect_at(
            Arc::new(MockPlatform::healthy()),
            &[
                fixture.root.clone(),
                idle.parent().unwrap().parent().unwrap().to_path_buf(),
            ],
            Some(&fixture.transcripts),
            &[],
            Limits {
                top: 1,
                ..Limits::default()
            },
            fixture.now,
        )
        .unwrap();
        assert_eq!(report.sessions_found, 2);
        assert_eq!(report.idle_sessions, 2);
        assert_eq!(report.sessions.len(), 1);
        assert_eq!(report.omitted_sessions, 1);
    }

    #[test]
    fn overlapping_and_aliased_roots_do_not_exhaust_a_complete_walk_budget() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let path = fixture.session(IDLE);
        fixture.session(LIVE);
        let baseline = fixture.run(MockPlatform::healthy(), Limits::default());
        assert!(baseline.complete, "{baseline:#?}");
        let alias = fixture.root.with_file_name("tmp-alias");
        symlink(&fixture.root, &alias).unwrap();

        let report = inspect_at(
            Arc::new(MockPlatform::healthy()),
            &[
                fixture.root.clone(),
                alias,
                path.parent().unwrap().parent().unwrap().to_path_buf(),
            ],
            Some(&fixture.transcripts),
            &[],
            Limits {
                max_entries: baseline.entries_examined + 1,
                ..Limits::default()
            },
            fixture.now,
        )
        .unwrap();

        assert!(report.complete, "{report:#?}");
        assert_eq!(report.sessions_found, 2);
        assert_eq!(report.idle_sessions, 2);
        assert_eq!(report.entries_examined, baseline.entries_examined);
    }

    #[test]
    fn ignores_unrecognized_layouts_and_preserves_non_utf8_display_identity() {
        let mut fixture = Fixture::new();
        let renamed = fixture.root.with_file_name(OsStr::from_bytes(b"tmp-\xff"));
        fs::rename(&fixture.root, &renamed).unwrap();
        fixture.root = renamed;
        fixture.session(IDLE);
        fs::create_dir_all(fixture.root.join("claude-not-a-uid/project/session")).unwrap();
        let report = fixture.run(MockPlatform::healthy(), Limits::default());
        assert_eq!(report.sessions_found, 1);
        let json = serde_json::to_value(&report).unwrap();
        assert!(
            json["sessions"][0]["native_path_hex"]
                .as_str()
                .unwrap()
                .contains("ff")
        );
        assert!(session_uuid(OsStr::new("not-a-session")).is_none());
        assert!(session_uuid(OsStr::new("11111111/1111-4111-8111-111111111111")).is_none());
        assert_eq!(claude_uid(OsStr::new("claude-1000")), Some(1000));
        assert_eq!(claude_uid(OsStr::new("claude-+1000")), None);
    }
}
