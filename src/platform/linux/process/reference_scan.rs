//! Bounded, coverage-aware scans of the visible Linux proc namespace.
//!
//! Positive references survive another PID's access failure. `complete` means
//! that this sweep inspected its visible scope, not that procfs is an atomic
//! snapshot or that hidepid/container namespaces expose every host process.
//! Deadlines are cooperative: a single blocked kernel operation cannot be
//! interrupted here, except `cmdline` and `environ` reads, which wait on the
//! target's memory-map lock and are abandoned at the deadline
//! (`memory_reads`). Caps bound discovery, descriptor work, and result memory.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::{
    OPEN_FILES_MAX_PIDS, OPEN_FILES_SCAN_BUDGET, PROC_ROOT, open_file_kind_for_fd,
    open_file_mode_for_fd, pid_from_proc_entry_name, resolve_absolute_path,
};
use crate::core::errors::{Result, SbhError};
use crate::platform::types::{ExecutablesResult, OpenFile, OpenFilesResult, ProcessInfo};

mod build_environment;
mod memory_reads;
mod unix_sockets;

use build_environment::sweep as build_directory_sweep;

const MAX_DESCRIPTORS: usize = 262_144;
/// Half the sweep's descriptor budget. One process past this cap makes every
/// sweep incomplete and holds every deletion on the host: on ts2
/// (2026-10-16) a `bfs` search kept 65,536 directory descriptors open (its
/// limit was 1,048,576) under the old 16,384 cap, and the host deleted
/// nothing for hours. Reading 65,536 links takes well under a second.
const MAX_DESCRIPTORS_PER_PID: usize = 131_072;
const MAX_PROC_ENTRIES: usize = OPEN_FILES_MAX_PIDS + 4096;
const MAX_EXECUTABLE_COMM_BYTES: usize = 256;
const MAX_EXECUTABLE_STAT_BYTES: usize = 8192;
/// Socket metadata is bounded independently of descriptor enumeration.
/// Failed or oversized reads revoke coverage; they never mean an empty table.
const MAX_UNIX_SOCKET_TABLE_BYTES: usize = 32 * 1024 * 1024;
// Linux include/linux/sched.h: task has no user executable (PF_KTHREAD).
const PF_KTHREAD: u64 = 0x0020_0000;

type Entries = Box<dyn Iterator<Item = io::Result<OsString>>>;

/// The small syscall seam permits deterministic access errors and elapsed-time
/// tests even when the test runner is root. Production uses the real procfs.
trait ProcAccess {
    fn entries(&self, path: &Path) -> io::Result<Entries>;
    fn link(&self, path: &Path) -> io::Result<PathBuf>;
    fn process_gone(&self, path: &Path) -> bool;
    fn now(&self) -> Instant;

    fn read_bounded(&self, path: &Path, limit: usize) -> io::Result<Vec<u8>> {
        read_proc_bytes(path, limit)
    }

    /// [`Self::read_bounded`] for `cmdline` or `environ`, whose read waits for
    /// the process's memory-map lock and so lasts as long as the process is
    /// stuck in a fault or mmap. Production stops waiting after `wait`.
    fn read_process_memory(
        &self,
        path: &Path,
        limit: usize,
        wait: Duration,
    ) -> io::Result<Vec<u8>> {
        let _ = wait;
        self.read_bounded(path, limit)
    }
}

struct NativeProc;

impl ProcAccess for NativeProc {
    fn entries(&self, path: &Path) -> io::Result<Entries> {
        Ok(Box::new(
            fs::read_dir(path)?.map(|entry| entry.map(|entry| entry.file_name())),
        ))
    }

    fn link(&self, path: &Path) -> io::Result<PathBuf> {
        fs::read_link(path)
    }

    fn process_gone(&self, path: &Path) -> bool {
        fs::symlink_metadata(path).is_err_and(|error| disappeared(&error))
    }

    fn now(&self) -> Instant {
        Instant::now()
    }

    fn read_process_memory(
        &self,
        path: &Path,
        limit: usize,
        wait: Duration,
    ) -> io::Result<Vec<u8>> {
        let process = path.parent().unwrap_or(path);
        let path = path.to_path_buf();
        memory_reads::read(process, wait, move || read_proc_bytes(&path, limit))
    }
}

#[derive(Clone, Copy)]
struct Limits {
    time: Duration,
    pids: usize,
    proc_entries: usize,
    descriptors: usize,
    per_pid: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            time: OPEN_FILES_SCAN_BUDGET,
            pids: OPEN_FILES_MAX_PIDS,
            proc_entries: MAX_PROC_ENTRIES,
            descriptors: MAX_DESCRIPTORS,
            per_pid: MAX_DESCRIPTORS_PER_PID,
        }
    }
}

struct Sweep<'a, P> {
    proc: &'a P,
    limits: Limits,
    started: Instant,
    complete: bool,
    descriptors_seen: usize,
    /// The first process whose descriptors a cap cut short, and that cap:
    /// otherwise the sweep is incomplete with nothing saying why.
    descriptor_limit: Option<(i32, usize)>,
    /// Bound socket paths by inode, read once, when the first socket
    /// descriptor is seen.
    unix_sockets: Option<unix_sockets::Table>,
}

impl<'a, P: ProcAccess> Sweep<'a, P> {
    fn new(proc: &'a P, limits: Limits) -> Self {
        Self {
            proc,
            limits,
            started: proc.now(),
            complete: true,
            descriptors_seen: 0,
            descriptor_limit: None,
            unix_sockets: None,
        }
    }

    /// Which process a descriptor cap cut short, if one did. It also travels
    /// as `OpenFilesResult::incomplete_reason`, so the scanner's incomplete
    /// line and explain name the cause, not only this sweep's log line.
    fn descriptor_limit_reason(&self, proc_root: &Path) -> Option<String> {
        let (pid, limit) = self.descriptor_limit?;
        let comm = self
            .proc
            .read_bounded(&proc_root.join(pid.to_string()).join("comm"), 64)
            .map(|raw| String::from_utf8_lossy(&raw).trim().to_string())
            .unwrap_or_default();
        Some(format!(
            "pid {pid} ({comm}) has more than {limit} open descriptors, past the sweep's limit"
        ))
    }

    /// The `[SBH-SAFETY]` explanation for a descriptor cap, if one was hit.
    fn descriptor_limit_note(&self, proc_root: &Path) -> Option<String> {
        self.descriptor_limit_reason(proc_root).map(|reason| {
            format!("[SBH-SAFETY] open-file sweep incomplete: {reason}; candidates are held")
        })
    }

    /// Preserve positive bindings and propagate missing socket coverage to both
    /// the PAL scorer and the executor's final path-only sweep.
    fn unix_socket_path(&mut self, proc_root: &Path, inode: u64) -> Option<PathBuf> {
        if self.expired() {
            return None;
        }
        let proc = self.proc;
        let started = self.started;
        let time = self.limits.time;
        let table = self.unix_sockets.get_or_insert_with(|| {
            proc.read_bounded(
                &proc_root.join("net").join("unix"),
                MAX_UNIX_SOCKET_TABLE_BYTES,
            )
            .map(|raw| {
                unix_sockets::Table::parse(&raw, MAX_DESCRIPTORS, || {
                    proc.now()
                        .checked_duration_since(started)
                        .is_none_or(|elapsed| elapsed >= time)
                })
            })
            .unwrap_or_default()
        });
        self.complete &= table.complete_for(inode);
        let path = table.path(inode).map(Path::to_path_buf);
        self.expired();
        path
    }

    /// Time left before the deadline.
    fn remaining(&self) -> Duration {
        let elapsed = self
            .proc
            .now()
            .checked_duration_since(self.started)
            .unwrap_or(self.limits.time);
        self.limits.time.saturating_sub(elapsed)
    }

    fn expired(&mut self) -> bool {
        if self
            .proc
            .now()
            .checked_duration_since(self.started)
            .is_none_or(|elapsed| elapsed >= self.limits.time)
        {
            self.complete = false;
            true
        } else {
            false
        }
    }

    fn pids(&mut self, proc_root: &Path) -> io::Result<Vec<i32>> {
        let entries = self.proc.entries(proc_root)?;
        let mut pids = Vec::new();
        for (seen, entry) in entries.enumerate() {
            if self.expired() || seen >= self.limits.proc_entries {
                self.complete = false;
                break;
            }
            let Ok(name) = entry else {
                self.complete = false;
                continue;
            };
            let Some(pid) = name
                .to_str()
                .and_then(pid_from_proc_entry_name)
                .filter(|pid| *pid > 0)
            else {
                continue;
            };
            if pids.len() == self.limits.pids {
                self.complete = false;
                break;
            }
            pids.push(pid);
        }
        let current = i32::try_from(std::process::id()).ok();
        // Preserve useful self-reference evidence when the visible process
        // set is large; otherwise use deterministic PID order.
        pids.sort_unstable_by_key(|pid| (Some(*pid) != current, *pid));
        pids.dedup();
        Ok(pids)
    }

    fn fds(&mut self, proc_root: &Path, pid: i32, roots: &[PathBuf], out: &mut Vec<OpenFile>) {
        self.fd_targets(proc_root, pid, |process, fd, fd_path, target| {
            let path = resolve_absolute_path(&target);
            if roots.iter().any(|root| path.starts_with(root)) {
                out.push(OpenFile {
                    pid,
                    path,
                    fd: Some(fd),
                    kind: open_file_kind_for_fd(fd_path),
                    mode: open_file_mode_for_fd(process, fd),
                });
            }
        });
    }

    /// Shared coverage and budget enforcement for annotated PAL results and
    /// the executor's path-only sweep. The latter does not stat each target,
    /// read fdinfo, or resolve every process path before root filtering.
    fn fd_targets(
        &mut self,
        proc_root: &Path,
        pid: i32,
        mut visit: impl FnMut(&Path, i32, &Path, PathBuf),
    ) {
        let process = proc_root.join(pid.to_string());
        let fd_dir = process.join("fd");
        let entries = match self.proc.entries(&fd_dir) {
            Ok(entries) => entries,
            // Main-thread exit can hide fd/ while the thread group still has
            // open files. A missing fd directory is benign only for a PID
            // confirmed gone, never for an inaccessible or still-live PID.
            Err(error) => {
                if !disappeared(&error) || !self.proc.process_gone(&process) {
                    self.complete = false;
                }
                return;
            }
        };
        for (seen, entry) in entries.enumerate() {
            let cap = if seen >= self.limits.per_pid {
                Some(self.limits.per_pid)
            } else {
                (self.descriptors_seen >= self.limits.descriptors)
                    .then_some(self.limits.descriptors)
            };
            if let Some(cap) = cap {
                self.descriptor_limit.get_or_insert((pid, cap));
            }
            if self.expired() || cap.is_some() {
                self.complete = false;
                break;
            }
            self.descriptors_seen += 1;
            let Ok(name) = entry else {
                self.complete = false;
                continue;
            };
            let Some(fd) = name
                .to_str()
                .filter(|name| !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|name| name.parse::<i32>().ok())
            else {
                self.complete = false;
                continue;
            };
            let fd_path = fd_dir.join(&name);
            let target = match self.proc.link(&fd_path) {
                Ok(target) => target,
                // The kernel may close an individual descriptor after readdir.
                Err(error) if disappeared(&error) => continue,
                Err(_) => {
                    self.complete = false;
                    continue;
                }
            };
            if !target.is_absolute() {
                // A listening AF_UNIX socket links as `socket:[inode]`; its
                // file is named only in /proc/net/unix. tmux, ssh-agent and
                // the iOS Simulator's launchd serve such sockets from
                // otherwise empty temp directories, and deleting the
                // directory leaves the server running but unreachable.
                if let Some(bound) =
                    socket_inode(&target).and_then(|inode| self.unix_socket_path(proc_root, inode))
                {
                    visit(&process, fd, &fd_path, bound);
                } else if !pseudo_target(&target)
                    || (target
                        .as_os_str()
                        .as_encoded_bytes()
                        .starts_with(b"socket:[")
                        && socket_inode(&target).is_none())
                {
                    // Kernel pseudo-links must not become paths relative to
                    // sbh's cwd. Unknown relative targets are not absence
                    // evidence.
                    self.complete = false;
                }
                continue;
            }
            visit(&process, fd, &fd_path, target);
            if self.expired() {
                break;
            }
        }
    }

    fn executable(
        &mut self,
        proc_root: &Path,
        pid: i32,
        roots: &[PathBuf],
        out: &mut Vec<ProcessInfo>,
    ) {
        let process = proc_root.join(pid.to_string());
        let target = match self.proc.link(&process.join("exe")) {
            Ok(target) => target,
            Err(error) => {
                if !disappeared(&error) || !self.no_user_executable(&process, pid) {
                    self.complete = false;
                }
                return;
            }
        };
        if !target.is_absolute() {
            self.complete = false;
            return;
        }
        let executable = resolve_absolute_path(&target);
        if !roots.iter().any(|root| executable.starts_with(root)) {
            return;
        }

        // Discover the executable BEFORE optional display metadata. A missing,
        // denied, invalid-byte or oversized comm cannot erase this reference.
        // A name is an annotation, never evidence that the executable is absent.
        let name = if self.expired() {
            None
        } else {
            self.proc
                .read_bounded(&process.join("comm"), MAX_EXECUTABLE_COMM_BYTES)
                .ok()
                .map(|raw| String::from_utf8_lossy(&raw).trim().to_string())
                .filter(|name| !name.is_empty())
        }
        .unwrap_or_else(|| {
            executable.file_name().map_or_else(
                || format!("pid {pid}"),
                |name| name.to_string_lossy().into_owned(),
            )
        });
        // This query supplies reference evidence. General process statistics
        // remain available through process_list; fetching command lines and
        // accounting for every visible PID is not required to protect a path.
        out.push(ProcessInfo {
            pid,
            parent_pid: None,
            name,
            command_line: Vec::new(),
            executable: Some(executable),
            cwd: None,
            start_time_unix_ms: None,
            virtual_memory_bytes: None,
            resident_memory_bytes: None,
            cpu_user_micros: None,
            cpu_system_micros: None,
        });
    }

    fn no_user_executable(&mut self, process: &Path, pid: i32) -> bool {
        if self.expired() {
            return false;
        }
        if self.proc.process_gone(process) {
            return true;
        }
        // ENOENT alone is not absence evidence: /proc/PID/exe can disappear
        // when the main thread exits while sibling threads still execute.
        // Kernel threads and terminal single-thread processes genuinely lack
        // a user executable. Require explicit bounded stat evidence for them.
        self.proc
            .read_bounded(&process.join("stat"), MAX_EXECUTABLE_STAT_BYTES)
            .is_ok_and(|raw| stat_has_no_user_executable(&raw, pid))
    }

    /// [`Self::no_user_executable`], giving an exiting process a moment to
    /// finish. Its argv reads empty once its memory is released, shortly
    /// before it becomes a zombie or is reaped. On a busy build host (trj,
    /// 2,373 processes) short-lived compilers exited mid-sweep in two of
    /// three sweeps, and each one made the whole sweep incomplete and held
    /// the batch. A process still running after the settle, such as one
    /// whose main thread exited while its siblings run, stays unproven.
    fn exited_without_user_executable(&mut self, process: &Path, pid: i32) -> bool {
        for settle in EXIT_SETTLE {
            if self.no_user_executable(process, pid) {
                return true;
            }
            if self.expired() {
                return false;
            }
            std::thread::sleep(settle);
        }
        self.no_user_executable(process, pid)
    }
}

/// Waits between re-checks of a process whose argv read empty.
const EXIT_SETTLE: [Duration; 3] = [
    Duration::from_millis(2),
    Duration::from_millis(10),
    Duration::from_millis(50),
];

fn read_proc_bytes(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "non-regular proc metadata",
        ));
    }
    let mut raw = Vec::new();
    file.take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut raw)?;
    if raw.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proc metadata exceeds limit",
        ));
    }
    Ok(raw)
}

fn stat_has_no_user_executable(raw: &[u8], pid: i32) -> bool {
    let Ok(raw) = std::str::from_utf8(raw) else {
        return false;
    };
    let Some((observed_pid, _)) = raw.split_once('(') else {
        return false;
    };
    if observed_pid.trim().parse::<i32>().ok() != Some(pid) {
        return false;
    }
    let Ok(fields) = super::proc_stat_fields_after_comm(raw) else {
        return false;
    };
    // stat fields 9 (flags) and 20 (num_threads); fields[0] is field 3 (state).
    let Some(flags) = fields.get(6).and_then(|value| value.parse::<u64>().ok()) else {
        return false;
    };
    let Some(threads) = fields.get(17).and_then(|value| value.parse::<u64>().ok()) else {
        return false;
    };
    threads > 0
        && (flags & PF_KTHREAD != 0
            || (threads == 1 && matches!(fields.first().copied(), Some("Z" | "X" | "x"))))
}

fn disappeared(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}

fn socket_inode(target: &Path) -> Option<u64> {
    let raw = target
        .as_os_str()
        .as_encoded_bytes()
        .strip_prefix(b"socket:[")?
        .strip_suffix(b"]")?;
    unix_sockets::decimal(raw).filter(|inode| *inode != 0)
}

// Keep the original positive-path parser fixture; coverage assertions live in
// the shared typed parser and the PAL/executor socket regression tests below.
#[cfg(test)]
fn parse_unix_socket_paths(raw: &[u8]) -> std::collections::HashMap<u64, PathBuf> {
    unix_sockets::Table::parse(raw, MAX_DESCRIPTORS, || false).paths
}

fn pseudo_target(path: &Path) -> bool {
    path.to_str().is_some_and(|text| {
        [
            "socket:[",
            "pipe:[",
            "anon_inode:",
            "net:[",
            "mnt:[",
            "pid:[",
            "user:[",
            "uts:[",
            "ipc:[",
            "cgroup:[",
            "time:[",
        ]
        .iter()
        .any(|prefix| text.starts_with(prefix))
    })
}

/// One bounded path-only sweep for native cleanup preflight. Coverage has the
/// same meaning as open_files(), including partial positives on access errors.
/// At most two path spellings are retained per inspected descriptor.
pub(super) fn open_targets() -> Result<(Vec<PathBuf>, bool)> {
    open_targets_with(&NativeProc, Path::new(PROC_ROOT), Limits::default())
}

fn open_targets_with(
    proc: &impl ProcAccess,
    proc_root: &Path,
    limits: Limits,
) -> Result<(Vec<PathBuf>, bool)> {
    let mut sweep = Sweep::new(proc, limits);
    let pids = sweep
        .pids(proc_root)
        .map_err(|error| SbhError::io(proc_root, error))?;
    let mut targets = std::collections::HashSet::new();
    let current = i32::try_from(std::process::id()).ok();
    let mut denied = None;
    let mut refused = 0usize;
    for pid in pids {
        if sweep.expired() {
            break;
        }
        let own = Some(pid) == current;
        sweep.fd_targets(proc_root, pid, |_, _, _, target| {
            // sbh's own directory handles are its scanner walking a tree (or
            // the executor and quarantine at work), not a user of what is
            // below them. Counting them skipped as FileOpen whatever candidate
            // the scanner was still walking when its batch arrived, which then
            // backed off and could park the mount for a whole rescan interval.
            // sbh's own regular files (logs, databases) still count.
            if own && fs::metadata(&target).is_ok_and(|metadata| metadata.is_dir()) {
                return;
            }
            add_target_spellings(&mut targets, target);
        });
        // A process working inside a tree is using it, whatever it holds
        // open at this instant (bd-d1kt): rustc compiles a registry crate
        // from that crate's source directory.
        if !own {
            // Not through `proc.link`: the sweep's descriptor bounds count links.
            match fs::read_link(proc_root.join(pid.to_string()).join("cwd")) {
                Ok(cwd) => add_target_spellings(&mut targets, cwd),
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    refused += 1;
                    denied.get_or_insert(UnreadableProcess {
                        pid,
                        file: "cwd",
                        error,
                    });
                }
                // Exited, or a zombie without a working directory: it works
                // nowhere, and counting it would stall every batch.
                Err(_) => {}
            }
        }
    }
    // The build metadata phase uses the remaining deadline, not another full
    // proc-scan allowance. Its missing coverage must reach final preflight.
    let elapsed = proc
        .now()
        .checked_duration_since(sweep.started)
        .unwrap_or(limits.time);
    let build = build_directory_sweep(
        proc,
        proc_root,
        Limits {
            time: limits.time.saturating_sub(elapsed),
            ..limits
        },
    );
    sweep.complete &= build.complete;
    for (_, directory) in build.directories {
        add_target_spellings(&mut targets, directory);
    }
    let build_denied = build.denied;
    // A process sbh may not inspect could be using any candidate: its
    // references are unknown, not absent, so the sweep certifies nothing.
    // Name a refused build tool first: an unprivileged daemon is refused
    // pid 1 before it reaches the build anyone is looking for.
    let refused = refused + usize::from(build_denied.is_some());
    if let Some(unreadable) = build_denied.or(denied) {
        sweep.complete = false;
        let others = refused.saturating_sub(1);
        eprintln!(
            "[SBH-SAFETY] open-file sweep incomplete: cannot read /proc/{}/{} ({}){}; \
             candidates in this batch are held",
            unreadable.pid,
            unreadable.file,
            unreadable.error,
            if others == 0 {
                String::new()
            } else {
                format!(", nor {others} more")
            }
        );
    }
    if let Some(note) = sweep.descriptor_limit_note(proc_root) {
        eprintln!("{note}");
    }
    let mut targets: Vec<_> = targets.into_iter().collect();
    targets.sort_unstable();
    // Failed/empty directory reads and final ordering belong to the same
    // cooperative budget. An expired observation cannot certify absence.
    sweep.expired();
    Ok((targets, sweep.complete))
}

/// The first process whose working directory, environment or invocation
/// metadata could not be inspected completely.
struct UnreadableProcess {
    pid: i32,
    file: &'static str,
    error: io::Error,
}

/// An environment larger than this is skipped, not truncated.
const BUILD_ENVIRON_LIMIT: usize = 512 * 1024;

pub(super) fn build_directories() -> Vec<(i32, PathBuf)> {
    build_directory_snapshot().0
}

/// Return positive build references and observation completeness together.
pub(super) fn build_directory_snapshot() -> (Vec<(i32, PathBuf)>, bool) {
    let result = build_directory_sweep(&NativeProc, Path::new(PROC_ROOT), Limits::default());
    (result.directories, result.complete)
}

/// Positive directory references from live Rust, Go, Node, Python and native
/// compiler processes (bd-d1kt, bd-j7ho). A build need not hold a descriptor in
/// its external cache between reads. The same bounded discovery feeds scoring
/// and the native executor. Unreadable metadata remains best-effort evidence,
/// not a claim of complete coverage; raw environments are never logged.
#[cfg(test)]
fn build_directories_with(
    proc: &impl ProcAccess,
    proc_root: &Path,
    limits: Limits,
) -> Vec<(i32, PathBuf)> {
    build_directory_sweep(proc, proc_root, limits).directories
}

fn add_target_spellings(targets: &mut std::collections::HashSet<PathBuf>, target: PathBuf) {
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};

    // procfs appends this suffix to unlinked files, but it can also be part
    // of a real filename. Preserve the literal spelling AND the stripped
    // possibility: stripping unconditionally hides a live directory named
    // "target (deleted)". Work on bytes so neither form loses non-UTF-8 names.
    if let Some(stripped) = target.as_os_str().as_bytes().strip_suffix(b" (deleted)") {
        let stripped = PathBuf::from(OsString::from_vec(stripped.to_vec()));
        if stripped.is_absolute() {
            targets.insert(stripped);
        }
    }
    targets.insert(target);
}

pub(super) fn open_files(root: &Path) -> Result<OpenFilesResult> {
    open_files_with(&NativeProc, Path::new(PROC_ROOT), root, Limits::default())
}

/// One sweep for every root (bd-om52): the sweep reads each process's
/// descriptors whatever the root, so asking per root repeated all of it.
pub(super) fn open_files_roots(roots: &[PathBuf]) -> Result<OpenFilesResult> {
    open_files_with_roots(&NativeProc, Path::new(PROC_ROOT), roots, Limits::default())
}

fn open_files_with(
    proc: &impl ProcAccess,
    proc_root: &Path,
    root: &Path,
    limits: Limits,
) -> Result<OpenFilesResult> {
    open_files_with_roots(proc, proc_root, &[root.to_path_buf()], limits)
}

fn open_files_with_roots(
    proc: &impl ProcAccess,
    proc_root: &Path,
    roots: &[PathBuf],
    limits: Limits,
) -> Result<OpenFilesResult> {
    let roots: Vec<PathBuf> = roots
        .iter()
        .map(|root| resolve_absolute_path(root))
        .collect();
    let mut sweep = Sweep::new(proc, limits);
    let pids = sweep
        .pids(proc_root)
        .map_err(|error| SbhError::io(proc_root, error))?;
    let mut files = Vec::new();
    for pid in pids {
        if sweep.expired() {
            break;
        }
        sweep.fds(proc_root, pid, &roots, &mut files);
    }
    let incomplete_reason = sweep.descriptor_limit_reason(proc_root);
    if let Some(reason) = &incomplete_reason {
        eprintln!("[SBH-SAFETY] open-file sweep incomplete: {reason}; candidates are held");
    }
    // Include time spent in a failed/empty directory read in the one budget.
    sweep.expired();
    files.sort_by(|left, right| {
        left.pid
            .cmp(&right.pid)
            .then_with(|| left.fd.cmp(&right.fd))
            .then_with(|| left.path.cmp(&right.path))
    });
    Ok(OpenFilesResult {
        files,
        complete: sweep.complete,
        incomplete_reason,
    })
}

pub(super) fn executables(root: &Path) -> Result<ExecutablesResult> {
    executables_with(&NativeProc, Path::new(PROC_ROOT), root, Limits::default())
}

/// One sweep for every root; see [`open_files_roots`].
pub(super) fn executables_roots(roots: &[PathBuf]) -> Result<ExecutablesResult> {
    executables_with_roots(&NativeProc, Path::new(PROC_ROOT), roots, Limits::default())
}

fn executables_with(
    proc: &impl ProcAccess,
    proc_root: &Path,
    root: &Path,
    limits: Limits,
) -> Result<ExecutablesResult> {
    executables_with_roots(proc, proc_root, &[root.to_path_buf()], limits)
}

fn executables_with_roots(
    proc: &impl ProcAccess,
    proc_root: &Path,
    roots: &[PathBuf],
    limits: Limits,
) -> Result<ExecutablesResult> {
    let roots: Vec<PathBuf> = roots
        .iter()
        .map(|root| resolve_absolute_path(root))
        .collect();
    let mut sweep = Sweep::new(proc, limits);
    let pids = sweep
        .pids(proc_root)
        .map_err(|error| SbhError::io(proc_root, error))?;
    let mut processes = Vec::new();
    for pid in pids {
        if sweep.expired() {
            break;
        }
        sweep.executable(proc_root, pid, &roots, &mut processes);
    }
    sweep.expired();
    processes.sort_by(|left, right| {
        left.pid
            .cmp(&right.pid)
            .then_with(|| left.executable.cmp(&right.executable))
    });
    Ok(ExecutablesResult {
        processes,
        complete: sweep.complete,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::os::unix::fs::symlink;

    struct Fixture {
        _temp: tempfile::TempDir,
        proc_root: PathBuf,
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let base = fs::canonicalize(temp.path()).unwrap();
            let proc_root = base.join("proc");
            let root = base.join("artifacts");
            fs::create_dir(&proc_root).unwrap();
            fs::create_dir(&root).unwrap();
            Self {
                _temp: temp,
                proc_root,
                root,
            }
        }

        fn pid(&self, pid: i32) -> PathBuf {
            let process = self.proc_root.join(pid.to_string());
            fs::create_dir_all(process.join("fd")).unwrap();
            fs::create_dir_all(process.join("fdinfo")).unwrap();
            // Existing transport fixtures describe a readable invocation
            // with no CLI override; argv failures have dedicated fixtures.
            let cmdline = process.join("cmdline");
            if !cmdline.exists() {
                fs::write(cmdline, b"fixture\0").unwrap();
            }
            process
        }

        fn fd(&self, pid: i32, fd: i32) -> PathBuf {
            let process = self.pid(pid);
            let path = self.root.join(format!("kept-{pid}-{fd}"));
            fs::write(&path, b"retained artifact").unwrap();
            symlink(&path, process.join("fd").join(fd.to_string())).unwrap();
            fs::write(
                process.join("fdinfo").join(fd.to_string()),
                "flags:\t0100002\n",
            )
            .unwrap();
            path
        }

        fn scan(&self, access: &impl ProcAccess, limits: Limits) -> OpenFilesResult {
            open_files_with(access, &self.proc_root, &self.root, limits).unwrap()
        }

        fn exe(&self, pid: i32) -> PathBuf {
            let process = self.pid(pid);
            let path = self.root.join(format!("program-{pid}"));
            fs::write(&path, b"retained program").unwrap();
            symlink(&path, process.join("exe")).unwrap();
            path
        }

        fn scan_executables(&self, access: &impl ProcAccess, limits: Limits) -> ExecutablesResult {
            executables_with(access, &self.proc_root, &self.root, limits).unwrap()
        }
    }

    /// All successful operations are actual fixture syscalls. Only named
    /// errors or elapsed time are injected, so root cannot mask EACCES tests.
    struct Faults {
        dirs: BTreeMap<PathBuf, i32>,
        links: BTreeMap<PathBuf, i32>,
        reads: BTreeMap<PathBuf, i32>,
        entry_error: Option<PathBuf>,
        absent_pid: Option<i32>,
        now: Cell<Instant>,
        advance_per_link: Duration,
        advance_per_read: Duration,
        link_calls: Cell<usize>,
        read_paths: RefCell<Vec<PathBuf>>,
    }

    impl Default for Faults {
        fn default() -> Self {
            Self {
                dirs: BTreeMap::new(),
                links: BTreeMap::new(),
                reads: BTreeMap::new(),
                entry_error: None,
                absent_pid: None,
                now: Cell::new(Instant::now()),
                advance_per_link: Duration::ZERO,
                advance_per_read: Duration::ZERO,
                link_calls: Cell::new(0),
                read_paths: RefCell::new(Vec::new()),
            }
        }
    }

    impl ProcAccess for Faults {
        fn entries(&self, path: &Path) -> io::Result<Entries> {
            if let Some(code) = self.dirs.get(path) {
                return Err(io::Error::from_raw_os_error(*code));
            }
            let mut entries: Vec<_> = NativeProc.entries(path)?.collect();
            entries.sort_by(|a, b| a.as_ref().ok().cmp(&b.as_ref().ok()));
            if self.entry_error.as_deref() == Some(path) {
                entries.insert(0, Err(io::Error::from_raw_os_error(libc::EIO)));
            }
            if path.file_name().is_some_and(|name| name == "proc")
                && let Some(pid) = self.absent_pid
            {
                entries.push(Ok(OsString::from(pid.to_string())));
            }
            Ok(Box::new(entries.into_iter()))
        }

        fn link(&self, path: &Path) -> io::Result<PathBuf> {
            self.link_calls.set(self.link_calls.get() + 1);
            self.now.set(self.now.get() + self.advance_per_link);
            self.links.get(path).map_or_else(
                || NativeProc.link(path),
                |code| Err(io::Error::from_raw_os_error(*code)),
            )
        }

        fn process_gone(&self, path: &Path) -> bool {
            NativeProc.process_gone(path)
        }

        fn now(&self) -> Instant {
            self.now.get()
        }

        fn read_bounded(&self, path: &Path, limit: usize) -> io::Result<Vec<u8>> {
            self.read_paths.borrow_mut().push(path.to_path_buf());
            self.now.set(self.now.get() + self.advance_per_read);
            self.reads.get(path).map_or_else(
                || read_proc_bytes(path, limit),
                |code| Err(io::Error::from_raw_os_error(*code)),
            )
        }
    }

    #[test]
    fn readable_scope_is_complete_and_sorted_with_real_annotations() {
        let fixture = Fixture::new();
        let high = fixture.fd(22, 9);
        let low = fixture.fd(11, 3);
        let result = fixture.scan(&NativeProc, Limits::default());
        assert!(result.complete);
        assert_eq!(
            result
                .files
                .iter()
                .map(|file| &file.path)
                .collect::<Vec<_>>(),
            vec![&low, &high]
        );
        for file in result.files {
            assert_eq!(file.kind, crate::platform::types::OpenFileKind::Regular);
            assert_eq!(file.mode, crate::platform::types::OpenFileMode::ReadWrite);
            assert_eq!(fs::read(file.path).unwrap(), b"retained artifact");
        }
    }

    #[test]
    fn real_current_pid_scope_has_complete_coverage_and_keeps_its_open_file() {
        let fixture = Fixture::new();
        let target = fixture.root.join("held-open");
        let _held = fs::File::create(&target).unwrap();
        let pid = i32::try_from(std::process::id()).unwrap();
        let mut sweep = Sweep::new(&NativeProc, Limits::default());
        let mut files = Vec::new();
        sweep.fds(
            Path::new(PROC_ROOT),
            pid,
            std::slice::from_ref(&fixture.root),
            &mut files,
        );
        sweep.expired();
        assert!(sweep.complete);
        assert!(
            files
                .iter()
                .any(|file| file.pid == pid && file.path == target)
        );
    }

    #[test]
    fn denied_pid_does_not_erase_other_pids_or_claim_complete_coverage() {
        let fixture = Fixture::new();
        fixture.fd(1, 0);
        let retained = fixture.fd(2, 0);
        for code in [libc::EACCES, libc::EPERM, libc::EIO, libc::EMFILE] {
            let mut access = Faults::default();
            access.dirs.insert(fixture.proc_root.join("1/fd"), code);
            let result = fixture.scan(&access, Limits::default());
            assert!(!result.complete, "error {code} must remain incomplete");
            assert_eq!(result.files.len(), 1);
            assert_eq!(result.files[0].path, retained);
        }
    }

    #[test]
    fn denied_link_keeps_readable_descriptors_from_the_same_process() {
        let fixture = Fixture::new();
        fixture.fd(1, 0);
        let retained = fixture.fd(1, 1);
        let mut access = Faults::default();
        access
            .links
            .insert(fixture.proc_root.join("1/fd/0"), libc::EACCES);
        let result = fixture.scan(&access, Limits::default());
        assert!(!result.complete);
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, retained);
    }

    #[test]
    fn exited_pid_and_closed_descriptor_are_not_permission_failures() {
        let fixture = Fixture::new();
        fixture.fd(1, 0);
        let retained = fixture.fd(1, 1);
        let mut access = Faults {
            absent_pid: Some(99),
            ..Faults::default()
        };
        access
            .links
            .insert(fixture.proc_root.join("1/fd/0"), libc::ENOENT);
        let result = fixture.scan(&access, Limits::default());
        assert!(result.complete);
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, retained);
    }

    #[test]
    fn missing_fd_directory_for_a_live_pid_is_incomplete() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.proc_root.join("1")).unwrap();
        let retained = fixture.fd(2, 0);
        let result = fixture.scan(&NativeProc, Limits::default());
        assert!(!result.complete);
        assert_eq!(result.files[0].path, retained);
    }

    #[test]
    fn directory_iteration_errors_revoke_coverage_but_keep_positive_results() {
        let fixture = Fixture::new();
        let retained = fixture.fd(1, 0);
        for path in [&fixture.proc_root, &fixture.proc_root.join("1/fd")] {
            let access = Faults {
                entry_error: Some(path.clone()),
                ..Faults::default()
            };
            let result = fixture.scan(&access, Limits::default());
            assert!(!result.complete);
            assert_eq!(result.files[0].path, retained);
        }
    }

    #[test]
    fn per_pid_limit_keeps_other_processes_visible_and_exact_boundary_complete() {
        let fixture = Fixture::new();
        fixture.fd(1, 0);
        fixture.fd(1, 1);
        let retained = fixture.fd(2, 0);
        let limits = Limits {
            per_pid: 1,
            ..Limits::default()
        };
        let result = fixture.scan(&Faults::default(), limits);
        assert!(!result.complete);
        assert_eq!(result.files.len(), 2);
        assert!(result.files.iter().any(|file| file.path == retained));
        let result = fixture.scan(
            &NativeProc,
            Limits {
                per_pid: 2,
                ..limits
            },
        );
        assert!(result.complete);
        assert_eq!(result.files.len(), 3);
    }

    /// A cap that cuts a process short names that process and the cap, and a
    /// sweep within its caps names nothing (ts2: a `bfs` with 65,536
    /// descriptors held every batch while the logs said only "incomplete").
    #[test]
    fn a_descriptor_cap_names_the_process_it_cut_short() {
        let fixture = Fixture::new();
        fixture.fd(7, 0);
        fixture.fd(7, 1);
        fs::write(fixture.pid(7).join("comm"), "bfs\n").unwrap();
        let roots = [fixture.root.clone()];
        let mut capped = Sweep::new(
            &NativeProc,
            Limits {
                per_pid: 1,
                ..Limits::default()
            },
        );
        let mut files = Vec::new();
        capped.fds(&fixture.proc_root, 7, &roots, &mut files);
        assert!(!capped.complete);
        assert_eq!(capped.descriptor_limit, Some((7, 1)));
        let note = capped.descriptor_limit_note(&fixture.proc_root).unwrap();
        assert!(
            note.contains("pid 7 (bfs) has more than 1 open descriptors"),
            "{note}"
        );

        let mut whole = Sweep::new(&NativeProc, Limits::default());
        whole.fds(&fixture.proc_root, 7, &roots, &mut Vec::new());
        assert!(whole.complete);
        assert_eq!(whole.descriptor_limit_note(&fixture.proc_root), None);

        // The PAL result carries the same cause, for the scanner and explain.
        let result = fixture.scan(
            &NativeProc,
            Limits {
                per_pid: 1,
                ..Limits::default()
            },
        );
        assert!(!result.complete);
        assert_eq!(
            result.incomplete_reason.as_deref(),
            Some("pid 7 (bfs) has more than 1 open descriptors, past the sweep's limit")
        );
        assert_eq!(
            fixture
                .scan(&NativeProc, Limits::default())
                .incomplete_reason,
            None
        );
    }

    /// The ts2 incident's count fits the default limits: 65,538 descriptors in
    /// one process no longer make the sweep incomplete (bd-qs1r).
    #[test]
    fn one_process_with_65538_descriptors_fits_the_default_limits() {
        let fixture = Fixture::new();
        let process = fixture.pid(1);
        let walked = fixture.root.join("walked-dir");
        fs::create_dir(&walked).unwrap();
        for fd in 0..65_538 {
            symlink(&walked, process.join("fd").join(fd.to_string())).unwrap();
        }
        let (targets, complete) =
            open_targets_with(&Faults::default(), &fixture.proc_root, Limits::default()).unwrap();
        assert!(complete);
        assert!(targets.contains(&walked));
    }

    #[test]
    fn total_limit_never_overallocates_results_and_distinguishes_eof() {
        let fixture = Fixture::new();
        for fd in 0..3 {
            fixture.fd(1, fd);
        }
        for limit in 0..=4 {
            let access = Faults::default();
            let result = fixture.scan(
                &access,
                Limits {
                    descriptors: limit,
                    ..Limits::default()
                },
            );
            assert_eq!(result.files.len(), limit.min(3));
            assert_eq!(access.link_calls.get(), limit.min(3));
            assert_eq!(result.complete, limit >= 3);
        }
    }

    #[test]
    fn slow_progress_does_not_renew_the_sweep_deadline() {
        let fixture = Fixture::new();
        for fd in 0..5 {
            fixture.fd(1, fd);
        }
        let access = Faults {
            advance_per_link: Duration::from_secs(1),
            ..Faults::default()
        };
        let result = fixture.scan(
            &access,
            Limits {
                time: Duration::from_secs(2),
                ..Limits::default()
            },
        );
        assert!(!result.complete);
        assert_eq!(result.files.len(), 2);
        assert_eq!(
            access.link_calls.get(),
            2,
            "deadline applies inside one PID"
        );
    }

    #[test]
    fn bounded_pid_discovery_is_not_claimed_as_full_coverage() {
        let fixture = Fixture::new();
        for pid in 1..=3 {
            fixture.fd(pid, 0);
        }
        for limit in 0..=4 {
            let result = fixture.scan(
                &Faults::default(),
                Limits {
                    pids: limit,
                    ..Limits::default()
                },
            );
            assert_eq!(result.files.len(), limit.min(3));
            assert_eq!(result.complete, limit >= 3);
        }
        for index in 0..5 {
            fs::write(fixture.proc_root.join(format!("aaa{index}")), b"").unwrap();
        }
        let result = fixture.scan(
            &Faults::default(),
            Limits {
                proc_entries: 4,
                ..Limits::default()
            },
        );
        assert!(!result.complete);
    }

    #[test]
    fn pseudo_links_do_not_turn_into_cwd_relative_references() {
        let fixture = Fixture::new();
        socket_table_fixture(&fixture, b"");
        let process = fixture.pid(1);
        for (fd, target) in [
            "socket:[123]",
            "pipe:[456]",
            "anon_inode:[eventpoll]",
            "net:[789]",
        ]
        .iter()
        .enumerate()
        {
            symlink(target, process.join("fd").join(fd.to_string())).unwrap();
        }
        let result = open_files_with(
            &NativeProc,
            &fixture.proc_root,
            Path::new("/"),
            Limits::default(),
        )
        .unwrap();
        assert!(result.complete);
        assert!(result.files.is_empty());
        symlink("unexpected-relative-file", process.join("fd/4")).unwrap();
        let result = fixture.scan(&NativeProc, Limits::default());
        assert!(!result.complete);
    }

    /// A process serving a socket inside a tree is using the tree, though its
    /// descriptor links only to `socket:[inode]` (tmux, ssh-agent, the iOS
    /// Simulator's launchd). Abstract and unbound sockets name no file.
    #[test]
    fn a_bound_unix_socket_is_a_reference_to_its_file() {
        let fixture = Fixture::new();
        let served = fixture.root.join("tmux-1000").join("default");
        fs::create_dir_all(served.parent().unwrap()).unwrap();
        let process = fixture.pid(77);
        for (fd, inode) in [(5, 4242), (6, 4343), (7, 4444)] {
            symlink(
                format!("socket:[{inode}]"),
                process.join("fd").join(fd.to_string()),
            )
            .unwrap();
        }
        fs::create_dir_all(fixture.proc_root.join("net")).unwrap();
        fs::write(
            fixture.proc_root.join("net").join("unix"),
            format!(
                "Num       RefCount Protocol Flags    Type St Inode Path\n\
                 0000000000000000: 00000002 00000000 00010000 0001 01  4242 {}\n\
                 0000000000000000: 00000002 00000000 00010000 0001 01  4343 @abstract\n\
                 0000000000000000: 00000003 00000000 00000000 0001 03  4444\n",
                served.display()
            ),
        )
        .unwrap();

        let result = fixture.scan(&NativeProc, Limits::default());
        assert!(result.complete);
        assert_eq!(
            result
                .files
                .iter()
                .map(|file| (file.pid, file.path.clone()))
                .collect::<Vec<_>>(),
            vec![(77, served.clone())]
        );
        let (targets, complete) =
            open_targets_with(&NativeProc, &fixture.proc_root, Limits::default()).unwrap();
        assert!(complete);
        assert!(targets.contains(&served), "{targets:?}");
    }

    #[test]
    fn unix_socket_table_rows_keep_only_absolute_bound_paths() {
        let table = parse_unix_socket_paths(
            b"Num       RefCount Protocol Flags    Type St Inode Path\n\
              0000000000000000: 00000002 00000000 00010000 0001 01 123456 /run/user/1000/bus\n\
              0000000000000000: 00000002 00000000 00010000 0001 01    17 /tmp/with space.sock\n\
              0000000000000000: 00000002 00000000 00010000 0001 01    18 @/tmp/.X11-unix/X0\n\
              0000000000000000: 00000003 00000000 00000000 0001 03    19\n\
              garbage\n",
        );
        assert_eq!(table.len(), 2);
        assert_eq!(table[&123_456], PathBuf::from("/run/user/1000/bus"));
        assert_eq!(table[&17], PathBuf::from("/tmp/with space.sock"));
        assert_eq!(socket_inode(Path::new("socket:[17]")), Some(17));
        assert_eq!(socket_inode(Path::new("pipe:[17]")), None);
    }

    #[test]
    fn invalid_descriptor_names_cannot_certify_absence() {
        let fixture = Fixture::new();
        let process = fixture.pid(1);
        symlink(&fixture.root, process.join("fd/-1")).unwrap();
        let result = fixture.scan(&NativeProc, Limits::default());
        assert!(!result.complete);
        assert!(result.files.is_empty());
    }

    #[test]
    fn byte_paths_and_missing_annotations_preserve_positive_references() {
        use std::os::unix::ffi::OsStringExt;
        let fixture = Fixture::new();
        let process = fixture.pid(1);
        let target = fixture
            .root
            .join(OsString::from_vec(b"artifact-\xff".to_vec()));
        fs::write(&target, b"non-UTF-8 path").unwrap();
        symlink(&target, process.join("fd/0")).unwrap();
        let result = fixture.scan(&NativeProc, Limits::default());
        assert!(result.complete);
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, target);
        assert_eq!(
            result.files[0].mode,
            crate::platform::types::OpenFileMode::Unknown
        );
    }

    #[test]
    fn discovery_failure_returns_an_error_instead_of_an_empty_complete_result() {
        let fixture = Fixture::new();
        let mut access = Faults::default();
        access.dirs.insert(fixture.proc_root.clone(), libc::EACCES);
        assert!(
            open_files_with(
                &access,
                &fixture.proc_root,
                &fixture.root,
                Limits::default()
            )
            .is_err()
        );
    }

    #[test]
    fn mode_annotations_read_only_the_bounded_fdinfo_prefix() {
        let fixture = Fixture::new();
        fixture.fd(1, 0);
        let mut bytes = b"flags:\t0100002\n".to_vec();
        bytes.resize(4096, b' ');
        // Invalid UTF-8 outside the bounded prefix would make an unbounded
        // read_to_string fail and throw away a perfectly valid flags field.
        bytes.extend([0xff; 8192]);
        fs::write(fixture.proc_root.join("1/fdinfo/0"), bytes).unwrap();
        let result = fixture.scan(&NativeProc, Limits::default());
        assert!(result.complete);
        assert_eq!(result.files.len(), 1);
        assert_eq!(
            result.files[0].mode,
            crate::platform::types::OpenFileMode::ReadWrite
        );
    }

    #[test]
    fn path_only_sweep_deduplicates_targets_and_orders_them() {
        let fixture = Fixture::new();
        let first = fixture.fd(1, 0);
        let second = fixture.fd(2, 0);
        symlink(&first, fixture.proc_root.join("2/fd/1")).unwrap();
        let (targets, complete) =
            open_targets_with(&NativeProc, &fixture.proc_root, Limits::default()).unwrap();
        assert!(complete);
        assert_eq!(targets, vec![first, second]);
    }

    /// sbh's own directory handles are its scanner mid-walk, not a user of
    /// the tree: the executor used to skip whatever candidate the scanner was
    /// still walking as FileOpen. Its own regular files, and every other
    /// process's handles, still count.
    #[test]
    fn path_only_sweep_ignores_this_process_own_directory_handles() {
        let fixture = Fixture::new();
        let own = i32::try_from(std::process::id()).unwrap();
        let walked = fixture.root.join("candidate-target");
        fs::create_dir(&walked).unwrap();
        let own_log = fixture.fd(own, 3);
        symlink(&walked, fixture.proc_root.join(format!("{own}/fd/4"))).unwrap();
        let (targets, complete) =
            open_targets_with(&NativeProc, &fixture.proc_root, Limits::default()).unwrap();
        assert!(complete);
        assert_eq!(targets, vec![own_log.clone()]);

        // Another process holding the same directory is a user of it.
        let other = own.checked_add(1).unwrap();
        fixture.pid(other);
        symlink(&walked, fixture.proc_root.join(format!("{other}/fd/0"))).unwrap();
        let (targets, complete) =
            open_targets_with(&NativeProc, &fixture.proc_root, Limits::default()).unwrap();
        assert!(complete);
        assert!(targets.contains(&walked));
        assert!(targets.contains(&own_log));
    }

    /// bd-d1kt: a process's working directory counts, sbh's own does not.
    #[test]
    fn path_only_sweep_counts_a_process_working_directory() {
        let fixture = Fixture::new();
        let own = i32::try_from(std::process::id()).unwrap();
        let other = own.checked_add(1).unwrap();
        let building = fixture.root.join("cargo-home/registry/src/serde");
        let idle = fixture.root.join("idle");
        fs::create_dir_all(&building).unwrap();
        fs::create_dir(&idle).unwrap();
        symlink(&building, fixture.pid(other).join("cwd")).unwrap();
        symlink(&idle, fixture.pid(own).join("cwd")).unwrap();
        let (targets, complete) =
            open_targets_with(&NativeProc, &fixture.proc_root, Limits::default()).unwrap();
        assert!(complete);
        assert_eq!(targets, vec![building]);
    }

    /// bd-d1kt: rch's shared cargo cache is named in every rustc's environment
    /// and held open by none of them.
    #[test]
    fn a_live_build_names_its_cargo_home_and_target_directory() {
        let fixture = Fixture::new();
        let own = i32::try_from(std::process::id()).unwrap();
        let home = fixture.root.join("rch-cargo-cache");
        let target = fixture.root.join("pooled-target");
        let environ = |home: &Path, target: &Path| {
            format!(
                "PATH=/usr/bin\0CARGO_HOME={}\0CARGO_TARGET_DIR={}\0RELATIVE=x\0",
                home.display(),
                target.display()
            )
        };
        let tool = |pid: i32, comm: &str, env: &str| {
            let process = fixture.pid(pid);
            fs::write(process.join("comm"), format!("{comm}\n")).unwrap();
            fs::write(process.join("environ"), env).unwrap();
        };
        let other = own.checked_add(1).unwrap();
        tool(other, "rustc", &environ(&home, &target));
        // Not a build tool, sbh itself, and a relative value: none count.
        tool(
            other + 1,
            "bash",
            &environ(&fixture.root.join("shell"), &target),
        );
        tool(
            own,
            "rustc",
            &environ(&fixture.root.join("own"), &fixture.root.join("own-t")),
        );
        tool(other + 2, "cargo", "CARGO_HOME=relative/home\0");

        let found = build_directories_with(&NativeProc, &fixture.proc_root, Limits::default());
        let paths: Vec<_> = found.iter().map(|(_, path)| path.clone()).collect();
        assert!(found.iter().all(|(pid, _)| *pid == other));
        assert_eq!(
            paths,
            vec![
                home.join("registry/index"),
                home.join("registry/cache"),
                home.join("registry/src"),
                home.join("git/db"),
                home.join("git/checkouts"),
                target.clone(),
            ]
        );

        let (targets, _) =
            open_targets_with(&NativeProc, &fixture.proc_root, Limits::default()).unwrap();
        assert!(targets.contains(&home.join("registry/src")));
        assert!(targets.contains(&target));
    }

    /// ts2 2026-10-15: `rch exec -- cargo build` compiles on a worker, so the
    /// only local process is `rch`, and its fresh mktemp target stays empty
    /// until the artifacts sync back. Its environment names the target.
    #[test]
    fn an_offloaded_rch_build_names_its_target_directory() {
        let fixture = Fixture::new();
        let own = i32::try_from(std::process::id()).unwrap();
        let target = fixture
            .root
            .join("mea-bfv-recurrence/rch-target-20261015T091718Z-p8M5L7");
        let process = fixture.pid(own.checked_add(1).unwrap());
        fs::write(process.join("comm"), "rch\n").unwrap();
        fs::write(
            process.join("environ"),
            format!(
                "HOME=/home/builder\0CARGO_TARGET_DIR={}\0RCH_REQUIRE_REMOTE=1\0",
                target.display()
            ),
        )
        .unwrap();

        let found = build_directories_with(&NativeProc, &fixture.proc_root, Limits::default());
        assert!(found.iter().any(|(_, path)| *path == target), "{found:?}");
    }

    #[test]
    fn a_default_home_build_holds_its_cargo_caches_and_an_idle_home_does_not() {
        let fixture = Fixture::new();
        let pid = i32::try_from(std::process::id())
            .unwrap()
            .checked_add(1)
            .unwrap();
        let user_home = fixture.root.join("home/user");
        let cargo_home = user_home.join(".cargo");
        for store in ["registry/src", "git/db"] {
            fs::create_dir_all(cargo_home.join(store)).unwrap();
        }
        let process = fixture.pid(pid);
        let environ = format!("PATH=/usr/bin\0HOME={}\0", user_home.display());
        fs::write(process.join("environ"), &environ).unwrap();
        let roots = vec![fixture.root.clone()];

        // Control: the same home under a shell, no build running. Nothing
        // names the caches, so they stay reclaimable.
        fs::write(process.join("comm"), b"bash\n").unwrap();
        assert!(
            build_directories_with(&NativeProc, &fixture.proc_root, Limits::default()).is_empty()
        );
        let (targets, _) =
            open_targets_with(&NativeProc, &fixture.proc_root, Limits::default()).unwrap();
        let ancestors = crate::scanner::walker::open_path_ancestors_for_roots(&targets, &roots);
        assert!(!ancestors.contains(&cargo_home.join("registry")));
        assert!(!ancestors.contains(&cargo_home.join("git/db")));

        // A build with no CARGO_HOME uses `$HOME/.cargo`: its stores, and the
        // directories above them, are references with no descriptor open.
        fs::write(process.join("comm"), b"rustc\n").unwrap();
        let found = build_directories_with(&NativeProc, &fixture.proc_root, Limits::default());
        assert_eq!(
            found,
            [
                "registry/index",
                "registry/cache",
                "registry/src",
                "git/db",
                "git/checkouts"
            ]
            .iter()
            .map(|store| (pid, cargo_home.join(store)))
            .collect::<Vec<_>>()
        );
        let (targets, _) =
            open_targets_with(&NativeProc, &fixture.proc_root, Limits::default()).unwrap();
        let ancestors = crate::scanner::walker::open_path_ancestors_for_roots(&targets, &roots);
        for held in ["registry", "registry/src", "git", "git/db"] {
            assert!(ancestors.contains(&cargo_home.join(held)), "{held} is held");
        }
        assert!(ancestors.contains(&cargo_home));
        assert_eq!(fs::read_dir(process.join("fd")).unwrap().count(), 0);
    }

    #[test]
    fn a_refused_build_environment_holds_the_batch() {
        let fixture = Fixture::new();
        let pid = i32::try_from(std::process::id())
            .unwrap()
            .checked_add(1)
            .unwrap();
        let process = fixture.pid(pid);
        let work = fixture.root.join("work");
        fs::create_dir(&work).unwrap();
        fs::write(process.join("comm"), b"rustc\n").unwrap();
        fs::write(process.join("environ"), b"HOME=/home/builder\0").unwrap();
        symlink(&work, process.join("cwd")).unwrap();
        let sweep = |faults: &Faults| {
            open_targets_with(faults, &fixture.proc_root, Limits::default())
                .unwrap()
                .1
        };
        assert!(sweep(&Faults::default()), "everything readable");

        // A daemon that may not inspect the builder (another uid, no
        // CAP_SYS_PTRACE) cannot know what it uses: the batch is held.
        let mut refused = Faults::default();
        refused.reads.insert(process.join("environ"), libc::EACCES);
        assert!(!sweep(&refused), "a refused build environment");
        // An exited process uses nothing; counting it would stall every batch.
        let mut gone = Faults::default();
        gone.reads.insert(process.join("environ"), libc::ESRCH);
        assert!(sweep(&gone), "gone is not refused");

        // A refused environment of a process that is not a build tool is
        // never read at all.
        fs::write(process.join("comm"), b"bash\n").unwrap();
        let mut unrelated = Faults::default();
        unrelated
            .reads
            .insert(process.join("environ"), libc::EACCES);
        assert!(sweep(&unrelated));
    }

    #[test]
    fn one_sweep_answers_every_root() {
        let fixture = Fixture::new();
        let kept = fixture.fd(1, 0);
        let other_root = fixture.root.join("other-root");
        fs::create_dir(&other_root).unwrap();
        let elsewhere = other_root.join("held");
        fs::write(&elsewhere, b"held").unwrap();
        let process = fixture.pid(2);
        symlink(&elsewhere, process.join("fd").join("3")).unwrap();
        fs::write(
            process.join("fdinfo").join("3"),
            b"pos:\t0\nflags:\t0100002\n",
        )
        .unwrap();
        let roots = vec![kept.parent().unwrap().to_path_buf(), other_root];

        let access = Faults::default();
        let result =
            open_files_with_roots(&access, &fixture.proc_root, &roots, Limits::default()).unwrap();
        assert!(result.complete);
        let paths: Vec<_> = result.files.iter().map(|file| file.path.clone()).collect();
        assert!(paths.contains(&resolve_absolute_path(&kept)));
        assert!(paths.contains(&resolve_absolute_path(&elsewhere)));
        // Each descriptor link is read once, not once per root.
        let single = access.link_calls.get();
        let per_root = Faults::default();
        for root in &roots {
            open_files_with(&per_root, &fixture.proc_root, root, Limits::default()).unwrap();
        }
        assert_eq!(per_root.link_calls.get(), single * roots.len());
    }

    #[test]
    fn external_build_caches_reach_scoring_and_executor_without_open_files() {
        let fixture = Fixture::new();
        let first = i32::try_from(std::process::id())
            .unwrap()
            .checked_add(1)
            .unwrap();
        for (offset, (comm, key)) in [
            ("go", "GOCACHE"),
            ("go", "GOMODCACHE"),
            ("npm install", "npm_config_cache"),
            ("uv", "UV_CACHE_DIR"),
            ("python3.13", "PIP_CACHE_DIR"),
            ("sccache", "SCCACHE_DIR"),
            ("clang-20", "CCACHE_DIR"),
        ]
        .iter()
        .enumerate()
        {
            let pid = first + i32::try_from(offset).unwrap();
            let process = fixture.pid(pid);
            let cache = fixture.root.join(key);
            fs::create_dir(&cache).unwrap();
            fs::write(cache.join("keep"), b"active cache").unwrap();
            fs::write(process.join("comm"), format!("{comm}\n")).unwrap();
            fs::write(
                process.join("environ"),
                format!("{key}={}\0", cache.display()),
            )
            .unwrap();
        }
        let found = build_directories_with(&NativeProc, &fixture.proc_root, Limits::default());
        assert_eq!(found.len(), 7);
        let (targets, complete) =
            open_targets_with(&NativeProc, &fixture.proc_root, Limits::default()).unwrap();
        assert!(complete);
        let roots = vec![fixture.root.clone()];
        let ancestors = crate::scanner::walker::open_path_ancestors_for_roots(&targets, &roots);
        for (pid, cache) in found {
            assert!(targets.contains(&cache));
            assert!(ancestors.contains(&cache));
            assert!(ancestors.contains(&fixture.root));
            assert_eq!(
                fs::read_dir(fixture.proc_root.join(pid.to_string()).join("fd"))
                    .unwrap()
                    .count(),
                0
            );
            assert_eq!(fs::read(cache.join("keep")).unwrap(), b"active cache");
        }
    }

    #[test]
    fn relative_build_roots_use_the_process_cwd_and_keep_absolute_evidence_on_denial() {
        let fixture = Fixture::new();
        let pid = i32::try_from(std::process::id())
            .unwrap()
            .checked_add(1)
            .unwrap();
        let process = fixture.pid(pid);
        fs::write(process.join("comm"), b"rustc\n").unwrap();
        fs::write(
            process.join("environ"),
            b"CARGO_TARGET_DIR=../target\0SCCACHE_DIR=/shared/cache\0",
        )
        .unwrap();
        let cwd = fixture.root.join("workspace");
        fs::create_dir(&cwd).unwrap();
        symlink(&cwd, process.join("cwd")).unwrap();
        assert_eq!(
            build_directories_with(&NativeProc, &fixture.proc_root, Limits::default()),
            vec![
                (pid, cwd.join("../target")),
                (pid, PathBuf::from("/shared/cache")),
            ]
        );
        let mut denied = Faults::default();
        denied.links.insert(process.join("cwd"), libc::EACCES);
        assert_eq!(
            build_directories_with(&denied, &fixture.proc_root, Limits::default()),
            vec![(pid, PathBuf::from("/shared/cache"))]
        );
    }

    #[test]
    fn build_metadata_does_not_renew_deadlines_or_read_unrelated_environments() {
        let fixture = Fixture::new();
        let pid = i32::try_from(std::process::id())
            .unwrap()
            .checked_add(1)
            .unwrap();
        let process = fixture.pid(pid);
        fs::write(process.join("comm"), b"go\n").unwrap();
        fs::write(process.join("environ"), b"GOCACHE=/shared/go\0").unwrap();
        let slow = Faults {
            advance_per_read: Duration::from_secs(1),
            ..Faults::default()
        };
        let limits = Limits {
            time: Duration::from_secs(2),
            ..Limits::default()
        };
        assert_eq!(
            build_directories_with(&slow, &fixture.proc_root, limits),
            vec![(pid, PathBuf::from("/shared/go"))]
        );
        assert_eq!(slow.link_calls.get(), 0);
        assert_eq!(slow.read_paths.borrow().len(), 2);
        fs::write(process.join("comm"), b"bash\n").unwrap();
        let unrelated = Faults::default();
        assert!(
            build_directories_with(&unrelated, &fixture.proc_root, Limits::default()).is_empty()
        );
        assert_eq!(*unrelated.read_paths.borrow(), vec![process.join("comm")]);
    }

    #[test]
    fn path_only_sweep_retains_partial_positives_on_denied_processes() {
        let fixture = Fixture::new();
        fixture.fd(1, 0);
        let retained = fixture.fd(2, 0);
        for code in [libc::EACCES, libc::EPERM, libc::EIO, libc::EMFILE] {
            let mut access = Faults::default();
            access.dirs.insert(fixture.proc_root.join("1/fd"), code);
            let (targets, complete) =
                open_targets_with(&access, &fixture.proc_root, Limits::default()).unwrap();
            assert!(!complete, "error {code}");
            assert_eq!(targets, vec![retained.clone()]);
            assert!(!fixture.scan(&access, Limits::default()).complete);
        }
    }

    #[test]
    fn path_only_sweep_preserves_link_and_enumeration_failures() {
        let fixture = Fixture::new();
        fixture.fd(1, 0);
        let retained = fixture.fd(1, 1);
        let mut access = Faults::default();
        access
            .links
            .insert(fixture.proc_root.join("1/fd/0"), libc::EIO);
        let (targets, complete) =
            open_targets_with(&access, &fixture.proc_root, Limits::default()).unwrap();
        assert!(!complete);
        assert_eq!(targets, vec![retained.clone()]);
        for path in [&fixture.proc_root, &fixture.proc_root.join("1/fd")] {
            let access = Faults {
                entry_error: Some(path.clone()),
                ..Faults::default()
            };
            let (targets, complete) =
                open_targets_with(&access, &fixture.proc_root, Limits::default()).unwrap();
            assert!(!complete);
            assert!(targets.contains(&retained));
        }
    }

    #[test]
    fn path_only_discovery_failure_is_not_empty_complete_evidence() {
        let fixture = Fixture::new();
        let mut access = Faults::default();
        access.dirs.insert(fixture.proc_root.clone(), libc::EACCES);
        assert!(open_targets_with(&access, &fixture.proc_root, Limits::default()).is_err());
    }

    #[test]
    fn path_only_sweep_keeps_the_same_exact_bounds_as_the_pal() {
        let fixture = Fixture::new();
        for fd in 0..3 {
            fixture.fd(1, fd);
        }
        let retained = fixture.fd(2, 0);
        for limit in 0..=5 {
            let limits = Limits {
                descriptors: limit,
                ..Limits::default()
            };
            let access = Faults::default();
            let (targets, complete) =
                open_targets_with(&access, &fixture.proc_root, limits).unwrap();
            assert_eq!(targets.len(), limit.min(4));
            assert_eq!(access.link_calls.get(), limit.min(4));
            assert_eq!(complete, limit >= 4);
            assert_eq!(complete, fixture.scan(&Faults::default(), limits).complete);
        }
        let (targets, complete) = open_targets_with(
            &Faults::default(),
            &fixture.proc_root,
            Limits {
                per_pid: 1,
                ..Limits::default()
            },
        )
        .unwrap();
        assert!(!complete);
        assert_eq!(targets.len(), 2);
        assert!(
            targets.contains(&retained),
            "one busy PID must not hide later PIDs"
        );
    }

    #[test]
    fn path_only_deadline_applies_inside_a_single_pid() {
        let fixture = Fixture::new();
        for fd in 0..5 {
            fixture.fd(1, fd);
        }
        let access = Faults {
            advance_per_link: Duration::from_secs(1),
            ..Faults::default()
        };
        let (targets, complete) = open_targets_with(
            &access,
            &fixture.proc_root,
            Limits {
                time: Duration::from_secs(2),
                ..Limits::default()
            },
        )
        .unwrap();
        assert!(!complete);
        assert_eq!(targets.len(), 2);
        assert_eq!(access.link_calls.get(), 2);
    }

    #[test]
    fn path_only_sweep_preserves_normal_process_and_descriptor_churn() {
        let fixture = Fixture::new();
        fixture.fd(1, 0);
        let retained = fixture.fd(1, 1);
        let mut access = Faults {
            absent_pid: Some(99),
            ..Faults::default()
        };
        access
            .links
            .insert(fixture.proc_root.join("1/fd/0"), libc::ENOENT);
        let (targets, complete) =
            open_targets_with(&access, &fixture.proc_root, Limits::default()).unwrap();
        assert!(complete);
        assert_eq!(targets, vec![retained]);
    }

    #[test]
    fn path_only_sweep_keeps_literal_deleted_suffix_and_byte_paths() {
        use std::os::unix::ffi::OsStringExt as _;
        let fixture = Fixture::new();
        let process = fixture.pid(1);
        let literal = fixture
            .root
            .join(OsString::from_vec(b"target-\xff (deleted)".to_vec()));
        fs::create_dir(&literal).unwrap();
        symlink(&literal, process.join("fd/0")).unwrap();
        let stripped = fixture
            .root
            .join(OsString::from_vec(b"target-\xff".to_vec()));
        let (targets, complete) =
            open_targets_with(&NativeProc, &fixture.proc_root, Limits::default()).unwrap();
        assert!(complete);
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&literal));
        assert!(targets.contains(&stripped));
        assert!(literal.is_dir(), "inspection is read-only");
    }

    #[test]
    fn path_only_sweep_leaves_resolution_to_the_scoped_ancestor_mapper() {
        let fixture = Fixture::new();
        let process = fixture.pid(1);
        let directory = fixture.root.join("real");
        fs::create_dir(&directory).unwrap();
        let alias = fixture.root.join("alias");
        symlink(&directory, &alias).unwrap();
        let target = alias.join("object");
        fs::write(directory.join("object"), b"kept").unwrap();
        symlink(&target, process.join("fd/0")).unwrap();
        let (targets, complete) =
            open_targets_with(&NativeProc, &fixture.proc_root, Limits::default()).unwrap();
        assert!(complete);
        assert_eq!(targets, vec![target]);
        assert_eq!(
            fixture.scan(&NativeProc, Limits::default()).files[0].path,
            directory.join("object")
        );
    }

    #[test]
    fn path_only_sweep_excludes_pseudo_links_but_reports_unknown_relative_targets() {
        let fixture = Fixture::new();
        socket_table_fixture(&fixture, b"");
        let retained = fixture.fd(1, 0);
        symlink("socket:[123]", fixture.proc_root.join("1/fd/1")).unwrap();
        symlink("anon_inode:[eventpoll]", fixture.proc_root.join("1/fd/2")).unwrap();
        let (targets, complete) =
            open_targets_with(&NativeProc, &fixture.proc_root, Limits::default()).unwrap();
        assert!(complete);
        assert_eq!(targets, vec![retained.clone()]);
        symlink("unknown-relative-target", fixture.proc_root.join("1/fd/3")).unwrap();
        let (targets, complete) =
            open_targets_with(&NativeProc, &fixture.proc_root, Limits::default()).unwrap();
        assert!(!complete);
        assert_eq!(targets, vec![retained]);
    }

    fn task_stat(pid: i32, state: &str, flags: u64, threads: usize) -> String {
        let mut fields = vec!["0".to_string(); 20];
        fields[0] = state.to_string();
        fields[6] = flags.to_string();
        fields[17] = threads.to_string();
        format!("{pid} (worker with ) parens) {}\n", fields.join(" "))
    }

    #[test]
    fn executable_reference_does_not_require_ancillary_process_metadata() {
        let fixture = Fixture::new();
        let high = fixture.exe(22);
        let low = fixture.exe(11);
        let access = Faults::default();
        let result = fixture.scan_executables(&access, Limits::default());
        assert!(result.complete);
        assert_eq!(result.processes.len(), 2);
        assert_eq!(result.processes[0].executable.as_ref(), Some(&low));
        assert_eq!(result.processes[1].executable.as_ref(), Some(&high));
        assert_eq!(result.processes[0].name, "program-11");
        assert!(
            access
                .read_paths
                .borrow()
                .iter()
                .all(|path| path.ends_with("comm"))
        );
        assert_eq!(fs::read(low).unwrap(), b"retained program");
        assert_eq!(fs::read(high).unwrap(), b"retained program");
    }

    #[test]
    fn denied_executable_keeps_other_programs_but_revokes_complete_coverage() {
        let fixture = Fixture::new();
        fixture.exe(1);
        let retained = fixture.exe(2);
        for code in [libc::EACCES, libc::EPERM, libc::EIO, libc::EMFILE] {
            let mut access = Faults::default();
            access.links.insert(fixture.proc_root.join("1/exe"), code);
            let result = fixture.scan_executables(&access, Limits::default());
            assert!(!result.complete, "link error {code}");
            assert_eq!(result.processes.len(), 1);
            assert_eq!(result.processes[0].executable.as_ref(), Some(&retained));
        }
    }

    #[test]
    fn absent_exe_for_a_live_unclassified_process_is_unknown_not_safe() {
        let fixture = Fixture::new();
        fixture.pid(1);
        let retained = fixture.exe(2);
        let result = fixture.scan_executables(&NativeProc, Limits::default());
        assert!(!result.complete);
        assert_eq!(result.processes.len(), 1);
        assert_eq!(result.processes[0].executable.as_ref(), Some(&retained));
    }

    #[test]
    fn kernel_threads_terminal_single_threads_and_gone_pids_are_not_access_failures() {
        let fixture = Fixture::new();
        let kernel = fixture.pid(1);
        fs::write(kernel.join("stat"), task_stat(1, "S", PF_KTHREAD, 1)).unwrap();
        let zombie = fixture.pid(2);
        fs::write(zombie.join("stat"), task_stat(2, "Z", 0, 1)).unwrap();
        let retained = fixture.exe(3);
        let access = Faults {
            absent_pid: Some(99),
            ..Faults::default()
        };
        let result = fixture.scan_executables(&access, Limits::default());
        assert!(result.complete);
        assert_eq!(result.processes.len(), 1);
        assert_eq!(result.processes[0].executable.as_ref(), Some(&retained));
    }

    #[test]
    fn exited_group_leader_does_not_hide_executing_sibling_threads() {
        let fixture = Fixture::new();
        let process = fixture.pid(1);
        fs::write(process.join("stat"), task_stat(1, "Z", 0, 2)).unwrap();
        let result = fixture.scan_executables(&NativeProc, Limits::default());
        assert!(!result.complete);
        assert!(result.processes.is_empty());
        assert!(!stat_has_no_user_executable(
            task_stat(1, "S", 0, 1).as_bytes(),
            1
        ));
    }

    #[test]
    fn missing_exe_requires_valid_matching_and_readable_stat_evidence() {
        let fixture = Fixture::new();
        let process = fixture.pid(1);
        for raw in [
            task_stat(2, "Z", 0, 1).into_bytes(),
            task_stat(1, "Z", 0, 0).into_bytes(),
            b"1 (truncated) Z 0 0".to_vec(),
            vec![0xff; 100],
            vec![b' '; MAX_EXECUTABLE_STAT_BYTES + 1],
        ] {
            fs::write(process.join("stat"), raw).unwrap();
            assert!(
                !fixture
                    .scan_executables(&NativeProc, Limits::default())
                    .complete
            );
        }
        fs::write(process.join("stat"), task_stat(1, "Z", 0, 1)).unwrap();
        let mut access = Faults::default();
        access.reads.insert(process.join("stat"), libc::EACCES);
        assert!(
            !fixture
                .scan_executables(&access, Limits::default())
                .complete
        );
    }

    #[test]
    fn optional_name_failures_and_non_utf8_names_preserve_the_executable() {
        let fixture = Fixture::new();
        let target = fixture.exe(1);
        let comm = fixture.proc_root.join("1/comm");
        for raw in [
            Vec::new(),
            vec![b'x'; MAX_EXECUTABLE_COMM_BYTES + 1],
            b"worker-\xff\n".to_vec(),
        ] {
            fs::write(&comm, raw).unwrap();
            let result = fixture.scan_executables(&NativeProc, Limits::default());
            assert!(result.complete);
            assert_eq!(result.processes[0].executable.as_ref(), Some(&target));
            assert!(!result.processes[0].name.is_empty());
        }
        let mut access = Faults::default();
        access.reads.insert(comm, libc::EACCES);
        let result = fixture.scan_executables(&access, Limits::default());
        assert!(result.complete);
        assert_eq!(result.processes[0].name, "program-1");
        assert_eq!(result.processes[0].executable.as_ref(), Some(&target));
    }

    #[test]
    fn executable_queries_keep_raw_path_bytes_and_resolved_scope() {
        use std::os::unix::ffi::OsStringExt;
        let fixture = Fixture::new();
        let process = fixture.pid(1);
        let target = fixture
            .root
            .join(OsString::from_vec(b"program-\xff".to_vec()));
        fs::write(&target, b"byte-named program").unwrap();
        symlink(&target, process.join("exe")).unwrap();
        let alias = fixture.proc_root.join("artifact-alias");
        symlink(&fixture.root, &alias).unwrap();
        let result =
            executables_with(&NativeProc, &fixture.proc_root, &alias, Limits::default()).unwrap();
        assert!(result.complete);
        assert_eq!(result.processes.len(), 1);
        assert_eq!(result.processes[0].executable.as_ref(), Some(&target));
        assert_eq!(fs::read(target).unwrap(), b"byte-named program");
    }

    #[test]
    fn executable_discovery_distinguishes_exact_pid_and_entry_limits_from_truncation() {
        let fixture = Fixture::new();
        for pid in 1..=3 {
            fixture.exe(pid);
        }
        for limit in 0..=4 {
            for limits in [
                Limits {
                    pids: limit,
                    ..Limits::default()
                },
                Limits {
                    proc_entries: limit,
                    ..Limits::default()
                },
            ] {
                let access = Faults::default();
                let result = fixture.scan_executables(&access, limits);
                assert_eq!(result.processes.len(), limit.min(3));
                assert_eq!(access.link_calls.get(), limit.min(3));
                assert_eq!(result.complete, limit >= 3);
            }
        }
    }

    #[test]
    fn executable_metadata_consumes_the_same_deadline_without_losing_a_positive() {
        let fixture = Fixture::new();
        for pid in 1..=3 {
            fixture.exe(pid);
        }
        let access = Faults {
            advance_per_read: Duration::from_secs(2),
            ..Faults::default()
        };
        let result = fixture.scan_executables(
            &access,
            Limits {
                time: Duration::from_secs(2),
                ..Limits::default()
            },
        );
        assert!(!result.complete);
        assert_eq!(result.processes.len(), 1);
        assert_eq!(access.link_calls.get(), 1);
        assert_eq!(access.read_paths.borrow().len(), 1);
        let slow_link = Faults {
            advance_per_link: Duration::from_secs(3),
            ..Faults::default()
        };
        let result = fixture.scan_executables(
            &slow_link,
            Limits {
                time: Duration::from_secs(2),
                ..Limits::default()
            },
        );
        assert!(!result.complete);
        assert_eq!(result.processes.len(), 1);
        assert_eq!(slow_link.link_calls.get(), 1);
        assert!(slow_link.read_paths.borrow().is_empty());
    }

    #[test]
    fn current_pid_executable_scope_has_complete_native_coverage() {
        let executable = resolve_absolute_path(&std::env::current_exe().unwrap());
        let pid = i32::try_from(std::process::id()).unwrap();
        let mut sweep = Sweep::new(&NativeProc, Limits::default());
        let mut processes = Vec::new();
        sweep.executable(
            Path::new(PROC_ROOT),
            pid,
            std::slice::from_ref(&executable),
            &mut processes,
        );
        sweep.expired();
        assert!(sweep.complete);
        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].pid, pid);
        assert_eq!(processes[0].executable.as_ref(), Some(&executable));
        assert!(!processes[0].name.is_empty());
    }

    #[test]
    fn executable_discovery_errors_preserve_coverage_semantics() {
        let fixture = Fixture::new();
        let target = fixture.exe(1);
        let access = Faults {
            entry_error: Some(fixture.proc_root.clone()),
            ..Faults::default()
        };
        let result = fixture.scan_executables(&access, Limits::default());
        assert!(!result.complete);
        assert_eq!(result.processes[0].executable.as_ref(), Some(&target));
        let mut denied = Faults::default();
        denied.dirs.insert(fixture.proc_root.clone(), libc::EACCES);
        assert!(
            executables_with(
                &denied,
                &fixture.proc_root,
                &fixture.root,
                Limits::default()
            )
            .is_err()
        );
    }

    #[test]
    fn relative_executable_targets_never_become_cwd_relative_references() {
        let fixture = Fixture::new();
        let process = fixture.pid(1);
        symlink("unexpected-relative-program", process.join("exe")).unwrap();
        let result = fixture.scan_executables(&NativeProc, Limits::default());
        assert!(!result.complete);
        assert!(result.processes.is_empty());
    }

    #[test]
    fn executable_scope_does_not_expand_and_outside_programs_need_no_annotations() {
        let fixture = Fixture::new();
        let target = fixture.exe(1);
        fixture.exe(2);
        let access = Faults::default();
        let result =
            executables_with(&access, &fixture.proc_root, &target, Limits::default()).unwrap();
        assert!(result.complete);
        assert_eq!(result.processes.len(), 1);
        assert_eq!(result.processes[0].executable.as_ref(), Some(&target));
        assert_eq!(
            *access.read_paths.borrow(),
            vec![fixture.proc_root.join("1/comm")]
        );
    }

    #[test]
    fn nonregular_optional_metadata_cannot_block_or_discard_a_running_program() {
        let fixture = Fixture::new();
        let target = fixture.exe(1);
        let comm = fixture.proc_root.join("1/comm");
        nix::unistd::mkfifo(
            &comm,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        let result = fixture.scan_executables(&NativeProc, Limits::default());
        assert!(result.complete);
        assert_eq!(result.processes[0].executable.as_ref(), Some(&target));
        assert_eq!(result.processes[0].name, "program-1");
    }

    fn socket_table_fixture(fixture: &Fixture, rows: &[u8]) -> PathBuf {
        let path = fixture.proc_root.join("net/unix");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut raw = unix_sockets::HEADER.to_vec();
        raw.extend_from_slice(rows);
        fs::write(&path, raw).unwrap();
        path
    }

    fn socket_fd_fixture(fixture: &Fixture, pid: i32, fd: i32, inode: u64) {
        let process = fixture.pid(pid);
        symlink(
            format!("socket:[{inode}]"),
            process.join("fd").join(fd.to_string()),
        )
        .unwrap();
    }

    #[test]
    fn socket_table_read_failures_hold_both_scoring_and_executor_sweeps() {
        let fixture = Fixture::new();
        let retained = fixture.fd(77, 0);
        socket_fd_fixture(&fixture, 77, 1, 4242);
        let table = socket_table_fixture(&fixture, b"");
        for error in [
            libc::ENOENT,
            libc::EACCES,
            libc::EPERM,
            libc::EIO,
            libc::EFBIG,
        ] {
            let mut access = Faults::default();
            access.reads.insert(table.clone(), error);
            let result = fixture.scan(&access, Limits::default());
            assert!(!result.complete, "socket table error {error}");
            assert_eq!(result.files.len(), 1);
            assert_eq!(result.files[0].path, retained);
            let (targets, complete) =
                open_targets_with(&access, &fixture.proc_root, Limits::default()).unwrap();
            assert!(!complete, "executor must retain the same uncertainty");
            assert!(targets.contains(&retained));
        }
        assert_eq!(fs::read(retained).unwrap(), b"retained artifact");
    }

    #[test]
    fn malformed_socket_rows_keep_valid_bound_paths_but_never_certify_absence() {
        let fixture = Fixture::new();
        let retained = fixture.fd(77, 0);
        let served = fixture.root.join("server.sock");
        socket_fd_fixture(&fixture, 77, 1, 4242);
        let rows = format!(
            "garbage\n0: 2 0 10000 1 1 4242 {}\nbroken final row\n",
            served.display()
        );
        socket_table_fixture(&fixture, rows.as_bytes());
        let result = fixture.scan(&NativeProc, Limits::default());
        assert!(!result.complete);
        assert!(result.files.iter().any(|file| file.path == retained));
        assert!(result.files.iter().any(|file| file.path == served));
        let (targets, complete) =
            open_targets_with(&NativeProc, &fixture.proc_root, Limits::default()).unwrap();
        assert!(!complete);
        assert!(targets.contains(&retained));
        assert!(targets.contains(&served));
    }

    /// A relative binding is never rebuilt from the process's current cwd (it
    /// may have moved since bind), and it does not hold the batch either:
    /// Postfix binds every service relatively, and holding on it stopped all
    /// reclaim on css, csd and yto. A server still in its directory holds it
    /// through its cwd.
    #[test]
    fn a_relative_socket_binding_is_neither_rebuilt_nor_a_reason_to_hold() {
        let fixture = Fixture::new();
        socket_fd_fixture(&fixture, 77, 1, 4242);
        let current = fixture.root.join("not-the-bind-directory");
        fs::create_dir(&current).unwrap();
        symlink(&current, fixture.proc_root.join("77/cwd")).unwrap();
        socket_table_fixture(&fixture, b"0: 2 0 10000 1 1 4242 public/pickup\n");
        let result = fixture.scan(&NativeProc, Limits::default());
        assert!(result.complete);
        assert!(result.files.is_empty());
        let (targets, complete) =
            open_targets_with(&NativeProc, &fixture.proc_root, Limits::default()).unwrap();
        assert!(complete);
        assert!(!targets.contains(&current.join("public/pickup")));
        assert!(
            targets.contains(&current),
            "the independent cwd reference still counts"
        );
    }

    #[test]
    fn a_socket_table_is_read_once_even_when_failed_or_many_descriptors_use_it() {
        let fixture = Fixture::new();
        for fd in 0..16 {
            socket_fd_fixture(&fixture, 77, fd, 4242);
        }
        let path = socket_table_fixture(&fixture, b"0: 2 0 10000 1 1 4242 @abstract\n");
        for denied in [false, true] {
            let mut access = Faults::default();
            if denied {
                access.reads.insert(path.clone(), libc::EACCES);
            }
            let result = fixture.scan(&access, Limits::default());
            assert_eq!(result.complete, !denied);
            assert!(result.files.is_empty());
            assert_eq!(
                access
                    .read_paths
                    .borrow()
                    .iter()
                    .filter(|read| **read == path)
                    .count(),
                1,
                "failure does not start a per-descriptor retry loop"
            );
        }
    }

    #[test]
    fn malformed_socket_pseudo_links_are_not_known_fileless_descriptors() {
        for target in [
            "socket:[+42]",
            "socket:[]",
            "socket:[bad]",
            "socket:[0]",
            "socket:[42]extra",
        ] {
            let fixture = Fixture::new();
            let retained = fixture.fd(77, 0);
            symlink(target, fixture.proc_root.join("77/fd/1")).unwrap();
            let result = fixture.scan(&NativeProc, Limits::default());
            assert!(!result.complete, "{target}");
            assert_eq!(result.files[0].path, retained);
        }
    }

    #[test]
    fn scans_without_socket_descriptors_do_not_read_socket_tables() {
        let fixture = Fixture::new();
        fixture.fd(77, 0);
        let access = Faults::default();
        assert!(fixture.scan(&access, Limits::default()).complete);
        assert!(access.read_paths.borrow().is_empty());
    }

    #[test]
    fn expired_socket_resolution_does_not_start_another_proc_read() {
        let fixture = Fixture::new();
        socket_fd_fixture(&fixture, 77, 1, 4242);
        socket_table_fixture(&fixture, b"0: 2 0 10000 1 1 4242 @abstract\n");
        let access = Faults {
            advance_per_link: Duration::from_secs(2),
            ..Faults::default()
        };
        let result = fixture.scan(
            &access,
            Limits {
                time: Duration::from_secs(1),
                ..Limits::default()
            },
        );
        assert!(!result.complete);
        assert!(access.read_paths.borrow().is_empty());
    }

    #[test]
    fn socket_table_size_and_nonregular_file_failures_are_not_empty_evidence() {
        let fixture = Fixture::new();
        socket_fd_fixture(&fixture, 77, 1, 4242);
        let table = socket_table_fixture(&fixture, b"");
        fs::File::create(&table)
            .unwrap()
            .set_len(u64::try_from(MAX_UNIX_SOCKET_TABLE_BYTES).unwrap() + 1)
            .unwrap();
        assert!(!fixture.scan(&NativeProc, Limits::default()).complete);
        let saved = table.with_extension("oversized");
        fs::rename(&table, &saved).unwrap();
        nix::unistd::mkfifo(
            &table,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        assert!(!fixture.scan(&NativeProc, Limits::default()).complete);
    }

    #[test]
    fn a_native_listener_is_resolved_from_the_actual_kernel_table() {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::net::UnixListener;
        let fixture = Fixture::new();
        let path = fixture.root.join("bound.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let target = fs::read_link(format!("/proc/self/fd/{}", listener.as_raw_fd())).unwrap();
        let inode = socket_inode(&target).unwrap();
        let mut sweep = Sweep::new(&NativeProc, Limits::default());
        assert_eq!(
            sweep.unix_socket_path(Path::new(PROC_ROOT), inode),
            Some(path)
        );
        assert!(sweep.complete);
    }
}
