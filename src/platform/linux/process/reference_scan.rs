//! Bounded, coverage-aware scans of the visible Linux proc namespace.
//!
//! Positive references survive another PID's access failure. `complete` means
//! that this sweep inspected its visible scope, not that procfs is an atomic
//! snapshot or that hidepid/container namespaces expose every host process.
//! Deadlines are cooperative: a single blocked kernel operation cannot be
//! interrupted here. Caps bound discovery, descriptor work, and result memory.

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

const MAX_DESCRIPTORS: usize = 262_144;
const MAX_DESCRIPTORS_PER_PID: usize = 16_384;
const MAX_PROC_ENTRIES: usize = OPEN_FILES_MAX_PIDS + 4096;
const MAX_EXECUTABLE_COMM_BYTES: usize = 256;
const MAX_EXECUTABLE_STAT_BYTES: usize = 8192;
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
}

impl<'a, P: ProcAccess> Sweep<'a, P> {
    fn new(proc: &'a P, limits: Limits) -> Self {
        Self {
            proc,
            limits,
            started: proc.now(),
            complete: true,
            descriptors_seen: 0,
        }
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

    fn fds(&mut self, proc_root: &Path, pid: i32, root: &Path, out: &mut Vec<OpenFile>) {
        self.fd_targets(proc_root, pid, |process, fd, fd_path, target| {
            let path = resolve_absolute_path(&target);
            if path.starts_with(root) {
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
            if self.expired()
                || seen >= self.limits.per_pid
                || self.descriptors_seen >= self.limits.descriptors
            {
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
                // Kernel pseudo-links must not become paths relative to sbh's
                // cwd. Unknown relative targets are not absence evidence.
                if !pseudo_target(&target) {
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
        root: &Path,
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
        if !executable.starts_with(root) {
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
            .ok()
            .is_some_and(|raw| stat_has_no_user_executable(&raw, pid))
    }
}

fn read_proc_bytes(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "non-regular proc metadata"));
    }
    let mut raw = Vec::new();
    file.take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut raw)?;
    if raw.len() > limit {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "proc metadata exceeds limit"));
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
    for pid in pids {
        if sweep.expired() {
            break;
        }
        sweep.fd_targets(proc_root, pid, |_, _, _, target| {
            add_target_spellings(&mut targets, target);
        });
    }
    let mut targets: Vec<_> = targets.into_iter().collect();
    targets.sort_unstable();
    // Failed/empty directory reads and final ordering belong to the same
    // cooperative budget. An expired observation cannot certify absence.
    sweep.expired();
    Ok((targets, sweep.complete))
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

fn open_files_with(
    proc: &impl ProcAccess,
    proc_root: &Path,
    root: &Path,
    limits: Limits,
) -> Result<OpenFilesResult> {
    let root = resolve_absolute_path(root);
    let mut sweep = Sweep::new(proc, limits);
    let pids = sweep
        .pids(proc_root)
        .map_err(|error| SbhError::io(proc_root, error))?;
    let mut files = Vec::new();
    for pid in pids {
        if sweep.expired() {
            break;
        }
        sweep.fds(proc_root, pid, &root, &mut files);
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
    })
}

pub(super) fn executables(root: &Path) -> Result<ExecutablesResult> {
    executables_with(&NativeProc, Path::new(PROC_ROOT), root, Limits::default())
}

fn executables_with(
    proc: &impl ProcAccess,
    proc_root: &Path,
    root: &Path,
    limits: Limits,
) -> Result<ExecutablesResult> {
    let root = resolve_absolute_path(root);
    let mut sweep = Sweep::new(proc, limits);
    let pids = sweep
        .pids(proc_root)
        .map_err(|error| SbhError::io(proc_root, error))?;
    let mut processes = Vec::new();
    for pid in pids {
        if sweep.expired() {
            break;
        }
        sweep.executable(proc_root, pid, &root, &mut processes);
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
            result.files.iter().map(|file| &file.path).collect::<Vec<_>>(),
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
        sweep.fds(Path::new(PROC_ROOT), pid, &fixture.root, &mut files);
        sweep.expired();
        assert!(sweep.complete);
        assert!(files.iter().any(|file| file.pid == pid && file.path == target));
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
        let result = fixture.scan(&NativeProc, Limits { per_pid: 2, ..limits });
        assert!(result.complete);
        assert_eq!(result.files.len(), 3);
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
        assert_eq!(access.link_calls.get(), 2, "deadline applies inside one PID");
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
        let target = fixture.root.join(OsString::from_vec(b"artifact-\xff".to_vec()));
        fs::write(&target, b"non-UTF-8 path").unwrap();
        symlink(&target, process.join("fd/0")).unwrap();
        let result = fixture.scan(&NativeProc, Limits::default());
        assert!(result.complete);
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, target);
        assert_eq!(result.files[0].mode, crate::platform::types::OpenFileMode::Unknown);
    }

    #[test]
    fn discovery_failure_returns_an_error_instead_of_an_empty_complete_result() {
        let fixture = Fixture::new();
        let mut access = Faults::default();
        access.dirs.insert(fixture.proc_root.clone(), libc::EACCES);
        assert!(
            open_files_with(&access, &fixture.proc_root, &fixture.root, Limits::default()).is_err()
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
        assert_eq!(result.files[0].mode, crate::platform::types::OpenFileMode::ReadWrite);
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
        access.links.insert(fixture.proc_root.join("1/fd/0"), libc::EIO);
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
            Limits { per_pid: 1, ..Limits::default() },
        )
        .unwrap();
        assert!(!complete);
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&retained), "one busy PID must not hide later PIDs");
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
            Limits { time: Duration::from_secs(2), ..Limits::default() },
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
        let mut access = Faults { absent_pid: Some(99), ..Faults::default() };
        access.links.insert(fixture.proc_root.join("1/fd/0"), libc::ENOENT);
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
        let literal = fixture.root.join(OsString::from_vec(b"target-\xff (deleted)".to_vec()));
        fs::create_dir(&literal).unwrap();
        symlink(&literal, process.join("fd/0")).unwrap();
        let stripped = fixture.root.join(OsString::from_vec(b"target-\xff".to_vec()));
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
        assert_eq!(fixture.scan(&NativeProc, Limits::default()).files[0].path,
                   directory.join("object"));
    }

    #[test]
    fn path_only_sweep_excludes_pseudo_links_but_reports_unknown_relative_targets() {
        let fixture = Fixture::new();
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
        assert!(access.read_paths.borrow().iter().all(|path| path.ends_with("comm")));
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
        let access = Faults { absent_pid: Some(99), ..Faults::default() };
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
        assert!(!stat_has_no_user_executable(task_stat(1, "S", 0, 1).as_bytes(), 1));
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
            assert!(!fixture.scan_executables(&NativeProc, Limits::default()).complete);
        }
        fs::write(process.join("stat"), task_stat(1, "Z", 0, 1)).unwrap();
        let mut access = Faults::default();
        access.reads.insert(process.join("stat"), libc::EACCES);
        assert!(!fixture.scan_executables(&access, Limits::default()).complete);
    }

    #[test]
    fn optional_name_failures_and_non_utf8_names_preserve_the_executable() {
        let fixture = Fixture::new();
        let target = fixture.exe(1);
        let comm = fixture.proc_root.join("1/comm");
        for raw in [Vec::new(), vec![b'x'; MAX_EXECUTABLE_COMM_BYTES + 1], b"worker-\xff\n".to_vec()] {
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
        let target = fixture.root.join(OsString::from_vec(b"program-\xff".to_vec()));
        fs::write(&target, b"byte-named program").unwrap();
        symlink(&target, process.join("exe")).unwrap();
        let alias = fixture.proc_root.join("artifact-alias");
        symlink(&fixture.root, &alias).unwrap();
        let result = executables_with(&NativeProc, &fixture.proc_root, &alias, Limits::default()).unwrap();
        assert!(result.complete);
        assert_eq!(result.processes.len(), 1);
        assert_eq!(result.processes[0].executable.as_ref(), Some(&target));
        assert_eq!(fs::read(target).unwrap(), b"byte-named program");
    }

    #[test]
    fn executable_discovery_distinguishes_exact_pid_and_entry_limits_from_truncation() {
        let fixture = Fixture::new();
        for pid in 1..=3 { fixture.exe(pid); }
        for limit in 0..=4 {
            for limits in [
                Limits { pids: limit, ..Limits::default() },
                Limits { proc_entries: limit, ..Limits::default() },
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
        for pid in 1..=3 { fixture.exe(pid); }
        let access = Faults {
            advance_per_read: Duration::from_secs(2),
            ..Faults::default()
        };
        let result = fixture.scan_executables(&access, Limits { time: Duration::from_secs(2), ..Limits::default() });
        assert!(!result.complete);
        assert_eq!(result.processes.len(), 1);
        assert_eq!(access.link_calls.get(), 1);
        assert_eq!(access.read_paths.borrow().len(), 1);
        let slow_link = Faults {
            advance_per_link: Duration::from_secs(3),
            ..Faults::default()
        };
        let result = fixture.scan_executables(&slow_link, Limits { time: Duration::from_secs(2), ..Limits::default() });
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
        sweep.executable(Path::new(PROC_ROOT), pid, &executable, &mut processes);
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
        let access = Faults { entry_error: Some(fixture.proc_root.clone()), ..Faults::default() };
        let result = fixture.scan_executables(&access, Limits::default());
        assert!(!result.complete);
        assert_eq!(result.processes[0].executable.as_ref(), Some(&target));
        let mut denied = Faults::default();
        denied.dirs.insert(fixture.proc_root.clone(), libc::EACCES);
        assert!(executables_with(&denied, &fixture.proc_root, &fixture.root, Limits::default()).is_err());
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
        let result = executables_with(&access, &fixture.proc_root, &target, Limits::default()).unwrap();
        assert!(result.complete);
        assert_eq!(result.processes.len(), 1);
        assert_eq!(result.processes[0].executable.as_ref(), Some(&target));
        assert_eq!(*access.read_paths.borrow(), vec![fixture.proc_root.join("1/comm")]);
    }

    #[test]
    fn nonregular_optional_metadata_cannot_block_or_discard_a_running_program() {
        let fixture = Fixture::new();
        let target = fixture.exe(1);
        let comm = fixture.proc_root.join("1/comm");
        nix::unistd::mkfifo(&comm, nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR).unwrap();
        let result = fixture.scan_executables(&NativeProc, Limits::default());
        assert!(result.complete);
        assert_eq!(result.processes[0].executable.as_ref(), Some(&target));
        assert_eq!(result.processes[0].name, "program-1");
    }
}
