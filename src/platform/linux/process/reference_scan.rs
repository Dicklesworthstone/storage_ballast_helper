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
use crate::platform::types::{OpenFile, OpenFilesResult};

const MAX_DESCRIPTORS: usize = 262_144;
const MAX_DESCRIPTORS_PER_PID: usize = 16_384;
const MAX_PROC_ENTRIES: usize = OPEN_FILES_MAX_PIDS + 4096;

type Entries = Box<dyn Iterator<Item = io::Result<OsString>>>;

/// The small syscall seam permits deterministic access errors and elapsed-time
/// tests even when the test runner is root. Production uses the real procfs.
trait ProcAccess {
    fn entries(&self, path: &Path) -> io::Result<Entries>;
    fn link(&self, path: &Path) -> io::Result<PathBuf>;
    fn process_gone(&self, path: &Path) -> bool;
    fn now(&self) -> Instant;
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
            let path = resolve_absolute_path(&target);
            if path.starts_with(root) {
                out.push(OpenFile {
                    pid,
                    path,
                    fd: Some(fd),
                    kind: open_file_kind_for_fd(&fd_path),
                    mode: open_file_mode_for_fd(&process, fd),
                });
            }
            if self.expired() {
                break;
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
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
    }

    /// All successful operations are actual fixture syscalls. Only named
    /// errors or elapsed time are injected, so root cannot mask EACCES tests.
    struct Faults {
        dirs: BTreeMap<PathBuf, i32>,
        links: BTreeMap<PathBuf, i32>,
        entry_error: Option<PathBuf>,
        absent_pid: Option<i32>,
        now: Cell<Instant>,
        advance_per_link: Duration,
        link_calls: Cell<usize>,
    }

    impl Default for Faults {
        fn default() -> Self {
            Self {
                dirs: BTreeMap::new(),
                links: BTreeMap::new(),
                entry_error: None,
                absent_pid: None,
                now: Cell::new(Instant::now()),
                advance_per_link: Duration::ZERO,
                link_calls: Cell::new(0),
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
}
