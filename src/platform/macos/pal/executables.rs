//! Bounded executable-path observations shared by single- and multi-root queries.
//!
//! A successful pathname lookup is positive evidence even when optional task
//! statistics cannot be read. Never fetch argv, cwd or resource counters here.
//! Failed lookups revoke coverage; they are not proof of an idle candidate.
//! Two native errors are not failures: ESRCH (the process exited) and ENOENT
//! (its executable was unlinked, so it lies under no root).
//! This is a fresh observation of visible PIDs, not an atomic exec snapshot.

use std::collections::BTreeSet;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::{macos_process_path_variants, observed_process_path_under_root};
use crate::platform::macos::libproc::{proc_listpids_safe, proc_pidpath_safe};
use crate::platform::types::{
    ExecutablesResult, OPEN_FILES_MAX_PIDS, OPEN_FILES_SCAN_BUDGET, ProcessInfo,
};

const MAX_PATH_BYTES: usize = 8192;
const MAX_RETAINED_BYTES: usize = 8 * 1024 * 1024;
static PROBE_BUSY: OnceLock<Arc<AtomicBool>> = OnceLock::new();

#[derive(Clone, Copy)]
struct Limits {
    time: Duration,
    pids: usize,
    bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            time: OPEN_FILES_SCAN_BUDGET,
            pids: OPEN_FILES_MAX_PIDS,
            bytes: MAX_RETAINED_BYTES,
        }
    }
}

trait ProcessAccess {
    fn pids(&self) -> io::Result<Vec<i32>>;
    fn executable(&self, pid: i32) -> io::Result<PathBuf>;
    fn now(&self) -> Instant;
}

struct NativeProcesses;

impl ProcessAccess for NativeProcesses {
    fn pids(&self) -> io::Result<Vec<i32>> {
        proc_listpids_safe()
    }

    fn executable(&self, pid: i32) -> io::Result<PathBuf> {
        proc_pidpath_safe(pid)
    }

    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// One admission permit remains with the native worker, not its waiter. A
/// timed-out lookup can never cause later callers to accumulate stuck threads.
struct Admission(Arc<AtomicBool>);

impl Admission {
    fn acquire(busy: Arc<AtomicBool>) -> io::Result<Self> {
        busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "macOS executable inspection is already in progress",
                )
            })?;
        Ok(Self(busy))
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct Probe {
    receiver: mpsc::Receiver<io::Result<ExecutablesResult>>,
    worker: JoinHandle<()>,
}

impl Probe {
    fn start(
        admission: Admission,
        inspect: impl FnOnce() -> io::Result<ExecutablesResult> + Send + 'static,
    ) -> io::Result<Self> {
        // Each request owns its result channel. There is no shared mailbox or
        // cached result which a late lookup could deliver to another scope.
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("sbh-macos-executables".to_owned())
            .spawn(move || {
                let result = inspect();
                drop(admission);
                let _ = sender.send(result);
            })?;
        Ok(Self { receiver, worker })
    }

    fn wait(&self, timeout: Duration) -> io::Result<ExecutablesResult> {
        self.receiver
            .recv_timeout(timeout)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => io::Error::new(
                    io::ErrorKind::TimedOut,
                    "macOS executable inspection exceeded its caller wait budget",
                ),
                mpsc::RecvTimeoutError::Disconnected => {
                    io::Error::other("macOS executable worker stopped without a result")
                }
            })?
    }
}

pub(super) fn collect(roots: &[PathBuf]) -> io::Result<ExecutablesResult> {
    if roots.is_empty() {
        return Ok(ExecutablesResult {
            processes: Vec::new(),
            complete: true,
        });
    }
    let busy = PROBE_BUSY.get_or_init(|| Arc::new(AtomicBool::new(false)));
    // Acquire before copying root data or starting any native work.
    let admission = Admission::acquire(Arc::clone(busy))?;
    let roots = roots.to_vec();
    let probe = Probe::start(admission, move || {
        // Even relative-root resolution belongs in the worker. A blocked
        // getcwd must not defeat the caller's receive timeout.
        let mut variants: Vec<_> = roots
            .iter()
            .flat_map(|root| macos_process_path_variants(root))
            .collect();
        variants.sort();
        variants.dedup();
        collect_with(&NativeProcesses, &variants, Limits::default())
    })?;
    let result = probe.wait(OPEN_FILES_SCAN_BUDGET.saturating_add(Duration::from_millis(250)));
    // Never join a timed-out native call. Its permit remains held until it
    // finishes; subsequent callers receive incomplete evidence via an error.
    drop(probe.worker);
    result
}

/// Inspect each visible PID once, regardless of the number of candidate roots.
/// Limits cover attempted lookups and retained strings, not the native adapter's
/// temporary PID buffer or the duration of an individual blocked kernel call.
fn collect_with(
    access: &impl ProcessAccess,
    roots: &[PathBuf],
    limits: Limits,
) -> io::Result<ExecutablesResult> {
    let mut result = ExecutablesResult {
        processes: Vec::new(),
        complete: true,
    };
    if roots.is_empty() {
        return Ok(result);
    }
    if roots.iter().any(|root| !root.is_absolute()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "executable query roots could not be resolved",
        ));
    }
    let started = access.now();
    let in_budget = || {
        access
            .now()
            .checked_duration_since(started)
            .is_some_and(|elapsed| elapsed < limits.time)
    };
    if !in_budget() {
        result.complete = false;
        return Ok(result);
    }
    let pids = access.pids()?;
    let mut visited = BTreeSet::new();
    let mut retained_bytes = 0_usize;
    for (seen, pid) in pids.into_iter().enumerate() {
        if seen >= limits.pids || !in_budget() {
            result.complete = false;
            break;
        }
        // PID zero denotes the kernel, not a user executable. Duplicate PIDs
        // consume discovery work but never repeat the syscall or attribution.
        if pid == 0 || !visited.insert(pid) {
            continue;
        }
        if pid < 0 {
            result.complete = false;
            continue;
        }
        let executable = match access.executable(pid) {
            Ok(path) => path,
            // ESRCH is the native exited-process signal. A native ENOENT is a
            // process whose executable was unlinked after it started (a tool
            // that updated itself in place): that file is in no directory, so
            // no candidate root can hold it. On one Mac, 10 of 1,670 processes
            // were such (agent CLIs on a deleted version); counting them as
            // unknown left coverage incomplete on every pass, so nothing was
            // ever deleted there. EACCES, EPERM, EIO, an ENOENT without a
            // native errno and malformed path data remain unknown use.
            Err(error) if matches!(error.raw_os_error(), Some(libc::ESRCH | libc::ENOENT)) => {
                continue;
            }
            Err(_) => {
                result.complete = false;
                continue;
            }
        };
        if !executable.is_absolute()
            || executable.file_name().is_none()
            || executable.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES
        {
            result.complete = false;
            continue;
        }
        let Some(path) = observed_process_path_under_root(&executable, roots) else {
            continue;
        };
        let process = executable_reference(pid, path);
        let bytes = process
            .executable
            .as_ref()
            .map_or(0, |path| path.as_os_str().as_encoded_bytes().len())
            .saturating_add(process.name.len());
        if bytes > limits.bytes.saturating_sub(retained_bytes) {
            result.complete = false;
            break;
        }
        retained_bytes += bytes;
        // A final lookup that completes late still supplies positive evidence.
        // The shared deadline below revokes coverage without losing that path.
        result.processes.push(process);
    }
    result.processes.sort_by_key(|process| process.pid);
    result.complete &= in_budget();
    Ok(result)
}

fn executable_reference(pid: i32, path: PathBuf) -> ProcessInfo {
    // This display name belongs to the observed executable, not a second
    // process lookup which could now describe a reused PID. Optional identity
    // and resource annotations are deliberately absent rather than invented.
    let name = path.file_name().map_or_else(
        || format!("pid-{pid}"),
        |name| name.to_string_lossy().into_owned(),
    );
    ProcessInfo {
        pid,
        parent_pid: None,
        name,
        command_line: Vec::new(),
        executable: Some(path),
        cwd: None,
        start_time_unix_ms: None,
        virtual_memory_bytes: None,
        resident_memory_bytes: None,
        cpu_user_micros: None,
        cpu_system_micros: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::path::Path;

    struct Fixture {
        pids: Vec<i32>,
        paths: BTreeMap<i32, PathBuf>,
        failures: BTreeMap<i32, i32>,
        discovery_error: bool,
        discovery_time: Duration,
        lookup_time: Duration,
        now: Cell<Instant>,
        calls: RefCell<Vec<i32>>,
        discoveries: Cell<usize>,
    }

    impl Default for Fixture {
        fn default() -> Self {
            Self {
                pids: vec![42, 41],
                paths: BTreeMap::from([
                    (41, PathBuf::from("/scan/one/program")),
                    (42, PathBuf::from("/scan/two/program")),
                ]),
                failures: BTreeMap::new(),
                discovery_error: false,
                discovery_time: Duration::ZERO,
                lookup_time: Duration::ZERO,
                now: Cell::new(Instant::now()),
                calls: RefCell::new(Vec::new()),
                discoveries: Cell::new(0),
            }
        }
    }

    impl ProcessAccess for Fixture {
        fn pids(&self) -> io::Result<Vec<i32>> {
            self.discoveries.set(self.discoveries.get() + 1);
            self.now.set(self.now.get() + self.discovery_time);
            if self.discovery_error {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            Ok(self.pids.clone())
        }

        fn executable(&self, pid: i32) -> io::Result<PathBuf> {
            self.calls.borrow_mut().push(pid);
            self.now.set(self.now.get() + self.lookup_time);
            if let Some(code) = self.failures.get(&pid) {
                return Err(io::Error::from_raw_os_error(*code));
            }
            Ok(self.paths[&pid].clone())
        }

        fn now(&self) -> Instant {
            self.now.get()
        }
    }

    fn scan(fixture: &Fixture, limits: Limits) -> ExecutablesResult {
        collect_with(fixture, &[PathBuf::from("/scan")], limits).unwrap()
    }

    #[test]
    fn one_sweep_serves_all_roots_and_deduplicates_overlapping_scopes() {
        let fixture = Fixture::default();
        let result = collect_with(
            &fixture,
            &["/scan/one".into(), "/scan/two".into(), "/scan".into()],
            Limits::default(),
        )
        .unwrap();
        assert!(result.complete);
        assert_eq!(
            result.processes.iter().map(|p| p.pid).collect::<Vec<_>>(),
            vec![41, 42]
        );
        assert_eq!(*fixture.calls.borrow(), vec![42, 41]);
        assert_eq!(fixture.discoveries.get(), 1);
        assert!(
            result
                .processes
                .iter()
                .all(|p| p.command_line.is_empty() && p.cwd.is_none())
        );
    }

    #[test]
    fn denied_or_failed_lookup_keeps_other_positives_and_revokes_coverage() {
        for code in [libc::EACCES, libc::EPERM, libc::EIO, libc::EINVAL] {
            let mut fixture = Fixture::default();
            fixture.failures.insert(42, code);
            let result = scan(&fixture, Limits::default());
            assert!(!result.complete, "errno {code}");
            assert_eq!(result.processes.len(), 1);
            assert_eq!(result.processes[0].pid, 41);
            assert_eq!(
                result.processes[0].executable.as_deref(),
                Some(Path::new("/scan/one/program"))
            );
        }
    }

    #[test]
    fn exited_pid_is_distinct_from_an_unreadable_process() {
        // ESRCH: the process exited. ENOENT: its executable was unlinked, so
        // no root holds it. Neither is unknown use.
        for code in [libc::ESRCH, libc::ENOENT] {
            let mut fixture = Fixture::default();
            fixture.failures.insert(42, code);
            let result = scan(&fixture, Limits::default());
            assert!(result.complete, "errno {code}");
            assert_eq!(result.processes.len(), 1);
            assert_eq!(result.processes[0].pid, 41);
        }
    }

    #[test]
    fn empty_scope_and_failed_discovery_do_not_look_like_the_same_observation() {
        let fixture = Fixture {
            discovery_error: true,
            ..Fixture::default()
        };
        let empty = collect_with(&fixture, &[], Limits::default()).unwrap();
        assert!(empty.complete && empty.processes.is_empty());
        assert_eq!(fixture.discoveries.get(), 0);
        assert!(collect_with(&fixture, &["/scan".into()], Limits::default()).is_err());
        assert!(fixture.calls.borrow().is_empty());
    }

    #[test]
    fn unresolved_query_roots_cannot_certify_absence() {
        let fixture = Fixture::default();
        let result = collect_with(&fixture, &["relative".into()], Limits::default());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fixture.discoveries.get(), 0);
    }

    #[test]
    fn readable_empty_inventory_is_complete_but_late_discovery_is_not() {
        let mut fixture = Fixture {
            pids: Vec::new(),
            ..Fixture::default()
        };
        assert!(scan(&fixture, Limits::default()).complete);
        fixture.discovery_time = Duration::from_secs(2);
        assert!(
            !scan(
                &fixture,
                Limits {
                    time: Duration::from_secs(1),
                    ..Limits::default()
                }
            )
            .complete
        );
        assert!(fixture.calls.borrow().is_empty());
    }

    #[test]
    fn expired_budget_starts_no_native_work_and_progress_cannot_renew_it() {
        let fixture = Fixture::default();
        assert!(
            !scan(
                &fixture,
                Limits {
                    time: Duration::ZERO,
                    ..Limits::default()
                }
            )
            .complete
        );
        assert_eq!(fixture.discoveries.get(), 0);
        let fixture = Fixture {
            lookup_time: Duration::from_secs(2),
            ..Fixture::default()
        };
        let result = scan(
            &fixture,
            Limits {
                time: Duration::from_secs(1),
                ..Limits::default()
            },
        );
        assert!(!result.complete);
        assert_eq!(*fixture.calls.borrow(), vec![42]);
        assert_eq!(
            result.processes.len(),
            1,
            "retain a positive from a late syscall"
        );
    }

    #[test]
    fn late_final_out_of_scope_lookup_still_revokes_coverage() {
        let fixture = Fixture {
            pids: vec![41],
            lookup_time: Duration::from_secs(2),
            ..Fixture::default()
        };
        let result = collect_with(
            &fixture,
            &["/elsewhere".into()],
            Limits {
                time: Duration::from_secs(1),
                ..Limits::default()
            },
        )
        .unwrap();
        assert!(!result.complete);
        assert!(result.processes.is_empty());
    }

    #[test]
    fn exact_pid_limit_is_complete_only_when_discovery_was_exhausted() {
        for limit in 0..=3 {
            let fixture = Fixture::default();
            let result = scan(
                &fixture,
                Limits {
                    pids: limit,
                    ..Limits::default()
                },
            );
            assert_eq!(result.complete, limit >= 2);
            assert_eq!(fixture.calls.borrow().len(), limit.min(2));
            assert_eq!(result.processes.len(), limit.min(2));
        }
    }

    #[test]
    fn retained_byte_limit_counts_names_and_paths_without_discarding_earlier_records() {
        let fixture = Fixture::default();
        let bytes = "/scan/two/program".len() + "program".len();
        let result = scan(
            &fixture,
            Limits {
                bytes,
                ..Limits::default()
            },
        );
        assert!(!result.complete);
        assert_eq!(result.processes.len(), 1);
        assert_eq!(result.processes[0].pid, 42);
        let fixture = Fixture {
            pids: vec![42],
            ..Fixture::default()
        };
        assert!(
            scan(
                &fixture,
                Limits {
                    bytes,
                    ..Limits::default()
                }
            )
            .complete
        );
        assert!(
            !scan(
                &fixture,
                Limits {
                    bytes: bytes - 1,
                    ..Limits::default()
                }
            )
            .complete
        );
    }

    #[test]
    fn malformed_paths_are_not_rebased_and_native_bytes_are_preserved() {
        for path in [
            PathBuf::from("relative"),
            PathBuf::from("/"),
            PathBuf::from(format!("/{}", "x".repeat(MAX_PATH_BYTES))),
        ] {
            let mut fixture = Fixture::default();
            fixture.paths.insert(42, path);
            let result = scan(&fixture, Limits::default());
            assert!(!result.complete);
            assert_eq!(result.processes.len(), 1);
            assert_eq!(result.processes[0].pid, 41);
        }
        let mut fixture = Fixture::default();
        let path = PathBuf::from(OsString::from_vec(b"/scan/program-\xff".to_vec()));
        fixture.paths.insert(42, path.clone());
        let result = scan(&fixture, Limits::default());
        assert!(result.complete);
        assert_eq!(result.processes[1].executable.as_ref(), Some(&path));
    }

    #[test]
    fn duplicate_pids_and_prefix_siblings_do_not_invent_additional_references() {
        let mut fixture = Fixture {
            pids: vec![0, 41, 41, 42],
            ..Fixture::default()
        };
        fixture.paths.insert(42, "/scan-other/program".into());
        let result = scan(&fixture, Limits::default());
        assert!(result.complete);
        assert_eq!(result.processes.len(), 1);
        assert_eq!(*fixture.calls.borrow(), vec![41, 42]);
        fixture.pids.push(-1);
        assert!(!scan(&fixture, Limits::default()).complete);
    }

    #[test]
    fn native_current_pid_is_visible_without_optional_task_annotations() {
        struct CurrentPid;
        impl ProcessAccess for CurrentPid {
            fn pids(&self) -> io::Result<Vec<i32>> {
                Ok(vec![i32::try_from(std::process::id()).unwrap()])
            }
            fn executable(&self, pid: i32) -> io::Result<PathBuf> {
                proc_pidpath_safe(pid)
            }
            fn now(&self) -> Instant {
                Instant::now()
            }
        }
        let expected = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let result = collect_with(&CurrentPid, &[PathBuf::from("/")], Limits::default()).unwrap();
        assert!(result.complete);
        assert_eq!(result.processes.len(), 1);
        assert_eq!(result.processes[0].executable.as_ref(), Some(&expected));
        assert!(result.processes[0].command_line.is_empty());
        assert!(result.processes[0].start_time_unix_ms.is_none());
    }

    #[test]
    fn worker_failure_preserves_the_error_and_releases_admission() {
        let busy = Arc::new(AtomicBool::new(false));
        let admission = Admission::acquire(Arc::clone(&busy)).unwrap();
        let probe =
            Probe::start(admission, || Err(io::ErrorKind::PermissionDenied.into())).unwrap();
        assert_eq!(
            probe.wait(Duration::from_secs(5)).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        probe.worker.join().unwrap();
        assert!(!busy.load(Ordering::Acquire));
        assert!(Admission::acquire(busy).is_ok());
    }

    #[test]
    fn timed_out_worker_keeps_admission_and_its_late_result_cannot_cross_scopes() {
        let busy = Arc::new(AtomicBool::new(false));
        let (started, start) = mpsc::sync_channel(1);
        let (release, released) = mpsc::sync_channel(1);
        let probe = Probe::start(Admission::acquire(Arc::clone(&busy)).unwrap(), move || {
            started.send(()).unwrap();
            released.recv().unwrap();
            Ok(ExecutablesResult {
                processes: vec![executable_reference(41, "/first/program".into())],
                complete: true,
            })
        })
        .unwrap();
        start.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            probe.wait(Duration::ZERO).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            Admission::acquire(Arc::clone(&busy)).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        release.send(()).unwrap();
        probe.worker.join().unwrap();
        assert!(!busy.load(Ordering::Acquire));
        let fresh = Probe::start(Admission::acquire(busy).unwrap(), || {
            Ok(ExecutablesResult {
                processes: vec![executable_reference(42, "/second/program".into())],
                complete: true,
            })
        })
        .unwrap();
        let current = fresh.wait(Duration::from_secs(5)).unwrap();
        fresh.worker.join().unwrap();
        assert_eq!(
            current.processes[0].executable.as_deref(),
            Some(Path::new("/second/program"))
        );
        let late = probe.receiver.try_recv().unwrap().unwrap();
        assert_eq!(
            late.processes[0].executable.as_deref(),
            Some(Path::new("/first/program"))
        );
    }

    #[test]
    fn abandoning_the_receiver_does_not_release_a_running_native_probe() {
        let busy = Arc::new(AtomicBool::new(false));
        let (release, released) = mpsc::sync_channel(1);
        let probe = Probe::start(Admission::acquire(Arc::clone(&busy)).unwrap(), move || {
            released.recv().unwrap();
            Ok(ExecutablesResult {
                processes: Vec::new(),
                complete: true,
            })
        })
        .unwrap();
        drop(probe.receiver);
        assert_eq!(
            Admission::acquire(Arc::clone(&busy)).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        release.send(()).unwrap();
        probe.worker.join().unwrap();
        assert!(!busy.load(Ordering::Acquire));
    }

    #[test]
    fn worker_unwind_releases_admission_without_returning_complete_evidence() {
        let busy = Arc::new(AtomicBool::new(false));
        let probe = Probe::start(Admission::acquire(Arc::clone(&busy)).unwrap(), || {
            panic!("injected executable observer failure");
        })
        .unwrap();
        assert!(probe.worker.join().is_err());
        assert!(probe.receiver.recv_timeout(Duration::from_secs(5)).is_err());
        assert!(!busy.load(Ordering::Acquire));
    }
}
