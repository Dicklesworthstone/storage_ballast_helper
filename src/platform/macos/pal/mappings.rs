//! Fresh, bounded file-mapping observations for all candidate roots.
//!
//! The PAL's Vec-returning mapping API has no partial-coverage flag. Any failed
//! or truncated observation must therefore return an error, never a partial Vec
//! which its caller could mistake for a complete inventory. Native termination
//! is an observation, not an atomic VM snapshot or a reservation against exec.

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::{macos_process_path_variants, observed_process_path_under_root, region_protection};
use crate::platform::macos::libproc::{proc_listpids_safe, proc_pidinfo_task_all};
use crate::platform::types::{MappedRegion, OPEN_FILES_MAX_PIDS};

const SCAN_TIME: Duration = Duration::from_secs(12);
const MAX_QUERIES: usize = 262_144;
const MAX_QUERIES_PER_PID: usize = 16_384;
const MAX_REGIONS: usize = 65_536;
const MAX_ROOTS: usize = 4096;
const MAX_PATH_BYTES: usize = 8192;
const MAX_RETAINED_BYTES: usize = 8 * 1024 * 1024;
static PROBE_BUSY: OnceLock<Arc<AtomicBool>> = OnceLock::new();

#[derive(Clone, Copy)]
struct Limits {
    time: Duration,
    pids: usize,
    queries: usize,
    per_pid: usize,
    regions: usize,
    bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            time: SCAN_TIME,
            pids: OPEN_FILES_MAX_PIDS,
            queries: MAX_QUERIES,
            per_pid: MAX_QUERIES_PER_PID,
            regions: MAX_REGIONS,
            bytes: MAX_RETAINED_BYTES,
        }
    }
}

#[derive(Clone)]
struct Region {
    start: u64,
    size: u64,
    path: PathBuf,
    protection: u32,
}

trait ProcessAccess {
    fn pids(&self) -> io::Result<Vec<i32>>;
    fn identity(&self, pid: i32) -> io::Result<(u64, u64)>;
    fn next(&self, pid: i32, address: u64) -> io::Result<Option<Region>>;
    fn now(&self) -> Instant;
}

struct NativeProcesses;

impl ProcessAccess for NativeProcesses {
    fn pids(&self) -> io::Result<Vec<i32>> {
        let pids = proc_listpids_safe()?;
        // An all-process native inventory includes this running observer. In
        // particular, an adapter's zero-byte failure cannot certify emptiness.
        if !pids
            .iter()
            .any(|pid| u32::try_from(*pid).ok() == Some(std::process::id()))
        {
            return Err(io::Error::other(
                "native mapping inventory omitted its observer",
            ));
        }
        Ok(pids)
    }

    fn identity(&self, pid: i32) -> io::Result<(u64, u64)> {
        let info = proc_pidinfo_task_all(pid)?;
        if u32::try_from(pid).ok() != Some(info.pbsd.pbi_pid.0) {
            return Err(invalid("mapping process identity changed"));
        }
        Ok((info.pbsd.pbi_start_tvsec, info.pbsd.pbi_start_tvusec))
    }

    fn next(&self, pid: i32, address: u64) -> io::Result<Option<Region>> {
        let Some(info) = sbh_mach::proc_pid_next_mapped_region(pid, address)? else {
            return Ok(None);
        };
        Ok(Some(Region {
            start: info.prp_prinfo.pri_address,
            size: info.prp_prinfo.pri_size,
            path: info
                .prp_vip
                .path()
                .map_err(|_| invalid("malformed mapping pathname"))?
                .to_path_buf(),
            protection: info.prp_prinfo.pri_protection,
        }))
    }

    fn now(&self) -> Instant {
        Instant::now()
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn exhausted(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn exited(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ESRCH)
}

fn valid_mapping_path(path: &Path) -> bool {
    let bytes = path.as_os_str().as_encoded_bytes();
    path.is_absolute()
        && path.file_name().is_some()
        && bytes.len() <= MAX_PATH_BYTES
        && !bytes.contains(&0)
}

/// Limits count attempted queries, including the terminal query, and are shared
/// across roots. Neither an irrelevant mapping nor a failed call renews them.
#[allow(clippy::too_many_lines)]
fn collect_with(
    access: &impl ProcessAccess,
    roots: &[PathBuf],
    limits: Limits,
) -> io::Result<Vec<MappedRegion>> {
    if roots.is_empty() {
        return Ok(Vec::new());
    }
    if roots.iter().any(|root| !root.is_absolute()) {
        return Err(invalid("mapping roots could not be resolved"));
    }
    let started = access.now();
    let check_time = || {
        if access
            .now()
            .checked_duration_since(started)
            .is_some_and(|age| age < limits.time)
        {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "mapping inspection deadline exhausted",
            ))
        }
    };
    check_time()?;
    let pids = access.pids()?;
    let mut visited = BTreeSet::new();
    let mut regions = Vec::new();
    let mut queries = 0_usize;
    let mut bytes = 0_usize;
    for (seen, pid) in pids.into_iter().enumerate() {
        check_time()?;
        if seen >= limits.pids {
            return Err(exhausted("mapping process budget exhausted"));
        }
        if pid == 0 || !visited.insert(pid) {
            continue;
        }
        if pid < 0 {
            return Err(invalid("mapping inventory contained an invalid process id"));
        }
        let before = match access.identity(pid) {
            Ok(identity) => identity,
            Err(error) if exited(&error) => continue,
            Err(error) => return Err(error),
        };
        let first = regions.len();
        let bytes_before = bytes;
        let mut address = 0;
        let mut per_pid = 0;
        let mut gone = false;
        loop {
            check_time()?;
            if queries >= limits.queries || per_pid >= limits.per_pid {
                return Err(exhausted(
                    "mapping query budget exhausted before termination",
                ));
            }
            queries += 1;
            per_pid += 1;
            let region = match access.next(pid, address) {
                Ok(Some(region)) => region,
                Ok(None) => break,
                Err(error) if exited(&error) => {
                    gone = true;
                    break;
                }
                Err(error) => return Err(error),
            };
            let end = region
                .start
                .checked_add(region.size)
                .filter(|end| region.size > 0 && region.start >= address && *end > address)
                .ok_or_else(|| {
                    invalid("mapping range overflowed, overlapped or failed to advance")
                })?;
            if !valid_mapping_path(&region.path) {
                return Err(invalid("mapping pathname was unavailable or malformed"));
            }
            // Validate all records, including those outside the requested roots.
            if let Some(path) = observed_process_path_under_root(&region.path, roots) {
                let needed = path.as_os_str().as_encoded_bytes().len().saturating_add(3);
                if regions.len() >= limits.regions || needed > limits.bytes.saturating_sub(bytes) {
                    return Err(exhausted("mapping result budget exhausted"));
                }
                bytes += needed;
                regions.push(MappedRegion {
                    pid,
                    path,
                    start_address: Some(region.start),
                    end_address: Some(end),
                    protection: Some(region_protection(region.protection)),
                });
            }
            address = end;
        }
        check_time()?;
        if !gone {
            match access.identity(pid) {
                Ok(after) if after == before => {}
                Err(error) if exited(&error) => gone = true,
                Err(error) => return Err(error),
                Ok(_) => return Err(invalid("process changed during mapping inspection")),
            }
        }
        if gone {
            // Do not attribute a dead process's earlier records to a reused PID.
            regions.truncate(first);
            bytes = bytes_before;
        }
    }
    regions.sort_by(|left, right| {
        left.pid
            .cmp(&right.pid)
            .then_with(|| left.start_address.cmp(&right.start_address))
            .then_with(|| left.path.cmp(&right.path))
    });
    // Include empty inventories, the final native call and result ordering.
    check_time()?;
    Ok(regions)
}

struct Admission(Arc<AtomicBool>);

impl Admission {
    fn acquire(busy: Arc<AtomicBool>) -> io::Result<Self> {
        busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "mapping inspection already in progress",
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
    receiver: mpsc::Receiver<io::Result<Vec<MappedRegion>>>,
    worker: JoinHandle<()>,
}

impl Probe {
    fn start(
        admission: Admission,
        inspect: impl FnOnce() -> io::Result<Vec<MappedRegion>> + Send + 'static,
    ) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("sbh-macos-mappings".to_owned())
            .spawn(move || {
                let result = inspect();
                drop(admission);
                let _ = sender.send(result);
            })?;
        Ok(Self { receiver, worker })
    }

    fn wait(&self, timeout: Duration) -> io::Result<Vec<MappedRegion>> {
        self.receiver
            .recv_timeout(timeout)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => io::Error::new(
                    io::ErrorKind::TimedOut,
                    "mapping worker exceeded caller wait budget",
                ),
                mpsc::RecvTimeoutError::Disconnected => {
                    io::Error::other("mapping worker stopped without a result")
                }
            })?
    }
}

fn check_root_budget(roots: &[PathBuf]) -> io::Result<()> {
    if roots.len() > MAX_ROOTS
        || roots
            .iter()
            .try_fold(0_usize, |bytes, root| {
                bytes
                    .checked_add(root.as_os_str().as_encoded_bytes().len())
                    .filter(|total| *total <= MAX_RETAINED_BYTES)
            })
            .is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mapping root inventory is too large",
        ));
    }
    Ok(())
}

pub(super) fn collect(roots: &[PathBuf]) -> io::Result<Vec<MappedRegion>> {
    if roots.is_empty() {
        return Ok(Vec::new());
    }
    check_root_budget(roots)?;
    let busy = PROBE_BUSY.get_or_init(|| Arc::new(AtomicBool::new(false)));
    let admission = Admission::acquire(Arc::clone(busy))?;
    let roots = roots.to_vec();
    let probe = Probe::start(admission, move || {
        // getcwd and native enumeration belong to the admitted worker too.
        let mut variants: Vec<_> = roots
            .iter()
            .flat_map(|root| macos_process_path_variants(root))
            .collect();
        variants.sort();
        variants.dedup();
        collect_with(&NativeProcesses, &variants, Limits::default())
    })?;
    let result = probe.wait(SCAN_TIME.saturating_add(Duration::from_millis(250)));
    // A timed-out native call is not cancelled or joined. Its worker retains
    // admission until completion/unwind; late results use only its own channel.
    // The adapter's temporary PID buffer is outside the retained-result limits.
    drop(probe.worker);
    result
}

#[cfg(test)]
pub(super) fn collect_pid(pid: i32, roots: &[PathBuf]) -> io::Result<Vec<MappedRegion>> {
    struct OneProcess(i32);
    impl ProcessAccess for OneProcess {
        fn pids(&self) -> io::Result<Vec<i32>> {
            Ok(vec![self.0])
        }
        fn identity(&self, pid: i32) -> io::Result<(u64, u64)> {
            NativeProcesses.identity(pid)
        }
        fn next(&self, pid: i32, address: u64) -> io::Result<Option<Region>> {
            NativeProcesses.next(pid, address)
        }
        fn now(&self) -> Instant {
            Instant::now()
        }
    }
    collect_with(&OneProcess(pid), roots, Limits::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    struct Fixture {
        pids: Vec<i32>,
        rows: BTreeMap<(i32, u64), Region>,
        fault: Option<(i32, &'static str, usize, i32)>,
        changed: Option<i32>,
        calls: RefCell<Vec<(i32, &'static str)>>,
        now: Cell<Instant>,
        step: Duration,
        discovery_time: Duration,
    }

    impl Default for Fixture {
        fn default() -> Self {
            Self {
                pids: vec![41, 42],
                rows: BTreeMap::from([
                    ((41, 0), row("/scan/one/object", 4096)),
                    ((42, 0), row("/scan/two/object", 8192)),
                ]),
                fault: None,
                changed: None,
                calls: RefCell::new(Vec::new()),
                now: Cell::new(Instant::now()),
                step: Duration::ZERO,
                discovery_time: Duration::ZERO,
            }
        }
    }

    fn row(path: &str, start: u64) -> Region {
        Region {
            start,
            size: 4096,
            path: path.into(),
            protection: 5,
        }
    }

    impl Fixture {
        fn record(&self, pid: i32, field: &'static str) -> io::Result<usize> {
            self.calls.borrow_mut().push((pid, field));
            self.now.set(self.now.get() + self.step);
            let nth = self
                .calls
                .borrow()
                .iter()
                .filter(|entry| **entry == (pid, field))
                .count();
            if let Some((target, name, attempt, code)) = self.fault
                && pid == target
                && field == name
                && nth == attempt
            {
                return Err(io::Error::from_raw_os_error(code));
            }
            Ok(nth)
        }

        fn scan(&self, limits: Limits) -> io::Result<Vec<MappedRegion>> {
            collect_with(self, &[PathBuf::from("/scan")], limits)
        }
    }

    impl ProcessAccess for Fixture {
        fn pids(&self) -> io::Result<Vec<i32>> {
            self.record(0, "pids")?;
            self.now.set(self.now.get() + self.discovery_time);
            Ok(self.pids.clone())
        }
        fn identity(&self, pid: i32) -> io::Result<(u64, u64)> {
            let nth = self.record(pid, "identity")?;
            Ok((100 + u64::from(self.changed == Some(pid) && nth > 1), 0))
        }
        fn next(&self, pid: i32, address: u64) -> io::Result<Option<Region>> {
            self.record(pid, "region")?;
            Ok(self.rows.get(&(pid, address)).cloned())
        }
        fn now(&self) -> Instant {
            self.now.get()
        }
    }

    #[test]
    fn one_sweep_serves_every_root_without_duplicate_mapping_records() {
        let fixture = Fixture::default();
        let found = collect_with(
            &fixture,
            &["/scan".into(), "/scan/one".into()],
            Limits::default(),
        )
        .unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].pid, 41);
        assert_eq!(found[0].start_address, Some(4096));
        assert_eq!(found[0].end_address, Some(8192));
        assert_eq!(found[0].protection.as_deref(), Some("r-x"));
        assert_eq!(
            fixture
                .calls
                .borrow()
                .iter()
                .filter(|call| **call == (0, "pids"))
                .count(),
            1
        );
    }

    #[test]
    fn read_failures_never_return_a_partial_vector_as_complete() {
        for (pid, field, nth) in [
            (0, "pids", 1),
            (41, "identity", 1),
            (41, "region", 2),
            (42, "identity", 2),
        ] {
            for code in [
                libc::EACCES,
                libc::EPERM,
                libc::EIO,
                libc::ENOENT,
                libc::EINVAL,
            ] {
                let fixture = Fixture {
                    fault: Some((pid, field, nth, code)),
                    ..Fixture::default()
                };
                assert_eq!(
                    fixture.scan(Limits::default()).unwrap_err().raw_os_error(),
                    Some(code)
                );
            }
        }
    }

    #[test]
    fn process_exit_discards_only_that_process_after_earlier_regions() {
        for (field, nth) in [("identity", 1), ("region", 2), ("identity", 2)] {
            let fixture = Fixture {
                fault: Some((41, field, nth, libc::ESRCH)),
                ..Fixture::default()
            };
            let found = fixture.scan(Limits::default()).unwrap();
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].pid, 42);
        }
    }

    #[test]
    fn changed_identity_is_not_a_complete_mapping_observation() {
        let fixture = Fixture {
            changed: Some(41),
            ..Fixture::default()
        };
        assert_eq!(
            fixture.scan(Limits::default()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn malformed_ranges_fail_even_when_the_path_is_outside_the_scope() {
        for (start, size) in [(0, 0), (u64::MAX, 1), (8191, 1)] {
            let mut fixture = Fixture::default();
            fixture.rows.insert(
                (41, 8192),
                Region {
                    start,
                    size,
                    path: "/outside/file".into(),
                    protection: 0,
                },
            );
            assert_eq!(
                fixture.scan(Limits::default()).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn missing_relative_overlong_and_nul_paths_are_not_negative_evidence() {
        for path in [
            PathBuf::new(),
            PathBuf::from("relative"),
            PathBuf::from("/"),
            PathBuf::from(format!("/{}", "x".repeat(MAX_PATH_BYTES))),
            PathBuf::from("/nul\0name"),
        ] {
            let mut fixture = Fixture::default();
            fixture.rows.get_mut(&(41, 0)).unwrap().path = path;
            assert_eq!(
                fixture.scan(Limits::default()).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn terminal_queries_share_the_exact_global_and_per_process_budgets() {
        let mut fixture = Fixture::default();
        assert_eq!(
            fixture
                .scan(Limits {
                    queries: 4,
                    per_pid: 2,
                    pids: 2,
                    ..Limits::default()
                })
                .unwrap()
                .len(),
            2
        );
        for limits in [
            Limits {
                queries: 3,
                ..Limits::default()
            },
            Limits {
                per_pid: 1,
                ..Limits::default()
            },
            Limits {
                pids: 1,
                ..Limits::default()
            },
        ] {
            assert!(fixture.scan(limits).is_err());
        }
        fixture.rows.get_mut(&(41, 0)).unwrap().path = "/unrelated/object".into();
        assert!(
            fixture
                .scan(Limits {
                    queries: 3,
                    ..Limits::default()
                })
                .is_err(),
            "irrelevant records consume query work"
        );
    }

    #[test]
    fn record_and_string_limits_reject_truncation_not_exact_fits() {
        let fixture = Fixture::default();
        let bytes = "/scan/one/object".len() + "/scan/two/object".len() + 6;
        assert_eq!(
            fixture
                .scan(Limits {
                    regions: 2,
                    bytes,
                    ..Limits::default()
                })
                .unwrap()
                .len(),
            2
        );
        assert!(
            fixture
                .scan(Limits {
                    regions: 1,
                    ..Limits::default()
                })
                .is_err()
        );
        assert!(
            fixture
                .scan(Limits {
                    bytes: bytes - 1,
                    ..Limits::default()
                })
                .is_err()
        );
    }

    #[test]
    fn discovery_and_late_final_identity_reads_cannot_renew_the_deadline() {
        let fixture = Fixture {
            pids: Vec::new(),
            discovery_time: Duration::from_secs(1),
            ..Fixture::default()
        };
        assert_eq!(
            fixture
                .scan(Limits {
                    time: Duration::from_secs(1),
                    ..Limits::default()
                })
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        let fixture = Fixture {
            pids: vec![41],
            step: Duration::from_secs(1),
            ..Fixture::default()
        };
        assert_eq!(
            fixture
                .scan(Limits {
                    time: Duration::from_secs(5),
                    ..Limits::default()
                })
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            fixture
                .calls
                .borrow()
                .iter()
                .filter(|call| **call == (41, "identity"))
                .count(),
            2
        );
    }

    #[test]
    fn empty_scopes_skip_native_work_and_duplicate_pids_do_not_repeat_queries() {
        let fixture = Fixture {
            pids: vec![0, 41, 41],
            ..Fixture::default()
        };
        assert!(
            collect_with(&fixture, &[], Limits::default())
                .unwrap()
                .is_empty()
        );
        assert!(fixture.calls.borrow().is_empty());
        assert_eq!(fixture.scan(Limits::default()).unwrap().len(), 1);
        assert_eq!(
            fixture
                .calls
                .borrow()
                .iter()
                .filter(|call| **call == (41, "region"))
                .count(),
            2
        );
        let fixture = Fixture {
            pids: vec![-1],
            ..Fixture::default()
        };
        assert!(fixture.scan(Limits::default()).is_err());
    }

    #[test]
    fn native_byte_paths_and_private_aliases_survive_projection() {
        let mut fixture = Fixture {
            pids: vec![41],
            ..Fixture::default()
        };
        let path = PathBuf::from(OsString::from_vec(
            b"/private/tmp/active/object-\xff".to_vec(),
        ));
        fixture.rows.get_mut(&(41, 0)).unwrap().path = path.clone();
        let found = collect_with(&fixture, &["/tmp/active".into()], Limits::default()).unwrap();
        assert_eq!(found[0].path, path);
        assert!(
            collect_with(&fixture, &["/tmp/active-other".into()], Limits::default())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_fresh_scan_observes_new_mappings_instead_of_cached_absence() {
        let mut fixture = Fixture::default();
        fixture.rows.clear();
        assert!(fixture.scan(Limits::default()).unwrap().is_empty());
        fixture.rows.insert((41, 0), row("/scan/new", 4096));
        let found = fixture.scan(Limits::default()).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, Path::new("/scan/new"));
    }

    #[test]
    fn root_inventory_is_bounded_before_copying_or_starting_native_work() {
        assert!(check_root_budget(&vec![PathBuf::from("/scan"); MAX_ROOTS]).is_ok());
        assert!(check_root_budget(&vec![PathBuf::from("/scan"); MAX_ROOTS + 1]).is_err());
        let path = PathBuf::from("x".repeat(4096));
        assert!(check_root_budget(&vec![path.clone(); MAX_RETAINED_BYTES / 4096]).is_ok());
        assert!(check_root_budget(&vec![path; MAX_RETAINED_BYTES / 4096 + 1]).is_err());
    }

    #[test]
    fn timed_out_worker_keeps_admission_and_cannot_publish_into_a_later_request() {
        let busy = Arc::new(AtomicBool::new(false));
        let (release, released) = mpsc::sync_channel(1);
        let probe = Probe::start(Admission::acquire(Arc::clone(&busy)).unwrap(), move || {
            released.recv().unwrap();
            Err(io::ErrorKind::PermissionDenied.into())
        })
        .unwrap();
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
        let fresh = Probe::start(Admission::acquire(busy).unwrap(), || Ok(Vec::new())).unwrap();
        assert!(fresh.wait(Duration::from_secs(5)).unwrap().is_empty());
        fresh.worker.join().unwrap();
        assert_eq!(
            probe.receiver.try_recv().unwrap().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn abandoned_receivers_and_unwinding_do_not_leak_or_early_release_admission() {
        let busy = Arc::new(AtomicBool::new(false));
        let (release, released) = mpsc::sync_channel(1);
        let probe = Probe::start(Admission::acquire(Arc::clone(&busy)).unwrap(), move || {
            released.recv().unwrap();
            Ok(Vec::new())
        })
        .unwrap();
        drop(probe.receiver);
        assert!(Admission::acquire(Arc::clone(&busy)).is_err());
        release.send(()).unwrap();
        probe.worker.join().unwrap();
        let panics = Probe::start(Admission::acquire(Arc::clone(&busy)).unwrap(), || {
            panic!("injected mapping failure");
        })
        .unwrap();
        assert!(panics.worker.join().is_err());
        assert!(
            panics
                .receiver
                .recv_timeout(Duration::from_secs(5))
                .is_err()
        );
        assert!(Admission::acquire(busy).is_ok());
    }
}
