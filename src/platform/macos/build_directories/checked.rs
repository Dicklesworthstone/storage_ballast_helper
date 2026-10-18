//! Coverage-aware observation of the visible macOS build-process inventory.
//!
//! Positive references and coverage travel together. An unreadable process is
//! not an idle process; a finished observation is not an atomic snapshot or a
//! guarantee of visibility into other users or namespaces. Never log argv/env.

use std::collections::BTreeSet;
use std::io;
use std::path::PathBuf;

use super::{Limits, ProcessAccess};
use crate::platform::build_environment::CacheLayout;
use crate::platform::build_invocation;
use crate::platform::process_arguments::darwin_arguments;

fn gone(error: &io::Error) -> bool {
    // Only the native process-exit errno certifies disappearance. Permission,
    // malformed-record and generic NotFound errors are not absence evidence.
    error.raw_os_error() == Some(libc::ESRCH)
}

#[allow(clippy::too_many_lines)] // one bounded observation with independent positive evidence
pub(super) fn collect_with(
    access: &impl ProcessAccess,
    own: u32,
    limits: Limits,
) -> (Vec<(i32, PathBuf)>, bool) {
    let started = access.now();
    let in_budget = || {
        access
            .now()
            .checked_duration_since(started)
            .is_some_and(|elapsed| elapsed < limits.time)
    };
    if limits.pids == 0 || limits.paths == 0 || limits.bytes == 0 || !in_budget() {
        return (Vec::new(), false);
    }
    let Ok(pids) = access.pids() else {
        return (Vec::new(), false);
    };
    let mut directories = BTreeSet::new();
    let mut path_bytes = 0_usize;
    let mut complete = true;
    'processes: for (seen, pid) in pids.into_iter().enumerate() {
        if seen >= limits.pids || !in_budget() {
            complete = false;
            break;
        }
        if pid <= 0 || u32::try_from(pid).ok() == Some(own) {
            continue;
        }
        let before = match access.identity(pid) {
            Ok(identity) => identity,
            Err(error) => {
                complete &= gone(&error);
                continue;
            }
        };
        if before.pid != pid || before.name.is_empty() {
            complete = false;
            continue;
        }
        let Some(tool) = build_invocation::observed_tool(&before.name) else {
            continue;
        };
        if !in_budget() {
            complete = false;
            break;
        }
        let raw = match access.arguments(pid) {
            Ok(raw) => raw,
            Err(error) => {
                complete &= gone(&error);
                continue;
            }
        };
        if raw.len() > sbh_mach::PROCESS_ARGUMENTS_MAX_BYTES {
            complete = false;
            continue;
        }
        let Some(arguments) = darwin_arguments(&raw) else {
            complete = false;
            continue;
        };
        if !in_budget() {
            complete = false;
            break;
        }
        // Missing cwd revokes coverage, but independently observed absolute
        // destinations remain useful once the process identity is rechecked.
        let cwd = match access.cwd(pid) {
            Ok(cwd) if cwd.is_absolute() => Some(cwd),
            Err(error) if gone(&error) => continue,
            _ => {
                complete = false;
                None
            }
        };
        if !in_budget() {
            complete = false;
            break;
        }
        match access.identity(pid) {
            Ok(after) if after == before => {}
            Err(error) if gone(&error) => continue,
            _ => {
                complete = false;
                continue;
            }
        }
        // The final identity read may itself finish late. Keep its verified
        // positives, but the final deadline check below still revokes coverage.
        for directory in build_invocation::references(
            CacheLayout::MacOs,
            tool,
            arguments.argv,
            arguments.environment,
            cwd.as_deref(),
        ) {
            let key = (pid, directory);
            if directories.contains(&key) {
                continue;
            }
            let bytes = key.1.as_os_str().as_encoded_bytes().len();
            if directories.len() >= limits.paths
                || bytes > limits.bytes.saturating_sub(path_bytes)
            {
                complete = false;
                break 'processes;
            }
            path_bytes += bytes;
            directories.insert(key);
        }
    }
    // Include discovery, failed calls, empty inventories and the last metadata
    // read in the original deadline; successful progress never renews it.
    complete &= in_budget();
    (directories.into_iter().collect(), complete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::ProcessIdentity;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    struct Process {
        name: Vec<u8>,
        raw: Vec<u8>,
        cwd: Option<PathBuf>,
    }

    struct Fixture {
        processes: BTreeMap<i32, Process>,
        fault: Option<(i32, &'static str, usize, i32)>,
        changed: Option<i32>,
        reads: RefCell<Vec<(i32, &'static str)>>,
        now: Cell<Instant>,
        step: Duration,
        discovery_time: Duration,
    }

    impl Default for Fixture {
        fn default() -> Self {
            Self {
                processes: BTreeMap::new(),
                fault: None,
                changed: None,
                reads: RefCell::new(Vec::new()),
                now: Cell::new(Instant::now()),
                step: Duration::ZERO,
                discovery_time: Duration::ZERO,
            }
        }
    }

    impl Fixture {
        fn add(&mut self, pid: i32, name: &str, env: &[u8]) {
            let mut raw = 1_i32.to_ne_bytes().to_vec();
            raw.extend_from_slice(b"/usr/bin/build-tool\0\0");
            raw.extend_from_slice(name.as_bytes());
            raw.push(0);
            raw.extend_from_slice(env);
            self.processes.insert(pid, Process {
                name: name.as_bytes().to_vec(), raw, cwd: Some("/workspace".into()),
            });
        }

        fn read(&self, pid: i32, kind: &'static str) -> io::Result<usize> {
            self.reads.borrow_mut().push((pid, kind));
            self.now.set(self.now.get() + self.step);
            let count = self.reads.borrow().iter().filter(|entry| **entry == (pid, kind)).count();
            if let Some((target, field, nth, code)) = self.fault
                && target == pid && field == kind && (nth == 0 || nth == count)
            {
                return Err(io::Error::from_raw_os_error(code));
            }
            Ok(count)
        }

        fn collect(&self, limits: Limits) -> (Vec<(i32, PathBuf)>, bool) {
            collect_with(self, 99, limits)
        }
    }

    impl ProcessAccess for Fixture {
        fn pids(&self) -> io::Result<Vec<i32>> {
            self.read(0, "pids")?;
            self.now.set(self.now.get() + self.discovery_time);
            Ok(self.processes.keys().copied().collect())
        }
        fn identity(&self, pid: i32) -> io::Result<ProcessIdentity> {
            let count = self.read(pid, "identity")?;
            Ok(ProcessIdentity {
                pid,
                started: (100 + u64::from(self.changed == Some(pid) && count > 1), 0),
                name: self.processes[&pid].name.clone(),
            })
        }
        fn arguments(&self, pid: i32) -> io::Result<Vec<u8>> {
            self.read(pid, "arguments")?;
            Ok(self.processes[&pid].raw.clone())
        }
        fn cwd(&self, pid: i32) -> io::Result<PathBuf> {
            self.read(pid, "cwd")?;
            self.processes[&pid].cwd.clone().ok_or_else(|| io::ErrorKind::PermissionDenied.into())
        }
        fn now(&self) -> Instant { self.now.get() }
    }

    #[test]
    fn empty_readable_inventory_is_distinct_from_failed_discovery() {
        let mut fixture = Fixture::default();
        assert_eq!(fixture.collect(Limits::default()), (Vec::new(), true));
        fixture.fault = Some((0, "pids", 0, libc::EACCES));
        assert_eq!(fixture.collect(Limits::default()), (Vec::new(), false));
    }

    #[test]
    fn metadata_failures_revoke_coverage_without_erasing_other_builders() {
        for (field, nth) in [("identity", 1), ("arguments", 1), ("identity", 2)] {
            for code in [libc::EACCES, libc::EPERM, libc::EIO, libc::ENOENT] {
                let mut fixture = Fixture::default();
                fixture.add(41, "rustc", b"CARGO_TARGET_DIR=/unobserved\0");
                fixture.add(42, "rustc", b"CARGO_TARGET_DIR=/kept\0");
                fixture.fault = Some((41, field, nth, code));
                let (paths, complete) = fixture.collect(Limits::default());
                assert!(!complete, "{field} {nth} {code}");
                assert_eq!(paths, vec![(42, PathBuf::from("/kept"))]);
            }
        }
    }

    #[test]
    fn native_process_exit_is_not_an_inspection_failure() {
        for (field, nth) in [("identity", 1), ("arguments", 1), ("cwd", 1), ("identity", 2)] {
            let mut fixture = Fixture::default();
            fixture.add(41, "rustc", b"CARGO_TARGET_DIR=/exited\0");
            fixture.add(42, "rustc", b"CARGO_TARGET_DIR=/live\0");
            fixture.fault = Some((41, field, nth, libc::ESRCH));
            assert_eq!(fixture.collect(Limits::default()), (vec![(42, PathBuf::from("/live"))], true));
        }
    }

    #[test]
    fn malformed_or_oversized_arguments_are_not_an_empty_complete_observation() {
        for raw in [Vec::new(), vec![0xff; 3], vec![0; sbh_mach::PROCESS_ARGUMENTS_MAX_BYTES + 1]] {
            let mut fixture = Fixture::default();
            fixture.add(41, "rustc", b"CARGO_TARGET_DIR=/bad\0");
            fixture.add(42, "rustc", b"CARGO_TARGET_DIR=/kept\0");
            fixture.processes.get_mut(&41).unwrap().raw = raw;
            assert_eq!(fixture.collect(Limits::default()), (vec![(42, PathBuf::from("/kept"))], false));
        }
    }

    #[test]
    fn missing_or_relative_cwd_keeps_absolute_paths_and_revokes_coverage() {
        for cwd in [None, Some(PathBuf::from("relative"))] {
            let mut fixture = Fixture::default();
            fixture.add(41, "rustc", b"CARGO_TARGET_DIR=../target\0SCCACHE_DIR=/kept\0");
            fixture.processes.get_mut(&41).unwrap().cwd = cwd;
            assert_eq!(fixture.collect(Limits::default()), (vec![(41, PathBuf::from("/kept"))], false));
        }
    }

    #[test]
    fn changed_identity_cannot_certify_absence_or_mix_builders() {
        let mut fixture = Fixture::default();
        fixture.add(41, "rustc", b"CARGO_TARGET_DIR=/mixed\0");
        fixture.changed = Some(41);
        assert_eq!(fixture.collect(Limits::default()), (Vec::new(), false));
    }

    #[test]
    fn discovery_and_last_identity_read_consume_the_original_deadline() {
        let fixture = Fixture { discovery_time: Duration::from_secs(2), ..Fixture::default() };
        let limits = Limits { time: Duration::from_secs(2), ..Limits::default() };
        assert_eq!(fixture.collect(limits), (Vec::new(), false));
        let mut fixture = Fixture { step: Duration::from_secs(1), ..Fixture::default() };
        fixture.add(41, "rustc", b"CARGO_TARGET_DIR=/verified\0");
        let (paths, complete) = fixture.collect(Limits { time: Duration::from_secs(5), ..limits });
        assert_eq!(paths, vec![(41, PathBuf::from("/verified"))]);
        assert!(!complete, "the final identity syscall finished at the deadline");
        assert_eq!(fixture.reads.borrow().len(), 5);
    }

    #[test]
    fn exhausted_budget_does_not_start_another_metadata_call() {
        let mut fixture = Fixture { step: Duration::from_secs(1), ..Fixture::default() };
        fixture.add(41, "rustc", b"CARGO_TARGET_DIR=/unknown\0");
        let result = fixture.collect(Limits { time: Duration::from_secs(3), ..Limits::default() });
        assert_eq!(result, (Vec::new(), false));
        assert_eq!(*fixture.reads.borrow(), vec![(0, "pids"), (41, "identity"), (41, "arguments")]);
    }

    #[test]
    fn exact_pid_and_path_limits_do_not_claim_truncated_discovery_complete() {
        for cap in 1..=3 {
            let mut fixture = Fixture::default();
            fixture.add(41, "rustc", b"CARGO_TARGET_DIR=/a\0");
            fixture.add(42, "rustc", b"CARGO_TARGET_DIR=/b\0");
            let (paths, complete) = fixture.collect(Limits { pids: cap, ..Limits::default() });
            assert_eq!(paths.len(), cap.min(2));
            assert_eq!(complete, cap >= 2);
            let (paths, complete) = fixture.collect(Limits { paths: cap, ..Limits::default() });
            assert_eq!(paths.len(), cap.min(2));
            assert_eq!(complete, cap >= 2);
        }
    }

    #[test]
    fn retained_path_bytes_are_bounded_independently_of_path_count() {
        let mut fixture = Fixture::default();
        fixture.add(41, "rustc", b"CARGO_TARGET_DIR=/one\0SCCACHE_DIR=/two\0");
        for bytes in [3, 4, 7, 8, 9] {
            let (paths, complete) = fixture.collect(Limits { bytes, ..Limits::default() });
            assert!(paths.iter().map(|(_, path)| path.as_os_str().as_encoded_bytes().len()).sum::<usize>() <= bytes);
            assert_eq!(paths.len(), (bytes / 4).min(2));
            assert_eq!(complete, bytes >= 8);
        }
    }

    #[test]
    fn unrelated_and_own_processes_do_not_require_argument_access() {
        let mut fixture = Fixture::default();
        fixture.add(41, "bash", b"CARGO_TARGET_DIR=/unrelated\0");
        fixture.add(99, "rustc", b"CARGO_TARGET_DIR=/own\0");
        fixture.fault = Some((41, "arguments", 0, libc::EACCES));
        assert_eq!(fixture.collect(Limits::default()), (Vec::new(), true));
        assert_eq!(*fixture.reads.borrow(), vec![(0, "pids"), (41, "identity")]);
    }

    #[test]
    fn independent_builders_sharing_a_directory_retain_both_identities() {
        let mut fixture = Fixture::default();
        for pid in [41, 42] {
            fixture.add(pid, "rustc", b"CARGO_TARGET_DIR=/shared\0SCCACHE_DIR=/shared\0");
        }
        assert_eq!(fixture.collect(Limits { paths: 2, bytes: 14, ..Limits::default() }),
            (vec![(41, PathBuf::from("/shared")), (42, PathBuf::from("/shared"))], true));
    }
}
