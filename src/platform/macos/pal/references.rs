//! Fresh, coverage-aware descriptor observations for every candidate root.
//!
//! Native enumeration is not an atomic process snapshot. Access failures and
//! exhausted work budgets are missing evidence, never an empty safe inventory.
//! Process identities bracket descriptor reads; positive observations from
//! other processes survive a failed or changed process. No argv is inspected.

use std::collections::BTreeSet;
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::{
    OpenFile, OpenFileKind, OpenFileMode, OpenFilesResult, ProcFdInfo, ProcFdType,
    macos_process_path_variants, observed_process_path_under_root, open_file_kind, open_file_mode,
    proc_listpids_safe, proc_pid_list_fds, proc_pidfdinfo_vnode_path, proc_pidinfo_task_all,
};
use crate::platform::types::{OPEN_FILES_MAX_PIDS, OPEN_FILES_SCAN_BUDGET};

const MAX_DESCRIPTORS: usize = 262_144;
const MAX_DESCRIPTORS_PER_PID: usize = 16_384;
const MAX_RETAINED_PATH_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy)]
struct Limits {
    time: Duration,
    pids: usize,
    descriptors: usize,
    per_pid: usize,
    bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            time: OPEN_FILES_SCAN_BUDGET,
            pids: OPEN_FILES_MAX_PIDS,
            descriptors: MAX_DESCRIPTORS,
            per_pid: MAX_DESCRIPTORS_PER_PID,
            bytes: MAX_RETAINED_PATH_BYTES,
        }
    }
}

trait ProcessAccess {
    type Descriptor;

    fn pids(&self) -> io::Result<Vec<i32>>;
    fn identity(&self, pid: i32) -> io::Result<(u64, u64)>;
    fn descriptors(&self, pid: i32) -> io::Result<Vec<Self::Descriptor>>;
    fn reference(
        &self,
        pid: i32,
        descriptor: Self::Descriptor,
        roots: &[PathBuf],
    ) -> io::Result<Option<OpenFile>>;
    fn now(&self) -> Instant;
}

struct NativeProcesses;

impl ProcessAccess for NativeProcesses {
    type Descriptor = ProcFdInfo;

    fn pids(&self) -> io::Result<Vec<i32>> {
        proc_listpids_safe()
    }

    fn identity(&self, pid: i32) -> io::Result<(u64, u64)> {
        let info = proc_pidinfo_task_all(pid)?;
        if u32::try_from(pid).ok() != Some(info.pbsd.pbi_pid.0) {
            return Err(io::Error::other("process identity changed"));
        }
        Ok((info.pbsd.pbi_start_tvsec, info.pbsd.pbi_start_tvusec))
    }

    fn descriptors(&self, pid: i32) -> io::Result<Vec<ProcFdInfo>> {
        proc_pid_list_fds(pid)
    }

    fn reference(
        &self,
        pid: i32,
        descriptor: ProcFdInfo,
        roots: &[PathBuf],
    ) -> io::Result<Option<OpenFile>> {
        let fd = descriptor.proc_fd.0;
        if fd < 0 {
            return Err(io::Error::other("invalid process descriptor"));
        }
        let kind = descriptor
            .fd_type()
            .map_err(|_| io::Error::other("unknown process descriptor type"))?;
        if kind == ProcFdType::SOCKET {
            let Some(bound) = sbh_mach::proc_pid_unix_socket_path(pid, fd)? else {
                return Ok(None);
            };
            // Relative bindings cannot be reconstructed from a later cwd.
            // Preserve the existing absolute-bound-socket observation scope.
            return Ok(
                observed_process_path_under_root(&bound, roots).map(|path| OpenFile {
                    pid,
                    path,
                    fd: Some(fd),
                    kind: OpenFileKind::Socket,
                    mode: OpenFileMode::ReadWrite,
                }),
            );
        }
        if kind != ProcFdType::VNODE {
            return Ok(None);
        }
        let info = proc_pidfdinfo_vnode_path(pid, fd)?
            .ok_or_else(|| io::Error::other("vnode descriptor returned no metadata"))?;
        let path = info
            .path()
            .map_err(|_| io::Error::other("invalid vnode pathname"))?;
        if !path.is_absolute() {
            return Err(io::Error::other("vnode pathname is not absolute"));
        }
        Ok(
            observed_process_path_under_root(path, roots).map(|path| OpenFile {
                pid,
                path,
                fd: Some(fd),
                kind: open_file_kind(&info),
                mode: open_file_mode(info.pfi.fi_openflags),
            }),
        )
    }

    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// One fresh descriptor sweep, not one sweep or cached verdict per root.
/// Bounds cover attempted work and retained results, not the native adapter's
/// temporary enumeration buffers or a kernel call that blocks indefinitely.
pub(super) fn collect(roots: &[PathBuf]) -> io::Result<OpenFilesResult> {
    let mut variants: Vec<_> = roots
        .iter()
        .flat_map(|root| macos_process_path_variants(root))
        .collect();
    variants.sort();
    variants.dedup();
    collect_with(&NativeProcesses, &variants, Limits::default())
}

fn incomplete(result: &mut OpenFilesResult, reason: &'static str) {
    result.complete = false;
    result
        .incomplete_reason
        .get_or_insert_with(|| reason.to_owned());
}

fn gone(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ESRCH)
}

#[allow(clippy::too_many_lines)] // one shared budget and per-process publication boundary
fn collect_with(
    access: &impl ProcessAccess,
    roots: &[PathBuf],
    limits: Limits,
) -> io::Result<OpenFilesResult> {
    let mut result = OpenFilesResult::complete(Vec::new());
    if roots.is_empty() {
        return Ok(result);
    }
    let started = access.now();
    let in_budget = || {
        access
            .now()
            .checked_duration_since(started)
            .is_some_and(|elapsed| elapsed < limits.time)
    };
    if !in_budget() {
        incomplete(
            &mut result,
            "macOS descriptor inspection deadline exhausted",
        );
        return Ok(result);
    }
    let pids = access.pids()?;
    let mut visited = BTreeSet::new();
    let mut descriptors_seen = 0_usize;
    let mut retained_bytes = 0_usize;
    for (seen, pid) in pids.into_iter().enumerate() {
        if seen >= limits.pids || !in_budget() {
            incomplete(&mut result, "macOS process discovery budget exhausted");
            break;
        }
        if pid == 0 || !visited.insert(pid) {
            continue;
        }
        if pid < 0 {
            incomplete(
                &mut result,
                "macOS process inventory contained an invalid pid",
            );
            continue;
        }
        let before = match access.identity(pid) {
            Ok(identity) => identity,
            Err(error) => {
                if !gone(&error) {
                    incomplete(&mut result, "macOS process identity was unreadable");
                }
                continue;
            }
        };
        if !in_budget() {
            incomplete(
                &mut result,
                "macOS descriptor inspection deadline exhausted",
            );
            break;
        }
        let descriptors = match access.descriptors(pid) {
            Ok(descriptors) => descriptors,
            Err(error) => {
                if !gone(&error) {
                    incomplete(
                        &mut result,
                        "macOS process descriptor inventory was unreadable",
                    );
                }
                continue;
            }
        };
        let first = result.files.len();
        let bytes_before = retained_bytes;
        let mut exited = false;
        let mut stop = false;
        for (within_pid, descriptor) in descriptors.into_iter().enumerate() {
            if !in_budget() || descriptors_seen >= limits.descriptors {
                incomplete(&mut result, "macOS descriptor inspection budget exhausted");
                stop = true;
                break;
            }
            if within_pid >= limits.per_pid {
                incomplete(&mut result, "macOS per-process descriptor limit exhausted");
                break;
            }
            descriptors_seen += 1;
            match access.reference(pid, descriptor, roots) {
                Ok(Some(reference)) => {
                    let bytes = reference.path.as_os_str().as_encoded_bytes().len();
                    if bytes > limits.bytes.saturating_sub(retained_bytes) {
                        incomplete(&mut result, "macOS descriptor pathname budget exhausted");
                        stop = true;
                        break;
                    }
                    retained_bytes += bytes;
                    result.files.push(reference);
                }
                Ok(None) => {}
                Err(error) if gone(&error) => {
                    exited = true;
                    break;
                }
                // A descriptor can close after its inventory was read. Only
                // the descriptor-level EBADF is benign; list/identity errors
                // with the same errno still represent missing coverage.
                Err(error) if error.raw_os_error() == Some(libc::EBADF) => {}
                Err(_) => incomplete(&mut result, "macOS descriptor metadata was unreadable"),
            }
        }
        let verified = if exited {
            false
        } else if !in_budget() {
            incomplete(
                &mut result,
                "macOS descriptor inspection deadline exhausted",
            );
            stop = true;
            false
        } else {
            match access.identity(pid) {
                Ok(after) if after == before => true,
                Err(error) if gone(&error) => false,
                _ => {
                    incomplete(
                        &mut result,
                        "macOS process changed during descriptor inspection",
                    );
                    false
                }
            }
        };
        if !verified {
            // Never combine descriptor data from two incarnations of one PID.
            result.files.truncate(first);
            retained_bytes = bytes_before;
        }
        if stop {
            break;
        }
    }
    result.files.sort_by(|left, right| {
        left.pid
            .cmp(&right.pid)
            .then_with(|| left.fd.cmp(&right.fd))
            .then_with(|| left.path.cmp(&right.path))
    });
    // The last failed syscall, identity recheck and ordering count too.
    if !in_budget() {
        incomplete(
            &mut result,
            "macOS descriptor inspection deadline exhausted",
        );
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;

    struct Fixture {
        pids: Vec<i32>,
        files: BTreeMap<i32, Vec<i32>>,
        fault: Option<(i32, &'static str, i32)>,
        changed: Option<i32>,
        calls: RefCell<Vec<(i32, &'static str)>>,
        now: Cell<Instant>,
        step: Duration,
        discovery_step: Duration,
    }

    impl Default for Fixture {
        fn default() -> Self {
            Self {
                pids: vec![41, 42],
                files: BTreeMap::from([(41, vec![0, 1]), (42, vec![0])]),
                fault: None,
                changed: None,
                calls: RefCell::new(Vec::new()),
                now: Cell::new(Instant::now()),
                step: Duration::ZERO,
                discovery_step: Duration::ZERO,
            }
        }
    }

    impl Fixture {
        fn record(&self, pid: i32, field: &'static str) -> io::Result<()> {
            self.calls.borrow_mut().push((pid, field));
            self.now.set(self.now.get() + self.step);
            if let Some((target, name, code)) = self.fault
                && target == pid
                && name == field
            {
                return Err(io::Error::from_raw_os_error(code));
            }
            Ok(())
        }

        fn scan(&self, limits: Limits) -> OpenFilesResult {
            collect_with(self, &[PathBuf::from("/scan")], limits).unwrap()
        }
    }

    impl ProcessAccess for Fixture {
        type Descriptor = i32;

        fn pids(&self) -> io::Result<Vec<i32>> {
            self.record(0, "pids")?;
            self.now.set(self.now.get() + self.discovery_step);
            Ok(self.pids.clone())
        }

        fn identity(&self, pid: i32) -> io::Result<(u64, u64)> {
            self.record(pid, "identity")?;
            let count = self
                .calls
                .borrow()
                .iter()
                .filter(|call| **call == (pid, "identity"))
                .count();
            Ok((100 + u64::from(self.changed == Some(pid) && count > 1), 0))
        }

        fn descriptors(&self, pid: i32) -> io::Result<Vec<i32>> {
            self.record(pid, "descriptors")?;
            Ok(self.files.get(&pid).cloned().unwrap_or_default())
        }

        fn reference(&self, pid: i32, fd: i32, roots: &[PathBuf]) -> io::Result<Option<OpenFile>> {
            self.record(pid, if fd == 0 { "fd0" } else { "fd1" })?;
            let path = PathBuf::from(format!("/scan/pid-{pid}/fd-{fd}"));
            Ok(roots
                .iter()
                .any(|root| path.starts_with(root))
                .then_some(OpenFile {
                    pid,
                    path,
                    fd: Some(fd),
                    kind: OpenFileKind::Regular,
                    mode: OpenFileMode::Read,
                }))
        }

        fn now(&self) -> Instant {
            self.now.get()
        }
    }

    #[test]
    fn readable_inventory_is_complete_and_sorted() {
        let fixture = Fixture {
            pids: vec![42, 41],
            ..Fixture::default()
        };
        let result = fixture.scan(Limits::default());
        assert!(result.complete);
        assert!(result.incomplete_reason.is_none());
        assert_eq!(
            result
                .files
                .iter()
                .map(|file| (file.pid, file.fd))
                .collect::<Vec<_>>(),
            vec![(41, Some(0)), (41, Some(1)), (42, Some(0))]
        );
    }

    #[test]
    fn unreadable_process_preserves_other_processes_and_revokes_coverage() {
        for field in ["identity", "descriptors"] {
            for code in [
                libc::EACCES,
                libc::EPERM,
                libc::EIO,
                libc::EBADF,
                libc::ENOENT,
            ] {
                let fixture = Fixture {
                    fault: Some((41, field, code)),
                    ..Fixture::default()
                };
                let result = fixture.scan(Limits::default());
                assert!(!result.complete, "{field}: {code}");
                assert!(result.incomplete_reason.is_some());
                assert_eq!(result.files.len(), 1);
                assert_eq!(result.files[0].pid, 42);
            }
        }
    }

    #[test]
    fn unreadable_descriptor_keeps_other_descriptors_of_the_same_process() {
        let fixture = Fixture {
            fault: Some((41, "fd0", libc::EACCES)),
            ..Fixture::default()
        };
        let result = fixture.scan(Limits::default());
        assert!(!result.complete);
        assert_eq!(result.files.len(), 2);
        assert_eq!(result.files[0].pid, 41);
        assert_eq!(result.files[0].fd, Some(1));
        assert_eq!(result.files[1].pid, 42);
    }

    #[test]
    fn closed_descriptor_and_exited_process_are_not_permission_failures() {
        for field in ["identity", "descriptors", "fd1"] {
            let fixture = Fixture {
                fault: Some((41, field, libc::ESRCH)),
                ..Fixture::default()
            };
            let result = fixture.scan(Limits::default());
            assert!(result.complete);
            assert_eq!(result.files.len(), 1);
            assert_eq!(result.files[0].pid, 42);
        }
        let fixture = Fixture {
            fault: Some((41, "fd0", libc::EBADF)),
            ..Fixture::default()
        };
        let result = fixture.scan(Limits::default());
        assert!(result.complete);
        assert_eq!(result.files.len(), 2);
    }

    #[test]
    fn reused_pid_does_not_publish_mixed_descriptor_evidence() {
        let fixture = Fixture {
            changed: Some(41),
            ..Fixture::default()
        };
        let result = fixture.scan(Limits::default());
        assert!(!result.complete);
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].pid, 42);
    }

    #[test]
    fn multiple_roots_share_one_process_and_descriptor_sweep() {
        let fixture = Fixture::default();
        let result = collect_with(
            &fixture,
            &[
                PathBuf::from("/scan/pid-41"),
                PathBuf::from("/scan/pid-42"),
                PathBuf::from("/scan"),
            ],
            Limits::default(),
        )
        .unwrap();
        assert!(result.complete);
        assert_eq!(result.files.len(), 3);
        let calls = fixture.calls.borrow();
        assert_eq!(
            calls.iter().filter(|(_, field)| *field == "pids").count(),
            1
        );
        assert_eq!(
            calls
                .iter()
                .filter(|(_, field)| *field == "descriptors")
                .count(),
            2
        );
        assert_eq!(
            calls
                .iter()
                .filter(|(_, field)| matches!(*field, "fd0" | "fd1"))
                .count(),
            3
        );
    }

    #[test]
    fn per_pid_limit_preserves_later_processes_and_exact_eof() {
        let fixture = Fixture::default();
        let result = fixture.scan(Limits {
            per_pid: 1,
            ..Limits::default()
        });
        assert!(!result.complete);
        assert_eq!(result.files.len(), 2);
        assert_eq!(result.files[1].pid, 42);
        assert!(
            Fixture::default()
                .scan(Limits {
                    per_pid: 2,
                    ..Limits::default()
                })
                .complete
        );
    }

    #[test]
    fn total_descriptor_and_pid_limits_distinguish_exact_eof_from_truncation() {
        for descriptors in 0..=4 {
            let result = Fixture::default().scan(Limits {
                descriptors,
                ..Limits::default()
            });
            assert_eq!(result.files.len(), descriptors.min(3));
            assert_eq!(result.complete, descriptors >= 3);
        }
        for pids in 0..=3 {
            let result = Fixture::default().scan(Limits {
                pids,
                ..Limits::default()
            });
            assert_eq!(result.complete, pids >= 2);
        }
    }

    #[test]
    fn pathname_retention_budget_has_an_exact_boundary() {
        let fixture = Fixture {
            pids: vec![42],
            ..Fixture::default()
        };
        let bytes = "/scan/pid-42/fd-0".len();
        assert!(
            fixture
                .scan(Limits {
                    bytes,
                    ..Limits::default()
                })
                .complete
        );
        let result = fixture.scan(Limits {
            bytes: bytes - 1,
            ..Limits::default()
        });
        assert!(!result.complete);
        assert!(result.files.is_empty());
    }

    #[test]
    fn deadline_includes_empty_discovery_and_does_not_start_another_syscall() {
        let fixture = Fixture {
            pids: Vec::new(),
            discovery_step: Duration::from_secs(2),
            ..Fixture::default()
        };
        assert!(
            !fixture
                .scan(Limits {
                    time: Duration::from_secs(1),
                    ..Limits::default()
                })
                .complete
        );
        let fixture = Fixture {
            step: Duration::from_secs(1),
            ..Fixture::default()
        };
        let result = fixture.scan(Limits {
            time: Duration::from_secs(2),
            ..Limits::default()
        });
        assert!(!result.complete);
        assert!(result.files.is_empty());
        assert_eq!(*fixture.calls.borrow(), vec![(0, "pids"), (41, "identity")]);
    }

    #[test]
    fn late_final_identity_retains_verified_positive_but_not_complete_verdict() {
        let fixture = Fixture {
            pids: vec![42],
            step: Duration::from_secs(1),
            ..Fixture::default()
        };
        let result = fixture.scan(Limits {
            time: Duration::from_secs(5),
            ..Limits::default()
        });
        assert!(!result.complete);
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].pid, 42);
    }

    #[test]
    fn missing_scope_and_failed_discovery_have_distinct_results() {
        let fixture = Fixture {
            fault: Some((0, "pids", libc::EACCES)),
            ..Fixture::default()
        };
        let empty = collect_with(&fixture, &[], Limits::default()).unwrap();
        assert!(empty.complete);
        assert!(fixture.calls.borrow().is_empty());
        assert!(collect_with(&fixture, &[PathBuf::from("/scan")], Limits::default()).is_err());
    }

    #[test]
    fn successive_observations_do_not_reuse_an_empty_negative_snapshot() {
        let mut fixture = Fixture {
            files: BTreeMap::new(),
            ..Fixture::default()
        };
        let first = fixture.scan(Limits::default());
        assert!(first.complete);
        assert!(first.files.is_empty());
        fixture.files.insert(42, vec![0]);
        let second = fixture.scan(Limits::default());
        assert!(second.complete);
        assert_eq!(second.files.len(), 1);
    }
}
