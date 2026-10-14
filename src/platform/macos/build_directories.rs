//! Positive live-build cache evidence from native macOS process records.
//!
//! Do not invoke ps or a build tool, inspect unrelated environments, or use
//! sbh's HOME. Bound process work and each argument record; retain completed
//! positive observations when another process is inaccessible. This Vec-returning
//! PAL method is deliberately not a certificate of complete process visibility.

use std::collections::BTreeSet;
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::platform::build_environment::CacheLayout;
use crate::platform::build_invocation;
use crate::platform::process_arguments::darwin_arguments;
use crate::platform::types::{OPEN_FILES_MAX_PIDS, OPEN_FILES_SCAN_BUDGET};

const MAX_DECLARED_PATHS: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessIdentity {
    pid: i32,
    started: (u64, u64),
    name: Vec<u8>,
}

trait ProcessAccess {
    fn pids(&self) -> io::Result<Vec<i32>>;
    fn identity(&self, pid: i32) -> io::Result<ProcessIdentity>;
    fn arguments(&self, pid: i32) -> io::Result<Vec<u8>>;
    fn cwd(&self, pid: i32) -> io::Result<PathBuf>;
    fn now(&self) -> Instant;
}

struct NativeProcesses;

impl ProcessAccess for NativeProcesses {
    fn pids(&self) -> io::Result<Vec<i32>> {
        super::libproc::proc_listpids_safe()
    }

    fn identity(&self, pid: i32) -> io::Result<ProcessIdentity> {
        let raw = super::libproc::proc_pidinfo_task_all(pid)?;
        if u32::try_from(pid).ok() != Some(raw.pbsd.pbi_pid.0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "process id changed",
            ));
        }
        let bytes = |array: &[libc::c_char]| {
            array
                .iter()
                .take_while(|byte| **byte != 0)
                .map(|byte| byte.to_ne_bytes()[0])
                .collect::<Vec<u8>>()
        };
        let mut name = bytes(&raw.pbsd.pbi_name);
        if name.is_empty() {
            name = bytes(&raw.pbsd.pbi_comm);
        }
        Ok(ProcessIdentity {
            pid,
            started: (raw.pbsd.pbi_start_tvsec, raw.pbsd.pbi_start_tvusec),
            name,
        })
    }

    fn arguments(&self, pid: i32) -> io::Result<Vec<u8>> {
        sbh_mach::proc_pid_arguments(pid)
    }

    fn cwd(&self, pid: i32) -> io::Result<PathBuf> {
        sbh_mach::proc_pid_cwd(pid)
    }

    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Clone, Copy)]
struct Limits {
    time: Duration,
    pids: usize,
    paths: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            time: OPEN_FILES_SCAN_BUDGET,
            pids: OPEN_FILES_MAX_PIDS,
            paths: MAX_DECLARED_PATHS,
        }
    }
}

pub(super) fn collect() -> Vec<(i32, PathBuf)> {
    collect_with(&NativeProcesses, std::process::id(), Limits::default())
}

fn collect_with(access: &impl ProcessAccess, own: u32, limits: Limits) -> Vec<(i32, PathBuf)> {
    let started = access.now();
    let in_budget = || {
        access
            .now()
            .checked_duration_since(started)
            .is_some_and(|elapsed| elapsed < limits.time)
    };
    let mut directories = BTreeSet::new();
    if limits.pids == 0 || limits.paths == 0 || !in_budget() {
        return Vec::new();
    }
    let Ok(pids) = access.pids() else {
        return Vec::new();
    };
    for (seen, pid) in pids.into_iter().enumerate() {
        if seen >= limits.pids || directories.len() >= limits.paths || !in_budget() {
            break;
        }
        if pid <= 0 || u32::try_from(pid).ok() == Some(own) {
            continue;
        }
        let Ok(before) = access.identity(pid) else {
            continue;
        };
        if before.pid != pid {
            continue;
        }
        let Some(tool) = build_invocation::observed_tool(&before.name) else {
            continue;
        };
        if !in_budget() {
            break;
        }
        let Ok(raw) = access.arguments(pid) else {
            continue;
        };
        if raw.len() > sbh_mach::PROCESS_ARGUMENTS_MAX_BYTES {
            continue;
        }
        let Some(arguments) = darwin_arguments(&raw) else {
            continue;
        };
        if !in_budget() {
            break;
        }
        // An inaccessible cwd does not erase absolute cache declarations.
        // Relative values can only be interpreted in this process's cwd.
        let cwd = access.cwd(pid).ok();
        if !in_budget() {
            break;
        }
        // Process exit/reuse or a changed name must not combine observations
        // from different builders. This is still not an atomic exec snapshot.
        if access.identity(pid).ok().as_ref() != Some(&before) {
            continue;
        }
        for directory in build_invocation::references(
            CacheLayout::MacOs,
            tool,
            arguments.argv,
            arguments.environment,
            cwd.as_deref(),
        ) {
            if directories.len() >= limits.paths {
                break;
            }
            directories.insert((pid, directory));
        }
    }
    directories.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::fs;
    use std::process::{Child, Command, Stdio};

    struct FixtureProcess {
        name: Vec<u8>,
        arguments: Vec<u8>,
        cwd: Option<PathBuf>,
    }

    struct Fixture {
        processes: BTreeMap<i32, FixtureProcess>,
        denied: BTreeSet<i32>,
        changed: Option<i32>,
        reads: RefCell<Vec<(i32, &'static str)>>,
        now: Cell<Instant>,
        elapsed_per_read: Duration,
    }

    impl Default for Fixture {
        fn default() -> Self {
            Self {
                processes: BTreeMap::new(),
                denied: BTreeSet::new(),
                changed: None,
                reads: RefCell::new(Vec::new()),
                now: Cell::new(Instant::now()),
                elapsed_per_read: Duration::ZERO,
            }
        }
    }

    fn arguments(name: &str, environment: &[u8]) -> Vec<u8> {
        let mut raw = 1_i32.to_ne_bytes().to_vec();
        raw.extend_from_slice(b"/usr/bin/builder\0\0\0");
        raw.extend_from_slice(name.as_bytes());
        raw.push(0);
        raw.extend_from_slice(environment);
        raw
    }

    impl Fixture {
        fn add(&mut self, pid: i32, name: &str, environment: &[u8]) {
            self.processes.insert(
                pid,
                FixtureProcess {
                    name: name.as_bytes().to_vec(),
                    arguments: arguments(name, environment),
                    cwd: Some(PathBuf::from("/workspace")),
                },
            );
        }

        fn read(&self, pid: i32, kind: &'static str) {
            self.reads.borrow_mut().push((pid, kind));
            self.now.set(self.now.get() + self.elapsed_per_read);
        }

        fn invocation(&mut self, pid: i32, name: &str, argv: &[&[u8]], environment: &[u8]) {
            self.add(pid, name, environment);
            let mut raw = i32::try_from(argv.len()).unwrap().to_ne_bytes().to_vec();
            raw.extend_from_slice(b"/usr/bin/interpreter\0\0");
            for arg in argv {
                raw.extend_from_slice(arg);
                raw.push(0);
            }
            raw.extend_from_slice(environment);
            self.processes.get_mut(&pid).unwrap().arguments = raw;
        }
    }

    impl ProcessAccess for Fixture {
        fn pids(&self) -> io::Result<Vec<i32>> {
            Ok(self.processes.keys().copied().collect())
        }

        fn identity(&self, pid: i32) -> io::Result<ProcessIdentity> {
            self.read(pid, "identity");
            let count = self
                .reads
                .borrow()
                .iter()
                .filter(|read| **read == (pid, "identity"))
                .count();
            Ok(ProcessIdentity {
                pid,
                started: (100 + u64::from(self.changed == Some(pid) && count > 1), 0),
                name: self.processes[&pid].name.clone(),
            })
        }

        fn arguments(&self, pid: i32) -> io::Result<Vec<u8>> {
            self.read(pid, "arguments");
            if self.denied.contains(&pid) {
                return Err(io::Error::from_raw_os_error(libc::EACCES));
            }
            Ok(self.processes[&pid].arguments.clone())
        }

        fn cwd(&self, pid: i32) -> io::Result<PathBuf> {
            self.read(pid, "cwd");
            self.processes[&pid]
                .cwd
                .clone()
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EACCES))
        }

        fn now(&self) -> Instant {
            self.now.get()
        }
    }

    #[test]
    fn interpreter_hosted_package_managers_reach_native_cache_protection() {
        let mut fixture = Fixture::default();
        fixture.invocation(41, "Python", &[b"python3", b"-m", b"pip"], b"HOME=/builder\0");
        fixture.invocation(42, "node", &[b"node", b"/opt/npm/bin/npm-cli.js"], b"HOME=/builder\0");
        fixture.invocation(43, "python3", &[b"python3", b"worker.py", b"-m", b"pip"], b"HOME=/builder\0");
        assert_eq!(
            collect_with(&fixture, 99, Limits::default()),
            vec![
                (41, PathBuf::from("/builder/Library/Caches/pip")),
                (42, PathBuf::from("/builder/.npm")),
            ]
        );
        // A changed PID/start-time still defeats invocation-based evidence.
        fixture.changed = Some(41);
        fixture.reads.borrow_mut().clear();
        assert_eq!(
            collect_with(&fixture, 99, Limits::default()),
            vec![(42, PathBuf::from("/builder/.npm"))]
        );
    }

    #[test]
    fn native_transport_shape_feeds_shared_cache_rules_without_descriptors() {
        let mut fixture = Fixture::default();
        fixture.add(42, "rustc", b"CARGO_HOME=/cache/cargo\0CARGO_TARGET_DIR=/target\0");
        fixture.add(43, "go", b"HOME=/builder\0");
        fixture.add(44, "npm", b"HOME=/builder\0");
        fixture.add(45, "uv", b"HOME=/builder\0");
        let found = collect_with(&fixture, 99, Limits::default());
        assert!(found.contains(&(42, PathBuf::from("/cache/cargo/registry/src"))));
        assert!(found.contains(&(42, PathBuf::from("/target"))));
        assert!(found.contains(&(43, PathBuf::from("/builder/Library/Caches/go-build"))));
        assert!(found.contains(&(43, PathBuf::from("/builder/go/pkg/mod"))));
        assert!(found.contains(&(44, PathBuf::from("/builder/.npm"))));
        assert!(found.contains(&(45, PathBuf::from("/builder/.cache/uv"))));
        assert_eq!(found.len(), 10);
    }

    #[test]
    fn unrelated_and_own_processes_never_have_their_arguments_read() {
        let mut fixture = Fixture::default();
        fixture.add(41, "bash", b"CARGO_HOME=/unrelated\0");
        fixture.add(42, "cargo", b"CARGO_HOME=/own\0");
        fixture.add(43, "rustc", b"CARGO_TARGET_DIR=/active\0");
        assert_eq!(
            collect_with(&fixture, 42, Limits::default()),
            vec![(43, PathBuf::from("/active"))]
        );
        assert!(!fixture.reads.borrow().iter().any(|(pid, kind)| {
            *pid == 42 || (*pid == 41 && *kind != "identity")
        }));
    }

    #[test]
    fn denied_or_malformed_processes_keep_other_builds_positive_evidence() {
        let mut fixture = Fixture::default();
        for pid in 1..=4 {
            fixture.add(pid, "rustc", b"CARGO_TARGET_DIR=/active\0");
        }
        fixture.denied.insert(1);
        fixture.processes.get_mut(&2).unwrap().arguments = vec![0xff; 3];
        fixture.processes.get_mut(&3).unwrap().arguments =
            vec![0; sbh_mach::PROCESS_ARGUMENTS_MAX_BYTES + 1];
        assert_eq!(
            collect_with(&fixture, 99, Limits::default()),
            vec![(4, PathBuf::from("/active"))]
        );
    }

    #[test]
    fn relative_cache_values_require_the_observed_cwd_not_daemon_state() {
        let mut fixture = Fixture::default();
        fixture.add(42, "rustc", b"CARGO_TARGET_DIR=../target\0SCCACHE_DIR=/absolute\0");
        let found = collect_with(&fixture, 99, Limits::default());
        assert!(found.contains(&(42, PathBuf::from("/workspace/../target"))));
        assert!(found.contains(&(42, PathBuf::from("/absolute"))));
        fixture.processes.get_mut(&42).unwrap().cwd = None;
        assert_eq!(
            collect_with(&fixture, 99, Limits::default()),
            vec![(42, PathBuf::from("/absolute"))]
        );
    }

    #[test]
    fn changed_process_identity_cannot_publish_a_mixed_observation() {
        let mut fixture = Fixture::default();
        fixture.add(42, "rustc", b"CARGO_TARGET_DIR=/active\0");
        fixture.changed = Some(42);
        assert!(collect_with(&fixture, 99, Limits::default()).is_empty());
    }

    #[test]
    fn metadata_work_cannot_renew_the_deadline_or_exceed_result_bounds() {
        let mut fixture = Fixture::default();
        fixture.add(42, "rustc", b"CARGO_HOME=/active\0");
        fixture.add(43, "rustc", b"CARGO_HOME=/other\0");
        fixture.elapsed_per_read = Duration::from_secs(1);
        let limits = Limits {
            time: Duration::from_secs(2),
            ..Limits::default()
        };
        assert!(collect_with(&fixture, 99, limits).is_empty());
        assert_eq!(
            *fixture.reads.borrow(),
            vec![(42, "identity"), (42, "arguments")]
        );
        fixture.elapsed_per_read = Duration::ZERO;
        let found = collect_with(&fixture, 99, Limits { paths: 2, ..Limits::default() });
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|(pid, _)| *pid == 42));
        assert!(collect_with(&fixture, 99, Limits { pids: 0, ..Limits::default() }).is_empty());
        assert!(collect_with(&fixture, 99, Limits { paths: 0, ..Limits::default() }).is_empty());
    }

    struct ChildGuard(Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn macos_pal_exposes_a_live_builds_cwd_and_descriptor_free_cache() {
        use crate::platform::pal::Platform;
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let executable = root.join("cargo");
        // A native process fixture with a build-tool name, not a Cargo build.
        fs::copy("/bin/sleep", &executable).unwrap();
        let workspace = root.join("workspace");
        let home = root.join("cargo-home");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(home.join("registry/src")).unwrap();
        let child = ChildGuard(
            Command::new(&executable)
                .arg("30")
                .current_dir(&workspace)
                .env("CARGO_HOME", &home)
                .env("CARGO_TARGET_DIR", root.join("target"))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let pid = i32::try_from(child.0.id()).unwrap();
        let platform = super::super::pal::MacOsPal::new();
        assert!(platform
            .build_directories_in_use()
            .contains(&(pid, home.join("registry/src"))));
        let process = platform
            .process_list()
            .unwrap()
            .into_iter()
            .find(|process| process.pid == pid)
            .unwrap();
        assert_eq!(process.cwd.as_deref(), Some(workspace.as_path()));
        assert!(home.is_dir());
    }
}
