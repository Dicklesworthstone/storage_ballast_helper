//! Bounded Linux transport for positive build-directory evidence.
//!
//! Environment and argv observations are independent: losing either must not
//! erase positives from the other. Both the PAL scorer and native executor use
//! this sweep. Its completeness is observation coverage, not an exhaustive
//! resolver of configuration files, process mutations, or mount namespaces.
//! Raw argument/environment/configuration bytes are never logged.

use std::io;
use std::path::{Path, PathBuf};

use super::{BUILD_ENVIRON_LIMIT, Limits, ProcAccess, Sweep, UnreadableProcess, disappeared};
use crate::platform::build_environment::{self, CacheLayout, Tool};
use crate::platform::{build_invocation, cargo_config};

const BUILD_ARGV_LIMIT: usize = 512 * 1024;
const MAX_BUILD_REFERENCES: usize = 16_384;
const MAX_REFERENCE_BYTES: usize = 8 * 1024 * 1024;

pub(super) struct BuildReferences {
    pub(super) directories: Vec<(i32, PathBuf)>,
    pub(super) denied: Option<UnreadableProcess>,
    pub(super) complete: bool,
    path_bytes: usize,
}

impl BuildReferences {
    fn new() -> Self {
        Self {
            directories: Vec::new(),
            denied: None,
            complete: true,
            path_bytes: 0,
        }
    }

    fn push(&mut self, pid: i32, path: PathBuf) -> bool {
        let bytes = path.as_os_str().as_encoded_bytes().len();
        if self.directories.len() >= MAX_BUILD_REFERENCES
            || bytes > MAX_REFERENCE_BYTES.saturating_sub(self.path_bytes)
        {
            self.complete = false;
            return false;
        }
        self.path_bytes += bytes;
        self.directories.push((pid, path));
        true
    }

    fn missing(&mut self, pid: i32, file: &'static str, error: io::Error) {
        self.complete = false;
        self.denied
            .get_or_insert(UnreadableProcess { pid, file, error });
    }
}

/// Read only metadata of recognized tools, keeping independent positive
/// observations and one bounded diagnostic. The caller owns the scan budget.
pub(super) fn sweep(proc: &impl ProcAccess, proc_root: &Path, limits: Limits) -> BuildReferences {
    let mut sweep = Sweep::new(proc, limits);
    let mut result = BuildReferences::new();
    if sweep.expired() {
        result.complete = false;
        return result;
    }
    let Ok(pids) = sweep.pids(proc_root) else {
        result.complete = false;
        return result;
    };
    let own = i32::try_from(std::process::id()).ok();
    // A shared workspace/home is read once during this sweep, not once per
    // compiler or process. Discard the cache when the observation finishes.
    let mut configurations = cargo_config::Resolver::default();
    'processes: for pid in pids {
        if sweep.expired() {
            break;
        }
        if Some(pid) == own {
            continue;
        }
        let process = proc_root.join(pid.to_string());
        let Ok(comm) = proc.read_bounded(&process.join("comm"), 64) else {
            continue;
        };
        let Some(tool) = build_invocation::observed_tool(&comm) else {
            continue;
        };
        let environ = metadata(
            &mut sweep,
            &process,
            pid,
            "environ",
            BUILD_ENVIRON_LIMIT,
            &mut result,
        );
        // Read cwd before argv. If a slow read exhausts the deadline, retain
        // absolute paths already observed without starting another syscall.
        let cwd = if sweep.expired() {
            None
        } else {
            proc.link(&process.join("cwd")).ok()
        };
        let paths = if matches!(tool, Tool::Go | Tool::Compiler) {
            // The shared invocation parser has no CLI destinations for these
            // families yet. Do not add a proc read that supplies no evidence.
            build_environment::references(tool, &environ, cwd.as_deref())
        } else {
            let argv = metadata(
                &mut sweep,
                &process,
                pid,
                "cmdline",
                BUILD_ARGV_LIMIT,
                &mut result,
            );
            let mut paths = build_invocation::references(
                CacheLayout::Linux,
                tool,
                &argv,
                &environ,
                cwd.as_deref(),
            );
            if tool == Tool::Rust && cargo_config::is_cargo(&argv) {
                let evidence =
                    configurations.observe(&argv, &environ, cwd.as_deref(), |path, limit| {
                        if sweep.expired() {
                            Err(io::ErrorKind::TimedOut.into())
                        } else {
                            cargo_config::read_file(path, limit)
                        }
                    });
                if !evidence.complete {
                    result.missing(
                        pid,
                        "cargo config",
                        io::Error::other("Cargo configuration observation incomplete"),
                    );
                }
                for directory in evidence.directories {
                    if !paths.contains(&directory) {
                        paths.push(directory);
                    }
                }
            }
            paths
        };
        for path in paths {
            // Keep attribution to every live process sharing a cache. The
            // resolver deduplicates within one invocation; the executor later
            // deduplicates paths, but the scorer still needs process identity.
            if !result.push(pid, path) {
                break 'processes;
            }
        }
    }
    sweep.expired();
    result.complete &= sweep.complete;
    result
}

fn metadata(
    sweep: &mut Sweep<'_, impl ProcAccess>,
    process: &Path,
    pid: i32,
    file: &'static str,
    limit: usize,
    result: &mut BuildReferences,
) -> Vec<u8> {
    if sweep.expired() {
        result.complete = false;
        return Vec::new();
    }
    match sweep.proc.read_bounded(&process.join(file), limit) {
        Ok(raw) => {
            let invalid = (!raw.is_empty() && !raw.ends_with(b"\0"))
                || (file == "cmdline" && (raw.is_empty() || raw.first() == Some(&0)));
            if invalid {
                // Zombies can still have a build-tool comm but no argv. An
                // empty argv alone is not proof of that terminal state.
                let terminal =
                    file == "cmdline" && raw.is_empty() && sweep.no_user_executable(process, pid);
                if !terminal {
                    result.missing(
                        pid,
                        file,
                        io::Error::new(io::ErrorKind::InvalidData, "incomplete process metadata"),
                    );
                }
            }
            raw
        }
        Err(error) => {
            let gone = error.raw_os_error() == Some(libc::ESRCH)
                || (disappeared(&error) && !sweep.expired() && sweep.proc.process_gone(process));
            if !gone {
                result.missing(pid, file, error);
            }
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::fs;
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::fs::symlink;
    use std::time::{Duration, Instant};

    use super::super::{Entries, NativeProc, open_targets_with, read_proc_bytes};

    struct Fixture {
        _temp: tempfile::TempDir,
        root: PathBuf,
        proc_root: PathBuf,
        pid: i32,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let root = fs::canonicalize(temp.path()).unwrap();
            let proc_root = root.join("proc");
            fs::create_dir(&proc_root).unwrap();
            Self {
                _temp: temp,
                root,
                proc_root,
                pid: i32::try_from(std::process::id())
                    .unwrap()
                    .checked_add(1)
                    .unwrap(),
            }
        }

        fn install(&self, pid: i32, comm: &str, environment: &[u8], argv: &[u8]) -> PathBuf {
            let process = self.proc_root.join(pid.to_string());
            fs::create_dir_all(process.join("fd")).unwrap();
            fs::write(process.join("comm"), format!("{comm}\n")).unwrap();
            fs::write(process.join("environ"), environment).unwrap();
            fs::write(process.join("cmdline"), argv).unwrap();
            // A readable Cargo fixture also declares where its config
            // hierarchy starts. rustc's missing-cwd fixture remains unchanged.
            if matches!(
                comm,
                "cargo" | "cargo-clippy" | "cargo-rch-real" | "cargo-nextest"
            ) {
                symlink(&self.root, process.join("cwd")).unwrap();
            }
            process
        }

        fn collect(&self, proc: &impl ProcAccess) -> BuildReferences {
            sweep(proc, &self.proc_root, Limits::default())
        }
    }

    struct Fault {
        field: &'static str,
        code: i32,
        now: Cell<Instant>,
        step: Duration,
        reads: RefCell<Vec<PathBuf>>,
    }

    impl Fault {
        fn new(field: &'static str, code: i32) -> Self {
            Self {
                field,
                code,
                now: Cell::new(Instant::now()),
                step: Duration::ZERO,
                reads: RefCell::new(Vec::new()),
            }
        }
    }

    impl ProcAccess for Fault {
        fn entries(&self, path: &Path) -> io::Result<Entries> {
            NativeProc.entries(path)
        }

        fn link(&self, path: &Path) -> io::Result<PathBuf> {
            NativeProc.link(path)
        }

        fn process_gone(&self, path: &Path) -> bool {
            NativeProc.process_gone(path)
        }

        fn now(&self) -> Instant {
            self.now.get()
        }

        fn read_bounded(&self, path: &Path, limit: usize) -> io::Result<Vec<u8>> {
            self.now.set(self.now.get() + self.step);
            self.reads.borrow_mut().push(path.to_path_buf());
            if path.file_name().is_some_and(|name| name == self.field) {
                Err(io::Error::from_raw_os_error(self.code))
            } else {
                read_proc_bytes(path, limit)
            }
        }
    }

    #[test]
    fn command_line_only_destinations_reach_both_scoring_and_final_preflight() {
        for (comm, prefix) in [
            ("cargo", "cargo\0build\0--target-dir\0"),
            ("rustc", "rustc\0lib.rs\0--out-dir\0"),
            ("rustdoc", "rustdoc\0lib.rs\0-o\0"),
            ("pip3", "pip3\0install\0--cache-dir\0"),
            ("uv", "uv\0sync\0--cache-dir\0"),
            ("npm", "npm\0install\0--cache\0"),
            ("python3", "python3\0-m\0pip\0install\0--cache-dir\0"),
            ("node", "node\0/opt/npm/npm-cli.js\0install\0--cache\0"),
        ] {
            let fixture = Fixture::new();
            let target = fixture.root.join("live-target");
            fs::create_dir(&target).unwrap();
            fs::write(target.join("keep"), b"active").unwrap();
            let args = format!("{prefix}{}\0", target.display());
            let process = fixture.install(fixture.pid, comm, b"", args.as_bytes());
            let found = fixture.collect(&NativeProc);
            assert!(found.complete, "{comm}");
            assert_eq!(found.directories, vec![(fixture.pid, target.clone())]);
            let (targets, complete) =
                open_targets_with(&NativeProc, &fixture.proc_root, Limits::default()).unwrap();
            assert!(complete, "{comm}");
            assert!(targets.contains(&target), "{comm}: {targets:?}");
            let ancestors = crate::scanner::walker::open_path_ancestors_for_roots(
                &targets,
                std::slice::from_ref(&fixture.root),
            );
            assert!(ancestors.contains(&target));
            assert_eq!(fs::read_dir(process.join("fd")).unwrap().count(), 0);
            assert_eq!(fs::read(target.join("keep")).unwrap(), b"active");
        }
    }

    #[test]
    fn denied_environment_keeps_argv_evidence_but_holds_the_batch() {
        let fixture = Fixture::new();
        let target = fixture.root.join("argv-only");
        fixture.install(
            fixture.pid,
            "cargo",
            b"CARGO_TARGET_DIR=/environment\0",
            format!("cargo\0build\0--target-dir={}\0", target.display()).as_bytes(),
        );
        let access = Fault::new("environ", libc::EACCES);
        let found = fixture.collect(&access);
        assert!(!found.complete);
        assert_eq!(found.directories, vec![(fixture.pid, target.clone())]);
        assert_eq!(found.denied.unwrap().file, "environ");
        let (targets, complete) =
            open_targets_with(&access, &fixture.proc_root, Limits::default()).unwrap();
        assert!(!complete);
        assert!(targets.contains(&target));
    }

    #[test]
    fn unavailable_argv_keeps_environment_evidence_and_never_certifies_absence() {
        let fixture = Fixture::new();
        fixture.install(
            fixture.pid,
            "cargo",
            b"CARGO_TARGET_DIR=/known\0",
            b"cargo\0",
        );
        for code in [
            libc::EACCES,
            libc::EPERM,
            libc::ENOENT,
            libc::EIO,
            libc::EMFILE,
        ] {
            let access = Fault::new("cmdline", code);
            let found = fixture.collect(&access);
            assert!(!found.complete, "{code}");
            assert_eq!(
                found.directories,
                vec![(fixture.pid, PathBuf::from("/known"))]
            );
            assert_eq!(found.denied.unwrap().file, "cmdline");
            let (targets, complete) =
                open_targets_with(&access, &fixture.proc_root, Limits::default()).unwrap();
            assert!(!complete);
            assert!(targets.contains(&PathBuf::from("/known")));
        }
    }

    #[test]
    fn malformed_oversized_and_nonregular_argv_are_not_parsed_as_complete() {
        let fixture = Fixture::new();
        let process = fixture.install(fixture.pid, "cargo", b"CARGO_TARGET_DIR=/known\0", b"");
        for raw in [
            Vec::new(),
            b"\0build\0--target-dir=/decoy\0".to_vec(),
            b"cargo\0build\0--target-dir=/unterminated".to_vec(),
            vec![b'x'; BUILD_ARGV_LIMIT + 1],
        ] {
            fs::write(process.join("cmdline"), raw).unwrap();
            let found = fixture.collect(&NativeProc);
            assert!(!found.complete);
            assert_eq!(
                found.directories,
                vec![(fixture.pid, PathBuf::from("/known"))]
            );
        }
        let cmdline = process.join("cmdline");
        fs::rename(&cmdline, process.join("saved-argv")).unwrap();
        nix::unistd::mkfifo(
            &cmdline,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        let found = fixture.collect(&NativeProc);
        assert!(!found.complete);
        assert_eq!(
            found.directories,
            vec![(fixture.pid, PathBuf::from("/known"))]
        );
    }

    #[test]
    fn incomplete_environment_keeps_complete_entries_and_independent_argv() {
        let fixture = Fixture::new();
        fixture.install(
            fixture.pid,
            "cargo",
            b"CARGO_TARGET_DIR=/known\0HOME=/unfinished",
            b"cargo\0build\0--target-dir=/cli\0",
        );
        let found = fixture.collect(&NativeProc);
        assert!(!found.complete);
        assert_eq!(
            found.directories,
            vec![
                (fixture.pid, PathBuf::from("/known")),
                (fixture.pid, PathBuf::from("/cli")),
            ]
        );
    }

    #[test]
    fn argument_paths_preserve_native_bytes_and_use_only_the_process_cwd() {
        let fixture = Fixture::new();
        let process = fixture.install(
            fixture.pid,
            "rustc",
            b"",
            b"rustc\0lib.rs\0--out-dir\0../target-\xff = data\0",
        );
        assert!(fixture.collect(&NativeProc).directories.is_empty());
        symlink(&fixture.root, process.join("cwd")).unwrap();
        let expected = fixture.root.join(std::ffi::OsString::from_vec(
            b"../target-\xff = data".to_vec(),
        ));
        assert_eq!(
            fixture.collect(&NativeProc).directories,
            vec![(fixture.pid, expected)]
        );
    }

    #[test]
    fn forwarded_arguments_and_unrelated_processes_do_not_invent_destinations() {
        let fixture = Fixture::new();
        fixture.install(
            fixture.pid,
            "cargo",
            b"CARGO_TARGET_DIR=/known\0",
            b"cargo\0run\0--\0--target-dir=/decoy\0",
        );
        assert_eq!(
            fixture.collect(&NativeProc).directories,
            vec![(fixture.pid, PathBuf::from("/known"))]
        );
        fs::write(
            fixture.proc_root.join(fixture.pid.to_string()).join("comm"),
            b"bash\n",
        )
        .unwrap();
        let access = Fault::new("unused", libc::EIO);
        assert!(fixture.collect(&access).directories.is_empty());
        assert_eq!(access.reads.borrow().len(), 1);
        assert!(access.reads.borrow()[0].ends_with("comm"));
    }

    #[test]
    fn deadline_exhaustion_retains_positives_without_starting_an_argv_read() {
        let fixture = Fixture::new();
        fixture.install(
            fixture.pid,
            "cargo",
            b"CARGO_TARGET_DIR=/known\0",
            b"cargo\0",
        );
        let mut access = Fault::new("unused", libc::EIO);
        access.step = Duration::from_secs(1);
        let found = sweep(
            &access,
            &fixture.proc_root,
            Limits {
                time: Duration::from_secs(2),
                ..Limits::default()
            },
        );
        assert!(!found.complete);
        assert_eq!(
            found.directories,
            vec![(fixture.pid, PathBuf::from("/known"))]
        );
        assert_eq!(access.reads.borrow().len(), 2);
        assert!(
            !access
                .reads
                .borrow()
                .iter()
                .any(|path| path.ends_with("cmdline"))
        );
    }

    #[test]
    fn process_churn_and_terminal_empty_argv_are_distinct_from_missing_live_metadata() {
        let fixture = Fixture::new();
        let process = fixture.install(fixture.pid, "cargo", b"", b"");
        assert!(!fixture.collect(&NativeProc).complete);
        let mut fields = ["0"; 20];
        fields[0] = "Z";
        fields[17] = "1";
        fs::write(
            process.join("stat"),
            format!("{} (cargo) {}\n", fixture.pid, fields.join(" ")),
        )
        .unwrap();
        assert!(fixture.collect(&NativeProc).complete);
        fs::write(process.join("cmdline"), b"cargo\0").unwrap();
        let gone = Fault::new("environ", libc::ESRCH);
        assert!(fixture.collect(&gone).complete);
    }

    #[test]
    fn shared_caches_retain_each_builders_identity_without_duplicate_paths_per_builder() {
        let fixture = Fixture::new();
        for pid in [fixture.pid, fixture.pid + 1] {
            fixture.install(
                pid,
                "cargo",
                b"CARGO_TARGET_DIR=/shared\0",
                b"cargo\0build\0--target-dir=/shared\0",
            );
        }
        assert_eq!(
            fixture.collect(&NativeProc).directories,
            vec![
                (fixture.pid, PathBuf::from("/shared")),
                (fixture.pid + 1, PathBuf::from("/shared")),
            ]
        );
        let (targets, complete) =
            open_targets_with(&NativeProc, &fixture.proc_root, Limits::default()).unwrap();
        assert!(complete);
        // The now-explicit fixture cwd is also a legitimate point reference.
        let mut expected = vec![PathBuf::from("/shared"), fixture.root.clone()];
        expected.sort();
        assert_eq!(targets, expected);
    }

    #[test]
    fn retained_reference_count_and_byte_budgets_fail_closed() {
        let mut result = BuildReferences::new();
        for _ in 0..MAX_BUILD_REFERENCES {
            assert!(result.push(1, PathBuf::from("/cache")));
        }
        assert!(!result.push(1, PathBuf::from("/overflow")));
        assert!(!result.complete);
        assert_eq!(result.directories.len(), MAX_BUILD_REFERENCES);
        let mut result = BuildReferences::new();
        assert!(result.push(1, PathBuf::from("/".repeat(MAX_REFERENCE_BYTES))));
        assert!(!result.push(1, PathBuf::from("/overflow")));
        assert!(!result.complete);
        assert_eq!(result.path_bytes, MAX_REFERENCE_BYTES);
        assert_eq!(result.directories.len(), 1);
    }

    #[test]
    fn config_only_outputs_reach_the_native_executor_without_open_descriptors() {
        let fixture = Fixture::new();
        let config_dir = fixture.root.join(".cargo");
        fs::create_dir(&config_dir).unwrap();
        let target = fixture.root.join("separate-output");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("keep"), b"live build").unwrap();
        fs::write(
            config_dir.join("config.toml"),
            "[build]\ntarget-dir='separate-output'",
        )
        .unwrap();
        let process = fixture.install(fixture.pid, "cargo", b"", b"cargo\0build\0");
        let found = fixture.collect(&NativeProc);
        assert!(found.complete);
        assert_eq!(found.directories, vec![(fixture.pid, target.clone())]);
        let (targets, complete) =
            open_targets_with(&NativeProc, &fixture.proc_root, Limits::default()).unwrap();
        assert!(complete);
        assert!(targets.contains(&target));
        assert_eq!(fs::read_dir(process.join("fd")).unwrap().count(), 0);
        assert_eq!(fs::read(target.join("keep")).unwrap(), b"live build");
    }

    #[test]
    fn incomplete_config_holds_native_preflight_without_erasing_known_outputs() {
        let fixture = Fixture::new();
        let config_dir = fixture.root.join(".cargo");
        fs::create_dir(&config_dir).unwrap();
        fs::write(config_dir.join("config.toml"), "[build]\ntarget-dir = [").unwrap();
        fixture.install(
            fixture.pid,
            "cargo",
            b"CARGO_TARGET_DIR=/known\0",
            b"cargo\0build\0",
        );
        let found = fixture.collect(&NativeProc);
        assert!(!found.complete);
        assert_eq!(
            found.directories,
            vec![(fixture.pid, PathBuf::from("/known"))]
        );
        assert_eq!(found.denied.unwrap().file, "cargo config");
        let (targets, complete) =
            open_targets_with(&NativeProc, &fixture.proc_root, Limits::default()).unwrap();
        assert!(!complete);
        assert!(targets.contains(&PathBuf::from("/known")));
    }

    #[test]
    fn inline_config_and_environment_destinations_are_independent_and_deduplicated() {
        let fixture = Fixture::new();
        fixture.install(
            fixture.pid,
            "cargo-rch-real",
            b"CARGO_TARGET_DIR=/known\0",
            b"cargo-rch-real\0build\0--config=build.target-dir='/known'\0--config=build.build-dir='/intermediate'\0",
        );
        let found = fixture.collect(&NativeProc);
        assert!(found.complete);
        assert_eq!(
            found.directories,
            vec![
                (fixture.pid, PathBuf::from("/known")),
                (fixture.pid, PathBuf::from("/intermediate"))
            ]
        );
    }
}
