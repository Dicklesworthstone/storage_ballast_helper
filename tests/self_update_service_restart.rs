//! Real Linux self-replacement through the CLI, with isolated systemctl fixtures.
#![cfg(all(target_os = "linux", feature = "cli"))]

use std::ffi::OsString;
use std::fs;
use std::io::Write as _;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use storage_ballast_helper::cli::{
    HostSpecifier, OfflineBundleArtifact, OfflineBundleManifest, RELEASE_REPOSITORY,
    ReleaseChannel, resolve_updater_artifact_contract,
};

const SYSTEMCTL: &str = r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$SBH_TEST_SYSTEMCTL_LOG"
readlink "/proc/$PPID/exe" >> "$SBH_TEST_UPDATER_EXE"
if [ "${1-}" = --user ]; then shift; fi
case "${1-}" in
    show)
        [ "$*" = 'show sbh.service --property=LoadState --value' ]
        [ "${LC_ALL-}" = C ]
        case "$SBH_TEST_SERVICE_STATE" in
            unloaded) printf 'not-found\n' ;;
            unloaded-exit-four) printf 'not-found\n'; exit 4 ;;
            no-manager)
                printf '%s\n' "System has not been booted with systemd as init system (PID 1). Can't operate." >&2
                printf 'Failed to connect to bus: Host is down\n' >&2
                exit 1
                ;;
            query-failure) printf 'fixture state query denied\n' >&2; exit 23 ;;
            bus-failure) printf 'Failed to connect to bus: Permission denied\n' >&2; exit 1 ;;
            bus-disconnected) printf 'Failed to connect to bus: Host is down\n' >&2; exit 1 ;;
            masked) printf 'masked\n' ;;
            bad-setting) printf 'bad-setting\n' ;;
            empty-response) : ;;
            unknown-response) printf 'future-load-state\n' ;;
            *) printf 'loaded\n' ;;
        esac
        ;;
    is-enabled)
        # A service can run without boot-time enablement. This branch ensures
        # reverting to the old command fails the loaded-disabled regression.
        case "$SBH_TEST_SERVICE_STATE" in
            loaded-disabled|unloaded|unloaded-exit-four) printf 'disabled\n'; exit 1 ;;
            *) printf 'enabled\n' ;;
        esac
        ;;
    restart)
        if [ "$SBH_TEST_SERVICE_STATE" = restart-failure ]; then
            printf 'fixture restart denied\n' >&2
            exit 23
        fi
        # Model ExecStart pointing at the installed path, never the old inode.
        actual=$(sha256sum "$SBH_TEST_SERVICE_BINARY")
        [ "${actual%% *}" = "$SBH_TEST_EXPECTED_SHA" ]
        "$SBH_TEST_SERVICE_BINARY" --version >> "$SBH_TEST_RESTART_VERSIONS"
        : > "$SBH_TEST_RESTART_REQUEST"
        ;;
    *) printf 'unexpected systemctl command: %s\n' "$*" >&2; exit 91 ;;
esac
"#;

const BUSCTL: &str = r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$SBH_TEST_BUSCTL_LOG"
[ "${LC_ALL-}" = C ]
case "${1-}" in --user|--system) ;; *) exit 92 ;; esac
shift
while [ "${1-}" != get-property ]; do
    case "${1-}" in
        --json=short|--timeout=*|--auto-start=no|--allow-interactive-authorization=no) ;;
        *) exit 92 ;;
    esac
    shift
done
shift
[ "$1" = org.freedesktop.systemd1 ]
[ "$2" = /org/freedesktop/systemd1/unit/sbh_2eservice ]
shift 2
case "$*" in
    'org.freedesktop.systemd1.Service ExecStart')
        if [ "$SBH_TEST_SERVICE_STATE" = target-query-failure ]; then
            printf 'fixture ExecStart access denied\n' >&2
            exit 24
        fi
        cat "$SBH_TEST_EXEC_START_JSON"
        ;;
    'org.freedesktop.systemd1.Unit ActiveState SubState')
        case "$SBH_TEST_SERVICE_STATE" in
            activation-query-failure) printf 'fixture activation access denied\n' >&2; exit 25 ;;
            condition-skipped) active=inactive; sub=dead ;;
            exited-runtime) active=active; sub=exited ;;
            delayed-activation)
                if [ -e "$SBH_TEST_RUNTIME_PID.first" ]; then
                    active=active; sub=running
                else
                    : > "$SBH_TEST_RUNTIME_PID.first"
                    active=activating; sub=start
                fi
                ;;
            *) active=active; sub=running ;;
        esac
        printf '{"type":"s","data":"%s"}\n{"type":"s","data":"%s"}\n' "$active" "$sub"
        ;;
    'org.freedesktop.systemd1.Service MainPID ExecMainStartTimestampMonotonic')
        attempt=0
        while [ ! -s "$SBH_TEST_RUNTIME_PID" ]; do
            attempt=$((attempt + 1))
            if [ "$attempt" -gt 100 ]; then
                printf 'fixture runtime not ready\n' >&2
                exit 96
            fi
            sleep 0.01
        done
        pid=$(cat "$SBH_TEST_RUNTIME_PID")
        if [ "$SBH_TEST_SERVICE_STATE" = zero-runtime-pid ]; then pid=0; fi
        printf '{"type":"u","data":%s}\n{"type":"t","data":1}\n' "$pid"
        ;;
    *) printf 'unexpected busctl property query: %s\n' "$*" >&2; exit 93 ;;
esac
"#;

// A live process running the selected SBH image, without starting its daemon.
// Fill stdout's pipe before launching --version, so the process blocks inside
// the installed executable. The reader stays open until Drop kills/reaps it.
struct HeldVersion {
    child: Child,
    _reader: OwnedFd,
}

impl HeldVersion {
    fn start(binary: &Path) -> Self {
        use nix::errno::Errno;
        use nix::fcntl::{FcntlArg, OFlag, fcntl};
        use nix::unistd::{pipe2, write};

        let (reader, writer) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).unwrap();
        loop {
            match write(&writer, &[0_u8; 4096]) {
                Ok(n) => assert!(n > 0),
                Err(Errno::EAGAIN) => break,
                Err(error) => panic!("fill version pipe: {error}"),
            }
        }
        fcntl(&writer, FcntlArg::F_SETFL(OFlag::empty())).unwrap();
        let child = Command::new(binary)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::from(writer))
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Self {
            child,
            _reader: reader,
        }
    }
}

impl Drop for HeldVersion {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct FinishOnDrop<'a>(&'a AtomicBool);

impl Drop for FinishOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    home: PathBuf,
    binary: PathBuf,
    service_binary: PathBuf,
    exec_start: PathBuf,
    bus_calls: PathBuf,
    manifest: PathBuf,
    expected_sha: String,
    path: OsString,
    calls: PathBuf,
    updater_exe: PathBuf,
    versions: PathBuf,
}

fn sha256(path: &Path) -> String {
    // sha2 0.11's digest array has no `LowerHex`; hex-encode the bytes.
    use std::fmt::Write as _;
    Sha256::digest(fs::read(path).unwrap()).iter().fold(
        String::with_capacity(64),
        |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        },
    )
}

fn executable(path: &Path, contents: &[u8]) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

impl Fixture {
    fn new(relative_install: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let home = root.join("home");
        let binary = root.join(relative_install);
        let tools = root.join("tools");
        let payload = root.join("payload");
        for directory in [
            home.as_path(),
            tools.as_path(),
            payload.as_path(),
            binary.parent().unwrap(),
        ] {
            fs::create_dir_all(directory).unwrap();
        }
        fs::write(home.join("config.toml"), "").unwrap();
        fs::copy(env!("CARGO_BIN_EXE_sbh"), &binary).unwrap();
        let replacement = payload.join("sbh");
        fs::copy(env!("CARGO_BIN_EXE_sbh"), &replacement).unwrap();
        // A harmless ELF trailer makes the promoted file observably different
        // while retaining the patched updater for a second update invocation.
        fs::OpenOptions::new()
            .append(true)
            .open(&replacement)
            .unwrap()
            .write_all(b"\nSBH issue 35 replacement fixture\n")
            .unwrap();
        let expected_sha = sha256(&replacement);
        assert_ne!(sha256(&binary), expected_sha);

        let tag = format!("v{}", env!("CARGO_PKG_VERSION"));
        let contract = resolve_updater_artifact_contract(
            HostSpecifier::detect().unwrap(),
            ReleaseChannel::Stable,
            Some(&tag),
        )
        .unwrap();
        let archive = root.join(contract.asset_name());
        let output = Command::new("tar")
            .env("XZ_OPT", "-0")
            .arg("-cJf")
            .arg(&archive)
            .arg("-C")
            .arg(&payload)
            .arg("sbh")
            .output()
            .unwrap();
        assert!(output.status.success(), "tar failed: {output:?}");
        // The updater accepts a bundle only under the release asset names.
        let checksum = root.join(contract.checksum_name());
        fs::write(
            &checksum,
            format!("{}  {}\n", sha256(&archive), contract.asset_name()),
        )
        .unwrap();
        let manifest = root.join("bundle.json");
        let bundle = OfflineBundleManifest {
            version: "1".to_string(),
            repository: RELEASE_REPOSITORY.to_string(),
            release_tag: tag,
            artifacts: vec![OfflineBundleArtifact {
                target: contract.target.triple.to_string(),
                archive: archive.to_str().unwrap().to_string(),
                checksum: checksum.to_str().unwrap().to_string(),
                sigstore_bundle: None,
            }],
        };
        fs::write(&manifest, serde_json::to_vec(&bundle).unwrap()).unwrap();
        executable(&tools.join("systemctl"), SYSTEMCTL.as_bytes());
        executable(&tools.join("busctl"), BUSCTL.as_bytes());
        executable(
            &tools.join("sbh"),
            b"#!/bin/sh\nprintf 'unrelated PATH binary invoked\\n' >&2\nexit 99\n",
        );
        let mut paths = vec![tools];
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_else(|| OsString::from("/usr/bin:/bin")),
        ));
        let mut fixture = Self {
            home,
            service_binary: binary.clone(),
            binary,
            exec_start: root.join("exec-start.json"),
            bus_calls: root.join("busctl.log"),
            manifest,
            expected_sha,
            path: std::env::join_paths(paths).unwrap(),
            calls: root.join("systemctl.log"),
            updater_exe: root.join("updater-exe.log"),
            versions: root.join("versions.log"),
            _temp: temp,
        };
        fixture.set_service_binary(fixture.binary.clone());
        fixture
    }

    fn set_service_binary(&mut self, path: PathBuf) {
        let value = json!({
            "type": "a(sasbttttuii)",
            "data": [[path, [path, "daemon"], false, 0, 0, 0, 0, 0, 0, 0]]
        });
        fs::write(&self.exec_start, serde_json::to_vec(&value).unwrap()).unwrap();
        self.service_binary = path;
    }

    fn run(&self, service_state: &str, args: &[&str]) -> Output {
        let invocation = tempfile::tempdir_in(&self.home).unwrap();
        let request = invocation.path().join("restart-request");
        let pid_file = invocation.path().join("runtime-pid");
        let old_runtime = invocation.path().join("old-sbh");
        if service_state == "stale-runtime" {
            fs::copy(&self.binary, &old_runtime).unwrap();
        }
        let finished = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let helper = scope.spawn(|| {
                let mut held = None;
                while !finished.load(Ordering::Relaxed) {
                    if request.is_file() && held.is_none() {
                        let binary = if service_state == "stale-runtime" {
                            &old_runtime
                        } else {
                            &self.service_binary
                        };
                        let process = HeldVersion::start(binary);
                        fs::write(&pid_file, process.child.id().to_string()).unwrap();
                        held = Some(process);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
            // Stop and reap the fixture even if spawning the updater fails.
            let finish = FinishOnDrop(&finished);
            let output = Command::new(&self.binary)
                .args(["update", "--json", "--offline"])
                .arg(&self.manifest)
                .arg("--config")
                .arg(self.home.join("config.toml"))
                .args(args)
                .env("HOME", &self.home)
                .env("XDG_CONFIG_HOME", self.home.join(".config"))
                .env("XDG_DATA_HOME", self.home.join(".local/share"))
                .env("XDG_CACHE_HOME", self.home.join(".cache"))
                .env_remove("SBH_CONFIG")
                .env_remove("SBH_CONFIG_PATH")
                .env("LC_ALL", "C.UTF-8")
                .env("PATH", &self.path)
                .env("SBH_TEST_SERVICE_STATE", service_state)
                .env("SBH_TEST_SERVICE_BINARY", &self.service_binary)
                .env("SBH_TEST_EXEC_START_JSON", &self.exec_start)
                .env("SBH_TEST_BUSCTL_LOG", &self.bus_calls)
                .env("SBH_TEST_EXPECTED_SHA", &self.expected_sha)
                .env("SBH_TEST_SYSTEMCTL_LOG", &self.calls)
                .env("SBH_TEST_UPDATER_EXE", &self.updater_exe)
                .env("SBH_TEST_RESTART_VERSIONS", &self.versions)
                .env("SBH_TEST_RESTART_REQUEST", &request)
                .env("SBH_TEST_RUNTIME_PID", &pid_file)
                .output();
            drop(finish);
            helper.join().unwrap();
            output.unwrap()
        })
    }

    fn assert_applied(&self, output: &Output, restart_status: &str) -> Value {
        let report: Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("invalid update JSON: {error}; {output:?}"));
        assert_eq!(report["applied"], true, "{report}");
        assert_eq!(report["install_path"], self.binary.to_str().unwrap());
        assert_eq!(
            report["service_restart"]["status"], restart_status,
            "{report}"
        );
        assert_eq!(sha256(&self.binary), self.expected_sha);
        let observed = fs::read_to_string(&self.updater_exe).unwrap();
        let deleted = format!("{} (deleted)", self.binary.display());
        assert!(!observed.is_empty());
        assert!(observed.lines().all(|line| line == deleted), "{observed}");
        report
    }
}

#[test]
fn user_and_custom_installations_survive_two_actual_updates() {
    for location in [
        "home/.local/bin/sbh",
        "opt/sbhprev/sbh",
        "custom destination/sbh",
    ] {
        let fixture = Fixture::new(location);
        for _ in 0..2 {
            let old_inode = fs::metadata(&fixture.binary).unwrap().ino();
            let output = fixture.run("unloaded", &["--force"]);
            assert_eq!(output.status.code(), Some(0), "{output:?}");
            let report = fixture.assert_applied(&output, "skipped");
            assert_eq!(report["success"], true);
            assert_ne!(fs::metadata(&fixture.binary).unwrap().ino(), old_inode);
        }
        let calls = fs::read_to_string(&fixture.calls).unwrap();
        assert_eq!(calls.lines().count(), 2, "{calls}");
        assert!(!calls.contains("restart"));
        assert!(!fixture.versions.exists());
        assert!(!fixture.bus_calls.exists());
    }
}

#[test]
fn loaded_user_service_restarts_the_new_executable_on_each_update() {
    for location in [
        "home/.local/bin/sbh",
        "custom destination/sbh",
        "quoted\" destination/sbh",
    ] {
        let fixture = Fixture::new(location);
        for _ in 0..2 {
            let output = fixture.run("loaded", &["--force", "--user"]);
            assert_eq!(output.status.code(), Some(0), "{output:?}");
            let report = fixture.assert_applied(&output, "restarted");
            assert_eq!(report["success"], true);
            assert_eq!(report["service_restart"]["scope"], "user");
        }
        let calls = fs::read_to_string(&fixture.calls).unwrap();
        assert_eq!(calls.matches("--user restart sbh.service").count(), 2);
        let queries = fs::read_to_string(&fixture.bus_calls).unwrap();
        assert_eq!(
            queries
                .matches("org.freedesktop.systemd1.Service ExecStart")
                .count(),
            4
        );
        assert!(
            queries
                .matches("org.freedesktop.systemd1.Unit ActiveState SubState")
                .count()
                >= 4
        );
        assert!(queries.lines().all(|line| line.starts_with("--user ")));
        let versions = fs::read_to_string(&fixture.versions).unwrap();
        assert_eq!(versions.lines().count(), 2);
        assert!(
            versions
                .lines()
                .all(|line| line.contains(env!("CARGO_PKG_VERSION")))
        );
    }
}

#[test]
fn real_restart_failure_preserves_applied_update_and_exit_two() {
    let fixture = Fixture::new("custom destination/sbh");
    let output = fixture.run("restart-failure", &["--force", "--user"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let report = fixture.assert_applied(&output, "failed");
    assert_eq!(report["success"], false);
    let error = report["service_restart"]["error"].as_str().unwrap();
    assert!(error.contains("fixture restart denied"), "{error}");
    assert!(error.contains("23"), "{error}");
    assert!(!fixture.versions.exists());
    assert!(
        !fs::read_to_string(&fixture.bus_calls)
            .unwrap()
            .contains("ActiveState")
    );
}

#[test]
fn system_scope_preserves_privilege_checks_after_replacement() {
    let fixture = Fixture::new("opt/sbhprev/sbh");
    let output = fixture.run("loaded", &["--force"]);
    let report = if nix::unistd::geteuid().is_root() {
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        fixture.assert_applied(&output, "restarted")
    } else {
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(!fixture.versions.exists());
        let calls = fs::read_to_string(&fixture.calls).unwrap();
        assert!(!calls.contains("restart"), "{calls}");
        fixture.assert_applied(&output, "failed")
    };
    assert_eq!(report["service_restart"]["scope"], "system");
    assert!(
        fs::read_to_string(&fixture.bus_calls)
            .unwrap()
            .starts_with("--system ")
    );
}

#[test]
fn container_without_a_systemd_manager_does_not_fail_an_applied_update() {
    let fixture = Fixture::new("home/.local/bin/sbh");
    let output = fixture.run("no-manager", &["--force"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report = fixture.assert_applied(&output, "skipped");
    assert_eq!(report["success"], true);
    assert!(!fixture.bus_calls.exists());
}

#[test]
fn check_dry_run_and_up_to_date_do_not_restart_or_replace() {
    let fixture = Fixture::new("home/.local/bin/sbh");
    let original_sha = sha256(&fixture.binary);
    let cases: &[&[&str]] = &[&["--check", "--force"], &["--dry-run", "--force"], &[]];
    for args in cases {
        let output = fixture.run("loaded", args);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["success"], true);
        assert_eq!(report["applied"], false);
        assert!(report["service_restart"].is_null());
        assert_eq!(sha256(&fixture.binary), original_sha);
        assert!(!fixture.calls.exists());
        assert!(!fixture.bus_calls.exists());
    }
}

#[test]
fn running_but_disabled_service_is_restarted_after_update() {
    let fixture = Fixture::new("custom destination/sbh");
    let output = fixture.run("loaded-disabled", &["--force", "--user"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report = fixture.assert_applied(&output, "restarted");
    assert_eq!(report["success"], true);
    let calls = fs::read_to_string(&fixture.calls).unwrap();
    assert!(calls.contains("--user show sbh.service --property=LoadState --value"));
    assert!(calls.contains("--user restart sbh.service"));
    assert!(!calls.contains("is-enabled"));
    assert_eq!(
        fs::read_to_string(&fixture.versions)
            .unwrap()
            .lines()
            .count(),
        1
    );
}

#[test]
fn absent_user_units_are_successful_with_either_unknown_unit_exit_code() {
    for state in ["unloaded", "unloaded-exit-four"] {
        let fixture = Fixture::new("home/.local/bin/sbh");
        let output = fixture.run(state, &["--force", "--user"]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let report = fixture.assert_applied(&output, "skipped");
        assert_eq!(report["success"], true);
        assert_eq!(report["service_restart"]["scope"], "user");
        assert!(!fixture.versions.exists());
        assert!(!fixture.bus_calls.exists());
    }
}

#[test]
fn inspection_failures_never_report_a_successful_skipped_update() {
    for (state, diagnostic) in [
        ("query-failure", "fixture state query denied"),
        ("bus-failure", "Permission denied"),
        ("bus-disconnected", "Host is down"),
        ("masked", "LoadState=masked"),
        ("bad-setting", "LoadState=bad-setting"),
        ("empty-response", "unexpected LoadState"),
        ("unknown-response", "future-load-state"),
    ] {
        let fixture = Fixture::new("opt/sbhprev/sbh");
        let output = fixture.run(state, &["--force", "--user"]);
        assert_eq!(output.status.code(), Some(2), "{state}: {output:?}");
        let report = fixture.assert_applied(&output, "failed");
        assert_eq!(report["success"], false);
        let error = report["service_restart"]["error"].as_str().unwrap();
        assert!(error.contains(diagnostic), "{state}: {error}");
        let calls = fs::read_to_string(&fixture.calls).unwrap();
        assert!(!calls.contains("restart"), "{state}: {calls}");
        assert!(!fixture.versions.exists());
        assert!(!fixture.bus_calls.exists());
    }
}

#[test]
fn a_loaded_unit_pointing_at_another_installation_is_not_restarted() {
    let mut fixture = Fixture::new("home/.local/bin/sbh");
    let other = fixture.home.join("other-sbh");
    fs::copy(&fixture.binary, &other).unwrap();
    let before = sha256(&other);
    fixture.set_service_binary(other.clone());
    let output = fixture.run("loaded", &["--force", "--user"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let report = fixture.assert_applied(&output, "failed");
    assert_eq!(report["success"], false);
    let error = report["service_restart"]["error"].as_str().unwrap();
    assert!(
        error.contains("refusing to restart a different installation"),
        "{error}"
    );
    assert_eq!(sha256(&other), before);
    assert!(
        !fs::read_to_string(&fixture.calls)
            .unwrap()
            .contains("restart")
    );
    assert!(!fixture.versions.exists());
}

#[test]
fn effective_exec_start_symlink_tracks_both_replacements() {
    let mut fixture = Fixture::new("custom destination/sbh");
    let link = fixture.home.join("service-sbh");
    std::os::unix::fs::symlink(&fixture.binary, &link).unwrap();
    fixture.set_service_binary(link);
    for _ in 0..2 {
        let output = fixture.run("loaded", &["--force", "--user"]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        fixture.assert_applied(&output, "restarted");
    }
    assert_eq!(
        fs::read_to_string(&fixture.versions)
            .unwrap()
            .lines()
            .count(),
        2
    );
}

#[test]
fn effective_exec_start_retaining_the_old_inode_is_rejected() {
    let mut fixture = Fixture::new("opt/sbhprev/sbh");
    let old = fixture.home.join("old-inode");
    fs::hard_link(&fixture.binary, &old).unwrap();
    fixture.set_service_binary(old);
    let output = fixture.run("loaded", &["--force", "--user"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let report = fixture.assert_applied(&output, "failed");
    assert!(
        report["service_restart"]["error"]
            .as_str()
            .unwrap()
            .contains("different installation")
    );
    assert!(
        !fs::read_to_string(&fixture.calls)
            .unwrap()
            .contains("restart")
    );
}

#[test]
fn failed_exec_start_verification_never_restarts_a_loaded_service() {
    for state in ["target-query-failure", "malformed-target"] {
        let fixture = Fixture::new("opt/sbhprev/sbh");
        if state == "malformed-target" {
            fs::write(&fixture.exec_start, "not json").unwrap();
        }
        let output = fixture.run(state, &["--force", "--user"]);
        assert_eq!(output.status.code(), Some(2), "{state}: {output:?}");
        let report = fixture.assert_applied(&output, "failed");
        assert_eq!(report["success"], false);
        let error = report["service_restart"]["error"].as_str().unwrap();
        assert!(error.contains("ExecStart"), "{error}");
        assert!(
            !fs::read_to_string(&fixture.calls)
                .unwrap()
                .contains("restart")
        );
        assert!(!fixture.versions.exists());
    }
}

#[test]
fn successful_restart_job_without_activation_is_a_failure() {
    for state in ["condition-skipped", "exited-runtime", "zero-runtime-pid"] {
        let fixture = Fixture::new("home/.local/bin/sbh");
        let output = fixture.run(state, &["--force", "--user"]);
        assert_eq!(output.status.code(), Some(2), "{state}: {output:?}");
        let report = fixture.assert_applied(&output, "failed");
        assert_eq!(report["success"], false);
        let calls = fs::read_to_string(&fixture.calls).unwrap();
        assert_eq!(calls.matches("--user restart sbh.service").count(), 1);
        assert!(
            fixture.versions.is_file(),
            "the restart command really succeeded"
        );
    }
}

#[test]
fn running_old_image_after_successful_restart_is_a_failure() {
    let fixture = Fixture::new("custom destination/sbh");
    let output = fixture.run("stale-runtime", &["--force", "--user"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let report = fixture.assert_applied(&output, "failed");
    assert_eq!(report["success"], false);
    let error = report["service_restart"]["error"].as_str().unwrap();
    assert!(
        error.contains("activation") || error.contains("running executable differs"),
        "{error}"
    );
    assert_eq!(
        fs::read_to_string(&fixture.calls)
            .unwrap()
            .matches("--user restart sbh.service")
            .count(),
        1
    );
}

#[test]
fn activation_query_failure_is_not_reported_as_restarted() {
    let fixture = Fixture::new("opt/sbhprev/sbh");
    let output = fixture.run("activation-query-failure", &["--force", "--user"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let report = fixture.assert_applied(&output, "failed");
    assert_eq!(report["success"], false);
    assert!(
        report["service_restart"]["error"]
            .as_str()
            .unwrap()
            .contains("fixture activation access denied")
    );
    assert_eq!(
        fs::read_to_string(&fixture.calls)
            .unwrap()
            .matches("--user restart sbh.service")
            .count(),
        1
    );
}

#[test]
fn activation_waits_for_startup_to_finish_without_restarting_twice() {
    let fixture = Fixture::new("home/.local/bin/sbh");
    let output = fixture.run("delayed-activation", &["--force", "--user"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report = fixture.assert_applied(&output, "restarted");
    assert_eq!(report["success"], true);
    assert_eq!(
        fs::read_to_string(&fixture.calls)
            .unwrap()
            .matches("--user restart sbh.service")
            .count(),
        1
    );
    assert!(
        fs::read_to_string(&fixture.bus_calls)
            .unwrap()
            .matches("ActiveState SubState")
            .count()
            >= 3
    );
}
