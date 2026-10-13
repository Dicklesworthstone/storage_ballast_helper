//! Linux CLI transaction ownership, including the post-publication restart window.
#![cfg(all(target_os = "linux", feature = "cli"))]

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use storage_ballast_helper::cli::{
    HostSpecifier, OfflineBundleArtifact, OfflineBundleManifest, RELEASE_REPOSITORY,
    ReleaseChannel, resolve_updater_artifact_contract,
};
use storage_ballast_helper::core::hex_lower;
use storage_ballast_helper::update_handoff::acquire_update_lock;

const SYSTEMCTL: &str = r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$SBH_TEST_TRANSACTION_ROOT/calls"
if [ "${1-}" = --user ]; then shift; fi
case "$*" in
    'show sbh.service --property=LoadState --value') printf 'loaded\n' ;;
    'restart sbh.service')
        : > "$SBH_TEST_TRANSACTION_ROOT/restart-entered"
        i=0
        while [ ! -e "$SBH_TEST_TRANSACTION_ROOT/release-restart" ] && [ "$i" -lt 600 ]; do
            i=$((i + 1))
            sleep 0.05
        done
        printf 'fixture restart failure after publication\n' >&2
        exit 23
        ;;
    *) printf 'unexpected systemctl arguments: %s\n' "$*" >&2; exit 91 ;;
esac
"#;

const BUSCTL: &str = r#"#!/bin/sh
set -eu
case "$*" in
    *' org.freedesktop.systemd1.Service ExecStart')
        cat "$SBH_TEST_TRANSACTION_ROOT/exec-start.json"
        ;;
    *) printf 'unexpected busctl arguments: %s\n' "$*" >&2; exit 92 ;;
esac
"#;

struct Fixture {
    temp: tempfile::TempDir,
    binary: PathBuf,
}

fn digest(path: &Path) -> String {
    hex_lower(Sha256::digest(fs::read(path).unwrap()))
}

fn executable(path: &Path, contents: &[u8]) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

impl Fixture {
    fn new(relative: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join(relative).join("sbh");
        fs::create_dir_all(binary.parent().unwrap()).unwrap();
        fs::create_dir_all(temp.path().join("home")).unwrap();
        fs::create_dir(temp.path().join("tools")).unwrap();
        fs::write(temp.path().join("config.toml"), "").unwrap();
        fs::copy(env!("CARGO_BIN_EXE_sbh"), &binary).unwrap();
        executable(&temp.path().join("tools/systemctl"), SYSTEMCTL.as_bytes());
        executable(&temp.path().join("tools/busctl"), BUSCTL.as_bytes());
        let property = json!({
            "type": "a(sasbttttuii)",
            "data": [[binary, [binary, "daemon"], false, 0, 0, 0, 0, 0, 0, 0]]
        });
        fs::write(
            temp.path().join("exec-start.json"),
            serde_json::to_vec(&property).unwrap(),
        )
        .unwrap();
        Self { temp, binary }
    }

    fn root(&self) -> &Path {
        self.temp.path()
    }

    fn command(&self) -> Command {
        let home = self.root().join("home");
        let path = std::env::join_paths([
            self.root().join("tools"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
        ])
        .unwrap();
        let mut command = Command::new(&self.binary);
        command
            .env_clear()
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("XDG_DATA_HOME", home.join(".local/share"))
            .env("XDG_CACHE_HOME", home.join(".cache"))
            .env("TMPDIR", self.root())
            .env("SBH_TEST_TRANSACTION_ROOT", self.root())
            .env("PATH", path)
            .arg("--config")
            .arg(self.root().join("config.toml"))
            .args(["--json", "update"])
            .stdin(Stdio::null());
        if let Some(path) = std::env::var_os("LD_LIBRARY_PATH") {
            command.env("LD_LIBRARY_PATH", path);
        }
        command
    }

    fn bundle(&self) -> (PathBuf, String) {
        let payload = self.root().join("payload");
        fs::create_dir(&payload).unwrap();
        let replacement = payload.join("sbh");
        fs::copy(&self.binary, &replacement).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&replacement)
            .unwrap()
            .write_all(b"\ntransaction-lock replacement fixture\n")
            .unwrap();
        let expected = digest(&replacement);
        let tag = format!("v{}", env!("CARGO_PKG_VERSION"));
        let contract = resolve_updater_artifact_contract(
            HostSpecifier::detect().unwrap(),
            ReleaseChannel::Stable,
            Some(&tag),
        )
        .unwrap();
        let archive = self.root().join(contract.asset_name());
        let packed = Command::new("tar")
            .env("XZ_OPT", "-0")
            .arg("-cJf")
            .arg(&archive)
            .arg("-C")
            .arg(&payload)
            .arg("sbh")
            .output()
            .unwrap();
        assert!(packed.status.success(), "{packed:?}");
        let checksum = self.root().join(contract.checksum_name());
        fs::write(
            &checksum,
            format!("{}  {}\n", digest(&archive), contract.asset_name()),
        )
        .unwrap();
        let manifest = OfflineBundleManifest {
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
        let path = self.root().join("bundle.json");
        fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        (path, expected)
    }
}

struct Running {
    child: Child,
    reaped: bool,
}

impl Running {
    fn status(&mut self) -> Option<ExitStatus> {
        let status = self.child.try_wait().unwrap();
        self.reaped = status.is_some();
        status
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if !self.reaped {
            // This fixture started its own process group. Terminate it only
            // while the owned, unreaped leader still pins the group identity.
            let pid = nix::unistd::Pid::from_raw(i32::try_from(self.child.id()).unwrap());
            let _ = nix::sys::signal::killpg(pid, nix::sys::signal::Signal::SIGKILL);
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn assert_contention(output: &Output) {
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], false);
    assert_eq!(report["applied"], false);
    assert_eq!(report["exit_code"], 2);
    assert!(report["service_restart"].is_null());
    assert!(
        report["error"]
            .as_str()
            .unwrap()
            .contains("another sbh update or rollback"),
        "{report}"
    );
}

#[test]
fn contention_precedes_update_and_rollback_but_not_backup_inventory() {
    let fixture = Fixture::new("home/.local/bin");
    let before = digest(&fixture.binary);
    let guard = acquire_update_lock(&fixture.binary).unwrap();
    let output = fixture
        .command()
        .args(["--force", "--offline"])
        .arg(fixture.root().join("missing-bundle.json"))
        .output()
        .unwrap();
    assert_contention(&output);
    let output = fixture.command().arg("--rollback").output().unwrap();
    assert_contention(&output);
    let output = fixture.command().arg("--list-backups").output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(!fixture.root().join("calls").exists());
    assert!(
        !fixture
            .root()
            .join("home/.local/share/sbh/backups")
            .exists()
    );
    assert_eq!(digest(&fixture.binary), before);
    drop(guard);
    // The unlocked command now reaches offline validation rather than the lock.
    let output = fixture
        .command()
        .args(["--force", "--offline"])
        .arg(fixture.root().join("missing-bundle.json"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("another sbh update or rollback"));
    assert!(acquire_update_lock(&fixture.binary).is_ok());
    assert_eq!(digest(&fixture.binary), before);
}

#[test]
fn real_replacement_retains_ownership_during_restart_and_releases_on_failure() {
    let fixture = Fixture::new("custom destination");
    let (bundle, expected) = fixture.bundle();
    let before = fs::metadata(&fixture.binary).unwrap().ino();
    let stdout = fixture.root().join("first.json");
    let stderr = fixture.root().join("first.stderr");
    let mut first = Running {
        child: fixture
            .command()
            .args(["--force", "--user", "--offline"])
            .arg(&bundle)
            .stdout(File::create(&stdout).unwrap())
            .stderr(File::create(&stderr).unwrap())
            .process_group(0)
            .spawn()
            .unwrap(),
        reaped: false,
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    while !fixture.root().join("restart-entered").exists() {
        assert!(
            first.status().is_none(),
            "updater exited before restart: {}\n{}",
            fs::read_to_string(&stdout).unwrap(),
            fs::read_to_string(&stderr).unwrap()
        );
        assert!(Instant::now() < deadline, "updater never reached restart");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_ne!(fs::metadata(&fixture.binary).unwrap().ino(), before);
    assert_eq!(digest(&fixture.binary), expected);
    let calls_before = fs::read(fixture.root().join("calls")).unwrap();
    // This is the actual newly installed SBH binary, not a script pretending
    // to update. Neither another apply nor a rollback may cross this boundary.
    let second = fixture
        .command()
        .args(["--force", "--user", "--offline"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert_contention(&second);
    let rollback = fixture.command().arg("--rollback").output().unwrap();
    assert_contention(&rollback);
    assert_eq!(digest(&fixture.binary), expected);
    assert_eq!(
        fs::read(fixture.root().join("calls")).unwrap(),
        calls_before
    );
    fs::write(fixture.root().join("release-restart"), b"done").unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = first.status() {
            break status;
        }
        assert!(Instant::now() < deadline, "updater did not finish");
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(2));
    let report: Value = serde_json::from_slice(&fs::read(stdout).unwrap()).unwrap();
    assert_eq!(report["applied"], true);
    assert_eq!(report["success"], false);
    assert_eq!(report["service_restart"]["status"], "failed");
    assert!(
        report["service_restart"]["error"]
            .as_str()
            .unwrap()
            .contains("fixture restart failure after publication"),
        "{report}"
    );
    assert!(acquire_update_lock(&fixture.binary).is_ok());
    assert_eq!(digest(&fixture.binary), expected);
}
