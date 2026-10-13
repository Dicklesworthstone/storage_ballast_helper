//! Real Linux self-replacement through the CLI, with isolated systemctl fixtures.
#![cfg(all(target_os = "linux", feature = "cli"))]

use std::ffi::OsString;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
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
    is-enabled)
        case "$SBH_TEST_SERVICE_STATE" in
            unloaded) printf 'disabled\n'; exit 1 ;;
            no-manager) printf 'System has not been booted with systemd\n' >&2; exit 1 ;;
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
        ;;
    *) printf 'unexpected systemctl command: %s\n' "$*" >&2; exit 91 ;;
esac
"#;

struct Fixture {
    _temp: tempfile::TempDir,
    home: PathBuf,
    binary: PathBuf,
    manifest: PathBuf,
    expected_sha: String,
    path: OsString,
    calls: PathBuf,
    updater_exe: PathBuf,
    versions: PathBuf,
}

fn sha256(path: &Path) -> String {
    format!("{:x}", Sha256::digest(fs::read(path).unwrap()))
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
        let checksum = root.join("archive.sha256");
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
        executable(
            &tools.join("sbh"),
            b"#!/bin/sh\nprintf 'unrelated PATH binary invoked\\n' >&2\nexit 99\n",
        );
        let mut paths = vec![tools];
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_else(|| OsString::from("/usr/bin:/bin")),
        ));
        Self {
            home,
            binary,
            manifest,
            expected_sha,
            path: std::env::join_paths(paths).unwrap(),
            calls: root.join("systemctl.log"),
            updater_exe: root.join("updater-exe.log"),
            versions: root.join("versions.log"),
            _temp: temp,
        }
    }

    fn run(&self, service_state: &str, args: &[&str]) -> Output {
        Command::new(&self.binary)
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
            .env("PATH", &self.path)
            .env("SBH_TEST_SERVICE_STATE", service_state)
            .env("SBH_TEST_SERVICE_BINARY", &self.binary)
            .env("SBH_TEST_EXPECTED_SHA", &self.expected_sha)
            .env("SBH_TEST_SYSTEMCTL_LOG", &self.calls)
            .env("SBH_TEST_UPDATER_EXE", &self.updater_exe)
            .env("SBH_TEST_RESTART_VERSIONS", &self.versions)
            .output()
            .unwrap()
    }

    fn assert_applied(&self, output: &Output, restart_status: &str) -> Value {
        let report: Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("invalid update JSON: {error}; {output:?}"));
        assert_eq!(report["applied"], true, "{report}");
        assert_eq!(report["install_path"], self.binary.to_str().unwrap());
        assert_eq!(report["service_restart"]["status"], restart_status, "{report}");
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
    }
}

#[test]
fn loaded_user_service_restarts_the_new_executable_on_each_update() {
    let fixture = Fixture::new("home/.local/bin/sbh");
    for _ in 0..2 {
        let output = fixture.run("loaded", &["--force", "--user"]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let report = fixture.assert_applied(&output, "restarted");
        assert_eq!(report["success"], true);
        assert_eq!(report["service_restart"]["scope"], "user");
    }
    let calls = fs::read_to_string(&fixture.calls).unwrap();
    assert_eq!(calls.matches("--user restart sbh.service").count(), 2);
    let versions = fs::read_to_string(&fixture.versions).unwrap();
    assert_eq!(versions.lines().count(), 2);
    assert!(
        versions
            .lines()
            .all(|line| line.contains(env!("CARGO_PKG_VERSION")))
    );
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
}

#[test]
fn container_without_a_systemd_manager_does_not_fail_an_applied_update() {
    let fixture = Fixture::new("home/.local/bin/sbh");
    let output = fixture.run("no-manager", &["--force"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report = fixture.assert_applied(&output, "skipped");
    assert_eq!(report["success"], true);
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
    }
}
