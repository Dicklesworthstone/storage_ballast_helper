//! The root `install.sh` (the short one-liner installer), run for real
//! against stubbed `curl` and `gh` that serve a fake release from disk, so
//! no network is used (bd-fgxo).

#![cfg(unix)]

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

const ASSETS: [&str; 4] = [
    "sbh_linux_amd64",
    "sbh_linux_arm64",
    "sbh_darwin_amd64",
    "sbh_darwin_arm64",
];

fn executable(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// A fake release server on disk: `srv/latest` names the latest tag and
/// `srv/<tag>/` holds the four binaries (shell scripts that print their
/// version) and a SHA256SUMS covering them.
struct Release {
    dir: tempfile::TempDir,
}

impl Release {
    fn new(latest: &str, tags: &[&str]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let srv = dir.path().join("srv");
        fs::create_dir_all(&srv).unwrap();
        fs::write(srv.join("latest"), latest).unwrap();
        for tag in tags {
            let release = srv.join(tag);
            fs::create_dir_all(&release).unwrap();
            let mut sums = String::new();
            for asset in ASSETS {
                let body = format!("#!/bin/sh\necho \"sbh {}\"\n", tag.trim_start_matches('v'));
                fs::write(release.join(asset), &body).unwrap();
                for byte in Sha256::digest(body.as_bytes()) {
                    write!(sums, "{byte:02x}").unwrap();
                }
                writeln!(sums, "  {asset}").unwrap();
            }
            fs::write(release.join("SHA256SUMS"), sums).unwrap();
        }
        let bin = dir.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        executable(
            &bin.join("curl"),
            r#"#!/bin/bash
out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in -o) out="$2"; shift 2 ;; -*) shift ;; *) url="$1"; shift ;; esac
done
case "$url" in
  */releases/latest) printf '{"url":"x","tag_name":"%s","name":"x"}' "$(cat "$FAKE_SRV/latest")" ;;
  */releases/download/*)
    file="$FAKE_SRV/${url#*/releases/download/}"
    [ -f "$file" ] || exit 22
    if [ -n "$out" ]; then cp "$file" "$out"; else cat "$file"; fi ;;
  *) exit 22 ;;
esac
"#,
        );
        executable(&bin.join("gh"), "#!/bin/bash\ncat \"$FAKE_SRV/latest\"\n");
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn install(&self, args: &[&str], env_dest: Option<&Path>) -> Output {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("install.sh");
        let mut command = Command::new("bash");
        command
            .arg(script)
            .args(args)
            .env_clear()
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.path("bin").display()),
            )
            .env("HOME", self.dir.path())
            .env("FAKE_SRV", self.path("srv"));
        // Always point the fallback at a temp dir: a script that ignores its
        // arguments must never reach the host's /usr/local/bin (it did, once,
        // when this suite was run against the pre-fix script).
        let fallback = self.path("fallback-dest");
        command.env("SBH_INSTALL_DIR", env_dest.unwrap_or(&fallback));
        command.output().unwrap()
    }
}

fn installed_version(dir: &Path) -> String {
    let output = Command::new(dir.join("sbh")).output().unwrap();
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[test]
fn dest_is_honoured_over_the_environment_and_creates_the_directory() {
    let release = Release::new("v9.9.9", &["v9.9.9"]);
    let env_dir = release.path("env-dest");
    fs::create_dir_all(&env_dir).unwrap();
    let dest = release.path("flag-dest/nested");

    let output = release.install(&["--dest", dest.to_str().unwrap()], Some(&env_dir));
    assert!(output.status.success(), "{output:?}");
    assert_eq!(installed_version(&dest), "sbh 9.9.9");
    assert!(
        !env_dir.join("sbh").exists(),
        "--dest must win over SBH_INSTALL_DIR"
    );

    let equals = release.path("equals-dest");
    let output = release.install(&[&format!("--dest={}", equals.display())], None);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(installed_version(&equals), "sbh 9.9.9");
}

#[test]
fn version_selects_a_release_other_than_the_latest() {
    let release = Release::new("v9.9.9", &["v9.9.8", "v9.9.9"]);
    let dest = release.path("dest");
    let output = release.install(
        &["--dest", dest.to_str().unwrap(), "--version", "9.9.8"],
        None,
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(installed_version(&dest), "sbh 9.9.8");
    assert!(!release.path("fallback-dest").join("sbh").exists());
}

#[test]
fn bad_arguments_exit_two_and_install_nothing() {
    let release = Release::new("v9.9.9", &["v9.9.9"]);
    let env_dir = release.path("env-dest");
    fs::create_dir_all(&env_dir).unwrap();
    for args in [
        vec!["--bogus"],
        vec!["--dest"],
        vec!["--dest="],
        vec!["--version"],
        vec!["/opt/somewhere"],
    ] {
        let output = release.install(&args, Some(&env_dir));
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(!env_dir.join("sbh").exists(), "{args:?} installed anyway");
    }
    let help = release.install(&["--help"], Some(&env_dir));
    assert!(help.status.success(), "{help:?}");
    assert!(String::from_utf8_lossy(&help.stdout).contains("--dest <dir>"));
    assert!(!env_dir.join("sbh").exists());
}
