//! Opt-in RAM-scratch qualification against real Linux mount namespaces.
//!
//! Run through `scripts/quality-gate.sh --stage native-ram-scratch`. Each test
//! re-executes itself through `unshare --mount --propagation private` before
//! creating any mounts. Namespace or privilege failures fail the test; they
//! never become successful skips. Only fresh fixture paths are mounted, and
//! namespace teardown releases the mounts. The small fixture directories are
//! retained for inspection; no production mount or cleanup policy is changed.

#![cfg(all(target_os = "linux", feature = "cli"))]

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

use nix::mount::{MntFlags, MsFlags, mount, umount, umount2};
use storage_ballast_helper::monitor::ram_scratch::{
    self, ScratchLimits, ScratchMount, ScratchReport,
};

const CHILD_CASE: &str = "SBH_RAM_SCRATCH_NATIVE_CASE";
const CHILD_ROOT: &str = "SBH_RAM_SCRATCH_NATIVE_ROOT";
const PARENT_NAMESPACE: &str = "SBH_RAM_SCRATCH_PARENT_MOUNT_NAMESPACE";
const PARENT_PID: &str = "SBH_RAM_SCRATCH_PARENT_PID";
const MIB: u64 = 1024 * 1024;

/// The harness parent never changes its mount namespace. `unshare` execs the
/// child without `--fork`, so the child's parent is the original test process.
fn in_private_namespace(name: &str, run: impl FnOnce(&Path)) {
    if std::env::var(CHILD_CASE).as_deref() == Ok(name) {
        let current = fs::read_link("/proc/self/ns/mnt").unwrap();
        let saved = std::env::var_os(PARENT_NAMESPACE).expect("parent mount namespace");
        let parent_pid = std::env::var(PARENT_PID).expect("parent process ID");
        assert_eq!(nix::unistd::getppid().to_string(), parent_pid);
        assert_eq!(
            fs::read_link(format!("/proc/{parent_pid}/ns/mnt")).unwrap(),
            Path::new(&saved),
            "the harness parent's mount namespace must be unchanged"
        );
        assert_ne!(
            current,
            Path::new(&saved),
            "refuse mounts outside a new namespace"
        );
        let table = fs::read_to_string("/proc/self/mountinfo").unwrap();
        for line in table.lines() {
            assert!(
                !line
                    .split_whitespace()
                    .skip(6)
                    .take_while(|field| *field != "-")
                    .any(|field| field.starts_with("shared:") || field.starts_with("master:")),
                "unshare must make inherited mounts recursively private before setup: {line}"
            );
        }
        let root = std::env::var_os(CHILD_ROOT).expect("private fixture root");
        run(Path::new(&root));
        return;
    }

    let parent_namespace = fs::read_link("/proc/self/ns/mnt").unwrap();
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
    fs::create_dir_all(base).unwrap();
    let root = tempfile::Builder::new()
        .prefix("sbh-ram-scratch-native-")
        .tempdir_in(base)
        .unwrap()
        .keep();
    let marker = root.file_name().unwrap().to_string_lossy();
    let original_device = fs::metadata(&root).unwrap().dev();
    assert!(
        !fs::read_to_string("/proc/self/mountinfo")
            .unwrap()
            .contains(marker.as_ref())
    );
    let output = Command::new("unshare")
        .args(["--mount", "--propagation", "private", "--"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            name,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_CASE, name)
        .env(CHILD_ROOT, &root)
        .env(PARENT_NAMESPACE, &parent_namespace)
        .env(PARENT_PID, std::process::id().to_string())
        .output()
        .expect("native RAM-scratch qualification needs util-linux unshare");

    // Check isolation even when setup or the collector assertions failed.
    assert_eq!(
        fs::read_link("/proc/self/ns/mnt").unwrap(),
        parent_namespace
    );
    assert_eq!(fs::metadata(&root).unwrap().dev(), original_device);
    assert!(
        !fs::read_to_string("/proc/self/mountinfo")
            .unwrap()
            .contains(marker.as_ref()),
        "fixture mounts must never appear in the parent mount namespace"
    );
    // Prefix child libtest output so the quality gate counts each outer test
    // once, rather than adding the re-executed child's summary a second time.
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        println!("namespace: {line}");
    }
    for line in String::from_utf8_lossy(&output.stderr).lines() {
        eprintln!("namespace: {line}");
    }
    println!("fixture directories retained at {}", root.display());
    assert!(
        output.status.success(),
        "native RAM-scratch qualification failed ({}): Linux must allow private mount namespaces and CAP_SYS_ADMIN; a capability failure is not a passing test",
        output.status
    );
}

fn tmpfs(path: &Path, limit: &str) {
    mount(
        Some("sbh-ram-scratch-test"),
        path,
        Some("tmpfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some(limit),
    )
    .expect("mount tiny tmpfs inside the disposable private namespace");
}

fn bind(source: &Path, target: &Path) {
    mount(
        Some(source),
        target,
        Option::<&str>::None,
        MsFlags::MS_BIND,
        Option::<&str>::None,
    )
    .expect("bind only private fixture paths");
}

/// Independent mount identity from the kernel's fdinfo projection.
fn mount_id(path: &Path) -> u64 {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)
        .unwrap();
    let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd())).unwrap();
    info.lines()
        .find_map(|line| line.strip_prefix("mnt_id:"))
        .expect("Linux native qualification needs fdinfo mount IDs")
        .trim()
        .parse()
        .unwrap()
}

/// Allocate one small marker, never fill or pressure a filesystem.
fn marker(path: &Path) {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap()
        .write_all(&[0x5a; 4096])
        .unwrap();
}

fn inspect(root: &Path) -> ScratchReport {
    let report = ram_scratch::inspect(
        &storage_ballast_helper::platform::current(),
        ScratchLimits {
            timeout_secs: 30,
            max_processes: 131_072,
            max_mounts: 1024,
        },
    )
    .expect("collect native RAM-scratch report");
    assert!(report.read_only && report.supported);
    if !report.complete {
        assert_eq!(report.exit_code, 4, "{report:?}");
    }
    let assessment = report.assessment.as_ref().unwrap();
    println!(
        "{}",
        serde_json::json!({
            "schema": report.schema,
            "read_only": report.read_only,
            "complete": report.complete,
            "exit_code": report.exit_code,
            "fixture_mounts": assessment.mounts.iter()
                .filter(|entry| Path::new(&entry.path).starts_with(root))
                .collect::<Vec<_>>(),
            "fixture_issue_details": report.issue_details.iter()
                .filter(|issue| issue.path.as_ref().is_some_and(|path| Path::new(path).starts_with(root)))
                .collect::<Vec<_>>(),
        })
    );
    report
}

fn measured<'a>(report: &'a ScratchReport, path: &Path, device: u64) -> &'a ScratchMount {
    let entries: Vec<_> = report
        .assessment
        .as_ref()
        .unwrap()
        .mounts
        .iter()
        .filter(|entry| Path::new(&entry.path) == path && entry.filesystem_id == device)
        .collect();
    assert_eq!(entries.len(), 1, "{report:?}");
    entries[0]
}

fn no_fixture_issues(report: &ScratchReport, root: &Path) {
    assert!(
        !report.issue_details.iter().any(|issue| issue
            .path
            .as_ref()
            .is_some_and(|path| Path::new(path).starts_with(root))),
        "{report:?}"
    );
    // Inherited host mounts/processes can already be inaccessible. Such
    // evidence must stay incomplete; fixture visibility must not hide it.
    if report.issue_details.is_empty() {
        assert!(report.complete, "a complete control must stay complete");
        assert!(matches!(report.exit_code, 0 | 1));
    } else {
        assert!(!report.complete);
        assert_eq!(report.exit_code, 4);
    }
}

fn cli_incomplete(path: &Path, kind: &str) {
    let output = Command::new(env!("CARGO_BIN_EXE_sbh"))
        .args([
            "--json",
            "check",
            "--ram-scratch",
            "--ram-scratch-timeout-secs",
            "30",
            "--ram-scratch-max-entries",
            "1",
            "--ram-scratch-depth",
            "0",
        ])
        .env_remove("SBH_TEST_MODE")
        .output()
        .expect("run read-only RAM-scratch CLI");
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["complete"], false);
    assert_eq!(report["exit_code"], 4);
    assert_eq!(report["read_only"], true);
    let issues = report["issue_details"].as_array().unwrap();
    assert!(
        issues.iter().any(|issue| issue["kind"] == kind
            && issue["path"]
                .as_str()
                .is_some_and(|value| Path::new(value) == path)),
        "expected {kind} for {} in CLI JSON: {report}",
        path.display()
    );
    println!(
        "CLI exit 4: {}",
        serde_json::json!({
            "schema": report["schema"],
            "complete": report["complete"],
            "exit_code": report["exit_code"],
            "issue_details": issues.iter()
                .filter(|issue| issue["path"].as_str().is_some_and(|value| Path::new(value) == path))
                .collect::<Vec<_>>(),
        })
    );
}

#[test]
#[ignore = "requires Linux private mount namespaces and root; run native-ram-scratch"]
fn native_visible_tmpfs_and_file_bind_alias() {
    in_private_namespace("native_visible_tmpfs_and_file_bind_alias", |root| {
        let visible = root.join("visible");
        fs::create_dir(&visible).unwrap();
        tmpfs(&visible, "size=1m");
        let payload = visible.join("one-page");
        marker(&payload);
        let device = fs::metadata(&visible).unwrap().dev();
        let original = inspect(root);
        let original_used = measured(&original, &visible, device).used_bytes;
        assert!(
            original_used > 0,
            "the one-page marker must be accounted for"
        );
        no_fixture_issues(&original, root);

        let alias = root.join("file-alias");
        File::create_new(&alias).unwrap();
        bind(&payload, &alias);
        assert_ne!(mount_id(&visible), mount_id(&alias));
        assert_eq!(fs::metadata(&alias).unwrap().dev(), device);
        let report = inspect(root);
        no_fixture_issues(&report, root);
        for path in [&visible, &alias] {
            let entry = measured(&report, path, device);
            assert_eq!(entry.total_bytes, MIB);
            assert_eq!(entry.used_bytes, original_used);
        }
        assert_eq!(fs::read(&alias).unwrap(), [0x5a; 4096]);
    });
}

#[test]
#[ignore = "requires Linux private mount namespaces and root; run native-ram-scratch"]
fn native_covered_child_is_incomplete_in_library_and_cli() {
    in_private_namespace(
        "native_covered_child_is_incomplete_in_library_and_cli",
        |root| {
            let parent = root.join("parent");
            let covered = parent.join("covered");
            let empty = root.join("empty");
            fs::create_dir_all(&covered).unwrap();
            fs::create_dir(&empty).unwrap();
            tmpfs(&covered, "size=1m");
            marker(&covered.join("one-page"));
            let hidden_id = mount_id(&covered);
            let hidden_device = fs::metadata(&covered).unwrap().dev();
            no_fixture_issues(&inspect(root), root);
            bind(&empty, &parent);
            let cover_id = mount_id(&parent);
            assert_eq!(
                fs::metadata(&covered).unwrap_err().raw_os_error(),
                Some(libc::ENOENT)
            );

            let report = inspect(root);
            assert!(!report.complete);
            assert_eq!(report.exit_code, 4);
            let issue = report
                .issue_details
                .iter()
                .find(|issue| issue.mount_id == Some(hidden_id))
                .expect("the hidden mount must remain explicit unknown evidence");
            assert_eq!(issue.kind, "mount_covered");
            assert_eq!(issue.operation, Some("topology"));
            assert_eq!(
                issue.os_error, None,
                "the collector does not look up a known-covered path"
            );
            let cover = issue.covered_by.as_ref().unwrap();
            assert_eq!(cover.mount_id, cover_id);
            assert_eq!(Path::new(&cover.path), parent);
            assert!(
                !report
                    .assessment
                    .as_ref()
                    .unwrap()
                    .mounts
                    .iter()
                    .any(|entry| entry.filesystem_id == hidden_device)
            );
            cli_incomplete(&covered, "mount_covered");
        },
    );
}

#[test]
#[ignore = "requires Linux private mount namespaces and root; run native-ram-scratch"]
fn native_stacked_tmpfs_keeps_lower_occupancy_unknown() {
    in_private_namespace(
        "native_stacked_tmpfs_keeps_lower_occupancy_unknown",
        |root| {
            let path = root.join("stack");
            fs::create_dir(&path).unwrap();
            tmpfs(&path, "size=1m");
            marker(&path.join("lower-page"));
            let lower_id = mount_id(&path);
            let lower_device = fs::metadata(&path).unwrap().dev();
            tmpfs(&path, "size=2m");
            let upper_id = mount_id(&path);
            let upper_device = fs::metadata(&path).unwrap().dev();
            assert_ne!(lower_id, upper_id);
            assert_ne!(lower_device, upper_device);

            let report = inspect(root);
            assert!(!report.complete);
            assert_eq!(report.exit_code, 4);
            let issue = report
                .issue_details
                .iter()
                .find(|issue| issue.mount_id == Some(lower_id))
                .unwrap();
            assert_eq!(issue.kind, "mount_covered");
            assert_eq!(issue.covered_by.as_ref().unwrap().mount_id, upper_id);
            let upper = measured(&report, &path, upper_device);
            assert_eq!(upper.total_bytes, 2 * MIB);
            assert_eq!(
                upper.used_bytes, 0,
                "the empty upper tmpfs is separate from the occupied lower one"
            );
            assert!(
                !report
                    .assessment
                    .as_ref()
                    .unwrap()
                    .mounts
                    .iter()
                    .any(|entry| entry.filesystem_id == lower_device)
            );
            cli_incomplete(&path, "mount_covered");

            umount(&path).expect("remove only the fixture's upper mount in its private namespace");
            assert_eq!(mount_id(&path), lower_id);
            let restored = inspect(root);
            no_fixture_issues(&restored, root);
            let lower = measured(&restored, &path, lower_device);
            assert_eq!(lower.total_bytes, MIB);
            assert!(lower.used_bytes > 0);
            assert_eq!(fs::read(path.join("lower-page")).unwrap(), [0x5a; 4096]);
        },
    );
}

#[test]
#[ignore = "requires Linux private mount namespaces and root; run native-ram-scratch"]
fn native_fresh_inspection_identifies_a_replacement() {
    in_private_namespace("native_fresh_inspection_identifies_a_replacement", |root| {
        let path = root.join("replace");
        fs::create_dir(&path).unwrap();
        tmpfs(&path, "size=1m");
        marker(&path.join("old-page"));
        let old_id = mount_id(&path);
        let old = File::open(&path).unwrap();
        let old_device = old.metadata().unwrap().dev();
        let before = inspect(root);
        assert!(measured(&before, &path, old_device).used_bytes > 0);
        umount2(&path, MntFlags::MNT_DETACH)
            .expect("detach only the fixture mount inside its private namespace");
        tmpfs(&path, "size=2m");
        let new_device = fs::metadata(&path).unwrap().dev();
        assert_ne!(new_device, old_device);
        assert_ne!(mount_id(&path), old_id);
        let report = inspect(root);
        no_fixture_issues(&report, root);
        let new = measured(&report, &path, new_device);
        assert_eq!(new.total_bytes, 2 * MIB);
        assert_eq!(new.used_bytes, 0);
        assert!(
            !report
                .assessment
                .as_ref()
                .unwrap()
                .mounts
                .iter()
                .any(|entry| entry.filesystem_id == old_device)
        );
        // Pin the old filesystem for the whole case so its device/mount ID
        // cannot be recycled into the replacement under test.
        assert_eq!(old.metadata().unwrap().dev(), old_device);
    });
}

#[test]
#[ignore = "requires Linux private mount namespaces and root; run native-ram-scratch"]
fn native_visible_mount_permission_denial_stays_incomplete() {
    in_private_namespace(
        "native_visible_mount_permission_denial_stays_incomplete",
        |root| {
            assert!(
                nix::unistd::geteuid().is_root(),
                "credential fixture needs root"
            );
            let denied = root.join("denied");
            let path = denied.join("visible-tmpfs");
            fs::create_dir_all(&path).unwrap();
            tmpfs(&path, "size=1m");
            let expected_id = mount_id(&path);
            fs::set_permissions(&denied, fs::Permissions::from_mode(0o000)).unwrap();
            // This is the isolated, single-test child. Drop only its effective
            // privilege after every mount is set up; root bypasses chmod denials.
            nix::unistd::seteuid(nix::unistd::Uid::from_raw(65_534)).unwrap();
            let report = inspect(root);
            assert!(!report.complete);
            assert_eq!(report.exit_code, 4);
            let issue = report
                .issue_details
                .iter()
                .find(|issue| issue.mount_id == Some(expected_id))
                .unwrap();
            assert_eq!(issue.kind, "permission_denied");
            assert_eq!(issue.os_error, Some(libc::EACCES));
            assert!(issue.covered_by.is_none());
        },
    );
}
