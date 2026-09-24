//! Regressions exercising the real updater and backup-store entry points.

use super::{BackupStore, BinaryTrustPolicy, extract_and_install};
use std::fs;
use std::path::PathBuf;

fn fixture(body: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("downloaded-sbh");
    let dest = temp.path().join("bin/sbh");
    fs::create_dir(dest.parent().unwrap()).unwrap();
    fs::write(&source, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::write(&dest, b"old installed binary").unwrap();
    (temp, source, dest)
}

#[test]
fn update_self_test_can_still_find_the_installed_command() {
    let (_temp, source, dest) = fixture(
        r#"candidate_dir=${0%/*}
case "$candidate_dir" in
    */.sbh-install-*) bin_dir=${candidate_dir%/*} ;;
    *) bin_dir=$candidate_dir ;;
esac
test -f "$bin_dir/sbh""#,
    );
    extract_and_install(&source, &dest, BinaryTrustPolicy::BypassNoVerify, false).unwrap();
    assert_eq!(fs::read(&dest).unwrap(), fs::read(&source).unwrap());
}

#[test]
fn update_self_test_failure_keeps_the_installed_binary() {
    let (_temp, source, dest) = fixture("exit 7");
    let error = extract_and_install(&source, &dest, BinaryTrustPolicy::BypassNoVerify, false)
        .unwrap_err();
    assert!(error.contains("self-test"));
    assert_eq!(fs::read(&dest).unwrap(), b"old installed binary");
    assert!(!source.with_extension("extract").exists());
}

#[test]
fn update_does_not_write_through_a_preexisting_new_symlink() {
    use std::os::unix::fs::symlink;
    let (temp, source, dest) = fixture("exit 0");
    let victim = temp.path().join("unrelated-file");
    fs::write(&victim, b"must survive").unwrap();
    symlink(&victim, dest.with_extension("new")).unwrap();
    extract_and_install(&source, &dest, BinaryTrustPolicy::BypassNoVerify, false).unwrap();
    assert_eq!(fs::read(victim).unwrap(), b"must survive");
}

#[test]
fn update_rejects_a_symlink_candidate() {
    use std::os::unix::fs::symlink;
    let (temp, source, dest) = fixture("exit 0");
    let linked = temp.path().join("linked-download");
    symlink(&source, &linked).unwrap();
    assert!(extract_and_install(&linked, &dest, BinaryTrustPolicy::BypassNoVerify, false).is_err());
    assert_eq!(fs::read(dest).unwrap(), b"old installed binary");
}

#[test]
fn rollback_replaces_the_inode_instead_of_overwriting_open_readers() {
    use std::io::Read as _;
    let (temp, source, dest) = fixture("exit 0");
    let store = BackupStore::open(temp.path().join("backups"));
    let snapshot = store.create(&source, "previous").unwrap();
    let mut original = fs::File::open(&dest).unwrap();
    let result = store.rollback(&dest, Some(&snapshot.id)).unwrap();
    assert!(result.success);
    let mut old_bytes = Vec::new();
    original.read_to_end(&mut old_bytes).unwrap();
    assert_eq!(old_bytes, b"old installed binary");
    assert_eq!(fs::read(dest).unwrap(), fs::read(snapshot.path).unwrap());
}

#[cfg(target_os = "linux")]
#[test]
fn rollback_works_while_the_destination_binary_is_executing() {
    struct Running(std::process::Child);
    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let (temp, source, dest) = fixture("exit 0");
    let store = BackupStore::open(temp.path().join("backups"));
    let snapshot = store.create(&source, "previous").unwrap();
    fs::copy("/bin/sleep", &dest).unwrap();
    let mut running = Running(std::process::Command::new(&dest).arg("30").spawn().unwrap());
    assert!(running.0.try_wait().unwrap().is_none());
    let result = store.rollback(&dest, Some(&snapshot.id)).unwrap();
    assert!(result.success);
    assert!(running.0.try_wait().unwrap().is_none());
    assert_eq!(fs::read(dest).unwrap(), fs::read(snapshot.path).unwrap());
}
