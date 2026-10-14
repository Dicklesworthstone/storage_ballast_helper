use super::*;
use crate::platform::pal::MockPlatform;

#[test]
fn incomplete_process_evidence_never_admits_compression() {
    let path = Path::new("/tmp/cold-input");
    assert!(check_active(path, -1, &MockPlatform::healthy()).is_ok());
    assert!(
        check_active(
            path,
            -1,
            &MockPlatform::healthy().with_open_files_complete(false)
        )
        .is_err()
    );
    assert!(
        check_active(
            path,
            -1,
            &MockPlatform::healthy().with_executables_complete(false)
        )
        .is_err()
    );
}

#[test]
fn fresh_marker_checks_do_not_reuse_negative_preflight_caches() {
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("cold.bin");
    fs::write(&file, b"unchanged contents").unwrap();
    let config = Config::default();
    let platform = MockPlatform::healthy();
    assert!(check_protection(&file, &config, &platform).is_ok());
    fs::write(temp.path().join(".sbh-protect"), b"").unwrap();
    assert!(check_protection(&file, &config, &platform).is_err());
    assert_eq!(fs::read(&file).unwrap(), b"unchanged contents");
}

#[test]
fn configured_parent_protection_is_a_hard_veto_for_explicit_files() {
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("cold.bin");
    fs::write(&file, b"protected").unwrap();
    let mut config = Config::default();
    config
        .scanner
        .protected_paths
        .push(temp.path().to_string_lossy().into_owned());
    assert!(check_protection(&file, &config, &MockPlatform::healthy()).is_err());
}

#[test]
fn pinned_descriptor_refuses_replaced_or_symlinked_paths() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("cold.bin");
    fs::write(&path, b"original").unwrap();
    let file = File::open(&path).unwrap();
    let stamp = FileStamp::read(&file).unwrap();
    assert!(verify_path(&path, &file, stamp).is_ok());
    let retained = temp.path().join("retained.bin");
    fs::rename(&path, &retained).unwrap();
    std::os::unix::fs::symlink(&retained, &path).unwrap();
    assert!(verify_path(&path, &file, stamp).is_err());
    assert_eq!(fs::read(&retained).unwrap(), b"original");
}

#[test]
fn preflight_hash_is_exact_and_short_reads_or_deadlines_are_not_success() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("cold.bin");
    fs::write(&path, b"abc").unwrap();
    let file = File::open(path).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    assert_eq!(
        digest(&file, 3, deadline).unwrap(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(digest(&file, 4, deadline).is_err());
    assert_eq!(
        digest(&file, 3, Instant::now()).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
}

#[test]
fn insufficient_headroom_never_overflows_into_admission() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("cold.bin");
    fs::write(&path, b"abc").unwrap();
    let file = File::open(path).unwrap();
    assert!(check_headroom(&file, u64::MAX).is_err());
}

#[test]
fn only_the_exact_inspection_descriptor_is_exempt_from_open_file_vetoes() {
    let pid = i32::try_from(std::process::id()).unwrap();
    assert!(!foreign_reference(pid, Some(42), 42));
    assert!(foreign_reference(pid, Some(1), 42));
    assert!(foreign_reference(pid, None, 42));
    assert!(foreign_reference(-1, Some(42), 42));
    assert!(foreign_reference(pid.saturating_add(1), Some(42), 42));
}
