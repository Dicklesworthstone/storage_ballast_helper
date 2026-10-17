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

#[test]
fn git_packfile_preview_and_apply_stop_before_hashing_or_journaling() {
    use crate::platform::pal::{FsStats, MountPoint, PlatformPaths};
    use std::collections::HashMap;

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let path = root.join("repo/.git/objects/pack/old.pack");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, b"repository payload must stay untouched").unwrap();
    filetime::set_file_mtime(&path, filetime::FileTime::from_unix_time(1, 0)).unwrap();
    let stats = FsStats {
        total_bytes: 16 * 1024 * 1024 * 1024,
        free_bytes: 8 * 1024 * 1024 * 1024,
        available_bytes: 8 * 1024 * 1024 * 1024,
        fs_type: "btrfs".into(),
        mount_point: root.clone(),
        is_readonly: false,
    };
    // Advertise Btrfs to reach real application admission on any test FS.
    // The expected Git refusal precedes all Btrfs ioctls, not a mock mutation.
    let platform = MockPlatform::new(
        vec![MountPoint {
            path: root.clone(),
            device: "fixture".into(),
            fs_type: "btrfs".into(),
            is_ram_backed: false,
        }],
        HashMap::from([(root.clone(), stats)]),
        MockPlatform::healthy().memory_info().unwrap(),
        PlatformPaths::default(),
    );
    let policy = CompressionPolicy {
        min_size_bytes: 1,
        min_age_secs: 3600,
        max_bytes: 1024,
        ..Default::default()
    };
    for apply in [false, true] {
        let mut item = CompressionFileReport::new(&path);
        let mut audit = AuditSession::new(root.join("journal"), 1, &policy);
        let mut bytes = 0;
        let mut identities = BTreeSet::new();
        let error = process_file(
            &path,
            None,
            &mut item,
            &policy,
            CompressionMode {
                apply,
                allow_zstd_feature: true,
                acknowledgement: crate::scanner::compression::ConcurrencyAcknowledgement::Quiescent,
            },
            &Config::default(),
            &platform,
            Instant::now() + Duration::from_secs(30),
            &mut bytes,
            &mut identities,
            &mut audit,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("Git repository"));
        assert!(!item.mutation_attempted);
        assert!(item.sha256_before.is_none());
        assert!(item.operation_id.is_none());
        assert!(audit.path().is_none());
        assert_eq!(bytes, 0);
        assert!(identities.is_empty());
        assert!(!root.join("journal").exists());
        assert_eq!(
            fs::read(&path).unwrap(),
            b"repository payload must stay untouched"
        );
    }
}

#[test]
fn per_chunk_protection_detects_a_new_gitfile_without_reusing_admission() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let path = root.join("cold.bin");
    fs::write(&path, b"not rewritten").unwrap();
    let config = Config::default();
    let platform = MockPlatform::healthy();
    assert!(check_protection(&path, &config, &platform).is_ok());
    fs::write(root.join(".git"), b"gitdir: /not-followed\n").unwrap();
    let error = check_protection(&path, &config, &platform).unwrap_err();
    assert!(error.to_string().contains("Git repository"));
    assert_eq!(fs::read(&path).unwrap(), b"not rewritten");
}
