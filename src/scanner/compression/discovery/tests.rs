use super::*;

#[test]
fn limits_reject_unbounded_work_and_traversal_cursors() {
    assert!(DiscoveryLimits::default().validate().is_ok());
    for limits in [
        DiscoveryLimits { max_depth: 65, ..Default::default() },
        DiscoveryLimits { max_entries: 0, ..Default::default() },
        DiscoveryLimits { max_directories: 8193, ..Default::default() },
        DiscoveryLimits { timeout_secs: 61, ..Default::default() },
        DiscoveryLimits { after: Some("/data/../elsewhere".into()), ..Default::default() },
    ] {
        assert!(limits.validate().is_err(), "{limits:?}");
    }
    for token in ["", "a", "zz", "00", "72656c6174697665", "2f612f2e2e2f62"] {
        assert!(continuation_path(token).is_err(), "{token}");
    }
}

#[cfg(unix)]
#[test]
fn continuations_preserve_non_utf8_filename_bytes() {
    use std::os::unix::ffi::OsStrExt as _;
    let path = continuation_path("2f746d702f636f6c642dff").unwrap();
    assert_eq!(path.as_os_str().as_bytes(), b"/tmp/cold-\xff");
}

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod native_tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use crate::platform::pal::MockPlatform;

    fn cold(path: &Path) {
        fs::write(path, b"cold contents").unwrap();
        let old = filetime::FileTime::from_unix_time(1, 0);
        filetime::set_file_mtime(path, old).unwrap();
    }

    fn policy() -> CompressionPolicy {
        CompressionPolicy { min_size_bytes: 1, min_age_secs: 3600, ..Default::default() }
    }

    fn scan(roots: &[PathBuf], limits: &DiscoveryLimits, policy: &CompressionPolicy) -> Selection {
        discover(roots, policy, limits, &Config::default(), &MockPlatform::healthy()).unwrap()
    }

    #[test]
    fn sorted_discovery_prunes_markers_symlinks_hot_files_and_suffixes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let outside = tempfile::tempdir().unwrap();
        cold(&outside.path().join("outside.bin"));
        fs::create_dir(root.join("protected")).unwrap();
        fs::write(root.join("protected/.sbh-protect"), b"").unwrap();
        cold(&root.join("protected/secret.bin"));
        symlink(outside.path(), root.join("alias")).unwrap();
        cold(&root.join("z.bin"));
        cold(&root.join("a.bin"));
        cold(&root.join("archive.ZST"));
        fs::write(root.join("hot.bin"), b"recent").unwrap();
        let selection = scan(&[root.clone()], &DiscoveryLimits::default(), &policy());
        assert!(selection.report().complete, "{:?}", selection.report());
        assert_eq!(selection.paths(), [root.join("a.bin"), root.join("z.bin")]);
        assert_eq!(selection.report().selected_bytes, 26);
        assert_eq!(selection.report().directories_opened, 1);
        assert_eq!(fs::read(outside.path().join("outside.bin")).unwrap(), b"cold contents");
    }

    #[test]
    fn a_full_file_budget_has_a_native_continuation_without_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        for name in ["c.bin", "a.bin", "b.bin"] { cold(&root.join(name)); }
        let policy = CompressionPolicy { max_files: 2, ..policy() };
        let first = scan(&[root.clone()], &DiscoveryLimits::default(), &policy);
        assert!(!first.report().complete);
        assert_eq!(first.paths(), [root.join("a.bin"), root.join("b.bin")]);
        let after = continuation_path(first.report().resume_after_hex.as_deref().unwrap()).unwrap();
        let second = scan(&[root.clone()], &DiscoveryLimits { after: Some(after), ..Default::default() }, &policy);
        assert!(second.report().complete);
        assert_eq!(second.paths(), [root.join("c.bin")]);
    }

    #[test]
    fn partial_directory_enumeration_never_claims_a_sorted_prefix() {
        let dir = tempfile::tempdir().unwrap();
        cold(&dir.path().join("a.bin"));
        cold(&dir.path().join("b.bin"));
        let selection = scan(&[dir.path().into()], &DiscoveryLimits { max_entries: 1, ..Default::default() }, &policy());
        assert!(!selection.report().complete);
        assert!(selection.paths().is_empty());
        assert!(selection.report().resume_after_hex.is_none());
        assert_eq!(selection.report().entries_examined, 1);
    }

    #[test]
    fn selected_files_and_roots_are_revalidated_after_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap().join("root");
        fs::create_dir(&root).unwrap();
        let path = root.join("cold.bin");
        cold(&path);
        let selection = scan(&[root.clone()], &DiscoveryLimits::default(), &policy());
        let file = fs::File::open(&path).unwrap();
        let stamp = sbh_btrfs::FileStamp::read(&file).unwrap();
        assert!(selection.validate_file(&path, stamp).is_ok());
        fs::rename(&root, root.with_file_name("retained-root")).unwrap();
        fs::create_dir(&root).unwrap();
        cold(&path);
        let replacement = fs::File::open(&path).unwrap();
        assert!(selection.validate_file(&path, sbh_btrfs::FileStamp::read(&replacement).unwrap()).is_err());
        assert!(selection.validate_scope(&path).is_err());
    }

    #[test]
    fn protected_roots_overlapping_roots_and_hardlinks_do_not_expand_scope() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        fs::create_dir(root.join("sub")).unwrap();
        cold(&root.join("sub/a.bin"));
        cold(&root.join("linked.bin"));
        fs::hard_link(root.join("linked.bin"), root.join("linked-again.bin")).unwrap();
        let selection = scan(&[root.join("sub"), root.clone()], &DiscoveryLimits::default(), &policy());
        assert_eq!(selection.report().roots.len(), 1);
        assert_eq!(selection.paths(), [root.join("sub/a.bin")]);
        let mut config = Config::default();
        config.scanner.protected_paths.push(root.to_string_lossy().into_owned());
        let protected = discover(&[root], &policy(), &DiscoveryLimits::default(), &config, &MockPlatform::healthy()).unwrap();
        assert!(protected.paths().is_empty());
        assert!(protected.report().complete);
        assert_eq!(protected.report().directories_opened, 0);
    }

    #[test]
    fn depth_and_byte_limits_are_real_and_outside_cursors_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        fs::create_dir(root.join("sub")).unwrap();
        cold(&root.join("a.bin"));
        cold(&root.join("sub/b.bin"));
        let selection = scan(&[root.clone()], &DiscoveryLimits { max_depth: 0, ..Default::default() }, &policy());
        assert!(!selection.report().complete);
        assert_eq!(selection.paths(), [root.join("a.bin")]);
        let selection = scan(&[root.clone()], &DiscoveryLimits::default(), &CompressionPolicy { max_bytes: 13, ..policy() });
        assert_eq!(selection.report().selected_bytes, 13);
        assert_eq!(selection.report().selected_files, 1);
        assert!(discover(&[root], &policy(), &DiscoveryLimits { after: Some("/unrelated/file".into()), ..Default::default() }, &Config::default(), &MockPlatform::healthy()).is_err());
    }
}
