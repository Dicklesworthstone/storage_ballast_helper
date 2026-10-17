use super::*;

#[test]
fn limits_reject_unbounded_work_and_traversal_cursors() {
    assert!(DiscoveryLimits::default().validate().is_ok());
    for limits in [
        DiscoveryLimits {
            max_depth: 65,
            ..Default::default()
        },
        DiscoveryLimits {
            max_entries: 0,
            ..Default::default()
        },
        DiscoveryLimits {
            max_directories: 8193,
            ..Default::default()
        },
        DiscoveryLimits {
            timeout_secs: 61,
            ..Default::default()
        },
        DiscoveryLimits {
            after: Some("/data/../elsewhere".into()),
            ..Default::default()
        },
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

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod native_tests {
    use super::*;
    use crate::platform::pal::MockPlatform;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn cold(path: &Path) {
        fs::write(path, b"cold contents").unwrap();
        let old = filetime::FileTime::from_unix_time(1, 0);
        filetime::set_file_mtime(path, old).unwrap();
    }

    fn policy() -> CompressionPolicy {
        CompressionPolicy {
            min_size_bytes: 1,
            min_age_secs: 3600,
            ..Default::default()
        }
    }

    fn scan(roots: &[PathBuf], limits: &DiscoveryLimits, policy: &CompressionPolicy) -> Selection {
        discover(
            roots,
            policy,
            limits,
            &Config::default(),
            &MockPlatform::healthy(),
        )
        .unwrap()
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
        let selection = scan(
            std::slice::from_ref(&root),
            &DiscoveryLimits::default(),
            &policy(),
        );
        assert!(selection.report().complete, "{:?}", selection.report());
        assert_eq!(selection.paths(), [root.join("a.bin"), root.join("z.bin")]);
        assert_eq!(selection.report().selected_bytes, 26);
        assert_eq!(selection.report().directories_opened, 1);
        assert_eq!(
            fs::read(outside.path().join("outside.bin")).unwrap(),
            b"cold contents"
        );
    }

    #[test]
    fn a_full_file_budget_has_a_native_continuation_without_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        for name in ["c.bin", "a.bin", "b.bin"] {
            cold(&root.join(name));
        }
        let policy = CompressionPolicy {
            max_files: 2,
            ..policy()
        };
        let first = scan(
            std::slice::from_ref(&root),
            &DiscoveryLimits::default(),
            &policy,
        );
        assert!(!first.report().complete);
        assert_eq!(first.paths(), [root.join("a.bin"), root.join("b.bin")]);
        let after = continuation_path(first.report().resume_after_hex.as_deref().unwrap()).unwrap();
        let second = scan(
            std::slice::from_ref(&root),
            &DiscoveryLimits {
                after: Some(after),
                ..Default::default()
            },
            &policy,
        );
        assert!(second.report().complete);
        assert_eq!(second.paths(), [root.join("c.bin")]);
    }

    #[test]
    fn partial_directory_enumeration_never_claims_a_sorted_prefix() {
        let dir = tempfile::tempdir().unwrap();
        cold(&dir.path().join("a.bin"));
        cold(&dir.path().join("b.bin"));
        let selection = scan(
            &[dir.path().into()],
            &DiscoveryLimits {
                max_entries: 1,
                ..Default::default()
            },
            &policy(),
        );
        assert!(!selection.report().complete);
        assert!(selection.paths().is_empty());
        assert!(selection.report().resume_after_hex.is_none());
        assert_eq!(selection.report().entries_examined, 1);
    }

    /// A directory budget stops with a cursor at the last path visited to
    /// completion, so resumed runs (the daemon tier) cover the whole tree,
    /// each file once. Before, only the file limit left a cursor, and a
    /// budget-stopped walk restarted from the top on every run.
    #[test]
    fn a_budget_stop_resumes_until_the_tree_is_covered_without_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        for sub in ["d1", "d2", "d3", "d4"] {
            fs::create_dir(root.join(sub)).unwrap();
            cold(&root.join(sub).join("f.bin"));
        }
        let mut after = None;
        let mut seen = Vec::new();
        let mut runs = 0;
        loop {
            runs += 1;
            assert!(runs <= 8, "no progress after {runs} runs: {seen:?}");
            let selection = scan(
                std::slice::from_ref(&root),
                &DiscoveryLimits {
                    max_directories: 3,
                    after: after.clone(),
                    ..Default::default()
                },
                &policy(),
            );
            seen.extend(selection.paths());
            let Some(hex) = selection.report().resume_after_hex.as_deref() else {
                assert!(selection.report().complete);
                break;
            };
            assert_eq!(
                selection.report().stop_reason.as_deref(),
                Some("discovery directory budget exhausted")
            );
            after = Some(continuation_path(hex).unwrap());
        }
        assert!(runs > 1, "the budget must actually stop the first run");
        seen.sort();
        assert_eq!(
            seen,
            ["d1", "d2", "d3", "d4"].map(|sub| root.join(sub).join("f.bin"))
        );
    }

    /// A subtree past the depth limit is skipped and the walk goes on: a stop
    /// there would recur at the same directory on every resumed run.
    #[test]
    fn a_too_deep_subtree_is_skipped_without_stopping_the_walk() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        fs::create_dir_all(root.join("a/deep")).unwrap();
        cold(&root.join("a/deep/f.bin"));
        fs::create_dir(root.join("b")).unwrap();
        cold(&root.join("b/f.bin"));
        let selection = scan(
            std::slice::from_ref(&root),
            &DiscoveryLimits {
                max_depth: 1,
                ..Default::default()
            },
            &policy(),
        );
        assert_eq!(selection.paths(), [root.join("b/f.bin")]);
        assert!(!selection.report().complete);
        assert_eq!(selection.report().skipped.get("depth_limit"), Some(&1));
        assert!(selection.report().stop_reason.is_none());
        assert!(selection.report().resume_after_hex.is_none());
    }

    #[test]
    fn selected_files_and_roots_are_revalidated_after_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap().join("root");
        fs::create_dir(&root).unwrap();
        let path = root.join("cold.bin");
        cold(&path);
        let selection = scan(
            std::slice::from_ref(&root),
            &DiscoveryLimits::default(),
            &policy(),
        );
        let file = fs::File::open(&path).unwrap();
        let stamp = sbh_btrfs::FileStamp::read(&file).unwrap();
        assert!(selection.validate_file(&path, stamp).is_ok());
        fs::rename(&root, root.with_file_name("retained-root")).unwrap();
        fs::create_dir(&root).unwrap();
        cold(&path);
        let replacement = fs::File::open(&path).unwrap();
        assert!(
            selection
                .validate_file(&path, sbh_btrfs::FileStamp::read(&replacement).unwrap())
                .is_err()
        );
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
        let selection = scan(
            &[root.join("sub"), root.clone()],
            &DiscoveryLimits::default(),
            &policy(),
        );
        assert_eq!(selection.report().roots.len(), 1);
        assert_eq!(selection.paths(), [root.join("sub/a.bin")]);
        let mut config = Config::default();
        config
            .scanner
            .protected_paths
            .push(root.to_string_lossy().into_owned());
        let protected = discover(
            &[root],
            &policy(),
            &DiscoveryLimits::default(),
            &config,
            &MockPlatform::healthy(),
        )
        .unwrap();
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
        let selection = scan(
            std::slice::from_ref(&root),
            &DiscoveryLimits {
                max_depth: 0,
                ..Default::default()
            },
            &policy(),
        );
        assert!(!selection.report().complete);
        assert_eq!(selection.paths(), [root.join("a.bin")]);
        let selection = scan(
            std::slice::from_ref(&root),
            &DiscoveryLimits::default(),
            &CompressionPolicy {
                max_bytes: 13,
                ..policy()
            },
        );
        assert_eq!(selection.report().selected_bytes, 13);
        assert_eq!(selection.report().selected_files, 1);
        assert!(
            discover(
                &[root],
                &policy(),
                &DiscoveryLimits {
                    after: Some("/unrelated/file".into()),
                    ..Default::default()
                },
                &Config::default(),
                &MockPlatform::healthy()
            )
            .is_err()
        );
    }

    #[test]
    fn repository_subtrees_are_pruned_before_depth_and_entry_budgets() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        for name in ["a-worktree", "b-linked", "c-bare", "d-admin"] {
            fs::create_dir_all(root.join(name).join("deep/nested")).unwrap();
            cold(&root.join(name).join("deep/nested/cold.bin"));
        }
        fs::create_dir(root.join("a-worktree/.git")).unwrap();
        fs::write(root.join("b-linked/.git"), b"gitdir: /not-followed\n").unwrap();
        fs::write(root.join("c-bare/HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::create_dir(root.join("c-bare/objects")).unwrap();
        fs::write(root.join("d-admin/HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::write(root.join("d-admin/commondir"), b"/not-followed\n").unwrap();
        cold(&root.join("z.bin"));
        let selection = scan(
            std::slice::from_ref(&root),
            &DiscoveryLimits {
                max_depth: 0,
                max_entries: 5,
                max_directories: 1,
                ..Default::default()
            },
            &policy(),
        );
        assert!(selection.report().complete, "{:?}", selection.report());
        assert_eq!(selection.paths(), [root.join("z.bin")]);
        assert_eq!(selection.report().skipped.get("git_repository"), Some(&4));
        assert_eq!(selection.report().directories_opened, 1);
        assert_eq!(selection.report().entries_examined, 5);
        for name in ["a-worktree", "b-linked", "c-bare", "d-admin"] {
            assert_eq!(
                fs::read(root.join(name).join("deep/nested/cold.bin")).unwrap(),
                b"cold contents"
            );
        }
    }

    #[test]
    fn explicit_roots_inside_repository_scopes_are_not_enumerated() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        fs::create_dir_all(root.join("repo/.git/objects/pack")).unwrap();
        fs::create_dir_all(root.join("repo/src/deep")).unwrap();
        fs::create_dir_all(root.join("bare/objects/pack")).unwrap();
        fs::write(root.join("bare/HEAD"), b"ref: refs/heads/main\n").unwrap();
        for name in [
            "repo/src/deep",
            "repo/.git/objects/pack",
            "bare/objects/pack",
        ] {
            let inside = root.join(name);
            cold(&inside.join("cold.bin"));
            let selection = scan(
                &[inside],
                &DiscoveryLimits {
                    max_depth: 0,
                    max_entries: 1,
                    max_directories: 1,
                    ..Default::default()
                },
                &policy(),
            );
            assert!(selection.report().complete, "{:?}", selection.report());
            assert!(selection.paths().is_empty());
            assert_eq!(selection.report().skipped.get("git_repository"), Some(&1));
            assert_eq!(selection.report().entries_examined, 0);
            assert_eq!(selection.report().directories_opened, 0);
        }
    }

    #[test]
    fn retained_selection_rechecks_git_ancestry_even_outside_its_root() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().canonicalize().unwrap();
        let root = parent.join("scope");
        fs::create_dir(&root).unwrap();
        let path = root.join("cold.bin");
        cold(&path);
        let selection = scan(
            std::slice::from_ref(&root),
            &DiscoveryLimits::default(),
            &policy(),
        );
        let file = fs::File::open(&path).unwrap();
        let stamp = sbh_btrfs::FileStamp::read(&file).unwrap();
        assert!(selection.validate_file(&path, stamp).is_ok());
        fs::write(parent.join(".git"), b"gitdir: /not-followed\n").unwrap();
        // Neither file identity nor contents changed. New Git ancestry alone
        // must invalidate the earlier selection for both revalidation methods.
        assert_eq!(sbh_btrfs::FileStamp::read(&file).unwrap(), stamp);
        assert_eq!(
            selection.validate_scope(&path).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            selection.validate_file(&path, stamp).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let fresh = scan(&[root], &DiscoveryLimits::default(), &policy());
        assert!(fresh.paths().is_empty());
        assert_eq!(fresh.report().directories_opened, 0);
        assert_eq!(fs::read(&path).unwrap(), b"cold contents");
    }

    fn btrfs_platform() -> MockPlatform {
        use crate::platform::pal::{FsStats, MemoryInfo, MountPoint, PlatformPaths};
        let mount = PathBuf::from("/");
        let stats = FsStats {
            total_bytes: 1_000_000_000_000,
            free_bytes: 500_000_000_000,
            available_bytes: 500_000_000_000,
            fs_type: "btrfs".into(),
            mount_point: mount.clone(),
            is_readonly: false,
        };
        MockPlatform::new(
            vec![MountPoint {
                path: mount.clone(),
                device: "mockdev".into(),
                fs_type: "btrfs".into(),
                is_ram_backed: false,
            }],
            std::collections::HashMap::from([(mount, stats)]),
            MemoryInfo {
                total_bytes: 64 << 30,
                available_bytes: 32 << 30,
                swap_total_bytes: 0,
                swap_free_bytes: 0,
            },
            PlatformPaths::default(),
        )
    }

    fn run_selected(
        selection: &Selection,
        platform: &MockPlatform,
    ) -> crate::scanner::compression::CompressionReport {
        crate::scanner::compression::run_discovered(
            selection,
            &policy(),
            crate::scanner::compression::CompressionMode::default(),
            &Config::default(),
            platform,
            &mut |_| {},
        )
        .unwrap()
    }

    #[test]
    fn discovered_execution_refuses_a_replaced_root_before_opening_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().canonicalize().unwrap();
        let root = parent.join("root");
        fs::create_dir(&root).unwrap();
        cold(&root.join("a.bin"));
        let selection = scan(
            std::slice::from_ref(&root),
            &DiscoveryLimits::default(),
            &policy(),
        );
        assert_eq!(selection.paths(), [root.join("a.bin")]);
        // Unchanged: the selection admits the file, and the mock filesystem
        // type is what stops this preview.
        let admitted = run_selected(&selection, &MockPlatform::healthy());
        assert_eq!(admitted.files.len(), 1);
        assert!(
            admitted.files[0].detail.contains("unsupported filesystem"),
            "{:?}",
            admitted.files[0]
        );
        // A lookalike root holding the same name is not the discovered root.
        fs::rename(&root, parent.join("moved")).unwrap();
        fs::create_dir(&root).unwrap();
        cold(&root.join("a.bin"));
        let refused = run_selected(&selection, &MockPlatform::healthy());
        assert_eq!(refused.files.len(), 1);
        let file = &refused.files[0];
        assert_eq!(file.outcome, "failed", "{file:?}");
        assert!(file.detail.contains("root was replaced"), "{file:?}");
        assert!(!file.mutation_attempted);
        assert_eq!(refused.unvisited_files, 0);
        assert_eq!(fs::read(root.join("a.bin")).unwrap(), b"cold contents");
    }

    #[test]
    fn discovered_execution_refuses_a_file_changed_after_discovery() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        cold(&root.join("changed.bin"));
        cold(&root.join("same.bin"));
        let selection = scan(
            std::slice::from_ref(&root),
            &DiscoveryLimits::default(),
            &policy(),
        );
        assert_eq!(
            selection.paths(),
            [root.join("changed.bin"), root.join("same.bin")]
        );
        // Still cold (mtime restored), so only the discovery stamp can refuse
        // it. The length differs because ctime alone can share a coarse tick.
        fs::write(root.join("changed.bin"), b"cold contents, edited").unwrap();
        filetime::set_file_mtime(
            root.join("changed.bin"),
            filetime::FileTime::from_unix_time(1, 0),
        )
        .unwrap();
        let report = run_selected(&selection, &btrfs_platform());
        assert_eq!(report.files.len(), 2);
        let changed = &report.files[0];
        assert_eq!(changed.outcome, "failed", "{changed:?}");
        assert!(
            changed
                .detail
                .contains("changed after compression discovery"),
            "{changed:?}"
        );
        assert!(!changed.mutation_attempted);
        // The unchanged sibling passes the selection checks and continues to
        // the real extent inspection, whatever this host's filesystem is.
        let same = &report.files[1];
        assert!(!same.detail.contains("discovery"), "{same:?}");
        assert!(!same.mutation_attempted);
        assert_eq!(fs::read(root.join("same.bin")).unwrap(), b"cold contents");
    }

    #[test]
    fn repository_pruning_preserves_sorted_continuation_without_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        fs::create_dir_all(root.join("b-repo/.git")).unwrap();
        cold(&root.join("b-repo/cold.bin"));
        for name in ["a.bin", "c.bin", "d.bin"] {
            cold(&root.join(name));
        }
        let policy = CompressionPolicy {
            max_files: 1,
            ..policy()
        };
        let first = scan(
            std::slice::from_ref(&root),
            &DiscoveryLimits::default(),
            &policy,
        );
        assert_eq!(first.paths(), [root.join("a.bin")]);
        let second = scan(
            std::slice::from_ref(&root),
            &DiscoveryLimits {
                after: Some(
                    continuation_path(first.report().resume_after_hex.as_deref().unwrap()).unwrap(),
                ),
                ..Default::default()
            },
            &policy,
        );
        assert_eq!(second.paths(), [root.join("c.bin")]);
        assert_eq!(second.report().skipped.get("git_repository"), Some(&1));
        let third = scan(
            std::slice::from_ref(&root),
            &DiscoveryLimits {
                after: Some(
                    continuation_path(second.report().resume_after_hex.as_deref().unwrap())
                        .unwrap(),
                ),
                ..Default::default()
            },
            &policy,
        );
        assert_eq!(third.paths(), [root.join("d.bin")]);
        assert!(third.report().complete);
        assert!(third.report().resume_after_hex.is_none());
        assert_eq!(
            fs::read(root.join("b-repo/cold.bin")).unwrap(),
            b"cold contents"
        );
    }
}
