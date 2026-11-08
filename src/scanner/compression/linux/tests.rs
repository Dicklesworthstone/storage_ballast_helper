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
fn newly_mapped_files_are_refused_even_when_cached_evidence_is_empty() {
    use crate::core::errors::Result;
    use crate::platform::pal::{FsStats, MemoryInfo, MountPoint, PlatformPaths, ServiceManager};
    use crate::platform::types::{ExecutablesResult, MappedRegion, OpenFilesResult};
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;

    #[derive(Default)]
    struct NewMapping {
        fresh_queries: AtomicUsize,
    }

    impl Platform for NewMapping {
        fn fs_stats(&self, path: &Path) -> Result<FsStats> {
            MockPlatform::healthy().fs_stats(path)
        }
        fn mount_points(&self) -> Result<Vec<MountPoint>> {
            Ok(Vec::new())
        }
        fn is_ram_backed(&self, _: &Path) -> Result<bool> {
            Ok(false)
        }
        fn default_paths(&self) -> PlatformPaths {
            PlatformPaths::default()
        }
        fn memory_info(&self) -> Result<MemoryInfo> {
            MockPlatform::healthy().memory_info()
        }
        fn service_manager(&self) -> Box<dyn ServiceManager> {
            panic!("activity checks must not control services")
        }
        fn open_files_under(&self, _: &Path) -> Result<OpenFilesResult> {
            Ok(OpenFilesResult::complete(Vec::new()))
        }
        fn executables_under(&self, _: &Path) -> Result<ExecutablesResult> {
            Ok(ExecutablesResult {
                processes: Vec::new(),
                complete: true,
            })
        }
        fn build_directories_in_use_checked(&self) -> (Vec<(i32, PathBuf)>, bool) {
            (Vec::new(), true)
        }
        fn mmap_regions_under(&self, _: &Path) -> Result<Vec<MappedRegion>> {
            // The reader mapped the file after this cached empty observation.
            Ok(Vec::new())
        }
        fn mmap_regions_under_fresh(&self, path: &Path) -> Result<Vec<MappedRegion>> {
            if self.fresh_queries.fetch_add(1, Ordering::Relaxed) == 0 {
                return Ok(Vec::new());
            }
            Ok(vec![MappedRegion {
                pid: 424_242,
                path: path.to_path_buf(),
                start_address: Some(0x1000),
                end_address: Some(0x2000),
                protection: Some("r--".into()),
            }])
        }
    }

    let platform = NewMapping::default();
    let path = Path::new("/tmp/newly-mapped-input");
    assert!(check_active(path, -1, &platform).is_ok());
    assert!(platform.mmap_regions_under(path).unwrap().is_empty());
    let error = check_active(path, -1, &platform).unwrap_err();
    assert!(error.to_string().contains("active memory mappings"));
    assert_eq!(platform.fresh_queries.load(Ordering::Relaxed), 2);
}

#[test]
fn fresh_marker_checks_do_not_reuse_negative_preflight_caches() {
    let temp = crate::tempdir_outside_git();
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
    let temp = crate::tempdir_outside_git();
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
    let temp = crate::tempdir_outside_git();
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
    let temp = crate::tempdir_outside_git();
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
    let temp = crate::tempdir_outside_git();
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

    let temp = crate::tempdir_outside_git();
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
            &PassControl {
                deadline: Instant::now() + Duration::from_secs(30),
                stop: None,
            },
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
    let temp = crate::tempdir_outside_git();
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

#[test]
fn a_stop_ends_a_started_file_between_chunks_but_the_deadline_does_not() {
    let stop = AtomicBool::new(false);
    let control = PassControl {
        deadline: Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
        stop: Some(&stop),
    };
    // Past the pass deadline no file starts, but a started one goes on.
    assert_eq!(control.admit().unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert!(control.check_stop().is_ok());
    stop.store(true, Ordering::Release);
    assert_eq!(
        control.check_stop().unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(
        control.admit().unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    let unstoppable = PassControl {
        deadline: Instant::now() + Duration::from_secs(30),
        stop: None,
    };
    assert!(unstoppable.admit().is_ok());
}

#[test]
fn a_revocation_or_expiry_during_chunk_preparation_prevents_the_first_rewrite() {
    use std::os::unix::fs::FileExt;
    use std::sync::atomic::AtomicU64;
    use std::sync::mpsc;

    for (case, expected) in [
        ("revoked", Some(io::ErrorKind::Interrupted)),
        ("expired", Some(io::ErrorKind::TimedOut)),
        ("unchanged", None),
    ] {
        let temp = crate::tempdir_outside_git();
        let path = temp.path().canonicalize().unwrap().join("cold.bin");
        fs::write(&path, b"original contents").unwrap();
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let stop = AtomicBool::new(false);
        let elapsed = AtomicU64::new(0);
        let started = Instant::now();
        let control = PassControl {
            // A started file owns its file allowance; an expired pass clock
            // must not stop the unchanged positive control.
            deadline: started,
            stop: Some(&stop),
        };
        let (entered, probe_started) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        let (result, mutations) = std::thread::scope(|scope| {
            let file = &file;
            let path = &path;
            let elapsed = &elapsed;
            let worker = scope.spawn(move || {
                let mut mutations = 0;
                let result = apply_chunk(
                    &control,
                    started + Duration::from_secs(10),
                    || {
                        // This is the same preparation/mutation boundary used
                        // by process_file. Real descriptor checks surround a
                        // controlled preparation pause; the test
                        // does not require a writable Btrfs filesystem.
                        let stamp = FileStamp::read(file)?;
                        check_active(path, file.as_raw_fd(), &MockPlatform::healthy())?;
                        entered.send(()).unwrap();
                        resume.recv_timeout(Duration::from_secs(5)).unwrap();
                        verify_path(path, file, stamp)?;
                        Ok(vec![(0, 4), (4, 4)])
                    },
                    |offset, length| {
                        assert_eq!(length, 4);
                        mutations += 1;
                        file.write_all_at(b"DONE", offset)
                    },
                    || started + Duration::from_secs(elapsed.load(Ordering::Acquire)),
                );
                (result, mutations)
            });
            probe_started.recv_timeout(Duration::from_secs(5)).unwrap();
            match case {
                "revoked" => stop.store(true, Ordering::Release),
                "expired" => elapsed.store(10, Ordering::Release),
                _ => {}
            }
            release.send(()).unwrap();
            worker.join().unwrap()
        });
        if let Some(kind) = expected {
            assert_eq!(result.unwrap_err().kind(), kind, "{case}");
            assert_eq!(mutations, 0, "{case}");
            assert_eq!(fs::read(&path).unwrap(), b"original contents", "{case}");
        } else {
            result.unwrap();
            assert_eq!(mutations, 2);
            assert_eq!(fs::read(&path).unwrap(), b"DONEDONE contents");
        }
    }
}

#[test]
fn each_native_range_renews_revocation_and_the_started_files_deadline() {
    use std::cell::Cell;
    use std::os::unix::fs::FileExt;

    for (case, expected) in [
        ("revoked", Some(io::ErrorKind::Interrupted)),
        ("expired", Some(io::ErrorKind::TimedOut)),
        ("unchanged", None),
    ] {
        let temp = crate::tempdir_outside_git();
        let path = temp.path().join("cold.bin");
        fs::write(&path, b"original contents").unwrap();
        let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        let stop = AtomicBool::new(false);
        let started = Instant::now();
        let elapsed = Cell::new(0);
        let control = PassControl {
            deadline: started,
            stop: Some(&stop),
        };
        let mut mutations = 0;
        let result = apply_chunk(
            &control,
            started + Duration::from_secs(10),
            || Ok(vec![(0, 4), (4, 4)]),
            |offset, length| {
                assert_eq!(length, 4);
                file.write_all_at(b"DONE", offset)?;
                mutations += 1;
                // A single logical chunk can contain several raw extents.
                // Finishing the first one grants no permission for the next.
                match case {
                    "revoked" => stop.store(true, Ordering::Release),
                    "expired" => elapsed.set(10),
                    _ => {}
                }
                Ok(())
            },
            || started + Duration::from_secs(elapsed.get()),
        );
        if let Some(kind) = expected {
            assert_eq!(result.unwrap_err().kind(), kind, "{case}");
            assert_eq!(mutations, 1, "{case}");
            assert_eq!(fs::read(&path).unwrap(), b"DONEinal contents", "{case}");
        } else {
            result.unwrap();
            assert_eq!(mutations, 2);
            assert_eq!(fs::read(&path).unwrap(), b"DONEDONE contents");
        }
    }
}

#[test]
fn a_refused_or_failed_chunk_never_reaches_a_later_range() {
    let stop = AtomicBool::new(true);
    let control = PassControl {
        deadline: Instant::now() + Duration::from_secs(30),
        stop: Some(&stop),
    };
    let error = apply_chunk(
        &control,
        control.deadline,
        || panic!("revoked work must not start native preparation"),
        |_, _| panic!("revoked work must not reach the rewrite"),
        Instant::now,
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);

    stop.store(false, Ordering::Release);
    let error = apply_chunk(
        &control,
        control.deadline,
        || {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "probe refused",
            ))
        },
        |_, _| panic!("a failed preparation must not reach the rewrite"),
        Instant::now,
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    let mut mutations = 0;
    let error = apply_chunk(
        &control,
        control.deadline,
        || Ok(vec![(0, 4), (4, 4)]),
        |_, _| {
            mutations += 1;
            Err(io::Error::new(io::ErrorKind::StorageFull, "rewrite failed"))
        },
        Instant::now,
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::StorageFull);
    assert_eq!(mutations, 1, "native errors stop the remaining ranges");
}

#[test]
fn a_raised_stop_ends_the_pass_before_any_file_is_opened() {
    let temp = crate::tempdir_outside_git();
    let path = temp.path().join("cold.bin");
    fs::write(&path, b"untouched").unwrap();
    let stop = AtomicBool::new(true);
    let mut observed = 0;
    let report = run(
        std::slice::from_ref(&path),
        None,
        &CompressionPolicy::default(),
        CompressionMode::default(),
        &Config::default(),
        &MockPlatform::healthy(),
        Some(&stop),
        &mut |_| observed += 1,
    )
    .unwrap();
    assert!(report.files.is_empty());
    assert_eq!(observed, 0);
    assert_eq!(report.unvisited_files, 1);
    assert_eq!(report.exit_code, 4, "unvisited files are not a clean pass");
    assert!(
        report
            .stop_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("no longer allows changes")),
        "{:?}",
        report.stop_reason
    );
    assert!(report.journal_path.is_none());
    assert_eq!(fs::read(&path).unwrap(), b"untouched");
}
