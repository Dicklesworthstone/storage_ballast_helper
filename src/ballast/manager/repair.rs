//! Repair an existing sacrificial reserve without unlinking it first.
//!
//! A corrupt header does not make the file's allocated space worthless. Keep
//! its inode linked throughout allocation and writing; an ENOSPC, I/O error or
//! process death must not turn repair into deletion of the remaining reserve.
//! This is allocation preservation, not transactional preservation of ballast
//! contents. An interrupted repair can still have a damaged header and can be
//! retried, or released by the ordinary configured-slot emergency path.
//!
//! Callers hold the pool lock and have already admitted the full configured
//! file size against live headroom (including possible CoW allocation). No
//! temporary reserve or hidden recovery file is created.

use super::BallastManager;
use crate::core::errors::{Result, SbhError};

pub(super) fn existing(manager: &BallastManager, index: u32) -> Result<bool> {
    #[cfg(unix)]
    {
        unix::repair_with(manager, index, unix::prepare_storage)
    }
    #[cfg(not(unix))]
    {
        let path = manager.file_path(index);
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(SbhError::io(&path, error)),
            Ok(_) => Err(SbhError::Runtime {
                details: "safe in-place ballast repair is unavailable on this platform".to_string(),
            }),
        }
    }
}

#[cfg(unix)]
mod unix {
    use super::{BallastManager, Result, SbhError};
    use std::fs::{self, File, Metadata, OpenOptions};
    use std::io::{self, Seek, SeekFrom, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;

    use rustix::fs::{Mode, OFlags};

    use super::super::{HEADER_SIZE, ballast_file_name, ballast_header_buffer};

    fn invalid(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    fn same_identity(left: &Metadata, right: &Metadata) -> bool {
        left.dev() == right.dev() && left.ino() == right.ino()
    }

    fn eligible(file: &Metadata, pool: &Metadata) -> bool {
        file.is_file() && file.nlink() == 1 && file.dev() == pool.dev()
    }

    fn current(
        manager: &BallastManager,
        path: &Path,
        pool: &Metadata,
        file: &File,
        initial: &Metadata,
    ) -> io::Result<()> {
        let pool_now = fs::symlink_metadata(&manager.ballast_dir)?;
        let named = fs::symlink_metadata(path)?;
        let opened = file.metadata()?;
        if !pool_now.is_dir()
            || !same_identity(pool, &pool_now)
            || !eligible(&named, pool)
            || !eligible(&opened, pool)
            || !same_identity(initial, &named)
            || !same_identity(initial, &opened)
        {
            return Err(invalid("ballast file or pool changed during repair"));
        }
        Ok(())
    }

    // The production allocator and deterministic failure injections use the
    // same open/identity/finalization boundary. A preparation error never enters
    // the shrinking/header-finalization path and never invokes unlink cleanup.
    pub(super) fn repair_with(
        manager: &BallastManager,
        index: u32,
        prepare: impl FnOnce(&BallastManager, &mut File, &Path, u64) -> Result<()>,
    ) -> Result<bool> {
        let path = manager.file_path(index);
        let size = manager.config.file_size_bytes;
        if size < HEADER_SIZE as u64 {
            return Err(SbhError::InvalidConfig {
                details: format!("file_size_bytes ({size}) must be >= HEADER_SIZE ({HEADER_SIZE})"),
            });
        }
        let header = ballast_header_buffer(index, size)?;
        let io = |error| SbhError::io(&path, error);
        let pool = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&manager.ballast_dir)
            .map_err(|error| SbhError::io(&manager.ballast_dir, error))?;
        let pool_meta = pool.metadata().map_err(io)?;
        let before = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(io(error)),
        };
        if !eligible(&before, &pool_meta) {
            return Err(io(invalid(
                "ballast repair requires an independent same-device regular file",
            )));
        }
        let name = ballast_file_name(index);
        let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        #[cfg(target_os = "linux")]
        let fd = {
            use rustix::fs::{ResolveFlags, openat2};
            // Also reject same-device file bind mounts: repairing such a slot
            // would write through to an external file, unlike unlink (EBUSY).
            openat2(
                &pool,
                name.as_str(),
                flags,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
            )
        };
        #[cfg(not(target_os = "linux"))]
        let fd = rustix::fs::openat(&pool, name.as_str(), flags, Mode::empty());
        let mut file = File::from(fd.map_err(|error| io(error.into()))?);
        current(manager, &path, &pool_meta, &file, &before).map_err(io)?;
        let opened = file.metadata().map_err(io)?;
        if opened.len() != before.len()
            || opened.mtime() != before.mtime()
            || opened.mtime_nsec() != before.mtime_nsec()
            || opened.ctime() != before.ctime()
            || opened.ctime_nsec() != before.ctime_nsec()
        {
            return Err(io(invalid("ballast changed before repair started")));
        }

        prepare(manager, &mut file, &path, size)?;
        file.sync_all().map_err(io)?;
        current(manager, &path, &pool_meta, &file, &before).map_err(io)?;
        // Write a complete new header only after storage preparation succeeds.
        // A failed or interrupted header write still leaves the reserve linked.
        file.seek(SeekFrom::Start(0)).map_err(io)?;
        file.write_all(&header).map_err(io)?;
        file.sync_all().map_err(io)?;
        current(manager, &path, &pool_meta, &file, &before).map_err(io)?;
        // Shrink an oversized slot only at the end, never before replacement
        // allocation/writes succeed. Failure after this point retains at least
        // the requested logical length, not necessarily the old larger length.
        file.set_len(size).map_err(io)?;
        file.sync_all().map_err(io)?;
        current(manager, &path, &pool_meta, &file, &before).map_err(io)?;
        manager
            .verify_single_file(&path, index)
            .map_err(|details| SbhError::Runtime {
                details: format!("repaired ballast failed verification: {details}"),
            })?;
        current(manager, &path, &pool_meta, &file, &before).map_err(io)?;
        Ok(true)
    }

    pub(super) fn prepare_storage(
        manager: &BallastManager,
        file: &mut File,
        path: &Path,
        size: u64,
    ) -> Result<()> {
        #[cfg(target_os = "linux")]
        if !manager.skip_fallocate {
            use rustix::fs::{FallocateFlags, fallocate};
            // The path-based PAL may open with O_TRUNC. Repair must use the
            // already-verified descriptor and never discard old allocation.
            match fallocate(&*file, FallocateFlags::KEEP_SIZE, 0, size) {
                Ok(()) => return Ok(()),
                Err(error) => {
                    let error = io::Error::from(error);
                    // Only an unsupported allocation primitive merits a write
                    // fallback. ENOSPC, EDQUOT and I/O failures stop here.
                    if !error.raw_os_error().is_some_and(|code| {
                        code == libc::EOPNOTSUPP || code == libc::ENOSYS || code == libc::EINVAL
                    }) {
                        return Err(SbhError::io(path, error));
                    }
                }
            }
        }
        // CoW repair, and platforms without the descriptor allocator, write
        // incompressible data through the open file without truncating it.
        // Rewriting the full data range also fills holes in sparse reserves.
        file.seek(SeekFrom::Start(HEADER_SIZE as u64))
            .map_err(|error| SbhError::io(path, error))?;
        manager.write_random_data(file, size - HEADER_SIZE as u64, path)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::core::config::BallastConfig;
        use std::io::Read;
        use std::os::unix::fs::symlink;

        const SIZE: u64 = 32 * 1024;

        fn fixture() -> (tempfile::TempDir, BallastManager, std::path::PathBuf) {
            let temp = tempfile::tempdir().unwrap();
            let config = BallastConfig {
                file_count: 1,
                file_size_bytes: SIZE,
                replenish_cooldown_minutes: 0,
                auto_provision: true,
                overrides: std::collections::BTreeMap::new(),
            };
            let mut manager =
                BallastManager::new_unfloored(temp.path().join("pool"), config).unwrap();
            manager.set_skip_fallocate(true);
            assert_eq!(manager.provision(None).unwrap().files_created, 1);
            let path = manager.file_path(1);
            (temp, manager, path)
        }

        fn corrupt_header(path: &Path) {
            let mut file = OpenOptions::new().write(true).open(path).unwrap();
            file.write_all(b"BROKEN").unwrap();
            file.sync_all().unwrap();
        }

        #[test]
        fn both_maintenance_paths_repair_without_replacing_the_inode() {
            for gradual in [false, true] {
                for random in [false, true] {
                    let (_temp, mut manager, path) = fixture();
                    let inode = fs::metadata(&path).unwrap().ino();
                    corrupt_header(&path);
                    manager.set_skip_fallocate(random);
                    let report = if gradual {
                        manager.replenish_one(None).unwrap()
                    } else {
                        manager.provision(None).unwrap()
                    };
                    assert_eq!(report.files_created, 1, "{report:?}");
                    assert!(report.errors.is_empty(), "{report:?}");
                    assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
                    assert_eq!(manager.verify().unwrap().files_ok, 1);
                    assert_eq!(manager.releasable_bytes(), SIZE);
                    assert_eq!(fs::read_dir(manager.ballast_dir()).unwrap().count(), 2);
                }
            }
        }

        #[test]
        fn truncated_reserve_grows_in_place_and_remains_releasable() {
            let (_temp, mut manager, path) = fixture();
            let inode = fs::metadata(&path).unwrap().ino();
            OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(8192)
                .unwrap();
            let report = manager.replenish_one(None).unwrap();
            assert_eq!(report.files_created, 1, "{report:?}");
            assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
            assert_eq!(manager.verify().unwrap().files_ok, 1);
            assert_eq!(manager.release(1).unwrap().bytes_freed, SIZE);
        }

        #[test]
        fn failure_before_allocation_preserves_the_existing_reserve() {
            let (_temp, manager, path) = fixture();
            let before = fs::read(&path).unwrap();
            let inode = fs::metadata(&path).unwrap().ino();
            let result = repair_with(&manager, 1, |_, _, path, _| {
                Err(SbhError::io(
                    path,
                    io::Error::from_raw_os_error(libc::ENOSPC),
                ))
            });
            assert!(result.is_err());
            assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
            assert_eq!(fs::read(&path).unwrap(), before);
        }

        #[test]
        fn partial_write_failure_keeps_the_named_allocation_for_emergency_release() {
            let (_temp, mut manager, path) = fixture();
            let before = fs::metadata(&path).unwrap();
            let result = repair_with(&manager, 1, |_, file, path, _| {
                file.seek(SeekFrom::End(0)).unwrap();
                file.write_all(&[7u8; 4096]).unwrap();
                file.sync_all().unwrap();
                Err(SbhError::io(
                    path,
                    io::Error::from_raw_os_error(libc::ENOSPC),
                ))
            });
            assert!(result.is_err());
            let after = fs::metadata(&path).unwrap();
            assert_eq!(before.ino(), after.ino());
            assert!(after.len() >= before.len());
            assert!(after.blocks() >= before.blocks());
            manager.update_config(manager.config().clone());
            assert_eq!(manager.available_count(), 1);
            assert!(manager.release(1).unwrap().bytes_freed >= SIZE);
        }

        #[test]
        fn failed_downsize_does_not_discard_the_old_larger_reserve() {
            let (_temp, mut manager, path) = fixture();
            let mut config = manager.config().clone();
            config.file_size_bytes = SIZE / 2;
            manager.update_config(config);
            let before = fs::read(&path).unwrap();
            assert!(
                repair_with(&manager, 1, |_, _, path, _| {
                    Err(SbhError::io(
                        path,
                        io::Error::other("injected allocation failure"),
                    ))
                })
                .is_err()
            );
            assert_eq!(fs::read(&path).unwrap(), before);
            let inode = fs::metadata(&path).unwrap().ino();
            let report = manager.replenish_one(None).unwrap();
            assert_eq!(report.files_created, 1, "{report:?}");
            assert_eq!(fs::metadata(&path).unwrap().len(), SIZE / 2);
            assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
        }

        #[test]
        fn invalid_configuration_never_deletes_an_existing_slot() {
            for gradual in [false, true] {
                let (_temp, mut manager, path) = fixture();
                let before = fs::read(&path).unwrap();
                let mut config = manager.config().clone();
                config.file_size_bytes = 1;
                manager.update_config(config);
                let report = if gradual {
                    manager.replenish_one(None).unwrap()
                } else {
                    manager.provision(None).unwrap()
                };
                assert_eq!(report.files_created, 0);
                assert!(!report.errors.is_empty());
                assert_eq!(fs::read(&path).unwrap(), before);
            }
        }

        #[test]
        fn headroom_refusal_never_starts_repair() {
            let (_temp, mut manager, path) = fixture();
            corrupt_header(&path);
            let before = fs::read(&path).unwrap();
            manager.set_provision_floor(20.0);
            for gradual in [false, true] {
                let report = if gradual {
                    manager.replenish_one(Some(&|| 0.0)).unwrap()
                } else {
                    manager.provision(Some(&|| 0.0)).unwrap()
                };
                assert_eq!(report.files_created, 0);
                assert_eq!(report.skipped_for_floor, 1);
                assert_eq!(fs::read(&path).unwrap(), before);
            }
        }

        #[test]
        fn symlink_slots_never_write_through_to_external_or_missing_targets() {
            for dangling in [false, true] {
                let (temp, mut manager, path) = fixture();
                let saved = temp.path().join("saved");
                fs::rename(&path, &saved).unwrap();
                let external = if dangling {
                    temp.path().join("absent")
                } else {
                    saved.clone()
                };
                let before = fs::read(&saved).unwrap();
                symlink(&external, &path).unwrap();
                let report = manager.provision(None).unwrap();
                assert_eq!(report.files_created, 0);
                assert!(!report.errors.is_empty());
                assert_eq!(fs::read_link(&path).unwrap(), external);
                assert_eq!(fs::read(saved).unwrap(), before);
                if dangling {
                    assert!(!external.exists());
                }
            }
        }

        #[test]
        fn hard_linked_slot_is_not_rewritten() {
            let (temp, mut manager, path) = fixture();
            corrupt_header(&path);
            let external = temp.path().join("external");
            fs::hard_link(&path, &external).unwrap();
            let before = fs::read(&external).unwrap();
            let report = manager.replenish_one(None).unwrap();
            assert_eq!(report.files_created, 0);
            assert!(!report.errors.is_empty());
            assert_eq!(fs::read(external).unwrap(), before);
            assert_eq!(fs::metadata(&path).unwrap().nlink(), 2);
        }

        #[test]
        fn nonregular_slots_are_rejected_without_opening_them() {
            for fifo in [false, true] {
                let (temp, manager, path) = fixture();
                fs::rename(&path, temp.path().join("saved")).unwrap();
                if fifo {
                    nix::unistd::mkfifo(path.as_path(), nix::sys::stat::Mode::S_IRUSR).unwrap();
                } else {
                    fs::create_dir(&path).unwrap();
                }
                assert!(
                    repair_with(&manager, 1, |_, _, _, _| {
                        panic!("a nonregular slot must not reach storage preparation")
                    })
                    .is_err()
                );
                assert!(fs::symlink_metadata(path).is_ok());
            }
        }

        #[test]
        fn changed_slot_is_not_overwritten_or_unlinked_at_finalization() {
            let (temp, manager, path) = fixture();
            let saved = temp.path().join("saved");
            let before = fs::read(&path).unwrap();
            assert!(
                repair_with(&manager, 1, |_, _, _, _| {
                    fs::rename(&path, &saved).unwrap();
                    fs::write(&path, b"replacement owned by another operation").unwrap();
                    Ok(())
                })
                .is_err()
            );
            assert_eq!(
                fs::read(&path).unwrap(),
                b"replacement owned by another operation"
            );
            assert_eq!(fs::read(saved).unwrap(), before);
        }

        #[test]
        fn changed_pool_is_not_used_for_header_publication() {
            let (temp, manager, path) = fixture();
            let saved = temp.path().join("saved-pool");
            let before = fs::read(&path).unwrap();
            assert!(
                repair_with(&manager, 1, |_, _, _, _| {
                    fs::rename(manager.ballast_dir(), &saved).unwrap();
                    fs::create_dir(manager.ballast_dir()).unwrap();
                    fs::write(&path, b"new pool reserve").unwrap();
                    Ok(())
                })
                .is_err()
            );
            assert_eq!(fs::read(&path).unwrap(), b"new pool reserve");
            assert_eq!(fs::read(saved.join(ballast_file_name(1))).unwrap(), before);
        }

        #[test]
        fn newly_linked_reserve_is_rejected_before_header_finalization() {
            let (temp, manager, path) = fixture();
            let before = fs::read(&path).unwrap();
            let external = temp.path().join("external");
            assert!(
                repair_with(&manager, 1, |_, _, _, _| {
                    fs::hard_link(&path, &external).unwrap();
                    Ok(())
                })
                .is_err()
            );
            assert_eq!(fs::read(external).unwrap(), before);
        }

        #[test]
        fn a_sparse_slot_is_filled_without_retiring_its_identity() {
            let (_temp, mut manager, path) = fixture();
            let inode = fs::metadata(&path).unwrap().ino();
            let file = OpenOptions::new().write(true).open(&path).unwrap();
            file.set_len(HEADER_SIZE as u64).unwrap();
            file.set_len(SIZE).unwrap();
            corrupt_header(&path);
            let report = manager.replenish_one(None).unwrap();
            assert_eq!(report.files_created, 1, "{report:?}");
            assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
            assert_eq!(manager.verify().unwrap().files_ok, 1);
            let mut bytes = Vec::new();
            File::open(path).unwrap().read_to_end(&mut bytes).unwrap();
            assert!(bytes[HEADER_SIZE..].iter().any(|&byte| byte != 0));
        }
    }
}
