//! Exclusive, descriptor-owned creation of a new ballast slot.
//!
//! The caller holds the pool lock and has admitted a full file against fresh
//! headroom. O_EXCL resolves the absent-slot race in the kernel; allocation,
//! random fallback and header writes all use that same file descriptor. Error
//! cleanup checks identity relative to the opened pool, never a bare pathname.
//! A changed or multiply linked entry is retained rather than guessed at.
//!
//! This does not make a directory writable by hostile same-UID processes a
//! safe namespace: an unlink identity check is not an atomic compare-and-unlink.
//! Pool directories and the platform implementation remain trust boundaries.

use super::BallastManager;
use crate::core::errors::{Result, SbhError};

pub(super) fn create(manager: &BallastManager, index: u32) -> Result<()> {
    #[cfg(unix)]
    {
        unix::create_with(manager, index, unix::prepare)
    }
    #[cfg(not(unix))]
    {
        let _ = (manager, index);
        Err(SbhError::UnsupportedPlatform {
            details: "safe ballast creation requires Unix descriptor-relative filesystem operations".to_string(),
        })
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::fs::{self, File, Metadata, OpenOptions};
    use std::io::{self, Seek, SeekFrom, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};

    use rustix::fs::{AtFlags, Mode, OFlags, openat, statat, unlinkat};

    use super::super::{HEADER_SIZE, ballast_file_name, ballast_header_buffer, is_storage_exhausted_error};
    use crate::platform::types::PalError;

    fn invalid(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    fn same_identity(left: &Metadata, right: &Metadata) -> bool {
        left.dev() == right.dev() && left.ino() == right.ino()
    }

    fn allocated(metadata: &Metadata, size: u64) -> bool {
        metadata.is_file()
            && metadata.len() >= size
            && metadata.blocks().checked_mul(512).is_some_and(|bytes| bytes >= size)
    }

    struct NewSlot {
        pool: File,
        pool_path: PathBuf,
        name: String,
        file: File,
        identity: Metadata,
        committed: bool,
    }

    impl NewSlot {
        fn open(manager: &BallastManager, index: u32) -> io::Result<Self> {
            let pool = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&manager.ballast_dir)?;
            let name = ballast_file_name(index);
            // No prior existence check confers permission to truncate. Even a
            // dangling symlink or a file inserted after repair's absent result
            // is a collision, not an allocation target or cleanup candidate.
            let file = File::from(openat(
                &pool,
                name.as_str(),
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )?);
            let identity = file.metadata()?;
            let slot = Self {
                pool,
                pool_path: manager.ballast_dir.clone(),
                name,
                file,
                identity,
                committed: false,
            };
            slot.current()?;
            Ok(slot)
        }

        fn named_is_ours(&self) -> io::Result<bool> {
            let named = match statat(&self.pool, self.name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
                Ok(named) => named,
                Err(rustix::io::Errno::NOENT) => return Ok(false),
                Err(error) => return Err(error.into()),
            };
            #[allow(clippy::unnecessary_cast)]
            Ok(named.st_dev as u64 == self.identity.dev()
                && named.st_ino as u64 == self.identity.ino()
                && rustix::fs::FileType::from_raw_mode(named.st_mode) == rustix::fs::FileType::RegularFile
                && named.st_nlink == 1)
        }

        fn current(&self) -> io::Result<()> {
            let pool = self.pool.metadata()?;
            let named_pool = fs::symlink_metadata(&self.pool_path)?;
            let file = self.file.metadata()?;
            if !named_pool.is_dir()
                || !same_identity(&pool, &named_pool)
                || !same_identity(&self.identity, &file)
                || !file.is_file()
                || file.nlink() != 1
                || file.dev() != pool.dev()
                || !self.named_is_ours()?
            {
                return Err(invalid("ballast slot or pool changed during creation"));
            }
            Ok(())
        }
    }

    impl Drop for NewSlot {
        fn drop(&mut self) {
            if !self.committed && self.named_is_ours().unwrap_or(false) {
                // Cleanup is restricted to the inode this attempt created.
                // A renamed pool is still reached through the original fd.
                if unlinkat(&self.pool, self.name.as_str(), AtFlags::empty()).is_ok() {
                    let _ = self.pool.sync_all();
                }
            }
        }
    }

    pub(super) fn create_with(
        manager: &BallastManager,
        index: u32,
        prepare: impl FnOnce(&BallastManager, &mut File, &Path, u64) -> Result<()>,
    ) -> Result<()> {
        let size = manager.config.file_size_bytes;
        if size < HEADER_SIZE as u64 {
            return Err(SbhError::InvalidConfig {
                details: format!("file_size_bytes ({size}) must be >= HEADER_SIZE ({HEADER_SIZE})"),
            });
        }
        let header = ballast_header_buffer(index, size)?;
        let path = manager.file_path(index);
        let io = |error| SbhError::io(&path, error);
        let mut slot = NewSlot::open(manager, index).map_err(io)?;
        // Persist the ordinary slot name before allocation. An interrupted
        // process leaves discoverable reserve, never a hidden staging pool.
        slot.pool.sync_all().map_err(io)?;
        prepare(manager, &mut slot.file, &path, size)?;
        slot.current().map_err(io)?;
        slot.file.seek(SeekFrom::Start(0)).map_err(io)?;
        slot.file.write_all(&header).map_err(io)?;
        slot.file.set_len(size).map_err(io)?;
        slot.file.sync_all().map_err(io)?;
        slot.current().map_err(io)?;
        let metadata = slot.file.metadata().map_err(io)?;
        if metadata.len() != size || !allocated(&metadata, size) {
            return Err(io(invalid("new ballast file is not fully allocated")));
        }
        slot.pool.sync_all().map_err(io)?;
        slot.current().map_err(io)?;
        slot.committed = true;
        Ok(())
    }

    fn fallback_allowed(error: &SbhError) -> bool {
        if is_storage_exhausted_error(error) {
            return false;
        }
        match error {
            SbhError::Io { source, .. } => source.kind() == io::ErrorKind::Unsupported
                || source.raw_os_error().is_some_and(|code| {
                    code == libc::ENOSYS || code == libc::EOPNOTSUPP || code == libc::EINVAL
                }),
            SbhError::Pal { source: PalError::NotImplemented { .. } } => true,
            // The PAL's block verifier reports underallocation distinctly from
            // native errno failures. APFS may accept preallocation yet leave
            // holes; refill those through this same descriptor, not a reopen.
            SbhError::Pal { source: PalError::MethodFailed { method_name, details, .. } } => {
                method_name == "preallocate_file"
                    && details.contains("allocated bytes after preallocation; expected at least")
            }
            _ => false,
        }
    }

    pub(super) fn prepare(
        manager: &BallastManager,
        file: &mut File,
        path: &Path,
        size: u64,
    ) -> Result<()> {
        if !manager.skip_fallocate {
            match manager.platform.preallocate_open_file(file, path, size) {
                Ok(()) => {
                    if allocated(&file.metadata().map_err(|error| SbhError::io(path, error))?, size) {
                        return Ok(());
                    }
                    // A nominal success (including a mock) does not establish
                    // actual block allocation. Fill the holes below.
                }
                Err(error) if fallback_allowed(&error) => {}
                Err(error) => return Err(error),
            }
        }
        file.seek(SeekFrom::Start(HEADER_SIZE as u64))
            .map_err(|error| SbhError::io(path, error))?;
        manager.write_random_data(file, size - HEADER_SIZE as u64, path)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::core::config::BallastConfig;
        use crate::platform::pal::MockPlatform;
        use std::sync::Arc;
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        const SIZE: u64 = 32768;

        fn fixture() -> (tempfile::TempDir, BallastManager) {
            let temp = tempfile::tempdir().unwrap();
            let pool = temp.path().join("pool");
            fs::create_dir(&pool).unwrap();
            let config = BallastConfig {
                file_count: 1,
                file_size_bytes: SIZE,
                replenish_cooldown_minutes: 0,
                auto_provision: true,
                overrides: std::collections::BTreeMap::new(),
            };
            let manager = BallastManager::new_unfloored(pool, config).unwrap();
            (temp, manager)
        }

        #[test]
        fn native_and_random_creation_make_real_owner_only_reserve() {
            for random in [false, true] {
                let (_temp, mut manager) = fixture();
                manager.set_skip_fallocate(random);
                let report = manager.provision(None).unwrap();
                assert_eq!(report.files_created, 1, "{report:?}");
                assert!(report.errors.is_empty(), "{report:?}");
                let path = manager.file_path(1);
                let metadata = fs::metadata(&path).unwrap();
                assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
                assert_eq!(metadata.nlink(), 1);
                assert_eq!(metadata.len(), SIZE);
                assert!(allocated(&metadata, SIZE));
                assert_eq!(manager.verify().unwrap().files_ok, 1);
                assert_eq!(manager.release(1).unwrap().bytes_freed, SIZE);
            }
        }

        #[test]
        fn collision_never_truncates_or_removes_a_competing_file() {
            let (_temp, manager) = fixture();
            let path = manager.file_path(1);
            fs::write(&path, b"another creator owns this").unwrap();
            let inode = fs::metadata(&path).unwrap().ino();
            assert!(create_with(&manager, 1, |_, _, _, _| panic!("collision must not allocate")).is_err());
            assert_eq!(fs::read(&path).unwrap(), b"another creator owns this");
            assert_eq!(fs::metadata(path).unwrap().ino(), inode);
        }

        #[test]
        fn links_and_special_entries_are_collisions_not_cleanup_targets() {
            for kind in 0..4 {
                let (temp, manager) = fixture();
                let path = manager.file_path(1);
                let external = temp.path().join("external");
                fs::write(&external, b"keep external").unwrap();
                match kind {
                    0 => symlink(&external, &path).unwrap(),
                    1 => symlink(temp.path().join("absent"), &path).unwrap(),
                    2 => fs::hard_link(&external, &path).unwrap(),
                    _ => fs::create_dir(&path).unwrap(),
                }
                assert!(create_with(&manager, 1, |_, _, _, _| panic!("must not allocate")).is_err());
                assert!(fs::symlink_metadata(path).is_ok());
                assert_eq!(fs::read(external).unwrap(), b"keep external");
            }
        }

        #[test]
        fn a_fifo_collision_returns_without_opening_it_for_io() {
            let (_temp, manager) = fixture();
            let path = manager.file_path(1);
            nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR).unwrap();
            assert!(create_with(&manager, 1, |_, _, _, _| panic!("must not allocate")).is_err());
            assert!(fs::symlink_metadata(path).is_ok());
        }

        #[test]
        fn partial_allocation_failure_removes_only_the_new_slot_and_retries() {
            let (_temp, manager) = fixture();
            let path = manager.file_path(1);
            let error = create_with(&manager, 1, |_, file, path, _| {
                file.write_all(b"partial").unwrap();
                Err(SbhError::io(path, io::Error::from_raw_os_error(libc::ENOSPC)))
            }).unwrap_err();
            assert!(is_storage_exhausted_error(&error));
            assert!(fs::symlink_metadata(&path).is_err());
            create_with(&manager, 1, prepare).unwrap();
            assert!(allocated(&fs::metadata(path).unwrap(), SIZE));
        }

        #[test]
        fn a_replacement_survives_cleanup_after_allocator_failure() {
            let (temp, manager) = fixture();
            let path = manager.file_path(1);
            let ours = temp.path().join("moved-new-file");
            let result = create_with(&manager, 1, |_, file, path, _| {
                fs::rename(path, &ours).unwrap();
                fs::write(path, b"replacement data").unwrap();
                file.write_all(b"owned descriptor").unwrap();
                Err(SbhError::io(path, io::Error::from_raw_os_error(libc::EIO)))
            });
            assert!(result.is_err());
            assert_eq!(fs::read(path).unwrap(), b"replacement data");
            assert_eq!(fs::read(ours).unwrap(), b"owned descriptor");
        }

        #[test]
        fn replacement_after_successful_preparation_is_not_finalized() {
            let (temp, manager) = fixture();
            let path = manager.file_path(1);
            let ours = temp.path().join("retired");
            assert!(create_with(&manager, 1, |manager, file, path, size| {
                prepare(manager, file, path, size)?;
                fs::rename(path, &ours).unwrap();
                fs::write(path, b"do not finalize this").unwrap();
                Ok(())
            }).is_err());
            assert_eq!(fs::read(path).unwrap(), b"do not finalize this");
            assert!(ours.exists());
        }

        #[test]
        fn symlink_substitution_does_not_redirect_writes_or_cleanup() {
            let (temp, manager) = fixture();
            let outside = temp.path().join("external");
            let ours = temp.path().join("ours");
            fs::write(&outside, b"external stays intact").unwrap();
            assert!(create_with(&manager, 1, |_, file, path, _| {
                fs::rename(path, &ours).unwrap();
                symlink(&outside, path).unwrap();
                file.write_all(b"our partial write").unwrap();
                Ok(())
            }).is_err());
            assert_eq!(fs::read(outside).unwrap(), b"external stays intact");
            assert!(fs::symlink_metadata(manager.file_path(1)).unwrap().file_type().is_symlink());
            assert_eq!(fs::read(ours).unwrap(), b"our partial write");
        }

        #[test]
        fn renamed_pool_cleanup_stays_relative_to_the_opened_directory() {
            let (temp, manager) = fixture();
            let retired = temp.path().join("retired-pool");
            let replacement = manager.file_path(1);
            assert!(create_with(&manager, 1, |_, _, path, _| {
                fs::rename(&manager.ballast_dir, &retired).unwrap();
                fs::create_dir(&manager.ballast_dir).unwrap();
                fs::write(&replacement, b"new pool file").unwrap();
                Err(SbhError::io(path, io::Error::from_raw_os_error(libc::EIO)))
            }).is_err());
            assert_eq!(fs::read(replacement).unwrap(), b"new pool file");
            assert!(!retired.join(ballast_file_name(1)).exists());
        }

        #[test]
        fn new_hard_link_prevents_success_and_destructive_cleanup() {
            let (temp, manager) = fixture();
            let linked = temp.path().join("second-link");
            assert!(create_with(&manager, 1, |_, file, path, _| {
                file.write_all(b"shared inode").unwrap();
                fs::hard_link(path, &linked).unwrap();
                Ok(())
            }).is_err());
            assert_eq!(fs::read(manager.file_path(1)).unwrap(), b"shared inode");
            assert_eq!(fs::read(linked).unwrap(), b"shared inode");
        }

        #[test]
        fn mock_sparse_success_is_filled_instead_of_claimed_as_reserve() {
            let (_temp, manager) = fixture();
            let path = manager.file_path(1);
            let config = manager.config.clone();
            let platform = MockPlatform::healthy().with_block_count(&path, SIZE / 512);
            let mut manager = BallastManager::with_platform(manager.ballast_dir.clone(), config, Arc::new(platform)).unwrap();
            let report = manager.provision(None).unwrap();
            assert_eq!(report.files_created, 1, "{report:?}");
            assert!(allocated(&fs::metadata(path).unwrap(), SIZE));
            assert_eq!(manager.verify().unwrap().files_ok, 1);
        }

        #[test]
        fn injected_space_and_quota_exhaustion_stop_the_batch() {
            for message in ["No space left on device", "Disk quota exceeded"] {
                let (_temp, manager) = fixture();
                let path = manager.file_path(1);
                let mut config = manager.config.clone();
                config.file_count = 3;
                let platform = MockPlatform::healthy().with_preallocate_failure(
                    &path,
                    PalError::method_failed("mock", "preallocate_file", message),
                );
                let mut manager = BallastManager::with_platform(
                    manager.ballast_dir.clone(), config, Arc::new(platform),
                ).unwrap();
                let report = manager.provision(None).unwrap();
                assert_eq!(report.files_created, 0);
                assert_eq!(report.errors.len(), 1, "{report:?}");
                assert!(report.errors[0].contains("storage exhausted"));
                for index in 1..=3 {
                    assert!(!manager.file_path(index).exists());
                }
            }
        }

        #[test]
        fn only_the_pals_underallocation_error_allows_a_write_fallback() {
            use crate::platform::pal::verify_preallocated_blocks;
            let path = Path::new("/test/ballast");
            let sparse = verify_preallocated_blocks("descriptor", path, SIZE, 0).unwrap_err();
            assert!(fallback_allowed(&sparse));
            let overflow = verify_preallocated_blocks("descriptor", path, SIZE, u64::MAX)
                .unwrap_err();
            assert!(!fallback_allowed(&overflow));
            for details in ["I/O error", "EDQUOT", "unexpected mock preallocation request"] {
                let error = SbhError::Pal {
                    source: PalError::method_failed("descriptor", "preallocate_file", details),
                };
                assert!(!fallback_allowed(&error));
            }
        }

        #[test]
        fn native_io_and_quota_failures_are_not_retried_as_random_writes() {
            let path = Path::new("/test/ballast");
            for code in [libc::ENOSPC, libc::EDQUOT, libc::EIO, libc::EACCES, libc::EROFS] {
                assert!(!fallback_allowed(&SbhError::io(path, io::Error::from_raw_os_error(code))));
            }
            for code in [libc::ENOSYS, libc::EOPNOTSUPP, libc::EINVAL] {
                assert!(fallback_allowed(&SbhError::io(path, io::Error::from_raw_os_error(code))));
            }
        }

        #[test]
        fn invalid_size_and_headroom_refusal_create_no_slot() {
            let (_temp, mut manager) = fixture();
            let path = manager.file_path(1);
            manager.config.file_size_bytes = 1;
            assert!(create_with(&manager, 1, |_, _, _, _| panic!("invalid size")).is_err());
            assert!(!path.exists());
            manager.config.file_size_bytes = SIZE;
            manager.set_provision_floor(20.0);
            let report = manager.replenish_one(Some(&|| 0.0)).unwrap();
            assert_eq!(report.files_created, 0);
            assert!(report.skipped_for_floor > 0);
            assert!(!path.exists());
        }
    }
}
