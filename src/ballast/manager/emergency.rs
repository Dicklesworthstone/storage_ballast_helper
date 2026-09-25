//! Managed-pool release without allocating a lock file or waiting for a writer.
//!
//! The configured pool's canonical slots are the managed deletion surface,
//! including damaged ballast. Retired pools have the stricter adoption contract
//! in `coordinator::stranded`. Unix operations below stay relative to an opened
//! pool directory and hold the existing provisioner's flock for the whole pass.

use super::{BallastManager, ReleaseReport};
use crate::core::errors::Result;

fn empty_report() -> ReleaseReport {
    ReleaseReport {
        files_released: 0,
        bytes_freed: 0,
        warnings: Vec::new(),
        errors: Vec::new(),
        released: Vec::new(),
    }
}

#[cfg(unix)]
mod unix {
    use std::ffi::OsStr;
    use std::fs::{File, Metadata, OpenOptions};
    use std::io::{self, Read};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;

    use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags, flock, openat, unlinkat};

    use super::super::{BallastFile, BallastHeader, HEADER_SIZE, ballast_file_name};
    use super::{BallastManager, ReleaseReport, Result, empty_report};
    use crate::core::errors::SbhError;

    fn invalid(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    fn open_regular(directory: &File, name: &OsStr) -> io::Result<File> {
        let fd = openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let file = File::from(fd);
        let meta = file.metadata()?;
        if !meta.is_file() || meta.nlink() != 1 {
            return Err(invalid("not an independently releasable regular file"));
        }
        if meta.dev() != directory.metadata()?.dev() {
            return Err(invalid("ballast slot is on a different filesystem"));
        }
        Ok(file)
    }

    fn same_file(left: &Metadata, right: &Metadata) -> bool {
        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.len() == right.len()
            && left.nlink() == right.nlink()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }

    /// No mkdir, create, truncate, write or blocking flock on this path.
    struct PoolLock {
        directory: File,
        _lock: File,
    }

    impl PoolLock {
        fn open(path: &Path, configured_count: usize) -> io::Result<Option<Self>> {
            let directory = match OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)
            {
                Ok(directory) => directory,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
            };
            let lock = match open_regular(&directory, OsStr::new(".lock")) {
                Ok(lock) => lock,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    // A never-provisioned empty directory needs no mutation.
                    // Existing payloads without their lock are not authority to
                    // invent another locking protocol on a full filesystem.
                    for index in 1..=configured_count {
                        let name = ballast_file_name(
                            u32::try_from(index).map_err(|_| invalid("ballast index exceeds u32"))?,
                        );
                        match open_regular(&directory, OsStr::new(&name)) {
                            Err(missing) if missing.kind() == io::ErrorKind::NotFound => {}
                            _ => return Err(invalid("existing ballast pool lock is missing")),
                        }
                    }
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
            flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
                let error = io::Error::from(error);
                if error.kind() == io::ErrorKind::WouldBlock {
                    io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "ballast pool is busy; release deferred without waiting for provisioning",
                    )
                } else {
                    error
                }
            })?;
            let current_lock = open_regular(&directory, OsStr::new(".lock"))?;
            if !same_file(&lock.metadata()?, &current_lock.metadata()?) {
                return Err(invalid("ballast pool lock was replaced while acquiring it"));
            }
            Ok(Some(Self {
                directory,
                _lock: lock,
            }))
        }

        fn remove(&self, name: &OsStr, expected: &Metadata) -> io::Result<()> {
            // Reject a replacement before unlinking. The flock serializes
            // cooperative manager writes; the opened directory prevents a
            // renamed parent from redirecting the operation into another tree.
            let current = open_regular(&self.directory, name)?;
            if !same_file(expected, &current.metadata()?) {
                return Err(invalid("ballast slot changed during the release pass"));
            }
            unlinkat(&self.directory, name, AtFlags::empty())?;
            Ok(())
        }
    }

    fn verify_open_file(file: &mut File, meta: &Metadata, index: u32, size: u64) -> bool {
        if meta.len() != size || meta.blocks().saturating_mul(512) < size {
            return false;
        }
        let mut bytes = [0u8; HEADER_SIZE];
        if file.read_exact(&mut bytes).is_err() {
            return false;
        }
        let end = bytes
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(HEADER_SIZE);
        serde_json::from_slice::<BallastHeader>(&bytes[..end]).is_ok_and(|header| {
            header.validate() && header.file_index == index && header.file_size == size
        }) && file.metadata().is_ok_and(|after| same_file(meta, &after))
    }

    pub(in super::super) fn release(
        manager: &mut BallastManager,
        count: usize,
    ) -> Result<ReleaseReport> {
        let mut report = empty_report();
        if count == 0 || manager.config.file_count == 0 {
            return Ok(report);
        }
        let last_index =
            u32::try_from(manager.config.file_count).map_err(|_| SbhError::InvalidConfig {
                details: "ballast file_count exceeds the supported index range".to_string(),
            })?;
        let Some(guard) = PoolLock::open(&manager.ballast_dir, manager.config.file_count)
            .map_err(|error| SbhError::io(&manager.ballast_dir, error))?
        else {
            manager.inventory.clear();
            return Ok(report);
        };
        let mut inventory = Vec::new();
        // Snapshot the real slots under the lock, not the manager's startup
        // cache: another CLI may have provisioned or released files meanwhile.
        for index in (1..=last_index).rev() {
            let name = ballast_file_name(index);
            let path = manager.ballast_dir.join(&name);
            let opened = open_regular(&guard.directory, OsStr::new(&name));
            let mut file = match opened {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    let message = format!("cannot inspect ballast file {index}: {error}");
                    report.warnings.push(message.clone());
                    report.errors.push(message);
                    continue;
                }
            };
            let meta = match file.metadata() {
                Ok(meta) => meta,
                Err(error) => {
                    report
                        .errors
                        .push(format!("cannot stat ballast file {index}: {error}"));
                    continue;
                }
            };
            // Logical length is not freed space for a sparse/truncated reserve.
            // This is a conservative allocation estimate, not an observed free
            // delta: CoW snapshots can still retain blocks after unlink.
            let size = meta.len().min(meta.blocks().saturating_mul(512));
            if report.files_released < count {
                match guard.remove(OsStr::new(&name), &meta) {
                    Ok(()) => {
                        report.files_released += 1;
                        report.bytes_freed = report.bytes_freed.saturating_add(size);
                        report.released.push((path, size));
                        continue;
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => {
                        let message = format!("failed to release file {index}: {error}");
                        report.warnings.push(message.clone());
                        report.errors.push(message);
                    }
                }
            }
            let integrity_ok =
                verify_open_file(&mut file, &meta, index, manager.config.file_size_bytes);
            let created_at = meta
                .created()
                .ok()
                .map(|time| {
                    let time: chrono::DateTime<chrono::Utc> = time.into();
                    time.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                })
                .unwrap_or_default();
            inventory.push(BallastFile {
                path,
                index,
                size,
                created_at,
                integrity_ok,
            });
        }
        inventory.reverse();
        manager.inventory = inventory;
        // Do not hold the pool lock while querying platform snapshot metadata.
        drop(guard);
        if report.files_released > 0 {
            report
                .warnings
                .extend(manager.local_snapshot_release_warnings());
        }
        Ok(report)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fs;
        use std::os::unix::fs::symlink;
        use std::sync::mpsc;
        use std::time::Duration;

        use crate::core::config::BallastConfig;

        fn config() -> BallastConfig {
            BallastConfig {
                file_count: 3,
                file_size_bytes: 12_288,
                replenish_cooldown_minutes: 0,
                auto_provision: true,
                overrides: Default::default(),
            }
        }

        fn fixture() -> (tempfile::TempDir, BallastManager) {
            let root = tempfile::tempdir().unwrap();
            let mut manager = BallastManager::new(root.path().join("pool"), config()).unwrap();
            assert_eq!(manager.provision(None).unwrap().files_created, 3);
            (root, manager)
        }

        #[test]
        fn emergency_release_does_not_wait_for_a_provisioner() {
            let (_root, manager) = fixture();
            let lock = File::open(manager.ballast_dir.join(".lock")).unwrap();
            flock(&lock, FlockOperation::LockExclusive).unwrap();
            let (tx, rx) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                let mut manager = manager;
                let result = manager.release(1);
                assert!(tx.send((manager, result)).is_ok());
            });
            let immediate = rx.recv_timeout(Duration::from_secs(2));
            // Always release the fixture lock before joining, even on failure.
            drop(lock);
            let (mut manager, result) = match immediate {
                Ok(result) => result,
                Err(error) => {
                    worker.join().unwrap();
                    panic!("release waited for the held pool lock: {error}");
                }
            };
            worker.join().unwrap();
            assert!(result.unwrap_err().to_string().contains("busy"));
            assert_eq!(manager.inventory.len(), 3, "busy is not missing");
            assert_eq!(manager.release(1).unwrap().files_released, 1);
        }

        #[test]
        fn gradual_replenishment_does_not_wait_for_another_pool_writer() {
            let (_root, mut manager) = fixture();
            manager.release(1).unwrap();
            let lock = File::open(manager.ballast_dir.join(".lock")).unwrap();
            flock(&lock, FlockOperation::LockExclusive).unwrap();
            let (tx, rx) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                let result = manager.replenish_one(None);
                assert!(tx.send((manager, result)).is_ok());
            });
            let immediate = rx.recv_timeout(Duration::from_secs(2));
            drop(lock);
            let (mut manager, result) = match immediate {
                Ok(result) => result,
                Err(error) => {
                    worker.join().unwrap();
                    panic!("replenishment waited for the held pool lock: {error}");
                }
            };
            worker.join().unwrap();
            assert!(result.is_err());
            assert_eq!(manager.available_count(), 2);
            assert_eq!(manager.replenish_one(None).unwrap().files_created, 1);
        }

        #[test]
        fn release_does_not_create_a_missing_pool_or_lock() {
            let root = tempfile::tempdir().unwrap();
            let pool = root.path().join("absent");
            let mut manager = BallastManager::new(pool.clone(), config()).unwrap();
            assert_eq!(manager.release(1).unwrap().files_released, 0);
            assert!(!pool.exists());
            fs::create_dir(&pool).unwrap();
            assert_eq!(manager.release(1).unwrap().files_released, 0);
            assert!(!pool.join(".lock").exists());
        }

        #[test]
        fn existing_payload_without_a_lock_is_not_released_unlocked() {
            let (_root, mut manager) = fixture();
            fs::rename(
                manager.ballast_dir.join(".lock"),
                manager.ballast_dir.join("saved-lock"),
            )
            .unwrap();
            assert!(
                manager
                    .release(1)
                    .unwrap_err()
                    .to_string()
                    .contains("lock is missing")
            );
            assert!(!manager.ballast_dir.join(".lock").exists());
            assert!(manager.file_path(3).exists());
        }

        #[test]
        fn release_refreshes_a_cache_that_predates_external_provisioning() {
            let root = tempfile::tempdir().unwrap();
            let pool = root.path().join("pool");
            let mut stale = BallastManager::new(pool.clone(), config()).unwrap();
            let mut writer = BallastManager::new(pool, config()).unwrap();
            writer.provision(None).unwrap();
            assert_eq!(stale.available_count(), 0);
            assert_eq!(stale.release(2).unwrap().files_released, 2);
            assert_eq!(stale.available_count(), 1);
            assert!(stale.file_path(1).exists());
        }

        #[test]
        fn external_removal_does_not_consume_the_success_quota() {
            let (_root, mut manager) = fixture();
            fs::remove_file(manager.file_path(3)).unwrap();
            let report = manager.release(2).unwrap();
            assert_eq!(report.files_released, 2);
            assert!(report.errors.is_empty());
            assert_eq!(report.bytes_freed, 2 * config().file_size_bytes);
            assert_eq!(manager.available_count(), 0);
        }

        #[test]
        fn symlink_slot_is_skipped_without_following_or_unlinking_it() {
            let (root, mut manager) = fixture();
            let victim = root.path().join("precious");
            fs::write(&victim, b"keep").unwrap();
            fs::remove_file(manager.file_path(3)).unwrap();
            symlink(&victim, manager.file_path(3)).unwrap();
            let report = manager.release(2).unwrap();
            assert_eq!(report.files_released, 2);
            assert!(!report.errors.is_empty());
            assert!(
                fs::symlink_metadata(manager.file_path(3))
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(fs::read(victim).unwrap(), b"keep");
        }

        #[test]
        fn fifo_slot_does_not_block_release_or_inventory_refresh() {
            use nix::sys::stat::Mode as FifoMode;
            use nix::unistd::mkfifo;
            let (_root, mut manager) = fixture();
            fs::remove_file(manager.file_path(3)).unwrap();
            mkfifo(&manager.file_path(3), FifoMode::S_IRUSR | FifoMode::S_IWUSR).unwrap();
            let report = manager.release(1).unwrap();
            assert_eq!(report.files_released, 1);
            assert!(!report.errors.is_empty());
            assert_eq!(manager.available_count(), 1);
            assert!(manager.file_path(1).exists());
        }

        #[test]
        fn hardlinked_slots_do_not_claim_releasable_bytes() {
            let (root, mut manager) = fixture();
            let alias = root.path().join("linked");
            fs::hard_link(manager.file_path(3), &alias).unwrap();
            let report = manager.release(3).unwrap();
            assert_eq!(report.files_released, 2);
            assert_eq!(report.bytes_freed, 2 * config().file_size_bytes);
            assert!(manager.file_path(3).exists());
            assert_eq!(fs::metadata(alias).unwrap().len(), config().file_size_bytes);
        }

        #[test]
        fn zero_count_needs_neither_lock_nor_directory_access() {
            let (_root, mut manager) = fixture();
            let lock = File::open(manager.ballast_dir.join(".lock")).unwrap();
            flock(&lock, FlockOperation::LockExclusive).unwrap();
            assert_eq!(manager.release(0).unwrap().files_released, 0);
            assert_eq!(manager.available_count(), 3);
        }

        #[test]
        fn sparse_slot_reports_only_its_allocated_data() {
            let (_root, mut manager) = fixture();
            let path = manager.file_path(3);
            let payload = File::create(&path).unwrap();
            payload.set_len(1 << 30).unwrap();
            let expected = fs::metadata(&path)
                .unwrap()
                .blocks()
                .saturating_mul(512)
                .min(1 << 30);
            drop(payload);
            let report = manager.release(1).unwrap();
            assert_eq!(report.files_released, 1);
            assert_eq!(report.bytes_freed, expected);
            assert_eq!(report.released[0].1, expected);
        }

        #[test]
        fn damaged_managed_ballast_remains_releasable() {
            let (_root, mut manager) = fixture();
            fs::write(manager.file_path(3), b"damaged ballast").unwrap();
            let report = manager.release(1).unwrap();
            assert_eq!(report.files_released, 1);
            assert!(!manager.file_path(3).exists());
        }

        #[test]
        fn directory_slot_cannot_prevent_lower_slots_from_being_released() {
            let (_root, mut manager) = fixture();
            fs::remove_file(manager.file_path(3)).unwrap();
            fs::create_dir(manager.file_path(3)).unwrap();
            fs::write(manager.file_path(3).join("keep"), b"keep").unwrap();
            let report = manager.release(2).unwrap();
            assert_eq!(report.files_released, 2);
            assert_eq!(
                fs::read(manager.file_path(3).join("keep")).unwrap(),
                b"keep"
            );
        }

        #[test]
        fn release_rejects_a_symlinked_pool_lock() {
            let (root, mut manager) = fixture();
            let lock = manager.ballast_dir.join(".lock");
            let other = root.path().join("other-lock");
            fs::rename(&lock, &other).unwrap();
            symlink(other, &lock).unwrap();
            assert!(manager.release(1).is_err());
            assert!(manager.file_path(3).exists());
        }

        #[test]
        fn release_rejects_a_fifo_pool_lock_without_waiting() {
            use nix::sys::stat::Mode as FifoMode;
            use nix::unistd::mkfifo;
            let (_root, mut manager) = fixture();
            let lock = manager.ballast_dir.join(".lock");
            fs::rename(&lock, manager.ballast_dir.join("saved-lock")).unwrap();
            mkfifo(&lock, FifoMode::S_IRUSR | FifoMode::S_IWUSR).unwrap();
            assert!(manager.release(1).is_err());
            assert!(manager.file_path(3).exists());
        }

        #[test]
        fn excessive_file_count_is_rejected_before_accessing_slots() {
            let (_root, mut manager) = fixture();
            if usize::BITS > u32::BITS {
                manager.config.file_count = usize::MAX;
                assert!(manager.release(1).is_err());
                assert!(manager.file_path(3).exists());
            }
        }

        #[test]
        fn payload_replacement_revokes_an_in_flight_unlink() {
            let (_root, manager) = fixture();
            let guard = PoolLock::open(&manager.ballast_dir, config().file_count)
                .unwrap()
                .unwrap();
            let path = manager.file_path(3);
            let meta = fs::metadata(&path).unwrap();
            fs::rename(&path, manager.ballast_dir.join("previous")).unwrap();
            fs::write(&path, b"replacement").unwrap();
            let name = path.file_name().unwrap();
            assert!(guard.remove(name, &meta).is_err());
            assert_eq!(fs::read(&path).unwrap(), b"replacement");
        }

        #[test]
        fn renamed_parent_does_not_redirect_unlink_into_its_replacement() {
            let (root, manager) = fixture();
            let guard = PoolLock::open(&manager.ballast_dir, config().file_count)
                .unwrap()
                .unwrap();
            let path = manager.file_path(3);
            let meta = fs::metadata(&path).unwrap();
            let moved = root.path().join("moved-pool");
            fs::rename(&manager.ballast_dir, &moved).unwrap();
            fs::create_dir(&manager.ballast_dir).unwrap();
            fs::write(&path, b"new directory's contents").unwrap();
            guard.remove(path.file_name().unwrap(), &meta).unwrap();
            assert_eq!(fs::read(path).unwrap(), b"new directory's contents");
            assert!(!moved.join(ballast_file_name(3)).exists());
        }
    }
}

#[cfg(unix)]
pub(super) use unix::release;

// Preserve the portable manager behavior on non-Unix targets. The no-allocation
// and nonblocking-flock contract above is for the supported Unix daemon hosts.
#[cfg(not(unix))]
pub(super) fn release(manager: &mut BallastManager, count: usize) -> Result<ReleaseReport> {
    let _lock = manager.acquire_lock(false)?;
    let mut report = empty_report();
    manager.scan_existing();
    let mut available: Vec<u32> = manager.inventory.iter().map(|file| file.index).collect();
    available.sort_unstable_by(|left, right| right.cmp(left));
    for index in available {
        if report.files_released >= count {
            break;
        }
        let path = manager.file_path(index);
        let size = std::fs::metadata(&path).map_or(0, |meta| meta.len());
        match std::fs::remove_file(&path) {
            Ok(()) => {
                report.files_released += 1;
                report.bytes_freed = report.bytes_freed.saturating_add(size);
                report.released.push((path, size));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => report.errors.push(format!("failed to release file {index}: {error}")),
        }
    }
    manager.scan_existing();
    if report.files_released > 0 {
        report
            .warnings
            .extend(manager.local_snapshot_release_warnings());
    }
    Ok(report)
}
