//! Read-only reserve accounting shared by status and the manager inventory.
//!
//! Logical length is not emergency capacity. Count only independently linked,
//! regular files on the pool's filesystem, bounded by their allocated blocks.
//! These are allocation estimates, not guaranteed free-space deltas: snapshots
//! may retain extents after unlink. No observation creates a directory or lock.
//! On Unix, verified surplus files remain visible after a target is reduced or
//! disabled, so the pressure controller can still release that physical reserve.

use std::ffi::OsStr;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use super::{
    BallastAvailability, BallastFile, BallastHeader, BallastHealth, BallastManager,
    HEADER_SIZE, ballast_file_name,
};
use crate::core::config::BallastConfig;

fn pool_metadata(path: &Path) -> std::io::Result<Metadata> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ballast pool is not a real directory",
        ));
    }
    Ok(meta)
}

fn independently_releasable(meta: &Metadata, pool: &Metadata) -> bool {
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        meta.nlink() == 1 && meta.dev() == pool.dev()
    }
    #[cfg(not(unix))]
    {
        let _ = pool;
        true
    }
}

fn allocated_bytes(meta: &Metadata) -> u64 {
    #[cfg(unix)]
    {
        meta.len().min(meta.blocks().saturating_mul(512))
    }
    #[cfg(not(unix))]
    {
        // Non-Unix release retains the platform's logical-length contract.
        meta.len()
    }
}

fn same_identity(left: &Metadata, right: &Metadata) -> bool {
    #[cfg(unix)]
    {
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        left.is_dir() == right.is_dir() && left.created().ok() == right.created().ok()
    }
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    if !same_identity(left, right) || left.len() != right.len() {
        return false;
    }
    #[cfg(unix)]
    {
        left.nlink() == right.nlink()
            && left.blocks() == right.blocks()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        left.is_file() == right.is_file() && left.modified().ok() == right.modified().ok()
    }
}

/// Unix verification stays relative to an opened pool, including its final
/// pathname recheck. Opening never creates a lock or follows the pool symlink.
struct PoolReader {
    path: PathBuf,
    meta: Metadata,
    #[cfg(unix)]
    directory: File,
}

impl PoolReader {
    fn open(path: &Path) -> std::io::Result<Self> {
        #[cfg(unix)]
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        #[cfg(unix)]
        let meta = directory.metadata()?;
        #[cfg(not(unix))]
        let meta = pool_metadata(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            meta,
            #[cfg(unix)]
            directory,
        })
    }

    fn open_slot(&self, name: &OsStr) -> std::io::Result<File> {
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, OFlags, openat};

            let fd = openat(
                &self.directory,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            Ok(File::from(fd))
        }
        #[cfg(not(unix))]
        {
            let path = self.path.join(name);
            if !fs::symlink_metadata(&path)?.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "ballast slot is not a regular file",
                ));
            }
            OpenOptions::new().read(true).open(path)
        }
    }

    fn is_current(&self) -> bool {
        pool_metadata(&self.path).is_ok_and(|after| same_identity(&self.meta, &after))
    }
}

#[cfg(unix)]
#[derive(Default)]
struct SurplusSnapshot {
    files: Vec<BallastFile>,
    unreadable: usize,
}

/// Preserve the same ownership boundary as emergency release: outside the
/// configured slots, a familiar filename alone proves nothing. Verify the
/// original header/size/allocation through the opened directory, not against a
/// newly configured file size. No lock acquisition or mutation belongs here.
#[cfg(unix)]
fn read_surplus(pool: &PoolReader, index: u32) -> std::io::Result<Option<BallastFile>> {
    let name = ballast_file_name(index);
    let mut file = match pool.open_slot(OsStr::new(&name)) {
        Ok(file) => file,
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ELOOP) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let meta = file.metadata()?;
    if !independently_releasable(&meta, &pool.meta)
        || meta.len() < HEADER_SIZE as u64
        || allocated_bytes(&meta) < meta.len()
    {
        return Ok(None);
    }
    let mut bytes = [0u8; HEADER_SIZE];
    match file.read_exact(&mut bytes) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let end = bytes.iter().position(|&byte| byte == 0).unwrap_or(HEADER_SIZE);
    let Ok(header) = serde_json::from_slice::<BallastHeader>(&bytes[..end]) else {
        return Ok(None);
    };
    if !header.validate() || header.file_index != index || header.file_size != meta.len() {
        return Ok(None);
    }
    let after = file.metadata()?;
    let current = pool.open_slot(OsStr::new(&name))?;
    if !same_file(&meta, &after) || !same_file(&meta, &current.metadata()?) || !pool.is_current() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "surplus ballast or its pool changed during observation",
        ));
    }
    let created_at = meta
        .created()
        .ok()
        .map(|time| {
            let time: chrono::DateTime<chrono::Utc> = time.into();
            time.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        })
        .unwrap_or_default();
    Ok(Some(BallastFile {
        path: pool.path.join(name),
        index,
        size: allocated_bytes(&meta),
        created_at,
        integrity_ok: true,
    }))
}

#[cfg(unix)]
fn verified_surplus(
    path: &Path,
    configured_count: usize,
    expected_pool: &Metadata,
) -> std::io::Result<SurplusSnapshot> {
    let pool = PoolReader::open(path)?;
    if !same_identity(expected_pool, &pool.meta) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ballast pool changed before surplus observation",
        ));
    }
    let mut snapshot = SurplusSnapshot::default();
    for index in super::emergency::existing_indices(path, &pool.meta)? {
        if usize::try_from(index).is_ok_and(|index| index <= configured_count) {
            continue;
        }
        match read_surplus(&pool, index) {
            Ok(Some(file)) => snapshot.files.push(file),
            Ok(None) => {}
            // Keep independently verified neighbors visible. Unknown is not
            // missing, and the status snapshot must advertise its uncertainty.
            Err(_) => snapshot.unreadable = snapshot.unreadable.saturating_add(1),
        }
    }
    if !pool.is_current() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ballast pool changed during surplus observation",
        ));
    }
    Ok(snapshot)
}

pub(super) fn observe(ballast_dir: &Path, config: &BallastConfig) -> BallastAvailability {
    let configured_pool_bytes =
        (config.file_count as u64).saturating_mul(config.file_size_bytes);
    let mut result = BallastAvailability {
        configured_count: config.file_count,
        configured_file_size_bytes: config.file_size_bytes,
        configured_pool_bytes,
        available_count: 0,
        missing_count: 0,
        unreadable_count: 0,
        releasable_bytes: 0,
        health: BallastHealth::evaluate(configured_pool_bytes, 0),
    };
    match pool_metadata(ballast_dir) {
        Ok(pool) => {
            for i in 1..=config.file_count {
                let Ok(index) = u32::try_from(i) else {
                    result.unreadable_count += config.file_count - i + 1;
                    break;
                };
                let path = ballast_dir.join(ballast_file_name(index));
                match fs::symlink_metadata(path) {
                    Ok(meta) if independently_releasable(&meta, &pool) => {
                        result.available_count += 1;
                        result.releasable_bytes = result
                            .releasable_bytes
                            .saturating_add(allocated_bytes(&meta));
                    }
                    // A link, directory or foreign-device slot is not a reserve
                    // the managed release path can reclaim independently.
                    Ok(_) => result.missing_count += 1,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        result.missing_count += 1;
                    }
                    Err(_) => result.unreadable_count += 1,
                }
            }
            #[cfg(unix)]
            match verified_surplus(ballast_dir, config.file_count, &pool) {
                Ok(surplus) => {
                    result.available_count = result
                        .available_count
                        .saturating_add(surplus.files.len());
                    for file in surplus.files {
                        result.releasable_bytes = result.releasable_bytes.saturating_add(file.size);
                    }
                    result.unreadable_count = result
                        .unreadable_count
                        .saturating_add(surplus.unreadable);
                }
                // Directory enumeration failed: we cannot claim that there is
                // no surplus. Preserve any already counted unreadable slots.
                Err(_) => result.unreadable_count = result.unreadable_count.max(1),
            }
            // Do not combine slots observed through two different pool paths.
            // This is a best-effort read-only snapshot, not a release lease.
            if !pool_metadata(ballast_dir).is_ok_and(|after| same_identity(&pool, &after)) {
                result.available_count = 0;
                result.missing_count = 0;
                result.releasable_bytes = 0;
                result.unreadable_count = config.file_count.max(1);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            result.missing_count = config.file_count;
        }
        Err(_) => result.unreadable_count = config.file_count.max(1),
    }
    result.health = if configured_pool_bytes == 0 {
        BallastHealth::Unconfigured
    } else if result.unreadable_count != 0 {
        BallastHealth::Indeterminate
    } else {
        BallastHealth::evaluate(configured_pool_bytes, result.releasable_bytes)
    };
    result
}

pub(super) fn inventory(manager: &BallastManager) -> Vec<BallastFile> {
    let Ok(pool) = pool_metadata(&manager.ballast_dir) else {
        return Vec::new();
    };
    let mut inventory = Vec::new();
    for i in 1..=manager.config.file_count {
        let Ok(index) = u32::try_from(i) else {
            break;
        };
        let path = manager.file_path(index);
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !independently_releasable(&meta, &pool) {
            continue;
        }
        let integrity_ok = manager.verify_single_file(&path, index).is_ok();
        // A failed verification can mean a damaged reserve (still releasable),
        // but never carry pre-verification bytes across a replacement or write.
        if !fs::symlink_metadata(&path).is_ok_and(|after| same_file(&meta, &after)) {
            continue;
        }
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
            size: allocated_bytes(&meta),
            created_at,
            integrity_ok,
        });
    }
    #[cfg(unix)]
    if let Ok(surplus) = verified_surplus(&manager.ballast_dir, manager.config.file_count, &pool) {
        inventory.extend(surplus.files);
    }
    if !pool_metadata(&manager.ballast_dir).is_ok_and(|after| same_identity(&pool, &after)) {
        inventory.clear();
    }
    inventory
}

pub(super) fn verify(
    manager: &BallastManager,
    path: &Path,
    expected_index: u32,
) -> std::result::Result<(), String> {
    verify_with_block_count(manager, path, expected_index, || {
        manager
            .platform
            .file_block_count(path)
            .map_err(|error| format!("block count: {error}"))
    })
}

fn verify_with_block_count(
    manager: &BallastManager,
    path: &Path,
    expected_index: u32,
    read_blocks: impl FnOnce() -> std::result::Result<u64, String>,
) -> std::result::Result<(), String> {
    if path != manager.file_path(expected_index).as_path() {
        return Err("ballast verification path is outside the expected pool slot".to_string());
    }
    let pool = PoolReader::open(&manager.ballast_dir)
        .map_err(|error| format!("open pool: {error}"))?;
    let name = ballast_file_name(expected_index);
    let mut file = pool
        .open_slot(OsStr::new(&name))
        .map_err(|error| format!("open: {error}"))?;
    let meta = file.metadata().map_err(|error| format!("metadata: {error}"))?;
    if !independently_releasable(&meta, &pool.meta) {
        return Err("ballast slot is not an independently releasable regular file".to_string());
    }
    if meta.len() != manager.config.file_size_bytes {
        return Err(format!(
            "size mismatch: expected {} got {}",
            manager.config.file_size_bytes,
            meta.len()
        ));
    }
    let mut header_buf = [0u8; HEADER_SIZE];
    file.read_exact(&mut header_buf)
        .map_err(|e| format!("read header: {e}"))?;
    let json_end = header_buf
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(HEADER_SIZE);
    let header_str = std::str::from_utf8(&header_buf[..json_end])
        .map_err(|e| format!("header not UTF-8: {e}"))?;
    let header: BallastHeader =
        serde_json::from_str(header_str).map_err(|e| format!("header parse: {e}"))?;
    if !header.validate() {
        return Err(format!("bad magic: {}", header.magic));
    }
    if header.file_index != expected_index {
        return Err(format!(
            "index mismatch: expected {expected_index} got {}",
            header.file_index
        ));
    }
    if header.file_size != manager.config.file_size_bytes {
        return Err(format!(
            "header size mismatch: {} vs {}",
            header.file_size, manager.config.file_size_bytes
        ));
    }
    let platform_bytes = read_blocks()?
        .checked_mul(512)
        .ok_or_else(|| "allocated block count overflow".to_string())?;
    // Preserve PAL diagnostics/mock behavior, but an optimistic pathname probe
    // cannot override underallocation on the descriptor whose header we read.
    let observed_bytes = allocated_bytes(&meta).min(platform_bytes);
    if observed_bytes < manager.config.file_size_bytes {
        return Err(format!(
            "allocated bytes mismatch: expected at least {} got {observed_bytes}",
            manager.config.file_size_bytes
        ));
    }
    let after = file.metadata().map_err(|error| format!("restat: {error}"))?;
    let current = pool
        .open_slot(OsStr::new(&name))
        .map_err(|error| format!("reopen slot: {error}"))?;
    let current_meta = current
        .metadata()
        .map_err(|error| format!("restat slot: {error}"))?;
    if !same_file(&meta, &after) || !same_file(&meta, &current_meta) || !pool.is_current() {
        return Err("ballast file or pool changed during verification".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> BallastConfig {
        BallastConfig {
            file_count: 3,
            file_size_bytes: 65_536,
            replenish_cooldown_minutes: 0,
            auto_provision: true,
            overrides: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn damaged_regular_files_remain_releasable_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ballast_file_name(1));
        fs::write(&path, b"damaged but still allocated reserve").unwrap();
        let expected = allocated_bytes(&fs::symlink_metadata(&path).unwrap());
        let report = observe(dir.path(), &config());
        assert_eq!(report.available_count, 1);
        assert_eq!(report.missing_count, 2);
        assert_eq!(report.unreadable_count, 0);
        assert_eq!(report.releasable_bytes, expected);
        assert_eq!(report.health, BallastHealth::Degraded);
        let manager = BallastManager::new(dir.path().to_path_buf(), config()).unwrap();
        assert_eq!(manager.releasable_bytes(), expected);
        assert!(!manager.inventory()[0].integrity_ok);
        assert!(!dir.path().join(".lock").exists());
    }

    #[cfg(unix)]
    #[test]
    fn sparse_reserve_does_not_masquerade_as_a_full_pool() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = config();
        config.file_count = 1;
        config.file_size_bytes = 64 * 1024 * 1024;
        let path = dir.path().join(ballast_file_name(1));
        let file = File::create(&path).unwrap();
        file.set_len(config.file_size_bytes).unwrap();
        file.sync_all().unwrap();
        let meta = file.metadata().unwrap();
        let expected = allocated_bytes(&meta);
        let report = observe(dir.path(), &config);
        assert_eq!(report.releasable_bytes, expected);
        assert_eq!(report.available_count, 1);
        assert_eq!(
            report.health,
            BallastHealth::evaluate(config.file_size_bytes, expected)
        );
        let manager = BallastManager::new(dir.path().to_path_buf(), config).unwrap();
        assert_eq!(manager.releasable_bytes(), expected);
        assert!(!manager.inventory()[0].integrity_ok);
    }

    #[cfg(unix)]
    #[test]
    fn links_and_directories_are_not_counted_as_releasable_slots() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let pool = dir.path().join("pool");
        fs::create_dir(&pool).unwrap();
        let external = dir.path().join("important-data");
        let contents = vec![42u8; 65_536];
        fs::write(&external, &contents).unwrap();
        symlink(&external, pool.join(ballast_file_name(1))).unwrap();
        fs::hard_link(&external, pool.join(ballast_file_name(2))).unwrap();
        fs::create_dir(pool.join(ballast_file_name(3))).unwrap();
        let report = observe(&pool, &config());
        assert_eq!(report.available_count, 0);
        assert_eq!(report.missing_count, 3);
        assert_eq!(report.unreadable_count, 0);
        assert_eq!(report.releasable_bytes, 0);
        assert_eq!(report.health, BallastHealth::Empty);
        let manager = BallastManager::new(pool.clone(), config()).unwrap();
        assert!(manager.inventory().is_empty());
        assert_eq!(fs::read(external).unwrap(), contents);
        assert!(!pool.join(".lock").exists());
    }

    #[cfg(unix)]
    #[test]
    fn pool_symlink_is_indeterminate_and_is_never_followed() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join(ballast_file_name(1)), vec![0u8; 65_536]).unwrap();
        let alias = dir.path().join("alias");
        symlink(&real, &alias).unwrap();
        let report = observe(&alias, &config());
        assert_eq!(report.health, BallastHealth::Indeterminate);
        assert_eq!(report.unreadable_count, 3);
        assert_eq!(report.missing_count, 0);
        assert_eq!(report.releasable_bytes, 0);
        assert!(!report.is_authoritative());
        assert!(
            BallastManager::new(alias, config())
                .unwrap()
                .inventory()
                .is_empty()
        );
    }

    #[test]
    fn non_directory_pool_is_unknown_not_a_missing_reserve() {
        let dir = tempfile::tempdir().unwrap();
        let pool = dir.path().join("not-a-directory");
        fs::write(&pool, b"keep").unwrap();
        let report = observe(&pool, &config());
        assert_eq!(report.health, BallastHealth::Indeterminate);
        assert_eq!(report.unreadable_count, 3);
        assert_eq!(report.missing_count, 0);
        assert_eq!(fs::read(pool).unwrap(), b"keep");
    }

    #[test]
    fn absent_pool_is_empty_without_creating_anything() {
        let dir = tempfile::tempdir().unwrap();
        let pool = dir.path().join("absent");
        let report = observe(&pool, &config());
        assert_eq!(report.health, BallastHealth::Empty);
        assert_eq!(report.missing_count, 3);
        assert!(report.is_authoritative());
        assert!(!pool.exists());
    }

    #[test]
    fn zero_configured_bytes_outrank_unknown_pool_state() {
        let dir = tempfile::tempdir().unwrap();
        let pool = dir.path().join("not-a-directory");
        fs::write(&pool, b"keep").unwrap();
        let mut config = config();
        config.file_size_bytes = 0;
        assert_eq!(observe(&pool, &config).health, BallastHealth::Unconfigured);
    }

    #[cfg(unix)]
    fn verified_fixture() -> (tempfile::TempDir, BallastManager) {
        use rand::Rng as _;
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let pool = dir.path().join("pool");
        fs::create_dir(&pool).unwrap();
        let config = config();
        let path = pool.join(ballast_file_name(1));
        let header = super::super::ballast_header_buffer(1, config.file_size_bytes).unwrap();
        let mut bytes = vec![0u8; usize::try_from(config.file_size_bytes).unwrap()];
        rand::rng().fill_bytes(&mut bytes);
        bytes[..HEADER_SIZE].copy_from_slice(&header);
        fs::write(&path, bytes).unwrap();
        let platform = crate::platform::pal::MockPlatform::healthy()
            .with_block_count(path, config.file_size_bytes.div_ceil(512));
        let manager = BallastManager::with_platform(pool, config, Arc::new(platform)).unwrap();
        (dir, manager)
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_verification_accepts_an_unchanged_allocated_reserve() {
        let (_dir, manager) = verified_fixture();
        assert!(verify(&manager, &manager.file_path(1), 1).is_ok());
        assert!(manager.inventory()[0].integrity_ok);
        assert!(!manager.ballast_dir.join(".lock").exists());
    }

    #[cfg(unix)]
    #[test]
    fn valid_header_through_a_symlink_is_not_verified() {
        use std::os::unix::fs::symlink;

        let (dir, manager) = verified_fixture();
        let path = manager.file_path(1);
        let original = fs::read(&path).unwrap();
        let external = dir.path().join("external");
        fs::rename(&path, &external).unwrap();
        symlink(&external, &path).unwrap();
        assert!(verify(&manager, &path, 1).is_err());
        assert_eq!(fs::read(external).unwrap(), original);
    }

    #[cfg(unix)]
    #[test]
    fn valid_header_in_a_hard_link_is_not_verified() {
        let (dir, manager) = verified_fixture();
        let path = manager.file_path(1);
        fs::hard_link(&path, dir.path().join("external")).unwrap();
        let error = verify(&manager, &path, 1).unwrap_err();
        assert!(error.contains("independently releasable"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn same_contents_replacement_during_probe_is_rejected() {
        let (dir, manager) = verified_fixture();
        let path = manager.file_path(1);
        let original = fs::read(&path).unwrap();
        let error = verify_with_block_count(&manager, &path, 1, || {
            fs::rename(&path, dir.path().join("retired")).unwrap();
            fs::write(&path, &original).unwrap();
            Ok(manager.config.file_size_bytes.div_ceil(512))
        })
        .unwrap_err();
        assert!(error.contains("changed during verification"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn truncation_during_probe_is_rejected() {
        let (_dir, manager) = verified_fixture();
        let path = manager.file_path(1);
        let error = verify_with_block_count(&manager, &path, 1, || {
            OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(HEADER_SIZE as u64)
                .unwrap();
            Ok(manager.config.file_size_bytes.div_ceil(512))
        })
        .unwrap_err();
        assert!(error.contains("changed during verification"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn new_hard_link_during_probe_is_rejected() {
        let (dir, manager) = verified_fixture();
        let path = manager.file_path(1);
        let error = verify_with_block_count(&manager, &path, 1, || {
            fs::hard_link(&path, dir.path().join("external")).unwrap();
            Ok(manager.config.file_size_bytes.div_ceil(512))
        })
        .unwrap_err();
        assert!(error.contains("changed during verification"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn pool_replacement_during_probe_is_rejected() {
        let (dir, manager) = verified_fixture();
        let path = manager.file_path(1);
        let original = fs::read(&path).unwrap();
        let error = verify_with_block_count(&manager, &path, 1, || {
            fs::rename(&manager.ballast_dir, dir.path().join("retired-pool")).unwrap();
            fs::create_dir(&manager.ballast_dir).unwrap();
            fs::write(&path, &original).unwrap();
            Ok(manager.config.file_size_bytes.div_ceil(512))
        })
        .unwrap_err();
        assert!(error.contains("changed during verification"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_allocation_cannot_be_overridden_by_an_optimistic_probe() {
        let (_dir, manager) = verified_fixture();
        let path = manager.file_path(1);
        // Preserve the valid header while making the rest of the file sparse.
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(HEADER_SIZE as u64).unwrap();
        file.set_len(manager.config.file_size_bytes).unwrap();
        file.sync_all().unwrap();
        let allocated = allocated_bytes(&file.metadata().unwrap());
        let result = verify_with_block_count(&manager, &path, 1, || {
            Ok(manager.config.file_size_bytes.div_ceil(512))
        });
        if allocated < manager.config.file_size_bytes {
            assert!(result.unwrap_err().contains("allocated bytes mismatch"));
        } else {
            // A filesystem may eagerly allocate the extension rather than
            // create a hole; that is an actual fully allocated reserve.
            assert!(result.is_ok());
        }
    }

    #[cfg(unix)]
    #[test]
    fn corrupt_or_overflowing_platform_allocation_is_rejected() {
        let (_dir, manager) = verified_fixture();
        let path = manager.file_path(1);
        for blocks in [0, u64::MAX] {
            assert!(verify_with_block_count(&manager, &path, 1, || Ok(blocks)).is_err());
        }
        assert!(
            verify_with_block_count(&manager, &path, 1, || Err("probe failed".into())).is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn verification_never_accepts_an_outside_path() {
        let (dir, manager) = verified_fixture();
        let outside = dir.path().join("external");
        fs::copy(manager.file_path(1), &outside).unwrap();
        let error = verify(&manager, &outside, 1).unwrap_err();
        assert!(error.contains("outside the expected pool slot"));
    }

    #[test]
    fn inventory_byte_total_saturates_instead_of_wrapping() {
        let dir = tempfile::tempdir().unwrap();
        let mut manager = BallastManager::new(dir.path().to_path_buf(), config()).unwrap();
        manager.inventory = (1..=2)
            .map(|index| BallastFile {
                path: manager.file_path(index),
                index,
                size: u64::MAX,
                created_at: String::new(),
                integrity_ok: true,
            })
            .collect();
        assert_eq!(manager.releasable_bytes(), u64::MAX);
    }

    #[cfg(unix)]
    fn provisioned_fixture() -> (tempfile::TempDir, BallastManager) {
        let root = tempfile::tempdir().unwrap();
        let mut manager =
            BallastManager::new_unfloored(root.path().join("pool"), config()).unwrap();
        assert_eq!(manager.provision(None).unwrap().files_created, 3);
        (root, manager)
    }

    #[cfg(unix)]
    fn pressure(mount: &Path, level: crate::monitor::pid::PressureLevel) -> crate::monitor::pid::PressureResponse {
        crate::monitor::pid::PressureResponse {
            level,
            urgency: if level == crate::monitor::pid::PressureLevel::Critical { 1.0 } else { 0.4 },
            scan_interval: std::time::Duration::from_secs(1),
            release_ballast_files: 0,
            max_delete_batch: 10,
            fallback_active: false,
            causing_mount: mount.to_path_buf(),
            free_pct: 1.0,
            predicted_seconds: None,
        }
    }

    #[cfg(unix)]
    #[test]
    fn reloaded_and_reopened_pools_keep_surplus_visible_to_pressure_release() {
        use crate::ballast::release::BallastReleaseController;
        use crate::monitor::pid::PressureLevel;

        for target in [0, 1, 2] {
            for restart in [false, true] {
                let (root, mut manager) = provisioned_fixture();
                let mut changed = config();
                changed.file_count = target;
                changed.file_size_bytes *= 2;
                if restart {
                    manager = BallastManager::new(manager.ballast_dir.clone(), changed.clone()).unwrap();
                } else {
                    manager.update_config(changed.clone());
                }
                assert_eq!(manager.available_count(), 3);
                assert_eq!(manager.releasable_bytes(), 3 * config().file_size_bytes);
                let observed = BallastAvailability::observe(&manager.ballast_dir, &changed);
                assert_eq!(observed.available_count, 3);
                assert_eq!(observed.configured_count, target);
                assert_eq!(observed.releasable_bytes, manager.releasable_bytes());
                assert!(observed.is_authoritative());
                assert_eq!(observed.health, manager.health());
                let mut controller = BallastReleaseController::new(0);
                let report = controller
                    .maybe_release(root.path(), &mut manager, &pressure(root.path(), PressureLevel::Critical))
                    .unwrap()
                    .expect("physical reserve must reach the pressure-driven release path");
                assert_eq!(report.files_released, 3);
                assert_eq!(report.bytes_freed, 3 * config().file_size_bytes);
                assert!(report.errors.is_empty(), "{report:?}");
                assert_eq!(manager.config().file_count, target);
                let after = BallastAvailability::observe(&manager.ballast_dir, &changed);
                assert_eq!(after.available_count, 0);
                assert_eq!(after.releasable_bytes, 0);
                assert_eq!(after.missing_count, target);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn surplus_is_used_by_graduated_release_without_reenabling_growth() {
        use crate::ballast::release::BallastReleaseController;
        use crate::monitor::pid::PressureLevel;

        let (root, mut manager) = provisioned_fixture();
        let mut disabled = config();
        disabled.file_count = 0;
        manager.update_config(disabled);
        assert_eq!(manager.health(), BallastHealth::Unconfigured);
        let mut controller = BallastReleaseController::new(0);
        assert!(!controller
            .maybe_replenish(root.path(), &mut manager, PressureLevel::Green, &|| 100.0)
            .unwrap());
        assert_eq!(manager.available_count(), 3);
        let orange = pressure(root.path(), PressureLevel::Orange);
        let first = controller.maybe_release(root.path(), &mut manager, &orange).unwrap().unwrap();
        assert_eq!(first.files_released, 1);
        assert!(controller.maybe_release(root.path(), &mut manager, &orange).unwrap().is_none());
        let remaining = controller
            .maybe_release(root.path(), &mut manager, &pressure(root.path(), PressureLevel::Critical))
            .unwrap()
            .unwrap();
        assert_eq!(remaining.files_released, 2);
        assert_eq!(manager.available_count(), 0);
        assert!(!controller
            .maybe_replenish(root.path(), &mut manager, PressureLevel::Green, &|| 100.0)
            .unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn read_only_surplus_observation_does_not_create_a_missing_lock() {
        let (_root, mut manager) = verified_fixture();
        let retained = fs::read(manager.file_path(1)).unwrap();
        let mut disabled = config();
        disabled.file_count = 0;
        manager.update_config(disabled.clone());
        let observed = BallastAvailability::observe(&manager.ballast_dir, &disabled);
        assert_eq!(manager.available_count(), 1);
        assert_eq!(observed.available_count, 1);
        assert_eq!(observed.releasable_bytes, config().file_size_bytes);
        assert_eq!(observed.health, BallastHealth::Unconfigured);
        assert_eq!(observed.missing_count, 0);
        assert!(observed.is_authoritative());
        assert!(!manager.ballast_dir.join(".lock").exists());
        assert_eq!(fs::read(manager.file_path(1)).unwrap(), retained);
    }

    #[cfg(unix)]
    #[test]
    fn invalid_surplus_is_neither_capacity_nor_deletion_authority() {
        use crate::ballast::release::BallastReleaseController;
        use crate::monitor::pid::PressureLevel;

        let (root, mut manager) = provisioned_fixture();
        let invalid = manager.file_path(3);
        fs::write(&invalid, b"foreign or corrupt surplus").unwrap();
        let wrong_index = manager.file_path(4);
        fs::copy(manager.file_path(2), &wrong_index).unwrap();
        let copied = fs::read(&wrong_index).unwrap();
        let mut changed = config();
        changed.file_count = 1;
        manager.update_config(changed.clone());
        let observed = BallastAvailability::observe(&manager.ballast_dir, &changed);
        assert_eq!(observed.available_count, 2);
        assert_eq!(observed.releasable_bytes, 2 * config().file_size_bytes);
        assert_eq!(manager.available_count(), 2);
        let mut controller = BallastReleaseController::new(0);
        let report = controller
            .maybe_release(root.path(), &mut manager, &pressure(root.path(), PressureLevel::Critical))
            .unwrap()
            .unwrap();
        assert_eq!(report.files_released, 2);
        assert!(!report.errors.is_empty());
        assert_eq!(fs::read(invalid).unwrap(), b"foreign or corrupt surplus");
        assert_eq!(fs::read(wrong_index).unwrap(), copied);
    }

    #[cfg(unix)]
    #[test]
    fn surplus_links_and_nonregular_entries_are_not_reserved_capacity() {
        use nix::sys::stat::Mode;
        use nix::unistd::mkfifo;
        use std::os::unix::fs::symlink;

        let (root, mut manager) = verified_fixture();
        let external = root.path().join("external");
        fs::rename(manager.file_path(1), &external).unwrap();
        let retained = fs::read(&external).unwrap();
        symlink(&external, manager.file_path(1)).unwrap();
        fs::hard_link(&external, manager.file_path(2)).unwrap();
        mkfifo(&manager.file_path(3), Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
        fs::create_dir(manager.file_path(4)).unwrap();
        let mut disabled = config();
        disabled.file_count = 0;
        manager.update_config(disabled.clone());
        let observed = BallastAvailability::observe(&manager.ballast_dir, &disabled);
        assert_eq!(observed.available_count, 0);
        assert_eq!(observed.releasable_bytes, 0);
        assert_eq!(observed.missing_count, 0);
        assert!(observed.is_authoritative());
        assert_eq!(manager.available_count(), 0);
        assert_eq!(fs::read(external).unwrap(), retained);
        assert!(!manager.ballast_dir.join(".lock").exists());
    }

    #[cfg(unix)]
    #[test]
    fn surplus_does_not_hide_missing_configured_slots() {
        let (_root, mut manager) = provisioned_fixture();
        fs::remove_file(manager.file_path(1)).unwrap();
        let mut changed = config();
        changed.file_count = 1;
        manager.update_config(changed.clone());
        let observed = BallastAvailability::observe(&manager.ballast_dir, &changed);
        assert_eq!(observed.configured_count, 1);
        assert_eq!(observed.available_count, 2);
        assert_eq!(observed.missing_count, 1);
        assert_eq!(observed.releasable_bytes, 2 * config().file_size_bytes);
        assert_eq!(observed.health, BallastHealth::Ok);
        assert_eq!(manager.available_count(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn surplus_discovery_is_bound_to_the_original_directory_identity() {
        let (root, manager) = verified_fixture();
        let expected = pool_metadata(&manager.ballast_dir).unwrap();
        let retained = fs::read(manager.file_path(1)).unwrap();
        fs::rename(&manager.ballast_dir, root.path().join("old-pool")).unwrap();
        fs::create_dir(&manager.ballast_dir).unwrap();
        fs::write(manager.file_path(1), &retained).unwrap();
        assert!(verified_surplus(&manager.ballast_dir, 0, &expected).is_err());
        assert_eq!(fs::read(manager.file_path(1)).unwrap(), retained);
        assert!(!manager.ballast_dir.join(".lock").exists());
    }

    #[cfg(unix)]
    #[test]
    fn cached_surplus_is_revalidated_at_release_after_external_damage() {
        use crate::ballast::release::BallastReleaseController;
        use crate::monitor::pid::PressureLevel;

        let (root, mut manager) = provisioned_fixture();
        let mut disabled = config();
        disabled.file_count = 0;
        manager.update_config(disabled.clone());
        assert_eq!(manager.available_count(), 3);
        let changed = manager.file_path(3);
        fs::write(&changed, b"replacement data").unwrap();
        assert_eq!(manager.available_count(), 3, "the cached observation predates the write");
        assert_eq!(BallastAvailability::observe(&manager.ballast_dir, &disabled).available_count, 2);
        let mut controller = BallastReleaseController::new(0);
        let report = controller
            .maybe_release(root.path(), &mut manager, &pressure(root.path(), PressureLevel::Critical))
            .unwrap()
            .unwrap();
        assert_eq!(report.files_released, 2);
        assert_eq!(report.bytes_freed, 2 * config().file_size_bytes);
        assert_eq!(fs::read(changed).unwrap(), b"replacement data");
        assert_eq!(manager.available_count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn very_high_surplus_index_does_not_imply_billions_of_missing_slots() {
        let (_root, mut manager) = verified_fixture();
        let mut bytes = fs::read(manager.file_path(1)).unwrap();
        let header = super::super::ballast_header_buffer(u32::MAX, config().file_size_bytes).unwrap();
        bytes[..HEADER_SIZE].copy_from_slice(&header);
        fs::write(manager.file_path(u32::MAX), bytes).unwrap();
        let mut disabled = config();
        disabled.file_count = 0;
        manager.update_config(disabled.clone());
        let observed = BallastAvailability::observe(&manager.ballast_dir, &disabled);
        assert_eq!(observed.available_count, 2);
        assert_eq!(observed.missing_count, 0);
        assert_eq!(observed.releasable_bytes, 2 * config().file_size_bytes);
        assert_eq!(manager.available_count(), 2);
        assert_eq!(manager.inventory()[1].index, u32::MAX);
    }

    #[test]
    fn disabled_target_does_not_turn_an_unknown_pool_into_proven_absence() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("not-a-directory");
        fs::write(&path, b"keep").unwrap();
        let mut disabled = config();
        disabled.file_count = 0;
        let observed = BallastAvailability::observe(&path, &disabled);
        assert_eq!(observed.health, BallastHealth::Unconfigured);
        assert_eq!(observed.available_count, 0);
        assert_eq!(observed.missing_count, 0);
        assert!(!observed.is_authoritative());
        assert_eq!(fs::read(path).unwrap(), b"keep");
    }
}
