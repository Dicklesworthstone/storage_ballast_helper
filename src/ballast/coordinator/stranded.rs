//! Read-only adoption and identity-checked release of retired ballast pools.
//!
//! A remembered pathname is not deletion authority. Reopen the same directory,
//! take the existing manager lock without waiting or allocating, and revalidate
//! the file's identity and header before unlinking relative to that directory.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::ballast::manager::{BallastHealth, ReleaseReport};

/// Conventional legacy locations, including former user-scope installations.
/// Only the first level of account directories is enumerated, never user data.
pub(super) fn legacy_dirs(
    watched: &[PathBuf],
    configured: Option<&Path>,
    home: Option<&Path>,
) -> Vec<PathBuf> {
    let homes = conventional_homes(&[PathBuf::from("/home"), PathBuf::from("/Users")]);
    legacy_dirs_with_homes(watched, configured, home, homes)
}

fn conventional_homes(containers: &[PathBuf]) -> Vec<PathBuf> {
    let mut homes = vec![PathBuf::from("/root")];
    for container in containers {
        let Ok(entries) = std::fs::read_dir(container) else {
            continue;
        };
        // Bound account enumeration; this is not a recursive filesystem scan.
        for entry in entries.take(4096).flatten() {
            if entry
                .file_type()
                .is_ok_and(|kind| kind.is_dir() || kind.is_symlink())
            {
                homes.push(entry.path());
            }
        }
    }
    homes
}

fn legacy_dirs_with_homes(
    watched: &[PathBuf],
    configured: Option<&Path>,
    home: Option<&Path>,
    discovered: Vec<PathBuf>,
) -> Vec<PathBuf> {
    let mut homes: BTreeSet<PathBuf> = discovered.into_iter().collect();
    if let Some(home) = home.filter(|home| home.is_absolute()) {
        homes.insert(home.to_path_buf());
    }
    for path in watched.iter().map(PathBuf::as_path).chain(configured) {
        for ancestor in path.ancestors() {
            if ancestor == Path::new("/root")
                || ancestor.parent().is_some_and(|parent| {
                    parent == Path::new("/home") || parent == Path::new("/Users")
                })
            {
                homes.insert(ancestor.to_path_buf());
            }
        }
    }
    let mut dirs = vec![PathBuf::from("/var/lib/sbh/ballast")];
    for home in homes {
        dirs.push(home.join(".local/share/sbh/ballast"));
        dirs.push(home.join("Library/Application Support/sbh/ballast"));
    }
    dirs
}

pub(super) fn health(configured: u64, managed: BallastHealth, bytes: u64) -> BallastHealth {
    if managed == BallastHealth::Indeterminate {
        managed
    } else {
        BallastHealth::evaluate(configured, bytes)
    }
}

pub(super) fn empty_report() -> ReleaseReport {
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
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::OsStr;
    use std::fs::{self, File, Metadata, OpenOptions};
    use std::io::{self, Read};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};

    use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags, flock, openat, unlinkat};

    use crate::ballast::manager::{BallastHeader, HEADER_SIZE, MAGIC, ReleaseReport};

    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct Identity {
        device: u64,
        inode: u64,
    }

    impl Identity {
        fn of(meta: &Metadata) -> Self {
            Self {
                device: meta.dev(),
                inode: meta.ino(),
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct FileIdentity {
        identity: Identity,
        size: u64,
        modified: (i64, i64),
        changed: (i64, i64),
    }

    impl FileIdentity {
        fn of(meta: &Metadata) -> Self {
            Self {
                identity: Identity::of(meta),
                size: meta.len(),
                modified: (meta.mtime(), meta.mtime_nsec()),
                changed: (meta.ctime(), meta.ctime_nsec()),
            }
        }
    }

    #[derive(Debug)]
    struct Snapshot {
        directory: Identity,
        file: FileIdentity,
    }

    #[derive(Debug, Default)]
    pub(in super::super) struct StrandedReserve {
        files: Vec<(PathBuf, u64)>,
        snapshots: BTreeMap<PathBuf, Snapshot>,
    }

    fn invalid(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    fn open_directory(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }

    fn open_regular(directory: &File, name: &OsStr) -> io::Result<File> {
        let fd = openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let file = File::from(fd);
        if !file.metadata()?.is_file() {
            return Err(invalid("not a regular ballast file"));
        }
        Ok(file)
    }

    fn index(name: &OsStr) -> Option<u32> {
        let name = name.to_str()?;
        let index = name
            .strip_prefix("SBH_BALLAST_FILE_")?
            .strip_suffix(".dat")?
            .parse()
            .ok()?;
        (index > 0 && name == format!("SBH_BALLAST_FILE_{index:05}.dat")).then_some(index)
    }

    fn read_candidate(directory: &File, name: &OsStr) -> io::Result<(File, FileIdentity)> {
        let index = index(name).ok_or_else(|| invalid("not a canonical ballast filename"))?;
        let mut file = open_regular(directory, name)?;
        let meta = file.metadata()?;
        // A hard-linked or sparse file is not independently releasable reserve.
        if meta.nlink() != 1
            || meta.len() < HEADER_SIZE as u64
            || meta.blocks().saturating_mul(512) < meta.len()
        {
            return Err(invalid(
                "ballast is linked, truncated, or not fully allocated",
            ));
        }
        let identity = FileIdentity::of(&meta);
        let mut bytes = [0u8; HEADER_SIZE];
        file.read_exact(&mut bytes)?;
        let end = bytes
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(HEADER_SIZE);
        let header: BallastHeader = serde_json::from_slice(&bytes[..end])
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if header.magic != MAGIC || header.file_index != index || header.file_size != meta.len() {
            return Err(invalid(
                "ballast header does not match its filename and actual size",
            ));
        }
        if FileIdentity::of(&file.metadata()?) != identity {
            return Err(invalid("ballast changed while reading its header"));
        }
        Ok((file, identity))
    }

    impl StrandedReserve {
        pub(in super::super) fn discover(dirs: &[PathBuf], managed: &Path, mount: &Path) -> Self {
            let mut reserve = Self::default();
            let Ok(mount_meta) = fs::metadata(mount) else {
                return reserve;
            };
            let managed_identity = fs::metadata(managed).ok().map(|meta| Identity::of(&meta));
            let mut seen = BTreeSet::new();
            for dir in dirs {
                // Resolve aliases once, then retain and check inode identity.
                let Ok(dir) = fs::canonicalize(dir) else {
                    continue;
                };
                let Ok(directory) = open_directory(&dir) else {
                    continue;
                };
                let Ok(meta) = directory.metadata() else {
                    continue;
                };
                let identity = Identity::of(&meta);
                if identity.device != mount_meta.dev()
                    || Some(identity) == managed_identity
                    || !seen.insert(identity)
                {
                    continue;
                }
                let Ok(entries) = fs::read_dir(&dir) else {
                    continue;
                };
                let mut files = Vec::new();
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let Some(index) = index(&name) else {
                        continue;
                    };
                    let Ok((_, file)) = read_candidate(&directory, &name) else {
                        continue;
                    };
                    let path = dir.join(name);
                    files.push((index, path.clone(), file.size));
                    reserve.snapshots.insert(
                        path,
                        Snapshot {
                            directory: identity,
                            file,
                        },
                    );
                }
                files.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
                reserve
                    .files
                    .extend(files.into_iter().map(|(_, path, size)| (path, size)));
            }
            reserve
        }

        pub(in super::super) fn files(&self) -> &[(PathBuf, u64)] {
            &self.files
        }

        pub(in super::super) fn bytes(&self) -> u64 {
            self.files
                .iter()
                .map(|(_, size)| *size)
                .fold(0, u64::saturating_add)
        }

        /// Revalidate before crediting reserve against new allocation. Known
        /// losses revoke stale inventory; unreadable or busy entries defer
        /// growth instead of silently treating an unknown reserve as empty.
        /// This never adopts a replacement under an old snapshot's authority.
        pub(in super::super) fn refresh(&mut self) -> Vec<String> {
            let mut errors = Vec::new();
            let mut kept = Vec::new();
            for (path, size) in std::mem::take(&mut self.files) {
                let Some(snapshot) = self.snapshots.get(&path) else {
                    continue;
                };
                match with_validated_candidate(&path, snapshot, |_, _| Ok(())) {
                    Ok(()) => kept.push((path, size)),
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::NotFound | io::ErrorKind::InvalidData
                        ) =>
                    {
                        self.snapshots.remove(&path);
                    }
                    Err(error) => {
                        errors.push(format!(
                            "cannot determine adopted reserve at {}: {error}",
                            path.display()
                        ));
                        kept.push((path, size));
                    }
                }
            }
            self.files = kept;
            errors
        }

        /// Missing/replaced entries revoke the cached authority and do not
        /// consume the quota. A busy directory cannot block a healthy sibling.
        pub(in super::super) fn release(&mut self, count: usize) -> ReleaseReport {
            let mut report = super::empty_report();
            let mut kept = Vec::new();
            for (path, size) in std::mem::take(&mut self.files) {
                if report.files_released >= count {
                    kept.push((path, size));
                    continue;
                }
                let Some(snapshot) = self.snapshots.get(&path) else {
                    continue;
                };
                match release_one(&path, snapshot) {
                    Ok(()) => {
                        self.snapshots.remove(&path);
                        report.files_released += 1;
                        report.bytes_freed = report.bytes_freed.saturating_add(size);
                        report.released.push((path, size));
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        self.snapshots.remove(&path);
                    }
                    Err(error) => {
                        let message = format!("stranded ballast {}: {error}", path.display());
                        report.warnings.push(message.clone());
                        report.errors.push(message);
                        if error.kind() == io::ErrorKind::InvalidData {
                            self.snapshots.remove(&path);
                        } else {
                            kept.push((path, size));
                        }
                    }
                }
            }
            self.files = kept;
            report
        }
    }

    fn with_validated_candidate(
        path: &Path,
        snapshot: &Snapshot,
        action: impl FnOnce(&File, &OsStr) -> io::Result<()>,
    ) -> io::Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| invalid("ballast has no parent"))?;
        let directory = open_directory(parent)?;
        if Identity::of(&directory.metadata()?) != snapshot.directory {
            return Err(invalid("ballast directory was replaced"));
        }
        // The same lock as BallastManager, but never create it or wait behind
        // a provisioner. Legacy pools produced by the manager already have it.
        let lock = open_regular(&directory, OsStr::new(".lock")).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                io::Error::other("existing ballast lock is missing; refusing unlocked access")
            } else {
                error
            }
        })?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive)?;
        let name = path
            .file_name()
            .ok_or_else(|| invalid("ballast has no filename"))?;
        let (_file, current) = read_candidate(&directory, name)?;
        if current != snapshot.file {
            return Err(invalid(
                "ballast file was replaced or modified since adoption",
            ));
        }
        // Keep directory, payload and manager lock alive throughout the action.
        action(&directory, name)
    }

    fn release_one(path: &Path, snapshot: &Snapshot) -> io::Result<()> {
        with_validated_candidate(path, snapshot, |directory, name| {
            // Cooperating CLI/daemon writers hold .lock; anchoring the unlink to
            // the open directory also prevents an ancestor rename redirecting it.
            unlinkat(directory, name, AtFlags::empty())?;
            Ok(())
        })
    }
}

#[cfg(unix)]
pub(super) use unix::StrandedReserve;

// No pathname-only fallback on platforms without anchored Unix file operations.
#[cfg(not(unix))]
#[derive(Debug, Default)]
pub(super) struct StrandedReserve;

#[cfg(not(unix))]
impl StrandedReserve {
    pub(super) fn discover(_dirs: &[PathBuf], _managed: &Path, _mount: &Path) -> Self {
        Self
    }
    pub(super) fn files(&self) -> &[(PathBuf, u64)] {
        &[]
    }
    pub(super) fn bytes(&self) -> u64 {
        0
    }
    pub(super) fn refresh(&mut self) -> Vec<String> {
        Vec::new()
    }
    pub(super) fn release(&mut self, _count: usize) -> ReleaseReport {
        empty_report()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_locations_include_only_known_homes_and_conventional_paths() {
        let dirs = legacy_dirs_with_homes(
            &[
                PathBuf::from("/home/alice/projects"),
                PathBuf::from("/data/projects"),
            ],
            Some(Path::new("/Users/bob/new-reserve")),
            Some(Path::new("/root")),
            Vec::new(),
        );
        for expected in [
            "/var/lib/sbh/ballast",
            "/root/.local/share/sbh/ballast",
            "/home/alice/.local/share/sbh/ballast",
            "/Users/bob/.local/share/sbh/ballast",
        ] {
            assert!(dirs.contains(&PathBuf::from(expected)));
        }
        assert!(!dirs.iter().any(|path| path.starts_with("/data")));
        assert_eq!(dirs.len(), 7);
    }

    #[test]
    fn discovers_other_accounts_without_descending_into_their_data() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("ubuntu");
        std::fs::create_dir_all(home.join("projects/not-an-account")).unwrap();
        std::fs::write(temp.path().join("not-a-directory"), b"ignored").unwrap();
        let homes = conventional_homes(&[temp.path().to_path_buf()]);
        let dirs = legacy_dirs_with_homes(&[], None, None, homes);
        assert!(dirs.contains(&home.join(".local/share/sbh/ballast")));
        assert!(
            !dirs
                .iter()
                .any(|path| path.starts_with(home.join("projects")))
        );
        assert!(
            !dirs
                .iter()
                .any(|path| path.starts_with(temp.path().join("not-a-directory")))
        );
    }

    #[test]
    fn reserve_health_counts_retired_bytes_but_preserves_unknown_managed_state() {
        assert_eq!(health(100, BallastHealth::Empty, 100), BallastHealth::Ok);
        assert_eq!(
            health(100, BallastHealth::Empty, 30),
            BallastHealth::Degraded
        );
        assert_eq!(
            health(100, BallastHealth::Indeterminate, 100),
            BallastHealth::Indeterminate
        );
        assert_eq!(
            health(0, BallastHealth::Unconfigured, 100),
            BallastHealth::Unconfigured
        );
    }
}

#[cfg(all(test, unix))]
mod release_tests {
    use super::*;
    use crate::ballast::manager::{BallastHeader, HEADER_SIZE, MAGIC};
    use rustix::fs::{FlockOperation, flock};
    use std::fs::{self, File};
    use std::os::unix::fs::symlink;

    fn ballast(dir: &Path, index: u32) -> PathBuf {
        fs::create_dir_all(dir).unwrap();
        let name = format!("SBH_BALLAST_FILE_{index:05}.dat");
        let path = dir.join(name);
        let size = HEADER_SIZE * 2;
        let header = BallastHeader {
            magic: MAGIC.to_string(),
            file_index: index,
            created_at: "2026-09-24T00:00:00Z".to_string(),
            file_size: size as u64,
            purpose: "test reserve".to_string(),
        };
        let encoded = serde_json::to_vec(&header).unwrap();
        let mut bytes = vec![0; size];
        bytes[..encoded.len()].copy_from_slice(&encoded);
        fs::write(&path, bytes).unwrap();
        fs::write(dir.join(".lock"), b"").unwrap();
        path
    }

    fn discover(root: &Path, dirs: &[PathBuf]) -> StrandedReserve {
        StrandedReserve::discover(dirs, &root.join("managed"), root)
    }

    #[test]
    fn release_is_quota_bound_and_never_needs_the_managed_directory() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("legacy");
        for index in 1..=3 {
            ballast(&dir, index);
        }
        let mut reserve = discover(temp.path(), &[dir]);
        assert_eq!(reserve.files().len(), 3);
        assert_eq!(reserve.bytes(), 3 * (HEADER_SIZE as u64) * 2);
        assert_eq!(reserve.release(0).files_released, 0);
        let report = reserve.release(2);
        assert_eq!(report.files_released, 2);
        assert_eq!(report.bytes_freed, 4 * HEADER_SIZE as u64);
        assert!(report.errors.is_empty());
        assert_eq!(reserve.files().len(), 1);
        assert!(!temp.path().join("managed").exists());
    }

    #[test]
    fn directory_aliases_are_not_double_counted_or_adopted_from_the_managed_pool() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("legacy");
        ballast(&dir, 1);
        let alias = temp.path().join("alias");
        symlink(&dir, &alias).unwrap();
        let dirs = [dir.clone(), alias.clone(), dir];
        assert_eq!(discover(temp.path(), &dirs).files().len(), 1);
        assert!(
            StrandedReserve::discover(&dirs, &alias, temp.path())
                .files()
                .is_empty()
        );
    }

    #[test]
    fn discovery_rejects_symlinks_hardlinks_and_forged_or_mismatched_headers() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("legacy");
        let good = ballast(&dir, 1);
        let linked = ballast(&dir, 2);
        fs::hard_link(&linked, temp.path().join("keep-link")).unwrap();
        symlink(&good, dir.join("SBH_BALLAST_FILE_00003.dat")).unwrap();
        fs::copy(&good, dir.join("SBH_BALLAST_FILE_00004.dat")).unwrap();
        fs::write(
            dir.join("SBH_BALLAST_FILE_00005.dat"),
            vec![b'x'; HEADER_SIZE * 2],
        )
        .unwrap();
        let reserve = discover(temp.path(), &[dir]);
        assert_eq!(reserve.files().len(), 1);
        assert_eq!(reserve.files()[0].0, fs::canonicalize(good).unwrap());
    }

    #[test]
    fn a_valid_replacement_is_not_authorized_by_the_previous_file_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("legacy");
        let path = ballast(&dir, 1);
        let mut reserve = discover(temp.path(), &[dir]);
        let replacement = ballast(&temp.path().join("replacement"), 1);
        fs::rename(replacement, &path).unwrap();
        let report = reserve.release(1);
        assert_eq!(report.files_released, 0);
        assert_eq!(report.errors.len(), 1);
        assert!(path.exists());
        assert!(
            reserve.files().is_empty(),
            "changed identity revokes cached authority"
        );
    }

    #[test]
    fn same_inode_content_changes_are_revalidated() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("legacy");
        let path = ballast(&dir, 1);
        let mut reserve = discover(temp.path(), &[dir]);
        fs::write(&path, vec![b'x'; HEADER_SIZE * 2]).unwrap();
        let report = reserve.release(1);
        assert_eq!(report.files_released, 0);
        assert_eq!(report.errors.len(), 1);
        assert!(path.exists());
    }

    #[test]
    fn replaced_directory_never_redirects_release_to_another_pool() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("legacy");
        ballast(&dir, 1);
        let mut reserve = discover(temp.path(), std::slice::from_ref(&dir));
        fs::rename(&dir, temp.path().join("old")).unwrap();
        let replacement = ballast(&dir, 1);
        let report = reserve.release(1);
        assert_eq!(report.files_released, 0);
        assert!(replacement.exists());
        assert_eq!(report.errors.len(), 1);
    }

    #[test]
    fn busy_pool_does_not_block_release_from_a_healthy_pool() {
        let temp = tempfile::tempdir().unwrap();
        let busy = temp.path().join("busy");
        let healthy = temp.path().join("healthy");
        let busy_file = ballast(&busy, 1);
        let healthy_file = ballast(&healthy, 1);
        let mut reserve = discover(temp.path(), &[busy.clone(), healthy]);
        let lock = File::open(busy.join(".lock")).unwrap();
        flock(&lock, FlockOperation::NonBlockingLockExclusive).unwrap();
        let report = reserve.release(1);
        assert_eq!(report.files_released, 1);
        assert_eq!(report.errors.len(), 1);
        assert!(busy_file.exists());
        assert!(!healthy_file.exists());
        drop(lock);
        assert_eq!(reserve.release(1).files_released, 1);
    }

    #[test]
    fn missing_lock_is_reported_without_allocating_a_replacement_lock() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("legacy");
        let path = ballast(&dir, 1);
        let mut reserve = discover(temp.path(), std::slice::from_ref(&dir));
        fs::remove_file(dir.join(".lock")).unwrap();
        let report = reserve.release(1);
        assert_eq!(report.files_released, 0);
        assert_eq!(report.errors.len(), 1);
        assert!(path.exists());
        assert!(!dir.join(".lock").exists());
    }

    #[test]
    fn lock_symlinks_are_never_followed() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("legacy");
        let path = ballast(&dir, 1);
        let mut reserve = discover(temp.path(), std::slice::from_ref(&dir));
        let other = temp.path().join("unrelated");
        fs::write(&other, b"keep").unwrap();
        fs::remove_file(dir.join(".lock")).unwrap();
        symlink(&other, dir.join(".lock")).unwrap();
        assert_eq!(reserve.release(1).files_released, 0);
        assert!(path.exists());
        assert_eq!(fs::read(other).unwrap(), b"keep");
    }

    #[test]
    fn missing_files_do_not_consume_release_quota_or_claim_freed_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("legacy");
        for index in 1..=3 {
            ballast(&dir, index);
        }
        let mut reserve = discover(temp.path(), &[dir]);
        fs::remove_file(&reserve.files()[0].0).unwrap();
        let report = reserve.release(2);
        assert_eq!(report.files_released, 2);
        assert_eq!(report.bytes_freed, 4 * HEADER_SIZE as u64);
        assert!(reserve.files().is_empty());
    }

    #[test]
    fn discovery_and_empty_release_do_not_create_any_paths() {
        let temp = tempfile::tempdir().unwrap();
        let mut reserve = discover(temp.path(), &[temp.path().join("missing")]);
        assert_eq!(reserve.release(1).files_released, 0);
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn adoption_never_counts_reserve_on_a_different_device() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("legacy");
        let path = ballast(&dir, 1);
        let reserve =
            StrandedReserve::discover(&[dir], &temp.path().join("managed"), Path::new("/proc"));
        assert!(reserve.files().is_empty());
        assert!(path.exists());
    }

    #[test]
    fn refresh_revokes_missing_and_replaced_files_without_adopting_the_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("legacy");
        let first = ballast(&dir, 1);
        let second = ballast(&dir, 2);
        let third = ballast(&dir, 3);
        let mut reserve = discover(temp.path(), &[dir]);
        fs::remove_file(first).unwrap();
        let replacement = ballast(&temp.path().join("replacement"), 2);
        fs::rename(replacement, &second).unwrap();
        assert!(reserve.refresh().is_empty());
        assert_eq!(reserve.files().len(), 1);
        assert_eq!(reserve.files()[0].0, fs::canonicalize(third).unwrap());
        assert!(second.exists());
        assert_eq!(reserve.bytes(), 2 * HEADER_SIZE as u64);
    }

    #[test]
    fn refresh_reports_unknown_reserve_instead_of_authorizing_replacement_allocation() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("legacy");
        ballast(&dir, 1);
        let mut reserve = discover(temp.path(), std::slice::from_ref(&dir));
        let lock = File::open(dir.join(".lock")).unwrap();
        flock(&lock, FlockOperation::NonBlockingLockExclusive).unwrap();
        assert_eq!(reserve.refresh().len(), 1);
        assert_eq!(reserve.files().len(), 1);
        drop(lock);
        assert!(reserve.refresh().is_empty());
        assert_eq!(reserve.files().len(), 1);
    }
}
