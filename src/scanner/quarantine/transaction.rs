//! Descriptor-relative quarantine transactions and payload transfers.
//!
//! A store lock pins a directory, not its pathname. Reading recovery records or
//! removing them through that pathname after locking can act on a replacement
//! store while the purge itself still operates on the old descriptor. Keep the
//! manifest, payload lookup and finalization in the same opened directory.
//!
//! The lock coordinates cooperating processes. This does not authenticate
//! manifests against a writer with access to the locked directory itself.
//! Original parent aliases are resolved once and rejected if they lead into
//! quarantine. Parent bindings and the captured source identity are rechecked
//! before moving, but the last check and rename are not one conditional syscall.
//! A namespace move after transfer does not rebase the record's stored paths;
//! finalization preserves the record with the opened store, not its replacement.

use std::ffi::{OsStr, OsString};
use std::fs::File;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::io;
#[cfg(unix)]
use std::io::Write;
use std::path::{Component, Path};

use serde::{Serialize, de::DeserializeOwned};

use super::{MAX_RECORD_BYTES, QuarantineRecord, invalid};
#[cfg(unix)]
use super::decode_json;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    File,
    Directory,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Identity {
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) kind: Kind,
}

impl Identity {
    pub(super) fn matches_record(self, record: &QuarantineRecord) -> bool {
        matches!(self.kind, Kind::File | Kind::Directory)
            && (self.device, self.inode) == (record.device_id, record.inode)
    }

    #[cfg(unix)]
    #[allow(clippy::unnecessary_cast, clippy::cast_sign_loss)]
    fn of(stat: &rustix::fs::Stat) -> Self {
        use rustix::fs::FileType;
        Self {
            device: stat.st_dev as u64,
            inode: stat.st_ino as u64,
            kind: match FileType::from_raw_mode(stat.st_mode) {
                FileType::RegularFile => Kind::File,
                FileType::Directory => Kind::Directory,
                _ => Kind::Other,
            },
        }
    }
}

fn child_name(name: &OsStr) -> io::Result<()> {
    let path = Path::new(name);
    let mut parts = path.components();
    if !matches!(parts.next(), Some(Component::Normal(_)))
        || parts.next().is_some()
        || path.file_name() != Some(name)
    {
        return Err(invalid("quarantine transaction requires a single child name"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn unsupported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "quarantine requires Unix directory descriptors")
}

#[derive(Debug)]
pub(super) struct Directory {
    file: File,
}

impl Directory {
    /// Original-path aliases (including macOS /tmp) are resolved only when
    /// opening the parent. Subsequent operations use this descriptor and one
    /// basename, never the original parent pathname again.
    pub(super) fn parent_of(path: &Path) -> io::Result<(Self, OsString)> {
        let absolute = std::path::absolute(path)?;
        let name = absolute.file_name().ok_or_else(|| invalid("payload has no basename"))?;
        child_name(name)?;
        let parent = absolute.parent().ok_or_else(|| invalid("payload has no parent"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
                .open(parent)?;
            Ok((Self { file }, name.to_os_string()))
        }
        #[cfg(not(unix))]
        {
            let _ = parent;
            Err(unsupported())
        }
    }

    pub(super) fn open_store(path: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?;
            Ok(Self { file })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(unsupported())
        }
    }

    pub(super) fn from_locked(file: &File) -> io::Result<Self> {
        Ok(Self { file: file.try_clone()? })
    }

    pub(super) fn identity(&self) -> io::Result<Identity> {
        #[cfg(unix)]
        {
            Ok(Identity::of(&rustix::fs::fstat(&self.file)?))
        }
        #[cfg(not(unix))]
        Err(unsupported())
    }

    pub(super) fn require_path(&self, path: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::metadata(path)?;
            let identity = self.identity()?;
            if !metadata.is_dir() || (metadata.dev(), metadata.ino()) != (identity.device, identity.inode) {
                return Err(invalid("quarantine transaction parent pathname changed"));
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(unsupported())
        }
    }

    fn ancestors(&self, mut visit: impl FnMut(&Self) -> io::Result<()>) -> io::Result<()> {
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, OFlags, openat};
            let mut current = Self::from_locked(&self.file)?;
            // Bound descriptors and namespace churn independently of path
            // length. The literal '..' is internal, never a caller's child name.
            for _ in 0..256 {
                visit(&current)?;
                let parent = Self { file: File::from(openat(
                    &current.file,
                    "..",
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?) };
                if parent.identity()? == current.identity()? {
                    return Ok(());
                }
                current = parent;
            }
            Err(invalid("quarantine ancestor traversal limit reached"))
        }
        #[cfg(not(unix))]
        {
            let _ = &mut visit;
            Err(unsupported())
        }
    }

    pub(super) fn require_outside(&self, store: &Self) -> io::Result<()> {
        let forbidden = store.identity()?;
        self.ancestors(|directory| {
            if directory.identity()? == forbidden {
                Err(invalid("original payload parent resolves inside quarantine"))
            } else {
                Ok(())
            }
        })
    }

    pub(super) fn sync_ancestors(&self) -> io::Result<()> {
        self.ancestors(Self::sync)
    }

    pub(super) fn create_directory(&self, name: &OsStr) -> io::Result<Self> {
        child_name(name)?;
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, mkdirat};
            mkdirat(&self.file, name, Mode::RUSR | Mode::WUSR | Mode::XUSR)?;
            match self.child(name) {
                Ok(directory) => Ok(directory),
                Err(error) => {
                    // Never recurse or remove an existing nonempty sibling.
                    let _ = self.remove_directory(name);
                    Err(error)
                }
            }
        }
        #[cfg(not(unix))]
        Err(unsupported())
    }

    pub(super) fn write_new_json(&self, name: &OsStr, value: &impl Serialize) -> io::Result<()> {
        child_name(name)?;
        let bytes = serde_json::to_vec_pretty(value)?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(invalid("quarantine metadata exceeds the size limit"));
        }
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, OFlags, fstat, openat};
            let mut file = File::from(openat(
                &self.file,
                name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )?);
            let identity = Identity::of(&fstat(&file)?);
            let result = file.write_all(&bytes).and_then(|()| file.sync_all());
            if result.is_err() && self.inspect(name).is_ok_and(|current| current == Some(identity)) {
                let _ = self.remove_file(name);
            }
            result
        }
        #[cfg(not(unix))]
        Err(unsupported())
    }

    pub(super) fn rename_noreplace(&self, name: &OsStr, to: &Self, new_name: &OsStr) -> io::Result<()> {
        child_name(name)?;
        child_name(new_name)?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            rustix::fs::renameat_with(
                &self.file, name, &to.file, new_name, rustix::fs::RenameFlags::NOREPLACE,
            )?;
            Ok(())
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = to;
            Err(io::Error::new(io::ErrorKind::Unsupported, "atomic no-replace rename is unavailable"))
        }
    }

    pub(super) fn inspect(&self, name: &OsStr) -> io::Result<Option<Identity>> {
        child_name(name)?;
        #[cfg(unix)]
        {
            use rustix::fs::{AtFlags, statat};
            match statat(&self.file, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => Ok(Some(Identity::of(&stat))),
                Err(rustix::io::Errno::NOENT) => Ok(None),
                Err(error) => Err(error.into()),
            }
        }
        #[cfg(not(unix))]
        Err(unsupported())
    }

    pub(super) fn child(&self, name: &OsStr) -> io::Result<Self> {
        child_name(name)?;
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, OFlags, fstat};
            let expected = self.inspect(name)?.ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "quarantine decision directory is absent")
            })?;
            if expected.kind != Kind::Directory
                || expected.device != Identity::of(&fstat(&self.file)?).device
            {
                return Err(invalid("quarantine decision is not a same-device directory"));
            }
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            #[cfg(target_os = "linux")]
            let fd = rustix::fs::openat2(
                &self.file,
                name,
                flags,
                Mode::empty(),
                rustix::fs::ResolveFlags::BENEATH
                    | rustix::fs::ResolveFlags::NO_SYMLINKS
                    | rustix::fs::ResolveFlags::NO_MAGICLINKS
                    | rustix::fs::ResolveFlags::NO_XDEV,
            )?;
            #[cfg(not(target_os = "linux"))]
            let fd = rustix::fs::openat(&self.file, name, flags, Mode::empty())?;
            let file = File::from(fd);
            if Identity::of(&fstat(&file)?) != expected {
                return Err(invalid("quarantine decision directory changed while opening"));
            }
            Ok(Self { file })
        }
        #[cfg(not(unix))]
        Err(unsupported())
    }

    pub(super) fn read_json<T: DeserializeOwned>(&self, name: &OsStr) -> io::Result<T> {
        child_name(name)?;
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, OFlags, openat};
            let file = File::from(openat(
                &self.file,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            decode_json(file)
        }
        #[cfg(not(unix))]
        Err(unsupported())
    }

    pub(super) fn remove_file(&self, name: &OsStr) -> io::Result<()> {
        self.remove(name, false)
    }

    pub(super) fn remove_directory(&self, name: &OsStr) -> io::Result<()> {
        self.remove(name, true)
    }

    fn remove(&self, name: &OsStr, directory: bool) -> io::Result<()> {
        child_name(name)?;
        #[cfg(unix)]
        {
            use rustix::fs::{AtFlags, unlinkat};
            let flags = if directory { AtFlags::REMOVEDIR } else { AtFlags::empty() };
            match unlinkat(&self.file, name, flags) {
                Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
                Err(error) => Err(error.into()),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = directory;
            Err(unsupported())
        }
    }

    pub(super) fn sync(&self) -> io::Result<()> {
        self.file.sync_all()
    }
}

/// One observed payload name under an opened parent. No payload file is opened
/// (in particular, no FIFO, device or symlink target). Identity is checked again
/// immediately before rename. This is not an atomic inode-conditional rename:
/// an uncooperative writer to the opened source directory can still race the
/// last check. Descriptor binding prevents ancestor replacement from redirecting
/// the operation; the store lock supplies interoperation exclusion.
#[derive(Debug)]
pub(super) struct Payload {
    pub(super) parent: Directory,
    pub(super) name: OsString,
    pub(super) identity: Identity,
}

impl Payload {
    pub(super) fn observe(parent: Directory, name: OsString) -> io::Result<Option<Self>> {
        let Some(identity) = parent.inspect(&name)? else {
            return Ok(None);
        };
        if !matches!(identity.kind, Kind::File | Kind::Directory) {
            return Err(invalid("candidate is not a regular file or directory"));
        }
        Ok(Some(Self { parent, name, identity }))
    }

    pub(super) fn open(path: &Path) -> io::Result<Self> {
        let (parent, name) = Directory::parent_of(path)?;
        Self::observe(parent, name)?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "quarantine source is absent")
        })
    }

    pub(super) fn verify(&self) -> io::Result<()> {
        if self.parent.inspect(&self.name)? != Some(self.identity) {
            return Err(invalid("quarantine source identity changed before rename"));
        }
        Ok(())
    }

    pub(super) fn move_to(&self, parent: &Directory, name: &OsStr) -> io::Result<()> {
        self.verify()?;
        self.parent.rename_noreplace(&self.name, parent, name)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::scanner::quarantine::QuarantineStore;
    use super::super::{
        TransactionStep, confined_purge, lock_store, purge_with, quarantine_with_hook,
        read_record_at, restore_with_hook,
    };
    use std::fs;
    use std::time::Duration;

    fn held(base: &Path) -> (QuarantineStore, QuarantineRecord) {
        let store = QuarantineStore::under(base);
        let source = base.join("artifact");
        fs::write(&source, b"only copy").unwrap();
        let record = store.quarantine(&source, "held", 9, Duration::ZERO, None).unwrap();
        (store, record)
    }

    #[test]
    fn a_locked_read_uses_the_original_store_after_its_path_is_replaced() {
        for pending in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let (store, record) = held(temp.path());
            if pending {
                fs::rename(store.root().join("held.json"), store.root().join("held.pending")).unwrap();
            }
            let lock = lock_store(store.root()).unwrap();
            let directory = Directory::from_locked(&lock).unwrap();
            let saved = temp.path().join("retained-store");
            fs::rename(store.root(), &saved).unwrap();
            fs::create_dir(store.root()).unwrap();
            fs::write(store.root().join("held.json"), b"unrelated replacement record").unwrap();
            assert_eq!(read_record_at(&store, "held", &directory).unwrap(), Some(record));
            assert_eq!(fs::read(saved.join("held/artifact")).unwrap(), b"only copy");
            assert_eq!(fs::read(store.root().join("held.json")).unwrap(), b"unrelated replacement record");
        }
    }

    #[test]
    fn purge_finalization_cannot_remove_replacement_stores_recovery_data() {
        let temp = tempfile::tempdir().unwrap();
        let (store, record) = held(temp.path());
        let saved = temp.path().join("purged-store");
        let result = purge_with(&store, "held", None, |lock, selected| {
            let removed = confined_purge::remove_payload(lock, selected)?;
            // The real payload is gone, but the transaction has not removed
            // its manifest yet. A path-based finalizer would touch this new store.
            fs::rename(store.root(), &saved)?;
            fs::create_dir_all(store.root().join("held"))?;
            for name in ["held.json", "held.pending", "held.stuck", "held/keep"] {
                fs::write(store.root().join(name), name.as_bytes())?;
            }
            Ok(Some(removed))
        }).unwrap();
        assert_eq!(result, Some(9));
        assert!(!saved.join("held.json").exists());
        assert!(!saved.join("held").exists());
        assert!(!record.original_path.exists());
        for name in ["held.json", "held.pending", "held.stuck", "held/keep"] {
            assert_eq!(fs::read(store.root().join(name)).unwrap(), name.as_bytes());
        }
    }

    #[test]
    fn anchored_manifest_reads_refuse_symlinks_fifos_and_non_child_names() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let (store, _) = held(temp.path());
        let lock = lock_store(store.root()).unwrap();
        let directory = Directory::from_locked(&lock).unwrap();
        let outside = temp.path().join("outside.json");
        fs::write(&outside, b"{}\n").unwrap();
        symlink(&outside, store.root().join("link.json")).unwrap();
        nix::unistd::mkfifo(
            &store.root().join("pipe.json"),
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        ).unwrap();
        for name in ["link.json", "pipe.json", "../outside.json", "/outside.json", "held/../held.json"] {
            assert!(directory.read_json::<serde_json::Value>(OsStr::new(name)).is_err());
        }
        assert_eq!(fs::read(outside).unwrap(), b"{}\n");
        assert_eq!(directory.read_json::<QuarantineRecord>(OsStr::new("held.json")).unwrap().decision_id, "held");
    }

    #[test]
    fn quarantine_refuses_a_replaced_store_before_moving_the_source() {
        let temp = tempfile::tempdir().unwrap();
        let store = QuarantineStore::under(temp.path());
        let source = temp.path().join("artifact");
        let saved = temp.path().join("original-store");
        fs::write(&source, b"original source").unwrap();
        let result = quarantine_with_hook(&store, &source, "move", 15, Duration::ZERO, None, &mut |step| {
            if step == TransactionStep::Prepared {
                fs::rename(store.root(), &saved).unwrap();
                fs::create_dir_all(store.root().join("move")).unwrap();
                fs::write(store.root().join("move.pending"), b"foreign recovery").unwrap();
                fs::write(store.root().join("move/keep"), b"foreign data").unwrap();
            }
        });
        assert!(result.is_err());
        assert_eq!(fs::read(source).unwrap(), b"original source");
        assert!(!saved.join("move.pending").exists(), "definitely unmoved reservation can be cleaned");
        assert!(!saved.join("move").exists());
        assert_eq!(fs::read(store.root().join("move.pending")).unwrap(), b"foreign recovery");
        assert_eq!(fs::read(store.root().join("move/keep")).unwrap(), b"foreign data");
        assert!(!store.root().join("move/artifact").exists());
    }

    #[test]
    fn quarantine_publication_stays_with_the_moved_payload_after_store_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let store = QuarantineStore::under(temp.path());
        let source = temp.path().join("artifact");
        let saved = temp.path().join("original-store");
        fs::write(&source, b"only copy").unwrap();
        let record = quarantine_with_hook(&store, &source, "move", 9, Duration::ZERO, None, &mut |step| {
            if step == TransactionStep::Moved {
                fs::rename(store.root(), &saved).unwrap();
                fs::create_dir_all(store.root().join("move")).unwrap();
                fs::write(store.root().join("move.pending"), b"foreign pending").unwrap();
                fs::write(store.root().join("move/keep"), b"foreign data").unwrap();
            }
        }).unwrap();
        assert!(!source.exists());
        assert_eq!(fs::read(saved.join("move/artifact")).unwrap(), b"only copy");
        let persisted: QuarantineRecord = serde_json::from_slice(&fs::read(saved.join("move.json")).unwrap()).unwrap();
        assert_eq!(persisted, record);
        assert!(!saved.join("move.pending").exists());
        assert_eq!(fs::read(store.root().join("move.pending")).unwrap(), b"foreign pending");
        assert_eq!(fs::read(store.root().join("move/keep")).unwrap(), b"foreign data");
        assert!(!store.root().join("move.json").exists(), "never publish a foreign pending file");
    }

    #[test]
    fn a_source_replaced_during_write_ahead_preparation_is_not_moved() {
        let temp = tempfile::tempdir().unwrap();
        let store = QuarantineStore::under(temp.path());
        let source = temp.path().join("artifact");
        let retained = temp.path().join("retained-original");
        fs::write(&source, b"original source").unwrap();
        let result = quarantine_with_hook(&store, &source, "move", 15, Duration::ZERO, None, &mut |step| {
            if step == TransactionStep::Prepared {
                fs::rename(&source, &retained).unwrap();
                fs::write(&source, b"replacement source").unwrap();
            }
        });
        assert!(result.is_err());
        assert_eq!(fs::read(&source).unwrap(), b"replacement source");
        assert_eq!(fs::read(retained).unwrap(), b"original source");
        assert!(!store.root().join("move/artifact").exists());
        assert!(store.root().join("move.pending").exists(), "uncertain ownership retains recovery evidence");
        assert!(store.restore("move", false).is_err(), "replacement is not a completed undo");
        assert_eq!(fs::read(source).unwrap(), b"replacement source");
    }

    #[test]
    fn restore_refuses_a_replaced_decision_directory_before_rename() {
        let temp = tempfile::tempdir().unwrap();
        let (store, record) = held(temp.path());
        let saved = temp.path().join("retained-decision");
        let result = restore_with_hook(&store, "held", false, &mut |step| {
            if step == TransactionStep::Prepared {
                fs::rename(store.root().join("held"), &saved).unwrap();
                fs::create_dir(store.root().join("held")).unwrap();
                fs::write(&record.quarantine_path, b"replacement held data").unwrap();
            }
        });
        assert!(result.is_err());
        assert!(!record.original_path.exists());
        assert_eq!(fs::read(saved.join("artifact")).unwrap(), b"only copy");
        assert_eq!(fs::read(&record.quarantine_path).unwrap(), b"replacement held data");
        assert_eq!(store.record("held").unwrap(), Some(record));
    }

    #[test]
    fn restore_cannot_be_redirected_through_a_replaced_original_parent() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let store = QuarantineStore::under(temp.path());
        let project = temp.path().join("project");
        let outside = temp.path().join("outside");
        let saved = temp.path().join("retained-project");
        fs::create_dir(&project).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(project.join("artifact"), b"only copy").unwrap();
        fs::write(outside.join("artifact"), b"unrelated existing file").unwrap();
        let record = store.quarantine(&project.join("artifact"), "held", 9, Duration::ZERO, None).unwrap();
        let result = restore_with_hook(&store, "held", true, &mut |step| {
            if step == TransactionStep::Prepared {
                fs::rename(&project, &saved).unwrap();
                symlink(&outside, &project).unwrap();
            }
        });
        assert!(result.is_err());
        assert_eq!(fs::read(&record.quarantine_path).unwrap(), b"only copy");
        assert_eq!(fs::read(outside.join("artifact")).unwrap(), b"unrelated existing file");
        assert!(!outside.join("artifact.restored-held").exists());
        assert!(!saved.join("artifact").exists());
        assert_eq!(store.record("held").unwrap(), Some(record));
    }

    #[test]
    fn restore_finalization_preserves_replacement_store_records() {
        let temp = tempfile::tempdir().unwrap();
        let (store, record) = held(temp.path());
        let saved = temp.path().join("restored-store");
        let outcome = restore_with_hook(&store, "held", false, &mut |step| {
            if step == TransactionStep::Moved {
                fs::rename(store.root(), &saved).unwrap();
                fs::create_dir_all(store.root().join("held")).unwrap();
                for name in ["held.json", "held.pending", "held.stuck", "held/keep"] {
                    fs::write(store.root().join(name), name.as_bytes()).unwrap();
                }
            }
        }).unwrap();
        assert_eq!(outcome.restored_to, record.original_path);
        assert_eq!(fs::read(outcome.restored_to).unwrap(), b"only copy");
        assert!(!saved.join("held.json").exists());
        assert!(!saved.join("held").exists());
        for name in ["held.json", "held.pending", "held.stuck", "held/keep"] {
            assert_eq!(fs::read(store.root().join(name)).unwrap(), name.as_bytes());
        }
    }

    #[test]
    fn an_original_parent_alias_into_quarantine_is_not_a_restore_destination() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let store = QuarantineStore::under(temp.path());
        let project = temp.path().join("project");
        fs::create_dir(&project).unwrap();
        fs::write(project.join("artifact"), b"only copy").unwrap();
        let record = store.quarantine(&project.join("artifact"), "held", 9, Duration::ZERO, None).unwrap();
        let redirected = store.root().join("redirected");
        fs::create_dir(&redirected).unwrap();
        fs::rename(&project, temp.path().join("retained-project")).unwrap();
        symlink(&redirected, &project).unwrap();
        assert!(store.restore("held", true).is_err());
        assert!(!redirected.join("artifact").exists());
        assert_eq!(fs::read(&record.quarantine_path).unwrap(), b"only copy");
        assert_eq!(store.record("held").unwrap(), Some(record));
    }

    #[test]
    fn stable_original_parent_aliases_support_file_and_directory_round_trips() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let actual = temp.path().join("actual");
        let alias = temp.path().join("alias");
        fs::create_dir(&actual).unwrap();
        symlink(&actual, &alias).unwrap();
        let store = QuarantineStore::under(temp.path());
        for directory in [false, true] {
            let name = if directory { "tree" } else { "file" };
            let path = alias.join(name);
            let leaf = if directory {
                fs::create_dir(&path).unwrap();
                path.join("leaf")
            } else {
                path.clone()
            };
            fs::write(&leaf, b"round trip").unwrap();
            let record = store.quarantine(&path, name, 10, Duration::ZERO, None).unwrap();
            assert_eq!(record.original_path, path);
            assert!(!path.exists());
            assert_eq!(store.restore(name, false).unwrap().restored_to, path);
            assert_eq!(fs::read(leaf).unwrap(), b"round trip");
            assert!(store.record(name).unwrap().is_none());
        }
    }
}
