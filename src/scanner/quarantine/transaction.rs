//! Descriptor-relative quarantine transaction bookkeeping.
//!
//! A store lock pins a directory, not its pathname. Reading recovery records or
//! removing them through that pathname after locking can act on a replacement
//! store while the purge itself still operates on the old descriptor. Keep the
//! manifest, payload lookup and finalization in the same opened directory.
//!
//! The lock coordinates cooperating processes. This does not authenticate
//! manifests against a writer with access to the locked directory itself.

use std::ffi::OsStr;
use std::fs::File;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::io;
use std::path::{Component, Path};

use serde::de::DeserializeOwned;

use super::{QuarantineRecord, invalid};
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::scanner::quarantine::QuarantineStore;
    use super::super::{confined_purge, lock_store, purge_with, read_record_at};
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
}
