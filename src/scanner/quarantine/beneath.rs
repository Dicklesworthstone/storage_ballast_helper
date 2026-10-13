//! Open one directory entry beneath an opened parent without following a
//! symlink or crossing a mount.
//!
//! Linux prefers `openat2(RESOLVE_NO_XDEV)`, which also refuses bind mounts of
//! the same device. A seccomp filter can make `openat2` unavailable: systemd's
//! `RestrictSUIDSGID=` cannot inspect its `open_how` argument, so it returns
//! `ENOSYS` for every call, expecting callers to fall back to `openat` (trj and
//! vmi1227854 ran sbh that way; every confined deletion failed with os error
//! 38). The fallback opens with `O_NOFOLLOW` and keeps the descriptor only when
//! `statx` reports the parent's own mount ID, which a bind mount, even of the
//! same device, does not share. Nothing below the entry is read or changed
//! before that check. A kernel that cannot report mount IDs still fails closed.

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;

use rustix::fs::{Mode, OFlags};

/// Open the directory `name` (a single component the caller has validated)
/// beneath `parent`, refusing a symlink or a mount boundary.
pub(super) fn open_dir_beneath(parent: &File, name: &OsStr) -> io::Result<OwnedFd> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{ResolveFlags, openat2};
        match openat2(
            parent,
            name,
            flags,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        ) {
            Err(rustix::io::Errno::NOSYS) => open_dir_beneath_same_mount(parent, name, flags),
            result => result.map_err(Into::into),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(rustix::fs::openat(parent, name, flags, Mode::empty())?)
    }
}

/// The `openat2`-less path: open without following, then require the
/// parent's mount ID.
#[cfg(target_os = "linux")]
fn open_dir_beneath_same_mount(parent: &File, name: &OsStr, flags: OFlags) -> io::Result<OwnedFd> {
    let parent_mount = mount_id(parent)?;
    let fd = rustix::fs::openat(parent, name, flags, Mode::empty())?;
    if mount_id(&fd)? != parent_mount {
        return Err(io::Error::from_raw_os_error(libc::EXDEV));
    }
    Ok(fd)
}

#[cfg(target_os = "linux")]
fn mount_id(fd: impl std::os::fd::AsFd) -> io::Result<u64> {
    use rustix::fs::{AtFlags, StatxFlags, statx};
    let stat = statx(fd, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)?;
    if stat.stx_mask & StatxFlags::MNT_ID.bits() == 0 {
        // Without a mount ID a same-device bind mount is indistinguishable.
        return Err(io::Error::from_raw_os_error(libc::ENOSYS));
    }
    Ok(stat.stx_mnt_id)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use nix::mount::{MntFlags, MsFlags, mount, umount2};
    use std::fs;
    use std::os::unix::fs::{MetadataExt, symlink};

    fn parent(dir: &std::path::Path) -> File {
        File::open(dir).unwrap()
    }

    #[test]
    fn fallback_opens_a_plain_child_directory() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("child")).unwrap();
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let fd = open_dir_beneath_same_mount(&parent(dir.path()), OsStr::new("child"), flags)
            .expect("same-mount child opens");
        let opened = rustix::fs::fstat(&fd).unwrap();
        let expected = rustix::fs::stat(dir.path().join("child")).unwrap();
        assert_eq!(
            (opened.st_dev, opened.st_ino),
            (expected.st_dev, expected.st_ino)
        );
    }

    #[test]
    fn fallback_refuses_a_symlink_and_a_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("real")).unwrap();
        symlink(dir.path().join("real"), dir.path().join("link")).unwrap();
        fs::write(dir.path().join("file"), b"x").unwrap();
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let p = parent(dir.path());
        assert!(open_dir_beneath_same_mount(&p, OsStr::new("link"), flags).is_err());
        assert!(open_dir_beneath_same_mount(&p, OsStr::new("file"), flags).is_err());
    }

    /// A bind mount of the same filesystem keeps the device number but not the
    /// mount ID. Needs root (mount); skipped otherwise.
    #[test]
    fn fallback_refuses_a_same_device_bind_mount() {
        if !nix::unistd::geteuid().is_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let target = dir.path().join("bound");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("precious"), b"outside").unwrap();
        fs::create_dir(&target).unwrap();
        if mount(
            Some(&source),
            &target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .is_err()
        {
            return;
        }
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let outcome = open_dir_beneath_same_mount(&parent(dir.path()), OsStr::new("bound"), flags);
        let same_device =
            fs::metadata(&target).map(|m| m.dev() == fs::metadata(dir.path()).unwrap().dev());
        umount2(&target, MntFlags::MNT_DETACH).unwrap();
        assert!(
            same_device.unwrap(),
            "the bind mount shares the device number"
        );
        let error = outcome.expect_err("a bind mount is a mount boundary");
        assert_eq!(error.raw_os_error(), Some(libc::EXDEV));
        assert_eq!(fs::read(source.join("precious")).unwrap(), b"outside");
    }
}
