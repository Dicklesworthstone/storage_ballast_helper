//! Open one directory entry beneath an opened parent without following a
//! symlink or crossing a mount.
//!
//! Linux prefers `openat2(RESOLVE_NO_XDEV)`, which also refuses bind mounts of
//! the same device. A seccomp filter can make `openat2` unavailable: systemd's
//! `RestrictSUIDSGID=` cannot inspect its `open_how` argument, so it returns
//! `ENOSYS` for every call, expecting callers to fall back to `openat` (trj and
//! vmi1227854 ran sbh that way; every confined deletion failed with os error
//! 38). The fallback opens with `O_NOFOLLOW` and keeps the descriptor only when
//! the entry has the parent's own mount ID, which a bind mount, even of the
//! same device, does not share. Prefer `statx`; when its mount-ID field is
//! unavailable, use the kernel's `/proc/thread-self/fdinfo` for the still-open
//! descriptor. This also supports pre-5.8 kernels without weakening the check
//! to a device-number comparison. Missing or untrusted evidence fails closed.
//!
//! In-place ballast repair opens a regular file the same way (#28): a
//! same-device file bind mount on a slot would make the repair write through
//! to an external file.

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, BorrowedFd};

use rustix::fs::{Mode, OFlags};

/// Open the directory `name` (a single component the caller has validated)
/// beneath `parent`, refusing a symlink or a mount boundary.
pub(super) fn open_dir_beneath(parent: &File, name: &OsStr) -> io::Result<OwnedFd> {
    open_beneath(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
    )
}

/// Open the entry `name` beneath `parent` with `flags` (which must include
/// `NOFOLLOW`), refusing a symlink or a mount boundary, a same-device bind
/// mount included.
pub fn open_beneath(parent: &File, name: &OsStr, flags: OFlags) -> io::Result<OwnedFd> {
    debug_assert!(flags.contains(OFlags::NOFOLLOW));
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
            Err(rustix::io::Errno::NOSYS) => open_beneath_same_mount(parent, name, flags),
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
fn open_beneath_same_mount(parent: &File, name: &OsStr, flags: OFlags) -> io::Result<OwnedFd> {
    open_beneath_with_mount_id(parent, name, flags, mount_id)
}

#[cfg(target_os = "linux")]
fn open_beneath_with_mount_id(
    parent: &File,
    name: &OsStr,
    flags: OFlags,
    lookup: fn(BorrowedFd<'_>) -> io::Result<u64>,
) -> io::Result<OwnedFd> {
    let parent_mount = lookup(parent.as_fd())?;
    let fd = rustix::fs::openat(parent, name, flags, Mode::empty())?;
    if lookup(fd.as_fd())? != parent_mount {
        return Err(io::Error::from_raw_os_error(libc::EXDEV));
    }
    Ok(fd)
}

#[cfg(target_os = "linux")]
fn mount_id(fd: BorrowedFd<'_>) -> io::Result<u64> {
    use rustix::fs::{AtFlags, StatxFlags, statx};
    let primary = statx(fd, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)
        .map(|stat| (stat.stx_mask & StatxFlags::MNT_ID.bits() != 0).then_some(stat.stx_mnt_id))
        .map_err(Into::into);
    resolve_mount_id(primary, || proc_mount_id(fd))
}

/// Do not turn arbitrary I/O failures into a successful compatibility probe.
/// An absent statx field and syscall/feature-denial errors are the only cases
/// where another kernel interface may establish the missing mount identity.
#[cfg(target_os = "linux")]
fn resolve_mount_id(
    primary: io::Result<Option<u64>>,
    fallback: impl FnOnce() -> io::Result<u64>,
) -> io::Result<u64> {
    match primary {
        Ok(Some(id)) => Ok(id),
        Ok(None) => fallback(),
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP | libc::EPERM | libc::EACCES)
            ) =>
        {
            fallback()
        }
        Err(error) => Err(error),
    }
}

/// fdinfo's mnt_id is the ordinary mount ID, matching STATX_MNT_ID (not
/// STATX_MNT_ID_UNIQUE). Borrowing the descriptor pins its lifetime while the
/// kernel is queried; do not resolve the entry's pathname again. thread-self
/// also selects the calling thread's descriptor table after unshare(CLONE_FILES).
#[cfg(target_os = "linux")]
fn proc_mount_id(fd: BorrowedFd<'_>) -> io::Result<u64> {
    use std::os::fd::AsRawFd;

    let path = format!("/proc/thread-self/fdinfo/{}", fd.as_raw_fd());
    let info = File::from(rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    read_proc_mount_id(info)
}

#[cfg(target_os = "linux")]
fn read_proc_mount_id(info: File) -> io::Result<u64> {
    use rustix::fs::{PROC_SUPER_MAGIC, fstatfs};
    use std::io::Read;

    const MAX_FDINFO_BYTES: usize = 16_384;

    // A replaced/masked /proc must not supply an ordinary file as evidence.
    // Check the opened handle, not a pathname that could change before read.
    if fstatfs(&info)?.f_type != PROC_SUPER_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mount-ID evidence is not from procfs",
        ));
    }
    let mut contents = String::new();
    info.take(MAX_FDINFO_BYTES as u64 + 1)
        .read_to_string(&mut contents)?;
    if contents.len() > MAX_FDINFO_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mount-ID evidence exceeds the fdinfo read budget",
        ));
    }
    parse_proc_mount_id(&contents)
}

#[cfg(target_os = "linux")]
fn parse_proc_mount_id(contents: &str) -> io::Result<u64> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid fdinfo mount ID");
    if !contents.ends_with('\n') {
        return Err(invalid());
    }
    let mut result = None;
    for line in contents.lines() {
        let Some(value) = line.strip_prefix("mnt_id:") else {
            continue;
        };
        let value = value.trim();
        if result.is_some() || value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
        let id = value.parse::<u64>().map_err(|_| invalid())?;
        if id == 0 {
            return Err(invalid());
        }
        result = Some(id);
    }
    result.ok_or_else(invalid)
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
        let fd = open_beneath_same_mount(&parent(dir.path()), OsStr::new("child"), flags)
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
        assert!(open_beneath_same_mount(&p, OsStr::new("link"), flags).is_err());
        assert!(open_beneath_same_mount(&p, OsStr::new("file"), flags).is_err());
    }

    /// #28: ballast repair opens a regular file read-write the same way.
    #[test]
    fn fallback_opens_a_plain_file_and_refuses_a_symlink_to_one() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("slot"), b"ballast").unwrap();
        symlink(dir.path().join("slot"), dir.path().join("link")).unwrap();
        let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let p = parent(dir.path());
        let fd =
            open_beneath_same_mount(&p, OsStr::new("slot"), flags).expect("same-mount file opens");
        let expected = rustix::fs::stat(dir.path().join("slot")).unwrap();
        let opened = rustix::fs::fstat(&fd).unwrap();
        assert_eq!(
            (opened.st_dev, opened.st_ino),
            (expected.st_dev, expected.st_ino)
        );
        assert!(open_beneath_same_mount(&p, OsStr::new("link"), flags).is_err());
    }

    /// A same-device file bind mount on a slot would make an in-place repair
    /// write through to the external file. Needs root (mount); skipped
    /// otherwise.
    #[test]
    fn fallback_refuses_a_same_device_file_bind_mount() {
        if !nix::unistd::geteuid().is_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        let slot = dir.path().join("slot");
        fs::write(&outside, b"external file").unwrap();
        fs::write(&slot, b"ballast").unwrap();
        if mount(
            Some(&outside),
            &slot,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .is_err()
        {
            return;
        }
        let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let outcome = open_beneath_same_mount(&parent(dir.path()), OsStr::new("slot"), flags);
        let proc_outcome = open_beneath_with_mount_id(
            &parent(dir.path()),
            OsStr::new("slot"),
            flags,
            proc_mount_id,
        );
        umount2(&slot, MntFlags::MNT_DETACH).unwrap();
        for result in [outcome, proc_outcome] {
            let error = result.expect_err("a file bind mount is a mount boundary");
            assert_eq!(error.raw_os_error(), Some(libc::EXDEV));
        }
        assert_eq!(fs::read(&outside).unwrap(), b"external file");
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
        let outcome = open_beneath_same_mount(&parent(dir.path()), OsStr::new("bound"), flags);
        let proc_outcome = open_beneath_with_mount_id(
            &parent(dir.path()),
            OsStr::new("bound"),
            flags,
            proc_mount_id,
        );
        let same_device =
            fs::metadata(&target).map(|m| m.dev() == fs::metadata(dir.path()).unwrap().dev());
        umount2(&target, MntFlags::MNT_DETACH).unwrap();
        assert!(
            same_device.unwrap(),
            "the bind mount shares the device number"
        );
        for result in [outcome, proc_outcome] {
            let error = result.expect_err("a bind mount is a mount boundary");
            assert_eq!(error.raw_os_error(), Some(libc::EXDEV));
        }
        assert_eq!(fs::read(source.join("precious")).unwrap(), b"outside");
    }

    #[test]
    fn proc_mount_id_accepts_complete_kernel_records() {
        for contents in [
            "pos:\t0\nflags:\t0100002\nmnt_id:\t19\n",
            "mnt_id: 19\nino: 63107\nlock: ignored future metadata\n",
            "pos: 0\nmnt_id:\t  19  \n",
        ] {
            assert_eq!(parse_proc_mount_id(contents).unwrap(), 19);
        }
    }

    #[test]
    fn proc_mount_id_rejects_missing_ambiguous_and_malformed_evidence() {
        for contents in [
            "",
            "pos: 0\nflags: 0100002\n",
            "mnt_id: 19",
            "mnt_id:\n",
            "mnt_id: 0\n",
            "mnt_id: -19\n",
            "mnt_id: +19\n",
            "mnt_id: 19x\n",
            "mnt_id: 19 20\n",
            "mnt_id: 18446744073709551616\n",
            "mnt_id: 19\nmnt_id: 19\n",
            "mnt_id: 19\nmnt_id: 20\n",
        ] {
            assert_eq!(
                parse_proc_mount_id(contents).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "accepted {contents:?}"
            );
        }
    }

    #[test]
    fn available_statx_evidence_does_not_read_proc() {
        assert_eq!(
            resolve_mount_id(Ok(Some(19)), || panic!("proc must not be consulted")).unwrap(),
            19
        );
    }

    #[test]
    fn missing_statx_field_or_blocked_syscall_uses_proc() {
        assert_eq!(resolve_mount_id(Ok(None), || Ok(19)).unwrap(), 19);
        for errno in [
            libc::ENOSYS,
            libc::EINVAL,
            libc::EOPNOTSUPP,
            libc::EPERM,
            libc::EACCES,
        ] {
            assert_eq!(
                resolve_mount_id(Err(io::Error::from_raw_os_error(errno)), || Ok(19)).unwrap(),
                19
            );
        }
    }

    #[test]
    fn definitive_statx_errors_are_not_hidden_by_proc() {
        for errno in [libc::EBADF, libc::EIO, libc::ENOMEM, libc::EFAULT, libc::ENOENT] {
            let error = resolve_mount_id(Err(io::Error::from_raw_os_error(errno)), || {
                panic!("definitive errors must not fall back")
            })
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(errno));
        }
    }

    #[test]
    fn unavailable_proc_evidence_still_fails_closed() {
        let error = resolve_mount_id(Ok(None), || {
            Err(io::Error::from_raw_os_error(libc::EACCES))
        })
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EACCES));
    }

    #[test]
    fn ordinary_files_cannot_masquerade_as_proc_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("fdinfo");
        fs::write(&fake, "pos: 0\nflags: 0100002\nmnt_id: 19\n").unwrap();
        assert_eq!(
            read_proc_mount_id(File::open(fake).unwrap())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn real_proc_mount_id_agrees_with_statx_and_survives_unlink() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slot");
        fs::write(&path, b"ballast").unwrap();
        let file = File::open(&path).unwrap();
        let id = proc_mount_id(file.as_fd()).unwrap();
        assert_eq!(mount_id(file.as_fd()).unwrap(), id);
        fs::remove_file(&path).unwrap();
        assert_eq!(proc_mount_id(file.as_fd()).unwrap(), id);
        assert_eq!(proc_mount_id(parent(dir.path()).as_fd()).unwrap(), id);
    }

    #[test]
    fn proc_only_fallback_opens_files_and_directories_but_not_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("child")).unwrap();
        fs::write(dir.path().join("slot"), b"ballast").unwrap();
        symlink("child", dir.path().join("link")).unwrap();
        let p = parent(dir.path());
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        for name in ["child", "slot"] {
            let fd = open_beneath_with_mount_id(&p, OsStr::new(name), flags, proc_mount_id)
                .expect("verified same-mount entry opens without statx");
            let opened = rustix::fs::fstat(&fd).unwrap();
            let expected = rustix::fs::stat(dir.path().join(name)).unwrap();
            assert_eq!(
                (opened.st_dev, opened.st_ino),
                (expected.st_dev, expected.st_ino)
            );
        }
        assert!(open_beneath_with_mount_id(&p, OsStr::new("link"), flags, proc_mount_id).is_err());
    }
}
