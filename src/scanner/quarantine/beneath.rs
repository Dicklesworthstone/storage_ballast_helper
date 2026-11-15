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
//!
//! The fallback is also used when a seccomp profile reports `EPERM` instead
//! of `ENOSYS`. Every backend enforces the same single-component, no-follow,
//! non-creating/non-truncating input contract before opening anything.

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(not(target_os = "linux"))]
use rustix::fs::Mode;
use rustix::fs::OFlags;

#[cfg(all(target_os = "linux", any(test, feature = "daemon")))]
pub use crate::platform::linux::no_symlinks::mount_id;

/// Open the directory `name` (one normal path component)
/// beneath `parent`, refusing a symlink or a mount boundary.
pub(super) fn open_dir_beneath(parent: &File, name: &OsStr) -> io::Result<OwnedFd> {
    open_beneath(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
    )
}

/// Open an existing entry `name` beneath `parent`, refusing a symlink or a
/// mount boundary, a same-device bind mount included on Linux.
///
/// `name` must be one normal path component. `flags` must include `NOFOLLOW`
/// and must not create, truncate, or request a symlink descriptor. Invalid
/// inputs are refused before any filesystem access, in release builds too.
pub fn open_beneath(parent: &File, name: &OsStr, flags: OFlags) -> io::Result<OwnedFd> {
    validate_open(name, flags)?;
    #[cfg(target_os = "linux")]
    {
        crate::platform::linux::no_symlinks::open_beneath_no_symlinks(
            parent,
            Path::new(name),
            flags,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(rustix::fs::openat(parent, name, flags, Mode::empty())?)
    }
}

/// Unlike `openat2`, `openat(O_NOFOLLOW)` only protects the last component.
/// Never normalize a caller's path: even `child/` or `child/.` can change
/// symlink handling. Reject the original bytes, including NUL, before open.
fn validate_open(name: &OsStr, flags: OFlags) -> io::Result<()> {
    let bytes = name.as_encoded_bytes();
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
        || bytes.contains(&0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "confined open requires one normal path component",
        ));
    }
    if !flags.contains(OFlags::NOFOLLOW) || flags.intersects(OFlags::CREATE | OFlags::TRUNC) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "confined open requires NOFOLLOW and cannot create or truncate",
        ));
    }
    #[cfg(target_os = "linux")]
    if flags.contains(OFlags::TMPFILE) || flags.contains(OFlags::PATH) {
        // TMPFILE includes DIRECTORY: testing intersects(TMPFILE) would
        // incorrectly reject every ordinary directory open. PATH|NOFOLLOW
        // can return a descriptor to the symlink itself instead of refusing it.
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "confined open cannot create temporary files or open symlink descriptors",
        ));
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::platform::linux::no_symlinks::{
        open_beneath_no_symlinks, proc_mount_id, resolve as resolve_open,
        walk_beneath_with_mount_id,
    };
    use nix::mount::{MntFlags, MsFlags, mount, umount2};
    use std::fs;
    use std::os::fd::{AsFd, BorrowedFd};
    use std::os::unix::fs::{MetadataExt, symlink};

    fn open_beneath_same_mount(parent: &File, name: &OsStr, flags: OFlags) -> io::Result<OwnedFd> {
        open_beneath_with_mount_id(parent, name, flags, mount_id)
    }

    fn open_beneath_with_mount_id(
        parent: &File,
        name: &OsStr,
        flags: OFlags,
        lookup: fn(BorrowedFd<'_>) -> io::Result<u64>,
    ) -> io::Result<OwnedFd> {
        validate_open(name, flags)?;
        walk_beneath_with_mount_id(parent, Path::new(name), flags, lookup)
    }

    fn parent(dir: &std::path::Path) -> File {
        File::open(dir).unwrap()
    }

    #[test]
    fn denied_openat2_keeps_nested_metadata_and_read_opens_confined() {
        use crate::platform::linux::no_symlinks::with_openat2_denied;
        use std::os::unix::fs::FileTypeExt;

        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("nested/child")).unwrap();
        fs::write(dir.path().join("nested/child/file"), b"inside").unwrap();
        nix::unistd::mkfifo(
            &dir.path().join("nested/pipe"),
            nix::sys::stat::Mode::S_IRUSR,
        )
        .unwrap();
        let p = parent(dir.path());
        let metadata = OFlags::PATH | OFlags::NOFOLLOW;
        let readonly = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK;

        for denial in [rustix::io::Errno::NOSYS, rustix::io::Errno::PERM] {
            with_openat2_denied(denial, || {
                let root = File::from(
                    open_beneath_no_symlinks(&p, std::path::Path::new("."), metadata).unwrap(),
                );
                assert_eq!(root.metadata().unwrap().ino(), p.metadata().unwrap().ino());

                let mut opened = File::from(
                    open_beneath_no_symlinks(
                        &p,
                        std::path::Path::new("nested/child/file"),
                        readonly,
                    )
                    .unwrap(),
                );
                assert_eq!(opened.metadata().unwrap().len(), 6);
                let mut text = String::new();
                std::io::Read::read_to_string(&mut opened, &mut text).unwrap();
                assert_eq!(text, "inside");
                let child = File::from(
                    open_beneath_no_symlinks(
                        &p,
                        std::path::Path::new("nested/child"),
                        readonly | OFlags::DIRECTORY,
                    )
                    .unwrap(),
                );
                assert!(child.metadata().unwrap().is_dir());

                // O_PATH must inspect a FIFO without opening its payload or
                // waiting for a writer.
                let pipe = File::from(
                    open_beneath_no_symlinks(&p, std::path::Path::new("nested/pipe"), metadata)
                        .unwrap(),
                );
                assert!(pipe.metadata().unwrap().file_type().is_fifo());
            });
        }
    }

    #[test]
    fn denied_openat2_never_follows_a_leaf_or_ancestor_symlink() {
        use crate::platform::linux::no_symlinks::with_openat2_denied;

        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("nested")).unwrap();
        fs::write(outside.path().join("precious"), b"outside").unwrap();
        symlink(outside.path(), dir.path().join("alias")).unwrap();
        symlink(
            outside.path().join("precious"),
            dir.path().join("nested/link"),
        )
        .unwrap();
        let p = parent(dir.path());
        for denial in [rustix::io::Errno::NOSYS, rustix::io::Errno::PERM] {
            with_openat2_denied(denial, || {
                // The shared metadata API may observe the final symlink
                // itself, but it must neither follow nor read its target.
                let leaf = File::from(
                    open_beneath_no_symlinks(&p, std::path::Path::new("nested/link"), OFlags::PATH)
                        .unwrap(),
                );
                assert!(leaf.metadata().unwrap().file_type().is_symlink());
                let leaf = open_beneath_no_symlinks(
                    &p,
                    std::path::Path::new("nested/link"),
                    OFlags::RDONLY | OFlags::NONBLOCK,
                )
                .unwrap_err();
                assert_eq!(leaf.raw_os_error(), Some(libc::ELOOP));
                for flags in [
                    OFlags::PATH | OFlags::NOFOLLOW,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                ] {
                    let ancestor =
                        open_beneath_no_symlinks(&p, std::path::Path::new("alias/precious"), flags)
                            .unwrap_err();
                    assert_eq!(ancestor.raw_os_error(), Some(libc::ENOTDIR));
                }
            });
        }
        assert_eq!(
            fs::read(outside.path().join("precious")).unwrap(),
            b"outside"
        );
    }

    #[test]
    fn confined_path_inputs_are_rejected_before_either_backend() {
        use crate::platform::linux::no_symlinks::with_openat2_denied;
        use std::path::Path;

        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("slot"), b"keep").unwrap();
        let p = parent(dir.path());
        let flags = OFlags::PATH | OFlags::NOFOLLOW;
        let check = || {
            for path in [
                "",
                "..",
                "/slot",
                "child/../slot",
                "child/./slot",
                "child//slot",
                "child/",
                "./slot",
                "slot\0tail",
            ] {
                assert_eq!(
                    open_beneath_no_symlinks(&p, Path::new(path), flags)
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::InvalidInput,
                    "{path:?}",
                );
            }
            for mode in [
                flags | OFlags::CREATE,
                flags | OFlags::TRUNC,
                flags | OFlags::TMPFILE,
            ] {
                assert_eq!(
                    open_beneath_no_symlinks(&p, Path::new("slot"), mode)
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::InvalidInput,
                );
            }
            // Quarantine/repair intentionally permits a writable handle to
            // one authorized child, but multi-component inspection cannot.
            for mode in [OFlags::WRONLY, OFlags::RDWR] {
                assert_eq!(
                    open_beneath_no_symlinks(&p, Path::new("child/slot"), mode)
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::InvalidInput,
                );
            }
        };
        check();
        // A definitive primary denial also proves validation happens before
        // the primary syscall, not only in the fallback.
        with_openat2_denied(rustix::io::Errno::ACCESS, check);
        with_openat2_denied(rustix::io::Errno::NOSYS, check);
        assert_eq!(fs::read(dir.path().join("slot")).unwrap(), b"keep");
    }

    #[test]
    fn denied_openat2_preserves_root_pinning_after_a_path_replacement() {
        use crate::platform::linux::no_symlinks::with_openat2_denied;
        use std::path::Path;

        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("root");
        let moved = dir.path().join("moved");
        let outside = dir.path().join("outside");
        fs::create_dir(&original).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(original.join("file"), b"inside").unwrap();
        fs::write(outside.join("file"), b"outside").unwrap();
        let p = parent(&original);
        fs::rename(&original, &moved).unwrap();
        symlink(&outside, &original).unwrap();
        with_openat2_denied(rustix::io::Errno::NOSYS, || {
            let opened = File::from(
                open_beneath_no_symlinks(&p, Path::new("file"), OFlags::PATH | OFlags::NOFOLLOW)
                    .unwrap(),
            );
            assert_eq!(
                opened.metadata().unwrap().ino(),
                fs::metadata(moved.join("file")).unwrap().ino(),
            );
            assert_ne!(
                opened.metadata().unwrap().ino(),
                fs::metadata(outside.join("file")).unwrap().ino(),
            );
        });
    }

    #[test]
    fn fallback_rejects_an_ancestor_moved_outside_the_pinned_root() {
        use std::cell::RefCell;
        use std::path::Path;

        thread_local! {
            static MOVE: RefCell<Option<(u64, std::path::PathBuf, std::path::PathBuf)>> =
                const { RefCell::new(None) };
        }
        fn move_after_lookup(fd: BorrowedFd<'_>) -> io::Result<u64> {
            let mount = mount_id(fd)?;
            let inode = rustix::fs::fstat(fd)?.st_ino;
            MOVE.with_borrow_mut(|pending| {
                if pending
                    .as_ref()
                    .is_some_and(|(expected, _, _)| *expected == inode)
                {
                    let (_, original, outside) = pending.take().unwrap();
                    fs::rename(&original, &outside)?;
                    fs::write(outside.join("introduced-after-rename"), b"outside")?;
                    // Replacing the name must not make the old descriptor's
                    // child look like part of the new authorized directory.
                    fs::create_dir(original)?;
                }
                Ok::<_, io::Error>(())
            })?;
            Ok(mount)
        }

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let outside = dir.path().join("moved");
        fs::create_dir_all(root.join("child")).unwrap();
        let p = parent(&root);
        MOVE.set(Some((
            fs::metadata(root.join("child")).unwrap().ino(),
            root.join("child"),
            outside.clone(),
        )));
        let error = walk_beneath_with_mount_id(
            &p,
            Path::new("child/introduced-after-rename"),
            OFlags::PATH | OFlags::NOFOLLOW,
            move_after_lookup,
        )
        .unwrap_err();
        assert!(MOVE.with_borrow(Option::is_none), "rename hook did not run");
        assert_eq!(error.raw_os_error(), Some(libc::EAGAIN));
        assert_eq!(
            fs::read(outside.join("introduced-after-rename")).unwrap(),
            b"outside",
        );
    }

    #[test]
    fn denied_openat2_refuses_a_real_mount_boundary_and_retains_access_errors() {
        use crate::platform::linux::no_symlinks::with_openat2_denied;
        use std::path::Path;

        let root = parent(Path::new("/"));
        let proc = parent(Path::new("/proc"));
        assert_ne!(
            mount_id(root.as_fd()).unwrap(),
            mount_id(proc.as_fd()).unwrap()
        );
        for denial in [rustix::io::Errno::NOSYS, rustix::io::Errno::PERM] {
            with_openat2_denied(denial, || {
                for path in ["proc", "proc/self"] {
                    let error = open_beneath_no_symlinks(
                        &root,
                        Path::new(path),
                        OFlags::PATH | OFlags::NOFOLLOW,
                    )
                    .unwrap_err();
                    assert_eq!(error.raw_os_error(), Some(libc::EXDEV));
                }
            });
        }
        with_openat2_denied(rustix::io::Errno::ACCESS, || {
            let error =
                open_beneath_no_symlinks(&root, Path::new("."), OFlags::PATH | OFlags::NOFOLLOW)
                    .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EACCES));
        });
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
        let path_outcome = walk_beneath_with_mount_id(
            &parent(dir.path()),
            std::path::Path::new("slot"),
            OFlags::PATH | OFlags::NOFOLLOW,
            mount_id,
        );
        umount2(&slot, MntFlags::MNT_DETACH).unwrap();
        for result in [outcome, proc_outcome, path_outcome] {
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
        let path_outcome = walk_beneath_with_mount_id(
            &parent(dir.path()),
            std::path::Path::new("bound/precious"),
            OFlags::PATH | OFlags::NOFOLLOW,
            mount_id,
        );
        let same_device =
            fs::metadata(&target).map(|m| m.dev() == fs::metadata(dir.path()).unwrap().dev());
        umount2(&target, MntFlags::MNT_DETACH).unwrap();
        assert!(
            same_device.unwrap(),
            "the bind mount shares the device number"
        );
        for result in [outcome, proc_outcome, path_outcome] {
            let error = result.expect_err("a bind mount is a mount boundary");
            assert_eq!(error.raw_os_error(), Some(libc::EXDEV));
        }
        assert_eq!(fs::read(source.join("precious")).unwrap(), b"outside");
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

    #[test]
    fn both_seccomp_denials_use_the_verified_fallback() {
        for error in [rustix::io::Errno::NOSYS, rustix::io::Errno::PERM] {
            let dir = tempfile::tempdir().unwrap();
            fs::write(dir.path().join("slot"), b"ballast").unwrap();
            let p = parent(dir.path());
            let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let fd = resolve_open(Err(error), || {
                open_beneath_with_mount_id(&p, OsStr::new("slot"), flags, proc_mount_id)
            })
            .expect("denied openat2 still admits a verified same-mount slot");
            assert_eq!(File::from(fd).metadata().unwrap().len(), 7);
        }
    }

    #[test]
    fn resolution_and_access_errors_never_take_the_compatibility_path() {
        for error in [
            rustix::io::Errno::XDEV,
            rustix::io::Errno::LOOP,
            rustix::io::Errno::ACCESS,
            rustix::io::Errno::NOENT,
            rustix::io::Errno::INVAL,
            rustix::io::Errno::IO,
        ] {
            let outcome = resolve_open(Err(error), || panic!("must preserve rejection"));
            assert_eq!(
                outcome.unwrap_err().raw_os_error(),
                Some(error.raw_os_error())
            );
        }
    }

    #[test]
    fn a_successful_primary_open_does_not_use_the_fallback() {
        let file = tempfile::tempfile().unwrap();
        let fd = resolve_open(Ok(file.into()), || panic!("must keep primary descriptor"));
        assert!(fd.is_ok());
    }

    #[test]
    fn a_denied_primary_does_not_hide_a_failed_mount_check() {
        let error = resolve_open(Err(rustix::io::Errno::PERM), || {
            Err(io::Error::from_raw_os_error(libc::EXDEV))
        })
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EXDEV));
    }

    #[test]
    fn fallback_rejects_unsafe_arguments_before_mount_lookup() {
        fn no_lookup(_: BorrowedFd<'_>) -> io::Result<u64> {
            panic!("invalid inputs must be refused before any filesystem access")
        }
        let dir = tempfile::tempdir().unwrap();
        let p = parent(dir.path());
        let normal = OFlags::RDWR | OFlags::NOFOLLOW;
        for (name, flags) in [
            ("../slot", normal),
            ("/slot", normal),
            ("alias/slot", normal),
            ("slot/", normal),
            ("slot", OFlags::RDWR),
            ("slot", normal | OFlags::TRUNC),
            ("slot", normal | OFlags::CREATE),
            ("slot", normal | OFlags::TMPFILE),
            ("slot", normal | OFlags::PATH),
        ] {
            let error =
                open_beneath_with_mount_id(&p, OsStr::new(name), flags, no_lookup).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn linux_special_open_modes_cannot_bypass_admission() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("child")).unwrap();
        symlink("child", dir.path().join("link")).unwrap();
        let p = parent(dir.path());
        for flags in [
            OFlags::NOFOLLOW | OFlags::PATH,
            OFlags::NOFOLLOW | OFlags::RDWR | OFlags::TMPFILE,
        ] {
            for name in ["child", "link"] {
                assert_eq!(
                    open_beneath(&p, OsStr::new(name), flags)
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::InvalidInput
                );
            }
        }
        // TMPFILE overlaps DIRECTORY. The normal directory flag must remain legal.
        assert!(open_dir_beneath(&p, OsStr::new("child")).is_ok());
        assert!(
            fs::read_dir(dir.path().join("child"))
                .unwrap()
                .next()
                .is_none()
        );
    }
}

#[cfg(test)]
mod input_tests {
    use super::*;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;

    #[test]
    fn every_backend_rejects_non_component_names_before_opening() {
        let dir = tempfile::tempdir().unwrap();
        let parent = File::open(dir.path()).unwrap();
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        for name in [
            "",
            ".",
            "..",
            "/",
            "/outside",
            "../outside",
            "child/../outside",
            "child/grandchild",
            "child/",
            "./child",
            "child/.",
            "nul\0tail",
        ] {
            assert_eq!(
                open_beneath(&parent, OsStr::new(name), flags)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput,
                "accepted {name:?}"
            );
        }
    }

    #[test]
    fn a_same_mount_symlink_cannot_supply_an_intermediate_component() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        let inside = dir.path().join("inside");
        fs::create_dir(&outside).unwrap();
        fs::create_dir(&inside).unwrap();
        fs::write(outside.join("precious"), b"keep").unwrap();
        symlink(&outside, inside.join("alias")).unwrap();
        let parent = File::open(&inside).unwrap();
        let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        assert_eq!(
            open_beneath(&parent, OsStr::new("alias/precious"), flags)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(open_beneath(&parent, OsStr::new("alias"), flags).is_err());
        assert_eq!(fs::read(outside.join("precious")).unwrap(), b"keep");
    }

    #[test]
    fn creating_truncating_and_following_flags_never_modify_a_slot() {
        let dir = tempfile::tempdir().unwrap();
        let parent = File::open(dir.path()).unwrap();
        let slot = dir.path().join("slot");
        fs::write(&slot, b"keep ballast").unwrap();
        for flags in [
            OFlags::RDWR,
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::TRUNC,
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CREATE,
        ] {
            for name in ["slot", "missing"] {
                assert_eq!(
                    open_beneath(&parent, OsStr::new(name), flags)
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::InvalidInput
                );
            }
            assert_eq!(fs::read(&slot).unwrap(), b"keep ballast");
            assert!(!dir.path().join("missing").exists());
        }
    }

    #[test]
    fn ordinary_non_utf8_and_dot_names_are_still_valid_entries() {
        let dir = tempfile::tempdir().unwrap();
        let parent = File::open(dir.path()).unwrap();
        let mut names = vec![
            OsStr::new(".hidden"),
            OsStr::new("..."),
            OsStr::new("a..b"),
            OsStr::new("with space"),
        ];
        // APFS refuses names that are not valid UTF-8 (EILSEQ).
        if cfg!(target_os = "linux") {
            names.push(OsStr::from_bytes(b"nonutf8-\xff"));
        }
        for name in names {
            fs::write(dir.path().join(name), b"keep").unwrap();
            let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let fd = open_beneath(&parent, name, flags).expect("normal existing entry opens");
            assert_eq!(File::from(fd).metadata().unwrap().len(), 4);
        }
        fs::create_dir(dir.path().join("child")).unwrap();
        assert!(open_dir_beneath(&parent, OsStr::new("child")).is_ok());
    }
}
