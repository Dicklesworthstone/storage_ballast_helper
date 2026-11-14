//! Open an absolute path that has no symlink in any component.
//!
//! `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` does this in one
//! call. systemd's `RestrictSUIDSGID=` cannot inspect openat2's `open_how`
//! argument, so its seccomp filter fails every openat2 with `ENOSYS` (some
//! profiles report `EPERM`) and expects callers to fall back to `openat`. The
//! fallback walks the path one component at a time with `O_NOFOLLOW`, which
//! refuses a symlink, magic links included, at every step. Like the openat2
//! flags it crosses mount points. It never resolves `.` or `..`: the caller
//! passes a canonical path, and anything else is refused before any open.

use std::io;
use std::os::fd::OwnedFd;
use std::path::{Component, Path};

use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat, openat2};
use rustix::io::Errno;

/// Open `path` (absolute, with only normal components) with `flags`, refusing
/// a symlink in any component. `NOFOLLOW` and `CLOEXEC` are always added.
pub fn open_without_symlinks(path: &Path, flags: OFlags) -> io::Result<OwnedFd> {
    let flags = flags | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    resolve(
        openat2(
            CWD,
            path,
            flags,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        ),
        || walk(path, flags),
    )
}

/// Only an unavailable openat2 falls back. A refused symlink (ELOOP), a
/// missing file or denied access is the answer, not a reason to retry.
fn resolve(
    primary: rustix::io::Result<OwnedFd>,
    fallback: impl FnOnce() -> io::Result<OwnedFd>,
) -> io::Result<OwnedFd> {
    match primary {
        Err(Errno::NOSYS | Errno::PERM) => fallback(),
        result => result.map_err(Into::into),
    }
}

/// The openat2-less path. Each directory is held as an `O_PATH` descriptor
/// (search permission suffices, as for path resolution); `O_DIRECTORY` with
/// `O_NOFOLLOW` makes a symlinked directory fail with `ENOTDIR`, and the last
/// component's `O_NOFOLLOW` makes a symlinked file fail with `ELOOP`.
fn walk(path: &Path, flags: OFlags) -> io::Result<OwnedFd> {
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a no-symlink open requires an absolute path",
        ));
    }
    let names = components
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a no-symlink open requires a canonical path",
            )),
        })
        .collect::<io::Result<Vec<_>>>()?;
    let Some((last, parents)) = names.split_last() else {
        return Ok(openat(CWD, "/", flags, Mode::empty())?);
    };
    let directory_flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = openat(CWD, "/", directory_flags, Mode::empty())?;
    for name in parents {
        directory = openat(&directory, *name, directory_flags, Mode::empty())?;
    }
    Ok(openat(&directory, *last, flags, Mode::empty())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Read;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    fn read(fd: OwnedFd) -> String {
        let mut text = String::new();
        File::from(fd).read_to_string(&mut text).unwrap();
        text
    }

    #[test]
    fn the_fallback_reads_a_symlink_free_path_and_refuses_every_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        fs::create_dir_all(root.join("real/.cargo")).unwrap();
        fs::write(root.join("real/.cargo/config.toml"), "[build]\n").unwrap();
        symlink(root.join("real"), root.join("linked")).unwrap();
        symlink(
            root.join("real/.cargo/config.toml"),
            root.join("real/.cargo/alias.toml"),
        )
        .unwrap();
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;

        let opened = walk(&root.join("real/.cargo/config.toml"), flags).unwrap();
        assert_eq!(read(opened), "[build]\n");
        let directory = walk(&root.join("real/.cargo"), flags | OFlags::DIRECTORY).unwrap();
        assert!(File::from(directory).metadata().unwrap().is_dir());

        let error = walk(&root.join("linked/.cargo/config.toml"), flags).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOTDIR), "{error}");
        let error = walk(&root.join("real/.cargo/alias.toml"), flags).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ELOOP), "{error}");
        let error = walk(&root.join("real/.cargo/missing.toml"), flags).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        // Magic links are symlinks to O_NOFOLLOW as well.
        let exe = PathBuf::from(format!("/proc/{}/exe", std::process::id()));
        let error = walk(&exe, flags).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ELOOP), "{error}");

        for path in ["relative/config.toml", "/tmp/../etc/passwd"] {
            let error = walk(Path::new(path), flags).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{path}");
        }
    }

    /// Only an unavailable openat2 (seccomp: ENOSYS or EPERM) takes the
    /// fallback; a resolution refusal from openat2 itself is final.
    #[test]
    fn only_an_unavailable_openat2_falls_back() {
        for errno in [Errno::NOSYS, Errno::PERM] {
            let error = resolve(Err(errno), || Err(io::Error::other("fallback"))).unwrap_err();
            assert_eq!(error.to_string(), "fallback", "{errno:?}");
        }
        for errno in [Errno::LOOP, Errno::XDEV, Errno::NOENT, Errno::ACCESS] {
            let error = resolve(Err(errno), || panic!("{errno:?} must not fall back")).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(errno.raw_os_error()));
        }
    }

    /// Whatever this kernel and seccomp profile allow, the public entry point
    /// reads a symlink-free path and refuses a symlinked one.
    #[test]
    fn the_entry_point_refuses_symlinks_with_or_without_openat2() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        fs::write(root.join("config.toml"), "x").unwrap();
        symlink(root.join("config.toml"), root.join("alias.toml")).unwrap();
        let opened = open_without_symlinks(&root.join("config.toml"), OFlags::RDONLY).unwrap();
        assert_eq!(read(opened), "x");
        let error = open_without_symlinks(&root.join("alias.toml"), OFlags::RDONLY).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ELOOP), "{error}");
    }
}
