//! Open existing paths without following symlinks, with optional mount confinement.
//!
//! `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` does this in one
//! call. systemd's `RestrictSUIDSGID=` cannot inspect openat2's `open_how`
//! argument, so its seccomp filter fails every openat2 with `ENOSYS` (some
//! profiles report `EPERM`) and expects callers to fall back to `openat`. The
//! fallback walks one component at a time with `O_NOFOLLOW`. Absolute opens
//! may cross mounts; descriptor-relative opens require the root's mount ID
//! at every step, refusing even same-device bind mounts. The input contract
//! is checked before either backend. Metadata-only `O_PATH` opens may inspect
//! a final symlink itself, but never follow it or open a special file for I/O.

use std::cell::Cell;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat, openat2};
use rustix::io::Errno;

/// Open `path` (absolute, with only normal components) with `flags`, refusing
/// traversal through any symlink. `NOFOLLOW` and `CLOEXEC` are always added.
/// Creating, truncating and temporary-file opens are refused before any I/O.
pub fn open_without_symlinks(path: &Path, flags: OFlags) -> io::Result<OwnedFd> {
    validate_open(path, flags, true)?;
    let flags = flags | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    resolve(
        openat2_existing(
            CWD,
            path,
            flags,
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        ),
        || walk(path, flags),
    )
}

/// Open an existing path using the kernel's resolution flags. Keeping this
/// syscall boundary shared lets tests exercise actual caller workflows under
/// a denied syscall without installing process-wide seccomp filters.
pub fn openat2_existing(
    parent: impl std::os::fd::AsFd,
    path: &Path,
    flags: OFlags,
    resolve_flags: ResolveFlags,
) -> rustix::io::Result<OwnedFd> {
    #[cfg(test)]
    if let Some(error) = OPENAT2_DENIAL.get() {
        let index = if !resolve_flags.contains(ResolveFlags::BENEATH) {
            0
        } else if flags.contains(OFlags::PATH) {
            1
        } else {
            2
        };
        let mut calls = OPENAT2_DENIED_CALLS.get();
        calls[index] += 1;
        OPENAT2_DENIED_CALLS.set(calls);
        return Err(error);
    }
    openat2(parent, path, flags, Mode::empty(), resolve_flags)
}

#[cfg(test)]
std::thread_local! {
    static OPENAT2_DENIAL: std::cell::Cell<Option<Errno>> = const {
        std::cell::Cell::new(None)
    };
    static OPENAT2_DENIED_CALLS: std::cell::Cell<[usize; 3]> = const {
        std::cell::Cell::new([0; 3])
    };
}

/// Denied absolute, relative metadata and relative data opens in this scope.
/// Integration tests use these counts to catch callers bypassing the seam.
#[cfg(test)]
pub fn denied_openat2_calls() -> [usize; 3] {
    OPENAT2_DENIED_CALLS.get()
}

/// Force a syscall denial on this test thread only, restoring nested scopes
/// and unwinding automatically. No production override exists.
#[cfg(test)]
pub fn with_openat2_denied<T>(error: Errno, body: impl FnOnce() -> T) -> T {
    struct Restore {
        denial: Option<Errno>,
        calls: [usize; 3],
    }

    impl Drop for Restore {
        fn drop(&mut self) {
            OPENAT2_DENIAL.set(self.denial);
            OPENAT2_DENIED_CALLS.set(self.calls);
        }
    }

    let _restore = Restore {
        denial: OPENAT2_DENIAL.replace(Some(error)),
        calls: OPENAT2_DENIED_CALLS.replace([0; 3]),
    };
    body()
}

/// Open an existing relative path beneath `root` without following symlinks
/// or crossing mounts, including same-device file and directory bind mounts.
///
/// `relative` is `.` for the root itself, or normal components separated by
/// single slashes. Empty, absolute, parent, dot-component and trailing-slash
/// spellings are refused. `NOFOLLOW` and `CLOEXEC` are always added. A final
/// `PATH` descriptor can describe a symlink without following it; callers
/// that need a regular file or directory must verify its type.
///
/// The fallback holds each directory and rechecks its original parent/name
/// binding before opening the final entry and before returning it. This is
/// descriptor-anchored resolution, not an atomic pathname snapshot; callers
/// must still revalidate their own live identity and protection evidence.
/// Multi-component paths permit only read/metadata opens. Writable opens are
/// limited to one name beneath the caller's already authorized parent.
pub fn open_beneath_no_symlinks(
    root: &File,
    relative: &Path,
    flags: OFlags,
) -> io::Result<OwnedFd> {
    open_checked(root, relative, flags, &BeneathState::default(), &mut || {
        Ok(())
    })
}

#[derive(Debug, Default)]
struct BeneathState {
    unavailable: Cell<bool>,
    root_mount: Cell<Option<u64>>,
}

/// A fixed directory descriptor and its confined-open capability cache.
/// Keeping the root alive prevents descriptor reuse from lending its cached
/// mount identity to a different root. No directory contents are cached.
#[derive(Debug)]
pub struct BeneathDirectory {
    file: File,
    state: BeneathState,
}

impl BeneathDirectory {
    pub(crate) fn new(file: File) -> Self {
        Self {
            file,
            state: BeneathState::default(),
        }
    }

    pub(crate) fn file(&self) -> &File {
        &self.file
    }

    /// Reuse syscall availability and the pinned root's mount ID across a
    /// metadata traversal. `check` can stop work between component opens and
    /// ancestry checks when a caller's deadline or cancellation expires.
    pub(crate) fn open_checked(
        &self,
        relative: &Path,
        flags: OFlags,
        mut check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<OwnedFd> {
        open_checked(&self.file, relative, flags, &self.state, &mut check)
    }
}

fn open_checked(
    root: &File,
    relative: &Path,
    flags: OFlags,
    state: &BeneathState,
    check: &mut impl FnMut() -> io::Result<()>,
) -> io::Result<OwnedFd> {
    validate_open(relative, flags, false)?;
    check()?;
    let flags = flags | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    if !state.unavailable.get() {
        match openat2_existing(
            root,
            relative,
            flags,
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        ) {
            Ok(fd) => {
                check()?;
                return Ok(fd);
            }
            Err(Errno::NOSYS | Errno::PERM) => state.unavailable.set(true),
            Err(error) => return Err(error.into()),
        }
    }
    check()?;
    let root_mount = if let Some(mount) = state.root_mount.get() {
        mount
    } else {
        let mount = mount_id(root.as_fd())?;
        state.root_mount.set(Some(mount));
        mount
    };
    walk_beneath_checked(root, relative, flags, root_mount, mount_id, check)
}

/// Validate the original bytes, not Path::components' normalized view. A
/// `child/.` or trailing slash changes final-symlink handling on Linux.
fn validate_open(path: &Path, flags: OFlags, absolute: bool) -> io::Result<()> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= libc::PATH_MAX as usize {
        return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
    }
    if flags.intersects(OFlags::CREATE | OFlags::TRUNC) || flags.contains(OFlags::TMPFILE) {
        // TMPFILE includes DIRECTORY, so intersects(TMPFILE) would reject
        // ordinary directory opens too.
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a no-symlink open cannot create or truncate files",
        ));
    }
    if !absolute && bytes.contains(&b'/') && flags.intersects(OFlags::WRONLY | OFlags::RDWR) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a writable confined open requires one authorized child name",
        ));
    }
    let names = if absolute {
        bytes.strip_prefix(b"/").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a no-symlink open requires an absolute path",
            )
        })?
    } else {
        bytes
    };
    if (absolute && names.is_empty()) || (!absolute && names == b".") {
        return Ok(());
    }
    if names
        .split(|byte| *byte == b'/')
        .any(|name| name.is_empty() || name == b"." || name == b".." || name.contains(&0))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a no-symlink open requires normal path components",
        ));
    }
    Ok(())
}

/// Exercise actual descriptor fallback in callers without changing process
/// environment or other test threads. Nested scopes and unwinding restore it.
#[cfg(test)]
pub fn with_openat2_error<T>(error: Errno, run: impl FnOnce() -> T) -> T {
    with_openat2_denied(error, run)
}

/// Only an unavailable openat2 falls back. A refused symlink (ELOOP), a
/// missing file or denied access is the answer, not a reason to retry.
pub fn resolve(
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
    validate_open(path, flags, true)?;
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

/// Search only through held O_PATH directory descriptors. Every opened
/// component must share the root's mount ID, not just its device number.
#[cfg(test)]
pub fn walk_beneath_with_mount_id(
    root: &File,
    relative: &Path,
    flags: OFlags,
    lookup: fn(BorrowedFd<'_>) -> io::Result<u64>,
) -> io::Result<OwnedFd> {
    validate_open(relative, flags, false)?;
    walk_beneath_checked(
        root,
        relative,
        flags,
        lookup(root.as_fd())?,
        lookup,
        &mut || Ok(()),
    )
}

fn walk_beneath_checked(
    root: &File,
    relative: &Path,
    flags: OFlags,
    root_mount: u64,
    lookup: fn(BorrowedFd<'_>) -> io::Result<u64>,
    check: &mut impl FnMut() -> io::Result<()>,
) -> io::Result<OwnedFd> {
    let flags = flags | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    // One validated child name is already a single atomic lookup relative
    // to the caller's pinned parent. No intermediate directory can move
    // outside that authority. Preserve the original quarantine/repair cost;
    // mutation callers still revalidate the name before writing or unlinking.
    if !relative.as_os_str().as_bytes().contains(&b'/') {
        check()?;
        let fd = openat(root, relative, flags, Mode::empty())?;
        if lookup(fd.as_fd())? != root_mount {
            return Err(io::Error::from_raw_os_error(libc::EXDEV));
        }
        check()?;
        return Ok(fd);
    }
    let names: Vec<_> = relative
        .as_os_str()
        .as_bytes()
        .split(|byte| *byte == b'/')
        .map(OsStr::from_bytes)
        .collect();
    let (last, parents) = names
        .split_last()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing relative path"))?;
    let directory_flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut held = Vec::with_capacity(parents.len());
    for name in parents {
        check()?;
        let parent = held
            .last()
            .map_or_else(|| root.as_fd(), |(_, fd): &(&OsStr, OwnedFd)| fd.as_fd());
        let child = openat(parent, *name, directory_flags, Mode::empty())?;
        if lookup(child.as_fd())? != root_mount {
            return Err(io::Error::from_raw_os_error(libc::EXDEV));
        }
        held.push((*name, child));
    }
    verify_ancestry(root, &held, root_mount, lookup, check)?;
    let parent = held
        .last()
        .map_or_else(|| root.as_fd(), |(_, fd)| fd.as_fd());
    check()?;
    let opened = openat(parent, *last, flags, Mode::empty())?;
    if lookup(opened.as_fd())? != root_mount {
        return Err(io::Error::from_raw_os_error(libc::EXDEV));
    }
    verify_ancestry(root, &held, root_mount, lookup, check)?;
    verify_binding(parent, last, opened.as_fd(), root_mount, lookup, check)?;
    check()?;
    Ok(opened)
}

fn verify_ancestry(
    root: &File,
    held: &[(&OsStr, OwnedFd)],
    root_mount: u64,
    lookup: fn(BorrowedFd<'_>) -> io::Result<u64>,
    check: &mut impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    let mut parent = root.as_fd();
    for (name, directory) in held {
        verify_binding(parent, name, directory.as_fd(), root_mount, lookup, check)?;
        parent = directory.as_fd();
    }
    Ok(())
}

fn verify_binding(
    parent: BorrowedFd<'_>,
    name: &OsStr,
    expected: BorrowedFd<'_>,
    root_mount: u64,
    lookup: fn(BorrowedFd<'_>) -> io::Result<u64>,
    check: &mut impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    check()?;
    let current = openat(
        parent,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    if lookup(current.as_fd())? != root_mount {
        return Err(io::Error::from_raw_os_error(libc::EXDEV));
    }
    let original = rustix::fs::fstat(expected)?;
    let current = rustix::fs::fstat(current)?;
    if original.st_dev != current.st_dev
        || original.st_ino != current.st_ino
        || rustix::fs::FileType::from_raw_mode(original.st_mode)
            != rustix::fs::FileType::from_raw_mode(current.st_mode)
    {
        return Err(io::Error::from_raw_os_error(libc::EAGAIN));
    }
    Ok(())
}

/// Read a pinned descriptor's mount identity using verified kernel evidence.
pub fn mount_id(fd: BorrowedFd<'_>) -> io::Result<u64> {
    use rustix::fs::{AtFlags, StatxFlags, statx};
    let primary = statx(fd, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)
        .map(|stat| (stat.stx_mask & StatxFlags::MNT_ID.bits() != 0).then_some(stat.stx_mnt_id))
        .map_err(Into::into);
    resolve_mount_id(primary, || proc_mount_id(fd))
}

/// An absent statx field and syscall/feature denial are the only failures
/// for which another kernel interface may establish the mount identity.
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

/// fdinfo's mnt_id matches STATX_MNT_ID, not STATX_MNT_ID_UNIQUE. The borrowed
/// descriptor pins its lifetime; thread-self follows this thread's fd table.
pub fn proc_mount_id(fd: BorrowedFd<'_>) -> io::Result<u64> {
    use std::os::fd::AsRawFd;

    let path = format!("/proc/thread-self/fdinfo/{}", fd.as_raw_fd());
    let info = File::from(rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    read_proc_mount_id(info)
}

fn read_proc_mount_id(info: File) -> io::Result<u64> {
    use rustix::fs::{PROC_SUPER_MAGIC, fstatfs};
    use std::io::Read;

    const MAX_FDINFO_BYTES: usize = 16_384;

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
        if result.is_some() || value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::fs::{self, File};
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::path::PathBuf;

    fn read(fd: OwnedFd) -> String {
        let mut text = String::new();
        File::from(fd).read_to_string(&mut text).unwrap();
        text
    }

    #[test]
    fn syscall_denial_scope_is_nested_thread_local_and_unwind_safe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().canonicalize().unwrap().join("plain");
        fs::write(&path, "kept").unwrap();
        with_openat2_denied(Errno::ACCESS, || {
            assert_eq!(
                open_without_symlinks(&path, OFlags::RDONLY)
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EACCES),
            );
            assert_eq!(denied_openat2_calls(), [1, 0, 0]);
            with_openat2_denied(Errno::NOSYS, || {
                assert_eq!(
                    read(open_without_symlinks(&path, OFlags::RDONLY).unwrap()),
                    "kept",
                );
            });
            assert_eq!(OPENAT2_DENIAL.get(), Some(Errno::ACCESS));

            assert_eq!(denied_openat2_calls(), [1, 0, 0]);
            let other_path = path.clone();
            let other = std::thread::spawn(move || {
                read(open_without_symlinks(&other_path, OFlags::RDONLY).unwrap())
            });
            assert_eq!(other.join().unwrap(), "kept");

            let panicked = std::panic::catch_unwind(|| {
                with_openat2_denied(Errno::PERM, || panic!("test scope unwind"));
            });
            assert!(panicked.is_err());
            assert_eq!(OPENAT2_DENIAL.get(), Some(Errno::ACCESS));
        });
        assert!(OPENAT2_DENIAL.get().is_none());
        assert_eq!(
            read(open_without_symlinks(&path, OFlags::RDONLY).unwrap()),
            "kept",
        );
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

    #[test]
    fn unavailable_openat2_reads_nested_files_and_the_pinned_root() {
        let temp = tempfile::tempdir().unwrap();
        let path = fs::canonicalize(temp.path()).unwrap();
        fs::create_dir_all(path.join("one/two")).unwrap();
        fs::write(path.join("one/two/data"), "reserve").unwrap();
        let root = File::open(&path).unwrap();
        for error in [Errno::NOSYS, Errno::PERM] {
            with_openat2_error(error, || {
                assert_eq!(
                    read(
                        open_without_symlinks(&path.join("one/two/data"), OFlags::RDONLY).unwrap()
                    ),
                    "reserve"
                );
                assert_eq!(
                    read(
                        open_beneath_no_symlinks(&root, Path::new("one/two/data"), OFlags::RDONLY)
                            .unwrap()
                    ),
                    "reserve"
                );
                let opened = File::from(
                    open_beneath_no_symlinks(
                        &root,
                        Path::new("."),
                        OFlags::PATH | OFlags::DIRECTORY,
                    )
                    .unwrap(),
                );
                assert_eq!(
                    opened.metadata().unwrap().ino(),
                    root.metadata().unwrap().ino()
                );
            });
        }
    }

    #[test]
    fn a_retained_root_remembers_syscall_denial_without_caching_directory_contents() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("child")).unwrap();
        fs::write(temp.path().join("child/data"), "initial").unwrap();
        for denial in [Errno::NOSYS, Errno::PERM] {
            let root = BeneathDirectory::new(File::open(temp.path()).unwrap());
            let open = || root.open_checked(Path::new("child/data"), OFlags::RDONLY, || Ok(()));
            with_openat2_error(denial, || assert!(open().is_ok()));
            fs::write(temp.path().join("child/data"), "current").unwrap();
            with_openat2_error(Errno::IO, || {
                // EIO must stop a native open, but this root already learned
                // to use the fallback. A fresh root must still try native I/O.
                assert_eq!(read(open().unwrap()), "current");
                let fresh = BeneathDirectory::new(File::open(temp.path()).unwrap());
                let error = fresh
                    .open_checked(Path::new("child/data"), OFlags::RDONLY, || Ok(()))
                    .unwrap_err();
                assert_eq!(error.raw_os_error(), Some(libc::EIO));
            });
        }
    }

    #[test]
    fn a_traversal_budget_can_stop_after_a_component_or_before_returning_the_final_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = fs::canonicalize(temp.path()).unwrap();
        fs::create_dir_all(path.join("one/two")).unwrap();
        fs::write(path.join("one/two/data"), "keep").unwrap();
        let root = BeneathDirectory::new(File::open(&path).unwrap());
        for stop_at in [path.join("one"), path.join("one/two/data")] {
            let stopped = Cell::new(false);
            let error = with_openat2_error(Errno::NOSYS, || {
                root.open_checked(Path::new("one/two/data"), OFlags::RDONLY, || {
                    // Observe actual held descriptors, not an expected count
                    // of internal callbacks. Stop once traversal reaches the
                    // first descendant or has opened the final entry.
                    let reached = fs::read_dir("/proc/thread-self/fd")?
                        .flatten()
                        .any(|entry| {
                            fs::read_link(entry.path()).is_ok_and(|opened| opened == stop_at)
                        });
                    if reached {
                        stopped.set(true);
                        Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "observation budget expired",
                        ))
                    } else {
                        Ok(())
                    }
                })
            })
            .unwrap_err();
            assert!(
                stopped.get(),
                "budget did not observe {}",
                stop_at.display()
            );
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        }
        // A paused observation closes its temporary handles and does not
        // corrupt the capability cache or prevent a later authorized probe.
        let file = root
            .open_checked(Path::new("one/two/data"), OFlags::RDONLY, || Ok(()))
            .unwrap();
        assert_eq!(read(file), "keep");
    }

    #[test]
    fn final_path_descriptors_inspect_symlinks_and_fifos_without_following_or_reading() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("child")).unwrap();
        fs::write(temp.path().join("child/data"), "keep").unwrap();
        symlink("data", temp.path().join("child/link")).unwrap();
        symlink("child", temp.path().join("alias")).unwrap();
        nix::unistd::mkfifo(
            &temp.path().join("child/fifo"),
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        let root = File::open(temp.path()).unwrap();
        for error in [Errno::NOSYS, Errno::PERM] {
            with_openat2_error(error, || {
                for (path, expected) in [
                    ("child/link", rustix::fs::FileType::Symlink),
                    ("child/fifo", rustix::fs::FileType::Fifo),
                ] {
                    let fd =
                        open_beneath_no_symlinks(&root, Path::new(path), OFlags::PATH).unwrap();
                    assert_eq!(
                        rustix::fs::FileType::from_raw_mode(rustix::fs::fstat(fd).unwrap().st_mode),
                        expected,
                    );
                }
                for path in ["alias/data", "child/link"] {
                    assert!(
                        open_beneath_no_symlinks(&root, Path::new(path), OFlags::RDONLY).is_err()
                    );
                }
                assert!(
                    open_beneath_no_symlinks(&root, Path::new("child/fifo/data"), OFlags::PATH,)
                        .is_err()
                );
            });
        }
        assert_eq!(fs::read(temp.path().join("child/data")).unwrap(), b"keep");
    }

    #[test]
    fn both_backends_reject_unsafe_raw_paths_and_open_modes_before_syscalls() {
        let temp = tempfile::tempdir().unwrap();
        let path = fs::canonicalize(temp.path()).unwrap();
        let root = File::open(&path).unwrap();
        fs::create_dir(path.join("child")).unwrap();
        fs::write(path.join("child/data"), "keep").unwrap();
        // EIO proves a rejected argument never reaches even the primary
        // syscall; ENOSYS/PERM exercise the same contract under a filter.
        for error in [Errno::IO, Errno::NOSYS, Errno::PERM] {
            with_openat2_error(error, || {
                for relative in [
                    "",
                    "/child/data",
                    "../child/data",
                    "child/../data",
                    "./child/data",
                    "child/./data",
                    "child//data",
                    "child/data/",
                    "child/data/.",
                    "nul\0tail",
                ] {
                    assert_eq!(
                        open_beneath_no_symlinks(&root, Path::new(relative), OFlags::PATH)
                            .unwrap_err()
                            .kind(),
                        io::ErrorKind::InvalidInput,
                        "{relative:?}",
                    );
                }
                for suffix in [
                    "child/../data",
                    "child/./data",
                    "child//data",
                    "child/data/",
                ] {
                    assert_eq!(
                        open_without_symlinks(&path.join(suffix), OFlags::RDONLY)
                            .unwrap_err()
                            .kind(),
                        io::ErrorKind::InvalidInput,
                        "{suffix:?}",
                    );
                }
                for flags in [OFlags::TRUNC, OFlags::CREATE, OFlags::TMPFILE] {
                    assert_eq!(
                        open_without_symlinks(&path.join("child/data"), flags)
                            .unwrap_err()
                            .kind(),
                        io::ErrorKind::InvalidInput,
                    );
                    assert_eq!(
                        open_beneath_no_symlinks(&root, Path::new("child"), flags)
                            .unwrap_err()
                            .kind(),
                        io::ErrorKind::InvalidInput,
                    );
                }
                for flags in [OFlags::RDWR, OFlags::WRONLY] {
                    assert_eq!(
                        open_beneath_no_symlinks(&root, Path::new("child/data"), flags)
                            .unwrap_err()
                            .kind(),
                        io::ErrorKind::InvalidInput,
                    );
                }
            });
        }
        assert_eq!(fs::read(path.join("child/data")).unwrap(), b"keep");
    }

    #[test]
    fn kernel_path_length_limit_is_preserved_before_either_backend() {
        let dir = tempfile::tempdir().unwrap();
        let root = BeneathDirectory::new(File::open(dir.path()).unwrap());
        let relative = "x".repeat(libc::PATH_MAX as usize);
        let absolute = format!("/{relative}");
        for denial in [Errno::IO, Errno::NOSYS, Errno::PERM] {
            with_openat2_denied(denial, || {
                for result in [
                    open_without_symlinks(Path::new(&absolute), OFlags::PATH),
                    open_beneath_no_symlinks(root.file(), Path::new(&relative), OFlags::PATH),
                    root.open_checked(Path::new(&relative), OFlags::PATH, || Ok(())),
                ] {
                    assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::ENAMETOOLONG));
                }
                assert_eq!(denied_openat2_calls(), [0; 3]);
            });
        }
    }

    #[test]
    fn relative_fallback_refuses_real_mount_boundaries_without_privileges() {
        let root = File::open("/").unwrap();
        let proc = File::open("/proc").unwrap();
        assert_ne!(
            mount_id(root.as_fd()).unwrap(),
            mount_id(proc.as_fd()).unwrap()
        );
        for error in [Errno::NOSYS, Errno::PERM] {
            with_openat2_error(error, || {
                for path in ["proc", "proc/version"] {
                    let refusal =
                        open_beneath_no_symlinks(&root, Path::new(path), OFlags::PATH).unwrap_err();
                    assert_eq!(refusal.raw_os_error(), Some(libc::EXDEV), "{path}");
                }
            });
        }
    }

    struct MoveDuringLookup {
        inode: u64,
        from: PathBuf,
        to: PathBuf,
        fired: bool,
    }

    thread_local! {
        static MOVE_DURING_LOOKUP: RefCell<Option<MoveDuringLookup>> = const { RefCell::new(None) };
    }

    fn moving_lookup(fd: BorrowedFd<'_>) -> io::Result<u64> {
        let id = mount_id(fd)?;
        let metadata = rustix::fs::fstat(fd)?;
        MOVE_DURING_LOOKUP.with_borrow_mut(|movement| {
            if let Some(movement) = movement
                && !movement.fired
                && metadata.st_ino == movement.inode
            {
                fs::rename(&movement.from, &movement.to)?;
                fs::create_dir_all(movement.from.join("two"))?;
                fs::write(movement.from.join("two/data"), "replacement")?;
                movement.fired = true;
            }
            Ok::<_, io::Error>(())
        })?;
        Ok(id)
    }

    #[test]
    fn moved_out_ancestors_cannot_lend_authority_to_nested_reads() {
        for move_at in ["one", "one/two/data"] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("root");
            fs::create_dir_all(path.join("one/two")).unwrap();
            fs::write(path.join("one/two/data"), "original").unwrap();
            let root = File::open(&path).unwrap();
            MOVE_DURING_LOOKUP.set(Some(MoveDuringLookup {
                inode: fs::metadata(path.join(move_at)).unwrap().ino(),
                from: path.join("one"),
                to: temp.path().join("moved"),
                fired: false,
            }));
            let result = walk_beneath_with_mount_id(
                &root,
                Path::new("one/two/data"),
                OFlags::RDONLY,
                moving_lookup,
            );
            let movement = MOVE_DURING_LOOKUP.take().unwrap();
            assert!(movement.fired, "rename hook did not execute at {move_at}");
            assert_eq!(
                result.unwrap_err().raw_os_error(),
                Some(libc::EAGAIN),
                "{move_at}"
            );
            assert_eq!(fs::read(movement.to.join("two/data")).unwrap(), b"original");
            assert_eq!(fs::read(path.join("one/two/data")).unwrap(), b"replacement");
        }
    }

    #[test]
    fn unavailable_mount_evidence_does_not_open_any_child() {
        fn denied(_: BorrowedFd<'_>) -> io::Result<u64> {
            Err(io::Error::from_raw_os_error(libc::EACCES))
        }
        let temp = tempfile::tempdir().unwrap();
        let root = File::open(temp.path()).unwrap();
        // The missing path would return ENOENT if path lookup occurred first.
        let error =
            walk_beneath_with_mount_id(&root, Path::new("missing/child"), OFlags::PATH, denied)
                .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EACCES));
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
        for errno in [
            libc::EBADF,
            libc::EIO,
            libc::ENOMEM,
            libc::EFAULT,
            libc::ENOENT,
        ] {
            let error = resolve_mount_id(Err(io::Error::from_raw_os_error(errno)), || {
                panic!("definitive errors must not fall back")
            })
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(errno));
        }
    }

    #[test]
    fn unavailable_proc_evidence_still_fails_closed() {
        let error = resolve_mount_id(Ok(None), || Err(io::Error::from_raw_os_error(libc::EACCES)))
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
        assert_eq!(
            proc_mount_id(File::open(dir.path()).unwrap().as_fd()).unwrap(),
            id
        );
    }
}
