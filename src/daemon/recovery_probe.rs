//! A small write test on an already-authorized recovery surface.
//!
//! The probe never opens an existing file for writing. Its randomly named
//! workspace is private, and every operation after opening a base is relative
//! to verified directory descriptors. Namespace uncertainty retains the private
//! workspace rather than risking cleanup of somebody else's replacement.

use std::path::Path;

/// Test allocation and writeback on `mount` through one existing authorized
/// directory. Admission sees the pinned canonical base, after opening it and
/// before any write. The base must still have that identity after admission.
/// This never creates missing bases or follows a workspace/leaf symlink.
pub(super) fn probe_writable_surface(
    mount: &Path,
    base: &Path,
    mut admit: impl FnMut(&Path) -> bool,
) -> bool {
    #[cfg(unix)]
    {
        for _ in 0..4 {
            let name = format!(".sbh-recovery-{:032x}", rand::random::<u128>());
            match unix::probe_with_admission(mount, base, &name, &mut admit, &mut |_, _| Ok(())) {
                Ok(()) => return true,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return false,
            }
        }
        false
    }
    #[cfg(not(unix))]
    {
        let _ = (mount, base, &mut admit);
        false
    }
}

#[cfg(unix)]
mod unix {
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, Write};
    #[cfg(target_os = "linux")]
    use std::os::fd::AsFd;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::{Path, PathBuf};

    use rustix::fs::{
        AtFlags, FileType, Mode, OFlags, Stat, fstat, mkdirat, openat, statat, unlinkat,
    };

    const PROBE_BYTES: usize = 4096;
    const LEAF: &str = "write-test";

    fn changed() -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "recovery probe identity changed",
        )
    }

    fn same_identity(left: &Stat, right: &Stat) -> bool {
        left.st_dev == right.st_dev
            && left.st_ino == right.st_ino
            && FileType::from_raw_mode(left.st_mode) == FileType::from_raw_mode(right.st_mode)
    }

    struct Directory {
        original: PathBuf,
        resolved: PathBuf,
        file: File,
        identity: Stat,
        #[cfg(target_os = "linux")]
        mount_id: u64,
    }

    impl Directory {
        fn open(path: &Path) -> io::Result<Self> {
            // Stable configured aliases, including macOS /tmp, are permitted.
            // The resolved directory is then pinned, and both spellings must
            // still name that directory at every mutation boundary.
            let resolved = fs::canonicalize(path)?;
            let file = Self::open_file(&resolved)?;
            let identity = fstat(&file)?;
            if FileType::from_raw_mode(identity.st_mode) != FileType::Directory {
                return Err(changed());
            }
            let directory = Self {
                original: path.to_path_buf(),
                resolved,
                #[cfg(target_os = "linux")]
                mount_id: crate::scanner::quarantine::descriptor_mount_id(file.as_fd())?,
                file,
                identity,
            };
            directory.current()?;
            Ok(directory)
        }

        fn open_file(path: &Path) -> io::Result<File> {
            OpenOptions::new()
                .read(true)
                .custom_flags(
                    libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
                .open(path)
        }

        fn verify_file(&self, file: &File) -> io::Result<()> {
            if !same_identity(&self.identity, &fstat(file)?) {
                return Err(changed());
            }
            #[cfg(target_os = "linux")]
            if crate::scanner::quarantine::descriptor_mount_id(file.as_fd())? != self.mount_id {
                // A bind mount can preserve dev/inode while changing which
                // mount the name refers to, including its read-only state.
                return Err(changed());
            }
            if nix::sys::statvfs::fstatvfs(file)?
                .flags()
                .contains(nix::sys::statvfs::FsFlags::ST_RDONLY)
            {
                return Err(io::Error::from_raw_os_error(libc::EROFS));
            }
            Ok(())
        }

        fn current(&self) -> io::Result<()> {
            let resolved = fs::canonicalize(&self.original)?;
            let named = fs::symlink_metadata(&self.resolved)?;
            if resolved != self.resolved || !named.is_dir() || named.file_type().is_symlink() {
                return Err(changed());
            }
            self.verify_file(&Self::open_file(&self.resolved)?)?;
            self.verify_file(&self.file)?;
            Ok(())
        }
    }

    /// The reservation exists before an opened private workspace does. Its
    /// cleanup can only remove our still-matching, empty directory; errors
    /// obtaining identity or a changed namespace leave it alone.
    struct EmptyReservation<'a> {
        base: &'a Directory,
        name: &'a str,
        identity: &'a Stat,
        armed: bool,
    }

    impl Drop for EmptyReservation<'_> {
        fn drop(&mut self) {
            if self.armed
                && owned_directory(self.identity)
                && self.identity.st_dev == self.base.identity.st_dev
                && self.base.current().is_ok()
                && statat(&self.base.file, self.name, AtFlags::SYMLINK_NOFOLLOW)
                    .is_ok_and(|named| same_identity(self.identity, &named))
            {
                let _ = unlinkat(&self.base.file, self.name, AtFlags::REMOVEDIR);
            }
        }
    }

    struct Workspace {
        base: Directory,
        name: String,
        directory: File,
        identity: Stat,
        leaf: Option<(File, Stat)>,
        removed: bool,
    }

    impl Workspace {
        fn create(base: Directory, name: &str) -> io::Result<Self> {
            Self::create_with_mode(base, name, Mode::RUSR | Mode::WUSR | Mode::XUSR)
        }

        fn create_with_mode(base: Directory, name: &str, mode: Mode) -> io::Result<Self> {
            // mkdirat is exclusive: a file, link, directory or other existing
            // entry with this name is a collision, never a cleanup target.
            base.current()?;
            mkdirat(&base.file, name, mode)?;
            let identity = statat(&base.file, name, AtFlags::SYMLINK_NOFOLLOW)?;
            let mut reservation = EmptyReservation {
                base: &base,
                name,
                identity: &identity,
                armed: true,
            };
            if !private_directory(&identity) || identity.st_dev != base.identity.st_dev {
                return Err(changed());
            }
            let directory = File::from(crate::scanner::quarantine::open_beneath(
                &base.file,
                name.as_ref(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            )?);
            if !same_identity(&identity, &fstat(&directory)?) {
                return Err(changed());
            }
            reservation.armed = false;
            drop(reservation);
            let workspace = Self {
                base,
                name: name.to_string(),
                directory,
                identity,
                leaf: None,
                removed: false,
            };
            workspace.current()?;
            Ok(workspace)
        }

        fn current(&self) -> io::Result<()> {
            self.base.current()?;
            let named = statat(
                &self.base.file,
                self.name.as_str(),
                AtFlags::SYMLINK_NOFOLLOW,
            )?;
            let opened = fstat(&self.directory)?;
            if !same_identity(&self.identity, &named)
                || !same_identity(&self.identity, &opened)
                || !private_directory(&named)
                || !private_directory(&opened)
            {
                return Err(changed());
            }
            if let Some((file, identity)) = &self.leaf {
                let named = statat(&self.directory, LEAF, AtFlags::SYMLINK_NOFOLLOW)?;
                let opened = fstat(file)?;
                if !same_identity(identity, &named)
                    || !same_identity(identity, &opened)
                    || named.st_nlink != 1
                    || opened.st_nlink != 1
                    || FileType::from_raw_mode(opened.st_mode) != FileType::RegularFile
                {
                    return Err(changed());
                }
            }
            Ok(())
        }

        fn create_leaf(&mut self) -> io::Result<()> {
            self.current()?;
            let file = File::from(openat(
                &self.directory,
                LEAF,
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )?);
            let identity = fstat(&file)?;
            if identity.st_dev != self.identity.st_dev
                || identity.st_uid != nix::unistd::geteuid().as_raw()
                || identity.st_mode & 0o077 != 0
            {
                return Err(changed());
            }
            self.leaf = Some((file, identity));
            self.current()
        }

        fn cleanup(&mut self) -> io::Result<()> {
            if self.removed {
                return Ok(());
            }
            // Never recurse. A replacement, unexpected extra entry, changed
            // alias or lost identity retains our private staging for inspection.
            self.current()?;
            if self.leaf.is_some() {
                unlinkat(&self.directory, LEAF, AtFlags::empty())?;
                self.leaf = None;
            }
            self.current()?;
            unlinkat(&self.base.file, self.name.as_str(), AtFlags::REMOVEDIR)?;
            self.removed = true;
            Ok(())
        }
    }

    impl Drop for Workspace {
        fn drop(&mut self) {
            let _ = self.cleanup();
        }
    }

    fn private_directory(stat: &Stat) -> bool {
        owned_directory(stat) && stat.st_mode & 0o777 == 0o700
    }

    fn owned_directory(stat: &Stat) -> bool {
        FileType::from_raw_mode(stat.st_mode) == FileType::Directory
            && stat.st_uid == nix::unistd::geteuid().as_raw()
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Step {
        WorkspaceCreated,
        FileCreated,
        Written,
    }

    #[cfg(test)]
    pub(super) fn probe(
        mount: &Path,
        base: &Path,
        name: &str,
        hook: &mut impl FnMut(Step, &Path) -> io::Result<()>,
    ) -> io::Result<()> {
        probe_with_admission(mount, base, name, &mut |_| true, hook)
    }

    pub(super) fn probe_with_admission(
        mount: &Path,
        base: &Path,
        name: &str,
        admit: &mut impl FnMut(&Path) -> bool,
        hook: &mut impl FnMut(Step, &Path) -> io::Result<()>,
    ) -> io::Result<()> {
        let mount = Directory::open(mount)?;
        let base = Directory::open(base)?;
        if base.identity.st_dev != mount.identity.st_dev {
            return Err(io::Error::from_raw_os_error(libc::EXDEV));
        }
        if !admit(&base.resolved) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "recovery probe surface is not authorized",
            ));
        }
        mount.current()?;
        let mut workspace = Workspace::create(base, name)?;
        let path = workspace.base.resolved.join(name);
        hook(Step::WorkspaceCreated, &path)?;
        mount.current()?;
        workspace.create_leaf()?;
        hook(Step::FileCreated, &path)?;
        mount.current()?;
        workspace.current()?;
        let file = &mut workspace.leaf.as_mut().ok_or_else(changed)?.0;
        file.write_all(&[0_u8; PROBE_BYTES])?;
        file.sync_all()?;
        hook(Step::Written, &path)?;
        mount.current()?;
        workspace.current()?;
        workspace.cleanup()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn recovery_probe_cleans_an_empty_reservation_with_restrictive_owner_permissions() {
            let temporary = tempfile::tempdir().unwrap();
            let base = Directory::open(temporary.path()).unwrap();
            // Equivalent to owner bits being removed by umask, without
            // changing the process-wide umask in a parallel test suite.
            assert!(Workspace::create_with_mode(base, "private", Mode::empty()).is_err());
            assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 0);
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn recovery_probe_rejects_changed_mount_evidence_even_with_matching_inode() {
            let temporary = tempfile::tempdir().unwrap();
            let mut directory = Directory::open(temporary.path()).unwrap();
            directory.mount_id ^= 1;
            assert_eq!(
                directory.current().unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 0);
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn recovery_probe_refuses_a_read_only_failing_mount_before_admission() {
            let temporary = tempfile::tempdir().unwrap();
            // Containers commonly expose a read-only sysfs or proc subtree.
            // No mount operation or mutation of these surfaces is needed.
            for path in [Path::new("/sys"), Path::new("/proc/sys")] {
                let Ok(file) = File::open(path) else { continue };
                let Ok(stats) = nix::sys::statvfs::fstatvfs(&file) else {
                    continue;
                };
                if !stats
                    .flags()
                    .contains(nix::sys::statvfs::FsFlags::ST_RDONLY)
                {
                    continue;
                }
                let error = probe_with_admission(
                    path,
                    temporary.path(),
                    "private",
                    &mut |_| panic!("a read-only mount cannot authorize recovery"),
                    &mut |_, _| Ok(()),
                )
                .unwrap_err();
                assert_eq!(error.raw_os_error(), Some(libc::EROFS));
                assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 0);
                return;
            }
            eprintln!("read-only mount fixture unavailable on this host");
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::unix::{Step, probe};
    use super::*;
    use std::fs;
    use std::io;
    use std::os::unix::fs::{MetadataExt, symlink};

    #[test]
    fn recovery_probe_is_private_and_never_touches_the_legacy_probe() {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().join("scratch");
        fs::create_dir(&base).unwrap();
        let outside = root.path().join("important");
        fs::write(&outside, b"keep this data").unwrap();
        fs::create_dir(base.join(".sbh")).unwrap();
        symlink(&outside, base.join(".sbh/probe")).unwrap();
        probe(
            root.path(),
            &base,
            ".sbh-recovery-test",
            &mut |step, path| {
                assert_eq!(fs::metadata(path)?.mode() & 0o777, 0o700);
                if step == Step::FileCreated {
                    let leaf = fs::metadata(path.join("write-test"))?;
                    assert_eq!(leaf.mode() & 0o777, 0o600);
                    assert_eq!(leaf.nlink(), 1);
                }
                if step == Step::Written {
                    assert_eq!(fs::metadata(path.join("write-test"))?.len(), 4096);
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(fs::read(&outside).unwrap(), b"keep this data");
        assert!(base.join(".sbh/probe").is_symlink());
        assert!(!base.join(".sbh-recovery-test").exists());
        assert_eq!(fs::read_dir(&base).unwrap().count(), 1);
    }

    #[test]
    fn recovery_probe_collisions_preserve_files_directories_links_and_fifos() {
        for kind in ["file", "directory", "symlink", "fifo"] {
            let root = tempfile::tempdir().unwrap();
            let occupied = root.path().join("occupied");
            let sentinel = root.path().join("sentinel");
            fs::write(&sentinel, b"not a probe").unwrap();
            match kind {
                "file" => fs::write(&occupied, b"existing contents").unwrap(),
                "directory" => {
                    fs::create_dir(&occupied).unwrap();
                    fs::write(occupied.join("user-data"), b"existing contents").unwrap();
                }
                "symlink" => symlink(&sentinel, &occupied).unwrap(),
                _ => nix::unistd::mkfifo(&occupied, nix::sys::stat::Mode::S_IRUSR).unwrap(),
            }
            let before = fs::symlink_metadata(&occupied).unwrap();
            let error =
                probe(root.path(), root.path(), "occupied", &mut |_, _| Ok(())).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{kind}");
            let after = fs::symlink_metadata(&occupied).unwrap();
            assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
            assert_eq!(fs::read(&sentinel).unwrap(), b"not a probe");
            if kind == "file" {
                assert_eq!(fs::read(&occupied).unwrap(), b"existing contents");
            }
        }
    }

    #[test]
    fn recovery_probe_retains_staging_when_a_base_is_replaced() {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().join("scratch");
        let saved = root.path().join("saved");
        fs::create_dir(&base).unwrap();
        let result = probe(root.path(), &base, ".sbh-recovery-test", &mut |step, _| {
            if step == Step::WorkspaceCreated {
                fs::rename(&base, &saved)?;
                fs::create_dir(&base)?;
                fs::write(base.join("user-data"), b"replacement survives")?;
            }
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(
            fs::read(base.join("user-data")).unwrap(),
            b"replacement survives"
        );
        assert!(saved.join(".sbh-recovery-test").is_dir());
        assert!(!saved.join(".sbh-recovery-test/write-test").exists());
    }

    #[test]
    fn recovery_probe_retains_staging_when_its_workspace_is_replaced() {
        let root = tempfile::tempdir().unwrap();
        let saved = root.path().join("saved");
        let result = probe(
            root.path(),
            root.path(),
            ".sbh-recovery-test",
            &mut |step, path| {
                if step == Step::FileCreated {
                    fs::rename(path, &saved)?;
                    fs::create_dir(path)?;
                    fs::write(path.join("user-data"), b"replacement survives")?;
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(
            fs::read(root.path().join(".sbh-recovery-test/user-data")).unwrap(),
            b"replacement survives",
        );
        assert_eq!(fs::metadata(saved.join("write-test")).unwrap().len(), 0);
    }

    #[test]
    fn recovery_probe_never_removes_a_replaced_leaf() {
        let root = tempfile::tempdir().unwrap();
        let saved = root.path().join("saved-probe");
        let result = probe(
            root.path(),
            root.path(),
            ".sbh-recovery-test",
            &mut |step, path| {
                if step == Step::Written {
                    fs::rename(path.join("write-test"), &saved)?;
                    fs::write(path.join("write-test"), b"user replacement")?;
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(fs::metadata(saved).unwrap().len(), 4096);
        assert_eq!(
            fs::read(root.path().join(".sbh-recovery-test/write-test")).unwrap(),
            b"user replacement",
        );
    }

    #[test]
    fn recovery_probe_failed_write_cleans_only_its_own_private_workspace() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("user-data"), b"keep").unwrap();
        let result = probe(
            root.path(),
            root.path(),
            ".sbh-recovery-test",
            &mut |step, _| {
                if step == Step::FileCreated {
                    Err(io::Error::from_raw_os_error(libc::ENOSPC))
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::ENOSPC));
        assert_eq!(fs::read(root.path().join("user-data")).unwrap(), b"keep");
        assert!(!root.path().join(".sbh-recovery-test").exists());
    }

    #[test]
    fn recovery_probe_accepts_a_stable_base_alias_but_does_not_create_missing_bases() {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().join("scratch");
        fs::create_dir(&base).unwrap();
        let alias = root.path().join("alias");
        symlink(&base, &alias).unwrap();
        assert!(probe_writable_surface(root.path(), &alias, |_| true));
        assert!(alias.is_symlink());
        assert_eq!(fs::read_dir(&base).unwrap().count(), 0);
        let missing = root.path().join("missing");
        assert!(!probe_writable_surface(root.path(), &missing, |_| true));
        assert!(!missing.exists());
    }

    #[test]
    fn recovery_probe_binds_admission_to_the_opened_base_before_any_write() {
        let root = tempfile::tempdir().unwrap();
        let allowed = root.path().join("allowed");
        let other = root.path().join("other");
        fs::create_dir(&allowed).unwrap();
        fs::create_dir(&other).unwrap();
        fs::write(other.join("user-data"), b"keep").unwrap();
        let alias = root.path().join("alias");
        let saved_alias = root.path().join("saved-alias");
        symlink(&allowed, &alias).unwrap();
        let result = unix::probe_with_admission(
            root.path(),
            &alias,
            ".sbh-recovery-test",
            &mut |resolved| {
                assert_eq!(resolved, fs::canonicalize(&allowed).unwrap());
                fs::rename(&alias, &saved_alias).unwrap();
                symlink(&other, &alias).unwrap();
                true
            },
            &mut |_, _| panic!("a changed alias must fail before creating staging"),
        );
        assert!(result.is_err());
        assert_eq!(fs::read_dir(&allowed).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&other).unwrap().count(), 1);
        assert_eq!(fs::read(other.join("user-data")).unwrap(), b"keep");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recovery_probe_refuses_a_writable_surface_on_another_device() {
        let root = tempfile::tempdir().unwrap();
        assert_ne!(
            fs::metadata(root.path()).unwrap().dev(),
            fs::metadata("/proc").unwrap().dev()
        );
        // /proc is only opened for its directory identity; the writable test
        // base is local. A wrong-device probe must create nothing in it.
        assert!(!probe_writable_surface(
            Path::new("/proc"),
            root.path(),
            |_| true
        ));
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }
}
