//! Ownership of a filesystem control endpoint across startup and shutdown.
//!
//! The persistent sidecar lease serializes cooperating servers for this name;
//! it is never unlinked (unlinking a flock inode creates two lock domains).
//! Reclaim only an owned socket whose nonblocking connect probe was refused.
//! Cleanup is relative to the opened parent and checks the bound socket's
//! identity, so a replaced endpoint or parent is not somebody else's cleanup.
//! These checks do not make an attacker with the same uid unable to rename
//! files between syscalls; the endpoint directory remains a trust boundary.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use nix::errno::Errno as NixErrno;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, UnixAddr, connect, socket};
use rustix::fs::{
    AtFlags, FileType, FlockOperation, Mode, OFlags, Stat, flock, fstat, openat, statat, unlinkat,
};
use rustix::io::Errno;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    kind: FileType,
    uid: u32,
}

impl Identity {
    fn of(stat: &Stat) -> Self {
        #[allow(clippy::unnecessary_cast)]
        Self {
            device: stat.st_dev as u64,
            inode: stat.st_ino as u64,
            kind: FileType::from_raw_mode(stat.st_mode),
            uid: stat.st_uid,
        }
    }
}

fn occupied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::AddrInUse, message)
}

fn inspect(parent: &File, name: &OsStr) -> io::Result<Option<Stat>> {
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(stat)),
        Err(Errno::NOENT) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn lease_name(name: &OsStr) -> OsString {
    let mut lease = name.to_os_string();
    lease.push(".lock");
    lease
}

/// Holds the lease until after the listener has closed and cleanup finishes.
pub(super) struct EndpointGuard {
    parent: File,
    parent_path: PathBuf,
    name: OsString,
    lease_name: OsString,
    lease: File,
    bound: Option<Identity>,
}

impl EndpointGuard {
    fn check_location(&self) -> io::Result<()> {
        let named_parent = statat(
            rustix::fs::CWD,
            &self.parent_path,
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
        if Identity::of(&named_parent) != Identity::of(&fstat(&self.parent)?) {
            return Err(occupied("control socket parent changed during startup"));
        }
        let lease = inspect(&self.parent, &self.lease_name)?
            .ok_or_else(|| occupied("control socket lease disappeared"))?;
        if Identity::of(&lease) != Identity::of(&fstat(&self.lease)?) || lease.st_nlink != 1 {
            return Err(occupied("control socket lease was replaced"));
        }
        Ok(())
    }

    fn remove_same_socket(&self, expected: Identity) -> io::Result<()> {
        let Some(current) = inspect(&self.parent, &self.name)? else {
            return Ok(());
        };
        if Identity::of(&current) != expected || expected.kind != FileType::Socket {
            return Err(occupied(
                "control socket changed; leaving replacement untouched",
            ));
        }
        match unlinkat(&self.parent, &self.name, AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

impl Drop for EndpointGuard {
    fn drop(&mut self) {
        if let Some(expected) = self.bound.take() {
            // No pathname traversal here, including when a parent was renamed.
            // Never remove the sidecar: another process may have opened it.
            let _ = self.remove_same_socket(expected);
        }
    }
}

/// Bind with an owner-only, independently linked, nonblocking lifetime lease.
pub(super) fn bind(path: &Path) -> io::Result<(UnixListener, EndpointGuard)> {
    let absolute = std::path::absolute(path)?;
    let name = absolute.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "control socket has no filename",
        )
    })?;
    let parent_path = absolute.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "control socket has no parent")
    })?;
    fs::create_dir_all(parent_path)?;
    let parent_path = fs::canonicalize(parent_path)?;
    let resolved = parent_path.join(name);
    // Reject unsupported/overlong addresses before touching an existing entry.
    let _address = UnixAddr::new(&resolved)?;
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&parent_path)?;
    let lease_name = lease_name(name);
    let lease = File::from(openat(
        &parent,
        &lease_name,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )?);
    let metadata = fstat(&lease)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_nlink != 1
        || metadata.st_uid != nix::unistd::geteuid().as_raw()
        || metadata.st_mode & 0o077 != 0
        || metadata.st_dev != fstat(&parent)?.st_dev
    {
        return Err(occupied(
            "control socket lease is not a private owned regular file",
        ));
    }
    flock(&lease, FlockOperation::NonBlockingLockExclusive)?;
    let mut guard = EndpointGuard {
        parent,
        parent_path,
        name: name.to_os_string(),
        lease_name,
        lease,
        bound: None,
    };
    guard.check_location()?;
    if let Some(existing) = inspect(&guard.parent, &guard.name)? {
        let identity = Identity::of(&existing);
        if identity.kind != FileType::Socket
            || identity.uid != nix::unistd::geteuid().as_raw()
            || existing.st_nlink != 1
        {
            return Err(occupied(
                "control endpoint exists but is not an owned socket",
            ));
        }
        if !connection_refused(&resolved)? {
            return Err(occupied(
                "control socket is active or its liveness is uncertain",
            ));
        }
        guard.check_location()?;
        guard.remove_same_socket(identity)?;
    }
    guard.check_location()?;
    let listener = UnixListener::bind(&resolved)?;
    let bound = inspect(&guard.parent, &guard.name)?
        .ok_or_else(|| occupied("bound control socket disappeared"))?;
    let identity = Identity::of(&bound);
    if identity.kind != FileType::Socket || identity.uid != nix::unistd::geteuid().as_raw() {
        return Err(occupied("bound control socket was replaced"));
    }
    guard.bound = Some(identity);
    guard.check_location()?;
    // Only after ownership is established. The server does not accept until
    // this mode change and its own nonblocking setup have both succeeded.
    fs::set_permissions(&resolved, fs::Permissions::from_mode(0o600))?;
    guard.check_location()?;
    if inspect(&guard.parent, &guard.name)?
        .as_ref()
        .map(Identity::of)
        != guard.bound
    {
        return Err(occupied("control socket changed while setting permissions"));
    }
    listener.set_nonblocking(true)?;
    Ok((listener, guard))
}

fn connection_refused(path: &Path) -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    let flags = SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK;
    #[cfg(not(target_os = "linux"))]
    let flags = SockFlag::empty();
    let fd = socket(AddressFamily::Unix, SockType::Stream, flags, None)?;
    #[cfg(not(target_os = "linux"))]
    {
        use nix::fcntl::{FcntlArg, FdFlag, fcntl};
        fcntl(&fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
    }
    let stream = UnixStream::from(fd);
    stream.set_nonblocking(true)?;
    match connect(stream.as_raw_fd(), &UnixAddr::new(path)?) {
        Err(NixErrno::ECONNREFUSED) => Ok(true),
        // Success, backlog saturation, interrupted/in-progress connection,
        // wrong socket type and permission failures all preserve the endpoint.
        Ok(()) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink};
    use std::sync::Arc;

    use super::super::{
        ControlBackend, ControlCommand, ControlResponse, ControlServer, Peer, request,
    };

    struct Echo;

    impl ControlBackend for Echo {
        fn handle(&self, command: ControlCommand, _peer: Option<Peer>) -> ControlResponse {
            ControlResponse::success(serde_json::json!({ "command": command.name() }))
        }
    }

    #[test]
    fn an_existing_regular_file_is_never_treated_as_a_stale_socket() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.sock");
        fs::write(&path, b"not a socket; preserve me").unwrap();
        assert!(ControlServer::start(&path, "secret", Arc::new(Echo)).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"not a socket; preserve me");
    }

    #[test]
    fn endpoint_symlinks_and_dangling_symlinks_are_left_untouched() {
        for dangling in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("control.sock");
            let target = temp.path().join("elsewhere");
            if !dangling {
                fs::write(&target, b"keep").unwrap();
            }
            symlink(&target, &path).unwrap();
            assert!(bind(&path).is_err());
            assert_eq!(fs::read_link(&path).unwrap(), target);
            if !dangling {
                assert_eq!(fs::read(target).unwrap(), b"keep");
            }
        }
    }

    #[test]
    fn a_live_server_keeps_its_endpoint_when_another_server_starts() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.sock");
        let first = ControlServer::start(&path, "first", Arc::new(Echo)).unwrap();
        let inode = fs::symlink_metadata(&path).unwrap().ino();
        assert!(ControlServer::start(&path, "second", Arc::new(Echo)).is_err());
        assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), inode);
        assert!(
            request(&path, "first", "ping", &serde_json::json!({}))
                .unwrap()
                .ok
        );
        first.stop();
        let replacement = ControlServer::start(&path, "second", Arc::new(Echo)).unwrap();
        assert!(
            request(&path, "second", "ping", &serde_json::json!({}))
                .unwrap()
                .ok
        );
        replacement.stop();
    }

    #[test]
    fn an_unleased_live_listener_is_not_unlinked() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let inode = fs::symlink_metadata(&path).unwrap().ino();
        assert!(bind(&path).is_err());
        assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), inode);
        assert!(UnixStream::connect(&path).is_ok());
        drop(listener);
        let (listener, guard) = bind(&path).unwrap();
        drop(listener);
        drop(guard);
        assert!(!path.exists());
    }

    #[test]
    fn confirmed_stale_socket_recovers_with_private_permissions() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.sock");
        drop(UnixListener::bind(&path).unwrap());
        assert!(connection_refused(&path).unwrap());
        let (listener, guard) = bind(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!connection_refused(&path).unwrap());
        drop(listener);
        drop(guard);
        assert!(!path.exists());
    }

    #[test]
    fn lease_inode_survives_shutdown_and_is_reused_on_restart() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.sock");
        let lease = temp.path().join("control.sock.lock");
        let (listener, guard) = bind(&path).unwrap();
        let inode = fs::metadata(&lease).unwrap().ino();
        assert_eq!(
            fs::metadata(&lease).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(listener);
        drop(guard);
        assert_eq!(fs::metadata(&lease).unwrap().ino(), inode);
        let (listener, guard) = bind(&path).unwrap();
        assert_eq!(fs::metadata(&lease).unwrap().ino(), inode);
        drop(listener);
        drop(guard);
    }

    #[test]
    fn independent_names_in_a_shared_directory_have_independent_leases() {
        let temp = tempfile::tempdir().unwrap();
        let (first, first_guard) = bind(&temp.path().join("first.sock")).unwrap();
        let (second, second_guard) = bind(&temp.path().join("second.sock")).unwrap();
        drop(first);
        drop(first_guard);
        assert!(UnixStream::connect(temp.path().join("second.sock")).is_ok());
        drop(second);
        drop(second_guard);
    }

    #[test]
    fn shutdown_preserves_a_replacement_file_or_socket() {
        for replacement_socket in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("control.sock");
            let (old, guard) = bind(&path).unwrap();
            fs::rename(&path, temp.path().join("old.sock")).unwrap();
            let replacement = if replacement_socket {
                Some(UnixListener::bind(&path).unwrap())
            } else {
                fs::write(&path, b"replacement").unwrap();
                None
            };
            let inode = fs::symlink_metadata(&path).unwrap().ino();
            drop(old);
            drop(guard);
            assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), inode);
            if replacement_socket {
                assert!(UnixStream::connect(&path).is_ok());
            } else {
                assert_eq!(fs::read(&path).unwrap(), b"replacement");
            }
            drop(replacement);
        }
    }

    #[test]
    fn parent_replacement_cannot_redirect_shutdown_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("current");
        let path = parent.join("control.sock");
        let (old, guard) = bind(&path).unwrap();
        let moved_parent = temp.path().join("retired");
        fs::rename(&parent, &moved_parent).unwrap();
        fs::create_dir(&parent).unwrap();
        let replacement = UnixListener::bind(&path).unwrap();
        drop(old);
        drop(guard);
        assert!(UnixStream::connect(&path).is_ok());
        assert!(!moved_parent.join("control.sock").exists());
        assert!(moved_parent.join("control.sock.lock").exists());
        drop(replacement);
    }

    #[test]
    fn lease_links_and_nonprivate_leases_are_rejected_without_modification() {
        for kind in ["symlink", "hardlink", "public"] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("control.sock");
            let target = temp.path().join("important");
            let lease = temp.path().join("control.sock.lock");
            fs::write(&target, b"not lock contents").unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
            match kind {
                "symlink" => symlink(&target, &lease).unwrap(),
                "hardlink" => fs::hard_link(&target, &lease).unwrap(),
                _ => {
                    fs::write(&lease, b"public").unwrap();
                    fs::set_permissions(&lease, fs::Permissions::from_mode(0o644)).unwrap();
                }
            }
            assert!(bind(&path).is_err(), "{kind}");
            assert!(!path.exists());
            assert_eq!(fs::read(&target).unwrap(), b"not lock contents");
            assert_eq!(
                fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn fifo_endpoint_is_refused_without_opening_it() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.sock");
        nix::unistd::mkfifo(
            &path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        assert!(bind(&path).is_err());
        assert!(fs::symlink_metadata(path).unwrap().file_type().is_fifo());
    }

    #[test]
    fn lease_replacement_is_detected_before_endpoint_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.sock");
        let (listener, guard) = bind(&path).unwrap();
        let lease = temp.path().join("control.sock.lock");
        fs::rename(&lease, temp.path().join("retired.lock")).unwrap();
        fs::write(&lease, b"replacement").unwrap();
        assert!(guard.check_location().is_err());
        // The endpoint still exists and the replacement lock is not altered.
        assert!(path.exists());
        assert_eq!(fs::read(&lease).unwrap(), b"replacement");
        drop(listener);
        drop(guard);
        assert_eq!(fs::read(lease).unwrap(), b"replacement");
    }

    #[test]
    fn parent_aliases_share_one_endpoint_lease() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("real");
        fs::create_dir(&parent).unwrap();
        let alias = temp.path().join("alias");
        symlink(&parent, &alias).unwrap();
        let (listener, guard) = bind(&parent.join("control.sock")).unwrap();
        assert!(bind(&alias.join("control.sock")).is_err());
        assert!(UnixStream::connect(alias.join("control.sock")).is_ok());
        drop(listener);
        drop(guard);
    }
}
