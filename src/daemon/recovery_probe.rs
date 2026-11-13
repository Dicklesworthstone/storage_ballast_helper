//! A small write test on an already-authorized recovery surface.
//!
//! The probe never opens an existing file for writing. Its randomly named
//! workspace is private, and every operation after opening a base is relative
//! to verified directory descriptors. Namespace uncertainty retains the private
//! workspace rather than risking cleanup of somebody else's replacement.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Permission expires even if the monitor cannot poll again. Cancellation
/// never frees a worker slot until its native operation actually returns.
pub(super) struct ProbePermit {
    cancelled: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    deadline: Instant,
}

impl ProbePermit {
    pub(super) fn allowed(&self) -> bool {
        !self.cancelled.load(Ordering::Acquire)
            && !self.shutdown.load(Ordering::Acquire)
            && Instant::now() < self.deadline
    }
}

struct PendingProbe<K> {
    key: K,
    started_at: Instant,
    cancelled: Arc<AtomicBool>,
    receiver: Receiver<bool>,
    worker: JoinHandle<()>,
}

/// Recovery writes must not hold up pressure control on other filesystems.
/// Results are single-use and bound to the requesting mount incarnation and
/// surface. A blocked probe retains one of four slots across invalidation;
/// neither polling, shutdown nor dropping this coordinator joins workers.
pub(super) struct BackgroundProbes<K> {
    pending: HashMap<PathBuf, PendingProbe<K>>,
    max_workers: usize,
    max_age: Duration,
}

impl<K> Default for BackgroundProbes<K> {
    fn default() -> Self {
        Self {
            pending: HashMap::new(),
            max_workers: 4,
            // A Recovery mount normally contributes a 30-second cadence.
            // Permit a completed probe to reach the next tick, but never
            // treat a delayed native return as a newly collected result.
            max_age: Duration::from_secs(60),
        }
    }
}

impl<K: PartialEq> BackgroundProbes<K> {
    pub(super) fn poll_or_start(
        &mut self,
        mount: &Path,
        key: K,
        permission_deadline: Instant,
        shutdown: Arc<AtomicBool>,
        probe: impl FnOnce(&ProbePermit) -> bool + Send + 'static,
    ) -> Option<bool> {
        let now = Instant::now();
        if shutdown.load(Ordering::Acquire) || now >= permission_deadline {
            self.cancel_mount(mount);
            return None;
        }
        self.pending.retain(|_, pending| {
            if now.saturating_duration_since(pending.started_at) >= self.max_age {
                pending.cancelled.store(true, Ordering::Release);
            }
            !pending.cancelled.load(Ordering::Acquire) || !pending.worker.is_finished()
        });
        if let Some(pending) = self.pending.get(mount) {
            if pending.key != key {
                pending.cancelled.store(true, Ordering::Release);
            }
            if !pending.worker.is_finished() {
                return None;
            }
            let pending = self.pending.remove(mount).expect("probe exists");
            if !pending.cancelled.load(Ordering::Acquire) && !shutdown.load(Ordering::Acquire) {
                return Some(pending.receiver.try_recv().unwrap_or(false));
            }
        }
        if self.pending.len() >= self.max_workers {
            return None;
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let permit = ProbePermit {
            cancelled: Arc::clone(&cancelled),
            shutdown,
            deadline: permission_deadline.min(now + self.max_age),
        };
        let (sender, receiver) = sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("sbh-recovery-probe".to_string())
            .spawn(move || {
                let success = permit.allowed() && probe(&permit) && permit.allowed();
                let _ = sender.try_send(success);
            })
            .ok()?;
        self.pending.insert(
            mount.to_path_buf(),
            PendingProbe {
                key,
                started_at: now,
                cancelled,
                receiver,
                worker,
            },
        );
        None
    }

    pub(super) fn cancel_mount(&self, mount: &Path) {
        if let Some(pending) = self.pending.get(mount) {
            pending.cancelled.store(true, Ordering::Release);
        }
    }

    pub(super) fn retain_mounts(&self, mut current: impl FnMut(&Path) -> bool) {
        for (mount, pending) in &self.pending {
            if !current(mount) {
                pending.cancelled.store(true, Ordering::Release);
            }
        }
    }

    pub(super) fn cancel_all(&self) {
        self.retain_mounts(|_| false);
    }
}

impl<K> Drop for BackgroundProbes<K> {
    fn drop(&mut self) {
        for pending in self.pending.values() {
            pending.cancelled.store(true, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod background_tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc::channel;

    fn until_finished<K>(probes: &BackgroundProbes<K>, mount: &Path) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while !probes.pending[mount].worker.is_finished() {
            assert!(Instant::now() < deadline, "probe did not finish");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn blocked_recovery_probe_retains_its_slot_while_other_mounts_progress() {
        let mut probes = BackgroundProbes::<u64> {
            pending: HashMap::new(),
            max_workers: 2,
            max_age: Duration::from_secs(60),
        };
        let shutdown = Arc::new(AtomicBool::new(false));
        let deadline = Instant::now() + Duration::from_secs(30);
        let mount = Path::new("/blocked");
        let (entered_tx, entered_rx) = channel();
        let (resume_tx, resume_rx) = channel();
        assert_eq!(
            probes.poll_or_start(mount, 0, deadline, Arc::clone(&shutdown), move |permit| {
                entered_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
                permit.allowed()
            }),
            None
        );
        entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        for key in 1..100 {
            probes.cancel_all();
            assert_eq!(
                probes.poll_or_start(mount, key, deadline, Arc::clone(&shutdown), |_| {
                    panic!("a cancelled but blocked worker still owns its slot")
                }),
                None
            );
            assert_eq!(probes.pending.len(), 1);
        }
        let healthy = Path::new("/healthy");
        assert_eq!(
            probes.poll_or_start(healthy, 0, deadline, Arc::clone(&shutdown), |_| true),
            None
        );
        until_finished(&probes, healthy);
        assert_eq!(
            probes.poll_or_start(healthy, 0, deadline, Arc::clone(&shutdown), |_| false),
            Some(true)
        );
        // Successful evidence is consumed once; another request needs its own
        // native result, even with identical path and scope.
        assert_eq!(
            probes.poll_or_start(healthy, 0, deadline, Arc::clone(&shutdown), |_| false),
            None
        );
        until_finished(&probes, healthy);
        assert_eq!(
            probes.poll_or_start(healthy, 0, deadline, Arc::clone(&shutdown), |_| true),
            Some(false)
        );
        resume_tx.send(()).unwrap();
        until_finished(&probes, mount);
        assert_eq!(
            probes.poll_or_start(mount, 99, deadline, shutdown, |_| false),
            None,
            "late success from the cancelled worker is never accepted"
        );
    }

    #[test]
    fn recovery_probe_worker_limit_survives_missing_mounts_and_reloads() {
        let mut probes = BackgroundProbes::<u64>::default();
        let shutdown = Arc::new(AtomicBool::new(false));
        let deadline = Instant::now() + Duration::from_secs(30);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut release = Vec::new();
        for index in 0..4 {
            let (resume_tx, resume_rx) = channel();
            release.push(resume_tx);
            let calls = Arc::clone(&calls);
            probes.poll_or_start(
                Path::new(&format!("/blocked-{index}")),
                0,
                deadline,
                Arc::clone(&shutdown),
                move |permit| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    resume_rx.recv().unwrap();
                    permit.allowed()
                },
            );
        }
        let started_deadline = Instant::now() + Duration::from_secs(3);
        while calls.load(Ordering::SeqCst) != 4 {
            assert!(Instant::now() < started_deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        for _ in 0..100 {
            probes.retain_mounts(|_| false);
            probes.cancel_all();
            assert_eq!(
                probes.poll_or_start(
                    Path::new("/another"),
                    0,
                    deadline,
                    Arc::clone(&shutdown),
                    |_| panic!("all native slots are still occupied"),
                ),
                None
            );
        }
        assert_eq!(probes.pending.len(), 4);
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        for sender in release {
            sender.send(()).unwrap();
        }
        for mount in probes.pending.keys() {
            until_finished(&probes, mount);
        }
    }

    #[test]
    fn recovery_probe_rejects_replaced_scope_expired_delivery_and_missing_evidence() {
        for reason in ["scope", "expired", "missing", "shutdown"] {
            let mut probes = BackgroundProbes::<u64>::default();
            let shutdown = Arc::new(AtomicBool::new(false));
            let deadline = Instant::now() + Duration::from_secs(30);
            let mount = Path::new("/mount");
            probes.poll_or_start(mount, 0, deadline, Arc::clone(&shutdown), |_| true);
            until_finished(&probes, mount);
            let mut current_deadline = deadline;
            let key = u64::from(reason == "scope");
            match reason {
                "expired" => {
                    probes.pending.get_mut(mount).unwrap().started_at = Instant::now()
                        .checked_sub(Duration::from_secs(120))
                        .expect("the expired recovery timestamp is representable");
                }
                "missing" => current_deadline = Instant::now(),
                "shutdown" => shutdown.store(true, Ordering::Release),
                _ => {}
            }
            assert_eq!(
                probes.poll_or_start(mount, key, current_deadline, shutdown, |_| false),
                None,
                "{reason} must not admit a completed success"
            );
        }
    }

    #[test]
    fn dropping_recovery_probes_revokes_permission_without_waiting_for_native_io() {
        let mut probes = BackgroundProbes::<u64>::default();
        let (entered_tx, entered_rx) = channel();
        let (resume_tx, resume_rx) = channel();
        let (permitted_tx, permitted_rx) = channel();
        probes.poll_or_start(
            Path::new("/mount"),
            0,
            Instant::now() + Duration::from_secs(30),
            Arc::new(AtomicBool::new(false)),
            move |permit| {
                entered_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
                permitted_tx.send(permit.allowed()).unwrap();
                true
            },
        );
        entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let (dropped_tx, dropped_rx) = channel();
        let join_handle = std::thread::spawn(move || {
            drop(probes);
            dropped_tx.send(()).unwrap();
        });
        let dropped = dropped_rx.recv_timeout(Duration::from_secs(3));
        resume_tx.send(()).unwrap();
        dropped.expect("dropping probes must not join a blocked worker");
        join_handle.join().unwrap();
        assert!(!permitted_rx.recv_timeout(Duration::from_secs(3)).unwrap());
    }
}

/// Test allocation and writeback on `mount` through one existing authorized
/// directory. Admission sees the pinned canonical base, after opening it and
/// before any write. The base must still have that identity after admission.
/// This never creates missing bases or follows a workspace/leaf symlink.
#[cfg(test)]
pub(super) fn probe_writable_surface(
    mount: &Path,
    base: &Path,
    admit: impl FnMut(&Path) -> bool,
) -> bool {
    probe_writable_surface_guarded(mount, base, admit, || true)
}

/// As above, with revocable permission checked after potentially blocking
/// identity reads and immediately before each new allocation or write.
pub(super) fn probe_writable_surface_guarded(
    mount: &Path,
    base: &Path,
    mut admit: impl FnMut(&Path) -> bool,
    continuing: impl Fn() -> bool,
) -> bool {
    #[cfg(unix)]
    {
        for _ in 0..4 {
            let name = format!(".sbh-recovery-{:032x}", rand::random::<u128>());
            match unix::probe_with_admission_and_guard(
                mount,
                base,
                &name,
                &mut admit,
                &continuing,
                &mut |_, _| Ok(()),
            ) {
                Ok(()) => return true,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return false,
            }
        }
        false
    }
    #[cfg(not(unix))]
    {
        let _ = (mount, base, &mut admit, continuing);
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

    fn check_permission(continuing: &impl Fn() -> bool) -> io::Result<()> {
        if continuing() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "recovery probe permission expired or was revoked",
            ))
        }
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
        fn create(base: Directory, name: &str, continuing: &impl Fn() -> bool) -> io::Result<Self> {
            Self::create_guarded(base, name, Mode::RUSR | Mode::WUSR | Mode::XUSR, continuing)
        }

        #[cfg(test)]
        fn create_with_mode(base: Directory, name: &str, mode: Mode) -> io::Result<Self> {
            Self::create_guarded(base, name, mode, &|| true)
        }

        fn create_guarded(
            base: Directory,
            name: &str,
            mode: Mode,
            continuing: &impl Fn() -> bool,
        ) -> io::Result<Self> {
            // mkdirat is exclusive: a file, link, directory or other existing
            // entry with this name is a collision, never a cleanup target.
            base.current()?;
            check_permission(continuing)?;
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

        fn create_leaf(&mut self, continuing: &impl Fn() -> bool) -> io::Result<()> {
            self.current()?;
            check_permission(continuing)?;
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

    #[cfg(test)]
    pub(super) fn probe_with_admission(
        mount: &Path,
        base: &Path,
        name: &str,
        admit: &mut impl FnMut(&Path) -> bool,
        hook: &mut impl FnMut(Step, &Path) -> io::Result<()>,
    ) -> io::Result<()> {
        probe_with_admission_and_guard(mount, base, name, admit, &|| true, hook)
    }

    pub(super) fn probe_with_admission_and_guard(
        mount: &Path,
        base: &Path,
        name: &str,
        admit: &mut impl FnMut(&Path) -> bool,
        continuing: &impl Fn() -> bool,
        hook: &mut impl FnMut(Step, &Path) -> io::Result<()>,
    ) -> io::Result<()> {
        check_permission(continuing)?;
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
        let mut workspace = Workspace::create(base, name, continuing)?;
        let path = workspace.base.resolved.join(name);
        hook(Step::WorkspaceCreated, &path)?;
        mount.current()?;
        workspace.create_leaf(continuing)?;
        hook(Step::FileCreated, &path)?;
        mount.current()?;
        workspace.current()?;
        check_permission(continuing)?;
        let file = &mut workspace.leaf.as_mut().ok_or_else(changed)?.0;
        file.write_all(&[0_u8; PROBE_BYTES])?;
        check_permission(continuing)?;
        file.sync_all()?;
        hook(Step::Written, &path)?;
        mount.current()?;
        workspace.current()?;
        workspace.cleanup()?;
        check_permission(continuing)
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
    fn recovery_probe_revocation_stops_each_new_write_and_preserves_user_files() {
        use std::cell::Cell;

        for revoke_at in [Step::WorkspaceCreated, Step::FileCreated, Step::Written] {
            let root = tempfile::tempdir().unwrap();
            fs::write(root.path().join("user-data"), b"keep").unwrap();
            let allowed = Cell::new(true);
            let mut seen = Vec::new();
            let result = unix::probe_with_admission_and_guard(
                root.path(),
                root.path(),
                ".sbh-recovery-cancelled",
                &mut |_| true,
                &|| allowed.get(),
                &mut |step, path| {
                    seen.push(step);
                    if step == revoke_at {
                        if step == Step::FileCreated {
                            assert_eq!(fs::metadata(path.join("write-test"))?.len(), 0);
                        }
                        allowed.set(false);
                    }
                    Ok(())
                },
            );
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
            assert_eq!(seen.last(), Some(&revoke_at));
            assert_eq!(fs::read(root.path().join("user-data")).unwrap(), b"keep");
            assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
        }
    }

    #[test]
    fn recovery_probe_revoked_during_admission_creates_nothing() {
        use std::cell::Cell;

        let root = tempfile::tempdir().unwrap();
        let allowed = Cell::new(true);
        let result = unix::probe_with_admission_and_guard(
            root.path(),
            root.path(),
            ".sbh-recovery-cancelled",
            &mut |_| {
                allowed.set(false);
                true
            },
            &|| allowed.get(),
            &mut |_, _| panic!("revoked admission cannot create a workspace"),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }

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
