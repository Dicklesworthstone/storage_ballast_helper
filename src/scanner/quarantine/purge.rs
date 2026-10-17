//! Descriptor-relative removal of one recorded quarantine payload.
//!
//! The store lock serializes cooperating daemon/CLI operations. Every child
//! lookup is relative to an opened directory, with no symlink traversal and
//! identity rechecks before descent/unlink. Only the recorded basename is
//! removed; unrelated decision-directory siblings are never enumerated.
//!
//! Linux uses openat2(NO_XDEV) to reject bind mounts as well as device changes.
//! An unavailable/blocked openat2 fails closed, without a weaker fallback.
//! Other Unix systems use no-follow opens and device checks. The caller keeps
//! the manifest on any error; a partial purge can have removed earlier children
//! already, but the remaining payload is still tracked for retry or undo.

use std::fs::File;
use std::io;

use super::QuarantineRecord;

pub(super) fn remove_payload(store: &File, record: &QuarantineRecord) -> io::Result<bool> {
    #[cfg(unix)]
    {
        unix::remove_payload(store, record)
    }
    #[cfg(not(unix))]
    {
        let _ = (store, record);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "confined quarantine purge requires Unix directory descriptors",
        ))
    }
}

#[cfg(unix)]
mod unix {
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Component, Path};

    use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat, fstat, statat, unlinkat};
    use rustix::io::Errno;

    use super::QuarantineRecord;

    // Each level owns a directory descriptor and a directory stream. Bound
    // stack/fd consumption independently of adversarial tree depth. A wide
    // directory is streamed, not collected into an unbounded in-memory plan.
    const MAX_DIRECTORY_DEPTH: usize = 64;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Identity {
        device: u64,
        inode: u64,
        kind: FileType,
    }

    impl Identity {
        #[allow(clippy::unnecessary_cast, clippy::cast_sign_loss)]
        fn of(stat: &Stat) -> Self {
            Self {
                // dev_t is signed on some Unix targets; records use u64.
                device: stat.st_dev as u64,
                inode: stat.st_ino as u64,
                kind: FileType::from_raw_mode(stat.st_mode),
            }
        }
    }

    fn invalid(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    fn validate_name(name: &OsStr) -> io::Result<()> {
        let mut parts = Path::new(name).components();
        if !matches!(parts.next(), Some(Component::Normal(_))) || parts.next().is_some() {
            return Err(invalid("quarantine purge requires a single child name"));
        }
        Ok(())
    }

    fn inspect(parent: &File, name: &OsStr) -> io::Result<Option<Identity>> {
        validate_name(name)?;
        match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok(Some(Identity::of(&stat))),
            Err(Errno::NOENT) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn same_child(parent: &File, name: &OsStr, expected: Identity) -> io::Result<bool> {
        match inspect(parent, name)? {
            Some(current) if current == expected => Ok(true),
            None => Ok(false),
            Some(_) => Err(invalid("quarantine child identity changed during purge")),
        }
    }

    fn open_directory(parent: &File, name: &OsStr, expected: Identity) -> io::Result<File> {
        validate_name(name)?;
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        #[cfg(target_os = "linux")]
        let fd = {
            use rustix::fs::{ResolveFlags, openat2};
            openat2(
                parent,
                name,
                flags,
                Mode::empty(),
                ResolveFlags::BENEATH
                    | ResolveFlags::NO_SYMLINKS
                    | ResolveFlags::NO_MAGICLINKS
                    | ResolveFlags::NO_XDEV,
            )?
        };
        #[cfg(not(target_os = "linux"))]
        let fd = rustix::fs::openat(parent, name, flags, Mode::empty())?;
        let directory = File::from(fd);
        if Identity::of(&fstat(&directory)?) != expected {
            return Err(invalid("quarantine directory changed while opening it"));
        }
        Ok(directory)
    }

    // Explicit scheduling points for deterministic replacement regressions.
    // Production passes a no-op closure which is monomorphized away.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Step {
        Inspected,
        Opened,
        BeforeUnlink,
    }

    pub(super) fn remove_payload(store: &File, record: &QuarantineRecord) -> io::Result<bool> {
        remove_with_hook(store, record, &mut |_, _| {})
    }

    fn remove_with_hook(
        store: &File,
        record: &QuarantineRecord,
        hook: &mut impl FnMut(&OsStr, Step),
    ) -> io::Result<bool> {
        let id = OsStr::new(&record.decision_id);
        let Some(entry_identity) = inspect(store, id)? else {
            // A prior removal may not yet have been persisted.
            store.sync_all()?;
            return Ok(false);
        };
        if entry_identity.kind != FileType::Directory
            || entry_identity.device != record.device_id
            || Identity::of(&fstat(store)?).device != record.device_id
        {
            return Err(invalid("quarantine entry is not a same-device directory"));
        }
        let entry = open_directory(store, id, entry_identity)?;
        let name = record
            .original_path
            .file_name()
            .ok_or_else(|| invalid("quarantine origin has no basename"))?;
        let Some(payload) = inspect(&entry, name)? else {
            entry.sync_all()?;
            return Ok(false);
        };
        if (payload.device, payload.inode) != (record.device_id, record.inode)
            || !matches!(payload.kind, FileType::RegularFile | FileType::Directory)
        {
            return Err(invalid(
                "quarantine payload identity changed; refusing purge",
            ));
        }
        let removed = remove_child(&entry, name, payload, 0, hook)?;
        // Sync the SAME opened parent before the caller drops recovery data.
        entry.sync_all()?;
        Ok(removed)
    }

    fn remove_child(
        parent: &File,
        name: &OsStr,
        expected: Identity,
        depth: usize,
        hook: &mut impl FnMut(&OsStr, Step),
    ) -> io::Result<bool> {
        hook(name, Step::Inspected);
        if expected.kind == FileType::Directory {
            if depth >= MAX_DIRECTORY_DEPTH {
                return Err(invalid("quarantine purge directory depth limit reached"));
            }
            let directory = open_directory(parent, name, expected)?;
            hook(name, Step::Opened);
            if !same_child(parent, name, expected)? {
                return Err(invalid("quarantine directory disappeared before traversal"));
            }
            for child in Dir::read_from(&directory)? {
                let child = child?;
                let bytes = child.file_name().to_bytes();
                if bytes == b"." || bytes == b".." {
                    continue;
                }
                let child_name = OsStr::from_bytes(bytes);
                let Some(identity) = inspect(&directory, child_name)? else {
                    continue;
                };
                if identity.device != expected.device {
                    return Err(invalid("quarantine purge refuses a nested filesystem"));
                }
                remove_child(&directory, child_name, identity, depth + 1, hook)?;
            }
        }
        hook(name, Step::BeforeUnlink);
        if !same_child(parent, name, expected)? {
            return Ok(false);
        }
        let flags = if expected.kind == FileType::Directory {
            AtFlags::REMOVEDIR
        } else {
            // Symlinks, sockets and FIFOs are unlinked as directory entries;
            // never open their targets or block waiting for a writer. The
            // kernel refuses unlinking a mount point, including a file bind.
            AtFlags::empty()
        };
        match unlinkat(parent, name, flags) {
            Ok(()) => Ok(true),
            Err(Errno::NOENT) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fs;
        use std::os::unix::fs::symlink;
        use std::time::Duration;

        use crate::scanner::quarantine::{QuarantineStore, safety::lock_store};

        fn held_tree(base: &Path, id: &str) -> (QuarantineStore, QuarantineRecord) {
            let source = base.join(format!("artifact-{id}"));
            fs::create_dir_all(source.join("nested")).unwrap();
            fs::write(source.join("nested/leaf"), b"held bytes").unwrap();
            let store = QuarantineStore::under(base);
            let record = store
                .quarantine(&source, id, 100, Duration::ZERO, None)
                .unwrap();
            (store, record)
        }

        #[test]
        fn recursive_purge_preserves_rebuilt_original_and_unrecorded_siblings() {
            let temp = tempfile::tempdir().unwrap();
            let (store, record) = held_tree(temp.path(), "tree");
            fs::create_dir_all(&record.original_path).unwrap();
            fs::write(record.original_path.join("new-build"), b"keep rebuild").unwrap();
            let sibling = record.quarantine_path.parent().unwrap().join("unrecorded");
            fs::write(&sibling, b"keep sibling").unwrap();
            assert_eq!(store.purge("tree").unwrap(), 100);
            assert!(!record.quarantine_path.exists());
            assert_eq!(fs::read(sibling).unwrap(), b"keep sibling");
            assert_eq!(
                fs::read(record.original_path.join("new-build")).unwrap(),
                b"keep rebuild"
            );
            assert!(store.record("tree").unwrap().is_none());
            assert_eq!(store.purge("tree").unwrap(), 0);
        }

        #[test]
        fn nested_symlink_targets_are_never_opened_or_traversed() {
            let temp = tempfile::tempdir().unwrap();
            let (store, record) = held_tree(temp.path(), "links");
            let outside = temp.path().join("outside");
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("precious"), b"untouched").unwrap();
            symlink(&outside, record.quarantine_path.join("directory-link")).unwrap();
            symlink(
                outside.join("precious"),
                record.quarantine_path.join("file-link"),
            )
            .unwrap();
            symlink("absent", record.quarantine_path.join("dangling")).unwrap();
            assert_eq!(store.purge("links").unwrap(), 100);
            assert_eq!(fs::read(outside.join("precious")).unwrap(), b"untouched");
            assert!(!record.quarantine_path.exists());
        }

        #[test]
        fn native_filename_admission_and_purge_preserve_exact_paths() {
            let temp = tempfile::tempdir().unwrap();
            let (store, record) = held_tree(temp.path(), "bytes");
            let name = OsStr::from_bytes(b"non-utf8-\xff");
            let nested = record.quarantine_path.join(name);
            match fs::create_dir(&nested) {
                Ok(()) => {
                    // Retain the arbitrary-byte directory and child proof on
                    // Linux and any native filesystem admitting these bytes.
                    fs::write(nested.join(name), b"opaque name").unwrap();
                    assert_eq!(fs::read(nested.join(name)).unwrap(), b"opaque name");
                }
                Err(error) => {
                    // APFS refuses this fixture before the executor runs. Do
                    // not replace its bytes with the Unicode replacement
                    // character or claim that rejection proves byte purge.
                    #[cfg(not(target_os = "macos"))]
                    panic!("the raw-byte fixture must be admitted: {error}");
                    #[cfg(target_os = "macos")]
                    {
                        assert_eq!(error.raw_os_error(), Some(libc::EILSEQ));
                        assert!(!nested.exists());
                        assert!(
                            !record
                                .quarantine_path
                                .join(name.to_string_lossy().as_ref())
                                .exists()
                        );
                        assert_eq!(
                            fs::read(record.quarantine_path.join("nested/leaf")).unwrap(),
                            b"held bytes"
                        );
                    }
                }
            }
            // Exercise the actual confined purge on both platforms, with
            // supported non-ASCII directory and child names, plus a survivor.
            let supported = OsStr::from_bytes("native-雪-🦀".as_bytes());
            let supported_dir = record.quarantine_path.join(supported);
            fs::create_dir(&supported_dir).unwrap();
            fs::write(supported_dir.join(supported), b"native path").unwrap();
            assert_eq!(
                fs::read(supported_dir.join(supported)).unwrap(),
                b"native path"
            );
            let outside = temp.path().join(supported);
            fs::write(&outside, b"outside survives").unwrap();
            assert_eq!(store.purge("bytes").unwrap(), 100);
            assert!(!record.quarantine_path.exists());
            assert_eq!(fs::read(outside).unwrap(), b"outside survives");
            assert!(store.record("bytes").unwrap().is_none());
        }

        #[test]
        fn hard_linked_children_only_lose_their_quarantine_name() {
            let temp = tempfile::tempdir().unwrap();
            let (store, record) = held_tree(temp.path(), "hardlink");
            let outside = temp.path().join("keep");
            fs::hard_link(record.quarantine_path.join("nested/leaf"), &outside).unwrap();
            assert_eq!(store.purge("hardlink").unwrap(), 100);
            assert_eq!(fs::read(outside).unwrap(), b"held bytes");
        }

        #[test]
        fn nested_fifo_is_unlinked_without_opening_or_waiting_for_a_writer() {
            let temp = tempfile::tempdir().unwrap();
            let (store, record) = held_tree(temp.path(), "fifo");
            nix::unistd::mkfifo(
                &record.quarantine_path.join("pipe"),
                nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
            )
            .unwrap();
            assert_eq!(store.purge("fifo").unwrap(), 100);
            assert!(!record.quarantine_path.exists());
        }

        #[test]
        fn wrong_recorded_identity_refuses_before_removing_any_child() {
            let temp = tempfile::tempdir().unwrap();
            let (store, record) = held_tree(temp.path(), "identity");
            let lock = lock_store(store.root()).unwrap();
            for wrong_device in [false, true] {
                let mut wrong = record.clone();
                if wrong_device {
                    wrong.device_id ^= 1;
                } else {
                    wrong.inode ^= 1;
                }
                assert!(remove_payload(&lock, &wrong).is_err());
                assert_eq!(
                    fs::read(record.quarantine_path.join("nested/leaf")).unwrap(),
                    b"held bytes"
                );
            }
        }

        #[test]
        fn directory_replaced_by_symlink_after_inspection_is_not_followed() {
            let temp = tempfile::tempdir().unwrap();
            let (store, record) = held_tree(temp.path(), "swap");
            let outside = temp.path().join("outside");
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("precious"), b"keep").unwrap();
            let nested = record.quarantine_path.join("nested");
            let saved = temp.path().join("saved");
            let lock = lock_store(store.root()).unwrap();
            let mut fired = false;
            let result = remove_with_hook(&lock, &record, &mut |name, step| {
                if name == "nested" && step == Step::Inspected && !fired {
                    fired = true;
                    fs::rename(&nested, &saved).unwrap();
                    symlink(&outside, &nested).unwrap();
                }
            });
            assert!(fired);
            assert!(result.is_err());
            assert_eq!(fs::read(outside.join("precious")).unwrap(), b"keep");
            assert_eq!(fs::read(saved.join("leaf")).unwrap(), b"held bytes");
            assert!(store.record("swap").unwrap().is_some());
        }

        #[test]
        fn opened_directory_replacement_is_detected_before_traversal() {
            let temp = tempfile::tempdir().unwrap();
            let (store, record) = held_tree(temp.path(), "opened");
            let nested = record.quarantine_path.join("nested");
            let saved = temp.path().join("saved");
            let lock = lock_store(store.root()).unwrap();
            let mut fired = false;
            let result = remove_with_hook(&lock, &record, &mut |name, step| {
                if name == "nested" && step == Step::Opened && !fired {
                    fired = true;
                    fs::rename(&nested, &saved).unwrap();
                    fs::create_dir(&nested).unwrap();
                    fs::write(nested.join("new"), b"replacement").unwrap();
                }
            });
            assert!(fired);
            assert!(result.is_err());
            assert_eq!(fs::read(saved.join("leaf")).unwrap(), b"held bytes");
            assert_eq!(fs::read(nested.join("new")).unwrap(), b"replacement");
        }

        #[test]
        fn leaf_replacement_at_the_unlink_boundary_is_preserved() {
            let temp = tempfile::tempdir().unwrap();
            let (store, record) = held_tree(temp.path(), "leaf-swap");
            let leaf = record.quarantine_path.join("nested/leaf");
            let saved = temp.path().join("saved-leaf");
            let lock = lock_store(store.root()).unwrap();
            let mut fired = false;
            let result = remove_with_hook(&lock, &record, &mut |name, step| {
                if name == "leaf" && step == Step::BeforeUnlink && !fired {
                    fired = true;
                    fs::rename(&leaf, &saved).unwrap();
                    fs::write(&leaf, b"replacement").unwrap();
                }
            });
            assert!(fired);
            assert!(result.is_err());
            assert_eq!(fs::read(saved).unwrap(), b"held bytes");
            assert_eq!(fs::read(leaf).unwrap(), b"replacement");
        }

        #[test]
        fn a_vanished_payload_does_not_claim_a_second_release() {
            let temp = tempfile::tempdir().unwrap();
            let (store, record) = held_tree(temp.path(), "vanished");
            fs::rename(&record.quarantine_path, &record.original_path).unwrap();
            let lock = lock_store(store.root()).unwrap();
            assert!(!remove_payload(&lock, &record).unwrap());
            assert_eq!(
                fs::read(record.original_path.join("nested/leaf")).unwrap(),
                b"held bytes"
            );
        }

        #[test]
        fn excessive_depth_retains_recovery_metadata_and_other_entries_still_drain() {
            let temp = tempfile::tempdir().unwrap();
            let (store, record) = held_tree(temp.path(), "deep");
            let mut deepest = record.quarantine_path;
            for _ in 0..MAX_DIRECTORY_DEPTH {
                deepest.push("d");
                fs::create_dir(&deepest).unwrap();
            }
            fs::write(deepest.join("keep"), b"not reached").unwrap();
            let error = store.purge("deep").unwrap_err().to_string();
            assert!(error.contains("depth limit"), "{error}");
            assert!(store.record("deep").unwrap().is_some());
            let (_, healthy) = held_tree(temp.path(), "healthy");
            let outcome = store.drain_all().unwrap();
            assert_eq!(outcome.entries, 1);
            assert_eq!(outcome.bytes, 100);
            assert_eq!(outcome.failures.len(), 1);
            assert_eq!(outcome.failures[0].decision_id, "deep");
            assert!(!healthy.quarantine_path.exists());
            assert_eq!(fs::read(deepest.join("keep")).unwrap(), b"not reached");
            assert!(store.record("deep").unwrap().is_some());
        }

        #[test]
        fn descriptor_operations_reject_non_child_names() {
            let temp = tempfile::tempdir().unwrap();
            let parent = File::open(temp.path()).unwrap();
            for name in ["", ".", "..", "../outside", "/absolute", "child/grandchild"] {
                assert!(inspect(&parent, OsStr::new(name)).is_err(), "{name:?}");
            }
        }

        #[cfg(target_os = "linux")]
        mod mount_tests {
            use super::*;
            use std::os::unix::fs::MetadataExt;
            use std::path::PathBuf;

            use crate::core::errors::SbhError;
            use nix::errno::Errno as NixErrno;
            use nix::mount::{MntFlags, MsFlags, mount, umount, umount2};

            #[derive(Clone, Copy)]
            enum BoundAt {
                Subtree,
                Payload,
                DecisionDirectory,
                File,
            }

            struct Mounted {
                scratch: Option<tempfile::TempDir>,
                store: QuarantineStore,
                record: QuarantineRecord,
                target: PathBuf,
                retained: PathBuf,
                before: Vec<u8>,
                attached: bool,
            }

            impl Mounted {
                fn bind(at: BoundAt) -> Option<Self> {
                    let scratch = tempfile::tempdir().unwrap();
                    let (store, record) = held_tree(scratch.path(), "mounted");
                    let foreign = scratch.path().join("foreign");
                    fs::create_dir(&foreign).unwrap();
                    fs::write(foreign.join("precious"), b"not quarantine data").unwrap();
                    let (source, target, retained) = match at {
                        BoundAt::Subtree => {
                            let target = record.quarantine_path.join("nested/bound");
                            fs::create_dir(&target).unwrap();
                            (foreign.clone(), target, foreign.join("precious"))
                        }
                        BoundAt::Payload => (
                            record.quarantine_path.clone(),
                            record.quarantine_path.clone(),
                            record.quarantine_path.join("nested/leaf"),
                        ),
                        BoundAt::DecisionDirectory => {
                            let target = record.quarantine_path.parent().unwrap().to_path_buf();
                            (
                                target.clone(),
                                target,
                                record.quarantine_path.join("nested/leaf"),
                            )
                        }
                        BoundAt::File => {
                            let target = record.quarantine_path.join("nested/bound-file");
                            fs::write(&target, b"covered file").unwrap();
                            (foreign.join("precious"), target, foreign.join("precious"))
                        }
                    };
                    let before = fs::read(&retained).unwrap();
                    match mount(
                        Some(source.as_path()),
                        target.as_path(),
                        None::<&str>,
                        MsFlags::MS_BIND,
                        None::<&str>,
                    ) {
                        Ok(()) => {}
                        Err(NixErrno::EPERM | NixErrno::EACCES | NixErrno::ENOSYS) => {
                            eprintln!("TEST SKIP: bind-mount fixture requires mount capability");
                            return None;
                        }
                        Err(error) => panic!("bind-mount fixture failed: {error}"),
                    }
                    // Install the cleanup guard immediately after mount succeeds.
                    Some(Self {
                        scratch: Some(scratch),
                        store,
                        record,
                        target,
                        retained,
                        before,
                        attached: true,
                    })
                }

                fn detach(&mut self) {
                    umount(self.target.as_path()).unwrap();
                    self.attached = false;
                }

                fn assert_preserved(&self) {
                    assert_eq!(fs::read(&self.retained).unwrap(), self.before);
                    assert!(self.store.record("mounted").unwrap().is_some());
                }
            }

            impl Drop for Mounted {
                fn drop(&mut self) {
                    if self.attached
                        && let Err(error) = umount2(self.target.as_path(), MntFlags::MNT_DETACH)
                    {
                        // Never let TempDir's unrestricted recursive cleanup
                        // traverse a fixture mount that could not be detached.
                        if let Some(scratch) = self.scratch.take() {
                            let preserved = scratch.keep();
                            eprintln!(
                                "fixture unmount failed ({error}); retained {}",
                                preserved.display()
                            );
                        }
                    }
                }
            }

            fn assert_errno(error: SbhError, code: i32) {
                match error {
                    SbhError::Io { source, .. } => {
                        assert_eq!(source.raw_os_error(), Some(code), "{source}");
                    }
                    other => panic!("expected a filesystem boundary error, got {other}"),
                }
            }

            #[test]
            fn same_device_bind_subtree_is_preserved_and_other_entries_drain() {
                let Some(mut fixture) = Mounted::bind(BoundAt::Subtree) else {
                    return;
                };
                assert_eq!(
                    fs::metadata(&fixture.target).unwrap().dev(),
                    fixture.record.device_id
                );
                assert_errno(fixture.store.purge("mounted").unwrap_err(), libc::EXDEV);
                fixture.assert_preserved();
                let (_, healthy) = held_tree(fixture.scratch.as_ref().unwrap().path(), "healthy");
                let drained = fixture.store.drain_all().unwrap();
                assert_eq!(drained.entries, 1);
                assert_eq!(drained.bytes, 100);
                assert_eq!(drained.failures.len(), 1);
                assert!(!healthy.quarantine_path.exists());
                fixture.assert_preserved();
                fixture.detach();
                assert_eq!(fixture.store.purge("mounted").unwrap(), 100);
                assert_eq!(fs::read(&fixture.retained).unwrap(), fixture.before);
                assert!(fixture.store.stuck_entries().unwrap().is_empty());
            }

            #[test]
            fn self_bound_payload_is_refused_even_when_record_identity_still_matches() {
                let Some(fixture) = Mounted::bind(BoundAt::Payload) else {
                    return;
                };
                let metadata = fs::metadata(&fixture.target).unwrap();
                assert_eq!(metadata.dev(), fixture.record.device_id);
                assert_eq!(metadata.ino(), fixture.record.inode);
                assert_errno(fixture.store.purge("mounted").unwrap_err(), libc::EXDEV);
                fixture.assert_preserved();
            }

            #[test]
            fn self_bound_decision_directory_is_refused_before_payload_traversal() {
                let Some(fixture) = Mounted::bind(BoundAt::DecisionDirectory) else {
                    return;
                };
                assert_errno(fixture.store.purge("mounted").unwrap_err(), libc::EXDEV);
                fixture.assert_preserved();
            }

            #[test]
            fn mounted_file_is_not_unlinked_or_modified() {
                let Some(fixture) = Mounted::bind(BoundAt::File) else {
                    return;
                };
                assert_errno(fixture.store.purge("mounted").unwrap_err(), libc::EBUSY);
                fixture.assert_preserved();
                assert_eq!(fs::read(&fixture.target).unwrap(), fixture.before);
            }

            #[test]
            fn pending_manifest_survives_mount_refusal_and_drains_after_unmount() {
                let Some(mut fixture) = Mounted::bind(BoundAt::Subtree) else {
                    return;
                };
                let manifest = fixture.store.root().join("mounted.json");
                let pending = fixture.store.root().join("mounted.pending");
                fs::rename(&manifest, &pending).unwrap();
                assert_errno(fixture.store.purge("mounted").unwrap_err(), libc::EXDEV);
                assert!(pending.exists());
                assert!(!manifest.exists());
                fixture.assert_preserved();
                fixture.detach();
                assert_eq!(fixture.store.purge("mounted").unwrap(), 100);
                assert!(!pending.exists());
                assert!(!fixture.record.quarantine_path.exists());
                assert_eq!(fs::read(&fixture.retained).unwrap(), fixture.before);
            }

            #[test]
            fn existing_kernel_mount_boundaries_can_be_checked_without_mount_privileges() {
                let Ok(mounts) = fs::read_to_string("/proc/self/mountinfo") else {
                    eprintln!("TEST SKIP: Linux mount inventory is unavailable");
                    return;
                };
                let mut checked = 0;
                // Read-only opens, never purge these system directories.
                // Container /proc/bus is often a same-device bind mount.
                for (parent_path, name, full_path) in
                    [("/dev", "shm", "/dev/shm"), ("/proc", "bus", "/proc/bus")]
                {
                    if !mounts
                        .lines()
                        .any(|line| line.split_whitespace().nth(4) == Some(full_path))
                    {
                        continue;
                    }
                    let Ok(parent) = File::open(parent_path) else {
                        continue;
                    };
                    let Ok(Some(identity)) = inspect(&parent, OsStr::new(name)) else {
                        continue;
                    };
                    let error = open_directory(&parent, OsStr::new(name), identity).unwrap_err();
                    assert_eq!(
                        error.raw_os_error(),
                        Some(libc::EXDEV),
                        "{full_path}: {error}"
                    );
                    checked += 1;
                }
                if checked == 0 {
                    eprintln!("TEST SKIP: no readable fixture-free mount boundaries found");
                }
            }
        }
    }
}
