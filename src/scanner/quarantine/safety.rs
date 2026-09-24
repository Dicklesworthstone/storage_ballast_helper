//! Transaction and identity boundaries for the quarantine store.
//!
//! The write-ahead record is durable before moving the only copy of the
//! payload. Readers recognize a completed move even if publishing `.json`
//! was interrupted. Pending records never authorize removing the original.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Serialize, de::DeserializeOwned};

use super::{
    QuarantineRecord, QuarantineStore, QuarantineUnavailable, RestoreOutcome, device_of, now_secs,
};
use crate::core::errors::{Result, SbhError};

const MAX_RECORD_BYTES: u64 = 1024 * 1024;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(super) fn validate_id(id: &str) -> io::Result<()> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(invalid("invalid quarantine decision id"));
    }
    Ok(())
}

fn pending_path(store: &QuarantineStore, id: &str) -> PathBuf {
    store.root().join(format!("{id}.pending"))
}

pub(super) fn has_pending_record(store: &QuarantineStore, id: &str) -> bool {
    pending_path(store, id).is_file()
}

fn exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

fn remove_file_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

// Lock the directory itself: this needs no lock-file allocation at ENOSPC,
// works across daemon/CLI processes, and disappears on process death. Never
// unlink a lock inode or wait indefinitely behind a slow pressure drain.
fn lock_store(root: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(root)?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "quarantine requires directory locking on this platform",
        ))
    }
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

// Syncing a new store itself does not persist its name in its parent. The
// root can be nested beneath newly created `.sbh` directories; persist every
// ancestor link before the payload can disappear from its original parent.
fn sync_store_ancestors(root: &Path) -> io::Result<()> {
    let root = std::path::absolute(root)?;
    for ancestor in root.ancestors() {
        sync_directory(ancestor)?;
    }
    Ok(())
}

// An existence check followed by rename is not enough: a rebuild can create
// the destination between the two. Both supported platforms have a kernel
// no-replace rename. Unsupported filesystems/platforms must refuse, never
// fall back to an overwrite-capable rename.
fn rename_noreplace(source: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use rustix::fs::{CWD, RenameFlags, renameat_with};
        renameat_with(CWD, source, CWD, destination, RenameFlags::NOREPLACE)?;
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (source, destination);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic no-replace rename is unavailable on this platform",
        ))
    }
}

pub(super) fn read_json<T: DeserializeOwned>(path: &Path) -> io::Result<T> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // NONBLOCK keeps a replaced manifest FIFO from hanging the daemon.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_RECORD_BYTES {
        return Err(invalid("quarantine metadata is not a bounded regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(invalid("quarantine metadata grew beyond the size limit"));
    }
    serde_json::from_slice(&bytes).map_err(io::Error::from)
}

fn write_new_json(path: &Path, value: &impl Serialize) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(invalid("quarantine metadata exceeds the size limit"));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let result = file.write_all(&bytes).and_then(|()| file.sync_all());
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

// Replace bookkeeping atomically rather than following a forged .stuck
// symlink. A unique, exclusively-created temporary file also avoids writers
// sharing/truncating one another's staging file.
pub(super) fn write_json(path: &Path, value: &impl Serialize) -> io::Result<()> {
    let tmp = path.with_extension(format!(
        "{}-{}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ));
    write_new_json(&tmp, value)?;
    let result = fs::rename(&tmp, path);
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}

fn validate_record(store: &QuarantineStore, id: &str, record: &QuarantineRecord) -> io::Result<()> {
    validate_id(id)?;
    if record.decision_id != id {
        return Err(invalid("quarantine record id does not match its filename"));
    }
    let name = record
        .original_path
        .file_name()
        .ok_or_else(|| invalid("original has no basename"))?;
    let expected = std::path::absolute(store.entry_dir(id).join(name))?;
    if std::path::absolute(&record.quarantine_path)? != expected {
        return Err(invalid(
            "quarantine payload path escapes its decision directory",
        ));
    }
    if std::path::absolute(&record.original_path)?.starts_with(std::path::absolute(store.root())?) {
        return Err(invalid("quarantine origin is inside the quarantine store"));
    }
    Ok(())
}

// Keep layout validation separate from identity validation. Damaged entries
// still appear in inventories and produce per-entry failures during a drain;
// one such entry must never prevent the healthy entries from draining.
fn payload_metadata(
    store: &QuarantineStore,
    record: &QuarantineRecord,
) -> io::Result<Option<fs::Metadata>> {
    let dir = store.entry_dir(&record.decision_id);
    match fs::symlink_metadata(&dir) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err(invalid("quarantine entry directory was replaced")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    }
    let metadata = match fs::symlink_metadata(&record.quarantine_path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if (!metadata.is_file() && !metadata.is_dir())
        || device_of(&record.quarantine_path)? != (record.device_id, record.inode)
    {
        return Err(invalid(
            "quarantine payload identity changed; refusing to move or purge it",
        ));
    }
    Ok(Some(metadata))
}

fn read_manifest(store: &QuarantineStore, id: &str) -> Result<Option<(QuarantineRecord, bool)>> {
    validate_id(id).map_err(|e| SbhError::io(store.root(), e))?;
    let path = store.record_path(id);
    let (record, pending) = match read_json::<QuarantineRecord>(&path) {
        Ok(record) => (record, false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let pending = pending_path(store, id);
            match read_json::<QuarantineRecord>(&pending) {
                Ok(record) => (record, true),
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(SbhError::io(&pending, e)),
            }
        }
        Err(e) => return Err(SbhError::io(&path, e)),
    };
    validate_record(store, id, &record).map_err(|e| SbhError::io(&path, e))?;
    Ok(Some((record, pending)))
}

pub(super) fn read_record(store: &QuarantineStore, id: &str) -> Result<Option<QuarantineRecord>> {
    let Some((record, pending)) = read_manifest(store, id)? else {
        return Ok(None);
    };
    if pending
        && payload_metadata(store, &record)
            .map_err(|e| SbhError::io(&record.quarantine_path, e))?
            .is_none()
    {
        // The process stopped before the rename. This record is not held
        // space and never authorizes deletion of the still-live original.
        return Ok(None);
    }
    Ok(Some(record))
}

// An interrupted reservation may be retried only while its exact original
// is still present and no payload was moved. Empty-directory removal refuses
// unknown siblings; neither a rebuilt original nor unrelated bytes are touched.
fn recover_reservation(store: &QuarantineStore, id: &str, source: &Path) -> io::Result<()> {
    let pending = pending_path(store, id);
    if !exists(&pending)? {
        return Ok(());
    }
    let record = read_json::<QuarantineRecord>(&pending)?;
    validate_record(store, id, &record)?;
    if std::path::absolute(source)? != std::path::absolute(&record.original_path)?
        || device_of(source)? != (record.device_id, record.inode)
        || payload_metadata(store, &record)?.is_some()
    {
        return Err(invalid(
            "pending quarantine belongs to a different or completed move",
        ));
    }
    match fs::remove_dir(store.entry_dir(id)) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    remove_file_if_present(&pending)?;
    sync_directory(store.root())
}

pub(super) fn quarantine(
    store: &QuarantineStore,
    path: &Path,
    id: &str,
    size_bytes: u64,
    ttl: Duration,
    decision: Option<serde_json::Value>,
) -> std::result::Result<QuarantineRecord, QuarantineUnavailable> {
    let unavailable = |e: io::Error| QuarantineUnavailable::RootUnavailable(e.to_string());
    validate_id(id).map_err(unavailable)?;
    store.ensure_root()?;
    let lock = lock_store(store.root()).map_err(unavailable)?;
    let metadata = fs::symlink_metadata(path).map_err(unavailable)?;
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(unavailable(invalid(
            "candidate is not a regular file or directory",
        )));
    }
    let (dev, ino) = device_of(path).map_err(unavailable)?;
    if dev != device_of(store.root()).map_err(unavailable)?.0 {
        return Err(QuarantineUnavailable::CrossDevice);
    }
    let name = path
        .file_name()
        .ok_or_else(|| unavailable(invalid("candidate has no file name")))?;
    let manifest = store.record_path(id);
    let pending = pending_path(store, id);
    if exists(&manifest).map_err(unavailable)? {
        return Err(unavailable(invalid(
            "decision id already has a quarantine record",
        )));
    }
    recover_reservation(store, id, path).map_err(unavailable)?;
    let dir = store.entry_dir(id);
    let timestamp = now_secs();
    let record = QuarantineRecord {
        decision_id: id.to_string(),
        original_path: std::path::absolute(path).map_err(unavailable)?,
        quarantine_path: std::path::absolute(dir.join(name)).map_err(unavailable)?,
        device_id: dev,
        inode: ino,
        size_bytes,
        quarantined_at: timestamp,
        expires_at: timestamp.saturating_add(ttl.as_secs()),
        decision,
    };
    validate_record(store, id, &record).map_err(unavailable)?;
    // Reserving the whole decision directory, not just its basename, stops
    // a reused id from orphaning an earlier payload with a different name.
    fs::create_dir(&dir).map_err(unavailable)?;
    if let Err(e) =
        write_new_json(&pending, &record).and_then(|()| sync_store_ancestors(store.root()))
    {
        let _ = fs::remove_file(&pending);
        let _ = fs::remove_dir(&dir);
        return Err(unavailable(e));
    }
    if let Err(e) = rename_noreplace(path, &record.quarantine_path) {
        let _ = fs::remove_file(&pending);
        let _ = fs::remove_dir(&dir);
        return Err(QuarantineUnavailable::RenameFailed(e.to_string()));
    }
    // After the move, NEVER return a failure that makes the executor unlink
    // a newly recreated original. The durable pending record is sufficient
    // for inventory, undo, and drain even if finalization cannot complete.
    let finish = || -> io::Result<()> {
        sync_directory(&dir)?;
        if let Some(parent) = record.original_path.parent() {
            sync_directory(parent)?;
        }
        rename_noreplace(&pending, &manifest)?;
        lock.sync_all()
    };
    if let Err(e) = finish() {
        eprintln!("[SBH-QUARANTINE] {id} moved; retaining recovery metadata: {e}");
    }
    Ok(record)
}

fn remove_records(store: &QuarantineStore, id: &str) -> io::Result<()> {
    remove_file_if_present(&store.record_path(id))?;
    remove_file_if_present(&pending_path(store, id))?;
    store.clear_stuck(id);
    Ok(())
}

pub(super) fn purge(store: &QuarantineStore, id: &str) -> Result<u64> {
    validate_id(id).map_err(|e| SbhError::io(store.root(), e))?;
    let lock = match lock_store(store.root()) {
        Ok(lock) => lock,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(SbhError::io(store.root(), e)),
    };
    let Some(record) = read_record(store, id)? else {
        store.clear_stuck(id);
        return Ok(0);
    };
    let metadata =
        payload_metadata(store, &record).map_err(|e| SbhError::io(&record.quarantine_path, e))?;
    let bytes = if let Some(metadata) = metadata {
        // Only the recorded payload is authorized, not arbitrary siblings
        // subsequently placed in the decision directory.
        let result = if metadata.is_dir() {
            fs::remove_dir_all(&record.quarantine_path)
        } else {
            fs::remove_file(&record.quarantine_path)
        };
        result.map_err(|e| SbhError::io(&record.quarantine_path, e))?;
        record.size_bytes
    } else {
        // Interrupted cleanup or a prior undo did not free these bytes now.
        0
    };
    // Persist the payload removal before dropping its recovery record. A
    // crash must not resurrect a payload after its manifest has disappeared.
    sync_existing_directory(&store.entry_dir(id))
        .map_err(|e| SbhError::io(store.entry_dir(id), e))?;
    remove_records(store, id).map_err(|e| SbhError::io(store.record_path(id), e))?;
    let _ = fs::remove_dir(store.entry_dir(id));
    lock.sync_all().map_err(|e| SbhError::io(store.root(), e))?;
    Ok(bytes)
}

fn sync_existing_directory(path: &Path) -> io::Result<()> {
    match sync_directory(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn suffixed_destination(record: &QuarantineRecord) -> PathBuf {
    let mut destination = record.original_path.clone();
    let mut name = destination.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".restored-{}", record.decision_id));
    destination.set_file_name(name);
    destination
}

fn restored_destination(record: &QuarantineRecord) -> Option<PathBuf> {
    [record.original_path.clone(), suffixed_destination(record)]
        .into_iter()
        .find(|path| {
            fs::symlink_metadata(path).is_ok_and(|m| m.is_file() || m.is_dir())
                && device_of(path).ok() == Some((record.device_id, record.inode))
        })
}

fn finish_restore(store: &QuarantineStore, id: &str, destination: &Path, lock: &File) {
    let finish = || -> io::Result<()> {
        if let Some(parent) = destination.parent() {
            sync_directory(parent)?;
        }
        sync_existing_directory(&store.entry_dir(id))?;
        remove_records(store, id)?;
        let _ = fs::remove_dir(store.entry_dir(id));
        lock.sync_all()
    };
    if let Err(e) = finish() {
        eprintln!("[SBH-QUARANTINE] {id} restored; metadata cleanup deferred: {e}");
    }
}

pub(super) fn restore(
    store: &QuarantineStore,
    id: &str,
    force_suffix: bool,
) -> Result<RestoreOutcome> {
    validate_id(id).map_err(|e| SbhError::io(store.root(), e))?;
    let lock = lock_store(store.root()).map_err(|e| SbhError::io(store.root(), e))?;
    // Include pending manifests even without a held payload: explicit undo
    // can cancel an unmoved reservation or finish an interrupted pending
    // restore, but only when the exact original inode is already in place.
    let Some((record, _)) = read_manifest(store, id)? else {
        return Err(SbhError::Runtime {
            details: format!("no quarantined entry for decision {id}"),
        });
    };
    if payload_metadata(store, &record)
        .map_err(|e| SbhError::io(&record.quarantine_path, e))?
        .is_none()
    {
        // Undo may have completed its rename before the process stopped.
        // Recognize that exact inode, including a force-suffix destination,
        // rather than moving or overwriting a newly rebuilt original.
        let destination = restored_destination(&record).ok_or_else(|| SbhError::Runtime {
            details: format!("quarantined entry for {id} is gone"),
        })?;
        finish_restore(store, id, &destination, &lock);
        return Ok(RestoreOutcome {
            decision_id: id.to_string(),
            restored_to: destination,
            size_bytes: record.size_bytes,
        });
    }
    let mut destination = record.original_path.clone();
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|e| SbhError::io(parent, e))?;
    }
    match rename_noreplace(&record.quarantine_path, &destination) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            if !force_suffix {
                return Err(SbhError::Runtime {
                    details: format!(
                        "{} exists again; pass --force-suffix to restore next to it",
                        destination.display()
                    ),
                });
            }
            destination = suffixed_destination(&record);
            rename_noreplace(&record.quarantine_path, &destination)
                .map_err(|e| SbhError::io(&destination, e))?;
        }
        Err(e) => return Err(SbhError::io(&destination, e)),
    }
    finish_restore(store, id, &destination, &lock);
    Ok(RestoreOutcome {
        decision_id: id.to_string(),
        restored_to: destination,
        size_bytes: record.size_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(base: &Path, id: &str) -> (QuarantineStore, QuarantineRecord) {
        let store = QuarantineStore::under(base);
        let source = base.join(format!("target-{id}"));
        fs::write(&source, b"original bytes").unwrap();
        let record = store
            .quarantine(&source, id, 100, Duration::from_secs(0), None)
            .unwrap();
        (store, record)
    }

    #[test]
    fn a_completed_move_with_only_pending_metadata_is_restorable_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (store, record) = held(dir.path(), "pending");
        // Crash immediately after moving the payload, before publishing JSON.
        fs::rename(
            store.record_path("pending"),
            pending_path(&store, "pending"),
        )
        .unwrap();
        let reopened = QuarantineStore::at(store.root().to_path_buf());
        assert_eq!(reopened.records().unwrap(), vec![record.clone()]);
        assert_eq!(reopened.held_bytes().unwrap(), 100);
        reopened.restore("pending", false).unwrap();
        assert_eq!(fs::read(&record.original_path).unwrap(), b"original bytes");
        assert!(!pending_path(&store, "pending").exists());
    }

    #[test]
    fn pending_before_the_move_never_authorizes_deleting_the_original() {
        let dir = tempfile::tempdir().unwrap();
        let (store, record) = held(dir.path(), "before");
        fs::rename(store.record_path("before"), pending_path(&store, "before")).unwrap();
        fs::rename(&record.quarantine_path, &record.original_path).unwrap();
        assert!(store.record("before").unwrap().is_none());
        assert_eq!(store.held_bytes().unwrap(), 0);
        assert_eq!(store.drain_all().unwrap().bytes, 0);
        let outcome = store.restore("before", false).unwrap();
        assert_eq!(outcome.restored_to, record.original_path);
        assert_eq!(fs::read(&record.original_path).unwrap(), b"original bytes");
        assert!(!pending_path(&store, "before").exists());
    }

    #[test]
    fn pressure_can_drain_a_completed_pending_move() {
        let dir = tempfile::tempdir().unwrap();
        let (store, record) = held(dir.path(), "pressure");
        fs::rename(
            store.record_path("pressure"),
            pending_path(&store, "pressure"),
        )
        .unwrap();
        assert_eq!(store.drain_all().unwrap().bytes, 100);
        assert!(!record.quarantine_path.exists());
        assert!(!pending_path(&store, "pressure").exists());
    }

    #[test]
    fn duplicate_decision_id_never_overwrites_an_earlier_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let (store, record) = held(dir.path(), "same");
        let second = dir.path().join("different-basename");
        fs::write(&second, b"second payload").unwrap();
        assert!(
            store
                .quarantine(&second, "same", 200, Duration::ZERO, None)
                .is_err()
        );
        assert_eq!(store.record("same").unwrap(), Some(record.clone()));
        assert_eq!(fs::read(second).unwrap(), b"second payload");
        store.restore("same", false).unwrap();
        assert_eq!(fs::read(record.original_path).unwrap(), b"original bytes");
    }

    #[test]
    fn invalid_ids_are_rejected_before_creating_or_removing_anything() {
        let dir = tempfile::tempdir().unwrap();
        let store = QuarantineStore::under(dir.path());
        let source = dir.path().join("target");
        fs::write(&source, b"keep").unwrap();
        for id in ["", ".", "..", "../outside", "/absolute", "x/y", "x\\y"] {
            assert!(
                store
                    .quarantine(&source, id, 1, Duration::ZERO, None)
                    .is_err()
            );
            assert!(store.purge(id).is_err());
            assert!(store.restore(id, true).is_err());
            assert!(store.record(id).is_err());
        }
        assert!(!store.root().exists());
        assert_eq!(fs::read(source).unwrap(), b"keep");
    }

    #[test]
    fn suffix_restore_never_overwrites_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let (store, record) = held(dir.path(), "suffix");
        fs::write(&record.original_path, b"new build").unwrap();
        let suffix = dir.path().join("target-suffix.restored-suffix");
        fs::write(&suffix, b"previous recovery").unwrap();
        assert!(store.restore("suffix", true).is_err());
        assert_eq!(fs::read(suffix).unwrap(), b"previous recovery");
        assert_eq!(fs::read(record.original_path).unwrap(), b"new build");
        assert_eq!(fs::read(record.quarantine_path).unwrap(), b"original bytes");
        assert!(store.record("suffix").unwrap().is_some());
    }

    #[test]
    fn replaced_payload_is_neither_restored_nor_purged() {
        let dir = tempfile::tempdir().unwrap();
        let (store, record) = held(dir.path(), "replaced");
        let saved = dir.path().join("saved-original");
        fs::rename(&record.quarantine_path, &saved).unwrap();
        fs::write(&record.quarantine_path, b"unrelated replacement").unwrap();
        assert!(store.restore("replaced", false).is_err());
        assert!(store.purge("replaced").is_err());
        let out = store.drain_all().unwrap();
        assert_eq!(out.bytes, 0);
        assert_eq!(out.failures.len(), 1);
        assert_eq!(
            fs::read(record.quarantine_path).unwrap(),
            b"unrelated replacement"
        );
        assert_eq!(fs::read(saved).unwrap(), b"original bytes");
    }

    #[test]
    fn an_unrecorded_sibling_is_not_part_of_the_purge() {
        let dir = tempfile::tempdir().unwrap();
        let (store, record) = held(dir.path(), "sibling");
        let other = store.entry_dir("sibling").join("unrelated");
        fs::write(&other, b"not approved for deletion").unwrap();
        assert_eq!(store.purge("sibling").unwrap(), 100);
        assert!(!record.quarantine_path.exists());
        assert_eq!(fs::read(other).unwrap(), b"not approved for deletion");
    }

    #[test]
    fn an_already_absent_payload_does_not_claim_reclaimed_bytes_again() {
        let dir = tempfile::tempdir().unwrap();
        let (store, record) = held(dir.path(), "gone");
        fs::remove_file(record.quarantine_path).unwrap();
        assert_eq!(store.purge("gone").unwrap(), 0);
        assert!(store.record("gone").unwrap().is_none());
    }

    #[test]
    fn records_cannot_redirect_restore_or_purge_outside_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let (store, mut record) = held(dir.path(), "forged");
        let outside = dir.path().join("unrelated");
        fs::write(&outside, b"precious").unwrap();
        record.quarantine_path.clone_from(&outside);
        write_json(&store.record_path("forged"), &record).unwrap();
        assert!(store.record("forged").is_err());
        assert!(store.restore("forged", false).is_err());
        assert!(store.purge("forged").is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"precious");
        record.decision_id = "../unrelated".to_string();
        write_json(&store.record_path("forged"), &record).unwrap();
        assert!(store.record("forged").is_err());
        assert_eq!(store.drain_all().unwrap().bytes, 0);
        assert_eq!(fs::read(outside).unwrap(), b"precious");
    }

    #[test]
    fn a_busy_store_refuses_mutations_and_the_lock_releases_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let (store, record) = held(dir.path(), "locked");
        let lock = lock_store(store.root()).unwrap();
        assert!(store.restore("locked", false).is_err());
        assert!(store.purge("locked").is_err());
        assert!(record.quarantine_path.exists());
        drop(lock);
        store.restore("locked", false).unwrap();
        assert!(record.original_path.exists());
    }

    #[test]
    fn metadata_failure_leaves_the_source_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let store = QuarantineStore::under(dir.path());
        let source = dir.path().join("target");
        fs::write(&source, b"only copy").unwrap();
        let oversized = serde_json::Value::String("x".repeat(1024 * 1024));
        assert!(
            store
                .quarantine(&source, "huge", 9, Duration::ZERO, Some(oversized))
                .is_err()
        );
        assert_eq!(fs::read(source).unwrap(), b"only copy");
        assert!(!pending_path(&store, "huge").exists());
        assert!(!store.entry_dir("huge").exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_metadata_and_entry_directories_are_refused() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let (store, record) = held(dir.path(), "symlink");
        let saved = dir.path().join("saved-dir");
        fs::rename(store.entry_dir("symlink"), &saved).unwrap();
        symlink(&saved, store.entry_dir("symlink")).unwrap();
        assert!(store.restore("symlink", false).is_err());
        assert!(store.purge("symlink").is_err());
        assert_eq!(
            fs::read(saved.join("target-symlink")).unwrap(),
            b"original bytes"
        );
        let manifest = store.record_path("symlink");
        let saved_manifest = dir.path().join("saved-manifest");
        fs::rename(&manifest, &saved_manifest).unwrap();
        symlink(&saved_manifest, &manifest).unwrap();
        assert!(store.record("symlink").is_err());
        assert!(!record.original_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn dangling_suffix_symlinks_are_not_overwritten() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let (store, record) = held(dir.path(), "dangling");
        fs::write(&record.original_path, b"rebuilt").unwrap();
        let suffix = dir.path().join("target-dangling.restored-dangling");
        symlink("missing-destination", &suffix).unwrap();
        assert!(store.restore("dangling", true).is_err());
        assert_eq!(
            fs::read_link(suffix).unwrap(),
            Path::new("missing-destination")
        );
        assert!(record.quarantine_path.exists());
    }

    #[test]
    fn retrying_an_interrupted_undo_finishes_metadata_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let (store, record) = held(dir.path(), "retry-undo");
        fs::rename(&record.quarantine_path, &record.original_path).unwrap();
        let outcome = store.restore("retry-undo", false).unwrap();
        assert_eq!(outcome.restored_to, record.original_path);
        assert_eq!(fs::read(outcome.restored_to).unwrap(), b"original bytes");
        assert!(store.record("retry-undo").unwrap().is_none());
    }

    #[test]
    fn retrying_an_interrupted_suffix_undo_preserves_the_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let (store, record) = held(dir.path(), "retry-suffix");
        fs::write(&record.original_path, b"new build").unwrap();
        let destination = suffixed_destination(&record);
        fs::rename(&record.quarantine_path, &destination).unwrap();
        let outcome = store.restore("retry-suffix", true).unwrap();
        assert_eq!(outcome.restored_to, destination);
        assert_eq!(fs::read(destination).unwrap(), b"original bytes");
        assert_eq!(fs::read(record.original_path).unwrap(), b"new build");
        assert!(store.record("retry-suffix").unwrap().is_none());
    }

    #[test]
    fn missing_payload_and_a_different_original_are_not_a_completed_undo() {
        let dir = tempfile::tempdir().unwrap();
        let (store, record) = held(dir.path(), "not-restored");
        fs::rename(&record.quarantine_path, dir.path().join("saved")).unwrap();
        fs::write(&record.original_path, b"different inode").unwrap();
        assert!(store.restore("not-restored", true).is_err());
        assert!(store.record("not-restored").unwrap().is_some());
        assert_eq!(fs::read(record.original_path).unwrap(), b"different inode");
    }

    #[test]
    fn a_reservation_interrupted_before_the_move_can_be_retried() {
        let dir = tempfile::tempdir().unwrap();
        let (store, record) = held(dir.path(), "retry-reservation");
        fs::rename(
            store.record_path("retry-reservation"),
            pending_path(&store, "retry-reservation"),
        )
        .unwrap();
        fs::rename(&record.quarantine_path, &record.original_path).unwrap();
        let new_record = store
            .quarantine(
                &record.original_path,
                "retry-reservation",
                100,
                Duration::ZERO,
                None,
            )
            .unwrap();
        assert_eq!(new_record.inode, record.inode);
        assert!(new_record.quarantine_path.exists());
        assert!(!new_record.original_path.exists());
        assert!(!pending_path(&store, "retry-reservation").exists());
    }

    #[test]
    fn reservation_recovery_never_discards_unrecognized_siblings() {
        let dir = tempfile::tempdir().unwrap();
        let (store, record) = held(dir.path(), "reserved");
        fs::rename(
            store.record_path("reserved"),
            pending_path(&store, "reserved"),
        )
        .unwrap();
        fs::rename(&record.quarantine_path, &record.original_path).unwrap();
        let unknown = store.entry_dir("reserved").join("unrecognized");
        fs::write(&unknown, b"preserve").unwrap();
        assert!(
            store
                .quarantine(&record.original_path, "reserved", 100, Duration::ZERO, None)
                .is_err()
        );
        assert_eq!(fs::read(unknown).unwrap(), b"preserve");
        assert_eq!(fs::read(record.original_path).unwrap(), b"original bytes");
        assert!(pending_path(&store, "reserved").exists());
    }

    #[test]
    fn relative_source_paths_remain_findable_after_absolute_recording() {
        let cwd = std::env::current_dir().unwrap();
        let dir = tempfile::tempdir_in(&cwd).unwrap();
        let store = QuarantineStore::under(dir.path());
        let source = dir.path().join("relative-target");
        let relative = source.strip_prefix(&cwd).unwrap();
        fs::write(&source, b"relative bytes").unwrap();
        let record = store
            .quarantine(relative, "relative", 14, Duration::ZERO, None)
            .unwrap();
        assert_eq!(record.original_path, source);
        assert_eq!(store.record_for_path(relative).unwrap(), Some(record));
        store.restore("relative", false).unwrap();
        assert_eq!(fs::read(source).unwrap(), b"relative bytes");
    }

    #[test]
    fn pending_undo_can_finish_after_the_payload_was_restored() {
        let dir = tempfile::tempdir().unwrap();
        let (store, record) = held(dir.path(), "pending-undo");
        fs::rename(
            store.record_path("pending-undo"),
            pending_path(&store, "pending-undo"),
        )
        .unwrap();
        fs::write(&record.original_path, b"new build").unwrap();
        let destination = suffixed_destination(&record);
        fs::rename(&record.quarantine_path, &destination).unwrap();
        let outcome = store.restore("pending-undo", true).unwrap();
        assert_eq!(outcome.restored_to, destination);
        assert_eq!(fs::read(destination).unwrap(), b"original bytes");
        assert_eq!(fs::read(record.original_path).unwrap(), b"new build");
        assert!(!pending_path(&store, "pending-undo").exists());
    }

    #[test]
    fn pending_recovery_refuses_a_rebuilt_original() {
        let dir = tempfile::tempdir().unwrap();
        let (store, record) = held(dir.path(), "pending-rebuilt");
        fs::rename(
            store.record_path("pending-rebuilt"),
            pending_path(&store, "pending-rebuilt"),
        )
        .unwrap();
        fs::rename(&record.quarantine_path, dir.path().join("saved")).unwrap();
        fs::write(&record.original_path, b"different inode").unwrap();
        assert!(store.restore("pending-rebuilt", true).is_err());
        assert!(
            store
                .quarantine(
                    &record.original_path,
                    "pending-rebuilt",
                    100,
                    Duration::ZERO,
                    None,
                )
                .is_err()
        );
        assert_eq!(fs::read(record.original_path).unwrap(), b"different inode");
        assert!(pending_path(&store, "pending-rebuilt").exists());
    }
}
