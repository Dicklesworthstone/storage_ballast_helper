//! Transaction and identity boundaries for the quarantine store.
//!
//! The write-ahead record is durable before moving the only copy of the
//! payload. Readers recognize a completed move even if publishing `.json`
//! was interrupted. Pending records never authorize removing the original.
//! Payload transfers and record finalization share opened directory anchors;
//! replacing a parent pathname cannot redirect the subsequent rename or unlink.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Serialize, de::DeserializeOwned};

use super::budget::PurgeBudget;
use super::{
    QuarantineCompletion, QuarantineRecord, QuarantineStore, QuarantineUnavailable, RecoveryState,
    RestoreOutcome, now_secs,
};
use crate::core::errors::{Result, SbhError};

#[cfg(unix)]
#[path = "beneath.rs"]
mod beneath;
#[path = "purge.rs"]
mod confined_purge;
#[path = "transaction.rs"]
mod transaction;

#[cfg(all(target_os = "linux", feature = "daemon"))]
pub use beneath::mount_id;
#[cfg(unix)]
pub use beneath::open_beneath;
pub use confined_purge::remove_direct;
use transaction::{Directory, Kind, Payload};

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

// Lock the directory itself: this needs no lock-file allocation at ENOSPC,
// works across daemon/CLI processes, and disappears on process death. Never
// unlink a lock inode or wait indefinitely behind a slow pressure drain.
struct StoreLock {
    file: File,
    owner_pid: u32,
}

impl std::ops::Deref for StoreLock {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        &self.file
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        if self.owner_pid == std::process::id() {
            // Closing alone leaves the flock held by any inherited copy of
            // the open file description. End THIS process's lock scope even
            // if a child is still between fork and exec. An inherited guard
            // in a different PID must not unlock its parent's active scope.
            let _ = rustix::fs::flock(&self.file, rustix::fs::FlockOperation::Unlock);
        }
    }
}

fn lock_store(root: &Path) -> io::Result<StoreLock> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(root)?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
        Ok(StoreLock {
            file,
            owner_pid: std::process::id(),
        })
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
    decode_json(file)
}

fn decode_json<T: DeserializeOwned>(file: File) -> io::Result<T> {
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

pub(super) fn read_record(store: &QuarantineStore, id: &str) -> Result<Option<QuarantineRecord>> {
    validate_id(id).map_err(|e| SbhError::io(store.root(), e))?;
    let root = match Directory::open_store(store.root()) {
        Ok(root) => root,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(SbhError::io(store.root(), e)),
    };
    read_record_at(store, id, &root)
}

fn read_manifest_at(
    store: &QuarantineStore,
    id: &str,
    root: &Directory,
) -> Result<Option<(QuarantineRecord, bool)>> {
    validate_id(id).map_err(|e| SbhError::io(store.root(), e))?;
    let ((mut record, manifest_identity), pending) =
        match root.read_json_identified::<QuarantineRecord>(OsStr::new(&format!("{id}.json"))) {
            Ok(record) => (record, false),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                match root
                    .read_json_identified::<QuarantineRecord>(OsStr::new(&format!("{id}.pending")))
                {
                    Ok(record) => (record, true),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                    Err(e) => return Err(SbhError::io(pending_path(store, id), e)),
                }
            }
            Err(e) => return Err(SbhError::io(store.record_path(id), e)),
        };
    validate_record(store, id, &record).map_err(|e| SbhError::io(store.record_path(id), e))?;
    if record.recovery_state.is_intact() {
        let witness = root
            .inspect(OsStr::new(&format!("{id}.intact")))
            .map_err(|e| SbhError::io(store.root(), e))?;
        record.recovery_state = match witness {
            Some(identity) if identity.kind == Kind::File && identity == manifest_identity => {
                RecoveryState::Intact
            }
            None => RecoveryState::PurgeStarted,
            Some(_) => RecoveryState::Unknown,
        };
    }
    Ok(Some((record, pending)))
}

fn payload_at(root: &Directory, record: &QuarantineRecord) -> io::Result<Option<Payload>> {
    let entry = match root.child(OsStr::new(&record.decision_id)) {
        Ok(entry) => entry,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let name = record
        .original_path
        .file_name()
        .ok_or_else(|| invalid("original has no basename"))?;
    let Some(payload) = Payload::observe(entry, name.to_os_string())? else {
        return Ok(None);
    };
    if !payload.identity.matches_record(record) {
        return Err(invalid(
            "quarantine payload identity changed; refusing transaction",
        ));
    }
    Ok(Some(payload))
}

fn read_record_at(
    store: &QuarantineStore,
    id: &str,
    root: &Directory,
) -> Result<Option<QuarantineRecord>> {
    let Some((record, pending)) = read_manifest_at(store, id, root)? else {
        return Ok(None);
    };
    if pending
        && payload_at(root, &record)
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
fn recover_reservation(
    store: &QuarantineStore,
    root: &Directory,
    id: &str,
    source_path: &Path,
    source: &Payload,
) -> io::Result<()> {
    let pending = format!("{id}.pending");
    if root.inspect(OsStr::new(&pending))?.is_none() {
        return Ok(());
    }
    let record = root.read_json::<QuarantineRecord>(OsStr::new(&pending))?;
    validate_record(store, id, &record)?;
    if source_path != std::path::absolute(&record.original_path)?.as_path()
        || !source.identity.matches_record(&record)
        || payload_at(root, &record)?.is_some()
    {
        return Err(invalid(
            "pending quarantine belongs to a different or completed move",
        ));
    }
    source.verify()?;
    root.remove_directory(OsStr::new(id))?;
    discard_linked_witness(root, id, OsStr::new(&pending))?;
    root.remove_file(OsStr::new(&pending))?;
    root.sync()
}

// Reservation rollback may remove only the witness attached to our manifest.
// An existing unrelated name must survive a failed exclusive admission.
fn discard_linked_witness(root: &Directory, id: &str, manifest: &OsStr) -> io::Result<()> {
    let expected = root.inspect(manifest)?;
    let witness = format!("{id}.intact");
    if expected.is_some_and(|identity| identity.kind == Kind::File)
        && root.inspect(OsStr::new(&witness))? == expected
    {
        root.remove_file(OsStr::new(&witness))?;
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TransactionStep {
    SourcePinned,
    Locked,
    Prepared,
    Moved,
}

pub(super) fn quarantine(
    store: &QuarantineStore,
    path: &Path,
    expected: &fs::Metadata,
    id: &str,
    size_bytes: u64,
    ttl: Duration,
    decision: Option<serde_json::Value>,
) -> std::result::Result<QuarantineRecord, QuarantineUnavailable> {
    quarantine_with_hook(
        store,
        path,
        expected,
        id,
        size_bytes,
        ttl,
        decision,
        &mut |_| {},
    )
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn quarantine_with_hook(
    store: &QuarantineStore,
    path: &Path,
    expected: &fs::Metadata,
    id: &str,
    size_bytes: u64,
    ttl: Duration,
    decision: Option<serde_json::Value>,
    hook: &mut impl FnMut(TransactionStep),
) -> std::result::Result<QuarantineRecord, QuarantineUnavailable> {
    let unavailable = |e: io::Error| QuarantineUnavailable::RootUnavailable(e.to_string());
    validate_id(id).map_err(unavailable)?;
    let original_path = std::path::absolute(path).map_err(unavailable)?;
    let source = Payload::open_checked(&original_path, expected).map_err(unavailable)?;
    hook(TransactionStep::SourcePinned);
    store.ensure_root()?;
    let lock = lock_store(store.root()).map_err(unavailable)?;
    let root = Directory::from_locked(&lock).map_err(unavailable)?;
    source.verify().map_err(unavailable)?;
    if source.identity.device != root.identity().map_err(unavailable)?.device {
        return Err(QuarantineUnavailable::CrossDevice);
    }
    source.parent.require_outside(&root).map_err(unavailable)?;
    hook(TransactionStep::Locked);
    let manifest = format!("{id}.json");
    let pending = format!("{id}.pending");
    if root
        .inspect(OsStr::new(&manifest))
        .map_err(unavailable)?
        .is_some()
    {
        return Err(unavailable(invalid(
            "decision id already has a quarantine record",
        )));
    }
    recover_reservation(store, &root, id, &original_path, &source).map_err(unavailable)?;
    let dir = store.entry_dir(id);
    let timestamp = now_secs();
    let record = QuarantineRecord {
        decision_id: id.to_string(),
        original_path,
        quarantine_path: std::path::absolute(dir.join(&source.name)).map_err(unavailable)?,
        device_id: source.identity.device,
        inode: source.identity.inode,
        size_bytes,
        quarantined_at: timestamp,
        expires_at: timestamp.saturating_add(ttl.as_secs()),
        recovery_state: RecoveryState::Intact,
        decision,
    };
    validate_record(store, id, &record).map_err(unavailable)?;
    // Reserving the whole decision directory, not just its basename, stops
    // a reused id from orphaning an earlier payload with a different name.
    let entry = root.create_directory(OsStr::new(id)).map_err(unavailable)?;
    if let Err(e) = root.write_new_json(OsStr::new(&pending), &record) {
        // The writer cleans only a file it exclusively created. EEXIST must
        // never remove somebody else's recovery record.
        let _ = root.remove_directory(OsStr::new(id));
        return Err(unavailable(e));
    }
    // A hard link to the existing manifest proves no purge has begun. Reserve
    // it before moving the payload; revocation later needs no free inode.
    if let Err(e) = root.link_file(OsStr::new(&pending), OsStr::new(&format!("{id}.intact"))) {
        discard_unmoved_reservation(&root, &entry, &source, &record);
        return Err(unavailable(e));
    }
    if let Err(e) = entry.sync().and_then(|()| root.sync_ancestors()) {
        discard_unmoved_reservation(&root, &entry, &source, &record);
        return Err(unavailable(e));
    }
    hook(TransactionStep::Prepared);
    let transfer = || -> io::Result<()> {
        root.require_path(store.root())?;
        entry.require_path(&dir)?;
        source.parent.require_path(
            record
                .original_path
                .parent()
                .ok_or_else(|| invalid("original has no parent"))?,
        )?;
        source.parent.require_outside(&root)?;
        source.move_to(&entry, &source.name)
    };
    if let Err(e) = transfer() {
        // An ambiguous filesystem failure is not proof that nothing moved.
        // Discard only when the exact source remains and the target is absent.
        discard_unmoved_reservation(&root, &entry, &source, &record);
        return Err(QuarantineUnavailable::RenameFailed(e.to_string()));
    }
    hook(TransactionStep::Moved);
    // After the move, NEVER return a failure that makes the executor unlink
    // a newly recreated original. The durable pending record is sufficient
    // for inventory, undo, and drain even if finalization cannot complete.
    let finish = || -> io::Result<()> {
        entry.sync()?;
        source.parent.sync()?;
        root.rename_noreplace(OsStr::new(&pending), &root, OsStr::new(&manifest))?;
        root.sync()
    };
    if let Err(e) = finish() {
        eprintln!("[SBH-QUARANTINE] {id} moved; retaining recovery metadata: {e}");
    }
    Ok(record)
}

fn discard_unmoved_reservation(
    root: &Directory,
    entry: &Directory,
    source: &Payload,
    record: &QuarantineRecord,
) {
    let pending = format!("{}.pending", record.decision_id);
    if source.verify().is_ok()
        && entry
            .inspect(&source.name)
            .is_ok_and(|payload| payload.is_none())
        && root
            .read_json::<QuarantineRecord>(OsStr::new(&pending))
            .is_ok_and(|current| current == *record)
    {
        let _ = discard_linked_witness(root, &record.decision_id, OsStr::new(&pending));
        let _ = root.remove_file(OsStr::new(&pending));
        let _ = root.remove_directory(OsStr::new(&record.decision_id));
        let _ = root.sync();
    }
}

fn remove_records_at(root: &Directory, id: &str) -> io::Result<()> {
    validate_id(id)?;
    // Revoke proof first: interruption must not leave a manifest that can
    // later claim intact contents after its payload was permanently removed.
    root.remove_file(OsStr::new(&format!("{id}.intact")))?;
    root.remove_file(OsStr::new(&format!("{id}.json")))?;
    root.remove_file(OsStr::new(&format!("{id}.pending")))?;
    // Stuck bookkeeping remains best-effort after guarded record cleanup.
    let _ = root.remove_file(OsStr::new(&format!("{id}.stuck")));
    Ok(())
}

// A new-format record keeps its intact proof in a hard link to the manifest.
// Removing and syncing that existing directory entry needs no new inode or
// manifest allocation, even when this purge is relieving inode exhaustion.
fn revoke_intact_witness(root: &Directory, record: &mut QuarantineRecord) -> io::Result<()> {
    revoke_intact_witness_with_sync(root, record, Directory::sync)
}

fn revoke_intact_witness_with_sync(
    root: &Directory,
    record: &mut QuarantineRecord,
    sync: impl FnOnce(&Directory) -> io::Result<()>,
) -> io::Result<()> {
    if payload_at(root, record)?.is_none() {
        return Ok(());
    }
    let witness = format!("{}.intact", record.decision_id);
    if !matches!(record.recovery_state, RecoveryState::Unknown)
        || root.inspect(OsStr::new(&witness))?.is_some()
    {
        root.remove_file(OsStr::new(&witness))?;
        // Repeat this barrier for PurgeStarted after a prior failed fsync:
        // seeing a missing witness does not yet prove its removal is durable.
        sync(root)?;
    }
    if !matches!(record.recovery_state, RecoveryState::Unknown) {
        record.recovery_state = RecoveryState::PurgeStarted;
    }
    Ok(())
}

#[derive(Debug, Default)]
pub(super) struct PurgeOutcome {
    pub(super) bytes: u64,
    pub(super) completed: Option<QuarantineCompletion>,
}

pub(super) fn purge(store: &QuarantineStore, id: &str) -> Result<u64> {
    purge_with(store, id, None, |lock, root, record| {
        revoke_intact_witness(root, record)?;
        confined_purge::remove_payload(lock, record).map(Some)
    })?
    .map(|outcome| outcome.bytes)
    .ok_or_else(|| SbhError::Runtime {
        details: "unlimited quarantine purge unexpectedly paused".to_string(),
    })
}

/// A budget pause or pressure hold returns `None`. Lock contention or changed
/// selection returns `WouldBlock`, which the batch layer defers without recording
/// a stuck entry. The selected TTL, identity and decision must still match under
/// the lock before pressure authority is renewed.
pub(super) fn purge_with_budget_and_gate(
    store: &QuarantineStore,
    selected: &QuarantineRecord,
    budget: &mut PurgeBudget,
    gate: &mut impl FnMut(&QuarantineRecord) -> bool,
) -> Result<Option<PurgeOutcome>> {
    if budget.exhausted() {
        return Ok(None);
    }
    purge_with(
        store,
        &selected.decision_id,
        Some(selected),
        |lock, root, record| {
            if !gate(record) {
                return Ok(None);
            }
            revoke_intact_witness(root, record)?;
            // Revocation includes durable I/O. Capacity and resource authority
            // must still hold afterwards, before any payload unlink begins.
            if !gate(record) {
                return Ok(None);
            }
            let record = &*record;
            // Renew at bounded mutation checkpoints rather than issuing an
            // expensive filesystem-capacity probe for every small child.
            let mut remaining_unlinks = super::budget::PRESSURE_RECHECK_UNLINKS;
            let mut renew = || {
                if remaining_unlinks == 0 {
                    if !gate(record) {
                        return false;
                    }
                    remaining_unlinks = super::budget::PRESSURE_RECHECK_UNLINKS;
                }
                remaining_unlinks -= 1;
                true
            };
            confined_purge::remove_payload_with_budget_and_gate(lock, record, budget, &mut renew)
        },
    )
}

fn purge_with(
    store: &QuarantineStore,
    id: &str,
    selected: Option<&QuarantineRecord>,
    remove: impl FnOnce(&File, &Directory, &mut QuarantineRecord) -> io::Result<Option<bool>>,
) -> Result<Option<PurgeOutcome>> {
    validate_id(id).map_err(|e| SbhError::io(store.root(), e))?;
    let lock = match lock_store(store.root()) {
        Ok(lock) => lock,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(Some(PurgeOutcome::default()));
        }
        Err(e) => return Err(SbhError::io(store.root(), e)),
    };
    let root = Directory::from_locked(&lock).map_err(|e| SbhError::io(store.root(), e))?;
    let Some(mut record) = read_record_at(store, id, &root)? else {
        let _ = root.remove_file(std::ffi::OsStr::new(&format!("{id}.stuck")));
        return Ok(Some(PurgeOutcome::default()));
    };
    if selected.is_some_and(|selected| selected != &record) {
        // Inventory is read before locking: another cooperating operation can
        // restore/reuse this ID or extend its TTL meanwhile. The fresh inode
        // matching its NEW manifest does not validate the OLD drain decision.
        // A later batch must select the new record on its own terms.
        return Err(SbhError::io(
            store.root(),
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "quarantine record changed after selection; retry with fresh inventory",
            ),
        ));
    }
    // Resolve the payload from the locked store descriptor, not a pathname
    // checked earlier. Nested mounts are not part of a quarantined artifact.
    // On refusal keep its manifest so later drains/undo can recover what
    // remains; never fall back to unrestricted recursive removal.
    let Some(removed) =
        remove(&lock, &root, &mut record).map_err(|e| SbhError::io(&record.quarantine_path, e))?
    else {
        return Ok(None);
    };
    let completed_at = removed.then(SystemTime::now);
    let bytes = if removed {
        record.size_bytes
    } else {
        // Interrupted cleanup or a prior undo did not free these bytes now.
        0
    };
    // The confined remover synced the opened payload parent before this
    // point, including an already-absent payload from an interrupted purge.
    remove_records_at(&root, id).map_err(|e| SbhError::io(store.record_path(id), e))?;
    let _ = root.remove_directory(std::ffi::OsStr::new(id));
    root.sync().map_err(|e| SbhError::io(store.root(), e))?;
    // Publish physical-removal evidence only after the whole transaction
    // succeeds. A later absent-payload retry must not invent a fresh unlink.
    Ok(Some(PurgeOutcome {
        bytes,
        completed: completed_at.map(|completed_at| QuarantineCompletion {
            record,
            completed_at,
        }),
    }))
}

fn suffixed_destination(record: &QuarantineRecord) -> PathBuf {
    let mut destination = record.original_path.clone();
    let mut name = destination.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".restored-{}", record.decision_id));
    destination.set_file_name(name);
    destination
}

fn restored_destination(record: &QuarantineRecord) -> Option<(PathBuf, Payload)> {
    [record.original_path.clone(), suffixed_destination(record)]
        .into_iter()
        .find_map(|path| {
            let payload = Payload::open(&path).ok()?;
            payload
                .identity
                .matches_record(record)
                .then_some((path, payload))
        })
}

fn finish_restore(root: &Directory, id: &str, source: Option<&Directory>, destination: &Directory) {
    let finish = || -> io::Result<()> {
        destination.sync_ancestors()?;
        if let Some(source) = source {
            source.sync()?;
        } else {
            match root.child(OsStr::new(id)) {
                Ok(entry) => entry.sync()?,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        remove_records_at(root, id)?;
        let _ = root.remove_directory(OsStr::new(id));
        root.sync()
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
    restore_with_hook(store, id, force_suffix, &mut |_| {})
}

fn restore_with_hook(
    store: &QuarantineStore,
    id: &str,
    force_suffix: bool,
    hook: &mut impl FnMut(TransactionStep),
) -> Result<RestoreOutcome> {
    validate_id(id).map_err(|e| SbhError::io(store.root(), e))?;
    let lock = lock_store(store.root()).map_err(|e| SbhError::io(store.root(), e))?;
    let root = Directory::from_locked(&lock).map_err(|e| SbhError::io(store.root(), e))?;
    hook(TransactionStep::Locked);
    // Include pending manifests even without a held payload: explicit undo
    // can cancel an unmoved reservation or finish an interrupted pending
    // restore, but only when the exact original inode is already in place.
    let Some((record, _)) = read_manifest_at(store, id, &root)? else {
        return Err(SbhError::Runtime {
            details: format!("no quarantined entry for decision {id}"),
        });
    };
    let Some(source) =
        payload_at(&root, &record).map_err(|e| SbhError::io(&record.quarantine_path, e))?
    else {
        // Undo may have completed its rename before the process stopped.
        // Recognize that exact inode, including a force-suffix destination,
        // rather than moving or overwriting a newly rebuilt original.
        let (destination, payload) =
            restored_destination(&record).ok_or_else(|| SbhError::Runtime {
                details: format!("quarantined entry for {id} is gone"),
            })?;
        payload
            .parent
            .require_outside(&root)
            .map_err(|e| SbhError::io(&destination, e))?;
        payload
            .verify()
            .map_err(|e| SbhError::io(&destination, e))?;
        finish_restore(&root, id, None, &payload.parent);
        return Ok(RestoreOutcome {
            decision_id: id.to_string(),
            restored_to: destination,
            original_size_bytes: record.size_bytes,
            size_bytes: record
                .recovery_state
                .is_intact()
                .then_some(record.size_bytes),
            completeness: record.recovery_state,
        });
    };
    let mut destination = record.original_path.clone();
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|e| SbhError::io(parent, e))?;
    }
    let (target, name) =
        Directory::parent_of(&destination).map_err(|e| SbhError::io(&destination, e))?;
    hook(TransactionStep::Prepared);
    let check = || -> io::Result<()> {
        root.require_path(store.root())?;
        source.parent.require_path(&store.entry_dir(id))?;
        target.require_path(
            destination
                .parent()
                .ok_or_else(|| invalid("restore has no parent"))?,
        )?;
        target.require_outside(&root)
    };
    check().map_err(|e| SbhError::io(&destination, e))?;
    match source.move_to(&target, &name) {
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
            let suffix = destination
                .file_name()
                .ok_or_else(|| SbhError::io(&destination, invalid("restore has no basename")))?;
            source
                .move_to(&target, suffix)
                .map_err(|e| SbhError::io(&destination, e))?;
        }
        Err(e) => return Err(SbhError::io(&destination, e)),
    }
    hook(TransactionStep::Moved);
    finish_restore(&root, id, Some(&source.parent), &target);
    Ok(RestoreOutcome {
        decision_id: id.to_string(),
        restored_to: destination,
        original_size_bytes: record.size_bytes,
        size_bytes: record
            .recovery_state
            .is_intact()
            .then_some(record.size_bytes),
        completeness: record.recovery_state,
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

    #[cfg(unix)]
    #[test]
    fn intact_recovery_requires_the_original_regular_manifest_witness() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let (store, record) = held(dir.path(), "intact-proof");
        let manifest = fs::symlink_metadata(store.record_path("intact-proof")).unwrap();
        let witness_path = store.root().join("intact-proof.intact");
        let witness = fs::symlink_metadata(&witness_path).unwrap();
        assert!(witness.is_file());
        assert_eq!(
            (manifest.dev(), manifest.ino()),
            (witness.dev(), witness.ino())
        );
        assert!(manifest.nlink() >= 2);

        let reopened = QuarantineStore::at(store.root().to_path_buf());
        assert_eq!(reopened.record("intact-proof").unwrap(), Some(record));
        let restored = reopened.restore("intact-proof", false).unwrap();
        assert_eq!(restored.completeness, RecoveryState::Intact);
        assert_eq!(restored.original_size_bytes, 100);
        assert_eq!(restored.size_bytes, Some(100));
        assert_eq!(fs::read(restored.restored_to).unwrap(), b"original bytes");
        assert!(fs::symlink_metadata(witness_path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn missing_copied_or_symlinked_witnesses_never_claim_intact_recovery() {
        use std::os::unix::fs::symlink;
        for (kind, expected) in [
            ("missing", RecoveryState::PurgeStarted),
            ("copied", RecoveryState::Unknown),
            ("symlinked", RecoveryState::Unknown),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (store, record) = held(dir.path(), "untrusted-proof");
            let witness = store.root().join("untrusted-proof.intact");
            fs::remove_file(&witness).unwrap();
            match kind {
                "copied" => {
                    fs::copy(store.record_path("untrusted-proof"), &witness).unwrap();
                }
                "symlinked" => {
                    symlink(store.record_path("untrusted-proof"), &witness).unwrap();
                }
                _ => {}
            }
            let reopened = QuarantineStore::at(store.root().to_path_buf());
            assert_eq!(
                reopened
                    .record("untrusted-proof")
                    .unwrap()
                    .unwrap()
                    .recovery_state,
                expected,
                "{kind}",
            );
            let restored = reopened.restore("untrusted-proof", false).unwrap();
            assert_eq!(restored.completeness, expected, "{kind}");
            assert_eq!(restored.size_bytes, None);
            assert_eq!(restored.original_size_bytes, record.size_bytes);
            assert_eq!(fs::read(restored.restored_to).unwrap(), b"original bytes");
            assert!(fs::symlink_metadata(witness).is_err());
        }
    }

    #[test]
    fn legacy_manifests_restore_available_contents_without_inventing_completeness() {
        let dir = tempfile::tempdir().unwrap();
        let (store, record) = held(dir.path(), "legacy-proof");
        let mut legacy = serde_json::to_value(&record).unwrap();
        legacy.as_object_mut().unwrap().remove("recovery_state");
        write_json(&store.record_path("legacy-proof"), &legacy).unwrap();
        fs::remove_file(store.root().join("legacy-proof.intact")).unwrap();

        let reopened = QuarantineStore::at(store.root().to_path_buf());
        assert_eq!(
            reopened
                .record("legacy-proof")
                .unwrap()
                .unwrap()
                .recovery_state,
            RecoveryState::Unknown,
        );
        let restored = reopened.restore("legacy-proof", false).unwrap();
        assert_eq!(restored.completeness, RecoveryState::Unknown);
        assert_eq!(restored.size_bytes, None);
        assert_eq!(restored.original_size_bytes, record.size_bytes);
        assert_eq!(fs::read(restored.restored_to).unwrap(), b"original bytes");
    }

    #[test]
    fn failed_witness_sync_blocks_unlink_and_retries_the_barrier_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let (store, record) = held(dir.path(), "sync-proof");
        let manifest = fs::read(store.record_path("sync-proof")).unwrap();
        let mut sync_attempts = 0;
        let mut payload_attempted = false;
        for attempt in 0..2 {
            let reopened = QuarantineStore::at(store.root().to_path_buf());
            let selected = reopened.record("sync-proof").unwrap().unwrap();
            assert_eq!(
                selected.recovery_state,
                if attempt == 0 {
                    RecoveryState::Intact
                } else {
                    RecoveryState::PurgeStarted
                },
            );
            let result = purge_with(
                &reopened,
                "sync-proof",
                Some(&selected),
                |lock, root, working| {
                    revoke_intact_witness_with_sync(root, working, |_| {
                        sync_attempts += 1;
                        Err(io::Error::other("injected witness fsync failure"))
                    })?;
                    payload_attempted = true;
                    confined_purge::remove_payload(lock, working).map(Some)
                },
            );
            assert!(result.is_err());
            assert!(
                !payload_attempted,
                "durability failure must precede payload work"
            );
            assert_eq!(
                fs::read(&record.quarantine_path).unwrap(),
                b"original bytes"
            );
            assert_eq!(fs::read(store.record_path("sync-proof")).unwrap(), manifest);
            assert!(!store.root().join("sync-proof.intact").exists());
        }
        assert_eq!(
            sync_attempts, 2,
            "absence after a failed sync is not durable proof"
        );
        let completed = store.drain_all().unwrap();
        assert!(completed.failures.is_empty());
        assert_eq!(completed.completed.len(), 1);
        assert_eq!(
            completed.completed[0].record.recovery_state,
            RecoveryState::PurgeStarted,
        );
        assert!(!record.quarantine_path.exists());
        assert!(store.record("sync-proof").unwrap().is_none());
    }

    #[test]
    fn partial_pending_metadata_cannot_resurrect_intact_recovery_after_publication() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("partial-target");
        fs::create_dir(&source).unwrap();
        for index in 0..96 {
            fs::write(source.join(format!("{index:03}")), b"held child").unwrap();
        }
        let store = QuarantineStore::under(dir.path());
        let record = store
            .quarantine(&source, "pending-partial", 4096, Duration::ZERO, None)
            .unwrap();
        fs::rename(
            store.record_path("pending-partial"),
            pending_path(&store, "pending-partial"),
        )
        .unwrap();
        let first = store.drain_all_with_budget(32).unwrap();
        assert!(first.budget_exhausted);
        assert!(first.completed.is_empty());
        assert!(first.failures.is_empty());
        let remaining = fs::read_dir(&record.quarantine_path).unwrap().count();
        assert!(remaining > 0 && remaining < 96);
        assert_eq!(
            store
                .record("pending-partial")
                .unwrap()
                .unwrap()
                .recovery_state,
            RecoveryState::PurgeStarted,
        );

        // Finishing publication cannot recreate the original hard-link proof.
        fs::rename(
            pending_path(&store, "pending-partial"),
            store.record_path("pending-partial"),
        )
        .unwrap();
        let reopened = QuarantineStore::at(store.root().to_path_buf());
        let restored = reopened.restore("pending-partial", false).unwrap();
        assert_eq!(restored.completeness, RecoveryState::PurgeStarted);
        assert_eq!(restored.size_bytes, None);
        assert_eq!(restored.original_size_bytes, 4096);
        assert_eq!(
            fs::read_dir(restored.restored_to).unwrap().count(),
            remaining
        );
        assert!(!store.root().join("pending-partial.intact").exists());
    }

    #[test]
    fn an_existing_witness_refuses_admission_without_touching_the_source_or_foreign_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = QuarantineStore::under(dir.path());
        store.ensure_root().unwrap();
        let source = dir.path().join("new-payload");
        fs::write(&source, b"source survives").unwrap();
        let witness = store.root().join("collision.intact");
        fs::write(&witness, b"foreign witness").unwrap();
        assert!(
            store
                .quarantine(&source, "collision", 100, Duration::ZERO, None)
                .is_err()
        );
        assert_eq!(fs::read(source).unwrap(), b"source survives");
        assert_eq!(fs::read(witness).unwrap(), b"foreign witness");
        assert!(!store.root().join("collision.pending").exists());
        assert!(!store.entry_dir("collision").exists());
        assert!(store.records().unwrap().is_empty());
    }

    #[test]
    fn a_post_unlink_failure_is_not_replayed_as_a_new_success() {
        let dir = tempfile::tempdir().unwrap();
        let (store, mut record) = held(dir.path(), "post-unlink");
        let failed = purge_with(
            &store,
            "post-unlink",
            Some(&record),
            |lock, root, selected| {
                revoke_intact_witness(root, selected)?;
                assert!(confined_purge::remove_payload(lock, selected)?);
                // Model a finalization interruption after permanent removal.
                Err(io::Error::other(
                    "injected post-unlink finalization failure",
                ))
            },
        );
        assert!(failed.is_err());
        assert!(!record.quarantine_path.exists());
        record.recovery_state = RecoveryState::PurgeStarted;
        assert_eq!(store.record("post-unlink").unwrap(), Some(record.clone()));

        let resumed =
            purge_with_budget_and_gate(&store, &record, &mut PurgeBudget::bounded(32), &mut |_| {
                true
            })
            .unwrap()
            .unwrap();
        assert_eq!(resumed.bytes, 0);
        assert!(resumed.completed.is_none());
        assert!(store.record("post-unlink").unwrap().is_none());
        assert_eq!(store.purge("post-unlink").unwrap(), 0);
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
    #[cfg(unix)]
    fn dropping_the_guard_releases_its_lock_while_an_inherited_child_fd_stays_open() {
        struct Holder(std::process::Child);
        impl Drop for Holder {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let (store, record) = held(dir.path(), "inherited");
        let lock = lock_store(store.root()).unwrap();
        // stdin deliberately retains this same open file description across
        // exec. The real holder process outlives the parent's lock scope.
        let mut child = Holder(
            std::process::Command::new("/bin/sh")
                .args(["-c", "printf ready; exec /bin/sleep 60"])
                .stdin(std::process::Stdio::from(lock.try_clone().unwrap()))
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut stdout = child.0.stdout.take().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut ready = [0u8; 5];
            let result = stdout.read_exact(&mut ready).map(|()| ready);
            let _ = ready_tx.send(result);
        });
        assert_eq!(
            ready_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap(),
            *b"ready"
        );
        reader.join().unwrap();
        assert_eq!(
            lock_store(store.root()).err().unwrap().kind(),
            io::ErrorKind::WouldBlock,
            "the active guard still excludes a competing operation"
        );
        assert!(record.quarantine_path.exists());
        drop(lock);
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "holder is still alive"
        );
        store.restore("inherited", false).unwrap();
        assert_eq!(fs::read(&record.original_path).unwrap(), b"original bytes");
        assert!(!record.quarantine_path.exists());
        assert!(store.record("inherited").unwrap().is_none());
        assert!(child.0.try_wait().unwrap().is_none());
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

    #[test]
    fn busy_batch_drains_defer_without_poisoning_healthy_entries() {
        let dir = tempfile::tempdir().unwrap();
        let (store, first) = held(dir.path(), "busy-a");
        let (_, second) = held(dir.path(), "busy-b");
        let (_, third) = held(dir.path(), "busy-c");
        let lock = lock_store(store.root()).unwrap();
        for _ in 0..3 {
            for out in [
                store.drain_expired(now_secs()).unwrap(),
                store.drain_all().unwrap(),
            ] {
                assert_eq!(out.counts(), (0, 0));
                assert!(out.failures.is_empty());
                assert_eq!(out.skipped_stuck, 0);
                assert_eq!(out.deferred_entries, 1);
                assert!(!out.budget_exhausted, "contention is not budget exhaustion");
            }
        }
        for record in [&first, &second, &third] {
            assert_eq!(
                fs::read(&record.quarantine_path).unwrap(),
                b"original bytes"
            );
            assert!(!store.stuck_path(&record.decision_id).exists());
        }
        // Explicit mutations remain refused while another operation owns the lock.
        assert!(store.purge("busy-a").is_err());
        drop(lock);
        // No hour-long cooldown was fabricated by those contending drains.
        let out = store.drain_expired(now_secs()).unwrap();
        assert_eq!(out.counts(), (3, 300));
        assert_eq!(out.deferred_entries, 0);
        assert!(out.failures.is_empty());
    }

    #[test]
    fn an_extended_ttl_cannot_be_bypassed_by_an_old_inventory_selection() {
        let dir = tempfile::tempdir().unwrap();
        let (store, selected) = held(dir.path(), "ttl-changed");
        let mut extended = selected.clone();
        extended.expires_at += 3600;
        write_json(&store.record_path("ttl-changed"), &extended).unwrap();
        // Replacing the manifest inode no longer authenticates its old witness.
        extended.recovery_state = RecoveryState::Unknown;
        let mut out = super::super::DrainOutcome::default();
        let mut budget = PurgeBudget::bounded(32);
        assert!(!store.try_purge(&selected, selected.expires_at, &mut out, &mut budget));
        assert_eq!(out.deferred_entries, 1);
        assert!(!out.budget_exhausted);
        assert!(out.failures.is_empty());
        assert!(!store.stuck_path("ttl-changed").exists());
        assert_eq!(store.record("ttl-changed").unwrap(), Some(extended.clone()));
        assert_eq!(
            fs::read(&extended.quarantine_path).unwrap(),
            b"original bytes"
        );
        assert_eq!(
            store.drain_expired(selected.expires_at).unwrap().counts(),
            (0, 0)
        );
        assert_eq!(
            store.drain_expired(extended.expires_at).unwrap().counts(),
            (1, 100)
        );
    }

    #[test]
    fn a_reused_decision_id_does_not_inherit_the_previous_payloads_selection() {
        let dir = tempfile::tempdir().unwrap();
        let (store, selected) = held(dir.path(), "reused");
        store.restore("reused", false).unwrap();
        let source = dir.path().join("new-payload");
        fs::write(&source, b"new protected-by-ttl payload").unwrap();
        let fresh = store
            .quarantine(&source, "reused", 200, Duration::from_hours(24), None)
            .unwrap();
        assert_ne!(fresh.inode, selected.inode, "original inode still exists");
        let mut out = super::super::DrainOutcome::default();
        assert!(!store.try_purge(
            &selected,
            now_secs(),
            &mut out,
            &mut PurgeBudget::bounded(32),
        ));
        assert!(out.failures.is_empty());
        assert!(!out.budget_exhausted);
        assert_eq!(out.deferred_entries, 1);
        assert_eq!(out.bytes, 0);
        assert_eq!(store.record("reused").unwrap(), Some(fresh.clone()));
        assert_eq!(
            fs::read(&selected.original_path).unwrap(),
            b"original bytes"
        );
        assert_eq!(
            fs::read(&fresh.quarantine_path).unwrap(),
            b"new protected-by-ttl payload"
        );
        // A fresh forced selection may reclaim the newly held entry, not the original.
        assert_eq!(store.drain_all().unwrap().counts(), (1, 200));
        assert_eq!(fs::read(selected.original_path).unwrap(), b"original bytes");
    }

    #[test]
    fn pending_manifest_publication_preserves_an_unchanged_selection() {
        let dir = tempfile::tempdir().unwrap();
        let (store, selected) = held(dir.path(), "published");
        fs::rename(
            store.record_path("published"),
            pending_path(&store, "published"),
        )
        .unwrap();
        let from_pending = store.record("published").unwrap().unwrap();
        assert_eq!(from_pending, selected);
        fs::rename(
            pending_path(&store, "published"),
            store.record_path("published"),
        )
        .unwrap();
        // Changing only the publication state is not changing the selected
        // payload or policy. Admit it through the same locked snapshot check.
        assert_eq!(
            purge_with_budget_and_gate(
                &store,
                &from_pending,
                &mut PurgeBudget::bounded(32),
                &mut |_| true,
            )
            .unwrap()
            .map(|outcome| outcome.bytes),
            Some(100)
        );
        assert!(!selected.quarantine_path.exists());
        assert!(store.record("published").unwrap().is_none());
    }
}
