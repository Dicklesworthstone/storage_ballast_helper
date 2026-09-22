//! Quarantine-first deletion (Layer 7).
//!
//! At Green, and for manual `clean`,
//! a candidate is not unlinked but renamed into
//! `<mount>/.sbh/quarantine/<decision-id>/<basename>` on the same
//! filesystem, next to a metadata record that names its original path. The
//! space is not freed yet; it is "reclaimable on demand": expired entries
//! are unlinked on Green ticks, and pressure drains the quarantine
//! oldest-first before any new deletion. `sbh undo <decision-id>` restores
//! an entry by renaming it back.
//!
//! Why: on 2026-05-16 and 2026-05-22 a mis-scoring deleted ~87 working
//! trees and ~28 crate directories at once, and the only remedy was a
//! backup. The vetoes that closed that hole cannot close the next one; at
//! Green there is time to keep the bytes around, so sbh does.
//!
//! Invariant (property-tested): a path is never both present at its
//! original location and held in quarantine.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::core::errors::{Result, SbhError};
use crate::scanner::protection::{MARKER_FILENAME, create_marker};

mod safety;

/// Directory under the mount's `.sbh` that holds quarantined entries.
pub const QUARANTINE_DIR_NAME: &str = "quarantine";

/// Default time an entry stays in quarantine before it is unlinked.
pub const DEFAULT_TTL_HOURS: u64 = 24;

/// Default share of the volume the quarantine may occupy before the oldest
/// entries are unlinked to make room.
pub const DEFAULT_MAX_BYTES_PCT: f64 = 5.0;

/// How long an entry that failed to unlink is left alone before a drain
/// tries it again.
///
/// A drain must not retry a stuck entry every sweep: at
/// `QUARANTINE_SWEEP_INTERVAL` that is a failed `remove_dir_all` per minute
/// forever, and the log line that reports it drowns out everything else.
/// Conditions do change — a busy mount is unmounted, a lock is dropped, an
/// immutable bit is cleared — so the entry is retried, just not hot. Pressure
/// and `emergency` ignore this cooldown: when the disk is filling, one more
/// `EBUSY` costs less than the space does.
pub const STUCK_RETRY_SECS: u64 = 3600;

/// Extension of the sidecar that remembers a failed purge. Deliberately not
/// `json`, so `records()` can never mistake it for a record.
const STUCK_EXTENSION: &str = "stuck";

/// One entry a drain could not unlink, with the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainFailure {
    /// The decision whose entry would not go.
    pub decision_id: String,
    /// Where the entry is held.
    pub path: PathBuf,
    /// How many consecutive drains have failed on it, this one included.
    pub failures: u32,
    /// The `SBH-*` code of the underlying error, for the activity log.
    pub code: String,
    /// The underlying error.
    pub error: String,
}

/// What a drain actually managed to do.
///
/// Drains are best-effort per entry: a single unremovable entry must never
/// abort the batch. Before this existed the drains propagated the first
/// per-entry error with `?`, and because `records()` is sorted oldest-first
/// and the sweep re-enters from the top every minute, one stuck entry wedged
/// the whole store permanently while `sbh status` still read green.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DrainOutcome {
    /// Entries unlinked.
    pub entries: usize,
    /// Bytes their records claimed.
    pub bytes: u64,
    /// Entries that would not unlink this pass.
    pub failures: Vec<DrainFailure>,
    /// Entries skipped because they are still cooling down after a failure.
    pub skipped_stuck: usize,
}

impl DrainOutcome {
    /// Nothing was unlinked and nothing failed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries == 0 && self.failures.is_empty()
    }

    /// `(entries, bytes)` for callers that only report totals.
    #[must_use]
    pub const fn counts(&self) -> (usize, u64) {
        (self.entries, self.bytes)
    }

    /// Fold `other` into this outcome (used when a TTL pass and a cap pass
    /// run in the same sweep).
    #[must_use]
    pub fn merged(mut self, other: Self) -> Self {
        self.entries += other.entries;
        self.bytes = self.bytes.saturating_add(other.bytes);
        self.skipped_stuck += other.skipped_stuck;
        self.failures.extend(other.failures);
        self
    }

    /// Failures seen for the first time, which are the ones worth logging.
    /// A still-stuck entry is not news every hour.
    pub fn new_failures(&self) -> impl Iterator<Item = &DrainFailure> {
        self.failures.iter().filter(|f| f.failures == 1)
    }
}

/// A quarantine entry that a drain has failed to unlink, persisted next to
/// the record so the state survives a daemon restart and `sbh doctor` can
/// report it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StuckEntry {
    /// The decision whose entry will not go.
    pub decision_id: String,
    /// Where the entry is held.
    pub path: PathBuf,
    /// Consecutive failed drains.
    pub failures: u32,
    /// Unix seconds of the first failure.
    pub first_failed_at: u64,
    /// Unix seconds of the most recent failure.
    pub last_failed_at: u64,
    /// The most recent error.
    pub last_error: String,
}

/// The record kept next to a quarantined entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineRecord {
    /// The decision that quarantined the entry (`decision_log` id).
    pub decision_id: String,
    /// Where the entry lived.
    pub original_path: PathBuf,
    /// Where it is held now (`<root>/<decision-id>/<basename>`).
    pub quarantine_path: PathBuf,
    /// Device of the entry at quarantine time.
    pub device_id: u64,
    /// Inode of the entry at quarantine time.
    pub inode: u64,
    /// Size estimate at decision time (bytes).
    pub size_bytes: u64,
    /// Unix seconds.
    pub quarantined_at: u64,
    /// Unix seconds after which the entry may be unlinked.
    pub expires_at: u64,
    /// A compact decision snapshot for `sbh explain`.
    #[serde(default)]
    pub decision: Option<serde_json::Value>,
}

/// Why an entry could not be quarantined and had to be unlinked instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineUnavailable {
    /// The quarantine root could not be created or is not a directory.
    RootUnavailable(String),
    /// The candidate lives on a different filesystem than the quarantine
    /// root: a rename would be a copy, which is neither instant nor safe.
    CrossDevice,
    /// The rename itself failed.
    RenameFailed(String),
}

impl std::fmt::Display for QuarantineUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RootUnavailable(detail) => write!(f, "quarantine root unavailable: {detail}"),
            Self::CrossDevice => f.write_str("candidate is on a different filesystem"),
            Self::RenameFailed(detail) => write!(f, "rename into quarantine failed: {detail}"),
        }
    }
}

/// What `restore` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOutcome {
    /// The decision whose entry was restored.
    pub decision_id: String,
    /// Where the entry was put back (differs from the record's original path
    /// only under `force_suffix`).
    pub restored_to: PathBuf,
    /// The bytes the record claimed.
    pub size_bytes: u64,
}

/// A quarantine root on one mount.
#[derive(Debug, Clone)]
pub struct QuarantineStore {
    root: PathBuf,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(unix)]
fn device_of(path: &Path) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::symlink_metadata(path)?;
    Ok((meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
fn device_of(_path: &Path) -> io::Result<(u64, u64)> {
    Ok((0, 0))
}

impl QuarantineStore {
    /// The store whose root directory is `root` (see `quarantine_root_for`).
    #[must_use]
    pub fn for_root(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    /// The store under a scan root or mount point: `<base>/.sbh/quarantine`.
    #[must_use]
    pub fn under(base: &Path) -> Self {
        Self {
            root: base.join(".sbh").join(QUARANTINE_DIR_NAME),
        }
    }

    /// A store at an explicit root (tests, `sbh undo --path`).
    #[must_use]
    pub fn at(root: PathBuf) -> Self {
        Self { root }
    }

    /// The directory holding the entries and their records.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Create the root (with its `.sbh-protect` marker so no scan ever
    /// scores it) or report why it cannot be used.
    fn ensure_root(&self) -> std::result::Result<(), QuarantineUnavailable> {
        fs::create_dir_all(&self.root)
            .map_err(|e| QuarantineUnavailable::RootUnavailable(e.to_string()))?;
        if !fs::symlink_metadata(&self.root)
            .is_ok_and(|metadata| metadata.file_type().is_dir())
        {
            return Err(QuarantineUnavailable::RootUnavailable(
                "not a directory, or is a symlink".to_string(),
            ));
        }
        if !self.root.join(MARKER_FILENAME).exists() {
            create_marker(&self.root, None)
                .map_err(|e| QuarantineUnavailable::RootUnavailable(e.to_string()))?;
        }
        Ok(())
    }

    fn record_path(&self, decision_id: &str) -> PathBuf {
        self.root.join(format!("{decision_id}.json"))
    }

    fn entry_dir(&self, decision_id: &str) -> PathBuf {
        self.root.join(decision_id)
    }

    fn stuck_path(&self, decision_id: &str) -> PathBuf {
        self.root.join(format!("{decision_id}.{STUCK_EXTENSION}"))
    }

    /// The stuck marker for `decision_id`, if a drain has failed on it.
    fn stuck(&self, decision_id: &str) -> Option<StuckEntry> {
        safety::validate_id(decision_id).ok()?;
        safety::read_json(&self.stuck_path(decision_id)).ok()
    }

    /// Record (or extend) a failed purge. Returns the updated marker so the
    /// caller can tell a first failure from a repeat.
    fn note_stuck(&self, record: &QuarantineRecord, error: &str, now_unix: u64) -> StuckEntry {
        let previous = self.stuck(&record.decision_id);
        let marker = StuckEntry {
            decision_id: record.decision_id.clone(),
            path: record.quarantine_path.clone(),
            failures: previous
                .as_ref()
                .map_or(1, |p| p.failures.saturating_add(1)),
            first_failed_at: previous.as_ref().map_or(now_unix, |p| p.first_failed_at),
            last_failed_at: now_unix,
            last_error: error.to_string(),
        };
        // Best-effort: if the marker cannot be written the drain still
        // continues, it just retries this entry next sweep instead of
        // cooling down. Never fail a drain over bookkeeping.
        let _ = safety::write_json(&self.stuck_path(&record.decision_id), &marker);
        marker
    }

    fn clear_stuck(&self, decision_id: &str) {
        let _ = fs::remove_file(self.stuck_path(decision_id));
    }

    /// Whether a previously-failed entry is still inside its retry cooldown.
    fn cooling_down(&self, decision_id: &str, now_unix: u64) -> bool {
        self.stuck(decision_id)
            .is_some_and(|s| now_unix.saturating_sub(s.last_failed_at) < STUCK_RETRY_SECS)
    }

    /// Every entry a drain has failed to unlink, oldest failure first.
    /// Markers whose record is already gone are dropped as they are found.
    pub fn stuck_entries(&self) -> Result<Vec<StuckEntry>> {
        let mut stuck = Vec::new();
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(stuck),
            Err(e) => return Err(SbhError::io(&self.root, e)),
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some(STUCK_EXTENSION) {
                continue;
            }
            if let Ok(marker) = safety::read_json::<StuckEntry>(&path)
                && safety::validate_id(&marker.decision_id).is_ok()
                && path.file_stem().and_then(|s| s.to_str()) == Some(marker.decision_id.as_str())
            {
                // An orphan marker (record purged by another path) is noise.
                if self.record_path(&marker.decision_id).exists()
                    || safety::has_pending_record(self, &marker.decision_id)
                {
                    stuck.push(marker);
                } else {
                    let _ = fs::remove_file(&path);
                }
            }
        }
        stuck.sort_by(|a, b| {
            a.first_failed_at
                .cmp(&b.first_failed_at)
                .then_with(|| a.decision_id.cmp(&b.decision_id))
        });
        Ok(stuck)
    }

    /// Try to unlink one entry, folding the result into `out`. A per-entry
    /// failure is recorded, never propagated: the batch must continue.
    fn try_purge(&self, record: &QuarantineRecord, now_unix: u64, out: &mut DrainOutcome) {
        match self.purge(&record.decision_id) {
            Ok(bytes) => {
                out.entries += 1;
                out.bytes = out.bytes.saturating_add(bytes);
            }
            Err(e) => {
                let code = e.code().to_string();
                let error = e.to_string();
                let marker = self.note_stuck(record, &error, now_unix);
                out.failures.push(DrainFailure {
                    decision_id: record.decision_id.clone(),
                    path: record.quarantine_path.clone(),
                    failures: marker.failures,
                    code,
                    error,
                });
            }
        }
    }

    /// Move `path` into quarantine under `decision_id`. Same filesystem
    /// only; the caller unlinks instead when this returns `Err`.
    pub fn quarantine(
        &self,
        path: &Path,
        decision_id: &str,
        size_bytes: u64,
        ttl: Duration,
        decision: Option<serde_json::Value>,
    ) -> std::result::Result<QuarantineRecord, QuarantineUnavailable> {
        safety::quarantine(self, path, decision_id, size_bytes, ttl, decision)
    }

    /// Every valid record in the store, oldest first. Completed moves with
    /// a write-ahead `.pending` record are included after an interruption.
    pub fn records(&self) -> Result<Vec<QuarantineRecord>> {
        let mut records = Vec::new();
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(records),
            Err(e) => return Err(SbhError::io(&self.root, e)),
        };
        let mut seen = std::collections::BTreeSet::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if !matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("json" | "pending")
            ) {
                continue;
            }
            if let Some(id) = path.file_stem().and_then(|s| s.to_str())
                && seen.insert(id.to_string())
                && let Ok(Some(record)) = self.record(id)
            {
                records.push(record);
            }
        }
        records.sort_by(|a, b| {
            a.quarantined_at
                .cmp(&b.quarantined_at)
                .then_with(|| a.decision_id.cmp(&b.decision_id))
        });
        Ok(records)
    }

    /// The record for `decision_id`, if held.
    pub fn record(&self, decision_id: &str) -> Result<Option<QuarantineRecord>> {
        safety::read_record(self, decision_id)
    }

    /// Bytes held (the decision-time size estimates summed).
    pub fn held_bytes(&self) -> Result<u64> {
        Ok(self
            .records()?
            .iter()
            .map(|r| r.size_bytes)
            .fold(0u64, u64::saturating_add))
    }

    /// Unlink one entry for good (record included). Returns the bytes its
    /// record claimed.
    pub fn purge(&self, decision_id: &str) -> Result<u64> {
        safety::purge(self, decision_id)
    }

    /// Unlink every entry whose TTL has expired.
    ///
    /// Best-effort per entry: an entry that will not unlink is recorded and
    /// skipped, and the rest of the batch still drains. `Err` means the store
    /// itself could not be read.
    pub fn drain_expired(&self, now_unix: u64) -> Result<DrainOutcome> {
        let mut out = DrainOutcome::default();
        for record in self.records()? {
            if record.expires_at > now_unix {
                continue;
            }
            if self.cooling_down(&record.decision_id, now_unix) {
                out.skipped_stuck += 1;
                continue;
            }
            self.try_purge(&record, now_unix, &mut out);
        }
        Ok(out)
    }

    /// Unlink entries oldest-first until at least `bytes_needed` of claimed
    /// bytes are gone (or the store is empty).
    pub fn drain_oldest(&self, bytes_needed: u64) -> Result<DrainOutcome> {
        self.drain_oldest_inner(bytes_needed, now_secs(), false)
    }

    /// `drain_oldest`, ignoring the stuck cooldown. For pressure and
    /// `emergency`, where the space matters more than a tidy log.
    pub fn drain_oldest_forced(&self, bytes_needed: u64) -> Result<DrainOutcome> {
        self.drain_oldest_inner(bytes_needed, now_secs(), true)
    }

    fn drain_oldest_inner(
        &self,
        bytes_needed: u64,
        now_unix: u64,
        force: bool,
    ) -> Result<DrainOutcome> {
        let mut out = DrainOutcome::default();
        for record in self.records()? {
            if out.bytes >= bytes_needed {
                break;
            }
            if !force && self.cooling_down(&record.decision_id, now_unix) {
                out.skipped_stuck += 1;
                continue;
            }
            self.try_purge(&record, now_unix, &mut out);
        }
        Ok(out)
    }

    /// Unlink everything held, retrying entries that are cooling down: this
    /// is the pressure path, and held bytes are the cheapest space there is.
    pub fn drain_all(&self) -> Result<DrainOutcome> {
        self.drain_oldest_forced(u64::MAX)
    }

    /// Unlink oldest entries until the store holds at most `max_bytes`.
    pub fn enforce_cap(&self, max_bytes: u64) -> Result<DrainOutcome> {
        let held = self.held_bytes()?;
        if held <= max_bytes {
            return Ok(DrainOutcome::default());
        }
        self.drain_oldest(held - max_bytes)
    }

    /// Put an entry back where it came from by rename. Refuses when the
    /// original path exists again unless `force_suffix`, which restores to
    /// `<original>.restored-<decision-id>` instead.
    pub fn restore(&self, decision_id: &str, force_suffix: bool) -> Result<RestoreOutcome> {
        safety::restore(self, decision_id, force_suffix)
    }

    /// The record whose original path is `path`, if held.
    pub fn record_for_path(&self, path: &Path) -> Result<Option<QuarantineRecord>> {
        Ok(self
            .records()?
            .into_iter()
            .find(|record| record.original_path == path))
    }
}

#[cfg(test)]
fn write_record(path: &Path, record: &QuarantineRecord) -> io::Result<()> {
    safety::write_json(path, record)
}

/// The quarantine root for `path`: `<root>/.sbh/quarantine` for the longest
/// of `roots` that contains it, else the same under its mount point.
#[must_use]
pub fn quarantine_root_for(path: &Path, roots: &[PathBuf]) -> PathBuf {
    let base = roots
        .iter()
        .filter(|root| path.starts_with(root))
        .max_by_key(|root| root.as_os_str().len())
        .cloned()
        .unwrap_or_else(|| mount_point_of(path));
    base.join(".sbh").join(QUARANTINE_DIR_NAME)
}

/// The highest ancestor of `path` on the same device: its mount point
/// (`/` when the path cannot be stat'ed).
#[must_use]
pub fn mount_point_of(path: &Path) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(meta) = fs::symlink_metadata(path) else {
            return PathBuf::from("/");
        };
        let dev = meta.dev();
        let mut current = path.to_path_buf();
        loop {
            let Some(parent) = current.parent() else {
                return current;
            };
            match fs::metadata(parent) {
                Ok(m) if m.dev() == dev => current = parent.to_path_buf(),
                _ => return current,
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        PathBuf::from("/")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn tree(dir: &Path, name: &str, files: usize) -> PathBuf {
        let root = dir.join(name);
        fs::create_dir_all(root.join("deep")).unwrap();
        for i in 0..files {
            fs::write(root.join("deep").join(format!("f{i}")), vec![b'x'; 100 + i]).unwrap();
        }
        root
    }

    fn tree_digest(root: &Path) -> BTreeSet<(PathBuf, Vec<u8>)> {
        fn walk(base: &Path, dir: &Path, out: &mut BTreeSet<(PathBuf, Vec<u8>)>) {
            for entry in fs::read_dir(dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(base, &path, out);
                } else {
                    out.insert((
                        path.strip_prefix(base).unwrap().to_path_buf(),
                        fs::read(&path).unwrap(),
                    ));
                }
            }
        }
        let mut out = BTreeSet::new();
        walk(root, root, &mut out);
        out
    }

    #[test]
    fn quarantine_renames_within_the_device_and_restore_is_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let store = QuarantineStore::at(dir.path().join("q"));
        let target = tree(dir.path(), "proj/target", 5);
        let before = tree_digest(&target);
        let record = store
            .quarantine(&target, "d1", 4096, Duration::from_hours(24), None)
            .unwrap();
        assert!(!target.exists(), "the original is gone");
        assert!(record.quarantine_path.exists());
        assert!(
            store.root().join(MARKER_FILENAME).exists(),
            "root is protected"
        );
        assert_eq!(store.records().unwrap().len(), 1);
        assert_eq!(store.held_bytes().unwrap(), 4096);
        assert_eq!(
            store.record_for_path(&target).unwrap().unwrap().decision_id,
            "d1"
        );

        let outcome = store.restore("d1", false).unwrap();
        assert_eq!(outcome.restored_to, target);
        assert_eq!(tree_digest(&target), before, "restore is byte-identical");
        assert!(store.records().unwrap().is_empty());
        assert!(store.record("d1").unwrap().is_none());
    }

    #[test]
    fn restore_refuses_an_existing_original_unless_suffixed() {
        let dir = tempfile::tempdir().unwrap();
        let store = QuarantineStore::at(dir.path().join("q"));
        let target = tree(dir.path(), "proj/target", 2);
        store
            .quarantine(&target, "d2", 10, Duration::from_hours(1), None)
            .unwrap();
        // A rebuild recreates the original path.
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("new"), b"fresh").unwrap();
        let err = store.restore("d2", false).unwrap_err().to_string();
        assert!(err.contains("exists again"), "{err}");
        assert!(store.record("d2").unwrap().is_some(), "still held");
        let outcome = store.restore("d2", true).unwrap();
        assert_eq!(
            outcome.restored_to,
            dir.path().join("proj").join("target.restored-d2")
        );
        assert!(outcome.restored_to.join("deep").join("f0").exists());
        assert!(target.join("new").exists(), "the rebuild is untouched");
        assert!(store.restore("d2", true).is_err(), "restored once only");
    }

    #[test]
    fn cross_device_candidates_are_refused() {
        // /dev/shm (tmpfs) is a different device from /data/tmp or /tmp on
        // every host this runs on; skip honestly when it is not.
        let shm = Path::new("/dev/shm");
        if !shm.is_dir() {
            eprintln!("no /dev/shm here; cross-device case not exercised");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let store = QuarantineStore::at(dir.path().join("q"));
        store.ensure_root().unwrap();
        let (root_dev, _) = device_of(store.root()).unwrap();
        let (shm_dev, _) = device_of(shm).unwrap();
        if root_dev == shm_dev {
            eprintln!("/dev/shm shares a device with the scratch dir; case not exercised");
            return;
        }
        let victim = tempfile::tempdir_in(shm).unwrap();
        let file = victim.path().join("artifact");
        fs::write(&file, b"x").unwrap();
        let err = store
            .quarantine(&file, "d3", 1, Duration::from_hours(1), None)
            .unwrap_err();
        assert_eq!(err, QuarantineUnavailable::CrossDevice);
        assert!(file.exists(), "a refused quarantine touches nothing");
    }

    #[test]
    fn an_unusable_root_is_reported_not_unlinked() {
        let dir = tempfile::tempdir().unwrap();
        // A file where the root should be.
        let root = dir.path().join("q");
        fs::write(&root, b"not a dir").unwrap();
        let store = QuarantineStore::at(root);
        let target = tree(dir.path(), "proj/target", 1);
        let err = store
            .quarantine(&target, "d4", 1, Duration::from_hours(1), None)
            .unwrap_err();
        assert!(
            matches!(err, QuarantineUnavailable::RootUnavailable(_)),
            "{err}"
        );
        assert!(target.exists());
    }

    #[test]
    fn drains_follow_ttl_age_and_cap() {
        let dir = tempfile::tempdir().unwrap();
        let store = QuarantineStore::at(dir.path().join("q"));
        for (i, ttl) in [3600u64, 0, 7200].iter().enumerate() {
            let target = tree(dir.path(), &format!("p{i}/target"), 1);
            store
                .quarantine(
                    &target,
                    &format!("d{i}"),
                    1000 * (i as u64 + 1),
                    Duration::from_secs(*ttl),
                    None,
                )
                .unwrap();
            // Distinct ages for oldest-first ordering.
            let path = store.record_path(&format!("d{i}"));
            let mut record: QuarantineRecord =
                serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
            record.quarantined_at = 1_000 + i as u64;
            record.expires_at = record.quarantined_at + ttl;
            write_record(&path, &record).unwrap();
        }
        assert_eq!(store.held_bytes().unwrap(), 6000);
        // Only d1 (ttl 0) has expired at t = 1_500.
        assert_eq!(store.drain_expired(1_500).unwrap().counts(), (1, 2000));
        assert!(store.record("d1").unwrap().is_none());
        // Oldest first: d0 goes before d2.
        assert_eq!(store.drain_oldest(1).unwrap().counts(), (1, 1000));
        assert!(store.record("d0").unwrap().is_none());
        assert!(store.record("d2").unwrap().is_some());
        // The cap.
        let target = tree(dir.path(), "p9/target", 1);
        store
            .quarantine(&target, "d9", 5000, Duration::from_hours(1), None)
            .unwrap();
        assert_eq!(store.held_bytes().unwrap(), 8000);
        assert_eq!(store.enforce_cap(6000).unwrap().counts(), (1, 3000));
        assert_eq!(store.held_bytes().unwrap(), 5000);
        assert_eq!(store.drain_all().unwrap().counts(), (1, 5000));
        assert_eq!(store.held_bytes().unwrap(), 0);
        assert_eq!(store.enforce_cap(0).unwrap().counts(), (0, 0));
    }

    #[test]
    fn quarantine_root_prefers_the_longest_scan_root_then_the_mount() {
        let roots = vec![PathBuf::from("/data"), PathBuf::from("/data/projects")];
        assert_eq!(
            quarantine_root_for(Path::new("/data/projects/x/target"), &roots),
            PathBuf::from("/data/projects/.sbh/quarantine")
        );
        assert_eq!(
            quarantine_root_for(Path::new("/data/other/target"), &roots),
            PathBuf::from("/data/.sbh/quarantine")
        );
        assert_eq!(
            mount_point_of(Path::new("/dev/shm/nonexistent-sbh-probe")),
            PathBuf::from("/"),
            "unstat-able paths fall back to /"
        );
        assert_eq!(mount_point_of(Path::new("/")), PathBuf::from("/"));
        let dir = tempfile::tempdir().unwrap();
        let mp = mount_point_of(dir.path());
        assert!(
            dir.path().starts_with(&mp),
            "{} under {}",
            dir.path().display(),
            mp.display()
        );
        assert_eq!(
            quarantine_root_for(dir.path(), &[]),
            mp.join(".sbh").join(QUARANTINE_DIR_NAME)
        );
    }

    /// For any sequence of quarantine / drain / restore operations no path
    /// is ever both at its original location and held in quarantine, and
    /// every held record points at an existing entry.
    #[test]
    fn no_path_is_both_present_and_quarantined() {
        let dir = tempfile::tempdir().unwrap();
        let store = QuarantineStore::at(dir.path().join("q"));
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let originals: Vec<PathBuf> = (0..6)
            .map(|i| dir.path().join(format!("p{i}")).join("target"))
            .collect();
        for path in &originals {
            fs::create_dir_all(path).unwrap();
            fs::write(path.join("f"), b"x").unwrap();
        }
        let check = |store: &QuarantineStore| {
            let records = store.records().unwrap();
            for record in &records {
                assert!(
                    fs::symlink_metadata(&record.original_path).is_err(),
                    "{} is both present and quarantined",
                    record.original_path.display()
                );
                assert!(record.quarantine_path.exists(), "{record:?}");
            }
        };
        for step in 0..300 {
            let i = (next() % 6) as usize;
            let id = format!("id{i}");
            match next() % 5 {
                0 | 1 => {
                    if originals[i].exists() {
                        store
                            .quarantine(&originals[i], &id, 1, Duration::from_secs(60), None)
                            .unwrap();
                    }
                }
                2 => {
                    if store.record(&id).unwrap().is_some() {
                        store.restore(&id, false).unwrap();
                    }
                }
                3 => {
                    let _ = store.purge(&id).unwrap();
                    if !originals[i].exists() {
                        // Something else recreated the path.
                        fs::create_dir_all(&originals[i]).unwrap();
                        fs::write(originals[i].join("f"), b"y").unwrap();
                    }
                }
                _ => {
                    let _ = store.drain_oldest(1).unwrap();
                }
            }
            check(&store);
            let _ = step;
        }
    }

    /// Make `purge` fail for `decision_id` in a way root cannot bypass:
    /// replace the entry directory with a regular file, so `remove_dir_all`
    /// gets `ENOTDIR`. A permissions-based poison (chmod the entry dir) would
    /// silently succeed when the suite runs as root — which it does whenever
    /// `cargo test` is offloaded — and the test would prove nothing.
    fn poison(store: &QuarantineStore, decision_id: &str) {
        let dir = store.entry_dir(decision_id);
        fs::remove_dir_all(&dir).unwrap();
        fs::write(&dir, b"not a directory").unwrap();
    }

    /// Quarantine `n` entries with ids `d0..dn`, all expired at `t = 1_500`,
    /// each claiming 1000 bytes, with distinct ascending ages.
    fn expired_store(dir: &Path, n: usize) -> QuarantineStore {
        let store = QuarantineStore::at(dir.join("q"));
        for i in 0..n {
            let target = tree(dir, &format!("p{i}/target"), 1);
            let id = format!("d{i}");
            store
                .quarantine(&target, &id, 1000, Duration::from_secs(0), None)
                .unwrap();
            let path = store.record_path(&id);
            let mut record: QuarantineRecord =
                serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
            record.quarantined_at = 1_000 + i as u64;
            record.expires_at = 1_100;
            write_record(&path, &record).unwrap();
        }
        store
    }

    #[test]
    fn one_unremovable_entry_does_not_abort_the_batch() {
        let dir = tempfile::tempdir().unwrap();
        let store = expired_store(dir.path(), 3);
        // Poison the OLDEST entry: `records()` is sorted oldest-first, so the
        // previous `?`-in-loop implementation freed exactly nothing here.
        poison(&store, "d0");

        let out = store.drain_expired(1_500).unwrap();

        assert_eq!(out.entries, 2, "the two healthy entries must still drain");
        assert_eq!(out.bytes, 2000);
        assert_eq!(out.failures.len(), 1);
        assert_eq!(out.failures[0].decision_id, "d0");
        assert_eq!(out.failures[0].failures, 1);
        assert!(store.record("d1").unwrap().is_none());
        assert!(store.record("d2").unwrap().is_none());
        assert!(
            store.record("d0").unwrap().is_some(),
            "poisoned entry stays"
        );
    }

    #[test]
    fn a_stuck_entry_is_reported_once_then_cools_down() {
        let dir = tempfile::tempdir().unwrap();
        let store = expired_store(dir.path(), 1);
        poison(&store, "d0");

        let first = store.drain_expired(1_500).unwrap();
        assert_eq!(first.new_failures().count(), 1, "first failure is news");
        assert_eq!(first.skipped_stuck, 0);

        // Same second: still inside STUCK_RETRY_SECS, so it is skipped rather
        // than retried, and produces no second log line.
        let second = store.drain_expired(1_500).unwrap();
        assert_eq!(second.entries, 0);
        assert!(second.failures.is_empty());
        assert_eq!(second.skipped_stuck, 1);
        assert_eq!(second.new_failures().count(), 0);

        // Past the cooldown it is retried, and the repeat is not "new".
        let later = store.drain_expired(1_500 + STUCK_RETRY_SECS).unwrap();
        assert_eq!(later.failures.len(), 1);
        assert_eq!(later.failures[0].failures, 2);
        assert_eq!(later.new_failures().count(), 0);
    }

    #[test]
    fn pressure_drain_retries_an_entry_that_is_cooling_down() {
        let dir = tempfile::tempdir().unwrap();
        let store = expired_store(dir.path(), 2);
        poison(&store, "d0");

        let cooled = store.drain_expired(1_500).unwrap();
        assert_eq!(cooled.failures.len(), 1);
        assert_eq!(cooled.entries, 1, "d1 drains");

        // `drain_all` is the pressure path: it must not honour the cooldown,
        // because held bytes are the cheapest space available at Orange+.
        let forced = store.drain_all().unwrap();
        assert_eq!(forced.skipped_stuck, 0, "pressure ignores the cooldown");
        assert_eq!(forced.failures.len(), 1);
        assert_eq!(forced.failures[0].decision_id, "d0");
    }

    #[test]
    fn stuck_entries_are_listed_and_cleared_when_the_entry_finally_goes() {
        let dir = tempfile::tempdir().unwrap();
        let store = expired_store(dir.path(), 2);
        // Keep the original inode: repairing permissions or a mount must not
        // authorize purging an unrelated replacement at the same path.
        let saved = dir.path().join("saved");
        fs::rename(store.entry_dir("d0").join("target"), &saved).unwrap();
        poison(&store, "d0");
        store.drain_expired(1_500).unwrap();

        let stuck = store.stuck_entries().unwrap();
        assert_eq!(stuck.len(), 1);
        assert_eq!(stuck[0].decision_id, "d0");
        assert_eq!(stuck[0].failures, 1);
        assert!(!stuck[0].last_error.is_empty());

        // Repair the entry and drain past the cooldown: the marker must go
        // with it, or `doctor` reports a phantom forever.
        let entry = store.entry_dir("d0");
        fs::remove_file(&entry).unwrap();
        fs::create_dir(&entry).unwrap();
        fs::rename(&saved, entry.join("target")).unwrap();
        let out = store.drain_expired(1_500 + STUCK_RETRY_SECS).unwrap();
        assert_eq!(out.entries, 1);
        assert!(out.failures.is_empty());
        assert!(store.stuck_entries().unwrap().is_empty());
        assert!(!store.stuck_path("d0").exists());
    }

    #[test]
    fn a_stuck_marker_is_never_mistaken_for_a_record() {
        let dir = tempfile::tempdir().unwrap();
        let store = expired_store(dir.path(), 2);
        poison(&store, "d0");
        store.drain_expired(1_500).unwrap();
        // `records()` keys off the `json` extension; `.stuck` must not parse
        // as a record or held_bytes and the drains would double-count.
        assert_eq!(store.records().unwrap().len(), 1);
        assert_eq!(store.held_bytes().unwrap(), 1000);
    }

    #[test]
    fn bytes_freed_equal_the_sum_over_removable_expired_entries() {
        // The acceptance property: no early exit, whatever the mix.
        for poisoned in [vec![], vec![0], vec![2], vec![0, 3], vec![0, 1, 2, 3, 4]] {
            let dir = tempfile::tempdir().unwrap();
            let store = expired_store(dir.path(), 5);
            for i in &poisoned {
                poison(&store, &format!("d{i}"));
            }
            let expected = 5 - poisoned.len();
            let out = store.drain_expired(1_500).unwrap();
            assert_eq!(out.entries, expected, "poisoned={poisoned:?}");
            assert_eq!(out.bytes, expected as u64 * 1000, "poisoned={poisoned:?}");
            assert_eq!(out.failures.len(), poisoned.len(), "poisoned={poisoned:?}");
        }
    }
}
