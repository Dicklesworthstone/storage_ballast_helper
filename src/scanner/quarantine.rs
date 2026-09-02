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

/// Directory under the mount's `.sbh` that holds quarantined entries.
pub const QUARANTINE_DIR_NAME: &str = "quarantine";

/// Default time an entry stays in quarantine before it is unlinked.
pub const DEFAULT_TTL_HOURS: u64 = 24;

/// Default share of the volume the quarantine may occupy before the oldest
/// entries are unlinked to make room.
pub const DEFAULT_MAX_BYTES_PCT: f64 = 5.0;

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
        if !self.root.is_dir() {
            return Err(QuarantineUnavailable::RootUnavailable(
                "not a directory".to_string(),
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
        self.ensure_root()?;
        let (root_dev, _) = device_of(&self.root)
            .map_err(|e| QuarantineUnavailable::RootUnavailable(e.to_string()))?;
        let (dev, ino) =
            device_of(path).map_err(|e| QuarantineUnavailable::RenameFailed(e.to_string()))?;
        if dev != root_dev {
            return Err(QuarantineUnavailable::CrossDevice);
        }
        let Some(name) = path.file_name() else {
            return Err(QuarantineUnavailable::RenameFailed(
                "candidate has no file name".to_string(),
            ));
        };
        let dir = self.entry_dir(decision_id);
        fs::create_dir_all(&dir).map_err(|e| QuarantineUnavailable::RenameFailed(e.to_string()))?;
        let target = dir.join(name);
        if target.exists() {
            return Err(QuarantineUnavailable::RenameFailed(format!(
                "{} already holds an entry",
                target.display()
            )));
        }
        fs::rename(path, &target)
            .map_err(|e| QuarantineUnavailable::RenameFailed(e.to_string()))?;
        let quarantined_at = now_secs();
        let record = QuarantineRecord {
            decision_id: decision_id.to_string(),
            original_path: path.to_path_buf(),
            quarantine_path: target,
            device_id: dev,
            inode: ino,
            size_bytes,
            quarantined_at,
            expires_at: quarantined_at.saturating_add(ttl.as_secs()),
            decision,
        };
        // The record is what makes the entry restorable; without it the
        // entry is just bytes in a hidden directory, so a record write
        // failure is a quarantine failure and the rename is undone.
        if let Err(e) = write_record(&self.record_path(decision_id), &record) {
            let _ = fs::rename(&record.quarantine_path, path);
            let _ = fs::remove_dir(&dir);
            return Err(QuarantineUnavailable::RootUnavailable(format!(
                "record write failed: {e}"
            )));
        }
        Ok(record)
    }

    /// Every record in the store, oldest first.
    pub fn records(&self) -> Result<Vec<QuarantineRecord>> {
        let mut records = Vec::new();
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(records),
            Err(e) => return Err(SbhError::io(&self.root, e)),
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(text) = fs::read_to_string(&path)
                && let Ok(record) = serde_json::from_str::<QuarantineRecord>(&text)
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
        let path = self.record_path(decision_id);
        match fs::read_to_string(&path) {
            Ok(text) => Ok(serde_json::from_str(&text).ok()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(SbhError::io(&path, e)),
        }
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
        let Some(record) = self.record(decision_id)? else {
            return Ok(0);
        };
        let dir = self.entry_dir(decision_id);
        if dir.exists() {
            fs::remove_dir_all(&dir).map_err(|e| SbhError::io(&dir, e))?;
        }
        let record_path = self.record_path(decision_id);
        fs::remove_file(&record_path).map_err(|e| SbhError::io(&record_path, e))?;
        Ok(record.size_bytes)
    }

    /// Unlink every entry whose TTL has expired. Returns `(entries, bytes)`.
    pub fn drain_expired(&self, now_unix: u64) -> Result<(usize, u64)> {
        let mut count = 0;
        let mut bytes = 0u64;
        for record in self.records()? {
            if record.expires_at <= now_unix {
                bytes = bytes.saturating_add(self.purge(&record.decision_id)?);
                count += 1;
            }
        }
        Ok((count, bytes))
    }

    /// Unlink entries oldest-first until at least `bytes_needed` of claimed
    /// bytes are gone (or the store is empty). Returns `(entries, bytes)`.
    pub fn drain_oldest(&self, bytes_needed: u64) -> Result<(usize, u64)> {
        let mut count = 0;
        let mut bytes = 0u64;
        for record in self.records()? {
            if bytes >= bytes_needed {
                break;
            }
            bytes = bytes.saturating_add(self.purge(&record.decision_id)?);
            count += 1;
        }
        Ok((count, bytes))
    }

    /// Unlink everything held. Returns `(entries, bytes)`.
    pub fn drain_all(&self) -> Result<(usize, u64)> {
        self.drain_oldest(u64::MAX)
    }

    /// Unlink oldest entries until the store holds at most `max_bytes`.
    pub fn enforce_cap(&self, max_bytes: u64) -> Result<(usize, u64)> {
        let held = self.held_bytes()?;
        if held <= max_bytes {
            return Ok((0, 0));
        }
        self.drain_oldest(held - max_bytes)
    }

    /// Put an entry back where it came from by rename. Refuses when the
    /// original path exists again unless `force_suffix`, which restores to
    /// `<original>.restored-<decision-id>` instead.
    pub fn restore(&self, decision_id: &str, force_suffix: bool) -> Result<RestoreOutcome> {
        let Some(record) = self.record(decision_id)? else {
            return Err(SbhError::Runtime {
                details: format!("no quarantined entry for decision {decision_id}"),
            });
        };
        if !record.quarantine_path.exists() {
            return Err(SbhError::Runtime {
                details: format!(
                    "quarantined entry for {decision_id} is gone: {}",
                    record.quarantine_path.display()
                ),
            });
        }
        let mut destination = record.original_path.clone();
        if fs::symlink_metadata(&destination).is_ok() {
            if !force_suffix {
                return Err(SbhError::Runtime {
                    details: format!(
                        "{} exists again; pass --force-suffix to restore next to it",
                        destination.display()
                    ),
                });
            }
            let name = destination
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            destination.set_file_name(format!("{name}.restored-{decision_id}"));
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|e| SbhError::io(parent, e))?;
        }
        fs::rename(&record.quarantine_path, &destination)
            .map_err(|e| SbhError::io(&record.quarantine_path, e))?;
        let _ = fs::remove_dir(self.entry_dir(decision_id));
        let record_path = self.record_path(decision_id);
        fs::remove_file(&record_path).map_err(|e| SbhError::io(&record_path, e))?;
        Ok(RestoreOutcome {
            decision_id: decision_id.to_string(),
            restored_to: destination,
            size_bytes: record.size_bytes,
        })
    }

    /// The record whose original path is `path`, if held.
    pub fn record_for_path(&self, path: &Path) -> Result<Option<QuarantineRecord>> {
        Ok(self
            .records()?
            .into_iter()
            .find(|record| record.original_path == path))
    }
}

fn write_record(path: &Path, record: &QuarantineRecord) -> io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(record)?)?;
    fs::rename(&tmp, path)
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
        assert_eq!(store.drain_expired(1_500).unwrap(), (1, 2000));
        assert!(store.record("d1").unwrap().is_none());
        // Oldest first: d0 goes before d2.
        assert_eq!(store.drain_oldest(1).unwrap(), (1, 1000));
        assert!(store.record("d0").unwrap().is_none());
        assert!(store.record("d2").unwrap().is_some());
        // The cap.
        let target = tree(dir.path(), "p9/target", 1);
        store
            .quarantine(&target, "d9", 5000, Duration::from_hours(1), None)
            .unwrap();
        assert_eq!(store.held_bytes().unwrap(), 8000);
        assert_eq!(store.enforce_cap(6000).unwrap(), (1, 3000));
        assert_eq!(store.held_bytes().unwrap(), 5000);
        assert_eq!(store.drain_all().unwrap(), (1, 5000));
        assert_eq!(store.held_bytes().unwrap(), 0);
        assert_eq!(store.enforce_cap(0).unwrap(), (0, 0));
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
}
