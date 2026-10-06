//! Bounded, crash-consistent persistence for scanner hints.
//!
//! Serialize the live ordered map twice (hash, then file), never clone every
//! record or build a second index-sized JSON buffer. A private staging file is
//! flushed and synced before atomic replacement. A failed save cannot truncate
//! the last good checkpoint or a predictable `.tmp` path belonging to someone
//! else. Loading is bounded even if the file grows after its initial stat.
//!
//! This is a cache, not deletion authority. Missing, stale, oversized, changed,
//! or corrupt checkpoints fall back to an empty index and ordinary discovery.

use std::collections::{BTreeMap, btree_map::Entry};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use serde::de::{self, SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use super::{
    CHECKPOINT_VERSION, CandidateIndexRecord, IndexedIdentity, ScannerCandidateIndex,
    ScannerIndexContext, ScannerIndexLoadStatus,
};
use crate::core::errors::{Result, SbhError};

// Checkpoint I/O limits, not limits on the live scanner. An oversized live
// index remains usable; its failed checkpoint save retains the previous file.
const MAX_CHECKPOINT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CHECKPOINT_RECORDS: usize = 100_000;

#[derive(Serialize, Deserialize)]
struct Checkpoint {
    version: u32,
    context: ScannerIndexContext,
    event_generation: u64,
    #[serde(deserialize_with = "read_records")]
    records: Vec<CandidateIndexRecord>,
    integrity_hash: [u8; 32],
}

fn read_records<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<CandidateIndexRecord>, D::Error> {
    struct RecordsVisitor;

    impl<'de> Visitor<'de> for RecordsVisitor {
        type Value = Vec<CandidateIndexRecord>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a bounded scanner candidate sequence")
        }

        fn visit_seq<A: SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut records = Vec::new();
            while let Some(record) = sequence.next_element()? {
                if records.len() == MAX_CHECKPOINT_RECORDS {
                    return Err(de::Error::custom(
                        "scanner checkpoint record limit exceeded",
                    ));
                }
                records.push(record);
            }
            Ok(records)
        }
    }

    deserializer.deserialize_seq(RecordsVisitor)
}

struct OrderedRecords<'a>(&'a BTreeMap<IndexedIdentity, CandidateIndexRecord>);

impl Serialize for OrderedRecords<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for record in self.0.values() {
            sequence.serialize_element(record)?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct CheckpointView<'a> {
    version: u32,
    context: &'a ScannerIndexContext,
    event_generation: u64,
    records: OrderedRecords<'a>,
    integrity_hash: [u8; 32],
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

struct LimitedWriter<W> {
    inner: W,
    remaining: u64,
}

impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.remaining {
            return Err(invalid("scanner checkpoint byte limit exceeded"));
        }
        let count = self.inner.write(bytes)?;
        self.remaining -= count as u64;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// `Take` alone would turn an over-limit whitespace tail into apparent EOF.
// After exhausting the allowance, distinguish real EOF from one extra byte.
struct LimitedReader<R> {
    inner: R,
    remaining: u64,
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            return match self.inner.read(&mut [0u8; 1])? {
                0 => Ok(0),
                _ => Err(invalid("scanner checkpoint byte limit exceeded")),
            };
        }
        let limit = bytes
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let count = self.inner.read(&mut bytes[..limit])?;
        self.remaining -= count as u64;
        Ok(count)
    }
}

struct DigestWriter(Sha256);

impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// Preserve the v2 hash contract byte-for-byte: JSON(context), LE generation,
// JSON(records). Streaming must not invalidate existing complete checkpoints.
fn integrity_hash(
    context: &ScannerIndexContext,
    generation: u64,
    records: &impl Serialize,
    limit: u64,
) -> io::Result<[u8; 32]> {
    let mut writer = LimitedWriter {
        inner: DigestWriter(Sha256::new()),
        remaining: limit,
    };
    serde_json::to_writer(&mut writer, context).map_err(io::Error::other)?;
    writer.write_all(&generation.to_le_bytes())?;
    serde_json::to_writer(&mut writer, records).map_err(io::Error::other)?;
    Ok(writer.inner.0.finalize().into())
}

fn same_identity(left: &Metadata, right: &Metadata) -> bool {
    if !left.is_file() || !right.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        left.created().ok() == right.created().ok()
    }
}

fn same_snapshot(left: &Metadata, right: &Metadata) -> bool {
    if !same_identity(left, right)
        || left.len() != right.len()
        || left.modified().ok() != right.modified().ok()
    {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.ctime() == right.ctime() && left.ctime_nsec() == right.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        true
    }
}

struct StagingFile {
    path: PathBuf,
    file: File,
    published: bool,
}

impl StagingFile {
    fn create(parent: &Path) -> io::Result<Self> {
        for _ in 0..16 {
            let path = parent.join(format!(
                ".sbh-index-{}-{:016x}.tmp",
                std::process::id(),
                rand::random::<u64>(),
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(file) => {
                    return Ok(Self {
                        path,
                        file,
                        published: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not reserve a private scanner checkpoint staging file",
        ))
    }
}

impl Drop for StagingFile {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        // Remove only our own staging inode, never a replacement or a shared
        // fixed-name temp file. A process crash may leave this private file;
        // the loader ignores it and still opens only the published checkpoint.
        if let (Ok(owned), Ok(current)) = (self.file.metadata(), fs::symlink_metadata(&self.path))
            && same_identity(&owned, &current)
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn sync_parents(parent: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        // Newly created ancestors must also survive a restart. Resolve aliases
        // so the directory links synced are those that actually hold the file.
        let resolved = fs::canonicalize(parent)?;
        for directory in resolved.ancestors() {
            File::open(directory)?.sync_all()?;
        }
    }
    #[cfg(not(unix))]
    let _ = parent;
    Ok(())
}

pub(super) fn save(index: &ScannerCandidateIndex, path: &Path) -> Result<()> {
    save_with(index, path, MAX_CHECKPOINT_BYTES, |_| Ok(()))
        .map_err(|error| SbhError::io(path, error))
}

fn save_with(
    index: &ScannerCandidateIndex,
    path: &Path,
    limit: u64,
    before_publish: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    if index.records.len() > MAX_CHECKPOINT_RECORDS {
        return Err(invalid("scanner checkpoint record limit exceeded"));
    }
    let records = OrderedRecords(&index.records);
    let integrity_hash = integrity_hash(&index.context, index.event_generation, &records, limit)?;
    let checkpoint = CheckpointView {
        version: CHECKPOINT_VERSION,
        context: &index.context,
        event_generation: index.event_generation,
        records,
        integrity_hash,
    };
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut stage = StagingFile::create(parent)?;
    {
        let mut writer = LimitedWriter {
            inner: BufWriter::new(&stage.file),
            remaining: limit,
        };
        serde_json::to_writer(&mut writer, &checkpoint).map_err(io::Error::other)?;
        writer.flush()?;
    }
    stage.file.sync_all()?;
    let ready = stage.file.metadata()?;
    // The test seam is after all staging writes/syncs and before the only
    // operation that replaces the published file. Production passes a no-op.
    before_publish(&stage.path)?;
    if !same_snapshot(&ready, &fs::symlink_metadata(&stage.path)?) {
        return Err(invalid(
            "scanner checkpoint staging file changed before publication",
        ));
    }
    fs::rename(&stage.path, path)?;
    stage.published = true;
    // A sync failure here is reported even though the complete new snapshot
    // may already be visible. Never try to roll it back over another writer.
    sync_parents(parent)
}

pub(super) fn load(
    path: &Path,
    expected_context: ScannerIndexContext,
) -> (ScannerCandidateIndex, ScannerIndexLoadStatus) {
    match load_with_limit(path, &expected_context, MAX_CHECKPOINT_BYTES) {
        Ok(index) => (index, ScannerIndexLoadStatus::Loaded),
        Err(status) => (ScannerCandidateIndex::new(expected_context), status),
    }
}

fn load_with_limit(
    path: &Path,
    expected_context: &ScannerIndexContext,
    limit: u64,
) -> std::result::Result<ScannerCandidateIndex, ScannerIndexLoadStatus> {
    let corrupt = |error: io::Error| ScannerIndexLoadStatus::Corrupt(error.to_string());
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(ScannerIndexLoadStatus::Missing);
        }
        Err(error) => return Err(corrupt(error)),
    };
    let before = file.metadata().map_err(corrupt)?;
    if !before.is_file() || before.len() > limit {
        return Err(corrupt(invalid(
            "scanner checkpoint is not a bounded regular file",
        )));
    }
    let reader = BufReader::new(LimitedReader {
        inner: &file,
        remaining: limit,
    });
    let checkpoint: Checkpoint = serde_json::from_reader(reader)
        .map_err(|error| ScannerIndexLoadStatus::Corrupt(error.to_string()))?;
    if !same_snapshot(&before, &file.metadata().map_err(corrupt)?) {
        return Err(corrupt(invalid(
            "scanner checkpoint changed while reading it",
        )));
    }
    if checkpoint.version != CHECKPOINT_VERSION {
        return Err(ScannerIndexLoadStatus::Stale(format!(
            "unsupported scanner index version {} (expected {CHECKPOINT_VERSION})",
            checkpoint.version,
        )));
    }
    if &checkpoint.context != expected_context {
        return Err(ScannerIndexLoadStatus::Stale(
            "root or scanner config fingerprint changed".to_string(),
        ));
    }
    let computed = integrity_hash(
        &checkpoint.context,
        checkpoint.event_generation,
        &checkpoint.records,
        limit,
    )
    .map_err(corrupt)?;
    if computed != checkpoint.integrity_hash {
        return Err(corrupt(invalid("integrity hash mismatch")));
    }
    let mut records = BTreeMap::new();
    let mut paths = BTreeMap::new();
    for record in checkpoint.records {
        if record.event_generation > checkpoint.event_generation {
            return Err(corrupt(invalid(
                "candidate generation exceeds checkpoint generation",
            )));
        }
        if paths.insert(record.path.clone(), record.identity).is_some() {
            // Older checkpoints could retain multiple incarnations of one
            // path. Their ordering cannot identify the current one without a
            // fresh walk, so rediscover instead of reviving an obsolete hint.
            return Err(ScannerIndexLoadStatus::Stale(
                "multiple candidate identities for one path; rediscovery required".to_string(),
            ));
        }
        match records.entry(record.identity) {
            Entry::Vacant(entry) => {
                entry.insert(record);
            }
            Entry::Occupied(_) => {
                return Err(corrupt(invalid(
                    "duplicate candidate identity in scanner checkpoint",
                )));
            }
        }
    }
    Ok(ScannerCandidateIndex {
        context: checkpoint.context,
        event_generation: checkpoint.event_generation,
        records,
        paths,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::index::{CandidateSafetyState, IndexedEntryKind, IndexedPruneDecision};
    use crate::scanner::patterns::StructuralSignals;
    use std::time::{Duration, UNIX_EPOCH};

    fn fixture(label: &str) -> ScannerCandidateIndex {
        let mut index = ScannerCandidateIndex::new(ScannerIndexContext {
            root_fingerprint: format!("roots-{label}"),
            config_fingerprint: "config".to_string(),
        });
        for inode in 1..=3 {
            index.upsert(CandidateIndexRecord {
                path: PathBuf::from(format!("/cache/{label}/target-{inode}")),
                identity: IndexedIdentity {
                    device_id: 9,
                    inode,
                    kind: IndexedEntryKind::Directory,
                },
                parent_identity: None,
                parent_mtime_nanos: None,
                candidate_mtime_nanos: 1,
                candidate_ctime_nanos: Some(2),
                size_estimate_bytes: 4096 * inode,
                prune_decision: IndexedPruneDecision::CandidateOpaque,
                score: Some(0.9),
                safety_state: CandidateSafetyState::Safe,
                fail_count: 0,
                cooldown_until_nanos: None,
                event_generation: 0,
                structural_signals: StructuralSignals::default(),
            });
        }
        index
    }

    // Independent old encoder: this is intentionally not the streaming helper.
    fn legacy(index: &ScannerCandidateIndex) -> Checkpoint {
        let records: Vec<_> = index.records.values().cloned().collect();
        let mut hash = Sha256::new();
        hash.update(serde_json::to_vec(&index.context).unwrap());
        hash.update(index.event_generation.to_le_bytes());
        hash.update(serde_json::to_vec(&records).unwrap());
        Checkpoint {
            version: CHECKPOINT_VERSION,
            context: index.context.clone(),
            event_generation: index.event_generation,
            records,
            integrity_hash: hash.finalize().into(),
        }
    }

    #[test]
    fn streaming_bytes_match_v2_and_preserve_failure_cooldowns_after_restart() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("checkpoint.json");
        let mut index = fixture("original");
        let id = *index.records.keys().next().unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(1000);
        index.record_failure(id, now, Duration::from_secs(30), Duration::from_secs(60));
        save(&index, &path).unwrap();
        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes, serde_json::to_vec(&legacy(&index)).unwrap());
        let (loaded, status) = load(&path, index.context.clone());
        assert_eq!(status, ScannerIndexLoadStatus::Loaded);
        assert_eq!(loaded.records, index.records);
        assert!(loaded.in_cooldown(id, now + Duration::from_secs(10)));
        assert!(!loaded.in_cooldown(id, now + Duration::from_secs(31)));
    }

    #[test]
    fn interrupted_save_preserves_the_published_snapshot_and_cleans_only_its_staging() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("checkpoint.json");
        let old = fixture("old");
        save(&old, &path).unwrap();
        let bytes = fs::read(&path).unwrap();
        let leftover = temp.path().join(".sbh-index-old-crash.tmp");
        fs::write(&leftover, b"prior crash evidence").unwrap();
        let error = save_with(&fixture("new"), &path, MAX_CHECKPOINT_BYTES, |stage| {
            let staged: Checkpoint = serde_json::from_slice(&fs::read(stage)?).unwrap();
            assert_eq!(staged.context, fixture("new").context);
            Err(io::Error::other("injected failure before publication"))
        })
        .unwrap_err();
        assert!(error.to_string().contains("injected failure"));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(fs::read(leftover).unwrap(), b"prior crash evidence");
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
        assert_eq!(load(&path, old.context).1, ScannerIndexLoadStatus::Loaded);
    }

    #[test]
    fn failed_rename_leaves_existing_destination_untouched() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("directory-not-checkpoint");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("keep"), b"unrelated").unwrap();
        assert!(save(&fixture("new"), &path).is_err());
        assert_eq!(fs::read(path.join("keep")).unwrap(), b"unrelated");
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[test]
    fn size_limit_failure_keeps_the_previous_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("checkpoint.json");
        let index = fixture("small");
        save(&index, &path).unwrap();
        let before = fs::read(&path).unwrap();
        // Hashing fits, but the full checkpoint exceeds this smaller bound.
        assert!(save_with(&index, &path, before.len() as u64 - 1, |_| Ok(())).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn predictable_temp_symlink_never_truncates_its_target() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("checkpoint.json");
        let important = temp.path().join("important");
        fs::write(&important, b"do not truncate").unwrap();
        let old_temp = path.with_extension("tmp");
        symlink(&important, &old_temp).unwrap();
        save(&fixture("new"), &path).unwrap();
        assert_eq!(fs::read(important).unwrap(), b"do not truncate");
        assert!(
            fs::symlink_metadata(old_temp)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[allow(clippy::needless_collect)]
    #[test]
    fn concurrent_saves_publish_whole_snapshots_with_independent_staging() {
        use std::sync::{Arc, Barrier};
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("checkpoint.json");
        let ready = Arc::new(Barrier::new(2));
        let workers: Vec<_> = ["first", "second"]
            .into_iter()
            .map(|label| {
                let path = path.clone();
                let ready = Arc::clone(&ready);
                std::thread::spawn(move || {
                    save_with(&fixture(label), &path, MAX_CHECKPOINT_BYTES, |_| {
                        ready.wait();
                        Ok(())
                    })
                    .unwrap();
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        let bytes = fs::read(&path).unwrap();
        assert!(
            ["first", "second"]
                .into_iter()
                .any(|label| { bytes == serde_json::to_vec(&legacy(&fixture(label))).unwrap() }),
            "the winner must be one complete snapshot, not a mix of writers",
        );
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_fifos_and_directories_are_not_checkpoint_inputs() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let index = fixture("new");
        let real = temp.path().join("real.json");
        save(&index, &real).unwrap();
        let alias = temp.path().join("alias.json");
        symlink(&real, &alias).unwrap();
        let dangling = temp.path().join("dangling.json");
        symlink("missing-target", &dangling).unwrap();
        let fifo = temp.path().join("fifo.json");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR).unwrap();
        for path in [
            alias.as_path(),
            dangling.as_path(),
            fifo.as_path(),
            temp.path(),
        ] {
            let (loaded, status) = load(path, index.context.clone());
            assert!(loaded.is_empty());
            assert!(
                matches!(status, ScannerIndexLoadStatus::Corrupt(_)),
                "{status:?}"
            );
        }
        assert_eq!(
            load(&temp.path().join("absent.json"), index.context).1,
            ScannerIndexLoadStatus::Missing,
        );
    }

    #[test]
    fn oversized_sparse_checkpoint_is_rejected_without_parsing_it() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("large.json");
        File::create(&path)
            .unwrap()
            .set_len(MAX_CHECKPOINT_BYTES + 1)
            .unwrap();
        let (loaded, status) = load(&path, fixture("new").context);
        assert!(loaded.is_empty());
        assert!(matches!(status, ScannerIndexLoadStatus::Corrupt(_)));
        assert_eq!(fs::metadata(path).unwrap().len(), MAX_CHECKPOINT_BYTES + 1);
    }

    #[test]
    fn bounded_reader_distinguishes_real_eof_from_over_limit_whitespace() {
        let mut exact = LimitedReader {
            inner: &b"{}"[..],
            remaining: 2,
        };
        let value: serde_json::Value = serde_json::from_reader(&mut exact).unwrap();
        assert_eq!(value, serde_json::json!({}));
        let mut extended = LimitedReader {
            inner: &b"{}   "[..],
            remaining: 2,
        };
        assert!(serde_json::from_reader::<_, serde_json::Value>(&mut extended).is_err());
        assert_eq!(extended.inner, b"  ", "only one excess byte is probed");
    }

    #[test]
    fn truncated_tampered_and_trailing_garbage_snapshots_fall_back_to_discovery() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("checkpoint.json");
        let index = fixture("original");
        let checkpoint = legacy(&index);
        let bytes = serde_json::to_vec(&checkpoint).unwrap();
        let mut tampered = legacy(&index);
        tampered.records[0].size_estimate_bytes += 1;
        let mut garbage = bytes.clone();
        garbage.extend_from_slice(b" not-json");
        for bad in [
            bytes[..bytes.len() / 2].to_vec(),
            serde_json::to_vec(&tampered).unwrap(),
            garbage,
        ] {
            fs::write(&path, &bad).unwrap();
            let (loaded, status) = load(&path, index.context.clone());
            assert!(loaded.is_empty());
            assert!(
                matches!(status, ScannerIndexLoadStatus::Corrupt(_)),
                "{status:?}"
            );
            assert_eq!(
                fs::read(&path).unwrap(),
                bad,
                "a read-only load never repairs the file"
            );
        }
    }

    #[test]
    fn valid_hash_does_not_hide_duplicate_identities_or_impossible_generations() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("checkpoint.json");
        let index = fixture("new");
        for duplicate in [true, false] {
            let mut checkpoint = legacy(&index);
            if duplicate {
                let mut duplicate = checkpoint.records[0].clone();
                duplicate.path = PathBuf::from("/cache/same-identity-other-path");
                checkpoint.records.push(duplicate);
            } else {
                checkpoint.records[0].event_generation = 1;
            }
            checkpoint.integrity_hash = integrity_hash(
                &checkpoint.context,
                checkpoint.event_generation,
                &checkpoint.records,
                MAX_CHECKPOINT_BYTES,
            )
            .unwrap();
            fs::write(&path, serde_json::to_vec(&checkpoint).unwrap()).unwrap();
            let (loaded, status) = load(&path, index.context.clone());
            assert!(loaded.is_empty());
            assert!(
                matches!(status, ScannerIndexLoadStatus::Corrupt(_)),
                "{status:?}"
            );
        }
    }

    #[test]
    fn older_generation_hints_keep_their_invalidated_state_after_restart() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("new/parents/checkpoint.json");
        let mut index = fixture("generation");
        index.mark_event_overflow();
        save(&index, &path).unwrap();
        let (loaded, status) = load(&path, index.context.clone());
        assert_eq!(status, ScannerIndexLoadStatus::Loaded);
        assert_eq!(loaded.event_generation(), 1);
        assert_eq!(loaded.len(), 3);
        assert!(loaded.ranked_records(UNIX_EPOCH, 3).is_empty());
    }

    #[test]
    fn old_checkpoint_with_multiple_incarnations_of_one_path_requires_rediscovery() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("checkpoint.json");
        let index = fixture("old-incarnations");
        let mut checkpoint = legacy(&index);
        checkpoint.records[1].path = checkpoint.records[0].path.clone();
        checkpoint.integrity_hash = integrity_hash(
            &checkpoint.context,
            checkpoint.event_generation,
            &checkpoint.records,
            MAX_CHECKPOINT_BYTES,
        )
        .unwrap();
        let bytes = serde_json::to_vec(&checkpoint).unwrap();
        fs::write(&path, &bytes).unwrap();
        let (loaded, status) = load(&path, index.context);
        assert!(
            matches!(status, ScannerIndexLoadStatus::Stale(_)),
            "{status:?}"
        );
        assert!(loaded.is_empty());
        assert!(loaded.paths.is_empty());
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}
