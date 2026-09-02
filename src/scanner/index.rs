//! Persistent scanner v2 candidate index.
//!
//! This index is keyed by filesystem identity and stores one record per
//! candidate root. It deliberately does not model every child entry in opaque
//! artifact trees; the walker/scorer decide which root is a candidate, and this
//! module persists that root's freshness and safety state.

#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{BufReader, BufWriter, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::core::config::ScannerConfig;
use crate::core::errors::{Result, SbhError};
use crate::scanner::patterns::{
    ArtifactCategory, ArtifactClassification, OpaqueTreeClassification, OpaqueTreeDisposition,
};
use crate::scanner::scoring::{
    CandidacyScore, DecisionAction, DecisionOutcome, EvidenceLedger, ScoreFactors,
};
use crate::scanner::walker::{FsEntryKind, FsIdentity};

const CHECKPOINT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IndexedEntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

impl From<FsEntryKind> for IndexedEntryKind {
    fn from(value: FsEntryKind) -> Self {
        match value {
            FsEntryKind::File => Self::File,
            FsEntryKind::Directory => Self::Directory,
            FsEntryKind::Symlink => Self::Symlink,
            FsEntryKind::Other => Self::Other,
        }
    }
}

impl From<IndexedEntryKind> for FsEntryKind {
    fn from(value: IndexedEntryKind) -> Self {
        match value {
            IndexedEntryKind::File => Self::File,
            IndexedEntryKind::Directory => Self::Directory,
            IndexedEntryKind::Symlink => Self::Symlink,
            IndexedEntryKind::Other => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct IndexedIdentity {
    pub device_id: u64,
    pub inode: u64,
    pub kind: IndexedEntryKind,
}

impl From<FsIdentity> for IndexedIdentity {
    fn from(value: FsIdentity) -> Self {
        Self {
            device_id: value.device_id,
            inode: value.inode,
            kind: value.kind.into(),
        }
    }
}

impl From<IndexedIdentity> for FsIdentity {
    fn from(value: IndexedIdentity) -> Self {
        Self {
            device_id: value.device_id,
            inode: value.inode,
            kind: value.kind.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndexedPruneDecision {
    None,
    CandidateOpaque,
    ProtectedOpaque,
    SignalOnly,
}

impl IndexedPruneDecision {
    fn from_opaque_tree(opaque_tree: Option<&OpaqueTreeClassification>) -> Self {
        let Some(opaque_tree) = opaque_tree else {
            return Self::None;
        };
        match opaque_tree.disposition {
            OpaqueTreeDisposition::CandidateOpaque => Self::CandidateOpaque,
            OpaqueTreeDisposition::ProtectedOpaque => Self::ProtectedOpaque,
            OpaqueTreeDisposition::SignalOnly => Self::SignalOnly,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidateSafetyState {
    Unknown,
    Safe,
    ActiveReference,
    Vetoed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateFreshness {
    Fresh,
    Missing,
    IdentityChanged,
    MetadataChanged,
    EventGenerationChanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScannerIndexLoadStatus {
    Loaded,
    Missing,
    Stale(String),
    Corrupt(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannerIndexContext {
    pub root_fingerprint: String,
    pub config_fingerprint: String,
}

impl ScannerIndexContext {
    #[must_use]
    pub fn from_roots_and_config(root_paths: &[PathBuf], scanner_config: &ScannerConfig) -> Self {
        Self {
            root_fingerprint: root_fingerprint(root_paths),
            config_fingerprint: config_fingerprint(scanner_config),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidateIndexRecord {
    pub path: PathBuf,
    pub identity: IndexedIdentity,
    pub parent_identity: Option<IndexedIdentity>,
    pub parent_mtime_nanos: Option<u128>,
    pub candidate_mtime_nanos: u128,
    pub candidate_ctime_nanos: Option<u128>,
    pub size_estimate_bytes: u64,
    pub prune_decision: IndexedPruneDecision,
    pub score: Option<f64>,
    pub safety_state: CandidateSafetyState,
    pub fail_count: u32,
    pub cooldown_until_nanos: Option<u128>,
    pub event_generation: u64,
}

impl CandidateIndexRecord {
    pub fn from_candidate_score(
        score: &CandidacyScore,
        opaque_tree: Option<&OpaqueTreeClassification>,
        event_generation: u64,
    ) -> Result<Option<Self>> {
        let Some(identity) = score.identity else {
            return Ok(None);
        };
        let metadata =
            fs::symlink_metadata(&score.path).map_err(|e| SbhError::io(&score.path, e))?;
        let (parent_identity, parent_mtime_nanos) = parent_snapshot(&score.path);

        Ok(Some(Self {
            path: score.path.clone(),
            identity: identity.into(),
            parent_identity,
            parent_mtime_nanos,
            candidate_mtime_nanos: system_time_nanos(
                metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            ),
            candidate_ctime_nanos: ctime_for_path(&score.path).map(system_time_nanos),
            size_estimate_bytes: score.size_bytes,
            prune_decision: IndexedPruneDecision::from_opaque_tree(opaque_tree),
            score: Some(score.total_score),
            safety_state: safety_state_from_score(score),
            fail_count: 0,
            cooldown_until_nanos: None,
            event_generation,
        }))
    }

    #[must_use]
    pub fn freshness(
        &self,
        current_identity: Option<IndexedIdentity>,
        entry_modified_nanos: Option<u128>,
        status_change_nanos: Option<u128>,
        current_event_generation: u64,
    ) -> CandidateFreshness {
        let Some(current_identity) = current_identity else {
            return CandidateFreshness::Missing;
        };
        if current_identity != self.identity {
            return CandidateFreshness::IdentityChanged;
        }
        if current_event_generation != self.event_generation {
            return CandidateFreshness::EventGenerationChanged;
        }
        if entry_modified_nanos != Some(self.candidate_mtime_nanos)
            || status_change_nanos != self.candidate_ctime_nanos
        {
            return CandidateFreshness::MetadataChanged;
        }
        CandidateFreshness::Fresh
    }

    #[must_use]
    pub fn parent_discovery_valid(
        &self,
        parent_identity: Option<IndexedIdentity>,
        parent_mtime_nanos: Option<u128>,
    ) -> bool {
        self.parent_identity == parent_identity && self.parent_mtime_nanos == parent_mtime_nanos
    }

    #[must_use]
    pub fn evidence_matches(&self, other: &Self) -> bool {
        self.path == other.path
            && self.identity == other.identity
            && self.candidate_mtime_nanos == other.candidate_mtime_nanos
            && self.candidate_ctime_nanos == other.candidate_ctime_nanos
            && self.size_estimate_bytes == other.size_estimate_bytes
            && self.prune_decision == other.prune_decision
    }

    #[must_use]
    pub fn to_candidate_score(&self) -> CandidacyScore {
        let total_score = self.score.unwrap_or(0.0).clamp(0.0, 1.0);
        CandidacyScore {
            path: self.path.clone(),
            identity: Some(self.identity.into()),
            total_score,
            factors: ScoreFactors {
                location: total_score,
                name: total_score,
                age: total_score,
                size: total_score,
                structure: total_score,
                pressure_multiplier: 1.0,
            },
            vetoed: false,
            veto_reason: None,
            classification: ArtifactClassification {
                pattern_name: std::borrow::Cow::Borrowed("indexed-v2-candidate"),
                category: ArtifactCategory::Unknown,
                name_confidence: total_score,
                structural_confidence: total_score,
                combined_confidence: total_score,
            },
            size_bytes: self.size_estimate_bytes,
            age: Duration::ZERO,
            decision: DecisionOutcome {
                action: DecisionAction::Delete,
                posterior_abandoned: total_score,
                expected_loss_keep: total_score,
                expected_loss_delete: 1.0 - total_score,
                calibration_score: total_score,
                fallback_active: false,
                certainty: crate::scanner::scoring::ArtifactCertainty::Unclear,
                posterior_floor_applied: false,
            },
            ledger: EvidenceLedger {
                terms: Vec::new(),
                summary: "v2 persistent index candidate".to_string(),
            },
        }
    }
}

fn safety_state_from_score(score: &CandidacyScore) -> CandidateSafetyState {
    if !score.vetoed {
        return CandidateSafetyState::Safe;
    }
    if score.veto_reason.as_ref().is_some_and(|reason| {
        reason.contains("active reference")
            || reason.contains("currently open")
            || reason.contains("Cannot reclaim safely")
    }) {
        CandidateSafetyState::ActiveReference
    } else {
        CandidateSafetyState::Vetoed
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScannerIndexCheckpoint {
    version: u32,
    context: ScannerIndexContext,
    event_generation: u64,
    records: Vec<CandidateIndexRecord>,
    integrity_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct ScannerCandidateIndex {
    context: ScannerIndexContext,
    event_generation: u64,
    records: BTreeMap<IndexedIdentity, CandidateIndexRecord>,
}

impl ScannerCandidateIndex {
    #[must_use]
    pub fn new(context: ScannerIndexContext) -> Self {
        Self {
            context,
            event_generation: 0,
            records: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn context(&self) -> &ScannerIndexContext {
        &self.context
    }

    #[must_use]
    pub fn event_generation(&self) -> u64 {
        self.event_generation
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    #[must_use]
    pub fn get(&self, identity: IndexedIdentity) -> Option<&CandidateIndexRecord> {
        self.records.get(&identity)
    }

    pub fn upsert(&mut self, mut record: CandidateIndexRecord) {
        record.event_generation = self.event_generation;
        if let Some(existing) = self.records.get(&record.identity)
            && existing.evidence_matches(&record)
        {
            record.fail_count = existing.fail_count;
            record.cooldown_until_nanos = existing.cooldown_until_nanos;
            if existing.safety_state == CandidateSafetyState::Failed {
                record.safety_state = CandidateSafetyState::Failed;
            }
        }
        self.records.insert(record.identity, record);
    }

    #[must_use]
    pub fn candidate_in_cooldown(&self, record: &CandidateIndexRecord, now: SystemTime) -> bool {
        self.records.get(&record.identity).is_some_and(|existing| {
            existing.evidence_matches(record) && self.in_cooldown(record.identity, now)
        })
    }

    #[must_use]
    pub fn ranked_candidate_scores(&self, now: SystemTime, limit: usize) -> Vec<CandidacyScore> {
        let mut records = self
            .records
            .values()
            .filter(|record| {
                matches!(
                    record.safety_state,
                    CandidateSafetyState::Safe | CandidateSafetyState::Failed
                ) && record.score.is_some()
                    && !self.in_cooldown(record.identity, now)
            })
            .collect::<Vec<_>>();
        records.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.size_estimate_bytes.cmp(&a.size_estimate_bytes))
        });
        records
            .into_iter()
            .take(limit)
            .map(CandidateIndexRecord::to_candidate_score)
            .collect()
    }

    pub fn mark_event_overflow(&mut self) {
        self.event_generation = self.event_generation.saturating_add(1);
    }

    pub fn record_failure(
        &mut self,
        identity: IndexedIdentity,
        now: SystemTime,
        base_cooldown: Duration,
        max_cooldown: Duration,
    ) {
        let Some(record) = self.records.get_mut(&identity) else {
            return;
        };
        record.fail_count = record.fail_count.saturating_add(1);
        record.safety_state = CandidateSafetyState::Failed;

        let shift = record.fail_count.saturating_sub(1).min(31);
        let multiplier = 1_u32.checked_shl(shift).unwrap_or(u32::MAX);
        let cooldown = base_cooldown.saturating_mul(multiplier).min(max_cooldown);
        record.cooldown_until_nanos = Some(system_time_nanos(now + cooldown));
    }

    #[must_use]
    pub fn in_cooldown(&self, identity: IndexedIdentity, now: SystemTime) -> bool {
        let Some(record) = self.records.get(&identity) else {
            return false;
        };
        record
            .cooldown_until_nanos
            .is_some_and(|until| system_time_nanos(now) < until)
    }

    pub fn save_checkpoint(&self, path: &Path) -> Result<()> {
        let records = self.records.values().cloned().collect::<Vec<_>>();
        let integrity_hash =
            checkpoint_integrity_hash(&self.context, self.event_generation, &records)?;
        let checkpoint = ScannerIndexCheckpoint {
            version: CHECKPOINT_VERSION,
            context: self.context.clone(),
            event_generation: self.event_generation,
            records,
            integrity_hash,
        };

        let temp_path = path.with_extension("tmp");
        if let Some(parent) = temp_path.parent() {
            fs::create_dir_all(parent).map_err(|e| SbhError::io(parent, e))?;
        }

        let file = {
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                opts.mode(0o600);
            }
            opts.open(&temp_path)
                .map_err(|e| SbhError::io(&temp_path, e))?
        };
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &checkpoint).map_err(|e| SbhError::Serialization {
            context: "scanner_candidate_index_write",
            details: e.to_string(),
        })?;
        writer.flush().map_err(|e| SbhError::io(&temp_path, e))?;
        fs::rename(&temp_path, path).map_err(|e| SbhError::io(path, e))?;
        Ok(())
    }

    #[must_use]
    pub fn load_checkpoint(
        path: &Path,
        expected_context: ScannerIndexContext,
    ) -> (Self, ScannerIndexLoadStatus) {
        let missing = || {
            (
                Self::new(expected_context.clone()),
                ScannerIndexLoadStatus::Missing,
            )
        };
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return missing(),
            Err(err) => {
                return (
                    Self::new(expected_context),
                    ScannerIndexLoadStatus::Corrupt(err.to_string()),
                );
            }
        };
        let reader = BufReader::new(file);
        let checkpoint: ScannerIndexCheckpoint = match serde_json::from_reader(reader) {
            Ok(checkpoint) => checkpoint,
            Err(err) => {
                return (
                    Self::new(expected_context),
                    ScannerIndexLoadStatus::Corrupt(err.to_string()),
                );
            }
        };

        if checkpoint.version != CHECKPOINT_VERSION {
            return (
                Self::new(expected_context),
                ScannerIndexLoadStatus::Stale(format!(
                    "unsupported scanner index version {} (expected {CHECKPOINT_VERSION})",
                    checkpoint.version
                )),
            );
        }
        if checkpoint.context != expected_context {
            return (
                Self::new(expected_context),
                ScannerIndexLoadStatus::Stale(
                    "root or scanner config fingerprint changed".to_string(),
                ),
            );
        }
        match checkpoint_integrity_hash(
            &checkpoint.context,
            checkpoint.event_generation,
            &checkpoint.records,
        ) {
            Ok(computed) if computed == checkpoint.integrity_hash => {}
            Ok(_) => {
                return (
                    Self::new(expected_context),
                    ScannerIndexLoadStatus::Corrupt("integrity hash mismatch".to_string()),
                );
            }
            Err(err) => {
                return (
                    Self::new(expected_context),
                    ScannerIndexLoadStatus::Corrupt(err.to_string()),
                );
            }
        }

        let mut records = BTreeMap::new();
        for record in checkpoint.records {
            records.insert(record.identity, record);
        }
        (
            Self {
                context: checkpoint.context,
                event_generation: checkpoint.event_generation,
                records,
            },
            ScannerIndexLoadStatus::Loaded,
        )
    }
}

fn checkpoint_integrity_hash(
    context: &ScannerIndexContext,
    event_generation: u64,
    records: &[CandidateIndexRecord],
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let context_bytes = serde_json::to_vec(context).map_err(|e| SbhError::Serialization {
        context: "scanner_candidate_index_integrity",
        details: e.to_string(),
    })?;
    let records_bytes = serde_json::to_vec(records).map_err(|e| SbhError::Serialization {
        context: "scanner_candidate_index_integrity",
        details: e.to_string(),
    })?;
    hasher.update(context_bytes);
    hasher.update(event_generation.to_le_bytes());
    hasher.update(records_bytes);
    Ok(hasher.finalize().into())
}

fn root_fingerprint(root_paths: &[PathBuf]) -> String {
    let mut roots = root_paths.to_vec();
    roots.sort();

    let mut hasher = Sha256::new();
    for root in roots {
        hasher.update(root.as_os_str().as_encoded_bytes());
        match fs::symlink_metadata(&root) {
            Ok(metadata) => {
                let identity = identity_from_metadata(&metadata);
                hasher.update(identity.device_id.to_le_bytes());
                hasher.update(identity.inode.to_le_bytes());
                hasher.update([identity.kind as u8]);
            }
            Err(_) => hasher.update(b"missing-root"),
        }
    }
    hex_hash(hasher.finalize().into())
}

fn config_fingerprint(scanner_config: &ScannerConfig) -> String {
    let bytes = serde_json::to_vec(scanner_config).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_hash(hasher.finalize().into())
}

fn parent_snapshot(path: &Path) -> (Option<IndexedIdentity>, Option<u128>) {
    let Some(parent) = path.parent() else {
        return (None, None);
    };
    let Ok(metadata) = fs::symlink_metadata(parent) else {
        return (None, None);
    };
    (
        Some(identity_from_metadata(&metadata)),
        metadata.modified().ok().map(system_time_nanos),
    )
}

fn identity_from_metadata(metadata: &fs::Metadata) -> IndexedIdentity {
    let kind = if metadata.file_type().is_symlink() {
        IndexedEntryKind::Symlink
    } else if metadata.is_dir() {
        IndexedEntryKind::Directory
    } else if metadata.is_file() {
        IndexedEntryKind::File
    } else {
        IndexedEntryKind::Other
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        IndexedIdentity {
            device_id: metadata.dev(),
            inode: metadata.ino(),
            kind,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        IndexedIdentity {
            device_id: 0,
            inode: 0,
            kind,
        }
    }
}

fn ctime_for_path(path: &Path) -> Option<SystemTime> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(path).ok()?;
        let secs = metadata.ctime();
        let nanos = metadata.ctime_nsec();
        if secs < 0 || nanos < 0 {
            return None;
        }
        Some(UNIX_EPOCH + Duration::new(u64::try_from(secs).ok()?, u32::try_from(nanos).ok()?))
    }
    #[cfg(not(unix))]
    {
        fs::symlink_metadata(path).ok()?.created().ok()
    }
}

fn system_time_nanos(time: SystemTime) -> u128 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos()
}

fn hex_hash(hash: [u8; 32]) -> String {
    use std::fmt::Write as _;
    hash.iter().fold(String::with_capacity(64), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::ScannerEngineMode;
    use crate::scanner::patterns::{
        ArtifactCategory, ArtifactClassification, OpaqueTreeClassification,
    };
    use crate::scanner::scoring::{DecisionAction, DecisionOutcome, EvidenceLedger, ScoreFactors};
    use crate::scanner::walker::FsEntryKind;
    use std::borrow::Cow;

    fn identity(n: u64) -> IndexedIdentity {
        IndexedIdentity {
            device_id: 7,
            inode: n,
            kind: IndexedEntryKind::Directory,
        }
    }

    fn context(label: &str) -> ScannerIndexContext {
        ScannerIndexContext {
            root_fingerprint: format!("root-{label}"),
            config_fingerprint: format!("config-{label}"),
        }
    }

    fn record(id: IndexedIdentity, parent: IndexedIdentity) -> CandidateIndexRecord {
        CandidateIndexRecord {
            path: PathBuf::from(format!("/tmp/target-{}", id.inode)),
            identity: id,
            parent_identity: Some(parent),
            parent_mtime_nanos: Some(100),
            candidate_mtime_nanos: 200,
            candidate_ctime_nanos: Some(300),
            size_estimate_bytes: 1024,
            prune_decision: IndexedPruneDecision::CandidateOpaque,
            score: Some(0.9),
            safety_state: CandidateSafetyState::Safe,
            fail_count: 0,
            cooldown_until_nanos: None,
            event_generation: 0,
        }
    }

    fn score(path: PathBuf, fs_identity: FsIdentity) -> CandidacyScore {
        CandidacyScore {
            path,
            identity: Some(fs_identity),
            total_score: 0.9,
            factors: ScoreFactors {
                location: 0.8,
                name: 0.9,
                age: 0.8,
                size: 0.7,
                structure: 0.9,
                pressure_multiplier: 1.0,
            },
            vetoed: false,
            veto_reason: None,
            classification: ArtifactClassification {
                pattern_name: Cow::Borrowed("target"),
                category: ArtifactCategory::RustTarget,
                name_confidence: 0.95,
                structural_confidence: 0.95,
                combined_confidence: 0.95,
            },
            size_bytes: 1024,
            age: Duration::from_hours(1),
            decision: DecisionOutcome {
                action: DecisionAction::Delete,
                posterior_abandoned: 0.9,
                expected_loss_keep: 1.0,
                expected_loss_delete: 0.1,
                calibration_score: 0.9,
                fallback_active: false,
                certainty: crate::scanner::scoring::ArtifactCertainty::Definite,
                posterior_floor_applied: false,
            },
            ledger: EvidenceLedger {
                terms: Vec::new(),
                summary: "test".to_string(),
            },
        }
    }

    #[test]
    fn checkpoint_survives_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("scanner-index.json");
        let ctx = context("same");
        let mut index = ScannerCandidateIndex::new(ctx.clone());
        let record = record(identity(1), identity(99));
        index.upsert(record.clone());
        index.save_checkpoint(&path).unwrap();

        let (loaded, status) = ScannerCandidateIndex::load_checkpoint(&path, ctx);

        assert_eq!(status, ScannerIndexLoadStatus::Loaded);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.get(record.identity), Some(&record));
    }

    #[test]
    fn stale_config_invalidates_checkpoint() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("scanner-index.json");
        let mut index = ScannerCandidateIndex::new(context("old"));
        index.upsert(record(identity(1), identity(99)));
        index.save_checkpoint(&path).unwrap();

        let (loaded, status) = ScannerCandidateIndex::load_checkpoint(&path, context("new"));

        assert!(matches!(status, ScannerIndexLoadStatus::Stale(_)));
        assert!(loaded.is_empty());
    }

    #[test]
    fn corrupt_checkpoint_invalidates() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("scanner-index.json");
        fs::write(&path, "{not valid json").unwrap();

        let (loaded, status) = ScannerCandidateIndex::load_checkpoint(&path, context("same"));

        assert!(matches!(status, ScannerIndexLoadStatus::Corrupt(_)));
        assert!(loaded.is_empty());
    }

    #[test]
    fn parent_mtime_does_not_prove_candidate_freshness() {
        let parent = identity(99);
        let record = record(identity(1), parent);

        assert!(record.parent_discovery_valid(Some(parent), Some(100)));
        assert_eq!(
            record.freshness(Some(identity(1)), Some(201), Some(300), 0),
            CandidateFreshness::MetadataChanged,
            "candidate mtime must invalidate even when parent discovery metadata is unchanged"
        );
    }

    #[test]
    fn event_generation_invalidates_candidate_freshness() {
        let record = record(identity(1), identity(99));

        assert_eq!(
            record.freshness(Some(identity(1)), Some(200), Some(300), 1),
            CandidateFreshness::EventGenerationChanged
        );
    }

    #[test]
    fn records_failure_backoff() {
        let mut index = ScannerCandidateIndex::new(context("same"));
        let id = identity(1);
        index.upsert(record(id, identity(99)));
        let now = UNIX_EPOCH + Duration::from_secs(1_000);

        index.record_failure(id, now, Duration::from_secs(10), Duration::from_mins(1));

        assert!(index.in_cooldown(id, now + Duration::from_secs(5)));
        assert!(!index.in_cooldown(id, now + Duration::from_secs(11)));
        assert_eq!(index.get(id).unwrap().fail_count, 1);
    }

    #[test]
    fn upsert_preserves_backoff_for_same_evidence() {
        let mut index = ScannerCandidateIndex::new(context("same"));
        let id = identity(1);
        let record = record(id, identity(99));
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        index.upsert(record.clone());
        index.record_failure(id, now, Duration::from_secs(10), Duration::from_mins(1));

        index.upsert(record);

        assert!(index.in_cooldown(id, now + Duration::from_secs(5)));
        assert_eq!(index.get(id).unwrap().fail_count, 1);
    }

    #[test]
    fn upsert_resets_backoff_when_evidence_changes() {
        let mut index = ScannerCandidateIndex::new(context("same"));
        let id = identity(1);
        let mut changed = record(id, identity(99));
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        index.upsert(record(id, identity(99)));
        index.record_failure(id, now, Duration::from_secs(10), Duration::from_mins(1));
        changed.candidate_mtime_nanos += 1;

        index.upsert(changed);

        assert!(!index.in_cooldown(id, now + Duration::from_secs(5)));
        assert_eq!(index.get(id).unwrap().fail_count, 0);
    }

    #[test]
    fn ranked_candidates_come_from_safe_non_cooled_records() {
        let mut index = ScannerCandidateIndex::new(context("same"));
        let high = identity(1);
        let low = identity(2);
        let cooled = identity(3);
        let mut high_record = record(high, identity(99));
        high_record.score = Some(0.9);
        high_record.size_estimate_bytes = 100;
        let mut low_record = record(low, identity(99));
        low_record.score = Some(0.6);
        low_record.size_estimate_bytes = 200;
        let mut cooled_record = record(cooled, identity(99));
        cooled_record.score = Some(0.95);
        index.upsert(low_record);
        index.upsert(high_record);
        index.upsert(cooled_record);
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        index.record_failure(cooled, now, Duration::from_secs(10), Duration::from_mins(1));

        let ranked = index.ranked_candidate_scores(now + Duration::from_secs(5), 8);

        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].identity, Some(FsIdentity::from(high)));
        assert_eq!(ranked[1].identity, Some(FsIdentity::from(low)));
    }

    #[test]
    fn ranked_candidates_retry_failed_records_after_cooldown() {
        let mut index = ScannerCandidateIndex::new(context("same"));
        let failed = identity(1);
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        index.upsert(record(failed, identity(99)));
        index.record_failure(failed, now, Duration::from_secs(10), Duration::from_mins(1));

        let cooling = index.ranked_candidate_scores(now + Duration::from_secs(5), 8);
        assert!(
            cooling.is_empty(),
            "expected no ranked candidates while the failure cooldown is active, got {cooling:?}"
        );

        let ranked = index.ranked_candidate_scores(now + Duration::from_secs(11), 8);

        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].identity, Some(FsIdentity::from(failed)));
    }

    #[test]
    fn opaque_candidate_is_one_record_not_children() {
        let mut index = ScannerCandidateIndex::new(context("same"));
        let tmp = tempfile::tempdir().unwrap();
        let candidate = tmp.path().join("target");
        fs::create_dir(&candidate).unwrap();
        fs::create_dir(candidate.join("debug")).unwrap();
        fs::write(candidate.join("debug").join("object.o"), "obj").unwrap();
        let metadata = fs::symlink_metadata(&candidate).unwrap();
        let score = score(
            candidate,
            FsIdentity {
                device_id: identity_from_metadata(&metadata).device_id,
                inode: identity_from_metadata(&metadata).inode,
                kind: FsEntryKind::Directory,
            },
        );
        let opaque = OpaqueTreeClassification {
            disposition: OpaqueTreeDisposition::CandidateOpaque,
            reason: "test".into(),
            classification: score.classification.clone(),
        };
        let record = CandidateIndexRecord::from_candidate_score(
            &score,
            Some(&opaque),
            index.event_generation(),
        )
        .unwrap()
        .unwrap();

        index.upsert(record);

        assert_eq!(index.len(), 1);
        assert!(
            index
                .get(IndexedIdentity::from(score.identity.unwrap()))
                .is_some_and(
                    |record| record.prune_decision == IndexedPruneDecision::CandidateOpaque
                )
        );
    }

    #[test]
    fn context_changes_when_scanner_config_changes() {
        let roots = vec![PathBuf::from("/tmp")];
        let v1_config = ScannerConfig {
            engine: ScannerEngineMode::V1,
            ..Default::default()
        };
        let v2_config = ScannerConfig {
            engine: ScannerEngineMode::V2,
            ..Default::default()
        };
        let v1 = ScannerIndexContext::from_roots_and_config(&roots, &v1_config);
        let v2 = ScannerIndexContext::from_roots_and_config(&roots, &v2_config);

        assert_ne!(v1.config_fingerprint, v2.config_fingerprint);
    }
}
