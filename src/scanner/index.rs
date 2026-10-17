//! Persistent scanner v2 candidate index.
//!
//! This index is keyed by filesystem identity and stores one record per
//! candidate root. It deliberately does not model every child entry in opaque
//! artifact trees; the walker/scorer decide which root is a candidate, and this
//! module persists that root's freshness and safety state.

#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::core::config::ScannerConfig;
use crate::core::errors::{Result, SbhError};
use crate::scanner::patterns::{
    ArtifactCategory, ArtifactClassification, OpaqueTreeClassification, OpaqueTreeDisposition,
    StructuralSignals,
};
use crate::scanner::scoring::{
    CandidacyScore, DecisionAction, DecisionOutcome, EvidenceLedger, ScoreFactors,
};
use crate::scanner::walker::{FsEntryKind, FsIdentity};

mod checkpoint;
mod replay;

/// Bumped to 2 when records gained `structural_signals`; a version-1
/// checkpoint is rejected and the next pass walks the roots once.
const CHECKPOINT_VERSION: u32 = 2;

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
    /// The structural evidence the walk found under the candidate (markers
    /// under `debug/`, a `CACHEDIR.TAG`, object files). A replay scores with
    /// this instead of re-walking the subtree or, worse, looking only at the
    /// root's own entries and downgrading a definite target to `unclear`.
    #[serde(default)]
    pub structural_signals: StructuralSignals,
}

impl CandidateIndexRecord {
    pub fn from_candidate_score(
        score: &CandidacyScore,
        opaque_tree: Option<&OpaqueTreeClassification>,
        structural_signals: StructuralSignals,
        event_generation: u64,
    ) -> Result<Option<Self>> {
        let Some(identity) = score.identity else {
            return Ok(None);
        };
        let metadata =
            fs::symlink_metadata(&score.path).map_err(|e| SbhError::io(&score.path, e))?;
        // Never attach a replacement's metadata to the old scanner identity.
        // The next walk may index the replacement with its own evidence.
        if identity_from_metadata(&metadata) != IndexedIdentity::from(identity) {
            return Ok(None);
        }
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
            structural_signals,
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
            && self.structural_signals == other.structural_signals
    }

    /// A `CandidacyScore` fabricated from the persisted total score (every
    /// factor set to it, no vetoes). Never a dispatch verdict: the daemon
    /// re-scores the path with fresh evidence instead.
    #[deprecated(
        note = "persisted scores are hints; re-score the path with fresh evidence (bd-rc-master-ajg1.8.1)"
    )]
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
                regret_calibration: 1.0,
                category_suspended: false,
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

#[derive(Debug, Clone)]
pub struct ScannerCandidateIndex {
    context: ScannerIndexContext,
    event_generation: u64,
    records: BTreeMap<IndexedIdentity, CandidateIndexRecord>,
    /// One current identity per observed path. A rebuilt artifact must retire
    /// its old inode's replay hint rather than leave both in the ranked queue.
    /// Derived from records on load, never independently persisted.
    paths: BTreeMap<PathBuf, IndexedIdentity>,
}

impl ScannerCandidateIndex {
    #[must_use]
    pub fn new(context: ScannerIndexContext) -> Self {
        Self {
            context,
            event_generation: 0,
            records: BTreeMap::new(),
            paths: BTreeMap::new(),
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
        // A fresh observation of this path supersedes every earlier identity
        // at that path, even when the new candidate is vetoed or has no score.
        // Otherwise an obsolete high score can monopolize a bounded replay.
        if let Some(previous) = self.paths.get(&record.path).copied()
            && previous != record.identity
        {
            self.records.remove(&previous);
        }
        if let Some(existing) = self.records.get(&record.identity) {
            if existing.path != record.path {
                // Rename or a newly observed alias of the same identity:
                // reusing its old path later must not retire this new binding.
                self.paths.remove(&existing.path);
            }
            if existing.evidence_matches(&record) {
                record.fail_count = existing.fail_count;
                record.cooldown_until_nanos = existing.cooldown_until_nanos;
                // A failed attempt is retryable, not permission to overwrite
                // a newly observed active-reference or safety veto with Failed.
                if existing.safety_state == CandidateSafetyState::Failed
                    && record.safety_state == CandidateSafetyState::Safe
                {
                    record.safety_state = CandidateSafetyState::Failed;
                }
            }
        }
        self.paths.insert(record.path.clone(), record.identity);
        self.records.insert(record.identity, record);
    }

    #[must_use]
    pub fn candidate_in_cooldown(&self, record: &CandidateIndexRecord, now: SystemTime) -> bool {
        self.records.get(&record.identity).is_some_and(|existing| {
            existing.evidence_matches(record) && self.in_cooldown(record.identity, now)
        })
    }

    /// The `limit` best current-generation candidates (safe or previously
    /// failed, finite positive scores, not cooling down), best score then
    /// largest first. Ties break by path and identity, not discovery order.
    /// Uses O(limit) ranking storage rather than sorting the entire index.
    /// These remain hints: the daemon re-stats and re-scores each result
    /// with fresh vetoes before dispatch (`replay_indexed_record`).
    #[must_use]
    pub fn ranked_records(&self, now: SystemTime, limit: usize) -> Vec<CandidateIndexRecord> {
        replay::ranked_records(
            self.records.values(),
            self.event_generation,
            system_time_nanos(now),
            limit,
        )
    }

    /// Persisted scores turned straight into dispatchable candidates. Kept
    /// for the index's own tests; the daemon never dispatches from it.
    #[deprecated(
        note = "persisted scores are hints; use ranked_records and re-score each record (bd-rc-master-ajg1.8.1)"
    )]
    #[must_use]
    pub fn ranked_candidate_scores(&self, now: SystemTime, limit: usize) -> Vec<CandidacyScore> {
        #[allow(deprecated)]
        self.ranked_records(now, limit)
            .iter()
            .map(CandidateIndexRecord::to_candidate_score)
            .collect()
    }

    pub fn mark_event_overflow(&mut self) {
        if let Some(next) = self.event_generation.checked_add(1) {
            self.event_generation = next;
        } else {
            // Saturation would make a subsequent overflow leave every record
            // apparently fresh. Reset only after revoking all old records.
            self.records.clear();
            self.paths.clear();
            self.event_generation = 0;
        }
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

    /// Publish a complete, synced checkpoint without cloning the record map.
    /// Failure before publication leaves the previous checkpoint intact.
    pub fn save_checkpoint(&self, path: &Path) -> Result<()> {
        checkpoint::save(self, path)
    }

    /// Load a bounded regular-file snapshot; unusable caches yield an empty
    /// index so the scanner can rediscover candidates instead of failing boot.
    #[must_use]
    pub fn load_checkpoint(
        path: &Path,
        expected_context: ScannerIndexContext,
    ) -> (Self, ScannerIndexLoadStatus) {
        checkpoint::load(path, expected_context)
    }
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
            structural_signals: StructuralSignals::default(),
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
                regret_calibration: 1.0,
                category_suspended: false,
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

        #[allow(deprecated)]
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

        #[allow(deprecated)]
        let cooling = index.ranked_candidate_scores(now + Duration::from_secs(5), 8);
        assert!(
            cooling.is_empty(),
            "expected no ranked candidates while the failure cooldown is active, got {cooling:?}"
        );

        #[allow(deprecated)]
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
            StructuralSignals::default(),
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

    fn assert_path_index_consistent(index: &ScannerCandidateIndex) {
        assert_eq!(index.paths.len(), index.records.len());
        for (identity, record) in &index.records {
            assert_eq!(index.paths.get(&record.path), Some(identity));
        }
    }

    #[test]
    fn rebuilding_one_path_does_not_accumulate_replayable_old_inodes() {
        let mut index = ScannerCandidateIndex::new(context("rebuild"));
        for inode in 1..=1000 {
            let mut current = record(identity(inode), identity(99));
            current.path = PathBuf::from("/cache/rebuilt/target");
            current.score = Some(if inode == 1 { 0.99 } else { 0.6 });
            index.upsert(current.clone());
            assert_eq!(index.len(), 1);
            assert_eq!(index.ranked_records(UNIX_EPOCH, 1), vec![current]);
            assert_path_index_consistent(&index);
        }
    }

    #[test]
    fn a_vetoed_replacement_retires_the_old_high_score_without_starving_other_work() {
        for state in [
            CandidateSafetyState::Vetoed,
            CandidateSafetyState::ActiveReference,
        ] {
            let mut index = ScannerCandidateIndex::new(context("veto"));
            let mut old = record(identity(1), identity(99));
            old.score = Some(0.99);
            let useful = record(identity(2), identity(99));
            index.upsert(old.clone());
            index.upsert(useful.clone());
            let mut replacement = old.clone();
            replacement.identity = identity(3);
            replacement.safety_state = state;
            index.upsert(replacement);
            assert!(index.get(old.identity).is_none());
            assert_eq!(index.ranked_records(UNIX_EPOCH, 1), vec![useful]);
            assert_path_index_consistent(&index);
        }
    }

    #[test]
    fn late_failure_for_a_retired_inode_does_not_cool_down_its_replacement() {
        let mut index = ScannerCandidateIndex::new(context("late-failure"));
        let old = record(identity(1), identity(99));
        index.upsert(old.clone());
        index.record_failure(
            old.identity,
            UNIX_EPOCH,
            Duration::from_secs(60),
            Duration::from_secs(60),
        );
        let mut replacement = old.clone();
        replacement.identity = identity(2);
        index.upsert(replacement.clone());
        index.record_failure(
            old.identity,
            UNIX_EPOCH,
            Duration::from_secs(60),
            Duration::from_secs(60),
        );
        assert_eq!(index.ranked_records(UNIX_EPOCH, 1), vec![replacement]);
        assert!(index.get(old.identity).is_none());
        assert_path_index_consistent(&index);
    }

    #[test]
    fn reusing_an_old_path_after_a_rename_preserves_the_renamed_candidate() {
        let mut index = ScannerCandidateIndex::new(context("rename"));
        let original = record(identity(1), identity(99));
        let mut renamed = original.clone();
        renamed.path = PathBuf::from("/cache/new-name");
        index.upsert(original.clone());
        index.upsert(renamed.clone());
        let mut replacement = original;
        replacement.identity = identity(2);
        index.upsert(replacement.clone());
        assert_eq!(index.len(), 2);
        assert_eq!(index.get(renamed.identity), Some(&renamed));
        assert_eq!(index.get(replacement.identity), Some(&replacement));
        assert_path_index_consistent(&index);
    }

    #[test]
    fn rename_over_an_indexed_path_retires_only_the_displaced_identity() {
        let mut index = ScannerCandidateIndex::new(context("replace-rename"));
        let first = record(identity(1), identity(99));
        let second = record(identity(2), identity(99));
        index.upsert(first.clone());
        index.upsert(second.clone());
        let mut renamed = first.clone();
        renamed.path = second.path;
        index.upsert(renamed.clone());
        assert!(index.get(second.identity).is_none());
        assert_eq!(index.get(first.identity), Some(&renamed));
        let mut third = first;
        third.identity = identity(3);
        index.upsert(third);
        assert_eq!(index.len(), 2);
        assert_eq!(index.get(renamed.identity), Some(&renamed));
        assert_path_index_consistent(&index);
    }

    #[test]
    fn replacement_lookup_is_rebuilt_after_checkpoint_restart() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("checkpoint.json");
        let mut index = ScannerCandidateIndex::new(context("restart"));
        let old = record(identity(1), identity(99));
        index.upsert(old.clone());
        index.save_checkpoint(&path).unwrap();
        let (mut restarted, status) = ScannerCandidateIndex::load_checkpoint(&path, index.context);
        assert_eq!(status, ScannerIndexLoadStatus::Loaded);
        assert_path_index_consistent(&restarted);
        let mut current = old.clone();
        current.identity = identity(2);
        restarted.upsert(current.clone());
        assert!(restarted.get(old.identity).is_none());
        assert_eq!(restarted.ranked_records(UNIX_EPOCH, 1), vec![current]);
        assert_path_index_consistent(&restarted);
    }

    #[test]
    fn overflow_clears_path_bindings_before_generation_reuse() {
        let mut index = ScannerCandidateIndex::new(context("overflow"));
        index.event_generation = u64::MAX;
        index.upsert(record(identity(1), identity(99)));
        index.mark_event_overflow();
        assert!(index.paths.is_empty());
        let mut current = record(identity(2), identity(99));
        current.path = record(identity(1), identity(99)).path;
        index.upsert(current.clone());
        assert_eq!(index.ranked_records(UNIX_EPOCH, 1), vec![current]);
        assert_path_index_consistent(&index);
    }

    #[test]
    fn identical_inode_numbers_on_different_devices_remain_independent() {
        let mut index = ScannerCandidateIndex::new(context("devices"));
        let first = record(identity(1), identity(99));
        let mut second = first.clone();
        second.identity.device_id += 1;
        second.path = PathBuf::from("/other-device/target");
        index.upsert(first.clone());
        index.upsert(second.clone());
        assert_eq!(index.len(), 2);
        assert_eq!(index.get(first.identity), Some(&first));
        assert_eq!(index.get(second.identity), Some(&second));
        assert_path_index_consistent(&index);
    }

    #[cfg(unix)]
    #[test]
    fn observed_real_directory_replacement_revokes_the_old_replay_hint() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("target");
        fs::create_dir(&path).unwrap();
        let old_identity = identity_from_metadata(&fs::symlink_metadata(&path).unwrap());
        let old_score = score(path.clone(), old_identity.into());
        let old = CandidateIndexRecord::from_candidate_score(
            &old_score,
            None,
            StructuralSignals::default(),
            0,
        )
        .unwrap()
        .unwrap();
        let mut index = ScannerCandidateIndex::new(context("filesystem"));
        index.upsert(old);
        // Preserve the original inode so this is deterministic even on a
        // filesystem that immediately recycles deleted directory identities.
        let retired = temp.path().join("retired-original");
        fs::rename(&path, &retired).unwrap();
        fs::create_dir(&path).unwrap();
        let new_identity = identity_from_metadata(&fs::symlink_metadata(&path).unwrap());
        assert_ne!(new_identity, old_identity);
        let mut fresh_score = score(path, new_identity.into());
        fresh_score.vetoed = true;
        fresh_score.veto_reason = Some("currently open".into());
        let fresh = CandidateIndexRecord::from_candidate_score(
            &fresh_score,
            None,
            StructuralSignals::default(),
            0,
        )
        .unwrap()
        .unwrap();
        index.upsert(fresh);
        assert!(index.get(old_identity).is_none());
        assert!(index.ranked_records(SystemTime::now(), 10).is_empty());
        assert!(
            retired.is_dir(),
            "retiring an index hint never deletes its artifact"
        );
        assert_path_index_consistent(&index);
    }
}
