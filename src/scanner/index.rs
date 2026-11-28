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
use crate::scanner::planner::{SafetyObservation, hard_veto, rejected_scopes};
use crate::scanner::scoring::{
    CandidacyScore, DecisionAction, DecisionOutcome, EvidenceLedger, ScoreFactors,
};
use crate::scanner::walker::{FsEntryKind, FsIdentity};

mod checkpoint;
mod replay;

/// Older checkpoints could discard an alias's veto or encode a suspended
/// category as safe. Rediscover once before trusting their replay hints.
const CHECKPOINT_VERSION: u32 = 3;

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

impl CandidateSafetyState {
    fn is_veto(self) -> bool {
        matches!(self, Self::Vetoed | Self::ActiveReference)
    }
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
    #[serde(with = "crate::core::path_serde")]
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
    /// under `debug/`, a `CACHEDIR.TAG`, object files). These describe the
    /// indexed observation. Reclaim replay renews evidence on disk.
    #[serde(default)]
    pub structural_signals: StructuralSignals,
}

impl CandidateIndexRecord {
    fn safety_observation(&self) -> SafetyObservation<'_> {
        SafetyObservation {
            path: &self.path,
            identity: Some(self.identity.into()),
            vetoed: self.safety_state.is_veto(),
        }
    }

    /// Missing and positively rebound paths retire old evidence. An
    /// unreadable directory cannot establish that its veto disappeared.
    fn may_still_name_object(&self) -> bool {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) => identity_from_metadata(&metadata) == self.identity,
            Err(error) => !matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ),
        }
    }

    pub fn from_candidate_score(
        score: &CandidacyScore,
        opaque_tree: Option<&OpaqueTreeClassification>,
        structural_signals: StructuralSignals,
        event_generation: u64,
    ) -> Result<Option<Self>> {
        let Some(identity) = score.identity else {
            return Ok(None);
        };
        let Some(mut row) = Self::from_binding(&score.path, identity.into(), event_generation)?
        else {
            return Ok(None);
        };
        row.size_estimate_bytes = score.size_bytes;
        row.prune_decision = IndexedPruneDecision::from_opaque_tree(opaque_tree);
        row.score = Some(score.total_score);
        row.safety_state = safety_state_from_score(score);
        row.structural_signals = structural_signals;
        Ok(Some(row))
    }

    fn from_binding(
        path: &Path,
        identity: IndexedIdentity,
        event_generation: u64,
    ) -> Result<Option<Self>> {
        let metadata = fs::symlink_metadata(path).map_err(|e| SbhError::io(path, e))?;
        // Never attach a replacement's metadata to the old scanner identity.
        // The next walk may index the replacement with its own evidence.
        if identity_from_metadata(&metadata) != identity {
            return Ok(None);
        }
        let (parent_identity, parent_mtime_nanos) = parent_snapshot(path);

        Ok(Some(Self {
            path: path.to_owned(),
            identity,
            parent_identity,
            parent_mtime_nanos,
            candidate_mtime_nanos: system_time_nanos(
                metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            ),
            candidate_ctime_nanos: ctime_for_path(path).map(system_time_nanos),
            size_estimate_bytes: 0,
            prune_decision: IndexedPruneDecision::None,
            score: None,
            safety_state: CandidateSafetyState::Unknown,
            fail_count: 0,
            cooldown_until_nanos: None,
            event_generation,
            structural_signals: StructuralSignals::default(),
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

    /// The same filesystem object in the same observed state: what a failure
    /// backoff belongs to. The priority pre-scan and the walk describe one
    /// directory with different size estimates, prune decisions and
    /// structural evidence; comparing those (`evidence_matches`) reset the
    /// backoff whenever both saw a directory in one pass, so a refused
    /// candidate was dispatched again on the next.
    #[must_use]
    pub fn same_object(&self, other: &Self) -> bool {
        self.path == other.path && self.same_object_state(other)
    }

    fn same_object_state(&self, other: &Self) -> bool {
        self.identity == other.identity
            && self.candidate_mtime_nanos == other.candidate_mtime_nanos
            && self.candidate_ctime_nanos == other.candidate_ctime_nanos
    }

    fn inherit_backoff(&mut self, existing: &Self) {
        if self.same_object_state(existing) {
            self.fail_count = existing.fail_count;
            self.cooldown_until_nanos = existing.cooldown_until_nanos;
            if existing.safety_state == CandidateSafetyState::Failed
                && self.safety_state == CandidateSafetyState::Safe
            {
                self.safety_state = CandidateSafetyState::Failed;
            }
        }
    }

    fn alias_binding_current(&self) -> bool {
        fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            identity_from_metadata(&metadata) == self.identity
                && metadata.modified().ok().map(system_time_nanos)
                    == Some(self.candidate_mtime_nanos)
                && ctime_for_path(&self.path).map(system_time_nanos) == self.candidate_ctime_nanos
        })
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
    if !hard_veto(score) {
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
    /// Other observed spellings contribute evidence, never another ranked
    /// replay slot for the same identity.
    aliases: BTreeMap<PathBuf, CandidateIndexRecord>,
}

impl ScannerCandidateIndex {
    #[must_use]
    pub fn new(context: ScannerIndexContext) -> Self {
        Self {
            context,
            event_generation: 0,
            records: BTreeMap::new(),
            paths: BTreeMap::new(),
            aliases: BTreeMap::new(),
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
        self.aliases.remove(&record.path);
        // A fresh observation of this path supersedes every earlier identity
        // at that path, even when the new candidate is vetoed or has no score.
        // Otherwise an obsolete high score can monopolize a bounded replay.
        if let Some(previous) = self.paths.get(&record.path).copied()
            && previous != record.identity
        {
            self.forget_observation(&record.path, previous);
        }
        if let Some(existing) = self.records.get(&record.identity) {
            if existing.path != record.path {
                // Rename or a newly observed alias of the same identity:
                // reusing its old path later must not retire this new binding.
                self.paths.remove(&existing.path);
                // A rename retires the old spelling. A live alias still
                // connects its descendants and direct veto to this object.
                if existing.may_still_name_object() {
                    self.aliases.insert(existing.path.clone(), existing.clone());
                }
            }
            record.inherit_backoff(existing);
        }
        self.paths.insert(record.path.clone(), record.identity);
        self.records.insert(record.identity, record);
    }

    #[must_use]
    pub fn candidate_in_cooldown(&self, record: &CandidateIndexRecord, now: SystemTime) -> bool {
        self.records.get(&record.identity).is_some_and(|existing| {
            existing.same_object_state(record) && self.in_cooldown(record.identity, now)
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
        self.ranked_matching(now, limit, |_| true)
    }

    /// [`Self::ranked_records`] restricted to records under one of `roots`.
    /// One index serves every pass over the configured roots; a pass replays
    /// only what lies under the roots it was asked to relieve.
    #[must_use]
    pub fn ranked_records_within(
        &self,
        roots: &[PathBuf],
        now: SystemTime,
        limit: usize,
    ) -> Vec<CandidateIndexRecord> {
        self.ranked_matching(now, limit, |path| {
            roots.iter().any(|root| path.starts_with(root))
        })
    }

    pub(crate) fn safety_observations(
        &self,
    ) -> impl Iterator<Item = SafetyObservation<'_>> + Clone {
        self.records
            .values()
            .chain(self.aliases.values())
            .map(CandidateIndexRecord::safety_observation)
    }

    fn ranked_matching(
        &self,
        now: SystemTime,
        limit: usize,
        within_scope: impl Fn(&Path) -> bool,
    ) -> Vec<CandidateIndexRecord> {
        if limit == 0 {
            return Vec::new();
        }
        // Apply the full graph before scope, score, cooldown or heap limits.
        // With no vetoes ranking still needs only the bounded heap.
        let evidence = self.safety_observations();
        let denied = evidence
            .clone()
            .any(|row| row.vetoed)
            .then(|| rejected_scopes(evidence));
        let now_nanos = system_time_nanos(now);
        let admitted = |i: usize, row: &CandidateIndexRecord| {
            denied.as_ref().is_none_or(|flags| !flags[i])
                && within_scope(&row.path)
                && replay::eligible(row, self.event_generation, now_nanos)
        };
        // A scoped pass may see only an alternate spelling. Keep one usable
        // spelling per object and renew alternate bindings before nomination.
        let mut alternate = BTreeMap::new();
        for (i, alias) in self.aliases.values().enumerate() {
            if admitted(i + self.records.len(), alias)
                && !self.in_cooldown(alias.identity, now)
                && alias.alias_binding_current()
            {
                alternate
                    .entry(alias.identity)
                    .and_modify(|best: &mut &CandidateIndexRecord| {
                        if replay::compare(alias, best).is_lt() {
                            *best = alias;
                        }
                    })
                    .or_insert(alias);
            }
        }
        let eligible_scope = self.records.values().enumerate().filter_map(|(i, record)| {
            if admitted(i, record) {
                Some(record)
            } else {
                alternate.get(&record.identity).copied()
            }
        });
        replay::ranked_records(eligible_scope, self.event_generation, now_nanos, limit)
    }

    /// Forget a record whose path is gone or now names another object. A
    /// replacement is indexed with its own evidence when a walk finds it.
    pub fn forget(&mut self, identity: IndexedIdentity) {
        if let Some(record) = self.records.remove(&identity)
            && self.paths.get(&record.path) == Some(&identity)
        {
            self.paths.remove(&record.path);
        }
        self.aliases.retain(|_, alias| alias.identity != identity);
    }

    /// Missing or replaced at this spelling. Other observed bindings still
    /// contribute their own safety evidence.
    pub(crate) fn forget_observation(&mut self, path: &Path, identity: IndexedIdentity) {
        if self.paths.get(path) == Some(&identity) {
            self.paths.remove(path);
            if let Some(previous) = self.records.remove(&identity) {
                let next = self
                    .aliases
                    .values()
                    .find(|alias| alias.identity == identity && alias.may_still_name_object())
                    .map(|alias| alias.path.clone());
                if let Some(mut promoted) = next.and_then(|key| self.aliases.remove(&key)) {
                    promoted.inherit_backoff(&previous);
                    if !promoted.alias_binding_current() {
                        promoted.score = None;
                        if !promoted.safety_state.is_veto() {
                            promoted.safety_state = CandidateSafetyState::Unknown;
                        }
                    }
                    self.paths.insert(promoted.path.clone(), identity);
                    self.records.insert(identity, promoted);
                }
            }
        } else if self
            .aliases
            .get(path)
            .is_some_and(|record| record.identity == identity)
        {
            self.aliases.remove(path);
        }
    }

    /// A fresh replay can discover a veto after the shortlist was built.
    /// Record the direct refusal separately from retry backoff.
    pub(crate) fn mark_observed_veto(&mut self, path: &Path, identity: IndexedIdentity) {
        let row = if self.paths.get(path) == Some(&identity) {
            self.records.get_mut(&identity)
        } else {
            self.aliases
                .get_mut(path)
                .filter(|row| row.identity == identity)
        };
        if let Some(row) = row {
            if !row.safety_state.is_veto() {
                row.safety_state = CandidateSafetyState::Vetoed;
            }
        } else if let Ok(Some(mut row)) =
            CandidateIndexRecord::from_binding(path, identity, self.event_generation)
        {
            // Protected or unrankable observations can be the only evidence
            // keeping a later replay of their enclosing artifact safe.
            row.safety_state = CandidateSafetyState::Vetoed;
            self.upsert(row);
        }
    }

    /// Drop records that can neither be replayed nor hold a candidate back:
    /// written before the current event generation, not cooling down, and
    /// either never failed or no longer present. A walk that sees the path
    /// again re-indexes it. Without this a long-lived index keeps every path
    /// it ever scored, deleted ones included, until the checkpoint limit
    /// refuses to save. Returns the number of records dropped.
    pub fn evict_stale(&mut self, now: SystemTime) -> usize {
        let now_nanos = system_time_nanos(now);
        let generation = self.event_generation;
        let before = self.records.len();
        self.aliases
            .retain(|_, alias| alias.may_still_name_object());
        let alias_ids: std::collections::BTreeSet<_> =
            self.aliases.values().map(|alias| alias.identity).collect();
        for id in &alias_ids {
            if let Some(missing) = self
                .records
                .get(id)
                .filter(|row| !row.may_still_name_object())
            {
                let old_path = missing.path.clone();
                self.forget_observation(&old_path, *id);
            }
        }
        self.records.retain(|_, record| {
            // When a scoped change revoked an old veto, disappearance or
            // replacement is positive evidence that the old binding is gone.
            if record.score.is_none() && record.safety_state.is_veto() {
                return record.may_still_name_object();
            }
            record.event_generation == generation
                || ((record.safety_state.is_veto() || alias_ids.contains(&record.identity))
                    && record.may_still_name_object())
                || record
                    .cooldown_until_nanos
                    .is_some_and(|until| now_nanos < until)
                // Kept so a path that keeps failing keeps its growing backoff.
                || (record.fail_count > 0 && fs::symlink_metadata(&record.path).is_ok())
        });
        let records = &self.records;
        self.paths
            .retain(|_, identity| records.contains_key(identity));
        before - self.records.len()
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
            self.aliases.clear();
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
        // Executor feedback may arrive after a newer walk observed a veto or
        // event invalidation revoked this hint. Failure is retry state, never
        // permission to replace that stronger safety evidence.
        if record.safety_state == CandidateSafetyState::Safe {
            record.safety_state = CandidateSafetyState::Failed;
        }

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
    #[cfg(unix)]
    fn replay_keeps_vetoes_across_live_aliases_restarts_and_scoped_events() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("original");
        let mirror = tmp.path().join("mirror");
        let target = real.join("target");
        let hold = target.join("hold");
        let clear = target.join("clear");
        fs::create_dir_all(&hold).unwrap();
        fs::create_dir(&clear).unwrap();
        std::os::unix::fs::symlink(&real, &mirror).unwrap();
        let fixture = |path: &Path, score_value, safety_state| {
            let id = identity_from_metadata(&fs::symlink_metadata(path).unwrap());
            let mut row = record(id, identity(99));
            row.path = path.to_path_buf();
            row.score = score_value;
            row.safety_state = safety_state;
            row
        };
        let mut index = ScannerCandidateIndex::new(context("alias"));
        let alias_target = mirror.join("target");
        let roots = [alias_target.clone()];
        let old_parent = fixture(&target, Some(0.2), CandidateSafetyState::Safe);
        let parent = fixture(&alias_target, Some(1.0), CandidateSafetyState::Safe);
        let child = fixture(&hold, None, CandidateSafetyState::ActiveReference);
        let sibling = fixture(
            &alias_target.join("clear"),
            Some(0.4),
            CandidateSafetyState::Safe,
        );
        for row in [&old_parent, &parent, &child, &sibling] {
            index.upsert(row.clone());
        }
        let checkpoint = tmp.path().join("index.json");
        index.save_checkpoint(&checkpoint).unwrap();
        let (mut index, status) =
            ScannerCandidateIndex::load_checkpoint(&checkpoint, index.context().clone());
        assert_eq!(status, ScannerIndexLoadStatus::Loaded);
        assert_eq!(
            index.ranked_records_within(&roots, UNIX_EPOCH, 1),
            vec![sibling.clone()]
        );
        index.invalidate_paths([hold.as_path()]);
        assert_eq!(index.get(parent.identity).unwrap().score, None);
        index.mark_event_overflow();
        index.evict_stale(UNIX_EPOCH);
        index.upsert(parent.clone());
        index.upsert(sibling.clone());
        assert_eq!(
            index.ranked_records_within(&roots, UNIX_EPOCH, 1)[0].path,
            sibling.path
        );

        // A reliable rescore at the original veto path releases the parent.
        let mut resumed = child.clone();
        resumed.safety_state = CandidateSafetyState::Safe;
        resumed.score = Some(0.1);
        index.upsert(resumed);
        assert_eq!(
            index.ranked_records_within(&roots, UNIX_EPOCH, 1)[0].path,
            parent.path
        );

        // The same inode can have different path-specific vetoes. Seeing it
        // safely through another spelling must not undo a refusal at hold.
        index.mark_observed_veto(&child.path, child.identity);
        let alias_child = fixture(
            &alias_target.join("hold"),
            Some(0.95),
            CandidateSafetyState::Safe,
        );
        index.upsert(alias_child.clone());
        assert_eq!(
            index.ranked_records_within(&roots, UNIX_EPOCH, 1)[0].path,
            sibling.path
        );
        index.forget_observation(&alias_child.path, alias_child.identity);
        assert_eq!(
            index.ranked_records_within(&roots, UNIX_EPOCH, 1)[0].path,
            sibling.path
        );
        index.forget_observation(&child.path, child.identity);
        assert_eq!(
            index.ranked_records_within(&roots, UNIX_EPOCH, 1)[0].path,
            parent.path
        );
    }

    #[test]
    #[cfg(unix)]
    fn scoped_replay_renews_alternate_names_deduplicates_and_keeps_backoff() {
        let tmp = tempfile::tempdir().unwrap();
        let original = tmp.path().join("A");
        let link = tmp.path().join("B");
        let a = original.join("target");
        let b = link.join("target");
        fs::create_dir_all(&a).unwrap();
        std::os::unix::fs::symlink(&original, &link).unwrap();
        let id = identity_from_metadata(&fs::symlink_metadata(&a).unwrap());
        let observed = |path: &Path, rank| {
            let mut row = CandidateIndexRecord::from_binding(path, id, 0)
                .unwrap()
                .unwrap();
            row.score = Some(rank);
            row.size_estimate_bytes = 100;
            row.safety_state = CandidateSafetyState::Safe;
            row
        };
        let mut index = ScannerCandidateIndex::new(context("scoped-alias"));
        index.upsert(observed(&a, 0.8));
        index.upsert(observed(&b, 0.9));
        let scopes = [original.clone()];
        assert_eq!(
            index.ranked_records_within(&scopes, UNIX_EPOCH, 1)[0].path,
            a
        );
        assert_eq!(index.ranked_records(UNIX_EPOCH, 10).len(), 1);
        index.record_failure(
            id,
            UNIX_EPOCH,
            Duration::from_secs(10),
            Duration::from_secs(30),
        );
        assert!(
            index
                .ranked_records_within(&scopes, UNIX_EPOCH, 1)
                .is_empty()
        );
        // The alternate was positively identified and rescored. Switching
        // primary cannot shorten the retry backoff for the same object.
        index.upsert(observed(&a, 0.8));
        assert!(index.ranked_records(UNIX_EPOCH, 10).is_empty());
        index.forget_observation(&a, id);
        assert!(index.ranked_records(UNIX_EPOCH, 10).is_empty());
        assert_eq!(
            index.ranked_records(UNIX_EPOCH + Duration::from_secs(10), 10)[0].path,
            b
        );
        assert!(
            index
                .ranked_records_within(&scopes, UNIX_EPOCH + Duration::from_secs(10), 1)
                .is_empty()
        );

        index.upsert(observed(&a, 0.8));
        fs::create_dir(b.join("new-child")).unwrap();
        assert!(
            index
                .ranked_records_within(&[link], UNIX_EPOCH + Duration::from_secs(10), 1)
                .is_empty(),
            "stale alternate metadata requires a fresh walk"
        );
    }

    #[test]
    fn category_suspension_and_reason_only_veto_survive_indexing() {
        let mut held = score("/held".into(), identity(1).into());
        held.decision.category_suspended = true;
        assert_eq!(safety_state_from_score(&held), CandidateSafetyState::Vetoed);
        held.decision.category_suspended = false;
        held.veto_reason = Some("active reference".into());
        assert_eq!(
            safety_state_from_score(&held),
            CandidateSafetyState::ActiveReference
        );
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
    fn replay_is_scoped_to_the_pass_roots() {
        let mut index = ScannerCandidateIndex::new(context("same"));
        let mut inside = record(identity(1), identity(99));
        inside.path = PathBuf::from("/data/tmp/build-1/target");
        let mut outside = record(identity(2), identity(99));
        outside.path = PathBuf::from("/home/u/.cache/uv");
        let mut sibling = record(identity(3), identity(99));
        sibling.path = PathBuf::from("/data/tmpx/target");
        index.upsert(inside);
        index.upsert(outside);
        index.upsert(sibling);
        let now = UNIX_EPOCH + Duration::from_secs(1_000);

        let ranked = index.ranked_records_within(&[PathBuf::from("/data/tmp")], now, 8);

        assert_eq!(
            ranked.iter().map(|r| r.identity).collect::<Vec<_>>(),
            vec![identity(1)]
        );
        assert_eq!(index.ranked_records(now, 8).len(), 3);
    }

    #[test]
    fn forget_removes_only_the_named_identity() {
        let mut index = ScannerCandidateIndex::new(context("same"));
        let old = record(identity(1), identity(99));
        let path = old.path.clone();
        index.upsert(old);
        let mut replacement = record(identity(2), identity(99));
        replacement.path = path.clone();
        index.upsert(replacement);

        // The superseded identity is already gone; forgetting it again must
        // not unbind the path from its replacement.
        index.forget(identity(1));
        assert_eq!(index.paths.get(&path), Some(&identity(2)));

        index.forget(identity(2));
        assert!(index.is_empty());
        assert!(index.paths.is_empty());
    }

    #[test]
    fn eviction_keeps_current_cooling_and_failing_records() {
        let tmp = tempfile::tempdir().unwrap();
        let mut index = ScannerCandidateIndex::new(context("same"));
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let base = Duration::from_secs(10);
        let max = Duration::from_mins(1);
        let at = |n: u64, path: PathBuf| {
            let mut r = record(identity(n), identity(99));
            r.path = path;
            r
        };
        // Written in generation 0, then the generation advances.
        index.upsert(at(1, tmp.path().join("stale")));
        index.upsert(at(2, tmp.path().join("cooling")));
        index.record_failure(identity(2), now, base, max);
        let failing = tmp.path().join("failing");
        std::fs::create_dir(&failing).unwrap();
        index.upsert(at(3, failing));
        index.record_failure(identity(3), now, base, max);
        index.upsert(at(4, tmp.path().join("failed-and-gone")));
        index.record_failure(identity(4), now, base, max);
        index.mark_event_overflow();
        index.upsert(at(5, tmp.path().join("current")));

        let later = now + Duration::from_secs(5);
        assert_eq!(index.evict_stale(later), 1, "only the idle stale record");
        assert!(index.get(identity(1)).is_none());
        assert!(index.get(identity(2)).is_some());

        // After the cooldowns: a failing path that still exists keeps its
        // backoff history; one that is gone is dropped.
        let after = now + Duration::from_secs(30);
        assert_eq!(index.evict_stale(after), 2);
        assert!(index.get(identity(3)).is_some());
        assert!(index.get(identity(5)).is_some());
        assert_eq!(index.paths.len(), index.len());
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
            tree_last_modified: None,
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
