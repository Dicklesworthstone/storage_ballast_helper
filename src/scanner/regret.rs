//! Regret labels and regret-calibrated delete thresholds (Q4).
//!
//! A deletion was a mistake when the same directory entry (parent device
//! and inode, name) is recreated within `window` of the deletion while a
//! process with its working directory or an open file under the parent is
//! alive: something was still using it. That is a `regret` outcome; a
//! window that passes with verified absence is `clean`; a recreation with no
//! live user, a late sighting, or an unresolved filesystem observation is
//! `unknown` (not evidence either way).
//!
//! Outcomes calibrate the fast lane per category. Each category keeps a
//! Beta posterior on its regret rate under an empirical-Bayes prior pooled
//! across categories, and reports a Clopper-Pearson upper bound
//! (`delta` 0.05) on that rate. The bound's excess over the tolerated rate
//! (`alpha` 0.02 for Definite-dominated categories, 0.005 otherwise) lowers
//! the category's `calibration` factor, which the decision layer already
//! turns into a higher required posterior for Delete. Zero regrets never
//! tighten anything. A per-category e-process (H0: regret rate <= alpha)
//! suspends only that category's deletions for `suspend` when it alarms.

#![allow(clippy::cast_precision_loss)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[cfg(feature = "sqlite")]
use crate::scanner::patterns::ArtifactCategory;
use crate::scanner::scoring::ArtifactCertainty;
#[cfg(feature = "sqlite")]
use crate::scanner::scoring::{CACHE_REDELETION_MEMORY, is_warm_cache};

/// Tunables (`[scoring]` regret keys).
#[derive(Debug, Clone, PartialEq)]
pub struct RegretConfig {
    /// How long after a deletion a recreation counts as regret.
    pub window: Duration,
    /// Tolerated regret rate for a category whose decisions are mostly
    /// Definite.
    pub alpha_definite: f64,
    /// Tolerated regret rate otherwise.
    pub alpha_likely: f64,
    /// Confidence level complement of the Clopper-Pearson bound.
    pub delta: f64,
    /// Strength (pseudo-observations) of the pooled prior.
    pub prior_strength: f64,
    /// E-process alarm threshold (H0: regret rate <= alpha).
    pub e_threshold: f64,
    /// How long an alarm suspends the category's deletions.
    pub suspend: Duration,
}

impl Default for RegretConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_mins(30),
            alpha_definite: 0.02,
            alpha_likely: 0.005,
            delta: 0.05,
            prior_strength: 10.0,
            e_threshold: 20.0,
            suspend: Duration::from_hours(1),
        }
    }
}

/// What became of a deletion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// Recreated inside the window while a process used the parent.
    Regret,
    /// The window passed without a recreation.
    Clean,
    /// The observation cannot establish either regret or a clean deletion.
    Unknown,
}

impl Outcome {
    /// The stored outcome for a name (`None` for anything else).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "regret" => Some(Self::Regret),
            "clean" => Some(Self::Clean),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }

    /// The stored name of the outcome.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Regret => "regret",
            Self::Clean => "clean",
            Self::Unknown => "unknown",
        }
    }
}

/// The inclusive window of resolved outcomes used for category calibration.
pub const REGRET_EVIDENCE_WINDOW: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// One category observation with its original wall-clock time. Ingestion time
/// must not extend the useful life of evidence read from the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegretObservation {
    /// Artifact category key at decision time.
    pub category: String,
    /// Structural certainty at decision time.
    pub certainty: ArtifactCertainty,
    /// Resolved outcome; unknown observations do not change calibration.
    pub outcome: Outcome,
    /// When the outcome was observed, rather than when it was imported.
    pub observed_at: SystemTime,
}

impl RegretObservation {
    #[cfg(feature = "sqlite")]
    fn from_stored(stored: &crate::logger::sqlite::StoredOutcome) -> Option<Self> {
        Some(Self {
            category: stored.category.clone(),
            certainty: certainty_from_name(&stored.certainty),
            outcome: Outcome::from_name(&stored.outcome)?,
            observed_at: chrono::DateTime::parse_from_rfc3339(&stored.observed_at)
                .ok()
                .map(SystemTime::from)?,
        })
    }

    fn expired(&self, now: SystemTime) -> bool {
        now.duration_since(self.observed_at)
            .is_ok_and(|age| age > REGRET_EVIDENCE_WINDOW)
    }
}

/// Persisted scoring evidence shared by daemon startup and manual cleanup.
/// Loading history never creates a ledger or replays a runtime suspension.
#[cfg(feature = "sqlite")]
#[derive(Debug, Default)]
pub struct ScoringHistory {
    /// Valid outcomes from the last 30 days, ready for
    /// [`RegretCalibrator::replay`].
    pub outcomes: Vec<RegretObservation>,
    /// Actual warm-cache deletions within [`CACHE_REDELETION_MEMORY`], with
    /// receipts and their later outcome labels counted only once.
    pub cache_deletions: Vec<(PathBuf, ArtifactCategory, SystemTime)>,
}

#[cfg(feature = "sqlite")]
impl ScoringHistory {
    /// Read the existing ledger without creating or migrating it. Missing
    /// or unreadable history leaves the normal scoring defaults in force.
    /// Queries use the bounded outcome and cache-history time windows.
    #[must_use]
    pub fn load(sqlite_db: &Path) -> Self {
        Self::load_at(sqlite_db, SystemTime::now())
    }

    fn load_at(sqlite_db: &Path, now: SystemTime) -> Self {
        let Ok(db) = crate::logger::sqlite::SqliteLogger::open_read_only(sqlite_db) else {
            return Self::default();
        };
        let since = |window| {
            chrono::DateTime::<chrono::Utc>::from(now.checked_sub(window).unwrap_or(UNIX_EPOCH))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        };
        let outcomes = db
            .outcomes_since(&since(REGRET_EVIDENCE_WINDOW))
            .unwrap_or_else(|error| {
                eprintln!("[SBH-REGRET] could not replay stored outcomes: {error}");
                Vec::new()
            });
        let receipts = db
            .successful_deletions_since(&since(CACHE_REDELETION_MEMORY))
            .unwrap_or_else(|error| {
                eprintln!("[SBH-REGRET] could not replay successful deletion receipts: {error}");
                Vec::new()
            });
        Self {
            cache_deletions: replay_cache_deletions(receipts, &outcomes, now),
            outcomes: outcomes
                .iter()
                .filter_map(RegretObservation::from_stored)
                .collect(),
        }
    }
}

/// Read-only import bookkeeping for persisted scoring evidence.
///
/// Each fingerprint retains the greatest multiplicity seen in one source
/// generation. Re-reading a copied ledger does not duplicate its effects, but
/// separate identical rows in that ledger still represent separate events.
/// The daemon filters its own run's writes before admission.
#[cfg(feature = "sqlite")]
#[derive(Debug, Default)]
pub struct HistoryAdmission {
    generation: u64,
    receipts: BTreeMap<SystemTime, HashMap<ReceiptFingerprint, SourceMultiplicity>>,
    outcomes: BTreeMap<SystemTime, HashMap<OutcomeFingerprint, SourceMultiplicity>>,
    cache_groups: HashMap<(String, String), CacheHistoryGroup>,
    cache_expiry: BTreeMap<SystemTime, HashSet<(String, String)>>,
}

#[cfg(feature = "sqlite")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReceiptFingerprint {
    decision_id: String,
    path: String,
    // Category is hydrated from decision_log for legacy receipts. Its
    // availability can change when that table is pruned or copied, without
    // changing the successful mutation this fingerprint identifies.
    recorded_at: SystemTime,
    completed_at: Option<SystemTime>,
}

#[cfg(feature = "sqlite")]
impl From<&crate::logger::sqlite::StoredDeletion> for ReceiptFingerprint {
    fn from(receipt: &crate::logger::sqlite::StoredDeletion) -> Self {
        Self {
            decision_id: receipt.decision_id.clone(),
            path: receipt.path.clone(),
            recorded_at: receipt.recorded_at,
            completed_at: receipt.completed_at,
        }
    }
}

#[cfg(feature = "sqlite")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct OutcomeFingerprint {
    decision_id: String,
    path: String,
    category: String,
    certainty: String,
    outcome: String,
    observed_at: SystemTime,
    after_secs: u64,
    detail: String,
}

#[cfg(feature = "sqlite")]
#[derive(Debug, Default)]
struct SourceMultiplicity {
    generation: u64,
    seen: u64,
    admitted: u64,
}

#[cfg(feature = "sqlite")]
impl SourceMultiplicity {
    fn admit(&mut self, generation: u64) -> bool {
        if self.generation != generation {
            self.generation = generation;
            self.seen = 0;
        }
        self.seen = self.seen.saturating_add(1);
        if self.seen <= self.admitted {
            return false;
        }
        self.admitted = self.seen;
        true
    }
}

#[cfg(feature = "sqlite")]
#[derive(Debug, Default)]
struct CacheHistoryGroup {
    receipts: Vec<crate::logger::sqlite::StoredDeletion>,
    outcomes: Vec<(SystemTime, crate::logger::sqlite::StoredOutcome)>,
    deletions: Vec<(PathBuf, ArtifactCategory, SystemTime)>,
}

#[cfg(feature = "sqlite")]
impl CacheHistoryGroup {
    fn rebuild(&mut self, now: SystemTime) {
        // Reconcile only this decision/path group. Reconsidering its matches
        // also handles a better-matching receipt or earlier label arriving
        // later, without making effects depend on database page boundaries.
        self.deletions = replay_cache_deletions(
            self.receipts.clone(),
            self.outcomes.iter().map(|(_, outcome)| outcome),
            now,
        );
    }

    fn expire(&mut self, now: SystemTime) {
        self.receipts.retain(|receipt| {
            retained_at(
                receipt.completed_at.unwrap_or(receipt.recorded_at),
                now,
                CACHE_REDELETION_MEMORY + RECEIPT_MATCH_ROUNDING,
            )
        });
        self.outcomes
            .retain(|(deleted_at, _)| retained_at(*deleted_at, now, CACHE_REDELETION_MEMORY));
        self.rebuild(now);
    }
}

#[cfg(feature = "sqlite")]
impl HistoryAdmission {
    /// Begin reading a different database generation from its start. Existing
    /// evidence and admitted multiplicities survive; per-source counts reset
    /// lazily when each fingerprint is encountered.
    pub fn begin_generation(&mut self) {
        if let Some(generation) = self.generation.checked_add(1) {
            self.generation = generation;
        } else {
            // Preserve multiplicities even after a counter wrap. This visits
            // retained keys once per u64::MAX source generations, never per
            // polling pass.
            for counts in self
                .receipts
                .values_mut()
                .flat_map(HashMap::values_mut)
                .chain(self.outcomes.values_mut().flat_map(HashMap::values_mut))
            {
                counts.generation = 0;
                counts.seen = 0;
            }
            self.generation = 1;
        }
    }

    /// Admit one irreversible-success receipt. A new source occurrence
    /// returns true; a copied occurrence or expired receipt returns false.
    /// Cache effects stay inside this admission state so a later label never
    /// contributes a second deletion.
    pub fn admit_receipt(
        &mut self,
        receipt: crate::logger::sqlite::StoredDeletion,
        now: SystemTime,
    ) -> bool {
        self.expire(now);
        let deleted_at = receipt.completed_at.unwrap_or(receipt.recorded_at);
        if !retained_at(
            deleted_at,
            now,
            CACHE_REDELETION_MEMORY + RECEIPT_MATCH_ROUNDING,
        ) {
            return false;
        }
        let (admitted, occurrence) = {
            let counts = self
                .receipts
                .entry(deleted_at)
                .or_default()
                .entry(ReceiptFingerprint::from(&receipt))
                .or_default();
            (counts.admit(self.generation), counts.seen)
        };
        if !admitted {
            self.enrich_receipt(&receipt, occurrence, now);
            return false;
        }
        let key = (receipt.decision_id.clone(), receipt.path.clone());
        // Keep the receipt for the matcher rounding allowance after its own
        // effect expires. An outcome with a rounded later deletion time must
        // not resurrect an already expired, successfully paired removal.
        let expires_from = deleted_at
            .checked_add(RECEIPT_MATCH_ROUNDING)
            .unwrap_or(deleted_at);
        self.cache_expiry
            .entry(expires_from)
            .or_default()
            .insert(key.clone());
        let group = self.cache_groups.entry(key).or_default();
        group.receipts.push(receipt);
        group.rebuild(now);
        true
    }

    fn enrich_receipt(
        &mut self,
        receipt: &crate::logger::sqlite::StoredDeletion,
        occurrence: u64,
        now: SystemTime,
    ) {
        if receipt.category.is_none() {
            return;
        }
        let key = (receipt.decision_id.clone(), receipt.path.clone());
        let Some(group) = self.cache_groups.get_mut(&key) else {
            return;
        };
        let mut matched = 0;
        let mut changed = false;
        for existing in &mut group.receipts {
            if existing.recorded_at == receipt.recorded_at
                && existing.completed_at == receipt.completed_at
            {
                matched += 1;
                if matched == occurrence {
                    if existing.category.is_none() {
                        existing.category.clone_from(&receipt.category);
                        changed = true;
                    }
                    break;
                }
            }
        }
        if changed {
            group.rebuild(now);
        }
    }

    /// Admit one outcome and return its calibration observation exactly once
    /// per source occurrence. Unknown labels still restore cache history, but
    /// the calibrator treats them as no evidence. A caller chooses live alarm
    /// handling or historical replay according to the source's checkpoint.
    pub fn admit_outcome(
        &mut self,
        outcome: crate::logger::sqlite::StoredOutcome,
        now: SystemTime,
    ) -> Option<RegretObservation> {
        self.expire(now);
        let observation = RegretObservation::from_stored(&outcome)?;
        if observation.expired(now) {
            return None;
        }
        let fingerprint = OutcomeFingerprint {
            decision_id: outcome.decision_id.clone(),
            path: outcome.path.clone(),
            category: outcome.category.clone(),
            certainty: outcome.certainty.clone(),
            outcome: outcome.outcome.clone(),
            observed_at: observation.observed_at,
            after_secs: outcome.after_secs,
            detail: outcome.detail.clone(),
        };
        if !self
            .outcomes
            .entry(observation.observed_at)
            .or_default()
            .entry(fingerprint)
            .or_default()
            .admit(self.generation)
        {
            return None;
        }
        if let Some(deleted_at) = observation
            .observed_at
            .checked_sub(Duration::from_secs(outcome.after_secs))
            && retained_at(deleted_at, now, CACHE_REDELETION_MEMORY)
        {
            let key = (outcome.decision_id.clone(), outcome.path.clone());
            self.cache_expiry
                .entry(deleted_at)
                .or_default()
                .insert(key.clone());
            let group = self.cache_groups.entry(key).or_default();
            group.outcomes.push((deleted_at, outcome));
            group.rebuild(now);
        }
        Some(observation)
    }

    /// Forget only evidence whose original timestamp has left its window.
    /// Ordered timestamp buckets make an idle refresh independent of the
    /// number of retained fingerprints.
    pub fn expire(&mut self, now: SystemTime) {
        expire_buckets(
            &mut self.receipts,
            now,
            CACHE_REDELETION_MEMORY + RECEIPT_MATCH_ROUNDING,
        );
        expire_buckets(&mut self.outcomes, now, REGRET_EVIDENCE_WINDOW);
        let Some(cutoff) = now.checked_sub(CACHE_REDELETION_MEMORY) else {
            return;
        };
        while self
            .cache_expiry
            .first_key_value()
            .is_some_and(|(at, _)| *at < cutoff)
        {
            let (_, keys) = self
                .cache_expiry
                .pop_first()
                .expect("expired bucket exists");
            for key in keys {
                let empty = self.cache_groups.get_mut(&key).is_some_and(|group| {
                    group.expire(now);
                    group.receipts.is_empty() && group.outcomes.is_empty()
                });
                if empty {
                    self.cache_groups.remove(&key);
                }
            }
        }
    }

    /// Current imported warm-cache deletion counts. The daemon combines
    /// these with its own directly observed removals, whose ledger copies
    /// were excluded by run provenance before admission.
    pub fn cache_redeletions(&mut self, now: SystemTime) -> HashMap<PathBuf, u32> {
        self.expire(now);
        crate::scanner::scoring::cache_redeletion_counts(
            self.cache_groups.values().flat_map(|group| {
                group
                    .deletions
                    .iter()
                    .map(|(path, category, deleted_at)| (path, *category, *deleted_at))
            }),
            now,
        )
    }
}

#[cfg(feature = "sqlite")]
fn retained_at(observed_at: SystemTime, now: SystemTime, window: Duration) -> bool {
    !now.duration_since(observed_at)
        .is_ok_and(|age| age > window)
}

#[cfg(feature = "sqlite")]
fn expire_buckets<T>(buckets: &mut BTreeMap<SystemTime, T>, now: SystemTime, window: Duration) {
    let Some(cutoff) = now.checked_sub(window) else {
        return;
    };
    while buckets
        .first_key_value()
        .is_some_and(|(at, _)| *at < cutoff)
    {
        buckets.pop_first();
    }
}

/// A persisted success restores warm-cache backoff even if the daemon stopped
/// before its regret window ended. Outcomes remain a fallback for old or
/// missing receipts, never a second count of the same successful deletion.
#[cfg(feature = "sqlite")]
fn replay_cache_deletions<'a>(
    receipts: Vec<crate::logger::sqlite::StoredDeletion>,
    outcomes: impl IntoIterator<Item = &'a crate::logger::sqlite::StoredOutcome>,
    now: SystemTime,
) -> Vec<(PathBuf, ArtifactCategory, SystemTime)> {
    let recent = |deleted_at| {
        !now.duration_since(deleted_at)
            .is_ok_and(|age| age > CACHE_REDELETION_MEMORY)
    };
    // Match before expiring receipt effects. A rounded outcome timestamp
    // must not turn a paired, just-expired receipt into a new fallback count.
    let mut receipts = receipts;
    let mut by_version: HashMap<(String, String), Vec<usize>> = HashMap::new();
    for (index, receipt) in receipts.iter().enumerate() {
        by_version
            .entry((receipt.decision_id.clone(), receipt.path.clone()))
            .or_default()
            .push(index);
    }
    let mut matched = vec![false; receipts.len()];
    let mut history = Vec::new();
    let mut labelled: Vec<_> = outcomes
        .into_iter()
        .filter_map(|stored| {
            Outcome::from_name(&stored.outcome)?;
            let observed_at = chrono::DateTime::parse_from_rfc3339(&stored.observed_at)
                .ok()
                .map(SystemTime::from)?;
            let deleted_at = observed_at.checked_sub(Duration::from_secs(stored.after_secs))?;
            recent(deleted_at).then_some((stored, deleted_at, observed_at))
        })
        .collect();
    labelled.sort_by_key(|(_, deleted_at, _)| *deleted_at);
    for (stored, deleted_at, observed_at) in labelled {
        let key = (stored.decision_id.clone(), stored.path.clone());
        let matched_receipt = by_version.get(&key).and_then(|indices| {
            indices
                .iter()
                .copied()
                .filter(|&index| {
                    !matched[index]
                        && deletion_receipt_matches(&receipts[index], deleted_at, observed_at)
                })
                .min_by_key(|&index| {
                    let completed = receipts[index]
                        .completed_at
                        .unwrap_or(receipts[index].recorded_at);
                    completed
                        .duration_since(deleted_at)
                        .unwrap_or_else(|error| error.duration())
                })
        });
        if let Some(index) = matched_receipt {
            matched[index] = true;
            // A legacy receipt may outlive its decision record. Its matching
            // outcome still supplies the original structural classification.
            if receipts[index].category.is_none() {
                receipts[index].category = Some(stored.category.clone());
            }
        } else {
            let path = PathBuf::from(&stored.path);
            let category = stored.category.parse().unwrap_or(ArtifactCategory::Unknown);
            if is_warm_cache(&path, category) {
                history.push((path, category, deleted_at));
            }
        }
    }
    history.extend(receipts.into_iter().filter_map(|receipt| {
        if !recent(receipt.completed_at.unwrap_or(receipt.recorded_at)) {
            return None;
        }
        let path = PathBuf::from(receipt.path);
        let category = receipt
            .category
            .and_then(|category| category.parse().ok())
            .unwrap_or(ArtifactCategory::Unknown);
        is_warm_cache(&path, category).then_some((
            path,
            category,
            receipt.completed_at.unwrap_or(receipt.recorded_at),
        ))
    }));
    history
}

#[cfg(feature = "sqlite")]
const RECEIPT_MATCH_ROUNDING: Duration = Duration::from_secs(2);

#[cfg(feature = "sqlite")]
fn deletion_receipt_matches(
    receipt: &crate::logger::sqlite::StoredDeletion,
    deleted_at: SystemTime,
    observed_at: SystemTime,
) -> bool {
    // Outcome timestamps and elapsed times are stored as whole seconds.
    // Match that rounding without conflating a later reuse of the same inode
    // and stable decision id with an earlier, separately observed deletion.
    let rounding = RECEIPT_MATCH_ROUNDING;
    receipt.completed_at.map_or_else(
        || {
            // Legacy timestamps were sampled by the logger. They can lag the
            // unlink, but cannot stand for an unrelated later deletion beyond
            // the matching outcome's observation window.
            receipt.recorded_at >= deleted_at.checked_sub(rounding).unwrap_or(deleted_at)
                && receipt.recorded_at <= observed_at.checked_add(rounding).unwrap_or(observed_at)
        },
        |completed_at| {
            completed_at
                .duration_since(deleted_at)
                .unwrap_or_else(|error| error.duration())
                <= rounding
        },
    )
}

/// The identity of a directory entry: its parent's device and inode plus
/// its name. Survives a delete-and-recreate of the entry itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntryIdentity {
    /// Device of the parent directory.
    pub parent_device: u64,
    /// Inode of the parent directory.
    pub parent_inode: u64,
    /// The entry's file name within that parent.
    pub name: String,
}

impl EntryIdentity {
    /// The identity of `path` from its parent's metadata; `None` when the
    /// parent cannot be stat'ed or the path has no name.
    #[must_use]
    pub fn of(path: &Path) -> Option<Self> {
        let parent = path.parent()?;
        let name = path.file_name()?.to_string_lossy().into_owned();
        let meta = std::fs::metadata(parent).ok()?;
        if !meta.is_dir() {
            return None;
        }
        Some(Self::from_parent_meta(&meta, name))
    }

    #[cfg(unix)]
    fn from_parent_meta(meta: &std::fs::Metadata, name: String) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            parent_device: meta.dev(),
            parent_inode: meta.ino(),
            name,
        }
    }

    #[cfg(not(unix))]
    fn from_parent_meta(_meta: &std::fs::Metadata, name: String) -> Self {
        Self {
            parent_device: 0,
            parent_inode: 0,
            name,
        }
    }
}

/// A deletion under watch.
#[derive(Debug, Clone)]
pub struct Watch {
    /// The decision that removed the entry.
    pub decision_id: String,
    /// Where the entry was.
    pub path: PathBuf,
    /// The entry's identity, captured before the removal.
    pub identity: EntryIdentity,
    /// Artifact category key (`{:?}` of the classification category).
    pub category: String,
    /// Structural certainty at decision time.
    pub certainty: ArtifactCertainty,
    /// When the entry was removed.
    pub deleted_at: Instant,
}

impl Watch {
    /// Observe the original directory entry, asking about live users only
    /// after a successful lookup. A missing entry is evidence only when its
    /// original parent can still be verified.
    #[must_use]
    pub fn observe(&self, parent_in_use: impl FnOnce(&Path) -> bool) -> Sighting {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            let (Some(parent), Some(name)) = (self.path.parent(), self.path.file_name()) else {
                return Sighting::Indeterminate;
            };
            // Anchor the lookup to the opened parent. A pathname swap cannot
            // redirect the entry lookup into a replacement directory.
            let Ok(directory) = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
                .open(parent)
            else {
                return Sighting::Indeterminate;
            };
            let Ok(meta) = directory.metadata() else {
                return Sighting::Indeterminate;
            };
            if EntryIdentity::from_parent_meta(&meta, name.to_string_lossy().into_owned())
                != self.identity
            {
                return Sighting::Indeterminate;
            }
            let lookup =
                rustix::fs::statat(&directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                    .map(|_| ())
                    .map_err(std::io::Error::from);
            let sighting = Sighting::from_entry_lookup(lookup, || parent_in_use(parent));
            // The original directory must still occupy the watched path,
            // including after any slower process-table observation.
            if EntryIdentity::of(&self.path).as_ref() != Some(&self.identity) {
                return Sighting::Indeterminate;
            }
            sighting
        }
        #[cfg(not(unix))]
        {
            // EntryIdentity has no stable device/inode implementation here.
            // Do not manufacture evidence from a pathname-only observation.
            let _ = parent_in_use;
            Sighting::Indeterminate
        }
    }
}

/// A resolved outcome, ready for the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionOutcome {
    /// The decision the outcome belongs to.
    pub decision_id: String,
    /// The deleted entry's original path.
    pub path: PathBuf,
    /// Artifact category key at decision time.
    pub category: String,
    /// `definite`, `likely` or `unclear` at decision time.
    pub certainty: String,
    /// What became of the deletion.
    pub outcome: Outcome,
    /// Unix seconds.
    pub observed_at: u64,
    /// Seconds between the deletion and the observation.
    pub after_secs: u64,
    /// A one-line reason.
    pub detail: String,
}

impl DecisionOutcome {
    /// The timestamped calibration observation carried by this outcome.
    /// An out-of-range wall-clock timestamp supplies no evidence.
    #[must_use]
    pub fn observation(&self) -> Option<RegretObservation> {
        Some(RegretObservation {
            category: self.category.clone(),
            certainty: certainty_from_name(&self.certainty),
            outcome: self.outcome,
            observed_at: UNIX_EPOCH.checked_add(Duration::from_secs(self.observed_at))?,
        })
    }
}

/// What the detector sees when it looks at a watched path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sighting {
    /// The entry is absent from its verified original parent.
    Absent,
    /// The entry exists again in its verified original parent.
    Recreated {
        /// A process has its cwd or an open file under the parent.
        parent_in_use: bool,
    },
    /// The entry or its original parent could not be observed reliably.
    Indeterminate,
}

impl Sighting {
    #[cfg(unix)]
    fn from_entry_lookup(
        lookup: std::io::Result<()>,
        parent_in_use: impl FnOnce() -> bool,
    ) -> Self {
        match lookup {
            Ok(()) => Self::Recreated {
                parent_in_use: parent_in_use(),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::Absent,
            Err(_) => Self::Indeterminate,
        }
    }
}

/// Watches deletions and labels them.
#[derive(Debug, Clone)]
pub struct RegretDetector {
    window: Duration,
    watches: Vec<PendingWatch>,
}

/// The window in force when this deletion started being observed. Config
/// reloads change future watches without moving an existing deadline.
#[derive(Debug, Clone)]
struct PendingWatch {
    watch: Watch,
    window: Duration,
}

impl RegretDetector {
    /// A detector with no watches; `window` is the regret window.
    #[must_use]
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            watches: Vec::new(),
        }
    }

    /// Deletions still under watch.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.watches.len()
    }

    /// Change the observation window for future deletions. Watches already
    /// pending retain the window with which they were registered.
    pub fn set_window(&mut self, window: Duration) {
        self.window = window;
    }

    /// Start watching a deletion. The identity must have been captured
    /// before the entry was removed.
    pub fn watch(&mut self, watch: Watch) {
        self.watches
            .retain(|pending| pending.watch.decision_id != watch.decision_id);
        self.watches.push(PendingWatch {
            watch,
            window: self.window,
        });
    }

    /// Resolve observations assigned the same monotonic instant. For live
    /// filesystem or process-table lookups, use [`Self::check_with_clock`]
    /// so time spent observing a path cannot make its timestamp stale.
    pub fn check(
        &mut self,
        now: Instant,
        look: impl FnMut(&Watch) -> Sighting,
    ) -> Vec<DecisionOutcome> {
        self.check_with_clock(|| now, look)
    }

    /// Resolve watches using a monotonic clock sampled immediately before
    /// and after each `look` (two clock reads per watched entry).
    /// Recreated entries resolve immediately. An observation completing at or
    /// after the deadline is `unknown`: the sighting cannot establish whether
    /// the recreation happened inside the window. Verified absent entries
    /// resolve `clean` only when their observation starts at or after expiry.
    /// An absent lookup that straddles the deadline remains pending for a fresh
    /// observation; indeterminate observations expire as `unknown`.
    pub fn check_with_clock(
        &mut self,
        mut clock: impl FnMut() -> Instant,
        mut look: impl FnMut(&Watch) -> Sighting,
    ) -> Vec<DecisionOutcome> {
        let mut outcomes = Vec::new();
        let mut keep = Vec::with_capacity(self.watches.len());
        for PendingWatch { watch, window } in self.watches.drain(..) {
            let observation_started = clock();
            let sighting = look(&watch);
            let observed_at = clock();
            let age = observed_at.saturating_duration_since(watch.deleted_at);
            let outcome = match sighting {
                Sighting::Recreated { .. } if age >= window => Some((
                    Outcome::Unknown,
                    "recreation observation completed at or after regret window expiry",
                )),
                Sighting::Recreated {
                    parent_in_use: true,
                } => Some((Outcome::Regret, "recreated while a process used the parent")),
                Sighting::Recreated {
                    parent_in_use: false,
                } => Some((
                    Outcome::Unknown,
                    "recreated with no live user under the parent",
                )),
                Sighting::Absent
                    if observation_started.saturating_duration_since(watch.deleted_at)
                        >= window =>
                {
                    Some((Outcome::Clean, "window passed without a recreation"))
                }
                Sighting::Indeterminate if age >= window => Some((
                    Outcome::Unknown,
                    "regret window expired without a reliable filesystem observation",
                )),
                Sighting::Absent | Sighting::Indeterminate => None,
            };
            match outcome {
                Some((outcome, detail)) => outcomes.push(DecisionOutcome {
                    decision_id: watch.decision_id,
                    path: watch.path,
                    category: watch.category,
                    certainty: certainty_name(watch.certainty).to_string(),
                    outcome,
                    observed_at: now_unix(),
                    after_secs: age.as_secs(),
                    detail: detail.to_string(),
                }),
                None => keep.push(PendingWatch { watch, window }),
            }
        }
        self.watches = keep;
        outcomes
    }
}

/// The stored name of a certainty class.
#[must_use]
pub fn certainty_name(certainty: ArtifactCertainty) -> &'static str {
    match certainty {
        ArtifactCertainty::Definite => "definite",
        ArtifactCertainty::Likely => "likely",
        ArtifactCertainty::Unclear => "unclear",
    }
}

/// The certainty class a stored name denotes (`Unclear` for anything else).
#[must_use]
pub fn certainty_from_name(name: &str) -> ArtifactCertainty {
    match name {
        "definite" => ArtifactCertainty::Definite,
        "likely" => ArtifactCertainty::Likely,
        _ => ArtifactCertainty::Unclear,
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// One category's regret evidence.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CategoryStats {
    /// Resolved outcomes counted as evidence (`regret` or `clean`).
    pub decisions: u64,
    /// Of those, regrets.
    pub regrets: u64,
    /// Of those, decisions whose candidate was Definite.
    pub definite_decisions: u64,
    /// Log e-process value against H0: regret rate <= alpha.
    #[serde(skip)]
    e_log: f64,
    /// Suspension end, if the e-process alarmed.
    #[serde(skip)]
    suspended_until: Option<Instant>,
}

/// The per-category picture the decision layer and `sbh explain` read.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CategoryCalibration {
    /// Artifact category key.
    pub category: String,
    /// Resolved outcomes counted as evidence.
    pub decisions: u64,
    /// Of those, regrets.
    pub regrets: u64,
    /// Tolerated regret rate for the category.
    pub alpha: f64,
    /// Posterior mean regret rate under the pooled prior.
    pub posterior_mean: f64,
    /// Clopper-Pearson upper bound on the regret rate.
    pub upper_bound: f64,
    /// `1 - excess of the bound over alpha`; 1 with no regrets.
    pub calibration: f64,
    /// The category's e-process value against H0: rate <= alpha.
    pub e_value: f64,
    /// Whether the category's deletions are suspended right now.
    pub suspended: bool,
}

/// Compact count deltas for one category at one observation timestamp.
/// Many outcomes recorded in the same clock tick need only one bucket.
#[derive(Debug, Clone, Default)]
struct EvidenceCounts {
    decisions: u64,
    regrets: u64,
    definite_decisions: u64,
}

/// Regret rates per category with the pooled prior, bounds, calibration
/// factors and suspensions.
#[derive(Debug, Clone)]
pub struct RegretCalibrator {
    config: RegretConfig,
    categories: BTreeMap<String, CategoryStats>,
    evidence: BTreeMap<SystemTime, BTreeMap<String, EvidenceCounts>>,
}

impl RegretCalibrator {
    /// A calibrator with no evidence.
    #[must_use]
    pub fn new(config: RegretConfig) -> Self {
        Self {
            config,
            categories: BTreeMap::new(),
            evidence: BTreeMap::new(),
        }
    }

    /// The tunables in force.
    #[must_use]
    pub fn config(&self) -> &RegretConfig {
        &self.config
    }

    /// Apply live settings without losing observed outcomes or shortening
    /// an existing suspension. A changed tolerated rate starts that
    /// category's sequential test afresh: its likelihood was accumulated
    /// against a different null hypothesis.
    pub fn update_config(&mut self, config: RegretConfig) {
        let definite_changed =
            self.config.alpha_definite.to_bits() != config.alpha_definite.to_bits();
        let likely_changed = self.config.alpha_likely.to_bits() != config.alpha_likely.to_bits();
        for stats in self.categories.values_mut() {
            let alpha_changed = if stats.definite_decisions * 2 >= stats.decisions {
                definite_changed
            } else {
                likely_changed
            };
            if alpha_changed {
                stats.e_log = 0.0;
            }
        }
        self.config = config;
    }

    /// Record an outcome observed now. `Unknown` outcomes are not evidence.
    /// Persisted or delayed observations must use their original timestamp
    /// through [`Self::record_observation`].
    pub fn record(
        &mut self,
        category: &str,
        certainty: ArtifactCertainty,
        outcome: Outcome,
        now: Instant,
    ) {
        let observed_at = SystemTime::now();
        self.record_observation(
            &RegretObservation {
                category: category.to_string(),
                certainty,
                outcome,
                observed_at,
            },
            observed_at,
            now,
        );
    }

    /// Apply a newly observed outcome to calibration and the live sequential
    /// alarm. Expired or unknown observations cannot contribute evidence.
    pub fn record_observation(
        &mut self,
        observation: &RegretObservation,
        now_wall: SystemTime,
        now: Instant,
    ) {
        self.expire(now_wall);
        if observation.outcome == Outcome::Unknown || observation.expired(now_wall) {
            return;
        }
        let alpha = self.alpha_for(&observation.category, observation.certainty);
        self.add_evidence(observation);
        let stats = self
            .categories
            .get_mut(&observation.category)
            .expect("adding evidence creates its category");
        // E-process for H0: rate <= alpha against p1 = min(0.5, 4 alpha).
        let p1 = (4.0 * alpha).min(0.5);
        let step = if observation.outcome == Outcome::Regret {
            (p1 / alpha).ln()
        } else {
            ((1.0 - p1) / (1.0 - alpha)).ln()
        };
        stats.e_log = (stats.e_log + step).clamp(-5.0, 6.0);
        if stats.e_log.exp() >= self.config.e_threshold {
            // A new alarm may extend an active suspension, but a shorter
            // duration loaded since the previous alarm must not reduce it.
            stats.suspended_until = stats.suspended_until.max(Some(now + self.config.suspend));
            stats.e_log = 0.0;
        }
    }

    /// Add historical calibration evidence without replaying sequential alarm
    /// steps or changing any live suspension. Callers admit each observation
    /// once before using this method.
    pub fn replay_observation(&mut self, observation: &RegretObservation, now_wall: SystemTime) {
        self.expire(now_wall);
        if observation.outcome != Outcome::Unknown && !observation.expired(now_wall) {
            self.add_evidence(observation);
        }
    }

    /// Rebuild calibration from timestamped historical outcomes. Historical
    /// alarms have already served; an existing live alarm remains untouched.
    pub fn replay(
        &mut self,
        outcomes: impl IntoIterator<Item = RegretObservation>,
        now_wall: SystemTime,
    ) {
        for observation in outcomes {
            self.replay_observation(&observation, now_wall);
        }
    }

    fn add_evidence(&mut self, observation: &RegretObservation) {
        let counts = self
            .evidence
            .entry(observation.observed_at)
            .or_default()
            .entry(observation.category.clone())
            .or_default();
        let stats = self
            .categories
            .entry(observation.category.clone())
            .or_default();
        counts.decisions += 1;
        stats.decisions += 1;
        if observation.certainty == ArtifactCertainty::Definite {
            counts.definite_decisions += 1;
            stats.definite_decisions += 1;
        }
        if observation.outcome == Outcome::Regret {
            counts.regrets += 1;
            stats.regrets += 1;
        }
    }

    /// Remove evidence strictly older than the inclusive thirty-day window.
    /// Only expired timestamp buckets are visited. Sequential-test state and
    /// active suspension deadlines are independent of this rolling evidence.
    pub fn expire(&mut self, now_wall: SystemTime) {
        let Some(cutoff) = now_wall.checked_sub(REGRET_EVIDENCE_WINDOW) else {
            return;
        };
        while self
            .evidence
            .first_key_value()
            .is_some_and(|(at, _)| *at < cutoff)
        {
            let (_, expired) = self.evidence.pop_first().expect("expired bucket exists");
            for (category, counts) in expired {
                let stats = self
                    .categories
                    .get_mut(&category)
                    .expect("retained evidence has category counts");
                stats.decisions -= counts.decisions;
                stats.regrets -= counts.regrets;
                stats.definite_decisions -= counts.definite_decisions;
            }
        }
    }

    fn alpha_for(&self, category: &str, certainty: ArtifactCertainty) -> f64 {
        match self.categories.get(category) {
            Some(stats) if stats.decisions > 0 => {
                if stats.definite_decisions * 2 >= stats.decisions {
                    self.config.alpha_definite
                } else {
                    self.config.alpha_likely
                }
            }
            _ if certainty == ArtifactCertainty::Definite => self.config.alpha_definite,
            _ => self.config.alpha_likely,
        }
    }

    /// Pooled prior across categories: mean regret rate with
    /// `prior_strength` pseudo-observations (a half regret keeps it off 0).
    fn prior(&self) -> (f64, f64) {
        let (regrets, decisions) = self
            .categories
            .values()
            .fold((0.0f64, 0.0f64), |(r, n), s| {
                (r + s.regrets as f64, n + s.decisions as f64)
            });
        let mean = ((regrets + 0.5) / (decisions + 1.0)).clamp(1e-4, 0.5);
        let strength = self.config.prior_strength.max(1.0);
        (mean * strength, (1.0 - mean) * strength)
    }

    /// The calibration factor for `category` (1 when unknown).
    #[must_use]
    pub fn calibration(&self, category: &str) -> f64 {
        self.summary(category).map_or(1.0, |c| c.calibration)
    }

    /// Whether `category` is suspended (its e-process alarmed within the
    /// suspension window).
    #[must_use]
    pub fn suspended(&self, category: &str, now: Instant) -> bool {
        self.categories
            .get(category)
            .and_then(|s| s.suspended_until)
            .is_some_and(|until| now < until)
    }

    /// Active category alarms, including a category whose calibration
    /// evidence has just expired. Expiry must not clear deletion authority.
    #[must_use]
    pub fn suspended_categories(&self, now: Instant) -> HashSet<String> {
        self.categories
            .iter()
            .filter(|(_, stats)| stats.suspended_until.is_some_and(|until| now < until))
            .map(|(category, _)| category.clone())
            .collect()
    }

    /// The category's picture, if it has evidence.
    #[must_use]
    pub fn summary(&self, category: &str) -> Option<CategoryCalibration> {
        let stats = self.categories.get(category)?;
        if stats.decisions == 0 {
            return None;
        }
        let alpha = self.alpha_for(category, ArtifactCertainty::Likely);
        let (a0, b0) = self.prior();
        let posterior_mean = (a0 + stats.regrets as f64) / (a0 + b0 + stats.decisions as f64);
        let upper_bound = clopper_pearson_upper(stats.regrets, stats.decisions, self.config.delta);
        let calibration = if stats.regrets == 0 {
            1.0
        } else {
            1.0 - ((upper_bound - alpha).max(0.0) / (1.0 - alpha)).clamp(0.0, 1.0)
        };
        Some(CategoryCalibration {
            category: category.to_string(),
            decisions: stats.decisions,
            regrets: stats.regrets,
            alpha,
            posterior_mean,
            upper_bound,
            calibration,
            e_value: stats.e_log.exp(),
            suspended: stats
                .suspended_until
                .is_some_and(|until| Instant::now() < until),
        })
    }

    /// Every category with evidence.
    #[must_use]
    pub fn summaries(&self) -> Vec<CategoryCalibration> {
        self.categories
            .keys()
            .filter_map(|c| self.summary(c))
            .collect()
    }

    /// The calibration factors by category, for the scoring engine.
    #[must_use]
    pub fn calibrations(&self) -> HashMap<String, f64> {
        self.summaries()
            .into_iter()
            .map(|c| (c.category, c.calibration))
            .collect()
    }
}

/// Clopper-Pearson upper bound on a binomial proportion with `regrets`
/// successes in `decisions` trials at confidence `1 - delta`.
#[must_use]
pub fn clopper_pearson_upper(regrets: u64, decisions: u64, delta: f64) -> f64 {
    if decisions == 0 {
        return 1.0;
    }
    if regrets >= decisions {
        return 1.0;
    }
    let delta = delta.clamp(1e-9, 0.5);
    if regrets == 0 {
        // Closed form: 1 - delta^(1/n).
        return 1.0 - delta.powf(1.0 / decisions as f64);
    }
    let a = regrets as f64 + 1.0;
    let b = (decisions - regrets) as f64;
    beta_quantile(1.0 - delta, a, b)
}

/// The `p` quantile of Beta(a, b) by bisection on the regularized
/// incomplete beta function.
fn beta_quantile(p: f64, a: f64, b: f64) -> f64 {
    let (mut lo, mut hi) = (0.0f64, 1.0f64);
    for _ in 0..80 {
        let mid = f64::midpoint(lo, hi);
        if regularized_incomplete_beta(mid, a, b) < p {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    f64::midpoint(lo, hi)
}

/// `I_x(a, b)` by Lentz's continued fraction (Numerical Recipes `betai`).
fn regularized_incomplete_beta(x: f64, a: f64, b: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    if x >= 1.0 {
        return 1.0;
    }
    let ln_front = a.mul_add(
        x.ln(),
        b.mul_add((1.0 - x).ln(), ln_gamma(a + b) - ln_gamma(a) - ln_gamma(b)),
    );
    if x < (a + 1.0) / (a + b + 2.0) {
        ln_front.exp() * beta_continued_fraction(x, a, b) / a
    } else {
        1.0 - ln_front.exp() * beta_continued_fraction(1.0 - x, b, a) / b
    }
}

#[allow(clippy::many_single_char_names)]
fn beta_continued_fraction(x: f64, a: f64, b: f64) -> f64 {
    const TINY: f64 = 1e-300;
    const EPS: f64 = 1e-14;
    let qab = a + b;
    let qap = a + 1.0;
    let qam = a - 1.0;
    let mut c = 1.0;
    let mut d = 1.0 - qab * x / qap;
    if d.abs() < TINY {
        d = TINY;
    }
    d = 1.0 / d;
    let mut h = d;
    for m in 1..=300 {
        let m = f64::from(m);
        let m2 = 2.0 * m;
        let aa = m * (b - m) * x / ((qam + m2) * (a + m2));
        d = aa.mul_add(d, 1.0);
        if d.abs() < TINY {
            d = TINY;
        }
        c = 1.0 + aa / c;
        if c.abs() < TINY {
            c = TINY;
        }
        d = 1.0 / d;
        h *= d * c;
        let aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2));
        d = aa.mul_add(d, 1.0);
        if d.abs() < TINY {
            d = TINY;
        }
        c = 1.0 + aa / c;
        if c.abs() < TINY {
            c = TINY;
        }
        d = 1.0 / d;
        let del = d * c;
        h *= del;
        if (del - 1.0).abs() < EPS {
            break;
        }
    }
    h
}

/// Lanczos approximation of `ln Γ(x)` for `x > 0`.
fn ln_gamma(x: f64) -> f64 {
    const COEFFICIENTS: [f64; 6] = [
        76.180_091_729_471_46,
        -86.505_320_329_416_77,
        24.014_098_240_830_91,
        -1.231_739_572_450_155,
        0.120_865_097_386_617_9e-2,
        -0.539_523_938_495_3e-5,
    ];
    let mut y = x;
    let tmp = x + 5.5;
    let tmp = (x + 0.5).mul_add(-tmp.ln(), tmp);
    let mut ser = 1.000_000_000_190_015;
    for coefficient in COEFFICIENTS {
        y += 1.0;
        ser += coefficient / y;
    }
    -tmp + (2.506_628_274_631_000_5 * ser / x).ln()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "sqlite")]
    #[test]
    fn scoring_history_missing_or_unreadable_ledger_creates_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing/activity.sqlite3");
        let history = ScoringHistory::load(&missing);
        assert!(history.outcomes.is_empty());
        assert!(history.cache_deletions.is_empty());
        assert!(!missing.parent().unwrap().exists());

        let invalid = directory.path().join("invalid.sqlite3");
        std::fs::write(&invalid, b"not a SQLite database").unwrap();
        let history = ScoringHistory::load(&invalid);
        assert!(history.outcomes.is_empty());
        assert!(history.cache_deletions.is_empty());
        assert_eq!(std::fs::read(&invalid).unwrap(), b"not a SQLite database");

        // Reading a database from an older or unrelated schema must not
        // quietly install sbh's schema or change its journal mode.
        let legacy = directory.path().join("legacy.sqlite3");
        let connection = rusqlite::Connection::open(&legacy).unwrap();
        connection
            .execute_batch("CREATE TABLE existing_marker (id INTEGER PRIMARY KEY)")
            .unwrap();
        drop(connection);
        let before = std::fs::read(&legacy).unwrap();
        let history = ScoringHistory::load(&legacy);
        assert!(history.outcomes.is_empty());
        assert!(history.cache_deletions.is_empty());
        assert_eq!(std::fs::read(&legacy).unwrap(), before);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn scoring_history_keeps_pending_receipts_and_bounds_each_evidence_window() {
        use crate::logger::sqlite::{ActivityRow, SqliteLogger};
        use crate::scanner::scoring::cache_redeletion_counts;

        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("activity.sqlite3");
        let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let recent = now - Duration::from_secs(10);
        let db = SqliteLogger::open(&database).unwrap();
        for (path, completed_at) in [
            ("/data/tmp/pending-cache", recent),
            (
                "/data/tmp/expired-receipt",
                now - CACHE_REDELETION_MEMORY - Duration::from_secs(1),
            ),
        ] {
            let timestamp = chrono::DateTime::<chrono::Utc>::from(completed_at)
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            db.log_activity(&ActivityRow {
                timestamp: timestamp.clone(),
                event_type: "artifact_delete".to_string(),
                severity: "info".to_string(),
                path: Some(path.to_string()),
                size_bytes: Some(4096),
                score: Some(0.99),
                score_factors: None,
                pressure_level: None,
                free_pct: None,
                duration_ms: Some(1),
                success: 1,
                error_code: None,
                error_message: None,
                details: Some(format!(
                    "decision_id=0123456789ab;category=GoCache;completed_at={timestamp}"
                )),
            })
            .unwrap();
        }
        for (id, category, outcome, observed_at) in [
            ("fallback", "GoCache", Outcome::Unknown, recent),
            (
                "retained",
                "RustTarget",
                Outcome::Regret,
                now - Duration::from_secs(10 * 24 * 60 * 60),
            ),
            (
                "expired",
                "RustTarget",
                Outcome::Regret,
                now - Duration::from_secs(31 * 24 * 60 * 60),
            ),
        ] {
            db.log_outcome(&DecisionOutcome {
                decision_id: id.to_string(),
                path: PathBuf::from(format!("/data/tmp/{id}")),
                category: category.to_string(),
                certainty: "definite".to_string(),
                outcome,
                observed_at: observed_at.duration_since(UNIX_EPOCH).unwrap().as_secs(),
                after_secs: 10,
                detail: String::new(),
            })
            .unwrap();
        }
        drop(db);

        let history = ScoringHistory::load_at(&database, now);
        assert_eq!(history.outcomes.len(), 2);
        assert_eq!(
            history
                .outcomes
                .iter()
                .filter(|observation| observation.outcome == Outcome::Regret)
                .count(),
            1,
        );
        assert_eq!(
            cache_redeletion_counts(history.cache_deletions, now),
            HashMap::from([
                (PathBuf::from("/data/tmp/pending-cache"), 1),
                (PathBuf::from("/data/tmp/fallback"), 1),
            ]),
            "pending successes survive without labels; old evidence expires independently",
        );
    }

    #[cfg(feature = "sqlite")]
    fn history_receipt(
        decision_id: &str,
        path: &str,
        completed_at: SystemTime,
    ) -> crate::logger::sqlite::StoredDeletion {
        crate::logger::sqlite::StoredDeletion {
            decision_id: decision_id.to_string(),
            path: path.to_string(),
            category: Some("GoCache".to_string()),
            recorded_at: completed_at + Duration::from_secs(1),
            completed_at: Some(completed_at),
        }
    }

    #[cfg(feature = "sqlite")]
    fn history_outcome(
        decision_id: &str,
        path: &str,
        deleted_at: SystemTime,
        outcome: Outcome,
    ) -> crate::logger::sqlite::StoredOutcome {
        crate::logger::sqlite::StoredOutcome {
            decision_id: decision_id.to_string(),
            path: path.to_string(),
            category: "GoCache".to_string(),
            certainty: "definite".to_string(),
            outcome: outcome.as_str().to_string(),
            observed_at: chrono::DateTime::<chrono::Utc>::from(
                deleted_at + Duration::from_secs(10),
            )
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            after_secs: 10,
            detail: "history fixture".to_string(),
        }
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn history_admission_retains_duplicate_rows_without_recounting_copied_sources() {
        let deleted_at = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let now = deleted_at + Duration::from_secs(20);
        let path = "/data/tmp/recreated-cache";
        let receipt = history_receipt("0123456789ab", path, deleted_at);
        let outcome = history_outcome("0123456789ab", path, deleted_at, Outcome::Clean);
        let mut history = HistoryAdmission::default();
        for _ in 0..2 {
            assert!(history.admit_receipt(receipt.clone(), now));
            assert!(history.admit_outcome(outcome.clone(), now).is_some());
        }
        assert_eq!(history.cache_redeletions(now)[Path::new(path)], 2);

        history.begin_generation();
        for _ in 0..2 {
            assert!(!history.admit_receipt(receipt.clone(), now));
            assert!(history.admit_outcome(outcome.clone(), now).is_none());
        }
        assert_eq!(history.cache_redeletions(now)[Path::new(path)], 2);
        // A genuinely additional identical row in this generation remains
        // observable; a fingerprint is not merely a set membership test.
        assert!(history.admit_receipt(receipt, now));
        assert!(history.admit_outcome(outcome, now).is_some());
        assert_eq!(history.cache_redeletions(now)[Path::new(path)], 3);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn history_admission_enriches_legacy_receipts_without_counting_them_again() {
        let deleted_at = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let now = deleted_at + Duration::from_secs(30);
        let path = "/data/tmp/legacy-cache";
        let mut unknown = history_receipt("0123456789ab", path, deleted_at);
        unknown.completed_at = None;
        unknown.category = None;
        let mut known = unknown.clone();
        known.category = Some("GoCache".to_string());
        let mut history = HistoryAdmission::default();
        for _ in 0..2 {
            assert!(history.admit_receipt(unknown.clone(), now));
        }
        assert!(history.cache_redeletions(now).is_empty());

        history.begin_generation();
        assert!(!history.admit_receipt(known.clone(), now));
        assert!(!history.admit_receipt(unknown.clone(), now));
        assert_eq!(history.cache_redeletions(now)[Path::new(path)], 1);
        history.begin_generation();
        for _ in 0..2 {
            assert!(!history.admit_receipt(known.clone(), now));
        }
        assert_eq!(history.cache_redeletions(now)[Path::new(path)], 2);
        history.begin_generation();
        for _ in 0..2 {
            assert!(!history.admit_receipt(unknown.clone(), now));
        }
        assert_eq!(
            history.cache_redeletions(now)[Path::new(path)],
            2,
            "losing decision_log hydration cannot recount or erase known receipts",
        );

        let mut labelled = HistoryAdmission::default();
        labelled.admit_receipt(unknown, now);
        labelled.admit_outcome(
            history_outcome("0123456789ab", path, deleted_at, Outcome::Clean),
            now,
        );
        assert_eq!(labelled.cache_redeletions(now)[Path::new(path)], 1);
        labelled.begin_generation();
        assert!(!labelled.admit_receipt(known, now));
        assert_eq!(
            labelled.cache_redeletions(now)[Path::new(path)],
            1,
            "a category recovered from a matching label is not a second deletion",
        );
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn history_admission_pairs_receipts_and_labels_independently_of_arrival_order() {
        let deleted_at = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let now = deleted_at + Duration::from_secs(30);
        let path = "/data/tmp/reused-inode-cache";
        let first = history_receipt("0123456789ab", path, deleted_at);
        let second = history_receipt("0123456789ab", path, deleted_at + Duration::from_secs(3));
        let flexible = history_outcome(
            "0123456789ab",
            path,
            deleted_at + Duration::from_secs(1),
            Outcome::Clean,
        );
        let exact = history_outcome("0123456789ab", path, deleted_at, Outcome::Regret);
        for receipts_first in [true, false] {
            let mut history = HistoryAdmission::default();
            if receipts_first {
                history.admit_receipt(first.clone(), now);
                history.admit_receipt(second.clone(), now);
            }
            history.admit_outcome(flexible.clone(), now);
            history.admit_outcome(exact.clone(), now);
            if !receipts_first {
                history.admit_receipt(second.clone(), now);
                history.admit_receipt(first.clone(), now);
            }
            // The later-arriving exact label needs the first receipt; the
            // flexible label must be reconsidered against the second receipt.
            assert_eq!(history.cache_redeletions(now)[Path::new(path)], 2);
        }
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn history_admission_uses_receipt_completion_at_the_exact_cache_expiry_boundary() {
        let deleted_at = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let now = deleted_at + Duration::from_secs(30);
        let path = "/data/tmp/rounded-cache";
        let receipt = history_receipt("0123456789ab", path, deleted_at);
        let outcome = history_outcome(
            "0123456789ab",
            path,
            deleted_at + Duration::from_secs(1),
            Outcome::Unknown,
        );
        for receipt_first in [true, false] {
            let mut history = HistoryAdmission::default();
            if receipt_first {
                history.admit_receipt(receipt.clone(), now);
            }
            assert!(history.admit_outcome(outcome.clone(), now).is_some());
            if !receipt_first {
                history.admit_receipt(receipt.clone(), now);
            }
            assert_eq!(history.cache_redeletions(now)[Path::new(path)], 1);
            assert_eq!(
                history.cache_redeletions(deleted_at + CACHE_REDELETION_MEMORY)[Path::new(path)],
                1,
            );
            assert!(
                history
                    .cache_redeletions(
                        deleted_at + CACHE_REDELETION_MEMORY + Duration::from_nanos(1),
                    )
                    .is_empty(),
                "a later rounded outcome must not resurrect an expired receipt",
            );
            assert!(
                history
                    .cache_redeletions(
                        deleted_at + CACHE_REDELETION_MEMORY + Duration::from_secs(3),
                    )
                    .is_empty(),
            );
            assert!(history.cache_groups.is_empty());
        }
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn history_admission_keeps_independent_windows_and_rejects_unusable_rows() {
        let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let mut history = HistoryAdmission::default();
        let old_deletion = now - Duration::from_secs(8 * 24 * 60 * 60);
        assert!(!history.admit_receipt(
            history_receipt("0123456789ab", "/data/tmp/expired-cache", old_deletion),
            now,
        ));
        let retained = history
            .admit_outcome(
                history_outcome(
                    "0123456789ab",
                    "/data/tmp/expired-cache",
                    old_deletion,
                    Outcome::Regret,
                ),
                now,
            )
            .unwrap();
        assert_eq!(retained.outcome, Outcome::Regret);
        assert_eq!(retained.observed_at, old_deletion + Duration::from_secs(10));
        assert!(history.cache_redeletions(now).is_empty());

        let fallback_path = "/data/tmp/outcome-only-cache";
        let fallback = history_outcome(
            "abcdef012345",
            fallback_path,
            now - Duration::from_secs(30),
            Outcome::Unknown,
        );
        assert_eq!(
            history
                .admit_outcome(fallback.clone(), now)
                .unwrap()
                .outcome,
            Outcome::Unknown,
        );
        assert_eq!(history.cache_redeletions(now)[Path::new(fallback_path)], 1);
        let mut malformed = fallback.clone();
        malformed.outcome = "not-a-label".to_string();
        assert!(history.admit_outcome(malformed, now).is_none());
        let mut malformed = fallback;
        malformed.observed_at = "not-a-time".to_string();
        assert!(history.admit_outcome(malformed, now).is_none());
        assert!(
            history
                .admit_outcome(
                    history_outcome(
                        "fedcba987654",
                        "/data/tmp/too-old-cache",
                        now - REGRET_EVIDENCE_WINDOW - Duration::from_secs(11),
                        Outcome::Regret,
                    ),
                    now,
                )
                .is_none()
        );

        history.expire(now + REGRET_EVIDENCE_WINDOW + Duration::from_secs(1));
        assert!(history.receipts.is_empty());
        assert!(history.outcomes.is_empty());
        assert!(history.cache_groups.is_empty());
        assert!(history.cache_expiry.is_empty());
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn history_admission_recovers_legacy_classification_and_distinct_reuses() {
        let deleted_at = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let now = deleted_at + Duration::from_secs(60);
        let path = "/data/tmp/legacy-cache";
        let mut legacy = history_receipt("0123456789ab", path, deleted_at);
        legacy.completed_at = None;
        legacy.category = None;
        let mut history = HistoryAdmission::default();
        history.admit_receipt(legacy, now);
        assert!(history.cache_redeletions(now).is_empty());
        history.admit_outcome(
            history_outcome("0123456789ab", path, deleted_at, Outcome::Clean),
            now,
        );
        assert_eq!(history.cache_redeletions(now)[Path::new(path)], 1);

        // Inode/decision-id reuse at a later completion time is a distinct
        // deletion, even though the path and stable id are identical.
        let reused_at = deleted_at + Duration::from_secs(30);
        history.admit_receipt(history_receipt("0123456789ab", path, reused_at), now);
        history.admit_outcome(
            history_outcome("0123456789ab", path, reused_at, Outcome::Clean),
            now,
        );
        assert_eq!(history.cache_redeletions(now)[Path::new(path)], 2);
    }

    fn watch(id: &str, path: &Path, category: &str, at: Instant) -> Watch {
        Watch {
            decision_id: id.to_string(),
            path: path.to_path_buf(),
            identity: EntryIdentity {
                parent_device: 1,
                parent_inode: 2,
                name: path.file_name().unwrap().to_string_lossy().into_owned(),
            },
            category: category.to_string(),
            certainty: ArtifactCertainty::Definite,
            deleted_at: at,
        }
    }

    #[test]
    fn incomplete_beta_matches_known_values() {
        assert!((regularized_incomplete_beta(0.5, 1.0, 1.0) - 0.5).abs() < 1e-12);
        // I_x(1, b) = 1 - (1 - x)^b.
        assert!(
            (regularized_incomplete_beta(0.3, 1.0, 4.0) - (1.0 - 0.7f64.powi(4))).abs() < 1e-10
        );
        // I_x(a, 1) = x^a.
        assert!((regularized_incomplete_beta(0.6, 3.0, 1.0) - 0.6f64.powi(3)).abs() < 1e-10);
        // Symmetry: I_x(a, b) = 1 - I_{1-x}(b, a).
        let lhs = regularized_incomplete_beta(0.35, 2.5, 4.5);
        let rhs = 1.0 - regularized_incomplete_beta(0.65, 4.5, 2.5);
        assert!((lhs - rhs).abs() < 1e-10, "{lhs} vs {rhs}");
        assert!((ln_gamma(5.0) - 24f64.ln()).abs() < 1e-9);
    }

    #[test]
    fn clopper_pearson_bound_is_monotone_in_count_and_matches_the_closed_forms() {
        assert_eq!(clopper_pearson_upper(0, 0, 0.05), 1.0);
        assert!(
            (clopper_pearson_upper(0, 20, 0.05) - (1.0 - 0.05f64.powf(1.0 / 20.0))).abs() < 1e-12
        );
        assert_eq!(clopper_pearson_upper(5, 5, 0.05), 1.0);
        // One regret in ten: the textbook 95% one-sided upper bound is 0.394.
        let one_in_ten = clopper_pearson_upper(1, 10, 0.05);
        assert!((one_in_ten - 0.3942).abs() < 2e-3, "{one_in_ten}");
        // More trials with the same regrets lower the bound; more regrets raise it.
        let mut previous = 1.0;
        for n in [2u64, 5, 10, 50, 200, 1000] {
            let bound = clopper_pearson_upper(1, n, 0.05);
            assert!(bound < previous, "n={n}: {bound} >= {previous}");
            previous = bound;
        }
        let mut previous = 0.0;
        for k in 0..50u64 {
            let bound = clopper_pearson_upper(k, 50, 0.05);
            assert!(bound > previous, "k={k}: {bound} <= {previous}");
            previous = bound;
        }
    }

    #[test]
    fn zero_regrets_never_tighten_and_ten_percent_tightens_only_its_category() {
        let now = Instant::now();
        let mut calibrator = RegretCalibrator::new(RegretConfig::default());
        for _ in 0..200 {
            calibrator.record(
                "rust_target",
                ArtifactCertainty::Definite,
                Outcome::Clean,
                now,
            );
        }
        assert_eq!(calibrator.calibration("rust_target"), 1.0);
        assert!(!calibrator.suspended("rust_target", now));
        let summary = calibrator.summary("rust_target").unwrap();
        assert!(summary.upper_bound < 0.02, "{summary:?}");

        for i in 0..100 {
            let outcome = if i % 10 == 0 {
                Outcome::Regret
            } else {
                Outcome::Clean
            };
            calibrator.record("node_modules", ArtifactCertainty::Likely, outcome, now);
        }
        let node = calibrator.summary("node_modules").unwrap();
        assert_eq!(node.regrets, 10);
        assert!(node.upper_bound > 0.1 && node.upper_bound < 0.2, "{node:?}");
        assert!(node.calibration < 0.9, "{node:?}");
        assert_eq!(
            calibrator.calibration("rust_target"),
            1.0,
            "another category is untouched"
        );
        assert!((calibrator.calibration("never_seen") - 1.0).abs() < f64::EPSILON);
        let factors = calibrator.calibrations();
        assert_eq!(factors.len(), 2);
        // Unknown outcomes are not evidence.
        calibrator.record(
            "node_modules",
            ArtifactCertainty::Likely,
            Outcome::Unknown,
            now,
        );
        assert_eq!(calibrator.summary("node_modules").unwrap().decisions, 100);
    }

    #[test]
    fn a_run_of_regrets_suspends_only_that_category_for_the_configured_time() {
        let now = Instant::now();
        let config = RegretConfig {
            suspend: Duration::from_mins(10),
            ..RegretConfig::default()
        };
        let mut calibrator = RegretCalibrator::new(config);
        calibrator.record(
            "rust_target",
            ArtifactCertainty::Definite,
            Outcome::Clean,
            now,
        );
        for _ in 0..3 {
            calibrator.record("pip_cache", ArtifactCertainty::Likely, Outcome::Regret, now);
        }
        assert!(
            calibrator.suspended("pip_cache", now),
            "{:?}",
            calibrator.summary("pip_cache")
        );
        assert!(!calibrator.suspended("rust_target", now));
        assert!(!calibrator.suspended("pip_cache", now + Duration::from_secs(601)));
        // Replay from the ledger rebuilds the counts but not the suspension.
        let mut rebuilt = RegretCalibrator::new(RegretConfig::default());
        let observed_at = SystemTime::now();
        rebuilt.replay(
            (0..3).map(|_| RegretObservation {
                category: "pip_cache".to_string(),
                certainty: ArtifactCertainty::Likely,
                outcome: Outcome::Regret,
                observed_at,
            }),
            observed_at,
        );
        assert_eq!(rebuilt.summary("pip_cache").unwrap().regrets, 3);
        assert!(!rebuilt.suspended("pip_cache", now));
    }

    #[test]
    fn calibration_evidence_expires_at_its_original_observation_boundary() {
        let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let cutoff = now - REGRET_EVIDENCE_WINDOW;
        let observation = |category: &str, outcome, observed_at| RegretObservation {
            category: category.to_string(),
            certainty: ArtifactCertainty::Definite,
            outcome,
            observed_at,
        };
        let mut calibrator = RegretCalibrator::new(RegretConfig::default());
        calibrator.replay(
            [
                observation("GoCache", Outcome::Regret, cutoff),
                observation("GoCache", Outcome::Clean, now),
                observation("GoCache", Outcome::Regret, cutoff - Duration::from_nanos(1)),
                observation("RustTarget", Outcome::Regret, now),
            ],
            now,
        );
        let before = calibrator.summary("GoCache").unwrap();
        assert_eq!((before.decisions, before.regrets), (2, 1));
        assert!(before.calibration < 1.0);

        // SQL's >= cutoff includes the exact boundary. Importing that row now
        // must not grant it another thirty days of influence.
        calibrator.expire(now);
        assert_eq!(calibrator.summary("GoCache").unwrap(), before);
        calibrator.expire(now + Duration::from_nanos(1));
        let after = calibrator.summary("GoCache").unwrap();
        assert_eq!((after.decisions, after.regrets), (1, 0));
        assert_eq!(after.calibration, 1.0);
        assert_eq!(calibrator.summary("RustTarget").unwrap().regrets, 1);

        calibrator.expire(now + REGRET_EVIDENCE_WINDOW + Duration::from_nanos(1));
        assert!(calibrator.calibrations().is_empty());
    }

    #[test]
    fn expiry_keeps_active_suspensions_and_live_sequential_evidence() {
        let now_wall = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let now = Instant::now();
        let mut calibrator = RegretCalibrator::new(RegretConfig {
            suspend: Duration::from_secs(60),
            ..RegretConfig::default()
        });
        let observation = RegretObservation {
            category: "GoCache".to_string(),
            certainty: ArtifactCertainty::Definite,
            outcome: Outcome::Regret,
            observed_at: now_wall - REGRET_EVIDENCE_WINDOW,
        };
        // Three regrets raise the alarm; the fourth starts its next sequence.
        for _ in 0..4 {
            calibrator.record_observation(&observation, now_wall, now);
        }
        let e_log = calibrator.categories["GoCache"].e_log;
        let deadline = calibrator.categories["GoCache"].suspended_until;
        assert!(e_log > 0.0);
        assert_eq!(deadline, Some(now + Duration::from_secs(60)));

        calibrator.expire(now_wall + Duration::from_nanos(1));
        assert!(calibrator.summary("GoCache").is_none());
        assert_eq!(calibrator.categories["GoCache"].e_log, e_log);
        assert_eq!(calibrator.categories["GoCache"].suspended_until, deadline);
        assert_eq!(
            calibrator.suspended_categories(now + Duration::from_secs(59)),
            HashSet::from(["GoCache".to_string()]),
        );
        assert!(
            calibrator
                .suspended_categories(now + Duration::from_secs(60))
                .is_empty(),
        );

        // Loading old evidence can change calibration but cannot restart a
        // served alarm, reset a live sequence, or shorten its deadline.
        calibrator.replay(
            (0..100).map(|_| RegretObservation {
                category: "GoCache".to_string(),
                certainty: ArtifactCertainty::Definite,
                outcome: Outcome::Regret,
                observed_at: now_wall,
            }),
            now_wall + Duration::from_nanos(1),
        );
        assert_eq!(calibrator.summary("GoCache").unwrap().regrets, 100);
        assert_eq!(calibrator.categories["GoCache"].e_log, e_log);
        assert_eq!(calibrator.categories["GoCache"].suspended_until, deadline);
    }

    #[test]
    fn timestamp_buckets_keep_dense_evidence_and_match_a_fresh_replay() {
        let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let cutoff = now - REGRET_EVIDENCE_WINDOW;
        let clean = RegretObservation {
            category: "GoCache".to_string(),
            certainty: ArtifactCertainty::Definite,
            outcome: Outcome::Clean,
            observed_at: cutoff,
        };
        let recent = RegretObservation {
            outcome: Outcome::Regret,
            observed_at: now,
            ..clean.clone()
        };
        let mut running = RegretCalibrator::new(RegretConfig::default());
        for _ in 0..10_000 {
            running.replay_observation(&clean, now);
        }
        running.replay_observation(&recent, now);
        assert_eq!(running.summary("GoCache").unwrap().decisions, 10_001);
        assert_eq!(running.evidence.len(), 2);
        assert_eq!(running.evidence[&cutoff].len(), 1);
        assert_eq!(running.evidence[&cutoff]["GoCache"].decisions, 10_000);

        let after = now + Duration::from_nanos(1);
        running.expire(after);
        let mut restarted = RegretCalibrator::new(RegretConfig::default());
        restarted.replay([recent], after);
        assert_eq!(running.summary("GoCache"), restarted.summary("GoCache"));
        assert_eq!(running.summary("GoCache").unwrap().regrets, 1);
        assert_eq!(running.evidence.len(), 1);
    }

    #[test]
    fn reconfiguration_preserves_evidence_and_resets_only_changed_nulls() {
        let now = Instant::now();
        let mut calibrator = RegretCalibrator::new(RegretConfig::default());
        for (category, certainty, clean, regrets) in [
            ("rust_target", ArtifactCertainty::Definite, 20, 1),
            ("node_modules", ArtifactCertainty::Likely, 3, 1),
            ("suspended", ArtifactCertainty::Definite, 0, 4),
        ] {
            for _ in 0..clean {
                calibrator.record(category, certainty, Outcome::Clean, now);
            }
            for _ in 0..regrets {
                calibrator.record(category, certainty, Outcome::Regret, now);
            }
        }
        let before = calibrator.categories.clone();
        let rust_before = calibrator.summary("rust_target").unwrap();
        assert!(calibrator.suspended("suspended", now));
        assert_ne!(before["rust_target"].e_log, 0.0);
        assert_ne!(before["node_modules"].e_log, 0.0);

        let mut updated = calibrator.config().clone();
        updated.alpha_definite = 0.04;
        updated.suspend = Duration::from_secs(1);
        calibrator.update_config(updated.clone());
        assert_eq!(calibrator.config(), &updated);
        for (category, original) in &before {
            let current = &calibrator.categories[category];
            assert_eq!(current.decisions, original.decisions);
            assert_eq!(current.regrets, original.regrets);
            assert_eq!(current.definite_decisions, original.definite_decisions);
            assert_eq!(current.suspended_until, original.suspended_until);
        }
        assert_eq!(calibrator.categories["rust_target"].e_log, 0.0);
        assert_eq!(calibrator.categories["suspended"].e_log, 0.0);
        assert_eq!(
            calibrator.categories["node_modules"].e_log,
            before["node_modules"].e_log
        );
        let rust_after = calibrator.summary("rust_target").unwrap();
        assert_eq!(rust_after.alpha, 0.04);
        assert_eq!(rust_after.posterior_mean, rust_before.posterior_mean);
        assert_eq!(rust_after.upper_bound, rust_before.upper_bound);
        assert!(rust_after.calibration > rust_before.calibration);
        assert!(calibrator.suspended("suspended", now + Duration::from_secs(2)));

        calibrator.record(
            "rust_target",
            ArtifactCertainty::Definite,
            Outcome::Clean,
            now,
        );
        // The next likelihood step uses the new alpha: (1 - 4 * .04) /
        // (1 - .04), starting from the reset e-value of one.
        assert!((calibrator.summary("rust_target").unwrap().e_value - 0.875).abs() < 1e-12);

        // Identical rates keep the accumulated likelihood, including a
        // category whose rate was unchanged by the preceding reload.
        let unchanged = calibrator.summaries();
        calibrator.update_config(updated.clone());
        assert_eq!(calibrator.summaries(), unchanged);

        updated.alpha_likely = 0.01;
        calibrator.update_config(updated);
        assert_eq!(calibrator.categories["node_modules"].e_log, 0.0);
        assert_eq!(calibrator.summary("node_modules").unwrap().alpha, 0.01);
    }

    #[test]
    fn reconfiguration_changes_future_suspensions_without_truncating_existing_ones() {
        let now = Instant::now();
        let mut config = RegretConfig {
            suspend: Duration::from_secs(600),
            ..RegretConfig::default()
        };
        let mut calibrator = RegretCalibrator::new(config.clone());
        for _ in 0..3 {
            calibrator.record("old", ArtifactCertainty::Definite, Outcome::Regret, now);
        }
        for _ in 0..2 {
            calibrator.record("future", ArtifactCertainty::Definite, Outcome::Regret, now);
        }
        let future_likelihood = calibrator.summary("future").unwrap().e_value;
        config.suspend = Duration::from_secs(30);
        calibrator.update_config(config);
        assert_eq!(
            calibrator.summary("future").unwrap().e_value,
            future_likelihood
        );
        calibrator.record("future", ArtifactCertainty::Definite, Outcome::Regret, now);
        assert!(calibrator.suspended("future", now + Duration::from_secs(29)));
        assert!(!calibrator.suspended("future", now + Duration::from_secs(30)));
        assert!(calibrator.suspended("old", now + Duration::from_secs(599)));
        assert!(!calibrator.suspended("old", now + Duration::from_secs(600)));
    }

    #[test]
    fn a_shorter_reloaded_suspension_cannot_shorten_an_active_alarm() {
        let now = Instant::now();
        let mut config = RegretConfig {
            suspend: Duration::from_secs(600),
            ..RegretConfig::default()
        };
        let mut calibrator = RegretCalibrator::new(config.clone());
        for _ in 0..3 {
            calibrator.record("active", ArtifactCertainty::Definite, Outcome::Regret, now);
        }
        config.suspend = Duration::from_secs(30);
        calibrator.update_config(config);
        let next_alarm = now + Duration::from_secs(5);
        for category in ["active", "fresh"] {
            for _ in 0..3 {
                calibrator.record(
                    category,
                    ArtifactCertainty::Definite,
                    Outcome::Regret,
                    next_alarm,
                );
            }
        }
        assert!(calibrator.suspended("fresh", now + Duration::from_secs(34)));
        assert!(!calibrator.suspended("fresh", now + Duration::from_secs(35)));
        assert!(calibrator.suspended("active", now + Duration::from_secs(599)));
        assert!(!calibrator.suspended("active", now + Duration::from_secs(600)));

        // An alarm near the existing deadline must still extend it by the
        // newly configured duration; preserving a deadline cannot freeze it.
        for _ in 0..3 {
            calibrator.record(
                "active",
                ArtifactCertainty::Definite,
                Outcome::Regret,
                now + Duration::from_secs(590),
            );
        }
        assert!(calibrator.suspended("active", now + Duration::from_secs(619)));
        assert!(!calibrator.suspended("active", now + Duration::from_secs(620)));
    }

    #[test]
    fn changed_windows_apply_only_to_new_watches_in_both_directions() {
        let t0 = Instant::now();
        for (old_secs, new_secs, first, last) in [(60, 120, "old", "new"), (120, 60, "new", "old")]
        {
            let old_window = Duration::from_secs(old_secs);
            let new_window = Duration::from_secs(new_secs);
            let mut detector = RegretDetector::new(old_window);
            detector.watch(watch("old", Path::new("/p/old"), "rust_target", t0));
            detector.set_window(new_window);
            detector.watch(watch("new", Path::new("/p/new"), "rust_target", t0));
            let first_deadline = t0 + old_window.min(new_window);
            let mut recreated = detector.clone();
            let before = detector.check(
                first_deadline.checked_sub(Duration::from_nanos(1)).unwrap(),
                |_| Sighting::Absent,
            );
            assert!(before.is_empty());
            let expired = detector.check(first_deadline, |_| Sighting::Absent);
            assert_eq!(expired.len(), 1);
            assert_eq!(expired[0].decision_id, first);
            assert_eq!(expired[0].outcome, Outcome::Clean);
            assert_eq!(detector.pending(), 1);
            let remaining = detector.check(t0 + old_window.max(new_window), |_| Sighting::Absent);
            assert_eq!(remaining.len(), 1);
            assert_eq!(remaining[0].decision_id, last);
            assert_eq!(detector.pending(), 0);

            // The same captured windows also govern recreation: extending
            // the config cannot turn an expired old watch into regret, and
            // shortening it cannot expire an old watch early.
            let outcomes = recreated.check(first_deadline, |_| Sighting::Recreated {
                parent_in_use: true,
            });
            assert_eq!(outcomes.len(), 2);
            for outcome in outcomes {
                let expected = if outcome.decision_id == first {
                    Outcome::Unknown
                } else {
                    Outcome::Regret
                };
                assert_eq!(outcome.outcome, expected);
            }
        }
    }

    #[test]
    fn detector_labels_recreation_in_use_as_regret_and_expiry_as_clean() {
        let t0 = Instant::now();
        let mut detector = RegretDetector::new(Duration::from_mins(30));
        let a = PathBuf::from("/p/a/target");
        let b = PathBuf::from("/p/b/target");
        let c = PathBuf::from("/p/c/target");
        detector.watch(watch("d-a", &a, "rust_target", t0));
        detector.watch(watch("d-b", &b, "rust_target", t0));
        detector.watch(watch("d-c", &c, "rust_target", t0));
        assert_eq!(detector.pending(), 3);
        // Ten minutes in: a is back with a live user, b is back unused,
        // c is still gone.
        let outcomes = detector.check(t0 + Duration::from_secs(600), |w| {
            if w.path == a || w.path == b {
                Sighting::Recreated {
                    parent_in_use: w.path == a,
                }
            } else {
                Sighting::Absent
            }
        });
        assert_eq!(outcomes.len(), 2);
        let by_id: HashMap<_, _> = outcomes
            .iter()
            .map(|o| (o.decision_id.as_str(), o))
            .collect();
        assert_eq!(by_id["d-a"].outcome, Outcome::Regret);
        assert_eq!(by_id["d-b"].outcome, Outcome::Unknown);
        assert_eq!(by_id["d-a"].after_secs, 600);
        assert_eq!(detector.pending(), 1);
        // The window passes for c.
        let outcomes = detector.check(t0 + Duration::from_mins(30), |_| Sighting::Absent);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].outcome, Outcome::Clean);
        assert_eq!(detector.pending(), 0);
    }

    #[test]
    fn detector_recreation_deadline_is_exclusive() {
        let t0 = Instant::now();
        let window = Duration::from_secs(60);
        for (age, active_outcome) in [
            (
                window.checked_sub(Duration::from_nanos(1)).unwrap(),
                Outcome::Regret,
            ),
            (window, Outcome::Unknown),
            (window + Duration::from_nanos(1), Outcome::Unknown),
            (Duration::from_hours(2), Outcome::Unknown),
        ] {
            for parent_in_use in [false, true] {
                let mut detector = RegretDetector::new(window);
                detector.watch(watch("delayed", Path::new("/p/target"), "rust_target", t0));
                let outcomes = detector.check(t0 + age, |_| Sighting::Recreated { parent_in_use });
                assert_eq!(outcomes.len(), 1);
                let expected = if parent_in_use {
                    active_outcome
                } else {
                    Outcome::Unknown
                };
                assert_eq!(
                    outcomes[0].outcome, expected,
                    "age={age:?}, parent_in_use={parent_in_use}"
                );
                assert_eq!(detector.pending(), 0);
            }
        }
    }

    #[test]
    fn slow_observations_use_each_completion_time_instead_of_the_sweep_start() {
        use std::cell::Cell;

        let t0 = Instant::now();
        let clock = Cell::new(t0 + Duration::from_secs(59));
        let clock_reads = Cell::new(0);
        let mut detector = RegretDetector::new(Duration::from_secs(60));
        for id in ["first", "later", "uncertain"] {
            detector.watch(watch(id, Path::new("/p/target"), "rust_target", t0));
        }
        let outcomes = detector.check_with_clock(
            || {
                clock_reads.set(clock_reads.get() + 1);
                clock.get()
            },
            |watched| {
                // The first observation alone crosses the deadline. Every
                // subsequent lookup must get its own completion timestamp.
                clock.set(clock.get() + Duration::from_secs(2));
                if watched.decision_id == "uncertain" {
                    Sighting::Indeterminate
                } else {
                    Sighting::Recreated {
                        parent_in_use: true,
                    }
                }
            },
        );
        assert_eq!(clock_reads.get(), 6);
        assert_eq!(outcomes.len(), 3);
        for (outcome, after_secs) in outcomes.iter().zip([61, 63, 65]) {
            assert_eq!(outcome.outcome, Outcome::Unknown, "{}", outcome.decision_id);
            assert_eq!(outcome.after_secs, after_secs);
        }
        assert_eq!(detector.pending(), 0);
    }

    #[test]
    fn an_absent_observation_crossing_expiry_waits_for_a_fresh_lookup() {
        use std::cell::Cell;

        let t0 = Instant::now();
        let clock = Cell::new(t0 + Duration::from_secs(59));
        let mut detector = RegretDetector::new(Duration::from_secs(60));
        detector.watch(watch("absent", Path::new("/p/target"), "rust_target", t0));
        let crossing = detector.check_with_clock(
            || clock.get(),
            |_| {
                clock.set(clock.get() + Duration::from_secs(2));
                Sighting::Absent
            },
        );
        assert!(
            crossing.is_empty(),
            "absence may have been seen before expiry"
        );
        assert_eq!(detector.pending(), 1);

        let after = detector.check_with_clock(
            || clock.get(),
            |_| {
                clock.set(clock.get() + Duration::from_secs(2));
                Sighting::Absent
            },
        );
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].outcome, Outcome::Clean);
        assert_eq!(after[0].after_secs, 63);
        assert_eq!(detector.pending(), 0);
    }

    #[test]
    fn detector_absence_remains_pending_before_expiry_and_clean_afterwards() {
        let t0 = Instant::now();
        let window = Duration::from_secs(60);
        let mut detector = RegretDetector::new(window);
        for id in ["at-deadline", "after-deadline"] {
            detector.watch(watch(id, Path::new("/p/target"), "rust_target", t0));
        }
        let before = detector.check(
            (t0 + window).checked_sub(Duration::from_nanos(1)).unwrap(),
            |_| Sighting::Absent,
        );
        assert!(before.is_empty());
        assert_eq!(detector.pending(), 2);

        let at = detector.check(t0 + window, |w| {
            if w.decision_id == "after-deadline" {
                Sighting::Recreated {
                    parent_in_use: false,
                }
            } else {
                Sighting::Absent
            }
        });
        assert_eq!(at.len(), 2);
        let clean = at.iter().find(|o| o.decision_id == "at-deadline").unwrap();
        assert_eq!(clean.outcome, Outcome::Clean);
        assert_eq!(detector.pending(), 0);

        detector.watch(watch(
            "late-absence",
            Path::new("/p/target"),
            "rust_target",
            t0,
        ));
        let after = detector.check(t0 + window + Duration::from_secs(1), |_| Sighting::Absent);
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].outcome, Outcome::Clean);
    }

    #[test]
    fn late_recreations_do_not_change_calibration_or_suspension() {
        let t0 = Instant::now();
        for prior_regrets in [0, 3] {
            let mut detector = RegretDetector::new(Duration::from_secs(60));
            let mut calibrator = RegretCalibrator::new(RegretConfig::default());
            calibrator.record(
                "rust_target",
                ArtifactCertainty::Definite,
                Outcome::Clean,
                t0,
            );
            for _ in 0..prior_regrets {
                calibrator.record(
                    "rust_target",
                    ArtifactCertainty::Definite,
                    Outcome::Regret,
                    t0,
                );
            }
            let before = calibrator.summary("rust_target").unwrap();
            for id in ["late-a", "late-b", "late-c"] {
                detector.watch(watch(id, Path::new("/p/target"), "rust_target", t0));
            }
            let now = t0 + Duration::from_secs(60);
            let outcomes = detector.check(now, |_| Sighting::Recreated {
                parent_in_use: true,
            });
            assert_eq!(outcomes.len(), 3);
            for outcome in outcomes {
                assert_eq!(outcome.outcome, Outcome::Unknown);
                calibrator.record(
                    &outcome.category,
                    certainty_from_name(&outcome.certainty),
                    outcome.outcome,
                    now,
                );
            }
            assert_eq!(calibrator.summary("rust_target").unwrap(), before);
            assert_eq!(calibrator.suspended("rust_target", now), prior_regrets > 0);
        }
    }

    #[test]
    fn indeterminate_observations_expire_unknown_without_changing_calibration() {
        let t0 = Instant::now();
        let window = Duration::from_secs(60);
        for prior_regrets in [0, 3] {
            let mut detector = RegretDetector::new(window);
            let mut calibrator = RegretCalibrator::new(RegretConfig::default());
            calibrator.record(
                "rust_target",
                ArtifactCertainty::Definite,
                Outcome::Clean,
                t0,
            );
            for _ in 0..prior_regrets {
                calibrator.record(
                    "rust_target",
                    ArtifactCertainty::Definite,
                    Outcome::Regret,
                    t0,
                );
            }
            let before = calibrator.summary("rust_target").unwrap();
            detector.watch(watch(
                "unreadable",
                Path::new("/p/target"),
                "rust_target",
                t0,
            ));
            for age in [
                Duration::ZERO,
                window.checked_sub(Duration::from_nanos(1)).unwrap(),
            ] {
                assert!(
                    detector
                        .check(t0 + age, |_| Sighting::Indeterminate)
                        .is_empty()
                );
                assert_eq!(detector.pending(), 1);
            }
            let now = t0 + window;
            let outcomes = detector.check(now, |_| Sighting::Indeterminate);
            assert_eq!(outcomes.len(), 1);
            assert_eq!(outcomes[0].outcome, Outcome::Unknown);
            calibrator.record(
                &outcomes[0].category,
                certainty_from_name(&outcomes[0].certainty),
                outcomes[0].outcome,
                now,
            );
            assert_eq!(calibrator.summary("rust_target").unwrap(), before);
            assert_eq!(calibrator.suspended("rust_target", now), prior_regrets > 0);
            assert_eq!(detector.pending(), 0);
        }
    }

    #[test]
    fn a_reliable_observation_can_resolve_a_previously_indeterminate_watch() {
        let t0 = Instant::now();
        let window = Duration::from_secs(60);
        for (sighting, at, expected) in [
            (Sighting::Absent, t0 + window, Outcome::Clean),
            (
                Sighting::Recreated {
                    parent_in_use: true,
                },
                t0 + Duration::from_secs(30),
                Outcome::Regret,
            ),
        ] {
            let mut detector = RegretDetector::new(window);
            detector.watch(watch("retry", Path::new("/p/target"), "rust_target", t0));
            assert!(detector.check(t0, |_| Sighting::Indeterminate).is_empty());
            let outcomes = detector.check(at, |_| sighting);
            assert_eq!(outcomes.len(), 1);
            assert_eq!(outcomes[0].outcome, expected);
            assert_eq!(detector.pending(), 0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn failed_entry_lookups_do_not_become_absence_or_query_processes() {
        use std::io::ErrorKind;

        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::NotADirectory,
            ErrorKind::Interrupted,
            ErrorKind::Other,
        ] {
            let sighting = Sighting::from_entry_lookup(Err(kind.into()), || {
                panic!("failed lookup must not query processes")
            });
            assert_eq!(sighting, Sighting::Indeterminate, "{kind:?}");
        }
        let absent = Sighting::from_entry_lookup(Err(ErrorKind::NotFound.into()), || {
            panic!("absent entry must not query processes")
        });
        assert_eq!(absent, Sighting::Absent);
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_observation_verifies_absence_recreation_and_parent_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("project");
        let target = parent.join("target");
        std::fs::create_dir(&parent).unwrap();
        let mut watched = watch("deleted", &target, "rust_target", Instant::now());
        watched.identity = EntryIdentity::of(&target).unwrap();
        assert_eq!(
            watched.observe(|_| panic!("absent entry must not query processes")),
            Sighting::Absent
        );

        std::fs::create_dir(&target).unwrap();
        for parent_in_use in [false, true] {
            assert_eq!(
                watched.observe(|observed_parent| {
                    assert_eq!(observed_parent, parent);
                    parent_in_use
                }),
                Sighting::Recreated { parent_in_use }
            );
        }

        std::fs::rename(&parent, dir.path().join("original-project")).unwrap();
        assert_eq!(watched.observe(|_| true), Sighting::Indeterminate);
        std::fs::create_dir(&parent).unwrap();
        assert_eq!(watched.observe(|_| true), Sighting::Indeterminate);
        std::fs::create_dir(&target).unwrap();
        assert_eq!(watched.observe(|_| true), Sighting::Indeterminate);
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_observation_rechecks_parent_after_process_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("project");
        let target = parent.join("target");
        std::fs::create_dir_all(&target).unwrap();
        let mut watched = watch("deleted", &target, "rust_target", Instant::now());
        watched.identity = EntryIdentity::of(&target).unwrap();
        let observation = watched.observe(|_| {
            std::fs::rename(&parent, dir.path().join("original-project")).unwrap();
            std::fs::create_dir_all(&target).unwrap();
            true
        });
        assert_eq!(observation, Sighting::Indeterminate);
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_observation_accepts_stable_parent_aliases_but_not_retargeting() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("original");
        let replacement = dir.path().join("replacement");
        let alias = dir.path().join("alias");
        std::fs::create_dir(&original).unwrap();
        std::fs::create_dir(&replacement).unwrap();
        std::os::unix::fs::symlink(&original, &alias).unwrap();
        let target = alias.join("target");
        let mut watched = watch("deleted", &target, "rust_target", Instant::now());
        watched.identity = EntryIdentity::of(&target).unwrap();
        assert_eq!(watched.observe(|_| true), Sighting::Absent);
        std::fs::create_dir(&target).unwrap();
        assert_eq!(
            watched.observe(|_| true),
            Sighting::Recreated {
                parent_in_use: true
            }
        );

        std::fs::rename(&alias, dir.path().join("previous-alias")).unwrap();
        std::os::unix::fs::symlink(&replacement, &alias).unwrap();
        assert_eq!(watched.observe(|_| true), Sighting::Indeterminate);
        std::fs::create_dir(&target).unwrap();
        assert_eq!(watched.observe(|_| true), Sighting::Indeterminate);
    }

    #[test]
    fn entry_identity_survives_recreation_of_the_entry() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let before = EntryIdentity::of(&target).unwrap();
        std::fs::remove_dir(&target).unwrap();
        std::fs::create_dir(&target).unwrap();
        let after = EntryIdentity::of(&target).unwrap();
        assert_eq!(before, after);
        assert_eq!(before.name, "target");
        assert!(EntryIdentity::of(Path::new("/")).is_none());
    }
}
