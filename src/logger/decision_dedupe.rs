//! Evidence-ledger dedupe (bd-jl92).
//!
//! The daemon re-evaluates every candidate on every scan pass, and each
//! verdict used to be written in full (~2.5 KB of JSON, SQLite plus JSONL).
//! An unchanged kept path was recorded ~15 times a day: on one host 1.5M
//! `decision_log` rows for 153k paths, 6.3 GB inside the 30-day retention.
//! Once the daemon stopped sending kept candidates to the policy engine, the
//! same happened to Delete verdicts that later executor gates (planner budget,
//! certainty, pressure confirmation, open files) held back: on fmd one
//! `node_modules` was recorded 56 times in a day before it was deleted, 45k
//! rows a day in all, which held its database at the size cap.
//!
//! Every verdict is now recorded once per artifact version and verdict, and
//! again only after [`DECISION_REFRESH`], so `sbh explain` keeps finding a
//! current record. A changed verdict or a changed artifact (the stable id
//! covers path, device, inode and size) is always recorded. The verdict the
//! executor carries out is recorded again when it runs (see
//! [`DecisionDedupe::should_record_executed`]), so every deletion's evidence
//! is the evidence it was executed on.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant, SystemTime};

use crate::scanner::decision_record::DecisionRecord;

/// How long an unchanged verdict for one artifact version is not recorded
/// again.
pub const DECISION_REFRESH: Duration = Duration::from_hours(24);

/// Artifacts remembered in memory at most. Overflow observations consult the
/// indexed persisted ledger; live cache entries are never cleared for admission.
const MAX_REMEMBERED: usize = 1 << 18;
/// A full cache is swept at most once a minute, not once per overflow artifact.
const CACHE_PRUNE_INTERVAL: Duration = Duration::from_mins(1);

/// Remembers the last acknowledged verdict per artifact version.
#[derive(Debug)]
pub struct DecisionDedupe {
    /// Artifact key -> (verdict key, when acknowledged, that record's
    /// per-run `decision_id`).
    last: HashMap<u64, (u64, Instant, u64)>,
    capacity: usize,
    overflowed: bool,
    last_prune: Option<Instant>,
    /// Only rows after this decision_log ID may satisfy an overflow lookup.
    persisted_after: i64,
    /// Startup, recovery and a failed write require a new successful insert
    /// before any persisted record can suppress an observation.
    persisted_lookup_blocked: bool,
}

impl Default for DecisionDedupe {
    fn default() -> Self {
        Self {
            last: HashMap::new(),
            capacity: MAX_REMEMBERED,
            overflowed: false,
            last_prune: None,
            persisted_after: 0,
            persisted_lookup_blocked: true,
        }
    }
}

impl DecisionDedupe {
    /// Check overflow observations against the newest persisted row for their
    /// path. The lookup must be read-only and return None on unavailable or
    /// malformed evidence. Cached observations need no database query.
    ///
    /// Execution events deliberately do not use this path: a per-run numeric
    /// decision ID from a previous daemon must never suppress execution evidence.
    pub fn should_record_with_history(
        &mut self,
        record: &DecisionRecord,
        now: Instant,
        wall_time: SystemTime,
        lookup: impl FnOnce() -> Option<(i64, DecisionRecord)>,
    ) -> bool {
        if self.overflowed
            && !self.persisted_lookup_blocked
            && !self.last.contains_key(&artifact_key(record))
            && let Some((row_id, persisted)) = lookup()
            && row_id > self.persisted_after
            && persisted.id == record.id
            && persisted.path == record.path
            && verdict_key(&persisted) == verdict_key(record)
            && chrono::DateTime::parse_from_rfc3339(&persisted.timestamp)
                .ok()
                .and_then(|timestamp| wall_time.duration_since(SystemTime::from(timestamp)).ok())
                .is_some_and(|age| age < DECISION_REFRESH)
        {
            return false;
        }
        self.should_record(record, now)
    }

    /// Fence off older persisted verdicts after a write failure. Otherwise a
    /// changed verdict written only to JSONL could make its previous SQLite row
    /// incorrectly suppress the next retry. Unaffected cached entries stay valid.
    pub fn persistence_failed(&mut self) {
        self.persisted_lookup_blocked = true;
    }

    /// Acknowledge the exact decision_log insert, including its row ID.
    /// After a failure this conservatively makes older overflow rows repeat once;
    /// no per-artifact failure set can grow beyond the cache's memory bound.
    pub fn acknowledge_persisted(&mut self, record: &DecisionRecord, now: Instant, row_id: i64) {
        if self.persisted_lookup_blocked {
            self.persisted_after = self.persisted_after.max(row_id.saturating_sub(1));
            self.persisted_lookup_blocked = false;
        }
        self.acknowledge(record, now);
    }

    /// Exercise the production admission path with a small memory bound.
    #[cfg(test)]
    pub(crate) fn with_capacity_for_test(capacity: usize) -> Self {
        Self {
            capacity,
            ..Self::default()
        }
    }

    /// Whether `record` must be written to the evidence ledger at `now`.
    /// Admission invalidates the previous verdict; only `acknowledge` can
    /// suppress later observations after a successful persistence attempt.
    pub fn should_record(&mut self, record: &DecisionRecord, now: Instant) -> bool {
        let artifact = artifact_key(record);
        if let Some((seen, at, _)) = self.last.get(&artifact)
            && *seen == verdict_key(record)
            && now
                .checked_duration_since(*at)
                .is_some_and(|age| age < DECISION_REFRESH)
        {
            return false;
        }
        // An intervening decision may reach JSONL even if SQLite fails.
        // It must not leave an older acknowledged verdict suppressing retries.
        self.last.remove(&artifact);
        true
    }

    /// Whether the verdict the executor just carried out must be written.
    /// Always, unless this very record (same per-run `decision_id`) is the
    /// one already acknowledged for the artifact: a verdict executed on the
    /// pass that first recorded it needs no second row, while one held back
    /// for passes whose repeats were skipped gets its execution-time evidence.
    pub fn should_record_executed(&mut self, record: &DecisionRecord) -> bool {
        let artifact = artifact_key(record);
        if let Some((seen, _, decision_id)) = self.last.get(&artifact)
            && *decision_id == record.decision_id
            && *seen == verdict_key(record)
        {
            return false;
        }
        self.last.remove(&artifact);
        true
    }

    /// Remember a decision only after the caller confirms its SQLite write.
    /// Buffered JSONL output and producer admission are not acknowledgements.
    pub fn acknowledge(&mut self, record: &DecisionRecord, now: Instant) {
        let artifact = artifact_key(record);
        if self.last.len() >= self.capacity
            && !self.last.contains_key(&artifact)
            && self
                .last_prune
                .is_none_or(|at| now.saturating_duration_since(at) >= CACHE_PRUNE_INTERVAL)
        {
            self.last_prune = Some(now);
            self.last.retain(|_, (_, at, _)| {
                now.checked_duration_since(*at)
                    .is_some_and(|age| age < DECISION_REFRESH)
            });
        }
        if self.last.len() < self.capacity || self.last.contains_key(&artifact) {
            self.last
                .insert(artifact, (verdict_key(record), now, record.decision_id));
        } else {
            self.overflowed = true;
        }
    }

    /// Artifacts currently remembered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.last.len()
    }

    /// Whether nothing is remembered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.last.is_empty()
    }
}

/// The artifact version: the stable decision id (path, device, inode, size),
/// or the path for records written before stable ids.
fn artifact_key(record: &DecisionRecord) -> u64 {
    let mut hasher = DefaultHasher::new();
    if record.id.is_empty() {
        record.path.hash(&mut hasher);
    } else {
        record.id.hash(&mut hasher);
    }
    hasher.finish()
}

/// What the ledger would say about it: the verdict and why.
fn verdict_key(record: &DecisionRecord) -> u64 {
    let mut hasher = DefaultHasher::new();
    format!(
        "{:?}|{:?}|{}|{:?}|{:?}|{}|{}|{:?}",
        record.action,
        record.effective_action,
        record.vetoed,
        record.veto_reason,
        record.policy_mode,
        record.fallback_active,
        record.category_suspended,
        record.comparator_action
    )
    .hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::decision_record::{ActionRecord, PolicyMode, sample_record_for_tests};
    use crate::scanner::scoring::DecisionAction;

    fn record(id: &str, effective: Option<DecisionAction>, mode: PolicyMode) -> DecisionRecord {
        let mut record = sample_record_for_tests(mode, effective);
        record.id = id.to_string();
        record
    }

    fn kept(id: &str) -> DecisionRecord {
        record(id, Some(DecisionAction::Keep), PolicyMode::Live)
    }

    #[test]
    fn a_full_cache_keeps_live_entries_and_bounds_expiry_sweeps() {
        let mut dedupe = DecisionDedupe::with_capacity_for_test(4);
        let now = Instant::now();
        for index in 0..4 {
            dedupe.acknowledge(&kept(&format!("{index:012x}")), now);
        }
        for index in 4..12 {
            dedupe.acknowledge(
                &kept(&format!("{index:012x}")),
                now + Duration::from_secs(index - 4),
            );
            assert_eq!(dedupe.len(), 4);
            assert_eq!(dedupe.last_prune, Some(now));
        }
        assert!(dedupe.overflowed);
        assert!(!dedupe.should_record(&kept("000000000000"), now));
        dedupe.acknowledge(&kept("ffffffffffff"), now + CACHE_PRUNE_INTERVAL);
        assert_eq!(dedupe.last_prune, Some(now + CACHE_PRUNE_INTERVAL));
        assert_eq!(dedupe.len(), 4);
        dedupe.acknowledge(&kept("eeeeeeeeeeee"), now + DECISION_REFRESH);
        assert_eq!(dedupe.len(), 1, "expired slots can be reused");
    }

    #[test]
    fn overflow_history_requires_current_matching_acknowledged_evidence() {
        let mut dedupe = DecisionDedupe::with_capacity_for_test(1);
        let now = Instant::now();
        let wall = SystemTime::now();
        let stamp = |time: SystemTime| {
            chrono::DateTime::<chrono::Utc>::from(time)
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        };
        let resident = kept("aaaaaaaaaaaa");
        let mut overflow = kept("bbbbbbbbbbbb");
        overflow.timestamp = stamp(wall);
        dedupe.acknowledge_persisted(&resident, now, 1);
        dedupe.acknowledge_persisted(&overflow, now, 2);
        assert!(
            !dedupe.should_record_with_history(&resident, now, wall, || {
                panic!("resident decisions must not read SQLite")
            })
        );
        assert!(
            !dedupe.should_record_with_history(&overflow, now, wall, || {
                Some((2, overflow.clone()))
            })
        );

        let mut stale = overflow.clone();
        stale.timestamp = stamp(wall - DECISION_REFRESH);
        let mut future = overflow.clone();
        future.timestamp = stamp(wall + Duration::from_secs(1));
        let mut invalid = overflow.clone();
        invalid.timestamp = "invalid".to_string();
        let mut replaced = overflow.clone();
        replaced.id = "cccccccccccc".to_string();
        let mut other_path = overflow.clone();
        other_path.path = other_path.path.join("other");
        let mut changed = overflow.clone();
        changed.effective_action = Some(ActionRecord::Review);
        for evidence in [stale, future, invalid, replaced, other_path, changed] {
            assert!(
                dedupe.should_record_with_history(&overflow, now, wall, || { Some((2, evidence)) })
            );
        }
        dedupe.persistence_failed();
        assert!(dedupe.should_record_with_history(&overflow, now, wall, || {
            panic!("failed persistence must block overflow reads")
        }));
    }

    /// The bead's acceptance: re-evaluating an unchanged kept artifact N times
    /// within the refresh writes one record, and the refresh writes it again.
    #[test]
    fn an_unchanged_kept_artifact_is_recorded_once_per_refresh() {
        let mut dedupe = DecisionDedupe::default();
        let t0 = Instant::now();
        let kept = kept("aaaaaaaaaaaa");
        assert!(dedupe.should_record(&kept, t0));
        dedupe.acknowledge(&kept, t0);
        // Every 10 minutes for most of a day: nothing new to say.
        let repeats = (1..=140)
            .filter(|i| dedupe.should_record(&kept, t0 + Duration::from_mins(i * 10)))
            .count();
        assert_eq!(repeats, 0);
        assert!(dedupe.should_record(&kept, t0 + DECISION_REFRESH));
        dedupe.acknowledge(&kept, t0 + DECISION_REFRESH);
        assert!(!dedupe.should_record(&kept, t0 + DECISION_REFRESH + Duration::from_mins(10)));
    }

    /// A changed verdict is news: review, a veto, a policy mode change.
    #[test]
    fn a_changed_verdict_is_always_recorded() {
        let mut dedupe = DecisionDedupe::default();
        let t0 = Instant::now();
        let id = "bbbbbbbbbbbb";
        assert!(dedupe.should_record(&kept(id), t0));
        dedupe.acknowledge(&kept(id), t0);
        let review = record(id, Some(DecisionAction::Review), PolicyMode::Live);
        assert!(dedupe.should_record(&review, t0 + Duration::from_secs(1)));
        dedupe.acknowledge(&review, t0 + Duration::from_secs(1));
        assert!(!dedupe.should_record(&review, t0 + Duration::from_secs(2)));
        let mut vetoed = kept(id);
        vetoed.vetoed = true;
        vetoed.veto_reason = Some("open file".to_string());
        assert!(dedupe.should_record(&vetoed, t0 + Duration::from_secs(3)));
        dedupe.acknowledge(&vetoed, t0 + Duration::from_secs(3));
        let shadow = record(id, Some(DecisionAction::Keep), PolicyMode::Shadow);
        assert!(dedupe.should_record(&shadow, t0 + Duration::from_secs(4)));
        dedupe.acknowledge(&shadow, t0 + Duration::from_secs(4));
        // Back to the first verdict: it differs from the last one recorded.
        assert!(dedupe.should_record(&kept(id), t0 + Duration::from_secs(5)));
    }

    #[test]
    fn failed_attempts_never_suppress_retries_or_restore_an_older_verdict() {
        let mut dedupe = DecisionDedupe::default();
        let now = Instant::now();
        let kept = kept("aaaaaaaaaaaa");
        assert!(dedupe.should_record(&kept, now));
        assert!(dedupe.should_record(&kept, now));
        assert!(dedupe.is_empty());
        dedupe.acknowledge(&kept, now);
        assert!(!dedupe.should_record(&kept, now));

        let review = record(
            "aaaaaaaaaaaa",
            Some(DecisionAction::Review),
            PolicyMode::Live,
        );
        assert!(dedupe.should_record(&review, now));
        // The changed attempt failed to persist: returning to the old KEEP
        // still needs a record, even if the failed attempt reached JSONL.
        assert!(dedupe.should_record(&kept, now));
        dedupe.acknowledge(&kept, now);
        let delete = record(
            "aaaaaaaaaaaa",
            Some(DecisionAction::Delete),
            PolicyMode::Live,
        );
        assert!(dedupe.should_record(&delete, now));
        dedupe.acknowledge(&delete, now);
        assert!(dedupe.should_record(&kept, now));
    }

    #[test]
    fn changed_fallback_and_comparator_verdicts_are_recorded() {
        let now = Instant::now();
        let kept = kept("bbbbbbbbbbbb");
        let mut fallback = kept.clone();
        fallback.fallback_active = !kept.fallback_active;
        let mut suspended = kept.clone();
        suspended.category_suspended = !kept.category_suspended;
        let mut comparator = kept.clone();
        comparator.comparator_action = if kept.comparator_action == Some(ActionRecord::Review) {
            Some(ActionRecord::Keep)
        } else {
            Some(ActionRecord::Review)
        };
        for changed in [fallback, suspended, comparator] {
            let mut dedupe = DecisionDedupe::default();
            dedupe.acknowledge(&kept, now);
            assert!(dedupe.should_record(&changed, now));
            dedupe.acknowledge(&changed, now);
            assert!(!dedupe.should_record(&changed, now));
        }
        let mut rescored = kept.clone();
        rescored.age_secs += 60;
        rescored.total_score += 0.01;
        rescored.calibration_score += 0.01;
        let mut dedupe = DecisionDedupe::default();
        dedupe.acknowledge(&kept, now);
        assert!(!dedupe.should_record(&rescored, now));
    }

    /// A Delete verdict that later executor gates hold back is re-evaluated
    /// on every pass too: one record per refresh, like any other verdict. A
    /// new artifact version (another stable id) or a record without one is
    /// judged on its own.
    #[test]
    fn repeated_delete_verdicts_and_new_artifacts() {
        let mut dedupe = DecisionDedupe::default();
        let t0 = Instant::now();
        let delete = record(
            "cccccccccccc",
            Some(DecisionAction::Delete),
            PolicyMode::Live,
        );
        assert!(dedupe.should_record(&delete, t0));
        dedupe.acknowledge(&delete, t0);
        // fmd: 56 passes in a day before the planner chose it.
        let repeats = (1..=56)
            .filter(|i| dedupe.should_record(&delete, t0 + Duration::from_mins(i * 25)))
            .count();
        assert_eq!(repeats, 0);
        assert!(dedupe.should_record(&delete, t0 + DECISION_REFRESH));
        let mut legacy_delete = kept("dddddddddddd");
        legacy_delete.effective_action = None;
        legacy_delete.action = ActionRecord::Delete;
        assert!(dedupe.should_record(&legacy_delete, t0));
        dedupe.acknowledge(&legacy_delete, t0);
        assert!(!dedupe.should_record(&legacy_delete, t0 + Duration::from_secs(1)));
        // Vetoing a held Delete is a changed verdict.
        let mut vetoed = delete.clone();
        vetoed.vetoed = true;
        vetoed.veto_reason = Some("open file".to_string());
        assert!(dedupe.should_record(&vetoed, t0 + Duration::from_secs(2)));

        assert!(dedupe.should_record(&kept("eeeeeeeeeeee"), t0));
        dedupe.acknowledge(&kept("eeeeeeeeeeee"), t0);
        assert!(dedupe.should_record(&kept("ffffffffffff"), t0));
        dedupe.acknowledge(&kept("ffffffffffff"), t0);
        let mut unversioned = kept("");
        assert!(dedupe.should_record(&unversioned, t0));
        dedupe.acknowledge(&unversioned, t0);
        assert!(!dedupe.should_record(&unversioned, t0 + Duration::from_secs(1)));
        unversioned.path = unversioned.path.join("other");
        assert!(dedupe.should_record(&unversioned, t0 + Duration::from_secs(2)));
    }

    /// The executed verdict is the deletion's evidence: written at execution
    /// unless the executor carried out the very record already written.
    #[test]
    fn an_executed_verdict_is_recorded_unless_that_record_already_was() {
        let t0 = Instant::now();
        let at_pass = |n: u64| {
            let mut delete = record(
                "abababababab",
                Some(DecisionAction::Delete),
                PolicyMode::Live,
            );
            delete.decision_id = n;
            delete
        };

        // Recorded on pass 1, executed on pass 1: one row.
        let mut dedupe = DecisionDedupe::default();
        assert!(dedupe.should_record(&at_pass(1), t0));
        dedupe.acknowledge(&at_pass(1), t0);
        assert!(!dedupe.should_record_executed(&at_pass(1)));

        // Recorded on pass 1, held, executed on pass 4: the pass-4 record.
        let mut dedupe = DecisionDedupe::default();
        dedupe.acknowledge(&at_pass(1), t0);
        for n in 2..=4 {
            assert!(!dedupe.should_record(&at_pass(n), t0 + Duration::from_mins(n * 25)));
        }
        assert!(dedupe.should_record_executed(&at_pass(4)));
        dedupe.acknowledge(&at_pass(4), t0 + Duration::from_mins(100));
        assert!(!dedupe.should_record_executed(&at_pass(4)));

        // Never acknowledged (the SQLite write failed): written.
        let mut dedupe = DecisionDedupe::default();
        assert!(dedupe.should_record(&at_pass(7), t0));
        assert!(dedupe.should_record_executed(&at_pass(7)));

        // Same per-run id but a different verdict on record: written.
        let mut dedupe = DecisionDedupe::default();
        let mut shadow = at_pass(9);
        shadow.policy_mode = PolicyMode::Shadow;
        dedupe.acknowledge(&shadow, t0);
        assert!(dedupe.should_record_executed(&at_pass(9)));
    }
}
