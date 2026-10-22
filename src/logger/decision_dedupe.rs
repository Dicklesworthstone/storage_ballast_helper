//! Evidence-ledger dedupe (bd-jl92).
//!
//! The daemon re-evaluates every candidate on every scan pass, and each
//! verdict used to be written in full (~2.5 KB of JSON, SQLite plus JSONL).
//! An unchanged kept path was recorded ~15 times a day: on one host 1.5M
//! `decision_log` rows for 153k paths, 6.3 GB inside the 30-day retention.
//!
//! A verdict that cannot delete anything (effective Keep or Review, or a veto)
//! is now recorded once per artifact version and verdict, and again only
//! after [`DECISION_REFRESH`], so `sbh explain` keeps finding a current
//! record. A changed verdict, a changed artifact (the stable id covers path,
//! device, inode and size) and every decision that may delete are always
//! recorded: the deletion audit trail is unconditional.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

use crate::scanner::decision_record::{ActionRecord, DecisionRecord};

/// How long an unchanged non-deleting verdict for one artifact version is
/// not recorded again.
pub const DECISION_REFRESH: Duration = Duration::from_hours(24);

/// Artifacts remembered at most. Past it, entries older than the refresh are
/// dropped first, then everything: the cost is one repeated record each.
const MAX_REMEMBERED: usize = 1 << 18;

/// Remembers the last recorded verdict per artifact version.
#[derive(Debug, Default)]
pub struct DecisionDedupe {
    last: HashMap<u64, (u64, Instant)>,
}

impl DecisionDedupe {
    /// Whether `record` must be written to the evidence ledger at `now`.
    pub fn should_record(&mut self, record: &DecisionRecord, now: Instant) -> bool {
        if may_delete(record) {
            return true;
        }
        let artifact = artifact_key(record);
        let verdict = verdict_key(record);
        if let Some((seen, at)) = self.last.get(&artifact)
            && *seen == verdict
            && now
                .checked_duration_since(*at)
                .is_some_and(|age| age < DECISION_REFRESH)
        {
            return false;
        }
        if self.last.len() >= MAX_REMEMBERED {
            self.last.retain(|_, (_, at)| {
                now.checked_duration_since(*at)
                    .is_some_and(|age| age < DECISION_REFRESH)
            });
            if self.last.len() >= MAX_REMEMBERED {
                self.last.clear();
            }
        }
        self.last.insert(artifact, (verdict, now));
        true
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

/// A decision that may delete: an effective Delete, or a Delete with no
/// effective action recorded (older producers), unless vetoed.
fn may_delete(record: &DecisionRecord) -> bool {
    if record.vetoed {
        return false;
    }
    record.effective_action.unwrap_or(record.action) == ActionRecord::Delete
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
        "{:?}|{:?}|{}|{:?}|{:?}",
        record.action,
        record.effective_action,
        record.vetoed,
        record.veto_reason,
        record.policy_mode
    )
    .hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::decision_record::{PolicyMode, sample_record_for_tests};
    use crate::scanner::scoring::DecisionAction;

    fn record(id: &str, effective: Option<DecisionAction>, mode: PolicyMode) -> DecisionRecord {
        let mut record = sample_record_for_tests(mode, effective);
        record.id = id.to_string();
        record
    }

    fn kept(id: &str) -> DecisionRecord {
        record(id, Some(DecisionAction::Keep), PolicyMode::Live)
    }

    /// The bead's acceptance: re-evaluating an unchanged kept artifact N times
    /// within the refresh writes one record, and the refresh writes it again.
    #[test]
    fn an_unchanged_kept_artifact_is_recorded_once_per_refresh() {
        let mut dedupe = DecisionDedupe::default();
        let t0 = Instant::now();
        let kept = kept("aaaaaaaaaaaa");
        assert!(dedupe.should_record(&kept, t0));
        // Every 10 minutes for most of a day: nothing new to say.
        let repeats = (1..=140)
            .filter(|i| dedupe.should_record(&kept, t0 + Duration::from_mins(i * 10)))
            .count();
        assert_eq!(repeats, 0);
        assert!(dedupe.should_record(&kept, t0 + DECISION_REFRESH));
        assert!(!dedupe.should_record(&kept, t0 + DECISION_REFRESH + Duration::from_mins(10)));
    }

    /// A changed verdict is news: review, a veto, a policy mode change.
    #[test]
    fn a_changed_verdict_is_always_recorded() {
        let mut dedupe = DecisionDedupe::default();
        let t0 = Instant::now();
        let id = "bbbbbbbbbbbb";
        assert!(dedupe.should_record(&kept(id), t0));
        let review = record(id, Some(DecisionAction::Review), PolicyMode::Live);
        assert!(dedupe.should_record(&review, t0 + Duration::from_secs(1)));
        assert!(!dedupe.should_record(&review, t0 + Duration::from_secs(2)));
        let mut vetoed = kept(id);
        vetoed.vetoed = true;
        vetoed.veto_reason = Some("open file".to_string());
        assert!(dedupe.should_record(&vetoed, t0 + Duration::from_secs(3)));
        let shadow = record(id, Some(DecisionAction::Keep), PolicyMode::Shadow);
        assert!(dedupe.should_record(&shadow, t0 + Duration::from_secs(4)));
        // Back to the first verdict: it differs from the last one recorded.
        assert!(dedupe.should_record(&kept(id), t0 + Duration::from_secs(5)));
    }

    /// The deletion audit trail is unconditional, and a new artifact version
    /// (another stable id) or a record without one is judged on its own.
    #[test]
    fn deletes_and_new_artifacts_are_always_recorded() {
        let mut dedupe = DecisionDedupe::default();
        let t0 = Instant::now();
        let delete = record(
            "cccccccccccc",
            Some(DecisionAction::Delete),
            PolicyMode::Live,
        );
        for i in 0..3 {
            assert!(dedupe.should_record(&delete, t0 + Duration::from_secs(i)));
        }
        let mut legacy_delete = kept("dddddddddddd");
        legacy_delete.effective_action = None;
        legacy_delete.action = ActionRecord::Delete;
        assert!(dedupe.should_record(&legacy_delete, t0));
        assert!(dedupe.should_record(&legacy_delete, t0 + Duration::from_secs(1)));

        assert!(dedupe.should_record(&kept("eeeeeeeeeeee"), t0));
        assert!(dedupe.should_record(&kept("ffffffffffff"), t0));
        let mut unversioned = kept("");
        assert!(dedupe.should_record(&unversioned, t0));
        assert!(!dedupe.should_record(&unversioned, t0 + Duration::from_secs(1)));
        unversioned.path = unversioned.path.join("other");
        assert!(dedupe.should_record(&unversioned, t0 + Duration::from_secs(2)));
    }
}
