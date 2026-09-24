//! Bounded, deterministic selection of replay hints, never deletion authority.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use super::{CandidateIndexRecord, CandidateSafetyState};

/// Best records compare smallest, so the heap exposes the worst retained
/// record. A full sort and the bounded selection have exactly the same order.
fn compare(a: &CandidateIndexRecord, b: &CandidateIndexRecord) -> Ordering {
    b.score
        .unwrap_or(f64::NEG_INFINITY)
        .total_cmp(&a.score.unwrap_or(f64::NEG_INFINITY))
        .then_with(|| b.size_estimate_bytes.cmp(&a.size_estimate_bytes))
        .then_with(|| a.path.cmp(&b.path))
        .then_with(|| a.identity.cmp(&b.identity))
}

struct RankedRecord<'a>(&'a CandidateIndexRecord);

impl PartialEq for RankedRecord<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for RankedRecord<'_> {}

impl PartialOrd for RankedRecord<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RankedRecord<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        compare(self.0, other.0)
    }
}

fn eligible(record: &CandidateIndexRecord, generation: u64, now_nanos: u128) -> bool {
    record.event_generation == generation
        && matches!(
            record.safety_state,
            CandidateSafetyState::Safe | CandidateSafetyState::Failed
        )
        && record
            .score
            .is_some_and(|score| score.is_finite() && score > 0.0)
        && record
            .cooldown_until_nanos
            .is_none_or(|until| now_nanos >= until)
}

pub(super) fn ranked_records<'a>(
    records: impl Iterator<Item = &'a CandidateIndexRecord>,
    generation: u64,
    now_nanos: u128,
    limit: usize,
) -> Vec<CandidateIndexRecord> {
    if limit == 0 {
        return Vec::new();
    }
    // Do not reserve `limit`: a caller may request usize::MAX from a tiny
    // index. References, not cloned paths/records, occupy the bounded heap.
    let mut best = BinaryHeap::new();
    for record in records.filter(|record| eligible(record, generation, now_nanos)) {
        let candidate = RankedRecord(record);
        if best.len() < limit {
            best.push(candidate);
        } else if best.peek().is_some_and(|worst| candidate < *worst)
            && let Some(mut worst) = best.peek_mut()
        {
            *worst = candidate;
        }
    }
    best.into_sorted_vec()
        .into_iter()
        .map(|ranked| ranked.0.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::index::{
        IndexedEntryKind, IndexedIdentity, IndexedPruneDecision, ScannerCandidateIndex,
        ScannerIndexContext, ScannerIndexLoadStatus,
    };
    use crate::scanner::patterns::StructuralSignals;
    use std::path::PathBuf;
    use std::time::{Duration, UNIX_EPOCH};

    fn record(inode: u64) -> CandidateIndexRecord {
        CandidateIndexRecord {
            path: PathBuf::from(format!("/cache/target-{inode:04}")),
            identity: IndexedIdentity {
                device_id: 7,
                inode,
                kind: IndexedEntryKind::Directory,
            },
            parent_identity: None,
            parent_mtime_nanos: None,
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

    fn index() -> ScannerCandidateIndex {
        ScannerCandidateIndex::new(ScannerIndexContext {
            root_fingerprint: "replay-root".to_string(),
            config_fingerprint: "replay-config".to_string(),
        })
    }

    #[test]
    fn stale_high_scores_cannot_starve_a_reconciled_candidate() {
        let mut index = index();
        for inode in 1..=100 {
            index.upsert(record(inode));
        }
        index.mark_event_overflow();
        let mut fresh = record(101);
        fresh.score = Some(0.6);
        index.upsert(fresh.clone());
        let ranked = index.ranked_records(UNIX_EPOCH, 1);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].identity, fresh.identity);
        assert_eq!(ranked[0].event_generation, index.event_generation());
        assert!(index.get(record(1).identity).is_some());
    }

    #[test]
    fn replay_generation_remains_revoked_after_checkpoint_restart() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("index.json");
        let mut index = index();
        index.upsert(record(1));
        index.mark_event_overflow();
        index.save_checkpoint(&path).unwrap();
        let (mut loaded, status) =
            ScannerCandidateIndex::load_checkpoint(&path, index.context().clone());
        assert_eq!(status, ScannerIndexLoadStatus::Loaded);
        assert!(loaded.ranked_records(UNIX_EPOCH, 1).is_empty());
        loaded.upsert(record(1));
        assert_eq!(loaded.ranked_records(UNIX_EPOCH, 1).len(), 1);
    }

    #[test]
    fn invalid_scores_and_safety_vetoes_do_not_consume_replay_slots() {
        let mut records = Vec::new();
        for score in [
            None,
            Some(f64::NAN),
            Some(f64::INFINITY),
            Some(-1.0),
            Some(0.0),
        ] {
            let mut bad = record(1);
            bad.score = score;
            records.push(bad);
        }
        for state in [
            CandidateSafetyState::Unknown,
            CandidateSafetyState::ActiveReference,
            CandidateSafetyState::Vetoed,
        ] {
            let mut bad = record(2);
            bad.safety_state = state;
            records.push(bad);
        }
        records.push(record(3));
        let ranked = ranked_records(records.iter(), 0, 0, 1);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].identity, record(3).identity);
    }

    #[test]
    fn bounded_ranking_matches_full_sort_in_both_enumeration_orders() {
        let mut records = (0..512_u32)
            .map(|n| {
                let mut record = record(u64::from(n));
                record.score = Some(f64::from((n * 37) % 19 + 1) / 20.0);
                record.size_estimate_bytes = u64::from((n * 53) % 31) * 1024;
                record
            })
            .collect::<Vec<_>>();
        let mut reference = records.clone();
        reference.sort_by(compare);
        for limit in [0, 1, 7, 32, 512, usize::MAX] {
            let expected = &reference[..limit.min(reference.len())];
            assert_eq!(ranked_records(records.iter(), 0, 0, limit), expected);
            records.reverse();
            assert_eq!(ranked_records(records.iter(), 0, 0, limit), expected);
        }
    }

    #[test]
    fn zero_limit_does_not_even_enumerate_the_index() {
        let records = std::iter::from_fn(|| -> Option<&CandidateIndexRecord> {
            panic!("zero-capacity selection must not scan the index")
        });
        assert!(ranked_records(records, 0, 0, 0).is_empty());
    }

    #[test]
    fn ties_break_on_path_before_filesystem_identity() {
        let mut first = record(20);
        first.path = PathBuf::from("/cache/a");
        let mut second = record(1);
        second.path = PathBuf::from("/cache/b");
        let records = [second, first.clone()];
        assert_eq!(ranked_records(records.iter(), 0, 0, 1), vec![first]);
    }

    #[test]
    fn fresh_safety_veto_survives_a_previously_failed_attempt() {
        for state in [
            CandidateSafetyState::Vetoed,
            CandidateSafetyState::ActiveReference,
            CandidateSafetyState::Unknown,
        ] {
            let mut index = index();
            let mut current = record(1);
            index.upsert(current.clone());
            index.record_failure(
                current.identity,
                UNIX_EPOCH,
                Duration::from_secs(1),
                Duration::from_secs(1),
            );
            current.safety_state = state;
            index.upsert(current.clone());
            assert_eq!(index.get(current.identity).unwrap().safety_state, state);
            assert!(
                index
                    .ranked_records(UNIX_EPOCH + Duration::from_secs(2), 1)
                    .is_empty()
            );
        }
    }

    #[test]
    fn changed_structural_evidence_reopens_a_previously_failed_candidate() {
        let mut index = index();
        let mut current = record(1);
        index.upsert(current.clone());
        index.record_failure(
            current.identity,
            UNIX_EPOCH,
            Duration::from_secs(60),
            Duration::from_secs(60),
        );
        current.structural_signals.has_cachedir_tag = true;
        assert!(!index.candidate_in_cooldown(&current, UNIX_EPOCH));
        index.upsert(current.clone());
        assert_eq!(index.get(current.identity).unwrap().fail_count, 0);
        assert_eq!(index.ranked_records(UNIX_EPOCH, 1), vec![current]);
    }

    #[test]
    fn identical_evidence_keeps_backoff_and_retries_at_the_exact_boundary() {
        let mut index = index();
        let current = record(1);
        index.upsert(current.clone());
        index.record_failure(
            current.identity,
            UNIX_EPOCH,
            Duration::from_secs(10),
            Duration::from_secs(10),
        );
        index.upsert(current);
        assert!(
            index
                .ranked_records(UNIX_EPOCH + Duration::from_secs(9), 1)
                .is_empty()
        );
        let ranked = index.ranked_records(UNIX_EPOCH + Duration::from_secs(10), 1);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].safety_state, CandidateSafetyState::Failed);
        assert_eq!(ranked[0].fail_count, 1);
    }

    #[test]
    fn generation_wrap_revokes_every_record_before_reuse() {
        let mut index = index();
        index.event_generation = u64::MAX;
        index.upsert(record(1));
        index.mark_event_overflow();
        assert_eq!(index.event_generation(), 0);
        assert!(index.is_empty());
        index.upsert(record(2));
        assert_eq!(index.ranked_records(UNIX_EPOCH, 1).len(), 1);
    }
}
