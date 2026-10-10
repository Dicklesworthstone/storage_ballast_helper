//! Bounded, deterministic selection and scoped revocation of replay hints.
//! Persisted records are never deletion authority.

use std::cmp::Ordering;
use std::collections::{BTreeSet, BinaryHeap};
use std::path::Path;

use super::{CandidateIndexRecord, CandidateSafetyState, ScannerCandidateIndex};

impl ScannerCandidateIndex {
    /// Revoke replay hints overlapping changed paths or reconciliation scopes.
    ///
    /// An event inside an opaque candidate invalidates that candidate even
    /// when its root's identity and mtime are unchanged. An event at an
    /// ancestor invalidates all indexed descendants. Unrelated projects keep
    /// their current generation and remain available under pressure.
    ///
    /// Coalesce overlapping scopes before using the ordered path index; do
    /// not walk the filesystem, clone the record map, or scan the whole index
    /// for every event. Temporary storage depends on the number of scopes,
    /// not the number of candidates. Returns the number of changed records.
    pub fn invalidate_paths<'a>(
        &mut self,
        paths: impl IntoIterator<Item = &'a Path>,
    ) -> usize {
        let scopes: BTreeSet<&Path> = paths.into_iter().collect();
        let mut covered: Option<&Path> = None;
        let mut invalidated = 0;
        for scope in scopes {
            // Path ordering compares components: descendants form one range,
            // while e.g. `target-other` is not inside `target`.
            if covered.is_some_and(|ancestor| scope.starts_with(ancestor)) {
                continue;
            }
            covered = Some(scope);
            // The root itself is handled by the descendant range below.
            for ancestor in scope.ancestors().skip(1) {
                if let Some(identity) = self.paths.get(ancestor)
                    && let Some(record) = self.records.get_mut(identity)
                {
                    invalidated += usize::from(revoke(record));
                }
            }
            for (_, identity) in self
                .paths
                .range(scope.to_path_buf()..)
                .take_while(|(path, _)| path.starts_with(scope))
            {
                if let Some(record) = self.records.get_mut(identity) {
                    invalidated += usize::from(revoke(record));
                }
            }
        }
        invalidated
    }
}

fn revoke(record: &mut CandidateIndexRecord) -> bool {
    let changed = record.score.is_some() || record.safety_state != CandidateSafetyState::Unknown;
    // Clearing only the safety state is insufficient: executor feedback from
    // a batch already in flight can subsequently set it to Failed (retryable).
    // No positive score survives to make that stale evidence replayable.
    record.score = None;
    record.safety_state = CandidateSafetyState::Unknown;
    // Keep identity, observed metadata, structural evidence, and backoff as
    // historical hints. A new walk must score the candidate again; unchanged
    // evidence must not erase its accumulated failed-deletion cooldown.
    changed
}

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

    #[test]
    fn descendant_change_revokes_opaque_root_without_a_global_generation_bump() {
        let mut index = index();
        let current = record(1);
        let other = record(2);
        index.upsert(current.clone());
        index.upsert(other.clone());
        let changed = current.path.join("debug/deps/object.o");
        assert_eq!(index.invalidate_paths([changed.as_path()]), 1);
        let invalidated = index.get(current.identity).unwrap();
        assert!(invalidated.evidence_matches(&current), "root metadata need not change");
        assert_eq!(invalidated.score, None);
        assert_eq!(invalidated.safety_state, CandidateSafetyState::Unknown);
        assert_eq!(index.event_generation(), 0);
        assert_eq!(index.ranked_records(UNIX_EPOCH, 1), vec![other]);
        assert_eq!(index.invalidate_paths([changed.as_path()]), 0);
        index.upsert(current.clone());
        assert_eq!(index.ranked_records(UNIX_EPOCH, 1), vec![current]);
    }

    #[test]
    fn ancestor_and_duplicate_scopes_revoke_descendants_once_not_prefix_siblings() {
        let mut index = index();
        let paths = [
            "/cache/project/target",
            "/cache/project/target/debug",
            "/cache/project/node_modules",
            "/cache/project-other/target",
            "/cache/project.other/target",
            "/cache/another/target",
        ];
        for (n, path) in paths.iter().enumerate() {
            let mut current = record(u64::try_from(n).unwrap());
            current.path = PathBuf::from(path);
            index.upsert(current);
        }
        let scopes = [
            Path::new("/cache/project/target/debug/object.o"),
            Path::new("/cache/project"),
            Path::new("/cache/project/target"),
            Path::new("/cache/project"),
        ];
        assert_eq!(index.invalidate_paths(scopes), 3);
        assert_eq!(index.len(), paths.len(), "invalidation is not eviction");
        for (n, _) in paths.iter().enumerate() {
            let current = index.get(record(u64::try_from(n).unwrap()).identity).unwrap();
            assert_eq!(current.score.is_none(), n < 3);
        }
        assert_eq!(index.invalidate_paths([Path::new("/cache/absent")]), 0);
        assert_eq!(index.ranked_records(UNIX_EPOCH, usize::MAX).len(), 3);
    }

    #[test]
    fn delayed_failure_feedback_cannot_restore_a_revoked_score_or_erase_backoff() {
        let mut index = index();
        let current = record(1);
        index.upsert(current.clone());
        index.record_failure(current.identity, UNIX_EPOCH, Duration::from_secs(10), Duration::from_secs(60));
        let before = index.get(current.identity).unwrap().clone();
        index.invalidate_paths([current.path.as_path()]);
        let invalidated = index.get(current.identity).unwrap();
        assert_eq!(invalidated.fail_count, before.fail_count);
        assert_eq!(invalidated.cooldown_until_nanos, before.cooldown_until_nanos);
        assert!(invalidated.evidence_matches(&before));
        // The daemon drains executor feedback after applying event invalidation.
        index.record_failure(current.identity, UNIX_EPOCH, Duration::from_secs(10), Duration::from_secs(60));
        let after_cooldown = UNIX_EPOCH + Duration::from_secs(100);
        assert!(index.ranked_records(after_cooldown, 1).is_empty());
        assert_eq!(index.get(current.identity).unwrap().score, None);
        // Only a new scoring observation restores eligibility, retaining the
        // same evidence's failure history rather than starting a hot retry loop.
        index.upsert(current.clone());
        assert_eq!(index.get(current.identity).unwrap().fail_count, 2);
        assert!(index.ranked_records(UNIX_EPOCH, 1).is_empty());
        assert_eq!(index.ranked_records(after_cooldown, 1)[0].identity, current.identity);
    }

    #[test]
    fn scoped_revocation_and_unrelated_replay_survive_checkpoint_restart() {
        let temp = tempfile::tempdir().unwrap();
        let checkpoint = temp.path().join("index.json");
        let mut index = index();
        let current = record(1);
        let other = record(2);
        index.upsert(current.clone());
        index.upsert(other.clone());
        index.invalidate_paths([current.path.join("debug/changed.o").as_path()]);
        index.save_checkpoint(&checkpoint).unwrap();
        let (mut loaded, status) = ScannerCandidateIndex::load_checkpoint(&checkpoint, index.context().clone());
        assert_eq!(status, ScannerIndexLoadStatus::Loaded);
        assert_eq!(loaded.event_generation(), index.event_generation());
        assert_eq!(loaded.get(current.identity).unwrap().score, None);
        assert_eq!(loaded.ranked_records(UNIX_EPOCH, usize::MAX), vec![other]);
        loaded.record_failure(current.identity, UNIX_EPOCH, Duration::ZERO, Duration::ZERO);
        assert_eq!(loaded.ranked_records(UNIX_EPOCH, 1).len(), 1);
        loaded.upsert(current);
        assert_eq!(loaded.ranked_records(UNIX_EPOCH, usize::MAX).len(), 2);
    }

    #[test]
    fn revocation_uses_current_path_bindings_after_rename_or_rebuild() {
        let mut index = index();
        let old = record(1);
        index.upsert(old.clone());
        let mut moved = old.clone();
        moved.path = PathBuf::from("/cache/moved/target");
        index.upsert(moved.clone());
        assert_eq!(index.invalidate_paths([old.path.as_path()]), 0);
        assert_eq!(index.ranked_records(UNIX_EPOCH, 1), vec![moved.clone()]);
        let mut replacement = record(2);
        replacement.path.clone_from(&moved.path);
        index.upsert(replacement.clone());
        assert_eq!(index.invalidate_paths([moved.path.as_path()]), 1);
        assert!(index.get(old.identity).is_none());
        assert_eq!(index.get(replacement.identity).unwrap().score, None);
    }

    #[cfg(unix)]
    #[test]
    fn scoped_revocation_preserves_non_utf8_component_boundaries() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let root = PathBuf::from("/cache").join(OsString::from_vec(vec![b'p', 0xff]));
        let sibling = PathBuf::from("/cache").join(OsString::from_vec(vec![b'p', 0xff, b'-']));
        let mut index = index();
        let mut current = record(1);
        current.path = root.join("target");
        let mut other = record(2);
        other.path = sibling.join("target");
        index.upsert(current);
        index.upsert(other.clone());
        assert_eq!(index.invalidate_paths([root.as_path()]), 1);
        assert_eq!(index.ranked_records(UNIX_EPOCH, 1), vec![other]);
    }

    proptest::proptest! {
        #[test]
        fn scoped_revocation_matches_full_overlap_reference(
            changes in proptest::collection::vec((0u32..8, 0u32..4, 0u32..4), 0..40),
        ) {
            let mut index = index();
            let mut records = Vec::new();
            for project in 0..8_u32 {
                for target in 0..4_u32 {
                    let mut current = record(u64::from(project * 4 + target));
                    current.path = PathBuf::from(format!("/cache/p{project}/target-{target}"));
                    index.upsert(current.clone());
                    records.push(current);
                }
            }
            let scopes: Vec<PathBuf> = changes.into_iter().map(|(project, target, depth)| {
                let project = PathBuf::from(format!("/cache/p{project}"));
                match depth {
                    0 => project,
                    1 => project.join(format!("target-{target}")),
                    2 => project.join(format!("target-{target}/debug/object.o")),
                    _ => project.with_file_name(format!("{}-other", project.file_name().unwrap().to_string_lossy())),
                }
            }).collect();
            let expected: Vec<bool> = records.iter().map(|record| {
                scopes.iter().any(|path| record.path.starts_with(path) || path.starts_with(&record.path))
            }).collect();
            let count = index.invalidate_paths(scopes.iter().rev().map(PathBuf::as_path));
            proptest::prop_assert_eq!(count, expected.iter().filter(|affected| **affected).count());
            for (record, affected) in records.iter().zip(expected) {
                let actual = index.get(record.identity).unwrap();
                proptest::prop_assert_eq!(actual.score.is_none(), affected);
                proptest::prop_assert!(actual.evidence_matches(record));
            }
            proptest::prop_assert_eq!(index.event_generation(), 0);
            proptest::prop_assert_eq!(index.invalidate_paths(scopes.iter().map(PathBuf::as_path)), 0);
        }
    }
}
