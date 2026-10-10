//! Cooperative traversal budgets for quarantine drains.
//!
//! A paused purge leaves its manifest and remaining payload in place. The
//! filesystem itself is the continuation: the next call opens and validates
//! the record again, then visits only the children still present. No deletion
//! authority, open descriptor, or mutable traversal cursor survives a call.
//!
//! This bounds traversal work, not elapsed time. Directory inventory, record
//! I/O, synchronization, and an individual kernel operation can still block.

/// Traversal checkpoints shared by all payloads in one default drain call.
///
/// Checkpoints occur before record attempts, payload lookup, descent,
/// directory iteration and unlink. This is not a count of reclaimed files
/// or a wall-clock deadline. Explicit single-entry `purge` keeps its
/// synchronous completion semantics.
pub const DEFAULT_DRAIN_WORK: usize = 16_384;

#[derive(Debug)]
pub(super) struct PurgeBudget {
    remaining: Option<usize>,
}

impl PurgeBudget {
    pub(super) const fn bounded(steps: usize) -> Self {
        Self {
            remaining: Some(steps),
        }
    }

    pub(super) const fn unlimited() -> Self {
        Self { remaining: None }
    }

    pub(super) const fn exhausted(&self) -> bool {
        matches!(self.remaining, Some(0))
    }

    pub(super) fn take(&mut self) -> bool {
        match &mut self.remaining {
            None => true,
            Some(0) => false,
            Some(remaining) => {
                *remaining -= 1;
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::quarantine::{DrainOutcome, QuarantineRecord, QuarantineStore};
    use std::fs;
    use std::path::Path;
    use std::time::Duration;

    fn held_tree(base: &Path, id: &str, files: usize) -> (QuarantineStore, QuarantineRecord) {
        let source = base.join(format!("artifact-{id}"));
        fs::create_dir_all(source.join("children")).unwrap();
        for i in 0..files {
            fs::write(source.join("children").join(format!("{i:04}")), b"held").unwrap();
        }
        let store = QuarantineStore::under(base);
        let record = store
            .quarantine(&source, id, 1234, Duration::ZERO, None)
            .unwrap();
        (store, record)
    }

    fn remaining_files(record: &QuarantineRecord) -> usize {
        let children = record.quarantine_path.join("children");
        match fs::read_dir(children) {
            Ok(entries) => entries
                .map(|entry| {
                    entry.unwrap();
                    1usize
                })
                .sum(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => panic!("cannot inspect remaining payload: {error}"),
        }
    }

    #[test]
    fn work_allowance_is_exact_and_cannot_underflow() {
        for limit in [0, 1, 3, 256, DEFAULT_DRAIN_WORK] {
            let mut budget = PurgeBudget::bounded(limit);
            for _ in 0..limit {
                assert!(!budget.exhausted());
                assert!(budget.take());
            }
            assert!(budget.exhausted());
            assert!(!budget.take());
            assert!(!budget.take());
        }
        let mut unlimited = PurgeBudget::unlimited();
        for _ in 0..DEFAULT_DRAIN_WORK * 2 {
            assert!(unlimited.take());
            assert!(!unlimited.exhausted());
        }
    }

    #[test]
    fn zero_work_preserves_payload_and_does_not_manufacture_a_stuck_entry() {
        let temp = tempfile::tempdir().unwrap();
        let (store, record) = held_tree(temp.path(), "zero", 8);
        let out = store.drain_all_with_budget(0).unwrap();
        assert_eq!(out.counts(), (0, 0));
        assert!(out.budget_exhausted);
        assert_eq!(out.deferred_entries, 1);
        assert!(out.failures.is_empty());
        assert_eq!(out.skipped_stuck, 0);
        assert_eq!(remaining_files(&record), 8);
        assert_eq!(store.record("zero").unwrap(), Some(record));
        assert!(!store.root().join("zero.stuck").exists());
    }

    #[test]
    fn a_large_payload_resumes_after_reopening_without_double_counting_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let (store, record) = held_tree(temp.path(), "wide", 96);
        let outside = temp.path().join("outside");
        fs::write(&outside, b"outside survives").unwrap();
        fs::create_dir(&record.original_path).unwrap();
        fs::write(record.original_path.join("new-build"), b"keep rebuild").unwrap();
        let mut entries = 0;
        let mut bytes = 0;
        let mut previous = 96;
        let mut paused = false;
        for _ in 0..100 {
            // No in-memory continuation or lock is retained across calls.
            let reopened = QuarantineStore::at(store.root().to_path_buf());
            let out = reopened.drain_all_with_budget(32).unwrap();
            assert!(out.failures.is_empty());
            assert_eq!(out.skipped_stuck, 0);
            entries += out.entries;
            bytes += out.bytes;
            if reopened.record("wide").unwrap().is_none() {
                assert!(!out.budget_exhausted);
                break;
            }
            paused = true;
            assert!(out.budget_exhausted);
            assert_eq!(out.deferred_entries, 1);
            assert_eq!(out.counts(), (0, 0), "do not credit a still-held entry");
            let remaining = remaining_files(&record);
            assert!(
                remaining < previous,
                "each adequately sized slice makes progress"
            );
            previous = remaining;
            assert_eq!(reopened.record("wide").unwrap(), Some(record.clone()));
            assert!(!reopened.root().join("wide.stuck").exists());
        }
        assert!(
            paused,
            "fixture must exercise continuation, not only completion"
        );
        assert_eq!((entries, bytes), (1, 1234));
        assert!(store.record("wide").unwrap().is_none());
        assert_eq!(store.drain_all_with_budget(32).unwrap().counts(), (0, 0));
        assert_eq!(fs::read(outside).unwrap(), b"outside survives");
        assert_eq!(
            fs::read(record.original_path.join("new-build")).unwrap(),
            b"keep rebuild"
        );
    }

    #[test]
    fn one_budget_is_shared_across_payloads_instead_of_restarting_for_each_entry() {
        let temp = tempfile::tempdir().unwrap();
        let store = QuarantineStore::under(temp.path());
        for id in ["a", "b", "c"] {
            let source = temp.path().join(id);
            fs::write(&source, b"payload").unwrap();
            store
                .quarantine(&source, id, 100, Duration::ZERO, None)
                .unwrap();
        }
        // A file consumes record-attempt, lookup, entry and pre-unlink checks.
        let first = store.drain_all_with_budget(4).unwrap();
        assert_eq!(first.counts(), (1, 100));
        assert!(first.budget_exhausted);
        assert_eq!(first.deferred_entries, 1);
        assert_eq!(store.records().unwrap().len(), 2);
        let rest = store.drain_all().unwrap();
        assert_eq!(rest.counts(), (2, 200));
        assert!(rest.failures.is_empty());
    }

    #[test]
    fn partial_payload_remains_restorable_and_explicit_purge_can_finish_it() {
        let temp = tempfile::tempdir().unwrap();
        let (store, record) = held_tree(temp.path(), "undo", 96);
        assert!(store.drain_all_with_budget(32).unwrap().budget_exhausted);
        let remaining = remaining_files(&record);
        assert!(remaining > 0 && remaining < 96);
        let restored = store.restore("undo", false).unwrap();
        assert_eq!(restored.restored_to, record.original_path);
        assert_eq!(
            fs::read_dir(restored.restored_to.join("children"))
                .unwrap()
                .count(),
            remaining
        );
        assert!(store.record("undo").unwrap().is_none());
        let (_, second) = held_tree(temp.path(), "finish", 96);
        assert!(store.drain_all_with_budget(32).unwrap().budget_exhausted);
        assert_eq!(store.purge("finish").unwrap(), 1234);
        assert!(!second.quarantine_path.exists());
        assert_eq!(store.purge("finish").unwrap(), 0);
    }

    #[test]
    fn resumed_purge_refuses_a_replaced_payload_and_still_drains_other_entries() {
        let temp = tempfile::tempdir().unwrap();
        let (store, record) = held_tree(temp.path(), "replaced", 96);
        assert!(store.drain_all_with_budget(32).unwrap().budget_exhausted);
        let saved = temp.path().join("saved-partial");
        fs::rename(&record.quarantine_path, &saved).unwrap();
        fs::create_dir(&record.quarantine_path).unwrap();
        fs::write(
            record.quarantine_path.join("new"),
            b"do not delete replacement",
        )
        .unwrap();
        let (_, healthy) = held_tree(temp.path(), "healthy", 1);
        let out = store.drain_all_with_budget(256).unwrap();
        assert_eq!(out.counts(), (1, 1234));
        assert_eq!(out.failures.len(), 1);
        assert_eq!(out.failures[0].decision_id, "replaced");
        assert!(!healthy.quarantine_path.exists());
        assert!(saved.is_dir());
        assert_eq!(
            fs::read(record.quarantine_path.join("new")).unwrap(),
            b"do not delete replacement"
        );
        assert!(store.record("replaced").unwrap().is_some());
    }

    #[test]
    fn expired_slices_do_not_touch_entries_whose_ttl_has_not_elapsed() {
        let temp = tempfile::tempdir().unwrap();
        let (store, expired) = held_tree(temp.path(), "expired", 48);
        let source = temp.path().join("future");
        fs::write(&source, b"retain until expiry").unwrap();
        let future = store
            .quarantine(&source, "future", 100, Duration::from_hours(24), None)
            .unwrap();
        let now = expired.expires_at.max(future.quarantined_at);
        assert!(future.expires_at > now);
        let mut total = 0;
        for _ in 0..100 {
            let out = store.drain_expired_with_budget(now, 32).unwrap();
            assert!(out.failures.is_empty());
            total += out.bytes;
            assert_eq!(
                fs::read(&future.quarantine_path).unwrap(),
                b"retain until expiry"
            );
            if !out.budget_exhausted {
                break;
            }
        }
        assert_eq!(total, expired.size_bytes);
        assert!(store.record("expired").unwrap().is_none());
        assert_eq!(store.record("future").unwrap(), Some(future));
    }

    #[test]
    fn merged_outcomes_retain_pending_work_without_turning_it_into_failure() {
        let first = DrainOutcome {
            entries: 1,
            bytes: 100,
            ..DrainOutcome::default()
        };
        let paused = DrainOutcome {
            deferred_entries: 1,
            budget_exhausted: true,
            ..DrainOutcome::default()
        };
        let merged = first.merged(paused);
        assert_eq!(merged.counts(), (1, 100));
        assert_eq!(merged.deferred_entries, 1);
        assert!(merged.budget_exhausted);
        assert!(merged.failures.is_empty());
    }
}
