//! Leading-root opportunities for pressure-limited scans.
//!
//! A request may name every root yet run out of time in the first one. Moving
//! a round-robin cursor by the length of the returned list would therefore
//! advance it by a complete lap without giving another root a real lead.
//! Track only the first opportunity, separately from completed scan evidence.
//!
//! Fallback rotates all supplied roots. VOI reserves alternate leading turns
//! for never-scanned/day-overdue roots without permanently displacing the
//! ordinary dirty/index winner. Histories are per path, not a global cursor:
//! interleaved requests for disjoint mounts cannot consume each other's turn.
//! No remembered path is ever added to a caller's scope or registered for
//! maintenance. Configuration reload discards this opportunity history.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
struct Opportunity {
    last_lead: u64,
    ordinary_due: bool,
}

#[derive(Debug, Clone, Default)]
pub(super) struct PressureOrder {
    history: BTreeMap<PathBuf, Opportunity>,
    sequence: u64,
}

impl PressureOrder {
    pub(super) fn reset(&mut self) {
        *self = Self::default();
    }

    fn compare(&self, left: &Path, right: &Path) -> Ordering {
        let age = |path: &Path| self.history.get(path).map_or(0, |entry| entry.last_lead);
        age(left).cmp(&age(right)).then_with(|| left.cmp(right))
    }

    /// `paths` already has the ordinary dirty/index order. Return precisely
    /// its unique scope; pressure's entry/time budget is the caller's, not the
    /// maintenance scheduler's root-count budget. Only an opportunity is spent.
    pub(super) fn reorder(
        &mut self,
        paths: &mut Vec<PathBuf>,
        fallback: bool,
        overdue: impl Fn(&Path) -> bool,
    ) {
        let mut unique = BTreeSet::new();
        paths.retain(|path| unique.insert(path.clone()));
        if paths.is_empty() {
            return;
        }
        if fallback {
            paths.sort_by(|left, right| self.compare(left, right));
        } else {
            let next = paths
                .iter()
                .enumerate()
                .filter(|(_, path)| overdue(path))
                .min_by(|(_, left), (_, right)| self.compare(left, right))
                .map(|(index, _)| index);
            let ordinary_due = self
                .history
                .get(&paths[0])
                .is_some_and(|entry| entry.ordinary_due);
            if let Some(index) = next
                && index > 0
                && !ordinary_due
            {
                self.history
                    .entry(paths[0].clone())
                    .or_default()
                    .ordinary_due = true;
                // Preserve the relative heuristic order of every other root.
                paths[..=index].rotate_right(1);
            }
        }

        // Saturation must not pin a previously preferred root at the minimum
        // ticket forever. Reset scheduling history, never scan/dirty evidence.
        if self.sequence == u64::MAX {
            self.reset();
        }
        self.sequence += 1;
        let entry = self.history.entry(paths[0].clone()).or_default();
        entry.last_lead = self.sequence;
        entry.ordinary_due = false;
    }
}

#[cfg(test)]
mod tests {
    use super::super::{MAX_REVISIT_INTERVAL, VoiConfig, VoiScheduler};
    use super::*;
    use std::time::{Duration, Instant};

    fn paths(names: &[&str]) -> Vec<PathBuf> {
        names.iter().map(|name| PathBuf::from(*name)).collect()
    }

    fn scheduler(names: &[&str]) -> VoiScheduler {
        let mut scheduler = VoiScheduler::new(VoiConfig::default());
        for path in paths(names) {
            scheduler.register_path(path);
        }
        scheduler
    }

    #[test]
    fn fallback_rotates_the_lead_even_when_every_root_is_returned() {
        let mut order = PressureOrder::default();
        for expected in ["/a", "/b", "/c", "/a", "/b", "/c"] {
            let mut ranked = paths(&["/c", "/b", "/a", "/c"]);
            order.reorder(&mut ranked, true, |_| {
                panic!("fallback must ignore forecasts")
            });
            assert_eq!(ranked[0], Path::new(expected));
            assert_eq!(ranked.len(), 3);
            assert_eq!(ranked.iter().collect::<BTreeSet<_>>().len(), 3);
        }
    }

    #[test]
    fn overdue_roots_share_the_lead_with_continuously_dirty_work() {
        let mut order = PressureOrder::default();
        for expected in ["/a", "/hot", "/b", "/hot", "/c", "/hot", "/a"] {
            let mut ranked = paths(&["/hot", "/c", "/b", "/a"]);
            order.reorder(&mut ranked, false, |path| path != Path::new("/hot"));
            assert_eq!(ranked[0], Path::new(expected));
            let remainder: Vec<_> = ranked
                .iter()
                .filter(|path| path.as_path() != Path::new(expected))
                .collect();
            let original = paths(&["/hot", "/c", "/b", "/a"]);
            let expected_remainder: Vec<_> = original
                .iter()
                .filter(|path| path.as_path() != Path::new(expected))
                .collect();
            assert_eq!(remainder, expected_remainder);
        }
    }

    #[test]
    fn disjoint_mount_requests_cannot_consume_each_others_turns() {
        for fallback in [false, true] {
            let mut order = PressureOrder::default();
            let left = paths(&["/left/a", "/left/b"]);
            let right = paths(&["/right/a", "/right/b", "/right/c"]);
            let mut left_seen = BTreeSet::new();
            let mut right_seen = BTreeSet::new();
            for _ in 0..6 {
                let mut ranked = left.clone();
                order.reorder(&mut ranked, fallback, |_| true);
                left_seen.insert(ranked[0].clone());
                let mut ranked = right.clone();
                order.reorder(&mut ranked, fallback, |_| true);
                right_seen.insert(ranked[0].clone());
            }
            assert_eq!(left_seen, left.into_iter().collect());
            assert_eq!(right_seen, right.into_iter().collect());
        }
    }

    #[test]
    fn restricted_scopes_never_reintroduce_previously_seen_paths() {
        let mut order = PressureOrder::default();
        let mut all = paths(&["/a", "/b", "/c"]);
        order.reorder(&mut all, true, |_| true);
        for _ in 0..5 {
            let mut restricted = paths(&["/b", "/b"]);
            order.reorder(&mut restricted, false, |_| true);
            assert_eq!(restricted, paths(&["/b"]));
        }
        let sequence = order.sequence;
        let history_len = order.history.len();
        order.reorder(&mut Vec::new(), true, |_| panic!("empty scope"));
        assert_eq!(order.sequence, sequence);
        assert_eq!(order.history.len(), history_len);
    }

    #[test]
    fn exhausted_sequence_starts_a_new_fair_rotation() {
        let mut order = PressureOrder::default();
        let mut ranked = paths(&["/a", "/b", "/c"]);
        order.reorder(&mut ranked, false, |_| true);
        order.sequence = u64::MAX;
        let mut seen = BTreeSet::new();
        for _ in 0..6 {
            let mut ranked = paths(&["/a", "/b", "/c"]);
            order.reorder(&mut ranked, false, |_| true);
            seen.insert(ranked[0].clone());
        }
        assert_eq!(seen, paths(&["/a", "/b", "/c"]).into_iter().collect());
        assert_eq!(order.sequence, 6);
    }

    #[test]
    fn pressure_ranking_obeys_both_disabled_and_calibration_fallback() {
        let now = Instant::now();
        let scope = paths(&["/c", "/b", "/a"]);
        for disabled in [false, true] {
            let mut scheduler = scheduler(&["/a", "/b", "/c"]);
            scheduler.config.enabled = !disabled;
            if !disabled {
                for _ in 0..scheduler.config.fallback_trigger_windows {
                    scheduler.calibration.record_window(1.0, &scheduler.config);
                }
            }
            assert!(scheduler.is_fallback_active());
            scheduler.record_dirty(&PathBuf::from("/c"), true, now);
            for expected in ["/a", "/b", "/c", "/a"] {
                assert_eq!(scheduler.rank_paths(&scope, now)[0], Path::new(expected));
            }
            assert!(
                scheduler
                    .path_stats(&PathBuf::from("/c"))
                    .unwrap()
                    .dirty_pending
            );
        }
    }

    #[test]
    fn pressure_exploration_rescues_zero_yield_roots_without_faking_completion() {
        let mut scheduler = scheduler(&["/a", "/b", "/hot"]);
        let start = Instant::now();
        let now = start + MAX_REVISIT_INTERVAL;
        for cold in ["/a", "/b"] {
            scheduler.record_scan_result(&PathBuf::from(cold), 0, 0, 0, 1_000_000.0, start);
        }
        scheduler.record_scan_result(&PathBuf::from("/hot"), 1_000_000_000, 10, 0, 1.0, now);
        scheduler.record_dirty(&PathBuf::from("/hot"), true, now);
        let scope = paths(&["/hot", "/b", "/a"]);
        // Pressure's entry/time budget must not be replaced by the Green root budget.
        scheduler.config.scan_budget_per_interval = 0;
        for expected in ["/a", "/hot", "/b", "/hot"] {
            let ranked = scheduler.rank_paths(&scope, now);
            assert_eq!(ranked[0], Path::new(expected));
            assert_eq!(ranked.len(), scope.len());
        }
        for cold in ["/a", "/b"] {
            let stats = scheduler.path_stats(&PathBuf::from(cold)).unwrap();
            assert_eq!(stats.scan_count, 1);
            assert_eq!(stats.last_scanned, Some(start));
            assert_eq!(stats.forecast_reclaim, 0.0);
        }
        let hot = scheduler.path_stats(&PathBuf::from("/hot")).unwrap();
        assert_eq!(hot.scan_count, 1);
        assert!(hot.dirty_pending);
    }

    #[test]
    fn recent_scans_keep_ordinary_dirty_and_hazard_order_until_due() {
        let mut scheduler = scheduler(&["/cold", "/hot"]);
        let start = Instant::now();
        scheduler.record_scan_result(&PathBuf::from("/cold"), 0, 0, 0, 1000.0, start);
        scheduler.record_scan_result(&PathBuf::from("/hot"), 1_000_000_000, 1, 0, 1.0, start);
        scheduler.record_dirty(&PathBuf::from("/hot"), true, start);
        let scope = paths(&["/cold", "/hot"]);
        let deadline = start + MAX_REVISIT_INTERVAL;
        let before = deadline.checked_sub(Duration::from_nanos(1)).unwrap();
        for _ in 0..4 {
            assert_eq!(scheduler.rank_paths(&scope, before)[0], Path::new("/hot"));
        }
        assert_eq!(
            scheduler.rank_paths(&scope, deadline)[0],
            Path::new("/cold")
        );
        scheduler.record_scan_result(&PathBuf::from("/cold"), 0, 0, 0, 1000.0, deadline);
        assert_eq!(scheduler.rank_paths(&scope, deadline)[0], Path::new("/hot"));
    }

    #[test]
    fn unregistered_pressure_paths_do_not_become_maintenance_roots() {
        let mut scheduler = scheduler(&["/registered"]);
        let now = Instant::now();
        let scope = paths(&["/external/b", "/external/a"]);
        let mut seen = BTreeSet::new();
        for _ in 0..4 {
            seen.insert(scheduler.rank_paths(&scope, now)[0].clone());
        }
        assert_eq!(seen, scope.into_iter().collect());
        assert_eq!(scheduler.calibration_summary().total_paths_tracked, 1);
        let plan = scheduler.schedule(now);
        assert_eq!(plan.paths.len(), 1);
        assert_eq!(plan.paths[0].path, Path::new("/registered"));
    }

    #[test]
    fn maintenance_and_pressure_opportunities_are_independent() {
        let mut scheduler = scheduler(&["/a", "/b", "/c"]);
        scheduler.config.scan_budget_per_interval = 1;
        let mut reference = scheduler.clone();
        let now = Instant::now();
        let scope = paths(&["/a", "/b", "/c"]);
        for _ in 0..10 {
            let _ = scheduler.rank_paths(&scope, now);
            assert_eq!(
                scheduler.schedule(now).paths[0].path,
                reference.schedule(now).paths[0].path
            );
        }
        let mut reference = scheduler.clone();
        for _ in 0..10 {
            let _ = scheduler.schedule(now);
            assert_eq!(
                scheduler.rank_paths(&scope, now),
                reference.rank_paths(&scope, now)
            );
        }
    }

    #[test]
    fn configuration_reload_resets_opportunities_but_preserves_evidence() {
        let mut scheduler = scheduler(&["/a", "/b"]);
        let now = Instant::now();
        scheduler.record_dirty(&PathBuf::from("/b"), true, now);
        let _ = scheduler.rank_paths(&paths(&["/a", "/b"]), now);
        assert!(scheduler.pressure_order.sequence > 0);
        scheduler.update_config(VoiConfig {
            enabled: false,
            ..VoiConfig::default()
        });
        assert_eq!(scheduler.pressure_order.sequence, 0);
        assert!(scheduler.pressure_order.history.is_empty());
        assert!(
            scheduler
                .path_stats(&PathBuf::from("/b"))
                .unwrap()
                .dirty_pending
        );
        assert_eq!(
            scheduler.rank_paths(&paths(&["/b", "/a"]), now)[0],
            Path::new("/a")
        );
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        #[test]
        fn every_continuously_overdue_root_gets_a_lead_despite_changing_winners(
            priorities in proptest::collection::vec(0usize..1000, 1..32),
            fallback in proptest::bool::ANY,
        ) {
            let scope: Vec<_> = (0..priorities.len())
                .map(|index| PathBuf::from(format!("/root/{index:03}")))
                .collect();
            let expected: BTreeSet<_> = scope.iter().cloned().collect();
            let mut seen = BTreeSet::new();
            let mut order = PressureOrder::default();
            let bound = if fallback { scope.len() } else { 2 * scope.len() };
            for tick in 0..bound {
                let mut ranked = scope.clone();
                ranked.rotate_left(priorities[tick % priorities.len()] % scope.len());
                order.reorder(&mut ranked, fallback, |_| true);
                let unique: BTreeSet<_> = ranked.iter().cloned().collect();
                proptest::prop_assert_eq!(&unique, &expected);
                proptest::prop_assert_eq!(ranked.len(), scope.len());
                seen.insert(ranked[0].clone());
            }
            proptest::prop_assert_eq!(seen, expected);
        }
    }
}
