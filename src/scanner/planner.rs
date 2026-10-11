//! Risk-budgeted batch planning with a hard safety-admission boundary.
//!
//! A vetoed descendant cannot be removed indirectly by selecting its parent.
//! Likewise, a vetoed root cannot be bypassed by selecting one of its children,
//! another observation at the same path, or an observed identity alias. Perform
//! these checks before any risk/byte optimization or counterfactual accounting.
//!
//! Admission uses only the observations supplied in this batch. It neither
//! canonicalizes paths nor discovers unseen aliases, mounts or active references.
//! The executor must still perform fresh identity, protection and lease checks.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use crate::scanner::scoring::CandidacyScore;
use crate::scanner::walker::FsIdentity;

mod optimization;

pub use optimization::{BatchPlan, PlanRequest, PlannedItem, RiskBudgetByLevel};

/// Choose a disjoint, risk-budgeted batch after enforcing all supplied vetoes.
///
/// Hard vetoes and category suspensions exclude overlapping deletion scopes and
/// observed aliases. `Keep` or an ineligible `Review` alone is not a protection
/// marker: it must not prevent an independently admissible subtree from being
/// considered. Rejections are not risk-budget skips and cannot contribute bytes
/// to either the chosen plan or its top-N comparison.
///
/// All existing item limits, emergency review rules, risk bounds, target-cover
/// alternatives and deterministic ranking apply to the admitted observations.
#[must_use]
pub fn plan_batch(
    candidates: Vec<CandidacyScore>,
    request: &PlanRequest,
) -> (Vec<CandidacyScore>, BatchPlan) {
    if !candidates.iter().any(hard_veto) {
        return optimization::plan_batch(candidates, request);
    }
    let rejected = rejected_observations(&candidates);
    let admitted = candidates
        .into_iter()
        .zip(rejected)
        .filter_map(|(candidate, rejected)| (!rejected).then_some(candidate))
        .collect();
    optimization::plan_batch(admitted, request)
}

fn hard_veto(candidate: &CandidacyScore) -> bool {
    candidate.vetoed || candidate.decision.category_suspended
}

/// Identity/path equivalence is transitive, even when observations disagree
/// about which inode occupied a path. Unknown identities never form a group.
/// Path containment is deliberately NOT an equivalence edge: a rejected parent
/// must not turn its independently safe children into vetoed scopes.
struct Groups {
    parent: Vec<usize>,
    size: Vec<usize>,
}

impl Groups {
    fn new(len: usize) -> Self {
        Self {
            parent: (0..len).collect(),
            size: vec![1; len],
        }
    }

    fn root(&mut self, mut index: usize) -> usize {
        while self.parent[index] != index {
            self.parent[index] = self.parent[self.parent[index]];
            index = self.parent[index];
        }
        index
    }

    fn unite(&mut self, left: usize, right: usize) {
        let mut left = self.root(left);
        let mut right = self.root(right);
        if left == right {
            return;
        }
        if self.size[left] < self.size[right] {
            std::mem::swap(&mut left, &mut right);
        }
        self.parent[right] = left;
        self.size[left] += self.size[right];
    }
}

fn rejected_observations(candidates: &[CandidacyScore]) -> Vec<bool> {
    let mut groups = Groups::new(candidates.len());
    let mut paths: BTreeMap<&Path, usize> = BTreeMap::new();
    let mut identities: HashMap<FsIdentity, usize> = HashMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        if let Some(previous) = paths.insert(candidate.path.as_path(), index) {
            groups.unite(index, previous);
        }
        if let Some(identity) = candidate.identity
            && let Some(previous) = identities.insert(identity, index)
        {
            groups.unite(index, previous);
        }
    }
    let roots: Vec<_> = (0..candidates.len()).map(|index| groups.root(index)).collect();
    let mut protected = vec![false; candidates.len()];
    for (index, candidate) in candidates.iter().enumerate() {
        if hard_veto(candidate) {
            protected[roots[index]] = true;
        }
    }
    // All observed spellings of an explicitly vetoed cleanup unit are veto
    // scopes. Collect them before filtering so an invalid/Keep observation
    // carrying a real veto cannot disappear ahead of a more optimistic alias.
    let scopes: BTreeSet<_> = candidates
        .iter()
        .enumerate()
        .filter(|(index, _)| protected[roots[*index]])
        .map(|(_, candidate)| candidate.path.clone())
        .collect();
    let mut rejected = protected;
    for (index, candidate) in candidates.iter().enumerate() {
        let path = candidate.path.as_path();
        let under_veto = path.ancestors().any(|ancestor| scopes.contains(ancestor));
        // Path ordering compares components. A descendant, when present, is
        // the first scope at or after this path; prefix siblings do not match.
        let contains_veto = scopes
            .range(candidate.path.clone()..)
            .next()
            .is_some_and(|scope| scope.starts_with(path));
        if under_veto || contains_veto {
            // An alias of a parent that would remove a vetoed descendant is
            // also inadmissible as a WHOLE cleanup unit. Do not promote that
            // parent to a veto scope: doing so would wrongly exclude siblings.
            rejected[roots[index]] = true;
        }
    }
    roots.into_iter().map(|root| rejected[root]).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::pid::PressureLevel;
    use crate::scanner::patterns::ArtifactClassification;
    use crate::scanner::scoring::{
        ArtifactCertainty, DecisionAction, DecisionOutcome, EvidenceLedger, ScoreFactors,
    };
    use crate::scanner::walker::FsEntryKind;
    use std::path::PathBuf;
    use std::time::Duration;

    fn candidate(path: &str, bytes: u64, identity: Option<(u64, u64)>) -> CandidacyScore {
        CandidacyScore {
            path: PathBuf::from(path),
            identity: identity.map(|(device_id, inode)| FsIdentity {
                device_id,
                inode,
                kind: FsEntryKind::Directory,
            }),
            total_score: 0.99,
            factors: ScoreFactors {
                location: 0.9,
                name: 0.9,
                age: 1.0,
                size: 0.5,
                structure: 0.5,
                pressure_multiplier: 1.0,
            },
            vetoed: false,
            veto_reason: None,
            classification: ArtifactClassification::unknown(),
            size_bytes: bytes,
            age: Duration::from_hours(3),
            decision: DecisionOutcome {
                action: DecisionAction::Delete,
                posterior_abandoned: 0.99,
                expected_loss_keep: 0.0,
                expected_loss_delete: 0.0,
                calibration_score: 1.0,
                fallback_active: false,
                certainty: ArtifactCertainty::Likely,
                posterior_floor_applied: false,
                regret_calibration: 1.0,
                category_suspended: false,
            },
            ledger: EvidenceLedger {
                terms: Vec::new(),
                summary: String::new(),
            },
        }
    }

    fn veto(mut candidate: CandidacyScore) -> CandidacyScore {
        candidate.vetoed = true;
        candidate.veto_reason = Some("active or protected contents".to_string());
        candidate
    }

    fn request(target_bytes: Option<u64>) -> PlanRequest {
        PlanRequest {
            level: PressureLevel::Critical,
            target_bytes,
            max_items: 100,
            risk_budget: None,
            false_positive_loss: 50.0,
            include_review: true,
        }
    }

    #[test]
    fn a_vetoed_descendant_excludes_its_parent_but_not_a_safe_sibling() {
        let candidates = vec![
            candidate("/cache/tree", 1000, Some((7, 1))),
            veto(candidate("/cache/tree/busy", 1, Some((7, 2)))),
            candidate("/cache/tree/safe", 4, Some((7, 3))),
            candidate("/cache/tree-other", 6, Some((7, 4))),
        ];
        let req = request(Some(10));
        // Demonstrate the actual old optimizer's failure on this same input.
        let (old, _) = optimization::plan_batch(candidates.clone(), &req);
        assert!(old.iter().any(|candidate| candidate.path == Path::new("/cache/tree")));
        let (chosen, plan) = plan_batch(candidates, &req);
        let paths: BTreeSet<_> = chosen.iter().map(|candidate| candidate.path.as_path()).collect();
        assert_eq!(paths, BTreeSet::from([
            Path::new("/cache/tree/safe"), Path::new("/cache/tree-other"),
        ]));
        assert_eq!(plan.planned_bytes, 10);
        assert_eq!(plan.top_n_bytes, 10);
        assert!(plan.target_met);
        assert!(plan.skipped_for_budget.is_empty());
        assert!(plan.skipped_for_overlap.is_empty());
    }

    #[test]
    fn a_vetoed_root_blocks_descendants_and_conflicting_path_observations() {
        for identity in [None, Some((7, 99))] {
            let blocked = veto(candidate("/cache/held", 1, Some((7, 1))));
            let candidates = vec![
                blocked,
                candidate("/cache/held", 1000, identity),
                candidate("/cache/held/deep/target", 1000, Some((7, 2))),
                candidate("/cache/held-other", 7, None),
            ];
            let (chosen, plan) = plan_batch(candidates, &request(Some(8)));
            assert_eq!(chosen.len(), 1);
            assert_eq!(chosen[0].path, Path::new("/cache/held-other"));
            assert_eq!(plan.planned_bytes, 7);
            assert_eq!(plan.top_n_bytes, 7);
            assert!(!plan.target_met);
        }
    }

    #[test]
    fn veto_scopes_follow_transitive_path_and_identity_aliases() {
        let candidates = vec![
            veto(candidate("/protected/target", 1, Some((7, 1)))),
            candidate("/alias/b", 100, Some((7, 1))),
            candidate("/alias/b", 100, Some((7, 2))),
            candidate("/alias/c", 100, Some((7, 2))),
            candidate("/alias/c/deep", 100, None),
            candidate("/alias/b/deep", 100, Some((7, 3))),
            candidate("/independent", 9, None),
        ];
        assert_eq!(rejected_observations(&candidates), vec![true, true, true, true, true, true, false]);
        let (chosen, plan) = plan_batch(candidates, &request(Some(10)));
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].path, Path::new("/independent"));
        assert_eq!(plan.top_n_bytes, 9);
        assert!(!plan.target_met);
    }

    #[test]
    fn aliases_of_an_unsafe_enclosing_candidate_cannot_restore_its_capacity() {
        let candidates = vec![
            veto(candidate("/cache/tree/busy", 1, Some((7, 1)))),
            candidate("/cache/tree", 1000, Some((7, 2))),
            candidate("/elsewhere/same-tree", 1000, Some((7, 2))),
            candidate("/cache/tree/safe", 5, Some((7, 3))),
        ];
        assert_eq!(rejected_observations(&candidates), vec![true, true, true, false]);
        let (chosen, plan) = plan_batch(candidates, &request(Some(6)));
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].path, Path::new("/cache/tree/safe"));
        assert_eq!(plan.planned_bytes, 5);
        assert!(!plan.target_met);
    }

    #[test]
    fn suspension_is_a_hard_boundary_at_every_pressure_level() {
        for level in [PressureLevel::Green, PressureLevel::Yellow, PressureLevel::Orange,
            PressureLevel::Red, PressureLevel::Critical]
        {
            let mut suspended = candidate("/cache/tree/suspended", 1, None);
            suspended.decision.category_suspended = true;
            suspended.decision.action = DecisionAction::Keep;
            // Invalid scoring evidence cannot erase a separately supplied veto.
            suspended.total_score = f64::NAN;
            suspended.decision.posterior_abandoned = f64::NAN;
            let mut req = request(Some(8));
            req.level = level;
            let (chosen, plan) = plan_batch(vec![
                suspended,
                candidate("/cache/tree", 1000, None),
                candidate("/independent", 7, None),
            ], &req);
            assert_eq!(chosen.len(), 1);
            assert_eq!(chosen[0].path, Path::new("/independent"));
            assert_eq!(plan.planned_bytes, 7);
            assert!(!plan.target_met);
        }
    }

    #[test]
    fn ordinary_keep_and_review_are_not_subtree_protection_markers() {
        for action in [DecisionAction::Keep, DecisionAction::Review] {
            let mut child = candidate("/cache/tree/child", 1, None);
            child.decision.action = action;
            let mut req = request(Some(10));
            req.include_review = false;
            let candidates = vec![child, candidate("/cache/tree", 100, None)];
            let expected = optimization::plan_batch(candidates.clone(), &req);
            assert_eq!(plan_batch(candidates, &req), expected);
            assert_eq!(expected.0[0].path, Path::new("/cache/tree"));
        }
    }

    #[test]
    fn devices_kinds_and_unknown_identities_do_not_share_veto_authority() {
        let blocked = veto(candidate("/blocked", 1, Some((7, 1))));
        let other_device = candidate("/other-device", 3, Some((8, 1)));
        let mut other_kind = candidate("/other-kind", 4, Some((7, 1)));
        other_kind.identity.as_mut().unwrap().kind = FsEntryKind::File;
        let candidates = vec![blocked, other_device, other_kind, candidate("/unknown", 5, None)];
        assert_eq!(rejected_observations(&candidates), vec![true, false, false, false]);
        let (chosen, plan) = plan_batch(candidates, &request(None));
        assert_eq!(chosen.len(), 3);
        assert_eq!(plan.planned_bytes, 12);
    }

    #[cfg(unix)]
    #[test]
    fn native_path_components_are_compared_without_lossy_aliases() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let path = |bytes: &[u8]| PathBuf::from(OsString::from_vec(bytes.to_vec()));
        let mut blocked = veto(candidate("/unused", 1, None));
        blocked.path = path(b"/cache/\xff");
        let mut nested = candidate("/unused", 2, None);
        nested.path = path(b"/cache/\xff/target");
        let mut sibling = candidate("/unused", 3, None);
        sibling.path = path(b"/cache/\xff-other");
        let distinct = candidate("/cache/�", 4, None);
        let candidates = vec![blocked, nested, sibling, distinct];
        assert_eq!(rejected_observations(&candidates), vec![true, true, false, false]);
        assert_eq!(plan_batch(candidates, &request(None)).1.planned_bytes, 7);
    }

    // Independent small-instance reference: explicit graph reachability and
    // all-pairs component-aware containment, not the production union/find or
    // ordered-range lookup. Containment never joins equivalence components.
    fn reference_rejections(candidates: &[CandidacyScore]) -> Vec<bool> {
        let same = |left: usize, right: usize| {
            candidates[left].path == candidates[right].path
                || candidates[left].identity.is_some_and(|id| candidates[right].identity == Some(id))
        };
        let expand = |marked: &mut Vec<bool>| loop {
            let mut changed = false;
            for left in 0..candidates.len() {
                for right in 0..candidates.len() {
                    if marked[left] && !marked[right] && same(left, right) {
                        marked[right] = true;
                        changed = true;
                    }
                }
            }
            if !changed { break; }
        };
        let mut protected: Vec<_> = candidates.iter().map(hard_veto).collect();
        expand(&mut protected);
        let mut rejected = protected.clone();
        for (left, candidate) in candidates.iter().enumerate() {
            for (right, scope) in candidates.iter().enumerate() {
                if protected[right]
                    && (candidate.path.starts_with(&scope.path) || scope.path.starts_with(&candidate.path))
                {
                    rejected[left] = true;
                }
            }
        }
        expand(&mut rejected);
        rejected
    }

    #[test]
    fn public_plans_match_exhaustive_admission_under_permutation() {
        let names = ["/p/a", "/p/a/child", "/p/a-other", "/p/b", "/p/b/child", "/q/a", "/q/b"];
        let mut seed = 0x91e1_0da5_34bf_0821u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for trial in 0..256 {
            let mut candidates: Vec<_> = (0..12).map(|_| {
                let path = names[(next() % names.len() as u64) as usize];
                let identity = (next() % 3 != 0).then(|| (7 + next() % 2, next() % 5));
                let mut candidate = candidate(path, 1 + next() % 100, identity);
                candidate.vetoed = next() % 7 == 0;
                candidate.decision.category_suspended = next() % 13 == 0;
                candidate
            }).collect();
            let mut req = request(Some(120));
            req.max_items = 1 + trial % 5;
            req.risk_budget = Some(1.5);
            let reference = reference_rejections(&candidates);
            assert_eq!(rejected_observations(&candidates), reference);
            let admitted = candidates.iter().zip(&reference)
                .filter(|(_, rejected)| !**rejected)
                .map(|(candidate, _)| candidate.clone())
                .collect();
            let expected = optimization::plan_batch(admitted, &req);
            for _ in 0..4 {
                candidates.rotate_left(3);
                candidates.reverse();
                let actual = plan_batch(candidates.clone(), &req);
                assert_eq!(actual, expected);
                assert!(actual.0.len() <= req.max_items);
                assert!(actual.1.risk_used <= 1.5 + 1e-9);
                assert_eq!(actual.1.planned_bytes, actual.0.iter().map(|c| c.size_bytes).sum::<u64>());
            }
        }
    }
}
