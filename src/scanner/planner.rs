//! Risk-budgeted batch planning with a hard safety-admission boundary.
//!
//! A vetoed descendant cannot be removed indirectly by selecting its parent.
//! Likewise, a vetoed root cannot be bypassed by selecting one of its children,
//! another observation at the same path, or an observed identity alias. Perform
//! these checks before any risk/byte optimization or counterfactual accounting.
//!
//! Directory aliases also carry their descendants' vetoes: if `/a` and `/b`
//! name the same directory, `/a/busy` protects `/b/busy/child` even without an
//! observation of `/b/busy` itself. Only prefixes of supplied paths are stored;
//! alias cycles never generate an unbounded set of synthetic pathnames.
//! Ordinary batches without aliases use direct path scopes instead of building
//! that graph; alias detection includes observations that cannot be selected.
//!
//! Admission uses only the observations supplied in this batch. It neither
//! canonicalizes paths nor discovers unseen aliases, mounts or active references.
//! The executor must still perform fresh identity, protection and lease checks.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsString;
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

fn has_path_aliases(candidates: &[CandidacyScore]) -> bool {
    let mut identities: HashMap<FsIdentity, &Path> = HashMap::new();
    for candidate in candidates {
        if let Some(identity) = candidate.identity
            && let Some(previous) = identities.insert(identity, candidate.path.as_path())
            && previous != candidate.path.as_path()
        {
            return true;
        }
    }
    false
}

fn rejected_observations(candidates: &[CandidacyScore]) -> Vec<bool> {
    // Most walks observe each physical entry at one path. Do not materialize
    // every path prefix and graph edge just because one candidate is protected.
    // Keep/invalid-score observations still participate in alias detection.
    if has_path_aliases(candidates) {
        return rejected_with_aliases(candidates);
    }
    let scopes: BTreeSet<_> = candidates
        .iter()
        .filter(|candidate| hard_veto(candidate))
        .map(|candidate| candidate.path.clone())
        .collect();
    candidates
        .iter()
        .map(|candidate| {
            let path = candidate.path.as_path();
            path.ancestors().any(|ancestor| scopes.contains(ancestor))
                || scopes
                    .range(candidate.path.clone()..)
                    .next()
                    .is_some_and(|scope| scope.starts_with(path))
        })
        .collect()
}

/// Identity/path equivalence, closed under equal child names. Children of
/// equivalent directories are equivalent observations too, including prefix
/// nodes for which the batch has no separate candidacy score.
///
/// Containment is NOT an equivalence edge. In particular, rejecting a parent
/// because it contains a protected child must not protect its safe siblings.
struct Groups {
    parent: Vec<usize>,
    size: Vec<usize>,
    children: Vec<BTreeMap<OsString, usize>>,
}

impl Groups {
    fn new(len: usize) -> Self {
        Self {
            parent: (0..len).collect(),
            size: vec![1; len],
            children: vec![BTreeMap::new(); len],
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
        // Iterative congruence closure also handles an observed directory
        // aliasing one of its ancestors. No recursion or path expansion.
        let mut pending = vec![(left, right)];
        while let Some((left, right)) = pending.pop() {
            let mut left = self.root(left);
            let mut right = self.root(right);
            if left == right {
                continue;
            }
            if self.size[left] < self.size[right] {
                std::mem::swap(&mut left, &mut right);
            }
            self.parent[right] = left;
            self.size[left] += self.size[right];
            // Move the smaller group's edges. Each edge is moved only as its
            // owning equivalence class grows; duplicate labels induce unions.
            for (name, child) in std::mem::take(&mut self.children[right]) {
                if let Some(previous) = self.children[left].insert(name, child) {
                    pending.push((previous, child));
                }
            }
        }
    }
}

fn mark_reachable(marked: &mut [bool], edges: &[Vec<usize>]) {
    let mut pending: Vec<_> = marked
        .iter()
        .enumerate()
        .filter_map(|(index, &marked)| marked.then_some(index))
        .collect();
    while let Some(index) = pending.pop() {
        for &next in &edges[index] {
            if !marked[next] {
                marked[next] = true;
                pending.push(next);
            }
        }
    }
}

fn rejected_with_aliases(candidates: &[CandidacyScore]) -> Vec<bool> {
    // The finite prefix trie is bounded by the input's total path components,
    // not by the filesystem's size or the number of spellings an alias cycle
    // could produce. Native components are never converted through UTF-8.
    let mut paths: BTreeMap<&Path, usize> = BTreeMap::new();
    let mut observations = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let next = paths.len();
        observations.push(*paths.entry(candidate.path.as_path()).or_insert(next));
        for ancestor in candidate.path.ancestors().skip(1) {
            let next = paths.len();
            paths.entry(ancestor).or_insert(next);
        }
    }
    let mut groups = Groups::new(paths.len());
    for (&path, &index) in &paths {
        if let Some(parent) = path.parent()
            && let Some(&parent_index) = paths.get(parent)
            && let Some(name) = path.components().next_back()
        {
            groups.children[parent_index].insert(name.as_os_str().to_os_string(), index);
        }
    }
    let mut identities: HashMap<FsIdentity, usize> = HashMap::new();
    for (candidate, &index) in candidates.iter().zip(&observations) {
        if let Some(identity) = candidate.identity
            && let Some(previous) = identities.insert(identity, index)
        {
            groups.unite(index, previous);
        }
    }
    let roots: Vec<_> = (0..paths.len()).map(|index| groups.root(index)).collect();
    let mut descendants = vec![Vec::new(); paths.len()];
    let mut ancestors = vec![Vec::new(); paths.len()];
    for (parent, children) in groups.children.iter().enumerate() {
        for &child in children.values() {
            descendants[roots[parent]].push(roots[child]);
            ancestors[roots[child]].push(roots[parent]);
        }
    }
    let mut rejected = vec![false; paths.len()];
    for (candidate, &index) in candidates.iter().zip(&observations) {
        if hard_veto(candidate) {
            rejected[roots[index]] = true;
        }
    }
    // First protect the vetoed subtrees, across all observed directory aliases.
    mark_reachable(&mut rejected, &descendants);
    // Then refuse enclosing cleanup units. NEVER feed this upward result into
    // downward propagation: their independently safe siblings stay eligible.
    mark_reachable(&mut rejected, &ancestors);
    observations
        .into_iter()
        .map(|index| rejected[roots[index]])
        .collect()
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
        candidate.veto_reason = Some("active or protected contents".into());
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
        assert!(
            old.iter()
                .any(|candidate| candidate.path == Path::new("/cache/tree"))
        );
        let (chosen, plan) = plan_batch(candidates, &req);
        let paths: BTreeSet<_> = chosen
            .iter()
            .map(|candidate| candidate.path.as_path())
            .collect();
        assert_eq!(
            paths,
            BTreeSet::from([
                Path::new("/cache/tree/safe"),
                Path::new("/cache/tree-other"),
            ])
        );
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
        assert_eq!(
            rejected_observations(&candidates),
            vec![true, true, true, true, true, true, false]
        );
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
        assert_eq!(
            rejected_observations(&candidates),
            vec![true, true, true, false]
        );
        let (chosen, plan) = plan_batch(candidates, &request(Some(6)));
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].path, Path::new("/cache/tree/safe"));
        assert_eq!(plan.planned_bytes, 5);
        assert!(!plan.target_met);
    }

    #[test]
    fn suspension_is_a_hard_boundary_at_every_pressure_level() {
        for level in [
            PressureLevel::Green,
            PressureLevel::Yellow,
            PressureLevel::Orange,
            PressureLevel::Red,
            PressureLevel::Critical,
        ] {
            let mut suspended = candidate("/cache/tree/suspended", 1, None);
            suspended.decision.category_suspended = true;
            suspended.decision.action = DecisionAction::Keep;
            // Invalid scoring evidence cannot erase a separately supplied veto.
            suspended.total_score = f64::NAN;
            suspended.decision.posterior_abandoned = f64::NAN;
            let mut req = request(Some(8));
            req.level = level;
            let (chosen, plan) = plan_batch(
                vec![
                    suspended,
                    candidate("/cache/tree", 1000, None),
                    candidate("/independent", 7, None),
                ],
                &req,
            );
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
        let candidates = vec![
            blocked,
            other_device,
            other_kind,
            candidate("/unknown", 5, None),
        ];
        assert_eq!(
            rejected_observations(&candidates),
            vec![true, false, false, false]
        );
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
        assert_eq!(
            rejected_observations(&candidates),
            vec![true, true, false, false]
        );
        assert_eq!(plan_batch(candidates, &request(None)).1.planned_bytes, 7);
    }

    #[test]
    fn a_veto_follows_parent_aliases_without_an_explicit_child_observation() {
        let candidates = vec![
            candidate("/cache/tree", 1000, Some((7, 1))),
            candidate("/mirror", 1000, Some((7, 1))),
            veto(candidate("/cache/tree/busy", 1, Some((7, 2)))),
            candidate("/mirror/busy/deep", 1000, None),
            candidate("/mirror/safe", 5, Some((7, 3))),
            candidate("/independent", 7, None),
        ];
        assert_eq!(
            direct_reference_rejections(&candidates),
            vec![true, true, true, false, false, false],
            "the previous boundary missed the aliased descendant"
        );
        assert_eq!(
            rejected_observations(&candidates),
            vec![true, true, true, true, false, false]
        );
        let (chosen, plan) = plan_batch(candidates, &request(Some(13)));
        let paths: BTreeSet<_> = chosen.iter().map(|c| c.path.as_path()).collect();
        assert_eq!(
            paths,
            BTreeSet::from([Path::new("/mirror/safe"), Path::new("/independent")])
        );
        assert_eq!(plan.planned_bytes, 12);
        assert_eq!(plan.top_n_bytes, 12);
        assert!(!plan.target_met);
        assert!(plan.skipped_for_budget.is_empty());
        assert!(plan.skipped_for_overlap.is_empty());
    }

    #[test]
    fn nested_directory_aliases_reach_a_fixed_point_independently_of_order() {
        let mut candidates = vec![
            candidate("/a", 1000, Some((7, 1))),
            candidate("/b", 1000, Some((7, 1))),
            candidate("/a/sub", 1000, Some((7, 2))),
            candidate("/third", 1000, Some((7, 2))),
            veto(candidate("/third/busy", 1, None)),
            candidate("/b/sub/busy/deep", 1000, None),
            candidate("/b/sub/safe", 5, None),
            candidate("/b/other", 7, None),
        ];
        let expected = BTreeSet::from([
            PathBuf::from("/b/sub/safe"),
            PathBuf::from("/b/other"),
        ]);
        for _ in 0..candidates.len() {
            let actual: BTreeSet<_> = candidates
                .iter()
                .zip(rejected_observations(&candidates))
                .filter(|(_, rejected)| !*rejected)
                .map(|(candidate, _)| candidate.path.clone())
                .collect();
            assert_eq!(actual, expected);
            candidates.rotate_left(1);
        }
        candidates.reverse();
        assert_eq!(
            rejected_observations(&candidates),
            reference_rejections(&candidates)
        );
    }

    #[test]
    fn directory_alias_cycles_terminate_without_protecting_safe_siblings() {
        let candidates = vec![
            candidate("/tree", 1000, Some((7, 1))),
            candidate("/tree/again", 1000, Some((7, 1))),
            veto(candidate("/tree/busy", 1, None)),
            candidate("/tree/again/again/busy/deep", 1000, None),
            candidate("/tree/again/safe", 5, None),
            candidate("/other", 7, None),
        ];
        assert_eq!(
            rejected_observations(&candidates),
            vec![true, true, true, true, false, false]
        );
        let (chosen, plan) = plan_batch(candidates, &request(Some(13)));
        assert_eq!(chosen.len(), 2);
        assert_eq!(plan.planned_bytes, 12);
        assert!(!plan.target_met);
    }

    #[test]
    fn a_veto_below_an_alias_refuses_the_other_aliases_enclosing_scope() {
        let candidates = vec![
            candidate("/source", 1000, Some((7, 1))),
            candidate("/holder/alias", 1000, Some((7, 1))),
            veto(candidate("/source/held", 1, None)),
            candidate("/holder", 1000, None),
            candidate("/holder/safe", 5, None),
        ];
        assert_eq!(
            rejected_observations(&candidates),
            vec![true, true, true, true, false]
        );
        assert_eq!(plan_batch(candidates, &request(None)).1.planned_bytes, 5);
    }

    #[cfg(unix)]
    #[test]
    fn directory_alias_child_names_preserve_native_bytes() {
        use std::os::unix::ffi::OsStringExt;
        let mut held = veto(candidate("/unused", 1, None));
        held.path = PathBuf::from(OsString::from_vec(b"/a/\xff".to_vec()));
        let mut child = candidate("/unused", 1000, None);
        child.path = PathBuf::from(OsString::from_vec(b"/b/\xff/deep".to_vec()));
        let candidates = vec![
            candidate("/a", 1000, Some((7, 1))),
            candidate("/b", 1000, Some((7, 1))),
            held,
            child,
            candidate("/b/�/deep", 5, None),
        ];
        assert_eq!(
            rejected_observations(&candidates),
            vec![true, true, true, true, false]
        );
        assert_eq!(plan_batch(candidates, &request(None)).1.planned_bytes, 5);
    }

    #[test]
    fn alias_detection_requires_a_full_identity_at_distinct_paths() {
        let mut other_kind = candidate("/file", 1, Some((7, 1)));
        other_kind.identity.as_mut().unwrap().kind = FsEntryKind::File;
        let mut candidates = vec![
            candidate("/a", 1, Some((7, 1))),
            candidate("/a", 2, Some((7, 1))),
            candidate("/a", 3, Some((7, 2))),
            candidate("/other-device", 4, Some((8, 1))),
            other_kind,
            candidate("/unknown", 5, None),
            candidate("/other-unknown", 6, None),
        ];
        assert!(!has_path_aliases(&candidates));
        candidates.push(candidate("/b", 7, Some((7, 2))));
        assert!(has_path_aliases(&candidates));
    }

    #[test]
    fn large_nonaliased_batches_preserve_every_independent_sibling() {
        let mut candidates = Vec::new();
        let mut expected = Vec::new();
        for index in 0..5000u64 {
            let path = format!("/cache/group-{index}/target");
            let mut root = candidate(&path, 1000, Some((7, index + 1)));
            root.vetoed = index % 1000 == 0;
            expected.extend([root.vetoed, root.vetoed, false]);
            candidates.push(root);
            candidates.push(candidate(&format!("{path}/child"), 1, None));
            candidates.push(candidate(&format!("/cache/group-{index}/safe"), 1, None));
        }
        assert!(!has_path_aliases(&candidates));
        let actual = rejected_observations(&candidates);
        assert_eq!(actual, expected);
        assert_eq!(actual.iter().filter(|&&rejected| rejected).count(), 10);
    }

    #[test]
    fn nonplannable_alias_evidence_still_propagates_category_suspensions() {
        for level in [
            PressureLevel::Green,
            PressureLevel::Yellow,
            PressureLevel::Orange,
            PressureLevel::Red,
            PressureLevel::Critical,
        ] {
            let mut source = candidate("/a", 1000, Some((7, 1)));
            source.decision.action = DecisionAction::Keep;
            source.total_score = f64::NAN;
            let mut alias = source.clone();
            alias.path = PathBuf::from("/b");
            let mut suspended = candidate("/a/busy", 1, None);
            suspended.decision.action = DecisionAction::Keep;
            suspended.decision.category_suspended = true;
            suspended.decision.posterior_abandoned = f64::NAN;
            let candidates = vec![
                source,
                alias,
                suspended,
                candidate("/b/busy/deep", 1000, None),
                candidate("/b/safe", 5, None),
            ];
            assert!(has_path_aliases(&candidates));
            let mut req = request(Some(6));
            req.level = level;
            req.include_review = false;
            let (chosen, plan) = plan_batch(candidates, &req);
            assert_eq!(chosen.len(), 1);
            assert_eq!(chosen[0].path, Path::new("/b/safe"));
            assert_eq!(plan.planned_bytes, 5);
            assert_eq!(plan.top_n_bytes, 5);
            assert!(!plan.target_met);
        }
    }

    // Previous small-instance oracle, retained to assert no old refusal is
    // weakened. Its direct path/identity relation does not infer descendants
    // of parent aliases; the concrete regressions above pin the difference.
    fn direct_reference_rejections(candidates: &[CandidacyScore]) -> Vec<bool> {
        let same = |left: usize, right: usize| {
            candidates[left].path == candidates[right].path
                || candidates[left]
                    .identity
                    .is_some_and(|id| candidates[right].identity == Some(id))
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
            if !changed {
                break;
            }
        };
        let mut protected: Vec<_> = candidates.iter().map(hard_veto).collect();
        expand(&mut protected);
        let mut rejected = protected.clone();
        for (left, candidate) in candidates.iter().enumerate() {
            for (right, scope) in candidates.iter().enumerate() {
                if protected[right]
                    && (candidate.path.starts_with(&scope.path)
                        || scope.path.starts_with(&candidate.path))
                {
                    rejected[left] = true;
                }
            }
        }
        expand(&mut rejected);
        rejected
    }

    fn reference_equivalence(
        candidates: &[CandidacyScore],
        paths: &[&Path],
        observations: &[usize],
    ) -> Vec<Vec<bool>> {
        let parents: Vec<_> = paths
            .iter()
            .map(|path| {
                path.parent()
                    .and_then(|parent| paths.iter().position(|path| *path == parent))
            })
            .collect();
        let mut equivalent = vec![vec![false; paths.len()]; paths.len()];
        for (index, row) in equivalent.iter_mut().enumerate() {
            row[index] = true;
        }
        for (left, candidate) in candidates.iter().enumerate() {
            for (right, other) in candidates.iter().enumerate() {
                if candidate
                    .identity
                    .is_some_and(|identity| other.identity == Some(identity))
                {
                    equivalent[observations[left]][observations[right]] = true;
                }
            }
        }
        loop {
            let mut changed = false;
            for (via, _) in paths.iter().enumerate() {
                for (left, _) in paths.iter().enumerate() {
                    for (right, _) in paths.iter().enumerate() {
                        if equivalent[left][via]
                            && equivalent[via][right]
                            && !equivalent[left][right]
                        {
                            equivalent[left][right] = true;
                            changed = true;
                        }
                    }
                }
            }
            for (left, path) in paths.iter().enumerate() {
                for (right, other) in paths.iter().enumerate() {
                    if let (Some(a), Some(b)) = (parents[left], parents[right])
                        && equivalent[a][b]
                        && path.components().next_back() == other.components().next_back()
                        && !equivalent[left][right]
                    {
                        equivalent[left][right] = true;
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
        equivalent
    }

    // Independent small-instance oracle: an explicit all-pairs equivalence
    // relation, transitive closure and pairwise path containment. No production
    // trie unions, edge merging or reachability helpers are used here.
    fn reference_rejections(candidates: &[CandidacyScore]) -> Vec<bool> {
        let paths: Vec<_> = candidates
            .iter()
            .flat_map(|candidate| candidate.path.ancestors())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let observations: Vec<_> = candidates
            .iter()
            .map(|candidate| {
                paths
                    .iter()
                    .position(|path| *path == candidate.path)
                    .unwrap()
            })
            .collect();
        let equivalent = reference_equivalence(candidates, &paths, &observations);
        let mut marked = vec![false; paths.len()];
        for (candidate, &index) in candidates.iter().zip(&observations) {
            marked[index] |= hard_veto(candidate);
        }
        for upwards in [false, true] {
            loop {
                let mut changed = false;
                for (left, path) in paths.iter().enumerate() {
                    for (right, other) in paths.iter().enumerate() {
                        let contains = if upwards {
                            path.starts_with(other)
                        } else {
                            other.starts_with(path)
                        };
                        if marked[left] && !marked[right] && (equivalent[left][right] || contains) {
                            marked[right] = true;
                            changed = true;
                        }
                    }
                }
                if !changed {
                    break;
                }
            }
        }
        observations.into_iter().map(|index| marked[index]).collect()
    }

    #[test]
    fn public_plans_match_exhaustive_admission_under_permutation() {
        let names = [
            "/p/a",
            "/p/a/child",
            "/p/a-other",
            "/p/b",
            "/p/b/child",
            "/q/a",
            "/q/b",
        ];
        let mut seed = 0x91e1_0da5_34bf_0821u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for trial in 0..256 {
            let mut candidates: Vec<_> = (0..12)
                .map(|_| {
                    let index = usize::try_from(next() % names.len() as u64).unwrap();
                    let path = names[index];
                    let identity = (next() % 3 != 0).then(|| (7 + next() % 2, next() % 5));
                    let mut candidate = candidate(path, 1 + next() % 100, identity);
                    candidate.vetoed = next() % 7 == 0;
                    candidate.decision.category_suspended = next() % 13 == 0;
                    candidate
                })
                .collect();
            let mut req = request(Some(120));
            req.max_items = 1 + trial % 5;
            req.risk_budget = Some(1.5);
            let reference = reference_rejections(&candidates);
            assert_eq!(rejected_observations(&candidates), reference);
            if !has_path_aliases(&candidates) {
                assert_eq!(rejected_with_aliases(&candidates), reference);
            }
            let old = direct_reference_rejections(&candidates);
            for (old, &current) in old.iter().zip(&reference) {
                assert!(!old || current, "an existing veto must never be weakened");
            }
            let admitted = candidates
                .iter()
                .zip(&reference)
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
                assert_eq!(
                    actual.1.planned_bytes,
                    actual.0.iter().map(|c| c.size_bytes).sum::<u64>()
                );
            }
        }
    }
}
