//! Risk-budgeted batch planning (W1, G16).
//!
//! The executor used to take the top-N candidates by composite score. When
//! a byte target is known (`clean --target-free`, the bytes a pressured
//! mount needs to return to Yellow), "highest score first" is not "least
//! risk for the bytes we need": a large candidate at posterior 0.85 is
//! often a better first choice than a small one at 0.95. The decision
//! layer already prices every candidate's loss; this module chooses the
//! *set*.
//!
//! The planner is the fractional-knapsack greedy: order candidates by
//! expected reclaim per unit of expected loss, take them while the level's
//! batch size, the risk budget and the byte target allow, and stop as soon
//! as the target is met. For the shapes that occur here (a handful of
//! candidates, one budget) that is within a constant factor of the 0/1
//! optimum, and every choice is explainable with two numbers.
//!
//! Determinism: ties break on bytes descending, then path ascending, so
//! identical inputs plan identically whatever order the walker found them
//! in (design principle 3).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::monitor::pid::PressureLevel;
use crate::scanner::decision_record::stable_decision_id;
use crate::scanner::scoring::{CandidacyScore, DecisionAction};

/// The risk budget per pressure level as a multiple of one false-positive
/// loss (`scoring.false_positive_loss`): how many "average mistakes" one
/// batch may risk. `None` is unbounded.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RiskBudgetByLevel {
    /// Green: at most one average mistake.
    pub green: f64,
    /// Yellow.
    pub yellow: f64,
    /// Orange.
    pub orange: f64,
    /// Red.
    pub red: f64,
    /// Critical is always unbounded; the field exists so the table reads
    /// whole in the config and `sbh explain`.
    pub critical: Option<f64>,
}

impl Default for RiskBudgetByLevel {
    fn default() -> Self {
        Self {
            green: 1.0,
            yellow: 2.0,
            orange: 5.0,
            red: 10.0,
            critical: None,
        }
    }
}

impl RiskBudgetByLevel {
    /// The budget for `level` in loss units, given one false-positive loss.
    #[must_use]
    pub fn budget(&self, level: PressureLevel, false_positive_loss: f64) -> Option<f64> {
        let multiple = match level {
            PressureLevel::Green => self.green,
            PressureLevel::Yellow => self.yellow,
            PressureLevel::Orange => self.orange,
            PressureLevel::Red => self.red,
            PressureLevel::Critical => return self.critical.map(|m| m * false_positive_loss),
        };
        Some(multiple * false_positive_loss)
    }
}

/// What the planner was asked to do.
#[derive(Debug, Clone, PartialEq)]
pub struct PlanRequest {
    /// The pressure level the batch runs at.
    pub level: PressureLevel,
    /// Bytes the batch should reach; `None` means "as much as the batch
    /// size and budget allow".
    pub target_bytes: Option<u64>,
    /// The level's batch size (0 plans nothing).
    pub max_items: usize,
    /// Risk budget in loss units; `None` is unbounded.
    pub risk_budget: Option<f64>,
    /// One false-positive loss, the unit of `risk_budget`.
    pub false_positive_loss: f64,
    /// Whether `Review` candidates may be planned (emergency only).
    pub include_review: bool,
}

/// One planned or skipped candidate, as the record and `explain` show it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlannedItem {
    /// The candidate's path.
    pub path: PathBuf,
    /// The candidate's stable decision id (`sbh explain --id`).
    pub decision_id: String,
    /// 1-based position in the batch (0 for a skipped candidate).
    pub rank: usize,
    /// Expected reclaim (the candidate's size estimate).
    pub bytes: u64,
    /// Posterior that the candidate is abandoned.
    pub posterior: f64,
    /// `(1 - posterior) * false_positive_loss`.
    pub expected_loss: f64,
    /// Bytes per loss unit, the greedy key.
    pub value: f64,
}

/// The planned batch and its accounting.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BatchPlan {
    /// Pressure level the plan was made for.
    pub level: String,
    /// The byte target, if any.
    pub target_bytes: Option<u64>,
    /// Bytes the chosen set is expected to reclaim.
    pub planned_bytes: u64,
    /// Risk budget in loss units, if bounded.
    pub risk_budget: Option<f64>,
    /// Expected loss of the chosen set.
    pub risk_used: f64,
    /// Chosen candidates in execution order.
    pub chosen: Vec<PlannedItem>,
    /// Plannable candidates the budget or batch size left out.
    pub skipped_for_budget: Vec<PlannedItem>,
    /// Expected loss the top-N-by-score set for the same target would have
    /// carried; what the explanation compares against.
    pub top_n_risk: f64,
    /// Bytes the top-N-by-score set would have reclaimed.
    pub top_n_bytes: u64,
    /// Whether the target was met by the chosen set.
    pub target_met: bool,
}

impl BatchPlan {
    /// One line for the log: `level=.. target_bytes=.. planned_bytes=..
    /// risk_budget=.. risk_used=.. chosen=n skipped_for_budget=m`.
    #[must_use]
    pub fn summary_line(&self) -> String {
        format!(
            "level={} target_bytes={} planned_bytes={} risk_budget={} risk_used={:.2} chosen={} skipped_for_budget={} top_n_risk={:.2}",
            self.level,
            self.target_bytes
                .map_or_else(|| "none".to_string(), |b| b.to_string()),
            self.planned_bytes,
            self.risk_budget
                .map_or_else(|| "unbounded".to_string(), |b| format!("{b:.2}")),
            self.risk_used,
            self.chosen.len(),
            self.skipped_for_budget.len(),
            self.top_n_risk
        )
    }

    /// Why the item at `rank` was chosen, for `explain`.
    #[must_use]
    pub fn explain_choice(&self, rank: usize) -> Option<String> {
        let item = self.chosen.iter().find(|item| item.rank == rank)?;
        let share = if self.top_n_risk > 0.0 {
            format!(
                " with {:.0}% of the risk the top-scored set would use",
                self.risk_used / self.top_n_risk * 100.0
            )
        } else {
            String::new()
        };
        Some(format!(
            "chosen {}: {} at posterior {:.2} (loss {:.1} of budget {}) because it {}{share}",
            ordinal(rank),
            format_bytes(item.bytes),
            item.posterior,
            item.expected_loss,
            self.risk_budget
                .map_or_else(|| "unbounded".to_string(), |b| format!("{b:.1}")),
            if self.target_bytes.is_some() {
                if self.target_met {
                    "reaches the target"
                } else {
                    "moves toward the target"
                }
            } else {
                "reclaims the most per unit of risk"
            }
        ))
    }
}

#[allow(clippy::cast_precision_loss)]
fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn ordinal(n: usize) -> String {
    let suffix = match (n % 10, n % 100) {
        (1, 11) | (2, 12) | (3, 13) => "th",
        (1, _) => "st",
        (2, _) => "nd",
        (3, _) => "rd",
        _ => "th",
    };
    format!("{n}{suffix}")
}

fn plannable(candidate: &CandidacyScore, include_review: bool) -> bool {
    !candidate.vetoed
        && match candidate.decision.action {
            DecisionAction::Delete => true,
            DecisionAction::Review => include_review,
            DecisionAction::Keep => false,
        }
}

#[allow(clippy::cast_precision_loss)]
fn item(candidate: &CandidacyScore, false_positive_loss: f64) -> PlannedItem {
    let posterior = candidate.decision.posterior_abandoned.clamp(0.0, 1.0);
    // A candidate the model is certain about still carries a floor of loss,
    // so the greedy key stays finite and a huge certain candidate does not
    // drown every other consideration.
    let expected_loss = ((1.0 - posterior) * false_positive_loss).max(1e-6);
    PlannedItem {
        path: candidate.path.clone(),
        decision_id: stable_decision_id(&candidate.path, candidate.identity, candidate.size_bytes),
        rank: 0,
        bytes: candidate.size_bytes,
        posterior,
        expected_loss,
        value: candidate.size_bytes as f64 / expected_loss,
    }
}

/// Plan a batch: the chosen candidates in execution order, plus the plan.
///
/// Candidates that are not plannable (vetoed, `Keep`, `Review` outside
/// emergency) are dropped silently; the rest are either chosen or listed
/// under `skipped_for_budget`.
#[must_use]
#[allow(clippy::cast_precision_loss, clippy::too_many_lines)]
pub fn plan_batch(
    candidates: Vec<CandidacyScore>,
    request: &PlanRequest,
) -> (Vec<CandidacyScore>, BatchPlan) {
    let mut plannable: Vec<(PlannedItem, CandidacyScore)> = candidates
        .into_iter()
        .filter(|c| plannable(c, request.include_review))
        .map(|c| (item(&c, request.false_positive_loss), c))
        .collect();

    // The comparison set: top-N by score for the same target.
    let (top_n_bytes, top_n_risk) = {
        let mut by_score: Vec<&(PlannedItem, CandidacyScore)> = plannable.iter().collect();
        by_score.sort_by(|a, b| {
            b.1.total_score
                .partial_cmp(&a.1.total_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.0.bytes.cmp(&a.0.bytes))
                .then_with(|| a.0.path.cmp(&b.0.path))
        });
        let mut bytes = 0u64;
        let mut risk = 0.0;
        for (planned, _) in by_score.into_iter().take(request.max_items) {
            if request.target_bytes.is_some_and(|target| bytes >= target) {
                break;
            }
            bytes = bytes.saturating_add(planned.bytes);
            risk += planned.expected_loss;
        }
        (bytes, risk)
    };

    // Greedy by value; deterministic tie-breaks.
    plannable.sort_by(|a, b| {
        b.0.value
            .partial_cmp(&a.0.value)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.0.bytes.cmp(&a.0.bytes))
            .then_with(|| a.0.path.cmp(&b.0.path))
    });

    // Greedy pass: take in value order whatever the budget, batch size and
    // target still allow. Skipping past an item that does not fit is what
    // makes this a set choice rather than a prefix.
    let mut chosen_idx: Vec<usize> = Vec::new();
    let mut planned_bytes = 0u64;
    let mut risk_used = 0.0f64;
    for (index, (planned, _)) in plannable.iter().enumerate() {
        let target_met = request
            .target_bytes
            .is_some_and(|target| planned_bytes >= target);
        let over_budget = request
            .risk_budget
            .is_some_and(|budget| risk_used + planned.expected_loss > budget + 1e-9);
        if target_met || chosen_idx.len() >= request.max_items || over_budget {
            continue;
        }
        planned_bytes = planned_bytes.saturating_add(planned.bytes);
        risk_used += planned.expected_loss;
        chosen_idx.push(index);
    }
    let mut target_met = request
        .target_bytes
        .is_some_and(|target| planned_bytes >= target);
    // The 2-approximation: when the greedy set falls short of the target
    // (or has none), the single largest candidate that fits the budget on
    // its own beats a bundle of small safe ones if it reclaims more.
    if !target_met && request.max_items >= 1 {
        let best_single = plannable
            .iter()
            .enumerate()
            .filter(|(_, (planned, _))| {
                request
                    .risk_budget
                    .is_none_or(|budget| planned.expected_loss <= budget + 1e-9)
            })
            .max_by(|(_, (a, _)), (_, (b, _))| {
                a.bytes.cmp(&b.bytes).then_with(|| b.path.cmp(&a.path))
            });
        if let Some((index, (planned, _))) = best_single
            && planned.bytes > planned_bytes
        {
            chosen_idx = vec![index];
            planned_bytes = planned.bytes;
            risk_used = planned.expected_loss;
            target_met = request
                .target_bytes
                .is_some_and(|target| planned_bytes >= target);
        }
    }

    let mut chosen = Vec::with_capacity(chosen_idx.len());
    let mut chosen_scores = Vec::with_capacity(chosen_idx.len());
    let mut skipped = Vec::new();
    for (index, (mut planned, score)) in plannable.into_iter().enumerate() {
        if let Some(rank) = chosen_idx
            .iter()
            .position(|&chosen_index| chosen_index == index)
        {
            planned.rank = rank + 1;
            chosen.push(planned);
            chosen_scores.push(score);
        } else {
            skipped.push(planned);
        }
    }
    // Only budget/size skips are worth listing; a target already met is a
    // success, not a skip.
    if target_met {
        skipped.clear();
    }
    let plan = BatchPlan {
        level: format!("{:?}", request.level).to_lowercase(),
        target_bytes: request.target_bytes,
        planned_bytes,
        risk_budget: request.risk_budget,
        risk_used,
        chosen,
        skipped_for_budget: skipped,
        top_n_risk,
        top_n_bytes,
        target_met,
    };
    (chosen_scores, plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::patterns::ArtifactClassification;
    use crate::scanner::scoring::{
        ArtifactCertainty, DecisionOutcome, EvidenceLedger, ScoreFactors,
    };
    use std::path::Path;
    use std::time::Duration;

    fn candidate(
        path: &str,
        bytes: u64,
        posterior: f64,
        score: f64,
        action: DecisionAction,
    ) -> CandidacyScore {
        CandidacyScore {
            path: PathBuf::from(path),
            identity: None,
            total_score: score,
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
                action,
                posterior_abandoned: posterior,
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

    fn request(level: PressureLevel, target: Option<u64>, budget: Option<f64>) -> PlanRequest {
        PlanRequest {
            level,
            target_bytes: target,
            max_items: 10,
            risk_budget: budget,
            false_positive_loss: 50.0,
            include_review: false,
        }
    }

    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;

    #[test]
    fn the_large_mid_posterior_candidate_goes_first_for_a_byte_target() {
        let candidates = vec![
            candidate("/p/small", 200 * MIB, 0.95, 2.0, DecisionAction::Delete),
            candidate("/p/large", 40 * GIB, 0.85, 1.6, DecisionAction::Delete),
            candidate("/p/medium", 2 * GIB, 0.90, 1.8, DecisionAction::Delete),
        ];
        let (chosen, plan) = plan_batch(
            candidates,
            &request(PressureLevel::Orange, Some(30 * GIB), Some(250.0)),
        );
        assert_eq!(chosen.len(), 1, "{plan:?}");
        assert_eq!(chosen[0].path, Path::new("/p/large"));
        assert!(plan.target_met);
        assert_eq!(plan.planned_bytes, 40 * GIB);
        assert!((plan.risk_used - 7.5).abs() < 1e-9, "{}", plan.risk_used);
        // Top-N by score would have taken small, medium, large: 2.5 + 5 + 7.5.
        assert!((plan.top_n_risk - 15.0).abs() < 1e-9, "{}", plan.top_n_risk);
        assert!(plan.risk_used < plan.top_n_risk);
        assert!(
            plan.skipped_for_budget.is_empty(),
            "a met target is not a skip"
        );
        let why = plan.explain_choice(1).unwrap();
        assert!(why.contains("chosen 1st"), "{why}");
        assert!(why.contains("posterior 0.85"), "{why}");
        assert!(why.contains("reaches the target"), "{why}");
        assert!(why.contains("50% of the risk"), "{why}");
        assert!(
            plan.summary_line()
                .starts_with("level=orange target_bytes=")
        );
    }

    #[test]
    fn budget_and_batch_size_bound_the_set_and_list_the_skipped() {
        let candidates = vec![
            candidate("/p/a", 10 * GIB, 0.60, 1.0, DecisionAction::Delete), // loss 20
            candidate("/p/b", 10 * GIB, 0.70, 1.0, DecisionAction::Delete), // loss 15
            candidate("/p/c", 10 * GIB, 0.90, 1.0, DecisionAction::Delete), // loss 5
            candidate("/p/d", GIB, 0.99, 1.0, DecisionAction::Delete),      // loss 0.5
        ];
        let (chosen, plan) = plan_batch(
            candidates.clone(),
            &request(PressureLevel::Green, None, Some(21.0)),
        );
        let paths: Vec<_> = chosen
            .iter()
            .map(|c| c.path.to_string_lossy().into_owned())
            .collect();
        // Greedy by bytes/loss: c (2 GiB/unit), d (2 GiB/unit, fewer bytes), b, a.
        // c (5) + d (0.5) + b (15) = 20.5 fits; a (20) does not.
        assert_eq!(paths, vec!["/p/c", "/p/d", "/p/b"], "{plan:?}");
        assert_eq!(plan.skipped_for_budget.len(), 1);
        assert_eq!(plan.skipped_for_budget[0].path, Path::new("/p/a"));
        assert!(!plan.target_met);
        assert!(plan.risk_used <= 21.0);
        let mut small = request(PressureLevel::Green, None, None);
        small.max_items = 2;
        let (chosen, plan) = plan_batch(candidates, &small);
        assert_eq!(chosen.len(), 2);
        assert_eq!(plan.skipped_for_budget.len(), 2);
    }

    #[test]
    fn review_is_planned_only_in_emergency_and_keep_never() {
        let candidates = vec![
            candidate("/p/review", 5 * GIB, 0.9, 1.0, DecisionAction::Review),
            candidate("/p/keep", 5 * GIB, 0.9, 1.0, DecisionAction::Keep),
            candidate("/p/delete", GIB, 0.9, 1.0, DecisionAction::Delete),
        ];
        let (chosen, plan) =
            plan_batch(candidates.clone(), &request(PressureLevel::Red, None, None));
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].path, Path::new("/p/delete"));
        assert!(
            plan.skipped_for_budget.is_empty(),
            "unplannable candidates are not skips"
        );
        let mut emergency = request(PressureLevel::Critical, None, None);
        emergency.include_review = true;
        let (chosen, _) = plan_batch(candidates, &emergency);
        assert_eq!(chosen.len(), 2);
        assert!(
            chosen
                .iter()
                .all(|c| c.decision.action != DecisionAction::Keep)
        );
    }

    #[test]
    fn level_budgets_scale_and_critical_is_unbounded() {
        let table = RiskBudgetByLevel::default();
        assert_eq!(table.budget(PressureLevel::Green, 50.0), Some(50.0));
        assert_eq!(table.budget(PressureLevel::Yellow, 50.0), Some(100.0));
        assert_eq!(table.budget(PressureLevel::Orange, 50.0), Some(250.0));
        assert_eq!(table.budget(PressureLevel::Red, 50.0), Some(500.0));
        assert_eq!(table.budget(PressureLevel::Critical, 50.0), None);
        let bounded = RiskBudgetByLevel {
            critical: Some(20.0),
            ..RiskBudgetByLevel::default()
        };
        assert_eq!(bounded.budget(PressureLevel::Critical, 50.0), Some(1000.0));
    }

    #[test]
    fn plans_are_deterministic_under_permutation() {
        let base = vec![
            candidate("/p/a", 3 * GIB, 0.80, 1.0, DecisionAction::Delete),
            candidate("/p/b", 3 * GIB, 0.80, 1.2, DecisionAction::Delete),
            candidate("/p/c", 6 * GIB, 0.60, 1.4, DecisionAction::Delete),
            candidate("/p/d", 512 * MIB, 0.99, 1.1, DecisionAction::Delete),
            candidate("/p/e", 3 * GIB, 0.80, 0.9, DecisionAction::Delete),
        ];
        let req = request(PressureLevel::Yellow, Some(7 * GIB), Some(100.0));
        let (reference, reference_plan) = plan_batch(base.clone(), &req);
        let reference_paths: Vec<_> = reference.iter().map(|c| c.path.clone()).collect();
        let mut seed = 0x1234_5678u64;
        for _ in 0..50 {
            let mut shuffled = base.clone();
            for i in (1..shuffled.len()).rev() {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let j = usize::try_from(seed % (i as u64 + 1)).unwrap_or(0);
                shuffled.swap(i, j);
            }
            let (chosen, plan) = plan_batch(shuffled, &req);
            let paths: Vec<_> = chosen.iter().map(|c| c.path.clone()).collect();
            assert_eq!(paths, reference_paths);
            assert_eq!(plan, reference_plan);
        }
        // Equal value, equal bytes: path ascending decides.
        assert_eq!(reference_paths[0], Path::new("/p/d"), "{reference_paths:?}");
    }

    /// The greedy set is never over budget and reclaims at least half of
    /// what the best 0/1 subset within the same budget would, on random
    /// small instances.
    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn greedy_is_within_factor_two_of_the_brute_force_optimum() {
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _case in 0..300 {
            let n = 2 + (next() % 7) as usize;
            let candidates: Vec<CandidacyScore> = (0..n)
                .map(|i| {
                    let bytes = (1 + next() % 64) * MIB;
                    let posterior = 0.5 + (next() % 50) as f64 / 100.0;
                    candidate(
                        &format!("/p/{i}"),
                        bytes,
                        posterior,
                        1.0,
                        DecisionAction::Delete,
                    )
                })
                .collect();
            let losses: Vec<f64> = candidates
                .iter()
                .map(|c| ((1.0 - c.decision.posterior_abandoned) * 50.0).max(1e-6))
                .collect();
            let total_loss: f64 = losses.iter().sum();
            let budget = total_loss * (0.2 + (next() % 60) as f64 / 100.0);
            let mut req = request(PressureLevel::Orange, None, Some(budget));
            req.max_items = n;
            let (chosen, plan) = plan_batch(candidates.clone(), &req);
            assert!(plan.risk_used <= budget + 1e-6, "over budget: {plan:?}");
            let greedy_bytes: u64 = chosen.iter().map(|c| c.size_bytes).sum();
            assert_eq!(greedy_bytes, plan.planned_bytes);
            // Brute force over all subsets.
            let mut best = 0u64;
            for mask in 0u32..(1 << n) {
                let mut loss = 0.0;
                let mut bytes = 0u64;
                for (i, c) in candidates.iter().enumerate() {
                    if mask & (1 << i) != 0 {
                        loss += losses[i];
                        bytes += c.size_bytes;
                    }
                }
                if loss <= budget + 1e-9 {
                    best = best.max(bytes);
                }
            }
            // Greedy plus the first skipped item exceeds the optimum for a
            // fractional knapsack, so greedy alone is at least half of it
            // whenever the optimum is nonzero.
            assert!(
                greedy_bytes * 2 >= best || best == 0,
                "greedy {greedy_bytes} vs optimum {best}: {plan:?}"
            );
        }
    }
}
