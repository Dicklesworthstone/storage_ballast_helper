//! Multi-factor candidacy scoring engine: location, name, age, size, structure weights
//! with hard vetoes and pressure multiplier.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::cmp::Ordering;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use crate::core::config::ScoringConfig;
use crate::scanner::patterns::{ArtifactCategory, ArtifactClassification, StructuralSignals};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScoringWeights {
    pub location: f64,
    pub name: f64,
    pub age: f64,
    pub size: f64,
    pub structure: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScoreFactors {
    pub location: f64,
    pub name: f64,
    pub age: f64,
    pub size: f64,
    pub structure: f64,
    pub pressure_multiplier: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionAction {
    Keep,
    Delete,
    Review,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceTerm {
    pub name: &'static str,
    pub weight: f64,
    pub value: f64,
    pub contribution: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceLedger {
    pub terms: Vec<EvidenceTerm>,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DecisionOutcome {
    pub action: DecisionAction,
    pub posterior_abandoned: f64,
    pub expected_loss_keep: f64,
    pub expected_loss_delete: f64,
    pub calibration_score: f64,
    pub fallback_active: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CandidacyScore {
    pub path: PathBuf,
    pub total_score: f64,
    pub factors: ScoreFactors,
    pub vetoed: bool,
    pub veto_reason: Option<String>,
    pub classification: ArtifactClassification,
    pub size_bytes: u64,
    pub age: Duration,
    pub decision: DecisionOutcome,
    pub ledger: EvidenceLedger,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CandidateInput {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub age: Duration,
    pub classification: ArtifactClassification,
    pub signals: StructuralSignals,
    pub is_open: bool,
    pub excluded: bool,
}

/// Deterministic score engine with expected-loss decision layer.
#[derive(Debug, Clone)]
pub struct ScoringEngine {
    weights: ScoringWeights,
    min_file_age: Duration,
    min_score: f64,
    false_positive_loss: f64,
    false_negative_loss: f64,
    calibration_floor: f64,
}

impl ScoringEngine {
    #[must_use]
    pub fn from_config(scoring: &ScoringConfig, min_file_age_minutes: u64) -> Self {
        Self {
            weights: ScoringWeights {
                location: scoring.location_weight,
                name: scoring.name_weight,
                age: scoring.age_weight,
                size: scoring.size_weight,
                structure: scoring.structure_weight,
            },
            min_file_age: Duration::from_secs(min_file_age_minutes.saturating_mul(60)),
            min_score: scoring.min_score,
            false_positive_loss: scoring.false_positive_loss,
            false_negative_loss: scoring.false_negative_loss,
            calibration_floor: scoring.calibration_floor,
        }
    }

    /// Score one candidate deterministically.
    #[must_use]
    pub fn score_candidate(&self, input: &CandidateInput, urgency: f64) -> CandidacyScore {
        if let Some(reason) = self.veto_reason(input) {
            return self.vetoed(input, reason);
        }

        let factors = ScoreFactors {
            location: factor_location(&input.path),
            name: factor_name(&input.path, &input.classification),
            age: factor_age(input.age),
            size: factor_size(input.size_bytes),
            structure: factor_structure(input.signals),
            pressure_multiplier: pressure_multiplier(urgency),
        };

        let base = self.weights.structure.mul_add(
            factors.structure,
            self.weights.size.mul_add(
                factors.size,
                self.weights.age.mul_add(
                    factors.age,
                    self.weights
                        .location
                        .mul_add(factors.location, self.weights.name * factors.name),
                ),
            ),
        );
        let total = (base * factors.pressure_multiplier).clamp(0.0, 3.0);

        let posterior_abandoned =
            posterior_from_score(total, input.classification.combined_confidence);
        let base_expected_loss_keep = posterior_abandoned * self.false_negative_loss;
        let base_expected_loss_delete = (1.0 - posterior_abandoned) * self.false_positive_loss;
        let calibration = calibration_score(input.classification.combined_confidence, factors);
        let fallback_active = calibration < self.calibration_floor;
        let uncertainty = epistemic_uncertainty(posterior_abandoned, calibration);
        let (expected_loss_keep, expected_loss_delete) = uncertainty_adjusted_losses(
            base_expected_loss_keep,
            base_expected_loss_delete,
            posterior_abandoned,
            calibration,
            uncertainty,
        );

        let action = decide_action(
            total,
            self.min_score,
            expected_loss_keep,
            expected_loss_delete,
            posterior_abandoned,
            calibration,
            fallback_active,
        );

        let ledger = build_ledger(
            factors,
            self.weights,
            posterior_abandoned,
            base_expected_loss_keep,
            base_expected_loss_delete,
            expected_loss_keep,
            expected_loss_delete,
            calibration,
            uncertainty,
            action,
        );

        CandidacyScore {
            path: input.path.clone(),
            total_score: total,
            factors,
            vetoed: false,
            veto_reason: None,
            classification: input.classification.clone(),
            size_bytes: input.size_bytes,
            age: input.age,
            decision: DecisionOutcome {
                action,
                posterior_abandoned,
                expected_loss_keep,
                expected_loss_delete,
                calibration_score: calibration,
                fallback_active,
            },
            ledger,
        }
    }

    /// Score and rank many candidates.
    ///
    /// Tie-break is path lexicographic order to preserve determinism.
    #[must_use]
    pub fn score_batch(&self, candidates: &[CandidateInput], urgency: f64) -> Vec<CandidacyScore> {
        let mut scores = candidates
            .iter()
            .map(|candidate| self.score_candidate(candidate, urgency))
            .collect::<Vec<_>>();
        scores.sort_by(|left, right| {
            right
                .total_score
                .partial_cmp(&left.total_score)
                .unwrap_or(Ordering::Equal)
                .then_with(|| left.path.cmp(&right.path))
        });
        scores
    }

    fn veto_reason(&self, input: &CandidateInput) -> Option<String> {
        if has_git_component(&input.path) || input.signals.has_git {
            return Some("path contains .git".to_string());
        }
        if is_system_path(&input.path) {
            return Some("system path is never deletable".to_string());
        }
        if input.age < self.min_file_age {
            return Some(format!(
                "age {}s below minimum {}s",
                input.age.as_secs(),
                self.min_file_age.as_secs()
            ));
        }
        if input.excluded {
            return Some("matched user exclusion".to_string());
        }
        if input.is_open {
            return Some("currently open by another process".to_string());
        }
        None
    }

    fn vetoed(&self, input: &CandidateInput, reason: String) -> CandidacyScore {
        CandidacyScore {
            path: input.path.clone(),
            total_score: 0.0,
            factors: ScoreFactors {
                location: 0.0,
                name: 0.0,
                age: 0.0,
                size: 0.0,
                structure: 0.0,
                pressure_multiplier: 1.0,
            },
            vetoed: true,
            veto_reason: Some(reason),
            classification: input.classification.clone(),
            size_bytes: input.size_bytes,
            age: input.age,
            decision: DecisionOutcome {
                action: DecisionAction::Keep,
                posterior_abandoned: 0.0,
                expected_loss_keep: 0.0,
                expected_loss_delete: self.false_positive_loss,
                calibration_score: 1.0,
                fallback_active: true,
            },
            ledger: EvidenceLedger {
                terms: Vec::new(),
                summary: "hard veto applied".to_string(),
            },
        }
    }
}

fn factor_location(path: &Path) -> f64 {
    let text = path.to_string_lossy().to_lowercase();
    if text.starts_with("/tmp") || text.starts_with("/var/tmp") || text.starts_with("/dev/shm") {
        0.95
    } else if text.contains("/data/projects/") && text.contains("/target") {
        0.80
    } else if text.contains("/data/projects/") && text.contains("/.target") {
        0.85
    } else if text.contains("/data/projects/") && text.contains("/.tmp_") {
        0.90
    } else if text.contains("/.cache/") {
        0.60
    } else if text.contains("/projects/") {
        0.40
    } else if text.contains("/documents/") {
        0.10
    } else if is_system_path(path) {
        0.0
    } else {
        0.30
    }
}

fn factor_name(path: &Path, classification: &ArtifactClassification) -> f64 {
    let name = path
        .file_name()
        .map_or_else(String::new, |value| value.to_string_lossy().to_lowercase());
    let mut score = classification.combined_confidence;
    if name.contains("tmp") || name.contains("temp") || name.contains("cache") {
        score += 0.10;
    }
    if classification.category == ArtifactCategory::RustTarget {
        score += 0.15;
    }
    if name.contains("backup") || name.contains("save") || name.contains("important") {
        score -= 0.30;
    }
    score.clamp(0.0, 1.0)
}

fn factor_age(age: Duration) -> f64 {
    let hours = age.as_secs_f64() / 3600.0;
    if hours < 0.5 {
        0.0
    } else if hours < 2.0 {
        0.20
    } else if hours < 4.0 {
        0.70
    } else if hours < 10.0 {
        1.0
    } else if hours < 24.0 {
        0.85
    } else if hours < 24.0 * 7.0 {
        0.60
    } else if hours < 24.0 * 30.0 {
        0.40
    } else {
        0.25
    }
}

fn factor_size(size_bytes: u64) -> f64 {
    const MIB: u64 = 1_048_576;
    const GIB: u64 = 1_073_741_824;
    if size_bytes < MIB {
        0.05
    } else if size_bytes < 10 * MIB {
        0.20
    } else if size_bytes < 100 * MIB {
        0.40
    } else if size_bytes < GIB {
        0.70
    } else if size_bytes < 10 * GIB {
        1.0
    } else if size_bytes < 50 * GIB {
        0.90
    } else {
        0.75
    }
}

fn factor_structure(signals: StructuralSignals) -> f64 {
    if signals.has_git {
        return 0.0;
    }
    if signals.has_fingerprint || signals.has_incremental {
        return 0.95;
    }
    if signals.has_deps && signals.has_build {
        return 0.85;
    }
    if signals.has_cargo_toml {
        return 0.05;
    }
    if signals.mostly_object_files {
        return 0.90;
    }
    0.40
}

fn pressure_multiplier(urgency: f64) -> f64 {
    let u = urgency.clamp(0.0, 1.0);
    if u <= 0.3 {
        1.0 + u
    } else if u <= 0.5 {
        (u - 0.3).mul_add(1.0, 1.3)
    } else if u <= 0.8 {
        (u - 0.5).mul_add(0.5 / 0.3, 1.5)
    } else {
        (u - 0.8).mul_add(5.0, 2.0)
    }
}

fn posterior_from_score(total_score: f64, confidence: f64) -> f64 {
    let scaled_score = (total_score / 3.0).clamp(0.0, 1.0);
    let logit = 3.5f64.mul_add(scaled_score - 0.5, 2.0 * (confidence - 0.5));
    1.0 / (1.0 + (-logit).exp())
}

fn calibration_score(classification_confidence: f64, factors: ScoreFactors) -> f64 {
    let spread = (factors.location - factors.structure).abs();
    0.75f64
        .mul_add(classification_confidence, 0.25 * (1.0 - spread))
        .clamp(0.0, 1.0)
}

fn uncertainty_adjusted_losses(
    base_keep_loss: f64,
    base_delete_loss: f64,
    posterior_abandoned: f64,
    calibration: f64,
    uncertainty: f64,
) -> (f64, f64) {
    let posterior = posterior_abandoned.clamp(0.0, 1.0);
    let calibration_penalty = 1.0 - calibration.clamp(0.0, 1.0);
    let uncertainty = uncertainty.clamp(0.0, 1.0);

    let uncertainty_discount = 0.5f64.mul_add(-uncertainty, 1.0);
    let keep_multiplier = (posterior * uncertainty_discount).mul_add(0.80, 1.0);
    let delete_slope = 0.90f64.mul_add(calibration_penalty, 0.90).max(0.90);
    let delete_multiplier = uncertainty.mul_add(delete_slope, 1.0);

    (
        base_keep_loss * keep_multiplier,
        base_delete_loss * delete_multiplier,
    )
}

fn decide_action(
    total_score: f64,
    min_score: f64,
    keep_loss: f64,
    delete_loss: f64,
    posterior_abandoned: f64,
    calibration: f64,
    fallback_active: bool,
) -> DecisionAction {
    if total_score < min_score || fallback_active {
        return DecisionAction::Keep;
    }
    let uncertainty = epistemic_uncertainty(posterior_abandoned, calibration);
    let decision_margin = (keep_loss - delete_loss).abs();
    let review_band = (1.0 - calibration).mul_add(2.0, 5.0f64.mul_add(uncertainty, 1.0));
    if decision_margin <= review_band {
        DecisionAction::Review
    } else if delete_loss < keep_loss {
        let min_delete_posterior =
            (1.0 - calibration.clamp(0.0, 1.0)).mul_add(0.20, 0.20f64.mul_add(uncertainty, 0.60));
        let delete_advantage = delete_advantage_ratio(keep_loss, delete_loss);
        let required_advantage = min_delete_advantage(calibration, uncertainty);
        if posterior_abandoned >= min_delete_posterior.clamp(0.60, 0.95)
            && delete_advantage >= required_advantage
        {
            DecisionAction::Delete
        } else {
            DecisionAction::Review
        }
    } else {
        DecisionAction::Keep
    }
}

fn delete_advantage_ratio(keep_loss: f64, delete_loss: f64) -> f64 {
    let safe_keep = keep_loss.max(0.0);
    let safe_delete = delete_loss.max(0.0);
    if safe_delete <= f64::EPSILON {
        f64::INFINITY
    } else {
        safe_keep / safe_delete
    }
}

fn min_delete_advantage(calibration: f64, uncertainty: f64) -> f64 {
    let calibration_penalty = 1.0 - calibration.clamp(0.0, 1.0);
    uncertainty
        .mul_add(1.6, calibration_penalty.mul_add(0.9, 1.2))
        .clamp(1.2, 4.0)
}

fn epistemic_uncertainty(posterior_abandoned: f64, calibration: f64) -> f64 {
    let p = posterior_abandoned.clamp(1e-6, 1.0 - 1e-6);
    let entropy = -(p * p.ln() + (1.0 - p) * (1.0 - p).ln()) / std::f64::consts::LN_2;
    let calibration_penalty = 1.0 - calibration.clamp(0.0, 1.0);
    0.65f64
        .mul_add(entropy, 0.35 * calibration_penalty)
        .clamp(0.0, 1.0)
}

#[allow(clippy::too_many_arguments)]
fn build_ledger(
    factors: ScoreFactors,
    weights: ScoringWeights,
    posterior_abandoned: f64,
    base_expected_loss_keep: f64,
    base_expected_loss_delete: f64,
    expected_loss_keep: f64,
    expected_loss_delete: f64,
    calibration: f64,
    uncertainty: f64,
    action: DecisionAction,
) -> EvidenceLedger {
    let terms = vec![
        EvidenceTerm {
            name: "location",
            weight: weights.location,
            value: factors.location,
            contribution: weights.location * factors.location,
        },
        EvidenceTerm {
            name: "name",
            weight: weights.name,
            value: factors.name,
            contribution: weights.name * factors.name,
        },
        EvidenceTerm {
            name: "age",
            weight: weights.age,
            value: factors.age,
            contribution: weights.age * factors.age,
        },
        EvidenceTerm {
            name: "size",
            weight: weights.size,
            value: factors.size,
            contribution: weights.size * factors.size,
        },
        EvidenceTerm {
            name: "structure",
            weight: weights.structure,
            value: factors.structure,
            contribution: weights.structure * factors.structure,
        },
        EvidenceTerm {
            name: "pressure_multiplier",
            weight: 1.0,
            value: factors.pressure_multiplier,
            contribution: factors.pressure_multiplier,
        },
        EvidenceTerm {
            name: "calibration",
            weight: 1.0,
            value: calibration,
            contribution: calibration,
        },
        EvidenceTerm {
            name: "uncertainty",
            weight: 1.0,
            value: uncertainty,
            contribution: uncertainty,
        },
        EvidenceTerm {
            name: "delete_advantage_ratio",
            weight: 1.0,
            value: delete_advantage_ratio(expected_loss_keep, expected_loss_delete),
            contribution: delete_advantage_ratio(expected_loss_keep, expected_loss_delete),
        },
        EvidenceTerm {
            name: "required_delete_advantage",
            weight: 1.0,
            value: min_delete_advantage(calibration, uncertainty),
            contribution: min_delete_advantage(calibration, uncertainty),
        },
    ];
    let decision_margin = expected_loss_keep - expected_loss_delete;
    let delete_advantage = delete_advantage_ratio(expected_loss_keep, expected_loss_delete);
    let required_delete_advantage = min_delete_advantage(calibration, uncertainty);
    let summary = format!(
        "posterior_abandoned={posterior_abandoned:.3}; keep_loss={expected_loss_keep:.2}; \
delete_loss={expected_loss_delete:.2}; base_keep_loss={base_expected_loss_keep:.2}; \
base_delete_loss={base_expected_loss_delete:.2}; loss_margin={decision_margin:.2}; \
uncertainty={uncertainty:.3}; calibration={calibration:.3}; delete_advantage={delete_advantage:.2}; \
required_delete_advantage={required_delete_advantage:.2}; action={action:?}"
    );
    EvidenceLedger { terms, summary }
}

fn has_git_component(path: &Path) -> bool {
    path.components().any(|component| match component {
        Component::Normal(name) => name == ".git",
        _ => false,
    })
}

fn is_system_path(path: &Path) -> bool {
    // Check exact root first (never delete `/` itself).
    if path == Path::new("/") {
        return true;
    }
    // Check prefixes for protected system directories.
    [
        Path::new("/boot"),
        Path::new("/etc"),
        Path::new("/usr"),
        Path::new("/bin"),
        Path::new("/sbin"),
        Path::new("/proc"),
        Path::new("/sys"),
    ]
    .iter()
    .any(|root| path == *root || path.starts_with(root))
}

#[cfg(test)]
mod tests {
    use super::{CandidateInput, DecisionAction, ScoringEngine};
    use crate::core::config::ScoringConfig;
    use crate::scanner::patterns::{ArtifactCategory, ArtifactClassification, StructuralSignals};
    use std::path::PathBuf;
    use std::time::Duration;

    fn default_engine() -> ScoringEngine {
        ScoringEngine::from_config(&ScoringConfig::default(), 30)
    }

    fn classification(confidence: f64, category: ArtifactCategory) -> ArtifactClassification {
        ArtifactClassification {
            pattern_name: "test".to_string(),
            category,
            name_confidence: confidence,
            structural_confidence: confidence,
            combined_confidence: confidence,
        }
    }

    #[test]
    fn git_paths_are_hard_vetoed() {
        let engine = default_engine();
        let score = engine.score_candidate(
            &CandidateInput {
                path: PathBuf::from("/data/projects/repo/.git/objects"),
                size_bytes: 1024,
                age: Duration::from_secs(3600),
                classification: classification(0.9, ArtifactCategory::RustTarget),
                signals: StructuralSignals::default(),
                is_open: false,
                excluded: false,
            },
            0.8,
        );
        assert!(score.vetoed);
        assert!(score.total_score.abs() < f64::EPSILON);
        assert_eq!(score.decision.action, DecisionAction::Keep);
    }

    #[test]
    fn high_confidence_old_target_gets_actionable_recommendation() {
        let engine = default_engine();
        let score = engine.score_candidate(
            &CandidateInput {
                path: PathBuf::from("/tmp/cargo-target-quietwillow"),
                size_bytes: 5 * 1_073_741_824,
                age: Duration::from_secs(6 * 3600),
                classification: classification(0.95, ArtifactCategory::RustTarget),
                signals: StructuralSignals {
                    has_incremental: true,
                    has_deps: true,
                    has_build: true,
                    has_fingerprint: true,
                    has_git: false,
                    has_cargo_toml: false,
                    mostly_object_files: true,
                },
                is_open: false,
                excluded: false,
            },
            0.7,
        );
        assert!(!score.vetoed);
        assert!(score.total_score > 1.0);
        // Decision-theoretic engine may produce Delete or Review depending
        // on calibration/loss balance — both are actionable for high-confidence targets.
        assert_ne!(
            score.decision.action,
            DecisionAction::Keep,
            "high-confidence target should not be kept"
        );
    }

    #[test]
    fn scoring_is_deterministic() {
        let engine = default_engine();
        let input = CandidateInput {
            path: PathBuf::from("/tmp/cargo-target-same"),
            size_bytes: 2 * 1_073_741_824,
            age: Duration::from_secs(5 * 3600),
            classification: classification(0.9, ArtifactCategory::RustTarget),
            signals: StructuralSignals {
                has_incremental: true,
                has_deps: true,
                has_build: true,
                has_fingerprint: false,
                has_git: false,
                has_cargo_toml: false,
                mostly_object_files: true,
            },
            is_open: false,
            excluded: false,
        };
        let a = engine.score_candidate(&input, 0.5);
        let b = engine.score_candidate(&input, 0.5);
        assert!((a.total_score - b.total_score).abs() < f64::EPSILON);
        assert_eq!(a.decision, b.decision);
        assert_eq!(a.ledger.summary, b.ledger.summary);
    }

    #[test]
    fn pressure_multiplier_increases_total_score() {
        let engine = default_engine();
        let input = CandidateInput {
            path: PathBuf::from("/tmp/cargo-target-pressure"),
            size_bytes: 1_073_741_824,
            age: Duration::from_secs(4 * 3600),
            classification: classification(0.9, ArtifactCategory::RustTarget),
            signals: StructuralSignals {
                has_incremental: true,
                has_deps: true,
                has_build: true,
                has_fingerprint: true,
                has_git: false,
                has_cargo_toml: false,
                mostly_object_files: false,
            },
            is_open: false,
            excluded: false,
        };
        let low = engine.score_candidate(&input, 0.0);
        let high = engine.score_candidate(&input, 1.0);
        assert!(high.total_score >= low.total_score);
    }

    #[test]
    fn epistemic_uncertainty_penalizes_mid_probability_and_low_calibration() {
        let edge_high_cal = super::epistemic_uncertainty(0.95, 0.95);
        let mid_high_cal = super::epistemic_uncertainty(0.50, 0.95);
        let mid_low_cal = super::epistemic_uncertainty(0.50, 0.55);

        assert!(mid_high_cal > edge_high_cal);
        assert!(mid_low_cal > mid_high_cal);
    }

    #[test]
    fn decision_boundary_prefers_review_when_margin_is_thin_and_uncertain() {
        let action = super::decide_action(1.2, 0.45, 24.0, 22.5, 0.78, 0.56, false);
        assert_eq!(action, DecisionAction::Review);
    }

    #[test]
    fn decision_boundary_allows_delete_when_margin_and_confidence_are_strong() {
        let action = super::decide_action(1.6, 0.45, 28.0, 4.0, 0.93, 0.90, false);
        assert_eq!(action, DecisionAction::Delete);
    }

    #[test]
    fn decision_boundary_reviews_when_advantage_ratio_is_too_weak_for_risk() {
        let action = super::decide_action(1.6, 0.45, 30.0, 20.0, 0.90, 0.55, false);
        assert_eq!(action, DecisionAction::Review);
    }

    #[test]
    fn decision_boundary_deletes_when_advantage_ratio_clears_risk_threshold() {
        let action = super::decide_action(1.6, 0.45, 30.0, 4.0, 0.92, 0.75, false);
        assert_eq!(action, DecisionAction::Delete);
    }

    #[test]
    fn uncertainty_adjustment_penalizes_delete_loss_more_than_keep_loss() {
        let (keep_loss, delete_loss) =
            super::uncertainty_adjusted_losses(24.0, 10.0, 0.80, 0.50, 0.90);
        assert!(keep_loss > 24.0);
        assert!(delete_loss > 10.0);
        assert!(delete_loss - 10.0 > keep_loss - 24.0);
    }
}
