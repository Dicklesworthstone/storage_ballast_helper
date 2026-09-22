//! Shared admission checks for planning and the live mutation boundary.
//!
//! `DeletionPlan` and `CandidacyScore` are public data, not proof that the
//! receiving executor approved a mutation. Never trust a caller to have
//! filtered them, and never let emergency Review admission erase a veto.

use super::{CandidacyScore, DecisionAction, DeletionConfig, SkipReason};

pub(super) fn check(
    candidate: &CandidacyScore,
    config: &DeletionConfig,
) -> Result<(), SkipReason> {
    let decision = &candidate.decision;
    if candidate.vetoed || candidate.veto_reason.is_some() || decision.category_suspended {
        return Err(SkipReason::Vetoed);
    }
    if !config.min_score.is_finite()
        || config.min_score < 0.0
        || !candidate.total_score.is_finite()
        || candidate.total_score < config.min_score
    {
        return Err(SkipReason::BelowThreshold);
    }
    let actionable = match decision.action {
        DecisionAction::Delete => true,
        DecisionAction::Review => config.include_review,
        DecisionAction::Keep => false,
    };
    if !actionable
        || !probability(decision.posterior_abandoned)
        || !probability(decision.calibration_score)
        || !probability(decision.regret_calibration)
        || !nonnegative_finite(decision.expected_loss_keep)
        || !nonnegative_finite(decision.expected_loss_delete)
    {
        return Err(SkipReason::Vetoed);
    }
    Ok(())
}

fn probability(value: f64) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

fn nonnegative_finite(value: f64) -> bool {
    value.is_finite() && value >= 0.0
}
