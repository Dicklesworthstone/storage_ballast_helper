//! Shadow-mode policy engine with progressive delivery gates.
//!
//! Manages the lifecycle: **observe** → **canary** → **enforce**, with automatic
//! fallback to `FallbackSafe` on guardrail breaches and recovery via clean-window gates.
//!
//! In observe (shadow) mode, the engine scores candidates and produces `DecisionRecord`s
//! but never mutates the filesystem. In canary mode, a capped subset of deletions are
//! executed. In enforce mode, normal deletion occurs.

#![allow(clippy::cast_precision_loss)]

use std::fmt;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::monitor::guardrails::{GuardDiagnostics, GuardStatus};
use crate::scanner::decision_record::{
    ActionRecord, DecisionRecord, DecisionRecordBuilder, PolicyMode,
};
use crate::scanner::scoring::{CandidacyScore, DecisionAction};

// ──────────────────── policy mode ────────────────────

/// Active policy mode controlling side-effect scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActiveMode {
    /// Observe only: score and log, no deletions.
    Observe,
    /// Canary: execute capped deletions, log comparisons.
    Canary,
    /// Enforce: normal deletion pipeline.
    Enforce,
    /// Fallback safe: all adaptive actions blocked, conservative only.
    FallbackSafe,
}

impl ActiveMode {
    /// Whether this mode allows any filesystem deletions.
    #[must_use]
    pub fn allows_deletion(self) -> bool {
        matches!(self, Self::Canary | Self::Enforce)
    }

    /// Convert to the decision_record `PolicyMode` for evidence logging.
    #[must_use]
    pub fn to_policy_mode(self) -> PolicyMode {
        match self {
            Self::Observe | Self::FallbackSafe => PolicyMode::Shadow,
            Self::Canary => PolicyMode::Canary,
            Self::Enforce => PolicyMode::Live,
        }
    }
}

impl fmt::Display for ActiveMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Observe => write!(f, "observe"),
            Self::Canary => write!(f, "canary"),
            Self::Enforce => write!(f, "enforce"),
            Self::FallbackSafe => write!(f, "fallback_safe"),
        }
    }
}

// ──────────────────── fallback trigger ────────────────────

/// Reason the engine entered fallback-safe mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackReason {
    /// Calibration score below floor for N consecutive windows.
    CalibrationBreach {
        /// Number of consecutive breach windows observed.
        consecutive_windows: usize,
    },
    /// Guard e-process alarm tripped (drift detected).
    GuardrailDrift,
    /// Canary hourly deletion budget exceeded.
    CanaryBudgetExhausted,
    /// Policy error or panic recovery.
    PolicyError {
        /// Error details.
        details: String,
    },
    /// Evidence serialization failure.
    SerializationFailure,
    /// External kill-switch (env var or config).
    KillSwitch,
}

impl fmt::Display for FallbackReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CalibrationBreach {
                consecutive_windows,
            } => write!(f, "calibration breach ({consecutive_windows} windows)"),
            Self::GuardrailDrift => write!(f, "guardrail drift alarm"),
            Self::CanaryBudgetExhausted => write!(f, "canary budget exhausted"),
            Self::PolicyError { details } => write!(f, "policy error: {details}"),
            Self::SerializationFailure => write!(f, "evidence serialization failure"),
            Self::KillSwitch => write!(f, "kill-switch engaged"),
        }
    }
}

// ──────────────────── policy config ────────────────────

/// Configuration for the policy engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Initial mode on daemon start.
    pub initial_mode: ActiveMode,
    /// Maximum candidates to evaluate per loop iteration.
    pub max_candidates_per_loop: usize,
    /// Maximum hypothetical delete set per loop (observe mode).
    pub max_hypothetical_deletes: usize,
    /// Maximum canary deletions per hour.
    pub max_canary_deletes_per_hour: usize,
    /// Number of consecutive clean windows required for recovery from fallback.
    pub recovery_clean_windows: usize,
    /// Number of consecutive calibration breach windows before fallback.
    pub calibration_breach_windows: usize,
    /// Expected-loss penalty added to delete action when guard is not PASS.
    pub guard_penalty: f64,
    /// Loss values.
    pub loss_delete_useful: f64,
    /// Loss for keeping abandoned artifacts.
    pub loss_keep_abandoned: f64,
    /// Loss for review action (any state).
    pub loss_review: f64,
    /// Whether the kill-switch is active (forces fallback_safe).
    pub kill_switch: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            initial_mode: ActiveMode::Observe,
            max_candidates_per_loop: 100,
            max_hypothetical_deletes: 25,
            max_canary_deletes_per_hour: 10,
            recovery_clean_windows: 3,
            calibration_breach_windows: 3,
            guard_penalty: 50.0,
            loss_delete_useful: 100.0,
            loss_keep_abandoned: 30.0,
            loss_review: 5.0,
            kill_switch: false,
        }
    }
}

// ──────────────────── policy decision ────────────────────

/// The result of evaluating a batch of candidates through the policy engine.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    /// Decision records for all evaluated candidates.
    pub records: Vec<DecisionRecord>,
    /// Candidates approved for actual deletion (empty in observe/fallback modes).
    pub approved_for_deletion: Vec<CandidacyScore>,
    /// Count of candidates that would be deleted in enforce mode.
    pub hypothetical_deletes: usize,
    /// Count of candidates that would be kept.
    pub hypothetical_keeps: usize,
    /// Count of candidates flagged for review.
    pub hypothetical_reviews: usize,
    /// Whether budget was exhausted during evaluation.
    pub budget_exhausted: bool,
    /// Active mode when the decision was made.
    pub mode: ActiveMode,
}

// ──────────────────── mode transition ────────────────────

/// Valid transitions in the policy state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    /// Promote: observe→canary or canary→enforce.
    Promote,
    /// Demote: enforce→canary or canary→observe.
    Demote,
    /// Emergency fallback to safe mode.
    Fallback(FallbackReason),
    /// Recovery from fallback to the pre-fallback mode.
    Recover,
}

// ──────────────────── policy engine ────────────────────

/// The shadow-mode policy engine with progressive delivery gates.
pub struct PolicyEngine {
    config: PolicyConfig,
    mode: ActiveMode,
    pre_fallback_mode: ActiveMode,
    fallback_reason: Option<FallbackReason>,
    builder: DecisionRecordBuilder,
    consecutive_clean_windows: usize,
    consecutive_breach_windows: usize,
    canary_deletes_this_hour: usize,
    canary_hour_start: Instant,
    total_decisions: u64,
    total_fallback_entries: u64,
    transition_log: Vec<TransitionEntry>,
}

/// Record of a mode transition.
#[derive(Debug, Clone, Serialize)]
pub struct TransitionEntry {
    /// Transition type.
    pub transition: String,
    /// Mode before transition.
    pub from: String,
    /// Mode after transition.
    pub to: String,
    /// Decision count at time of transition.
    pub at_decision: u64,
    /// Reason (for fallback entries).
    pub reason: Option<String>,
}

impl PolicyEngine {
    /// Create a new policy engine with the given configuration.
    #[must_use]
    pub fn new(config: PolicyConfig) -> Self {
        let initial = if config.kill_switch {
            ActiveMode::FallbackSafe
        } else {
            config.initial_mode
        };
        Self {
            config,
            mode: initial,
            pre_fallback_mode: initial,
            fallback_reason: None,
            builder: DecisionRecordBuilder::new(),
            consecutive_clean_windows: 0,
            consecutive_breach_windows: 0,
            canary_deletes_this_hour: 0,
            canary_hour_start: Instant::now(),
            total_decisions: 0,
            total_fallback_entries: 0,
            transition_log: Vec::new(),
        }
    }

    /// Current active mode.
    #[must_use]
    pub fn mode(&self) -> ActiveMode {
        self.mode
    }

    /// Why the engine is in fallback mode (if applicable).
    #[must_use]
    pub fn fallback_reason(&self) -> Option<&FallbackReason> {
        self.fallback_reason.as_ref()
    }

    /// Total decisions made across all loops.
    #[must_use]
    pub fn total_decisions(&self) -> u64 {
        self.total_decisions
    }

    /// Total times fallback_safe was entered.
    #[must_use]
    pub fn total_fallback_entries(&self) -> u64 {
        self.total_fallback_entries
    }

    /// Ordered log of mode transitions.
    #[must_use]
    pub fn transition_log(&self) -> &[TransitionEntry] {
        &self.transition_log
    }

    // ──────────── core evaluation ────────────

    /// Evaluate a batch of scored candidates through the policy engine.
    ///
    /// Returns a `PolicyDecision` with evidence records and the approved
    /// deletion set (which may be empty in observe/fallback modes).
    pub fn evaluate(
        &mut self,
        candidates: &[CandidacyScore],
        guard: Option<&GuardDiagnostics>,
    ) -> PolicyDecision {
        // Check kill-switch.
        if self.config.kill_switch && self.mode != ActiveMode::FallbackSafe {
            self.enter_fallback(FallbackReason::KillSwitch);
        }

        // Check guard status for automatic fallback.
        if let Some(diag) = guard {
            self.check_guard_triggers(diag);
        }

        let budget = self.config.max_candidates_per_loop.min(candidates.len());
        let policy_mode = self.mode.to_policy_mode();

        let mut records = Vec::with_capacity(budget);
        let mut approved = Vec::new();
        let mut hypothetical_deletes = 0usize;
        let mut hypothetical_keeps = 0usize;
        let mut hypothetical_reviews = 0usize;
        let mut budget_exhausted = false;

        for (i, candidate) in candidates.iter().enumerate() {
            if i >= budget {
                budget_exhausted = true;
                break;
            }

            // Build the evidence record.
            let comparator = if self.mode == ActiveMode::Observe {
                // In observe mode, the "comparator" is the enforce-mode action.
                Some(candidate.decision.action)
            } else {
                None
            };

            let record = self
                .builder
                .build(candidate, policy_mode, guard, comparator);
            self.total_decisions += 1;

            // Count hypothetical outcomes.
            match record.action {
                ActionRecord::Delete => hypothetical_deletes += 1,
                ActionRecord::Keep => hypothetical_keeps += 1,
                ActionRecord::Review => hypothetical_reviews += 1,
            }

            // Decide whether to approve for actual deletion.
            if self.should_approve_deletion(candidate, guard) {
                approved.push(candidate.clone());
            }

            records.push(record);

            // Enforce hypothetical budget in observe mode.
            if self.mode == ActiveMode::Observe
                && hypothetical_deletes >= self.config.max_hypothetical_deletes
            {
                budget_exhausted = true;
                break;
            }
        }

        PolicyDecision {
            records,
            approved_for_deletion: approved,
            hypothetical_deletes,
            hypothetical_keeps,
            hypothetical_reviews,
            budget_exhausted,
            mode: self.mode,
        }
    }

    /// Apply a guard observation window and update breach/recovery counters.
    pub fn observe_window(&mut self, guard: &GuardDiagnostics) {
        if guard.status == GuardStatus::Pass && !guard.e_process_alarm {
            self.consecutive_clean_windows += 1;
            self.consecutive_breach_windows = 0;

            // Check recovery condition.
            if self.mode == ActiveMode::FallbackSafe
                && self.consecutive_clean_windows >= self.config.recovery_clean_windows
            {
                self.recover_from_fallback();
            }
        } else {
            self.consecutive_clean_windows = 0;
            if guard.status == GuardStatus::Fail {
                self.consecutive_breach_windows += 1;
                if self.consecutive_breach_windows >= self.config.calibration_breach_windows {
                    self.enter_fallback(FallbackReason::CalibrationBreach {
                        consecutive_windows: self.consecutive_breach_windows,
                    });
                }
            }
        }
    }

    // ──────────── mode transitions ────────────

    /// Manually promote: observe→canary or canary→enforce.
    ///
    /// Returns `true` if the transition was valid and applied.
    pub fn promote(&mut self) -> bool {
        match self.mode {
            ActiveMode::Observe => {
                self.apply_transition(ActiveMode::Canary, "promote");
                true
            }
            ActiveMode::Canary => {
                self.apply_transition(ActiveMode::Enforce, "promote");
                true
            }
            _ => false,
        }
    }

    /// Manually demote: enforce→canary or canary→observe.
    ///
    /// Returns `true` if the transition was valid and applied.
    pub fn demote(&mut self) -> bool {
        match self.mode {
            ActiveMode::Enforce => {
                self.apply_transition(ActiveMode::Canary, "demote");
                true
            }
            ActiveMode::Canary => {
                self.apply_transition(ActiveMode::Observe, "demote");
                true
            }
            _ => false,
        }
    }

    /// Force fallback_safe mode with the given reason.
    pub fn enter_fallback(&mut self, reason: FallbackReason) {
        if self.mode != ActiveMode::FallbackSafe {
            self.pre_fallback_mode = self.mode;
            let reason_str = reason.to_string();
            self.fallback_reason = Some(reason);
            self.total_fallback_entries += 1;
            self.consecutive_clean_windows = 0;
            self.log_transition(
                "fallback",
                self.mode,
                ActiveMode::FallbackSafe,
                Some(reason_str),
            );
            self.mode = ActiveMode::FallbackSafe;
        }
    }

    /// Generate a diagnostic snapshot of the policy engine state.
    #[must_use]
    pub fn diagnostics(&self) -> PolicyDiagnostics {
        PolicyDiagnostics {
            mode: self.mode,
            pre_fallback_mode: self.pre_fallback_mode,
            fallback_reason: self.fallback_reason.as_ref().map(ToString::to_string),
            total_decisions: self.total_decisions,
            total_fallback_entries: self.total_fallback_entries,
            consecutive_clean_windows: self.consecutive_clean_windows,
            consecutive_breach_windows: self.consecutive_breach_windows,
            canary_deletes_this_hour: self.canary_deletes_this_hour,
            transition_count: self.transition_log.len(),
        }
    }

    // ──────────── private helpers ────────────

    fn should_approve_deletion(
        &mut self,
        candidate: &CandidacyScore,
        guard: Option<&GuardDiagnostics>,
    ) -> bool {
        // FallbackSafe and Observe never delete.
        if !self.mode.allows_deletion() {
            return false;
        }

        // Only approve candidates with Delete action.
        if candidate.decision.action != DecisionAction::Delete {
            return false;
        }

        // Apply guard penalty check.
        if let Some(diag) = guard
            && !diag.status.adaptive_allowed()
        {
            let penalized_delete_loss =
                candidate.decision.expected_loss_delete + self.config.guard_penalty;
            if penalized_delete_loss >= candidate.decision.expected_loss_keep {
                return false;
            }
        }

        // Canary mode: check hourly budget.
        if self.mode == ActiveMode::Canary {
            self.rotate_canary_hour();
            if self.canary_deletes_this_hour >= self.config.max_canary_deletes_per_hour {
                self.enter_fallback(FallbackReason::CanaryBudgetExhausted);
                return false;
            }
            self.canary_deletes_this_hour += 1;
        }

        true
    }

    fn check_guard_triggers(&mut self, diag: &GuardDiagnostics) {
        if diag.e_process_alarm && self.mode != ActiveMode::FallbackSafe {
            self.enter_fallback(FallbackReason::GuardrailDrift);
        }
    }

    fn recover_from_fallback(&mut self) {
        let target = self.pre_fallback_mode;
        self.fallback_reason = None;
        self.log_transition("recover", self.mode, target, None);
        self.mode = target;
    }

    fn apply_transition(&mut self, to: ActiveMode, kind: &str) {
        self.log_transition(kind, self.mode, to, None);
        self.mode = to;
    }

    fn log_transition(
        &mut self,
        kind: &str,
        from: ActiveMode,
        to: ActiveMode,
        reason: Option<String>,
    ) {
        self.transition_log.push(TransitionEntry {
            transition: kind.to_string(),
            from: from.to_string(),
            to: to.to_string(),
            at_decision: self.total_decisions,
            reason,
        });
    }

    fn rotate_canary_hour(&mut self) {
        if self.canary_hour_start.elapsed() >= std::time::Duration::from_secs(3600) {
            self.canary_deletes_this_hour = 0;
            self.canary_hour_start = Instant::now();
        }
    }
}

// ──────────────────── diagnostics ────────────────────

/// Snapshot of the policy engine state for status reporting.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyDiagnostics {
    /// Current active mode.
    pub mode: ActiveMode,
    /// Mode before fallback (for recovery target).
    pub pre_fallback_mode: ActiveMode,
    /// Reason for current fallback (if applicable).
    pub fallback_reason: Option<String>,
    /// Total decisions made.
    pub total_decisions: u64,
    /// Total times fallback was entered.
    pub total_fallback_entries: u64,
    /// Consecutive clean guard windows (for recovery tracking).
    pub consecutive_clean_windows: usize,
    /// Consecutive breach windows (for fallback trigger).
    pub consecutive_breach_windows: usize,
    /// Canary deletions in the current hour.
    pub canary_deletes_this_hour: usize,
    /// Number of mode transitions recorded.
    pub transition_count: usize,
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::guardrails::GuardDiagnostics;
    use crate::scanner::patterns::{ArtifactCategory, ArtifactClassification, StructuralSignals};
    use crate::scanner::scoring::{
        CandidacyScore, DecisionAction, DecisionOutcome, EvidenceLedger, EvidenceTerm, ScoreFactors,
    };
    use std::path::PathBuf;
    use std::time::Duration;

    fn default_config() -> PolicyConfig {
        PolicyConfig::default()
    }

    fn sample_candidate(action: DecisionAction, score: f64) -> CandidacyScore {
        CandidacyScore {
            path: PathBuf::from("/data/projects/test/.target_opus"),
            total_score: score,
            factors: ScoreFactors {
                location: 0.85,
                name: 0.90,
                age: 1.0,
                size: 0.70,
                structure: 0.95,
                pressure_multiplier: 1.5,
            },
            vetoed: false,
            veto_reason: None,
            classification: ArtifactClassification {
                pattern_name: ".target*".to_string(),
                category: ArtifactCategory::RustTarget,
                name_confidence: 0.9,
                structural_confidence: 0.95,
                combined_confidence: 0.92,
            },
            size_bytes: 3_000_000_000,
            age: Duration::from_secs(5 * 3600),
            decision: DecisionOutcome {
                action,
                posterior_abandoned: 0.87,
                expected_loss_keep: 8.7,
                expected_loss_delete: 1.3,
                calibration_score: 0.82,
                fallback_active: false,
            },
            ledger: EvidenceLedger {
                terms: vec![EvidenceTerm {
                    name: "location",
                    weight: 0.25,
                    value: 0.85,
                    contribution: 0.2125,
                }],
                summary: "test".to_string(),
            },
        }
    }

    fn passing_guard() -> GuardDiagnostics {
        GuardDiagnostics {
            status: GuardStatus::Pass,
            observation_count: 25,
            median_rate_error: 0.12,
            conservative_fraction: 0.80,
            e_process_value: 3.5,
            e_process_alarm: false,
            consecutive_clean: 5,
            reason: "calibration verified".to_string(),
        }
    }

    fn failing_guard() -> GuardDiagnostics {
        GuardDiagnostics {
            status: GuardStatus::Fail,
            observation_count: 25,
            median_rate_error: 0.45,
            conservative_fraction: 0.55,
            e_process_value: 25.0,
            e_process_alarm: true,
            consecutive_clean: 0,
            reason: "drift detected".to_string(),
        }
    }

    // ──── mode lifecycle tests ────

    #[test]
    fn starts_in_observe_by_default() {
        let engine = PolicyEngine::new(default_config());
        assert_eq!(engine.mode(), ActiveMode::Observe);
    }

    #[test]
    fn kill_switch_forces_fallback() {
        let mut config = default_config();
        config.kill_switch = true;
        let engine = PolicyEngine::new(config);
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
    }

    #[test]
    fn promote_observe_to_canary() {
        let mut engine = PolicyEngine::new(default_config());
        assert!(engine.promote());
        assert_eq!(engine.mode(), ActiveMode::Canary);
    }

    #[test]
    fn promote_canary_to_enforce() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote();
        assert!(engine.promote());
        assert_eq!(engine.mode(), ActiveMode::Enforce);
    }

    #[test]
    fn promote_enforce_fails() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote();
        engine.promote();
        assert!(!engine.promote());
        assert_eq!(engine.mode(), ActiveMode::Enforce);
    }

    #[test]
    fn demote_enforce_to_canary() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote();
        engine.promote();
        assert!(engine.demote());
        assert_eq!(engine.mode(), ActiveMode::Canary);
    }

    #[test]
    fn demote_canary_to_observe() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote();
        assert!(engine.demote());
        assert_eq!(engine.mode(), ActiveMode::Observe);
    }

    #[test]
    fn demote_observe_fails() {
        let mut engine = PolicyEngine::new(default_config());
        assert!(!engine.demote());
        assert_eq!(engine.mode(), ActiveMode::Observe);
    }

    #[test]
    fn fallback_safe_preserves_pre_mode() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote(); // canary
        engine.enter_fallback(FallbackReason::GuardrailDrift);
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
        assert_eq!(engine.pre_fallback_mode, ActiveMode::Canary);
    }

    #[test]
    fn recovery_restores_pre_fallback_mode() {
        let mut config = default_config();
        config.recovery_clean_windows = 2;
        let mut engine = PolicyEngine::new(config);
        engine.promote(); // canary
        engine.enter_fallback(FallbackReason::GuardrailDrift);

        let good = passing_guard();
        engine.observe_window(&good);
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
        engine.observe_window(&good);
        assert_eq!(engine.mode(), ActiveMode::Canary);
        assert!(engine.fallback_reason().is_none());
    }

    #[test]
    fn calibration_breach_triggers_fallback() {
        let mut config = default_config();
        config.calibration_breach_windows = 2;
        let mut engine = PolicyEngine::new(config);
        engine.promote(); // canary

        let bad = GuardDiagnostics {
            status: GuardStatus::Fail,
            observation_count: 25,
            median_rate_error: 0.45,
            conservative_fraction: 0.55,
            e_process_value: 10.0,
            e_process_alarm: false,
            consecutive_clean: 0,
            reason: "bad calibration".to_string(),
        };

        engine.observe_window(&bad);
        assert_eq!(engine.mode(), ActiveMode::Canary);
        engine.observe_window(&bad);
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
        assert!(matches!(
            engine.fallback_reason(),
            Some(FallbackReason::CalibrationBreach { .. })
        ));
    }

    #[test]
    fn drift_alarm_triggers_fallback() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote(); // canary
        let drift = failing_guard();
        engine.evaluate(&[], Some(&drift));
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
    }

    // ──── evaluation tests ────

    #[test]
    fn observe_mode_produces_no_deletions() {
        let mut engine = PolicyEngine::new(default_config());
        let candidates = vec![
            sample_candidate(DecisionAction::Delete, 2.5),
            sample_candidate(DecisionAction::Delete, 2.0),
        ];
        let guard = passing_guard();
        let decision = engine.evaluate(&candidates, Some(&guard));

        assert!(decision.approved_for_deletion.is_empty());
        assert_eq!(decision.hypothetical_deletes, 2);
        assert_eq!(decision.records.len(), 2);
        assert_eq!(decision.mode, ActiveMode::Observe);
    }

    #[test]
    fn enforce_mode_approves_delete_candidates() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote();
        engine.promote(); // enforce
        let candidates = vec![
            sample_candidate(DecisionAction::Delete, 2.5),
            sample_candidate(DecisionAction::Keep, 0.5),
        ];
        let guard = passing_guard();
        let decision = engine.evaluate(&candidates, Some(&guard));

        assert_eq!(decision.approved_for_deletion.len(), 1);
        assert_eq!(decision.hypothetical_deletes, 1);
        assert_eq!(decision.hypothetical_keeps, 1);
    }

    #[test]
    fn canary_mode_respects_hourly_budget() {
        let mut config = default_config();
        config.max_canary_deletes_per_hour = 2;
        let mut engine = PolicyEngine::new(config);
        engine.promote(); // canary

        let candidates = vec![
            sample_candidate(DecisionAction::Delete, 2.5),
            sample_candidate(DecisionAction::Delete, 2.3),
            sample_candidate(DecisionAction::Delete, 2.1),
        ];
        let guard = passing_guard();
        let decision = engine.evaluate(&candidates, Some(&guard));

        // Should approve 2, then enter fallback on the 3rd.
        assert_eq!(decision.approved_for_deletion.len(), 2);
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
    }

    #[test]
    fn observe_mode_respects_hypothetical_budget() {
        let mut config = default_config();
        config.max_hypothetical_deletes = 2;
        config.max_candidates_per_loop = 100;
        let mut engine = PolicyEngine::new(config);

        let candidates = vec![
            sample_candidate(DecisionAction::Delete, 2.5),
            sample_candidate(DecisionAction::Delete, 2.3),
            sample_candidate(DecisionAction::Delete, 2.1),
            sample_candidate(DecisionAction::Keep, 0.5),
        ];
        let decision = engine.evaluate(&candidates, None);

        assert!(decision.budget_exhausted);
        assert_eq!(decision.hypothetical_deletes, 2);
        // Should have stopped after 2 deletes, not processed all 4.
        assert!(decision.records.len() <= 3);
    }

    #[test]
    fn candidate_budget_limits_evaluation() {
        let mut config = default_config();
        config.max_candidates_per_loop = 2;
        let mut engine = PolicyEngine::new(config);

        let candidates = vec![
            sample_candidate(DecisionAction::Delete, 2.5),
            sample_candidate(DecisionAction::Delete, 2.3),
            sample_candidate(DecisionAction::Delete, 2.1),
        ];
        let decision = engine.evaluate(&candidates, None);

        assert!(decision.budget_exhausted);
        assert_eq!(decision.records.len(), 2);
    }

    #[test]
    fn guard_penalty_blocks_deletion_when_not_pass() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote();
        engine.promote(); // enforce

        let mut candidate = sample_candidate(DecisionAction::Delete, 2.5);
        // expected_loss_delete=1.3, guard_penalty=50.0 → penalized=51.3 > keep=8.7
        let guard = GuardDiagnostics {
            status: GuardStatus::Unknown,
            observation_count: 5,
            median_rate_error: 0.3,
            conservative_fraction: 0.6,
            e_process_value: 1.0,
            e_process_alarm: false,
            consecutive_clean: 0,
            reason: "insufficient data".to_string(),
        };

        let decision = engine.evaluate(&[candidate], Some(&guard));
        assert!(decision.approved_for_deletion.is_empty());
    }

    #[test]
    fn fallback_safe_blocks_all_deletions() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote();
        engine.promote(); // enforce
        engine.enter_fallback(FallbackReason::KillSwitch);

        let candidates = vec![sample_candidate(DecisionAction::Delete, 2.5)];
        let guard = passing_guard();
        let decision = engine.evaluate(&candidates, Some(&guard));

        assert!(decision.approved_for_deletion.is_empty());
        assert_eq!(decision.mode, ActiveMode::FallbackSafe);
    }

    // ──── diagnostics tests ────

    #[test]
    fn diagnostics_snapshot() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote(); // canary
        let candidates = vec![sample_candidate(DecisionAction::Delete, 2.5)];
        engine.evaluate(&candidates, None);

        let diag = engine.diagnostics();
        assert_eq!(diag.mode, ActiveMode::Canary);
        assert_eq!(diag.total_decisions, 1);
        assert_eq!(diag.transition_count, 1);
    }

    #[test]
    fn transition_log_captures_history() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote(); // observe→canary
        engine.promote(); // canary→enforce
        engine.demote(); // enforce→canary

        let log = engine.transition_log();
        assert_eq!(log.len(), 3);
        assert_eq!(log[0].from, "observe");
        assert_eq!(log[0].to, "canary");
        assert_eq!(log[1].from, "canary");
        assert_eq!(log[1].to, "enforce");
        assert_eq!(log[2].from, "enforce");
        assert_eq!(log[2].to, "canary");
    }

    #[test]
    fn double_fallback_is_idempotent() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote(); // canary
        engine.enter_fallback(FallbackReason::GuardrailDrift);
        engine.enter_fallback(FallbackReason::KillSwitch);

        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
        assert_eq!(engine.total_fallback_entries(), 1);
        assert_eq!(engine.pre_fallback_mode, ActiveMode::Canary);
    }

    #[test]
    fn active_mode_display() {
        assert_eq!(ActiveMode::Observe.to_string(), "observe");
        assert_eq!(ActiveMode::Canary.to_string(), "canary");
        assert_eq!(ActiveMode::Enforce.to_string(), "enforce");
        assert_eq!(ActiveMode::FallbackSafe.to_string(), "fallback_safe");
    }

    #[test]
    fn active_mode_allows_deletion() {
        assert!(!ActiveMode::Observe.allows_deletion());
        assert!(ActiveMode::Canary.allows_deletion());
        assert!(ActiveMode::Enforce.allows_deletion());
        assert!(!ActiveMode::FallbackSafe.allows_deletion());
    }

    #[test]
    fn fallback_reason_display() {
        let r = FallbackReason::CalibrationBreach {
            consecutive_windows: 3,
        };
        assert!(r.to_string().contains("3 windows"));

        let r2 = FallbackReason::PolicyError {
            details: "panic in scorer".to_string(),
        };
        assert!(r2.to_string().contains("panic in scorer"));
    }

    #[test]
    fn evaluate_records_decision_ids_sequentially() {
        let mut engine = PolicyEngine::new(default_config());
        let candidates = vec![
            sample_candidate(DecisionAction::Delete, 2.5),
            sample_candidate(DecisionAction::Keep, 0.5),
        ];
        let d1 = engine.evaluate(&candidates, None);
        let d2 = engine.evaluate(&candidates, None);

        assert_eq!(d1.records[0].decision_id, 1);
        assert_eq!(d1.records[1].decision_id, 2);
        assert_eq!(d2.records[0].decision_id, 3);
        assert_eq!(d2.records[1].decision_id, 4);
    }

    #[test]
    fn observe_mode_sets_shadow_policy() {
        let mut engine = PolicyEngine::new(default_config());
        let candidates = vec![sample_candidate(DecisionAction::Delete, 2.5)];
        let decision = engine.evaluate(&candidates, None);
        assert_eq!(decision.records[0].policy_mode, PolicyMode::Shadow);
    }

    #[test]
    fn enforce_mode_sets_live_policy() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote();
        engine.promote();
        let candidates = vec![sample_candidate(DecisionAction::Delete, 2.5)];
        let decision = engine.evaluate(&candidates, None);
        assert_eq!(decision.records[0].policy_mode, PolicyMode::Live);
    }

    #[test]
    fn clean_windows_reset_on_breach() {
        let mut config = default_config();
        config.recovery_clean_windows = 3;
        let mut engine = PolicyEngine::new(config);
        engine.enter_fallback(FallbackReason::GuardrailDrift);

        let good = passing_guard();
        let bad = GuardDiagnostics {
            status: GuardStatus::Fail,
            e_process_alarm: false,
            ..failing_guard()
        };

        engine.observe_window(&good);
        engine.observe_window(&good);
        assert_eq!(engine.consecutive_clean_windows, 2);
        engine.observe_window(&bad);
        assert_eq!(engine.consecutive_clean_windows, 0);
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
    }
}
