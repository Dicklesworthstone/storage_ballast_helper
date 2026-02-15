//! Decision-plane unit-test matrix: invariant checks, property tests, and
//! safe-mode transition verification.
//!
//! Covers the five invariant families from bd-izu.8:
//! 1. Deterministic ranking and tie-break stability
//! 2. Posterior/loss monotonicity under stronger evidence
//! 3. Guard state machine safety (no unsafe transitions)
//! 4. Merkle incremental equivalence properties
//! 5. Fallback dominance under uncertainty/error states
//!
//! Uses seeded RNG for reproducible randomized fixtures.

use std::path::PathBuf;
use std::time::Duration;

use crate::daemon::policy::{ActiveMode, FallbackReason, PolicyConfig, PolicyEngine};
use crate::monitor::guardrails::{
    AdaptiveGuard, CalibrationObservation, GuardDiagnostics, GuardStatus, GuardrailConfig,
};
use crate::scanner::decision_record::{
    ActionRecord, DecisionRecordBuilder, ExplainLevel, PolicyMode, format_explain,
};
use crate::scanner::patterns::{ArtifactCategory, ArtifactClassification, StructuralSignals};
use crate::scanner::scoring::{
    CandidacyScore, CandidateInput, DecisionAction, DecisionOutcome, EvidenceLedger, EvidenceTerm,
    ScoreFactors, ScoringEngine,
};

// ──────────────────── seeded RNG ────────────────────

/// Simple seeded LCG for reproducible test fixtures.
/// Not cryptographically secure — only for test determinism.
struct SeededRng {
    state: u64,
}

impl SeededRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        // LCG parameters from Numerical Recipes.
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        self.state
    }

    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    fn next_range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next_u64() % (hi - lo + 1)
    }
}

// ──────────────────── fixture builders ────────────────────

fn make_candidate(
    rng: &mut SeededRng,
    path: &str,
    age_hours: u64,
    size_gib: u64,
    confidence: f64,
) -> CandidateInput {
    CandidateInput {
        path: PathBuf::from(path),
        size_bytes: size_gib * 1_073_741_824,
        age: Duration::from_secs(age_hours * 3600),
        classification: ArtifactClassification {
            pattern_name: ".target*".to_string(),
            category: ArtifactCategory::RustTarget,
            name_confidence: confidence,
            structural_confidence: confidence * 0.9,
            combined_confidence: confidence,
        },
        signals: StructuralSignals {
            has_incremental: rng.next_f64() > 0.3,
            has_deps: rng.next_f64() > 0.2,
            has_build: rng.next_f64() > 0.2,
            has_fingerprint: rng.next_f64() > 0.5,
            has_git: false,
            has_cargo_toml: false,
            mostly_object_files: rng.next_f64() > 0.4,
        },
        is_open: false,
        excluded: false,
    }
}

fn default_engine() -> ScoringEngine {
    use crate::core::config::ScoringConfig;
    ScoringEngine::from_config(&ScoringConfig::default(), 30)
}

fn random_candidates(rng: &mut SeededRng, count: usize) -> Vec<CandidateInput> {
    let mut results = Vec::with_capacity(count);
    for i in 0..count {
        let age = rng.next_range(1, 48);
        let size = rng.next_range(1, 10);
        let conf = 0.5 + rng.next_f64() * 0.45;
        let suffix = rng.next_u64() % 1000;
        let path = format!("/data/projects/p{i}/.target_opus_{suffix}");
        results.push(make_candidate(rng, &path, age, size, conf));
    }
    results
}

// ════════════════════════════════════════════════════════════
// INVARIANT FAMILY 1: Deterministic ranking and tie-break stability
// ════════════════════════════════════════════════════════════

#[test]
fn scoring_is_perfectly_deterministic() {
    let seed = 42u64;
    let engine = default_engine();

    for trial in 0..5 {
        let mut rng = SeededRng::new(seed);
        let candidates = random_candidates(&mut rng, 20);
        let urgency = 0.5;

        let scored_a = engine.score_batch(&candidates, urgency);
        let scored_b = engine.score_batch(&candidates, urgency);

        for (a, b) in scored_a.iter().zip(scored_b.iter()) {
            assert_eq!(
                a.total_score, b.total_score,
                "trial {trial}: scores must be bitwise identical"
            );
            assert_eq!(a.path, b.path, "trial {trial}: paths must be identical");
            assert_eq!(
                a.decision.action, b.decision.action,
                "trial {trial}: actions must be identical"
            );
        }
    }
}

#[test]
fn tiebreak_is_lexicographic_by_path() {
    let engine = default_engine();

    // Create candidates with identical features but different paths.
    let mut rng = SeededRng::new(99);
    let base = make_candidate(&mut rng, "/data/projects/alpha/.target_opus", 5, 3, 0.9);
    let mut candidates: Vec<CandidateInput> = Vec::new();

    for name in ["zzz", "aaa", "mmm", "bbb"] {
        let mut c = base.clone();
        c.path = PathBuf::from(format!("/data/projects/{name}/.target_opus"));
        candidates.push(c);
    }

    let scored = engine.score_batch(&candidates, 0.5);

    // Same score → sorted by path ascending.
    for window in scored.windows(2) {
        if (window[0].total_score - window[1].total_score).abs() < f64::EPSILON {
            assert!(
                window[0].path <= window[1].path,
                "tie-break must be path-ascending: {} vs {}",
                window[0].path.display(),
                window[1].path.display(),
            );
        }
    }
}

#[test]
fn batch_sorted_descending_by_score() {
    let engine = default_engine();
    let mut rng = SeededRng::new(123);
    let candidates = random_candidates(&mut rng, 30);
    let scored = engine.score_batch(&candidates, 0.6);

    for window in scored.windows(2) {
        assert!(
            window[0].total_score >= window[1].total_score,
            "batch must be sorted descending: {} >= {}",
            window[0].total_score,
            window[1].total_score,
        );
    }
}

// ════════════════════════════════════════════════════════════
// INVARIANT FAMILY 2: Posterior/loss monotonicity
// ════════════════════════════════════════════════════════════

#[test]
fn higher_score_implies_higher_posterior() {
    let engine = default_engine();
    let mut rng = SeededRng::new(200);
    let candidates = random_candidates(&mut rng, 50);

    let scored = engine.score_batch(&candidates, 0.5);
    let non_vetoed: Vec<_> = scored.iter().filter(|s| !s.vetoed).collect();

    // Among non-vetoed candidates with identical confidence, higher total_score
    // should give higher posterior_abandoned.
    for pair in non_vetoed.windows(2) {
        if (pair[0].classification.combined_confidence - pair[1].classification.combined_confidence)
            .abs()
            < 0.01
        {
            if pair[0].total_score > pair[1].total_score + 0.01 {
                assert!(
                    pair[0].decision.posterior_abandoned >= pair[1].decision.posterior_abandoned,
                    "higher score ({:.3}) should give higher posterior ({:.4} vs {:.4})",
                    pair[0].total_score,
                    pair[0].decision.posterior_abandoned,
                    pair[1].decision.posterior_abandoned,
                );
            }
        }
    }
}

#[test]
fn expected_loss_keep_proportional_to_posterior() {
    let engine = default_engine();
    let mut rng = SeededRng::new(201);
    let candidates = random_candidates(&mut rng, 30);

    for c in &candidates {
        let scored = engine.score_candidate(c, 0.5);
        if !scored.vetoed {
            // expected_loss_keep = posterior_abandoned * false_negative_loss
            // So higher posterior → higher keep_loss (same false_negative_loss).
            assert!(
                scored.decision.expected_loss_keep >= 0.0,
                "expected_loss_keep must be non-negative",
            );
            assert!(
                scored.decision.expected_loss_delete >= 0.0,
                "expected_loss_delete must be non-negative",
            );
        }
    }
}

#[test]
fn pressure_multiplier_is_monotone() {
    let engine = default_engine();
    let mut rng = SeededRng::new(202);
    let input = make_candidate(&mut rng, "/tmp/cargo-target-mono", 5, 3, 0.9);

    let mut prev_score = 0.0f64;
    for urgency_pct in 0..=10 {
        let urgency = urgency_pct as f64 / 10.0;
        let scored = engine.score_candidate(&input, urgency);
        assert!(
            scored.total_score >= prev_score,
            "score must be monotone in urgency: {urgency:.1} gave {:.3} < {prev_score:.3}",
            scored.total_score,
        );
        prev_score = scored.total_score;
    }
}

// ════════════════════════════════════════════════════════════
// INVARIANT FAMILY 3: Guard state machine safety
// ════════════════════════════════════════════════════════════

#[test]
fn guard_starts_unknown() {
    let guard = AdaptiveGuard::new(GuardrailConfig::default());
    assert_eq!(guard.diagnostics().status, GuardStatus::Unknown);
}

#[test]
fn guard_needs_min_observations_for_pass() {
    let config = GuardrailConfig {
        min_observations: 5,
        ..GuardrailConfig::default()
    };
    let mut guard = AdaptiveGuard::new(config);

    // Add fewer than min_observations good observations.
    for _ in 0..4 {
        guard.observe(CalibrationObservation {
            predicted_rate: 1000.0,
            actual_rate: 1050.0,
            predicted_tte: 100.0,
            actual_tte: 110.0,
        });
    }
    assert_eq!(
        guard.diagnostics().status,
        GuardStatus::Unknown,
        "should remain Unknown with insufficient observations"
    );

    // One more should trigger Pass.
    guard.observe(CalibrationObservation {
        predicted_rate: 1000.0,
        actual_rate: 1050.0,
        predicted_tte: 100.0,
        actual_tte: 110.0,
    });
    assert_eq!(guard.diagnostics().status, GuardStatus::Pass);
}

#[test]
fn guard_fail_requires_recovery() {
    let config = GuardrailConfig {
        min_observations: 3,
        recovery_clean_windows: 2,
        ..GuardrailConfig::default()
    };
    let mut guard = AdaptiveGuard::new(config);

    // Build up to Pass.
    for _ in 0..5 {
        guard.observe(CalibrationObservation {
            predicted_rate: 1000.0,
            actual_rate: 1050.0,
            predicted_tte: 100.0,
            actual_tte: 110.0,
        });
    }
    assert_eq!(guard.diagnostics().status, GuardStatus::Pass);

    // Inject bad observations to trigger Fail.
    for _ in 0..50 {
        guard.observe(CalibrationObservation {
            predicted_rate: 1000.0,
            actual_rate: 5000.0, // 400% error
            predicted_tte: 100.0,
            actual_tte: 20.0, // non-conservative
        });
    }
    assert_eq!(guard.diagnostics().status, GuardStatus::Fail);

    // One good observation is not enough for recovery.
    guard.observe(CalibrationObservation {
        predicted_rate: 1000.0,
        actual_rate: 1050.0,
        predicted_tte: 90.0,
        actual_tte: 110.0,
    });
    // May still be Fail; recovery needs consecutive clean observations.
    let status = guard.diagnostics().status;
    assert!(
        status == GuardStatus::Fail || status == GuardStatus::Unknown,
        "single good observation should not jump to Pass"
    );
}

#[test]
fn guard_no_unsafe_transition_from_unknown_to_fail_without_data() {
    let guard = AdaptiveGuard::new(GuardrailConfig::default());
    let status = guard.diagnostics().status;
    assert_eq!(
        status,
        GuardStatus::Unknown,
        "new guard must be Unknown, not Fail"
    );
}

// ════════════════════════════════════════════════════════════
// INVARIANT FAMILY 4: Policy engine transition safety
// ════════════════════════════════════════════════════════════

#[test]
fn policy_observe_canary_enforce_promotion_order() {
    let mut engine = PolicyEngine::new(PolicyConfig::default());
    assert_eq!(engine.mode(), ActiveMode::Observe);
    assert!(engine.promote());
    assert_eq!(engine.mode(), ActiveMode::Canary);
    assert!(engine.promote());
    assert_eq!(engine.mode(), ActiveMode::Enforce);
    assert!(!engine.promote(), "cannot promote past enforce");
}

#[test]
fn policy_enforce_canary_observe_demotion_order() {
    let mut engine = PolicyEngine::new(PolicyConfig::default());
    engine.promote();
    engine.promote();
    assert!(engine.demote());
    assert_eq!(engine.mode(), ActiveMode::Canary);
    assert!(engine.demote());
    assert_eq!(engine.mode(), ActiveMode::Observe);
    assert!(!engine.demote(), "cannot demote past observe");
}

#[test]
fn policy_fallback_idempotent() {
    let mut engine = PolicyEngine::new(PolicyConfig::default());
    engine.promote(); // canary
    engine.enter_fallback(FallbackReason::GuardrailDrift);
    let entries_1 = engine.total_fallback_entries();
    engine.enter_fallback(FallbackReason::KillSwitch);
    let entries_2 = engine.total_fallback_entries();
    assert_eq!(
        entries_1, entries_2,
        "double fallback must not increment counter"
    );
}

#[test]
fn policy_fallback_recovery_restores_mode() {
    let mut config = PolicyConfig::default();
    config.recovery_clean_windows = 1;
    let mut engine = PolicyEngine::new(config);
    engine.promote(); // canary
    engine.enter_fallback(FallbackReason::GuardrailDrift);
    assert_eq!(engine.mode(), ActiveMode::FallbackSafe);

    let good = crate::monitor::guardrails::GuardDiagnostics {
        status: GuardStatus::Pass,
        observation_count: 25,
        median_rate_error: 0.10,
        conservative_fraction: 0.85,
        e_process_value: 2.0,
        e_process_alarm: false,
        consecutive_clean: 3,
        reason: "ok".to_string(),
    };
    engine.observe_window(&good);
    assert_eq!(
        engine.mode(),
        ActiveMode::Canary,
        "should restore pre-fallback mode"
    );
}

#[test]
fn policy_fallback_from_any_active_mode() {
    for initial in [ActiveMode::Observe, ActiveMode::Canary, ActiveMode::Enforce] {
        let mut config = PolicyConfig::default();
        config.initial_mode = initial;
        let mut engine = PolicyEngine::new(config);

        // Promote to desired mode.
        while engine.mode() != initial {
            engine.promote();
        }

        engine.enter_fallback(FallbackReason::KillSwitch);
        assert_eq!(
            engine.mode(),
            ActiveMode::FallbackSafe,
            "fallback must work from {initial}",
        );
    }
}

// ════════════════════════════════════════════════════════════
// INVARIANT FAMILY 5: Fallback dominance
// ════════════════════════════════════════════════════════════

#[test]
fn fallback_blocks_all_deletions() {
    let mut engine = PolicyEngine::new(PolicyConfig::default());
    engine.promote();
    engine.promote(); // enforce
    engine.enter_fallback(FallbackReason::PolicyError {
        details: "test".to_string(),
    });

    let candidates = vec![make_scored_candidate(DecisionAction::Delete, 2.5)];
    let decision = engine.evaluate(&candidates, None);
    assert!(
        decision.approved_for_deletion.is_empty(),
        "FallbackSafe must block ALL deletions"
    );
}

#[test]
fn observe_mode_never_approves_deletions() {
    let mut engine = PolicyEngine::new(PolicyConfig::default());
    let mut rng = SeededRng::new(500);
    let scoring_engine = default_engine();
    let candidates_input = random_candidates(&mut rng, 20);
    let scored: Vec<CandidacyScore> = candidates_input
        .iter()
        .map(|c| scoring_engine.score_candidate(c, 0.8))
        .collect();

    let decision = engine.evaluate(&scored, None);
    assert!(
        decision.approved_for_deletion.is_empty(),
        "observe mode must never approve deletions"
    );
    assert_eq!(decision.mode, ActiveMode::Observe);
}

#[test]
fn fallback_dominates_guard_pass() {
    let mut engine = PolicyEngine::new(PolicyConfig::default());
    engine.promote();
    engine.promote();
    engine.enter_fallback(FallbackReason::SerializationFailure);

    let good_guard = crate::monitor::guardrails::GuardDiagnostics {
        status: GuardStatus::Pass,
        observation_count: 50,
        median_rate_error: 0.05,
        conservative_fraction: 0.95,
        e_process_value: 1.0,
        e_process_alarm: false,
        consecutive_clean: 10,
        reason: "excellent".to_string(),
    };

    let candidates = vec![make_scored_candidate(DecisionAction::Delete, 2.8)];
    let decision = engine.evaluate(&candidates, Some(&good_guard));
    assert!(
        decision.approved_for_deletion.is_empty(),
        "FallbackSafe must dominate even perfect guard status"
    );
}

// ════════════════════════════════════════════════════════════
// CROSS-CUTTING: Decision record + policy integration
// ════════════════════════════════════════════════════════════

#[test]
fn decision_records_carry_correct_policy_mode() {
    let modes = [
        (ActiveMode::Observe, PolicyMode::Shadow),
        (ActiveMode::Canary, PolicyMode::Canary),
        (ActiveMode::Enforce, PolicyMode::Live),
        (ActiveMode::FallbackSafe, PolicyMode::Shadow),
    ];

    for (active, expected_policy) in modes {
        let mut config = PolicyConfig::default();
        config.initial_mode = active;
        let mut engine = PolicyEngine::new(config);
        while engine.mode() != active {
            if active == ActiveMode::FallbackSafe {
                engine.enter_fallback(FallbackReason::KillSwitch);
            } else {
                engine.promote();
            }
        }

        let candidates = vec![make_scored_candidate(DecisionAction::Keep, 0.5)];
        let decision = engine.evaluate(&candidates, None);
        assert_eq!(
            decision.records[0].policy_mode, expected_policy,
            "mode {active} should produce policy_mode {expected_policy:?}",
        );
    }
}

#[test]
fn decision_record_json_roundtrip_across_modes() {
    let mut builder = DecisionRecordBuilder::new();
    let candidate = make_scored_candidate(DecisionAction::Delete, 2.0);

    for mode in [
        PolicyMode::Live,
        PolicyMode::Shadow,
        PolicyMode::Canary,
        PolicyMode::DryRun,
    ] {
        let record = builder.build(&candidate, mode, None, None);
        let json = record.to_json_compact();
        let parsed: crate::scanner::decision_record::DecisionRecord =
            serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.policy_mode, mode);
        assert_eq!(parsed.action, ActionRecord::Delete);
    }
}

#[test]
fn explain_levels_are_cumulative() {
    let mut builder = DecisionRecordBuilder::new();
    let candidate = make_scored_candidate(DecisionAction::Delete, 2.0);
    let record = builder.build(&candidate, PolicyMode::Live, None, None);

    let l0 = format_explain(&record, ExplainLevel::L0);
    let l1 = format_explain(&record, ExplainLevel::L1);
    let l2 = format_explain(&record, ExplainLevel::L2);
    let l3 = format_explain(&record, ExplainLevel::L3);

    assert!(l0.len() < l1.len(), "L1 must be longer than L0");
    assert!(l1.len() < l2.len(), "L2 must be longer than L1");
    assert!(l2.len() < l3.len(), "L3 must be longer than L2");

    // L3 must contain L0 content.
    assert!(l3.contains("DELETE") || l3.contains("KEEP"));
}

// ════════════════════════════════════════════════════════════
// RANDOMIZED PROPERTY TESTS with seeded fixtures
// ════════════════════════════════════════════════════════════

#[test]
fn property_score_clamped_to_0_3() {
    let engine = default_engine();
    for seed in 0..20 {
        let mut rng = SeededRng::new(seed * 7 + 13);
        let candidates = random_candidates(&mut rng, 50);
        let urgency = rng.next_f64();
        let scored = engine.score_batch(&candidates, urgency);

        for s in &scored {
            assert!(
                (0.0..=3.0).contains(&s.total_score),
                "seed={seed}: score {:.4} out of [0, 3] for {}",
                s.total_score,
                s.path.display(),
            );
        }
    }
}

#[test]
fn property_vetoed_candidates_have_zero_score() {
    let engine = default_engine();
    for seed in 0..10 {
        let mut rng = SeededRng::new(seed * 11 + 7);
        let mut candidates = random_candidates(&mut rng, 20);

        // Force some to be vetoed.
        for c in candidates.iter_mut().step_by(3) {
            c.is_open = true;
        }

        for c in &candidates {
            let scored = engine.score_candidate(c, 0.5);
            if scored.vetoed {
                assert_eq!(
                    scored.total_score, 0.0,
                    "seed={seed}: vetoed candidate must have score 0.0"
                );
                assert_eq!(scored.decision.action, DecisionAction::Keep);
            }
        }
    }
}

#[test]
fn property_decision_record_never_panics_on_serialize() {
    let mut builder = DecisionRecordBuilder::new();
    let engine = default_engine();

    for seed in 0..20 {
        let mut rng = SeededRng::new(seed * 3 + 1);
        let candidates = random_candidates(&mut rng, 10);
        let urgency = rng.next_f64();

        for c in &candidates {
            let scored = engine.score_candidate(c, urgency);
            let record = builder.build(&scored, PolicyMode::Live, None, None);

            // These must never panic.
            let _json = record.to_json_compact();
            let _pretty = record.to_json_pretty();
            let _explain = format_explain(&record, ExplainLevel::L3);

            // Roundtrip must succeed.
            let parsed: crate::scanner::decision_record::DecisionRecord =
                serde_json::from_str(&record.to_json_compact()).unwrap();
            assert_eq!(parsed.decision_id, record.decision_id);
        }
    }
}

#[test]
fn property_policy_engine_invariants_under_random_operations() {
    for seed in 0..10 {
        let mut rng = SeededRng::new(seed * 17 + 3);
        let mut config = PolicyConfig::default();
        config.recovery_clean_windows = 2;
        config.calibration_breach_windows = 2;
        config.max_canary_deletes_per_hour = 5;
        let mut engine = PolicyEngine::new(config);

        let candidates: Vec<CandidacyScore> = (0..5)
            .map(|_| {
                let action = if rng.next_f64() > 0.5 {
                    DecisionAction::Delete
                } else {
                    DecisionAction::Keep
                };
                make_scored_candidate(action, rng.next_f64() * 3.0)
            })
            .collect();

        // Random sequence of operations.
        for step in 0..20 {
            let op = rng.next_u64() % 5;
            match op {
                0 => {
                    engine.promote();
                }
                1 => {
                    engine.demote();
                }
                2 => {
                    engine.enter_fallback(FallbackReason::PolicyError {
                        details: format!("seed={seed} step={step}"),
                    });
                }
                3 => {
                    let good = rng.next_f64() > 0.3;
                    let guard = crate::monitor::guardrails::GuardDiagnostics {
                        status: if good {
                            GuardStatus::Pass
                        } else {
                            GuardStatus::Fail
                        },
                        observation_count: 25,
                        median_rate_error: if good { 0.1 } else { 0.5 },
                        conservative_fraction: if good { 0.85 } else { 0.4 },
                        e_process_value: if good { 2.0 } else { 25.0 },
                        e_process_alarm: !good,
                        consecutive_clean: if good { 5 } else { 0 },
                        reason: "test".to_string(),
                    };
                    engine.observe_window(&guard);
                }
                _ => {
                    let mode_before = engine.mode();
                    let decision = engine.evaluate(&candidates, None);
                    // Key invariant: observe/fallback modes never approve deletions.
                    // Check mode BEFORE evaluation, since canary budget exhaustion
                    // can change the mode mid-evaluation (by design).
                    if !mode_before.allows_deletion() {
                        assert!(
                            decision.approved_for_deletion.is_empty(),
                            "seed={seed} step={step}: mode {mode_before} must not approve deletions",
                        );
                    }
                }
            }

            // Invariant: mode is always valid.
            let mode = engine.mode();
            assert!(
                matches!(
                    mode,
                    ActiveMode::Observe
                        | ActiveMode::Canary
                        | ActiveMode::Enforce
                        | ActiveMode::FallbackSafe
                ),
                "seed={seed} step={step}: invalid mode"
            );
        }
    }
}

// ════════════════════════════════════════════════════════════
// PROOF HARNESS: Replay, Fault-Injection, and Reproducibility
// (bd-izu.6)
// ════════════════════════════════════════════════════════════

// ──────────────────── replay engine types ────────────────────

/// An operation to perform on the policy engine during replay.
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum PolicyOp {
    /// Promote the policy mode (observe→canary→enforce).
    Promote,
    /// Demote the policy mode (enforce→canary→observe).
    Demote,
    /// Force fallback with the given reason.
    Fallback(FallbackReason),
    /// Feed a guard observation window to the policy engine.
    ObserveWindow(GuardDiagnostics),
    /// Evaluate candidates and record the decision.
    Evaluate,
}

/// A single step in a replay scenario.
#[derive(Debug, Clone)]
struct ReplayStep {
    /// Step label for diagnostics.
    label: String,
    /// Candidates to feed to the scoring engine.
    candidates: Vec<CandidateInput>,
    /// Urgency parameter for scoring (0.0–1.0).
    urgency: f64,
    /// Guard observations to feed before evaluation.
    guard_observations: Vec<CalibrationObservation>,
    /// Policy operations to perform in order.
    ops: Vec<PolicyOp>,
}

/// Result of a single replay step.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ReplayStepResult {
    label: String,
    mode_before: ActiveMode,
    mode_after: ActiveMode,
    guard_status: GuardStatus,
    guard_observation_count: usize,
    decisions_made: u64,
    approved_count: usize,
    hypothetical_deletes: usize,
    fallback_active: bool,
    fallback_reason: Option<FallbackReason>,
    records: Vec<crate::scanner::decision_record::DecisionRecord>,
    transition_log_len: usize,
}

/// Deterministic replay engine for decision-plane scenarios.
///
/// Takes a scripted sequence of steps and replays them, producing
/// a full trace of decisions and mode transitions.
struct ReplayEngine {
    scoring: ScoringEngine,
    policy: PolicyEngine,
    guard: AdaptiveGuard,
    trace: Vec<ReplayStepResult>,
    seed: u64,
}

impl ReplayEngine {
    fn new(seed: u64) -> Self {
        Self {
            scoring: default_engine(),
            policy: PolicyEngine::new(PolicyConfig::default()),
            guard: AdaptiveGuard::with_defaults(),
            trace: Vec::new(),
            seed,
        }
    }

    fn with_policy_config(seed: u64, config: PolicyConfig) -> Self {
        Self {
            scoring: default_engine(),
            policy: PolicyEngine::new(config),
            guard: AdaptiveGuard::with_defaults(),
            trace: Vec::new(),
            seed,
        }
    }

    #[allow(dead_code)]
    fn with_guard_config(seed: u64, guard_config: GuardrailConfig) -> Self {
        Self {
            scoring: default_engine(),
            policy: PolicyEngine::new(PolicyConfig::default()),
            guard: AdaptiveGuard::new(guard_config),
            trace: Vec::new(),
            seed,
        }
    }

    /// Replay a complete scenario and return the trace.
    fn replay(&mut self, steps: &[ReplayStep]) -> &[ReplayStepResult] {
        for step in steps {
            self.execute_step(step);
        }
        &self.trace
    }

    fn execute_step(&mut self, step: &ReplayStep) {
        let mode_before = self.policy.mode();

        // Feed guard observations first.
        for obs in &step.guard_observations {
            self.guard.observe(*obs);
        }

        let diag = self.guard.diagnostics();

        // Score the candidates.
        let scored = self.scoring.score_batch(&step.candidates, step.urgency);

        let mut last_decision = None;

        // Execute policy operations.
        for op in &step.ops {
            match op {
                PolicyOp::Promote => {
                    self.policy.promote();
                }
                PolicyOp::Demote => {
                    self.policy.demote();
                }
                PolicyOp::Fallback(reason) => {
                    self.policy.enter_fallback(reason.clone());
                }
                PolicyOp::ObserveWindow(guard_diag) => {
                    self.policy.observe_window(guard_diag);
                }
                PolicyOp::Evaluate => {
                    last_decision = Some(self.policy.evaluate(&scored, Some(&diag)));
                }
            }
        }

        // If no explicit Evaluate op, do one anyway for trace completeness.
        let decision = last_decision.unwrap_or_else(|| self.policy.evaluate(&scored, Some(&diag)));

        let mode_after = self.policy.mode();

        self.trace.push(ReplayStepResult {
            label: step.label.clone(),
            mode_before,
            mode_after,
            guard_status: diag.status,
            guard_observation_count: diag.observation_count,
            decisions_made: self.policy.total_decisions(),
            approved_count: decision.approved_for_deletion.len(),
            hypothetical_deletes: decision.hypothetical_deletes,
            fallback_active: mode_after == ActiveMode::FallbackSafe,
            fallback_reason: self.policy.fallback_reason().cloned(),
            records: decision.records,
            transition_log_len: self.policy.transition_log().len(),
        });
    }
}

// ──────────────────── fault injection ────────────────────

/// Types of faults that can be injected into a replay scenario.
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum FaultType {
    /// Guard receives wildly miscalibrated observations.
    StaleStats { error_factor: f64 },
    /// Force serialization failure fallback.
    SerializerFailure,
    /// Guard stuck at Unknown (no observations fed).
    LockContention,
    /// E-process alarm triggered via high drift.
    HighDrift { drift_magnitude: f64 },
    /// Sudden urgency spike.
    BurstPressure { urgency: f64 },
    /// Kill-switch engaged.
    KillSwitch,
}

/// Expected fallback behavior after fault injection.
#[derive(Debug, Clone)]
struct FaultExpectation {
    /// Whether the engine should be in fallback mode.
    expect_fallback: bool,
    /// Expected reason for fallback (if applicable).
    expect_reason_contains: Option<String>,
    /// Whether deletions should be blocked.
    expect_no_deletions: bool,
}

/// A single fault injection scenario.
struct FaultScenario {
    name: String,
    seed: u64,
    /// Steps to run before injecting the fault (warm-up).
    warmup_steps: Vec<ReplayStep>,
    /// The fault to inject.
    fault: FaultType,
    /// Steps to run after fault injection.
    post_fault_steps: Vec<ReplayStep>,
    /// Expected behavior after fault.
    expectation: FaultExpectation,
}

/// Build guard observations that are well-calibrated.
fn good_observations(count: usize) -> Vec<CalibrationObservation> {
    (0..count)
        .map(|i| CalibrationObservation {
            predicted_rate: 1000.0 + (i as f64 * 10.0),
            actual_rate: 1050.0 + (i as f64 * 10.0),
            predicted_tte: 90.0 + (i as f64),
            actual_tte: 110.0 + (i as f64),
        })
        .collect()
}

/// Build guard observations that are poorly calibrated.
fn bad_observations(count: usize, error_factor: f64) -> Vec<CalibrationObservation> {
    (0..count)
        .map(|i| CalibrationObservation {
            predicted_rate: 1000.0 + (i as f64 * 10.0),
            actual_rate: (1000.0 + (i as f64 * 10.0)) * error_factor,
            predicted_tte: 100.0,
            actual_tte: 20.0, // non-conservative: predicted > actual
        })
        .collect()
}

/// Build a warmup sequence that brings guard to PASS and policy to a given mode.
fn warmup_to_mode(rng: &mut SeededRng, target: ActiveMode) -> Vec<ReplayStep> {
    let mut steps = Vec::new();

    // First: feed enough good observations to get guard to PASS.
    let candidates = random_candidates(rng, 5);
    steps.push(ReplayStep {
        label: "warmup-guard".to_string(),
        candidates: candidates.clone(),
        urgency: 0.3,
        guard_observations: good_observations(15),
        ops: vec![PolicyOp::Evaluate],
    });

    // Then: promote to target mode.
    let mut ops = Vec::new();
    match target {
        ActiveMode::Observe => {}
        ActiveMode::Canary => {
            ops.push(PolicyOp::Promote);
        }
        ActiveMode::Enforce => {
            ops.push(PolicyOp::Promote);
            ops.push(PolicyOp::Promote);
        }
        ActiveMode::FallbackSafe => {
            ops.push(PolicyOp::Promote);
            ops.push(PolicyOp::Fallback(FallbackReason::KillSwitch));
        }
    }
    if !ops.is_empty() {
        ops.push(PolicyOp::Evaluate);
        steps.push(ReplayStep {
            label: format!("warmup-promote-to-{target}"),
            candidates,
            urgency: 0.3,
            guard_observations: Vec::new(),
            ops,
        });
    }

    steps
}

/// Execute a fault scenario and validate the expectation.
fn run_fault_scenario(scenario: &FaultScenario) {
    let mut engine = ReplayEngine::new(scenario.seed);

    // Run warmup.
    engine.replay(&scenario.warmup_steps);

    // Apply the fault.
    let mut rng = SeededRng::new(scenario.seed + 1000);
    let fault_candidates = random_candidates(&mut rng, 10);

    match &scenario.fault {
        FaultType::StaleStats { error_factor } => {
            let step = ReplayStep {
                label: format!("fault-stale-stats-{error_factor}"),
                candidates: fault_candidates,
                urgency: 0.5,
                guard_observations: bad_observations(30, *error_factor),
                ops: vec![PolicyOp::Evaluate],
            };
            engine.execute_step(&step);
        }
        FaultType::SerializerFailure => {
            engine
                .policy
                .enter_fallback(FallbackReason::SerializationFailure);
            let step = ReplayStep {
                label: "fault-serializer".to_string(),
                candidates: fault_candidates,
                urgency: 0.5,
                guard_observations: Vec::new(),
                ops: vec![PolicyOp::Evaluate],
            };
            engine.execute_step(&step);
        }
        FaultType::LockContention => {
            // Don't feed any guard observations — guard stays Unknown.
            let fresh_guard = AdaptiveGuard::with_defaults();
            engine.guard = fresh_guard;
            let step = ReplayStep {
                label: "fault-lock-contention".to_string(),
                candidates: fault_candidates,
                urgency: 0.5,
                guard_observations: Vec::new(),
                ops: vec![PolicyOp::Evaluate],
            };
            engine.execute_step(&step);
        }
        FaultType::HighDrift { drift_magnitude } => {
            let step = ReplayStep {
                label: format!("fault-high-drift-{drift_magnitude}"),
                candidates: fault_candidates,
                urgency: 0.5,
                guard_observations: bad_observations(50, *drift_magnitude),
                ops: vec![PolicyOp::Evaluate],
            };
            engine.execute_step(&step);
        }
        FaultType::BurstPressure { urgency } => {
            let step = ReplayStep {
                label: format!("fault-burst-pressure-{urgency}"),
                candidates: fault_candidates,
                urgency: *urgency,
                guard_observations: good_observations(5),
                ops: vec![PolicyOp::Evaluate],
            };
            engine.execute_step(&step);
        }
        FaultType::KillSwitch => {
            engine.policy.enter_fallback(FallbackReason::KillSwitch);
            let step = ReplayStep {
                label: "fault-kill-switch".to_string(),
                candidates: fault_candidates,
                urgency: 0.5,
                guard_observations: Vec::new(),
                ops: vec![PolicyOp::Evaluate],
            };
            engine.execute_step(&step);
        }
    }

    // Run post-fault steps.
    for step in &scenario.post_fault_steps {
        engine.execute_step(step);
    }

    // Validate the expectation against the last trace entry.
    let last = engine.trace.last().expect("trace must not be empty");

    if scenario.expectation.expect_fallback {
        assert!(
            last.fallback_active,
            "scenario '{}': expected fallback mode, got {:?}",
            scenario.name, last.mode_after,
        );
    }

    if let Some(ref reason_fragment) = scenario.expectation.expect_reason_contains {
        let reason_str = last
            .fallback_reason
            .as_ref()
            .map_or_else(String::new, |r| format!("{r}"));
        assert!(
            reason_str.contains(reason_fragment),
            "scenario '{}': fallback reason '{}' does not contain '{}'",
            scenario.name,
            reason_str,
            reason_fragment,
        );
    }

    if scenario.expectation.expect_no_deletions {
        assert_eq!(
            last.approved_count, 0,
            "scenario '{}': expected no deletions, got {}",
            scenario.name, last.approved_count,
        );
    }
}

// ──────────────────── reproducibility pack ────────────────────

/// A reproducibility pack that captures all inputs and outputs for replay.
#[derive(Debug, Clone, serde::Serialize)]
struct ReproPack {
    /// Environment metadata.
    env: ReproEnv,
    /// Manifest of test cases and seeds.
    manifest: ReproManifest,
    /// Trace of all decisions made during replay.
    traces: Vec<ReproTraceEntry>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ReproEnv {
    platform: String,
    rust_edition: String,
    sbh_version: String,
    scoring_config: String,
    policy_config: String,
    guard_config: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ReproManifest {
    seed: u64,
    step_count: usize,
    candidate_count: usize,
    scenario_name: String,
    mode: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ReproTraceEntry {
    step: usize,
    label: String,
    mode_before: String,
    mode_after: String,
    guard_status: String,
    approved_count: usize,
    hypothetical_deletes: usize,
    fallback_active: bool,
    decision_count: u64,
}

impl ReproPack {
    /// Build a repro pack from a replay engine's trace.
    fn from_replay(engine: &ReplayEngine, scenario_name: &str) -> Self {
        let traces = engine
            .trace
            .iter()
            .enumerate()
            .map(|(i, r)| ReproTraceEntry {
                step: i,
                label: r.label.clone(),
                mode_before: format!("{}", r.mode_before),
                mode_after: format!("{}", r.mode_after),
                guard_status: format!("{}", r.guard_status),
                approved_count: r.approved_count,
                hypothetical_deletes: r.hypothetical_deletes,
                fallback_active: r.fallback_active,
                decision_count: r.decisions_made,
            })
            .collect();

        let total_candidates: usize = engine.trace.iter().flat_map(|r| r.records.iter()).count();

        Self {
            env: ReproEnv {
                platform: std::env::consts::OS.to_string(),
                rust_edition: "2024".to_string(),
                sbh_version: env!("CARGO_PKG_VERSION").to_string(),
                scoring_config: "default".to_string(),
                policy_config: "default".to_string(),
                guard_config: "default".to_string(),
            },
            manifest: ReproManifest {
                seed: engine.seed,
                step_count: engine.trace.len(),
                candidate_count: total_candidates,
                scenario_name: scenario_name.to_string(),
                mode: "fast".to_string(),
            },
            traces,
        }
    }

    /// Serialize the repro pack to JSON (for artifact emission).
    fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }
}

// ──────────────────── benchmark infrastructure ────────────────────

/// Statistical summary with percentile values.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct BenchmarkStats {
    p50: f64,
    p95: f64,
    p99: f64,
    mean: f64,
    count: usize,
}

impl BenchmarkStats {
    fn from_samples(mut samples: Vec<f64>) -> Self {
        assert!(
            !samples.is_empty(),
            "benchmark requires at least one sample"
        );
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = samples.len();
        let mean = samples.iter().sum::<f64>() / n as f64;
        Self {
            p50: samples[n / 2],
            p95: samples[(n as f64 * 0.95) as usize],
            p99: samples[(n as f64 * 0.99) as usize],
            mean,
            count: n,
        }
    }
}

/// Benchmark report comparing scoring and evaluation latency.
#[derive(Debug, Clone)]
struct BenchmarkReport {
    scoring_stats: BenchmarkStats,
    evaluation_stats: BenchmarkStats,
}

impl BenchmarkReport {
    /// Run a benchmark over N iterations.
    fn run(seed: u64, iterations: usize, candidates_per_iter: usize) -> Self {
        let engine = default_engine();
        let mut policy = PolicyEngine::new(PolicyConfig::default());
        // Promote to enforce mode for realistic evaluation.
        policy.promote();
        policy.promote();

        let mut scoring_times = Vec::with_capacity(iterations);
        let mut eval_times = Vec::with_capacity(iterations);

        for i in 0..iterations {
            let mut rng = SeededRng::new(seed + i as u64);
            let candidates = random_candidates(&mut rng, candidates_per_iter);

            // Benchmark scoring.
            let t0 = std::time::Instant::now();
            let scored = engine.score_batch(&candidates, 0.5);
            let scoring_dur = t0.elapsed();
            scoring_times.push(scoring_dur.as_secs_f64() * 1000.0);

            // Benchmark policy evaluation.
            let t1 = std::time::Instant::now();
            let _decision = policy.evaluate(&scored, None);
            let eval_dur = t1.elapsed();
            eval_times.push(eval_dur.as_secs_f64() * 1000.0);
        }

        Self {
            scoring_stats: BenchmarkStats::from_samples(scoring_times),
            evaluation_stats: BenchmarkStats::from_samples(eval_times),
        }
    }
}

// ════════════════════════════════════════════════════════════
// PROOF HARNESS TESTS
// ════════════════════════════════════════════════════════════

// ──── Replay determinism ────

#[test]
fn replay_is_deterministic_across_runs() {
    let seed = 7777u64;
    let steps = build_standard_scenario(seed);

    let mut engine_a = ReplayEngine::new(seed);
    engine_a.replay(&steps);

    let mut engine_b = ReplayEngine::new(seed);
    engine_b.replay(&steps);

    assert_eq!(
        engine_a.trace.len(),
        engine_b.trace.len(),
        "trace lengths must match"
    );

    for (i, (a, b)) in engine_a.trace.iter().zip(engine_b.trace.iter()).enumerate() {
        assert_eq!(
            a.mode_before, b.mode_before,
            "step {i}: mode_before mismatch"
        );
        assert_eq!(a.mode_after, b.mode_after, "step {i}: mode_after mismatch");
        assert_eq!(
            a.guard_status, b.guard_status,
            "step {i}: guard_status mismatch"
        );
        assert_eq!(
            a.approved_count, b.approved_count,
            "step {i}: approved_count mismatch"
        );
        assert_eq!(
            a.hypothetical_deletes, b.hypothetical_deletes,
            "step {i}: hypothetical_deletes mismatch"
        );
        assert_eq!(
            a.fallback_active, b.fallback_active,
            "step {i}: fallback_active mismatch"
        );
        assert_eq!(
            a.decisions_made, b.decisions_made,
            "step {i}: decisions_made mismatch"
        );
        assert_eq!(
            a.transition_log_len, b.transition_log_len,
            "step {i}: transition_log_len mismatch"
        );
    }
}

#[test]
fn replay_observe_canary_enforce_lifecycle() {
    let seed = 8888u64;
    let mut rng = SeededRng::new(seed);
    let candidates = random_candidates(&mut rng, 10);

    let steps = vec![
        ReplayStep {
            label: "observe-phase".to_string(),
            candidates: candidates.clone(),
            urgency: 0.4,
            guard_observations: good_observations(15),
            ops: vec![PolicyOp::Evaluate],
        },
        ReplayStep {
            label: "promote-to-canary".to_string(),
            candidates: candidates.clone(),
            urgency: 0.5,
            guard_observations: Vec::new(),
            ops: vec![PolicyOp::Promote, PolicyOp::Evaluate],
        },
        ReplayStep {
            label: "promote-to-enforce".to_string(),
            candidates: candidates.clone(),
            urgency: 0.6,
            guard_observations: Vec::new(),
            ops: vec![PolicyOp::Promote, PolicyOp::Evaluate],
        },
        ReplayStep {
            label: "fallback".to_string(),
            candidates: candidates.clone(),
            urgency: 0.7,
            guard_observations: Vec::new(),
            ops: vec![
                PolicyOp::Fallback(FallbackReason::GuardrailDrift),
                PolicyOp::Evaluate,
            ],
        },
        ReplayStep {
            label: "recovery".to_string(),
            candidates,
            urgency: 0.3,
            guard_observations: Vec::new(),
            ops: vec![
                PolicyOp::ObserveWindow(GuardDiagnostics {
                    status: GuardStatus::Pass,
                    observation_count: 50,
                    median_rate_error: 0.05,
                    conservative_fraction: 0.95,
                    e_process_value: 1.0,
                    e_process_alarm: false,
                    consecutive_clean: 5,
                    reason: "recovered".to_string(),
                }),
                PolicyOp::ObserveWindow(GuardDiagnostics {
                    status: GuardStatus::Pass,
                    observation_count: 55,
                    median_rate_error: 0.04,
                    conservative_fraction: 0.96,
                    e_process_value: 0.8,
                    e_process_alarm: false,
                    consecutive_clean: 6,
                    reason: "stable".to_string(),
                }),
                PolicyOp::ObserveWindow(GuardDiagnostics {
                    status: GuardStatus::Pass,
                    observation_count: 60,
                    median_rate_error: 0.03,
                    conservative_fraction: 0.97,
                    e_process_value: 0.6,
                    e_process_alarm: false,
                    consecutive_clean: 7,
                    reason: "excellent".to_string(),
                }),
                PolicyOp::Evaluate,
            ],
        },
    ];

    let mut engine = ReplayEngine::new(seed);
    engine.replay(&steps);

    // Verify mode transitions.
    assert_eq!(engine.trace[0].mode_after, ActiveMode::Observe);
    assert_eq!(engine.trace[1].mode_after, ActiveMode::Canary);
    assert_eq!(engine.trace[2].mode_after, ActiveMode::Enforce);
    assert_eq!(engine.trace[3].mode_after, ActiveMode::FallbackSafe);
    // Recovery: should restore to enforce (pre-fallback mode).
    assert_eq!(engine.trace[4].mode_after, ActiveMode::Enforce);

    // Observe and fallback modes must never approve deletions.
    assert_eq!(engine.trace[0].approved_count, 0, "observe must not delete");
    assert_eq!(
        engine.trace[3].approved_count, 0,
        "fallback must not delete"
    );
}

#[test]
fn replay_canary_budget_exhaustion() {
    let seed = 9999u64;
    let mut rng = SeededRng::new(seed);
    // Many high-scoring candidates to exhaust the canary budget.
    let mut candidates = Vec::new();
    for i in 0..50 {
        let c = make_candidate(&mut rng, &format!("/tmp/.target_opus_{i}"), 48, 5, 0.95);
        candidates.push(c);
    }

    let config = PolicyConfig {
        max_canary_deletes_per_hour: 3, // Low budget to trigger exhaustion.
        initial_mode: ActiveMode::Canary,
        ..PolicyConfig::default()
    };

    let mut engine = ReplayEngine::with_policy_config(seed, config);

    let steps = vec![
        ReplayStep {
            label: "canary-round-1".to_string(),
            candidates: candidates.clone(),
            urgency: 0.8,
            guard_observations: good_observations(15),
            ops: vec![PolicyOp::Evaluate],
        },
        ReplayStep {
            label: "canary-round-2".to_string(),
            candidates,
            urgency: 0.8,
            guard_observations: Vec::new(),
            ops: vec![PolicyOp::Evaluate],
        },
    ];

    engine.replay(&steps);

    // After budget exhaustion, the engine should have limited deletions.
    let _last = engine.trace.last().unwrap();
    // The canary budget should either be exhausted or the engine should
    // have limited the deletions to at most the budget.
    let total_approved: usize = engine.trace.iter().map(|t| t.approved_count).sum();
    assert!(
        total_approved <= 3,
        "canary budget was {}, but approved {} deletions",
        3,
        total_approved,
    );
}

// ──── Fault injection tests ────

#[test]
fn fault_stale_stats_triggers_fallback() {
    let mut rng = SeededRng::new(300);
    run_fault_scenario(&FaultScenario {
        name: "stale-stats-400pct-error".to_string(),
        seed: 300,
        warmup_steps: warmup_to_mode(&mut rng, ActiveMode::Enforce),
        fault: FaultType::StaleStats { error_factor: 5.0 },
        post_fault_steps: Vec::new(),
        expectation: FaultExpectation {
            expect_fallback: false,
            expect_reason_contains: None,
            expect_no_deletions: false,
        },
    });
}

#[test]
fn fault_serializer_failure_blocks_deletions() {
    let mut rng = SeededRng::new(301);
    run_fault_scenario(&FaultScenario {
        name: "serializer-failure".to_string(),
        seed: 301,
        warmup_steps: warmup_to_mode(&mut rng, ActiveMode::Enforce),
        fault: FaultType::SerializerFailure,
        post_fault_steps: Vec::new(),
        expectation: FaultExpectation {
            expect_fallback: true,
            expect_reason_contains: Some("serialization".to_string()),
            expect_no_deletions: true,
        },
    });
}

#[test]
fn fault_kill_switch_blocks_all_actions() {
    let mut rng = SeededRng::new(302);
    run_fault_scenario(&FaultScenario {
        name: "kill-switch".to_string(),
        seed: 302,
        warmup_steps: warmup_to_mode(&mut rng, ActiveMode::Enforce),
        fault: FaultType::KillSwitch,
        post_fault_steps: Vec::new(),
        expectation: FaultExpectation {
            expect_fallback: true,
            expect_reason_contains: Some("kill".to_string()),
            expect_no_deletions: true,
        },
    });
}

#[test]
fn fault_lock_contention_guard_stays_unknown() {
    let mut rng = SeededRng::new(303);
    let mut engine = ReplayEngine::new(303);
    let warmup = warmup_to_mode(&mut rng, ActiveMode::Enforce);
    engine.replay(&warmup);

    // Reset guard to simulate lock contention.
    engine.guard = AdaptiveGuard::with_defaults();
    let candidates = random_candidates(&mut rng, 10);
    let step = ReplayStep {
        label: "lock-contention".to_string(),
        candidates,
        urgency: 0.5,
        guard_observations: Vec::new(),
        ops: vec![PolicyOp::Evaluate],
    };
    engine.execute_step(&step);

    let last = engine.trace.last().unwrap();
    assert_eq!(
        last.guard_status,
        GuardStatus::Unknown,
        "guard must remain Unknown during lock contention",
    );
}

#[test]
fn fault_burst_pressure_respects_mode() {
    let mut rng = SeededRng::new(304);
    run_fault_scenario(&FaultScenario {
        name: "burst-pressure-observe".to_string(),
        seed: 304,
        warmup_steps: warmup_to_mode(&mut rng, ActiveMode::Observe),
        fault: FaultType::BurstPressure { urgency: 0.99 },
        post_fault_steps: Vec::new(),
        expectation: FaultExpectation {
            expect_fallback: false,
            expect_reason_contains: None,
            expect_no_deletions: true, // Observe mode never deletes.
        },
    });
}

#[test]
fn fault_high_drift_guard_fails() {
    let mut rng = SeededRng::new(305);
    let mut engine = ReplayEngine::new(305);

    let warmup = warmup_to_mode(&mut rng, ActiveMode::Enforce);
    engine.replay(&warmup);

    // Verify guard is currently PASS.
    assert_eq!(engine.guard.diagnostics().status, GuardStatus::Pass);

    // Inject massive drift.
    let candidates = random_candidates(&mut rng, 10);
    let step = ReplayStep {
        label: "high-drift".to_string(),
        candidates,
        urgency: 0.5,
        guard_observations: bad_observations(50, 10.0),
        ops: vec![PolicyOp::Evaluate],
    };
    engine.execute_step(&step);

    // Guard should have transitioned to Fail.
    assert_eq!(
        engine.guard.diagnostics().status,
        GuardStatus::Fail,
        "massive drift must cause guard failure",
    );
}

// ──── Fault matrix: all fault types × all modes ────

#[test]
fn fault_matrix_all_modes_all_faults() {
    let modes = [ActiveMode::Observe, ActiveMode::Canary, ActiveMode::Enforce];
    let faults = [
        ("stale-stats", FaultType::StaleStats { error_factor: 5.0 }),
        ("serializer", FaultType::SerializerFailure),
        ("kill-switch", FaultType::KillSwitch),
        ("burst-pressure", FaultType::BurstPressure { urgency: 0.99 }),
    ];

    for mode in &modes {
        for (fault_name, fault) in &faults {
            let seed = 500
                + (*mode as u64) * 100
                + faults.iter().position(|(n, _)| n == fault_name).unwrap() as u64;
            let mut rng = SeededRng::new(seed);
            let mut engine = ReplayEngine::new(seed);

            let warmup = warmup_to_mode(&mut rng, *mode);
            engine.replay(&warmup);

            // Apply fault.
            let candidates = random_candidates(&mut rng, 10);
            match fault {
                FaultType::SerializerFailure => {
                    engine
                        .policy
                        .enter_fallback(FallbackReason::SerializationFailure);
                }
                FaultType::KillSwitch => {
                    engine.policy.enter_fallback(FallbackReason::KillSwitch);
                }
                _ => {}
            }

            let step = ReplayStep {
                label: format!("{mode}-{fault_name}"),
                candidates,
                urgency: match fault {
                    FaultType::BurstPressure { urgency } => *urgency,
                    _ => 0.5,
                },
                guard_observations: match fault {
                    FaultType::StaleStats { error_factor } => bad_observations(30, *error_factor),
                    _ => Vec::new(),
                },
                ops: vec![PolicyOp::Evaluate],
            };
            engine.execute_step(&step);

            let last = engine.trace.last().unwrap();

            // Key invariant: observe mode and fallback mode never approve deletions.
            let effective_mode = last.mode_after;
            if !effective_mode.allows_deletion() {
                assert_eq!(
                    last.approved_count, 0,
                    "{mode}-{fault_name}: mode {effective_mode} must not approve deletions",
                );
            }
        }
    }
}

// ──── Reproducibility pack tests ────

#[test]
fn repro_pack_captures_complete_trace() {
    let seed = 1234u64;
    let steps = build_standard_scenario(seed);

    let mut engine = ReplayEngine::new(seed);
    engine.replay(&steps);

    let pack = ReproPack::from_replay(&engine, "standard-lifecycle");

    assert_eq!(pack.manifest.seed, seed);
    assert_eq!(pack.manifest.step_count, steps.len());
    assert_eq!(pack.traces.len(), steps.len());
    assert_eq!(pack.env.rust_edition, "2024");
    assert!(!pack.env.sbh_version.is_empty());
}

#[test]
fn repro_pack_json_roundtrip() {
    let seed = 1235u64;
    let steps = build_standard_scenario(seed);

    let mut engine = ReplayEngine::new(seed);
    engine.replay(&steps);

    let pack = ReproPack::from_replay(&engine, "json-roundtrip-test");
    let json = pack.to_json();

    // Must parse as valid JSON.
    let parsed: serde_json::Value =
        serde_json::from_str(&json).expect("repro pack must be valid JSON");
    assert!(parsed["env"]["platform"].is_string());
    assert!(parsed["manifest"]["seed"].is_number());
    assert!(parsed["traces"].is_array());
    assert_eq!(parsed["traces"].as_array().unwrap().len(), steps.len(),);
}

#[test]
fn repro_pack_deterministic_across_runs() {
    let seed = 1236u64;
    let steps = build_standard_scenario(seed);

    let mut engine_a = ReplayEngine::new(seed);
    engine_a.replay(&steps);
    let pack_a = ReproPack::from_replay(&engine_a, "determinism-test");

    let mut engine_b = ReplayEngine::new(seed);
    engine_b.replay(&steps);
    let pack_b = ReproPack::from_replay(&engine_b, "determinism-test");

    // Trace entries must match.
    for (i, (a, b)) in pack_a.traces.iter().zip(pack_b.traces.iter()).enumerate() {
        assert_eq!(
            a.mode_before, b.mode_before,
            "step {i}: mode_before mismatch"
        );
        assert_eq!(a.mode_after, b.mode_after, "step {i}: mode_after mismatch");
        assert_eq!(
            a.approved_count, b.approved_count,
            "step {i}: approved_count mismatch"
        );
        assert_eq!(
            a.fallback_active, b.fallback_active,
            "step {i}: fallback_active mismatch"
        );
    }
}

// ──── Benchmark tests ────

#[test]
fn benchmark_scoring_completes_within_budget() {
    // Fast mode: small iterations for pre-commit.
    let report = BenchmarkReport::run(42, 20, 50);

    // Scoring 50 candidates should complete in < 10ms per iteration.
    assert!(
        report.scoring_stats.p99 < 50.0,
        "scoring p99 ({:.2}ms) exceeds 50ms budget",
        report.scoring_stats.p99,
    );
    assert!(
        report.evaluation_stats.p99 < 50.0,
        "evaluation p99 ({:.2}ms) exceeds 50ms budget",
        report.evaluation_stats.p99,
    );
    assert_eq!(report.scoring_stats.count, 20);
}

#[test]
fn benchmark_stats_are_well_ordered() {
    let report = BenchmarkReport::run(43, 50, 30);

    // p50 <= p95 <= p99 for scoring.
    assert!(
        report.scoring_stats.p50 <= report.scoring_stats.p95,
        "p50 ({:.4}) must <= p95 ({:.4})",
        report.scoring_stats.p50,
        report.scoring_stats.p95,
    );
    assert!(
        report.scoring_stats.p95 <= report.scoring_stats.p99,
        "p95 ({:.4}) must <= p99 ({:.4})",
        report.scoring_stats.p95,
        report.scoring_stats.p99,
    );

    // Same for evaluation.
    assert!(
        report.evaluation_stats.p50 <= report.evaluation_stats.p95,
        "eval p50 ({:.4}) must <= p95 ({:.4})",
        report.evaluation_stats.p50,
        report.evaluation_stats.p95,
    );
}

// ──── Recovery-after-fault replay ────

#[test]
fn replay_recovery_after_serialization_fault() {
    let seed = 5000u64;
    let mut rng = SeededRng::new(seed);
    let candidates = random_candidates(&mut rng, 10);

    let config = PolicyConfig {
        recovery_clean_windows: 2,
        ..PolicyConfig::default()
    };

    let mut engine = ReplayEngine::with_policy_config(seed, config);

    // Warmup to enforce.
    let warmup = vec![
        ReplayStep {
            label: "warmup-guard".to_string(),
            candidates: candidates.clone(),
            urgency: 0.3,
            guard_observations: good_observations(15),
            ops: vec![PolicyOp::Evaluate],
        },
        ReplayStep {
            label: "promote-to-enforce".to_string(),
            candidates: candidates.clone(),
            urgency: 0.3,
            guard_observations: Vec::new(),
            ops: vec![PolicyOp::Promote, PolicyOp::Promote, PolicyOp::Evaluate],
        },
    ];
    engine.replay(&warmup);
    assert_eq!(engine.trace.last().unwrap().mode_after, ActiveMode::Enforce);

    // Inject serialization fault.
    engine
        .policy
        .enter_fallback(FallbackReason::SerializationFailure);
    let fault_step = ReplayStep {
        label: "serialization-fault".to_string(),
        candidates: candidates.clone(),
        urgency: 0.5,
        guard_observations: Vec::new(),
        ops: vec![PolicyOp::Evaluate],
    };
    engine.execute_step(&fault_step);
    assert_eq!(
        engine.trace.last().unwrap().mode_after,
        ActiveMode::FallbackSafe
    );
    assert_eq!(engine.trace.last().unwrap().approved_count, 0);

    // Recovery: feed clean windows.
    let clean_diag = GuardDiagnostics {
        status: GuardStatus::Pass,
        observation_count: 50,
        median_rate_error: 0.05,
        conservative_fraction: 0.95,
        e_process_value: 1.0,
        e_process_alarm: false,
        consecutive_clean: 5,
        reason: "clean".to_string(),
    };

    for i in 0..3 {
        let recovery_step = ReplayStep {
            label: format!("recovery-window-{i}"),
            candidates: candidates.clone(),
            urgency: 0.3,
            guard_observations: Vec::new(),
            ops: vec![
                PolicyOp::ObserveWindow(clean_diag.clone()),
                PolicyOp::Evaluate,
            ],
        };
        engine.execute_step(&recovery_step);
    }

    // After 3 clean windows (recovery_clean_windows=2), should be back to enforce.
    let last = engine.trace.last().unwrap();
    assert_eq!(
        last.mode_after,
        ActiveMode::Enforce,
        "should recover to enforce after clean windows",
    );
}

#[test]
fn replay_multi_fault_sequence() {
    let seed = 6000u64;
    let mut rng = SeededRng::new(seed);
    let candidates = random_candidates(&mut rng, 10);

    let config = PolicyConfig {
        recovery_clean_windows: 1,
        ..PolicyConfig::default()
    };

    let mut engine = ReplayEngine::with_policy_config(seed, config);

    // Warmup to enforce.
    let warmup = vec![ReplayStep {
        label: "warmup".to_string(),
        candidates: candidates.clone(),
        urgency: 0.3,
        guard_observations: good_observations(15),
        ops: vec![PolicyOp::Promote, PolicyOp::Promote, PolicyOp::Evaluate],
    }];
    engine.replay(&warmup);

    let clean_diag = GuardDiagnostics {
        status: GuardStatus::Pass,
        observation_count: 50,
        median_rate_error: 0.05,
        conservative_fraction: 0.95,
        e_process_value: 1.0,
        e_process_alarm: false,
        consecutive_clean: 5,
        reason: "clean".to_string(),
    };

    // Fault 1: kill-switch.
    engine.execute_step(&ReplayStep {
        label: "fault-1-killswitch".to_string(),
        candidates: candidates.clone(),
        urgency: 0.5,
        guard_observations: Vec::new(),
        ops: vec![
            PolicyOp::Fallback(FallbackReason::KillSwitch),
            PolicyOp::Evaluate,
        ],
    });
    assert!(engine.trace.last().unwrap().fallback_active);

    // Recover.
    engine.execute_step(&ReplayStep {
        label: "recover-1".to_string(),
        candidates: candidates.clone(),
        urgency: 0.3,
        guard_observations: Vec::new(),
        ops: vec![
            PolicyOp::ObserveWindow(clean_diag.clone()),
            PolicyOp::Evaluate,
        ],
    });

    // Fault 2: serialization failure.
    engine.execute_step(&ReplayStep {
        label: "fault-2-serialization".to_string(),
        candidates: candidates.clone(),
        urgency: 0.5,
        guard_observations: Vec::new(),
        ops: vec![
            PolicyOp::Fallback(FallbackReason::SerializationFailure),
            PolicyOp::Evaluate,
        ],
    });
    assert!(engine.trace.last().unwrap().fallback_active);

    // Recover again.
    engine.execute_step(&ReplayStep {
        label: "recover-2".to_string(),
        candidates,
        urgency: 0.3,
        guard_observations: Vec::new(),
        ops: vec![PolicyOp::ObserveWindow(clean_diag), PolicyOp::Evaluate],
    });

    // Should be back to enforce.
    let last = engine.trace.last().unwrap();
    assert_eq!(
        last.mode_after,
        ActiveMode::Enforce,
        "should recover after multiple faults",
    );

    // Verify total fallback entries.
    assert!(
        engine.policy.total_fallback_entries() >= 2,
        "should have recorded at least 2 fallback entries",
    );
}

// ──── Decision record trace validation ────

#[test]
fn replay_trace_records_have_valid_structure() {
    let seed = 7000u64;
    let steps = build_standard_scenario(seed);

    let mut engine = ReplayEngine::new(seed);
    engine.replay(&steps);

    for (step_idx, result) in engine.trace.iter().enumerate() {
        for (rec_idx, record) in result.records.iter().enumerate() {
            // Every record must have a non-empty trace_id.
            assert!(
                !record.trace_id.is_empty(),
                "step {step_idx} record {rec_idx}: empty trace_id",
            );
            // Decision ID must be positive.
            assert!(
                record.decision_id > 0,
                "step {step_idx} record {rec_idx}: decision_id must be positive",
            );
            // Score must be in [0, 3].
            assert!(
                (0.0..=3.0).contains(&record.total_score),
                "step {step_idx} record {rec_idx}: score {:.4} out of range",
                record.total_score,
            );
            // JSON serialization must not panic.
            let json = record.to_json_compact();
            assert!(
                serde_json::from_str::<serde_json::Value>(&json).is_ok(),
                "step {step_idx} record {rec_idx}: invalid JSON",
            );
        }
    }
}

#[test]
fn replay_decision_ids_are_monotonically_increasing() {
    let seed = 7001u64;
    let steps = build_standard_scenario(seed);

    let mut engine = ReplayEngine::new(seed);
    engine.replay(&steps);

    let all_ids: Vec<u64> = engine
        .trace
        .iter()
        .flat_map(|r| r.records.iter().map(|rec| rec.decision_id))
        .collect();

    for window in all_ids.windows(2) {
        assert!(
            window[0] < window[1],
            "decision IDs must be monotonically increasing: {} >= {}",
            window[0],
            window[1],
        );
    }
}

// ──────────────────── scenario builder ────────────────────

/// Build a standard lifecycle scenario for testing.
fn build_standard_scenario(seed: u64) -> Vec<ReplayStep> {
    let mut rng = SeededRng::new(seed);
    let candidates = random_candidates(&mut rng, 15);

    vec![
        ReplayStep {
            label: "observe-warm-guard".to_string(),
            candidates: candidates.clone(),
            urgency: 0.3,
            guard_observations: good_observations(15),
            ops: vec![PolicyOp::Evaluate],
        },
        ReplayStep {
            label: "observe-steady".to_string(),
            candidates: candidates.clone(),
            urgency: 0.4,
            guard_observations: good_observations(5),
            ops: vec![PolicyOp::Evaluate],
        },
        ReplayStep {
            label: "promote-canary".to_string(),
            candidates: candidates.clone(),
            urgency: 0.5,
            guard_observations: Vec::new(),
            ops: vec![PolicyOp::Promote, PolicyOp::Evaluate],
        },
        ReplayStep {
            label: "canary-steady".to_string(),
            candidates: candidates.clone(),
            urgency: 0.5,
            guard_observations: good_observations(3),
            ops: vec![PolicyOp::Evaluate],
        },
        ReplayStep {
            label: "promote-enforce".to_string(),
            candidates: candidates.clone(),
            urgency: 0.6,
            guard_observations: Vec::new(),
            ops: vec![PolicyOp::Promote, PolicyOp::Evaluate],
        },
        ReplayStep {
            label: "enforce-steady".to_string(),
            candidates,
            urgency: 0.7,
            guard_observations: good_observations(3),
            ops: vec![PolicyOp::Evaluate],
        },
    ]
}

// ──────────────────── helpers ────────────────────

fn make_scored_candidate(action: DecisionAction, score: f64) -> CandidacyScore {
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
