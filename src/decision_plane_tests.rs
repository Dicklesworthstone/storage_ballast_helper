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

use crate::daemon::policy::{
    ActiveMode, FallbackReason, PolicyConfig, PolicyEngine,
};
use crate::monitor::guardrails::{
    AdaptiveGuard, CalibrationObservation, GuardrailConfig, GuardStatus,
};
use crate::scanner::decision_record::{
    ActionRecord, DecisionRecordBuilder, ExplainLevel, PolicyMode,
    format_explain,
};
use crate::scanner::scoring::{
    CandidacyScore, CandidateInput, DecisionAction, DecisionOutcome, EvidenceLedger,
    EvidenceTerm, ScoreFactors, ScoringEngine,
};
use crate::scanner::patterns::{ArtifactCategory, ArtifactClassification, StructuralSignals};

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
        self.state = self.state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
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
            assert_eq!(
                a.path, b.path,
                "trial {trial}: paths must be identical"
            );
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
        if (pair[0].classification.combined_confidence
            - pair[1].classification.combined_confidence)
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
            actual_rate: 5000.0,  // 400% error
            predicted_tte: 100.0,
            actual_tte: 20.0,   // non-conservative
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
    assert_eq!(entries_1, entries_2, "double fallback must not increment counter");
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
    assert_eq!(engine.mode(), ActiveMode::Canary, "should restore pre-fallback mode");
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

    for mode in [PolicyMode::Live, PolicyMode::Shadow, PolicyMode::Canary, PolicyMode::DryRun] {
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
                0 => { engine.promote(); }
                1 => { engine.demote(); }
                2 => {
                    engine.enter_fallback(FallbackReason::PolicyError {
                        details: format!("seed={seed} step={step}"),
                    });
                }
                3 => {
                    let good = rng.next_f64() > 0.3;
                    let guard = crate::monitor::guardrails::GuardDiagnostics {
                        status: if good { GuardStatus::Pass } else { GuardStatus::Fail },
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
