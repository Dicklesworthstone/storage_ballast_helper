//! Decision-plane proof harness: deterministic replay, fault-injection,
//! reproducibility pack emission, and benchmark reporting.
//!
//! Two operating modes:
//! - **Fast** (default): reduced scenario set for pre-commit (~1s)
//! - **Full** (`SBH_PROOF_FULL=1`): complete matrix for CI/nightly
//!
//! bd-izu.6

mod common;

use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use storage_ballast_helper::core::config::ScoringConfig;
use storage_ballast_helper::daemon::policy::{
    ActiveMode, FallbackReason, PolicyConfig, PolicyEngine,
};
use storage_ballast_helper::monitor::guardrails::{
    AdaptiveGuard, CalibrationObservation, GuardDiagnostics, GuardStatus, GuardrailConfig,
};
use storage_ballast_helper::scanner::decision_record::{
    ActionRecord, DecisionRecord, DecisionRecordBuilder, ExplainLevel, PolicyMode, format_explain,
};
use storage_ballast_helper::scanner::patterns::{
    ArtifactCategory, ArtifactClassification, StructuralSignals,
};
use storage_ballast_helper::scanner::scoring::{
    CandidacyScore, CandidateInput, DecisionAction, DecisionOutcome, EvidenceLedger, EvidenceTerm,
    ScoreFactors, ScoringEngine,
};

// ════════════════════════════════════════════════════════════
// INFRASTRUCTURE: Seeded RNG + helpers
// ════════════════════════════════════════════════════════════

/// Simple seeded LCG for reproducible test fixtures (not crypto).
struct SeededRng {
    state: u64,
}

impl SeededRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        self.state
    }

    fn next_f64(&mut self) -> f64 {
        let bits = 0x3FF0_0000_0000_0000_u64 | (self.next_u64() >> 12);
        f64::from_bits(bits) - 1.0
    }

    fn next_range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next_u64() % (hi - lo + 1)
    }

    fn next_bool(&mut self, probability: f64) -> bool {
        self.next_f64() < probability
    }
}

fn is_full_mode() -> bool {
    std::env::var("SBH_PROOF_FULL").is_ok_and(|v| v == "1" || v == "true")
}

fn fast_or_full(fast: usize, full: usize) -> usize {
    if is_full_mode() { full } else { fast }
}

fn u64_from_usize(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn usize_from_u64(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

fn elapsed_micros_u64(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX)
}

// ════════════════════════════════════════════════════════════
// FIXTURE BUILDERS
// ════════════════════════════════════════════════════════════

fn make_candidate_input(
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
            pattern_name: ".target*".into(),
            category: ArtifactCategory::RustTarget,
            name_confidence: confidence,
            structural_confidence: confidence * 0.9,
            combined_confidence: confidence,
        },
        signals: StructuralSignals {
            has_incremental: rng.next_bool(0.7),
            has_deps: rng.next_bool(0.8),
            has_build: rng.next_bool(0.8),
            has_fingerprint: rng.next_bool(0.5),
            has_git: false,
            has_cargo_toml: false,
            mostly_object_files: rng.next_bool(0.6),
        },
        is_open: false,
        excluded: false,
    }
}

fn random_candidates(rng: &mut SeededRng, count: usize) -> Vec<CandidateInput> {
    (0..count)
        .map(|i| {
            let age = rng.next_range(1, 48);
            let size = rng.next_range(1, 10);
            let conf = rng.next_f64().mul_add(0.45, 0.5);
            let suffix = rng.next_u64() % 1000;
            make_candidate_input(
                rng,
                &format!("/data/p{i}/.target_{suffix}"),
                age,
                size,
                conf,
            )
        })
        .collect()
}

fn make_scored(action: DecisionAction, score: f64) -> CandidacyScore {
    CandidacyScore {
        path: PathBuf::from("/data/test/.target_opus"),
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
            pattern_name: ".target*".into(),
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
            terms: vec![
                EvidenceTerm {
                    name: "location",
                    weight: 0.25,
                    value: 0.85,
                    contribution: 0.2125,
                },
                EvidenceTerm {
                    name: "name",
                    weight: 0.20,
                    value: 0.90,
                    contribution: 0.18,
                },
            ],
            summary: "test candidate".to_string(),
        },
    }
}

fn good_guard() -> GuardDiagnostics {
    GuardDiagnostics {
        status: GuardStatus::Pass,
        observation_count: 25,
        median_rate_error: 0.10,
        conservative_fraction: 0.85,
        e_process_value: 2.0,
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

fn good_observation() -> CalibrationObservation {
    CalibrationObservation {
        predicted_rate: 1000.0,
        actual_rate: 1050.0,
        predicted_tte: 100.0,
        actual_tte: 110.0,
    }
}

fn bad_observation() -> CalibrationObservation {
    CalibrationObservation {
        predicted_rate: 1000.0,
        actual_rate: 5000.0,
        predicted_tte: 100.0,
        actual_tte: 20.0,
    }
}

fn default_engine() -> ScoringEngine {
    ScoringEngine::from_config(&ScoringConfig::default(), 30)
}

// ════════════════════════════════════════════════════════════
// TRACE TYPES: for replay engine
// ════════════════════════════════════════════════════════════

/// A single operation in a decision-plane trace.
#[derive(Debug, Clone)]
enum TraceOp {
    /// Score a batch of candidates at the given urgency.
    ScoreBatch {
        seed: u64,
        count: usize,
        urgency: f64,
    },
    /// Evaluate candidates through the policy engine.
    PolicyEvaluate {
        candidates: Vec<CandidacyScore>,
        guard: Option<GuardDiagnostics>,
    },
    /// Promote policy mode.
    PolicyPromote,
    /// Demote policy mode.
    PolicyDemote,
    /// Force fallback.
    PolicyFallback(FallbackReason),
    /// Observe a guard window.
    GuardObserve(CalibrationObservation),
    /// Observe a policy window.
    PolicyObserveWindow(GuardDiagnostics),
}

/// Recorded outcome of a trace step for comparison.
#[derive(Debug, Clone)]
struct TraceOutcome {
    step: usize,
    op_name: String,
    policy_mode: Option<ActiveMode>,
    guard_status: Option<GuardStatus>,
    scores: Vec<f64>,
    actions: Vec<ActionRecord>,
    approved_count: usize,
    decision_ids: Vec<u64>,
}

/// Replay result comparing two runs of the same trace.
struct ReplayReport {
    trace_name: String,
    seed: u64,
    total_steps: usize,
    mismatches: Vec<ReplayMismatch>,
    pass: bool,
}

struct ReplayMismatch {
    step: usize,
    field: String,
    expected: String,
    actual: String,
}

// ════════════════════════════════════════════════════════════
// SECTION 1: DETERMINISTIC REPLAY ENGINE
// ════════════════════════════════════════════════════════════

/// Execute a trace and collect outcomes.
#[allow(clippy::too_many_lines)]
fn execute_trace(trace: &[TraceOp]) -> Vec<TraceOutcome> {
    let mut engine = PolicyEngine::new(PolicyConfig::default());
    let scoring = default_engine();
    let mut guard = AdaptiveGuard::new(GuardrailConfig {
        min_observations: 5,
        ..GuardrailConfig::default()
    });
    let mut outcomes = Vec::with_capacity(trace.len());

    for (step, op) in trace.iter().enumerate() {
        let outcome = match op {
            TraceOp::ScoreBatch {
                seed,
                count,
                urgency,
            } => {
                let mut rng = SeededRng::new(*seed);
                let inputs = random_candidates(&mut rng, *count);
                let scored = scoring.score_batch(&inputs, *urgency);
                TraceOutcome {
                    step,
                    op_name: "score_batch".to_string(),
                    policy_mode: Some(engine.mode()),
                    guard_status: Some(guard.status()),
                    scores: scored.iter().map(|s| s.total_score).collect(),
                    actions: scored
                        .iter()
                        .map(|s| ActionRecord::from(s.decision.action))
                        .collect(),
                    approved_count: 0,
                    decision_ids: Vec::new(),
                }
            }
            TraceOp::PolicyEvaluate {
                candidates,
                guard: guard_diag,
            } => {
                let decision = engine.evaluate(candidates, guard_diag.as_ref());
                TraceOutcome {
                    step,
                    op_name: "policy_evaluate".to_string(),
                    policy_mode: Some(decision.mode),
                    guard_status: None,
                    scores: decision.records.iter().map(|r| r.total_score).collect(),
                    actions: decision.records.iter().map(|r| r.action).collect(),
                    approved_count: decision.approved_for_deletion.len(),
                    decision_ids: decision.records.iter().map(|r| r.decision_id).collect(),
                }
            }
            TraceOp::PolicyPromote => {
                engine.promote();
                TraceOutcome {
                    step,
                    op_name: "promote".to_string(),
                    policy_mode: Some(engine.mode()),
                    guard_status: None,
                    scores: Vec::new(),
                    actions: Vec::new(),
                    approved_count: 0,
                    decision_ids: Vec::new(),
                }
            }
            TraceOp::PolicyDemote => {
                engine.demote();
                TraceOutcome {
                    step,
                    op_name: "demote".to_string(),
                    policy_mode: Some(engine.mode()),
                    guard_status: None,
                    scores: Vec::new(),
                    actions: Vec::new(),
                    approved_count: 0,
                    decision_ids: Vec::new(),
                }
            }
            TraceOp::PolicyFallback(reason) => {
                engine.enter_fallback(reason.clone());
                TraceOutcome {
                    step,
                    op_name: "fallback".to_string(),
                    policy_mode: Some(engine.mode()),
                    guard_status: None,
                    scores: Vec::new(),
                    actions: Vec::new(),
                    approved_count: 0,
                    decision_ids: Vec::new(),
                }
            }
            TraceOp::GuardObserve(obs) => {
                guard.observe(*obs);
                TraceOutcome {
                    step,
                    op_name: "guard_observe".to_string(),
                    policy_mode: None,
                    guard_status: Some(guard.status()),
                    scores: Vec::new(),
                    actions: Vec::new(),
                    approved_count: 0,
                    decision_ids: Vec::new(),
                }
            }
            TraceOp::PolicyObserveWindow(diag) => {
                engine.observe_window(diag);
                TraceOutcome {
                    step,
                    op_name: "observe_window".to_string(),
                    policy_mode: Some(engine.mode()),
                    guard_status: None,
                    scores: Vec::new(),
                    actions: Vec::new(),
                    approved_count: 0,
                    decision_ids: Vec::new(),
                }
            }
        };
        outcomes.push(outcome);
    }
    outcomes
}

/// Compare two trace outcomes for exact equality.
fn compare_outcomes(
    trace_name: &str,
    seed: u64,
    expected: &[TraceOutcome],
    actual: &[TraceOutcome],
) -> ReplayReport {
    let mut mismatches = Vec::new();

    if expected.len() != actual.len() {
        mismatches.push(ReplayMismatch {
            step: 0,
            field: "step_count".to_string(),
            expected: expected.len().to_string(),
            actual: actual.len().to_string(),
        });
        return ReplayReport {
            trace_name: trace_name.to_string(),
            seed,
            total_steps: expected.len(),
            pass: false,
            mismatches,
        };
    }

    for (e, a) in expected.iter().zip(actual.iter()) {
        if e.policy_mode != a.policy_mode {
            mismatches.push(ReplayMismatch {
                step: e.step,
                field: "policy_mode".to_string(),
                expected: format!("{:?}", e.policy_mode),
                actual: format!("{:?}", a.policy_mode),
            });
        }
        if e.guard_status != a.guard_status {
            mismatches.push(ReplayMismatch {
                step: e.step,
                field: "guard_status".to_string(),
                expected: format!("{:?}", e.guard_status),
                actual: format!("{:?}", a.guard_status),
            });
        }
        if e.scores.len() == a.scores.len() {
            for (i, (es, as_)) in e.scores.iter().zip(a.scores.iter()).enumerate() {
                if (es - as_).abs() > f64::EPSILON {
                    mismatches.push(ReplayMismatch {
                        step: e.step,
                        field: format!("score[{i}]"),
                        expected: format!("{es:.6}"),
                        actual: format!("{as_:.6}"),
                    });
                }
            }
        } else {
            mismatches.push(ReplayMismatch {
                step: e.step,
                field: "scores_len".to_string(),
                expected: e.scores.len().to_string(),
                actual: a.scores.len().to_string(),
            });
        }
        if e.actions != a.actions {
            mismatches.push(ReplayMismatch {
                step: e.step,
                field: "actions".to_string(),
                expected: format!("{:?}", e.actions),
                actual: format!("{:?}", a.actions),
            });
        }
        if e.approved_count != a.approved_count {
            mismatches.push(ReplayMismatch {
                step: e.step,
                field: "approved_count".to_string(),
                expected: e.approved_count.to_string(),
                actual: a.approved_count.to_string(),
            });
        }
        if e.decision_ids != a.decision_ids {
            mismatches.push(ReplayMismatch {
                step: e.step,
                field: "decision_ids".to_string(),
                expected: format!("{:?}", e.decision_ids),
                actual: format!("{:?}", a.decision_ids),
            });
        }
    }

    let pass = mismatches.is_empty();
    ReplayReport {
        trace_name: trace_name.to_string(),
        seed,
        total_steps: expected.len(),
        pass,
        mismatches,
    }
}

fn assert_replay_pass(report: &ReplayReport) {
    if !report.pass {
        let mut msg = format!(
            "REPLAY FAILED: '{}' (seed={}, steps={}):\n",
            report.trace_name, report.seed, report.total_steps,
        );
        for m in &report.mismatches {
            let _ = writeln!(
                msg,
                "  step {}: {} expected={} actual={}",
                m.step, m.field, m.expected, m.actual,
            );
        }
        panic!("{msg}");
    }
}

// ──── replay tests ────

#[test]
fn replay_scoring_is_deterministic_across_runs() {
    let seeds = fast_or_full(5, 50);
    for seed in 0..u64_from_usize(seeds) {
        let trace = vec![
            TraceOp::ScoreBatch {
                seed,
                count: 20,
                urgency: 0.5,
            },
            TraceOp::ScoreBatch {
                seed: seed + 1000,
                count: 10,
                urgency: 0.8,
            },
        ];

        let run1 = execute_trace(&trace);
        let run2 = execute_trace(&trace);
        let report = compare_outcomes("scoring_determinism", seed, &run1, &run2);
        assert_replay_pass(&report);
    }
}

#[test]
fn replay_policy_lifecycle_trace() {
    let candidates = vec![
        make_scored(DecisionAction::Delete, 2.5),
        make_scored(DecisionAction::Keep, 0.5),
    ];

    let trace = vec![
        // Start in observe.
        TraceOp::PolicyEvaluate {
            candidates: candidates.clone(),
            guard: Some(good_guard()),
        },
        // Promote to canary.
        TraceOp::PolicyPromote,
        TraceOp::PolicyEvaluate {
            candidates: candidates.clone(),
            guard: Some(good_guard()),
        },
        // Promote to enforce.
        TraceOp::PolicyPromote,
        TraceOp::PolicyEvaluate {
            candidates: candidates.clone(),
            guard: Some(good_guard()),
        },
        // Fallback.
        TraceOp::PolicyFallback(FallbackReason::GuardrailDrift),
        TraceOp::PolicyEvaluate {
            candidates,
            guard: Some(good_guard()),
        },
        // Recovery.
        TraceOp::PolicyObserveWindow(good_guard()),
        TraceOp::PolicyObserveWindow(good_guard()),
        TraceOp::PolicyObserveWindow(good_guard()),
    ];

    let run1 = execute_trace(&trace);
    let run2 = execute_trace(&trace);
    let report = compare_outcomes("policy_lifecycle", 0, &run1, &run2);
    assert_replay_pass(&report);

    // Verify specific mode transitions.
    assert_eq!(run1[0].policy_mode, Some(ActiveMode::Observe));
    assert_eq!(run1[0].approved_count, 0); // observe never approves
    assert_eq!(run1[2].policy_mode, Some(ActiveMode::Canary));
    assert_eq!(run1[4].policy_mode, Some(ActiveMode::Enforce));
    assert!(run1[4].approved_count > 0); // enforce approves deletes
    assert_eq!(run1[6].policy_mode, Some(ActiveMode::FallbackSafe));
    assert_eq!(run1[6].approved_count, 0); // fallback blocks all
}

#[test]
fn replay_guard_state_machine_trace() {
    let trace = vec![
        // Start unknown, feed good observations.
        TraceOp::GuardObserve(good_observation()),
        TraceOp::GuardObserve(good_observation()),
        TraceOp::GuardObserve(good_observation()),
        TraceOp::GuardObserve(good_observation()),
        TraceOp::GuardObserve(good_observation()),
        // Should be Pass now. Feed bad to trigger Fail.
        TraceOp::GuardObserve(bad_observation()),
        TraceOp::GuardObserve(bad_observation()),
        TraceOp::GuardObserve(bad_observation()),
        TraceOp::GuardObserve(bad_observation()),
        TraceOp::GuardObserve(bad_observation()),
        // Feed good for recovery.
        TraceOp::GuardObserve(good_observation()),
        TraceOp::GuardObserve(good_observation()),
        TraceOp::GuardObserve(good_observation()),
    ];

    let run1 = execute_trace(&trace);
    let run2 = execute_trace(&trace);
    let report = compare_outcomes("guard_state_machine", 0, &run1, &run2);
    assert_replay_pass(&report);

    // Verify state progression.
    // After 5 good obs (min_observations=5), should be Pass.
    assert_eq!(run1[4].guard_status, Some(GuardStatus::Pass));
}

#[test]
fn replay_mixed_operations_seeded() {
    let iterations = fast_or_full(5, 30);
    for seed in 0..u64_from_usize(iterations) {
        let mut rng = SeededRng::new(seed * 31 + 7);
        let mut trace = Vec::new();

        for _ in 0..20 {
            let op = rng.next_u64() % 6;
            match op {
                0 => trace.push(TraceOp::ScoreBatch {
                    seed: rng.next_u64(),
                    count: usize_from_u64(rng.next_range(5, 20)),
                    urgency: rng.next_f64(),
                }),
                1 => trace.push(TraceOp::PolicyPromote),
                2 => trace.push(TraceOp::PolicyDemote),
                3 => trace.push(TraceOp::PolicyFallback(FallbackReason::PolicyError {
                    details: format!("fault-{seed}"),
                })),
                4 => {
                    if rng.next_bool(0.6) {
                        trace.push(TraceOp::GuardObserve(good_observation()));
                    } else {
                        trace.push(TraceOp::GuardObserve(bad_observation()));
                    }
                }
                _ => {
                    let candidates = vec![
                        make_scored(DecisionAction::Delete, rng.next_f64() * 3.0),
                        make_scored(DecisionAction::Keep, rng.next_f64()),
                    ];
                    trace.push(TraceOp::PolicyEvaluate {
                        candidates,
                        guard: if rng.next_bool(0.5) {
                            Some(good_guard())
                        } else {
                            None
                        },
                    });
                }
            }
        }

        let run1 = execute_trace(&trace);
        let run2 = execute_trace(&trace);
        let report = compare_outcomes("mixed_seeded", seed, &run1, &run2);
        assert_replay_pass(&report);
    }
}

// ════════════════════════════════════════════════════════════
// SECTION 2: FAULT-INJECTION SUITE
// ════════════════════════════════════════════════════════════

// Fault family 1: Serialization failure → fallback-safe behavior

#[test]
fn fault_serialization_failure_triggers_conservative_action() {
    // When evidence serialization fails, the engine should produce
    // fallback-safe decisions (no deletions approved).
    let mut engine = PolicyEngine::new(PolicyConfig::default());
    engine.promote();
    engine.promote(); // enforce

    // Simulate serialization failure by entering fallback.
    engine.enter_fallback(FallbackReason::SerializationFailure);

    let candidates = vec![
        make_scored(DecisionAction::Delete, 2.8),
        make_scored(DecisionAction::Delete, 2.5),
    ];
    let decision = engine.evaluate(&candidates, Some(&good_guard()));

    assert!(
        decision.approved_for_deletion.is_empty(),
        "serialization failure must block all deletions"
    );
    assert_eq!(decision.mode, ActiveMode::FallbackSafe);

    // Records should still be produced (for logging).
    assert_eq!(decision.records.len(), 2);
    assert_eq!(decision.records[0].policy_mode, PolicyMode::Shadow);
}

// Fault family 2: Stale guard stats → conservative fallback

#[test]
fn fault_stale_guard_unknown_blocks_adaptive() {
    let mut engine = PolicyEngine::new(PolicyConfig::default());
    engine.promote();
    engine.promote(); // enforce

    let stale_guard = GuardDiagnostics {
        status: GuardStatus::Unknown,
        observation_count: 3,
        median_rate_error: 0.5,
        conservative_fraction: 0.4,
        e_process_value: 1.0,
        e_process_alarm: false,
        consecutive_clean: 0,
        reason: "insufficient data (stale)".to_string(),
    };

    let candidates = vec![make_scored(DecisionAction::Delete, 2.5)];
    let decision = engine.evaluate(&candidates, Some(&stale_guard));

    // Guard penalty should block the deletion even in enforce mode.
    assert!(
        decision.approved_for_deletion.is_empty(),
        "stale guard data must prevent adaptive deletions"
    );
}

// Fault family 3: E-process drift alarm → immediate fallback

#[test]
fn fault_eprocess_drift_forces_fallback() {
    let mut engine = PolicyEngine::new(PolicyConfig::default());
    engine.promote(); // canary

    let drift_guard = failing_guard();
    let candidates = vec![make_scored(DecisionAction::Delete, 2.5)];
    let decision = engine.evaluate(&candidates, Some(&drift_guard));

    assert_eq!(
        engine.mode(),
        ActiveMode::FallbackSafe,
        "e-process alarm must force fallback"
    );
    assert!(decision.approved_for_deletion.is_empty());
}

// Fault family 4: Canary budget exhaustion → graceful degradation

#[test]
fn fault_canary_budget_exhaustion() {
    let config = PolicyConfig {
        max_canary_deletes_per_hour: 2,
        ..PolicyConfig::default()
    };
    let mut engine = PolicyEngine::new(config);
    engine.promote(); // canary

    let candidates = vec![
        make_scored(DecisionAction::Delete, 2.8),
        make_scored(DecisionAction::Delete, 2.5),
        make_scored(DecisionAction::Delete, 2.3),
        make_scored(DecisionAction::Delete, 2.1),
    ];
    let decision = engine.evaluate(&candidates, Some(&good_guard()));

    // Should approve 2 then enter fallback.
    assert_eq!(decision.approved_for_deletion.len(), 2);
    assert_eq!(
        engine.mode(),
        ActiveMode::FallbackSafe,
        "canary budget exhaustion must trigger fallback"
    );
    assert!(matches!(
        engine.fallback_reason(),
        Some(FallbackReason::CanaryBudgetExhausted)
    ));
}

// Fault family 5: Kill-switch engagement → immediate block

#[test]
fn fault_kill_switch_blocks_everything() {
    let config = PolicyConfig {
        kill_switch: true,
        initial_mode: ActiveMode::Enforce,
        ..PolicyConfig::default()
    };
    let engine = PolicyEngine::new(config);

    assert_eq!(
        engine.mode(),
        ActiveMode::FallbackSafe,
        "kill-switch must override initial_mode"
    );
}

// Fault family 6: Calibration breach cascade → fallback after N windows

#[test]
fn fault_calibration_breach_cascade() {
    let config = PolicyConfig {
        calibration_breach_windows: 3,
        ..PolicyConfig::default()
    };
    let mut engine = PolicyEngine::new(config);
    engine.promote(); // canary

    let bad_guard = GuardDiagnostics {
        status: GuardStatus::Fail,
        observation_count: 25,
        median_rate_error: 0.45,
        conservative_fraction: 0.55,
        e_process_value: 5.0,
        e_process_alarm: false, // no alarm, but calibration is bad
        consecutive_clean: 0,
        reason: "calibration failed".to_string(),
    };

    engine.observe_window(&bad_guard);
    assert_eq!(engine.mode(), ActiveMode::Canary);
    engine.observe_window(&bad_guard);
    assert_eq!(engine.mode(), ActiveMode::Canary);
    engine.observe_window(&bad_guard);
    assert_eq!(
        engine.mode(),
        ActiveMode::FallbackSafe,
        "3 consecutive breaches must trigger fallback"
    );
    assert!(matches!(
        engine.fallback_reason(),
        Some(FallbackReason::CalibrationBreach {
            consecutive_windows: 3
        })
    ));
}

// Fault family 7: Recovery after fault — clean windows restore mode

#[test]
fn fault_recovery_after_drift() {
    let config = PolicyConfig {
        recovery_clean_windows: 2,
        ..PolicyConfig::default()
    };
    let mut engine = PolicyEngine::new(config);
    engine.promote();
    engine.promote(); // enforce
    engine.enter_fallback(FallbackReason::GuardrailDrift);

    assert_eq!(engine.mode(), ActiveMode::FallbackSafe);

    // One clean window — not enough.
    engine.observe_window(&good_guard());
    assert_eq!(engine.mode(), ActiveMode::FallbackSafe);

    // Second clean window — recovery.
    // Recovery caps at Canary (mandatory canary gate), not directly to Enforce.
    engine.observe_window(&good_guard());
    assert_eq!(
        engine.mode(),
        ActiveMode::Canary,
        "recovery caps at Canary (mandatory canary gate)"
    );
    assert!(engine.fallback_reason().is_none());

    // An explicit promote is required to return to Enforce.
    engine.promote();
    assert_eq!(engine.mode(), ActiveMode::Enforce);
}

// Fault family 8: Guard with mixed observations → correct status transitions

#[test]
fn fault_guard_mixed_observation_sequence() {
    let config = GuardrailConfig {
        min_observations: 3,
        recovery_clean_windows: 2,
        e_process_threshold: 1e30, // extremely high so e-process doesn't interfere
        ..GuardrailConfig::default()
    };
    let mut guard = AdaptiveGuard::new(config);

    // Build to Pass.
    for _ in 0..5 {
        guard.observe(good_observation());
    }
    assert_eq!(guard.status(), GuardStatus::Pass);

    // Inject bad observations to trigger Fail (window_size=50 default).
    for _ in 0..50 {
        guard.observe(bad_observation());
    }
    assert_eq!(guard.status(), GuardStatus::Fail);

    // Recovery: need 2 consecutive good observations.
    guard.observe(good_observation());
    assert_eq!(guard.status(), GuardStatus::Fail); // 1 good, need 2
    guard.observe(bad_observation()); // reset counter
    assert_eq!(guard.diagnostics().consecutive_clean, 0);
    guard.observe(good_observation());
    guard.observe(good_observation());
    assert_eq!(guard.status(), GuardStatus::Pass); // recovered
}

// Comprehensive fault matrix: all fault types with expected fallback behavior

#[test]
fn fault_matrix_all_types_produce_expected_fallback() {
    struct FaultCase {
        name: &'static str,
        reason: FallbackReason,
    }

    let cases = vec![
        FaultCase {
            name: "serialization",
            reason: FallbackReason::SerializationFailure,
        },
        FaultCase {
            name: "guardrail_drift",
            reason: FallbackReason::GuardrailDrift,
        },
        FaultCase {
            name: "canary_budget",
            reason: FallbackReason::CanaryBudgetExhausted,
        },
        FaultCase {
            name: "kill_switch",
            reason: FallbackReason::KillSwitch,
        },
        FaultCase {
            name: "policy_error",
            reason: FallbackReason::PolicyError {
                details: "test error".to_string(),
            },
        },
        FaultCase {
            name: "calibration_breach",
            reason: FallbackReason::CalibrationBreach {
                consecutive_windows: 3,
            },
        },
    ];

    for case in &cases {
        let mut engine = PolicyEngine::new(PolicyConfig::default());
        engine.promote();
        engine.promote(); // enforce

        engine.enter_fallback(case.reason.clone());

        let candidates = vec![make_scored(DecisionAction::Delete, 2.5)];
        let decision = engine.evaluate(&candidates, Some(&good_guard()));

        assert!(
            decision.approved_for_deletion.is_empty(),
            "fault '{}' must block all deletions",
            case.name,
        );
        assert_eq!(
            decision.mode,
            ActiveMode::FallbackSafe,
            "fault '{}' must set mode to FallbackSafe",
            case.name,
        );
    }
}

// ════════════════════════════════════════════════════════════
// SECTION 3: REPRODUCIBILITY PACK EMISSION
// ════════════════════════════════════════════════════════════

/// Reproducibility pack: captures environment, configuration, and trace data.
#[derive(Debug, serde::Serialize)]
struct ReproducibilityPack {
    /// Environment metadata.
    env: EnvRecord,
    /// Manifest of test configuration.
    manifest: ManifestRecord,
    /// Trace bundle with outcomes.
    trace_bundle: TraceBundle,
}

#[derive(Debug, serde::Serialize)]
struct EnvRecord {
    os: String,
    arch: String,
    rust_version: String,
    timestamp: String,
    hostname: String,
}

#[derive(Debug, serde::Serialize)]
struct ManifestRecord {
    seed: u64,
    scenario_count: usize,
    candidate_count: usize,
    scoring_config: ScoringConfigSnapshot,
    policy_config: PolicyConfigSnapshot,
}

#[derive(Debug, serde::Serialize)]
struct ScoringConfigSnapshot {
    weights: [f64; 5],
    false_positive_loss: f64,
    false_negative_loss: f64,
    calibration_floor: f64,
}

#[derive(Debug, serde::Serialize)]
struct PolicyConfigSnapshot {
    initial_mode: String,
    max_candidates_per_loop: usize,
    max_canary_deletes_per_hour: usize,
    recovery_clean_windows: usize,
}

#[derive(Debug, serde::Serialize)]
struct TraceBundle {
    steps: Vec<TraceBundleStep>,
    invariants_checked: usize,
    invariants_passed: usize,
}

#[derive(Debug, serde::Serialize)]
struct TraceBundleStep {
    step: usize,
    operation: String,
    mode_after: Option<String>,
    guard_after: Option<String>,
    scores: Vec<f64>,
    actions: Vec<String>,
    approved_count: usize,
}

fn build_env_record() -> EnvRecord {
    EnvRecord {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        rust_version: std::env::var("CARGO_PKG_RUST_VERSION")
            .unwrap_or_else(|_| "unknown".to_string()),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or_else(|_| "0".to_string(), |d| d.as_secs().to_string()),
        hostname: std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string()),
    }
}

fn outcomes_to_bundle(outcomes: &[TraceOutcome]) -> TraceBundle {
    let steps: Vec<TraceBundleStep> = outcomes
        .iter()
        .map(|o| TraceBundleStep {
            step: o.step,
            operation: o.op_name.clone(),
            mode_after: o.policy_mode.map(|m| m.to_string()),
            guard_after: o.guard_status.map(|s| s.to_string()),
            scores: o.scores.clone(),
            actions: o
                .actions
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            approved_count: o.approved_count,
        })
        .collect();

    let invariants_checked = steps.len();
    let invariants_passed = invariants_checked; // all passed if we reach here

    TraceBundle {
        steps,
        invariants_checked,
        invariants_passed,
    }
}

#[test]
fn repro_pack_generates_valid_json() {
    let seed = 42u64;
    let trace = vec![
        TraceOp::ScoreBatch {
            seed,
            count: 10,
            urgency: 0.5,
        },
        TraceOp::PolicyPromote,
        TraceOp::PolicyEvaluate {
            candidates: vec![make_scored(DecisionAction::Delete, 2.5)],
            guard: Some(good_guard()),
        },
    ];

    let outcomes = execute_trace(&trace);
    let config = ScoringConfig::default();

    let pack = ReproducibilityPack {
        env: build_env_record(),
        manifest: ManifestRecord {
            seed,
            scenario_count: trace.len(),
            candidate_count: 10,
            scoring_config: ScoringConfigSnapshot {
                weights: [
                    config.location_weight,
                    config.name_weight,
                    config.age_weight,
                    config.size_weight,
                    config.structure_weight,
                ],
                false_positive_loss: config.false_positive_loss,
                false_negative_loss: config.false_negative_loss,
                calibration_floor: config.calibration_floor,
            },
            policy_config: PolicyConfigSnapshot {
                initial_mode: "observe".to_string(),
                max_candidates_per_loop: 100,
                max_canary_deletes_per_hour: 10,
                recovery_clean_windows: 3,
            },
        },
        trace_bundle: outcomes_to_bundle(&outcomes),
    };

    // Must serialize without panic.
    let json = serde_json::to_string_pretty(&pack).expect("repro pack must serialize");
    assert!(!json.is_empty());

    // Must contain key sections.
    assert!(json.contains("\"os\""));
    assert!(json.contains("\"seed\""));
    assert!(json.contains("\"steps\""));
    assert!(json.contains("\"invariants_checked\""));

    // Roundtrip via serde_json::Value.
    let value: serde_json::Value = serde_json::from_str(&json).expect("must parse back");
    assert_eq!(value["manifest"]["seed"], 42);
    assert_eq!(
        value["trace_bundle"]["invariants_checked"],
        u64_from_usize(trace.len()),
    );
}

#[test]
fn repro_pack_is_deterministic() {
    let seed = 99u64;
    let trace = vec![
        TraceOp::ScoreBatch {
            seed,
            count: 15,
            urgency: 0.6,
        },
        TraceOp::PolicyPromote,
        TraceOp::PolicyPromote,
        TraceOp::PolicyEvaluate {
            candidates: vec![
                make_scored(DecisionAction::Delete, 2.5),
                make_scored(DecisionAction::Keep, 0.3),
            ],
            guard: Some(good_guard()),
        },
        TraceOp::PolicyFallback(FallbackReason::GuardrailDrift),
    ];

    let outcomes1 = execute_trace(&trace);
    let outcomes2 = execute_trace(&trace);

    let bundle1 = outcomes_to_bundle(&outcomes1);
    let bundle2 = outcomes_to_bundle(&outcomes2);

    // Bundles must be structurally identical.
    assert_eq!(bundle1.steps.len(), bundle2.steps.len());
    for (s1, s2) in bundle1.steps.iter().zip(bundle2.steps.iter()) {
        assert_eq!(s1.operation, s2.operation);
        assert_eq!(s1.mode_after, s2.mode_after);
        assert_eq!(s1.guard_after, s2.guard_after);
        assert_eq!(s1.scores.len(), s2.scores.len());
        for (a, b) in s1.scores.iter().zip(s2.scores.iter()) {
            assert!(
                (a - b).abs() < f64::EPSILON,
                "scores must be bitwise identical"
            );
        }
        assert_eq!(s1.actions, s2.actions);
        assert_eq!(s1.approved_count, s2.approved_count);
    }
}

#[test]
fn repro_pack_writes_to_tempdir() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let seed = 77u64;

    let trace = vec![TraceOp::ScoreBatch {
        seed,
        count: 5,
        urgency: 0.3,
    }];
    let outcomes = execute_trace(&trace);
    let config = ScoringConfig::default();

    let pack = ReproducibilityPack {
        env: build_env_record(),
        manifest: ManifestRecord {
            seed,
            scenario_count: 1,
            candidate_count: 5,
            scoring_config: ScoringConfigSnapshot {
                weights: [
                    config.location_weight,
                    config.name_weight,
                    config.age_weight,
                    config.size_weight,
                    config.structure_weight,
                ],
                false_positive_loss: config.false_positive_loss,
                false_negative_loss: config.false_negative_loss,
                calibration_floor: config.calibration_floor,
            },
            policy_config: PolicyConfigSnapshot {
                initial_mode: "observe".to_string(),
                max_candidates_per_loop: 100,
                max_canary_deletes_per_hour: 10,
                recovery_clean_windows: 3,
            },
        },
        trace_bundle: outcomes_to_bundle(&outcomes),
    };

    // Write env.json.
    let env_path = dir.path().join("env.json");
    std::fs::write(&env_path, serde_json::to_string_pretty(&pack.env).unwrap())
        .expect("write env.json");
    assert!(env_path.exists());

    // Write manifest.json.
    let manifest_path = dir.path().join("manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&pack.manifest).unwrap(),
    )
    .expect("write manifest.json");
    assert!(manifest_path.exists());

    // Write trace_bundle.json.
    let trace_path = dir.path().join("trace_bundle.json");
    std::fs::write(
        &trace_path,
        serde_json::to_string_pretty(&pack.trace_bundle).unwrap(),
    )
    .expect("write trace_bundle.json");
    assert!(trace_path.exists());

    // Verify files are non-empty and parseable.
    for path in &[&env_path, &manifest_path, &trace_path] {
        let content = std::fs::read_to_string(path).unwrap();
        assert!(!content.is_empty());
        let _: serde_json::Value = serde_json::from_str(&content).expect("must be valid JSON");
    }
}

// ════════════════════════════════════════════════════════════
// SECTION 4: STATISTICAL BENCHMARK REPORT
// ════════════════════════════════════════════════════════════

/// Benchmark timing report with percentile statistics.
#[derive(Debug, serde::Serialize)]
struct BenchmarkReport {
    operation: String,
    sample_count: usize,
    p50_us: u64,
    p95_us: u64,
    p99_us: u64,
    min_us: u64,
    max_us: u64,
    mean_us: u64,
}

fn compute_percentile(sorted: &[u64], percentile: u32) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let len = sorted.len();
    let pct = usize::try_from(percentile).unwrap_or(0);
    let idx = len.saturating_mul(pct).saturating_add(99) / 100;
    let idx = idx.saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)]
}

fn benchmark_operation<F: FnMut()>(name: &str, iterations: usize, mut op: F) -> BenchmarkReport {
    let mut timings = Vec::with_capacity(iterations);

    // Warmup.
    for _ in 0..3 {
        op();
    }

    for _ in 0..iterations {
        let start = Instant::now();
        op();
        timings.push(elapsed_micros_u64(start));
    }

    timings.sort_unstable();
    let sum: u64 = timings.iter().sum();

    BenchmarkReport {
        operation: name.to_string(),
        sample_count: iterations,
        p50_us: compute_percentile(&timings, 50),
        p95_us: compute_percentile(&timings, 95),
        p99_us: compute_percentile(&timings, 99),
        min_us: timings[0],
        max_us: *timings.last().unwrap(),
        mean_us: sum / u64_from_usize(iterations),
    }
}

#[test]
fn benchmark_scoring_engine() {
    let iterations = fast_or_full(20, 100);
    let engine = default_engine();
    let mut rng = SeededRng::new(42);
    let candidates = random_candidates(&mut rng, 50);

    let report = benchmark_operation("score_batch_50", iterations, || {
        let _ = engine.score_batch(&candidates, 0.5);
    });

    // Serialize to verify structure.
    let json = serde_json::to_string_pretty(&report).unwrap();
    assert!(json.contains("\"p50_us\""));
    assert!(json.contains("\"p95_us\""));

    // Sanity: scoring 50 candidates should be fast.
    assert!(
        report.p99_us < 50_000, // 50ms ceiling
        "scoring 50 candidates took p99={}us, expected < 50000us",
        report.p99_us,
    );
}

#[test]
fn benchmark_policy_evaluation() {
    let iterations = fast_or_full(20, 100);
    let candidates = vec![
        make_scored(DecisionAction::Delete, 2.5),
        make_scored(DecisionAction::Keep, 0.5),
        make_scored(DecisionAction::Delete, 2.0),
    ];
    let guard = good_guard();

    let report = benchmark_operation("policy_eval_3", iterations, || {
        let mut engine = PolicyEngine::new(PolicyConfig::default());
        engine.promote();
        engine.promote();
        let _ = engine.evaluate(&candidates, Some(&guard));
    });

    let json = serde_json::to_string_pretty(&report).unwrap();
    assert!(json.contains("\"operation\""));

    // Policy evaluation should be very fast.
    assert!(
        report.p99_us < 10_000, // 10ms ceiling
        "policy eval took p99={}us, expected < 10000us",
        report.p99_us,
    );
}

#[test]
fn benchmark_decision_record_serialization() {
    let iterations = fast_or_full(50, 500);
    let mut builder = DecisionRecordBuilder::new();
    let candidate = make_scored(DecisionAction::Delete, 2.5);
    let record = builder.build(&candidate, PolicyMode::Live, Some(&good_guard()), None);

    let report = benchmark_operation("decision_record_json", iterations, || {
        let json = record.to_json_compact();
        let _: DecisionRecord = serde_json::from_str(&json).unwrap();
    });

    // Serialization should be cheap.
    assert!(
        report.p99_us < 5_000, // 5ms ceiling
        "decision record roundtrip took p99={}us",
        report.p99_us,
    );
}

#[test]
fn benchmark_guard_observation() {
    let iterations = fast_or_full(50, 500);

    let report = benchmark_operation("guard_observe_50", iterations, || {
        let mut guard = AdaptiveGuard::new(GuardrailConfig {
            min_observations: 5,
            window_size: 50,
            ..GuardrailConfig::default()
        });
        for _ in 0..50 {
            guard.observe(good_observation());
        }
    });

    assert!(
        report.p99_us < 5_000,
        "50 guard observations took p99={}us",
        report.p99_us,
    );
}

#[test]
fn benchmark_report_comparison() {
    // Generate two reports and verify they can be compared.
    let engine = default_engine();
    let mut rng = SeededRng::new(42);
    let candidates = random_candidates(&mut rng, 30);
    let iterations = fast_or_full(10, 50);

    let report1 = benchmark_operation("scoring_run1", iterations, || {
        let _ = engine.score_batch(&candidates, 0.5);
    });

    let report2 = benchmark_operation("scoring_run2", iterations, || {
        let _ = engine.score_batch(&candidates, 0.5);
    });

    // Build a comparison report.
    let delta_p50 = i128::from(report2.p50_us) - i128::from(report1.p50_us);
    let delta_p95 = i128::from(report2.p95_us) - i128::from(report1.p95_us);
    let delta_p99 = i128::from(report2.p99_us) - i128::from(report1.p99_us);

    let comparison = serde_json::json!({
        "baseline": {
            "p50_us": report1.p50_us,
            "p95_us": report1.p95_us,
            "p99_us": report1.p99_us,
        },
        "current": {
            "p50_us": report2.p50_us,
            "p95_us": report2.p95_us,
            "p99_us": report2.p99_us,
        },
        "delta": {
            "p50_us": delta_p50,
            "p95_us": delta_p95,
            "p99_us": delta_p99,
        },
    });

    let json = serde_json::to_string_pretty(&comparison).unwrap();
    assert!(json.contains("\"baseline\""));
    assert!(json.contains("\"current\""));
    assert!(json.contains("\"delta\""));
}

// ════════════════════════════════════════════════════════════
// SECTION 5: CROSS-CUTTING INVARIANT VERIFICATION
// ════════════════════════════════════════════════════════════

#[test]
fn invariant_fallback_always_dominates() {
    // For every possible fault type, verify that:
    // 1. FallbackSafe is entered
    // 2. No deletions are approved
    // 3. Decision records are still produced
    // 4. Records carry shadow policy mode
    let iterations = fast_or_full(5, 20);

    for seed in 0..u64_from_usize(iterations) {
        let mut rng = SeededRng::new(seed * 13 + 5);

        let faults = [
            FallbackReason::SerializationFailure,
            FallbackReason::GuardrailDrift,
            FallbackReason::CanaryBudgetExhausted,
            FallbackReason::KillSwitch,
            FallbackReason::PolicyError {
                details: format!("seed-{seed}"),
            },
            FallbackReason::CalibrationBreach {
                consecutive_windows: 3,
            },
        ];

        for fault in &faults {
            let mut engine = PolicyEngine::new(PolicyConfig::default());
            // Randomly promote before fallback.
            let promotions = rng.next_range(0, 2);
            for _ in 0..promotions {
                engine.promote();
            }
            engine.enter_fallback(fault.clone());

            let candidates: Vec<CandidacyScore> = (0..5)
                .map(|_| make_scored(DecisionAction::Delete, 2.0 + rng.next_f64()))
                .collect();

            let decision = engine.evaluate(&candidates, Some(&good_guard()));

            assert!(decision.approved_for_deletion.is_empty());
            assert_eq!(decision.mode, ActiveMode::FallbackSafe);
            assert!(!decision.records.is_empty());
            for record in &decision.records {
                assert_eq!(record.policy_mode, PolicyMode::Shadow);
            }
        }
    }
}

#[test]
fn invariant_decision_ids_are_globally_monotonic() {
    let mut engine = PolicyEngine::new(PolicyConfig::default());
    let candidates = vec![
        make_scored(DecisionAction::Delete, 2.5),
        make_scored(DecisionAction::Keep, 0.5),
    ];

    let mut prev_max_id = 0u64;

    for _ in 0..10 {
        let decision = engine.evaluate(&candidates, None);
        for record in &decision.records {
            assert!(
                record.decision_id > prev_max_id,
                "decision_id {} must be > previous max {}",
                record.decision_id,
                prev_max_id,
            );
            prev_max_id = record.decision_id;
        }
    }
}

#[test]
fn invariant_all_records_serialize_and_roundtrip() {
    let iterations = fast_or_full(10, 50);

    for seed in 0..u64_from_usize(iterations) {
        let mut rng = SeededRng::new(seed * 7 + 3);
        let engine = default_engine();
        let inputs = random_candidates(&mut rng, 20);
        let urgency = rng.next_f64();
        let scored = engine.score_batch(&inputs, urgency);

        let mut builder = DecisionRecordBuilder::new();
        for s in &scored {
            let record = builder.build(s, PolicyMode::Live, None, None);

            // Compact JSON roundtrip.
            let json = record.to_json_compact();
            let parsed: DecisionRecord = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("seed={seed}: JSON roundtrip failed: {e}\njson={json}"));
            assert_eq!(parsed.decision_id, record.decision_id);
            assert_eq!(parsed.action, record.action);
            // JSON uses decimal representation; f64 roundtrip tolerance
            // must account for representation loss (typically < 1e-12).
            assert!(
                (parsed.total_score - record.total_score).abs() < 1e-10,
                "seed={seed}: score mismatch: {} vs {}",
                parsed.total_score,
                record.total_score,
            );

            // Explain at all levels.
            for level in [
                ExplainLevel::L0,
                ExplainLevel::L1,
                ExplainLevel::L2,
                ExplainLevel::L3,
            ] {
                let text = format_explain(&record, level);
                assert!(!text.is_empty(), "seed={seed}: explain {level} is empty");
            }

            // JSON at all levels.
            for level in [
                ExplainLevel::L0,
                ExplainLevel::L1,
                ExplainLevel::L2,
                ExplainLevel::L3,
            ] {
                let val = record.to_json_at_level(level);
                assert!(
                    val.is_object(),
                    "seed={seed}: json_at_level {level} not object"
                );
            }
        }
    }
}

#[test]
fn invariant_transition_log_is_append_only() {
    let mut engine = PolicyEngine::new(PolicyConfig::default());

    let ops = [
        |e: &mut PolicyEngine| {
            e.promote();
        },
        |e: &mut PolicyEngine| {
            e.promote();
        },
        |e: &mut PolicyEngine| {
            e.demote();
        },
        |e: &mut PolicyEngine| {
            e.enter_fallback(FallbackReason::KillSwitch);
        },
    ];

    let mut prev_len = 0;
    for op in &ops {
        op(&mut engine);
        let log = engine.transition_log();
        assert!(log.len() >= prev_len, "transition log must be append-only");
        prev_len = log.len();
    }
}

// ════════════════════════════════════════════════════════════
// SECTION 6: FULL-MODE COMPREHENSIVE MATRIX
// ════════════════════════════════════════════════════════════

#[test]
fn full_mode_exhaustive_seed_replay() {
    if !is_full_mode() {
        return; // skip in fast mode
    }

    for seed in 0..100u64 {
        let mut rng = SeededRng::new(seed);
        let mut trace = Vec::new();

        // Generate a longer trace.
        for _ in 0..50 {
            let op = rng.next_u64() % 7;
            match op {
                0 => trace.push(TraceOp::ScoreBatch {
                    seed: rng.next_u64(),
                    count: usize_from_u64(rng.next_range(5, 30)),
                    urgency: rng.next_f64(),
                }),
                1 => trace.push(TraceOp::PolicyPromote),
                2 => trace.push(TraceOp::PolicyDemote),
                3 => trace.push(TraceOp::PolicyFallback(FallbackReason::PolicyError {
                    details: format!("seed-{seed}"),
                })),
                4 => {
                    let obs = if rng.next_bool(0.6) {
                        good_observation()
                    } else {
                        bad_observation()
                    };
                    trace.push(TraceOp::GuardObserve(obs));
                }
                5 => {
                    let diag = if rng.next_bool(0.7) {
                        good_guard()
                    } else {
                        failing_guard()
                    };
                    trace.push(TraceOp::PolicyObserveWindow(diag));
                }
                _ => {
                    let count = usize_from_u64(rng.next_range(1, 5));
                    let candidates: Vec<CandidacyScore> = (0..count)
                        .map(|_| {
                            if rng.next_bool(0.6) {
                                make_scored(DecisionAction::Delete, rng.next_f64() * 3.0)
                            } else {
                                make_scored(DecisionAction::Keep, rng.next_f64())
                            }
                        })
                        .collect();
                    let guard = if rng.next_bool(0.5) {
                        Some(good_guard())
                    } else {
                        None
                    };
                    trace.push(TraceOp::PolicyEvaluate { candidates, guard });
                }
            }
        }

        let run1 = execute_trace(&trace);
        let run2 = execute_trace(&trace);
        let report = compare_outcomes("exhaustive_seed", seed, &run1, &run2);
        assert_replay_pass(&report);
    }
}
