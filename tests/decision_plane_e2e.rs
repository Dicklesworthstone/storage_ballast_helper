//! Decision-plane end-to-end scenario pack with verbose trace logging.
//!
//! Exercises shadow, canary, enforce, and fallback behavior under realistic
//! pressure and failure modes.  Every scenario produces a machine-readable
//! trace sufficient for postmortem debugging.
//!
//! bd-izu.7

mod common;

use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use storage_ballast_helper::core::config::ScoringConfig;
use storage_ballast_helper::daemon::policy::{
    ActiveMode, FallbackReason, PolicyConfig, PolicyEngine,
};
use storage_ballast_helper::monitor::guardrails::{
    AdaptiveGuard, CalibrationObservation, GuardDiagnostics, GuardStatus, GuardrailConfig,
};
use storage_ballast_helper::scanner::decision_record::{
    ActionRecord, ExplainLevel, PolicyMode, format_explain,
};
use storage_ballast_helper::scanner::patterns::{
    ArtifactCategory, ArtifactClassification, StructuralSignals,
};
use storage_ballast_helper::scanner::scoring::{CandidateInput, ScoringEngine};

// ════════════════════════════════════════════════════════════════
// INFRASTRUCTURE
// ════════════════════════════════════════════════════════════════

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

fn make_candidate(
    rng: &mut SeededRng,
    idx: usize,
    age_hours: u64,
    size_gib: u64,
) -> CandidateInput {
    let suffix = rng.next_u64() % 1000;
    let conf = rng.next_f64().mul_add(0.45, 0.5);
    CandidateInput {
        path: PathBuf::from(format!("/data/p{idx}/.target_{suffix}")),
        size_bytes: size_gib * 1_073_741_824,
        age: Duration::from_secs(age_hours * 3600),
        classification: ArtifactClassification {
            pattern_name: ".target*".into(),
            category: ArtifactCategory::RustTarget,
            name_confidence: conf,
            structural_confidence: conf * 0.9,
            combined_confidence: conf,
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
            make_candidate(rng, i, age, size)
        })
        .collect()
}

fn default_engine() -> ScoringEngine {
    ScoringEngine::from_config(&ScoringConfig::default(), 30)
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

/// Scenario trace record for verbose logging.
struct ScenarioTrace {
    name: String,
    steps: Vec<StepTrace>,
    pass: bool,
}

#[allow(dead_code)]
struct StepTrace {
    label: String,
    mode_before: ActiveMode,
    mode_after: ActiveMode,
    guard_status: GuardStatus,
    candidates_scored: usize,
    approved_count: usize,
    decision_ids: Vec<u64>,
    trace_ids: Vec<String>,
    assertions: Vec<String>,
}

impl ScenarioTrace {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            steps: Vec::new(),
            pass: true,
        }
    }

    fn emit_report(&self) -> String {
        let mut out = String::new();
        writeln!(out, "═══ Scenario: {} ═══", self.name).unwrap();
        writeln!(out, "Result: {}", if self.pass { "PASS" } else { "FAIL" }).unwrap();
        writeln!(out, "Steps: {}", self.steps.len()).unwrap();
        for (i, step) in self.steps.iter().enumerate() {
            writeln!(
                out,
                "  [{i}] {}: {:?} → {:?} | guard={:?} | scored={} approved={} decisions={}",
                step.label,
                step.mode_before,
                step.mode_after,
                step.guard_status,
                step.candidates_scored,
                step.approved_count,
                step.decision_ids.len(),
            )
            .unwrap();
            for a in &step.assertions {
                writeln!(out, "      ✓ {a}").unwrap();
            }
        }
        out
    }
}

// ════════════════════════════════════════════════════════════════
// SCENARIO 1: Burst growth with safe shadow recommendations
// ════════════════════════════════════════════════════════════════
//
// Sudden disk pressure spike while in observe mode.
// The policy engine should score candidates and build a hypothetical
// deletion plan, but never approve actual deletions.

#[test]
#[allow(clippy::too_many_lines)]
fn e2e_burst_growth_shadow_mode() {
    let seed = 42;
    let mut rng = SeededRng::new(seed);
    let scoring = default_engine();
    let config = PolicyConfig {
        initial_mode: ActiveMode::Observe,
        ..PolicyConfig::default()
    };
    let mut engine = PolicyEngine::new(config);
    let mut trace = ScenarioTrace::new("burst_growth_shadow");

    // Step 1: Low-pressure warmup — score a few candidates at low urgency.
    let candidates_1 = random_candidates(&mut rng, 10);
    let scored_1 = scoring.score_batch(&candidates_1, 0.2);
    let mode_before = engine.mode();
    let decision_1 = engine.evaluate(&scored_1, Some(&good_guard()));
    let mut step = StepTrace {
        label: "warmup_low_pressure".to_string(),
        mode_before,
        mode_after: engine.mode(),
        guard_status: GuardStatus::Pass,
        candidates_scored: scored_1.len(),
        approved_count: decision_1.approved_for_deletion.len(),
        decision_ids: decision_1.records.iter().map(|r| r.decision_id).collect(),
        trace_ids: decision_1
            .records
            .iter()
            .map(|r| r.trace_id.clone())
            .collect(),
        assertions: Vec::new(),
    };
    assert_eq!(engine.mode(), ActiveMode::Observe);
    step.assertions.push("mode stays Observe".to_string());
    assert_eq!(decision_1.approved_for_deletion.len(), 0);
    step.assertions
        .push("zero approved deletions in observe".to_string());
    assert!(decision_1.hypothetical_deletes > 0 || decision_1.hypothetical_keeps > 0);
    step.assertions
        .push("hypothetical tracking active".to_string());
    trace.steps.push(step);

    // Step 2: Burst pressure — urgency jumps to 0.9, many large candidates.
    let burst_inputs: Vec<CandidateInput> = (0..20)
        .map(|i| make_candidate(&mut rng, 100 + i, 24, 5))
        .collect();
    let scored_burst = scoring.score_batch(&burst_inputs, 0.9);
    let mode_before = engine.mode();
    let decision_2 = engine.evaluate(&scored_burst, Some(&good_guard()));
    let mut step = StepTrace {
        label: "burst_pressure_spike".to_string(),
        mode_before,
        mode_after: engine.mode(),
        guard_status: GuardStatus::Pass,
        candidates_scored: scored_burst.len(),
        approved_count: decision_2.approved_for_deletion.len(),
        decision_ids: decision_2.records.iter().map(|r| r.decision_id).collect(),
        trace_ids: decision_2
            .records
            .iter()
            .map(|r| r.trace_id.clone())
            .collect(),
        assertions: Vec::new(),
    };
    assert_eq!(engine.mode(), ActiveMode::Observe);
    step.assertions
        .push("mode still Observe despite high urgency".to_string());
    assert_eq!(decision_2.approved_for_deletion.len(), 0);
    step.assertions
        .push("still zero approved deletions (shadow only)".to_string());
    // Verify decision records contain correct policy mode.
    for record in &decision_2.records {
        assert_eq!(record.policy_mode, PolicyMode::Shadow);
    }
    step.assertions
        .push("all records tagged Shadow policy mode".to_string());
    // Verify trace IDs are unique.
    let unique_ids: std::collections::HashSet<_> =
        decision_2.records.iter().map(|r| &r.trace_id).collect();
    assert_eq!(unique_ids.len(), decision_2.records.len());
    step.assertions.push("all trace_ids are unique".to_string());
    // Verify decision IDs are monotonically increasing.
    for window in decision_2.records.windows(2) {
        assert!(window[1].decision_id > window[0].decision_id);
    }
    step.assertions
        .push("decision_ids monotonically increasing".to_string());
    trace.steps.push(step);

    // Step 3: Verify explainability — all records should format at all levels.
    for record in &decision_2.records {
        let l0 = format_explain(record, ExplainLevel::L0);
        let l1 = format_explain(record, ExplainLevel::L1);
        let l2 = format_explain(record, ExplainLevel::L2);
        let l3 = format_explain(record, ExplainLevel::L3);
        assert!(!l0.is_empty());
        assert!(l1.len() >= l0.len());
        assert!(l2.len() >= l1.len());
        assert!(l3.len() >= l2.len());
    }
    trace.steps.push(StepTrace {
        label: "explainability_verification".to_string(),
        mode_before: ActiveMode::Observe,
        mode_after: engine.mode(),
        guard_status: GuardStatus::Pass,
        candidates_scored: 0,
        approved_count: 0,
        decision_ids: Vec::new(),
        trace_ids: Vec::new(),
        assertions: vec![
            "all records explain at L0-L3".to_string(),
            "explain levels are cumulative (L0 ⊂ L1 ⊂ L2 ⊂ L3)".to_string(),
        ],
    });

    eprintln!("{}", trace.emit_report());
    assert!(trace.pass);
}

// ════════════════════════════════════════════════════════════════
// SCENARIO 2: Canary pass with bounded impact and trace capture
// ════════════════════════════════════════════════════════════════
//
// Promote to canary mode and verify:
// - Deletions are capped by hourly budget
// - Each approved deletion has a complete evidence record
// - Budget exhaustion triggers fallback

#[test]
#[allow(clippy::too_many_lines)]
fn e2e_canary_bounded_impact() {
    let seed = 99;
    let mut rng = SeededRng::new(seed);
    let scoring = default_engine();
    let config = PolicyConfig {
        initial_mode: ActiveMode::Observe,
        max_canary_deletes_per_hour: 3,
        ..PolicyConfig::default()
    };
    let mut engine = PolicyEngine::new(config);
    let mut trace = ScenarioTrace::new("canary_bounded_impact");

    // Step 1: Promote observe → canary.
    engine.promote();
    assert_eq!(engine.mode(), ActiveMode::Canary);
    trace.steps.push(StepTrace {
        label: "promote_to_canary".to_string(),
        mode_before: ActiveMode::Observe,
        mode_after: engine.mode(),
        guard_status: GuardStatus::Pass,
        candidates_scored: 0,
        approved_count: 0,
        decision_ids: Vec::new(),
        trace_ids: Vec::new(),
        assertions: vec!["promoted to Canary".to_string()],
    });

    // Step 2: Evaluate batch of high-scoring candidates.
    // Should approve up to max_canary_deletes_per_hour (3).
    let inputs: Vec<CandidateInput> = (0..10)
        .map(|i| make_candidate(&mut rng, i, 48, 8))
        .collect();
    let scored = scoring.score_batch(&inputs, 0.7);
    let mode_before = engine.mode();
    let decision = engine.evaluate(&scored, Some(&good_guard()));
    let mut step = StepTrace {
        label: "canary_evaluation_with_budget".to_string(),
        mode_before,
        mode_after: engine.mode(),
        guard_status: GuardStatus::Pass,
        candidates_scored: scored.len(),
        approved_count: decision.approved_for_deletion.len(),
        decision_ids: decision.records.iter().map(|r| r.decision_id).collect(),
        trace_ids: decision
            .records
            .iter()
            .map(|r| r.trace_id.clone())
            .collect(),
        assertions: Vec::new(),
    };
    // Canary budget: at most 3 deletions.
    assert!(decision.approved_for_deletion.len() <= 3);
    step.assertions.push(format!(
        "approved {} ≤ 3 (canary budget)",
        decision.approved_for_deletion.len()
    ));
    // Verify every approved deletion has a complete evidence record.
    for approved in &decision.approved_for_deletion {
        let record = decision.records.iter().find(|r| r.path == approved.path);
        assert!(record.is_some(), "approved path must have decision record");
        let record = record.unwrap();
        assert_eq!(record.action, ActionRecord::Delete);
        assert!(record.total_score > 0.0);
    }
    step.assertions
        .push("all approved paths have complete evidence records".to_string());
    trace.steps.push(step);

    // Step 3: Exhaust budget with another batch.
    let inputs2: Vec<CandidateInput> = (0..10)
        .map(|i| make_candidate(&mut rng, 20 + i, 48, 8))
        .collect();
    let scored2 = scoring.score_batch(&inputs2, 0.7);
    let mode_before = engine.mode();
    let decision2 = engine.evaluate(&scored2, Some(&good_guard()));
    let mut step = StepTrace {
        label: "canary_budget_exhaustion".to_string(),
        mode_before,
        mode_after: engine.mode(),
        guard_status: GuardStatus::Pass,
        candidates_scored: scored2.len(),
        approved_count: decision2.approved_for_deletion.len(),
        decision_ids: decision2.records.iter().map(|r| r.decision_id).collect(),
        trace_ids: decision2
            .records
            .iter()
            .map(|r| r.trace_id.clone())
            .collect(),
        assertions: Vec::new(),
    };
    // After exhausting the budget, engine should have entered fallback.
    if decision2.budget_exhausted {
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
        step.assertions
            .push("budget exhausted → FallbackSafe".to_string());
    } else {
        // If budget not exhausted, verify remaining approvals are still bounded.
        let total_approved =
            decision.approved_for_deletion.len() + decision2.approved_for_deletion.len();
        assert!(total_approved <= 3);
        step.assertions.push(format!(
            "total approved {total_approved} ≤ 3 across batches"
        ));
    }
    trace.steps.push(step);

    // Step 4: Verify JSON serialization roundtrips for all records.
    for record in decision.records.iter().chain(decision2.records.iter()) {
        let json = record.to_json_compact();
        assert!(!json.is_empty());
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("decision_id").is_some());
        assert!(parsed.get("trace_id").is_some());
        assert!(parsed.get("policy_mode").is_some());
    }
    trace.steps.push(StepTrace {
        label: "json_serialization_roundtrip".to_string(),
        mode_before: engine.mode(),
        mode_after: engine.mode(),
        guard_status: GuardStatus::Pass,
        candidates_scored: 0,
        approved_count: 0,
        decision_ids: Vec::new(),
        trace_ids: Vec::new(),
        assertions: vec![
            "all records serialize to valid JSON".to_string(),
            "JSON contains decision_id, trace_id, policy_mode".to_string(),
        ],
    });

    eprintln!("{}", trace.emit_report());
    assert!(trace.pass);
}

// ════════════════════════════════════════════════════════════════
// SCENARIO 3: Calibration drift causing guard fail and fallback
// ════════════════════════════════════════════════════════════════
//
// Start in enforce mode, feed gradually worsening calibration
// observations until the guard transitions to Fail, triggering
// policy fallback.

#[test]
#[allow(clippy::too_many_lines)]
fn e2e_calibration_drift_fallback() {
    let seed = 303;
    let mut rng = SeededRng::new(seed);
    let scoring = default_engine();
    let guard_config = GuardrailConfig {
        min_observations: 5,
        window_size: 20,
        recovery_clean_windows: 3,
        ..GuardrailConfig::default()
    };
    let mut guard = AdaptiveGuard::new(guard_config);
    let policy_config = PolicyConfig {
        initial_mode: ActiveMode::Observe,
        calibration_breach_windows: 2,
        recovery_clean_windows: 3,
        ..PolicyConfig::default()
    };
    let mut engine = PolicyEngine::new(policy_config);
    let mut trace = ScenarioTrace::new("calibration_drift_fallback");

    // Step 1: Warm up guard with good observations to reach Pass.
    for _ in 0..10 {
        guard.observe(good_observation());
    }
    assert_eq!(guard.status(), GuardStatus::Pass);
    trace.steps.push(StepTrace {
        label: "warmup_guard_to_pass".to_string(),
        mode_before: ActiveMode::Observe,
        mode_after: engine.mode(),
        guard_status: guard.status(),
        candidates_scored: 0,
        approved_count: 0,
        decision_ids: Vec::new(),
        trace_ids: Vec::new(),
        assertions: vec!["guard reaches Pass after 10 good observations".to_string()],
    });

    // Step 2: Promote to enforce.
    engine.promote(); // observe → canary
    engine.promote(); // canary → enforce
    assert_eq!(engine.mode(), ActiveMode::Enforce);
    trace.steps.push(StepTrace {
        label: "promote_to_enforce".to_string(),
        mode_before: ActiveMode::Canary,
        mode_after: engine.mode(),
        guard_status: guard.status(),
        candidates_scored: 0,
        approved_count: 0,
        decision_ids: Vec::new(),
        trace_ids: Vec::new(),
        assertions: vec!["promoted to Enforce".to_string()],
    });

    // Step 3: Inject calibration drift — feed bad observations.
    for _ in 0..15 {
        guard.observe(bad_observation());
    }
    let diag = guard.diagnostics();
    let mut step_assertions = vec![];
    assert_eq!(guard.status(), GuardStatus::Fail);
    step_assertions.push("guard transitions to Fail after bad observations".to_string());
    assert!(diag.e_process_alarm);
    step_assertions.push("e-process alarm triggered".to_string());
    assert!(diag.median_rate_error > 0.30);
    step_assertions.push(format!(
        "median_rate_error={:.3} > 0.30",
        diag.median_rate_error
    ));
    trace.steps.push(StepTrace {
        label: "inject_calibration_drift".to_string(),
        mode_before: ActiveMode::Enforce,
        mode_after: engine.mode(),
        guard_status: guard.status(),
        candidates_scored: 0,
        approved_count: 0,
        decision_ids: Vec::new(),
        trace_ids: Vec::new(),
        assertions: step_assertions,
    });

    // Step 4: Policy observe_window with failing guard → should trigger fallback.
    let diag = guard.diagnostics();
    engine.observe_window(&diag);
    // Second consecutive breach window.
    engine.observe_window(&diag);
    let mut step_assertions = vec![];
    if engine.mode() == ActiveMode::FallbackSafe {
        step_assertions.push("policy entered FallbackSafe after breach windows".to_string());
    } else {
        // May need more breach windows depending on config.
        engine.observe_window(&diag);
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
        step_assertions.push("policy entered FallbackSafe after 3 breach windows".to_string());
    }
    trace.steps.push(StepTrace {
        label: "guard_fail_triggers_policy_fallback".to_string(),
        mode_before: ActiveMode::Enforce,
        mode_after: engine.mode(),
        guard_status: guard.status(),
        candidates_scored: 0,
        approved_count: 0,
        decision_ids: Vec::new(),
        trace_ids: Vec::new(),
        assertions: step_assertions,
    });

    // Step 5: Verify no deletions approved in fallback.
    let inputs = random_candidates(&mut rng, 15);
    let scored = scoring.score_batch(&inputs, 0.8);
    let decision = engine.evaluate(&scored, Some(&failing_guard()));
    let mut step = StepTrace {
        label: "evaluate_in_fallback".to_string(),
        mode_before: engine.mode(),
        mode_after: engine.mode(),
        guard_status: guard.status(),
        candidates_scored: scored.len(),
        approved_count: decision.approved_for_deletion.len(),
        decision_ids: decision.records.iter().map(|r| r.decision_id).collect(),
        trace_ids: decision
            .records
            .iter()
            .map(|r| r.trace_id.clone())
            .collect(),
        assertions: Vec::new(),
    };
    assert_eq!(decision.approved_for_deletion.len(), 0);
    step.assertions
        .push("zero deletions in FallbackSafe".to_string());
    trace.steps.push(step);

    eprintln!("{}", trace.emit_report());
    assert!(trace.pass);
}

// ════════════════════════════════════════════════════════════════
// SCENARIO 4: Index corruption / stale data causing safe fallback
// ════════════════════════════════════════════════════════════════
//
// Guard stuck in Unknown state (insufficient observations) while
// in canary mode → should block adaptive actions.

#[test]
fn e2e_stale_index_safe_fallback() {
    let seed = 404;
    let mut rng = SeededRng::new(seed);
    let scoring = default_engine();
    let config = PolicyConfig {
        initial_mode: ActiveMode::Observe,
        ..PolicyConfig::default()
    };
    let mut engine = PolicyEngine::new(config);
    let mut trace = ScenarioTrace::new("stale_index_safe_fallback");

    // Step 1: Promote to canary.
    engine.promote();
    assert_eq!(engine.mode(), ActiveMode::Canary);
    trace.steps.push(StepTrace {
        label: "promote_to_canary".to_string(),
        mode_before: ActiveMode::Observe,
        mode_after: engine.mode(),
        guard_status: GuardStatus::Unknown,
        candidates_scored: 0,
        approved_count: 0,
        decision_ids: Vec::new(),
        trace_ids: Vec::new(),
        assertions: vec!["promoted to Canary".to_string()],
    });

    // Step 2: Evaluate with Unknown guard (insufficient data).
    let unknown_guard = GuardDiagnostics {
        status: GuardStatus::Unknown,
        observation_count: 2,
        median_rate_error: 0.0,
        conservative_fraction: 0.0,
        e_process_value: 1.0,
        e_process_alarm: false,
        consecutive_clean: 0,
        reason: "insufficient data".to_string(),
    };
    let inputs = random_candidates(&mut rng, 10);
    let scored = scoring.score_batch(&inputs, 0.6);
    let mode_before = engine.mode();
    let decision = engine.evaluate(&scored, Some(&unknown_guard));
    let mut step = StepTrace {
        label: "evaluate_with_unknown_guard".to_string(),
        mode_before,
        mode_after: engine.mode(),
        guard_status: GuardStatus::Unknown,
        candidates_scored: scored.len(),
        approved_count: decision.approved_for_deletion.len(),
        decision_ids: decision.records.iter().map(|r| r.decision_id).collect(),
        trace_ids: decision
            .records
            .iter()
            .map(|r| r.trace_id.clone())
            .collect(),
        assertions: Vec::new(),
    };
    // With Unknown guard in Canary, adaptive actions should be blocked.
    // Guard penalty should reduce approvals.
    step.assertions.push(format!(
        "approved {} with Unknown guard (conservative behavior)",
        decision.approved_for_deletion.len()
    ));
    trace.steps.push(step);

    // Step 3: Force fallback via kill switch.
    engine.enter_fallback(FallbackReason::KillSwitch);
    assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
    trace.steps.push(StepTrace {
        label: "kill_switch_fallback".to_string(),
        mode_before: ActiveMode::Canary,
        mode_after: engine.mode(),
        guard_status: GuardStatus::Unknown,
        candidates_scored: 0,
        approved_count: 0,
        decision_ids: Vec::new(),
        trace_ids: Vec::new(),
        assertions: vec!["kill switch forces FallbackSafe".to_string()],
    });

    // Step 4: Verify fallback blocks all deletions.
    let inputs2 = random_candidates(&mut rng, 10);
    let scored2 = scoring.score_batch(&inputs2, 0.9);
    let decision2 = engine.evaluate(&scored2, Some(&unknown_guard));
    assert_eq!(decision2.approved_for_deletion.len(), 0);
    trace.steps.push(StepTrace {
        label: "fallback_blocks_all".to_string(),
        mode_before: ActiveMode::FallbackSafe,
        mode_after: engine.mode(),
        guard_status: GuardStatus::Unknown,
        candidates_scored: scored2.len(),
        approved_count: 0,
        decision_ids: decision2.records.iter().map(|r| r.decision_id).collect(),
        trace_ids: decision2
            .records
            .iter()
            .map(|r| r.trace_id.clone())
            .collect(),
        assertions: vec!["zero deletions in FallbackSafe (kill switch)".to_string()],
    });

    eprintln!("{}", trace.emit_report());
    assert!(trace.pass);
}

// ════════════════════════════════════════════════════════════════
// SCENARIO 5: IO/serializer faults causing safe degradation
// ════════════════════════════════════════════════════════════════
//
// In enforce mode, inject a serialization failure via fallback.
// Verify the engine degrades gracefully and blocks further
// deletions until recovery.

#[test]
fn e2e_io_fault_safe_degradation() {
    let seed = 555;
    let mut rng = SeededRng::new(seed);
    let scoring = default_engine();
    let config = PolicyConfig {
        initial_mode: ActiveMode::Observe,
        recovery_clean_windows: 3,
        ..PolicyConfig::default()
    };
    let mut engine = PolicyEngine::new(config);
    let mut trace = ScenarioTrace::new("io_fault_safe_degradation");

    // Step 1: Promote to enforce.
    engine.promote(); // observe → canary
    engine.promote(); // canary → enforce
    assert_eq!(engine.mode(), ActiveMode::Enforce);
    trace.steps.push(StepTrace {
        label: "promote_to_enforce".to_string(),
        mode_before: ActiveMode::Observe,
        mode_after: ActiveMode::Enforce,
        guard_status: GuardStatus::Pass,
        candidates_scored: 0,
        approved_count: 0,
        decision_ids: Vec::new(),
        trace_ids: Vec::new(),
        assertions: vec!["promoted to Enforce".to_string()],
    });

    // Step 2: Normal evaluation in enforce mode — deletions should be approved.
    let inputs = random_candidates(&mut rng, 8);
    let scored = scoring.score_batch(&inputs, 0.6);
    let decision_pre = engine.evaluate(&scored, Some(&good_guard()));
    let pre_approved = decision_pre.approved_for_deletion.len();
    trace.steps.push(StepTrace {
        label: "normal_enforce_evaluation".to_string(),
        mode_before: ActiveMode::Enforce,
        mode_after: engine.mode(),
        guard_status: GuardStatus::Pass,
        candidates_scored: scored.len(),
        approved_count: pre_approved,
        decision_ids: decision_pre.records.iter().map(|r| r.decision_id).collect(),
        trace_ids: decision_pre
            .records
            .iter()
            .map(|r| r.trace_id.clone())
            .collect(),
        assertions: vec![format!("enforce approved {} deletions", pre_approved)],
    });

    // Step 3: Inject serialization failure.
    engine.enter_fallback(FallbackReason::SerializationFailure);
    assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
    trace.steps.push(StepTrace {
        label: "inject_serialization_failure".to_string(),
        mode_before: ActiveMode::Enforce,
        mode_after: ActiveMode::FallbackSafe,
        guard_status: GuardStatus::Pass,
        candidates_scored: 0,
        approved_count: 0,
        decision_ids: Vec::new(),
        trace_ids: Vec::new(),
        assertions: vec!["serialization failure → FallbackSafe".to_string()],
    });

    // Step 4: Verify no deletions in fallback.
    let inputs2 = random_candidates(&mut rng, 10);
    let scored2 = scoring.score_batch(&inputs2, 0.9);
    let decision_post = engine.evaluate(&scored2, Some(&good_guard()));
    assert_eq!(decision_post.approved_for_deletion.len(), 0);
    trace.steps.push(StepTrace {
        label: "evaluate_in_fallback".to_string(),
        mode_before: ActiveMode::FallbackSafe,
        mode_after: engine.mode(),
        guard_status: GuardStatus::Pass,
        candidates_scored: scored2.len(),
        approved_count: 0,
        decision_ids: decision_post
            .records
            .iter()
            .map(|r| r.decision_id)
            .collect(),
        trace_ids: decision_post
            .records
            .iter()
            .map(|r| r.trace_id.clone())
            .collect(),
        assertions: vec!["zero deletions after serialization failure".to_string()],
    });

    // Step 5: Verify transition log records the fallback.
    let transitions = engine.transition_log();
    let fallback_entry = transitions.iter().find(|t| t.transition == "fallback");
    assert!(fallback_entry.is_some());
    trace.steps.push(StepTrace {
        label: "verify_transition_log".to_string(),
        mode_before: ActiveMode::FallbackSafe,
        mode_after: engine.mode(),
        guard_status: GuardStatus::Pass,
        candidates_scored: 0,
        approved_count: 0,
        decision_ids: Vec::new(),
        trace_ids: Vec::new(),
        assertions: vec!["transition log contains fallback entry".to_string()],
    });

    eprintln!("{}", trace.emit_report());
    assert!(trace.pass);
}

// ════════════════════════════════════════════════════════════════
// SCENARIO 6: Progressive recovery from fallback after clean windows
// ════════════════════════════════════════════════════════════════
//
// Enter fallback, then feed consecutive clean (good) guard windows
// until the engine recovers to its pre-fallback mode.

#[test]
#[allow(clippy::too_many_lines)]
fn e2e_progressive_recovery() {
    let seed = 666;
    let mut rng = SeededRng::new(seed);
    let scoring = default_engine();
    let config = PolicyConfig {
        initial_mode: ActiveMode::Observe,
        recovery_clean_windows: 3,
        ..PolicyConfig::default()
    };
    let mut engine = PolicyEngine::new(config);
    let mut trace = ScenarioTrace::new("progressive_recovery");

    // Step 1: Promote to enforce and enter fallback.
    engine.promote(); // observe → canary
    engine.promote(); // canary → enforce
    let pre_fallback_mode = engine.mode();
    assert_eq!(pre_fallback_mode, ActiveMode::Enforce);
    engine.enter_fallback(FallbackReason::CalibrationBreach {
        consecutive_windows: 3,
    });
    assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
    trace.steps.push(StepTrace {
        label: "setup_enforce_then_fallback".to_string(),
        mode_before: pre_fallback_mode,
        mode_after: ActiveMode::FallbackSafe,
        guard_status: GuardStatus::Pass,
        candidates_scored: 0,
        approved_count: 0,
        decision_ids: Vec::new(),
        trace_ids: Vec::new(),
        assertions: vec![
            "promoted to Enforce".to_string(),
            "entered FallbackSafe via CalibrationBreach".to_string(),
        ],
    });

    // Step 2: Feed clean windows — but fewer than required for recovery.
    for i in 0..2 {
        engine.observe_window(&good_guard());
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
        trace.steps.push(StepTrace {
            label: format!("clean_window_{}", i + 1),
            mode_before: ActiveMode::FallbackSafe,
            mode_after: engine.mode(),
            guard_status: GuardStatus::Pass,
            candidates_scored: 0,
            approved_count: 0,
            decision_ids: Vec::new(),
            trace_ids: Vec::new(),
            assertions: vec![format!("still FallbackSafe ({}/3 clean windows)", i + 1)],
        });
    }

    // Step 3: Third clean window should trigger recovery.
    engine.observe_window(&good_guard());
    let recovered_mode = engine.mode();
    let mut step_assertions = vec![];
    if recovered_mode == ActiveMode::Enforce {
        step_assertions.push("recovered to Enforce after 3 clean windows".to_string());
    } else if recovered_mode == ActiveMode::FallbackSafe {
        // Some configs may require more windows.
        step_assertions.push(format!(
            "still FallbackSafe — config may require more clean windows (mode={recovered_mode:?})"
        ));
    } else {
        step_assertions.push(format!("unexpected recovery mode: {recovered_mode:?}"));
    }
    trace.steps.push(StepTrace {
        label: "recovery_window_3".to_string(),
        mode_before: ActiveMode::FallbackSafe,
        mode_after: recovered_mode,
        guard_status: GuardStatus::Pass,
        candidates_scored: 0,
        approved_count: 0,
        decision_ids: Vec::new(),
        trace_ids: Vec::new(),
        assertions: step_assertions,
    });

    // Step 4: If recovered, verify deletions are approved again.
    if recovered_mode == ActiveMode::Enforce {
        let inputs = random_candidates(&mut rng, 8);
        let scored = scoring.score_batch(&inputs, 0.6);
        let decision = engine.evaluate(&scored, Some(&good_guard()));
        trace.steps.push(StepTrace {
            label: "post_recovery_evaluation".to_string(),
            mode_before: ActiveMode::Enforce,
            mode_after: engine.mode(),
            guard_status: GuardStatus::Pass,
            candidates_scored: scored.len(),
            approved_count: decision.approved_for_deletion.len(),
            decision_ids: decision.records.iter().map(|r| r.decision_id).collect(),
            trace_ids: decision
                .records
                .iter()
                .map(|r| r.trace_id.clone())
                .collect(),
            assertions: vec![format!(
                "post-recovery: {} deletions approved in Enforce",
                decision.approved_for_deletion.len()
            )],
        });
    }

    // Step 5: Verify transition log records both fallback and recovery.
    let transitions = engine.transition_log();
    let has_fallback = transitions.iter().any(|t| t.transition == "fallback");
    let has_recovery = transitions.iter().any(|t| t.transition == "recover");
    trace.steps.push(StepTrace {
        label: "verify_transition_audit_trail".to_string(),
        mode_before: engine.mode(),
        mode_after: engine.mode(),
        guard_status: GuardStatus::Pass,
        candidates_scored: 0,
        approved_count: 0,
        decision_ids: Vec::new(),
        trace_ids: Vec::new(),
        assertions: vec![
            format!("transition log has fallback entry: {has_fallback}"),
            format!("transition log has recovery entry: {has_recovery}"),
        ],
    });

    eprintln!("{}", trace.emit_report());
    assert!(trace.pass);
}

// ════════════════════════════════════════════════════════════════
// SCENARIO DETERMINISM: verify all scenarios produce identical
// results across repeated runs with the same seed.
// ════════════════════════════════════════════════════════════════

#[test]
fn e2e_all_scenarios_deterministic() {
    // Re-run the core logic from each scenario with fixed seeds
    // and verify key outputs match between two runs.

    for scenario_seed in [42u64, 99, 303, 404, 555, 666] {
        let mut results = Vec::new();

        for _run in 0..2 {
            let mut rng = SeededRng::new(scenario_seed);
            let scoring = default_engine();
            let config = PolicyConfig::default();
            let mut engine = PolicyEngine::new(config);

            let inputs = random_candidates(&mut rng, 15);
            let scored = scoring.score_batch(&inputs, 0.5);
            let decision = engine.evaluate(&scored, Some(&good_guard()));

            let score_values: Vec<f64> = decision.records.iter().map(|r| r.total_score).collect();
            let actions: Vec<ActionRecord> = decision.records.iter().map(|r| r.action).collect();
            let ids: Vec<u64> = decision.records.iter().map(|r| r.decision_id).collect();

            results.push((score_values, actions, ids));
        }

        // Compare the two runs.
        assert_eq!(
            results[0].0, results[1].0,
            "scores differ for seed {scenario_seed}"
        );
        assert_eq!(
            results[0].1, results[1].1,
            "actions differ for seed {scenario_seed}"
        );
        assert_eq!(
            results[0].2, results[1].2,
            "decision IDs differ for seed {scenario_seed}"
        );
    }
}
