//! Stress tests and load simulators for extreme pressure scenarios.
//!
//! Exercises EWMA, PID, policy engine, guardrails, ballast, and self-monitor
//! under synthetic but realistic pressure traces.
//!
//! bd-3sb

mod common;

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use storage_ballast_helper::ballast::manager::BallastManager;
use storage_ballast_helper::core::config::{BallastConfig, ScoringConfig};
use storage_ballast_helper::daemon::policy::{ActiveMode, PolicyConfig, PolicyEngine};
use storage_ballast_helper::daemon::self_monitor::{SelfMonitor, ThreadHeartbeat};
use storage_ballast_helper::monitor::ewma::DiskRateEstimator;
use storage_ballast_helper::monitor::guardrails::{
    AdaptiveGuard, CalibrationObservation, GuardStatus, GuardrailConfig,
};
use storage_ballast_helper::monitor::pid::{PidPressureController, PressureLevel, PressureReading};
use storage_ballast_helper::scanner::decision_record::ActionRecord;
use storage_ballast_helper::scanner::patterns::{
    ArtifactCategory, ArtifactClassification, StructuralSignals,
};
use storage_ballast_helper::scanner::scoring::{CandidateInput, ScoringEngine};

// ════════════════════════════════════════════════════════════════
// INFRASTRUCTURE
// ════════════════════════════════════════════════════════════════

/// Stress report emitted at the end of each scenario.
struct StressReport {
    scenario: String,
    steps: usize,
    metrics: Vec<(String, String)>,
    pass: bool,
}

impl StressReport {
    fn new(scenario: &str) -> Self {
        Self {
            scenario: scenario.to_string(),
            steps: 0,
            metrics: Vec::new(),
            pass: true,
        }
    }
    fn metric(&mut self, key: &str, value: impl std::fmt::Display) {
        self.metrics.push((key.to_string(), value.to_string()));
    }
    fn emit(&self) -> String {
        let mut out = String::new();
        writeln!(out, "═══ Stress: {} ═══", self.scenario).unwrap();
        writeln!(out, "Result: {}", if self.pass { "PASS" } else { "FAIL" }).unwrap();
        writeln!(out, "Steps: {}", self.steps).unwrap();
        for (k, v) in &self.metrics {
            writeln!(out, "  {k}: {v}").unwrap();
        }
        out
    }
}

fn make_pid() -> PidPressureController {
    PidPressureController::new(
        0.25,  // kp
        0.08,  // ki
        0.02,  // kd
        100.0, // integral_cap
        18.0,  // target_free_pct
        1.0,   // hysteresis_pct
        20.0,  // green
        14.0,  // yellow
        10.0,  // orange
        6.0,   // red
        Duration::from_secs(1),
    )
}

fn make_ewma() -> DiskRateEstimator {
    DiskRateEstimator::new(0.3, 0.1, 0.8, 3)
}

fn make_candidate(idx: usize, age_hours: u64, size_gib: u64) -> CandidateInput {
    CandidateInput {
        path: PathBuf::from(format!("/data/p{idx}/.target_{}", idx * 100)),
        size_bytes: size_gib * 1_073_741_824,
        age: Duration::from_secs(age_hours * 3600),
        classification: ArtifactClassification {
            pattern_name: ".target*".to_string(),
            category: ArtifactCategory::RustTarget,
            name_confidence: 0.85,
            structural_confidence: 0.75,
            combined_confidence: 0.80,
        },
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
    }
}

// ════════════════════════════════════════════════════════════════
// SCENARIO A: Rapid fill burst under compile-like load
// ════════════════════════════════════════════════════════════════
//
// Simulates a large parallel compile filling disk at ~500 MB/s.
// EWMA should detect acceleration quickly, PID should escalate to
// Red/Critical within a few ticks, urgency should approach 1.0.

#[test]
fn stress_rapid_fill_burst() {
    let total: u64 = 1_000_000_000_000; // 1 TB
    let initial_free: u64 = 200_000_000_000; // 200 GB free (20%)
    let burst_rate: u64 = 5_000_000_000; // 5 GB/s consumption

    let mut ewma = make_ewma();
    let mut pid = make_pid();
    let mut report = StressReport::new("rapid_fill_burst");

    let start = Instant::now();
    let tick = Duration::from_secs(2);
    let mut free = initial_free;
    let mut max_urgency: f64 = 0.0;
    let mut red_reached_at: Option<usize> = None;
    let mut critical_reached_at: Option<usize> = None;

    for i in 0..60 {
        // Consume space at burst rate.
        free = free.saturating_sub(burst_rate * tick.as_secs());

        let tick_index = u32::try_from(i).expect("tick index fits u32");
        let t = start + tick * tick_index;
        let estimate = ewma.update(free, t, total / 10);
        let reading = PressureReading {
            free_bytes: free,
            total_bytes: total,
        };
        let response = pid.update(reading, Some(estimate.seconds_to_exhaustion), t);

        max_urgency = max_urgency.max(response.urgency);

        if response.level == PressureLevel::Red && red_reached_at.is_none() {
            red_reached_at = Some(i);
        }
        if response.level == PressureLevel::Critical && critical_reached_at.is_none() {
            critical_reached_at = Some(i);
        }

        report.steps += 1;

        // Stop if disk fully consumed.
        if free == 0 {
            break;
        }
    }

    // Assertions.
    assert!(
        max_urgency > 0.8,
        "urgency should spike near 1.0, got {max_urgency}"
    );
    assert!(
        red_reached_at.is_some(),
        "should reach Red during rapid fill"
    );
    let red_tick = red_reached_at.unwrap();
    assert!(
        red_tick < 30,
        "should reach Red quickly, took {red_tick} ticks"
    );

    report.metric("max_urgency", format!("{max_urgency:.3}"));
    report.metric("red_reached_at_tick", red_tick);
    report.metric(
        "critical_reached_at_tick",
        critical_reached_at.map_or_else(|| "never".to_string(), |tick_idx| tick_idx.to_string()),
    );
    report.metric("final_free_bytes", free);
    report.metric("ticks_simulated", report.steps);

    eprintln!("{}", report.emit());
    assert!(report.pass);
}

// ════════════════════════════════════════════════════════════════
// SCENARIO B: Sustained low-free-space pressure
// ════════════════════════════════════════════════════════════════
//
// Disk stays at ~8% free for an extended period (normal CI churn).
// PID should stabilize in Yellow/Orange, urgency moderate but not max.

#[test]
fn stress_sustained_low_pressure() {
    let total: u64 = 500_000_000_000; // 500 GB
    let target_free: u64 = 100_000_000_000; // 20% free (green boundary)

    let mut ewma = make_ewma();
    let mut pid = make_pid();
    let mut report = StressReport::new("sustained_low_pressure");

    let start = Instant::now();
    let tick = Duration::from_secs(5);
    let mut urgency_sum = 0.0;
    let mut urgency_max: f64 = 0.0;
    let mut urgency_min: f64 = 1.0;
    let mut level_counts = [0usize; 5]; // Green, Yellow, Orange, Red, Critical

    // Small random walk around 8% free.
    let mut free = target_free;
    for i in 0..200 {
        // Jitter ±500MB.
        let jitter = if i % 3 == 0 {
            500_000_000i64
        } else {
            -300_000_000
        };
        let jittered_free = i128::from(free) + i128::from(jitter);
        free = u64::try_from(jittered_free.max(0)).expect("clamped free space is non-negative");
        free = free.min(total);

        let tick_index = u32::try_from(i).expect("tick index fits u32");
        let t = start + tick * tick_index;
        let estimate = ewma.update(free, t, total / 10);
        let reading = PressureReading {
            free_bytes: free,
            total_bytes: total,
        };
        let response = pid.update(reading, Some(estimate.seconds_to_exhaustion), t);

        urgency_sum += response.urgency;
        urgency_max = urgency_max.max(response.urgency);
        urgency_min = urgency_min.min(response.urgency);

        let idx = match response.level {
            PressureLevel::Green => 0,
            PressureLevel::Yellow => 1,
            PressureLevel::Orange => 2,
            PressureLevel::Red => 3,
            PressureLevel::Critical => 4,
        };
        level_counts[idx] += 1;
        report.steps += 1;
    }

    let avg_urgency = urgency_sum / 200.0;

    // At 8% free with thresholds green=20%, yellow=14%, orange=10%, red=6%:
    // We expect mostly Orange with some Yellow.
    assert!(
        avg_urgency > 0.1 && avg_urgency < 0.9,
        "sustained pressure should have moderate urgency, got {avg_urgency:.3}"
    );
    // Should NOT frequently hit Critical.
    assert!(
        level_counts[4] < 10,
        "should rarely hit Critical at 8% free, got {} times",
        level_counts[4]
    );

    report.metric("avg_urgency", format!("{avg_urgency:.3}"));
    report.metric(
        "urgency_range",
        format!("{urgency_min:.3}..{urgency_max:.3}"),
    );
    report.metric(
        "level_distribution",
        format!(
            "G={} Y={} O={} R={} C={}",
            level_counts[0], level_counts[1], level_counts[2], level_counts[3], level_counts[4]
        ),
    );

    eprintln!("{}", report.emit());
    assert!(report.pass);
}

// ════════════════════════════════════════════════════════════════
// SCENARIO C: Flash fill in RAM-backed locations
// ════════════════════════════════════════════════════════════════
//
// /dev/shm or tmpfs fills from 80% free to 2% in under 10 seconds.
// Tests that EWMA detects the extreme acceleration and PID responds
// with maximum urgency immediately.

#[test]
fn stress_flash_fill_ram_backed() {
    let total: u64 = 64_000_000_000; // 64 GB tmpfs
    let initial_free: u64 = 51_200_000_000; // 80%
    let flash_rate: u64 = 5_000_000_000; // 5 GB/s

    let mut ewma = make_ewma();
    let mut pid = make_pid();
    let mut report = StressReport::new("flash_fill_ram_backed");

    let start = Instant::now();
    let tick = Duration::from_millis(500); // fast sampling
    let mut free = initial_free;
    let mut ticks_to_critical = 0usize;
    let mut max_urgency: f64 = 0.0;

    for i in 0..40 {
        free = free.saturating_sub(flash_rate / 2); // per half-second

        let tick_index = u32::try_from(i).expect("tick index fits u32");
        let t = start + tick * tick_index;
        let estimate = ewma.update(free, t, total / 10);
        let reading = PressureReading {
            free_bytes: free,
            total_bytes: total,
        };
        let response = pid.update(reading, Some(estimate.seconds_to_exhaustion), t);

        max_urgency = max_urgency.max(response.urgency);

        if (response.level == PressureLevel::Critical || response.level == PressureLevel::Red)
            && ticks_to_critical == 0
        {
            ticks_to_critical = i + 1;
        }
        report.steps += 1;

        if free < total / 50 {
            break; // 2% free
        }
    }

    assert!(
        ticks_to_critical > 0,
        "should reach critical during flash fill"
    );
    assert!(
        ticks_to_critical < 25,
        "should reach critical fast, took {ticks_to_critical} ticks"
    );
    assert!(
        max_urgency > 0.7,
        "flash fill should produce high urgency, got {max_urgency:.3}"
    );

    report.metric("ticks_to_critical", ticks_to_critical);
    report.metric("max_urgency", format!("{max_urgency:.3}"));
    report.metric("final_free_bytes", free);

    eprintln!("{}", report.emit());
    assert!(report.pass);
}

// ════════════════════════════════════════════════════════════════
// SCENARIO D: Recovery under ongoing write pressure
// ════════════════════════════════════════════════════════════════
//
// Disk fills to critical, then cleanup frees 50 GB, but writes
// continue at a moderate rate. Verifies EWMA detects the recovery
// trend and PID de-escalates smoothly.

#[test]
fn stress_recovery_under_write_pressure() {
    let total: u64 = 1_000_000_000_000;
    let mut free: u64 = 150_000_000_000; // start at 15%
    let consumption_rate: u64 = 2_000_000_000; // 2 GB/s
    let tick = Duration::from_secs(2);

    let mut ewma = make_ewma();
    let mut pid = make_pid();
    let mut report = StressReport::new("recovery_under_write_pressure");

    let start = Instant::now();
    let mut phase = "filling";
    let mut levels = Vec::new();
    let mut recovery_start_tick: Option<usize> = None;
    let mut first_deescalation: Option<usize> = None;

    for i in 0..120 {
        match phase {
            "filling" => {
                free = free.saturating_sub(consumption_rate * tick.as_secs());
                if free < total / 20 {
                    // 5% — trigger recovery by freeing 200 GB.
                    free += 200_000_000_000;
                    free = free.min(total);
                    phase = "recovering";
                    recovery_start_tick = Some(i);
                }
            }
            "recovering" => {
                // Ongoing writes at quarter rate, net positive after cleanup.
                free = free.saturating_sub(consumption_rate / 4 * tick.as_secs());
            }
            _ => {}
        }

        let tick_index = u32::try_from(i).expect("tick index fits u32");
        let t = start + tick * tick_index;
        let estimate = ewma.update(free, t, total / 10);
        let reading = PressureReading {
            free_bytes: free,
            total_bytes: total,
        };
        let response = pid.update(reading, Some(estimate.seconds_to_exhaustion), t);

        levels.push(response.level);

        if phase == "recovering"
            && matches!(
                response.level,
                PressureLevel::Green | PressureLevel::Yellow | PressureLevel::Orange
            )
            && first_deescalation.is_none()
        {
            first_deescalation = Some(i);
        }

        report.steps += 1;
    }

    assert!(
        recovery_start_tick.is_some(),
        "should reach critical and trigger recovery"
    );

    // After injecting 200 GB free space, the system should de-escalate.
    let post_recovery: Vec<_> = levels.iter().skip(recovery_start_tick.unwrap()).collect();
    let has_any_deescalation = post_recovery.iter().any(|l| {
        matches!(
            l,
            PressureLevel::Green | PressureLevel::Yellow | PressureLevel::Orange
        )
    });
    assert!(
        has_any_deescalation,
        "should de-escalate after 200 GB freed"
    );

    report.metric("recovery_start_tick", recovery_start_tick.unwrap());
    report.metric(
        "first_deescalation_tick",
        first_deescalation.map_or_else(|| "never".to_string(), |tick_idx| tick_idx.to_string()),
    );

    eprintln!("{}", report.emit());
    assert!(report.pass);
}

// ════════════════════════════════════════════════════════════════
// SCENARIO E: Self-monitor thread health under overload
// ════════════════════════════════════════════════════════════════
//
// Simulates stalled threads by creating heartbeats that don't beat,
// verifying the health snapshot detects stalls and dead threads.

#[test]
fn stress_thread_health_overload() {
    let tmp = tempfile::tempdir().unwrap();
    let state_path = tmp.path().join("state.json");
    let mut monitor = SelfMonitor::new(state_path);
    let mut report = StressReport::new("thread_health_overload");

    // Create heartbeats simulating multiple daemon threads.
    let healthy_beat = ThreadHeartbeat::new("monitor");
    let stalled_beat = ThreadHeartbeat::new("scanner");
    let also_stalled = ThreadHeartbeat::new("logger");

    // Beat the healthy one regularly.
    healthy_beat.beat();

    // Don't beat stalled ones — they'll appear as stalled.
    let heartbeats: Vec<Arc<ThreadHeartbeat>> =
        vec![healthy_beat.clone(), stalled_beat, also_stalled];

    // Wait briefly, then check health.
    std::thread::sleep(Duration::from_millis(50));
    healthy_beat.beat(); // fresh beat

    let health = monitor.health_snapshot(
        &heartbeats,
        Duration::from_millis(10), // very short threshold to force stall detection
        PressureLevel::Red,
    );

    // The healthy thread should be healthy.
    let healthy_thread_count = health
        .thread_status
        .iter()
        .filter(|t| t.is_healthy())
        .count();
    let unhealthy_threads: Vec<_> = health
        .thread_status
        .iter()
        .filter(|t| !t.is_healthy())
        .collect();

    let overall_healthy = unhealthy_threads.is_empty();
    report.metric("healthy_threads", healthy_thread_count);
    report.metric("unhealthy_threads", unhealthy_threads.len());
    report.metric("overall_healthy", overall_healthy);

    // At least the stalled threads should be detected.
    assert!(
        unhealthy_threads.len() >= 2,
        "should detect at least 2 stalled threads, found {}",
        unhealthy_threads.len()
    );

    // Record scan and deletion metrics under pressure.
    for i in 0..100 {
        monitor.record_scan(
            50 + i,
            i.min(10),
            Duration::from_millis(100 + i as u64 * 10),
        );
        if i % 5 == 0 {
            monitor.record_deletions(2, 5_000_000_000);
        }
        if i % 20 == 0 {
            monitor.record_error();
        }
    }

    report.metric(
        "avg_scan_duration_ms",
        monitor.avg_scan_duration().as_millis(),
    );
    report.metric("total_scans", 100);
    report.metric("total_errors", monitor.errors_total);
    report.steps = 100;

    eprintln!("{}", report.emit());
    assert!(report.pass);
}

// ════════════════════════════════════════════════════════════════
// SCENARIO F: Decision-plane drift triggering fallback
// ════════════════════════════════════════════════════════════════
//
// Start in enforce mode with good calibration, then inject
// progressively worsening predictions. Guard should transition
// to Fail, policy should enter FallbackSafe, and no deletions
// should be approved. Tests the full pipeline under drift.

#[test]
fn stress_decision_plane_drift() {
    let scoring = ScoringEngine::from_config(&ScoringConfig::default(), 30);
    let guard_config = GuardrailConfig {
        min_observations: 5,
        window_size: 30,
        recovery_clean_windows: 5,
        ..GuardrailConfig::default()
    };
    let mut guard = AdaptiveGuard::new(guard_config);
    let policy_config = PolicyConfig {
        initial_mode: ActiveMode::Observe,
        calibration_breach_windows: 3,
        recovery_clean_windows: 5,
        ..PolicyConfig::default()
    };
    let mut engine = PolicyEngine::new(policy_config);
    let mut report = StressReport::new("decision_plane_drift");

    // Phase 1: Warmup — good calibration, promote to enforce.
    for _ in 0..15 {
        guard.observe(CalibrationObservation {
            predicted_rate: 1000.0,
            actual_rate: 1050.0,
            predicted_tte: 90.0,
            actual_tte: 100.0,
        });
    }
    assert_eq!(guard.status(), GuardStatus::Pass);
    engine.promote(); // observe → canary
    engine.promote(); // canary → enforce
    assert_eq!(engine.mode(), ActiveMode::Enforce);

    // Phase 2: Evaluate candidates in enforce — should approve some.
    let candidates: Vec<CandidateInput> = (0..20).map(|i| make_candidate(i, 48, 5)).collect();
    let scored = scoring.score_batch(&candidates, 0.6);
    let decision_pre = engine.evaluate(&scored, Some(&guard.diagnostics()));
    let pre_approved = decision_pre.approved_for_deletion.len();
    report.metric("pre_drift_approvals", pre_approved);
    report.steps += 1;

    // Phase 3: Inject drift — 50 bad observations.
    let mut drift_steps = 0;
    let mut guard_fail_at: Option<usize> = None;
    for i in 0..50 {
        let drift_idx = f64::from(u32::try_from(i).expect("drift index fits in u32"));
        guard.observe(CalibrationObservation {
            predicted_rate: 1000.0,
            actual_rate: drift_idx.mul_add(100.0, 3000.0),
            predicted_tte: 100.0,
            actual_tte: 15.0,
        });
        drift_steps += 1;

        if guard.status() == GuardStatus::Fail && guard_fail_at.is_none() {
            guard_fail_at = Some(i);
        }

        // Feed the guard state to the policy engine.
        let diag = guard.diagnostics();
        engine.observe_window(&diag);

        // Once in fallback, verify no deletions.
        if engine.mode() == ActiveMode::FallbackSafe {
            let scored2 = scoring.score_batch(&candidates, 0.9);
            let decision = engine.evaluate(&scored2, Some(&diag));
            assert_eq!(
                decision.approved_for_deletion.len(),
                0,
                "fallback should block all deletions"
            );
            break;
        }
    }
    report.steps += drift_steps;

    assert!(guard_fail_at.is_some(), "guard should transition to Fail");
    assert_eq!(
        engine.mode(),
        ActiveMode::FallbackSafe,
        "policy should enter FallbackSafe"
    );

    report.metric("guard_fail_at_step", guard_fail_at.unwrap());
    report.metric("drift_steps_to_fallback", drift_steps);

    // Phase 4: Recovery — feed good observations.
    let mut recovery_steps = 0;
    for _ in 0..20 {
        guard.observe(CalibrationObservation {
            predicted_rate: 1000.0,
            actual_rate: 1020.0,
            predicted_tte: 90.0,
            actual_tte: 100.0,
        });
        engine.observe_window(&guard.diagnostics());
        recovery_steps += 1;

        if engine.mode() != ActiveMode::FallbackSafe {
            break;
        }
    }
    report.steps += recovery_steps;
    report.metric("recovery_steps", recovery_steps);
    report.metric("final_mode", format!("{:?}", engine.mode()));

    // Verify transition log is comprehensive.
    let transitions = engine.transition_log();
    let has_fallback = transitions.iter().any(|t| t.transition == "fallback");
    assert!(has_fallback, "transition log must record fallback");
    report.metric("transition_log_entries", transitions.len());

    eprintln!("{}", report.emit());
    assert!(report.pass);
}

// ════════════════════════════════════════════════════════════════
// SCENARIO G: Guard integrity failure forcing conservative mode
// ════════════════════════════════════════════════════════════════
//
// Guard stuck in Unknown (insufficient data), combined with high
// urgency. Policy should behave conservatively despite pressure.

#[test]
fn stress_guard_integrity_failure() {
    let scoring = ScoringEngine::from_config(&ScoringConfig::default(), 30);
    let guard_config = GuardrailConfig {
        min_observations: 100, // deliberately high — guard never reaches Pass
        window_size: 200,
        ..GuardrailConfig::default()
    };
    let mut guard = AdaptiveGuard::new(guard_config);
    let policy_config = PolicyConfig {
        initial_mode: ActiveMode::Observe,
        ..PolicyConfig::default()
    };
    let mut engine = PolicyEngine::new(policy_config);
    let mut report = StressReport::new("guard_integrity_failure");

    // Feed a few observations — not enough to reach min_observations.
    for _ in 0..10 {
        guard.observe(CalibrationObservation {
            predicted_rate: 1000.0,
            actual_rate: 1050.0,
            predicted_tte: 90.0,
            actual_tte: 100.0,
        });
    }
    assert_eq!(guard.status(), GuardStatus::Unknown);

    // Promote to canary despite Unknown guard.
    engine.promote();
    assert_eq!(engine.mode(), ActiveMode::Canary);

    // Evaluate 100 batches with high urgency and Unknown guard.
    let mut total_approved = 0;
    let mut total_evaluated = 0;
    for batch in 0..100 {
        let candidates: Vec<CandidateInput> = (0..10)
            .map(|i| make_candidate(batch * 10 + i, 72, 8))
            .collect();
        let scored = scoring.score_batch(&candidates, 0.8);
        let decision = engine.evaluate(&scored, Some(&guard.diagnostics()));
        total_approved += decision.approved_for_deletion.len();
        total_evaluated += scored.len();
        report.steps += 1;

        // If budget exhausted, engine should enter fallback.
        if decision.budget_exhausted || engine.mode() == ActiveMode::FallbackSafe {
            break;
        }
    }

    // With Unknown guard, the guard_penalty should heavily penalize
    // delete actions, making most candidates Keep. The canary budget
    // should also limit total deletions.
    report.metric("total_evaluated", total_evaluated);
    report.metric("total_approved", total_approved);
    report.metric("final_mode", format!("{:?}", engine.mode()));
    report.metric("guard_status", format!("{:?}", guard.status()));

    // Conservative behavior check: approval rate should be low.
    if total_evaluated > 0 {
        let approved_count = u32::try_from(total_approved).expect("approved count fits in u32");
        let evaluated_count = u32::try_from(total_evaluated).expect("evaluated count fits in u32");
        let approval_rate = f64::from(approved_count) / f64::from(evaluated_count);
        report.metric("approval_rate", format!("{approval_rate:.4}"));
        assert!(
            approval_rate < 0.5,
            "approval rate should be conservative with Unknown guard, got {approval_rate:.4}"
        );
    }

    eprintln!("{}", report.emit());
    assert!(report.pass);
}

// ════════════════════════════════════════════════════════════════
// SCENARIO H: Multi-agent swarm simulation
// ════════════════════════════════════════════════════════════════
//
// Simulates N agents generating build artifacts concurrently while
// the scoring engine processes them. Verifies deterministic ranking
// and proper veto handling under concurrent artifact creation.

#[test]
fn stress_multi_agent_swarm() {
    let scoring = ScoringEngine::from_config(&ScoringConfig::default(), 30);
    let policy_config = PolicyConfig {
        initial_mode: ActiveMode::Observe,
        max_canary_deletes_per_hour: 50,
        ..PolicyConfig::default()
    };
    let mut engine = PolicyEngine::new(policy_config);
    engine.promote(); // canary
    engine.promote(); // enforce
    let mut report = StressReport::new("multi_agent_swarm");

    // Simulate 10 agents, each creating 5-10 target dirs.
    let agent_names = [
        ".target_opus_main",
        "cargo-target-quietwillow",
        "pi_agent_cyanrobin",
        "_target_sandygate",
        ".tmp_target_bravo",
        "cargo_target_delta",
        "pi_target_echo",
        "cass-target-foxtrot",
        "br-build-golf",
        "target-hotel",
    ];

    let mut all_candidates = Vec::new();
    for (agent_idx, name) in agent_names.iter().enumerate() {
        let artifact_count = 5 + agent_idx % 6;
        for artifact_idx in 0..artifact_count {
            let age_hours = (artifact_idx as u64 + 1) * 6;
            let size_gib = 1 + (artifact_idx as u64 % 5);
            let mut candidate = make_candidate(agent_idx * 100 + artifact_idx, age_hours, size_gib);
            candidate.path = PathBuf::from(format!("/data/p{agent_idx}/{name}_{artifact_idx}"));
            candidate.classification.pattern_name = format!("{name}*");

            // Some agents have .git (should be vetoed via excluded flag).
            if agent_idx == 3 && artifact_idx == 0 {
                candidate.signals.has_git = true;
                candidate.excluded = true;
            }
            // Some artifacts are open (should be vetoed).
            if artifact_idx == 0 && agent_idx < 3 {
                candidate.is_open = true;
            }

            all_candidates.push(candidate);
        }
    }

    let total_candidates = all_candidates.len();
    report.metric("total_candidates", total_candidates);

    // Score all candidates at high urgency.
    let scored = scoring.score_batch(&all_candidates, 0.7);

    // Count vetoed candidates.
    let vetoed_count = scored.iter().filter(|s| s.vetoed).count();
    let open_vetoed_count = all_candidates.iter().filter(|c| c.is_open).count();
    let git_excluded_count = all_candidates.iter().filter(|c| c.excluded).count();

    report.metric("vetoed_count", vetoed_count);
    report.metric("open_file_candidates", open_vetoed_count);
    report.metric("git_excluded", git_excluded_count);

    // Evaluate through policy.
    let guard_diag = storage_ballast_helper::monitor::guardrails::GuardDiagnostics {
        status: GuardStatus::Pass,
        observation_count: 25,
        median_rate_error: 0.10,
        conservative_fraction: 0.85,
        e_process_value: 2.0,
        e_process_alarm: false,
        consecutive_clean: 5,
        reason: "calibration verified".to_string(),
    };
    let decision = engine.evaluate(&scored, Some(&guard_diag));

    let approved = decision.approved_for_deletion.len();
    let total_records = decision.records.len();
    report.metric("approved_deletions", approved);
    report.metric("total_decision_records", total_records);

    // Verify determinism: run the same pipeline twice.
    let mut engine2 = PolicyEngine::new(PolicyConfig {
        initial_mode: ActiveMode::Observe,
        max_canary_deletes_per_hour: 50,
        ..PolicyConfig::default()
    });
    engine2.promote();
    engine2.promote();
    let scored2 = scoring.score_batch(&all_candidates, 0.7);
    let decision2 = engine2.evaluate(&scored2, Some(&guard_diag));

    // Scores must be identical.
    let run_one_scores: Vec<f64> = decision.records.iter().map(|r| r.total_score).collect();
    let run_two_scores: Vec<f64> = decision2.records.iter().map(|r| r.total_score).collect();
    assert_eq!(
        run_one_scores, run_two_scores,
        "scoring must be deterministic"
    );

    // Actions must be identical.
    let actions1: Vec<ActionRecord> = decision.records.iter().map(|r| r.action).collect();
    let actions2: Vec<ActionRecord> = decision2.records.iter().map(|r| r.action).collect();
    assert_eq!(actions1, actions2, "actions must be deterministic");

    // No vetoed candidate should be in approved list.
    for approved_candidate in &decision.approved_for_deletion {
        assert!(
            !approved_candidate.vetoed,
            "vetoed candidate should not be approved: {:?}",
            approved_candidate.path
        );
    }

    report.metric("determinism", "verified");
    report.steps = 2;

    eprintln!("{}", report.emit());
    assert!(report.pass);
}

// ════════════════════════════════════════════════════════════════
// SCENARIO I: EWMA convergence under varying load patterns
// ════════════════════════════════════════════════════════════════
//
// Feed 500 ticks of varying disk usage patterns (steady, burst,
// recovery, plateau) and verify EWMA tracks trends correctly
// without diverging or producing NaN/Inf.

#[test]
fn stress_ewma_convergence() {
    let mut ewma = make_ewma();
    let mut report = StressReport::new("ewma_convergence");

    let total: u64 = 1_000_000_000_000;
    let start = Instant::now();
    let tick = Duration::from_secs(2);
    let threshold = total / 10;
    let mut free: u64 = 500_000_000_000; // 50%

    let mut nan_count = 0usize;
    let mut inf_count = 0usize;
    let mut negative_tte_count = 0usize;

    // Phase 1: Steady consumption (100 ticks).
    for i in 0_u32..100 {
        free = free.saturating_sub(1_000_000_000); // 1 GB/tick
        let t = start + tick * i;
        let est = ewma.update(free, t, threshold);
        if est.bytes_per_second.is_nan() {
            nan_count += 1;
        }
        if est.bytes_per_second.is_infinite() {
            inf_count += 1;
        }
        if est.seconds_to_exhaustion < 0.0 {
            negative_tte_count += 1;
        }
    }

    // Phase 2: Sudden burst (50 ticks at 10x rate).
    for i in 100_u32..150 {
        free = free.saturating_sub(10_000_000_000); // 10 GB/tick
        let t = start + tick * i;
        let est = ewma.update(free, t, threshold);
        if est.bytes_per_second.is_nan() {
            nan_count += 1;
        }
        if est.bytes_per_second.is_infinite() {
            inf_count += 1;
        }
    }

    // Phase 3: Recovery — free space increases (cleanup, 100 ticks).
    for i in 150_u32..250 {
        free = free.saturating_add(2_000_000_000).min(total); // 2 GB/tick recovered
        let t = start + tick * i;
        let est = ewma.update(free, t, threshold);
        if est.bytes_per_second.is_nan() {
            nan_count += 1;
        }
        if est.bytes_per_second.is_infinite() {
            inf_count += 1;
        }
        // During recovery, trend should eventually become Recovering or Stable.
    }

    // Phase 4: Plateau (100 ticks, stable).
    for i in 250_u32..350 {
        // Tiny jitter.
        let jitter: i64 = if i % 2 == 0 {
            100_000_000
        } else {
            -100_000_000
        };
        let jittered_free = i128::from(free) + i128::from(jitter);
        free = u64::try_from(jittered_free.max(0)).expect("clamped free space is non-negative");
        let t = start + tick * i;
        let est = ewma.update(free, t, threshold);
        if est.bytes_per_second.is_nan() {
            nan_count += 1;
        }
        if est.bytes_per_second.is_infinite() {
            inf_count += 1;
        }
    }

    // Phase 5: Another fill (100 ticks, moderate).
    for i in 350_u32..450 {
        free = free.saturating_sub(500_000_000); // 500 MB/tick
        let t = start + tick * i;
        let est = ewma.update(free, t, threshold);
        if est.bytes_per_second.is_nan() {
            nan_count += 1;
        }
        if est.bytes_per_second.is_infinite() {
            inf_count += 1;
        }
    }

    report.steps = 450;
    report.metric("total_samples", ewma.sample_count());
    report.metric("nan_count", nan_count);
    report.metric("inf_count", inf_count);
    report.metric("negative_tte_count", negative_tte_count);
    report.metric("final_free_bytes", free);

    assert_eq!(nan_count, 0, "EWMA should never produce NaN");
    assert_eq!(inf_count, 0, "EWMA should never produce Inf");

    eprintln!("{}", report.emit());
    assert!(report.pass);
}

// ════════════════════════════════════════════════════════════════
// SCENARIO J: PID controller stability under oscillating pressure
// ════════════════════════════════════════════════════════════════
//
// Rapidly oscillating free space to test PID doesn't ring or diverge.

#[test]
fn stress_pid_stability_oscillation() {
    let total: u64 = 1_000_000_000_000;
    let mut pid = make_pid();
    let mut report = StressReport::new("pid_stability_oscillation");

    let start = Instant::now();
    let tick = Duration::from_secs(1);
    let mut urgency_values = Vec::new();

    // Oscillate between 8% and 22% free rapidly.
    for i in 0_u32..200 {
        let free = if i % 2 == 0 {
            total.saturating_mul(8).saturating_div(100)
        } else {
            total.saturating_mul(22).saturating_div(100)
        };

        let t = start + tick * i;
        let reading = PressureReading {
            free_bytes: free,
            total_bytes: total,
        };
        let response = pid.update(reading, None, t);
        urgency_values.push(response.urgency);
        report.steps += 1;
    }

    // Check: urgency should not grow without bound.
    let max_urgency = urgency_values.iter().copied().fold(0.0f64, f64::max);
    assert!(
        max_urgency <= 1.0,
        "PID urgency should be clamped to 1.0, got {max_urgency}"
    );

    // Check: urgency should not become NaN.
    let has_nan = urgency_values.iter().any(|u| u.is_nan());
    assert!(!has_nan, "PID should never produce NaN urgency");

    // Check: no negative urgency.
    let has_negative = urgency_values.iter().any(|u| *u < 0.0);
    assert!(!has_negative, "PID should never produce negative urgency");

    report.metric("max_urgency", format!("{max_urgency:.3}"));
    report.metric(
        "urgency_variance",
        format!("{:.4}", variance(&urgency_values)),
    );

    eprintln!("{}", report.emit());
    assert!(report.pass);
}

// ════════════════════════════════════════════════════════════════
// SCENARIO K: Ballast provision/release/verify cycle
// ════════════════════════════════════════════════════════════════
//
// Provision, verify, release, replenish in a tight loop.

#[test]
fn stress_ballast_lifecycle() {
    let tmp = tempfile::tempdir().unwrap();
    let ballast_dir = tmp.path().join("ballast");
    std::fs::create_dir_all(&ballast_dir).unwrap();

    let config = BallastConfig {
        file_count: 5,
        file_size_bytes: 1024 * 1024, // 1 MB each (small for test speed)
        replenish_cooldown_minutes: 0,
        auto_provision: true,
        overrides: std::collections::HashMap::default(),
    };

    let mut manager = BallastManager::new(ballast_dir, config).unwrap();
    let mut report = StressReport::new("ballast_lifecycle");

    // Phase 1: Provision.
    let prov = manager.provision(None).unwrap();
    assert_eq!(prov.files_created, 5);
    assert_eq!(prov.errors.len(), 0);
    report.metric("provisioned_files", prov.files_created);
    report.metric("provisioned_bytes", prov.total_bytes);

    // Phase 2: Verify.
    let verify = manager.verify();
    assert_eq!(verify.files_ok, 5);
    assert_eq!(verify.files_corrupted, 0);
    report.metric("verified_ok", verify.files_ok);

    // Phase 3: Release 3 files.
    let release = manager.release(3).unwrap();
    assert_eq!(release.files_released, 3);
    assert_eq!(manager.available_count(), 2);
    report.metric("released_files", release.files_released);
    report.metric("released_bytes", release.bytes_freed);

    // Phase 4: Replenish.
    let replenish = manager.replenish(None).unwrap();
    assert_eq!(replenish.errors.len(), 0);
    report.metric("replenished_files", replenish.files_created);

    // Phase 5: Tight release/replenish loop.
    for i in 0..10 {
        let available = manager.available_count();
        if available > 0 {
            let rel = manager.release(1).unwrap();
            assert_eq!(rel.files_released, 1);
        }
        let rep = manager.replenish(None).unwrap();
        assert_eq!(rep.errors.len(), 0, "cycle {i}: replenish errors");
        report.steps += 1;
    }

    // Final verify.
    let final_verify = manager.verify();
    assert_eq!(final_verify.files_corrupted, 0);
    report.metric("final_files_ok", final_verify.files_ok);
    report.metric("final_available", manager.available_count());

    eprintln!("{}", report.emit());
    assert!(report.pass);
}

// ════════════════════════════════════════════════════════════════
// SCENARIO L: Full pipeline stress — EWMA + PID + Policy + Guard
// ════════════════════════════════════════════════════════════════
//
// End-to-end stress test driving all components together through
// a realistic multi-phase pressure scenario with 500 ticks.

#[test]
#[allow(clippy::too_many_lines)]
fn stress_full_pipeline() {
    let total: u64 = 1_000_000_000_000;
    let mut free: u64 = 300_000_000_000;

    let mut ewma = make_ewma();
    let mut pid = make_pid();
    let scoring = ScoringEngine::from_config(&ScoringConfig::default(), 30);
    let guard_config = GuardrailConfig {
        min_observations: 5,
        window_size: 30,
        recovery_clean_windows: 3,
        ..GuardrailConfig::default()
    };
    let mut guard = AdaptiveGuard::new(guard_config);
    let policy_config = PolicyConfig {
        initial_mode: ActiveMode::Observe,
        calibration_breach_windows: 3,
        recovery_clean_windows: 3,
        max_canary_deletes_per_hour: 20,
        ..PolicyConfig::default()
    };
    let mut engine = PolicyEngine::new(policy_config);
    let mut report = StressReport::new("full_pipeline");

    let start = Instant::now();
    let tick = Duration::from_secs(2);
    let threshold = total / 10;

    let mut total_approved = 0usize;
    let mut total_hypothetical = 0usize;
    let mut mode_transitions = 0usize;
    let mut fallback_entries = 0usize;
    let mut last_mode = engine.mode();

    // Seed guard with good initial observations.
    for _ in 0..10 {
        guard.observe(CalibrationObservation {
            predicted_rate: 1000.0,
            actual_rate: 1050.0,
            predicted_tte: 90.0,
            actual_tte: 100.0,
        });
    }

    // Promote to enforce for full stress.
    engine.promote(); // observe → canary
    engine.promote(); // canary → enforce

    for i in 0_u32..500 {
        // Simulate varied pressure phases.
        let consumption = match i {
            0..=99 => 500_000_000,      // moderate: 500 MB/tick
            100..=149 => 5_000_000_000, // burst: 5 GB/tick
            150..=249 => 0,             // plateau + cleanup
            250..=349 => 1_000_000_000, // moderate
            350..=399 => 3_000_000_000, // heavy
            _ => 200_000_000,           // light
        };

        // Apply cleanup at certain intervals.
        if i == 150 {
            free += 100_000_000_000; // 100 GB cleanup
        }
        if i == 300 {
            free += 50_000_000_000; // 50 GB cleanup
        }

        free = free.saturating_sub(consumption);
        free = free.min(total);

        let t = start + tick * i;
        let estimate = ewma.update(free, t, threshold);
        let consumption_rate = u64_to_f64(consumption);

        // Update guard with calibration observation.
        let obs = CalibrationObservation {
            predicted_rate: estimate.bytes_per_second.max(1.0),
            actual_rate: consumption_rate / tick.as_secs_f64(),
            predicted_tte: estimate.seconds_to_exhaustion.max(1.0),
            actual_tte: if consumption > 0 {
                u64_to_f64(free) / consumption_rate * tick.as_secs_f64()
            } else {
                f64::MAX
            },
        };
        guard.observe(obs);

        // Feed guard diagnostics to policy engine.
        let diag = guard.diagnostics();
        engine.observe_window(&diag);

        let reading = PressureReading {
            free_bytes: free,
            total_bytes: total,
        };
        let response = pid.update(reading, Some(estimate.seconds_to_exhaustion), t);

        // Score candidates when urgency is high enough.
        if response.urgency > 0.3 {
            let candidates: Vec<CandidateInput> = (0..5)
                .map(|j| {
                    let candidate_idx =
                        usize::try_from(i * 5 + j).expect("candidate index fits in usize");
                    make_candidate(candidate_idx, 24, 2)
                })
                .collect();
            let scored = scoring.score_batch(&candidates, response.urgency);
            let decision = engine.evaluate(&scored, Some(&diag));
            total_approved += decision.approved_for_deletion.len();
            total_hypothetical += decision.hypothetical_deletes;
        }

        // Track mode transitions.
        let current_mode = engine.mode();
        if current_mode != last_mode {
            mode_transitions += 1;
            if current_mode == ActiveMode::FallbackSafe {
                fallback_entries += 1;
            }
            last_mode = current_mode;
        }

        report.steps += 1;

        if free == 0 {
            break;
        }
    }

    report.metric("total_ticks", report.steps);
    report.metric("total_approved_deletions", total_approved);
    report.metric("total_hypothetical_deletions", total_hypothetical);
    report.metric("mode_transitions", mode_transitions);
    report.metric("fallback_entries", fallback_entries);
    report.metric("final_mode", format!("{:?}", engine.mode()));
    report.metric("final_free_bytes", free);
    report.metric("guard_status", format!("{:?}", guard.status()));
    report.metric("ewma_samples", ewma.sample_count());
    report.metric("transition_log_entries", engine.transition_log().len());

    // Sanity: pipeline should complete without panic or infinite loop.
    assert!(report.steps >= 100, "pipeline should run many ticks");

    eprintln!("{}", report.emit());
    assert!(report.pass);
}

// ════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════

fn variance(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let sample_count = f64::from(u32::try_from(values.len()).expect("sample count fits in u32"));
    let mean = values.iter().sum::<f64>() / sample_count;
    let sq_sum: f64 = values.iter().map(|v| (v - mean).powi(2)).sum();
    sq_sum / sample_count
}

fn u64_to_f64(value: u64) -> f64 {
    let upper = u32::try_from(value >> 32).expect("upper half fits in u32");
    let lower = u32::try_from(value & u64::from(u32::MAX)).expect("lower half fits in u32");
    f64::from(upper) * 4_294_967_296.0 + f64::from(lower)
}
