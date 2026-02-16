//! Deterministic replay regression suite (bd-xzt.4.10).
//!
//! Defines canonical trace fixtures for pressure transitions, stale state,
//! degraded telemetry, ballast events, and policy transitions. Each trace
//! is replayed through the headless harness and asserts stable derived
//! view-model/output invariants via trace digests.
//!
//! **Regression detection strategy:** each scenario runs a defined step
//! sequence through the Elm update loop, then asserts:
//! 1. Model state invariants (screen, degraded, counts, cursor positions).
//! 2. Frame content invariants (key labels, badge text, presence/absence).
//! 3. Determinism: re-running the same trace on a fresh harness produces
//!    an identical trace digest (SHA-256 of state transitions).
//!
//! Golden digest values are NOT hardcoded (the codebase evolves across
//! agents). Instead, determinism is verified by running each trace twice.

#![allow(clippy::too_many_lines)] // Test fixtures are verbose by nature.

use super::model::{DashboardMsg, Screen};
use super::telemetry::{
    DataSource, DecisionEvidence, FactorBreakdown, TelemetryResult, TimelineEvent,
};
use super::test_harness::{
    DashboardHarness, HarnessStep, sample_healthy_state, sample_pressured_state,
};
use crate::daemon::self_monitor::{
    BallastState, Counters, DaemonState, LastScanState, MountPressure, PressureState,
};

// ──────────────────── daemon state fixtures ────────────────────

/// Intermediate yellow pressure — disk filling but not critical.
fn yellow_pressure_state() -> DaemonState {
    DaemonState {
        version: "0.1.0".into(),
        pid: 1234,
        started_at: "2026-02-16T00:00:00Z".into(),
        uptime_seconds: 5400,
        last_updated: "2026-02-16T01:30:00Z".into(),
        pressure: PressureState {
            overall: "yellow".into(),
            mounts: vec![MountPressure {
                path: "/data".into(),
                free_pct: 12.5,
                level: "yellow".into(),
                rate_bps: Some(-10_000.0),
            }],
        },
        ballast: BallastState {
            available: 8,
            total: 10,
            released: 2,
        },
        last_scan: LastScanState {
            at: Some("2026-02-16T01:29:00Z".into()),
            candidates: 20,
            deleted: 3,
        },
        counters: Counters {
            scans: 90,
            deletions: 3,
            bytes_freed: 1_500_000_000,
            errors: 0,
            dropped_log_events: 0,
        },
        memory_rss_bytes: 48_000_000,
    }
}

/// Red critical pressure — disk nearly full.
fn red_critical_state() -> DaemonState {
    DaemonState {
        version: "0.1.0".into(),
        pid: 1234,
        started_at: "2026-02-16T00:00:00Z".into(),
        uptime_seconds: 7200,
        last_updated: "2026-02-16T02:00:00Z".into(),
        pressure: PressureState {
            overall: "red".into(),
            mounts: vec![MountPressure {
                path: "/data".into(),
                free_pct: 2.1,
                level: "red".into(),
                rate_bps: Some(-80_000.0),
            }],
        },
        ballast: BallastState {
            available: 1,
            total: 10,
            released: 9,
        },
        last_scan: LastScanState {
            at: Some("2026-02-16T01:59:00Z".into()),
            candidates: 50,
            deleted: 20,
        },
        counters: Counters {
            scans: 120,
            deletions: 20,
            bytes_freed: 8_000_000_000,
            errors: 1,
            dropped_log_events: 0,
        },
        memory_rss_bytes: 72_000_000,
    }
}

/// Recovery state — pressure back to green after intervention.
fn recovery_state() -> DaemonState {
    DaemonState {
        version: "0.1.0".into(),
        pid: 1234,
        started_at: "2026-02-16T00:00:00Z".into(),
        uptime_seconds: 9000,
        last_updated: "2026-02-16T02:30:00Z".into(),
        pressure: PressureState {
            overall: "green".into(),
            mounts: vec![MountPressure {
                path: "/data".into(),
                free_pct: 65.0,
                level: "green".into(),
                rate_bps: Some(200.0),
            }],
        },
        ballast: BallastState {
            available: 10,
            total: 10,
            released: 0,
        },
        last_scan: LastScanState {
            at: Some("2026-02-16T02:29:00Z".into()),
            candidates: 2,
            deleted: 0,
        },
        counters: Counters {
            scans: 150,
            deletions: 20,
            bytes_freed: 8_000_000_000,
            errors: 1,
            dropped_log_events: 0,
        },
        memory_rss_bytes: 40_000_000,
    }
}

/// Ballast fully depleted under pressure.
fn ballast_depleted_state() -> DaemonState {
    DaemonState {
        version: "0.1.0".into(),
        pid: 1234,
        started_at: "2026-02-16T00:00:00Z".into(),
        uptime_seconds: 6000,
        last_updated: "2026-02-16T01:40:00Z".into(),
        pressure: PressureState {
            overall: "red".into(),
            mounts: vec![MountPressure {
                path: "/data".into(),
                free_pct: 1.5,
                level: "red".into(),
                rate_bps: Some(-100_000.0),
            }],
        },
        ballast: BallastState {
            available: 0,
            total: 10,
            released: 10,
        },
        last_scan: LastScanState {
            at: Some("2026-02-16T01:39:00Z".into()),
            candidates: 60,
            deleted: 25,
        },
        counters: Counters {
            scans: 100,
            deletions: 25,
            bytes_freed: 10_000_000_000,
            errors: 3,
            dropped_log_events: 0,
        },
        memory_rss_bytes: 80_000_000,
    }
}

/// Two mounts at divergent pressure levels.
fn multi_mount_divergent_state() -> DaemonState {
    DaemonState {
        version: "0.1.0".into(),
        pid: 1234,
        started_at: "2026-02-16T00:00:00Z".into(),
        uptime_seconds: 4800,
        last_updated: "2026-02-16T01:20:00Z".into(),
        pressure: PressureState {
            overall: "red".into(),
            mounts: vec![
                MountPressure {
                    path: "/".into(),
                    free_pct: 55.0,
                    level: "green".into(),
                    rate_bps: Some(100.0),
                },
                MountPressure {
                    path: "/data".into(),
                    free_pct: 4.0,
                    level: "red".into(),
                    rate_bps: Some(-60_000.0),
                },
            ],
        },
        ballast: BallastState {
            available: 3,
            total: 10,
            released: 7,
        },
        last_scan: LastScanState {
            at: Some("2026-02-16T01:19:00Z".into()),
            candidates: 35,
            deleted: 12,
        },
        counters: Counters {
            scans: 80,
            deletions: 12,
            bytes_freed: 6_000_000_000,
            errors: 0,
            dropped_log_events: 0,
        },
        memory_rss_bytes: 52_000_000,
    }
}

// ──────────────────── telemetry fixtures ────────────────────

/// Mixed-severity timeline events for replay scenarios.
fn sample_timeline_events() -> Vec<TimelineEvent> {
    vec![
        TimelineEvent {
            timestamp: "2026-02-16T01:00:00Z".into(),
            event_type: "pressure_change".into(),
            severity: "warning".into(),
            path: None,
            size_bytes: None,
            score: None,
            pressure_level: Some("yellow".into()),
            free_pct: Some(15.0),
            success: None,
            error_code: None,
            error_message: None,
            duration_ms: None,
            details: Some("pressure rose to yellow".into()),
        },
        TimelineEvent {
            timestamp: "2026-02-16T01:05:00Z".into(),
            event_type: "artifact_delete".into(),
            severity: "info".into(),
            path: Some("/data/target/debug".into()),
            size_bytes: Some(2_000_000_000),
            score: Some(0.95),
            pressure_level: Some("yellow".into()),
            free_pct: Some(15.0),
            success: Some(true),
            error_code: None,
            error_message: None,
            duration_ms: Some(150),
            details: Some("deleted build artifact".into()),
        },
        TimelineEvent {
            timestamp: "2026-02-16T01:10:00Z".into(),
            event_type: "pressure_change".into(),
            severity: "critical".into(),
            path: None,
            size_bytes: None,
            score: None,
            pressure_level: Some("red".into()),
            free_pct: Some(3.0),
            success: None,
            error_code: None,
            error_message: None,
            duration_ms: None,
            details: Some("pressure escalated to red".into()),
        },
    ]
}

/// Decision evidence fixture with one delete and one vetoed keep.
fn sample_decisions() -> Vec<DecisionEvidence> {
    vec![
        DecisionEvidence {
            decision_id: 1,
            timestamp: "2026-02-16T01:05:00Z".into(),
            path: "/data/target/debug".into(),
            size_bytes: 2_000_000_000,
            age_secs: 86400,
            action: "delete".into(),
            effective_action: Some("delete".into()),
            policy_mode: "enforce".into(),
            factors: FactorBreakdown {
                location: 0.9,
                name: 0.8,
                age: 0.7,
                size: 0.95,
                structure: 0.85,
                pressure_multiplier: 1.2,
            },
            total_score: 0.95,
            posterior_abandoned: 0.92,
            expected_loss_keep: 4.5,
            expected_loss_delete: 0.3,
            calibration_score: 0.85,
            vetoed: false,
            veto_reason: None,
            guard_status: Some("pass".into()),
            summary: "High confidence delete".into(),
            raw_json: None,
        },
        DecisionEvidence {
            decision_id: 2,
            timestamp: "2026-02-16T01:06:00Z".into(),
            path: "/data/.cache/agent-workspace".into(),
            size_bytes: 500_000_000,
            age_secs: 3600,
            action: "keep".into(),
            effective_action: Some("keep".into()),
            policy_mode: "enforce".into(),
            factors: FactorBreakdown {
                location: 0.3,
                name: 0.2,
                age: 0.1,
                size: 0.4,
                structure: 0.1,
                pressure_multiplier: 1.2,
            },
            total_score: 0.22,
            posterior_abandoned: 0.15,
            expected_loss_keep: 0.5,
            expected_loss_delete: 3.2,
            calibration_score: 0.78,
            vetoed: true,
            veto_reason: Some("recently active workspace".into()),
            guard_status: Some("veto".into()),
            summary: "Protected by veto".into(),
            raw_json: None,
        },
    ]
}

/// Observe-mode decisions (shadow only, no enforcement).
fn observe_mode_decisions() -> Vec<DecisionEvidence> {
    vec![DecisionEvidence {
        decision_id: 10,
        timestamp: "2026-02-16T01:00:00Z".into(),
        path: "/data/old-target".into(),
        size_bytes: 1_000_000_000,
        age_secs: 172800,
        action: "delete".into(),
        effective_action: Some("observe".into()),
        policy_mode: "observe".into(),
        factors: FactorBreakdown {
            location: 0.8,
            name: 0.7,
            age: 0.9,
            size: 0.6,
            structure: 0.7,
            pressure_multiplier: 1.0,
        },
        total_score: 0.78,
        posterior_abandoned: 0.80,
        expected_loss_keep: 2.0,
        expected_loss_delete: 0.5,
        calibration_score: 0.70,
        vetoed: false,
        veto_reason: None,
        guard_status: Some("pass".into()),
        summary: "Would delete in enforce mode".into(),
        raw_json: None,
    }]
}

/// Canary-mode decisions (partial enforcement).
fn canary_mode_decisions() -> Vec<DecisionEvidence> {
    vec![DecisionEvidence {
        decision_id: 20,
        timestamp: "2026-02-16T01:30:00Z".into(),
        path: "/data/stale-cache".into(),
        size_bytes: 800_000_000,
        age_secs: 259200,
        action: "delete".into(),
        effective_action: Some("delete".into()),
        policy_mode: "canary".into(),
        factors: FactorBreakdown {
            location: 0.7,
            name: 0.6,
            age: 0.95,
            size: 0.5,
            structure: 0.6,
            pressure_multiplier: 1.1,
        },
        total_score: 0.82,
        posterior_abandoned: 0.88,
        expected_loss_keep: 3.0,
        expected_loss_delete: 0.4,
        calibration_score: 0.82,
        vetoed: false,
        veto_reason: None,
        guard_status: Some("pass".into()),
        summary: "Canary deletion approved".into(),
        raw_json: None,
    }]
}

fn timeline_result(events: Vec<TimelineEvent>) -> TelemetryResult<Vec<TimelineEvent>> {
    TelemetryResult {
        data: events,
        source: DataSource::Sqlite,
        partial: false,
        diagnostics: String::new(),
    }
}

fn partial_timeline_result(events: Vec<TimelineEvent>) -> TelemetryResult<Vec<TimelineEvent>> {
    TelemetryResult {
        data: events,
        source: DataSource::Jsonl,
        partial: true,
        diagnostics: "schema-shield recovered=2 dropped=1".into(),
    }
}

fn decisions_result(decisions: Vec<DecisionEvidence>) -> TelemetryResult<Vec<DecisionEvidence>> {
    TelemetryResult {
        data: decisions,
        source: DataSource::Sqlite,
        partial: false,
        diagnostics: String::new(),
    }
}

fn unavailable_timeline() -> TelemetryResult<Vec<TimelineEvent>> {
    TelemetryResult::unavailable("no telemetry backend available".into())
}

fn unavailable_decisions() -> TelemetryResult<Vec<DecisionEvidence>> {
    TelemetryResult::unavailable("no telemetry backend available".into())
}

// ──────────────────── helper: run trace twice, verify determinism ────────────────────

/// Run a closure that drives a harness, return its trace digest.
fn run_and_digest(f: impl Fn(&mut DashboardHarness)) -> String {
    let mut h = DashboardHarness::default();
    f(&mut h);
    h.trace_digest()
}

/// Assert that running the same trace function twice yields identical digests.
fn assert_deterministic(f: impl Fn(&mut DashboardHarness)) {
    let d1 = run_and_digest(&f);
    let d2 = run_and_digest(&f);
    assert_eq!(d1, d2, "trace digest mismatch: reducer is non-deterministic");
}

// ══════════════════════════════════════════════════════════════
//  Scenario 1: Pressure escalation (green → yellow → red)
// ══════════════════════════════════════════════════════════════

#[test]
fn replay_pressure_escalation_green_to_red() {
    let mut h = DashboardHarness::default();

    // Phase 1: startup with healthy (green) state.
    h.startup_with_state(sample_healthy_state());
    assert!(!h.is_degraded());
    assert_eq!(h.screen(), Screen::Overview);

    let frame = h.last_frame();
    assert!(frame.text.contains("GREEN"), "expected GREEN level in overview");

    // Phase 2: pressure rises to yellow.
    h.feed_state(yellow_pressure_state());
    h.tick();
    let frame = h.last_frame();
    assert!(
        frame.text.contains("YELLOW"),
        "expected YELLOW level after pressure rise"
    );

    // Phase 3: pressure escalates to red.
    h.feed_state(red_critical_state());
    h.tick();
    let frame = h.last_frame();
    assert!(
        frame.text.contains("RED"),
        "expected RED level after critical pressure"
    );

    // Model invariants.
    let model = h.model_mut();
    assert!(model.daemon_state.is_some());
    let state = model.daemon_state.as_ref().unwrap();
    assert_eq!(state.pressure.overall, "red");
    assert_eq!(state.ballast.available, 1);
    assert!(!model.degraded);
}

#[test]
fn replay_pressure_escalation_is_deterministic() {
    assert_deterministic(|h| {
        h.startup_with_state(sample_healthy_state());
        h.feed_state(yellow_pressure_state());
        h.tick();
        h.feed_state(red_critical_state());
        h.tick();
    });
}

// ══════════════════════════════════════════════════════════════
//  Scenario 2: Pressure recovery (red → green)
// ══════════════════════════════════════════════════════════════

#[test]
fn replay_pressure_recovery() {
    let mut h = DashboardHarness::default();

    // Start in red.
    h.startup_with_state(red_critical_state());
    let frame = h.last_frame();
    assert!(frame.text.contains("RED"));

    // Recover to green.
    h.feed_state(recovery_state());
    h.tick();
    let frame = h.last_frame();
    assert!(
        frame.text.contains("GREEN"),
        "expected GREEN after recovery"
    );

    let model = h.model_mut();
    let state = model.daemon_state.as_ref().unwrap();
    assert_eq!(state.pressure.overall, "green");
    assert_eq!(state.ballast.available, 10);
    assert_eq!(state.ballast.released, 0);
}

#[test]
fn replay_pressure_recovery_is_deterministic() {
    assert_deterministic(|h| {
        h.startup_with_state(red_critical_state());
        h.feed_state(recovery_state());
        h.tick();
    });
}

// ══════════════════════════════════════════════════════════════
//  Scenario 3: Degraded lifecycle (healthy → unavailable → recovery)
// ══════════════════════════════════════════════════════════════

#[test]
fn replay_degraded_lifecycle() {
    let mut h = DashboardHarness::default();

    // Starts degraded (no data yet).
    assert!(h.is_degraded());

    // Feed healthy data — clears degraded.
    h.startup_with_state(sample_healthy_state());
    assert!(!h.is_degraded());

    // Daemon becomes unreachable.
    h.feed_unavailable();
    assert!(h.is_degraded());
    let frame = h.last_frame();
    assert!(
        frame.text.contains("DEGRADED"),
        "expected DEGRADED badge when daemon unreachable"
    );

    // Daemon recovers.
    h.feed_state(sample_healthy_state());
    assert!(!h.is_degraded());
    let frame = h.last_frame();
    assert!(
        !frame.text.contains("DEGRADED"),
        "DEGRADED should clear on recovery"
    );

    // Verify adapter counters reflect the transitions.
    let model = h.model_mut();
    // startup_with_state = tick + feed(Some) + tick → 1 read
    // feed_unavailable → 1 error
    // feed_state(healthy) → 1 read
    assert_eq!(model.adapter_reads, 2);
    assert_eq!(model.adapter_errors, 1);
}

#[test]
fn replay_degraded_lifecycle_is_deterministic() {
    assert_deterministic(|h| {
        h.startup_with_state(sample_healthy_state());
        h.feed_unavailable();
        h.feed_state(sample_healthy_state());
    });
}

// ══════════════════════════════════════════════════════════════
//  Scenario 4: Degraded telemetry (partial data)
// ══════════════════════════════════════════════════════════════

#[test]
fn replay_degraded_telemetry() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());

    // Navigate to Timeline (S2).
    h.navigate_to_number(2);
    assert_eq!(h.screen(), Screen::Timeline);

    // Inject partial timeline data via schema-shield fallback.
    let events = sample_timeline_events();
    let event_count = events.len();
    h.inject_msg(DashboardMsg::TelemetryTimeline(partial_timeline_result(
        events,
    )));

    let model = h.model_mut();
    assert_eq!(model.timeline_events.len(), event_count);
    assert!(model.timeline_partial);
    assert_eq!(model.timeline_source, DataSource::Jsonl);
    assert!(model.timeline_diagnostics.contains("schema-shield"));

    // Now inject healthy data — should clear partial flag.
    let fresh_events = sample_timeline_events();
    h.inject_msg(DashboardMsg::TelemetryTimeline(timeline_result(
        fresh_events,
    )));

    let model = h.model_mut();
    assert!(!model.timeline_partial);
    assert_eq!(model.timeline_source, DataSource::Sqlite);
    assert!(model.timeline_diagnostics.is_empty());
}

#[test]
fn replay_unavailable_telemetry() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());

    // Navigate to Explainability (S3).
    h.navigate_to_number(3);
    assert_eq!(h.screen(), Screen::Explainability);

    // Inject unavailable decisions.
    h.inject_msg(DashboardMsg::TelemetryDecisions(unavailable_decisions()));

    let model = h.model_mut();
    assert!(model.explainability_decisions.is_empty());
    assert!(model.explainability_partial);
    assert_eq!(model.explainability_source, DataSource::None);
    assert!(
        model
            .explainability_diagnostics
            .contains("no telemetry backend")
    );
}

// ══════════════════════════════════════════════════════════════
//  Scenario 5: Ballast depletion and replenish
// ══════════════════════════════════════════════════════════════

#[test]
fn replay_ballast_depletion_and_replenish() {
    let mut h = DashboardHarness::default();

    // Start with full ballast.
    h.startup_with_state(sample_healthy_state());
    let model = h.model_mut();
    let state = model.daemon_state.as_ref().unwrap();
    assert_eq!(state.ballast.available, 10);
    assert_eq!(state.ballast.released, 0);

    // Pressure rises, ballast partially released.
    h.feed_state(yellow_pressure_state());
    let model = h.model_mut();
    let state = model.daemon_state.as_ref().unwrap();
    assert_eq!(state.ballast.available, 8);
    assert_eq!(state.ballast.released, 2);

    // Ballast fully depleted under extreme pressure.
    h.feed_state(ballast_depleted_state());
    let model = h.model_mut();
    let state = model.daemon_state.as_ref().unwrap();
    assert_eq!(state.ballast.available, 0);
    assert_eq!(state.ballast.released, 10);

    // Recovery — ballast replenished.
    h.feed_state(recovery_state());
    let model = h.model_mut();
    let state = model.daemon_state.as_ref().unwrap();
    assert_eq!(state.ballast.available, 10);
    assert_eq!(state.ballast.released, 0);
}

#[test]
fn replay_ballast_cycle_is_deterministic() {
    assert_deterministic(|h| {
        h.startup_with_state(sample_healthy_state());
        h.feed_state(yellow_pressure_state());
        h.feed_state(ballast_depleted_state());
        h.feed_state(recovery_state());
    });
}

// ══════════════════════════════════════════════════════════════
//  Scenario 6: Multi-mount pressure divergence
// ══════════════════════════════════════════════════════════════

#[test]
fn replay_multi_mount_pressure_divergence() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(multi_mount_divergent_state());

    let frame = h.last_frame();
    // Both mounts should appear in rendered output.
    assert!(frame.text.contains("/data"), "missing /data mount");
    assert!(frame.text.contains("RED"), "missing RED level for /data");
    assert!(frame.text.contains("GREEN"), "missing GREEN level for /");

    // Rate histories should be populated for both mounts.
    let model = h.model_mut();
    assert!(
        model.rate_histories.contains_key("/data"),
        "missing rate history for /data"
    );
    assert!(
        model.rate_histories.contains_key("/"),
        "missing rate history for /"
    );
}

#[test]
fn replay_multi_mount_rate_accumulation() {
    let mut h = DashboardHarness::default();

    // Feed the same multi-mount state 5 times to build up rate history.
    h.tick();
    for _ in 0..5 {
        h.feed_state(multi_mount_divergent_state());
        h.tick();
    }

    let model = h.model_mut();
    let data_history = model.rate_histories.get("/data").unwrap();
    assert_eq!(data_history.len(), 5, "expected 5 rate samples for /data");

    let root_history = model.rate_histories.get("/").unwrap();
    assert_eq!(root_history.len(), 5, "expected 5 rate samples for /");
}

// ══════════════════════════════════════════════════════════════
//  Scenario 7: Policy mode transitions (observe → canary → enforce)
// ══════════════════════════════════════════════════════════════

#[test]
fn replay_policy_mode_transitions() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());

    // Navigate to Explainability (S3).
    h.navigate_to_number(3);

    // Phase 1: observe-mode decisions.
    h.inject_msg(DashboardMsg::TelemetryDecisions(decisions_result(
        observe_mode_decisions(),
    )));
    let model = h.model_mut();
    assert_eq!(model.explainability_decisions.len(), 1);
    assert_eq!(model.explainability_decisions[0].policy_mode, "observe");

    // Phase 2: canary-mode decisions replace observe.
    h.inject_msg(DashboardMsg::TelemetryDecisions(decisions_result(
        canary_mode_decisions(),
    )));
    let model = h.model_mut();
    assert_eq!(model.explainability_decisions.len(), 1);
    assert_eq!(model.explainability_decisions[0].policy_mode, "canary");

    // Phase 3: enforce-mode decisions.
    h.inject_msg(DashboardMsg::TelemetryDecisions(decisions_result(
        sample_decisions(),
    )));
    let model = h.model_mut();
    assert_eq!(model.explainability_decisions.len(), 2);
    assert_eq!(model.explainability_decisions[0].policy_mode, "enforce");
    assert_eq!(model.explainability_decisions[1].policy_mode, "enforce");
}

// ══════════════════════════════════════════════════════════════
//  Scenario 8: Timeline filter cycle and cursor movement
// ══════════════════════════════════════════════════════════════

#[test]
fn replay_timeline_filter_cycle() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());
    h.navigate_to_number(2); // Timeline

    // Inject events with mixed severities.
    h.inject_msg(DashboardMsg::TelemetryTimeline(timeline_result(
        sample_timeline_events(),
    )));

    // Default filter: All — sees all 3 events.
    let model = h.model_mut();
    assert_eq!(model.timeline_events.len(), 3);
    let all_count = model.timeline_filtered_events().len();
    assert_eq!(all_count, 3, "All filter should show all events");

    // Cycle to Info filter — only 1 info event.
    h.inject_char('f');
    let model = h.model_mut();
    let info_count = model.timeline_filtered_events().len();
    assert_eq!(info_count, 1, "Info filter should show 1 event");

    // Cycle to Warning filter — only 1 warning event.
    h.inject_char('f');
    let model = h.model_mut();
    let warning_count = model.timeline_filtered_events().len();
    assert_eq!(warning_count, 1, "Warning filter should show 1 event");

    // Cycle to Critical filter — only 1 critical event.
    h.inject_char('f');
    let model = h.model_mut();
    let critical_count = model.timeline_filtered_events().len();
    assert_eq!(critical_count, 1, "Critical filter should show 1 event");

    // Cycle back to All.
    h.inject_char('f');
    let model = h.model_mut();
    let all_again = model.timeline_filtered_events().len();
    assert_eq!(all_again, 3, "All filter should show all events again");
}

#[test]
fn replay_timeline_cursor_movement() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());
    h.navigate_to_number(2);

    h.inject_msg(DashboardMsg::TelemetryTimeline(timeline_result(
        sample_timeline_events(),
    )));

    // Cursor starts at 0 (or clamped to last if follow mode).
    let model = h.model_mut();
    // Follow mode defaults to true, so cursor should be at last event.
    let expected_initial = model.timeline_filtered_events().len() - 1;
    assert_eq!(model.timeline_selected, expected_initial);

    // Move cursor up with 'k'.
    h.inject_char('k');
    let model = h.model_mut();
    assert_eq!(
        model.timeline_selected,
        expected_initial.saturating_sub(1),
        "k should move cursor up"
    );
}

#[test]
fn replay_timeline_follow_mode() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());
    h.navigate_to_number(2);

    // Inject initial events — follow mode should put cursor at end.
    let events = sample_timeline_events();
    h.inject_msg(DashboardMsg::TelemetryTimeline(timeline_result(
        events.clone(),
    )));

    let model = h.model_mut();
    assert!(model.timeline_follow, "follow should default to true");
    assert_eq!(model.timeline_selected, 2, "cursor at last event (idx 2)");

    // Disable follow with 'F'.
    h.inject_char('F');
    let model = h.model_mut();
    assert!(!model.timeline_follow, "F should toggle follow off");

    // New data arrives — cursor should NOT jump to end.
    let mut more_events = events;
    more_events.push(TimelineEvent {
        timestamp: "2026-02-16T01:15:00Z".into(),
        event_type: "ballast_release".into(),
        severity: "info".into(),
        path: None,
        size_bytes: None,
        score: None,
        pressure_level: Some("red".into()),
        free_pct: Some(3.0),
        success: Some(true),
        error_code: None,
        error_message: None,
        duration_ms: None,
        details: Some("released 1 ballast file".into()),
    });
    h.inject_msg(DashboardMsg::TelemetryTimeline(timeline_result(
        more_events,
    )));

    let model = h.model_mut();
    assert_eq!(
        model.timeline_selected, 2,
        "cursor should stay at 2 with follow off"
    );
}

// ══════════════════════════════════════════════════════════════
//  Scenario 9: Full operator workflow
// ══════════════════════════════════════════════════════════════

#[test]
fn replay_full_operator_workflow() {
    let mut h = DashboardHarness::default();

    // Step 1: Startup.
    h.startup_with_state(sample_healthy_state());
    assert_eq!(h.screen(), Screen::Overview);
    assert!(!h.is_degraded());

    // Step 2: Navigate all 7 screens.
    for n in 1..=7u8 {
        h.navigate_to_number(n);
        assert_eq!(
            h.screen().number(),
            n,
            "expected screen {n} after key press"
        );
    }

    // Step 3: Back to overview via history.
    h.navigate_to_number(1);
    assert_eq!(h.screen(), Screen::Overview);

    // Step 4: Inject pressure transition.
    h.feed_state(yellow_pressure_state());
    h.tick();

    // Step 5: Open and close help overlay.
    h.open_help();
    assert!(h.overlay().is_some());
    h.inject_keycode(ftui_core::event::KeyCode::Escape);
    assert!(h.overlay().is_none());

    // Step 6: Navigate to timeline, inject events.
    h.navigate_to_number(2);
    h.inject_msg(DashboardMsg::TelemetryTimeline(timeline_result(
        sample_timeline_events(),
    )));

    // Step 7: Navigate to explainability, inject decisions.
    h.navigate_to_number(3);
    h.inject_msg(DashboardMsg::TelemetryDecisions(decisions_result(
        sample_decisions(),
    )));

    // Step 8: Inject error notification.
    h.inject_error("test error", "replay-suite");
    assert_eq!(h.notification_count(), 1);

    // Step 9: Quit.
    h.quit();
    assert!(h.is_quit());

    // Sanity: we accumulated many frames through the full workflow.
    assert!(
        h.frame_count() > 20,
        "expected >20 frames in full workflow, got {}",
        h.frame_count()
    );
}

#[test]
fn replay_full_operator_workflow_is_deterministic() {
    assert_deterministic(|h| {
        h.startup_with_state(sample_healthy_state());
        for n in 1..=7u8 {
            h.navigate_to_number(n);
        }
        h.navigate_to_number(1);
        h.feed_state(yellow_pressure_state());
        h.tick();
        h.open_help();
        h.inject_keycode(ftui_core::event::KeyCode::Escape);
        h.navigate_to_number(2);
        h.inject_msg(DashboardMsg::TelemetryTimeline(timeline_result(
            sample_timeline_events(),
        )));
        h.navigate_to_number(3);
        h.inject_msg(DashboardMsg::TelemetryDecisions(decisions_result(
            sample_decisions(),
        )));
        h.inject_error("test error", "replay-suite");
        h.quit();
    });
}

// ══════════════════════════════════════════════════════════════
//  Scenario 10: Candidates screen replay with sort cycling
// ══════════════════════════════════════════════════════════════

#[test]
fn replay_candidates_sort_cycle() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());
    h.navigate_to_number(4); // Candidates (S4)

    // Inject candidate data.
    h.inject_msg(DashboardMsg::TelemetryCandidates(decisions_result(
        sample_decisions(),
    )));

    let model = h.model_mut();
    assert_eq!(model.candidates_list.len(), 2);

    // Cycle sort: Score → Size → Age → Path → Score.
    h.inject_char('s'); // Size
    h.inject_char('s'); // Age
    h.inject_char('s'); // Path
    h.inject_char('s'); // Back to Score

    // Cursor navigation.
    h.inject_char('j'); // Down
    let model = h.model_mut();
    assert_eq!(model.candidates_selected, 1, "j moves cursor down");

    h.inject_char('k'); // Up
    let model = h.model_mut();
    assert_eq!(model.candidates_selected, 0, "k moves cursor up");
}

// ══════════════════════════════════════════════════════════════
//  Scenario 11: Error injection and notification lifecycle
// ══════════════════════════════════════════════════════════════

#[test]
fn replay_error_notification_lifecycle() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());

    // Inject 3 errors (max visible).
    h.inject_error("error 1", "adapter");
    h.inject_error("error 2", "telemetry");
    h.inject_error("error 3", "runtime");
    assert_eq!(h.notification_count(), 3);

    // Expire the first notification.
    h.inject_msg(DashboardMsg::NotificationExpired(0));
    assert_eq!(h.notification_count(), 2);

    // Expire all remaining.
    h.inject_msg(DashboardMsg::NotificationExpired(1));
    h.inject_msg(DashboardMsg::NotificationExpired(2));
    assert_eq!(h.notification_count(), 0);
}

// ══════════════════════════════════════════════════════════════
//  Scenario 12: Frame metrics injection (diagnostics screen)
// ══════════════════════════════════════════════════════════════

#[test]
fn replay_frame_metrics_accumulation() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());
    h.navigate_to_number(7); // Diagnostics

    // Inject frame metrics.
    for ms in [16.0, 18.0, 14.0, 20.0, 15.0] {
        h.inject_msg(DashboardMsg::FrameMetrics { duration_ms: ms });
    }

    let model = h.model_mut();
    assert_eq!(model.frame_times.len(), 5);
    let stats = model.frame_times.stats().unwrap();
    assert!((stats.0 - 15.0).abs() < f64::EPSILON, "latest should be 15.0");
    assert!((stats.2 - 14.0).abs() < f64::EPSILON, "min should be 14.0");
    assert!((stats.3 - 20.0).abs() < f64::EPSILON, "max should be 20.0");
}

// ══════════════════════════════════════════════════════════════
//  Scenario 13: Resize during active session
// ══════════════════════════════════════════════════════════════

#[test]
fn replay_resize_preserves_state() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());
    h.navigate_to_number(3);

    h.inject_msg(DashboardMsg::TelemetryDecisions(decisions_result(
        sample_decisions(),
    )));

    // Resize terminal.
    h.resize(80, 24);

    // State should be preserved after resize.
    let model = h.model_mut();
    assert_eq!(model.screen, Screen::Explainability);
    assert_eq!(model.terminal_size, (80, 24));
    assert_eq!(model.explainability_decisions.len(), 2);
    assert!(!model.degraded);
}

// ══════════════════════════════════════════════════════════════
//  Fixture compatibility: all builders produce valid serde roundtrips
// ══════════════════════════════════════════════════════════════

#[test]
fn fixture_compatibility_daemon_states() {
    let states = [
        ("healthy", sample_healthy_state()),
        ("pressured", sample_pressured_state()),
        ("yellow", yellow_pressure_state()),
        ("red_critical", red_critical_state()),
        ("recovery", recovery_state()),
        ("ballast_depleted", ballast_depleted_state()),
        ("multi_mount", multi_mount_divergent_state()),
    ];

    for (name, state) in &states {
        let json = serde_json::to_string(state).unwrap_or_else(|e| {
            panic!("fixture {name} failed to serialize: {e}");
        });
        let roundtrip: DaemonState = serde_json::from_str(&json).unwrap_or_else(|e| {
            panic!("fixture {name} failed to deserialize: {e}");
        });
        assert_eq!(
            roundtrip.version, state.version,
            "fixture {name} serde roundtrip version mismatch"
        );
        assert_eq!(
            roundtrip.pid, state.pid,
            "fixture {name} serde roundtrip pid mismatch"
        );
        assert_eq!(
            roundtrip.pressure.overall, state.pressure.overall,
            "fixture {name} serde roundtrip pressure mismatch"
        );
    }
}

#[test]
fn fixture_compatibility_telemetry() {
    // Timeline events.
    let events = sample_timeline_events();
    let json = serde_json::to_string(&events).unwrap();
    let roundtrip: Vec<TimelineEvent> = serde_json::from_str(&json).unwrap();
    assert_eq!(roundtrip.len(), events.len());

    // Decision evidence.
    let decisions = sample_decisions();
    let json = serde_json::to_string(&decisions).unwrap();
    let roundtrip: Vec<DecisionEvidence> = serde_json::from_str(&json).unwrap();
    assert_eq!(roundtrip.len(), decisions.len());

    // Observe mode.
    let observe = observe_mode_decisions();
    let json = serde_json::to_string(&observe).unwrap();
    let roundtrip: Vec<DecisionEvidence> = serde_json::from_str(&json).unwrap();
    assert_eq!(roundtrip[0].policy_mode, "observe");

    // Canary mode.
    let canary = canary_mode_decisions();
    let json = serde_json::to_string(&canary).unwrap();
    let roundtrip: Vec<DecisionEvidence> = serde_json::from_str(&json).unwrap();
    assert_eq!(roundtrip[0].policy_mode, "canary");
}

// ══════════════════════════════════════════════════════════════
//  Scenario 14: Scripted replay via HarnessStep (run_script)
// ══════════════════════════════════════════════════════════════

#[test]
fn replay_scripted_sequence_via_run_script() {
    let script = vec![
        HarnessStep::Tick,
        HarnessStep::FeedHealthyState,
        HarnessStep::Tick,
        HarnessStep::Char('2'),              // Navigate to Timeline
        HarnessStep::Char('['),              // Prev → Overview
        HarnessStep::FeedPressuredState,     // Pressure spike
        HarnessStep::Tick,
        HarnessStep::Char('5'),              // Navigate to Ballast
        HarnessStep::FeedHealthyState,       // Recovery
        HarnessStep::Tick,
        HarnessStep::Error {
            message: "scripted error".into(),
            source: "test".into(),
        },
    ];

    let mut h = DashboardHarness::default();
    h.run_script(&script);

    assert_eq!(h.screen(), Screen::Ballast);
    assert!(!h.is_degraded());
    assert_eq!(h.notification_count(), 1);
    assert!(h.frame_count() > 10);
}

#[test]
fn replay_scripted_sequence_is_deterministic() {
    let script = vec![
        HarnessStep::Tick,
        HarnessStep::FeedHealthyState,
        HarnessStep::Tick,
        HarnessStep::Char('2'),
        HarnessStep::Char('['),
        HarnessStep::FeedPressuredState,
        HarnessStep::Tick,
        HarnessStep::Char('5'),
        HarnessStep::FeedHealthyState,
        HarnessStep::Tick,
        HarnessStep::Error {
            message: "scripted error".into(),
            source: "test".into(),
        },
    ];

    let d1 = {
        let mut h = DashboardHarness::default();
        h.run_script(&script);
        h.trace_digest()
    };
    let d2 = {
        let mut h = DashboardHarness::default();
        h.run_script(&script);
        h.trace_digest()
    };
    assert_eq!(d1, d2, "scripted replay must be deterministic");
}

// ══════════════════════════════════════════════════════════════
//  Scenario 15: Stale mount pruning in rate histories
// ══════════════════════════════════════════════════════════════

#[test]
fn replay_stale_mount_pruned_from_rate_histories() {
    let mut h = DashboardHarness::default();

    // Feed multi-mount state — populates rate histories for / and /data.
    h.tick();
    h.feed_state(multi_mount_divergent_state());
    h.tick();

    let model = h.model_mut();
    assert!(model.rate_histories.contains_key("/"));
    assert!(model.rate_histories.contains_key("/data"));

    // Feed single-mount state — only /data remains.
    h.feed_state(sample_healthy_state());
    h.tick();

    let model = h.model_mut();
    assert!(
        model.rate_histories.contains_key("/data"),
        "/data should still have history"
    );
    // Stale mount "/" should be pruned.
    assert!(
        !model.rate_histories.contains_key("/"),
        "/ should be pruned when no longer in state"
    );
}
