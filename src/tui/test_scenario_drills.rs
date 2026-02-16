//! Scenario-driven e2e drills for cross-component dashboard regression detection (bd-xzt.4.8).
//!
//! Each drill simulates a realistic multi-step operator workflow that exercises
//! monitor → control → scanner → logging → dashboard integration. Every drill
//! produces structured [`ArtifactCollector`] output with frame captures at
//! assertion points, making failure post-mortems straightforward.
//!
//! **Key differences from `test_replay.rs`:**
//! - Multi-phase operator workflows across multiple screens
//! - Artifact capture at every assertion point for post-mortem use
//! - Cross-component integration: telemetry + daemon state + incident actions
//! - Incident playbook and quick-release workflow coverage
//! - Determinism verification for CI stability

#![allow(clippy::too_many_lines)]

use super::e2e_artifact::{
    ArtifactCollector, AssertionRecord, CaseStatus, DiagnosticEntry, FrameCapture,
};
use super::model::{BallastVolume, DashboardMsg, Overlay, Screen};
use super::telemetry::{
    DataSource, DecisionEvidence, FactorBreakdown, TelemetryResult, TimelineEvent,
};
use super::test_harness::{DashboardHarness, sample_healthy_state};
use crate::daemon::self_monitor::{
    BallastState, Counters, DaemonState, LastScanState, MountPressure, PressureState,
};

// ──────────────────── daemon state fixtures ────────────────────

/// Yellow pressure — disk filling, partial ballast release.
fn yellow_state() -> DaemonState {
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
        policy_mode: "enforce".into(),
        memory_rss_bytes: 48_000_000,
    }
}

/// Red critical — almost out of space.
fn red_state() -> DaemonState {
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
        policy_mode: "enforce".into(),
        memory_rss_bytes: 72_000_000,
    }
}

/// Recovery — green again, ballast replenished.
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
        policy_mode: "enforce".into(),
        memory_rss_bytes: 40_000_000,
    }
}

/// Ballast fully depleted — emergency territory.
fn depleted_state() -> DaemonState {
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
        policy_mode: "enforce".into(),
        memory_rss_bytes: 80_000_000,
    }
}

/// Multi-mount: / green, /data red — divergent pressure.
fn multi_mount_state() -> DaemonState {
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
        policy_mode: "enforce".into(),
        memory_rss_bytes: 52_000_000,
    }
}

// ──────────────────── telemetry fixtures ────────────────────

/// Pressure escalation timeline: green → yellow → red.
fn escalation_timeline() -> Vec<TimelineEvent> {
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
            details: Some("pressure rose to yellow on /data".into()),
        },
        TimelineEvent {
            timestamp: "2026-02-16T01:05:00Z".into(),
            event_type: "artifact_delete".into(),
            severity: "info".into(),
            path: Some("/data/project-alpha/target/debug".into()),
            size_bytes: Some(2_000_000_000),
            score: Some(0.95),
            pressure_level: Some("yellow".into()),
            free_pct: Some(14.0),
            success: Some(true),
            error_code: None,
            error_message: None,
            duration_ms: Some(150),
            details: Some("deleted build artifact, 2.0 GB freed".into()),
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
        TimelineEvent {
            timestamp: "2026-02-16T01:12:00Z".into(),
            event_type: "ballast_release".into(),
            severity: "info".into(),
            path: Some("/data/.sbh-ballast/ballast_007.bin".into()),
            size_bytes: Some(1_073_741_824),
            score: None,
            pressure_level: Some("red".into()),
            free_pct: Some(3.5),
            success: Some(true),
            error_code: None,
            error_message: None,
            duration_ms: Some(5),
            details: Some("released ballast file, 1.0 GiB freed".into()),
        },
    ]
}

/// High-confidence enforce-mode decisions.
fn enforce_decisions() -> Vec<DecisionEvidence> {
    vec![
        DecisionEvidence {
            decision_id: 1,
            timestamp: "2026-02-16T01:05:00Z".into(),
            path: "/data/project-alpha/target/debug".into(),
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
            summary: "High confidence: stale build artifact".into(),
            raw_json: None,
        },
        DecisionEvidence {
            decision_id: 2,
            timestamp: "2026-02-16T01:06:00Z".into(),
            path: "/data/agent-workspace/.cache".into(),
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
            summary: "Protected: active workspace".into(),
            raw_json: None,
        },
        DecisionEvidence {
            decision_id: 3,
            timestamp: "2026-02-16T01:08:00Z".into(),
            path: "/data/project-beta/target/release".into(),
            size_bytes: 3_000_000_000,
            age_secs: 172_800,
            action: "delete".into(),
            effective_action: Some("delete".into()),
            policy_mode: "enforce".into(),
            factors: FactorBreakdown {
                location: 0.85,
                name: 0.75,
                age: 0.9,
                size: 0.98,
                structure: 0.9,
                pressure_multiplier: 1.3,
            },
            total_score: 0.97,
            posterior_abandoned: 0.95,
            expected_loss_keep: 6.0,
            expected_loss_delete: 0.2,
            calibration_score: 0.90,
            vetoed: false,
            veto_reason: None,
            guard_status: Some("pass".into()),
            summary: "Very high confidence: 2-day-old release build".into(),
            raw_json: None,
        },
    ]
}

/// Observe-mode shadow decisions for audit trail.
fn observe_decisions() -> Vec<DecisionEvidence> {
    vec![DecisionEvidence {
        decision_id: 10,
        timestamp: "2026-02-16T01:00:00Z".into(),
        path: "/data/old-target".into(),
        size_bytes: 1_000_000_000,
        age_secs: 172_800,
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

/// Ballast volumes for multi-mount scenario.
fn multi_mount_volumes() -> Vec<BallastVolume> {
    vec![
        BallastVolume {
            mount_point: "/".into(),
            ballast_dir: "/.sbh-ballast".into(),
            fs_type: "ext4".into(),
            strategy: "fallocate".into(),
            files_available: 5,
            files_total: 5,
            releasable_bytes: 5_368_709_120,
            skipped: false,
            skip_reason: None,
        },
        BallastVolume {
            mount_point: "/data".into(),
            ballast_dir: "/data/.sbh-ballast".into(),
            fs_type: "ext4".into(),
            strategy: "fallocate".into(),
            files_available: 1,
            files_total: 5,
            releasable_bytes: 1_073_741_824,
            skipped: false,
            skip_reason: None,
        },
    ]
}

/// Depleted ballast volumes.
fn depleted_volumes() -> Vec<BallastVolume> {
    vec![BallastVolume {
        mount_point: "/data".into(),
        ballast_dir: "/data/.sbh-ballast".into(),
        fs_type: "ext4".into(),
        strategy: "fallocate".into(),
        files_available: 0,
        files_total: 10,
        releasable_bytes: 0,
        skipped: false,
        skip_reason: None,
    }]
}

// ──────────────────── telemetry helpers ────────────────────

fn timeline_result(events: Vec<TimelineEvent>) -> TelemetryResult<Vec<TimelineEvent>> {
    TelemetryResult {
        data: events,
        source: DataSource::Sqlite,
        partial: false,
        diagnostics: String::new(),
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

fn ballast_result(volumes: Vec<BallastVolume>) -> TelemetryResult<Vec<BallastVolume>> {
    TelemetryResult {
        data: volumes,
        source: DataSource::Sqlite,
        partial: false,
        diagnostics: String::new(),
    }
}

fn partial_timeline(events: Vec<TimelineEvent>) -> TelemetryResult<Vec<TimelineEvent>> {
    TelemetryResult {
        data: events,
        source: DataSource::Jsonl,
        partial: true,
        diagnostics: "schema-shield recovered=2 dropped=1".into(),
    }
}

// ──────────────────── frame capture helper ────────────────────

fn capture_frame(h: &DashboardHarness) -> FrameCapture {
    let frame = h.last_frame();
    FrameCapture {
        tick: h.tick_count(),
        screen: format!("{:?}", frame.screen),
        overlay: frame.overlay.as_ref().map(|o| format!("{o:?}")),
        degraded: frame.degraded,
        last_cmd: Some(frame.last_cmd_debug.clone()),
        text: frame.text.clone(),
    }
}

/// Convenience: convert any displayable value to `Option<String>` for assertion `actual` field.
#[allow(clippy::unnecessary_wraps)]
fn s<T: std::fmt::Display + ?Sized>(val: &T) -> Option<String> {
    Some(val.to_string())
}

#[allow(dead_code)]
fn assert_record(
    label: &str,
    passed: bool,
    expected: &str,
    actual: Option<&str>,
) -> AssertionRecord {
    AssertionRecord {
        label: label.into(),
        passed,
        expected: expected.into(),
        actual: actual.map(String::from),
        location: None,
    }
}

// ══════════════════════════════════════════════════════════════
//  Drill 1: Pressure Escalation Triage
//  Simulates: operator sees green → yellow → red, navigates
//  timeline and overview, verifies cross-screen state coherence.
// ══════════════════════════════════════════════════════════════

#[test]
fn drill_pressure_escalation_triage() {
    let mut collector =
        ArtifactCollector::new("scenario-drills").with_run_id("drill-pressure-escalation");

    let mut h = DashboardHarness::default();

    // Phase 1: Green startup.
    h.startup_with_state(sample_healthy_state());
    let frame = h.last_frame();
    let green_ok = frame.text.contains("GREEN");
    assert!(green_ok, "overview should show GREEN at startup");

    collector
        .start_case("phase1_green_startup")
        .section("pressure_escalation")
        .tags(["pressure", "startup"])
        .frame(capture_frame(&h))
        .assertion("overview shows GREEN", green_ok, "GREEN in frame", None)
        .status(CaseStatus::Pass)
        .finish();

    // Phase 2: Yellow pressure — check timeline for warning.
    h.feed_state(yellow_state());
    h.tick();

    let frame = h.last_frame();
    let yellow_ok = frame.text.contains("YELLOW");
    assert!(yellow_ok, "overview should show YELLOW");

    // Navigate to timeline.
    h.navigate_to_number(2);
    assert_eq!(h.screen(), Screen::Timeline);

    // Inject escalation timeline.
    h.inject_msg(DashboardMsg::TelemetryTimeline(timeline_result(
        escalation_timeline(),
    )));

    let model = h.model_mut();
    let timeline_count = model.timeline_events.len();
    assert_eq!(timeline_count, 4);

    collector
        .start_case("phase2_yellow_with_timeline")
        .section("pressure_escalation")
        .tags(["pressure", "timeline", "yellow"])
        .frame(capture_frame(&h))
        .assertion("overview shows YELLOW", yellow_ok, "YELLOW in frame", None)
        .assertion(
            "timeline has 4 events",
            timeline_count == 4,
            "4",
            s(&timeline_count),
        )
        .assertion(
            "on timeline screen",
            h.screen() == Screen::Timeline,
            "Timeline",
            s(&format!("{:?}", h.screen())),
        )
        .status(CaseStatus::Pass)
        .finish();

    // Phase 3: Red escalation — return to overview.
    h.feed_state(red_state());
    h.tick();
    h.navigate_to_number(1);
    assert_eq!(h.screen(), Screen::Overview);

    let frame = h.last_frame();
    let red_ok = frame.text.contains("RED");
    assert!(red_ok, "overview should show RED after escalation");

    // Verify ballast depletion reflected in overview.
    let model = h.model_mut();
    let state = model.daemon_state.as_ref().unwrap();
    let ballast_available = state.ballast.available;
    assert_eq!(ballast_available, 1);

    collector
        .start_case("phase3_red_escalation")
        .section("pressure_escalation")
        .tags(["pressure", "red", "ballast"])
        .frame(capture_frame(&h))
        .assertion("overview shows RED", red_ok, "RED in frame", None)
        .assertion(
            "ballast nearly depleted",
            ballast_available == 1,
            "1",
            s(&ballast_available),
        )
        .status(CaseStatus::Pass)
        .finish();

    // Phase 4: Recovery.
    h.feed_state(recovery_state());
    h.tick();

    let frame = h.last_frame();
    let green_again = frame.text.contains("GREEN");
    assert!(green_again, "overview should show GREEN after recovery");

    let fc = capture_frame(&h);
    let model = h.model_mut();
    let state = model.daemon_state.as_ref().unwrap();
    let ballast_avail = state.ballast.available;
    assert_eq!(ballast_avail, 10);

    collector
        .start_case("phase4_recovery")
        .section("pressure_escalation")
        .tags(["pressure", "recovery", "green"])
        .frame(fc)
        .assertion("overview shows GREEN", green_again, "GREEN in frame", None)
        .assertion(
            "ballast fully replenished",
            ballast_avail == 10,
            "10",
            s(&ballast_avail),
        )
        .status(CaseStatus::Pass)
        .finish();

    let bundle = collector.finalize();
    assert_eq!(bundle.summary.passed, 4);
    assert_eq!(bundle.summary.failed, 0);

    // Verify artifact is serializable for post-mortem.
    let json = serde_json::to_string_pretty(&bundle).unwrap();
    assert!(json.contains("drill-pressure-escalation"));
    assert!(json.contains("pressure_escalation"));
}

#[test]
fn drill_pressure_escalation_is_deterministic() {
    let run = |h: &mut DashboardHarness| {
        h.startup_with_state(sample_healthy_state());
        h.feed_state(yellow_state());
        h.tick();
        h.navigate_to_number(2);
        h.inject_msg(DashboardMsg::TelemetryTimeline(timeline_result(
            escalation_timeline(),
        )));
        h.feed_state(red_state());
        h.tick();
        h.navigate_to_number(1);
        h.feed_state(recovery_state());
        h.tick();
    };

    let d1 = {
        let mut h = DashboardHarness::default();
        run(&mut h);
        h.trace_digest()
    };
    let d2 = {
        let mut h = DashboardHarness::default();
        run(&mut h);
        h.trace_digest()
    };
    assert_eq!(
        d1, d2,
        "pressure escalation triage drill must be deterministic"
    );
}

// ══════════════════════════════════════════════════════════════
//  Drill 2: Ballast Operations Under Pressure
//  Simulates: operator monitors ballast depletion, navigates
//  ballast screen, verifies volume status badges.
// ══════════════════════════════════════════════════════════════

#[test]
fn drill_ballast_operations_under_pressure() {
    let mut collector = ArtifactCollector::new("scenario-drills").with_run_id("drill-ballast-ops");

    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());

    // Phase 1: Navigate to ballast screen with full pool.
    h.navigate_to_number(5);
    assert_eq!(h.screen(), Screen::Ballast);

    // Inject healthy ballast data.
    h.inject_msg(DashboardMsg::TelemetryBallast(ballast_result(vec![
        BallastVolume {
            mount_point: "/data".into(),
            ballast_dir: "/data/.sbh-ballast".into(),
            fs_type: "ext4".into(),
            strategy: "fallocate".into(),
            files_available: 10,
            files_total: 10,
            releasable_bytes: 10_737_418_240,
            skipped: false,
            skip_reason: None,
        },
    ])));

    let model = h.model_mut();
    let vol_count = model.ballast_volumes.len();
    assert_eq!(vol_count, 1);
    let status = model.ballast_volumes[0].status_level();
    assert_eq!(status, "OK");

    collector
        .start_case("phase1_full_ballast")
        .section("ballast_operations")
        .tags(["ballast", "healthy"])
        .frame(capture_frame(&h))
        .assertion("1 volume loaded", vol_count == 1, "1", s(&vol_count))
        .assertion("status is OK", status == "OK", "OK", s(&status))
        .status(CaseStatus::Pass)
        .finish();

    // Phase 2: Pressure rises — ballast depleting.
    h.feed_state(yellow_state());
    h.tick();

    h.inject_msg(DashboardMsg::TelemetryBallast(ballast_result(vec![
        BallastVolume {
            mount_point: "/data".into(),
            ballast_dir: "/data/.sbh-ballast".into(),
            fs_type: "ext4".into(),
            strategy: "fallocate".into(),
            files_available: 3,
            files_total: 10,
            releasable_bytes: 3_221_225_472,
            skipped: false,
            skip_reason: None,
        },
    ])));

    let model = h.model_mut();
    let status = model.ballast_volumes[0].status_level();
    assert_eq!(status, "LOW");

    collector
        .start_case("phase2_ballast_depleting")
        .section("ballast_operations")
        .tags(["ballast", "pressure", "low"])
        .frame(capture_frame(&h))
        .assertion("status is LOW", status == "LOW", "LOW", s(&status))
        .status(CaseStatus::Pass)
        .finish();

    // Phase 3: Full depletion.
    h.feed_state(depleted_state());
    h.tick();
    h.inject_msg(DashboardMsg::TelemetryBallast(ballast_result(
        depleted_volumes(),
    )));

    let fc = capture_frame(&h);
    let model = h.model_mut();
    let status = model.ballast_volumes[0].status_level();
    let files_avail = model.ballast_volumes[0].files_available;
    assert_eq!(status, "CRITICAL");

    collector
        .start_case("phase3_ballast_critical")
        .section("ballast_operations")
        .tags(["ballast", "critical", "depleted"])
        .frame(fc)
        .assertion(
            "status is CRITICAL",
            status == "CRITICAL",
            "CRITICAL",
            s(&status),
        )
        .assertion("0 files available", files_avail == 0, "0", s(&files_avail))
        .status(CaseStatus::Pass)
        .finish();

    // Phase 4: Navigate to candidates screen to see what was deleted.
    h.navigate_to_number(4);
    assert_eq!(h.screen(), Screen::Candidates);

    h.inject_msg(DashboardMsg::TelemetryCandidates(decisions_result(
        enforce_decisions(),
    )));

    let model = h.model_mut();
    let candidate_count = model.candidates_list.len();
    assert_eq!(candidate_count, 3);

    // Sort by score — highest confidence first.
    let top_score = model.candidates_list[0].total_score;
    assert!(top_score > 0.9);

    collector
        .start_case("phase4_candidates_review")
        .section("ballast_operations")
        .tags(["candidates", "scoring"])
        .frame(capture_frame(&h))
        .assertion(
            "3 candidates loaded",
            candidate_count == 3,
            "3",
            s(&candidate_count),
        )
        .assertion(
            "top candidate score > 0.9",
            top_score > 0.9,
            "> 0.9",
            s(&format!("{top_score:.2}")),
        )
        .status(CaseStatus::Pass)
        .finish();

    // Phase 5: Recovery — back to ballast, verify replenish.
    h.feed_state(recovery_state());
    h.tick();
    h.navigate_to_number(5);

    h.inject_msg(DashboardMsg::TelemetryBallast(ballast_result(vec![
        BallastVolume {
            mount_point: "/data".into(),
            ballast_dir: "/data/.sbh-ballast".into(),
            fs_type: "ext4".into(),
            strategy: "fallocate".into(),
            files_available: 10,
            files_total: 10,
            releasable_bytes: 10_737_418_240,
            skipped: false,
            skip_reason: None,
        },
    ])));

    let model = h.model_mut();
    let status = model.ballast_volumes[0].status_level();
    assert_eq!(status, "OK");

    collector
        .start_case("phase5_ballast_recovery")
        .section("ballast_operations")
        .tags(["ballast", "recovery"])
        .frame(capture_frame(&h))
        .assertion("status restored to OK", status == "OK", "OK", s(&status))
        .status(CaseStatus::Pass)
        .finish();

    let bundle = collector.finalize();
    assert_eq!(bundle.summary.passed, 5);
    assert_eq!(bundle.summary.failed, 0);
}

#[test]
fn drill_ballast_operations_is_deterministic() {
    let run = |h: &mut DashboardHarness| {
        h.startup_with_state(sample_healthy_state());
        h.navigate_to_number(5);
        h.inject_msg(DashboardMsg::TelemetryBallast(ballast_result(
            depleted_volumes(),
        )));
        h.feed_state(depleted_state());
        h.tick();
        h.feed_state(recovery_state());
        h.tick();
    };

    let d1 = {
        let mut h = DashboardHarness::default();
        run(&mut h);
        h.trace_digest()
    };
    let d2 = {
        let mut h = DashboardHarness::default();
        run(&mut h);
        h.trace_digest()
    };
    assert_eq!(d1, d2, "ballast operations drill must be deterministic");
}

// ══════════════════════════════════════════════════════════════
//  Drill 3: Explainability Audit Trail
//  Simulates: operator examines decision evidence, verifies
//  veto reasons, factor breakdowns, and cross-references with
//  timeline events.
// ══════════════════════════════════════════════════════════════

#[test]
fn drill_explainability_audit_trail() {
    let mut collector =
        ArtifactCollector::new("scenario-drills").with_run_id("drill-explainability");

    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());

    // Phase 1: Navigate to explainability, load observe-mode decisions.
    h.navigate_to_number(3);
    assert_eq!(h.screen(), Screen::Explainability);

    h.inject_msg(DashboardMsg::TelemetryDecisions(decisions_result(
        observe_decisions(),
    )));

    let fc = capture_frame(&h);
    let model = h.model_mut();
    let dec_count = model.explainability_decisions.len();
    assert_eq!(dec_count, 1);
    let mode = model.explainability_decisions[0].policy_mode.clone();
    assert_eq!(mode, "observe");
    let effective = model.explainability_decisions[0]
        .effective_action
        .as_deref()
        .unwrap_or("")
        .to_owned();
    assert_eq!(effective, "observe");

    collector
        .start_case("phase1_observe_mode")
        .section("explainability")
        .tags(["explainability", "observe", "policy"])
        .frame(fc)
        .assertion("1 observe decision", dec_count == 1, "1", s(&dec_count))
        .assertion(
            "policy mode is observe",
            mode == "observe",
            "observe",
            s(&mode),
        )
        .assertion(
            "effective action is observe",
            effective == "observe",
            "observe",
            s(&effective),
        )
        .status(CaseStatus::Pass)
        .finish();

    // Phase 2: Transition to enforce-mode decisions.
    h.inject_msg(DashboardMsg::TelemetryDecisions(decisions_result(
        enforce_decisions(),
    )));

    let fc = capture_frame(&h);
    let model = h.model_mut();
    let dec_count = model.explainability_decisions.len();
    assert_eq!(dec_count, 3);

    // Verify veto is present.
    let vetoed_dec = model.explainability_decisions.iter().find(|d| d.vetoed);
    assert!(
        vetoed_dec.is_some(),
        "should have at least one vetoed decision"
    );
    let veto_reason = vetoed_dec
        .unwrap()
        .veto_reason
        .as_deref()
        .unwrap_or("")
        .to_string();
    assert!(
        veto_reason.contains("recently active"),
        "veto reason should explain why"
    );

    // Verify non-vetoed decisions have high confidence.
    let delete_count = model
        .explainability_decisions
        .iter()
        .filter(|d| !d.vetoed && d.action == "delete")
        .count();
    assert_eq!(delete_count, 2);
    for d in model
        .explainability_decisions
        .iter()
        .filter(|d| !d.vetoed && d.action == "delete")
    {
        assert!(
            d.total_score > 0.9,
            "delete decisions should have high confidence"
        );
    }
    let has_vetoed = vetoed_dec.is_some();

    collector
        .start_case("phase2_enforce_with_veto")
        .section("explainability")
        .tags(["explainability", "enforce", "veto"])
        .frame(fc)
        .assertion("3 enforce decisions", dec_count == 3, "3", s(&dec_count))
        .assertion("has vetoed decision", has_vetoed, "true", None)
        .assertion(
            "veto reason explains",
            veto_reason.contains("recently active"),
            "recently active",
            s(&veto_reason),
        )
        .assertion(
            "2 high-confidence deletes",
            delete_count == 2,
            "2",
            s(&delete_count),
        )
        .status(CaseStatus::Pass)
        .finish();

    // Phase 3: Cross-reference with timeline — navigate to timeline, verify
    // the same path appears in both views.
    h.navigate_to_number(2);
    assert_eq!(h.screen(), Screen::Timeline);

    h.inject_msg(DashboardMsg::TelemetryTimeline(timeline_result(
        escalation_timeline(),
    )));

    let model = h.model_mut();
    let timeline_paths: Vec<_> = model
        .timeline_events
        .iter()
        .filter_map(|e| e.path.as_deref())
        .collect();
    let decision_paths: Vec<_> = model
        .explainability_decisions
        .iter()
        .map(|d| d.path.as_str())
        .collect();

    // At least one path should appear in both timeline and decisions.
    let cross_referenced = timeline_paths.iter().any(|tp| decision_paths.contains(tp));
    assert!(
        cross_referenced,
        "at least one path should appear in both timeline and decisions"
    );

    collector
        .start_case("phase3_cross_reference")
        .section("explainability")
        .tags(["explainability", "timeline", "cross-reference"])
        .frame(capture_frame(&h))
        .assertion(
            "cross-referenced path exists",
            cross_referenced,
            "true",
            None,
        )
        .status(CaseStatus::Pass)
        .finish();

    // Phase 4: Factor breakdown inspection — navigate back to explainability,
    // expand detail on the top decision.
    h.navigate_to_number(3);
    h.inject_char('j'); // Move to first decision.
    h.inject_keycode(ftui_core::event::KeyCode::Enter); // Expand detail.

    let model = h.model_mut();
    let expanded = model.explainability_detail;
    assert!(expanded, "detail should be expanded after Enter");

    collector
        .start_case("phase4_factor_breakdown")
        .section("explainability")
        .tags(["explainability", "detail", "factors"])
        .frame(capture_frame(&h))
        .assertion("detail expanded", expanded, "true", s(&expanded))
        .status(CaseStatus::Pass)
        .finish();

    let bundle = collector.finalize();
    assert_eq!(bundle.summary.passed, 4);
    assert_eq!(bundle.summary.failed, 0);
}

#[test]
fn drill_explainability_audit_is_deterministic() {
    let run = |h: &mut DashboardHarness| {
        h.startup_with_state(sample_healthy_state());
        h.navigate_to_number(3);
        h.inject_msg(DashboardMsg::TelemetryDecisions(decisions_result(
            observe_decisions(),
        )));
        h.inject_msg(DashboardMsg::TelemetryDecisions(decisions_result(
            enforce_decisions(),
        )));
        h.navigate_to_number(2);
        h.inject_msg(DashboardMsg::TelemetryTimeline(timeline_result(
            escalation_timeline(),
        )));
        h.navigate_to_number(3);
        h.inject_char('j');
        h.inject_keycode(ftui_core::event::KeyCode::Enter);
    };

    let d1 = {
        let mut h = DashboardHarness::default();
        run(&mut h);
        h.trace_digest()
    };
    let d2 = {
        let mut h = DashboardHarness::default();
        run(&mut h);
        h.trace_digest()
    };
    assert_eq!(d1, d2, "explainability audit drill must be deterministic");
}

// ══════════════════════════════════════════════════════════════
//  Drill 4: Degraded Dashboard Recovery
//  Simulates: dashboard starts degraded, partial telemetry
//  arrives, full recovery occurs. Verifies diagnostics screen
//  tracks adapter health correctly.
// ══════════════════════════════════════════════════════════════

#[test]
fn drill_degraded_dashboard_recovery() {
    let mut collector =
        ArtifactCollector::new("scenario-drills").with_run_id("drill-degraded-recovery");

    let mut h = DashboardHarness::default();
    h.tick(); // Initial tick to capture a frame.

    // Phase 1: Dashboard starts degraded (no data).
    let degraded = h.is_degraded();
    assert!(degraded, "dashboard should start degraded");

    collector
        .start_case("phase1_initial_degraded")
        .section("degraded_recovery")
        .tags(["degraded", "startup"])
        .frame(capture_frame(&h))
        .assertion("starts degraded", degraded, "true", s(&degraded))
        .status(CaseStatus::Pass)
        .finish();

    // Phase 2: Partial telemetry arrives on timeline.
    h.startup_with_state(sample_healthy_state());
    assert!(!h.is_degraded());

    h.navigate_to_number(2);
    h.inject_msg(DashboardMsg::TelemetryTimeline(partial_timeline(
        escalation_timeline(),
    )));

    let fc = capture_frame(&h);
    let model = h.model_mut();
    let partial = model.timeline_partial;
    assert!(partial);
    let source_is_jsonl = model.timeline_source == DataSource::Jsonl;
    let source_str = format!("{:?}", model.timeline_source);
    assert!(source_is_jsonl);
    let diag_ok = model.timeline_diagnostics.contains("schema-shield");
    let diag_str = model.timeline_diagnostics.clone();
    assert!(diag_ok);

    collector
        .start_case("phase2_partial_telemetry")
        .section("degraded_recovery")
        .tags(["degraded", "partial", "schema-shield"])
        .frame(fc)
        .assertion("timeline is partial", partial, "true", s(&partial))
        .assertion("source is JSONL", source_is_jsonl, "Jsonl", s(&source_str))
        .assertion(
            "diagnostics mention schema-shield",
            diag_ok,
            "schema-shield",
            s(&diag_str),
        )
        .status(CaseStatus::Pass)
        .finish();

    // Phase 3: Daemon goes away.
    h.feed_unavailable();
    let degraded = h.is_degraded();
    assert!(degraded);

    let model = h.model_mut();
    let errors = model.adapter_errors;
    assert!(errors >= 1);

    collector
        .start_case("phase3_daemon_unavailable")
        .section("degraded_recovery")
        .tags(["degraded", "unavailable"])
        .frame(capture_frame(&h))
        .assertion("degraded after unavailable", degraded, "true", s(&degraded))
        .assertion("adapter errors recorded", errors >= 1, ">= 1", s(&errors))
        .status(CaseStatus::Pass)
        .finish();

    // Phase 4: Full recovery with clean telemetry.
    h.feed_state(sample_healthy_state());
    assert!(!h.is_degraded());

    h.inject_msg(DashboardMsg::TelemetryTimeline(timeline_result(
        escalation_timeline(),
    )));

    let fc = capture_frame(&h);
    let model = h.model_mut();
    let partial = model.timeline_partial;
    assert!(!partial, "should no longer be partial");
    let source_is_sqlite = model.timeline_source == DataSource::Sqlite;
    let source_str = format!("{:?}", model.timeline_source);
    assert!(source_is_sqlite);

    collector
        .start_case("phase4_full_recovery")
        .section("degraded_recovery")
        .tags(["recovery", "clean-telemetry"])
        .frame(fc)
        .assertion("not partial after recovery", !partial, "false", s(&partial))
        .assertion(
            "source is Sqlite",
            source_is_sqlite,
            "Sqlite",
            s(&source_str),
        )
        .status(CaseStatus::Pass)
        .finish();

    // Phase 5: Navigate to diagnostics, verify adapter counters.
    h.navigate_to_number(7);
    assert_eq!(h.screen(), Screen::Diagnostics);

    let model = h.model_mut();
    let reads = model.adapter_reads;
    let errors = model.adapter_errors;

    collector
        .start_case("phase5_diagnostics_counters")
        .section("degraded_recovery")
        .tags(["diagnostics", "adapters"])
        .frame(capture_frame(&h))
        .assertion("adapter reads > 0", reads > 0, "> 0", s(&reads))
        .assertion("adapter errors > 0", errors > 0, "> 0", s(&errors))
        .status(CaseStatus::Pass)
        .finish();

    let bundle = collector.finalize();
    assert_eq!(bundle.summary.passed, 5);
    assert_eq!(bundle.summary.failed, 0);
}

#[test]
fn drill_degraded_recovery_is_deterministic() {
    let run = |h: &mut DashboardHarness| {
        h.startup_with_state(sample_healthy_state());
        h.navigate_to_number(2);
        h.inject_msg(DashboardMsg::TelemetryTimeline(partial_timeline(
            escalation_timeline(),
        )));
        h.feed_unavailable();
        h.feed_state(sample_healthy_state());
        h.inject_msg(DashboardMsg::TelemetryTimeline(timeline_result(
            escalation_timeline(),
        )));
        h.navigate_to_number(7);
    };

    let d1 = {
        let mut h = DashboardHarness::default();
        run(&mut h);
        h.trace_digest()
    };
    let d2 = {
        let mut h = DashboardHarness::default();
        run(&mut h);
        h.trace_digest()
    };
    assert_eq!(d1, d2, "degraded recovery drill must be deterministic");
}

// ══════════════════════════════════════════════════════════════
//  Drill 5: Multi-Mount Incident Response
//  Simulates: operator handles divergent pressure across mounts,
//  uses incident playbook, examines per-mount ballast status.
// ══════════════════════════════════════════════════════════════

#[test]
fn drill_multi_mount_incident_response() {
    let mut collector = ArtifactCollector::new("scenario-drills").with_run_id("drill-multi-mount");

    let mut h = DashboardHarness::default();
    h.startup_with_state(multi_mount_state());

    // Phase 1: Overview shows divergent pressure.
    let frame = h.last_frame();
    let has_red = frame.text.contains("RED");
    let has_green = frame.text.contains("GREEN");
    assert!(has_red, "should show RED for /data");
    assert!(has_green, "should show GREEN for /");

    collector
        .start_case("phase1_divergent_pressure")
        .section("multi_mount_incident")
        .tags(["multi-mount", "pressure"])
        .frame(capture_frame(&h))
        .assertion("RED visible", has_red, "RED", None)
        .assertion("GREEN visible", has_green, "GREEN", None)
        .status(CaseStatus::Pass)
        .finish();

    // Phase 2: Open incident playbook.
    h.inject_char('!');
    let overlay = h.overlay();
    let has_playbook = overlay == Some(Overlay::IncidentPlaybook);
    assert!(has_playbook, "! should open incident playbook");

    collector
        .start_case("phase2_incident_playbook")
        .section("multi_mount_incident")
        .tags(["incident", "playbook"])
        .frame(capture_frame(&h))
        .assertion(
            "playbook overlay open",
            has_playbook,
            "IncidentPlaybook",
            overlay.as_ref().map(|o| format!("{o:?}")),
        )
        .status(CaseStatus::Pass)
        .finish();

    // Phase 3: Close playbook, navigate to ballast.
    h.inject_keycode(ftui_core::event::KeyCode::Escape);
    assert!(h.overlay().is_none());

    h.navigate_to_number(5);
    assert_eq!(h.screen(), Screen::Ballast);

    // Inject multi-mount ballast volumes.
    h.inject_msg(DashboardMsg::TelemetryBallast(ballast_result(
        multi_mount_volumes(),
    )));

    let model = h.model_mut();
    let vol_count = model.ballast_volumes.len();
    assert_eq!(vol_count, 2);

    // / should be OK (5/5), /data should be LOW (1/5).
    let root_vol = model.ballast_volumes.iter().find(|v| v.mount_point == "/");
    let data_vol = model
        .ballast_volumes
        .iter()
        .find(|v| v.mount_point == "/data");
    assert!(root_vol.is_some());
    assert!(data_vol.is_some());
    let root_status = root_vol.unwrap().status_level();
    let data_status = data_vol.unwrap().status_level();
    assert_eq!(root_status, "OK");
    assert_eq!(data_status, "LOW");

    collector
        .start_case("phase3_per_mount_ballast")
        .section("multi_mount_incident")
        .tags(["ballast", "multi-mount", "per-volume"])
        .frame(capture_frame(&h))
        .assertion("2 volumes", vol_count == 2, "2", s(&vol_count))
        .assertion("/ is OK", root_status == "OK", "OK", s(&root_status))
        .assertion("/data is LOW", data_status == "LOW", "LOW", s(&data_status))
        .status(CaseStatus::Pass)
        .finish();

    // Phase 4: Navigate to explainability for /data decisions.
    h.navigate_to_number(3);
    h.inject_msg(DashboardMsg::TelemetryDecisions(decisions_result(
        enforce_decisions(),
    )));

    let fc = capture_frame(&h);
    let model = h.model_mut();
    let data_decisions: Vec<_> = model
        .explainability_decisions
        .iter()
        .filter(|d| d.path.starts_with("/data"))
        .collect();
    assert!(
        !data_decisions.is_empty(),
        "should have decisions for /data paths"
    );
    let data_dec_count = data_decisions.len();

    collector
        .start_case("phase4_data_mount_decisions")
        .section("multi_mount_incident")
        .tags(["explainability", "multi-mount"])
        .frame(fc)
        .assertion(
            "/data decisions exist",
            data_dec_count > 0,
            "non-empty",
            s(&data_dec_count),
        )
        .status(CaseStatus::Pass)
        .finish();

    let bundle = collector.finalize();
    assert_eq!(bundle.summary.passed, 4);
    assert_eq!(bundle.summary.failed, 0);
}

// ══════════════════════════════════════════════════════════════
//  Drill 6: Full Incident to Resolution
//  End-to-end: green → escalation → incident playbook →
//  explainability audit → quick-release → timeline check →
//  recovery. The canonical "is the dashboard useful?" drill.
// ══════════════════════════════════════════════════════════════

#[test]
fn drill_full_incident_to_resolution() {
    let mut collector =
        ArtifactCollector::new("scenario-drills").with_run_id("drill-full-incident");

    let mut h = DashboardHarness::default();

    // Step 1: Green startup — everything normal.
    h.startup_with_state(sample_healthy_state());
    assert_eq!(h.screen(), Screen::Overview);
    assert!(!h.is_degraded());

    collector
        .start_case("step1_green_startup")
        .section("full_incident")
        .tags(["incident", "startup", "green"])
        .frame(capture_frame(&h))
        .assertion(
            "starts on Overview",
            h.screen() == Screen::Overview,
            "Overview",
            None,
        )
        .status(CaseStatus::Pass)
        .finish();

    // Step 2: Pressure escalates.
    h.feed_state(yellow_state());
    h.tick();
    h.feed_state(red_state());
    h.tick();

    let frame = h.last_frame();
    assert!(frame.text.contains("RED"));

    collector
        .start_case("step2_pressure_escalation")
        .section("full_incident")
        .tags(["incident", "pressure", "red"])
        .frame(capture_frame(&h))
        .assertion("RED visible", frame.text.contains("RED"), "RED", None)
        .status(CaseStatus::Pass)
        .finish();

    // Step 3: Operator opens incident playbook.
    h.inject_char('!');
    assert_eq!(h.overlay(), Some(Overlay::IncidentPlaybook));

    collector
        .start_case("step3_playbook_opened")
        .section("full_incident")
        .tags(["incident", "playbook"])
        .frame(capture_frame(&h))
        .assertion(
            "playbook open",
            h.overlay() == Some(Overlay::IncidentPlaybook),
            "IncidentPlaybook",
            None,
        )
        .status(CaseStatus::Pass)
        .finish();

    // Step 4: Close playbook, examine explainability.
    h.inject_keycode(ftui_core::event::KeyCode::Escape);
    h.navigate_to_number(3);

    h.inject_msg(DashboardMsg::TelemetryDecisions(decisions_result(
        enforce_decisions(),
    )));

    let model = h.model_mut();
    let total_decisions = model.explainability_decisions.len();
    assert_eq!(total_decisions, 3);

    // Navigate through decisions.
    h.inject_char('j');
    h.inject_char('j');
    let model = h.model_mut();
    let cursor = model.explainability_selected;

    collector
        .start_case("step4_explainability_review")
        .section("full_incident")
        .tags(["incident", "explainability"])
        .frame(capture_frame(&h))
        .assertion(
            "3 decisions loaded",
            total_decisions == 3,
            "3",
            s(&total_decisions),
        )
        .assertion("cursor navigated", cursor > 0, "> 0", s(&cursor))
        .status(CaseStatus::Pass)
        .finish();

    // Step 5: Quick-release ballast (x shortcut).
    h.inject_char('x');
    // Quick-release should navigate to ballast screen with confirmation overlay.
    let screen = h.screen();
    let overlay = h.overlay();
    let on_ballast = screen == Screen::Ballast;
    let has_confirm = matches!(overlay, Some(Overlay::Confirmation(_)));

    collector
        .start_case("step5_quick_release")
        .section("full_incident")
        .tags(["incident", "quick-release", "ballast"])
        .frame(capture_frame(&h))
        .assertion(
            "on Ballast screen",
            on_ballast,
            "Ballast",
            s(&format!("{screen:?}")),
        )
        .assertion(
            "confirmation overlay",
            has_confirm,
            "Confirmation",
            overlay.as_ref().map(|o| format!("{o:?}")),
        )
        .status(CaseStatus::Pass)
        .finish();

    // Step 6: Dismiss confirmation, check timeline for ballast event.
    h.inject_keycode(ftui_core::event::KeyCode::Escape);
    h.navigate_to_number(2);

    h.inject_msg(DashboardMsg::TelemetryTimeline(timeline_result(
        escalation_timeline(),
    )));

    let model = h.model_mut();
    let has_ballast_event = model
        .timeline_events
        .iter()
        .any(|e| e.event_type == "ballast_release");
    assert!(has_ballast_event);

    collector
        .start_case("step6_timeline_verification")
        .section("full_incident")
        .tags(["incident", "timeline", "ballast-release"])
        .frame(capture_frame(&h))
        .assertion(
            "ballast_release event in timeline",
            has_ballast_event,
            "true",
            s(&has_ballast_event),
        )
        .status(CaseStatus::Pass)
        .finish();

    // Step 7: Recovery — pressure drops, back to overview.
    h.feed_state(recovery_state());
    h.tick();
    h.navigate_to_number(1);

    let frame = h.last_frame();
    let recovered = frame.text.contains("GREEN");
    assert!(recovered);

    let fc = capture_frame(&h);
    let model = h.model_mut();
    let state = model.daemon_state.as_ref().unwrap();
    let ballast_avail = state.ballast.available;
    let pressure_overall = state.pressure.overall.clone();
    assert_eq!(ballast_avail, 10);
    assert_eq!(pressure_overall, "green");

    collector
        .start_case("step7_resolution")
        .section("full_incident")
        .tags(["incident", "resolution", "recovery"])
        .frame(fc)
        .assertion("GREEN after recovery", recovered, "GREEN", None)
        .assertion(
            "ballast fully replenished",
            ballast_avail == 10,
            "10",
            s(&ballast_avail),
        )
        .assertion(
            "pressure is green",
            pressure_overall == "green",
            "green",
            s(&pressure_overall),
        )
        .status(CaseStatus::Pass)
        .finish();

    let bundle = collector.finalize();
    assert_eq!(bundle.summary.passed, 7);
    assert_eq!(bundle.summary.failed, 0);

    // Verify drill logs are rich enough for post-mortem.
    let json = serde_json::to_string_pretty(&bundle).unwrap();
    assert!(
        json.contains("drill-full-incident"),
        "bundle should have correct run_id"
    );
    assert!(json.contains("full_incident"), "cases should have section");
    // Every case should have at least one frame capture.
    for case in &bundle.cases {
        assert!(
            !case.frames.is_empty(),
            "case {} missing frame captures",
            case.name
        );
    }
    // All cases should have tags.
    for case in &bundle.cases {
        assert!(!case.tags.is_empty(), "case {} missing tags", case.name);
    }
}

#[test]
fn drill_full_incident_is_deterministic() {
    let run = |h: &mut DashboardHarness| {
        h.startup_with_state(sample_healthy_state());
        h.feed_state(yellow_state());
        h.tick();
        h.feed_state(red_state());
        h.tick();
        h.inject_char('!');
        h.inject_keycode(ftui_core::event::KeyCode::Escape);
        h.navigate_to_number(3);
        h.inject_msg(DashboardMsg::TelemetryDecisions(decisions_result(
            enforce_decisions(),
        )));
        h.inject_char('j');
        h.inject_char('j');
        h.inject_char('x');
        h.inject_keycode(ftui_core::event::KeyCode::Escape);
        h.navigate_to_number(2);
        h.inject_msg(DashboardMsg::TelemetryTimeline(timeline_result(
            escalation_timeline(),
        )));
        h.feed_state(recovery_state());
        h.tick();
        h.navigate_to_number(1);
    };

    let d1 = {
        let mut h = DashboardHarness::default();
        run(&mut h);
        h.trace_digest()
    };
    let d2 = {
        let mut h = DashboardHarness::default();
        run(&mut h);
        h.trace_digest()
    };
    assert_eq!(d1, d2, "full incident drill must be deterministic");
}

// ══════════════════════════════════════════════════════════════
//  Drill 7: Artifact Bundle Structural Validation
//  Ensures the artifact schema itself meets post-mortem
//  requirements: serializable, validated, traceable.
// ══════════════════════════════════════════════════════════════

#[test]
fn drill_artifact_bundle_structural_validation() {
    let mut collector =
        ArtifactCollector::new("structural-validation").with_run_id("drill-validation");

    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());

    // Case 1: Passing case with assertions.
    collector
        .start_case("passing_case")
        .section("validation")
        .tags(["structural"])
        .frame(capture_frame(&h))
        .assertion("trivial pass", true, "true", None)
        .diagnostic(DiagnosticEntry::info("startup complete"))
        .status(CaseStatus::Pass)
        .finish();

    // Case 2: Case with rich diagnostics.
    h.feed_state(red_state());
    h.tick();

    collector
        .start_case("diagnostics_case")
        .section("validation")
        .tags(["structural", "diagnostics"])
        .frame(capture_frame(&h))
        .diagnostic(DiagnosticEntry::warn("pressure threshold crossed"))
        .diagnostic(DiagnosticEntry::error("simulated error for validation").with_source("drill"))
        .assertion("red pressure", true, "RED", None)
        .status(CaseStatus::Pass)
        .finish();

    let bundle = collector.finalize();

    // Validate serialization roundtrip.
    let json = serde_json::to_string(&bundle).unwrap();
    let roundtrip: super::e2e_artifact::TestRunBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(roundtrip.suite, "structural-validation");
    assert_eq!(roundtrip.cases.len(), 2);
    assert_eq!(roundtrip.summary.passed, 2);
    assert_eq!(roundtrip.summary.failed, 0);

    // Every case must have a trace_id and case_id.
    for case in &roundtrip.cases {
        assert!(
            !case.trace_id.is_empty(),
            "case {} missing trace_id",
            case.name
        );
        assert!(
            !case.case_id.is_empty(),
            "case {} missing case_id",
            case.name
        );
        assert!(
            !case.started_at.is_empty(),
            "case {} missing started_at",
            case.name
        );
    }

    // Diagnostics are preserved in roundtrip.
    let diag_case = &roundtrip.cases[1];
    assert_eq!(diag_case.diagnostics.len(), 2);
    assert_eq!(diag_case.diagnostics[0].level, "warn");
    assert_eq!(diag_case.diagnostics[1].level, "error");
    assert_eq!(diag_case.diagnostics[1].source.as_deref(), Some("drill"));
}
