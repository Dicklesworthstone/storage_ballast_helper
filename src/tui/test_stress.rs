//! Stress and performance tests for the TUI dashboard.
//!
//! Validates that the Elm-style model/update/render pipeline handles
//! sustained high-frequency ticks, large telemetry payloads, bursty data
//! arrivals, intermittent adapter failures, and notification saturation
//! without unbounded memory growth or excessive processing time.
//!
//! All tests use the headless `DashboardHarness` — no terminal, no timing
//! dependencies, fully deterministic.
//!
//! **Bead:** bd-xzt.4.5

#![allow(
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_lossless,
    clippy::suboptimal_flops,
    clippy::too_many_lines
)]

use std::time::Instant;

use super::e2e_artifact::{ArtifactCollector, CaseStatus, DiagnosticEntry};
use super::model::{BallastVolume, DashboardMsg, Screen};
use super::test_harness::{
    DashboardHarness, HarnessStep, sample_healthy_state, sample_pressured_state,
};
use crate::tui::telemetry::{
    DataSource, DecisionEvidence, FactorBreakdown, TelemetryResult, TimelineEvent,
};

// ──────────────────── helpers ────────────────────

fn make_timeline_events(count: usize) -> Vec<TimelineEvent> {
    (0..count)
        .map(|i| {
            let severity = match i % 3 {
                0 => "info",
                1 => "warning",
                _ => "critical",
            };
            TimelineEvent {
                timestamp: format!(
                    "2026-01-01T{:02}:{:02}:{:02}Z",
                    i / 3600,
                    (i / 60) % 60,
                    i % 60
                ),
                event_type: format!("event_{i}"),
                severity: severity.to_owned(),
                path: Some(format!("/data/artifact_{i}")),
                size_bytes: Some((i as u64) * 1024),
                score: Some(0.5 + (i as f64) * 0.001),
                pressure_level: None,
                free_pct: None,
                success: Some(true),
                error_code: None,
                error_message: None,
                duration_ms: Some(i as u64),
                details: None,
            }
        })
        .collect()
}

fn make_candidates(count: usize) -> Vec<DecisionEvidence> {
    (0..count)
        .map(|i| DecisionEvidence {
            decision_id: i as u64,
            timestamp: format!("2026-01-01T00:{:02}:{:02}Z", (i / 60) % 60, i % 60),
            path: format!("/data/candidate_{i}"),
            size_bytes: ((count - i) as u64) * 4096,
            age_secs: (i as u64) * 300,
            action: "delete".to_owned(),
            effective_action: None,
            policy_mode: "live".to_owned(),
            factors: FactorBreakdown {
                location: 0.3 + (i as f64) * 0.005,
                name: 0.4,
                age: 0.5 + (i as f64) * 0.003,
                size: 0.6,
                structure: 0.2,
                pressure_multiplier: 1.0,
            },
            total_score: 1.5 + (i as f64) * 0.01,
            posterior_abandoned: 0.7,
            expected_loss_keep: 20.0,
            expected_loss_delete: 30.0,
            calibration_score: 0.75,
            vetoed: false,
            veto_reason: None,
            guard_status: None,
            summary: String::new(),
            raw_json: None,
        })
        .collect()
}

fn make_ballast_volumes(count: usize) -> Vec<BallastVolume> {
    (0..count)
        .map(|i| BallastVolume {
            mount_point: format!("/mnt/vol_{i}"),
            ballast_dir: format!("/mnt/vol_{i}/.sbh/ballast"),
            fs_type: "ext4".to_owned(),
            strategy: "fallocate".to_owned(),
            files_available: 5 + i,
            files_total: 10 + i,
            releasable_bytes: ((5 + i) as u64) * 1_073_741_824,
            skipped: false,
            skip_reason: None,
        })
        .collect()
}

fn telemetry_timeline(events: Vec<TimelineEvent>) -> DashboardMsg {
    DashboardMsg::TelemetryTimeline(TelemetryResult {
        data: events,
        source: DataSource::Sqlite,
        partial: false,
        diagnostics: String::new(),
    })
}

fn telemetry_candidates(candidates: Vec<DecisionEvidence>) -> DashboardMsg {
    DashboardMsg::TelemetryCandidates(TelemetryResult {
        data: candidates,
        source: DataSource::Sqlite,
        partial: false,
        diagnostics: String::new(),
    })
}

fn telemetry_decisions(decisions: Vec<DecisionEvidence>) -> DashboardMsg {
    DashboardMsg::TelemetryDecisions(TelemetryResult {
        data: decisions,
        source: DataSource::Sqlite,
        partial: false,
        diagnostics: String::new(),
    })
}

fn telemetry_ballast(volumes: Vec<BallastVolume>) -> DashboardMsg {
    DashboardMsg::TelemetryBallast(TelemetryResult {
        data: volumes,
        source: DataSource::Sqlite,
        partial: false,
        diagnostics: String::new(),
    })
}

// ──────────────────── high-frequency tick processing ────────────────────

#[test]
fn sustained_tick_processing_1000_ticks() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());

    let start = Instant::now();
    for _ in 0..1000 {
        h.tick();
    }
    let elapsed = start.elapsed();

    // 1000 ticks should process well under 5 seconds on any CI box.
    assert!(
        elapsed.as_secs() < 5,
        "1000 ticks took {elapsed:?} — budget exceeded"
    );
    // Tick counter should wrap correctly.
    assert_eq!(h.tick_count(), 1002); // 2 from startup + 1000
    assert!(!h.is_degraded());
}

#[test]
fn tick_processing_across_all_screens() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());

    for screen_num in 1..=7 {
        h.navigate_to_number(screen_num);
        for _ in 0..100 {
            h.tick();
        }
    }
    // Verify we navigated through all screens and model is still coherent.
    assert!(!h.is_quit());
    assert!(!h.is_degraded());
    assert!(h.tick_count() > 700);
}

// ──────────────────── large telemetry payloads ────────────────────

#[test]
fn large_timeline_event_stream() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());
    h.navigate_to_number(2); // Timeline screen

    let events = make_timeline_events(1000);
    let start = Instant::now();
    h.inject_msg(telemetry_timeline(events));
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs() < 3,
        "injecting 1000 timeline events took {elapsed:?}"
    );

    // Model should hold all events.
    assert_eq!(h.model_mut().timeline_events.len(), 1000);
    // Render should still produce output.
    h.tick();
    assert!(!h.last_frame().text.is_empty());
}

#[test]
fn large_candidate_list_with_sorting() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());
    h.navigate_to_number(4); // Candidates screen

    let candidates = make_candidates(500);
    h.inject_msg(telemetry_candidates(candidates));
    assert_eq!(h.model_mut().candidates_list.len(), 500);

    // Cycle through all sort orders and verify each completes quickly.
    let start = Instant::now();
    for _ in 0..4 {
        h.inject_char('s'); // cycle sort
        h.tick(); // re-render
    }
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs() < 3,
        "sorting 500 candidates 4 times took {elapsed:?}"
    );
    // Sort should have cycled back to Score.
    assert_eq!(
        h.model_mut().candidates_sort,
        super::model::CandidatesSortOrder::Score
    );
}

#[test]
fn large_decision_evidence_for_explainability() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());
    h.navigate_to_number(3); // Explainability screen

    let decisions = make_candidates(300);
    h.inject_msg(telemetry_decisions(decisions));
    assert_eq!(h.model_mut().explainability_decisions.len(), 300);

    // Cursor navigation through large list.
    for _ in 0..50 {
        h.inject_char('j'); // down
    }
    assert_eq!(h.model_mut().explainability_selected, 50);
    for _ in 0..10 {
        h.inject_char('k'); // up
    }
    assert_eq!(h.model_mut().explainability_selected, 40);
}

#[test]
fn large_ballast_volumes() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());
    h.navigate_to_number(5); // Ballast screen

    let volumes = make_ballast_volumes(50);
    h.inject_msg(telemetry_ballast(volumes));
    assert_eq!(h.model_mut().ballast_volumes.len(), 50);

    // Ballast screen key handler (j/k) is wired by bd-xzt.3.5.
    // For now, verify data loads correctly and rendering works.
    h.tick();
    assert!(!h.last_frame().text.is_empty());
    // Model-level cursor navigation still works.
    assert!(h.model_mut().ballast_cursor_down());
    assert_eq!(h.model_mut().ballast_selected, 1);
}

// ──────────────────── bursty telemetry arrivals ────────────────────

#[test]
fn bursty_timeline_updates() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());
    h.navigate_to_number(2);

    // Simulate 20 rapid bursts of 50 events each.
    for burst in 0..20 {
        let events = make_timeline_events(50);
        h.inject_msg(telemetry_timeline(events));
        h.tick();
        // Each burst replaces the previous data (not appending).
        assert_eq!(
            h.model_mut().timeline_events.len(),
            50,
            "burst {burst}: event count should be 50"
        );
    }
    assert!(!h.is_degraded());
}

#[test]
fn bursty_candidate_updates_with_sort_stability() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());
    h.navigate_to_number(4);

    for _ in 0..10 {
        let candidates = make_candidates(100);
        h.inject_msg(telemetry_candidates(candidates));
        h.inject_char('s'); // cycle sort
        h.tick();
    }
    // Model should still be coherent.
    assert_eq!(h.model_mut().candidates_list.len(), 100);
    assert!(!h.is_quit());
}

// ──────────────────── intermittent adapter failures ────────────────────

#[test]
fn alternating_success_and_failure_data_updates() {
    let mut h = DashboardHarness::default();

    for i in 0..200 {
        if i % 3 == 0 {
            h.feed_unavailable();
        } else {
            h.feed_state(sample_healthy_state());
        }
    }

    // After 200 updates: last was i=199, 199%3=1 => healthy => not degraded.
    assert!(!h.is_degraded());
    // Counter tracking: ~67 failures, ~133 successes.
    let model = h.model_mut();
    assert!(
        model.adapter_reads > 100,
        "expected >100 reads, got {}",
        model.adapter_reads
    );
    assert!(
        model.adapter_errors > 50,
        "expected >50 errors, got {}",
        model.adapter_errors
    );
    assert_eq!(model.adapter_reads + model.adapter_errors, 200);
}

#[test]
fn sustained_unavailable_then_recovery() {
    let mut h = DashboardHarness::default();

    // 100 consecutive failures.
    for _ in 0..100 {
        h.feed_unavailable();
    }
    assert!(h.is_degraded());
    assert_eq!(h.model_mut().adapter_errors, 100);

    // Recovery: single healthy update clears degraded.
    h.feed_state(sample_healthy_state());
    assert!(!h.is_degraded());
    assert_eq!(h.model_mut().adapter_reads, 1);
}

#[test]
fn error_flood_does_not_crash() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());

    for i in 0..500 {
        h.inject_error(&format!("error {i}: disk read failed"), "adapter");
    }
    // Notifications capped at MAX_NOTIFICATIONS (3).
    assert!(h.notification_count() <= 3);
    // Model should still be usable.
    assert!(!h.is_quit());
    h.tick();
    assert!(!h.last_frame().text.is_empty());
}

// ──────────────────── frame-time budget assertions ────────────────────

#[test]
fn frame_metrics_accumulation_under_load() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());
    h.navigate_to_number(7); // Diagnostics screen

    // Push 200 frame metrics (ring buffer capacity is 60).
    for i in 0..200 {
        #[allow(clippy::cast_precision_loss)]
        h.inject_msg(DashboardMsg::FrameMetrics {
            duration_ms: 10.0 + (i as f64) * 0.1,
        });
    }

    let model = h.model_mut();
    // Ring buffer should be capped at 60.
    assert_eq!(model.frame_times.len(), 60);
    // Latest should be the last pushed value.
    let latest = model.frame_times.latest().unwrap();
    assert!((latest - 29.9).abs() < 0.01); // 10.0 + 199 * 0.1 = 29.9

    let (current, avg, min, max) = model.frame_time_stats().unwrap();
    assert!(current > 0.0);
    assert!(avg > 0.0);
    assert!(min <= avg);
    assert!(avg <= max);
}

#[test]
fn render_under_load_stays_within_budget() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());

    // Load up all telemetry screens with data.
    h.inject_msg(telemetry_timeline(make_timeline_events(500)));
    h.inject_msg(telemetry_candidates(make_candidates(200)));
    h.inject_msg(telemetry_decisions(make_candidates(200)));
    h.inject_msg(telemetry_ballast(make_ballast_volumes(20)));

    // Measure 100 full render cycles across all screens.
    let start = Instant::now();
    for cycle in 0..100 {
        let screen_num = (cycle % 7) as u8 + 1;
        h.navigate_to_number(screen_num);
        h.tick();
    }
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs() < 10,
        "100 render cycles across all screens took {elapsed:?}"
    );
}

// ──────────────────── memory stability ────────────────────

#[test]
fn rate_histories_bounded_after_many_mount_updates() {
    let mut h = DashboardHarness::default();

    // Feed states with varying mount counts to exercise pruning.
    for i in 0..500 {
        let mut state = sample_healthy_state();
        // Alternate between 1 and 3 mounts to trigger prune logic.
        if i % 5 == 0 {
            state.pressure.mounts = vec![
                crate::daemon::self_monitor::MountPressure {
                    path: "/data".into(),
                    free_pct: 50.0,
                    level: "green".into(),
                    rate_bps: Some(100.0),
                },
                crate::daemon::self_monitor::MountPressure {
                    path: "/tmp".into(),
                    free_pct: 80.0,
                    level: "green".into(),
                    rate_bps: Some(50.0),
                },
                crate::daemon::self_monitor::MountPressure {
                    path: "/home".into(),
                    free_pct: 60.0,
                    level: "green".into(),
                    rate_bps: Some(75.0),
                },
            ];
        }
        h.feed_state(state);
    }

    let model = h.model_mut();
    // rate_histories should only have entries for currently active mounts.
    // The last iteration (i=499, 499%5=4) had the default single /data mount.
    assert_eq!(model.rate_histories.len(), 1);
    // Each RateHistory has capacity 30, should never exceed.
    for rh in model.rate_histories.values() {
        assert!(rh.len() <= 30);
    }
}

#[test]
fn notification_eviction_prevents_unbounded_growth() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());

    for i in 0..1000 {
        h.inject_error(&format!("error {i}"), "stress");
    }

    // Notifications should never exceed MAX_NOTIFICATIONS (3).
    assert!(h.notification_count() <= 3);
    // IDs should be monotonically advancing.
    let model = h.model_mut();
    assert!(model.next_notification_id >= 1000);
}

#[test]
fn frame_times_ring_buffer_bounded_after_heavy_metrics() {
    let mut h = DashboardHarness::default();

    for i in 0..5000 {
        #[allow(clippy::cast_precision_loss)]
        h.inject_msg(DashboardMsg::FrameMetrics {
            duration_ms: (i as f64) * 0.01,
        });
    }

    // Ring buffer capacity is 60; must never grow beyond that.
    assert_eq!(h.model_mut().frame_times.len(), 60);
}

// ──────────────────── screen switching under load ────────────────────

#[test]
fn rapid_screen_cycling_under_data_load() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());

    // Populate all telemetry screens.
    h.inject_msg(telemetry_timeline(make_timeline_events(200)));
    h.inject_msg(telemetry_candidates(make_candidates(100)));
    h.inject_msg(telemetry_decisions(make_candidates(100)));
    h.inject_msg(telemetry_ballast(make_ballast_volumes(10)));

    // Rapidly cycle through screens 500 times using ] key.
    let start = Instant::now();
    for _ in 0..500 {
        h.navigate_next();
    }
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs() < 5,
        "500 screen switches took {elapsed:?}"
    );
    // After 500 next navigations (7 screens), we should be back near start.
    // 500 % 7 = 3, so 3 screens past Overview = Candidates.
    assert_eq!(h.screen(), Screen::Candidates);
}

#[test]
fn screen_history_depth_under_direct_navigation() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());

    // Navigate by number key 300 times — history grows linearly.
    for i in 0..300 {
        let n = (i % 7) as u8 + 1;
        h.navigate_to_number(n);
    }

    // History should record each navigation except same-screen no-ops.
    // We start on Overview(1), then go 1,2,3,4,5,6,7,1,2,...
    // First nav to 1 is no-op, then 2 adds to history, etc.
    assert!(h.history_depth() > 0);
    assert!(!h.is_quit());
}

// ──────────────────── combined stress scenario ────────────────────

#[test]
fn realistic_long_running_session() {
    let mut h = DashboardHarness::default();

    // Phase 1: Startup with healthy state.
    h.startup_with_state(sample_healthy_state());
    assert!(!h.is_degraded());

    // Phase 2: Stream telemetry data while navigating.
    for round in 0..50 {
        h.tick();

        // Feed alternating states.
        if round % 10 < 7 {
            h.feed_state(sample_healthy_state());
        } else {
            h.feed_state(sample_pressured_state());
        }

        // Navigate to different screens.
        let screen = (round % 7) as u8 + 1;
        h.navigate_to_number(screen);

        // Inject telemetry based on current screen.
        match screen {
            2 => {
                h.inject_msg(telemetry_timeline(make_timeline_events(50)));
            }
            3 => {
                h.inject_msg(telemetry_decisions(make_candidates(30)));
            }
            4 => {
                h.inject_msg(telemetry_candidates(make_candidates(40)));
                h.inject_char('s'); // cycle sort
            }
            5 => {
                h.inject_msg(telemetry_ballast(make_ballast_volumes(5)));
            }
            7 => {
                #[allow(clippy::cast_precision_loss)]
                h.inject_msg(DashboardMsg::FrameMetrics {
                    duration_ms: 16.0 + (round as f64) * 0.1,
                });
            }
            _ => {}
        }

        // Occasional errors.
        if round % 13 == 0 {
            h.inject_error("transient fault", "adapter");
        }
    }

    // Phase 3: Verify model integrity.
    assert!(!h.is_quit());
    let model = h.model_mut();
    assert!(model.tick > 50);
    assert!(model.adapter_reads > 0);
    // Notifications should be bounded.
    assert!(model.notifications.len() <= 3);
    // Frame times should not exceed ring buffer capacity.
    assert!(model.frame_times.len() <= 60);
}

#[test]
fn deterministic_stress_replay() {
    // Two identical stress scripts must produce identical trace digests.
    let script: Vec<HarnessStep> = {
        let mut steps = Vec::new();
        steps.push(HarnessStep::Tick);
        steps.push(HarnessStep::FeedHealthyState);
        for i in 0..100 {
            steps.push(HarnessStep::Tick);
            match i % 7 {
                0 => steps.push(HarnessStep::Char('1')),
                1 => steps.push(HarnessStep::Char('2')),
                2 => steps.push(HarnessStep::Char('3')),
                3 => steps.push(HarnessStep::Char('4')),
                4 => steps.push(HarnessStep::Char('5')),
                5 => steps.push(HarnessStep::Char('6')),
                _ => steps.push(HarnessStep::Char('7')),
            }
            if i % 11 == 0 {
                steps.push(HarnessStep::FeedPressuredState);
            } else {
                steps.push(HarnessStep::FeedHealthyState);
            }
            if i % 17 == 0 {
                steps.push(HarnessStep::Error {
                    message: format!("fault at step {i}"),
                    source: "stress".to_owned(),
                });
            }
        }
        steps.push(HarnessStep::Char('q'));
        steps
    };

    let mut h1 = DashboardHarness::default();
    let mut h2 = DashboardHarness::default();
    h1.run_script(&script);
    h2.run_script(&script);

    assert_eq!(h1.trace_digest(), h2.trace_digest());
    assert_eq!(h1.command_trace(), h2.command_trace());
    assert!(h1.is_quit());
}

// ──────────────────── overlay stress ────────────────────

#[test]
fn rapid_help_overlay_toggling() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());

    for _ in 0..200 {
        h.open_help();
        assert_eq!(h.overlay(), Some(super::model::Overlay::Help));
        h.inject_char('?'); // toggle close
        assert!(h.overlay().is_none());
    }
    assert!(!h.is_quit());
}

#[test]
fn overlay_with_screen_switching() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());

    for i in 0..100 {
        let n = (i % 7) as u8 + 1;
        h.navigate_to_number(n);
        h.open_help();
        // Keys while overlay is open should not navigate.
        h.inject_char('3');
        assert_eq!(h.overlay(), Some(super::model::Overlay::Help));
        h.inject_keycode(ftui::KeyCode::Escape);
        assert!(h.overlay().is_none());
    }
}

// ──────────────────── resize stress ────────────────────

#[test]
fn rapid_resize_under_data_load() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());

    // Populate with data.
    h.inject_msg(telemetry_timeline(make_timeline_events(100)));

    let start = Instant::now();
    for i in 0..200 {
        let cols = 80 + (i % 120) as u16;
        let rows = 20 + (i % 40) as u16;
        h.resize(cols, rows);
        h.tick();
    }
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs() < 5,
        "200 resizes with ticks took {elapsed:?}"
    );
    assert!(!h.is_quit());
}

// ──────────────────── structured performance artifact ────────────────────

/// Runs a multi-scenario stress suite and captures results in a structured
/// [`TestRunBundle`] suitable for trend tracking and regression comparison.
#[test]
fn performance_artifact_collection() {
    let mut collector =
        ArtifactCollector::new("stress-perf").with_run_id("stress-perf-deterministic");

    // ── Scenario 1: sustained tick throughput ──
    {
        let start = Instant::now();
        let mut h = DashboardHarness::default();
        h.startup_with_state(sample_healthy_state());
        for _ in 0..500 {
            h.tick();
        }
        let elapsed = start.elapsed();
        let pass = elapsed.as_millis() < 5000;
        let trace = format!(
            "ticks=502 elapsed_ms={} frames={}",
            elapsed.as_millis(),
            h.frame_count()
        );
        collector
            .start_case("sustained_tick_500")
            .section("throughput")
            .tags(["stress", "tui"])
            .status(if pass {
                CaseStatus::Pass
            } else {
                CaseStatus::Fail
            })
            .assertion(
                "tick_budget_5s",
                pass,
                "<5000ms",
                Some(format!("{}ms", elapsed.as_millis())),
            )
            .diagnostic(DiagnosticEntry::info(trace))
            .finish();
    }

    // ── Scenario 2: full-screen render cycle under load ──
    {
        let mut h = DashboardHarness::default();
        h.startup_with_state(sample_healthy_state());
        h.inject_msg(telemetry_timeline(make_timeline_events(500)));
        h.inject_msg(telemetry_candidates(make_candidates(200)));
        h.inject_msg(telemetry_decisions(make_candidates(200)));
        h.inject_msg(telemetry_ballast(make_ballast_volumes(20)));

        let start = Instant::now();
        for cycle in 0..70 {
            let screen_num = (cycle % 7) as u8 + 1;
            h.navigate_to_number(screen_num);
            h.tick();
        }
        let elapsed = start.elapsed();
        let pass = elapsed.as_millis() < 10000;
        let trace = format!(
            "cycles=70 elapsed_ms={} avg_ms={:.2}",
            elapsed.as_millis(),
            elapsed.as_millis() as f64 / 70.0
        );
        collector
            .start_case("render_cycle_all_screens_70")
            .section("render")
            .tags(["stress", "tui"])
            .status(if pass {
                CaseStatus::Pass
            } else {
                CaseStatus::Fail
            })
            .assertion(
                "render_budget_10s",
                pass,
                "<10000ms",
                Some(format!("{}ms", elapsed.as_millis())),
            )
            .diagnostic(DiagnosticEntry::info(trace))
            .finish();
    }

    // ── Scenario 3: bursty data + navigation combined ──
    {
        let start = Instant::now();
        let mut h = DashboardHarness::default();
        h.startup_with_state(sample_healthy_state());
        for round in 0..100 {
            h.tick();
            if round % 3 == 0 {
                h.feed_unavailable();
            } else {
                h.feed_state(sample_healthy_state());
            }
            let screen = (round % 7) as u8 + 1;
            h.navigate_to_number(screen);
            if round % 7 == 0 {
                h.inject_error("transient fault", "adapter");
            }
        }
        let elapsed = start.elapsed();
        let pass = elapsed.as_millis() < 10000;
        let model = h.model_mut();
        let trace = format!(
            "rounds=100 elapsed_ms={} reads={} errors={} notifs={}",
            elapsed.as_millis(),
            model.adapter_reads,
            model.adapter_errors,
            model.notifications.len()
        );
        collector
            .start_case("bursty_mixed_workload_100")
            .section("integration")
            .tags(["stress", "tui"])
            .status(if pass {
                CaseStatus::Pass
            } else {
                CaseStatus::Fail
            })
            .assertion(
                "mixed_budget_10s",
                pass,
                "<10000ms",
                Some(format!("{}ms", elapsed.as_millis())),
            )
            .diagnostic(DiagnosticEntry::info(trace))
            .finish();
    }

    // ── Finalize and validate ──
    let bundle = collector.finalize();
    assert_eq!(bundle.suite, "stress-perf");
    assert_eq!(bundle.summary.total, 3);
    assert_eq!(
        bundle.summary.failed,
        0,
        "Performance regressions detected:\n{}",
        bundle
            .cases
            .iter()
            .filter(|c| c.status == CaseStatus::Fail)
            .map(|c| format!("  FAIL: {} — {:?}", c.name, c.diagnostics))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(bundle.validation_warnings.is_empty());

    // Verify the bundle is serializable for trend tracking.
    let json = serde_json::to_string_pretty(&bundle).unwrap();
    assert!(json.contains("stress-perf"));
    assert!(json.contains("throughput"));
    assert!(json.contains("elapsed_ms="));
}
