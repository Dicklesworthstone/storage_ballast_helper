//! Property-based tests for dashboard reducer invariants.
//!
//! Uses `proptest` to verify that arbitrary sequences of dashboard messages
//! maintain critical state invariants: valid screens, bounded collections,
//! monotonic counters, cursor clamping, and navigation consistency.
//!
//! **Bead:** bd-xzt.4.11

use std::path::PathBuf;
use std::time::Duration;

use ftui::{KeyCode, KeyEvent, KeyEventKind, Modifiers};
use proptest::prelude::*;

use super::model::{
    BallastVolume, CandidatesSortOrder, DashboardError, DashboardModel, DashboardMsg, Overlay,
    Screen,
};
use super::update;
use crate::daemon::self_monitor::{
    BallastState, Counters, DaemonState, LastScanState, MountPressure, PressureState,
};
use crate::tui::telemetry::{
    DataSource, DecisionEvidence, FactorBreakdown, TelemetryResult, TimelineEvent,
};

// ──────────────────── strategies ────────────────────

fn arb_screen() -> impl Strategy<Value = Screen> {
    (1u8..=7).prop_map(|n| Screen::from_number(n).unwrap())
}

fn arb_key_code() -> impl Strategy<Value = KeyCode> {
    prop_oneof![
        Just(KeyCode::Char('1')),
        Just(KeyCode::Char('2')),
        Just(KeyCode::Char('3')),
        Just(KeyCode::Char('4')),
        Just(KeyCode::Char('5')),
        Just(KeyCode::Char('6')),
        Just(KeyCode::Char('7')),
        Just(KeyCode::Char('j')),
        Just(KeyCode::Char('k')),
        Just(KeyCode::Char('f')),
        Just(KeyCode::Char('s')),
        Just(KeyCode::Char('r')),
        Just(KeyCode::Char('b')),
        Just(KeyCode::Char('?')),
        Just(KeyCode::Char(':')),
        Just(KeyCode::Char('[')),
        Just(KeyCode::Char(']')),
        Just(KeyCode::Char('d')),
        Just(KeyCode::Char('G')),
        Just(KeyCode::Char('V')),
        Just(KeyCode::Escape),
        Just(KeyCode::Enter),
        Just(KeyCode::Up),
        Just(KeyCode::Down),
    ]
}

fn arb_key_event() -> impl Strategy<Value = KeyEvent> {
    arb_key_code().prop_map(|code| KeyEvent {
        code,
        modifiers: Modifiers::NONE,
        kind: KeyEventKind::Press,
    })
}

fn arb_daemon_state() -> impl Strategy<Value = DaemonState> {
    (0.0f64..100.0, any::<bool>()).prop_map(|(free_pct, pressured)| DaemonState {
        version: "0.1.0".into(),
        pid: 1234,
        started_at: "2026-01-01T00:00:00Z".into(),
        uptime_seconds: 3600,
        last_updated: "2026-01-01T01:00:00Z".into(),
        pressure: PressureState {
            overall: if pressured { "red" } else { "green" }.into(),
            mounts: vec![MountPressure {
                path: "/data".into(),
                free_pct,
                level: if pressured { "red" } else { "green" }.into(),
                rate_bps: Some(if pressured { -5000.0 } else { 100.0 }),
            }],
        },
        ballast: BallastState {
            available: 5,
            total: 10,
            released: 5,
        },
        last_scan: LastScanState {
            at: Some("2026-01-01T00:30:00Z".into()),
            candidates: 10,
            deleted: 2,
        },
        counters: Counters {
            scans: 30,
            deletions: 2,
            bytes_freed: 1_000_000,
            errors: 0,
            dropped_log_events: 0,
        },
        policy_mode: "enforce".into(),
        memory_rss_bytes: 32_000_000,
    })
}

fn arb_timeline_event() -> impl Strategy<Value = TimelineEvent> {
    prop_oneof![Just("info"), Just("warning"), Just("critical")].prop_map(|sev| TimelineEvent {
        timestamp: "2026-01-01T00:00:00Z".to_owned(),
        event_type: "scan".to_owned(),
        severity: sev.to_owned(),
        path: None,
        size_bytes: None,
        score: None,
        pressure_level: None,
        free_pct: None,
        success: None,
        error_code: None,
        error_message: None,
        duration_ms: None,
        details: None,
    })
}

fn arb_decision() -> impl Strategy<Value = DecisionEvidence> {
    (0u64..1000, 0.0f64..10.0, 0u64..100_000, 0u64..86400).prop_map(|(id, score, size, age)| {
        DecisionEvidence {
            decision_id: id,
            timestamp: String::new(),
            path: format!("/test/{id}"),
            size_bytes: size,
            age_secs: age,
            action: "delete".to_owned(),
            effective_action: None,
            policy_mode: "live".to_owned(),
            factors: FactorBreakdown {
                location: 0.5,
                name: 0.5,
                age: 0.5,
                size: 0.5,
                structure: 0.5,
                pressure_multiplier: 1.0,
            },
            total_score: score,
            posterior_abandoned: 0.7,
            expected_loss_keep: 20.0,
            expected_loss_delete: 30.0,
            calibration_score: 0.75,
            vetoed: false,
            veto_reason: None,
            guard_status: None,
            summary: String::new(),
            raw_json: None,
        }
    })
}

fn arb_ballast_volume() -> impl Strategy<Value = BallastVolume> {
    (0usize..20, 0usize..20).prop_map(|(avail, total)| {
        let total = avail.max(total);
        BallastVolume {
            mount_point: "/mnt/test".to_owned(),
            ballast_dir: "/mnt/test/.sbh/ballast".to_owned(),
            fs_type: "ext4".to_owned(),
            strategy: "fallocate".to_owned(),
            files_available: avail,
            files_total: total,
            releasable_bytes: (avail as u64) * 1_073_741_824,
            skipped: false,
            skip_reason: None,
        }
    })
}

/// Generate an arbitrary dashboard message suitable for property testing.
///
/// Excludes Resize (which cannot invalidate invariants) and focuses on
/// messages that exercise state machine transitions.
fn arb_msg() -> impl Strategy<Value = DashboardMsg> {
    prop_oneof![
        // Tick
        Just(DashboardMsg::Tick),
        // Key events
        arb_key_event().prop_map(DashboardMsg::Key),
        // Data updates (Some/None)
        arb_daemon_state().prop_map(|s| DashboardMsg::DataUpdate(Some(Box::new(s)))),
        Just(DashboardMsg::DataUpdate(None)),
        // Direct navigation
        arb_screen().prop_map(DashboardMsg::Navigate),
        Just(DashboardMsg::NavigateBack),
        // Overlays
        Just(DashboardMsg::ToggleOverlay(Overlay::Help)),
        Just(DashboardMsg::ToggleOverlay(Overlay::CommandPalette)),
        Just(DashboardMsg::CloseOverlay),
        // Refresh
        Just(DashboardMsg::ForceRefresh),
        // Errors
        Just(DashboardMsg::Error(DashboardError {
            message: "test error".into(),
            source: "proptest".into(),
        })),
        // Notification expiry (arbitrary ID)
        (0u64..100).prop_map(DashboardMsg::NotificationExpired),
        // Frame metrics
        (0.1f64..100.0).prop_map(|d| DashboardMsg::FrameMetrics { duration_ms: d }),
        // Timeline telemetry (0-10 events)
        prop::collection::vec(arb_timeline_event(), 0..10).prop_map(|events| {
            DashboardMsg::TelemetryTimeline(TelemetryResult {
                data: events,
                source: DataSource::Sqlite,
                partial: false,
                diagnostics: String::new(),
            })
        }),
        // Decision telemetry (0-10 decisions)
        prop::collection::vec(arb_decision(), 0..10).prop_map(|decisions| {
            DashboardMsg::TelemetryDecisions(TelemetryResult {
                data: decisions,
                source: DataSource::Sqlite,
                partial: false,
                diagnostics: String::new(),
            })
        }),
        // Candidate telemetry (0-10 candidates)
        prop::collection::vec(arb_decision(), 0..10).prop_map(|candidates| {
            DashboardMsg::TelemetryCandidates(TelemetryResult {
                data: candidates,
                source: DataSource::Sqlite,
                partial: false,
                diagnostics: String::new(),
            })
        }),
        // Ballast telemetry (0-5 volumes)
        prop::collection::vec(arb_ballast_volume(), 0..5).prop_map(|volumes| {
            DashboardMsg::TelemetryBallast(TelemetryResult {
                data: volumes,
                source: DataSource::Sqlite,
                partial: false,
                diagnostics: String::new(),
            })
        }),
    ]
}

fn fresh_model() -> DashboardModel {
    DashboardModel::new(
        PathBuf::from("/tmp/prop-state.json"),
        vec![],
        Duration::from_secs(1),
        (120, 40),
    )
}

// ──────────────────── invariant checks ────────────────────

/// Assert all model invariants that must hold after any message sequence.
fn assert_model_invariants(model: &DashboardModel) {
    // Screen is a valid variant (1-7).
    let screen_num = model.screen.number();
    assert!(
        (1..=7).contains(&screen_num),
        "screen number {screen_num} out of range"
    );

    // Screen history contains only valid screens.
    for (i, s) in model.screen_history.iter().enumerate() {
        let n = s.number();
        assert!(
            (1..=7).contains(&n),
            "history[{i}] screen number {n} out of range"
        );
    }

    // Notifications bounded.
    assert!(
        model.notifications.len() <= 3,
        "notifications exceed MAX_NOTIFICATIONS: {}",
        model.notifications.len()
    );

    // Notification IDs are monotonically assigned.
    for window in model.notifications.windows(2) {
        assert!(
            window[0].id < window[1].id,
            "notification IDs not monotonic: {} >= {}",
            window[0].id,
            window[1].id
        );
    }

    // Frame times ring buffer bounded.
    assert!(
        model.frame_times.len() <= 60,
        "frame_times exceeded capacity: {}",
        model.frame_times.len()
    );

    // Rate histories bounded per mount.
    for (mount, rh) in &model.rate_histories {
        assert!(
            rh.len() <= 30,
            "rate_history for {mount} exceeded capacity: {}",
            rh.len()
        );
    }

    // Cursor clamping: timeline_selected within bounds.
    if model.timeline_events.is_empty() {
        assert_eq!(
            model.timeline_selected, 0,
            "timeline cursor non-zero with empty events"
        );
    }

    // Cursor clamping: explainability_selected within bounds.
    if model.explainability_decisions.is_empty() {
        assert_eq!(
            model.explainability_selected, 0,
            "explainability cursor non-zero with empty decisions"
        );
    }

    // Cursor clamping: candidates_selected within bounds.
    if model.candidates_list.is_empty() {
        assert_eq!(
            model.candidates_selected, 0,
            "candidates cursor non-zero with empty list"
        );
    }

    // Cursor clamping: ballast_selected within bounds.
    if model.ballast_volumes.is_empty() {
        assert_eq!(
            model.ballast_selected, 0,
            "ballast cursor non-zero with empty volumes"
        );
    }

    // Adapter counters are non-negative (they're u64, so this is always true,
    // but verify the sum makes sense).
    // adapter_reads + adapter_errors should be >= 0 (trivially true for u64).
}

// ──────────────────── property tests ────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Any sequence of 1-50 messages preserves all model invariants.
    #[test]
    fn reducer_preserves_invariants(
        msgs in prop::collection::vec(arb_msg(), 1..50)
    ) {
        let mut model = fresh_model();
        for msg in msgs {
            let _ = update::update(&mut model, msg);
            assert_model_invariants(&model);
        }
    }

    /// The quit flag only transitions from false to true, never back.
    #[test]
    fn quit_is_monotonic(
        msgs in prop::collection::vec(arb_msg(), 1..30)
    ) {
        let mut model = fresh_model();
        let mut ever_quit = false;
        for msg in msgs {
            let _ = update::update(&mut model, msg);
            if model.quit {
                ever_quit = true;
            }
            if ever_quit {
                // Once quit, always quit.
                prop_assert!(model.quit, "quit flag reverted to false after being set");
            }
        }
    }

    /// Screen.next().prev() is always identity.
    #[test]
    fn screen_next_prev_identity(screen in arb_screen()) {
        prop_assert_eq!(screen.next().prev(), screen);
        prop_assert_eq!(screen.prev().next(), screen);
    }

    /// Cycling through all 7 nexts returns to the original screen.
    #[test]
    fn screen_next_cycle_returns_to_start(screen in arb_screen()) {
        let mut s = screen;
        for _ in 0..7 {
            s = s.next();
        }
        prop_assert_eq!(s, screen);
    }

    /// Navigate(screen) then NavigateBack returns to the original screen
    /// (when starting from a different screen).
    #[test]
    fn navigate_then_back_returns(
        start in arb_screen(),
        target in arb_screen()
    ) {
        prop_assume!(start != target);
        let mut model = fresh_model();
        model.screen = start;
        model.screen_history.clear();

        update::update(&mut model, DashboardMsg::Navigate(target));
        prop_assert_eq!(model.screen, target);

        update::update(&mut model, DashboardMsg::NavigateBack);
        prop_assert_eq!(model.screen, start);
    }

    /// Data updates never cause panics regardless of alternation pattern.
    #[test]
    fn data_update_alternation_no_panic(
        pattern in prop::collection::vec(any::<bool>(), 1..100)
    ) {
        let mut model = fresh_model();
        let pattern_len = pattern.len();
        for healthy in pattern {
            if healthy {
                let state = DaemonState {
                    version: "0.1.0".into(),
                    pid: 1,
                    started_at: "2026-01-01T00:00:00Z".into(),
                    uptime_seconds: 0,
                    last_updated: "2026-01-01T00:00:00Z".into(),
                    pressure: PressureState {
                        overall: "green".into(),
                        mounts: vec![MountPressure {
                            path: "/data".into(),
                            free_pct: 50.0,
                            level: "green".into(),
                            rate_bps: Some(0.0),
                        }],
                    },
                    ballast: BallastState { available: 5, total: 10, released: 5 },
                    last_scan: LastScanState { at: None, candidates: 0, deleted: 0 },
                    counters: Counters {
                        scans: 0, deletions: 0, bytes_freed: 0, errors: 0,
                        dropped_log_events: 0,
                    },
                    policy_mode: "enforce".into(),
        memory_rss_bytes: 0,
                };
                update::update(&mut model, DashboardMsg::DataUpdate(Some(Box::new(state))));
            } else {
                update::update(&mut model, DashboardMsg::DataUpdate(None));
            }
        }
        assert_model_invariants(&model);
        // Adapter counters should match the pattern length.
        prop_assert_eq!(
            model.adapter_reads + model.adapter_errors,
            pattern_len as u64
        );
    }

    /// Telemetry cursor clamping: after replacing data with a smaller set,
    /// the cursor must be clamped to the new bounds.
    #[test]
    fn timeline_cursor_clamped_after_shrink(
        initial_count in 5usize..50,
        cursor_pos in 0usize..50,
        shrunk_count in 0usize..5
    ) {
        let mut model = fresh_model();
        // Set up initial timeline data.
        let events: Vec<TimelineEvent> = (0..initial_count)
            .map(|i| TimelineEvent {
                timestamp: format!("2026-01-01T00:00:{:02}Z", i % 60),
                event_type: "scan".to_owned(),
                severity: "info".to_owned(),
                path: None, size_bytes: None, score: None,
                pressure_level: None, free_pct: None, success: None,
                error_code: None, error_message: None, duration_ms: None,
                details: None,
            })
            .collect();
        model.timeline_events = events;
        model.timeline_selected = cursor_pos.min(initial_count - 1);

        // Shrink the data.
        let shrunk: Vec<TimelineEvent> = (0..shrunk_count)
            .map(|i| TimelineEvent {
                timestamp: format!("2026-01-01T00:01:{:02}Z", i % 60),
                event_type: "scan".to_owned(),
                severity: "info".to_owned(),
                path: None, size_bytes: None, score: None,
                pressure_level: None, free_pct: None, success: None,
                error_code: None, error_message: None, duration_ms: None,
                details: None,
            })
            .collect();
        update::update(
            &mut model,
            DashboardMsg::TelemetryTimeline(TelemetryResult {
                data: shrunk,
                source: DataSource::Sqlite,
                partial: false,
                diagnostics: String::new(),
            }),
        );

        // Cursor must be clamped.
        if model.timeline_events.is_empty() {
            prop_assert_eq!(model.timeline_selected, 0);
        } else {
            prop_assert!(
                model.timeline_selected < model.timeline_events.len(),
                "cursor {} >= events len {}",
                model.timeline_selected,
                model.timeline_events.len()
            );
        }
    }

    /// Candidates cursor clamping after data replacement.
    #[test]
    fn candidates_cursor_clamped_after_shrink(
        initial_count in 5usize..50,
        cursor_pos in 0usize..50,
        shrunk_count in 0usize..5
    ) {
        let mut model = fresh_model();
        let candidates: Vec<DecisionEvidence> = (0..initial_count)
            .map(|i| DecisionEvidence {
                decision_id: i as u64,
                timestamp: String::new(),
                path: format!("/test/{i}"),
                size_bytes: 1000,
                age_secs: 60,
                action: "delete".to_owned(),
                effective_action: None,
                policy_mode: "live".to_owned(),
                factors: FactorBreakdown {
                    location: 0.5, name: 0.5, age: 0.5,
                    size: 0.5, structure: 0.5, pressure_multiplier: 1.0,
                },
                total_score: 1.5,
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
            .collect();
        model.candidates_list = candidates;
        model.candidates_selected = cursor_pos.min(initial_count - 1);

        let shrunk: Vec<DecisionEvidence> = (0..shrunk_count)
            .map(|i| DecisionEvidence {
                decision_id: (1000 + i) as u64,
                timestamp: String::new(),
                path: format!("/test/new_{i}"),
                size_bytes: 1000,
                age_secs: 60,
                action: "delete".to_owned(),
                effective_action: None,
                policy_mode: "live".to_owned(),
                factors: FactorBreakdown {
                    location: 0.5, name: 0.5, age: 0.5,
                    size: 0.5, structure: 0.5, pressure_multiplier: 1.0,
                },
                total_score: 1.5,
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
            .collect();
        update::update(
            &mut model,
            DashboardMsg::TelemetryCandidates(TelemetryResult {
                data: shrunk,
                source: DataSource::Sqlite,
                partial: false,
                diagnostics: String::new(),
            }),
        );

        if model.candidates_list.is_empty() {
            prop_assert_eq!(model.candidates_selected, 0);
        } else {
            prop_assert!(
                model.candidates_selected < model.candidates_list.len(),
                "cursor {} >= list len {}",
                model.candidates_selected,
                model.candidates_list.len()
            );
        }
    }

    /// Overlay toggle is idempotent: toggling twice returns to None.
    #[test]
    fn overlay_toggle_idempotent(_unused in 0..1i32) {
        let mut model = fresh_model();
        prop_assert!(model.active_overlay.is_none());

        update::update(
            &mut model,
            DashboardMsg::ToggleOverlay(Overlay::Help),
        );
        prop_assert_eq!(model.active_overlay, Some(Overlay::Help));

        update::update(
            &mut model,
            DashboardMsg::ToggleOverlay(Overlay::Help),
        );
        prop_assert!(model.active_overlay.is_none());
    }

    /// Notification IDs are always strictly monotonically increasing.
    #[test]
    fn notification_ids_monotonic(
        error_count in 1usize..50
    ) {
        let mut model = fresh_model();
        let mut prev_id: Option<u64> = None;
        for i in 0..error_count {
            let id = model.push_notification(
                super::model::NotificationLevel::Error,
                format!("error {i}"),
            );
            if let Some(prev) = prev_id {
                prop_assert!(id > prev, "ID {id} <= previous {prev}");
            }
            prev_id = Some(id);
        }
        assert_model_invariants(&model);
    }

    /// CandidatesSortOrder cycles back to Score after 4 cycles.
    #[test]
    fn sort_order_cycles_back(start_idx in 0u8..4) {
        let start = match start_idx {
            0 => CandidatesSortOrder::Score,
            1 => CandidatesSortOrder::Size,
            2 => CandidatesSortOrder::Age,
            _ => CandidatesSortOrder::Path,
        };
        let mut s = start;
        for _ in 0..4 {
            s = s.cycle();
        }
        prop_assert_eq!(s, start);
    }

    /// SeverityFilter cycles back to All after 4 cycles.
    #[test]
    fn severity_filter_cycles_back(start_idx in 0u8..4) {
        let start = match start_idx {
            0 => super::model::SeverityFilter::All,
            1 => super::model::SeverityFilter::Info,
            2 => super::model::SeverityFilter::Warning,
            _ => super::model::SeverityFilter::Critical,
        };
        let mut f = start;
        for _ in 0..4 {
            f = f.cycle();
        }
        prop_assert_eq!(f, start);
    }

    /// Random key events never panic, even on all screens with/without overlays.
    #[test]
    fn random_keys_never_panic(
        keys in prop::collection::vec(arb_key_event(), 1..100),
        screen in arb_screen()
    ) {
        let mut model = fresh_model();
        model.screen = screen;
        for key in keys {
            let _ = update::update(&mut model, DashboardMsg::Key(key));
        }
        assert_model_invariants(&model);
    }

    /// Frame metrics push never causes ring buffer overflow.
    #[test]
    fn frame_metrics_bounded(
        values in prop::collection::vec(0.1f64..1000.0, 1..200)
    ) {
        let mut model = fresh_model();
        for v in values {
            update::update(&mut model, DashboardMsg::FrameMetrics { duration_ms: v });
        }
        prop_assert!(model.frame_times.len() <= 60);
    }

    /// Resize never panics and preserves terminal dimensions.
    #[test]
    fn resize_preserves_dimensions(
        cols in 20u16..500,
        rows in 10u16..200
    ) {
        let mut model = fresh_model();
        update::update(&mut model, DashboardMsg::Resize { cols, rows });
        prop_assert_eq!(model.terminal_size, (cols, rows));
        assert_model_invariants(&model);
    }

    // ── scheduler / command invariants ──

    /// Tick always produces a Batch containing FetchData and ScheduleTick,
    /// regardless of which screen is active.
    #[test]
    fn tick_always_produces_fetch_and_schedule(screen in arb_screen()) {
        let mut model = fresh_model();
        model.screen = screen;
        let cmd = update::update(&mut model, DashboardMsg::Tick);
        match cmd {
            super::model::DashboardCmd::Batch(ref cmds) => {
                let has_fetch = cmds.iter().any(|c| {
                    matches!(c, super::model::DashboardCmd::FetchData)
                });
                let has_schedule = cmds.iter().any(|c| {
                    matches!(c, super::model::DashboardCmd::ScheduleTick(_))
                });
                prop_assert!(has_fetch, "Tick on {screen:?} missing FetchData");
                prop_assert!(has_schedule, "Tick on {screen:?} missing ScheduleTick");
            }
            _ => prop_assert!(false, "Tick on {screen:?} did not return Batch"),
        }
    }

    /// FetchTelemetry is included in Tick only on telemetry-backed screens
    /// (Timeline, Explainability, Candidates, Ballast).
    #[test]
    fn tick_telemetry_screen_dependent(screen in arb_screen()) {
        let mut model = fresh_model();
        model.screen = screen;
        let cmd = update::update(&mut model, DashboardMsg::Tick);

        let has_telemetry = if let super::model::DashboardCmd::Batch(ref cmds) = cmd {
            cmds.iter().any(|c| matches!(c, super::model::DashboardCmd::FetchTelemetry))
        } else {
            false
        };

        let should_have = matches!(
            screen,
            Screen::Timeline | Screen::Explainability | Screen::Candidates | Screen::Ballast
        );
        prop_assert_eq!(has_telemetry, should_have);
    }

    /// Tick never produces Quit, ExecutePreferenceAction, or
    /// ScheduleNotificationExpiry commands.
    #[test]
    fn tick_never_produces_invalid_commands(screen in arb_screen()) {
        fn check_no_invalid(cmd: &super::model::DashboardCmd) -> bool {
            match cmd {
                super::model::DashboardCmd::Quit
                | super::model::DashboardCmd::ExecutePreferenceAction(_)
                | super::model::DashboardCmd::ScheduleNotificationExpiry { .. } => false,
                super::model::DashboardCmd::Batch(cmds) => cmds.iter().all(check_no_invalid),
                _ => true,
            }
        }

        let mut model = fresh_model();
        model.screen = screen;
        let cmd = update::update(&mut model, DashboardMsg::Tick);
        prop_assert!(check_no_invalid(&cmd), "Tick on {screen:?} produced invalid command");
    }

    // ── overlay invariants ──

    /// When an overlay is active, number-key screen navigation does not
    /// change the current screen.
    #[test]
    fn overlay_blocks_number_key_navigation(
        screen in arb_screen(),
        overlay in prop_oneof![Just(Overlay::Help), Just(Overlay::Voi)],
        number in 1u8..=7
    ) {
        let mut model = fresh_model();
        model.screen = screen;
        model.active_overlay = Some(overlay);

        update::update(&mut model, DashboardMsg::Key(KeyEvent {
            code: KeyCode::Char((b'0' + number) as char),
            modifiers: Modifiers::NONE,
            kind: KeyEventKind::Press,
        }));

        prop_assert_eq!(model.screen, screen);
    }

    // ── history invariants ──

    /// navigate_to only grows history when moving to a different screen,
    /// and navigate_back only shrinks it.
    #[test]
    fn history_grows_and_shrinks_consistently(
        targets in prop::collection::vec(arb_screen(), 1..20)
    ) {
        let mut model = fresh_model();
        let mut expected_depth = 0usize;

        for target in &targets {
            let before = model.screen;
            if model.navigate_to(*target) {
                expected_depth += 1;
                prop_assert_eq!(model.screen_history.len(), expected_depth);
                prop_assert_eq!(*model.screen_history.last().unwrap(), before);
            }
        }

        // Pop everything back.
        while model.navigate_back() {
            expected_depth -= 1;
            prop_assert_eq!(model.screen_history.len(), expected_depth);
        }
        prop_assert_eq!(expected_depth, 0);
    }

    // ── detail pane invariants ──

    /// When telemetry data shrinks to empty, the detail pane closes.
    #[test]
    fn detail_pane_closes_when_data_emptied(variant in 0u8..3) {
        let mut model = fresh_model();
        let empty_result = || TelemetryResult {
            data: vec![],
            source: DataSource::Sqlite,
            partial: false,
            diagnostics: String::new(),
        };

        match variant {
            0 => {
                // Explainability
                model.explainability_decisions = vec![sample_decision(1)];
                model.explainability_detail = true;
                update::update(&mut model, DashboardMsg::TelemetryDecisions(empty_result()));
                prop_assert!(!model.explainability_detail,
                    "explainability detail should close when data emptied");
            }
            1 => {
                // Candidates
                model.candidates_list = vec![sample_decision(2)];
                model.candidates_detail = true;
                update::update(&mut model, DashboardMsg::TelemetryCandidates(empty_result()));
                prop_assert!(!model.candidates_detail,
                    "candidates detail should close when data emptied");
            }
            _ => {
                // Ballast
                model.ballast_volumes = vec![sample_ballast_volume()];
                model.ballast_detail = true;
                update::update(&mut model, DashboardMsg::TelemetryBallast(TelemetryResult {
                    data: vec![],
                    source: DataSource::Sqlite,
                    partial: false,
                    diagnostics: String::new(),
                }));
                prop_assert!(!model.ballast_detail,
                    "ballast detail should close when data emptied");
            }
        }
        assert_model_invariants(&model);
    }

    // ── auto-follow invariants ──

    /// Timeline auto-follow jumps to the last event only when enabled.
    #[test]
    fn timeline_follow_jumps_only_when_enabled(
        events in prop::collection::vec(arb_timeline_event(), 2..20),
        follow in any::<bool>()
    ) {
        let mut model = fresh_model();
        model.timeline_follow = follow;
        model.timeline_selected = 0;

        let event_count = events.len();
        update::update(&mut model, DashboardMsg::TelemetryTimeline(TelemetryResult {
            data: events,
            source: DataSource::Sqlite,
            partial: false,
            diagnostics: String::new(),
        }));

        if follow {
            // With the default SeverityFilter::All, all events pass.
            prop_assert_eq!(model.timeline_selected, event_count.saturating_sub(1),
                "follow mode should jump to last event");
        }
        // When !follow, cursor is clamped but not necessarily at the end.
        prop_assert!(model.timeline_selected < event_count,
            "cursor {0} >= event count {event_count}", model.timeline_selected);
    }

    // ── backpressure stress ──

    /// Rapid tick sequences don't cause unbounded growth in any collection.
    #[test]
    fn rapid_ticks_no_unbounded_growth(
        count in 50usize..500,
        screen in arb_screen()
    ) {
        let mut model = fresh_model();
        model.screen = screen;
        for _ in 0..count {
            let _ = update::update(&mut model, DashboardMsg::Tick);
        }
        // Tick counter wraps (u64, so won't overflow in practice but test the mechanism).
        // Collections must remain bounded.
        assert_model_invariants(&model);
        prop_assert!(model.frame_times.len() <= 60);
        for rh in model.rate_histories.values() {
            prop_assert!(rh.len() <= 30);
        }
    }
}

// ──────────────────── test helpers ────────────────────

fn sample_decision(id: u64) -> DecisionEvidence {
    DecisionEvidence {
        decision_id: id,
        timestamp: String::new(),
        path: format!("/test/{id}"),
        size_bytes: 1000,
        age_secs: 60,
        action: "delete".to_owned(),
        effective_action: None,
        policy_mode: "live".to_owned(),
        factors: FactorBreakdown {
            location: 0.5,
            name: 0.5,
            age: 0.5,
            size: 0.5,
            structure: 0.5,
            pressure_multiplier: 1.0,
        },
        total_score: 1.5,
        posterior_abandoned: 0.7,
        expected_loss_keep: 20.0,
        expected_loss_delete: 30.0,
        calibration_score: 0.75,
        vetoed: false,
        veto_reason: None,
        guard_status: None,
        summary: String::new(),
        raw_json: None,
    }
}

fn sample_ballast_volume() -> BallastVolume {
    BallastVolume {
        mount_point: "/mnt/test".to_owned(),
        ballast_dir: "/mnt/test/.sbh/ballast".to_owned(),
        fs_type: "ext4".to_owned(),
        strategy: "fallocate".to_owned(),
        files_available: 5,
        files_total: 10,
        releasable_bytes: 5_368_709_120,
        skipped: false,
        skip_reason: None,
    }
}

// ──────────────────── non-proptest invariant tests ────────────────────

#[test]
fn screen_from_number_exhaustive() {
    for n in 0u8..=255 {
        let result = Screen::from_number(n);
        if (1..=7).contains(&n) {
            assert!(result.is_some(), "from_number({n}) should be Some");
            assert_eq!(result.unwrap().number(), n);
        } else {
            assert!(result.is_none(), "from_number({n}) should be None");
        }
    }
}

#[test]
fn navigate_back_on_empty_history_is_noop() {
    let mut model = fresh_model();
    assert_eq!(model.screen, Screen::Overview);
    assert!(!model.navigate_back());
    assert_eq!(model.screen, Screen::Overview);
}

#[test]
fn close_overlay_when_none_is_noop() {
    let mut model = fresh_model();
    assert!(model.active_overlay.is_none());
    update::update(&mut model, DashboardMsg::CloseOverlay);
    assert!(model.active_overlay.is_none());
    assert_model_invariants(&model);
}

#[test]
fn notification_expiry_for_nonexistent_id_is_noop() {
    let mut model = fresh_model();
    model.push_notification(super::model::NotificationLevel::Info, "test".into());
    assert_eq!(model.notifications.len(), 1);

    update::update(&mut model, DashboardMsg::NotificationExpired(999));
    assert_eq!(model.notifications.len(), 1);
    assert_model_invariants(&model);
}

#[test]
fn degraded_state_toggles_with_data_updates() {
    let mut model = fresh_model();
    assert!(model.degraded);

    // Healthy update clears degraded.
    update::update(
        &mut model,
        DashboardMsg::DataUpdate(Some(Box::new(DaemonState {
            version: "0.1.0".into(),
            pid: 1,
            started_at: "2026-01-01T00:00:00Z".into(),
            uptime_seconds: 0,
            last_updated: "2026-01-01T00:00:00Z".into(),
            pressure: PressureState {
                overall: "green".into(),
                mounts: vec![],
            },
            ballast: BallastState {
                available: 0,
                total: 0,
                released: 0,
            },
            last_scan: LastScanState {
                at: None,
                candidates: 0,
                deleted: 0,
            },
            counters: Counters {
                scans: 0,
                deletions: 0,
                bytes_freed: 0,
                errors: 0,
                dropped_log_events: 0,
            },
            policy_mode: "enforce".into(),
            memory_rss_bytes: 0,
        }))),
    );
    assert!(!model.degraded);

    // Unavailable re-enters degraded.
    update::update(&mut model, DashboardMsg::DataUpdate(None));
    assert!(model.degraded);
    assert_model_invariants(&model);
}
