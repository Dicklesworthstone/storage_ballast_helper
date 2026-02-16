//! Pure update function for the Elm-style TUI dashboard.
//!
//! `update()` takes the current model and a message, mutates the model, and
//! returns a command describing any side-effects the runtime should execute.
//!
//! **Design invariant:** this module performs zero I/O. All effects are
//! described as [`DashboardCmd`] values.

use std::time::Instant;

use ftui_core::event::KeyCode;

use super::model::{
    DashboardCmd, DashboardModel, DashboardMsg, NotificationLevel, Overlay, RateHistory, Screen,
};

/// Apply a message to the model and return the next command for the runtime.
///
/// This is the core state machine of the dashboard. Every state transition
/// goes through this function, making the dashboard deterministic and testable.
pub fn update(model: &mut DashboardModel, msg: DashboardMsg) -> DashboardCmd {
    match msg {
        DashboardMsg::Tick => {
            model.tick = model.tick.wrapping_add(1);
            DashboardCmd::Batch(vec![
                DashboardCmd::FetchData,
                DashboardCmd::ScheduleTick(model.refresh),
            ])
        }

        DashboardMsg::Key(key) => {
            // Input precedence (IA §4.2):
            // 1. Overlay keys (if overlay is active)
            // 2. Global navigation keys
            if model.active_overlay.is_some() {
                handle_overlay_key(model, key)
            } else {
                handle_global_key(model, key)
            }
        }

        DashboardMsg::Resize { cols, rows } => {
            model.terminal_size = (cols, rows);
            DashboardCmd::None
        }

        DashboardMsg::DataUpdate(state) => {
            model.last_fetch = Some(Instant::now());

            if let Some(ref s) = state {
                model.degraded = false;

                // Update rate histories from mount data.
                let mut active_mounts = Vec::new();
                for mount in &s.pressure.mounts {
                    active_mounts.push(mount.path.clone());
                    model
                        .rate_histories
                        .entry(mount.path.clone())
                        .or_insert_with(|| RateHistory::new(30))
                        .push(mount.rate_bps.unwrap_or(0.0));
                }
                // Prune stale mounts (e.g. unmounted volumes).
                model
                    .rate_histories
                    .retain(|k, _| active_mounts.contains(k));
            } else {
                model.degraded = true;
            }

            model.daemon_state = state.map(|s| *s);
            DashboardCmd::None
        }

        DashboardMsg::Navigate(screen) => {
            model.navigate_to(screen);
            DashboardCmd::None
        }

        DashboardMsg::NavigateBack => {
            model.navigate_back();
            DashboardCmd::None
        }

        DashboardMsg::ToggleOverlay(overlay) => {
            if model.active_overlay.as_ref() == Some(&overlay) {
                model.active_overlay = None;
            } else {
                model.active_overlay = Some(overlay);
            }
            DashboardCmd::None
        }

        DashboardMsg::CloseOverlay => {
            model.active_overlay = None;
            DashboardCmd::None
        }

        DashboardMsg::ForceRefresh => DashboardCmd::FetchData,

        DashboardMsg::NotificationExpired(id) => {
            model.notifications.retain(|n| n.id != id);
            DashboardCmd::None
        }

        DashboardMsg::Error(err) => {
            let id = model.push_notification(NotificationLevel::Error, err.message);
            DashboardCmd::ScheduleNotificationExpiry {
                id,
                after: std::time::Duration::from_secs(10),
            }
        }
    }
}

// ──────────────────── key handlers ────────────────────

/// Handle keys when an overlay is active (IA §4.2 precedence level 2).
///
/// Overlays consume most keys. Only Esc (close), Ctrl-C (quit), and the
/// overlay's own toggle key pass through.
fn handle_overlay_key(model: &mut DashboardModel, key: ftui_core::event::KeyEvent) -> DashboardCmd {
    match key.code {
        // Ctrl-C always quits, regardless of overlay state.
        KeyCode::Char('c') if key.ctrl() => {
            model.quit = true;
            DashboardCmd::Quit
        }
        // Esc closes the active overlay.
        KeyCode::Escape => {
            model.active_overlay = None;
            DashboardCmd::None
        }
        // Toggle keys: pressing the same overlay key closes it.
        KeyCode::Char('?') if model.active_overlay == Some(Overlay::Help) => {
            model.active_overlay = None;
            DashboardCmd::None
        }
        KeyCode::Char('v') if model.active_overlay == Some(Overlay::Voi) => {
            model.active_overlay = None;
            DashboardCmd::None
        }
        KeyCode::Char('p')
            if key.ctrl() && model.active_overlay == Some(Overlay::CommandPalette) =>
        {
            model.active_overlay = None;
            DashboardCmd::None
        }
        // All other keys are consumed by the overlay (no screen passthrough).
        _ => DashboardCmd::None,
    }
}

/// Handle global keys when no overlay is active (IA §4.1 + §4.2 level 4).
fn handle_global_key(model: &mut DashboardModel, key: ftui_core::event::KeyEvent) -> DashboardCmd {
    match key.code {
        // ── Exit keys ──
        // Ctrl-C: always immediate quit.
        KeyCode::Char('c') if key.ctrl() => {
            model.quit = true;
            DashboardCmd::Quit
        }
        // q: quit from any non-overlay state.
        KeyCode::Char('q') => {
            model.quit = true;
            DashboardCmd::Quit
        }
        // Esc: cascade — navigate back first, quit only if nowhere to go.
        KeyCode::Escape => {
            if model.navigate_back() {
                DashboardCmd::None
            } else {
                model.quit = true;
                DashboardCmd::Quit
            }
        }

        // ── Screen navigation: number keys 1-7 (IA §4.1) ──
        KeyCode::Char(c @ '1'..='7') => {
            if let Some(screen) = Screen::from_number(c as u8 - b'0') {
                model.navigate_to(screen);
            }
            DashboardCmd::None
        }

        // ── Screen navigation: [/] for prev/next (IA §4.1) ──
        KeyCode::Char('[') => {
            let prev = model.screen.prev();
            model.navigate_to(prev);
            DashboardCmd::None
        }
        KeyCode::Char(']') => {
            let next = model.screen.next();
            model.navigate_to(next);
            DashboardCmd::None
        }

        // ── Overlay toggles ──
        KeyCode::Char('?') => {
            model.active_overlay = Some(Overlay::Help);
            DashboardCmd::None
        }
        KeyCode::Char('v') => {
            model.active_overlay = Some(Overlay::Voi);
            DashboardCmd::None
        }
        KeyCode::Char('p') if key.ctrl() => {
            model.active_overlay = Some(Overlay::CommandPalette);
            DashboardCmd::None
        }
        KeyCode::Char(':') => {
            model.active_overlay = Some(Overlay::CommandPalette);
            DashboardCmd::None
        }

        // ── Quick actions ──
        // b: jump to ballast screen (J-2 fast path, IA §4.1).
        KeyCode::Char('b') => {
            model.navigate_to(Screen::Ballast);
            DashboardCmd::None
        }
        // r: force refresh (bypass timer).
        KeyCode::Char('r') => DashboardCmd::FetchData,

        // Unhandled keys are no-ops.
        _ => DashboardCmd::None,
    }
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use ftui_core::event::{KeyCode, KeyEvent, KeyEventKind, Modifiers};

    use super::*;
    use crate::daemon::self_monitor::{
        BallastState, Counters, DaemonState, LastScanState, MountPressure, PressureState,
    };
    use crate::tui::model::DashboardError;

    fn test_model() -> DashboardModel {
        DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (80, 24),
        )
    }

    fn make_key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: Modifiers::NONE,
            kind: KeyEventKind::Press,
        }
    }

    fn make_key_ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: Modifiers::CTRL,
            kind: KeyEventKind::Press,
        }
    }

    fn sample_daemon_state() -> DaemonState {
        DaemonState {
            version: String::from("0.1.0"),
            pid: 1234,
            started_at: String::from("2026-02-16T00:00:00Z"),
            uptime_seconds: 3600,
            last_updated: String::from("2026-02-16T01:00:00Z"),
            pressure: PressureState {
                overall: String::from("yellow"),
                mounts: vec![MountPressure {
                    path: String::from("/"),
                    free_pct: 45.0,
                    level: String::from("yellow"),
                    rate_bps: Some(1024.0),
                }],
            },
            ballast: BallastState {
                available: 3,
                total: 5,
                released: 2,
            },
            last_scan: LastScanState {
                at: Some(String::from("2026-02-16T00:59:00Z")),
                candidates: 12,
                deleted: 3,
            },
            counters: Counters {
                scans: 100,
                deletions: 25,
                bytes_freed: 1_073_741_824,
                errors: 0,
                dropped_log_events: 0,
            },
            memory_rss_bytes: 52_428_800,
        }
    }

    // ── Tick / timer ──

    #[test]
    fn tick_increments_counter_and_fetches_data() {
        let mut model = test_model();
        assert_eq!(model.tick, 0);

        let cmd = update(&mut model, DashboardMsg::Tick);
        assert_eq!(model.tick, 1);
        assert!(matches!(cmd, DashboardCmd::Batch(_)));
    }

    #[test]
    fn tick_wraps_at_u64_max() {
        let mut model = test_model();
        model.tick = u64::MAX;
        update(&mut model, DashboardMsg::Tick);
        assert_eq!(model.tick, 0);
    }

    // ── Exit keys ──

    #[test]
    fn quit_on_q_key() {
        let mut model = test_model();
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('q'))));
        assert!(model.quit);
        assert!(matches!(cmd, DashboardCmd::Quit));
    }

    #[test]
    fn esc_quits_when_no_history() {
        let mut model = test_model();
        assert!(model.screen_history.is_empty());
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Escape)));
        assert!(model.quit);
        assert!(matches!(cmd, DashboardCmd::Quit));
    }

    #[test]
    fn esc_navigates_back_when_history_exists() {
        let mut model = test_model();
        model.navigate_to(Screen::Timeline);
        assert_eq!(model.screen, Screen::Timeline);
        assert!(!model.screen_history.is_empty());

        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Escape)));
        assert!(!model.quit);
        assert_eq!(model.screen, Screen::Overview);
        assert!(matches!(cmd, DashboardCmd::None));
    }

    #[test]
    fn esc_cascade_back_then_quit() {
        let mut model = test_model();
        model.navigate_to(Screen::Timeline);
        model.navigate_to(Screen::Candidates);

        // First Esc: back to Timeline.
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Escape)));
        assert_eq!(model.screen, Screen::Timeline);
        assert!(!model.quit);

        // Second Esc: back to Overview.
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Escape)));
        assert_eq!(model.screen, Screen::Overview);
        assert!(!model.quit);

        // Third Esc: quit (no more history).
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Escape)));
        assert!(model.quit);
        assert!(matches!(cmd, DashboardCmd::Quit));
    }

    #[test]
    fn ctrl_c_always_quits() {
        let mut model = test_model();
        let cmd = update(
            &mut model,
            DashboardMsg::Key(make_key_ctrl(KeyCode::Char('c'))),
        );
        assert!(model.quit);
        assert!(matches!(cmd, DashboardCmd::Quit));
    }

    #[test]
    fn ctrl_c_quits_even_with_overlay_active() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::Help);

        let cmd = update(
            &mut model,
            DashboardMsg::Key(make_key_ctrl(KeyCode::Char('c'))),
        );
        assert!(model.quit);
        assert!(matches!(cmd, DashboardCmd::Quit));
    }

    // ── Screen navigation: number keys ──

    #[test]
    fn number_keys_navigate_to_screens() {
        let mut model = test_model();
        for (key, expected) in [
            ('1', Screen::Overview),
            ('2', Screen::Timeline),
            ('3', Screen::Explainability),
            ('4', Screen::Candidates),
            ('5', Screen::Ballast),
            ('6', Screen::LogSearch),
            ('7', Screen::Diagnostics),
        ] {
            model.screen = Screen::Overview;
            model.screen_history.clear();
            update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char(key))));
            assert_eq!(
                model.screen, expected,
                "key '{key}' should navigate to {expected:?}"
            );
        }
    }

    #[test]
    fn number_key_same_screen_is_noop() {
        let mut model = test_model();
        assert_eq!(model.screen, Screen::Overview);
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('1'))));
        assert_eq!(model.screen, Screen::Overview);
        assert!(model.screen_history.is_empty());
    }

    #[test]
    fn number_key_pushes_history() {
        let mut model = test_model();
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('3'))));
        assert_eq!(model.screen, Screen::Explainability);
        assert_eq!(model.screen_history, vec![Screen::Overview]);
    }

    // ── Screen navigation: [/] bracket keys ──

    #[test]
    fn bracket_right_navigates_next() {
        let mut model = test_model();
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char(']'))));
        assert_eq!(model.screen, Screen::Timeline);
    }

    #[test]
    fn bracket_left_navigates_prev() {
        let mut model = test_model();
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('['))));
        assert_eq!(model.screen, Screen::Diagnostics); // wraps S1 → S7
    }

    #[test]
    fn bracket_keys_wrap_around() {
        let mut model = test_model();
        model.screen = Screen::Diagnostics;
        model.screen_history.clear();
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char(']'))));
        assert_eq!(model.screen, Screen::Overview); // wraps S7 → S1
    }

    // ── Overlay toggles ──

    #[test]
    fn question_mark_opens_help_overlay() {
        let mut model = test_model();
        assert!(model.active_overlay.is_none());
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('?'))));
        assert_eq!(model.active_overlay, Some(Overlay::Help));
    }

    #[test]
    fn v_opens_voi_overlay() {
        let mut model = test_model();
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('v'))));
        assert_eq!(model.active_overlay, Some(Overlay::Voi));
    }

    #[test]
    fn ctrl_p_opens_command_palette() {
        let mut model = test_model();
        update(
            &mut model,
            DashboardMsg::Key(make_key_ctrl(KeyCode::Char('p'))),
        );
        assert_eq!(model.active_overlay, Some(Overlay::CommandPalette));
    }

    #[test]
    fn colon_opens_command_palette() {
        let mut model = test_model();
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char(':'))));
        assert_eq!(model.active_overlay, Some(Overlay::CommandPalette));
    }

    // ── Overlay key handling (input precedence) ──

    #[test]
    fn overlay_esc_closes_overlay_without_quit() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::Help);

        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Escape)));
        assert!(model.active_overlay.is_none());
        assert!(!model.quit);
        assert!(matches!(cmd, DashboardCmd::None));
    }

    #[test]
    fn overlay_consumes_navigation_keys() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::Help);

        // Number keys should NOT navigate when overlay is active.
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('3'))));
        assert_eq!(model.screen, Screen::Overview);
        assert!(model.active_overlay.is_some());
    }

    #[test]
    fn overlay_consumes_q_key() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::Voi);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('q'))));
        assert!(!model.quit);
        assert!(model.active_overlay.is_some());
    }

    #[test]
    fn help_overlay_toggle_closes_with_question_mark() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::Help);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('?'))));
        assert!(model.active_overlay.is_none());
    }

    #[test]
    fn voi_overlay_toggle_closes_with_v() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::Voi);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('v'))));
        assert!(model.active_overlay.is_none());
    }

    #[test]
    fn command_palette_toggle_closes_with_ctrl_p() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::CommandPalette);

        update(
            &mut model,
            DashboardMsg::Key(make_key_ctrl(KeyCode::Char('p'))),
        );
        assert!(model.active_overlay.is_none());
    }

    // ── Quick actions ──

    #[test]
    fn b_key_jumps_to_ballast_screen() {
        let mut model = test_model();
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('b'))));
        assert_eq!(model.screen, Screen::Ballast);
        assert_eq!(model.screen_history, vec![Screen::Overview]);
    }

    #[test]
    fn r_key_forces_data_refresh() {
        let mut model = test_model();
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('r'))));
        assert!(matches!(cmd, DashboardCmd::FetchData));
    }

    // ── Message-based navigation ──

    #[test]
    fn navigate_msg_changes_screen() {
        let mut model = test_model();
        update(&mut model, DashboardMsg::Navigate(Screen::LogSearch));
        assert_eq!(model.screen, Screen::LogSearch);
        assert_eq!(model.screen_history, vec![Screen::Overview]);
    }

    #[test]
    fn navigate_back_msg_pops_history() {
        let mut model = test_model();
        model.navigate_to(Screen::Diagnostics);
        update(&mut model, DashboardMsg::NavigateBack);
        assert_eq!(model.screen, Screen::Overview);
    }

    #[test]
    fn toggle_overlay_msg() {
        let mut model = test_model();
        update(&mut model, DashboardMsg::ToggleOverlay(Overlay::Help));
        assert_eq!(model.active_overlay, Some(Overlay::Help));

        // Toggle again closes it.
        update(&mut model, DashboardMsg::ToggleOverlay(Overlay::Help));
        assert!(model.active_overlay.is_none());
    }

    #[test]
    fn close_overlay_msg() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::Voi);
        update(&mut model, DashboardMsg::CloseOverlay);
        assert!(model.active_overlay.is_none());
    }

    #[test]
    fn force_refresh_msg_returns_fetch_data() {
        let mut model = test_model();
        let cmd = update(&mut model, DashboardMsg::ForceRefresh);
        assert!(matches!(cmd, DashboardCmd::FetchData));
    }

    // ── Notifications ──

    #[test]
    fn error_msg_creates_notification() {
        let mut model = test_model();
        let cmd = update(
            &mut model,
            DashboardMsg::Error(DashboardError {
                message: "adapter failed".into(),
                source: "state_file".into(),
            }),
        );
        assert_eq!(model.notifications.len(), 1);
        assert_eq!(model.notifications[0].message, "adapter failed");
        assert!(matches!(
            cmd,
            DashboardCmd::ScheduleNotificationExpiry { .. }
        ));
    }

    #[test]
    fn notification_expired_removes_notification() {
        let mut model = test_model();
        let id = model.push_notification(NotificationLevel::Info, "test".into());
        assert_eq!(model.notifications.len(), 1);

        update(&mut model, DashboardMsg::NotificationExpired(id));
        assert!(model.notifications.is_empty());
    }

    #[test]
    fn notification_expired_with_wrong_id_is_noop() {
        let mut model = test_model();
        model.push_notification(NotificationLevel::Info, "test".into());
        update(&mut model, DashboardMsg::NotificationExpired(999));
        assert_eq!(model.notifications.len(), 1);
    }

    // ── Data updates ──

    #[test]
    fn data_update_with_state_clears_degraded() {
        let mut model = test_model();
        assert!(model.degraded);

        let cmd = update(
            &mut model,
            DashboardMsg::DataUpdate(Some(Box::new(sample_daemon_state()))),
        );
        assert!(!model.degraded);
        assert!(model.daemon_state.is_some());
        assert!(model.last_fetch.is_some());
        assert!(matches!(cmd, DashboardCmd::None));
    }

    #[test]
    fn data_update_none_sets_degraded() {
        let mut model = test_model();
        update(
            &mut model,
            DashboardMsg::DataUpdate(Some(Box::new(sample_daemon_state()))),
        );
        assert!(!model.degraded);

        update(&mut model, DashboardMsg::DataUpdate(None));
        assert!(model.degraded);
        assert!(model.daemon_state.is_none());
    }

    #[test]
    fn data_update_populates_rate_histories() {
        let mut model = test_model();
        assert!(model.rate_histories.is_empty());

        update(
            &mut model,
            DashboardMsg::DataUpdate(Some(Box::new(sample_daemon_state()))),
        );
        assert!(model.rate_histories.contains_key("/"));
        assert_eq!(model.rate_histories["/"].latest(), Some(1024.0));
    }

    #[test]
    fn stale_mounts_pruned_on_data_update() {
        let mut model = test_model();

        update(
            &mut model,
            DashboardMsg::DataUpdate(Some(Box::new(sample_daemon_state()))),
        );
        assert!(model.rate_histories.contains_key("/"));

        let mut empty_state = sample_daemon_state();
        empty_state.pressure.mounts.clear();
        update(
            &mut model,
            DashboardMsg::DataUpdate(Some(Box::new(empty_state))),
        );
        assert!(model.rate_histories.is_empty());
    }

    #[test]
    fn resize_updates_terminal_size() {
        let mut model = test_model();
        let cmd = update(
            &mut model,
            DashboardMsg::Resize {
                cols: 120,
                rows: 40,
            },
        );
        assert_eq!(model.terminal_size, (120, 40));
        assert!(matches!(cmd, DashboardCmd::None));
    }

    #[test]
    fn unknown_key_is_noop() {
        let mut model = test_model();
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('z'))));
        assert!(!model.quit);
        assert!(matches!(cmd, DashboardCmd::None));
    }

    // ── Determinism: same input → same output ──

    #[test]
    fn deterministic_navigation_sequence() {
        // Two models given the same message sequence must end in the same state.
        let msgs: Vec<DashboardMsg> = vec![
            DashboardMsg::Key(make_key(KeyCode::Char('3'))),
            DashboardMsg::Key(make_key(KeyCode::Char('5'))),
            DashboardMsg::Key(make_key(KeyCode::Escape)),
            DashboardMsg::Key(make_key(KeyCode::Char('['))),
            DashboardMsg::Key(make_key(KeyCode::Char('?'))),
            DashboardMsg::Key(make_key(KeyCode::Escape)),
            DashboardMsg::Key(make_key(KeyCode::Char('1'))),
        ];

        let mut m1 = test_model();
        let mut m2 = test_model();

        for (msg1, msg2) in msgs.into_iter().zip({
            // Reconstruct the same sequence.
            vec![
                DashboardMsg::Key(make_key(KeyCode::Char('3'))),
                DashboardMsg::Key(make_key(KeyCode::Char('5'))),
                DashboardMsg::Key(make_key(KeyCode::Escape)),
                DashboardMsg::Key(make_key(KeyCode::Char('['))),
                DashboardMsg::Key(make_key(KeyCode::Char('?'))),
                DashboardMsg::Key(make_key(KeyCode::Escape)),
                DashboardMsg::Key(make_key(KeyCode::Char('1'))),
            ]
        }) {
            update(&mut m1, msg1);
            update(&mut m2, msg2);
        }

        assert_eq!(m1.screen, m2.screen);
        assert_eq!(m1.screen_history, m2.screen_history);
        assert_eq!(m1.active_overlay, m2.active_overlay);
        assert_eq!(m1.quit, m2.quit);
        assert_eq!(m1.tick, m2.tick);
    }

    #[test]
    fn deterministic_full_cycle() {
        // Navigate through all screens, end at Overview.
        let mut model = test_model();
        for n in b'2'..=b'7' {
            update(
                &mut model,
                DashboardMsg::Key(make_key(KeyCode::Char(n as char))),
            );
        }
        assert_eq!(model.screen, Screen::Diagnostics);
        assert_eq!(model.screen_history.len(), 6);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('1'))));
        assert_eq!(model.screen, Screen::Overview);
        assert_eq!(model.screen_history.len(), 7);
    }
}
