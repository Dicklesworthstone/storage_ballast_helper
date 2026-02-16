//! Pure update function for the Elm-style TUI dashboard.
//!
//! `update()` takes the current model and a message, mutates the model, and
//! returns a command describing any side-effects the runtime should execute.
//!
//! **Design invariant:** this module performs zero I/O. All effects are
//! described as [`DashboardCmd`] values.

use std::time::Instant;

use ftui_core::event::KeyCode;

use super::input::{InputAction, InputContext};
use super::model::{
    DashboardCmd, DashboardModel, DashboardMsg, NotificationLevel, RateHistory, Screen,
};

/// Apply a message to the model and return the next command for the runtime.
///
/// This is the core state machine of the dashboard. Every state transition
/// goes through this function, making the dashboard deterministic and testable.
pub fn update(model: &mut DashboardModel, msg: DashboardMsg) -> DashboardCmd {
    match msg {
        DashboardMsg::Tick => {
            model.tick = model.tick.wrapping_add(1);
            let mut cmds = vec![
                DashboardCmd::FetchData,
                DashboardCmd::ScheduleTick(model.refresh),
            ];
            // Request telemetry data when on a screen that needs it.
            if matches!(
                model.screen,
                Screen::Timeline
                    | Screen::Explainability
                    | Screen::Candidates
                    | Screen::Ballast
            ) {
                cmds.push(DashboardCmd::FetchTelemetry);
            }
            DashboardCmd::Batch(cmds)
        }

        DashboardMsg::Key(key) => {
            // Route through the centralized input layer (IA §4.2).
            // Overlay keys → global keys → screen-specific keys.
            let context = InputContext {
                screen: model.screen,
                active_overlay: model.active_overlay,
            };
            let resolution = super::input::resolve_key_event(&key, context);
            if let Some(action) = resolution.action {
                apply_input_action(model, action)
            } else if resolution.consumed {
                // Overlay consumed the key without producing an action.
                DashboardCmd::None
            } else {
                // Passthrough: delegate to screen-specific handlers.
                handle_screen_key(model, key)
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
                model.adapter_reads += 1;

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
                model.adapter_errors += 1;
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

        DashboardMsg::TelemetryTimeline(result) => {
            model.timeline_source = result.source;
            model.timeline_partial = result.partial;
            model.timeline_diagnostics = result.diagnostics;
            model.timeline_events = result.data;
            // Clamp cursor to valid range after data refresh.
            let filtered_len = model.timeline_filtered_events().len();
            if filtered_len == 0 {
                model.timeline_selected = 0;
            } else if model.timeline_selected >= filtered_len {
                model.timeline_selected = filtered_len - 1;
            }
            // Auto-follow: jump to latest event.
            if model.timeline_follow && filtered_len > 0 {
                model.timeline_selected = filtered_len - 1;
            }
            DashboardCmd::None
        }

        DashboardMsg::TelemetryDecisions(result) => {
            model.explainability_source = result.source;
            model.explainability_partial = result.partial;
            model.explainability_diagnostics = result.diagnostics;
            model.explainability_decisions = result.data;
            // Clamp cursor to valid range after data refresh.
            if model.explainability_decisions.is_empty() {
                model.explainability_selected = 0;
                model.explainability_detail = false;
            } else if model.explainability_selected >= model.explainability_decisions.len() {
                model.explainability_selected = model.explainability_decisions.len() - 1;
            }
            DashboardCmd::None
        }

        DashboardMsg::TelemetryCandidates(result) => {
            model.candidates_source = result.source;
            model.candidates_partial = result.partial;
            model.candidates_diagnostics = result.diagnostics;
            model.candidates_list = result.data;
            // Apply current sort order to incoming data.
            model.candidates_apply_sort();
            // Clamp cursor to valid range after data refresh.
            if model.candidates_list.is_empty() {
                model.candidates_selected = 0;
                model.candidates_detail = false;
            } else if model.candidates_selected >= model.candidates_list.len() {
                model.candidates_selected = model.candidates_list.len() - 1;
            }
            DashboardCmd::None
        }

        DashboardMsg::FrameMetrics { duration_ms } => {
            model.frame_times.push(duration_ms);
            DashboardCmd::None
        }

        DashboardMsg::TelemetryBallast(result) => {
            model.ballast_source = result.source;
            model.ballast_partial = result.partial;
            model.ballast_diagnostics = result.diagnostics;
            model.ballast_volumes = result.data;
            // Clamp cursor to valid range after data refresh.
            if model.ballast_volumes.is_empty() {
                model.ballast_selected = 0;
                model.ballast_detail = false;
            } else if model.ballast_selected >= model.ballast_volumes.len() {
                model.ballast_selected = model.ballast_volumes.len() - 1;
            }
            DashboardCmd::None
        }
    }
}

// ──────────────────── key handlers ────────────────────

/// Translate a resolved [`InputAction`] into model mutations and a command.
///
/// This is the single authority for global key-action semantics. Screen-specific
/// keys (j/k/f/s/etc.) are handled separately in [`handle_screen_key`].
fn apply_input_action(model: &mut DashboardModel, action: InputAction) -> DashboardCmd {
    match action {
        InputAction::Quit => {
            model.quit = true;
            DashboardCmd::Quit
        }
        InputAction::BackOrQuit => {
            if model.navigate_back() {
                DashboardCmd::None
            } else {
                model.quit = true;
                DashboardCmd::Quit
            }
        }
        InputAction::CloseOverlay => {
            model.palette_reset();
            model.active_overlay = None;
            DashboardCmd::None
        }
        InputAction::Navigate(screen) => {
            model.navigate_to(screen);
            DashboardCmd::None
        }
        InputAction::NavigatePrev => {
            let prev = model.screen.prev();
            model.navigate_to(prev);
            DashboardCmd::None
        }
        InputAction::NavigateNext => {
            let next = model.screen.next();
            model.navigate_to(next);
            DashboardCmd::None
        }
        InputAction::OpenOverlay(overlay) => {
            model.palette_reset();
            model.active_overlay = Some(overlay);
            DashboardCmd::None
        }
        InputAction::ToggleOverlay(overlay) => {
            if model.active_overlay.as_ref() == Some(&overlay) {
                model.palette_reset();
                model.active_overlay = None;
            } else {
                model.palette_reset();
                model.active_overlay = Some(overlay);
            }
            DashboardCmd::None
        }
        InputAction::ForceRefresh => DashboardCmd::FetchData,
        InputAction::JumpBallast => {
            model.navigate_to(Screen::Ballast);
            DashboardCmd::None
        }
        InputAction::PaletteType(c) => {
            model.palette_query.push(c);
            palette_clamp_cursor(model);
            DashboardCmd::None
        }
        InputAction::PaletteBackspace => {
            model.palette_query.pop();
            palette_clamp_cursor(model);
            DashboardCmd::None
        }
        InputAction::PaletteExecute => {
            let results =
                super::input::search_palette_actions(&model.palette_query, PALETTE_RESULT_LIMIT);
            if let Some(selected) = results.get(model.palette_selected) {
                let action = selected.action;
                model.active_overlay = None;
                model.palette_reset();
                apply_input_action(model, action)
            } else {
                DashboardCmd::None
            }
        }
        InputAction::PaletteCursorUp => {
            if model.palette_selected > 0 {
                model.palette_selected -= 1;
            }
            DashboardCmd::None
        }
        InputAction::PaletteCursorDown => {
            let result_count =
                super::input::search_palette_actions(&model.palette_query, PALETTE_RESULT_LIMIT)
                    .len();
            if result_count > 0 && model.palette_selected < result_count - 1 {
                model.palette_selected += 1;
            }
            DashboardCmd::None
        }
    }
}

const PALETTE_RESULT_LIMIT: usize = 15;

fn palette_clamp_cursor(model: &mut DashboardModel) {
    let count =
        super::input::search_palette_actions(&model.palette_query, PALETTE_RESULT_LIMIT).len();
    if count == 0 {
        model.palette_selected = 0;
    } else if model.palette_selected >= count {
        model.palette_selected = count - 1;
    }
}

/// Dispatch screen-specific keys that are not global navigation.
fn handle_screen_key(model: &mut DashboardModel, key: ftui_core::event::KeyEvent) -> DashboardCmd {
    match model.screen {
        Screen::Timeline => handle_timeline_key(model, key),
        Screen::Explainability => handle_explainability_key(model, key),
        Screen::Candidates => handle_candidates_key(model, key),
        Screen::Diagnostics => handle_diagnostics_key(model, key),
        Screen::Ballast => handle_ballast_key(model, key),
        _ => DashboardCmd::None,
    }
}

/// Handle keys specific to the Timeline screen (S2).
fn handle_timeline_key(
    model: &mut DashboardModel,
    key: ftui_core::event::KeyEvent,
) -> DashboardCmd {
    match key.code {
        // Up/k: move cursor up in the event list.
        KeyCode::Up | KeyCode::Char('k') => {
            model.timeline_cursor_up();
            DashboardCmd::None
        }
        // Down/j: move cursor down in the event list.
        KeyCode::Down | KeyCode::Char('j') => {
            model.timeline_cursor_down();
            DashboardCmd::None
        }
        // f: cycle severity filter (All → Info → Warning → Critical → All).
        KeyCode::Char('f') => {
            model.timeline_cycle_filter();
            DashboardCmd::None
        }
        // F (shift-f): toggle follow mode.
        KeyCode::Char('F') => {
            model.timeline_toggle_follow();
            DashboardCmd::None
        }
        _ => DashboardCmd::None,
    }
}

/// Handle keys specific to the Explainability screen (S3).
fn handle_explainability_key(
    model: &mut DashboardModel,
    key: ftui_core::event::KeyEvent,
) -> DashboardCmd {
    match key.code {
        // Up/k: move cursor up in the decisions list.
        KeyCode::Up | KeyCode::Char('k') => {
            model.explainability_cursor_up();
            DashboardCmd::None
        }
        // Down/j: move cursor down in the decisions list.
        KeyCode::Down | KeyCode::Char('j') => {
            model.explainability_cursor_down();
            DashboardCmd::None
        }
        // Enter/Space: toggle detail pane for selected decision.
        KeyCode::Enter | KeyCode::Char(' ') => {
            model.explainability_toggle_detail();
            DashboardCmd::None
        }
        // d: close detail pane (if open).
        KeyCode::Char('d') => {
            if model.explainability_detail {
                model.explainability_detail = false;
            }
            DashboardCmd::None
        }
        _ => DashboardCmd::None,
    }
}

/// Handle keys specific to the Candidates screen (S4).
fn handle_candidates_key(
    model: &mut DashboardModel,
    key: ftui_core::event::KeyEvent,
) -> DashboardCmd {
    match key.code {
        // Up/k: move cursor up in the candidates list.
        KeyCode::Up | KeyCode::Char('k') => {
            model.candidates_cursor_up();
            DashboardCmd::None
        }
        // Down/j: move cursor down in the candidates list.
        KeyCode::Down | KeyCode::Char('j') => {
            model.candidates_cursor_down();
            DashboardCmd::None
        }
        // Enter/Space: toggle detail pane for selected candidate.
        KeyCode::Enter | KeyCode::Char(' ') => {
            model.candidates_toggle_detail();
            DashboardCmd::None
        }
        // d: close detail pane (if open).
        KeyCode::Char('d') => {
            if model.candidates_detail {
                model.candidates_detail = false;
            }
            DashboardCmd::None
        }
        // s: cycle sort order.
        KeyCode::Char('s') => {
            model.candidates_cycle_sort();
            DashboardCmd::None
        }
        _ => DashboardCmd::None,
    }
}

/// Handle keys specific to the Ballast screen (S5).
fn handle_ballast_key(
    model: &mut DashboardModel,
    key: ftui_core::event::KeyEvent,
) -> DashboardCmd {
    match key.code {
        // Up/k: move cursor up in the volumes list.
        KeyCode::Up | KeyCode::Char('k') => {
            model.ballast_cursor_up();
            DashboardCmd::None
        }
        // Down/j: move cursor down in the volumes list.
        KeyCode::Down | KeyCode::Char('j') => {
            model.ballast_cursor_down();
            DashboardCmd::None
        }
        // Enter/Space: toggle detail pane for selected volume.
        KeyCode::Enter | KeyCode::Char(' ') => {
            model.ballast_toggle_detail();
            DashboardCmd::None
        }
        // d: close detail pane (if open).
        KeyCode::Char('d') => {
            if model.ballast_detail {
                model.ballast_detail = false;
            }
            DashboardCmd::None
        }
        _ => DashboardCmd::None,
    }
}

/// Handle keys specific to the Diagnostics screen (S7).
fn handle_diagnostics_key(
    model: &mut DashboardModel,
    key: ftui_core::event::KeyEvent,
) -> DashboardCmd {
    match key.code {
        // V (shift-v): toggle verbose diagnostics mode.
        KeyCode::Char('V') => {
            model.diagnostics_toggle_verbose();
            DashboardCmd::None
        }
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
    use crate::tui::model::{DashboardError, Overlay};
    use crate::tui::telemetry::DataSource;

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

    // ── S3 Explainability key handling tests ──

    use crate::tui::telemetry::{DecisionEvidence, FactorBreakdown, TelemetryResult};

    fn sample_decision(id: u64) -> DecisionEvidence {
        DecisionEvidence {
            decision_id: id,
            timestamp: String::from("2026-02-16T03:15:42Z"),
            path: String::from("/data/projects/test/target"),
            size_bytes: 100_000,
            age_secs: 3600,
            action: String::from("delete"),
            effective_action: Some(String::from("delete")),
            policy_mode: String::from("live"),
            factors: FactorBreakdown {
                location: 0.8,
                name: 0.7,
                age: 0.9,
                size: 0.5,
                structure: 0.8,
                pressure_multiplier: 1.2,
            },
            total_score: 2.0,
            posterior_abandoned: 0.85,
            expected_loss_keep: 25.0,
            expected_loss_delete: 15.0,
            calibration_score: 0.80,
            vetoed: false,
            veto_reason: None,
            guard_status: None,
            summary: String::from("test decision"),
            raw_json: None,
        }
    }

    #[test]
    fn explainability_j_k_navigate_cursor() {
        let mut model = test_model();
        model.screen = Screen::Explainability;
        model.explainability_decisions =
            vec![sample_decision(1), sample_decision(2), sample_decision(3)];
        assert_eq!(model.explainability_selected, 0);

        // j moves down
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('j'))));
        assert_eq!(model.explainability_selected, 1);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('j'))));
        assert_eq!(model.explainability_selected, 2);

        // j at bottom is clamped
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('j'))));
        assert_eq!(model.explainability_selected, 2);

        // k moves up
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('k'))));
        assert_eq!(model.explainability_selected, 1);

        // k at top is clamped
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('k'))));
        assert_eq!(model.explainability_selected, 0);
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('k'))));
        assert_eq!(model.explainability_selected, 0);
    }

    #[test]
    fn explainability_arrows_navigate_cursor() {
        let mut model = test_model();
        model.screen = Screen::Explainability;
        model.explainability_decisions = vec![sample_decision(1), sample_decision(2)];

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Down)));
        assert_eq!(model.explainability_selected, 1);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Up)));
        assert_eq!(model.explainability_selected, 0);
    }

    #[test]
    fn explainability_enter_toggles_detail() {
        let mut model = test_model();
        model.screen = Screen::Explainability;
        model.explainability_decisions = vec![sample_decision(1)];
        assert!(!model.explainability_detail);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Enter)));
        assert!(model.explainability_detail);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Enter)));
        assert!(!model.explainability_detail);
    }

    #[test]
    fn explainability_d_closes_detail() {
        let mut model = test_model();
        model.screen = Screen::Explainability;
        model.explainability_decisions = vec![sample_decision(1)];
        model.explainability_detail = true;

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('d'))));
        assert!(!model.explainability_detail);
    }

    #[test]
    fn explainability_keys_noop_on_other_screens() {
        let mut model = test_model();
        model.screen = Screen::Overview;

        // j/k should be no-ops on overview (unhandled keys).
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('j'))));
        assert_eq!(model.explainability_selected, 0);
    }

    #[test]
    fn telemetry_decisions_msg_updates_model() {
        let mut model = test_model();
        let result = TelemetryResult {
            data: vec![sample_decision(10), sample_decision(20)],
            source: crate::tui::telemetry::DataSource::Sqlite,
            partial: false,
            diagnostics: String::new(),
        };

        let cmd = update(&mut model, DashboardMsg::TelemetryDecisions(result));
        assert!(matches!(cmd, DashboardCmd::None));
        assert_eq!(model.explainability_decisions.len(), 2);
        assert_eq!(
            model.explainability_source,
            crate::tui::telemetry::DataSource::Sqlite
        );
        assert!(!model.explainability_partial);
    }

    #[test]
    fn telemetry_decisions_clamps_cursor() {
        let mut model = test_model();
        model.explainability_selected = 5; // out of range

        let result = TelemetryResult {
            data: vec![sample_decision(1), sample_decision(2)],
            source: crate::tui::telemetry::DataSource::Sqlite,
            partial: false,
            diagnostics: String::new(),
        };

        update(&mut model, DashboardMsg::TelemetryDecisions(result));
        assert_eq!(model.explainability_selected, 1); // clamped to last
    }

    #[test]
    fn telemetry_decisions_empty_resets_state() {
        let mut model = test_model();
        model.explainability_selected = 3;
        model.explainability_detail = true;

        let result = TelemetryResult {
            data: vec![],
            source: crate::tui::telemetry::DataSource::None,
            partial: true,
            diagnostics: String::from("no data available"),
        };

        update(&mut model, DashboardMsg::TelemetryDecisions(result));
        assert_eq!(model.explainability_selected, 0);
        assert!(!model.explainability_detail);
        assert!(model.explainability_partial);
    }

    #[test]
    fn tick_on_explainability_requests_telemetry() {
        let mut model = test_model();
        model.screen = Screen::Explainability;

        let cmd = update(&mut model, DashboardMsg::Tick);
        // Should be a Batch containing FetchTelemetry.
        if let DashboardCmd::Batch(cmds) = cmd {
            let has_telemetry = cmds
                .iter()
                .any(|c| matches!(c, DashboardCmd::FetchTelemetry));
            assert!(has_telemetry, "Tick on S3 should include FetchTelemetry");
        } else {
            panic!("Expected Batch command from Tick");
        }
    }

    #[test]
    fn tick_on_overview_does_not_request_telemetry() {
        let mut model = test_model();
        model.screen = Screen::Overview;

        let cmd = update(&mut model, DashboardMsg::Tick);
        if let DashboardCmd::Batch(cmds) = cmd {
            let has_telemetry = cmds
                .iter()
                .any(|c| matches!(c, DashboardCmd::FetchTelemetry));
            assert!(
                !has_telemetry,
                "Tick on S1 should not include FetchTelemetry"
            );
        }
    }

    // ── S2 Timeline key handling tests ──

    use crate::tui::model::SeverityFilter;
    use crate::tui::telemetry::TimelineEvent;

    fn sample_timeline_event(severity: &str, event_type: &str) -> TimelineEvent {
        TimelineEvent {
            timestamp: String::from("2026-02-16T03:15:42Z"),
            event_type: event_type.to_owned(),
            severity: severity.to_owned(),
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
        }
    }

    #[test]
    fn timeline_j_k_navigate_cursor() {
        let mut model = test_model();
        model.screen = Screen::Timeline;
        model.timeline_events = vec![
            sample_timeline_event("info", "a"),
            sample_timeline_event("info", "b"),
            sample_timeline_event("info", "c"),
        ];
        assert_eq!(model.timeline_selected, 0);

        // j moves down
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('j'))));
        assert_eq!(model.timeline_selected, 1);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('j'))));
        assert_eq!(model.timeline_selected, 2);

        // j at bottom is clamped
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('j'))));
        assert_eq!(model.timeline_selected, 2);

        // k moves up
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('k'))));
        assert_eq!(model.timeline_selected, 1);
    }

    #[test]
    fn timeline_arrows_navigate_cursor() {
        let mut model = test_model();
        model.screen = Screen::Timeline;
        model.timeline_events = vec![
            sample_timeline_event("info", "a"),
            sample_timeline_event("info", "b"),
        ];

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Down)));
        assert_eq!(model.timeline_selected, 1);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Up)));
        assert_eq!(model.timeline_selected, 0);
    }

    #[test]
    fn timeline_f_cycles_filter() {
        let mut model = test_model();
        model.screen = Screen::Timeline;
        model.timeline_events = vec![sample_timeline_event("info", "a")];
        assert_eq!(model.timeline_filter, SeverityFilter::All);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('f'))));
        assert_eq!(model.timeline_filter, SeverityFilter::Info);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('f'))));
        assert_eq!(model.timeline_filter, SeverityFilter::Warning);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('f'))));
        assert_eq!(model.timeline_filter, SeverityFilter::Critical);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('f'))));
        assert_eq!(model.timeline_filter, SeverityFilter::All);
    }

    #[test]
    fn timeline_f_resets_cursor() {
        let mut model = test_model();
        model.screen = Screen::Timeline;
        model.timeline_events = vec![
            sample_timeline_event("info", "a"),
            sample_timeline_event("info", "b"),
        ];
        model.timeline_selected = 1;

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('f'))));
        assert_eq!(model.timeline_selected, 0);
    }

    #[test]
    fn timeline_shift_f_toggles_follow() {
        let mut model = test_model();
        model.screen = Screen::Timeline;
        model.timeline_events = vec![
            sample_timeline_event("info", "a"),
            sample_timeline_event("info", "b"),
        ];
        model.timeline_follow = false;
        model.timeline_selected = 0;

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('F'))));
        assert!(model.timeline_follow);
        assert_eq!(model.timeline_selected, 1); // jumped to latest

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('F'))));
        assert!(!model.timeline_follow);
    }

    #[test]
    fn timeline_manual_nav_disables_follow() {
        let mut model = test_model();
        model.screen = Screen::Timeline;
        model.timeline_events = vec![
            sample_timeline_event("info", "a"),
            sample_timeline_event("info", "b"),
        ];
        model.timeline_follow = true;
        model.timeline_selected = 1;

        // Moving up disables follow mode
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('k'))));
        assert!(!model.timeline_follow);
        assert_eq!(model.timeline_selected, 0);
    }

    #[test]
    fn timeline_keys_noop_on_other_screens() {
        let mut model = test_model();
        model.screen = Screen::Overview;

        // f should not cycle filter on Overview
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('f'))));
        assert_eq!(model.timeline_filter, SeverityFilter::All);
    }

    #[test]
    fn telemetry_timeline_msg_updates_model() {
        let mut model = test_model();
        let result = TelemetryResult {
            data: vec![
                sample_timeline_event("info", "scan"),
                sample_timeline_event("warning", "pressure_change"),
            ],
            source: DataSource::Sqlite,
            partial: false,
            diagnostics: String::new(),
        };

        let cmd = update(&mut model, DashboardMsg::TelemetryTimeline(result));
        assert!(matches!(cmd, DashboardCmd::None));
        assert_eq!(model.timeline_events.len(), 2);
        assert_eq!(model.timeline_source, DataSource::Sqlite);
        assert!(!model.timeline_partial);
    }

    #[test]
    fn telemetry_timeline_clamps_cursor() {
        let mut model = test_model();
        model.timeline_selected = 10; // out of range

        let result = TelemetryResult {
            data: vec![sample_timeline_event("info", "a")],
            source: DataSource::Sqlite,
            partial: false,
            diagnostics: String::new(),
        };

        update(&mut model, DashboardMsg::TelemetryTimeline(result));
        assert_eq!(model.timeline_selected, 0); // clamped to last (only 1 event)
    }

    #[test]
    fn telemetry_timeline_follow_jumps_to_latest() {
        let mut model = test_model();
        model.timeline_follow = true;
        model.timeline_selected = 0;

        let result = TelemetryResult {
            data: vec![
                sample_timeline_event("info", "a"),
                sample_timeline_event("info", "b"),
                sample_timeline_event("info", "c"),
            ],
            source: DataSource::Sqlite,
            partial: false,
            diagnostics: String::new(),
        };

        update(&mut model, DashboardMsg::TelemetryTimeline(result));
        assert_eq!(model.timeline_selected, 2); // jumped to latest
    }

    #[test]
    fn telemetry_timeline_empty_resets_cursor() {
        let mut model = test_model();
        model.timeline_selected = 5;

        let result = TelemetryResult {
            data: vec![],
            source: DataSource::None,
            partial: true,
            diagnostics: String::from("no data"),
        };

        update(&mut model, DashboardMsg::TelemetryTimeline(result));
        assert_eq!(model.timeline_selected, 0);
        assert!(model.timeline_partial);
    }

    #[test]
    fn tick_on_timeline_requests_telemetry() {
        let mut model = test_model();
        model.screen = Screen::Timeline;

        let cmd = update(&mut model, DashboardMsg::Tick);
        if let DashboardCmd::Batch(cmds) = cmd {
            let has_telemetry = cmds
                .iter()
                .any(|c| matches!(c, DashboardCmd::FetchTelemetry));
            assert!(has_telemetry, "Tick on S2 should include FetchTelemetry");
        } else {
            panic!("Expected Batch command from Tick");
        }
    }

    // ── S4 Candidates key handling tests ──

    #[test]
    fn candidates_j_k_navigate_cursor() {
        let mut model = test_model();
        model.screen = Screen::Candidates;
        model.candidates_list = vec![sample_decision(1), sample_decision(2), sample_decision(3)];
        assert_eq!(model.candidates_selected, 0);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('j'))));
        assert_eq!(model.candidates_selected, 1);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('j'))));
        assert_eq!(model.candidates_selected, 2);

        // j at bottom is clamped
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('j'))));
        assert_eq!(model.candidates_selected, 2);

        // k moves up
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('k'))));
        assert_eq!(model.candidates_selected, 1);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('k'))));
        assert_eq!(model.candidates_selected, 0);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('k'))));
        assert_eq!(model.candidates_selected, 0);
    }

    #[test]
    fn candidates_arrows_navigate_cursor() {
        let mut model = test_model();
        model.screen = Screen::Candidates;
        model.candidates_list = vec![sample_decision(1), sample_decision(2)];

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Down)));
        assert_eq!(model.candidates_selected, 1);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Up)));
        assert_eq!(model.candidates_selected, 0);
    }

    #[test]
    fn candidates_enter_toggles_detail() {
        let mut model = test_model();
        model.screen = Screen::Candidates;
        model.candidates_list = vec![sample_decision(1)];
        assert!(!model.candidates_detail);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Enter)));
        assert!(model.candidates_detail);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Enter)));
        assert!(!model.candidates_detail);
    }

    #[test]
    fn candidates_d_closes_detail() {
        let mut model = test_model();
        model.screen = Screen::Candidates;
        model.candidates_list = vec![sample_decision(1)];
        model.candidates_detail = true;

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('d'))));
        assert!(!model.candidates_detail);
    }

    #[test]
    fn candidates_s_cycles_sort() {
        let mut model = test_model();
        model.screen = Screen::Candidates;
        model.candidates_list = vec![sample_decision(1)];

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('s'))));
        assert_eq!(
            model.candidates_sort,
            crate::tui::model::CandidatesSortOrder::Size
        );

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('s'))));
        assert_eq!(
            model.candidates_sort,
            crate::tui::model::CandidatesSortOrder::Age
        );
    }

    #[test]
    fn candidates_keys_noop_on_other_screens() {
        let mut model = test_model();
        model.screen = Screen::Overview;

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('s'))));
        assert_eq!(
            model.candidates_sort,
            crate::tui::model::CandidatesSortOrder::Score
        );
    }

    #[test]
    fn telemetry_candidates_msg_updates_model() {
        let mut model = test_model();
        let result = TelemetryResult {
            data: vec![sample_decision(10), sample_decision(20)],
            source: crate::tui::telemetry::DataSource::Sqlite,
            partial: false,
            diagnostics: String::new(),
        };

        let cmd = update(&mut model, DashboardMsg::TelemetryCandidates(result));
        assert!(matches!(cmd, DashboardCmd::None));
        assert_eq!(model.candidates_list.len(), 2);
        assert_eq!(
            model.candidates_source,
            crate::tui::telemetry::DataSource::Sqlite
        );
        assert!(!model.candidates_partial);
    }

    #[test]
    fn telemetry_candidates_clamps_cursor() {
        let mut model = test_model();
        model.candidates_selected = 5;

        let result = TelemetryResult {
            data: vec![sample_decision(1), sample_decision(2)],
            source: crate::tui::telemetry::DataSource::Sqlite,
            partial: false,
            diagnostics: String::new(),
        };

        update(&mut model, DashboardMsg::TelemetryCandidates(result));
        assert_eq!(model.candidates_selected, 1);
    }

    #[test]
    fn telemetry_candidates_empty_resets_state() {
        let mut model = test_model();
        model.candidates_selected = 3;
        model.candidates_detail = true;

        let result = TelemetryResult {
            data: vec![],
            source: crate::tui::telemetry::DataSource::None,
            partial: true,
            diagnostics: String::from("no data available"),
        };

        update(&mut model, DashboardMsg::TelemetryCandidates(result));
        assert_eq!(model.candidates_selected, 0);
        assert!(!model.candidates_detail);
        assert!(model.candidates_partial);
    }

    #[test]
    fn tick_on_candidates_requests_telemetry() {
        let mut model = test_model();
        model.screen = Screen::Candidates;

        let cmd = update(&mut model, DashboardMsg::Tick);
        if let DashboardCmd::Batch(cmds) = cmd {
            let has_telemetry = cmds
                .iter()
                .any(|c| matches!(c, DashboardCmd::FetchTelemetry));
            assert!(has_telemetry, "Tick on S4 should include FetchTelemetry");
        } else {
            panic!("Expected Batch command from Tick");
        }
    }

    // ── S7 Diagnostics key handling tests ──

    #[test]
    fn diagnostics_shift_v_toggles_verbose() {
        let mut model = test_model();
        model.screen = Screen::Diagnostics;
        assert!(!model.diagnostics_verbose);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('V'))));
        assert!(model.diagnostics_verbose);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('V'))));
        assert!(!model.diagnostics_verbose);
    }

    #[test]
    fn diagnostics_v_noop_on_other_screens() {
        let mut model = test_model();
        model.screen = Screen::Overview;

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('V'))));
        assert!(!model.diagnostics_verbose);
    }

    #[test]
    fn diagnostics_other_keys_are_noop() {
        let mut model = test_model();
        model.screen = Screen::Diagnostics;

        // j/k/s should do nothing on diagnostics screen.
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('j'))));
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('k'))));
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('s'))));
        assert!(!model.diagnostics_verbose);
    }

    #[test]
    fn frame_metrics_msg_records_duration() {
        let mut model = test_model();
        assert!(model.frame_times.is_empty());

        let cmd = update(&mut model, DashboardMsg::FrameMetrics { duration_ms: 16.5 });
        assert!(matches!(cmd, DashboardCmd::None));
        assert_eq!(model.frame_times.len(), 1);
        assert_eq!(model.frame_times.latest(), Some(16.5));
    }

    #[test]
    fn frame_metrics_accumulates() {
        let mut model = test_model();
        update(&mut model, DashboardMsg::FrameMetrics { duration_ms: 10.0 });
        update(&mut model, DashboardMsg::FrameMetrics { duration_ms: 20.0 });
        update(&mut model, DashboardMsg::FrameMetrics { duration_ms: 15.0 });
        assert_eq!(model.frame_times.len(), 3);
        assert_eq!(model.frame_times.latest(), Some(15.0));
    }

    #[test]
    fn data_update_success_increments_adapter_reads() {
        let mut model = test_model();
        assert_eq!(model.adapter_reads, 0);

        update(
            &mut model,
            DashboardMsg::DataUpdate(Some(Box::new(sample_daemon_state()))),
        );
        assert_eq!(model.adapter_reads, 1);
        assert_eq!(model.adapter_errors, 0);

        update(
            &mut model,
            DashboardMsg::DataUpdate(Some(Box::new(sample_daemon_state()))),
        );
        assert_eq!(model.adapter_reads, 2);
    }

    #[test]
    fn data_update_none_increments_adapter_errors() {
        let mut model = test_model();
        assert_eq!(model.adapter_errors, 0);

        update(&mut model, DashboardMsg::DataUpdate(None));
        assert_eq!(model.adapter_errors, 1);
        assert_eq!(model.adapter_reads, 0);

        update(&mut model, DashboardMsg::DataUpdate(None));
        assert_eq!(model.adapter_errors, 2);
    }

    #[test]
    fn data_update_mixed_tracks_both_counters() {
        let mut model = test_model();
        update(
            &mut model,
            DashboardMsg::DataUpdate(Some(Box::new(sample_daemon_state()))),
        );
        update(&mut model, DashboardMsg::DataUpdate(None));
        update(
            &mut model,
            DashboardMsg::DataUpdate(Some(Box::new(sample_daemon_state()))),
        );
        assert_eq!(model.adapter_reads, 2);
        assert_eq!(model.adapter_errors, 1);
    }

    #[test]
    fn tick_on_diagnostics_does_not_request_telemetry() {
        let mut model = test_model();
        model.screen = Screen::Diagnostics;

        let cmd = update(&mut model, DashboardMsg::Tick);
        if let DashboardCmd::Batch(cmds) = cmd {
            let has_telemetry = cmds
                .iter()
                .any(|c| matches!(c, DashboardCmd::FetchTelemetry));
            assert!(
                !has_telemetry,
                "Tick on S7 should not include FetchTelemetry"
            );
        }
    }

    // ── S5 Ballast key handling tests ──

    use crate::tui::model::BallastVolume;

    fn sample_volume(mount: &str, available: usize, total: usize) -> BallastVolume {
        BallastVolume {
            mount_point: mount.to_string(),
            ballast_dir: format!("{mount}/.sbh/ballast"),
            fs_type: "ext4".to_string(),
            strategy: "fallocate".to_string(),
            files_available: available,
            files_total: total,
            releasable_bytes: available as u64 * 1_073_741_824,
            skipped: false,
            skip_reason: None,
        }
    }

    #[test]
    fn ballast_j_k_navigate_cursor() {
        let mut model = test_model();
        model.screen = Screen::Ballast;
        model.ballast_volumes = vec![
            sample_volume("/", 3, 5),
            sample_volume("/data", 2, 5),
            sample_volume("/home", 4, 5),
        ];
        assert_eq!(model.ballast_selected, 0);

        // j moves down
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('j'))));
        assert_eq!(model.ballast_selected, 1);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('j'))));
        assert_eq!(model.ballast_selected, 2);

        // j at bottom is clamped
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('j'))));
        assert_eq!(model.ballast_selected, 2);

        // k moves up
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('k'))));
        assert_eq!(model.ballast_selected, 1);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('k'))));
        assert_eq!(model.ballast_selected, 0);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('k'))));
        assert_eq!(model.ballast_selected, 0);
    }

    #[test]
    fn ballast_arrows_navigate_cursor() {
        let mut model = test_model();
        model.screen = Screen::Ballast;
        model.ballast_volumes = vec![sample_volume("/", 3, 5), sample_volume("/data", 2, 5)];

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Down)));
        assert_eq!(model.ballast_selected, 1);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Up)));
        assert_eq!(model.ballast_selected, 0);
    }

    #[test]
    fn ballast_enter_toggles_detail() {
        let mut model = test_model();
        model.screen = Screen::Ballast;
        model.ballast_volumes = vec![sample_volume("/", 3, 5)];
        assert!(!model.ballast_detail);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Enter)));
        assert!(model.ballast_detail);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Enter)));
        assert!(!model.ballast_detail);
    }

    #[test]
    fn ballast_space_toggles_detail() {
        let mut model = test_model();
        model.screen = Screen::Ballast;
        model.ballast_volumes = vec![sample_volume("/", 3, 5)];
        assert!(!model.ballast_detail);

        update(
            &mut model,
            DashboardMsg::Key(make_key(KeyCode::Char(' '))),
        );
        assert!(model.ballast_detail);
    }

    #[test]
    fn ballast_d_closes_detail() {
        let mut model = test_model();
        model.screen = Screen::Ballast;
        model.ballast_volumes = vec![sample_volume("/", 3, 5)];
        model.ballast_detail = true;

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('d'))));
        assert!(!model.ballast_detail);
    }

    #[test]
    fn ballast_d_noop_when_detail_closed() {
        let mut model = test_model();
        model.screen = Screen::Ballast;
        model.ballast_volumes = vec![sample_volume("/", 3, 5)];
        assert!(!model.ballast_detail);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('d'))));
        assert!(!model.ballast_detail);
    }

    #[test]
    fn ballast_keys_noop_on_other_screens() {
        let mut model = test_model();
        model.screen = Screen::Overview;
        model.ballast_volumes = vec![sample_volume("/", 3, 5), sample_volume("/data", 2, 5)];

        // j should not move ballast cursor on overview
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('j'))));
        assert_eq!(model.ballast_selected, 0);
    }

    #[test]
    fn telemetry_ballast_msg_updates_model() {
        let mut model = test_model();
        let result = TelemetryResult {
            data: vec![sample_volume("/", 3, 5), sample_volume("/data", 2, 5)],
            source: DataSource::Sqlite,
            partial: false,
            diagnostics: String::new(),
        };

        let cmd = update(&mut model, DashboardMsg::TelemetryBallast(result));
        assert!(matches!(cmd, DashboardCmd::None));
        assert_eq!(model.ballast_volumes.len(), 2);
        assert_eq!(model.ballast_source, DataSource::Sqlite);
        assert!(!model.ballast_partial);
    }

    #[test]
    fn telemetry_ballast_clamps_cursor() {
        let mut model = test_model();
        model.ballast_selected = 5; // out of range

        let result = TelemetryResult {
            data: vec![sample_volume("/", 3, 5), sample_volume("/data", 2, 5)],
            source: DataSource::Sqlite,
            partial: false,
            diagnostics: String::new(),
        };

        update(&mut model, DashboardMsg::TelemetryBallast(result));
        assert_eq!(model.ballast_selected, 1); // clamped to last
    }

    #[test]
    fn telemetry_ballast_empty_resets_state() {
        let mut model = test_model();
        model.ballast_selected = 3;
        model.ballast_detail = true;

        let result = TelemetryResult {
            data: vec![],
            source: DataSource::None,
            partial: true,
            diagnostics: String::from("no ballast data"),
        };

        update(&mut model, DashboardMsg::TelemetryBallast(result));
        assert_eq!(model.ballast_selected, 0);
        assert!(!model.ballast_detail);
        assert!(model.ballast_partial);
    }

    #[test]
    fn tick_on_ballast_requests_telemetry() {
        let mut model = test_model();
        model.screen = Screen::Ballast;

        let cmd = update(&mut model, DashboardMsg::Tick);
        if let DashboardCmd::Batch(cmds) = cmd {
            let has_telemetry = cmds
                .iter()
                .any(|c| matches!(c, DashboardCmd::FetchTelemetry));
            assert!(has_telemetry, "Tick on S5 should include FetchTelemetry");
        } else {
            panic!("Expected Batch command from Tick");
        }
    }

    // ── Command palette interaction tests ──

    #[test]
    fn palette_opens_with_clean_state() {
        let mut model = test_model();
        update(
            &mut model,
            DashboardMsg::Key(make_key_ctrl(KeyCode::Char('p'))),
        );
        assert_eq!(model.active_overlay, Some(Overlay::CommandPalette));
        assert!(model.palette_query.is_empty());
        assert_eq!(model.palette_selected, 0);
    }

    #[test]
    fn palette_opens_with_colon() {
        let mut model = test_model();
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char(':'))));
        assert_eq!(model.active_overlay, Some(Overlay::CommandPalette));
        assert!(model.palette_query.is_empty());
        assert_eq!(model.palette_selected, 0);
    }

    #[test]
    fn palette_typing_builds_query() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::CommandPalette);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('n'))));
        assert_eq!(model.palette_query, "n");

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('a'))));
        assert_eq!(model.palette_query, "na");

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('v'))));
        assert_eq!(model.palette_query, "nav");
    }

    #[test]
    fn palette_backspace_removes_character() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::CommandPalette);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('a'))));
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('b'))));
        assert_eq!(model.palette_query, "ab");

        update(
            &mut model,
            DashboardMsg::Key(make_key(KeyCode::Backspace)),
        );
        assert_eq!(model.palette_query, "a");
    }

    #[test]
    fn palette_backspace_on_empty_is_noop() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::CommandPalette);
        assert!(model.palette_query.is_empty());

        update(
            &mut model,
            DashboardMsg::Key(make_key(KeyCode::Backspace)),
        );
        assert!(model.palette_query.is_empty());
    }

    #[test]
    fn palette_cursor_navigation() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::CommandPalette);
        // Empty query shows all 15 palette actions.
        assert_eq!(model.palette_selected, 0);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Down)));
        assert_eq!(model.palette_selected, 1);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Down)));
        assert_eq!(model.palette_selected, 2);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Up)));
        assert_eq!(model.palette_selected, 1);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Up)));
        assert_eq!(model.palette_selected, 0);

        // Up at top is clamped.
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Up)));
        assert_eq!(model.palette_selected, 0);
    }

    #[test]
    fn palette_execute_navigates_and_closes() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::CommandPalette);
        // Empty query, first result is nav.overview (already there), second is nav.timeline.
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Down)));
        assert_eq!(model.palette_selected, 1);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Enter)));
        assert_eq!(model.screen, Screen::Timeline);
        assert!(model.active_overlay.is_none());
        assert!(model.palette_query.is_empty());
        assert_eq!(model.palette_selected, 0);
    }

    #[test]
    fn palette_execute_with_search() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::CommandPalette);

        // Type "ballast" to narrow results.
        for c in "ballast".chars() {
            update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char(c))));
        }

        // First result should be nav.ballast or action.jump_ballast.
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Enter)));
        assert_eq!(model.screen, Screen::Ballast);
        assert!(model.active_overlay.is_none());
    }

    #[test]
    fn palette_esc_closes_and_resets() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::CommandPalette);
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('x'))));
        assert_eq!(model.palette_query, "x");

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Escape)));
        assert!(model.active_overlay.is_none());
        assert!(model.palette_query.is_empty());
        assert_eq!(model.palette_selected, 0);
    }

    #[test]
    fn palette_toggle_closes_and_resets() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::CommandPalette);
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('a'))));
        assert_eq!(model.palette_query, "a");

        update(
            &mut model,
            DashboardMsg::Key(make_key_ctrl(KeyCode::Char('p'))),
        );
        assert!(model.active_overlay.is_none());
        assert!(model.palette_query.is_empty());
        assert_eq!(model.palette_selected, 0);
    }

    #[test]
    fn palette_cursor_clamps_on_query_change() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::CommandPalette);

        // Move cursor to a high position with empty query (15 results).
        for _ in 0..10 {
            update(&mut model, DashboardMsg::Key(make_key(KeyCode::Down)));
        }
        assert_eq!(model.palette_selected, 10);

        // Type a very specific query that produces fewer results.
        for c in "action.quit".chars() {
            update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char(c))));
        }
        // Cursor should be clamped to the result count.
        assert!(model.palette_selected < 15);
    }

    #[test]
    fn palette_ctrl_c_still_quits() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::CommandPalette);
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('a'))));

        let cmd = update(
            &mut model,
            DashboardMsg::Key(make_key_ctrl(KeyCode::Char('c'))),
        );
        assert!(model.quit);
        assert!(matches!(cmd, DashboardCmd::Quit));
    }

    #[test]
    fn palette_typing_does_not_trigger_global_keys() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::CommandPalette);

        // 'q' in palette types, does not quit.
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('q'))));
        assert!(!model.quit);
        assert_eq!(model.palette_query, "q");
    }

    #[test]
    fn palette_execute_on_no_results_is_noop() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::CommandPalette);

        // Type gibberish that matches nothing.
        for c in "zzzzzzzzz".chars() {
            update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char(c))));
        }

        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Enter)));
        assert!(matches!(cmd, DashboardCmd::None));
        assert_eq!(model.active_overlay, Some(Overlay::CommandPalette));
    }
}
