//! Pure update function for the Elm-style TUI dashboard.
//!
//! `update()` takes the current model and a message, mutates the model, and
//! returns a command describing any side-effects the runtime should execute.

#![allow(clippy::too_many_lines)]
//!
//! **Design invariant:** this module performs zero I/O. All effects are
//! described as [`DashboardCmd`] values.

use std::time::Instant;

use ftui::{KeyCode, MouseButton, MouseEvent, MouseEventKind};

use super::input::{InputAction, InputContext};
use super::layout::{
    BallastPane, CandidatesPane, ExplainabilityPane, LogSearchPane, OverviewPane, TimelinePane,
    build_ballast_layout, build_candidates_layout, build_explainability_layout,
    build_log_search_layout, build_overview_layout, build_timeline_layout,
};
use super::model::{
    BallastVolume, ConfirmAction, DashboardCmd, DashboardModel, DashboardMsg, NotificationLevel,
    Overlay, PreferenceAction, RateHistory, Screen,
};

const FRAME_HEADER_ROWS: u16 = 6;
const FRAME_FOOTER_ROWS: u16 = 1;
const HEADER_TAB_ROW: u16 = 2;

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
                Screen::Overview
                    | Screen::Timeline
                    | Screen::Explainability
                    | Screen::Candidates
                    | Screen::Ballast
            ) {
                cmds.push(DashboardCmd::FetchTelemetry);
            }
            DashboardCmd::Batch(cmds)
        }

        DashboardMsg::Key(key) => {
            // The Log Search query editor owns every key while it is open
            // (Esc cancels, Enter runs), ahead of the global bindings.
            if model.screen == Screen::LogSearch
                && model.log_search.editing
                && model.active_overlay.is_none()
            {
                return handle_log_search_editing_key(model, key);
            }
            // Replay scrubber keys (bd-rc-master-ajg1.4.13): queued for the
            // runtime's driver; Space pauses/resumes, `,`/`.` step, Home/End
            // seek. Only while `--replay` drives the cockpit.
            if model.replay.is_some()
                && model.active_overlay.is_none()
                && let Some(command) = replay_command_for(key.code)
            {
                model.replay_pending = Some(command);
                return DashboardCmd::None;
            }
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
            // Clamp to 1×1: zero dimensions cause Buffer/Frame panics.
            model.terminal_size = (cols.max(1), rows.max(1));
            DashboardCmd::None
        }

        DashboardMsg::Mouse(event) => handle_mouse_event(model, event),

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

            // The Ballast screen lists the daemon's own per-mount inventory.
            // A daemon older than that field gives only the aggregate, so
            // one volume is synthesized on the first monitored mount (it
            // has no pool directory, so a release on it can only go
            // through the daemon).
            if let Some(ref ds) = model.daemon_state {
                if !ds.ballast_pools.is_empty() {
                    let volumes = ds
                        .ballast_pools
                        .iter()
                        .map(BallastVolume::from_pool_state)
                        .collect();
                    model.set_ballast_volumes(volumes);
                    model.ballast_source = crate::tui::telemetry::DataSource::None;
                } else if ds.ballast.total > 0 && model.ballast_volumes.is_empty() {
                    let mount = ds
                        .pressure
                        .mounts
                        .first()
                        .map_or_else(|| "/".to_string(), |m| m.path.clone());
                    model.set_ballast_volumes(vec![BallastVolume {
                        mount_point: mount,
                        ballast_dir: String::new(),
                        fs_type: String::new(),
                        strategy: String::new(),
                        files_available: ds.ballast.available,
                        files_total: ds.ballast.total,
                        releasable_bytes: 0,
                        skipped: false,
                        skip_reason: None,
                    }]);
                    model.ballast_source = crate::tui::telemetry::DataSource::None;
                }
            }

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

        DashboardMsg::TelemetryLogSearch(result) => {
            model.log_search.accept(result);
            DashboardCmd::None
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
            // A jump from the Timeline that arrived before the decisions.
            if let Some(pending) = model.explainability_pending_select.take()
                && !model.select_decision_by_stable_id(&pending)
            {
                model.explainability_diagnostics =
                    format!("decision {pending} is not among the loaded decisions");
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
            model.set_ballast_volumes(result.data);
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
            if model.explainability_detail {
                model.explainability_detail = false;
                return DashboardCmd::None;
            }
            if model.candidates_detail {
                model.candidates_detail = false;
                return DashboardCmd::None;
            }
            if model.ballast_detail {
                model.ballast_detail = false;
                return DashboardCmd::None;
            }
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
        InputAction::SetStartScreen(start_screen) => {
            DashboardCmd::ExecutePreferenceAction(PreferenceAction::SetStartScreen(start_screen))
        }
        InputAction::SetDensity(density) => {
            DashboardCmd::ExecutePreferenceAction(PreferenceAction::SetDensity(density))
        }
        InputAction::SetHintVerbosity(hint_verbosity) => DashboardCmd::ExecutePreferenceAction(
            PreferenceAction::SetHintVerbosity(hint_verbosity),
        ),
        InputAction::ResetPreferencesToPersisted => {
            DashboardCmd::ExecutePreferenceAction(PreferenceAction::ResetToPersisted)
        }
        InputAction::RevertPreferencesToDefaults => {
            DashboardCmd::ExecutePreferenceAction(PreferenceAction::RevertToDefaults)
        }
        InputAction::OverviewFocusNext => {
            if model.screen == Screen::Overview {
                overview_focus_step(model, true);
            }
            DashboardCmd::None
        }
        InputAction::OverviewFocusPrev => {
            if model.screen == Screen::Overview {
                overview_focus_step(model, false);
            }
            DashboardCmd::None
        }
        InputAction::OverviewActivateFocused => {
            if model.screen == Screen::Overview {
                overview_ensure_focus_visible(model);
                let target = model.overview_focus_target_screen();
                model.navigate_to(target);
            }
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
        // ── Incident workflow shortcuts (bd-xzt.3.9) ──
        InputAction::IncidentShowPlaybook => {
            model.incident_playbook_selected = 0;
            model.active_overlay = Some(Overlay::IncidentPlaybook);
            DashboardCmd::None
        }
        InputAction::IncidentQuickRelease => {
            // Jump to the Ballast screen, land on a volume that has files to
            // give (the selected one if it does), and open the confirmation.
            model.navigate_to(Screen::Ballast);
            model.select_ballast_volume_with_files();
            if open_ballast_confirmation(model, ConfirmAction::BallastRelease) {
                model.push_notification(
                    NotificationLevel::Warning,
                    "Quick-release: confirm ballast release on selected volume".to_string(),
                );
            }
            DashboardCmd::None
        }
        InputAction::ConfirmOverlay => {
            let Some(Overlay::Confirmation(action)) = model.active_overlay else {
                return DashboardCmd::None;
            };
            model.active_overlay = None;
            let Some(volume) = model.ballast_selected_volume() else {
                model.push_notification(
                    NotificationLevel::Warning,
                    "No ballast volume selected; nothing released".to_string(),
                );
                return DashboardCmd::None;
            };
            let mount = volume.mount_point.clone();
            let ballast_dir = volume.ballast_dir.clone();
            match action {
                ConfirmAction::BallastRelease | ConfirmAction::BallastReleaseAll => {
                    let count = if action == ConfirmAction::BallastRelease {
                        1
                    } else {
                        volume.files_available.max(1)
                    };
                    model.push_notification(
                        NotificationLevel::Info,
                        format!("Releasing {count} ballast file(s) on {mount}…"),
                    );
                    DashboardCmd::ReleaseBallast {
                        mount,
                        ballast_dir,
                        count,
                    }
                }
                ConfirmAction::BallastReplenish => {
                    model.push_notification(
                        NotificationLevel::Info,
                        format!("Replenishing ballast on {mount}…"),
                    );
                    DashboardCmd::ReplenishBallast { mount, ballast_dir }
                }
            }
        }
        InputAction::IncidentPlaybookNavigate => {
            let severity =
                super::incident::IncidentSeverity::from_daemon_state(model.daemon_state.as_ref());
            let entries = super::incident::playbook_for_severity(severity);
            if let Some(entry) = entries.get(model.incident_playbook_selected) {
                let target = entry.target;
                model.active_overlay = None;
                model.navigate_to(target);
            }
            DashboardCmd::None
        }
        InputAction::IncidentPlaybookUp => {
            if model.incident_playbook_selected > 0 {
                model.incident_playbook_selected -= 1;
            }
            DashboardCmd::None
        }
        InputAction::IncidentPlaybookDown => {
            let severity =
                super::incident::IncidentSeverity::from_daemon_state(model.daemon_state.as_ref());
            let entry_count = super::incident::playbook_for_severity(severity).len();
            if entry_count > 0 && model.incident_playbook_selected < entry_count - 1 {
                model.incident_playbook_selected += 1;
            }
            DashboardCmd::None
        }
    }
}

// Keep command execution and cursor movement aligned with the rendered list.
const PALETTE_RESULT_LIMIT: usize = 10;

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
fn handle_screen_key(model: &mut DashboardModel, key: ftui::KeyEvent) -> DashboardCmd {
    match model.screen {
        Screen::Timeline => handle_timeline_key(model, key),
        Screen::Explainability => handle_explainability_key(model, key),
        Screen::Candidates => handle_candidates_key(model, key),
        Screen::Diagnostics => handle_diagnostics_key(model, key),
        Screen::Ballast => handle_ballast_key(model, key),
        Screen::LogSearch => handle_log_search_key(model, key),
        Screen::Overview => DashboardCmd::None,
    }
}

/// Keys on the Log Search screen (S6) outside the query editor.
fn handle_log_search_key(model: &mut DashboardModel, key: ftui::KeyEvent) -> DashboardCmd {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            model.log_search.cursor_up();
            DashboardCmd::None
        }
        KeyCode::Down | KeyCode::Char('j') => {
            model.log_search.cursor_down();
            DashboardCmd::None
        }
        // /: edit the query (the current one is the starting text).
        KeyCode::Char('/') => {
            model.log_search.draft = model.log_search.query.clone();
            model.log_search.editing = true;
            DashboardCmd::None
        }
        // n / p: next and previous page of the same query.
        KeyCode::Char('n') => {
            if model.log_search.has_more {
                model.log_search.page += 1;
                model.log_search.selected = 0;
                DashboardCmd::FetchTelemetry
            } else {
                DashboardCmd::None
            }
        }
        KeyCode::Char('p') => {
            if model.log_search.page > 0 {
                model.log_search.page -= 1;
                model.log_search.selected = 0;
                DashboardCmd::FetchTelemetry
            } else {
                DashboardCmd::None
            }
        }
        // c: clear the query and show the newest entries again.
        KeyCode::Char('c') => {
            model.log_search.query.clear();
            model.log_search.page = 0;
            model.log_search.selected = 0;
            DashboardCmd::FetchTelemetry
        }
        // Enter: open the selected entry on the Timeline.
        KeyCode::Enter => {
            let Some(entry) = model.log_search.selected_entry() else {
                return DashboardCmd::None;
            };
            let target = entry.timestamp.clone();
            let target_path = entry.path.clone();
            model.navigate_to(Screen::Timeline);
            let position = model
                .timeline_filtered_events()
                .iter()
                .position(|e| e.timestamp == target && e.path == target_path);
            if let Some(index) = position {
                model.timeline_selected = index;
                model.timeline_follow = false;
            } else {
                model.push_notification(
                    NotificationLevel::Info,
                    "Entry is not in the Timeline's current window".to_string(),
                );
            }
            DashboardCmd::None
        }
        _ => DashboardCmd::None,
    }
}

/// Keys while the Log Search query editor is open: printable characters
/// and Backspace edit the draft, Enter runs it from page 0, Esc cancels.
fn handle_log_search_editing_key(model: &mut DashboardModel, key: ftui::KeyEvent) -> DashboardCmd {
    match key.code {
        KeyCode::Char('c') if key.ctrl() => DashboardCmd::Quit,
        KeyCode::Escape => {
            model.log_search.editing = false;
            model.log_search.draft.clear();
            DashboardCmd::None
        }
        KeyCode::Enter => {
            model.log_search.query = model.log_search.draft.trim().to_string();
            model.log_search.editing = false;
            model.log_search.draft.clear();
            model.log_search.page = 0;
            model.log_search.selected = 0;
            DashboardCmd::FetchTelemetry
        }
        KeyCode::Backspace => {
            model.log_search.draft.pop();
            DashboardCmd::None
        }
        KeyCode::Char(c) if !key.ctrl() => {
            if model.log_search.draft.chars().count() < 200 {
                model.log_search.draft.push(c);
            }
            DashboardCmd::None
        }
        _ => DashboardCmd::None,
    }
}

/// Handle keys specific to the Timeline screen (S2).
fn handle_timeline_key(model: &mut DashboardModel, key: ftui::KeyEvent) -> DashboardCmd {
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
        // Enter: a deletion links to its ledger decision; open it on the
        // Explainability screen (selected now if loaded, or as soon as the
        // decisions arrive).
        KeyCode::Enter => {
            let Some(decision_id) = model
                .timeline_selected_event()
                .and_then(|event| event.decision_id.clone())
            else {
                return DashboardCmd::None;
            };
            model.navigate_to(Screen::Explainability);
            if !model.select_decision_by_stable_id(&decision_id) {
                model.explainability_pending_select = Some(decision_id);
            }
            DashboardCmd::None
        }
        _ => DashboardCmd::None,
    }
}

/// Handle keys specific to the Explainability screen (S3).
fn handle_explainability_key(model: &mut DashboardModel, key: ftui::KeyEvent) -> DashboardCmd {
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
fn handle_candidates_key(model: &mut DashboardModel, key: ftui::KeyEvent) -> DashboardCmd {
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
fn handle_ballast_key(model: &mut DashboardModel, key: ftui::KeyEvent) -> DashboardCmd {
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
        // X (shift-x): release every available file on the selected volume,
        // behind the confirmation. Plain `x` is the global single-file
        // quick-release.
        KeyCode::Char('X') => {
            open_ballast_confirmation(model, ConfirmAction::BallastReleaseAll);
            DashboardCmd::None
        }
        // p: recreate the released files on the selected volume.
        KeyCode::Char('p') => {
            open_ballast_confirmation(model, ConfirmAction::BallastReplenish);
            DashboardCmd::None
        }
        _ => DashboardCmd::None,
    }
}

/// The scrubber command a key means during replay, if any.
const fn replay_command_for(code: KeyCode) -> Option<crate::tui::replay::ReplayCommand> {
    use crate::tui::replay::ReplayCommand;
    match code {
        KeyCode::Char(' ') => Some(ReplayCommand::TogglePause),
        KeyCode::Char(',') => Some(ReplayCommand::StepBack),
        KeyCode::Char('.') => Some(ReplayCommand::StepForward),
        KeyCode::Home => Some(ReplayCommand::SeekStart),
        KeyCode::End => Some(ReplayCommand::SeekEnd),
        _ => None,
    }
}

/// Open the confirmation for a mutating ballast action on the selected
/// volume, or say why there is nothing to act on. Returns whether it opened.
fn open_ballast_confirmation(model: &mut DashboardModel, action: ConfirmAction) -> bool {
    if model.replay.is_some() {
        model.push_notification(
            NotificationLevel::Warning,
            "Replay: ballast actions are disabled (the log is history, not a daemon)".to_string(),
        );
        return false;
    }
    let Some(volume) = model.ballast_selected_volume() else {
        model.push_notification(
            NotificationLevel::Warning,
            "No ballast volume selected".to_string(),
        );
        return false;
    };
    let mount = volume.mount_point.clone();
    let blocked = match action {
        ConfirmAction::BallastRelease | ConfirmAction::BallastReleaseAll
            if volume.files_available == 0 =>
        {
            Some(format!("No ballast file available to release on {mount}"))
        }
        ConfirmAction::BallastReplenish if volume.files_available >= volume.files_total => {
            Some(format!("Ballast pool on {mount} is already full"))
        }
        _ => None,
    };
    if let Some(reason) = blocked {
        model.push_notification(NotificationLevel::Warning, reason);
        return false;
    }
    model.active_overlay = Some(Overlay::Confirmation(action));
    true
}

/// Handle keys specific to the Diagnostics screen (S7).
fn handle_diagnostics_key(model: &mut DashboardModel, key: ftui::KeyEvent) -> DashboardCmd {
    match key.code {
        // V (shift-v): toggle verbose diagnostics mode.
        KeyCode::Char('V') => {
            model.diagnostics_toggle_verbose();
            DashboardCmd::None
        }
        _ => DashboardCmd::None,
    }
}

fn handle_mouse_event(model: &mut DashboardModel, event: MouseEvent) -> DashboardCmd {
    if model.active_overlay.is_some() {
        return handle_overlay_mouse(model, event);
    }

    if matches!(event.kind, MouseEventKind::Down(MouseButton::Left))
        && let Some(screen) = header_tab_hit_screen(model, event.x, event.y)
    {
        model.navigate_to(screen);
        return DashboardCmd::None;
    }

    match model.screen {
        Screen::Overview => handle_overview_mouse(model, event),
        Screen::Timeline => handle_timeline_mouse(model, event),
        Screen::Explainability => handle_explainability_mouse(model, event),
        Screen::Candidates => handle_candidates_mouse(model, event),
        Screen::Ballast => handle_ballast_mouse(model, event),
        Screen::LogSearch => handle_log_search_mouse(model, event),
        Screen::Diagnostics => DashboardCmd::None,
    }
}

fn handle_overlay_mouse(model: &mut DashboardModel, event: MouseEvent) -> DashboardCmd {
    if matches!(event.kind, MouseEventKind::Down(MouseButton::Left)) {
        model.palette_reset();
        model.active_overlay = None;
    }
    DashboardCmd::None
}

fn handle_overview_mouse(model: &mut DashboardModel, event: MouseEvent) -> DashboardCmd {
    let hovered = overview_pane_at(model, event.x, event.y);
    model.overview_set_hover(hovered);
    match event.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if let Some(pane) = hovered {
                model.overview_set_focus(pane);
                let target = model.overview_focus_target_screen();
                model.navigate_to(target);
            }
            DashboardCmd::None
        }
        MouseEventKind::ScrollUp => {
            if hovered == Some(OverviewPane::CandidateHotlist) {
                model.candidates_cursor_up();
            }
            DashboardCmd::None
        }
        MouseEventKind::ScrollDown => {
            if hovered == Some(OverviewPane::CandidateHotlist) {
                model.candidates_cursor_down();
            }
            DashboardCmd::None
        }
        _ => DashboardCmd::None,
    }
}

fn handle_timeline_mouse(model: &mut DashboardModel, event: MouseEvent) -> DashboardCmd {
    match event.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if let Some(idx) = timeline_row_hit(model, event.x, event.y) {
                model.timeline_selected = idx;
                model.timeline_follow = false;
            }
            DashboardCmd::None
        }
        MouseEventKind::ScrollUp if point_in_body(model, event.x, event.y) => {
            model.timeline_cursor_up();
            DashboardCmd::None
        }
        MouseEventKind::ScrollDown if point_in_body(model, event.x, event.y) => {
            model.timeline_cursor_down();
            DashboardCmd::None
        }
        _ => DashboardCmd::None,
    }
}

fn handle_explainability_mouse(model: &mut DashboardModel, event: MouseEvent) -> DashboardCmd {
    match event.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if let Some(idx) = explainability_row_hit(model, event.x, event.y) {
                model.explainability_selected = idx;
                model.explainability_detail = true;
            }
            DashboardCmd::None
        }
        MouseEventKind::ScrollUp if point_in_body(model, event.x, event.y) => {
            model.explainability_cursor_up();
            DashboardCmd::None
        }
        MouseEventKind::ScrollDown if point_in_body(model, event.x, event.y) => {
            model.explainability_cursor_down();
            DashboardCmd::None
        }
        _ => DashboardCmd::None,
    }
}

fn handle_candidates_mouse(model: &mut DashboardModel, event: MouseEvent) -> DashboardCmd {
    match event.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if let Some(idx) = candidates_row_hit(model, event.x, event.y) {
                model.candidates_selected = idx;
                model.candidates_detail = true;
            }
            DashboardCmd::None
        }
        MouseEventKind::ScrollUp if point_in_body(model, event.x, event.y) => {
            model.candidates_cursor_up();
            DashboardCmd::None
        }
        MouseEventKind::ScrollDown if point_in_body(model, event.x, event.y) => {
            model.candidates_cursor_down();
            DashboardCmd::None
        }
        _ => DashboardCmd::None,
    }
}

fn handle_ballast_mouse(model: &mut DashboardModel, event: MouseEvent) -> DashboardCmd {
    match event.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if let Some(idx) = ballast_row_hit(model, event.x, event.y) {
                model.ballast_selected = idx;
                model.ballast_detail = true;
            }
            DashboardCmd::None
        }
        MouseEventKind::ScrollUp if point_in_body(model, event.x, event.y) => {
            model.ballast_cursor_up();
            DashboardCmd::None
        }
        MouseEventKind::ScrollDown if point_in_body(model, event.x, event.y) => {
            model.ballast_cursor_down();
            DashboardCmd::None
        }
        _ => DashboardCmd::None,
    }
}

fn handle_log_search_mouse(model: &mut DashboardModel, event: MouseEvent) -> DashboardCmd {
    match event.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if let Some(idx) = log_search_row_hit(model, event.x, event.y) {
                model.log_search.selected = idx;
            }
            DashboardCmd::None
        }
        MouseEventKind::ScrollUp if point_in_body(model, event.x, event.y) => {
            model.log_search.cursor_up();
            DashboardCmd::None
        }
        MouseEventKind::ScrollDown if point_in_body(model, event.x, event.y) => {
            model.log_search.cursor_down();
            DashboardCmd::None
        }
        _ => DashboardCmd::None,
    }
}

fn dashboard_body_height(model: &DashboardModel) -> u16 {
    let notif_rows = u16::try_from(model.notifications.len().min(3)).unwrap_or(3);
    model
        .terminal_size
        .1
        .saturating_sub(FRAME_HEADER_ROWS)
        .saturating_sub(FRAME_FOOTER_ROWS)
        .saturating_sub(notif_rows)
}

fn body_local_y(model: &DashboardModel, y: u16) -> Option<u16> {
    if y < FRAME_HEADER_ROWS {
        return None;
    }
    let local_y = y.saturating_sub(FRAME_HEADER_ROWS);
    (local_y < dashboard_body_height(model)).then_some(local_y)
}

fn point_in_body(model: &DashboardModel, x: u16, y: u16) -> bool {
    let cols = model.terminal_size.0;
    x < cols && body_local_y(model, y).is_some()
}

fn centered_window(selected: usize, total: usize, rows: usize) -> (usize, usize) {
    if total == 0 {
        return (0, 0);
    }
    let rows = rows.max(1).min(total);
    let start = selected
        .saturating_sub(rows / 2)
        .min(total.saturating_sub(rows));
    let end = (start + rows).min(total);
    (start, end)
}

fn pane_content_row(x: u16, local_y: u16, rect: super::layout::PaneRect) -> Option<usize> {
    if rect.width < 3 || rect.height < 3 {
        return None;
    }
    let content_col_start = rect.col.saturating_add(1);
    let content_col_end = rect.col.saturating_add(rect.width).saturating_sub(1);
    let content_row_start = rect.row.saturating_add(1);
    let content_row_end = rect.row.saturating_add(rect.height).saturating_sub(1);
    if x < content_col_start
        || x >= content_col_end
        || local_y < content_row_start
        || local_y >= content_row_end
    {
        return None;
    }
    Some(usize::from(local_y.saturating_sub(content_row_start)))
}

fn timeline_row_hit(model: &DashboardModel, x: u16, y: u16) -> Option<usize> {
    let local_y = body_local_y(model, y)?;
    let layout = build_timeline_layout(model.terminal_size.0, dashboard_body_height(model));
    let list = layout
        .placements
        .into_iter()
        .find(|p| p.visible && p.pane == TimelinePane::EventList)?;
    let rel_row = pane_content_row(x, local_y, list.rect)?;
    let total = model.timeline_filtered_events().len();
    let rows = usize::from(list.rect.height.saturating_sub(2).max(1));
    let (start, end) = centered_window(model.timeline_selected, total, rows);
    let visible = end.saturating_sub(start);
    (rel_row < visible).then_some(start + rel_row)
}

fn explainability_row_hit(model: &DashboardModel, x: u16, y: u16) -> Option<usize> {
    let local_y = body_local_y(model, y)?;
    let layout = build_explainability_layout(model.terminal_size.0, dashboard_body_height(model));
    let list = layout
        .placements
        .into_iter()
        .find(|p| p.visible && p.pane == ExplainabilityPane::FactorBreakdown)?;
    let rel_row = pane_content_row(x, local_y, list.rect)?;
    let total = model.explainability_decisions.len();
    let rows = usize::from(list.rect.height.saturating_sub(2).max(1));
    let (start, end) = centered_window(model.explainability_selected, total, rows);
    let visible = end.saturating_sub(start);
    (rel_row < visible).then_some(start + rel_row)
}

fn candidates_row_hit(model: &DashboardModel, x: u16, y: u16) -> Option<usize> {
    let local_y = body_local_y(model, y)?;
    let layout = build_candidates_layout(model.terminal_size.0, dashboard_body_height(model));
    let list = layout
        .placements
        .into_iter()
        .find(|p| p.visible && p.pane == CandidatesPane::CandidateList)?;
    let rel_row = pane_content_row(x, local_y, list.rect)?;
    let total = model.candidates_list.len();
    let rows = usize::from(list.rect.height.saturating_sub(2).max(1));
    let (start, end) = centered_window(model.candidates_selected, total, rows);
    let visible = end.saturating_sub(start);
    (rel_row < visible).then_some(start + rel_row)
}

fn ballast_row_hit(model: &DashboardModel, x: u16, y: u16) -> Option<usize> {
    let local_y = body_local_y(model, y)?;
    let layout = build_ballast_layout(model.terminal_size.0, dashboard_body_height(model));
    let list = layout
        .placements
        .into_iter()
        .find(|p| p.visible && p.pane == BallastPane::VolumeList)?;
    let rel_row = pane_content_row(x, local_y, list.rect)?;
    let total = model.ballast_volumes.len();
    let rows = usize::from(list.rect.height.saturating_sub(2).max(1));
    let (start, end) = centered_window(model.ballast_selected, total, rows);
    let visible = end.saturating_sub(start);
    (rel_row < visible).then_some(start + rel_row)
}

fn log_search_row_hit(model: &DashboardModel, x: u16, y: u16) -> Option<usize> {
    let local_y = body_local_y(model, y)?;
    let layout = build_log_search_layout(model.terminal_size.0, dashboard_body_height(model));
    let list = layout
        .placements
        .into_iter()
        .find(|p| p.visible && p.pane == LogSearchPane::LogList)?;
    let rel_row = pane_content_row(x, local_y, list.rect)?;
    let total = model.log_search.results.len();
    let rows = usize::from(list.rect.height.saturating_sub(2).max(1));
    let (start, end) = centered_window(model.log_search.selected, total, rows);
    let visible = end.saturating_sub(start);
    (rel_row < visible).then_some(start + rel_row)
}

fn screen_tab_label(screen: Screen) -> &'static str {
    match screen {
        Screen::Overview => "Overview",
        Screen::Timeline => "Timeline",
        Screen::Explainability => "Explain",
        Screen::Candidates => "Candidates",
        Screen::Ballast => "Ballast",
        Screen::LogSearch => "Logs",
        Screen::Diagnostics => "Diagnostics",
    }
}

fn header_tab_hit_screen(model: &DashboardModel, x: u16, y: u16) -> Option<Screen> {
    if y != HEADER_TAB_ROW || x < 1 || x >= model.terminal_size.0.saturating_sub(1) {
        return None;
    }

    let screens = [
        Screen::Overview,
        Screen::Timeline,
        Screen::Explainability,
        Screen::Candidates,
        Screen::Ballast,
        Screen::LogSearch,
        Screen::Diagnostics,
    ];
    let mut cursor_x = 1u16;
    for screen in screens {
        let label = format!(" {}:{} ", screen.number(), screen_tab_label(screen));
        let width = u16::try_from(label.chars().count()).unwrap_or(u16::MAX);
        let end = cursor_x.saturating_add(width);
        if x >= cursor_x && x < end {
            return Some(screen);
        }
        cursor_x = end.saturating_add(1);
    }
    None
}

fn overview_visible_panes(model: &DashboardModel) -> Vec<OverviewPane> {
    let body_height = dashboard_body_height(model);
    build_overview_layout(model.terminal_size.0, body_height)
        .placements
        .into_iter()
        .filter(|p| p.visible)
        .map(|p| p.pane)
        .collect()
}

fn overview_ensure_focus_visible(model: &mut DashboardModel) {
    let visible = overview_visible_panes(model);
    if visible.is_empty() {
        return;
    }
    if !visible.contains(&model.overview_focus_pane) {
        model.overview_set_focus(visible[0]);
    }
}

fn overview_focus_step(model: &mut DashboardModel, forward: bool) {
    let visible = overview_visible_panes(model);
    if visible.is_empty() {
        return;
    }

    let current = visible
        .iter()
        .position(|pane| *pane == model.overview_focus_pane);
    let next = match (current, forward) {
        (Some(idx), true) => (idx + 1) % visible.len(),
        (Some(0) | None, false) => visible.len() - 1,
        (Some(idx), false) => idx - 1,
        (None, true) => 0,
    };
    model.overview_set_focus(visible[next]);
}

fn overview_pane_at(model: &DashboardModel, x: u16, y: u16) -> Option<OverviewPane> {
    let body_top = FRAME_HEADER_ROWS;
    let body_height = dashboard_body_height(model);
    if y < body_top || y >= body_top.saturating_add(body_height) {
        return None;
    }
    let local_y = y.saturating_sub(body_top);
    let layout = build_overview_layout(model.terminal_size.0, body_height);
    layout
        .placements
        .into_iter()
        .filter(|p| p.visible)
        .find(|p| {
            x >= p.rect.col
                && x < p.rect.col.saturating_add(p.rect.width)
                && local_y >= p.rect.row
                && local_y < p.rect.row.saturating_add(p.rect.height)
        })
        .map(|p| p.pane)
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use ftui::{
        KeyCode, KeyEvent, KeyEventKind, Modifiers, MouseButton, MouseEvent, MouseEventKind,
    };

    use super::*;
    use crate::daemon::self_monitor::{
        BallastState, Counters, DaemonState, LastScanState, MountPressure, PressureState,
    };
    use crate::tui::layout::{OverviewPane, PaneRect};
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

    fn make_mouse(kind: MouseEventKind, x: u16, y: u16) -> MouseEvent {
        MouseEvent {
            kind,
            x,
            y,
            modifiers: Modifiers::NONE,
        }
    }

    fn overview_pane_center(model: &DashboardModel, pane: OverviewPane) -> (u16, u16) {
        let body_height = dashboard_body_height(model);
        let placement = build_overview_layout(model.terminal_size.0, body_height)
            .placements
            .into_iter()
            .find(|p| p.visible && p.pane == pane)
            .expect("overview pane should be visible");
        let x = placement.rect.col.saturating_add(placement.rect.width / 2);
        let y = FRAME_HEADER_ROWS
            .saturating_add(placement.rect.row)
            .saturating_add(placement.rect.height / 2);
        (x, y)
    }

    fn header_tab_center(target: Screen) -> (u16, u16) {
        let screens = [
            Screen::Overview,
            Screen::Timeline,
            Screen::Explainability,
            Screen::Candidates,
            Screen::Ballast,
            Screen::LogSearch,
            Screen::Diagnostics,
        ];
        let mut cursor_x = 1u16;
        for screen in screens {
            let label = format!(" {}:{} ", screen.number(), screen_tab_label(screen));
            let width = u16::try_from(label.chars().count()).unwrap_or(0);
            if screen == target {
                return (cursor_x.saturating_add(width / 2), HEADER_TAB_ROW);
            }
            cursor_x = cursor_x.saturating_add(width).saturating_add(1);
        }
        (1, HEADER_TAB_ROW)
    }

    fn timeline_list_rect(model: &DashboardModel) -> PaneRect {
        let layout = build_timeline_layout(model.terminal_size.0, dashboard_body_height(model));
        layout
            .placements
            .into_iter()
            .find(|p| p.visible && p.pane == TimelinePane::EventList)
            .expect("timeline list pane")
            .rect
    }

    fn explainability_list_rect(model: &DashboardModel) -> PaneRect {
        let layout =
            build_explainability_layout(model.terminal_size.0, dashboard_body_height(model));
        layout
            .placements
            .into_iter()
            .find(|p| p.visible && p.pane == ExplainabilityPane::FactorBreakdown)
            .expect("explainability list pane")
            .rect
    }

    fn candidates_list_rect(model: &DashboardModel) -> PaneRect {
        let layout = build_candidates_layout(model.terminal_size.0, dashboard_body_height(model));
        layout
            .placements
            .into_iter()
            .find(|p| p.visible && p.pane == CandidatesPane::CandidateList)
            .expect("candidates list pane")
            .rect
    }

    fn ballast_list_rect(model: &DashboardModel) -> PaneRect {
        let layout = build_ballast_layout(model.terminal_size.0, dashboard_body_height(model));
        layout
            .placements
            .into_iter()
            .find(|p| p.visible && p.pane == BallastPane::VolumeList)
            .expect("ballast list pane")
            .rect
    }

    fn log_list_rect(model: &DashboardModel) -> PaneRect {
        let layout = build_log_search_layout(model.terminal_size.0, dashboard_body_height(model));
        layout
            .placements
            .into_iter()
            .find(|p| p.visible && p.pane == LogSearchPane::LogList)
            .expect("log list pane")
            .rect
    }

    fn pane_row_click(rect: PaneRect, row: u16) -> (u16, u16) {
        let x = rect.col.saturating_add(2);
        let y = FRAME_HEADER_ROWS
            .saturating_add(rect.row)
            .saturating_add(1)
            .saturating_add(row);
        (x, y)
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
            policy_mode: "enforce".into(),
            memory_rss_bytes: 52_428_800,
            ..crate::daemon::self_monitor::DaemonState::default()
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
    fn esc_closes_detail_before_history_navigation() {
        let mut model = test_model();
        model.navigate_to(Screen::Candidates);
        model.candidates_detail = true;
        model.screen_history = vec![Screen::Overview];

        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Escape)));
        assert!(matches!(cmd, DashboardCmd::None));
        assert_eq!(model.screen, Screen::Candidates);
        assert!(!model.candidates_detail);
        assert!(!model.quit);
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

    #[test]
    fn mouse_click_on_overview_pane_navigates_to_target_screen() {
        let mut model = test_model();
        model.screen = Screen::Overview;
        let (click_x, click_y) = overview_pane_center(&model, OverviewPane::PressureSummary);
        let cmd = update(
            &mut model,
            DashboardMsg::Mouse(make_mouse(
                MouseEventKind::Down(MouseButton::Left),
                click_x,
                click_y,
            )),
        );
        assert!(matches!(cmd, DashboardCmd::None));
        assert_eq!(model.screen, Screen::Timeline);
    }

    #[test]
    fn mouse_move_updates_overview_hover_state() {
        let mut model = test_model();
        model.screen = Screen::Overview;
        let (x, y) = overview_pane_center(&model, OverviewPane::PressureSummary);
        update(
            &mut model,
            DashboardMsg::Mouse(make_mouse(MouseEventKind::Moved, x, y)),
        );
        assert!(model.overview_hover_pane.is_some());
    }

    #[test]
    fn mouse_wheel_on_hotlist_moves_candidate_selection() {
        let mut model = test_model();
        model.screen = Screen::Overview;
        model.terminal_size = (140, 42);
        model.candidates_list = vec![sample_decision(1), sample_decision(2)];
        model.candidates_selected = 0;
        let (x, y) = overview_pane_center(&model, OverviewPane::CandidateHotlist);

        update(
            &mut model,
            DashboardMsg::Mouse(make_mouse(MouseEventKind::ScrollDown, x, y)),
        );
        assert_eq!(model.candidates_selected, 1);

        update(
            &mut model,
            DashboardMsg::Mouse(make_mouse(MouseEventKind::ScrollUp, x, y)),
        );
        assert_eq!(model.candidates_selected, 0);
    }

    #[test]
    fn mouse_wheel_outside_hotlist_does_not_move_candidates() {
        let mut model = test_model();
        model.screen = Screen::Overview;
        model.terminal_size = (140, 42);
        model.candidates_list = vec![sample_decision(1), sample_decision(2)];
        model.candidates_selected = 1;
        let (x, y) = overview_pane_center(&model, OverviewPane::PressureSummary);

        update(
            &mut model,
            DashboardMsg::Mouse(make_mouse(MouseEventKind::ScrollDown, x, y)),
        );
        assert_eq!(model.candidates_selected, 1);
    }

    #[test]
    fn mouse_click_on_header_tab_navigates_to_screen() {
        let mut model = test_model();
        model.screen = Screen::Overview;
        let (x, y) = header_tab_center(Screen::Ballast);
        update(
            &mut model,
            DashboardMsg::Mouse(make_mouse(MouseEventKind::Down(MouseButton::Left), x, y)),
        );
        assert_eq!(model.screen, Screen::Ballast);
    }

    #[test]
    fn timeline_mouse_wheel_scrolls_anywhere_in_body() {
        let mut model = test_model();
        model.screen = Screen::Timeline;
        model.timeline_events = vec![
            sample_timeline_event("info", "a"),
            sample_timeline_event("warning", "b"),
            sample_timeline_event("critical", "c"),
        ];
        model.timeline_selected = 1;
        let rect = timeline_list_rect(&model);
        let (x, y) = pane_row_click(rect, 0);
        update(
            &mut model,
            DashboardMsg::Mouse(make_mouse(MouseEventKind::ScrollDown, x, y)),
        );
        assert_eq!(model.timeline_selected, 2);
        update(
            &mut model,
            DashboardMsg::Mouse(make_mouse(MouseEventKind::ScrollUp, x, y)),
        );
        assert_eq!(model.timeline_selected, 1);
    }

    #[test]
    fn explainability_click_row_selects_and_opens_detail() {
        let mut model = test_model();
        model.screen = Screen::Explainability;
        model.explainability_decisions = vec![sample_decision(1), sample_decision(2)];
        model.explainability_selected = 0;
        model.explainability_detail = false;
        let rect = explainability_list_rect(&model);
        let (x, y) = pane_row_click(rect, 1);
        update(
            &mut model,
            DashboardMsg::Mouse(make_mouse(MouseEventKind::Down(MouseButton::Left), x, y)),
        );
        assert_eq!(model.explainability_selected, 1);
        assert!(model.explainability_detail);
    }

    #[test]
    fn candidates_click_row_selects_and_opens_detail() {
        let mut model = test_model();
        model.screen = Screen::Candidates;
        model.candidates_list = vec![sample_decision(1), sample_decision(2)];
        model.candidates_selected = 0;
        model.candidates_detail = false;
        let rect = candidates_list_rect(&model);
        let (x, y) = pane_row_click(rect, 1);
        update(
            &mut model,
            DashboardMsg::Mouse(make_mouse(MouseEventKind::Down(MouseButton::Left), x, y)),
        );
        assert_eq!(model.candidates_selected, 1);
        assert!(model.candidates_detail);
    }

    #[test]
    fn ballast_click_row_selects_and_opens_detail() {
        let mut model = test_model();
        model.screen = Screen::Ballast;
        model.ballast_volumes = vec![sample_volume("/", 3, 5), sample_volume("/data", 2, 5)];
        model.ballast_selected = 0;
        model.ballast_detail = false;
        let rect = ballast_list_rect(&model);
        let (x, y) = pane_row_click(rect, 1);
        update(
            &mut model,
            DashboardMsg::Mouse(make_mouse(MouseEventKind::Down(MouseButton::Left), x, y)),
        );
        assert_eq!(model.ballast_selected, 1);
        assert!(model.ballast_detail);
    }

    #[test]
    fn log_search_wheel_scrolls_the_search_selection() {
        let mut model = test_model();
        model.screen = Screen::LogSearch;
        model.log_search.results = vec![
            sample_timeline_event("info", "a"),
            sample_timeline_event("warning", "b"),
            sample_timeline_event("critical", "c"),
        ];
        model.log_search.selected = 1;
        let rect = log_list_rect(&model);
        let (x, y) = pane_row_click(rect, 0);
        update(
            &mut model,
            DashboardMsg::Mouse(make_mouse(MouseEventKind::ScrollDown, x, y)),
        );
        assert_eq!(model.log_search.selected, 2);
        update(
            &mut model,
            DashboardMsg::Mouse(make_mouse(MouseEventKind::ScrollUp, x, y)),
        );
        assert_eq!(model.log_search.selected, 1);
        // The Timeline's own cursor is untouched by the search list.
        assert_eq!(model.timeline_selected, 0);
    }

    #[test]
    fn overview_focus_navigation_skips_hidden_panes() {
        let mut model = test_model();
        model.screen = Screen::Overview;
        model.terminal_size = (80, 16);
        model.overview_set_focus(OverviewPane::ExtendedCounters);

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Tab)));
        let visible = overview_visible_panes(&model);
        assert!(visible.contains(&model.overview_focus_pane));
        assert_ne!(model.overview_focus_pane, OverviewPane::ExtendedCounters);
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
    fn overlay_mouse_click_closes_overlay_without_quit() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::Help);

        let cmd = update(
            &mut model,
            DashboardMsg::Mouse(make_mouse(MouseEventKind::Down(MouseButton::Left), 10, 10)),
        );
        assert!(model.active_overlay.is_none());
        assert!(!model.quit);
        assert!(matches!(cmd, DashboardCmd::None));
    }

    #[test]
    fn overlay_mouse_click_closes_palette_and_resets_query() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::CommandPalette);
        model.palette_query = String::from("diag");
        model.palette_selected = 4;

        update(
            &mut model,
            DashboardMsg::Mouse(make_mouse(MouseEventKind::Down(MouseButton::Left), 20, 8)),
        );
        assert!(model.active_overlay.is_none());
        assert!(model.palette_query.is_empty());
        assert_eq!(model.palette_selected, 0);
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

    #[test]
    fn palette_preference_density_action_dispatches_runtime_command() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::CommandPalette);
        model.palette_query = "pref.density.compact".to_string();

        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Enter)));
        assert!(matches!(
            cmd,
            DashboardCmd::ExecutePreferenceAction(PreferenceAction::SetDensity(
                crate::tui::preferences::DensityMode::Compact
            ))
        ));
    }

    #[test]
    fn palette_preference_reset_defaults_dispatches_runtime_command() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::CommandPalette);
        model.palette_query = "pref.reset.defaults".to_string();

        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Enter)));
        assert!(matches!(
            cmd,
            DashboardCmd::ExecutePreferenceAction(PreferenceAction::RevertToDefaults)
        ));
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
    fn tick_on_overview_requests_telemetry() {
        let mut model = test_model();
        model.screen = Screen::Overview;

        let cmd = update(&mut model, DashboardMsg::Tick);
        if let DashboardCmd::Batch(cmds) = cmd {
            let has_telemetry = cmds
                .iter()
                .any(|c| matches!(c, DashboardCmd::FetchTelemetry));
            assert!(has_telemetry, "Tick on S1 should include FetchTelemetry");
        }
    }

    // ── S2 Timeline key handling tests ──

    use crate::tui::model::SeverityFilter;
    use crate::tui::telemetry::TimelineEvent;

    fn sample_timeline_event(severity: &str, event_type: &str) -> TimelineEvent {
        TimelineEvent {
            decision_id: None,
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
    fn enter_on_the_release_confirmation_emits_a_control_release() {
        let mut model = test_model();
        model.screen = Screen::Ballast;
        model.ballast_volumes = vec![sample_volume("/", 3, 5), sample_volume("/data", 2, 5)];
        model.ballast_selected = 1;

        // Single release: one file on the selected mount.
        model.active_overlay = Some(Overlay::Confirmation(ConfirmAction::BallastRelease));
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Enter)));
        match cmd {
            DashboardCmd::ReleaseBallast {
                mount,
                ballast_dir,
                count,
            } => {
                assert_eq!(mount, "/data");
                assert_eq!(ballast_dir, "/data/.sbh/ballast");
                assert_eq!(count, 1);
            }
            other => panic!("expected ReleaseBallast, got {other:?}"),
        }
        assert!(model.active_overlay.is_none(), "confirmation closes");
        assert!(
            model
                .notifications
                .iter()
                .any(|n| n.message.contains("Releasing 1 ballast file")),
            "operator is told what was asked for"
        );

        // Release-all: X on the Ballast screen opens the confirmation, Enter
        // asks for every available file on the selected mount.
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('X'))));
        assert!(matches!(cmd, DashboardCmd::None));
        assert_eq!(
            model.active_overlay,
            Some(Overlay::Confirmation(ConfirmAction::BallastReleaseAll))
        );
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Enter)));
        assert!(
            matches!(cmd, DashboardCmd::ReleaseBallast { ref mount, count, .. } if mount == "/data" && count == 2),
            "{cmd:?}"
        );

        // Replenish: p opens its confirmation, Enter emits the replenish.
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('p'))));
        assert_eq!(
            model.active_overlay,
            Some(Overlay::Confirmation(ConfirmAction::BallastReplenish))
        );
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Enter)));
        assert!(
            matches!(cmd, DashboardCmd::ReplenishBallast { ref mount, ref ballast_dir } if mount == "/data" && ballast_dir == "/data/.sbh/ballast"),
            "{cmd:?}"
        );

        // A full pool has nothing to replenish, an empty one nothing to
        // release: the confirmation does not open and the reason is shown.
        model.ballast_volumes[1] = sample_volume("/data", 5, 5);
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('p'))));
        assert!(model.active_overlay.is_none());
        assert!(
            model
                .notifications
                .iter()
                .any(|n| n.message.contains("already full")),
            "{:?}",
            model.notifications
        );
        model.ballast_volumes[1] = sample_volume("/data", 0, 5);
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('X'))));
        assert!(model.active_overlay.is_none());
        assert!(
            model
                .notifications
                .iter()
                .any(|n| n.message.contains("No ballast file available")),
            "{:?}",
            model.notifications
        );
        model.ballast_volumes[1] = sample_volume("/data", 2, 5);

        // No volume selected: nothing is sent to the daemon.
        model.ballast_volumes.clear();
        model.active_overlay = Some(Overlay::Confirmation(ConfirmAction::BallastRelease));
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Enter)));
        assert!(matches!(cmd, DashboardCmd::None), "{cmd:?}");
        assert!(model.active_overlay.is_none());

        // Escape still cancels without a command.
        model.ballast_volumes = vec![sample_volume("/", 3, 5)];
        model.active_overlay = Some(Overlay::Confirmation(ConfirmAction::BallastReleaseAll));
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Escape)));
        assert!(matches!(cmd, DashboardCmd::None), "{cmd:?}");
        assert!(model.active_overlay.is_none());
    }

    #[test]
    fn daemon_pool_records_drive_the_volume_list_and_quick_release() {
        use crate::daemon::self_monitor::BallastPoolState;

        let pool = |mount: &str, dir: &str, available: usize, total: usize| BallastPoolState {
            mount: mount.to_string(),
            ballast_dir: dir.to_string(),
            fs_type: "ext4".to_string(),
            strategy: "fallocate".to_string(),
            available,
            total,
            releasable_bytes: available as u64 * 1_048_576,
            skipped: false,
            skip_reason: None,
        };
        let mut model = test_model();
        // Written in one order by the daemon, listed sorted by mount.
        let state = DaemonState {
            ballast_pools: vec![
                pool("/data", "/data/.sbh/ballast", 2, 2),
                pool("/", "/.sbh/ballast", 0, 0),
            ],
            ..Default::default()
        };
        update(&mut model, DashboardMsg::DataUpdate(Some(Box::new(state))));
        let mounts: Vec<&str> = model
            .ballast_volumes
            .iter()
            .map(|v| v.mount_point.as_str())
            .collect();
        assert_eq!(mounts, vec!["/", "/data"]);
        assert_eq!(model.ballast_volumes[1].ballast_dir, "/data/.sbh/ballast");
        assert_eq!(model.ballast_selected, 0, "cursor starts on the first row");

        // Quick-release lands on the volume that has files, not the root
        // row without a pool, and opens the confirmation there.
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('x'))));
        assert_eq!(model.screen, Screen::Ballast);
        assert_eq!(model.ballast_selected, 1);
        assert_eq!(
            model.active_overlay,
            Some(Overlay::Confirmation(ConfirmAction::BallastRelease))
        );
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Enter)));
        assert!(
            matches!(cmd, DashboardCmd::ReleaseBallast { ref mount, ref ballast_dir, count: 1 } if mount == "/data" && ballast_dir == "/data/.sbh/ballast"),
            "{cmd:?}"
        );

        // A refresh keeps the cursor on the same mount even when the list
        // order changes, and an older daemon (no pool records) still gets
        // the synthesized aggregate volume.
        let refreshed = DaemonState {
            ballast_pools: vec![
                pool("/", "/.sbh/ballast", 0, 0),
                pool("/data", "/data/.sbh/ballast", 1, 2),
            ],
            ..Default::default()
        };
        update(
            &mut model,
            DashboardMsg::DataUpdate(Some(Box::new(refreshed))),
        );
        assert_eq!(
            model.ballast_selected_volume().unwrap().mount_point,
            "/data"
        );
        assert_eq!(model.ballast_selected_volume().unwrap().files_available, 1);

        let mut legacy = test_model();
        let old_daemon = DaemonState {
            ballast: BallastState {
                available: 3,
                total: 4,
                released: 1,
            },
            ..Default::default()
        };
        update(
            &mut legacy,
            DashboardMsg::DataUpdate(Some(Box::new(old_daemon))),
        );
        assert_eq!(legacy.ballast_volumes.len(), 1);
        assert_eq!(legacy.ballast_volumes[0].files_available, 3);
        assert!(legacy.ballast_volumes[0].ballast_dir.is_empty());

        // Quick-release with nothing to give explains itself instead of
        // opening a confirmation that could only fail.
        let mut empty = test_model();
        empty.ballast_volumes = vec![sample_volume("/", 0, 5)];
        update(&mut empty, DashboardMsg::Key(make_key(KeyCode::Char('x'))));
        assert!(empty.active_overlay.is_none());
        assert!(
            empty
                .notifications
                .iter()
                .any(|n| n.message.contains("No ballast file available")),
            "{:?}",
            empty.notifications
        );
    }

    fn log_event(timestamp: &str, path: &str) -> crate::tui::telemetry::TimelineEvent {
        crate::tui::telemetry::TimelineEvent {
            timestamp: timestamp.to_string(),
            event_type: "artifact_delete".to_string(),
            severity: "info".to_string(),
            path: Some(path.to_string()),
            size_bytes: None,
            score: None,
            pressure_level: None,
            free_pct: None,
            success: Some(true),
            error_code: None,
            error_message: None,
            duration_ms: None,
            details: None,
            decision_id: None,
        }
    }

    fn log_page(
        events: Vec<crate::tui::telemetry::TimelineEvent>,
        page: usize,
        has_more: bool,
    ) -> DashboardMsg {
        DashboardMsg::TelemetryLogSearch(crate::tui::telemetry::TelemetryResult {
            data: crate::tui::telemetry::LogSearchPage {
                events,
                page,
                page_size: 50,
                has_more,
            },
            source: crate::tui::telemetry::DataSource::Sqlite,
            partial: false,
            diagnostics: String::new(),
        })
    }

    /// bd-rc-master-ajg1.4.10: `/` edits the query inline and owns every key
    /// until Enter runs it or Esc cancels; n/p page, c clears, Enter opens
    /// the entry on the Timeline.
    #[test]
    fn log_search_query_editing_paging_and_open_on_timeline() {
        let mut model = test_model();
        model.screen = Screen::LogSearch;
        update(
            &mut model,
            log_page(vec![log_event("t1", "/a"), log_event("t2", "/b")], 0, true),
        );
        assert!(model.log_search.ran);
        assert_eq!(model.log_search.results.len(), 2);

        // / opens the editor; typed keys (even q) go to the draft.
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('/'))));
        assert!(matches!(cmd, DashboardCmd::None));
        assert!(model.log_search.editing);
        for c in ['q', 'u', 'e', 'r', 'y'] {
            update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char(c))));
        }
        assert!(!model.quit, "q while editing is text, not quit");
        assert_eq!(model.log_search.draft, "query");
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Backspace)));
        assert_eq!(model.log_search.draft, "quer");

        // Esc cancels: query unchanged, editor closed.
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Escape)));
        assert!(matches!(cmd, DashboardCmd::None));
        assert!(!model.log_search.editing);
        assert!(model.log_search.query.is_empty());
        assert_eq!(model.screen, Screen::LogSearch, "Esc did not navigate back");

        // Enter runs the draft from page 0 and asks for telemetry.
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('/'))));
        for c in "type:artifact_delete".chars() {
            update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char(c))));
        }
        model.log_search.page = 3;
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Enter)));
        assert!(matches!(cmd, DashboardCmd::FetchTelemetry), "{cmd:?}");
        assert_eq!(model.log_search.query, "type:artifact_delete");
        assert_eq!(model.log_search.page, 0);
        assert!(!model.log_search.editing);
        let query = model.log_search.to_query();
        assert_eq!(query.event_type.as_deref(), Some("artifact_delete"));
        assert_eq!(query.page_size, crate::tui::model::LOG_SEARCH_PAGE_SIZE);

        // n pages forward only while more exists; p back only above page 0.
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('n'))));
        assert!(matches!(cmd, DashboardCmd::FetchTelemetry));
        assert_eq!(model.log_search.page, 1);
        update(&mut model, log_page(vec![log_event("t3", "/c")], 1, false));
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('n'))));
        assert!(matches!(cmd, DashboardCmd::None));
        assert_eq!(model.log_search.page, 1);
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('p'))));
        assert!(matches!(cmd, DashboardCmd::FetchTelemetry));
        assert_eq!(model.log_search.page, 0);
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('p'))));
        assert!(matches!(cmd, DashboardCmd::None));

        // c clears the query.
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('c'))));
        assert!(matches!(cmd, DashboardCmd::FetchTelemetry));
        assert!(model.log_search.query.is_empty());

        // Enter on a result opens it on the Timeline when it is there.
        update(
            &mut model,
            log_page(vec![log_event("t1", "/a"), log_event("t2", "/b")], 0, false),
        );
        model.timeline_events = vec![log_event("t0", "/z"), log_event("t2", "/b")];
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('j'))));
        assert_eq!(model.log_search.selected, 1);
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Enter)));
        assert_eq!(model.screen, Screen::Timeline);
        assert_eq!(model.timeline_selected, 1);
        assert!(!model.timeline_follow);
    }

    /// bd-rc-master-ajg1.4.13: during replay the scrubber keys queue a
    /// command for the runtime's driver instead of reaching the screens,
    /// and ballast actions are refused with a hint.
    #[test]
    fn replay_keys_queue_commands_and_actions_are_refused() {
        use crate::tui::replay::{ReplayCommand, ReplaySpeed, ReplayStatus};

        let mut model = test_model();
        model.screen = Screen::Ballast;
        model.ballast_volumes = vec![sample_volume("/data", 2, 5)];

        // Without replay, Space on the Ballast screen toggles the detail pane.
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char(' '))));
        assert!(model.replay_pending.is_none());
        assert!(model.ballast_detail);
        model.ballast_detail = false;

        model.replay = Some(ReplayStatus {
            file: "activity.jsonl".to_string(),
            cursor_ts: Some("2026-08-30T10:00:02Z".to_string()),
            applied: 2,
            total: 4,
            paused: false,
            speed: ReplaySpeed::X10,
            skipped_lines: 0,
        });
        for (code, expected) in [
            (KeyCode::Char(' '), ReplayCommand::TogglePause),
            (KeyCode::Char(','), ReplayCommand::StepBack),
            (KeyCode::Char('.'), ReplayCommand::StepForward),
            (KeyCode::Home, ReplayCommand::SeekStart),
            (KeyCode::End, ReplayCommand::SeekEnd),
        ] {
            let cmd = update(&mut model, DashboardMsg::Key(make_key(code)));
            assert!(matches!(cmd, DashboardCmd::None));
            assert_eq!(model.replay_pending.take(), Some(expected), "{code:?}");
        }
        assert!(
            !model.ballast_detail,
            "Space went to the scrubber, not the screen"
        );

        // Other keys still navigate; overlays take precedence over the scrubber.
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('2'))));
        assert_eq!(model.screen, Screen::Timeline);
        model.active_overlay = Some(Overlay::Help);
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char(' '))));
        assert!(
            model.replay_pending.is_none(),
            "help overlay swallowed Space"
        );
        model.active_overlay = None;

        // Quick-release and the Ballast keys refuse with a hint.
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('x'))));
        assert!(model.active_overlay.is_none());
        assert!(
            model
                .notifications
                .iter()
                .any(|n| n.message.contains("Replay: ballast actions are disabled")),
            "{:?}",
            model.notifications
        );
        model.screen = Screen::Ballast;
        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('X'))));
        assert!(model.active_overlay.is_none());
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

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char(' '))));
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

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Backspace)));
        assert_eq!(model.palette_query, "a");
    }

    #[test]
    fn palette_backspace_on_empty_is_noop() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::CommandPalette);
        assert!(model.palette_query.is_empty());

        update(&mut model, DashboardMsg::Key(make_key(KeyCode::Backspace)));
        assert!(model.palette_query.is_empty());
    }

    #[test]
    fn palette_cursor_navigation() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::CommandPalette);
        // Empty query shows the first page of palette actions.
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
    fn palette_cursor_clamps_to_rendered_page_limit() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::CommandPalette);

        for _ in 0..50 {
            update(&mut model, DashboardMsg::Key(make_key(KeyCode::Down)));
        }

        assert_eq!(model.palette_selected, PALETTE_RESULT_LIMIT - 1);
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

        // Move cursor to the bottom of the rendered page with empty query.
        for _ in 0..10 {
            update(&mut model, DashboardMsg::Key(make_key(KeyCode::Down)));
        }
        assert_eq!(model.palette_selected, PALETTE_RESULT_LIMIT - 1);

        // Type a very specific query that produces fewer results.
        for c in "action.quit".chars() {
            update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char(c))));
        }
        // Cursor should be clamped to the result count.
        assert!(model.palette_selected < PALETTE_RESULT_LIMIT);
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

    // ── Tick on LogSearch screen ──

    #[test]
    fn tick_on_logsearch_does_not_request_telemetry() {
        let mut model = test_model();
        model.screen = Screen::LogSearch;

        let cmd = update(&mut model, DashboardMsg::Tick);
        if let DashboardCmd::Batch(cmds) = cmd {
            let has_telemetry = cmds
                .iter()
                .any(|c| matches!(c, DashboardCmd::FetchTelemetry));
            assert!(
                !has_telemetry,
                "Tick on S6 should not include FetchTelemetry"
            );
        }
    }

    // ── Multi-mount DataUpdate ──

    #[test]
    fn data_update_with_multiple_mounts() {
        let mut model = test_model();
        let mut state = sample_daemon_state();
        state.pressure.mounts.push(MountPressure {
            path: String::from("/data"),
            free_pct: 25.0,
            level: String::from("orange"),
            rate_bps: Some(2048.0),
        });

        update(&mut model, DashboardMsg::DataUpdate(Some(Box::new(state))));
        assert_eq!(model.rate_histories.len(), 2);
        assert!(model.rate_histories.contains_key("/"));
        assert!(model.rate_histories.contains_key("/data"));
    }

    #[test]
    fn data_update_prunes_stale_mount_histories() {
        let mut model = test_model();

        // First update with two mounts.
        let mut state1 = sample_daemon_state();
        state1.pressure.mounts.push(MountPressure {
            path: String::from("/data"),
            free_pct: 25.0,
            level: String::from("orange"),
            rate_bps: Some(512.0),
        });
        update(&mut model, DashboardMsg::DataUpdate(Some(Box::new(state1))));
        assert_eq!(model.rate_histories.len(), 2);

        // Second update with only one mount — /data was unmounted.
        let state2 = sample_daemon_state(); // only has "/"
        update(&mut model, DashboardMsg::DataUpdate(Some(Box::new(state2))));
        assert_eq!(model.rate_histories.len(), 1);
        assert!(model.rate_histories.contains_key("/"));
        assert!(!model.rate_histories.contains_key("/data"));
    }

    #[test]
    fn data_update_some_clears_degraded() {
        let mut model = test_model();
        model.degraded = true;
        update(
            &mut model,
            DashboardMsg::DataUpdate(Some(Box::new(sample_daemon_state()))),
        );
        assert!(!model.degraded);
    }

    // ── Tick wrapping ──

    #[test]
    fn tick_wraps_counter() {
        let mut model = test_model();
        model.tick = u64::MAX;
        update(&mut model, DashboardMsg::Tick);
        assert_eq!(model.tick, 0); // wrapping_add
    }

    // ── Tick always includes FetchData + ScheduleTick ──

    #[test]
    fn tick_always_includes_fetch_data_and_schedule_tick() {
        let mut model = test_model();
        let cmd = update(&mut model, DashboardMsg::Tick);
        if let DashboardCmd::Batch(cmds) = cmd {
            let has_fetch = cmds.iter().any(|c| matches!(c, DashboardCmd::FetchData));
            let has_schedule = cmds
                .iter()
                .any(|c| matches!(c, DashboardCmd::ScheduleTick(_)));
            assert!(has_fetch, "Tick must always include FetchData");
            assert!(has_schedule, "Tick must always include ScheduleTick");
        } else {
            panic!("Expected Batch command from Tick");
        }
    }

    // ── Error msg creates notification ──

    #[test]
    fn error_msg_creates_notification_and_schedules_expiry() {
        let mut model = test_model();
        let cmd = update(
            &mut model,
            DashboardMsg::Error(crate::tui::model::DashboardError {
                message: "test error".to_string(),
                source: "adapter".to_string(),
            }),
        );
        assert_eq!(model.notifications.len(), 1);
        assert_eq!(model.notifications[0].message, "test error");
        assert!(matches!(
            cmd,
            DashboardCmd::ScheduleNotificationExpiry { .. }
        ));
    }

    // ── ForceRefresh msg ──

    #[test]
    fn force_refresh_returns_fetch_data() {
        let mut model = test_model();
        let cmd = update(&mut model, DashboardMsg::ForceRefresh);
        assert!(matches!(cmd, DashboardCmd::FetchData));
    }

    // ── ToggleOverlay/CloseOverlay msgs ──

    #[test]
    fn toggle_overlay_opens_and_closes() {
        let mut model = test_model();
        update(&mut model, DashboardMsg::ToggleOverlay(Overlay::Help));
        assert_eq!(model.active_overlay, Some(Overlay::Help));

        update(&mut model, DashboardMsg::ToggleOverlay(Overlay::Help));
        assert!(model.active_overlay.is_none());
    }

    #[test]
    fn close_overlay_clears_active() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::Voi);
        update(&mut model, DashboardMsg::CloseOverlay);
        assert!(model.active_overlay.is_none());
    }

    // ── TelemetryTimeline follow mode ──

    #[test]
    fn telemetry_timeline_follow_mode_jumps_to_latest() {
        let mut model = test_model();
        model.timeline_follow = true;
        model.timeline_selected = 0;

        let result = TelemetryResult {
            data: vec![
                sample_timeline_event("info", "a"),
                sample_timeline_event("info", "b"),
                sample_timeline_event("info", "c"),
            ],
            source: crate::tui::telemetry::DataSource::Sqlite,
            partial: false,
            diagnostics: String::new(),
        };

        update(&mut model, DashboardMsg::TelemetryTimeline(result));
        assert_eq!(model.timeline_selected, 2); // last event
    }

    #[test]
    fn telemetry_timeline_no_follow_clamps_cursor() {
        let mut model = test_model();
        model.timeline_follow = false;
        model.timeline_selected = 5; // out of range

        let result = TelemetryResult {
            data: vec![
                sample_timeline_event("info", "a"),
                sample_timeline_event("info", "b"),
            ],
            source: crate::tui::telemetry::DataSource::Sqlite,
            partial: false,
            diagnostics: String::new(),
        };

        update(&mut model, DashboardMsg::TelemetryTimeline(result));
        assert_eq!(model.timeline_selected, 1); // clamped to last
    }

    #[test]
    fn esc_quits_when_history_empty() {
        let mut model = test_model();
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Escape)));
        assert!(matches!(cmd, DashboardCmd::Quit));
        assert!(model.quit);
    }

    // ── Preference action commands ──

    #[test]
    fn preference_action_commands_returned() {
        let mut model = test_model();
        model.active_overlay = Some(Overlay::CommandPalette);
        // Type exact action ID for density compact
        for c in "pref.density.compact".chars() {
            update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char(c))));
        }
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Enter)));
        assert!(matches!(
            cmd,
            DashboardCmd::ExecutePreferenceAction(PreferenceAction::SetDensity(
                crate::tui::preferences::DensityMode::Compact
            ))
        ));
    }

    // ── DataUpdate with None rate_bps ──

    #[test]
    fn data_update_handles_none_rate_bps() {
        let mut model = test_model();
        let mut state = sample_daemon_state();
        state.pressure.mounts[0].rate_bps = None;

        update(&mut model, DashboardMsg::DataUpdate(Some(Box::new(state))));
        assert_eq!(model.rate_histories.len(), 1);
        let history = model.rate_histories.get("/").unwrap();
        assert_eq!(history.latest(), Some(0.0)); // None → 0.0 fallback
    }

    // ── DataUpdate sets last_fetch ──

    #[test]
    fn data_update_sets_last_fetch() {
        let mut model = test_model();
        assert!(model.last_fetch.is_none());

        update(
            &mut model,
            DashboardMsg::DataUpdate(Some(Box::new(sample_daemon_state()))),
        );
        assert!(model.last_fetch.is_some());
    }

    #[test]
    fn data_update_none_also_sets_last_fetch() {
        let mut model = test_model();
        assert!(model.last_fetch.is_none());

        update(&mut model, DashboardMsg::DataUpdate(None));
        assert!(model.last_fetch.is_some());
    }
}
