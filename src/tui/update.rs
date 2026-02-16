//! Pure update function for the Elm-style TUI dashboard.
//!
//! `update()` takes the current model and a message, mutates the model, and
//! returns a command describing any side-effects the runtime should execute.
//!
//! **Design invariant:** this module performs zero I/O. All effects are
//! described as [`DashboardCmd`] values.

use std::time::Instant;

use crossterm::event::{KeyCode, KeyModifiers};

use super::model::{DashboardCmd, DashboardModel, DashboardMsg, RateHistory};

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

        DashboardMsg::Key(key) => match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                model.quit = true;
                DashboardCmd::Quit
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                model.quit = true;
                DashboardCmd::Quit
            }
            // Future: screen navigation keys will be handled here.
            _ => DashboardCmd::None,
        },

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

            model.daemon_state = state;
            DashboardCmd::None
        }
    }
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    use super::*;
    use crate::daemon::self_monitor::{
        BallastState, Counters, DaemonState, LastScanState, MountPressure, PressureState,
    };

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
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn make_key_ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
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

    #[test]
    fn tick_increments_counter_and_fetches_data() {
        let mut model = test_model();
        assert_eq!(model.tick, 0);

        let cmd = update(&mut model, DashboardMsg::Tick);
        assert_eq!(model.tick, 1);
        assert!(matches!(cmd, DashboardCmd::Batch(_)));
    }

    #[test]
    fn quit_on_q_key() {
        let mut model = test_model();
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('q'))));
        assert!(model.quit);
        assert!(matches!(cmd, DashboardCmd::Quit));
    }

    #[test]
    fn quit_on_esc() {
        let mut model = test_model();
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Esc)));
        assert!(model.quit);
        assert!(matches!(cmd, DashboardCmd::Quit));
    }

    #[test]
    fn quit_on_ctrl_c() {
        let mut model = test_model();
        let cmd = update(
            &mut model,
            DashboardMsg::Key(make_key_ctrl(KeyCode::Char('c'))),
        );
        assert!(model.quit);
        assert!(matches!(cmd, DashboardCmd::Quit));
    }

    #[test]
    fn unknown_key_is_noop() {
        let mut model = test_model();
        let cmd = update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('z'))));
        assert!(!model.quit);
        assert!(matches!(cmd, DashboardCmd::None));
    }

    #[test]
    fn resize_updates_terminal_size() {
        let mut model = test_model();
        assert_eq!(model.terminal_size, (80, 24));

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
    fn data_update_with_state_clears_degraded() {
        let mut model = test_model();
        assert!(model.degraded);

        let cmd = update(
            &mut model,
            DashboardMsg::DataUpdate(Some(sample_daemon_state())),
        );
        assert!(!model.degraded);
        assert!(model.daemon_state.is_some());
        assert!(model.last_fetch.is_some());
        assert!(matches!(cmd, DashboardCmd::None));
    }

    #[test]
    fn data_update_none_sets_degraded() {
        let mut model = test_model();
        // First make it non-degraded.
        update(
            &mut model,
            DashboardMsg::DataUpdate(Some(sample_daemon_state())),
        );
        assert!(!model.degraded);

        // Now send None.
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
            DashboardMsg::DataUpdate(Some(sample_daemon_state())),
        );
        assert!(model.rate_histories.contains_key("/"));
        assert_eq!(model.rate_histories["/"].latest(), Some(1024.0));
    }

    #[test]
    fn stale_mounts_pruned_on_data_update() {
        let mut model = test_model();

        // First update with mount "/".
        update(
            &mut model,
            DashboardMsg::DataUpdate(Some(sample_daemon_state())),
        );
        assert!(model.rate_histories.contains_key("/"));

        // Second update with no mounts at all.
        let mut empty_state = sample_daemon_state();
        empty_state.pressure.mounts.clear();
        update(&mut model, DashboardMsg::DataUpdate(Some(empty_state)));
        assert!(model.rate_histories.is_empty());
    }

    #[test]
    fn tick_wraps_at_u64_max() {
        let mut model = test_model();
        model.tick = u64::MAX;
        update(&mut model, DashboardMsg::Tick);
        assert_eq!(model.tick, 0);
    }
}
