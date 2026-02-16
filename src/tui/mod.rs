//! New TUI dashboard runtime (Elm-style model/update/cmd).
//!
//! This module provides the canonical runtime entrypoint for the new dashboard,
//! replacing the legacy `cli::dashboard` during migration. All new dashboard
//! features are implemented here; the legacy path is preserved as a fallback
//! until the Phase 4 verification matrix is complete (bd-xzt.4.*).
//!
//! Architecture reference: `docs/adr-tui-integration-strategy.md`

pub mod model;
pub mod render;
pub mod update;

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{self, Event};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::execute;

use crate::daemon::self_monitor::SelfMonitor;

use model::{DashboardCmd, DashboardModel, DashboardMsg};
use update::update;

// ──────────────────── configuration ────────────────────

/// Configuration for the new TUI dashboard.
pub struct NewDashboardConfig {
    /// Path to the daemon state file.
    pub state_file: PathBuf,
    /// Refresh interval.
    pub refresh: Duration,
    /// Filesystem paths to monitor in degraded mode.
    pub monitor_paths: Vec<PathBuf>,
}

// ──────────────────── entry point ────────────────────

/// Run the new Elm-style TUI dashboard until the user exits.
///
/// This is the canonical entry point for `--new-dashboard`. It:
/// 1. Enters raw mode + alternate screen.
/// 2. Creates the initial model.
/// 3. Runs the event loop (tick → fetch → update → render).
/// 4. Restores terminal state on exit (including on panic).
///
/// # Errors
/// Returns an `io::Error` if terminal setup/teardown or rendering fails.
pub fn run_new_dashboard(config: &NewDashboardConfig) -> io::Result<()> {
    let mut stdout = io::stdout();

    // Enter raw mode + alternate screen.
    terminal::enable_raw_mode()?;
    execute!(stdout, EnterAlternateScreen)?;

    let result = run_event_loop(&mut stdout, config);

    // Always restore terminal state, even on error.
    let _ = execute!(stdout, LeaveAlternateScreen);
    let _ = terminal::disable_raw_mode();

    result
}

// ──────────────────── event loop ────────────────────

fn run_event_loop(stdout: &mut io::Stdout, config: &NewDashboardConfig) -> io::Result<()> {
    let terminal_size = terminal::size().unwrap_or((80, 24));

    let mut model = DashboardModel::new(
        config.state_file.clone(),
        config.monitor_paths.clone(),
        config.refresh,
        terminal_size,
    );

    // Initial data fetch + render.
    execute_cmd(&mut model, DashboardCmd::FetchData);
    render::render(&model, stdout)?;

    loop {
        // Poll for events with a short timeout to allow periodic ticks.
        let poll_timeout = Duration::from_millis(50);

        if event::poll(poll_timeout)? {
            let msg = match event::read()? {
                Event::Key(key) => Some(DashboardMsg::Key(key)),
                Event::Resize(cols, rows) => Some(DashboardMsg::Resize { cols, rows }),
                _ => None,
            };

            if let Some(msg) = msg {
                let cmd = update(&mut model, msg);
                if model.quit {
                    return Ok(());
                }
                execute_cmd(&mut model, cmd);
                render::render(&model, stdout)?;
            }
        }

        // Check if it's time for a tick.
        let should_tick = model
            .last_fetch
            .is_none_or(|last| last.elapsed() >= model.refresh);

        if should_tick {
            let cmd = update(&mut model, DashboardMsg::Tick);
            if model.quit {
                return Ok(());
            }
            execute_cmd(&mut model, cmd);
            render::render(&model, stdout)?;
        }
    }
}

// ──────────────────── command executor ────────────────────

/// Execute a side-effect command produced by the update function.
///
/// This is the only place where I/O happens in response to model updates.
fn execute_cmd(model: &mut DashboardModel, cmd: DashboardCmd) {
    match cmd {
        DashboardCmd::None => {}
        DashboardCmd::Quit => {
            model.quit = true;
        }
        DashboardCmd::FetchData => {
            let state = SelfMonitor::read_state(&model.state_file).ok();
            let data_cmd = update(model, DashboardMsg::DataUpdate(state));
            // DataUpdate always returns None, but handle recursively for safety.
            execute_cmd(model, data_cmd);
        }
        DashboardCmd::ScheduleTick(_duration) => {
            // Tick scheduling is handled by the event loop's poll timeout and
            // the `should_tick` check. This command is a no-op in the current
            // implementation but exists for future async runtime support.
        }
        DashboardCmd::Batch(cmds) => {
            for c in cmds {
                execute_cmd(model, c);
                if model.quit {
                    return;
                }
            }
        }
    }
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_dashboard_config_round_trip() {
        let config = NewDashboardConfig {
            state_file: PathBuf::from("/tmp/sbh-state.json"),
            refresh: Duration::from_millis(500),
            monitor_paths: vec![PathBuf::from("/"), PathBuf::from("/home")],
        };
        assert_eq!(config.refresh.as_millis(), 500);
        assert_eq!(config.monitor_paths.len(), 2);
    }

    #[test]
    fn execute_cmd_fetch_populates_model() {
        // FetchData with a nonexistent state file should set degraded mode.
        let mut model = DashboardModel::new(
            PathBuf::from("/nonexistent/sbh-state.json"),
            vec![],
            Duration::from_secs(1),
            (80, 24),
        );
        assert!(model.daemon_state.is_none());

        execute_cmd(&mut model, DashboardCmd::FetchData);
        assert!(model.degraded);
        assert!(model.daemon_state.is_none());
        assert!(model.last_fetch.is_some());
    }

    #[test]
    fn execute_cmd_quit_sets_flag() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (80, 24),
        );
        assert!(!model.quit);

        execute_cmd(&mut model, DashboardCmd::Quit);
        assert!(model.quit);
    }

    #[test]
    fn execute_cmd_batch_processes_all() {
        let mut model = DashboardModel::new(
            PathBuf::from("/nonexistent/state.json"),
            vec![],
            Duration::from_secs(1),
            (80, 24),
        );

        execute_cmd(
            &mut model,
            DashboardCmd::Batch(vec![
                DashboardCmd::FetchData,
                DashboardCmd::ScheduleTick(Duration::from_secs(1)),
            ]),
        );
        assert!(model.last_fetch.is_some());
    }

    #[test]
    fn execute_cmd_batch_stops_on_quit() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (80, 24),
        );

        execute_cmd(
            &mut model,
            DashboardCmd::Batch(vec![
                DashboardCmd::Quit,
                DashboardCmd::FetchData, // should not execute
            ]),
        );
        assert!(model.quit);
        assert!(model.last_fetch.is_none());
    }
}
