//! Canonical runtime entrypoint for dashboard execution.
//!
//! The new cockpit path uses [`TerminalGuard`] for panic-safe terminal
//! lifecycle management. The legacy fallback retains its own cleanup logic.

#![allow(missing_docs)]

use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crossterm::cursor;
use crossterm::event::{self, Event};
use crossterm::execute;
use crossterm::terminal::{self, ClearType};

use super::model::{DashboardCmd, DashboardModel, DashboardMsg};
use super::terminal_guard::TerminalGuard;
use super::{render, update};
use crate::cli::dashboard::{self, DashboardConfig as LegacyDashboardConfig};
use crate::daemon::self_monitor::DaemonState;

/// Which runtime path to execute.
///
/// `NewCockpit` is the canonical modern entrypoint. During the migration it can
/// intentionally delegate to legacy rendering while we wire model/update/view
/// internals behind the same external contract.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DashboardRuntimeMode {
    #[default]
    NewCockpit,
    LegacyFallback,
}

/// Runtime configuration shared by both new and legacy dashboard executors.
#[derive(Debug, Clone)]
pub struct DashboardRuntimeConfig {
    pub state_file: PathBuf,
    pub refresh: Duration,
    pub monitor_paths: Vec<PathBuf>,
    pub mode: DashboardRuntimeMode,
}

impl DashboardRuntimeConfig {
    /// Build the underlying legacy dashboard config.
    #[must_use]
    pub fn as_legacy_config(&self) -> LegacyDashboardConfig {
        LegacyDashboardConfig {
            state_file: self.state_file.clone(),
            refresh: self.refresh,
            monitor_paths: self.monitor_paths.clone(),
        }
    }
}

/// Run dashboard runtime via one canonical entrypoint.
///
/// All `sbh dashboard` invocations should flow through this function while the
/// migration is in progress so runtime selection stays deterministic and testable.
///
/// # Errors
/// Returns I/O errors from terminal/event/renderer layers.
pub fn run_dashboard(config: &DashboardRuntimeConfig) -> io::Result<()> {
    match config.mode {
        DashboardRuntimeMode::NewCockpit => run_new_cockpit(config),
        DashboardRuntimeMode::LegacyFallback => run_legacy_fallback(config),
    }
}

fn run_new_cockpit(config: &DashboardRuntimeConfig) -> io::Result<()> {
    // TerminalGuard handles raw mode + alternate screen with panic safety.
    // Drop restores the terminal even on panic or early return.
    let _guard = TerminalGuard::new()?;

    let (cols, rows) = TerminalGuard::terminal_size();
    let mut model = DashboardModel::new(
        config.state_file.clone(),
        config.monitor_paths.clone(),
        config.refresh,
        (cols, rows),
    );

    // Pending notification auto-dismiss timers: (notification_id, expires_at).
    let mut notification_timers: Vec<(u64, Instant)> = Vec::new();

    // Initial data fetch.
    let initial = read_state_file(&config.state_file);
    update::update(&mut model, DashboardMsg::DataUpdate(initial));

    let mut stdout = io::stdout();

    loop {
        // Render current frame.
        let frame = render::render(&model);
        execute!(
            stdout,
            terminal::Clear(ClearType::All),
            cursor::MoveTo(0, 0)
        )?;
        stdout.write_all(frame.as_bytes())?;
        stdout.flush()?;

        // Check for expired notification timers.
        let now = Instant::now();
        let expired: Vec<u64> = notification_timers
            .iter()
            .filter(|(_, deadline)| now >= *deadline)
            .map(|(id, _)| *id)
            .collect();
        notification_timers.retain(|(_, deadline)| now < *deadline);
        for id in expired {
            update::update(&mut model, DashboardMsg::NotificationExpired(id));
        }

        // Poll for terminal events (timeout = refresh interval).
        let poll_timeout = model.refresh;
        if event::poll(poll_timeout)? {
            let cmd = match event::read()? {
                Event::Key(key) if key.kind == crossterm::event::KeyEventKind::Press => {
                    update::update(&mut model, DashboardMsg::Key(key))
                }
                Event::Resize(c, r) => {
                    update::update(&mut model, DashboardMsg::Resize { cols: c, rows: r })
                }
                _ => DashboardCmd::None,
            };
            execute_cmd(
                &mut model,
                &config.state_file,
                cmd,
                &mut notification_timers,
            );
        } else {
            // Timeout = tick (periodic refresh).
            let cmd = update::update(&mut model, DashboardMsg::Tick);
            execute_cmd(
                &mut model,
                &config.state_file,
                cmd,
                &mut notification_timers,
            );
        }

        if model.quit {
            break;
        }
    }

    // TerminalGuard Drop handles cleanup.
    Ok(())
}

/// Execute a command returned by the update function.
///
/// This is the bridge between the pure state machine and the I/O world.
fn execute_cmd(
    model: &mut DashboardModel,
    state_file: &Path,
    cmd: DashboardCmd,
    timers: &mut Vec<(u64, Instant)>,
) {
    match cmd {
        DashboardCmd::None => {}
        DashboardCmd::FetchData => {
            let state = read_state_file(state_file);
            let inner_cmd = update::update(model, DashboardMsg::DataUpdate(state));
            execute_cmd(model, state_file, inner_cmd, timers);
        }
        DashboardCmd::ScheduleTick(_) => {
            // Tick scheduling is handled by the poll timeout in the main loop.
        }
        DashboardCmd::Quit => {
            model.quit = true;
        }
        DashboardCmd::Batch(cmds) => {
            for c in cmds {
                execute_cmd(model, state_file, c, timers);
            }
        }
        DashboardCmd::FetchTelemetry => {
            // Stub: telemetry query adapters land in bd-xzt.2.4.
        }
        DashboardCmd::ScheduleNotificationExpiry { id, after } => {
            timers.push((id, Instant::now() + after));
        }
    }
}

/// Read and parse the daemon state file. Returns `None` on any error.
fn read_state_file(path: &Path) -> Option<Box<DaemonState>> {
    let content = std::fs::read_to_string(path).ok()?;
    let state: DaemonState = serde_json::from_str(&content).ok()?;
    Some(Box::new(state))
}

fn run_legacy_fallback(config: &DashboardRuntimeConfig) -> io::Result<()> {
    dashboard::run(&config.as_legacy_config())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_mode_defaults_to_new_cockpit() {
        assert_eq!(
            DashboardRuntimeMode::default(),
            DashboardRuntimeMode::NewCockpit
        );
    }

    #[test]
    fn runtime_config_maps_to_legacy_config() {
        let cfg = DashboardRuntimeConfig {
            state_file: PathBuf::from("/tmp/state.json"),
            refresh: Duration::from_millis(750),
            monitor_paths: vec![PathBuf::from("/tmp"), PathBuf::from("/data/projects")],
            mode: DashboardRuntimeMode::LegacyFallback,
        };

        let legacy = cfg.as_legacy_config();
        assert_eq!(legacy.state_file, PathBuf::from("/tmp/state.json"));
        assert_eq!(legacy.refresh, Duration::from_millis(750));
        assert_eq!(legacy.monitor_paths.len(), 2);
    }
}
