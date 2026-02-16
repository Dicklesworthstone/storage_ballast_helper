//! Elm-style state model for the new TUI dashboard.
//!
//! All display state lives in [`DashboardModel`]. Input and data events arrive
//! as [`DashboardMsg`] values; side-effects are represented as [`DashboardCmd`]
//! values returned from the update function.
//!
//! **Design invariant:** the model is deterministic and testable — no I/O
//! happens here.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crossterm::event::KeyEvent;

use crate::daemon::self_monitor::DaemonState;

// ──────────────────── screens ────────────────────

/// Top-level screens in the dashboard navigation model.
///
/// Additional screens (timeline, explainability, candidates, ballast) will be
/// added in Phase 3 (bd-xzt.3.*). The enum is non-exhaustive to allow future
/// extension without breaking downstream matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Screen {
    /// Primary overview: pressure gauges, EWMA trends, ballast, counters.
    /// Provides parity with the legacy dashboard (contracts C-05 through C-18).
    Overview,
}

impl Default for Screen {
    fn default() -> Self {
        Self::Overview
    }
}

// ──────────────────── rate history ────────────────────

/// Ring buffer tracking recent rate readings for sparkline rendering.
#[derive(Debug, Clone)]
pub struct RateHistory {
    values: Vec<f64>,
    capacity: usize,
    write_pos: usize,
}

impl RateHistory {
    /// Create a new ring buffer with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            values: Vec::with_capacity(capacity),
            capacity,
            write_pos: 0,
        }
    }

    /// Push a new value into the ring buffer, overwriting the oldest if full.
    pub fn push(&mut self, value: f64) {
        if self.values.len() < self.capacity {
            self.values.push(value);
        } else {
            self.values[self.write_pos] = value;
        }
        self.write_pos = (self.write_pos + 1) % self.capacity;
    }

    /// Get values in chronological order, normalized to `0.0..=1.0` range.
    ///
    /// Zero-only histories normalize to 0.5 (midpoint).
    #[must_use]
    pub fn normalized(&self) -> Vec<f64> {
        if self.values.is_empty() {
            return Vec::new();
        }

        let max_abs = self.values.iter().map(|v| v.abs()).fold(0.0_f64, f64::max);
        if max_abs == 0.0 {
            return vec![0.5; self.values.len()];
        }

        let len = self.values.len();
        let start = if len < self.capacity {
            0
        } else {
            self.write_pos
        };

        (0..len)
            .map(|i| {
                let idx = (start + i) % len;
                f64::midpoint(self.values[idx] / max_abs, 1.0)
            })
            .collect()
    }

    /// Most recently pushed value, if any.
    #[must_use]
    pub fn latest(&self) -> Option<f64> {
        if self.values.is_empty() {
            return None;
        }
        let idx = if self.write_pos == 0 {
            self.values.len() - 1
        } else {
            self.write_pos - 1
        };
        Some(self.values[idx])
    }
}

// ──────────────────── model ────────────────────

/// Complete display state for the new TUI dashboard.
///
/// This struct is the single source of truth for the view layer. The update
/// function produces a new model; the render function reads it immutably.
#[derive(Debug)]
pub struct DashboardModel {
    /// Active screen.
    pub screen: Screen,
    /// Most recent daemon state snapshot (None when daemon is not running).
    pub daemon_state: Option<DaemonState>,
    /// Per-mount rate histories for sparkline rendering.
    pub rate_histories: HashMap<String, RateHistory>,
    /// Terminal dimensions (columns, rows).
    pub terminal_size: (u16, u16),
    /// Whether we are in degraded mode (daemon unreachable).
    pub degraded: bool,
    /// Monotonic tick counter for timing-dependent rendering.
    pub tick: u64,
    /// Configured refresh interval.
    pub refresh: Duration,
    /// Path to the daemon state file.
    pub state_file: PathBuf,
    /// Filesystem paths to monitor in degraded mode.
    pub monitor_paths: Vec<PathBuf>,
    /// Timestamp of last data fetch (for staleness detection).
    pub last_fetch: Option<Instant>,
    /// Whether the user has requested quit.
    pub quit: bool,
}

impl DashboardModel {
    /// Create a new model with the given configuration.
    #[must_use]
    pub fn new(
        state_file: PathBuf,
        monitor_paths: Vec<PathBuf>,
        refresh: Duration,
        terminal_size: (u16, u16),
    ) -> Self {
        Self {
            screen: Screen::default(),
            daemon_state: None,
            rate_histories: HashMap::new(),
            terminal_size,
            degraded: true,
            tick: 0,
            refresh,
            state_file,
            monitor_paths,
            last_fetch: None,
            quit: false,
        }
    }
}

// ──────────────────── messages ────────────────────

/// Events that drive state transitions in the dashboard model.
#[derive(Debug)]
pub enum DashboardMsg {
    /// Periodic timer tick — triggers data refresh and re-render.
    Tick,
    /// Terminal key press event.
    Key(KeyEvent),
    /// Terminal was resized.
    Resize { cols: u16, rows: u16 },
    /// Fresh daemon state arrived (None = daemon unreachable).
    DataUpdate(Option<DaemonState>),
}

// ──────────────────── commands ────────────────────

/// Side-effects returned by the update function for the runtime to execute.
#[derive(Debug)]
pub enum DashboardCmd {
    /// No side-effect.
    None,
    /// Read the daemon state file and deliver a `DataUpdate` message.
    FetchData,
    /// Schedule the next tick after the given duration.
    ScheduleTick(Duration),
    /// Terminate the dashboard event loop.
    Quit,
    /// Execute multiple commands.
    Batch(Vec<DashboardCmd>),
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_screen_is_overview() {
        assert_eq!(Screen::default(), Screen::Overview);
    }

    #[test]
    fn new_model_starts_degraded() {
        let model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (80, 24),
        );
        assert!(model.degraded);
        assert!(model.daemon_state.is_none());
        assert!(!model.quit);
        assert_eq!(model.tick, 0);
        assert_eq!(model.screen, Screen::Overview);
    }

    #[test]
    fn rate_history_push_and_normalize() {
        let mut h = RateHistory::new(5);
        h.push(100.0);
        h.push(-100.0);
        h.push(0.0);

        let norm = h.normalized();
        assert_eq!(norm.len(), 3);
        assert!((norm[0] - 1.0).abs() < 0.01);
        assert!((norm[1] - 0.0).abs() < 0.01);
        assert!((norm[2] - 0.5).abs() < 0.01);
    }

    #[test]
    fn rate_history_wraps_correctly() {
        let mut h = RateHistory::new(3);
        h.push(1.0);
        h.push(2.0);
        h.push(3.0);
        h.push(4.0); // overwrites 1.0

        assert_eq!(h.values.len(), 3);
        assert_eq!(h.latest(), Some(4.0));
        assert_eq!(h.normalized().len(), 3);
    }

    #[test]
    fn rate_history_all_zeros_normalize_to_midpoint() {
        let mut h = RateHistory::new(5);
        h.push(0.0);
        h.push(0.0);
        h.push(0.0);

        let norm = h.normalized();
        assert!(norm.iter().all(|v| (*v - 0.5).abs() < 0.01));
    }

    #[test]
    fn rate_history_empty_latest_is_none() {
        let h = RateHistory::new(10);
        assert_eq!(h.latest(), None);
        assert!(h.normalized().is_empty());
    }
}
