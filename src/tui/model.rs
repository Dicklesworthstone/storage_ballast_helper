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
/// Maps to the 7-screen topology defined in
/// `docs/dashboard-information-architecture.md` (S1–S7).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Screen {
    /// S1: Primary overview — pressure gauges, EWMA trends, ballast, counters.
    /// Provides parity with the legacy dashboard (contracts C-05 through C-18).
    #[default]
    Overview,
    /// S2: Ordered event stream with severity filtering.
    Timeline,
    /// S3: Decision evidence, posterior trace, and factor contributions.
    Explainability,
    /// S4: Candidate ranking with score breakdown and veto visibility.
    Candidates,
    /// S5: Per-volume ballast inventory, release, and replenish controls.
    Ballast,
    /// S6: JSONL/SQLite log viewing with search and filter.
    LogSearch,
    /// S7: Daemon health, performance percentiles, thread status.
    Diagnostics,
}

/// Total number of screens (used for prev/next wrapping).
const SCREEN_COUNT: u8 = 7;

impl Screen {
    /// 1-based screen number for hotkey mapping (IA §4.1: keys `1`–`7`).
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::Overview => 1,
            Self::Timeline => 2,
            Self::Explainability => 3,
            Self::Candidates => 4,
            Self::Ballast => 5,
            Self::LogSearch => 6,
            Self::Diagnostics => 7,
        }
    }

    /// Resolve a 1-based number key to a screen. Returns `None` for out-of-range.
    #[must_use]
    pub const fn from_number(n: u8) -> Option<Self> {
        match n {
            1 => Some(Self::Overview),
            2 => Some(Self::Timeline),
            3 => Some(Self::Explainability),
            4 => Some(Self::Candidates),
            5 => Some(Self::Ballast),
            6 => Some(Self::LogSearch),
            7 => Some(Self::Diagnostics),
            _ => None,
        }
    }

    /// Next screen in navigation order, wrapping S7 → S1 (IA §4.1: `]` key).
    #[must_use]
    pub const fn next(self) -> Self {
        let n = self.number() % SCREEN_COUNT + 1;
        // SAFETY: n is always 1..=7, so from_number always returns Some.
        match Self::from_number(n) {
            Some(s) => s,
            None => Self::Overview,
        }
    }

    /// Previous screen in navigation order, wrapping S1 → S7 (IA §4.1: `[` key).
    #[must_use]
    pub const fn prev(self) -> Self {
        let n = if self.number() == 1 {
            SCREEN_COUNT
        } else {
            self.number() - 1
        };
        match Self::from_number(n) {
            Some(s) => s,
            None => Self::Diagnostics,
        }
    }
}

// ──────────────────── overlays ────────────────────

/// Floating surfaces that overlay the current screen (IA §3.2: O1–O6).
///
/// Only one overlay can be active at a time. Overlays have input precedence
/// over screen-level keys (IA §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overlay {
    /// O1: Fuzzy-search command palette (`Ctrl-P` or `:`).
    CommandPalette,
    /// O2: Contextual key map for current screen (`?`).
    Help,
    /// O3: VOI scheduler state panel (`v`).
    Voi,
    /// O6: Modal confirmation for mutating actions.
    Confirmation(ConfirmAction),
}

/// Actions that require modal confirmation before execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmAction {
    /// Release a single ballast file on the selected mount.
    BallastRelease,
    /// Release all ballast files on the selected mount.
    BallastReleaseAll,
}

// ──────────────────── notifications ────────────────────

/// Toast notification displayed in the top-right corner (IA §3.2: O4).
///
/// Info notifications auto-dismiss after 5 seconds. Warnings persist until
/// manually dismissed. Max 3 visible at once.
#[derive(Debug, Clone)]
pub struct Notification {
    /// Monotonic ID for expiry tracking.
    pub id: u64,
    /// Severity level controlling auto-dismiss behavior.
    pub level: NotificationLevel,
    /// Human-readable message text.
    pub message: String,
}

/// Notification severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationLevel {
    Info,
    Warning,
    Error,
}

// ──────────────────── errors ────────────────────

/// An error event surfaced through the model for operator visibility.
#[derive(Debug, Clone)]
pub struct DashboardError {
    /// Human-readable error description.
    pub message: String,
    /// Subsystem that produced the error (e.g. "adapter", "telemetry").
    pub source: String,
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

/// Maximum number of visible notification toasts (IA §3.2 O4).
const MAX_NOTIFICATIONS: usize = 3;

/// Complete display state for the new TUI dashboard.
///
/// This struct is the single source of truth for the view layer. The update
/// function produces a new model; the render function reads it immutably.
#[derive(Debug)]
pub struct DashboardModel {
    /// Active screen.
    pub screen: Screen,
    /// Screen navigation history for back-navigation (most recent last).
    pub screen_history: Vec<Screen>,
    /// Currently active overlay, if any. Only one at a time per IA §4.2.
    pub active_overlay: Option<Overlay>,
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
    /// Active notification toasts (oldest first, max [`MAX_NOTIFICATIONS`]).
    pub notifications: Vec<Notification>,
    /// Monotonic counter for notification IDs.
    pub next_notification_id: u64,
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
            screen_history: Vec::new(),
            active_overlay: None,
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
            notifications: Vec::new(),
            next_notification_id: 0,
        }
    }

    /// Push a notification, evicting the oldest if at capacity.
    /// Returns the assigned notification ID.
    pub fn push_notification(&mut self, level: NotificationLevel, message: String) -> u64 {
        let id = self.next_notification_id;
        self.next_notification_id += 1;
        self.notifications.push(Notification { id, level, message });
        while self.notifications.len() > MAX_NOTIFICATIONS {
            self.notifications.remove(0);
        }
        id
    }

    /// Navigate to a screen, recording the current screen in history.
    /// No-op if already on the target screen.
    /// Returns `true` if navigation occurred.
    pub fn navigate_to(&mut self, target: Screen) -> bool {
        if target == self.screen {
            return false;
        }
        self.screen_history.push(self.screen);
        self.screen = target;
        true
    }

    /// Go back to the previous screen. Returns `true` if history was non-empty.
    pub fn navigate_back(&mut self) -> bool {
        if let Some(prev) = self.screen_history.pop() {
            self.screen = prev;
            true
        } else {
            false
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
    DataUpdate(Option<Box<DaemonState>>),
    /// Navigate directly to a screen.
    Navigate(Screen),
    /// Go back to the previous screen (pop history stack).
    NavigateBack,
    /// Toggle an overlay on or off.
    ToggleOverlay(Overlay),
    /// Close the currently active overlay.
    CloseOverlay,
    /// Force an immediate data refresh (bypass timer).
    ForceRefresh,
    /// A notification's auto-dismiss timer expired.
    NotificationExpired(u64),
    /// An error event to surface to the operator.
    Error(DashboardError),
}

// ──────────────────── commands ────────────────────

/// Side-effects returned by the update function for the runtime to execute.
///
/// All async work is represented as a command — the update function never
/// performs I/O directly, keeping the state machine deterministic and testable.
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
    Batch(Vec<Self>),
    /// Query telemetry data for timeline/explainability panes.
    FetchTelemetry,
    /// Schedule a notification auto-dismiss after the given duration.
    ScheduleNotificationExpiry { id: u64, after: Duration },
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_model() -> DashboardModel {
        DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (80, 24),
        )
    }

    // ── Screen enum ──

    #[test]
    fn default_screen_is_overview() {
        assert_eq!(Screen::default(), Screen::Overview);
    }

    #[test]
    fn screen_number_round_trip() {
        for n in 1..=7 {
            let screen = Screen::from_number(n).unwrap();
            assert_eq!(screen.number(), n);
        }
    }

    #[test]
    fn screen_from_number_out_of_range() {
        assert_eq!(Screen::from_number(0), None);
        assert_eq!(Screen::from_number(8), None);
    }

    #[test]
    fn screen_next_wraps() {
        assert_eq!(Screen::Overview.next(), Screen::Timeline);
        assert_eq!(Screen::Diagnostics.next(), Screen::Overview);
    }

    #[test]
    fn screen_prev_wraps() {
        assert_eq!(Screen::Overview.prev(), Screen::Diagnostics);
        assert_eq!(Screen::Timeline.prev(), Screen::Overview);
    }

    #[test]
    fn screen_next_prev_cycle_all_seven() {
        let mut s = Screen::Overview;
        for _ in 0..7 {
            s = s.next();
        }
        assert_eq!(s, Screen::Overview);
    }

    #[test]
    fn screen_prev_next_are_inverse() {
        for n in 1..=7 {
            let s = Screen::from_number(n).unwrap();
            assert_eq!(s.next().prev(), s);
            assert_eq!(s.prev().next(), s);
        }
    }

    // ── Model ──

    #[test]
    fn new_model_starts_degraded() {
        let model = test_model();
        assert!(model.degraded);
        assert!(model.daemon_state.is_none());
        assert!(!model.quit);
        assert_eq!(model.tick, 0);
        assert_eq!(model.screen, Screen::Overview);
        assert!(model.screen_history.is_empty());
        assert!(model.active_overlay.is_none());
        assert!(model.notifications.is_empty());
    }

    #[test]
    fn navigate_to_pushes_history() {
        let mut model = test_model();
        assert!(model.navigate_to(Screen::Timeline));
        assert_eq!(model.screen, Screen::Timeline);
        assert_eq!(model.screen_history, vec![Screen::Overview]);
    }

    #[test]
    fn navigate_to_same_screen_is_noop() {
        let mut model = test_model();
        assert!(!model.navigate_to(Screen::Overview));
        assert!(model.screen_history.is_empty());
    }

    #[test]
    fn navigate_back_pops_history() {
        let mut model = test_model();
        model.navigate_to(Screen::Timeline);
        model.navigate_to(Screen::Candidates);
        assert_eq!(model.screen, Screen::Candidates);
        assert_eq!(model.screen_history.len(), 2);

        assert!(model.navigate_back());
        assert_eq!(model.screen, Screen::Timeline);
        assert!(model.navigate_back());
        assert_eq!(model.screen, Screen::Overview);
        assert!(!model.navigate_back()); // empty history
    }

    #[test]
    fn push_notification_evicts_oldest() {
        let mut model = test_model();
        model.push_notification(NotificationLevel::Info, "a".into());
        model.push_notification(NotificationLevel::Info, "b".into());
        model.push_notification(NotificationLevel::Info, "c".into());
        assert_eq!(model.notifications.len(), 3);

        let id = model.push_notification(NotificationLevel::Warning, "d".into());
        assert_eq!(model.notifications.len(), 3);
        assert_eq!(model.notifications[0].message, "b"); // "a" evicted
        assert_eq!(model.notifications[2].id, id);
    }

    #[test]
    fn notification_ids_are_monotonic() {
        let mut model = test_model();
        let id1 = model.push_notification(NotificationLevel::Info, "x".into());
        let id2 = model.push_notification(NotificationLevel::Info, "y".into());
        assert_eq!(id2, id1 + 1);
    }

    // ── RateHistory ──

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
