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

use ftui_core::event::KeyEvent;

use crate::daemon::self_monitor::DaemonState;
use crate::tui::telemetry::{
    DataSource, DecisionEvidence, EventFilter, TelemetryResult, TimelineEvent,
};

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

// ──────────────────── candidates sort ────────────────────

/// Sort order for the candidates screen (S4).
///
/// Cycles through `Score → Size → Age → Path → Score` via the `s` key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CandidatesSortOrder {
    /// Highest total score first (most likely safe to delete).
    #[default]
    Score,
    /// Largest file size first (highest reclaim impact).
    Size,
    /// Oldest modification time first.
    Age,
    /// Alphabetical by path.
    Path,
}

impl CandidatesSortOrder {
    /// Advance to the next sort order in the cycle.
    #[must_use]
    pub const fn cycle(self) -> Self {
        match self {
            Self::Score => Self::Size,
            Self::Size => Self::Age,
            Self::Age => Self::Path,
            Self::Path => Self::Score,
        }
    }

    /// Human-readable label for status display.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Score => "score",
            Self::Size => "size",
            Self::Age => "age",
            Self::Path => "path",
        }
    }
}

// ──────────────────── timeline filter ────────────────────

/// Severity-level filter for the timeline screen (S2).
///
/// Cycles through `All → Info → Warning → Critical → All` via the `f` key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SeverityFilter {
    /// Show all events regardless of severity.
    #[default]
    All,
    /// Show only informational events.
    Info,
    /// Show only warning events.
    Warning,
    /// Show only critical events.
    Critical,
}

impl SeverityFilter {
    /// Advance to the next filter in the cycle.
    #[must_use]
    pub const fn cycle(self) -> Self {
        match self {
            Self::All => Self::Info,
            Self::Info => Self::Warning,
            Self::Warning => Self::Critical,
            Self::Critical => Self::All,
        }
    }

    /// Human-readable label for status bar display.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }

    /// Convert to an [`EventFilter`] for adapter queries.
    #[must_use]
    pub fn to_event_filter(self) -> EventFilter {
        match self {
            Self::All => EventFilter::default(),
            Self::Info => EventFilter {
                severities: vec!["info".to_owned()],
                ..EventFilter::default()
            },
            Self::Warning => EventFilter {
                severities: vec!["warning".to_owned()],
                ..EventFilter::default()
            },
            Self::Critical => EventFilter {
                severities: vec!["critical".to_owned()],
                ..EventFilter::default()
            },
        }
    }

    /// Check whether a severity string passes this filter.
    #[must_use]
    pub fn matches(self, severity: &str) -> bool {
        match self {
            Self::All => true,
            Self::Info => severity == "info",
            Self::Warning => severity == "warning",
            Self::Critical => severity == "critical",
        }
    }
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

    /// Number of values currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// True if the ring buffer has no values.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Compute (latest, avg, min, max) over stored values, or None if empty.
    #[must_use]
    pub fn stats(&self) -> Option<(f64, f64, f64, f64)> {
        let latest = self.latest()?;
        let sum: f64 = self.values.iter().sum();
        #[allow(clippy::cast_precision_loss)]
        let avg = sum / self.values.len() as f64;
        let min = self.values.iter().cloned().reduce(f64::min).unwrap_or(0.0);
        let max = self.values.iter().cloned().reduce(f64::max).unwrap_or(0.0);
        Some((latest, avg, min, max))
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

    // ── Timeline screen (S2) state ──
    /// Cached timeline events for the timeline screen.
    pub timeline_events: Vec<TimelineEvent>,
    /// Active severity filter for the timeline view.
    pub timeline_filter: SeverityFilter,
    /// Cursor position in the filtered event list.
    pub timeline_selected: usize,
    /// Follow mode: auto-scroll to newest events on data arrival.
    pub timeline_follow: bool,
    /// Backend that sourced the current timeline data.
    pub timeline_source: DataSource,
    /// Whether the timeline data is known to be incomplete.
    pub timeline_partial: bool,
    /// Diagnostic message from the telemetry adapter.
    pub timeline_diagnostics: String,

    // ── Explainability screen (S3) state ──
    /// Cached decision evidence for the explainability screen.
    pub explainability_decisions: Vec<DecisionEvidence>,
    /// Cursor position in the decisions list.
    pub explainability_selected: usize,
    /// Whether the detail pane is expanded for the selected decision.
    pub explainability_detail: bool,
    /// Backend that sourced the current decision data.
    pub explainability_source: DataSource,
    /// Whether the decision data is known to be incomplete.
    pub explainability_partial: bool,
    /// Diagnostic message from the telemetry adapter.
    pub explainability_diagnostics: String,

    // ── Candidates screen (S4) state ──
    /// Cached candidate ranking for the candidates screen.
    pub candidates_list: Vec<DecisionEvidence>,
    /// Cursor position in the candidates list.
    pub candidates_selected: usize,
    /// Whether the detail pane is expanded for the selected candidate.
    pub candidates_detail: bool,
    /// Backend that sourced the current candidate data.
    pub candidates_source: DataSource,
    /// Whether the candidate data is known to be incomplete.
    pub candidates_partial: bool,
    /// Diagnostic message from the telemetry adapter.
    pub candidates_diagnostics: String,
    /// Sort order for the candidates list.
    pub candidates_sort: CandidatesSortOrder,

    // ── Diagnostics screen (S7) state ──
    /// Toggle for verbose diagnostics output.
    pub diagnostics_verbose: bool,
    /// Ring buffer of recent frame durations (milliseconds) for sparkline.
    pub frame_times: RateHistory,
    /// Count of missed/skipped ticks detected by the runtime.
    pub missed_ticks: u64,
    /// Total successful adapter reads (DataUpdate with Some).
    pub adapter_reads: u64,
    /// Total adapter read errors (DataUpdate with None).
    pub adapter_errors: u64,
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
            timeline_events: Vec::new(),
            timeline_filter: SeverityFilter::default(),
            timeline_selected: 0,
            timeline_follow: true,
            timeline_source: DataSource::None,
            timeline_partial: false,
            timeline_diagnostics: String::new(),
            explainability_decisions: Vec::new(),
            explainability_selected: 0,
            explainability_detail: false,
            explainability_source: DataSource::None,
            explainability_partial: false,
            explainability_diagnostics: String::new(),
            candidates_list: Vec::new(),
            candidates_selected: 0,
            candidates_detail: false,
            candidates_source: DataSource::None,
            candidates_partial: false,
            candidates_diagnostics: String::new(),
            candidates_sort: CandidatesSortOrder::default(),
            diagnostics_verbose: false,
            frame_times: RateHistory::new(60),
            missed_ticks: 0,
            adapter_reads: 0,
            adapter_errors: 0,
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

    // ── Timeline (S2) methods ──

    /// Events filtered by the current severity filter.
    #[must_use]
    pub fn timeline_filtered_events(&self) -> Vec<&TimelineEvent> {
        self.timeline_events
            .iter()
            .filter(|e| self.timeline_filter.matches(&e.severity))
            .collect()
    }

    /// Move the timeline cursor up. Returns `true` if the cursor moved.
    pub fn timeline_cursor_up(&mut self) -> bool {
        if self.timeline_selected > 0 {
            self.timeline_selected -= 1;
            self.timeline_follow = false;
            true
        } else {
            false
        }
    }

    /// Move the timeline cursor down. Returns `true` if the cursor moved.
    pub fn timeline_cursor_down(&mut self) -> bool {
        let max = self.timeline_filtered_events().len().saturating_sub(1);
        if self.timeline_selected < max {
            self.timeline_selected += 1;
            true
        } else {
            false
        }
    }

    /// Cycle the severity filter to the next level and reset the cursor.
    pub fn timeline_cycle_filter(&mut self) {
        self.timeline_filter = self.timeline_filter.cycle();
        self.timeline_selected = 0;
    }

    /// Toggle follow mode (auto-scroll on new data).
    pub fn timeline_toggle_follow(&mut self) {
        self.timeline_follow = !self.timeline_follow;
        if self.timeline_follow {
            // Jump to latest
            let count = self.timeline_filtered_events().len();
            self.timeline_selected = count.saturating_sub(1);
        }
    }

    /// Get the currently selected timeline event, if any.
    #[must_use]
    pub fn timeline_selected_event(&self) -> Option<&TimelineEvent> {
        let filtered = self.timeline_filtered_events();
        filtered.get(self.timeline_selected).copied()
    }

    // ── Explainability (S3) methods ──

    /// Move the explainability cursor up. Returns `true` if the cursor moved.
    pub fn explainability_cursor_up(&mut self) -> bool {
        if self.explainability_selected > 0 {
            self.explainability_selected -= 1;
            true
        } else {
            false
        }
    }

    /// Move the explainability cursor down. Returns `true` if the cursor moved.
    pub fn explainability_cursor_down(&mut self) -> bool {
        if !self.explainability_decisions.is_empty()
            && self.explainability_selected < self.explainability_decisions.len() - 1
        {
            self.explainability_selected += 1;
            true
        } else {
            false
        }
    }

    /// Toggle the detail pane for the selected decision.
    pub fn explainability_toggle_detail(&mut self) {
        self.explainability_detail = !self.explainability_detail;
    }

    /// Get the currently selected decision, if any.
    #[must_use]
    pub fn explainability_selected_decision(&self) -> Option<&DecisionEvidence> {
        self.explainability_decisions
            .get(self.explainability_selected)
    }

    // ── Candidates (S4) methods ──

    /// Move the candidates cursor up. Returns `true` if the cursor moved.
    pub fn candidates_cursor_up(&mut self) -> bool {
        if self.candidates_selected > 0 {
            self.candidates_selected -= 1;
            true
        } else {
            false
        }
    }

    /// Move the candidates cursor down. Returns `true` if the cursor moved.
    pub fn candidates_cursor_down(&mut self) -> bool {
        if !self.candidates_list.is_empty()
            && self.candidates_selected < self.candidates_list.len() - 1
        {
            self.candidates_selected += 1;
            true
        } else {
            false
        }
    }

    /// Toggle the detail pane for the selected candidate.
    pub fn candidates_toggle_detail(&mut self) {
        self.candidates_detail = !self.candidates_detail;
    }

    /// Cycle to the next sort order and re-sort the candidates list.
    pub fn candidates_cycle_sort(&mut self) {
        self.candidates_sort = self.candidates_sort.cycle();
        self.candidates_apply_sort();
    }

    /// Apply the current sort order to the candidates list.
    pub fn candidates_apply_sort(&mut self) {
        match self.candidates_sort {
            CandidatesSortOrder::Score => {
                self.candidates_list.sort_by(|a, b| {
                    b.total_score
                        .partial_cmp(&a.total_score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
            }
            CandidatesSortOrder::Size => {
                self.candidates_list
                    .sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
            }
            CandidatesSortOrder::Age => {
                self.candidates_list
                    .sort_by(|a, b| b.age_secs.cmp(&a.age_secs));
            }
            CandidatesSortOrder::Path => {
                self.candidates_list.sort_by(|a, b| a.path.cmp(&b.path));
            }
        }
    }

    /// Get the currently selected candidate, if any.
    #[must_use]
    pub fn candidates_selected_item(&self) -> Option<&DecisionEvidence> {
        self.candidates_list.get(self.candidates_selected)
    }

    // ── Diagnostics (S7) methods ──

    /// Toggle verbose diagnostics mode.
    pub fn diagnostics_toggle_verbose(&mut self) {
        self.diagnostics_verbose = !self.diagnostics_verbose;
    }

    /// Compute frame time statistics from the ring buffer.
    /// Returns (current_ms, avg_ms, min_ms, max_ms) or None if empty.
    #[must_use]
    pub fn frame_time_stats(&self) -> Option<(f64, f64, f64, f64)> {
        self.frame_times.stats()
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
    /// Timeline events arrived from the telemetry adapter.
    TelemetryTimeline(TelemetryResult<Vec<TimelineEvent>>),
    /// Decision evidence arrived from the telemetry adapter.
    TelemetryDecisions(TelemetryResult<Vec<DecisionEvidence>>),
    /// Candidate ranking data arrived from the telemetry adapter.
    TelemetryCandidates(TelemetryResult<Vec<DecisionEvidence>>),
    /// Frame metrics reported by the runtime after each render cycle.
    FrameMetrics { duration_ms: f64 },
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

    // ── SeverityFilter ──

    #[test]
    fn severity_filter_cycles_through_all_levels() {
        let f = SeverityFilter::All;
        assert_eq!(f.cycle(), SeverityFilter::Info);
        assert_eq!(f.cycle().cycle(), SeverityFilter::Warning);
        assert_eq!(f.cycle().cycle().cycle(), SeverityFilter::Critical);
        assert_eq!(f.cycle().cycle().cycle().cycle(), SeverityFilter::All);
    }

    #[test]
    fn severity_filter_labels() {
        assert_eq!(SeverityFilter::All.label(), "all");
        assert_eq!(SeverityFilter::Info.label(), "info");
        assert_eq!(SeverityFilter::Warning.label(), "warning");
        assert_eq!(SeverityFilter::Critical.label(), "critical");
    }

    #[test]
    fn severity_filter_matches_correctly() {
        assert!(SeverityFilter::All.matches("info"));
        assert!(SeverityFilter::All.matches("warning"));
        assert!(SeverityFilter::All.matches("critical"));
        assert!(SeverityFilter::Info.matches("info"));
        assert!(!SeverityFilter::Info.matches("warning"));
        assert!(SeverityFilter::Critical.matches("critical"));
        assert!(!SeverityFilter::Critical.matches("info"));
    }

    #[test]
    fn severity_filter_to_event_filter() {
        let ef = SeverityFilter::All.to_event_filter();
        assert!(ef.is_empty());

        let ef = SeverityFilter::Warning.to_event_filter();
        assert_eq!(ef.severities, vec!["warning"]);
        assert!(ef.event_types.is_empty());
    }

    // ── Timeline state ──

    fn make_event(severity: &str, event_type: &str) -> TimelineEvent {
        TimelineEvent {
            timestamp: "2026-01-01T00:00:00Z".to_owned(),
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
    fn timeline_defaults() {
        let model = test_model();
        assert!(model.timeline_events.is_empty());
        assert_eq!(model.timeline_filter, SeverityFilter::All);
        assert_eq!(model.timeline_selected, 0);
        assert!(model.timeline_follow);
        assert_eq!(model.timeline_source, DataSource::None);
    }

    #[test]
    fn timeline_cursor_navigation() {
        let mut model = test_model();
        model.timeline_events = vec![
            make_event("info", "scan"),
            make_event("warning", "pressure_change"),
            make_event("critical", "artifact_delete"),
        ];

        assert!(!model.timeline_cursor_up()); // already at 0
        assert!(model.timeline_cursor_down());
        assert_eq!(model.timeline_selected, 1);
        assert!(!model.timeline_follow); // manual nav disables follow

        assert!(model.timeline_cursor_down());
        assert_eq!(model.timeline_selected, 2);
        assert!(!model.timeline_cursor_down()); // at end
    }

    #[test]
    fn timeline_filter_narrows_events() {
        let mut model = test_model();
        model.timeline_events = vec![
            make_event("info", "scan"),
            make_event("warning", "pressure_change"),
            make_event("critical", "artifact_delete"),
        ];

        assert_eq!(model.timeline_filtered_events().len(), 3);

        model.timeline_filter = SeverityFilter::Warning;
        assert_eq!(model.timeline_filtered_events().len(), 1);
        assert_eq!(
            model.timeline_filtered_events()[0].event_type,
            "pressure_change"
        );
    }

    #[test]
    fn timeline_cycle_filter_resets_cursor() {
        let mut model = test_model();
        model.timeline_events = vec![make_event("info", "a"), make_event("warning", "b")];
        model.timeline_selected = 1;

        model.timeline_cycle_filter();
        assert_eq!(model.timeline_filter, SeverityFilter::Info);
        assert_eq!(model.timeline_selected, 0);
    }

    #[test]
    fn timeline_toggle_follow_jumps_to_latest() {
        let mut model = test_model();
        model.timeline_events = vec![
            make_event("info", "a"),
            make_event("info", "b"),
            make_event("info", "c"),
        ];
        model.timeline_follow = false;
        model.timeline_selected = 0;

        model.timeline_toggle_follow();
        assert!(model.timeline_follow);
        assert_eq!(model.timeline_selected, 2); // jumped to last
    }

    #[test]
    fn timeline_selected_event_returns_correct_item() {
        let mut model = test_model();
        model.timeline_events = vec![make_event("info", "first"), make_event("warning", "second")];

        assert_eq!(
            model.timeline_selected_event().map(|e| &e.event_type),
            Some(&"first".to_owned())
        );

        model.timeline_selected = 1;
        assert_eq!(
            model.timeline_selected_event().map(|e| &e.event_type),
            Some(&"second".to_owned())
        );
    }

    #[test]
    fn timeline_selected_event_with_filter() {
        let mut model = test_model();
        model.timeline_events = vec![
            make_event("info", "a"),
            make_event("warning", "b"),
            make_event("critical", "c"),
        ];
        model.timeline_filter = SeverityFilter::Critical;
        model.timeline_selected = 0;

        assert_eq!(
            model.timeline_selected_event().map(|e| &e.event_type),
            Some(&"c".to_owned())
        );
    }

    // ── Explainability state tests ──

    fn sample_decision(id: u64) -> crate::tui::telemetry::DecisionEvidence {
        crate::tui::telemetry::DecisionEvidence {
            decision_id: id,
            timestamp: String::new(),
            path: String::from("/test"),
            size_bytes: 1000,
            age_secs: 60,
            action: String::from("delete"),
            effective_action: None,
            policy_mode: String::from("live"),
            factors: crate::tui::telemetry::FactorBreakdown {
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

    #[test]
    fn new_model_explainability_defaults() {
        let model = test_model();
        assert!(model.explainability_decisions.is_empty());
        assert_eq!(model.explainability_selected, 0);
        assert!(!model.explainability_detail);
        assert_eq!(
            model.explainability_source,
            crate::tui::telemetry::DataSource::None
        );
    }

    #[test]
    fn explainability_cursor_down_moves() {
        let mut model = test_model();
        model.explainability_decisions = vec![sample_decision(1), sample_decision(2)];
        assert!(model.explainability_cursor_down());
        assert_eq!(model.explainability_selected, 1);
    }

    #[test]
    fn explainability_cursor_down_clamps_at_end() {
        let mut model = test_model();
        model.explainability_decisions = vec![sample_decision(1)];
        assert!(!model.explainability_cursor_down());
        assert_eq!(model.explainability_selected, 0);
    }

    #[test]
    fn explainability_cursor_up_moves() {
        let mut model = test_model();
        model.explainability_decisions = vec![sample_decision(1), sample_decision(2)];
        model.explainability_selected = 1;
        assert!(model.explainability_cursor_up());
        assert_eq!(model.explainability_selected, 0);
    }

    #[test]
    fn explainability_cursor_up_clamps_at_start() {
        let mut model = test_model();
        model.explainability_decisions = vec![sample_decision(1)];
        assert!(!model.explainability_cursor_up());
        assert_eq!(model.explainability_selected, 0);
    }

    #[test]
    fn explainability_toggle_detail() {
        let mut model = test_model();
        model.explainability_toggle_detail();
        assert!(model.explainability_detail);
        model.explainability_toggle_detail();
        assert!(!model.explainability_detail);
    }

    #[test]
    fn explainability_selected_decision_returns_correct() {
        let mut model = test_model();
        model.explainability_decisions = vec![sample_decision(10), sample_decision(20)];
        model.explainability_selected = 1;
        let d = model.explainability_selected_decision().unwrap();
        assert_eq!(d.decision_id, 20);
    }

    #[test]
    fn explainability_selected_decision_none_when_empty() {
        let model = test_model();
        assert!(model.explainability_selected_decision().is_none());
    }

    #[test]
    fn explainability_cursor_empty_decisions() {
        let mut model = test_model();
        assert!(!model.explainability_cursor_down());
        assert!(!model.explainability_cursor_up());
    }

    // ── Candidates state tests ──

    fn sample_candidate(id: u64, score: f64, size: u64, age: u64) -> DecisionEvidence {
        DecisionEvidence {
            decision_id: id,
            timestamp: String::new(),
            path: format!("/test/{id}"),
            size_bytes: size,
            age_secs: age,
            action: String::from("delete"),
            effective_action: None,
            policy_mode: String::from("live"),
            factors: crate::tui::telemetry::FactorBreakdown {
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
    }

    #[test]
    fn new_model_candidates_defaults() {
        let model = test_model();
        assert!(model.candidates_list.is_empty());
        assert_eq!(model.candidates_selected, 0);
        assert!(!model.candidates_detail);
        assert_eq!(model.candidates_source, DataSource::None);
        assert_eq!(model.candidates_sort, CandidatesSortOrder::Score);
    }

    #[test]
    fn candidates_cursor_down_moves() {
        let mut model = test_model();
        model.candidates_list = vec![
            sample_candidate(1, 2.0, 1000, 60),
            sample_candidate(2, 1.5, 2000, 120),
        ];
        assert!(model.candidates_cursor_down());
        assert_eq!(model.candidates_selected, 1);
    }

    #[test]
    fn candidates_cursor_down_clamps_at_end() {
        let mut model = test_model();
        model.candidates_list = vec![sample_candidate(1, 2.0, 1000, 60)];
        assert!(!model.candidates_cursor_down());
        assert_eq!(model.candidates_selected, 0);
    }

    #[test]
    fn candidates_cursor_up_moves() {
        let mut model = test_model();
        model.candidates_list = vec![
            sample_candidate(1, 2.0, 1000, 60),
            sample_candidate(2, 1.5, 2000, 120),
        ];
        model.candidates_selected = 1;
        assert!(model.candidates_cursor_up());
        assert_eq!(model.candidates_selected, 0);
    }

    #[test]
    fn candidates_cursor_up_clamps_at_start() {
        let mut model = test_model();
        model.candidates_list = vec![sample_candidate(1, 2.0, 1000, 60)];
        assert!(!model.candidates_cursor_up());
        assert_eq!(model.candidates_selected, 0);
    }

    #[test]
    fn candidates_toggle_detail() {
        let mut model = test_model();
        model.candidates_toggle_detail();
        assert!(model.candidates_detail);
        model.candidates_toggle_detail();
        assert!(!model.candidates_detail);
    }

    #[test]
    fn candidates_selected_item_returns_correct() {
        let mut model = test_model();
        model.candidates_list = vec![
            sample_candidate(10, 2.0, 1000, 60),
            sample_candidate(20, 1.5, 2000, 120),
        ];
        model.candidates_selected = 1;
        let c = model.candidates_selected_item().unwrap();
        assert_eq!(c.decision_id, 20);
    }

    #[test]
    fn candidates_selected_item_none_when_empty() {
        let model = test_model();
        assert!(model.candidates_selected_item().is_none());
    }

    #[test]
    fn candidates_cursor_empty_list() {
        let mut model = test_model();
        assert!(!model.candidates_cursor_down());
        assert!(!model.candidates_cursor_up());
    }

    #[test]
    fn candidates_sort_order_cycles() {
        let s = CandidatesSortOrder::Score;
        assert_eq!(s.cycle(), CandidatesSortOrder::Size);
        assert_eq!(s.cycle().cycle(), CandidatesSortOrder::Age);
        assert_eq!(s.cycle().cycle().cycle(), CandidatesSortOrder::Path);
        assert_eq!(
            s.cycle().cycle().cycle().cycle(),
            CandidatesSortOrder::Score
        );
    }

    #[test]
    fn candidates_sort_order_labels() {
        assert_eq!(CandidatesSortOrder::Score.label(), "score");
        assert_eq!(CandidatesSortOrder::Size.label(), "size");
        assert_eq!(CandidatesSortOrder::Age.label(), "age");
        assert_eq!(CandidatesSortOrder::Path.label(), "path");
    }

    #[test]
    fn candidates_cycle_sort_reorders_list() {
        let mut model = test_model();
        model.candidates_list = vec![
            sample_candidate(1, 1.0, 5000, 60),
            sample_candidate(2, 2.0, 1000, 120),
            sample_candidate(3, 0.5, 3000, 30),
        ];
        // Default sort is Score (descending).
        model.candidates_apply_sort();
        assert_eq!(model.candidates_list[0].decision_id, 2); // score 2.0
        assert_eq!(model.candidates_list[1].decision_id, 1); // score 1.0
        assert_eq!(model.candidates_list[2].decision_id, 3); // score 0.5

        // Cycle to Size (descending).
        model.candidates_cycle_sort();
        assert_eq!(model.candidates_sort, CandidatesSortOrder::Size);
        assert_eq!(model.candidates_list[0].decision_id, 1); // 5000 bytes
        assert_eq!(model.candidates_list[1].decision_id, 3); // 3000 bytes
        assert_eq!(model.candidates_list[2].decision_id, 2); // 1000 bytes

        // Cycle to Age (descending).
        model.candidates_cycle_sort();
        assert_eq!(model.candidates_sort, CandidatesSortOrder::Age);
        assert_eq!(model.candidates_list[0].decision_id, 2); // 120s
        assert_eq!(model.candidates_list[1].decision_id, 1); // 60s
        assert_eq!(model.candidates_list[2].decision_id, 3); // 30s

        // Cycle to Path (ascending).
        model.candidates_cycle_sort();
        assert_eq!(model.candidates_sort, CandidatesSortOrder::Path);
        assert_eq!(model.candidates_list[0].decision_id, 1); // /test/1
        assert_eq!(model.candidates_list[1].decision_id, 2); // /test/2
        assert_eq!(model.candidates_list[2].decision_id, 3); // /test/3
    }

    // ── Diagnostics state tests ──

    #[test]
    fn new_model_diagnostics_defaults() {
        let model = test_model();
        assert!(!model.diagnostics_verbose);
        assert!(model.frame_times.is_empty());
        assert_eq!(model.missed_ticks, 0);
        assert_eq!(model.adapter_reads, 0);
        assert_eq!(model.adapter_errors, 0);
    }

    #[test]
    fn diagnostics_toggle_verbose() {
        let mut model = test_model();
        assert!(!model.diagnostics_verbose);
        model.diagnostics_toggle_verbose();
        assert!(model.diagnostics_verbose);
        model.diagnostics_toggle_verbose();
        assert!(!model.diagnostics_verbose);
    }

    #[test]
    fn frame_time_stats_empty_returns_none() {
        let model = test_model();
        assert!(model.frame_time_stats().is_none());
    }

    #[test]
    fn frame_time_stats_with_data() {
        let mut model = test_model();
        model.frame_times.push(10.0);
        model.frame_times.push(20.0);
        model.frame_times.push(30.0);

        let (current, avg, min, max) = model.frame_time_stats().unwrap();
        assert!((current - 30.0).abs() < 0.01);
        assert!((avg - 20.0).abs() < 0.01);
        assert!((min - 10.0).abs() < 0.01);
        assert!((max - 30.0).abs() < 0.01);
    }

    #[test]
    fn frame_times_ring_buffer_capacity() {
        let mut model = test_model();
        // Ring buffer capacity is 60 (set in new()).
        for i in 0..100 {
            #[allow(clippy::cast_precision_loss)]
            model.frame_times.push(i as f64);
        }
        assert_eq!(model.frame_times.len(), 60);
        // Latest should be the last pushed value.
        assert_eq!(model.frame_times.latest(), Some(99.0));
    }

    #[test]
    fn frame_time_stats_single_value() {
        let mut model = test_model();
        model.frame_times.push(16.7);
        let (current, avg, min, max) = model.frame_time_stats().unwrap();
        assert!((current - 16.7).abs() < 0.01);
        assert!((avg - 16.7).abs() < 0.01);
        assert!((min - 16.7).abs() < 0.01);
        assert!((max - 16.7).abs() < 0.01);
    }

    #[test]
    fn adapter_counters_independent() {
        let mut model = test_model();
        model.adapter_reads = 42;
        model.adapter_errors = 3;
        assert_eq!(model.adapter_reads, 42);
        assert_eq!(model.adapter_errors, 3);
    }
}
