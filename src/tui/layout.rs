//! Responsive pane composition primitives for dashboard screens.
//!
//! Provides layout builders for all seven dashboard screens (S1–S7) with
//! adaptive pane visibility based on terminal dimensions. Each builder
//! produces a layout plan that downstream renderers consume to place content.

#![allow(missing_docs)]

/// Minimum terminal width below which the dashboard shows a "too small" message.
pub const MIN_USABLE_COLS: u16 = 40;
/// Minimum terminal height below which the dashboard shows a "too small" message.
pub const MIN_USABLE_ROWS: u16 = 8;

/// Check whether the terminal is large enough for the dashboard to render usefully.
/// Returns `true` if the terminal is too small (below minimum thresholds).
#[must_use]
pub const fn is_terminal_too_small(cols: u16, rows: u16) -> bool {
    cols < MIN_USABLE_COLS || rows < MIN_USABLE_ROWS
}

/// Layout class selected from terminal width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutClass {
    Narrow,
    Wide,
}

/// Priority of a pane for narrow-screen collapse behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanePriority {
    P0,
    P1,
    P2,
}

/// Overview screen panes from the IA contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverviewPane {
    PressureSummary,
    ActionLane,
    EwmaTrend,
    RecentActivity,
    BallastQuick,
    ExtendedCounters,
}

impl OverviewPane {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::PressureSummary => "pressure-summary",
            Self::ActionLane => "action-lane",
            Self::EwmaTrend => "ewma-trend",
            Self::RecentActivity => "recent-activity",
            Self::BallastQuick => "ballast-quick",
            Self::ExtendedCounters => "extended-counters",
        }
    }
}

/// Minimal rectangular placement metadata for a pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaneRect {
    pub col: u16,
    pub row: u16,
    pub width: u16,
    pub height: u16,
}

impl PaneRect {
    #[must_use]
    pub const fn new(col: u16, row: u16, width: u16, height: u16) -> Self {
        Self {
            col,
            row,
            width,
            height,
        }
    }
}

/// Placement definition for a single pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PanePlacement {
    pub pane: OverviewPane,
    pub priority: PanePriority,
    pub rect: PaneRect,
    pub visible: bool,
}

impl PanePlacement {
    #[must_use]
    pub const fn new(
        pane: OverviewPane,
        priority: PanePriority,
        rect: PaneRect,
        visible: bool,
    ) -> Self {
        Self {
            pane,
            priority,
            rect,
            visible,
        }
    }
}

/// Complete overview layout plan selected for terminal size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverviewLayout {
    pub class: LayoutClass,
    pub placements: Vec<PanePlacement>,
}

const WIDE_THRESHOLD_COLS: u16 = 100;

/// Classify layout from terminal width.
#[must_use]
pub const fn classify_layout(cols: u16) -> LayoutClass {
    if cols < WIDE_THRESHOLD_COLS {
        LayoutClass::Narrow
    } else {
        LayoutClass::Wide
    }
}

/// Build pane placements for the overview screen.
#[must_use]
pub fn build_overview_layout(cols: u16, rows: u16) -> OverviewLayout {
    match classify_layout(cols) {
        LayoutClass::Narrow => build_narrow_layout(cols, rows),
        LayoutClass::Wide => build_wide_layout(cols, rows),
    }
}

fn build_narrow_layout(cols: u16, rows: u16) -> OverviewLayout {
    let full_width = cols.max(1);
    let p2_visible = rows >= 20;

    let placements = vec![
        PanePlacement::new(
            OverviewPane::PressureSummary,
            PanePriority::P0,
            PaneRect::new(0, 0, full_width, 3),
            true,
        ),
        PanePlacement::new(
            OverviewPane::ActionLane,
            PanePriority::P0,
            PaneRect::new(0, 3, full_width, 3),
            true,
        ),
        PanePlacement::new(
            OverviewPane::EwmaTrend,
            PanePriority::P1,
            PaneRect::new(0, 6, full_width, 3),
            true,
        ),
        PanePlacement::new(
            OverviewPane::RecentActivity,
            PanePriority::P1,
            PaneRect::new(0, 9, full_width, 3),
            true,
        ),
        PanePlacement::new(
            OverviewPane::BallastQuick,
            PanePriority::P1,
            PaneRect::new(0, 12, full_width, 2),
            true,
        ),
        PanePlacement::new(
            OverviewPane::ExtendedCounters,
            PanePriority::P2,
            PaneRect::new(0, 14, full_width, 2),
            p2_visible,
        ),
    ];

    OverviewLayout {
        class: LayoutClass::Narrow,
        placements,
    }
}

fn build_wide_layout(cols: u16, rows: u16) -> OverviewLayout {
    let full_width = cols.max(1);
    let (left_width, right_width) = split_columns(full_width, 1);
    let right_col = left_width.saturating_add(1);
    let p2_visible = rows >= 24;

    let placements = vec![
        PanePlacement::new(
            OverviewPane::PressureSummary,
            PanePriority::P0,
            PaneRect::new(0, 0, left_width, 4),
            true,
        ),
        PanePlacement::new(
            OverviewPane::ActionLane,
            PanePriority::P0,
            PaneRect::new(right_col, 0, right_width, 4),
            true,
        ),
        PanePlacement::new(
            OverviewPane::EwmaTrend,
            PanePriority::P1,
            PaneRect::new(0, 4, left_width, 4),
            true,
        ),
        PanePlacement::new(
            OverviewPane::RecentActivity,
            PanePriority::P1,
            PaneRect::new(right_col, 4, right_width, 4),
            true,
        ),
        PanePlacement::new(
            OverviewPane::BallastQuick,
            PanePriority::P1,
            PaneRect::new(right_col, 8, right_width, 3),
            true,
        ),
        PanePlacement::new(
            OverviewPane::ExtendedCounters,
            PanePriority::P2,
            PaneRect::new(0, 11, full_width, 3),
            p2_visible,
        ),
    ];

    OverviewLayout {
        class: LayoutClass::Wide,
        placements,
    }
}

// ──────────────────── timeline layout (S2) ────────────────────

/// Panes for the timeline screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimelinePane {
    /// Filter bar showing active severity filter and follow-mode indicator.
    FilterBar,
    /// Scrollable event list (main area).
    EventList,
    /// Detail panel for the selected event (shown in wide layout).
    EventDetail,
    /// Status footer with event count and data-source indicator.
    StatusFooter,
}

impl TimelinePane {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::FilterBar => "tl-filter-bar",
            Self::EventList => "tl-event-list",
            Self::EventDetail => "tl-event-detail",
            Self::StatusFooter => "tl-status-footer",
        }
    }
}

/// Placement for a timeline pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimelinePlacement {
    pub pane: TimelinePane,
    pub priority: PanePriority,
    pub rect: PaneRect,
    pub visible: bool,
}

impl TimelinePlacement {
    #[must_use]
    pub const fn new(
        pane: TimelinePane,
        priority: PanePriority,
        rect: PaneRect,
        visible: bool,
    ) -> Self {
        Self {
            pane,
            priority,
            rect,
            visible,
        }
    }
}

/// Complete timeline layout plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineLayout {
    pub class: LayoutClass,
    pub placements: Vec<TimelinePlacement>,
}

/// Build pane placements for the timeline screen.
#[must_use]
pub fn build_timeline_layout(cols: u16, rows: u16) -> TimelineLayout {
    match classify_layout(cols) {
        LayoutClass::Narrow => build_narrow_timeline(cols, rows),
        LayoutClass::Wide => build_wide_timeline(cols, rows),
    }
}

fn build_narrow_timeline(cols: u16, rows: u16) -> TimelineLayout {
    let w = cols.max(1);
    // Filter bar: 1 row, event list: remaining, status: 1 row.
    let footer_row = rows.saturating_sub(1);
    let list_height = footer_row.saturating_sub(1).max(1);

    let placements = vec![
        TimelinePlacement::new(
            TimelinePane::FilterBar,
            PanePriority::P0,
            PaneRect::new(0, 0, w, 1),
            true,
        ),
        TimelinePlacement::new(
            TimelinePane::EventList,
            PanePriority::P0,
            PaneRect::new(0, 1, w, list_height),
            true,
        ),
        // Detail panel hidden in narrow layout.
        TimelinePlacement::new(
            TimelinePane::EventDetail,
            PanePriority::P2,
            PaneRect::new(0, 0, 0, 0),
            false,
        ),
        TimelinePlacement::new(
            TimelinePane::StatusFooter,
            PanePriority::P0,
            PaneRect::new(0, footer_row, w, 1),
            true,
        ),
    ];

    TimelineLayout {
        class: LayoutClass::Narrow,
        placements,
    }
}

fn build_wide_timeline(cols: u16, rows: u16) -> TimelineLayout {
    let full_width = cols.max(1);
    let (list_width, detail_width) = split_columns(full_width, 1);
    let detail_col = list_width.saturating_add(1);
    let footer_row = rows.saturating_sub(1);
    let body_height = footer_row.saturating_sub(1).max(1);
    let detail_visible = rows >= 10;

    let placements = vec![
        TimelinePlacement::new(
            TimelinePane::FilterBar,
            PanePriority::P0,
            PaneRect::new(0, 0, full_width, 1),
            true,
        ),
        TimelinePlacement::new(
            TimelinePane::EventList,
            PanePriority::P0,
            PaneRect::new(0, 1, list_width, body_height),
            true,
        ),
        TimelinePlacement::new(
            TimelinePane::EventDetail,
            PanePriority::P1,
            PaneRect::new(detail_col, 1, detail_width, body_height),
            detail_visible,
        ),
        TimelinePlacement::new(
            TimelinePane::StatusFooter,
            PanePriority::P0,
            PaneRect::new(0, footer_row, full_width, 1),
            true,
        ),
    ];

    TimelineLayout {
        class: LayoutClass::Wide,
        placements,
    }
}

// ──────────────────── ballast layout (S5) ────────────────────

/// Panes for the ballast operations screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BallastPane {
    /// Per-volume inventory list (main area).
    VolumeList,
    /// Detail panel for the selected volume (shown in wide layout).
    VolumeDetail,
    /// Status footer with data-source indicator and volume count.
    StatusFooter,
}

impl BallastPane {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::VolumeList => "bl-volume-list",
            Self::VolumeDetail => "bl-volume-detail",
            Self::StatusFooter => "bl-status-footer",
        }
    }
}

/// Placement for a ballast pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BallastPlacement {
    pub pane: BallastPane,
    pub priority: PanePriority,
    pub rect: PaneRect,
    pub visible: bool,
}

impl BallastPlacement {
    #[must_use]
    pub const fn new(
        pane: BallastPane,
        priority: PanePriority,
        rect: PaneRect,
        visible: bool,
    ) -> Self {
        Self {
            pane,
            priority,
            rect,
            visible,
        }
    }
}

/// Complete ballast layout plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BallastLayout {
    pub class: LayoutClass,
    pub placements: Vec<BallastPlacement>,
}

/// Build pane placements for the ballast screen.
#[must_use]
pub fn build_ballast_layout(cols: u16, rows: u16) -> BallastLayout {
    match classify_layout(cols) {
        LayoutClass::Narrow => build_narrow_ballast(cols, rows),
        LayoutClass::Wide => build_wide_ballast(cols, rows),
    }
}

fn build_narrow_ballast(cols: u16, rows: u16) -> BallastLayout {
    let w = cols.max(1);
    let footer_row = rows.saturating_sub(1);
    let list_height = footer_row.max(1);

    let placements = vec![
        BallastPlacement::new(
            BallastPane::VolumeList,
            PanePriority::P0,
            PaneRect::new(0, 0, w, list_height),
            true,
        ),
        // Detail panel hidden in narrow layout.
        BallastPlacement::new(
            BallastPane::VolumeDetail,
            PanePriority::P2,
            PaneRect::new(0, 0, 0, 0),
            false,
        ),
        BallastPlacement::new(
            BallastPane::StatusFooter,
            PanePriority::P0,
            PaneRect::new(0, footer_row, w, 1),
            true,
        ),
    ];

    BallastLayout {
        class: LayoutClass::Narrow,
        placements,
    }
}

fn build_wide_ballast(cols: u16, rows: u16) -> BallastLayout {
    let full_width = cols.max(1);
    let (list_width, detail_width) = split_columns(full_width, 1);
    let detail_col = list_width.saturating_add(1);
    let footer_row = rows.saturating_sub(1);
    let body_height = footer_row.max(1);
    let detail_visible = rows >= 10;

    let placements = vec![
        BallastPlacement::new(
            BallastPane::VolumeList,
            PanePriority::P0,
            PaneRect::new(0, 0, list_width, body_height),
            true,
        ),
        BallastPlacement::new(
            BallastPane::VolumeDetail,
            PanePriority::P1,
            PaneRect::new(detail_col, 0, detail_width, body_height),
            detail_visible,
        ),
        BallastPlacement::new(
            BallastPane::StatusFooter,
            PanePriority::P0,
            PaneRect::new(0, footer_row, full_width, 1),
            true,
        ),
    ];

    BallastLayout {
        class: LayoutClass::Wide,
        placements,
    }
}

// ──────────────────── explainability layout (S3) ────────────────────

/// Panes for the explainability screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplainabilityPane {
    /// Decision summary header (decision ID, timestamp, outcome).
    DecisionHeader,
    /// Factor contribution breakdown (posterior, scoring weights).
    FactorBreakdown,
    /// Veto / safety-check detail panel (wide layout only).
    VetoDetail,
    /// Status footer with data-source indicator.
    StatusFooter,
}

impl ExplainabilityPane {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::DecisionHeader => "ex-decision-header",
            Self::FactorBreakdown => "ex-factor-breakdown",
            Self::VetoDetail => "ex-veto-detail",
            Self::StatusFooter => "ex-status-footer",
        }
    }
}

/// Placement for an explainability pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExplainabilityPlacement {
    pub pane: ExplainabilityPane,
    pub priority: PanePriority,
    pub rect: PaneRect,
    pub visible: bool,
}

impl ExplainabilityPlacement {
    #[must_use]
    pub const fn new(
        pane: ExplainabilityPane,
        priority: PanePriority,
        rect: PaneRect,
        visible: bool,
    ) -> Self {
        Self {
            pane,
            priority,
            rect,
            visible,
        }
    }
}

/// Complete explainability layout plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplainabilityLayout {
    pub class: LayoutClass,
    pub placements: Vec<ExplainabilityPlacement>,
}

/// Build pane placements for the explainability screen.
#[must_use]
pub fn build_explainability_layout(cols: u16, rows: u16) -> ExplainabilityLayout {
    match classify_layout(cols) {
        LayoutClass::Narrow => build_narrow_explainability(cols, rows),
        LayoutClass::Wide => build_wide_explainability(cols, rows),
    }
}

fn build_narrow_explainability(cols: u16, rows: u16) -> ExplainabilityLayout {
    let w = cols.max(1);
    let footer_row = rows.saturating_sub(1);
    let breakdown_height = footer_row.saturating_sub(3).max(1);

    let placements = vec![
        ExplainabilityPlacement::new(
            ExplainabilityPane::DecisionHeader,
            PanePriority::P0,
            PaneRect::new(0, 0, w, 3),
            true,
        ),
        ExplainabilityPlacement::new(
            ExplainabilityPane::FactorBreakdown,
            PanePriority::P0,
            PaneRect::new(0, 3, w, breakdown_height),
            true,
        ),
        // Veto detail hidden in narrow layout — info merged into factor view.
        ExplainabilityPlacement::new(
            ExplainabilityPane::VetoDetail,
            PanePriority::P2,
            PaneRect::new(0, 0, 0, 0),
            false,
        ),
        ExplainabilityPlacement::new(
            ExplainabilityPane::StatusFooter,
            PanePriority::P0,
            PaneRect::new(0, footer_row, w, 1),
            true,
        ),
    ];

    ExplainabilityLayout {
        class: LayoutClass::Narrow,
        placements,
    }
}

fn build_wide_explainability(cols: u16, rows: u16) -> ExplainabilityLayout {
    let full_width = cols.max(1);
    let (left_width, right_width) = split_columns(full_width, 1);
    let right_col = left_width.saturating_add(1);
    let footer_row = rows.saturating_sub(1);
    let body_height = footer_row.saturating_sub(3).max(1);
    let veto_visible = rows >= 12;

    let placements = vec![
        ExplainabilityPlacement::new(
            ExplainabilityPane::DecisionHeader,
            PanePriority::P0,
            PaneRect::new(0, 0, full_width, 3),
            true,
        ),
        ExplainabilityPlacement::new(
            ExplainabilityPane::FactorBreakdown,
            PanePriority::P0,
            PaneRect::new(0, 3, left_width, body_height),
            true,
        ),
        ExplainabilityPlacement::new(
            ExplainabilityPane::VetoDetail,
            PanePriority::P1,
            PaneRect::new(right_col, 3, right_width, body_height),
            veto_visible,
        ),
        ExplainabilityPlacement::new(
            ExplainabilityPane::StatusFooter,
            PanePriority::P0,
            PaneRect::new(0, footer_row, full_width, 1),
            true,
        ),
    ];

    ExplainabilityLayout {
        class: LayoutClass::Wide,
        placements,
    }
}

// ──────────────────── candidates layout (S4) ────────────────────

/// Panes for the candidates screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidatesPane {
    /// Summary bar with candidate count and filter state.
    SummaryBar,
    /// Scrollable candidate list with scores.
    CandidateList,
    /// Score breakdown panel for selected candidate (wide layout only).
    ScoreDetail,
    /// Status footer with data-source indicator.
    StatusFooter,
}

impl CandidatesPane {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::SummaryBar => "cd-summary-bar",
            Self::CandidateList => "cd-candidate-list",
            Self::ScoreDetail => "cd-score-detail",
            Self::StatusFooter => "cd-status-footer",
        }
    }
}

/// Placement for a candidates pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidatesPlacement {
    pub pane: CandidatesPane,
    pub priority: PanePriority,
    pub rect: PaneRect,
    pub visible: bool,
}

impl CandidatesPlacement {
    #[must_use]
    pub const fn new(
        pane: CandidatesPane,
        priority: PanePriority,
        rect: PaneRect,
        visible: bool,
    ) -> Self {
        Self {
            pane,
            priority,
            rect,
            visible,
        }
    }
}

/// Complete candidates layout plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatesLayout {
    pub class: LayoutClass,
    pub placements: Vec<CandidatesPlacement>,
}

/// Build pane placements for the candidates screen.
#[must_use]
pub fn build_candidates_layout(cols: u16, rows: u16) -> CandidatesLayout {
    match classify_layout(cols) {
        LayoutClass::Narrow => build_narrow_candidates(cols, rows),
        LayoutClass::Wide => build_wide_candidates(cols, rows),
    }
}

fn build_narrow_candidates(cols: u16, rows: u16) -> CandidatesLayout {
    let w = cols.max(1);
    let footer_row = rows.saturating_sub(1);
    let list_height = footer_row.saturating_sub(1).max(1);

    let placements = vec![
        CandidatesPlacement::new(
            CandidatesPane::SummaryBar,
            PanePriority::P0,
            PaneRect::new(0, 0, w, 1),
            true,
        ),
        CandidatesPlacement::new(
            CandidatesPane::CandidateList,
            PanePriority::P0,
            PaneRect::new(0, 1, w, list_height),
            true,
        ),
        // Score detail hidden in narrow layout.
        CandidatesPlacement::new(
            CandidatesPane::ScoreDetail,
            PanePriority::P2,
            PaneRect::new(0, 0, 0, 0),
            false,
        ),
        CandidatesPlacement::new(
            CandidatesPane::StatusFooter,
            PanePriority::P0,
            PaneRect::new(0, footer_row, w, 1),
            true,
        ),
    ];

    CandidatesLayout {
        class: LayoutClass::Narrow,
        placements,
    }
}

fn build_wide_candidates(cols: u16, rows: u16) -> CandidatesLayout {
    let full_width = cols.max(1);
    let (list_width, detail_width) = split_columns(full_width, 1);
    let detail_col = list_width.saturating_add(1);
    let footer_row = rows.saturating_sub(1);
    let body_height = footer_row.saturating_sub(1).max(1);
    let detail_visible = rows >= 10;

    let placements = vec![
        CandidatesPlacement::new(
            CandidatesPane::SummaryBar,
            PanePriority::P0,
            PaneRect::new(0, 0, full_width, 1),
            true,
        ),
        CandidatesPlacement::new(
            CandidatesPane::CandidateList,
            PanePriority::P0,
            PaneRect::new(0, 1, list_width, body_height),
            true,
        ),
        CandidatesPlacement::new(
            CandidatesPane::ScoreDetail,
            PanePriority::P1,
            PaneRect::new(detail_col, 1, detail_width, body_height),
            detail_visible,
        ),
        CandidatesPlacement::new(
            CandidatesPane::StatusFooter,
            PanePriority::P0,
            PaneRect::new(0, footer_row, full_width, 1),
            true,
        ),
    ];

    CandidatesLayout {
        class: LayoutClass::Wide,
        placements,
    }
}

// ──────────────────── log search layout (S6) ────────────────────

/// Panes for the log search screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSearchPane {
    /// Search/filter input bar.
    SearchBar,
    /// Scrollable log entry list.
    LogList,
    /// Entry detail panel (wide layout only).
    EntryDetail,
    /// Status footer with result count and source indicator.
    StatusFooter,
}

impl LogSearchPane {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::SearchBar => "ls-search-bar",
            Self::LogList => "ls-log-list",
            Self::EntryDetail => "ls-entry-detail",
            Self::StatusFooter => "ls-status-footer",
        }
    }
}

/// Placement for a log search pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogSearchPlacement {
    pub pane: LogSearchPane,
    pub priority: PanePriority,
    pub rect: PaneRect,
    pub visible: bool,
}

impl LogSearchPlacement {
    #[must_use]
    pub const fn new(
        pane: LogSearchPane,
        priority: PanePriority,
        rect: PaneRect,
        visible: bool,
    ) -> Self {
        Self {
            pane,
            priority,
            rect,
            visible,
        }
    }
}

/// Complete log search layout plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSearchLayout {
    pub class: LayoutClass,
    pub placements: Vec<LogSearchPlacement>,
}

/// Build pane placements for the log search screen.
#[must_use]
pub fn build_log_search_layout(cols: u16, rows: u16) -> LogSearchLayout {
    match classify_layout(cols) {
        LayoutClass::Narrow => build_narrow_log_search(cols, rows),
        LayoutClass::Wide => build_wide_log_search(cols, rows),
    }
}

fn build_narrow_log_search(cols: u16, rows: u16) -> LogSearchLayout {
    let w = cols.max(1);
    let footer_row = rows.saturating_sub(1);
    let list_height = footer_row.saturating_sub(1).max(1);

    let placements = vec![
        LogSearchPlacement::new(
            LogSearchPane::SearchBar,
            PanePriority::P0,
            PaneRect::new(0, 0, w, 1),
            true,
        ),
        LogSearchPlacement::new(
            LogSearchPane::LogList,
            PanePriority::P0,
            PaneRect::new(0, 1, w, list_height),
            true,
        ),
        // Entry detail hidden in narrow layout.
        LogSearchPlacement::new(
            LogSearchPane::EntryDetail,
            PanePriority::P2,
            PaneRect::new(0, 0, 0, 0),
            false,
        ),
        LogSearchPlacement::new(
            LogSearchPane::StatusFooter,
            PanePriority::P0,
            PaneRect::new(0, footer_row, w, 1),
            true,
        ),
    ];

    LogSearchLayout {
        class: LayoutClass::Narrow,
        placements,
    }
}

fn build_wide_log_search(cols: u16, rows: u16) -> LogSearchLayout {
    let full_width = cols.max(1);
    let (list_width, detail_width) = split_columns(full_width, 1);
    let detail_col = list_width.saturating_add(1);
    let footer_row = rows.saturating_sub(1);
    let body_height = footer_row.saturating_sub(1).max(1);
    let detail_visible = rows >= 10;

    let placements = vec![
        LogSearchPlacement::new(
            LogSearchPane::SearchBar,
            PanePriority::P0,
            PaneRect::new(0, 0, full_width, 1),
            true,
        ),
        LogSearchPlacement::new(
            LogSearchPane::LogList,
            PanePriority::P0,
            PaneRect::new(0, 1, list_width, body_height),
            true,
        ),
        LogSearchPlacement::new(
            LogSearchPane::EntryDetail,
            PanePriority::P1,
            PaneRect::new(detail_col, 1, detail_width, body_height),
            detail_visible,
        ),
        LogSearchPlacement::new(
            LogSearchPane::StatusFooter,
            PanePriority::P0,
            PaneRect::new(0, footer_row, full_width, 1),
            true,
        ),
    ];

    LogSearchLayout {
        class: LayoutClass::Wide,
        placements,
    }
}

// ──────────────────── diagnostics layout (S7) ────────────────────

/// Panes for the diagnostics screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticsPane {
    /// Health summary header (daemon status, mode badge).
    HealthHeader,
    /// Thread status table (main area).
    ThreadTable,
    /// Performance percentiles panel (wide layout only).
    PerfPanel,
    /// Status footer with data-source indicator.
    StatusFooter,
}

impl DiagnosticsPane {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::HealthHeader => "dg-health-header",
            Self::ThreadTable => "dg-thread-table",
            Self::PerfPanel => "dg-perf-panel",
            Self::StatusFooter => "dg-status-footer",
        }
    }
}

/// Placement for a diagnostics pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagnosticsPlacement {
    pub pane: DiagnosticsPane,
    pub priority: PanePriority,
    pub rect: PaneRect,
    pub visible: bool,
}

impl DiagnosticsPlacement {
    #[must_use]
    pub const fn new(
        pane: DiagnosticsPane,
        priority: PanePriority,
        rect: PaneRect,
        visible: bool,
    ) -> Self {
        Self {
            pane,
            priority,
            rect,
            visible,
        }
    }
}

/// Complete diagnostics layout plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticsLayout {
    pub class: LayoutClass,
    pub placements: Vec<DiagnosticsPlacement>,
}

/// Build pane placements for the diagnostics screen.
#[must_use]
pub fn build_diagnostics_layout(cols: u16, rows: u16) -> DiagnosticsLayout {
    match classify_layout(cols) {
        LayoutClass::Narrow => build_narrow_diagnostics(cols, rows),
        LayoutClass::Wide => build_wide_diagnostics(cols, rows),
    }
}

fn build_narrow_diagnostics(cols: u16, rows: u16) -> DiagnosticsLayout {
    let w = cols.max(1);
    let footer_row = rows.saturating_sub(1);
    let table_height = footer_row.saturating_sub(3).max(1);
    let perf_visible = rows >= 20;
    // In narrow layout, perf panel stacks below thread table when there's room.
    let perf_row = 3u16.saturating_add(table_height);
    let perf_height = if perf_visible {
        footer_row.saturating_sub(perf_row).max(1)
    } else {
        0
    };

    let placements = vec![
        DiagnosticsPlacement::new(
            DiagnosticsPane::HealthHeader,
            PanePriority::P0,
            PaneRect::new(0, 0, w, 3),
            true,
        ),
        DiagnosticsPlacement::new(
            DiagnosticsPane::ThreadTable,
            PanePriority::P0,
            PaneRect::new(0, 3, w, table_height),
            true,
        ),
        DiagnosticsPlacement::new(
            DiagnosticsPane::PerfPanel,
            PanePriority::P2,
            PaneRect::new(0, perf_row, w, perf_height),
            perf_visible,
        ),
        DiagnosticsPlacement::new(
            DiagnosticsPane::StatusFooter,
            PanePriority::P0,
            PaneRect::new(0, footer_row, w, 1),
            true,
        ),
    ];

    DiagnosticsLayout {
        class: LayoutClass::Narrow,
        placements,
    }
}

fn build_wide_diagnostics(cols: u16, rows: u16) -> DiagnosticsLayout {
    let full_width = cols.max(1);
    let (left_width, right_width) = split_columns(full_width, 1);
    let right_col = left_width.saturating_add(1);
    let footer_row = rows.saturating_sub(1);
    let body_height = footer_row.saturating_sub(3).max(1);
    let perf_visible = rows >= 12;

    let placements = vec![
        DiagnosticsPlacement::new(
            DiagnosticsPane::HealthHeader,
            PanePriority::P0,
            PaneRect::new(0, 0, full_width, 3),
            true,
        ),
        DiagnosticsPlacement::new(
            DiagnosticsPane::ThreadTable,
            PanePriority::P0,
            PaneRect::new(0, 3, left_width, body_height),
            true,
        ),
        DiagnosticsPlacement::new(
            DiagnosticsPane::PerfPanel,
            PanePriority::P1,
            PaneRect::new(right_col, 3, right_width, body_height),
            perf_visible,
        ),
        DiagnosticsPlacement::new(
            DiagnosticsPane::StatusFooter,
            PanePriority::P0,
            PaneRect::new(0, footer_row, full_width, 1),
            true,
        ),
    ];

    DiagnosticsLayout {
        class: LayoutClass::Wide,
        placements,
    }
}

// ──────────────────── shared helpers ────────────────────

fn split_columns(cols: u16, gutter: u16) -> (u16, u16) {
    let usable = cols.saturating_sub(gutter);
    let left = (usable.saturating_mul(3) / 5).max(1);
    let right = usable.saturating_sub(left).max(1);
    (left, right)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_layout_switches_at_threshold() {
        assert_eq!(classify_layout(80), LayoutClass::Narrow);
        assert_eq!(classify_layout(99), LayoutClass::Narrow);
        assert_eq!(classify_layout(100), LayoutClass::Wide);
    }

    #[test]
    fn narrow_layout_hides_p2_under_height_budget() {
        let layout = build_overview_layout(90, 18);
        let p2 = layout
            .placements
            .iter()
            .find(|p| p.pane == OverviewPane::ExtendedCounters);
        assert!(p2.is_some_and(|p| !p.visible));
    }

    #[test]
    fn wide_layout_uses_two_columns() {
        let layout = build_overview_layout(140, 30);
        assert_eq!(layout.class, LayoutClass::Wide);
        let pressure = layout
            .placements
            .iter()
            .find(|p| p.pane == OverviewPane::PressureSummary)
            .expect("pressure pane");
        let action = layout
            .placements
            .iter()
            .find(|p| p.pane == OverviewPane::ActionLane)
            .expect("action pane");
        assert!(action.rect.col > pressure.rect.col);
    }

    // ── Timeline layout ──

    #[test]
    fn narrow_timeline_hides_detail_panel() {
        let layout = build_timeline_layout(80, 24);
        assert_eq!(layout.class, LayoutClass::Narrow);
        let detail = layout
            .placements
            .iter()
            .find(|p| p.pane == TimelinePane::EventDetail);
        assert!(detail.is_some_and(|p| !p.visible));
    }

    #[test]
    fn narrow_timeline_has_filter_list_and_footer() {
        let layout = build_timeline_layout(80, 24);
        let filter = layout
            .placements
            .iter()
            .find(|p| p.pane == TimelinePane::FilterBar);
        assert!(filter.is_some_and(|p| p.visible));
        let list = layout
            .placements
            .iter()
            .find(|p| p.pane == TimelinePane::EventList);
        assert!(list.is_some_and(|p| p.visible && p.rect.height > 0));
        let footer = layout
            .placements
            .iter()
            .find(|p| p.pane == TimelinePane::StatusFooter);
        assert!(footer.is_some_and(|p| p.visible));
    }

    #[test]
    fn wide_timeline_shows_detail_panel() {
        let layout = build_timeline_layout(140, 30);
        assert_eq!(layout.class, LayoutClass::Wide);
        let detail = layout
            .placements
            .iter()
            .find(|p| p.pane == TimelinePane::EventDetail)
            .expect("detail pane");
        assert!(detail.visible);
        assert!(detail.rect.col > 0);
    }

    #[test]
    fn timeline_pane_ids_are_unique() {
        let panes = [
            TimelinePane::FilterBar,
            TimelinePane::EventList,
            TimelinePane::EventDetail,
            TimelinePane::StatusFooter,
        ];
        let ids: Vec<_> = panes.iter().map(|p| p.id()).collect();
        for (i, a) in ids.iter().enumerate() {
            for b in &ids[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    // ── Ballast layout ──

    #[test]
    fn narrow_ballast_hides_detail_panel() {
        let layout = build_ballast_layout(80, 24);
        assert_eq!(layout.class, LayoutClass::Narrow);
        let detail = layout
            .placements
            .iter()
            .find(|p| p.pane == BallastPane::VolumeDetail);
        assert!(detail.is_some_and(|p| !p.visible));
    }

    #[test]
    fn narrow_ballast_has_list_and_footer() {
        let layout = build_ballast_layout(80, 24);
        let list = layout
            .placements
            .iter()
            .find(|p| p.pane == BallastPane::VolumeList);
        assert!(list.is_some_and(|p| p.visible && p.rect.height > 0));
        let footer = layout
            .placements
            .iter()
            .find(|p| p.pane == BallastPane::StatusFooter);
        assert!(footer.is_some_and(|p| p.visible));
    }

    #[test]
    fn wide_ballast_shows_detail_panel() {
        let layout = build_ballast_layout(140, 30);
        assert_eq!(layout.class, LayoutClass::Wide);
        let detail = layout
            .placements
            .iter()
            .find(|p| p.pane == BallastPane::VolumeDetail)
            .expect("detail pane");
        assert!(detail.visible);
        assert!(detail.rect.col > 0);
    }

    #[test]
    fn wide_ballast_detail_hidden_on_short_terminal() {
        let layout = build_ballast_layout(140, 8);
        let detail = layout
            .placements
            .iter()
            .find(|p| p.pane == BallastPane::VolumeDetail);
        assert!(detail.is_some_and(|p| !p.visible));
    }

    #[test]
    fn ballast_pane_ids_are_unique() {
        let panes = [
            BallastPane::VolumeList,
            BallastPane::VolumeDetail,
            BallastPane::StatusFooter,
        ];
        let ids: Vec<_> = panes.iter().map(|p| p.id()).collect();
        for (i, a) in ids.iter().enumerate() {
            for b in &ids[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    // ── Minimum size checks ──

    #[test]
    fn terminal_too_small_below_thresholds() {
        assert!(is_terminal_too_small(39, 24));
        assert!(is_terminal_too_small(80, 7));
        assert!(is_terminal_too_small(20, 5));
    }

    #[test]
    fn terminal_usable_at_thresholds() {
        assert!(!is_terminal_too_small(40, 8));
        assert!(!is_terminal_too_small(80, 24));
        assert!(!is_terminal_too_small(200, 50));
    }

    // ── Explainability layout (S3) ──

    #[test]
    fn narrow_explainability_hides_veto_detail() {
        let layout = build_explainability_layout(80, 24);
        assert_eq!(layout.class, LayoutClass::Narrow);
        let veto = layout
            .placements
            .iter()
            .find(|p| p.pane == ExplainabilityPane::VetoDetail);
        assert!(veto.is_some_and(|p| !p.visible));
    }

    #[test]
    fn narrow_explainability_has_header_breakdown_footer() {
        let layout = build_explainability_layout(80, 24);
        let header = layout
            .placements
            .iter()
            .find(|p| p.pane == ExplainabilityPane::DecisionHeader);
        assert!(header.is_some_and(|p| p.visible));
        let breakdown = layout
            .placements
            .iter()
            .find(|p| p.pane == ExplainabilityPane::FactorBreakdown);
        assert!(breakdown.is_some_and(|p| p.visible && p.rect.height > 0));
        let footer = layout
            .placements
            .iter()
            .find(|p| p.pane == ExplainabilityPane::StatusFooter);
        assert!(footer.is_some_and(|p| p.visible));
    }

    #[test]
    fn wide_explainability_shows_veto_detail() {
        let layout = build_explainability_layout(140, 30);
        assert_eq!(layout.class, LayoutClass::Wide);
        let veto = layout
            .placements
            .iter()
            .find(|p| p.pane == ExplainabilityPane::VetoDetail)
            .expect("veto pane");
        assert!(veto.visible);
        assert!(veto.rect.col > 0);
    }

    #[test]
    fn wide_explainability_veto_hidden_on_short_terminal() {
        let layout = build_explainability_layout(140, 10);
        let veto = layout
            .placements
            .iter()
            .find(|p| p.pane == ExplainabilityPane::VetoDetail);
        assert!(veto.is_some_and(|p| !p.visible));
    }

    #[test]
    fn explainability_pane_ids_are_unique() {
        let panes = [
            ExplainabilityPane::DecisionHeader,
            ExplainabilityPane::FactorBreakdown,
            ExplainabilityPane::VetoDetail,
            ExplainabilityPane::StatusFooter,
        ];
        let ids: Vec<_> = panes.iter().map(|p| p.id()).collect();
        for (i, a) in ids.iter().enumerate() {
            for b in &ids[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    // ── Candidates layout (S4) ──

    #[test]
    fn narrow_candidates_hides_score_detail() {
        let layout = build_candidates_layout(80, 24);
        assert_eq!(layout.class, LayoutClass::Narrow);
        let detail = layout
            .placements
            .iter()
            .find(|p| p.pane == CandidatesPane::ScoreDetail);
        assert!(detail.is_some_and(|p| !p.visible));
    }

    #[test]
    fn narrow_candidates_has_summary_list_footer() {
        let layout = build_candidates_layout(80, 24);
        let summary = layout
            .placements
            .iter()
            .find(|p| p.pane == CandidatesPane::SummaryBar);
        assert!(summary.is_some_and(|p| p.visible));
        let list = layout
            .placements
            .iter()
            .find(|p| p.pane == CandidatesPane::CandidateList);
        assert!(list.is_some_and(|p| p.visible && p.rect.height > 0));
        let footer = layout
            .placements
            .iter()
            .find(|p| p.pane == CandidatesPane::StatusFooter);
        assert!(footer.is_some_and(|p| p.visible));
    }

    #[test]
    fn wide_candidates_shows_score_detail() {
        let layout = build_candidates_layout(140, 30);
        assert_eq!(layout.class, LayoutClass::Wide);
        let detail = layout
            .placements
            .iter()
            .find(|p| p.pane == CandidatesPane::ScoreDetail)
            .expect("score detail pane");
        assert!(detail.visible);
        assert!(detail.rect.col > 0);
    }

    #[test]
    fn wide_candidates_detail_hidden_on_short_terminal() {
        let layout = build_candidates_layout(140, 8);
        let detail = layout
            .placements
            .iter()
            .find(|p| p.pane == CandidatesPane::ScoreDetail);
        assert!(detail.is_some_and(|p| !p.visible));
    }

    #[test]
    fn candidates_pane_ids_are_unique() {
        let panes = [
            CandidatesPane::SummaryBar,
            CandidatesPane::CandidateList,
            CandidatesPane::ScoreDetail,
            CandidatesPane::StatusFooter,
        ];
        let ids: Vec<_> = panes.iter().map(|p| p.id()).collect();
        for (i, a) in ids.iter().enumerate() {
            for b in &ids[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    // ── Log search layout (S6) ──

    #[test]
    fn narrow_log_search_hides_entry_detail() {
        let layout = build_log_search_layout(80, 24);
        assert_eq!(layout.class, LayoutClass::Narrow);
        let detail = layout
            .placements
            .iter()
            .find(|p| p.pane == LogSearchPane::EntryDetail);
        assert!(detail.is_some_and(|p| !p.visible));
    }

    #[test]
    fn narrow_log_search_has_search_list_footer() {
        let layout = build_log_search_layout(80, 24);
        let search = layout
            .placements
            .iter()
            .find(|p| p.pane == LogSearchPane::SearchBar);
        assert!(search.is_some_and(|p| p.visible));
        let list = layout
            .placements
            .iter()
            .find(|p| p.pane == LogSearchPane::LogList);
        assert!(list.is_some_and(|p| p.visible && p.rect.height > 0));
        let footer = layout
            .placements
            .iter()
            .find(|p| p.pane == LogSearchPane::StatusFooter);
        assert!(footer.is_some_and(|p| p.visible));
    }

    #[test]
    fn wide_log_search_shows_entry_detail() {
        let layout = build_log_search_layout(140, 30);
        assert_eq!(layout.class, LayoutClass::Wide);
        let detail = layout
            .placements
            .iter()
            .find(|p| p.pane == LogSearchPane::EntryDetail)
            .expect("entry detail pane");
        assert!(detail.visible);
        assert!(detail.rect.col > 0);
    }

    #[test]
    fn log_search_pane_ids_are_unique() {
        let panes = [
            LogSearchPane::SearchBar,
            LogSearchPane::LogList,
            LogSearchPane::EntryDetail,
            LogSearchPane::StatusFooter,
        ];
        let ids: Vec<_> = panes.iter().map(|p| p.id()).collect();
        for (i, a) in ids.iter().enumerate() {
            for b in &ids[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    // ── Diagnostics layout (S7) ──

    #[test]
    fn narrow_diagnostics_hides_perf_panel_on_short() {
        let layout = build_diagnostics_layout(80, 15);
        assert_eq!(layout.class, LayoutClass::Narrow);
        let perf = layout
            .placements
            .iter()
            .find(|p| p.pane == DiagnosticsPane::PerfPanel);
        assert!(perf.is_some_and(|p| !p.visible));
    }

    #[test]
    fn narrow_diagnostics_shows_perf_panel_on_tall() {
        let layout = build_diagnostics_layout(80, 25);
        let perf = layout
            .placements
            .iter()
            .find(|p| p.pane == DiagnosticsPane::PerfPanel);
        assert!(perf.is_some_and(|p| p.visible));
    }

    #[test]
    fn narrow_diagnostics_has_header_table_footer() {
        let layout = build_diagnostics_layout(80, 24);
        let header = layout
            .placements
            .iter()
            .find(|p| p.pane == DiagnosticsPane::HealthHeader);
        assert!(header.is_some_and(|p| p.visible));
        let table = layout
            .placements
            .iter()
            .find(|p| p.pane == DiagnosticsPane::ThreadTable);
        assert!(table.is_some_and(|p| p.visible && p.rect.height > 0));
        let footer = layout
            .placements
            .iter()
            .find(|p| p.pane == DiagnosticsPane::StatusFooter);
        assert!(footer.is_some_and(|p| p.visible));
    }

    #[test]
    fn wide_diagnostics_shows_perf_panel() {
        let layout = build_diagnostics_layout(140, 30);
        assert_eq!(layout.class, LayoutClass::Wide);
        let perf = layout
            .placements
            .iter()
            .find(|p| p.pane == DiagnosticsPane::PerfPanel)
            .expect("perf panel");
        assert!(perf.visible);
        assert!(perf.rect.col > 0);
    }

    #[test]
    fn wide_diagnostics_perf_hidden_on_short_terminal() {
        let layout = build_diagnostics_layout(140, 10);
        let perf = layout
            .placements
            .iter()
            .find(|p| p.pane == DiagnosticsPane::PerfPanel);
        assert!(perf.is_some_and(|p| !p.visible));
    }

    #[test]
    fn diagnostics_pane_ids_are_unique() {
        let panes = [
            DiagnosticsPane::HealthHeader,
            DiagnosticsPane::ThreadTable,
            DiagnosticsPane::PerfPanel,
            DiagnosticsPane::StatusFooter,
        ];
        let ids: Vec<_> = panes.iter().map(|p| p.id()).collect();
        for (i, a) in ids.iter().enumerate() {
            for b in &ids[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    // ── Edge-case dimension tests (all screens) ──

    /// Every layout builder must not panic at extreme dimensions.
    #[test]
    fn all_layouts_survive_extreme_dimensions() {
        let sizes: &[(u16, u16)] = &[
            (1, 1),
            (40, 8),
            (60, 15),
            (80, 24),
            (100, 24),
            (120, 30),
            (200, 50),
            (0, 0),
            (u16::MAX, u16::MAX),
        ];
        for &(cols, rows) in sizes {
            // S1
            let _ = build_overview_layout(cols, rows);
            // S2
            let _ = build_timeline_layout(cols, rows);
            // S3
            let _ = build_explainability_layout(cols, rows);
            // S4
            let _ = build_candidates_layout(cols, rows);
            // S5
            let _ = build_ballast_layout(cols, rows);
            // S6
            let _ = build_log_search_layout(cols, rows);
            // S7
            let _ = build_diagnostics_layout(cols, rows);
        }
    }

    /// P0 panes must always be visible regardless of terminal size.
    #[test]
    fn p0_panes_always_visible_overview() {
        for &(cols, rows) in &[(40, 8), (80, 10), (200, 50)] {
            let layout = build_overview_layout(cols, rows);
            for p in &layout.placements {
                if matches!(p.priority, PanePriority::P0) {
                    assert!(
                        p.visible,
                        "P0 overview pane {:?} hidden at {cols}x{rows}",
                        p.pane
                    );
                }
            }
        }
    }

    #[test]
    fn p0_panes_always_visible_timeline() {
        for &(cols, rows) in &[(40, 8), (80, 10), (200, 50)] {
            let layout = build_timeline_layout(cols, rows);
            for p in &layout.placements {
                if matches!(p.priority, PanePriority::P0) {
                    assert!(
                        p.visible,
                        "P0 timeline pane {:?} hidden at {cols}x{rows}",
                        p.pane
                    );
                }
            }
        }
    }

    #[test]
    fn p0_panes_always_visible_explainability() {
        for &(cols, rows) in &[(40, 8), (80, 10), (200, 50)] {
            let layout = build_explainability_layout(cols, rows);
            for p in &layout.placements {
                if matches!(p.priority, PanePriority::P0) {
                    assert!(
                        p.visible,
                        "P0 explainability pane {:?} hidden at {cols}x{rows}",
                        p.pane
                    );
                }
            }
        }
    }

    #[test]
    fn p0_panes_always_visible_candidates() {
        for &(cols, rows) in &[(40, 8), (80, 10), (200, 50)] {
            let layout = build_candidates_layout(cols, rows);
            for p in &layout.placements {
                if matches!(p.priority, PanePriority::P0) {
                    assert!(
                        p.visible,
                        "P0 candidates pane {:?} hidden at {cols}x{rows}",
                        p.pane
                    );
                }
            }
        }
    }

    #[test]
    fn p0_panes_always_visible_ballast() {
        for &(cols, rows) in &[(40, 8), (80, 10), (200, 50)] {
            let layout = build_ballast_layout(cols, rows);
            for p in &layout.placements {
                if matches!(p.priority, PanePriority::P0) {
                    assert!(
                        p.visible,
                        "P0 ballast pane {:?} hidden at {cols}x{rows}",
                        p.pane
                    );
                }
            }
        }
    }

    #[test]
    fn p0_panes_always_visible_log_search() {
        for &(cols, rows) in &[(40, 8), (80, 10), (200, 50)] {
            let layout = build_log_search_layout(cols, rows);
            for p in &layout.placements {
                if matches!(p.priority, PanePriority::P0) {
                    assert!(
                        p.visible,
                        "P0 log search pane {:?} hidden at {cols}x{rows}",
                        p.pane
                    );
                }
            }
        }
    }

    #[test]
    fn p0_panes_always_visible_diagnostics() {
        for &(cols, rows) in &[(40, 8), (80, 10), (200, 50)] {
            let layout = build_diagnostics_layout(cols, rows);
            for p in &layout.placements {
                if matches!(p.priority, PanePriority::P0) {
                    assert!(
                        p.visible,
                        "P0 diagnostics pane {:?} hidden at {cols}x{rows}",
                        p.pane
                    );
                }
            }
        }
    }

    /// All visible P0 panes must have non-zero dimensions.
    #[test]
    fn visible_panes_have_nonzero_dimensions() {
        for &(cols, rows) in &[(40, 8), (80, 24), (140, 30)] {
            // S1
            for p in &build_overview_layout(cols, rows).placements {
                if p.visible {
                    assert!(
                        p.rect.width > 0 && p.rect.height > 0,
                        "overview pane {:?} has zero dim at {cols}x{rows}",
                        p.pane
                    );
                }
            }
            // S2
            for p in &build_timeline_layout(cols, rows).placements {
                if p.visible {
                    assert!(
                        p.rect.width > 0 && p.rect.height > 0,
                        "timeline pane {:?} has zero dim at {cols}x{rows}",
                        p.pane
                    );
                }
            }
            // S3
            for p in &build_explainability_layout(cols, rows).placements {
                if p.visible {
                    assert!(
                        p.rect.width > 0 && p.rect.height > 0,
                        "explainability pane {:?} has zero dim at {cols}x{rows}",
                        p.pane
                    );
                }
            }
            // S4
            for p in &build_candidates_layout(cols, rows).placements {
                if p.visible {
                    assert!(
                        p.rect.width > 0 && p.rect.height > 0,
                        "candidates pane {:?} has zero dim at {cols}x{rows}",
                        p.pane
                    );
                }
            }
            // S5
            for p in &build_ballast_layout(cols, rows).placements {
                if p.visible {
                    assert!(
                        p.rect.width > 0 && p.rect.height > 0,
                        "ballast pane {:?} has zero dim at {cols}x{rows}",
                        p.pane
                    );
                }
            }
            // S6
            for p in &build_log_search_layout(cols, rows).placements {
                if p.visible {
                    assert!(
                        p.rect.width > 0 && p.rect.height > 0,
                        "log_search pane {:?} has zero dim at {cols}x{rows}",
                        p.pane
                    );
                }
            }
            // S7
            for p in &build_diagnostics_layout(cols, rows).placements {
                if p.visible {
                    assert!(
                        p.rect.width > 0 && p.rect.height > 0,
                        "diagnostics pane {:?} has zero dim at {cols}x{rows}",
                        p.pane
                    );
                }
            }
        }
    }

    /// Wide layouts hide side panels when terminal is too short.
    #[test]
    fn wide_layouts_adapt_to_short_terminals() {
        let short_rows = 8;

        // Timeline: detail hidden
        let tl = build_timeline_layout(140, short_rows);
        let tl_detail = tl
            .placements
            .iter()
            .find(|p| p.pane == TimelinePane::EventDetail);
        assert!(tl_detail.is_some_and(|p| !p.visible));

        // Ballast: detail hidden
        let bl = build_ballast_layout(140, short_rows);
        let bl_detail = bl
            .placements
            .iter()
            .find(|p| p.pane == BallastPane::VolumeDetail);
        assert!(bl_detail.is_some_and(|p| !p.visible));

        // Candidates: score detail hidden
        let cd = build_candidates_layout(140, short_rows);
        let cd_detail = cd
            .placements
            .iter()
            .find(|p| p.pane == CandidatesPane::ScoreDetail);
        assert!(cd_detail.is_some_and(|p| !p.visible));

        // Log search: entry detail hidden
        let ls = build_log_search_layout(140, short_rows);
        let ls_detail = ls
            .placements
            .iter()
            .find(|p| p.pane == LogSearchPane::EntryDetail);
        assert!(ls_detail.is_some_and(|p| !p.visible));

        // Diagnostics: perf panel hidden
        let dg = build_diagnostics_layout(140, short_rows);
        let dg_perf = dg
            .placements
            .iter()
            .find(|p| p.pane == DiagnosticsPane::PerfPanel);
        assert!(dg_perf.is_some_and(|p| !p.visible));
    }

    /// split_columns produces valid sizes for any input.
    #[test]
    fn split_columns_edge_cases() {
        // Zero width
        let (l, r) = split_columns(0, 1);
        assert!(l >= 1 && r >= 1);

        // Width 1 with gutter
        let (l, r) = split_columns(1, 1);
        assert!(l >= 1 && r >= 1);

        // Normal case
        let (l, r) = split_columns(120, 1);
        assert_eq!(l + 1 + r, 120);
    }
}
