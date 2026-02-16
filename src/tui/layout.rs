//! Responsive pane composition primitives for dashboard screens.

#![allow(missing_docs)]

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
}
