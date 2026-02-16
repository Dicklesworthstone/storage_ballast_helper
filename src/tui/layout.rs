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
}
