//! Render-surface scaffolding for the new dashboard runtime.
//!
//! Two entrypoints:
//! - `render_frame()` — Frame-based widget rendering (production path).
//! - `render_to_string()` — legacy String-returning path (used by tests and
//!   the headless harness that asserts on text content).

#![allow(missing_docs)]
#![allow(clippy::too_many_lines)]

use super::layout::{
    BallastPane, CandidatesPane, DiagnosticsPane, ExplainabilityPane, LogSearchPane,
    MIN_USABLE_COLS, MIN_USABLE_ROWS, OverviewPane, PanePriority, TimelinePane,
    build_ballast_layout, build_candidates_layout, build_diagnostics_layout,
    build_explainability_layout, build_log_search_layout, build_overview_layout,
    build_timeline_layout, is_terminal_too_small,
};
use super::model::{
    BallastVolume, DashboardModel, NotificationLevel, PreferenceProfileMode, Screen,
};
use super::preferences::{DensityMode, HintVerbosity, StartScreen};
use super::theme::{AccessibilityProfile, PaletteEntry, SpacingScale, Theme, ThemePalette};
use super::widgets::{
    colored_sparkline, extract_time, gauge, human_bytes, human_duration, human_rate, key_hint,
    mini_bar_chart, section_header, segmented_gauge, separator_line, sparkline, status_badge,
    styled_badge, trend_label,
};
use crate::tui::telemetry::{DataSource, DecisionEvidence, TimelineEvent};

use ftui::core::geometry::Rect;
use ftui::layout::{Constraint, Flex};
use ftui::text::{Line, Span, Text};
use ftui::widgets::Widget;
use ftui::widgets::block::Block;
use ftui::widgets::borders::BorderType;
use ftui::widgets::paragraph::Paragraph;
use ftui::{Frame, PackedRgba, Style};

const FRAME_HEADER_ROWS: u16 = 4;
const FRAME_FOOTER_ROWS: u16 = 1;

/// Legacy string-returning render path for test compatibility.
///
/// Production code should use `render_frame()` instead.
#[must_use]
pub fn render(model: &DashboardModel) -> String {
    render_to_string(model)
}

/// Legacy string-returning render for the headless test harness.
#[must_use]
pub fn render_to_string(model: &DashboardModel) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let accessibility = AccessibilityProfile::from_environment();
    let mut theme = Theme::for_terminal(model.terminal_size.0, accessibility);
    theme.spacing = match model.density {
        DensityMode::Compact => SpacingScale::compact(),
        DensityMode::Comfortable => SpacingScale::comfortable(),
    };

    // Always-on header: mode indicator, active screen, overlay status.
    let mode = if model.degraded { "DEGRADED" } else { "NORMAL" };
    let label = screen_label(model.screen);
    let _ = writeln!(
        out,
        "SBH Dashboard ({mode})  [{label}]  tick={}  size={}x{}",
        model.tick, model.terminal_size.0, model.terminal_size.1
    );
    let _ = writeln!(
        out,
        "theme={} spacing={}",
        color_mode_label(&theme),
        spacing_mode_label(&theme),
    );
    let _ = writeln!(
        out,
        "prefs mode={} start={} density={} hints={}",
        preference_profile_mode_label(model.preference_profile_mode),
        start_screen_label(model.preferred_start_screen),
        model.density,
        model.hint_verbosity,
    );

    if is_terminal_too_small(model.terminal_size.0, model.terminal_size.1) {
        let _ = writeln!(
            out,
            "terminal-too-small: need >= {}x{}, got {}x{}",
            MIN_USABLE_COLS, MIN_USABLE_ROWS, model.terminal_size.0, model.terminal_size.1
        );
        return out;
    }

    // Breadcrumb navigation trail.
    if !model.screen_history.is_empty() {
        let max_crumbs = 5;
        let history = &model.screen_history;
        let start = if history.len() > max_crumbs {
            history.len() - max_crumbs
        } else {
            0
        };
        let mut crumb = String::from("nav:");
        for s in &history[start..] {
            let _ = write!(crumb, " {} >", screen_label(*s));
        }
        let _ = write!(crumb, " {}", screen_label(model.screen));
        let _ = writeln!(out, "{crumb}");
    }

    // Overlay rendering.
    if let Some(ref overlay) = model.active_overlay {
        match overlay {
            super::model::Overlay::CommandPalette => {
                render_command_palette(model, &mut out);
            }
            other => {
                let _ = writeln!(out, "[overlay: {other:?}]");
            }
        }
    }

    // Screen-specific content.
    match model.screen {
        Screen::Overview => render_overview(model, &theme, &mut out),
        Screen::Timeline => render_timeline(model, &theme, &mut out),
        Screen::Explainability => render_explainability(model, &theme, &mut out),
        Screen::Candidates => render_candidates(model, &theme, &mut out),
        Screen::LogSearch => render_log_search(model, &theme, &mut out),
        Screen::Diagnostics => render_diagnostics(model, &theme, &mut out),
        Screen::Ballast => render_ballast(model, &theme, &mut out),
    }

    // Notification toasts (O4).
    for notif in &model.notifications {
        let badge = notification_badge(&theme.palette, theme.accessibility, notif.level);
        let _ = writeln!(out, "[toast#{}] {} {}", notif.id, badge, notif.message);
    }

    out
}

// ══════════════════════════════════════════════════════════════════════════════
// Frame-based widget rendering (production path)
// ══════════════════════════════════════════════════════════════════════════════

/// Render the dashboard into a Frame using proper ftui widgets.
///
/// This is the production rendering path that produces colored, bordered,
/// Flex-layout output through the ftui widget system.
pub fn render_frame(model: &DashboardModel, frame: &mut Frame) {
    let area = Rect::new(0, 0, model.terminal_size.0, model.terminal_size.1);
    let accessibility = AccessibilityProfile::from_environment();
    let mut theme = Theme::for_terminal(model.terminal_size.0, accessibility);
    theme.spacing = match model.density {
        DensityMode::Compact => SpacingScale::compact(),
        DensityMode::Comfortable => SpacingScale::comfortable(),
    };

    // Fill background.
    let bg_color = theme.palette.surface_bg();
    for y in area.y..area.y + area.height {
        for x in area.x..area.x + area.width {
            if let Some(cell) = frame.buffer.get_mut(x, y) {
                cell.bg = bg_color;
            }
        }
    }

    if is_terminal_too_small(model.terminal_size.0, model.terminal_size.1) {
        frame_render_too_small(model, &theme, area, frame);
        return;
    }

    // Split: header (persistent nav + status) | body | footer | notifications.
    let notif_rows = u16::try_from(model.notifications.len().min(3)).unwrap_or(3);
    let chunks = Flex::vertical()
        .constraints([
            Constraint::Fixed(FRAME_HEADER_ROWS),
            Constraint::Fill,
            Constraint::Fixed(FRAME_FOOTER_ROWS),
            Constraint::Fixed(notif_rows),
        ])
        .split(area);

    let header_area = chunks[0];
    let body_area = chunks[1];
    let footer_area = chunks[2];
    let notif_area = chunks[3];

    // ── Header ──
    frame_render_header(model, &theme, header_area, frame);

    // ── Body (screen-specific content) ──
    frame_render_screen(model, &theme, body_area, frame);
    if let Some(overlay) = model.active_overlay {
        frame_render_overlay(model, overlay, &theme, body_area, frame);
    }

    // ── Footer keybindings ──
    frame_render_footer(model, &theme, footer_area, frame);

    // ── Notification toasts ──
    frame_render_notifications(model, &theme, notif_area, frame);
}

fn frame_render_too_small(model: &DashboardModel, theme: &Theme, area: Rect, frame: &mut Frame) {
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .title("SBH Dashboard")
        .border_style(Style::default().fg(theme.palette.warning_color()))
        .style(Style::default().bg(theme.palette.panel_bg()));
    let inner = block.inner(area);
    block.render(area, frame);

    if inner.height == 0 || inner.width == 0 {
        return;
    }

    let msg = format!(
        "Terminal too small for dashboard layout.\nNeed >= {}x{}, got {}x{}.\nResize terminal to continue.",
        MIN_USABLE_COLS, MIN_USABLE_ROWS, model.terminal_size.0, model.terminal_size.1
    );
    Paragraph::new(msg)
        .style(Style::default().fg(theme.palette.warning_color()))
        .render(inner, frame);
}

fn frame_render_header(model: &DashboardModel, theme: &Theme, area: Rect, frame: &mut Frame) {
    // Paint header background.
    for y in area.y..area.y.saturating_add(area.height) {
        for x in area.x..area.x.saturating_add(area.width) {
            if let Some(cell) = frame.buffer.get_mut(x, y) {
                cell.bg = theme.palette.panel_bg();
            }
        }
    }

    if area.height == 0 || area.width == 0 {
        return;
    }

    let mut lines = Vec::new();

    // ── Row 1: Title + mode pill + policy pill ──
    let mode_str = if model.degraded { "DEGRADED" } else { "NORMAL" };
    let mode_color = if model.degraded {
        theme.palette.warning_color()
    } else {
        theme.palette.success_color()
    };

    let mut title_spans = vec![
        Span::styled(
            " SBH Dashboard ",
            Style::default().fg(theme.palette.accent_color()).bold(),
        ),
        Span::styled(
            format!(" {mode_str} "),
            Style::default()
                .fg(PackedRgba::rgb(20, 20, 30))
                .bg(mode_color)
                .bold(),
        ),
    ];
    if let Some(ref state) = model.daemon_state
        && !state.policy_mode.is_empty()
    {
        let policy_color = policy_mode_color(&state.policy_mode, &theme.palette);
        title_spans.push(Span::raw(" "));
        title_spans.push(Span::styled(
            format!(" {} ", state.policy_mode.to_ascii_uppercase()),
            Style::default()
                .fg(PackedRgba::rgb(20, 20, 30))
                .bg(policy_color)
                .bold(),
        ));
    }
    lines.push(Line::from_spans(title_spans));

    // ── Row 2: Tab strip with per-screen accent on active tab ──
    let screens = [
        Screen::Overview,
        Screen::Timeline,
        Screen::Explainability,
        Screen::Candidates,
        Screen::Ballast,
        Screen::LogSearch,
        Screen::Diagnostics,
    ];
    let mut nav_spans = Vec::new();
    nav_spans.push(Span::raw(" "));
    for (idx, screen) in screens.iter().enumerate() {
        let active = *screen == model.screen;
        let label = format!(" {}:{} ", screen.number(), screen_tab_label(*screen));
        let style = if active {
            Style::default()
                .fg(PackedRgba::rgb(20, 20, 30))
                .bg(theme.palette.tab_active_bg(screen.number()))
                .bold()
        } else {
            Style::default().fg(theme.palette.text_secondary())
        };
        nav_spans.push(Span::styled(label, style));
        if idx + 1 < screens.len() {
            nav_spans.push(Span::raw(" "));
        }
    }
    lines.push(Line::from_spans(nav_spans));

    // ── Row 3: Breadcrumb trail (only when history exists) ──
    if model.screen_history.is_empty() {
        // Thin separator line when no breadcrumbs.
        lines.push(separator_line(
            usize::from(area.width),
            theme.palette.border_color(),
        ));
    } else {
        let max_crumbs = 6;
        let history = &model.screen_history;
        let start = history.len().saturating_sub(max_crumbs);
        let mut crumb_spans: Vec<Span> = vec![Span::styled(
            " \u{25B8} ",
            Style::default().fg(theme.palette.muted_color()),
        )];
        for s in &history[start..] {
            crumb_spans.push(Span::styled(
                screen_tab_label(*s),
                Style::default().fg(theme.palette.text_secondary()),
            ));
            crumb_spans.push(Span::styled(
                " \u{203A} ",
                Style::default().fg(theme.palette.muted_color()),
            ));
        }
        crumb_spans.push(Span::styled(
            screen_tab_label(model.screen),
            Style::default().fg(theme.palette.accent_color()).bold(),
        ));
        lines.push(Line::from_spans(crumb_spans));
    }

    let visible_lines = usize::from(area.height);
    let inner = Rect::new(area.x, area.y, area.width, area.height);
    Paragraph::new(Text::from_lines(lines.into_iter().take(visible_lines)))
        .style(Style::default().fg(theme.palette.text_primary()))
        .render(inner, frame);
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

fn frame_render_screen(model: &DashboardModel, theme: &Theme, area: Rect, frame: &mut Frame) {
    match model.screen {
        Screen::Overview => frame_render_overview(model, theme, area, frame),
        Screen::Timeline => frame_render_timeline(model, theme, area, frame),
        Screen::Explainability => frame_render_explainability(model, theme, area, frame),
        Screen::Candidates => frame_render_candidates(model, theme, area, frame),
        Screen::Ballast => frame_render_ballast(model, theme, area, frame),
        Screen::LogSearch => frame_render_log_search(model, theme, area, frame),
        Screen::Diagnostics => frame_render_diagnostics(model, theme, area, frame),
    }
}

fn frame_render_overview(model: &DashboardModel, theme: &Theme, area: Rect, frame: &mut Frame) {
    let layout = build_overview_layout(area.width, area.height);
    for placement in layout.placements.iter().filter(|p| p.visible) {
        let pane_area = rect_in_body(area, placement.rect);
        if pane_area.width < 2 || pane_area.height < 2 {
            continue;
        }
        frame_render_overview_card(model, theme, placement.pane, pane_area, frame);
    }
}

fn rect_in_body(body: Rect, pane: crate::tui::layout::PaneRect) -> Rect {
    let x = body.x.saturating_add(pane.col);
    let y = body.y.saturating_add(pane.row);
    let body_right = body.x.saturating_add(body.width);
    let body_bottom = body.y.saturating_add(body.height);
    if x >= body_right || y >= body_bottom {
        return Rect::new(body.x, body.y, 0, 0);
    }
    let max_w = body_right.saturating_sub(x);
    let max_h = body_bottom.saturating_sub(y);
    Rect::new(x, y, pane.width.min(max_w), pane.height.min(max_h))
}

fn frame_render_overview_card(
    model: &DashboardModel,
    theme: &Theme,
    pane: OverviewPane,
    area: Rect,
    frame: &mut Frame,
) {
    let border_color = if model.overview_focus_pane == pane {
        theme.palette.accent_color()
    } else if model.overview_hover_pane == Some(pane) {
        theme.palette.warning_color()
    } else {
        theme.palette.border_color()
    };

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .title(overview_pane_title(pane))
        .border_style(Style::default().fg(border_color))
        .style(Style::default().bg(theme.palette.panel_bg()));
    let inner = block.inner(area);
    block.render(area, frame);

    if inner.height == 0 || inner.width == 0 {
        return;
    }
    let show_target_hint = (model.overview_focus_pane == pane
        || model.overview_hover_pane == Some(pane))
        && model.hint_verbosity != HintVerbosity::Off;
    let content = overview_pane_styled(model, theme, pane, inner.width, show_target_hint);
    Paragraph::new(content)
        .style(Style::default().fg(theme.palette.text_secondary()))
        .render(inner, frame);
}

fn overview_pane_title(pane: OverviewPane) -> &'static str {
    match pane {
        OverviewPane::PressureSummary => "Pressure Matrix",
        OverviewPane::ForecastHorizon => "Forecast Horizon",
        OverviewPane::ActionLane => "Action Rail",
        OverviewPane::EwmaTrend => "Trend Lattice",
        OverviewPane::DecisionPulse => "Decision Pulse",
        OverviewPane::CandidateHotlist => "Candidate Hotlist",
        OverviewPane::BallastQuick => "Ballast Fleet",
        OverviewPane::SpecialLocations => "Special Locations",
        OverviewPane::ExtendedCounters => "Runtime Counters",
    }
}

fn overview_pane_text(
    model: &DashboardModel,
    theme: &Theme,
    pane: OverviewPane,
    pane_width: u16,
    show_target_hint: bool,
) -> String {
    let base = match pane {
        OverviewPane::PressureSummary => render_pressure_summary(model, theme, pane_width),
        OverviewPane::ForecastHorizon => render_forecast_horizon(model, theme),
        OverviewPane::ActionLane => render_action_lane(model),
        OverviewPane::EwmaTrend => render_ewma_trend(model),
        OverviewPane::DecisionPulse => render_decision_pulse(model, theme),
        OverviewPane::CandidateHotlist => render_candidate_hotlist(model, theme, pane_width),
        OverviewPane::BallastQuick => render_ballast_quick(model, theme),
        OverviewPane::SpecialLocations => render_special_locations(model, theme),
        OverviewPane::ExtendedCounters => render_extended_counters(model),
    };
    if show_target_hint {
        format!(
            "{base}\n  -> Enter/Space/click opens {}",
            overview_pane_target_label(pane)
        )
    } else {
        base
    }
}

/// Styled version of overview pane content, returning `Text` with colored spans.
fn overview_pane_styled(
    model: &DashboardModel,
    theme: &Theme,
    pane: OverviewPane,
    pane_width: u16,
    show_target_hint: bool,
) -> Text {
    let mut lines = match pane {
        OverviewPane::PressureSummary => styled_pressure_summary(model, theme, pane_width),
        OverviewPane::ForecastHorizon => styled_forecast_horizon(model, theme),
        OverviewPane::EwmaTrend => styled_ewma_trend(model, theme),
        OverviewPane::DecisionPulse => styled_decision_pulse(model, theme),
        OverviewPane::CandidateHotlist => styled_candidate_hotlist(model, theme, pane_width),
        OverviewPane::BallastQuick => styled_ballast_quick(model, theme),
        _ => {
            // Fallback: use plain text rendering for remaining panes.
            let plain = overview_pane_text(model, theme, pane, pane_width, false);
            plain.lines().map(|l| Line::from(l.to_string())).collect()
        }
    };
    if show_target_hint {
        lines.push(Line::from_spans([
            Span::styled(
                "  \u{2192} ",
                Style::default().fg(theme.palette.muted_color()),
            ),
            Span::styled(
                format!("Enter/Space opens {}", overview_pane_target_label(pane)),
                Style::default().fg(theme.palette.text_secondary()),
            ),
        ]));
    }
    Text::from_lines(lines)
}

#[allow(clippy::option_if_let_else)]
fn styled_pressure_summary(model: &DashboardModel, theme: &Theme, pane_width: u16) -> Vec<Line> {
    if let Some(ref state) = model.daemon_state {
        let mut lines = Vec::new();
        let level_color = theme.palette.pressure_color(&state.pressure.overall);

        // Header line with styled badge.
        let mut header = vec![
            Span::styled(
                "pressure ",
                Style::default().fg(theme.palette.text_secondary()),
            ),
            styled_badge(&state.pressure.overall.to_ascii_uppercase(), level_color),
        ];
        if !state.policy_mode.is_empty() {
            let policy_color = policy_mode_color(&state.policy_mode, &theme.palette);
            header.push(Span::raw(" "));
            header.push(styled_badge(
                &state.policy_mode.to_ascii_uppercase(),
                policy_color,
            ));
        }
        lines.push(Line::from_spans(header));

        // Mount rows with segmented gauges.
        let gauge_w = gauge_width_for(pane_width).max(8);
        for mount in &state.pressure.mounts {
            let used_pct = 100.0 - mount.free_pct;
            let mount_path = truncate_path(&mount.path, 16);
            let mut row = vec![Span::styled(
                format!("  {mount_path:<16} "),
                Style::default().fg(theme.palette.text_secondary()),
            )];
            row.extend(segmented_gauge(used_pct, gauge_w, &theme.palette));

            let rate_str = mount.rate_bps.map_or_else(String::new, |r| {
                let s = human_rate(r);
                if r > 0.0 {
                    format!(" {s} \u{26a0}")
                } else {
                    format!(" {s}")
                }
            });
            if !rate_str.is_empty() {
                let rate_color = if mount.rate_bps.is_some_and(|r| r > 0.0) {
                    theme.palette.warning_color()
                } else {
                    theme.palette.text_secondary()
                };
                row.push(Span::styled(rate_str, Style::default().fg(rate_color)));
            }
            lines.push(Line::from_spans(row));
        }
        lines
    } else {
        let plain = render_pressure_summary(model, theme, pane_width);
        plain.lines().map(|l| Line::from(l.to_string())).collect()
    }
}

fn styled_forecast_horizon(model: &DashboardModel, theme: &Theme) -> Vec<Line> {
    if let Some(ref state) = model.daemon_state {
        let worst = state
            .pressure
            .mounts
            .iter()
            .min_by(|a, b| a.free_pct.total_cmp(&b.free_pct));
        if let Some(worst) = worst {
            let level_color = theme.palette.pressure_color(&worst.level);
            let eta = worst.rate_bps.and_then(|rate| {
                if rate <= 0.0 || worst.free_pct <= 0.0 {
                    None
                } else {
                    let bytes_left = (worst.free_pct / 100.0) * 100.0 * 1024.0 * 1024.0 * 1024.0;
                    Some((bytes_left / rate).max(0.0))
                }
            });
            let eta_str = eta.map_or_else(|| "N/A".to_string(), eta_label);
            let urgency_color = if worst.free_pct < 10.0 {
                theme.palette.danger_color()
            } else if worst.free_pct < 25.0 {
                theme.palette.warning_color()
            } else {
                theme.palette.success_color()
            };

            return vec![
                Line::from_spans([
                    Span::styled(
                        "forecast ",
                        Style::default().fg(theme.palette.text_secondary()),
                    ),
                    styled_badge(&worst.level.to_ascii_uppercase(), level_color),
                ]),
                Line::from_spans([
                    Span::styled(
                        "  worst=",
                        Style::default().fg(theme.palette.text_secondary()),
                    ),
                    Span::styled(
                        &*worst.path,
                        Style::default().fg(theme.palette.text_primary()),
                    ),
                ]),
                Line::from_spans([
                    Span::styled(
                        format!("  free={:.1}%", worst.free_pct),
                        Style::default().fg(urgency_color),
                    ),
                    Span::styled(
                        format!("  eta\u{2248}{eta_str}"),
                        Style::default().fg(urgency_color).bold(),
                    ),
                ]),
            ];
        }
    }
    vec![Line::from(Span::styled(
        "forecast awaiting daemon trend inputs",
        Style::default().fg(theme.palette.muted_color()),
    ))]
}

fn styled_ewma_trend(model: &DashboardModel, theme: &Theme) -> Vec<Line> {
    if model.rate_histories.is_empty() {
        return vec![Line::from(Span::styled(
            "ewma no rate data",
            Style::default().fg(theme.palette.muted_color()),
        ))];
    }

    let mut sorted: Vec<_> = model.rate_histories.iter().collect();
    sorted.sort_unstable_by(|a, b| a.0.cmp(b.0));

    let mut lines = vec![Line::from(Span::styled(
        format!("ewma {} mounts", sorted.len()),
        Style::default().fg(theme.palette.text_secondary()),
    ))];

    for (path, history) in &sorted {
        let normalized = history.normalized();
        let latest = history.latest().unwrap_or(0.0);
        let rate_str = human_rate(latest);
        let trend = trend_label(latest);

        let mut row: Vec<Span> = vec![Span::styled(
            format!("  {path:<14} "),
            Style::default().fg(theme.palette.text_secondary()),
        )];
        // Colored sparkline instead of monochrome.
        row.extend(colored_sparkline(&normalized, &theme.palette));
        let rate_color = if latest > 1_000_000.0 {
            theme.palette.danger_color()
        } else if latest > 0.0 {
            theme.palette.warning_color()
        } else {
            theme.palette.success_color()
        };
        row.push(Span::styled(
            format!(" {rate_str} {trend}"),
            Style::default().fg(rate_color),
        ));
        if latest > 1_000_000.0 {
            row.push(Span::styled(
                " \u{26a0}",
                Style::default().fg(theme.palette.danger_color()),
            ));
        }
        lines.push(Line::from_spans(row));
    }
    lines
}

fn styled_decision_pulse(model: &DashboardModel, theme: &Theme) -> Vec<Line> {
    if model.explainability_decisions.is_empty() {
        return vec![Line::from(Span::styled(
            "decision-pulse no evidence loaded yet",
            Style::default().fg(theme.palette.muted_color()),
        ))];
    }
    let total = model.explainability_decisions.len();
    let total_u32 = u32::try_from(total).unwrap_or(u32::MAX);
    let vetoed = model
        .explainability_decisions
        .iter()
        .filter(|d| d.vetoed)
        .count();
    let avg = model
        .explainability_decisions
        .iter()
        .map(|d| d.total_score)
        .sum::<f64>()
        / f64::from(total_u32.max(1));

    let (badge_label, badge_color) = if vetoed > 0 {
        ("VETOES", theme.palette.warning_color())
    } else {
        ("CLEAR", theme.palette.success_color())
    };

    vec![
        Line::from_spans([
            Span::styled(
                "decision-pulse ",
                Style::default().fg(theme.palette.text_secondary()),
            ),
            styled_badge(badge_label, badge_color),
        ]),
        Line::from_spans([
            Span::styled(
                "  decisions=",
                Style::default().fg(theme.palette.text_secondary()),
            ),
            styled_badge(&total.to_string(), theme.palette.accent_color()),
            Span::styled(
                "  vetoed=",
                Style::default().fg(theme.palette.text_secondary()),
            ),
            styled_badge(
                &vetoed.to_string(),
                if vetoed > 0 {
                    theme.palette.warning_color()
                } else {
                    theme.palette.success_color()
                },
            ),
            Span::styled(
                format!("  avg={avg:.2}"),
                Style::default().fg(theme.palette.text_secondary()),
            ),
        ]),
    ]
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn styled_candidate_hotlist(model: &DashboardModel, theme: &Theme, pane_width: u16) -> Vec<Line> {
    if model.candidates_list.is_empty() {
        return vec![Line::from(Span::styled(
            "hotlist no candidate ranking loaded yet",
            Style::default().fg(theme.palette.muted_color()),
        ))];
    }
    let pane_w = usize::from(pane_width);
    let path_w = pane_w.saturating_sub(36).clamp(12, 46);
    let mut lines = vec![Line::from(Span::styled(
        format!("hotlist total={}", model.candidates_list.len()),
        Style::default().fg(theme.palette.text_secondary()),
    ))];

    for (idx, candidate) in model.candidates_list.iter().take(5).enumerate() {
        let (badge_label, badge_color) = if candidate.total_score >= 0.8 {
            ("HOT", theme.palette.critical_color())
        } else if candidate.total_score >= 0.6 {
            ("WARM", theme.palette.warning_color())
        } else {
            ("MILD", theme.palette.accent_color())
        };
        let cursor_char = if idx == model.candidates_selected {
            "\u{25B8}"
        } else {
            " "
        };
        let cursor_color = if idx == model.candidates_selected {
            theme.palette.accent_color()
        } else {
            theme.palette.muted_color()
        };
        let score_color = theme.palette.gauge_gradient(candidate.total_score);
        let mut row = vec![
            Span::styled(
                format!("{cursor_char} {:>2}.", idx + 1),
                Style::default().fg(cursor_color),
            ),
            Span::raw(" "),
            mini_bar_chart(candidate.total_score, score_color),
            Span::styled(
                format!(" {:.2}", candidate.total_score),
                Style::default().fg(score_color),
            ),
            Span::raw(" "),
            styled_badge(badge_label, badge_color),
            Span::styled(
                format!(" {:>8} ", human_bytes(candidate.size_bytes)),
                Style::default().fg(theme.palette.text_secondary()),
            ),
            Span::styled(
                truncate_path(&candidate.path, path_w),
                Style::default().fg(theme.palette.text_primary()),
            ),
        ];
        if candidate.vetoed {
            row.push(Span::styled(
                " VETO",
                Style::default().fg(theme.palette.danger_color()).bold(),
            ));
        }
        lines.push(Line::from_spans(row));
    }
    lines
}

#[allow(clippy::option_if_let_else)]
fn styled_ballast_quick(model: &DashboardModel, theme: &Theme) -> Vec<Line> {
    if let Some(ref state) = model.daemon_state {
        let (badge_label, badge_color) = if state.ballast.total > 0 && state.ballast.available == 0
        {
            ("CRITICAL", theme.palette.critical_color())
        } else if state.ballast.available.saturating_mul(2) < state.ballast.total {
            ("LOW", theme.palette.warning_color())
        } else {
            ("OK", theme.palette.success_color())
        };

        let ratio = if state.ballast.total > 0 {
            #[allow(clippy::cast_precision_loss)]
            let pct = (state.ballast.available as f64 / state.ballast.total as f64) * 100.0;
            pct
        } else {
            0.0
        };

        vec![
            Line::from_spans([
                Span::styled(
                    "ballast ",
                    Style::default().fg(theme.palette.text_secondary()),
                ),
                styled_badge(badge_label, badge_color),
            ]),
            Line::from_spans([Span::styled(
                format!(
                    "  available={}/{} released={}",
                    state.ballast.available, state.ballast.total, state.ballast.released,
                ),
                Style::default().fg(theme.palette.text_secondary()),
            )]),
            {
                let gauge_w = 20;
                let mut row = vec![Span::styled(
                    "  ",
                    Style::default().fg(theme.palette.text_secondary()),
                )];
                row.extend(segmented_gauge(100.0 - ratio, gauge_w, &theme.palette));
                Line::from_spans(row)
            },
        ]
    } else {
        vec![Line::from_spans([
            Span::styled(
                "ballast ",
                Style::default().fg(theme.palette.text_secondary()),
            ),
            styled_badge("UNKNOWN", theme.palette.muted_color()),
            Span::styled(
                " unavailable",
                Style::default().fg(theme.palette.muted_color()),
            ),
        ])]
    }
}

fn overview_pane_target_label(pane: OverviewPane) -> &'static str {
    match pane {
        OverviewPane::ActionLane | OverviewPane::DecisionPulse => "Explainability",
        OverviewPane::CandidateHotlist => "Candidates",
        OverviewPane::BallastQuick => "Ballast",
        OverviewPane::ExtendedCounters => "Diagnostics",
        OverviewPane::PressureSummary
        | OverviewPane::ForecastHorizon
        | OverviewPane::EwmaTrend
        | OverviewPane::SpecialLocations => "Timeline",
    }
}

fn frame_render_text_pane(
    theme: &Theme,
    area: Rect,
    title: &str,
    content: String,
    emphasis: bool,
    frame: &mut Frame,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    if area.height < 3 || area.width < 6 {
        Paragraph::new(content)
            .style(Style::default().fg(theme.palette.text_primary()))
            .render(area, frame);
        return;
    }

    let border_color = if emphasis {
        theme.palette.accent_color()
    } else {
        theme.palette.border_color()
    };
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .title(title)
        .border_style(Style::default().fg(border_color))
        .style(Style::default().bg(theme.palette.panel_bg()));
    let inner = block.inner(area);
    block.render(area, frame);
    Paragraph::new(content)
        .style(Style::default().fg(theme.palette.text_secondary()))
        .render(inner, frame);
}

fn frame_render_styled_pane(
    theme: &Theme,
    area: Rect,
    title: &str,
    content: Text,
    emphasis: bool,
    frame: &mut Frame,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    if area.height < 3 || area.width < 6 {
        Paragraph::new(content)
            .style(Style::default().fg(theme.palette.text_primary()))
            .render(area, frame);
        return;
    }

    let border_color = if emphasis {
        theme.palette.accent_color()
    } else {
        theme.palette.border_color()
    };
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .title(title)
        .border_style(Style::default().fg(border_color))
        .style(Style::default().bg(theme.palette.panel_bg()));
    let inner = block.inner(area);
    block.render(area, frame);
    Paragraph::new(content)
        .style(Style::default().fg(theme.palette.text_secondary()))
        .render(inner, frame);
}

fn frame_render_status_strip(theme: &Theme, area: Rect, content: String, frame: &mut Frame) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    Paragraph::new(content)
        .style(
            Style::default()
                .fg(theme.palette.muted_color())
                .bg(theme.palette.panel_bg()),
        )
        .render(area, frame);
}

fn pane_body_rows(area: Rect) -> usize {
    usize::from(area.height.saturating_sub(2).max(1))
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

const fn data_source_label(source: DataSource) -> &'static str {
    match source {
        DataSource::Sqlite => "SQLite",
        DataSource::Jsonl => "JSONL",
        DataSource::None => "none",
    }
}

fn frame_render_timeline(model: &DashboardModel, theme: &Theme, area: Rect, frame: &mut Frame) {
    let layout = build_timeline_layout(area.width, area.height);
    for placement in layout.placements.iter().filter(|p| p.visible) {
        let pane_area = rect_in_body(area, placement.rect);
        if pane_area.width == 0 || pane_area.height == 0 {
            continue;
        }
        match placement.pane {
            TimelinePane::FilterBar => frame_render_text_pane(
                theme,
                pane_area,
                "S2 Filters",
                frame_timeline_filter_text(model),
                false,
                frame,
            ),
            TimelinePane::EventList => frame_render_text_pane(
                theme,
                pane_area,
                "S2 Timeline Events",
                frame_timeline_list_text(model, theme, pane_body_rows(pane_area)),
                true,
                frame,
            ),
            TimelinePane::EventDetail => frame_render_text_pane(
                theme,
                pane_area,
                "S2 Event Detail",
                frame_timeline_detail_text(model, theme),
                true,
                frame,
            ),
            TimelinePane::StatusFooter => frame_render_status_strip(
                theme,
                pane_area,
                String::from(
                    "j/k or wheel scroll  f filter  F follow  r refresh  Esc overlay->detail->back->quit",
                ),
                frame,
            ),
        }
    }
}

fn frame_timeline_filter_text(model: &DashboardModel) -> String {
    let follow = if model.timeline_follow { "on" } else { "off" };
    format!(
        "severity={}  follow={}  source={}  partial={}",
        model.timeline_filter.label(),
        follow,
        data_source_label(model.timeline_source),
        model.timeline_partial,
    )
}

fn frame_timeline_list_text(model: &DashboardModel, theme: &Theme, rows: usize) -> String {
    use std::fmt::Write as _;
    let filtered = model.timeline_filtered_events();
    let total = model.timeline_events.len();
    if filtered.is_empty() {
        return format!(
            "No events available for filter={}.\nPress f to cycle severity filters.",
            model.timeline_filter.label()
        );
    }

    let mut out = String::new();
    let (start, end) = centered_window(model.timeline_selected, filtered.len(), rows);
    let _ = writeln!(
        out,
        "events={} of {} (rows {}..{})",
        filtered.len(),
        total,
        start + 1,
        end
    );
    for (offset, event) in filtered[start..end].iter().enumerate() {
        let idx = start + offset;
        let cursor = if idx == model.timeline_selected {
            "\u{25B8}"
        } else {
            " "
        };
        render_event_row(cursor, event, theme, &mut out);
    }
    out
}

fn frame_timeline_detail_text(model: &DashboardModel, theme: &Theme) -> String {
    let mut out = String::new();
    if let Some(event) = model.timeline_selected_event() {
        render_event_detail(event, theme, &mut out);
    } else {
        out.push_str("No selected event.");
    }
    out
}

fn frame_render_explainability(
    model: &DashboardModel,
    theme: &Theme,
    area: Rect,
    frame: &mut Frame,
) {
    let layout = build_explainability_layout(area.width, area.height);
    for placement in layout.placements.iter().filter(|p| p.visible) {
        let pane_area = rect_in_body(area, placement.rect);
        if pane_area.width == 0 || pane_area.height == 0 {
            continue;
        }
        match placement.pane {
            ExplainabilityPane::DecisionHeader => frame_render_text_pane(
                theme,
                pane_area,
                "S3 Decision Header",
                frame_explainability_header_text(model),
                false,
                frame,
            ),
            ExplainabilityPane::FactorBreakdown => frame_render_text_pane(
                theme,
                pane_area,
                "S3 Decisions",
                frame_explainability_list_text(model, theme, pane_body_rows(pane_area)),
                true,
                frame,
            ),
            ExplainabilityPane::VetoDetail => frame_render_text_pane(
                theme,
                pane_area,
                "S3 Detail / Veto",
                frame_explainability_detail_text(model, theme, pane_area.width),
                true,
                frame,
            ),
            ExplainabilityPane::StatusFooter => frame_render_status_strip(
                theme,
                pane_area,
                String::from(
                    "j/k or wheel scroll  click row opens detail  Enter/Space toggle detail  d close  Esc overlay->detail->back->quit",
                ),
                frame,
            ),
        }
    }
}

fn frame_explainability_header_text(model: &DashboardModel) -> String {
    use std::fmt::Write as _;
    let mut out = format!(
        "source={} partial={} decisions={} selected={}",
        data_source_label(model.explainability_source),
        model.explainability_partial,
        model.explainability_decisions.len(),
        model.explainability_selected.saturating_add(1),
    );
    if let Some(state) = &model.daemon_state {
        let _ = write!(
            out,
            "\npressure={} policy={} scans={} deletions={}",
            state.pressure.overall,
            state.policy_mode,
            state.counters.scans,
            state.counters.deletions
        );
    }
    if !model.explainability_diagnostics.is_empty() {
        let _ = write!(out, "\ndiag={}", model.explainability_diagnostics);
    }
    out
}

fn frame_explainability_list_text(model: &DashboardModel, theme: &Theme, rows: usize) -> String {
    use std::fmt::Write as _;
    if model.explainability_decisions.is_empty() {
        return String::from("No decision evidence loaded.");
    }
    let mut out = String::new();
    let total = model.explainability_decisions.len();
    let (start, end) = centered_window(model.explainability_selected, total, rows);
    for idx in start..end {
        let decision = &model.explainability_decisions[idx];
        let cursor = if idx == model.explainability_selected {
            "\u{25B8}"
        } else {
            " "
        };
        let veto_marker = if decision.vetoed { " VETO" } else { "" };
        let _ = writeln!(
            out,
            "{cursor} #{:<4} {} {} score={:.2} P(abn)={:.2}{}",
            decision.decision_id,
            extract_time(&decision.timestamp),
            action_badge(&decision.action, theme),
            decision.total_score,
            decision.posterior_abandoned,
            veto_marker,
        );
    }
    out
}

fn frame_explainability_detail_text(
    model: &DashboardModel,
    theme: &Theme,
    pane_width: u16,
) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    if let Some(decision) = model.explainability_selected_decision() {
        if model.explainability_detail {
            render_decision_detail(decision, theme, usize::from(pane_width).max(40), &mut out);
        } else {
            let _ = writeln!(out, "path={}", decision.path);
            let _ = writeln!(out, "action={}", decision.action);
            let _ = writeln!(out, "score={:.3}", decision.total_score);
            let _ = writeln!(out, "posterior={:.3}", decision.posterior_abandoned);
            let _ = writeln!(out, "calibration={:.3}", decision.calibration_score);
            if decision.vetoed
                && let Some(reason) = &decision.veto_reason
            {
                let _ = writeln!(out, "veto={reason}");
            }
            let _ = writeln!(out, "Enter/Space for full detail");
        }
    } else {
        out.push_str("No selected decision.");
    }
    out
}

fn frame_render_candidates(model: &DashboardModel, theme: &Theme, area: Rect, frame: &mut Frame) {
    let layout = build_candidates_layout(area.width, area.height);
    for placement in layout.placements.iter().filter(|p| p.visible) {
        let pane_area = rect_in_body(area, placement.rect);
        if pane_area.width == 0 || pane_area.height == 0 {
            continue;
        }
        match placement.pane {
            CandidatesPane::SummaryBar => frame_render_text_pane(
                theme,
                pane_area,
                "S4 Summary",
                frame_candidates_summary_text(model),
                false,
                frame,
            ),
            CandidatesPane::CandidateList => frame_render_text_pane(
                theme,
                pane_area,
                "S4 Candidate Ranking",
                frame_candidates_list_text(model, theme, pane_body_rows(pane_area)),
                true,
                frame,
            ),
            CandidatesPane::ScoreDetail => frame_render_text_pane(
                theme,
                pane_area,
                "S4 Score Detail",
                frame_candidates_detail_text(model, theme, pane_area.width),
                true,
                frame,
            ),
            CandidatesPane::StatusFooter => frame_render_status_strip(
                theme,
                pane_area,
                String::from(
                    "j/k or wheel scroll  click row opens detail  Enter/Space toggle detail  s sort  d close  Esc overlay->detail->back->quit",
                ),
                frame,
            ),
        }
    }
}

fn frame_candidates_summary_text(model: &DashboardModel) -> String {
    use std::fmt::Write as _;
    let mut out = format!(
        "source={} partial={} candidates={} sort={}",
        data_source_label(model.candidates_source),
        model.candidates_partial,
        model.candidates_list.len(),
        model.candidates_sort.label(),
    );
    let reclaimable: u64 = model
        .candidates_list
        .iter()
        .filter(|c| !c.vetoed && c.action == "delete")
        .map(|c| c.size_bytes)
        .sum();
    let _ = write!(out, "\nreclaimable={}", human_bytes(reclaimable));
    if !model.candidates_diagnostics.is_empty() {
        let _ = write!(out, "\ndiag={}", model.candidates_diagnostics);
    }
    out
}

fn frame_candidates_list_text(model: &DashboardModel, theme: &Theme, rows: usize) -> String {
    use std::fmt::Write as _;
    if model.candidates_list.is_empty() {
        return String::from("No candidates loaded.");
    }
    let mut out = String::new();
    let total = model.candidates_list.len();
    let (start, end) = centered_window(model.candidates_selected, total, rows);
    for idx in start..end {
        let candidate = &model.candidates_list[idx];
        let cursor = if idx == model.candidates_selected {
            "\u{25B8}"
        } else {
            " "
        };
        let veto = if candidate.vetoed { "VETO" } else { "-" };
        let _ = writeln!(
            out,
            "{cursor} #{:<4} {} score={:.2} size={} age={} {}",
            candidate.decision_id,
            action_badge(&candidate.action, theme),
            candidate.total_score,
            human_bytes(candidate.size_bytes),
            human_duration(candidate.age_secs),
            veto,
        );
    }
    out
}

fn frame_candidates_detail_text(model: &DashboardModel, theme: &Theme, pane_width: u16) -> String {
    let mut out = String::new();
    if let Some(candidate) = model.candidates_selected_item() {
        if model.candidates_detail {
            render_candidate_detail(candidate, theme, usize::from(pane_width).max(40), &mut out);
        } else {
            out = format!(
                "path={}\naction={}\nscore={:.3}\nsize={}\nage={}\nEnter/Space for full detail",
                candidate.path,
                candidate.action,
                candidate.total_score,
                human_bytes(candidate.size_bytes),
                human_duration(candidate.age_secs),
            );
        }
    } else {
        out.push_str("No selected candidate.");
    }
    out
}

fn frame_render_ballast(model: &DashboardModel, theme: &Theme, area: Rect, frame: &mut Frame) {
    let layout = build_ballast_layout(area.width, area.height);
    for placement in layout.placements.iter().filter(|p| p.visible) {
        let pane_area = rect_in_body(area, placement.rect);
        if pane_area.width == 0 || pane_area.height == 0 {
            continue;
        }
        match placement.pane {
            BallastPane::VolumeList => frame_render_text_pane(
                theme,
                pane_area,
                "S5 Volume Inventory",
                frame_ballast_list_text(model, theme, pane_body_rows(pane_area)),
                true,
                frame,
            ),
            BallastPane::VolumeDetail => frame_render_text_pane(
                theme,
                pane_area,
                "S5 Volume Detail",
                frame_ballast_detail_text(model, theme),
                true,
                frame,
            ),
            BallastPane::StatusFooter => frame_render_status_strip(
                theme,
                pane_area,
                String::from(
                    "j/k or wheel scroll  click row opens detail  Enter/Space toggle detail  d close  Esc overlay->detail->back->quit",
                ),
                frame,
            ),
        }
    }
}

fn frame_ballast_list_text(model: &DashboardModel, theme: &Theme, rows: usize) -> String {
    use std::fmt::Write as _;
    if model.ballast_volumes.is_empty() {
        return String::from("No ballast inventory loaded.");
    }
    let mut out = String::new();
    let total = model.ballast_volumes.len();
    let (start, end) = centered_window(model.ballast_selected, total, rows);
    for idx in start..end {
        let vol = &model.ballast_volumes[idx];
        let cursor = if idx == model.ballast_selected {
            "\u{25B8}"
        } else {
            " "
        };
        let status = vol.status_level();
        let status_color = match status {
            "OK" => theme.palette.success,
            "LOW" => theme.palette.warning,
            "CRITICAL" => theme.palette.critical,
            _ => theme.palette.muted,
        };
        let _ = writeln!(
            out,
            "{cursor} {} {:<18} files={}/{} releasable={}",
            status_badge(status, status_color, theme.accessibility),
            truncate_path(&vol.mount_point, 18),
            vol.files_available,
            vol.files_total,
            human_bytes(vol.releasable_bytes),
        );
    }
    out
}

fn frame_ballast_detail_text(model: &DashboardModel, theme: &Theme) -> String {
    let mut out = String::new();
    if let Some(vol) = model.ballast_selected_volume() {
        if model.ballast_detail {
            render_volume_detail(vol, theme, &mut out);
        } else {
            out = format!(
                "mount={}\nstatus={}\nfiles={}/{}\nreleasable={}\nEnter/Space for full detail",
                vol.mount_point,
                vol.status_level(),
                vol.files_available,
                vol.files_total,
                human_bytes(vol.releasable_bytes),
            );
        }
    } else {
        out.push_str("No selected volume.");
    }
    out
}

fn frame_render_log_search(model: &DashboardModel, theme: &Theme, area: Rect, frame: &mut Frame) {
    let layout = build_log_search_layout(area.width, area.height);
    for placement in layout.placements.iter().filter(|p| p.visible) {
        let pane_area = rect_in_body(area, placement.rect);
        if pane_area.width == 0 || pane_area.height == 0 {
            continue;
        }
        match placement.pane {
            LogSearchPane::SearchBar => frame_render_text_pane(
                theme,
                pane_area,
                "S6 Log Search",
                frame_log_search_header_text(model),
                false,
                frame,
            ),
            LogSearchPane::LogList => frame_render_text_pane(
                theme,
                pane_area,
                "S6 Entries",
                frame_log_search_list_text(model, theme, pane_body_rows(pane_area)),
                true,
                frame,
            ),
            LogSearchPane::EntryDetail => frame_render_text_pane(
                theme,
                pane_area,
                "S6 Entry Detail",
                frame_log_search_detail_text(model, theme),
                true,
                frame,
            ),
            LogSearchPane::StatusFooter => frame_render_status_strip(
                theme,
                pane_area,
                String::from(
                    "mouse wheel scrolls entries  click row focuses entry  Esc overlay->back->quit",
                ),
                frame,
            ),
        }
    }
}

fn frame_log_search_header_text(model: &DashboardModel) -> String {
    format!(
        "query=<not-yet-editable>  source={}  timeline-events={}  mode=preview",
        data_source_label(model.timeline_source),
        model.timeline_events.len(),
    )
}

fn frame_log_entries(model: &DashboardModel) -> Vec<&TimelineEvent> {
    model.timeline_events.iter().collect()
}

fn frame_log_search_list_text(model: &DashboardModel, theme: &Theme, rows: usize) -> String {
    use std::fmt::Write as _;
    let entries = frame_log_entries(model);
    if entries.is_empty() {
        return String::from("No log entries loaded. Timeline telemetry powers this preview.");
    }
    let mut out = String::new();
    let selected = model.timeline_selected.min(entries.len().saturating_sub(1));
    let (start, end) = centered_window(selected, entries.len(), rows);
    for (idx, event) in entries.iter().enumerate().take(end).skip(start) {
        let event = *event;
        let cursor = if idx == selected { "\u{25B8}" } else { " " };
        let _ = writeln!(
            out,
            "{cursor} {} {} {:<18} {}",
            extract_time(&event.timestamp),
            severity_badge(&event.severity, theme),
            event.event_type,
            event.path.as_deref().map_or("-", |p| truncate_path(p, 24)),
        );
    }
    out
}

fn frame_log_search_detail_text(model: &DashboardModel, theme: &Theme) -> String {
    let entries = frame_log_entries(model);
    let mut out = String::new();
    if entries.is_empty() {
        out.push_str("No selected entry.");
        return out;
    }
    let selected = model.timeline_selected.min(entries.len().saturating_sub(1));
    render_event_detail(entries[selected], theme, &mut out);
    out
}

fn frame_render_diagnostics(model: &DashboardModel, theme: &Theme, area: Rect, frame: &mut Frame) {
    let layout = build_diagnostics_layout(area.width, area.height);
    for placement in layout.placements.iter().filter(|p| p.visible) {
        let pane_area = rect_in_body(area, placement.rect);
        if pane_area.width == 0 || pane_area.height == 0 {
            continue;
        }
        match placement.pane {
            DiagnosticsPane::HealthHeader => frame_render_text_pane(
                theme,
                pane_area,
                "S7 Health",
                frame_diagnostics_health_text(model),
                false,
                frame,
            ),
            DiagnosticsPane::ThreadTable => frame_render_text_pane(
                theme,
                pane_area,
                "S7 Runtime/Adapters",
                frame_diagnostics_runtime_text(model),
                true,
                frame,
            ),
            DiagnosticsPane::PerfPanel => frame_render_styled_pane(
                theme,
                pane_area,
                "S7 Performance",
                frame_diagnostics_perf_styled(model, theme),
                true,
                frame,
            ),
            DiagnosticsPane::StatusFooter => frame_render_status_strip(
                theme,
                pane_area,
                format!(
                    "Shift-V verbose={}  r refresh  Esc overlay->back->quit",
                    if model.diagnostics_verbose {
                        "on"
                    } else {
                        "off"
                    }
                ),
                frame,
            ),
        }
    }
}

fn frame_diagnostics_health_text(model: &DashboardModel) -> String {
    use std::fmt::Write as _;
    let mut out = format!(
        "mode={} tick={} refresh={}ms missed={}",
        if model.degraded { "degraded" } else { "normal" },
        model.tick,
        model.refresh.as_millis(),
        model.missed_ticks,
    );
    let fetch_age = model.last_fetch.map_or_else(
        || String::from("never"),
        |t| format!("{}ms", t.elapsed().as_millis()),
    );
    let _ = write!(
        out,
        "\nlast-fetch={} notifications={}",
        fetch_age,
        model.notifications.len()
    );
    if let Some(state) = &model.daemon_state {
        let _ = write!(
            out,
            "\npolicy={} pressure={} pid={} rss={}",
            state.policy_mode,
            state.pressure.overall,
            state.pid,
            human_bytes(state.memory_rss_bytes),
        );
    }
    out
}

fn frame_diagnostics_runtime_text(model: &DashboardModel) -> String {
    use std::fmt::Write as _;
    let mut out = format!(
        "adapter reads={} errors={}",
        model.adapter_reads, model.adapter_errors
    );
    if let Some(state) = &model.daemon_state {
        let _ = write!(
            out,
            "\nscans={} deletions={} errors={} dropped={}",
            state.counters.scans,
            state.counters.deletions,
            state.counters.errors,
            state.counters.dropped_log_events,
        );
    }
    let _ = write!(
        out,
        "\ntimeline={} explain={} candidates={} ballast={}",
        data_source_label(model.timeline_source),
        data_source_label(model.explainability_source),
        data_source_label(model.candidates_source),
        data_source_label(model.ballast_source),
    );
    if model.diagnostics_verbose {
        let _ = write!(
            out,
            "\nscreen={} history={} events={} decisions={} candidates={}",
            screen_label(model.screen),
            model.screen_history.len(),
            model.timeline_events.len(),
            model.explainability_decisions.len(),
            model.candidates_list.len(),
        );
    }
    out
}

fn frame_diagnostics_perf_styled(model: &DashboardModel, theme: &Theme) -> Text {
    let mut lines = Vec::new();
    if let Some((current, avg, min, max)) = model.frame_time_stats() {
        let current_color = if current > 16.0 {
            theme.palette.danger_color()
        } else if current > 8.0 {
            theme.palette.warning_color()
        } else {
            theme.palette.success_color()
        };
        lines.push(Line::from_spans([
            Span::styled(
                "frame ",
                Style::default().fg(theme.palette.text_secondary()),
            ),
            Span::styled(
                format!("{current:.1}ms"),
                Style::default().fg(current_color).bold(),
            ),
            Span::styled(
                format!("  avg={avg:.1}ms  min={min:.1}ms  max={max:.1}ms"),
                Style::default().fg(theme.palette.text_secondary()),
            ),
        ]));
    } else {
        lines.push(Line::from(Span::styled(
            "frame no data yet",
            Style::default().fg(theme.palette.muted_color()),
        )));
    }
    let normalized = model.frame_times.normalized();
    if !normalized.is_empty() {
        let mut trace_spans = vec![Span::styled(
            "trace ",
            Style::default().fg(theme.palette.text_secondary()),
        )];
        trace_spans.extend(colored_sparkline(&normalized, &theme.palette));
        lines.push(Line::from_spans(trace_spans));
    }
    lines.push(Line::from(Span::styled(
        format!(
            "terminal={}x{}",
            model.terminal_size.0, model.terminal_size.1
        ),
        Style::default().fg(theme.palette.text_secondary()),
    )));
    Text::from_lines(lines)
}

fn frame_render_footer(model: &DashboardModel, theme: &Theme, area: Rect, frame: &mut Frame) {
    let accent = theme.palette.tab_active_bg(model.screen.number());

    let mut spans: Vec<Span> = Vec::new();

    // Screen-specific key hints (most important bindings only).
    let bindings: &[(&str, &str)] = match model.screen {
        Screen::Overview => &[
            ("Tab", "focus"),
            ("\u{23CE}", "open"),
            ("1-7", "screen"),
            ("?", "help"),
            (":", "cmd"),
            ("Esc", "back"),
        ],
        Screen::Timeline => &[
            ("j/k", "nav"),
            ("f", "filter"),
            ("F", "follow"),
            ("r", "refresh"),
            ("?", "help"),
            ("Esc", "back"),
        ],
        Screen::Explainability | Screen::Ballast => &[
            ("j/k", "nav"),
            ("\u{23CE}", "detail"),
            ("d", "close"),
            ("r", "refresh"),
            ("?", "help"),
            ("Esc", "back"),
        ],
        Screen::Candidates => &[
            ("j/k", "nav"),
            ("\u{23CE}", "detail"),
            ("s", "sort"),
            ("d", "close"),
            ("?", "help"),
            ("Esc", "back"),
        ],
        Screen::LogSearch => &[
            ("j/k", "nav"),
            ("1-7", "screen"),
            ("r", "refresh"),
            ("?", "help"),
            ("Esc", "back"),
        ],
        Screen::Diagnostics => &[
            ("V", "verbose"),
            ("r", "refresh"),
            ("1-7", "screen"),
            ("?", "help"),
            ("Esc", "back"),
        ],
    };

    for (key, label) in bindings {
        spans.extend(key_hint(key, label, accent));
    }

    // Right-align screen position indicator.
    let position = format!(
        " {}/7 {} ",
        model.screen.number(),
        screen_tab_label(model.screen)
    );
    let used_width: usize = spans.iter().map(|s| s.content.len()).sum();
    let pad = usize::from(area.width).saturating_sub(used_width + position.len());
    if pad > 0 {
        spans.push(Span::raw(" ".repeat(pad)));
    }
    spans.push(Span::styled(
        position,
        Style::default()
            .fg(theme.palette.text_secondary())
            .bg(theme.palette.panel_bg()),
    ));

    Paragraph::new(Line::from_spans(spans))
        .style(
            Style::default()
                .fg(theme.palette.muted_color())
                .bg(theme.palette.surface_bg()),
        )
        .render(area, frame);
}

fn frame_render_notifications(
    model: &DashboardModel,
    theme: &Theme,
    area: Rect,
    frame: &mut Frame,
) {
    let mut lines = Vec::new();
    for notif in model.notifications.iter().take(3) {
        let (badge, color) = match notif.level {
            NotificationLevel::Info => ("INFO", theme.palette.accent_color()),
            NotificationLevel::Warning => ("WARN", theme.palette.warning_color()),
            NotificationLevel::Error => ("ERROR", theme.palette.critical_color()),
        };
        lines.push(Line::from_spans([
            Span::styled("\u{2502}", Style::default().fg(color)),
            Span::styled(
                format!(" {badge} "),
                Style::default()
                    .fg(PackedRgba::rgb(20, 20, 30))
                    .bg(color)
                    .bold(),
            ),
            Span::raw("  "),
            Span::styled(
                &*notif.message,
                Style::default().fg(theme.palette.text_primary()),
            ),
        ]));
    }
    if !lines.is_empty() {
        Paragraph::new(Text::from_lines(lines))
            .style(Style::default().fg(theme.palette.text_primary()))
            .render(area, frame);
    }
}

fn frame_render_overlay(
    model: &DashboardModel,
    overlay: super::model::Overlay,
    theme: &Theme,
    body_area: Rect,
    frame: &mut Frame,
) {
    // Soft scrim behind overlays so context remains visible but de-emphasized.
    let scrim = theme.palette.scrim_bg();
    for y in body_area.y..body_area.y.saturating_add(body_area.height) {
        for x in body_area.x..body_area.x.saturating_add(body_area.width) {
            if let Some(cell) = frame.buffer.get_mut(x, y) {
                cell.bg = scrim;
                cell.fg = theme.palette.muted_color();
            }
        }
    }

    let overlay_area = overlay_panel_rect(body_area, overlay);

    let title = match overlay {
        super::model::Overlay::CommandPalette => "Command Palette",
        super::model::Overlay::Help => "Help",
        super::model::Overlay::Voi => "VOI Scheduler",
        super::model::Overlay::Confirmation(..) => "Confirm",
        super::model::Overlay::IncidentPlaybook => "Incident Playbook",
    };

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .title(title)
        .border_style(Style::default().fg(theme.palette.accent_color()))
        .style(Style::default().bg(theme.palette.panel_bg()));
    let inner = block.inner(overlay_area);
    block.render(overlay_area, frame);

    match overlay {
        super::model::Overlay::CommandPalette => {
            let mut lines = Vec::new();
            // Search input with styled prompt.
            lines.push(Line::from_spans([
                Span::styled(
                    " \u{25B8} ",
                    Style::default()
                        .fg(PackedRgba::rgb(20, 20, 30))
                        .bg(theme.palette.accent_color())
                        .bold(),
                ),
                Span::raw(" "),
                Span::styled(
                    &*model.palette_query,
                    Style::default().fg(theme.palette.text_primary()),
                ),
            ]));
            let results = super::input::search_palette_actions(&model.palette_query, 50);
            let shown = results.len().min(PALETTE_DISPLAY_LIMIT);
            lines.push(Line::from_spans([
                Span::styled(
                    format!("  {shown}/{}", results.len()),
                    Style::default().fg(theme.palette.muted_color()),
                ),
                Span::styled(" matches", Style::default().fg(theme.palette.muted_color())),
            ]));
            lines.push(separator_line(
                usize::from(inner.width).min(60),
                theme.palette.border_color(),
            ));
            for (i, action) in results.iter().take(PALETTE_DISPLAY_LIMIT).enumerate() {
                let selected = i == model.palette_selected;
                let cursor_span = if selected {
                    Span::styled(
                        " \u{25B8} ",
                        Style::default().fg(theme.palette.accent_color()).bold(),
                    )
                } else {
                    Span::raw("   ")
                };
                let (id_style, title_style) = if selected {
                    (
                        Style::default()
                            .fg(theme.palette.accent_color())
                            .bg(theme.palette.highlight_bg())
                            .bold(),
                        Style::default()
                            .fg(theme.palette.text_primary())
                            .bg(theme.palette.highlight_bg()),
                    )
                } else {
                    (
                        Style::default().fg(theme.palette.text_secondary()),
                        Style::default().fg(theme.palette.text_secondary()),
                    )
                };
                lines.push(Line::from_spans([
                    cursor_span,
                    Span::styled(format!("{:<12}", action.id), id_style),
                    Span::styled(action.title, title_style),
                ]));
            }
            Paragraph::new(Text::from_lines(lines)).render(inner, frame);
        }
        super::model::Overlay::Help => {
            let accent = theme.palette.accent_color();
            let help_bindings: &[(&str, &str, &str)] = &[
                // (category, key, description)
                ("Navigation", "?", "toggle help"),
                ("Navigation", ":", "command palette"),
                ("Navigation", "1-7", "jump to screen"),
                ("Navigation", "[/]", "prev/next screen"),
                ("Screen", "Tab", "next overview pane"),
                ("Screen", "S-Tab", "prev overview pane"),
                ("Screen", "\u{23CE}", "open focused pane"),
                ("Screen", "j/k", "navigate list items"),
                ("Overlay", "Esc", "close \u{2192} back \u{2192} quit"),
                ("Overlay", "click", "close overlay"),
                ("General", "r", "refresh data"),
                ("General", "q", "quit dashboard"),
            ];
            let mut lines = Vec::new();
            let mut last_category = "";
            for (category, key, desc) in help_bindings {
                if *category != last_category {
                    if !last_category.is_empty() {
                        lines.push(Line::from(""));
                    }
                    lines.push(Line::from(Span::styled(
                        format!(" {category}"),
                        Style::default().fg(theme.palette.text_primary()).bold(),
                    )));
                    last_category = category;
                }
                let mut row = vec![Span::raw("  ")];
                row.extend(key_hint(key, desc, accent));
                lines.push(Line::from_spans(row));
            }
            Paragraph::new(Text::from_lines(lines)).render(inner, frame);
        }
        super::model::Overlay::Voi => {
            let voi_text = concat!(
                "  VOI (Value-of-Information) Scan Scheduler\n",
                "\n",
                "  Allocates a limited scan budget to paths most\n",
                "  likely to yield reclaimable space.\n",
                "\n",
                "  Budget:  5 paths per cycle (configurable)\n",
                "  Split:   80% exploitation / 20% exploration\n",
                "\n",
                "  Exploitation selects paths with the highest\n",
                "  expected reclaim weighted by IO cost and\n",
                "  false-positive risk.\n",
                "\n",
                "  Exploration re-scans least-recently-visited\n",
                "  paths to discover changed workloads.\n",
                "\n",
                "  Fallback: if forecast MAPE > 50% for 3\n",
                "  windows, reverts to round-robin scheduling.\n",
                "  Recovers after 5 clean windows.\n",
                "\n",
                "  Config: [scheduler] section in config.toml\n",
                "  Esc or click closes overlay (then back/quit).",
            );
            Paragraph::new(voi_text)
                .style(Style::default().fg(theme.palette.text_primary()))
                .render(inner, frame);
        }
        _ => {
            Paragraph::new(format!(
                "  {title} overlay\n\n  Esc or click closes overlay.\n  Next Esc closes detail or goes back.\n  Final Esc quits."
            ))
                .style(Style::default().fg(theme.palette.text_secondary()))
                .render(inner, frame);
        }
    }
}

fn overlay_panel_rect(body_area: Rect, overlay: super::model::Overlay) -> Rect {
    // Scale overlays with terminal size while preserving minimum readable bounds.
    let (width_pct, height_pct, min_w, min_h) = match overlay {
        super::model::Overlay::CommandPalette => (78u16, 80u16, 52u16, 12u16),
        super::model::Overlay::Help => (86u16, 84u16, 58u16, 14u16),
        super::model::Overlay::Voi => (88u16, 88u16, 62u16, 16u16),
        super::model::Overlay::Confirmation(..) => (56u16, 42u16, 44u16, 10u16),
        super::model::Overlay::IncidentPlaybook => (78u16, 76u16, 56u16, 14u16),
    };
    let desired_w =
        u16::try_from((u32::from(body_area.width) * u32::from(width_pct)) / 100).unwrap_or(0);
    let desired_h =
        u16::try_from((u32::from(body_area.height) * u32::from(height_pct)) / 100).unwrap_or(0);
    let max_w = body_area.width.saturating_sub(2).max(1);
    let max_h = body_area.height.saturating_sub(2).max(1);
    let overlay_w = clamp_overlay_dimension(desired_w, min_w, max_w);
    let overlay_h = clamp_overlay_dimension(desired_h, min_h, max_h);
    let x = body_area.x + (body_area.width.saturating_sub(overlay_w)) / 2;
    let y = body_area.y + (body_area.height.saturating_sub(overlay_h)) / 2;
    Rect::new(x, y, overlay_w, overlay_h)
}

fn clamp_overlay_dimension(desired: u16, min: u16, max: u16) -> u16 {
    if max == 0 {
        return 0;
    }
    let lower = min.min(max);
    desired.max(lower).min(max)
}

const PALETTE_DISPLAY_LIMIT: usize = 10;

fn render_command_palette(model: &DashboardModel, out: &mut String) {
    use std::fmt::Write as _;

    let _ = writeln!(out, "Command Palette");
    let _ = writeln!(out, "> {}", model.palette_query);

    let all_results = super::input::search_palette_actions(&model.palette_query, 50);
    let total = all_results.len();
    let shown = total.min(PALETTE_DISPLAY_LIMIT);
    let _ = writeln!(out, "matches: {shown} / {total}");

    for (i, action) in all_results.iter().take(PALETTE_DISPLAY_LIMIT).enumerate() {
        let cursor = if i == model.palette_selected {
            ">"
        } else {
            " "
        };
        let _ = writeln!(out, "{cursor} {}: {}", action.id, action.title);
    }

    let _ = writeln!(out, "Enter execute  Esc close");
}

fn screen_label(screen: Screen) -> &'static str {
    match screen {
        Screen::Overview => "S1 Overview",
        Screen::Timeline => "S2 Timeline",
        Screen::Explainability => "S3 Explain",
        Screen::Candidates => "S4 Candidates",
        Screen::Ballast => "S5 Ballast",
        Screen::LogSearch => "S6 Logs",
        Screen::Diagnostics => "S7 Diagnostics",
    }
}

fn color_mode_label(theme: &Theme) -> &'static str {
    if theme.accessibility.no_color() {
        "mono"
    } else {
        "color"
    }
}

fn spacing_mode_label(theme: &Theme) -> &'static str {
    if theme.spacing.outer_padding == 0 {
        "compact"
    } else {
        "comfortable"
    }
}

fn preference_profile_mode_label(mode: PreferenceProfileMode) -> &'static str {
    match mode {
        PreferenceProfileMode::Defaults => "defaults",
        PreferenceProfileMode::Persisted => "persisted",
        PreferenceProfileMode::SessionOverride => "session",
    }
}

fn start_screen_label(start_screen: StartScreen) -> &'static str {
    match start_screen {
        StartScreen::Overview => "overview",
        StartScreen::Timeline => "timeline",
        StartScreen::Explainability => "explainability",
        StartScreen::Candidates => "candidates",
        StartScreen::Ballast => "ballast",
        StartScreen::LogSearch => "log_search",
        StartScreen::Diagnostics => "diagnostics",
        StartScreen::Remember => "remember",
    }
}

fn write_navigation_hint(model: &DashboardModel, out: &mut String, full: &str, minimal: &str) {
    use std::fmt::Write as _;
    // Safety floor: only optional navigation/help hints are hidden.
    // Pressure/veto/safety indicators remain always visible in all modes.
    let line = match model.hint_verbosity {
        HintVerbosity::Full => Some(full),
        HintVerbosity::Minimal => Some(minimal),
        HintVerbosity::Off => None,
    };
    if let Some(line) = line {
        let _ = writeln!(out);
        let _ = writeln!(out, "{line}");
    }
}

fn render_overview(model: &DashboardModel, theme: &Theme, out: &mut String) {
    use std::fmt::Write as _;
    let layout = build_overview_layout(model.terminal_size.0, model.terminal_size.1);
    let visible = layout.placements.iter().filter(|pane| pane.visible).count();
    let _ = writeln!(
        out,
        "overview-layout={:?}/{:?} visible-panes={visible} focus={} hover={}",
        layout.class,
        layout.density,
        model.overview_focus_pane.id(),
        model.overview_hover_pane.map_or("-", OverviewPane::id),
    );

    for placement in layout.placements.iter().filter(|pane| pane.visible) {
        let content = match placement.pane {
            OverviewPane::PressureSummary => {
                render_pressure_summary(model, theme, placement.rect.width)
            }
            OverviewPane::ForecastHorizon => render_forecast_horizon(model, theme),
            OverviewPane::ActionLane => render_action_lane(model),
            OverviewPane::EwmaTrend => render_ewma_trend(model),
            OverviewPane::DecisionPulse => render_decision_pulse(model, theme),
            OverviewPane::CandidateHotlist => {
                render_candidate_hotlist(model, theme, placement.rect.width)
            }
            OverviewPane::BallastQuick => render_ballast_quick(model, theme),
            OverviewPane::SpecialLocations => render_special_locations(model, theme),
            OverviewPane::ExtendedCounters => render_extended_counters(model),
        };
        // First line shares the pane header; continuation lines are indented.
        let mut lines = content.lines();
        if let Some(first) = lines.next() {
            let _ = writeln!(
                out,
                "[{} {} @{},{} {}x{}] {}",
                placement.pane.id(),
                pane_priority_label(placement.priority),
                placement.rect.col,
                placement.rect.row,
                placement.rect.width,
                placement.rect.height,
                first,
            );
            for line in lines {
                let _ = writeln!(out, "  {line}");
            }
        }
    }

    write_navigation_hint(
        model,
        out,
        "Tab/Shift-Tab pane focus  Enter/Space open pane  mouse move/click drill-in  1-7 screens  [/] prev/next  b ballast  r refresh  ? help  : palette",
        "Tab focus  Enter/Space open pane  mouse click  1-7 screens  [/] prev/next",
    );
}

fn pane_priority_label(priority: PanePriority) -> &'static str {
    match priority {
        PanePriority::P0 => "p0",
        PanePriority::P1 => "p1",
        PanePriority::P2 => "p2",
    }
}

#[allow(clippy::option_if_let_else)]
fn render_pressure_summary(model: &DashboardModel, theme: &Theme, pane_width: u16) -> String {
    use std::fmt::Write as _;

    if let Some(ref state) = model.daemon_state {
        let worst_free_pct = state
            .pressure
            .mounts
            .iter()
            .map(|mount| mount.free_pct)
            .reduce(f64::min)
            .unwrap_or(100.0);
        let badge = status_badge(
            &state.pressure.overall.to_ascii_uppercase(),
            theme.palette.for_pressure_level(&state.pressure.overall),
            theme.accessibility,
        );
        let gauge_w = gauge_width_for(pane_width).max(8);
        let policy_label = if state.policy_mode.is_empty() {
            String::new()
        } else {
            let policy_badge = status_badge(
                &state.policy_mode.to_ascii_uppercase(),
                policy_mode_palette(&state.policy_mode, &theme.palette),
                theme.accessibility,
            );
            format!(" policy={policy_badge}")
        };
        let mut out = format!(
            "pressure {badge} worst-free={worst_free_pct:.1}% mounts={}{policy_label}",
            state.pressure.mounts.len(),
        );

        let pane_w = usize::from(pane_width);
        let path_w = pane_w.saturating_sub(40).clamp(8, 26);
        let _ = write!(
            out,
            "\n  {mount:<path_w$} {free:>11} {rate:>11} {level:>10} used",
            mount = "mount",
            free = "free",
            rate = "rate",
            level = "level",
            path_w = path_w,
        );

        for mount in &state.pressure.mounts {
            let used_pct = 100.0 - mount.free_pct;
            let g = gauge(used_pct, gauge_w);
            let level_core = mount
                .level
                .to_ascii_uppercase()
                .chars()
                .take(8)
                .collect::<String>();
            let level = format!("[{level_core}]");
            let rate = mount.rate_bps.map_or_else(|| "-".to_string(), human_rate);
            let rate_warn = match mount.rate_bps {
                Some(r) if r > 0.0 && mount.free_pct > 0.0 => " \u{26a0}",
                _ => "",
            };
            let mount_path = truncate_path(&mount.path, path_w);
            let _ = write!(
                out,
                "\n  {mount_path:<path_w$} {free:>5.1}% free {rate:>11} {level:>10} {g}{rate_warn}",
                free = mount.free_pct,
                rate = rate,
                level = level,
                g = g,
                path_w = path_w,
            );
        }
        out
    } else if model.degraded && !model.monitor_paths.is_empty() {
        let badge = status_badge("DEGRADED", theme.palette.warning, theme.accessibility);
        let mut out = format!(
            "pressure {badge} live-fs-stats paths={}",
            model.monitor_paths.len(),
        );
        for path in &model.monitor_paths {
            let _ = write!(out, "\n  {}", path.display());
        }
        out
    } else {
        let badge = status_badge("UNKNOWN", theme.palette.muted, theme.accessibility);
        format!("pressure {badge} daemon-state-unavailable")
    }
}

fn gauge_width_for(pane_width: u16) -> usize {
    usize::from(pane_width).clamp(28, 64) / 3
}

#[allow(clippy::option_if_let_else)]
fn render_action_lane(model: &DashboardModel) -> String {
    if let Some(ref state) = model.daemon_state {
        format!(
            "actions scans={} deleted={} freed={}",
            state.counters.scans,
            state.counters.deletions,
            human_bytes(state.counters.bytes_freed),
        )
    } else {
        String::from("actions awaiting daemon connection")
    }
}

#[allow(clippy::option_if_let_else)]
fn render_forecast_horizon(model: &DashboardModel, theme: &Theme) -> String {
    if let Some(ref state) = model.daemon_state {
        let worst = state
            .pressure
            .mounts
            .iter()
            .min_by(|a, b| a.free_pct.total_cmp(&b.free_pct));
        if let Some(worst) = worst {
            let eta = worst.rate_bps.and_then(|rate| {
                if rate <= 0.0 || worst.free_pct <= 0.0 {
                    None
                } else {
                    // Rough forecast: assume 100GiB * free% remaining.
                    let bytes_left = (worst.free_pct / 100.0) * 100.0 * 1024.0 * 1024.0 * 1024.0;
                    Some((bytes_left / rate).max(0.0))
                }
            });
            let eta_label = eta.map_or_else(|| "insufficient trend data".to_string(), eta_label);
            let badge = status_badge(
                &worst.level.to_ascii_uppercase(),
                theme.palette.for_pressure_level(&worst.level),
                theme.accessibility,
            );
            return format!(
                "forecast {badge} worst={} free={:.1}% eta≈{eta_label}",
                worst.path, worst.free_pct
            );
        }
    }
    String::from("forecast awaiting daemon trend inputs")
}

fn render_ewma_trend(model: &DashboardModel) -> String {
    use std::fmt::Write as _;

    if model.rate_histories.is_empty() {
        return String::from("ewma no-rate-data");
    }

    let mut sorted: Vec<_> = model.rate_histories.iter().collect();
    sorted.sort_unstable_by(|a, b| a.0.cmp(b.0));

    let mut out = format!("ewma {} mounts", sorted.len());
    for (path, history) in &sorted {
        let normalized = history.normalized();
        let trace = sparkline(&normalized);
        let latest = history.latest().unwrap_or(0.0);
        let rate_str = human_rate(latest);
        let trend = trend_label(latest);
        let alert = if latest > 1_000_000.0 {
            " \u{26a0}"
        } else {
            ""
        };
        let _ = write!(out, "\n  {path:<14} {trace} {rate_str} {trend}{alert}");
    }
    out
}

#[allow(clippy::option_if_let_else)]
fn render_decision_pulse(model: &DashboardModel, theme: &Theme) -> String {
    let activity_line = render_recent_activity(model);
    if model.explainability_decisions.is_empty() {
        return format!("decision-pulse no evidence loaded yet\n  {activity_line}");
    }
    let total = model.explainability_decisions.len();
    let total_u32 = u32::try_from(total).unwrap_or(u32::MAX);
    let vetoed = model
        .explainability_decisions
        .iter()
        .filter(|d| d.vetoed)
        .count();
    let avg = model
        .explainability_decisions
        .iter()
        .map(|d| d.total_score)
        .sum::<f64>()
        / f64::from(total_u32.max(1));
    let badge = if vetoed > 0 {
        status_badge("VETOES", theme.palette.warning, theme.accessibility)
    } else {
        status_badge("CLEAR", theme.palette.success, theme.accessibility)
    };
    format!(
        "decision-pulse {badge} decisions={total} vetoed={vetoed} avg-score={avg:.2}\n  {activity_line}"
    )
}

#[allow(clippy::option_if_let_else)]
fn render_candidate_hotlist(model: &DashboardModel, theme: &Theme, pane_width: u16) -> String {
    use std::fmt::Write as _;

    if model.candidates_list.is_empty() {
        return String::from("hotlist no candidate ranking loaded yet");
    }
    let pane_w = usize::from(pane_width);
    let path_w = pane_w.saturating_sub(36).clamp(12, 46);
    let mut out = format!(
        "hotlist total={} source={:?}",
        model.candidates_list.len(),
        model.candidates_source
    );
    let _ = write!(out, "\n  rank score   size        age      path");
    for (idx, candidate) in model.candidates_list.iter().take(5).enumerate() {
        let badge = if candidate.total_score >= 0.8 {
            status_badge("HOT", theme.palette.critical, theme.accessibility)
        } else if candidate.total_score >= 0.6 {
            status_badge("WARM", theme.palette.warning, theme.accessibility)
        } else {
            status_badge("MILD", theme.palette.accent, theme.accessibility)
        };
        let cursor = if idx == model.candidates_selected {
            ">"
        } else {
            " "
        };
        let veto = if candidate.vetoed { " VETO" } else { "" };
        let _ = write!(
            out,
            "\n{cursor} {:>2}. {:>5.2} {:>10} {:>8} {} {:<path_w$}{veto}",
            idx + 1,
            candidate.total_score,
            human_bytes(candidate.size_bytes),
            human_duration(candidate.age_secs),
            badge,
            truncate_path(&candidate.path, path_w),
            path_w = path_w,
        );
    }
    out
}

#[allow(clippy::option_if_let_else)]
fn render_special_locations(model: &DashboardModel, theme: &Theme) -> String {
    if model.timeline_events.is_empty() {
        return String::from("special-locations no timeline telemetry loaded yet");
    }
    let mut tmp_hits = 0usize;
    let mut data_tmp_hits = 0usize;
    let mut critical = 0usize;
    for event in &model.timeline_events {
        if let Some(path) = event.path.as_deref() {
            if path.contains("/tmp") {
                tmp_hits += 1;
            }
            if path.contains("/data/tmp") {
                data_tmp_hits += 1;
            }
        }
        if event.severity == "critical" {
            critical += 1;
        }
    }
    let badge = if critical > 0 {
        status_badge("WATCH", theme.palette.warning, theme.accessibility)
    } else {
        status_badge("STABLE", theme.palette.success, theme.accessibility)
    };
    format!(
        "special-locations {badge} /tmp-events={tmp_hits} /data/tmp-events={data_tmp_hits} critical-events={critical}"
    )
}

fn eta_label(secs: f64) -> String {
    if !secs.is_finite() {
        return "unknown".to_string();
    }
    if secs >= 86_400.0 {
        return format!("{:.1}d", secs / 86_400.0);
    }
    if secs >= 3_600.0 {
        return format!("{:.1}h", secs / 3_600.0);
    }
    if secs >= 60.0 {
        return format!("{:.1}m", secs / 60.0);
    }
    format!("{secs:.0}s")
}

#[allow(clippy::option_if_let_else)]
fn render_recent_activity(model: &DashboardModel) -> String {
    if let Some(ref state) = model.daemon_state {
        let at_str = state.last_scan.at.as_deref().map_or("never", extract_time);
        format!(
            "activity last-scan={at_str} candidates={} deleted={} errors={}",
            state.last_scan.candidates, state.last_scan.deleted, state.counters.errors,
        )
    } else {
        String::from("activity unavailable while degraded")
    }
}

#[allow(clippy::option_if_let_else)]
fn render_ballast_quick(model: &DashboardModel, theme: &Theme) -> String {
    if let Some(ref state) = model.daemon_state {
        let (palette, label) = if state.ballast.total > 0 && state.ballast.available == 0 {
            (theme.palette.critical, "CRITICAL")
        } else if state.ballast.available.saturating_mul(2) < state.ballast.total {
            (theme.palette.warning, "LOW")
        } else {
            (theme.palette.success, "OK")
        };
        let badge = status_badge(label, palette, theme.accessibility);
        format!(
            "ballast {badge} available={}/{} released={}",
            state.ballast.available, state.ballast.total, state.ballast.released,
        )
    } else {
        let badge = status_badge("UNKNOWN", theme.palette.muted, theme.accessibility);
        format!("ballast {badge} unavailable")
    }
}

#[allow(clippy::option_if_let_else)]
fn render_extended_counters(model: &DashboardModel) -> String {
    use std::fmt::Write as _;

    if let Some(ref state) = model.daemon_state {
        let policy = if state.policy_mode.is_empty() {
            "unknown"
        } else {
            &state.policy_mode
        };
        let dropped_warn = if state.counters.dropped_log_events > 0 {
            " \u{26a0}"
        } else {
            ""
        };
        let mut out = format!(
            "runtime scans={} deletions={} errors={} dropped={}{dropped_warn}",
            state.counters.scans,
            state.counters.deletions,
            state.counters.errors,
            state.counters.dropped_log_events,
        );
        let _ = write!(
            out,
            "\n  freed={} rss={} uptime={}",
            human_bytes(state.counters.bytes_freed),
            human_bytes(state.memory_rss_bytes),
            human_duration(state.uptime_seconds),
        );
        let _ = write!(
            out,
            "\n  pid={} policy={} adapters(r/e)={}/{}",
            state.pid, policy, model.adapter_reads, model.adapter_errors
        );
        out
    } else {
        format!(
            "counters unavailable\n  adapters(r/e)={}/{}",
            model.adapter_reads, model.adapter_errors
        )
    }
}

// ──────────────────── S2: Timeline ────────────────────

fn render_timeline(model: &DashboardModel, theme: &Theme, out: &mut String) {
    use std::fmt::Write as _;
    let layout = build_timeline_layout(model.terminal_size.0, model.terminal_size.1);

    // ── Filter bar ──
    let filter_bar = layout
        .placements
        .iter()
        .find(|p| p.pane == TimelinePane::FilterBar && p.visible);
    if filter_bar.is_some() {
        let follow_indicator = if model.timeline_follow {
            " [FOLLOW]"
        } else {
            ""
        };
        let _ = writeln!(
            out,
            "filter={}{follow_indicator}",
            model.timeline_filter.label(),
        );
    }

    // ── Data-source header ──
    let source_label = match model.timeline_source {
        DataSource::Sqlite => "SQLite",
        DataSource::Jsonl => "JSONL",
        DataSource::None => "none",
    };
    let health_badge = if model.timeline_source == DataSource::None {
        status_badge("NO DATA", theme.palette.muted, theme.accessibility)
    } else if model.timeline_partial {
        status_badge("PARTIAL", theme.palette.warning, theme.accessibility)
    } else {
        status_badge("OK", theme.palette.success, theme.accessibility)
    };
    let _ = writeln!(out, "data-source={source_label} {health_badge}");

    if !model.timeline_diagnostics.is_empty() {
        let _ = writeln!(out, "  diag: {}", model.timeline_diagnostics);
    }

    // ── Filtered event list ──
    let filtered = model.timeline_filtered_events();
    let total = model.timeline_events.len();
    let shown = filtered.len();
    let _ = writeln!(out, "events={shown}/{total}");

    let _ = writeln!(out);
    if filtered.is_empty() {
        if total == 0 {
            let _ = writeln!(
                out,
                "No timeline events available. The daemon must be running with"
            );
            let _ = writeln!(out, "telemetry enabled to populate this screen.");
        } else {
            let _ = writeln!(
                out,
                "No events match the current filter ({}).",
                model.timeline_filter.label()
            );
            let _ = writeln!(out, "Press f to cycle the severity filter.");
        }
    } else {
        let list_visible = layout
            .placements
            .iter()
            .find(|p| p.pane == TimelinePane::EventList && p.visible);
        let max_rows = list_visible.map_or(shown, |p| usize::from(p.rect.height));

        // Compute visible window around selected item.
        let window_start = model
            .timeline_selected
            .saturating_sub(max_rows / 2)
            .min(shown.saturating_sub(max_rows));
        let window_end = (window_start + max_rows).min(shown);

        for (idx, event) in filtered[window_start..window_end].iter().enumerate() {
            let abs_idx = window_start + idx;
            let cursor = if abs_idx == model.timeline_selected {
                ">"
            } else {
                " "
            };
            render_event_row(cursor, event, theme, out);
        }
    }

    // ── Detail pane (wide layout only) ──
    let detail_visible = layout
        .placements
        .iter()
        .any(|p| p.pane == TimelinePane::EventDetail && p.visible);
    if detail_visible && let Some(event) = model.timeline_selected_event() {
        let _ = writeln!(out);
        let width = usize::from(model.terminal_size.0).max(40);
        let _ = writeln!(out, "{}", section_header("Event Detail", width));
        render_event_detail(event, theme, out);
    }

    // ── Status footer ──
    let footer_visible = layout
        .placements
        .iter()
        .any(|p| p.pane == TimelinePane::StatusFooter && p.visible);
    if footer_visible {
        write_navigation_hint(
            model,
            out,
            "j/k or \u{2191}/\u{2193} navigate  f filter  F follow  r refresh  ? help  : palette",
            "j/k navigate  f filter  F follow  r refresh",
        );
    }
}

fn render_event_row(cursor: &str, event: &TimelineEvent, theme: &Theme, out: &mut String) {
    use std::fmt::Write as _;
    let time = extract_time(&event.timestamp);
    let sev_badge = severity_badge(&event.severity, theme);
    let path_short = event.path.as_deref().map_or("-", |p| truncate_path(p, 30));
    let size_str = event.size_bytes.map(human_bytes).unwrap_or_default();
    let success_marker = match event.success {
        Some(true) => " \u{2713}",
        Some(false) => " \u{2717}",
        None => "",
    };
    let _ = writeln!(
        out,
        "{cursor} {time} {sev_badge} {:<20} {path_short} {size_str}{success_marker}",
        event.event_type,
    );
}

fn render_event_detail(event: &TimelineEvent, theme: &Theme, out: &mut String) {
    use std::fmt::Write as _;
    let _ = writeln!(out, "  timestamp:  {}", event.timestamp);
    let _ = writeln!(out, "  event-type: {}", event.event_type);
    let sev_badge = severity_badge(&event.severity, theme);
    let _ = writeln!(out, "  severity:   {sev_badge}");

    if let Some(ref path) = event.path {
        let _ = writeln!(out, "  path:       {path}");
    }
    if let Some(size) = event.size_bytes {
        let _ = writeln!(out, "  size:       {} ({size} bytes)", human_bytes(size));
    }
    if let Some(score) = event.score {
        let _ = writeln!(out, "  score:      {score:.4}");
    }
    if let Some(ref level) = event.pressure_level {
        let _ = writeln!(out, "  pressure:   {level}");
    }
    if let Some(pct) = event.free_pct {
        let _ = writeln!(out, "  free:       {pct:.1}%");
    }
    if let Some(success) = event.success {
        let marker = if success { "yes" } else { "no" };
        let _ = writeln!(out, "  success:    {marker}");
    }
    if let Some(ref code) = event.error_code {
        let _ = writeln!(out, "  error-code: {code}");
    }
    if let Some(ref msg) = event.error_message {
        let _ = writeln!(out, "  error:      {msg}");
    }
    if let Some(ms) = event.duration_ms {
        let _ = writeln!(out, "  duration:   {ms}ms");
    }
    if let Some(ref details) = event.details {
        let _ = writeln!(out, "  details:    {details}");
    }
}

fn severity_badge(severity: &str, theme: &Theme) -> String {
    let (palette, label) = match severity {
        "critical" => (theme.palette.critical, "CRITICAL"),
        "warning" => (theme.palette.warning, "WARNING"),
        "info" => (theme.palette.accent, "INFO"),
        _ => (theme.palette.muted, severity),
    };
    status_badge(label, palette, theme.accessibility)
}

// ──────────────────── S6: Log Search ────────────────────

fn render_log_search(model: &DashboardModel, theme: &Theme, out: &mut String) {
    use std::fmt::Write as _;

    let layout = build_log_search_layout(model.terminal_size.0, model.terminal_size.1);
    let source_label = match model.timeline_source {
        DataSource::Sqlite => "SQLite",
        DataSource::Jsonl => "JSONL",
        DataSource::None => "none",
    };
    let _ = writeln!(
        out,
        "query=<preview> source={source_label} entries={} mode=timeline-mirror",
        model.timeline_events.len(),
    );
    if !model.timeline_diagnostics.is_empty() {
        let _ = writeln!(out, "  diag: {}", model.timeline_diagnostics);
    }

    let entries = &model.timeline_events;
    let _ = writeln!(out);
    if entries.is_empty() {
        let _ = writeln!(
            out,
            "No log entries loaded. Timeline telemetry powers this preview."
        );
    } else {
        let selected = model.timeline_selected.min(entries.len().saturating_sub(1));
        let list_visible = layout
            .placements
            .iter()
            .find(|p| p.pane == LogSearchPane::LogList && p.visible);
        let max_rows = list_visible.map_or(entries.len(), |p| usize::from(p.rect.height));
        let window_start = selected
            .saturating_sub(max_rows / 2)
            .min(entries.len().saturating_sub(max_rows));
        let window_end = (window_start + max_rows).min(entries.len());
        for (idx, event) in entries
            .iter()
            .enumerate()
            .take(window_end)
            .skip(window_start)
        {
            let cursor = if idx == selected { ">" } else { " " };
            render_event_row(cursor, event, theme, out);
        }
    }

    let detail_visible = layout
        .placements
        .iter()
        .any(|p| p.pane == LogSearchPane::EntryDetail && p.visible);
    if detail_visible && !entries.is_empty() {
        let selected = model.timeline_selected.min(entries.len().saturating_sub(1));
        let _ = writeln!(out);
        let width = usize::from(model.terminal_size.0).max(40);
        let _ = writeln!(out, "{}", section_header("Entry Detail", width));
        render_event_detail(&entries[selected], theme, out);
    }

    write_navigation_hint(
        model,
        out,
        "j/k or wheel navigate  click row focus  r refresh  ? help  : palette",
        "j/k or wheel navigate  click row focus  r refresh",
    );
}

// ──────────────────── S3: Explainability ────────────────────

fn render_explainability(model: &DashboardModel, theme: &Theme, out: &mut String) {
    use std::fmt::Write as _;
    let width = usize::from(model.terminal_size.0).max(40);

    // ── Data-source header ──
    let source_label = match model.explainability_source {
        DataSource::Sqlite => "SQLite",
        DataSource::Jsonl => "JSONL",
        DataSource::None => "none",
    };
    let health_badge = if model.explainability_source == DataSource::None {
        status_badge("NO DATA", theme.palette.muted, theme.accessibility)
    } else if model.explainability_partial {
        status_badge("PARTIAL", theme.palette.warning, theme.accessibility)
    } else {
        status_badge("OK", theme.palette.success, theme.accessibility)
    };

    let _ = writeln!(
        out,
        "data-source={source_label} {health_badge} decisions={}",
        model.explainability_decisions.len(),
    );

    if !model.explainability_diagnostics.is_empty() {
        let _ = writeln!(out, "  diag: {}", model.explainability_diagnostics);
    }

    // ── Policy mode indicator ──
    if let Some(ref state) = model.daemon_state {
        let pressure_badge = status_badge(
            &state.pressure.overall.to_ascii_uppercase(),
            theme.palette.for_pressure_level(&state.pressure.overall),
            theme.accessibility,
        );
        let _ = writeln!(
            out,
            "pressure={pressure_badge} scans={} deletions={} errors={}",
            state.counters.scans, state.counters.deletions, state.counters.errors,
        );
    }

    // ── Empty state ──
    if model.explainability_decisions.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "No decision evidence available. The daemon must be running with"
        );
        let _ = writeln!(out, "telemetry enabled to populate this screen.");
        let _ = writeln!(
            out,
            "Press r to force refresh, or check daemon status with key 1."
        );
        write_navigation_hint(
            model,
            out,
            "j/k or \u{2191}/\u{2193} navigate  Enter/Space expand  d close detail  r refresh  ? help  : palette",
            "j/k navigate  Enter/Space detail  d close  r refresh",
        );
        return;
    }

    // ── Decisions list ──
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", section_header("Recent Decisions", width));

    for (i, decision) in model.explainability_decisions.iter().enumerate() {
        let cursor = if i == model.explainability_selected {
            ">"
        } else {
            " "
        };
        let action_badge = action_badge(&decision.action, theme);
        let veto_marker = if decision.vetoed { " VETOED" } else { "" };
        let path_short = truncate_path(&decision.path, 40);
        let time = extract_time(&decision.timestamp);
        let _ = writeln!(
            out,
            "{cursor} #{:<4} {time} {action_badge}{veto_marker}  score={:.2}  P(abn)={:.2}  {}  {}",
            decision.decision_id,
            decision.total_score,
            decision.posterior_abandoned,
            human_bytes(decision.size_bytes),
            path_short,
        );
    }

    // ── Detail pane (expanded for selected decision) ──
    if model.explainability_detail {
        if let Some(decision) = model.explainability_selected_decision() {
            let _ = writeln!(out);
            let _ = writeln!(out, "{}", section_header("Decision Detail", width));
            render_decision_detail(decision, theme, width, out);
        }
    } else {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Press Enter/Space to expand detail for selected decision"
        );
    }

    write_navigation_hint(
        model,
        out,
        "j/k or \u{2191}/\u{2193} navigate  Enter/Space expand  d close detail  r refresh  ? help  : palette",
        "j/k navigate  Enter/Space detail  d close  r refresh",
    );
}

fn render_decision_detail(
    decision: &DecisionEvidence,
    theme: &Theme,
    width: usize,
    out: &mut String,
) {
    use std::fmt::Write as _;

    // ── Identity ──
    let _ = writeln!(out, "  decision-id: #{}", decision.decision_id);
    let _ = writeln!(out, "  timestamp:   {}", decision.timestamp);
    let _ = writeln!(out, "  path:        {}", decision.path);
    let _ = writeln!(
        out,
        "  size:        {} ({} bytes)",
        human_bytes(decision.size_bytes),
        decision.size_bytes
    );
    let _ = writeln!(out, "  age:         {}", human_duration(decision.age_secs));

    // ── Action & Policy ──
    let act_badge = action_badge(&decision.action, theme);
    let _ = writeln!(out, "  action:      {act_badge}");
    if let Some(ref effective) = decision.effective_action {
        let eff_badge = action_badge(effective, theme);
        let _ = writeln!(out, "  effective:   {eff_badge}");
    }
    let _ = writeln!(out, "  policy-mode: {}", decision.policy_mode);

    // ── Veto ──
    if decision.vetoed {
        let veto_badge = status_badge("VETOED", theme.palette.danger, theme.accessibility);
        let _ = writeln!(out, "  veto:        {veto_badge}");
        if let Some(ref reason) = decision.veto_reason {
            let _ = writeln!(out, "  veto-reason: {reason}");
        }
    }

    // ── Guard status ──
    if let Some(ref guard) = decision.guard_status {
        let _ = writeln!(out, "  guard:       {guard}");
    }

    // ── Factor breakdown ──
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", section_header("Factor Breakdown", width));
    let bar_width = (width / 3).clamp(10, 30);
    render_factor_bar(
        out,
        "location ",
        decision.factors.location,
        bar_width,
        theme,
    );
    render_factor_bar(out, "name     ", decision.factors.name, bar_width, theme);
    render_factor_bar(out, "age      ", decision.factors.age, bar_width, theme);
    render_factor_bar(out, "size     ", decision.factors.size, bar_width, theme);
    render_factor_bar(
        out,
        "structure",
        decision.factors.structure,
        bar_width,
        theme,
    );
    let _ = writeln!(
        out,
        "  pressure-multiplier: {:.2}x",
        decision.factors.pressure_multiplier
    );
    let _ = writeln!(out, "  total-score: {:.4}", decision.total_score);

    // ── Bayesian decision ──
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", section_header("Bayesian Decision", width));
    let _ = writeln!(
        out,
        "  P(abandoned):     {:.4}",
        decision.posterior_abandoned
    );
    let _ = writeln!(
        out,
        "  E[loss|keep]:     {:.2}",
        decision.expected_loss_keep
    );
    let _ = writeln!(
        out,
        "  E[loss|delete]:   {:.2}",
        decision.expected_loss_delete
    );
    let _ = writeln!(out, "  calibration:      {:.4}", decision.calibration_score);

    // ── Uncertainty indicator ──
    let confidence_level = if decision.calibration_score >= 0.85 {
        "HIGH"
    } else if decision.calibration_score >= 0.60 {
        "MODERATE"
    } else {
        "LOW"
    };
    let confidence_palette = if decision.calibration_score >= 0.85 {
        theme.palette.success
    } else if decision.calibration_score >= 0.60 {
        theme.palette.warning
    } else {
        theme.palette.danger
    };
    let confidence_badge = status_badge(confidence_level, confidence_palette, theme.accessibility);
    let _ = writeln!(out, "  confidence:       {confidence_badge}");

    // ── Summary ──
    if !decision.summary.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "  summary: {}", decision.summary);
    }
}

/// Render a horizontal bar for a single scoring factor (0.0..=1.0).
fn render_factor_bar(out: &mut String, label: &str, value: f64, width: usize, _theme: &Theme) {
    use std::fmt::Write as _;
    let clamped = value.clamp(0.0, 1.0);
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let filled = (clamped * width as f64).round() as usize;
    let empty = width.saturating_sub(filled);
    let _ = writeln!(
        out,
        "  {label} [{}{} ] {:.2}",
        "█".repeat(filled),
        "░".repeat(empty),
        value,
    );
}

fn action_badge(action: &str, theme: &Theme) -> String {
    let (palette, label) = match action {
        "delete" => (theme.palette.danger, "DELETE"),
        "keep" => (theme.palette.success, "KEEP"),
        "review" => (theme.palette.warning, "REVIEW"),
        _ => (theme.palette.muted, action),
    };
    status_badge(label, palette, theme.accessibility)
}

/// Truncate a path string for display, keeping the tail end.
fn truncate_path(path: &str, max_len: usize) -> &str {
    if path.len() <= max_len {
        path
    } else {
        // Clamp to a valid UTF-8 char boundary before slicing.
        let start = path.ceil_char_boundary(path.len() - max_len);
        // Find the next '/' boundary to avoid cutting mid-component.
        path[start..]
            .find('/')
            .map_or(&path[start..], |idx| &path[start + idx..])
    }
}

// ──────────────────── S4: Candidates ────────────────────

#[allow(clippy::too_many_lines)]
fn render_candidates(model: &DashboardModel, theme: &Theme, out: &mut String) {
    use std::fmt::Write as _;
    let width = usize::from(model.terminal_size.0).max(40);

    // ── Data-source header ──
    let source_label = match model.candidates_source {
        DataSource::Sqlite => "SQLite",
        DataSource::Jsonl => "JSONL",
        DataSource::None => "none",
    };
    let health_badge = if model.candidates_source == DataSource::None {
        status_badge("NO DATA", theme.palette.muted, theme.accessibility)
    } else if model.candidates_partial {
        status_badge("PARTIAL", theme.palette.warning, theme.accessibility)
    } else {
        status_badge("OK", theme.palette.success, theme.accessibility)
    };

    let _ = writeln!(
        out,
        "data-source={source_label} {health_badge} candidates={}",
        model.candidates_list.len(),
    );

    if !model.candidates_diagnostics.is_empty() {
        let _ = writeln!(out, "  diag: {}", model.candidates_diagnostics);
    }

    // ── Sort indicator ──
    let _ = writeln!(out, "sort={}", model.candidates_sort.label());

    // ── Policy context ──
    if let Some(ref state) = model.daemon_state {
        let pressure_badge = status_badge(
            &state.pressure.overall.to_ascii_uppercase(),
            theme.palette.for_pressure_level(&state.pressure.overall),
            theme.accessibility,
        );
        let _ = writeln!(
            out,
            "pressure={pressure_badge} scans={} deletions={} errors={}",
            state.counters.scans, state.counters.deletions, state.counters.errors,
        );
    }

    // ── Empty state ──
    if model.candidates_list.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "No scan candidates available. The daemon must be running with"
        );
        let _ = writeln!(out, "telemetry enabled to populate this screen.");
        let _ = writeln!(
            out,
            "Press r to force refresh, or check daemon status with key 1."
        );
        write_navigation_hint(
            model,
            out,
            "j/k or \u{2191}/\u{2193} navigate  Enter/Space expand  d close  s sort  r refresh  ? help  : palette",
            "j/k navigate  Enter/Space detail  s sort  r refresh",
        );
        return;
    }

    // ── Candidate ranking list ──
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", section_header("Scan Candidates", width));

    // Column headers.
    let _ = writeln!(
        out,
        "  {:<4} {:<8} {:<6} {:<10} {:<8} {:<6} PATH",
        "#", "ACTION", "SCORE", "SIZE", "AGE", "VETO"
    );

    for (i, candidate) in model.candidates_list.iter().enumerate() {
        let cursor = if i == model.candidates_selected {
            ">"
        } else {
            " "
        };
        let action_badge = action_badge(&candidate.action, theme);
        let veto_col = if candidate.vetoed { "YES" } else { "-" };
        let age_str = human_duration(candidate.age_secs);
        let size_str = human_bytes(candidate.size_bytes);
        let path_short = truncate_path(&candidate.path, 40);
        let _ = writeln!(
            out,
            "{cursor} {:<4} {action_badge} {:.2}  {:<10} {:<8} {:<6} {}",
            candidate.decision_id, candidate.total_score, size_str, age_str, veto_col, path_short,
        );
    }

    // ── Vetoed summary ──
    let vetoed_count = model.candidates_list.iter().filter(|c| c.vetoed).count();
    if vetoed_count > 0 {
        let _ = writeln!(out);
        let veto_badge = status_badge("VETOED", theme.palette.danger, theme.accessibility);
        let _ = writeln!(
            out,
            "{vetoed_count} candidate(s) {veto_badge} — protected from deletion"
        );
    }

    // ── Reclaim estimate ──
    let total_reclaimable: u64 = model
        .candidates_list
        .iter()
        .filter(|c| !c.vetoed && c.action == "delete")
        .map(|c| c.size_bytes)
        .sum();
    if total_reclaimable > 0 {
        let _ = writeln!(
            out,
            "estimated reclaimable: {}",
            human_bytes(total_reclaimable)
        );
    }

    // ── Detail pane (expanded for selected candidate) ──
    if model.candidates_detail {
        if let Some(candidate) = model.candidates_selected_item() {
            let _ = writeln!(out);
            let _ = writeln!(out, "{}", section_header("Candidate Detail", width));
            render_candidate_detail(candidate, theme, width, out);
        }
    } else {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Press Enter/Space to expand detail for selected candidate"
        );
    }

    write_navigation_hint(
        model,
        out,
        "j/k or \u{2191}/\u{2193} navigate  Enter/Space expand  d close  s sort  r refresh  ? help  : palette",
        "j/k navigate  Enter/Space detail  s sort  r refresh",
    );
}

fn render_candidate_detail(
    candidate: &DecisionEvidence,
    theme: &Theme,
    width: usize,
    out: &mut String,
) {
    use std::fmt::Write as _;

    // ── Identity ──
    let _ = writeln!(out, "  decision-id: #{}", candidate.decision_id);
    let _ = writeln!(out, "  timestamp:   {}", candidate.timestamp);
    let _ = writeln!(out, "  path:        {}", candidate.path);
    let _ = writeln!(
        out,
        "  size:        {} ({} bytes)",
        human_bytes(candidate.size_bytes),
        candidate.size_bytes
    );
    let _ = writeln!(out, "  age:         {}", human_duration(candidate.age_secs));

    // ── Action & Policy ──
    let ab = action_badge(&candidate.action, theme);
    let _ = writeln!(out, "  action:      {ab}");
    if let Some(ref effective) = candidate.effective_action {
        let eff_badge = action_badge(effective, theme);
        let _ = writeln!(out, "  effective:   {eff_badge}");
    }
    let _ = writeln!(out, "  policy-mode: {}", candidate.policy_mode);

    // ── Safety / Veto ──
    if candidate.vetoed {
        let veto_badge = status_badge("VETOED", theme.palette.danger, theme.accessibility);
        let _ = writeln!(out, "  veto:        {veto_badge}");
        if let Some(ref reason) = candidate.veto_reason {
            let _ = writeln!(out, "  veto-reason: {reason}");
        }
    } else {
        let safe_badge = status_badge("CLEAR", theme.palette.success, theme.accessibility);
        let _ = writeln!(out, "  safety:      {safe_badge}");
    }

    // ── Guard status ──
    if let Some(ref guard) = candidate.guard_status {
        let _ = writeln!(out, "  guard:       {guard}");
    }

    // ── Score breakdown ──
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", section_header("Score Breakdown", width));
    let bar_width = (width / 3).clamp(10, 30);
    render_factor_bar(
        out,
        "location ",
        candidate.factors.location,
        bar_width,
        theme,
    );
    render_factor_bar(out, "name     ", candidate.factors.name, bar_width, theme);
    render_factor_bar(out, "age      ", candidate.factors.age, bar_width, theme);
    render_factor_bar(out, "size     ", candidate.factors.size, bar_width, theme);
    render_factor_bar(
        out,
        "structure",
        candidate.factors.structure,
        bar_width,
        theme,
    );
    let _ = writeln!(
        out,
        "  pressure-multiplier: {:.2}x",
        candidate.factors.pressure_multiplier
    );
    let _ = writeln!(out, "  total-score: {:.4}", candidate.total_score);

    // ── Decision statistics ──
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", section_header("Decision Statistics", width));
    let _ = writeln!(
        out,
        "  P(abandoned):     {:.4}",
        candidate.posterior_abandoned
    );
    let _ = writeln!(
        out,
        "  E[loss|keep]:     {:.2}",
        candidate.expected_loss_keep
    );
    let _ = writeln!(
        out,
        "  E[loss|delete]:   {:.2}",
        candidate.expected_loss_delete
    );
    let _ = writeln!(
        out,
        "  calibration:      {:.4}",
        candidate.calibration_score
    );

    // ── Confidence badge ──
    let confidence_level = if candidate.calibration_score >= 0.85 {
        "HIGH"
    } else if candidate.calibration_score >= 0.60 {
        "MODERATE"
    } else {
        "LOW"
    };
    let confidence_palette = if candidate.calibration_score >= 0.85 {
        theme.palette.success
    } else if candidate.calibration_score >= 0.60 {
        theme.palette.warning
    } else {
        theme.palette.danger
    };
    let confidence_badge = status_badge(confidence_level, confidence_palette, theme.accessibility);
    let _ = writeln!(out, "  confidence:       {confidence_badge}");

    // ── Summary ──
    if !candidate.summary.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "  summary: {}", candidate.summary);
    }
}

// ──────────────────── S7: Diagnostics ────────────────────

#[allow(clippy::too_many_lines)]
fn render_diagnostics(model: &DashboardModel, theme: &Theme, out: &mut String) {
    use std::fmt::Write as _;
    let width = usize::from(model.terminal_size.0).max(40);

    // ── Dashboard health ──
    let mode_badge = if model.degraded {
        status_badge("DEGRADED", theme.palette.warning, theme.accessibility)
    } else {
        status_badge("NORMAL", theme.palette.success, theme.accessibility)
    };
    let _ = writeln!(out, "{}", section_header("Dashboard Health", width));
    let _ = writeln!(out, "  mode:          {mode_badge}");
    let _ = writeln!(
        out,
        "  tick:          {} (refresh={}ms)",
        model.tick,
        model.refresh.as_millis(),
    );
    let _ = writeln!(out, "  missed-ticks:  {}", model.missed_ticks);

    // ── Policy mode ──
    if let Some(ref state) = model.daemon_state
        && !state.policy_mode.is_empty()
    {
        let policy_badge = status_badge(
            &state.policy_mode.to_ascii_uppercase(),
            policy_mode_palette(&state.policy_mode, &theme.palette),
            theme.accessibility,
        );
        let _ = writeln!(out, "  policy:        {policy_badge}");
    }

    // ── Last fetch staleness ──
    let fetch_label = model.last_fetch.map_or_else(
        || String::from("never"),
        |t| format!("{}ms ago", t.elapsed().as_millis()),
    );
    let _ = writeln!(out, "  last-fetch:    {fetch_label}");
    let _ = writeln!(out, "  notifications: {} active", model.notifications.len(),);

    // ── Dropped log events ──
    if let Some(ref state) = model.daemon_state {
        let dropped = state.counters.dropped_log_events;
        if dropped > 0 {
            let warn_badge = status_badge("WARN", theme.palette.warning, theme.accessibility);
            let _ = writeln!(out, "  dropped-logs:  {dropped} {warn_badge}");
        } else {
            let _ = writeln!(out, "  dropped-logs:  0");
        }
    }

    // ── Frame timing ──
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", section_header("Frame Timing", width));

    if let Some((current, avg, min, max)) = model.frame_time_stats() {
        let _ = writeln!(
            out,
            "  current: {current:.1}ms  avg: {avg:.1}ms  min: {min:.1}ms  max: {max:.1}ms",
        );

        #[allow(clippy::cast_precision_loss)]
        let budget_ms = model.refresh.as_millis() as f64;
        let budget_pct = if budget_ms > 0.0 {
            (avg / budget_ms) * 100.0
        } else {
            0.0
        };
        let budget_badge = if budget_pct > 80.0 {
            status_badge("OVER", theme.palette.danger, theme.accessibility)
        } else if budget_pct > 50.0 {
            status_badge("HIGH", theme.palette.warning, theme.accessibility)
        } else {
            status_badge("OK", theme.palette.success, theme.accessibility)
        };
        let _ = writeln!(
            out,
            "  budget:  {budget_pct:.0}% of {budget_ms:.0}ms {budget_badge}",
        );

        // Sparkline of recent frame times.
        let normalized = model.frame_times.normalized();
        if !normalized.is_empty() {
            let trace = sparkline(&normalized);
            let _ = writeln!(
                out,
                "  history: {trace} ({} samples)",
                model.frame_times.len(),
            );
        }
    } else {
        let _ = writeln!(out, "  no frame data yet");
    }

    // ── Data adapters ──
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", section_header("Data Adapters", width));

    let adapter_total = model.adapter_reads + model.adapter_errors;
    #[allow(clippy::cast_precision_loss)]
    let error_rate = if adapter_total > 0 {
        (model.adapter_errors as f64 / adapter_total as f64) * 100.0
    } else {
        0.0
    };
    let adapter_badge = if model.adapter_errors == 0 {
        status_badge("OK", theme.palette.success, theme.accessibility)
    } else if error_rate < 10.0 {
        status_badge("DEGRADED", theme.palette.warning, theme.accessibility)
    } else {
        status_badge("FAILING", theme.palette.danger, theme.accessibility)
    };
    let _ = writeln!(
        out,
        "  state-adapter: {adapter_badge} reads={} errors={} ({error_rate:.0}%)",
        model.adapter_reads, model.adapter_errors,
    );

    // ── Telemetry backends ──
    let sources = [
        ("timeline", model.timeline_source, model.timeline_partial),
        (
            "explainability",
            model.explainability_source,
            model.explainability_partial,
        ),
        (
            "candidates",
            model.candidates_source,
            model.candidates_partial,
        ),
    ];
    for (name, source, partial) in &sources {
        let src_label = match source {
            DataSource::Sqlite => "SQLite",
            DataSource::Jsonl => "JSONL",
            DataSource::None => "none",
        };
        let src_badge = if matches!(source, DataSource::None) {
            status_badge("INACTIVE", theme.palette.muted, theme.accessibility)
        } else if *partial {
            status_badge("PARTIAL", theme.palette.warning, theme.accessibility)
        } else {
            status_badge("OK", theme.palette.success, theme.accessibility)
        };
        let _ = writeln!(out, "  {name:<16} {src_badge} source={src_label}");
    }

    // ── Terminal ──
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", section_header("Terminal", width));
    let _ = writeln!(
        out,
        "  size:    {}x{}",
        model.terminal_size.0, model.terminal_size.1,
    );
    let _ = writeln!(
        out,
        "  theme:   {} spacing={}",
        color_mode_label(theme),
        spacing_mode_label(theme),
    );

    // ── Daemon process (verbose) ──
    if model.diagnostics_verbose {
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", section_header("Daemon Process", width));
        if let Some(ref state) = model.daemon_state {
            let _ = writeln!(out, "  version: {}", state.version);
            let _ = writeln!(out, "  pid:     {}", state.pid);
            let _ = writeln!(out, "  uptime:  {}", human_duration(state.uptime_seconds),);
            let _ = writeln!(out, "  rss:     {}", human_bytes(state.memory_rss_bytes));
            let _ = writeln!(
                out,
                "  scans={} deletions={} errors={} dropped={}",
                state.counters.scans,
                state.counters.deletions,
                state.counters.errors,
                state.counters.dropped_log_events,
            );
        } else {
            let _ = writeln!(out, "  daemon not connected");
        }

        // ── Screen state summary ──
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", section_header("Screen State", width));
        let _ = writeln!(out, "  active:      {}", screen_label(model.screen));
        let _ = writeln!(out, "  history:     {} entries", model.screen_history.len(),);
        let _ = writeln!(out, "  rate-mounts: {} tracked", model.rate_histories.len(),);
        let _ = writeln!(
            out,
            "  timeline:    {} events (filter={})",
            model.timeline_events.len(),
            model.timeline_filter.label(),
        );
        let _ = writeln!(
            out,
            "  decisions:   {}",
            model.explainability_decisions.len(),
        );
        let _ = writeln!(
            out,
            "  candidates:  {} (sort={})",
            model.candidates_list.len(),
            model.candidates_sort.label(),
        );
    }

    // ── Navigation hint ──
    let verbose_label = if model.diagnostics_verbose {
        "on"
    } else {
        "off"
    };
    write_navigation_hint(
        model,
        out,
        &format!("V verbose ({verbose_label})  r refresh  ? help  : palette  q quit"),
        "V verbose  r refresh  q quit",
    );
}

// ──────────────────── S5: Ballast Operations ────────────────────

fn render_ballast(model: &DashboardModel, theme: &Theme, out: &mut String) {
    use std::fmt::Write as _;
    let width = usize::from(model.terminal_size.0).max(40);

    // ── Data-source header ──
    let source_label = match model.ballast_source {
        DataSource::Sqlite => "SQLite",
        DataSource::Jsonl => "JSONL",
        DataSource::None => "none",
    };
    let health_badge = if model.ballast_source == DataSource::None {
        status_badge("NO DATA", theme.palette.muted, theme.accessibility)
    } else if model.ballast_partial {
        status_badge("PARTIAL", theme.palette.warning, theme.accessibility)
    } else {
        status_badge("OK", theme.palette.success, theme.accessibility)
    };

    let _ = writeln!(
        out,
        "data-source={source_label} {health_badge} volumes={}",
        model.ballast_volumes.len(),
    );

    if !model.ballast_diagnostics.is_empty() {
        let _ = writeln!(out, "  diag: {}", model.ballast_diagnostics);
    }

    // ── Aggregate ballast state from daemon ──
    if let Some(ref state) = model.daemon_state {
        let avail = state.ballast.available;
        let total = state.ballast.total;
        let released = state.ballast.released;
        let aggregate_badge = if total == 0 {
            status_badge("UNCONFIGURED", theme.palette.muted, theme.accessibility)
        } else if avail == 0 {
            status_badge("CRITICAL", theme.palette.critical, theme.accessibility)
        } else if avail.saturating_mul(2) < total {
            status_badge("LOW", theme.palette.warning, theme.accessibility)
        } else {
            status_badge("OK", theme.palette.success, theme.accessibility)
        };
        let _ = writeln!(
            out,
            "ballast: {avail}/{total} available, {released} released {aggregate_badge}",
        );
    }

    // ── Empty state ──
    if model.ballast_volumes.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "No ballast volume data available. The daemon must be running with"
        );
        let _ = writeln!(out, "ballast pools configured to populate this screen.");
        let _ = writeln!(
            out,
            "Press r to force refresh, or check daemon status with key 1."
        );
        write_navigation_hint(
            model,
            out,
            "j/k or \u{2191}/\u{2193} navigate  Enter/Space expand  d close  r refresh  ? help  : palette",
            "j/k navigate  Enter/Space detail  d close  r refresh",
        );
        return;
    }

    // ── Volume inventory table ──
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", section_header("Ballast Volumes", width));

    // Column headers.
    let _ = writeln!(
        out,
        "  {:<4} {:<12} {:<20} {:<8} {:<8} {:<10} RELEASABLE",
        "#", "STATUS", "MOUNT", "FILES", "FS", "STRATEGY"
    );

    for (i, vol) in model.ballast_volumes.iter().enumerate() {
        let cursor = if i == model.ballast_selected {
            ">"
        } else {
            " "
        };
        let status = vol.status_level();
        let status_color = match status {
            "OK" => theme.palette.success,
            "LOW" => theme.palette.warning,
            "CRITICAL" => theme.palette.critical,
            _ => theme.palette.muted,
        };
        let badge = status_badge(status, status_color, theme.accessibility);
        let files = format!("{}/{}", vol.files_available, vol.files_total);
        let mount_short = truncate_path(&vol.mount_point, 20);
        let releasable = human_bytes(vol.releasable_bytes);
        let _ = writeln!(
            out,
            "{cursor} {:<4} {badge} {:<20} {:<8} {:<8} {:<10} {}",
            i + 1,
            mount_short,
            files,
            vol.fs_type,
            vol.strategy,
            releasable,
        );
    }

    // ── Total releasable ──
    let total_releasable: u64 = model
        .ballast_volumes
        .iter()
        .filter(|v| !v.skipped)
        .map(|v| v.releasable_bytes)
        .sum();
    if total_releasable > 0 {
        let _ = writeln!(out, "total releasable: {}", human_bytes(total_releasable));
    }

    // ── Skipped summary ──
    let skipped_count = model.ballast_volumes.iter().filter(|v| v.skipped).count();
    if skipped_count > 0 {
        let skip_badge = status_badge("SKIPPED", theme.palette.muted, theme.accessibility);
        let _ = writeln!(out, "{skipped_count} volume(s) {skip_badge}");
    }

    // ── Detail pane ──
    if model.ballast_detail {
        if let Some(vol) = model.ballast_selected_volume() {
            let _ = writeln!(out);
            let _ = writeln!(out, "{}", section_header("Volume Detail", width));
            render_volume_detail(vol, theme, out);
        }
    } else {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Press Enter/Space to expand detail for selected volume"
        );
    }

    write_navigation_hint(
        model,
        out,
        "j/k or \u{2191}/\u{2193} navigate  Enter/Space expand  d close  r refresh  ? help  : palette",
        "j/k navigate  Enter/Space detail  d close  r refresh",
    );
}

fn render_volume_detail(vol: &BallastVolume, theme: &Theme, out: &mut String) {
    use std::fmt::Write as _;

    let _ = writeln!(out, "  mount:      {}", vol.mount_point);
    let _ = writeln!(out, "  ballast:    {}", vol.ballast_dir);
    let _ = writeln!(out, "  fs-type:    {}", vol.fs_type);
    let _ = writeln!(out, "  strategy:   {}", vol.strategy);
    let _ = writeln!(
        out,
        "  files:      {}/{}",
        vol.files_available, vol.files_total
    );
    let _ = writeln!(
        out,
        "  releasable: {} ({} bytes)",
        human_bytes(vol.releasable_bytes),
        vol.releasable_bytes
    );

    // Status badge.
    let status = vol.status_level();
    let status_color = match status {
        "OK" => theme.palette.success,
        "LOW" => theme.palette.warning,
        "CRITICAL" => theme.palette.critical,
        _ => theme.palette.muted,
    };
    let badge = status_badge(status, status_color, theme.accessibility);
    let _ = writeln!(out, "  status:     {badge}");

    if vol.skipped
        && let Some(ref reason) = vol.skip_reason
    {
        let _ = writeln!(out, "  skip-reason: {reason}");
    }

    // File fill gauge.
    if vol.files_total > 0 {
        #[allow(clippy::cast_precision_loss)]
        let fill_pct = (vol.files_available as f64 / vol.files_total as f64) * 100.0;
        let bar = gauge(fill_pct, 20);
        let _ = writeln!(out, "  fill: {bar}");
    }
}

/// Map policy mode string to a `PaletteEntry` for `status_badge`.
fn policy_mode_palette(mode: &str, palette: &ThemePalette) -> PaletteEntry {
    match mode {
        "enforce" => palette.success,
        "canary" => palette.warning,
        "observe" => palette.accent,
        "fallback_safe" => palette.critical,
        _ => palette.muted,
    }
}

/// Map policy mode string to a display color for frame-based rendering.
fn policy_mode_color(mode: &str, palette: &ThemePalette) -> PackedRgba {
    match mode {
        "enforce" => palette.success_color(),
        "canary" => palette.warning_color(),
        "observe" => palette.accent_color(),
        "fallback_safe" => palette.critical_color(),
        _ => palette.muted_color(),
    }
}

fn notification_badge(
    palette: &ThemePalette,
    accessibility: AccessibilityProfile,
    level: NotificationLevel,
) -> String {
    match level {
        NotificationLevel::Info => status_badge("INFO", palette.accent, accessibility),
        NotificationLevel::Warning => status_badge("WARN", palette.warning, accessibility),
        NotificationLevel::Error => status_badge("ERROR", palette.critical, accessibility),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use super::*;
    use crate::daemon::self_monitor::{
        BallastState, Counters, DaemonState, LastScanState, MountPressure, PressureState,
    };
    use crate::tui::model::{Overlay, SeverityFilter};

    fn sample_state(level: &str, free_pct: f64) -> DaemonState {
        DaemonState {
            version: String::from("0.1.0"),
            pid: 1234,
            started_at: String::from("2026-02-16T00:00:00Z"),
            uptime_seconds: 1_337,
            last_updated: String::from("2026-02-16T01:00:00Z"),
            pressure: PressureState {
                overall: level.to_string(),
                mounts: vec![MountPressure {
                    path: String::from("/"),
                    free_pct,
                    level: level.to_string(),
                    rate_bps: Some(-4096.0),
                }],
            },
            ballast: BallastState {
                available: 2,
                total: 4,
                released: 2,
            },
            last_scan: LastScanState {
                at: Some(String::from("2026-02-16T00:59:00Z")),
                candidates: 12,
                deleted: 3,
            },
            counters: Counters {
                scans: 100,
                deletions: 5,
                bytes_freed: 1_024_000,
                errors: 1,
                dropped_log_events: 0,
            },
            policy_mode: "enforce".into(),
            memory_rss_bytes: 52_428_800,
        }
    }

    #[test]
    fn render_includes_mode_and_dimensions() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![PathBuf::from("/tmp")],
            Duration::from_secs(1),
            (120, 42),
        );
        model.tick = 9;
        model.degraded = false;

        let frame = render(&model);
        assert!(frame.contains("NORMAL"));
        assert!(frame.contains("tick=9"));
        assert!(frame.contains("120x42"));
        assert!(frame.contains("[S1 Overview]"));
        assert!(frame.contains("theme="));
    }

    #[test]
    fn render_header_includes_active_preference_profile() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 42),
        );
        model.set_preference_profile(
            StartScreen::Timeline,
            DensityMode::Compact,
            HintVerbosity::Off,
            PreferenceProfileMode::SessionOverride,
        );
        let frame = render(&model);
        assert!(frame.contains("prefs mode=session"));
        assert!(frame.contains("start=timeline"));
        assert!(frame.contains("density=compact"));
        assert!(frame.contains("hints=off"));
    }

    #[test]
    fn render_reports_terminal_too_small() {
        let model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (30, 7),
        );

        let frame = render(&model);
        assert!(frame.contains("terminal-too-small"));
        assert!(frame.contains("need >= 40x8"));
    }

    #[test]
    fn hint_verbosity_off_hides_navigation_hints_but_keeps_safety_signal() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 40),
        );
        model.degraded = false;
        model.daemon_state = Some(sample_state("red", 4.2));
        model.hint_verbosity = HintVerbosity::Off;
        model.screen = Screen::Overview;

        let frame = render(&model);
        assert!(!frame.contains("? help"));
        assert!(frame.contains("pressure"));
        assert!(frame.contains("RED"));
    }

    #[test]
    fn render_log_search_screen_shows_real_content() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (80, 24),
        );
        model.screen = Screen::LogSearch;
        let frame = render(&model);
        assert!(frame.contains("[S6 Logs]"));
        assert!(frame.contains("query=<preview>"));
        assert!(!frame.contains("implementation pending"));
    }

    #[test]
    fn render_shows_overlay_indicator() {
        use super::super::model::Overlay;
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (80, 24),
        );
        model.active_overlay = Some(Overlay::Help);
        let frame = render(&model);
        assert!(frame.contains("overlay"));
        assert!(frame.contains("Help"));
    }

    #[test]
    fn render_shows_notifications() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (80, 24),
        );
        model.push_notification(NotificationLevel::Error, "disk full".into());
        let frame = render(&model);
        assert!(frame.contains("disk full"));
        assert!(frame.contains("ERROR"));
        assert!(frame.contains("toast#"));
    }

    fn multi_mount_state() -> DaemonState {
        DaemonState {
            version: String::from("0.1.0"),
            pid: 4567,
            started_at: String::from("2026-02-16T00:00:00Z"),
            uptime_seconds: 7200,
            last_updated: String::from("2026-02-16T02:00:00Z"),
            pressure: PressureState {
                overall: String::from("yellow"),
                mounts: vec![
                    MountPressure {
                        path: String::from("/"),
                        free_pct: 22.5,
                        level: String::from("green"),
                        rate_bps: Some(-500.0),
                    },
                    MountPressure {
                        path: String::from("/data"),
                        free_pct: 8.3,
                        level: String::from("yellow"),
                        rate_bps: Some(2_000_000.0),
                    },
                ],
            },
            ballast: BallastState {
                available: 1,
                total: 4,
                released: 3,
            },
            last_scan: LastScanState {
                at: Some(String::from("2026-02-16T01:45:30.123Z")),
                candidates: 42,
                deleted: 7,
            },
            counters: Counters {
                scans: 200,
                deletions: 15,
                bytes_freed: 2_147_483_648,
                errors: 3,
                dropped_log_events: 1,
            },
            policy_mode: "enforce".into(),
            memory_rss_bytes: 104_857_600,
        }
    }

    #[test]
    fn overview_uses_layout_and_pressure_priority() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.degraded = false;
        model.daemon_state = Some(sample_state("red", 4.2));
        model
            .rate_histories
            .entry(String::from("/"))
            .or_insert_with(|| super::super::model::RateHistory::new(30))
            .push(-4096.0);

        let frame = render(&model);
        assert!(frame.contains("overview-layout=Wide"));
        assert!(frame.contains("[pressure-summary p0"));
        assert!(frame.contains("RED"));
        assert!(frame.contains("ballast"));
    }

    #[test]
    fn pressure_shows_per_mount_detail() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.daemon_state = Some(multi_mount_state());

        let frame = render(&model);
        // Both mounts appear with their paths.
        assert!(frame.contains("/data"));
        assert!(frame.contains("[GREEN]"));
        assert!(frame.contains("[YELLOW]"));
        // Mount with positive rate + free > 0 shows warning.
        assert!(frame.contains("\u{26a0}"));
        // Per-mount gauge present.
        assert!(frame.contains("22.5% free"));
        assert!(frame.contains("8.3% free"));
    }

    #[test]
    fn ewma_shows_all_mounts_with_trend_labels() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        for mount in ["/", "/data", "/home", "/var"] {
            let h = model
                .rate_histories
                .entry(mount.to_string())
                .or_insert_with(|| super::super::model::RateHistory::new(30));
            h.push(500.0);
        }

        let frame = render(&model);
        // All 4 mounts visible (no longer capped at 3).
        assert!(frame.contains("ewma 4 mounts"));
        assert!(frame.contains("/home"));
        assert!(frame.contains("/var"));
        // Smart rate formatting present.
        assert!(frame.contains("B/s"));
        // Trend label present.
        assert!(frame.contains("(stable)"));
    }

    #[test]
    fn action_lane_formats_freed_bytes() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.daemon_state = Some(multi_mount_state());

        let frame = render(&model);
        // 2_147_483_648 bytes = 2.0 GB
        assert!(frame.contains("freed=2.0 GB"));
    }

    #[test]
    fn recent_activity_extracts_time() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.daemon_state = Some(multi_mount_state());

        let frame = render(&model);
        // Time portion extracted from "2026-02-16T01:45:30.123Z".
        assert!(frame.contains("last-scan=01:45:30"));
        assert!(!frame.contains("2026-02-16T01:45:30"));
    }

    #[test]
    fn counters_show_human_rss_and_uptime() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.daemon_state = Some(multi_mount_state());

        let frame = render(&model);
        // 104_857_600 bytes = 100.0 MB
        assert!(frame.contains("rss=100.0 MB"));
        // PID visible.
        assert!(frame.contains("pid=4567"));
        // 7200 seconds = 2h 00m
        assert!(frame.contains("uptime=2h 00m"));
    }

    #[test]
    fn degraded_pressure_lists_monitor_paths() {
        let model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![PathBuf::from("/"), PathBuf::from("/data")],
            Duration::from_secs(1),
            (120, 30),
        );
        assert!(model.degraded);
        assert!(model.daemon_state.is_none());

        let frame = render(&model);
        assert!(frame.contains("DEGRADED"));
        assert!(frame.contains("paths=2"));
    }

    // ── S3 Explainability screen tests ──

    use crate::tui::telemetry::FactorBreakdown;

    fn sample_decision(
        id: u64,
        action: &str,
        vetoed: bool,
    ) -> crate::tui::telemetry::DecisionEvidence {
        crate::tui::telemetry::DecisionEvidence {
            decision_id: id,
            timestamp: String::from("2026-02-16T03:15:42Z"),
            path: String::from("/data/projects/test-proj/target/debug"),
            size_bytes: 524_288_000,
            age_secs: 7200,
            action: action.to_string(),
            effective_action: Some(action.to_string()),
            policy_mode: String::from("live"),
            factors: FactorBreakdown {
                location: 0.80,
                name: 0.75,
                age: 0.90,
                size: 0.60,
                structure: 0.85,
                pressure_multiplier: 1.3,
            },
            total_score: 2.15,
            posterior_abandoned: 0.87,
            expected_loss_keep: 26.1,
            expected_loss_delete: 13.0,
            calibration_score: 0.82,
            vetoed,
            veto_reason: if vetoed {
                Some(String::from("contains .git"))
            } else {
                None
            },
            guard_status: Some(String::from("Pass")),
            summary: String::from("High-confidence build artifact, scored above threshold"),
            raw_json: None,
        }
    }

    #[test]
    fn explainability_empty_shows_no_data_message() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Explainability;

        let frame = render(&model);
        assert!(frame.contains("[S3 Explain]"));
        assert!(frame.contains("NO DATA") || frame.contains("no data"));
        assert!(frame.contains("No decision evidence available"));
    }

    #[test]
    fn explainability_shows_decisions_list() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Explainability;
        model.explainability_decisions = vec![
            sample_decision(42, "delete", false),
            sample_decision(43, "keep", false),
        ];
        model.explainability_source = crate::tui::telemetry::DataSource::Sqlite;

        let frame = render(&model);
        assert!(frame.contains("[S3 Explain]"));
        assert!(frame.contains("data-source=SQLite"));
        assert!(frame.contains("decisions=2"));
        assert!(frame.contains("#42"));
        assert!(frame.contains("#43"));
        assert!(frame.contains("DELETE"));
        assert!(frame.contains("KEEP"));
        assert!(frame.contains("Recent Decisions"));
    }

    #[test]
    fn explainability_shows_veto_marker() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Explainability;
        model.explainability_decisions = vec![sample_decision(99, "delete", true)];

        let frame = render(&model);
        assert!(frame.contains("VETOED"));
    }

    #[test]
    fn explainability_detail_shows_factor_breakdown() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 40),
        );
        model.screen = Screen::Explainability;
        model.explainability_decisions = vec![sample_decision(42, "delete", false)];
        model.explainability_detail = true;

        let frame = render(&model);
        assert!(frame.contains("Decision Detail"));
        assert!(frame.contains("Factor Breakdown"));
        assert!(frame.contains("location"));
        assert!(frame.contains("0.80"));
        assert!(frame.contains("Bayesian Decision"));
        assert!(frame.contains("P(abandoned)"));
        assert!(frame.contains("0.8700"));
        assert!(frame.contains("calibration"));
    }

    #[test]
    fn explainability_detail_shows_veto_reason() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 40),
        );
        model.screen = Screen::Explainability;
        model.explainability_decisions = vec![sample_decision(99, "delete", true)];
        model.explainability_detail = true;

        let frame = render(&model);
        assert!(frame.contains("VETOED"));
        assert!(frame.contains("contains .git"));
    }

    #[test]
    fn explainability_shows_confidence_badge() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 40),
        );
        model.screen = Screen::Explainability;
        model.explainability_decisions = vec![sample_decision(42, "delete", false)];
        model.explainability_detail = true;

        let frame = render(&model);
        // calibration_score = 0.82 => MODERATE confidence
        assert!(frame.contains("MODERATE"));
    }

    #[test]
    fn explainability_partial_data_shows_warning() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Explainability;
        model.explainability_decisions = vec![sample_decision(1, "keep", false)];
        model.explainability_source = crate::tui::telemetry::DataSource::Jsonl;
        model.explainability_partial = true;
        model.explainability_diagnostics = "SQLite unavailable, using JSONL fallback".into();

        let frame = render(&model);
        assert!(frame.contains("PARTIAL"));
        assert!(frame.contains("JSONL"));
        assert!(frame.contains("SQLite unavailable"));
    }

    #[test]
    fn explainability_cursor_indicator() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Explainability;
        model.explainability_decisions = vec![
            sample_decision(1, "delete", false),
            sample_decision(2, "keep", false),
        ];
        model.explainability_selected = 1;

        let frame = render(&model);
        // Second decision should have the cursor marker
        let lines: Vec<&str> = frame.lines().collect();
        let cursor_line = lines.iter().find(|l| l.contains("#2") && l.contains('>'));
        assert!(cursor_line.is_some(), "cursor should be on decision #2");
    }

    #[test]
    fn truncate_path_preserves_short_paths() {
        assert_eq!(truncate_path("/short/path", 40), "/short/path");
    }

    #[test]
    fn truncate_path_truncates_long_paths_at_boundary() {
        let long = "/very/long/deeply/nested/project/target/debug/build/artifact";
        let truncated = truncate_path(long, 30);
        assert!(truncated.len() <= 35); // might be slightly longer due to boundary
        assert!(truncated.starts_with('/'));
    }

    // ── S2 Timeline screen tests ──

    use crate::tui::telemetry::TimelineEvent as TlEvent;

    fn sample_timeline_event(severity: &str, event_type: &str) -> TlEvent {
        TlEvent {
            timestamp: String::from("2026-02-16T03:15:42Z"),
            event_type: event_type.to_owned(),
            severity: severity.to_owned(),
            path: Some(String::from("/data/projects/test/target/debug")),
            size_bytes: Some(524_288_000),
            score: Some(2.15),
            pressure_level: Some(String::from("yellow")),
            free_pct: Some(12.5),
            success: Some(true),
            error_code: None,
            error_message: None,
            duration_ms: Some(150),
            details: Some(String::from("artifact cleanup")),
        }
    }

    #[test]
    fn timeline_empty_shows_no_events_message() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Timeline;

        let frame = render(&model);
        assert!(frame.contains("[S2 Timeline]"));
        assert!(frame.contains("events=0/0"));
        assert!(frame.contains("No timeline events available"));
    }

    #[test]
    fn timeline_shows_event_list() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Timeline;
        model.timeline_events = vec![
            sample_timeline_event("info", "scan_complete"),
            sample_timeline_event("warning", "pressure_change"),
        ];
        model.timeline_source = DataSource::Sqlite;

        let frame = render(&model);
        assert!(frame.contains("events=2/2"));
        assert!(frame.contains("data-source=SQLite"));
        assert!(frame.contains("scan_complete"));
        assert!(frame.contains("pressure_change"));
    }

    #[test]
    fn timeline_filter_shows_subset_count() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Timeline;
        model.timeline_events = vec![
            sample_timeline_event("info", "scan"),
            sample_timeline_event("warning", "pressure_change"),
            sample_timeline_event("critical", "artifact_delete"),
        ];
        model.timeline_filter = SeverityFilter::Warning;

        let frame = render(&model);
        assert!(frame.contains("filter=warning"));
        assert!(frame.contains("events=1/3"));
    }

    #[test]
    fn timeline_follow_mode_shows_indicator() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Timeline;
        model.timeline_follow = true;

        let frame = render(&model);
        assert!(frame.contains("[FOLLOW]"));
    }

    #[test]
    fn timeline_cursor_shows_marker() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Timeline;
        model.timeline_events = vec![
            sample_timeline_event("info", "first"),
            sample_timeline_event("info", "second"),
        ];
        model.timeline_selected = 1;

        let frame = render(&model);
        let lines: Vec<&str> = frame.lines().collect();
        let cursor_line = lines
            .iter()
            .find(|l| l.contains("second") && l.starts_with('>'));
        assert!(cursor_line.is_some(), "cursor should be on second event");
    }

    #[test]
    fn timeline_wide_shows_event_detail() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (140, 30),
        );
        model.screen = Screen::Timeline;
        model.timeline_events = vec![sample_timeline_event("info", "scan_complete")];

        let frame = render(&model);
        assert!(frame.contains("Event Detail"));
        assert!(frame.contains("timestamp:"));
        assert!(frame.contains("artifact cleanup"));
    }

    #[test]
    fn timeline_empty_filter_shows_hint() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Timeline;
        model.timeline_events = vec![sample_timeline_event("info", "scan")];
        model.timeline_filter = SeverityFilter::Critical;

        let frame = render(&model);
        assert!(frame.contains("events=0/1"));
        assert!(frame.contains("No events match"));
    }

    #[test]
    fn timeline_partial_data_shows_warning() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Timeline;
        model.timeline_source = DataSource::Jsonl;
        model.timeline_partial = true;
        model.timeline_diagnostics = "SQLite unavailable".into();

        let frame = render(&model);
        assert!(frame.contains("PARTIAL"));
        assert!(frame.contains("SQLite unavailable"));
    }

    #[test]
    fn timeline_severity_badges() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Timeline;
        model.timeline_events = vec![
            sample_timeline_event("info", "a"),
            sample_timeline_event("warning", "b"),
            sample_timeline_event("critical", "c"),
        ];

        let frame = render(&model);
        assert!(frame.contains("INFO"));
        assert!(frame.contains("WARNING"));
        assert!(frame.contains("CRITICAL"));
    }

    // ── S4 Candidates screen tests ──

    fn sample_candidate(
        id: u64,
        action: &str,
        vetoed: bool,
        score: f64,
        size: u64,
    ) -> crate::tui::telemetry::DecisionEvidence {
        crate::tui::telemetry::DecisionEvidence {
            decision_id: id,
            timestamp: String::from("2026-02-16T04:30:00Z"),
            path: String::from("/data/projects/myapp/target/debug"),
            size_bytes: size,
            age_secs: 3600,
            action: action.to_string(),
            effective_action: Some(action.to_string()),
            policy_mode: String::from("live"),
            factors: FactorBreakdown {
                location: 0.80,
                name: 0.75,
                age: 0.90,
                size: 0.60,
                structure: 0.85,
                pressure_multiplier: 1.3,
            },
            total_score: score,
            posterior_abandoned: 0.87,
            expected_loss_keep: 26.1,
            expected_loss_delete: 13.0,
            calibration_score: 0.82,
            vetoed,
            veto_reason: if vetoed {
                Some(String::from("path contains .git"))
            } else {
                None
            },
            guard_status: Some(String::from("Pass")),
            summary: String::from("Build artifact candidate"),
            raw_json: None,
        }
    }

    #[test]
    fn candidates_empty_shows_no_data_message() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Candidates;

        let frame = render(&model);
        assert!(frame.contains("[S4 Candidates]"));
        assert!(frame.contains("NO DATA") || frame.contains("no data"));
        assert!(frame.contains("No scan candidates available"));
    }

    #[test]
    fn candidates_shows_ranking_list() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Candidates;
        model.candidates_list = vec![
            sample_candidate(10, "delete", false, 2.15, 524_288_000),
            sample_candidate(11, "keep", false, 0.45, 1_048_576),
        ];
        model.candidates_source = crate::tui::telemetry::DataSource::Sqlite;

        let frame = render(&model);
        assert!(frame.contains("[S4 Candidates]"));
        assert!(frame.contains("data-source=SQLite"));
        assert!(frame.contains("candidates=2"));
        assert!(frame.contains("Scan Candidates"));
        assert!(frame.contains("DELETE"));
        assert!(frame.contains("KEEP"));
    }

    #[test]
    fn candidates_shows_veto_markers() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Candidates;
        model.candidates_list = vec![
            sample_candidate(10, "delete", true, 2.15, 100_000),
            sample_candidate(11, "delete", false, 1.50, 200_000),
        ];

        let frame = render(&model);
        assert!(frame.contains("VETOED"));
        assert!(frame.contains("1 candidate(s)"));
        assert!(frame.contains("protected from deletion"));
    }

    #[test]
    fn candidates_shows_sort_indicator() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Candidates;
        model.candidates_list = vec![sample_candidate(1, "delete", false, 2.0, 1000)];

        let frame = render(&model);
        assert!(frame.contains("sort=score"));
    }

    #[test]
    fn candidates_cursor_indicator() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Candidates;
        model.candidates_list = vec![
            sample_candidate(1, "delete", false, 2.0, 1000),
            sample_candidate(2, "keep", false, 0.5, 2000),
        ];
        model.candidates_selected = 1;

        let frame = render(&model);
        let lines: Vec<&str> = frame.lines().collect();
        let cursor_line = lines.iter().find(|l| l.contains('2') && l.starts_with('>'));
        assert!(cursor_line.is_some(), "cursor should be on candidate #2");
    }

    #[test]
    fn candidates_detail_shows_score_breakdown() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 40),
        );
        model.screen = Screen::Candidates;
        model.candidates_list = vec![sample_candidate(42, "delete", false, 2.15, 524_288_000)];
        model.candidates_detail = true;

        let frame = render(&model);
        assert!(frame.contains("Candidate Detail"));
        assert!(frame.contains("Score Breakdown"));
        assert!(frame.contains("location"));
        assert!(frame.contains("0.80"));
        assert!(frame.contains("Decision Statistics"));
        assert!(frame.contains("P(abandoned)"));
    }

    #[test]
    fn candidates_detail_shows_veto_reason() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 40),
        );
        model.screen = Screen::Candidates;
        model.candidates_list = vec![sample_candidate(99, "delete", true, 2.0, 1000)];
        model.candidates_detail = true;

        let frame = render(&model);
        assert!(frame.contains("VETOED"));
        assert!(frame.contains("path contains .git"));
    }

    #[test]
    fn candidates_shows_reclaim_estimate() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Candidates;
        model.candidates_list = vec![
            sample_candidate(1, "delete", false, 2.0, 1_073_741_824),
            sample_candidate(2, "delete", false, 1.5, 524_288_000),
            sample_candidate(3, "keep", false, 0.3, 100_000_000),
        ];

        let frame = render(&model);
        // Only delete (non-vetoed) candidates counted: 1GB + 500MB = 1.5GB
        assert!(frame.contains("estimated reclaimable: 1.5 GB"));
    }

    #[test]
    fn candidates_partial_data_shows_warning() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Candidates;
        model.candidates_list = vec![sample_candidate(1, "keep", false, 0.5, 1000)];
        model.candidates_source = crate::tui::telemetry::DataSource::Jsonl;
        model.candidates_partial = true;
        model.candidates_diagnostics = "SQLite unavailable, using JSONL fallback".into();

        let frame = render(&model);
        assert!(frame.contains("PARTIAL"));
        assert!(frame.contains("JSONL"));
        assert!(frame.contains("SQLite unavailable"));
    }

    #[test]
    fn candidates_confidence_badge_in_detail() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 40),
        );
        model.screen = Screen::Candidates;
        model.candidates_list = vec![sample_candidate(42, "delete", false, 2.15, 1000)];
        model.candidates_detail = true;

        let frame = render(&model);
        // calibration_score = 0.82 => MODERATE confidence
        assert!(frame.contains("MODERATE"));
    }

    // ── S7 Diagnostics screen tests ──

    #[test]
    fn diagnostics_shows_health_section() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Diagnostics;
        model.tick = 42;

        let frame = render(&model);
        assert!(frame.contains("[S7 Diagnostics]"));
        assert!(frame.contains("Dashboard Health"));
        assert!(frame.contains("DEGRADED")); // starts degraded
        assert!(frame.contains("tick:"));
        assert!(frame.contains("42"));
        assert!(frame.contains("refresh=1000ms"));
        assert!(frame.contains("missed-ticks:"));
    }

    #[test]
    fn diagnostics_shows_normal_mode_when_not_degraded() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Diagnostics;
        model.degraded = false;

        let frame = render(&model);
        assert!(frame.contains("NORMAL"));
    }

    #[test]
    fn diagnostics_shows_frame_timing_with_data() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Diagnostics;
        for ms in [2.0, 3.0, 1.5, 4.0, 2.5] {
            model.frame_times.push(ms);
        }

        let frame = render(&model);
        assert!(frame.contains("Frame Timing"));
        assert!(frame.contains("current: 2.5ms"));
        assert!(frame.contains("avg:"));
        assert!(frame.contains("budget:"));
        assert!(frame.contains("5 samples"));
    }

    #[test]
    fn diagnostics_no_frame_data_message() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Diagnostics;

        let frame = render(&model);
        assert!(frame.contains("no frame data yet"));
    }

    #[test]
    fn diagnostics_shows_adapter_health() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Diagnostics;
        model.adapter_reads = 95;
        model.adapter_errors = 5;

        let frame = render(&model);
        assert!(frame.contains("Data Adapters"));
        assert!(frame.contains("reads=95"));
        assert!(frame.contains("errors=5"));
        assert!(frame.contains("DEGRADED")); // 5% error rate < 10%
    }

    #[test]
    fn diagnostics_adapter_ok_with_zero_errors() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Diagnostics;
        model.degraded = false;
        model.adapter_reads = 100;
        model.adapter_errors = 0;

        let frame = render(&model);
        // Should show "OK" for adapter health (not DEGRADED from dashboard mode)
        let adapter_line = frame
            .lines()
            .find(|l| l.contains("state-adapter:"))
            .expect("adapter line");
        assert!(adapter_line.contains("OK") || adapter_line.contains("ok"));
    }

    #[test]
    fn diagnostics_shows_telemetry_sources() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Diagnostics;
        model.timeline_source = DataSource::Sqlite;
        model.explainability_source = DataSource::Jsonl;
        model.explainability_partial = true;

        let frame = render(&model);
        assert!(frame.contains("timeline"));
        assert!(frame.contains("SQLite"));
        assert!(frame.contains("explainability"));
        assert!(frame.contains("JSONL"));
        assert!(frame.contains("PARTIAL"));
        assert!(frame.contains("candidates"));
        assert!(frame.contains("INACTIVE")); // candidates still DataSource::None
    }

    #[test]
    fn diagnostics_shows_terminal_info() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Diagnostics;

        let frame = render(&model);
        assert!(frame.contains("Terminal"));
        assert!(frame.contains("120x30"));
    }

    #[test]
    fn diagnostics_verbose_shows_daemon_and_screen_state() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 40),
        );
        model.screen = Screen::Diagnostics;
        model.diagnostics_verbose = true;
        model.daemon_state = Some(sample_state("green", 80.0));

        let frame = render(&model);
        assert!(frame.contains("Daemon Process"));
        assert!(frame.contains("pid:"));
        assert!(frame.contains("1234"));
        assert!(frame.contains("rss:"));
        assert!(frame.contains("Screen State"));
        assert!(frame.contains("active:"));
        assert!(frame.contains("S7 Diagnostics"));
    }

    #[test]
    fn diagnostics_verbose_off_hides_daemon_section() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Diagnostics;
        model.diagnostics_verbose = false;
        model.daemon_state = Some(sample_state("green", 80.0));

        let frame = render(&model);
        assert!(!frame.contains("Daemon Process"));
        assert!(!frame.contains("Screen State"));
    }

    #[test]
    fn diagnostics_navigation_hint() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Diagnostics;

        let frame = render(&model);
        assert!(frame.contains("V verbose"));
        assert!(frame.contains("(off)"));

        model.diagnostics_verbose = true;
        let frame = render(&model);
        assert!(frame.contains("(on)"));
    }

    #[test]
    fn diagnostics_budget_badge_reflects_load() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Diagnostics;
        // avg = 900ms, budget = 1000ms → 90% → OVER badge
        for _ in 0..10 {
            model.frame_times.push(900.0);
        }

        let frame = render(&model);
        assert!(frame.contains("OVER"));
    }

    #[test]
    fn diagnostics_adapter_failing_at_high_error_rate() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Diagnostics;
        model.adapter_reads = 5;
        model.adapter_errors = 15; // 75% error rate

        let frame = render(&model);
        let adapter_line = frame
            .lines()
            .find(|l| l.contains("state-adapter:"))
            .expect("adapter line");
        assert!(adapter_line.contains("FAILING"));
    }

    // ── S5 Ballast screen tests ──

    use crate::tui::model::BallastVolume;

    fn sample_ballast_volume(
        mount: &str,
        available: usize,
        total: usize,
        releasable: u64,
        skipped: bool,
    ) -> BallastVolume {
        BallastVolume {
            mount_point: mount.to_string(),
            ballast_dir: format!("{mount}/.sbh/ballast"),
            fs_type: String::from("ext4"),
            strategy: String::from("fallocate"),
            files_available: available,
            files_total: total,
            releasable_bytes: releasable,
            skipped,
            skip_reason: if skipped {
                Some(String::from("unsupported filesystem"))
            } else {
                None
            },
        }
    }

    #[test]
    fn ballast_empty_shows_no_data_message() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Ballast;

        let frame = render(&model);
        assert!(frame.contains("[S5 Ballast]"));
        assert!(frame.contains("NO DATA") || frame.contains("no data"));
        assert!(frame.contains("No ballast volume data available"));
    }

    #[test]
    fn ballast_shows_volume_list() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Ballast;
        model.ballast_volumes = vec![
            sample_ballast_volume("/", 3, 5, 3_221_225_472, false),
            sample_ballast_volume("/data", 2, 5, 2_147_483_648, false),
        ];
        model.ballast_source = DataSource::Sqlite;

        let frame = render(&model);
        assert!(frame.contains("[S5 Ballast]"));
        assert!(frame.contains("data-source=SQLite"));
        assert!(frame.contains("volumes=2"));
        assert!(frame.contains("Ballast Volumes"));
        assert!(frame.contains("ext4"));
        assert!(frame.contains("fallocate"));
    }

    #[test]
    fn ballast_shows_status_badges() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Ballast;
        model.ballast_volumes = vec![
            sample_ballast_volume("/", 4, 5, 4_294_967_296, false),
            sample_ballast_volume("/data", 1, 5, 1_073_741_824, false),
            sample_ballast_volume("/mnt/nfs", 0, 0, 0, true),
        ];

        let frame = render(&model);
        assert!(frame.contains("OK"));
        assert!(frame.contains("LOW"));
        assert!(frame.contains("SKIPPED"));
    }

    #[test]
    fn ballast_shows_total_releasable() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Ballast;
        model.ballast_volumes = vec![
            sample_ballast_volume("/", 3, 5, 1_073_741_824, false),
            sample_ballast_volume("/data", 2, 5, 2_147_483_648, false),
        ];

        let frame = render(&model);
        assert!(frame.contains("total releasable: 3.0 GB"));
    }

    #[test]
    fn ballast_shows_skipped_summary() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Ballast;
        model.ballast_volumes = vec![
            sample_ballast_volume("/", 3, 5, 3_221_225_472, false),
            sample_ballast_volume("/mnt/nfs", 0, 0, 0, true),
        ];

        let frame = render(&model);
        assert!(frame.contains("1 volume(s)"));
        assert!(frame.contains("SKIPPED"));
    }

    #[test]
    fn ballast_cursor_indicator() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Ballast;
        model.ballast_volumes = vec![
            sample_ballast_volume("/", 3, 5, 3_221_225_472, false),
            sample_ballast_volume("/data", 2, 5, 2_147_483_648, false),
        ];
        model.ballast_selected = 1;

        let frame = render(&model);
        let lines: Vec<&str> = frame.lines().collect();
        let cursor_line = lines
            .iter()
            .find(|l| l.contains("/data") && l.starts_with('>'));
        assert!(cursor_line.is_some(), "cursor should be on /data volume");
    }

    #[test]
    fn ballast_detail_shows_volume_info() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 40),
        );
        model.screen = Screen::Ballast;
        model.ballast_volumes = vec![sample_ballast_volume("/", 3, 5, 3_221_225_472, false)];
        model.ballast_detail = true;

        let frame = render(&model);
        assert!(frame.contains("Volume Detail"));
        assert!(frame.contains("mount:"));
        assert!(frame.contains("ballast:"));
        assert!(frame.contains("/.sbh/ballast"));
        assert!(frame.contains("fs-type:"));
        assert!(frame.contains("strategy:"));
        assert!(frame.contains("files:"));
        assert!(frame.contains("3/5"));
        assert!(frame.contains("fill:"));
    }

    #[test]
    fn ballast_detail_shows_skip_reason() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 40),
        );
        model.screen = Screen::Ballast;
        model.ballast_volumes = vec![sample_ballast_volume("/mnt/nfs", 0, 0, 0, true)];
        model.ballast_detail = true;

        let frame = render(&model);
        assert!(frame.contains("SKIPPED"));
        assert!(frame.contains("unsupported filesystem"));
    }

    #[test]
    fn ballast_partial_data_shows_warning() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Ballast;
        model.ballast_volumes = vec![sample_ballast_volume("/", 3, 5, 3_221_225_472, false)];
        model.ballast_source = DataSource::Jsonl;
        model.ballast_partial = true;
        model.ballast_diagnostics = "SQLite unavailable, using JSONL fallback".into();

        let frame = render(&model);
        assert!(frame.contains("PARTIAL"));
        assert!(frame.contains("JSONL"));
        assert!(frame.contains("SQLite unavailable"));
    }

    #[test]
    fn ballast_aggregate_from_daemon_state() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        model.screen = Screen::Ballast;
        model.ballast_volumes = vec![sample_ballast_volume("/", 3, 5, 3_221_225_472, false)];
        model.daemon_state = Some(sample_state("green", 80.0));

        let frame = render(&model);
        assert!(frame.contains("ballast:"));
        assert!(frame.contains("available"));
        assert!(frame.contains("released"));
    }

    // ── bd-xzt.3.7: Navigation & Command Palette ──

    #[test]
    fn breadcrumb_not_shown_with_empty_history() {
        let model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (80, 24),
        );
        let frame = render(&model);
        assert!(!frame.contains("nav:"));
    }

    #[test]
    fn breadcrumb_shown_after_navigation() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (80, 24),
        );
        model.navigate_to(Screen::Timeline);
        model.navigate_to(Screen::Candidates);

        let frame = render(&model);
        assert!(frame.contains("nav:"));
        assert!(frame.contains("S1 Overview"));
        assert!(frame.contains("S2 Timeline"));
        assert!(frame.contains("S4 Candidates"));
    }

    #[test]
    fn breadcrumb_limited_to_five_entries() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 30),
        );
        // Navigate through 7 screens to build long history.
        model.navigate_to(Screen::Timeline);
        model.navigate_to(Screen::Explainability);
        model.navigate_to(Screen::Candidates);
        model.navigate_to(Screen::Ballast);
        model.navigate_to(Screen::Diagnostics);
        model.navigate_to(Screen::Overview);

        let frame = render(&model);
        // Breadcrumb shows last 5 + current, so first entry (Overview) is trimmed.
        let nav_line = frame.lines().find(|l| l.starts_with("nav:")).unwrap();
        // Count "> " separators: 5 entries + current = 5 " > " separators.
        let separator_count = nav_line.matches(" > ").count();
        assert!(separator_count <= 5, "breadcrumb too long: {nav_line}");
    }

    #[test]
    fn palette_overlay_renders_search_box() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (80, 24),
        );
        model.active_overlay = Some(Overlay::CommandPalette);
        model.palette_query = String::from("ballast");

        let frame = render(&model);
        assert!(frame.contains("Command Palette"));
        assert!(frame.contains("> ballast"));
        assert!(frame.contains("matches:"));
    }

    #[test]
    fn palette_overlay_shows_matching_actions() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (80, 24),
        );
        model.active_overlay = Some(Overlay::CommandPalette);

        let frame = render(&model);
        // Empty query shows all actions (up to 10 displayed).
        let total = super::super::input::command_palette_actions().len();
        assert!(
            frame.contains(&format!("matches: 10 / {total}")),
            "expected 'matches: 10 / {total}' in frame"
        );
        assert!(frame.contains("nav.overview"));
        assert!(frame.contains("Enter execute"));
        assert!(frame.contains("Esc close"));
    }

    #[test]
    fn palette_overlay_shows_cursor() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (80, 24),
        );
        model.active_overlay = Some(Overlay::CommandPalette);
        model.palette_selected = 2;

        let frame = render(&model);
        // Third action should have cursor ">"
        let has_palette_lines = frame
            .lines()
            .filter(|l| l.starts_with("> ") || l.starts_with("  "))
            .any(|l| l.contains("nav.") || l.contains("overlay.") || l.contains("action."));
        assert!(has_palette_lines);
    }

    #[test]
    fn palette_overlay_suppresses_debug_line() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (80, 24),
        );
        model.active_overlay = Some(Overlay::CommandPalette);

        let frame = render(&model);
        // Should NOT show debug "[overlay: CommandPalette]"
        assert!(!frame.contains("[overlay: CommandPalette]"));
        // But should show the actual palette UI
        assert!(frame.contains("Command Palette"));
    }

    #[test]
    fn help_overlay_still_shows_debug_line() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (80, 24),
        );
        model.active_overlay = Some(Overlay::Help);

        let frame = render(&model);
        assert!(frame.contains("[overlay: Help]"));
    }

    #[test]
    fn overview_has_navigation_footer() {
        let model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (80, 24),
        );
        let frame = render(&model);
        assert!(frame.contains("? help"));
        assert!(frame.contains(": palette"));
    }

    #[test]
    fn all_screens_mention_palette_in_footer() {
        let screens = [
            Screen::Overview,
            Screen::Timeline,
            Screen::Explainability,
            Screen::Candidates,
            Screen::Diagnostics,
            Screen::Ballast,
            Screen::LogSearch,
        ];
        for screen in screens {
            let mut model = DashboardModel::new(
                PathBuf::from("/tmp/state.json"),
                vec![],
                Duration::from_secs(1),
                (80, 24),
            );
            model.screen = screen;
            let frame = render(&model);
            assert!(
                frame.contains("palette"),
                "screen {screen:?} missing palette hint"
            );
        }
    }

    #[test]
    fn all_screens_mention_help_in_footer() {
        let screens = [
            Screen::Overview,
            Screen::Timeline,
            Screen::Explainability,
            Screen::Candidates,
            Screen::Diagnostics,
            Screen::Ballast,
            Screen::LogSearch,
        ];
        for screen in screens {
            let mut model = DashboardModel::new(
                PathBuf::from("/tmp/state.json"),
                vec![],
                Duration::from_secs(1),
                (80, 24),
            );
            model.screen = screen;
            let frame = render(&model);
            assert!(
                frame.contains("help"),
                "screen {screen:?} missing help hint"
            );
        }
    }
}
