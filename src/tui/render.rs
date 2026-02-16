//! Render-surface scaffolding for the new dashboard runtime.

#![allow(missing_docs)]

use super::layout::{OverviewPane, PanePriority, build_overview_layout};
use super::model::{DashboardModel, NotificationLevel, Screen};
use super::theme::{AccessibilityProfile, Theme, ThemePalette};
use super::widgets::{gauge, sparkline, status_badge};

/// Stable render entrypoint for screen dispatch.
///
/// The implementation here remains intentionally minimal until screen-specific
/// beads (`bd-xzt.3.*`) populate real widgets and layouts.
#[must_use]
pub fn render(model: &DashboardModel) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let accessibility = AccessibilityProfile::from_environment();
    let theme = Theme::for_terminal(model.terminal_size.0, accessibility);

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
        color_mode_label(theme),
        spacing_mode_label(theme),
    );

    if let Some(ref overlay) = model.active_overlay {
        let _ = writeln!(out, "[overlay: {overlay:?}]");
    }

    // Screen-specific content (stubs until bd-xzt.3.*).
    match model.screen {
        Screen::Overview => render_overview(model, theme, &mut out),
        screen => render_screen_stub(screen_label(screen), theme, &mut out),
    }

    // Notification toasts (O4).
    for notif in &model.notifications {
        let badge = notification_badge(theme.palette, theme.accessibility, notif.level);
        let _ = writeln!(out, "[toast#{}] {} {}", notif.id, badge, notif.message);
    }

    out
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

fn color_mode_label(theme: Theme) -> &'static str {
    if theme.accessibility.no_color() {
        "mono"
    } else {
        "color"
    }
}

fn spacing_mode_label(theme: Theme) -> &'static str {
    if theme.spacing.outer_padding == 0 {
        "compact"
    } else {
        "comfortable"
    }
}

fn render_overview(model: &DashboardModel, theme: Theme, out: &mut String) {
    use std::fmt::Write as _;
    let layout = build_overview_layout(model.terminal_size.0, model.terminal_size.1);
    let visible = layout.placements.iter().filter(|pane| pane.visible).count();
    let _ = writeln!(
        out,
        "overview-layout={:?} visible-panes={visible}",
        layout.class
    );

    for placement in layout.placements.iter().filter(|pane| pane.visible) {
        let content = match placement.pane {
            OverviewPane::PressureSummary => {
                render_pressure_summary(model, theme, placement.rect.width)
            }
            OverviewPane::ActionLane => render_action_lane(model),
            OverviewPane::EwmaTrend => render_ewma_trend(model),
            OverviewPane::RecentActivity => render_recent_activity(model),
            OverviewPane::BallastQuick => render_ballast_quick(model, theme),
            OverviewPane::ExtendedCounters => render_extended_counters(model),
        };
        let _ = writeln!(
            out,
            "[{} {} @{},{} {}x{}] {}",
            placement.pane.id(),
            pane_priority_label(placement.priority),
            placement.rect.col,
            placement.rect.row,
            placement.rect.width,
            placement.rect.height,
            content,
        );
    }
}

fn pane_priority_label(priority: PanePriority) -> &'static str {
    match priority {
        PanePriority::P0 => "p0",
        PanePriority::P1 => "p1",
        PanePriority::P2 => "p2",
    }
}

fn render_pressure_summary(model: &DashboardModel, theme: Theme, pane_width: u16) -> String {
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
        let used_gauge = gauge(100.0 - worst_free_pct, gauge_width_for(pane_width));
        format!(
            "pressure {badge} worst-free={worst_free_pct:.1}% used={used_gauge} mounts={}",
            state.pressure.mounts.len(),
        )
    } else {
        let badge = status_badge("UNKNOWN", theme.palette.muted, theme.accessibility);
        format!("pressure {badge} daemon-state-unavailable")
    }
}

fn gauge_width_for(pane_width: u16) -> usize {
    usize::from(pane_width).clamp(28, 64) / 3
}

fn render_action_lane(model: &DashboardModel) -> String {
    if let Some(ref state) = model.daemon_state {
        format!(
            "actions scans={} deleted={} bytes-freed={}",
            state.counters.scans, state.counters.deletions, state.counters.bytes_freed,
        )
    } else {
        String::from("actions awaiting daemon connection")
    }
}

fn render_ewma_trend(model: &DashboardModel) -> String {
    if model.rate_histories.is_empty() {
        return String::from("ewma no-rate-data");
    }

    let mut series: Vec<(&str, String)> = model
        .rate_histories
        .iter()
        .map(|(path, history)| {
            let normalized = history.normalized();
            let trace = sparkline(&normalized);
            let latest = history.latest().unwrap_or(0.0);
            (path.as_str(), format!("{path}:{trace}({latest:+.0}B/s)"))
        })
        .collect();
    series.sort_unstable_by(|a, b| a.0.cmp(b.0));

    let joined = series
        .into_iter()
        .map(|(_, line)| line)
        .take(3)
        .collect::<Vec<_>>()
        .join(" | ");
    format!("ewma {joined}")
}

fn render_recent_activity(model: &DashboardModel) -> String {
    if let Some(ref state) = model.daemon_state {
        format!(
            "activity last-scan={} candidates={} deleted={} errors={}",
            state.last_scan.at.as_deref().unwrap_or("never"),
            state.last_scan.candidates,
            state.last_scan.deleted,
            state.counters.errors,
        )
    } else {
        String::from("activity unavailable while degraded")
    }
}

fn render_ballast_quick(model: &DashboardModel, theme: Theme) -> String {
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

fn render_extended_counters(model: &DashboardModel) -> String {
    if let Some(ref state) = model.daemon_state {
        format!(
            "counters errors={} dropped-log-events={} rss={}B",
            state.counters.errors, state.counters.dropped_log_events, state.memory_rss_bytes,
        )
    } else {
        String::from("counters unavailable")
    }
}

fn render_screen_stub(name: &str, theme: Theme, out: &mut String) {
    use std::fmt::Write as _;
    let pending = status_badge("PENDING", theme.palette.muted, theme.accessibility);
    let _ = writeln!(
        out,
        "{name} {pending} — implementation pending (bd-xzt.3.*)"
    );
    let _ = writeln!(out, "Press 1-7 to navigate, ? for help, q to quit");
}

fn notification_badge(
    palette: ThemePalette,
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
    fn render_stub_screens_show_label() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (80, 24),
        );
        model.screen = Screen::Timeline;
        let frame = render(&model);
        assert!(frame.contains("[S2 Timeline]"));
        assert!(frame.contains("pending"));
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
}
