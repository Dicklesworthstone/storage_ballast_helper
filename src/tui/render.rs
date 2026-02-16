//! Render-surface scaffolding for the new dashboard runtime.

#![allow(missing_docs)]

use super::model::{DashboardModel, Screen};

/// Stable render entrypoint for screen dispatch.
///
/// The implementation here remains intentionally minimal until screen-specific
/// beads (`bd-xzt.3.*`) populate real widgets and layouts.
#[must_use]
pub fn render(model: &DashboardModel) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();

    // Always-on header: mode indicator, active screen, overlay status.
    let mode = if model.degraded { "DEGRADED" } else { "NORMAL" };
    let label = screen_label(model.screen);
    let _ = writeln!(
        out,
        "SBH Dashboard ({mode})  [{label}]  tick={}  size={}x{}",
        model.tick, model.terminal_size.0, model.terminal_size.1
    );

    if let Some(ref overlay) = model.active_overlay {
        let _ = writeln!(out, "[overlay: {overlay:?}]");
    }

    // Screen-specific content (stubs until bd-xzt.3.*).
    match model.screen {
        Screen::Overview => render_overview_stub(model, &mut out),
        screen => render_screen_stub(screen_label(screen), &mut out),
    }

    // Notification toasts (O4).
    for notif in &model.notifications {
        let _ = writeln!(out, "[{:?}] {}", notif.level, notif.message);
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

fn render_overview_stub(model: &DashboardModel, out: &mut String) {
    use std::fmt::Write as _;
    if let Some(ref state) = model.daemon_state {
        let _ = writeln!(
            out,
            "Pressure: {} ({} mounts)",
            state.pressure.overall,
            state.pressure.mounts.len()
        );
        let _ = writeln!(
            out,
            "Ballast: {}/{} available, {} released",
            state.ballast.available, state.ballast.total, state.ballast.released
        );
        let _ = writeln!(
            out,
            "Counters: {} scans, {} deletions, {} freed",
            state.counters.scans, state.counters.deletions, state.counters.bytes_freed
        );
    } else {
        let _ = writeln!(out, "Daemon state unavailable — showing degraded view");
    }
}

fn render_screen_stub(name: &str, out: &mut String) {
    use std::fmt::Write as _;
    let _ = writeln!(out, "{name} — implementation pending (bd-xzt.3.*)");
    let _ = writeln!(out, "Press 1-7 to navigate, ? for help, q to quit");
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use super::*;

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
        use super::super::model::NotificationLevel;
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (80, 24),
        );
        model.push_notification(NotificationLevel::Error, "disk full".into());
        let frame = render(&model);
        assert!(frame.contains("disk full"));
        assert!(frame.contains("Error"));
    }
}
