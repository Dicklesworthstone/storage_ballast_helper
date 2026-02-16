//! Render-surface scaffolding for the new dashboard runtime.

#![allow(missing_docs)]

use super::layout::{
    OverviewPane, PanePriority, TimelinePane, build_overview_layout, build_timeline_layout,
};
use super::model::{BallastVolume, DashboardModel, NotificationLevel, Screen, SeverityFilter};
use super::theme::{AccessibilityProfile, Theme, ThemePalette};
use super::widgets::{
    extract_time, gauge, human_bytes, human_duration, human_rate, section_header, sparkline,
    status_badge, trend_label,
};
use crate::tui::telemetry::{DataSource, DecisionEvidence, TimelineEvent};

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

    // Screen-specific content.
    match model.screen {
        Screen::Overview => render_overview(model, theme, &mut out),
        Screen::Timeline => render_timeline(model, theme, &mut out),
        Screen::Explainability => render_explainability(model, theme, &mut out),
        Screen::Candidates => render_candidates(model, theme, &mut out),
        Screen::Diagnostics => render_diagnostics(model, theme, &mut out),
        Screen::Ballast => render_ballast(model, theme, &mut out),
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
}

fn pane_priority_label(priority: PanePriority) -> &'static str {
    match priority {
        PanePriority::P0 => "p0",
        PanePriority::P1 => "p1",
        PanePriority::P2 => "p2",
    }
}

fn render_pressure_summary(model: &DashboardModel, theme: Theme, pane_width: u16) -> String {
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
        let gauge_w = gauge_width_for(pane_width);
        let mut out = format!(
            "pressure {badge} worst-free={worst_free_pct:.1}% mounts={}",
            state.pressure.mounts.len(),
        );

        // Per-mount detail rows matching legacy dashboard parity.
        for mount in &state.pressure.mounts {
            let used_pct = 100.0 - mount.free_pct;
            let g = gauge(used_pct, gauge_w);
            let level = mount.level.to_ascii_uppercase();
            let rate_warn = match mount.rate_bps {
                Some(r) if r > 0.0 && mount.free_pct > 0.0 => " \u{26a0}",
                _ => "",
            };
            let _ = write!(
                out,
                "\n  {:<14} {} ({:.1}% free) [{level}]{rate_warn}",
                mount.path, g, mount.free_pct,
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

fn render_recent_activity(model: &DashboardModel) -> String {
    if let Some(ref state) = model.daemon_state {
        let at_str = state
            .last_scan
            .at
            .as_deref()
            .map(extract_time)
            .unwrap_or("never");
        format!(
            "activity last-scan={at_str} candidates={} deleted={} errors={}",
            state.last_scan.candidates, state.last_scan.deleted, state.counters.errors,
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
            "counters errors={} dropped-log-events={} rss={} pid={} uptime={}",
            state.counters.errors,
            state.counters.dropped_log_events,
            human_bytes(state.memory_rss_bytes),
            state.pid,
            human_duration(state.uptime_seconds),
        )
    } else {
        String::from("counters unavailable")
    }
}

// ──────────────────── S2: Timeline ────────────────────

fn render_timeline(model: &DashboardModel, theme: Theme, out: &mut String) {
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

    if filtered.is_empty() {
        let _ = writeln!(out);
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
        let _ = writeln!(out);
        let list_visible = layout
            .placements
            .iter()
            .find(|p| p.pane == TimelinePane::EventList && p.visible);
        let max_rows = list_visible
            .map(|p| usize::from(p.rect.height))
            .unwrap_or(shown);

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
    if detail_visible {
        if let Some(event) = model.timeline_selected_event() {
            let _ = writeln!(out);
            let width = usize::from(model.terminal_size.0).max(40);
            let _ = writeln!(out, "{}", section_header("Event Detail", width));
            render_event_detail(event, theme, out);
        }
    }

    // ── Status footer ──
    let footer_visible = layout
        .placements
        .iter()
        .any(|p| p.pane == TimelinePane::StatusFooter && p.visible);
    if footer_visible {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "j/k or \u{2191}/\u{2193} navigate  f filter  F follow  r refresh  ? help"
        );
    }
}

fn render_event_row(cursor: &str, event: &TimelineEvent, theme: Theme, out: &mut String) {
    use std::fmt::Write as _;
    let time = extract_time(&event.timestamp);
    let sev_badge = severity_badge(&event.severity, theme);
    let path_short = event
        .path
        .as_deref()
        .map(|p| truncate_path(p, 30))
        .unwrap_or("-");
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

fn render_event_detail(event: &TimelineEvent, theme: Theme, out: &mut String) {
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

fn severity_badge(severity: &str, theme: Theme) -> String {
    let (palette, label) = match severity {
        "critical" => (theme.palette.critical, "CRITICAL"),
        "warning" => (theme.palette.warning, "WARNING"),
        "info" => (theme.palette.accent, "INFO"),
        _ => (theme.palette.muted, severity),
    };
    status_badge(label, palette, theme.accessibility)
}

// ──────────────────── S3: Explainability ────────────────────

fn render_explainability(model: &DashboardModel, theme: Theme, out: &mut String) {
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
        let _ = writeln!(out, "Press Enter to expand detail for selected decision");
    }

    // ── Navigation hint ──
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "j/k or \u{2191}/\u{2193} navigate  Enter expand  d close detail  r refresh"
    );
}

fn render_decision_detail(
    decision: &DecisionEvidence,
    theme: Theme,
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
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_precision_loss)]
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
        let start = path.len() - max_len;
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
        let _ = writeln!(out, "Press Enter to expand detail for selected candidate");
    }

    // ── Navigation hint ──
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "j/k or \u{2191}/\u{2193} navigate  Enter expand  d close  s sort  r refresh"
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

    // ── Last fetch staleness ──
    let fetch_label = match model.last_fetch {
        Some(t) => {
            let elapsed = t.elapsed();
            format!("{}ms ago", elapsed.as_millis())
        }
        None => String::from("never"),
    };
    let _ = writeln!(out, "  last-fetch:    {fetch_label}");
    let _ = writeln!(out, "  notifications: {} active", model.notifications.len(),);

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
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "V verbose ({verbose_label})  r refresh  ? help  q quit"
    );
}

// ──────────────────── S5: Ballast Operations ────────────────────

fn render_ballast(model: &DashboardModel, theme: Theme, out: &mut String) {
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
        return;
    }

    // ── Volume inventory table ──
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", section_header("Ballast Volumes", width));

    // Column headers.
    let _ = writeln!(
        out,
        "  {:<4} {:<12} {:<20} {:<8} {:<8} {:<10} {}",
        "#", "STATUS", "MOUNT", "FILES", "FS", "STRATEGY", "RELEASABLE"
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
        let _ = writeln!(out, "Press Enter to expand detail for selected volume");
    }

    // ── Navigation hint ──
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "j/k or \u{2191}/\u{2193} navigate  Enter expand  d close  r refresh"
    );
}

fn render_volume_detail(vol: &BallastVolume, theme: Theme, out: &mut String) {
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

    if vol.skipped {
        if let Some(ref reason) = vol.skip_reason {
            let _ = writeln!(out, "  skip-reason: {reason}");
        }
    }

    // File fill gauge.
    if vol.files_total > 0 {
        #[allow(clippy::cast_precision_loss)]
        let fill_pct = (vol.files_available as f64 / vol.files_total as f64) * 100.0;
        let bar = gauge(fill_pct, 20);
        let _ = writeln!(out, "  fill: {bar}");
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
        model.screen = Screen::LogSearch;
        let frame = render(&model);
        assert!(frame.contains("[S6 Logs]"));
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
        let cursor_line = lines.iter().find(|l| l.contains("2") && l.starts_with('>'));
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
}
