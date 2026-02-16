//! Frame rendering dispatcher for the new TUI dashboard.
//!
//! Each screen has a dedicated render function. The dispatcher reads the
//! model's active screen and delegates. All rendering uses crossterm's
//! queue/execute macros for batched terminal writes.
//!
//! Render functions are read-only over the model — they never mutate state.

use std::io::{self, Write};

use crossterm::cursor::MoveTo;
use crossterm::style::{Attribute, Color, SetAttribute, SetForegroundColor};
use crossterm::terminal::{Clear, ClearType};
use crossterm::{execute, queue};

use crate::daemon::self_monitor::DaemonState;
use crate::monitor::fs_stats::FsStatsCollector;
use crate::platform::pal::detect_platform;

use super::model::{DashboardModel, RateHistory, Screen};

// ──────────────────── sparkline characters ────────────────────

const SPARK_CHARS: [char; 8] = ['\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}', '\u{2588}'];

// ──────────────────── public dispatcher ────────────────────

/// Render the current frame based on the model's active screen.
///
/// This is the top-level entry point called by the runtime after each update.
pub fn render(model: &DashboardModel, stdout: &mut io::Stdout) -> io::Result<()> {
    match model.screen {
        Screen::Overview => render_overview(model, stdout),
    }
}

// ──────────────────── overview screen ────────────────────

/// Render the overview screen with full parity to the legacy dashboard.
///
/// Satisfies contracts C-05 through C-18 from the baseline contract checklist
/// (`docs/dashboard-status-contract-baseline.md`).
fn render_overview(model: &DashboardModel, stdout: &mut io::Stdout) -> io::Result<()> {
    let (cols, _rows) = model.terminal_size;
    let width = cols as usize;
    let gauge_width = 20.min(width.saturating_sub(50));
    let mut row = 0u16;

    queue!(stdout, MoveTo(0, 0), Clear(ClearType::All))?;

    // ── Header ──
    render_header(stdout, model, width, &mut row)?;

    // Blank separator.
    row += 1;

    // ── Pressure Gauges ──
    render_pressure_gauges(stdout, model, width, gauge_width, &mut row)?;

    // Blank separator.
    row += 1;

    // ── EWMA Trends ──
    render_ewma_trends(stdout, model, &mut row)?;

    // Blank separator.
    row += 1;

    // ── Ballast Status + Counters ──
    render_ballast_and_counters(stdout, model, width, &mut row)?;

    // ── Footer ──
    row += 1;
    render_footer(stdout, width, &mut row)?;

    stdout.flush()
}

// ──────────────────── section renderers ────────────────────

fn render_header(
    stdout: &mut io::Stdout,
    model: &DashboardModel,
    width: usize,
    row: &mut u16,
) -> io::Result<()> {
    let version = model
        .daemon_state
        .as_ref()
        .map(|s| s.version.as_str())
        .unwrap_or(env!("CARGO_PKG_VERSION"));
    let uptime_str = model
        .daemon_state
        .as_ref()
        .map_or_else(|| "N/A".to_string(), |s| human_duration(s.uptime_seconds));
    let mode = if model.degraded { "DEGRADED" } else { "LIVE" };

    let header = format!(" Storage Ballast Helper v{version}  [{mode}]");
    let right = format!("uptime: {uptime_str} ");
    let pad = width.saturating_sub(header.len() + right.len());

    queue!(
        stdout,
        MoveTo(0, *row),
        SetForegroundColor(Color::Cyan),
        SetAttribute(Attribute::Bold),
    )?;
    write!(stdout, "\u{250c}\u{2500}{header}{:\u{2500}<pad$}{right}\u{2500}\u{2510}", "", pad = pad)?;
    queue!(stdout, SetAttribute(Attribute::Reset))?;
    *row += 1;

    // Blank separator line.
    queue!(stdout, MoveTo(0, *row))?;
    write!(stdout, "\u{2502} ")?;
    *row += 1;

    Ok(())
}

fn render_pressure_gauges(
    stdout: &mut io::Stdout,
    model: &DashboardModel,
    _width: usize,
    gauge_width: usize,
    row: &mut u16,
) -> io::Result<()> {
    queue!(
        stdout,
        MoveTo(3, *row),
        SetForegroundColor(Color::White),
        SetAttribute(Attribute::Bold),
    )?;
    write!(stdout, "Pressure Gauges")?;
    queue!(stdout, SetAttribute(Attribute::Reset))?;
    *row += 1;

    if let Some(ref s) = model.daemon_state {
        for mount in &s.pressure.mounts {
            let used_pct = 100.0 - mount.free_pct;
            let gauge = render_gauge(used_pct, gauge_width);
            let free_str = format!("{:.1}% free", mount.free_pct);
            let level_str = level_label(&mount.level);

            queue!(stdout, MoveTo(3, *row), SetForegroundColor(Color::White))?;
            write!(stdout, "{:<12}", mount.path)?;
            queue!(stdout, SetForegroundColor(level_color(&mount.level)))?;
            write!(stdout, "{gauge}  ({free_str})  {level_str}")?;

            if let Some(rate) = mount.rate_bps
                && rate > 0.0
                && mount.free_pct > 0.0
            {
                queue!(stdout, SetForegroundColor(Color::Yellow))?;
                write!(stdout, "  \u{26a0}")?;
            }

            queue!(stdout, SetAttribute(Attribute::Reset))?;
            *row += 1;
        }
    } else {
        // Degraded mode: attempt live filesystem stats.
        let platform = detect_platform().ok();
        let fs_collector = platform.as_ref().map(|p| {
            FsStatsCollector::new(
                std::sync::Arc::clone(p),
                std::time::Duration::from_secs(1),
            )
        });

        if let Some(collector) = &fs_collector {
            for path in &model.monitor_paths {
                if let Ok(stats) = collector.collect(path) {
                    let used_pct = 100.0 - stats.free_pct();
                    let gauge = render_gauge(used_pct, gauge_width);
                    let free_human = human_bytes(stats.free_bytes);

                    queue!(stdout, MoveTo(3, *row), SetForegroundColor(Color::White))?;
                    let display_path = path.to_string_lossy();
                    write!(stdout, "{display_path:<12}")?;
                    queue!(stdout, SetForegroundColor(Color::DarkGrey))?;
                    write!(stdout, "{gauge}  ({free_human} free)  --")?;
                    queue!(stdout, SetAttribute(Attribute::Reset))?;
                    *row += 1;
                }
            }
        }

        if model.monitor_paths.is_empty() {
            queue!(stdout, MoveTo(3, *row), SetForegroundColor(Color::DarkGrey))?;
            write!(stdout, "(no paths configured)")?;
            queue!(stdout, SetAttribute(Attribute::Reset))?;
            *row += 1;
        }
    }

    Ok(())
}

fn render_ewma_trends(
    stdout: &mut io::Stdout,
    model: &DashboardModel,
    row: &mut u16,
) -> io::Result<()> {
    queue!(
        stdout,
        MoveTo(3, *row),
        SetForegroundColor(Color::White),
        SetAttribute(Attribute::Bold),
    )?;
    write!(stdout, "EWMA Trends (last 30 readings)")?;
    queue!(stdout, SetAttribute(Attribute::Reset))?;
    *row += 1;

    if model.rate_histories.is_empty() {
        queue!(stdout, MoveTo(3, *row), SetForegroundColor(Color::DarkGrey))?;
        write!(stdout, "(no data yet)")?;
        queue!(stdout, SetAttribute(Attribute::Reset))?;
        *row += 1;
    } else {
        let mut sorted_keys: Vec<_> = model.rate_histories.keys().collect();
        sorted_keys.sort();

        for path in sorted_keys {
            let history = &model.rate_histories[path];
            let spark = render_sparkline(&history.normalized());
            let latest = history.latest().unwrap_or(0.0);
            let rate_str = format_rate(latest);
            let (trend_label, color) = trend_meta(latest);

            queue!(stdout, MoveTo(3, *row), SetForegroundColor(Color::White))?;
            write!(stdout, "{path:<12}")?;
            queue!(stdout, SetForegroundColor(color))?;
            write!(stdout, "{spark}  {rate_str} {trend_label}")?;

            if latest > 1_000_000.0 {
                write!(stdout, " \u{26a0}")?;
            }

            queue!(stdout, SetAttribute(Attribute::Reset))?;
            *row += 1;
        }
    }

    Ok(())
}

fn render_ballast_and_counters(
    stdout: &mut io::Stdout,
    model: &DashboardModel,
    width: usize,
    row: &mut u16,
) -> io::Result<()> {
    if let Some(ref s) = model.daemon_state {
        render_live_ballast_counters(stdout, s, width, row)
    } else {
        queue!(stdout, MoveTo(3, *row), SetForegroundColor(Color::DarkGrey))?;
        write!(
            stdout,
            "(daemon not running \u{2014} showing static filesystem stats)"
        )?;
        queue!(stdout, SetAttribute(Attribute::Reset))?;
        *row += 1;
        Ok(())
    }
}

fn render_live_ballast_counters(
    stdout: &mut io::Stdout,
    s: &DaemonState,
    width: usize,
    row: &mut u16,
) -> io::Result<()> {
    // Section headers: Last Scan (left) + Ballast (right).
    queue!(
        stdout,
        MoveTo(3, *row),
        SetForegroundColor(Color::White),
        SetAttribute(Attribute::Bold),
    )?;
    write!(stdout, "Last Scan")?;

    let ballast_col = width.saturating_sub(30).max(40);
    queue!(
        stdout,
        MoveTo(ballast_col as u16, *row),
        SetForegroundColor(Color::White),
        SetAttribute(Attribute::Bold),
    )?;
    write!(stdout, "Ballast")?;
    queue!(stdout, SetAttribute(Attribute::Reset))?;
    *row += 1;

    // Last scan info.
    queue!(stdout, MoveTo(3, *row), SetForegroundColor(Color::White))?;
    if let Some(ref at) = s.last_scan.at {
        let time_part = at.split('T').nth(1).unwrap_or(at);
        let time_short = time_part.split('.').next().unwrap_or(time_part);
        write!(
            stdout,
            "{time_short}  {} candidates, {} deleted",
            s.last_scan.candidates, s.last_scan.deleted,
        )?;
    } else {
        queue!(stdout, SetForegroundColor(Color::DarkGrey))?;
        write!(stdout, "(no scans yet)")?;
    }

    // Ballast info (right column).
    let released = s.ballast.released;
    let total = s.ballast.total;
    let avail = s.ballast.available;
    let ballast_color = if released > total / 2 {
        Color::Yellow
    } else {
        Color::Green
    };

    queue!(
        stdout,
        MoveTo(ballast_col as u16, *row),
        SetForegroundColor(ballast_color),
    )?;
    write!(stdout, "{avail}/{total} available ({released} released)")?;
    queue!(stdout, SetAttribute(Attribute::Reset))?;
    *row += 1;

    // Blank separator.
    *row += 1;

    // Counters / PID summary.
    let gb_freed = s.counters.bytes_freed as f64 / 1_073_741_824.0;
    let rss_mb = s.memory_rss_bytes / (1024 * 1024);

    queue!(
        stdout,
        MoveTo(3, *row),
        SetForegroundColor(Color::White),
        SetAttribute(Attribute::Bold),
    )?;
    write!(stdout, "Counters")?;
    queue!(stdout, SetAttribute(Attribute::Reset))?;
    *row += 1;

    queue!(stdout, MoveTo(3, *row), SetForegroundColor(Color::White))?;
    write!(
        stdout,
        "Scans: {}  |  Deleted: {} ({:.1} GB freed)  |  Errors: {}  |  RSS: {} MB  |  PID: {}",
        s.counters.scans, s.counters.deletions, gb_freed, s.counters.errors, rss_mb, s.pid,
    )?;
    queue!(stdout, SetAttribute(Attribute::Reset))?;
    *row += 1;

    Ok(())
}

fn render_footer(stdout: &mut io::Stdout, width: usize, row: &mut u16) -> io::Result<()> {
    let footer = " Press q or Esc to exit ";
    let pad = width.saturating_sub(footer.len() + 4);
    queue!(stdout, MoveTo(0, *row), SetForegroundColor(Color::Cyan))?;
    write!(stdout, "\u{2514}\u{2500}{footer}{:\u{2500}<pad$}\u{2500}\u{2500}\u{2518}", "", pad = pad)?;
    queue!(stdout, SetAttribute(Attribute::Reset))?;
    Ok(())
}

// ──────────────────── rendering helpers ────────────────────

fn render_gauge(used_pct: f64, width: usize) -> String {
    let filled = ((used_pct / 100.0) * width as f64).round() as usize;
    let filled = filled.min(width);
    let empty = width.saturating_sub(filled);
    format!(
        "[{}{}] {:.0}%",
        "\u{2588}".repeat(filled),
        "\u{2591}".repeat(empty),
        used_pct,
    )
}

fn render_sparkline(values: &[f64]) -> String {
    values
        .iter()
        .map(|v| {
            let idx = (v.clamp(0.0, 1.0) * 7.0).round() as usize;
            SPARK_CHARS[idx.min(7)]
        })
        .collect()
}

fn level_color(level: &str) -> Color {
    match level {
        "green" => Color::Green,
        "yellow" => Color::Yellow,
        "orange" => Color::DarkYellow,
        "red" | "critical" => Color::Red,
        _ => Color::White,
    }
}

fn level_label(level: &str) -> &str {
    match level {
        "green" => "GREEN",
        "yellow" => "YELLOW",
        "orange" => "ORANGE",
        "red" => "RED",
        "critical" => "CRITICAL",
        _ => level,
    }
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];
    let mut size = bytes as f64;
    for unit in UNITS {
        if size < 1024.0 {
            return if size >= 100.0 {
                format!("{size:.0} {unit}")
            } else if size >= 10.0 {
                format!("{size:.1} {unit}")
            } else {
                format!("{size:.2} {unit}")
            };
        }
        size /= 1024.0;
    }
    format!("{size:.1} PB")
}

fn human_duration(secs: u64) -> String {
    if secs < 60 {
        return format!("{secs}s");
    }
    if secs < 3600 {
        return format!("{}m {}s", secs / 60, secs % 60);
    }
    let hours = secs / 3600;
    if hours < 24 {
        return format!("{}h {}m", hours, (secs % 3600) / 60);
    }
    let days = hours / 24;
    format!("{}d {}h", days, hours % 24)
}

fn format_rate(rate: f64) -> String {
    if rate.abs() < 1024.0 {
        format!("{rate:.0} B/s")
    } else if rate.abs() < 1_048_576.0 {
        format!("{:.1} KB/s", rate / 1024.0)
    } else {
        format!("{:.1} MB/s", rate / 1_048_576.0)
    }
}

fn trend_meta(rate: f64) -> (&'static str, Color) {
    if rate > 1_000_000.0 {
        ("(accelerating)", Color::Red)
    } else if rate > 0.0 {
        ("(stable)", Color::Yellow)
    } else if rate < -1_000_000.0 {
        ("(recovering)", Color::Green)
    } else {
        ("(idle)", Color::Green)
    }
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gauge_empty() {
        let g = render_gauge(0.0, 20);
        assert!(g.contains("0%"));
        assert_eq!(g.matches('\u{2591}').count(), 20);
    }

    #[test]
    fn gauge_full() {
        let g = render_gauge(100.0, 20);
        assert!(g.contains("100%"));
        assert_eq!(g.matches('\u{2588}').count(), 20);
    }

    #[test]
    fn gauge_clamps_over_100() {
        let g = render_gauge(150.0, 10);
        assert_eq!(g.matches('\u{2588}').count(), 10);
    }

    #[test]
    fn sparkline_renders_correct_count() {
        let values = vec![0.0, 0.25, 0.5, 0.75, 1.0];
        let spark = render_sparkline(&values);
        assert_eq!(spark.chars().count(), 5);
    }

    #[test]
    fn sparkline_empty_is_empty() {
        assert!(render_sparkline(&[]).is_empty());
    }

    #[test]
    fn human_bytes_formatting() {
        assert_eq!(human_bytes(0), "0.00 B");
        assert_eq!(human_bytes(1024), "1.00 KB");
        assert_eq!(human_bytes(1_073_741_824), "1.00 GB");
    }

    #[test]
    fn human_duration_formatting() {
        assert_eq!(human_duration(30), "30s");
        assert_eq!(human_duration(90), "1m 30s");
        assert_eq!(human_duration(3600), "1h 0m");
        assert_eq!(human_duration(90000), "1d 1h");
    }

    #[test]
    fn level_color_mapping() {
        assert_eq!(level_color("green"), Color::Green);
        assert_eq!(level_color("red"), Color::Red);
        assert_eq!(level_color("critical"), Color::Red);
        assert_eq!(level_color("unknown"), Color::White);
    }

    #[test]
    fn trend_meta_classification() {
        assert_eq!(trend_meta(2_000_000.0).0, "(accelerating)");
        assert_eq!(trend_meta(500.0).0, "(stable)");
        assert_eq!(trend_meta(-2_000_000.0).0, "(recovering)");
        assert_eq!(trend_meta(0.0).0, "(idle)");
    }
}
