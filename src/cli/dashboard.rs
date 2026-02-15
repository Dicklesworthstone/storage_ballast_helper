//! Live TUI dashboard: real-time pressure gauges, EWMA sparklines, activity log,
//! ballast inventory, and PID controller state.
//!
//! Reads from the daemon's `state.json` file (written by `SelfMonitor`). When
//! the daemon is not running, falls back to live filesystem stats in degraded mode.
//!
//! Uses `crossterm` for raw terminal manipulation (alternate screen, cursor
//! positioning, color output). No heavy TUI framework needed — the layout is
//! a fixed grid refreshed by polling.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]

use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crossterm::cursor::MoveTo;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::style::{Attribute, Color, SetAttribute, SetForegroundColor};
use crossterm::terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{execute, queue};

use crate::daemon::self_monitor::{DaemonState, SelfMonitor};
use crate::monitor::fs_stats::FsStatsCollector;
use crate::platform::pal::detect_platform;

// ──────────────────── sparkline characters ────────────────────

/// Unicode block characters for sparkline rendering (8 levels).
const SPARK_CHARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

// ──────────────────── color mapping ────────────────────

/// Map a pressure level string to an ANSI color.
fn level_color(level: &str) -> Color {
    match level {
        "green" => Color::Green,
        "yellow" => Color::Yellow,
        "orange" => Color::DarkYellow,
        "red" | "critical" => Color::Red,
        _ => Color::White,
    }
}

/// Map a pressure level string to a display label.
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

// ──────────────────── gauge rendering ────────────────────

/// Render a horizontal bar gauge.
///
/// Returns a string like `[████████████░░░░░░░░] 62%`
fn render_gauge(used_pct: f64, width: usize) -> String {
    let filled = ((used_pct / 100.0) * width as f64).round() as usize;
    let filled = filled.min(width);
    let empty = width.saturating_sub(filled);

    format!(
        "[{}{}] {:.0}%",
        "█".repeat(filled),
        "░".repeat(empty),
        used_pct,
    )
}

/// Render a sparkline from a slice of values (0.0..=1.0 normalized).
fn render_sparkline(values: &[f64]) -> String {
    values
        .iter()
        .map(|v| {
            let idx = (v.clamp(0.0, 1.0) * 7.0).round() as usize;
            SPARK_CHARS[idx.min(7)]
        })
        .collect()
}

// ──────────────────── format helpers ────────────────────

/// Human-readable byte size.
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

/// Human-readable duration.
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

// ──────────────────── dashboard config ────────────────────

/// Configuration for the dashboard display.
pub struct DashboardConfig {
    /// Path to the daemon state file.
    pub state_file: PathBuf,
    /// Refresh interval.
    pub refresh: Duration,
    /// Filesystem paths to monitor in degraded mode.
    pub monitor_paths: Vec<PathBuf>,
}

// ──────────────────── dashboard state ────────────────────

/// Tracks recent rate readings for sparkline history.
struct RateHistory {
    /// Ring buffer of rate values (bytes/sec, negative = freeing).
    values: Vec<f64>,
    capacity: usize,
    write_pos: usize,
}

impl RateHistory {
    fn new(capacity: usize) -> Self {
        Self {
            values: Vec::with_capacity(capacity),
            capacity,
            write_pos: 0,
        }
    }

    fn push(&mut self, value: f64) {
        if self.values.len() < self.capacity {
            self.values.push(value);
        } else {
            self.values[self.write_pos] = value;
        }
        self.write_pos = (self.write_pos + 1) % self.capacity;
    }

    /// Get values in chronological order, normalized to 0..1 range.
    fn normalized(&self) -> Vec<f64> {
        if self.values.is_empty() {
            return Vec::new();
        }

        let max_abs = self.values.iter().map(|v| v.abs()).fold(0.0f64, f64::max);
        if max_abs == 0.0 {
            return vec![0.5; self.values.len()];
        }

        // Reorder ring buffer to chronological.
        let len = self.values.len();
        let start = if len < self.capacity {
            0
        } else {
            self.write_pos
        };

        (0..len)
            .map(|i| {
                let idx = (start + i) % len;
                // Map from [-max, +max] to [0, 1].
                (self.values[idx] / max_abs + 1.0) / 2.0
            })
            .collect()
    }

    fn latest(&self) -> Option<f64> {
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

// ──────────────────── main dashboard loop ────────────────────

/// Run the dashboard until the user exits (q/Ctrl-C/Esc).
pub fn run(config: DashboardConfig) -> io::Result<()> {
    let mut stdout = io::stdout();

    // Enter raw mode + alternate screen.
    terminal::enable_raw_mode()?;
    execute!(stdout, EnterAlternateScreen)?;

    let result = run_inner(&mut stdout, &config);

    // Always restore terminal state.
    let _ = execute!(stdout, LeaveAlternateScreen);
    let _ = terminal::disable_raw_mode();

    result
}

fn run_inner(stdout: &mut io::Stdout, config: &DashboardConfig) -> io::Result<()> {
    let mut rate_histories: Vec<(String, RateHistory)> = Vec::new();

    // For degraded mode: use live fs stats.
    let platform = detect_platform().ok();
    let fs_collector = platform
        .as_ref()
        .map(|p| FsStatsCollector::new(std::sync::Arc::clone(p), Duration::from_secs(1)));

    let mut last_render = Instant::now() - config.refresh; // Force immediate first render.

    loop {
        // Poll for keyboard events.
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }

        // Refresh at configured interval.
        if last_render.elapsed() < config.refresh {
            continue;
        }
        last_render = Instant::now();

        let (cols, rows) = terminal::size()?;
        let width = cols as usize;

        // Try reading daemon state.
        let state = SelfMonitor::read_state(&config.state_file).ok();

        // Update rate histories from state.
        if let Some(ref s) = state {
            for mount in &s.pressure.mounts {
                let entry = rate_histories
                    .iter_mut()
                    .find(|(path, _)| *path == mount.path);
                if let Some((_, history)) = entry {
                    history.push(mount.rate_bps.unwrap_or(0.0));
                } else {
                    let mut h = RateHistory::new(30);
                    h.push(mount.rate_bps.unwrap_or(0.0));
                    rate_histories.push((mount.path.clone(), h));
                }
            }
        }

        // Render.
        render_frame(
            stdout,
            width,
            rows as usize,
            state.as_ref(),
            &rate_histories,
            &config.monitor_paths,
            fs_collector.as_ref(),
        )?;
    }
}

// ──────────────────── frame rendering ────────────────────

fn render_frame(
    stdout: &mut io::Stdout,
    width: usize,
    _rows: usize,
    state: Option<&DaemonState>,
    rate_histories: &[(String, RateHistory)],
    monitor_paths: &[PathBuf],
    fs_collector: Option<&FsStatsCollector>,
) -> io::Result<()> {
    let gauge_width = 20.min(width.saturating_sub(50));
    let mut row = 0u16;

    queue!(stdout, MoveTo(0, 0), Clear(ClearType::All))?;

    // ── Header ──
    let version = state
        .map(|s| s.version.as_str())
        .unwrap_or(env!("CARGO_PKG_VERSION"));
    let uptime_str = state
        .map(|s| human_duration(s.uptime_seconds))
        .unwrap_or_else(|| "N/A".to_string());
    let mode = if state.is_some() { "LIVE" } else { "DEGRADED" };

    let header = format!(" Storage Ballast Helper v{version}  [{mode}]");
    let right = format!("uptime: {uptime_str} ");
    let pad = width.saturating_sub(header.len() + right.len());

    queue!(
        stdout,
        MoveTo(0, row),
        SetForegroundColor(Color::Cyan),
        SetAttribute(Attribute::Bold),
    )?;
    write!(stdout, "┌─{header}{:─<pad$}{right}─┐", "", pad = pad,)?;
    queue!(stdout, SetAttribute(Attribute::Reset))?;
    row += 1;

    // Blank separator.
    write_padded_line(stdout, row, "", width)?;
    row += 1;

    // ── Pressure Gauges ──
    queue!(
        stdout,
        MoveTo(3, row),
        SetForegroundColor(Color::White),
        SetAttribute(Attribute::Bold),
    )?;
    write!(stdout, "Pressure Gauges")?;
    queue!(stdout, SetAttribute(Attribute::Reset))?;
    row += 1;

    if let Some(ref s) = state {
        for mount in &s.pressure.mounts {
            let used_pct = 100.0 - mount.free_pct;
            let gauge = render_gauge(used_pct, gauge_width);
            let free_str = format!("{:.1}% free", mount.free_pct);
            let level_str = level_label(&mount.level);

            queue!(stdout, MoveTo(3, row), SetForegroundColor(Color::White),)?;
            write!(stdout, "{:<12}", mount.path)?;
            queue!(stdout, SetForegroundColor(level_color(&mount.level)))?;
            write!(stdout, "{gauge}  ({free_str})  {level_str}")?;

            // Time-to-exhaustion hint if rate is positive.
            if let Some(rate) = mount.rate_bps {
                if rate > 0.0 && mount.free_pct > 0.0 {
                    // rough estimate — free_bytes not available, use percentage
                    queue!(stdout, SetForegroundColor(Color::Yellow))?;
                    write!(stdout, "  ⚠")?;
                }
            }

            queue!(stdout, SetAttribute(Attribute::Reset))?;
            row += 1;
        }
    } else if let Some(collector) = fs_collector {
        // Degraded mode: collect live stats.
        for path in monitor_paths {
            if let Ok(stats) = collector.collect(path) {
                let used_pct = 100.0 - stats.free_pct();
                let gauge = render_gauge(used_pct, gauge_width);
                let free_human = human_bytes(stats.free_bytes);

                queue!(stdout, MoveTo(3, row), SetForegroundColor(Color::White))?;
                let display_path = path.to_string_lossy();
                write!(stdout, "{display_path:<12}")?;
                queue!(stdout, SetForegroundColor(Color::DarkGrey))?;
                write!(stdout, "{gauge}  ({free_human} free)  --")?;
                queue!(stdout, SetAttribute(Attribute::Reset))?;
                row += 1;
            }
        }
        if monitor_paths.is_empty() {
            queue!(stdout, MoveTo(3, row), SetForegroundColor(Color::DarkGrey))?;
            write!(stdout, "(no paths configured)")?;
            queue!(stdout, SetAttribute(Attribute::Reset))?;
            row += 1;
        }
    } else {
        queue!(stdout, MoveTo(3, row), SetForegroundColor(Color::DarkGrey))?;
        write!(stdout, "(daemon not running, no platform support)")?;
        queue!(stdout, SetAttribute(Attribute::Reset))?;
        row += 1;
    }

    // Blank separator.
    row += 1;

    // ── EWMA Trends ──
    queue!(
        stdout,
        MoveTo(3, row),
        SetForegroundColor(Color::White),
        SetAttribute(Attribute::Bold),
    )?;
    write!(stdout, "EWMA Trends (last 30 readings)")?;
    queue!(stdout, SetAttribute(Attribute::Reset))?;
    row += 1;

    if rate_histories.is_empty() {
        queue!(stdout, MoveTo(3, row), SetForegroundColor(Color::DarkGrey))?;
        write!(stdout, "(no data yet)")?;
        queue!(stdout, SetAttribute(Attribute::Reset))?;
        row += 1;
    } else {
        for (path, history) in rate_histories {
            let spark = render_sparkline(&history.normalized());
            let latest = history.latest().unwrap_or(0.0);
            let rate_str = if latest.abs() < 1024.0 {
                format!("{latest:.0} B/s")
            } else if latest.abs() < 1_048_576.0 {
                format!("{:.1} KB/s", latest / 1024.0)
            } else {
                format!("{:.1} MB/s", latest / 1_048_576.0)
            };
            let trend_label = if latest > 1_000_000.0 {
                "(accelerating)"
            } else if latest > 0.0 {
                "(stable)"
            } else if latest < -1_000_000.0 {
                "(recovering)"
            } else {
                "(idle)"
            };

            let color = if latest > 1_000_000.0 {
                Color::Red
            } else if latest > 0.0 {
                Color::Yellow
            } else {
                Color::Green
            };

            queue!(stdout, MoveTo(3, row), SetForegroundColor(Color::White))?;
            write!(stdout, "{path:<12}")?;
            queue!(stdout, SetForegroundColor(color))?;
            write!(stdout, "{spark}  {rate_str} {trend_label}")?;

            if latest > 1_000_000.0 {
                write!(stdout, " ⚠")?;
            }

            queue!(stdout, SetAttribute(Attribute::Reset))?;
            row += 1;
        }
    }

    // Blank separator.
    row += 1;

    // ── Ballast Status + Counters ──
    if let Some(ref s) = state {
        // Activity + Ballast on the same row section.
        queue!(
            stdout,
            MoveTo(3, row),
            SetForegroundColor(Color::White),
            SetAttribute(Attribute::Bold),
        )?;
        write!(stdout, "Last Scan")?;

        let ballast_col = width.saturating_sub(30).max(40);
        queue!(
            stdout,
            MoveTo(ballast_col as u16, row),
            SetForegroundColor(Color::White),
            SetAttribute(Attribute::Bold),
        )?;
        write!(stdout, "Ballast")?;
        queue!(stdout, SetAttribute(Attribute::Reset))?;
        row += 1;

        // Last scan info.
        queue!(stdout, MoveTo(3, row), SetForegroundColor(Color::White))?;
        if let Some(ref at) = s.last_scan.at {
            // Show just the time portion.
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
            MoveTo(ballast_col as u16, row),
            SetForegroundColor(ballast_color),
        )?;
        write!(stdout, "{avail}/{total} available ({released} released)")?;
        queue!(stdout, SetAttribute(Attribute::Reset))?;
        row += 1;

        // Blank separator.
        row += 1;

        // ── Counters / PID summary ──
        let gb_freed = s.counters.bytes_freed as f64 / 1_073_741_824.0;
        let rss_mb = s.memory_rss_bytes / (1024 * 1024);

        queue!(
            stdout,
            MoveTo(3, row),
            SetForegroundColor(Color::White),
            SetAttribute(Attribute::Bold),
        )?;
        write!(stdout, "Counters")?;
        queue!(stdout, SetAttribute(Attribute::Reset))?;
        row += 1;

        queue!(stdout, MoveTo(3, row), SetForegroundColor(Color::White))?;
        write!(
            stdout,
            "Scans: {}  |  Deleted: {} ({:.1} GB freed)  |  Errors: {}  |  RSS: {} MB  |  PID: {}",
            s.counters.scans, s.counters.deletions, gb_freed, s.counters.errors, rss_mb, s.pid,
        )?;
        queue!(stdout, SetAttribute(Attribute::Reset))?;
        row += 1;
    } else {
        queue!(stdout, MoveTo(3, row), SetForegroundColor(Color::DarkGrey))?;
        write!(
            stdout,
            "(daemon not running — showing static filesystem stats)"
        )?;
        queue!(stdout, SetAttribute(Attribute::Reset))?;
        row += 1;
    }

    // ── Footer ──
    row += 1;
    let footer = " Press q or Esc to exit ";
    let pad = width.saturating_sub(footer.len() + 4);
    queue!(stdout, MoveTo(0, row), SetForegroundColor(Color::Cyan),)?;
    write!(stdout, "└─{footer}{:─<pad$}──┘", "", pad = pad)?;
    queue!(stdout, SetAttribute(Attribute::Reset))?;

    stdout.flush()
}

fn write_padded_line(
    stdout: &mut io::Stdout,
    row: u16,
    content: &str,
    _width: usize,
) -> io::Result<()> {
    queue!(stdout, MoveTo(0, row))?;
    write!(stdout, "│ {content}")
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_gauge_empty() {
        let g = render_gauge(0.0, 20);
        assert!(g.starts_with("[░░░░░░░░░░░░░░░░░░░░]"));
        assert!(g.contains("0%"));
    }

    #[test]
    fn render_gauge_full() {
        let g = render_gauge(100.0, 20);
        assert!(g.starts_with("[████████████████████]"));
        assert!(g.contains("100%"));
    }

    #[test]
    fn render_gauge_half() {
        let g = render_gauge(50.0, 20);
        assert!(g.contains("50%"));
        // 10 filled, 10 empty
        assert_eq!(g.matches('█').count(), 10);
        assert_eq!(g.matches('░').count(), 10);
    }

    #[test]
    fn render_gauge_clamps_over_100() {
        let g = render_gauge(150.0, 10);
        // Should not panic, fills entire width
        assert_eq!(g.matches('█').count(), 10);
    }

    #[test]
    fn sparkline_renders_correctly() {
        let values = vec![0.0, 0.25, 0.5, 0.75, 1.0];
        let spark = render_sparkline(&values);
        assert_eq!(spark.chars().count(), 5);
        assert_eq!(spark.chars().next(), Some('▁'));
        assert_eq!(spark.chars().last(), Some('█'));
    }

    #[test]
    fn sparkline_empty() {
        let spark = render_sparkline(&[]);
        assert!(spark.is_empty());
    }

    #[test]
    fn human_bytes_formatting() {
        assert_eq!(human_bytes(0), "0.00 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.00 KB");
        assert_eq!(human_bytes(1_048_576), "1.00 MB");
        assert_eq!(human_bytes(1_073_741_824), "1.00 GB");
        assert_eq!(human_bytes(500_000_000_000), "466 GB");
    }

    #[test]
    fn human_duration_formatting() {
        assert_eq!(human_duration(30), "30s");
        assert_eq!(human_duration(90), "1m 30s");
        assert_eq!(human_duration(3600), "1h 0m");
        assert_eq!(human_duration(90000), "1d 1h");
    }

    #[test]
    fn rate_history_push_and_normalize() {
        let mut h = RateHistory::new(5);
        h.push(100.0);
        h.push(-100.0);
        h.push(0.0);

        let norm = h.normalized();
        assert_eq!(norm.len(), 3);
        // 100 -> (100/100 + 1)/2 = 1.0
        assert!((norm[0] - 1.0).abs() < 0.01);
        // -100 -> (-100/100 + 1)/2 = 0.0
        assert!((norm[1] - 0.0).abs() < 0.01);
        // 0 -> (0/100 + 1)/2 = 0.5
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

        let norm = h.normalized();
        assert_eq!(norm.len(), 3);
    }

    #[test]
    fn rate_history_latest() {
        let mut h = RateHistory::new(10);
        assert_eq!(h.latest(), None);
        h.push(42.0);
        assert_eq!(h.latest(), Some(42.0));
        h.push(99.0);
        assert_eq!(h.latest(), Some(99.0));
    }

    #[test]
    fn rate_history_all_zeros() {
        let mut h = RateHistory::new(5);
        h.push(0.0);
        h.push(0.0);
        h.push(0.0);

        let norm = h.normalized();
        // All zeros should normalize to 0.5 (midpoint).
        assert!(norm.iter().all(|v| (*v - 0.5).abs() < 0.01));
    }

    #[test]
    fn level_color_mapping() {
        assert_eq!(level_color("green"), Color::Green);
        assert_eq!(level_color("yellow"), Color::Yellow);
        assert_eq!(level_color("orange"), Color::DarkYellow);
        assert_eq!(level_color("red"), Color::Red);
        assert_eq!(level_color("critical"), Color::Red);
        assert_eq!(level_color("unknown"), Color::White);
    }

    #[test]
    fn level_label_mapping() {
        assert_eq!(level_label("green"), "GREEN");
        assert_eq!(level_label("critical"), "CRITICAL");
        assert_eq!(level_label("weird"), "weird");
    }
}
