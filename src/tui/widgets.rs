//! Widget primitives and shared visual helpers for dashboard screens.

#![allow(missing_docs)]

use super::theme::{AccessibilityProfile, PaletteEntry, ThemePalette};

use ftui::text::{Line, Span};
use ftui::{PackedRgba, Style};

/// Sparkline glyph ramp shared across screens.
pub const SPARK_CHARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// Render a normalized sparkline from `0.0..=1.0` values.
#[must_use]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn sparkline(values: &[f64]) -> String {
    values
        .iter()
        .map(|value| {
            let idx = (value.clamp(0.0, 1.0) * 7.0).round() as usize;
            SPARK_CHARS[idx.min(7)]
        })
        .collect()
}

/// Render a horizontal gauge with percentage label.
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
pub fn gauge(used_pct: f64, width: usize) -> String {
    let clamped_pct = used_pct.clamp(0.0, 100.0);
    let filled = ((clamped_pct / 100.0) * width as f64).round() as usize;
    let filled = filled.min(width);
    let empty = width.saturating_sub(filled);

    format!(
        "[{}{}] {:.0}%",
        "█".repeat(filled),
        "░".repeat(empty),
        clamped_pct,
    )
}

/// Render a semantic badge honoring no-color compatibility mode.
#[must_use]
pub fn status_badge(
    label: &str,
    palette: PaletteEntry,
    accessibility: AccessibilityProfile,
) -> String {
    if accessibility.no_color() {
        format!("[{label}]")
    } else {
        format!("[{}:{label}]", palette.text_tag)
    }
}

// ──────────────────── styled widget primitives ────────────────────

/// Sparkline with color gradient: green at low values, yellow mid, red high.
#[must_use]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn colored_sparkline<'a>(values: &[f64], palette: &ThemePalette) -> Vec<Span<'a>> {
    values
        .iter()
        .map(|value| {
            let v = value.clamp(0.0, 1.0);
            let idx = (v * 7.0).round() as usize;
            let ch = SPARK_CHARS[idx.min(7)];
            let color = palette.gauge_gradient(v);
            Span::styled(String::from(ch), Style::default().fg(color))
        })
        .collect()
}

/// Segmented gauge with color zones: green <50%, yellow 50-75%, orange 75-90%, red >90%.
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
pub fn segmented_gauge<'a>(used_pct: f64, width: usize, palette: &ThemePalette) -> Vec<Span<'a>> {
    let clamped = used_pct.clamp(0.0, 100.0);
    let filled = ((clamped / 100.0) * width as f64).round() as usize;
    let filled = filled.min(width);
    let empty = width.saturating_sub(filled);

    let mut spans = vec![Span::styled(
        "[",
        Style::default().fg(palette.muted_color()),
    )];

    // Each filled cell gets a color based on its position in the bar.
    for i in 0..filled {
        #[allow(clippy::cast_precision_loss)]
        let pos_pct = (i as f64 / width as f64) * 100.0;
        let color = if pos_pct < 50.0 {
            palette.success_color()
        } else if pos_pct < 75.0 {
            palette.warning_color()
        } else if pos_pct < 90.0 {
            palette.orange_color()
        } else {
            palette.danger_color()
        };
        spans.push(Span::styled("\u{2588}", Style::default().fg(color)));
    }

    if empty > 0 {
        spans.push(Span::styled(
            "\u{2591}".repeat(empty),
            Style::default().fg(palette.muted_color()),
        ));
    }

    spans.push(Span::styled(
        format!("] {clamped:.0}%"),
        Style::default().fg(palette.text_secondary()),
    ));

    spans
}

/// Vertical mini-bar chart using block characters for inline metrics.
const BAR_CHARS: [char; 8] = [
    '\u{258F}', '\u{258E}', '\u{258D}', '\u{258C}', '\u{258B}', '\u{258A}', '\u{2589}', '\u{2588}',
];

#[must_use]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn mini_bar_chart<'a>(value: f64, color: PackedRgba) -> Span<'a> {
    let v = value.clamp(0.0, 1.0);
    let idx = (v * 7.0).round() as usize;
    Span::styled(
        String::from(BAR_CHARS[idx.min(7)]),
        Style::default().fg(color),
    )
}

/// Pill-style badge with background color and contrasting foreground.
#[must_use]
pub fn styled_badge<'a>(label: &str, bg: PackedRgba) -> Span<'a> {
    Span::styled(
        format!(" {label} "),
        Style::default()
            .fg(PackedRgba::rgb(20, 20, 30))
            .bg(bg)
            .bold(),
    )
}

/// Animated progress indicator keyed to tick count.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn progress_indicator<'a>(tick: u64, color: PackedRgba) -> Span<'a> {
    const FRAMES: [&str; 4] = ["\u{25CB}", "\u{25D4}", "\u{25D1}", "\u{25D5}"];
    let frame = FRAMES[(tick as usize) % FRAMES.len()];
    Span::styled(String::from(frame), Style::default().fg(color))
}

/// Styled key hint with inverted key label for footer bars.
#[must_use]
pub fn key_hint<'a>(key: &str, label: &str, accent: PackedRgba) -> Vec<Span<'a>> {
    vec![
        Span::styled(
            format!(" {key} "),
            Style::default()
                .fg(PackedRgba::rgb(20, 20, 30))
                .bg(accent)
                .bold(),
        ),
        Span::styled(
            format!(" {label} "),
            Style::default().fg(PackedRgba::rgb(160, 160, 160)),
        ),
    ]
}

/// Styled horizontal separator line using box-drawing characters.
#[must_use]
pub fn separator_line(width: usize, color: PackedRgba) -> Line {
    Line::from(Span::styled(
        "\u{2500}".repeat(width),
        Style::default().fg(color),
    ))
}

// ──────────────────── formatting helpers ────────────────────

/// Format a byte count as a human-readable string (B, KB, MB, GB).
#[must_use]
pub fn human_bytes(bytes: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let bytes_f = bytes as f64;
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1_048_576 {
        format!("{:.1} KB", bytes_f / 1024.0)
    } else if bytes < 1_073_741_824 {
        format!("{:.1} MB", bytes_f / 1_048_576.0)
    } else {
        format!("{:.1} GB", bytes_f / 1_073_741_824.0)
    }
}

/// Format a rate in bytes/sec as a human-readable string.
#[must_use]
pub fn human_rate(bps: f64) -> String {
    let abs = bps.abs();
    let sign = if bps < 0.0 { "-" } else { "+" };
    if abs < 1024.0 {
        format!("{sign}{abs:.0} B/s")
    } else if abs < 1_048_576.0 {
        format!("{sign}{:.1} KB/s", abs / 1024.0)
    } else {
        format!("{sign}{:.1} MB/s", abs / 1_048_576.0)
    }
}

/// Classify a write rate into a trend label.
#[must_use]
pub fn trend_label(rate_bps: f64) -> &'static str {
    if rate_bps > 1_000_000.0 {
        "(accelerating)"
    } else if rate_bps > 0.0 {
        "(stable)"
    } else if rate_bps < -1_000_000.0 {
        "(recovering)"
    } else {
        "(idle)"
    }
}

/// Format seconds as a compact human duration (e.g. "2h 13m").
#[must_use]
pub fn human_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        format!("{h}h {m:02}m")
    }
}

/// Extract HH:MM:SS from an ISO-8601 timestamp string.
#[must_use]
pub fn extract_time(iso: &str) -> &str {
    let time_part = iso.split('T').nth(1).unwrap_or(iso);
    time_part.split('.').next().unwrap_or(time_part)
}

/// Render a section header with separator line.
#[must_use]
pub fn section_header(title: &str, width: usize) -> String {
    let rule_len = width.saturating_sub(title.len() + 4);
    format!("── {title} {}", "─".repeat(rule_len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::theme::{AccessibilityProfile, ColorMode, ContrastMode, MotionMode, Theme};

    #[test]
    fn sparkline_clamps_out_of_range_values() {
        let line = sparkline(&[-9.0, 0.0, 0.5, 1.0, 7.5]);
        assert_eq!(line.chars().count(), 5);
        assert_eq!(line.chars().next(), Some('▁'));
        assert_eq!(line.chars().last(), Some('█'));
    }

    #[test]
    fn gauge_renders_percent_and_bounds() {
        let half = gauge(50.0, 20);
        let over = gauge(150.0, 10);
        assert!(half.contains("50%"));
        assert_eq!(over.matches('█').count(), 10);
    }

    #[test]
    fn badge_respects_no_color_mode() {
        let accessibility = AccessibilityProfile {
            contrast: ContrastMode::Standard,
            motion: MotionMode::Full,
            color: ColorMode::Disabled,
        };
        let theme = Theme::for_terminal(120, accessibility);
        let badge = status_badge("LIVE", theme.palette.success, accessibility);
        assert_eq!(badge, "[LIVE]");
    }
}
