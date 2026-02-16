//! Widget primitives and shared visual helpers for dashboard screens.

#![allow(missing_docs)]

use super::theme::{AccessibilityProfile, PaletteEntry};

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
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
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
