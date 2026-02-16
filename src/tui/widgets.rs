//! Widget primitives and shared visual helpers for dashboard screens.

#![allow(missing_docs)]

/// Sparkline glyph ramp shared across screens.
pub const SPARK_CHARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// Render a normalized sparkline from `0.0..=1.0` values.
#[must_use]
pub fn sparkline(values: &[f64]) -> String {
    values
        .iter()
        .map(|value| {
            let idx = (value.clamp(0.0, 1.0) * 7.0).round() as usize;
            SPARK_CHARS[idx.min(7)]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparkline_clamps_out_of_range_values() {
        let line = sparkline(&[-9.0, 0.0, 0.5, 1.0, 7.5]);
        assert_eq!(line.chars().count(), 5);
        assert_eq!(line.chars().next(), Some('▁'));
        assert_eq!(line.chars().last(), Some('█'));
    }
}
