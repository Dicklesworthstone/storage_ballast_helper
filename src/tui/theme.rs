//! Shared theme tokens and accessibility profile hooks for dashboard rendering.

#![allow(missing_docs)]

use std::env;

use ftui::{PackedRgba, Style};

/// Contrast profile used by theme token selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContrastMode {
    Standard,
    High,
}

/// Motion profile hook used by animated surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MotionMode {
    Full,
    Reduced,
}

/// Color output mode for compatibility with `NO_COLOR` and terminal policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    Enabled,
    Disabled,
}

/// Accessibility knobs consumed by theme/layout primitives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessibilityProfile {
    pub contrast: ContrastMode,
    pub motion: MotionMode,
    pub color: ColorMode,
}

impl Default for AccessibilityProfile {
    fn default() -> Self {
        Self {
            contrast: ContrastMode::Standard,
            motion: MotionMode::Full,
            color: ColorMode::Enabled,
        }
    }
}

impl AccessibilityProfile {
    #[must_use]
    pub const fn from_no_color_flag(no_color: bool) -> Self {
        Self {
            contrast: ContrastMode::Standard,
            motion: MotionMode::Full,
            color: if no_color {
                ColorMode::Disabled
            } else {
                ColorMode::Enabled
            },
        }
    }

    #[must_use]
    pub fn from_environment() -> Self {
        let no_color = env::var_os("NO_COLOR").is_some();
        Self::from_no_color_flag(no_color)
    }

    #[must_use]
    pub const fn no_color(self) -> bool {
        matches!(self.color, ColorMode::Disabled)
    }

    #[must_use]
    pub const fn reduced_motion(self) -> bool {
        matches!(self.motion, MotionMode::Reduced)
    }
}

/// Semantic token category independent of concrete color codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticToken {
    Accent,
    Success,
    Warning,
    Danger,
    Critical,
    Muted,
    Neutral,
}

/// Render-facing palette entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaletteEntry {
    pub token: SemanticToken,
    pub color_tag: &'static str,
    pub text_tag: &'static str,
}

impl PaletteEntry {
    const fn new(token: SemanticToken, color_tag: &'static str, text_tag: &'static str) -> Self {
        Self {
            token,
            color_tag,
            text_tag,
        }
    }
}

/// Shared semantic palette for all dashboard screens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThemePalette {
    pub accent: PaletteEntry,
    pub success: PaletteEntry,
    pub warning: PaletteEntry,
    pub danger: PaletteEntry,
    pub critical: PaletteEntry,
    pub muted: PaletteEntry,
    pub neutral: PaletteEntry,
}

impl ThemePalette {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            accent: PaletteEntry::new(SemanticToken::Accent, "cyan", "accent"),
            success: PaletteEntry::new(SemanticToken::Success, "green", "ok"),
            warning: PaletteEntry::new(SemanticToken::Warning, "yellow", "warn"),
            danger: PaletteEntry::new(SemanticToken::Danger, "red", "danger"),
            critical: PaletteEntry::new(SemanticToken::Critical, "magenta", "critical"),
            muted: PaletteEntry::new(SemanticToken::Muted, "dark-grey", "muted"),
            neutral: PaletteEntry::new(SemanticToken::Neutral, "white", "normal"),
        }
    }

    #[must_use]
    pub const fn high_contrast() -> Self {
        Self {
            accent: PaletteEntry::new(SemanticToken::Accent, "bright-cyan", "accent"),
            success: PaletteEntry::new(SemanticToken::Success, "bright-green", "ok"),
            warning: PaletteEntry::new(SemanticToken::Warning, "bright-yellow", "warn"),
            danger: PaletteEntry::new(SemanticToken::Danger, "bright-red", "danger"),
            critical: PaletteEntry::new(SemanticToken::Critical, "bright-red", "critical"),
            muted: PaletteEntry::new(SemanticToken::Muted, "grey", "muted"),
            neutral: PaletteEntry::new(SemanticToken::Neutral, "bright-white", "normal"),
        }
    }

    #[must_use]
    pub const fn from_contrast(mode: ContrastMode) -> Self {
        match mode {
            ContrastMode::Standard => Self::standard(),
            ContrastMode::High => Self::high_contrast(),
        }
    }

    // ── PackedRgba color accessors (tui feature only) ──

    #[must_use]
    pub fn accent_color(&self) -> PackedRgba {
        PackedRgba::rgb(0, 200, 200)
    }
    #[must_use]
    pub fn success_color(&self) -> PackedRgba {
        PackedRgba::rgb(80, 200, 80)
    }
    #[must_use]
    pub fn warning_color(&self) -> PackedRgba {
        PackedRgba::rgb(230, 190, 50)
    }
    #[must_use]
    pub fn orange_color(&self) -> PackedRgba {
        PackedRgba::rgb(230, 130, 30)
    }
    #[must_use]
    pub fn danger_color(&self) -> PackedRgba {
        PackedRgba::rgb(220, 60, 60)
    }
    #[must_use]
    pub fn critical_color(&self) -> PackedRgba {
        PackedRgba::rgb(200, 50, 200)
    }
    #[must_use]
    pub fn muted_color(&self) -> PackedRgba {
        PackedRgba::rgb(100, 100, 100)
    }
    #[must_use]
    pub fn text_primary(&self) -> PackedRgba {
        PackedRgba::rgb(220, 220, 220)
    }
    #[must_use]
    pub fn text_secondary(&self) -> PackedRgba {
        PackedRgba::rgb(160, 160, 160)
    }
    #[must_use]
    pub fn surface_bg(&self) -> PackedRgba {
        PackedRgba::rgb(20, 20, 30)
    }
    #[must_use]
    pub fn panel_bg(&self) -> PackedRgba {
        PackedRgba::rgb(30, 30, 45)
    }
    #[must_use]
    pub fn border_color(&self) -> PackedRgba {
        PackedRgba::rgb(60, 60, 80)
    }
    #[must_use]
    pub fn highlight_bg(&self) -> PackedRgba {
        PackedRgba::rgb(40, 50, 70)
    }

    // ── Screen accent colors ──

    /// Per-screen accent color for tab highlights and screen-specific chrome.
    #[must_use]
    pub fn screen_accent(&self, screen: &str) -> PackedRgba {
        match screen {
            "overview" => PackedRgba::rgb(0, 200, 200),  // cyan
            "timeline" => PackedRgba::rgb(80, 140, 220), // blue
            "explainability" => PackedRgba::rgb(160, 100, 220), // violet
            "candidates" => PackedRgba::rgb(220, 180, 40), // amber
            "ballast" => PackedRgba::rgb(50, 200, 120),  // emerald
            "logs" => PackedRgba::rgb(140, 150, 170),    // slate
            "diagnostics" => PackedRgba::rgb(220, 80, 120), // rose
            _ => self.accent_color(),
        }
    }

    /// Screen accent for active tab background, keyed by 1-based screen number.
    #[must_use]
    pub fn tab_active_bg(&self, screen_number: u8) -> PackedRgba {
        match screen_number {
            1 => PackedRgba::rgb(0, 200, 200),   // overview: cyan
            2 => PackedRgba::rgb(80, 140, 220),  // timeline: blue
            3 => PackedRgba::rgb(160, 100, 220), // explain: violet
            4 => PackedRgba::rgb(220, 180, 40),  // candidates: amber
            5 => PackedRgba::rgb(50, 200, 120),  // ballast: emerald
            6 => PackedRgba::rgb(140, 150, 170), // logs: slate
            7 => PackedRgba::rgb(220, 80, 120),  // diagnostics: rose
            _ => self.accent_color(),
        }
    }

    /// Interpolated gauge gradient from green through yellow/orange to red.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    pub fn gauge_gradient(&self, t: f64) -> PackedRgba {
        let t = t.clamp(0.0, 1.0);
        // Green(80,200,80) -> Yellow(230,190,50) -> Orange(230,130,30) -> Red(220,60,60)
        let (r, g, b) = if t < 0.33 {
            let f = t / 0.33;
            lerp_rgb((80, 200, 80), (230, 190, 50), f)
        } else if t < 0.66 {
            let f = (t - 0.33) / 0.33;
            lerp_rgb((230, 190, 50), (230, 130, 30), f)
        } else {
            let f = (t - 0.66) / 0.34;
            lerp_rgb((230, 130, 30), (220, 60, 60), f)
        };
        PackedRgba::rgb(r, g, b)
    }

    /// Semi-transparent overlay background for scrims.
    #[must_use]
    pub fn scrim_bg(&self) -> PackedRgba {
        PackedRgba::rgb(15, 15, 25)
    }

    /// Map a pressure level string to a `PackedRgba` color.
    #[must_use]
    pub fn pressure_color(&self, level: &str) -> PackedRgba {
        match level {
            "green" => self.success_color(),
            "yellow" => self.warning_color(),
            "orange" => self.orange_color(),
            "red" => self.danger_color(),
            "critical" => self.critical_color(),
            _ => self.muted_color(),
        }
    }

    /// Build a `Style` for a semantic token.
    #[must_use]
    pub fn token_style(&self, token: SemanticToken) -> Style {
        let color = match token {
            SemanticToken::Accent => self.accent_color(),
            SemanticToken::Success => self.success_color(),
            SemanticToken::Warning => self.warning_color(),
            SemanticToken::Danger => self.danger_color(),
            SemanticToken::Critical => self.critical_color(),
            SemanticToken::Muted => self.muted_color(),
            SemanticToken::Neutral => self.text_primary(),
        };
        Style::default().fg(color)
    }

    #[must_use]
    pub fn for_pressure_level(self, level: &str) -> PaletteEntry {
        match level {
            "green" => self.success,
            "yellow" => self.warning,
            "orange" | "red" => self.danger,
            "critical" => self.critical,
            _ => self.neutral,
        }
    }
}

/// Shared spacing scale used by all screens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpacingScale {
    pub outer_padding: u16,
    pub inner_padding: u16,
    pub section_gap: u16,
    pub row_gap: u16,
}

impl SpacingScale {
    #[must_use]
    pub const fn compact() -> Self {
        Self {
            outer_padding: 0,
            inner_padding: 1,
            section_gap: 0,
            row_gap: 0,
        }
    }

    #[must_use]
    pub const fn comfortable() -> Self {
        Self {
            outer_padding: 1,
            inner_padding: 2,
            section_gap: 1,
            row_gap: 1,
        }
    }

    #[must_use]
    pub const fn for_columns(cols: u16) -> Self {
        if cols < 100 {
            Self::compact()
        } else {
            Self::comfortable()
        }
    }
}

/// Full render theme (palette + spacing + accessibility profile).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    pub accessibility: AccessibilityProfile,
    pub palette: ThemePalette,
    pub spacing: SpacingScale,
}

impl Theme {
    #[must_use]
    pub const fn for_terminal(cols: u16, accessibility: AccessibilityProfile) -> Self {
        Self {
            palette: ThemePalette::from_contrast(accessibility.contrast),
            spacing: SpacingScale::for_columns(cols),
            accessibility,
        }
    }
}

/// Linear interpolation between two RGB triples.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::many_single_char_names
)]
fn lerp_rgb(from: (u8, u8, u8), to: (u8, u8, u8), factor: f64) -> (u8, u8, u8) {
    let factor = factor.clamp(0.0, 1.0);
    let red = (f64::from(to.0) - f64::from(from.0))
        .mul_add(factor, f64::from(from.0))
        .round() as u8;
    let green = (f64::from(to.1) - f64::from(from.1))
        .mul_add(factor, f64::from(from.1))
        .round() as u8;
    let blue = (f64::from(to.2) - f64::from(from.2))
        .mul_add(factor, f64::from(from.2))
        .round() as u8;
    (red, green, blue)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_color_profile_disables_color_mode() {
        let profile = AccessibilityProfile::from_no_color_flag(true);
        assert!(profile.no_color());
    }

    #[test]
    fn spacing_compacts_on_narrow_terminals() {
        let compact = SpacingScale::for_columns(80);
        let wide = SpacingScale::for_columns(140);
        assert!(compact.outer_padding < wide.outer_padding);
        assert!(compact.inner_padding < wide.inner_padding);
    }

    #[test]
    fn pressure_level_maps_to_semantic_tokens() {
        let palette = ThemePalette::standard();
        assert_eq!(
            palette.for_pressure_level("critical").token,
            SemanticToken::Critical
        );
        assert_eq!(
            palette.for_pressure_level("green").token,
            SemanticToken::Success
        );
    }
}
