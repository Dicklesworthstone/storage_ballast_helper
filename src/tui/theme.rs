//! Shared theme tokens and accessibility profile hooks for dashboard rendering.

#![allow(missing_docs)]

use std::env;

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
