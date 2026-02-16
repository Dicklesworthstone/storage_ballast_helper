//! Dashboard user-preferences model with safe atomic persistence.
//!
//! Operators configure dashboard UX defaults (start screen, density, contrast,
//! hint verbosity) once and have them survive across sessions. The module is
//! designed so that persistence failures **never** block dashboard startup,
//! rendering, or safety-critical workflows.
//!
//! # Merge Order
//!
//! ```text
//! compiled defaults → persisted preferences → CLI/session overrides
//! ```
//!
//! Overrides win; lower layers provide fallback when higher layers are absent
//! or invalid.
//!
//! # Persistence Strategy
//!
//! Atomic write: serialize → temp file → fsync → rename over target. This
//! guarantees that readers never see a partial write. Debounce prevents
//! high-frequency saves (e.g. rapid preference toggling) from thrashing disk.
//!
//! # Error Philosophy
//!
//! Load errors: log + fall back to compiled defaults (never panic).
//! Save errors: surface as transient notification (never block).

use std::fmt;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::model::Screen;
use super::theme::{ContrastMode, MotionMode};

// ──────────────────── schema version ────────────────────

/// Current schema version. Bump when adding fields that older versions
/// wouldn't understand. `#[serde(default)]` ensures forward compatibility
/// for additive changes without a version bump.
const SCHEMA_VERSION: u32 = 1;

/// Minimum debounce interval between persisted writes.
const WRITE_DEBOUNCE: Duration = Duration::from_secs(2);

// ──────────────────── core preferences ────────────────────

/// Persisted dashboard UX preferences.
///
/// Every field has a sensible compiled default so the dashboard works even
/// without a preferences file. All fields carry `#[serde(default)]` so that
/// additive schema evolution just works.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UserPreferences {
    /// Schema version for migration detection.
    pub schema_version: u32,

    /// Screen to display on dashboard startup.
    #[serde(default = "default_start_screen")]
    pub start_screen: StartScreen,

    /// Visual density mode.
    #[serde(default)]
    pub density: DensityMode,

    /// Contrast preference (overrides environment detection if set).
    #[serde(default)]
    pub contrast: ContrastPreference,

    /// Motion preference (overrides environment detection if set).
    #[serde(default)]
    pub motion: MotionPreference,

    /// How verbose in-dashboard hints should be.
    #[serde(default)]
    pub hint_verbosity: HintVerbosity,

    /// How long notifications stay visible (seconds). 0 = never auto-dismiss.
    #[serde(default = "default_notification_timeout")]
    pub notification_timeout_secs: u32,

    /// Whether to show the help overlay on first launch.
    #[serde(default = "default_show_help_on_start")]
    pub show_help_on_start: bool,
}

impl Default for UserPreferences {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            start_screen: StartScreen::default(),
            density: DensityMode::default(),
            contrast: ContrastPreference::default(),
            motion: MotionPreference::default(),
            hint_verbosity: HintVerbosity::default(),
            notification_timeout_secs: default_notification_timeout(),
            show_help_on_start: default_show_help_on_start(),
        }
    }
}

fn default_start_screen() -> StartScreen {
    StartScreen::default()
}
fn default_notification_timeout() -> u32 {
    5
}
fn default_show_help_on_start() -> bool {
    true
}

// ──────────────────── preference enums ────────────────────

/// Start screen preference. Wraps the model Screen enum for serde
/// compatibility with stable string names.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartScreen {
    #[default]
    Overview,
    Timeline,
    Explainability,
    Candidates,
    Ballast,
    LogSearch,
    Diagnostics,
    /// Last-used screen from previous session.
    Remember,
}

impl StartScreen {
    /// Resolve to a concrete `Screen`, using `last_screen` for the `Remember`
    /// variant.
    #[must_use]
    pub fn resolve(self, last_screen: Option<Screen>) -> Screen {
        match self {
            Self::Overview => Screen::Overview,
            Self::Timeline => Screen::Timeline,
            Self::Explainability => Screen::Explainability,
            Self::Candidates => Screen::Candidates,
            Self::Ballast => Screen::Ballast,
            Self::LogSearch => Screen::LogSearch,
            Self::Diagnostics => Screen::Diagnostics,
            Self::Remember => last_screen.unwrap_or(Screen::Overview),
        }
    }
}

/// Visual density.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DensityMode {
    /// Tighter layout for smaller terminals.
    Compact,
    /// Balanced spacing (default).
    #[default]
    Comfortable,
}

/// Contrast preference.
///
/// `Auto` means defer to environment detection (`NO_COLOR`, terminal
/// capabilities). `Force*` variants override environment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContrastPreference {
    #[default]
    Auto,
    ForceStandard,
    ForceHigh,
}

impl ContrastPreference {
    /// Resolve to a concrete `ContrastMode`, using `env_detected` as the
    /// fallback for `Auto`.
    #[must_use]
    pub fn resolve(self, env_detected: ContrastMode) -> ContrastMode {
        match self {
            Self::Auto => env_detected,
            Self::ForceStandard => ContrastMode::Standard,
            Self::ForceHigh => ContrastMode::High,
        }
    }
}

/// Motion preference.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MotionPreference {
    #[default]
    Auto,
    ForceFull,
    ForceReduced,
}

impl MotionPreference {
    /// Resolve to a concrete `MotionMode`, using `env_detected` as fallback.
    #[must_use]
    pub fn resolve(self, env_detected: MotionMode) -> MotionMode {
        match self {
            Self::Auto => env_detected,
            Self::ForceFull => MotionMode::Full,
            Self::ForceReduced => MotionMode::Reduced,
        }
    }
}

/// How verbose inline hints should be.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HintVerbosity {
    /// Show all hints and guidance text.
    #[default]
    Full,
    /// Show abbreviated hints.
    Minimal,
    /// Hide all hints.
    Off,
}

// ──────────────────── validation ────────────────────

/// Validation result for loaded preferences.
#[derive(Debug, Clone)]
pub struct ValidationReport {
    pub warnings: Vec<String>,
    pub applied_defaults: Vec<String>,
}

impl ValidationReport {
    fn new() -> Self {
        Self {
            warnings: Vec::new(),
            applied_defaults: Vec::new(),
        }
    }

    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.warnings.is_empty() && self.applied_defaults.is_empty()
    }
}

/// Validate and normalize loaded preferences. Returns the (possibly patched)
/// preferences and a report of any issues found.
pub fn validate(mut prefs: UserPreferences) -> (UserPreferences, ValidationReport) {
    let mut report = ValidationReport::new();

    if prefs.schema_version > SCHEMA_VERSION {
        report.warnings.push(format!(
            "preferences schema version {} is newer than supported {}; \
             unknown fields will be ignored",
            prefs.schema_version, SCHEMA_VERSION,
        ));
    }

    if prefs.notification_timeout_secs > 300 {
        report.warnings.push(format!(
            "notification_timeout_secs={} exceeds 300s max; clamped to 300",
            prefs.notification_timeout_secs,
        ));
        prefs.notification_timeout_secs = 300;
    }

    (prefs, report)
}

// ──────────────────── display ────────────────────

impl fmt::Display for DensityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compact => write!(f, "compact"),
            Self::Comfortable => write!(f, "comfortable"),
        }
    }
}

impl fmt::Display for HintVerbosity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => write!(f, "full"),
            Self::Minimal => write!(f, "minimal"),
            Self::Off => write!(f, "off"),
        }
    }
}

impl fmt::Display for ContrastPreference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::ForceStandard => write!(f, "standard"),
            Self::ForceHigh => write!(f, "high"),
        }
    }
}

impl fmt::Display for MotionPreference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::ForceFull => write!(f, "full"),
            Self::ForceReduced => write!(f, "reduced"),
        }
    }
}

// ──────────────────── persistence ────────────────────

/// Load outcome from the persistence layer.
#[derive(Debug)]
pub enum LoadOutcome {
    /// Successfully loaded and validated.
    Loaded {
        prefs: UserPreferences,
        report: ValidationReport,
    },
    /// File not found — using defaults (normal for first launch).
    Missing,
    /// File exists but is corrupt or unparseable — using defaults.
    Corrupt {
        details: String,
        defaults: UserPreferences,
    },
    /// I/O error reading the file — using defaults.
    IoError {
        details: String,
        defaults: UserPreferences,
    },
}

impl LoadOutcome {
    /// Extract the effective preferences regardless of load status.
    #[must_use]
    pub fn into_prefs(self) -> UserPreferences {
        match self {
            Self::Loaded { prefs, .. } => prefs,
            Self::Missing => UserPreferences::default(),
            Self::Corrupt { defaults, .. } | Self::IoError { defaults, .. } => defaults,
        }
    }

    /// Whether the load was successful (loaded or first-launch missing).
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Loaded { .. } | Self::Missing)
    }
}

/// Resolve the default preferences file path.
///
/// Uses `SBH_PREFERENCES_FILE` env var if set, otherwise
/// `~/.config/sbh/preferences.json`.
pub fn default_preferences_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("SBH_PREFERENCES_FILE") {
        return Some(PathBuf::from(path));
    }

    home_dir().map(|home| home.join(".config").join("sbh").join("preferences.json"))
}

/// Load preferences from a file path.
///
/// Returns a [`LoadOutcome`] — never panics, never blocks on error.
pub fn load(path: &Path) -> LoadOutcome {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return LoadOutcome::Missing,
        // Binary garbage / invalid UTF-8 is corrupt content, not an I/O error.
        Err(e) if e.kind() == io::ErrorKind::InvalidData => {
            return LoadOutcome::Corrupt {
                details: format!("{e}"),
                defaults: UserPreferences::default(),
            };
        }
        Err(e) => {
            return LoadOutcome::IoError {
                details: format!("{e}"),
                defaults: UserPreferences::default(),
            };
        }
    };

    let prefs: UserPreferences = match serde_json::from_str(&content) {
        Ok(p) => p,
        Err(e) => {
            return LoadOutcome::Corrupt {
                details: format!("{e}"),
                defaults: UserPreferences::default(),
            };
        }
    };

    let (prefs, report) = validate(prefs);
    LoadOutcome::Loaded { prefs, report }
}

/// Atomic save: serialize → temp file → fsync → rename.
///
/// Creates parent directories as needed. Returns the path written on success.
pub fn save(prefs: &UserPreferences, path: &Path) -> io::Result<PathBuf> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(prefs)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Write to temp file in same directory (same filesystem for rename).
    let tmp_path = path.with_extension("json.tmp");
    {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
    }

    // Atomic rename over target.
    fs::rename(&tmp_path, path)?;

    Ok(path.to_path_buf())
}

// ──────────────────── debounced writer ────────────────────

/// Debounced writer that limits persistence frequency.
///
/// Call `request_save()` whenever preferences change. The writer will
/// delay the actual write until the debounce interval elapses, coalescing
/// rapid changes into a single I/O.
pub struct DebouncedWriter {
    path: PathBuf,
    debounce: Duration,
    last_write: Option<Instant>,
    pending: bool,
}

impl DebouncedWriter {
    /// Create a new writer targeting the given path.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            debounce: WRITE_DEBOUNCE,
            last_write: None,
            pending: false,
        }
    }

    /// Override the debounce interval (useful for testing).
    #[must_use]
    pub fn with_debounce(mut self, d: Duration) -> Self {
        self.debounce = d;
        self
    }

    /// Mark that preferences have changed and should be persisted.
    pub fn request_save(&mut self) {
        self.pending = true;
    }

    /// Check if a save is pending.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.pending
    }

    /// Attempt to flush if the debounce interval has elapsed. Returns
    /// `Some(Ok(path))` if a write happened, `Some(Err(e))` if it failed,
    /// or `None` if no write was needed yet.
    pub fn try_flush(&mut self, prefs: &UserPreferences) -> Option<io::Result<PathBuf>> {
        if !self.pending {
            return None;
        }

        let now = Instant::now();
        if let Some(last) = self.last_write
            && now.duration_since(last) < self.debounce
        {
            return None; // Too soon.
        }

        self.pending = false;
        self.last_write = Some(now);
        Some(save(prefs, &self.path))
    }

    /// Force an immediate write, bypassing debounce. Used on shutdown.
    pub fn force_flush(&mut self, prefs: &UserPreferences) -> Option<io::Result<PathBuf>> {
        if !self.pending {
            return None;
        }

        self.pending = false;
        self.last_write = Some(Instant::now());
        Some(save(prefs, &self.path))
    }
}

// ──────────────────── merge ────────────────────

/// Session overrides that take precedence over persisted preferences.
///
/// Populated from CLI flags like `--start-screen`, `--density`, etc.
/// `None` means "use persisted value".
#[derive(Debug, Clone, Default)]
pub struct SessionOverrides {
    pub start_screen: Option<StartScreen>,
    pub density: Option<DensityMode>,
    pub contrast: Option<ContrastPreference>,
    pub motion: Option<MotionPreference>,
    pub hint_verbosity: Option<HintVerbosity>,
    pub notification_timeout_secs: Option<u32>,
}

/// Merge compiled defaults → persisted → session overrides.
///
/// Returns the effective preferences for this session. Session overrides
/// are **not** persisted (they're transient for the current invocation).
#[must_use]
pub fn merge(persisted: &UserPreferences, overrides: &SessionOverrides) -> UserPreferences {
    UserPreferences {
        schema_version: persisted.schema_version,
        start_screen: overrides.start_screen.unwrap_or(persisted.start_screen),
        density: overrides.density.unwrap_or(persisted.density),
        contrast: overrides.contrast.unwrap_or(persisted.contrast),
        motion: overrides.motion.unwrap_or(persisted.motion),
        hint_verbosity: overrides.hint_verbosity.unwrap_or(persisted.hint_verbosity),
        notification_timeout_secs: overrides
            .notification_timeout_secs
            .unwrap_or(persisted.notification_timeout_secs),
        show_help_on_start: persisted.show_help_on_start,
    }
}

// ──────────────────── resolved preferences ────────────────────

/// Fully resolved preferences ready for consumption by the dashboard model.
///
/// All `Auto` values are resolved against environment detection. This is the
/// struct that model/update/render consume — no more `Auto` ambiguity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPreferences {
    pub start_screen: Screen,
    pub density: DensityMode,
    pub contrast: ContrastMode,
    pub motion: MotionMode,
    pub hint_verbosity: HintVerbosity,
    pub notification_timeout: Duration,
    pub show_help_on_start: bool,
}

impl ResolvedPreferences {
    /// Resolve from merged preferences using environment-detected accessibility
    /// settings and an optional last-used screen.
    #[must_use]
    pub fn resolve(
        prefs: &UserPreferences,
        env_contrast: ContrastMode,
        env_motion: MotionMode,
        last_screen: Option<Screen>,
    ) -> Self {
        Self {
            start_screen: prefs.start_screen.resolve(last_screen),
            density: prefs.density,
            contrast: prefs.contrast.resolve(env_contrast),
            motion: prefs.motion.resolve(env_motion),
            hint_verbosity: prefs.hint_verbosity,
            notification_timeout: Duration::from_secs(u64::from(prefs.notification_timeout_secs)),
            show_help_on_start: prefs.show_help_on_start,
        }
    }
}

// ──────────────────── internal helpers ────────────────────

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Default values ──

    #[test]
    fn defaults_are_sensible() {
        let prefs = UserPreferences::default();
        assert_eq!(prefs.schema_version, SCHEMA_VERSION);
        assert_eq!(prefs.start_screen, StartScreen::Overview);
        assert_eq!(prefs.density, DensityMode::Comfortable);
        assert_eq!(prefs.contrast, ContrastPreference::Auto);
        assert_eq!(prefs.motion, MotionPreference::Auto);
        assert_eq!(prefs.hint_verbosity, HintVerbosity::Full);
        assert_eq!(prefs.notification_timeout_secs, 5);
        assert!(prefs.show_help_on_start);
    }

    // ── JSON roundtrip ──

    #[test]
    fn roundtrip_json() {
        let prefs = UserPreferences {
            start_screen: StartScreen::Timeline,
            density: DensityMode::Compact,
            contrast: ContrastPreference::ForceHigh,
            motion: MotionPreference::ForceReduced,
            hint_verbosity: HintVerbosity::Off,
            notification_timeout_secs: 10,
            show_help_on_start: false,
            ..Default::default()
        };
        let json = serde_json::to_string_pretty(&prefs).unwrap();
        let back: UserPreferences = serde_json::from_str(&json).unwrap();
        assert_eq!(prefs, back);
    }

    #[test]
    fn deserialize_empty_object_gives_defaults() {
        let back: UserPreferences = serde_json::from_str("{}").unwrap();
        assert_eq!(back, UserPreferences::default());
    }

    #[test]
    fn deserialize_partial_object_fills_defaults() {
        let json = r#"{"density": "compact"}"#;
        let back: UserPreferences = serde_json::from_str(json).unwrap();
        assert_eq!(back.density, DensityMode::Compact);
        assert_eq!(back.start_screen, StartScreen::Overview); // default
        assert_eq!(back.hint_verbosity, HintVerbosity::Full); // default
    }

    #[test]
    fn unknown_fields_ignored() {
        let json = r#"{"density": "compact", "future_field": 42}"#;
        let back: UserPreferences = serde_json::from_str(json).unwrap();
        assert_eq!(back.density, DensityMode::Compact);
    }

    // ── Validation ──

    #[test]
    fn validation_clamps_notification_timeout() {
        let prefs = UserPreferences {
            notification_timeout_secs: 9999,
            ..Default::default()
        };
        let (fixed, report) = validate(prefs);
        assert_eq!(fixed.notification_timeout_secs, 300);
        assert!(!report.warnings.is_empty());
    }

    #[test]
    fn validation_warns_on_future_schema() {
        let prefs = UserPreferences {
            schema_version: 999,
            ..Default::default()
        };
        let (_, report) = validate(prefs);
        assert!(report.warnings.iter().any(|w| w.contains("newer")));
    }

    #[test]
    fn validation_passes_for_defaults() {
        let (_, report) = validate(UserPreferences::default());
        assert!(report.is_clean());
    }

    // ── StartScreen resolution ──

    #[test]
    fn start_screen_resolve_explicit() {
        assert_eq!(StartScreen::Diagnostics.resolve(None), Screen::Diagnostics,);
    }

    #[test]
    fn start_screen_resolve_remember_with_last() {
        assert_eq!(
            StartScreen::Remember.resolve(Some(Screen::Ballast)),
            Screen::Ballast,
        );
    }

    #[test]
    fn start_screen_resolve_remember_without_last() {
        assert_eq!(StartScreen::Remember.resolve(None), Screen::Overview,);
    }

    // ── Contrast/motion resolution ──

    #[test]
    fn contrast_auto_defers_to_env() {
        assert_eq!(
            ContrastPreference::Auto.resolve(ContrastMode::High),
            ContrastMode::High,
        );
    }

    #[test]
    fn contrast_force_overrides_env() {
        assert_eq!(
            ContrastPreference::ForceStandard.resolve(ContrastMode::High),
            ContrastMode::Standard,
        );
    }

    #[test]
    fn motion_auto_defers_to_env() {
        assert_eq!(
            MotionPreference::Auto.resolve(MotionMode::Reduced),
            MotionMode::Reduced,
        );
    }

    #[test]
    fn motion_force_overrides_env() {
        assert_eq!(
            MotionPreference::ForceFull.resolve(MotionMode::Reduced),
            MotionMode::Full,
        );
    }

    // ── Merge ──

    #[test]
    fn merge_uses_persisted_when_no_overrides() {
        let persisted = UserPreferences {
            density: DensityMode::Compact,
            ..Default::default()
        };
        let merged = merge(&persisted, &SessionOverrides::default());
        assert_eq!(merged.density, DensityMode::Compact);
    }

    #[test]
    fn merge_override_wins() {
        let persisted = UserPreferences::default();
        let overrides = SessionOverrides {
            density: Some(DensityMode::Compact),
            hint_verbosity: Some(HintVerbosity::Off),
            ..Default::default()
        };
        let merged = merge(&persisted, &overrides);
        assert_eq!(merged.density, DensityMode::Compact);
        assert_eq!(merged.hint_verbosity, HintVerbosity::Off);
        // Non-overridden fields stay at persisted.
        assert_eq!(merged.start_screen, StartScreen::Overview);
    }

    // ── ResolvedPreferences ──

    #[test]
    fn resolved_preferences_complete() {
        let prefs = UserPreferences {
            start_screen: StartScreen::Remember,
            contrast: ContrastPreference::ForceHigh,
            motion: MotionPreference::Auto,
            notification_timeout_secs: 10,
            ..Default::default()
        };
        let resolved = ResolvedPreferences::resolve(
            &prefs,
            ContrastMode::Standard,
            MotionMode::Full,
            Some(Screen::Timeline),
        );
        assert_eq!(resolved.start_screen, Screen::Timeline);
        assert_eq!(resolved.contrast, ContrastMode::High);
        assert_eq!(resolved.motion, MotionMode::Full);
        assert_eq!(resolved.notification_timeout, Duration::from_secs(10));
    }

    // ── Persistence ──

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prefs.json");

        let prefs = UserPreferences {
            density: DensityMode::Compact,
            hint_verbosity: HintVerbosity::Minimal,
            ..Default::default()
        };

        save(&prefs, &path).unwrap();
        let outcome = load(&path);
        match outcome {
            LoadOutcome::Loaded {
                prefs: loaded,
                report,
            } => {
                assert_eq!(loaded, prefs);
                assert!(report.is_clean());
            }
            other => panic!("expected Loaded, got {other:?}"),
        }
    }

    #[test]
    fn load_missing_file_returns_missing() {
        let path = PathBuf::from("/nonexistent/sbh/prefs.json");
        assert!(matches!(load(&path), LoadOutcome::Missing));
    }

    #[test]
    fn load_corrupt_file_returns_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prefs.json");
        fs::write(&path, "not valid json {{{").unwrap();
        let outcome = load(&path);
        assert!(matches!(outcome, LoadOutcome::Corrupt { .. }));
    }

    #[test]
    fn load_outcome_into_prefs_returns_defaults_on_failure() {
        let outcome = LoadOutcome::Corrupt {
            details: "bad".into(),
            defaults: UserPreferences::default(),
        };
        let prefs = outcome.into_prefs();
        assert_eq!(prefs, UserPreferences::default());
    }

    #[test]
    fn save_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deep").join("nested").join("prefs.json");
        let prefs = UserPreferences::default();
        save(&prefs, &path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn save_atomicity_no_tmp_leftover() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prefs.json");
        let tmp_path = path.with_extension("json.tmp");
        save(&UserPreferences::default(), &path).unwrap();
        assert!(path.exists());
        assert!(!tmp_path.exists());
    }

    // ── Debounced writer ──

    #[test]
    fn debounced_writer_no_pending_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prefs.json");
        let mut writer = DebouncedWriter::new(path);
        assert!(writer.try_flush(&UserPreferences::default()).is_none());
    }

    #[test]
    fn debounced_writer_first_save_immediate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prefs.json");
        let mut writer = DebouncedWriter::new(path.clone()).with_debounce(Duration::ZERO);
        writer.request_save();
        let result = writer.try_flush(&UserPreferences::default());
        assert!(result.is_some());
        assert!(result.unwrap().is_ok());
        assert!(path.exists());
    }

    #[test]
    fn debounced_writer_respects_debounce() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prefs.json");
        let mut writer = DebouncedWriter::new(path).with_debounce(Duration::from_secs(60));

        // First write goes through.
        writer.request_save();
        assert!(writer.try_flush(&UserPreferences::default()).is_some());

        // Second write within debounce is suppressed.
        writer.request_save();
        assert!(writer.try_flush(&UserPreferences::default()).is_none());
        assert!(writer.is_pending()); // Still pending.
    }

    #[test]
    fn debounced_writer_force_flush_bypasses_debounce() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prefs.json");
        let mut writer = DebouncedWriter::new(path).with_debounce(Duration::from_secs(60));

        // First write.
        writer.request_save();
        assert!(writer.try_flush(&UserPreferences::default()).is_some());

        // Force flush bypasses debounce.
        writer.request_save();
        assert!(writer.force_flush(&UserPreferences::default()).is_some());
        assert!(!writer.is_pending());
    }

    // ── Display impls ──

    #[test]
    fn display_impls() {
        assert_eq!(DensityMode::Compact.to_string(), "compact");
        assert_eq!(DensityMode::Comfortable.to_string(), "comfortable");
        assert_eq!(HintVerbosity::Full.to_string(), "full");
        assert_eq!(HintVerbosity::Off.to_string(), "off");
        assert_eq!(ContrastPreference::Auto.to_string(), "auto");
        assert_eq!(ContrastPreference::ForceHigh.to_string(), "high");
        assert_eq!(MotionPreference::ForceReduced.to_string(), "reduced");
    }

    // ── Enum serde ──

    #[test]
    fn start_screen_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&StartScreen::LogSearch).unwrap(),
            "\"log_search\"",
        );
        let back: StartScreen = serde_json::from_str("\"log_search\"").unwrap();
        assert_eq!(back, StartScreen::LogSearch);
    }

    #[test]
    fn density_mode_serde() {
        let json = serde_json::to_string(&DensityMode::Compact).unwrap();
        assert_eq!(json, "\"compact\"");
        let back: DensityMode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, DensityMode::Compact);
    }

    #[test]
    fn contrast_preference_serde() {
        for pref in [
            ContrastPreference::Auto,
            ContrastPreference::ForceStandard,
            ContrastPreference::ForceHigh,
        ] {
            let json = serde_json::to_string(&pref).unwrap();
            let back: ContrastPreference = serde_json::from_str(&json).unwrap();
            assert_eq!(pref, back);
        }
    }

    #[test]
    fn hint_verbosity_serde() {
        for v in [
            HintVerbosity::Full,
            HintVerbosity::Minimal,
            HintVerbosity::Off,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let back: HintVerbosity = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    // ── Edge cases ──

    #[test]
    fn notification_timeout_zero_means_no_dismiss() {
        let prefs = UserPreferences {
            notification_timeout_secs: 0,
            ..Default::default()
        };
        let (fixed, report) = validate(prefs);
        assert_eq!(fixed.notification_timeout_secs, 0);
        assert!(report.is_clean()); // 0 is valid (means never auto-dismiss).
    }

    #[test]
    fn load_outcome_is_ok_variants() {
        assert!(LoadOutcome::Missing.is_ok());
        assert!(
            !LoadOutcome::Corrupt {
                details: String::new(),
                defaults: UserPreferences::default(),
            }
            .is_ok()
        );
    }
}
