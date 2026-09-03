//! `sbh docs`: documentation generated from the code (bd-rc-master-ajg1.12.2).
//!
//! The README used to carry hand-typed tables of environment variables,
//! dashboard keys, palette actions, and playbook entries, and they drifted.
//! This module builds one document from the binary's own tables (`--json`),
//! renders the Markdown for each section, and rewrites (`--render`) or
//! verifies (`--check`) the regions a file marks with
//! `<!-- sbh-docs:begin <section> -->` … `<!-- sbh-docs:end -->`. Prose
//! outside the markers is never touched.
//!
//! Sections: `env-vars` (the registry below, which a test keeps equal to
//! the `SBH_*` names the code reads), `commands` (from clap), and with the
//! `tui` feature `dashboard-screens`, `dashboard-keymap`,
//! `dashboard-palette`, `dashboard-playbook`; `defaults` is the default
//! configuration as TOML (JSON only).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};

use crate::core::config::Config;
use crate::core::errors::{ERROR_CODES, ErrorCodeDoc, Result, SbhError};
use crate::monitor::pid::{
    BATCH_SLOPE_KNEE, IntervalRule, LevelResponse, PressureLevel, RESPONSE_TABLE,
};

/// Bumped when a section's shape changes.
pub const SCHEMA_VERSION: u32 = 1;
/// Start of a generated region: `<!-- sbh-docs:begin <section> -->`.
pub const BEGIN_MARKER: &str = "<!-- sbh-docs:begin ";
/// End of a generated region.
pub const END_MARKER: &str = "<!-- sbh-docs:end -->";

/// What an environment variable belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvArea {
    /// Overrides one `config.toml` key (applied after the file is read).
    ConfigOverride,
    /// Where files live.
    Paths,
    /// How the CLI prints.
    Output,
    /// The dashboard.
    Dashboard,
    /// Service integration.
    Service,
    /// Release and update plumbing.
    Release,
    /// Test and CI hooks (honored only under `SBH_TEST_MODE=1` where noted).
    Test,
}

impl EnvArea {
    const fn label(self) -> &'static str {
        match self {
            Self::ConfigOverride => "config override",
            Self::Paths => "paths",
            Self::Output => "output",
            Self::Dashboard => "dashboard",
            Self::Service => "service",
            Self::Release => "release",
            Self::Test => "test",
        }
    }
}

/// One documented environment variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EnvVarDoc {
    pub name: &'static str,
    pub area: EnvArea,
    pub controls: &'static str,
}

const fn var(name: &'static str, area: EnvArea, controls: &'static str) -> EnvVarDoc {
    EnvVarDoc {
        name,
        area,
        controls,
    }
}

const fn cfg(name: &'static str, key: &'static str) -> EnvVarDoc {
    var(name, EnvArea::ConfigOverride, key)
}

/// Every `SBH_*` environment variable the code reads.
///
/// A config override's `controls` is the `config.toml` key it sets. A unit
/// test walks `src/` and fails when a variable is read but not listed here,
/// or listed but no longer read.
pub const ENV_VARS: &[EnvVarDoc] = &[
    var(
        "SBH_CONFIG",
        EnvArea::Paths,
        "Config file path when `--config` is not given",
    ),
    var(
        "SBH_CONFIG_PATH",
        EnvArea::Service,
        "Config file path the launchd plist hands the daemon",
    ),
    var(
        "SBH_USE_XDG_PATHS",
        EnvArea::Paths,
        "Use XDG user paths (`~/.config/sbh`, `~/.local/share/sbh`) instead of the system paths",
    ),
    var(
        "SBH_OUTPUT_FORMAT",
        EnvArea::Output,
        "`human` or `json` when neither `--json` nor a terminal decides",
    ),
    var(
        "SBH_PREFERENCES_FILE",
        EnvArea::Dashboard,
        "Dashboard preferences file (default `~/.config/sbh/preferences.json`)",
    ),
    cfg("SBH_DASHBOARD_MODE", "`dashboard.mode` (`legacy` or `new`)"),
    cfg(
        "SBH_DASHBOARD_KILL_SWITCH",
        "`dashboard.kill_switch` (force the live status view)",
    ),
    var(
        "SBH_LAUNCHD_LABEL",
        EnvArea::Service,
        "launchd job label override for the macOS service",
    ),
    var(
        "SBH_SYSTEMD_UNIT_DIR",
        EnvArea::Service,
        "Directory the systemd unit is written to and read from",
    ),
    var(
        "SBH_ACTIVE_LEASE_TOKEN",
        EnvArea::Service,
        "Renewal token `sbh lease run` hands the leased command (`lease renew` reads it)",
    ),
    var(
        "SBH_ACTIVE_LEASE_TARGET",
        EnvArea::Service,
        "Leased target `sbh lease run` hands the leased command (default for `lease status`/`renew`)",
    ),
    var(
        "SBH_MACOS_QUERY_FOUNDATION_PURGEABLE",
        EnvArea::Service,
        "Ask Foundation for purgeable space on macOS (opt-in, slower)",
    ),
    cfg("SBH_BEHAVIOR_PRESET", "`pressure.behavior_preset`"),
    cfg("SBH_POLICY_KILL_SWITCH", "`policy.kill_switch`"),
    cfg("SBH_PREDICTION_ENABLED", "`prediction.enabled`"),
    cfg("SBH_PREDICTION_MIN_SAMPLES", "`prediction.min_samples`"),
    cfg(
        "SBH_PREDICTION_MIN_CONFIDENCE",
        "`prediction.min_confidence`",
    ),
    cfg(
        "SBH_PREDICTION_WARNING_HORIZON_MINUTES",
        "`prediction.warning_horizon_minutes`",
    ),
    cfg(
        "SBH_PREDICTION_ACTION_HORIZON_MINUTES",
        "`prediction.action_horizon_minutes`",
    ),
    cfg(
        "SBH_PREDICTION_IMMINENT_DANGER_MINUTES",
        "`prediction.imminent_danger_minutes`",
    ),
    cfg(
        "SBH_PREDICTION_CRITICAL_DANGER_MINUTES",
        "`prediction.critical_danger_minutes`",
    ),
    cfg(
        "SBH_PRESSURE_POLL_INTERVAL_MS",
        "`pressure.poll_interval_ms`",
    ),
    cfg(
        "SBH_PRESSURE_GREEN_MIN_FREE_PCT",
        "`pressure.green_min_free_pct`",
    ),
    cfg(
        "SBH_PRESSURE_YELLOW_MIN_FREE_PCT",
        "`pressure.yellow_min_free_pct`",
    ),
    cfg(
        "SBH_PRESSURE_ORANGE_MIN_FREE_PCT",
        "`pressure.orange_min_free_pct`",
    ),
    cfg(
        "SBH_PRESSURE_RED_MIN_FREE_PCT",
        "`pressure.red_min_free_pct`",
    ),
    cfg(
        "SBH_PRESSURE_BEHAVIOR_HYSTERESIS_SECS",
        "`pressure.behavior_hysteresis_secs`",
    ),
    cfg("SBH_SCANNER_ENGINE", "`scanner.engine`"),
    cfg("SBH_SCANNER_EVENT_SOURCE", "`scanner.event_source`"),
    cfg(
        "SBH_SCANNER_EVENT_WATCH_BUDGET",
        "`scanner.event_watch_budget`",
    ),
    cfg("SBH_SCANNER_DRY_RUN", "`scanner.dry_run`"),
    cfg("SBH_SCANNER_CROSS_DEVICES", "`scanner.cross_devices`"),
    cfg("SBH_SCANNER_FOLLOW_SYMLINKS", "`scanner.follow_symlinks`"),
    cfg("SBH_SCANNER_MAX_DEPTH", "`scanner.max_depth`"),
    cfg("SBH_SCANNER_PARALLELISM", "`scanner.parallelism`"),
    cfg("SBH_SCANNER_MAX_DELETE_BATCH", "`scanner.max_delete_batch`"),
    cfg(
        "SBH_SCANNER_MIN_FILE_AGE_MINUTES",
        "`scanner.min_file_age_minutes`",
    ),
    cfg(
        "SBH_SCANNER_MIN_RESCAN_INTERVAL_SECS",
        "`scanner.min_rescan_interval_secs`",
    ),
    cfg(
        "SBH_SCANNER_MAX_SCAN_DUTY_CYCLE_PCT",
        "`scanner.max_scan_duty_cycle_pct`",
    ),
    cfg(
        "SBH_SCANNER_ACTIVE_REFERENCE_CACHE_TTL_SECS",
        "`scanner.active_reference_cache_ttl_secs`",
    ),
    cfg(
        "SBH_SCANNER_ACTIVE_REFERENCE_MIN_SIZE_BYTES",
        "`scanner.active_reference_min_size_bytes`",
    ),
    cfg(
        "SBH_SCANNER_REPEAT_DELETION_BASE_COOLDOWN_SECS",
        "`scanner.repeat_deletion_base_cooldown_secs`",
    ),
    cfg(
        "SBH_SCANNER_REPEAT_DELETION_MAX_COOLDOWN_SECS",
        "`scanner.repeat_deletion_max_cooldown_secs`",
    ),
    cfg("SBH_SCORING_LOCATION_WEIGHT", "`scoring.location_weight`"),
    cfg("SBH_SCORING_NAME_WEIGHT", "`scoring.name_weight`"),
    cfg("SBH_SCORING_AGE_WEIGHT", "`scoring.age_weight`"),
    cfg("SBH_SCORING_SIZE_WEIGHT", "`scoring.size_weight`"),
    cfg("SBH_SCORING_STRUCTURE_WEIGHT", "`scoring.structure_weight`"),
    cfg("SBH_SCORING_MIN_SCORE", "`scoring.min_score`"),
    cfg(
        "SBH_SCORING_CALIBRATION_FLOOR",
        "`scoring.calibration_floor`",
    ),
    cfg(
        "SBH_SCORING_POSTERIOR_FLOOR_DEFINITE",
        "`scoring.posterior_floor_definite`",
    ),
    cfg(
        "SBH_SCORING_FALSE_POSITIVE_LOSS",
        "`scoring.false_positive_loss`",
    ),
    cfg(
        "SBH_SCORING_FALSE_NEGATIVE_LOSS",
        "`scoring.false_negative_loss`",
    ),
    cfg(
        "SBH_SYSTEM_TUNING_WRITEBACK_ENABLED",
        "`system_tuning.writeback.enabled`",
    ),
    cfg(
        "SBH_SYSTEM_TUNING_WRITEBACK_AUTO_APPLY_ON_INSTALL",
        "`system_tuning.writeback.auto_apply_on_install`",
    ),
    cfg(
        "SBH_SYSTEM_TUNING_WRITEBACK_TARGET_DRAIN_SECS",
        "`system_tuning.writeback.target_drain_secs`",
    ),
    cfg(
        "SBH_SYSTEM_TUNING_WRITEBACK_HARD_RATIO",
        "`system_tuning.writeback.hard_ratio`",
    ),
    cfg(
        "SBH_SYSTEM_TUNING_WRITEBACK_MIN_BACKGROUND_BYTES",
        "`system_tuning.writeback.min_background_bytes`",
    ),
    cfg(
        "SBH_SYSTEM_TUNING_WRITEBACK_MAX_BACKGROUND_BYTES",
        "`system_tuning.writeback.max_background_bytes`",
    ),
    cfg(
        "SBH_SYSTEM_TUNING_WRITEBACK_BENCHMARK_ENABLED",
        "`system_tuning.writeback.benchmark_enabled`",
    ),
    cfg(
        "SBH_SYSTEM_TUNING_WRITEBACK_BENCHMARK_BYTES",
        "`system_tuning.writeback.benchmark_bytes`",
    ),
    cfg(
        "SBH_SYSTEM_TUNING_WRITEBACK_POOL_WARN_BYTES",
        "`system_tuning.writeback.pool_warn_bytes`",
    ),
    cfg("SBH_TELEMETRY_CPU_BUDGET_PCT", "`telemetry.cpu_budget_pct`"),
    cfg(
        "SBH_TELEMETRY_FS_CACHE_TTL_MS",
        "`telemetry.fs_cache_ttl_ms`",
    ),
    cfg(
        "SBH_TELEMETRY_EWMA_BASE_ALPHA",
        "`telemetry.ewma_base_alpha`",
    ),
    cfg("SBH_TELEMETRY_EWMA_MIN_ALPHA", "`telemetry.ewma_min_alpha`"),
    cfg("SBH_TELEMETRY_EWMA_MAX_ALPHA", "`telemetry.ewma_max_alpha`"),
    cfg(
        "SBH_TELEMETRY_EWMA_MIN_SAMPLES",
        "`telemetry.ewma_min_samples`",
    ),
    cfg(
        "SBH_TELEMETRY_DAEMON_RSS_WARNING_BYTES",
        "`telemetry.daemon_rss_warning_bytes`",
    ),
    cfg(
        "SBH_TELEMETRY_DAEMON_RSS_HARD_LIMIT_BYTES",
        "`telemetry.daemon_rss_hard_limit_bytes`",
    ),
    cfg("SBH_UPDATE_ENABLED", "`update.enabled`"),
    cfg(
        "SBH_UPDATE_BACKGROUND_REFRESH",
        "`update.background_refresh`",
    ),
    cfg("SBH_UPDATE_OPT_OUT", "`update.opt_out`"),
    cfg(
        "SBH_UPDATE_METADATA_CACHE_TTL_SECONDS",
        "`update.metadata_cache_ttl_seconds`",
    ),
    cfg(
        "SBH_UPDATE_METADATA_CACHE_FILE",
        "`update.metadata_cache_file`",
    ),
    cfg("SBH_UPDATE_NOTICES_ENABLED", "`update.notices_enabled`"),
    var(
        "SBH_RELEASE_API_BASE",
        EnvArea::Release,
        "Point the release API at another server (honored only under `SBH_TEST_MODE=1`)",
    ),
    var(
        "SBH_RELEASE_DOWNLOAD_BASE",
        EnvArea::Release,
        "Point release downloads at another server (honored only under `SBH_TEST_MODE=1`)",
    ),
    var(
        "SBH_TEST_MODE",
        EnvArea::Test,
        "`1` enables the test overlays (injected filesystem stats, release server overrides); the daemon refuses to start under a service manager in this mode",
    ),
    var(
        "SBH_TEST_FS_STATS",
        EnvArea::Test,
        "Injected per-mount filesystem statistics table (test mode)",
    ),
    var(
        "SBH_ARTIFACT_DIR",
        EnvArea::Test,
        "Where the dashboard e2e artifact bundles are written",
    ),
    var(
        "SBH_TUI_ARTIFACT_DIR",
        EnvArea::Test,
        "Where the TUI test artifacts are written",
    ),
    var(
        "SBH_TUI_ARTIFACT_FRAMES",
        EnvArea::Test,
        "Include rendered frame text in the TUI test artifacts",
    ),
];

/// `SBH_*` string literals in the source that are not environment
/// variables: a file-name prefix, a workflow secret prefix, and the build
/// metadata `build.rs` sets for `option_env!`.
pub const NOT_ENV_VARS: &[&str] = &[
    "SBH_BALLAST_FILE_",
    "SBH_RELEASE_SECRET_",
    "SBH_BUILD_GIT_SHA",
    "SBH_BUILD_TIMESTAMP",
    "SBH_BUILD_TARGET",
    "SBH_BUILD_PROFILE",
];

/// One CLI argument as clap describes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArgDoc {
    pub long: Option<String>,
    pub short: Option<char>,
    pub value_name: Option<String>,
    pub help: String,
    pub global: bool,
}

/// One (sub)command as clap describes it, `path` being the words after
/// `sbh` (for example `ballast release`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommandDoc {
    pub path: String,
    pub about: String,
    pub args: Vec<ArgDoc>,
}

/// Collect every command and subcommand from a clap definition, depth
/// first, hidden ones excluded.
#[must_use]
pub fn command_docs(root: &clap::Command) -> Vec<CommandDoc> {
    let mut out = Vec::new();
    for sub in root.get_subcommands() {
        collect_commands(sub, "", &mut out);
    }
    out
}

fn collect_commands(command: &clap::Command, prefix: &str, out: &mut Vec<CommandDoc>) {
    if command.is_hide_set() {
        return;
    }
    let path = if prefix.is_empty() {
        command.get_name().to_string()
    } else {
        format!("{prefix} {}", command.get_name())
    };
    let args = command
        .get_arguments()
        .filter(|arg| !arg.is_hide_set() && arg.get_id() != "help" && arg.get_id() != "version")
        .map(|arg| ArgDoc {
            long: arg.get_long().map(str::to_string),
            short: arg.get_short(),
            value_name: arg
                .get_value_names()
                .and_then(|names| names.first())
                .map(ToString::to_string),
            help: arg.get_help().map(ToString::to_string).unwrap_or_default(),
            global: arg.is_global_set(),
        })
        .collect();
    out.push(CommandDoc {
        path: path.clone(),
        about: command
            .get_about()
            .map(ToString::to_string)
            .unwrap_or_default(),
        args,
    });
    for sub in command.get_subcommands() {
        collect_commands(sub, &path, out);
    }
}

/// The dashboard tables, present only in a `tui` build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DashboardDocs {
    pub screens: Vec<ScreenEntry>,
    pub keymap: Vec<KeymapEntry>,
    pub palette: Vec<PaletteEntry>,
    pub playbook: Vec<PlaybookEntryDoc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScreenEntry {
    pub number: u8,
    pub name: String,
    pub hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeymapEntry {
    pub keys: String,
    pub group: String,
    pub context: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaletteEntry {
    pub id: String,
    pub title: String,
    pub shortcut: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlaybookEntryDoc {
    pub label: String,
    pub target: String,
    pub min_severity: String,
    pub description: String,
}

#[cfg(feature = "tui")]
#[must_use]
pub fn dashboard_docs() -> Option<DashboardDocs> {
    use crate::tui::incident::{INCIDENT_PLAYBOOK, IncidentSeverity};
    use crate::tui::input::{
        KEYMAP, KeyContext, KeyGroup, command_palette_actions, screen_catalog, screen_name,
    };

    let context_label = |context: KeyContext| -> String {
        match context {
            KeyContext::Global => "Global".to_string(),
            KeyContext::Screen(screen) => screen_name(screen).to_string(),
            KeyContext::Screens(screens) => screens
                .iter()
                .map(|s| screen_name(*s))
                .collect::<Vec<_>>()
                .join(", "),
            KeyContext::Overlay(overlay) => format!("{} overlay", overlay_name(overlay)),
            KeyContext::Replay => "Replay (`--replay`)".to_string(),
        }
    };
    let group_label = |group: KeyGroup| match group {
        KeyGroup::Navigation => "Navigation",
        KeyGroup::Overlays => "Overlays",
        KeyGroup::Incident => "Incident shortcuts",
        KeyGroup::Screen => "Screen-specific",
        KeyGroup::Replay => "Replay scrubber",
    };
    Some(DashboardDocs {
        screens: screen_catalog()
            .into_iter()
            .map(|s| ScreenEntry {
                number: s.number,
                name: s.name.to_string(),
                hint: s.hint.to_string(),
            })
            .collect(),
        keymap: KEYMAP
            .iter()
            .map(|b| KeymapEntry {
                keys: b.keys.to_string(),
                group: group_label(b.group).to_string(),
                context: context_label(b.context),
                description: b.description.to_string(),
            })
            .collect(),
        palette: command_palette_actions()
            .iter()
            .map(|a| PaletteEntry {
                id: a.id.to_string(),
                title: a.title.to_string(),
                shortcut: a.shortcut.to_string(),
            })
            .collect(),
        playbook: INCIDENT_PLAYBOOK
            .iter()
            .map(|e| PlaybookEntryDoc {
                label: e.label.to_string(),
                target: screen_name(e.target).to_string(),
                min_severity: match e.min_severity {
                    IncidentSeverity::Normal => "Normal",
                    IncidentSeverity::Elevated => "Elevated",
                    IncidentSeverity::High => "High",
                    IncidentSeverity::Critical => "Critical",
                }
                .to_string(),
                description: e
                    .description
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" "),
            })
            .collect(),
    })
}

#[cfg(feature = "tui")]
fn overlay_name(overlay: crate::tui::model::Overlay) -> &'static str {
    use crate::tui::model::Overlay;
    match overlay {
        Overlay::Help => "Help",
        Overlay::Voi => "VOI",
        Overlay::CommandPalette => "Command palette",
        Overlay::IncidentPlaybook => "Incident playbook",
        Overlay::Confirmation(_) => "Confirmation",
    }
}

#[cfg(not(feature = "tui"))]
#[must_use]
pub fn dashboard_docs() -> Option<DashboardDocs> {
    None
}

/// One named runtime constant or default, read from the code that uses it.
#[derive(Debug, Clone, Serialize)]
pub struct ConstantDoc {
    /// Subsystem the constant belongs to.
    pub area: &'static str,
    /// The identifier or config key.
    pub name: &'static str,
    /// The value, rendered for people (durations in s/ms, sizes in KiB/MiB/GiB).
    pub value: String,
    /// What the value controls.
    pub meaning: &'static str,
    /// The file that owns it.
    pub source: &'static str,
}

/// One row of the pressure-level table, derived from the default
/// thresholds and the controller's response table.
#[derive(Debug, Clone, Serialize)]
pub struct PressureLevelDoc {
    pub level: String,
    pub free_range: String,
    pub scan_interval: String,
    pub ballast_release: String,
    pub delete_batch: String,
}

/// One scoring factor with its default weight.
#[derive(Debug, Clone, Serialize)]
pub struct ScoringWeightDoc {
    pub factor: &'static str,
    pub weight: f64,
    pub measures: &'static str,
}

fn fmt_duration(duration: Duration) -> String {
    let millis = duration.as_millis();
    if millis.is_multiple_of(1000) {
        format!("{} s", duration.as_secs())
    } else {
        format!("{millis} ms")
    }
}

fn fmt_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    if bytes >= GIB && bytes.is_multiple_of(GIB) {
        format!("{} GiB", bytes / GIB)
    } else if bytes >= MIB && bytes.is_multiple_of(MIB) {
        format!("{} MiB", bytes / MIB)
    } else if bytes >= KIB && bytes.is_multiple_of(KIB) {
        format!("{} KiB", bytes / KIB)
    } else {
        format!("{bytes} B")
    }
}

// The callers pass numbers and temporaries; by value keeps the table readable.
#[allow(clippy::needless_pass_by_value)]
fn constant(
    area: &'static str,
    name: &'static str,
    value: impl ToString,
    meaning: &'static str,
    source: &'static str,
) -> ConstantDoc {
    ConstantDoc {
        area,
        name,
        value: value.to_string(),
        meaning,
        source,
    }
}

/// The runtime constants and defaults, read from the code that owns them.
///
/// Rows that depend on the host (the walker's parallelism) describe the
/// rule rather than this machine's number, so the rendered table is the
/// same everywhere.
#[must_use]
#[allow(clippy::too_many_lines)] // one row per constant; splitting hides nothing
pub fn constants() -> Vec<ConstantDoc> {
    use crate::ballast::manager as ballast;
    use crate::core::config::{
        BallastConfig, PressureConfig, ScannerConfig, ScoringConfig, TelemetryConfig,
    };
    use crate::daemon::self_monitor;
    use crate::monitor::{ewma, guardrails, pid};
    use crate::scanner::{deletion, planner, quarantine, walker};

    const CONFIG: &str = "src/core/config.rs";
    let pressure = PressureConfig::default();
    let controller = &pressure.controller;
    let prediction = &pressure.prediction;
    let telemetry = TelemetryConfig::default();
    let guard = guardrails::GuardrailConfig::default();
    let deletion = deletion::DeletionConfig::default();
    let scanner = ScannerConfig::default();
    let scoring = ScoringConfig::default();
    let budget = planner::RiskBudgetByLevel::default();
    let ballast_cfg = BallastConfig::default();

    let mut rows = vec![
        constant(
            "pressure",
            "green_min_free_pct",
            pressure.green_min_free_pct,
            "Green above this free %",
            CONFIG,
        ),
        constant(
            "pressure",
            "yellow_min_free_pct",
            pressure.yellow_min_free_pct,
            "Yellow at or above this free %",
            CONFIG,
        ),
        constant(
            "pressure",
            "orange_min_free_pct",
            pressure.orange_min_free_pct,
            "Orange at or above this free %",
            CONFIG,
        ),
        constant(
            "pressure",
            "red_min_free_pct",
            pressure.red_min_free_pct,
            "Red at or above this free %; Critical below it",
            CONFIG,
        ),
        constant(
            "pressure",
            "poll_interval_ms",
            pressure.poll_interval_ms,
            "Base poll interval the response table divides",
            CONFIG,
        ),
        constant(
            "pressure",
            "maintenance_interval_secs",
            pressure.maintenance_interval_secs,
            "Green maintenance pass cadence",
            CONFIG,
        ),
        constant(
            "pressure",
            "behavior_hysteresis_secs",
            pressure.behavior_hysteresis_secs,
            "Dwell before a behavior cell change takes effect",
            CONFIG,
        ),
        constant(
            "controller",
            "kp",
            controller.kp,
            "Proportional gain per point of free-% error",
            CONFIG,
        ),
        constant("controller", "ki", controller.ki, "Integral gain", CONFIG),
        constant("controller", "kd", controller.kd, "Derivative gain", CONFIG),
        constant(
            "controller",
            "kf",
            controller.kf,
            "Feedforward weight of the time-to-red forecast",
            CONFIG,
        ),
        constant(
            "controller",
            "integral_cap",
            controller.integral_cap,
            "Anti-windup bound on the integral term",
            CONFIG,
        ),
        constant(
            "controller",
            "hysteresis_pct",
            controller.hysteresis_pct,
            "Free-% band before a level change is accepted",
            CONFIG,
        ),
        constant(
            "controller",
            "reference_total_bytes",
            fmt_bytes(controller.reference_total_bytes),
            "Volume size at which Kp is unscaled",
            CONFIG,
        ),
        constant(
            "controller",
            "kp_scale_min",
            controller.kp_scale_min,
            "Lower clamp of the capacity gain schedule",
            CONFIG,
        ),
        constant(
            "controller",
            "kp_scale_max",
            controller.kp_scale_max,
            "Upper clamp of the capacity gain schedule",
            CONFIG,
        ),
        constant(
            "controller",
            "BATCH_SLOPE_KNEE",
            pid::BATCH_SLOPE_KNEE,
            "Urgency above which Red/Critical batches grow",
            "src/monitor/pid.rs",
        ),
        constant(
            "prediction",
            "enabled",
            prediction.enabled,
            "Forecast-driven early action",
            CONFIG,
        ),
        constant(
            "prediction",
            "action_horizon_minutes",
            prediction.action_horizon_minutes,
            "Forecast inside this raises urgency (feedforward)",
            CONFIG,
        ),
        constant(
            "prediction",
            "warning_horizon_minutes",
            prediction.warning_horizon_minutes,
            "Forecast inside this warns",
            CONFIG,
        ),
        constant(
            "prediction",
            "min_confidence",
            prediction.min_confidence,
            "Forecast confidence needed to act",
            CONFIG,
        ),
        constant(
            "prediction",
            "min_samples",
            prediction.min_samples,
            "Rate samples needed before forecasting",
            CONFIG,
        ),
        constant(
            "prediction",
            "imminent_danger_minutes",
            prediction.imminent_danger_minutes,
            "Time-to-red treated as imminent",
            CONFIG,
        ),
        constant(
            "prediction",
            "critical_danger_minutes",
            prediction.critical_danger_minutes,
            "Time-to-red treated as critical",
            CONFIG,
        ),
        constant(
            "prediction",
            "burst_min_confidence",
            prediction.burst_min_confidence,
            "Confidence needed to act on a burst forecast",
            CONFIG,
        ),
        constant(
            "prediction",
            "coverage_target",
            prediction.coverage_target,
            "Conformal coverage of the time-to-red bound",
            CONFIG,
        ),
        constant(
            "ewma",
            "fs_cache_ttl_ms",
            telemetry.fs_cache_ttl_ms,
            "Filesystem stats cache lifetime",
            CONFIG,
        ),
        constant(
            "ewma",
            "ewma_base_alpha",
            telemetry.ewma_base_alpha,
            "Base smoothing factor of the rate estimator",
            CONFIG,
        ),
        constant(
            "ewma",
            "ewma_min_alpha",
            telemetry.ewma_min_alpha,
            "Smallest adaptive alpha",
            CONFIG,
        ),
        constant(
            "ewma",
            "ewma_max_alpha",
            telemetry.ewma_max_alpha,
            "Largest adaptive alpha",
            CONFIG,
        ),
        constant(
            "ewma",
            "ewma_min_samples",
            telemetry.ewma_min_samples,
            "Samples before the rate estimate is trusted",
            CONFIG,
        ),
        constant(
            "ewma",
            "ewma_rate_history_size",
            telemetry.ewma_rate_history_size,
            "Rate samples kept for burst calibration",
            CONFIG,
        ),
        constant(
            "ewma",
            "DEFAULT_RATE_HISTORY_CAP",
            ewma::DEFAULT_RATE_HISTORY_CAP,
            "Estimator's own history cap",
            "src/monitor/ewma.rs",
        ),
        constant(
            "ewma",
            "BURST_CALIBRATION_MIN",
            ewma::BURST_CALIBRATION_MIN,
            "Samples before burstiness is calibrated",
            "src/monitor/ewma.rs",
        ),
        constant(
            "guardrails",
            "min_observations",
            guard.min_observations,
            "Observations before the guard can alarm",
            "src/monitor/guardrails.rs",
        ),
        constant(
            "guardrails",
            "window_size",
            guard.window_size,
            "Rolling calibration window",
            "src/monitor/guardrails.rs",
        ),
        constant(
            "guardrails",
            "max_rate_error",
            guard.max_rate_error,
            "Relative rate error tolerated per window",
            "src/monitor/guardrails.rs",
        ),
        constant(
            "guardrails",
            "coverage_target",
            guard.coverage_target,
            "Target conformal coverage",
            "src/monitor/guardrails.rs",
        ),
        constant(
            "guardrails",
            "coverage_tolerance",
            guard.coverage_tolerance,
            "Coverage shortfall tolerated",
            "src/monitor/guardrails.rs",
        ),
        constant(
            "guardrails",
            "e_process_threshold",
            guard.e_process_threshold,
            "E-process value that raises the alarm",
            "src/monitor/guardrails.rs",
        ),
        constant(
            "guardrails",
            "e_process_penalty",
            guard.e_process_penalty,
            "E-process multiplier for a bad window",
            "src/monitor/guardrails.rs",
        ),
        constant(
            "guardrails",
            "e_process_reward",
            guard.e_process_reward,
            "E-process multiplier for a good window",
            "src/monitor/guardrails.rs",
        ),
        constant(
            "guardrails",
            "recovery_clean_windows",
            guard.recovery_clean_windows,
            "Clean windows that clear an alarm",
            "src/monitor/guardrails.rs",
        ),
        constant(
            "guardrails",
            "E_PROCESS_LOG_MIN",
            guardrails::E_PROCESS_LOG_MIN,
            "Lower clamp of the e-process log value",
            "src/monitor/guardrails.rs",
        ),
        constant(
            "guardrails",
            "E_PROCESS_LOG_MAX",
            guardrails::E_PROCESS_LOG_MAX,
            "Upper clamp of the e-process log value",
            "src/monitor/guardrails.rs",
        ),
        constant(
            "guardrails",
            "NOISE_FLOOR_RATE_BYTES_PER_SEC",
            guardrails::NOISE_FLOOR_RATE_BYTES_PER_SEC,
            "Rates below this are noise, not drift",
            "src/monitor/guardrails.rs",
        ),
        constant(
            "guardrails",
            "MATERIAL_RATE_HORIZON_SECS",
            guardrails::MATERIAL_RATE_HORIZON_SECS,
            "Horizon over which a rate must matter",
            "src/monitor/guardrails.rs",
        ),
        constant(
            "guardrails",
            "guardrail_window_size",
            telemetry.guardrail_window_size,
            "Config-side window size fed to the guard",
            CONFIG,
        ),
        constant(
            "guardrails",
            "guardrail_min_observations",
            telemetry.guardrail_min_observations,
            "Config-side minimum observations",
            CONFIG,
        ),
        constant(
            "deletion",
            "circuit_breaker_threshold",
            deletion.circuit_breaker_threshold,
            "Consecutive failures that halt the batch",
            "src/scanner/deletion.rs",
        ),
        constant(
            "deletion",
            "circuit_breaker_cooldown",
            fmt_duration(deletion.circuit_breaker_cooldown),
            "Pause after the breaker trips",
            "src/scanner/deletion.rs",
        ),
        constant(
            "deletion",
            "max_batch_size",
            deletion.max_batch_size,
            "Executor batch cap before the planner applies",
            "src/scanner/deletion.rs",
        ),
        constant(
            "scanner",
            "max_depth",
            scanner.max_depth,
            "Walker depth limit",
            CONFIG,
        ),
        constant(
            "scanner",
            "parallelism",
            "half the CPU count, at least 1",
            "Walker threads (computed on the host)",
            CONFIG,
        ),
        constant(
            "scanner",
            "min_rescan_interval_secs",
            scanner.min_rescan_interval_secs,
            "Shortest gap between scans of one root",
            CONFIG,
        ),
        constant(
            "scanner",
            "max_scan_duty_cycle_pct",
            scanner.max_scan_duty_cycle_pct,
            "Share of wall time the scanner may use",
            CONFIG,
        ),
        constant(
            "scanner",
            "scan_time_budget_secs",
            scanner.scan_time_budget_secs,
            "Longest single scan",
            CONFIG,
        ),
        constant(
            "scanner",
            "quarantine_ttl_hours",
            scanner.quarantine_ttl_hours,
            "Quarantined entries expire after this",
            CONFIG,
        ),
        constant(
            "scanner",
            "quarantine_max_bytes_pct",
            scanner.quarantine_max_bytes_pct,
            "Quarantine size cap as % of the volume",
            CONFIG,
        ),
        constant(
            "scanner",
            "active_reference_cache_ttl_secs",
            scanner.active_reference_cache_ttl_secs,
            "Active-reference (open file) cache lifetime",
            CONFIG,
        ),
        constant(
            "scanner",
            "active_reference_min_size_bytes",
            fmt_bytes(scanner.active_reference_min_size_bytes),
            "Smallest entry checked for active references",
            CONFIG,
        ),
        constant(
            "walker",
            "RESULT_CHANNEL_CAP",
            walker::RESULT_CHANNEL_CAP,
            "Worker → collector channel bound",
            "src/scanner/walker.rs",
        ),
        constant(
            "walker",
            "WORK_RECV_TIMEOUT",
            fmt_duration(walker::WORK_RECV_TIMEOUT),
            "Idle wait before a worker re-checks shutdown",
            "src/scanner/walker.rs",
        ),
        constant(
            "walker",
            "SEND_TIMEOUT",
            fmt_duration(walker::SEND_TIMEOUT),
            "Wait on a full channel before dropping the entry",
            "src/scanner/walker.rs",
        ),
        constant(
            "walker",
            "MAX_ENTRIES_PER_DIR",
            walker::MAX_ENTRIES_PER_DIR,
            "Entries read per directory before it is cut off",
            "src/scanner/walker.rs",
        ),
        constant(
            "walker",
            "OPEN_FILES_SCAN_BUDGET",
            fmt_duration(walker::OPEN_FILES_SCAN_BUDGET),
            "Time budget of one /proc open-file sweep",
            "src/scanner/walker.rs",
        ),
        constant(
            "walker",
            "OPEN_FILES_MAX_PIDS",
            walker::OPEN_FILES_MAX_PIDS,
            "Processes inspected per open-file sweep",
            "src/scanner/walker.rs",
        ),
        constant(
            "walker",
            "OPAQUE_CANDIDATE_SIZE_FLOOR",
            fmt_bytes(walker::OPAQUE_CANDIDATE_SIZE_FLOOR),
            "Opaque trees smaller than this are not sized",
            "src/scanner/walker.rs",
        ),
        constant(
            "walker",
            "OPAQUE_SIZE_PROBE_BUDGET",
            walker::OPAQUE_SIZE_PROBE_BUDGET,
            "Entries an opaque-tree size probe may visit",
            "src/scanner/walker.rs",
        ),
        constant(
            "walker",
            "TREE_IDLE_PROBE_MAX_ENTRIES",
            walker::TREE_IDLE_PROBE_MAX_ENTRIES,
            "Entries an idle (mtime) probe may visit",
            "src/scanner/walker.rs",
        ),
        constant(
            "walker",
            "TREE_IDLE_PROBE_MAX_DEPTH",
            walker::TREE_IDLE_PROBE_MAX_DEPTH,
            "Depth of an idle (mtime) probe",
            "src/scanner/walker.rs",
        ),
        constant(
            "scoring",
            "min_score",
            scoring.min_score,
            "Lowest score that becomes a candidate",
            CONFIG,
        ),
        constant(
            "scoring",
            "false_positive_loss",
            scoring.false_positive_loss,
            "Loss of deleting something wanted",
            CONFIG,
        ),
        constant(
            "scoring",
            "false_negative_loss",
            scoring.false_negative_loss,
            "Loss of keeping an artifact",
            CONFIG,
        ),
        constant(
            "scoring",
            "calibration_floor",
            scoring.calibration_floor,
            "Calibration needed for adaptive actions",
            CONFIG,
        ),
        constant(
            "scoring",
            "posterior_floor_definite",
            scoring.posterior_floor_definite,
            "Posterior needed for a definite label",
            CONFIG,
        ),
        constant(
            "scoring",
            "regret_window_minutes",
            scoring.regret_window_minutes,
            "Window in which a recreated path counts as regret",
            CONFIG,
        ),
        constant(
            "scoring",
            "regret_alpha_definite",
            scoring.regret_alpha_definite,
            "Regret rate tolerated for definite deletions",
            CONFIG,
        ),
        constant(
            "scoring",
            "regret_alpha_likely",
            scoring.regret_alpha_likely,
            "Regret rate tolerated for likely deletions",
            CONFIG,
        ),
        constant(
            "scoring",
            "regret_suspend_minutes",
            scoring.regret_suspend_minutes,
            "Suspension after the regret rate is exceeded",
            CONFIG,
        ),
        constant(
            "scoring",
            "batch_risk_budget.green",
            budget.green,
            "Expected loss per batch at Green (× false_positive_loss)",
            "src/scanner/planner.rs",
        ),
        constant(
            "scoring",
            "batch_risk_budget.yellow",
            budget.yellow,
            "Expected loss per batch at Yellow",
            "src/scanner/planner.rs",
        ),
        constant(
            "scoring",
            "batch_risk_budget.orange",
            budget.orange,
            "Expected loss per batch at Orange",
            "src/scanner/planner.rs",
        ),
        constant(
            "scoring",
            "batch_risk_budget.red",
            budget.red,
            "Expected loss per batch at Red",
            "src/scanner/planner.rs",
        ),
        constant(
            "scoring",
            "batch_risk_budget.critical",
            budget
                .critical
                .map_or_else(|| "unbounded".to_string(), |v| v.to_string()),
            "Expected loss per batch at Critical",
            "src/scanner/planner.rs",
        ),
        constant(
            "ballast",
            "file_count",
            ballast_cfg.file_count,
            "Ballast files per volume",
            CONFIG,
        ),
        constant(
            "ballast",
            "file_size_bytes",
            fmt_bytes(ballast_cfg.file_size_bytes),
            "Size of one ballast file",
            CONFIG,
        ),
        constant(
            "ballast",
            "replenish_cooldown_minutes",
            ballast_cfg.replenish_cooldown_minutes,
            "Wait before released ballast is rebuilt",
            CONFIG,
        ),
        constant(
            "ballast",
            "auto_provision",
            ballast_cfg.auto_provision,
            "Provision pools at daemon start",
            CONFIG,
        ),
        constant(
            "ballast",
            "HEADER_SIZE",
            fmt_bytes(ballast::HEADER_SIZE as u64),
            "Ballast file header; also the smallest valid file",
            "src/ballast/manager.rs",
        ),
        constant(
            "ballast",
            "MAGIC",
            ballast::MAGIC,
            "Header magic string",
            "src/ballast/manager.rs",
        ),
        constant(
            "ballast",
            "CHUNK_SIZE",
            fmt_bytes(ballast::CHUNK_SIZE as u64),
            "Write chunk when filling a ballast file",
            "src/ballast/manager.rs",
        ),
        constant(
            "ballast",
            "FSYNC_EVERY_BYTES",
            fmt_bytes(ballast::FSYNC_EVERY_BYTES),
            "fsync cadence while filling",
            "src/ballast/manager.rs",
        ),
        constant(
            "ballast",
            "DEFAULT_PROVISION_FLOOR_PCT",
            ballast::DEFAULT_PROVISION_FLOOR_PCT,
            "Manager's floor before the config applies",
            "src/ballast/manager.rs",
        ),
        constant(
            "ballast",
            "ballast_provision_floor_pct()",
            Config::default().ballast_provision_floor_pct(),
            "Effective floor with default thresholds: max(orange, red + 2)",
            CONFIG,
        ),
        constant(
            "quarantine",
            "DEFAULT_TTL_HOURS",
            quarantine::DEFAULT_TTL_HOURS,
            "Quarantine TTL used without config",
            "src/scanner/quarantine.rs",
        ),
        constant(
            "quarantine",
            "DEFAULT_MAX_BYTES_PCT",
            quarantine::DEFAULT_MAX_BYTES_PCT,
            "Quarantine size cap used without config",
            "src/scanner/quarantine.rs",
        ),
        constant(
            "daemon",
            "DAEMON_STATE_WRITE_INTERVAL_SECS",
            self_monitor::DAEMON_STATE_WRITE_INTERVAL_SECS,
            "state.json write cadence",
            "src/daemon/self_monitor.rs",
        ),
        constant(
            "daemon",
            "DAEMON_STATE_STALE_THRESHOLD_SECS",
            self_monitor::DAEMON_STATE_STALE_THRESHOLD_SECS,
            "state.json older than this is stale",
            "src/daemon/self_monitor.rs",
        ),
        constant(
            "daemon",
            "DEFAULT_DAEMON_RSS_WARNING_BYTES",
            fmt_bytes(self_monitor::DEFAULT_DAEMON_RSS_WARNING_BYTES),
            "RSS that logs a warning",
            "src/daemon/self_monitor.rs",
        ),
        constant(
            "daemon",
            "DEFAULT_DAEMON_RSS_HARD_LIMIT_BYTES",
            fmt_bytes(self_monitor::DEFAULT_DAEMON_RSS_HARD_LIMIT_BYTES),
            "RSS at which the daemon restarts itself",
            "src/daemon/self_monitor.rs",
        ),
        constant(
            "daemon",
            "daemon_rss_warning_bytes",
            fmt_bytes(telemetry.daemon_rss_warning_bytes),
            "Config-side RSS warning",
            CONFIG,
        ),
        constant(
            "daemon",
            "daemon_rss_hard_limit_bytes",
            fmt_bytes(telemetry.daemon_rss_hard_limit_bytes),
            "Config-side RSS hard limit",
            CONFIG,
        ),
        constant(
            "logger",
            "CHANNEL_CAPACITY",
            crate::logger::dual::CHANNEL_CAPACITY,
            "Logger channel bound (try_send, drops when full)",
            "src/logger/dual.rs",
        ),
    ];
    rows.extend(daemon_constants());
    rows
}

#[cfg(feature = "daemon")]
fn daemon_constants() -> Vec<ConstantDoc> {
    use crate::daemon::loop_main as daemon;
    const SOURCE: &str = "src/daemon/loop_main.rs";
    vec![
        constant(
            "daemon",
            "SCANNER_CHANNEL_CAP",
            daemon::SCANNER_CHANNEL_CAP,
            "Monitor → scanner requests in flight",
            SOURCE,
        ),
        constant(
            "daemon",
            "EXECUTOR_CHANNEL_CAP",
            daemon::EXECUTOR_CHANNEL_CAP,
            "Scanner → executor batches in flight",
            SOURCE,
        ),
        constant(
            "daemon",
            "MEMORY_PRESSURE_CHANNEL_CAP",
            daemon::MEMORY_PRESSURE_CHANNEL_CAP,
            "Memory-pressure samples buffered",
            SOURCE,
        ),
        constant(
            "daemon",
            "CONTROL_CHANNEL_CAP",
            daemon::CONTROL_CHANNEL_CAP,
            "Control-socket requests buffered",
            SOURCE,
        ),
        constant(
            "daemon",
            "REPORT_CHANNEL_CAP",
            daemon::REPORT_CHANNEL_CAP,
            "Executor reports and index feedback buffered",
            SOURCE,
        ),
        constant(
            "daemon",
            "MAX_RESPAWNS",
            daemon::MAX_RESPAWNS,
            "Thread respawns allowed per window",
            SOURCE,
        ),
        constant(
            "daemon",
            "RESPAWN_WINDOW",
            fmt_duration(daemon::RESPAWN_WINDOW),
            "Window for the respawn limit",
            SOURCE,
        ),
        constant(
            "daemon",
            "THREAD_HEALTH_CHECK_INTERVAL",
            fmt_duration(daemon::THREAD_HEALTH_CHECK_INTERVAL),
            "Thread liveness check cadence",
            SOURCE,
        ),
        constant(
            "daemon",
            "THREAD_STALL_THRESHOLD",
            fmt_duration(daemon::THREAD_STALL_THRESHOLD),
            "Heartbeat age that counts as a stall",
            SOURCE,
        ),
        constant(
            "daemon",
            "CATALOG_PROBE_MAX_ENTRIES",
            daemon::CATALOG_PROBE_MAX_ENTRIES,
            "Entries a catalog freshness probe may visit",
            SOURCE,
        ),
        constant(
            "daemon",
            "CATALOG_PROBE_MAX_DEPTH",
            daemon::CATALOG_PROBE_MAX_DEPTH,
            "Depth of a catalog freshness probe",
            SOURCE,
        ),
    ]
}

#[cfg(not(feature = "daemon"))]
fn daemon_constants() -> Vec<ConstantDoc> {
    Vec::new()
}

fn scan_interval_text(rule: IntervalRule) -> String {
    match rule {
        IntervalRule::Divide { by: 1, .. } => "base interval".to_string(),
        IntervalRule::Divide { by, floor_ms } => format!("base/{by} (at least {floor_ms} ms)"),
        IntervalRule::Fixed { ms } => format!("{ms} ms"),
    }
}

fn ballast_release_text(row: &LevelResponse) -> String {
    if row.release_below_knee == row.release_above_knee {
        format!("{} files", row.release_below_knee)
    } else {
        format!(
            "{}-{} files (urgency > {})",
            row.release_below_knee, row.release_above_knee, row.release_knee
        )
    }
}

fn delete_batch_text(row: &LevelResponse) -> String {
    let mut text = row.batch_base.to_string();
    for (knee, batch) in row.batch_steps {
        let _ = write!(text, ", {batch} above urgency {knee}");
    }
    if row.batch_urgency_slope > 0.0 {
        let _ = write!(
            text,
            " + {} x max(urgency - {}, 0)",
            row.batch_urgency_slope, BATCH_SLOPE_KNEE
        );
    }
    text
}

/// The pressure-level table from the default thresholds and the response table.
#[must_use]
pub fn pressure_levels() -> Vec<PressureLevelDoc> {
    use crate::core::config::PressureConfig;
    let p = PressureConfig::default();
    let free_range = |level: PressureLevel| match level {
        PressureLevel::Green => format!("> {}%", p.green_min_free_pct),
        PressureLevel::Yellow => format!("{}-{}%", p.yellow_min_free_pct, p.green_min_free_pct),
        PressureLevel::Orange => format!("{}-{}%", p.orange_min_free_pct, p.yellow_min_free_pct),
        PressureLevel::Red => format!("{}-{}%", p.red_min_free_pct, p.orange_min_free_pct),
        PressureLevel::Critical => format!("< {}%", p.red_min_free_pct),
    };
    RESPONSE_TABLE
        .iter()
        .map(|row| PressureLevelDoc {
            level: format!("{:?}", row.level),
            free_range: free_range(row.level),
            scan_interval: scan_interval_text(row.interval),
            ballast_release: ballast_release_text(row),
            delete_batch: delete_batch_text(row),
        })
        .collect()
}

/// The five scoring factors with their default weights.
#[must_use]
pub fn scoring_weights() -> Vec<ScoringWeightDoc> {
    let s = crate::core::config::ScoringConfig::default();
    vec![
        ScoringWeightDoc {
            factor: "location",
            weight: s.location_weight,
            measures: "How safe the directory is (temp > build > source)",
        },
        ScoringWeightDoc {
            factor: "name",
            weight: s.name_weight,
            measures: "Pattern match against known artifact names (`target/`, `node_modules`, `.o`)",
        },
        ScoringWeightDoc {
            factor: "age",
            weight: s.age_weight,
            measures: "Time since last access or modification",
        },
        ScoringWeightDoc {
            factor: "size",
            weight: s.size_weight,
            measures: "Bytes reclaimable (larger scores higher)",
        },
        ScoringWeightDoc {
            factor: "structure",
            weight: s.structure_weight,
            measures: "Directory structure signals (depth, siblings, markers)",
        },
    ]
}

/// The whole generated document.
#[derive(Debug, Clone, Serialize)]
pub struct DocsDocument {
    pub schema_version: u32,
    pub sbh_version: &'static str,
    pub env_vars: Vec<EnvVarDoc>,
    pub commands: Vec<CommandDoc>,
    pub dashboard: Option<DashboardDocs>,
    pub error_codes: Vec<ErrorCodeDoc>,
    pub constants: Vec<ConstantDoc>,
    pub pressure_levels: Vec<PressureLevelDoc>,
    pub scoring_weights: Vec<ScoringWeightDoc>,
    pub defaults_toml: String,
}

impl DocsDocument {
    /// Build from the CLI definition; the defaults come from `Config::default()`.
    #[must_use]
    pub fn build(cli: &clap::Command) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            sbh_version: env!("CARGO_PKG_VERSION"),
            env_vars: ENV_VARS.to_vec(),
            commands: command_docs(cli),
            dashboard: dashboard_docs(),
            error_codes: ERROR_CODES.to_vec(),
            constants: constants(),
            pressure_levels: pressure_levels(),
            scoring_weights: scoring_weights(),
            defaults_toml: toml::to_string_pretty(&Config::default()).unwrap_or_default(),
        }
    }

    /// The document as JSON.
    #[must_use]
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({}))
    }

    /// The section names this build can render.
    #[must_use]
    pub fn section_names(&self) -> Vec<&'static str> {
        let mut names = vec![
            "env-vars",
            "commands",
            "error-codes",
            "constants",
            "pressure-levels",
            "scoring-weights",
        ];
        if self.dashboard.is_some() {
            names.extend([
                "dashboard-screens",
                "dashboard-keymap",
                "dashboard-palette",
                "dashboard-playbook",
            ]);
        }
        names
    }

    /// Markdown for one section, or `None` for a name this build cannot
    /// render (unknown, or a dashboard section without the `tui` feature).
    #[must_use]
    pub fn render_section(&self, name: &str) -> Option<String> {
        match name {
            "env-vars" => Some(self.render_env_vars()),
            "commands" => Some(self.render_commands()),
            "error-codes" => Some(self.render_error_codes()),
            "constants" => Some(self.render_constants()),
            "pressure-levels" => Some(self.render_pressure_levels()),
            "scoring-weights" => Some(self.render_scoring_weights()),
            "dashboard-screens" => self.dashboard.as_ref().map(render_screens),
            "dashboard-keymap" => self.dashboard.as_ref().map(render_keymap),
            "dashboard-palette" => self.dashboard.as_ref().map(render_palette),
            "dashboard-playbook" => self.dashboard.as_ref().map(render_playbook),
            _ => None,
        }
    }

    fn render_env_vars(&self) -> String {
        let mut out = String::from("| Variable | Area | Controls |\n| --- | --- | --- |\n");
        for var in &self.env_vars {
            let _ = writeln!(
                out,
                "| `{}` | {} | {} |",
                var.name,
                var.area.label(),
                var.controls
            );
        }
        out
    }

    fn render_commands(&self) -> String {
        let mut out = String::from("| Command | Purpose |\n| --- | --- |\n");
        for command in &self.commands {
            let _ = writeln!(out, "| `sbh {}` | {} |", command.path, command.about);
        }
        out
    }

    fn render_constants(&self) -> String {
        let mut out = String::from(
            "| Area | Constant | Value | Meaning | Where |\n| --- | --- | --- | --- | --- |\n",
        );
        for row in &self.constants {
            let _ = writeln!(
                out,
                "| {} | `{}` | `{}` | {} | `{}` |",
                row.area, row.name, row.value, row.meaning, row.source
            );
        }
        out
    }

    fn render_pressure_levels(&self) -> String {
        let mut out = String::from(
            "| Level | Default free % | Scan interval | Ballast release | Max delete batch |\n| --- | --- | --- | --- | --- |\n",
        );
        for row in &self.pressure_levels {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} |",
                row.level, row.free_range, row.scan_interval, row.ballast_release, row.delete_batch
            );
        }
        out
    }

    fn render_scoring_weights(&self) -> String {
        let mut out =
            String::from("| Factor | Default weight | What it measures |\n| --- | --- | --- |\n");
        for row in &self.scoring_weights {
            let _ = writeln!(
                out,
                "| `{}` | {} | {} |",
                row.factor, row.weight, row.measures
            );
        }
        out
    }

    fn render_error_codes(&self) -> String {
        let mut out = String::from(
            "| Code | Variant | Family | Retryable | Typical cause |\n| --- | --- | --- | --- | --- |\n",
        );
        for row in &self.error_codes {
            let _ = writeln!(
                out,
                "| `{}` | `{}` | {} | {} | {} |",
                row.code,
                row.variant,
                row.category,
                if row.retryable { "yes" } else { "no" },
                row.cause
            );
        }
        out
    }
}

fn render_screens(docs: &DashboardDocs) -> String {
    let mut out = String::from("| Key | Screen | Purpose |\n| --- | --- | --- |\n");
    for screen in &docs.screens {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} |",
            screen.number, screen.name, screen.hint
        );
    }
    out
}

fn render_keymap(docs: &DashboardDocs) -> String {
    let mut out = String::new();
    let mut groups: Vec<&str> = Vec::new();
    for entry in &docs.keymap {
        if !groups.contains(&entry.group.as_str()) {
            groups.push(&entry.group);
        }
    }
    for (index, group) in groups.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        let _ = writeln!(out, "**{group}:**\n");
        out.push_str("| Key | Where | Action |\n| --- | --- | --- |\n");
        for entry in docs.keymap.iter().filter(|e| e.group == *group) {
            let _ = writeln!(
                out,
                "| {} | {} | {} |",
                entry.keys, entry.context, entry.description
            );
        }
    }
    out
}

fn render_palette(docs: &DashboardDocs) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "All {} actions, by family (`id` — title, shortcut where one exists):\n",
        docs.palette.len()
    );
    let mut families: BTreeMap<String, Vec<&PaletteEntry>> = BTreeMap::new();
    for entry in &docs.palette {
        let family = entry
            .id
            .rsplit_once('.')
            .map_or(entry.id.as_str(), |(head, _)| head)
            .to_string();
        families.entry(family).or_default().push(entry);
    }
    for (family, entries) in families {
        let _ = writeln!(out, "- `{family}.*` ({}):", entries.len());
        for entry in entries {
            if entry.shortcut.is_empty() {
                let _ = writeln!(out, "  - `{}` — {}", entry.id, entry.title);
            } else {
                let _ = writeln!(
                    out,
                    "  - `{}` — {} (`{}`)",
                    entry.id, entry.title, entry.shortcut
                );
            }
        }
    }
    out
}

fn render_playbook(docs: &DashboardDocs) -> String {
    let mut out = String::new();
    for (index, entry) in docs.playbook.iter().enumerate() {
        let severity = if entry.min_severity == "High" || entry.min_severity == "Critical" {
            format!(", {}", entry.min_severity)
        } else {
            String::new()
        };
        let _ = writeln!(
            out,
            "{}. {} ({} screen{severity})",
            index + 1,
            entry.label,
            entry.target
        );
    }
    out
}

/// Rewrite every marked region of `text` from `document`. Returns the new
/// text and the names of the regions whose content changed.
pub fn render_regions(text: &str, document: &DocsDocument) -> Result<(String, Vec<String>)> {
    let mut out = String::with_capacity(text.len());
    let mut changed = Vec::new();
    let mut rest = text;
    while let Some(begin_at) = rest.find(BEGIN_MARKER) {
        let (before, from_marker) = rest.split_at(begin_at);
        out.push_str(before);
        let marker_end = from_marker
            .find("-->")
            .ok_or_else(|| bad("unterminated begin marker"))?;
        let name = from_marker[BEGIN_MARKER.len()..marker_end].trim();
        let after_marker_line = from_marker[marker_end + 3..]
            .strip_prefix('\n')
            .ok_or_else(|| bad(format!("the begin marker for {name:?} must end its line")))?;
        let end_at = after_marker_line
            .find(END_MARKER)
            .ok_or_else(|| bad(format!("region {name:?} has no end marker")))?;
        let old_body = &after_marker_line[..end_at];
        let rendered = document.render_section(name).ok_or_else(|| {
            bad(format!(
                "unknown docs section {name:?} (this build renders: {})",
                document.section_names().join(", ")
            ))
        })?;
        if old_body != rendered {
            changed.push(name.to_string());
        }
        let _ = write!(
            out,
            "{}-->\n{rendered}{END_MARKER}",
            &from_marker[..marker_end]
        );
        rest = &after_marker_line[end_at + END_MARKER.len()..];
    }
    out.push_str(rest);
    Ok((out, changed))
}

/// Rewrite `path` in place; returns the regions that changed.
pub fn render_file(path: &Path, document: &DocsDocument) -> Result<Vec<String>> {
    let text = fs::read_to_string(path).map_err(|source| SbhError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let (rendered, changed) = render_regions(&text, document)?;
    if !changed.is_empty() {
        fs::write(path, rendered).map_err(|source| SbhError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(changed)
}

/// The regions of `path` that differ from what the code generates.
pub fn check_file(path: &Path, document: &DocsDocument) -> Result<Vec<String>> {
    let text = fs::read_to_string(path).map_err(|source| SbhError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    render_regions(&text, document).map(|(_, changed)| changed)
}

/// README "Command Reference" rows naming a command clap does not have.
///
/// A row's command is the longest prefix of its `sbh …` words that is a
/// known command path; flags, placeholders and `a|b` alternatives are not
/// part of the path (bd-rc-master-ajg1.12.3).
#[must_use]
pub fn undocumented_commands(
    text: &str,
    section: &str,
    known: &std::collections::BTreeSet<String>,
) -> Vec<String> {
    let Some(body) = section_body(text, section) else {
        return vec![format!("no {section:?} section")];
    };
    let mut missing = Vec::new();
    for line in body.lines() {
        let Some(rest) = line.strip_prefix("| `sbh ") else {
            continue;
        };
        let Some(cell_end) = rest.find('`') else {
            continue;
        };
        if command_path_of(&rest[..cell_end], known).is_empty() {
            missing.push(line.trim().to_string());
        }
    }
    missing
}

/// The text of the markdown section that starts with `heading` (a `## …`
/// line) up to the next `## ` heading.
fn section_body<'a>(text: &'a str, heading: &str) -> Option<&'a str> {
    let start = text.find(heading)?;
    let end = text[start..]
        .find("\n## ")
        .map_or(text.len(), |end| start + end);
    Some(&text[start..end])
}

/// The longest known command path at the start of a documented `sbh …`
/// cell (`"config show|set"` resolves to `config show`; flags, placeholders
/// and `[…]` end the path).
fn command_path_of(cell: &str, known: &std::collections::BTreeSet<String>) -> String {
    let mut path = String::new();
    for word in cell.split_whitespace() {
        if word.starts_with('<') || word.starts_with('[') {
            break;
        }
        // `sbh service --systemd reinstall-unit`: a flag may sit between
        // the path words.
        if word.starts_with('-') {
            continue;
        }
        // `config show|set|…` (or `show\|set` inside a table) documents
        // alternatives in one cell.
        let word = word
            .split('|')
            .next()
            .unwrap_or(word)
            .trim_end_matches('\\');
        let candidate = if path.is_empty() {
            word.to_string()
        } else {
            format!("{path} {word}")
        };
        if known.contains(&candidate) {
            path = candidate;
        } else if path.is_empty() {
            break;
        }
        // A flag value (`--mount M`) may also sit between path words: an
        // unknown word after a known prefix is skipped.
    }
    path
}

/// The `--long` flags mentioned in a table row.
fn long_flags_in(row: &str) -> Vec<&str> {
    let mut flags = Vec::new();
    let mut rest = row;
    while let Some(at) = rest.find("--") {
        let after = &rest[at + 2..];
        let len = after
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'-')
            .count();
        if len > 0 && after.as_bytes()[0].is_ascii_alphabetic() {
            flags.push(&after[..len]);
        }
        rest = &after[len..];
    }
    flags
}

/// Rows of the command table under `section` whose `--flag` mentions name
/// a flag the resolved subcommand (or the global flags) does not have.
///
/// Each finding is `"<row>: --flag"`, so the fix is one edit away.
#[must_use]
pub fn undocumented_flags(text: &str, section: &str, root: &clap::Command) -> Vec<String> {
    let docs = command_docs(root);
    let known: std::collections::BTreeSet<String> = docs.iter().map(|c| c.path.clone()).collect();
    let flags_of: BTreeMap<&str, Vec<&str>> = docs
        .iter()
        .map(|c| {
            (
                c.path.as_str(),
                c.args.iter().filter_map(|a| a.long.as_deref()).collect(),
            )
        })
        .collect();
    let globals: Vec<&str> = root
        .get_arguments()
        .filter_map(clap::Arg::get_long)
        .chain(["help", "version"])
        .collect();
    let Some(body) = section_body(text, section) else {
        return vec![format!("no {section:?} section")];
    };
    let mut findings = Vec::new();
    for line in body.lines() {
        let Some(rest) = line.strip_prefix("| `sbh ") else {
            continue;
        };
        let Some(cell_end) = rest.find('`') else {
            continue;
        };
        let path = command_path_of(&rest[..cell_end], &known);
        if path.is_empty() {
            continue; // reported by undocumented_commands
        }
        // A flag may belong to the row's command or to any ancestor
        // (`sbh ballast release` rows may mention `sbh ballast` flags).
        let mut allowed: Vec<&str> = globals.clone();
        let mut prefix = String::new();
        for word in path.split(' ') {
            prefix = if prefix.is_empty() {
                word.to_string()
            } else {
                format!("{prefix} {word}")
            };
            if let Some(flags) = flags_of.get(prefix.as_str()) {
                allowed.extend(flags);
            }
        }
        for flag in long_flags_in(line) {
            if !allowed.contains(&flag) {
                findings.push(format!("{}: --{flag}", line.trim()));
            }
        }
    }
    findings
}

/// Backticked repository paths (`src/…`, `docs/…`, `scripts/…`, `tests/…`,
/// `.github/…`) in `text` that do not exist under `root`.
#[must_use]
pub fn missing_file_references(text: &str, root: &Path) -> Vec<String> {
    const PREFIXES: [&str; 5] = ["src/", "docs/", "scripts/", "tests/", ".github/"];
    let mut missing = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (index, line) in text.lines().enumerate() {
        let mut rest = line;
        while let Some(open) = rest.find('`') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('`') else {
                break;
            };
            let token = after[..close].trim_end_matches(['/', ':']);
            rest = &after[close + 1..];
            let is_path = PREFIXES.iter().any(|p| token.starts_with(p))
                && !token.chars().any(|c| {
                    c.is_whitespace() || matches!(c, '*' | '<' | '>' | '{' | '}' | '…' | '|')
                });
            if is_path
                && !token.ends_with('/')
                && seen.insert(token.to_string())
                && !root.join(token).exists()
            {
                missing.push(format!("line {}: `{token}`", index + 1));
            }
        }
    }
    missing
}

fn bad(details: impl Into<String>) -> SbhError {
    SbhError::ConfigParse {
        context: "docs",
        details: details.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// The constants table reads each value where the code uses it: the
    /// breaker threshold and the walker channel bound come back as the
    /// defaults, no (area, name) repeats, and nothing in it depends on the
    /// host the docs were rendered on.
    #[test]
    fn constants_read_the_values_at_their_point_of_use() {
        let rows = constants();
        let find = |name: &str| {
            rows.iter()
                .find(|row| row.name == name)
                .unwrap_or_else(|| panic!("no constants row named {name}"))
        };
        assert_eq!(
            find("circuit_breaker_threshold").value,
            crate::scanner::deletion::DeletionConfig::default()
                .circuit_breaker_threshold
                .to_string()
        );
        assert_eq!(
            find("RESULT_CHANNEL_CAP").value,
            crate::scanner::walker::RESULT_CHANNEL_CAP.to_string()
        );
        assert_eq!(find("circuit_breaker_cooldown").value, "30 s");
        assert_eq!(find("E_PROCESS_LOG_MAX").value, "3.5");
        assert_eq!(
            find("parallelism").value,
            "half the CPU count, at least 1",
            "host-dependent values describe the rule, not this machine"
        );
        let mut seen = BTreeSet::new();
        for row in &rows {
            assert!(!row.value.is_empty(), "{} has an empty value", row.name);
            assert!(
                seen.insert((row.area, row.name)),
                "duplicate constants row {}/{}",
                row.area,
                row.name
            );
        }
        if cfg!(feature = "daemon") {
            assert_eq!(
                find("SCANNER_CHANNEL_CAP").value,
                crate::daemon::loop_main::SCANNER_CHANNEL_CAP.to_string()
            );
        }
        assert_eq!(fmt_bytes(1 << 30), "1 GiB");
        assert_eq!(fmt_bytes(256 * 1024 * 1024), "256 MiB");
        assert_eq!(fmt_bytes(4096), "4 KiB");
        assert_eq!(fmt_bytes(1500), "1500 B");
        assert_eq!(fmt_duration(Duration::from_millis(250)), "250 ms");
        assert_eq!(fmt_duration(Duration::from_secs(300)), "300 s");
    }

    /// The pressure table is derived from the default thresholds and the
    /// response table, one row per level in order.
    #[test]
    fn pressure_levels_follow_the_response_table() {
        let rows = pressure_levels();
        let p = crate::core::config::PressureConfig::default();
        let levels: Vec<&str> = rows.iter().map(|row| row.level.as_str()).collect();
        assert_eq!(levels, vec!["Green", "Yellow", "Orange", "Red", "Critical"]);
        assert_eq!(rows[0].free_range, format!("> {}%", p.green_min_free_pct));
        assert_eq!(rows[4].free_range, format!("< {}%", p.red_min_free_pct));
        assert_eq!(rows[0].scan_interval, "base interval");
        let yellow = &RESPONSE_TABLE[1];
        assert_eq!(
            rows[1].ballast_release,
            format!(
                "{}-{} files (urgency > {})",
                yellow.release_below_knee, yellow.release_above_knee, yellow.release_knee
            )
        );
        assert_eq!(rows[4].ballast_release, "10 files");
        assert_eq!(
            rows[0].delete_batch,
            "2, 5 above urgency 0.5, 10 above urgency 0.8"
        );
        assert_eq!(rows[3].delete_batch, "20 + 60 x max(urgency - 0.5, 0)");
        assert_eq!(rows[4].scan_interval, "100 ms");

        let weights = scoring_weights();
        let sum: f64 = weights.iter().map(|w| w.weight).sum();
        assert!(
            (sum - 1.0).abs() < 1e-9,
            "default weights sum to 1, got {sum}"
        );
    }

    /// Every `"SBH_…"` literal under `src/` (a name the code reads) minus the
    /// known non-variables.
    fn names_in_source() -> BTreeSet<String> {
        fn walk(dir: &Path, out: &mut BTreeSet<String>) {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs")
                    && !path.ends_with("cli/docs.rs")
                {
                    let text = fs::read_to_string(&path).unwrap();
                    let mut rest = text.as_str();
                    while let Some(at) = rest.find("\"SBH_") {
                        let name_start = at + 1;
                        let tail = &rest[name_start..];
                        let len = tail
                            .find(|c: char| {
                                !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                            })
                            .unwrap_or(tail.len());
                        if tail.as_bytes().get(len) == Some(&b'"') {
                            out.insert(tail[..len].to_string());
                        }
                        rest = &rest[name_start + len..];
                    }
                }
            }
        }
        let mut out = BTreeSet::new();
        walk(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
        for skip in NOT_ENV_VARS {
            out.remove(*skip);
        }
        out
    }

    #[test]
    fn registry_lists_exactly_the_variables_the_code_reads() {
        let in_source = names_in_source();
        let registered: BTreeSet<String> = ENV_VARS.iter().map(|v| v.name.to_string()).collect();
        let unregistered: Vec<_> = in_source.difference(&registered).collect();
        let stale: Vec<_> = registered.difference(&in_source).collect();
        assert!(
            unregistered.is_empty(),
            "read by the code but not in ENV_VARS: {unregistered:?}"
        );
        assert!(
            stale.is_empty(),
            "in ENV_VARS but no longer read anywhere under src/: {stale:?}"
        );
        assert_eq!(
            registered.len(),
            ENV_VARS.len(),
            "no duplicate registry entries"
        );
    }

    #[test]
    fn config_overrides_name_a_config_key() {
        for var in ENV_VARS {
            if var.area == EnvArea::ConfigOverride {
                assert!(
                    var.controls.starts_with('`') && var.controls.contains('.'),
                    "{} should name its config key: {}",
                    var.name,
                    var.controls
                );
            }
        }
    }

    fn test_document() -> DocsDocument {
        let cli = clap::Command::new("sbh")
            .subcommand(
                clap::Command::new("status").about("Show status").arg(
                    clap::Arg::new("json")
                        .long("json")
                        .help("JSON output")
                        .global(true),
                ),
            )
            .subcommand(
                clap::Command::new("ballast")
                    .about("Ballast pools")
                    .subcommand(clap::Command::new("release").about("Release files")),
            )
            .subcommand(clap::Command::new("secret").hide(true));
        DocsDocument::build(&cli)
    }

    #[test]
    fn commands_are_collected_depth_first_without_hidden_ones() {
        let document = test_document();
        let paths: Vec<&str> = document.commands.iter().map(|c| c.path.as_str()).collect();
        assert_eq!(paths, vec!["status", "ballast", "ballast release"]);
        assert_eq!(document.commands[0].args.len(), 1);
        assert_eq!(document.commands[0].args[0].long.as_deref(), Some("json"));
        assert!(document.commands[0].args[0].global);
        let markdown = document.render_section("commands").unwrap();
        assert!(markdown.contains("| `sbh ballast release` | Release files |"));
        assert!(document.render_section("no-such-section").is_none());
        assert!(
            !document.defaults_toml.is_empty(),
            "defaults render as TOML"
        );
    }

    #[test]
    fn regions_render_idempotently_and_check_reports_drift() {
        let document = test_document();
        let text = "intro\n<!-- sbh-docs:begin commands -->\nstale\n<!-- sbh-docs:end -->\noutro\n\
                    <!-- sbh-docs:begin env-vars -->\n<!-- sbh-docs:end -->\n";
        let (rendered, changed) = render_regions(text, &document).unwrap();
        assert_eq!(changed, vec!["commands", "env-vars"]);
        assert!(rendered.starts_with("intro\n<!-- sbh-docs:begin commands -->\n| Command |"));
        assert!(rendered.contains("<!-- sbh-docs:end -->\noutro\n"));
        assert!(rendered.contains("| `SBH_CONFIG` | paths |"));
        let (again, changed_again) = render_regions(&rendered, &document).unwrap();
        assert_eq!(again, rendered, "rendering is idempotent");
        assert!(changed_again.is_empty());

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("README.md");
        fs::write(&path, text).unwrap();
        assert_eq!(
            check_file(&path, &document).unwrap(),
            vec!["commands", "env-vars"]
        );
        assert_eq!(
            render_file(&path, &document).unwrap(),
            vec!["commands", "env-vars"]
        );
        assert!(check_file(&path, &document).unwrap().is_empty());
        assert!(
            render_file(&path, &document).unwrap().is_empty(),
            "nothing rewritten when clean"
        );

        let unknown = "<!-- sbh-docs:begin nope -->\n<!-- sbh-docs:end -->\n";
        let err = render_regions(unknown, &document).unwrap_err().to_string();
        assert!(err.contains("unknown docs section"), "{err}");
        let unterminated = "<!-- sbh-docs:begin commands -->\nbody\n";
        let err = render_regions(unterminated, &document)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no end marker"), "{err}");
    }

    /// The documented-commands check flags a command clap lacks and accepts
    /// flags, placeholders and `a|b` alternatives after a real command.
    #[test]
    fn undocumented_commands_flags_only_unknown_commands() {
        let known: BTreeSet<String> = [
            "status",
            "ballast",
            "ballast release",
            "config",
            "lease",
            "lease run",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let readme = "intro\n## Command Reference\n\n| Command | Purpose |\n| --- | --- |\n\
                      | `sbh status --json` | ok |\n\
                      | `sbh ballast release N` | ok |\n\
                      | `sbh config show|set|validate` | ok |\n\
                      | `sbh lease run --target PATH -- COMMAND...` | ok |\n\
                      | `sbh nosuch --flag` | flagged |\n\
                      | `sbh ballast nosub` | ok: ballast exists, the word is treated as an argument |\n\
                      \n## Next section\n| `sbh other` | outside the section |\n";
        let missing = undocumented_commands(readme, "## Command Reference", &known);
        assert_eq!(missing, vec!["| `sbh nosuch --flag` | flagged |"]);
        assert_eq!(
            undocumented_commands("no reference here", "## Command Reference", &known),
            vec!["no \"## Command Reference\" section"]
        );
        // AGENTS.md escapes the alternatives as `show\|set`.
        assert!(
            undocumented_commands(
                "## CLI Command Reference\n| `sbh config show\\|set` | ok |\n",
                "## CLI Command Reference",
                &known
            )
            .is_empty()
        );
    }

    fn fixture_cli() -> clap::Command {
        use clap::{Arg, Command};
        Command::new("sbh")
            .arg(Arg::new("json").long("json").global(true))
            .subcommand(Command::new("status").arg(Arg::new("watch").long("watch")))
            .subcommand(
                Command::new("ballast")
                    .arg(Arg::new("mount").long("mount"))
                    .subcommand(Command::new("release").arg(Arg::new("count").long("count"))),
            )
    }

    /// A documented flag must exist on the row's command, an ancestor, or
    /// the global flags; a made-up one is reported with its row (the
    /// negative self-test the CI check relies on).
    #[test]
    fn documented_flags_must_exist_on_their_command() {
        let root = fixture_cli();
        let good = "## Command Reference\n\
                    | `sbh status --watch --json` | ok |\n\
                    | `sbh ballast release --count N --mount M` | ancestor flag ok |\n\
                    | `sbh ballast --mount M release [--count N]` | flag between path words |\n\
                    | `sbh status` | mentions `--help` too |\n\
                    | `sbh nosuch --whatever` | unknown commands are not this check's job |\n\
                    \n## Next\n| `sbh status --bogus` | outside |\n";
        assert!(undocumented_flags(good, "## Command Reference", &root).is_empty());

        let bad = "## Command Reference\n| `sbh status --wach` | typo |\n\
                   | `sbh ballast --count 1` | subcommand flag on the parent |\n";
        assert_eq!(
            undocumented_flags(bad, "## Command Reference", &root),
            vec![
                "| `sbh status --wach` | typo |: --wach".to_string(),
                "| `sbh ballast --count 1` | subcommand flag on the parent |: --count".to_string(),
            ]
        );
        assert_eq!(
            long_flags_in("a -- b --x1 --two-words --9 --"),
            vec!["x1", "two-words"]
        );
    }

    /// Backticked repository paths must exist; wildcards, placeholders and
    /// paths outside the tracked prefixes are ignored.
    #[test]
    fn backticked_repository_paths_must_exist() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src/tui")).unwrap();
        fs::write(dir.path().join("src/tui/replay.rs"), "").unwrap();
        fs::create_dir_all(dir.path().join("docs")).unwrap();
        fs::write(dir.path().join("docs/a.md"), "").unwrap();
        let text = "see `src/tui/replay.rs` and `docs/a.md:` and `src/tui/` (a directory)\n\
                    globs `src/**/*.rs`, placeholders `docs/<name>.md`, braces `src/tui/{a,b}.rs`\n\
                    outside `target/debug/sbh` and `/etc/sbh/config.toml`\n\
                    missing `src/tui/gone.rs` and `scripts/nope.sh`; repeated `src/tui/gone.rs`\n";
        assert_eq!(
            missing_file_references(text, dir.path()),
            vec![
                "line 4: `src/tui/gone.rs`".to_string(),
                "line 4: `scripts/nope.sh`".to_string()
            ]
        );
    }

    #[cfg(feature = "tui")]
    #[test]
    fn dashboard_sections_render_from_the_tui_tables() {
        let document = test_document();
        let dashboard = document.dashboard.as_ref().expect("tui build");
        assert_eq!(dashboard.screens.len(), 7);
        assert_eq!(
            dashboard.playbook.len(),
            crate::tui::incident::INCIDENT_PLAYBOOK.len()
        );
        assert_eq!(
            dashboard.palette.len(),
            crate::tui::input::command_palette_actions().len()
        );
        let keymap = document.render_section("dashboard-keymap").unwrap();
        assert!(keymap.starts_with("**Navigation:**\n\n| Key | Where | Action |"));
        assert!(keymap.contains("| `Shift-X` | Ballast |"));
        let palette = document.render_section("dashboard-palette").unwrap();
        assert!(palette.contains("- `incident.*` (3):"));
        assert!(palette.contains("`incident.quick-release`"));
        let playbook = document.render_section("dashboard-playbook").unwrap();
        assert!(playbook.starts_with("1. Release ballast (Ballast screen, High)\n"));
        let screens = document.render_section("dashboard-screens").unwrap();
        assert!(screens.contains("| `5` | Ballast |"));
    }
}
