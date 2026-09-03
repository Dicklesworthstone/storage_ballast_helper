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

use serde::Serialize;
use serde_json::{Value, json};

use crate::core::config::Config;
use crate::core::errors::{Result, SbhError};

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
        }
    };
    let group_label = |group: KeyGroup| match group {
        KeyGroup::Navigation => "Navigation",
        KeyGroup::Overlays => "Overlays",
        KeyGroup::Incident => "Incident shortcuts",
        KeyGroup::Screen => "Screen-specific",
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

/// The whole generated document.
#[derive(Debug, Clone, Serialize)]
pub struct DocsDocument {
    pub schema_version: u32,
    pub sbh_version: &'static str,
    pub env_vars: Vec<EnvVarDoc>,
    pub commands: Vec<CommandDoc>,
    pub dashboard: Option<DashboardDocs>,
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
        let mut names = vec!["env-vars", "commands"];
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
