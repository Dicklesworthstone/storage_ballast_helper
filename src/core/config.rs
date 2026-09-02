//! Configuration system: TOML file + env var overrides + smart defaults.

#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::core::errors::{Result, SbhError};
use crate::daemon::notifications::NotificationConfig;
use crate::daemon::policy::{BehaviorConfig, BehaviorDispatchTable, BehaviorPreset, PolicyConfig};

/// Supplemental protection file written by `sbh protect`.
pub const SACRED_CONFIG_FILENAME: &str = "sacred.toml";

/// A key in the config file that no section declares.
///
/// Collected (not fatal) by [`Config::load`]; `sbh config validate` lists
/// them and fails under `--strict` or `[core] strict_config = true`, and the
/// daemon warns per key at startup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnknownConfigKey {
    /// Dotted key path as written, e.g. `scoring.weights` or `monitor`.
    pub path: String,
    /// "did you mean `x`?" or the replacement for a legacy README key.
    pub suggestion: Option<String>,
}

impl std::fmt::Display for UnknownConfigKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.suggestion {
            Some(suggestion) => write!(f, "unknown config key `{}` ({suggestion})", self.path),
            None => write!(f, "unknown config key `{}`", self.path),
        }
    }
}

/// `[core]`: behaviour of the config loader itself.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct CoreConfig {
    /// Refuse to start the daemon (and fail `config validate`) when the file
    /// contains keys no section declares, instead of warning about them.
    pub strict_config: bool,
}

/// Full SBH configuration model.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub core: CoreConfig,
    pub pressure: PressureConfig,
    pub scanner: ScannerConfig,
    pub scoring: ScoringConfig,
    pub ballast: BallastConfig,
    pub scheduler: VoiConfig,
    pub update: UpdateConfig,
    pub telemetry: TelemetryConfig,
    pub paths: PathsConfig,
    pub notifications: NotificationConfig,
    pub dashboard: DashboardConfig,
    pub policy: PolicyConfig,
    /// Memory-by-disk behavior matrix (`preset`, `memory_never_reduces_cleanup`,
    /// `cells`). See [`BehaviorConfig`].
    pub behavior: BehaviorConfig,
    pub system_tuning: SystemTuningConfig,
    /// Keys the loaded file contained that no section declares. Not part
    /// of the file format (never serialized; excluded from `stable_hash`).
    #[serde(skip)]
    pub unknown_keys: Vec<UnknownConfigKey>,
}

/// Parse a config file leniently: every struct rejects unknown keys, so the
/// parser is run repeatedly, removing each reported unknown key from the raw
/// table until it succeeds. The removed keys come back with did-you-mean
/// suggestions; the returned config is what a lenient parse would have
/// produced. Any other parse error is returned as-is.
fn parse_config_lenient(raw: &str) -> Result<(Config, Vec<UnknownConfigKey>)> {
    const MAX_UNKNOWN_KEYS: usize = 256;
    let mut table: toml::Table = toml::from_str(raw)?;
    let mut unknown = Vec::new();
    loop {
        match table.clone().try_into::<Config>() {
            Ok(config) => return Ok((config, unknown)),
            Err(err) => {
                let message = err.to_string();
                let Some((field, expected)) = parse_unknown_field_error(&message) else {
                    return Err(err.into());
                };
                let Some(path) = remove_unknown_key(&mut table, &field, &expected) else {
                    return Err(err.into());
                };
                let suggestion = suggest_config_key(&field, &expected, &path);
                unknown.push(UnknownConfigKey { path, suggestion });
                if unknown.len() > MAX_UNKNOWN_KEYS {
                    return Err(SbhError::InvalidConfig {
                        details: format!(
                            "more than {MAX_UNKNOWN_KEYS} unknown keys; this is not an sbh config file"
                        ),
                    });
                }
            }
        }
    }
}

/// Extract (`field`, expected keys) from serde's `unknown field` message,
/// which reads "unknown field `x`, expected one of `a`, `b`" or
/// "unknown field `x`, expected `a`".
fn parse_unknown_field_error(message: &str) -> Option<(String, Vec<String>)> {
    let rest = message.split("unknown field `").nth(1)?;
    let (field, after) = rest.split_once('`')?;
    let expected_part = after.split("expected").nth(1).unwrap_or("");
    let expected_line = expected_part.lines().next().unwrap_or("");
    let expected = expected_line
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect();
    Some((field.to_string(), expected))
}

/// Remove `field` from the table the parser complained about and return its
/// dotted path. Prefers a table whose other keys are all in `expected` (the
/// keys the complaining struct declares); falls back to the first table that
/// holds the key at all (a section with several unknown keys).
fn remove_unknown_key(table: &mut toml::Table, field: &str, expected: &[String]) -> Option<String> {
    let mut prefix = Vec::new();
    remove_unknown_key_in(table, field, expected, true, &mut prefix)
        .or_else(|| remove_unknown_key_in(table, field, expected, false, &mut prefix))
}

fn remove_unknown_key_in(
    table: &mut toml::Table,
    field: &str,
    expected: &[String],
    siblings_must_be_known: bool,
    prefix: &mut Vec<String>,
) -> Option<String> {
    if table.contains_key(field) {
        let siblings_known = table
            .keys()
            .filter(|key| key.as_str() != field)
            .all(|key| expected.iter().any(|known| known == key));
        if !siblings_must_be_known || siblings_known {
            table.remove(field);
            let mut path = prefix.clone();
            path.push(field.to_string());
            return Some(path.join("."));
        }
    }
    for (key, value) in table.iter_mut() {
        prefix.push(key.clone());
        let found = match value {
            toml::Value::Table(inner) => {
                remove_unknown_key_in(inner, field, expected, siblings_must_be_known, prefix)
            }
            toml::Value::Array(items) => items.iter_mut().enumerate().find_map(|(index, item)| {
                let toml::Value::Table(inner) = item else {
                    return None;
                };
                prefix.push(format!("[{index}]"));
                let found =
                    remove_unknown_key_in(inner, field, expected, siblings_must_be_known, prefix);
                prefix.pop();
                found
            }),
            _ => None,
        };
        prefix.pop();
        if found.is_some() {
            return found;
        }
    }
    None
}

/// Replacements for keys that older READMEs and configs used.
fn legacy_config_key_hint(path: &str) -> Option<&'static str> {
    let leaf = path.rsplit('.').next().unwrap_or(path);
    let hint = match path {
        "monitor" => {
            "the [monitor] section became [pressure]: green_min_free_pct, yellow_min_free_pct, orange_min_free_pct, red_min_free_pct, poll_interval_ms"
        }
        "logging" => "the [logging] section became [paths]: sqlite_db, jsonl_log",
        "guardrails" => {
            "guardrail settings live in [scoring] calibration_floor and [telemetry] guardrail_window_size / guardrail_min_observations"
        }
        "scoring.weights" => {
            "weights are flat keys: [scoring] location_weight, name_weight, age_weight, size_weight, structure_weight"
        }
        "ballast.per_volume_file_count" => "use [ballast] file_count",
        "ballast.per_volume_file_size_mb" => "use [ballast] file_size_bytes",
        "policy.mode" => "use [policy] initial_mode = \"observe\" | \"canary\" | \"enforce\"",
        "policy.canary_delete_cap_per_hour" => "use [policy] max_canary_deletes_per_hour",
        "policy.fallback_safe" => {
            "use [policy] kill_switch = true to hold the daemon in fallback-safe"
        }
        _ => match leaf {
            "file_size_mb" => "use file_size_bytes",
            "scan_interval_secs" | "sample_interval_seconds" => "use [pressure] poll_interval_ms",
            "max_ballast_mb" => "use [ballast] file_count and file_size_bytes",
            "log_level" => "removed; there is no log level setting",
            _ => return None,
        },
    };
    Some(hint)
}

/// A did-you-mean for an unknown key: a legacy-key hint when the key is a
/// known relic, else the closest declared key by edit distance.
fn suggest_config_key(field: &str, expected: &[String], path: &str) -> Option<String> {
    if let Some(hint) = legacy_config_key_hint(path) {
        return Some(hint.to_string());
    }
    let threshold = (field.len() / 3).max(2);
    expected
        .iter()
        .map(|candidate| (levenshtein(field, candidate), candidate))
        .filter(|(distance, _)| *distance <= threshold)
        .min_by_key(|(distance, _)| *distance)
        .map(|(_, candidate)| format!("did you mean `{candidate}`?"))
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    let mut current = vec![0; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        current[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let substitution = previous[j] + usize::from(ca != cb);
            current[j + 1] = (previous[j + 1] + 1).min(current[j] + 1).min(substitution);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[b.len()]
}

/// Expand a leading `~`, `~/`, `$HOME` or `${HOME}` in a path. Anything
/// else is returned unchanged; without a `HOME` the path is left alone.
#[must_use]
pub fn expand_home_path(path: &Path) -> PathBuf {
    let Some(text) = path.to_str() else {
        return path.to_path_buf();
    };
    PathBuf::from(expand_home_str(text))
}

/// [`expand_home_path`] for string-typed paths and globs.
#[must_use]
pub fn expand_home_str(text: &str) -> String {
    let Some(home) = env::var_os("HOME") else {
        return text.to_string();
    };
    let home = home.to_string_lossy();
    for prefix in ["~/", "$HOME/", "${HOME}/"] {
        if let Some(rest) = text.strip_prefix(prefix) {
            return format!("{}/{rest}", home.trim_end_matches('/'));
        }
    }
    if text == "~" || text == "$HOME" || text == "${HOME}" {
        return home.to_string();
    }
    text.to_string()
}

/// Pressure thresholds and control knobs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct PressureConfig {
    pub green_min_free_pct: f64,
    pub yellow_min_free_pct: f64,
    pub orange_min_free_pct: f64,
    pub red_min_free_pct: f64,
    pub poll_interval_ms: u64,
    /// Minimum seconds between repeated behavior transitions in the same direction.
    pub behavior_hysteresis_secs: u64,
    /// Predictive pre-emption settings.
    pub prediction: PredictionConfig,
}

/// Knobs for predictive pre-emptive action (EWMA → graduated response).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct PredictionConfig {
    /// Master switch — when false, predictive pipeline is disabled.
    pub enabled: bool,
    /// Start pre-emptive cleanup when predicted exhaustion is within this many minutes.
    pub action_horizon_minutes: f64,
    /// Emit early-warning events when predicted exhaustion is within this many minutes.
    pub warning_horizon_minutes: f64,
    /// Minimum EWMA confidence required before any pre-emptive action.
    pub min_confidence: f64,
    /// Minimum EWMA sample count before any pre-emptive action.
    pub min_samples: u64,
    /// Threshold below which we escalate to imminent danger.
    pub imminent_danger_minutes: f64,
    /// Threshold below which imminent danger becomes critical.
    pub critical_danger_minutes: f64,
    /// Minimum confidence required during detected bursts. Higher than normal
    /// min_confidence to avoid false alarms from transient compilation spikes.
    pub burst_min_confidence: f64,
}

/// Scanner runtime implementation selector.
///
/// `V1` is the current directory-walker implementation. `V2` enables the
/// event/index-assisted scanner path behind the rollout flag while keeping all
/// destructive actions behind the existing policy and deletion gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ScannerEngineMode {
    /// Current production scanner implementation.
    #[default]
    V1,
    /// Event/index-assisted scanner rollout path.
    V2,
}

impl std::fmt::Display for ScannerEngineMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V1 => f.write_str("v1"),
            Self::V2 => f.write_str("v2"),
        }
    }
}

impl std::str::FromStr for ScannerEngineMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "v1" => Ok(Self::V1),
            "v2" => Ok(Self::V2),
            other => Err(format!(
                "invalid scanner engine {other:?}: expected \"v1\" or \"v2\""
            )),
        }
    }
}

/// Filesystem event backend selection for scanner v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ScannerEventSourceMode {
    /// Prefer a safe kernel backend when one is available; otherwise fall back
    /// to reconciliation.
    #[default]
    Auto,
    /// Force stat/mtime reconciliation without a kernel event source.
    ReconciliationOnly,
}

impl std::fmt::Display for ScannerEventSourceMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => f.write_str("auto"),
            Self::ReconciliationOnly => f.write_str("reconciliation-only"),
        }
    }
}

impl std::str::FromStr for ScannerEventSourceMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "reconciliation-only" | "reconciliation_only" => Ok(Self::ReconciliationOnly),
            other => Err(format!(
                "invalid scanner event source {other:?}: expected \"auto\" or \"reconciliation-only\""
            )),
        }
    }
}

/// Scanner behavior and safety constraints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
// Independent operator toggles on a config struct, not an encoded state machine.
#[allow(clippy::struct_excessive_bools)]
pub struct ScannerConfig {
    pub engine: ScannerEngineMode,
    pub event_source: ScannerEventSourceMode,
    pub event_watch_budget: usize,
    pub root_paths: Vec<PathBuf>,
    pub excluded_paths: Vec<PathBuf>,
    pub protected_paths: Vec<String>,
    pub min_file_age_minutes: u64,
    pub max_depth: usize,
    pub parallelism: usize,
    pub follow_symlinks: bool,
    pub cross_devices: bool,
    pub dry_run: bool,
    pub max_delete_batch: usize,
    pub repeat_deletion_base_cooldown_secs: u64,
    pub repeat_deletion_max_cooldown_secs: u64,
    /// Minimum seconds to wait after a scan pass that found nothing reclaimable
    /// before running another pass triggered by the *same* sustained pressure.
    ///
    /// Belt-and-suspenders against CPU hot-loops (B6): if a pass yields zero
    /// reclaimable candidates, re-scanning immediately just burns a core. This
    /// cooldown forces a pause. Forced/operator scans and rising pressure (Red/
    /// Critical) bypass it. `0` disables the cooldown (legacy behavior).
    pub min_rescan_interval_secs: u64,
    /// Ceiling on the share of wall-clock time the scanner may spend scanning,
    /// as a percentage. `0` — or any value `>= 100` — disables the limiter
    /// (legacy behavior).
    ///
    /// `min_rescan_interval_secs` only paces *unproductive* passes. On a
    /// chronically-full host every pass reclaims a trickle, so the empty-pass
    /// counter resets forever, the Red/Critical bypass never expires, and the
    /// daemon re-walks back-to-back and pins a core (#15). This is the missing
    /// floor: after a pass lasting `T`, the next pressure-driven pass waits at
    /// least `T * (100 - pct) / pct`.
    ///
    /// Bounds *scanning time*, not core count — the scan is parallel (see
    /// `parallelism`), so the process-wide CPU share lands near
    /// `pct * parallelism`, not `pct` of one core. The wait is clamped to a 5s
    /// floor and a 5min ceiling so a fast pass cannot busy-wait and a
    /// budget-exhausting pass cannot stall reclaim on a filling disk.
    ///
    /// Forced/operator scans and config reloads always bypass it.
    pub max_scan_duty_cycle_pct: u8,
    /// Maximum wall-clock seconds for a single scan pass. 0 = use built-in default.
    pub scan_time_budget_secs: u64,
    /// Seconds to reuse active file/process/mmap evidence before refreshing.
    /// 0 disables caching and forces a fresh probe on demand.
    pub active_reference_cache_ttl_secs: u64,
    /// Minimum candidate size before running expensive active-reference probes.
    /// 0 checks every candidate.
    pub active_reference_min_size_bytes: u64,
    /// When a pressured device has no configured `root_paths` (and
    /// `cross_devices` is off), scan the known-safe cache locations on that
    /// device (`~/.cache/pip`, cargo registry caches, npm `_cacache`, Trash,
    /// `/var/tmp/*`, ...) as opaque candidates instead of doing nothing.
    /// Every veto and the executor pre-flight still apply. Turn off on shared
    /// multi-user hosts where other users' caches must stay untouched.
    pub catalog_roots_on_pressured_device: bool,
    /// How often (seconds) a catalog scan may repeat on the same mount at the
    /// same pressure level; a rising level re-arms it immediately.
    pub catalog_rescan_interval_secs: u64,
    /// Active append-only log truncation policy.
    ///
    /// Standard delete is blocked by the FileOpen veto when a process holds a
    /// write fd on a growing log. This policy lets the daemon reclaim space by
    /// `ftruncate`-ing matching files in place, which preserves the open fd so
    /// the writer keeps logging into the same (now sparse) file.
    pub log_truncation: LogTruncationConfig,
}

/// Active-log truncate-in-place policy.
///
/// Matches by a small custom path-pattern language to avoid pulling in a glob
/// dependency. Each `paths` entry is an absolute path that may contain a
/// literal `*` wildcard inside a segment — matched against direct children of
/// that segment (e.g. `/home/*/.codex/log/codex-tui.log` expands to one file
/// per home). Other wildcard characters such as `?` are treated literally.
/// `~` and `$HOME` are NOT expanded; configure absolute paths explicitly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct LogTruncationConfig {
    /// Master switch. Disabled by default for backward compatibility with
    /// existing deployments; enable explicitly per-host once paths are vetted.
    pub enabled: bool,
    /// Path patterns to consider. See struct-level docs for the pattern grammar.
    pub paths: Vec<String>,
    /// Minimum file size before truncation is attempted. Set high enough that
    /// a routine ad-hoc log isn't truncated mid-write under low pressure.
    pub min_size_bytes: u64,
    /// Free-percent ceiling below which truncation is allowed even on files
    /// younger than `min_age_minutes`. Above this threshold, only files that
    /// have not been modified for `min_age_minutes` are eligible. 100 disables
    /// the pressure gate (always-eligible if size threshold met).
    pub pressure_free_pct_ceiling: u8,
    /// Minimum file mtime age (minutes) before truncation in non-pressure mode.
    /// Prevents truncating a log that's actively being written under healthy
    /// disk conditions just because it crossed the size threshold.
    pub min_age_minutes: u64,
}

/// Multi-factor score weights and decision-theoretic losses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ScoringConfig {
    pub min_score: f64,
    pub location_weight: f64,
    pub name_weight: f64,
    pub age_weight: f64,
    pub size_weight: f64,
    pub structure_weight: f64,
    pub false_positive_loss: f64,
    pub false_negative_loss: f64,
    pub calibration_floor: f64,
    /// Posterior-abandoned floor applied to candidates whose *structural*
    /// evidence is definite (validated `CACHEDIR.TAG`, Rust build markers, Go
    /// build cache, `node_modules` under a temp root, DerivedData, Electron
    /// caches). The floor changes only the prior fed into the expected-loss
    /// decision; every veto still runs first. Default 0.85.
    pub posterior_floor_definite: f64,
}

/// Ballast allocation settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct BallastConfig {
    pub file_count: usize,
    pub file_size_bytes: u64,
    pub replenish_cooldown_minutes: u64,
    /// Automatically provision ballast pools on each monitored volume.
    pub auto_provision: bool,
    /// Per-volume overrides keyed by mount-point path (e.g., "/data").
    /// Uses BTreeMap for stable ordering in hash generation.
    #[serde(default)]
    pub overrides: BTreeMap<String, BallastVolumeOverride>,
}

/// Per-volume override for ballast pool settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct BallastVolumeOverride {
    /// Whether to provision a ballast pool on this volume (default: true).
    pub enabled: bool,
    /// Override file count for this volume.
    pub file_count: Option<usize>,
    /// Override file size in bytes for this volume.
    pub file_size_bytes: Option<u64>,
}

impl Default for BallastVolumeOverride {
    fn default() -> Self {
        Self {
            enabled: true,
            file_count: None,
            file_size_bytes: None,
        }
    }
}

impl BallastConfig {
    /// Resolve effective file_count for a given mount point, applying overrides.
    #[must_use]
    pub fn effective_file_count(&self, mount_path: &str) -> usize {
        let key = strip_trailing_separator(mount_path);
        self.overrides
            .get(key)
            .and_then(|o| o.file_count)
            .unwrap_or(self.file_count)
    }

    /// Resolve effective file_size_bytes for a given mount point, applying overrides.
    #[must_use]
    pub fn effective_file_size_bytes(&self, mount_path: &str) -> u64 {
        let key = strip_trailing_separator(mount_path);
        self.overrides
            .get(key)
            .and_then(|o| o.file_size_bytes)
            .unwrap_or(self.file_size_bytes)
    }

    /// Check whether a volume is enabled for ballast (disabled via override).
    #[must_use]
    pub fn is_volume_enabled(&self, mount_path: &str) -> bool {
        let key = strip_trailing_separator(mount_path);
        self.overrides.get(key).is_none_or(|o| o.enabled)
    }
}

/// Tuning knobs for the VOI scan scheduler.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct VoiConfig {
    /// Master switch.
    pub enabled: bool,
    /// Maximum number of paths to scan per scheduling interval.
    pub scan_budget_per_interval: usize,
    /// Minimum fraction of budget reserved for exploration (round-robin of least-scanned paths).
    pub exploration_quota_fraction: f64,
    /// Weight for IO cost penalty (bytes estimated per scan).
    pub io_cost_weight: f64,
    /// Weight for false-positive risk penalty.
    pub fp_risk_weight: f64,
    /// Weight for exploration bonus.
    pub exploration_weight: f64,
    /// Forecast-error threshold: if MAPE exceeds this, switch to fallback.
    pub forecast_error_threshold: f64,
    /// Number of consecutive windows with high forecast error before triggering fallback.
    pub fallback_trigger_windows: u32,
    /// Number of consecutive windows with acceptable error to exit fallback.
    pub recovery_trigger_windows: u32,
    /// Minimum scans of a path before its forecast is considered reliable.
    pub min_observations_for_forecast: u32,
    /// Alpha value for EWMA smoothing of per-path statistics.
    pub ewma_alpha: f64,
}

impl Default for VoiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_budget_per_interval: 5,
            exploration_quota_fraction: 0.20,
            io_cost_weight: 0.1,
            fp_risk_weight: 0.15,
            exploration_weight: 0.25,
            forecast_error_threshold: 0.5,
            fallback_trigger_windows: 3,
            recovery_trigger_windows: 5,
            min_observations_for_forecast: 3,
            ewma_alpha: 0.3,
        }
    }
}

/// Logging and stats-collector tuning.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    pub fs_cache_ttl_ms: u64,
    pub ewma_base_alpha: f64,
    pub ewma_min_alpha: f64,
    pub ewma_max_alpha: f64,
    pub ewma_min_samples: u64,
    /// Size of the EWMA rate history ring buffer for burst detection.
    pub ewma_rate_history_size: usize,
    /// Rolling window size for the adaptive guard calibration tracking.
    pub guardrail_window_size: usize,
    /// Minimum observations before the adaptive guard can transition to PASS.
    pub guardrail_min_observations: usize,
    /// RSS threshold that emits self-monitor warnings.
    pub daemon_rss_warning_bytes: u64,
    /// RSS hard cap that makes the daemon exit nonzero for service restart.
    pub daemon_rss_hard_limit_bytes: u64,
}

/// Update-check behavior, cache policy, and opt-out controls.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct UpdateConfig {
    pub enabled: bool,
    pub metadata_cache_ttl_seconds: u64,
    pub metadata_cache_file: PathBuf,
    pub background_refresh: bool,
    pub notices_enabled: bool,
}

/// System-level (OS kernel) tuning that complements sbh's own controls.
///
/// Currently models kernel writeback (dirty-page) limit tuning. On high-RAM
/// hosts the default percentage-based `vm.dirty_ratio` knobs let many GB of
/// dirty pages pile up and then flush in bursts through kernel writeback threads
/// that ignore `ionice`, stalling interactive I/O. sbh recommends — and, when
/// invoked with privilege, applies — absolute byte limits sized to the backing
/// device's write bandwidth. This is never done by the daemon at runtime: it is
/// surfaced by `sbh doctor --system` and applied by `sbh tune --apply` or `sbh
/// install` (both root-gated, backup-first, reversible).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct SystemTuningConfig {
    /// Master switch for writeback tuning detection/recommendation.
    pub writeback_enabled: bool,
    /// Apply + persist writeback tuning during `sbh install` when run as root.
    pub writeback_auto_apply_on_install: bool,
    /// Target seconds for the background dirty pool to drain at device bandwidth.
    pub writeback_target_drain_secs: f64,
    /// Hard-limit (`vm.dirty_bytes`) multiple of the background limit.
    pub writeback_hard_ratio: u64,
    /// Floor for `vm.dirty_background_bytes`.
    pub writeback_min_background_bytes: u64,
    /// Ceiling for `vm.dirty_background_bytes`.
    pub writeback_max_background_bytes: u64,
    /// Run the on-volume bandwidth micro-benchmark when applying.
    pub writeback_benchmark_enabled: bool,
    /// Byte budget for the bandwidth micro-benchmark write.
    pub writeback_benchmark_bytes: u64,
    /// Effective dirty-pool size above which `doctor` warns (ratio-mode hosts).
    pub writeback_pool_warn_bytes: u64,
    /// Path of the persisted sysctl.d snippet.
    pub writeback_sysctl_path: PathBuf,
}

impl Default for SystemTuningConfig {
    fn default() -> Self {
        Self {
            writeback_enabled: true,
            writeback_auto_apply_on_install: true,
            writeback_target_drain_secs: 1.0,
            writeback_hard_ratio: 4,
            writeback_min_background_bytes: 256 * 1024 * 1024,
            writeback_max_background_bytes: 2 * 1024 * 1024 * 1024,
            writeback_benchmark_enabled: true,
            writeback_benchmark_bytes: 96 * 1024 * 1024,
            writeback_pool_warn_bytes: 4 * 1024 * 1024 * 1024,
            writeback_sysctl_path: PathBuf::from("/etc/sysctl.d/99-sbh-writeback.conf"),
        }
    }
}

/// Dashboard runtime selection mode.
///
/// Controls which TUI implementation `sbh dashboard` uses during phased rollout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DashboardMode {
    /// Use the legacy crossterm-based dashboard (pre-overhaul).
    Legacy,
    /// Use the new FrankentUI-based cockpit (post-overhaul).
    #[default]
    New,
}

impl std::fmt::Display for DashboardMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Legacy => f.write_str("legacy"),
            Self::New => f.write_str("new"),
        }
    }
}

impl std::str::FromStr for DashboardMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "legacy" => Ok(Self::Legacy),
            "new" => Ok(Self::New),
            other => Err(format!(
                "invalid dashboard mode {other:?}: expected \"legacy\" or \"new\""
            )),
        }
    }
}

/// Dashboard rollout controls.
///
/// Provides phased rollout semantics for the TUI overhaul:
/// - `mode`: selects runtime (legacy vs new) as the config-level default
/// - `kill_switch`: emergency override that forces legacy regardless of other settings
///
/// Resolution priority (highest wins):
/// 1. `SBH_DASHBOARD_KILL_SWITCH=true` env var → Legacy
/// 2. `--legacy-dashboard` CLI flag → Legacy
/// 3. `--new-dashboard` CLI flag → New
/// 4. `SBH_DASHBOARD_MODE` env var → parsed mode
/// 5. `dashboard.mode` config field → configured mode
/// 6. Hardcoded default → New
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct DashboardConfig {
    /// Default runtime mode when no CLI flag or env var overrides.
    pub mode: DashboardMode,
    /// Emergency kill switch: forces legacy dashboard regardless of all other settings.
    pub kill_switch: bool,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            mode: DashboardMode::New,
            kill_switch: false,
        }
    }
}

/// Filesystem paths used by sbh.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct PathsConfig {
    pub config_file: PathBuf,
    pub ballast_dir: PathBuf,
    pub state_file: PathBuf,
    pub sqlite_db: PathBuf,
    pub jsonl_log: PathBuf,
}

impl PathsConfig {
    /// Native user-scope paths for macOS.
    #[must_use]
    pub fn macos_native_for_home(home_dir: &Path) -> Self {
        let data_dir = macos_data_dir(home_dir);
        paths_from_config_data_and_ballast_dir(
            macos_config_file_for_home(home_dir),
            &data_dir,
            macos_native_ballast_dir_for_data_dir(&data_dir),
        )
    }

    /// XDG user-scope paths for users who explicitly choose that layout.
    #[must_use]
    pub fn xdg_for_home(home_dir: &Path) -> Self {
        let data_dir = xdg_data_dir(home_dir);
        paths_from_config_and_data_dir(xdg_config_file_for_home(home_dir), &data_dir)
    }

    /// System-scope paths used when a service process has no user home.
    #[must_use]
    pub fn system_default() -> Self {
        let data_dir = system_data_dir();
        paths_from_config_data_and_ballast_dir(
            system_config_file(),
            &data_dir,
            system_ballast_dir_for_data_dir(&data_dir),
        )
    }

    /// Default paths for a service scope.
    #[must_use]
    pub fn for_service_scope(user_scope: bool) -> Self {
        if user_scope {
            Self::default()
        } else {
            Self::system_default()
        }
    }

    /// Durable scanner v2 candidate-index checkpoint.
    #[must_use]
    pub fn scanner_index_file(&self) -> PathBuf {
        data_dir_for_paths(self).join("scanner-index-v2.json")
    }
}

/// User-managed protection paths kept separate from the generated main config.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SacredConfig {
    #[serde(alias = "paths")]
    pub protected_paths: Vec<String>,
}

impl SacredConfig {
    pub fn normalize(&mut self) {
        let mut normalized = Vec::new();
        for path in self.protected_paths.drain(..) {
            let trimmed = path.trim();
            if !trimmed.is_empty() && !normalized.iter().any(|known| known == trimmed) {
                normalized.push(trimmed.to_string());
            }
        }
        self.protected_paths = normalized;
    }

    pub fn add_protected_path(&mut self, path: impl Into<String>) -> bool {
        let path = path.into();
        if self.protected_paths.iter().any(|known| known == &path) {
            false
        } else {
            self.protected_paths.push(path);
            true
        }
    }

    pub fn remove_protected_path(&mut self, path: &str) -> bool {
        let before = self.protected_paths.len();
        self.protected_paths
            .retain(|known| !protected_path_matches(known, path));
        before != self.protected_paths.len()
    }
}

fn protected_path_matches(known: &str, path: &str) -> bool {
    known == path
        || crate::core::paths::resolve_absolute_path(Path::new(known))
            == crate::core::paths::resolve_absolute_path(Path::new(path))
}

impl Default for PressureConfig {
    fn default() -> Self {
        Self {
            green_min_free_pct: 20.0,
            yellow_min_free_pct: 14.0,
            orange_min_free_pct: 10.0,
            red_min_free_pct: 6.0,
            poll_interval_ms: 5_000,
            behavior_hysteresis_secs: 5,
            prediction: PredictionConfig::default(),
        }
    }
}

impl Default for PredictionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            action_horizon_minutes: 30.0,
            warning_horizon_minutes: 60.0,
            min_confidence: 0.7,
            min_samples: 5,
            imminent_danger_minutes: 5.0,
            critical_danger_minutes: 2.0,
            burst_min_confidence: 0.85,
        }
    }
}

impl Default for ScannerConfig {
    fn default() -> Self {
        // Safe-by-default scan roots: only ephemeral temp directories.
        // `/data/projects`, `/home`, and `/root` are NOT included by default —
        // these hold source code and personal files, and historical scanner
        // heuristics have proven unsafe there (2026-05-16 fleet carnage wiped
        // ~87 working trees under `/data/projects` on trj; 2026-05-22 vmi
        // rerun deleted synced source crate stubs across the worker fleet).
        // Operators who want broader sweeps must opt in via config (or the
        // setup wizard), and the hardcoded refusal in
        // `deletion::preflight_check` will still veto anything that looks
        // like source code regardless of which roots are configured.
        Self {
            // V2 (opaque-pruning) is the default engine: it is the modern
            // traversal path that reuses v1's scoring/guardrail/deletion safety
            // surfaces, is what the production fleet runs (systemd sets
            // SBH_SCANNER_ENGINE=v2), and is required for structural artifact
            // detection — notably Go GOCACHE/GOMODCACHE caches that live under
            // arbitrary names no name pattern can match. Pin `engine = "v1"` in
            // config to opt back into the legacy full-descent walker.
            engine: ScannerEngineMode::V2,
            event_source: ScannerEventSourceMode::Auto,
            event_watch_budget: 8192,
            root_paths: vec![
                PathBuf::from("/tmp"),
                PathBuf::from("/data/tmp"),
                PathBuf::from("/var/tmp"),
            ],
            // Note: `/data/projects` is intentionally NOT in this list.
            // The setup wizard (cli/wizard.rs) actively adds `/data/projects`
            // to `root_paths` when run, and adding it ALSO to `excluded_paths`
            // would silently break wizard-generated configs (the walker would
            // refuse to descend into the configured root). The hardcoded
            // `is_hardcoded_source_tree` check in
            // `scanner::deletion::preflight_check` is the real defense and
            // applies regardless of config — operators can scan
            // `/data/projects` for legitimate target-dir cleanup, and
            // deletions of anything that looks like source code are vetoed
            // at preflight time.
            excluded_paths: vec![
                PathBuf::from("/"),
                PathBuf::from("/boot"),
                PathBuf::from("/etc"),
                PathBuf::from("/usr"),
                PathBuf::from("/bin"),
                PathBuf::from("/sbin"),
                PathBuf::from("/proc"),
                PathBuf::from("/sys"),
                PathBuf::from("/var/log"),
            ],
            protected_paths: Vec::new(),
            min_file_age_minutes: 5,
            max_depth: 10,
            parallelism: std::thread::available_parallelism()
                .map_or(2, |n| n.get().saturating_div(2).max(1)),
            follow_symlinks: false,
            cross_devices: false,
            dry_run: false,
            max_delete_batch: 20,
            repeat_deletion_base_cooldown_secs: 300,
            repeat_deletion_max_cooldown_secs: 3600,
            min_rescan_interval_secs: 90,
            catalog_roots_on_pressured_device: true,
            catalog_rescan_interval_secs: 900,
            // 25% => after a pass of T seconds, wait 3T before the next
            // pressure-driven pass. Keeps reclaim continuous on a full
            // disk while capping the scanner near a quarter of one core.
            max_scan_duty_cycle_pct: 25,
            // 300s is too short for /data/tmp on agent-swarm machines where
            // a single directory can hold tens of thousands of test artifact
            // entries. Scans timing out before identifying candidates was the
            // failure mode behind the 2026-04-30 100%-disk incident on ts1.
            scan_time_budget_secs: 900,
            active_reference_cache_ttl_secs: 30,
            active_reference_min_size_bytes: 100 * 1024 * 1024,
            log_truncation: LogTruncationConfig::default(),
        }
    }
}

impl Default for LogTruncationConfig {
    fn default() -> Self {
        // Defaults target the AI-coding-agent log patterns that drove the
        // 2026-05-13 css/ts2/trj fill incident: codex held write fds on
        // 81G–318G `codex-tui.log` files that sbh could not delete. Patterns
        // are listed but the feature is off by default so existing deployments
        // pick it up only after operator review.
        Self {
            enabled: false,
            paths: vec![
                "/home/*/.codex/log/codex-tui.log".to_string(),
                "/root/.codex/log/codex-tui.log".to_string(),
                "/home/*/.codex/log/*.log".to_string(),
            ],
            min_size_bytes: 1_073_741_824, // 1 GiB
            pressure_free_pct_ceiling: 15,
            min_age_minutes: 60,
        }
    }
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            min_score: 0.35,
            location_weight: 0.25,
            name_weight: 0.25,
            age_weight: 0.20,
            size_weight: 0.15,
            structure_weight: 0.15,
            false_positive_loss: 50.0,
            false_negative_loss: 30.0,
            calibration_floor: 0.40,
            posterior_floor_definite: 0.85,
        }
    }
}

impl Default for BallastConfig {
    fn default() -> Self {
        Self {
            file_count: 10,
            file_size_bytes: 1_073_741_824,
            replenish_cooldown_minutes: 10,
            auto_provision: true,
            overrides: BTreeMap::new(),
        }
    }
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            fs_cache_ttl_ms: 1_000,
            ewma_base_alpha: 0.30,
            ewma_min_alpha: 0.10,
            ewma_max_alpha: 0.75,
            ewma_min_samples: 3,
            ewma_rate_history_size: 200,
            guardrail_window_size: 500,
            guardrail_min_observations: 60,
            daemon_rss_warning_bytes: 256 * 1024 * 1024,
            daemon_rss_hard_limit_bytes: 500 * 1024 * 1024,
        }
    }
}

impl Default for UpdateConfig {
    fn default() -> Self {
        let paths = PathsConfig::default();
        Self {
            enabled: true,
            metadata_cache_ttl_seconds: 30 * 60,
            metadata_cache_file: default_update_metadata_cache_file(&paths),
            background_refresh: true,
            notices_enabled: true,
        }
    }
}

impl Default for PathsConfig {
    fn default() -> Self {
        env::var_os("HOME").map_or_else(Self::system_default, |home| {
            default_user_paths_for_home(&PathBuf::from(home))
        })
    }
}

fn default_user_paths_for_home(home_dir: &Path) -> PathsConfig {
    #[cfg(target_os = "macos")]
    {
        if macos_prefers_xdg_paths(home_dir) {
            xdg_paths_from_env_or_home(home_dir)
        } else {
            PathsConfig::macos_native_for_home(home_dir)
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        xdg_paths_from_env_or_home(home_dir)
    }
}

fn paths_from_config_and_data_dir(config_file: PathBuf, data_dir: &Path) -> PathsConfig {
    paths_from_config_data_and_ballast_dir(config_file, data_dir, data_dir.join("ballast"))
}

fn paths_from_config_data_and_ballast_dir(
    config_file: PathBuf,
    data_dir: &Path,
    ballast_dir: PathBuf,
) -> PathsConfig {
    PathsConfig {
        config_file,
        ballast_dir,
        state_file: data_dir.join("state.json"),
        sqlite_db: data_dir.join("activity.sqlite3"),
        jsonl_log: data_dir.join("activity.jsonl"),
    }
}

fn xdg_config_file_for_home(home_dir: &Path) -> PathBuf {
    home_dir.join(".config").join("sbh").join("config.toml")
}

fn xdg_data_dir(home_dir: &Path) -> PathBuf {
    home_dir.join(".local").join("share").join("sbh")
}

fn xdg_paths_from_env_or_home(home_dir: &Path) -> PathsConfig {
    let data_dir = xdg_data_dir_from_env_or_home(home_dir);
    paths_from_config_and_data_dir(xdg_config_file_from_env_or_home(home_dir), &data_dir)
}

fn xdg_config_file_from_env_or_home(home_dir: &Path) -> PathBuf {
    env::var_os("XDG_CONFIG_HOME").map_or_else(
        || xdg_config_file_for_home(home_dir),
        |dir| PathBuf::from(dir).join("sbh").join("config.toml"),
    )
}

fn xdg_data_dir_from_env_or_home(home_dir: &Path) -> PathBuf {
    env::var_os("XDG_DATA_HOME").map_or_else(
        || xdg_data_dir(home_dir),
        |dir| PathBuf::from(dir).join("sbh"),
    )
}

fn macos_config_file_for_home(home_dir: &Path) -> PathBuf {
    macos_data_dir(home_dir).join("config.toml")
}

fn macos_data_dir(home_dir: &Path) -> PathBuf {
    home_dir
        .join("Library")
        .join("Application Support")
        .join("sbh")
}

fn macos_native_ballast_dir_for_data_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("ballast.bin")
}

fn system_ballast_dir_for_data_dir(data_dir: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        data_dir.join("ballast.bin")
    }
    #[cfg(not(target_os = "macos"))]
    {
        data_dir.join("ballast")
    }
}

#[cfg(target_os = "macos")]
fn macos_prefers_xdg_paths(home_dir: &Path) -> bool {
    if env_truthy("SBH_USE_XDG_PATHS")
        || env::var_os("XDG_CONFIG_HOME").is_some()
        || env::var_os("XDG_DATA_HOME").is_some()
    {
        return true;
    }

    let native_config = macos_config_file_for_home(home_dir);
    let xdg_config = xdg_config_file_from_env_or_home(home_dir);
    xdg_config.exists() && !native_config.exists()
}

#[cfg(target_os = "macos")]
fn env_truthy(name: &str) -> bool {
    env::var_os(name).is_some_and(|value| {
        matches!(
            value.to_string_lossy().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn system_config_file() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library")
            .join("Application Support")
            .join("sbh")
            .join("config.toml")
    }
    #[cfg(not(target_os = "macos"))]
    {
        PathBuf::from("/etc/sbh/config.toml")
    }
}

/// Which file an invocation with no explicit `--config` / `SBH_CONFIG` reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImplicitConfigChoice {
    /// The per-user config (or, when it is absent, built-in defaults).
    User,
    /// No per-user config exists but the system one does: read it so an
    /// unprivileged `sbh status` sees what the system service sees.
    SystemFallback,
    /// The process is root and a system config exists. Root is the identity
    /// the system service and `sudo sbh …` share, so both must resolve the
    /// same file; `shadowed_user_config` records that root's own per-user
    /// file also exists and is being ignored.
    SystemForRoot { shadowed_user_config: bool },
}

/// Decide the implicit config file. Privilege must not silently change which
/// config is in force: before this rule `sudo sbh ballast provision` read
/// `~root/.config/sbh/config.toml`, so the pool declared by
/// `/etc/sbh/config.toml` (root-owned, hence only writable via sudo) could
/// never be provisioned, and `sbh status` and `sudo sbh status` reported two
/// different pools. An explicit `--config` / `SBH_CONFIG` still wins and is
/// handled by the caller.
fn choose_implicit_config(
    is_root: bool,
    user_config_exists: bool,
    system_config_exists: bool,
) -> ImplicitConfigChoice {
    if is_root && system_config_exists {
        ImplicitConfigChoice::SystemForRoot {
            shadowed_user_config: user_config_exists,
        }
    } else if !user_config_exists && system_config_exists {
        ImplicitConfigChoice::SystemFallback
    } else {
        ImplicitConfigChoice::User
    }
}

/// Why `sbh` reads a particular config file. Printed by `sbh config path`
/// and used by [`Config::load`], so the two can never disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigPathSource {
    /// `--config PATH`.
    Explicit,
    /// The `SBH_CONFIG` environment variable.
    Env,
    /// The platform's per-user (or service-scope) default path.
    Default,
    /// No per-user config exists but the system one does.
    SystemFallback,
    /// Running as root with a system config present.
    SystemForRoot,
}

impl ConfigPathSource {
    /// Whether the operator named this file (so its absence is an error).
    #[must_use]
    pub const fn is_explicit(self) -> bool {
        matches!(self, Self::Explicit | Self::Env)
    }

    /// Whether the system config (and system data paths) are in force.
    #[must_use]
    pub const fn is_system(self) -> bool {
        matches!(self, Self::SystemFallback | Self::SystemForRoot)
    }
}

impl std::fmt::Display for ConfigPathSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Explicit => "--config",
            Self::Env => "SBH_CONFIG",
            Self::Default => "default",
            Self::SystemFallback => "system fallback",
            Self::SystemForRoot => "system (root)",
        })
    }
}

/// The config file an invocation reads, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedConfigPath {
    pub path: PathBuf,
    pub source: ConfigPathSource,
    pub exists: bool,
    /// Root's own per-user config, ignored in favour of the system one.
    pub shadowed_user_config: Option<PathBuf>,
    /// One sentence for humans.
    pub reason: String,
}

/// Pure resolution over already-observed inputs (testable without touching
/// the environment or the real filesystem layout).
fn resolve_config_path_from(
    explicit: Option<&Path>,
    env_config: Option<&Path>,
    default_path: &Path,
    system_config: &Path,
    is_root: bool,
    allow_system_fallback: bool,
) -> ResolvedConfigPath {
    if let Some(path) = explicit {
        return ResolvedConfigPath {
            path: path.to_path_buf(),
            source: ConfigPathSource::Explicit,
            exists: path.exists(),
            shadowed_user_config: None,
            reason: "--config names this file".to_string(),
        };
    }
    if let Some(path) = env_config {
        return ResolvedConfigPath {
            path: path.to_path_buf(),
            source: ConfigPathSource::Env,
            exists: path.exists(),
            shadowed_user_config: None,
            reason: "SBH_CONFIG names this file".to_string(),
        };
    }
    let choice = if allow_system_fallback {
        choose_implicit_config(is_root, default_path.exists(), system_config.exists())
    } else {
        ImplicitConfigChoice::User
    };
    match choice {
        ImplicitConfigChoice::User => {
            let exists = default_path.exists();
            let reason = if exists {
                "the default config for this user".to_string()
            } else if allow_system_fallback {
                format!(
                    "no config file for this user and none at {}; built-in defaults apply",
                    system_config.display()
                )
            } else {
                "no config file at the service-scope default; built-in defaults apply".to_string()
            };
            ResolvedConfigPath {
                path: default_path.to_path_buf(),
                source: ConfigPathSource::Default,
                exists,
                shadowed_user_config: None,
                reason,
            }
        }
        ImplicitConfigChoice::SystemFallback => ResolvedConfigPath {
            path: system_config.to_path_buf(),
            source: ConfigPathSource::SystemFallback,
            exists: true,
            shadowed_user_config: None,
            reason: format!(
                "no per-user config at {}; reading the system config the service uses",
                default_path.display()
            ),
        },
        ImplicitConfigChoice::SystemForRoot {
            shadowed_user_config,
        } => ResolvedConfigPath {
            path: system_config.to_path_buf(),
            source: ConfigPathSource::SystemForRoot,
            exists: true,
            shadowed_user_config: shadowed_user_config.then(|| default_path.to_path_buf()),
            reason: "running as root: the system config is the one the service and sudo share"
                .to_string(),
        },
    }
}

fn resolve_config_path_with(
    explicit: Option<&Path>,
    default_paths: &PathsConfig,
    allow_system_fallback: bool,
) -> ResolvedConfigPath {
    let env_config = if explicit.is_none() {
        env::var_os("SBH_CONFIG").map(PathBuf::from)
    } else {
        None
    };
    resolve_config_path_from(
        explicit,
        env_config.as_deref(),
        &default_paths.config_file,
        &system_config_file(),
        effective_uid_is_root(),
        allow_system_fallback,
    )
}

fn effective_uid_is_root() -> bool {
    #[cfg(unix)]
    {
        nix::unistd::Uid::effective().is_root()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Platform data directory of a system-scope service.
///
/// `/var/lib/sbh` on Linux, `/private/var/sbh` on macOS. Read-side CLI
/// commands use it to point an unprivileged operator at the daemon's real
/// activity database.
#[must_use]
pub fn system_data_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/private/var/sbh")
    }
    #[cfg(not(target_os = "macos"))]
    {
        PathBuf::from("/var/lib/sbh")
    }
}

fn default_update_metadata_cache_file(paths: &PathsConfig) -> PathBuf {
    data_dir_for_paths(paths).join("update-metadata.json")
}

fn data_dir_for_paths(paths: &PathsConfig) -> PathBuf {
    paths
        .state_file
        .parent()
        .map_or_else(system_data_dir, PathBuf::from)
}

fn apply_missing_path_defaults(
    paths: &mut PathsConfig,
    raw_value: &toml::Value,
    defaults: &PathsConfig,
) {
    if !raw_paths_contains_key(raw_value, "ballast_dir") {
        paths.ballast_dir.clone_from(&defaults.ballast_dir);
    }
    if !raw_paths_contains_key(raw_value, "state_file") {
        paths.state_file.clone_from(&defaults.state_file);
    }
    if !raw_paths_contains_key(raw_value, "sqlite_db") {
        paths.sqlite_db.clone_from(&defaults.sqlite_db);
    }
    if !raw_paths_contains_key(raw_value, "jsonl_log") {
        paths.jsonl_log.clone_from(&defaults.jsonl_log);
    }
}

fn raw_paths_contains_key(raw_value: &toml::Value, key: &str) -> bool {
    raw_value
        .get("paths")
        .and_then(toml::Value::as_table)
        .is_some_and(|paths| paths.contains_key(key))
}

impl Config {
    /// Build a default config with an explicit path layout.
    #[must_use]
    pub fn with_paths(paths: PathsConfig) -> Self {
        let mut config = Self::default();
        config.update.metadata_cache_file = default_update_metadata_cache_file(&paths);
        config.paths = paths;
        config
    }

    /// Default configuration path.
    #[must_use]
    pub fn default_path() -> PathBuf {
        PathsConfig::default().config_file
    }

    /// Load config using service-scope defaults when no explicit config path is given.
    pub fn load_for_service_scope(path: Option<&Path>, user_scope: bool) -> Result<Self> {
        Self::load_with_default_paths(path, PathsConfig::for_service_scope(user_scope), false)
    }

    /// The config file [`Config::load`] would read for this invocation, and
    /// why. `sbh config path` prints it; the two share one resolver.
    #[must_use]
    pub fn resolve_config_path(explicit: Option<&Path>) -> ResolvedConfigPath {
        resolve_config_path_with(explicit, &PathsConfig::default(), true)
    }

    /// Load config from default or explicit path, then apply env overrides.
    ///
    /// Resolution order for config file path:
    /// 1. Explicit `path` argument (from `--config` CLI flag)
    /// 2. `SBH_CONFIG` environment variable
    /// 3. Platform-native default path
    ///    - Linux/XDG: `~/.config/sbh/config.toml`
    ///    - macOS: `~/Library/Application Support/sbh/config.toml`
    ///      unless XDG env vars or an existing XDG config opt into XDG layout.
    /// 4. System fallback when no user/default config exists
    ///    - Linux: `/etc/sbh/config.toml`
    ///    - macOS: `/Library/Application Support/sbh/config.toml`
    ///
    /// Missing config file is not an error when loading from default path; defaults are used.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        Self::load_with_default_paths(path, PathsConfig::default(), true)
    }

    fn load_with_default_paths(
        path: Option<&Path>,
        default_paths: PathsConfig,
        allow_system_fallback: bool,
    ) -> Result<Self> {
        // Which file: `--config`, then `SBH_CONFIG`, then the implicit choice
        // (a regular user without a per-user config reads the system config so
        // `sbh status` sees what the service sees; root always prefers the
        // system config so `sudo sbh …` and the service agree on which ballast
        // pool is real). `sbh config path` prints this same resolution.
        let resolved = resolve_config_path_with(path, &default_paths, allow_system_fallback);
        let is_explicit_path = resolved.source.is_explicit();
        let is_system_fallback = resolved.source.is_system();
        if let Some(shadowed) = &resolved.shadowed_user_config {
            eprintln!(
                "[SBH-CONFIG] Running as root: using system config at {} \
                 (ignoring {}; pass --config to read that file instead)",
                resolved.path.display(),
                shadowed.display()
            );
        }
        let announce_system_fallback = resolved.source == ConfigPathSource::SystemFallback;
        let effective_path = resolved.path;

        let mut cfg = if effective_path.exists() {
            let raw = fs::read_to_string(&effective_path).map_err(|source| SbhError::Io {
                path: effective_path.clone(),
                source,
            })?;
            let raw_value: toml::Value = toml::from_str(&raw)?;
            let (mut parsed, unknown_keys) = parse_config_lenient(&raw)?;
            parsed.unknown_keys = unknown_keys;
            let system_path_defaults;
            let path_defaults = if is_system_fallback || effective_path == system_config_file() {
                system_path_defaults = PathsConfig::system_default();
                &system_path_defaults
            } else {
                &default_paths
            };
            apply_missing_path_defaults(&mut parsed.paths, &raw_value, path_defaults);
            if announce_system_fallback {
                eprintln!(
                    "[SBH-CONFIG] Using system config at {}",
                    effective_path.display()
                );
            }
            parsed
        } else if is_explicit_path {
            return Err(SbhError::MissingConfig {
                path: effective_path,
            });
        } else {
            Self::with_paths(default_paths)
        };

        cfg.paths.config_file = effective_path;
        cfg.apply_env_overrides()?;
        cfg.merge_sacred_config()?;
        cfg.normalize_paths();
        cfg.validate()?;
        Ok(cfg)
    }

    /// Deterministic hash of the effective config for logging/telemetry.
    ///
    /// Uses FNV-1a for cross-process-stable hashing (M11: no `DefaultHasher`
    /// whose seed may vary across Rust releases).
    pub fn stable_hash(&self) -> Result<String> {
        let canonical = serde_json::to_string(self)?;
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in canonical.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
        Ok(format!("{hash:016x}"))
    }

    #[allow(clippy::too_many_lines)]
    fn apply_env_overrides(&mut self) -> Result<()> {
        // pressure
        set_env_f64(
            "SBH_PRESSURE_GREEN_MIN_FREE_PCT",
            &mut self.pressure.green_min_free_pct,
        )?;
        set_env_f64(
            "SBH_PRESSURE_YELLOW_MIN_FREE_PCT",
            &mut self.pressure.yellow_min_free_pct,
        )?;
        set_env_f64(
            "SBH_PRESSURE_ORANGE_MIN_FREE_PCT",
            &mut self.pressure.orange_min_free_pct,
        )?;
        set_env_f64(
            "SBH_PRESSURE_RED_MIN_FREE_PCT",
            &mut self.pressure.red_min_free_pct,
        )?;
        set_env_u64(
            "SBH_PRESSURE_POLL_INTERVAL_MS",
            &mut self.pressure.poll_interval_ms,
        )?;
        set_env_u64(
            "SBH_PRESSURE_BEHAVIOR_HYSTERESIS_SECS",
            &mut self.pressure.behavior_hysteresis_secs,
        )?;

        // prediction
        set_env_bool(
            "SBH_PREDICTION_ENABLED",
            &mut self.pressure.prediction.enabled,
        )?;
        set_env_f64(
            "SBH_PREDICTION_ACTION_HORIZON_MINUTES",
            &mut self.pressure.prediction.action_horizon_minutes,
        )?;
        set_env_f64(
            "SBH_PREDICTION_WARNING_HORIZON_MINUTES",
            &mut self.pressure.prediction.warning_horizon_minutes,
        )?;
        set_env_f64(
            "SBH_PREDICTION_MIN_CONFIDENCE",
            &mut self.pressure.prediction.min_confidence,
        )?;
        set_env_u64(
            "SBH_PREDICTION_MIN_SAMPLES",
            &mut self.pressure.prediction.min_samples,
        )?;
        set_env_f64(
            "SBH_PREDICTION_IMMINENT_DANGER_MINUTES",
            &mut self.pressure.prediction.imminent_danger_minutes,
        )?;
        set_env_f64(
            "SBH_PREDICTION_CRITICAL_DANGER_MINUTES",
            &mut self.pressure.prediction.critical_danger_minutes,
        )?;

        // scanner
        set_env_u64(
            "SBH_SCANNER_MIN_FILE_AGE_MINUTES",
            &mut self.scanner.min_file_age_minutes,
        )?;
        self.apply_scanner_env_overrides_from(env_var)?;
        set_env_usize("SBH_SCANNER_MAX_DEPTH", &mut self.scanner.max_depth)?;
        set_env_usize("SBH_SCANNER_PARALLELISM", &mut self.scanner.parallelism)?;
        set_env_bool(
            "SBH_SCANNER_FOLLOW_SYMLINKS",
            &mut self.scanner.follow_symlinks,
        )?;
        set_env_bool("SBH_SCANNER_CROSS_DEVICES", &mut self.scanner.cross_devices)?;
        set_env_bool("SBH_SCANNER_DRY_RUN", &mut self.scanner.dry_run)?;
        set_env_usize(
            "SBH_SCANNER_MAX_DELETE_BATCH",
            &mut self.scanner.max_delete_batch,
        )?;
        set_env_u64(
            "SBH_SCANNER_REPEAT_DELETION_BASE_COOLDOWN_SECS",
            &mut self.scanner.repeat_deletion_base_cooldown_secs,
        )?;
        set_env_u64(
            "SBH_SCANNER_REPEAT_DELETION_MAX_COOLDOWN_SECS",
            &mut self.scanner.repeat_deletion_max_cooldown_secs,
        )?;
        set_env_u64(
            "SBH_SCANNER_MIN_RESCAN_INTERVAL_SECS",
            &mut self.scanner.min_rescan_interval_secs,
        )?;
        set_env_u8(
            "SBH_SCANNER_MAX_SCAN_DUTY_CYCLE_PCT",
            &mut self.scanner.max_scan_duty_cycle_pct,
        )?;
        set_env_u64(
            "SBH_SCANNER_ACTIVE_REFERENCE_CACHE_TTL_SECS",
            &mut self.scanner.active_reference_cache_ttl_secs,
        )?;
        set_env_u64(
            "SBH_SCANNER_ACTIVE_REFERENCE_MIN_SIZE_BYTES",
            &mut self.scanner.active_reference_min_size_bytes,
        )?;

        // scoring
        set_env_f64("SBH_SCORING_MIN_SCORE", &mut self.scoring.min_score)?;
        set_env_f64(
            "SBH_SCORING_LOCATION_WEIGHT",
            &mut self.scoring.location_weight,
        )?;
        set_env_f64("SBH_SCORING_NAME_WEIGHT", &mut self.scoring.name_weight)?;
        set_env_f64("SBH_SCORING_AGE_WEIGHT", &mut self.scoring.age_weight)?;
        set_env_f64("SBH_SCORING_SIZE_WEIGHT", &mut self.scoring.size_weight)?;
        set_env_f64(
            "SBH_SCORING_STRUCTURE_WEIGHT",
            &mut self.scoring.structure_weight,
        )?;
        set_env_f64(
            "SBH_SCORING_FALSE_POSITIVE_LOSS",
            &mut self.scoring.false_positive_loss,
        )?;
        set_env_f64(
            "SBH_SCORING_FALSE_NEGATIVE_LOSS",
            &mut self.scoring.false_negative_loss,
        )?;
        set_env_f64(
            "SBH_SCORING_CALIBRATION_FLOOR",
            &mut self.scoring.calibration_floor,
        )?;
        set_env_f64(
            "SBH_SCORING_POSTERIOR_FLOOR_DEFINITE",
            &mut self.scoring.posterior_floor_definite,
        )?;

        // telemetry
        set_env_u64(
            "SBH_TELEMETRY_FS_CACHE_TTL_MS",
            &mut self.telemetry.fs_cache_ttl_ms,
        )?;
        set_env_f64(
            "SBH_TELEMETRY_EWMA_BASE_ALPHA",
            &mut self.telemetry.ewma_base_alpha,
        )?;
        set_env_f64(
            "SBH_TELEMETRY_EWMA_MIN_ALPHA",
            &mut self.telemetry.ewma_min_alpha,
        )?;
        set_env_f64(
            "SBH_TELEMETRY_EWMA_MAX_ALPHA",
            &mut self.telemetry.ewma_max_alpha,
        )?;
        set_env_u64(
            "SBH_TELEMETRY_EWMA_MIN_SAMPLES",
            &mut self.telemetry.ewma_min_samples,
        )?;
        set_env_u64(
            "SBH_TELEMETRY_DAEMON_RSS_WARNING_BYTES",
            &mut self.telemetry.daemon_rss_warning_bytes,
        )?;
        set_env_u64(
            "SBH_TELEMETRY_DAEMON_RSS_HARD_LIMIT_BYTES",
            &mut self.telemetry.daemon_rss_hard_limit_bytes,
        )?;

        // update
        self.apply_update_env_overrides_from(env_var)?;

        // dashboard
        if let Some(raw) = env_var("SBH_DASHBOARD_MODE") {
            self.dashboard.mode =
                raw.parse::<DashboardMode>()
                    .map_err(|details| SbhError::ConfigParse {
                        context: "env",
                        details: format!("SBH_DASHBOARD_MODE={raw:?}: {details}"),
                    })?;
        }
        set_env_bool("SBH_DASHBOARD_KILL_SWITCH", &mut self.dashboard.kill_switch)?;

        // policy
        set_env_bool("SBH_POLICY_KILL_SWITCH", &mut self.policy.kill_switch)?;

        // behavior matrix (rollback: SBH_BEHAVIOR_PRESET=v0.5)
        if let Some(raw) = env_var("SBH_BEHAVIOR_PRESET") {
            self.behavior.preset =
                raw.parse::<BehaviorPreset>()
                    .map_err(|details| SbhError::ConfigParse {
                        context: "env",
                        details: format!("SBH_BEHAVIOR_PRESET={raw:?}: {details}"),
                    })?;
        }

        // system tuning (kernel writeback)
        set_env_bool(
            "SBH_SYSTEM_TUNING_WRITEBACK_ENABLED",
            &mut self.system_tuning.writeback_enabled,
        )?;
        set_env_bool(
            "SBH_SYSTEM_TUNING_WRITEBACK_AUTO_APPLY_ON_INSTALL",
            &mut self.system_tuning.writeback_auto_apply_on_install,
        )?;
        set_env_f64(
            "SBH_SYSTEM_TUNING_WRITEBACK_TARGET_DRAIN_SECS",
            &mut self.system_tuning.writeback_target_drain_secs,
        )?;
        set_env_u64(
            "SBH_SYSTEM_TUNING_WRITEBACK_HARD_RATIO",
            &mut self.system_tuning.writeback_hard_ratio,
        )?;
        set_env_u64(
            "SBH_SYSTEM_TUNING_WRITEBACK_MIN_BACKGROUND_BYTES",
            &mut self.system_tuning.writeback_min_background_bytes,
        )?;
        set_env_u64(
            "SBH_SYSTEM_TUNING_WRITEBACK_MAX_BACKGROUND_BYTES",
            &mut self.system_tuning.writeback_max_background_bytes,
        )?;
        set_env_bool(
            "SBH_SYSTEM_TUNING_WRITEBACK_BENCHMARK_ENABLED",
            &mut self.system_tuning.writeback_benchmark_enabled,
        )?;
        set_env_u64(
            "SBH_SYSTEM_TUNING_WRITEBACK_BENCHMARK_BYTES",
            &mut self.system_tuning.writeback_benchmark_bytes,
        )?;
        set_env_u64(
            "SBH_SYSTEM_TUNING_WRITEBACK_POOL_WARN_BYTES",
            &mut self.system_tuning.writeback_pool_warn_bytes,
        )?;

        Ok(())
    }

    fn apply_scanner_env_overrides_from<F>(&mut self, mut lookup: F) -> Result<()>
    where
        F: FnMut(&str) -> Option<String>,
    {
        if let Some(raw) = lookup("SBH_SCANNER_ENGINE") {
            self.scanner.engine =
                raw.parse::<ScannerEngineMode>()
                    .map_err(|details| SbhError::ConfigParse {
                        context: "env",
                        details: format!("SBH_SCANNER_ENGINE={raw:?}: {details}"),
                    })?;
        }
        if let Some(raw) = lookup("SBH_SCANNER_EVENT_SOURCE") {
            self.scanner.event_source =
                raw.parse::<ScannerEventSourceMode>()
                    .map_err(|details| SbhError::ConfigParse {
                        context: "env",
                        details: format!("SBH_SCANNER_EVENT_SOURCE={raw:?}: {details}"),
                    })?;
        }
        if let Some(raw) = lookup("SBH_SCANNER_EVENT_WATCH_BUDGET") {
            self.scanner.event_watch_budget =
                parse_env_usize("SBH_SCANNER_EVENT_WATCH_BUDGET", &raw)?;
        }

        Ok(())
    }

    fn apply_update_env_overrides_from<F>(&mut self, mut lookup: F) -> Result<()>
    where
        F: FnMut(&str) -> Option<String>,
    {
        if let Some(raw) = lookup("SBH_UPDATE_ENABLED") {
            self.update.enabled = parse_env_bool("SBH_UPDATE_ENABLED", &raw)?;
        }

        if let Some(raw) = lookup("SBH_UPDATE_METADATA_CACHE_TTL_SECONDS") {
            self.update.metadata_cache_ttl_seconds =
                parse_env_u64("SBH_UPDATE_METADATA_CACHE_TTL_SECONDS", &raw)?;
        }

        if let Some(raw) = lookup("SBH_UPDATE_METADATA_CACHE_FILE") {
            self.update.metadata_cache_file = PathBuf::from(raw);
        }

        if let Some(raw) = lookup("SBH_UPDATE_BACKGROUND_REFRESH") {
            self.update.background_refresh = parse_env_bool("SBH_UPDATE_BACKGROUND_REFRESH", &raw)?;
        }

        if let Some(raw) = lookup("SBH_UPDATE_NOTICES_ENABLED") {
            self.update.notices_enabled = parse_env_bool("SBH_UPDATE_NOTICES_ENABLED", &raw)?;
        }

        // Global opt-out: disables checks, background refresh, and update notices.
        if let Some(raw) = lookup("SBH_UPDATE_OPT_OUT")
            && parse_env_bool("SBH_UPDATE_OPT_OUT", &raw)?
        {
            self.update.enabled = false;
            self.update.background_refresh = false;
            self.update.notices_enabled = false;
        }

        Ok(())
    }

    /// Normalize paths for consistent comparison (M27).
    fn normalize_paths(&mut self) {
        // `~` and `$HOME` in path-typed fields: a literal `~` directory is
        // never what an operator meant.
        for path in [
            &mut self.paths.config_file,
            &mut self.paths.ballast_dir,
            &mut self.paths.state_file,
            &mut self.paths.sqlite_db,
            &mut self.paths.jsonl_log,
            &mut self.update.metadata_cache_file,
            &mut self.system_tuning.writeback_sysctl_path,
            &mut self.notifications.file.path,
        ] {
            *path = expand_home_path(path);
        }
        for path in self
            .scanner
            .root_paths
            .iter_mut()
            .chain(self.scanner.excluded_paths.iter_mut())
        {
            *path = expand_home_path(path);
        }
        for pattern in self
            .scanner
            .protected_paths
            .iter_mut()
            .chain(self.scanner.log_truncation.paths.iter_mut())
        {
            *pattern = expand_home_str(pattern);
        }

        // Strip trailing slashes from ballast override keys.
        // Uses BTreeMap for stable iteration order.
        let old_overrides = std::mem::take(&mut self.ballast.overrides);
        let normalized: BTreeMap<String, BallastVolumeOverride> = old_overrides
            .into_iter()
            .map(|(k, v)| {
                let key = strip_trailing_separator(&k).to_string();
                (key, v)
            })
            .collect();
        self.ballast.overrides = normalized;

        // Strip trailing slashes from scanner root_paths.
        for path in &mut self.scanner.root_paths {
            let s = path.to_string_lossy();
            // Don't strip if it looks like a root ("/" or "C:\").
            let is_unix_root = s.len() == 1;
            let is_win_root = s.len() == 3 && s.chars().nth(1) == Some(':');

            if !is_unix_root && !is_win_root {
                let stripped = strip_trailing_separator(&s);
                if stripped.len() != s.len() {
                    *path = PathBuf::from(stripped);
                }
            }
        }
    }

    /// Percent of a volume that must remain free after each ballast file is
    /// created: the Orange threshold, but never closer than two points to
    /// Red. A reserve is worth building only while the volume is still above
    /// the level at which the daemon starts reclaiming; below Red it is
    /// releasing, not reserving.
    #[must_use]
    pub fn ballast_provision_floor_pct(&self) -> f64 {
        self.pressure
            .orange_min_free_pct
            .max(self.pressure.red_min_free_pct + 2.0)
            .clamp(0.0, 100.0)
    }

    #[allow(clippy::too_many_lines)]
    fn validate(&self) -> Result<()> {
        // Behavior matrix: custom cell keys must name a real cell.
        BehaviorDispatchTable::from_config(&self.behavior).map_err(|details| {
            SbhError::InvalidConfig {
                details: format!("behavior: {details}"),
            }
        })?;

        // I31: Thresholds must be in 0.0..=100.0.
        for (name, val) in [
            ("green_min_free_pct", self.pressure.green_min_free_pct),
            ("yellow_min_free_pct", self.pressure.yellow_min_free_pct),
            ("orange_min_free_pct", self.pressure.orange_min_free_pct),
            ("red_min_free_pct", self.pressure.red_min_free_pct),
        ] {
            if !(0.0..=100.0).contains(&val) {
                return Err(SbhError::InvalidConfig {
                    details: format!("pressure.{name} must be in [0, 100], got {val}"),
                });
            }
        }

        if !(self.pressure.green_min_free_pct > self.pressure.yellow_min_free_pct
            && self.pressure.yellow_min_free_pct > self.pressure.orange_min_free_pct
            && self.pressure.orange_min_free_pct > self.pressure.red_min_free_pct)
        {
            return Err(SbhError::InvalidConfig {
                details: "pressure thresholds must strictly descend: green > yellow > orange > red"
                    .to_string(),
            });
        }

        // Prevent CPU spin from zero poll interval.
        if self.pressure.poll_interval_ms < 100 {
            return Err(SbhError::InvalidConfig {
                details: format!(
                    "pressure.poll_interval_ms must be >= 100, got {}",
                    self.pressure.poll_interval_ms
                ),
            });
        }

        if self.pressure.prediction.enabled {
            let pred = &self.pressure.prediction;

            // All horizon minutes must be positive (used in division/comparison).
            for (name, val) in [
                ("action_horizon_minutes", pred.action_horizon_minutes),
                ("warning_horizon_minutes", pred.warning_horizon_minutes),
                ("imminent_danger_minutes", pred.imminent_danger_minutes),
            ] {
                if val <= 0.0 {
                    return Err(SbhError::InvalidConfig {
                        details: format!("prediction.{name} must be > 0, got {val}"),
                    });
                }
            }

            if pred.warning_horizon_minutes <= pred.action_horizon_minutes {
                return Err(SbhError::InvalidConfig {
                    details: "prediction.warning_horizon_minutes must be > action_horizon_minutes"
                        .to_string(),
                });
            }
            if pred.action_horizon_minutes <= pred.imminent_danger_minutes {
                return Err(SbhError::InvalidConfig {
                    details: "prediction.action_horizon_minutes must be > imminent_danger_minutes"
                        .to_string(),
                });
            }
            if pred.imminent_danger_minutes <= pred.critical_danger_minutes {
                return Err(SbhError::InvalidConfig {
                    details: "prediction.imminent_danger_minutes must be > critical_danger_minutes"
                        .to_string(),
                });
            }
            if pred.critical_danger_minutes < 0.0 {
                return Err(SbhError::InvalidConfig {
                    details: "prediction.critical_danger_minutes must be >= 0".to_string(),
                });
            }
            validate_prob("prediction.min_confidence", pred.min_confidence)?;
        }

        if self.scanner.parallelism == 0 {
            return Err(SbhError::InvalidConfig {
                details: "scanner.parallelism must be >= 1".to_string(),
            });
        }
        if self.scanner.max_depth == 0 {
            return Err(SbhError::InvalidConfig {
                details: "scanner.max_depth must be >= 1".to_string(),
            });
        }
        if self.scanner.max_delete_batch == 0 {
            return Err(SbhError::InvalidConfig {
                details: "scanner.max_delete_batch must be >= 1".to_string(),
            });
        }
        if self.scanner.repeat_deletion_base_cooldown_secs == 0 {
            return Err(SbhError::InvalidConfig {
                details: "scanner.repeat_deletion_base_cooldown_secs must be >= 1".to_string(),
            });
        }
        if self.scanner.repeat_deletion_max_cooldown_secs == 0 {
            return Err(SbhError::InvalidConfig {
                details: "scanner.repeat_deletion_max_cooldown_secs must be >= 1".to_string(),
            });
        }
        if self.scanner.repeat_deletion_max_cooldown_secs
            < self.scanner.repeat_deletion_base_cooldown_secs
        {
            return Err(SbhError::InvalidConfig {
                details: "scanner.repeat_deletion_max_cooldown_secs must be >= scanner.repeat_deletion_base_cooldown_secs".to_string(),
            });
        }

        validate_prob("scoring.min_score", self.scoring.min_score)?;
        validate_prob("scoring.calibration_floor", self.scoring.calibration_floor)?;
        validate_prob(
            "scoring.posterior_floor_definite",
            self.scoring.posterior_floor_definite,
        )?;

        // I35: min_score must be <= calibration_floor.
        if self.scoring.min_score > self.scoring.calibration_floor {
            return Err(SbhError::InvalidConfig {
                details: format!(
                    "scoring.min_score ({}) must be <= scoring.calibration_floor ({})",
                    self.scoring.min_score, self.scoring.calibration_floor
                ),
            });
        }

        // I32: Individual scoring weights must be finite and non-negative.
        for (name, val) in [
            ("location_weight", self.scoring.location_weight),
            ("name_weight", self.scoring.name_weight),
            ("age_weight", self.scoring.age_weight),
            ("size_weight", self.scoring.size_weight),
            ("structure_weight", self.scoring.structure_weight),
        ] {
            if !val.is_finite() || val < 0.0 {
                return Err(SbhError::InvalidConfig {
                    details: format!("scoring.{name} must be a finite value >= 0.0, got {val}"),
                });
            }
        }

        // M13: Loss values must be finite and non-negative.
        if !self.scoring.false_positive_loss.is_finite()
            || !self.scoring.false_negative_loss.is_finite()
            || self.scoring.false_positive_loss < 0.0
            || self.scoring.false_negative_loss < 0.0
        {
            return Err(SbhError::InvalidConfig {
                details: "scoring.false_positive_loss and false_negative_loss must be finite values >= 0.0"
                    .to_string(),
            });
        }

        validate_prob(
            "scheduler.exploration_quota_fraction",
            self.scheduler.exploration_quota_fraction,
        )?;
        validate_prob("scheduler.ewma_alpha", self.scheduler.ewma_alpha)?;
        if self.scheduler.scan_budget_per_interval == 0 {
            return Err(SbhError::InvalidConfig {
                details: "scheduler.scan_budget_per_interval must be >= 1".to_string(),
            });
        }
        if self.scheduler.min_observations_for_forecast == 0 {
            return Err(SbhError::InvalidConfig {
                details: "scheduler.min_observations_for_forecast must be >= 1".to_string(),
            });
        }
        for (name, val) in [
            ("io_cost_weight", self.scheduler.io_cost_weight),
            ("fp_risk_weight", self.scheduler.fp_risk_weight),
            ("exploration_weight", self.scheduler.exploration_weight),
            (
                "forecast_error_threshold",
                self.scheduler.forecast_error_threshold,
            ),
        ] {
            if !val.is_finite() || val < 0.0 {
                return Err(SbhError::InvalidConfig {
                    details: format!("scheduler.{name} must be a finite value >= 0.0, got {val}"),
                });
            }
        }

        let sum = self.scoring.location_weight
            + self.scoring.name_weight
            + self.scoring.age_weight
            + self.scoring.size_weight
            + self.scoring.structure_weight;
        if (sum - 1.0).abs() > 1e-9 {
            return Err(SbhError::InvalidConfig {
                details: format!("scoring weights must sum to 1.0; got {sum:.6}"),
            });
        }

        if !(self.telemetry.ewma_min_alpha > 0.0
            && self.telemetry.ewma_min_alpha <= self.telemetry.ewma_base_alpha
            && self.telemetry.ewma_base_alpha <= self.telemetry.ewma_max_alpha
            && self.telemetry.ewma_max_alpha < 1.0)
        {
            return Err(SbhError::InvalidConfig {
                details: "EWMA alpha values must satisfy 0 < min <= base <= max < 1".to_string(),
            });
        }
        if self.telemetry.daemon_rss_warning_bytes == 0 {
            return Err(SbhError::InvalidConfig {
                details: "telemetry.daemon_rss_warning_bytes must be > 0".to_string(),
            });
        }
        if self.telemetry.daemon_rss_hard_limit_bytes == 0 {
            return Err(SbhError::InvalidConfig {
                details: "telemetry.daemon_rss_hard_limit_bytes must be > 0".to_string(),
            });
        }
        if self.telemetry.daemon_rss_warning_bytes > self.telemetry.daemon_rss_hard_limit_bytes {
            return Err(SbhError::InvalidConfig {
                details: "telemetry.daemon_rss_warning_bytes must be <= telemetry.daemon_rss_hard_limit_bytes"
                    .to_string(),
            });
        }

        if self.ballast.file_count == 0 || self.ballast.file_size_bytes == 0 {
            return Err(SbhError::InvalidConfig {
                details: "ballast.file_count and ballast.file_size_bytes must be > 0".to_string(),
            });
        }

        // BallastManager iterates file indices in a tight loop — absurdly large
        // counts cause hangs. Cap at 100_000 (with default 1 GiB file size =
        // 100 TiB of ballast, which is far beyond any realistic use).
        if self.ballast.file_count > 100_000 {
            return Err(SbhError::InvalidConfig {
                details: format!(
                    "ballast.file_count ({}) exceeds maximum (100000)",
                    self.ballast.file_count,
                ),
            });
        }

        // Ballast files need a 4096-byte header; anything smaller is unusable.
        if self.ballast.file_size_bytes < 4096 {
            return Err(SbhError::InvalidConfig {
                details: format!(
                    "ballast.file_size_bytes ({}) must be >= 4096 (header size)",
                    self.ballast.file_size_bytes,
                ),
            });
        }

        // Per-volume overrides must also satisfy the same constraints.
        for (mount, ovr) in &self.ballast.overrides {
            if let Some(count) = ovr.file_count {
                if count == 0 {
                    return Err(SbhError::InvalidConfig {
                        details: format!("ballast.overrides[\"{mount}\"].file_count must be > 0"),
                    });
                }
                if count > u32::MAX as usize {
                    return Err(SbhError::InvalidConfig {
                        details: format!(
                            "ballast.overrides[\"{mount}\"].file_count ({count}) exceeds maximum ({})",
                            u32::MAX,
                        ),
                    });
                }
            }
            if let Some(size) = ovr.file_size_bytes
                && size < 4096
            {
                return Err(SbhError::InvalidConfig {
                    details: format!(
                        "ballast.overrides[\"{mount}\"].file_size_bytes ({size}) must be >= 4096 (header size)"
                    ),
                });
            }
        }

        if self.update.metadata_cache_ttl_seconds == 0 {
            return Err(SbhError::InvalidConfig {
                details: "update.metadata_cache_ttl_seconds must be > 0".to_string(),
            });
        }

        if !self.update.enabled && self.update.background_refresh {
            return Err(SbhError::InvalidConfig {
                details: "update.background_refresh cannot be true when update.enabled=false"
                    .to_string(),
            });
        }

        // Validate protected_paths glob patterns are compilable.
        for pattern in &self.scanner.protected_paths {
            crate::scanner::protection::validate_glob_pattern(pattern)?;
        }

        // System tuning (kernel writeback).
        let tuning = &self.system_tuning;
        if !tuning.writeback_target_drain_secs.is_finite()
            || tuning.writeback_target_drain_secs <= 0.0
            || tuning.writeback_target_drain_secs > 30.0
        {
            return Err(SbhError::InvalidConfig {
                details: format!(
                    "system_tuning.writeback_target_drain_secs must be in (0, 30], got {}",
                    tuning.writeback_target_drain_secs
                ),
            });
        }
        // The hard limit (`vm.dirty_bytes`) must sit strictly above the background
        // limit, or the kernel silently halves the background threshold. Bound the
        // ratio so it can never collapse to the background limit (1) nor saturate
        // `vm.dirty_bytes` to an effectively-unlimited value.
        if tuning.writeback_hard_ratio < 2 || tuning.writeback_hard_ratio > 64 {
            return Err(SbhError::InvalidConfig {
                details: format!(
                    "system_tuning.writeback_hard_ratio must be in [2, 64], got {}",
                    tuning.writeback_hard_ratio
                ),
            });
        }
        if tuning.writeback_min_background_bytes < 4096 {
            return Err(SbhError::InvalidConfig {
                details: format!(
                    "system_tuning.writeback_min_background_bytes ({}) must be >= 4096",
                    tuning.writeback_min_background_bytes
                ),
            });
        }
        if tuning.writeback_max_background_bytes < tuning.writeback_min_background_bytes {
            return Err(SbhError::InvalidConfig {
                details: format!(
                    "system_tuning.writeback_max_background_bytes ({}) must be >= writeback_min_background_bytes ({})",
                    tuning.writeback_max_background_bytes, tuning.writeback_min_background_bytes
                ),
            });
        }
        if tuning.writeback_benchmark_bytes < 1024 * 1024 {
            return Err(SbhError::InvalidConfig {
                details: format!(
                    "system_tuning.writeback_benchmark_bytes ({}) must be >= 1 MiB",
                    tuning.writeback_benchmark_bytes
                ),
            });
        }
        if tuning.writeback_pool_warn_bytes == 0 {
            return Err(SbhError::InvalidConfig {
                details: "system_tuning.writeback_pool_warn_bytes must be > 0".to_string(),
            });
        }
        // `sysctl --system` only loads files matching `*.conf` on boot, so a path
        // without that suffix would apply at runtime yet silently fail to persist
        // across a reboot.
        if tuning
            .writeback_sysctl_path
            .extension()
            .and_then(|ext| ext.to_str())
            != Some("conf")
        {
            return Err(SbhError::InvalidConfig {
                details: format!(
                    "system_tuning.writeback_sysctl_path must end in .conf (sysctl loads only *.conf files), got {}",
                    tuning.writeback_sysctl_path.display()
                ),
            });
        }

        Ok(())
    }

    fn merge_sacred_config(&mut self) -> Result<()> {
        let sacred_path = sacred_config_path_for(&self.paths.config_file);
        let sacred = load_sacred_config(&sacred_path)?;
        for protected_path in sacred.protected_paths {
            if !self
                .scanner
                .protected_paths
                .iter()
                .any(|known| known == &protected_path)
            {
                self.scanner.protected_paths.push(protected_path);
            }
        }
        Ok(())
    }
}

#[must_use]
pub fn sacred_config_path_for(config_file: &Path) -> PathBuf {
    config_file.parent().map_or_else(
        || PathBuf::from(SACRED_CONFIG_FILENAME),
        |dir| dir.join(SACRED_CONFIG_FILENAME),
    )
}

pub fn load_sacred_config(path: &Path) -> Result<SacredConfig> {
    if !path.exists() {
        return Ok(SacredConfig::default());
    }

    let raw = fs::read_to_string(path).map_err(|source| SbhError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut sacred: SacredConfig = toml::from_str(&raw)?;
    sacred.normalize();
    Ok(sacred)
}

pub fn write_sacred_config(path: &Path, sacred: &SacredConfig) -> Result<()> {
    let mut normalized = sacred.clone();
    normalized.normalize();
    let raw = toml::to_string_pretty(&normalized).map_err(|source| SbhError::Serialization {
        context: "toml",
        details: source.to_string(),
    })?;

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|source| SbhError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    fs::write(path, raw).map_err(|source| SbhError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn validate_prob(name: &str, value: f64) -> Result<()> {
    if !(0.0..=1.0).contains(&value) {
        return Err(SbhError::InvalidConfig {
            details: format!("{name} must be in [0,1], got {value}"),
        });
    }
    Ok(())
}

fn env_var(name: &str) -> Option<String> {
    env::var(name).ok().filter(|raw| !raw.trim().is_empty())
}

fn set_env_f64(name: &str, slot: &mut f64) -> Result<()> {
    if let Some(raw) = env_var(name) {
        *slot = raw.parse::<f64>().map_err(|error| SbhError::ConfigParse {
            context: "env",
            details: format!("{name}={raw:?}: {error}"),
        })?;
    }
    Ok(())
}

fn set_env_u64(name: &str, slot: &mut u64) -> Result<()> {
    if let Some(raw) = env_var(name) {
        *slot = raw.parse::<u64>().map_err(|error| SbhError::ConfigParse {
            context: "env",
            details: format!("{name}={raw:?}: {error}"),
        })?;
    }
    Ok(())
}

fn set_env_u8(name: &str, slot: &mut u8) -> Result<()> {
    if let Some(raw) = env_var(name) {
        *slot = raw.parse::<u8>().map_err(|error| SbhError::ConfigParse {
            context: "env",
            details: format!("{name}={raw:?}: {error}"),
        })?;
    }
    Ok(())
}

fn set_env_usize(name: &str, slot: &mut usize) -> Result<()> {
    if let Some(raw) = env_var(name) {
        *slot = raw
            .parse::<usize>()
            .map_err(|error| SbhError::ConfigParse {
                context: "env",
                details: format!("{name}={raw:?}: {error}"),
            })?;
    }
    Ok(())
}

fn set_env_bool(name: &str, slot: &mut bool) -> Result<()> {
    if let Some(raw) = env_var(name) {
        *slot = parse_env_bool(name, &raw)?;
    }
    Ok(())
}

fn parse_env_u64(name: &str, raw: &str) -> Result<u64> {
    raw.parse::<u64>().map_err(|error| SbhError::ConfigParse {
        context: "env",
        details: format!("{name}={raw:?}: {error}"),
    })
}

fn parse_env_usize(name: &str, raw: &str) -> Result<usize> {
    raw.parse::<usize>().map_err(|error| SbhError::ConfigParse {
        context: "env",
        details: format!("{name}={raw:?}: {error}"),
    })
}

fn parse_env_bool(name: &str, raw: &str) -> Result<bool> {
    raw.parse::<bool>().map_err(|error| SbhError::ConfigParse {
        context: "env",
        details: format!("{name}={raw:?}: {error}"),
    })
}

fn strip_trailing_separator(s: &str) -> &str {
    s.strip_suffix('/')
        .or_else(|| s.strip_suffix('\\'))
        .unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::{
        BehaviorPreset, Config, PathsConfig, SacredConfig, SbhError, ScannerEngineMode,
        load_sacred_config, sacred_config_path_for, write_sacred_config,
    };
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    fn vars(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn default_config_is_valid() {
        let cfg = Config::default();
        assert!(cfg.validate().is_ok());
    }

    /// The ballast headroom floor follows the pressure thresholds instead of
    /// a fixed 20%: provisioning may take a volume down to Orange but never
    /// into Red (kept two points above it).
    #[test]
    fn ballast_provision_floor_tracks_pressure_thresholds() {
        let mut cfg = Config::default();
        assert!((cfg.ballast_provision_floor_pct() - 10.0).abs() < f64::EPSILON);

        cfg.pressure.orange_min_free_pct = 7.0;
        cfg.pressure.red_min_free_pct = 6.0;
        assert!((cfg.ballast_provision_floor_pct() - 8.0).abs() < f64::EPSILON);

        cfg.pressure.orange_min_free_pct = 30.0;
        cfg.pressure.red_min_free_pct = 5.0;
        assert!((cfg.ballast_provision_floor_pct() - 30.0).abs() < f64::EPSILON);
    }

    #[test]
    fn scoring_posterior_floor_definite_defaults_parses_and_validates() {
        let cfg = Config::default();
        assert!((cfg.scoring.posterior_floor_definite - 0.85).abs() < f64::EPSILON);

        let parsed: Config = toml::from_str("[scoring]\nposterior_floor_definite = 0.9\n")
            .expect("floor should parse");
        assert!((parsed.scoring.posterior_floor_definite - 0.9).abs() < f64::EPSILON);
        assert!(parsed.validate().is_ok());

        let mut bad = Config::default();
        bad.scoring.posterior_floor_definite = 1.5;
        let err = bad
            .validate()
            .expect_err("floor above 1.0 must be rejected");
        assert!(err.to_string().contains("posterior_floor_definite"));
    }

    #[test]
    fn behavior_preset_env_override_and_custom_cell_validation() {
        let mut cfg = Config::default();
        assert_eq!(cfg.behavior.preset, BehaviorPreset::V0_6);
        assert!(cfg.behavior.memory_never_reduces_cleanup);

        let parsed: Config = toml::from_str(
            "[behavior]\npreset = \"custom\"\n[behavior.cells.normal_orange]\nscan = \"aggressive\"\ncleanup = \"identify_only\"\nballast = \"none\"\nnotify = \"low\"\n",
        )
        .expect("custom behavior config should parse");
        assert_eq!(parsed.behavior.preset, BehaviorPreset::Custom);
        assert!(parsed.validate().is_ok());

        cfg.behavior.preset = BehaviorPreset::Custom;
        cfg.behavior.cells.insert(
            "normal_purple".to_string(),
            parsed.behavior.cells["normal_orange"],
        );
        let err = cfg
            .validate()
            .expect_err("unknown disk level must be rejected");
        assert!(err.to_string().contains("normal_purple"), "{err}");

        let mut env_cfg = Config::default();
        env_cfg
            .apply_scanner_env_overrides_from(|_| None)
            .expect("no-op");
        // The env parser is the same FromStr the daemon uses.
        assert_eq!(
            "v0.5".parse::<BehaviorPreset>().expect("parses"),
            BehaviorPreset::V0_5
        );
        assert!(
            toml::from_str::<Config>("[behavior]\npreset = \"v9\"\n").is_err(),
            "unknown preset must fail to parse"
        );
    }

    #[test]
    fn pressure_behavior_hysteresis_defaults_and_toml_override() {
        let cfg = Config::default();
        assert_eq!(cfg.pressure.behavior_hysteresis_secs, 5);

        let toml_str = "[pressure]\nbehavior_hysteresis_secs = 9\n";
        let parsed: Config = toml::from_str(toml_str).expect("should parse");
        assert_eq!(parsed.pressure.behavior_hysteresis_secs, 9);
    }

    #[test]
    fn macos_native_paths_use_application_support() {
        let home = Path::new("/Users/operator");
        let paths = PathsConfig::macos_native_for_home(home);

        let app_support = home.join("Library").join("Application Support").join("sbh");
        assert_eq!(paths.config_file, app_support.join("config.toml"));
        assert_eq!(paths.ballast_dir, app_support.join("ballast.bin"));
        assert_eq!(paths.state_file, app_support.join("state.json"));
        assert_eq!(paths.sqlite_db, app_support.join("activity.sqlite3"));
        assert_eq!(paths.jsonl_log, app_support.join("activity.jsonl"));
    }

    #[test]
    fn xdg_paths_preserve_linux_and_opt_in_layout() {
        let home = Path::new("/home/operator");
        let paths = PathsConfig::xdg_for_home(home);

        assert_eq!(
            paths.config_file,
            home.join(".config").join("sbh").join("config.toml")
        );
        assert_eq!(
            paths.state_file,
            home.join(".local")
                .join("share")
                .join("sbh")
                .join("state.json")
        );
    }

    #[test]
    fn system_default_paths_follow_platform_scope() {
        let paths = PathsConfig::system_default();

        #[cfg(target_os = "macos")]
        {
            assert_eq!(
                paths.config_file,
                PathBuf::from("/Library/Application Support/sbh/config.toml")
            );
            assert_eq!(
                paths.state_file,
                PathBuf::from("/private/var/sbh/state.json")
            );
            assert_eq!(
                paths.ballast_dir,
                PathBuf::from("/private/var/sbh/ballast.bin")
            );
        }

        #[cfg(target_os = "linux")]
        {
            assert_eq!(paths.config_file, PathBuf::from("/etc/sbh/config.toml"));
            assert_eq!(paths.state_file, PathBuf::from("/var/lib/sbh/state.json"));
            assert_eq!(paths.ballast_dir, PathBuf::from("/var/lib/sbh/ballast"));
        }
    }

    #[test]
    fn root_prefers_system_config_whenever_it_exists() {
        use super::{ImplicitConfigChoice, choose_implicit_config};
        // The sudo/system-service identity must resolve the same file the
        // unprivileged CLI falls back to, even when root has a per-user config.
        assert_eq!(
            choose_implicit_config(true, true, true),
            ImplicitConfigChoice::SystemForRoot {
                shadowed_user_config: true
            }
        );
        assert_eq!(
            choose_implicit_config(true, false, true),
            ImplicitConfigChoice::SystemForRoot {
                shadowed_user_config: false
            }
        );
        // Without a system config root behaves like any user.
        assert_eq!(
            choose_implicit_config(true, true, false),
            ImplicitConfigChoice::User
        );
        assert_eq!(
            choose_implicit_config(true, false, false),
            ImplicitConfigChoice::User
        );
    }

    #[test]
    fn unprivileged_user_config_still_wins_over_system_config() {
        use super::{ImplicitConfigChoice, choose_implicit_config};
        assert_eq!(
            choose_implicit_config(false, true, true),
            ImplicitConfigChoice::User
        );
        assert_eq!(
            choose_implicit_config(false, false, true),
            ImplicitConfigChoice::SystemFallback
        );
        assert_eq!(
            choose_implicit_config(false, false, false),
            ImplicitConfigChoice::User
        );
    }

    #[test]
    fn unknown_keys_are_collected_with_suggestions_and_the_rest_still_loads() {
        use super::parse_config_lenient;
        let raw = "[monitor]\nsample_interval_seconds = 2\n\n\
                   [scanner]\nmax_dpeth = 3\nparallelism = 2\n\n\
                   [scoring.weights]\nlocation = 0.25\n\n\
                   [ballast]\nper_volume_file_count = 5\nper_volume_file_size_mb = 1024\nfile_count = 3\n\n\
                   [policy]\nmode = \"observe\"\n";
        let (config, unknown) = parse_config_lenient(raw).expect("lenient parse succeeds");
        assert_eq!(
            config.scanner.parallelism, 2,
            "known keys next to unknown ones still apply"
        );
        assert_eq!(config.ballast.file_count, 3);

        let paths: Vec<&str> = unknown.iter().map(|k| k.path.as_str()).collect();
        for expected in [
            "monitor",
            "scanner.max_dpeth",
            "scoring.weights",
            "ballast.per_volume_file_count",
            "ballast.per_volume_file_size_mb",
            "policy.mode",
        ] {
            assert!(paths.contains(&expected), "missing {expected} in {paths:?}");
        }
        let suggestion = |path: &str| {
            unknown
                .iter()
                .find(|k| k.path == path)
                .and_then(|k| k.suggestion.clone())
                .unwrap_or_default()
        };
        assert!(
            suggestion("scanner.max_dpeth").contains("max_depth"),
            "{}",
            suggestion("scanner.max_dpeth")
        );
        assert!(suggestion("monitor").contains("[pressure]"));
        assert!(suggestion("ballast.per_volume_file_size_mb").contains("file_size_bytes"));
        assert!(suggestion("policy.mode").contains("initial_mode"));
        assert!(suggestion("scoring.weights").contains("location_weight"));

        // The same text refuses a strict parse: unknown keys are never silent.
        assert!(toml::from_str::<Config>(raw).is_err());
        // A genuinely malformed file is still an error, not an "unknown key".
        assert!(parse_config_lenient("[scanner]\nparallelism = \"two\"\n").is_err());
    }

    #[test]
    fn config_load_reports_unknown_keys_without_failing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[scanner]\nparalellism = 2\nmax_depth = 4\n").unwrap();
        let config = Config::load(Some(&path)).expect("load stays lenient");
        assert_eq!(config.scanner.max_depth, 4);
        assert_eq!(config.unknown_keys.len(), 1);
        assert_eq!(config.unknown_keys[0].path, "scanner.paralellism");
        assert_eq!(
            config.unknown_keys[0].suggestion.as_deref(),
            Some("did you mean `parallelism`?")
        );
        assert!(!config.core.strict_config, "strict mode is opt-in");
        // The hash and serialized form ignore the diagnostics.
        assert!(!toml::to_string(&config).unwrap().contains("unknown_keys"));
    }

    #[test]
    fn parse_unknown_field_error_handles_both_serde_forms() {
        use super::{levenshtein, parse_unknown_field_error};
        let (field, expected) = parse_unknown_field_error(
            "TOML parse error at line 1, column 1\n  |\n1 | [x]\n  | ^^^\nunknown field `x`, expected one of `a`, `b_c`, `d`\n",
        )
        .unwrap();
        assert_eq!(field, "x");
        assert_eq!(expected, vec!["a", "b_c", "d"]);
        let (field, expected) =
            parse_unknown_field_error("unknown field `only`, expected `single`").unwrap();
        assert_eq!(
            (field.as_str(), expected),
            ("only", vec!["single".to_string()])
        );
        assert!(parse_unknown_field_error("invalid type: string, expected integer").is_none());
        assert_eq!(levenshtein("max_dpeth", "max_depth"), 2);
        assert_eq!(levenshtein("", "abc"), 3);
    }

    #[test]
    fn home_expansion_applies_to_path_fields() {
        use super::expand_home_str;
        let Ok(home) = std::env::var("HOME") else {
            return;
        };
        let home = home.trim_end_matches('/').to_string();
        assert_eq!(expand_home_str("~/x"), format!("{home}/x"));
        assert_eq!(expand_home_str("$HOME/y"), format!("{home}/y"));
        assert_eq!(expand_home_str("${HOME}"), home);
        assert_eq!(expand_home_str("/abs/~/not"), "/abs/~/not");
        let mut config = Config::default();
        config.notifications.file.path = PathBuf::from("~/n.jsonl");
        config.scanner.root_paths = vec![PathBuf::from("$HOME/projects/")];
        config.scanner.protected_paths = vec!["~/keep-*".to_string()];
        config.normalize_paths();
        assert_eq!(
            config.notifications.file.path,
            PathBuf::from(format!("{home}/n.jsonl"))
        );
        assert_eq!(
            config.scanner.root_paths,
            vec![PathBuf::from(format!("{home}/projects"))]
        );
        assert_eq!(
            config.scanner.protected_paths,
            vec![format!("{home}/keep-*")]
        );
    }

    /// The README's configuration example is parsed here, so it cannot drift
    /// from the declared keys again (it once had six sections nobody read).
    #[test]
    fn readme_configuration_example_has_no_unknown_keys() {
        use super::parse_config_lenient;
        let readme = include_str!("../../README.md");
        let section = readme
            .find("## Configuration Example")
            .map(|start| &readme[start..])
            .expect("README has a Configuration Example section");
        let open = section.find("```toml").expect("toml block") + "```toml".len();
        let close = section[open..].find("```").expect("block end");
        let example = &section[open..open + close];
        let (config, unknown) = parse_config_lenient(example).expect("README example parses");
        assert!(
            unknown.is_empty(),
            "README example uses keys the config does not declare: {unknown:?}"
        );
        config.validate().expect("README example passes validation");
        assert_eq!(config.ballast.file_count, 5);
        assert!(!config.policy.kill_switch);
    }

    #[test]
    fn resolve_config_path_reports_source_and_reason() {
        use super::{ConfigPathSource, resolve_config_path_from};
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("user.toml");
        let system = dir.path().join("system.toml");
        let explicit = dir.path().join("explicit.toml");

        // --config wins even when the file is absent (its absence is an error later).
        let r = resolve_config_path_from(Some(&explicit), Some(&user), &user, &system, true, true);
        assert_eq!(
            (r.source, r.exists, &r.path),
            (ConfigPathSource::Explicit, false, &explicit)
        );
        assert!(r.source.is_explicit() && !r.source.is_system());

        // SBH_CONFIG next.
        let r = resolve_config_path_from(None, Some(&explicit), &user, &system, false, true);
        assert_eq!((r.source, &r.path), (ConfigPathSource::Env, &explicit));

        // Nothing on disk: the default path, built-in defaults.
        let r = resolve_config_path_from(None, None, &user, &system, false, true);
        assert_eq!(
            (r.source, r.exists, &r.path),
            (ConfigPathSource::Default, false, &user)
        );
        assert!(r.reason.contains("built-in defaults"), "{}", r.reason);

        // Only a system config: an unprivileged user falls back to it.
        std::fs::write(&system, "").unwrap();
        let r = resolve_config_path_from(None, None, &user, &system, false, true);
        assert_eq!(
            (r.source, r.exists, &r.path),
            (ConfigPathSource::SystemFallback, true, &system)
        );
        assert!(r.source.is_system());
        assert!(
            r.reason.contains(&user.display().to_string()),
            "{}",
            r.reason
        );

        // A per-user config wins for an unprivileged user...
        std::fs::write(&user, "").unwrap();
        let r = resolve_config_path_from(None, None, &user, &system, false, true);
        assert_eq!((r.source, &r.path), (ConfigPathSource::Default, &user));
        // ...but root reads the system config and reports the shadowed file.
        let r = resolve_config_path_from(None, None, &user, &system, true, true);
        assert_eq!(
            (r.source, &r.path),
            (ConfigPathSource::SystemForRoot, &system)
        );
        assert_eq!(r.shadowed_user_config.as_deref(), Some(user.as_path()));

        // Service-scope loads never fall back.
        let r = resolve_config_path_from(None, None, &user, &system, true, false);
        assert_eq!(r.source, ConfigPathSource::Default);
        assert!(r.shadowed_user_config.is_none());
    }

    #[test]
    fn service_scope_defaults_use_system_paths_for_system_services() {
        let paths = PathsConfig::for_service_scope(false);
        assert_eq!(paths, PathsConfig::system_default());
    }

    #[test]
    fn config_with_paths_keeps_update_cache_in_same_data_dir() {
        let paths = PathsConfig {
            config_file: PathBuf::from("/tmp/sbh/config.toml"),
            ballast_dir: PathBuf::from("/tmp/sbh/ballast"),
            state_file: PathBuf::from("/tmp/sbh/state.json"),
            sqlite_db: PathBuf::from("/tmp/sbh/activity.sqlite3"),
            jsonl_log: PathBuf::from("/tmp/sbh/activity.jsonl"),
        };

        let cfg = Config::with_paths(paths);

        assert_eq!(
            cfg.update.metadata_cache_file,
            PathBuf::from("/tmp/sbh/update-metadata.json")
        );
    }

    #[test]
    fn load_with_scoped_defaults_fills_missing_paths_from_scope() {
        let tmp = TempDir::new().expect("tempdir");
        let config_path = tmp.path().join("config.toml");
        std::fs::write(&config_path, "[ballast]\nfile_count = 3\n").expect("write config");
        let scoped_paths = PathsConfig {
            config_file: config_path.clone(),
            ballast_dir: tmp.path().join("system").join("ballast.bin"),
            state_file: tmp.path().join("system").join("state.json"),
            sqlite_db: tmp.path().join("system").join("activity.sqlite3"),
            jsonl_log: tmp.path().join("system").join("activity.jsonl"),
        };

        let cfg = Config::load_with_default_paths(Some(&config_path), scoped_paths.clone(), false)
            .expect("config should load");

        assert_eq!(cfg.ballast.file_count, 3);
        assert_eq!(cfg.paths.config_file, config_path);
        assert_eq!(cfg.paths.ballast_dir, scoped_paths.ballast_dir);
        assert_eq!(cfg.paths.state_file, scoped_paths.state_file);
        assert_eq!(cfg.paths.sqlite_db, scoped_paths.sqlite_db);
        assert_eq!(cfg.paths.jsonl_log, scoped_paths.jsonl_log);
    }

    #[test]
    fn scanner_active_reference_defaults_bound_expensive_probes() {
        let cfg = Config::default();
        assert_eq!(cfg.scanner.active_reference_cache_ttl_secs, 30);
        assert_eq!(
            cfg.scanner.active_reference_min_size_bytes,
            100 * 1024 * 1024
        );
    }

    #[test]
    fn scanner_engine_defaults_to_v2_and_parses_toml() {
        let cfg = Config::default();
        assert_eq!(cfg.scanner.engine, ScannerEngineMode::V2);

        // v1 remains explicitly selectable for operators who want the legacy
        // full-descent walker.
        let parsed: Config =
            toml::from_str("[scanner]\nengine = \"v1\"\n").expect("scanner engine should parse");
        assert_eq!(parsed.scanner.engine, ScannerEngineMode::V1);

        let shown = toml::to_string_pretty(&parsed).expect("config should serialize");
        assert!(shown.contains("engine = \"v1\""));
    }

    #[test]
    fn scanner_engine_rejects_invalid_toml() {
        let err = toml::from_str::<Config>("[scanner]\nengine = \"v3\"\n")
            .expect_err("invalid scanner engine should fail parsing");

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn scanner_engine_env_override_parses() {
        let mut cfg = Config::default();
        let overrides = vars(&[("SBH_SCANNER_ENGINE", "v2")]);

        cfg.apply_scanner_env_overrides_from(|name| overrides.get(name).cloned())
            .expect("scanner env override should parse");

        assert_eq!(cfg.scanner.engine, ScannerEngineMode::V2);
    }

    #[test]
    fn scanner_engine_invalid_env_override_is_rejected() {
        let mut cfg = Config::default();
        let overrides = vars(&[("SBH_SCANNER_ENGINE", "evented")]);

        let err = cfg
            .apply_scanner_env_overrides_from(|name| overrides.get(name).cloned())
            .expect_err("invalid scanner engine should fail");
        match err {
            SbhError::ConfigParse { context, details } => {
                assert_eq!(context, "env");
                assert!(details.contains("SBH_SCANNER_ENGINE"));
                assert!(details.contains("expected \"v1\" or \"v2\""));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn scoring_weights_must_sum_to_one() {
        let mut cfg = Config::default();
        cfg.scoring.location_weight = 0.9;
        cfg.scoring.name_weight = 0.9;
        let err = cfg.validate().expect_err("expected invalid weights");
        match err {
            SbhError::InvalidConfig { details } => {
                assert!(details.contains("sum to 1.0"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn stable_hash_changes_when_config_changes() {
        let cfg = Config::default();
        let hash_before = cfg.stable_hash().expect("hash should compute");
        let mut modified = Config::default();
        modified.scanner.max_depth += 1;
        let hash_after = modified.stable_hash().expect("hash should compute");
        assert_ne!(hash_before, hash_after);
    }

    #[test]
    fn pressure_thresholds_must_descend() {
        let mut cfg = Config::default();
        cfg.pressure.yellow_min_free_pct = cfg.pressure.green_min_free_pct + 1.0;
        let err = cfg.validate().expect_err("expected validation error");
        assert!(err.to_string().contains("strictly descend"));
    }

    #[test]
    fn ewma_alpha_ordering_enforced() {
        let mut cfg = Config::default();
        cfg.telemetry.ewma_min_alpha = 0.9;
        cfg.telemetry.ewma_base_alpha = 0.1;
        let err = cfg.validate().expect_err("expected alpha validation error");
        assert!(err.to_string().contains("alpha"));
    }

    #[test]
    fn daemon_rss_hard_limit_defaults_to_500_mib() {
        let cfg = Config::default();
        assert_eq!(cfg.telemetry.daemon_rss_warning_bytes, 256 * 1024 * 1024);
        assert_eq!(cfg.telemetry.daemon_rss_hard_limit_bytes, 500 * 1024 * 1024);
    }

    #[test]
    fn daemon_rss_hard_limit_must_not_be_below_warning_limit() {
        let mut cfg = Config::default();
        cfg.telemetry.daemon_rss_warning_bytes = 1024;
        cfg.telemetry.daemon_rss_hard_limit_bytes = 512;
        let err = cfg
            .validate()
            .expect_err("expected daemon rss threshold validation error");
        assert!(
            err.to_string()
                .contains("daemon_rss_warning_bytes must be <=")
        );
    }

    #[test]
    fn min_observations_for_forecast_zero_rejected() {
        let mut cfg = Config::default();
        cfg.scheduler.min_observations_for_forecast = 0;
        let err = cfg
            .validate()
            .expect_err("expected min_observations validation error");
        assert!(err.to_string().contains("min_observations_for_forecast"));
    }

    #[test]
    fn ballast_zero_count_rejected() {
        let mut cfg = Config::default();
        cfg.ballast.file_count = 0;
        let err = cfg
            .validate()
            .expect_err("expected ballast validation error");
        assert!(err.to_string().contains("ballast"));
    }

    #[test]
    fn update_zero_cache_ttl_rejected() {
        let mut cfg = Config::default();
        cfg.update.metadata_cache_ttl_seconds = 0;
        let err = cfg
            .validate()
            .expect_err("expected update ttl validation error");
        assert!(err.to_string().contains("metadata_cache_ttl_seconds"));
    }

    #[test]
    fn update_disabled_disallows_background_refresh() {
        let mut cfg = Config::default();
        cfg.update.enabled = false;
        cfg.update.background_refresh = true;
        let err = cfg
            .validate()
            .expect_err("expected update background refresh validation error");
        assert!(err.to_string().contains("background_refresh"));
    }

    #[test]
    fn update_default_cache_file_name_is_stable() {
        let cfg = Config::default();
        assert!(
            cfg.update
                .metadata_cache_file
                .to_string_lossy()
                .ends_with("update-metadata.json")
        );
    }

    #[test]
    fn update_env_opt_out_disables_all_update_controls() {
        let mut cfg = Config::default();
        let overrides = vars(&[
            ("SBH_UPDATE_ENABLED", "true"),
            ("SBH_UPDATE_BACKGROUND_REFRESH", "true"),
            ("SBH_UPDATE_NOTICES_ENABLED", "true"),
            ("SBH_UPDATE_OPT_OUT", "true"),
        ]);

        cfg.apply_update_env_overrides_from(|name| overrides.get(name).cloned())
            .expect("update env overrides should parse");

        assert!(!cfg.update.enabled);
        assert!(!cfg.update.background_refresh);
        assert!(!cfg.update.notices_enabled);
    }

    #[test]
    fn update_env_cache_fields_override_defaults() {
        let mut cfg = Config::default();
        let overrides = vars(&[
            ("SBH_UPDATE_METADATA_CACHE_TTL_SECONDS", "7200"),
            (
                "SBH_UPDATE_METADATA_CACHE_FILE",
                "/tmp/sbh/custom-update-metadata.json",
            ),
        ]);

        cfg.apply_update_env_overrides_from(|name| overrides.get(name).cloned())
            .expect("update env overrides should parse");

        assert_eq!(cfg.update.metadata_cache_ttl_seconds, 7_200);
        assert_eq!(
            cfg.update.metadata_cache_file,
            std::path::PathBuf::from("/tmp/sbh/custom-update-metadata.json")
        );
    }

    #[test]
    fn update_env_invalid_boolean_rejected() {
        let mut cfg = Config::default();
        let overrides = vars(&[("SBH_UPDATE_NOTICES_ENABLED", "yes-please")]);

        let err = cfg
            .apply_update_env_overrides_from(|name| overrides.get(name).cloned())
            .expect_err("invalid bool should fail");
        match err {
            SbhError::ConfigParse { context, details } => {
                assert_eq!(context, "env");
                assert!(details.contains("SBH_UPDATE_NOTICES_ENABLED"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn scanner_zero_parallelism_rejected() {
        let mut cfg = Config::default();
        cfg.scanner.parallelism = 0;
        let err = cfg.validate().expect_err("expected parallelism error");
        assert!(err.to_string().contains("parallelism"));
    }

    #[test]
    fn scanner_repeat_deletion_base_cooldown_must_be_positive() {
        let mut cfg = Config::default();
        cfg.scanner.repeat_deletion_base_cooldown_secs = 0;
        let err = cfg.validate().expect_err("expected base cooldown error");
        assert!(
            err.to_string()
                .contains("repeat_deletion_base_cooldown_secs")
        );
    }

    #[test]
    fn scanner_repeat_deletion_max_cooldown_must_be_positive() {
        let mut cfg = Config::default();
        cfg.scanner.repeat_deletion_max_cooldown_secs = 0;
        let err = cfg.validate().expect_err("expected max cooldown error");
        assert!(
            err.to_string()
                .contains("repeat_deletion_max_cooldown_secs")
        );
    }

    #[test]
    fn system_tuning_defaults_are_valid() {
        assert!(Config::default().validate().is_ok());
    }

    #[test]
    fn system_tuning_hard_ratio_must_be_in_range() {
        // 1 would make the background limit equal the hard limit (kernel halves it).
        let mut low = Config::default();
        low.system_tuning.writeback_hard_ratio = 1;
        let err = low.validate().expect_err("expected hard_ratio error");
        assert!(err.to_string().contains("writeback_hard_ratio"));

        // An absurd ratio would saturate vm.dirty_bytes to an unlimited value.
        let mut high = Config::default();
        high.system_tuning.writeback_hard_ratio = 65;
        let err = high.validate().expect_err("expected hard_ratio error");
        assert!(err.to_string().contains("writeback_hard_ratio"));
    }

    #[test]
    fn system_tuning_max_background_must_not_be_below_min() {
        let mut cfg = Config::default();
        cfg.system_tuning.writeback_min_background_bytes = 2 * 1024 * 1024 * 1024;
        cfg.system_tuning.writeback_max_background_bytes = 256 * 1024 * 1024;
        let err = cfg.validate().expect_err("expected max<min error");
        assert!(err.to_string().contains("writeback_max_background_bytes"));
    }

    #[test]
    fn system_tuning_drain_secs_must_be_in_range() {
        let mut cfg = Config::default();
        cfg.system_tuning.writeback_target_drain_secs = 0.0;
        let err = cfg.validate().expect_err("expected drain_secs error");
        assert!(err.to_string().contains("writeback_target_drain_secs"));
    }

    #[test]
    fn system_tuning_sysctl_path_must_end_in_conf() {
        let mut cfg = Config::default();
        // sysctl only loads *.conf on boot; a non-.conf path would not persist.
        cfg.system_tuning.writeback_sysctl_path = PathBuf::from("/etc/sysctl.d/99-sbh-writeback");
        let err = cfg.validate().expect_err("expected sysctl_path error");
        assert!(err.to_string().contains("writeback_sysctl_path"));
    }

    #[test]
    fn scanner_repeat_deletion_max_cooldown_must_not_be_lower_than_base() {
        let mut cfg = Config::default();
        cfg.scanner.repeat_deletion_base_cooldown_secs = 600;
        cfg.scanner.repeat_deletion_max_cooldown_secs = 60;
        let err = cfg
            .validate()
            .expect_err("expected cooldown ordering validation error");
        assert!(err.to_string().contains("must be >="));
    }

    #[test]
    fn scoring_min_score_out_of_range_rejected() {
        let mut cfg = Config::default();
        cfg.scoring.min_score = 2.0;
        let err = cfg.validate().expect_err("expected min_score error");
        assert!(err.to_string().contains("min_score"));
    }

    #[test]
    fn ballast_volume_override_effective_file_count() {
        use super::BallastConfig;
        use std::collections::BTreeMap;
        let mut overrides = BTreeMap::new();
        overrides.insert(
            "/data".to_string(),
            super::BallastVolumeOverride {
                enabled: true,
                file_count: Some(20),
                file_size_bytes: None,
            },
        );
        let cfg = BallastConfig {
            file_count: 10,
            file_size_bytes: 1_000_000,
            replenish_cooldown_minutes: 30,
            auto_provision: true,
            overrides,
        };
        assert_eq!(cfg.effective_file_count("/data"), 20);
        assert_eq!(cfg.effective_file_count("/other"), 10);
    }

    #[test]
    fn ballast_volume_disabled_override() {
        use super::BallastConfig;
        use std::collections::BTreeMap;
        let mut overrides = BTreeMap::new();
        overrides.insert(
            "/tmp".to_string(),
            super::BallastVolumeOverride {
                enabled: false,
                file_count: None,
                file_size_bytes: None,
            },
        );
        let cfg = BallastConfig {
            file_count: 10,
            file_size_bytes: 1_000_000,
            replenish_cooldown_minutes: 30,
            auto_provision: true,
            overrides,
        };
        assert!(!cfg.is_volume_enabled("/tmp"));
        assert!(cfg.is_volume_enabled("/data"));
    }

    #[test]
    fn normalize_paths_trims_trailing_slashes_and_keeps_root() {
        let mut cfg = Config::default();
        cfg.ballast.overrides.insert(
            "/data/".to_string(),
            super::BallastVolumeOverride::default(),
        );
        cfg.scanner.root_paths = vec![PathBuf::from("/"), PathBuf::from("/data/")];

        cfg.normalize_paths();

        assert!(cfg.ballast.overrides.contains_key("/data"));
        assert!(!cfg.ballast.overrides.contains_key("/data/"));
        assert!(cfg.scanner.root_paths.contains(&PathBuf::from("/")));
        assert!(cfg.scanner.root_paths.contains(&PathBuf::from("/data")));
    }

    #[test]
    fn windows_path_normalization() {
        let mut cfg = Config::default();
        // Override with Windows-style trailing slash
        cfg.ballast.overrides.insert(
            "C:\\Data\\".to_string(),
            super::BallastVolumeOverride::default(),
        );
        // Root path with Windows-style trailing slash
        cfg.scanner.root_paths = vec![PathBuf::from("C:\\"), PathBuf::from("C:\\Data\\")];

        cfg.normalize_paths();

        // Key should be stripped
        assert!(cfg.ballast.overrides.contains_key("C:\\Data"));
        assert!(!cfg.ballast.overrides.contains_key("C:\\Data\\"));

        // Roots check
        // C:\ is root, should be preserved (len=3)
        assert!(cfg.scanner.root_paths.contains(&PathBuf::from("C:\\")));
        // C:\Data\ is not root, should be stripped
        assert!(cfg.scanner.root_paths.contains(&PathBuf::from("C:\\Data")));
    }

    #[test]
    fn load_returns_error_for_explicit_missing_path() {
        let result = Config::load(Some(Path::new("/nonexistent/sbh/config.toml")));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, SbhError::MissingConfig { .. }));
    }

    #[test]
    fn prediction_horizon_ordering_enforced() {
        let mut cfg = Config::default();
        // warning_horizon must be > action_horizon
        cfg.pressure.prediction.warning_horizon_minutes = 10.0;
        cfg.pressure.prediction.action_horizon_minutes = 30.0;
        let err = cfg.validate().expect_err("expected prediction error");
        assert!(err.to_string().contains("warning_horizon"));
    }

    #[test]
    fn valid_protected_paths_accepted() {
        let mut cfg = Config::default();
        cfg.scanner.protected_paths = vec![
            "/data/important/**".to_string(),
            "/home/*/projects".to_string(),
        ];
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn sacred_config_round_trips_and_deduplicates_paths() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("sacred.toml");
        let sacred = SacredConfig {
            protected_paths: vec![
                "/data/projects/critical".to_string(),
                "/data/projects/critical".to_string(),
                "  /Users/jemanuel/Pictures/*.photoslibrary  ".to_string(),
            ],
        };

        write_sacred_config(&path, &sacred).unwrap();
        let loaded = load_sacred_config(&path).unwrap();

        assert_eq!(
            loaded.protected_paths,
            vec![
                "/data/projects/critical".to_string(),
                "/Users/jemanuel/Pictures/*.photoslibrary".to_string(),
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn sacred_config_removes_canonical_equivalent_paths() {
        let tmp = TempDir::new().unwrap();
        let real = tmp.path().join("real");
        let alias = tmp.path().join("alias");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();

        let mut sacred = SacredConfig {
            protected_paths: vec![alias.to_string_lossy().to_string()],
        };

        let real_path = real.to_string_lossy();
        assert!(sacred.remove_protected_path(real_path.as_ref()));
        assert!(
            sacred.protected_paths.is_empty(),
            "removing the only protected path must leave none, got {:?}",
            sacred.protected_paths
        );
    }

    #[test]
    fn load_merges_sacred_config_protected_paths() {
        let tmp = TempDir::new().unwrap();
        let config_path = tmp.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[scanner]\nprotected_paths = [\"/data/base\"]\n",
        )
        .unwrap();
        std::fs::write(
            sacred_config_path_for(&config_path),
            "protected_paths = [\"/data/critical\", \"/data/base\"]\n",
        )
        .unwrap();

        let loaded = Config::load(Some(&config_path)).unwrap();

        assert_eq!(
            loaded.scanner.protected_paths,
            vec!["/data/base".to_string(), "/data/critical".to_string()]
        );
    }

    #[test]
    fn ballast_file_size_below_header_rejected() {
        let mut cfg = Config::default();
        cfg.ballast.file_size_bytes = 2048; // below 4096 header size
        let err = cfg.validate().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("4096"),
            "error should mention header size: {msg}"
        );
    }

    #[test]
    fn ballast_file_count_exceeding_cap_rejected() {
        let mut cfg = Config::default();
        cfg.ballast.file_count = 100_001;
        let err = cfg.validate().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("exceeds maximum"),
            "error should mention exceeds maximum: {msg}"
        );
    }

    #[test]
    fn stable_hash_deterministic() {
        let cfg = Config::default();
        let h1 = cfg.stable_hash().expect("hash");
        let h2 = cfg.stable_hash().expect("hash");
        assert_eq!(h1, h2);
    }

    // ── Dashboard rollout config ─────────────────────────────────

    #[test]
    fn dashboard_mode_default_is_new() {
        let cfg = Config::default();
        assert_eq!(cfg.dashboard.mode, super::DashboardMode::New);
        assert!(!cfg.dashboard.kill_switch);
    }

    #[test]
    fn dashboard_mode_parse_roundtrip() {
        use super::DashboardMode;
        for (input, expected) in [
            ("legacy", DashboardMode::Legacy),
            ("new", DashboardMode::New),
        ] {
            let parsed: DashboardMode = input.parse().unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed.to_string(), input);
        }
    }

    #[test]
    fn dashboard_mode_parse_case_insensitive() {
        use super::DashboardMode;
        for input in ["LEGACY", "Legacy", "NEW", "New", "  new  "] {
            let parsed: DashboardMode = input.parse().unwrap();
            assert!(parsed == DashboardMode::Legacy || parsed == DashboardMode::New);
        }
    }

    #[test]
    fn dashboard_mode_parse_invalid_rejected() {
        use super::DashboardMode;
        let err = "auto".parse::<DashboardMode>().unwrap_err();
        assert!(err.contains("invalid dashboard mode"));
    }

    #[test]
    fn dashboard_config_deserializes_from_toml() {
        let toml_str = r#"
[dashboard]
mode = "new"
kill_switch = true
"#;
        let cfg: Config = toml::from_str(toml_str).expect("should parse");
        assert_eq!(cfg.dashboard.mode, super::DashboardMode::New);
        assert!(cfg.dashboard.kill_switch);
    }

    #[test]
    fn dashboard_config_defaults_when_absent_from_toml() {
        let toml_str = "[pressure]\npoll_interval_ms = 500\n";
        let cfg: Config = toml::from_str(toml_str).expect("should parse");
        assert_eq!(cfg.dashboard.mode, super::DashboardMode::New);
        assert!(!cfg.dashboard.kill_switch);
    }
}
