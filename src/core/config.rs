//! Configuration system: TOML file + env var overrides + smart defaults.

#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::core::errors::{Result, SbhError};
use crate::daemon::notifications::NotificationConfig;

/// Full SBH configuration model.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
#[derive(Default)]
pub struct Config {
    pub pressure: PressureConfig,
    pub scanner: ScannerConfig,
    pub scoring: ScoringConfig,
    pub ballast: BallastConfig,
    pub scheduler: VoiConfig,
    pub update: UpdateConfig,
    pub telemetry: TelemetryConfig,
    pub paths: PathsConfig,
    pub notifications: NotificationConfig,
}

/// Pressure thresholds and control knobs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct PressureConfig {
    pub green_min_free_pct: f64,
    pub yellow_min_free_pct: f64,
    pub orange_min_free_pct: f64,
    pub red_min_free_pct: f64,
    pub poll_interval_ms: u64,
    /// Predictive pre-emption settings.
    pub prediction: PredictionConfig,
}

/// Knobs for predictive pre-emptive action (EWMA → graduated response).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
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
}

/// Scanner behavior and safety constraints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ScannerConfig {
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
}

/// Multi-factor score weights and decision-theoretic losses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
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
}

/// Ballast allocation settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
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
#[serde(default)]
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
#[serde(default)]
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
#[serde(default)]
pub struct TelemetryConfig {
    pub fs_cache_ttl_ms: u64,
    pub ewma_base_alpha: f64,
    pub ewma_min_alpha: f64,
    pub ewma_max_alpha: f64,
    pub ewma_min_samples: u64,
}

/// Update-check behavior, cache policy, and opt-out controls.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UpdateConfig {
    pub enabled: bool,
    pub metadata_cache_ttl_seconds: u64,
    pub metadata_cache_file: PathBuf,
    pub background_refresh: bool,
    pub notices_enabled: bool,
}

/// Filesystem paths used by sbh.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PathsConfig {
    pub config_file: PathBuf,
    pub ballast_dir: PathBuf,
    pub state_file: PathBuf,
    pub sqlite_db: PathBuf,
    pub jsonl_log: PathBuf,
}

impl Default for PressureConfig {
    fn default() -> Self {
        Self {
            green_min_free_pct: 20.0,
            yellow_min_free_pct: 14.0,
            orange_min_free_pct: 10.0,
            red_min_free_pct: 6.0,
            poll_interval_ms: 1_000,
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
        }
    }
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            root_paths: vec![PathBuf::from("/data/projects"), PathBuf::from("/tmp")],
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
            min_file_age_minutes: 30,
            max_depth: 10,
            parallelism: std::thread::available_parallelism()
                .map_or(2, |n| n.get().saturating_div(2).max(1)),
            follow_symlinks: false,
            cross_devices: false,
            dry_run: false,
            max_delete_batch: 20,
        }
    }
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            min_score: 0.45,
            location_weight: 0.25,
            name_weight: 0.25,
            age_weight: 0.20,
            size_weight: 0.15,
            structure_weight: 0.15,
            false_positive_loss: 100.0,
            false_negative_loss: 30.0,
            calibration_floor: 0.55,
        }
    }
}

impl Default for BallastConfig {
    fn default() -> Self {
        Self {
            file_count: 10,
            file_size_bytes: 1_073_741_824,
            replenish_cooldown_minutes: 30,
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
        }
    }
}

impl Default for UpdateConfig {
    fn default() -> Self {
        let home_dir = env::var_os("HOME").map_or_else(
            || {
                eprintln!(
                    "[SBH-CONFIG] WARNING: HOME not set, falling back to /tmp for update paths"
                );
                PathBuf::from("/tmp")
            },
            PathBuf::from,
        );
        let data_dir = home_dir.join(".local").join("share").join("sbh");
        Self {
            enabled: true,
            metadata_cache_ttl_seconds: 30 * 60,
            metadata_cache_file: data_dir.join("update-metadata.json"),
            background_refresh: true,
            notices_enabled: true,
        }
    }
}

impl Default for PathsConfig {
    fn default() -> Self {
        let home_dir = env::var_os("HOME").map_or_else(
            || {
                eprintln!(
                    "[SBH-CONFIG] WARNING: HOME not set, falling back to /tmp for data paths"
                );
                PathBuf::from("/tmp")
            },
            PathBuf::from,
        );
        let cfg = home_dir.join(".config").join("sbh").join("config.toml");
        let data = home_dir.join(".local").join("share").join("sbh");
        Self {
            config_file: cfg,
            ballast_dir: data.join("ballast"),
            state_file: data.join("state.json"),
            sqlite_db: data.join("activity.sqlite3"),
            jsonl_log: data.join("activity.jsonl"),
        }
    }
}

impl Config {
    /// Default configuration path.
    #[must_use]
    pub fn default_path() -> PathBuf {
        PathsConfig::default().config_file
    }

    /// Load config from default or explicit path, then apply env overrides.
    ///
    /// Missing config file is not an error when loading from default path; defaults are used.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let path_buf = path.map_or_else(Self::default_path, Path::to_path_buf);
        let is_explicit_path = path.is_some();

        let mut cfg = if path_buf.exists() {
            let raw = fs::read_to_string(&path_buf).map_err(|source| SbhError::Io {
                path: path_buf.clone(),
                source,
            })?;
            let parsed: Self = toml::from_str(&raw)?;
            parsed
        } else if is_explicit_path {
            return Err(SbhError::MissingConfig { path: path_buf });
        } else {
            Self::default()
        };

        cfg.paths.config_file = path_buf;
        cfg.apply_env_overrides()?;
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

        // update
        self.apply_update_env_overrides_from(env_var)?;

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

    #[allow(clippy::too_many_lines)]
    fn validate(&self) -> Result<()> {
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

        validate_prob("scoring.min_score", self.scoring.min_score)?;
        validate_prob("scoring.calibration_floor", self.scoring.calibration_floor)?;

        // I35: min_score must be <= calibration_floor.
        if self.scoring.min_score > self.scoring.calibration_floor {
            return Err(SbhError::InvalidConfig {
                details: format!(
                    "scoring.min_score ({}) must be <= scoring.calibration_floor ({})",
                    self.scoring.min_score, self.scoring.calibration_floor
                ),
            });
        }

        // I32: Individual scoring weights must be non-negative.
        for (name, val) in [
            ("location_weight", self.scoring.location_weight),
            ("name_weight", self.scoring.name_weight),
            ("age_weight", self.scoring.age_weight),
            ("size_weight", self.scoring.size_weight),
            ("structure_weight", self.scoring.structure_weight),
        ] {
            if val < 0.0 {
                return Err(SbhError::InvalidConfig {
                    details: format!("scoring.{name} must be >= 0.0, got {val}"),
                });
            }
        }

        // M13: Loss values must be non-negative.
        if self.scoring.false_positive_loss < 0.0 || self.scoring.false_negative_loss < 0.0 {
            return Err(SbhError::InvalidConfig {
                details: "scoring.false_positive_loss and false_negative_loss must be >= 0.0"
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
        for (name, val) in [
            ("io_cost_weight", self.scheduler.io_cost_weight),
            ("fp_risk_weight", self.scheduler.fp_risk_weight),
            ("exploration_weight", self.scheduler.exploration_weight),
            (
                "forecast_error_threshold",
                self.scheduler.forecast_error_threshold,
            ),
        ] {
            if val < 0.0 {
                return Err(SbhError::InvalidConfig {
                    details: format!("scheduler.{name} must be >= 0.0, got {val}"),
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

        if self.ballast.file_count == 0 || self.ballast.file_size_bytes == 0 {
            return Err(SbhError::InvalidConfig {
                details: "ballast.file_count and ballast.file_size_bytes must be > 0".to_string(),
            });
        }

        // BallastManager casts file indices to u32 for headers/filenames.
        if self.ballast.file_count > u32::MAX as usize {
            return Err(SbhError::InvalidConfig {
                details: format!(
                    "ballast.file_count ({}) exceeds maximum ({})",
                    self.ballast.file_count,
                    u32::MAX,
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

        Ok(())
    }
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
    use super::{Config, SbhError};
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

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
    fn ballast_file_count_exceeding_u32_max_rejected() {
        let mut cfg = Config::default();
        cfg.ballast.file_count = u32::MAX as usize + 1;
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
}
