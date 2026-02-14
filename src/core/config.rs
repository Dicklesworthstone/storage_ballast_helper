//! Configuration system: TOML file + env var overrides + smart defaults.

#![allow(missing_docs)]

use std::collections::hash_map::DefaultHasher;
use std::env;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::core::errors::{Result, SbhError};

/// Full SBH configuration model.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Config {
    pub pressure: PressureConfig,
    pub scanner: ScannerConfig,
    pub scoring: ScoringConfig,
    pub ballast: BallastConfig,
    pub telemetry: TelemetryConfig,
    pub paths: PathsConfig,
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
}

/// Scanner behavior and safety constraints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ScannerConfig {
    pub root_paths: Vec<PathBuf>,
    pub excluded_paths: Vec<PathBuf>,
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct BallastConfig {
    pub file_count: usize,
    pub file_size_bytes: u64,
    pub replenish_cooldown_minutes: u64,
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

/// Filesystem paths used by sbh.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct PathsConfig {
    pub config_file: PathBuf,
    pub ballast_dir: PathBuf,
    pub state_file: PathBuf,
    pub sqlite_db: PathBuf,
    pub jsonl_log: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            pressure: PressureConfig::default(),
            scanner: ScannerConfig::default(),
            scoring: ScoringConfig::default(),
            ballast: BallastConfig::default(),
            telemetry: TelemetryConfig::default(),
            paths: PathsConfig::default(),
        }
    }
}

impl Default for PressureConfig {
    fn default() -> Self {
        Self {
            green_min_free_pct: 20.0,
            yellow_min_free_pct: 14.0,
            orange_min_free_pct: 10.0,
            red_min_free_pct: 6.0,
            poll_interval_ms: 1_000,
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

impl Default for PathsConfig {
    fn default() -> Self {
        let home_dir = env::var_os("HOME").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
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
        cfg.validate()?;
        Ok(cfg)
    }

    /// Deterministic hash of the effective config for logging/telemetry.
    pub fn stable_hash(&self) -> Result<String> {
        let canonical = serde_json::to_string(self)?;
        let mut hasher = DefaultHasher::new();
        canonical.hash(&mut hasher);
        Ok(format!("{:016x}", hasher.finish()))
    }

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

        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if !(self.pressure.green_min_free_pct > self.pressure.yellow_min_free_pct
            && self.pressure.yellow_min_free_pct > self.pressure.orange_min_free_pct
            && self.pressure.orange_min_free_pct > self.pressure.red_min_free_pct)
        {
            return Err(SbhError::InvalidConfig {
                details: "pressure thresholds must strictly descend: green > yellow > orange > red"
                    .to_string(),
            });
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
        *slot = raw.parse::<bool>().map_err(|error| SbhError::ConfigParse {
            context: "env",
            details: format!("{name}={raw:?}: {error}"),
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Config, SbhError};

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
        let mut modified = cfg.clone();
        modified.scanner.max_depth += 1;
        let hash_after = modified.stable_hash().expect("hash should compute");
        assert_ne!(hash_before, hash_after);
    }
}
