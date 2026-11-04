//! Finite inode pressure, separate from filesystem bytes and fill forecasts.

use serde::{Deserialize, Serialize};

use crate::core::config::InodePressureConfig;
use crate::monitor::pid::{PressureLevel, classify_level};
use crate::platform::pal::InodeStats;

/// One validated inode reading and the independent pressure it implies.
///
/// The target is a filesystem counter goal, not an estimate of how many
/// inodes any candidate would reclaim. A fresh reading must stop cleanup.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InodePressureEvidence {
    /// Finite inode capacity reported by the filesystem.
    pub total: u64,
    /// Free inodes including reserved capacity.
    pub free: u64,
    /// Inodes available to an ordinary caller.
    pub available: u64,
    /// Available inode percentage; never a byte free-space percentage.
    pub free_pct: f64,
    /// Independent inode pressure, serialized as a lowercase level.
    pub level: String,
    /// Stop goal, including the configured recovery hysteresis.
    pub target_available: u64,
}

impl InodePressureEvidence {
    /// The typed level consumed by the per-mount controller.
    #[must_use]
    pub fn pressure_level(&self) -> PressureLevel {
        match self.level.as_str() {
            "yellow" => PressureLevel::Yellow,
            "orange" => PressureLevel::Orange,
            "red" => PressureLevel::Red,
            "critical" => PressureLevel::Critical,
            _ => PressureLevel::Green,
        }
    }
}

/// Classify a fresh finite reading using independent thresholds and hysteresis.
///
/// Pressure rises immediately. Recovery steps down at most one level after
/// clearing that level's threshold plus hysteresis. Missing/disabled/invalid
/// evidence must reset the caller's previous level instead of retaining a
/// stale deletion permission. Byte thresholds, floors and forecasts do not
/// participate in this classification.
#[must_use]
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub fn classify_inode_pressure(
    stats: InodeStats,
    config: &InodePressureConfig,
    previous: PressureLevel,
) -> Option<InodePressureEvidence> {
    if !config.enabled || !config.is_valid() {
        return None;
    }
    let stats = stats.validated()?;
    let free_pct = stats.available_pct()?;
    let [green, yellow, orange, red] = [
        config.green_min_free_pct,
        config.yellow_min_free_pct,
        config.orange_min_free_pct,
        config.red_min_free_pct,
    ];
    let hysteresis = config.hysteresis_pct;
    let raw = classify_level(free_pct, green, yellow, orange, red);
    let level = if raw >= previous {
        raw
    } else {
        match previous {
            PressureLevel::Critical if free_pct >= red + hysteresis => PressureLevel::Red,
            PressureLevel::Red if free_pct >= orange + hysteresis => PressureLevel::Orange,
            PressureLevel::Orange if free_pct >= yellow + hysteresis => PressureLevel::Yellow,
            PressureLevel::Yellow if free_pct >= green + hysteresis => PressureLevel::Green,
            _ => previous,
        }
    };
    let target_available =
        ((stats.total as f64 * (green + hysteresis) / 100.0).ceil() as u64).min(stats.total);
    Some(InodePressureEvidence {
        total: stats.total,
        free: stats.free,
        available: stats.available,
        free_pct,
        level: format!("{level:?}").to_lowercase(),
        target_available,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(available: u64, previous: PressureLevel) -> InodePressureEvidence {
        classify_inode_pressure(
            InodeStats::new(10_000, available, available).unwrap(),
            &InodePressureConfig::default(),
            previous,
        )
        .unwrap()
    }

    #[test]
    fn inode_thresholds_are_independent_and_use_available_counts() {
        for (available, expected) in [
            (1000, PressureLevel::Green),
            (999, PressureLevel::Yellow),
            (500, PressureLevel::Yellow),
            (499, PressureLevel::Orange),
            (200, PressureLevel::Orange),
            (199, PressureLevel::Red),
            (100, PressureLevel::Red),
            (99, PressureLevel::Critical),
            (0, PressureLevel::Critical),
        ] {
            assert_eq!(
                reading(available, PressureLevel::Green).pressure_level(),
                expected
            );
        }
        let reserved = classify_inode_pressure(
            InodeStats::new(10_000, 9000, 0).unwrap(),
            &InodePressureConfig::default(),
            PressureLevel::Green,
        )
        .unwrap();
        assert_eq!(reserved.pressure_level(), PressureLevel::Critical);
        assert_eq!(reserved.free, 9000);
        assert_eq!(reserved.free_pct, 0.0);
    }

    #[test]
    fn inode_hysteresis_recovers_gradually_and_escalates_immediately() {
        assert_eq!(
            reading(149, PressureLevel::Critical).pressure_level(),
            PressureLevel::Critical
        );
        assert_eq!(
            reading(150, PressureLevel::Critical).pressure_level(),
            PressureLevel::Red
        );
        assert_eq!(
            reading(249, PressureLevel::Red).pressure_level(),
            PressureLevel::Red
        );
        assert_eq!(
            reading(250, PressureLevel::Red).pressure_level(),
            PressureLevel::Orange
        );
        assert_eq!(
            reading(1049, PressureLevel::Yellow).pressure_level(),
            PressureLevel::Yellow
        );
        assert_eq!(
            reading(1050, PressureLevel::Yellow).pressure_level(),
            PressureLevel::Green
        );
        assert_eq!(
            reading(0, PressureLevel::Yellow).pressure_level(),
            PressureLevel::Critical
        );
    }

    #[test]
    fn inode_goal_rounds_up_and_includes_recovery_margin() {
        let evidence = classify_inode_pressure(
            InodeStats::new(101, 1, 1).unwrap(),
            &InodePressureConfig::default(),
            PressureLevel::Green,
        )
        .unwrap();
        assert_eq!(evidence.target_available, 11);
        let json = serde_json::to_value(evidence).unwrap();
        assert_eq!(json["level"], "critical");
        assert_eq!(json["available"], 1);
        assert_eq!(json["target_available"], 11);
    }

    #[test]
    fn absent_invalid_or_disabled_inode_evidence_cannot_authorize_pressure() {
        let stats = InodeStats::new(1000, 0, 0).unwrap();
        let mut config = InodePressureConfig {
            enabled: false,
            ..InodePressureConfig::default()
        };
        assert!(classify_inode_pressure(stats, &config, PressureLevel::Critical).is_none());
        config.enabled = true;
        config.hysteresis_pct = f64::NAN;
        assert!(classify_inode_pressure(stats, &config, PressureLevel::Critical).is_none());
        config.hysteresis_pct = 0.5;
        config.green_min_free_pct = 100.0;
        assert!(classify_inode_pressure(stats, &config, PressureLevel::Critical).is_none());
        assert!(
            classify_inode_pressure(
                InodeStats {
                    total: 0,
                    free: 0,
                    available: 0
                },
                &InodePressureConfig::default(),
                PressureLevel::Critical,
            )
            .is_none()
        );
    }
}
