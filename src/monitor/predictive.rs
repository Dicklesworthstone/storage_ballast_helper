//! Predictive action pipeline: maps EWMA forecasts to pre-emptive cleanup actions.
//!
//! Transforms sbh from reactive (act after thresholds crossed) to predictive (act before
//! thresholds crossed based on consumption rate forecasts). The EWMA estimator provides
//! time-to-exhaustion predictions; this module maps those predictions to a graduated
//! response timeline:
//!
//! | Time remaining | Action |
//! |----------------|--------|
//! | > warning horizon | `Clear` — no action |
//! | warning..action horizon | `EarlyWarning` — log, increase scan frequency |
//! | action horizon..5 min | `PreemptiveCleanup` — start scanning/deleting |
//! | < 5 min | `ImminentDanger` — release ballast + aggressive cleanup |
//!
//! Confidence gating prevents false alarms from brief spikes or insufficient data.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::monitor::ewma::{RateEstimate, Trend};

/// Tuning knobs for predictive pre-emption.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct PredictiveConfig {
    /// Master switch — when false, `evaluate` always returns `Clear`.
    pub enabled: bool,
    /// Start pre-emptive cleanup when predicted exhaustion is within this many minutes.
    pub action_horizon_minutes: f64,
    /// Emit early-warning events when predicted exhaustion is within this many minutes.
    pub warning_horizon_minutes: f64,
    /// Minimum EWMA confidence required before any pre-emptive action.
    pub min_confidence: f64,
    /// Minimum EWMA sample count before any pre-emptive action.
    pub min_samples: u64,
    /// Minutes-remaining threshold below which we escalate to `ImminentDanger`.
    pub imminent_danger_minutes: f64,
    /// Minutes-remaining threshold below which `ImminentDanger` is critical (release ALL ballast).
    pub critical_danger_minutes: f64,
}

impl Default for PredictiveConfig {
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

/// Graduated pre-emptive response to predicted disk exhaustion.
#[derive(Debug, Clone, PartialEq)]
pub enum PredictiveAction {
    /// No predicted issue within the warning horizon.
    Clear,

    /// Disk will be full within the warning horizon — log and increase monitoring frequency.
    EarlyWarning {
        mount: PathBuf,
        minutes_remaining: f64,
        confidence: f64,
        rate_bytes_per_second: f64,
        trend: Trend,
    },

    /// Disk will be full within the action horizon — start pre-emptive cleanup.
    PreemptiveCleanup {
        mount: PathBuf,
        minutes_remaining: f64,
        confidence: f64,
        rate_bytes_per_second: f64,
        /// Suggested cleanup aggressiveness: lower score threshold means more aggressive.
        recommended_min_score: f64,
        /// Suggested free-space target percentage (increases as time decreases).
        recommended_free_target_pct: f64,
    },

    /// Imminent disk exhaustion (< 5 min) — release ballast + aggressive cleanup.
    ImminentDanger {
        mount: PathBuf,
        minutes_remaining: f64,
        /// Whether this is critical (< 2 min) — release ALL ballast.
        critical: bool,
    },
}

impl PredictiveAction {
    /// Returns the action severity as a numeric level for comparison.
    /// Higher values = more severe.
    #[must_use]
    pub fn severity(&self) -> u8 {
        match self {
            Self::Clear => 0,
            Self::EarlyWarning { .. } => 1,
            Self::PreemptiveCleanup { .. } => 2,
            Self::ImminentDanger { critical: false, .. } => 3,
            Self::ImminentDanger { critical: true, .. } => 4,
        }
    }

    /// Human-readable event name for structured logging.
    #[must_use]
    pub fn event_name(&self) -> &'static str {
        match self {
            Self::Clear => "predictive_clear",
            Self::EarlyWarning { .. } => "predictive_warning",
            Self::PreemptiveCleanup { .. } => "predictive_cleanup",
            Self::ImminentDanger { critical: false, .. } => "predictive_imminent",
            Self::ImminentDanger { critical: true, .. } => "predictive_critical",
        }
    }

    /// Whether this action recommends scanning/deletion.
    #[must_use]
    pub fn should_cleanup(&self) -> bool {
        matches!(
            self,
            Self::PreemptiveCleanup { .. } | Self::ImminentDanger { .. }
        )
    }

    /// Whether this action recommends ballast release.
    #[must_use]
    pub fn should_release_ballast(&self) -> bool {
        matches!(self, Self::ImminentDanger { .. })
    }
}

/// Construct a [`PredictiveConfig`] from the core config's [`PredictionConfig`].
impl From<crate::core::config::PredictionConfig> for PredictiveConfig {
    fn from(cfg: crate::core::config::PredictionConfig) -> Self {
        Self {
            enabled: cfg.enabled,
            action_horizon_minutes: cfg.action_horizon_minutes,
            warning_horizon_minutes: cfg.warning_horizon_minutes,
            min_confidence: cfg.min_confidence,
            min_samples: cfg.min_samples,
            imminent_danger_minutes: cfg.imminent_danger_minutes,
            critical_danger_minutes: cfg.critical_danger_minutes,
        }
    }
}

/// Evaluates EWMA predictions and maps them to graduated pre-emptive actions.
#[derive(Debug, Clone)]
pub struct PredictiveActionPolicy {
    config: PredictiveConfig,
}

impl PredictiveActionPolicy {
    #[must_use]
    pub fn new(config: PredictiveConfig) -> Self {
        Self { config }
    }

    /// Create from the core config's prediction settings.
    #[must_use]
    pub fn from_config(cfg: crate::core::config::PredictionConfig) -> Self {
        Self::new(PredictiveConfig::from(cfg))
    }

    /// Evaluate EWMA prediction and current disk state to determine pre-emptive action.
    ///
    /// Confidence gating prevents false alarms:
    /// - Disabled → always `Clear`
    /// - Fallback active (insufficient data) → `Clear`
    /// - Low confidence → `Clear`
    /// - Insufficient samples → `Clear`
    /// - Recovering/Decelerating trend → `Clear`
    /// - Not consuming space (rate ≤ 0) → `Clear`
    #[must_use]
    pub fn evaluate(
        &self,
        estimate: &RateEstimate,
        current_free_pct: f64,
        mount: PathBuf,
    ) -> PredictiveAction {
        if !self.config.enabled {
            return PredictiveAction::Clear;
        }

        // Confidence gating: reject unreliable predictions.
        if estimate.fallback_active {
            return PredictiveAction::Clear;
        }
        if estimate.confidence < self.config.min_confidence {
            return PredictiveAction::Clear;
        }

        // Trend gating: only act on consumption, not recovery.
        match estimate.trend {
            Trend::Recovering | Trend::Decelerating => return PredictiveAction::Clear,
            Trend::Stable | Trend::Accelerating => {}
        }

        // Not consuming space — no prediction needed.
        if estimate.bytes_per_second <= 0.0 {
            return PredictiveAction::Clear;
        }

        // Current free space already low override: if we're already in a good state
        // (lots of free space), we still respect the EWMA prediction.
        let minutes_remaining = estimate.seconds_to_exhaustion / 60.0;

        // Guard against infinite or nonsensical values.
        if !minutes_remaining.is_finite() || minutes_remaining < 0.0 {
            return PredictiveAction::Clear;
        }

        self.classify(
            minutes_remaining,
            estimate.confidence,
            estimate.bytes_per_second,
            estimate.trend,
            current_free_pct,
            mount,
        )
    }

    /// Map minutes-remaining to action tier.
    fn classify(
        &self,
        minutes_remaining: f64,
        confidence: f64,
        rate_bps: f64,
        trend: Trend,
        current_free_pct: f64,
        mount: PathBuf,
    ) -> PredictiveAction {
        if minutes_remaining <= self.config.critical_danger_minutes {
            PredictiveAction::ImminentDanger {
                mount,
                minutes_remaining,
                critical: true,
            }
        } else if minutes_remaining <= self.config.imminent_danger_minutes {
            PredictiveAction::ImminentDanger {
                mount,
                minutes_remaining,
                critical: false,
            }
        } else if minutes_remaining <= self.config.action_horizon_minutes {
            // Aggressiveness scales with time pressure.
            // At action_horizon: gentle (min_score=0.60, target=15%).
            // At imminent_danger boundary: aggressive (min_score=0.30, target=25%).
            let range = self.config.action_horizon_minutes - self.config.imminent_danger_minutes;
            let progress = if range > 0.0 {
                ((self.config.action_horizon_minutes - minutes_remaining) / range).clamp(0.0, 1.0)
            } else {
                1.0
            };
            let recommended_min_score = lerp(0.60, 0.30, progress);
            let recommended_free_target_pct = lerp(
                current_free_pct.max(15.0),
                current_free_pct.max(25.0),
                progress,
            );

            PredictiveAction::PreemptiveCleanup {
                mount,
                minutes_remaining,
                confidence,
                rate_bytes_per_second: rate_bps,
                recommended_min_score,
                recommended_free_target_pct,
            }
        } else if minutes_remaining <= self.config.warning_horizon_minutes {
            PredictiveAction::EarlyWarning {
                mount,
                minutes_remaining,
                confidence,
                rate_bytes_per_second: rate_bps,
                trend,
            }
        } else {
            PredictiveAction::Clear
        }
    }
}

/// Linear interpolation between two values.
#[inline]
fn lerp(a: f64, b: f64, t: f64) -> f64 {
    (b - a).mul_add(t, a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::ewma::Trend;

    fn default_policy() -> PredictiveActionPolicy {
        PredictiveActionPolicy::new(PredictiveConfig::default())
    }

    fn make_estimate(
        bytes_per_second: f64,
        seconds_to_exhaustion: f64,
        confidence: f64,
        trend: Trend,
        fallback_active: bool,
    ) -> RateEstimate {
        RateEstimate {
            bytes_per_second,
            acceleration: 0.0,
            seconds_to_exhaustion,
            seconds_to_threshold: seconds_to_exhaustion * 0.8,
            confidence,
            trend,
            alpha_used: 0.3,
            fallback_active,
        }
    }

    #[test]
    fn disabled_policy_always_returns_clear() {
        let policy = PredictiveActionPolicy::new(PredictiveConfig {
            enabled: false,
            ..Default::default()
        });
        let est = make_estimate(500_000_000.0, 60.0, 0.95, Trend::Accelerating, false);
        assert_eq!(
            policy.evaluate(&est, 80.0, PathBuf::from("/data")),
            PredictiveAction::Clear
        );
    }

    #[test]
    fn fallback_active_returns_clear() {
        let policy = default_policy();
        let est = make_estimate(500_000_000.0, 60.0, 0.95, Trend::Accelerating, true);
        assert_eq!(
            policy.evaluate(&est, 80.0, PathBuf::from("/data")),
            PredictiveAction::Clear
        );
    }

    #[test]
    fn low_confidence_returns_clear() {
        let policy = default_policy();
        let est = make_estimate(500_000_000.0, 60.0, 0.5, Trend::Accelerating, false);
        assert_eq!(
            policy.evaluate(&est, 80.0, PathBuf::from("/data")),
            PredictiveAction::Clear
        );
    }

    #[test]
    fn recovering_trend_returns_clear() {
        let policy = default_policy();
        let est = make_estimate(500_000_000.0, 120.0, 0.95, Trend::Recovering, false);
        assert_eq!(
            policy.evaluate(&est, 80.0, PathBuf::from("/data")),
            PredictiveAction::Clear
        );
    }

    #[test]
    fn decelerating_trend_returns_clear() {
        let policy = default_policy();
        let est = make_estimate(500_000_000.0, 900.0, 0.95, Trend::Decelerating, false);
        assert_eq!(
            policy.evaluate(&est, 80.0, PathBuf::from("/data")),
            PredictiveAction::Clear
        );
    }

    #[test]
    fn negative_consumption_returns_clear() {
        let policy = default_policy();
        // bytes_per_second <= 0 means free space is growing.
        let est = make_estimate(-100.0, f64::INFINITY, 0.95, Trend::Stable, false);
        assert_eq!(
            policy.evaluate(&est, 80.0, PathBuf::from("/data")),
            PredictiveAction::Clear
        );
    }

    #[test]
    fn exhaustion_beyond_warning_horizon_returns_clear() {
        let policy = default_policy();
        // 120 minutes > 60-minute warning horizon.
        let est = make_estimate(100_000.0, 7200.0, 0.85, Trend::Stable, false);
        assert_eq!(
            policy.evaluate(&est, 80.0, PathBuf::from("/data")),
            PredictiveAction::Clear
        );
    }

    #[test]
    fn exhaustion_within_warning_horizon_returns_early_warning() {
        let policy = default_policy();
        // 42 minutes: within 60-minute warning horizon, beyond 30-minute action horizon.
        let est = make_estimate(100_000.0, 42.0 * 60.0, 0.85, Trend::Stable, false);
        let action = policy.evaluate(&est, 80.0, PathBuf::from("/data"));
        match action {
            PredictiveAction::EarlyWarning {
                minutes_remaining,
                confidence,
                ..
            } => {
                assert!((minutes_remaining - 42.0).abs() < 0.01);
                assert!((confidence - 0.85).abs() < 0.01);
            }
            other => panic!("expected EarlyWarning, got {other:?}"),
        }
    }

    #[test]
    fn exhaustion_within_action_horizon_returns_preemptive_cleanup() {
        let policy = default_policy();
        // 20 minutes: within 30-minute action horizon, above 5-minute imminent threshold.
        let est = make_estimate(500_000_000.0, 20.0 * 60.0, 0.90, Trend::Accelerating, false);
        let action = policy.evaluate(&est, 78.0, PathBuf::from("/data"));
        match action {
            PredictiveAction::PreemptiveCleanup {
                minutes_remaining,
                confidence,
                recommended_min_score,
                recommended_free_target_pct,
                ..
            } => {
                assert!((minutes_remaining - 20.0).abs() < 0.01);
                assert!((confidence - 0.90).abs() < 0.01);
                // 20 min is 10/25 of the way from action_horizon (30) to imminent (5).
                assert!(recommended_min_score < 0.60);
                assert!(recommended_min_score > 0.30);
                assert!(recommended_free_target_pct >= 15.0);
            }
            other => panic!("expected PreemptiveCleanup, got {other:?}"),
        }
    }

    #[test]
    fn exhaustion_at_action_boundary_still_preemptive_cleanup() {
        let policy = default_policy();
        // Exactly 30 minutes: right at the action horizon boundary.
        let est = make_estimate(500_000.0, 30.0 * 60.0, 0.80, Trend::Stable, false);
        let action = policy.evaluate(&est, 50.0, PathBuf::from("/data"));
        assert!(matches!(action, PredictiveAction::PreemptiveCleanup { .. }));
    }

    #[test]
    fn imminent_danger_at_4_minutes() {
        let policy = default_policy();
        // 4 minutes: below 5-minute threshold.
        let est = make_estimate(500_000_000.0, 4.0 * 60.0, 0.95, Trend::Accelerating, false);
        let action = policy.evaluate(&est, 10.0, PathBuf::from("/data"));
        match action {
            PredictiveAction::ImminentDanger {
                minutes_remaining,
                critical,
                ..
            } => {
                assert!((minutes_remaining - 4.0).abs() < 0.01);
                assert!(!critical);
            }
            other => panic!("expected ImminentDanger, got {other:?}"),
        }
    }

    #[test]
    fn critical_danger_at_1_minute() {
        let policy = default_policy();
        // 1 minute: below 2-minute critical threshold.
        let est = make_estimate(500_000_000.0, 60.0, 0.95, Trend::Accelerating, false);
        let action = policy.evaluate(&est, 5.0, PathBuf::from("/data"));
        match action {
            PredictiveAction::ImminentDanger {
                minutes_remaining,
                critical,
                ..
            } => {
                assert!((minutes_remaining - 1.0).abs() < 0.01);
                assert!(critical, "should be critical at 1 minute");
            }
            other => panic!("expected ImminentDanger (critical), got {other:?}"),
        }
    }

    #[test]
    fn high_consumption_at_80pct_full_triggers_preemptive_cleanup() {
        let policy = default_policy();
        // 500 MB/s consumption, disk 80% full, ~28 minutes to exhaustion.
        let est = make_estimate(500_000_000.0, 28.0 * 60.0, 0.88, Trend::Accelerating, false);
        let action = policy.evaluate(&est, 80.0, PathBuf::from("/data"));
        assert!(
            matches!(action, PredictiveAction::PreemptiveCleanup { .. }),
            "expected PreemptiveCleanup at 80% full with 28 min left"
        );
    }

    #[test]
    fn brief_spike_with_insufficient_samples_returns_clear() {
        let policy = default_policy();
        // High rate but fallback_active=true (< min_samples).
        let est = make_estimate(1_000_000_000.0, 30.0, 0.3, Trend::Accelerating, true);
        assert_eq!(
            policy.evaluate(&est, 90.0, PathBuf::from("/data")),
            PredictiveAction::Clear
        );
    }

    #[test]
    fn severity_ordering() {
        assert!(PredictiveAction::Clear.severity() < PredictiveAction::EarlyWarning {
            mount: PathBuf::from("/"),
            minutes_remaining: 50.0,
            confidence: 0.9,
            rate_bytes_per_second: 100.0,
            trend: Trend::Stable,
        }.severity());

        assert!(PredictiveAction::EarlyWarning {
            mount: PathBuf::from("/"),
            minutes_remaining: 50.0,
            confidence: 0.9,
            rate_bytes_per_second: 100.0,
            trend: Trend::Stable,
        }.severity() < PredictiveAction::PreemptiveCleanup {
            mount: PathBuf::from("/"),
            minutes_remaining: 20.0,
            confidence: 0.9,
            rate_bytes_per_second: 100.0,
            recommended_min_score: 0.5,
            recommended_free_target_pct: 20.0,
        }.severity());

        assert!(PredictiveAction::ImminentDanger {
            mount: PathBuf::from("/"),
            minutes_remaining: 4.0,
            critical: false,
        }.severity() < PredictiveAction::ImminentDanger {
            mount: PathBuf::from("/"),
            minutes_remaining: 1.0,
            critical: true,
        }.severity());
    }

    #[test]
    fn event_names_are_distinct() {
        let names = [
            PredictiveAction::Clear.event_name(),
            PredictiveAction::EarlyWarning {
                mount: PathBuf::from("/"),
                minutes_remaining: 50.0,
                confidence: 0.9,
                rate_bytes_per_second: 100.0,
                trend: Trend::Stable,
            }
            .event_name(),
            PredictiveAction::PreemptiveCleanup {
                mount: PathBuf::from("/"),
                minutes_remaining: 20.0,
                confidence: 0.9,
                rate_bytes_per_second: 100.0,
                recommended_min_score: 0.5,
                recommended_free_target_pct: 20.0,
            }
            .event_name(),
            PredictiveAction::ImminentDanger {
                mount: PathBuf::from("/"),
                minutes_remaining: 4.0,
                critical: false,
            }
            .event_name(),
            PredictiveAction::ImminentDanger {
                mount: PathBuf::from("/"),
                minutes_remaining: 1.0,
                critical: true,
            }
            .event_name(),
        ];
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(unique.len(), names.len(), "event names must be distinct");
    }

    #[test]
    fn should_cleanup_logic() {
        assert!(!PredictiveAction::Clear.should_cleanup());
        assert!(!PredictiveAction::EarlyWarning {
            mount: PathBuf::from("/"),
            minutes_remaining: 50.0,
            confidence: 0.9,
            rate_bytes_per_second: 100.0,
            trend: Trend::Stable,
        }
        .should_cleanup());
        assert!(PredictiveAction::PreemptiveCleanup {
            mount: PathBuf::from("/"),
            minutes_remaining: 20.0,
            confidence: 0.9,
            rate_bytes_per_second: 100.0,
            recommended_min_score: 0.5,
            recommended_free_target_pct: 20.0,
        }
        .should_cleanup());
        assert!(PredictiveAction::ImminentDanger {
            mount: PathBuf::from("/"),
            minutes_remaining: 4.0,
            critical: false,
        }
        .should_cleanup());
    }

    #[test]
    fn should_release_ballast_logic() {
        assert!(!PredictiveAction::Clear.should_release_ballast());
        assert!(!PredictiveAction::EarlyWarning {
            mount: PathBuf::from("/"),
            minutes_remaining: 50.0,
            confidence: 0.9,
            rate_bytes_per_second: 100.0,
            trend: Trend::Stable,
        }
        .should_release_ballast());
        assert!(!PredictiveAction::PreemptiveCleanup {
            mount: PathBuf::from("/"),
            minutes_remaining: 20.0,
            confidence: 0.9,
            rate_bytes_per_second: 100.0,
            recommended_min_score: 0.5,
            recommended_free_target_pct: 20.0,
        }
        .should_release_ballast());
        assert!(PredictiveAction::ImminentDanger {
            mount: PathBuf::from("/"),
            minutes_remaining: 4.0,
            critical: false,
        }
        .should_release_ballast());
    }

    #[test]
    fn preemptive_aggressiveness_scales_linearly() {
        let policy = default_policy();

        // Near action horizon (30 min) — gentle.
        let gentle_est =
            make_estimate(100_000.0, 29.0 * 60.0, 0.90, Trend::Stable, false);
        let gentle = policy.evaluate(&gentle_est, 50.0, PathBuf::from("/data"));

        // Near imminent (6 min) — aggressive.
        let aggressive_est =
            make_estimate(100_000.0, 6.0 * 60.0, 0.90, Trend::Stable, false);
        let aggressive = policy.evaluate(&aggressive_est, 50.0, PathBuf::from("/data"));

        match (&gentle, &aggressive) {
            (
                PredictiveAction::PreemptiveCleanup {
                    recommended_min_score: gentle_score,
                    ..
                },
                PredictiveAction::PreemptiveCleanup {
                    recommended_min_score: aggressive_score,
                    ..
                },
            ) => {
                assert!(
                    gentle_score > aggressive_score,
                    "gentle ({gentle_score}) should have higher min_score than aggressive ({aggressive_score})"
                );
            }
            _ => panic!("both should be PreemptiveCleanup: gentle={gentle:?}, aggressive={aggressive:?}"),
        }
    }

    #[test]
    fn infinity_seconds_to_exhaustion_returns_clear() {
        let policy = default_policy();
        let est = make_estimate(100.0, f64::INFINITY, 0.95, Trend::Stable, false);
        assert_eq!(
            policy.evaluate(&est, 80.0, PathBuf::from("/data")),
            PredictiveAction::Clear
        );
    }

    #[test]
    fn nan_seconds_to_exhaustion_returns_clear() {
        let policy = default_policy();
        let est = make_estimate(100.0, f64::NAN, 0.95, Trend::Stable, false);
        assert_eq!(
            policy.evaluate(&est, 80.0, PathBuf::from("/data")),
            PredictiveAction::Clear
        );
    }

    #[test]
    fn custom_horizons_respected() {
        let policy = PredictiveActionPolicy::new(PredictiveConfig {
            action_horizon_minutes: 10.0,
            warning_horizon_minutes: 20.0,
            imminent_danger_minutes: 3.0,
            ..Default::default()
        });

        // 15 min: within custom 20-min warning, beyond custom 10-min action.
        let est = make_estimate(100_000.0, 15.0 * 60.0, 0.90, Trend::Stable, false);
        assert!(matches!(
            policy.evaluate(&est, 80.0, PathBuf::from("/data")),
            PredictiveAction::EarlyWarning { .. }
        ));

        // 8 min: within custom 10-min action, above custom 3-min imminent.
        let est2 = make_estimate(100_000.0, 8.0 * 60.0, 0.90, Trend::Stable, false);
        assert!(matches!(
            policy.evaluate(&est2, 80.0, PathBuf::from("/data")),
            PredictiveAction::PreemptiveCleanup { .. }
        ));

        // 2.5 min: below custom 3-min imminent, above custom 2-min critical.
        let est3 = make_estimate(100_000.0, 2.5 * 60.0, 0.90, Trend::Stable, false);
        assert!(matches!(
            policy.evaluate(&est3, 80.0, PathBuf::from("/data")),
            PredictiveAction::ImminentDanger { critical: false, .. }
        ));

        // 1.5 min: below custom 2-min critical threshold.
        let est4 = make_estimate(100_000.0, 1.5 * 60.0, 0.90, Trend::Stable, false);
        assert!(matches!(
            policy.evaluate(&est4, 80.0, PathBuf::from("/data")),
            PredictiveAction::ImminentDanger { critical: true, .. }
        ));
    }

    #[test]
    fn steady_recovery_after_cleanup_stops_preemptive_actions() {
        let policy = default_policy();
        // Recovering trend: free space is growing.
        let est = make_estimate(-500_000.0, f64::INFINITY, 0.95, Trend::Recovering, false);
        assert_eq!(
            policy.evaluate(&est, 15.0, PathBuf::from("/data")),
            PredictiveAction::Clear,
            "should not act when trend is Recovering"
        );
    }
}
