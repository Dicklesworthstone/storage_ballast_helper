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
    /// Minimum confidence required during detected bursts. Higher than normal
    /// `min_confidence` because burst-inflated predictions are inherently less reliable.
    pub burst_min_confidence: f64,
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
            burst_min_confidence: 0.85,
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
            Self::ImminentDanger {
                critical: false, ..
            } => 3,
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
            Self::ImminentDanger {
                critical: false, ..
            } => "predictive_imminent",
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

/// Construct a [`PredictiveConfig`] from the core config's
/// [`PredictionConfig`](crate::core::config::PredictionConfig).
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
            burst_min_confidence: cfg.burst_min_confidence,
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
        self.evaluate_with_samples(
            estimate,
            current_free_pct,
            mount,
            Some(estimate.sample_count),
        )
    }

    /// Evaluate with an explicit sample count for min_samples gating.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn evaluate_with_samples(
        &self,
        estimate: &RateEstimate,
        current_free_pct: f64,
        mount: PathBuf,
        sample_count: Option<u64>,
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

        // Sample count gating: require minimum samples before acting.
        if let Some(count) = sample_count
            && count < self.config.min_samples
        {
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

        // Hard gate: if more than half the disk is free, no prediction can be
        // credible unless confidence is very high (>0.95). Consuming 50%+ of a
        // disk in minutes is physically implausible for normal workloads.
        // This is checked early so it also covers the burst-aware path below.
        if current_free_pct > 50.0 && estimate.confidence < 0.95 {
            return PredictiveAction::Clear;
        }

        // ── Burst-aware prediction gating ──
        // When the burst detector is calibrated and a burst is likely, use the
        // historical median rate (not the burst-inflated EWMA) for time projection.
        // This is the key fix: a 30-second rustc burst consuming 5GB/min will NOT
        // trigger "disk full in 1m" because the median rate shows it's transient.
        let bs = &estimate.burst_state;
        if bs.calibrated && bs.burst_probability > 0.5 {
            // Use median rate for time projection instead of burst-inflated EWMA.
            let median_minutes = if bs.median_rate > 0.0 {
                estimate.seconds_to_exhaustion * (estimate.bytes_per_second / bs.median_rate) / 60.0
            } else {
                f64::INFINITY
            };

            // If median-rate projection shows no danger, return Clear.
            if median_minutes > self.config.warning_horizon_minutes {
                return PredictiveAction::Clear;
            }

            // Take the more conservative (longer) estimate.
            let ewma_minutes = estimate.seconds_to_exhaustion / 60.0;
            let minutes_remaining = ewma_minutes.max(median_minutes);

            if !minutes_remaining.is_finite() || minutes_remaining < 0.0 {
                return PredictiveAction::Clear;
            }

            // Apply confidence penalty during bursts.
            let effective_confidence =
                estimate.confidence * 0.3f64.mul_add(-bs.burst_probability, 1.0);

            // Require higher confidence during bursts — use the configured burst
            // threshold, but never lower than the normal min_confidence.
            let burst_min_confidence = self
                .config
                .min_confidence
                .max(self.config.burst_min_confidence);
            if effective_confidence < burst_min_confidence {
                return PredictiveAction::Clear;
            }

            return self.classify(
                minutes_remaining,
                effective_confidence,
                estimate.bytes_per_second,
                estimate.trend,
                current_free_pct,
                mount,
            );
        }

        let minutes_remaining = estimate.seconds_to_exhaustion / 60.0;

        // Guard against infinite or nonsensical values.
        if !minutes_remaining.is_finite() || minutes_remaining < 0.0 {
            return PredictiveAction::Clear;
        }

        // Implied-rate sanity gate: when the predicted consumption rate implies
        // consuming a large fraction of free space per minute, the prediction
        // is almost certainly a transient EWMA spike (e.g. a rustc burst).
        // This gate is unconditional — it fires even before the burst
        // detector is calibrated, which is critical during the first 15+
        // minutes after daemon restart.
        //
        // Production evidence: vmi1264463 at 73% free predicted "disk full in
        // 53m" (86% conf, implied 1.4%/min), vmi1152480 at 35% free predicted
        // "disk full in 54m" (78% conf, implied 0.65%/min).
        if current_free_pct > 20.0 && minutes_remaining > self.config.imminent_danger_minutes {
            let implied_rate_pct_per_min = current_free_pct / minutes_remaining;
            // Two tiers:
            // 1. Moderate rate (>1%/min with >40% free): require 0.90+ confidence.
            //    Catches most false alarms from burst EWMA spikes.
            // 2. Extreme rate (>5%/min): require confidence proportional to severity.
            //    Catches remaining extreme cases even at lower free space.
            if implied_rate_pct_per_min > 1.0
                && current_free_pct > 40.0
                && estimate.confidence < 0.90
            {
                return PredictiveAction::Clear;
            }
            if implied_rate_pct_per_min > 5.0 {
                let severity = ((implied_rate_pct_per_min - 5.0) / 10.0).clamp(0.0, 1.0);
                let required = severity.mul_add(
                    0.95 - self.config.min_confidence,
                    self.config.min_confidence,
                );
                if estimate.confidence < required {
                    return PredictiveAction::Clear;
                }
            }
        }

        // Free-space sanity gate: when the burst detector is calibrated but
        // hasn't flagged a burst (probability < 0.5), and the implied
        // consumption rate is unrealistically high, the EWMA is likely
        // tracking a transient spike. Require higher confidence proportional
        // to the implied rate to suppress false "disk full in Xm" alarms.
        //
        // This specifically targets the production failure mode: 31% free,
        // "disk full in 5m" at 73% confidence — a rustc compilation burst
        // that the burst detector scored at 0.3 (below the 0.5 threshold).
        if bs.calibrated
            && bs.burst_probability < 0.5
            && current_free_pct > 20.0
            && minutes_remaining <= self.config.action_horizon_minutes
        {
            let implied_rate_pct_per_min = current_free_pct / minutes_remaining;
            // Gate kicks in above 5%/min implied consumption — that's consuming
            // 50% of a 1TB disk in 10 minutes, which is almost always a burst.
            if implied_rate_pct_per_min > 5.0 {
                let severity = ((implied_rate_pct_per_min - 5.0) / 10.0).clamp(0.0, 1.0);
                let required = severity.mul_add(
                    0.95 - self.config.min_confidence,
                    self.config.min_confidence,
                );
                if estimate.confidence < required {
                    return PredictiveAction::Clear;
                }
            }
        }

        // Median-rate cross-check: when the burst detector is calibrated and
        // we have plenty of free space (>25%), cross-validate the EWMA-based
        // prediction against the robust median rate. If the EWMA rate diverges
        // >3× from the median, the EWMA is tracking a transient spike.
        //
        // Production evidence: trj at 32% free predicted "disk full on /data
        // in 37m at 74% confidence" — burst_probability was only 0.3 (below
        // the 0.5 threshold for the burst-aware path), but the EWMA was
        // inflated by a rustc compilation burst. The median rate (which is
        // robust to outliers) showed no danger.
        if bs.calibrated
            && bs.median_rate > 0.0
            && current_free_pct > 25.0
            && minutes_remaining <= self.config.warning_horizon_minutes
        {
            let rate_divergence = estimate.bytes_per_second / bs.median_rate;
            if rate_divergence > 3.0 {
                // EWMA is >3× the robust median — likely spike-inflated.
                // Re-project using median rate: if median says no danger, gate it.
                let median_seconds = estimate.seconds_to_exhaustion * rate_divergence;
                let median_minutes = median_seconds / 60.0;
                if median_minutes > self.config.warning_horizon_minutes {
                    return PredictiveAction::Clear;
                }
                // Median also says danger — use the more conservative (longer) estimate.
                let conservative_minutes = minutes_remaining.max(median_minutes);
                return self.classify(
                    conservative_minutes,
                    estimate.confidence,
                    estimate.bytes_per_second,
                    estimate.trend,
                    current_free_pct,
                    mount,
                );
            }
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
            // Keep target recommendation policy-driven (15%..25%) instead of
            // collapsing to very low values under severe pressure.
            let _ = current_free_pct;
            let recommended_free_target_pct = lerp(15.0, 25.0, progress);

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
    use crate::monitor::ewma::{BurstState, Trend};

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
            sample_count: 10,
            confidence,
            trend,
            alpha_used: 0.3,
            fallback_active,
            burst_state: BurstState::default(),
        }
    }

    fn make_burst_estimate(
        bytes_per_second: f64,
        seconds_to_exhaustion: f64,
        confidence: f64,
        trend: Trend,
        burst_probability: f64,
        median_rate: f64,
    ) -> RateEstimate {
        RateEstimate {
            bytes_per_second,
            acceleration: 0.0,
            seconds_to_exhaustion,
            seconds_to_threshold: seconds_to_exhaustion * 0.8,
            sample_count: 10,
            confidence,
            trend,
            alpha_used: 0.3,
            fallback_active: false,
            burst_state: BurstState {
                burst_probability,
                median_rate,
                burst_duration_samples: 3,
                calibrated: true,
                ..BurstState::default()
            },
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
        let action = policy.evaluate(&est, 25.0, PathBuf::from("/data"));
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
        // Disk 78% full (22% free).
        let est = make_estimate(500_000_000.0, 20.0 * 60.0, 0.90, Trend::Accelerating, false);
        let action = policy.evaluate(&est, 22.0, PathBuf::from("/data"));
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
        let action = policy.evaluate(&est, 25.0, PathBuf::from("/data"));
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
        // 500 MB/s consumption, disk 80% full (20% free), ~28 minutes to exhaustion.
        let est = make_estimate(500_000_000.0, 28.0 * 60.0, 0.88, Trend::Accelerating, false);
        let action = policy.evaluate(&est, 20.0, PathBuf::from("/data"));
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
        assert!(
            PredictiveAction::Clear.severity()
                < PredictiveAction::EarlyWarning {
                    mount: PathBuf::from("/"),
                    minutes_remaining: 50.0,
                    confidence: 0.9,
                    rate_bytes_per_second: 100.0,
                    trend: Trend::Stable,
                }
                .severity()
        );

        assert!(
            PredictiveAction::EarlyWarning {
                mount: PathBuf::from("/"),
                minutes_remaining: 50.0,
                confidence: 0.9,
                rate_bytes_per_second: 100.0,
                trend: Trend::Stable,
            }
            .severity()
                < PredictiveAction::PreemptiveCleanup {
                    mount: PathBuf::from("/"),
                    minutes_remaining: 20.0,
                    confidence: 0.9,
                    rate_bytes_per_second: 100.0,
                    recommended_min_score: 0.5,
                    recommended_free_target_pct: 20.0,
                }
                .severity()
        );

        assert!(
            PredictiveAction::ImminentDanger {
                mount: PathBuf::from("/"),
                minutes_remaining: 4.0,
                critical: false,
            }
            .severity()
                < PredictiveAction::ImminentDanger {
                    mount: PathBuf::from("/"),
                    minutes_remaining: 1.0,
                    critical: true,
                }
                .severity()
        );
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
        assert!(
            !PredictiveAction::EarlyWarning {
                mount: PathBuf::from("/"),
                minutes_remaining: 50.0,
                confidence: 0.9,
                rate_bytes_per_second: 100.0,
                trend: Trend::Stable,
            }
            .should_cleanup()
        );
        assert!(
            PredictiveAction::PreemptiveCleanup {
                mount: PathBuf::from("/"),
                minutes_remaining: 20.0,
                confidence: 0.9,
                rate_bytes_per_second: 100.0,
                recommended_min_score: 0.5,
                recommended_free_target_pct: 20.0,
            }
            .should_cleanup()
        );
        assert!(
            PredictiveAction::ImminentDanger {
                mount: PathBuf::from("/"),
                minutes_remaining: 4.0,
                critical: false,
            }
            .should_cleanup()
        );
    }

    #[test]
    fn should_release_ballast_logic() {
        assert!(!PredictiveAction::Clear.should_release_ballast());
        assert!(
            !PredictiveAction::EarlyWarning {
                mount: PathBuf::from("/"),
                minutes_remaining: 50.0,
                confidence: 0.9,
                rate_bytes_per_second: 100.0,
                trend: Trend::Stable,
            }
            .should_release_ballast()
        );
        assert!(
            !PredictiveAction::PreemptiveCleanup {
                mount: PathBuf::from("/"),
                minutes_remaining: 20.0,
                confidence: 0.9,
                rate_bytes_per_second: 100.0,
                recommended_min_score: 0.5,
                recommended_free_target_pct: 20.0,
            }
            .should_release_ballast()
        );
        assert!(
            PredictiveAction::ImminentDanger {
                mount: PathBuf::from("/"),
                minutes_remaining: 4.0,
                critical: false,
            }
            .should_release_ballast()
        );
    }

    #[test]
    fn preemptive_aggressiveness_scales_linearly() {
        let policy = default_policy();

        // Near action horizon (30 min) — gentle.
        let gentle_est = make_estimate(100_000.0, 29.0 * 60.0, 0.90, Trend::Stable, false);
        let gentle = policy.evaluate(&gentle_est, 50.0, PathBuf::from("/data"));

        // Near imminent (6 min) — aggressive.
        let aggressive_est = make_estimate(100_000.0, 6.0 * 60.0, 0.90, Trend::Stable, false);
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
            _ => panic!(
                "both should be PreemptiveCleanup: gentle={gentle:?}, aggressive={aggressive:?}"
            ),
        }
    }

    #[test]
    fn low_current_free_still_recommends_reasonable_target_floor() {
        let policy = default_policy();
        // 20 minutes: within action horizon but above imminent danger.
        let est = make_estimate(250_000_000.0, 20.0 * 60.0, 0.90, Trend::Accelerating, false);

        let action = policy.evaluate(&est, 4.0, PathBuf::from("/data"));
        match action {
            PredictiveAction::PreemptiveCleanup {
                recommended_free_target_pct,
                ..
            } => {
                assert!(
                    recommended_free_target_pct >= 15.0,
                    "target should keep policy floor, got {recommended_free_target_pct}"
                );
            }
            other => panic!("expected PreemptiveCleanup, got {other:?}"),
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
            policy.evaluate(&est, 25.0, PathBuf::from("/data")),
            PredictiveAction::EarlyWarning { .. }
        ));

        // 8 min: within custom 10-min action, above custom 3-min imminent.
        let est2 = make_estimate(100_000.0, 8.0 * 60.0, 0.90, Trend::Stable, false);
        assert!(matches!(
            policy.evaluate(&est2, 25.0, PathBuf::from("/data")),
            PredictiveAction::PreemptiveCleanup { .. }
        ));

        // 2.5 min: below custom 3-min imminent, above custom 2-min critical.
        let est3 = make_estimate(100_000.0, 2.5 * 60.0, 0.90, Trend::Stable, false);
        assert!(matches!(
            policy.evaluate(&est3, 25.0, PathBuf::from("/data")),
            PredictiveAction::ImminentDanger {
                critical: false,
                ..
            }
        ));

        // 1.5 min: below custom 2-min critical threshold.
        let est4 = make_estimate(100_000.0, 1.5 * 60.0, 0.90, Trend::Stable, false);
        assert!(matches!(
            policy.evaluate(&est4, 25.0, PathBuf::from("/data")),
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

    #[test]
    fn burst_with_safe_median_returns_clear() {
        let policy = default_policy();
        // Burst: EWMA says 1 minute to exhaustion, but median rate (100 bytes/sec)
        // projects hours of runway. Should return Clear.
        let est = make_burst_estimate(
            500_000_000.0, // burst-inflated EWMA rate
            60.0,          // 1 minute to exhaustion per EWMA
            0.95,          // high confidence
            Trend::Stable,
            0.9,   // high burst probability
            100.0, // low median rate (steady baseline)
        );
        assert_eq!(
            policy.evaluate(&est, 80.0, PathBuf::from("/data")),
            PredictiveAction::Clear,
            "burst with safe median rate should return Clear"
        );
    }

    #[test]
    fn burst_gating_is_conservative_even_with_dangerous_median() {
        let policy = default_policy();
        // During a detected burst (bp > 0.5), the confidence penalty makes it
        // nearly impossible to pass the raised 0.85 confidence bar. This is
        // intentional: "false alarms are just as bad as misses."
        // The system will act once the burst subsides and bp drops below 0.5.
        let est = make_burst_estimate(
            500_000_000.0, // burst-inflated EWMA rate
            60.0,          // 1 minute to exhaustion per EWMA
            0.99,          // very high confidence
            Trend::Stable,
            0.6,           // moderate burst probability
            400_000_000.0, // median rate is also dangerous
        );
        // effective_confidence = 0.99 * (1 - 0.3 * 0.6) = 0.99 * 0.82 = 0.812 < 0.85
        let action = policy.evaluate(&est, 10.0, PathBuf::from("/data"));
        assert_eq!(
            action,
            PredictiveAction::Clear,
            "burst gating should be conservative — returns Clear during detected bursts"
        );

        // Without burst detection, the same rate triggers action.
        let est_no_burst = make_estimate(500_000_000.0, 60.0, 0.95, Trend::Stable, false);
        let action_no_burst = policy.evaluate(&est_no_burst, 10.0, PathBuf::from("/data"));
        assert!(
            action_no_burst.severity() >= 2,
            "without burst flag, dangerous rate should trigger action: got {action_no_burst:?}"
        );
    }

    #[test]
    fn low_burst_probability_uses_normal_path() {
        let policy = default_policy();
        // burst_probability below 0.5 threshold — normal path.
        let mut est = make_estimate(500_000_000.0, 60.0, 0.95, Trend::Accelerating, false);
        est.burst_state = BurstState {
            burst_probability: 0.3,
            median_rate: 100.0,
            burst_duration_samples: 1,
            calibrated: true,
            ..BurstState::default()
        };
        let action = policy.evaluate(&est, 10.0, PathBuf::from("/data"));
        // Normal path with 1 min left → ImminentDanger.
        assert!(matches!(action, PredictiveAction::ImminentDanger { .. }));
    }

    #[test]
    fn free_space_sanity_gate_blocks_false_alarms() {
        let policy = default_policy();
        // Simulate the production failure: 31% free, "disk full in 2 min",
        // 73% confidence, calibrated burst detector that scored 0.3 probability.
        let mut est = make_estimate(100_000.0, 2.0 * 60.0, 0.73, Trend::Stable, false);
        est.burst_state = BurstState {
            burst_probability: 0.3,
            median_rate: 1000.0,
            burst_duration_samples: 2,
            calibrated: true,
            ..BurstState::default()
        };
        let action = policy.evaluate(&est, 31.0, PathBuf::from("/data"));
        // Implied rate = 31%/2min = 15.5%/min > 5.
        // severity = (15.5-5)/10 = 1.0 (clamped), required = 0.7+0.25 = 0.95.
        // Confidence 0.73 < 0.95 → gated.
        assert_eq!(
            action,
            PredictiveAction::Clear,
            "should suppress false alarm: 31% free in 2 min with 73% confidence"
        );
    }

    #[test]
    fn free_space_gate_allows_high_confidence_predictions() {
        let policy = default_policy();
        // Same scenario but with very high confidence — should NOT be gated.
        let mut est = make_estimate(100_000.0, 3.0 * 60.0, 0.98, Trend::Accelerating, false);
        est.burst_state = BurstState {
            burst_probability: 0.1,
            median_rate: 1000.0,
            burst_duration_samples: 0,
            calibrated: true,
            ..BurstState::default()
        };
        let action = policy.evaluate(&est, 25.0, PathBuf::from("/data"));
        // Implied rate = 25%/3min = 8.3%/min > 5, but confidence 0.98 > required.
        assert!(
            action.severity() >= 3,
            "high-confidence prediction should not be gated: got {action:?}"
        );
    }

    #[test]
    fn free_space_gate_inactive_when_burst_uncalibrated() {
        let policy = default_policy();
        // Burst detector not calibrated — gate should not apply.
        let est = make_estimate(100_000.0, 4.0 * 60.0, 0.75, Trend::Stable, false);
        // Default BurstState has calibrated=false.
        let action = policy.evaluate(&est, 30.0, PathBuf::from("/data"));
        // Should use normal path without free-space gating.
        assert!(
            action.severity() >= 1,
            "uncalibrated burst detector should not trigger gate: got {action:?}"
        );
    }

    #[test]
    fn median_rate_crosscheck_gates_spike_inflated_ewma() {
        let policy = default_policy();
        // Production scenario: trj at 32% free, "disk full in 37m at 74%
        // confidence". EWMA rate is spike-inflated (10× median rate) from a
        // rustc burst, but burst_probability is only 0.3 (below 0.5 threshold).
        // The median rate (100 bytes/sec) projects hours of runway.
        let ewma_rate = 1000.0; // 10× the median
        let seconds_to_exhaustion = 37.0 * 60.0; // 37 minutes per EWMA
        let mut est = make_estimate(ewma_rate, seconds_to_exhaustion, 0.74, Trend::Stable, false);
        est.burst_state = BurstState {
            burst_probability: 0.3,
            median_rate: 100.0, // robust baseline: 10× lower than EWMA
            burst_duration_samples: 1,
            calibrated: true,
            ..BurstState::default()
        };
        // 32% free, EWMA diverges 10× from median → median projects 370 min → Clear.
        let action = policy.evaluate(&est, 32.0, PathBuf::from("/data"));
        assert_eq!(
            action,
            PredictiveAction::Clear,
            "spike-inflated EWMA should be gated by median-rate cross-check: got {action:?}"
        );
    }

    #[test]
    fn median_rate_crosscheck_allows_when_both_agree() {
        let policy = default_policy();
        // When EWMA and median rate agree (within 3×), normal path proceeds.
        let ewma_rate = 500.0;
        let seconds_to_exhaustion = 20.0 * 60.0; // 20 min
        let mut est = make_estimate(ewma_rate, seconds_to_exhaustion, 0.85, Trend::Stable, false);
        est.burst_state = BurstState {
            burst_probability: 0.1,
            median_rate: 300.0, // 1.67× — within the 3× threshold
            burst_duration_samples: 0,
            calibrated: true,
            ..BurstState::default()
        };
        let action = policy.evaluate(&est, 30.0, PathBuf::from("/data"));
        assert!(
            action.severity() >= 2,
            "agreeing rates should allow prediction: got {action:?}"
        );
    }

    #[test]
    fn median_rate_crosscheck_inactive_at_low_free_space() {
        let policy = default_policy();
        // When free space is low (<25%), the cross-check doesn't apply —
        // we need to act even if rates diverge.
        let mut est = make_estimate(1000.0, 10.0 * 60.0, 0.85, Trend::Stable, false);
        est.burst_state = BurstState {
            burst_probability: 0.2,
            median_rate: 100.0, // 10× divergence
            burst_duration_samples: 1,
            calibrated: true,
            ..BurstState::default()
        };
        // 15% free — cross-check should NOT gate.
        let action = policy.evaluate(&est, 15.0, PathBuf::from("/data"));
        assert!(
            action.severity() >= 2,
            "low free space should bypass median cross-check: got {action:?}"
        );
    }
}
