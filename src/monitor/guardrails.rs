//! Conformal and e-process guardrails for adaptive controller actions.
//!
//! Provides a statistical guard layer using:
//! - **Rolling calibration diagnostics**: tracks forecast quality via quantile coverage
//! - **E-process drift detection**: anytime-valid sequential test for overconfidence/distribution shift
//!
//! High-impact adaptive actions (aggressive cleanup, emergency escalation) are only allowed
//! when the guard status is PASS. On guard fail, the system falls back to conservative policy.

#![allow(clippy::cast_precision_loss)]

use std::collections::VecDeque;
use std::fmt;

use serde::Serialize;

// ──────────────────── guard status ────────────────────

/// Current status of the statistical guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardStatus {
    /// Calibration is verified; adaptive actions allowed.
    Pass,
    /// Insufficient data; conservative fallback enforced.
    Unknown,
    /// Calibration failed or drift detected; adaptive actions blocked.
    Fail,
}

impl GuardStatus {
    /// Whether adaptive actions are allowed.
    #[must_use]
    pub fn adaptive_allowed(self) -> bool {
        self == Self::Pass
    }
}

impl fmt::Display for GuardStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Unknown => write!(f, "UNKNOWN"),
            Self::Fail => write!(f, "FAIL"),
        }
    }
}

// ──────────────────── calibration observation ────────────────────

/// A single forecast-vs-actual observation for calibration tracking.
#[derive(Debug, Clone, Copy)]
pub struct CalibrationObservation {
    /// Predicted rate of disk usage change (bytes/sec).
    pub predicted_rate: f64,
    /// Actual observed rate of disk usage change (bytes/sec).
    pub actual_rate: f64,
    /// Predicted time-to-exhaustion (seconds).
    pub predicted_tte: f64,
    /// Actual time elapsed before threshold breach (seconds), or `f64::INFINITY` if no breach.
    pub actual_tte: f64,
    /// Whether this observation was taken during a detected burst (actual rate exceeds
    /// the MAD-based robust upper bound). During bursts, large prediction errors are
    /// expected behavior — the EWMA intentionally damps the spike. Marking these as
    /// burst outliers prevents them from poisoning the guard window and causing
    /// permanent Fail status on machines with bursty workloads (rustc, cargo, etc.).
    pub burst_outlier: bool,
}

impl CalibrationObservation {
    /// Directional rate error: only penalizes UNDERESTIMATION of disk consumption.
    ///
    /// For a cleanup system, overestimation (predicted > actual) is the safe direction:
    /// the system predicts more filling than reality, triggering earlier cleanup. Only
    /// underestimation (actual > predicted, disk fills faster than predicted) is dangerous.
    ///
    /// This prevents post-burst EWMA decay (predicted >> actual, EWMA still elevated
    /// while reality returns to baseline) from poisoning the guard. During this phase,
    /// the EWMA is correctly recovering — its overestimation is safe, not miscalibration.
    fn rate_danger_ratio(self) -> f64 {
        // Ignore errors when rates are trivial (< 10 bytes/sec) to prevent
        // floating-point noise and minor EWMA lag during idle periods from
        // triggering calibration failure. Production: trj had predicted≈-2,
        // actual≈0 producing infinite error from noise-level disagreement.
        if self.actual_rate.abs() < 10.0 && self.predicted_rate.abs() < 10.0 {
            return 0.0;
        }

        // Only penalize underestimation: actual consumption exceeds prediction.
        let underestimation = self.actual_rate - self.predicted_rate;
        if underestimation <= 0.0 {
            // EWMA overestimates or matches actual — safe direction for cleanup.
            return 0.0;
        }

        // Use max(|actual|, |predicted|) as denominator for bounded ratios.
        // This prevents infinity when actual ≈ 0 and predicted is negative
        // (EWMA recovery lag), while preserving meaningful ratios when both
        // rates are significant.
        let denominator = self
            .actual_rate
            .abs()
            .max(self.predicted_rate.abs())
            .max(1.0);
        underestimation / denominator
    }

    /// Whether the TTE prediction was conservative (predicted <= actual).
    /// A conservative prediction triggers cleanup early rather than late,
    /// which is the safe direction.
    fn tte_conservative(self) -> bool {
        self.predicted_tte <= self.actual_tte
    }
}

// ──────────────────── guard configuration ────────────────────

/// Configuration for the statistical guardrails.
#[derive(Debug, Clone)]
pub struct GuardrailConfig {
    /// Minimum observations before guard can transition to PASS.
    pub min_observations: usize,
    /// Rolling window size for calibration tracking.
    pub window_size: usize,
    /// Maximum acceptable rate error ratio for calibration (0.0-1.0).
    /// Below this threshold, the forecast is "well-calibrated".
    pub max_rate_error: f64,
    /// Minimum fraction of observations that must be conservative for TTE calibration.
    pub min_conservative_fraction: f64,
    /// E-process evidence threshold for triggering drift alarm.
    pub e_process_threshold: f64,
    /// E-process likelihood ratio for each miscalibrated observation.
    pub e_process_penalty: f64,
    /// E-process likelihood ratio for each well-calibrated observation.
    pub e_process_reward: f64,
    /// Consecutive clean windows required before recovery from FAIL to PASS.
    pub recovery_clean_windows: usize,
}

impl Default for GuardrailConfig {
    fn default() -> Self {
        Self {
            min_observations: 60,
            window_size: 500,
            max_rate_error: 0.30,
            min_conservative_fraction: 0.70,
            e_process_threshold: 20.0,
            e_process_penalty: 1.5,
            // Symmetric in log-space: ln(1/1.5) = -ln(1.5).
            // This ensures good observations recover as fast as bad ones accumulate,
            // preventing permanent drift alarm on machines with bursty workloads.
            e_process_reward: 2.0_f64 / 3.0,
            recovery_clean_windows: 3,
        }
    }
}

// ──────────────────── guard diagnostics ────────────────────

/// Diagnostic summary of the current guard state for explainability.
#[derive(Debug, Clone, Serialize)]
pub struct GuardDiagnostics {
    /// Current guard status.
    pub status: GuardStatus,
    /// Number of observations in the rolling window.
    pub observation_count: usize,
    /// Median absolute rate error ratio in the window.
    pub median_rate_error: f64,
    /// Fraction of TTE predictions that were conservative.
    pub conservative_fraction: f64,
    /// Current e-process evidence value (log scale).
    pub e_process_value: f64,
    /// Whether e-process alarm is active.
    pub e_process_alarm: bool,
    /// Consecutive clean calibration windows (for recovery tracking).
    pub consecutive_clean: usize,
    /// Human-readable reason for current status.
    pub reason: String,
}

// ──────────────────── adaptive guard ────────────────────

/// Statistical guardrail for adaptive controller actions.
///
/// Maintains a rolling window of calibration observations and an
/// e-process sequential test for drift detection.
pub struct AdaptiveGuard {
    config: GuardrailConfig,
    /// Rolling window of recent calibration observations.
    observations: VecDeque<CalibrationObservation>,
    /// E-process evidence accumulator (multiplicative, stored as log for stability).
    e_process_log: f64,
    /// Current guard status.
    status: GuardStatus,
    /// Consecutive clean calibration windows for recovery.
    consecutive_clean: usize,
}

impl AdaptiveGuard {
    /// Create a new guard with the given configuration.
    #[must_use]
    pub fn new(config: GuardrailConfig) -> Self {
        Self {
            config,
            observations: VecDeque::new(),
            e_process_log: 0.0,
            status: GuardStatus::Unknown,
            consecutive_clean: 0,
        }
    }

    /// Create a guard with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(GuardrailConfig::default())
    }

    /// Record a new forecast-vs-actual observation and update guard status.
    pub fn observe(&mut self, obs: CalibrationObservation) {
        // Burst outliers are always "good" for calibration purposes.
        // During bursts, the EWMA intentionally damps the spike, so the predicted
        // rate diverges from actual — this is correct adaptive behavior, not
        // miscalibration. Counting burst observations as failures causes the guard
        // to permanently fail on machines with bursty workloads (production: 600+
        // consecutive breach windows on machines running rustc compilations).
        let obs_good = obs.burst_outlier
            || (obs.rate_danger_ratio() <= self.config.max_rate_error && obs.tte_conservative());

        // Maintain rolling window.
        self.observations.push_back(obs);
        while self.observations.len() > self.config.window_size {
            self.observations.pop_front();
        }

        // Update e-process with the new observation.
        // Good observations get full reward; bad observations get proportional penalty
        // scaled by how far the rate_danger_ratio exceeds the threshold.
        // This prevents barely-bad observations (ratio=0.31 vs threshold=0.30)
        // from accumulating the same penalty as catastrophically-bad ones (ratio=1.0).
        let lr = if obs_good {
            self.config.e_process_reward.ln()
        } else {
            let ratio = obs.rate_danger_ratio();
            let severity = ((ratio - self.config.max_rate_error)
                / (1.0 - self.config.max_rate_error))
                .clamp(0.0, 1.0);
            // Scale: severity 0.0 → 30% of base penalty, severity 1.0 → 100%.
            let scale = 0.7f64.mul_add(severity, 0.3);
            self.config.e_process_penalty.ln() * scale
        };
        self.e_process_log += lr;
        // Clamp to ensure responsiveness.
        // - Lower bound (-5.0): prevents "banking" too much credit (exp(-5) ~ 0.0067),
        //   ensuring we can detect drift within ~10-15 bad observations.
        // - Upper bound (3.5): prevents prolonged alarm state (exp(3.5) ~ 33),
        //   ensuring we can recover within ~7 good observations after the anomaly passes.
        //   (Prior cap of 5.0 → exp(5)=148 caused prolonged FAIL on Green machines.)
        self.e_process_log = self.e_process_log.clamp(-5.0, 3.5);

        // Recompute guard status.
        self.recompute_status(obs_good);
    }

    /// Current guard status.
    #[must_use]
    pub fn status(&self) -> GuardStatus {
        self.status
    }

    /// Whether adaptive actions are currently allowed.
    #[must_use]
    pub fn adaptive_allowed(&self) -> bool {
        self.status.adaptive_allowed()
    }

    /// Get full diagnostic summary.
    #[must_use]
    pub fn diagnostics(&self) -> GuardDiagnostics {
        let (median_error, conservative_frac) = self.calibration_metrics();
        let e_val = self.e_process_log.exp();
        let alarm = e_val >= self.config.e_process_threshold;

        let reason = match self.status {
            GuardStatus::Pass => "Calibration verified; adaptive actions allowed".to_string(),
            GuardStatus::Unknown => format!(
                "Insufficient observations ({}/{})",
                self.observations.len(),
                self.config.min_observations
            ),
            GuardStatus::Fail => {
                if alarm {
                    format!("E-process drift alarm (evidence={e_val:.1})")
                } else if median_error > self.config.max_rate_error {
                    format!("Rate calibration failed (median error={median_error:.2})")
                } else {
                    format!("TTE coverage low ({:.1}%)", conservative_frac * 100.0)
                }
            }
        };

        GuardDiagnostics {
            status: self.status,
            observation_count: self.observations.len(),
            median_rate_error: median_error,
            conservative_fraction: conservative_frac,
            e_process_value: e_val,
            e_process_alarm: alarm,
            consecutive_clean: self.consecutive_clean,
            reason,
        }
    }

    /// Reset the guard to initial state (e.g., after config change).
    pub fn reset(&mut self) {
        self.observations.clear();
        self.e_process_log = 0.0;
        self.status = GuardStatus::Unknown;
        self.consecutive_clean = 0;
    }

    /// Number of observations in the current window.
    #[must_use]
    pub fn observation_count(&self) -> usize {
        self.observations.len()
    }

    fn recompute_status(&mut self, latest_obs_good: bool) {
        // Not enough data → Unknown.
        if self.observations.len() < self.config.min_observations {
            self.status = GuardStatus::Unknown;
            self.consecutive_clean = 0;
            return;
        }

        let (median_error, conservative_frac) = self.calibration_metrics();
        let e_val = self.e_process_log.exp();
        let alarm = e_val >= self.config.e_process_threshold;

        let calibrated = median_error <= self.config.max_rate_error
            && conservative_frac >= self.config.min_conservative_fraction
            && !alarm;

        match self.status {
            GuardStatus::Pass => {
                if !calibrated {
                    self.status = GuardStatus::Fail;
                    self.consecutive_clean = 0;
                }
            }
            GuardStatus::Unknown => {
                if calibrated {
                    self.status = GuardStatus::Pass;
                    self.consecutive_clean = self.config.recovery_clean_windows;
                } else {
                    self.status = GuardStatus::Fail;
                    self.consecutive_clean = 0;
                }
            }
            GuardStatus::Fail => {
                // Recovery tracks consecutive good individual observations,
                // not window-level calibration (window may still contain old bad data).
                if latest_obs_good && !alarm {
                    self.consecutive_clean += 1;
                    if self.consecutive_clean >= self.config.recovery_clean_windows {
                        self.status = GuardStatus::Pass;
                        // Reset e-process on recovery to give a clean start.
                        self.e_process_log = 0.0;
                    }
                } else {
                    self.consecutive_clean = 0;
                }
            }
        }
    }

    fn calibration_metrics(&self) -> (f64, f64) {
        // Exclude burst outlier observations from calibration metrics.
        // During bursts, both rate error and TTE are expected to diverge —
        // the EWMA intentionally damps the spike. Including them would
        // permanently skew the calibration window on bursty machines.
        let non_burst: Vec<&CalibrationObservation> = self
            .observations
            .iter()
            .filter(|o| !o.burst_outlier)
            .collect();

        if non_burst.is_empty() {
            // All observations are burst outliers (or no observations at all).
            // Return neutral metrics that won't trigger calibration failure.
            return (0.0, 1.0);
        }

        // Compute median rate danger (underestimation only).
        let mut errors: Vec<f64> = non_burst.iter().map(|o| o.rate_danger_ratio()).collect();
        errors.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median_error = if errors.len().is_multiple_of(2) {
            let mid = errors.len() / 2;
            f64::midpoint(errors[mid - 1], errors[mid])
        } else {
            errors[errors.len() / 2]
        };

        // Compute conservative TTE fraction (burst outliers excluded).
        let conservative_count = non_burst.iter().filter(|o| o.tte_conservative()).count();
        let conservative_frac = conservative_count as f64 / non_burst.len() as f64;

        (median_error, conservative_frac)
    }
}

// ──────────────────── action gating ────────────────────

/// Gate an adaptive action through the guard.
///
/// If the guard status is PASS, the action passes through unchanged.
/// If the guard status is FAIL or UNKNOWN, high-impact actions are downgraded
/// to conservative fallbacks.
#[must_use]
pub fn gate_action(guard: &AdaptiveGuard, is_high_impact: bool) -> ActionDecision {
    if !is_high_impact {
        return ActionDecision::Allow {
            reason: "low-impact action — no guard check needed",
        };
    }

    match guard.status() {
        GuardStatus::Pass => ActionDecision::Allow {
            reason: "guard PASS — adaptive action allowed",
        },
        GuardStatus::Unknown => ActionDecision::Fallback {
            reason: "guard UNKNOWN — insufficient calibration data, using conservative fallback",
        },
        GuardStatus::Fail => ActionDecision::Block {
            reason: "guard FAIL — drift or miscalibration detected, action blocked",
        },
    }
}

/// Decision from the action gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionDecision {
    /// Action is allowed to proceed.
    Allow {
        /// Human-readable explanation.
        reason: &'static str,
    },
    /// Action is blocked; use conservative fallback.
    Fallback {
        /// Human-readable explanation.
        reason: &'static str,
    },
    /// Action is blocked entirely.
    Block {
        /// Human-readable explanation.
        reason: &'static str,
    },
}

impl ActionDecision {
    /// Whether the action should proceed (either normally or via fallback).
    #[must_use]
    pub fn should_proceed(self) -> bool {
        !matches!(self, Self::Block { .. })
    }

    /// Whether the action should use the adaptive strategy (vs conservative).
    #[must_use]
    pub fn adaptive_ok(self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    /// Human-readable reason.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::Allow { reason } | Self::Fallback { reason } | Self::Block { reason } => reason,
        }
    }
}

// ──────────────────── prediction scorecard ────────────────────

/// Outcome category for a single prediction tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PredictionOutcome {
    /// Non-actionable prediction — not counted in false alarm rate.
    Inactive,
    /// Actionable prediction that was realized (pressure reached Red+).
    Realized,
    /// Actionable prediction where intervention occurred (cleanup ran) and pressure
    /// dropped. This is a SUCCESS, not a false alarm — the system did its job.
    Intervened,
    /// Actionable prediction with NO intervention that was NOT realized.
    /// This is a genuine false alarm — the system cried wolf.
    FalseAlarm,
}

/// Tracks recent predictions vs. outcomes to compute realized accuracy.
///
/// Solves the "self-defeating prophecy" problem: when an actionable prediction
/// triggers cleanup that prevents disk exhaustion, the naive approach records
/// it as a false alarm, gradually suppressing all predictions. Instead, this
/// scorecard tracks three outcomes:
/// - **Realized**: pressure actually hit the danger zone — prediction was correct.
/// - **Intervened**: cleanup ran and pressure dropped — prediction was correct AND
///   the system successfully prevented the problem.
/// - **FalseAlarm**: no cleanup ran but pressure never approached danger — prediction
///   was genuinely wrong.
///
/// Only `FalseAlarm` outcomes count toward the false alarm rate.
pub struct PredictionScorecard {
    outcomes: VecDeque<PredictionOutcome>,
    max_outcomes: usize,
}

impl PredictionScorecard {
    /// Create a new scorecard with the given history size.
    #[must_use]
    pub fn new(max_outcomes: usize) -> Self {
        Self {
            outcomes: VecDeque::with_capacity(max_outcomes.min(1024)),
            max_outcomes: max_outcomes.max(1),
        }
    }

    /// Record a prediction outcome.
    ///
    /// - `was_actionable`: true if the prediction had severity >= 2
    ///   (PreemptiveCleanup or ImminentDanger).
    /// - `was_realized`: true if the disk actually hit the threshold within
    ///   the predicted time window (pressure >= Red).
    /// - `cleanup_ran`: true if any cleanup was performed during this tick
    ///   (deletions dispatched or ballast released).
    pub fn record(&mut self, was_actionable: bool, was_realized: bool, cleanup_ran: bool) {
        let outcome = if !was_actionable {
            PredictionOutcome::Inactive
        } else if was_realized {
            PredictionOutcome::Realized
        } else if cleanup_ran {
            // Prediction triggered cleanup and pressure didn't hit Red.
            // This is the system working correctly, NOT a false alarm.
            PredictionOutcome::Intervened
        } else {
            // Prediction said danger, no cleanup ran, and pressure never hit Red.
            // This is a genuine false alarm.
            PredictionOutcome::FalseAlarm
        };
        self.outcomes.push_back(outcome);
        while self.outcomes.len() > self.max_outcomes {
            self.outcomes.pop_front();
        }
    }

    /// Fraction of actionable predictions that were genuine false alarms.
    ///
    /// Denominator is (Realized + Intervened + FalseAlarm). Numerator is FalseAlarm only.
    /// Intervened outcomes are excluded from the false alarm count because they
    /// represent successful predictions that prevented the problem.
    #[must_use]
    pub fn false_alarm_rate(&self) -> f64 {
        let mut total_actionable = 0usize;
        let mut false_alarms = 0usize;
        for outcome in &self.outcomes {
            match outcome {
                PredictionOutcome::Realized | PredictionOutcome::Intervened => {
                    total_actionable += 1;
                }
                PredictionOutcome::FalseAlarm => {
                    total_actionable += 1;
                    false_alarms += 1;
                }
                PredictionOutcome::Inactive => {}
            }
        }
        if total_actionable == 0 {
            return 0.0;
        }
        false_alarms as f64 / total_actionable as f64
    }

    /// Dynamically adjust min_confidence based on false alarm rate.
    ///
    /// When false alarm rate exceeds 30%, raises the effective min_confidence
    /// to reduce future false positives. The adjustment is proportional:
    /// - false_alarm_rate = 0%   → base_confidence unchanged
    /// - false_alarm_rate = 30%  → base_confidence unchanged (threshold)
    /// - false_alarm_rate = 60%  → base_confidence + 0.10
    /// - false_alarm_rate = 100% → base_confidence + 0.20 (capped at 0.95)
    #[must_use]
    pub fn dynamic_min_confidence(&self, base_confidence: f64) -> f64 {
        let far = self.false_alarm_rate();
        if far <= 0.30 {
            return base_confidence;
        }
        // Scale penalty: 0.30→0, 1.0→0.20.
        let penalty = ((far - 0.30) / 0.70) * 0.20;
        (base_confidence + penalty).min(0.95)
    }

    /// Number of outcomes recorded.
    #[must_use]
    pub fn outcome_count(&self) -> usize {
        self.outcomes.len()
    }
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn good_obs() -> CalibrationObservation {
        CalibrationObservation {
            predicted_rate: 100.0,
            actual_rate: 105.0,
            predicted_tte: 300.0,
            actual_tte: 320.0,
            burst_outlier: false,
        }
    }

    fn bad_obs() -> CalibrationObservation {
        CalibrationObservation {
            predicted_rate: 100.0,
            actual_rate: 200.0,
            predicted_tte: 300.0,
            actual_tte: 150.0,
            burst_outlier: false,
        }
    }

    fn conservative_obs() -> CalibrationObservation {
        CalibrationObservation {
            predicted_rate: 100.0,
            actual_rate: 105.0,
            predicted_tte: 200.0,
            actual_tte: 300.0,
            burst_outlier: false,
        }
    }

    #[test]
    fn guard_starts_unknown() {
        let guard = AdaptiveGuard::with_defaults();
        assert_eq!(guard.status(), GuardStatus::Unknown);
        assert!(!guard.adaptive_allowed());
    }

    #[test]
    fn guard_passes_with_good_calibration() {
        let config = GuardrailConfig {
            min_observations: 5,
            ..Default::default()
        };
        let mut guard = AdaptiveGuard::new(config);

        for _ in 0..5 {
            guard.observe(good_obs());
        }

        assert_eq!(guard.status(), GuardStatus::Pass);
        assert!(guard.adaptive_allowed());
    }

    #[test]
    fn guard_fails_with_bad_calibration() {
        let config = GuardrailConfig {
            min_observations: 5,
            ..Default::default()
        };
        let mut guard = AdaptiveGuard::new(config);

        for _ in 0..5 {
            guard.observe(bad_obs());
        }

        assert_eq!(guard.status(), GuardStatus::Fail);
        assert!(!guard.adaptive_allowed());
    }

    #[test]
    fn guard_unknown_with_insufficient_data() {
        let config = GuardrailConfig {
            min_observations: 10,
            ..Default::default()
        };
        let mut guard = AdaptiveGuard::new(config);

        for _ in 0..9 {
            guard.observe(good_obs());
        }

        assert_eq!(guard.status(), GuardStatus::Unknown);
    }

    #[test]
    fn e_process_detects_drift() {
        let config = GuardrailConfig {
            min_observations: 5,
            e_process_threshold: 10.0,
            e_process_penalty: 2.0,
            e_process_reward: 0.9,
            ..Default::default()
        };
        let mut guard = AdaptiveGuard::new(config);

        // First establish PASS with good observations.
        for _ in 0..5 {
            guard.observe(good_obs());
        }
        assert_eq!(guard.status(), GuardStatus::Pass);

        // Inject many bad observations to trigger e-process alarm.
        for _ in 0..20 {
            guard.observe(bad_obs());
        }

        assert_eq!(guard.status(), GuardStatus::Fail);
        let diag = guard.diagnostics();
        assert!(diag.e_process_alarm);
    }

    #[test]
    fn recovery_requires_clean_windows() {
        let config = GuardrailConfig {
            min_observations: 3,
            recovery_clean_windows: 3,
            e_process_threshold: 100.0, // high threshold to avoid e-process interference
            ..Default::default()
        };
        let mut guard = AdaptiveGuard::new(config);

        // Drive to FAIL.
        for _ in 0..5 {
            guard.observe(bad_obs());
        }
        assert_eq!(guard.status(), GuardStatus::Fail);

        // Two clean windows — not enough for recovery.
        for _ in 0..2 {
            guard.observe(good_obs());
        }
        assert_eq!(guard.status(), GuardStatus::Fail);

        // Third clean window triggers recovery.
        guard.observe(good_obs());
        assert_eq!(guard.status(), GuardStatus::Pass);
    }

    #[test]
    fn recovery_resets_on_bad_observation() {
        let config = GuardrailConfig {
            min_observations: 3,
            recovery_clean_windows: 3,
            e_process_threshold: 100.0,
            ..Default::default()
        };
        let mut guard = AdaptiveGuard::new(config);

        // Drive to FAIL.
        for _ in 0..5 {
            guard.observe(bad_obs());
        }

        // Two clean, then one bad — resets recovery counter.
        guard.observe(good_obs());
        guard.observe(good_obs());
        guard.observe(bad_obs());
        assert_eq!(guard.status(), GuardStatus::Fail);
        assert_eq!(guard.diagnostics().consecutive_clean, 0);
    }

    #[test]
    fn calibration_metrics_compute_correctly() {
        let config = GuardrailConfig {
            min_observations: 3,
            window_size: 10,
            ..Default::default()
        };
        let mut guard = AdaptiveGuard::new(config);

        // All conservative with small error.
        for _ in 0..5 {
            guard.observe(conservative_obs());
        }

        let diag = guard.diagnostics();
        assert!(diag.median_rate_error < 0.1);
        assert!((diag.conservative_fraction - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn window_rolls_correctly() {
        let config = GuardrailConfig {
            min_observations: 3,
            window_size: 5,
            ..Default::default()
        };
        let mut guard = AdaptiveGuard::new(config);

        // Fill window with good, then push bad ones.
        for _ in 0..5 {
            guard.observe(good_obs());
        }
        assert_eq!(guard.observation_count(), 5);

        for _ in 0..5 {
            guard.observe(bad_obs());
        }
        assert_eq!(guard.observation_count(), 5);

        // Window should now be all bad.
        let diag = guard.diagnostics();
        assert!(diag.median_rate_error > 0.3);
    }

    #[test]
    fn reset_clears_state() {
        let config = GuardrailConfig {
            min_observations: 3,
            ..Default::default()
        };
        let mut guard = AdaptiveGuard::new(config);

        for _ in 0..5 {
            guard.observe(good_obs());
        }
        assert_eq!(guard.status(), GuardStatus::Pass);

        guard.reset();
        assert_eq!(guard.status(), GuardStatus::Unknown);
        assert_eq!(guard.observation_count(), 0);
    }

    #[test]
    fn diagnostics_reason_is_informative() {
        let guard = AdaptiveGuard::with_defaults();
        let diag = guard.diagnostics();
        assert!(diag.reason.contains("Insufficient"));

        let mut guard2 = AdaptiveGuard::new(GuardrailConfig {
            min_observations: 3,
            ..Default::default()
        });
        for _ in 0..5 {
            guard2.observe(good_obs());
        }
        assert!(guard2.diagnostics().reason.contains("verified"));
    }

    #[test]
    fn gate_allows_low_impact_always() {
        let guard = AdaptiveGuard::with_defaults();
        let decision = gate_action(&guard, false);
        assert!(decision.should_proceed());
        assert!(decision.adaptive_ok());
    }

    #[test]
    fn gate_blocks_high_impact_when_unknown() {
        let guard = AdaptiveGuard::with_defaults();
        let decision = gate_action(&guard, true);
        assert!(decision.should_proceed()); // fallback, not full block
        assert!(!decision.adaptive_ok());
    }

    #[test]
    fn gate_blocks_high_impact_when_fail() {
        let config = GuardrailConfig {
            min_observations: 3,
            ..Default::default()
        };
        let mut guard = AdaptiveGuard::new(config);
        for _ in 0..5 {
            guard.observe(bad_obs());
        }

        let decision = gate_action(&guard, true);
        assert!(!decision.should_proceed());
        assert!(!decision.adaptive_ok());
    }

    #[test]
    fn gate_allows_high_impact_when_pass() {
        let config = GuardrailConfig {
            min_observations: 3,
            ..Default::default()
        };
        let mut guard = AdaptiveGuard::new(config);
        for _ in 0..5 {
            guard.observe(good_obs());
        }

        let decision = gate_action(&guard, true);
        assert!(decision.should_proceed());
        assert!(decision.adaptive_ok());
    }

    #[test]
    fn action_decision_reason_is_nonempty() {
        let guard = AdaptiveGuard::with_defaults();
        let d1 = gate_action(&guard, false);
        assert!(
            !d1.reason().is_empty(),
            "gate decision without a guard must carry a reason"
        );

        let d2 = gate_action(&guard, true);
        assert!(
            !d2.reason().is_empty(),
            "gate decision with a guard must carry a reason"
        );
    }

    #[test]
    fn rate_danger_ratio_overestimation_is_safe() {
        // predicted=100 but actual=0: EWMA overestimates consumption → safe direction.
        let obs = CalibrationObservation {
            predicted_rate: 100.0,
            actual_rate: 0.0,
            predicted_tte: 300.0,
            actual_tte: 300.0,
            burst_outlier: false,
        };
        assert!(
            (obs.rate_danger_ratio() - 0.0).abs() < f64::EPSILON,
            "overestimation should return 0 (safe direction)"
        );

        // predicted=-500 (EWMA says recovering) but actual≈0 (idle):
        // underestimation = 0 - (-500) = 500, denominator = max(0, 500, 1) = 500.
        // Ratio = 500/500 = 1.0 — bounded, not infinity.
        let obs2 = CalibrationObservation {
            predicted_rate: -500.0,
            actual_rate: 0.0,
            predicted_tte: f64::INFINITY,
            actual_tte: f64::INFINITY,
            burst_outlier: false,
        };
        let ratio = obs2.rate_danger_ratio();
        assert!(
            ratio.is_finite() && ratio <= 1.0,
            "idle-vs-recovery mismatch should produce bounded ratio: got {ratio}"
        );
    }

    #[test]
    fn rate_danger_ratio_handles_both_zero() {
        let obs = CalibrationObservation {
            predicted_rate: 0.0,
            actual_rate: 0.0,
            predicted_tte: 300.0,
            actual_tte: 300.0,
            burst_outlier: false,
        };
        assert!((obs.rate_danger_ratio() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn rate_danger_ratio_underestimation_penalized() {
        // actual=1000, predicted=100: EWMA underestimates consumption → dangerous.
        let obs = CalibrationObservation {
            predicted_rate: 100.0,
            actual_rate: 1000.0,
            predicted_tte: 300.0,
            actual_tte: 300.0,
            burst_outlier: false,
        };
        assert!(
            obs.rate_danger_ratio() > 0.30,
            "underestimation of 90% should exceed threshold"
        );
    }

    #[test]
    fn rate_danger_ratio_post_burst_decay_is_safe() {
        // Post-burst: EWMA still elevated at 5000, reality back to 10 bytes/sec.
        // This is EWMA correctly recovering, not miscalibration.
        let obs = CalibrationObservation {
            predicted_rate: 5000.0,
            actual_rate: 10.0,
            predicted_tte: 60.0,
            actual_tte: f64::INFINITY,
            burst_outlier: false,
        };
        assert!(
            (obs.rate_danger_ratio() - 0.0).abs() < f64::EPSILON,
            "post-burst EWMA decay (overestimation) should be safe"
        );
    }

    #[test]
    fn tte_conservative_classification() {
        let conservative = CalibrationObservation {
            predicted_rate: 100.0,
            actual_rate: 100.0,
            predicted_tte: 200.0,
            actual_tte: 300.0,
            burst_outlier: false,
        };
        assert!(conservative.tte_conservative());

        let non_conservative = CalibrationObservation {
            predicted_rate: 100.0,
            actual_rate: 100.0,
            predicted_tte: 400.0,
            actual_tte: 300.0,
            burst_outlier: false,
        };
        assert!(!non_conservative.tte_conservative());
    }

    #[test]
    fn e_process_log_clamps_at_floor() {
        let config = GuardrailConfig {
            min_observations: 3,
            e_process_reward: 0.1, // aggressive reward → fast log decay
            ..Default::default()
        };
        let mut guard = AdaptiveGuard::new(config);

        // Many good observations should drive e_process_log down but not below the clamp floor.
        for _ in 0..200 {
            guard.observe(good_obs());
        }

        assert!(
            guard.e_process_log >= -5.0,
            "e_process_log should be clamped at -5.0"
        );
    }

    #[test]
    fn guard_status_display() {
        assert_eq!(GuardStatus::Pass.to_string(), "PASS");
        assert_eq!(GuardStatus::Unknown.to_string(), "UNKNOWN");
        assert_eq!(GuardStatus::Fail.to_string(), "FAIL");
    }

    #[test]
    fn diagnostics_serializes_to_json() {
        let guard = AdaptiveGuard::with_defaults();
        let diag = guard.diagnostics();
        let json = serde_json::to_string(&diag).unwrap();
        assert!(json.contains("\"status\":\"unknown\""));
        assert!(json.contains("\"observation_count\":0"));
    }

    #[test]
    fn pass_to_fail_transition() {
        let config = GuardrailConfig {
            min_observations: 3,
            window_size: 5,
            ..Default::default()
        };
        let mut guard = AdaptiveGuard::new(config);

        // Establish PASS.
        for _ in 0..5 {
            guard.observe(good_obs());
        }
        assert_eq!(guard.status(), GuardStatus::Pass);

        // Push all bad observations to fill window and trigger FAIL.
        for _ in 0..5 {
            guard.observe(bad_obs());
        }
        assert_eq!(guard.status(), GuardStatus::Fail);
    }

    #[test]
    fn fail_recovery_resets_e_process() {
        let config = GuardrailConfig {
            min_observations: 3,
            recovery_clean_windows: 2,
            e_process_threshold: 100.0,
            ..Default::default()
        };
        let mut guard = AdaptiveGuard::new(config);

        // Drive to FAIL.
        for _ in 0..5 {
            guard.observe(bad_obs());
        }
        assert_eq!(guard.status(), GuardStatus::Fail);

        // Recover.
        for _ in 0..2 {
            guard.observe(good_obs());
        }
        assert_eq!(guard.status(), GuardStatus::Pass);

        // After recovery, e-process should be reset to 0.
        assert!((guard.e_process_log - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn rate_danger_ratio_ignores_idle_noise() {
        let obs = CalibrationObservation {
            predicted_rate: 0.5, // Tiny noise
            actual_rate: 0.0,    // Idle
            predicted_tte: 300.0,
            actual_tte: 300.0,
            burst_outlier: false,
        };
        assert!((obs.rate_danger_ratio() - 0.0).abs() < f64::EPSILON);

        let obs2 = CalibrationObservation {
            predicted_rate: 0.0,
            actual_rate: 0.5, // Tiny noise
            predicted_tte: 300.0,
            actual_tte: 300.0,
            burst_outlier: false,
        };
        assert!((obs2.rate_danger_ratio() - 0.0).abs() < f64::EPSILON);

        // Production case: EWMA at -2 bytes/sec (slight recovery), actual idle.
        // Both rates < 10 bytes/sec → trivial noise, should return 0.
        let obs3 = CalibrationObservation {
            predicted_rate: -2.0,
            actual_rate: 0.0,
            predicted_tte: f64::INFINITY,
            actual_tte: f64::INFINITY,
            burst_outlier: false,
        };
        assert!((obs3.rate_danger_ratio() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn burst_outlier_observations_do_not_trigger_fail() {
        // Simulate production scenario: guard is at PASS, then a burst hits.
        // Burst observations have huge rate error (predicted=100, actual=50000)
        // but are marked as burst_outlier=true. Guard should stay at PASS.
        let config = GuardrailConfig {
            min_observations: 5,
            ..Default::default()
        };
        let mut guard = AdaptiveGuard::new(config);

        // Establish PASS with good observations.
        for _ in 0..10 {
            guard.observe(good_obs());
        }
        assert_eq!(guard.status(), GuardStatus::Pass);

        // Inject 20 burst outlier observations with massive rate error.
        for _ in 0..20 {
            guard.observe(CalibrationObservation {
                predicted_rate: 100.0,
                actual_rate: 50_000.0, // 500× error — normally fatal for guard
                predicted_tte: 300.0,
                actual_tte: 5.0,     // non-conservative
                burst_outlier: true, // but it's a known burst
            });
        }

        // Guard should still be PASS — burst outliers count as "good".
        assert_eq!(
            guard.status(),
            GuardStatus::Pass,
            "burst outlier observations should not trigger guard failure"
        );
    }

    #[test]
    fn burst_outlier_false_still_penalizes() {
        // Same scenario but burst_outlier=false — guard should fail.
        let config = GuardrailConfig {
            min_observations: 5,
            window_size: 30,
            ..Default::default()
        };
        let mut guard = AdaptiveGuard::new(config);

        for _ in 0..10 {
            guard.observe(good_obs());
        }
        assert_eq!(guard.status(), GuardStatus::Pass);

        for _ in 0..20 {
            guard.observe(CalibrationObservation {
                predicted_rate: 100.0,
                actual_rate: 50_000.0,
                predicted_tte: 300.0,
                actual_tte: 5.0,
                burst_outlier: false, // NOT a burst — should count as bad
            });
        }

        assert_eq!(
            guard.status(),
            GuardStatus::Fail,
            "non-burst bad observations should trigger guard failure"
        );
    }

    #[test]
    fn guard_recovers_after_burst_with_ewma_decay() {
        // Simulate the production scenario: guard is at PASS, burst hits (burst_outlier
        // marks it good), then EWMA decays slowly (predicted >> actual, not burst_outlier).
        // With directional error, the post-burst decay is safe (overestimation) and
        // should NOT cause guard to enter FAIL.
        let config = GuardrailConfig {
            min_observations: 5,
            ..Default::default()
        };
        let mut guard = AdaptiveGuard::new(config);

        // Establish PASS with good observations.
        for _ in 0..10 {
            guard.observe(good_obs());
        }
        assert_eq!(guard.status(), GuardStatus::Pass);

        // Burst phase: actual >> predicted, but marked as burst_outlier.
        for _ in 0..5 {
            guard.observe(CalibrationObservation {
                predicted_rate: 100.0,
                actual_rate: 50_000.0,
                predicted_tte: 300.0,
                actual_tte: 5.0,
                burst_outlier: true,
            });
        }
        assert_eq!(
            guard.status(),
            GuardStatus::Pass,
            "burst_outlier should keep PASS"
        );

        // Post-burst EWMA decay: predicted still elevated, actual back to baseline.
        // These are NOT burst outliers (actual rate is low). With the old symmetric
        // rate_error_ratio, these would be "bad" (huge error) and cause FAIL.
        // With directional rate_danger_ratio, these are "good" (overestimation is safe).
        for _ in 0..20 {
            guard.observe(CalibrationObservation {
                predicted_rate: 5000.0,    // EWMA still elevated
                actual_rate: 10.0,         // reality: disk idle
                predicted_tte: 60.0,       // EWMA predicts filling
                actual_tte: f64::INFINITY, // reality: not filling
                burst_outlier: false,      // NOT a burst outlier (actual is low)
            });
        }

        assert_eq!(
            guard.status(),
            GuardStatus::Pass,
            "post-burst EWMA decay (overestimation) should not cause guard FAIL"
        );
    }

    #[test]
    fn e_process_symmetric_recovery() {
        // With symmetric penalty/reward, recovery from max clamp should take
        // the same number of observations as it took to reach max clamp.
        let config = GuardrailConfig {
            min_observations: 3,
            recovery_clean_windows: 1,
            ..Default::default()
        };
        let mut guard = AdaptiveGuard::new(config);

        // Drive to FAIL with bad observations.
        for _ in 0..5 {
            guard.observe(bad_obs());
        }
        assert_eq!(guard.status(), GuardStatus::Fail);

        // Count how many good observations to recover.
        // With symmetric rewards, 5 bad + 5 good should bring e_process_log ~0.
        let mut count = 0;
        for _ in 0..20 {
            guard.observe(good_obs());
            count += 1;
            if guard.status() == GuardStatus::Pass {
                break;
            }
        }
        // Should recover within a small number of observations. With proportional penalty
        // (bad_obs has severity ~0.5), 5 bad obs accumulate ~1.0 in e_process_log. Recovery
        // takes ~3 good observations to zero out + 1 for recovery_clean_windows=1.
        assert!(
            count <= 10,
            "e_process should allow recovery within 10 observations, took {count}"
        );
    }

    #[test]
    fn scorecard_false_alarm_rate_tracks_correctly() {
        let mut sc = PredictionScorecard::new(100);
        // 10 actionable predictions: 7 realized, 3 false alarms (no cleanup, no realization).
        for _ in 0..7 {
            sc.record(true, true, false); // actionable + realized
        }
        for _ in 0..3 {
            sc.record(true, false, false); // actionable + NOT realized + no cleanup = false alarm
        }
        let far = sc.false_alarm_rate();
        assert!(
            (far - 0.3).abs() < 0.01,
            "expected ~0.30 false alarm rate, got {far}"
        );
    }

    #[test]
    fn scorecard_intervention_is_not_false_alarm() {
        let mut sc = PredictionScorecard::new(100);
        // 10 actionable predictions where cleanup ran and pressure dropped.
        // These are successful interventions, NOT false alarms.
        for _ in 0..10 {
            sc.record(true, false, true); // actionable + not realized + cleanup ran
        }
        assert!(
            (sc.false_alarm_rate() - 0.0).abs() < f64::EPSILON,
            "interventions should not count as false alarms, got {}",
            sc.false_alarm_rate(),
        );
    }

    #[test]
    fn scorecard_mixed_outcomes() {
        let mut sc = PredictionScorecard::new(100);
        for _ in 0..3 {
            sc.record(true, true, false); // realized
        }
        for _ in 0..4 {
            sc.record(true, false, true); // intervened (success)
        }
        for _ in 0..3 {
            sc.record(true, false, false); // false alarm
        }
        // 10 actionable total, 3 false alarms → 30%.
        let far = sc.false_alarm_rate();
        assert!(
            (far - 0.3).abs() < 0.01,
            "expected ~0.30 with interventions excluded, got {far}"
        );
    }

    #[test]
    fn scorecard_no_actionable_returns_zero() {
        let mut sc = PredictionScorecard::new(100);
        // Only non-actionable predictions.
        for _ in 0..10 {
            sc.record(false, false, false);
        }
        assert!((sc.false_alarm_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn scorecard_dynamic_confidence_raises_on_high_false_alarms() {
        let mut sc = PredictionScorecard::new(100);
        // 100% false alarm rate (no cleanup, no realization).
        for _ in 0..10 {
            sc.record(true, false, false);
        }
        let base = 0.70;
        let adjusted = sc.dynamic_min_confidence(base);
        assert!(
            adjusted > base,
            "confidence should be raised: base={base}, adjusted={adjusted}"
        );
        assert!(adjusted <= 0.95, "should be capped at 0.95: {adjusted}");
    }

    #[test]
    fn scorecard_dynamic_confidence_unchanged_below_threshold() {
        let mut sc = PredictionScorecard::new(100);
        // 20% false alarm rate (below 30% threshold).
        for _ in 0..8 {
            sc.record(true, true, false);
        }
        for _ in 0..2 {
            sc.record(true, false, false);
        }
        let base = 0.70;
        let adjusted = sc.dynamic_min_confidence(base);
        assert!(
            (adjusted - base).abs() < f64::EPSILON,
            "confidence should be unchanged: base={base}, adjusted={adjusted}"
        );
    }

    #[test]
    fn default_guardrail_config_larger_windows() {
        let config = GuardrailConfig::default();
        assert_eq!(config.min_observations, 60, "min_observations should be 60");
        assert_eq!(config.window_size, 500, "window_size should be 500");
    }
}
