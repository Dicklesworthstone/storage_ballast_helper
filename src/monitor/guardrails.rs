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
}

impl CalibrationObservation {
    /// Absolute relative error of the rate prediction.
    fn rate_error_ratio(self) -> f64 {
        if self.actual_rate.abs() < 1e-9 {
            if self.predicted_rate.abs() < 1e-9 {
                return 0.0;
            }
            return f64::INFINITY;
        }
        ((self.predicted_rate - self.actual_rate) / self.actual_rate).abs()
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
            min_observations: 10,
            window_size: 50,
            max_rate_error: 0.30,
            min_conservative_fraction: 0.70,
            e_process_threshold: 20.0,
            e_process_penalty: 1.5,
            e_process_reward: 0.8,
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
        let obs_good =
            obs.rate_error_ratio() <= self.config.max_rate_error && obs.tte_conservative();

        // Maintain rolling window.
        self.observations.push_back(obs);
        while self.observations.len() > self.config.window_size {
            self.observations.pop_front();
        }

        // Update e-process with the new observation.
        let lr = if obs_good {
            self.config.e_process_reward.ln()
        } else {
            self.config.e_process_penalty.ln()
        };
        self.e_process_log += lr;
        // Clamp to prevent numerical underflow.
        if self.e_process_log < -50.0 {
            self.e_process_log = -50.0;
        }

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
                    format!("TTE coverage low ({conservative_frac:.1}%)")
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
        if self.observations.is_empty() {
            return (f64::INFINITY, 0.0);
        }

        // Compute median rate error.
        let mut errors: Vec<f64> = self
            .observations
            .iter()
            .map(|o| o.rate_error_ratio())
            .collect();
        errors.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median_error = if errors.len() % 2 == 0 {
            let mid = errors.len() / 2;
            f64::midpoint(errors[mid - 1], errors[mid])
        } else {
            errors[errors.len() / 2]
        };

        // Compute conservative TTE fraction.
        let conservative_count = self
            .observations
            .iter()
            .filter(|o| o.tte_conservative())
            .count();
        let conservative_frac = conservative_count as f64 / self.observations.len() as f64;

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
        }
    }

    fn bad_obs() -> CalibrationObservation {
        CalibrationObservation {
            predicted_rate: 100.0,
            actual_rate: 200.0,
            predicted_tte: 300.0,
            actual_tte: 150.0,
        }
    }

    fn conservative_obs() -> CalibrationObservation {
        CalibrationObservation {
            predicted_rate: 100.0,
            actual_rate: 105.0,
            predicted_tte: 200.0,
            actual_tte: 300.0,
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
        assert!(!d1.reason().is_empty());

        let d2 = gate_action(&guard, true);
        assert!(!d2.reason().is_empty());
    }

    #[test]
    fn rate_error_ratio_handles_zero_actual() {
        let obs = CalibrationObservation {
            predicted_rate: 100.0,
            actual_rate: 0.0,
            predicted_tte: 300.0,
            actual_tte: 300.0,
        };
        assert!(obs.rate_error_ratio().is_infinite());
    }

    #[test]
    fn rate_error_ratio_handles_both_zero() {
        let obs = CalibrationObservation {
            predicted_rate: 0.0,
            actual_rate: 0.0,
            predicted_tte: 300.0,
            actual_tte: 300.0,
        };
        assert!((obs.rate_error_ratio() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn tte_conservative_classification() {
        let conservative = CalibrationObservation {
            predicted_rate: 100.0,
            actual_rate: 100.0,
            predicted_tte: 200.0,
            actual_tte: 300.0,
        };
        assert!(conservative.tte_conservative());

        let non_conservative = CalibrationObservation {
            predicted_rate: 100.0,
            actual_rate: 100.0,
            predicted_tte: 400.0,
            actual_tte: 300.0,
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

        // Many good observations should drive e_process_log down but not below -50.
        for _ in 0..200 {
            guard.observe(good_obs());
        }

        assert!(guard.e_process_log >= -50.0);
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
}
