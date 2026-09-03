//! Adaptive conformal lower bounds on time-to-exhaustion.
//!
//! The EWMA forecaster hands out a point estimate of the seconds until a
//! mount crosses its red threshold. Acting on a point estimate has no
//! stated error rate. Split conformal prediction turns the history of
//! how much the forecaster under-predicted time into a lower bound
//! `tte_lo` that covers the true time-to-exhaustion with probability
//! `coverage_target`, without assuming a distribution for the fill rate.
//! Adaptive conformal inference (ACI) keeps that guarantee under
//! distribution shift (a build burst) by moving the miscoverage level
//! `alpha` after every resolved prediction:
//!
//! ```text
//! s_t        = max(0, tte_pred - tte_actual) / tte_pred        nonconformity: relative under-prediction of time
//! q          = the ceil((n + 1)(1 - alpha))-th smallest of the last n scores
//! tte_lo     = tte_pred * (1 - q)
//! err_t      = 1[tte_actual < tte_lo at issue]
//! alpha_t+1  = alpha_t + gamma * (alpha_target - err_t)          gamma 0.01, alpha_target 1 - coverage_target
//! ```
//!
//! What a prediction resolves against: it is enrolled when issued, then
//! either the threshold is crossed (`tte_actual` is the elapsed time) or
//! its own horizon passes without a crossing, which is a censored
//! observation counted as a score of zero (the forecaster was not too
//! optimistic). Predictions are only enrolled while the mount is filling
//! at a material rate and the point estimate is inside `horizon_cap`, so
//! an idle mount contributes nothing (idle neutrality), and every pending
//! prediction is discarded when an intervention (ballast release, a
//! reclaim) changes the trajectory it was made on.

use std::collections::VecDeque;
use std::time::Instant;

use serde::{Deserialize, Serialize};

/// Tunables of one calibrator (per mount).
#[derive(Debug, Clone, PartialEq)]
pub struct ConformalConfig {
    /// Resolved scores kept for the quantile (matches the guardrail window).
    pub window: usize,
    /// Resolved samples before the bound is trusted; below it `tte_lo` is
    /// the point estimate and the state is `Warming`.
    pub warmup: usize,
    /// ACI step size.
    pub gamma: f64,
    /// Target probability that `tte_actual >= tte_lo`.
    pub coverage_target: f64,
    /// Predictions further out than this are not enrolled: they would
    /// resolve too late to matter and would pin the pending queue.
    pub horizon_cap_secs: f64,
}

impl Default for ConformalConfig {
    fn default() -> Self {
        Self {
            window: 500,
            warmup: 30,
            gamma: 0.01,
            coverage_target: 0.90,
            horizon_cap_secs: 7200.0,
        }
    }
}

/// Whether the bound carries its guarantee yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    /// Fewer than `warmup` resolved samples: `tte_lo` is the point estimate.
    Warming,
    /// The bound is calibrated on the resolved window.
    Calibrated,
}

/// A point forecast with its conformal lower bound.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TteInterval {
    pub point_secs: f64,
    pub lo_secs: f64,
    /// The miscoverage level in force when the bound was computed.
    pub alpha: f64,
    pub coverage_state: CoverageState,
    /// Resolved samples in the window.
    pub samples: usize,
    /// Fraction of resolved predictions the bound covered; `None` while
    /// nothing has resolved.
    pub coverage_empirical: Option<f64>,
}

/// What one `observe` call resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResolvedBatch {
    /// Predictions resolved this tick.
    pub resolved: usize,
    /// Of those, how many the bound covered.
    pub covered: usize,
    /// Of those, how many fell short of the bound issued with them.
    pub missed: usize,
}

#[derive(Debug, Clone)]
struct Pending {
    issued_at: Instant,
    tte_pred: f64,
    lo_at_issue: f64,
}

/// Online split-conformal calibrator with the ACI update.
#[derive(Debug, Clone)]
pub struct ConformalCalibrator {
    config: ConformalConfig,
    scores: VecDeque<f64>,
    covered: VecDeque<bool>,
    pending: VecDeque<Pending>,
    alpha: f64,
    resolved_total: u64,
}

impl ConformalCalibrator {
    #[must_use]
    pub fn new(config: ConformalConfig) -> Self {
        let alpha = (1.0 - config.coverage_target).clamp(0.0, 1.0);
        Self {
            config,
            scores: VecDeque::new(),
            covered: VecDeque::new(),
            pending: VecDeque::new(),
            alpha,
            resolved_total: 0,
        }
    }

    #[must_use]
    pub fn config(&self) -> &ConformalConfig {
        &self.config
    }

    /// The miscoverage level in force.
    #[must_use]
    pub fn alpha(&self) -> f64 {
        self.alpha
    }

    /// Resolved scores in the window.
    #[must_use]
    pub fn samples(&self) -> usize {
        self.scores.len()
    }

    /// Predictions issued and not yet resolved.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Predictions resolved since the calibrator was created.
    #[must_use]
    pub fn resolved_total(&self) -> u64 {
        self.resolved_total
    }

    #[must_use]
    pub fn coverage_state(&self) -> CoverageState {
        if self.scores.len() < self.config.warmup {
            CoverageState::Warming
        } else {
            CoverageState::Calibrated
        }
    }

    /// Fraction of resolved predictions whose bound held, over the window.
    #[must_use]
    pub fn coverage_empirical(&self) -> Option<f64> {
        if self.covered.is_empty() {
            return None;
        }
        let hits = self.covered.iter().filter(|c| **c).count();
        Some(hits as f64 / self.covered.len() as f64)
    }

    /// The `(1 - alpha)` empirical quantile of the window with the
    /// finite-sample correction `ceil((n + 1)(1 - alpha))`; `1.0` (the most
    /// conservative bound, `tte_lo = 0`) when the window is empty.
    #[must_use]
    pub fn quantile(&self) -> f64 {
        let n = self.scores.len();
        if n == 0 {
            return 1.0;
        }
        let mut sorted: Vec<f64> = self.scores.iter().copied().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let level = (1.0 - self.alpha).clamp(0.0, 1.0);
        // `k` is 1-based; a level of 1 (alpha <= 0) selects the maximum.
        let k = ((n as f64 + 1.0) * level).ceil().clamp(1.0, n as f64) as usize;
        sorted[k - 1]
    }

    /// The bound for a point estimate: the point itself while warming,
    /// otherwise `tte_pred * (1 - q)`.
    #[must_use]
    pub fn lower_bound(&self, tte_pred: f64) -> TteInterval {
        let state = self.coverage_state();
        let lo = if !tte_pred.is_finite() || tte_pred < 0.0 {
            tte_pred
        } else if state == CoverageState::Warming {
            tte_pred
        } else {
            (tte_pred * (1.0 - self.quantile())).clamp(0.0, tte_pred)
        };
        TteInterval {
            point_secs: tte_pred,
            lo_secs: lo,
            alpha: self.alpha,
            coverage_state: state,
            samples: self.scores.len(),
            coverage_empirical: self.coverage_empirical(),
        }
    }

    /// Enroll a prediction issued now. Infinite, non-positive and
    /// beyond-cap estimates are not enrolled (idle neutrality: the caller
    /// passes `None`-equivalents for mounts below the material rate).
    pub fn enroll(&mut self, now: Instant, tte_pred: f64) -> bool {
        if !tte_pred.is_finite() || tte_pred <= 0.0 || tte_pred > self.config.horizon_cap_secs {
            return false;
        }
        let lo_at_issue = self.lower_bound(tte_pred).lo_secs;
        self.pending.push_back(Pending {
            issued_at: now,
            tte_pred,
            lo_at_issue,
        });
        // A pending queue bounded by the window keeps memory flat when a
        // mount stays pressured without ever crossing.
        while self.pending.len() > self.config.window {
            self.pending.pop_front();
        }
        true
    }

    /// Resolve pending predictions against what happened by `now`:
    /// `crossed` means the threshold was reached this tick, so every
    /// pending prediction learns its actual time; otherwise predictions
    /// whose own horizon has passed resolve as censored (score 0).
    pub fn observe(&mut self, now: Instant, crossed: bool) -> ResolvedBatch {
        let mut batch = ResolvedBatch::default();
        let mut keep = VecDeque::with_capacity(self.pending.len());
        while let Some(pending) = self.pending.pop_front() {
            let elapsed = now.saturating_duration_since(pending.issued_at).as_secs_f64();
            let outcome = if crossed {
                self.record(pending.tte_pred, elapsed, pending.lo_at_issue)
            } else if elapsed >= pending.tte_pred {
                // The horizon passed without a crossing: the true time is at
                // least the prediction.
                self.record(pending.tte_pred, pending.tte_pred, pending.lo_at_issue)
            } else {
                keep.push_back(pending);
                continue;
            };
            batch.resolved += 1;
            if outcome == Some(true) {
                batch.covered += 1;
            } else if outcome == Some(false) {
                batch.missed += 1;
            }
        }
        self.pending = keep;
        batch
    }

    /// Forget every pending prediction: an intervention (ballast release,
    /// a reclaim, a remount) changed the trajectory they were made on.
    pub fn discard_pending(&mut self) -> usize {
        let n = self.pending.len();
        self.pending.clear();
        n
    }

    /// Record one resolved prediction: push its score, note whether the
    /// bound issued with it held, and take the ACI step. Returns whether
    /// the bound covered the outcome (`None` for an unusable pair).
    pub fn record(&mut self, tte_pred: f64, tte_actual: f64, lo_at_issue: f64) -> Option<bool> {
        if !tte_pred.is_finite() || tte_pred <= 0.0 || !tte_actual.is_finite() {
            return None;
        }
        let score = ((tte_pred - tte_actual.max(0.0)) / tte_pred).clamp(0.0, 1.0);
        let err = tte_actual < lo_at_issue;
        self.scores.push_back(score);
        while self.scores.len() > self.config.window {
            self.scores.pop_front();
        }
        self.covered.push_back(!err);
        while self.covered.len() > self.config.window {
            self.covered.pop_front();
        }
        let target = (1.0 - self.config.coverage_target).clamp(0.0, 1.0);
        let err_value = if err { 1.0 } else { 0.0 };
        // ACI: alpha drifts up while predictions are covered (the bound can
        // afford to be tighter) and down on every miss. It may leave [0, 1]
        // briefly by design; `quantile` clamps the level it derives.
        self.alpha = self
            .config
            .gamma
            .mul_add(target - err_value, self.alpha)
            .clamp(-0.5, 1.0);
        self.resolved_total = self.resolved_total.saturating_add(1);
        Some(!err)
    }

    /// Start over (config reload with new coverage settings).
    pub fn reset(&mut self) {
        self.scores.clear();
        self.covered.clear();
        self.pending.clear();
        self.alpha = (1.0 - self.config.coverage_target).clamp(0.0, 1.0);
        self.resolved_total = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A small deterministic generator (xorshift) for reproducible noise.
    struct Rng(u64);

    impl Rng {
        fn next_f64(&mut self) -> f64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 >> 11) as f64 / (1u64 << 53) as f64
        }

        /// Uniform in `[lo, hi)`.
        fn uniform(&mut self, lo: f64, hi: f64) -> f64 {
            lo + (hi - lo) * self.next_f64()
        }
    }

    /// Drive `n` resolved predictions where the true time is
    /// `pred * factor(i)` plus noise; returns per-sample coverage flags.
    fn run(
        calibrator: &mut ConformalCalibrator,
        rng: &mut Rng,
        n: usize,
        factor: impl Fn(usize) -> f64,
    ) -> Vec<bool> {
        let mut covered = Vec::with_capacity(n);
        for i in 0..n {
            let pred = rng.uniform(300.0, 3600.0);
            let actual = pred * factor(i) * rng.uniform(0.7, 1.3);
            let lo = calibrator.lower_bound(pred).lo_secs;
            let _ = calibrator.record(pred, actual, lo);
            covered.push(actual >= lo);
        }
        covered
    }

    fn rate(flags: &[bool]) -> f64 {
        flags.iter().filter(|c| **c).count() as f64 / flags.len() as f64
    }

    #[test]
    fn coverage_on_iid_residuals_reaches_the_target() {
        let mut calibrator = ConformalCalibrator::new(ConformalConfig::default());
        let mut rng = Rng(0x2545_F491_4F6C_DD1D);
        let flags = run(&mut calibrator, &mut rng, 5_000, |_| 1.0);
        let after_warmup = &flags[1_000..];
        let coverage = rate(after_warmup);
        assert!(
            (coverage - 0.90).abs() <= 0.02,
            "coverage {coverage} after warm-up"
        );
        assert_eq!(calibrator.coverage_state(), CoverageState::Calibrated);
        let reported = calibrator.coverage_empirical().unwrap();
        assert!((reported - 0.90).abs() <= 0.03, "reported {reported}");
        assert!(calibrator.alpha() > 0.0 && calibrator.alpha() < 0.3, "{}", calibrator.alpha());
    }

    #[test]
    fn adaptive_alpha_recovers_from_a_rate_step_faster_than_a_fixed_alpha() {
        let seed = 0x9E37_79B9_7F4A_7C15;
        let mut adaptive = ConformalCalibrator::new(ConformalConfig::default());
        let mut fixed = ConformalCalibrator::new(ConformalConfig {
            gamma: 0.0,
            ..ConformalConfig::default()
        });
        let mut rng_a = Rng(seed);
        let mut rng_f = Rng(seed);
        // Calm regime, then the fill rate doubles: the true time halves.
        let _ = run(&mut adaptive, &mut rng_a, 1_000, |_| 1.0);
        let _ = run(&mut fixed, &mut rng_f, 1_000, |_| 1.0);
        let shifted_a = run(&mut adaptive, &mut rng_a, 100, |_| 0.5);
        let shifted_f = run(&mut fixed, &mut rng_f, 100, |_| 0.5);
        let misses_a = shifted_a.iter().filter(|c| !**c).count();
        let misses_f = shifted_f.iter().filter(|c| !**c).count();
        assert!(
            misses_a < misses_f,
            "adaptive missed {misses_a}, fixed missed {misses_f} in the 100 samples after the step"
        );
        // Within those 100 samples the adaptive bound is covering again.
        let tail = rate(&shifted_a[50..]);
        assert!(tail >= 0.80, "adaptive coverage over the last 50: {tail}");
        assert!(adaptive.alpha() < 0.10, "alpha tightened to {}", adaptive.alpha());
    }

    #[test]
    fn warming_returns_the_point_estimate_until_warmup() {
        let mut calibrator = ConformalCalibrator::new(ConformalConfig {
            warmup: 5,
            ..ConformalConfig::default()
        });
        for i in 0..4 {
            let interval = calibrator.lower_bound(600.0);
            assert_eq!(interval.coverage_state, CoverageState::Warming);
            assert_eq!(interval.lo_secs, 600.0, "sample {i}");
            let _ = calibrator.record(600.0, 400.0, interval.lo_secs);
        }
        assert_eq!(calibrator.lower_bound(600.0).coverage_state, CoverageState::Warming);
        let _ = calibrator.record(600.0, 400.0, 600.0);
        let interval = calibrator.lower_bound(600.0);
        assert_eq!(interval.coverage_state, CoverageState::Calibrated);
        // Every sample under-predicted by a third: the bound gives that back.
        assert!(
            (interval.lo_secs - 400.0).abs() < 1e-9,
            "lo {}",
            interval.lo_secs
        );
        assert_eq!(interval.samples, 5);
    }

    #[test]
    fn idle_and_far_predictions_are_not_enrolled_and_horizons_censor() {
        let mut calibrator = ConformalCalibrator::new(ConformalConfig {
            warmup: 1,
            ..ConformalConfig::default()
        });
        let t0 = Instant::now();
        assert!(!calibrator.enroll(t0, f64::INFINITY), "idle mount");
        assert!(!calibrator.enroll(t0, 0.0));
        assert!(!calibrator.enroll(t0, 10_000.0), "beyond the cap");
        assert!(calibrator.enroll(t0, 120.0));
        assert_eq!(calibrator.pending(), 1);
        // Half-way: nothing resolves.
        assert_eq!(calibrator.observe(t0 + Duration::from_secs(60), false).resolved, 0);
        // The horizon passes without a crossing: censored, score 0, covered.
        let censored = calibrator.observe(t0 + Duration::from_secs(121), false);
        assert_eq!((censored.resolved, censored.covered, censored.missed), (1, 1, 0));
        assert_eq!(calibrator.samples(), 1);
        assert_eq!(calibrator.coverage_empirical(), Some(1.0));
        assert_eq!(calibrator.quantile(), 0.0);
        // A crossing resolves every pending prediction with its elapsed time.
        assert!(calibrator.enroll(t0 + Duration::from_secs(200), 300.0));
        assert!(calibrator.enroll(t0 + Duration::from_secs(250), 300.0));
        let crossed = calibrator.observe(t0 + Duration::from_secs(350), true);
        assert_eq!(crossed.resolved, 2);
        assert_eq!(crossed.covered + crossed.missed, 2);
        assert_eq!(calibrator.pending(), 0);
        assert_eq!(calibrator.samples(), 3);
        // Predicted 300 s, took 150 s and 100 s: scores 0.5 and 2/3.
        let q = calibrator.quantile();
        assert!((q - 2.0 / 3.0).abs() < 1e-9, "q {q}");
        // An intervention drops what was pending.
        assert!(calibrator.enroll(t0 + Duration::from_secs(400), 300.0));
        assert_eq!(calibrator.discard_pending(), 1);
        assert_eq!(calibrator.pending(), 0);
    }

    #[test]
    fn the_bound_never_exceeds_the_point_estimate_or_drops_below_zero() {
        let mut calibrator = ConformalCalibrator::new(ConformalConfig {
            warmup: 1,
            ..ConformalConfig::default()
        });
        let mut rng = Rng(7);
        for _ in 0..2_000 {
            let pred = rng.uniform(1.0, 5_000.0);
            let actual = rng.uniform(0.0, 6_000.0);
            let interval = calibrator.lower_bound(pred);
            assert!(interval.lo_secs <= interval.point_secs + 1e-9, "{interval:?}");
            assert!(interval.lo_secs >= 0.0, "{interval:?}");
            let _ = calibrator.record(pred, actual, interval.lo_secs);
        }
        let interval = calibrator.lower_bound(f64::INFINITY);
        assert!(interval.lo_secs.is_infinite(), "no forecast, no bound");
        calibrator.reset();
        assert_eq!(calibrator.samples(), 0);
        assert_eq!(calibrator.coverage_state(), CoverageState::Warming);
        assert!((calibrator.alpha() - 0.10).abs() < 1e-12);
    }

    #[test]
    fn quantile_uses_the_finite_sample_correction() {
        let mut calibrator = ConformalCalibrator::new(ConformalConfig {
            warmup: 1,
            gamma: 0.0,
            ..ConformalConfig::default()
        });
        for score in [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9] {
            // actual = pred * (1 - score)
            let _ = calibrator.record(100.0, 100.0 * (1.0 - score), 0.0);
        }
        // n = 10, alpha = 0.1: k = ceil(11 * 0.9) = 10 -> the maximum.
        assert!((calibrator.quantile() - 0.9).abs() < 1e-9);
        assert!((calibrator.lower_bound(100.0).lo_secs - 10.0).abs() < 1e-9);
    }
}
