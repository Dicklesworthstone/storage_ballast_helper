//! EWMA rate estimator: disk usage velocity, acceleration, time-to-exhaustion prediction.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::collections::VecDeque;
use std::time::Instant;

/// Trend classification for disk pressure dynamics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trend {
    Stable,
    Accelerating,
    Decelerating,
    Recovering,
}

/// Burst detection state derived from historical rate analysis.
#[derive(Debug, Clone)]
pub struct BurstState {
    /// Probability that the current workload is a transient burst [0.0, 1.0].
    pub burst_probability: f64,
    /// Median instantaneous rate from the history buffer (long-term baseline bytes/sec).
    pub median_rate: f64,
    /// Consecutive recent samples that exceeded 3× the median rate.
    pub burst_duration_samples: u32,
    /// Whether enough history has accumulated (30+ samples) for reliable burst detection.
    pub calibrated: bool,
    /// MAD (Median Absolute Deviation) of rates × 1.4826 (Gaussian consistency factor).
    /// Robust scale estimate: unaffected by burst outliers unlike standard deviation.
    pub mad_rate: f64,
    /// Robust upper bound = median_rate + 3 × mad_rate.
    /// Observations with rates above this are burst outliers and should be discounted
    /// by downstream calibration systems (guard, predictive).
    pub robust_upper_bound: f64,
}

impl Default for BurstState {
    fn default() -> Self {
        Self {
            burst_probability: 0.0,
            median_rate: 0.0,
            burst_duration_samples: 0,
            calibrated: false,
            mad_rate: 0.0,
            robust_upper_bound: f64::INFINITY,
        }
    }
}

impl BurstState {
    /// Whether the given rate is a burst outlier (above robust upper bound).
    #[must_use]
    pub fn is_burst_outlier(&self, rate: f64) -> bool {
        self.calibrated && rate.abs() > self.robust_upper_bound
    }
}

/// Output of the EWMA estimator.
#[derive(Debug, Clone)]
pub struct RateEstimate {
    pub bytes_per_second: f64,
    pub acceleration: f64,
    pub seconds_to_exhaustion: f64,
    pub seconds_to_threshold: f64,
    pub sample_count: u64,
    pub confidence: f64,
    pub trend: Trend,
    pub alpha_used: f64,
    pub fallback_active: bool,
    /// Burst detection state from historical rate analysis.
    pub burst_state: BurstState,
}

#[derive(Debug, Clone, Copy)]
struct SampleState {
    free_bytes: u64,
    at: Instant,
    #[allow(dead_code)]
    inst_rate: f64,
}

/// Default capacity for the rate history ring buffer used by burst detection.
pub const DEFAULT_RATE_HISTORY_CAP: usize = 200;

/// Minimum samples in rate_history before burst detection is considered calibrated.
pub const BURST_CALIBRATION_MIN: usize = 30;

/// Online EWMA estimator with adaptive alpha and fallback signaling.
#[derive(Debug, Clone)]
pub struct DiskRateEstimator {
    base_alpha: f64,
    min_alpha: f64,
    max_alpha: f64,
    ewma_rate: f64,
    ewma_accel: f64,
    residual_ewma: f64,
    /// EWMA of normalized prediction jitter (|Δprediction| / max(prediction, 60s)).
    prediction_jitter_ewma: f64,
    /// Previous seconds_to_threshold for computing prediction jitter.
    last_predicted_secs: Option<f64>,
    min_samples: u64,
    samples: u64,
    last: Option<SampleState>,
    /// Ring buffer of recent instantaneous rates for burst detection.
    rate_history: VecDeque<f64>,
    /// Maximum size of the rate_history ring buffer.
    rate_history_cap: usize,
    /// Count of consecutive recent samples exceeding 3× the median rate.
    burst_duration_samples: u32,
}

impl DiskRateEstimator {
    #[must_use]
    pub fn new(base_alpha: f64, min_alpha: f64, max_alpha: f64, min_samples: u64) -> Self {
        Self::with_history_cap(
            base_alpha,
            min_alpha,
            max_alpha,
            min_samples,
            DEFAULT_RATE_HISTORY_CAP,
        )
    }

    /// Create an estimator with a custom rate history buffer size for burst detection.
    #[must_use]
    pub fn with_history_cap(
        base_alpha: f64,
        min_alpha: f64,
        max_alpha: f64,
        min_samples: u64,
        rate_history_cap: usize,
    ) -> Self {
        Self {
            base_alpha,
            min_alpha,
            max_alpha,
            ewma_rate: 0.0,
            ewma_accel: 0.0,
            residual_ewma: 0.0,
            prediction_jitter_ewma: 0.0,
            last_predicted_secs: None,
            min_samples,
            samples: 0,
            last: None,
            rate_history: VecDeque::with_capacity(rate_history_cap.min(1024)),
            rate_history_cap: rate_history_cap.max(1),
            burst_duration_samples: 0,
        }
    }

    /// Update estimator parameters at runtime (e.g. after config reload).
    pub fn update_params(
        &mut self,
        base_alpha: f64,
        min_alpha: f64,
        max_alpha: f64,
        min_samples: u64,
    ) {
        self.base_alpha = base_alpha;
        self.min_alpha = min_alpha;
        self.max_alpha = max_alpha;
        self.min_samples = min_samples;
    }

    /// Update estimator state with a new free-bytes sample.
    ///
    /// `threshold_free_bytes` should be the configured red threshold in bytes.
    pub fn update(
        &mut self,
        free_bytes: u64,
        observed_at: Instant,
        threshold_free_bytes: u64,
    ) -> RateEstimate {
        let Some(previous) = self.last else {
            self.last = Some(SampleState {
                free_bytes,
                at: observed_at,
                inst_rate: 0.0,
            });
            return self.fallback_estimate(free_bytes, threshold_free_bytes);
        };

        let Some(dt_duration) = observed_at.checked_duration_since(previous.at) else {
            // Out-of-order timestamps can happen under clock jitter or caller
            // scheduling races. Fail safe instead of panicking.
            return self.fallback_estimate(free_bytes, threshold_free_bytes);
        };
        let dt = dt_duration.as_secs_f64();
        if dt <= 1e-6 {
            return self.fallback_estimate(free_bytes, threshold_free_bytes);
        }

        let consumed = previous.free_bytes as f64 - free_bytes as f64;
        let inst_rate = consumed / dt;
        let burstiness = ((inst_rate - self.ewma_rate).abs()) / (self.ewma_rate.abs() + 1.0);
        // Damp alpha during bursts: high burstiness → lower alpha → stickier EWMA.
        // burstiness=0 (steady): alpha=base_alpha (~0.30).
        // burstiness=5 (burst):  alpha≈base_alpha/11 → clamped to min_alpha (~0.10).
        let damping = 1.0 / 2.0f64.mul_add(burstiness, 1.0);
        let alpha = (self.base_alpha * damping).clamp(self.min_alpha, self.max_alpha);

        // Compute residual BEFORE updating ewma_rate so it measures
        // prediction error of the previous estimate.
        self.residual_ewma = ewma(
            alpha,
            self.residual_ewma,
            (inst_rate - self.ewma_rate).abs(),
        );
        let prev_ewma_rate = self.ewma_rate;
        self.ewma_rate = ewma(alpha, self.ewma_rate, inst_rate);
        // Compute acceleration from EWMA-smoothed rate change, not raw
        // instantaneous rates. This eliminates noise amplification when the
        // polling interval varies (e.g., PID changes poll from 4s to 0.5s).
        let smoothed_accel = (self.ewma_rate - prev_ewma_rate) / dt;
        self.ewma_accel = ewma(alpha, self.ewma_accel, smoothed_accel);

        self.samples = self.samples.saturating_add(1);
        self.last = Some(SampleState {
            free_bytes,
            at: observed_at,
            inst_rate,
        });

        // Maintain rate history ring buffer for burst detection.
        self.rate_history.push_back(inst_rate);
        while self.rate_history.len() > self.rate_history_cap {
            self.rate_history.pop_front();
        }

        let burst_state = self.compute_burst_state(inst_rate);

        let trend = classify_trend(self.ewma_rate, self.ewma_accel);
        let seconds_to_exhaustion =
            project_time(self.ewma_rate, self.ewma_accel, free_bytes as f64);
        let threshold_distance = free_bytes.saturating_sub(threshold_free_bytes);
        let seconds_to_threshold =
            project_time(self.ewma_rate, self.ewma_accel, threshold_distance as f64);

        // Track prediction jitter: how much seconds_to_threshold changes between
        // ticks, normalized by the prediction magnitude. Swings like 47m → 2m
        // produce jitter near 1.0+, penalizing confidence.
        if seconds_to_threshold.is_finite() {
            if let Some(prev) = self.last_predicted_secs {
                let change = (seconds_to_threshold - prev).abs();
                // Normalize by the larger of the two predictions (floor at 60s to
                // avoid division amplification near zero).
                let scale = seconds_to_threshold.abs().max(prev.abs()).max(60.0);
                let jitter = change / scale;
                self.prediction_jitter_ewma = ewma(alpha, self.prediction_jitter_ewma, jitter);
            }
            self.last_predicted_secs = Some(seconds_to_threshold);
        }

        let confidence = self.compute_confidence();
        let fallback_active = self.samples < self.min_samples || confidence < 0.2;

        RateEstimate {
            bytes_per_second: self.ewma_rate,
            acceleration: self.ewma_accel,
            seconds_to_exhaustion,
            seconds_to_threshold,
            sample_count: self.samples,
            confidence,
            trend,
            alpha_used: alpha,
            fallback_active,
            burst_state,
        }
    }

    /// Number of rate samples collected (excludes the initial seed sample).
    ///
    /// The first call to `update()` stores the seed value but does not
    /// increment the counter because no rate can be computed from a single
    /// observation. Subsequent calls each add one sample.
    #[must_use]
    pub fn sample_count(&self) -> u64 {
        self.samples
    }

    fn compute_confidence(&self) -> f64 {
        if self.samples == 0 {
            return 0.0;
        }
        let sample_term = (self.samples as f64 / self.min_samples.max(1) as f64).min(1.0);
        let residual_term = 1.0 / (1.0 + self.residual_ewma / (self.ewma_rate.abs() + 1.0));
        // Prediction stability: 1.0 when predictions are consistent, drops toward
        // 0.0 when predictions swing wildly between ticks (e.g. 47m → 2m).
        let stability_term = 1.0 / 3.0f64.mul_add(self.prediction_jitter_ewma, 1.0);
        0.3f64
            .mul_add(
                stability_term,
                0.2f64.mul_add(residual_term, 0.5 * sample_term),
            )
            .clamp(0.0, 1.0)
    }

    fn fallback_estimate(&self, free_bytes: u64, threshold_free_bytes: u64) -> RateEstimate {
        let threshold_distance = free_bytes.saturating_sub(threshold_free_bytes);
        RateEstimate {
            bytes_per_second: self.ewma_rate,
            acceleration: self.ewma_accel,
            seconds_to_exhaustion: if self.ewma_rate > 0.0 {
                free_bytes as f64 / self.ewma_rate
            } else {
                f64::INFINITY
            },
            seconds_to_threshold: if self.ewma_rate > 0.0 {
                threshold_distance as f64 / self.ewma_rate
            } else {
                f64::INFINITY
            },
            sample_count: self.samples,
            confidence: self.compute_confidence(),
            trend: classify_trend(self.ewma_rate, self.ewma_accel),
            alpha_used: self.base_alpha,
            fallback_active: true,
            burst_state: BurstState::default(),
        }
    }

    /// Compute burst detection state from the rate history ring buffer.
    fn compute_burst_state(&mut self, latest_rate: f64) -> BurstState {
        let calibrated = self.rate_history.len() >= BURST_CALIBRATION_MIN;
        if !calibrated || self.rate_history.is_empty() {
            self.burst_duration_samples = 0;
            return BurstState::default();
        }

        // Compute median of absolute rates in history.
        let mut sorted: Vec<f64> = self.rate_history.iter().map(|r| r.abs()).collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median_rate = if sorted.len().is_multiple_of(2) {
            let mid = sorted.len() / 2;
            f64::midpoint(sorted[mid - 1], sorted[mid])
        } else {
            sorted[sorted.len() / 2]
        };

        // MAD (Median Absolute Deviation) × 1.4826 (Gaussian consistency factor).
        // Robust scale estimator: unlike standard deviation, a single 50× burst spike
        // does not inflate MAD because it only affects one deviation from the median.
        let mut deviations: Vec<f64> = sorted.iter().map(|r| (r - median_rate).abs()).collect();
        deviations.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mad_raw = if deviations.len().is_multiple_of(2) {
            let mid = deviations.len() / 2;
            f64::midpoint(deviations[mid - 1], deviations[mid])
        } else {
            deviations[deviations.len() / 2]
        };
        // 1.4826 is the consistency factor for the normal distribution:
        // MAD * 1.4826 ≈ standard deviation when data is Gaussian.
        let mad_rate = mad_raw * 1.4826;
        let robust_upper_bound = 3.0f64.mul_add(mad_rate, median_rate);

        // Count consecutive recent samples above 3× median.
        // Guard: when median_rate is negligible (< 0.33 bytes/sec), threshold is
        // < 1.0 — skip burst counting to avoid false positives from idle noise
        // and ensure the counter resets instead of going stale.
        let threshold = median_rate * 3.0;
        if threshold > 1.0 && latest_rate.abs() > threshold {
            self.burst_duration_samples = self.burst_duration_samples.saturating_add(1);
        } else {
            self.burst_duration_samples = 0;
        }

        // Derive burst probability from deviation magnitude and duration.
        // deviation_factor: how far above the median this sample is (0 if below threshold).
        let deviation_factor = if median_rate > 1.0 {
            ((latest_rate.abs() / median_rate) - 1.0).max(0.0)
        } else {
            0.0
        };
        // Two-factor burst detection:
        // 1. Magnitude: extreme spikes (>10× median) get immediate strong signal.
        //    A 50× spike (deviation_factor=49) → magnitude_weight=1.0 → immediate detection.
        //    A 5× spike (deviation_factor=4) → magnitude_weight=0.4 → needs duration help.
        let magnitude_weight = (deviation_factor / 10.0).clamp(0.0, 1.0);
        // 2. Duration: moderate bursts need sustained consecutive samples.
        //    1 sample → 0.2, 3 samples → 0.6, 5+ → 1.0.
        let duration_weight = (f64::from(self.burst_duration_samples) / 5.0).min(1.0);
        // Combined: either strong magnitude OR sustained duration triggers detection.
        let combined_weight = magnitude_weight.max(duration_weight);
        let burst_probability =
            (deviation_factor * combined_weight / (deviation_factor + 1.0)).clamp(0.0, 1.0);

        BurstState {
            burst_probability,
            median_rate,
            burst_duration_samples: self.burst_duration_samples,
            calibrated,
            mad_rate,
            robust_upper_bound,
        }
    }
}

#[inline]
fn ewma(alpha: f64, prev: f64, current: f64) -> f64 {
    alpha.mul_add(current, (1.0 - alpha) * prev)
}

fn classify_trend(rate: f64, accel: f64) -> Trend {
    if rate < -1.0 {
        return Trend::Recovering;
    }
    if accel > 64.0 {
        Trend::Accelerating
    } else if accel < -64.0 {
        Trend::Decelerating
    } else {
        Trend::Stable
    }
}

fn project_time(rate: f64, accel: f64, distance_bytes: f64) -> f64 {
    if distance_bytes <= 0.0 {
        return 0.0;
    }
    if rate <= 0.0 {
        return f64::INFINITY;
    }
    if accel.abs() < 1e-9 {
        return distance_bytes / rate;
    }

    let discriminant = rate.mul_add(rate, 2.0 * accel * distance_bytes);
    if discriminant < 0.0 {
        // Deceleration is strong enough that the rate will reach zero before
        // covering `distance_bytes`. The disk will never fill at this trend.
        return f64::INFINITY;
    }
    let root = discriminant.sqrt();

    // Use the numerically stable form to avoid catastrophic cancellation.
    // When accel is small and negative, `(-rate + root)` suffers precision loss
    // because root ≈ rate. Instead, multiply both sides by the conjugate:
    //   t = (-rate + root) / accel = 2*distance / (rate + root)
    // The latter avoids subtracting nearly-equal quantities.
    let t = if accel < 0.0 {
        let denom = rate + root;
        if denom.abs() < f64::EPSILON {
            return f64::INFINITY;
        }
        2.0 * distance_bytes / denom
    } else {
        (-rate + root) / accel
    };

    // Reject results where the rate would have reached zero before t
    // (unphysical: rate can't go negative).
    if accel < 0.0 {
        let t_zero = -rate / accel; // time when rate reaches zero
        if t > t_zero {
            return f64::INFINITY;
        }
    }

    if t.is_finite() && t > 0.0 {
        t
    } else {
        distance_bytes / rate
    }
}

#[cfg(test)]
mod tests {
    use super::{DiskRateEstimator, Trend};
    use std::time::{Duration, Instant};

    #[test]
    fn fallback_active_until_min_samples() {
        // min_samples=3: first update is seed (samples=0), next 3 each increment.
        let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 3);
        let t0 = Instant::now();
        let r0 = estimator.update(1_000, t0, 100);
        assert!(r0.fallback_active, "seed update should be fallback");
        let r1 = estimator.update(900, t0 + Duration::from_secs(1), 100);
        assert!(r1.fallback_active, "samples=1 < min_samples=3");
        let r2 = estimator.update(800, t0 + Duration::from_secs(2), 100);
        assert!(r2.fallback_active, "samples=2 < min_samples=3");
        let r3 = estimator.update(700, t0 + Duration::from_secs(3), 100);
        assert!(!r3.fallback_active, "samples=3 >= min_samples=3");
    }

    #[test]
    fn detects_recovering_trend_on_free_space_growth() {
        let mut estimator = DiskRateEstimator::new(0.4, 0.1, 0.8, 2);
        let t0 = Instant::now();
        let _ = estimator.update(1_000, t0, 100);
        let _ = estimator.update(1_200, t0 + Duration::from_secs(1), 100);
        let reading = estimator.update(1_400, t0 + Duration::from_secs(2), 100);
        assert_eq!(reading.trend, Trend::Recovering);
        assert!(reading.bytes_per_second < 0.0);
    }

    #[test]
    fn produces_finite_exhaustion_time_for_positive_consumption() {
        let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 2);
        let t0 = Instant::now();
        let _ = estimator.update(10_000, t0, 1_000);
        let _ = estimator.update(9_000, t0 + Duration::from_secs(1), 1_000);
        let reading = estimator.update(8_000, t0 + Duration::from_secs(2), 1_000);
        assert!(reading.seconds_to_exhaustion.is_finite());
        assert!(reading.seconds_to_exhaustion > 0.0);
        assert!(reading.seconds_to_threshold.is_finite());
    }

    #[test]
    fn first_update_is_always_fallback() {
        let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 5);
        let t0 = Instant::now();
        let reading = estimator.update(50_000, t0, 5_000);
        assert!(reading.fallback_active);
        assert_eq!(estimator.sample_count(), 0);
    }

    #[test]
    fn confidence_increases_with_samples() {
        let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 5);
        let t0 = Instant::now();
        let _ = estimator.update(100_000, t0, 10_000);

        let mut prev_conf = 0.0;
        for i in 1_u64..=10 {
            let reading =
                estimator.update(100_000 - i * 1_000, t0 + Duration::from_secs(i), 10_000);
            // Confidence should generally increase (monotonic for steady input).
            if i >= 3 {
                assert!(
                    reading.confidence >= prev_conf - 0.01,
                    "confidence should increase: {} >= {} at sample {}",
                    reading.confidence,
                    prev_conf,
                    i
                );
            }
            prev_conf = reading.confidence;
        }
        assert!(
            prev_conf > 0.5,
            "confidence should be high after many steady samples"
        );
    }

    #[test]
    fn steady_consumption_detects_stable_trend() {
        let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 3);
        let t0 = Instant::now();
        let _ = estimator.update(100_000, t0, 10_000);
        // Feed steady 1000 bytes/sec consumption.
        // EWMA needs several samples to converge; acceleration drops below
        // threshold after ~8 steady samples.
        for i in 1_u64..=15 {
            let reading =
                estimator.update(100_000 - i * 1_000, t0 + Duration::from_secs(i), 10_000);
            if i >= 10 {
                assert_eq!(
                    reading.trend,
                    Trend::Stable,
                    "should be stable at sample {i}"
                );
            }
        }
    }

    #[test]
    fn zero_interval_returns_fallback() {
        let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 2);
        let t0 = Instant::now();
        let _ = estimator.update(10_000, t0, 1_000);
        // Same timestamp — zero dt.
        let reading = estimator.update(9_000, t0, 1_000);
        assert!(reading.fallback_active);
    }

    #[test]
    fn out_of_order_timestamp_returns_fallback_without_panicking() {
        let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 2);
        let t0 = Instant::now();
        let _ = estimator.update(10_000, t0, 1_000);
        let _ = estimator.update(9_500, t0 + Duration::from_secs(1), 1_000);

        // Regressed timestamp: previously this path could panic.
        let reading = estimator.update(9_000, t0, 1_000);
        assert!(reading.fallback_active);
        assert_eq!(
            estimator.sample_count(),
            1,
            "out-of-order sample should be ignored, not counted"
        );
    }

    #[test]
    fn no_consumption_gives_infinite_exhaustion() {
        let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 2);
        let t0 = Instant::now();
        let _ = estimator.update(50_000, t0, 5_000);
        let _ = estimator.update(50_000, t0 + Duration::from_secs(1), 5_000);
        let reading = estimator.update(50_000, t0 + Duration::from_secs(2), 5_000);
        // No consumption → rate ~0 → infinite exhaustion time.
        assert!(
            reading.seconds_to_exhaustion > 1_000_000.0
                || reading.seconds_to_exhaustion.is_infinite()
        );
    }

    #[test]
    fn sample_count_tracks_updates() {
        let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 2);
        assert_eq!(estimator.sample_count(), 0);
        let t0 = Instant::now();
        estimator.update(10_000, t0, 1_000);
        assert_eq!(estimator.sample_count(), 0); // First update doesn't count as a sample.
        estimator.update(9_000, t0 + Duration::from_secs(1), 1_000);
        assert_eq!(estimator.sample_count(), 1);
        estimator.update(8_000, t0 + Duration::from_secs(2), 1_000);
        assert_eq!(estimator.sample_count(), 2);
    }

    #[test]
    fn threshold_distance_respected() {
        let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 2);
        let t0 = Instant::now();
        let _ = estimator.update(50_000, t0, 10_000);
        let _ = estimator.update(40_000, t0 + Duration::from_secs(1), 10_000);
        let reading = estimator.update(30_000, t0 + Duration::from_secs(2), 10_000);

        // seconds_to_threshold should be less than seconds_to_exhaustion
        // because threshold (10_000) is reached before exhaustion (0).
        assert!(
            reading.seconds_to_threshold <= reading.seconds_to_exhaustion,
            "threshold {} should be reached before exhaustion {}",
            reading.seconds_to_threshold,
            reading.seconds_to_exhaustion,
        );
    }

    #[test]
    fn burst_spike_does_not_inflate_rate_estimate() {
        // Simulate: 40 steady samples at ~100 bytes/sec, then a sudden 50x burst.
        // The EWMA should damp the burst (low alpha) instead of amplifying it.
        let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 3);
        let t0 = Instant::now();
        let total_free = 10_000_000u64;
        let threshold = 100_000u64;

        // Seed.
        let _ = estimator.update(total_free, t0, threshold);

        // 40 steady samples: 100 bytes consumed per 30-second interval.
        for i in 1..=40u64 {
            let free = total_free - i * 100;
            let time = t0 + Duration::from_secs(i * 30);
            let _ = estimator.update(free, time, threshold);
        }

        let steady_estimate = estimator.update(
            total_free - 41 * 100,
            t0 + Duration::from_secs(41 * 30),
            threshold,
        );
        // Verify steady state was computed (used as baseline for burst comparison below).
        assert!(steady_estimate.bytes_per_second.abs() < 100.0);

        // Now inject a massive burst: 500_000 bytes consumed in 30 seconds (50x spike).
        let burst_free = total_free - 41 * 100 - 500_000;
        let burst_estimate = estimator.update(burst_free, t0 + Duration::from_mins(21), threshold);

        // The instantaneous burst rate is ~16667 bytes/sec, ~5000x the steady rate.
        // With alpha damping (alpha clamped low during bursts), the EWMA should
        // absorb far less of the spike than it would with the old amplifying alpha.
        // A single sample at alpha=0.1 moves EWMA ~10% of the way — so the EWMA
        // rate should be well below the instantaneous burst rate.
        let inst_burst_rate = 500_000.0 / 30.0;
        assert!(
            burst_estimate.bytes_per_second < inst_burst_rate * 0.5,
            "EWMA should absorb less than half the burst: inst={inst_burst_rate:.1}, ewma={:.1}",
            burst_estimate.bytes_per_second,
        );

        // Burst detection should flag this as a burst.
        assert!(
            burst_estimate.burst_state.calibrated,
            "should be calibrated after 40+ samples"
        );
        assert!(
            burst_estimate.burst_state.burst_duration_samples >= 1,
            "burst should be detected"
        );
    }

    #[test]
    fn burst_state_uncalibrated_below_threshold() {
        // With fewer than 30 samples, burst detection should report uncalibrated.
        let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 2);
        let t0 = Instant::now();
        let _ = estimator.update(100_000, t0, 10_000);

        for i in 1..=10u64 {
            let reading =
                estimator.update(100_000 - i * 1_000, t0 + Duration::from_secs(i), 10_000);
            assert!(
                !reading.burst_state.calibrated,
                "should not be calibrated at sample {i}"
            );
        }
    }

    #[test]
    fn extreme_spike_detected_on_first_sample() {
        // A single extreme spike (50×+ median) should immediately produce a
        // burst_probability > 0.5, without needing multiple consecutive samples.
        let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 3);
        let t0 = Instant::now();
        let total_free = 10_000_000u64;
        let threshold = 100_000u64;

        // Seed.
        let _ = estimator.update(total_free, t0, threshold);

        // 40 steady samples at ~100 bytes per 30s interval.
        for i in 1..=40u64 {
            let free = total_free - i * 100;
            let time = t0 + Duration::from_secs(i * 30);
            let _ = estimator.update(free, time, threshold);
        }

        // Single extreme spike: 500_000 bytes consumed in 30 seconds (~50× the steady rate).
        let burst_free = total_free - 40 * 100 - 500_000;
        let spike_estimate =
            estimator.update(burst_free, t0 + Duration::from_secs(41 * 30), threshold);

        assert!(
            spike_estimate.burst_state.calibrated,
            "should be calibrated after 40+ samples"
        );
        assert!(
            spike_estimate.burst_state.burst_probability > 0.5,
            "extreme spike should produce burst_probability > 0.5 on first sample, got {:.3}",
            spike_estimate.burst_state.burst_probability,
        );
        assert_eq!(
            spike_estimate.burst_state.burst_duration_samples, 1,
            "should be the first burst sample"
        );
    }

    #[test]
    fn moderate_burst_needs_multiple_samples() {
        // A moderate spike (5× median) should NOT immediately trigger — needs
        // sustained consecutive samples before burst_probability crosses 0.5.
        let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 3);
        let t0 = Instant::now();
        let total_free = 10_000_000u64;
        let threshold = 100_000u64;

        // Seed.
        let _ = estimator.update(total_free, t0, threshold);

        // 40 steady samples at ~1000 bytes per 30s interval.
        for i in 1..=40u64 {
            let free = total_free - i * 1000;
            let time = t0 + Duration::from_secs(i * 30);
            let _ = estimator.update(free, time, threshold);
        }

        // Single moderate spike: 5000 bytes consumed in 30s (5× the steady ~33 bytes/sec rate).
        let first_spike = estimator.update(
            total_free - 40 * 1000 - 5000,
            t0 + Duration::from_secs(41 * 30),
            threshold,
        );

        assert!(first_spike.burst_state.calibrated, "should be calibrated");
        // Moderate spike: first sample should NOT cross 0.5.
        assert!(
            first_spike.burst_state.burst_probability < 0.5,
            "moderate spike should NOT immediately trigger, got {:.3}",
            first_spike.burst_state.burst_probability,
        );
    }

    #[test]
    fn mad_rate_robust_to_outliers() {
        // MAD should be small during steady state and remain small even after a burst spike.
        let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 3);
        let t0 = Instant::now();
        let total_free = 10_000_000u64;
        let threshold = 100_000u64;

        let _ = estimator.update(total_free, t0, threshold);

        // 40 steady samples at ~100 bytes/30s (≈3.33 bytes/sec).
        for i in 1..=40u64 {
            let free = total_free - i * 100;
            let time = t0 + Duration::from_secs(i * 30);
            let _ = estimator.update(free, time, threshold);
        }

        let steady = estimator.update(
            total_free - 41 * 100,
            t0 + Duration::from_secs(41 * 30),
            threshold,
        );
        let steady_mad = steady.burst_state.mad_rate;
        let steady_bound = steady.burst_state.robust_upper_bound;
        assert!(steady.burst_state.calibrated);
        assert!(
            steady_mad < 10.0,
            "MAD should be small during steady state: {steady_mad}"
        );
        assert!(steady_bound > 0.0, "robust bound must be positive");

        // Inject a massive burst: 500_000 bytes consumed in 30 seconds.
        let burst_free = total_free - 41 * 100 - 500_000;
        let burst = estimator.update(burst_free, t0 + Duration::from_mins(21), threshold);
        // MAD should not be wildly inflated by a single outlier.
        // With 42 samples where 41 are ~3.33 and 1 is ~16667, the median barely
        // moves and the MAD barely moves (the outlier is just 1/42 of deviations).
        // When all steady rates are near-identical, MAD ≈ 0 — this is correct
        // (no dispersion). A single outlier can't push MAD above a small bound.
        assert!(
            burst.burst_state.mad_rate < 50.0,
            "MAD should resist outlier inflation: burst_mad={:.2}",
            burst.burst_state.mad_rate,
        );
        // The burst rate should be above the robust upper bound.
        let inst_burst_rate = 500_000.0 / 30.0;
        assert!(
            burst.burst_state.is_burst_outlier(inst_burst_rate),
            "burst rate {inst_burst_rate:.0} should be above robust bound {:.0}",
            burst.burst_state.robust_upper_bound,
        );
    }

    #[test]
    fn alpha_decreases_during_bursts() {
        // Verify that the alpha used during a burst is lower than during steady state.
        // We need enough steady samples for the EWMA to converge so that steady-state
        // burstiness is near zero and alpha approaches base_alpha.
        let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 2);
        let t0 = Instant::now();
        let _ = estimator.update(10_000_000, t0, 100_000);

        // 10 steady samples at exactly 1000 bytes/sec to converge the EWMA.
        for i in 1..=10u64 {
            let _ = estimator.update(10_000_000 - i * 1000, t0 + Duration::from_secs(i), 100_000);
        }
        // One more steady sample to get the alpha baseline.
        let steady = estimator.update(
            10_000_000 - 11 * 1000,
            t0 + Duration::from_secs(11),
            100_000,
        );

        // Burst: 500_000 bytes consumed in 1 second (500x spike).
        let burst = estimator.update(
            10_000_000 - 11 * 1000 - 500_000,
            t0 + Duration::from_secs(12),
            100_000,
        );

        assert!(
            burst.alpha_used < steady.alpha_used,
            "alpha during burst ({:.3}) should be less than steady ({:.3})",
            burst.alpha_used,
            steady.alpha_used,
        );
    }
}
