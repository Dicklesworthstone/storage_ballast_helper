//! EWMA rate estimator: disk usage velocity, acceleration, time-to-exhaustion prediction.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::time::Instant;

/// Trend classification for disk pressure dynamics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trend {
    Stable,
    Accelerating,
    Decelerating,
    Recovering,
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
}

#[derive(Debug, Clone, Copy)]
struct SampleState {
    free_bytes: u64,
    at: Instant,
    inst_rate: f64,
}

/// Online EWMA estimator with adaptive alpha and fallback signaling.
#[derive(Debug, Clone)]
pub struct DiskRateEstimator {
    base_alpha: f64,
    min_alpha: f64,
    max_alpha: f64,
    ewma_rate: f64,
    ewma_accel: f64,
    residual_ewma: f64,
    min_samples: u64,
    samples: u64,
    last: Option<SampleState>,
}

impl DiskRateEstimator {
    #[must_use]
    pub fn new(base_alpha: f64, min_alpha: f64, max_alpha: f64, min_samples: u64) -> Self {
        Self {
            base_alpha,
            min_alpha,
            max_alpha,
            ewma_rate: 0.0,
            ewma_accel: 0.0,
            residual_ewma: 0.0,
            min_samples,
            samples: 0,
            last: None,
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
        let alpha = 0.20f64
            .mul_add(burstiness, self.base_alpha)
            .clamp(self.min_alpha, self.max_alpha);

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

        let confidence = self.compute_confidence();
        let trend = classify_trend(self.ewma_rate, self.ewma_accel);
        let seconds_to_exhaustion =
            project_time(self.ewma_rate, self.ewma_accel, free_bytes as f64);
        let threshold_distance = free_bytes.saturating_sub(threshold_free_bytes);
        let seconds_to_threshold =
            project_time(self.ewma_rate, self.ewma_accel, threshold_distance as f64);
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
        0.7f64
            .mul_add(sample_term, 0.3 * residual_term)
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
}
