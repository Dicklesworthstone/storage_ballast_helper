//! EWMA rate estimator: disk usage velocity, acceleration, time-to-exhaustion prediction.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::collections::VecDeque;
use std::time::{Duration, Instant};

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
    /// Median of the consuming (positive) rates in the history; 0 when none.
    /// Unlike `median_rate` (over absolute rates), intervals that freed space
    /// do not count as consumption (#29).
    pub median_consumption_rate: f64,
    /// Median bytes consumed per observed interval, expressed as a rate.
    /// Idle and freeing intervals contribute zero to this baseline.
    pub median_drain_rate: f64,
    /// Signed rate of the latest observed interval, when calibrated. Unlike
    /// the EWMA or the positive-only median, this records whether consumption
    /// actually continued after a burst. `None` means no measured evidence.
    pub latest_rate: Option<f64>,
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
            median_consumption_rate: 0.0,
            median_drain_rate: 0.0,
            latest_rate: None,
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
    /// Projection rate corroborated by elapsed-time net consumption. Distant
    /// forecasts use the measured trend; at an imminent boundary a confirmed
    /// writer retains at least the immediate EWMA rate when it agrees with
    /// the measured windows. `None` means the EWMA supplies a projection
    /// without that sustained-consumption evidence.
    /// Unlike the burst median, the corroboration includes space freed by builds.
    pub forecast_rate_bytes_per_second: Option<f64>,
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
    /// Free bytes at the sample this estimate was computed from. The daemon's
    /// conformal correction rescales the forecast times but never this (#29).
    pub free_bytes: u64,
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

// Keep the projection window in wall time: at Critical the monitor may poll
// every 100 ms, so a 200-sample rate ring can represent only twenty seconds.
const FORECAST_HISTORY_INTERVAL: Duration = Duration::from_secs(5);
const FORECAST_HISTORY_WINDOW: Duration = Duration::from_mins(15);
const FORECAST_HISTORY_MIN: Duration = Duration::from_mins(5);
const FORECAST_HISTORY_MAX_GAP: Duration = Duration::from_mins(1);
const FORECAST_FAST_HORIZON: f64 = 5.0 * 60.0;
const FORECAST_CHANGE_INTERVAL: Duration = Duration::from_secs(20);
const FORECAST_HISTORY_CAP: usize = 182;

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
    /// Sparsely retained free-space observations for long-horizon forecasts.
    /// Time-weighted trends preserve signed net consumption rather than
    /// treating every brief allocation or release as a new trend.
    forecast_history: VecDeque<SampleState>,
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
            forecast_history: VecDeque::with_capacity(FORECAST_HISTORY_CAP),
        }
    }

    /// Update estimator parameters at runtime, retaining the most recent
    /// history within the new bound and all elapsed-time forecasting evidence.
    pub fn update_params(
        &mut self,
        base_alpha: f64,
        min_alpha: f64,
        max_alpha: f64,
        min_samples: u64,
        rate_history_cap: usize,
    ) {
        self.base_alpha = base_alpha;
        self.min_alpha = min_alpha;
        self.max_alpha = max_alpha;
        self.min_samples = min_samples;
        let rate_history_cap = rate_history_cap.max(1);
        if self.rate_history_cap != rate_history_cap {
            self.rate_history_cap = rate_history_cap;
            while self.rate_history.len() > rate_history_cap {
                self.rate_history.pop_front();
            }
            self.rate_history.shrink_to(rate_history_cap);
            self.burst_duration_samples = self
                .burst_duration_samples
                .min(u32::try_from(self.rate_history.len()).unwrap_or(u32::MAX));
        }
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
            let initial = SampleState {
                free_bytes,
                at: observed_at,
                inst_rate: 0.0,
            };
            self.last = Some(initial);
            self.forecast_history.push_back(initial);
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
        self.record_forecast_observation(free_bytes, observed_at, dt_duration);

        // Maintain rate history ring buffer for burst detection.
        self.rate_history.push_back(inst_rate);
        while self.rate_history.len() > self.rate_history_cap {
            self.rate_history.pop_front();
        }

        let burst_state = self.compute_burst_state(inst_rate, true);

        let trend = classify_trend(self.ewma_rate, self.ewma_accel);
        let threshold_distance = free_bytes.saturating_sub(threshold_free_bytes);
        let forecast_rate_bytes_per_second =
            self.forecast_rate(free_bytes, observed_at, threshold_distance);
        let projection_rate = forecast_rate_bytes_per_second.unwrap_or(self.ewma_rate);
        let seconds_to_exhaustion = project_time(projection_rate, free_bytes as f64);
        let seconds_to_threshold = project_time(projection_rate, threshold_distance as f64);

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
            forecast_rate_bytes_per_second,
            acceleration: self.ewma_accel,
            seconds_to_exhaustion,
            seconds_to_threshold,
            sample_count: self.samples,
            confidence,
            trend,
            alpha_used: alpha,
            fallback_active,
            burst_state,
            free_bytes,
        }
    }

    fn record_forecast_observation(&mut self, free_bytes: u64, at: Instant, gap: Duration) {
        if gap > FORECAST_HISTORY_MAX_GAP {
            // An unobserved interval is not evidence that a rate persisted.
            self.forecast_history.clear();
        }
        if self
            .forecast_history
            .back()
            .is_none_or(|last| at.saturating_duration_since(last.at) >= FORECAST_HISTORY_INTERVAL)
        {
            self.forecast_history.push_back(SampleState {
                free_bytes,
                at,
                inst_rate: 0.0,
            });
        }
        // Retain one observation before the window boundary for interpolation.
        while self.forecast_history.len() > 1
            && self.forecast_history.get(1).is_some_and(|next| {
                at.saturating_duration_since(next.at) >= FORECAST_HISTORY_WINDOW
            })
        {
            self.forecast_history.pop_front();
        }
        debug_assert!(self.forecast_history.len() <= FORECAST_HISTORY_CAP);
    }

    /// A corroborated projection rate. Distant forecasts use a longer measured
    /// net trend. Immediate danger retains at least the original EWMA response;
    /// neither a historical average nor a persistence test may postpone
    /// crossing a nearby pressure boundary.
    fn forecast_rate(&self, free_bytes: u64, at: Instant, threshold_distance: u64) -> Option<f64> {
        let elapsed = at.checked_duration_since(self.forecast_history.front()?.at)?;
        if elapsed < FORECAST_HISTORY_MIN {
            return None;
        }
        let danger_distance = if threshold_distance == 0 {
            free_bytes
        } else {
            threshold_distance
        };
        let immediate_danger =
            project_time(self.ewma_rate, danger_distance as f64) <= FORECAST_FAST_HORIZON;

        let window = elapsed.min(FORECAST_HISTORY_WINDOW);
        let net_rate = self.trend_rate(free_bytes, at, window)?;
        if !self.recent_change_observed(at) {
            return (!immediate_danger).then_some(net_rate);
        }

        // A new steady writer (or sustained recovery) must not wait half a
        // fifteen-minute median window. Three non-overlapping measured windows
        // must agree in sign and within a factor of two. A short burst followed
        // by idle time or deletion therefore cannot establish a new regime.
        let mut recent_rates = [0.0; 3];
        let mut newer_consumption = 0.0;
        for (step, rate) in (1..=3).zip(&mut recent_rates) {
            let older = self.consumed_since(free_bytes, at, FORECAST_CHANGE_INTERVAL * step)?;
            *rate = (older - newer_consumption) / FORECAST_CHANGE_INTERVAL.as_secs_f64();
            newer_consumption = older;
        }
        let recent_rate = newer_consumption / (FORECAST_CHANGE_INTERVAL * 3).as_secs_f64();
        let min_rate = recent_rates.into_iter().fold(f64::INFINITY, f64::min);
        let max_rate = recent_rates.into_iter().fold(f64::NEG_INFINITY, f64::max);
        let consistent = (min_rate > 0.0 && max_rate <= 2.0 * min_rate)
            || (max_rate < 0.0 && min_rate >= 2.0 * max_rate)
            || (min_rate.abs() <= 1.0 && max_rate.abs() <= 1.0);
        if immediate_danger {
            // Losing corroboration here sends predictive policy back through
            // its old burst median. After a confirmed new writer, that median
            // can still say "hours" and turn cleanup/ballast rescue into Clear
            // exactly when the new workload approaches Red or exhaustion.
            // Retain the measured persistence without slowing the immediate
            // response, but require the selected rate to agree with every
            // measured window under the same factor-of-two bound. At 100 ms
            // polling, one allocation can barely change a 20 s window yet
            // inflate EWMA twentyfold; the windows do not corroborate that
            // spike. Without agreement keep the immediate PID forecast and
            // leave predictive policy's independent burst gates in force.
            let projection_rate = recent_rate.max(self.ewma_rate);
            return (consistent && min_rate > 0.0 && projection_rate <= 2.0 * min_rate)
                .then_some(projection_rate);
        }
        let changed = recent_rate.signum() != net_rate.signum()
            || recent_rate.abs() > 2.0 * net_rate.abs()
            || 2.0 * recent_rate.abs() < net_rate.abs();
        Some(if consistent && changed {
            recent_rate
        } else {
            net_rate
        })
    }

    /// A least-squares consumption slope over elapsed time. Integrate each
    /// observed linear segment exactly, so variable polling does not give a
    /// densely sampled moment more weight. Using the entire window avoids
    /// letting a late build allocation or release dominate its endpoints.
    fn trend_rate(&self, free_bytes: u64, at: Instant, window: Duration) -> Option<f64> {
        let boundary = at.checked_sub(window)?;
        let seconds = window.as_secs_f64();
        let mut previous_time = 0.0;
        let mut previous_delta = self.consumed_since(free_bytes, at, window)?;
        let mut covariance = 0.0;
        let current = SampleState {
            free_bytes,
            at,
            inst_rate: 0.0,
        };
        for sample in self
            .forecast_history
            .iter()
            .filter(|sample| sample.at > boundary)
            .chain([&current])
        {
            // Normalize time to [0, 1]; its centered second moment is 1/12.
            // Integer subtraction preserves small deltas on large volumes.
            let time = sample.at.checked_duration_since(boundary)?.as_secs_f64() / seconds;
            let delta = (i128::from(sample.free_bytes) - i128::from(free_bytes)) as f64;
            let earlier = 2.0f64.mul_add(previous_time, time) - 1.5;
            let later = 2.0f64.mul_add(time, previous_time) - 1.5;
            covariance = ((time - previous_time) / 6.0)
                .mul_add(later.mul_add(delta, earlier * previous_delta), covariance);
            previous_time = time;
            previous_delta = delta;
        }
        Some(-12.0 * covariance / seconds)
    }

    /// Three interpolated windows are not three observations. In particular,
    /// a single minute-long native interval cannot establish persistence.
    fn recent_change_observed(&self, at: Instant) -> bool {
        let Some(boundary) = at.checked_sub(FORECAST_CHANGE_INTERVAL * 3) else {
            return false;
        };
        let Some(first) = self.forecast_history.front() else {
            return false;
        };
        if first.at > boundary {
            return false;
        }
        let mut previous = first.at;
        for next in self
            .forecast_history
            .iter()
            .skip(1)
            .map(|sample| sample.at)
            .chain([at])
        {
            if next > boundary
                && next.saturating_duration_since(previous) > FORECAST_CHANGE_INTERVAL
            {
                return false;
            }
            previous = next;
        }
        true
    }

    /// Signed bytes consumed since an exact elapsed-time boundary, including
    /// a partial bucket. Subtract integer counters before conversion so a
    /// small change on a large filesystem retains its precision.
    fn consumed_since(&self, free_bytes: u64, at: Instant, ago: Duration) -> Option<f64> {
        let boundary = at.checked_sub(ago)?;
        let current = SampleState {
            free_bytes,
            at,
            inst_rate: 0.0,
        };
        let mut previous = *self.forecast_history.front()?;
        if previous.at > boundary {
            return None;
        }
        for next in self.forecast_history.iter().skip(1).chain([&current]) {
            if next.at >= boundary {
                let span = next.at.checked_duration_since(previous.at)?.as_secs_f64();
                let offset = boundary.checked_duration_since(previous.at)?.as_secs_f64();
                let start_delta = (i128::from(previous.free_bytes) - i128::from(free_bytes)) as f64;
                if span == 0.0 {
                    return Some(start_delta);
                }
                let change = (i128::from(next.free_bytes) - i128::from(previous.free_bytes)) as f64;
                return Some(change.mul_add(offset / span, start_delta));
            }
            previous = *next;
        }
        None
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

    /// Recompute a retained observation after a policy change, without
    /// manufacturing a rate sample, burst observation or confidence reward.
    /// Rebasing the jitter comparison keeps a changed red boundary from being
    /// mistaken for an unstable filesystem on the next real observation.
    #[cfg(feature = "daemon")]
    pub(crate) fn reforecast(
        &mut self,
        previous: &RateEstimate,
        threshold_free_bytes: u64,
    ) -> RateEstimate {
        let mut estimate = previous.clone();
        let distance = previous.free_bytes.saturating_sub(threshold_free_bytes);
        estimate.forecast_rate_bytes_per_second = self
            .last
            .and_then(|last| self.forecast_rate(previous.free_bytes, last.at, distance));
        let projection_rate = estimate
            .forecast_rate_bytes_per_second
            .unwrap_or(self.ewma_rate);
        estimate.seconds_to_threshold = project_time(projection_rate, distance as f64);
        estimate.seconds_to_exhaustion = project_time(projection_rate, previous.free_bytes as f64);
        estimate.confidence = self.compute_confidence();
        estimate.fallback_active = self.samples < self.min_samples || estimate.confidence < 0.2;
        estimate.burst_state = self
            .last
            .map(|last| self.compute_burst_state(last.inst_rate, false))
            .unwrap_or_default();
        self.last_predicted_secs = estimate
            .seconds_to_threshold
            .is_finite()
            .then_some(estimate.seconds_to_threshold);
        estimate
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
            forecast_rate_bytes_per_second: None,
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
            free_bytes,
        }
    }

    /// Compute burst detection state from the rate history ring buffer.
    fn compute_burst_state(&mut self, latest_rate: f64, new_sample: bool) -> BurstState {
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
            if new_sample {
                self.burst_duration_samples = self.burst_duration_samples.saturating_add(1);
            }
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

        let (median_consumption_rate, median_drain_rate) = consumption_medians(&self.rate_history);
        BurstState {
            burst_probability,
            median_rate,
            burst_duration_samples: self.burst_duration_samples,
            calibrated,
            mad_rate,
            robust_upper_bound,
            median_consumption_rate,
            median_drain_rate,
            latest_rate: Some(latest_rate),
        }
    }
}

/// Rates during writes alone and across all intervals, respectively.
/// Both medians use the same sorted observations.
fn consumption_medians(rates: &VecDeque<f64>) -> (f64, f64) {
    let mut consuming: Vec<f64> = rates.iter().copied().filter(|rate| *rate > 0.0).collect();
    if consuming.is_empty() {
        return (0.0, 0.0);
    }
    consuming.sort_by(f64::total_cmp);
    let writing = f64::midpoint(
        consuming[(consuming.len() - 1) / 2],
        consuming[consuming.len() / 2],
    );
    let idle_or_freeing = rates.len() - consuming.len();
    let drain_at = |i: usize| i.checked_sub(idle_or_freeing).map_or(0.0, |j| consuming[j]);
    let typical = f64::midpoint(drain_at((rates.len() - 1) / 2), drain_at(rates.len() / 2));
    (writing, typical)
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

/// Time to consume `distance_bytes` at the smoothed rate.
///
/// Linear on purpose. The acceleration estimate changes sign between 5 s
/// samples under build traffic, and extrapolating it as `v*t + a*t*t/2` over
/// a horizon of minutes turned that noise into the forecast: on 2026-11-13,
/// hz4 filled at a realized 24 MB/s (72 min to full) while the quadratic
/// said "full within 30 min" in 45 of 111 samples (as low as 5.7 min) and
/// "never fills" in 64; vmi1264463, 21 h from full at 1.4 MB/s, was told
/// 8 min after one burst. The smoothed rate itself follows a real
/// sustained change within a few samples, and acceleration still sets
/// [`Trend`].
fn project_time(rate: f64, distance_bytes: f64) -> f64 {
    if distance_bytes <= 0.0 {
        return 0.0;
    }
    if rate <= 0.0 {
        return f64::INFINITY;
    }
    distance_bytes / rate
}

#[cfg(test)]
mod tests {
    use super::{DiskRateEstimator, Trend, VecDeque, consumption_medians};
    use std::time::{Duration, Instant};

    #[test]
    fn consumption_median_ignores_intervals_that_freed_space() {
        // #29: the absolute median of this history is 1,000 B/s, but only two
        // intervals consumed space.
        let rates: VecDeque<f64> = [-1000.0, -1000.0, -1000.0, 10.0, 20.0].into();
        assert_eq!(consumption_medians(&rates), (15.0, 0.0));
        assert_eq!(consumption_medians(&[-5.0, 0.0].into()), (0.0, 0.0));
        assert_eq!(consumption_medians(&[3.0, 1.0, 2.0].into()), (2.0, 2.0));
        assert_eq!(
            consumption_medians(&[-5.0, 0.0, 10.0, 20.0].into()),
            (15.0, 5.0)
        );
    }

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

    #[test]
    fn distant_runway_tracks_net_drain_through_repeated_allocations_and_frees() {
        let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 5);
        let start = Instant::now();
        let initial_free = 80_000_000_000;
        let threshold = 40_000_000_000;
        let net_rate = 3_000_000;
        estimator.update(initial_free, start, threshold);
        let mut immediate_recoveries = 0;
        for seconds in (5..=1800_u64).step_by(5) {
            let phase = seconds % 60;
            let transient = phase.min(60 - phase) * 60_000_000;
            let free = initial_free - seconds * net_rate - transient;
            let estimate = estimator.update(free, start + Duration::from_secs(seconds), threshold);
            if seconds < 900 {
                continue;
            }
            let projected_rate = estimate.forecast_rate_bytes_per_second.unwrap();
            assert!(
                (projected_rate / net_rate as f64 - 1.0).abs() < 0.1,
                "{estimate:?}"
            );
            let realized_runway = (free - threshold) as f64 / net_rate as f64;
            assert!((estimate.seconds_to_threshold / realized_runway - 1.0).abs() < 0.1);
            assert!(estimate.seconds_to_exhaustion.is_finite());
            immediate_recoveries += usize::from(estimate.bytes_per_second < 0.0);
        }
        // The test includes the former false "never fills" case, not just
        // positive spikes around an otherwise steady rate.
        assert!(immediate_recoveries > 0);
    }

    #[test]
    fn distant_runway_handles_misaligned_pulses_and_nonuniform_observations() {
        let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 5);
        let start = Instant::now();
        let initial_free = 90_000_000_000;
        let threshold = 45_000_000_000;
        let net_rate = 2_700_000;
        // Independent build jobs allocate and later free 3 GB. Their starts,
        // durations and native observation cadence share no aligned period
        // with the forecast window. Only the persistent 2.7 MB/s drain remains.
        let pulses = [
            (337, 37),
            (503, 29),
            (811, 41),
            (1057, 23),
            (1289, 47),
            (1567, 31),
            (1891, 39),
        ];
        let cadences = [3, 11, 5, 17, 7];
        estimator.update(initial_free, start, threshold);
        let mut seconds = 0;
        let mut step = 0;
        let mut misleading_endpoints = 0;
        while seconds < 2200 {
            seconds += cadences[step % cadences.len()];
            step += 1;
            let transient: u64 = pulses
                .iter()
                .map(|&(begin, duration)| {
                    if seconds < begin || seconds >= begin + duration {
                        return 0;
                    }
                    let phase = seconds - begin;
                    phase.min(duration - phase) * 6_000_000_000 / duration
                })
                .sum();
            let free = initial_free - seconds * net_rate - transient;
            let at = start + Duration::from_secs(seconds);
            let estimate = estimator.update(free, at, threshold);
            if seconds < 900 {
                continue;
            }
            let projected = estimate.forecast_rate_bytes_per_second.unwrap();
            let runway = (free - threshold) as f64 / net_rate as f64;
            assert!(
                (0.5..=2.0).contains(&(projected / net_rate as f64)),
                "at {seconds}s: {estimate:?}"
            );
            assert!(
                (0.5..=2.0).contains(&(estimate.seconds_to_threshold / runway)),
                "at {seconds}s: {estimate:?}"
            );
            assert!(estimate.seconds_to_exhaustion.is_finite());
            // An endpoint-only history would still falsely say "never fills"
            // on this trace, so passing cannot rely on harmonic cancellation.
            misleading_endpoints += usize::from(
                estimator
                    .consumed_since(free, at, super::FORECAST_HISTORY_WINDOW)
                    .unwrap()
                    < 0.0,
            );
        }
        assert!(misleading_endpoints > 0);
    }

    fn warm_long_forecast() -> (DiskRateEstimator, Instant, u64) {
        let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 5);
        let start = Instant::now();
        let initial_free = 80_000_000_000;
        estimator.update(initial_free, start, 0);
        for seconds in (5..=900_u64).step_by(5) {
            estimator.update(
                initial_free - seconds * 2_000_000,
                start + Duration::from_secs(seconds),
                0,
            );
        }
        (
            estimator,
            start + Duration::from_mins(15),
            initial_free - 1_800_000_000,
        )
    }

    #[test]
    fn short_burst_does_not_become_a_new_long_horizon_rate() {
        let (mut estimator, start, mut free) = warm_long_forecast();
        for seconds in (5..=60).step_by(5) {
            let rate = if seconds <= 30 { 50_000_000 } else { 2_000_000 };
            free -= rate * 5;
            let estimate = estimator.update(free, start + Duration::from_secs(seconds), 0);
            let projection_rate = estimate.forecast_rate_bytes_per_second.unwrap();
            assert!(projection_rate < 4_000_000.0, "{estimate:?}");
            assert!(estimate.seconds_to_exhaustion > 4.0 * 3600.0);
        }
    }

    #[test]
    fn sustained_new_writer_is_recognized_without_waiting_for_old_history_to_expire() {
        let (mut estimator, start, mut free) = warm_long_forecast();
        let mut last = None;
        for seconds in (5..=60).step_by(5) {
            free -= 100_000_000 * 5;
            last = Some(estimator.update(free, start + Duration::from_secs(seconds), 0));
        }
        let estimate = last.unwrap();
        assert_eq!(estimate.forecast_rate_bytes_per_second, Some(100_000_000.0));
        assert!((estimate.seconds_to_exhaustion - free as f64 / 100_000_000.0).abs() < 1e-6);
        assert!(estimate.seconds_to_exhaustion < 15.0 * 60.0);
    }

    #[test]
    fn sustained_recovery_and_stopped_writer_end_the_old_drain_forecast() {
        for recovery in [false, true] {
            let (mut estimator, start, mut free) = warm_long_forecast();
            let mut last = None;
            for seconds in (5..=60).step_by(5) {
                if recovery {
                    free += 20_000_000 * 5;
                }
                last = Some(estimator.update(free, start + Duration::from_secs(seconds), 0));
            }
            let estimate = last.unwrap();
            assert!(estimate.forecast_rate_bytes_per_second.unwrap() <= 0.0);
            assert!(estimate.seconds_to_exhaustion.is_infinite());
        }
    }

    #[test]
    fn imminent_boundary_keeps_the_immediate_ewma_response() {
        let (mut estimator, start, mut free) = warm_long_forecast();
        let threshold = free - 5_000_000_000;
        let mut fast_samples = 0;
        for seconds in (5..=30).step_by(5) {
            free -= 100_000_000 * 5;
            let estimate = estimator.update(free, start + Duration::from_secs(seconds), threshold);
            let immediate = (free - threshold) as f64 / estimate.bytes_per_second;
            if immediate <= super::FORECAST_FAST_HORIZON {
                assert_eq!(estimate.forecast_rate_bytes_per_second, None);
                assert!((estimate.seconds_to_threshold - immediate).abs() < 1e-6);
                fast_samples += 1;
            }
        }
        assert!(
            fast_samples > 0,
            "fixture must reach the immediate danger path"
        );
    }

    #[test]
    fn projection_history_is_time_weighted_and_bounded_at_fast_poll_cadences() {
        for millis_per_sample in [100_u64, 5000, 17000] {
            let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 5);
            let start = Instant::now();
            let initial_free = 80_000_000_000;
            estimator.update(initial_free, start, 0);
            let mut last = None;
            for step in 1..=1_000_000 / millis_per_sample {
                let elapsed_ms = step * millis_per_sample;
                let free = initial_free - elapsed_ms * 2000;
                last = Some(estimator.update(free, start + Duration::from_millis(elapsed_ms), 0));
                assert!(estimator.forecast_history.len() <= super::FORECAST_HISTORY_CAP);
            }
            let estimate = last.unwrap();
            assert!((estimate.forecast_rate_bytes_per_second.unwrap() - 2_000_000.0).abs() < 1e-6);
        }
    }

    #[test]
    fn unobserved_gap_cannot_substantiate_a_sustained_forecast() {
        let (mut estimator, start, free) = warm_long_forecast();
        let estimate = estimator.update(free - 240_000_000, start + Duration::from_secs(120), 0);
        assert_eq!(estimate.forecast_rate_bytes_per_second, None);
        assert_eq!(estimator.forecast_history.len(), 1);
    }

    #[test]
    fn one_coarse_observation_cannot_establish_three_sustained_change_windows() {
        let (mut estimator, start, free) = warm_long_forecast();
        let estimate = estimator.update(free - 6_000_000_000, start + Duration::from_secs(60), 0);
        assert!(estimate.forecast_rate_bytes_per_second.unwrap() < 20_000_000.0);
        assert!(estimate.seconds_to_exhaustion > 3600.0);
        assert!(!estimator.recent_change_observed(start + Duration::from_secs(60)));
    }

    #[test]
    fn reload_history_bound_retains_newest_rates_and_elapsed_time_forecasts() {
        let (mut estimator, start, mut free) = warm_long_forecast();
        for step in 1..=40 {
            free -= step * 5000;
            estimator.update(free, start + Duration::from_secs(step), 0);
        }
        let rate = estimator.ewma_rate;
        let samples = estimator.sample_count();
        let forecast_samples = estimator.forecast_history.len();
        let forecast_start = estimator.forecast_history.front().unwrap().at;
        estimator.update_params(0.3, 0.1, 0.8, 5, 30);
        assert_eq!(estimator.sample_count(), samples);
        assert_eq!(estimator.ewma_rate.to_bits(), rate.to_bits());
        assert_eq!(estimator.forecast_history.len(), forecast_samples);
        assert_eq!(
            estimator.forecast_history.front().unwrap().at,
            forecast_start
        );
        assert_eq!(estimator.rate_history.len(), 30);
        assert_eq!(estimator.rate_history.front(), Some(&55_000.0));
        assert_eq!(estimator.rate_history.back(), Some(&200_000.0));
        let estimate = estimator.update(free - 205_000, start + Duration::from_secs(41), 0);
        assert!(estimate.burst_state.calibrated);
        assert!((estimate.burst_state.median_rate - 132_500.0).abs() < f64::EPSILON);

        // Growing the cap cannot resurrect discarded measurements or turn
        // the reload itself into an observed consumption interval.
        estimator.update_params(0.3, 0.1, 0.8, 5, 100);
        assert_eq!(estimator.rate_history.len(), 30);
        assert_eq!(estimator.sample_count(), samples + 1);
        estimator.update(free - 415_000, start + Duration::from_secs(42), 0);
        assert_eq!(estimator.rate_history.len(), 31);
    }

    #[cfg(feature = "daemon")]
    #[test]
    fn reforecast_uses_resized_burst_history_without_counting_cached_samples() {
        let mut estimator = DiskRateEstimator::with_history_cap(0.3, 0.1, 0.8, 5, 50);
        let start = Instant::now();
        let mut free = 1_000_000_000;
        estimator.update(free, start, 0);
        for step in 1..=40 {
            free -= 1000;
            estimator.update(free, start + Duration::from_secs(step), 0);
        }
        free -= 50_000;
        let burst = estimator.update(free, start + Duration::from_secs(41), 0);
        assert!(burst.burst_state.calibrated);
        assert_eq!(burst.burst_state.burst_duration_samples, 1);
        assert_eq!(burst.burst_state.latest_rate, Some(50_000.0));
        for _ in 0..3 {
            let replay = estimator.reforecast(&burst, 0);
            assert_eq!(replay.sample_count, burst.sample_count);
            assert_eq!(replay.burst_state.burst_duration_samples, 1);
            assert_eq!(
                replay.burst_state.latest_rate,
                burst.burst_state.latest_rate
            );
            assert_eq!(
                replay.burst_state.burst_probability.to_bits(),
                burst.burst_state.burst_probability.to_bits()
            );
        }

        estimator.update_params(0.3, 0.1, 0.8, 5, 20);
        let reduced = estimator.reforecast(&burst, 0);
        assert!(!reduced.burst_state.calibrated);
        assert_eq!(reduced.burst_state.burst_duration_samples, 0);
        assert_eq!(reduced.burst_state.latest_rate, None);
        assert_eq!(reduced.sample_count, burst.sample_count);
        assert_eq!(
            reduced.bytes_per_second.to_bits(),
            burst.bytes_per_second.to_bits()
        );
    }
}
