//! Regression traces for the complete estimator-to-predictive-policy path.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::{PredictiveAction, PredictiveActionPolicy, PredictiveConfig, median_runway_minutes};
use crate::monitor::ewma::{BurstState, DiskRateEstimator, RateEstimate, Trend};

fn policy() -> PredictiveActionPolicy {
    PredictiveActionPolicy::new(PredictiveConfig::default())
}

fn forecast(acceleration: f64, burst_probability: f64, median_rate: f64) -> RateEstimate {
    RateEstimate {
        bytes_per_second: 1000.0,
        acceleration,
        seconds_to_exhaustion: 60.0,
        seconds_to_threshold: 48.0,
        sample_count: 40,
        confidence: 0.99,
        trend: Trend::Accelerating,
        alpha_used: 0.3,
        fallback_active: false,
        burst_state: BurstState {
            calibrated: true,
            burst_probability,
            median_rate,
            burst_duration_samples: 3,
            median_consumption_rate: median_rate,
            ..BurstState::default()
        },
        free_bytes: 60_000,
    }
}

#[test]
fn burst_path_projects_the_baseline_runway_without_acceleration() {
    // 60 s at the burst-inflated 1000 B/s is 60000 bytes free. At the
    // historical 100 B/s that is 10 minutes whatever the acceleration says.
    for acceleration in [-10.0, 0.0, 200.0] {
        let estimate = forecast(acceleration, 0.6, 100.0);
        assert!((median_runway_minutes(&estimate) - 10.0).abs() < 1e-9);
        match policy().evaluate(&estimate, 10.0, PathBuf::from("/data")) {
            PredictiveAction::PreemptiveCleanup {
                minutes_remaining, ..
            } => assert!((minutes_remaining - 10.0).abs() < 1e-9),
            other => panic!("baseline 10 min from full: {other:?}"),
        }
    }
    // A safe baseline (100 minutes at 10 B/s) clears the burst.
    assert_eq!(
        policy().evaluate(&forecast(200.0, 0.6, 10.0), 10.0, PathBuf::from("/data")),
        PredictiveAction::Clear
    );
}

#[test]
fn normal_path_median_crosscheck_projects_the_baseline_runway() {
    // Below the detected-burst threshold; high confidence passes the
    // implied-rate gate, so the separate median cross-check decides.
    match policy().evaluate(&forecast(200.0, 0.3, 100.0), 30.0, PathBuf::from("/data")) {
        PredictiveAction::PreemptiveCleanup {
            minutes_remaining, ..
        } => assert!((minutes_remaining - 10.0).abs() < 1e-9),
        other => panic!("baseline 10 min from full: {other:?}"),
    }
    assert_eq!(
        policy().evaluate(&forecast(200.0, 0.3, 10.0), 30.0, PathBuf::from("/data")),
        PredictiveAction::Clear
    );
}

#[test]
fn dangerous_baseline_still_releases_ballast() {
    let estimate = forecast(2.0, 0.6, 800.0);
    let action = policy().evaluate(&estimate, 10.0, PathBuf::from("/data"));
    assert!(action.should_release_ballast());
    match action {
        PredictiveAction::ImminentDanger {
            minutes_remaining,
            critical,
            ..
        } => {
            // 1000 B/s * 60 s / 800 B/s / 60 = 1.25 minutes.
            assert!((minutes_remaining - 1.25).abs() < 1e-9);
            assert!(critical);
        }
        other => panic!("expected critical rescue, got {other:?}"),
    }
}

#[test]
fn unverifiable_median_arithmetic_cannot_authorize_cleanup() {
    for probability in [0.3, 0.6] {
        let estimate = forecast(200.0, probability, f64::MIN_POSITIVE);
        assert!(median_runway_minutes(&estimate).is_infinite());
        assert_eq!(
            policy().evaluate(&estimate, 30.0, PathBuf::from("/data")),
            PredictiveAction::Clear
        );
    }
    let estimate = forecast(200.0, 0.6, 0.0);
    assert!(median_runway_minutes(&estimate).is_infinite());
    assert_eq!(
        policy().evaluate(&estimate, 10.0, PathBuf::from("/data")),
        PredictiveAction::Clear
    );
    // An absurd acceleration cannot move the baseline runway either way.
    assert!((median_runway_minutes(&forecast(f64::MAX, 0.6, 100.0)) - 10.0).abs() < 1e-9);
}

#[test]
fn sustained_write_burst_is_actionable_before_the_burst_flag_clears() {
    let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 5);
    let start = Instant::now();
    let mut free = 900_000_000;
    let threshold = 30_000_000;
    let mut estimate = estimator.update(free, start, threshold);
    for second in 1..=140 {
        // Build a reliable 1 MB/s baseline, then a sustained 10 MB/s burst.
        // The last sample still has burst probability 0.9: waiting for the
        // detector to clear would leave this workload without pre-emption.
        free -= if second <= 100 { 1_000_000 } else { 10_000_000 };
        estimate = estimator.update(free, start + Duration::from_secs(second), threshold);
    }
    assert_eq!(free, 400_000_000);
    assert!(estimate.burst_state.calibrated);
    assert!(estimate.burst_state.burst_probability > 0.5);
    assert!(estimate.confidence > 0.95);
    assert!(!estimate.fallback_active);
    let action = policy().evaluate(&estimate, 20.0, PathBuf::from("/data"));
    match action {
        PredictiveAction::PreemptiveCleanup {
            minutes_remaining,
            confidence,
            ..
        } => {
            // The baseline is 400 MB at the 1 MB/s median.
            assert!((minutes_remaining - 400.0 / 60.0).abs() < 0.01);
            assert!(confidence >= PredictiveConfig::default().min_confidence);
        }
        other => panic!("sustained burst was not protected: {other:?}; {estimate:?}"),
    }
}

fn warmed_estimator() -> (DiskRateEstimator, Instant, u64) {
    // Fixed alpha isolates the physical trend: the policy receives real
    // estimator output, not a manually assigned trend or exhaustion time.
    let mut estimator = DiskRateEstimator::new(1.0, 1.0, 1.0, 5);
    let start = Instant::now();
    let mut free = 500_000_000;
    estimator.update(free, start, 30_000_000);
    for second in 1..=100 {
        free -= 1_000_000;
        estimator.update(free, start + Duration::from_secs(second), 30_000_000);
    }
    (estimator, start + Duration::from_secs(101), free)
}

#[test]
fn slowing_write_trace_that_still_fills_disk_triggers_cleanup() {
    let (mut estimator, next, free) = warmed_estimator();
    let estimate = estimator.update(free - 999_000, next, 30_000_000);
    assert_eq!(estimate.trend, Trend::Decelerating);
    assert!(estimate.bytes_per_second > 0.0);
    assert!(estimate.seconds_to_exhaustion.is_finite());
    assert!(estimate.seconds_to_exhaustion < 600.0);
    assert!(matches!(
        policy().evaluate(&estimate, 20.0, PathBuf::from("/data")),
        PredictiveAction::PreemptiveCleanup { .. }
    ));
}

/// One slower sample is not a writer stopping: extrapolating that single
/// deceleration used to report "never fills" for a disk still filling.
#[test]
fn one_slower_sample_does_not_cancel_a_filling_forecast() {
    let (mut estimator, next, free) = warmed_estimator();
    let estimate = estimator.update(free - 900_000, next, 30_000_000);
    assert_eq!(estimate.trend, Trend::Decelerating);
    assert!(estimate.bytes_per_second > 0.0);
    // 399.1 MB free at 0.9 MB/s.
    assert!((estimate.seconds_to_exhaustion - 399_100_000.0 / 900_000.0).abs() < 1e-6);
    assert!(matches!(
        policy().evaluate(&estimate, 20.0, PathBuf::from("/data")),
        PredictiveAction::PreemptiveCleanup { .. }
    ));
}

#[test]
fn recovery_trace_stops_predictive_cleanup() {
    let (mut estimator, next, free) = warmed_estimator();
    let estimate = estimator.update(free + 1_000_000, next, 30_000_000);
    assert_eq!(estimate.trend, Trend::Recovering);
    assert!(estimate.bytes_per_second < 0.0);
    assert_eq!(
        policy().evaluate(&estimate, 20.0, PathBuf::from("/data")),
        PredictiveAction::Clear
    );
}
