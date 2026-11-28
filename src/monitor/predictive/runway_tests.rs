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
        forecast_rate_bytes_per_second: None,
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
fn long_window_forecasts_remain_clear_for_noisy_drain_at_low_free_percent() {
    let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 5);
    let start = Instant::now();
    let initial_free = 80_000_000_000;
    estimator.update(initial_free, start, 40_000_000_000);
    let mut short_ewma_forecasts = 0;
    let mut recovering_ewma_samples = 0;
    for seconds in (5..=1800_u64).step_by(5) {
        let phase = seconds % 60;
        let transient = phase.min(60 - phase) * 60_000_000;
        let free = initial_free - seconds * 3_000_000 - transient;
        let estimate = estimator.update(free, start + Duration::from_secs(seconds), 40_000_000_000);
        if seconds < 900 {
            continue;
        }
        if estimate.bytes_per_second > 0.0 && free as f64 / estimate.bytes_per_second < 3600.0 {
            short_ewma_forecasts += 1;
        }
        recovering_ewma_samples += usize::from(estimate.trend == Trend::Recovering);
        assert_eq!(
            policy().evaluate(&estimate, 9.0, PathBuf::from("/data")),
            PredictiveAction::Clear,
            "large, mostly full build disk still has hours of net runway: {estimate:?}"
        );
    }
    assert!(
        short_ewma_forecasts > 0,
        "fixture must contain transient warning forecasts"
    );
    assert!(
        recovering_ewma_samples > 0,
        "fixture must contain transient recovery forecasts"
    );
}

#[test]
fn long_window_net_drain_remains_actionable_during_a_short_freeing_interval() {
    let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 5);
    let start = Instant::now();
    let initial_free = 25_000_000_000;
    let mut estimate = estimator.update(initial_free, start, 0);
    for seconds in (5..=900_u64).step_by(5) {
        let phase = seconds % 100;
        let transient = phase.min(100 - phase) * 60_000_000;
        let free = initial_free - seconds * 10_000_000 - transient;
        estimate = estimator.update(free, start + Duration::from_secs(seconds), 0);
    }
    assert_eq!(estimate.trend, Trend::Recovering);
    assert!((estimate.forecast_rate_bytes_per_second.unwrap() - 10_000_000.0).abs() < 1e-6);
    assert!(
        matches!(
            policy().evaluate(&estimate, 9.0, PathBuf::from("/data")),
            PredictiveAction::PreemptiveCleanup { .. }
        ),
        "a brief release cannot hide the measured net drain: {estimate:?}"
    );
}

#[test]
fn long_window_policy_recognizes_a_new_sustained_writer_at_any_free_percent() {
    let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 5);
    let start = Instant::now();
    let mut free = 80_000_000_000;
    let mut estimate = estimator.update(free, start, 0);
    for seconds in (5..=960_u64).step_by(5) {
        let rate = if seconds <= 900 {
            2_000_000
        } else {
            100_000_000
        };
        free -= 5 * rate;
        estimate = estimator.update(free, start + Duration::from_secs(seconds), 0);
    }
    assert!(estimate.burst_state.burst_probability > 0.5);
    assert_eq!(estimate.forecast_rate_bytes_per_second, Some(100_000_000.0));
    for free_pct in [9.0, 90.0] {
        match policy().evaluate(&estimate, free_pct, PathBuf::from("/data")) {
            PredictiveAction::PreemptiveCleanup {
                minutes_remaining, ..
            } => {
                assert!((minutes_remaining - free as f64 / 100_000_000.0 / 60.0).abs() < 1e-6);
            }
            action => panic!("confirmed new writer at {free_pct}%: {action:?}; {estimate:?}"),
        }
    }
}

#[test]
fn sustained_writer_keeps_protection_when_the_immediate_forecast_takes_over() {
    // The long-window estimator has proved a new 100 MB/s writer after a
    // minute, but the burst median still reflects the old 2 MB/s workload.
    // Approaching Red or full must not discard that proof and change cleanup
    // back to Clear just because the immediate EWMA runway falls below 5 min.
    for (initial_free, threshold) in [
        (80_000_000_000_u64, 50_000_000_000_u64),
        (40_000_000_000, 0),
    ] {
        let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 5);
        let start = Instant::now();
        let mut free = initial_free;
        estimator.update(free, start, threshold);
        let mut crossed_fast_boundary = false;
        let mut rescued_before_full = false;
        for seconds in (5..=1080_u64).step_by(5) {
            free -= 5 * if seconds <= 900 {
                2_000_000
            } else {
                100_000_000
            };
            let estimate = estimator.update(free, start + Duration::from_secs(seconds), threshold);
            if seconds < 960 {
                continue;
            }
            let distance = free - threshold;
            let immediate_seconds = distance as f64 / estimate.bytes_per_second;
            let action = policy().evaluate(&estimate, 9.0, PathBuf::from("/data"));
            assert!(
                action.should_cleanup(),
                "confirmed writer lost protection at {seconds}s: {action:?}; {estimate:?}"
            );
            if immediate_seconds <= 300.0 {
                crossed_fast_boundary = true;
                assert!(
                    estimate.seconds_to_threshold <= immediate_seconds + 1e-6,
                    "corroboration must not delay an imminent boundary: {estimate:?}"
                );
                if threshold == 0 {
                    rescued_before_full = true;
                    assert!(
                        action.should_release_ballast(),
                        "confirmed imminent exhaustion must retain ballast rescue: {action:?}"
                    );
                }
            }
        }
        assert!(
            crossed_fast_boundary,
            "fixture must enter the immediate path"
        );
        assert_eq!(rescued_before_full, threshold == 0);
    }
}

#[test]
fn transient_writer_near_a_boundary_does_not_gain_sustained_authority() {
    let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 5);
    let start = Instant::now();
    let mut free = 40_000_000_000;
    estimator.update(free, start, 34_000_000_000);
    for seconds in (5..=900_u64).step_by(5) {
        free -= 5 * 2_000_000;
        estimator.update(free, start + Duration::from_secs(seconds), 34_000_000_000);
    }
    let mut saw_fast_forecast = false;
    let mut saw_post_burst_tail = false;
    for seconds in (905..=960_u64).step_by(5) {
        // Thirty seconds of allocation, followed by a return to the ordinary
        // rate, never establish three consistent twenty-second windows.
        free -= 5 * if seconds <= 930 {
            100_000_000
        } else {
            2_000_000
        };
        let estimate = estimator.update(free, start + Duration::from_secs(seconds), 34_000_000_000);
        if (free - 34_000_000_000) as f64 / estimate.bytes_per_second <= 300.0 {
            saw_fast_forecast = true;
            assert!(estimate.forecast_rate_bytes_per_second.is_none());
        }
        saw_post_burst_tail |= seconds > 930
            && estimate.burst_state.burst_probability < 0.5
            && estimate.forecast_rate_bytes_per_second.is_none()
            && estimate.seconds_to_exhaustion < 30.0 * 60.0;
        for free_pct in [1.0, 9.0, 15.0, 20.0, 25.0, 30.0, 90.0] {
            assert_eq!(
                policy().evaluate(&estimate, free_pct, PathBuf::from("/data")),
                PredictiveAction::Clear,
                "a transient allocation at {free_pct}% cannot corroborate itself: {estimate:?}"
            );
        }
    }
    assert!(
        saw_fast_forecast,
        "fixture must exercise the immediate path"
    );
    assert!(
        saw_post_burst_tail,
        "fixture must retain a short EWMA forecast after the burst flag clears"
    );
}

fn estimator_after_idle_burst() -> (DiskRateEstimator, Instant, u64) {
    let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 5);
    let start = Instant::now();
    let mut free = 6_000_000_000;
    estimator.update(free, start, 0);
    for seconds in (5..=900_u64).step_by(5) {
        estimator.update(free, start + Duration::from_secs(seconds), 0);
    }
    for seconds in (905..=930_u64).step_by(5) {
        free -= 500_000_000;
        estimator.update(free, start + Duration::from_secs(seconds), 0);
    }
    (estimator, start, free)
}

#[test]
fn releases_do_not_back_a_rescue_after_a_short_writer_returns_to_background() {
    let mib = 1_u64 << 20;
    for (release_ticks, slow_ticks, typical_mib) in [(60, 25, 0), (40, 45, 1)] {
        let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 5);
        let start = Instant::now();
        let mut free = 4000 * mib;
        estimator.update(free, start, 0);
        let mut tick = 0;
        // Interleave enough large frees and a brief burst for the median
        // absolute movement to be large in both traces. The second trace
        // has a consuming majority, but its typical write rate is low.
        for (ticks, change) in [(release_ticks, 100_i64), (slow_ticks, -1), (10, -100)] {
            for interval in 1..=ticks {
                tick += 1;
                free = free.checked_add_signed(change * (1_i64 << 20)).unwrap();
                let estimate = estimator.update(free, start + Duration::from_secs(tick), 0);
                if change == -100 && interval == ticks {
                    assert!(
                        policy()
                            .evaluate(&estimate, 9.0, PathBuf::from("/data"))
                            .should_release_ballast(),
                        "the active rapid writer still needs rescue: {estimate:?}"
                    );
                }
            }
        }
        free -= mib;
        let estimate = estimator.update(free, start + Duration::from_secs(tick + 1), 0);
        assert!(estimate.forecast_rate_bytes_per_second.is_none());
        assert!(estimate.seconds_to_exhaustion < 300.0);
        assert_eq!(estimate.burst_state.median_rate, (100 * mib) as f64);
        assert_eq!(
            estimate.burst_state.median_drain_rate,
            (typical_mib * mib) as f64
        );
        assert!(free / mib > 3600);
        assert_eq!(
            policy().evaluate(&estimate, 9.0, PathBuf::from("/data")),
            PredictiveAction::Clear,
            "{estimate:?}"
        );
    }
}

#[test]
fn ordinary_consumption_retains_its_conformal_early_action() {
    let mut estimate = forecast(0.0, 0.3, 1000.0);
    estimate.free_bytes = 45 * 60 * 1000;
    estimate.seconds_to_exhaustion = 20.0 * 60.0;
    estimate.burst_state.median_drain_rate = 1000.0;
    estimate.burst_state.latest_rate = Some(1000.0);
    assert!(matches!(
        policy().evaluate(&estimate, 9.0, PathBuf::from("/data")),
        PredictiveAction::PreemptiveCleanup {
            minutes_remaining: 20.0,
            ..
        }
    ));
}

#[test]
fn stopped_burst_cannot_trigger_ballast_release_before_calibration() {
    // Exercise both a fresh daemon and a history configured below the
    // calibration minimum. In each, the EWMA still projects seconds to full
    // after a burst drains 3 GB at 100 MB/s and then stops.
    for (cap, idle_intervals) in [(200, 12_u64), (20, 35)] {
        let mut estimator = DiskRateEstimator::with_history_cap(0.3, 0.1, 0.8, 5, cap);
        let start = Instant::now();
        let mut free = 3_500_000_000;
        let mut estimate = estimator.update(free, start, 0);
        for tick in 1..=idle_intervals + 6 {
            if tick > idle_intervals {
                free -= 500_000_000;
            }
            estimate = estimator.update(free, start + Duration::from_secs(5 * tick), 0);
        }
        let evaluate = |sample: &RateEstimate| policy().evaluate(sample, 9.0, "/data".into());
        assert!(!estimate.burst_state.calibrated);
        assert!(evaluate(&estimate).should_release_ballast(), "{estimate:?}");

        let after_burst = start + Duration::from_secs(5 * (idle_intervals + 7));
        let idle = estimator.update(free, after_burst, 0);
        assert!(idle.seconds_to_exhaustion < 60.0);
        assert!(idle.confidence >= PredictiveConfig::default().min_confidence);
        assert_eq!(evaluate(&idle), PredictiveAction::Clear, "{idle:?}");

        free -= 5_000_000;
        let slow = estimator.update(free, after_burst + Duration::from_secs(5), 0);
        assert!(slow.seconds_to_exhaustion < 60.0);
        match evaluate(&slow) {
            PredictiveAction::PreemptiveCleanup {
                minutes_remaining, ..
            } => assert!((minutes_remaining - 8.25).abs() < 1e-6),
            action => panic!("expected the slower writer's measured runway: {action:?}; {slow:?}"),
        }
    }
}

#[test]
fn transient_writer_after_idle_does_not_corroborate_its_residual_forecast() {
    for tail_bytes_per_interval in [0_u64, 4096] {
        let (mut estimator, start, mut free) = estimator_after_idle_burst();
        let mut saw_uncorroborated_fast_forecast = false;
        for seconds in (935..=990_u64).step_by(5) {
            free -= tail_bytes_per_interval;
            let estimate = estimator.update(free, start + Duration::from_secs(seconds), 0);
            assert!(estimate.burst_state.calibrated);
            assert_eq!(estimate.burst_state.median_rate, 0.0);
            assert_eq!(
                estimate.burst_state.latest_rate,
                Some(tail_bytes_per_interval as f64 / 5.0)
            );
            saw_uncorroborated_fast_forecast |= estimate.forecast_rate_bytes_per_second.is_none()
                && estimate.seconds_to_exhaustion < 300.0
                && estimate.confidence >= PredictiveConfig::default().min_confidence;
            for free_pct in [9.0, 90.0] {
                assert_eq!(
                    policy().evaluate(&estimate, free_pct, PathBuf::from("/data")),
                    PredictiveAction::Clear,
                    "transient writer at {seconds}s and {free_pct}% with {tail_bytes_per_interval} byte tail cannot corroborate its own EWMA: {estimate:?}"
                );
            }
        }
        assert!(
            saw_uncorroborated_fast_forecast,
            "fixture must retain an actionable immediate EWMA without persistence evidence"
        );
    }
}

#[test]
fn slower_writer_after_idle_burst_uses_its_measured_runway() {
    let (mut estimator, start, mut free) = estimator_after_idle_burst();
    free -= 5 * 2_000_000;
    let estimate = estimator.update(free, start + Duration::from_secs(935), 0);
    assert_eq!(estimate.burst_state.median_rate, 0.0);
    assert_eq!(estimate.burst_state.latest_rate, Some(2_000_000.0));
    assert!(estimate.forecast_rate_bytes_per_second.is_none());
    assert!(estimate.seconds_to_exhaustion < 120.0);
    match policy().evaluate(&estimate, 9.0, PathBuf::from("/data")) {
        PredictiveAction::PreemptiveCleanup {
            minutes_remaining, ..
        } => {
            assert!((minutes_remaining - free as f64 / 2_000_000.0 / 60.0).abs() < 1e-6);
        }
        action => panic!(
            "slower writer still needs cleanup at its measured runway: {action:?}; {estimate:?}"
        ),
    }
}

#[test]
fn idle_baseline_does_not_delay_a_live_rapid_writer() {
    // At 5-second polling the writer has only seconds left; at 60-second
    // polling the persistence windows cannot be independently observed.
    // Both need the immediate rescue path before a minute of corroboration.
    for (interval, initial_free, consuming_intervals) in
        [(5_u64, 2_500_000_000_u64, 4_u64), (60, 9_000_000_000, 1)]
    {
        let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 5);
        let start = Instant::now();
        let mut free = initial_free;
        estimator.update(free, start, 0);
        for seconds in (interval..=1800).step_by(usize::try_from(interval).unwrap()) {
            estimator.update(free, start + Duration::from_secs(seconds), 0);
        }
        for tick in 1..=consuming_intervals {
            free -= interval * 100_000_000;
            let estimate =
                estimator.update(free, start + Duration::from_secs(1800 + tick * interval), 0);
            assert!(estimate.burst_state.calibrated);
            assert_eq!(estimate.burst_state.median_rate, 0.0);
            assert_eq!(estimate.burst_state.latest_rate, Some(100_000_000.0));
            assert!(estimate.forecast_rate_bytes_per_second.is_none());
            assert!(free as f64 / 100_000_000.0 < 60.0);
            for free_pct in [9.0, 90.0] {
                let action = policy().evaluate(&estimate, free_pct, PathBuf::from("/data"));
                assert!(
                    action.should_release_ballast(),
                    "live rapid writer at {interval}s polling and {free_pct}% must retain rescue: {action:?}; {estimate:?}"
                );
            }
        }
    }
}

#[test]
fn confirmed_writer_keeps_rescue_during_a_brief_idle_interval() {
    let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 5);
    let start = Instant::now();
    let mut free = 10_000_000_000;
    estimator.update(free, start, 0);
    for seconds in (5..=900_u64).step_by(5) {
        estimator.update(free, start + Duration::from_secs(seconds), 0);
    }
    for seconds in (905..=960_u64).step_by(5) {
        free -= 500_000_000;
        estimator.update(free, start + Duration::from_secs(seconds), 0);
    }
    let estimate = estimator.update(free, start + Duration::from_secs(965), 0);
    assert_eq!(estimate.burst_state.median_rate, 0.0);
    assert_eq!(estimate.burst_state.latest_rate, Some(0.0));
    assert!(
        estimate
            .forecast_rate_bytes_per_second
            .is_some_and(|rate| rate > 0.0)
    );
    for free_pct in [9.0, 90.0] {
        let action = policy().evaluate(&estimate, free_pct, PathBuf::from("/data"));
        assert!(
            action.should_release_ballast(),
            "one idle interval cannot erase confirmed net drain: {action:?}; {estimate:?}"
        );
    }
}

#[test]
fn fast_polling_spike_cannot_borrow_sustained_consumption_evidence() {
    let mut estimator = DiskRateEstimator::new(0.3, 0.1, 0.8, 5);
    let start = Instant::now();
    let mut free = 3_800_000_000;
    estimator.update(free, start, 0);
    for tick in 1..=9000_u64 {
        free -= 200_000;
        estimator.update(free, start + Duration::from_millis(tick * 100), 0);
    }
    assert_eq!(free, 2_000_000_000);

    // One 100 ms allocation at 400 MB/s doubles the last 20-second bucket's
    // measured rate (still inside the window-consistency bound), but inflates
    // the immediate EWMA twentyfold. Those windows corroborate the ordinary
    // writer, not the inflated spike. Keep PID's immediate conservative input
    // without allowing it to bypass the predictive burst gate.
    free -= 40_000_000;
    let estimate = estimator.update(free, start + Duration::from_millis(900_100), 0);
    assert!(estimate.bytes_per_second > 40_000_000.0);
    assert!(estimate.seconds_to_threshold < 60.0);
    assert!(estimate.forecast_rate_bytes_per_second.is_none());
    assert_eq!(
        policy().evaluate(&estimate, 9.0, PathBuf::from("/data")),
        PredictiveAction::Clear,
        "a fast-poll spike cannot turn a sustained 16-minute runway into Critical: {estimate:?}"
    );
}

#[test]
fn long_window_policy_preserves_confidence_and_evidence_gates() {
    let mut base = forecast(0.0, 0.9, 1.0);
    base.forecast_rate_bytes_per_second = Some(1000.0);
    for invalid in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, 0.0] {
        let mut estimate = base.clone();
        estimate.forecast_rate_bytes_per_second = Some(invalid);
        assert_eq!(
            policy().evaluate(&estimate, 9.0, PathBuf::from("/data")),
            PredictiveAction::Clear
        );
    }
    let mut low_confidence = base.clone();
    low_confidence.confidence = 0.2;
    let mut warming = base.clone();
    warming.sample_count = 1;
    let mut fallback = base;
    fallback.fallback_active = true;
    for estimate in [low_confidence, warming, fallback] {
        assert_eq!(
            policy().evaluate(&estimate, 9.0, PathBuf::from("/data")),
            PredictiveAction::Clear
        );
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
    // implied-rate gate, so the separate median cross-check decides. Low
    // free percentages still admit real danger at the measured baseline.
    for free_pct in [1.0, 9.0, 15.0, 25.0, 30.0, 90.0] {
        match policy().evaluate(
            &forecast(200.0, 0.3, 100.0),
            free_pct,
            PathBuf::from("/data"),
        ) {
            PredictiveAction::PreemptiveCleanup {
                minutes_remaining, ..
            } => assert!((minutes_remaining - 10.0).abs() < 1e-9),
            other => panic!("baseline 10 min from full at {free_pct}%: {other:?}"),
        }
        assert_eq!(
            policy().evaluate(
                &forecast(200.0, 0.3, 10.0),
                free_pct,
                PathBuf::from("/data")
            ),
            PredictiveAction::Clear
        );
    }
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

#[test]
fn corrected_forecast_cannot_shorten_an_independent_median_baseline() {
    let mib = 1_u64 << 20;
    let gib = 1_u64 << 30;
    // Cover both the detected-burst path and the separate median cross-check.
    for (probability, free_pct, median_mib) in [(0.6, 12.0, 50.0), (0.3, 30.0, 20.0)] {
        let mut estimate = forecast(200.0, probability, median_mib * mib as f64);
        estimate.bytes_per_second = 100.0 * mib as f64;
        estimate.free_bytes = 200 * gib;
        // The daemon has already corrected this forecast to one minute.
        // Its measured baseline still has more than an hour of free space.
        estimate.seconds_to_exhaustion = 60.0;
        let expected_minutes = 200.0 * 1024.0 / median_mib / 60.0;
        assert!((median_runway_minutes(&estimate) - expected_minutes).abs() < 1e-9);
        assert_eq!(
            policy().evaluate(&estimate, free_pct, PathBuf::from("/data")),
            PredictiveAction::Clear,
            "a corrected forecast cannot corroborate itself: {estimate:?}"
        );
    }
}

#[test]
fn measured_burst_baseline_preserves_genuine_imminence_and_longer_forecasts() {
    let mib = 1_u64 << 20;
    let gib = 1_u64 << 30;
    for (free_gib, critical) in [(4, true), (8, false)] {
        let mut estimate = forecast(200.0, 0.6, 50.0 * mib as f64);
        estimate.bytes_per_second = 100.0 * mib as f64;
        estimate.free_bytes = free_gib * gib;
        let expected_minutes = free_gib as f64 * 1024.0 / 50.0 / 60.0;
        match policy().evaluate(&estimate, 12.0, PathBuf::from("/data")) {
            PredictiveAction::ImminentDanger {
                minutes_remaining,
                critical: actual_critical,
                ..
            } => {
                assert!((minutes_remaining - expected_minutes).abs() < 1e-9);
                assert_eq!(actual_critical, critical);
            }
            other => panic!("measured imminent exhaustion must remain actionable: {other:?}"),
        }

        // Independent evidence never makes a longer EWMA runway shorter.
        estimate.seconds_to_exhaustion = 45.0 * 60.0;
        match policy().evaluate(&estimate, 12.0, PathBuf::from("/data")) {
            PredictiveAction::EarlyWarning {
                minutes_remaining, ..
            } => assert!((minutes_remaining - 45.0).abs() < 1e-9),
            other => panic!("the longer forecast must win: {other:?}"),
        }
    }
}

#[test]
fn measured_median_runway_refuses_invalid_rates() {
    for median in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 0.0, -1.0] {
        assert!(
            median_runway_minutes(&forecast(0.0, 0.6, median)).is_infinite(),
            "invalid historical rate {median} must not authorize cleanup"
        );
    }
}
