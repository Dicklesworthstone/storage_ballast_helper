//! Exercise the production pass guard with scripted cumulative CPU readings.
//! These tests do not measure real host CPU or replace the caller's wall budget.

use super::PassCpuGuard;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn scripted(
    allowance: f64,
    now: Instant,
    samples: impl IntoIterator<Item = Option<f64>>,
) -> (PassCpuGuard, Arc<AtomicUsize>) {
    let mut samples: VecDeque<_> = samples.into_iter().collect();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed_calls = Arc::clone(&calls);
    let guard = PassCpuGuard::new(Some(allowance), now, move || {
        observed_calls.fetch_add(1, Ordering::Relaxed);
        samples.pop_front().expect("unexpected extra CPU query")
    })
    .with_sample_interval(Duration::from_millis(100));
    (guard, calls)
}

#[test]
fn failed_startup_read_recovers_without_charging_process_lifetime_cpu() {
    let t0 = Instant::now();
    let (mut guard, calls) = scripted(2.0, t0, [None, None, Some(400.0), Some(401.5), Some(402.0)]);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert!(!guard.exhausted(t0 + Duration::from_millis(100)));
    assert_eq!(guard.spent_secs(), 0.0);
    assert!(!guard.exhausted(t0 + Duration::from_millis(200)));
    assert_eq!(
        guard.spent_secs(),
        0.0,
        "400 seconds are not this pass's cost"
    );
    assert!(!guard.exhausted(t0 + Duration::from_millis(300)));
    assert_eq!(guard.spent_secs(), 1.5);
    assert!(guard.exhausted(t0 + Duration::from_millis(400)));
    assert_eq!(guard.spent_secs(), 2.0);
    assert!(guard.exhausted(t0 + Duration::from_secs(100)));
    assert_eq!(calls.load(Ordering::Relaxed), 5, "exhaustion stays latched");
}

#[test]
fn unusable_startup_counters_are_not_a_baseline_or_permanent_bypass() {
    for initial in [
        None,
        Some(f64::NAN),
        Some(f64::INFINITY),
        Some(f64::NEG_INFINITY),
        Some(-1.0),
    ] {
        let t0 = Instant::now();
        let (mut guard, _) = scripted(2.0, t0, [initial, Some(1000.0), Some(1002.0)]);
        assert!(
            !guard.exhausted(t0 + Duration::from_millis(100)),
            "{initial:?}"
        );
        assert_eq!(guard.spent_secs(), 0.0);
        assert!(
            guard.exhausted(t0 + Duration::from_millis(200)),
            "{initial:?}"
        );
        assert_eq!(guard.spent_secs(), 2.0);
    }
}

#[test]
fn temporary_read_failures_do_not_restart_an_established_allowance() {
    let t0 = Instant::now();
    let (mut guard, calls) = scripted(2.0, t0, [Some(10.0), None, Some(11.0), None, Some(12.0)]);
    for (tick, expected) in [(1, 0.0), (2, 1.0), (3, 1.0)] {
        assert!(!guard.exhausted(t0 + Duration::from_millis(tick * 100)));
        assert_eq!(guard.spent_secs(), expected);
    }
    assert!(guard.exhausted(t0 + Duration::from_millis(400)));
    assert_eq!(
        guard.spent_secs(),
        2.0,
        "the cumulative counter covers both gaps"
    );
    assert_eq!(calls.load(Ordering::Relaxed), 5);
}

#[test]
fn invalid_and_regressing_readings_never_refund_observed_cpu() {
    let t0 = Instant::now();
    let bad = [
        Some(11.0),
        Some(9.0),
        None,
        Some(f64::NAN),
        Some(f64::INFINITY),
        Some(f64::NEG_INFINITY),
        Some(-1.0),
    ];
    let samples = [Some(10.0), Some(11.5)]
        .into_iter()
        .chain(bad)
        .chain([Some(12.0)]);
    let (mut guard, _) = scripted(2.0, t0, samples);
    assert!(!guard.exhausted(t0 + Duration::from_millis(100)));
    assert_eq!(guard.spent_secs(), 1.5);
    for tick in 2..=8 {
        assert!(!guard.exhausted(t0 + Duration::from_millis(tick * 100)));
        assert_eq!(guard.spent_secs(), 1.5);
    }
    assert!(guard.exhausted(t0 + Duration::from_millis(900)));
    assert_eq!(guard.spent_secs(), 2.0);
}

#[test]
fn final_accounting_preserves_cost_when_its_last_sample_is_unusable() {
    for last in [
        None,
        Some(9.0),
        Some(11.0),
        Some(f64::NAN),
        Some(f64::INFINITY),
        Some(-1.0),
    ] {
        let t0 = Instant::now();
        let (mut guard, calls) = scripted(2.0, t0, [Some(10.0), Some(12.0), last]);
        assert!(guard.exhausted(t0 + Duration::from_millis(100)));
        assert_eq!(guard.finish(), 2.0, "{last:?}");
        assert!(guard.exhausted(t0 + Duration::from_secs(1)));
        assert_eq!(calls.load(Ordering::Relaxed), 3);
    }
    let t0 = Instant::now();
    let (mut guard, _) = scripted(2.0, t0, [Some(10.0), Some(12.0), Some(13.0)]);
    assert!(guard.exhausted(t0 + Duration::from_millis(100)));
    assert_eq!(
        guard.finish(),
        3.0,
        "final accounting includes observed overshoot"
    );
}

#[test]
fn persistent_measurement_failure_stays_wall_bounded_without_hot_polling() {
    let t0 = Instant::now();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed_calls = Arc::clone(&calls);
    let mut guard = PassCpuGuard::new(Some(2.0), t0, move || {
        observed_calls.fetch_add(1, Ordering::Relaxed);
        None
    })
    .with_sample_interval(Duration::from_millis(100));
    for ms in 0..100 {
        assert!(!guard.exhausted(t0 + Duration::from_millis(ms)));
    }
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert!(!guard.exhausted(t0 + Duration::from_millis(100)));
    for _ in 0..100 {
        assert!(!guard.exhausted(t0 + Duration::from_millis(100)));
        assert!(!guard.exhausted(t0 + Duration::from_millis(50)));
        assert!(!guard.exhausted(t0 + Duration::from_millis(199)));
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert!(!guard.exhausted(t0 + Duration::from_millis(200)));
    assert_eq!(calls.load(Ordering::Relaxed), 3);
    assert_eq!(
        guard.spent_secs(),
        0.0,
        "unknown measurements invent no cost"
    );
}

#[test]
fn finish_can_observe_recovery_but_does_not_invent_an_unmeasured_prefix() {
    let t0 = Instant::now();
    let (mut guard, calls) = scripted(2.0, t0, [None, Some(900.0), Some(901.0)]);
    assert_eq!(
        guard.finish(),
        0.0,
        "first valid reading is only a baseline"
    );
    assert_eq!(guard.finish(), 1.0);
    assert_eq!(calls.load(Ordering::Relaxed), 3);
}

#[test]
fn recovery_keeps_the_original_sampling_interval_and_bypasses_stay_unlimited() {
    let t0 = Instant::now();
    let (mut guard, calls) = scripted(2.0, t0, [None, Some(100.0), Some(102.0)]);
    assert!(!guard.exhausted(t0 + Duration::from_millis(100)));
    assert!(!guard.exhausted(t0 + Duration::from_millis(199)));
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert!(guard.exhausted(t0 + Duration::from_millis(200)));
    // A missing sample does not turn an intentionally unlimited guard into a
    // limited guard when telemetry later recovers. Final accounting still works.
    let mut samples = VecDeque::from([None, Some(1000.0), Some(2000.0)]);
    let mut unlimited = PassCpuGuard::new(None, t0, move || samples.pop_front().unwrap());
    assert!(!unlimited.exhausted(t0 + Duration::from_secs(100)));
    assert_eq!(unlimited.finish(), 0.0);
    assert_eq!(unlimited.finish(), 1000.0);
    assert!(!unlimited.exhausted(t0 + Duration::from_secs(1000)));
}

#[test]
fn zero_interval_still_rejects_a_regressing_observation_clock() {
    let t0 = Instant::now();
    let (mut guard, calls) = scripted(2.0, t0, [None, Some(10.0), Some(12.0)]);
    guard = guard.with_sample_interval(Duration::ZERO);
    assert!(!guard.exhausted(t0 + Duration::from_secs(1)));
    assert!(!guard.exhausted(t0));
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert!(guard.exhausted(t0 + Duration::from_secs(1)));
    assert_eq!(calls.load(Ordering::Relaxed), 3);
}

#[test]
fn guard_monotonically_tracks_the_largest_valid_delta_in_a_mixed_sequence() {
    // Independent expectation computed directly from the cumulative readings,
    // including failures before and after baseline acquisition, not by calling
    // the production sampling helper. Keep the allowance above the whole trace.
    let mut readings = Vec::new();
    for step in 0..256_u32 {
        readings.push(match step % 11 {
            0 => None,
            1 => Some(f64::NAN),
            2 => Some(f64::INFINITY),
            3 => Some(-1.0),
            4 => Some(1000.0),
            _ => Some(1000.0 + f64::from(step) / 4.0),
        });
    }
    let now = Instant::now();
    let state = Arc::new(Mutex::new(None));
    let sample = Arc::clone(&state);
    let mut guard = PassCpuGuard::new(Some(1000.0), now, move || *sample.lock().unwrap())
        .with_sample_interval(Duration::ZERO);
    let mut baseline = None;
    let mut greatest: f64 = 0.0;
    for reading in readings {
        *state.lock().unwrap() = reading;
        if let Some(current) = reading.filter(|value| value.is_finite() && *value >= 0.0) {
            if let Some(first) = baseline {
                let delta: f64 = current - first;
                greatest = greatest.max(delta);
            } else {
                baseline = Some(current);
            }
        }
        assert!(!guard.exhausted(now));
        assert_eq!(guard.spent_secs(), greatest);
        assert!(guard.spent_secs().is_finite());
    }
}
