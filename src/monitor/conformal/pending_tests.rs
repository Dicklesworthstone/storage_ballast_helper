//! Admission and resolution regressions through the live calibrator API.

use super::*;
use std::time::Duration;

fn calibrator(window: usize) -> ConformalCalibrator {
    ConformalCalibrator::new(ConformalConfig {
        window,
        warmup: window.max(1),
        ..ConformalConfig::default()
    })
}

#[test]
fn frequent_polling_cannot_evict_every_forecast_before_its_horizon() {
    let start = Instant::now();
    let mut c = calibrator(4);
    let mut admitted = 0;
    let mut resolved = 0;
    for second in 0..=6000 {
        let now = start + Duration::from_secs(second);
        resolved += c.observe(now, false).resolved;
        admitted += usize::from(c.enroll(now, 1200.0));
        assert!(c.pending() <= 4);
        assert_eq!(admitted, resolved + c.pending());
    }
    // Evict-on-full resolved nothing in this trace: every pending forecast
    // was replaced within four seconds, far before its 1200-second horizon.
    assert!(resolved >= 16, "no completed horizons: {resolved}");
    assert_eq!(c.resolved_total(), resolved as u64);
    assert_eq!(c.samples(), 4);
    assert_eq!(c.coverage_state(), CoverageState::Calibrated);
    assert_eq!(c.coverage_empirical(), Some(1.0));
}

#[test]
fn a_full_window_preserves_issue_times_and_bounds_until_crossing() {
    let start = Instant::now();
    let mut c = calibrator(4);
    let mut reference = calibrator(4);
    for second in 0..4 {
        assert!(c.enroll(start + Duration::from_secs(second), 100.0));
    }
    let alpha = c.alpha();
    for second in 4..50 {
        let now = start + Duration::from_secs(second);
        assert_eq!(c.observe(now, false), ResolvedBatch::default());
        assert!(!c.enroll(now, 1.0), "full admission must not replace a forecast");
    }
    assert_eq!(c.alpha(), alpha);
    assert_eq!(c.samples(), 0);
    let batch = c.observe(start + Duration::from_secs(50), true);
    assert_eq!((batch.resolved, batch.covered, batch.missed), (4, 0, 4));
    for second in 0..4 {
        assert_eq!(reference.record(100.0, f64::from(50 - second), 100.0), Some(false));
    }
    assert_eq!(c.scores, reference.scores);
    assert_eq!(c.alpha(), reference.alpha());
    assert_eq!(c.pending(), 0);
    assert!(c.enroll(start + Duration::from_secs(50), 100.0));
}

#[test]
fn later_short_horizons_resolve_without_waiting_for_the_oldest_forecast() {
    let start = Instant::now();
    let mut c = calibrator(3);
    assert!(c.enroll(start, 300.0));
    assert!(c.enroll(start + Duration::from_secs(1), 10.0));
    assert!(c.enroll(start + Duration::from_secs(2), 200.0));
    assert!(!c.enroll(start + Duration::from_secs(3), 1.0));
    assert_eq!(c.observe(start + Duration::from_secs(11), false).resolved, 1);
    assert_eq!(c.pending(), 2);
    assert!(c.enroll(start + Duration::from_secs(11), 1.0));
    assert_eq!(c.observe(start + Duration::from_secs(12), false).resolved, 1);
    assert_eq!(c.observe(start + Duration::from_secs(300), false).resolved, 2);
    assert_eq!(c.resolved_total(), 4);
    assert_eq!(c.pending(), 0);
}

#[test]
fn duplicate_timestamps_cannot_manufacture_calibration_samples() {
    let start = Instant::now();
    let mut c = calibrator(4);
    assert!(c.enroll(start, 60.0));
    for _ in 0..1000 {
        assert!(!c.enroll(start, 60.0));
    }
    assert_eq!(c.observe(start, true), ResolvedBatch::default());
    assert_eq!(c.pending(), 1, "a forecast cannot evaluate its own issuing sample");
    let next = start + Duration::from_secs(60);
    assert_eq!(c.observe(next, false).resolved, 1);
    assert!(c.enroll(next, 60.0));
    assert_eq!(c.observe(next, true), ResolvedBatch::default());
    assert_eq!(c.pending(), 1);
    assert_eq!(c.resolved_total(), 1);
}

#[test]
fn out_of_order_observations_leave_pending_and_resolved_evidence_unchanged() {
    let start = Instant::now();
    let mut c = calibrator(4);
    assert!(c.enroll(start + Duration::from_secs(10), 100.0));
    let alpha = c.alpha();
    assert_eq!(c.observe(start, true), ResolvedBatch::default());
    assert!(!c.enroll(start, 1.0));
    assert_eq!(c.pending(), 1);
    assert_eq!(c.samples(), 0);
    assert_eq!(c.alpha(), alpha);
    assert_eq!(c.observe(start + Duration::from_secs(20), false).resolved, 0);
    assert_eq!(c.observe(start + Duration::from_secs(15), true).resolved, 0);
    assert!(!c.enroll(start + Duration::from_secs(15), 1.0));
    assert_eq!(c.observe(start + Duration::from_secs(110), false).resolved, 1);
    assert_eq!(c.coverage_empirical(), Some(1.0));
}

#[test]
fn intervention_releases_capacity_without_creating_resolution_evidence() {
    let start = Instant::now();
    let mut c = calibrator(2);
    c.record(100.0, 50.0, 100.0).unwrap();
    assert!(c.enroll(start, 100.0));
    assert!(c.enroll(start + Duration::from_secs(1), 100.0));
    let alpha = c.alpha();
    assert_eq!(c.discard_pending(), 2);
    assert_eq!(c.samples(), 1);
    assert_eq!(c.resolved_total(), 1);
    assert_eq!(c.alpha(), alpha);
    assert!(c.enroll(start + Duration::from_secs(2), 100.0));
    c.reset();
    assert_eq!(c.pending(), 0);
    assert_eq!(c.samples(), 0);
    assert_eq!(c.resolved_total(), 0);
    assert!(c.enroll(start, 100.0), "reset establishes a fresh clock history");
}

#[test]
fn zero_capacity_and_invalid_forecasts_never_claim_admission() {
    let start = Instant::now();
    let mut disabled = calibrator(0);
    assert!(!disabled.enroll(start, 60.0));
    assert_eq!(disabled.pending(), 0);
    let mut c = calibrator(1);
    for point in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, 0.0, 7201.0] {
        assert!(!c.enroll(start, point));
    }
    assert!(c.enroll(start, 60.0), "rejected inputs must not reserve the timestamp");
    assert_eq!(c.pending(), 1);
}
