//! Finite-sample rank and evidence-admission regression tests.

use super::*;

fn fixed(coverage: f64) -> ConformalCalibrator {
    ConformalCalibrator::new(ConformalConfig {
        warmup: 1,
        gamma: 0.0,
        coverage_target: coverage,
        ..ConformalConfig::default()
    })
}

#[test]
fn an_unobserved_tail_is_not_the_largest_observed_residual() {
    let mut c = fixed(0.90);
    assert_eq!(c.record(100.0, 100.0, 100.0), Some(true));
    assert_eq!(c.samples(), 1);
    assert_eq!(c.coverage_empirical(), Some(1.0));
    // ceil(2 * .9) is the unseen second rank. The old clamp chose the
    // only observed score (zero) and returned 100 seconds of headroom.
    assert_eq!(c.quantile(), 1.0);
    assert_eq!(c.lower_bound(100.0).lo_secs, 0.0);
    // With enough completed horizons the empirical zero residual is usable.
    for _ in 0..9 {
        c.record(100.0, 100.0, 100.0).unwrap();
    }
    assert_eq!(c.quantile(), 0.0);
    assert_eq!(c.lower_bound(100.0).lo_secs, 100.0);
}

#[test]
fn exact_supported_rank_and_the_next_unseen_rank_are_distinct() {
    let mut c = fixed(0.75);
    for actual in [90.0, 80.0, 60.0] {
        c.record(100.0, actual, 0.0).unwrap();
    }
    // n=3, alpha=.25 -> ceil(4 * .75)=3, an observed rank.
    assert!((c.quantile() - 0.4).abs() < 1e-12);
    c.alpha = 0.249;
    assert_eq!(c.quantile(), 1.0);
    c.alpha = 0.251;
    assert!((c.quantile() - 0.4).abs() < 1e-12);
}

#[test]
fn nonpositive_alpha_uses_full_support_and_clean_outcomes_can_recover() {
    let mut c = ConformalCalibrator::new(ConformalConfig {
        warmup: 1,
        gamma: 0.25,
        ..ConformalConfig::default()
    });
    c.record(100.0, 20.0, 100.0).unwrap();
    assert!(c.alpha() < 0.0);
    assert_eq!(c.quantile(), 1.0);
    assert_eq!(c.lower_bound(100.0).lo_secs, 0.0);
    for _ in 0..40 {
        let issued = c.lower_bound(100.0).lo_secs;
        assert_eq!(c.record(100.0, 100.0, issued), Some(true));
    }
    assert!(c.alpha() > 0.0);
    assert_eq!(c.quantile(), 0.0);
    assert_eq!(c.lower_bound(100.0).lo_secs, 100.0);
}

#[test]
fn endpoint_alpha_and_malformed_alpha_never_index_outside_the_scores() {
    let mut c = fixed(0.9);
    for _ in 0..10 {
        c.record(100.0, 20.0, 0.0).unwrap();
    }
    for alpha in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.5, 0.0] {
        c.alpha = alpha;
        assert_eq!(c.quantile(), 1.0);
        assert_eq!(c.lower_bound(100.0).lo_secs, 0.0);
    }
    for alpha in [1.0, 2.0] {
        c.alpha = alpha;
        assert_eq!(c.quantile(), 0.0);
        assert_eq!(c.lower_bound(100.0).lo_secs, 100.0);
    }
}

#[test]
fn malformed_outcomes_do_not_change_scores_coverage_or_adaptive_alpha() {
    let mut c = ConformalCalibrator::new(ConformalConfig::default());
    c.record(100.0, 50.0, 100.0).unwrap();
    let alpha = c.alpha();
    let scores = c.scores.clone();
    for (actual, lo) in [
        (-1.0, 50.0),
        (f64::NAN, 50.0),
        (f64::INFINITY, 50.0),
        (f64::NEG_INFINITY, 50.0),
        (50.0, f64::NAN),
        (50.0, f64::INFINITY),
        (50.0, f64::NEG_INFINITY),
        (50.0, -1.0),
        (50.0, 101.0),
    ] {
        assert_eq!(c.record(100.0, actual, lo), None);
        assert_eq!(c.alpha(), alpha);
        assert_eq!(c.scores, scores);
        assert_eq!(c.resolved_total(), 1);
        assert_eq!(c.coverage_empirical(), Some(0.0));
    }
    // The support endpoints themselves are valid, including an immediate hit.
    assert_eq!(c.record(100.0, 0.0, 0.0), Some(true));
    assert_eq!(c.record(100.0, 100.0, 100.0), Some(true));
    assert_eq!(c.resolved_total(), 3);
}

#[test]
fn invalid_configuration_cannot_produce_resolved_calibration_evidence() {
    let configs = [
        ConformalConfig {
            window: 0,
            ..ConformalConfig::default()
        },
        ConformalConfig {
            coverage_target: f64::NAN,
            ..ConformalConfig::default()
        },
        ConformalConfig {
            coverage_target: -0.1,
            ..ConformalConfig::default()
        },
        ConformalConfig {
            coverage_target: 1.1,
            ..ConformalConfig::default()
        },
        ConformalConfig {
            gamma: f64::NAN,
            ..ConformalConfig::default()
        },
        ConformalConfig {
            gamma: f64::INFINITY,
            ..ConformalConfig::default()
        },
        ConformalConfig {
            gamma: -0.1,
            ..ConformalConfig::default()
        },
    ];
    for config in configs {
        let mut c = ConformalCalibrator::new(config);
        assert_eq!(c.record(100.0, 50.0, 100.0), None);
        assert_eq!(c.samples(), 0);
        assert_eq!(c.resolved_total(), 0);
        assert_eq!(c.coverage_empirical(), None);
        assert_eq!(c.quantile(), 1.0);
        let now = Instant::now();
        c.enroll(now, 100.0);
        let batch = c.observe(now + std::time::Duration::from_secs(100), false);
        assert_eq!(batch, ResolvedBatch::default());
        assert_eq!(c.resolved_total(), 0);
    }
    let c = ConformalCalibrator::new(ConformalConfig {
        warmup: 0,
        ..ConformalConfig::default()
    });
    assert_eq!(c.coverage_state(), CoverageState::Warming);
}

#[test]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn quantiles_match_an_explicit_augmented_order_statistic() {
    for n in 1..=64 {
        let mut c = fixed(0.9);
        for index in 0..n {
            let actual = f64::from(20 + (index * 17 + n * 7) % 80);
            c.record(100.0, actual, 0.0).unwrap();
        }
        // The extra support endpoint represents the unobserved test rank.
        let mut augmented: Vec<_> = c.scores.iter().copied().collect();
        augmented.push(1.0);
        augmented.sort_by(f64::total_cmp);
        for step in 1..=100 {
            c.alpha = f64::from(step) / 100.0;
            let rank = (f64::from(n + 1) * (1.0 - c.alpha)).ceil() as usize;
            let expected = if rank == 0 { 0.0 } else { augmented[rank - 1] };
            assert_eq!(c.quantile(), expected, "n={n} alpha={}", c.alpha);
            let bound = c.lower_bound(100.0);
            assert!((0.0..=100.0).contains(&bound.lo_secs));
        }
    }
}

#[test]
fn requiring_more_coverage_never_increases_the_reported_time_remaining() {
    let mut c = fixed(0.9);
    for actual in [100.0, 90.0, 80.0, 70.0, 60.0, 50.0, 40.0] {
        c.record(100.0, actual, 0.0).unwrap();
    }
    let mut previous = 100.0;
    for alpha in [1.0, 0.75, 0.5, 0.25, 0.10, 0.01, 0.0, -0.5] {
        c.alpha = alpha;
        let current = c.lower_bound(100.0).lo_secs;
        assert!(
            current <= previous,
            "alpha={alpha}: {previous} -> {current}"
        );
        previous = current;
    }
    assert_eq!(previous, 0.0);
}
