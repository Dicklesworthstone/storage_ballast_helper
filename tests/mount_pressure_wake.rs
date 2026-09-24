//! Public-controller regressions for pressure escalation during idle backoff.
//! No filesystem, process, clock sleeps, or pressure-threshold overrides.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use storage_ballast_helper::daemon::mount_controller::{
    IDLE_BACKOFF_CAP, IdleReason, MountController, MountControllerConfig, MountState, MountSurface,
    MountTickInput, WakeSignals, global_tick,
};
use storage_ballast_helper::monitor::pid::PressureLevel;

fn surface() -> MountSurface {
    MountSurface {
        configured_roots: 1,
        ..MountSurface::default()
    }
}

fn tick(level: PressureLevel, now: Instant) -> MountTickInput {
    MountTickInput {
        level,
        urgency: 0.5,
        free_pct: 10.0,
        seconds_to_red: None,
        prediction_confident: false,
        surface: surface(),
        releasable_ballast: false,
        recovery_needed: false,
        recovery_probe_ok: None,
        wake: WakeSignals::default(),
        now,
    }
}

fn idle_at(level: PressureLevel, now: Instant) -> MountController {
    let mut controller = MountController::new(
        PathBuf::from("/pressured"),
        MountControllerConfig {
            min_rescan_interval: IDLE_BACKOFF_CAP,
            ..MountControllerConfig::default()
        },
    );
    controller.observe(tick(level, now));
    controller.note_pass(0, false, now);
    assert_eq!(controller.state(), MountState::Idle);
    controller
}

#[test]
fn a_critical_mount_does_not_wait_out_an_hour_old_healthy_empty_pass() {
    let now = Instant::now();
    let mut controller = idle_at(PressureLevel::Green, now);
    assert_eq!(controller.idle_until(), Some(now + IDLE_BACKOFF_CAP));
    let at = now + Duration::from_secs(1);
    let decision = controller.observe(tick(PressureLevel::Critical, at));
    assert_eq!(decision.state, MountState::Reclaim);
    assert_eq!(
        decision.transition,
        Some((MountState::Idle, MountState::Reclaim))
    );
    assert!(decision.scan);
    assert!(!decision.release_ballast);
    assert!(!decision.probe_write);
    let record = controller.record(at);
    assert_eq!(record.level, "critical");
    assert_eq!(record.idle_reason, None);
    assert_eq!(record.rescan_in_secs, None);
    let base = Duration::from_secs(60);
    let urgent = Duration::from_secs(5);
    assert_eq!(
        global_tick([controller.cadence(base, urgent)], base),
        urgent
    );
}

#[test]
fn ascending_pressure_retries_once_per_level_and_keeps_empty_pass_backoff() {
    let now = Instant::now();
    let mut controller = idle_at(PressureLevel::Green, now);
    let levels = [
        PressureLevel::Yellow,
        PressureLevel::Orange,
        PressureLevel::Red,
        PressureLevel::Critical,
    ];
    for (index, level) in levels.into_iter().enumerate() {
        let decision = controller.observe(tick(level, now));
        assert!(decision.scan, "new severity {level:?}");
        controller.note_pass(0, false, now);
        assert_eq!(controller.empty_passes(), u32::try_from(index).unwrap() + 2);
        let deadline = controller.idle_until();
        for second in 1..100 {
            let decision = controller.observe(tick(level, now + Duration::from_secs(second)));
            assert_eq!(decision.state, MountState::Idle, "steady {level:?}");
            assert!(!decision.scan);
            assert_eq!(controller.idle_until(), deadline);
        }
    }
}

#[test]
fn pressure_jitter_does_not_reset_coverage_even_when_a_lower_pressure_pass_finishes() {
    let now = Instant::now();
    let mut controller = idle_at(PressureLevel::Red, now);
    for _ in 0..100 {
        controller.observe(MountTickInput {
            wake: WakeSignals {
                dirty_roots: true,
                ..WakeSignals::default()
            },
            ..tick(PressureLevel::Orange, now)
        });
        controller.note_pass(0, false, now);
        assert!(!controller.observe(tick(PressureLevel::Red, now)).scan);
    }
    assert!(controller.observe(tick(PressureLevel::Critical, now)).scan);
}

#[test]
fn newly_confident_near_term_prediction_wakes_a_green_idle_mount() {
    let now = Instant::now();
    let mut controller = idle_at(PressureLevel::Green, now);
    let forecast = MountTickInput {
        seconds_to_red: Some(120.0),
        prediction_confident: true,
        ..tick(PressureLevel::Green, now)
    };
    assert!(controller.observe(forecast).scan);
    controller.note_pass(0, false, now);
    for _ in 0..100 {
        assert!(!controller.observe(forecast).scan);
    }
    // A later actual severity rise is a separate opportunity to reclaim.
    assert!(controller.observe(tick(PressureLevel::Yellow, now)).scan);
}

#[test]
fn invalid_distant_or_low_confidence_predictions_do_not_trigger_reclamation() {
    let now = Instant::now();
    for seconds in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, 1801.0] {
        let mut controller = idle_at(PressureLevel::Green, now);
        let decision = controller.observe(MountTickInput {
            seconds_to_red: Some(seconds),
            prediction_confident: true,
            ..tick(PressureLevel::Green, now)
        });
        assert_eq!(
            decision.state,
            MountState::Idle,
            "invalid/distant {seconds}"
        );
        assert!(!decision.scan);
    }
    let mut controller = idle_at(PressureLevel::Green, now);
    let unconfident = MountTickInput {
        seconds_to_red: Some(0.0),
        prediction_confident: false,
        ..tick(PressureLevel::Green, now)
    };
    assert!(!controller.observe(unconfident).scan);
    for seconds in [0.0, 1800.0] {
        let mut controller = idle_at(PressureLevel::Green, now);
        let forecast = MountTickInput {
            seconds_to_red: Some(seconds),
            prediction_confident: true,
            ..tick(PressureLevel::Green, now)
        };
        assert!(controller.observe(forecast).scan);
    }
}

#[test]
fn only_a_full_healthy_window_rearms_the_same_pressure_episode() {
    let now = Instant::now();
    let mut controller = idle_at(PressureLevel::Red, now);
    for _ in 0..20 {
        for _ in 0..2 {
            assert!(!controller.observe(tick(PressureLevel::Green, now)).scan);
        }
        assert!(!controller.observe(tick(PressureLevel::Red, now)).scan);
    }
    for _ in 0..3 {
        controller.observe(tick(PressureLevel::Green, now));
    }
    assert!(controller.observe(tick(PressureLevel::Red, now)).scan);
}

#[test]
fn a_persistent_prediction_prevents_false_recovery_rearming() {
    let now = Instant::now();
    let mut controller = idle_at(PressureLevel::Green, now);
    let forecast = MountTickInput {
        seconds_to_red: Some(60.0),
        prediction_confident: true,
        ..tick(PressureLevel::Green, now)
    };
    controller.observe(forecast);
    controller.note_pass(0, false, now);
    for _ in 0..20 {
        for _ in 0..2 {
            assert!(!controller.observe(tick(PressureLevel::Green, now)).scan);
        }
        assert!(!controller.observe(forecast).scan);
    }
}

#[test]
fn expired_backoff_still_retries_a_steady_critical_mount() {
    let now = Instant::now();
    let mut controller = idle_at(PressureLevel::Critical, now);
    let before_deadline = (now + IDLE_BACKOFF_CAP)
        .checked_sub(Duration::from_secs(1))
        .unwrap();
    let deadline = now + IDLE_BACKOFF_CAP;
    assert!(
        !controller
            .observe(tick(PressureLevel::Critical, before_deadline))
            .scan
    );
    assert!(
        controller
            .observe(tick(PressureLevel::Critical, deadline))
            .scan
    );
    controller.note_pass(0, false, deadline);
    assert_eq!(controller.empty_passes(), 2);
    assert!(
        !controller
            .observe(tick(PressureLevel::Critical, deadline))
            .scan
    );
}

#[test]
fn forced_scan_and_reload_remain_explicit_wakes_after_pressure_is_covered() {
    let now = Instant::now();
    for wake in [
        WakeSignals {
            forced_scan: true,
            ..WakeSignals::default()
        },
        WakeSignals {
            reload: true,
            ..WakeSignals::default()
        },
    ] {
        let mut controller = idle_at(PressureLevel::Critical, now);
        let requested = MountTickInput {
            wake,
            ..tick(PressureLevel::Critical, now)
        };
        assert!(controller.observe(requested).scan);
        assert_eq!(controller.empty_passes(), 0);
        controller.note_pass(0, false, now);
        assert_eq!(controller.empty_passes(), 1);
        assert!(!controller.observe(tick(PressureLevel::Critical, now)).scan);
    }
}

#[test]
fn a_pressure_wake_does_not_grant_a_missing_actuator_or_bypass_recovery() {
    let now = Instant::now();
    let mut absent = idle_at(PressureLevel::Green, now);
    let decision = absent.observe(MountTickInput {
        surface: MountSurface::default(),
        ..tick(PressureLevel::Critical, now)
    });
    assert_eq!(decision.state, MountState::ObserveOnly);
    assert!(!decision.scan && !decision.release_ballast);
    assert_eq!(absent.idle_reason(), Some(IdleReason::NoSurface));

    let mut pool = idle_at(PressureLevel::Green, now);
    let decision = pool.observe(MountTickInput {
        surface: MountSurface {
            ballast_pool: true,
            ..MountSurface::default()
        },
        ..tick(PressureLevel::Critical, now)
    });
    assert_eq!(decision.state, MountState::Idle);
    assert!(!decision.scan && !decision.release_ballast);
    // When a real scan surface arrives, the unconsumed pressure wake still works.
    assert!(pool.observe(tick(PressureLevel::Critical, now)).scan);

    let mut recovering = idle_at(PressureLevel::Green, now);
    let decision = recovering.observe(MountTickInput {
        recovery_needed: true,
        ..tick(PressureLevel::Critical, now)
    });
    assert_eq!(decision.state, MountState::Recovery);
    assert!(decision.probe_write && !decision.scan && !decision.release_ballast);
    assert!(!recovering.observe(tick(PressureLevel::Critical, now)).scan);
}

#[test]
fn a_mounts_pressure_wake_does_not_wake_an_unrelated_idle_mount() {
    let now = Instant::now();
    let mut root = idle_at(PressureLevel::Green, now);
    let mut data = idle_at(PressureLevel::Green, now);
    assert!(root.observe(tick(PressureLevel::Critical, now)).scan);
    assert!(!data.observe(tick(PressureLevel::Green, now)).scan);
    assert_eq!(data.state(), MountState::Idle);
    assert_eq!(data.idle_until(), Some(now + IDLE_BACKOFF_CAP));
}
