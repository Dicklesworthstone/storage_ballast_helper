//! PID pressure controller: proportional-integral-derivative with hysteresis and anti-windup.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Coarse pressure state exposed to scanners/cleanup pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureLevel {
    Green,
    Yellow,
    Orange,
    Red,
    Critical,
}

/// Current filesystem pressure reading.
#[derive(Debug, Clone)]
pub struct PressureReading {
    pub free_bytes: u64,
    pub total_bytes: u64,
    pub mount: PathBuf,
}

impl PressureReading {
    #[must_use]
    pub fn free_pct(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        (self.free_bytes as f64 * 100.0) / self.total_bytes as f64
    }
}

/// Controller output used by orchestrator threads.
#[derive(Debug, Clone)]
pub struct PressureResponse {
    pub level: PressureLevel,
    pub urgency: f64,
    pub scan_interval: Duration,
    pub release_ballast_files: usize,
    pub max_delete_batch: usize,
    pub fallback_active: bool,
    pub causing_mount: PathBuf,
}

/// PID controller with hysteresis and anti-windup.
#[derive(Debug, Clone)]
pub struct PidPressureController {
    kp: f64,
    ki: f64,
    kd: f64,
    integral: f64,
    integral_cap: f64,
    hysteresis_pct: f64,
    target_free_pct: f64,
    prev_target_free_pct: f64,
    green_min_free_pct: f64,
    yellow_min_free_pct: f64,
    orange_min_free_pct: f64,
    red_min_free_pct: f64,
    base_poll_interval: Duration,
    /// Urgency boost thresholds derived from action_horizon_minutes.
    /// [critical_seconds, high_seconds, moderate_seconds]
    urgency_thresholds: [f64; 3],
    last_error: f64,
    last_update: Option<Instant>,
    level: PressureLevel,
}

impl PidPressureController {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        kp: f64,
        ki: f64,
        kd: f64,
        integral_cap: f64,
        target_free_pct: f64,
        hysteresis_pct: f64,
        green_min_free_pct: f64,
        yellow_min_free_pct: f64,
        orange_min_free_pct: f64,
        red_min_free_pct: f64,
        base_poll_interval: Duration,
    ) -> Self {
        Self {
            kp,
            ki,
            kd,
            integral: 0.0,
            integral_cap,
            hysteresis_pct,
            target_free_pct,
            prev_target_free_pct: target_free_pct,
            green_min_free_pct,
            yellow_min_free_pct,
            orange_min_free_pct,
            red_min_free_pct,
            base_poll_interval,
            urgency_thresholds: [60.0, 300.0, 900.0],
            last_error: 0.0,
            last_update: None,
            level: PressureLevel::Green,
        }
    }

    /// Derive urgency boost thresholds from the predictive action horizon.
    ///
    /// The thresholds scale linearly: critical = horizon/30, high = horizon/6, moderate = horizon/2.
    pub fn set_action_horizon_minutes(&mut self, action_horizon_minutes: f64) {
        let horizon_secs = action_horizon_minutes * 60.0;
        self.urgency_thresholds = [
            (horizon_secs / 30.0).max(30.0), // critical ~1min for 30min horizon
            (horizon_secs / 6.0).max(60.0),  // high ~5min for 30min horizon
            (horizon_secs / 2.0).max(120.0), // moderate ~15min for 30min horizon
        ];
    }

    /// Update the target free percentage (e.g., after config reload).
    /// Resets the derivative term if the target changed to avoid a spike.
    pub fn set_target_free_pct(&mut self, target: f64) {
        if (target - self.prev_target_free_pct).abs() > f64::EPSILON {
            self.last_error = 0.0; // reset derivative to avoid spike
            self.integral = 0.0; // reset integral — stale accumulation is invalid for new target
            self.last_update = None; // treat next update as fresh start
            self.prev_target_free_pct = target;
        }
        self.target_free_pct = target;
    }

    /// Update all four pressure-level thresholds (e.g., after config reload).
    /// These drive `classify_with_hysteresis` for level transitions.
    pub fn set_pressure_thresholds(&mut self, green: f64, yellow: f64, orange: f64, red: f64) {
        self.green_min_free_pct = green;
        self.yellow_min_free_pct = yellow;
        self.orange_min_free_pct = orange;
        self.red_min_free_pct = red;
    }

    /// Update controller state.
    ///
    /// `predicted_seconds_to_red` comes from EWMA and boosts urgency when time-to-red is short.
    pub fn update(
        &mut self,
        reading: PressureReading,
        predicted_seconds_to_red: Option<f64>,
        now: Instant,
    ) -> PressureResponse {
        let free_pct = reading.free_pct();
        let dt = self
            .last_update
            .map_or(1.0, |prev| now.saturating_duration_since(prev).as_secs_f64())
            .max(1e-6);

        let error = self.target_free_pct - free_pct;
        self.integral = error
            .mul_add(dt, self.integral)
            .clamp(-self.integral_cap, self.integral_cap);
        let derivative = (error - self.last_error) / dt;
        self.last_error = error;
        self.last_update = Some(now);

        let raw = self
            .kd
            .mul_add(derivative, self.kp.mul_add(error, self.ki * self.integral));
        let mut urgency = (1.0 - (-raw.max(0.0)).exp()).clamp(0.0, 1.0);

        if let Some(seconds) = predicted_seconds_to_red {
            let [critical, high, moderate] = self.urgency_thresholds;
            if seconds <= critical {
                urgency = urgency.max(1.0);
            } else if seconds <= high {
                urgency = urgency.max(0.90);
            } else if seconds <= moderate {
                urgency = urgency.max(0.70);
            }
        }

        self.level = classify_with_hysteresis(
            self.level,
            free_pct,
            self.hysteresis_pct,
            self.green_min_free_pct,
            self.yellow_min_free_pct,
            self.orange_min_free_pct,
            self.red_min_free_pct,
        );

        let (scan_interval, release_ballast_files, max_delete_batch) =
            response_policy(self.base_poll_interval, self.level, urgency);

        PressureResponse {
            level: self.level,
            urgency,
            scan_interval,
            release_ballast_files,
            max_delete_batch,
            fallback_active: false,
            causing_mount: reading.mount,
        }
    }
}

fn classify_with_hysteresis(
    current: PressureLevel,
    free_pct: f64,
    hysteresis: f64,
    green_min: f64,
    yellow_min: f64,
    orange_min: f64,
    red_min: f64,
) -> PressureLevel {
    match current {
        PressureLevel::Green => {
            if free_pct < yellow_min {
                PressureLevel::Yellow
            } else {
                PressureLevel::Green
            }
        }
        PressureLevel::Yellow => {
            if free_pct >= green_min + hysteresis {
                PressureLevel::Green
            } else if free_pct < orange_min {
                PressureLevel::Orange
            } else {
                PressureLevel::Yellow
            }
        }
        PressureLevel::Orange => {
            if free_pct >= yellow_min + hysteresis {
                PressureLevel::Yellow
            } else if free_pct < red_min {
                PressureLevel::Red
            } else {
                PressureLevel::Orange
            }
        }
        PressureLevel::Red => {
            if free_pct >= orange_min + hysteresis {
                PressureLevel::Orange
            } else if free_pct < (red_min / 2.0) {
                PressureLevel::Critical
            } else {
                PressureLevel::Red
            }
        }
        PressureLevel::Critical => {
            if free_pct >= red_min + hysteresis {
                PressureLevel::Red
            } else {
                PressureLevel::Critical
            }
        }
    }
}

fn response_policy(
    base_poll: Duration,
    level: PressureLevel,
    urgency: f64,
) -> (Duration, usize, usize) {
    #[allow(clippy::cast_possible_truncation)]
    let base_ms = base_poll.as_millis() as u64;
    match level {
        PressureLevel::Green => (Duration::from_millis(base_ms.max(1)), 0, 2),
        PressureLevel::Yellow => (
            Duration::from_millis((base_ms / 2).max(500)),
            usize::from(urgency > 0.55),
            5,
        ),
        PressureLevel::Orange => (
            Duration::from_millis((base_ms / 4).max(250)),
            if urgency > 0.75 { 3 } else { 1 },
            10,
        ),
        PressureLevel::Red => (
            Duration::from_millis((base_ms / 8).max(125)),
            if urgency > 0.85 { 5 } else { 3 },
            20,
        ),
        PressureLevel::Critical => (Duration::from_millis(100), 10, 40),
    }
}

#[cfg(test)]
mod tests {
    use super::{PidPressureController, PressureLevel, PressureReading};
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    #[test]
    fn escalates_level_when_free_space_drops() {
        let mut pid = PidPressureController::new(
            0.25,
            0.08,
            0.02,
            100.0,
            18.0,
            1.0,
            20.0,
            14.0,
            10.0,
            6.0,
            Duration::from_secs(1),
        );
        let now = Instant::now();
        let response = pid.update(
            PressureReading {
                free_bytes: 5,
                total_bytes: 100,
                mount: PathBuf::from("/"),
            },
            Some(120.0),
            now,
        );
        assert!(matches!(
            response.level,
            PressureLevel::Yellow
                | PressureLevel::Orange
                | PressureLevel::Red
                | PressureLevel::Critical
        ));
        assert!(response.urgency > 0.0);
    }

    #[test]
    fn hysteresis_prevents_immediate_bounce_to_green() {
        let mut pid = PidPressureController::new(
            0.25,
            0.08,
            0.02,
            100.0,
            18.0,
            1.0,
            20.0,
            14.0,
            10.0,
            6.0,
            Duration::from_secs(1),
        );
        let t0 = Instant::now();
        let _ = pid.update(
            PressureReading {
                free_bytes: 12,
                total_bytes: 100,
                mount: PathBuf::from("/"),
            },
            None,
            t0,
        );
        let second = pid.update(
            PressureReading {
                free_bytes: 20,
                total_bytes: 100,
                mount: PathBuf::from("/"),
            },
            None,
            t0 + Duration::from_secs(1),
        );
        assert_ne!(second.level, PressureLevel::Green);
        let third = pid.update(
            PressureReading {
                free_bytes: 23,
                total_bytes: 100,
                mount: PathBuf::from("/"),
            },
            None,
            t0 + Duration::from_secs(2),
        );
        assert_eq!(third.level, PressureLevel::Green);
    }

    #[test]
    fn predictive_signal_boosts_urgency() {
        let mut pid = PidPressureController::new(
            0.1,
            0.0,
            0.0,
            100.0,
            18.0,
            1.0,
            20.0,
            14.0,
            10.0,
            6.0,
            Duration::from_secs(1),
        );
        let now = Instant::now();
        let without_prediction = pid.update(
            PressureReading {
                free_bytes: 16,
                total_bytes: 100,
                mount: PathBuf::from("/"),
            },
            None,
            now,
        );
        let with_prediction = pid.update(
            PressureReading {
                free_bytes: 16,
                total_bytes: 100,
                mount: PathBuf::from("/"),
            },
            Some(45.0),
            now + Duration::from_secs(1),
        );
        assert!(with_prediction.urgency >= without_prediction.urgency);
        assert!(with_prediction.urgency >= 0.99);
    }

    #[test]
    fn pressure_reading_free_pct_zero_total() {
        let reading = PressureReading {
            free_bytes: 100,
            total_bytes: 0,
            mount: PathBuf::from("/"),
        };
        assert!(reading.free_pct().abs() < f64::EPSILON);
    }

    #[test]
    fn pressure_reading_free_pct_correct() {
        let reading = PressureReading {
            free_bytes: 25,
            total_bytes: 100,
            mount: PathBuf::from("/"),
        };
        assert!((reading.free_pct() - 25.0).abs() < 1e-6);
    }

    #[test]
    fn green_level_on_plenty_of_space() {
        let mut pid = PidPressureController::new(
            0.25,
            0.08,
            0.02,
            100.0,
            18.0,
            1.0,
            20.0,
            14.0,
            10.0,
            6.0,
            Duration::from_secs(1),
        );
        let now = Instant::now();
        let response = pid.update(
            PressureReading {
                free_bytes: 50,
                total_bytes: 100,
                mount: PathBuf::from("/"),
            },
            None,
            now,
        );
        assert_eq!(response.level, PressureLevel::Green);
    }

    #[test]
    fn critical_level_on_extremely_low_space() {
        let mut pid = PidPressureController::new(
            0.25,
            0.08,
            0.02,
            100.0,
            18.0,
            1.0,
            20.0,
            14.0,
            10.0,
            6.0,
            Duration::from_secs(1),
        );
        let t0 = Instant::now();
        // Drive through Yellow → Orange → Red → Critical.
        let _ = pid.update(
            PressureReading {
                free_bytes: 12,
                total_bytes: 100,
                mount: PathBuf::from("/"),
            },
            None,
            t0,
        );
        let _ = pid.update(
            PressureReading {
                free_bytes: 8,
                total_bytes: 100,
                mount: PathBuf::from("/"),
            },
            None,
            t0 + Duration::from_secs(1),
        );
        let _ = pid.update(
            PressureReading {
                free_bytes: 4,
                total_bytes: 100,
                mount: PathBuf::from("/"),
            },
            None,
            t0 + Duration::from_secs(2),
        );
        let response = pid.update(
            PressureReading {
                free_bytes: 1,
                total_bytes: 100,
                mount: PathBuf::from("/"),
            },
            None,
            t0 + Duration::from_secs(3),
        );
        assert_eq!(response.level, PressureLevel::Critical);
    }

    #[test]
    fn scan_interval_decreases_with_severity() {
        let mut pid = PidPressureController::new(
            0.25,
            0.08,
            0.02,
            100.0,
            18.0,
            1.0,
            20.0,
            14.0,
            10.0,
            6.0,
            Duration::from_secs(4),
        );
        let t0 = Instant::now();
        let green = pid.update(
            PressureReading {
                free_bytes: 50,
                total_bytes: 100,
                mount: PathBuf::from("/"),
            },
            None,
            t0,
        );
        // Reset to get yellow reading.
        let mut pid2 = PidPressureController::new(
            0.25,
            0.08,
            0.02,
            100.0,
            18.0,
            1.0,
            20.0,
            14.0,
            10.0,
            6.0,
            Duration::from_secs(4),
        );
        let _ = pid2.update(
            PressureReading {
                free_bytes: 12,
                total_bytes: 100,
                mount: PathBuf::from("/"),
            },
            None,
            t0,
        );
        let yellow = pid2.update(
            PressureReading {
                free_bytes: 12,
                total_bytes: 100,
                mount: PathBuf::from("/"),
            },
            None,
            t0 + Duration::from_secs(1),
        );
        assert!(
            yellow.scan_interval < green.scan_interval,
            "yellow interval {:?} should be less than green {:?}",
            yellow.scan_interval,
            green.scan_interval
        );
    }

    #[test]
    fn release_ballast_files_zero_at_green() {
        let mut pid = PidPressureController::new(
            0.25,
            0.08,
            0.02,
            100.0,
            18.0,
            1.0,
            20.0,
            14.0,
            10.0,
            6.0,
            Duration::from_secs(1),
        );
        let response = pid.update(
            PressureReading {
                free_bytes: 50,
                total_bytes: 100,
                mount: PathBuf::from("/"),
            },
            None,
            Instant::now(),
        );
        assert_eq!(response.release_ballast_files, 0);
    }

    #[test]
    fn predicted_300s_boosts_urgency_to_at_least_90pct() {
        let mut pid = PidPressureController::new(
            0.1,
            0.0,
            0.0,
            100.0,
            18.0,
            1.0,
            20.0,
            14.0,
            10.0,
            6.0,
            Duration::from_secs(1),
        );
        let response = pid.update(
            PressureReading {
                free_bytes: 16,
                total_bytes: 100,
                mount: PathBuf::from("/"),
            },
            Some(200.0),
            Instant::now(),
        );
        assert!(response.urgency >= 0.90);
    }

    #[test]
    fn set_pressure_thresholds_updates_all_four() {
        let mut ctrl = PidPressureController::new(
            0.25,
            0.08,
            0.02,
            100.0,
            18.0,
            1.0,
            20.0,
            14.0,
            10.0,
            6.0,
            Duration::from_secs(1),
        );

        // Initial thresholds from constructor.
        assert!((ctrl.green_min_free_pct - 20.0).abs() < f64::EPSILON);
        assert!((ctrl.yellow_min_free_pct - 14.0).abs() < f64::EPSILON);
        assert!((ctrl.orange_min_free_pct - 10.0).abs() < f64::EPSILON);
        assert!((ctrl.red_min_free_pct - 6.0).abs() < f64::EPSILON);

        // Update all four.
        ctrl.set_pressure_thresholds(40.0, 25.0, 15.0, 8.0);

        assert!((ctrl.green_min_free_pct - 40.0).abs() < f64::EPSILON);
        assert!((ctrl.yellow_min_free_pct - 25.0).abs() < f64::EPSILON);
        assert!((ctrl.orange_min_free_pct - 15.0).abs() < f64::EPSILON);
        assert!((ctrl.red_min_free_pct - 8.0).abs() < f64::EPSILON);
    }
}
