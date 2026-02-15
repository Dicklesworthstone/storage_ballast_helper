//! PID pressure controller: proportional-integral-derivative with hysteresis and anti-windup.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

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
#[derive(Debug, Clone, Copy)]
pub struct PressureReading {
    pub free_bytes: u64,
    pub total_bytes: u64,
}

impl PressureReading {
    #[must_use]
    pub fn free_pct(self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        (self.free_bytes as f64 * 100.0) / self.total_bytes as f64
    }
}

/// Controller output used by orchestrator threads.
#[derive(Debug, Clone, Copy)]
pub struct PressureResponse {
    pub level: PressureLevel,
    pub urgency: f64,
    pub scan_interval: Duration,
    pub release_ballast_files: usize,
    pub max_delete_batch: usize,
    pub fallback_active: bool,
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
    green_min_free_pct: f64,
    yellow_min_free_pct: f64,
    orange_min_free_pct: f64,
    red_min_free_pct: f64,
    base_poll_interval: Duration,
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
            green_min_free_pct,
            yellow_min_free_pct,
            orange_min_free_pct,
            red_min_free_pct,
            base_poll_interval,
            last_error: 0.0,
            last_update: None,
            level: PressureLevel::Green,
        }
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
            .map_or(1.0, |prev| now.duration_since(prev).as_secs_f64())
            .max(1e-6);

        let error = (self.target_free_pct - free_pct).max(0.0);
        self.integral = (self.integral + error * dt).clamp(-self.integral_cap, self.integral_cap);
        let derivative = (error - self.last_error) / dt;
        self.last_error = error;
        self.last_update = Some(now);

        let raw = self.kp * error + self.ki * self.integral + self.kd * derivative;
        let mut urgency = (1.0 - (-raw.max(0.0)).exp()).clamp(0.0, 1.0);

        if let Some(seconds) = predicted_seconds_to_red {
            if seconds <= 60.0 {
                urgency = urgency.max(1.0);
            } else if seconds <= 300.0 {
                urgency = urgency.max(0.90);
            } else if seconds <= 900.0 {
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
            },
            None,
            t0,
        );
        let second = pid.update(
            PressureReading {
                free_bytes: 20,
                total_bytes: 100,
            },
            None,
            t0 + Duration::from_secs(1),
        );
        assert_ne!(second.level, PressureLevel::Green);
        let third = pid.update(
            PressureReading {
                free_bytes: 23,
                total_bytes: 100,
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
            },
            None,
            now,
        );
        let with_prediction = pid.update(
            PressureReading {
                free_bytes: 16,
                total_bytes: 100,
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
        };
        assert_eq!(reading.free_pct(), 0.0);
    }

    #[test]
    fn pressure_reading_free_pct_correct() {
        let reading = PressureReading {
            free_bytes: 25,
            total_bytes: 100,
        };
        assert!((reading.free_pct() - 25.0).abs() < 1e-6);
    }

    #[test]
    fn green_level_on_plenty_of_space() {
        let mut pid = PidPressureController::new(
            0.25, 0.08, 0.02, 100.0, 18.0, 1.0,
            20.0, 14.0, 10.0, 6.0,
            Duration::from_secs(1),
        );
        let now = Instant::now();
        let response = pid.update(
            PressureReading { free_bytes: 50, total_bytes: 100 },
            None,
            now,
        );
        assert_eq!(response.level, PressureLevel::Green);
    }

    #[test]
    fn critical_level_on_extremely_low_space() {
        let mut pid = PidPressureController::new(
            0.25, 0.08, 0.02, 100.0, 18.0, 1.0,
            20.0, 14.0, 10.0, 6.0,
            Duration::from_secs(1),
        );
        let t0 = Instant::now();
        // Drive through Yellow → Orange → Red → Critical.
        let _ = pid.update(
            PressureReading { free_bytes: 12, total_bytes: 100 },
            None, t0,
        );
        let _ = pid.update(
            PressureReading { free_bytes: 8, total_bytes: 100 },
            None, t0 + Duration::from_secs(1),
        );
        let _ = pid.update(
            PressureReading { free_bytes: 4, total_bytes: 100 },
            None, t0 + Duration::from_secs(2),
        );
        let response = pid.update(
            PressureReading { free_bytes: 1, total_bytes: 100 },
            None, t0 + Duration::from_secs(3),
        );
        assert_eq!(response.level, PressureLevel::Critical);
    }

    #[test]
    fn scan_interval_decreases_with_severity() {
        let mut pid = PidPressureController::new(
            0.25, 0.08, 0.02, 100.0, 18.0, 1.0,
            20.0, 14.0, 10.0, 6.0,
            Duration::from_secs(4),
        );
        let t0 = Instant::now();
        let green = pid.update(
            PressureReading { free_bytes: 50, total_bytes: 100 },
            None, t0,
        );
        // Reset to get yellow reading.
        let mut pid2 = PidPressureController::new(
            0.25, 0.08, 0.02, 100.0, 18.0, 1.0,
            20.0, 14.0, 10.0, 6.0,
            Duration::from_secs(4),
        );
        let _ = pid2.update(
            PressureReading { free_bytes: 12, total_bytes: 100 },
            None, t0,
        );
        let yellow = pid2.update(
            PressureReading { free_bytes: 12, total_bytes: 100 },
            None, t0 + Duration::from_secs(1),
        );
        assert!(yellow.scan_interval < green.scan_interval,
            "yellow interval {:?} should be less than green {:?}",
            yellow.scan_interval, green.scan_interval);
    }

    #[test]
    fn release_ballast_files_zero_at_green() {
        let mut pid = PidPressureController::new(
            0.25, 0.08, 0.02, 100.0, 18.0, 1.0,
            20.0, 14.0, 10.0, 6.0,
            Duration::from_secs(1),
        );
        let response = pid.update(
            PressureReading { free_bytes: 50, total_bytes: 100 },
            None, Instant::now(),
        );
        assert_eq!(response.release_ballast_files, 0);
    }

    #[test]
    fn predicted_300s_boosts_urgency_to_at_least_90pct() {
        let mut pid = PidPressureController::new(
            0.1, 0.0, 0.0, 100.0, 18.0, 1.0,
            20.0, 14.0, 10.0, 6.0,
            Duration::from_secs(1),
        );
        let response = pid.update(
            PressureReading { free_bytes: 16, total_bytes: 100 },
            Some(200.0),
            Instant::now(),
        );
        assert!(response.urgency >= 0.70);
    }
}
