//! PID pressure controller: proportional-integral-derivative with hysteresis and anti-windup.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Coarse pressure state exposed to scanners/cleanup pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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
    pub predicted_seconds: Option<f64>,
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

    /// Reset internal state (integral, derivative).
    /// Call this when switching monitored targets to avoid state pollution.
    pub fn reset(&mut self) {
        self.integral = 0.0;
        self.last_error = 0.0;
        self.last_update = None;
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

        // Robust dt calculation: handle backward clock jumps and tiny intervals.
        // If time went backward or dt is negligible (< 100µs), fall back to the
        // configured base poll interval to prevent the derivative term from exploding.
        let dt = self
            .last_update
            .and_then(|prev| now.checked_duration_since(prev))
            .map(|d| d.as_secs_f64())
            .filter(|&d| d > 1e-4)
            .unwrap_or_else(|| self.base_poll_interval.as_secs_f64().max(0.1));

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

        let new_level = classify_with_hysteresis(
            self.level,
            free_pct,
            self.hysteresis_pct,
            self.green_min_free_pct,
            self.yellow_min_free_pct,
            self.orange_min_free_pct,
            self.red_min_free_pct,
        );

        // Reset integral on level change to prevent windup from previous state.
        if new_level != self.level {
            self.integral = 0.0;
        }
        self.level = new_level;

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
            predicted_seconds: predicted_seconds_to_red,
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
    let raw = raw_classify(free_pct, green_min, yellow_min, orange_min, red_min);

    // Fast attack: if the new level is more severe than the current level,
    // switch immediately. This ensures we respond to sudden pressure spikes
    // (e.g. Green -> Critical) in a single tick.
    if raw > current {
        return raw;
    }

    // Slow decay: if the new level is less severe, only switch if we've
    // cleared the hysteresis threshold for the CURRENT level.
    // This prevents rapid oscillation at boundaries.
    match current {
        PressureLevel::Critical => {
            // To leave Critical, we must be above the Red threshold + hysteresis.
            if free_pct >= red_min + hysteresis {
                raw
            } else {
                PressureLevel::Critical
            }
        }
        PressureLevel::Red => {
            // To leave Red, we must be above the Orange threshold + hysteresis.
            if free_pct >= orange_min + hysteresis {
                raw
            } else {
                PressureLevel::Red
            }
        }
        PressureLevel::Orange => {
            // To leave Orange, we must be above the Yellow threshold + hysteresis.
            if free_pct >= yellow_min + hysteresis {
                raw
            } else {
                PressureLevel::Orange
            }
        }
        PressureLevel::Yellow => {
            // To leave Yellow, we must be above the Green threshold + hysteresis.
            if free_pct >= green_min + hysteresis {
                raw
            } else {
                PressureLevel::Yellow
            }
        }
        PressureLevel::Green => PressureLevel::Green,
    }
}

fn raw_classify(
    free_pct: f64,
    green_min: f64,
    yellow_min: f64,
    orange_min: f64,
    red_min: f64,
) -> PressureLevel {
    if free_pct < red_min {
        PressureLevel::Critical
    } else if free_pct < orange_min {
        PressureLevel::Red
    } else if free_pct < yellow_min {
        PressureLevel::Orange
    } else if free_pct < green_min {
        PressureLevel::Yellow
    } else {
        PressureLevel::Green
    }
}

fn response_policy(
    base_poll: Duration,
    level: PressureLevel,
    urgency: f64,
) -> (Duration, usize, usize) {
    #[allow(clippy::cast_possible_truncation)]
    let base_ms = base_poll.as_millis().min(u128::from(u64::MAX)) as u64;
    match level {
        PressureLevel::Green => {
            let batch = if urgency > 0.8 {
                10
            } else if urgency > 0.5 {
                5
            } else {
                2
            };
            (Duration::from_millis(base_ms.max(1)), 0, batch)
        }
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

    #[test]
    fn integral_resets_on_level_change() {
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

        // 1. Establish Green state with some integral accumulation (target=18%, current=50%)
        // Error = 18 - 50 = -32. Integral should become negative.
        pid.update(
            PressureReading {
                free_bytes: 50,
                total_bytes: 100,
                mount: PathBuf::from("/"),
            },
            None,
            t0,
        );
        assert!(pid.integral < 0.0);
        let integral_before = pid.integral;

        // 2. Drop to Yellow (current=12%). Level changes Green -> Yellow.
        // This should trigger the reset logic.
        let response = pid.update(
            PressureReading {
                free_bytes: 12,
                total_bytes: 100,
                mount: PathBuf::from("/"),
            },
            None,
            t0 + Duration::from_secs(1),
        );

        assert_eq!(response.level, PressureLevel::Yellow);
        // Integral accumulates the new error first, then resets to 0.0 on level change.
        // This clears the windup from the previous state. The fresh error (18 - 12 = 6)
        // will be accumulated on the NEXT update call, starting from a clean slate.
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(
                pid.integral, 0.0,
                "integral should be reset to zero on level change"
            );
            assert_ne!(
                pid.integral,
                integral_before + 6.0,
                "integral should not carry over from previous level"
            );
        }
    }
}
