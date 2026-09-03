//! PID pressure controller: proportional-integral-derivative with hysteresis,
//! forecast feedforward, capacity gain scheduling and anti-windup that
//! follows actionability.
//!
//! The controller is per mount. Its output is an urgency in `[0, 1]`:
//!
//! - the proportional gain is scheduled by volume size (`Kp * sqrt(total /
//!   reference)`, clamped), so a one-point error on a 55 TiB pool and on a
//!   1 GiB root do not mean the same thing;
//! - the forecast enters as a smooth feedforward term `Kf * clamp(1 -
//!   t_red / H_action, 0, 1)` instead of stepped boosts;
//! - the integral is frozen while the mount has no actuator (observe-only,
//!   idle, recovering), so the controller cannot wind up into a Red urgency
//!   it can do nothing with.
//!
//! [`FORMULAS`] is the README's copy of the arithmetic; a test keeps the
//! two identical.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::core::config::PressureConfig;

/// The controller arithmetic, verbatim in the README ("PID Pressure
/// Controller" section).
pub const FORMULAS: &str = "error = target_free_pct - current_free_pct
kp_m = Kp * clamp(sqrt(total_bytes / reference_total_bytes), kp_scale_min, kp_scale_max)
integral = clamp(integral + error * dt, -integral_cap, integral_cap)   # frozen while the mount cannot act
derivative = 0.3 * (error - last_error) / dt + 0.7 * last_derivative
feedforward = Kf * clamp(1 - seconds_to_red / action_horizon_secs, 0, 1)   # 0 without a forecast
raw = kp_m * error + Ki * integral + Kd * derivative + feedforward
urgency = 1 - exp(-max(0, raw))";

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
    pub free_pct: f64,
    pub predicted_seconds: Option<f64>,
}

/// Gains, setpoint and level thresholds of one controller
/// (`[pressure]` and `[pressure.controller]` in the config).
#[derive(Debug, Clone, PartialEq)]
pub struct PidConfig {
    pub kp: f64,
    pub ki: f64,
    pub kd: f64,
    /// Forecast feedforward gain (`Kf`).
    pub kf: f64,
    pub integral_cap: f64,
    pub target_free_pct: f64,
    pub hysteresis_pct: f64,
    /// `[green, yellow, orange, red]` minimum free percentages.
    pub thresholds: [f64; 4],
    /// Volume size at which `Kp` applies unscaled.
    pub reference_total_bytes: u64,
    /// Bounds on the capacity multiplier of `Kp`.
    pub kp_scale_min: f64,
    pub kp_scale_max: f64,
}

impl Default for PidConfig {
    fn default() -> Self {
        Self {
            kp: 0.25,
            ki: 0.08,
            kd: 0.02,
            kf: 0.8,
            integral_cap: 100.0,
            target_free_pct: 18.0,
            hysteresis_pct: 1.0,
            thresholds: [20.0, 14.0, 10.0, 6.0],
            reference_total_bytes: 1 << 40,
            kp_scale_min: 0.5,
            kp_scale_max: 2.0,
        }
    }
}

impl PidConfig {
    /// Defaults with the given `[green, yellow, orange, red]` thresholds.
    #[must_use]
    pub fn with_thresholds(green: f64, yellow: f64, orange: f64, red: f64) -> Self {
        Self {
            thresholds: [green, yellow, orange, red],
            ..Self::default()
        }
    }
}

impl From<&PressureConfig> for PidConfig {
    fn from(pressure: &PressureConfig) -> Self {
        let controller = &pressure.controller;
        Self {
            kp: controller.kp,
            ki: controller.ki,
            kd: controller.kd,
            kf: controller.kf,
            integral_cap: controller.integral_cap,
            target_free_pct: pressure.green_min_free_pct,
            hysteresis_pct: controller.hysteresis_pct,
            thresholds: [
                pressure.green_min_free_pct,
                pressure.yellow_min_free_pct,
                pressure.orange_min_free_pct,
                pressure.red_min_free_pct,
            ],
            reference_total_bytes: controller.reference_total_bytes,
            kp_scale_min: controller.kp_scale_min,
            kp_scale_max: controller.kp_scale_max,
        }
    }
}

/// PID controller with hysteresis, feedforward and actionability-aware
/// anti-windup.
#[derive(Debug, Clone)]
pub struct PidPressureController {
    kp: f64,
    ki: f64,
    kd: f64,
    kf: f64,
    integral: f64,
    integral_cap: f64,
    /// Set from the mount's state each tick: no actuator, no integration.
    integral_frozen: bool,
    hysteresis_pct: f64,
    target_free_pct: f64,
    prev_target_free_pct: f64,
    green_min_free_pct: f64,
    yellow_min_free_pct: f64,
    orange_min_free_pct: f64,
    red_min_free_pct: f64,
    reference_total_bytes: u64,
    kp_scale_min: f64,
    kp_scale_max: f64,
    base_poll_interval: Duration,
    /// `H_action` of the feedforward term; `None` disables it.
    action_horizon_secs: Option<f64>,
    last_error: f64,
    last_derivative: f64,
    last_feedforward: f64,
    last_update: Option<Instant>,
    level: PressureLevel,
}

impl PidPressureController {
    #[must_use]
    pub fn new(config: &PidConfig, base_poll_interval: Duration) -> Self {
        let [green, yellow, orange, red] = config.thresholds;
        Self {
            kp: config.kp,
            ki: config.ki,
            kd: config.kd,
            kf: config.kf,
            integral: 0.0,
            integral_cap: config.integral_cap,
            integral_frozen: false,
            hysteresis_pct: config.hysteresis_pct,
            target_free_pct: config.target_free_pct,
            prev_target_free_pct: config.target_free_pct,
            green_min_free_pct: green,
            yellow_min_free_pct: yellow,
            orange_min_free_pct: orange,
            red_min_free_pct: red,
            reference_total_bytes: config.reference_total_bytes,
            kp_scale_min: config.kp_scale_min,
            kp_scale_max: config.kp_scale_max,
            base_poll_interval,
            action_horizon_secs: None,
            last_error: 0.0,
            last_derivative: 0.0,
            last_feedforward: 0.0,
            last_update: None,
            level: PressureLevel::Green,
        }
    }

    /// Apply new gains, thresholds and setpoint (config reload). A changed
    /// setpoint resets the integral and derivative, as `set_target_free_pct`
    /// does; gains change in place.
    pub fn apply_config(&mut self, config: &PidConfig) {
        self.kp = config.kp;
        self.ki = config.ki;
        self.kd = config.kd;
        self.kf = config.kf;
        self.integral_cap = config.integral_cap;
        self.integral = self.integral.clamp(-self.integral_cap, self.integral_cap);
        self.hysteresis_pct = config.hysteresis_pct;
        self.reference_total_bytes = config.reference_total_bytes;
        self.kp_scale_min = config.kp_scale_min;
        self.kp_scale_max = config.kp_scale_max;
        let [green, yellow, orange, red] = config.thresholds;
        self.set_pressure_thresholds(green, yellow, orange, red);
        self.set_target_free_pct(config.target_free_pct);
    }

    /// Enable the forecast feedforward with `H_action` = the predictive
    /// action horizon.
    pub fn set_action_horizon_minutes(&mut self, action_horizon_minutes: f64) {
        let horizon_secs = action_horizon_minutes * 60.0;
        self.action_horizon_secs =
            (horizon_secs.is_finite() && horizon_secs > 0.0).then_some(horizon_secs);
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

    /// Disable the forecast feedforward.
    ///
    /// Call when `prediction.enabled` is toggled to `false` during config
    /// reload, so the controller stops acting on stale forecasts.
    pub fn disable_urgency_boost(&mut self) {
        self.action_horizon_secs = None;
    }

    /// Update the base poll interval (e.g., after config reload).
    ///
    /// This affects the dt fallback (when timestamps are unavailable) and the
    /// response policy scan intervals.
    pub fn set_base_poll_interval(&mut self, interval: Duration) {
        self.base_poll_interval = interval;
    }

    /// Update all four pressure-level thresholds (e.g., after config reload).
    /// These drive `classify_with_hysteresis` for level transitions.
    pub fn set_pressure_thresholds(&mut self, green: f64, yellow: f64, orange: f64, red: f64) {
        self.green_min_free_pct = green;
        self.yellow_min_free_pct = yellow;
        self.orange_min_free_pct = orange;
        self.red_min_free_pct = red;
    }

    /// Anti-windup on actionability: while `frozen`, `update` keeps the
    /// integral where it is (the mount has no actuator: observe-only, idle
    /// after an empty pass, or recovering from EROFS/ENOSPC).
    pub fn freeze_integral(&mut self, frozen: bool) {
        self.integral_frozen = frozen;
    }

    #[must_use]
    pub fn integral_frozen(&self) -> bool {
        self.integral_frozen
    }

    /// The accumulated integral term (diagnostics and tests).
    #[must_use]
    pub fn integral(&self) -> f64 {
        self.integral
    }

    /// The feedforward term of the last update (diagnostics and tests).
    #[must_use]
    pub fn last_feedforward(&self) -> f64 {
        self.last_feedforward
    }

    /// The proportional gain in force for a volume of `total_bytes`:
    /// `Kp * clamp(sqrt(total / reference), kp_scale_min, kp_scale_max)`.
    #[must_use]
    pub fn scheduled_kp(&self, total_bytes: u64) -> f64 {
        self.kp * self.capacity_gain(total_bytes)
    }

    fn capacity_gain(&self, total_bytes: u64) -> f64 {
        let reference = self.reference_total_bytes.max(1) as f64;
        let ratio = total_bytes as f64 / reference;
        let (lo, hi) = if self.kp_scale_min <= self.kp_scale_max {
            (self.kp_scale_min, self.kp_scale_max)
        } else {
            (self.kp_scale_max, self.kp_scale_min)
        };
        if ratio.is_finite() && ratio > 0.0 {
            ratio.sqrt().clamp(lo, hi)
        } else {
            lo
        }
    }

    /// `Kf * clamp(1 - t_red / H_action, 0, 1)`; zero without a forecast or
    /// with the feedforward disabled.
    fn feedforward(&self, predicted_seconds_to_red: Option<f64>) -> f64 {
        match (predicted_seconds_to_red, self.action_horizon_secs) {
            (Some(seconds), Some(horizon)) if seconds.is_finite() => {
                self.kf * (1.0 - seconds.max(0.0) / horizon).clamp(0.0, 1.0)
            }
            _ => 0.0,
        }
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
    /// `predicted_seconds_to_red` comes from EWMA and enters as the
    /// feedforward term when the forecast is inside the action horizon.
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
        if !self.integral_frozen {
            self.integral = error
                .mul_add(dt, self.integral)
                .clamp(-self.integral_cap, self.integral_cap);
        }
        let raw_derivative = (error - self.last_error) / dt;
        // Low-pass filter on derivative to suppress measurement noise spikes.
        // Alpha=0.3: responsive enough for real pressure changes, smooths jitter.
        let derivative = 0.3f64.mul_add(raw_derivative, 0.7 * self.last_derivative);
        self.last_derivative = derivative;
        self.last_error = error;
        self.last_update = Some(now);

        let kp = self.scheduled_kp(reading.total_bytes);
        let feedforward = self.feedforward(predicted_seconds_to_red);
        self.last_feedforward = feedforward;
        let raw = self
            .kd
            .mul_add(derivative, kp.mul_add(error, self.ki * self.integral))
            + feedforward;
        let urgency = (1.0 - (-raw.max(0.0)).exp()).clamp(0.0, 1.0);

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
            free_pct,
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
    let raw = classify_level(free_pct, green_min, yellow_min, orange_min, red_min);

    // Fast attack: if the new level is more severe than the current level,
    // switch immediately. This ensures we respond to sudden pressure spikes
    // (e.g. Green -> Critical) in a single tick.
    if raw > current {
        return raw;
    }

    // Slow decay: if the new level is less severe, only step DOWN one level
    // per tick if we've cleared the hysteresis threshold for the CURRENT level.
    // This prevents rapid oscillation at boundaries and ensures gradual recovery.
    match current {
        PressureLevel::Critical => {
            // To leave Critical, we must be above the Red threshold + hysteresis.
            if free_pct >= red_min + hysteresis {
                PressureLevel::Red
            } else {
                PressureLevel::Critical
            }
        }
        PressureLevel::Red => {
            // To leave Red, we must be above the Orange threshold + hysteresis.
            if free_pct >= orange_min + hysteresis {
                PressureLevel::Orange
            } else {
                PressureLevel::Red
            }
        }
        PressureLevel::Orange => {
            // To leave Orange, we must be above the Yellow threshold + hysteresis.
            if free_pct >= yellow_min + hysteresis {
                PressureLevel::Yellow
            } else {
                PressureLevel::Orange
            }
        }
        PressureLevel::Yellow => {
            // To leave Yellow, we must be above the Green threshold + hysteresis.
            if free_pct >= green_min + hysteresis {
                PressureLevel::Green
            } else {
                PressureLevel::Yellow
            }
        }
        PressureLevel::Green => PressureLevel::Green,
    }
}

/// The level `free_pct` falls in against the four thresholds, with no
/// hysteresis: what a fresh controller would say.
#[must_use]
pub fn classify_level(
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
            // Dynamic batch scaling: 20 base + up to 30 more based on urgency > 0.5
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                20 + ((urgency - 0.5).max(0.0) * 60.0) as usize
            },
        ),
        PressureLevel::Critical => (
            Duration::from_millis(100),
            10,
            // Aggressive scaling: 40 base + up to 60 more
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                40 + ((urgency - 0.5).max(0.0) * 120.0) as usize
            },
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{PidConfig, PidPressureController, PressureLevel, PressureReading};
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    #[test]
    fn escalates_level_when_free_space_drops() {
        let mut pid = PidPressureController::new(
            &PidConfig {
                kp: 0.25,
                ki: 0.08,
                kd: 0.02,
                integral_cap: 100.0,
                target_free_pct: 18.0,
                hysteresis_pct: 1.0,
                thresholds: [20.0, 14.0, 10.0, 6.0],
                ..PidConfig::default()
            },
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
            &PidConfig {
                kp: 0.25,
                ki: 0.08,
                kd: 0.02,
                integral_cap: 100.0,
                target_free_pct: 18.0,
                hysteresis_pct: 1.0,
                thresholds: [20.0, 14.0, 10.0, 6.0],
                ..PidConfig::default()
            },
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
    fn forecast_feedforward_is_smooth_and_monotone_in_time_to_red() {
        let mut pid = PidPressureController::new(
            &PidConfig {
                kp: 0.1,
                ki: 0.0,
                kd: 0.0,
                ..PidConfig::default()
            },
            Duration::from_secs(1),
        );
        pid.set_action_horizon_minutes(30.0);
        let reading = || PressureReading {
            free_bytes: 16,
            total_bytes: 100,
            mount: PathBuf::from("/"),
        };
        let now = Instant::now();
        let without = pid.update(reading(), None, now);
        assert_eq!(pid.last_feedforward(), 0.0);
        let mut previous = without.urgency;
        // Closer forecasts raise urgency, smoothly, never past the gain.
        for (i, seconds) in [1800.0, 1200.0, 600.0, 300.0, 60.0, 0.0].iter().enumerate() {
            let response = pid.update(
                reading(),
                Some(*seconds),
                now + Duration::from_secs(i as u64 + 1),
            );
            assert!(
                response.urgency >= previous - 1e-9,
                "t_red={seconds}: {} < {previous}",
                response.urgency
            );
            let expected = 0.8 * (1.0 - seconds / 1800.0);
            assert!(
                (pid.last_feedforward() - expected).abs() < 1e-9,
                "t_red={seconds}: feedforward {}",
                pid.last_feedforward()
            );
            previous = response.urgency;
        }
        // Beyond the horizon the forecast adds nothing.
        let far = pid.update(reading(), Some(7200.0), now + Duration::from_secs(20));
        assert_eq!(pid.last_feedforward(), 0.0);
        assert!(far.urgency <= previous);
        // Disabled prediction: no feedforward even for an imminent forecast.
        pid.disable_urgency_boost();
        let _ = pid.update(reading(), Some(1.0), now + Duration::from_secs(21));
        assert_eq!(pid.last_feedforward(), 0.0);
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
            &PidConfig {
                kp: 0.25,
                ki: 0.08,
                kd: 0.02,
                integral_cap: 100.0,
                target_free_pct: 18.0,
                hysteresis_pct: 1.0,
                thresholds: [20.0, 14.0, 10.0, 6.0],
                ..PidConfig::default()
            },
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
            &PidConfig {
                kp: 0.25,
                ki: 0.08,
                kd: 0.02,
                integral_cap: 100.0,
                target_free_pct: 18.0,
                hysteresis_pct: 1.0,
                thresholds: [20.0, 14.0, 10.0, 6.0],
                ..PidConfig::default()
            },
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
            &PidConfig {
                kp: 0.25,
                ki: 0.08,
                kd: 0.02,
                integral_cap: 100.0,
                target_free_pct: 18.0,
                hysteresis_pct: 1.0,
                thresholds: [20.0, 14.0, 10.0, 6.0],
                ..PidConfig::default()
            },
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
            &PidConfig {
                kp: 0.25,
                ki: 0.08,
                kd: 0.02,
                integral_cap: 100.0,
                target_free_pct: 18.0,
                hysteresis_pct: 1.0,
                thresholds: [20.0, 14.0, 10.0, 6.0],
                ..PidConfig::default()
            },
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
            &PidConfig {
                kp: 0.25,
                ki: 0.08,
                kd: 0.02,
                integral_cap: 100.0,
                target_free_pct: 18.0,
                hysteresis_pct: 1.0,
                thresholds: [20.0, 14.0, 10.0, 6.0],
                ..PidConfig::default()
            },
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
    fn predicted_200s_raises_urgency_through_the_feedforward() {
        let config = PidConfig {
            kp: 0.1,
            ki: 0.0,
            kd: 0.0,
            ..PidConfig::default()
        };
        let reading = || PressureReading {
            free_bytes: 16,
            total_bytes: 100,
            mount: PathBuf::from("/"),
        };
        let mut without = PidPressureController::new(&config, Duration::from_secs(1));
        without.set_action_horizon_minutes(30.0);
        let baseline = without.update(reading(), None, Instant::now());
        let mut with = PidPressureController::new(&config, Duration::from_secs(1));
        with.set_action_horizon_minutes(30.0);
        let response = with.update(reading(), Some(200.0), Instant::now());
        // Kf * (1 - 200 / 1800) on top of Kp * 2 points.
        assert!(
            0.8f64
                .mul_add(-(1.0 - 200.0 / 1800.0), with.last_feedforward())
                .abs()
                < 1e-9
        );
        assert!(
            response.urgency > baseline.urgency,
            "{response:?} vs {baseline:?}"
        );
        // The test volume is 100 bytes, so the capacity gain sits at its floor
        // (0.5 * Kp); `scheduled_kp` is the gain actually applied.
        let expected =
            1.0 - (-(with.scheduled_kp(100).mul_add(2.0, with.last_feedforward()))).exp();
        assert!(
            (response.urgency - expected).abs() < 1e-6,
            "{}",
            response.urgency
        );
    }

    #[test]
    fn set_pressure_thresholds_updates_all_four() {
        let mut ctrl = PidPressureController::new(
            &PidConfig {
                kp: 0.25,
                ki: 0.08,
                kd: 0.02,
                integral_cap: 100.0,
                target_free_pct: 18.0,
                hysteresis_pct: 1.0,
                thresholds: [20.0, 14.0, 10.0, 6.0],
                ..PidConfig::default()
            },
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
    fn response_policy_scales_batch_size_with_urgency() {
        use super::response_policy;
        let base = Duration::from_secs(1);

        // Red level
        let (_, _, low_red) = response_policy(base, PressureLevel::Red, 0.5);
        let (_, _, high_red) = response_policy(base, PressureLevel::Red, 1.0);
        assert!(
            high_red > low_red,
            "Red batch size should scale with urgency (low={low_red}, high={high_red})"
        );
        assert_eq!(low_red, 20);
        // 20 + (0.5 * 60) = 50
        assert_eq!(high_red, 50);

        // Critical level
        let (_, _, low_crit) = response_policy(base, PressureLevel::Critical, 0.5);
        let (_, _, high_crit) = response_policy(base, PressureLevel::Critical, 1.0);
        assert!(
            high_crit > low_crit,
            "Critical batch size should scale with urgency (low={low_crit}, high={high_crit})"
        );
        assert_eq!(low_crit, 40);
        // 40 + (0.5 * 120) = 100
        assert_eq!(high_crit, 100);
    }

    fn sandbox_trace() -> Vec<(u64, PressureReading)> {
        let text = include_str!("../../tests/fixtures/sandbox-trace-2026-09-02.jsonl");
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let value: serde_json::Value = serde_json::from_str(line).unwrap();
                (
                    value["t_secs"].as_u64().unwrap(),
                    PressureReading {
                        free_bytes: value["free_bytes"].as_u64().unwrap(),
                        total_bytes: value["total_bytes"].as_u64().unwrap(),
                        mount: PathBuf::from(value["mount"].as_str().unwrap()),
                    },
                )
            })
            .collect()
    }

    /// The recorded trace (a fill from Green to below Red, a ballast
    /// release, the reclaim back to Green): the level tracks the raw
    /// classification within one step, urgency moves smoothly, and the
    /// controller settles once the volume is back above the setpoint.
    #[test]
    fn step_response_on_the_sandbox_trace_converges_without_overshoot() {
        let trace = sandbox_trace();
        assert!(trace.len() > 100, "trace has {} points", trace.len());
        let mut pid = PidPressureController::new(
            &PidConfig::with_thresholds(20.0, 14.0, 10.0, 6.0),
            Duration::from_secs(1),
        );
        pid.set_action_horizon_minutes(30.0);
        let t0 = Instant::now();
        let mut previous_urgency: Option<f64> = None;
        let mut previous_free = trace[0].1.free_pct();
        // A step in free space is answered over two ticks: the integral
        // accumulated before the step is released on the level change.
        let mut previous_free_jump = 0.0f64;
        let mut last = None;
        for (t_secs, reading) in trace {
            let free_pct = reading.free_pct();
            let raw = super::classify_level(free_pct, 20.0, 14.0, 10.0, 6.0);
            let response = pid.update(reading, None, t0 + Duration::from_secs(t_secs));
            assert!(
                response.level <= raw || (response.level as u8) <= raw as u8 + 1,
                "t={t_secs}: level {:?} overshoots raw {raw:?}",
                response.level
            );
            let jump = previous_urgency.map_or(0.0, |p| (response.urgency - p).abs());
            let free_jump = (free_pct - previous_free).abs();
            assert!(
                jump <= 0.5 || free_jump.max(previous_free_jump) >= 3.0,
                "t={t_secs}: urgency jumped {jump:.3} on a {free_jump:.2}-point move"
            );
            previous_urgency = Some(response.urgency);
            previous_free = free_pct;
            previous_free_jump = free_jump;
            last = Some(response);
        }
        let last = last.unwrap();
        assert_eq!(last.level, PressureLevel::Green, "{last:?}");
        assert!(last.urgency < 0.05, "settled urgency {}", last.urgency);
        assert!(
            pid.integral().abs() < 1e-6 || pid.integral() < 0.0,
            "no positive integral left: {}",
            pid.integral()
        );
    }

    #[test]
    fn capacity_gain_scales_kp_by_volume_size_within_bounds() {
        let pid = PidPressureController::new(&PidConfig::default(), Duration::from_secs(1));
        let tib = 1u64 << 40;
        assert!(
            (pid.scheduled_kp(tib) - 0.25).abs() < 1e-12,
            "reference volume"
        );
        assert!(
            (pid.scheduled_kp(4 * tib) - 0.5).abs() < 1e-12,
            "4 TiB: sqrt(4) = 2"
        );
        assert!(
            (pid.scheduled_kp(64 * tib) - 0.5).abs() < 1e-12,
            "clamped at 2 Kp"
        );
        assert!(
            (pid.scheduled_kp(tib / 4) - 0.125).abs() < 1e-12,
            "256 GiB: 0.5 Kp"
        );
        assert!(
            (pid.scheduled_kp(1 << 30) - 0.125).abs() < 1e-12,
            "1 GiB: clamped at 0.5 Kp"
        );
        assert!(
            (pid.scheduled_kp(0) - 0.125).abs() < 1e-12,
            "unknown size: the floor"
        );
    }

    #[test]
    fn frozen_integral_does_not_grow_and_thaws_in_place() {
        let mut pid = PidPressureController::new(
            &PidConfig {
                kp: 0.0,
                ki: 0.08,
                kd: 0.0,
                ..PidConfig::default()
            },
            Duration::from_secs(1),
        );
        let t0 = Instant::now();
        let reading = || PressureReading {
            free_bytes: 12,
            total_bytes: 100,
            mount: PathBuf::from("/"),
        };
        pid.freeze_integral(true);
        for i in 0..600 {
            let response = pid.update(reading(), None, t0 + Duration::from_secs(i));
            assert_eq!(pid.integral(), 0.0, "tick {i}");
            assert_eq!(
                response.urgency, 0.0,
                "tick {i}: only the integral could act"
            );
        }
        pid.freeze_integral(false);
        let response = pid.update(reading(), None, t0 + Duration::from_secs(600));
        assert!(pid.integral() > 0.0);
        assert!(response.urgency > 0.0);
    }

    #[test]
    fn apply_config_changes_gains_in_place_and_resets_on_a_new_setpoint() {
        let mut pid = PidPressureController::new(&PidConfig::default(), Duration::from_secs(1));
        let t0 = Instant::now();
        let reading = || PressureReading {
            free_bytes: 12,
            total_bytes: 1 << 40,
            mount: PathBuf::from("/"),
        };
        let _ = pid.update(reading(), None, t0);
        let _ = pid.update(reading(), None, t0 + Duration::from_secs(1));
        let integral = pid.integral();
        assert!(integral > 0.0);
        pid.apply_config(&PidConfig {
            kp: 1.0,
            integral_cap: 0.5,
            ..PidConfig::default()
        });
        assert!((pid.scheduled_kp(1 << 40) - 1.0).abs() < 1e-12);
        assert!(pid.integral() <= 0.5, "re-clamped to the new cap");
        pid.apply_config(&PidConfig {
            target_free_pct: 25.0,
            ..PidConfig::default()
        });
        assert_eq!(pid.integral(), 0.0, "a new setpoint starts clean");
    }

    /// The README's formula block is this module's `FORMULAS`, verbatim.
    #[test]
    fn readme_formulas_match_the_code() {
        let readme = include_str!("../../README.md");
        let block = format!("```\n{}\n```", super::FORMULAS);
        assert!(
            readme.contains(&block),
            "README's PID formula block differs from monitor::pid::FORMULAS"
        );
    }

    mod properties {
        use super::super::{PidConfig, PidPressureController, PressureReading};
        use proptest::prelude::*;
        use std::path::PathBuf;
        use std::time::{Duration, Instant};

        // `free_pct` is generated in 0..40, so the cast neither truncates
        // anything that matters nor sees a negative value.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        fn reading(free_pct: f64) -> PressureReading {
            PressureReading {
                free_bytes: (free_pct * 10_000.0) as u64,
                total_bytes: 1_000_000,
                mount: PathBuf::from("/"),
            }
        }

        proptest! {
            /// With the actuator frozen the integral never grows, whatever
            /// the error sequence.
            #[test]
            fn integral_stays_put_while_frozen(
                frees in proptest::collection::vec(0.0f64..40.0, 1..200),
                dt_ms in 100u64..5_000,
            ) {
                let mut pid = PidPressureController::new(&PidConfig::default(), Duration::from_secs(1));
                let t0 = Instant::now();
                pid.freeze_integral(true);
                for (i, free) in frees.iter().enumerate() {
                    let _ = pid.update(reading(*free), None, t0 + Duration::from_millis(dt_ms * i as u64));
                    prop_assert!(pid.integral().abs() < f64::EPSILON, "{}", pid.integral());
                }
            }

            /// Urgency is monotone non-increasing in the forecast's
            /// seconds-to-red, all else equal.
            #[test]
            fn urgency_is_monotone_in_time_to_red(
                free in 0.0f64..40.0,
                a in 0.0f64..7200.0,
                b in 0.0f64..7200.0,
            ) {
                let mut pid = PidPressureController::new(&PidConfig::default(), Duration::from_secs(1));
                pid.set_action_horizon_minutes(30.0);
                let t0 = Instant::now();
                let _ = pid.update(reading(free), None, t0);
                let (near, far) = if a <= b { (a, b) } else { (b, a) };
                let mut near_pid = pid.clone();
                let mut far_pid = pid.clone();
                let near_urgency = near_pid.update(reading(free), Some(near), t0 + Duration::from_secs(1)).urgency;
                let far_urgency = far_pid.update(reading(free), Some(far), t0 + Duration::from_secs(1)).urgency;
                prop_assert!(near_urgency + 1e-12 >= far_urgency, "near {near}: {near_urgency} < far {far}: {far_urgency}");
            }

            /// The scheduled gain stays inside its bounds for any volume.
            #[test]
            fn scheduled_kp_stays_within_bounds(total in 0u64..(1u64 << 60)) {
                let pid = PidPressureController::new(&PidConfig::default(), Duration::from_secs(1));
                let kp = pid.scheduled_kp(total);
                prop_assert!((0.125 - 1e-12..=0.5 + 1e-12).contains(&kp), "{kp}");
            }
        }
    }
}
