//! Bounded pressure-driven retries after an empty scan.
//!
//! An empty pass is evidence about the pressure at which it ran, not a
//! promise that a later, more aggressive pass will also be empty. Remember
//! the highest pressure already attempted during an incident so escalating
//! pressure gets a retry without turning threshold jitter into a scan loop.

use crate::monitor::pid::PressureLevel;

#[derive(Debug, Clone)]
pub(super) struct IdleWake {
    observed_level: PressureLevel,
    observed_prediction: bool,
    attempted_level: PressureLevel,
    attempted_prediction: bool,
    clear_ticks: u32,
}

impl Default for IdleWake {
    fn default() -> Self {
        Self {
            observed_level: PressureLevel::Green,
            observed_prediction: false,
            attempted_level: PressureLevel::Green,
            attempted_prediction: false,
            clear_ticks: 0,
        }
    }
}

impl IdleWake {
    /// Observe the current incident, returning whether it merits an early
    /// retry. Only `cover` consumes the retry: observe-only and recovering
    /// mounts must not spend it without getting an opportunity to scan.
    pub(super) fn observe(
        &mut self,
        level: PressureLevel,
        predicted: bool,
        recovery_clean_windows: u32,
    ) -> bool {
        self.observed_level = level;
        self.observed_prediction = predicted;
        if level == PressureLevel::Green && !predicted {
            self.clear_ticks = self.clear_ticks.saturating_add(1);
            if self.clear_ticks >= recovery_clean_windows.max(1) {
                self.reset();
            }
        } else {
            self.clear_ticks = 0;
        }
        level > self.attempted_level || (predicted && !self.attempted_prediction)
    }

    /// An empty pass, or an early retry that is now being dispatched, covers
    /// the observed severity. Do not lower the high-water mark on a dip.
    pub(super) fn cover(&mut self) {
        self.attempted_level = self.attempted_level.max(self.observed_level);
        self.attempted_prediction |= self.observed_prediction;
    }

    /// Productive work, explicit operator intervention, or sustained Green
    /// readings start a fresh incident. Keep the latest observation so an
    /// immediately following `cover` still accounts for that retry.
    pub(super) fn reset(&mut self) {
        self.attempted_level = PressureLevel::Green;
        self.attempted_prediction = false;
        self.clear_ticks = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_new_pressure_level_gets_one_retry_in_an_empty_incident() {
        let mut wake = IdleWake::default();
        for level in [
            PressureLevel::Yellow,
            PressureLevel::Orange,
            PressureLevel::Red,
            PressureLevel::Critical,
        ] {
            assert!(wake.observe(level, false, 3), "new severity {level:?}");
            wake.cover();
            for _ in 0..100 {
                assert!(!wake.observe(level, false, 3), "steady {level:?}");
            }
        }
    }

    #[test]
    fn lower_pressure_empty_passes_do_not_erase_the_attempted_high_water_mark() {
        let mut wake = IdleWake::default();
        assert!(wake.observe(PressureLevel::Red, false, 3));
        wake.cover();
        for _ in 0..100 {
            assert!(!wake.observe(PressureLevel::Orange, false, 3));
            wake.cover();
            assert!(!wake.observe(PressureLevel::Red, false, 3));
        }
        assert!(wake.observe(PressureLevel::Critical, false, 3));
    }

    #[test]
    fn observation_does_not_consume_a_retry_that_could_not_run() {
        let mut wake = IdleWake::default();
        for _ in 0..10 {
            assert!(wake.observe(PressureLevel::Critical, false, 3));
        }
        wake.cover();
        assert!(!wake.observe(PressureLevel::Critical, false, 3));
    }

    #[test]
    fn a_new_confident_prediction_is_independent_of_the_pressure_level() {
        let mut wake = IdleWake::default();
        wake.observe(PressureLevel::Green, false, 3);
        wake.cover();
        assert!(wake.observe(PressureLevel::Green, true, 3));
        wake.cover();
        for _ in 0..100 {
            assert!(!wake.observe(PressureLevel::Green, true, 3));
        }
        assert!(wake.observe(PressureLevel::Yellow, true, 3));
    }

    #[test]
    fn confidence_jitter_and_brief_green_dips_do_not_rearm_an_incident() {
        let mut wake = IdleWake::default();
        wake.observe(PressureLevel::Red, true, 3);
        wake.cover();
        for _ in 0..100 {
            assert!(!wake.observe(PressureLevel::Green, false, 3));
            assert!(!wake.observe(PressureLevel::Green, false, 3));
            assert!(!wake.observe(PressureLevel::Red, true, 3));
        }
    }

    #[test]
    fn a_full_clean_window_rearms_both_pressure_and_prediction_retries() {
        let mut wake = IdleWake::default();
        wake.observe(PressureLevel::Critical, true, 3);
        wake.cover();
        for _ in 0..3 {
            assert!(!wake.observe(PressureLevel::Green, false, 3));
        }
        assert!(wake.observe(PressureLevel::Yellow, true, 3));
    }

    #[test]
    fn reset_preserves_the_current_observation_for_immediate_admission() {
        let mut wake = IdleWake::default();
        wake.observe(PressureLevel::Critical, true, 3);
        wake.reset();
        wake.cover();
        assert!(!wake.observe(PressureLevel::Critical, true, 3));
    }
}
