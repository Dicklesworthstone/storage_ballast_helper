#![allow(missing_docs)]

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{Duration, Instant};
    use storage_ballast_helper::monitor::pid::{
        PidPressureController, PressureLevel, PressureReading,
    };

    #[test]
    fn pid_urgency_spikes_on_clock_skew() {
        let mut pid = PidPressureController::new(
            0.25,
            0.08,
            0.02, // Kd = 0.02
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

        // 1. Initial stable state (Green)
        // Target free = 18%. Current free = 20% (Green). Error = -2.0.
        let r1 = pid.update(
            PressureReading {
                free_bytes: 20,
                total_bytes: 100,
                mount: PathBuf::from("/"),
            },
            None,
            t0,
        );
        assert_eq!(r1.level, PressureLevel::Green);
        assert!(r1.urgency < 0.1, "Urgency should be low initially");

        // 2. Clock glitch: next update is "in the past" or same instant
        // Free space drops slightly to 19.9% (Error = -1.9).
        // Delta Error = -1.9 - (-2.0) = 0.1.
        // If dt is clamped to 1e-6, Derivative = 0.1 / 1e-6 = 100,000.
        // Kd * Derivative = 0.02 * 100,000 = 2,000.
        // Urgency -> 1.0.

        // We simulate "now" being equal to t0 (zero elapsed) or slightly backward.
        // saturating_duration_since(t0) will be 0.
        let t1 = t0;

        let r2 = pid.update(
            PressureReading {
                free_bytes: 199, // 19.9%
                total_bytes: 1000,
                mount: PathBuf::from("/"),
            },
            None,
            t1,
        );

        println!("Urgency after clock skew: {}", r2.urgency);

        // We expect this to fail if the bug exists (urgency will be spiked)
        // Ideally urgency should remain low because pressure is practically unchanged.
        assert!(
            r2.urgency < 0.5,
            "Urgency spiked to {} due to clock skew!",
            r2.urgency
        );
    }
}
