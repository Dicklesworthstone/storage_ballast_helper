#![allow(missing_docs)]

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{Duration, Instant};
    use storage_ballast_helper::monitor::pid::{
        PidConfig, PidPressureController, PressureLevel, PressureReading,
    };

    #[test]
    fn regression_issue_pid_slow_attack() {
        // Setup controller with standard thresholds:
        // Green > 20%
        // Yellow 14-20%
        // Orange 10-14%
        // Red 6-10%
        // Critical < 6%
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

        // 1. Start at healthy state (50% free).
        let r1 = pid.update(
            PressureReading {
                free_bytes: 50,
                total_bytes: 100,
                mount: PathBuf::from("/"),
            },
            None,
            t0,
        );
        assert_eq!(r1.level, PressureLevel::Green);

        // 2. Sudden drop to 1% free (Critical).
        // EXPECTATION: Should jump straight to Critical.
        let r2 = pid.update(
            PressureReading {
                free_bytes: 1,
                total_bytes: 100,
                mount: PathBuf::from("/"),
            },
            None,
            t0 + Duration::from_secs(1),
        );

        println!("After drop to 1% free: {:?}", r2.level);
        assert_eq!(
            r2.level,
            PressureLevel::Critical,
            "Should jump immediately to Critical on massive pressure spike"
        );

        // 3. Relax slightly to 7% free (Red).
        // Threshold to enter Red is 6%. To leave Critical (upwards), we need >= 6 + 1 = 7%.
        // So 7% should allow us to go to Red.
        let r3 = pid.update(
            PressureReading {
                free_bytes: 7,
                total_bytes: 100,
                mount: PathBuf::from("/"),
            },
            None,
            t0 + Duration::from_secs(2),
        );
        println!("After relax to 7% free: {:?}", r3.level);
        assert_eq!(
            r3.level,
            PressureLevel::Red,
            "Should relax to Red when hysteresis cleared"
        );
    }
}
