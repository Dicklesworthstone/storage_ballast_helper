//! Poll disk usage, run through EWMA + PID controller, and report pressure level.
//!
//! Usage:
//!   cargo run --example pressure_monitor -- /path/to/monitor
//!
//! Demonstrates library-only usage: filesystem stats, rate estimation, PID controller.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use storage_ballast_helper::core::config::Config;
use storage_ballast_helper::monitor::ewma::DiskRateEstimator;
use storage_ballast_helper::monitor::fs_stats::FsStatsCollector;
use storage_ballast_helper::monitor::pid::{PidPressureController, PressureReading};
use storage_ballast_helper::platform::pal::detect_platform;

fn main() {
    let monitor_path = std::env::args()
        .nth(1)
        .map_or_else(|| PathBuf::from("/"), PathBuf::from);

    println!("Monitoring: {}", monitor_path.display());

    let platform = detect_platform().expect("detect platform");
    let config = Config::default();
    let collector = FsStatsCollector::new(platform, Duration::from_secs(1));

    let mut estimator = DiskRateEstimator::new(0.3, 0.05, 0.8, 3);

    // Use sensible defaults for PID gains since Config doesn't expose them directly.
    let mut controller = PidPressureController::new(
        1.0,  // kp
        0.1,  // ki
        0.05, // kd
        50.0, // integral_cap
        20.0, // target_free_pct
        1.0,  // hysteresis_pct
        config.pressure.green_min_free_pct,
        config.pressure.yellow_min_free_pct,
        config.pressure.orange_min_free_pct,
        config.pressure.red_min_free_pct,
        Duration::from_millis(config.pressure.poll_interval_ms),
    );

    // Take 5 samples at 1-second intervals.
    for i in 0..5 {
        let stats = collector.collect(&monitor_path).expect("collect fs stats");
        let now = Instant::now();
        let red_pct = config.pressure.red_min_free_pct.clamp(0.0, 100.0);
        let red_basis_points = format!("{:.0}", red_pct * 100.0)
            .parse::<u64>()
            .unwrap_or(500);
        let threshold_bytes = stats
            .total_bytes
            .saturating_mul(red_basis_points)
            .saturating_div(10_000);
        let estimate = estimator.update(stats.free_bytes, now, threshold_bytes);

        let reading = PressureReading {
            free_bytes: stats.free_bytes,
            total_bytes: stats.total_bytes,
            mount: monitor_path.clone(),
        };
        let response = controller.update(reading.clone(), Some(estimate.seconds_to_threshold), now);

        println!(
            "[{i}] free={:.1}% rate={:+.0} B/s trend={:?} level={:?} urgency={:.2} poll={:?}",
            reading.free_pct(),
            estimate.bytes_per_second,
            estimate.trend,
            response.level,
            response.urgency,
            response.scan_interval,
        );

        std::thread::sleep(Duration::from_secs(1));
    }
}
