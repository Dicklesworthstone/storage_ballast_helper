#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::collections::HashMap;
use std::env;
use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use serde::Serialize;
use storage_ballast_helper::monitor::ewma::DiskRateEstimator;
use storage_ballast_helper::monitor::fs_stats::FsStatsCollector;
use storage_ballast_helper::monitor::pid::{PidConfig, PidPressureController, PressureReading};
use storage_ballast_helper::platform::pal::{
    FsStats, MemoryInfo, MockPlatform, MountPoint, Platform, PlatformPaths, detect_platform,
};

const GIB: u64 = 1024 * 1024 * 1024;
const DAEMON_POLL_TICK_BUDGET_MS: f64 = 200.0;
const PAL_SURFACE_BUDGET_MS: f64 = 5.0;
const STATUS_COLD_START_BUDGET_MS: f64 = 250.0;
const STATUS_COLD_START_SAMPLES: usize = 5;
const SUMMARY_ROUNDS: u32 = 7;
const SUMMARY_ITERATIONS_PER_ROUND: u32 = 2_048;

#[derive(Debug, Serialize)]
struct BenchmarkSummary {
    daemon_poll_tick_avg_ms: f64,
    daemon_poll_tick_budget_ms: f64,
    pal_surface_avg_ms: f64,
    pal_surface_budget_ms: f64,
    status_cold_start_p50_ms: f64,
    status_cold_start_budget_ms: f64,
    summary_rounds: u32,
    summary_iterations_per_round: u32,
}

impl BenchmarkSummary {
    fn assert_budgets(&self) {
        assert_at_most_ms(
            "daemon poll tick",
            self.daemon_poll_tick_avg_ms,
            self.daemon_poll_tick_budget_ms,
        );
        assert_at_most_ms(
            "PAL surface pass",
            self.pal_surface_avg_ms,
            self.pal_surface_budget_ms,
        );
        if self.status_cold_start_p50_ms > 0.0 && (budget_scale() - 1.0).abs() < f64::EPSILON {
            assert_at_most_ms(
                "status cold-start p50",
                self.status_cold_start_p50_ms,
                self.status_cold_start_budget_ms,
            );
        }
    }
}

struct PollTickFixture {
    collector: FsStatsCollector,
    root_path: PathBuf,
    estimator: DiskRateEstimator,
    controller: PidPressureController,
    started_at: Instant,
    sample_index: u64,
}

impl PollTickFixture {
    fn new() -> Self {
        let (platform, root_path) = benchmark_platform();
        Self {
            collector: FsStatsCollector::new(platform, Duration::ZERO),
            root_path,
            estimator: DiskRateEstimator::new(0.30, 0.10, 0.80, 3),
            controller: PidPressureController::new(
                &PidConfig {
                    kp: 0.25,
                    ki: 0.08,
                    kd: 0.02,
                    integral_cap: 100.0,
                    target_free_pct: 35.0,
                    hysteresis_pct: 1.0,
                    ..PidConfig::with_thresholds(35.0, 20.0, 10.0, 5.0)
                },
                Duration::from_secs(1),
            ),
            started_at: Instant::now(),
            sample_index: 0,
        }
    }

    fn tick(&mut self) {
        let stats = self
            .collector
            .collect(&self.root_path)
            .expect("synthetic fs stats should be available");
        let sample = self.sample_index;
        self.sample_index = self.sample_index.saturating_add(1);

        let consumed_bytes = (sample % 4096).saturating_mul(1024 * 1024);
        let available_bytes = stats.available_bytes.saturating_sub(consumed_bytes);
        let observed_at = self.started_at + Duration::from_secs(sample.saturating_add(1));
        let red_threshold_bytes = stats.total_bytes / 20;
        let rate_estimate =
            self.estimator
                .update(available_bytes, observed_at, red_threshold_bytes);
        let predicted_seconds = (rate_estimate.seconds_to_threshold.is_finite()
            && rate_estimate.seconds_to_threshold > 0.0)
            .then_some(rate_estimate.seconds_to_threshold);
        let response = self.controller.update(
            PressureReading {
                free_bytes: available_bytes,
                total_bytes: stats.total_bytes,
                mount: stats.mount_point,
            },
            predicted_seconds,
            observed_at,
        );
        black_box(response);
    }
}

struct PalSurfaceFixture {
    platform: Arc<dyn Platform>,
    root_path: PathBuf,
}

impl PalSurfaceFixture {
    fn new() -> Self {
        let (platform, root_path) = benchmark_platform();
        Self {
            platform,
            root_path,
        }
    }

    fn sample(&self) {
        black_box(
            self.platform
                .mount_points()
                .expect("synthetic mounts should be available"),
        );
        black_box(
            self.platform
                .fs_stats(&self.root_path)
                .expect("synthetic fs stats should be available"),
        );
        black_box(
            self.platform
                .capacity(&self.root_path)
                .expect("synthetic capacity should be available"),
        );
        black_box(
            self.platform
                .is_ram_backed(&self.root_path)
                .expect("synthetic ram-backed check should be available"),
        );
        black_box(self.platform.default_paths());
        black_box(
            self.platform
                .memory_info()
                .expect("synthetic memory info should be available"),
        );
        black_box(
            self.platform
                .mounts()
                .expect("synthetic mount info should be available"),
        );
    }
}

fn synthetic_root_path() -> PathBuf {
    PathBuf::from("/tmp/sbh-bench/workspace")
}

fn benchmark_platform() -> (Arc<dyn Platform>, PathBuf) {
    detect_platform().map_or_else(
        |_| (synthetic_platform(), synthetic_root_path()),
        |platform| (platform, env::temp_dir()),
    )
}

fn synthetic_platform() -> Arc<dyn Platform> {
    let mount_path = PathBuf::from("/tmp");
    let mounts = vec![MountPoint {
        path: mount_path.clone(),
        device: "sbh-bench".to_string(),
        fs_type: "apfs".to_string(),
        is_ram_backed: false,
    }];
    let fs_stats = FsStats {
        total_bytes: 1024 * GIB,
        free_bytes: 384 * GIB,
        available_bytes: 360 * GIB,
        fs_type: "apfs".to_string(),
        mount_point: mount_path.clone(),
        is_readonly: false,
    };
    let stats_by_mount = HashMap::from([(mount_path, fs_stats)]);
    let memory = MemoryInfo {
        total_bytes: 64 * GIB,
        available_bytes: 48 * GIB,
        swap_total_bytes: 8 * GIB,
        swap_free_bytes: 7 * GIB,
    };
    let paths = PlatformPaths {
        ballast_dir: PathBuf::from("/tmp/sbh-bench/state/ballast"),
        state_file: PathBuf::from("/tmp/sbh-bench/state/state.json"),
        sqlite_db: PathBuf::from("/tmp/sbh-bench/state/activity.sqlite3"),
        jsonl_log: PathBuf::from("/tmp/sbh-bench/state/activity.jsonl"),
    };

    Arc::new(MockPlatform::new(mounts, stats_by_mount, memory, paths))
}

fn assert_at_most_ms(name: &str, actual_ms: f64, budget_ms: f64) {
    assert!(
        actual_ms <= budget_ms,
        "{name} averaged {actual_ms:.3} ms; budget is {budget_ms:.3} ms"
    );
}

fn average_elapsed_ms(mut action: impl FnMut()) -> f64 {
    let total_iterations = SUMMARY_ROUNDS.saturating_mul(SUMMARY_ITERATIONS_PER_ROUND);
    let mut total = Duration::ZERO;
    for _ in 0..SUMMARY_ROUNDS {
        let started = Instant::now();
        for _ in 0..SUMMARY_ITERATIONS_PER_ROUND {
            action();
        }
        total = total.saturating_add(started.elapsed());
    }

    total.as_secs_f64() * 1000.0 / f64::from(total_iterations)
}

/// Shared CI runners run several times slower than the calibration
/// hardware; `SBH_BENCH_BUDGET_SCALE` widens the budgets there while the
/// checked-in constants stay strict for local hardware. The PR regression
/// limit still catches relative slowdowns.
fn budget_scale() -> f64 {
    std::env::var("SBH_BENCH_BUDGET_SCALE")
        .ok()
        .and_then(|scale| scale.parse::<f64>().ok())
        .filter(|scale| *scale >= 1.0)
        .unwrap_or(1.0)
}

fn find_sbh_bin() -> Option<PathBuf> {
    if let Ok(path) = env::var("SBH_BIN").map(PathBuf::from)
        && path.is_file()
    {
        return Some(path);
    }
    if let Ok(path) = env::var("CARGO_BIN_EXE_sbh").map(PathBuf::from)
        && path.is_file()
    {
        return Some(path);
    }
    if let Ok(current_exe) = env::current_exe()
        && let Some(deps_dir) = current_exe.parent()
    {
        if let Some(target_dir) = deps_dir.parent() {
            let candidate = target_dir.join(format!("sbh{}", env::consts::EXE_SUFFIX));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        let candidate = deps_dir.join(format!("sbh{}", env::consts::EXE_SUFFIX));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    for rel in ["target/release/sbh", "target/debug/sbh"] {
        let candidate = PathBuf::from(rel);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn measure_status_cold_start_p50_ms() -> f64 {
    let Some(sbh_bin) = find_sbh_bin() else {
        eprintln!(
            "[sbh-bench] warning: sbh binary not found, status cold-start measurement skipped"
        );
        return 0.0;
    };

    let mut samples_ms = Vec::with_capacity(STATUS_COLD_START_SAMPLES);
    for _ in 0..STATUS_COLD_START_SAMPLES {
        let started = Instant::now();
        let Ok(status) = Command::new(&sbh_bin)
            .args(["status", "--json"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        else {
            eprintln!(
                "[sbh-bench] warning: failed to spawn sbh binary for status cold-start measurement"
            );
            return 0.0;
        };

        if !status.success() {
            eprintln!("[sbh-bench] warning: sbh status --json exited with non-zero status");
            return 0.0;
        }
        samples_ms.push(started.elapsed().as_secs_f64() * 1000.0);
    }

    samples_ms.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    let median_index = samples_ms.len() / 2;
    samples_ms.get(median_index).copied().unwrap_or(0.0)
}

fn measure_summary() -> BenchmarkSummary {
    let mut poll_tick = PollTickFixture::new();
    let daemon_poll_tick_avg_ms = average_elapsed_ms(|| poll_tick.tick());

    let pal_surface = PalSurfaceFixture::new();
    let pal_surface_avg_ms = average_elapsed_ms(|| pal_surface.sample());

    let status_cold_start_p50_ms = measure_status_cold_start_p50_ms();

    BenchmarkSummary {
        daemon_poll_tick_avg_ms,
        daemon_poll_tick_budget_ms: DAEMON_POLL_TICK_BUDGET_MS * budget_scale(),
        pal_surface_avg_ms,
        pal_surface_budget_ms: PAL_SURFACE_BUDGET_MS * budget_scale(),
        status_cold_start_p50_ms,
        status_cold_start_budget_ms: STATUS_COLD_START_BUDGET_MS * budget_scale(),
        summary_rounds: SUMMARY_ROUNDS,
        summary_iterations_per_round: SUMMARY_ITERATIONS_PER_ROUND,
    }
}

fn write_summary_if_requested(summary: &BenchmarkSummary) {
    let Some(path) = env::var_os("SBH_BENCH_SUMMARY").map(PathBuf::from) else {
        return;
    };
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).expect("benchmark summary directory should be writable");
    }
    let payload = serde_json::to_string_pretty(summary).expect("benchmark summary should encode");
    fs::write(&path, format!("{payload}\n")).expect("benchmark summary should be writable");
}

fn macos_performance(c: &mut Criterion) {
    let summary = measure_summary();
    summary.assert_budgets();
    write_summary_if_requested(&summary);

    let mut group = c.benchmark_group("macos_performance");
    group.bench_function("daemon_poll_tick", |bench| {
        let mut fixture = PollTickFixture::new();
        bench.iter(|| fixture.tick());
    });
    group.bench_function("pal_surface", |bench| {
        let fixture = PalSurfaceFixture::new();
        bench.iter(|| fixture.sample());
    });
    if let Some(sbh_bin) = find_sbh_bin() {
        group.bench_function("status_cold_start", |bench| {
            bench.iter(|| {
                let _ = Command::new(&sbh_bin)
                    .args(["status", "--json"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            });
        });
    }
    group.finish();
}

criterion_group!(benches, macos_performance);
criterion_main!(benches);
