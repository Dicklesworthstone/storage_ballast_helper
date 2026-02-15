//! Shared test infrastructure for storage_ballast_helper.
//!
//! Provides:
//! - `CmdResult` + `run_cli_case()` — integration test CLI runner
//! - `MockPlatform` — configurable platform mock for unit tests
//! - `TestEnvironment` — realistic directory tree builder
//! - `create_fake_rust_target()` — builds a realistic `target/` directory
//! - `SyntheticTimeSeries` — generates pressure patterns for EWMA/PID testing

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ──────────────────── CLI test runner ────────────────────

pub struct CmdResult {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
    pub log_path: PathBuf,
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn resolve_bin_path() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_sbh") {
        let p = PathBuf::from(path);
        if p.exists() {
            return p;
        }
    }

    let exe_name = if cfg!(windows) { "sbh.exe" } else { "sbh" };
    let fallback = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(PathBuf::from))
        .and_then(|deps| deps.parent().map(PathBuf::from))
        .map(|debug_dir| debug_dir.join(exe_name));

    match fallback {
        Some(path) if path.exists() => path,
        _ => panic!(
            "unable to resolve sbh binary path for integration test (checked CARGO_BIN_EXE_sbh and debug sibling path)"
        ),
    }
}

pub fn run_cli_case(case_name: &str, args: &[&str]) -> CmdResult {
    let root = std::env::temp_dir().join("sbh-test-logs");
    fs::create_dir_all(&root).expect("create temp test log dir");

    let log_path = root.join(format!("{}-{}.log", sanitize(case_name), now_millis()));
    let bin_path = resolve_bin_path();

    let output = Command::new(&bin_path)
        .args(args)
        .env("SBH_TEST_VERBOSE", "1")
        .env("SBH_OUTPUT_FORMAT", "human")
        .env("RUST_BACKTRACE", "1")
        .output()
        .expect("execute sbh command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let mut log_content = String::new();
    log_content.push_str(&format!("case={case_name}\n"));
    log_content.push_str(&format!("bin={}\n", bin_path.display()));
    log_content.push_str(&format!("args={args:?}\n"));
    log_content.push_str(&format!("status={}\n", output.status));
    log_content.push_str("----- stdout -----\n");
    log_content.push_str(&stdout);
    log_content.push('\n');
    log_content.push_str("----- stderr -----\n");
    log_content.push_str(&stderr);
    log_content.push('\n');
    fs::write(&log_path, log_content).expect("write test log");

    CmdResult {
        status: output.status,
        stdout,
        stderr,
        log_path,
    }
}

// ──────────────────── MockPlatform ────────────────────

use storage_ballast_helper::platform::pal::{
    FsStats, MemoryInfo, MountPoint, NoopServiceManager, Platform, PlatformPaths, ServiceManager,
};
use storage_ballast_helper::core::errors::{Result, SbhError};

/// Configurable platform mock for unit tests.
///
/// Allows tests to control filesystem stats, mount points, memory info, and paths
/// without touching real system state.
pub struct MockPlatform {
    pub fs_stats: std::collections::HashMap<PathBuf, FsStats>,
    pub mounts: Vec<MountPoint>,
    pub memory: MemoryInfo,
    pub paths: PlatformPaths,
}

impl MockPlatform {
    /// Create a mock with sensible defaults (1 TB total, 250 GB free on `/data`).
    pub fn default_healthy() -> Self {
        let mut fs_stats = std::collections::HashMap::new();
        let data_path = PathBuf::from("/data");
        fs_stats.insert(
            data_path.clone(),
            FsStats {
                total_bytes: 1_000_000_000_000,
                free_bytes: 250_000_000_000,
                available_bytes: 250_000_000_000,
                fs_type: "ext4".to_string(),
                mount_point: data_path.clone(),
                is_readonly: false,
            },
        );

        Self {
            fs_stats,
            mounts: vec![MountPoint {
                path: data_path,
                device: "/dev/sda1".to_string(),
                fs_type: "ext4".to_string(),
                is_ram_backed: false,
            }],
            memory: MemoryInfo {
                total_bytes: 64 * 1024 * 1024 * 1024,
                available_bytes: 32 * 1024 * 1024 * 1024,
                swap_total_bytes: 16 * 1024 * 1024 * 1024,
                swap_free_bytes: 16 * 1024 * 1024 * 1024,
            },
            paths: PlatformPaths::default(),
        }
    }

    /// Create a mock in pressure state (disk 95% full).
    pub fn default_pressured() -> Self {
        let mut mock = Self::default_healthy();
        for stats in mock.fs_stats.values_mut() {
            stats.free_bytes = stats.total_bytes / 20; // 5% free
            stats.available_bytes = stats.free_bytes;
        }
        mock
    }

    /// Add a mount point with configurable free space.
    pub fn add_mount(&mut self, path: impl Into<PathBuf>, total: u64, free: u64) {
        let path = path.into();
        self.fs_stats.insert(
            path.clone(),
            FsStats {
                total_bytes: total,
                free_bytes: free,
                available_bytes: free,
                fs_type: "ext4".to_string(),
                mount_point: path.clone(),
                is_readonly: false,
            },
        );
        self.mounts.push(MountPoint {
            path,
            device: "/dev/mock".to_string(),
            fs_type: "ext4".to_string(),
            is_ram_backed: false,
        });
    }
}

impl Platform for MockPlatform {
    fn fs_stats(&self, path: &Path) -> Result<FsStats> {
        self.fs_stats
            .get(path)
            .cloned()
            .ok_or_else(|| SbhError::FsStats {
                path: path.to_path_buf(),
                details: "mock: path not configured".to_string(),
            })
    }

    fn mount_points(&self) -> Result<Vec<MountPoint>> {
        Ok(self.mounts.clone())
    }

    fn is_ram_backed(&self, path: &Path) -> Result<bool> {
        Ok(self
            .mounts
            .iter()
            .any(|m| m.path == path && m.is_ram_backed))
    }

    fn default_paths(&self) -> PlatformPaths {
        self.paths.clone()
    }

    fn memory_info(&self) -> Result<MemoryInfo> {
        Ok(self.memory.clone())
    }

    fn service_manager(&self) -> Box<dyn ServiceManager> {
        Box::new(NoopServiceManager)
    }
}

// ──────────────────── TestEnvironment ────────────────────

/// Builder for realistic directory trees with controlled file ages, sizes, and patterns.
pub struct TestEnvironment {
    root: tempfile::TempDir,
}

impl TestEnvironment {
    /// Create a new empty test environment.
    pub fn new() -> Self {
        Self {
            root: tempfile::tempdir().expect("create test tempdir"),
        }
    }

    /// Root directory path.
    pub fn root(&self) -> &Path {
        self.root.path()
    }

    /// Create a file with specified content and age.
    pub fn create_file(&self, rel_path: &str, content: &[u8], age: Duration) -> PathBuf {
        let path = self.root.path().join(rel_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(&path, content).expect("write test file");

        // Set modification time to (now - age).
        let mtime = SystemTime::now() - age;
        let _ = filetime::set_file_mtime(
            &path,
            filetime::FileTime::from_system_time(mtime),
        );

        path
    }

    /// Create an empty directory.
    pub fn create_dir(&self, rel_path: &str) -> PathBuf {
        let path = self.root.path().join(rel_path);
        fs::create_dir_all(&path).expect("create test dir");
        path
    }

    /// Create a file of specified size (filled with zeros).
    pub fn create_sized_file(&self, rel_path: &str, size: usize, age: Duration) -> PathBuf {
        self.create_file(rel_path, &vec![0u8; size], age)
    }
}

// ──────────────────── create_fake_rust_target ────────────────────

/// Build a realistic Rust `target/` directory with standard subdirectories.
///
/// Creates: `target/debug/incremental/`, `target/debug/deps/`,
/// `target/debug/build/`, `target/debug/.fingerprint/`, and some
/// dummy `.rlib` files.
pub fn create_fake_rust_target(root: &Path, age: Duration) -> PathBuf {
    let target = root.join("target");
    let debug = target.join("debug");

    for subdir in &["incremental", "deps", "build", ".fingerprint"] {
        fs::create_dir_all(debug.join(subdir)).expect("create target subdir");
    }

    // Dummy artifact files.
    let artifacts = &[
        "deps/libfoo-abc123.rlib",
        "deps/libbar-def456.rlib",
        "incremental/foo-abc/s-xyz-working/dep-graph.bin",
        "build/build-script-build/output",
        ".fingerprint/foo-abc/dep-lib-foo",
    ];

    for artifact in artifacts {
        let path = debug.join(artifact);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create artifact parent");
        }
        fs::write(&path, "dummy artifact data").expect("write artifact");
    }

    // Set age on the top-level target directory.
    if age > Duration::ZERO {
        let mtime = SystemTime::now() - age;
        let _ = filetime::set_file_mtime(
            &target,
            filetime::FileTime::from_system_time(mtime),
        );
    }

    target
}

// ──────────────────── SyntheticTimeSeries ────────────────────

/// Generates synthetic free-space time series for EWMA/PID testing.
///
/// Supports several realistic patterns: steady consumption, burst, recovery,
/// plateau, and oscillation.
pub struct SyntheticTimeSeries {
    /// Free-space values at each tick.
    pub values: Vec<u64>,
    /// Interval between ticks.
    pub tick_interval: Duration,
}

impl SyntheticTimeSeries {
    /// Steady consumption: free space decreases linearly.
    pub fn steady_consumption(initial_free: u64, rate_per_tick: u64, ticks: usize) -> Self {
        let mut values = Vec::with_capacity(ticks);
        let mut current = initial_free;
        for _ in 0..ticks {
            values.push(current);
            current = current.saturating_sub(rate_per_tick);
        }
        Self {
            values,
            tick_interval: Duration::from_secs(1),
        }
    }

    /// Burst consumption: normal rate then sudden spike.
    pub fn burst(
        initial_free: u64,
        normal_rate: u64,
        burst_rate: u64,
        normal_ticks: usize,
        burst_ticks: usize,
    ) -> Self {
        let total = normal_ticks + burst_ticks;
        let mut values = Vec::with_capacity(total);
        let mut current = initial_free;

        for _ in 0..normal_ticks {
            values.push(current);
            current = current.saturating_sub(normal_rate);
        }
        for _ in 0..burst_ticks {
            values.push(current);
            current = current.saturating_sub(burst_rate);
        }

        Self {
            values,
            tick_interval: Duration::from_secs(1),
        }
    }

    /// Recovery: consumption then free space increases.
    pub fn recovery(
        initial_free: u64,
        consume_rate: u64,
        consume_ticks: usize,
        recover_rate: u64,
        recover_ticks: usize,
    ) -> Self {
        let total = consume_ticks + recover_ticks;
        let mut values = Vec::with_capacity(total);
        let mut current = initial_free;

        for _ in 0..consume_ticks {
            values.push(current);
            current = current.saturating_sub(consume_rate);
        }
        for _ in 0..recover_ticks {
            values.push(current);
            current = current.saturating_add(recover_rate);
        }

        Self {
            values,
            tick_interval: Duration::from_secs(1),
        }
    }

    /// Plateau: steady state with no change.
    pub fn plateau(free_bytes: u64, ticks: usize) -> Self {
        Self {
            values: vec![free_bytes; ticks],
            tick_interval: Duration::from_secs(1),
        }
    }
}
