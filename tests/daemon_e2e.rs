//! Real-daemon end-to-end runner and scenario table (W10,
//! bd-rc-master-ajg1.11.1 and .11.2).
//!
//! Spawns the built `sbh` binary as a daemon against a temporary config,
//! optionally with injected filesystem statistics (`SBH_TEST_MODE=1` +
//! `SBH_TEST_FS_STATS`), captures stderr, the JSONL activity log and
//! `state.json`, polls with deadlines, and kills the daemon on timeout. A
//! scenario that never sees a state file fails; nothing here passes
//! vacuously.
//!
//! Two scenarios need a real filesystem whose free space and write mode the
//! test controls (a loop-mounted ext4 image): they are `#[ignore]`d and run
//! with `--ignored` where passwordless sudo is available.
#![allow(missing_docs)]

mod common;

use std::ffi::OsStr;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use serde_json::Value;
use storage_ballast_helper::scanner::active_lease::ActiveLease;

// ──────────────────── fixtures ────────────────────

/// A temp tree with the standard fixtures: a stale Definite cargo target,
/// a fresh target, and a source project with a `.git` sibling of its target.
pub struct Fixtures {
    pub root: PathBuf,
    pub stale_target: PathBuf,
    pub fresh_target: PathBuf,
    pub project_target: PathBuf,
}

impl Fixtures {
    /// Build the fixtures under `dir`. `stale_age` is applied to every
    /// mtime under the stale target; the directory's birth time is now, so
    /// callers gate on `min_file_age_minutes` accordingly.
    pub fn build(dir: &Path, stale_age: Duration, rlib_bytes: usize) -> Self {
        let root = dir.join("root");
        let stale_target = definite_target(&root.join("stale-proj"), stale_age, rlib_bytes);
        let fresh_target = definite_target(&root.join("fresh-proj"), Duration::ZERO, 1024);
        let project = root.join("src-proj");
        fs::create_dir_all(project.join(".git")).unwrap();
        let project_target = definite_target(&project, stale_age, 1024);
        Self {
            root,
            stale_target,
            fresh_target,
            project_target,
        }
    }

    /// Keep the fresh target fresh: a new write under it every call.
    pub fn touch_fresh(&self) {
        let path = self
            .fresh_target
            .join("debug")
            .join("deps")
            .join("libfresh-touch.rlib");
        let _ = fs::write(
            path,
            SystemTime::now()
                .elapsed()
                .map_or(0u128, |d| d.as_nanos())
                .to_string(),
        );
    }
}

/// A cargo target that classifies as Definite: valid `CACHEDIR.TAG` plus the
/// `debug/{deps,incremental,build,.fingerprint}` layout.
fn definite_target(project: &Path, age: Duration, rlib_bytes: usize) -> PathBuf {
    let target = project.join("target");
    let debug = target.join("debug");
    for sub in ["deps", "incremental", "build", ".fingerprint"] {
        fs::create_dir_all(debug.join(sub)).unwrap();
    }
    fs::write(
        target.join("CACHEDIR.TAG"),
        "Signature: 8a477f597d28d172789f06886806bc55\n# cargo\n",
    )
    .unwrap();
    fs::write(
        debug.join("deps").join("libfixture.rlib"),
        vec![0xA5u8; rlib_bytes],
    )
    .unwrap();
    fs::write(debug.join("incremental").join("unit-0"), b"x").unwrap();
    fs::write(debug.join(".fingerprint").join("lib-fixture"), b"x").unwrap();
    if age > Duration::ZERO {
        let mtime = filetime::FileTime::from_system_time(SystemTime::now() - age);
        set_mtime_recursive(&target, mtime);
    }
    target
}

fn set_mtime_recursive(path: &Path, mtime: filetime::FileTime) {
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            set_mtime_recursive(&entry.path(), mtime);
        }
    }
    let _ = filetime::set_file_mtime(path, mtime);
}

// ──────────────────── config ────────────────────

/// Knobs a scenario sets; everything else is the daemon's default.
pub struct ScenarioConfig {
    pub root_paths: Vec<PathBuf>,
    pub poll_interval_ms: u64,
    pub min_file_age_minutes: u64,
    pub maintenance_interval_secs: u64,
    pub min_rescan_interval_secs: u64,
    pub cross_devices: bool,
    pub catalog_roots: bool,
    pub thresholds: (f64, f64, f64, f64),
    pub ballast_files: usize,
    pub ballast_file_bytes: u64,
    /// Scanner engine: `v2` (default) or the `v1` rollback engine.
    pub engine: &'static str,
    /// When set, notifications go to this file (JSON lines) instead of
    /// being disabled.
    pub notify_file: Option<PathBuf>,
    /// Raw TOML appended after the generated sections.
    pub extra_toml: String,
    /// `scanner.max_scan_duty_cycle_pct` (100 disables the per-pass limiter).
    pub duty_cycle_pct: u8,
    /// `telemetry.cpu_budget_pct` (0 disables the daemon-wide budget).
    pub cpu_budget_pct: u8,
}

impl Default for ScenarioConfig {
    fn default() -> Self {
        Self {
            root_paths: Vec::new(),
            poll_interval_ms: 500,
            min_file_age_minutes: 30,
            maintenance_interval_secs: 1800,
            min_rescan_interval_secs: 90,
            cross_devices: false,
            catalog_roots: false,
            thresholds: (20.0, 14.0, 10.0, 6.0),
            // The config refuses a zero-file pool; one 1 MiB file is the
            // smallest reserve the daemon accepts.
            ballast_files: 1,
            ballast_file_bytes: 1_048_576,
            engine: "v2",
            notify_file: None,
            extra_toml: String::new(),
            duty_cycle_pct: 25,
            cpu_budget_pct: 25,
        }
    }
}

fn write_config(dir: &Path, scenario: &ScenarioConfig) -> PathBuf {
    let data = dir.join("data");
    fs::create_dir_all(&data).unwrap();
    let roots = scenario
        .root_paths
        .iter()
        .map(|p| format!("{:?}", p.display().to_string()))
        .collect::<Vec<_>>()
        .join(", ");
    let (green, yellow, orange, red) = scenario.thresholds;
    let notifications = scenario.notify_file.as_ref().map_or_else(
        || "[notifications]\nenabled = false\n".to_string(),
        |path| {
            format!(
                "[notifications]\nenabled = true\nchannels = [\"file\"]\n[notifications.file]\npath = {:?}\n",
                path.display().to_string()
            )
        },
    );
    let config = format!(
        r"[paths]
ballast_dir = {ballast:?}
jsonl_log = {jsonl:?}
sqlite_db = {sqlite:?}
state_file = {state:?}
[ballast]
file_count = {ballast_files}
file_size_bytes = {ballast_bytes}
[pressure]
poll_interval_ms = {poll}
maintenance_interval_secs = {maint}
green_min_free_pct = {green}
yellow_min_free_pct = {yellow}
orange_min_free_pct = {orange}
red_min_free_pct = {red}
[scanner]
engine = {engine:?}
cross_devices = {cross}
catalog_roots_on_pressured_device = {catalog}
root_paths = [{roots}]
min_file_age_minutes = {min_age}
min_rescan_interval_secs = {rescan}
max_scan_duty_cycle_pct = {duty}
max_depth = 6
parallelism = 2
[telemetry]
cpu_budget_pct = {budget}
{notifications}{extra}",
        ballast = data.join("ballast").display().to_string(),
        jsonl = data.join("activity.jsonl").display().to_string(),
        sqlite = data.join("activity.sqlite3").display().to_string(),
        state = data.join("state.json").display().to_string(),
        ballast_files = scenario.ballast_files,
        ballast_bytes = scenario.ballast_file_bytes,
        poll = scenario.poll_interval_ms,
        maint = scenario.maintenance_interval_secs,
        engine = scenario.engine,
        cross = scenario.cross_devices,
        catalog = scenario.catalog_roots,
        roots = roots,
        min_age = scenario.min_file_age_minutes,
        rescan = scenario.min_rescan_interval_secs,
        duty = scenario.duty_cycle_pct,
        budget = scenario.cpu_budget_pct,
        extra = scenario.extra_toml,
    );
    let path = dir.join("config.toml");
    fs::write(&path, config).unwrap();
    path
}

// ──────────────────── runner ────────────────────

/// A running daemon plus everything it writes.
pub struct DaemonRun {
    child: Child,
    pub config_path: PathBuf,
    pub data_dir: PathBuf,
    pub stderr_path: PathBuf,
    started: Instant,
}

/// What the runner refused or could not prove.
#[derive(Debug)]
pub enum RunnerError {
    /// The daemon exited before the scenario finished.
    Exited(std::process::ExitStatus, String),
    /// The daemon never wrote what the scenario waited for.
    Timeout(String),
}

impl std::fmt::Display for RunnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exited(status, stderr) => {
                write!(f, "daemon exited early ({status}); stderr tail:\n{stderr}")
            }
            Self::Timeout(what) => write!(f, "timed out waiting for {what}"),
        }
    }
}

impl DaemonRun {
    /// Spawn the built binary as a daemon. `injected` is the JSON mount table
    /// for `SBH_TEST_FS_STATS` (test mode is enabled whenever it is given).
    pub fn spawn(dir: &Path, scenario: &ScenarioConfig, injected: Option<&str>) -> Self {
        let config_path = write_config(dir, scenario);
        let data_dir = dir.join("data");
        let stderr_path = dir.join("daemon.stderr");
        let stderr = fs::File::create(&stderr_path).unwrap();
        let mut command = Command::new(common::sbh_bin_path());
        command
            .arg("--config")
            .arg(&config_path)
            .arg("daemon")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr)
            .env_remove("INVOCATION_ID")
            .env_remove("NOTIFY_SOCKET");
        if let Some(table) = injected {
            command
                .env("SBH_TEST_MODE", "1")
                .env("SBH_TEST_FS_STATS", table);
        }
        let child = command.spawn().expect("spawn sbh daemon");
        Self {
            child,
            config_path,
            data_dir,
            stderr_path,
            started: Instant::now(),
        }
    }

    pub fn state_path(&self) -> PathBuf {
        self.data_dir.join("state.json")
    }

    pub fn stderr(&self) -> String {
        fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }

    fn stderr_tail(&self) -> String {
        let text = self.stderr();
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(20)..].join("\n")
    }

    pub fn state(&self) -> Option<Value> {
        let raw = fs::read_to_string(self.state_path()).ok()?;
        serde_json::from_str(&raw).ok()
    }

    /// Parsed JSONL activity events.
    pub fn events(&self) -> Vec<Value> {
        fs::read_to_string(self.data_dir.join("activity.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    pub fn events_of(&self, kind: &str) -> Vec<Value> {
        self.events()
            .into_iter()
            .filter(|event| event.get("event").and_then(Value::as_str) == Some(kind))
            .collect()
    }

    /// Paths the daemon deleted so far (failed attempts excluded).
    pub fn deleted_paths(&self) -> Vec<PathBuf> {
        self.events_of("artifact_delete")
            .iter()
            .filter(|event| event.get("ok") != Some(&Value::Bool(false)))
            .filter_map(|event| event.get("path").and_then(Value::as_str))
            .map(PathBuf::from)
            .collect()
    }

    /// Send a signal by `kill` name (`-HUP`, `-USR1`).
    pub fn signal(&self, sig: &str) {
        let status = Command::new("kill")
            .arg(sig)
            .arg(self.child.id().to_string())
            .status()
            .expect("run kill");
        assert!(status.success(), "kill {sig} failed");
    }

    /// CPU seconds the daemon reports in `state.json` as a fraction of the
    /// wall time since spawn (`None` until the state file exists).
    pub fn cpu_ratio(&self) -> Option<f64> {
        let cpu = self.state()?.get("cpu_secs_total")?.as_f64()?;
        Some(cpu / self.started.elapsed().as_secs_f64())
    }

    /// The daemon's CPU time right now from the kernel (user + system), so
    /// a budget assertion does not depend on the 30 s state-write cadence.
    #[allow(clippy::cast_precision_loss)]
    pub fn proc_cpu_secs(&self) -> f64 {
        let stat = fs::read_to_string(format!("/proc/{}/stat", self.child.id())).unwrap();
        let tail = &stat[stat.rfind(')').unwrap() + 1..];
        let fields: Vec<&str> = tail.split_whitespace().collect();
        let ticks: u64 = fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap();
        let hz = nix::unistd::sysconf(nix::unistd::SysconfVar::CLK_TCK)
            .ok()
            .flatten()
            .unwrap_or(100);
        ticks as f64 / hz as f64
    }

    pub fn wall_secs(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }

    /// Number of stderr lines containing `needle`.
    pub fn stderr_count(&self, needle: &str) -> usize {
        self.stderr()
            .lines()
            .filter(|line| line.contains(needle))
            .count()
    }

    /// The controller record for `mount` from the latest state file.
    pub fn mount_record(&self, mount: &Path) -> Option<Value> {
        let state = self.state()?;
        let wanted = mount.to_string_lossy();
        state["mount_controllers"]
            .as_array()?
            .iter()
            .find(|c| c["mount"] == wanted.as_ref())
            .cloned()
    }

    /// Copy the daemon's stderr, activity log and state file somewhere that
    /// survives the scratch directory, for post-mortems; returns that dir.
    fn preserve_outputs(&self) -> PathBuf {
        let name = self
            .data_dir
            .parent()
            .and_then(Path::file_name)
            .map_or_else(|| "run".to_string(), |n| n.to_string_lossy().into_owned());
        let dir = scratch_base()
            .join("sbh-e2e-failures")
            .join(format!("{name}-{}", self.child.id()));
        let _ = fs::create_dir_all(&dir);
        for (from, to) in [
            (self.stderr_path.clone(), "daemon.stderr"),
            (self.data_dir.join("activity.jsonl"), "activity.jsonl"),
            (self.state_path(), "state.json"),
        ] {
            let _ = fs::copy(from, dir.join(to));
        }
        dir
    }

    fn timeout(&self, what: &str) -> RunnerError {
        RunnerError::Timeout(format!(
            "{what} after {:?}; deleted so far: {:?}; outputs kept in {}; stderr tail:\n{}",
            self.started.elapsed(),
            self.deleted_paths(),
            self.preserve_outputs().display(),
            self.stderr_tail()
        ))
    }

    /// Poll until `predicate` holds for the state file, the daemon exits, or
    /// the deadline passes. Never passes vacuously: no state means failure.
    pub fn wait_for_state(
        &mut self,
        what: &str,
        timeout: Duration,
        predicate: impl Fn(&Value) -> bool,
    ) -> Result<Value, RunnerError> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll daemon") {
                return Err(RunnerError::Exited(status, self.stderr_tail()));
            }
            if let Some(state) = self.state()
                && predicate(&state)
            {
                return Ok(state);
            }
            if Instant::now() >= deadline {
                return Err(self.timeout(what));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Poll until `predicate` holds for the run (events, deletions, ...).
    pub fn wait_until(
        &mut self,
        what: &str,
        timeout: Duration,
        mut predicate: impl FnMut(&Self) -> bool,
    ) -> Result<(), RunnerError> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll daemon") {
                return Err(RunnerError::Exited(status, self.stderr_tail()));
            }
            if predicate(self) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(self.timeout(what));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// SIGTERM, then wait; SIGKILL if the daemon ignores it.
    pub fn stop(mut self) -> std::process::ExitStatus {
        let pid = self.child.id();
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .status();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.child.try_wait().expect("poll daemon") {
                return status;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                return self.child.wait().expect("reap daemon");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for DaemonRun {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One injected mount as JSON: `series` steps `free` at the given seconds
/// after daemon start.
fn mount_entry(
    path: &Path,
    total: u64,
    free: u64,
    readonly: bool,
    series: &[(u64, u64)],
) -> String {
    let points = series
        .iter()
        .map(|(after_secs, free)| format!(r#"{{"after_secs":{after_secs},"free":{free}}}"#))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"path":{:?},"fs_type":"ext4","total":{total},"free":{free},"readonly":{readonly},"series":[{points}]}}"#,
        path.display().to_string()
    )
}

/// JSON mount table: `(path, total, free, readonly)`. A read-only mount gets
/// no ballast pool, which is how a scenario keeps a pressured mount without
/// any surface.
fn injected_table(mounts: &[(&Path, u64, u64, bool)]) -> String {
    let entries = mounts
        .iter()
        .map(|(path, total, free, readonly)| mount_entry(path, *total, *free, *readonly, &[]))
        .collect::<Vec<_>>();
    table_of(&entries)
}

fn table_of(entries: &[String]) -> String {
    format!(r#"{{"mounts":[{}]}}"#, entries.join(","))
}

/// `reason=...` from a `scan_complete` event's details.
fn scan_reason(event: &Value) -> Option<&str> {
    event
        .get("details")?
        .as_str()?
        .split_whitespace()
        .find_map(|kv| kv.strip_prefix("reason="))
}

/// A 1 TB `/` at 50% free that is read-only: Green, no root, no pool, so a
/// scenario's fixture mount is the only actionable surface.
fn quiet_root_mount() -> (&'static Path, u64, u64, bool) {
    (Path::new("/"), 1_000_000_000_000, 500_000_000_000, true)
}

/// Where scratch trees and preserved failure outputs live.
fn scratch_base() -> PathBuf {
    let preferred = PathBuf::from("/data/tmp");
    if preferred.is_dir() {
        preferred
    } else {
        std::env::temp_dir()
    }
}

fn scratch() -> tempfile::TempDir {
    tempfile::tempdir_in(scratch_base()).unwrap()
}

// ──────────────────── scenarios ────────────────────

/// The trivial start/stop scenario the bead's acceptance asks for: the
/// daemon writes a v2 state file, and the final write after SIGTERM records
/// a clean shutdown.
#[test]
fn runner_starts_and_stops_a_daemon() {
    let dir = scratch();
    let fixtures = Fixtures::build(dir.path(), Duration::from_hours(5), 4096);
    let scenario = ScenarioConfig {
        root_paths: vec![fixtures.root],
        ..ScenarioConfig::default()
    };
    let mut run = DaemonRun::spawn(dir.path(), &scenario, None);
    let state = run
        .wait_for_state("first state file", Duration::from_secs(30), |state| {
            state.get("schema_version").and_then(Value::as_u64) == Some(2)
        })
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        state
            .get("run_id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty())
    );
    assert_eq!(state["threads"]["monitor"]["status"], "running");
    // Every worker reports through its own heartbeat, the logger included.
    for thread in ["scanner", "executor", "logger"] {
        let record = &state["threads"][thread];
        assert_eq!(record["status"], "running", "{thread}: {record}");
        assert!(
            record["seconds_since_heartbeat"].as_u64().is_some(),
            "{thread}: {record}"
        );
    }

    let stopped = Instant::now();
    let status = run.stop();
    assert!(status.success(), "clean SIGTERM exit, got {status}");
    assert!(
        stopped.elapsed() < Duration::from_secs(10),
        "an idle daemon stops well inside the join budget: {:?}",
        stopped.elapsed()
    );
    let final_state: Value =
        serde_json::from_str(&fs::read_to_string(dir.path().join("data/state.json")).unwrap())
            .unwrap();
    assert_eq!(final_state["exit_reason"], "clean shutdown");
    assert!(final_state["stopped_at"].as_str().is_some());
    let stderr = fs::read_to_string(dir.path().join("daemon.stderr")).unwrap();
    assert!(stderr.contains("shutdown complete"), "{stderr}");

    // `sbh status` right after a clean stop: not running, the state file is
    // fresh (no stale flag), and the daemon block says why it stopped.
    let status = Command::new(common::sbh_bin_path())
        .arg("--config")
        .arg(dir.path().join("config.toml"))
        .args(["--json", "status"])
        .env_remove("SBH_TEST_MODE")
        .output()
        .expect("run sbh status");
    let payload: Value = serde_json::from_str(String::from_utf8_lossy(&status.stdout).trim())
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&status.stdout)));
    assert_eq!(payload["daemon_running"], false, "{payload}");
    assert_eq!(payload["state_stale"], false, "{payload}");
    assert_eq!(
        payload["daemon"]["exit_reason"], "clean shutdown",
        "{payload}"
    );
    assert!(
        payload["daemon"]["stopped_at"].as_str().is_some(),
        "{payload}"
    );
}

/// A daemon that exits at once, or never writes a state file, fails the
/// runner instead of passing vacuously.
#[test]
fn runner_fails_on_silent_daemon() {
    let dir = scratch();
    // A config the daemon refuses: an unknown key under strict mode.
    let data = dir.path().join("data");
    fs::create_dir_all(&data).unwrap();
    fs::write(
        dir.path().join("config.toml"),
        format!(
            "[core]\nstrict_config = true\nno_such_key = 1\n[paths]\nstate_file = {:?}\n",
            data.join("state.json").display().to_string()
        ),
    )
    .unwrap();
    let stderr = fs::File::create(dir.path().join("daemon.stderr")).unwrap();
    let child = Command::new(common::sbh_bin_path())
        .arg("--config")
        .arg(dir.path().join("config.toml"))
        .arg("daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()
        .unwrap();
    let mut run = DaemonRun {
        child,
        config_path: dir.path().join("config.toml"),
        data_dir: data,
        stderr_path: dir.path().join("daemon.stderr"),
        started: Instant::now(),
    };
    let outcome = run.wait_for_state(
        "a state file from a refusing daemon",
        Duration::from_secs(20),
        |_| true,
    );
    match outcome {
        Err(RunnerError::Exited(status, _)) => assert!(!status.success()),
        Err(RunnerError::Timeout(_)) => {}
        Ok(state) => panic!("a refusing daemon must not produce a state file: {state}"),
    }
}

/// Injected statistics never drive a managed daemon: with `SBH_TEST_MODE=1`
/// and a service-manager marker in the environment, `sbh daemon` refuses to
/// start and says why.
#[test]
fn test_mode_daemon_refuses_to_start_under_a_service_manager() {
    let dir = scratch();
    let scenario = ScenarioConfig::default();
    let config_path = write_config(dir.path(), &scenario);
    let output = Command::new(common::sbh_bin_path())
        .arg("--config")
        .arg(&config_path)
        .arg("daemon")
        .env("SBH_TEST_MODE", "1")
        .env("SBH_TEST_FS_STATS", r#"{"mounts":[]}"#)
        .env("INVOCATION_ID", "e2e-fake-unit")
        .output()
        .expect("run sbh daemon");
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("service manager") && stderr.contains("INVOCATION_ID"),
        "{stderr}"
    );
    assert!(
        !dir.path().join("data/state.json").exists(),
        "a refused daemon writes no state"
    );
}

/// The operator-host layout on a single-filesystem runner: `/` is Orange
/// with no root, no pool (read-only) and nothing sbh can act on, while the
/// fixture mount is Green with a configured root. The v0.5.1 daemon backed
/// off entirely in this layout. Now `/` must be observe-only
/// (idle_reason no_root_path_on_device) and the Green mount must keep its
/// maintenance cadence: a maintenance pass reclaims the stale Definite
/// target while the fresh target and the git project survive.
#[test]
fn injected_orange_mount_reclaims_only_the_stale_target() {
    let dir = scratch();
    let fixtures = Fixtures::build(dir.path(), Duration::from_hours(5), 64 * 1024);
    // The daemon polls its configured roots plus `/`, so the rootless
    // pressured mount is `/` itself; the fixture directory is its own mount.
    // 1 TB volumes: 11% free is Orange yet far above the 32 GiB
    // special-location floor, so /tmp and friends stay quiet.
    let rootless = PathBuf::from("/");
    let fixture_mount = dir.path().to_path_buf();
    let table = injected_table(&[
        (&fixture_mount, 1_000_000_000_000, 550_000_000_000, false),
        (&rootless, 1_000_000_000_000, 110_000_000_000, true),
    ]);
    let scenario = ScenarioConfig {
        root_paths: vec![fixtures.root.clone()],
        // The stale fixture's mtimes are five hours old but its directory
        // was just created; one minute is the shortest honest gate.
        min_file_age_minutes: 1,
        maintenance_interval_secs: 5,
        ..ScenarioConfig::default()
    };
    let mut run = DaemonRun::spawn(dir.path(), &scenario, Some(&table));

    // The first state write happens before the controllers exist; the next
    // one follows the 30 s state write interval, so allow several intervals.
    let state = run
        .wait_for_state(
            "per-mount controller states",
            Duration::from_secs(120),
            |state| {
                state["mount_controllers"]
                    .as_array()
                    .is_some_and(|controllers| {
                        controllers
                            .iter()
                            .any(|c| c["mount"] == rootless.to_string_lossy().as_ref())
                            && controllers
                                .iter()
                                .any(|c| c["mount"] == fixture_mount.to_string_lossy().as_ref())
                    })
            },
        )
        .unwrap_or_else(|e| panic!("{e}"));
    let controllers = state["mount_controllers"].as_array().unwrap();
    let rootless_state = controllers
        .iter()
        .find(|c| c["mount"] == rootless.to_string_lossy().as_ref())
        .unwrap();
    assert_eq!(rootless_state["state"], "observe_only", "{rootless_state}");
    assert_eq!(rootless_state["idle_reason"], "no_root_path_on_device");
    assert_eq!(rootless_state["level"], "orange");
    let fixture_state = controllers
        .iter()
        .find(|c| c["mount"] == fixture_mount.to_string_lossy().as_ref())
        .unwrap();
    assert_eq!(fixture_state["level"], "green", "{fixture_state}");
    assert_eq!(fixture_state["surface"], "configured", "{fixture_state}");
    assert_ne!(fixture_state["state"], "observe_only", "{fixture_state}");

    // Keep the fresh target fresh while the stale one crosses the age gate.
    let stale_path = fixtures.stale_target.clone();
    run.wait_until(
        "deletion of the stale target",
        Duration::from_secs(150),
        |run| {
            fixtures.touch_fresh();
            run.deleted_paths().iter().any(|p| p == &stale_path)
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));

    let deleted = run.deleted_paths();
    assert!(
        !deleted.iter().any(|p| p == &fixtures.fresh_target),
        "{deleted:?}"
    );
    let maintenance_scans = run
        .events_of("scan_complete")
        .iter()
        .filter(|event| {
            event
                .get("details")
                .and_then(Value::as_str)
                .is_some_and(|d| d.contains("reason=maintenance"))
        })
        .count();
    assert!(
        maintenance_scans >= 1,
        "the reclaim must come from a maintenance pass"
    );
    assert!(fixtures.fresh_target.exists());
    assert!(
        fixtures
            .project_target
            .parent()
            .unwrap()
            .join(".git")
            .exists(),
        "the git project root survives"
    );
    let cpu = run.cpu_ratio().unwrap_or(f64::NAN);
    let _ = writeln!(std::io::stderr(), "host-layout daemon cpu share: {cpu:.4}");
    let status = run.stop();
    assert!(status.success(), "{status}");
    let _ = fs::read_to_string(dir.path().join("daemon.stderr"))
        .map(|s| {
            assert!(s.contains("no_root_path_on_device"), "{s}");
            s
        })
        .unwrap();
    let _ = writeln!(std::io::stderr(), "deleted: {deleted:?}");
}

// ──────────────────── guarded candidates ────────────────────

/// Candidates that must survive a reclaim.
///
/// A Definite target with a file
/// held open by this process, a target under an active build lease held by
/// this process, and a symlink to a Definite target outside the root.
pub struct KeepFixtures {
    pub open_target: PathBuf,
    pub leased_target: PathBuf,
    pub link: PathBuf,
    pub link_dest: PathBuf,
    _open: fs::File,
    _lease: ActiveLease,
}

impl KeepFixtures {
    pub fn build(dir: &Path, root: &Path, stale_age: Duration) -> Self {
        let open_target = definite_target(&root.join("open-proj"), stale_age, 4096);
        let open = fs::File::open(
            open_target
                .join("debug")
                .join("deps")
                .join("libfixture.rlib"),
        )
        .unwrap();

        // A lease covers an immediate child of a configured root and is
        // taken before the target exists (it creates the directory), so the
        // leased target is `root/target` itself.
        let lease = ActiveLease::acquire(
            &[root.to_path_buf()],
            &root.join("target"),
            Duration::from_secs(600),
            1 << 30,
        )
        .expect("acquire an active lease");
        let leased_target = definite_target(root, stale_age, 4096);

        let link_dest = definite_target(&dir.join("outside-proj"), stale_age, 4096);
        let link_project = root.join("link-proj");
        fs::create_dir_all(&link_project).unwrap();
        let link = link_project.join("target");
        std::os::unix::fs::symlink(&link_dest, &link).unwrap();

        Self {
            open_target,
            leased_target,
            link,
            link_dest,
            _open: open,
            _lease: lease,
        }
    }

    /// Guarded candidates that are gone (empty when all survived).
    pub fn missing(&self) -> Vec<&Path> {
        let mut missing = Vec::new();
        if !self.open_target.exists() {
            missing.push(self.open_target.as_path());
        }
        if !self.leased_target.exists() {
            missing.push(self.leased_target.as_path());
        }
        if self.link.symlink_metadata().is_err() {
            missing.push(self.link.as_path());
        }
        if !self.link_dest.exists() {
            missing.push(self.link_dest.as_path());
        }
        missing
    }
}

// ──────────────────── privileged fixtures ────────────────────

fn sudo(args: &[&OsStr]) {
    let status = Command::new("sudo")
        .arg("-n")
        .args(args)
        .status()
        .expect("run sudo");
    assert!(
        status.success(),
        "sudo -n {:?} failed: this scenario needs passwordless sudo",
        args.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
    );
}

/// A real ext4 filesystem on a loop-mounted image file, owned by the test
/// user; unmounted on drop. Needs passwordless sudo.
struct LoopMount {
    path: PathBuf,
}

impl LoopMount {
    fn create(dir: &Path, size_mib: u64) -> Self {
        let image = dir.join("volume.img");
        fs::File::create(&image)
            .unwrap()
            .set_len(size_mib * 1024 * 1024)
            .unwrap();
        // No reserved blocks: `available` and `free` agree for an
        // unprivileged owner.
        let status = Command::new("mke2fs")
            .args(["-q", "-F", "-t", "ext4", "-m", "0"])
            .arg(&image)
            .status()
            .expect("run mke2fs");
        assert!(status.success(), "mke2fs failed");
        let path = dir.join("vol");
        fs::create_dir_all(&path).unwrap();
        sudo(&[
            OsStr::new("mount"),
            OsStr::new("-o"),
            OsStr::new("loop"),
            image.as_os_str(),
            path.as_os_str(),
        ]);
        let owner = format!("{}:{}", nix::unistd::getuid(), nix::unistd::getgid());
        sudo(&[OsStr::new("chown"), OsStr::new(&owner), path.as_os_str()]);
        Self { path }
    }

    fn remount(&self, mode: &str) {
        sudo(&[
            OsStr::new("mount"),
            OsStr::new("-o"),
            OsStr::new(&format!("remount,{mode}")),
            self.path.as_os_str(),
        ]);
    }

    /// `(total, available)` bytes as the daemon's own platform layer sees
    /// them.
    fn stats(&self) -> (u64, u64) {
        let platform = storage_ballast_helper::platform::pal::detect_platform().unwrap();
        let stats = platform.fs_stats(&self.path).unwrap();
        (stats.total_bytes, stats.available_bytes)
    }

    /// Write real bytes until `free_pct` percent of the volume is available.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    fn fill_to(&self, free_pct: f64) {
        let (total, available) = self.stats();
        let target = (total as f64 * free_pct / 100.0) as u64;
        let mut remaining = available.saturating_sub(target);
        let mut file = fs::File::create(self.path.join("filler.bin")).unwrap();
        let chunk = vec![0x5Au8; 1024 * 1024];
        while remaining > 0 {
            let n = remaining.min(chunk.len() as u64) as usize;
            file.write_all(&chunk[..n]).unwrap();
            remaining -= n as u64;
        }
        file.sync_all().unwrap();
    }
}

impl Drop for LoopMount {
    fn drop(&mut self) {
        let _ = Command::new("sudo")
            .args(["-n", "umount"])
            .arg(&self.path)
            .status();
    }
}

// ──────────────────── scenario table ────────────────────

/// Orange on the fixture mount: the pool file is released, the stale
/// Definite target is deleted once it clears the age gate, every guarded
/// sibling survives, and each deletion cites a recorded decision. Returns
/// the deleted paths relative to the root so the two engines can be
/// compared.
fn run_orange_reclaim(engine: &'static str) -> Vec<String> {
    let dir = scratch();
    let stale_age = Duration::from_hours(5);
    let fixtures = Fixtures::build(dir.path(), stale_age, 64 * 1024);
    let keep = KeepFixtures::build(dir.path(), &fixtures.root, stale_age);
    let created = Instant::now();
    let fixture_mount = dir.path().to_path_buf();
    // 11% free of 1 TB: Orange, far above the special-location floor.
    let table = injected_table(&[
        (&fixture_mount, 1_000_000_000_000, 110_000_000_000, false),
        quiet_root_mount(),
    ]);
    let scenario = ScenarioConfig {
        root_paths: vec![fixtures.root.clone()],
        min_file_age_minutes: 1,
        engine,
        ..ScenarioConfig::default()
    };
    let mut run = DaemonRun::spawn(dir.path(), &scenario, Some(&table));

    run.wait_until("the ballast release", Duration::from_secs(45), |run| {
        !run.events_of("ballast_release").is_empty()
    })
    .unwrap_or_else(|e| panic!("[{engine}] {e}"));

    // The fixtures were born seconds ago, so the one-minute age gate holds
    // them through the first passes and the mount backs off idle. Once the
    // gate has passed, a forced scan (SIGUSR1) wakes it instead of waiting
    // out the backoff; the reclaim itself is the daemon's own decision.
    let gate = created + Duration::from_secs(66);
    let stale_path = fixtures.stale_target.clone();
    run.wait_until("the age gate", Duration::from_secs(70), |run| {
        fixtures.touch_fresh();
        Instant::now() >= gate || run.deleted_paths().iter().any(|p| p == &stale_path)
    })
    .unwrap_or_else(|e| panic!("[{engine}] {e}"));
    if !run.deleted_paths().iter().any(|p| p == &stale_path) {
        run.signal("-USR1");
    }
    run.wait_until(
        "deletion of the stale target",
        Duration::from_secs(60),
        |run| {
            fixtures.touch_fresh();
            run.deleted_paths().iter().any(|p| p == &stale_path)
        },
    )
    .unwrap_or_else(|e| panic!("[{engine}] {e}"));

    // Every successful deletion cites a decision recorded for the same path.
    let decisions = run.events_of("decision");
    let delete_events: Vec<Value> = run
        .events_of("artifact_delete")
        .into_iter()
        .filter(|e| e.get("ok") != Some(&Value::Bool(false)))
        .collect();
    for delete in &delete_events {
        let id = delete["decision_id"]
            .as_str()
            .unwrap_or_else(|| panic!("[{engine}] artifact_delete without decision_id: {delete}"));
        assert!(
            decisions
                .iter()
                .any(|d| d["decision_id"] == id && d["path"] == delete["path"]),
            "[{engine}] no decision {id} recorded for {}",
            delete["path"]
        );
    }

    assert!(
        fixtures.fresh_target.exists(),
        "[{engine}] fresh target deleted"
    );
    assert!(
        fixtures
            .project_target
            .parent()
            .unwrap()
            .join(".git")
            .exists(),
        "[{engine}] the git project root survives"
    );
    let missing = keep.missing();
    assert!(
        missing.is_empty(),
        "[{engine}] guarded candidates deleted: {missing:?}"
    );
    let deleted = run.deleted_paths();
    for path in &deleted {
        assert!(
            path.starts_with(&fixtures.root),
            "[{engine}] deleted outside the root: {}",
            path.display()
        );
    }

    run.wait_for_state(
        "the fixture mount record",
        Duration::from_secs(60),
        |state| {
            state["mount_controllers"].as_array().is_some_and(|c| {
                c.iter()
                    .any(|c| c["mount"] == fixture_mount.to_string_lossy().as_ref())
            })
        },
    )
    .unwrap_or_else(|e| panic!("[{engine}] {e}"));
    let record = run.mount_record(&fixture_mount).unwrap();
    assert_eq!(record["surface"], "configured", "{record}");
    assert_eq!(record["level"], "orange", "{record}");
    assert!(
        record["state"] == "reclaim" || record["state"] == "idle",
        "[{engine}] {record}"
    );
    let state = run.state().unwrap();
    assert!(
        state["ballast"]["released"].as_u64().unwrap_or(0) >= 1,
        "[{engine}] {}",
        state["ballast"]
    );

    let status = run.stop();
    assert!(status.success(), "[{engine}] {status}");
    let mut names: Vec<String> = deleted
        .iter()
        .map(|p| {
            p.strip_prefix(&fixtures.root)
                .unwrap()
                .display()
                .to_string()
        })
        .collect();
    names.sort();
    names
}

/// Scenario `orange-reclaim` on the default v2 engine.
#[test]
fn orange_reclaim_deletes_the_stale_target_and_keeps_the_guarded_siblings() {
    let deleted = run_orange_reclaim("v2");
    assert!(
        deleted.iter().any(|n| n == "stale-proj/target"),
        "{deleted:?}"
    );
}

/// Scenario `engines`: the v1 rollback engine reclaims exactly what v2
/// reclaims on the same fixtures (both daemons run concurrently).
#[test]
fn engine_v1_reclaims_the_same_set_as_v2_at_orange() {
    let v2 = std::thread::spawn(|| run_orange_reclaim("v2"));
    let v1 = run_orange_reclaim("v1");
    let v2 = v2.join().expect("v2 run");
    assert_eq!(v1, v2, "engine parity");
    assert!(v1.iter().any(|n| n == "stale-proj/target"), "{v1:?}");
}

/// Scenario `red-ballast`: a pool of two on a mount that turns Red after
/// startup; both files are released, each logged once, before the scan
/// the same tick dispatches.
#[test]
fn red_pressure_releases_the_whole_pool_before_scanning() {
    let dir = scratch();
    let fixtures = Fixtures::build(dir.path(), Duration::from_hours(5), 4096);
    let fixture_mount = dir.path().to_path_buf();
    let (root, root_total, root_free, root_ro) = quiet_root_mount();
    // Green for the first 12 s (the pool provisions at startup), then 8%:
    // Red, between the 6% red floor and the 10% orange line.
    let table = table_of(&[
        mount_entry(
            &fixture_mount,
            1_000_000_000_000,
            500_000_000_000,
            false,
            &[(12, 80_000_000_000)],
        ),
        mount_entry(root, root_total, root_free, root_ro, &[]),
    ]);
    let scenario = ScenarioConfig {
        root_paths: vec![fixtures.root],
        ballast_files: 2,
        ..ScenarioConfig::default()
    };
    let mut run = DaemonRun::spawn(dir.path(), &scenario, Some(&table));
    run.wait_until(
        "two provisioned ballast files",
        Duration::from_secs(30),
        |run| run.events_of("ballast_provision").len() == 2,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    run.wait_until(
        "both ballast files released",
        Duration::from_secs(60),
        |run| run.events_of("ballast_release").len() >= 2,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    run.wait_until(
        "the scan after the release",
        Duration::from_secs(30),
        |run| {
            let events = run.events();
            let last_release = events.iter().rposition(|e| e["event"] == "ballast_release");
            last_release.is_some_and(|i| {
                events[i..]
                    .iter()
                    .any(|e| e["event"] == "scan_complete" && scan_reason(e) != Some("maintenance"))
            })
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));

    let events = run.events();
    let releases: Vec<&Value> = events
        .iter()
        .filter(|e| e["event"] == "ballast_release")
        .collect();
    assert_eq!(releases.len(), 2, "each file released once: {releases:?}");
    assert_ne!(releases[0]["path"], releases[1]["path"], "{releases:?}");
    let second_release = events
        .iter()
        .rposition(|e| e["event"] == "ballast_release")
        .unwrap();
    let first_release = events
        .iter()
        .position(|e| e["event"] == "ballast_release")
        .unwrap();
    let scans_between = events[first_release..second_release]
        .iter()
        .filter(|e| e["event"] == "scan_complete")
        .count();
    assert_eq!(
        scans_between, 0,
        "ballast is released before any scan: {events:?}"
    );

    let state = run
        .wait_for_state(
            "red state with the pool released",
            Duration::from_secs(60),
            |state| state["ballast"]["released"] == 2,
        )
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(state["ballast"]["available"], 0, "{}", state["ballast"]);
    let record = run.mount_record(&fixture_mount).unwrap();
    assert_eq!(record["level"], "red", "{record}");
    let status = run.stop();
    assert!(status.success(), "{status}");
}

/// Scenario `forced-scan`: SIGUSR1 at Green produces a forced
/// `scan_complete` within two seconds and deletes nothing behind the
/// default age gate.
#[test]
fn sigusr1_forces_a_green_scan_within_two_seconds() {
    let dir = scratch();
    let fixtures = Fixtures::build(dir.path(), Duration::from_hours(5), 4096);
    let fixture_mount = dir.path().to_path_buf();
    let table = injected_table(&[
        (&fixture_mount, 1_000_000_000_000, 500_000_000_000, false),
        quiet_root_mount(),
    ]);
    let scenario = ScenarioConfig {
        root_paths: vec![fixtures.root],
        ..ScenarioConfig::default()
    };
    let mut run = DaemonRun::spawn(dir.path(), &scenario, Some(&table));
    run.wait_until("the daemon start event", Duration::from_secs(30), |run| {
        !run.events_of("daemon_start").is_empty()
    })
    .unwrap_or_else(|e| panic!("{e}"));
    std::thread::sleep(Duration::from_secs(3));
    let forced = |run: &DaemonRun| {
        run.events_of("scan_complete")
            .iter()
            .filter(|e| scan_reason(e) == Some("forced"))
            .count()
    };
    let before = forced(&run);
    let sent = Instant::now();
    run.signal("-USR1");
    run.wait_until("a forced scan_complete", Duration::from_secs(10), |run| {
        forced(run) > before
    })
    .unwrap_or_else(|e| panic!("{e}"));
    let latency = sent.elapsed();
    assert!(
        latency <= Duration::from_secs(2),
        "forced scan completed after {latency:?}"
    );
    assert_eq!(run.stderr_count("forced scan triggered (SIGUSR1)"), 1);
    assert!(run.deleted_paths().is_empty(), "{:?}", run.deleted_paths());
    let status = run.stop();
    assert!(status.success(), "{status}");
}

/// Scenario `reload`: SIGHUP with a new root in the config file logs the
/// reload and the matrix, and the new root's stale target is reclaimed by
/// the next maintenance pass.
#[test]
fn sighup_reload_scans_the_new_root_and_relogs_the_matrix() {
    let dir = scratch();
    let root_a = dir.path().join("root");
    fs::create_dir_all(&root_a).unwrap();
    let fixture_mount = dir.path().to_path_buf();
    let table = injected_table(&[
        (&fixture_mount, 1_000_000_000_000, 500_000_000_000, false),
        quiet_root_mount(),
    ]);
    let mut scenario = ScenarioConfig {
        root_paths: vec![root_a],
        min_file_age_minutes: 0,
        maintenance_interval_secs: 5,
        ..ScenarioConfig::default()
    };
    let mut run = DaemonRun::spawn(dir.path(), &scenario, Some(&table));
    run.wait_until("the daemon start event", Duration::from_secs(30), |run| {
        !run.events_of("daemon_start").is_empty()
    })
    .unwrap_or_else(|e| panic!("{e}"));

    // A second root with a stale Definite target exists only in the new config.
    let root_b = dir.path().join("root-b");
    let late_target = definite_target(&root_b.join("late-proj"), Duration::from_hours(5), 4096);
    scenario.root_paths.push(root_b);
    // A `[behavior]` change is what makes the daemon re-log its matrix.
    scenario.extra_toml = "[behavior]\nmemory_never_reduces_cleanup = false\n".to_string();
    write_config(dir.path(), &scenario);
    run.signal("-HUP");
    run.wait_until("the config_reload event", Duration::from_secs(15), |run| {
        !run.events_of("config_reload").is_empty()
    })
    .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        run.events_of("info").iter().any(|e| {
            e["details"]
                .as_str()
                .is_some_and(|d| d.starts_with("config_reload:"))
        }),
        "the behavior matrix is re-logged on reload"
    );
    assert_eq!(run.stderr_count("config reloaded successfully"), 1);
    run.wait_until(
        "deletion of the late target",
        Duration::from_secs(40),
        |run| run.deleted_paths().iter().any(|p| p == &late_target),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let status = run.stop();
    assert!(status.success(), "{status}");
}

/// Scenario `special-location-horizon`: the operator host's 5.5 TiB `/` at
/// 13.9% free carries /tmp; with no consumption its horizon is infinite,
/// so a minute of polling raises no special-location alert. The daemon's
/// CPU share over that idle minute is reported alongside.
#[test]
fn special_locations_stay_quiet_at_fourteen_percent_of_a_large_volume() {
    let dir = scratch();
    let fixtures = Fixtures::build(dir.path(), Duration::from_hours(5), 4096);
    let fixture_mount = dir.path().to_path_buf();
    let table = injected_table(&[
        (&fixture_mount, 1_000_000_000_000, 500_000_000_000, false),
        (Path::new("/"), 6_047_313_952_768, 840_576_639_434, true),
    ]);
    let scenario = ScenarioConfig {
        root_paths: vec![fixtures.root],
        ..ScenarioConfig::default()
    };
    let mut run = DaemonRun::spawn(dir.path(), &scenario, Some(&table));
    let root = PathBuf::from("/");
    run.wait_for_state("the root mount record", Duration::from_secs(120), |state| {
        state["mount_controllers"]
            .as_array()
            .is_some_and(|c| c.iter().any(|c| c["mount"] == "/"))
    })
    .unwrap_or_else(|e| panic!("{e}"));
    run.wait_until("a minute of polling", Duration::from_secs(90), |run| {
        run.started.elapsed() >= Duration::from_secs(60)
    })
    .unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(run.stderr_count("[SBH-SPECIAL]"), 0, "{}", run.stderr());
    let alerts: Vec<Value> = run
        .events()
        .into_iter()
        .filter(|e| serde_json::to_string(e).unwrap().contains("SBH-2001"))
        .collect();
    assert!(alerts.is_empty(), "{alerts:?}");
    let record = run.mount_record(&root).unwrap();
    assert_eq!(record["level"], "orange", "{record}");
    assert_eq!(record["idle_reason"], "no_root_path_on_device", "{record}");
    let cpu = run.cpu_ratio().unwrap();
    let _ = writeln!(std::io::stderr(), "idle daemon cpu share: {cpu:.4}");
    assert!(cpu < 0.02, "idle daemon used {cpu:.4} of a CPU");
    let status = run.stop();
    assert!(status.success(), "{status}");
}

/// Scenario `partial-provision` (privileged): a real 128 MiB ext4 volume at
/// 22% free with the default 10% floor takes three 4 MiB ballast files of
/// the five configured; the fourth would cross the floor.
#[test]
#[ignore = "needs passwordless sudo for a loop-mounted ext4 image; run with --ignored"]
fn partial_provision_stops_the_pool_at_the_headroom_floor() {
    let dir = scratch();
    let vol = LoopMount::create(dir.path(), 128);
    vol.fill_to(22.0);
    let root = vol.path.join("root");
    fs::create_dir_all(&root).unwrap();
    let scenario = ScenarioConfig {
        root_paths: vec![root],
        ballast_files: 5,
        ballast_file_bytes: 4 * 1024 * 1024,
        ..ScenarioConfig::default()
    };
    let mut run = DaemonRun::spawn(dir.path(), &scenario, None);
    let volume = format!("volume={}", vol.path.display());
    run.wait_until(
        "the provision report for the volume",
        Duration::from_secs(60),
        |run| {
            run.stderr()
                .lines()
                .any(|l| l.contains(&volume) && l.contains("skipped_for_floor="))
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let report = run
        .stderr()
        .lines()
        .find(|l| l.contains(&volume) && l.contains("skipped_for_floor="))
        .unwrap()
        .to_string();
    assert!(report.contains("created=3 skipped_for_floor=2"), "{report}");
    let pool = vol.path.join(".sbh").join("ballast");
    let provisioned = run
        .events_of("ballast_provision")
        .iter()
        .filter(|e| {
            e["path"]
                .as_str()
                .is_some_and(|p| p.starts_with(&*pool.to_string_lossy()))
        })
        .count();
    assert_eq!(provisioned, 3, "{}", run.stderr());
    let status = run.stop();
    assert!(status.success(), "{status}");
}

/// Scenario `read-only` (privileged): a volume that turns read-only after
/// the pool exists parks its mount in Recovery on the first refused
/// deletion, with an error event and a notification; nothing is retried
/// while it stays read-only; after the remount the mount leaves Recovery
/// and every stale target is reclaimed.
#[test]
#[ignore = "needs passwordless sudo for a loop-mounted ext4 image; run with --ignored"]
fn read_only_volume_parks_deletions_in_recovery_until_remount() {
    let dir = scratch();
    let vol = LoopMount::create(dir.path(), 128);
    let root = vol.path.join("root");
    let targets: Vec<PathBuf> = ["a", "b", "c"]
        .iter()
        .map(|n| {
            definite_target(
                &root.join(format!("{n}-proj")),
                Duration::from_hours(5),
                4096,
            )
        })
        .collect();
    let notify = dir.path().join("notify.jsonl");
    let scenario = ScenarioConfig {
        root_paths: vec![root],
        min_file_age_minutes: 1,
        maintenance_interval_secs: 5,
        notify_file: Some(notify.clone()),
        ..ScenarioConfig::default()
    };
    let mut run = DaemonRun::spawn(dir.path(), &scenario, None);
    let pool = vol.path.join(".sbh").join("ballast");
    run.wait_until("the pool on the volume", Duration::from_secs(60), |run| {
        run.events_of("ballast_provision").iter().any(|e| {
            e["path"]
                .as_str()
                .is_some_and(|p| p.starts_with(&*pool.to_string_lossy()))
        })
    })
    .unwrap_or_else(|e| panic!("{e}"));

    vol.remount("ro");
    run.wait_until("the recovery incident", Duration::from_secs(120), |run| {
        run.stderr_count("[SBH-RECOVERY]") >= 1
    })
    .unwrap_or_else(|e| panic!("{e}"));
    let entered = Instant::now();
    let attempts_at_entry = run.events_of("artifact_delete").len();
    assert!(run.deleted_paths().is_empty(), "{:?}", run.deleted_paths());
    assert!(
        run.events_of("error")
            .iter()
            .any(|e| e["error_code"] == "SBH-2004"),
        "{:?}",
        run.events_of("error")
    );
    run.wait_until("the notification", Duration::from_secs(10), |_| {
        fs::read_to_string(&notify)
            .unwrap_or_default()
            .contains("SBH-2004")
    })
    .unwrap_or_else(|e| panic!("{e}"));
    run.wait_for_state(
        "recovery in the state file",
        Duration::from_secs(90),
        |state| {
            state["mount_controllers"].as_array().is_some_and(|c| {
                c.iter().any(|c| {
                    c["mount"] == vol.path.to_string_lossy().as_ref() && c["state"] == "recovery"
                })
            })
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));

    // No retries while read-only: 45 s later there is still one incident
    // and no further deletion attempt.
    run.wait_until("the quiet window", Duration::from_secs(60), |_| {
        entered.elapsed() >= Duration::from_secs(45)
    })
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(run.stderr_count("[SBH-RECOVERY]"), 1, "{}", run.stderr());
    assert_eq!(run.events_of("artifact_delete").len(), attempts_at_entry);
    assert!(run.deleted_paths().is_empty(), "{:?}", run.deleted_paths());

    vol.remount("rw");
    run.wait_until(
        "reclaim after the remount",
        Duration::from_secs(150),
        |run| {
            let deleted = run.deleted_paths();
            targets.iter().all(|t| deleted.contains(t))
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    run.wait_for_state(
        "recovery exit in the state file",
        Duration::from_secs(60),
        |state| {
            state["mount_controllers"].as_array().is_some_and(|c| {
                c.iter().any(|c| {
                    c["mount"] == vol.path.to_string_lossy().as_ref() && c["state"] != "recovery"
                })
            })
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let status = run.stop();
    assert!(status.success(), "{status}");
}

// ──────────────────── CPU budget (Q7) ────────────────────

/// A root with `projects` Definite cargo targets of `files` fresh files
/// each: expensive to walk, nothing to delete.
fn wide_fixture(dir: &Path, projects: usize, files: usize) -> PathBuf {
    let root = dir.join("root");
    for p in 0..projects {
        let target = definite_target(&root.join(format!("proj-{p:04}")), Duration::ZERO, 256);
        let deps = target.join("debug").join("deps");
        for f in 0..files {
            fs::write(deps.join(format!("lib{f:03}.rlib")), b"x").unwrap();
        }
    }
    root
}

/// One daemon over the wide fixture at Green with a one-second maintenance
/// interval on the full-walk v1 engine: `(cpu_secs, wall_secs, exceeded
/// lines, run)`.
fn run_expensive_scanner(cpu_budget_pct: u8, wall: Duration) -> (f64, f64, usize, DaemonRun) {
    let dir = scratch();
    let root = wide_fixture(dir.path(), 300, 40);
    let fixture_mount = dir.path().to_path_buf();
    let table = injected_table(&[
        (&fixture_mount, 1_000_000_000_000, 500_000_000_000, false),
        quiet_root_mount(),
    ]);
    let scenario = ScenarioConfig {
        root_paths: vec![root],
        engine: "v1",
        maintenance_interval_secs: 1,
        duty_cycle_pct: 100,
        cpu_budget_pct,
        ..ScenarioConfig::default()
    };
    let mut run = DaemonRun::spawn(dir.path(), &scenario, Some(&table));
    run.wait_until("the daemon start event", Duration::from_secs(30), |run| {
        !run.events_of("daemon_start").is_empty()
    })
    .unwrap_or_else(|e| panic!("[budget {cpu_budget_pct}] {e}"));
    run.wait_until(
        "the measurement window",
        wall + Duration::from_secs(5),
        |run| run.wall_secs() >= wall.as_secs_f64(),
    )
    .unwrap_or_else(|e| panic!("[budget {cpu_budget_pct}] {e}"));
    let cpu = run.proc_cpu_secs();
    let elapsed = run.wall_secs();
    let exceeded = run.stderr_count("cpu budget exceeded");
    // Keep the scratch dir alive with the run; the caller stops it.
    std::mem::forget(dir);
    (cpu, elapsed, exceeded, run)
}

/// Scenario `cpu-budget`: with the per-pass duty cycle disabled and a
/// deliberately expensive scanner, the daemon-wide budget holds the
/// documented bound `pct/100 * wall + burst`; the same daemon without a
/// budget burns more; the deficit line appears at most once a minute; and
/// `sbh status --json` reports `daemon.cpu_budget`.
#[test]
fn cpu_budget_bounds_an_expensive_scanner_at_green() {
    let window = Duration::from_secs(75);
    let unbudgeted = std::thread::spawn(move || run_expensive_scanner(0, window));
    let (cpu, wall, exceeded, run) = run_expensive_scanner(5, window);
    let (free_cpu, free_wall, free_exceeded, free_run) = unbudgeted.join().expect("unbudgeted run");
    let _ = writeln!(
        std::io::stderr(),
        "cpu budget 5%: {cpu:.2} s over {wall:.1} s ({:.1}%), exceeded lines {exceeded}; \
         unbudgeted: {free_cpu:.2} s over {free_wall:.1} s ({:.1}%)",
        cpu / wall * 100.0,
        free_cpu / free_wall * 100.0
    );

    // The documented bound plus one second for startup and the protected
    // operations (state writes, ballast checks) that share the process.
    let bound = 0.05f64.mul_add(wall, 5.0 + 1.0);
    assert!(
        cpu <= bound,
        "{cpu:.2} s of CPU exceeds the bound {bound:.2} s"
    );
    assert!(
        free_cpu > cpu,
        "the unbudgeted daemon ({free_cpu:.2} s) must burn more than the budgeted one ({cpu:.2} s), \
         or the scanner was not expensive enough to prove anything"
    );
    // The budget acted: passes were cut short as the bucket emptied (they
    // report as timed out), or the daemon went into deficit and said so.
    let cut_short = |run: &DaemonRun| {
        run.events_of("scan_complete")
            .iter()
            .filter(|e| {
                e["details"]
                    .as_str()
                    .is_some_and(|d| d.contains("timed_out=true"))
            })
            .count()
    };
    let deficit_warnings = run
        .events()
        .iter()
        .filter(|e| e["error_code"] == "SBH-3004" && e["severity"] == "warning")
        .count();
    let shortened = cut_short(&run);
    let _ = writeln!(
        std::io::stderr(),
        "cpu budget 5%: {shortened} passes cut short, {deficit_warnings} deficit warnings"
    );
    assert!(
        shortened >= 1 || deficit_warnings >= 1,
        "the budget never acted: no pass cut short and no deficit reported"
    );
    // A deficit is reported at most once a minute, on stderr and as an
    // activity warning; a daemon that never runs dry reports nothing.
    assert!(
        exceeded <= 3,
        "deficit line once per minute at most: {exceeded} in {wall:.0} s"
    );
    if exceeded >= 1 {
        assert!(
            deficit_warnings >= 1,
            "the deficit is also an activity warning"
        );
    }
    assert_eq!(
        free_exceeded, 0,
        "a disabled budget never reports a deficit"
    );
    assert_eq!(
        cut_short(&free_run),
        0,
        "without a budget no pass is cut short inside the 900 s scan budget"
    );

    let status = Command::new(common::sbh_bin_path())
        .arg("--config")
        .arg(&run.config_path)
        .args(["--json", "status"])
        .env_remove("SBH_TEST_MODE")
        .output()
        .expect("run sbh status");
    let payload: Value = serde_json::from_str(String::from_utf8_lossy(&status.stdout).trim())
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&status.stdout)));
    assert_eq!(
        payload["daemon"]["cpu_budget"]["pct"], 5,
        "{}",
        payload["daemon"]
    );
    assert!(
        payload["daemon"]["cpu_budget"]["used_pct_1m"]
            .as_f64()
            .is_some(),
        "{}",
        payload["daemon"]
    );

    assert!(run.stop().success());
    assert!(free_run.stop().success());
}

// ──────────────────── forecast (check --predict) ────────────────────

/// Scenario `check-predict`: an injected mount that loses 25 GB every four
/// seconds gives the daemon a red horizon of a minute or two; `check
/// --predict 30` against the live daemon exits 1 with that forecast, and
/// `sbh status --json` carries the per-mount rates. Once the daemon is
/// gone and its state file has aged past the staleness threshold, the same
/// check exits 0 and reports the forecast as unknown instead of reusing
/// the stale number.
#[test]
fn check_predict_reads_the_daemon_forecast_and_refuses_stale_state() {
    let dir = scratch();
    let fixtures = Fixtures::build(dir.path(), Duration::from_hours(5), 4096);
    let fixture_mount = dir.path().to_path_buf();
    // 1 TB volume: 50% free, falling 2.5% every 4 s (6.25 GB/s) from t=4 s
    // down to 5% (below red) at t=72 s, then holding there.
    let series: Vec<(u64, u64)> = (1..=18)
        .map(|i| (i * 4, 500_000_000_000u64.saturating_sub(i * 25_000_000_000)))
        .collect();
    let (root, root_total, root_free, root_ro) = quiet_root_mount();
    let table = table_of(&[
        mount_entry(
            &fixture_mount,
            1_000_000_000_000,
            500_000_000_000,
            false,
            &series,
        ),
        mount_entry(root, root_total, root_free, root_ro, &[]),
    ]);
    let scenario = ScenarioConfig {
        root_paths: vec![fixtures.root],
        ..ScenarioConfig::default()
    };
    let mut run = DaemonRun::spawn(dir.path(), &scenario, Some(&table));
    let mount_key = fixture_mount.to_string_lossy().into_owned();
    let state = run
        .wait_for_state(
            "a red horizon in the rates",
            Duration::from_secs(150),
            |state| {
                state["rates"][&mount_key]["seconds_to_red"]
                    .as_f64()
                    .is_some()
            },
        )
        .unwrap_or_else(|e| panic!("{e}"));
    let horizon = state["rates"][&mount_key]["seconds_to_red"]
        .as_f64()
        .unwrap();
    let _ = writeln!(std::io::stderr(), "daemon forecast: red in {horizon:.0} s");
    assert!(horizon < 30.0 * 60.0, "{horizon}");

    let check = |args: &[&str]| {
        Command::new(common::sbh_bin_path())
            .arg("--config")
            .arg(&run.config_path)
            .args(args)
            .env("SBH_TEST_MODE", "1")
            .env("SBH_TEST_FS_STATS", &table)
            .env("SBH_OUTPUT_FORMAT", "human")
            .output()
            .expect("run sbh check")
    };
    let path = fixture_mount.to_string_lossy().into_owned();
    let json = check(&["--json", "check", "--predict", "30", &path]);
    let payload: Value = serde_json::from_str(String::from_utf8_lossy(&json.stdout).trim())
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&json.stdout)));
    assert_eq!(json.status.code(), Some(1), "{payload}");
    assert_eq!(payload["status"], "warning", "{payload}");
    assert!(payload["seconds_to_red"].as_f64().is_some(), "{payload}");
    assert!(
        payload["forecast"]["confidence"].as_f64().is_some(),
        "{payload}"
    );
    assert_eq!(payload["exit_code"], 1);
    let human = check(&["check", "--predict", "30", &path]);
    assert_eq!(human.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&human.stdout).contains("predicted red in"),
        "{}",
        String::from_utf8_lossy(&human.stdout)
    );

    let status = check(&["--json", "status"]);
    let status_payload: Value =
        serde_json::from_str(String::from_utf8_lossy(&status.stdout).trim()).unwrap();
    let rates = &status_payload["rates"][&mount_key];
    assert!(
        rates["bytes_per_sec"].as_f64().is_some(),
        "{status_payload}"
    );
    assert!(rates["warming"].as_bool().is_some(), "{status_payload}");

    // Dead daemon, aged state: no forecast, no number, exit 0.
    assert!(run.stop().success());
    let state_path = dir.path().join("data/state.json");
    let old = SystemTime::now() - Duration::from_secs(600);
    filetime::set_file_mtime(&state_path, filetime::FileTime::from_system_time(old)).unwrap();
    let stale_check = Command::new(common::sbh_bin_path())
        .arg("--config")
        .arg(dir.path().join("config.toml"))
        .args(["--json", "check", "--predict", "30", &path])
        .env("SBH_TEST_MODE", "1")
        .env("SBH_TEST_FS_STATS", &table)
        .output()
        .expect("run sbh check");
    let stale_payload: Value =
        serde_json::from_str(String::from_utf8_lossy(&stale_check.stdout).trim()).unwrap();
    assert_eq!(stale_check.status.code(), Some(0), "{stale_payload}");
    assert!(
        stale_payload["forecast"]
            .as_str()
            .is_some_and(|s| s.contains("stale")),
        "{stale_payload}"
    );
}
