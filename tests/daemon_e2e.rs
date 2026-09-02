//! Real-daemon end-to-end runner (W10, bd-rc-master-ajg1.11.1).
//!
//! Spawns the built `sbh` binary as a daemon against a temporary config,
//! optionally with injected filesystem statistics (`SBH_TEST_MODE=1` +
//! `SBH_TEST_FS_STATS`), captures stderr, the JSONL activity log and
//! `state.json`, polls with deadlines, and kills the daemon on timeout. A
//! scenario that never sees a state file fails; nothing here passes
//! vacuously.

mod common;

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use serde_json::Value;

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
    pub cross_devices: bool,
    pub catalog_roots: bool,
    pub thresholds: (f64, f64, f64, f64),
    pub ballast_files: usize,
}

impl Default for ScenarioConfig {
    fn default() -> Self {
        Self {
            root_paths: Vec::new(),
            poll_interval_ms: 500,
            min_file_age_minutes: 30,
            maintenance_interval_secs: 1800,
            cross_devices: false,
            catalog_roots: false,
            thresholds: (20.0, 14.0, 10.0, 6.0),
            // The config refuses a zero-file pool; one 1 MiB file is the
            // smallest reserve the daemon accepts.
            ballast_files: 1,
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
    let config = format!(
        r#"[paths]
ballast_dir = {ballast:?}
jsonl_log = {jsonl:?}
sqlite_db = {sqlite:?}
state_file = {state:?}
[ballast]
file_count = {ballast_files}
file_size_bytes = 1048576
[pressure]
poll_interval_ms = {poll}
maintenance_interval_secs = {maint}
green_min_free_pct = {green}
yellow_min_free_pct = {yellow}
orange_min_free_pct = {orange}
red_min_free_pct = {red}
[scanner]
cross_devices = {cross}
catalog_roots_on_pressured_device = {catalog}
root_paths = [{roots}]
min_file_age_minutes = {min_age}
max_depth = 6
parallelism = 2
[notifications]
enabled = false
"#,
        ballast = data.join("ballast").display().to_string(),
        jsonl = data.join("activity.jsonl").display().to_string(),
        sqlite = data.join("activity.sqlite3").display().to_string(),
        state = data.join("state.json").display().to_string(),
        ballast_files = scenario.ballast_files,
        poll = scenario.poll_interval_ms,
        maint = scenario.maintenance_interval_secs,
        cross = scenario.cross_devices,
        catalog = scenario.catalog_roots,
        roots = roots,
        min_age = scenario.min_file_age_minutes,
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

    /// Paths the daemon deleted so far.
    pub fn deleted_paths(&self) -> Vec<PathBuf> {
        self.events_of("artifact_delete")
            .iter()
            .filter_map(|event| event.get("path").and_then(Value::as_str))
            .map(PathBuf::from)
            .collect()
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
                return Err(RunnerError::Timeout(format!(
                    "{what} after {:?}; stderr tail:\n{}",
                    self.started.elapsed(),
                    self.stderr_tail()
                )));
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
                return Err(RunnerError::Timeout(format!(
                    "{what} after {:?}; stderr tail:\n{}",
                    self.started.elapsed(),
                    self.stderr_tail()
                )));
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

/// JSON mount table: `(path, total, free, readonly)`. A read-only mount gets
/// no ballast pool, which is how a scenario keeps a pressured mount without
/// any surface.
fn injected_table(mounts: &[(&Path, u64, u64, bool)]) -> String {
    let entries = mounts
        .iter()
        .map(|(path, total, free, readonly)| {
            format!(
                r#"{{"path":{:?},"fs_type":"ext4","total":{total},"free":{free},"readonly":{readonly}}}"#,
                path.display().to_string()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(r#"{{"mounts":[{entries}]}}"#)
}

fn scratch() -> tempfile::TempDir {
    tempfile::tempdir_in("/data/tmp")
        .or_else(|_| tempfile::tempdir())
        .unwrap()
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
        root_paths: vec![fixtures.root.clone()],
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
    assert!(state["threads"]["monitor"]["status"] == "running");

    let status = run.stop();
    assert!(status.success(), "clean SIGTERM exit, got {status}");
    let final_state: Value =
        serde_json::from_str(&fs::read_to_string(dir.path().join("data/state.json")).unwrap())
            .unwrap();
    assert_eq!(final_state["exit_reason"], "clean shutdown");
    assert!(final_state["stopped_at"].as_str().is_some());
    let stderr = fs::read_to_string(dir.path().join("daemon.stderr")).unwrap();
    assert!(stderr.contains("shutdown complete"), "{stderr}");
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
    let stale = fixtures.stale_target.clone();
    run.wait_until(
        "deletion of the stale target",
        Duration::from_secs(150),
        |run| {
            fixtures.touch_fresh();
            run.deleted_paths().iter().any(|p| p == &stale)
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
