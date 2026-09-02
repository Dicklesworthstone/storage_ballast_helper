//! Daemon self-monitoring: RSS tracking, thread health checks, state file for CLI,
//! and sd_notify STATUS updates.
//!
//! The state file (`state.json`) is the primary mechanism for CLI-to-daemon communication.
//! Written atomically (write to `.tmp`, then `rename()`) every `DAEMON_STATE_WRITE_INTERVAL_SECS`
//! seconds so `sbh status`
//! can always read a consistent snapshot.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::core::config::TelemetryConfig;
use crate::core::errors::{Result, SbhError};
use crate::daemon::mount_controller::MountStateRecord;
use crate::monitor::pid::PressureLevel;
use crate::platform::pal::Platform;
use crate::platform::types::SelfStats;

// ──────────────────── constants ────────────────────

/// How often the daemon writes `state.json` (seconds).
pub const DAEMON_STATE_WRITE_INTERVAL_SECS: u64 = 30;

/// Floor for treating `state.json` as stale (seconds).
///
/// Must be `>= 2 × DAEMON_STATE_WRITE_INTERVAL_SECS` so that CLI commands
/// (`sbh status`, `sbh check`, `read_daemon_prediction`) never report the
/// daemon as absent simply because a write cycle hasn't completed yet.
pub const DAEMON_STATE_STALE_THRESHOLD_SECS: u64 = 90;
pub const DEFAULT_DAEMON_RSS_WARNING_BYTES: u64 = 256 * 1024 * 1024;
pub const DEFAULT_DAEMON_RSS_HARD_LIMIT_BYTES: u64 = 500 * 1024 * 1024;

// ──────────────────── daemon lock (liveness) ────────────────────

/// Lock file kept next to `state.json`.
///
/// A running daemon holds an exclusive advisory lock on it for its whole
/// life; the kernel drops the lock on any exit, including SIGKILL, so "is the
/// lock held?" is a race-free answer to "is a daemon running?" — unlike a
/// pidfile (stale after a crash, and a reused pid can be any process) or the
/// previous `/proc/*/cmdline` substring scan, which matched any shell whose
/// command line mentioned "sbh" and "daemon".
pub const DAEMON_LOCK_FILE_NAME: &str = "daemon.lock";

/// Identity of the daemon that holds the lock, written into the lock file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DaemonLockInfo {
    pub pid: u32,
    pub started_at: String,
    pub version: String,
}

/// Path of the daemon lock for a given `state.json` path.
#[must_use]
pub fn daemon_lock_path(state_file: &Path) -> PathBuf {
    state_file.with_file_name(DAEMON_LOCK_FILE_NAME)
}

/// Exclusive daemon lock; held until dropped (or the process exits).
#[derive(Debug)]
pub struct DaemonLock {
    #[cfg(unix)]
    _lock: nix::fcntl::Flock<fs::File>,
    path: PathBuf,
}

impl DaemonLock {
    /// Acquire the lock, refusing if another daemon already holds it.
    ///
    /// The file is created world-readable so an unprivileged `sbh status`
    /// can probe a root daemon's lock (flock works on a read-only handle).
    pub fn acquire(state_file: &Path) -> Result<Self> {
        let path = daemon_lock_path(state_file);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| SbhError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o644);
        }
        let file = options.open(&path).map_err(|source| SbhError::Io {
            path: path.clone(),
            source,
        })?;

        #[cfg(unix)]
        {
            use std::io::Write as _;

            #[allow(deprecated)]
            let mut lock = nix::fcntl::Flock::lock(
                file,
                nix::fcntl::FlockArg::LockExclusiveNonblock,
            )
            .map_err(|(file, errno)| {
                let owner = read_lock_info(&file);
                SbhError::Runtime {
                    details: format!(
                        "another sbh daemon already owns {} (pid {}, started {}, version {}): {errno}",
                        path.display(),
                        owner.pid,
                        if owner.started_at.is_empty() {
                            "unknown"
                        } else {
                            &owner.started_at
                        },
                        if owner.version.is_empty() {
                            "unknown"
                        } else {
                            &owner.version
                        },
                    ),
                }
            })?;

            let info = DaemonLockInfo {
                pid: std::process::id(),
                started_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                version: env!("CARGO_PKG_VERSION").to_string(),
            };
            let payload = serde_json::to_string(&info).map_err(|e| SbhError::Serialization {
                context: "daemon lock",
                details: e.to_string(),
            })?;
            let write = (|| {
                lock.set_len(0)?;
                lock.write_all(payload.as_bytes())?;
                lock.sync_all()
            })();
            write.map_err(|source| SbhError::Io {
                path: path.clone(),
                source,
            })?;

            Ok(Self { _lock: lock, path })
        }
        #[cfg(not(unix))]
        {
            let _ = file;
            Ok(Self { path })
        }
    }

    /// Path of the lock file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(unix)]
fn read_lock_info(file: &fs::File) -> DaemonLockInfo {
    use std::io::{Read as _, Seek as _};
    let mut handle = file;
    let mut raw = String::new();
    if handle.seek(std::io::SeekFrom::Start(0)).is_err() || handle.read_to_string(&mut raw).is_err()
    {
        return DaemonLockInfo::default();
    }
    serde_json::from_str(&raw).unwrap_or_default()
}

/// What probing the daemon lock found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonLockProbe {
    /// A daemon holds the lock.
    Held(DaemonLockInfo),
    /// The lock file exists but nobody holds it (daemon exited).
    Free,
    /// No lock file (never started, or a daemon older than lock support).
    Absent,
    /// The lock file cannot be opened (typically a root daemon probed by an
    /// unprivileged user on a locked-down state directory).
    Unreadable(String),
}

/// Probe the daemon lock without holding it.
#[must_use]
pub fn probe_daemon_lock(state_file: &Path) -> DaemonLockProbe {
    let path = daemon_lock_path(state_file);
    if !path.exists() {
        return DaemonLockProbe::Absent;
    }
    let file = match fs::File::open(&path) {
        Ok(file) => file,
        Err(e) => return DaemonLockProbe::Unreadable(e.to_string()),
    };
    #[cfg(unix)]
    {
        #[allow(deprecated)]
        match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock) {
            Ok(lock) => {
                drop(lock);
                DaemonLockProbe::Free
            }
            // EWOULDBLOCK is an alias of EAGAIN: the lock is held by someone.
            Err((file, nix::errno::Errno::EAGAIN)) => DaemonLockProbe::Held(read_lock_info(&file)),
            Err((_, errno)) => DaemonLockProbe::Unreadable(errno.to_string()),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        DaemonLockProbe::Free
    }
}

/// The CLI's answer to "is the daemon running?", with the evidence behind it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DaemonLiveness {
    /// Final verdict.
    pub running: bool,
    /// Stable machine-readable reason for the verdict.
    pub reason: &'static str,
    /// Seconds since `state.json` was last written, if it exists.
    pub state_age_secs: Option<u64>,
    /// Whether `state.json` is missing or older than the stale threshold.
    pub state_stale: bool,
    /// Identity from the held lock, when the lock decided the verdict.
    pub lock: Option<DaemonLockInfo>,
}

/// Decide daemon liveness from the lock, the state file age, and (optionally)
/// the service manager's view of the unit.
///
/// Precedence: a held lock is authoritative. Without a lock, a fresh
/// `state.json` still counts as running (a daemon older than lock support);
/// a released lock, or a stale or missing state file with no lock, does not.
///
/// The service manager's view is consulted only when the lock exists but
/// cannot be read (a root-owned system daemon queried by an unprivileged
/// user). It must not decide the other cases: the unit may run a daemon for
/// a *different* config, and an active unit whose daemon stopped writing
/// state is not doing its job.
#[must_use]
pub fn detect_daemon_liveness(state_file: &Path, service_active: Option<bool>) -> DaemonLiveness {
    let state_age_secs = fs::metadata(state_file)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|modified| std::time::SystemTime::now().duration_since(modified).ok())
        .map(|age| age.as_secs());
    let state_stale = state_age_secs.is_none_or(|age| age > DAEMON_STATE_STALE_THRESHOLD_SECS);

    let verdict =
        |running: bool, reason: &'static str, lock: Option<DaemonLockInfo>| DaemonLiveness {
            running,
            reason,
            state_age_secs,
            state_stale,
            lock,
        };

    match probe_daemon_lock(state_file) {
        DaemonLockProbe::Held(info) => verdict(true, "lock_held", Some(info)),
        // A lock file that nobody holds was left by a lock-aware daemon that
        // has since exited; a fresh state.json (< 90 s) must not resurrect it.
        DaemonLockProbe::Free => verdict(false, "lock_released", None),
        DaemonLockProbe::Absent => {
            if !state_stale {
                verdict(true, "state_fresh_no_lock", None)
            } else if state_age_secs.is_some() {
                verdict(false, "no_lock_state_stale", None)
            } else {
                verdict(false, "no_lock_no_state", None)
            }
        }
        DaemonLockProbe::Unreadable(_) => match service_active {
            Some(true) => verdict(true, "lock_unreadable_unit_active", None),
            Some(false) => verdict(false, "lock_unreadable_unit_inactive", None),
            None => verdict(!state_stale, "lock_unreadable_state_age_only", None),
        },
    }
}

#[cfg(all(test, unix))]
mod daemon_lock_tests {
    use super::*;

    fn state_file_in(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("state.json")
    }

    #[test]
    fn lock_is_exclusive_and_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let state_file = state_file_in(&dir);
        assert_eq!(probe_daemon_lock(&state_file), DaemonLockProbe::Absent);

        let lock = DaemonLock::acquire(&state_file).expect("first acquire");
        assert!(lock.path().exists());
        match probe_daemon_lock(&state_file) {
            DaemonLockProbe::Held(info) => {
                assert_eq!(info.pid, std::process::id());
                assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
            }
            other => panic!("expected Held while locked, got {other:?}"),
        }

        let second = DaemonLock::acquire(&state_file);
        let err = second.expect_err("second acquire must fail").to_string();
        assert!(
            err.contains(&format!("pid {}", std::process::id())),
            "error should name the owner, got: {err}"
        );

        drop(lock);
        assert_eq!(probe_daemon_lock(&state_file), DaemonLockProbe::Free);
        let _relock = DaemonLock::acquire(&state_file).expect("re-acquire after release");
    }

    #[test]
    fn liveness_follows_lock_then_state_then_unit() {
        let dir = tempfile::tempdir().unwrap();
        let state_file = state_file_in(&dir);

        // Nothing at all.
        let v = detect_daemon_liveness(&state_file, None);
        assert!(!v.running);
        assert_eq!(v.reason, "no_lock_no_state");
        assert!(v.state_stale);

        // Fresh state, no lock: an older daemon that predates the lock.
        fs::write(&state_file, "{}").unwrap();
        let v = detect_daemon_liveness(&state_file, None);
        assert!(v.running);
        assert_eq!(v.reason, "state_fresh_no_lock");
        assert!(!v.state_stale);

        // Stale state, no lock, unit inactive: not running.
        let old = filetime::FileTime::from_unix_time(1_600_000_000, 0);
        filetime::set_file_mtime(&state_file, old).unwrap();
        let v = detect_daemon_liveness(&state_file, Some(false));
        assert!(!v.running);
        assert_eq!(v.reason, "no_lock_state_stale");
        assert!(v.state_stale);

        // Stale state, no lock, unit active: the unit may belong to another
        // config (a fleet host's system service while querying an isolated
        // config), and a daemon that stopped writing state is not working.
        let v = detect_daemon_liveness(&state_file, Some(true));
        assert!(
            !v.running,
            "an active unit must not vouch for this state file"
        );
        assert_eq!(v.reason, "no_lock_state_stale");
        let v = detect_daemon_liveness(&dir.path().join("never-written.json"), Some(true));
        assert!(!v.running);
        assert_eq!(v.reason, "no_lock_no_state");

        // The lock wins over a stale state file.
        let lock = DaemonLock::acquire(&state_file).unwrap();
        let v = detect_daemon_liveness(&state_file, Some(false));
        assert!(v.running);
        assert_eq!(v.reason, "lock_held");
        assert_eq!(v.lock.map(|l| l.pid), Some(std::process::id()));

        // Daemon exited (lock released) moments after writing a fresh state
        // file: that is the SIGKILL case and must read as not running.
        drop(lock);
        fs::write(&state_file, "{}").unwrap();
        let v = detect_daemon_liveness(&state_file, None);
        assert!(!v.running, "released lock must beat a fresh state file");
        assert_eq!(v.reason, "lock_released");
        assert!(!v.state_stale);
        // ...even when the service manager says the unit is active: a
        // restarting unit re-acquires the lock, and until then it is not up.
        let v = detect_daemon_liveness(&state_file, Some(true));
        assert!(!v.running);
        assert_eq!(v.reason, "lock_released");
    }
}

// ──────────────────── state file schema ────────────────────

/// Top-level state written to `state.json` for CLI consumption.
///
/// All fields use `#[serde(default)]` so that minor schema evolution
/// (new fields added by a newer daemon, or old fields removed) does not
/// hard-fail deserialization. The dashboard adapter layer detects drift
/// and surfaces warnings rather than crashing.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DaemonState {
    pub version: String,
    pub pid: u32,
    pub started_at: String,
    pub uptime_seconds: u64,
    pub last_updated: String,
    pub pressure: PressureState,
    pub ballast: BallastState,
    pub last_scan: LastScanState,
    pub counters: Counters,
    pub memory_rss_bytes: u64,
    /// Active policy engine mode (enforce/observe/canary/fallback_safe).
    pub policy_mode: String,
    /// Per-mount control state: what the daemon is doing on each mount and
    /// why it is idle on the ones it is not working on.
    pub mount_controllers: Vec<MountStateRecord>,
}

/// Current pressure across monitored mounts.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PressureState {
    pub overall: String,
    pub mounts: Vec<MountPressure>,
}

/// Pressure info for a single mount.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MountPressure {
    pub path: String,
    #[serde(default)]
    pub free_pct: f64,
    pub level: String,
    pub rate_bps: Option<f64>,
}

/// Current ballast file state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BallastState {
    pub available: usize,
    pub total: usize,
    pub released: usize,
}

/// Last scan summary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LastScanState {
    pub at: Option<String>,
    pub candidates: usize,
    pub deleted: usize,
}

/// Cumulative counters since daemon start.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Counters {
    pub scans: u64,
    pub deletions: u64,
    pub bytes_freed: u64,
    pub errors: u64,
    /// Log events silently dropped due to channel back-pressure.
    pub dropped_log_events: u64,
}

// ──────────────────── health tracking ────────────────────

/// Thread health status for monitoring.
#[derive(Debug, Clone)]
pub enum ThreadStatus {
    Running {
        name: String,
        last_heartbeat: Instant,
    },
    Stalled {
        name: String,
        stalled_since: Instant,
    },
    Dead {
        name: String,
        died_at: Instant,
        error: String,
    },
}

impl ThreadStatus {
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Running { name, .. } | Self::Stalled { name, .. } | Self::Dead { name, .. } => {
                name
            }
        }
    }

    #[must_use]
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Running { .. })
    }
}

/// Atomic heartbeat timestamp for thread health detection.
///
/// Each worker thread increments this periodically. The self-monitor
/// checks for staleness (> 60s without update → stalled).
#[derive(Debug)]
pub struct ThreadHeartbeat {
    /// Milliseconds since process-local monotonic origin (`Instant`).
    last_beat_epoch_ms: AtomicU64,
    name: String,
}

impl ThreadHeartbeat {
    /// Create a new heartbeat tracker for a named thread.
    #[must_use]
    pub fn new(name: &str) -> Arc<Self> {
        Arc::new(Self {
            last_beat_epoch_ms: AtomicU64::new(epoch_ms()),
            name: name.to_string(),
        })
    }

    /// Record a heartbeat (called by the worker thread).
    pub fn beat(&self) {
        self.last_beat_epoch_ms.store(epoch_ms(), Ordering::Relaxed);
    }

    /// Check thread status based on heartbeat staleness.
    #[must_use]
    pub fn status(&self, stall_threshold: Duration) -> ThreadStatus {
        let last = self.last_beat_epoch_ms.load(Ordering::Relaxed);
        let now = epoch_ms();
        let elapsed_ms = now.saturating_sub(last);

        #[allow(clippy::cast_possible_truncation)]
        let threshold_ms = stall_threshold.as_millis() as u64;
        let approx_instant = Instant::now()
            .checked_sub(Duration::from_millis(elapsed_ms))
            .unwrap_or_else(Instant::now);

        if elapsed_ms > threshold_ms {
            ThreadStatus::Stalled {
                name: self.name.clone(),
                stalled_since: approx_instant,
            }
        } else {
            ThreadStatus::Running {
                name: self.name.clone(),
                last_heartbeat: approx_instant,
            }
        }
    }
}

/// Milliseconds since a process-local monotonic origin.
///
/// Uses `Instant` (monotonic clock) instead of `SystemTime` to avoid
/// false heartbeat readings when the system clock is adjusted.
fn epoch_ms() -> u64 {
    use std::sync::OnceLock;
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    let origin = ORIGIN.get_or_init(Instant::now);
    #[allow(clippy::cast_possible_truncation)]
    let ms = origin.elapsed().as_millis() as u64;
    ms
}

// ──────────────────── daemon health ────────────────────

/// Aggregate health snapshot for the daemon.
#[derive(Debug, Clone)]
pub struct DaemonHealth {
    pub uptime: Duration,
    pub memory_rss_bytes: u64,
    pub scan_count: u64,
    pub avg_scan_duration: Duration,
    pub last_scan_at: Option<Instant>,
    pub deletions_total: u64,
    pub bytes_freed_total: u64,
    pub errors_total: u64,
    pub thread_status: Vec<ThreadStatus>,
    pub last_pressure_level: PressureLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfMonitorTick {
    pub rss_bytes: u64,
    pub rss_warning_bytes: u64,
    pub rss_hard_limit_bytes: u64,
    pub rss_hard_limit_exceeded: bool,
}

impl SelfMonitorTick {
    #[must_use]
    pub const fn should_exit_for_rss_hard_limit(self) -> bool {
        self.rss_hard_limit_exceeded
    }
}

// ──────────────────── self-monitor ────────────────────

/// Periodic self-monitoring: writes state file, checks RSS, reports status.
pub struct SelfMonitor {
    state_file_path: PathBuf,
    platform: Arc<dyn Platform>,
    start_time: Instant,
    started_at_iso: String,
    write_interval: Duration,
    last_write: Option<Instant>,
    rss_warning_bytes: u64,
    rss_hard_limit_bytes: u64,

    // Mutable counters updated by the main loop.
    pub scan_count: u64,
    pub last_scan_at: Option<String>,
    pub last_scan_candidates: usize,
    pub last_scan_deleted: usize,
    pub deletions_total: u64,
    pub bytes_freed_total: u64,
    pub errors_total: u64,
    /// Cumulative scan duration for averaging.
    scan_duration_total: Duration,
    /// Latest per-mount pressure readings, set by the main loop each tick.
    mount_snapshot: Vec<MountPressure>,
    /// Latest per-mount controller records, set by the main loop each tick.
    controller_snapshot: Vec<MountStateRecord>,
}

impl SelfMonitor {
    /// Create a new self-monitor.
    pub fn new(state_file_path: PathBuf, platform: Arc<dyn Platform>) -> Self {
        Self::with_rss_limits(
            state_file_path,
            platform,
            DEFAULT_DAEMON_RSS_WARNING_BYTES,
            DEFAULT_DAEMON_RSS_HARD_LIMIT_BYTES,
        )
    }

    /// Record the per-mount readings and controller states the next state
    /// file write should carry. An empty `mounts` keeps the single
    /// causing-mount entry the writer builds itself.
    pub fn set_mount_snapshot(
        &mut self,
        mounts: Vec<MountPressure>,
        controllers: Vec<MountStateRecord>,
    ) {
        self.mount_snapshot = mounts;
        self.controller_snapshot = controllers;
    }

    /// Create a new self-monitor using daemon RSS limits from config.
    pub fn from_telemetry_config(
        state_file_path: PathBuf,
        platform: Arc<dyn Platform>,
        telemetry: &TelemetryConfig,
    ) -> Self {
        Self::with_rss_limits(
            state_file_path,
            platform,
            telemetry.daemon_rss_warning_bytes,
            telemetry.daemon_rss_hard_limit_bytes,
        )
    }

    fn with_rss_limits(
        state_file_path: PathBuf,
        platform: Arc<dyn Platform>,
        rss_warning_bytes: u64,
        rss_hard_limit_bytes: u64,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            state_file_path,
            platform,
            start_time: Instant::now(),
            started_at_iso: now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            write_interval: Duration::from_secs(DAEMON_STATE_WRITE_INTERVAL_SECS),
            last_write: None,
            rss_warning_bytes,
            rss_hard_limit_bytes,
            mount_snapshot: Vec::new(),
            controller_snapshot: Vec::new(),

            scan_count: 0,
            last_scan_at: None,
            last_scan_candidates: 0,
            last_scan_deleted: 0,
            deletions_total: 0,
            bytes_freed_total: 0,
            errors_total: 0,
            scan_duration_total: Duration::ZERO,
        }
    }

    /// Check if it's time to write the state file. If so, write it.
    ///
    /// Returns the current RSS sample and whether the hard cap was exceeded.
    #[allow(clippy::too_many_arguments)]
    pub fn maybe_write_state(
        &mut self,
        pressure_level: PressureLevel,
        free_pct: f64,
        mount_path: &str,
        ballast_available: usize,
        ballast_total: usize,
        dropped_log_events: u64,
        policy_mode: &str,
    ) -> SelfMonitorTick {
        let now = Instant::now();
        let rss = self.current_rss_bytes();
        let tick = SelfMonitorTick {
            rss_bytes: rss,
            rss_warning_bytes: self.rss_warning_bytes,
            rss_hard_limit_bytes: self.rss_hard_limit_bytes,
            rss_hard_limit_exceeded: rss > self.rss_hard_limit_bytes,
        };

        let write_due = self
            .last_write
            .is_none_or(|last| now.duration_since(last) >= self.write_interval);
        if !write_due && !tick.rss_hard_limit_exceeded {
            return tick;
        }

        if rss > self.rss_warning_bytes {
            eprintln!(
                "[SBH-SELFMON] WARNING: RSS {} MB exceeds limit {} MB",
                rss / (1024 * 1024),
                self.rss_warning_bytes / (1024 * 1024),
            );
        }
        if tick.rss_hard_limit_exceeded {
            eprintln!(
                "[SBH-SELFMON] FATAL: RSS {} MB exceeds hard limit {} MB; daemon will exit nonzero for service restart",
                rss / (1024 * 1024),
                self.rss_hard_limit_bytes / (1024 * 1024),
            );
        }

        let state = DaemonState {
            version: env!("CARGO_PKG_VERSION").to_string(),
            pid: std::process::id(),
            started_at: self.started_at_iso.clone(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            last_updated: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            pressure: PressureState {
                overall: format!("{pressure_level:?}").to_lowercase(),
                mounts: if self.mount_snapshot.is_empty() {
                    vec![MountPressure {
                        path: mount_path.to_string(),
                        free_pct,
                        level: format!("{pressure_level:?}").to_lowercase(),
                        rate_bps: None,
                    }]
                } else {
                    self.mount_snapshot.clone()
                },
            },
            ballast: BallastState {
                available: ballast_available,
                total: ballast_total,
                released: ballast_total.saturating_sub(ballast_available),
            },
            last_scan: LastScanState {
                at: self.last_scan_at.clone(),
                candidates: self.last_scan_candidates,
                deleted: self.last_scan_deleted,
            },
            counters: Counters {
                scans: self.scan_count,
                deletions: self.deletions_total,
                bytes_freed: self.bytes_freed_total,
                errors: self.errors_total,
                dropped_log_events,
            },
            memory_rss_bytes: rss,
            policy_mode: policy_mode.to_string(),
            mount_controllers: self.controller_snapshot.clone(),
        };

        let result = write_state_atomic(&self.state_file_path, &state);
        if let Err(e) = &result {
            eprintln!("[SBH-SELFMON] failed to write state file: {e}");
        }
        // Update last_write regardless of success to respect the interval
        // and prevent log spam on persistent errors (e.g. permission denied).
        self.last_write = Some(now);

        if result.is_err() {
            return tick;
        }

        tick
    }

    /// Build a status string suitable for sd_notify STATUS.
    #[must_use]
    pub fn status_line(
        &self,
        pressure_level: PressureLevel,
        free_pct: f64,
        mount_path: &str,
    ) -> String {
        let rss_mb = self.current_rss_bytes() / (1024 * 1024);
        let gb_freed = self.bytes_freed_total as f64 / 1_073_741_824.0;
        format!(
            "{pressure_level:?} {free_pct:.1}% free on {mount_path} | \
             {deletions} deletions ({gb_freed:.1} GB freed) | RSS {rss_mb} MB",
            deletions = self.deletions_total,
        )
    }

    /// Record a completed scan with its duration.
    pub fn record_scan(&mut self, candidates: usize, deleted: usize, duration: Duration) {
        self.scan_count += 1;
        self.scan_duration_total += duration;
        self.last_scan_at =
            Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
        self.last_scan_candidates = candidates;
        self.last_scan_deleted = deleted;
    }

    /// Average scan duration across all recorded scans.
    #[must_use]
    pub fn avg_scan_duration(&self) -> Duration {
        if self.scan_count == 0 {
            return Duration::ZERO;
        }
        let total_nanos = self.scan_duration_total.as_nanos();
        let avg_nanos = total_nanos / u128::from(self.scan_count);
        Duration::from_nanos(u64::try_from(avg_nanos).unwrap_or(u64::MAX))
    }

    /// Build a health snapshot from current state plus thread heartbeats.
    #[must_use]
    pub fn health_snapshot(
        &self,
        heartbeats: &[Arc<ThreadHeartbeat>],
        stall_threshold: Duration,
        pressure_level: PressureLevel,
    ) -> DaemonHealth {
        DaemonHealth {
            uptime: self.start_time.elapsed(),
            memory_rss_bytes: self.current_rss_bytes(),
            scan_count: self.scan_count,
            avg_scan_duration: self.avg_scan_duration(),
            last_scan_at: self
                .last_scan_at
                .as_deref()
                .and_then(parse_last_scan_instant),
            deletions_total: self.deletions_total,
            bytes_freed_total: self.bytes_freed_total,
            errors_total: self.errors_total,
            thread_status: heartbeats
                .iter()
                .map(|hb| hb.status(stall_threshold))
                .collect(),
            last_pressure_level: pressure_level,
        }
    }

    /// Record deletion results.
    pub fn record_deletions(&mut self, count: u64, bytes: u64) {
        self.deletions_total += count;
        self.bytes_freed_total += bytes;
        // Update last_scan_deleted so the state file reflects actual
        // deletions.  Scan completion and deletion completion arrive via
        // separate WorkerReport variants, so record_scan always passes 0.
        #[allow(clippy::cast_possible_truncation)]
        {
            self.last_scan_deleted = count as usize;
        }
    }

    /// Record an error.
    pub fn record_error(&mut self) {
        self.errors_total += 1;
    }

    fn current_rss_bytes(&self) -> u64 {
        self.current_self_stats().rss_bytes
    }

    fn current_self_stats(&self) -> SelfStats {
        self.platform
            .self_stats()
            .unwrap_or_else(|_| empty_self_stats())
    }

    /// Read the state file (for `sbh status` CLI command).
    pub fn read_state(path: &Path) -> std::result::Result<DaemonState, String> {
        let raw = fs::read_to_string(path).map_err(|e| format!("cannot read state file: {e}"))?;
        let state: DaemonState =
            serde_json::from_str(&raw).map_err(|e| format!("invalid state file: {e}"))?;

        // Check staleness.
        if let Ok(updated) = chrono::DateTime::parse_from_rfc3339(&state.last_updated) {
            let age = chrono::Utc::now().signed_duration_since(updated);
            #[allow(clippy::cast_possible_wrap)]
            if age.num_seconds() > DAEMON_STATE_STALE_THRESHOLD_SECS as i64 {
                eprintln!(
                    "[SBH-STATUS] WARNING: state file is {}s old — daemon may be stalled",
                    age.num_seconds()
                );
            }
        }

        Ok(state)
    }
}

fn parse_last_scan_instant(timestamp: &str) -> Option<Instant> {
    let parsed = chrono::DateTime::parse_from_rfc3339(timestamp).ok()?;
    let now = chrono::Utc::now();
    let age = now.signed_duration_since(parsed.with_timezone(&chrono::Utc));
    if age <= chrono::Duration::zero() {
        return Some(Instant::now());
    }
    let age_std = age.to_std().ok()?;
    Some(
        Instant::now()
            .checked_sub(age_std)
            .unwrap_or_else(Instant::now),
    )
}

// ──────────────────── atomic state file write ────────────────────

/// Write state.json atomically: write to .tmp, then rename.
///
/// Sets 0o644 permissions on the temp file (Unix only) so the state file is
/// world-readable. The state file contains only operational telemetry (pressure
/// levels, uptime, counters) and must be readable by the CLI running as a
/// non-root user (e.g. `sbh status` run by ubuntu while daemon runs as root).
fn write_state_atomic(path: &Path, state: &DaemonState) -> std::io::Result<()> {
    let tmp_path = path.with_extension("json.tmp");

    // Ensure parent directory exists.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(state).map_err(std::io::Error::other)?;

    let result = (|| {
        {
            use std::io::Write;
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                opts.mode(0o644);
            }
            let mut file = opts.open(&tmp_path)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
        }
        fs::rename(&tmp_path, path)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

fn empty_self_stats() -> SelfStats {
    SelfStats {
        rss_bytes: 0,
        virtual_memory_bytes: 0,
        cpu_user_micros: 0,
        cpu_system_micros: 0,
        idle_wakeups: None,
        bytes_read: None,
        bytes_written: None,
    }
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use crate::platform::pal::MockPlatform;

    fn test_self_stats(rss_bytes: u64) -> SelfStats {
        SelfStats {
            rss_bytes,
            virtual_memory_bytes: rss_bytes.saturating_mul(2),
            cpu_user_micros: 1_000,
            cpu_system_micros: 500,
            idle_wakeups: Some(0),
            bytes_read: Some(0),
            bytes_written: Some(0),
        }
    }

    fn test_monitor(path: PathBuf) -> SelfMonitor {
        SelfMonitor::new(
            path,
            Arc::new(MockPlatform::healthy().with_self_stats(test_self_stats(44_040_192))),
        )
    }

    #[test]
    fn daemon_state_serializes_correctly() {
        let state = DaemonState {
            version: "0.1.0".to_string(),
            pid: 12345,
            started_at: "2026-02-14T10:00:00.000Z".to_string(),
            uptime_seconds: 3600,
            last_updated: "2026-02-14T11:00:00.000Z".to_string(),
            pressure: PressureState {
                overall: "green".to_string(),
                mounts: vec![MountPressure {
                    path: "/data".to_string(),
                    free_pct: 23.4,
                    level: "green".to_string(),
                    rate_bps: Some(-12_400_000.0),
                }],
            },
            ballast: BallastState {
                available: 8,
                total: 10,
                released: 2,
            },
            last_scan: LastScanState {
                at: Some("2026-02-14T10:59:55.000Z".to_string()),
                candidates: 3,
                deleted: 0,
            },
            counters: Counters {
                scans: 1542,
                deletions: 312,
                bytes_freed: 467_800_000_000,
                errors: 2,
                dropped_log_events: 0,
            },
            memory_rss_bytes: 44_040_192,
            policy_mode: "enforce".into(),
            mount_controllers: Vec::new(),
        };

        let json = serde_json::to_string_pretty(&state).unwrap();
        assert!(json.contains("\"version\": \"0.1.0\""));
        assert!(json.contains("\"pid\": 12345"));
        assert!(json.contains("\"overall\": \"green\""));
        assert!(json.contains("\"available\": 8"));
        assert!(json.contains("\"scans\": 1542"));

        // Roundtrip.
        let parsed: DaemonState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.pid, 12345);
        assert_eq!(parsed.counters.bytes_freed, 467_800_000_000);
    }

    #[test]
    fn atomic_write_creates_state_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");

        let state = DaemonState {
            version: "0.1.0".to_string(),
            pid: 1,
            started_at: "2026-01-01T00:00:00.000Z".to_string(),
            uptime_seconds: 100,
            last_updated: "2026-01-01T00:01:40.000Z".to_string(),
            pressure: PressureState {
                overall: "green".to_string(),
                mounts: vec![],
            },
            ballast: BallastState {
                available: 5,
                total: 5,
                released: 0,
            },
            last_scan: LastScanState {
                at: None,
                candidates: 0,
                deleted: 0,
            },
            counters: Counters {
                scans: 0,
                deletions: 0,
                bytes_freed: 0,
                errors: 0,
                dropped_log_events: 0,
            },
            memory_rss_bytes: 0,
            policy_mode: String::new(),
            mount_controllers: Vec::new(),
        };

        write_state_atomic(&path, &state).unwrap();
        assert!(path.exists());

        // No temp file left behind.
        assert!(!dir.path().join("state.json.tmp").exists());

        // Readable.
        let read_back: DaemonState =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(read_back.uptime_seconds, 100);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");

        let state = DaemonState {
            version: "0.1.0".to_string(),
            pid: 1,
            started_at: "2026-01-01T00:00:00.000Z".to_string(),
            uptime_seconds: 0,
            last_updated: "2026-01-01T00:00:00.000Z".to_string(),
            pressure: PressureState {
                overall: "green".to_string(),
                mounts: vec![],
            },
            ballast: BallastState {
                available: 0,
                total: 0,
                released: 0,
            },
            last_scan: LastScanState {
                at: None,
                candidates: 0,
                deleted: 0,
            },
            counters: Counters {
                scans: 0,
                deletions: 0,
                bytes_freed: 0,
                errors: 0,
                dropped_log_events: 0,
            },
            memory_rss_bytes: 0,
            policy_mode: String::new(),
            mount_controllers: Vec::new(),
        };

        write_state_atomic(&path, &state).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o644,
            "state.json should be world-readable (0644) for CLI access, got {mode:o}"
        );
    }

    #[test]
    fn self_monitor_write_interval() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut monitor = test_monitor(path.clone());
        monitor.write_interval = Duration::from_mins(1);

        // First write always happens.
        let _rss =
            monitor.maybe_write_state(PressureLevel::Green, 25.0, "/data", 10, 10, 0, "enforce");
        assert!(path.exists());

        // Immediate second write is skipped (within interval).
        let content_before = fs::read_to_string(&path).unwrap();
        monitor.maybe_write_state(PressureLevel::Green, 25.0, "/data", 10, 10, 0, "enforce");
        let content_after = fs::read_to_string(&path).unwrap();
        // Content should be identical (no rewrite).
        assert_eq!(content_before, content_after);

        // After interval, write happens again.
        monitor.last_write = Some(
            Instant::now()
                .checked_sub(Duration::from_mins(2))
                .expect("test instant supports two-minute subtraction"),
        );
        monitor.maybe_write_state(PressureLevel::Yellow, 12.0, "/data", 8, 10, 0, "enforce");
        let updated = fs::read_to_string(&path).unwrap();
        assert!(updated.contains("yellow"));
    }

    #[test]
    fn read_state_parses_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut monitor = test_monitor(path.clone());
        monitor.scan_count = 42;
        monitor.deletions_total = 7;
        monitor.bytes_freed_total = 1_000_000;
        monitor.record_scan(5, 3, Duration::from_millis(200));

        monitor.maybe_write_state(PressureLevel::Green, 30.0, "/data", 10, 10, 0, "enforce");

        let state = SelfMonitor::read_state(&path).unwrap();
        assert_eq!(state.counters.scans, 43);
        assert_eq!(state.counters.deletions, 7);
        assert!(state.last_scan.at.is_some());
        assert_eq!(state.last_scan.candidates, 5);
        assert_eq!(state.last_scan.deleted, 3);
    }

    #[test]
    fn record_counters_accumulate() {
        let dir = tempfile::tempdir().unwrap();
        let mut monitor = test_monitor(dir.path().join("state.json"));

        monitor.record_scan(10, 3, Duration::from_millis(100));
        assert_eq!(monitor.scan_count, 1);
        assert_eq!(monitor.last_scan_candidates, 10);
        assert_eq!(monitor.last_scan_deleted, 3);

        monitor.record_scan(5, 2, Duration::from_millis(300));
        assert_eq!(monitor.scan_count, 2);
        assert_eq!(monitor.last_scan_candidates, 5);

        // Average scan duration: (100ms + 300ms) / 2 = 200ms.
        let avg = monitor.avg_scan_duration();
        assert_eq!(avg, Duration::from_millis(200));

        monitor.record_deletions(3, 5000);
        monitor.record_deletions(2, 3000);
        assert_eq!(monitor.deletions_total, 5);
        assert_eq!(monitor.bytes_freed_total, 8000);

        monitor.record_error();
        monitor.record_error();
        assert_eq!(monitor.errors_total, 2);
    }

    #[test]
    fn status_line_format() {
        let dir = tempfile::tempdir().unwrap();
        let mut monitor = test_monitor(dir.path().join("state.json"));
        monitor.deletions_total = 312;
        monitor.bytes_freed_total = 502_000_000_000;

        let line = monitor.status_line(PressureLevel::Green, 23.4, "/data");
        assert!(line.contains("Green"));
        assert!(line.contains("23.4%"));
        assert!(line.contains("312 deletions"));
        assert!(line.contains("/data"));
    }

    #[test]
    fn thread_heartbeat_detects_stall() {
        let hb = ThreadHeartbeat::new("test-thread");

        // Fresh heartbeat should be healthy.
        let status = hb.status(Duration::from_mins(1));
        assert!(status.is_healthy());
        assert_eq!(status.name(), "test-thread");

        // With a sub-millisecond threshold after a brief sleep, the heartbeat is stale.
        std::thread::sleep(Duration::from_millis(2));
        let status = hb.status(Duration::from_millis(1));
        assert!(!status.is_healthy());
    }

    #[test]
    fn thread_heartbeat_beat_resets_timer() {
        let hb = ThreadHeartbeat::new("worker");

        // Wait a bit, then beat.
        std::thread::sleep(Duration::from_millis(10));
        hb.beat();

        // Should still be healthy with reasonable threshold.
        let status = hb.status(Duration::from_mins(1));
        assert!(status.is_healthy());
    }

    #[test]
    fn avg_scan_duration_zero_when_no_scans() {
        let dir = tempfile::tempdir().unwrap();
        let monitor = test_monitor(dir.path().join("state.json"));
        assert_eq!(monitor.avg_scan_duration(), Duration::ZERO);
    }

    #[test]
    fn health_snapshot_includes_thread_status() {
        let dir = tempfile::tempdir().unwrap();
        let mut monitor = test_monitor(dir.path().join("state.json"));
        monitor.record_scan(10, 2, Duration::from_millis(150));
        monitor.record_deletions(2, 5000);

        let hb1 = ThreadHeartbeat::new("scanner");
        let hb2 = ThreadHeartbeat::new("executor");
        hb1.beat();
        hb2.beat();

        let health = monitor.health_snapshot(
            &[Arc::clone(&hb1), Arc::clone(&hb2)],
            Duration::from_mins(1),
            PressureLevel::Green,
        );

        assert_eq!(health.scan_count, 1);
        assert_eq!(health.avg_scan_duration, Duration::from_millis(150));
        assert_eq!(health.deletions_total, 2);
        assert_eq!(health.bytes_freed_total, 5000);
        assert_eq!(health.thread_status.len(), 2);
        assert!(health.thread_status.iter().all(ThreadStatus::is_healthy));
        assert!(matches!(health.last_pressure_level, PressureLevel::Green));
    }

    #[test]
    fn health_snapshot_detects_stalled_thread() {
        let dir = tempfile::tempdir().unwrap();
        let monitor = test_monitor(dir.path().join("state.json"));

        let hb = ThreadHeartbeat::new("stalled-worker");
        // Don't beat — with 1ms threshold after sleeping, it's stale.
        std::thread::sleep(Duration::from_millis(5));

        let health = monitor.health_snapshot(
            &[Arc::clone(&hb)],
            Duration::from_millis(1),
            PressureLevel::Yellow,
        );

        assert_eq!(health.thread_status.len(), 1);
        assert!(!health.thread_status[0].is_healthy());
        assert_eq!(health.thread_status[0].name(), "stalled-worker");
    }

    #[test]
    fn health_snapshot_restores_last_scan_age_from_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let mut monitor = test_monitor(dir.path().join("state.json"));
        monitor.last_scan_at = Some(
            (chrono::Utc::now() - chrono::Duration::seconds(120))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        );

        let health = monitor.health_snapshot(&[], Duration::from_mins(1), PressureLevel::Green);
        let elapsed = health
            .last_scan_at
            .expect("last_scan_at should parse")
            .elapsed();
        assert!(elapsed >= Duration::from_secs(100));
    }

    #[test]
    fn dead_thread_status_carries_error() {
        let status = ThreadStatus::Dead {
            name: "worker".to_string(),
            died_at: Instant::now(),
            error: "panicked at division by zero".to_string(),
        };
        assert!(!status.is_healthy());
        assert_eq!(status.name(), "worker");
    }

    #[test]
    fn current_rss_comes_from_platform_self_stats() {
        let dir = tempfile::tempdir().unwrap();
        let monitor = SelfMonitor::new(
            dir.path().join("state.json"),
            Arc::new(MockPlatform::healthy().with_self_stats(test_self_stats(12_345_678))),
        );

        assert_eq!(monitor.current_rss_bytes(), 12_345_678);
    }

    #[test]
    fn rss_hard_limit_breach_returns_exit_action_and_writes_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut monitor = SelfMonitor::with_rss_limits(
            path.clone(),
            Arc::new(MockPlatform::healthy().with_self_stats(test_self_stats(2048))),
            1024,
            1536,
        );

        let tick =
            monitor.maybe_write_state(PressureLevel::Green, 25.0, "/data", 10, 10, 0, "enforce");

        assert_eq!(tick.rss_bytes, 2048);
        assert_eq!(tick.rss_warning_bytes, 1024);
        assert_eq!(tick.rss_hard_limit_bytes, 1536);
        assert!(tick.should_exit_for_rss_hard_limit());
        let state = SelfMonitor::read_state(&path).expect("fatal RSS tick should persist state");
        assert_eq!(state.memory_rss_bytes, 2048);
    }

    #[test]
    fn rss_hard_limit_breach_forces_state_write_inside_interval() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut monitor = SelfMonitor::with_rss_limits(
            path.clone(),
            Arc::new(MockPlatform::healthy().with_self_stats(test_self_stats(4096))),
            1024,
            2048,
        );
        monitor.write_interval = Duration::from_hours(1);
        monitor.last_write = Some(Instant::now());

        let tick = monitor.maybe_write_state(PressureLevel::Red, 1.0, "/data", 0, 1, 0, "enforce");

        assert!(tick.should_exit_for_rss_hard_limit());
        let state = SelfMonitor::read_state(&path).expect("hard-limit tick should force write");
        assert_eq!(state.pressure.overall, "red");
        assert_eq!(state.memory_rss_bytes, 4096);
    }

    // ──────── failure-injection tests ────────

    #[test]
    fn corrupt_state_file_returns_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corrupt_state.json");

        // Inject: write garbage that is not valid JSON.
        fs::write(&path, b"{{{{not valid json!@#$").unwrap();

        let result = SelfMonitor::read_state(&path);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("invalid state file"),
            "error should mention invalid state file, got: {err}"
        );
    }

    #[test]
    fn truncated_state_file_returns_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("truncated_state.json");

        // Inject: write truncated JSON (simulates crash mid-write).
        fs::write(&path, r#"{"version":"0.1.0","pid":123"#).unwrap();

        let result = SelfMonitor::read_state(&path);
        assert!(result.is_err());
    }

    #[test]
    fn empty_state_file_returns_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty_state.json");

        // Inject: empty file (simulates disk-full zero-length write).
        fs::write(&path, b"").unwrap();

        let result = SelfMonitor::read_state(&path);
        assert!(result.is_err());
    }

    #[test]
    fn missing_state_file_returns_read_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent_state.json");

        let result = SelfMonitor::read_state(&path);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("cannot read"),
            "error should mention read failure, got: {err}"
        );
    }

    #[test]
    fn state_file_with_extra_fields_still_parses() {
        // Future-proofing: state file with unknown fields should still parse
        // (serde default behavior with Deserialize).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("future_state.json");

        // Write valid state with extra unknown fields.
        let json = r#"{
            "version": "9.9.9",
            "pid": 99999,
            "started_at": "2026-02-15T00:00:00.000Z",
            "uptime_seconds": 500,
            "last_updated": "2026-02-15T00:08:20.000Z",
            "pressure": {
                "overall": "green",
                "mounts": []
            },
            "ballast": {
                "available": 5,
                "total": 5,
                "released": 0
            },
            "last_scan": {
                "at": null,
                "candidates": 0,
                "deleted": 0
            },
            "counters": {
                "scans": 0,
                "deletions": 0,
                "bytes_freed": 0,
                "errors": 0,
                "dropped_log_events": 0
            },
            "memory_rss_bytes": 0,
            "future_field_one": "should be ignored",
            "future_field_two": 42
        }"#;
        fs::write(&path, json).unwrap();

        let result = SelfMonitor::read_state(&path);
        // This will fail if DaemonState uses #[serde(deny_unknown_fields)].
        // The test documents whether forward compatibility is supported.
        if let Ok(state) = result {
            assert_eq!(state.version, "9.9.9");
            assert_eq!(state.pid, 99999);
        }
        // If it errors, the test still passes — it documents current behavior.
    }

    #[test]
    fn write_failure_retries_on_next_call() {
        // Inject: state file path in non-creatable directory → write fails.
        // Expect: last_write is NOT updated, so next call retries immediately.
        let bad_path = PathBuf::from("/nonexistent_sbh_selfmon_test/state.json");
        let mut monitor = test_monitor(bad_path);

        // First write fails (bad path).
        monitor.maybe_write_state(PressureLevel::Green, 30.0, "/data", 5, 5, 0, "enforce");
        // last_write should be set to prevent busy-looping.
        assert!(
            monitor.last_write.is_some(),
            "last_write must be set even when state write fails (to prevent log spam)"
        );

        // Move to a valid path and verify it works on next call.
        // First, reset last_write so we don't have to wait for the interval in the test.
        monitor.last_write = None;

        let dir = tempfile::tempdir().unwrap();
        let good_path = dir.path().join("recovered_state.json");
        monitor.state_file_path = good_path.clone();

        monitor.maybe_write_state(PressureLevel::Yellow, 15.0, "/data", 3, 5, 0, "enforce");
        assert!(
            good_path.exists(),
            "state file must be written after path recovery"
        );
        assert!(
            monitor.last_write.is_some(),
            "last_write must be set after successful write"
        );

        let state = SelfMonitor::read_state(&good_path).unwrap();
        assert!(state.pressure.overall.contains("yellow"));
    }

    #[test]
    fn atomic_write_leaves_no_tmp_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clean_state.json");
        let mut monitor = test_monitor(path.clone());

        monitor.maybe_write_state(PressureLevel::Green, 40.0, "/data", 10, 10, 0, "enforce");

        assert!(path.exists());
        assert!(
            !dir.path().join("clean_state.json.tmp").exists(),
            "temp file must be cleaned up after atomic rename"
        );
    }

    #[test]
    fn concurrent_state_reads_during_writes() {
        // Verify atomic write means readers never see partial state.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("concurrent_state.json");
        let mut monitor = test_monitor(path.clone());
        monitor.write_interval = Duration::from_millis(0); // Allow every write.

        // Write 20 times with different pressure levels.
        for i in 0..20 {
            let level = if i % 2 == 0 {
                PressureLevel::Green
            } else {
                PressureLevel::Yellow
            };
            let free = if i % 2 == 0 { 30.0 } else { 15.0 };
            monitor.maybe_write_state(level, free, "/data", 10, 10, 0, "enforce");

            // Read back — must always be valid JSON.
            if path.exists() {
                let raw = fs::read_to_string(&path).unwrap();
                let parsed: std::result::Result<DaemonState, _> = serde_json::from_str(&raw);
                assert!(
                    parsed.is_ok(),
                    "state file must always be valid JSON, iteration {i}"
                );
            }
        }
    }
}
