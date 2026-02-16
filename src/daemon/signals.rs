//! Signal handling: SIGTERM/SIGINT graceful shutdown, SIGHUP config reload,
//! SIGUSR1 immediate scan trigger, and systemd watchdog heartbeat.
//!
//! Uses the `signal-hook` crate for safe signal registration. The main loop
//! polls `SignalHandler` flags each iteration rather than blocking on signals.

#![allow(missing_docs)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use signal_hook::consts::{SIGINT, SIGTERM};

// ──────────────────── signal handler ────────────────────

/// Thread-safe signal state shared between the signal handler and the main loop.
///
/// All flags use `Ordering::Relaxed` because the main loop polls them every iteration
/// and exact ordering with other atomics is not required.
#[derive(Clone)]
#[allow(clippy::struct_field_names)]
pub struct SignalHandler {
    shutdown_flag: Arc<AtomicBool>,
    reload_flag: Arc<AtomicBool>,
    scan_flag: Arc<AtomicBool>,
}

impl SignalHandler {
    /// Create a new handler and register OS signal hooks.
    ///
    /// On Unix: SIGTERM/SIGINT -> shutdown, SIGHUP -> reload, SIGUSR1 -> scan.
    /// Registration is best-effort; failures are logged to stderr but not fatal.
    #[must_use]
    pub fn new() -> Self {
        let handler = Self {
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            reload_flag: Arc::new(AtomicBool::new(false)),
            scan_flag: Arc::new(AtomicBool::new(false)),
        };

        handler.register_signals();
        handler
    }

    /// Check whether a shutdown has been requested.
    #[must_use]
    pub fn should_shutdown(&self) -> bool {
        self.shutdown_flag.load(Ordering::Relaxed)
    }

    /// Check (and clear) whether a config reload has been requested.
    #[must_use]
    pub fn should_reload(&self) -> bool {
        self.reload_flag.swap(false, Ordering::Relaxed)
    }

    /// Check (and clear) whether an immediate scan has been requested.
    #[must_use]
    pub fn should_scan(&self) -> bool {
        self.scan_flag.swap(false, Ordering::Relaxed)
    }

    /// Programmatically request shutdown (e.g., from watchdog timeout or error escalation).
    pub fn request_shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::Relaxed);
    }

    /// Programmatically request a config reload.
    pub fn request_reload(&self) {
        self.reload_flag.store(true, Ordering::Relaxed);
    }

    /// Programmatically request an immediate scan.
    pub fn request_scan(&self) {
        self.scan_flag.store(true, Ordering::Relaxed);
    }

    fn register_signals(&self) {
        // SIGTERM / SIGINT -> shutdown
        if let Err(e) = signal_hook::flag::register(SIGTERM, Arc::clone(&self.shutdown_flag)) {
            eprintln!("[SBH-SIGNAL] failed to register SIGTERM: {e}");
        }
        if let Err(e) = signal_hook::flag::register(SIGINT, Arc::clone(&self.shutdown_flag)) {
            eprintln!("[SBH-SIGNAL] failed to register SIGINT: {e}");
        }

        // SIGHUP -> reload (Unix only)
        #[cfg(unix)]
        {
            use signal_hook::consts::SIGHUP;
            if let Err(e) = signal_hook::flag::register(SIGHUP, Arc::clone(&self.reload_flag)) {
                eprintln!("[SBH-SIGNAL] failed to register SIGHUP: {e}");
            }
        }

        // SIGUSR1 -> immediate scan (Unix only)
        #[cfg(unix)]
        {
            use signal_hook::consts::SIGUSR1;
            if let Err(e) = signal_hook::flag::register(SIGUSR1, Arc::clone(&self.scan_flag)) {
                eprintln!("[SBH-SIGNAL] failed to register SIGUSR1: {e}");
            }
        }
    }
}

impl Default for SignalHandler {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────── shutdown coordinator ────────────────────

/// Coordinates graceful shutdown: waits for in-progress operations, flushes
/// buffers, then exits.
pub struct ShutdownCoordinator {
    /// Maximum time to wait for in-progress operations.
    pub timeout: Duration,
}

impl ShutdownCoordinator {
    /// Create a coordinator with the default 30-second timeout.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            timeout: Duration::from_secs(30),
        }
    }

    /// Execute the shutdown sequence. Returns `true` if shutdown completed
    /// cleanly within the timeout.
    ///
    /// `shutdown_tasks` is a list of named shutdown actions. Each returns
    /// `true` if it completed successfully.
    pub fn execute(&self, shutdown_tasks: &[(&str, &dyn Fn() -> bool)]) -> bool {
        let start = Instant::now();
        let mut all_ok = true;

        for (name, task) in shutdown_tasks {
            if start.elapsed() > self.timeout {
                eprintln!("[SBH-SHUTDOWN] timeout reached, abandoning remaining tasks");
                return false;
            }

            if task() {
                eprintln!("[SBH-SHUTDOWN] {name}: ok");
            } else {
                eprintln!("[SBH-SHUTDOWN] {name}: failed");
                all_ok = false;
            }
        }

        all_ok
    }
}

impl Default for ShutdownCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────── watchdog heartbeat ────────────────────

/// Systemd watchdog heartbeat tracker.
///
/// Tracks when the last heartbeat was sent so the main loop can call
/// `maybe_notify()` each iteration. If enough time has elapsed, it sends
/// `sd_notify(WATCHDOG=1)`.
pub struct WatchdogHeartbeat {
    /// Interval between heartbeat notifications (typically half of `WatchdogSec`).
    interval: Duration,
    /// Last time a heartbeat was sent.
    last_beat: Instant,
    /// Whether systemd watchdog integration is enabled.
    enabled: bool,
    /// Cached socket path (NOTIFY_SOCKET) to avoid repeated env lookups.
    socket_path: Option<String>,
}

impl WatchdogHeartbeat {
    /// Create a heartbeat with the given interval.
    ///
    /// `watchdog_sec` is the full watchdog timeout from systemd. The heartbeat
    /// will fire at half that interval.
    #[must_use]
    pub fn new(watchdog_sec: u64) -> Self {
        let socket_path = std::env::var("NOTIFY_SOCKET").ok().filter(|s| !s.is_empty());
        Self {
            interval: Duration::from_secs(watchdog_sec / 2),
            last_beat: Instant::now(),
            enabled: watchdog_sec > 0 && socket_path.is_some(),
            socket_path,
        }
    }

    /// Create a disabled heartbeat (for non-systemd environments).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            interval: Duration::from_secs(30),
            last_beat: Instant::now(),
            enabled: false,
            socket_path: None,
        }
    }

    /// If enough time has elapsed, send a watchdog notification.
    ///
    /// Returns `true` if a notification was sent.
    pub fn maybe_notify(&mut self, status: &str) -> bool {
        if !self.enabled {
            return false;
        }

        if self.last_beat.elapsed() < self.interval {
            return false;
        }

        self.last_beat = Instant::now();
        sd_notify_watchdog(status, self.socket_path.as_deref());
        true
    }

    /// Whether the watchdog is enabled.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Send `sd_notify(WATCHDOG=1)` + STATUS=<msg> to systemd.
fn sd_notify_watchdog(status: &str, socket_path: Option<&str>) {
    #[cfg(target_os = "linux")]
    {
        if let Some(path) = socket_path {
            sd_notify_linux(status, path);
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = status;
        let _ = socket_path;
    }
}

#[cfg(target_os = "linux")]
fn sd_notify_linux(status: &str, socket_path: &str) {
    use std::os::unix::net::UnixDatagram;

    let msg = format!("WATCHDOG=1\nSTATUS={status}\n");
    let Ok(sock) = UnixDatagram::unbound() else {
        return;
    };

    let _ = sock.send_to(msg.as_bytes(), socket_path);
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_handler_default_state() {
        let handler = SignalHandler {
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            reload_flag: Arc::new(AtomicBool::new(false)),
            scan_flag: Arc::new(AtomicBool::new(false)),
        };

        assert!(!handler.should_shutdown());
        assert!(!handler.should_reload());
        assert!(!handler.should_scan());
    }

    #[test]
    fn programmatic_shutdown_request() {
        let handler = SignalHandler {
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            reload_flag: Arc::new(AtomicBool::new(false)),
            scan_flag: Arc::new(AtomicBool::new(false)),
        };

        assert!(!handler.should_shutdown());
        handler.request_shutdown();
        assert!(handler.should_shutdown());
    }

    #[test]
    fn reload_flag_clears_on_read() {
        let handler = SignalHandler {
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            reload_flag: Arc::new(AtomicBool::new(false)),
            scan_flag: Arc::new(AtomicBool::new(false)),
        };

        handler.request_reload();
        assert!(handler.should_reload()); // First read: true
        assert!(!handler.should_reload()); // Second read: false (cleared)
    }

    #[test]
    fn scan_flag_clears_on_read() {
        let handler = SignalHandler {
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            reload_flag: Arc::new(AtomicBool::new(false)),
            scan_flag: Arc::new(AtomicBool::new(false)),
        };

        handler.request_scan();
        assert!(handler.should_scan());
        assert!(!handler.should_scan());
    }

    #[test]
    fn handler_is_clone_and_send() {
        let handler = SignalHandler {
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            reload_flag: Arc::new(AtomicBool::new(false)),
            scan_flag: Arc::new(AtomicBool::new(false)),
        };
        let h2 = handler.clone();

        handler.request_shutdown();
        assert!(h2.should_shutdown());
    }

    #[test]
    fn shutdown_coordinator_runs_tasks() {
        let coord = ShutdownCoordinator::new();

        let tasks: Vec<(&str, &dyn Fn() -> bool)> =
            vec![("flush logs", &|| true), ("close db", &|| true)];

        let result = coord.execute(&tasks);
        assert!(result);
    }

    #[test]
    fn shutdown_coordinator_reports_failures() {
        let coord = ShutdownCoordinator::new();

        let tasks: Vec<(&str, &dyn Fn() -> bool)> =
            vec![("good task", &|| true), ("bad task", &|| false)];

        let result = coord.execute(&tasks);
        assert!(!result);
    }

    #[test]
    fn watchdog_disabled_does_not_notify() {
        let mut wd = WatchdogHeartbeat::disabled();
        assert!(!wd.is_enabled());
        assert!(!wd.maybe_notify("test"));
    }

    #[test]
    fn watchdog_respects_interval() {
        // Construct directly with enabled=true — no env var mutation needed.
        let mut wd = WatchdogHeartbeat {
            interval: Duration::from_secs(60),
            last_beat: Instant::now(),
            enabled: true,
            socket_path: Some("/tmp/test.sock".to_string()),
        };
        // Just beat, so shouldn't fire again immediately.
        assert!(!wd.maybe_notify("test"));
    }

    #[test]
    fn watchdog_fires_after_interval() {
        // Construct directly with enabled=true — no env var mutation needed.
        let mut wd = WatchdogHeartbeat {
            interval: Duration::from_millis(1),
            last_beat: Instant::now()
                .checked_sub(Duration::from_secs(1))
                .expect("1s subtraction should be representable"),
            enabled: true,
            socket_path: Some("/tmp/test.sock".to_string()),
        };
        // Interval has elapsed, should fire (sd_notify handles failure gracefully).
        assert!(wd.maybe_notify("test"));
    }
}
