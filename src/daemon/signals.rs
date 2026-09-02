//! Signal handling: SIGTERM/SIGINT graceful shutdown, SIGHUP config reload,
//! SIGUSR1 immediate scan trigger, macOS SIGINFO status dump, and service
//! watchdog heartbeat.
//!
//! Uses the `signal-hook` crate for safe signal registration. The main loop
//! polls `SignalHandler` flags each iteration rather than blocking on signals.

#![allow(missing_docs)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use signal_hook::consts::{SIGINT, SIGTERM};

use crate::platform::pal::{NoopServiceManager, ServiceManager};

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
    status_dump_flag: Arc<AtomicBool>,
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
            status_dump_flag: Arc::new(AtomicBool::new(false)),
        };

        handler.register_signals();
        handler
    }

    /// Check whether a shutdown has been requested.
    #[must_use]
    pub fn should_shutdown(&self) -> bool {
        self.shutdown_flag.load(Ordering::Relaxed)
    }

    /// Shared shutdown flag for long-running worker threads.
    #[must_use]
    pub(crate) fn shutdown_token(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown_flag)
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

    /// Check (and clear) whether a foreground status dump has been requested.
    #[must_use]
    pub fn should_dump_status(&self) -> bool {
        self.status_dump_flag.swap(false, Ordering::Relaxed)
    }

    /// Check whether a foreground status dump is pending without clearing it.
    #[must_use]
    pub fn has_pending_status_dump(&self) -> bool {
        self.status_dump_flag.load(Ordering::Relaxed)
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

    /// Programmatically request a foreground status dump.
    pub fn request_status_dump(&self) {
        self.status_dump_flag.store(true, Ordering::Relaxed);
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

        // SIGINFO -> status dump (macOS only). On Linux signal 30 is SIGPWR,
        // so this must never be registered under a broad Unix cfg.
        #[cfg(target_os = "macos")]
        {
            use signal_hook::consts::SIGINFO;
            if let Err(e) = signal_hook::flag::register(SIGINFO, Arc::clone(&self.status_dump_flag))
            {
                eprintln!("[SBH-SIGNAL] failed to register SIGINFO: {e}");
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

/// Resolve the effective watchdog timeout in seconds.
///
/// systemd exports the unit's `WatchdogSec=` to the service as
/// `WATCHDOG_USEC` (microseconds) and, when it targets a specific process,
/// `WATCHDOG_PID`. An explicit `--watchdog-sec` wins; otherwise the
/// environment is honored so the generated unit (which does not pass the
/// flag) still gets heartbeats. A `WATCHDOG_PID` naming another process, or
/// an unparsable/zero value, disables the watchdog.
#[must_use]
pub fn resolve_watchdog_sec(
    explicit_sec: u64,
    watchdog_usec: Option<&str>,
    watchdog_pid: Option<&str>,
    own_pid: u32,
) -> u64 {
    if explicit_sec > 0 {
        return explicit_sec;
    }
    if let Some(pid) = watchdog_pid
        && pid.trim().parse::<u32>().ok() != Some(own_pid)
    {
        return 0;
    }
    watchdog_usec
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map_or(0, |usec| usec / 1_000_000)
}

/// Systemd watchdog heartbeat tracker.
///
/// Tracks when the last heartbeat was sent so the main loop can call
/// `maybe_notify()` each iteration. If enough time has elapsed, it delegates
/// notification to the active service manager.
pub struct WatchdogHeartbeat {
    /// Interval between heartbeat notifications (typically half of `WatchdogSec`).
    interval: Duration,
    /// Last time a heartbeat was sent.
    last_beat: Instant,
    /// Whether service-manager watchdog integration is enabled.
    enabled: bool,
    /// Platform service manager used to deliver watchdog notifications.
    service_manager: Box<dyn ServiceManager>,
}

impl WatchdogHeartbeat {
    /// Create a heartbeat with the given interval.
    ///
    /// `watchdog_sec` is the full watchdog timeout from the service manager.
    /// The heartbeat will fire at half that interval.
    #[must_use]
    pub fn new(watchdog_sec: u64, service_manager: Box<dyn ServiceManager>) -> Self {
        Self {
            interval: Duration::from_secs(watchdog_sec / 2),
            last_beat: Instant::now(),
            enabled: service_manager.watchdog_enabled(watchdog_sec),
            service_manager,
        }
    }

    /// Create a disabled heartbeat (for non-systemd environments).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            interval: Duration::from_secs(30),
            last_beat: Instant::now(),
            enabled: false,
            service_manager: Box::<NoopServiceManager>::default(),
        }
    }

    /// The heartbeat cadence (half the service manager's timeout).
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
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
        if let Err(error) = self.service_manager.notify_watchdog(status) {
            eprintln!("[SBH-WATCHDOG] failed to notify service manager: {error}");
        }
        true
    }

    /// Whether the watchdog is enabled.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn noop_service_manager() -> Box<dyn ServiceManager> {
        Box::<NoopServiceManager>::default()
    }

    #[test]
    fn resolve_watchdog_sec_prefers_explicit_then_systemd_env() {
        // Explicit flag wins regardless of environment.
        assert_eq!(resolve_watchdog_sec(45, Some("60000000"), None, 100), 45);
        // Generated unit: no flag, WATCHDOG_USEC from WatchdogSec=60.
        assert_eq!(resolve_watchdog_sec(0, Some("60000000"), None, 100), 60);
        // WATCHDOG_PID naming this process is honored; another pid disables.
        assert_eq!(
            resolve_watchdog_sec(0, Some("60000000"), Some("100"), 100),
            60
        );
        assert_eq!(
            resolve_watchdog_sec(0, Some("60000000"), Some("999"), 100),
            0
        );
        // Garbage, sub-second, or absent values disable the watchdog.
        assert_eq!(resolve_watchdog_sec(0, Some("soon"), None, 100), 0);
        assert_eq!(resolve_watchdog_sec(0, Some("500000"), None, 100), 0);
        assert_eq!(resolve_watchdog_sec(0, None, None, 100), 0);
    }

    #[test]
    fn signal_handler_default_state() {
        let handler = SignalHandler {
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            reload_flag: Arc::new(AtomicBool::new(false)),
            scan_flag: Arc::new(AtomicBool::new(false)),
            status_dump_flag: Arc::new(AtomicBool::new(false)),
        };

        assert!(!handler.should_shutdown());
        assert!(!handler.should_reload());
        assert!(!handler.should_scan());
        assert!(!handler.should_dump_status());
    }

    #[test]
    fn programmatic_shutdown_request() {
        let handler = SignalHandler {
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            reload_flag: Arc::new(AtomicBool::new(false)),
            scan_flag: Arc::new(AtomicBool::new(false)),
            status_dump_flag: Arc::new(AtomicBool::new(false)),
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
            status_dump_flag: Arc::new(AtomicBool::new(false)),
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
            status_dump_flag: Arc::new(AtomicBool::new(false)),
        };

        handler.request_scan();
        assert!(handler.should_scan());
        assert!(!handler.should_scan());
    }

    #[test]
    fn status_dump_flag_clears_on_read() {
        let handler = SignalHandler {
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            reload_flag: Arc::new(AtomicBool::new(false)),
            scan_flag: Arc::new(AtomicBool::new(false)),
            status_dump_flag: Arc::new(AtomicBool::new(false)),
        };

        handler.request_status_dump();
        assert!(handler.should_dump_status());
        assert!(!handler.should_dump_status());
    }

    #[test]
    fn pending_status_dump_check_does_not_clear_flag() {
        let handler = SignalHandler {
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            reload_flag: Arc::new(AtomicBool::new(false)),
            scan_flag: Arc::new(AtomicBool::new(false)),
            status_dump_flag: Arc::new(AtomicBool::new(false)),
        };

        handler.request_status_dump();
        assert!(handler.has_pending_status_dump());
        assert!(handler.should_dump_status());
        assert!(!handler.has_pending_status_dump());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn siginfo_sets_status_dump_flag_on_macos() {
        let handler = SignalHandler::new();

        signal_hook::low_level::raise(signal_hook::consts::SIGINFO)
            .expect("raise SIGINFO for signal handler test");
        let deadline = Instant::now() + Duration::from_secs(2);
        while !handler.should_dump_status() {
            assert!(Instant::now() < deadline, "SIGINFO did not set status flag");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!handler.should_dump_status());
    }

    #[test]
    fn handler_is_clone_and_send() {
        let handler = SignalHandler {
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            reload_flag: Arc::new(AtomicBool::new(false)),
            scan_flag: Arc::new(AtomicBool::new(false)),
            status_dump_flag: Arc::new(AtomicBool::new(false)),
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
    fn watchdog_new_uses_service_manager_enablement() {
        let wd = WatchdogHeartbeat::new(60, noop_service_manager());
        assert!(!wd.is_enabled());
    }

    #[test]
    fn watchdog_respects_interval() {
        // Construct directly with enabled=true — no environment mutation needed.
        let mut wd = WatchdogHeartbeat {
            interval: Duration::from_mins(1),
            last_beat: Instant::now(),
            enabled: true,
            service_manager: noop_service_manager(),
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
            service_manager: noop_service_manager(),
        };
        // Interval has elapsed, should fire (service manager handles no-op gracefully).
        assert!(wd.maybe_notify("test"));
    }
}
