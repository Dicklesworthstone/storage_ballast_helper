//! systemd service integration.

#[path = "systemd_load_state.rs"]
mod load_state;
#[path = "systemd_namespace.rs"]
mod namespace;

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::core::errors::{Result, SbhError};
use crate::platform::pal::ServiceManager;

use super::{SYSTEMD_UNIT_NAME, ServiceOwnershipPolicy, resolve_sbh_binary};

/// Parameters controlling systemd unit file generation and lifecycle commands.
#[derive(Debug, Clone)]
pub struct SystemdConfig {
    /// Whether to operate in user scope (`--user`).
    pub user_scope: bool,
    /// Absolute path to the sbh binary baked into the unit file.
    pub binary_path: PathBuf,
    /// Paths sbh needs read-write access to under `ProtectSystem=strict`.
    pub read_write_paths: Vec<PathBuf>,
}

impl SystemdConfig {
    /// Build a config from the current environment.
    ///
    /// `user_scope` controls system vs user service placement.
    pub fn from_env(user_scope: bool) -> Result<Self> {
        let binary_path = resolve_sbh_binary()?;
        let read_write_paths =
            crate::core::config::Config::load_for_service_scope(None, user_scope).map_or_else(
                |_| default_read_write_paths(user_scope),
                |config| Self::read_write_paths_for(&config, user_scope),
            );
        Ok(Self {
            user_scope,
            binary_path,
            read_write_paths,
        })
    }

    /// Directory where the unit file is written.
    ///
    /// Under `SBH_TEST_MODE=1`, `SBH_SYSTEMD_UNIT_DIR` redirects both scopes
    /// to a fixture directory so `doctor --service` and `reinstall-unit`
    /// can be exercised without touching the host's units.
    #[must_use]
    pub fn unit_dir(&self) -> PathBuf {
        if let Some(dir) = test_unit_dir_override() {
            return dir;
        }
        if self.user_scope {
            let home = env::var_os("HOME").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
            home.join(".config/systemd/user")
        } else {
            PathBuf::from("/etc/systemd/system")
        }
    }

    /// Directories whose `*.conf` drop-ins extend the unit: the unit's own
    /// `sbh.service.d/`, plus systemd's `system.control` tree where
    /// `systemctl set-property` writes for system units.
    #[must_use]
    pub fn dropin_dirs(&self) -> Vec<PathBuf> {
        let unit_dir = self.unit_dir();
        let mut dirs = vec![unit_dir.join(format!("{SYSTEMD_UNIT_NAME}.d"))];
        if test_unit_dir_override().is_some() {
            dirs.push(
                unit_dir
                    .join("system.control")
                    .join(format!("{SYSTEMD_UNIT_NAME}.d")),
            );
        } else if !self.user_scope {
            dirs.push(PathBuf::from(format!(
                "/etc/systemd/system.control/{SYSTEMD_UNIT_NAME}.d"
            )));
        }
        dirs
    }

    /// Every drop-in that currently extends the unit, `(path, contents)`,
    /// in the order systemd applies them (by file name within each dir).
    #[must_use]
    pub fn read_dropins(&self) -> Vec<(PathBuf, String)> {
        let mut dropins = Vec::new();
        for dir in self.dropin_dirs() {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            let mut paths: Vec<PathBuf> = entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "conf"))
                .collect();
            paths.sort();
            for path in paths {
                if let Ok(text) = fs::read_to_string(&path) {
                    dropins.push((path, text));
                }
            }
        }
        dropins
    }

    /// Full path to the generated unit file.
    #[must_use]
    pub fn unit_path(&self) -> PathBuf {
        self.unit_dir().join(SYSTEMD_UNIT_NAME)
    }

    /// Build a config whose `ReadWritePaths=` sandbox is derived from the
    /// sbh config the service will run with (see [`Self::read_write_paths_for`]).
    pub fn from_config(config: &crate::core::config::Config, user_scope: bool) -> Result<Self> {
        let mut systemd = Self::from_env(user_scope)?;
        systemd.read_write_paths = Self::read_write_paths_for(config, user_scope);
        Ok(systemd)
    }

    /// Every path the daemon must be able to write under `ProtectSystem=strict`:
    /// the scan roots it deletes under, the special locations it cleans,
    /// every ballast directory (configured, per-volume overrides'
    /// `<mount>/.sbh`), its own data/config/log/cache directories, plus the
    /// scope defaults. `/proc` and `/sys` are never included (kernel tuning
    /// is applied by `sbh tune`, never by the daemon). Deduplicated and
    /// sorted so a re-render is byte-stable.
    #[must_use]
    pub fn read_write_paths_for(
        config: &crate::core::config::Config,
        user_scope: bool,
    ) -> Vec<PathBuf> {
        let mut paths = default_read_write_paths(user_scope);
        // Special locations the daemon reclaims from.
        paths.push(PathBuf::from("/dev/shm"));
        paths.extend(config.scanner.root_paths.iter().cloned());
        paths.push(config.paths.ballast_dir.clone());
        for (mount, volume) in &config.ballast.overrides {
            if volume.enabled {
                paths.push(Path::new(mount).join(".sbh"));
            }
        }
        for file in [
            &config.paths.config_file,
            &config.paths.state_file,
            &config.paths.sqlite_db,
            &config.paths.jsonl_log,
            &config.update.metadata_cache_file,
            &config.notifications.file.path,
        ] {
            if let Some(parent) = file.parent() {
                paths.push(parent.to_path_buf());
            }
        }
        let mut paths: Vec<PathBuf> = paths
            .into_iter()
            .filter(|path| path.is_absolute())
            .filter(|path| !path.starts_with("/proc") && !path.starts_with("/sys"))
            .filter(|path| path != Path::new("/"))
            .collect();
        paths.sort();
        paths.dedup();
        paths
    }

    /// `ReadWritePaths=` value for `paths`, with systemd C escaping and
    /// literal percent specifiers. This never expands environment variables.
    #[must_use]
    pub fn render_read_write_paths(paths: &[PathBuf]) -> String {
        namespace::render(paths)
    }

    /// Parse the value of a `ReadWritePaths=` line (the inverse of
    /// [`Self::render_read_write_paths`]). Invalid syntax grants no paths.
    #[must_use]
    pub fn parse_read_write_paths(value: &str) -> Vec<PathBuf> {
        namespace::parse(value).unwrap_or_default()
    }

    /// Paths in `required` that a unit file's `ReadWritePaths=` line does not
    /// grant (a unit without `ProtectSystem=strict` needs none).
    #[must_use]
    pub fn missing_read_write_paths(unit_contents: &str, required: &[PathBuf]) -> Vec<PathBuf> {
        let strict = unit_contents
            .lines()
            .any(|line| line.trim() == "ProtectSystem=strict");
        if !strict {
            return Vec::new();
        }
        let granted: Vec<PathBuf> = unit_contents
            .lines()
            .filter_map(|line| line.trim().strip_prefix("ReadWritePaths="))
            .flat_map(Self::parse_read_write_paths)
            .collect();
        required
            .iter()
            .filter(|path| !granted.iter().any(|g| path.starts_with(g)))
            .cloned()
            .collect()
    }

    /// Rewrite the `ReadWritePaths=` line of an existing unit file to
    /// `paths` (added after `ProtectSystem=strict` when absent). Returns the
    /// new contents, or `None` when nothing changed.
    #[must_use]
    pub fn patch_read_write_paths(unit_contents: &str, paths: &[PathBuf]) -> Option<String> {
        let rendered = format!("ReadWritePaths={}", Self::render_read_write_paths(paths));
        let mut replaced = false;
        let mut lines: Vec<String> = unit_contents
            .lines()
            .map(|line| {
                if line.trim().starts_with("ReadWritePaths=") {
                    replaced = true;
                    rendered.clone()
                } else {
                    line.to_string()
                }
            })
            .collect();
        if !replaced {
            let index = lines
                .iter()
                .position(|line| line.trim() == "ProtectSystem=strict")?;
            lines.insert(index + 1, rendered);
        }
        let updated = lines.join("\n") + "\n";
        (updated != unit_contents).then_some(updated)
    }
}

/// [`ServiceManager`] implementation that drives `systemctl` and generates
/// a hardened systemd unit file.
#[derive(Debug, Clone)]
pub struct SystemdServiceManager {
    config: SystemdConfig,
}

impl SystemdServiceManager {
    /// Create a new manager with the given config.
    #[must_use]
    pub fn new(config: SystemdConfig) -> Self {
        Self { config }
    }

    /// Create a manager from the current environment.
    pub fn from_env(user_scope: bool) -> Result<Self> {
        Ok(Self::new(SystemdConfig::from_env(user_scope)?))
    }

    /// Create a manager with sandbox derived from a specific config.
    pub fn from_config(config: &crate::core::config::Config, user_scope: bool) -> Result<Self> {
        Ok(Self::new(SystemdConfig::from_config(config, user_scope)?))
    }

    /// Access the underlying config (for reading unit path, etc.).
    #[must_use]
    pub fn config(&self) -> &SystemdConfig {
        &self.config
    }

    /// Generate the full systemd unit file content.
    #[must_use]
    pub fn generate_unit_file(&self) -> String {
        self.generate_unit_file_with_config(None)
    }

    /// The unit with `--config <path>` on `ExecStart=` when `config` is set.
    /// `reinstall_unit` passes the config the existing unit runs with, so a
    /// repair does not silently switch the daemon to another config file.
    #[must_use]
    pub fn generate_unit_file_with_config(&self, config: Option<&Path>) -> String {
        let binary = systemd_exec_path(&self.config.binary_path, false);
        let rw_paths = SystemdConfig::render_read_write_paths(&self.config.read_write_paths);

        let mut unit = String::with_capacity(2048);

        writeln!(unit, "[Unit]").ok();
        writeln!(
            unit,
            "Description=Storage Ballast Helper - Disk Space Guardian"
        )
        .ok();
        writeln!(
            unit,
            "Documentation=https://github.com/Dicklesworthstone/storage_ballast_helper"
        )
        .ok();
        writeln!(unit, "After=local-fs.target").ok();
        writeln!(unit, "Wants=local-fs.target").ok();
        writeln!(unit).ok();

        writeln!(unit, "[Service]").ok();
        if self.config.user_scope {
            writeln!(unit, "Type=simple").ok();
        } else {
            // The daemon sends READY=1 after its workers are up and the first
            // state file is written (see MonitoringDaemon::run), STOPPING=1 on
            // shutdown, and WATCHDOG=1 heartbeats sized from WATCHDOG_USEC.
            writeln!(unit, "Type=notify").ok();
            writeln!(unit, "NotifyAccess=main").ok();
            writeln!(unit, "TimeoutStartSec=30").ok();
            writeln!(unit, "WatchdogSec=60").ok();
        }

        match config {
            Some(path) => writeln!(
                unit,
                "ExecStart={binary} daemon --config {}",
                systemd_exec_path(path, true)
            )
            .ok(),
            None => writeln!(unit, "ExecStart={binary} daemon").ok(),
        };
        writeln!(unit, "ExecReload=/bin/kill -HUP $MAINPID").ok();
        writeln!(unit, "Restart=on-failure").ok();
        writeln!(unit, "RestartSec=10").ok();
        writeln!(unit, "TimeoutStopSec=30").ok();
        writeln!(unit).ok();

        writeln!(unit, "# Low priority - never compete with build workloads").ok();
        writeln!(unit, "Nice=19").ok();
        writeln!(unit, "IOSchedulingClass=idle").ok();
        writeln!(unit, "IOSchedulingPriority=7").ok();
        writeln!(unit).ok();

        writeln!(unit, "# Security hardening").ok();
        writeln!(unit, "NoNewPrivileges=true").ok();

        if !self.config.user_scope {
            writeln!(unit, "ProtectSystem=strict").ok();
            writeln!(unit, "ReadWritePaths={rw_paths}").ok();
            writeln!(unit, "ProtectHome=false").ok();
            writeln!(unit, "PrivateTmp=false").ok();
            writeln!(unit, "ProtectKernelTunables=true").ok();
            writeln!(unit, "ProtectControlGroups=true").ok();
            writeln!(unit, "RestrictSUIDSGID=true").ok();
            writeln!(unit, "LimitNOFILE=4096").ok();
        }
        writeln!(unit).ok();

        writeln!(unit, "# Resource limits").ok();
        writeln!(unit, "MemoryMax=256M").ok();
        // One core as the runaway backstop; the weight (plus Nice/IO idle)
        // keeps it out of the way of builds. 10% of one core starved every
        // host: throttled in up to 100% of periods, scans timing out at Critical.
        writeln!(unit, "CPUQuota=100%").ok();
        writeln!(unit, "CPUWeight=1").ok();
        // glibc gives each walker thread its own malloc arena and keeps the
        // freed pages: on a 500k-entry tree RSS settled at 480 MiB against
        // ~290 MiB with two arenas, at the same scan CPU (ts2 2026-10-15).
        writeln!(unit, "Environment=MALLOC_ARENA_MAX=2").ok();
        writeln!(unit).ok();

        if !self.config.user_scope {
            writeln!(unit, "# Logging").ok();
            writeln!(unit, "StandardOutput=journal").ok();
            writeln!(unit, "StandardError=journal").ok();
            writeln!(unit, "SyslogIdentifier=sbh").ok();
            writeln!(unit).ok();
        }

        writeln!(unit, "[Install]").ok();
        if self.config.user_scope {
            writeln!(unit, "WantedBy=default.target").ok();
        } else {
            writeln!(unit, "WantedBy=multi-user.target").ok();
        }

        unit
    }

    fn check_binary_ownership(&self) {
        #[cfg(unix)]
        {
            if !self.config.user_scope
                && let Some(warning) = ServiceOwnershipPolicy::systemd_system_binary()
                    .warning_for_binary(&self.config.binary_path)
            {
                warning.print();
            }
        }
    }

    fn systemctl_args(&self, args: &[&str]) -> Vec<String> {
        let mut cmd_args: Vec<String> = Vec::with_capacity(args.len() + 1);
        if self.config.user_scope {
            cmd_args.push("--user".to_string());
        }
        cmd_args.extend(args.iter().map(|s| (*s).to_string()));
        cmd_args
    }

    fn run_systemctl(&self, args: &[&str]) -> Result<String> {
        let full_args = self.systemctl_args(args);
        let output = Command::new("systemctl")
            .args(&full_args)
            .output()
            .map_err(|source| SbhError::Io {
                path: PathBuf::from("systemctl"),
                source,
            })?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        if output.status.success() {
            Ok(stdout.trim().to_string())
        } else {
            Err(SbhError::Runtime {
                details: format_systemctl_failure(
                    &full_args,
                    output.status.code(),
                    &stdout,
                    &stderr,
                    &self.config.unit_path(),
                    self.config.user_scope,
                ),
            })
        }
    }

    fn run_systemctl_lenient(&self, args: &[&str]) -> String {
        let full_args = self.systemctl_args(args);
        let output = Command::new("systemctl").args(&full_args).output();
        match output {
            Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            Err(_) => String::new(),
        }
    }
}

impl ServiceManager for SystemdServiceManager {
    fn install(&self) -> Result<()> {
        validate_systemd_binary(&self.config.binary_path)?;
        self.check_binary_ownership();

        let unit_dir = self.config.unit_dir();
        let unit_path = self.config.unit_path();
        let unit_content = self.generate_unit_file();

        // Namespace setup precedes ExecStart (and ExecStartPre). Prepare the
        // exact grants before publishing/enabling a unit; never broaden them
        // to an existing ancestor or turn off ProtectSystem to make it start.
        if !self.config.user_scope {
            namespace::prepare(&self.config.read_write_paths)?;
        }
        fs::create_dir_all(&unit_dir).map_err(|source| SbhError::Io {
            path: unit_path.clone(),
            source,
        })?;

        fs::write(&unit_path, &unit_content).map_err(|source| SbhError::Io {
            path: unit_path.clone(),
            source,
        })?;

        self.run_systemctl(&["daemon-reload"])?;
        self.run_systemctl(&["enable", SYSTEMD_UNIT_NAME])?;

        Ok(())
    }

    fn uninstall(&self) -> Result<()> {
        let unit_path = self.config.unit_path();

        self.run_systemctl_lenient(&["stop", SYSTEMD_UNIT_NAME]);
        self.run_systemctl_lenient(&["disable", SYSTEMD_UNIT_NAME]);

        if unit_path.exists() {
            fs::remove_file(&unit_path).map_err(|source| SbhError::Io {
                path: unit_path.clone(),
                source,
            })?;
        }

        self.run_systemctl(&["daemon-reload"])?;

        Ok(())
    }

    fn status(&self) -> Result<String> {
        let state = self.run_systemctl_lenient(&["is-active", SYSTEMD_UNIT_NAME]);
        if state.is_empty() {
            return Ok("unknown".to_string());
        }
        Ok(state)
    }

    fn watchdog_enabled(&self, watchdog_sec: u64) -> bool {
        let socket_path = systemd_notify_socket();
        systemd_watchdog_enabled(watchdog_sec, socket_path.as_deref())
    }

    fn notify_watchdog(&self, status: &str) -> Result<()> {
        if let Some(socket_path) = systemd_notify_socket() {
            sd_notify_watchdog(status, &socket_path)?;
        }
        Ok(())
    }

    fn notify_ready(&self) -> Result<()> {
        let Some(socket_path) = systemd_notify_socket() else {
            return Ok(());
        };
        sd_notify_send(&sd_ready_message(std::process::id()), &socket_path).map_err(|source| {
            SbhError::Io {
                path: PathBuf::from(socket_path),
                source,
            }
        })
    }

    fn notify_stopping(&self) -> Result<()> {
        let Some(socket_path) = systemd_notify_socket() else {
            return Ok(());
        };
        sd_notify_send(SD_STOPPING_MESSAGE, &socket_path).map_err(|source| SbhError::Io {
            path: PathBuf::from(socket_path),
            source,
        })
    }

    fn notify_extend_startup(&self, extend_by: std::time::Duration, status: &str) -> Result<()> {
        let Some(socket_path) = systemd_notify_socket() else {
            return Ok(());
        };
        sd_notify_send(&sd_extend_timeout_message(extend_by, status), &socket_path).map_err(
            |source| SbhError::Io {
                path: PathBuf::from(socket_path),
                source,
            },
        )
    }

    fn restart(&self) -> Result<()> {
        load_state::restart(self.config.user_scope, || {
            self.run_systemctl(&["restart", SYSTEMD_UNIT_NAME])
                .map(|_| ())
        })
    }

    fn logs_path(&self) -> Result<Option<PathBuf>> {
        Ok(None)
    }

    fn is_loaded(&self) -> Result<bool> {
        load_state::is_loaded(self.config.user_scope, &self.config.unit_path())
    }
}

fn systemd_notify_socket() -> Option<String> {
    env::var("NOTIFY_SOCKET")
        .ok()
        .filter(|path| !path.is_empty())
}

fn systemd_watchdog_enabled(watchdog_sec: u64, socket_path: Option<&str>) -> bool {
    watchdog_sec > 0 && socket_path.is_some_and(|path| !path.is_empty())
}

/// `sd_notify(3)` message sent once shutdown begins.
pub const SD_STOPPING_MESSAGE: &str = "STOPPING=1\n";

/// `sd_notify(3)` readiness message. `MAINPID=` is included so a supervisor
/// that lost track of the main process (re-exec, `--background`) re-learns it.
#[must_use]
pub fn sd_ready_message(pid: u32) -> String {
    format!("READY=1\nMAINPID={pid}\n")
}

/// `sd_notify(3)` message extending the current start timeout to at least
/// `extend_by` from now (systemd 236+; older managers ignore it).
#[must_use]
pub fn sd_extend_timeout_message(extend_by: std::time::Duration, status: &str) -> String {
    format!(
        "EXTEND_TIMEOUT_USEC={}\nSTATUS={status}\n",
        extend_by.as_micros()
    )
}

/// `sd_notify(3)` watchdog heartbeat message.
#[must_use]
pub fn sd_watchdog_message(status: &str) -> String {
    format!("WATCHDOG=1\nSTATUS={status}\n")
}

fn sd_notify_watchdog(status: &str, socket_path: &str) -> Result<()> {
    sd_notify_send(&sd_watchdog_message(status), socket_path).map_err(|source| SbhError::Io {
        path: PathBuf::from(socket_path),
        source,
    })
}

/// Send one `sd_notify(3)` datagram to `socket_path`.
///
/// Supports filesystem sockets and Linux abstract sockets (`NOTIFY_SOCKET`
/// values starting with `@`, which systemd uses for some user managers).
/// Non-Linux platforms have no notify socket and report success without
/// sending anything.
#[cfg_attr(not(target_os = "linux"), allow(clippy::unnecessary_wraps))]
pub fn sd_notify_send(message: &str, socket_path: &str) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::linux::net::SocketAddrExt as _;
        use std::os::unix::net::{SocketAddr, UnixDatagram};

        let sock = UnixDatagram::unbound()?;
        if let Some(abstract_name) = socket_path.strip_prefix('@') {
            let addr = SocketAddr::from_abstract_name(abstract_name.as_bytes())?;
            sock.send_to_addr(message.as_bytes(), &addr)?;
        } else {
            sock.send_to(message.as_bytes(), socket_path)?;
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (message, socket_path);
        Ok(())
    }
}

fn format_systemctl_failure(
    args: &[String],
    exit_code: Option<i32>,
    stdout: &str,
    stderr: &str,
    unit_path: &std::path::Path,
    user_scope: bool,
) -> String {
    let status_command = if user_scope {
        format!("systemctl --user status {SYSTEMD_UNIT_NAME}")
    } else {
        format!("sudo systemctl status {SYSTEMD_UNIT_NAME}")
    };
    let journal_command = if user_scope {
        format!("journalctl --user -u {SYSTEMD_UNIT_NAME} -n 100 --no-pager")
    } else {
        format!("sudo journalctl -u {SYSTEMD_UNIT_NAME} -n 100 --no-pager")
    };
    format!(
        "{} failed with exit {}. stdout: {}; stderr: {}. \
         Verify the unit with: systemd-analyze verify {}. \
         Inspect service state with: {status_command}. \
         Inspect recent logs with: {journal_command}.",
        format_systemctl_command(args),
        exit_code.map_or_else(|| "signal".to_string(), |code| code.to_string()),
        compact_command_output(stdout),
        compact_command_output(stderr),
        systemd_shell_quote(&unit_path.display().to_string()),
    )
}

fn format_systemctl_command(args: &[String]) -> String {
    std::iter::once("systemctl")
        .chain(args.iter().map(String::as_str))
        .map(systemd_shell_quote)
        .collect::<Vec<_>>()
        .join(" ")
}

fn systemd_shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    if value.chars().all(|ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-' | ':' | '@' | '%' | '+')
    }) {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn compact_command_output(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "<empty>".to_string();
    }
    let mut lines = trimmed.lines();
    let mut rendered = lines.by_ref().take(6).collect::<Vec<_>>().join("\\n");
    if lines.next().is_some() {
        rendered.push_str("\\n...");
    }
    rendered
}

fn default_read_write_paths(user_scope: bool) -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("/tmp"), PathBuf::from("/var/tmp")];
    if user_scope {
        if let Some(home) = env::var_os("HOME") {
            let home = PathBuf::from(home);
            paths.push(home.join(".local/share/sbh"));
            paths.push(home.join(".config/sbh"));
        }
    } else {
        paths.push(PathBuf::from("/var/lib/sbh"));
        let root_home = Path::new("/root");
        if root_home.is_dir() {
            paths.push(root_home.join(".local/share/sbh"));
            paths.push(root_home.join(".config/sbh"));
        }
    }
    for candidate in ["/data", "/data/tmp"] {
        let p = PathBuf::from(candidate);
        if p.is_dir() {
            paths.push(p);
        }
    }
    paths
}

/// `SBH_SYSTEMD_UNIT_DIR`, honored only under `SBH_TEST_MODE=1`.
pub fn test_unit_dir_override() -> Option<PathBuf> {
    if !crate::platform::test_overlay::test_mode_requested() {
        return None;
    }
    env::var_os("SBH_SYSTEMD_UNIT_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

// ──────────────────── unit drift ────────────────────

/// Directives whose absence or change means the unit is not the one sbh
/// ships: the process type and its supervision, the priority and sandbox
/// hardening, and the resource caps. Anything else that differs is a
/// warning.
const HARDENING_DIRECTIVES: &[&str] = &[
    "Service/Type",
    "Service/NotifyAccess",
    "Service/WatchdogSec",
    "Service/Restart",
    "Service/Nice",
    "Service/IOSchedulingClass",
    "Service/IOSchedulingPriority",
    "Service/NoNewPrivileges",
    "Service/ProtectSystem",
    "Service/ReadWritePaths",
    "Service/ProtectKernelTunables",
    "Service/ProtectControlGroups",
    "Service/RestrictSUIDSGID",
    "Service/MemoryMax",
    "Service/CPUQuota",
    "Service/CPUWeight",
];

/// Directives that legitimately differ between hosts (paths, wording) and
/// are never reported.
const IGNORED_DIRECTIVES: &[&str] = &["Unit/Description", "Unit/Documentation"];

/// Keys whose values are whitespace-separated lists compared as sets.
const SET_VALUED_DIRECTIVES: &[&str] = &["Service/ReadWritePaths", "Service/ReadOnlyPaths"];

/// Parse unit-file text into `Section/Key -> values`.
///
/// Every occurrence of a key is kept, in order; an empty assignment resets
/// the key as systemd does. Comments and blank lines are skipped; keys
/// outside a section are filed under an empty section name.
#[must_use]
pub fn parse_unit_directives(text: &str) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut section = String::new();
    let mut directives: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            section = name.trim().to_string();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let full = format!("{section}/{}", key.trim());
        let value = value.trim().to_string();
        let entry = directives.entry(full).or_default();
        if value.is_empty() {
            entry.clear();
        } else {
            entry.push(value);
        }
    }
    directives
}

/// A directive whose installed value differs from the generated one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DirectiveChange {
    /// `Section/Key`.
    pub directive: String,
    /// Every value the installed unit (with its drop-ins) assigns.
    pub installed: Vec<String>,
    /// Every value the generated unit assigns.
    pub generated: Vec<String>,
    /// Whether the directive is part of the hardening contract.
    pub hardening: bool,
}

/// A drop-in file sbh did not write, and the directives it sets.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ForeignDropIn {
    /// The `*.conf` file.
    pub path: PathBuf,
    /// `Section/Key` of every directive it sets.
    pub directives: Vec<String>,
    /// Whether it overrides a hardening directive (a `Type=` or sandbox
    /// change through a drop-in is as bad as one in the unit).
    pub overrides_hardening: bool,
}

/// A `Condition*=` / `Assert*=` directive that can keep the unit from
/// starting.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ConditionGate {
    /// The unit file or drop-in that sets it.
    pub source: PathBuf,
    /// The directive as written, e.g. `ConditionPathExists=!/etc/sbh/HOTLOOP_DISABLED`.
    pub directive: String,
    /// `Some(true)` when the gate currently blocks the unit, `Some(false)`
    /// when it currently passes, `None` when sbh cannot evaluate it.
    pub blocking: Option<bool>,
}

/// How the installed unit differs from what sbh generates.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct UnitDrift {
    /// The unit file that was compared.
    pub unit_path: PathBuf,
    /// Generated directives the installed unit (with its drop-ins) lacks.
    pub missing_directives: Vec<String>,
    /// Directives present on both sides with different values.
    pub changed_directives: Vec<DirectiveChange>,
    /// Directives the installed unit sets that sbh never generates.
    pub extra_directives: Vec<String>,
    /// Drop-ins extending the unit (sbh writes none).
    pub foreign_dropins: Vec<ForeignDropIn>,
    /// Every `Condition*=` / `Assert*=` found, with its current effect.
    pub condition_gates: Vec<ConditionGate>,
    /// Whether `ExecStart=` runs the same binary path.
    pub exec_start_matches: bool,
}

/// The verdict `doctor --service` reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DriftSeverity {
    /// The installed unit is what sbh generates.
    Pass,
    /// Cosmetic or additive differences only.
    Warn,
    /// Missing hardening, a different binary, or a blocking gate.
    Fail,
}

impl UnitDrift {
    /// Compare `installed` (plus its `dropins`, applied in order) with the
    /// unit sbh would `generated` now.
    #[must_use]
    pub fn compute(
        unit_path: &Path,
        installed: &str,
        generated: &str,
        dropins: &[(PathBuf, String)],
    ) -> Self {
        let generated_directives = parse_unit_directives(generated);
        let mut effective = parse_unit_directives(installed);
        let mut foreign_dropins = Vec::new();
        let mut condition_gates = condition_gates_in(unit_path, &parse_unit_directives(installed));
        for (path, text) in dropins {
            let directives = parse_unit_directives(text);
            condition_gates.extend(condition_gates_in(path, &directives));
            foreign_dropins.push(ForeignDropIn {
                path: path.clone(),
                overrides_hardening: directives
                    .keys()
                    .any(|key| HARDENING_DIRECTIVES.contains(&key.as_str())),
                directives: directives.keys().cloned().collect(),
            });
            for (key, values) in directives {
                // Drop-ins override single values and extend list values,
                // which is what systemd does for the keys we compare.
                if SET_VALUED_DIRECTIVES.contains(&key.as_str()) {
                    effective.entry(key).or_default().extend(values);
                } else {
                    effective.insert(key, values);
                }
            }
        }

        let mut missing_directives = Vec::new();
        let mut changed_directives = Vec::new();
        for (directive, generated_values) in &generated_directives {
            if IGNORED_DIRECTIVES.contains(&directive.as_str()) || directive == "Service/ExecStart"
            {
                continue;
            }
            match effective.get(directive) {
                None => missing_directives.push(directive.clone()),
                Some(installed_values) => {
                    if !directive_values_equal(directive, installed_values, generated_values) {
                        changed_directives.push(DirectiveChange {
                            directive: directive.clone(),
                            installed: installed_values.clone(),
                            generated: generated_values.clone(),
                            hardening: HARDENING_DIRECTIVES.contains(&directive.as_str()),
                        });
                    }
                }
            }
        }
        let extra_directives = effective
            .keys()
            .filter(|key| {
                !generated_directives.contains_key(*key)
                    && !IGNORED_DIRECTIVES.contains(&key.as_str())
                    && !is_condition_directive(key)
            })
            .cloned()
            .collect();

        let exec_start_matches = match (
            exec_start_binary(&effective),
            exec_start_binary(&generated_directives),
        ) {
            (Some(installed), Some(generated)) => installed == generated,
            _ => false,
        };

        Self {
            unit_path: unit_path.to_path_buf(),
            missing_directives,
            changed_directives,
            extra_directives,
            foreign_dropins,
            condition_gates,
            exec_start_matches,
        }
    }

    /// Hardening directives that are missing or changed, `Section/Key`.
    #[must_use]
    pub fn hardening_gaps(&self) -> Vec<String> {
        let mut gaps: Vec<String> = self
            .missing_directives
            .iter()
            .filter(|directive| HARDENING_DIRECTIVES.contains(&directive.as_str()))
            .cloned()
            .collect();
        gaps.extend(
            self.changed_directives
                .iter()
                .filter(|change| change.hardening)
                .map(|change| change.directive.clone()),
        );
        gaps
    }

    /// Gates that currently keep the unit from starting.
    #[must_use]
    pub fn blocking_gates(&self) -> Vec<&ConditionGate> {
        self.condition_gates
            .iter()
            .filter(|gate| gate.blocking == Some(true))
            .collect()
    }

    /// FAIL for a hardening gap, a different binary, or a blocking gate;
    /// WARN for anything else that differs; PASS when nothing does.
    #[must_use]
    pub fn severity(&self) -> DriftSeverity {
        if !self.hardening_gaps().is_empty()
            || !self.exec_start_matches
            || !self.blocking_gates().is_empty()
            || self.foreign_dropins.iter().any(|d| d.overrides_hardening)
        {
            DriftSeverity::Fail
        } else if !self.missing_directives.is_empty()
            || !self.changed_directives.is_empty()
            || !self.extra_directives.is_empty()
            || !self.foreign_dropins.is_empty()
            || !self.condition_gates.is_empty()
        {
            DriftSeverity::Warn
        } else {
            DriftSeverity::Pass
        }
    }

    /// True when the installed unit is exactly what sbh generates.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.severity() == DriftSeverity::Pass
    }
}

fn is_condition_directive(directive: &str) -> bool {
    directive
        .rsplit_once('/')
        .is_some_and(|(_, key)| key.starts_with("Condition") || key.starts_with("Assert"))
}

fn condition_gates_in(
    source: &Path,
    directives: &std::collections::BTreeMap<String, Vec<String>>,
) -> Vec<ConditionGate> {
    let mut gates = Vec::new();
    for (directive, values) in directives {
        if !is_condition_directive(directive) {
            continue;
        }
        let key = directive
            .rsplit_once('/')
            .map_or(directive.as_str(), |(_, k)| k);
        for value in values {
            gates.push(ConditionGate {
                source: source.to_path_buf(),
                directive: format!("{key}={value}"),
                blocking: evaluate_condition(key, value),
            });
        }
    }
    gates
}

/// Evaluate the path conditions sbh understands; `None` for the rest.
fn evaluate_condition(key: &str, value: &str) -> Option<bool> {
    let (negated, target) = value
        .strip_prefix('!')
        .map_or((false, value), |rest| (true, rest));
    let target = target.trim_start_matches('|');
    // Globs, users, kernel versions and the rest are reported but not
    // evaluated.
    let holds = match key {
        "ConditionPathExists" | "AssertPathExists" => Path::new(target).exists(),
        "ConditionPathIsDirectory" | "AssertPathIsDirectory" => Path::new(target).is_dir(),
        _ => return None,
    };
    Some(holds == negated)
}

fn directive_values_equal(directive: &str, installed: &[String], generated: &[String]) -> bool {
    if SET_VALUED_DIRECTIVES.contains(&directive) {
        let split = |values: &[String]| -> std::collections::BTreeSet<String> {
            values
                .iter()
                .flat_map(|value| SystemdConfig::parse_read_write_paths(value))
                .map(|path| path.display().to_string())
                .collect()
        };
        return split(installed) == split(generated);
    }
    match (installed.last(), generated.last()) {
        (Some(a), Some(b)) => {
            a == b
                || matches!(
                    (percent_value(a), percent_value(b)),
                    (Some(x), Some(y)) if (x - y).abs() < f64::EPSILON
                )
        }
        (None, None) => true,
        _ => false,
    }
}

/// `10%` and `10.00%` (what `systemctl set-property` writes) are the same
/// quota.
fn percent_value(value: &str) -> Option<f64> {
    value.strip_suffix('%')?.trim().parse::<f64>().ok()
}

fn exec_start_binary(
    directives: &std::collections::BTreeMap<String, Vec<String>>,
) -> Option<Vec<u8>> {
    let commands = directives.get("Service/ExecStart")?;
    // Multiple commands cannot establish one executable identity.
    let [command] = commands.as_slice() else {
        return None;
    };
    let (word, _) = take_systemd_word(command)?;
    let prefix_len = word
        .iter()
        .take_while(|byte| b"-@:+!".contains(byte))
        .count();
    let binary = literal_systemd_word(&word[prefix_len..], false)?;
    (!binary.is_empty()).then_some(binary)
}

/// What `reinstall-unit` did.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReinstallReport {
    /// The unit file that was written.
    pub unit_path: PathBuf,
    /// Copy of the unit that was replaced, if one existed.
    pub backup_path: Option<PathBuf>,
    /// Drop-ins moved aside (with `purge_dropins`), `(from, to)`.
    pub dropins_moved: Vec<(PathBuf, PathBuf)>,
    /// Drop-ins left in place.
    pub dropins_kept: Vec<PathBuf>,
    /// Whether the written unit differs from what was installed before.
    pub changed: bool,
    /// Whether `systemctl daemon-reload` ran (it is skipped under the test
    /// unit-dir override).
    pub daemon_reloaded: bool,
}

impl SystemdServiceManager {
    /// Compare the installed unit and its drop-ins with what sbh would
    /// generate now. Errors when no unit is installed or a required sandbox
    /// path cannot be resolved; the latter names the 226/NAMESPACE blocker.
    pub fn drift_report(&self) -> Result<UnitDrift> {
        let unit_path = self.config.unit_path();
        let installed = fs::read_to_string(&unit_path).map_err(|source| SbhError::Io {
            path: unit_path.clone(),
            source,
        })?;
        let dropins = self.config.read_dropins();
        namespace::validate_unit(&installed, &dropins)?;
        Ok(UnitDrift::compute(
            &unit_path,
            &installed,
            &self.generate_unit_file(),
            &dropins,
        ))
    }

    /// Replace the installed unit with the generated one, keeping a
    /// timestamped backup beside it. Drop-ins are never deleted: with
    /// `purge_dropins` they are moved into the backup directory, otherwise
    /// they stay and keep applying.
    pub fn reinstall_unit(&self, purge_dropins: bool) -> Result<ReinstallReport> {
        validate_systemd_binary(&self.config.binary_path)?;
        let unit_path = self.config.unit_path();
        let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
        let backup_path = unit_path.with_file_name(format!("{SYSTEMD_UNIT_NAME}.bak-{stamp}"));
        // Keep the config the unit runs with: a fleet unit's
        // `--config /root/.config/sbh/config.toml` dropped by a repair made the
        // daemon load /etc/sbh/config.toml instead (vmi1152480, 2026-09-25).
        let previous = match fs::read_to_string(&unit_path) {
            Ok(text) => Some(text),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(source) => {
                return Err(SbhError::Io {
                    path: unit_path,
                    source,
                });
            }
        };
        let dropins = self.config.read_dropins();
        let preserved_config = preserved_unit_config(previous.as_deref().unwrap_or(""), &dropins)?;
        let generated = self.generate_unit_file_with_config(preserved_config.as_deref());
        // The repair path needs the same preparation as a fresh install.
        // Failure must leave the existing unit and its drop-ins untouched.
        if !self.config.user_scope {
            namespace::prepare(&self.config.read_write_paths)?;
        }

        let backup_path = if previous.is_some() {
            fs::copy(&unit_path, &backup_path).map_err(|source| SbhError::Io {
                path: backup_path.clone(),
                source,
            })?;
            Some(backup_path)
        } else {
            None
        };
        let changed = previous.as_deref() != Some(generated.as_str());
        if let Some(parent) = unit_path.parent() {
            fs::create_dir_all(parent).map_err(|source| SbhError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        fs::write(&unit_path, &generated).map_err(|source| SbhError::Io {
            path: unit_path.clone(),
            source,
        })?;

        let mut dropins_moved = Vec::new();
        let mut dropins_kept = Vec::new();
        for (path, _) in dropins {
            if purge_dropins {
                let aside_dir =
                    unit_path.with_file_name(format!("{SYSTEMD_UNIT_NAME}.bak-{stamp}.d"));
                fs::create_dir_all(&aside_dir).map_err(|source| SbhError::Io {
                    path: aside_dir.clone(),
                    source,
                })?;
                let name = path.file_name().map_or_else(
                    || "dropin.conf".to_string(),
                    |n| n.to_string_lossy().into_owned(),
                );
                let mut target = aside_dir.join(&name);
                if target.exists() {
                    target = aside_dir.join(format!(
                        "{}-{name}",
                        path.parent().and_then(Path::file_name).map_or_else(
                            || "dir".to_string(),
                            |d| d.to_string_lossy().into_owned()
                        )
                    ));
                }
                fs::rename(&path, &target).map_err(|source| SbhError::Io {
                    path: path.clone(),
                    source,
                })?;
                dropins_moved.push((path, target));
            } else {
                dropins_kept.push(path);
            }
        }

        let daemon_reloaded = if test_unit_dir_override().is_some() {
            false
        } else {
            self.run_systemctl(&["daemon-reload"])?;
            true
        };

        Ok(ReinstallReport {
            unit_path,
            backup_path,
            dropins_moved,
            dropins_kept,
            changed,
            daemon_reloaded,
        })
    }
}

// systemd ExecStart words are not shell words. Percent specifiers are expanded
// even inside quotes. Environment expansion applies to arguments, not the
// executable path, so doubling '$' in the executable selects the wrong file.
fn systemd_exec_path(path: &Path, argument: bool) -> String {
    let bytes = path.as_os_str().as_encoded_bytes();
    if !bytes.is_empty()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/._-:@+".contains(byte))
    {
        return path.to_string_lossy().into_owned();
    }
    let mut quoted = String::from("\"");
    for &byte in bytes {
        match byte {
            b'"' => quoted.push_str("\\\""),
            b'\\' => quoted.push_str("\\\\"),
            b'%' => quoted.push_str("%%"),
            b'$' if argument => quoted.push_str("$$"),
            b' '..=b'~' => quoted.push(char::from(byte)),
            _ => {
                let _ = write!(quoted, "\\x{byte:02x}");
            }
        }
    }
    quoted.push('"');
    quoted
}

// systemd rejects these characters in the executable itself even when they
// are escaped. Refuse before overwriting a working unit, rather than emitting
// a unit that can never start. Config arguments may contain escaped quotes.
fn validate_systemd_binary(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .copied()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'"' | b'\'' | b'\\'))
    {
        return Err(SbhError::Runtime {
            details: format!(
                "systemd requires an absolute executable path without control characters, quotes or backslashes: {}; move sbh to a supported installation path",
                path.display()
            ),
        });
    }
    Ok(())
}

// Read a whole systemd word, preserving native path bytes. Inconclusive syntax
// is not evidence of matching binaries. Only the C escapes systemd documents
// are accepted; this parser never invokes a shell or expands the environment.
fn take_systemd_word(input: &str) -> Option<(Vec<u8>, &str)> {
    let input = input.trim_start_matches(|ch: char| ch.is_ascii_whitespace());
    let mut chars = input.char_indices().peekable();
    chars.peek()?;
    let mut word = Vec::new();
    let mut quote = None;
    while let Some((index, ch)) = chars.next() {
        match ch {
            '\'' | '"' if quote == Some(ch) => quote = None,
            '\'' | '"' if quote.is_none() => quote = Some(ch),
            ch if ch.is_ascii_whitespace() && quote.is_none() => {
                return Some((word, &input[index..]));
            }
            '\\' => {
                let (_, escape) = chars.next()?;
                let byte = match escape {
                    'a' => 7,
                    'b' => 8,
                    'f' => 12,
                    'n' => b'\n',
                    'r' => b'\r',
                    't' => b'\t',
                    'v' => 11,
                    's' => b' ',
                    '\\' => b'\\',
                    '\'' => b'\'',
                    '"' => b'"',
                    'x' | 'u' | 'U' | '0'..='7' => {
                        let (radix, digits, mut value) = match escape {
                            'x' => (16, 2, 0u32),
                            'u' => (16, 4, 0),
                            'U' => (16, 8, 0),
                            digit => (8, 2, digit.to_digit(8)?),
                        };
                        for _ in 0..digits {
                            value = value
                                .checked_mul(radix)?
                                .checked_add(chars.next()?.1.to_digit(radix)?)?;
                        }
                        if matches!(escape, 'u' | 'U') {
                            let mut buffer = [0; 4];
                            word.extend_from_slice(
                                char::from_u32(value)?.encode_utf8(&mut buffer).as_bytes(),
                            );
                            continue;
                        }
                        u8::try_from(value).ok()?
                    }
                    _ => return None,
                };
                word.push(byte);
            }
            ch => {
                let mut buffer = [0; 4];
                word.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    quote.is_none().then_some((word, ""))
}

fn literal_systemd_word(word: &[u8], argument: bool) -> Option<Vec<u8>> {
    let mut literal = Vec::with_capacity(word.len());
    let mut bytes = word.iter().copied();
    while let Some(byte) = bytes.next() {
        if (byte == b'%' || (argument && byte == b'$')) && bytes.next()? != byte {
            // A real specifier/environment reference needs manager context.
            return None;
        }
        if byte == 0 {
            return None;
        }
        literal.push(byte);
    }
    Some(literal)
}

// Preserve the effective config before any backup or unit write. Silently
// dropping a quoted/dynamic config can restart a guardian with different scan
// roots and cleanup policy. Unresolvable config syntax must stop the repair.
fn preserved_unit_config(
    installed: &str,
    dropins: &[(PathBuf, String)],
) -> Result<Option<PathBuf>> {
    let key = "Service/ExecStart";
    let mut directives = parse_unit_directives(installed);
    for (_, text) in dropins {
        if let Some(commands) = parse_unit_directives(text).remove(key) {
            directives.insert(key.to_string(), commands);
        }
    }
    let invalid = || {
        SbhError::Runtime {
        details: "cannot preserve the installed systemd --config path; refusing to rewrite the unit; use one absolute literal config path without environment or unit specifiers".to_string(),
    }
    };
    let Some(commands) = directives.get(key) else {
        return Ok(None);
    };
    if commands.is_empty() {
        return Ok(None);
    }
    let [command] = commands.as_slice() else {
        return Err(invalid());
    };
    let (executable, mut rest) = take_systemd_word(command).ok_or_else(invalid)?;
    let prefix_len = executable
        .iter()
        .take_while(|byte| b"-@:+!".contains(byte))
        .count();
    let expand_environment = !executable[..prefix_len].contains(&b':');
    if executable[..prefix_len].contains(&b'@') {
        // With '@', the next word is argv[0], not a daemon option.
        rest = take_systemd_word(rest).ok_or_else(invalid)?.1;
    }
    let mut config = None;
    while !rest.trim().is_empty() {
        let (word, tail) = take_systemd_word(rest).ok_or_else(invalid)?;
        rest = tail;
        if word == b";" {
            return Err(invalid());
        }
        let value = if word == b"--config" {
            let (value, tail) = take_systemd_word(rest).ok_or_else(invalid)?;
            rest = tail;
            Some(value)
        } else {
            word.strip_prefix(b"--config=").map(<[u8]>::to_vec)
        };
        if let Some(value) = value {
            if config.is_some() {
                return Err(invalid());
            }
            let bytes = literal_systemd_word(&value, expand_environment).ok_or_else(invalid)?;
            #[cfg(unix)]
            let path = {
                use std::os::unix::ffi::OsStringExt;
                PathBuf::from(std::ffi::OsString::from_vec(bytes))
            };
            #[cfg(not(unix))]
            let path = PathBuf::from(String::from_utf8(bytes).map_err(|_| invalid())?);
            if !path.is_absolute() {
                return Err(invalid());
            }
            config = Some(path);
        }
    }
    Ok(config)
}

#[cfg(test)]
mod unit_drift_tests {
    use super::*;

    /// This host's hand-written unit, verbatim (2026-09-02).
    const HOST_UNIT: &str = "[Unit]\nDescription=Storage Ballast Helper daemon\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/usr/local/bin/sbh daemon --config /etc/sbh/config.toml\nRestart=always\nRestartSec=10\nTimeoutStopSec=30\nExecStartPre=/bin/mkdir -p /var/lib/sbh\nUMask=0022\n\n[Install]\nWantedBy=multi-user.target\n";

    fn manager() -> SystemdServiceManager {
        SystemdServiceManager::new(SystemdConfig {
            user_scope: false,
            binary_path: PathBuf::from("/usr/local/bin/sbh"),
            read_write_paths: vec![PathBuf::from("/tmp"), PathBuf::from("/var/lib/sbh")],
        })
    }

    fn host_dropins(gate_path: &Path) -> Vec<(PathBuf, String)> {
        vec![
            (
                PathBuf::from("/etc/systemd/system/sbh.service.d/10-scanner-v2.conf"),
                "[Service]\nEnvironment=SBH_SCANNER_ENGINE=v2\n".to_string(),
            ),
            (
                PathBuf::from("/etc/systemd/system/sbh.service.d/hotloop-guard.conf"),
                format!("[Unit]\nConditionPathExists=!{}\n", gate_path.display()),
            ),
            (
                PathBuf::from("/etc/systemd/system.control/sbh.service.d/50-CPUQuota.conf"),
                "# created via systemctl set-property\n[Service]\nCPUQuota=100.00%\n".to_string(),
            ),
            (
                PathBuf::from("/etc/systemd/system.control/sbh.service.d/50-CPUWeight.conf"),
                "# created via systemctl set-property\n[Service]\nCPUWeight=1\n".to_string(),
            ),
        ]
    }

    #[test]
    fn parser_keeps_sections_multiple_values_and_resets() {
        let parsed = parse_unit_directives(
            "# comment\n[Unit]\nAfter=a.target\nAfter=b.target\n[Service]\nReadWritePaths=/a /b\nReadWritePaths=\nReadWritePaths=/c\nType = notify\n",
        );
        assert_eq!(parsed["Unit/After"], vec!["a.target", "b.target"]);
        assert_eq!(parsed["Service/ReadWritePaths"], vec!["/c"]);
        assert_eq!(parsed["Service/Type"], vec!["notify"]);
    }

    #[test]
    fn generated_unit_has_no_drift_against_itself() {
        let manager = manager();
        let generated = manager.generate_unit_file();
        let drift = UnitDrift::compute(
            Path::new("/etc/systemd/system/sbh.service"),
            &generated,
            &generated,
            &[],
        );
        assert!(drift.is_clean(), "{drift:?}");
        assert!(drift.exec_start_matches);
    }

    #[test]
    fn generated_units_cap_glibc_malloc_arenas_in_both_scopes() {
        for user_scope in [false, true] {
            let mut manager = manager();
            manager.config.user_scope = user_scope;
            let directives = parse_unit_directives(&manager.generate_unit_file());
            assert_eq!(
                directives.get("Service/Environment"),
                Some(&vec!["MALLOC_ARENA_MAX=2".to_string()]),
                "user_scope={user_scope}"
            );
        }
    }

    #[test]
    fn read_write_paths_compare_as_sets() {
        let manager = manager();
        let generated = manager.generate_unit_file();
        let reordered = generated.replace(
            "ReadWritePaths=/tmp /var/lib/sbh",
            "ReadWritePaths=/var/lib/sbh /tmp",
        );
        assert_ne!(generated, reordered, "fixture must actually reorder");
        let drift = UnitDrift::compute(Path::new("/x/sbh.service"), &reordered, &generated, &[]);
        assert!(drift.is_clean(), "{drift:?}");
    }

    #[test]
    fn host_unit_fails_with_the_exact_hardening_gaps_and_gates() {
        let dir = tempfile::tempdir().unwrap();
        let gate = dir.path().join("HOTLOOP_DISABLED");
        std::fs::write(&gate, b"").unwrap();
        let manager = manager();
        let drift = UnitDrift::compute(
            Path::new("/etc/systemd/system/sbh.service"),
            HOST_UNIT,
            &manager.generate_unit_file(),
            &host_dropins(&gate),
        );
        assert_eq!(drift.severity(), DriftSeverity::Fail);
        assert!(drift.exec_start_matches, "same binary path");
        let gaps = drift.hardening_gaps();
        for expected in [
            "Service/Type",
            "Service/NotifyAccess",
            "Service/WatchdogSec",
            "Service/Restart",
            "Service/Nice",
            "Service/IOSchedulingClass",
            "Service/NoNewPrivileges",
            "Service/ProtectSystem",
            "Service/ReadWritePaths",
            "Service/MemoryMax",
        ] {
            assert!(
                gaps.contains(&expected.to_string()),
                "{expected} missing from {gaps:?}"
            );
        }
        // CPUQuota and CPUWeight are supplied by set-property drop-ins, so
        // they are not gaps.
        assert!(!gaps.contains(&"Service/CPUQuota".to_string()), "{gaps:?}");
        assert!(!gaps.contains(&"Service/CPUWeight".to_string()), "{gaps:?}");
        let type_change = drift
            .changed_directives
            .iter()
            .find(|c| c.directive == "Service/Type")
            .expect("Type differs");
        assert_eq!(type_change.installed, vec!["simple"]);
        assert_eq!(type_change.generated, vec!["notify"]);
        assert!(
            drift
                .extra_directives
                .contains(&"Service/UMask".to_string())
        );
        assert_eq!(drift.foreign_dropins.len(), 4);
        assert!(
            drift.foreign_dropins.iter().any(|d| d.overrides_hardening),
            "CPUQuota drop-in"
        );
        let gates = drift.blocking_gates();
        assert_eq!(gates.len(), 1, "{:?}", drift.condition_gates);
        assert!(gates[0].directive.starts_with("ConditionPathExists=!"));

        // Remove the kill switch: the gate passes, the unit still fails on hardening.
        std::fs::remove_file(&gate).unwrap();
        let drift = UnitDrift::compute(
            Path::new("/etc/systemd/system/sbh.service"),
            HOST_UNIT,
            &manager.generate_unit_file(),
            &host_dropins(&gate),
        );
        assert!(drift.blocking_gates().is_empty());
        assert_eq!(drift.condition_gates.len(), 1);
        assert_eq!(drift.severity(), DriftSeverity::Fail);
    }

    #[test]
    fn a_limits_only_dropin_is_a_warning_not_a_failure() {
        let manager = manager();
        let generated = manager.generate_unit_file();
        let dropins = vec![(
            PathBuf::from("/etc/systemd/system/sbh.service.d/env.conf"),
            "[Service]\nEnvironment=RUST_LOG=info\n".to_string(),
        )];
        let drift = UnitDrift::compute(
            Path::new("/x/sbh.service"),
            &generated,
            &generated,
            &dropins,
        );
        assert_eq!(drift.severity(), DriftSeverity::Warn);
        assert!(!drift.foreign_dropins[0].overrides_hardening);
    }

    #[test]
    fn a_different_binary_path_fails() {
        let manager = manager();
        let generated = manager.generate_unit_file();
        let moved = generated.replace("ExecStart=/usr/local/bin/sbh", "ExecStart=/opt/sbh/bin/sbh");
        let drift = UnitDrift::compute(Path::new("/x/sbh.service"), &moved, &generated, &[]);
        assert!(!drift.exec_start_matches);
        assert_eq!(drift.severity(), DriftSeverity::Fail);
    }
}

#[cfg(test)]
mod read_write_paths_tests {
    use super::*;
    use crate::core::config::{BallastVolumeOverride, Config};

    fn sample_config() -> Config {
        let mut config = Config::default();
        config.scanner.root_paths = vec![
            PathBuf::from("/data/projects"),
            PathBuf::from("/srv/builds with space"),
        ];
        config.paths.ballast_dir = PathBuf::from("/var/lib/sbh/ballast");
        config.paths.state_file = PathBuf::from("/var/lib/sbh/state.json");
        config.paths.sqlite_db = PathBuf::from("/var/lib/sbh/activity.sqlite3");
        config.paths.jsonl_log = PathBuf::from("/var/lib/sbh/activity.jsonl");
        config.paths.config_file = PathBuf::from("/etc/sbh/config.toml");
        config.notifications.file.path = PathBuf::from("/var/log/sbh/notifications.jsonl");
        config.system_tuning.writeback_sysctl_path = PathBuf::from("/proc/sys/vm/dirty_bytes");
        config.ballast.overrides.insert(
            "/data".to_string(),
            BallastVolumeOverride {
                enabled: true,
                ..BallastVolumeOverride::default()
            },
        );
        config.ballast.overrides.insert(
            "/mnt/disabled".to_string(),
            BallastVolumeOverride {
                enabled: false,
                ..BallastVolumeOverride::default()
            },
        );
        config
    }

    #[test]
    fn derived_sandbox_covers_roots_ballast_data_and_never_proc() {
        let paths = SystemdConfig::read_write_paths_for(&sample_config(), false);
        for expected in [
            "/data/projects",
            "/srv/builds with space",
            "/var/lib/sbh/ballast",
            "/var/lib/sbh",
            "/etc/sbh",
            "/var/log/sbh",
            "/data/.sbh",
            "/dev/shm",
            "/tmp",
        ] {
            assert!(
                paths.contains(&PathBuf::from(expected)),
                "{expected} missing from {paths:?}"
            );
        }
        assert!(
            !paths.contains(&PathBuf::from("/mnt/disabled/.sbh")),
            "disabled override volumes get no ballast dir"
        );
        assert!(
            paths
                .iter()
                .all(|p| !p.starts_with("/proc") && !p.starts_with("/sys")),
            "kernel tunables are never writable for the daemon: {paths:?}"
        );
        let mut sorted = paths.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(paths, sorted, "stable, deduplicated order");
    }

    #[test]
    fn read_write_paths_render_parse_and_patch_roundtrip() {
        let paths = vec![
            PathBuf::from("/data/projects"),
            PathBuf::from("/srv/builds with space"),
            PathBuf::from("/tmp"),
        ];
        let rendered = SystemdConfig::render_read_write_paths(&paths);
        assert_eq!(rendered, "/data/projects \"/srv/builds with space\" /tmp");
        assert_eq!(SystemdConfig::parse_read_write_paths(&rendered), paths);

        let unit = "[Service]\nNoNewPrivileges=true\nProtectSystem=strict\nReadWritePaths=/tmp /var/lib/sbh\nProtectHome=false\n";
        let required = vec![
            PathBuf::from("/data/projects"),
            PathBuf::from("/var/lib/sbh/ballast"),
            PathBuf::from("/tmp"),
        ];
        assert_eq!(
            SystemdConfig::missing_read_write_paths(unit, &required),
            vec![PathBuf::from("/data/projects")],
            "a granted parent covers its children; a new root is missing"
        );
        let patched = SystemdConfig::patch_read_write_paths(unit, &required).expect("changed");
        assert!(patched.contains("ReadWritePaths=/data/projects /var/lib/sbh/ballast /tmp\n"));
        assert!(
            SystemdConfig::missing_read_write_paths(&patched, &required).is_empty(),
            "after the patch nothing is missing"
        );
        assert!(
            SystemdConfig::patch_read_write_paths(&patched, &required).is_none(),
            "patching again is a no-op"
        );

        // A user-scope unit without ProtectSystem=strict needs no grants.
        let lenient = "[Service]\nNoNewPrivileges=true\n";
        assert_eq!(
            SystemdConfig::missing_read_write_paths(lenient, &required),
            Vec::<PathBuf>::new()
        );
        assert!(SystemdConfig::patch_read_write_paths(lenient, &required).is_none());
    }

    #[test]
    fn generated_unit_uses_the_derived_sandbox() {
        let config = sample_config();
        let systemd = SystemdConfig {
            user_scope: false,
            binary_path: PathBuf::from("/usr/local/bin/sbh"),
            read_write_paths: SystemdConfig::read_write_paths_for(&config, false),
        };
        let unit = SystemdServiceManager::new(systemd).generate_unit_file();
        let line = unit
            .lines()
            .find(|line| line.starts_with("ReadWritePaths="))
            .expect("unit has ReadWritePaths");
        assert!(line.contains("/data/projects"));
        assert!(line.contains("\"/srv/builds with space\""));
        assert!(!line.contains("/proc/sys"));
        assert!(unit.contains("ProtectSystem=strict\n"));
    }

    #[test]
    fn from_config_derives_read_write_paths_for_service_manager() {
        let config = sample_config();
        let manager = SystemdServiceManager::from_config(&config, false).expect("valid manager");
        assert_eq!(
            manager.config().read_write_paths,
            SystemdConfig::read_write_paths_for(&config, false)
        );
    }

    #[test]
    fn from_env_populates_read_write_paths() {
        let config = SystemdConfig::from_env(true).expect("valid config");
        assert!(!config.read_write_paths.is_empty());
        assert!(config.read_write_paths.contains(&PathBuf::from("/tmp")));
    }

    #[test]
    fn default_read_write_paths_system_scope_does_not_use_caller_home() {
        let paths = default_read_write_paths(false);
        if let Some(home) = env::var_os("HOME") {
            let home = PathBuf::from(home);
            if home != Path::new("/root") {
                assert!(
                    !paths.contains(&home.join(".local/share/sbh")),
                    "system scope must not inherit non-root caller's home: {paths:?}"
                );
            }
        }
    }
}

#[cfg(test)]
mod watchdog_tests {
    use super::*;

    #[test]
    fn systemd_watchdog_requires_timeout_and_notify_socket() {
        assert!(systemd_watchdog_enabled(60, Some("/run/systemd/notify")));
        assert!(!systemd_watchdog_enabled(0, Some("/run/systemd/notify")));
        assert!(!systemd_watchdog_enabled(60, None));
        assert!(!systemd_watchdog_enabled(60, Some("")));
    }

    #[test]
    fn sd_notify_messages_follow_the_protocol() {
        assert_eq!(
            sd_extend_timeout_message(std::time::Duration::from_secs(30), "provisioning ballast"),
            "EXTEND_TIMEOUT_USEC=30000000\nSTATUS=provisioning ballast\n"
        );
        assert_eq!(sd_ready_message(4242), "READY=1\nMAINPID=4242\n");
        assert_eq!(SD_STOPPING_MESSAGE, "STOPPING=1\n");
        assert_eq!(
            sd_watchdog_message("pressure=Green"),
            "WATCHDOG=1\nSTATUS=pressure=Green\n"
        );
    }

    /// The daemon must send READY=1 through the notify socket: a Type=notify
    /// unit is killed at TimeoutStartSec otherwise. Bind a real datagram
    /// socket and check the exact bytes that arrive.
    #[cfg(target_os = "linux")]
    #[test]
    fn sd_notify_send_delivers_ready_and_stopping_to_a_path_socket() {
        use std::os::unix::net::UnixDatagram;

        let dir = tempfile::tempdir().expect("temp dir");
        let socket_path = dir.path().join("notify.sock");
        let listener = UnixDatagram::bind(&socket_path).expect("bind notify socket");
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("set read timeout");
        let socket_str = socket_path.to_string_lossy().into_owned();

        sd_notify_send(&sd_ready_message(7), &socket_str).expect("send READY");
        sd_notify_send(SD_STOPPING_MESSAGE, &socket_str).expect("send STOPPING");

        let mut buf = [0u8; 256];
        let n = listener.recv(&mut buf).expect("receive READY datagram");
        assert_eq!(&buf[..n], b"READY=1\nMAINPID=7\n");
        let n = listener.recv(&mut buf).expect("receive STOPPING datagram");
        assert_eq!(&buf[..n], b"STOPPING=1\n");
    }

    /// `NOTIFY_SOCKET=@name` denotes a Linux abstract socket; the previous
    /// implementation treated it as a filesystem path and every notification
    /// silently failed.
    #[cfg(target_os = "linux")]
    #[test]
    fn sd_notify_send_supports_abstract_sockets() {
        use std::os::linux::net::SocketAddrExt as _;
        use std::os::unix::net::{SocketAddr, UnixDatagram};

        let name = format!("sbh-notify-test-{}", std::process::id());
        let addr = SocketAddr::from_abstract_name(name.as_bytes()).expect("abstract addr");
        let listener = UnixDatagram::bind_addr(&addr).expect("bind abstract notify socket");
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("set read timeout");

        sd_notify_send(&sd_watchdog_message("ok"), &format!("@{name}")).expect("send WATCHDOG");

        let mut buf = [0u8; 256];
        let n = listener.recv(&mut buf).expect("receive datagram");
        assert_eq!(&buf[..n], b"WATCHDOG=1\nSTATUS=ok\n");
    }

    #[test]
    fn sd_notify_send_reports_unreachable_socket() {
        let missing = "/nonexistent-dir-for-sbh-test/notify.sock";
        #[cfg(target_os = "linux")]
        assert!(sd_notify_send("READY=1\n", missing).is_err());
        #[cfg(not(target_os = "linux"))]
        assert!(sd_notify_send("READY=1\n", missing).is_ok());
    }

    #[test]
    fn systemctl_failure_names_command_outputs_and_remediation() {
        let diagnostic = format_systemctl_failure(
            &[
                "--user".to_string(),
                "enable".to_string(),
                SYSTEMD_UNIT_NAME.to_string(),
            ],
            Some(1),
            "stdout hint",
            "stderr detail",
            std::path::Path::new("/Users/me/.config/systemd/user/sbh.service"),
            true,
        );

        assert!(diagnostic.contains("systemctl --user enable sbh.service failed with exit 1"));
        assert!(diagnostic.contains("stdout: stdout hint"));
        assert!(diagnostic.contains("stderr: stderr detail"));
        assert!(
            diagnostic
                .contains("systemd-analyze verify /Users/me/.config/systemd/user/sbh.service")
        );
        assert!(diagnostic.contains("systemctl --user status sbh.service"));
        assert!(diagnostic.contains("journalctl --user -u sbh.service -n 100 --no-pager"));
    }

    #[test]
    fn systemctl_failure_quotes_unit_paths_with_spaces() {
        let diagnostic = format_systemctl_failure(
            &["daemon-reload".to_string()],
            Some(1),
            "",
            "",
            std::path::Path::new("/tmp/sbh test/sbh.service"),
            false,
        );

        assert!(diagnostic.contains("systemctl daemon-reload failed with exit 1"));
        assert!(diagnostic.contains("systemd-analyze verify '/tmp/sbh test/sbh.service'"));
        assert!(diagnostic.contains("sudo systemctl status sbh.service"));
    }
}

#[cfg(test)]
mod exec_path_tests {
    use super::*;

    fn manager(binary: &str, user_scope: bool) -> SystemdServiceManager {
        SystemdServiceManager::new(SystemdConfig {
            user_scope,
            binary_path: PathBuf::from(binary),
            read_write_paths: vec![PathBuf::from("/tmp")],
        })
    }

    #[test]
    fn ordinary_execstart_output_stays_unchanged() {
        let unit = manager("/usr/local/bin/sbh", false)
            .generate_unit_file_with_config(Some(Path::new("/etc/sbh/config.toml")));
        assert!(
            unit.contains("ExecStart=/usr/local/bin/sbh daemon --config /etc/sbh/config.toml\n")
        );
        assert!(unit.contains("ExecReload=/bin/kill -HUP $MAINPID\n"));
        assert!(unit.contains("NoNewPrivileges=true\n"));
        assert!(unit.contains("ProtectSystem=strict\n"));
    }

    #[test]
    fn execstart_preserves_spaces_specifiers_and_literal_dollars() {
        for user_scope in [false, true] {
            let unit = manager("/opt/sbh custom/%h/${HOME}/sbh", user_scope)
                .generate_unit_file_with_config(Some(Path::new(
                    "/etc/sbh config/%n/${USER}/config.toml",
                )));
            assert!(unit.contains(
                "ExecStart=\"/opt/sbh custom/%%h/${HOME}/sbh\" daemon --config \"/etc/sbh config/%%n/$${USER}/config.toml\"\n"
            ));
            assert_eq!(
                exec_start_binary(&parse_unit_directives(&unit)).unwrap(),
                b"/opt/sbh custom/%h/${HOME}/sbh"
            );
        }
    }

    #[test]
    fn config_paths_cannot_inject_unit_directives() {
        let path = Path::new("/etc/quoted\"/back\\slash\nUser=root\n/config.toml");
        let unit = manager("/usr/local/bin/sbh", false).generate_unit_file_with_config(Some(path));
        let directives = parse_unit_directives(&unit);
        assert!(!directives.contains_key("Service/User"));
        assert_eq!(directives["Service/ExecStart"].len(), 1);
        let encoded = systemd_exec_path(path, true);
        let (word, rest) = take_systemd_word(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(
            literal_systemd_word(&word, true).unwrap(),
            path.as_os_str().as_encoded_bytes()
        );
    }

    #[test]
    fn drift_compares_the_whole_quoted_executable_not_its_first_fragment() {
        let generated = manager("/opt/shared prefix/one/sbh", false).generate_unit_file();
        for command in [
            "\"/opt/shared prefix/two/sbh\" daemon",
            "/opt/shared prefix/one/sbh daemon",
            "\"/opt/shared prefix/one/sbh daemon",
        ] {
            let installed = format!("[Service]\nExecStart={command}\n");
            let drift =
                UnitDrift::compute(Path::new("/x/sbh.service"), &installed, &generated, &[]);
            assert!(!drift.exec_start_matches, "{command}");
        }
        for command in [
            "'/opt/shared prefix/one/sbh' daemon",
            r"-/opt/shared\sprefix/one/sbh daemon",
            r"/opt/shared\x20prefix/one/sbh daemon",
            r"/opt/shared\040prefix/one/sbh daemon",
            r"/opt/shared\u0020prefix/one/sbh daemon",
        ] {
            let parsed = parse_unit_directives(&format!("[Service]\nExecStart={command}\n"));
            assert_eq!(
                exec_start_binary(&parsed).unwrap(),
                b"/opt/shared prefix/one/sbh",
                "{command}"
            );
        }
    }

    #[test]
    fn malformed_or_context_dependent_execstart_is_not_a_match() {
        for command in [
            r"/opt/\xZZ/sbh daemon",
            r"/opt/\q/sbh daemon",
            r"/opt/\000/sbh daemon",
            r"/opt/\Uffffffff/sbh daemon",
            "\"/opt/missing quote/sbh daemon",
            "/opt/%h/sbh daemon",
            "\"\" daemon",
        ] {
            let parsed = parse_unit_directives(&format!("[Service]\nExecStart={command}\n"));
            assert!(exec_start_binary(&parsed).is_none(), "{command}");
        }
        let multiple =
            parse_unit_directives("[Service]\nExecStart=/opt/one/sbh\nExecStart=/opt/two/sbh\n");
        assert!(exec_start_binary(&multiple).is_none());
    }

    #[test]
    fn unsupported_systemd_executables_are_rejected_before_install() {
        for path in [
            "sbh",
            "/opt/a\"b/sbh",
            "/opt/a'b/sbh",
            "/opt/a\\b/sbh",
            "/opt/a\nb/sbh",
        ] {
            assert!(
                validate_systemd_binary(Path::new(path)).is_err(),
                "{path:?}"
            );
        }
        for path in [
            "/usr/local/bin/sbh",
            "/opt/custom path/sbh",
            "/opt/%h/${HOME}/sbh",
        ] {
            assert!(validate_systemd_binary(Path::new(path)).is_ok());
        }
    }

    #[cfg(unix)]
    #[test]
    fn encoding_and_drift_preserve_native_path_bytes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let path = Path::new(OsStr::from_bytes(b"/opt/custom-\xff space/sbh"));
        let mut manager = manager("/unused", true);
        manager.config.binary_path = path.to_path_buf();
        let unit = manager.generate_unit_file();
        assert!(unit.contains(r"\xff"));
        assert_eq!(
            exec_start_binary(&parse_unit_directives(&unit)).unwrap(),
            path.as_os_str().as_bytes()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires native systemd-analyze; no running service manager is needed"]
    fn native_systemd_accepts_generated_custom_paths() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        for (index, relative) in [
            "custom destination/sbh",
            "literal-%h/sbh",
            "literal-${HOME}/sbh",
            "unicode-\u{e9}/sbh",
        ]
        .iter()
        .enumerate()
        {
            let binary = temp.path().join(relative);
            fs::create_dir_all(binary.parent().unwrap()).unwrap();
            fs::write(&binary, b"#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
            let unit_path = temp.path().join(format!("sbh-path-{index}.service"));
            for user_scope in [false, true] {
                let manager = manager(binary.to_str().unwrap(), user_scope);
                fs::write(&unit_path, manager.generate_unit_file()).unwrap();
                let output = Command::new("systemd-analyze")
                    .args(["verify", "--man=no"])
                    .arg(&unit_path)
                    .output()
                    .expect("install systemd-analyze before running this ignored test");
                assert!(output.status.success(), "{relative}: {output:?}");
            }
            // Live parser negative controls: these are real, runnable files,
            // but the old unquoted/unescaped output names the wrong executable.
            if index < 2 {
                fs::write(
                    &unit_path,
                    format!("[Service]\nExecStart={} daemon\n", binary.display()),
                )
                .unwrap();
                let output = Command::new("systemd-analyze")
                    .args(["verify", "--man=no"])
                    .arg(&unit_path)
                    .output()
                    .unwrap();
                assert!(
                    !output.status.success(),
                    "baseline unexpectedly passed: {relative}"
                );
            }
        }
    }
}

#[cfg(test)]
mod preserved_config_tests {
    use super::*;

    #[test]
    fn repairs_preserve_quoted_escaped_and_equals_config_arguments() {
        for command in [
            r#""/opt/custom path/sbh" daemon --config "/etc/sbh config/a.toml""#,
            r#"/opt/sbh daemon "--config=/etc/sbh config/a.toml""#,
            r"/opt/sbh daemon --config /etc/sbh\sconfig/a.toml",
        ] {
            let unit = format!("[Service]\nExecStart={command}\n");
            assert_eq!(
                preserved_unit_config(&unit, &[]).unwrap(),
                Some(PathBuf::from("/etc/sbh config/a.toml"))
            );
        }
    }

    #[test]
    fn generated_literal_config_survives_repair_and_dropin_replacement() {
        let path = Path::new("/etc/custom %h/${HOME}/quote\"/config.toml");
        let manager = SystemdServiceManager::new(SystemdConfig {
            user_scope: true,
            binary_path: PathBuf::from("/opt/custom path/sbh"),
            read_write_paths: Vec::new(),
        });
        let generated = manager.generate_unit_file_with_config(Some(path));
        assert_eq!(
            preserved_unit_config(&generated, &[]).unwrap().as_deref(),
            Some(path)
        );
        let dropins = vec![(
            PathBuf::from("/unit/sbh.service.d/config.conf"),
            "[Service]\nExecStart=\nExecStart=/opt/sbh daemon --config '/etc/drop in/config.toml'\n".to_string(),
        )];
        assert_eq!(
            preserved_unit_config(&generated, &dropins).unwrap(),
            Some(PathBuf::from("/etc/drop in/config.toml"))
        );
    }

    #[test]
    fn repair_refuses_unknown_config_instead_of_switching_to_defaults() {
        for command in [
            "/opt/sbh daemon --config",
            "/opt/sbh daemon --config=",
            "/opt/sbh daemon --config relative.toml",
            "/opt/sbh daemon --config %h/config.toml",
            "/opt/sbh daemon --config /etc/${USER}/config.toml",
            "/opt/sbh daemon --config /etc/one --config /etc/two",
            "/opt/sbh daemon --config '/etc/unclosed quote",
        ] {
            let unit = format!("[Service]\nExecStart={command}\n");
            assert!(preserved_unit_config(&unit, &[]).is_err(), "{command}");
        }
        assert!(
            preserved_unit_config("[Service]\nExecStart=/opt/sbh daemon\n", &[])
                .unwrap()
                .is_none()
        );
        // ':' disables expansion in the old unit. The new generator escapes
        // the dollar signs when it emits the equivalent command without ':'.
        assert_eq!(
            preserved_unit_config(
                "[Service]\nExecStart=:/opt/sbh daemon --config /etc/${USER}/config.toml\n",
                &[],
            )
            .unwrap(),
            Some(PathBuf::from("/etc/${USER}/config.toml"))
        );
    }
}
