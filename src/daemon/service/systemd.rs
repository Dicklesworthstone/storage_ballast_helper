//! systemd service integration.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
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
        let read_write_paths = default_read_write_paths(user_scope);
        Ok(Self {
            user_scope,
            binary_path,
            read_write_paths,
        })
    }

    /// Directory where the unit file is written.
    #[must_use]
    pub fn unit_dir(&self) -> PathBuf {
        if self.user_scope {
            let home = env::var_os("HOME").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
            home.join(".config/systemd/user")
        } else {
            PathBuf::from("/etc/systemd/system")
        }
    }

    /// Full path to the generated unit file.
    #[must_use]
    pub fn unit_path(&self) -> PathBuf {
        self.unit_dir().join(SYSTEMD_UNIT_NAME)
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

    /// Access the underlying config (for reading unit path, etc.).
    #[must_use]
    pub fn config(&self) -> &SystemdConfig {
        &self.config
    }

    /// Generate the full systemd unit file content.
    #[must_use]
    pub fn generate_unit_file(&self) -> String {
        let binary = self.config.binary_path.display();
        let rw_paths = self
            .config
            .read_write_paths
            .iter()
            .map(|p| {
                let s = p.display().to_string();
                if s.contains(' ') || s.contains('"') {
                    // Systemd quote escaping: escape internal quotes and wrap in quotes.
                    format!("\"{}\"", s.replace('"', "\\\""))
                } else {
                    s
                }
            })
            .collect::<Vec<_>>()
            .join(" ");

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

        writeln!(unit, "ExecStart={binary} daemon").ok();
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
        writeln!(unit, "CPUQuota=10%").ok();
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
        self.check_binary_ownership();

        let unit_dir = self.config.unit_dir();
        let unit_path = self.config.unit_path();
        let unit_content = self.generate_unit_file();

        fs::create_dir_all(&unit_dir).map_err(|source| SbhError::Io {
            path: unit_dir.clone(),
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
            sd_notify_watchdog(status, &socket_path);
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

    fn restart(&self) -> Result<()> {
        self.run_systemctl(&["restart", SYSTEMD_UNIT_NAME])?;
        Ok(())
    }

    fn logs_path(&self) -> Result<Option<PathBuf>> {
        Ok(None)
    }

    fn is_loaded(&self) -> Result<bool> {
        let state = self.run_systemctl_lenient(&["is-enabled", SYSTEMD_UNIT_NAME]);
        Ok(matches!(
            state.as_str(),
            "enabled" | "static" | "linked" | "generated" | "transient"
        ))
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

/// `sd_notify(3)` watchdog heartbeat message.
#[must_use]
pub fn sd_watchdog_message(status: &str) -> String {
    format!("WATCHDOG=1\nSTATUS={status}\n")
}

fn sd_notify_watchdog(status: &str, socket_path: &str) {
    // Heartbeats are best-effort: a lost datagram costs one beat, and the
    // next one lands well within WatchdogSec.
    let _ = sd_notify_send(&sd_watchdog_message(status), socket_path);
}

/// Send one `sd_notify(3)` datagram to `socket_path`.
///
/// Supports filesystem sockets and Linux abstract sockets (`NOTIFY_SOCKET`
/// values starting with `@`, which systemd uses for some user managers).
/// Non-Linux platforms have no notify socket and report success without
/// sending anything.
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
    if !user_scope {
        paths.push(PathBuf::from("/var/lib/sbh"));
    }
    for candidate in ["/data", "/data/tmp"] {
        let p = PathBuf::from(candidate);
        if p.is_dir() {
            paths.push(p);
        }
    }
    if let Some(home) = env::var_os("HOME") {
        let home = PathBuf::from(home);
        paths.push(home.join(".local/share/sbh"));
        paths.push(home.join(".config/sbh"));
    }
    paths
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
