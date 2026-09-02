//! Service integration dispatcher and shared service lifecycle contracts.
//!
//! Platform-specific implementations live under `service/systemd.rs` and
//! `service/launchd.rs`. This file remains the module root so the repo can split
//! the code without deleting or moving `src/daemon/service.rs`.

mod launchctl;
mod launchd;
mod systemd;

use std::path::{Path, PathBuf};

use crate::core::errors::Result;
use crate::platform::pal::{NoopServiceManager, Platform, ServiceManager};
use crate::platform::types::ServiceKind;

pub use launchctl::{LaunchctlDomain, LaunchctlServiceTarget};
pub use launchd::{LaunchdConfig, LaunchdServiceManager, LaunchdStatusReport};
pub use systemd::{SystemdConfig, SystemdServiceManager};

/// Unit name for the systemd service.
pub const SYSTEMD_UNIT_NAME: &str = "sbh.service";
/// Plist label used for the launchd service.
pub const LAUNCHD_LABEL: &str = "com.sbh.daemon";
/// Environment override for tests and isolated launchd installs.
pub const LAUNCHD_LABEL_ENV: &str = "SBH_LAUNCHD_LABEL";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServiceOwnershipPolicy {
    owner: &'static str,
    group: &'static str,
    uid: u32,
    gid: u32,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServiceOwnershipWarning {
    binary_path: PathBuf,
    actual_uid: u32,
    actual_gid: u32,
    policy: ServiceOwnershipPolicy,
}

impl ServiceOwnershipPolicy {
    pub(crate) const fn systemd_system_binary() -> Self {
        Self {
            owner: "root",
            group: "root",
            uid: 0,
            gid: 0,
        }
    }

    pub(crate) const fn launchd_system_binary() -> Self {
        Self {
            owner: "root",
            group: "wheel",
            uid: 0,
            gid: 0,
        }
    }

    fn chown_command(self, binary_path: &Path) -> String {
        format!(
            "sudo chown {}:{} {}",
            self.owner,
            self.group,
            binary_path.display()
        )
    }

    #[cfg(unix)]
    pub(crate) fn warning_for_binary(self, binary_path: &Path) -> Option<ServiceOwnershipWarning> {
        use std::os::unix::fs::MetadataExt;

        let metadata = std::fs::metadata(binary_path).ok()?;
        let observed = (metadata.uid(), metadata.gid());
        if observed == (self.uid, self.gid) {
            return None;
        }
        Some(ServiceOwnershipWarning {
            binary_path: binary_path.to_path_buf(),
            actual_uid: observed.0,
            actual_gid: observed.1,
            policy: self,
        })
    }
}

#[cfg(unix)]
impl ServiceOwnershipWarning {
    pub(crate) fn print(&self) {
        eprintln!(
            "[SBH-WARN] SECURITY RISK: System service binary '{}' is NOT owned by {}:{} (uid={}, gid={}).",
            self.binary_path.display(),
            self.policy.owner,
            self.policy.group,
            self.actual_uid,
            self.actual_gid
        );
        eprintln!("[SBH-WARN] A non-root user could replace this binary and gain root privileges.");
        eprintln!(
            "[SBH-WARN] Recommendation: '{}'",
            self.policy.chown_command(&self.binary_path)
        );
    }
}

/// Return launchd labels that uninstall/discovery flows should inspect.
///
/// The default production label is always included. A configured label is added
/// only when it is a safe plist filename component; lifecycle operations still
/// perform strict validation and report configuration errors separately.
#[must_use]
pub fn launchd_labels_for_discovery(configured_label: Option<&str>) -> Vec<String> {
    let mut labels = vec![LAUNCHD_LABEL.to_string()];
    if let Some(label) = configured_label.filter(|label| is_launchd_discovery_label(label))
        && !labels.iter().any(|existing| existing == label)
    {
        labels.push(label.to_string());
    }
    labels
}

/// Build the system launchd plist path for a label.
#[must_use]
pub fn launchd_system_plist_path_for_label(label: &str) -> PathBuf {
    PathBuf::from("/Library/LaunchDaemons").join(format!("{label}.plist"))
}

/// Build the user launchd plist path for a label and home directory.
#[must_use]
pub fn launchd_user_plist_path_for_label(home: &Path, label: &str) -> PathBuf {
    home.join("Library")
        .join("LaunchAgents")
        .join(format!("{label}.plist"))
}

fn is_launchd_discovery_label(label: &str) -> bool {
    !label.is_empty()
        && label.trim() == label
        && label
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
}

/// Structured result from an install or uninstall operation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceActionResult {
    /// The action performed (`"install"` or `"uninstall"`).
    pub action: &'static str,
    /// Service system type (e.g., `"systemd"`, `"launchd"`).
    pub service_type: &'static str,
    /// Service scope (`"system"` or `"user"`).
    pub scope: &'static str,
    /// Path to the generated/removed unit file.
    pub unit_path: PathBuf,
    /// Whether the operation succeeded.
    pub success: bool,
    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Build a service manager from a platform service kind.
#[must_use]
pub fn service_manager_for_kind(kind: ServiceKind, user_scope: bool) -> Box<dyn ServiceManager> {
    try_service_manager_for_kind(kind, user_scope)
        .unwrap_or_else(|_| Box::<NoopServiceManager>::default())
}

/// Default service scope for unqualified status/doctor/control flows.
///
/// This mirrors the CLI auto-detection contract: Linux/systemd defaults to the
/// system service, while macOS/launchd defaults to the user LaunchAgent.
#[must_use]
pub const fn default_service_control_user_scope(kind: ServiceKind) -> bool {
    matches!(kind, ServiceKind::Launchd)
}

/// Build a service manager for status/doctor/control flows using the platform
/// default scope.
#[must_use]
pub fn service_manager_for_default_control_kind(kind: ServiceKind) -> Box<dyn ServiceManager> {
    service_manager_for_kind_control(kind, default_service_control_user_scope(kind))
}

/// Build a service manager for status/doctor/control flows.
///
/// launchd status and log inspection may target a system LaunchDaemon from a
/// non-root process, so this path uses launchd's control constructor instead of
/// the install constructor with its root guard.
#[must_use]
pub fn service_manager_for_kind_control(
    kind: ServiceKind,
    user_scope: bool,
) -> Box<dyn ServiceManager> {
    try_service_manager_for_kind_control(kind, user_scope)
        .unwrap_or_else(|_| Box::<NoopServiceManager>::default())
}

/// Build a service manager from a platform, using `Platform::service_kind()` as
/// the dispatch key.
#[must_use]
pub fn service_manager_for_platform<P: Platform>(
    platform: &P,
    user_scope: bool,
) -> Box<dyn ServiceManager> {
    service_manager_for_kind(platform.service_kind(), user_scope)
}

/// Fallible service-manager dispatcher used by CLI flows that want setup errors.
pub fn try_service_manager_for_kind(
    kind: ServiceKind,
    user_scope: bool,
) -> Result<Box<dyn ServiceManager>> {
    match kind {
        ServiceKind::Systemd => Ok(Box::new(SystemdServiceManager::from_env(user_scope)?)),
        ServiceKind::Launchd => Ok(Box::new(LaunchdServiceManager::from_env(user_scope)?)),
        ServiceKind::None => Ok(Box::<NoopServiceManager>::default()),
    }
}

/// Fallible service-manager dispatcher for status/doctor/control flows.
pub fn try_service_manager_for_kind_control(
    kind: ServiceKind,
    user_scope: bool,
) -> Result<Box<dyn ServiceManager>> {
    match kind {
        ServiceKind::Systemd => Ok(Box::new(SystemdServiceManager::from_env(user_scope)?)),
        ServiceKind::Launchd => Ok(Box::new(LaunchdServiceManager::from_env_for_control(
            user_scope,
        )?)),
        ServiceKind::None => Ok(Box::<NoopServiceManager>::default()),
    }
}

/// Resolve the sbh binary path (prefers the running binary, falls back to PATH).
fn resolve_sbh_binary() -> Result<PathBuf> {
    if let Ok(exe) = std::env::current_exe()
        && exe.exists()
    {
        return Ok(exe);
    }
    for candidate in &["/usr/local/bin/sbh", "/usr/bin/sbh"] {
        let p = Path::new(candidate);
        if p.exists() {
            return Ok(p.to_path_buf());
        }
    }
    Err(crate::core::errors::SbhError::Runtime {
        details: "could not locate sbh binary; install it to a PATH directory first".to_string(),
    })
}

#[cfg(test)]
mod service_ownership_policy_tests {
    use super::*;

    #[test]
    fn service_ownership_policy_formats_platform_groups() {
        let binary = Path::new("/usr/local/bin/sbh");

        assert_eq!(
            ServiceOwnershipPolicy::systemd_system_binary().chown_command(binary),
            "sudo chown root:root /usr/local/bin/sbh"
        );
        assert_eq!(
            ServiceOwnershipPolicy::launchd_system_binary().chown_command(binary),
            "sudo chown root:wheel /usr/local/bin/sbh"
        );
    }

    #[cfg(unix)]
    #[test]
    fn service_ownership_policy_accepts_matching_uid_gid() {
        use std::os::unix::fs::MetadataExt;

        let metadata = std::fs::metadata("/bin/sh").expect("/bin/sh should exist");
        let policy = ServiceOwnershipPolicy {
            owner: "current-owner",
            group: "current-group",
            uid: metadata.uid(),
            gid: metadata.gid(),
        };

        assert!(policy.warning_for_binary(Path::new("/bin/sh")).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn service_ownership_policy_warns_on_uid_gid_mismatch() {
        let binary = Path::new("/bin/sh");
        let warning = ServiceOwnershipPolicy {
            owner: "root",
            group: "wheel",
            uid: u32::MAX,
            gid: u32::MAX,
        }
        .warning_for_binary(binary)
        .expect("mismatched uid/gid should produce a warning");

        assert_eq!(
            warning.policy.chown_command(&warning.binary_path),
            "sudo chown root:wheel /bin/sh"
        );
    }
}

/// The pre-template inline unit writer. Nothing calls it; deleting it
/// needs operator permission (AGENTS.md rule 1), see bd-rc-master-ajg1.6.3.
#[deprecated(
    since = "0.5.2",
    note = "dead code; the template-based writers above are used (bd-rc-master-ajg1.6.3)"
)]
#[allow(dead_code)]
mod legacy_inline {

    use std::env;
    use std::fmt::Write as _;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use crate::core::errors::{Result, SbhError};
    use crate::platform::pal::ServiceManager;

    /// Unit name for the systemd service.
    const SYSTEMD_UNIT_NAME: &str = "sbh.service";

    // ---------------------------------------------------------------------------
    // Systemd configuration
    // ---------------------------------------------------------------------------

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

    // ---------------------------------------------------------------------------
    // Systemd service manager
    // ---------------------------------------------------------------------------

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

            // -- [Unit] section ------------------------------------------------
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

            // -- [Service] section ---------------------------------------------
            writeln!(unit, "[Service]").ok();

            if self.config.user_scope {
                // User services cannot use Type=notify without a sd_notify capable
                // supervisor; use simple for safety.
                writeln!(unit, "Type=simple").ok();
            } else {
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

            // -- Scheduling: lowest priority -----------------------------------
            writeln!(unit, "# Low priority — never compete with build workloads").ok();
            writeln!(unit, "Nice=19").ok();
            writeln!(unit, "IOSchedulingClass=idle").ok();
            writeln!(unit, "IOSchedulingPriority=7").ok();
            writeln!(unit).ok();

            // -- Security hardening -------------------------------------------
            writeln!(unit, "# Security hardening").ok();
            writeln!(unit, "NoNewPrivileges=true").ok();

            if !self.config.user_scope {
                // System services get strict protection; user services inherit
                // user-session sandboxing and cannot use ProtectSystem.
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

            // -- Resource limits -----------------------------------------------
            writeln!(unit, "# Resource limits").ok();
            writeln!(unit, "MemoryMax=256M").ok();
            writeln!(unit, "CPUQuota=10%").ok();
            writeln!(unit).ok();

            // -- Logging -------------------------------------------------------
            if !self.config.user_scope {
                writeln!(unit, "# Logging").ok();
                writeln!(unit, "StandardOutput=journal").ok();
                writeln!(unit, "StandardError=journal").ok();
                writeln!(unit, "SyslogIdentifier=sbh").ok();
                writeln!(unit).ok();
            }

            // -- [Install] section ---------------------------------------------
            writeln!(unit, "[Install]").ok();
            if self.config.user_scope {
                writeln!(unit, "WantedBy=default.target").ok();
            } else {
                writeln!(unit, "WantedBy=multi-user.target").ok();
            }

            unit
        }

        // -- systemctl helpers -------------------------------------------------

        fn check_binary_ownership(&self) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if !self.config.user_scope
                    && let Ok(meta) = fs::metadata(&self.config.binary_path)
                    && meta.uid() != 0
                {
                    eprintln!(
                        "[SBH-WARN] SECURITY RISK: System service binary '{}' is NOT owned by root (uid={}).",
                        self.config.binary_path.display(),
                        meta.uid()
                    );
                    eprintln!(
                        "[SBH-WARN] A non-root user could replace this binary and gain root privileges."
                    );
                    let group = if cfg!(target_os = "macos") {
                        "wheel"
                    } else {
                        "root"
                    };
                    eprintln!(
                        "[SBH-WARN] Recommendation: 'sudo chown root:{group} {}'",
                        self.config.binary_path.display()
                    );
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
                    details: format!(
                        "systemctl {} failed (exit {}): {}",
                        full_args.join(" "),
                        output.status.code().unwrap_or(-1),
                        stderr.trim()
                    ),
                })
            }
        }

        /// Run systemctl but don't error on non-zero exit (used for stop/disable
        /// where the service may already be stopped/disabled).
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

            // 1. Ensure parent directory exists.
            fs::create_dir_all(&unit_dir).map_err(|source| SbhError::Io {
                path: unit_dir.clone(),
                source,
            })?;

            // 2. Write unit file.
            fs::write(&unit_path, &unit_content).map_err(|source| SbhError::Io {
                path: unit_path.clone(),
                source,
            })?;

            // 3. Reload systemd daemon.
            self.run_systemctl(&["daemon-reload"])?;

            // 4. Enable the service.
            self.run_systemctl(&["enable", SYSTEMD_UNIT_NAME])?;

            Ok(())
        }

        fn uninstall(&self) -> Result<()> {
            let unit_path = self.config.unit_path();

            // 1. Stop service (lenient — may already be stopped).
            self.run_systemctl_lenient(&["stop", SYSTEMD_UNIT_NAME]);

            // 2. Disable service (lenient — may not be enabled).
            self.run_systemctl_lenient(&["disable", SYSTEMD_UNIT_NAME]);

            // 3. Remove unit file if it exists.
            if unit_path.exists() {
                fs::remove_file(&unit_path).map_err(|source| SbhError::Io {
                    path: unit_path.clone(),
                    source,
                })?;
            }

            // 4. Reload systemd daemon.
            self.run_systemctl(&["daemon-reload"])?;

            Ok(())
        }

        fn status(&self) -> Result<String> {
            // is-active returns non-zero for inactive/failed, so use lenient.
            let state = self.run_systemctl_lenient(&["is-active", SYSTEMD_UNIT_NAME]);
            if state.is_empty() {
                return Ok("unknown".to_string());
            }
            Ok(state)
        }
    }

    // ---------------------------------------------------------------------------
    // Service installation result (for structured CLI output)
    // ---------------------------------------------------------------------------

    /// Structured result from an install or uninstall operation.
    #[derive(Debug, Clone, serde::Serialize)]
    pub struct ServiceActionResult {
        /// The action performed (`"install"` or `"uninstall"`).
        pub action: &'static str,
        /// Service system type (e.g., `"systemd"`, `"launchd"`).
        pub service_type: &'static str,
        /// Service scope (`"system"` or `"user"`).
        pub scope: &'static str,
        /// Path to the generated/removed unit file.
        pub unit_path: PathBuf,
        /// Whether the operation succeeded.
        pub success: bool,
        /// Error message if the operation failed.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    /// Resolve the sbh binary path (prefers the running binary, falls back to PATH).
    fn resolve_sbh_binary() -> Result<PathBuf> {
        // First try: the currently running executable.
        if let Ok(exe) = env::current_exe()
            && exe.exists()
        {
            return Ok(exe);
        }
        // Fallback: search PATH.
        for candidate in &["/usr/local/bin/sbh", "/usr/bin/sbh"] {
            let p = Path::new(candidate);
            if p.exists() {
                return Ok(p.to_path_buf());
            }
        }
        Err(SbhError::Runtime {
            details: "could not locate sbh binary; install it to a PATH directory first"
                .to_string(),
        })
    }

    /// Default paths that sbh needs write access to under `ProtectSystem=strict`.
    ///
    /// Includes common cleanup targets (/tmp, /var/tmp) and sbh's own state dirs.
    /// Also probes for `/data` and `/data/tmp` since these are universal on the
    /// agent-fleet machines this tool was built for (Contabo VPS layout) and
    /// omitting them produces silent NotWritable skips that defeat the daemon's
    /// purpose. Callers (cli_app::install) further extend this list with the
    /// scanner.root_paths from the user's config.
    fn default_read_write_paths(user_scope: bool) -> Vec<PathBuf> {
        let mut paths = vec![PathBuf::from("/tmp"), PathBuf::from("/var/tmp")];
        if !user_scope {
            paths.push(PathBuf::from("/var/lib/sbh"));
        }
        // Probe for /data layouts common on agent-fleet machines. Only add them
        // if the directory exists so we don't pollute ReadWritePaths on hosts
        // without /data (which would make systemd refuse to start the unit).
        for candidate in ["/data", "/data/tmp"] {
            let p = PathBuf::from(candidate);
            if p.is_dir() {
                paths.push(p);
            }
        }
        // Add user-local data dir.
        if let Some(home) = env::var_os("HOME") {
            let home = PathBuf::from(home);
            paths.push(home.join(".local/share/sbh"));
            paths.push(home.join(".config/sbh"));
        }
        paths
    }

    // ---------------------------------------------------------------------------
    // Launchd configuration (macOS)
    // ---------------------------------------------------------------------------

    /// Plist label used for the launchd service.
    const LAUNCHD_LABEL: &str = "com.sbh.daemon";

    /// Parameters controlling launchd plist generation and lifecycle commands.
    #[derive(Debug, Clone)]
    pub struct LaunchdConfig {
        /// Whether to install as user agent (vs system daemon).
        pub user_scope: bool,
        /// Absolute path to the sbh binary.
        pub binary_path: PathBuf,
        /// Path to stdout log file.
        pub stdout_log: PathBuf,
        /// Path to stderr log file.
        pub stderr_log: PathBuf,
    }

    impl LaunchdConfig {
        /// Build a config from the current environment.
        ///
        /// If `user_scope` is false but the current process is not running as root,
        /// automatically escalates to user-scope to avoid permission errors when
        /// creating log directories under `/var/log/`.
        pub fn from_env(user_scope: bool) -> Result<Self> {
            let effective_user_scope = if !user_scope && !is_running_as_root() {
                eprintln!(
                    "[SBH] Not running as root — defaulting to user-scope launchd installation"
                );
                true
            } else {
                user_scope
            };

            let binary_path = resolve_sbh_binary()?;
            let (stdout_log, stderr_log) = default_launchd_log_paths(effective_user_scope);
            Ok(Self {
                user_scope: effective_user_scope,
                binary_path,
                stdout_log,
                stderr_log,
            })
        }

        /// Directory where the plist is installed.
        #[must_use]
        pub fn plist_dir(&self) -> PathBuf {
            if self.user_scope {
                let home = env::var_os("HOME").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
                home.join("Library/LaunchAgents")
            } else {
                PathBuf::from("/Library/LaunchDaemons")
            }
        }

        /// Full path to the plist file.
        #[must_use]
        pub fn plist_path(&self) -> PathBuf {
            self.plist_dir().join(format!("{LAUNCHD_LABEL}.plist"))
        }
    }

    // ---------------------------------------------------------------------------
    // Launchd service manager
    // ---------------------------------------------------------------------------

    /// [`ServiceManager`] implementation that generates a launchd plist and drives
    /// `launchctl` for lifecycle operations on macOS.
    #[derive(Debug, Clone)]
    pub struct LaunchdServiceManager {
        config: LaunchdConfig,
    }

    impl LaunchdServiceManager {
        /// Create a new manager with the given config.
        #[must_use]
        pub fn new(config: LaunchdConfig) -> Self {
            Self { config }
        }

        /// Create a manager from the current environment.
        pub fn from_env(user_scope: bool) -> Result<Self> {
            Ok(Self::new(LaunchdConfig::from_env(user_scope)?))
        }

        /// Access the underlying config.
        #[must_use]
        pub fn config(&self) -> &LaunchdConfig {
            &self.config
        }

        /// Generate the launchd plist XML content.
        #[must_use]
        pub fn generate_plist(&self) -> String {
            let binary = escape_xml(&self.config.binary_path.to_string_lossy());
            let stdout_log = escape_xml(&self.config.stdout_log.to_string_lossy());
            let stderr_log = escape_xml(&self.config.stderr_log.to_string_lossy());

            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary}</string>
        <string>daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>Nice</key>
    <integer>19</integer>
    <key>LowPriorityIO</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{stdout_log}</string>
    <key>StandardErrorPath</key>
    <string>{stderr_log}</string>
</dict>
</plist>
"#
            )
        }

        /// Run launchctl with the given arguments.
        #[allow(clippy::unused_self)]
        fn run_launchctl(&self, args: &[&str]) -> Result<String> {
            let output = Command::new("launchctl")
                .args(args)
                .output()
                .map_err(|source| SbhError::Io {
                    path: PathBuf::from("launchctl"),
                    source,
                })?;
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            if output.status.success() {
                Ok(stdout.trim().to_string())
            } else {
                Err(SbhError::Runtime {
                    details: format!(
                        "launchctl {} failed (exit {}): {}",
                        args.join(" "),
                        output.status.code().unwrap_or(-1),
                        stderr.trim()
                    ),
                })
            }
        }

        /// Run launchctl without erroring on failure.
        #[allow(clippy::unused_self)]
        fn run_launchctl_lenient(&self, args: &[&str]) -> String {
            let output = Command::new("launchctl").args(args).output();
            match output {
                Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
                Err(_) => String::new(),
            }
        }
    }

    impl ServiceManager for LaunchdServiceManager {
        fn install(&self) -> Result<()> {
            let plist_dir = self.config.plist_dir();
            let plist_path = self.config.plist_path();
            let plist_content = self.generate_plist();

            // Ensure log directory exists.
            if let Some(log_parent) = self.config.stdout_log.parent() {
                fs::create_dir_all(log_parent).map_err(|source| SbhError::Io {
                    path: log_parent.to_path_buf(),
                    source,
                })?;
            }

            // Ensure plist directory exists.
            fs::create_dir_all(&plist_dir).map_err(|source| SbhError::Io {
                path: plist_dir.clone(),
                source,
            })?;

            // Write plist file.
            fs::write(&plist_path, &plist_content).map_err(|source| SbhError::Io {
                path: plist_path.clone(),
                source,
            })?;

            // Load the service.
            let path_str = plist_path
                .to_str()
                .ok_or_else(|| SbhError::Runtime {
                    details: "plist path is not valid UTF-8".to_string(),
                })?
                .to_string();
            self.run_launchctl(&["load", &path_str])?;

            Ok(())
        }

        fn uninstall(&self) -> Result<()> {
            let plist_path = self.config.plist_path();

            // Unload (lenient — may not be loaded).
            if let Ok(path_str) = plist_path.to_str().ok_or(()) {
                self.run_launchctl_lenient(&["unload", path_str]);
            }

            // Remove plist file.
            if plist_path.exists() {
                fs::remove_file(&plist_path).map_err(|source| SbhError::Io {
                    path: plist_path.clone(),
                    source,
                })?;
            }

            Ok(())
        }

        fn status(&self) -> Result<String> {
            let output = self.run_launchctl_lenient(&["list", LAUNCHD_LABEL]);
            if output.is_empty() {
                return Ok("not loaded".to_string());
            }
            // Parse basic status from launchctl list output.
            if output.contains("\"Label\"") || output.contains(LAUNCHD_LABEL) {
                Ok("loaded".to_string())
            } else {
                Ok("unknown".to_string())
            }
        }
    }

    /// Minimal XML escaping for plist values.
    fn escape_xml(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '&' => out.push_str("&amp;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&apos;"),
                _ => out.push(c),
            }
        }
        out
    }

    /// Check whether the current process is running as root.
    ///
    /// Uses `nix::unistd::geteuid()` on Unix; always returns `false` on other
    /// platforms (launchd is macOS-only, but this keeps the code compilable
    /// everywhere).
    fn is_running_as_root() -> bool {
        #[cfg(unix)]
        {
            nix::unistd::geteuid().is_root()
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    /// Default log file paths for launchd service.
    fn default_launchd_log_paths(user_scope: bool) -> (PathBuf, PathBuf) {
        if user_scope {
            let home = env::var_os("HOME").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
            let log_dir = home.join("Library/Logs/sbh");
            (log_dir.join("sbh.log"), log_dir.join("sbh.err"))
        } else {
            (
                PathBuf::from("/var/log/sbh/sbh.log"),
                PathBuf::from("/var/log/sbh/sbh.err"),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Cursor;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::platform::pal::MockPlatform;

    fn test_config(user_scope: bool) -> SystemdConfig {
        SystemdConfig {
            user_scope,
            binary_path: PathBuf::from("/usr/local/bin/sbh"),
            read_write_paths: vec![
                PathBuf::from("/var/lib/sbh"),
                PathBuf::from("/tmp"),
                PathBuf::from("/data/tmp"),
            ],
        }
    }

    #[test]
    fn system_unit_file_contains_required_sections() {
        let mgr = SystemdServiceManager::new(test_config(false));
        let unit = mgr.generate_unit_file();

        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("[Service]"));
        assert!(unit.contains("[Install]"));
    }

    #[test]
    fn service_kind_dispatcher_returns_noop_for_none() {
        let mgr = service_manager_for_kind(ServiceKind::None, false);

        assert_eq!(mgr.status().unwrap(), "unknown");
        assert_eq!(mgr.logs_path().unwrap(), None);
        assert!(!mgr.is_loaded().unwrap());
    }

    #[test]
    fn platform_dispatcher_uses_pal_service_kind() {
        let platform = MockPlatform::healthy().with_service_kind(ServiceKind::None);
        let mgr = service_manager_for_platform(&platform, false);

        assert_eq!(mgr.status().unwrap(), "unknown");
    }

    #[test]
    fn default_control_scope_matches_platform_auto_detection() {
        assert!(!default_service_control_user_scope(ServiceKind::Systemd));
        assert!(default_service_control_user_scope(ServiceKind::Launchd));
        assert!(!default_service_control_user_scope(ServiceKind::None));
    }

    #[test]
    fn default_launchd_control_manager_targets_user_logs() {
        let mgr = service_manager_for_default_control_kind(ServiceKind::Launchd);
        let logs_path = mgr
            .logs_path()
            .expect("launchd control manager should expose log path")
            .expect("launchd control manager should not fall back to noop");

        assert!(
            logs_path.ends_with(Path::new("Library/Logs/sbh/sbh.log")),
            "default launchd control should inspect the user LaunchAgent, got {}",
            logs_path.display()
        );
    }

    #[test]
    fn launchd_discovery_labels_include_default_and_safe_configured_label() {
        let labels = launchd_labels_for_discovery(Some("com.example.sbh.test"));

        assert_eq!(
            labels,
            vec![
                LAUNCHD_LABEL.to_string(),
                "com.example.sbh.test".to_string()
            ]
        );
    }

    #[test]
    fn launchd_discovery_labels_ignore_unsafe_configured_label() {
        for label in [
            "",
            " com.example.sbh",
            "com/example/sbh",
            "com.example.$sbh",
        ] {
            assert_eq!(
                launchd_labels_for_discovery(Some(label)),
                vec![LAUNCHD_LABEL.to_string()],
                "label should be ignored for plist discovery: {label:?}"
            );
        }
    }

    #[test]
    fn launchd_plist_path_builders_use_canonical_macos_locations() {
        assert_eq!(
            launchd_system_plist_path_for_label("com.example.sbh.test"),
            PathBuf::from("/Library/LaunchDaemons/com.example.sbh.test.plist")
        );
        assert_eq!(
            launchd_user_plist_path_for_label(Path::new("/Users/tester"), "com.example.sbh.test"),
            PathBuf::from("/Users/tester/Library/LaunchAgents/com.example.sbh.test.plist")
        );
    }

    #[test]
    fn system_unit_file_uses_notify_type() {
        let mgr = SystemdServiceManager::new(test_config(false));
        let unit = mgr.generate_unit_file();

        assert!(unit.contains("Type=notify"));
        assert!(unit.contains("WatchdogSec=60"));
        // Type=notify without a start timeout would hang forever if READY=1
        // were ever lost; NotifyAccess=main restricts who may send it.
        assert!(unit.contains("TimeoutStartSec=30"));
        assert!(unit.contains("NotifyAccess=main"));
    }

    #[test]
    fn user_unit_file_uses_simple_type() {
        let mgr = SystemdServiceManager::new(test_config(true));
        let unit = mgr.generate_unit_file();

        assert!(unit.contains("Type=simple"));
        assert!(!unit.contains("WatchdogSec="));
    }

    #[test]
    fn system_unit_file_has_security_hardening() {
        let mgr = SystemdServiceManager::new(test_config(false));
        let unit = mgr.generate_unit_file();

        assert!(unit.contains("NoNewPrivileges=true"));
        assert!(unit.contains("ProtectSystem=strict"));
        assert!(unit.contains("ReadWritePaths="));
        assert!(unit.contains("ProtectHome=false"));
        assert!(unit.contains("ProtectKernelTunables=true"));
        assert!(unit.contains("ProtectControlGroups=true"));
        assert!(unit.contains("RestrictSUIDSGID=true"));
        assert!(unit.contains("LimitNOFILE=4096"));
    }

    #[test]
    fn user_unit_file_omits_system_only_directives() {
        let mgr = SystemdServiceManager::new(test_config(true));
        let unit = mgr.generate_unit_file();

        assert!(!unit.contains("ProtectSystem="));
        assert!(!unit.contains("ProtectHome="));
        assert!(!unit.contains("ProtectKernelTunables="));
    }

    #[test]
    fn unit_file_has_low_priority_scheduling() {
        let mgr = SystemdServiceManager::new(test_config(false));
        let unit = mgr.generate_unit_file();

        assert!(unit.contains("Nice=19"));
        assert!(unit.contains("IOSchedulingClass=idle"));
        assert!(unit.contains("IOSchedulingPriority=7"));
    }

    #[test]
    fn unit_file_has_resource_limits() {
        let mgr = SystemdServiceManager::new(test_config(false));
        let unit = mgr.generate_unit_file();

        assert!(unit.contains("MemoryMax=256M"));
        assert!(unit.contains("CPUQuota=10%"));
    }

    #[test]
    fn unit_file_has_restart_policy() {
        let mgr = SystemdServiceManager::new(test_config(false));
        let unit = mgr.generate_unit_file();

        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("RestartSec=10"));
        assert!(unit.contains("TimeoutStopSec=30"));
    }

    #[test]
    fn system_service_wants_multiuser() {
        let mgr = SystemdServiceManager::new(test_config(false));
        let unit = mgr.generate_unit_file();

        assert!(unit.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn user_service_wants_default() {
        let mgr = SystemdServiceManager::new(test_config(true));
        let unit = mgr.generate_unit_file();

        assert!(unit.contains("WantedBy=default.target"));
    }

    #[test]
    fn exec_start_uses_configured_binary() {
        let mut config = test_config(false);
        config.binary_path = PathBuf::from("/opt/sbh/bin/sbh");
        let mgr = SystemdServiceManager::new(config);
        let unit = mgr.generate_unit_file();

        assert!(unit.contains("ExecStart=/opt/sbh/bin/sbh daemon"));
    }

    #[test]
    fn unit_path_system_scope() {
        let config = test_config(false);
        assert_eq!(
            config.unit_path(),
            PathBuf::from("/etc/systemd/system/sbh.service")
        );
    }

    #[test]
    fn unit_path_user_scope() {
        let config = test_config(true);
        let path = config.unit_path();
        assert!(path.to_string_lossy().ends_with("systemd/user/sbh.service"));
    }

    #[test]
    fn system_unit_file_has_journal_logging() {
        let mgr = SystemdServiceManager::new(test_config(false));
        let unit = mgr.generate_unit_file();

        assert!(unit.contains("StandardOutput=journal"));
        assert!(unit.contains("StandardError=journal"));
        assert!(unit.contains("SyslogIdentifier=sbh"));
    }

    #[test]
    fn user_unit_file_omits_journal_directives() {
        let mgr = SystemdServiceManager::new(test_config(true));
        let unit = mgr.generate_unit_file();

        assert!(!unit.contains("StandardOutput=journal"));
        assert!(!unit.contains("SyslogIdentifier="));
    }

    // -- Launchd tests ----------------------------------------------------

    fn test_launchd_config(user_scope: bool) -> LaunchdConfig {
        let home = PathBuf::from("/Users/tester");
        let (stdout_log, stderr_log, working_directory, config_path) = if user_scope {
            (
                home.join("Library/Logs/sbh/sbh.log"),
                home.join("Library/Logs/sbh/sbh.err"),
                home.join("Library/Application Support/sbh"),
                home.join("Library/Application Support/sbh/config.toml"),
            )
        } else {
            (
                PathBuf::from("/var/log/sbh/sbh.log"),
                PathBuf::from("/var/log/sbh/sbh.err"),
                PathBuf::from("/private/var/sbh"),
                PathBuf::from("/Library/Application Support/sbh/config.toml"),
            )
        };
        LaunchdConfig {
            label: LAUNCHD_LABEL.to_string(),
            user_scope,
            binary_path: PathBuf::from("/usr/local/bin/sbh"),
            stdout_log,
            stderr_log,
            working_directory,
            config_path,
            rust_log: "info".to_string(),
        }
    }

    fn parse_plist(xml: &str) -> plist::Value {
        plist::Value::from_reader(Cursor::new(xml.as_bytes())).expect("plist should parse")
    }

    #[test]
    fn plist_is_valid_xml() {
        let mgr = LaunchdServiceManager::new(test_launchd_config(false));
        let plist = mgr.generate_plist();

        assert!(plist.starts_with("<?xml version="));
        assert!(plist.contains("<!DOCTYPE plist"));
        assert!(plist.contains("<plist version=\"1.0\">"));
        assert!(plist.contains("</plist>"));
    }

    #[test]
    fn plist_contains_label() {
        let mgr = LaunchdServiceManager::new(test_launchd_config(false));
        let plist = mgr.generate_plist();

        assert!(plist.contains("<key>Label</key>"));
        assert!(plist.contains("<string>com.sbh.daemon</string>"));
    }

    #[test]
    fn plist_contains_program_arguments() {
        let mgr = LaunchdServiceManager::new(test_launchd_config(false));
        let plist = mgr.generate_plist();

        assert!(plist.contains("<key>ProgramArguments</key>"));
        assert!(plist.contains("<string>/usr/local/bin/sbh</string>"));
        assert!(plist.contains("<string>daemon</string>"));
    }

    #[test]
    fn plist_has_auto_restart() {
        let mgr = LaunchdServiceManager::new(test_launchd_config(false));
        let plist = mgr.generate_plist();

        assert!(plist.contains("<key>KeepAlive</key>"));
        assert!(plist.contains("<key>SuccessfulExit</key>"));
        assert!(plist.contains("<key>Crashed</key>"));
    }

    #[test]
    fn plist_has_low_priority() {
        let mgr = LaunchdServiceManager::new(test_launchd_config(false));
        let plist = mgr.generate_plist();

        assert!(plist.contains("<key>Nice</key>"));
        assert!(plist.contains("<integer>19</integer>"));
        assert!(plist.contains("<key>LowPriorityIO</key>"));
        assert!(plist.contains("<true/>"));
    }

    #[test]
    fn plist_sets_background_qos_controls() {
        let mgr = LaunchdServiceManager::new(test_launchd_config(false));
        let value = parse_plist(&mgr.generate_plist());
        let dict = value.as_dictionary().expect("plist root should be a dict");

        assert_eq!(
            dict.get("ProcessType").and_then(plist::Value::as_string),
            Some("Background")
        );
        assert_eq!(
            dict.get("LowPriorityIO").and_then(plist::Value::as_boolean),
            Some(true)
        );
        assert_eq!(
            dict.get("Nice").and_then(plist::Value::as_signed_integer),
            Some(19)
        );
        assert_eq!(
            dict.get("ThrottleInterval")
                .and_then(plist::Value::as_signed_integer),
            Some(60)
        );
    }

    #[test]
    fn plist_has_throttle_interval() {
        let mgr = LaunchdServiceManager::new(test_launchd_config(false));
        let plist = mgr.generate_plist();

        assert!(plist.contains("<key>ThrottleInterval</key>"));
        assert!(plist.contains("<integer>60</integer>"));
    }

    #[test]
    fn plist_has_run_at_load() {
        let mgr = LaunchdServiceManager::new(test_launchd_config(false));
        let plist = mgr.generate_plist();

        assert!(plist.contains("<key>RunAtLoad</key>"));
    }

    #[test]
    fn plist_has_log_paths() {
        let mgr = LaunchdServiceManager::new(test_launchd_config(false));
        let plist = mgr.generate_plist();

        assert!(plist.contains("<key>StandardOutPath</key>"));
        assert!(plist.contains("<key>StandardErrorPath</key>"));
        assert!(plist.contains("/var/log/sbh/sbh.log"));
        assert!(plist.contains("/var/log/sbh/sbh.err"));
    }

    #[test]
    fn prepare_launchd_log_paths_creates_mode_0750_dir_and_log_files() {
        let temp = tempfile::tempdir().expect("tempdir should create");
        let log_dir = temp.path().join("Library/Logs/sbh");
        let mut config = test_launchd_config(true);
        config.stdout_log = log_dir.join("sbh.log");
        config.stderr_log = log_dir.join("sbh.err");
        let mgr = LaunchdServiceManager::new(config);

        mgr.prepare_log_paths().expect("log paths should prepare");

        assert!(log_dir.is_dir());
        assert!(log_dir.join("sbh.log").is_file());
        assert!(log_dir.join("sbh.err").is_file());
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&log_dir).unwrap().permissions().mode() & 0o777,
            0o750
        );
    }

    #[test]
    fn plist_has_working_directory_process_type_and_environment() {
        let mgr = LaunchdServiceManager::new(test_launchd_config(false));
        let value = parse_plist(&mgr.generate_plist());
        let dict = value.as_dictionary().expect("plist root should be a dict");
        let env = dict
            .get("EnvironmentVariables")
            .and_then(plist::Value::as_dictionary)
            .expect("EnvironmentVariables should be a dict");

        assert_eq!(
            dict.get("WorkingDirectory")
                .and_then(plist::Value::as_string),
            Some("/private/var/sbh")
        );
        assert_eq!(
            dict.get("ProcessType").and_then(plist::Value::as_string),
            Some("Background")
        );
        assert_eq!(
            env.get("SBH_CONFIG_PATH").and_then(plist::Value::as_string),
            Some("/Library/Application Support/sbh/config.toml")
        );
        assert_eq!(
            env.get("SBH_CONFIG").and_then(plist::Value::as_string),
            Some("/Library/Application Support/sbh/config.toml")
        );
        assert_eq!(
            env.get("RUST_LOG").and_then(plist::Value::as_string),
            Some("info")
        );
        assert_eq!(
            env.get(LAUNCHD_LABEL_ENV).and_then(plist::Value::as_string),
            Some(LAUNCHD_LABEL)
        );
    }

    #[test]
    fn plist_uses_configured_launchd_label_for_isolated_ci_runs() {
        let mut config = test_launchd_config(true);
        config.label = "com.dicklesworthstone.sbh.test.123".to_string();
        let mgr = LaunchdServiceManager::new(config);
        let value = parse_plist(&mgr.generate_plist());
        let dict = value.as_dictionary().expect("plist root should be a dict");
        let env = dict
            .get("EnvironmentVariables")
            .and_then(plist::Value::as_dictionary)
            .expect("EnvironmentVariables should be a dict");

        assert_eq!(
            dict.get("Label").and_then(plist::Value::as_string),
            Some("com.dicklesworthstone.sbh.test.123")
        );
        assert_eq!(
            env.get(LAUNCHD_LABEL_ENV).and_then(plist::Value::as_string),
            Some("com.dicklesworthstone.sbh.test.123")
        );
        assert!(
            mgr.config()
                .plist_path()
                .to_string_lossy()
                .ends_with("LaunchAgents/com.dicklesworthstone.sbh.test.123.plist")
        );
    }

    #[test]
    fn plist_matches_system_snapshot() {
        let mgr = LaunchdServiceManager::new(test_launchd_config(false));
        let expected = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/snapshots/launchd_system.plist"
        ));

        assert_eq!(parse_plist(&mgr.generate_plist()), parse_plist(expected));
    }

    #[test]
    fn plist_matches_user_snapshot() {
        let mgr = LaunchdServiceManager::new(test_launchd_config(true));
        let expected = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/snapshots/launchd_user.plist"
        ));

        assert_eq!(parse_plist(&mgr.generate_plist()), parse_plist(expected));
    }

    #[test]
    fn plist_uses_configured_binary() {
        let mut config = test_launchd_config(false);
        config.binary_path = PathBuf::from("/opt/sbh/bin/sbh");
        let mgr = LaunchdServiceManager::new(config);
        let plist = mgr.generate_plist();

        assert!(plist.contains("<string>/opt/sbh/bin/sbh</string>"));
    }

    #[test]
    fn plist_path_system_scope() {
        let config = test_launchd_config(false);
        assert_eq!(
            config.plist_path(),
            PathBuf::from("/Library/LaunchDaemons/com.sbh.daemon.plist")
        );
    }

    #[test]
    fn plist_path_user_scope() {
        let config = test_launchd_config(true);
        let path = config.plist_path();
        assert!(
            path.to_string_lossy()
                .ends_with("LaunchAgents/com.sbh.daemon.plist")
        );
    }
}
