//! launchd service integration.

use std::env;
use std::fs::{self, OpenOptions};
use std::io;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use plist::{Dictionary, Value};

use crate::core::config::PathsConfig;
use crate::core::errors::{Result, SbhError};
use crate::platform::pal::ServiceManager;

use super::launchctl::{self, LaunchctlDomain, LaunchctlServiceTarget};
use super::{LAUNCHD_LABEL, LAUNCHD_LABEL_ENV, ServiceOwnershipPolicy, resolve_sbh_binary};

/// Detailed launchd service status for CLI and JSON output.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LaunchdStatusReport {
    /// Service backend name.
    pub service_type: &'static str,
    /// Service scope (`"user"` or `"system"`).
    pub scope: &'static str,
    /// Full launchctl service target.
    pub target: String,
    /// Whether launchd currently knows about the service.
    pub loaded: bool,
    /// Whether the service appears to have a running process.
    pub running: bool,
    /// Raw launchd state when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Running process id when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Best-effort process elapsed runtime from `ps`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime: Option<String>,
    /// launchd active count when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_count: Option<u32>,
    /// Last exit status reported by launchd.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_exit_status: Option<i32>,
    /// Installed plist path.
    pub plist_path: PathBuf,
    /// Configured stdout log path.
    pub stdout_log: PathBuf,
    /// Configured stderr log path.
    pub stderr_log: PathBuf,
    /// Current stdout log file size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout_bytes: Option<u64>,
    /// Current stderr log file size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr_bytes: Option<u64>,
}

impl LaunchdStatusReport {
    /// Compact status label matching the `ServiceManager` contract.
    #[must_use]
    pub fn status_label(&self) -> String {
        self.state.as_ref().map_or_else(
            || {
                if self.running {
                    "running".to_string()
                } else if self.loaded {
                    "loaded".to_string()
                } else {
                    "not loaded".to_string()
                }
            },
            Clone::clone,
        )
    }
}

/// Parameters controlling launchd plist generation and lifecycle commands.
#[derive(Debug, Clone)]
pub struct LaunchdConfig {
    /// launchd label used in the plist and launchctl service target.
    pub label: String,
    /// Whether to install as user agent (vs system daemon).
    pub user_scope: bool,
    /// Absolute path to the sbh binary.
    pub binary_path: PathBuf,
    /// Path to stdout log file.
    pub stdout_log: PathBuf,
    /// Path to stderr log file.
    pub stderr_log: PathBuf,
    /// Directory launchd should use as the daemon working directory.
    pub working_directory: PathBuf,
    /// Config path exported to the daemon environment.
    pub config_path: PathBuf,
    /// RUST_LOG value exported to the daemon environment.
    pub rust_log: String,
}

impl LaunchdConfig {
    /// Build a config from the current environment.
    pub fn from_env(user_scope: bool) -> Result<Self> {
        if !user_scope && !is_running_as_root() {
            return Err(SbhError::PermissionDenied {
                path: PathBuf::from("/Library/LaunchDaemons"),
            });
        }
        Self::from_env_unchecked(user_scope)
    }

    fn from_env_unchecked(user_scope: bool) -> Result<Self> {
        let binary_path = resolve_sbh_binary()?;
        let (stdout_log, stderr_log) = default_launchd_log_paths(user_scope);
        let paths = if user_scope {
            PathsConfig::default()
        } else {
            PathsConfig::system_default()
        };
        let working_directory = paths
            .state_file
            .parent()
            .map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
        let config_path = env::var_os("SBH_CONFIG_PATH")
            .or_else(|| env::var_os("SBH_CONFIG"))
            .map_or(paths.config_file, PathBuf::from);
        let rust_log = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
        let label = launchd_label_from_env()?;
        Ok(Self {
            label,
            user_scope,
            binary_path,
            stdout_log,
            stderr_log,
            working_directory,
            config_path,
            rust_log,
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
        self.plist_dir().join(format!("{}.plist", self.label))
    }
}

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

    /// Create a manager for read/control operations.
    ///
    /// Unlike installation, status and log inspection may target a system
    /// LaunchDaemon from a non-root process. Privileged lifecycle operations
    /// still fail at `launchctl` when the caller lacks permission.
    pub fn from_env_for_control(user_scope: bool) -> Result<Self> {
        Ok(Self::new(LaunchdConfig::from_env_unchecked(user_scope)?))
    }

    /// Access the underlying config.
    #[must_use]
    pub fn config(&self) -> &LaunchdConfig {
        &self.config
    }

    fn domain_target(&self) -> LaunchctlDomain {
        launchctl::domain_for_scope(self.config.user_scope)
    }

    fn service_target(&self) -> LaunchctlServiceTarget {
        LaunchctlServiceTarget::new(self.domain_target(), self.config.label.clone())
    }

    pub(crate) fn prepare_log_paths(&self) -> Result<()> {
        prepare_launchd_log_file(&self.config.stdout_log)?;
        prepare_launchd_log_file(&self.config.stderr_log)
    }

    /// Return a detailed status report for CLI output.
    pub fn status_report(&self) -> Result<LaunchdStatusReport> {
        let target = self.service_target();
        let target_arg = target.as_arg();
        match launchctl::print(&target) {
            Ok(status) => {
                let plist_path = status
                    .plist_path
                    .as_ref()
                    .map_or_else(|| self.config.plist_path(), PathBuf::from);
                let status_label = status.summary();
                let running = status.pid.is_some() || status_label == "running";
                Ok(LaunchdStatusReport {
                    service_type: "launchd",
                    scope: if self.config.user_scope {
                        "user"
                    } else {
                        "system"
                    },
                    target: status.target,
                    loaded: status.loaded,
                    running,
                    state: status.state,
                    pid: status.pid,
                    uptime: status.pid.and_then(process_uptime),
                    active_count: status.active_count,
                    last_exit_status: status.last_exit_status,
                    plist_path,
                    stdout_log: self.config.stdout_log.clone(),
                    stderr_log: self.config.stderr_log.clone(),
                    stdout_bytes: log_file_bytes(&self.config.stdout_log),
                    stderr_bytes: log_file_bytes(&self.config.stderr_log),
                })
            }
            Err(error) if error.is_not_loaded() => Ok(LaunchdStatusReport {
                service_type: "launchd",
                scope: if self.config.user_scope {
                    "user"
                } else {
                    "system"
                },
                target: target_arg,
                loaded: false,
                running: false,
                state: None,
                pid: None,
                uptime: None,
                active_count: None,
                last_exit_status: None,
                plist_path: self.config.plist_path(),
                stdout_log: self.config.stdout_log.clone(),
                stderr_log: self.config.stderr_log.clone(),
                stdout_bytes: log_file_bytes(&self.config.stdout_log),
                stderr_bytes: log_file_bytes(&self.config.stderr_log),
            }),
            Err(error) => Err(error.into()),
        }
    }

    /// Generate the launchd plist XML content.
    #[must_use]
    pub fn generate_plist(&self) -> String {
        let mut bytes = Vec::new();
        self.plist_value()
            .to_writer_xml(&mut bytes)
            .expect("writing launchd plist to memory should not fail");
        String::from_utf8(bytes).expect("plist crate must emit UTF-8 XML")
    }

    fn plist_value(&self) -> Value {
        let mut keep_alive = Dictionary::new();
        keep_alive.insert("SuccessfulExit".to_string(), Value::Boolean(false));
        keep_alive.insert("Crashed".to_string(), Value::Boolean(true));

        let mut env_vars = Dictionary::new();
        env_vars.insert(
            "SBH_CONFIG_PATH".to_string(),
            Value::String(self.config.config_path.to_string_lossy().into_owned()),
        );
        env_vars.insert(
            "SBH_CONFIG".to_string(),
            Value::String(self.config.config_path.to_string_lossy().into_owned()),
        );
        env_vars.insert(
            "RUST_LOG".to_string(),
            Value::String(self.config.rust_log.clone()),
        );
        env_vars.insert(
            LAUNCHD_LABEL_ENV.to_string(),
            Value::String(self.config.label.clone()),
        );

        let mut root = Dictionary::new();
        root.insert(
            "Label".to_string(),
            Value::String(self.config.label.clone()),
        );
        root.insert(
            "ProgramArguments".to_string(),
            Value::Array(vec![
                Value::String(self.config.binary_path.to_string_lossy().into_owned()),
                Value::String("daemon".to_string()),
            ]),
        );
        root.insert("RunAtLoad".to_string(), Value::Boolean(true));
        root.insert("KeepAlive".to_string(), Value::Dictionary(keep_alive));
        root.insert("ThrottleInterval".to_string(), Value::Integer(60.into()));
        // macOS schedules by priority, not by share: under a saturated CPU a
        // `ProcessType=Background` (efficiency cores, throttled) or Nice 19
        // daemon gets no time at all. On mac-mini-max at load ~700 the root
        // daemon ran 0.1 s in two minutes and wrote no state for 40 minutes,
        // exactly while the machine needed a disk guardian. Standard QoS at
        // Nice 5 still yields to normal work; sbh's own CPU budget and scan
        // duty cycle bound what it takes.
        root.insert("Nice".to_string(), Value::Integer(5.into()));
        root.insert(
            "ProcessType".to_string(),
            Value::String("Standard".to_string()),
        );
        root.insert("LowPriorityIO".to_string(), Value::Boolean(true));
        root.insert(
            "WorkingDirectory".to_string(),
            Value::String(self.config.working_directory.to_string_lossy().into_owned()),
        );
        root.insert(
            "StandardOutPath".to_string(),
            Value::String(self.config.stdout_log.to_string_lossy().into_owned()),
        );
        root.insert(
            "StandardErrorPath".to_string(),
            Value::String(self.config.stderr_log.to_string_lossy().into_owned()),
        );
        root.insert(
            "EnvironmentVariables".to_string(),
            Value::Dictionary(env_vars),
        );
        Value::Dictionary(root)
    }

    fn check_binary_ownership(&self) {
        #[cfg(unix)]
        {
            if !self.config.user_scope
                && let Some(warning) = ServiceOwnershipPolicy::launchd_system_binary()
                    .warning_for_binary(&self.config.binary_path)
            {
                warning.print();
            }
        }
    }
}

impl ServiceManager for LaunchdServiceManager {
    fn install(&self) -> Result<()> {
        self.check_binary_ownership();

        let plist_dir = self.config.plist_dir();
        let plist_path = self.config.plist_path();
        let plist_content = self.generate_plist();

        self.prepare_log_paths()?;

        fs::create_dir_all(&plist_dir).map_err(|source| SbhError::Io {
            path: plist_dir.clone(),
            source,
        })?;

        fs::write(&plist_path, &plist_content).map_err(|source| SbhError::Io {
            path: plist_path.clone(),
            source,
        })?;

        let domain = self.domain_target();
        match launchctl::bootstrap(&domain, &plist_path) {
            Ok(_) => {}
            Err(error) if error.is_already_loaded() => {
                let _ = launchctl::bootout(&self.service_target());
                launchctl::bootstrap(&domain, &plist_path)?;
            }
            Err(error) => return Err(error.into()),
        }
        // Bootstrap already loads the service. A non-killing kickstart asks
        // launchd to start it without terminating the just-created job, which
        // can otherwise leave the service throttled in "spawn scheduled".
        launchctl::kickstart(&self.service_target(), false)?;
        launchctl::print(&self.service_target())?;

        Ok(())
    }

    fn uninstall(&self) -> Result<()> {
        let plist_path = self.config.plist_path();

        if let Err(error) = launchctl::bootout(&self.service_target())
            && !error.is_not_loaded()
        {
            return Err(error.into());
        }

        if plist_path.exists() {
            fs::remove_file(&plist_path).map_err(|source| SbhError::Io {
                path: plist_path.clone(),
                source,
            })?;
        }

        Ok(())
    }

    fn status(&self) -> Result<String> {
        Ok(self.status_report()?.status_label())
    }

    fn restart(&self) -> Result<()> {
        launchctl::kickstart(&self.service_target(), true)?;
        Ok(())
    }

    fn logs_path(&self) -> Result<Option<PathBuf>> {
        Ok(Some(self.config.stdout_log.clone()))
    }

    fn is_loaded(&self) -> Result<bool> {
        match launchctl::print(&self.service_target()) {
            Ok(_) => Ok(true),
            Err(error) if error.is_not_loaded() => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}

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

fn launchd_label_from_env() -> Result<String> {
    match env::var(LAUNCHD_LABEL_ENV) {
        Ok(label) => validate_launchd_label(&label),
        Err(env::VarError::NotPresent) => Ok(LAUNCHD_LABEL.to_string()),
        Err(env::VarError::NotUnicode(_)) => Err(SbhError::InvalidConfig {
            details: format!("{LAUNCHD_LABEL_ENV} must be valid UTF-8"),
        }),
    }
}

fn validate_launchd_label(label: &str) -> Result<String> {
    if label.is_empty() {
        return Err(SbhError::InvalidConfig {
            details: format!("{LAUNCHD_LABEL_ENV} must not be empty"),
        });
    }
    if label.trim() != label {
        return Err(SbhError::InvalidConfig {
            details: format!("{LAUNCHD_LABEL_ENV} must not contain surrounding whitespace"),
        });
    }
    if !label
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
    {
        return Err(SbhError::InvalidConfig {
            details: format!(
                "{LAUNCHD_LABEL_ENV} may only contain ASCII letters, digits, '.', '-', or '_'"
            ),
        });
    }
    Ok(label.to_string())
}

fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        nix::unistd::geteuid().as_raw()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

fn log_file_bytes(path: &Path) -> Option<u64> {
    fs::metadata(path).ok().map(|metadata| metadata.len())
}

fn process_uptime(pid: u32) -> Option<String> {
    let pid = pid.to_string();
    let output = Command::new("ps")
        .args(["-o", "etime=", "-p", pid.as_str()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let uptime = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if uptime.is_empty() {
        None
    } else {
        Some(uptime)
    }
}

fn launchd_log_dir_error(action: &str, dir: &Path, source: &io::Error) -> SbhError {
    SbhError::Runtime {
        details: format!(
            "launchd log directory {} cannot be {action} by uid {}: {source}. \
             The runtime user must be able to create and append logs in this directory.",
            dir.display(),
            current_uid()
        ),
    }
}

fn launchd_log_file_error(path: &Path, dir: &Path, source: &io::Error) -> SbhError {
    SbhError::Runtime {
        details: format!(
            "launchd log file {} cannot be opened for append by uid {}: {source}. \
             Verify directory {} exists with mode 0750 and is writable by the runtime user.",
            path.display(),
            current_uid(),
            dir.display()
        ),
    }
}

fn prepare_launchd_log_file(path: &Path) -> Result<()> {
    let dir = path.parent().ok_or_else(|| SbhError::Runtime {
        details: format!(
            "launchd log path {} has no parent directory",
            path.display()
        ),
    })?;

    fs::create_dir_all(dir).map_err(|source| launchd_log_dir_error("created", dir, &source))?;

    #[cfg(unix)]
    {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o750))
            .map_err(|source| launchd_log_dir_error("chmod 0750", dir, &source))?;
    }

    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|source| launchd_log_file_error(path, dir, &source))?;

    Ok(())
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn launchd_snapshot_settings(assertion: impl FnOnce()) {
        let mut settings = insta::Settings::clone_current();
        settings.set_snapshot_path("../../../tests/snapshots");
        settings.set_prepend_module_to_snapshot(false);
        settings.set_omit_expression(true);
        settings.bind(assertion);
    }

    fn launchd_user_snapshot_config() -> LaunchdConfig {
        let home = Path::new("/Users/tester");
        let paths = PathsConfig::macos_native_for_home(home);
        let working_directory = paths
            .state_file
            .parent()
            .expect("macOS state path has parent")
            .to_path_buf();
        LaunchdConfig {
            label: LAUNCHD_LABEL.to_string(),
            user_scope: true,
            binary_path: PathBuf::from("/usr/local/bin/sbh"),
            stdout_log: home.join("Library/Logs/sbh/sbh.log"),
            stderr_log: home.join("Library/Logs/sbh/sbh.err"),
            working_directory,
            config_path: paths.config_file,
            rust_log: "info".to_string(),
        }
    }

    fn launchd_system_snapshot_config() -> LaunchdConfig {
        LaunchdConfig {
            label: LAUNCHD_LABEL.to_string(),
            user_scope: false,
            binary_path: PathBuf::from("/usr/local/bin/sbh"),
            stdout_log: PathBuf::from("/var/log/sbh/sbh.log"),
            stderr_log: PathBuf::from("/var/log/sbh/sbh.err"),
            working_directory: PathBuf::from("/private/var/sbh"),
            config_path: PathBuf::from("/Library/Application Support/sbh/config.toml"),
            rust_log: "info".to_string(),
        }
    }

    #[test]
    fn launchd_user_plist_matches_snapshot() {
        let manager = LaunchdServiceManager::new(launchd_user_snapshot_config());

        launchd_snapshot_settings(|| {
            insta::assert_snapshot!("launchd_user", manager.generate_plist());
        });
    }

    #[test]
    fn launchd_system_plist_matches_snapshot() {
        let manager = LaunchdServiceManager::new(launchd_system_snapshot_config());

        launchd_snapshot_settings(|| {
            insta::assert_snapshot!("launchd_system", manager.generate_plist());
        });
    }

    #[test]
    fn launchd_watchdog_notification_is_noop() {
        let manager = LaunchdServiceManager::new(launchd_user_snapshot_config());

        assert!(!manager.watchdog_enabled(60));
        manager
            .notify_watchdog("pressure=green")
            .expect("launchd watchdog notification should be a no-op");
    }

    #[test]
    fn launchd_label_validation_accepts_reverse_dns_labels() {
        let label = validate_launchd_label("com.dicklesworthstone.sbh.test.123")
            .expect("reverse-DNS label should validate");

        assert_eq!(label, "com.dicklesworthstone.sbh.test.123");
    }

    #[test]
    fn launchd_label_validation_rejects_path_or_shell_metacharacters() {
        for label in ["", " com.sbh.daemon", "com/sbh/daemon", "com.sbh.$daemon"] {
            assert!(
                validate_launchd_label(label).is_err(),
                "label should be rejected: {label:?}"
            );
        }
    }

    #[test]
    fn service_target_uses_configured_label() {
        let config = LaunchdConfig {
            label: "com.dicklesworthstone.sbh.test.123".to_string(),
            user_scope: false,
            binary_path: PathBuf::from("/usr/local/bin/sbh"),
            stdout_log: PathBuf::from("/var/log/sbh/sbh.log"),
            stderr_log: PathBuf::from("/var/log/sbh/sbh.err"),
            working_directory: PathBuf::from("/var/lib/sbh"),
            config_path: PathBuf::from("/etc/sbh/config.toml"),
            rust_log: "info".to_string(),
        };
        let manager = LaunchdServiceManager::new(config);

        assert_eq!(
            manager.service_target().as_arg(),
            "system/com.dicklesworthstone.sbh.test.123"
        );
    }
}
