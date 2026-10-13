//! Verify that a successful restart actually activated the installed Linux image.
//!
//! A successful systemctl job is not proof of activation: a condition can skip
//! startup, Type=simple can return before exec, and another installation may run.

use std::fs::{self, File};
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::Value;

use crate::core::errors::{Result, SbhError};

const ACTIVATION_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const BUS_NAME: &str = "org.freedesktop.systemd1";
const OBJECT: &str = "/org/freedesktop/systemd1/unit/sbh_2eservice";

pub(super) fn restart_verified<F>(user_scope: bool, installed: &Path, restart: F) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    // Keep the inode alive through verification. A concurrent update must not
    // change the expected image, or let a reused inode satisfy the check.
    let image = File::open(installed).map_err(|source| SbhError::Io {
        path: installed.to_path_buf(),
        source,
    })?;
    let expected = image.metadata().map_err(|source| SbhError::Io {
        path: installed.to_path_buf(),
        source,
    })?;
    if !expected.is_file() {
        return Err(runtime("installed update is not a regular file"));
    }
    // Recheck immediately before the restart, not only during is_loaded().
    super::update_target::verify(user_scope, installed)?;
    require_unchanged_installation(installed, &expected)?;
    restart()?;
    wait_for_activation(installed, &expected, ACTIVATION_TIMEOUT, |deadline| {
        read_runtime(user_scope, deadline)
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeState {
    active: String,
    sub: String,
    pid: u32,
    started: u64,
}

impl RuntimeState {
    fn is_running(&self) -> bool {
        self.active == "active" && self.sub == "running" && self.pid > 0 && self.started > 0
    }

    fn terminal(&self) -> bool {
        matches!(self.active.as_str(), "inactive" | "failed" | "deactivating")
            || (self.active == "active" && self.sub == "exited")
    }

    fn diagnostic(&self) -> String {
        format!(
            "ActiveState={}, SubState={}, MainPID={}, ExecMainStartTimestampMonotonic={}",
            self.active, self.sub, self.pid, self.started
        )
    }
}

fn wait_for_activation<F>(
    installed: &Path,
    expected: &fs::Metadata,
    timeout: Duration,
    mut query: F,
) -> Result<()>
where
    F: FnMut(Instant) -> Result<RuntimeState>,
{
    let deadline = Instant::now() + timeout;
    let mut previous = None;
    loop {
        let state = query(deadline)?;
        require_unchanged_installation(installed, expected)?;
        if state.terminal() {
            return Err(runtime(format!(
                "sbh.service did not activate after update: {}; the installed binary was retained",
                state.diagnostic()
            )));
        }
        let matching = state.is_running() && running_image_matches(state.pid, expected)?;
        let identity = (state.pid, state.started);
        if matching && previous == Some(identity) {
            // Two consecutive observations must agree on the process and its
            // running inode. Never infer activation from the executable's name.
            return Ok(());
        }
        previous = matching.then_some(identity);
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(runtime(format!(
                "could not confirm sbh.service is running the installed update at {}: {}; \
                 running executable differs, is unavailable, or did not stabilize; \
                 inspect systemctl status and the service journal",
                installed.display(),
                state.diagnostic()
            )));
        }
        std::thread::sleep(POLL_INTERVAL.min(remaining));
    }
}

fn same_image(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.is_file() && right.is_file() && left.dev() == right.dev() && left.ino() == right.ino()
}

fn require_unchanged_installation(installed: &Path, expected: &fs::Metadata) -> Result<()> {
    let observed = fs::metadata(installed).map_err(|source| SbhError::Io {
        path: installed.to_path_buf(),
        source,
    })?;
    if same_image(expected, &observed) {
        return Ok(());
    }
    Err(runtime(format!(
        "installed update changed during service activation at {}; refusing to report success",
        installed.display()
    )))
}

fn running_image_matches(pid: u32, expected: &fs::Metadata) -> Result<bool> {
    let path = PathBuf::from(format!("/proc/{pid}/exe"));
    match fs::metadata(&path) {
        Ok(observed) => Ok(same_image(expected, &observed)),
        // Type=simple can report running before exec, and a process may exit
        // between the manager query and procfs inspection. Retry only absence.
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(SbhError::Io { path, source }),
    }
}

#[derive(Debug, Deserialize)]
struct Property {
    #[serde(rename = "type")]
    signature: String,
    data: Value,
}

fn read_runtime(user_scope: bool, deadline: Instant) -> Result<RuntimeState> {
    let unit = read_properties(
        user_scope,
        "org.freedesktop.systemd1.Unit",
        &["ActiveState", "SubState"],
        deadline,
    )?;
    let service = read_properties(
        user_scope,
        "org.freedesktop.systemd1.Service",
        &["MainPID", "ExecMainStartTimestampMonotonic"],
        deadline,
    )?;
    parse_runtime(&unit, &service)
}

fn parse_runtime(unit: &[u8], service: &[u8]) -> Result<RuntimeState> {
    let unit = parse_properties(unit, &["s", "s"])?;
    let service = parse_properties(service, &["u", "t"])?;
    let invalid = || runtime("invalid typed systemd activation properties");
    Ok(RuntimeState {
        active: unit[0].data.as_str().ok_or_else(invalid)?.to_string(),
        sub: unit[1].data.as_str().ok_or_else(invalid)?.to_string(),
        pid: u32::try_from(service[0].data.as_u64().ok_or_else(invalid)?).map_err(|_| invalid())?,
        started: service[1].data.as_u64().ok_or_else(invalid)?,
    })
}

fn parse_properties(bytes: &[u8], signatures: &[&str]) -> Result<Vec<Property>> {
    let properties = serde_json::Deserializer::from_slice(bytes)
        .into_iter::<Property>()
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| runtime(format!("invalid busctl activation response: {error}")))?;
    if properties.len() != signatures.len()
        || properties
            .iter()
            .zip(signatures)
            .any(|(property, signature)| property.signature != *signature)
    {
        return Err(runtime("unexpected typed busctl activation properties"));
    }
    Ok(properties)
}

fn read_properties(
    user_scope: bool,
    interface: &str,
    names: &[&str],
    deadline: Instant,
) -> Result<Vec<u8>> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(runtime(
            "timed out verifying sbh.service activation after update",
        ));
    }
    let scope = if user_scope { "--user" } else { "--system" };
    // Bound the client process and combined output too, not just each D-Bus
    // call. All queries share the remaining activation deadline.
    let output = super::query_output_with_limits(
        Command::new("busctl")
            .args([scope, "--json=short", "--auto-start=no"])
            .arg("--allow-interactive-authorization=no")
            .arg(format!("--timeout={}us", remaining.as_micros().max(1)))
            .args(["get-property", BUS_NAME, OBJECT, interface])
            .args(names)
            .env("LC_ALL", "C")
            .stdin(Stdio::null()),
        remaining,
        1024 * 1024,
    )
    .map_err(|error| {
        runtime(format!(
            "could not verify service activation with busctl: {error}"
        ))
    })?;
    if !output.status.success() {
        return Err(runtime(format!(
            "busctl {scope} {} activation query failed (exit {:?}): {}",
            names.join(","),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(output.stdout)
}

fn runtime(details: impl Into<String>) -> SbhError {
    SbhError::Runtime {
        details: details.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn current_state() -> RuntimeState {
        RuntimeState {
            active: "active".to_string(),
            sub: "running".to_string(),
            pid: std::process::id(),
            started: 1,
        }
    }

    #[test]
    fn activation_requires_two_stable_observations_of_the_running_image() {
        let installed = std::env::current_exe().unwrap();
        let expected = fs::metadata(&installed).unwrap();
        let mut observations = 0;
        wait_for_activation(&installed, &expected, Duration::from_secs(1), |_| {
            observations += 1;
            Ok(current_state())
        })
        .unwrap();
        assert_eq!(observations, 2);
    }

    #[test]
    fn process_generation_change_requires_a_new_stable_pair() {
        let installed = std::env::current_exe().unwrap();
        let expected = fs::metadata(&installed).unwrap();
        let mut observations = 0;
        wait_for_activation(&installed, &expected, Duration::from_secs(1), |_| {
            observations += 1;
            let mut state = current_state();
            state.started = if observations == 1 { 1 } else { 2 };
            Ok(state)
        })
        .unwrap();
        assert_eq!(observations, 3);
    }

    #[test]
    fn skipped_conditions_failed_and_exited_services_are_not_activation() {
        let installed = std::env::current_exe().unwrap();
        let expected = fs::metadata(&installed).unwrap();
        for (active, sub) in [
            ("inactive", "dead"),
            ("failed", "failed"),
            ("active", "exited"),
        ] {
            let error = wait_for_activation(&installed, &expected, Duration::ZERO, |_| {
                Ok(RuntimeState {
                    active: active.to_string(),
                    sub: sub.to_string(),
                    ..current_state()
                })
            })
            .unwrap_err()
            .to_string();
            assert!(error.contains("did not activate"), "{error}");
        }
    }

    #[test]
    fn a_correct_name_or_identical_copy_cannot_hide_a_stale_running_inode() {
        let dir = tempfile::tempdir().unwrap();
        let installed = dir.path().join("sbh");
        fs::copy(std::env::current_exe().unwrap(), &installed).unwrap();
        let expected = fs::metadata(&installed).unwrap();
        let error = wait_for_activation(&installed, &expected, Duration::ZERO, |_| {
            Ok(current_state())
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("running executable differs"), "{error}");
    }

    #[test]
    fn missing_pid_zero_pid_and_startup_states_never_pass() {
        let installed = std::env::current_exe().unwrap();
        let expected = fs::metadata(&installed).unwrap();
        for state in [
            RuntimeState {
                pid: 0,
                ..current_state()
            },
            RuntimeState {
                pid: u32::MAX,
                ..current_state()
            },
            RuntimeState {
                started: 0,
                ..current_state()
            },
            RuntimeState {
                active: "activating".to_string(),
                ..current_state()
            },
        ] {
            assert!(
                wait_for_activation(&installed, &expected, Duration::ZERO, |_| {
                    Ok(state.clone())
                })
                .is_err()
            );
        }
    }

    #[test]
    fn query_failure_and_replaced_installation_are_reported() {
        let installed = std::env::current_exe().unwrap();
        let expected = fs::metadata(&installed).unwrap();
        let error = wait_for_activation(&installed, &expected, Duration::ZERO, |_| {
            Err(runtime("bus permission denied"))
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("bus permission denied"));
        let dir = tempfile::tempdir().unwrap();
        let replaced = dir.path().join("sbh");
        fs::write(&replaced, b"different image").unwrap();
        let error = require_unchanged_installation(&replaced, &expected)
            .unwrap_err()
            .to_string();
        assert!(error.contains("changed during service activation"));
    }

    #[test]
    fn runtime_properties_preserve_types_order_and_cardinality() {
        let unit = b"{\"type\":\"s\",\"data\":\"active\"}\n{\"type\":\"s\",\"data\":\"running\"}\n";
        let service = b"{\"type\":\"u\",\"data\":42}\n{\"type\":\"t\",\"data\":1234}\n";
        let state = parse_runtime(unit, service).unwrap();
        assert!(state.is_running());
        assert_eq!((state.pid, state.started), (42, 1234));
        for data in [json!(-1), json!("42"), json!(u64::from(u32::MAX) + 1)] {
            let service = format!(
                "{}\n{}",
                json!({"type":"u", "data":data}),
                json!({"type":"t", "data":1})
            );
            assert!(parse_runtime(unit, service.as_bytes()).is_err());
        }
        assert!(parse_runtime(unit, b"{\"type\":\"u\",\"data\":42}").is_err());
        assert!(parse_runtime(service, unit).is_err());
        assert!(parse_runtime(b"not json", service).is_err());
        assert!(parse_runtime(unit, &[service.as_slice(), service.as_slice()].concat()).is_err());
    }
}
