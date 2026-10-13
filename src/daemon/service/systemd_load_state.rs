//! Distinguish a missing systemd unit from a failed runtime-state query.

#[path = "systemd_update_target.rs"]
mod update_target;

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::core::errors::{Result, SbhError};

use super::{SYSTEMD_UNIT_NAME, format_systemctl_failure};

pub(super) fn is_loaded(user_scope: bool, unit_path: &Path) -> Result<bool> {
    let mut args = Vec::with_capacity(5);
    if user_scope {
        args.push("--user".to_string());
    }
    args.extend(
        ["show", SYSTEMD_UNIT_NAME, "--property=LoadState", "--value"]
            .into_iter()
            .map(str::to_string),
    );
    let output = match Command::new("systemctl")
        .args(&args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .output()
    {
        Ok(output) => output,
        Err(source) => {
            // A minimal container may lack both systemctl and systemd. Missing
            // the client alone is not evidence that a service is absent.
            let runtime_absent = std::fs::metadata("/run/systemd/system")
                .is_err_and(|error| error.kind() == io::ErrorKind::NotFound);
            if missing_client_means_no_manager(source.kind(), user_scope, runtime_absent) {
                return Ok(false);
            }
            return Err(SbhError::Io {
                path: PathBuf::from("systemctl"),
                source,
            });
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let loaded = classify_load_state(output.status.code(), &stdout, &stderr, user_scope).map_err(
        |reason| SbhError::Runtime {
            details: if output.status.success() {
                format!("cannot determine whether {SYSTEMD_UNIT_NAME} is loaded: {reason}")
            } else {
                format_systemctl_failure(
                    &args,
                    output.status.code(),
                    &stdout,
                    &stderr,
                    unit_path,
                    user_scope,
                )
            },
        },
    )?;
    // Only the update command arms this preflight. Normal status/control flows
    // still inspect arbitrary installations. Missing units skip successfully
    // without requiring busctl; loaded units must target the published binary
    // before the caller can proceed to its privilege check and restart.
    if loaded && let Some(installed) = crate::update_handoff::install_path() {
        update_target::verify(user_scope, installed)?;
    }
    Ok(loaded)
}

fn missing_client_means_no_manager(
    error: io::ErrorKind,
    user_scope: bool,
    runtime_absent: bool,
) -> bool {
    error == io::ErrorKind::NotFound && !user_scope && runtime_absent
}

fn classify_load_state(
    exit_code: Option<i32>,
    stdout: &str,
    stderr: &str,
    user_scope: bool,
) -> std::result::Result<bool, String> {
    let state = stdout.trim();
    // show usually returns zero for not-found; also accept the unknown-unit
    // exit code, but never an arbitrary error or a signal.
    if matches!(exit_code, Some(0 | 4)) && state == "not-found" {
        return Ok(false);
    }
    if exit_code == Some(0) {
        return match state {
            "loaded" => Ok(true),
            "masked" | "error" | "bad-setting" => Err(format!(
                "LoadState={state}; the service cannot be safely restarted"
            )),
            _ => Err(format!("unexpected LoadState response: {state:?}")),
        };
    }
    // Only the explicit systemd-not-booted diagnostic establishes absence.
    // Generic bus/permission failures must reach the update error report.
    if exit_code == Some(1)
        && !user_scope
        && state.is_empty()
        && stderr.lines().any(|line| {
            line.trim()
                == "System has not been booted with systemd as init system (PID 1). Can't operate."
        })
    {
        return Ok(false);
    }
    Err(format!(
        "systemctl load-state query failed (exit {exit_code:?}): {}",
        stderr.trim()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NO_MANAGER: &str = "System has not been booted with systemd as init system (PID 1). Can't operate.\nFailed to connect to bus: Host is down\n";

    #[test]
    fn loaded_is_independent_of_enablement_and_scope() {
        for user_scope in [false, true] {
            assert!(classify_load_state(Some(0), "loaded\n", "", user_scope).unwrap());
            assert!(!classify_load_state(Some(0), "not-found\n", "", user_scope).unwrap());
            assert!(!classify_load_state(Some(4), "not-found\n", "", user_scope).unwrap());
            assert!(classify_load_state(Some(0), "enabled\n", "", user_scope).is_err());
            assert!(classify_load_state(Some(1), "disabled\n", "", user_scope).is_err());
        }
    }

    #[test]
    fn broken_masked_and_unrecognized_units_are_not_silently_skipped() {
        for (state, expected) in [
            ("masked", "LoadState=masked"),
            ("error", "LoadState=error"),
            ("bad-setting", "LoadState=bad-setting"),
            ("", "unexpected LoadState"),
            ("stub", "unexpected LoadState"),
            ("loaded\nnot-found", "unexpected LoadState"),
        ] {
            let error = classify_load_state(Some(0), state, "", false).unwrap_err();
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn permission_bus_and_signal_failures_do_not_become_absence() {
        for stderr in [
            "Access denied",
            "Failed to connect to bus: Permission denied",
            "Failed to connect to bus: No such file or directory",
            "Failed to connect to bus: Connection refused",
            "Failed to connect to bus: Host is down",
            "Failed to connect to bus: No medium found",
        ] {
            for user_scope in [false, true] {
                assert!(classify_load_state(Some(1), "", stderr, user_scope).is_err());
            }
        }
        for exit in [None, Some(1), Some(23)] {
            assert!(classify_load_state(exit, "loaded", "", false).is_err());
            assert!(classify_load_state(exit, "not-found", "", false).is_err());
        }
    }

    #[test]
    fn only_an_explicit_non_systemd_system_scope_is_skipped() {
        assert!(!classify_load_state(Some(1), "", NO_MANAGER, false).unwrap());
        assert!(classify_load_state(Some(1), "", NO_MANAGER, true).is_err());
        assert!(classify_load_state(None, "", NO_MANAGER, false).is_err());
        assert!(classify_load_state(Some(23), "", NO_MANAGER, false).is_err());
        assert!(classify_load_state(Some(1), "loaded", NO_MANAGER, false).is_err());
    }

    #[test]
    fn missing_client_requires_evidence_that_system_runtime_is_absent() {
        assert!(missing_client_means_no_manager(
            io::ErrorKind::NotFound,
            false,
            true
        ));
        for (error, user_scope, absent) in [
            (io::ErrorKind::NotFound, false, false),
            (io::ErrorKind::NotFound, true, true),
            (io::ErrorKind::PermissionDenied, false, true),
            (io::ErrorKind::Other, false, true),
        ] {
            assert!(!missing_client_means_no_manager(error, user_scope, absent));
        }
    }
}
