//! Distinguish a missing systemd unit from a failed runtime-state query.

#[path = "systemd_update_target.rs"]
mod update_target;

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

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
    let output = match query_output(
        Command::new("systemctl")
            .args(&args)
            .env("LC_ALL", "C")
            .stdin(Stdio::null()),
    ) {
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

// These are read-only queries, not the restart job (whose service-defined
// startup/stop timeouts must remain intact). Bound the client process itself:
// busctl's D-Bus timeout does not bound a stuck client or inherited output FDs.
pub(super) fn query_output(command: &mut Command) -> io::Result<Output> {
    query_output_with_limits(command, Duration::from_secs(5), 1024 * 1024)
}

#[cfg(unix)]
fn query_output_with_limits(
    command: &mut Command,
    timeout: Duration,
    max_output: usize,
) -> io::Result<Output> {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt as _;
    use std::time::Instant;

    // Separate sockets let us drain both streams without reader threads, disk
    // writes or unsafe fcntl calls. The child's endpoints remain blocking.
    let (mut stdout, stdout_writer) = UnixStream::pair()?;
    let (mut stderr, stderr_writer) = UnixStream::pair()?;
    stdout.set_nonblocking(true)?;
    stderr.set_nonblocking(true)?;
    let started = Instant::now();
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::from(OwnedFd::from(stdout_writer)))
        .stderr(Stdio::from(OwnedFd::from(stderr_writer)))
        .process_group(0)
        .spawn();
    // Command retains explicitly supplied FDs after spawn. Close those parent
    // copies even on spawn failure, or our own readers would never see EOF.
    command.stdout(Stdio::null()).stderr(Stdio::null());
    let mut child = QueryChild {
        child: child?,
        reaped: false,
    };
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut remaining = max_output;
    loop {
        drain_query_stream(&mut stdout, &mut out, &mut remaining)?;
        drain_query_stream(&mut stderr, &mut err, &mut remaining)?;
        if let Some(status) = child.child.try_wait()? {
            child.reaped = true;
            // Catch bytes written between the first drain and process exit.
            // Never block on a descendant that inherited a writer. A partial
            // response cannot establish that a unit is absent or safe to run.
            let out_closed = drain_query_stream(&mut stdout, &mut out, &mut remaining)?;
            let err_closed = drain_query_stream(&mut stderr, &mut err, &mut remaining)?;
            if !out_closed || !err_closed {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "service query exited without closing its output; refusing a partial response",
                ));
            }
            return Ok(Output {
                status,
                stdout: out,
                stderr: err,
            });
        }
        let Some(left) = timeout.checked_sub(started.elapsed()) else {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("service query exceeded its {timeout:?} deadline"),
            ));
        };
        std::thread::sleep(left.min(Duration::from_millis(5)));
    }
}

#[cfg(not(unix))]
fn query_output_with_limits(
    _command: &mut Command,
    _timeout: Duration,
    _max_output: usize,
) -> io::Result<Output> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "systemd service queries require a Unix host",
    ))
}

#[cfg(unix)]
fn drain_query_stream(
    stream: &mut impl io::Read,
    output: &mut Vec<u8>,
    remaining: &mut usize,
) -> io::Result<bool> {
    let mut buffer = [0u8; 4096];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                *remaining = remaining.checked_sub(count).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "service query exceeded its combined stdout/stderr byte limit",
                    )
                })?;
                output.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

#[cfg(unix)]
struct QueryChild {
    child: std::process::Child,
    reaped: bool,
}

#[cfg(unix)]
impl Drop for QueryChild {
    fn drop(&mut self) {
        if !self.reaped {
            // The unreaped leader pins this private process-group ID. Never
            // signal a group after reaping: its ID could already be reused.
            if let Ok(pid) = i32::try_from(self.child.id())
                && pid > 0
            {
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
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
            (io::ErrorKind::TimedOut, false, true),
            (io::ErrorKind::InvalidData, false, true),
            (io::ErrorKind::UnexpectedEof, false, true),
        ] {
            assert!(!missing_client_means_no_manager(error, user_scope, absent));
        }
    }
}

#[cfg(all(test, unix))]
mod query_tests {
    use super::*;
    use std::time::Instant;

    fn shell(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]);
        command
    }

    #[test]
    fn query_preserves_both_streams_exit_code_and_null_stdin() {
        let output = query_output(&mut shell(
            "if read -r line; then exit 99; fi; printf 'loaded\\n'; printf 'diagnostic\\n' >&2; exit 7",
        ))
        .unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, b"loaded\n");
        assert_eq!(output.stderr, b"diagnostic\n");
    }

    #[test]
    fn both_streams_are_drained_above_pipe_capacity() {
        let output = query_output(&mut shell(
            "head -c 262144 /dev/zero; head -c 262144 /dev/zero >&2",
        ))
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, vec![0; 262144]);
        assert_eq!(output.stderr, vec![0; 262144]);
    }

    #[test]
    fn combined_output_limit_is_enforced_even_on_successful_exit() {
        let error = query_output_with_limits(
            &mut shell("printf '12345'; printf '67890' >&2"),
            Duration::from_secs(5),
            9,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let output = query_output_with_limits(
            &mut shell("printf '12345'; printf '67890' >&2"),
            Duration::from_secs(5),
            10,
        )
        .unwrap();
        assert_eq!(output.stdout.len() + output.stderr.len(), 10);
    }

    #[test]
    fn continuously_writing_query_is_stopped_at_the_byte_limit() {
        let started = Instant::now();
        let error = query_output_with_limits(
            &mut shell("while :; do printf '0123456789abcdef'; done"),
            Duration::from_secs(5),
            1024,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn stalled_query_is_killed_and_reaped_at_the_deadline() {
        let temp = tempfile::tempdir().unwrap();
        let pid_file = temp.path().join("pid");
        let mut command = shell("printf '%s' $$ > \"$1\"; exec sleep 30");
        command.arg("query-test").arg(&pid_file);
        let started = Instant::now();
        let error = query_output_with_limits(&mut command, Duration::from_secs(1), 1024)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
        let pid = std::fs::read_to_string(pid_file)
            .unwrap()
            .parse::<i32>()
            .unwrap();
        assert_eq!(
            nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid), None),
            Err(nix::errno::Errno::ECHILD),
            "timed-out client must already have been reaped"
        );
    }

    #[test]
    fn missing_client_error_is_not_reclassified() {
        let temp = tempfile::tempdir().unwrap();
        let error = query_output(&mut Command::new(temp.path().join("missing-systemctl")))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn inherited_writer_cannot_block_or_authorize_a_partial_response() {
        let temp = tempfile::tempdir().unwrap();
        let release = temp.path().join("release-writer");
        // Release the descendant by a fixture file, never by signalling a PID
        // that may have been reaped/reused. The loop also expires on test failure.
        let mut command = shell(
            "(i=0; while [ ! -e \"$1\" ] && [ \"$i\" -lt 100 ]; do i=$((i+1)); sleep 0.1; done) & printf 'not-found\\n'; exit 0",
        );
        command.arg("query-test").arg(&release);
        let started = Instant::now();
        let result = query_output_with_limits(&mut command, Duration::from_secs(5), 1024);
        std::fs::write(release, b"done").unwrap();
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
