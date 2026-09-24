//! Bounded, non-interactive validation of a staged binary's `--version` command.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub(super) fn verify(path: &Path, timeout: Duration) -> Result<(), String> {
    let child = Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("failed to execute binary: {error}"))?;
    wait_for_child(child, timeout)
}

fn wait_for_child(child: Child, timeout: Duration) -> Result<(), String> {
    let mut probe = ProbeChild {
        child,
        reaped: false,
    };
    let started = Instant::now();
    loop {
        match probe.child.try_wait() {
            Ok(Some(status)) => {
                probe.reaped = true;
                return if status.success() {
                    Ok(())
                } else {
                    Err(format!("binary exited with status {status}"))
                };
            }
            Ok(None) => {}
            Err(error) => return Err(format!("failed to wait for binary self-test: {error}")),
        }
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return Err(format!(
                "binary --version self-test timed out after {} ms",
                timeout.as_millis()
            ));
        }
        std::thread::sleep((timeout - elapsed).min(Duration::from_millis(10)));
    }
}

struct ProbeChild {
    child: Child,
    reaped: bool,
}

impl Drop for ProbeChild {
    fn drop(&mut self) {
        if !self.reaped {
            // Closing pipes alone does not stop a stuck child. Always terminate
            // and reap it on timeout or a wait error; output was never buffered.
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn script(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("sbh");
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        (temp, path)
    }

    #[test]
    fn accepts_successful_version_probe() {
        let (_temp, path) = script("test \"$1\" = --version");
        verify(&path, Duration::from_secs(2)).unwrap();
    }

    #[test]
    fn reports_nonzero_exit() {
        let (_temp, path) = script("exit 7");
        assert!(verify(&path, Duration::from_secs(2)).unwrap_err().contains("status"));
    }

    #[test]
    fn reports_spawn_failure() {
        let temp = tempfile::tempdir().unwrap();
        assert!(verify(&temp.path().join("missing"), Duration::from_secs(2)).is_err());
    }

    #[test]
    fn does_not_wait_for_interactive_input() {
        let (_temp, path) = script("if read -r line; then exit 1; else exit 0; fi");
        verify(&path, Duration::from_secs(2)).unwrap();
    }

    #[test]
    fn times_out_and_reaps_stuck_child() {
        let (_temp, path) = script("exec sleep 30");
        let child = Command::new(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        #[cfg(target_os = "linux")]
        let pid = child.id();
        let error = wait_for_child(child, Duration::from_millis(40)).unwrap_err();
        assert!(error.contains("timed out"));
        #[cfg(target_os = "linux")]
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }

    #[test]
    fn noisy_child_cannot_fill_a_capture_buffer_or_pipe() {
        let (_temp, path) = script("while :; do printf 'noise'; printf 'noise' >&2; done");
        let error = verify(&path, Duration::from_millis(40)).unwrap_err();
        assert!(error.contains("timed out"));
    }
}
