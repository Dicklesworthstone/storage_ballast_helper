//! Check the manager's effective ExecStart before an update restarts a service.
//!
//! Read the typed D-Bus property, not a unit file (which misses drop-ins) or
//! systemctl's display-oriented ExecStart string (which does not unambiguously
//! escape arbitrary paths). No service configuration is rewritten here.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Deserialize;

use crate::core::errors::{Result, SbhError};

const SERVICE_BUS_NAME: &str = "org.freedesktop.systemd1";
const SERVICE_OBJECT: &str = "/org/freedesktop/systemd1/unit/sbh_2eservice";
const SERVICE_INTERFACE: &str = "org.freedesktop.systemd1.Service";
const EXEC_START_TYPE: &str = "a(sasbttttuii)";

// org.freedesktop.systemd1.Service.ExecStart: executable, argv, ignore-failure,
// four timestamps, PID, exit code, exit status. busctl get-property emits the
// variant value directly in `data`, unlike a busctl method-call reply.
type ExecCommand = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);

#[derive(Deserialize)]
struct ExecStartProperty {
    #[serde(rename = "type")]
    signature: String,
    data: Vec<ExecCommand>,
}

pub(super) fn verify(user_scope: bool, installed: &Path) -> Result<()> {
    let scope = if user_scope { "--user" } else { "--system" };
    let output = Command::new("busctl")
        .args([
            scope,
            "--json=short",
            "--timeout=5s",
            "--auto-start=no",
            "--allow-interactive-authorization=no",
            "get-property",
            SERVICE_BUS_NAME,
            SERVICE_OBJECT,
            SERVICE_INTERFACE,
            "ExecStart",
        ])
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            runtime(format!(
                "cannot verify sbh.service's update target: could not run busctl: {error}; \
                 install the systemd busctl utility before retrying the service restart"
            ))
        })?;
    if !output.status.success() {
        return Err(runtime(format!(
            "cannot verify sbh.service's update target: busctl {scope} ExecStart failed \
             (exit {:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let executable = parse_exec_start(&output.stdout)?;
    verify_same_binary(installed, &executable)
}

fn parse_exec_start(json: &[u8]) -> Result<PathBuf> {
    let property: ExecStartProperty = serde_json::from_slice(json)
        .map_err(|error| runtime(format!("invalid busctl ExecStart response: {error}")))?;
    if property.signature != EXEC_START_TYPE || property.data.len() != 1 {
        return Err(runtime(
            "expected exactly one typed ExecStart command for sbh.service".to_string(),
        ));
    }
    let command = &property.data[0];
    let executable = PathBuf::from(&command.0);
    if !executable.is_absolute() || command.0.contains('\0') || command.1.is_empty() {
        return Err(runtime(
            "invalid executable in sbh.service ExecStart".to_string(),
        ));
    }
    Ok(executable)
}

fn verify_same_binary(installed: &Path, service_binary: &Path) -> Result<()> {
    let expected = binary_metadata(installed)?;
    let actual = binary_metadata(service_binary)?;
    #[cfg(unix)]
    let same = {
        use std::os::unix::fs::MetadataExt;
        (expected.dev(), expected.ino()) == (actual.dev(), actual.ino())
    };
    #[cfg(not(unix))]
    let same = {
        let _ = (expected, actual);
        let expected = fs::canonicalize(installed).map_err(|source| SbhError::Io {
            path: installed.to_path_buf(),
            source,
        })?;
        let actual = fs::canonicalize(service_binary).map_err(|source| SbhError::Io {
            path: service_binary.to_path_buf(),
            source,
        })?;
        expected == actual
    };
    if same {
        return Ok(());
    }
    Err(runtime(format!(
        "sbh.service ExecStart uses {}, but the update was installed to {}; \
         refusing to restart a different installation. Update the service's installation \
         or repair its ExecStart explicitly; no unit files were changed",
        service_binary.display(),
        installed.display()
    )))
}

fn binary_metadata(path: &Path) -> Result<fs::Metadata> {
    if !path.is_absolute() {
        return Err(runtime(format!(
            "service executable must be absolute: {}",
            path.display()
        )));
    }
    let metadata = fs::metadata(path).map_err(|source| SbhError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(runtime(format!(
            "service executable is not a file: {}",
            path.display()
        )));
    }
    Ok(metadata)
}

fn runtime(details: String) -> SbhError {
    SbhError::Runtime { details }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn command(path: &str) -> serde_json::Value {
        json!([path, [path, "daemon"], false, 0, 0, 0, 0, 0, 0, 0])
    }

    fn property(commands: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"type": EXEC_START_TYPE, "data": commands})).unwrap()
    }

    #[test]
    fn typed_exec_start_preserves_spaces_quotes_and_delimiters() {
        for path in [
            "/home/tester/.local/bin/sbh",
            "/opt/custom destination/sbh",
            "/opt/quote\" and \\ slash/sbh",
            "/opt/ ; argv[]=not-the-path/sbh",
            "/opt/line\nbreak/sbh",
            "/opt/日本語/sbh",
        ] {
            assert_eq!(
                parse_exec_start(&property(json!([command(path)]))).unwrap(),
                Path::new(path)
            );
        }
    }

    #[test]
    fn missing_multiple_and_malformed_commands_are_rejected() {
        for commands in [
            json!([]),
            json!([command("/one"), command("/two")]),
            json!([["/short"]]),
        ] {
            assert!(parse_exec_start(&property(commands)).is_err());
        }
        for path in ["", "sbh", "/opt/null\0byte/sbh"] {
            assert!(parse_exec_start(&property(json!([command(path)]))).is_err());
        }
        assert!(parse_exec_start(br#"{"type":"as","data":[]}"#).is_err());
        assert!(parse_exec_start(b"not json").is_err());
        let no_args = property(json!([["/sbh", [], false, 0, 0, 0, 0, 0, 0, 0]]));
        assert!(parse_exec_start(&no_args).is_err());
    }

    #[test]
    fn a_separate_copy_with_identical_bytes_is_not_the_updated_installation() {
        let temp = tempfile::tempdir().unwrap();
        let installed = temp.path().join("sbh");
        let other = temp.path().join("other-sbh");
        fs::write(&installed, b"same version").unwrap();
        fs::copy(&installed, &other).unwrap();
        assert!(verify_same_binary(&installed, &installed).is_ok());
        let error = verify_same_binary(&installed, &other)
            .unwrap_err()
            .to_string();
        assert!(error.contains("refusing to restart a different installation"));
        assert!(error.contains(&installed.display().to_string()));
        assert!(error.contains(&other.display().to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_to_updated_installation_is_accepted_but_retained_old_inode_is_not() {
        let temp = tempfile::tempdir().unwrap();
        let installed = temp.path().join("sbh");
        let linked = temp.path().join("symlink");
        let old = temp.path().join("retained-old-inode");
        let staged = temp.path().join("new");
        fs::write(&installed, b"old").unwrap();
        std::os::unix::fs::symlink(&installed, &linked).unwrap();
        fs::hard_link(&installed, &old).unwrap();
        assert!(verify_same_binary(&installed, &old).is_ok());
        fs::write(&staged, b"new").unwrap();
        fs::rename(&staged, &installed).unwrap();
        assert!(verify_same_binary(&installed, &linked).is_ok());
        assert!(verify_same_binary(&installed, &old).is_err());
    }

    #[test]
    fn missing_or_non_file_targets_never_pass() {
        let temp = tempfile::tempdir().unwrap();
        let installed = temp.path().join("sbh");
        fs::write(&installed, b"new").unwrap();
        assert!(verify_same_binary(&installed, temp.path()).is_err());
        assert!(verify_same_binary(&installed, &temp.path().join("missing")).is_err());
        assert!(verify_same_binary(&temp.path().join("missing"), &installed).is_err());
        assert!(verify_same_binary(Path::new("sbh"), &installed).is_err());
    }
}
