//! Preserve executable identity across self-update and service construction.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::core::errors::{Result, SbhError};

static STARTUP_BINARY: OnceLock<PathBuf> = OnceLock::new();

/// Remember the running executable before any command can replace it.
///
/// Call this at CLI startup. On Linux, resolving the executable after an atomic
/// self-update returns the old inode's name with ` (deleted)` appended. Keeping
/// the original path lets service construction use the replacement at that same
/// location, including user-local and custom installations. Failure to capture
/// is non-fatal for commands that do not need a service manager; the fallible
/// resolver will report it if needed. Repeated calls never change the snapshot.
pub fn capture_sbh_binary_path() {
    if STARTUP_BINARY.get().is_none()
        && let Ok(exe) = std::env::current_exe()
        && exe.is_file()
    {
        let _ = STARTUP_BINARY.set(exe);
    }
}

pub(super) fn resolve_sbh_binary() -> Result<PathBuf> {
    if let Some(exe) = STARTUP_BINARY.get() {
        // This is an actual pathname captured before replacement, not a procfs
        // description. Never strip a literal suffix or select another install.
        return require_binary(exe);
    }

    let exe = std::env::current_exe().map_err(|error| SbhError::Runtime {
        details: format!("could not determine the running sbh executable: {error}"),
    })?;
    resolve_current_exe_path(&exe)
}

fn require_binary(path: &Path) -> Result<PathBuf> {
    if path.is_file() {
        return Ok(path.to_path_buf());
    }
    Err(SbhError::Runtime {
        details: format!(
            "could not locate installed sbh binary at {}; refusing to select another installation",
            path.display()
        ),
    })
}

fn resolve_current_exe_path(exe: &Path) -> Result<PathBuf> {
    if exe.is_file() {
        return Ok(exe.to_path_buf());
    }

    // Library callers may not run the CLI startup hook. Recover exactly the
    // replaced pathname, without lossy UTF-8 conversion or a PATH search. Strip
    // only one final kernel marker; a directory or a real filename may itself
    // contain the same text.
    #[cfg(target_os = "linux")]
    {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        if let Some(original) = exe.as_os_str().as_bytes().strip_suffix(b" (deleted)") {
            return require_binary(Path::new(OsStr::from_bytes(original)));
        }
    }

    require_binary(exe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn binary_at(root: &Path, relative: &Path) -> PathBuf {
        let binary = root.join(relative);
        fs::create_dir_all(binary.parent().unwrap()).unwrap();
        fs::write(&binary, b"replacement binary").unwrap();
        binary
    }

    #[test]
    fn resolves_user_custom_and_system_installations_without_path_search() {
        let temp = tempfile::tempdir().unwrap();
        for relative in [
            "home/tester/.local/bin/sbh",
            "opt/sbhprev/sbh",
            "custom destination/bin/sbh",
            "usr/local/bin/sbh",
            "usr/bin/sbh",
        ] {
            let binary = binary_at(temp.path(), Path::new(relative));
            assert_eq!(resolve_current_exe_path(&binary).unwrap(), binary);
        }
    }

    #[test]
    fn missing_binary_and_directories_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let unrelated = binary_at(temp.path(), Path::new("other/bin/sbh"));
        let missing = temp.path().join("original/bin/sbh");
        let error = resolve_current_exe_path(&missing).unwrap_err().to_string();
        assert!(error.contains(&missing.display().to_string()));
        assert!(unrelated.is_file());
        assert!(resolve_current_exe_path(temp.path()).is_err());
    }

    #[test]
    fn an_existing_literal_deleted_suffix_is_not_stripped() {
        let temp = tempfile::tempdir().unwrap();
        let literal = binary_at(temp.path(), Path::new("sbh (deleted)"));
        binary_at(temp.path(), Path::new("sbh"));
        assert_eq!(resolve_current_exe_path(&literal).unwrap(), literal);
    }

    #[test]
    fn a_missing_captured_path_never_selects_a_similarly_named_binary() {
        let temp = tempfile::tempdir().unwrap();
        binary_at(temp.path(), Path::new("sbh"));
        let captured = temp.path().join("sbh (deleted)");
        assert!(require_binary(&captured).is_err());
    }

    #[cfg(target_os = "linux")]
    fn deleted_path(path: &Path) -> PathBuf {
        let mut deleted = path.as_os_str().to_os_string();
        deleted.push(" (deleted)");
        PathBuf::from(deleted)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn replaced_executable_resolves_to_the_same_installation() {
        let temp = tempfile::tempdir().unwrap();
        for relative in ["home/.local/bin/sbh", "opt/sbhprev/sbh", "custom dir/sbh"] {
            let binary = binary_at(temp.path(), Path::new(relative));
            let deleted = deleted_path(&binary);
            assert!(!deleted.exists());
            assert_eq!(resolve_current_exe_path(&deleted).unwrap(), binary);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn only_one_final_deleted_marker_is_removed() {
        let temp = tempfile::tempdir().unwrap();
        let binary = binary_at(temp.path(), Path::new("dir (deleted)/sbh (deleted)"));
        assert_eq!(
            resolve_current_exe_path(&deleted_path(&binary)).unwrap(),
            binary
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn non_utf8_installation_paths_are_preserved() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let temp = tempfile::tempdir().unwrap();
        let binary = binary_at(
            temp.path(),
            Path::new(OsStr::from_bytes(b"custom-\xff/sbh")),
        );
        assert_eq!(
            resolve_current_exe_path(&deleted_path(&binary)).unwrap(),
            binary
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn deleted_executable_without_a_replacement_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing/sbh");
        assert!(resolve_current_exe_path(&deleted_path(&missing)).is_err());
        assert!(resolve_current_exe_path(&deleted_path(temp.path())).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn captured_path_survives_real_repeated_replacement() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;

        const PROBE_ENV: &str = "SBH_EXECUTABLE_REPLACEMENT_PROBE";
        if let Some(original) = std::env::var_os(PROBE_ENV).map(PathBuf::from) {
            capture_sbh_binary_path();
            for _ in 0..2 {
                let staged = original.with_extension("next");
                fs::write(&staged, b"#!/bin/sh\nexit 0\n").unwrap();
                fs::set_permissions(&staged, fs::Permissions::from_mode(0o755)).unwrap();
                fs::rename(&staged, &original).unwrap();
                assert_eq!(std::env::current_exe().unwrap(), deleted_path(&original));
                assert_eq!(resolve_sbh_binary().unwrap(), original);
                capture_sbh_binary_path();
                assert_eq!(resolve_sbh_binary().unwrap(), original);
                assert_eq!(
                    super::super::SystemdConfig::from_env(true)
                        .unwrap()
                        .binary_path,
                    original
                );
            }
            return;
        }

        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("home/.local/bin/sbh");
        fs::create_dir_all(binary.parent().unwrap()).unwrap();
        fs::copy(std::env::current_exe().unwrap(), &binary).unwrap();
        let binary = fs::canonicalize(binary).unwrap();
        let output = Command::new(&binary)
            .args([
                "--exact",
                "daemon::service::executable::tests::captured_path_survives_real_repeated_replacement",
                "--nocapture",
            ])
            .env(PROBE_ENV, &binary)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "replacement probe failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    }
}
