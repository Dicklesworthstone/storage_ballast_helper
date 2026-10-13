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
        && let Ok(exe) = resolve_uncaptured_binary()
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
    resolve_uncaptured_binary()
}

fn current_exe_path() -> Result<PathBuf> {
    std::env::current_exe().map_err(|error| SbhError::Runtime {
        details: format!("could not determine the running sbh executable: {error}"),
    })
}

fn resolve_uncaptured_binary() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;

        let running = std::fs::metadata("/proc/self/exe").map_err(|source| SbhError::Io {
            path: PathBuf::from("/proc/self/exe"),
            source,
        })?;
        // A real file can have the exact name of the kernel's deleted-path
        // description. Existence alone cannot distinguish it from a literal
        // live filename ending in " (deleted)". Compare the running image's
        // identity, and retry if a rename changed the name during inspection.
        // Link count is not sufficient: another hard link can retain the image.
        for _ in 0..3 {
            let exe = current_exe_path()?;
            let matches_running_image = std::fs::symlink_metadata(&exe).is_ok_and(|metadata| {
                metadata.is_file()
                    && metadata.dev() == running.dev()
                    && metadata.ino() == running.ino()
            });
            if current_exe_path()? != exe {
                continue;
            }
            return resolve_current_exe_path(&exe, matches_running_image);
        }
        Err(SbhError::Runtime {
            details: "running sbh executable changed location during path resolution; retry the command"
                .to_string(),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        require_binary(&current_exe_path()?)
    }
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

#[cfg(any(target_os = "linux", test))]
fn resolve_current_exe_path(exe: &Path, matches_running_image: bool) -> Result<PathBuf> {
    if matches_running_image {
        return require_binary(exe);
    }

    // Library callers may not run the CLI startup hook. Recover exactly the
    // replaced pathname, without lossy UTF-8 conversion or a PATH search. Strip
    // only one final kernel marker; a directory or a real filename may itself
    // contain the same text. An unrelated file at the decorated path must not
    // take precedence over the actual installation's replacement.
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
            assert_eq!(resolve_current_exe_path(&binary, true).unwrap(), binary);
        }
    }

    #[test]
    fn missing_binary_and_directories_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let unrelated = binary_at(temp.path(), Path::new("other/bin/sbh"));
        let missing = temp.path().join("original/bin/sbh");
        let error = resolve_current_exe_path(&missing, true).unwrap_err().to_string();
        assert!(error.contains(&missing.display().to_string()));
        assert!(unrelated.is_file());
        assert!(resolve_current_exe_path(temp.path(), true).is_err());
    }

    #[test]
    fn an_existing_literal_deleted_suffix_is_not_stripped() {
        let temp = tempfile::tempdir().unwrap();
        let literal = binary_at(temp.path(), Path::new("sbh (deleted)"));
        binary_at(temp.path(), Path::new("sbh"));
        assert_eq!(resolve_current_exe_path(&literal, true).unwrap(), literal);
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
            assert_eq!(resolve_current_exe_path(&deleted, false).unwrap(), binary);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn only_one_final_deleted_marker_is_removed() {
        let temp = tempfile::tempdir().unwrap();
        let binary = binary_at(temp.path(), Path::new("dir (deleted)/sbh (deleted)"));
        assert_eq!(
            resolve_current_exe_path(&deleted_path(&binary), false).unwrap(),
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
            resolve_current_exe_path(&deleted_path(&binary), false).unwrap(),
            binary
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn deleted_executable_without_a_replacement_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing/sbh");
        assert!(resolve_current_exe_path(&deleted_path(&missing), false).is_err());
        assert!(resolve_current_exe_path(&deleted_path(temp.path()), false).is_err());
        // A similarly named file must not turn a missing installation into success.
        fs::create_dir_all(missing.parent().unwrap()).unwrap();
        fs::write(deleted_path(&missing), b"unrelated file").unwrap();
        assert!(resolve_current_exe_path(&deleted_path(&missing), false).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_unrelated_deleted_name_never_beats_the_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let binary = binary_at(temp.path(), Path::new("sbh"));
        let decorated = deleted_path(&binary);
        fs::write(&decorated, b"unrelated executable").unwrap();
        assert_eq!(resolve_current_exe_path(&decorated, false).unwrap(), binary);
        // The same spelling is literal when it really denotes the running image.
        assert_eq!(resolve_current_exe_path(&decorated, true).unwrap(), decorated);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn uncaptured_path_ignores_a_deleted_name_decoy() {
        use std::os::unix::fs::MetadataExt;
        use std::process::Command;

        const PROBE_ENV: &str = "SBH_EXECUTABLE_REPLACEMENT_PROBE";
        if let Some(original) = std::env::var_os(PROBE_ENV).map(PathBuf::from) {
            assert!(STARTUP_BINARY.get().is_none());
            assert_eq!(resolve_sbh_binary().unwrap(), original);
            // Retain a hard link to the old image: nlink stays nonzero even
            // though procfs adds the deleted marker to the original dentry.
            fs::hard_link(&original, original.with_extension("retained")).unwrap();
            let staged = original.with_extension("next");
            fs::copy(&original, &staged).unwrap();
            fs::rename(&staged, &original).unwrap();
            let decorated = deleted_path(&original);
            fs::write(&decorated, b"unrelated file at the procfs description").unwrap();
            assert_eq!(std::env::current_exe().unwrap(), decorated);
            assert!(fs::metadata("/proc/self/exe").unwrap().nlink() > 0);
            assert!(decorated.is_file());
            assert_eq!(resolve_sbh_binary().unwrap(), original);
            assert_eq!(
                super::super::SystemdConfig::from_env(true).unwrap().binary_path,
                original
            );
            // A synthetic-name symlink to procfs has the same target inode as
            // the running image. It is still not that image's real pathname.
            fs::rename(&decorated, original.with_extension("saved-decoy")).unwrap();
            std::os::unix::fs::symlink("/proc/self/exe", &decorated).unwrap();
            assert_eq!(
                fs::metadata(&decorated).unwrap().ino(),
                fs::metadata("/proc/self/exe").unwrap().ino()
            );
            assert_eq!(resolve_sbh_binary().unwrap(), original);
            capture_sbh_binary_path();
            assert_eq!(STARTUP_BINARY.get().unwrap(), &original);
            assert_eq!(resolve_sbh_binary().unwrap(), original);
            // Neither the decoy nor the retained old image may hide a missing
            // replacement after the original spelling has been captured.
            fs::rename(&original, original.with_extension("saved-replacement")).unwrap();
            assert!(resolve_sbh_binary().is_err());
            return;
        }

        let temp = tempfile::tempdir().unwrap();
        for relative in ["home/.local/bin/sbh", "custom dir/sbh", "literal/sbh (deleted)"] {
            let binary = temp.path().join(relative);
            fs::create_dir_all(binary.parent().unwrap()).unwrap();
            fs::copy(std::env::current_exe().unwrap(), &binary).unwrap();
            let binary = fs::canonicalize(binary).unwrap();
            let output = Command::new(&binary)
                .args([
                    "--exact",
                    "daemon::service::executable::tests::uncaptured_path_ignores_a_deleted_name_decoy",
                    "--nocapture",
                ])
                .env(PROBE_ENV, &binary)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "uncaptured replacement probe failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        }
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
