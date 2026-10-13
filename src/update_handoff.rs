//! The explicit update destination shared by the CLI and service activation.
//!
//! This is separate from the running executable's snapshot: a system update can
//! install elsewhere. Only a parsed update command arms destination verification;
//! normal status and service-control commands are not tied to the caller's binary.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static INSTALL_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Capture the updater's selected destination before publishing the new binary.
///
/// Pass the exact path selected by the update options, or `None` for a non-update
/// command. The destination may not exist yet. Later calls cannot change the
/// command's intent, including changing a non-update command into an update.
pub fn capture_install_path(path: Option<PathBuf>) {
    INSTALL_PATH.get_or_init(|| path);
}

/// The selected update destination, absent for normal service-control commands.
pub fn install_path() -> Option<&'static Path> {
    INSTALL_PATH.get()?.as_deref()
}

/// Acquire exclusive ownership of a Linux CLI update/rollback transaction.
///
/// Hold the returned file until backup, publication, and service activation have
/// all finished. The installation directory, not the replaceable executable,
/// is locked: atomic rename must not let a second updater acquire a new inode's
/// lock halfway through activation. Directory aliases share the same lock.
///
/// This is advisory coordination between cooperating CLI invocations, not a
/// replacement for privilege checks or post-restart image verification. It
/// creates no lockfile, never removes a stale lock, and does not wait for another
/// transaction. The kernel releases ownership when the handle/process closes.
#[cfg(target_os = "linux")]
pub fn acquire_update_lock(install_path: &Path) -> std::io::Result<std::fs::File> {
    use std::fs::{OpenOptions, TryLockError};
    use std::io::{Error, ErrorKind};
    use std::os::unix::fs::OpenOptionsExt as _;

    if !install_path.is_absolute() || install_path.file_name().is_none() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "update transaction requires an absolute binary destination",
        ));
    }
    let parent = install_path
        .parent()
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "update destination has no parent"))?;
    // First-time --system installs may not have an installation directory yet.
    // O_DIRECTORY also refuses substituted non-directories without blocking.
    std::fs::create_dir_all(parent)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(parent)?;
    match directory.try_lock() {
        Ok(()) => Ok(directory),
        Err(TryLockError::WouldBlock) => Err(Error::new(
            ErrorKind::WouldBlock,
            format!(
                "another sbh update or rollback is already modifying {}; \
                 retry after that transaction finishes",
                install_path.display()
            ),
        )),
        Err(TryLockError::Error(error)) => Err(Error::new(
            error.kind(),
            format!("cannot lock update directory {}: {error}", parent.display()),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn command_intent_is_captured_once() {
        const PROBE: &str = "SBH_UPDATE_HANDOFF_CONTEXT_PROBE";
        if let Ok(mode) = std::env::var(PROBE) {
            let target = PathBuf::from("/opt/custom destination/sbh");
            assert_eq!(install_path(), None);
            let selected = (mode == "update").then_some(target);
            capture_install_path(selected.clone());
            capture_install_path(Some(PathBuf::from("/unrelated/sbh")));
            assert_eq!(install_path(), selected.as_deref());
            return;
        }
        for mode in ["update", "ordinary"] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "update_handoff::tests::command_intent_is_captured_once",
                ])
                .env(PROBE, mode)
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod transaction_lock_tests {
    use super::*;
    use std::fs;
    use std::io::ErrorKind;
    use std::os::unix::fs::{MetadataExt as _, symlink};

    #[test]
    fn same_destination_is_exclusive_until_the_guard_is_dropped() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("bin/sbh");
        let guard = acquire_update_lock(&binary).unwrap();
        let error = acquire_update_lock(&binary).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::WouldBlock);
        assert!(error.to_string().contains("another sbh update or rollback"));
        assert!(
            fs::read_dir(binary.parent().unwrap())
                .unwrap()
                .next()
                .is_none()
        );
        drop(guard);
        assert!(acquire_update_lock(&binary).is_ok());
    }

    #[test]
    fn publication_does_not_release_the_transaction_lock() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("sbh");
        let candidate = temp.path().join("next");
        fs::write(&binary, b"old").unwrap();
        let old_inode = fs::metadata(&binary).unwrap().ino();
        let guard = acquire_update_lock(&binary).unwrap();
        fs::write(&candidate, b"new").unwrap();
        fs::rename(&candidate, &binary).unwrap();
        assert_ne!(fs::metadata(&binary).unwrap().ino(), old_inode);
        assert_eq!(
            acquire_update_lock(&binary).unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
        assert_eq!(fs::read(&binary).unwrap(), b"new");
        drop(guard);
        assert!(acquire_update_lock(&binary).is_ok());
    }

    #[test]
    fn directory_aliases_share_ownership_but_other_installations_do_not() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("actual/sbh");
        let alias = temp.path().join("alias");
        let _guard = acquire_update_lock(&binary).unwrap();
        symlink(binary.parent().unwrap(), &alias).unwrap();
        assert_eq!(
            acquire_update_lock(&alias.join("sbh")).unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
        assert!(acquire_update_lock(&temp.path().join("other/sbh")).is_ok());
    }

    #[test]
    fn contention_never_changes_binary_contents_or_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("sbh");
        fs::write(&binary, b"installed image").unwrap();
        let before = fs::metadata(&binary).unwrap();
        let _guard = acquire_update_lock(&binary).unwrap();
        assert_eq!(
            acquire_update_lock(&binary).unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
        let after = fs::metadata(&binary).unwrap();
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
        assert_eq!(after.modified().unwrap(), before.modified().unwrap());
        assert_eq!(fs::read(binary).unwrap(), b"installed image");
    }

    #[test]
    fn invalid_destinations_fail_without_creating_a_lockfile() {
        for path in [Path::new("sbh"), Path::new("/")] {
            assert_eq!(
                acquire_update_lock(path).unwrap_err().kind(),
                ErrorKind::InvalidInput
            );
        }
        let temp = tempfile::tempdir().unwrap();
        let not_a_directory = temp.path().join("file");
        fs::write(&not_a_directory, b"keep").unwrap();
        assert!(acquire_update_lock(&not_a_directory.join("sbh")).is_err());
        assert_eq!(fs::read(not_a_directory).unwrap(), b"keep");
    }
}
