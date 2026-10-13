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
            let selected = (mode == "update").then_some(target.clone());
            capture_install_path(selected.clone());
            capture_install_path(Some(PathBuf::from("/unrelated/sbh")));
            assert_eq!(install_path(), selected.as_deref());
            return;
        }
        for mode in ["update", "ordinary"] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "update_handoff::tests::command_intent_is_captured_once"])
                .env(PROBE, mode)
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        }
    }
}
