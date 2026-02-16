//! Canonical runtime entrypoint for dashboard execution.

#![allow(missing_docs)]

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use crate::cli::dashboard::{self, DashboardConfig as LegacyDashboardConfig};

/// Which runtime path to execute.
///
/// `NewCockpit` is the canonical modern entrypoint. During the migration it can
/// intentionally delegate to legacy rendering while we wire model/update/view
/// internals behind the same external contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DashboardRuntimeMode {
    NewCockpit,
    LegacyFallback,
}

impl Default for DashboardRuntimeMode {
    fn default() -> Self {
        Self::NewCockpit
    }
}

/// Runtime configuration shared by both new and legacy dashboard executors.
#[derive(Debug, Clone)]
pub struct DashboardRuntimeConfig {
    pub state_file: PathBuf,
    pub refresh: Duration,
    pub monitor_paths: Vec<PathBuf>,
    pub mode: DashboardRuntimeMode,
}

impl DashboardRuntimeConfig {
    /// Build the underlying legacy dashboard config.
    #[must_use]
    pub fn as_legacy_config(&self) -> LegacyDashboardConfig {
        LegacyDashboardConfig {
            state_file: self.state_file.clone(),
            refresh: self.refresh,
            monitor_paths: self.monitor_paths.clone(),
        }
    }
}

/// Run dashboard runtime via one canonical entrypoint.
///
/// All `sbh dashboard` invocations should flow through this function while the
/// migration is in progress so runtime selection stays deterministic and testable.
///
/// # Errors
/// Returns I/O errors from terminal/event/renderer layers.
pub fn run_dashboard(config: &DashboardRuntimeConfig) -> io::Result<()> {
    match config.mode {
        DashboardRuntimeMode::NewCockpit => run_new_cockpit(config),
        DashboardRuntimeMode::LegacyFallback => run_legacy_fallback(config),
    }
}

fn run_new_cockpit(config: &DashboardRuntimeConfig) -> io::Result<()> {
    // bd-xzt.2.2+ will replace this with the new model/update/render runtime.
    // Keep the fallback contract identical during routing migration.
    run_legacy_fallback(config)
}

fn run_legacy_fallback(config: &DashboardRuntimeConfig) -> io::Result<()> {
    dashboard::run(&config.as_legacy_config())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_mode_defaults_to_new_cockpit() {
        assert_eq!(DashboardRuntimeMode::default(), DashboardRuntimeMode::NewCockpit);
    }

    #[test]
    fn runtime_config_maps_to_legacy_config() {
        let cfg = DashboardRuntimeConfig {
            state_file: PathBuf::from("/tmp/state.json"),
            refresh: Duration::from_millis(750),
            monitor_paths: vec![PathBuf::from("/tmp"), PathBuf::from("/data/projects")],
            mode: DashboardRuntimeMode::LegacyFallback,
        };

        let legacy = cfg.as_legacy_config();
        assert_eq!(legacy.state_file, PathBuf::from("/tmp/state.json"));
        assert_eq!(legacy.refresh, Duration::from_millis(750));
        assert_eq!(legacy.monitor_paths.len(), 2);
    }
}
