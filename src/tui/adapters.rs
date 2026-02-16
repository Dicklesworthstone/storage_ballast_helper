//! Typed adapter boundaries for dashboard runtime inputs.

#![allow(missing_docs)]

use std::path::Path;

use crate::daemon::self_monitor::DaemonState;

/// Health summary for runtime data sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterHealth {
    pub state_file_available: bool,
    pub telemetry_available: bool,
}

impl Default for AdapterHealth {
    fn default() -> Self {
        Self {
            state_file_available: true,
            telemetry_available: true,
        }
    }
}

/// Shared state-source contract. Implementations are added in `bd-xzt.2.3`.
pub trait StateAdapter {
    /// Returns `None` when data is unavailable or malformed.
    fn read_state(&self, state_file: &Path) -> Option<DaemonState>;

    /// Provides a coarse health signal for diagnostics.
    fn health(&self) -> AdapterHealth;
}

/// Bootstrap adapter used for scaffold wiring.
///
/// This intentionally returns `None` until the dedicated adapter bead
/// (`bd-xzt.2.3`) lands full parsing + staleness semantics.
#[derive(Debug, Default)]
pub struct NullStateAdapter;

impl StateAdapter for NullStateAdapter {
    fn read_state(&self, _state_file: &Path) -> Option<DaemonState> {
        None
    }

    fn health(&self) -> AdapterHealth {
        AdapterHealth {
            state_file_available: false,
            telemetry_available: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn null_adapter_reports_unavailable() {
        let adapter = NullStateAdapter;
        assert!(
            adapter
                .read_state(PathBuf::from("/tmp/state.json").as_path())
                .is_none()
        );
        assert_eq!(
            adapter.health(),
            AdapterHealth {
                state_file_available: false,
                telemetry_available: false,
            }
        );
    }
}
