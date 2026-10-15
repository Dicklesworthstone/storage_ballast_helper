//! Scanner engine rollout selection.
//!
//! The v2 engine, the default (`ScannerEngineMode::V2` in the scanner config),
//! dispatches to the opaque-pruning walker. Configuring `engine = "v1"` opts
//! back into the legacy full-descent walker.

use std::fmt;

use crate::core::config::ScannerEngineMode;

/// Concrete scanner dispatch path used for a scan pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerDispatch {
    /// Existing priority pre-scan plus directory walker implementation.
    V1DirectoryWalker,
    /// Directory walker with v2 pre-descent opaque-tree pruning enabled.
    V2OpaquePruningWalker,
}

impl fmt::Display for ScannerDispatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1DirectoryWalker => f.write_str("v1_directory_walker"),
            Self::V2OpaquePruningWalker => f.write_str("v2_opaque_pruning_walker"),
        }
    }
}

/// Common scanner engine surface for the rollout.
pub trait ScannerEngine {
    /// Config-selected engine mode.
    fn mode(&self) -> ScannerEngineMode;

    /// Concrete implementation path that will process this scan.
    fn dispatch(&self) -> ScannerDispatch;

    /// Whether this engine is currently in non-destructive shadow mode.
    fn shadow_mode(&self) -> bool;

    /// Whether the walker should enable pre-descent opaque-tree pruning.
    fn opaque_pruning(&self) -> bool;
}

/// Production scanner engine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct V1ScannerEngine;

impl ScannerEngine for V1ScannerEngine {
    fn mode(&self) -> ScannerEngineMode {
        ScannerEngineMode::V1
    }

    fn dispatch(&self) -> ScannerDispatch {
        ScannerDispatch::V1DirectoryWalker
    }

    fn shadow_mode(&self) -> bool {
        false
    }

    fn opaque_pruning(&self) -> bool {
        false
    }
}

/// Event-driven scanner rollout engine.
///
/// This type enables the v2 opaque-pruning traversal path while preserving the
/// shared scoring, guardrail, and deletion surfaces used by v1.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct V2ScannerEngine;

impl ScannerEngine for V2ScannerEngine {
    fn mode(&self) -> ScannerEngineMode {
        ScannerEngineMode::V2
    }

    fn dispatch(&self) -> ScannerDispatch {
        ScannerDispatch::V2OpaquePruningWalker
    }

    fn shadow_mode(&self) -> bool {
        false
    }

    fn opaque_pruning(&self) -> bool {
        true
    }
}

/// Config-selected engine wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedScannerEngine {
    /// Config selected the production v1 scanner.
    V1(V1ScannerEngine),
    /// Config selected the v2 opaque-pruning scanner.
    V2(V2ScannerEngine),
}

impl SelectedScannerEngine {
    /// Resolve the configured scanner mode to the current dispatch wrapper.
    #[must_use]
    pub fn for_mode(mode: ScannerEngineMode) -> Self {
        match mode {
            ScannerEngineMode::V1 => Self::V1(V1ScannerEngine),
            ScannerEngineMode::V2 => Self::V2(V2ScannerEngine),
        }
    }
}

impl ScannerEngine for SelectedScannerEngine {
    fn mode(&self) -> ScannerEngineMode {
        match self {
            Self::V1(engine) => engine.mode(),
            Self::V2(engine) => engine.mode(),
        }
    }

    fn dispatch(&self) -> ScannerDispatch {
        match self {
            Self::V1(engine) => engine.dispatch(),
            Self::V2(engine) => engine.dispatch(),
        }
    }

    fn shadow_mode(&self) -> bool {
        match self {
            Self::V1(engine) => engine.shadow_mode(),
            Self::V2(engine) => engine.shadow_mode(),
        }
    }

    fn opaque_pruning(&self) -> bool {
        match self {
            Self::V1(engine) => engine.opaque_pruning(),
            Self::V2(engine) => engine.opaque_pruning(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ScannerDispatch, ScannerEngine, SelectedScannerEngine};
    use crate::core::config::ScannerEngineMode;

    #[test]
    fn v2_enables_opaque_pruning_dispatch() {
        let engine = SelectedScannerEngine::for_mode(ScannerEngineMode::V2);

        assert_eq!(engine.mode(), ScannerEngineMode::V2);
        assert_eq!(engine.dispatch(), ScannerDispatch::V2OpaquePruningWalker);
        assert!(!engine.shadow_mode());
        assert!(engine.opaque_pruning());
    }

    #[test]
    fn v1_remains_the_non_shadow_default_dispatch() {
        let engine = SelectedScannerEngine::for_mode(ScannerEngineMode::V1);

        assert_eq!(engine.mode(), ScannerEngineMode::V1);
        assert_eq!(engine.dispatch(), ScannerDispatch::V1DirectoryWalker);
        assert!(!engine.shadow_mode());
        assert!(!engine.opaque_pruning());
    }
}
