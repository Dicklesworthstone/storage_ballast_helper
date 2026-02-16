//! TUI runtime scaffold and canonical dashboard entrypoint.
//!
//! This module is intentionally small in `bd-xzt.2.1`: it defines stable
//! seams (`model/update/render/adapters/input/widgets/runtime`) so later beads
//! can evolve behavior without further CLI routing churn.

#![allow(missing_docs)]

pub mod adapters;
pub mod e2e_artifact;
pub mod input;
pub mod layout;
pub mod model;
pub mod preferences;
pub mod render;
pub mod runtime;
pub mod telemetry;
pub mod terminal_guard;
pub mod theme;
pub mod update;
pub mod widgets;

#[cfg(test)]
mod parity_harness;
#[cfg(test)]
mod test_artifact;
#[cfg(test)]
mod test_fault_injection;
#[cfg(test)]
mod test_harness;
#[cfg(test)]
mod test_replay;

pub use runtime::{DashboardRuntimeConfig, DashboardRuntimeMode, run_dashboard};
