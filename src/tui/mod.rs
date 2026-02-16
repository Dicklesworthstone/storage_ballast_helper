//! TUI runtime scaffold and canonical dashboard entrypoint.
//!
//! This module is intentionally small in `bd-xzt.2.1`: it defines stable
//! seams (`model/update/render/adapters/input/widgets/runtime`) so later beads
//! can evolve behavior without further CLI routing churn.

#![allow(missing_docs)]

pub mod adapters;
pub mod input;
pub mod model;
pub mod render;
pub mod runtime;
pub mod telemetry;
pub mod update;
pub mod widgets;

pub use runtime::{DashboardRuntimeConfig, DashboardRuntimeMode, run_dashboard};
