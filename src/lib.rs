#![forbid(unsafe_code)]

//! Storage Ballast Helper (sbh) — system service preventing disk-full scenarios
//! from coding agent swarms.
//!
//! Three-pronged defense:
//! 1. **Ballast files** — pre-allocated sacrificial space released under pressure
//! 2. **Artifact scanner** — multi-factor scoring to find/delete stale build artifacts
//! 3. **Special location monitor** — hawk-like surveillance of /tmp, /dev/shm, etc.
//!
//! # Library usage
//!
//! Use the [`prelude`] for convenient access to the most common types:
//!
//! ```rust,no_run
//! use storage_ballast_helper::prelude::*;
//! ```
//!
//! Individual modules can also be imported directly:
//!
//! ```rust,no_run
//! use storage_ballast_helper::core::config::Config;
//! use storage_ballast_helper::scanner::walker::{DirectoryWalker, WalkerConfig};
//! ```

pub mod prelude;

pub mod ballast;
#[cfg(feature = "cli")]
pub mod cli;
pub mod core;
pub mod daemon;
pub mod logger;
pub mod monitor;
pub mod platform;
pub mod scanner;
#[cfg(feature = "tui")]
pub mod tui;

#[cfg(test)]
mod decision_plane_tests;
