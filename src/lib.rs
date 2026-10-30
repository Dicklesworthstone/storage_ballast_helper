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
pub mod fuzzing;
pub mod logger;
pub mod monitor;
pub mod platform;
#[cfg(unix)]
pub mod relocate;
pub mod scanner;
#[cfg(feature = "tui")]
pub mod tui;
pub mod tuning;
pub mod update_handoff;

#[cfg(test)]
mod decision_plane_tests;

/// A scratch directory for a test whose fixture must not sit inside a Git
/// checkout. Under rch, `TMPDIR` is `<mirror>/.rch-tmp`, and most workers'
/// mirrors are Git checkouts, so a fixture there is repository content to
/// every git-aware rule (30 lib tests failed that way on 8 of 10 workers,
/// 2026-10-29).
#[cfg(test)]
pub(crate) fn tempdir_outside_git() -> tempfile::TempDir {
    let base = std::env::temp_dir();
    if base.ancestors().any(|dir| dir.join(".git").exists()) {
        tempfile::tempdir_in("/tmp").expect("scratch directory outside any checkout")
    } else {
        tempfile::tempdir().expect("scratch directory")
    }
}
