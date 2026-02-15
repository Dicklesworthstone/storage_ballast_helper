#![forbid(unsafe_code)]

//! Storage Ballast Helper (sbh) — system service preventing disk-full scenarios
//! from coding agent swarms.
//!
//! Three-pronged defense:
//! 1. **Ballast files** — pre-allocated sacrificial space released under pressure
//! 2. **Artifact scanner** — multi-factor scoring to find/delete stale build artifacts
//! 3. **Special location monitor** — hawk-like surveillance of /tmp, /dev/shm, etc.

pub mod ballast;
pub mod cli;
pub mod core;
pub mod daemon;
pub mod logger;
pub mod monitor;
pub mod platform;
pub mod scanner;

#[cfg(test)]
mod decision_plane_tests;
