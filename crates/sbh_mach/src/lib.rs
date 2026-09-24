//! Safe macOS adapters for storage pressure monitoring and filesystem events.
//!
//! The main crate forbids unsafe code. Native lifetime and callback ownership
//! stay inside this crate; callers receive copied values and owned paths.

#![cfg(target_os = "macos")]
#![deny(unsafe_code)]

mod mach;
pub use mach::*;

pub mod fsevents;
