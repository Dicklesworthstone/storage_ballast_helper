//! Safe macOS adapters for storage pressure monitoring and filesystem events.
//!
//! The main crate forbids unsafe code. Native lifetime and callback ownership
//! stay inside this crate; callers receive copied values and owned paths.

#![cfg(target_os = "macos")]
#![deny(unsafe_code)]

mod mach;
pub use mach::*;

mod process_paths;
pub use process_paths::{PROCESS_ARGUMENTS_MAX_BYTES, proc_pid_arguments, proc_pid_cwd};

pub mod fsevents;
