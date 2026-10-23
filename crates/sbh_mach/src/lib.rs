//! Safe macOS adapters for storage pressure monitoring and filesystem events.
//!
//! The main crate forbids unsafe code. Native lifetime and callback ownership
//! stay inside this crate; callers receive copied values and owned paths.

#![cfg(target_os = "macos")]
#![deny(unsafe_code)]

mod mach;
pub use mach::*;

mod process_paths;
pub use process_paths::{
    PROCESS_ARGUMENTS_MAX_BYTES, proc_pid_arguments, proc_pid_cwd, proc_pid_unix_socket_path,
};

mod regions;
pub use regions::proc_pid_next_mapped_region;

pub mod fsevents;

mod unified_log;
pub use unified_log::{UNIFIED_LOG_MESSAGE_MAX_BYTES, UnifiedLogLevel, log_notification};
