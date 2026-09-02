//! Daemon subsystem: main monitoring loop, service integration, signal handling,
//! self-monitoring, and multi-channel notifications.

pub mod cpu_budget;
#[cfg(feature = "daemon")]
pub mod loop_main;
pub mod mount_controller;
pub mod notifications;
pub mod policy;
#[cfg(feature = "daemon")]
pub mod process_io_history;
pub mod self_monitor;
pub mod service;
#[cfg(feature = "daemon")]
pub mod signals;
