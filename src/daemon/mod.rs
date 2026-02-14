//! Daemon subsystem: main monitoring loop, service integration, signal handling,
//! self-monitoring.

pub mod loop_main;
pub mod self_monitor;
pub mod service;
pub mod signals;
