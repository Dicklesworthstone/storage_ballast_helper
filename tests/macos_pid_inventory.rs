//! Execute the actual macOS PID-buffer negotiation against deterministic fake
//! native replies on every CI platform. This tests the production algorithm,
//! not libproc or the macOS ABI; those still require a native Mac run.

#[path = "../crates/sbh_mach/src/mach/pid_inventory.rs"]
mod pid_inventory;
