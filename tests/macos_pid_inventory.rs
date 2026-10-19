//! Execute the actual macOS PID-buffer negotiation against deterministic fake
//! native replies on every CI platform. This tests the production algorithm,
//! not libproc or the macOS ABI; those still require a native Mac run.

// Its `pub(super)` items are sized for their place in sbh_mach; included
// here as a private test module, clippy calls that visibility redundant.
#[allow(clippy::redundant_pub_crate)]
#[path = "../crates/sbh_mach/src/mach/pid_inventory.rs"]
mod pid_inventory;
