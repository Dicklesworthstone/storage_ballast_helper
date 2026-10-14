//! Relocation of dormant protected scratch (`sbh relocate`).
//!
//! A `.sbh-protect` marker has no expiry: it records who protected a tree and
//! when, never for how long. Agents mark live caches and scratch so cleanup
//! leaves them alone, and the marker then outlives the work forever. On
//! 2026-10-14 the fleet held 962 GiB in 1,438 protected trees under scratch
//! roots, much of it on RAM-backed tmpfs.
//!
//! Protection still means "never delete". It no longer means "never move":
//! a protected tree whose every entry has gone unchanged, and unread, for
//! `min_idle_days` (14 by default), and that no live process holds, may be
//! copied to a backup location, verified byte for byte, and replaced by a
//! stub that says where it went and how to bring it back
//! (`sbh relocate --restore <stub>`).
//!
//! "Unread" needs evidence. A mount that maintains atime (relatime,
//! strictatime) provides it: the newest regular-file atime in the tree.
//! Directory atimes are ignored, because every scanner's `readdir` bumps
//! them. A `noatime` mount provides none, so there the evidence comes from
//! the ledger instead: the tree must have been observed, unchanged and
//! unheld, across sweeps spanning the whole idle window, with no gap between
//! sweeps longer than `max_gap_hours`.
//!
//! What is never a candidate, even when dormant:
//! - anything outside the configured scratch roots (`/home`, project trees
//!   and cargo homes in a home directory are not roots);
//! - shared tool caches by name (`.cargo`, `rch*`, `*cargo-cache*`, cass
//!   data, sbh's own `.sbh` store), because a quiet fortnight does not prove
//!   a shared cache is dead;
//! - a tree whose marker says `relocatable = false`;
//! - a tree that crosses a mount, could not be fully read, or is held by a
//!   process (open file, cwd, executable, mapping, or a live build's cargo
//!   home or target dir).

pub mod config;
pub mod ledger;
pub mod plan;
pub mod survey;

#[cfg(target_os = "linux")]
pub mod execute;

/// Name of the record written into a stub and next to the relocated copy.
pub const RECORD_FILENAME: &str = ".sbh-relocated.json";

/// Human-readable explanation written into a stub.
pub const README_FILENAME: &str = "RELOCATED.md";

/// Schema tag of the record and the JSON report.
pub const SCHEMA: &str = "sbh.relocate.v1";
