//! Artifact scanner: directory walker, pattern matching, multi-factor scoring, deletion.

pub mod active_lease;
pub mod decision_record;
pub mod deletion;
pub mod engine;
pub mod events;
pub mod index;
pub mod log_truncator;
pub mod merkle;
pub mod patterns;
pub mod protection;
pub mod quarantine;
pub mod scoring;
pub mod walker;
