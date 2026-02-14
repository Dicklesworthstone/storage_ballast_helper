//! Dual-write logging: SQLite (WAL) + JSONL append-only with graceful degradation.

pub mod dual;
pub mod jsonl;
pub mod sqlite;
pub mod stats;
