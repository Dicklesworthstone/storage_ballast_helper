//! SBH-prefixed error types with structured error codes.

#![allow(missing_docs)]

use std::path::{Path, PathBuf};

use thiserror::Error;

/// Shared `Result` alias for the project.
pub type Result<T> = std::result::Result<T, SbhError>;

/// Top-level error type for Storage Ballast Helper.
#[derive(Debug, Error)]
pub enum SbhError {
    #[error("[SBH-1001] invalid configuration: {details}")]
    InvalidConfig { details: String },

    #[error("[SBH-1002] missing configuration file: {path}")]
    MissingConfig { path: PathBuf },

    #[error("[SBH-1003] configuration parse failure in {context}: {details}")]
    ConfigParse {
        context: &'static str,
        details: String,
    },

    #[error("[SBH-1101] unsupported platform: {details}")]
    UnsupportedPlatform { details: String },

    #[error("[SBH-2001] filesystem stats failure for {path}: {details}")]
    FsStats { path: PathBuf, details: String },

    #[error("[SBH-2002] mount table parse failure: {details}")]
    MountParse { details: String },

    #[error("[SBH-2003] safety veto for {path}: {reason}")]
    SafetyVeto { path: PathBuf, reason: String },

    #[error("[SBH-2101] serialization failure in {context}: {details}")]
    Serialization {
        context: &'static str,
        details: String,
    },

    #[error("[SBH-2102] SQL failure in {context}: {details}")]
    Sql {
        context: &'static str,
        details: String,
    },

    #[error("[SBH-3001] permission denied for {path}")]
    PermissionDenied { path: PathBuf },

    #[error("[SBH-3002] IO failure at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("[SBH-3003] channel closed in component {component}")]
    ChannelClosed { component: &'static str },

    #[error("[SBH-3900] runtime failure: {details}")]
    Runtime { details: String },
}

impl SbhError {
    /// Stable machine-parseable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfig { .. } => "SBH-1001",
            Self::MissingConfig { .. } => "SBH-1002",
            Self::ConfigParse { .. } => "SBH-1003",
            Self::UnsupportedPlatform { .. } => "SBH-1101",
            Self::FsStats { .. } => "SBH-2001",
            Self::MountParse { .. } => "SBH-2002",
            Self::SafetyVeto { .. } => "SBH-2003",
            Self::Serialization { .. } => "SBH-2101",
            Self::Sql { .. } => "SBH-2102",
            Self::PermissionDenied { .. } => "SBH-3001",
            Self::Io { .. } => "SBH-3002",
            Self::ChannelClosed { .. } => "SBH-3003",
            Self::Runtime { .. } => "SBH-3900",
        }
    }

    /// Whether retrying might resolve the failure.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Io { .. }
                | Self::ChannelClosed { .. }
                | Self::FsStats { .. }
                | Self::Sql { .. }
                | Self::Runtime { .. }
        )
    }

    /// Convenience constructor for IO errors with a known path.
    #[must_use]
    pub fn io(path: impl AsRef<Path>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().to_path_buf(),
            source,
        }
    }
}

impl From<rusqlite::Error> for SbhError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sql {
            context: "rusqlite",
            details: value.to_string(),
        }
    }
}

impl From<serde_json::Error> for SbhError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization {
            context: "serde_json",
            details: value.to_string(),
        }
    }
}

impl From<toml::de::Error> for SbhError {
    fn from(value: toml::de::Error) -> Self {
        Self::ConfigParse {
            context: "toml",
            details: value.to_string(),
        }
    }
}
