//! Cross-platform PAL data contracts.

#![allow(missing_docs)]

use std::any::Any;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PalError {
    NotImplemented {
        os_name: String,
        method_name: String,
        bead: Option<String>,
    },
    MethodFailed {
        os_name: String,
        method_name: String,
        details: String,
    },
}

impl fmt::Display for PalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented {
                os_name,
                method_name,
                bead,
            } => {
                write!(
                    f,
                    "PAL method '{method_name}' is not yet implemented on {os_name}"
                )?;
                if let Some(bead) = bead {
                    write!(f, ". See bead {bead} for tracking")?;
                }
                Ok(())
            }
            Self::MethodFailed {
                os_name,
                method_name,
                details,
            } => {
                write!(
                    f,
                    "PAL method '{method_name}' failed on {os_name}: {details}"
                )
            }
        }
    }
}

impl std::error::Error for PalError {}

impl PalError {
    #[must_use]
    pub fn not_implemented(os_name: impl Into<String>, method_name: impl Into<String>) -> Self {
        Self::not_implemented_with_bead(os_name, method_name, None::<String>)
    }

    #[must_use]
    pub fn not_implemented_with_bead(
        os_name: impl Into<String>,
        method_name: impl Into<String>,
        bead: Option<impl Into<String>>,
    ) -> Self {
        Self::NotImplemented {
            os_name: os_name.into(),
            method_name: method_name.into(),
            bead: bead.map(Into::into),
        }
    }

    #[must_use]
    pub fn method_failed(
        os_name: impl Into<String>,
        method_name: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self::MethodFailed {
            os_name: os_name.into(),
            method_name: method_name.into(),
            details: details.into(),
        }
    }

    #[must_use]
    pub fn os_name(&self) -> &str {
        match self {
            Self::NotImplemented { os_name, .. } | Self::MethodFailed { os_name, .. } => os_name,
        }
    }

    #[must_use]
    pub fn method_name(&self) -> &str {
        match self {
            Self::NotImplemented { method_name, .. } | Self::MethodFailed { method_name, .. } => {
                method_name
            }
        }
    }

    #[must_use]
    pub fn bead(&self) -> Option<&str> {
        match self {
            Self::NotImplemented { bead, .. } => bead.as_deref(),
            Self::MethodFailed { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capacity {
    pub mount_point: PathBuf,
    pub fs_type: String,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub available_bytes: u64,
    pub is_readonly: bool,
    pub container_id: Option<String>,
    pub container_total_bytes: Option<u64>,
    pub container_available_bytes: Option<u64>,
    pub volume_total_bytes: Option<u64>,
    pub volume_available_bytes: Option<u64>,
    pub volume_role: Option<String>,
    pub shared_volumes: Vec<String>,
    pub is_primary: bool,
    pub purgeable_bytes: Option<u64>,
    pub local_snapshot_bytes: Option<u64>,
    pub estimated_reclaimable_by_snapshot_thinning: Option<SnapshotThinningEstimate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotThinningEstimate {
    pub bytes: u64,
    pub method: String,
}

impl SnapshotThinningEstimate {
    #[must_use]
    pub fn new(bytes: u64, method: impl Into<String>) -> Self {
        Self {
            bytes,
            method: method.into(),
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MountInfo {
    pub device: String,
    pub mount_point: PathBuf,
    pub fs_type: String,
    pub container_id: Option<String>,
    pub total_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub purgeable_bytes: Option<u64>,
    pub local_snapshot_bytes: Option<u64>,
    pub estimated_reclaimable_by_snapshot_thinning: Option<SnapshotThinningEstimate>,
    pub is_readonly: bool,
    pub is_ram_backed: bool,
    pub is_apfs_data_volume: bool,
    pub is_apfs_system_snapshot: bool,
    pub is_apfs_vm_volume: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalSnapshotInfo {
    pub name: String,
    pub date: Option<String>,
    pub retained_bytes_estimate: Option<u64>,
    pub mount_path: PathBuf,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MemoryPressureLevel {
    Normal,
    Warn,
    Critical,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryPressure {
    pub level: MemoryPressureLevel,
    pub free_pages: Option<u64>,
    pub used_pages: Option<u64>,
    pub page_size_bytes: Option<u64>,
    pub compressor_used_bytes: Option<u64>,
    pub swap_total_bytes: Option<u64>,
    pub swap_used_bytes: Option<u64>,
    pub linux_psi_avg10: Option<u64>,
}

pub type MemoryPressureCallback = Box<dyn Fn(MemoryPressure) + Send + Sync + 'static>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FullDiskAccessState {
    Granted,
    Missing,
    NotConfigured,
    NotApplicable,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FullDiskAccessStatus {
    pub state: FullDiskAccessState,
    pub probe_path: Option<PathBuf>,
    pub detail: String,
    pub cache_ttl_seconds: u64,
    pub cached: bool,
}

impl FullDiskAccessStatus {
    #[must_use]
    pub fn not_applicable(platform: &str) -> Self {
        Self {
            state: FullDiskAccessState::NotApplicable,
            probe_path: None,
            detail: format!("Full Disk Access is not required on {platform}"),
            cache_ttl_seconds: 0,
            cached: false,
        }
    }

    #[must_use]
    pub fn doctor_message(&self) -> String {
        let state = match self.state {
            FullDiskAccessState::Granted => "granted",
            FullDiskAccessState::Missing => "missing",
            FullDiskAccessState::NotConfigured => "not_configured",
            FullDiskAccessState::NotApplicable => "not_applicable",
            FullDiskAccessState::Unknown => "unknown",
        };
        self.probe_path.as_ref().map_or_else(
            || format!("{state}: {} (cached: {})", self.detail, self.cached),
            |path| {
                format!(
                    "{state}: {} (probe: {}, cached: {})",
                    self.detail,
                    path.display(),
                    self.cached,
                )
            },
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SubscriptionHandle {
    pub source: String,
    pub active: bool,
    #[serde(skip)]
    resource: Option<Arc<dyn Any + Send + Sync>>,
}

impl SubscriptionHandle {
    #[must_use]
    pub fn active(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            active: true,
            resource: None,
        }
    }

    #[must_use]
    pub(crate) fn active_with_liveness(source: impl Into<String>, liveness: Arc<()>) -> Self {
        let resource: Arc<dyn Any + Send + Sync> = liveness;
        Self {
            source: source.into(),
            active: true,
            resource: Some(resource),
        }
    }

    #[must_use]
    #[cfg(target_os = "macos")]
    pub(crate) fn active_with_resource<T>(source: impl Into<String>, resource: T) -> Self
    where
        T: Any + Send + Sync + 'static,
    {
        Self {
            source: source.into(),
            active: true,
            resource: Some(Arc::new(resource)),
        }
    }

    #[must_use]
    pub fn inactive(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            active: false,
            resource: None,
        }
    }
}

impl fmt::Debug for SubscriptionHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubscriptionHandle")
            .field("source", &self.source)
            .field("active", &self.active)
            .field("has_resource", &self.resource.is_some())
            .finish()
    }
}

impl PartialEq for SubscriptionHandle {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source && self.active == other.active
    }
}

impl Eq for SubscriptionHandle {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: i32,
    pub parent_pid: Option<i32>,
    pub name: String,
    pub command_line: Vec<String>,
    pub executable: Option<PathBuf>,
    pub cwd: Option<PathBuf>,
    pub start_time_unix_ms: Option<i64>,
    pub virtual_memory_bytes: Option<u64>,
    pub resident_memory_bytes: Option<u64>,
    pub cpu_user_micros: Option<u64>,
    pub cpu_system_micros: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessIo {
    pub pid: i32,
    pub bytes_read_total: u64,
    pub bytes_written_total: u64,
    pub bytes_read_recent_15m: Option<u64>,
    pub bytes_written_recent_15m: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OpenFileKind {
    Regular,
    Directory,
    Socket,
    Pipe,
    Device,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OpenFileMode {
    Read,
    Write,
    ReadWrite,
    Execute,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenFile {
    pub pid: i32,
    pub path: PathBuf,
    pub fd: Option<i32>,
    pub kind: OpenFileKind,
    pub mode: OpenFileMode,
}

/// Maximum time to spend scanning processes for open files or executables (5 s).
pub const OPEN_FILES_SCAN_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

/// Maximum number of PIDs to scan before bailing out (50,000).
pub const OPEN_FILES_MAX_PIDS: usize = 50_000;

/// Result of querying open files under a path, including completion status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenFilesResult {
    pub files: Vec<OpenFile>,
    pub complete: bool,
}

impl OpenFilesResult {
    #[must_use]
    pub fn complete(files: Vec<OpenFile>) -> Self {
        Self {
            files,
            complete: true,
        }
    }

    #[must_use]
    pub fn incomplete(files: Vec<OpenFile>) -> Self {
        Self {
            files,
            complete: false,
        }
    }
}

/// Result of querying running executables under a path, including completion status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutablesResult {
    pub processes: Vec<ProcessInfo>,
    pub complete: bool,
}

impl ExecutablesResult {
    #[must_use]
    pub fn complete(processes: Vec<ProcessInfo>) -> Self {
        Self {
            processes,
            complete: true,
        }
    }

    #[must_use]
    pub fn incomplete(processes: Vec<ProcessInfo>) -> Self {
        Self {
            processes,
            complete: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MappedRegion {
    pub pid: i32,
    pub path: PathBuf,
    pub start_address: Option<u64>,
    pub end_address: Option<u64>,
    pub protection: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SelfStats {
    pub rss_bytes: u64,
    pub virtual_memory_bytes: u64,
    pub cpu_user_micros: u64,
    pub cpu_system_micros: u64,
    pub idle_wakeups: Option<u64>,
    pub bytes_read: Option<u64>,
    pub bytes_written: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SacredPathKind {
    /// Protect exactly one path.
    ///
    /// Example: `~/Pictures/Photos Library.photoslibrary` protects that bundle
    /// path, but not a sibling renamed library unless another rule covers it.
    ExactMatch,
    /// Protect paths matched by a shell-style glob.
    ///
    /// Example: `~/Movies/*.fcpbundle` protects Final Cut Pro library bundles.
    GlobMatch,
    /// Protect cleanup candidates that contain a matching descendant.
    ///
    /// Example: `/private/tmp/*-trash-*` may be rejected when it contains a
    /// descendant matching `.beads/` or `.git/`.
    ContainsAny,
    /// Protect cleanup candidates by scanning for sacred marker names inside.
    ///
    /// Example: any candidate containing `beads.db`, `*.sqlite3`, or
    /// `.sbh-protect` is downgraded or refused before deletion.
    StowawayMarker,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SacredPathSource {
    /// Built into sbh for platform or cross-platform safety.
    ///
    /// Example: macOS Photos libraries and cross-platform `.git/` directories.
    Builtin,
    /// Loaded from user or system configuration.
    ///
    /// Example: an operator-defined project archive path in `sacred.toml`.
    UserConfig,
    /// Discovered from an on-disk protection marker.
    ///
    /// Example: a directory containing `.sbh-protect`.
    Marker,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SacredPath {
    /// Exact path, glob, or marker pattern used by this protection rule.
    ///
    /// Example: `~/Library/Messages/*` or `*.sqlite3`.
    pub pattern: String,
    /// How `pattern` is interpreted during overlap and stowaway checks.
    pub kind: SacredPathKind,
    /// Operator-facing explanation for why this path is protected.
    ///
    /// Example: `Messages history is user data`.
    pub reason: String,
    /// Origin of this protection rule.
    pub source: SacredPathSource,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ServiceKind {
    Systemd,
    Launchd,
    None,
}

#[cfg(test)]
mod tests {
    use super::{
        FullDiskAccessState, FullDiskAccessStatus, PalError, SacredPath, SacredPathKind,
        SacredPathSource,
    };

    #[test]
    fn sacred_path_exact_match_example_round_trips() {
        let path = SacredPath {
            pattern: "~/Pictures/Photos Library.photoslibrary".to_string(),
            kind: SacredPathKind::ExactMatch,
            reason: "Photos libraries are irreplaceable user data".to_string(),
            source: SacredPathSource::Builtin,
        };

        let encoded = serde_json::to_string(&path).expect("SacredPath should encode");
        let decoded: SacredPath = serde_json::from_str(&encoded).expect("SacredPath should decode");
        assert_eq!(decoded, path);
        assert!(encoded.contains("ExactMatch"));
        assert!(encoded.contains("Builtin"));
    }

    #[test]
    fn pal_not_implemented_includes_optional_bead_hint() {
        let error =
            PalError::not_implemented_with_bead("macos", "memory_pressure", Some("bd-hqu2.4"));

        assert_eq!(error.os_name(), "macos");
        assert_eq!(error.method_name(), "memory_pressure");
        assert_eq!(error.bead(), Some("bd-hqu2.4"));
        assert_eq!(
            error.to_string(),
            "PAL method 'memory_pressure' is not yet implemented on macos. See bead bd-hqu2.4 for tracking"
        );
    }

    #[test]
    fn full_disk_access_doctor_message_includes_state_and_probe() {
        let status = FullDiskAccessStatus {
            state: FullDiskAccessState::Missing,
            probe_path: Some("/Users/me/Library/Mail/V10/MailData/Envelope Index".into()),
            detail: "permission denied while probing Mail index".to_string(),
            cache_ttl_seconds: 60,
            cached: true,
        };

        let message = status.doctor_message();

        assert!(message.contains("missing"));
        assert!(message.contains("Envelope Index"));
        assert!(message.contains("cached: true"));
    }

    #[test]
    fn sacred_path_variant_examples_cover_catalog_semantics() {
        let examples = [
            SacredPath {
                pattern: "~/Movies/*.fcpbundle".to_string(),
                kind: SacredPathKind::GlobMatch,
                reason: "Final Cut Pro libraries are project data".to_string(),
                source: SacredPathSource::Builtin,
            },
            SacredPath {
                pattern: ".beads/".to_string(),
                kind: SacredPathKind::ContainsAny,
                reason: "Beads tracker state must not be removed from trash dirs".to_string(),
                source: SacredPathSource::Builtin,
            },
            SacredPath {
                pattern: "*.sqlite3".to_string(),
                kind: SacredPathKind::StowawayMarker,
                reason: "SQLite files commonly hold application state".to_string(),
                source: SacredPathSource::Builtin,
            },
            SacredPath {
                pattern: "/Volumes/archive".to_string(),
                kind: SacredPathKind::ExactMatch,
                reason: "Operator-configured archive".to_string(),
                source: SacredPathSource::UserConfig,
            },
            SacredPath {
                pattern: ".sbh-protect".to_string(),
                kind: SacredPathKind::StowawayMarker,
                reason: "Protection marker present".to_string(),
                source: SacredPathSource::Marker,
            },
        ];

        for example in examples {
            assert!(
                !example.pattern.is_empty(),
                "sacred path example must have a non-empty pattern: {example:?}"
            );
            assert!(
                !example.reason.is_empty(),
                "sacred path example must have a non-empty reason: {example:?}"
            );
        }
    }
}
