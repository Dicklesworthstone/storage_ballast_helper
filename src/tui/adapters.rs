//! Typed adapter boundaries for dashboard runtime inputs.

#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::core::errors::Result;
use crate::daemon::self_monitor::DAEMON_STATE_STALE_THRESHOLD_SECS;
use crate::daemon::self_monitor::DaemonState;
use crate::monitor::fs_stats::FsStatsCollector;
use crate::platform::pal::{Platform, detect_platform};

/// Health summary for runtime data sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterHealth {
    pub state_file_available: bool,
    pub telemetry_available: bool,
}

impl Default for AdapterHealth {
    fn default() -> Self {
        Self {
            state_file_available: true,
            telemetry_available: true,
        }
    }
}

/// Shared state-source contract. Implementations are added in `bd-xzt.2.3`.
pub trait StateAdapter {
    /// Returns `None` when data is unavailable or malformed.
    fn read_state(&self, state_file: &Path) -> Option<DaemonState>;

    /// Provides a coarse health signal for diagnostics.
    fn health(&self) -> AdapterHealth;
}

/// Bootstrap adapter used for scaffold wiring.
///
/// This intentionally returns `None` until the dedicated adapter bead
/// (`bd-xzt.2.3`) lands full parsing + staleness semantics.
#[derive(Debug, Default)]
pub struct NullStateAdapter;

impl StateAdapter for NullStateAdapter {
    fn read_state(&self, _state_file: &Path) -> Option<DaemonState> {
        None
    }

    fn health(&self) -> AdapterHealth {
        AdapterHealth {
            state_file_available: false,
            telemetry_available: false,
        }
    }
}

/// Freshness classification for state-file ingestion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateFreshness {
    Fresh,
    Stale { age: Duration },
    Missing,
    Malformed,
    ReadError(String),
}

/// Source used for the mount telemetry shown in the dashboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotSource {
    DaemonState,
    FilesystemFallback,
    Unavailable,
}

/// Typed mount row consumed by the dashboard view layer.
#[derive(Debug, Clone, PartialEq)]
pub struct MountSnapshot {
    pub path: String,
    pub free_pct: f64,
    pub level: String,
    pub rate_bps: Option<f64>,
    pub source: SnapshotSource,
}

/// Schema drift warnings detected during state file ingestion.
///
/// Populated by comparing actual JSON keys against expected struct fields.
/// Enables operators and maintainers to identify version mismatches between
/// the daemon writing `state.json` and the dashboard reading it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SchemaWarnings {
    /// Top-level JSON keys not recognized by the current typed model.
    pub unknown_fields: Vec<String>,
    /// Fields expected by the typed model but absent from the JSON.
    pub missing_fields: Vec<String>,
}

impl SchemaWarnings {
    /// Whether any drift was detected.
    #[must_use]
    pub fn has_drift(&self) -> bool {
        !self.unknown_fields.is_empty() || !self.missing_fields.is_empty()
    }
}

/// Typed data payload consumed by model/update code.
#[derive(Debug, Clone, PartialEq)]
pub struct DashboardSnapshot {
    pub daemon_state: Option<DaemonState>,
    pub mounts: Vec<MountSnapshot>,
    pub freshness: StateFreshness,
    pub source: SnapshotSource,
    /// Schema drift detected during deserialization. Empty when no drift.
    pub warnings: SchemaWarnings,
}

/// Typed state-file + fallback adapter for the new dashboard runtime.
pub struct DashboardStateAdapter {
    collector: FsStatsCollector,
    stale_threshold: Duration,
}

impl DashboardStateAdapter {
    /// Build an adapter from a specific platform implementation.
    #[must_use]
    pub fn new(
        platform: Arc<dyn Platform>,
        stale_threshold: Duration,
        cache_ttl: Duration,
    ) -> Self {
        Self {
            collector: FsStatsCollector::new(platform, cache_ttl),
            stale_threshold,
        }
    }

    /// Build an adapter using the detected host platform.
    ///
    /// # Errors
    /// Returns an error when the active platform cannot be detected.
    pub fn from_detected_platform() -> Result<Self> {
        let platform = detect_platform()?;
        Ok(Self::new(
            platform,
            Duration::from_secs(DAEMON_STATE_STALE_THRESHOLD_SECS),
            Duration::from_secs(1),
        ))
    }

    /// Read state-file data with stale detection, schema drift analysis, and
    /// filesystem fallback.
    #[must_use]
    pub fn load_snapshot(&self, state_file: &Path, monitor_paths: &[PathBuf]) -> DashboardSnapshot {
        let outcome = self.read_state_outcome(state_file);
        match outcome {
            StateReadOutcome::Fresh { state, warnings } => DashboardSnapshot {
                mounts: mounts_from_state(&state),
                daemon_state: Some(state),
                freshness: StateFreshness::Fresh,
                source: SnapshotSource::DaemonState,
                warnings,
            },
            StateReadOutcome::Stale {
                state,
                age,
                warnings,
            } => {
                let fallback_mounts = self.collect_fallback_mounts(monitor_paths);
                let source = fallback_source(&fallback_mounts);
                DashboardSnapshot {
                    daemon_state: Some(state),
                    mounts: fallback_mounts,
                    freshness: StateFreshness::Stale { age },
                    source,
                    warnings,
                }
            }
            StateReadOutcome::Missing => {
                let fallback_mounts = self.collect_fallback_mounts(monitor_paths);
                let source = fallback_source(&fallback_mounts);
                DashboardSnapshot {
                    daemon_state: None,
                    mounts: fallback_mounts,
                    freshness: StateFreshness::Missing,
                    source,
                    warnings: SchemaWarnings::default(),
                }
            }
            StateReadOutcome::Malformed => {
                let fallback_mounts = self.collect_fallback_mounts(monitor_paths);
                let source = fallback_source(&fallback_mounts);
                DashboardSnapshot {
                    daemon_state: None,
                    mounts: fallback_mounts,
                    freshness: StateFreshness::Malformed,
                    source,
                    warnings: SchemaWarnings::default(),
                }
            }
            StateReadOutcome::ReadError(details) => {
                let fallback_mounts = self.collect_fallback_mounts(monitor_paths);
                let source = fallback_source(&fallback_mounts);
                DashboardSnapshot {
                    daemon_state: None,
                    mounts: fallback_mounts,
                    freshness: StateFreshness::ReadError(details),
                    source,
                    warnings: SchemaWarnings::default(),
                }
            }
        }
    }

    fn read_state_outcome(&self, state_file: &Path) -> StateReadOutcome {
        let metadata = match std::fs::metadata(state_file) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return StateReadOutcome::Missing;
            }
            Err(error) => return StateReadOutcome::ReadError(error.to_string()),
        };

        let raw = match std::fs::read_to_string(state_file) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return StateReadOutcome::Missing;
            }
            Err(error) => return StateReadOutcome::ReadError(error.to_string()),
        };

        // Detect schema drift: parse as untyped Value first to compare keys.
        let warnings = detect_schema_drift(&raw);

        // `DaemonState` uses `#[serde(default)]` so that missing fields
        // get zero-values rather than hard-failing deserialization.
        let Ok(state) = serde_json::from_str::<DaemonState>(&raw) else {
            return StateReadOutcome::Malformed;
        };

        let modified = match metadata.modified() {
            Ok(modified) => modified,
            Err(error) => return StateReadOutcome::ReadError(error.to_string()),
        };
        let age = SystemTime::now()
            .duration_since(modified)
            .unwrap_or_default();

        if age > self.stale_threshold {
            StateReadOutcome::Stale {
                state,
                age,
                warnings,
            }
        } else {
            StateReadOutcome::Fresh { state, warnings }
        }
    }

    fn collect_fallback_mounts(&self, monitor_paths: &[PathBuf]) -> Vec<MountSnapshot> {
        let Ok(stats_by_path) = self.collector.collect_many(monitor_paths) else {
            return Vec::new();
        };

        let mut deduped = BTreeMap::<String, MountSnapshot>::new();
        for stats in stats_by_path.values() {
            let mount_path = stats.mount_point.display().to_string();
            deduped.entry(mount_path.clone()).or_insert_with(|| {
                let free_pct = stats.free_pct();
                MountSnapshot {
                    path: mount_path,
                    free_pct,
                    level: fallback_pressure_level(free_pct).to_string(),
                    rate_bps: None,
                    source: SnapshotSource::FilesystemFallback,
                }
            });
        }

        deduped.into_values().collect()
    }
}

impl StateAdapter for DashboardStateAdapter {
    fn read_state(&self, state_file: &Path) -> Option<DaemonState> {
        match self.read_state_outcome(state_file) {
            StateReadOutcome::Fresh { state, .. } => Some(state),
            StateReadOutcome::Stale { .. }
            | StateReadOutcome::Missing
            | StateReadOutcome::Malformed
            | StateReadOutcome::ReadError(_) => None,
        }
    }

    fn health(&self) -> AdapterHealth {
        AdapterHealth::default()
    }
}

#[derive(Debug)]
enum StateReadOutcome {
    Fresh {
        state: DaemonState,
        warnings: SchemaWarnings,
    },
    Stale {
        state: DaemonState,
        age: Duration,
        warnings: SchemaWarnings,
    },
    Missing,
    Malformed,
    ReadError(String),
}

/// Expected top-level keys in `DaemonState`. Used for drift detection.
const EXPECTED_STATE_KEYS: &[&str] = &[
    "version",
    "pid",
    "started_at",
    "uptime_seconds",
    "last_updated",
    "pressure",
    "ballast",
    "last_scan",
    "counters",
    "memory_rss_bytes",
];

/// Compare JSON keys against expected `DaemonState` fields.
fn detect_schema_drift(raw: &str) -> SchemaWarnings {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return SchemaWarnings::default();
    };
    let Some(obj) = value.as_object() else {
        return SchemaWarnings::default();
    };

    let actual_keys: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    let expected_keys: std::collections::BTreeSet<&str> =
        EXPECTED_STATE_KEYS.iter().copied().collect();

    let unknown_fields: Vec<String> = actual_keys
        .difference(&expected_keys)
        .map(|k| (*k).to_string())
        .collect();
    let missing_fields: Vec<String> = expected_keys
        .difference(&actual_keys)
        .map(|k| (*k).to_string())
        .collect();

    SchemaWarnings {
        unknown_fields,
        missing_fields,
    }
}

fn mounts_from_state(state: &DaemonState) -> Vec<MountSnapshot> {
    let mut mounts: Vec<_> = state
        .pressure
        .mounts
        .iter()
        .map(|mount| MountSnapshot {
            path: mount.path.clone(),
            free_pct: mount.free_pct,
            level: mount.level.clone(),
            rate_bps: mount.rate_bps,
            source: SnapshotSource::DaemonState,
        })
        .collect();
    mounts.sort_by(|left, right| left.path.cmp(&right.path));
    mounts
}

fn fallback_source(mounts: &[MountSnapshot]) -> SnapshotSource {
    if mounts.is_empty() {
        SnapshotSource::Unavailable
    } else {
        SnapshotSource::FilesystemFallback
    }
}

fn fallback_pressure_level(free_pct: f64) -> &'static str {
    if free_pct < 5.0 {
        "red"
    } else if free_pct < 20.0 {
        "orange"
    } else if free_pct < 35.0 {
        "yellow"
    } else {
        "green"
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;

    use filetime::{FileTime, set_file_mtime};
    use tempfile::TempDir;

    use crate::daemon::self_monitor::{
        BallastState, Counters, LastScanState, MountPressure, PressureState,
    };
    use crate::platform::pal::{FsStats, MemoryInfo, MockPlatform, MountPoint, PlatformPaths};

    use super::DashboardStateAdapter;
    use super::*;

    #[test]
    fn null_adapter_reports_unavailable() {
        let adapter = NullStateAdapter;
        assert!(
            adapter
                .read_state(PathBuf::from("/tmp/state.json").as_path())
                .is_none()
        );
        assert_eq!(
            adapter.health(),
            AdapterHealth {
                state_file_available: false,
                telemetry_available: false,
            }
        );
    }

    #[test]
    fn fresh_state_prefers_daemon_data() {
        let tmp = TempDir::new().expect("tempdir");
        let state_path = tmp.path().join("state.json");
        write_state_file(&state_path, sample_daemon_state()).expect("write state");

        let adapter = DashboardStateAdapter::new(
            mock_platform(),
            Duration::from_secs(90),
            Duration::from_secs(1),
        );
        let snapshot = adapter.load_snapshot(&state_path, &[PathBuf::from("/tmp/work")]);

        assert_eq!(snapshot.freshness, StateFreshness::Fresh);
        assert_eq!(snapshot.source, SnapshotSource::DaemonState);
        assert_eq!(snapshot.mounts.len(), 1);
        assert_eq!(snapshot.mounts[0].path, "/");
        assert_eq!(snapshot.mounts[0].source, SnapshotSource::DaemonState);
    }

    #[test]
    fn stale_state_falls_back_to_filesystem_stats() {
        let tmp = TempDir::new().expect("tempdir");
        let state_path = tmp.path().join("state.json");
        write_state_file(&state_path, sample_daemon_state()).expect("write state");

        let stale_mtime = FileTime::from_system_time(SystemTime::now() - Duration::from_secs(3600));
        set_file_mtime(&state_path, stale_mtime).expect("set stale mtime");

        let adapter = DashboardStateAdapter::new(
            mock_platform(),
            Duration::from_secs(90),
            Duration::from_secs(1),
        );
        let snapshot = adapter.load_snapshot(&state_path, &[PathBuf::from("/tmp/work")]);

        match snapshot.freshness {
            StateFreshness::Stale { age } => assert!(age.as_secs() >= 3000),
            other => panic!("expected stale freshness, got {other:?}"),
        }
        assert_eq!(snapshot.source, SnapshotSource::FilesystemFallback);
        assert_eq!(snapshot.mounts.len(), 1);
        assert_eq!(snapshot.mounts[0].path, "/tmp");
        assert_eq!(
            snapshot.mounts[0].source,
            SnapshotSource::FilesystemFallback
        );
        assert!(snapshot.daemon_state.is_some());
    }

    #[test]
    fn fresh_state_reports_schema_drift_without_failing_load() {
        let tmp = TempDir::new().expect("tempdir");
        let state_path = tmp.path().join("state.json");

        let mut value = serde_json::to_value(sample_daemon_state()).expect("state value");
        let object = value.as_object_mut().expect("state object");
        object.remove("memory_rss_bytes");
        object.insert(
            "future_schema_field".to_string(),
            serde_json::Value::String("preview".to_string()),
        );
        std::fs::write(
            &state_path,
            serde_json::to_string(&value).expect("state json"),
        )
        .expect("write state");

        let adapter = DashboardStateAdapter::new(
            mock_platform(),
            Duration::from_secs(90),
            Duration::from_secs(1),
        );
        let snapshot = adapter.load_snapshot(&state_path, &[PathBuf::from("/tmp/work")]);

        assert_eq!(snapshot.freshness, StateFreshness::Fresh);
        assert_eq!(snapshot.source, SnapshotSource::DaemonState);
        assert!(snapshot.daemon_state.is_some());
        assert!(snapshot.warnings.has_drift());
        assert!(
            snapshot
                .warnings
                .unknown_fields
                .iter()
                .any(|field| field == "future_schema_field")
        );
        assert!(
            snapshot
                .warnings
                .missing_fields
                .iter()
                .any(|field| field == "memory_rss_bytes")
        );
    }

    #[test]
    fn stale_state_keeps_schema_drift_metadata() {
        let tmp = TempDir::new().expect("tempdir");
        let state_path = tmp.path().join("state.json");

        let mut value = serde_json::to_value(sample_daemon_state()).expect("state value");
        let object = value.as_object_mut().expect("state object");
        object.remove("pressure");
        object.insert(
            "future_only_key".to_string(),
            serde_json::Value::String("next".to_string()),
        );
        std::fs::write(
            &state_path,
            serde_json::to_string(&value).expect("state json"),
        )
        .expect("write state");

        let stale_mtime = FileTime::from_system_time(SystemTime::now() - Duration::from_secs(3600));
        set_file_mtime(&state_path, stale_mtime).expect("set stale mtime");

        let adapter = DashboardStateAdapter::new(
            mock_platform(),
            Duration::from_secs(90),
            Duration::from_secs(1),
        );
        let snapshot = adapter.load_snapshot(&state_path, &[PathBuf::from("/tmp/work")]);

        assert!(matches!(snapshot.freshness, StateFreshness::Stale { .. }));
        assert_eq!(snapshot.source, SnapshotSource::FilesystemFallback);
        assert!(snapshot.daemon_state.is_some());
        assert!(snapshot.warnings.has_drift());
        assert!(
            snapshot
                .warnings
                .unknown_fields
                .iter()
                .any(|field| field == "future_only_key")
        );
        assert!(
            snapshot
                .warnings
                .missing_fields
                .iter()
                .any(|field| field == "pressure")
        );
    }

    #[test]
    fn malformed_state_falls_back() {
        let tmp = TempDir::new().expect("tempdir");
        let state_path = tmp.path().join("state.json");
        std::fs::write(&state_path, "not-json").expect("write malformed state");

        let adapter = DashboardStateAdapter::new(
            mock_platform(),
            Duration::from_secs(90),
            Duration::from_secs(1),
        );
        let snapshot = adapter.load_snapshot(&state_path, &[PathBuf::from("/tmp/work")]);

        assert_eq!(snapshot.freshness, StateFreshness::Malformed);
        assert_eq!(snapshot.source, SnapshotSource::FilesystemFallback);
        assert_eq!(snapshot.mounts.len(), 1);
    }

    #[test]
    fn missing_state_falls_back() {
        let tmp = TempDir::new().expect("tempdir");
        let state_path = tmp.path().join("missing-state.json");
        let adapter = DashboardStateAdapter::new(
            mock_platform(),
            Duration::from_secs(90),
            Duration::from_secs(1),
        );
        let snapshot = adapter.load_snapshot(&state_path, &[PathBuf::from("/tmp/work")]);

        assert_eq!(snapshot.freshness, StateFreshness::Missing);
        assert_eq!(snapshot.source, SnapshotSource::FilesystemFallback);
        assert_eq!(snapshot.mounts.len(), 1);
    }

    #[test]
    fn read_state_only_accepts_fresh_state() {
        let tmp = TempDir::new().expect("tempdir");
        let state_path = tmp.path().join("state.json");
        write_state_file(&state_path, sample_daemon_state()).expect("write state");

        let fresh_adapter = DashboardStateAdapter::new(
            mock_platform(),
            Duration::from_secs(90),
            Duration::from_secs(1),
        );
        assert!(fresh_adapter.read_state(&state_path).is_some());

        let stale_adapter = DashboardStateAdapter::new(
            mock_platform(),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        let stale_mtime = FileTime::from_system_time(SystemTime::now() - Duration::from_secs(300));
        set_file_mtime(&state_path, stale_mtime).expect("set stale mtime");
        assert!(stale_adapter.read_state(&state_path).is_none());
    }

    #[test]
    fn fallback_mounts_are_deduplicated_by_mount_path() {
        let tmp = TempDir::new().expect("tempdir");
        let state_path = tmp.path().join("missing-state.json");
        let adapter = DashboardStateAdapter::new(
            mock_platform(),
            Duration::from_secs(90),
            Duration::from_secs(1),
        );

        let snapshot = adapter.load_snapshot(
            &state_path,
            &[PathBuf::from("/tmp/work-a"), PathBuf::from("/tmp/work-b")],
        );

        assert_eq!(snapshot.freshness, StateFreshness::Missing);
        assert_eq!(snapshot.mounts.len(), 1);
        assert_eq!(snapshot.mounts[0].path, "/tmp");
    }

    fn write_state_file(path: &Path, state: DaemonState) -> std::io::Result<()> {
        let encoded = serde_json::to_string(&state).expect("state json");
        std::fs::write(path, encoded)
    }

    fn sample_daemon_state() -> DaemonState {
        DaemonState {
            version: "0.1.0".to_string(),
            pid: 42,
            started_at: "2026-02-16T00:00:00Z".to_string(),
            uptime_seconds: 60,
            last_updated: "2026-02-16T00:01:00Z".to_string(),
            pressure: PressureState {
                overall: "yellow".to_string(),
                mounts: vec![MountPressure {
                    path: "/".to_string(),
                    free_pct: 42.0,
                    level: "yellow".to_string(),
                    rate_bps: Some(1024.0),
                }],
            },
            ballast: BallastState {
                available: 9,
                total: 10,
                released: 1,
            },
            last_scan: LastScanState {
                at: Some("2026-02-16T00:00:30Z".to_string()),
                candidates: 7,
                deleted: 3,
            },
            counters: Counters {
                scans: 13,
                deletions: 5,
                bytes_freed: 4096,
                errors: 0,
                dropped_log_events: 0,
            },
            memory_rss_bytes: 1024 * 1024,
        }
    }

    fn mock_platform() -> Arc<dyn crate::platform::pal::Platform> {
        let mount = MountPoint {
            path: PathBuf::from("/tmp"),
            device: "tmpfs".to_string(),
            fs_type: "tmpfs".to_string(),
            is_ram_backed: true,
        };
        let stats = FsStats {
            total_bytes: 100,
            free_bytes: 70,
            available_bytes: 70,
            fs_type: "tmpfs".to_string(),
            mount_point: PathBuf::from("/tmp"),
            is_readonly: false,
        };
        Arc::new(MockPlatform::new(
            vec![mount.clone()],
            HashMap::from([(mount.path.clone(), stats)]),
            MemoryInfo {
                total_bytes: 1,
                available_bytes: 1,
                swap_total_bytes: 0,
                swap_free_bytes: 0,
            },
            PlatformPaths::default(),
        ))
    }

    // ──────────────── schema-shielding tests ────────────────

    #[test]
    fn fresh_state_has_no_schema_warnings() {
        let tmp = TempDir::new().expect("tempdir");
        let state_path = tmp.path().join("state.json");
        write_state_file(&state_path, sample_daemon_state()).expect("write");

        let adapter = DashboardStateAdapter::new(
            mock_platform(),
            Duration::from_secs(90),
            Duration::from_secs(1),
        );
        let snapshot = adapter.load_snapshot(&state_path, &[]);

        assert!(!snapshot.warnings.has_drift());
        assert!(snapshot.warnings.unknown_fields.is_empty());
        assert!(snapshot.warnings.missing_fields.is_empty());
    }

    #[test]
    fn extra_fields_in_json_produce_unknown_warning() {
        let tmp = TempDir::new().expect("tempdir");
        let state_path = tmp.path().join("state.json");

        // Write state with an extra top-level field (simulates newer daemon).
        let mut value: serde_json::Value =
            serde_json::to_value(sample_daemon_state()).expect("to value");
        value["new_telemetry_field"] = serde_json::json!({ "fancy": true });
        std::fs::write(&state_path, serde_json::to_string(&value).expect("json")).expect("write");

        let adapter = DashboardStateAdapter::new(
            mock_platform(),
            Duration::from_secs(90),
            Duration::from_secs(1),
        );
        let snapshot = adapter.load_snapshot(&state_path, &[]);

        assert!(snapshot.warnings.has_drift());
        assert_eq!(
            snapshot.warnings.unknown_fields,
            vec!["new_telemetry_field"]
        );
        assert!(snapshot.warnings.missing_fields.is_empty());
        // Despite drift, the state should parse successfully.
        assert!(snapshot.daemon_state.is_some());
        assert_eq!(snapshot.freshness, StateFreshness::Fresh);
    }

    #[test]
    fn missing_optional_fields_produce_missing_warning() {
        let tmp = TempDir::new().expect("tempdir");
        let state_path = tmp.path().join("state.json");

        // Write state missing the `memory_rss_bytes` field (simulates older daemon).
        let mut value: serde_json::Value =
            serde_json::to_value(sample_daemon_state()).expect("to value");
        value.as_object_mut().unwrap().remove("memory_rss_bytes");
        std::fs::write(&state_path, serde_json::to_string(&value).expect("json")).expect("write");

        let adapter = DashboardStateAdapter::new(
            mock_platform(),
            Duration::from_secs(90),
            Duration::from_secs(1),
        );
        let snapshot = adapter.load_snapshot(&state_path, &[]);

        assert!(snapshot.warnings.has_drift());
        assert!(snapshot.warnings.unknown_fields.is_empty());
        assert_eq!(snapshot.warnings.missing_fields, vec!["memory_rss_bytes"]);
        // Parsing still succeeds (serde default kicks in).
        assert!(snapshot.daemon_state.is_some());
        let state = snapshot.daemon_state.unwrap();
        assert_eq!(state.memory_rss_bytes, 0); // Default value
    }

    #[test]
    fn minimal_json_object_parses_with_all_defaults() {
        let tmp = TempDir::new().expect("tempdir");
        let state_path = tmp.path().join("state.json");

        // Write a near-empty JSON object — every field should default.
        std::fs::write(&state_path, "{}").expect("write");

        let adapter = DashboardStateAdapter::new(
            mock_platform(),
            Duration::from_secs(90),
            Duration::from_secs(1),
        );
        let snapshot = adapter.load_snapshot(&state_path, &[PathBuf::from("/tmp/work")]);

        // Should parse as Fresh (file was just written, so not stale).
        assert!(snapshot.daemon_state.is_some());
        let state = snapshot.daemon_state.unwrap();
        assert_eq!(state.version, "");
        assert_eq!(state.pid, 0);
        assert_eq!(state.pressure.mounts.len(), 0);
        assert_eq!(state.counters.scans, 0);

        // All known fields are missing.
        assert!(snapshot.warnings.has_drift());
        assert_eq!(
            snapshot.warnings.missing_fields.len(),
            EXPECTED_STATE_KEYS.len()
        );
    }

    #[test]
    fn both_extra_and_missing_fields_reported() {
        let tmp = TempDir::new().expect("tempdir");
        let state_path = tmp.path().join("state.json");

        let mut value: serde_json::Value =
            serde_json::to_value(sample_daemon_state()).expect("to value");
        let obj = value.as_object_mut().unwrap();
        obj.remove("counters");
        obj.insert("future_feature".to_string(), serde_json::json!(42));
        std::fs::write(&state_path, serde_json::to_string(&value).expect("json")).expect("write");

        let adapter = DashboardStateAdapter::new(
            mock_platform(),
            Duration::from_secs(90),
            Duration::from_secs(1),
        );
        let snapshot = adapter.load_snapshot(&state_path, &[]);

        assert!(snapshot.warnings.has_drift());
        assert_eq!(snapshot.warnings.unknown_fields, vec!["future_feature"]);
        assert_eq!(snapshot.warnings.missing_fields, vec!["counters"]);
        assert!(snapshot.daemon_state.is_some());
    }

    #[test]
    fn schema_warnings_default_is_no_drift() {
        let w = SchemaWarnings::default();
        assert!(!w.has_drift());
        assert!(w.unknown_fields.is_empty());
        assert!(w.missing_fields.is_empty());
    }

    #[test]
    fn detect_drift_on_non_json_returns_empty() {
        let w = detect_schema_drift("not valid json");
        assert!(!w.has_drift());
    }

    #[test]
    fn detect_drift_on_json_array_returns_empty() {
        let w = detect_schema_drift("[1, 2, 3]");
        assert!(!w.has_drift());
    }

    #[test]
    fn stale_state_still_reports_schema_warnings() {
        let tmp = TempDir::new().expect("tempdir");
        let state_path = tmp.path().join("state.json");

        let mut value: serde_json::Value =
            serde_json::to_value(sample_daemon_state()).expect("to value");
        value["extra_metric"] = serde_json::json!("new");
        std::fs::write(&state_path, serde_json::to_string(&value).expect("json")).expect("write");

        let stale_mtime = FileTime::from_system_time(SystemTime::now() - Duration::from_secs(3600));
        set_file_mtime(&state_path, stale_mtime).expect("set stale mtime");

        let adapter = DashboardStateAdapter::new(
            mock_platform(),
            Duration::from_secs(90),
            Duration::from_secs(1),
        );
        let snapshot = adapter.load_snapshot(&state_path, &[PathBuf::from("/tmp/work")]);

        assert!(matches!(snapshot.freshness, StateFreshness::Stale { .. }));
        assert!(snapshot.warnings.has_drift());
        assert_eq!(snapshot.warnings.unknown_fields, vec!["extra_metric"]);
    }
}
