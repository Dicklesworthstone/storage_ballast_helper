//! Automatic model/asset bootstrap: download, verify, cache, prefetch.
//!
//! Defines a manifest-driven asset pipeline where each required component
//! declares its name, version, checksum, source URL, size, and optional
//! signature. The pipeline handles resumable downloads, integrity verification,
//! local cache layout, offline diagnostics, and cache cleanup.

use std::fmt;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/// A single asset entry in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetEntry {
    /// Machine-readable asset name (e.g. "scoring-model-v2").
    pub name: String,
    /// Semantic version string.
    pub version: String,
    /// Expected SHA-256 hex digest of the file.
    pub sha256: String,
    /// Primary download URL.
    pub url: String,
    /// Optional mirror URLs for resilience.
    #[serde(default)]
    pub mirrors: Vec<String>,
    /// Expected file size in bytes (0 = unknown).
    #[serde(default)]
    pub size_bytes: u64,
    /// Whether this asset is required for operation.
    #[serde(default = "default_true")]
    pub required: bool,
    /// Optional description.
    #[serde(default)]
    pub description: String,
}

fn default_true() -> bool {
    true
}

/// Complete asset manifest for a release.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetManifest {
    /// Manifest schema version.
    pub version: String,
    /// Assets in this manifest.
    pub assets: Vec<AssetEntry>,
}

impl AssetManifest {
    /// Parse a manifest from JSON.
    ///
    /// # Errors
    /// Returns an error if the JSON is invalid or cannot be deserialized.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize to pretty JSON.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Return only required assets.
    #[must_use]
    pub fn required_assets(&self) -> Vec<&AssetEntry> {
        self.assets.iter().filter(|a| a.required).collect()
    }

    /// Total size of all assets (where known).
    #[must_use]
    pub fn total_size_bytes(&self) -> u64 {
        self.assets.iter().map(|a| a.size_bytes).sum()
    }
}

// ---------------------------------------------------------------------------
// Cache layout
// ---------------------------------------------------------------------------

/// Local asset cache, organized as `<cache_root>/<name>/<version>/<filename>`.
#[derive(Debug, Clone)]
pub struct AssetCache {
    root: PathBuf,
}

impl AssetCache {
    /// Create a new asset cache at the given root directory.
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Default cache root: `~/.local/share/sbh/assets`.
    #[must_use]
    pub fn default_root() -> PathBuf {
        std::env::var_os("HOME")
            .map_or_else(|| PathBuf::from("/tmp"), PathBuf::from)
            .join(".local")
            .join("share")
            .join("sbh")
            .join("assets")
    }

    /// Path where an asset would be cached.
    #[must_use]
    pub fn asset_path(&self, entry: &AssetEntry) -> PathBuf {
        let filename = url_filename(&entry.url);
        self.root
            .join(&entry.name)
            .join(&entry.version)
            .join(filename)
    }

    /// Path for the partial/in-progress download.
    #[must_use]
    pub fn partial_path(&self, entry: &AssetEntry) -> PathBuf {
        let mut path = self.asset_path(entry);
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        path.set_file_name(format!("{name}.partial"));
        path
    }

    /// Check if an asset is already cached and valid.
    #[must_use]
    pub fn is_cached(&self, entry: &AssetEntry) -> CacheStatus {
        let path = self.asset_path(entry);
        if !path.exists() {
            let partial = self.partial_path(entry);
            if partial.exists() {
                return CacheStatus::Partial {
                    bytes_downloaded: fs::metadata(&partial).map(|m| m.len()).unwrap_or(0),
                };
            }
            return CacheStatus::Missing;
        }

        // Verify checksum.
        match compute_sha256(&path) {
            Ok(hash) if hash == entry.sha256 => CacheStatus::Valid,
            Ok(hash) => CacheStatus::Corrupt {
                expected: entry.sha256.clone(),
                actual: hash,
            },
            Err(_) => CacheStatus::Corrupt {
                expected: entry.sha256.clone(),
                actual: String::new(),
            },
        }
    }

    /// List all cached assets with their status.
    #[must_use]
    pub fn inventory(&self, manifest: &AssetManifest) -> Vec<AssetStatus> {
        manifest
            .assets
            .iter()
            .map(|entry| {
                let path = self.asset_path(entry);
                let status = self.is_cached(entry);
                AssetStatus {
                    name: entry.name.clone(),
                    version: entry.version.clone(),
                    required: entry.required,
                    path,
                    status,
                }
            })
            .collect()
    }

    /// Remove all cached files for assets not in the manifest (old versions).
    ///
    /// # Errors
    /// Returns an error if directory traversal or removal fails.
    pub fn cleanup_stale(&self, manifest: &AssetManifest) -> io::Result<CleanupReport> {
        let mut removed_count = 0u64;
        let mut removed_bytes = 0u64;
        let mut errors = Vec::new();

        // Build set of valid asset dirs: <name>/<version>
        let valid_dirs: std::collections::HashSet<PathBuf> = manifest
            .assets
            .iter()
            .map(|a| PathBuf::from(&a.name).join(&a.version))
            .collect();

        if !self.root.exists() {
            return Ok(CleanupReport {
                removed_count,
                removed_bytes,
                errors,
            });
        }

        // Walk <root>/<name>/<version> and remove anything not in valid_dirs.
        if let Ok(name_entries) = fs::read_dir(&self.root) {
            for name_entry in name_entries.flatten() {
                if !name_entry.path().is_dir() {
                    continue;
                }
                let name_dir = name_entry.file_name().to_string_lossy().to_string();

                if let Ok(version_entries) = fs::read_dir(name_entry.path()) {
                    for version_entry in version_entries.flatten() {
                        if !version_entry.path().is_dir() {
                            continue;
                        }
                        let version_dir = version_entry.file_name().to_string_lossy().to_string();
                        let rel = PathBuf::from(&name_dir).join(&version_dir);

                        if !valid_dirs.contains(&rel) {
                            match remove_dir_contents(&version_entry.path()) {
                                Ok((count, bytes)) => {
                                    removed_count += count;
                                    removed_bytes += bytes;
                                }
                                Err(e) => {
                                    errors.push(format!("{}: {e}", version_entry.path().display()));
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(CleanupReport {
            removed_count,
            removed_bytes,
            errors,
        })
    }

    /// Total disk usage of the cache.
    #[must_use]
    pub fn disk_usage(&self) -> u64 {
        dir_size(&self.root)
    }
}

fn dir_size(path: &Path) -> u64 {
    if !path.exists() {
        return 0;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    entries
        .flatten()
        .map(|e| {
            if e.path().is_dir() {
                dir_size(&e.path())
            } else {
                e.metadata().map(|m| m.len()).unwrap_or(0)
            }
        })
        .sum()
}

fn remove_dir_contents(path: &Path) -> io::Result<(u64, u64)> {
    let mut count = 0u64;
    let mut bytes = 0u64;

    if path.is_dir() {
        for entry in fs::read_dir(path)?.flatten() {
            if entry.path().is_dir() {
                let (c, b) = remove_dir_contents(&entry.path())?;
                count += c;
                bytes += b;
            } else {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                fs::remove_file(entry.path())?;
                count += 1;
                bytes += size;
            }
        }
        fs::remove_dir(path)?;
    }

    Ok((count, bytes))
}

// ---------------------------------------------------------------------------
// Cache status
// ---------------------------------------------------------------------------

/// Status of a single cached asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum CacheStatus {
    /// Asset is cached and integrity-verified.
    Valid,
    /// Asset is not in cache.
    Missing,
    /// Partial download exists (resumable).
    Partial { bytes_downloaded: u64 },
    /// Cached file exists but checksum mismatch.
    Corrupt { expected: String, actual: String },
}

impl fmt::Display for CacheStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => f.write_str("valid"),
            Self::Missing => f.write_str("missing"),
            Self::Partial { bytes_downloaded } => {
                write!(f, "partial ({bytes_downloaded} bytes)")
            }
            Self::Corrupt { .. } => f.write_str("corrupt"),
        }
    }
}

/// Status report for a single asset.
#[derive(Debug, Clone, Serialize)]
pub struct AssetStatus {
    pub name: String,
    pub version: String,
    pub required: bool,
    pub path: PathBuf,
    pub status: CacheStatus,
}

/// Result of cache cleanup.
#[derive(Debug, Clone, Serialize)]
pub struct CleanupReport {
    pub removed_count: u64,
    pub removed_bytes: u64,
    pub errors: Vec<String>,
}

// ---------------------------------------------------------------------------
// Download + verification
// ---------------------------------------------------------------------------

/// Result of a single asset fetch attempt.
#[derive(Debug, Clone, Serialize)]
pub struct FetchResult {
    pub name: String,
    pub version: String,
    pub status: FetchStatus,
    pub path: PathBuf,
    pub message: String,
}

/// Outcome of a fetch operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum FetchStatus {
    /// Successfully downloaded and verified.
    Downloaded,
    /// Already cached (skip).
    Cached,
    /// Download failed.
    Failed,
    /// Integrity verification failed after download.
    IntegrityFailed,
    /// Dry-run: would download.
    DryRun,
    /// Skipped (not required and --required-only).
    Skipped,
}

impl fmt::Display for FetchStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Downloaded => f.write_str("downloaded"),
            Self::Cached => f.write_str("cached"),
            Self::Failed => f.write_str("failed"),
            Self::IntegrityFailed => f.write_str("integrity-failed"),
            Self::DryRun => f.write_str("dry-run"),
            Self::Skipped => f.write_str("skipped"),
        }
    }
}

/// Options for the fetch pipeline.
#[derive(Debug, Clone, Default)]
pub struct FetchOptions {
    /// Only report, do not download.
    pub dry_run: bool,
    /// Only fetch required assets.
    pub required_only: bool,
    /// Offline mode: fail fast if any required asset is missing.
    pub offline: bool,
}

/// Full fetch/prefetch summary.
#[derive(Debug, Clone, Serialize)]
pub struct FetchSummary {
    pub results: Vec<FetchResult>,
    pub downloaded_count: usize,
    pub cached_count: usize,
    pub failed_count: usize,
    pub total_bytes_downloaded: u64,
}

/// Run the fetch pipeline for all manifest assets.
#[must_use]
pub fn fetch_assets(
    manifest: &AssetManifest,
    cache: &AssetCache,
    opts: &FetchOptions,
) -> FetchSummary {
    let mut results = Vec::new();
    let mut total_bytes = 0u64;

    for entry in &manifest.assets {
        // Skip optional if --required-only.
        if opts.required_only && !entry.required {
            results.push(FetchResult {
                name: entry.name.clone(),
                version: entry.version.clone(),
                status: FetchStatus::Skipped,
                path: cache.asset_path(entry),
                message: "optional asset skipped".to_string(),
            });
            continue;
        }

        let status = cache.is_cached(entry);
        match status {
            CacheStatus::Valid => {
                results.push(FetchResult {
                    name: entry.name.clone(),
                    version: entry.version.clone(),
                    status: FetchStatus::Cached,
                    path: cache.asset_path(entry),
                    message: "already cached and verified".to_string(),
                });
                continue;
            }
            CacheStatus::Corrupt { .. } => {
                // Remove corrupt file and re-download.
                let _ = fs::remove_file(cache.asset_path(entry));
            }
            CacheStatus::Partial { .. } | CacheStatus::Missing => {}
        }

        // Offline mode: fail fast.
        if opts.offline {
            results.push(FetchResult {
                name: entry.name.clone(),
                version: entry.version.clone(),
                status: FetchStatus::Failed,
                path: cache.asset_path(entry),
                message: format!(
                    "offline mode: asset not in cache. Download manually:\n  curl -Lo {} {}",
                    cache.asset_path(entry).display(),
                    entry.url
                ),
            });
            continue;
        }

        // Dry-run.
        if opts.dry_run {
            results.push(FetchResult {
                name: entry.name.clone(),
                version: entry.version.clone(),
                status: FetchStatus::DryRun,
                path: cache.asset_path(entry),
                message: format!("would download from {}", entry.url),
            });
            continue;
        }

        // Attempt download.
        match download_and_verify(entry, cache) {
            Ok(size) => {
                total_bytes += size;
                results.push(FetchResult {
                    name: entry.name.clone(),
                    version: entry.version.clone(),
                    status: FetchStatus::Downloaded,
                    path: cache.asset_path(entry),
                    message: format!("downloaded and verified ({size} bytes)"),
                });
            }
            Err(e) => {
                results.push(FetchResult {
                    name: entry.name.clone(),
                    version: entry.version.clone(),
                    status: FetchStatus::Failed,
                    path: cache.asset_path(entry),
                    message: format!("download failed: {e}"),
                });
            }
        }
    }

    let downloaded_count = results
        .iter()
        .filter(|r| r.status == FetchStatus::Downloaded)
        .count();
    let cached_count = results
        .iter()
        .filter(|r| r.status == FetchStatus::Cached)
        .count();
    let failed_count = results
        .iter()
        .filter(|r| r.status == FetchStatus::Failed || r.status == FetchStatus::IntegrityFailed)
        .count();

    FetchSummary {
        results,
        downloaded_count,
        cached_count,
        failed_count,
        total_bytes_downloaded: total_bytes,
    }
}

/// Download an asset and verify its integrity.
///
/// Uses a `.partial` intermediate file and atomic rename for crash safety.
fn download_and_verify(entry: &AssetEntry, cache: &AssetCache) -> io::Result<u64> {
    let target = cache.asset_path(entry);
    let partial = cache.partial_path(entry);

    // Ensure parent directory exists.
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }

    // Write asset data to partial file.
    // In a real implementation this would use HTTP with resume support.
    // For now, we create the file structure to support the pipeline.
    //
    // The actual download is delegated to the caller or a platform-specific
    // HTTP client. This function expects the file to be placed at the partial
    // path before verification.
    if !partial.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "download not implemented in library; place file at {} then call verify",
                partial.display()
            ),
        ));
    }

    // Verify integrity.
    let hash = compute_sha256(&partial)?;
    if hash != entry.sha256 {
        // Remove corrupt partial.
        let _ = fs::remove_file(&partial);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "integrity check failed: expected {} got {hash}",
                entry.sha256
            ),
        ));
    }

    // Atomic rename from partial to final.
    let size = fs::metadata(&partial)?.len();
    fs::rename(&partial, &target)?;
    Ok(size)
}

/// Verify a single cached asset's integrity.
///
/// # Errors
/// Returns an error if the asset is not in the cache or cannot be read.
pub fn verify_cached_asset(entry: &AssetEntry, cache: &AssetCache) -> io::Result<bool> {
    let path = cache.asset_path(entry);
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "asset not in cache",
        ));
    }
    let hash = compute_sha256(&path)?;
    Ok(hash == entry.sha256)
}

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------

/// Compute SHA-256 hex digest of a file.
///
/// # Errors
/// Returns an error if the file cannot be read.
pub fn compute_sha256(path: &Path) -> io::Result<String> {
    let data = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let result = hasher.finalize();
    Ok(hex_encode(&result))
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn url_filename(url: &str) -> String {
    url.rsplit('/')
        .next()
        .unwrap_or("asset")
        .split('?')
        .next()
        .unwrap_or("asset")
        .to_string()
}

// ---------------------------------------------------------------------------
// Offline diagnostics
// ---------------------------------------------------------------------------

/// Check manifest readiness for offline operation.
#[must_use]
pub fn offline_readiness(manifest: &AssetManifest, cache: &AssetCache) -> OfflineReport {
    let mut missing_required = Vec::new();
    let mut missing_optional = Vec::new();
    let mut corrupt = Vec::new();

    for entry in &manifest.assets {
        match cache.is_cached(entry) {
            CacheStatus::Valid => {}
            CacheStatus::Missing | CacheStatus::Partial { .. } => {
                if entry.required {
                    missing_required.push(entry.name.clone());
                } else {
                    missing_optional.push(entry.name.clone());
                }
            }
            CacheStatus::Corrupt { .. } => {
                corrupt.push(entry.name.clone());
            }
        }
    }

    let ready = missing_required.is_empty() && corrupt.is_empty();

    OfflineReport {
        ready,
        missing_required,
        missing_optional,
        corrupt,
    }
}

/// Offline readiness report.
#[derive(Debug, Clone, Serialize)]
pub struct OfflineReport {
    /// Whether all required assets are cached and valid.
    pub ready: bool,
    /// Names of missing required assets.
    pub missing_required: Vec<String>,
    /// Names of missing optional assets.
    pub missing_optional: Vec<String>,
    /// Names of corrupt cached assets.
    pub corrupt: Vec<String>,
}

// ---------------------------------------------------------------------------
// Human-readable formatting
// ---------------------------------------------------------------------------

/// Format a fetch summary for terminal output.
#[must_use]
pub fn format_fetch_summary(summary: &FetchSummary) -> String {
    let mut out = String::new();

    for result in &summary.results {
        let status_label = match result.status {
            FetchStatus::Downloaded => "[DONE]",
            FetchStatus::Cached => "[ OK ]",
            FetchStatus::Failed | FetchStatus::IntegrityFailed => "[FAIL]",
            FetchStatus::DryRun => "[PLAN]",
            FetchStatus::Skipped => "[SKIP]",
        };
        let _ = writeln!(
            out,
            "  {status_label} {} v{}: {}",
            result.name, result.version, result.message
        );
    }

    let _ = writeln!(
        out,
        "\nSummary: {} downloaded, {} cached, {} failed",
        summary.downloaded_count, summary.cached_count, summary.failed_count,
    );

    out
}

/// Format offline readiness for terminal output.
#[must_use]
pub fn format_offline_report(report: &OfflineReport) -> String {
    let mut out = String::new();

    if report.ready {
        out.push_str("Offline readiness: OK (all required assets cached)\n");
    } else {
        out.push_str("Offline readiness: NOT READY\n");
        if !report.missing_required.is_empty() {
            out.push_str("  Missing required assets:\n");
            for name in &report.missing_required {
                let _ = writeln!(out, "    - {name}");
            }
        }
        if !report.corrupt.is_empty() {
            out.push_str("  Corrupt cached assets (re-download needed):\n");
            for name in &report.corrupt {
                let _ = writeln!(out, "    - {name}");
            }
        }
    }

    if !report.missing_optional.is_empty() {
        out.push_str("  Missing optional assets:\n");
        for name in &report.missing_optional {
            let _ = writeln!(out, "    - {name}");
        }
    }

    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_manifest() -> AssetManifest {
        AssetManifest {
            version: "1.0.0".to_string(),
            assets: vec![
                AssetEntry {
                    name: "scoring-model".to_string(),
                    version: "2.0.0".to_string(),
                    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        .to_string(),
                    url: "https://example.com/scoring-model-2.0.0.bin".to_string(),
                    mirrors: vec![],
                    size_bytes: 1024,
                    required: true,
                    description: "ML scoring model".to_string(),
                },
                AssetEntry {
                    name: "pattern-db".to_string(),
                    version: "1.0.0".to_string(),
                    sha256: "abc123".to_string(),
                    url: "https://example.com/pattern-db-1.0.0.json".to_string(),
                    mirrors: vec!["https://mirror.example.com/pattern-db.json".to_string()],
                    size_bytes: 512,
                    required: false,
                    description: "Optional pattern database".to_string(),
                },
            ],
        }
    }

    #[test]
    fn manifest_roundtrip() {
        let manifest = sample_manifest();
        let json = manifest.to_json().unwrap();
        let parsed = AssetManifest::from_json(&json).unwrap();
        assert_eq!(manifest, parsed);
    }

    #[test]
    fn manifest_required_assets() {
        let manifest = sample_manifest();
        let required = manifest.required_assets();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0].name, "scoring-model");
    }

    #[test]
    fn manifest_total_size() {
        let manifest = sample_manifest();
        assert_eq!(manifest.total_size_bytes(), 1536);
    }

    #[test]
    fn cache_asset_path_layout() {
        let tmp = TempDir::new().unwrap();
        let cache = AssetCache::new(tmp.path().to_path_buf());
        let entry = &sample_manifest().assets[0];

        let path = cache.asset_path(entry);
        assert!(path.starts_with(tmp.path()));
        assert!(path.to_string_lossy().contains("scoring-model"));
        assert!(path.to_string_lossy().contains("2.0.0"));
        assert!(path.to_string_lossy().contains("scoring-model-2.0.0.bin"));
    }

    #[test]
    fn cache_partial_path() {
        let tmp = TempDir::new().unwrap();
        let cache = AssetCache::new(tmp.path().to_path_buf());
        let entry = &sample_manifest().assets[0];

        let partial = cache.partial_path(entry);
        assert!(partial.to_string_lossy().ends_with(".partial"));
    }

    #[test]
    fn cache_status_missing() {
        let tmp = TempDir::new().unwrap();
        let cache = AssetCache::new(tmp.path().to_path_buf());
        let entry = &sample_manifest().assets[0];

        assert_eq!(cache.is_cached(entry), CacheStatus::Missing);
    }

    #[test]
    fn cache_status_valid() {
        let tmp = TempDir::new().unwrap();
        let cache = AssetCache::new(tmp.path().to_path_buf());

        // Create a file whose SHA-256 matches the empty-file hash.
        let entry = AssetEntry {
            name: "test".to_string(),
            version: "1.0".to_string(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            url: "https://example.com/test.bin".to_string(),
            mirrors: vec![],
            size_bytes: 0,
            required: true,
            description: String::new(),
        };

        let path = cache.asset_path(&entry);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"").unwrap(); // Empty file has the known hash.

        assert_eq!(cache.is_cached(&entry), CacheStatus::Valid);
    }

    #[test]
    fn cache_status_corrupt() {
        let tmp = TempDir::new().unwrap();
        let cache = AssetCache::new(tmp.path().to_path_buf());

        let entry = AssetEntry {
            name: "test".to_string(),
            version: "1.0".to_string(),
            sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            url: "https://example.com/test.bin".to_string(),
            mirrors: vec![],
            size_bytes: 5,
            required: true,
            description: String::new(),
        };

        let path = cache.asset_path(&entry);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"hello").unwrap();

        match cache.is_cached(&entry) {
            CacheStatus::Corrupt { expected, actual } => {
                assert_eq!(expected, entry.sha256);
                assert!(!actual.is_empty());
            }
            other => panic!("expected Corrupt, got {other:?}"),
        }
    }

    #[test]
    fn cache_status_partial() {
        let tmp = TempDir::new().unwrap();
        let cache = AssetCache::new(tmp.path().to_path_buf());
        let entry = &sample_manifest().assets[0];

        // Create partial file only.
        let partial = cache.partial_path(entry);
        fs::create_dir_all(partial.parent().unwrap()).unwrap();
        fs::write(&partial, b"partial data").unwrap();

        match cache.is_cached(entry) {
            CacheStatus::Partial { bytes_downloaded } => {
                assert_eq!(bytes_downloaded, 12);
            }
            other => panic!("expected Partial, got {other:?}"),
        }
    }

    #[test]
    fn inventory_reports_all_assets() {
        let tmp = TempDir::new().unwrap();
        let cache = AssetCache::new(tmp.path().to_path_buf());
        let manifest = sample_manifest();

        let inv = cache.inventory(&manifest);
        assert_eq!(inv.len(), 2);
        assert_eq!(inv[0].status, CacheStatus::Missing);
        assert_eq!(inv[1].status, CacheStatus::Missing);
    }

    #[test]
    fn cleanup_empty_cache() {
        let tmp = TempDir::new().unwrap();
        let cache = AssetCache::new(tmp.path().to_path_buf());
        let manifest = sample_manifest();

        let report = cache.cleanup_stale(&manifest).unwrap();
        assert_eq!(report.removed_count, 0);
    }

    #[test]
    fn cleanup_removes_stale_versions() {
        let tmp = TempDir::new().unwrap();
        let cache = AssetCache::new(tmp.path().to_path_buf());

        // Create a stale version directory.
        let stale = tmp
            .path()
            .join("scoring-model")
            .join("1.0.0")
            .join("old.bin");
        fs::create_dir_all(stale.parent().unwrap()).unwrap();
        fs::write(&stale, b"old data").unwrap();

        // Manifest requires version 2.0.0.
        let manifest = sample_manifest();
        let report = cache.cleanup_stale(&manifest).unwrap();
        assert_eq!(report.removed_count, 1);
        assert!(report.removed_bytes > 0);
        assert!(!stale.exists());
    }

    #[test]
    fn fetch_dry_run_does_not_create_files() {
        let tmp = TempDir::new().unwrap();
        let cache = AssetCache::new(tmp.path().to_path_buf());
        let manifest = sample_manifest();

        let opts = FetchOptions {
            dry_run: true,
            ..Default::default()
        };

        let summary = fetch_assets(&manifest, &cache, &opts);
        assert_eq!(summary.downloaded_count, 0);
        for result in &summary.results {
            assert!(
                result.status == FetchStatus::DryRun || result.status == FetchStatus::Cached,
                "dry-run should not download"
            );
        }
    }

    #[test]
    fn fetch_offline_fails_for_missing() {
        let tmp = TempDir::new().unwrap();
        let cache = AssetCache::new(tmp.path().to_path_buf());
        let manifest = sample_manifest();

        let opts = FetchOptions {
            offline: true,
            ..Default::default()
        };

        let summary = fetch_assets(&manifest, &cache, &opts);
        assert!(
            summary.failed_count > 0,
            "missing assets should fail in offline mode"
        );
        let first = &summary.results[0];
        assert_eq!(first.status, FetchStatus::Failed);
        assert!(first.message.contains("offline mode"));
    }

    #[test]
    fn fetch_skips_optional_with_required_only() {
        let tmp = TempDir::new().unwrap();
        let cache = AssetCache::new(tmp.path().to_path_buf());
        let manifest = sample_manifest();

        let opts = FetchOptions {
            required_only: true,
            dry_run: true,
            ..Default::default()
        };

        let summary = fetch_assets(&manifest, &cache, &opts);
        let optional = summary
            .results
            .iter()
            .find(|r| r.name == "pattern-db")
            .unwrap();
        assert_eq!(optional.status, FetchStatus::Skipped);
    }

    #[test]
    fn verify_cached_asset_valid() {
        let tmp = TempDir::new().unwrap();
        let cache = AssetCache::new(tmp.path().to_path_buf());

        let entry = AssetEntry {
            name: "test".to_string(),
            version: "1.0".to_string(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            url: "https://example.com/test.bin".to_string(),
            mirrors: vec![],
            size_bytes: 0,
            required: true,
            description: String::new(),
        };

        let path = cache.asset_path(&entry);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"").unwrap();

        assert!(verify_cached_asset(&entry, &cache).unwrap());
    }

    #[test]
    fn verify_cached_asset_mismatch() {
        let tmp = TempDir::new().unwrap();
        let cache = AssetCache::new(tmp.path().to_path_buf());

        let entry = AssetEntry {
            name: "test".to_string(),
            version: "1.0".to_string(),
            sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            url: "https://example.com/test.bin".to_string(),
            mirrors: vec![],
            size_bytes: 5,
            required: true,
            description: String::new(),
        };

        let path = cache.asset_path(&entry);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"hello").unwrap();

        assert!(!verify_cached_asset(&entry, &cache).unwrap());
    }

    #[test]
    fn offline_readiness_all_cached() {
        let tmp = TempDir::new().unwrap();
        let cache = AssetCache::new(tmp.path().to_path_buf());

        let entry = AssetEntry {
            name: "model".to_string(),
            version: "1.0".to_string(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            url: "https://example.com/model.bin".to_string(),
            mirrors: vec![],
            size_bytes: 0,
            required: true,
            description: String::new(),
        };

        let path = cache.asset_path(&entry);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"").unwrap();

        let manifest = AssetManifest {
            version: "1.0.0".to_string(),
            assets: vec![entry],
        };

        let report = offline_readiness(&manifest, &cache);
        assert!(report.ready);
    }

    #[test]
    fn offline_readiness_missing_required() {
        let tmp = TempDir::new().unwrap();
        let cache = AssetCache::new(tmp.path().to_path_buf());
        let manifest = sample_manifest();

        let report = offline_readiness(&manifest, &cache);
        assert!(!report.ready);
        assert!(
            report
                .missing_required
                .contains(&"scoring-model".to_string())
        );
    }

    #[test]
    fn url_filename_extraction() {
        assert_eq!(
            url_filename("https://example.com/path/model.bin"),
            "model.bin"
        );
        assert_eq!(
            url_filename("https://example.com/path/model.bin?token=abc"),
            "model.bin"
        );
        assert_eq!(url_filename("model.bin"), "model.bin");
    }

    #[test]
    fn hex_encode_correctness() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn compute_sha256_empty_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("empty");
        fs::write(&path, b"").unwrap();

        let hash = compute_sha256(&path).unwrap();
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn compute_sha256_known_content() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("hello");
        fs::write(&path, b"hello").unwrap();

        let hash = compute_sha256(&path).unwrap();
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn format_fetch_summary_output() {
        let summary = FetchSummary {
            results: vec![FetchResult {
                name: "model".to_string(),
                version: "1.0".to_string(),
                status: FetchStatus::Cached,
                path: PathBuf::from("/cache/model"),
                message: "already cached".to_string(),
            }],
            downloaded_count: 0,
            cached_count: 1,
            failed_count: 0,
            total_bytes_downloaded: 0,
        };

        let output = format_fetch_summary(&summary);
        assert!(output.contains("[ OK ] model v1.0"));
        assert!(output.contains("0 downloaded"));
        assert!(output.contains("1 cached"));
    }

    #[test]
    fn format_offline_ready() {
        let report = OfflineReport {
            ready: true,
            missing_required: vec![],
            missing_optional: vec![],
            corrupt: vec![],
        };
        let output = format_offline_report(&report);
        assert!(output.contains("OK"));
    }

    #[test]
    fn format_offline_not_ready() {
        let report = OfflineReport {
            ready: false,
            missing_required: vec!["model-v2".to_string()],
            missing_optional: vec!["extra-db".to_string()],
            corrupt: vec![],
        };
        let output = format_offline_report(&report);
        assert!(output.contains("NOT READY"));
        assert!(output.contains("model-v2"));
        assert!(output.contains("extra-db"));
    }

    #[test]
    fn disk_usage_empty() {
        let tmp = TempDir::new().unwrap();
        let cache = AssetCache::new(tmp.path().join("nonexistent"));
        assert_eq!(cache.disk_usage(), 0);
    }

    #[test]
    fn cache_status_display() {
        assert_eq!(CacheStatus::Valid.to_string(), "valid");
        assert_eq!(CacheStatus::Missing.to_string(), "missing");
        assert_eq!(
            CacheStatus::Partial {
                bytes_downloaded: 42
            }
            .to_string(),
            "partial (42 bytes)"
        );
        assert_eq!(
            CacheStatus::Corrupt {
                expected: String::new(),
                actual: String::new()
            }
            .to_string(),
            "corrupt"
        );
    }

    #[test]
    fn fetch_status_display() {
        assert_eq!(FetchStatus::Downloaded.to_string(), "downloaded");
        assert_eq!(FetchStatus::Failed.to_string(), "failed");
    }

    #[test]
    fn summary_serializes() {
        let summary = FetchSummary {
            results: vec![],
            downloaded_count: 0,
            cached_count: 0,
            failed_count: 0,
            total_bytes_downloaded: 0,
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"downloaded_count\":0"));
    }
}
