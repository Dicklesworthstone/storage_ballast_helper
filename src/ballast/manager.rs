//! Ballast file manager: create/verify/reclaim pre-allocated sacrificial space files.
//!
//! Ballast files are named `SBH_BALLAST_FILE_NNNNN.dat` and contain a 4096-byte
//! JSON header followed by reserved data blocks. On platforms with native
//! preallocation, provisioning uses the PAL for instant allocation; on CoW
//! filesystems (btrfs, zfs), random data is written in 4 MB chunks to defeat
//! deduplication.
//!
//! Access to the ballast directory is serialized via `flock()` on a lockfile so
//! concurrent daemon + CLI operations don't race.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::core::config::BallastConfig;
use crate::core::errors::{Result, SbhError};
use crate::platform::pal::Platform;

// ──────────────────── constants ────────────────────

const HEADER_SIZE: usize = 4096;
const MAGIC: &str = "SBH_BALLAST_v1";
const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4 MB write chunks
const FSYNC_EVERY_BYTES: u64 = 64 * 1024 * 1024; // fsync every 64 MB
const MIN_FREE_PCT: f64 = 20.0; // abort provisioning below this

// ──────────────────── header ────────────────────

/// JSON metadata stored in the first 4096 bytes of each ballast file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BallastHeader {
    pub magic: String,
    pub file_index: u32,
    pub created_at: String,
    pub file_size: u64,
    pub purpose: String,
}

impl BallastHeader {
    fn new(index: u32, size: u64) -> Self {
        let now = chrono::Utc::now();
        Self {
            magic: MAGIC.to_string(),
            file_index: index,
            created_at: now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            file_size: size,
            purpose: "Storage ballast for emergency space recovery".to_string(),
        }
    }

    fn validate(&self) -> bool {
        self.magic == MAGIC
    }
}

// ──────────────────── ballast file info ────────────────────

/// Tracked metadata about a single ballast file.
#[derive(Debug, Clone)]
pub struct BallastFile {
    pub path: PathBuf,
    pub index: u32,
    pub size: u64,
    pub created_at: String,
    pub integrity_ok: bool,
}

// ──────────────────── reports ────────────────────

/// Result of a provision or replenish operation.
#[derive(Debug, Clone)]
pub struct ProvisionReport {
    pub files_created: usize,
    pub files_skipped: usize,
    pub total_bytes: u64,
    pub errors: Vec<String>,
}

/// Result of a verify operation.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub files_checked: usize,
    pub files_ok: usize,
    pub files_corrupted: usize,
    pub files_missing: usize,
    pub details: Vec<String>,
}

/// Result of a release operation.
#[derive(Debug, Clone)]
pub struct ReleaseReport {
    pub files_released: usize,
    pub bytes_freed: u64,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

// ──────────────────── health ────────────────────

/// Machine-readable health of a ballast pool: how much of the configured
/// emergency reserve is actually releasable right now (#16).
///
/// The distinction matters operationally: configured totals describe intent,
/// while releasable bytes describe the reserve that actually exists on disk.
/// A dashboard that reads only configured totals can believe a full reserve
/// exists after every file has been released or lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BallastHealth {
    /// No reserve is configured (`file_count == 0` or `file_size_bytes == 0`).
    Unconfigured,
    /// The full configured reserve is present and releasable.
    Ok,
    /// Some reserve is releasable, but less than configured
    /// (released, missing, or truncated files).
    Degraded,
    /// A reserve is configured but zero bytes are releasable — the emergency
    /// reserve does not exist precisely when it may be needed. Surfaces
    /// loudly in `status`, `check`, and `doctor`.
    Empty,
    /// The pool could not be read, so its true state is unknown. Raised when
    /// `stat` fails for a reason other than "not found" — most often because
    /// an unprivileged caller cannot traverse a root-owned ballast directory
    /// (`/root/...` is mode 700). Reporting `Empty` here would be a lie in the
    /// most dangerous direction: it tells an operator their emergency reserve
    /// is gone when the daemon can still see and release every file.
    Indeterminate,
}

impl BallastHealth {
    /// Evaluate pool health from the configured pool size and the bytes that
    /// releasing every inventoried file would actually free.
    ///
    /// Integrity-corrupt files still count toward `releasable_bytes`:
    /// deleting a file frees its on-disk bytes regardless of header state.
    #[must_use]
    pub fn evaluate(configured_pool_bytes: u64, releasable_bytes: u64) -> Self {
        if configured_pool_bytes == 0 {
            Self::Unconfigured
        } else if releasable_bytes == 0 {
            Self::Empty
        } else if releasable_bytes < configured_pool_bytes {
            Self::Degraded
        } else {
            Self::Ok
        }
    }

    /// Stable machine-readable label for JSON output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unconfigured => "unconfigured",
            Self::Ok => "ok",
            Self::Degraded => "degraded",
            Self::Empty => "empty",
            Self::Indeterminate => "indeterminate",
        }
    }
}

impl std::fmt::Display for BallastHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Read-only snapshot of a ballast pool's actual availability (#16).
///
/// Unlike [`BallastManager::new`], observing never creates the pool
/// directory and never prunes orphans, so it is safe to call from read-only
/// surfaces (`sbh status`, `sbh check`, `sbh doctor`) even on a full or
/// read-only filesystem.
#[derive(Debug, Clone)]
pub struct BallastAvailability {
    /// Configured number of ballast files.
    pub configured_count: usize,
    /// Configured size of each ballast file in bytes.
    pub configured_file_size_bytes: u64,
    /// Configured total pool size (`count × size`, saturating).
    pub configured_pool_bytes: u64,
    /// Ballast files currently present on disk.
    pub available_count: usize,
    /// Configured files confirmed absent (released or lost).
    ///
    /// Only counts files whose `stat` returned `NotFound`. Files that could not
    /// be inspected at all are counted in `unreadable_count` instead, so a
    /// permission failure is never reported as a missing reserve.
    pub missing_count: usize,
    /// Configured files whose presence could not be determined, because `stat`
    /// failed for a reason other than "not found" (permission denied, I/O
    /// error). Non-zero means this snapshot is not authoritative.
    pub unreadable_count: usize,
    /// Bytes that releasing every present file would free.
    pub releasable_bytes: u64,
    /// Overall pool health derived from the fields above.
    pub health: BallastHealth,
}

impl BallastAvailability {
    /// Observe the pool at `ballast_dir` without mutating anything.
    #[must_use]
    pub fn observe(ballast_dir: &Path, config: &BallastConfig) -> Self {
        let configured_pool_bytes =
            (config.file_count as u64).saturating_mul(config.file_size_bytes);
        let mut available_count = 0usize;
        let mut missing_count = 0usize;
        let mut unreadable_count = 0usize;
        let mut releasable_bytes = 0u64;
        for i in 1..=config.file_count {
            let path = ballast_dir.join(ballast_file_name(i as u32));
            match fs::metadata(&path) {
                Ok(meta) if meta.is_file() => {
                    available_count += 1;
                    releasable_bytes = releasable_bytes.saturating_add(meta.len());
                }
                // Path exists but is not a regular file: the reserve slot is
                // genuinely unusable, which is a real absence.
                Ok(_) => missing_count += 1,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => missing_count += 1,
                // Permission denied, I/O error, and friends: we simply do not
                // know. Never fold this into `missing`.
                Err(_) => unreadable_count += 1,
            }
        }
        let health = if unreadable_count > 0 {
            BallastHealth::Indeterminate
        } else {
            BallastHealth::evaluate(configured_pool_bytes, releasable_bytes)
        };
        Self {
            configured_count: config.file_count,
            configured_file_size_bytes: config.file_size_bytes,
            configured_pool_bytes,
            available_count,
            missing_count,
            unreadable_count,
            releasable_bytes,
            health,
        }
    }

    /// Whether this snapshot is authoritative (every configured slot was
    /// successfully inspected). Callers should avoid asserting that the reserve
    /// is gone when this is `false`.
    #[must_use]
    pub const fn is_authoritative(&self) -> bool {
        self.unreadable_count == 0
    }
}

/// Canonical ballast file name for a 1-based index.
fn ballast_file_name(index: u32) -> String {
    format!("SBH_BALLAST_FILE_{index:05}.dat")
}

// ──────────────────── manager ────────────────────

/// Manages the lifecycle of ballast files: creation, verification, release, replenishment.
pub struct BallastManager {
    ballast_dir: PathBuf,
    config: BallastConfig,
    inventory: Vec<BallastFile>,
    platform: Arc<dyn Platform>,
    /// When true, skip platform preallocation and always write random data.
    /// Set for CoW filesystems (btrfs, zfs) where zero-allocated extents can
    /// be trivially deduplicated, defeating the purpose of ballast.
    skip_fallocate: bool,
}

impl BallastManager {
    /// Create a new manager for the given directory and configuration.
    pub fn new(ballast_dir: PathBuf, config: BallastConfig) -> Result<Self> {
        let platform: Arc<dyn Platform> = Arc::new(crate::platform::current());
        Self::with_platform(ballast_dir, config, platform)
    }

    /// Create a new manager with an explicit platform implementation.
    pub fn with_platform(
        ballast_dir: PathBuf,
        config: BallastConfig,
        platform: Arc<dyn Platform>,
    ) -> Result<Self> {
        fs::create_dir_all(&ballast_dir).map_err(|e| SbhError::io(&ballast_dir, e))?;

        let mut mgr = Self {
            ballast_dir,
            config,
            inventory: Vec::new(),
            platform,
            skip_fallocate: false,
        };
        // Prune any existing files that exceed the initial configuration count.
        let _ = mgr.prune_orphans();
        mgr.scan_existing();
        Ok(mgr)
    }

    /// Directory containing ballast files.
    pub fn ballast_dir(&self) -> &Path {
        &self.ballast_dir
    }

    /// Configuration for this manager.
    pub fn config(&self) -> &BallastConfig {
        &self.config
    }

    /// Current inventory of ballast files.
    pub fn inventory(&self) -> &[BallastFile] {
        &self.inventory
    }

    /// How many bytes can be released (sum of all inventoried files).
    pub fn releasable_bytes(&self) -> u64 {
        self.inventory.iter().map(|f| f.size).sum()
    }

    /// Number of ballast files currently available.
    pub fn available_count(&self) -> usize {
        self.inventory.len()
    }

    /// Configured total pool size (`file_count × file_size_bytes`, saturating).
    pub fn configured_pool_bytes(&self) -> u64 {
        (self.config.file_count as u64).saturating_mul(self.config.file_size_bytes)
    }

    /// Current pool health: configured reserve vs actually releasable bytes (#16).
    pub fn health(&self) -> BallastHealth {
        BallastHealth::evaluate(self.configured_pool_bytes(), self.releasable_bytes())
    }

    /// Update configuration at runtime.
    pub fn update_config(&mut self, config: BallastConfig) {
        self.config = config;
        // Prune any files that exceed the new configuration count.
        let _ = self.prune_orphans();
        // Re-scan inventory to reflect new file count limits.
        self.scan_existing();
    }

    /// Force random-data provisioning, skipping `fallocate`.
    ///
    /// Required on CoW filesystems (btrfs, zfs, bcachefs) where fallocate
    /// allocates zero-filled blocks that are trivially deduplicated.
    pub fn set_skip_fallocate(&mut self, skip: bool) {
        self.skip_fallocate = skip;
    }

    // ──────────────────── locking ────────────────────

    #[cfg(unix)]
    fn acquire_lock(&self) -> Result<nix::fcntl::Flock<File>> {
        let lock_path = self.ballast_dir.join(".lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|e| SbhError::io(&lock_path, e))?;

        #[allow(deprecated)]
        nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusive).map_err(|(_file, e)| {
            SbhError::Runtime {
                details: format!("failed to lock ballast dir: {e}"),
            }
        })
    }

    #[cfg(not(unix))]
    fn acquire_lock(&self) -> Result<()> {
        Ok(())
    }

    // ──────────────────── provision ────────────────────

    /// Create all ballast files (idempotent: skips existing valid files).
    ///
    /// If `free_pct_check` is provided, it's called before creating each file
    /// to ensure we don't go below the minimum free space threshold.
    pub fn provision(
        &mut self,
        free_pct_check: Option<&dyn Fn() -> f64>,
    ) -> Result<ProvisionReport> {
        let _lock = self.acquire_lock()?;
        let mut report = ProvisionReport {
            files_created: 0,
            files_skipped: 0,
            total_bytes: 0,
            errors: Vec::new(),
        };

        // Ensure no orphans exist before provisioning.
        let _ = self.prune_orphans();

        for i in 1..=self.config.file_count {
            let index = i as u32;
            let path = self.file_path(index);

            // Skip if already exists and valid.
            if path.exists() {
                if self.verify_single_file(&path, index).is_ok() {
                    report.files_skipped += 1;
                    continue;
                }
                // Corrupted: remove and recreate.
                let _ = fs::remove_file(&path);
            }

            // Free-space check.
            if let Some(check) = free_pct_check {
                let free = check();
                if free < MIN_FREE_PCT {
                    report.errors.push(format!(
                        "aborted at file {index}: free space {free:.1}% < {MIN_FREE_PCT}%"
                    ));
                    break;
                }
            }

            match self.create_ballast_file(index) {
                Ok(()) => {
                    report.files_created += 1;
                    let actual_size =
                        fs::metadata(&path).map_or(self.config.file_size_bytes, |m| m.len());
                    report.total_bytes += actual_size;
                }
                Err(e) => {
                    if record_create_error(&mut report, index, &path, &e) {
                        break;
                    }
                }
            }
        }

        self.scan_existing();
        Ok(report)
    }

    // ──────────────────── release ────────────────────

    /// Release N ballast files (delete highest-index first).
    pub fn release(&mut self, count: usize) -> Result<ReleaseReport> {
        let _lock = self.acquire_lock()?;
        let mut report = ReleaseReport {
            files_released: 0,
            bytes_freed: 0,
            warnings: Vec::new(),
            errors: Vec::new(),
        };

        // Collect indices of available files in descending order.
        let mut available: Vec<u32> = self.inventory.iter().map(|f| f.index).collect();
        available.sort_unstable_by(|a, b| b.cmp(a));

        for &index in available.iter().take(count) {
            let path = self.file_path(index);
            let actual_size = fs::metadata(&path).map_or(0, |m| m.len());
            match fs::remove_file(&path) {
                Ok(()) => {
                    report.files_released += 1;
                    report.bytes_freed += actual_size;
                }
                Err(e) => {
                    report
                        .errors
                        .push(format!("failed to release file {index}: {e}"));
                }
            }
        }

        if report.files_released > 0 {
            report
                .warnings
                .extend(self.local_snapshot_release_warnings());
        }

        self.scan_existing();
        Ok(report)
    }

    fn local_snapshot_release_warnings(&self) -> Vec<String> {
        let Ok(capacity) = self.platform.capacity(&self.ballast_dir) else {
            return Vec::new();
        };
        let Ok(snapshots) = self
            .platform
            .local_time_machine_snapshots(&capacity.mount_point)
        else {
            return Vec::new();
        };
        if snapshots.is_empty() {
            return Vec::new();
        }

        vec![time_machine_snapshot_release_warning(
            &capacity.mount_point,
            &snapshots,
        )]
    }

    // ──────────────────── verify ────────────────────

    /// Verify integrity of all expected ballast files.
    pub fn verify(&mut self) -> Result<VerifyReport> {
        let mut report = VerifyReport {
            files_checked: 0,
            files_ok: 0,
            files_corrupted: 0,
            files_missing: 0,
            details: Vec::new(),
        };

        for i in 1..=self.config.file_count {
            let index = i as u32;
            let path = self.file_path(index);
            report.files_checked += 1;

            if !path.exists() {
                report.files_missing += 1;
                report.details.push(format!("file {index}: missing"));
                continue;
            }

            match self.verify_single_file(&path, index) {
                Ok(()) => report.files_ok += 1,
                Err(msg) => {
                    report.files_corrupted += 1;
                    report.details.push(format!("file {index}: {msg}"));
                }
            }
        }

        Ok(report)
    }

    // ──────────────────── replenish ────────────────────

    /// Recreate released ballast files when pressure subsides.
    pub fn replenish(
        &mut self,
        free_pct_check: Option<&dyn Fn() -> f64>,
    ) -> Result<ProvisionReport> {
        // Replenish is the same as provision — it's idempotent.
        self.provision(free_pct_check)
    }

    /// Recreate at most one missing ballast file (for gradual replenishment).
    pub fn replenish_one(
        &mut self,
        free_pct_check: Option<&dyn Fn() -> f64>,
    ) -> Result<ProvisionReport> {
        let _lock = self.acquire_lock()?;
        let mut report = ProvisionReport {
            files_created: 0,
            files_skipped: 0,
            total_bytes: 0,
            errors: Vec::new(),
        };

        // Ensure no orphans exist before replenishing.
        let _ = self.prune_orphans();

        for i in 1..=self.config.file_count {
            let index = i as u32;
            let path = self.file_path(index);

            if path.exists() {
                if self.verify_single_file(&path, index).is_ok() {
                    report.files_skipped += 1;
                    continue;
                }
                let _ = fs::remove_file(&path);
            }

            // Free-space check.
            if let Some(check) = free_pct_check {
                let free = check();
                if free < MIN_FREE_PCT {
                    report.errors.push(format!(
                        "aborted at file {index}: free space {free:.1}% < {MIN_FREE_PCT}%"
                    ));
                    break;
                }
            }

            match self.create_ballast_file(index) {
                Ok(()) => {
                    report.files_created += 1;
                    let actual_size =
                        fs::metadata(&path).map_or(self.config.file_size_bytes, |m| m.len());
                    report.total_bytes += actual_size;
                    // Only create one file per call.
                    break;
                }
                Err(e) => {
                    if record_create_error(&mut report, index, &path, &e) {
                        break;
                    }
                }
            }
        }

        self.scan_existing();
        Ok(report)
    }

    // ──────────────────── internal ────────────────────

    /// Scan directory for ballast files with index > current file_count and remove them.
    fn prune_orphans(&self) -> Result<()> {
        let entries = match fs::read_dir(&self.ballast_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(SbhError::io(&self.ballast_dir, e)),
        };

        for entry in entries {
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };

            // Check pattern: SBH_BALLAST_FILE_{index:05}.dat
            if !name.starts_with("SBH_BALLAST_FILE_")
                || !std::path::Path::new(name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("dat"))
            {
                continue;
            }

            let prefix_len = "SBH_BALLAST_FILE_".len();
            let suffix_len = ".dat".len();
            if name.len() <= prefix_len + suffix_len {
                continue;
            }

            let num_part = &name[prefix_len..name.len() - suffix_len];
            if let Ok(index) = num_part.parse::<u32>()
                && (index > self.config.file_count as u32 || index == 0)
            {
                // Orphan!
                let _ = fs::remove_file(&path);
            }
        }
        Ok(())
    }

    fn file_path(&self, index: u32) -> PathBuf {
        self.ballast_dir.join(ballast_file_name(index))
    }

    fn scan_existing(&mut self) {
        self.inventory.clear();
        for i in 1..=self.config.file_count {
            let index = i as u32;
            let path = self.file_path(index);
            if path.exists() {
                let integrity_ok = self.verify_single_file(&path, index).is_ok();
                let size = fs::metadata(&path).map_or(0, |m| m.len());
                let created_at = fs::metadata(&path)
                    .ok()
                    .and_then(|m| m.created().ok())
                    .map(|t| {
                        let dt: chrono::DateTime<chrono::Utc> = t.into();
                        dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                    })
                    .unwrap_or_default();

                self.inventory.push(BallastFile {
                    path: path.clone(),
                    index,
                    size,
                    created_at,
                    integrity_ok,
                });
            }
            // If the file doesn't exist, it's been released (not added to inventory).
        }
    }

    fn verify_single_file(
        &self,
        path: &Path,
        expected_index: u32,
    ) -> std::result::Result<(), String> {
        // Check file size.
        let meta = fs::metadata(path).map_err(|e| format!("metadata: {e}"))?;
        if meta.len() != self.config.file_size_bytes {
            return Err(format!(
                "size mismatch: expected {} got {}",
                self.config.file_size_bytes,
                meta.len()
            ));
        }

        // Read and validate header.
        let mut file = File::open(path).map_err(|e| format!("open: {e}"))?;
        let mut header_buf = vec![0u8; HEADER_SIZE];
        file.read_exact(&mut header_buf)
            .map_err(|e| format!("read header: {e}"))?;

        // Find the end of JSON (null-padded).
        let json_end = header_buf
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(HEADER_SIZE);
        let header_str = std::str::from_utf8(&header_buf[..json_end])
            .map_err(|e| format!("header not UTF-8: {e}"))?;
        let header: BallastHeader =
            serde_json::from_str(header_str).map_err(|e| format!("header parse: {e}"))?;

        if !header.validate() {
            return Err(format!("bad magic: {}", header.magic));
        }
        if header.file_index != expected_index {
            return Err(format!(
                "index mismatch: expected {expected_index} got {}",
                header.file_index
            ));
        }
        if header.file_size != self.config.file_size_bytes {
            return Err(format!(
                "header size mismatch: {} vs {}",
                header.file_size, self.config.file_size_bytes
            ));
        }

        let blocks = self
            .platform
            .file_block_count(path)
            .map_err(|e| format!("block count: {e}"))?;
        let allocated_bytes = blocks
            .checked_mul(512)
            .ok_or_else(|| "allocated block count overflow".to_string())?;
        if allocated_bytes < self.config.file_size_bytes {
            return Err(format!(
                "allocated bytes mismatch: expected at least {} got {allocated_bytes}",
                self.config.file_size_bytes
            ));
        }

        Ok(())
    }

    fn create_ballast_file(&self, index: u32) -> Result<()> {
        let path = self.file_path(index);
        let size = self.config.file_size_bytes;

        if size < HEADER_SIZE as u64 {
            return Err(SbhError::InvalidConfig {
                details: format!("file_size_bytes ({size}) must be >= HEADER_SIZE ({HEADER_SIZE})"),
            });
        }

        let result = self.write_ballast_file_inner(index, &path, size);
        if result.is_err() {
            // Clean up partial file on write error.
            let _ = fs::remove_file(&path);
        }
        result
    }

    fn write_ballast_file_inner(&self, index: u32, path: &Path, size: u64) -> Result<()> {
        let header_buf = ballast_header_buffer(index, size)?;

        if !self.skip_fallocate {
            match self.platform.preallocate_file(path, size) {
                Ok(()) => {
                    Self::write_header_to_preallocated_file(path, size, &header_buf)?;
                    return Ok(());
                }
                Err(error) if is_storage_exhausted_error(&error) => return Err(error),
                Err(_) => {}
            }
        }

        let data_size = size - HEADER_SIZE as u64;
        let mut file = create_truncated_ballast_file(path)?;
        file.write_all(&header_buf)
            .map_err(|e| SbhError::io(path, e))?;
        self.write_random_data(&mut file, data_size, path)?;
        file.sync_all().map_err(|e| SbhError::io(path, e))?;
        Ok(())
    }

    fn write_header_to_preallocated_file(path: &Path, size: u64, header_buf: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(false)
            .truncate(false)
            .open(path)
            .map_err(|e| SbhError::io(path, e))?;
        file.set_len(size).map_err(|e| SbhError::io(path, e))?;
        file.write_all(header_buf)
            .map_err(|e| SbhError::io(path, e))?;
        file.sync_all().map_err(|e| SbhError::io(path, e))?;
        Ok(())
    }

    #[allow(clippy::unused_self)]
    fn write_random_data(&self, file: &mut File, data_size: u64, path: &Path) -> Result<()> {
        let mut rng = rand::rng();
        let mut written: u64 = 0;
        let mut chunk = vec![0u8; CHUNK_SIZE];
        let mut bytes_since_fsync: u64 = 0;

        while written < data_size {
            let remaining = data_size - written;
            let to_write = if remaining > CHUNK_SIZE as u64 {
                CHUNK_SIZE
            } else {
                remaining as usize
            };

            rng.fill_bytes(&mut chunk[..to_write]);
            file.write_all(&chunk[..to_write])
                .map_err(|e| SbhError::io(path, e))?;
            written += to_write as u64;
            bytes_since_fsync += to_write as u64;

            if bytes_since_fsync >= FSYNC_EVERY_BYTES {
                file.sync_all().map_err(|e| SbhError::io(path, e))?;
                bytes_since_fsync = 0;
            }
        }

        Ok(())
    }
}

fn ballast_header_buffer(index: u32, size: u64) -> Result<Vec<u8>> {
    let header = BallastHeader::new(index, size);
    let header_json = serde_json::to_string(&header)?;
    if header_json.len() > HEADER_SIZE {
        return Err(SbhError::Runtime {
            details: format!(
                "ballast header JSON ({} bytes) exceeds HEADER_SIZE ({HEADER_SIZE})",
                header_json.len()
            ),
        });
    }
    let mut header_buf = vec![0u8; HEADER_SIZE];
    header_buf[..header_json.len()].copy_from_slice(header_json.as_bytes());
    Ok(header_buf)
}

fn create_truncated_ballast_file(path: &Path) -> Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path).map_err(|e| SbhError::io(path, e))
}

fn record_create_error(
    report: &mut ProvisionReport,
    index: u32,
    path: &Path,
    error: &SbhError,
) -> bool {
    if is_storage_exhausted_error(error) {
        report.errors.push(format!(
            "file {index}: storage exhausted while creating ballast at {}; skipping remaining ballast provisioning so scanner and cleanup defenses can continue. Reduce ballast.file_count or ballast.file_size_bytes, free space, or run `sbh ballast replenish` after pressure clears: {error}",
            path.display()
        ));
        true
    } else {
        report.errors.push(format!("file {index}: {error}"));
        false
    }
}

fn is_storage_exhausted_error(error: &SbhError) -> bool {
    match error {
        SbhError::Io { source, .. } => io_error_is_storage_full(source),
        SbhError::Pal {
            source:
                crate::platform::types::PalError::MethodFailed {
                    details,
                    method_name,
                    ..
                },
        } if method_name == "preallocate_file" => message_mentions_storage_full(details),
        SbhError::Runtime { details } => message_mentions_storage_full(details),
        _ => false,
    }
}

fn io_error_is_storage_full(error: &std::io::Error) -> bool {
    error.kind() == ErrorKind::StorageFull
        || error
            .raw_os_error()
            .is_some_and(raw_os_error_is_storage_full)
}

#[cfg(unix)]
fn raw_os_error_is_storage_full(code: i32) -> bool {
    code == libc::ENOSPC
}

#[cfg(windows)]
fn raw_os_error_is_storage_full(code: i32) -> bool {
    code == 112
}

#[cfg(not(any(unix, windows)))]
fn raw_os_error_is_storage_full(_code: i32) -> bool {
    false
}

fn message_mentions_storage_full(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("no space left on device")
        || message.contains("enospc")
        || message.contains("storage full")
        || message.contains("disk full")
        || message.contains("not enough space")
}

fn time_machine_snapshot_release_warning(
    mount: &Path,
    snapshots: &[crate::platform::types::LocalSnapshotInfo],
) -> String {
    let count = snapshots.len();
    let snapshot_word = if count == 1 {
        "snapshot is"
    } else {
        "snapshots are"
    };
    let retained_bytes = snapshots
        .iter()
        .filter_map(|snapshot| snapshot.retained_bytes_estimate)
        .fold(0_u64, u64::saturating_add);
    let retained_clause = if retained_bytes == 0 {
        String::new()
    } else {
        format!(" Estimated retained bytes: {retained_bytes}.")
    };

    format!(
        "{count} Time Machine local {snapshot_word} present on {}. macOS may retain released ballast bytes until snapshots expire or are thinned.{retained_clause} Thin manually with: {}",
        mount.display(),
        time_machine_thin_command(mount)
    )
}

fn time_machine_thin_command(mount: &Path) -> String {
    let mount_text = mount.to_string_lossy();
    format!(
        "sudo tmutil thinlocalsnapshots {} 9999999999999999 4",
        shell_quote_for_warning(mount_text.as_ref())
    )
}

fn shell_quote_for_warning(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }

    if value.chars().all(|ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-' | ':' | '@' | '%' | '+')
    }) {
        return value.to_string();
    }

    format!("'{}'", value.replace('\'', "'\\''"))
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Regression: an unreadable ballast directory must NOT be reported as an
    /// empty reserve.
    ///
    /// The original `observe()` used `if let Ok(meta) = fs::metadata(..)`, which
    /// swallowed `PermissionDenied` exactly like `NotFound`. On a real fleet the
    /// ballast dir lives under root's home (mode 700), so `sbh status` run as an
    /// unprivileged user reported `available=0 missing=10 health=empty` for a
    /// pool that was fully present and releasable by the (root) daemon — the
    /// alarm fired in the most misleading possible direction.
    #[cfg(unix)]
    #[test]
    fn observe_reports_indeterminate_when_dir_is_unreadable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let ballast_dir = dir.path().join("ballast");
        std::fs::create_dir_all(&ballast_dir).expect("create ballast dir");

        let config = small_config();
        // Populate the pool so the files genuinely exist.
        for i in 1..=config.file_count {
            std::fs::write(ballast_dir.join(ballast_file_name(i as u32)), b"x").expect("write");
        }

        // Sanity: readable → not indeterminate, and all files are found.
        let readable = BallastAvailability::observe(&ballast_dir, &config);
        assert_eq!(readable.available_count, config.file_count);
        assert_eq!(readable.unreadable_count, 0);
        assert!(readable.is_authoritative());
        assert_ne!(readable.health, BallastHealth::Indeterminate);

        // Strip all permissions so stat() inside fails with EACCES.
        std::fs::set_permissions(&ballast_dir, std::fs::Permissions::from_mode(0o000))
            .expect("chmod 000");

        let observed = BallastAvailability::observe(&ballast_dir, &config);

        // Restore before asserting so a failure can't leave an undeletable dir.
        let _ = std::fs::set_permissions(&ballast_dir, std::fs::Permissions::from_mode(0o755));

        // Running as root defeats the permission check entirely; skip there.
        if observed.unreadable_count == 0 {
            println!("TEST SKIP: running as root, permissions not enforced");
            return;
        }

        assert_eq!(
            observed.unreadable_count, config.file_count,
            "every unstat-able file must count as unreadable"
        );
        assert_eq!(
            observed.missing_count, 0,
            "permission denied must never be reported as a missing reserve"
        );
        assert_eq!(observed.health, BallastHealth::Indeterminate);
        assert!(!observed.is_authoritative());
        println!("TEST PASS: observe_reports_indeterminate_when_dir_is_unreadable");
    }

    /// A genuinely absent pool must still report `Empty`, not `Indeterminate` —
    /// the fix must not mask the real "reserve is gone" alarm.
    #[test]
    fn observe_still_reports_empty_when_files_are_truly_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ballast_dir = dir.path().join("ballast");
        std::fs::create_dir_all(&ballast_dir).expect("create ballast dir");

        let config = small_config();
        let observed = BallastAvailability::observe(&ballast_dir, &config);

        assert_eq!(observed.available_count, 0);
        assert_eq!(observed.missing_count, config.file_count);
        assert_eq!(observed.unreadable_count, 0);
        assert!(observed.is_authoritative());
        assert_eq!(observed.health, BallastHealth::Empty);
        println!("TEST PASS: observe_still_reports_empty_when_files_are_truly_absent");
    }

    use crate::platform::pal::{MockPlatform, Platform};
    use crate::platform::types::LocalSnapshotInfo;
    use crate::platform::types::PalError;

    fn small_config() -> BallastConfig {
        BallastConfig {
            file_count: 3,
            file_size_bytes: HEADER_SIZE as u64 + 8192, // header + 8KB data
            replenish_cooldown_minutes: 0,
            auto_provision: true,
            overrides: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn provision_creates_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), small_config()).unwrap();
        let report = mgr.provision(None).unwrap();

        assert_eq!(report.files_created, 3);
        assert_eq!(report.files_skipped, 0);
        assert!(report.errors.is_empty());
        assert_eq!(mgr.inventory().len(), 3);

        // Verify files exist with correct size.
        for i in 1..=3 {
            let path = dir.path().join(format!("SBH_BALLAST_FILE_{i:05}.dat"));
            assert!(path.exists());
            assert_eq!(
                fs::metadata(&path).unwrap().len(),
                small_config().file_size_bytes
            );
        }
    }

    #[test]
    fn provision_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), small_config()).unwrap();

        let r1 = mgr.provision(None).unwrap();
        assert_eq!(r1.files_created, 3);

        let r2 = mgr.provision(None).unwrap();
        assert_eq!(r2.files_created, 0);
        assert_eq!(r2.files_skipped, 3);
    }

    #[test]
    fn verify_detects_good_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), small_config()).unwrap();
        mgr.provision(None).unwrap();

        let report = mgr.verify().unwrap();
        assert_eq!(report.files_checked, 3);
        assert_eq!(report.files_ok, 3);
        assert_eq!(report.files_corrupted, 0);
        assert_eq!(report.files_missing, 0);
    }

    #[test]
    fn verify_detects_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), small_config()).unwrap();
        // Don't provision — all files are missing.

        let report = mgr.verify().unwrap();
        assert_eq!(report.files_missing, 3);
    }

    #[test]
    fn verify_detects_corrupted_header() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), small_config()).unwrap();
        mgr.provision(None).unwrap();

        // Corrupt file 2's header.
        let path = dir.path().join("SBH_BALLAST_FILE_00002.dat");
        let mut data = fs::read(&path).unwrap();
        data[0..5].copy_from_slice(b"JUNK!");
        fs::write(&path, &data).unwrap();

        let report = mgr.verify().unwrap();
        assert_eq!(report.files_ok, 2);
        assert_eq!(report.files_corrupted, 1);
    }

    #[test]
    fn verify_detects_sparse_or_underallocated_file() {
        let dir = tempfile::tempdir().unwrap();
        let config = small_config();
        let expected_blocks = config.file_size_bytes.div_ceil(512);
        let platform = MockPlatform::healthy()
            .with_block_count(
                dir.path().join("SBH_BALLAST_FILE_00001.dat"),
                expected_blocks.saturating_sub(1),
            )
            .with_block_count(
                dir.path().join("SBH_BALLAST_FILE_00002.dat"),
                expected_blocks,
            )
            .with_block_count(
                dir.path().join("SBH_BALLAST_FILE_00003.dat"),
                expected_blocks,
            );
        let mut mgr =
            BallastManager::with_platform(dir.path().to_path_buf(), config, Arc::new(platform))
                .unwrap();
        mgr.provision(None).unwrap();

        let report = mgr.verify().unwrap();
        assert_eq!(report.files_ok, 2);
        assert_eq!(report.files_corrupted, 1);
        assert!(
            report
                .details
                .iter()
                .any(|detail| detail.contains("allocated bytes mismatch")),
            "sparse ballast file should fail allocated-block verification: {:?}",
            report.details
        );
    }

    #[test]
    fn provisioned_files_have_allocated_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), small_config()).unwrap();
        mgr.provision(None).unwrap();
        let platform = crate::platform::current();

        for i in 1..=3 {
            let path = dir.path().join(format!("SBH_BALLAST_FILE_{i:05}.dat"));
            let allocated_bytes = platform.file_block_count(&path).unwrap() * 512;
            assert!(
                allocated_bytes >= small_config().file_size_bytes,
                "{} allocated {allocated_bytes} bytes, expected at least {}",
                path.display(),
                small_config().file_size_bytes
            );
        }
    }

    #[test]
    fn release_deletes_highest_index_first() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), small_config()).unwrap();
        mgr.provision(None).unwrap();

        let report = mgr.release(2).unwrap();
        assert_eq!(report.files_released, 2);
        assert_eq!(report.bytes_freed, 2 * small_config().file_size_bytes);

        // File 1 should remain, files 2 and 3 should be gone.
        assert!(dir.path().join("SBH_BALLAST_FILE_00001.dat").exists());
        assert!(!dir.path().join("SBH_BALLAST_FILE_00002.dat").exists());
        assert!(!dir.path().join("SBH_BALLAST_FILE_00003.dat").exists());

        assert_eq!(mgr.inventory().len(), 1);
        assert_eq!(mgr.available_count(), 1);
    }

    #[test]
    fn release_warns_when_time_machine_local_snapshots_exist() {
        let dir = tempfile::tempdir().unwrap();
        let platform = MockPlatform::healthy()
            .with_name("macos")
            .with_local_time_machine_snapshots(
                PathBuf::from("/"),
                vec![LocalSnapshotInfo {
                    name: "com.apple.TimeMachine.2026-05-07-010203.local".to_string(),
                    date: Some("2026-05-07-010203".to_string()),
                    retained_bytes_estimate: Some(64),
                    mount_path: PathBuf::from("/"),
                }],
            );
        let mut mgr = BallastManager::with_platform(
            dir.path().to_path_buf(),
            small_config(),
            Arc::new(platform),
        )
        .unwrap();
        mgr.provision(None).unwrap();

        let report = mgr.release(1).unwrap();

        assert_eq!(report.files_released, 1);
        assert_eq!(report.warnings.len(), 1);
        assert!(report.warnings[0].contains("1 Time Machine local snapshot is present on /"));
        assert!(report.warnings[0].contains("Estimated retained bytes: 64"));
        assert!(report.warnings[0].contains("sudo tmutil thinlocalsnapshots / 9999999999999999 4"));
    }

    #[test]
    fn replenish_recreates_released_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), small_config()).unwrap();
        mgr.provision(None).unwrap();
        mgr.release(2).unwrap();
        assert_eq!(mgr.available_count(), 1);

        let report = mgr.replenish(None).unwrap();
        assert_eq!(report.files_created, 2);
        assert_eq!(mgr.available_count(), 3);
    }

    #[test]
    fn releasable_bytes_computed_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let config = small_config();
        let expected = config.file_size_bytes * 3;
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), config).unwrap();
        mgr.provision(None).unwrap();

        assert_eq!(mgr.releasable_bytes(), expected);

        mgr.release(1).unwrap();
        assert_eq!(
            mgr.releasable_bytes(),
            expected - small_config().file_size_bytes
        );
    }

    #[test]
    fn provision_aborts_when_free_space_low() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), small_config()).unwrap();

        // Simulate always-low free space.
        let report = mgr.provision(Some(&|| 5.0)).unwrap();
        assert_eq!(report.files_created, 0);
        assert!(!report.errors.is_empty());
    }

    #[test]
    fn provision_stops_gracefully_when_storage_is_full() {
        let dir = tempfile::tempdir().unwrap();
        let first_ballast = dir.path().join("SBH_BALLAST_FILE_00001.dat");
        let second_ballast = dir.path().join("SBH_BALLAST_FILE_00002.dat");
        let platform = MockPlatform::healthy().with_preallocate_failure(
            first_ballast.clone(),
            PalError::method_failed(
                "macos",
                "preallocate_file",
                "No space left on device (os error 28)",
            ),
        );
        let mut mgr = BallastManager::with_platform(
            dir.path().to_path_buf(),
            small_config(),
            Arc::new(platform),
        )
        .unwrap();

        let report = mgr.provision(None).unwrap();

        assert_eq!(report.files_created, 0);
        assert_eq!(report.errors.len(), 1);
        assert!(report.errors[0].contains("storage exhausted"));
        assert!(report.errors[0].contains("sbh ballast replenish"));
        assert!(
            !first_ballast.exists(),
            "partial ballast file should not remain after storage exhaustion"
        );
        assert!(
            !second_ballast.exists(),
            "provisioning should stop after storage exhaustion instead of hammering the volume"
        );
        assert_eq!(mgr.available_count(), 0);
    }

    #[test]
    fn full_lifecycle_provision_verify_release_replenish() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), small_config()).unwrap();

        // 1. Provision
        let p = mgr.provision(None).unwrap();
        assert_eq!(p.files_created, 3);

        // 2. Verify
        let v = mgr.verify().unwrap();
        assert_eq!(v.files_ok, 3);

        // 3. Release 2
        let r = mgr.release(2).unwrap();
        assert_eq!(r.files_released, 2);
        assert_eq!(mgr.available_count(), 1);

        // 4. Verify again (2 missing now)
        let v2 = mgr.verify().unwrap();
        assert_eq!(v2.files_ok, 1);
        assert_eq!(v2.files_missing, 2);

        // 5. Replenish
        let rep = mgr.replenish(None).unwrap();
        assert_eq!(rep.files_created, 2);

        // 6. Final verify
        let v3 = mgr.verify().unwrap();
        assert_eq!(v3.files_ok, 3);
    }

    #[test]
    fn header_roundtrip() {
        let header = BallastHeader::new(7, 1_073_741_824);
        let json = serde_json::to_string(&header).unwrap();
        let parsed: BallastHeader = serde_json::from_str(&json).unwrap();
        assert!(parsed.validate());
        assert_eq!(parsed.file_index, 7);
        assert_eq!(parsed.file_size, 1_073_741_824);
    }

    #[test]
    #[cfg(unix)]
    fn ballast_files_have_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), small_config()).unwrap();
        mgr.provision(None).unwrap();

        let path = dir.path().join("SBH_BALLAST_FILE_00001.dat");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "ballast file should be owner-only (0o600)");
    }

    #[test]
    fn reducing_file_count_removes_orphans() {
        let dir = tempfile::tempdir().unwrap();
        // Start with 5 files
        let mut config = small_config();
        config.file_count = 5;
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), config.clone()).unwrap();
        mgr.provision(None).unwrap();

        assert_eq!(mgr.available_count(), 5);
        for i in 1..=5 {
            assert!(
                dir.path()
                    .join(format!("SBH_BALLAST_FILE_{i:05}.dat"))
                    .exists()
            );
        }

        // Reduce to 3 files
        config.file_count = 3;
        mgr.update_config(config);

        // Inventory should show 3
        assert_eq!(mgr.available_count(), 3);

        // Files 4 and 5 should be gone
        assert!(
            !dir.path().join("SBH_BALLAST_FILE_00004.dat").exists(),
            "Orphaned file 4 should be removed"
        );
        assert!(
            !dir.path().join("SBH_BALLAST_FILE_00005.dat").exists(),
            "Orphaned file 5 should be removed"
        );
    }

    // ──── #16: health / availability ────

    #[test]
    fn ballast_health_evaluate_covers_all_states() {
        assert_eq!(BallastHealth::evaluate(0, 0), BallastHealth::Unconfigured);
        // Unconfigured wins even if stray bytes exist on disk.
        assert_eq!(BallastHealth::evaluate(0, 100), BallastHealth::Unconfigured);
        // Configured reserve with zero releasable bytes is the fail-loud state.
        assert_eq!(BallastHealth::evaluate(1000, 0), BallastHealth::Empty);
        assert_eq!(BallastHealth::evaluate(1000, 999), BallastHealth::Degraded);
        assert_eq!(BallastHealth::evaluate(1000, 1000), BallastHealth::Ok);
        // Over-provisioned (e.g. larger files than configured) still reads Ok.
        assert_eq!(BallastHealth::evaluate(1000, 1001), BallastHealth::Ok);
    }

    #[test]
    fn ballast_health_labels_are_stable() {
        assert_eq!(BallastHealth::Unconfigured.as_str(), "unconfigured");
        assert_eq!(BallastHealth::Ok.as_str(), "ok");
        assert_eq!(BallastHealth::Degraded.as_str(), "degraded");
        assert_eq!(BallastHealth::Empty.as_str(), "empty");
        assert_eq!(BallastHealth::Empty.to_string(), "empty");
    }

    #[test]
    fn availability_observe_reports_full_pool_and_never_mutates() {
        let dir = tempfile::tempdir().unwrap();
        let config = small_config();
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), config.clone()).unwrap();
        mgr.provision(None).unwrap();

        let availability = BallastAvailability::observe(dir.path(), &config);
        assert_eq!(availability.configured_count, 3);
        assert_eq!(availability.available_count, 3);
        assert_eq!(availability.missing_count, 0);
        assert_eq!(
            availability.releasable_bytes,
            3 * config.file_size_bytes,
            "releasable bytes should sum all present files"
        );
        assert_eq!(availability.health, BallastHealth::Ok);
        assert_eq!(mgr.health(), BallastHealth::Ok);
    }

    #[test]
    fn availability_observe_flags_empty_reserve_after_release() {
        let dir = tempfile::tempdir().unwrap();
        let config = small_config();
        let mut mgr = BallastManager::new(dir.path().to_path_buf(), config.clone()).unwrap();
        mgr.provision(None).unwrap();

        // Release one file → degraded.
        mgr.release(1).unwrap();
        let availability = BallastAvailability::observe(dir.path(), &config);
        assert_eq!(availability.available_count, 2);
        assert_eq!(availability.missing_count, 1);
        assert_eq!(availability.health, BallastHealth::Degraded);
        assert_eq!(mgr.health(), BallastHealth::Degraded);

        // Release the rest → configured-but-empty, the false-green trap (#16).
        mgr.release(2).unwrap();
        let availability = BallastAvailability::observe(dir.path(), &config);
        assert_eq!(availability.available_count, 0);
        assert_eq!(availability.missing_count, 3);
        assert_eq!(availability.releasable_bytes, 0);
        assert_eq!(availability.health, BallastHealth::Empty);
        assert_eq!(mgr.health(), BallastHealth::Empty);
    }

    #[test]
    fn availability_observe_missing_directory_is_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let pool_dir = dir.path().join("does-not-exist");
        let config = small_config();

        let availability = BallastAvailability::observe(&pool_dir, &config);
        assert_eq!(availability.available_count, 0);
        assert_eq!(availability.health, BallastHealth::Empty);
        // Observation must not create the pool directory.
        assert!(!pool_dir.exists(), "observe must never create directories");
    }

    #[test]
    fn availability_observe_unconfigured_pool() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = small_config();
        config.file_count = 0;
        let availability = BallastAvailability::observe(dir.path(), &config);
        assert_eq!(availability.configured_pool_bytes, 0);
        assert_eq!(availability.health, BallastHealth::Unconfigured);
    }
}
