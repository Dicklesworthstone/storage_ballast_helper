//! Ballast file manager: create/verify/reclaim pre-allocated sacrificial space files.
//!
//! Ballast files are named `SBH_BALLAST_FILE_NNNNN.dat` and contain a 4096-byte
//! JSON header followed by random data. On ext4/xfs, provisioning uses `fallocate()`
//! for instant allocation; on CoW filesystems (btrfs, zfs), random data is written
//! in 4 MB chunks to defeat deduplication.
//!
//! Access to the ballast directory is serialized via `flock()` on a lockfile so
//! concurrent daemon + CLI operations don't race.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]

use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;

use crate::core::config::BallastConfig;
use crate::core::errors::{Result, SbhError};

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
    pub errors: Vec<String>,
}

// ──────────────────── manager ────────────────────

/// Manages the lifecycle of ballast files: creation, verification, release, replenishment.
pub struct BallastManager {
    ballast_dir: PathBuf,
    config: BallastConfig,
    inventory: Vec<BallastFile>,
}

impl BallastManager {
    /// Create a new manager for the given directory and configuration.
    pub fn new(ballast_dir: PathBuf, config: BallastConfig) -> Result<Self> {
        fs::create_dir_all(&ballast_dir).map_err(|e| SbhError::io(&ballast_dir, e))?;

        let mut mgr = Self {
            ballast_dir,
            config,
            inventory: Vec::new(),
        };
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

    // ──────────────────── locking ────────────────────

    #[cfg(unix)]
    fn acquire_lock(&self) -> Result<File> {
        let lock_path = self.ballast_dir.join(".lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|e| SbhError::io(&lock_path, e))?;

        nix::fcntl::flock(file.as_raw_fd(), nix::fcntl::FlockArg::LockExclusive)
            .map_err(|e| SbhError::Runtime {
                details: format!("failed to lock ballast dir: {e}"),
            })?;

        Ok(file)
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
                    let actual_size = fs::metadata(&path)
                        .map(|m| m.len())
                        .unwrap_or(self.config.file_size_bytes);
                    report.total_bytes += actual_size;
                }
                Err(e) => {
                    report.errors.push(format!("file {index}: {e}"));
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
            errors: Vec::new(),
        };

        // Collect indices of available files in descending order.
        let mut available: Vec<u32> = self.inventory.iter().map(|f| f.index).collect();
        available.sort_unstable_by(|a, b| b.cmp(a));

        for &index in available.iter().take(count) {
            let path = self.file_path(index);
            let actual_size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
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

        self.scan_existing();
        Ok(report)
    }

    // ──────────────────── verify ────────────────────

    /// Verify integrity of all expected ballast files.
    pub fn verify(&mut self) -> Result<VerifyReport> {
        let _lock = self.acquire_lock()?;
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
                    let actual_size = fs::metadata(&path)
                        .map(|m| m.len())
                        .unwrap_or(self.config.file_size_bytes);
                    report.total_bytes += actual_size;
                    // Only create one file per call.
                    break;
                }
                Err(e) => {
                    report.errors.push(format!("file {index}: {e}"));
                }
            }
        }

        self.scan_existing();
        Ok(report)
    }

    // ──────────────────── internal ────────────────────

    fn file_path(&self, index: u32) -> PathBuf {
        self.ballast_dir
            .join(format!("SBH_BALLAST_FILE_{index:05}.dat"))
    }

    fn scan_existing(&mut self) {
        self.inventory.clear();
        for i in 1..=self.config.file_count {
            let index = i as u32;
            let path = self.file_path(index);
            if path.exists() {
                let integrity_ok = self.verify_single_file(&path, index).is_ok();
                let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
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
        let mut file = {
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                opts.mode(0o600);
            }
            opts.open(path).map_err(|e| SbhError::io(path, e))?
        };

        // Write header (4096 bytes, null-padded).
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
        file.write_all(&header_buf)
            .map_err(|e| SbhError::io(path, e))?;

        // Write data portion.
        let data_size = size - HEADER_SIZE as u64;

        // Try fallocate CLI first (instant on ext4/xfs, no unsafe needed).
        #[cfg(target_os = "linux")]
        {
            if try_fallocate_cli(path, size) {
                file.sync_all().map_err(|e| SbhError::io(path, e))?;
                return Ok(());
            }
        }

        // Fallback: write random data in chunks (works on all FS including CoW).
        self.write_random_data(&mut file, data_size, path)?;

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

// ──────────────────── fallocate (Linux) ────────────────────

/// Try to use the `fallocate` CLI tool for instant block allocation on ext4/xfs.
///
/// Falls back to random data writing if the command is not available or fails
/// (e.g., on CoW filesystems like btrfs/zfs where fallocate doesn't prevent dedup).
///
/// Only extends the file from the current position (after header) to total_size,
/// so we pass `total_size - HEADER_SIZE` as the length.
#[cfg(target_os = "linux")]
fn try_fallocate_cli(path: &Path, total_size: u64) -> bool {
    use std::process::Command;
    // Guard: total_size must be larger than the header we already wrote.
    let remaining = match total_size.checked_sub(HEADER_SIZE as u64) {
        Some(r) if r > 0 => r,
        _ => return false,
    };
    // fallocate -o OFFSET -l LENGTH PATH — extend the file past the header.
    Command::new("fallocate")
        .arg("-o")
        .arg(HEADER_SIZE.to_string())
        .arg("-l")
        .arg(remaining.to_string())
        .arg(path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
}
