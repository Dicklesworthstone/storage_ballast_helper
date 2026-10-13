//! Publish complete, collision-resistant rollback snapshots.

#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest as _, Sha256};

use crate::core::hex_lower;

use super::BackupSnapshot;

pub(super) fn create(
    store: &Path,
    install_path: &Path,
    version: &str,
) -> Result<BackupSnapshot, String> {
    fs::create_dir_all(store).map_err(|error| format!("failed to create backup dir: {error}"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let (id, entry) = allocate_entry(store, now)?;
    let result = write_snapshot(&entry, install_path, version, &id, now.as_secs());
    if result.is_err() {
        // This directory was created exclusively by this invocation. Never
        // remove a pre-existing snapshot when a new backup fails.
        let _ = fs::remove_dir_all(&entry);
    }
    result
}

/// Verify that a published snapshot still matches the digest recorded when it
/// was created. Rollback refuses legacy or corrupted snapshots before staging
/// can replace the currently working installation.
pub(super) fn verify_staged(snapshot: &BackupSnapshot, candidate: &Path) -> Result<(), String> {
    let entry = snapshot
        .path
        .parent()
        .ok_or_else(|| "backup snapshot has no parent directory".to_string())?;
    let metadata_path = entry.join("backup.json");
    let encoded = fs::read(&metadata_path)
        .map_err(|error| format!("failed to read backup metadata: {error}"))?;
    let metadata: serde_json::Value = serde_json::from_slice(&encoded)
        .map_err(|error| format!("failed to decode backup metadata: {error}"))?;
    let expected_size = metadata
        .get("binary_size")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "backup metadata is missing binary_size".to_string())?;
    let expected_sha256 = metadata
        .get("sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            "backup metadata is missing sha256; refusing an unverifiable rollback snapshot"
                .to_string()
        })?;

    let raw = fs::symlink_metadata(candidate)
        .map_err(|error| format!("failed to inspect staged rollback binary: {error}"))?;
    if !raw.is_file() {
        return Err(format!(
            "staged rollback binary is not a regular file: {}",
            candidate.display()
        ));
    }
    if raw.len() != expected_size {
        return Err(format!(
            "backup binary size mismatch: expected {expected_size} bytes, found {}",
            raw.len()
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut input = options
        .open(candidate)
        .map_err(|error| format!("failed to open staged rollback binary: {error}"))?;
    let opened = input
        .metadata()
        .map_err(|error| format!("failed to inspect open staged rollback binary: {error}"))?;
    if !opened.is_file() || opened.len() != expected_size {
        return Err("backup binary changed while validating rollback snapshot".to_string());
    }

    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut observed_size = 0u64;
    loop {
        let count = input
            .read(&mut buffer)
            .map_err(|error| format!("failed to read backup binary: {error}"))?;
        if count == 0 {
            break;
        }
        observed_size = observed_size
            .checked_add(u64::try_from(count).map_err(|_| "backup size overflow".to_string())?)
            .ok_or_else(|| "backup size overflow".to_string())?;
        hasher.update(&buffer[..count]);
    }
    if observed_size != expected_size {
        return Err(format!(
            "backup binary size changed during verification: expected {expected_size} bytes, read {observed_size}"
        ));
    }
    let observed_sha256 = hex_lower(hasher.finalize());
    if observed_sha256 != expected_sha256 {
        return Err(format!(
            "backup binary SHA-256 mismatch for snapshot {}",
            snapshot.id
        ));
    }
    Ok(())
}

fn allocate_entry(store: &Path, now: Duration) -> Result<(String, PathBuf), String> {
    for _ in 0..32 {
        let id = format!(
            "{}-{:09}-{:032x}",
            now.as_secs(),
            now.subsec_nanos(),
            rand::random::<u128>()
        );
        let entry = store.join(&id);
        #[cfg(unix)]
        let created = {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(&entry)
        };
        #[cfg(not(unix))]
        let created = fs::create_dir(&entry);
        match created {
            Ok(()) => return Ok((id, entry)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("failed to create backup entry: {error}")),
        }
    }
    Err("failed to allocate a unique backup entry after 32 attempts".to_string())
}

fn write_snapshot(
    entry: &Path,
    install_path: &Path,
    version: &str,
    id: &str,
    timestamp: u64,
) -> Result<BackupSnapshot, String> {
    // An installed command may legitimately be a symlink; follow it, but never
    // accept a directory/device/FIFO as the backup's executable contents.
    let metadata = fs::metadata(install_path)
        .map_err(|error| format!("failed to inspect binary for backup: {error}"))?;
    if !metadata.is_file() {
        return Err("backup source is not a regular file".to_string());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let mut input = options
        .open(install_path)
        .map_err(|error| format!("failed to open binary for backup: {error}"))?;
    if !input
        .metadata()
        .map_err(|error| format!("failed to inspect open backup source: {error}"))?
        .is_file()
    {
        return Err("open backup source is not a regular file".to_string());
    }
    let partial = entry.join("sbh.partial");
    let binary = entry.join("sbh");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|error| format!("failed to create partial backup: {error}"))?;
    let mut hasher = Sha256::new();
    let mut binary_size = 0u64;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let count = input
            .read(&mut buffer)
            .map_err(|error| format!("failed to read binary for backup: {error}"))?;
        if count == 0 {
            break;
        }
        output
            .write_all(&buffer[..count])
            .map_err(|error| format!("failed to copy binary for backup: {error}"))?;
        binary_size = binary_size
            .checked_add(u64::try_from(count).map_err(|_| "backup size overflow".to_string())?)
            .ok_or_else(|| "backup size overflow".to_string())?;
        hasher.update(&buffer[..count]);
    }
    let sha256 = hex_lower(hasher.finalize());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        output
            .set_permissions(fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("failed to set backup permissions: {error}"))?;
    }
    output
        .sync_all()
        .map_err(|error| format!("failed to sync backup binary: {error}"))?;
    drop(output);
    drop(input);

    let meta = serde_json::json!({
        "version": version,
        "timestamp": timestamp,
        "binary_size": binary_size,
        "sha256": sha256,
    });
    let encoded = serde_json::to_vec_pretty(&meta)
        .map_err(|error| format!("failed to encode backup metadata: {error}"))?;
    let mut metadata_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(entry.join("backup.json"))
        .map_err(|error| format!("failed to create backup metadata: {error}"))?;
    metadata_file
        .write_all(&encoded)
        .and_then(|()| metadata_file.sync_all())
        .map_err(|error| format!("failed to persist backup metadata: {error}"))?;
    drop(metadata_file);

    // Inventory ignores entries without `sbh`. This is the publication point:
    // neither a short binary nor metadata-less new snapshot can be selected.
    fs::rename(&partial, &binary)
        .map_err(|error| format!("failed to publish backup binary: {error}"))?;
    #[cfg(unix)]
    {
        File::open(entry)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("failed to sync backup entry: {error}"))?;
        if let Some(parent) = entry.parent() {
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("failed to sync backup store: {error}"))?;
        }
    }
    Ok(BackupSnapshot {
        id: id.to_string(),
        version: version.to_string(),
        timestamp,
        path: binary,
        binary_size,
    })
}
