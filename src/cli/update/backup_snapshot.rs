//! Publish complete, collision-resistant rollback snapshots.

#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    let binary_size = io::copy(&mut input, &mut output)
        .map_err(|error| format!("failed to copy binary for backup: {error}"))?;
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
