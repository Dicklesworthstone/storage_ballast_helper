//! Bounded, atomic persistence for optional process-attribution history.
//!
//! An invalid cache must not block daemon startup or allocate according to
//! untrusted sequence lengths. A failed refresh must leave the old cache
//! intact. The v1 bincode wire format is unchanged.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::path::Path;

use serde::de::{self, DeserializeOwned, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use super::{
    DEFAULT_MAX_PIDS, MAX_SAMPLES_PER_PROCESS, ProcessIoHistoryEntry, ProcessIoSample,
};
use crate::core::errors::{Result, SbhError};

const MAX_BYTES: usize = 16 * 1024 * 1024;

// Limit decoded collection sizes before allocation, not after decoding an
// attacker-controlled Vec. The byte limit alone is not a schema shape bound.
fn bounded_vec<'de, D, T, const LIMIT: usize>(
    deserializer: D,
) -> std::result::Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVec<T, const LIMIT: usize>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>, const LIMIT: usize> Visitor<'de> for BoundedVec<T, LIMIT> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {LIMIT} history values")
        }

        fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence.size_hint().is_some_and(|size| size > LIMIT) {
                return Err(de::Error::custom("history sequence exceeds its limit"));
            }
            let mut values = Vec::new();
            while let Some(value) = sequence.next_element()? {
                if values.len() == LIMIT {
                    return Err(de::Error::custom("history sequence exceeds its limit"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(BoundedVec::<T, LIMIT>(PhantomData))
}

pub(super) fn deserialize_entries<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<ProcessIoHistoryEntry>, D::Error>
where
    D: Deserializer<'de>,
{
    bounded_vec::<D, ProcessIoHistoryEntry, DEFAULT_MAX_PIDS>(deserializer)
}

pub(super) fn deserialize_samples<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<ProcessIoSample>, D::Error>
where
    D: Deserializer<'de>,
{
    bounded_vec::<D, ProcessIoSample, MAX_SAMPLES_PER_PROCESS>(deserializer)
}

pub(super) fn read<T: DeserializeOwned>(path: &Path) -> Option<T> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A replaced FIFO must not hang startup; a symlink is not our cache.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES as u64 {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > MAX_BYTES {
        return None;
    }
    let (value, consumed) = bincode::serde::decode_from_slice::<T, _>(
        &bytes,
        bincode::config::standard().with_limit::<MAX_BYTES>(),
    )
    .ok()?;
    (consumed == bytes.len()).then_some(value)
}

pub(super) fn write<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = bincode::serde::encode_to_vec(value, bincode::config::standard()).map_err(|error| {
        SbhError::Serialization {
            context: "bincode",
            details: error.to_string(),
        }
    })?;
    if bytes.len() > MAX_BYTES {
        return Err(SbhError::Serialization {
            context: "bincode",
            details: "process I/O history exceeds its snapshot size limit".to_string(),
        });
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| SbhError::io(parent, error))?;
    let temporary = path.with_extension(format!(
        "{}-{}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    // Do not remove anything if exclusive creation fails: that path is not
    // ours. Readers continue to see the old snapshot while this one is staged.
    let mut file = options
        .open(&temporary)
        .map_err(|error| SbhError::io(&temporary, error))?;
    let staged = file.write_all(&bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = staged {
        let _ = fs::remove_file(&temporary);
        return Err(SbhError::io(&temporary, error));
    }
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(SbhError::io(path, error));
    }
    #[cfg(unix)]
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| SbhError::io(parent, error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::process_io_history::{ProcessIoHistorySnapshot, SNAPSHOT_VERSION};

    #[test]
    fn round_trip_keeps_the_existing_bincode_wire_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history");
        let value = vec![1_u64, 250, 1 << 32];
        write(&path, &value).unwrap();
        assert_eq!(
            fs::read(&path).unwrap(),
            bincode::serde::encode_to_vec(&value, bincode::config::standard()).unwrap()
        );
        assert_eq!(read::<Vec<u64>>(&path), Some(value));
    }

    #[test]
    fn serialization_failure_preserves_the_previous_snapshot() {
        struct CannotSerialize;
        impl Serialize for CannotSerialize {
            fn serialize<S>(&self, _serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                Err(serde::ser::Error::custom("injected serialization failure"))
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history");
        write(&path, &42_u64).unwrap();
        assert!(write(&path, &CannotSerialize).is_err());
        assert_eq!(read::<u64>(&path), Some(42));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn failed_publication_cleans_only_its_staging_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("keep"), b"original").unwrap();
        assert!(write(&path, &42_u64).is_err());
        assert_eq!(fs::read(path.join("keep")).unwrap(), b"original");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn oversized_and_nonregular_snapshots_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversized");
        File::create(&path)
            .unwrap()
            .set_len(MAX_BYTES as u64 + 1)
            .unwrap();
        assert!(read::<u64>(&path).is_none());
        assert!(read::<u64>(dir.path()).is_none());
    }

    #[test]
    fn truncated_and_trailing_payloads_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history");
        let bytes = bincode::serde::encode_to_vec(&vec![1_u64, 2, 3], bincode::config::standard())
            .unwrap();
        fs::write(&path, &bytes[..bytes.len() - 1]).unwrap();
        assert!(read::<Vec<u64>>(&path).is_none());
        let mut trailing = bytes;
        trailing.push(0);
        fs::write(&path, trailing).unwrap();
        assert!(read::<Vec<u64>>(&path).is_none());
    }

    #[test]
    fn forged_collection_lengths_are_rejected_before_allocating_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history");
        // The tuple has exactly the wire prefix of a snapshot, but claims an
        // enormous entries vector without supplying any entries.
        let bytes = bincode::serde::encode_to_vec(
            &(SNAPSHOT_VERSION, 0_i64, u64::MAX),
            bincode::config::standard(),
        )
        .unwrap();
        fs::write(&path, bytes).unwrap();
        assert!(read::<ProcessIoHistorySnapshot>(&path).is_none());
        let bytes = bincode::serde::encode_to_vec(
            &(42_i32, Some(0_i64), u64::MAX),
            bincode::config::standard(),
        )
        .unwrap();
        fs::write(&path, bytes).unwrap();
        assert!(read::<ProcessIoHistoryEntry>(&path).is_none());
    }

    #[test]
    fn the_sample_shape_limit_accepts_its_boundary_and_rejects_excess() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history");
        let mut entry = ProcessIoHistoryEntry {
            pid: 42,
            start_time_unix_ms: Some(0),
            samples: vec![
                ProcessIoSample {
                    collected_at_unix_ms: 1_000,
                    bytes_read_total: 1,
                    bytes_written_total: 2,
                };
                MAX_SAMPLES_PER_PROCESS
            ],
        };
        write(&path, &entry).unwrap();
        assert_eq!(read::<ProcessIoHistoryEntry>(&path), Some(entry.clone()));
        entry.samples.push(entry.samples[0].clone());
        write(&path, &entry).unwrap();
        assert!(read::<ProcessIoHistoryEntry>(&path).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_and_fifos_cannot_redirect_or_block_snapshot_reads() {
        use nix::sys::stat::Mode;
        use nix::unistd::mkfifo;
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("original");
        write(&original, &42_u64).unwrap();
        let link = dir.path().join("link");
        symlink(&original, &link).unwrap();
        assert!(read::<u64>(&link).is_none());
        let fifo = dir.path().join("fifo");
        mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
        assert!(read::<u64>(&fifo).is_none());
        assert_eq!(read::<u64>(&original), Some(42));
    }

    #[cfg(unix)]
    #[test]
    fn publication_replaces_a_symlink_without_modifying_its_target() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, b"keep").unwrap();
        let path = dir.path().join("history");
        symlink(&victim, &path).unwrap();
        write(&path, &42_u64).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        assert!(fs::symlink_metadata(&path).unwrap().is_file());
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o077, 0);
        assert_eq!(read::<u64>(&path), Some(42));
    }
}
