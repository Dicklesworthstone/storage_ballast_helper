//! Byte-preserving, bounded and crash-consistent pre-scan continuation storage.
//!
//! Checkpoints are discovery hints, not deletion authority. Invalid input starts
//! discovery over. A failed save before publication keeps the previous checkpoint.
//! Unix publication is relative to the opened state directory, so replacing its
//! pathname cannot redirect writes or staging-file cleanup to another directory.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::PrescanCursor;

const VERSION: u32 = 1;
const MAX_CHECKPOINT_BYTES: usize = 4 * 1024 * 1024;
const MAX_ROOTS: usize = 8192;
const MAX_PATH_BYTES: usize = 16 * 1024;
const MAX_RAW_PATH_BYTES: usize = 512 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u32,
    progress: Progress,
    checksum: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Progress {
    root: Option<StoredPath>,
    after: Option<StoredPath>,
    // JSON object keys cannot represent arbitrary Unix names. An ordered
    // sequence preserves both roots and resume points without lossy conversion.
    continuations: Vec<(StoredPath, StoredPath)>,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum StoredPath {
    Text(String),
    UnixBytes { unix_bytes: Vec<u8> },
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

impl StoredPath {
    fn encode(path: &Path) -> io::Result<Self> {
        if let Some(text) = path.to_str() {
            return Ok(Self::Text(text.to_owned()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            Ok(Self::UnixBytes {
                unix_bytes: path.as_os_str().as_bytes().to_vec(),
            })
        }
        #[cfg(not(unix))]
        {
            Err(invalid("pre-scan path cannot be represented on this platform"))
        }
    }

    fn decode(self) -> io::Result<PathBuf> {
        match self {
            Self::Text(text) => Ok(PathBuf::from(text)),
            Self::UnixBytes { unix_bytes } => {
                #[cfg(unix)]
                {
                    use std::os::unix::ffi::OsStringExt;
                    Ok(PathBuf::from(OsString::from_vec(unix_bytes)))
                }
                #[cfg(not(unix))]
                {
                    let _ = unix_bytes;
                    Err(invalid("Unix pre-scan path on a non-Unix platform"))
                }
            }
        }
    }
}

fn validate(cursor: &PrescanCursor) -> io::Result<()> {
    if cursor.continuations.len() > MAX_ROOTS {
        return Err(invalid("pre-scan continuation count exceeds the limit"));
    }
    if let Some(after) = &cursor.after
        && cursor
            .root
            .as_deref()
            .is_none_or(|root| !direct_child(root, after))
    {
        return Err(invalid("pre-scan resume point is not a root's direct child"));
    }
    if cursor
        .continuations
        .iter()
        .any(|(root, after)| !direct_child(root, after))
    {
        return Err(invalid("pre-scan continuation escapes its root"));
    }
    let mut raw_bytes = 0usize;
    for path in cursor.root.iter().chain(&cursor.after).chain(
        cursor
            .continuations
            .iter()
            .flat_map(|(root, after)| [root, after]),
    ) {
        let bytes = path.as_os_str().as_encoded_bytes();
        if bytes.is_empty() || bytes.len() > MAX_PATH_BYTES || bytes.contains(&0) {
            return Err(invalid("invalid or oversized pre-scan path"));
        }
        raw_bytes = raw_bytes
            .checked_add(bytes.len())
            .filter(|total| *total <= MAX_RAW_PATH_BYTES)
            .ok_or_else(|| invalid("pre-scan path storage exceeds the limit"))?;
    }
    Ok(())
}

fn direct_child(root: &Path, after: &Path) -> bool {
    after.parent() == Some(root)
        && after.file_name().is_some()
        && !after
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
}

impl Progress {
    fn from_cursor(cursor: &PrescanCursor) -> io::Result<Self> {
        validate(cursor)?;
        Ok(Self {
            root: cursor.root.as_deref().map(StoredPath::encode).transpose()?,
            after: cursor.after.as_deref().map(StoredPath::encode).transpose()?,
            continuations: cursor
                .continuations
                .iter()
                .map(|(root, after)| {
                    Ok((StoredPath::encode(root)?, StoredPath::encode(after)?))
                })
                .collect::<io::Result<_>>()?,
        })
    }

    fn into_cursor(self) -> io::Result<PrescanCursor> {
        if self.continuations.len() > MAX_ROOTS {
            return Err(invalid("pre-scan continuation count exceeds the limit"));
        }
        let mut continuations = BTreeMap::new();
        for (root, after) in self.continuations {
            if continuations
                .insert(root.decode()?, after.decode()?)
                .is_some()
            {
                return Err(invalid("duplicate pre-scan continuation root"));
            }
        }
        let cursor = PrescanCursor {
            root: self.root.map(StoredPath::decode).transpose()?,
            after: self.after.map(StoredPath::decode).transpose()?,
            continuations,
            ..PrescanCursor::default()
        };
        validate(&cursor)?;
        Ok(cursor)
    }
}

struct LimitedWriter<W> {
    inner: W,
    remaining: usize,
}

impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(invalid("pre-scan checkpoint exceeds the byte limit"));
        }
        let written = self.inner.write(bytes)?;
        self.remaining -= written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn encode(value: &impl Serialize) -> io::Result<Vec<u8>> {
    let mut writer = LimitedWriter {
        inner: Vec::new(),
        remaining: MAX_CHECKPOINT_BYTES,
    };
    serde_json::to_writer(&mut writer, value).map_err(io::Error::other)?;
    Ok(writer.inner)
}

fn checksum(progress: &Progress) -> io::Result<[u8; 32]> {
    let mut digest = Sha256::new();
    digest.update(VERSION.to_le_bytes());
    digest.update(encode(progress)?);
    Ok(digest.finalize().into())
}

fn decode(bytes: &[u8]) -> io::Result<PrescanCursor> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(io::Error::other)?;
    if value.get("version").is_some()
        || value.get("progress").is_some()
        || value.get("checksum").is_some()
    {
        // Never reinterpret a damaged/newer envelope as an empty legacy cursor.
        let checkpoint: Checkpoint = serde_json::from_value(value).map_err(io::Error::other)?;
        if checkpoint.version != VERSION || checksum(&checkpoint.progress)? != checkpoint.checksum {
            return Err(invalid("pre-scan checkpoint version or checksum mismatch"));
        }
        checkpoint.progress.into_cursor()
    } else {
        // Existing UTF-8 checkpoints keep working; the next save upgrades them.
        let cursor: PrescanCursor = serde_json::from_value(value).map_err(io::Error::other)?;
        validate(&cursor)?;
        Ok(cursor)
    }
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        left.file_type() == right.file_type() && left.created().ok() == right.created().ok()
    }
}

fn same_snapshot(left: &Metadata, right: &Metadata) -> bool {
    if !same_file(left, right)
        || left.len() != right.len()
        || left.modified().ok() != right.modified().ok()
    {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.ctime() == right.ctime() && left.ctime_nsec() == right.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn read_bounded(reader: impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(invalid("pre-scan checkpoint grew beyond the byte limit"));
    }
    Ok(bytes)
}

fn read(path: &Path) -> io::Result<PrescanCursor> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > MAX_CHECKPOINT_BYTES as u64 {
        return Err(invalid("pre-scan checkpoint is not a bounded regular file"));
    }
    let bytes = read_bounded(&file, MAX_CHECKPOINT_BYTES)?;
    if !same_snapshot(&before, &file.metadata()?) {
        return Err(invalid("pre-scan checkpoint changed while reading"));
    }
    decode(&bytes)
}

pub(super) fn load(path: &Path) -> PrescanCursor {
    read(path).unwrap_or_default()
}

// A directory descriptor anchors all publication and cleanup operations on
// Unix. Ancestors of the configured state directory may intentionally be
// aliases, but its final component must be a real directory when opened.
struct StagingFile {
    parent_path: PathBuf,
    parent: File,
    name: OsString,
    file: File,
    published: bool,
}

impl StagingFile {
    fn create(parent_path: &Path) -> io::Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let parent = options.open(parent_path)?;
        for _ in 0..16 {
            let name = OsString::from(format!(
                ".sbh-prescan-{}-{:016x}.tmp",
                std::process::id(),
                rand::random::<u64>(),
            ));
            #[cfg(unix)]
            let opened = {
                use rustix::fs::{Mode, OFlags, openat};
                openat(
                    &parent,
                    &name,
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::RUSR | Mode::WUSR,
                )
                .map(File::from)
                .map_err(io::Error::from)
            };
            #[cfg(not(unix))]
            let opened = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(parent_path.join(&name));
            match opened {
                Ok(file) => {
                    return Ok(Self {
                        parent_path: parent_path.to_path_buf(),
                        parent,
                        name,
                        file,
                        published: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "cannot reserve a private pre-scan checkpoint staging file",
        ))
    }

    fn still_bound(&self) -> io::Result<()> {
        let current = fs::symlink_metadata(&self.parent_path)?;
        if !current.is_dir() || !same_file(&self.parent.metadata()?, &current) {
            return Err(invalid("pre-scan state directory changed before publication"));
        }
        Ok(())
    }

    fn publish(mut self, filename: &std::ffi::OsStr) -> io::Result<()> {
        self.file.sync_all()?;
        self.still_bound()?;
        #[cfg(unix)]
        {
            use rustix::fs::{AtFlags, fstat, renameat, statat};
            let owned = fstat(&self.file)?;
            let named = statat(&self.parent, &self.name, AtFlags::SYMLINK_NOFOLLOW)?;
            if owned.st_dev != named.st_dev || owned.st_ino != named.st_ino {
                return Err(invalid("pre-scan staging file was replaced before publication"));
            }
            renameat(&self.parent, &self.name, &self.parent, filename)?;
        }
        #[cfg(not(unix))]
        {
            let source = self.parent_path.join(&self.name);
            if !same_file(&self.file.metadata()?, &fs::symlink_metadata(&source)?) {
                return Err(invalid("pre-scan staging file was replaced before publication"));
            }
            fs::rename(source, self.parent_path.join(filename))?;
        }
        self.published = true;
        // Failure here is reported, but the complete new file is already visible.
        self.parent.sync_all()
    }
}

impl Drop for StagingFile {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        #[cfg(unix)]
        {
            use rustix::fs::{AtFlags, fstat, statat, unlinkat};
            if let (Ok(owned), Ok(named)) = (
                fstat(&self.file),
                statat(&self.parent, &self.name, AtFlags::SYMLINK_NOFOLLOW),
            ) && owned.st_dev == named.st_dev
                && owned.st_ino == named.st_ino
            {
                let _ = unlinkat(&self.parent, &self.name, AtFlags::empty());
            }
        }
        #[cfg(not(unix))]
        if self.still_bound().is_ok() {
            let path = self.parent_path.join(&self.name);
            if let (Ok(owned), Ok(named)) = (self.file.metadata(), fs::symlink_metadata(&path))
                && same_file(&owned, &named)
            {
                let _ = fs::remove_file(path);
            }
        }
    }
}

pub(super) fn save(cursor: &PrescanCursor, path: &Path) -> io::Result<()> {
    let filename = path
        .file_name()
        .ok_or_else(|| invalid("checkpoint requires a filename"))?;
    let progress = Progress::from_cursor(cursor)?;
    let checkpoint = Checkpoint {
        version: VERSION,
        checksum: checksum(&progress)?,
        progress,
    };
    // Bound serialization and reject invalid progress BEFORE creating anything.
    let bytes = encode(&checkpoint)?;
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut staging = StagingFile::create(parent)?;
    #[cfg(unix)]
    {
        // Persist newly created ancestor links as well as the final rename.
        // This is checkpoint I/O, never a per-entry scanner operation.
        let absolute = fs::canonicalize(parent)?;
        for ancestor in absolute.ancestors() {
            File::open(ancestor)?.sync_all()?;
        }
    }
    staging.file.write_all(&bytes)?;
    staging.publish(filename)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cursor(root: &str, child: &str) -> PrescanCursor {
        let mut cursor = PrescanCursor::new();
        cursor.advance(Path::new(root), &Path::new(root).join(child));
        cursor
    }

    #[test]
    fn versioned_and_legacy_progress_resume_both_mounts() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cursor.json");
        let mut expected = cursor("/mount-a", "a");
        expected.advance(Path::new("/mount-b"), Path::new("/mount-b/b"));
        fs::write(&path, serde_json::to_vec(&expected).unwrap()).unwrap();
        assert_eq!(load(&path), expected);
        save(&expected, &path).unwrap();
        assert_eq!(load(&path), expected);
        let json: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(json["version"], VERSION);
        assert!(json["progress"]["continuations"].is_array());
    }

    #[cfg(unix)]
    #[test]
    fn arbitrary_unix_roots_and_resume_names_survive_restart_byte_for_byte() {
        use std::os::unix::ffi::OsStringExt;
        let temp = tempfile::tempdir().unwrap();
        let checkpoint = temp.path().join("cursor.json");
        // Encoding is tested independently of APFS's filename admission rules.
        let root = PathBuf::from(OsString::from_vec(b"/mount-\xff".to_vec()));
        let child = root.join(OsString::from_vec(b"target-\xfe".to_vec()));
        let mut expected = PrescanCursor::new();
        expected.advance(&root, &child);
        expected.advance(Path::new("/other"), Path::new("/other/entry"));
        assert!(
            serde_json::to_vec(&expected).is_err(),
            "legacy PathBuf JSON cannot store these names"
        );
        save(&expected, &checkpoint).unwrap();
        let restored = read(&checkpoint).unwrap();
        assert_eq!(restored, expected);
        assert_eq!(restored.resume_after(&root), Some(child.as_path()));
    }

    #[test]
    fn corrupt_or_unsupported_envelopes_cannot_skip_discovery() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cursor.json");
        save(&cursor("/root", "a"), &path).unwrap();
        let original: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let mut corrupted = original.clone();
        corrupted["progress"]["after"] = serde_json::json!("/root/z");
        fs::write(&path, serde_json::to_vec(&corrupted).unwrap()).unwrap();
        assert!(read(&path).is_err());
        assert_eq!(load(&path), PrescanCursor::new());
        let mut future = original;
        future["version"] = serde_json::json!(VERSION + 1);
        fs::write(&path, serde_json::to_vec(&future).unwrap()).unwrap();
        assert!(read(&path).is_err());
        for bytes in [b"{truncated".as_slice(), b"{\"version\":1}", b"null"] {
            fs::write(&path, bytes).unwrap();
            assert_eq!(load(&path), PrescanCursor::new());
        }
    }

    #[test]
    fn invalid_resume_bindings_and_duplicate_roots_are_rejected() {
        for bad in [
            br#"{"root":null,"after":"/r/a"}"#.as_slice(),
            br#"{"root":"/r","after":"/other/z"}"#,
            br#"{"root":"/r","after":"/r/deep/z"}"#,
            br#"{"root":"/r","after":"/r/.."}"#,
            br#"{"continuations":{"/r":"/other/z"}}"#,
        ] {
            assert!(decode(bad).is_err());
        }
        let duplicate = Progress {
            root: None,
            after: None,
            continuations: vec![
                (StoredPath::Text("/r".into()), StoredPath::Text("/r/a".into())),
                (StoredPath::Text("/r".into()), StoredPath::Text("/r/z".into())),
            ],
        };
        assert!(duplicate.into_cursor().is_err());
    }

    #[test]
    fn oversized_or_invalid_save_preserves_the_last_good_checkpoint() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cursor.json");
        let good = cursor("/root", "a");
        save(&good, &path).unwrap();
        let bytes = fs::read(&path).unwrap();
        let bad = cursor("/root", &"x".repeat(MAX_PATH_BYTES + 1));
        assert!(save(&bad, &path).is_err());
        let mut too_many = PrescanCursor::new();
        for n in 0..=MAX_ROOTS {
            let root = PathBuf::from(format!("/r{n}"));
            too_many.continuations.insert(root.clone(), root.join("a"));
        }
        assert!(save(&too_many, &path).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(load(&path), good);
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[test]
    fn load_limits_cover_sparse_files_directories_and_growth_after_stat() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cursor.json");
        File::create(&path)
            .unwrap()
            .set_len(MAX_CHECKPOINT_BYTES as u64 + 1)
            .unwrap();
        assert!(read(&path).is_err());
        assert_eq!(load(&path), PrescanCursor::new());
        assert_eq!(load(temp.path()), PrescanCursor::new());
        assert!(read_bounded(&b"12345"[..], 4).is_err());
        assert_eq!(read_bounded(&b"1234"[..], 4).unwrap(), b"1234");
        let mut writer = LimitedWriter {
            inner: Vec::new(),
            remaining: 4,
        };
        writer.write_all(b"1234").unwrap();
        assert!(writer.write_all(b"5").is_err());
        assert_eq!(writer.inner, b"1234");
    }

    #[cfg(unix)]
    #[test]
    fn predictable_temp_alias_and_checkpoint_alias_never_overwrite_the_target() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cursor.json");
        let victim = temp.path().join("user-data");
        fs::write(&victim, b"keep me").unwrap();
        symlink(&victim, path.with_extension("json.tmp")).unwrap();
        symlink(&victim, &path).unwrap();
        assert!(read(&path).is_err());
        let expected = cursor("/root", "a");
        save(&expected, &path).unwrap();
        assert_eq!(load(&path), expected);
        assert_eq!(fs::read(&victim).unwrap(), b"keep me");
        assert!(
            fs::symlink_metadata(path.with_extension("json.tmp"))
                .unwrap()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn fifo_is_refused_without_waiting_for_a_writer() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cursor.fifo");
        nix::unistd::mkfifo(
            &path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        assert!(read(&path).is_err());
        assert_eq!(load(&path), PrescanCursor::new());
    }

    #[cfg(unix)]
    #[test]
    fn published_checkpoint_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("nested/state/cursor.json");
        save(&cursor("/root", "a"), &path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn replaced_parent_cannot_redirect_publication_or_cleanup() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("state");
        let moved = temp.path().join("state-moved");
        let outside = temp.path().join("outside");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&outside).unwrap();
        let mut staging = StagingFile::create(&parent).unwrap();
        let name = staging.name.clone();
        staging.file.write_all(b"new checkpoint").unwrap();
        fs::rename(&parent, &moved).unwrap();
        fs::write(outside.join("cursor.json"), b"unrelated checkpoint").unwrap();
        fs::write(outside.join(&name), b"unrelated staging file").unwrap();
        symlink(&outside, &parent).unwrap();
        assert!(staging.publish(std::ffi::OsStr::new("cursor.json")).is_err());
        assert_eq!(
            fs::read(outside.join("cursor.json")).unwrap(),
            b"unrelated checkpoint"
        );
        assert_eq!(
            fs::read(outside.join(name)).unwrap(),
            b"unrelated staging file"
        );
        assert_eq!(fs::read_dir(&moved).unwrap().count(), 0);
    }

    #[test]
    fn failed_publication_keeps_existing_destination_and_cleans_private_staging() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cursor.json");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("sentinel"), b"existing data").unwrap();
        assert!(save(&cursor("/root", "a"), &path).is_err());
        assert_eq!(fs::read(path.join("sentinel")).unwrap(), b"existing data");
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[test]
    fn concurrent_writers_publish_complete_independent_checkpoints() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cursor.json");
        let a = cursor("/root", "a");
        let b = cursor("/root", "b");
        save(&a, &path).unwrap();
        std::thread::scope(|scope| {
            for value in [&a, &b] {
                let path = &path;
                scope.spawn(move || {
                    for _ in 0..16 {
                        save(value, path).unwrap();
                    }
                });
            }
            for _ in 0..32 {
                // The strict loader may reject an old inode whose ctime
                // changed when a writer unlinked it by atomic replacement.
                // Independently verify publication itself never exposes a
                // torn JSON snapshot, whether this open sees the old or new fd.
                let observed = decode(&fs::read(&path).unwrap()).unwrap();
                assert!(observed == a || observed == b);
            }
        });
        let observed = read(&path).unwrap();
        assert!(observed == a || observed == b);
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }
}
