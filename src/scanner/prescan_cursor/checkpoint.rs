//! Byte-preserving, bounded and crash-consistent pre-scan continuation storage.
//!
//! Checkpoints are discovery hints, not deletion authority. Invalid input starts
//! discovery over. A failed save before publication keeps the previous checkpoint.
//! Unix publication is relative to the opened state directory, so replacing its
//! pathname cannot redirect writes or staging-file cleanup to another directory.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::shallow::{MAX_SHALLOW_BYTES, MAX_SHALLOW_ROOTS, ShallowFrame, ShallowPosition};
use super::{PrescanCursor, PressureOrder, WalkDispatchCursor, WalkDispatchPosition};
use crate::scanner::walker::{MAX_DISPATCH_CURSOR_BYTES, MAX_DISPATCH_CURSOR_ROWS};

const VERSION: u32 = 5;
const MAX_ROOTS: usize = 8192;
const MAX_PATH_BYTES: usize = 16 * 1024;
const MAX_RAW_PATH_BYTES: usize = 512 * 1024;
// Main and event-scoped discovery each retain independent continuation and
// shallow allowances; recursive dispatch adds a fifth native-name allowance.
// JSON escaping can expand every byte sixfold. The additional 2 MiB covers
// per-row fields and Unix byte-array wrappers at the existing row limits.
const MAX_CHECKPOINT_BYTES: usize = 6
    * (2 * MAX_RAW_PATH_BYTES + MAX_DISPATCH_CURSOR_BYTES + 2 * MAX_SHALLOW_BYTES)
    + 2 * 1024 * 1024;

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
    // Omit an absent order so version 1 progress retains its original checksum.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    walk_order: Vec<(StoredPath, u64, bool)>,
    // Empty dispatch history must not alter original v1/v2 checksum bytes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    walk_dispatch: Vec<StoredDispatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    shallow: Vec<(StoredPath, StoredShallow)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scoped: Option<Box<Self>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredShallow {
    entry: StoredPath,
    pending: Option<StoredPath>,
    frames: Vec<(StoredPath, Option<StoredPath>)>,
}

/// Preserve a v3 row's exact encoding until its checksum has been verified.
/// New window metadata must never be accepted under an older format version.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum StoredDispatch {
    Legacy((StoredPath, StoredPath)),
    Window(StoredWindow),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredWindow {
    directory: StoredPath,
    window_start: u32,
    next_child: Option<StoredPath>,
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

impl TryFrom<&Path> for StoredPath {
    type Error = io::Error;

    fn try_from(path: &Path) -> io::Result<Self> {
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
            Err(invalid(
                "pre-scan path cannot be represented on this platform",
            ))
        }
    }
}

impl TryFrom<StoredPath> for PathBuf {
    type Error = io::Error;

    fn try_from(path: StoredPath) -> io::Result<Self> {
        match path {
            StoredPath::Text(text) => Ok(Self::from(text)),
            StoredPath::UnixBytes { unix_bytes } => {
                #[cfg(unix)]
                {
                    use std::os::unix::ffi::OsStringExt;
                    Ok(Self::from(OsString::from_vec(unix_bytes)))
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
    if let Some(scoped) = cursor.scoped.as_deref() {
        if scoped.scoped.is_some()
            || !scoped.walk_dispatch.is_empty()
            || scoped.walk_order.opportunities().next().is_some()
        {
            return Err(invalid("invalid nested scoped pre-scan progress"));
        }
        validate(scoped)?;
    }
    if cursor.shallow.len() > MAX_SHALLOW_ROOTS {
        return Err(invalid("shallow pre-scan root count exceeds the limit"));
    }
    let mut shallow_bytes = 0usize;
    for (root, position) in &cursor.shallow {
        position.validate(root)?;
        for path in std::iter::once(root.as_path()).chain(position.paths()) {
            shallow_bytes = shallow_bytes
                .checked_add(path.as_os_str().len())
                .filter(|total| *total <= MAX_SHALLOW_BYTES)
                .ok_or_else(|| invalid("shallow pre-scan path storage exceeds the limit"))?;
        }
    }
    if cursor.continuations.len() > MAX_ROOTS {
        return Err(invalid("pre-scan continuation count exceeds the limit"));
    }
    if cursor.walk_order.opportunities().count() > MAX_ROOTS {
        return Err(invalid("recursive walk root count exceeds the limit"));
    }
    // The same validation as runtime restoration rejects duplicate directory
    // rows, traversal components, invalid basenames, and oversized history.
    WalkDispatchCursor::from_positions(cursor.walk_dispatch.as_ref().clone())?;
    if let Some(after) = &cursor.after
        && cursor
            .root
            .as_deref()
            .is_none_or(|root| !direct_child(root, after))
    {
        return Err(invalid(
            "pre-scan resume point is not a root's direct child",
        ));
    }
    if cursor
        .continuations
        .iter()
        .any(|(root, after)| !direct_child(root, after))
    {
        return Err(invalid("pre-scan continuation escapes its root"));
    }
    let mut raw_bytes = 0usize;
    for path in cursor
        .root
        .iter()
        .chain(&cursor.after)
        .chain(cursor.continuations.iter().flat_map(<[_; 2]>::from))
        .map(PathBuf::as_path)
        .chain(cursor.walk_order.opportunities().map(|(path, _, _)| path))
    {
        let bytes = path.as_os_str().as_encoded_bytes();
        if !super::shallow::valid_path(path) || bytes.len() > MAX_PATH_BYTES {
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
        && super::shallow::valid_path(root)
        && super::shallow::valid_path(after)
}

impl Progress {
    fn from_cursor(cursor: &PrescanCursor) -> io::Result<Self> {
        validate(cursor)?;
        Ok(Self {
            root: cursor
                .root
                .as_deref()
                .map(StoredPath::try_from)
                .transpose()?,
            after: cursor
                .after
                .as_deref()
                .map(StoredPath::try_from)
                .transpose()?,
            continuations: cursor
                .continuations
                .iter()
                .map(|(root, after)| {
                    Ok((
                        StoredPath::try_from(root.as_path())?,
                        StoredPath::try_from(after.as_path())?,
                    ))
                })
                .collect::<io::Result<_>>()?,
            walk_order: cursor
                .walk_order
                .opportunities()
                .map(|(path, last_lead, ordinary_due)| {
                    Ok((StoredPath::try_from(path)?, last_lead, ordinary_due))
                })
                .collect::<io::Result<_>>()?,
            walk_dispatch: cursor
                .walk_dispatch
                .iter()
                .map(|position| {
                    Ok(StoredDispatch::Window(StoredWindow {
                        directory: StoredPath::try_from(position.directory.as_path())?,
                        window_start: position.window_start,
                        next_child: position
                            .next_child
                            .as_deref()
                            .map(Path::new)
                            .map(StoredPath::try_from)
                            .transpose()?,
                    }))
                })
                .collect::<io::Result<_>>()?,
            shallow: cursor
                .shallow
                .iter()
                .map(|(root, position)| {
                    Ok((
                        StoredPath::try_from(root.as_path())?,
                        StoredShallow {
                            entry: StoredPath::try_from(position.entry.as_path())?,
                            pending: position
                                .pending
                                .as_deref()
                                .map(StoredPath::try_from)
                                .transpose()?,
                            frames: position
                                .frames
                                .iter()
                                .map(|frame| {
                                    Ok((
                                        StoredPath::try_from(frame.directory.as_path())?,
                                        frame
                                            .after
                                            .as_deref()
                                            .map(StoredPath::try_from)
                                            .transpose()?,
                                    ))
                                })
                                .collect::<io::Result<_>>()?,
                        },
                    ))
                })
                .collect::<io::Result<_>>()?,
            scoped: cursor
                .scoped
                .as_deref()
                .map(Self::from_cursor)
                .transpose()?
                .map(Box::new),
        })
    }

    fn into_cursor(self) -> io::Result<PrescanCursor> {
        if self.shallow.len() > MAX_SHALLOW_ROOTS
            || self.scoped.as_deref().is_some_and(|scoped| {
                scoped.scoped.is_some()
                    || !scoped.walk_order.is_empty()
                    || !scoped.walk_dispatch.is_empty()
            })
        {
            return Err(invalid("invalid scoped or shallow pre-scan progress"));
        }
        let mut shallow = BTreeMap::new();
        for (root, position) in self.shallow {
            if position.frames.len() > 2 {
                return Err(invalid("shallow pre-scan depth exceeds the limit"));
            }
            let position = ShallowPosition {
                entry: PathBuf::try_from(position.entry)?,
                pending: position.pending.map(PathBuf::try_from).transpose()?,
                frames: position
                    .frames
                    .into_iter()
                    .map(|(directory, after)| {
                        Ok(ShallowFrame {
                            directory: PathBuf::try_from(directory)?,
                            after: after.map(PathBuf::try_from).transpose()?,
                        })
                    })
                    .collect::<io::Result<_>>()?,
            };
            if shallow.insert(PathBuf::try_from(root)?, position).is_some() {
                return Err(invalid("duplicate shallow pre-scan root"));
            }
        }
        let scoped = self
            .scoped
            .map(|scoped| scoped.into_cursor())
            .transpose()?
            .map(Box::new);
        if self.continuations.len() > MAX_ROOTS {
            return Err(invalid("pre-scan continuation count exceeds the limit"));
        }
        if self.walk_order.len() > MAX_ROOTS {
            return Err(invalid("recursive walk root count exceeds the limit"));
        }
        if self.walk_dispatch.len() > MAX_DISPATCH_CURSOR_ROWS {
            return Err(invalid("recursive dispatch row count exceeds the limit"));
        }
        let mut continuations = BTreeMap::new();
        for (root, after) in self.continuations {
            if continuations
                .insert(PathBuf::try_from(root)?, PathBuf::try_from(after)?)
                .is_some()
            {
                return Err(invalid("duplicate pre-scan continuation root"));
            }
        }
        let mut roots = BTreeSet::new();
        let mut opportunities = Vec::with_capacity(self.walk_order.len());
        for (path, last_lead, ordinary_due) in self.walk_order {
            let path = PathBuf::try_from(path)?;
            if !roots.insert(path.clone()) {
                return Err(invalid("duplicate recursive walk root"));
            }
            opportunities.push((path, last_lead, ordinary_due));
        }
        let positions = self
            .walk_dispatch
            .into_iter()
            .map(|stored| {
                let (directory, window_start, next_child) = match stored {
                    StoredDispatch::Legacy((directory, child)) => (directory, 0, Some(child)),
                    StoredDispatch::Window(window) => {
                        (window.directory, window.window_start, window.next_child)
                    }
                };
                Ok(WalkDispatchPosition {
                    directory: PathBuf::try_from(directory)?,
                    window_start,
                    next_child: next_child
                        .map(PathBuf::try_from)
                        .transpose()?
                        .map(PathBuf::into_os_string),
                })
            })
            .collect::<io::Result<_>>()?;
        let walk_dispatch = WalkDispatchCursor::from_positions(positions)?.snapshot();
        let cursor = PrescanCursor {
            root: self.root.map(PathBuf::try_from).transpose()?,
            after: self.after.map(PathBuf::try_from).transpose()?,
            continuations,
            shallow,
            scoped,
            walk_order: PressureOrder::from_opportunities(opportunities),
            walk_dispatch: Arc::new(walk_dispatch),
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

fn checksum(version: u32, progress: &Progress) -> io::Result<[u8; 32]> {
    let mut digest = Sha256::new();
    digest.update(version.to_le_bytes());
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
        if !matches!(checkpoint.version, 1..=VERSION)
            || (checkpoint.version < 5
                && (!checkpoint.progress.shallow.is_empty()
                    || checkpoint.progress.scoped.is_some()))
            || (checkpoint.version < 3 && !checkpoint.progress.walk_dispatch.is_empty())
            || (checkpoint.version < 4
                && checkpoint
                    .progress
                    .walk_dispatch
                    .iter()
                    .any(|row| matches!(row, StoredDispatch::Window(_))))
            || checksum(checkpoint.version, &checkpoint.progress)? != checkpoint.checksum
        {
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
            return Err(invalid(
                "pre-scan state directory changed before publication",
            ));
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
                return Err(invalid(
                    "pre-scan staging file was replaced before publication",
                ));
            }
            renameat(&self.parent, &self.name, &self.parent, filename)?;
        }
        #[cfg(not(unix))]
        {
            let source = self.parent_path.join(&self.name);
            if !same_file(&self.file.metadata()?, &fs::symlink_metadata(&source)?) {
                return Err(invalid(
                    "pre-scan staging file was replaced before publication",
                ));
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
        checksum: checksum(VERSION, &progress)?,
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

    #[test]
    fn version_one_checkpoint_keeps_its_original_checksum_and_discovery_progress() {
        let original = br#"{"root":"/root","after":"/root/a","continuations":[]}"#;
        let mut digest = Sha256::new();
        digest.update(1_u32.to_le_bytes());
        digest.update(original);
        let checksum: [u8; 32] = digest.finalize().into();
        let envelope = serde_json::json!({
            "version": 1,
            "progress": serde_json::from_slice::<serde_json::Value>(original).unwrap(),
            "checksum": checksum,
        });
        let restored = decode(&serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert_eq!(restored, cursor("/root", "a"));
        assert_eq!(restored.walk_order.opportunities().count(), 0);
        assert!(restored.walk_dispatch().is_empty());
    }

    #[test]
    fn version_two_checkpoint_keeps_its_original_checksum_and_root_rotation() {
        let original = br#"{"root":"/root","after":"/root/a","continuations":[["/other","/other/b"]],"walk_order":[["/other",1,false],["/root",2,true]]}"#;
        let mut digest = Sha256::new();
        digest.update(2_u32.to_le_bytes());
        digest.update(original);
        let checksum: [u8; 32] = digest.finalize().into();
        let envelope = serde_json::json!({
            "version": 2,
            "progress": serde_json::from_slice::<serde_json::Value>(original).unwrap(),
            "checksum": checksum,
        });
        let restored = decode(&serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert_eq!(
            restored.position(),
            (Some(Path::new("/root")), Some(Path::new("/root/a")))
        );
        assert_eq!(
            restored.resume_after(Path::new("/other")),
            Some(Path::new("/other/b"))
        );
        assert_eq!(
            restored.walk_order.opportunities().collect::<Vec<_>>(),
            vec![
                (Path::new("/other"), 1, false),
                (Path::new("/root"), 2, true)
            ],
        );
        assert!(restored.walk_dispatch().is_empty());

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cursor.json");
        save(&restored, &path).unwrap();
        assert_eq!(read(&path).unwrap(), restored);
        let upgraded: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(upgraded["version"], VERSION);
    }

    #[test]
    fn version_three_checkpoint_keeps_its_original_checksum_and_child_priority() {
        // Independently encode the shipped v3 tuple shape. Deserializing it
        // directly into a v4 window would change bytes before verification.
        let original = br#"{"root":"/root","after":"/root/a","continuations":[],"walk_dispatch":[["/root/nested","next"]]}"#;
        let mut digest = Sha256::new();
        digest.update(3_u32.to_le_bytes());
        digest.update(original);
        let checksum: [u8; 32] = digest.finalize().into();
        let envelope = serde_json::json!({
            "version": 3,
            "progress": serde_json::from_slice::<serde_json::Value>(original).unwrap(),
            "checksum": checksum,
        });
        let restored = decode(&serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert_eq!(
            restored.resume_after(Path::new("/root")),
            Some(Path::new("/root/a"))
        );
        assert_eq!(
            restored.walk_dispatch(),
            &[WalkDispatchPosition {
                directory: PathBuf::from("/root/nested"),
                window_start: 0,
                next_child: Some(OsString::from("next")),
            }]
        );

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cursor.json");
        save(&restored, &path).unwrap();
        assert_eq!(read(&path).unwrap(), restored);
        let upgraded: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(upgraded["version"], VERSION);
        let row = &upgraded["progress"]["walk_dispatch"][0];
        assert_eq!(row["directory"], "/root/nested");
        assert_eq!(row["window_start"], 0);
        assert_eq!(row["next_child"], "next");

        // Window-only metadata cannot be smuggled into a claimed legacy row.
        let mut forged = envelope;
        forged["progress"]["walk_dispatch"][0] = serde_json::json!(["/root/nested", "next", 2048]);
        assert!(serde_json::from_value::<Checkpoint>(forged).is_err());
    }

    #[test]
    fn recursive_dispatch_survives_shallow_resets_and_keeps_disjoint_roots() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cursor.json");
        let mut dispatch = WalkDispatchCursor::from_positions(vec![
            WalkDispatchPosition {
                directory: PathBuf::from("/left/projects"),
                window_start: 2048,
                next_child: Some(OsString::from("next-left")),
            },
            WalkDispatchPosition {
                directory: PathBuf::from("/right/projects"),
                window_start: 4096,
                next_child: None,
            },
        ])
        .unwrap();
        let mut state = cursor("/left", "examined");
        assert!(state.remember_walk_dispatch(&dispatch));
        assert!(!state.remember_walk_dispatch(&dispatch));
        let rewind = state.clone();
        assert!(
            Arc::ptr_eq(&state.walk_dispatch, &rewind.walk_dispatch),
            "per-entry rewind snapshots must not clone all recursive paths",
        );
        state.reset();
        assert_eq!(state.position(), (None, None));
        save(&state, &path).unwrap();
        let mut restored = read(&path).unwrap();
        assert_eq!(restored.walk_dispatch(), dispatch.snapshot());
        // A shallow pass on one mount preserves the other's recursive turn.
        restored.advance(Path::new("/left"), Path::new("/left/later"));
        save(&restored, &path).unwrap();
        assert_eq!(read(&path).unwrap().walk_dispatch(), dispatch.snapshot());

        // Removing scope is an explicit current-config operation, not a
        // consequence of the last pass having selected only one mount.
        dispatch.retain_roots(&[PathBuf::from("/right")]);
        assert!(state.remember_walk_dispatch(&dispatch));
        assert_eq!(state.walk_dispatch().len(), 1);
        assert_eq!(
            rewind.walk_dispatch().len(),
            2,
            "replacement leaves prior snapshots isolated"
        );
        assert!(restored.remember_walk_dispatch(&dispatch));
        save(&restored, &path).unwrap();
        let final_state = read(&path).unwrap();
        assert_eq!(final_state.walk_dispatch().len(), 1);
        assert_eq!(
            final_state.walk_dispatch()[0].directory,
            Path::new("/right/projects")
        );
        assert_eq!(final_state.walk_dispatch()[0].window_start, 4096);
        assert!(final_state.walk_dispatch()[0].next_child.is_none());
    }

    #[test]
    fn recursive_turns_survive_restart_partial_mount_scopes_and_forced_prescans() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cursor.json");
        let roots: Vec<_> = ["/left/hot", "/left/a", "/right/hot", "/right/a"]
            .map(PathBuf::from)
            .into();
        let mut state = PrescanCursor::new();
        for expected in ["a", "hot", "a", "hot"] {
            for scope in roots.as_chunks::<2>().0 {
                let mut order = state.walk_order().clone();
                let mut ranked = scope.to_vec();
                order.reorder(&mut ranked, false, |_| true);
                assert_eq!(ranked[0].file_name().unwrap(), expected);
                assert!(state.remember_walk_order(&order, &roots));
                // An operator's fresh pre-scan must not consume or erase
                // recursive opportunities already granted to either mount.
                state.advance(&scope[0], &scope[0].join("examined"));
                state.reset();
                save(&state, &path).unwrap();
                state = read(&path).unwrap();
            }
        }
        assert_eq!(state.walk_order.opportunities().count(), 4);

        let mut order = state.walk_order().clone();
        let retained = &roots[..2];
        order.retain_roots(retained);
        assert!(state.remember_walk_order(&order, retained));
        assert!(!state.remember_walk_order(&order, retained));
        save(&state, &path).unwrap();
        let restored = read(&path).unwrap();
        let mut order = restored.walk_order().clone();
        let mut ranked = retained.to_vec();
        order.reorder(&mut ranked, false, |_| true);
        assert_eq!(ranked.len(), retained.len());
        assert!(ranked.iter().all(|root| retained.contains(root)));
        assert_eq!(restored.walk_order.opportunities().count(), 2);
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
        let roots = vec![root.clone(), PathBuf::from("/other")];
        let mut order = PressureOrder::default();
        order.reorder(&mut roots.clone(), false, |_| true);
        assert!(expected.remember_walk_order(&order, &roots));
        let dispatch = WalkDispatchCursor::from_positions(vec![WalkDispatchPosition {
            directory: root.join(OsString::from_vec(b"nested-\xfd".to_vec())),
            window_start: 12_345,
            next_child: Some(OsString::from_vec(b"pending-\xfc".to_vec())),
        }])
        .unwrap();
        assert!(expected.remember_walk_dispatch(&dispatch));
        assert!(
            serde_json::to_vec(&expected).is_err(),
            "legacy PathBuf JSON cannot store these names"
        );
        save(&expected, &checkpoint).unwrap();
        let restored = read(&checkpoint).unwrap();
        assert_eq!(restored, expected);
        assert_eq!(restored.resume_after(&root), Some(child.as_path()));
        assert_eq!(restored.walk_dispatch(), dispatch.snapshot());
    }

    #[test]
    fn malformed_dispatch_names_and_duplicate_directories_cannot_replace_good_state() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cursor.json");
        let mut good = cursor("/root", "examined");
        let dispatch = WalkDispatchCursor::from_positions(vec![WalkDispatchPosition {
            directory: PathBuf::from("/root/nested"),
            window_start: 0,
            next_child: Some(OsString::from("next")),
        }])
        .unwrap();
        good.remember_walk_dispatch(&dispatch);
        save(&good, &path).unwrap();
        let original = fs::read(&path).unwrap();
        for child in [
            "",
            ".",
            "..",
            "../outside",
            "/outside",
            "nested/child",
            "child/",
            "./child",
            "child/.",
            "bad\0name",
        ] {
            let mut invalid_cursor = good.clone();
            Arc::make_mut(&mut invalid_cursor.walk_dispatch)[0].next_child =
                Some(OsString::from(child));
            assert!(save(&invalid_cursor, &path).is_err(), "{child:?}");
            // Recompute the checksum to distinguish malformed-path refusal
            // from an incidental corruption check.
            let mut progress = Progress::from_cursor(&good).unwrap();
            let StoredDispatch::Window(window) = &mut progress.walk_dispatch[0] else {
                panic!("new checkpoints use window rows");
            };
            window.next_child = Some(StoredPath::Text(child.into()));
            let envelope = Checkpoint {
                version: VERSION,
                checksum: checksum(VERSION, &progress).unwrap(),
                progress,
            };
            assert!(decode(&encode(&envelope).unwrap()).is_err(), "{child:?}");
        }
        for directory in ["relative", "/root/../outside", "/bad\0directory"] {
            let mut invalid_cursor = good.clone();
            Arc::make_mut(&mut invalid_cursor.walk_dispatch)[0].directory =
                PathBuf::from(directory);
            assert!(save(&invalid_cursor, &path).is_err(), "{directory:?}");
        }
        let mut duplicate = Progress::from_cursor(&good).unwrap();
        duplicate
            .walk_dispatch
            .push(StoredDispatch::Window(StoredWindow {
                directory: StoredPath::Text("/root/nested".into()),
                window_start: 2048,
                next_child: Some(StoredPath::Text("another".into())),
            }));
        assert!(duplicate.into_cursor().is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(read(&path).unwrap(), good);
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[test]
    fn dispatch_history_has_independent_row_path_and_raw_byte_limits() {
        use crate::scanner::walker::{MAX_DISPATCH_CURSOR_BYTES, MAX_DISPATCH_CURSOR_PATH_BYTES};

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cursor.json");
        let good = cursor("/root", "a");
        save(&good, &path).unwrap();
        let original = fs::read(&path).unwrap();
        let mut too_many = good.clone();
        too_many.walk_dispatch = Arc::new(
            (0..=MAX_DISPATCH_CURSOR_ROWS)
                .map(|index| WalkDispatchPosition {
                    directory: PathBuf::from(format!("/root-{index}")),
                    window_start: 0,
                    next_child: Some(OsString::from("next")),
                })
                .collect(),
        );
        assert!(save(&too_many, &path).is_err());
        let mut too_long = good.clone();
        too_long.walk_dispatch = Arc::new(vec![WalkDispatchPosition {
            directory: PathBuf::from("/root"),
            window_start: 0,
            next_child: Some(OsString::from(
                "x".repeat(MAX_DISPATCH_CURSOR_PATH_BYTES + 1),
            )),
        }]);
        assert!(save(&too_long, &path).is_err());
        let mut too_large = good.clone();
        too_large.walk_dispatch = Arc::new(
            (0..=MAX_DISPATCH_CURSOR_BYTES / (MAX_DISPATCH_CURSOR_PATH_BYTES - 32))
                .map(|index| WalkDispatchPosition {
                    directory: PathBuf::from(format!(
                        "/root-{index}/{}",
                        "x".repeat(MAX_DISPATCH_CURSOR_PATH_BYTES - 32),
                    )),
                    window_start: 0,
                    next_child: Some(OsString::from("next")),
                })
                .collect(),
        );
        assert!(save(&too_large, &path).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(read(&path).unwrap(), good);
    }

    #[test]
    fn all_bounded_histories_fit_with_maximum_json_path_escaping() {
        use std::ffi::OsStr;

        use crate::scanner::walker::MAX_DISPATCH_CURSOR_PATH_BYTES;

        fn escaped_root(index: usize, bytes: usize) -> PathBuf {
            let prefix = format!("/{index}/");
            PathBuf::from(format!("{prefix}{}", "\u{1}".repeat(bytes - prefix.len())))
        }

        fn fill_discovery_budgets(state: &mut PrescanCursor) {
            let mut remaining = MAX_RAW_PATH_BYTES;
            let mut index = 0;
            while remaining > 0 {
                let row_bytes = remaining.min(2 * MAX_PATH_BYTES - 2);
                let root = escaped_root(index, (row_bytes - 2) / 2);
                let after = root.join("\u{2}");
                assert_eq!(root.as_os_str().len() + after.as_os_str().len(), row_bytes);
                state.continuations.insert(root, after);
                remaining -= row_bytes;
                index += 1;
            }
            assert_eq!(
                state
                    .continuations
                    .iter()
                    .map(|(root, after)| root.as_os_str().len() + after.as_os_str().len())
                    .sum::<usize>(),
                MAX_RAW_PATH_BYTES,
            );

            remaining = MAX_SHALLOW_BYTES;
            index = 0;
            while remaining > 0 {
                // A full depth-three position has seven paths. With one-byte
                // children, their suffixes contribute another 24 raw bytes.
                let row_bytes = remaining.min(7 * (MAX_PATH_BYTES - 6) + 24);
                let root = escaped_root(index, (row_bytes - 24) / 7);
                let entry = root.join("\u{2}");
                let directory = entry.join("\u{3}");
                let position = ShallowPosition {
                    entry: entry.clone(),
                    pending: Some(directory.join("\u{5}".repeat(1 + (row_bytes - 24) % 7))),
                    frames: vec![
                        ShallowFrame {
                            directory: entry.clone(),
                            after: Some(entry.join("\u{2}")),
                        },
                        ShallowFrame {
                            directory: directory.clone(),
                            after: Some(directory.join("\u{4}")),
                        },
                    ],
                };
                assert_eq!(
                    root.as_os_str().len()
                        + position
                            .paths()
                            .map(|path| path.as_os_str().len())
                            .sum::<usize>(),
                    row_bytes,
                );
                state.shallow.insert(root, position);
                remaining -= row_bytes;
                index += 1;
            }
            assert_eq!(
                state
                    .shallow
                    .iter()
                    .map(|(root, position)| {
                        root.as_os_str().len()
                            + position
                                .paths()
                                .map(|path| path.as_os_str().len())
                                .sum::<usize>()
                    })
                    .sum::<usize>(),
                MAX_SHALLOW_BYTES,
            );
        }

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cursor.json");
        let mut state = PrescanCursor::new();
        fill_discovery_budgets(&mut state);
        let mut scoped = PrescanCursor::new();
        fill_discovery_budgets(&mut scoped);
        state.scoped = Some(Box::new(scoped));
        let dispatch = WalkDispatchCursor::from_positions(
            (0..MAX_DISPATCH_CURSOR_BYTES / (2 * MAX_DISPATCH_CURSOR_PATH_BYTES))
                .map(|index| WalkDispatchPosition {
                    directory: escaped_root(index, MAX_DISPATCH_CURSOR_PATH_BYTES),
                    window_start: u32::MAX,
                    next_child: Some(OsString::from(
                        "\u{6}".repeat(MAX_DISPATCH_CURSOR_PATH_BYTES),
                    )),
                })
                .collect(),
        )
        .unwrap();
        assert!(state.remember_walk_dispatch(&dispatch));
        assert_eq!(
            state
                .walk_dispatch
                .iter()
                .map(|position| {
                    position.directory.as_os_str().len()
                        + position.next_child.as_deref().map_or(0, OsStr::len)
                })
                .sum::<usize>(),
            MAX_DISPATCH_CURSOR_BYTES,
        );
        // All five independent allowances are full, including both scoped
        // histories. The v4 8 MiB envelope cannot hold this valid v5 state.
        save(&state, &path).unwrap();
        let encoded_len = fs::metadata(&path).unwrap().len();
        assert!(encoded_len > 14 * 1024 * 1024);
        assert!(encoded_len < MAX_CHECKPOINT_BYTES as u64);
        assert_eq!(read(&path).unwrap(), state);
    }

    #[test]
    fn dispatch_corruption_and_history_in_old_envelopes_are_refused() {
        let dispatch = WalkDispatchCursor::from_positions(vec![WalkDispatchPosition {
            directory: PathBuf::from("/root/nested"),
            window_start: 2048,
            next_child: Some(OsString::from("next")),
        }])
        .unwrap();
        let mut state = cursor("/root", "a");
        state.remember_walk_dispatch(&dispatch);
        let progress = Progress::from_cursor(&state).unwrap();
        let envelope = Checkpoint {
            version: VERSION,
            checksum: checksum(VERSION, &progress).unwrap(),
            progress,
        };
        let mut corrupt = serde_json::to_value(&envelope).unwrap();
        corrupt["progress"]["walk_dispatch"][0]["next_child"] = serde_json::json!("changed");
        assert!(decode(&serde_json::to_vec(&corrupt).unwrap()).is_err());
        let mut shifted = serde_json::to_value(&envelope).unwrap();
        shifted["progress"]["walk_dispatch"][0]["window_start"] = serde_json::json!(4096);
        assert!(decode(&serde_json::to_vec(&shifted).unwrap()).is_err());
        for version in [1, 2, 3] {
            let progress = Progress::from_cursor(&state).unwrap();
            let old = Checkpoint {
                version,
                checksum: checksum(version, &progress).unwrap(),
                progress,
            };
            assert!(decode(&encode(&old).unwrap()).is_err());
        }
    }

    #[test]
    fn invalid_recursive_history_cannot_replace_a_good_checkpoint() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cursor.json");
        let good = cursor("/root", "a");
        save(&good, &path).unwrap();
        let bytes = fs::read(&path).unwrap();
        let mut too_many = good.clone();
        too_many.walk_order = PressureOrder::from_opportunities(
            (0..=MAX_ROOTS).map(|index| (PathBuf::from(format!("/r{index}")), 0, true)),
        );
        assert!(save(&too_many, &path).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);

        let mut duplicate = Progress::from_cursor(&good).unwrap();
        duplicate.walk_order = vec![
            (StoredPath::Text("/root".into()), 1, false),
            (StoredPath::Text("/root".into()), 0, true),
        ];
        assert!(duplicate.into_cursor().is_err());

        let mut changed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        changed["progress"]["walk_order"] = serde_json::json!([["/root", 10, false]]);
        assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
        assert_eq!(read(&path).unwrap(), good);
    }

    #[test]
    fn corrupt_or_unsupported_envelopes_cannot_skip_discovery() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cursor.json");
        save(&cursor("/root", "a"), &path).unwrap();
        let original: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
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
            walk_order: Vec::new(),
            walk_dispatch: Vec::new(),
            shallow: Vec::new(),
            scoped: None,
            continuations: vec![
                (
                    StoredPath::Text("/r".into()),
                    StoredPath::Text("/r/a".into()),
                ),
                (
                    StoredPath::Text("/r".into()),
                    StoredPath::Text("/r/z".into()),
                ),
            ],
        };
        assert!(duplicate.into_cursor().is_err());
    }

    #[test]
    fn shallow_checkpoint_paths_are_validated_even_with_a_matching_checksum() {
        let original = serde_json::json!({
            "root": "/root", "after": null, "continuations": [],
            "shallow": [["/root", {
                "entry": "/root/repo", "pending": "/root/repo/branch/target",
                "frames": [["/root/repo", null], ["/root/repo/branch", null]],
            }]],
        });
        let encode_progress = |value: serde_json::Value, version: u32| {
            let progress: Progress = serde_json::from_value(value).unwrap();
            encode(&Checkpoint {
                version,
                checksum: checksum(version, &progress).unwrap(),
                progress,
            })
            .unwrap()
        };
        assert!(decode(&encode_progress(original.clone(), VERSION)).is_ok());
        assert!(
            decode(&encode_progress(original.clone(), 4)).is_err(),
            "new traversal state requires the new version"
        );
        for bad in [
            "/root/repo/branch/../target",
            "/root/repo/branch/./target",
            "/outside/target",
            "/root/repo/other/target",
            "/root/repo/branch/target/.",
        ] {
            let mut value = original.clone();
            value["shallow"][0][1]["pending"] = serde_json::json!(bad);
            assert!(decode(&encode_progress(value, VERSION)).is_err(), "{bad}");
        }
        let mut invalid_root = original.clone();
        invalid_root["shallow"][0][0] = serde_json::json!("/root/.");
        assert!(decode(&encode_progress(invalid_root, VERSION)).is_err());
        let mut nested = original.clone();
        nested["scoped"] = original.clone();
        nested["scoped"]["scoped"] = original;
        assert!(
            decode(&encode_progress(nested, VERSION)).is_err(),
            "scoped progress cannot recurse"
        );
    }

    #[cfg(unix)]
    #[test]
    fn shallow_and_scoped_non_utf8_paths_round_trip_exactly() {
        use std::os::unix::ffi::OsStringExt;
        let temp = tempfile::tempdir().unwrap();
        let root = PathBuf::from("/root").join(OsString::from_vec(b"scope-\xff".to_vec()));
        let entry = root.join(OsString::from_vec(b"repo-\xfe".to_vec()));
        let mut configured = PrescanCursor::new();
        let mut scoped = configured.scoped_resume();
        assert!(matches!(
            scoped
                .poll_shallow(
                    &root,
                    &entry,
                    false,
                    || false,
                    |_, _| super::super::ShallowDisposition::Skip,
                )
                .unwrap(),
            super::super::ShallowPoll::Pending
        ));
        configured.remember_scoped(scoped, &[PathBuf::from("/root")]);
        let path = temp.path().join("cursor.json");
        save(&configured, &path).unwrap();
        assert_eq!(read(&path).unwrap(), configured);
        assert_eq!(
            read(&path).unwrap().scoped_resume().shallow[&root]
                .pending
                .as_ref(),
            Some(&entry)
        );
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
        assert!(
            staging
                .publish(std::ffi::OsStr::new("cursor.json"))
                .is_err()
        );
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
