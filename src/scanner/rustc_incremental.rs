//! Structural proof for a standalone rustc incremental cache.
//!
//! The root can have any name. Names alone never authorize reclamation: every
//! child must fit rustc's crate/session layout, every session must have a lock
//! file, and each crate needs a compiler metadata header. Unknown contents,
//! symlinks, I/O failures, and an exhausted inspection budget all fail closed.
//!
//! This is evidence, not a deletion permit. The deletion boundary acquires all
//! reported session locks, checks freshness, renews this exact inventory, and
//! keeps those locks while removing only entries from the inventory. Inspection
//! never opens a lock file: closing an unrelated handle can release
//! process-associated POSIX locks on platforms that use them.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::scanner::walker::FsIdentity;

pub(crate) const PATTERN_NAME: &str = "rustc-incremental-cache";

/// A complete, deterministically ordered observation of a recognized cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IncrementalCache {
    pub(crate) lock_files: Vec<PathBuf>,
    pub(crate) entries: Vec<IncrementalEntry>,
    pub(crate) latest_modified: SystemTime,
}

/// Includes the root, every directory, every lock, and every payload file.
/// Access time is intentionally absent because reading headers can update it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IncrementalEntry {
    pub(crate) path: PathBuf,
    pub(crate) identity: FsIdentity,
    pub(crate) modified: SystemTime,
    pub(crate) changed: (i64, u32),
    pub(crate) size: u64,
    pub(crate) link_count: u64,
}

/// Recognize an entire standalone cache without following its symlinks.
/// Unsupported platforms cannot supply the descriptor-relative proof.
pub(crate) fn inspect(path: &Path) -> Option<IncrementalCache> {
    #[cfg(unix)]
    {
        native::inspect_with_limit(path, 200_000)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// A denial-only hint for public candidates that carry a generic pattern label.
/// A crate-shaped child or uncertain directory listing requires full proof;
/// this function can never establish that anything is safe to delete.
pub(crate) fn requires_proof(path: &Path) -> bool {
    #[cfg(unix)]
    {
        native::requires_proof_with_limit(path, 200_000).unwrap_or(true)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

#[cfg(unix)]
mod native {
    use std::collections::HashSet;
    use std::ffi::OsStr;
    use std::fs::{self, File};
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;
    use std::time::{Duration, Instant, UNIX_EPOCH};

    use rustix::fs::{AtFlags, Dir, FileType, OFlags, Stat, fstat, statat};

    use super::{IncrementalCache, IncrementalEntry, Path};
    use crate::scanner::quarantine::open_beneath;
    use crate::scanner::walker::{FsEntryKind, FsIdentity};

    const INSPECTION_TIME: Duration = Duration::from_secs(2);

    struct Inspection {
        cache: IncrementalCache,
        remaining: usize,
        started: Instant,
        device: u64,
    }

    pub(super) fn requires_proof_with_limit(path: &Path, limit: usize) -> Option<bool> {
        let started = Instant::now();
        if path.components().any(|c| c == Component::ParentDir) {
            return None;
        }
        let name = path.file_name()?;
        let original_parent = path.parent().filter(|p| !p.as_os_str().is_empty());
        let original_parent = original_parent.unwrap_or_else(|| Path::new("."));
        let parent_path = fs::canonicalize(original_parent).ok()?;
        let parent = open_parent(&parent_path)?;
        let root = snapshot(
            path,
            &statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW).ok()?,
        )?;
        let directory = open_directory(&parent, &root)?;
        let mut remaining = limit;
        // Only names are inspected. A directory with a corrupt cache plus
        // unknown files must not downgrade to ordinary, unguarded deletion.
        for entry in Dir::read_from(&directory).ok()? {
            if started.elapsed() >= INSPECTION_TIME {
                return None;
            }
            let entry = entry.ok()?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            remaining = remaining.checked_sub(1)?;
            if std::str::from_utf8(name).is_ok_and(crate_name) {
                return Some(true);
            }
        }
        unchanged(&parent, &directory, &root)?;
        if fs::canonicalize(original_parent).ok()? != parent_path {
            return None;
        }
        let named_parent = fs::metadata(&parent_path).ok()?;
        let held_parent = parent.metadata().ok()?;
        if (named_parent.dev(), named_parent.ino()) != (held_parent.dev(), held_parent.ino())
            || started.elapsed() >= INSPECTION_TIME
        {
            return None;
        }
        Some(false)
    }

    pub(super) fn inspect_with_limit(path: &Path, limit: usize) -> Option<IncrementalCache> {
        // Resolve intentional ancestor aliases (notably macOS /tmp), then pin
        // the parent and open only the final basename with NOFOLLOW. Splitting
        // the basename also prevents a trailing slash from following a link.
        if path.components().any(|c| c == Component::ParentDir) {
            return None;
        }
        let name = path.file_name()?;
        let parent_path = path.parent().filter(|p| !p.as_os_str().is_empty());
        let parent_path = fs::canonicalize(parent_path.unwrap_or_else(|| Path::new("."))).ok()?;
        let parent = open_parent(&parent_path)?;
        let root = snapshot(
            path,
            &statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW).ok()?,
        )?;
        if root.identity.kind != FsEntryKind::Directory {
            return None;
        }
        let directory = open_directory(&parent, &root)?;
        let mut state = Inspection {
            cache: IncrementalCache {
                lock_files: Vec::new(),
                entries: Vec::new(),
                latest_modified: root.modified,
            },
            remaining: limit,
            started: Instant::now(),
            device: root.identity.device_id,
        };
        state.record(root.clone())?;
        let crates = state.children(&directory, path, |entry| {
            entry.identity.kind == FsEntryKind::Directory
                && entry
                    .path
                    .file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(crate_name)
        })?;
        if crates.is_empty() {
            return None;
        }
        for entry in &crates {
            state.inspect_crate(&directory, entry)?;
        }
        state.unchanged_children(&directory, &crates)?;
        unchanged(&parent, &directory, &root)?;
        // The caller's original parent spelling must still resolve to the
        // pinned parent. An ancestor rename or alias swap is not clearance.
        let original_parent = path.parent().filter(|p| !p.as_os_str().is_empty());
        if fs::canonicalize(original_parent.unwrap_or_else(|| Path::new("."))).ok()? != parent_path
        {
            return None;
        }
        let named_parent = fs::metadata(&parent_path).ok()?;
        let held_parent = parent.metadata().ok()?;
        if (named_parent.dev(), named_parent.ino()) != (held_parent.dev(), held_parent.ino()) {
            return None;
        }
        state.check_budget()?;
        state.cache.entries.sort_by(|a, b| a.path.cmp(&b.path));
        state.cache.lock_files.sort();
        Some(state.cache)
    }

    impl Inspection {
        fn check_budget(&self) -> Option<()> {
            (self.started.elapsed() < INSPECTION_TIME).then_some(())
        }

        fn record(&mut self, entry: IncrementalEntry) -> Option<()> {
            self.check_budget()?;
            self.remaining = self.remaining.checked_sub(1)?;
            if entry.identity.device_id != self.device {
                return None;
            }
            self.cache.latest_modified = self.cache.latest_modified.max(entry.modified);
            self.cache.entries.push(entry);
            Some(())
        }

        fn children(
            &mut self,
            directory: &File,
            path: &Path,
            accepted: impl Fn(&IncrementalEntry) -> bool,
        ) -> Option<Vec<IncrementalEntry>> {
            let mut children = Vec::new();
            for entry in Dir::read_from(directory).ok()? {
                self.check_budget()?;
                let entry = entry.ok()?;
                let name = entry.file_name();
                if name.to_bytes() == b"." || name.to_bytes() == b".." {
                    continue;
                }
                let child_path = path.join(OsStr::from_bytes(name.to_bytes()));
                let observed = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW).ok()?;
                let child = snapshot(&child_path, &observed)?;
                // Ordinary directories stop at the first non-cache entry; do
                // not enumerate a large source tree just to reject its shape.
                if !accepted(&child) {
                    return None;
                }
                self.record(child.clone())?;
                children.push(child);
            }
            Some(children)
        }

        fn unchanged_children(&self, parent: &File, children: &[IncrementalEntry]) -> Option<()> {
            for entry in children {
                self.check_budget()?;
                unchanged_name(parent, entry)?;
            }
            Some(())
        }

        fn inspect_crate(&mut self, parent: &File, entry: &IncrementalEntry) -> Option<()> {
            let directory = open_directory(parent, entry)?;
            let children = self.children(&directory, &entry.path, |child| {
                let Some(name) = child.path.file_name().and_then(OsStr::to_str) else {
                    return false;
                };
                match child.identity.kind {
                    // Unix rustc locks are empty, independent files. In
                    // particular, a metadata hardlink must not make a header
                    // read/close operate on an inode we may already lock.
                    FsEntryKind::File => {
                        child.size == 0
                            && child.link_count == 1
                            && name.strip_suffix(".lock").is_some_and(session_prefix)
                    }
                    FsEntryKind::Directory => session_name(name).is_some(),
                    _ => false,
                }
            })?;
            let mut locks = HashSet::new();
            let mut sessions = HashSet::new();
            let mut has_compiler_payload = false;
            for child in &children {
                self.check_budget()?;
                let name = child.path.file_name()?.to_str()?;
                if child.identity.kind == FsEntryKind::File {
                    let stem = name.strip_suffix(".lock")?;
                    if !locks.insert(stem.to_owned()) {
                        return None;
                    }
                    self.cache.lock_files.push(child.path.clone());
                } else {
                    let (stem, working) = session_name(name)?;
                    if !sessions.insert(stem.to_owned()) {
                        return None;
                    }
                    has_compiler_payload |= self.inspect_session(&directory, child, working)?;
                }
            }
            // Empty/partial working sessions can be remnants of failed builds,
            // but generated names alone must never establish a cache. Each
            // crate needs positive compiler metadata evidence somewhere in it.
            if sessions.is_empty()
                || !has_compiler_payload
                || !sessions.iter().all(|stem| locks.contains(stem))
            {
                return None;
            }
            self.unchanged_children(&directory, &children)?;
            unchanged(parent, &directory, entry)
        }

        fn inspect_session(
            &mut self,
            parent: &File,
            entry: &IncrementalEntry,
            working: bool,
        ) -> Option<bool> {
            let directory = open_directory(parent, entry)?;
            let children = self.children(&directory, &entry.path, |child| {
                child.identity.kind == FsEntryKind::File
            })?;
            let mut metadata = [false; 3];
            let mut has_compiler_payload = false;
            for child in &children {
                self.check_budget()?;
                let name = child.path.file_name()?.to_str()?;
                let slot = match name {
                    "dep-graph.bin" => Some(0),
                    "query-cache.bin" => Some(1),
                    "work-products.bin" => Some(2),
                    "dep-graph.part.bin" if working => None,
                    _ if work_product(name) => continue,
                    _ => return None,
                };
                // A killed compiler can leave an empty partial graph; it is
                // accounted for but cannot supply positive format evidence.
                if working && name == "dep-graph.part.bin" && child.size == 0 {
                    continue;
                }
                compiler_header(&directory, child)?;
                has_compiler_payload = true;
                if let Some(slot) = slot {
                    metadata[slot] = true;
                }
            }
            if !working && !metadata.into_iter().all(|present| present) {
                return None;
            }
            self.unchanged_children(&directory, &children)?;
            unchanged(parent, &directory, entry)?;
            Some(has_compiler_payload)
        }
    }

    fn open_parent(path: &Path) -> Option<File> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        #[cfg(target_os = "linux")]
        let fd = crate::platform::linux::no_symlinks::open_without_symlinks(path, flags).ok()?;
        #[cfg(not(target_os = "linux"))]
        let fd = rustix::fs::open(path, flags, rustix::fs::Mode::empty()).ok()?;
        Some(File::from(fd))
    }

    fn open_directory(parent: &File, entry: &IncrementalEntry) -> Option<File> {
        if entry.identity.kind != FsEntryKind::Directory {
            return None;
        }
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let file = File::from(open_beneath(parent, entry.path.file_name()?, flags).ok()?);
        if snapshot(&entry.path, &fstat(&file).ok()?)? != *entry {
            return None;
        }
        Some(file)
    }

    fn unchanged(parent: &File, opened: &File, entry: &IncrementalEntry) -> Option<()> {
        if snapshot(&entry.path, &fstat(opened).ok()?)? != *entry {
            return None;
        }
        unchanged_name(parent, entry)
    }

    fn unchanged_name(parent: &File, entry: &IncrementalEntry) -> Option<()> {
        let observed = statat(parent, entry.path.file_name()?, AtFlags::SYMLINK_NOFOLLOW).ok()?;
        (snapshot(&entry.path, &observed)? == *entry).then_some(())
    }

    /// rustc's file header: RSIC, little-endian u16 format version (0),
    /// one-byte compiler-version length, then that many version bytes.
    /// Only the small header is read, regardless of the payload's size.
    fn compiler_header(parent: &File, entry: &IncrementalEntry) -> Option<()> {
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let mut file = File::from(open_beneath(parent, entry.path.file_name()?, flags).ok()?);
        if snapshot(&entry.path, &fstat(&file).ok()?)? != *entry {
            return None;
        }
        let mut fixed = [0_u8; 7];
        file.read_exact(&mut fixed).ok()?;
        if &fixed[..6] != b"RSIC\0\0" || fixed[6] == 0 {
            return None;
        }
        let length = usize::from(fixed[6]);
        if entry.size <= 7 + u64::from(fixed[6]) {
            return None;
        }
        let mut version = [0_u8; 255];
        file.read_exact(&mut version[..length]).ok()?;
        if !version[..length]
            .iter()
            .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
        {
            return None;
        }
        unchanged(parent, &file, entry)
    }

    // rustix's native Stat integer widths differ between Linux and macOS.
    #[allow(clippy::useless_conversion)]
    fn snapshot(path: &Path, metadata: &Stat) -> Option<IncrementalEntry> {
        let kind = match FileType::from_raw_mode(metadata.st_mode) {
            FileType::Directory => FsEntryKind::Directory,
            FileType::RegularFile => FsEntryKind::File,
            _ => return None,
        };
        let seconds = i64::try_from(metadata.st_mtime).ok()?;
        let nanos = u32::try_from(metadata.st_mtime_nsec).ok()?;
        let changed = (
            i64::try_from(metadata.st_ctime).ok()?,
            u32::try_from(metadata.st_ctime_nsec).ok()?,
        );
        if nanos >= 1_000_000_000 || changed.1 >= 1_000_000_000 {
            return None;
        }
        let modified = if seconds >= 0 {
            UNIX_EPOCH.checked_add(Duration::new(seconds.unsigned_abs(), nanos))?
        } else {
            UNIX_EPOCH
                .checked_sub(Duration::from_secs(seconds.unsigned_abs()))?
                .checked_add(Duration::from_nanos(u64::from(nanos)))?
        };
        Some(IncrementalEntry {
            path: path.to_path_buf(),
            identity: FsIdentity {
                device_id: u64::try_from(metadata.st_dev).ok()?,
                inode: u64::try_from(metadata.st_ino).ok()?,
                kind,
            },
            modified,
            changed,
            size: u64::try_from(metadata.st_size).ok()?,
            link_count: u64::try_from(metadata.st_nlink).ok()?,
        })
    }

    fn base36(value: &str, width: usize, maximum: u128) -> bool {
        value.len() == width
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte.is_ascii_lowercase())
            && u128::from_str_radix(value, 36).is_ok_and(|value| value <= maximum)
    }

    fn crate_name(name: &str) -> bool {
        let Some((name, hash)) = name.rsplit_once('-') else {
            return false;
        };
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            && base36(hash, 13, u128::from(u64::MAX))
    }

    fn session_prefix(name: &str) -> bool {
        let Some(suffix) = name.strip_prefix("s-") else {
            return false;
        };
        let Some((timestamp, random)) = suffix.split_once('-') else {
            return false;
        };
        base36(timestamp, 10, u128::from(u64::MAX)) && base36(random, 7, u128::from(u32::MAX))
    }

    fn session_name(name: &str) -> Option<(&str, bool)> {
        let (stem, suffix) = name.rsplit_once('-')?;
        if !session_prefix(stem) {
            return None;
        }
        if suffix == "working" {
            Some((stem, true))
        } else if base36(suffix, 25, u128::MAX) {
            Some((stem, false))
        } else {
            None
        }
    }

    fn work_product(name: &str) -> bool {
        let Some((stem, extension)) = name.rsplit_once('.') else {
            return false;
        };
        !stem.is_empty()
            && stem
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            && matches!(extension, "o" | "dwo" | "s" | "ll" | "bc" | "rmeta")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::symlink;
        use std::path::PathBuf;
        use std::time::SystemTime;

        const CRATE: &str = "example_crate-0123456789abc";
        const STEM: &str = "s-0123456789-0123456";
        const SESSION: &str = "s-0123456789-0123456-0123456789abcdefghijklmno";

        fn metadata(path: &Path) {
            fs::write(path, b"RSIC\0\0\x04test\x01").unwrap();
        }

        fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("arbitrary-cache-root");
            let session = root.join(CRATE).join(SESSION);
            fs::create_dir_all(&session).unwrap();
            fs::write(root.join(CRATE).join(format!("{STEM}.lock")), []).unwrap();
            for name in ["dep-graph.bin", "query-cache.bin", "work-products.bin"] {
                metadata(&session.join(name));
            }
            fs::write(session.join("example.9f0b-cgu.0.rcgu.o"), b"object").unwrap();
            (temp, root, session)
        }

        #[test]
        fn complete_cache_produces_stable_inventory_including_locks_and_payload() {
            let (_temp, root, session) = fixture();
            let first = inspect_with_limit(&root, 100).expect("compiler cache is recognized");
            assert_eq!(first.entries.len(), 8);
            assert_eq!(
                first.lock_files,
                [root.join(CRATE).join(format!("{STEM}.lock"))]
            );
            assert!(first.entries.iter().any(|entry| entry.path == root));
            assert!(first.entries.iter().any(|entry| entry.path == session));
            assert_eq!(first, inspect_with_limit(&root, 100).unwrap());
        }

        #[test]
        fn denial_hint_finds_malformed_caches_after_unrelated_entries() {
            let temp = tempfile::tempdir().unwrap();
            fs::write(temp.path().join("ordinary.txt"), b"keep").unwrap();
            assert_eq!(requires_proof_with_limit(temp.path(), 100), Some(false));
            fs::write(temp.path().join(CRATE), b"not even a directory").unwrap();
            assert_eq!(requires_proof_with_limit(temp.path(), 100), Some(true));
            assert!(inspect_with_limit(temp.path(), 100).is_none());
        }

        #[test]
        fn denial_hint_never_treats_io_or_budget_failure_as_clearance() {
            let temp = tempfile::tempdir().unwrap();
            assert!(super::super::requires_proof(&temp.path().join("missing")));
            fs::write(temp.path().join("ordinary.txt"), b"keep").unwrap();
            assert!(requires_proof_with_limit(temp.path(), 0).is_none());
            let alias = tempfile::tempdir().unwrap();
            symlink(temp.path(), alias.path().join("root-link")).unwrap();
            assert!(super::super::requires_proof(
                &alias.path().join("root-link")
            ));
        }

        #[test]
        fn generated_names_and_object_extension_are_not_compiler_proof() {
            let temp = tempfile::tempdir().unwrap();
            let session = temp.path().join(CRATE).join(format!("{STEM}-working"));
            fs::create_dir_all(&session).unwrap();
            fs::write(temp.path().join(CRATE).join(format!("{STEM}.lock")), []).unwrap();
            fs::write(session.join("ordinary.o"), b"user data").unwrap();
            assert!(inspect_with_limit(temp.path(), 100).is_none());
        }

        #[test]
        fn finalized_sessions_require_all_three_compiler_metadata_files() {
            let temp = tempfile::tempdir().unwrap();
            let session = temp.path().join(CRATE).join(SESSION);
            fs::create_dir_all(&session).unwrap();
            fs::write(temp.path().join(CRATE).join(format!("{STEM}.lock")), []).unwrap();
            metadata(&session.join("dep-graph.bin"));
            metadata(&session.join("work-products.bin"));
            assert!(inspect_with_limit(temp.path(), 100).is_none());
        }

        #[test]
        fn working_and_orphan_lock_remnants_need_positive_crate_evidence() {
            let (_temp, root, _) = fixture();
            let crate_path = root.join(CRATE);
            let working = "s-012345678a-0123457";
            fs::create_dir(crate_path.join(format!("{working}-working"))).unwrap();
            fs::write(crate_path.join(format!("{working}.lock")), []).unwrap();
            fs::write(crate_path.join("s-012345678b-0123458.lock"), []).unwrap();
            let proof = inspect_with_limit(&root, 100).unwrap();
            assert_eq!(proof.lock_files.len(), 3);
            fs::create_dir(root.join("unproven-0123456789abc")).unwrap();
            assert!(inspect_with_limit(&root, 100).is_none());
        }

        #[test]
        fn working_partial_graph_can_supply_positive_compiler_evidence() {
            let temp = tempfile::tempdir().unwrap();
            let session = temp.path().join(CRATE).join(format!("{STEM}-working"));
            fs::create_dir_all(&session).unwrap();
            fs::write(temp.path().join(CRATE).join(format!("{STEM}.lock")), []).unwrap();
            metadata(&session.join("dep-graph.part.bin"));
            assert!(inspect_with_limit(temp.path(), 100).is_some());
        }

        #[test]
        fn lock_files_must_be_empty_and_have_no_hardlink_aliases() {
            let (_temp, root, _) = fixture();
            let lock = root.join(CRATE).join(format!("{STEM}.lock"));
            fs::write(&lock, b"unexpected lock contents").unwrap();
            assert!(inspect_with_limit(&root, 100).is_none());

            let (_temp, root, session) = fixture();
            let lock = root.join(CRATE).join(format!("{STEM}.lock"));
            fs::hard_link(&lock, session.join("lock-alias.o")).unwrap();
            assert!(inspect_with_limit(&root, 100).is_none());
        }

        #[test]
        fn missing_lock_or_duplicate_session_stem_is_not_a_complete_inventory() {
            let temp = tempfile::tempdir().unwrap();
            let session = temp.path().join(CRATE).join(SESSION);
            fs::create_dir_all(&session).unwrap();
            for name in ["dep-graph.bin", "query-cache.bin", "work-products.bin"] {
                metadata(&session.join(name));
            }
            assert!(inspect_with_limit(temp.path(), 100).is_none());
            fs::write(temp.path().join(CRATE).join(format!("{STEM}.lock")), []).unwrap();
            fs::create_dir(temp.path().join(CRATE).join(format!("{STEM}-working"))).unwrap();
            assert!(inspect_with_limit(temp.path(), 100).is_none());
        }

        #[test]
        fn unknown_contents_veto_at_every_depth() {
            for depth in 0..3 {
                let (_temp, root, session) = fixture();
                let parent = match depth {
                    0 => &root,
                    1 => session.parent().unwrap(),
                    _ => &session,
                };
                fs::write(parent.join("important-source.rs"), b"fn main() {}").unwrap();
                assert!(inspect_with_limit(&root, 100).is_none(), "depth {depth}");
            }
            let (_temp, root, session) = fixture();
            fs::create_dir(session.join("nested-output")).unwrap();
            assert!(inspect_with_limit(&root, 100).is_none());
        }

        #[test]
        fn malformed_or_truncated_headers_never_count_as_proof() {
            for bytes in [
                b"not rustc".as_slice(),
                b"RSIC\0\0\x04test", // header without payload
                b"RSIC\0\0\xffshort",
                b"RSIC\x01\0\x04test\x01", // unsupported format version
                b"RSIC\0\0\x04te\nst\x01",
                b"RSIC\0\0\0payload",
            ] {
                let (_temp, root, session) = fixture();
                fs::write(session.join("dep-graph.bin"), bytes).unwrap();
                assert!(inspect_with_limit(&root, 100).is_none(), "{bytes:?}");
            }
        }

        #[test]
        fn no_symlink_can_supply_a_root_crate_session_lock_or_payload() {
            let (_temp, root, session) = fixture();
            let aliases = tempfile::tempdir().unwrap();
            symlink(&root, aliases.path().join("root-link")).unwrap();
            assert!(inspect_with_limit(&aliases.path().join("root-link"), 100).is_none());
            assert!(inspect_with_limit(&aliases.path().join("root-link/"), 100).is_none());

            let crate_alias = aliases.path().join("crate-root");
            fs::create_dir(&crate_alias).unwrap();
            symlink(root.join(CRATE), crate_alias.join(CRATE)).unwrap();
            assert!(inspect_with_limit(&crate_alias, 100).is_none());

            for (name, target) in [
                ("s-012345678a-0123457-working", session.clone()),
                ("s-012345678a-0123457.lock", session.join("dep-graph.bin")),
            ] {
                let (_temp, root, _) = fixture();
                symlink(&target, root.join(CRATE).join(name)).unwrap();
                assert!(inspect_with_limit(&root, 100).is_none());
            }
            symlink(session.join("dep-graph.bin"), session.join("linked.o")).unwrap();
            assert!(inspect_with_limit(&root, 100).is_none());
        }

        #[test]
        fn lock_payload_and_directory_freshness_and_identity_are_part_of_proof() {
            let (_temp, root, session) = fixture();
            let before = inspect_with_limit(&root, 100).unwrap();
            let future = SystemTime::now() + Duration::from_secs(60);
            let future_time = filetime::FileTime::from_system_time(future);
            for path in [
                root.join(CRATE).join(format!("{STEM}.lock")),
                session.join("example.9f0b-cgu.0.rcgu.o"),
                session,
            ] {
                filetime::set_file_mtime(&path, future_time).unwrap();
                let after = inspect_with_limit(&root, 100).unwrap();
                assert_ne!(before, after);
                assert!(after.latest_modified >= future);
            }
        }

        #[test]
        fn exhausted_entry_budget_and_special_files_fail_closed() {
            let (_temp, root, session) = fixture();
            assert!(inspect_with_limit(&root, 7).is_none());
            assert!(inspect_with_limit(&root, 8).is_some());
            nix::unistd::mkfifo(&session.join("pipe.o"), nix::sys::stat::Mode::S_IRUSR).unwrap();
            assert!(inspect_with_limit(&root, 100).is_none());
        }

        #[test]
        fn grammar_matches_fixed_width_lowercase_rustc_names_and_codegen_outputs() {
            assert!(crate_name(CRATE));
            assert!(session_prefix(STEM));
            assert_eq!(session_name(SESSION), Some((STEM, false)));
            for name in [
                "crate-not-a-hash",
                "crate-zzzzzzzzzzzzz", // exceeds the stable crate id's u64
                "crate-0123456789abC",
                "crate-0123456789abcd",
            ] {
                assert!(!crate_name(name));
            }
            assert!(!session_prefix("s-0123456789-zzzzzzz"));
            assert!(session_name("s-0123456789-0123456-short").is_none());
            for extension in ["o", "asm.o", "dwo", "s", "ll", "bc", "pre-lto.bc", "rmeta"] {
                assert!(work_product(&format!("crate.0123-cgu.0.{extension}")));
            }
            for name in ["main.rs", "Cargo.toml", ".o", "save data.o", "unknown.bin"] {
                assert!(!work_product(name));
            }
        }
    }
}
