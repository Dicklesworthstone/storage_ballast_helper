//! Live authority for standalone rustc incremental-cache removal.
//!
//! A classifier label is not deletion authority. Re-prove the whole layout,
//! pin every session lock, and bind the confined unlink traversal to exactly
//! the entries that were inspected. A compiler can create a new session with
//! a new lock even while all old sessions are locked: that new entry must
//! never inherit the old cache's permission to be removed.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use super::{CandidacyScore, DeletionMode, SkipReason};
use crate::scanner::rustc_incremental::{self, IncrementalCache};
use crate::scanner::walker::{self, FsEntryKind, FsIdentity};

// rustc creates a session lock before acquiring it. Match its own orphan-lock
// grace rather than mistake that brief unlocked interval for an idle session.
const LOCK_CREATION_GRACE: Duration = Duration::from_secs(10);

/// Locks remain owned until the entire confined removal has returned.
pub(super) struct Guard {
    entries: BTreeMap<PathBuf, FsIdentity>,
    locks: Vec<File>,
    owner_pid: u32,
}

impl Drop for Guard {
    fn drop(&mut self) {
        #[cfg(unix)]
        if self.owner_pid == std::process::id() {
            // Do not leave locks held by a temporarily inherited descriptor
            // in an unrelated child. A forked copy must not unlock its parent.
            for file in &self.locks {
                let _ = rustix::fs::flock(file, rustix::fs::FlockOperation::Unlock);
            }
        }
    }
}

impl Guard {
    /// Called before descent and again immediately before each unlink.
    pub(super) fn authorize_entry(
        &self,
        relative: &Path,
        device: u64,
        inode: u64,
        is_directory: bool,
    ) -> io::Result<()> {
        let kind = if is_directory {
            FsEntryKind::Directory
        } else {
            FsEntryKind::File
        };
        let current = FsIdentity {
            device_id: device,
            inode,
            kind,
        };
        if self.entries.get(relative) != Some(&current) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "incremental-cache entry was added or replaced after its session locks were acquired",
            ));
        }
        Ok(())
    }
}

/// Check both the supplied label and the actual layout: a public or stale
/// candidate relabeled as an ordinary target must not bypass compiler locks.
fn needs_binding(candidate: &CandidacyScore) -> bool {
    candidate.classification.pattern_name != rustc_incremental::PATTERN_NAME
        && fs::symlink_metadata(&candidate.path).is_ok_and(|metadata| metadata.is_dir())
        && rustc_incremental::requires_proof(&candidate.path)
}

/// Preserve the safety requirement through caller hooks even if the layout
/// subsequently becomes unrecognizable. This never increases the score or
/// changes the decision/category; the label only requires additional proof.
pub(super) fn bind_owned(mut candidate: CandidacyScore) -> CandidacyScore {
    if needs_binding(&candidate) {
        candidate.classification.pattern_name = Cow::Borrowed(rustc_incremental::PATTERN_NAME);
    }
    candidate
}

pub(super) fn bind(candidate: &CandidacyScore) -> Cow<'_, CandidacyScore> {
    if needs_binding(candidate) {
        let mut bound = candidate.clone();
        bound.classification.pattern_name = Cow::Borrowed(rustc_incremental::PATTERN_NAME);
        Cow::Owned(bound)
    } else {
        Cow::Borrowed(candidate)
    }
}

fn inspect_candidate(candidate: &CandidacyScore) -> Result<Option<IncrementalCache>, SkipReason> {
    let labelled = candidate.classification.pattern_name == rustc_incremental::PATTERN_NAME;
    let metadata = fs::symlink_metadata(&candidate.path).map_err(|_| SkipReason::PathGone)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return if labelled {
            Err(SkipReason::Vetoed)
        } else {
            Ok(None)
        };
    }
    let path = fs::canonicalize(&candidate.path).map_err(|_| SkipReason::Vetoed)?;
    if !labelled && !rustc_incremental::requires_proof(&path) {
        return Ok(None);
    }
    match rustc_incremental::inspect(&path) {
        Some(cache) => Ok(Some(cache)),
        None => Err(SkipReason::Vetoed),
    }
}

/// Whole-root rename cannot exclude a new, independently locked session.
/// Preserve the recoverability contract by refusing, never unlinking instead.
pub(super) fn check_mode(candidate: &CandidacyScore, mode: DeletionMode) -> Result<(), SkipReason> {
    if mode == DeletionMode::Quarantine && inspect_candidate(candidate)?.is_some() {
        return Err(SkipReason::IncrementalQuarantineUnsupported);
    }
    Ok(())
}

/// Admission probes locks without retaining them across a queued plan.
pub(super) fn check(candidate: &CandidacyScore) -> Result<(), SkipReason> {
    let Some(cache) = inspect_candidate(candidate)? else {
        return Ok(());
    };
    let _guard = lock_cache(cache)?;
    Ok(())
}

/// Renew the proof after all caller hooks; the returned guard must outlive
/// actual removal, including every descriptor-relative child operation.
pub(super) fn acquire(candidate: &CandidacyScore) -> Result<Option<Guard>, SkipReason> {
    inspect_candidate(candidate)?.map(lock_cache).transpose()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn lock_cache(cache: IncrementalCache) -> Result<Guard, SkipReason> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    use rustix::fs::{FlockOperation, OFlags};

    if SystemTime::now()
        .duration_since(cache.latest_modified)
        .map_or(true, |idle| idle < LOCK_CREATION_GRACE)
    {
        return Err(SkipReason::FileOpen);
    }
    let root = cache.entries.first().ok_or(SkipReason::Vetoed)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&root.path)
        .map_err(|_| SkipReason::Vetoed)?;
    if walker::entry_metadata(&directory.metadata().map_err(|_| SkipReason::Vetoed)?).identity()
        != root.identity
    {
        return Err(SkipReason::IdentityMismatch);
    }
    let entries: BTreeMap<_, _> = cache
        .entries
        .iter()
        .map(|entry| {
            entry
                .path
                .strip_prefix(&root.path)
                .map(|relative| (relative.to_path_buf(), entry.identity))
                .map_err(|_| SkipReason::Vetoed)
        })
        .collect::<Result<_, _>>()?;
    let mut guard = Guard {
        entries,
        locks: Vec::with_capacity(cache.lock_files.len()),
        owner_pid: std::process::id(),
    };
    for path in &cache.lock_files {
        let relative = path
            .strip_prefix(&root.path)
            .map_err(|_| SkipReason::Vetoed)?;
        let mut parts = relative.components();
        let Some(std::path::Component::Normal(crate_name)) = parts.next() else {
            return Err(SkipReason::Vetoed);
        };
        let Some(std::path::Component::Normal(lock_name)) = parts.next() else {
            return Err(SkipReason::Vetoed);
        };
        if parts.next().is_some() {
            return Err(SkipReason::Vetoed);
        }
        let parent = File::from(
            crate::scanner::quarantine::open_beneath(
                &directory,
                crate_name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            )
            .map_err(|_| SkipReason::Vetoed)?,
        );
        let parent_identity =
            walker::entry_metadata(&parent.metadata().map_err(|_| SkipReason::Vetoed)?).identity();
        if guard.entries.get(Path::new(crate_name)) != Some(&parent_identity) {
            return Err(SkipReason::IdentityMismatch);
        }
        // Open existing files only, without following a link or crossing a
        // mount. RDWR supports exclusive flock on network filesystems too;
        // lack of write permission is a refusal, never permission widening.
        let file = File::from(
            crate::scanner::quarantine::open_beneath(
                &parent,
                lock_name,
                OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            )
            .map_err(|_| SkipReason::Vetoed)?,
        );
        let identity =
            walker::entry_metadata(&file.metadata().map_err(|_| SkipReason::Vetoed)?).identity();
        if identity.kind != FsEntryKind::File || guard.entries.get(relative) != Some(&identity) {
            return Err(SkipReason::IdentityMismatch);
        }
        // The pinned rustc uses flock on Linux. Darwin interoperates flock
        // with rustc's POSIX record locks across processes. Keep one locking
        // interface in this process, with descriptor-scoped ownership.
        rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK {
                SkipReason::FileOpen
            } else {
                SkipReason::Vetoed
            }
        })?;
        guard.locks.push(file);
    }
    // Lock acquisition and header reads can race compiler publication. The
    // full identity/timestamp inventory must still agree once every lock is
    // held; afterward the per-entry allowlist excludes all new sessions.
    if rustc_incremental::inspect(&root.path).as_ref() != Some(&cache) {
        return Err(SkipReason::Vetoed);
    }
    Ok(guard)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn lock_cache(_cache: IncrementalCache) -> Result<Guard, SkipReason> {
    Err(SkipReason::Vetoed)
}
