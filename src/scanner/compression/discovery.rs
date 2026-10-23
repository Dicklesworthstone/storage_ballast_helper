//! Bounded, descriptor-relative discovery of cold compression candidates.
//!
//! A selection is an observation, not mutation authority. It retains native
//! paths, file stamps and pinned root descriptors for execution revalidation.
//! Discovery never follows directory symlinks or crosses descendant mounts.

use std::io;
use std::path::{Component, Path, PathBuf};

use serde::Serialize;

use super::CompressionPolicy;
use crate::core::config::Config;
use crate::platform::pal::Platform;

/// Traversal limits, independent of the compression rewrite budget.
#[derive(Debug, Clone)]
pub struct DiscoveryLimits {
    /// Maximum directory depth below an explicit root (0 scans its files only).
    pub max_depth: usize,
    /// Maximum directory entries enumerated, including excluded entries.
    pub max_entries: usize,
    /// Maximum directories enumerated.
    pub max_directories: usize,
    /// Cooperative discovery deadline; a blocking filesystem call can exceed it.
    pub timeout_secs: u64,
    /// Resume strictly after this native absolute pathname in sorted traversal.
    /// This is a skip hint, never permission to bypass fresh admission.
    pub after: Option<PathBuf>,
}

impl Default for DiscoveryLimits {
    fn default() -> Self {
        Self {
            max_depth: 32,
            max_entries: 100_000,
            max_directories: 4096,
            timeout_secs: 30,
            after: None,
        }
    }
}

impl DiscoveryLimits {
    /// Reject unbounded input before opening any root.
    pub fn validate(&self) -> io::Result<()> {
        if self.max_depth > 64
            || !(1..=1_000_000).contains(&self.max_entries)
            || !(1..=8192).contains(&self.max_directories)
            || !(1..=60).contains(&self.timeout_secs)
        {
            return Err(invalid(
                "discovery requires depth <= 64, 1..1000000 entries, 1..8192 directories and 1..60 seconds",
            ));
        }
        if let Some(path) = &self.after {
            validate_absolute(path)?;
        }
        Ok(())
    }
}

/// Bounded discovery diagnostics. Paths are display-only; the continuation
/// token separately preserves their exact native bytes.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryReport {
    /// Native discovery is available only with the Linux compression backend.
    pub supported: bool,
    /// Canonical explicit roots, sorted and with overlapping subroots removed.
    pub roots: Vec<String>,
    /// Directory entries actually enumerated, including filtered entries.
    pub entries_examined: usize,
    /// Directories actually enumerated.
    pub directories_opened: usize,
    /// Files selected by metadata; live backend checks still apply to each one.
    pub selected_files: usize,
    /// Selected logical input bytes, not a reclaim estimate.
    pub selected_bytes: u64,
    /// Cheap exclusions, grouped by reason without retaining every filename.
    pub skipped: std::collections::BTreeMap<String, usize>,
    /// False on any budget stop or incomplete read. Never a snapshot guarantee.
    pub complete: bool,
    /// Why discovery stopped before all requested work was examined.
    pub stop_reason: Option<String>,
    /// Native bytes, as lowercase hex, of the path a stopped walk resumes
    /// after: the last selected file when the file limit stopped it, else the
    /// last path visited to completion when a byte, directory, entry or time
    /// budget or a failed entry stopped it. Everything sorted before it is done.
    /// Absent when the walk completed or stopped before visiting anything.
    /// Pass to `--after-hex` to resume.
    pub resume_after_hex: Option<String>,
}

/// Private selection evidence, retained until execution finishes.
#[derive(Debug)]
pub struct Selection {
    report: DiscoveryReport,
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    native: native::Evidence,
}

impl Selection {
    /// Traversal accounting, including incomplete discovery.
    #[must_use]
    pub fn report(&self) -> &DiscoveryReport {
        &self.report
    }

    /// Native paths in deterministic order. These are not an authorization token.
    #[must_use]
    pub fn paths(&self) -> Vec<PathBuf> {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            self.native.files.keys().cloned().collect()
        }
        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        {
            Vec::new()
        }
    }

    /// Recheck both the discovered file and its original root. An old selection
    /// cannot silently admit a replacement or a renamed root.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub fn validate_file(&self, path: &Path, stamp: sbh_btrfs::FileStamp) -> io::Result<()> {
        let candidate = self
            .native
            .files
            .get(path)
            .ok_or_else(|| invalid("file was not observed in this selection"))?;
        if candidate.stamp != stamp {
            return Err(io::Error::other("file changed after compression discovery"));
        }
        self.validate_scope(path)
    }

    /// Recheck root confinement and Git exclusion between chunks without comparing
    /// the original ctime: completed defrag can legitimately change file ctime.
    /// This does not replace the executor's other live protection checks.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub fn validate_scope(&self, path: &Path) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt as _;

        let candidate = self
            .native
            .files
            .get(path)
            .ok_or_else(|| invalid("file was not observed in this selection"))?;
        let root = &self.native.roots[candidate.root];
        if !path.starts_with(&root.path) || path.canonicalize()? != path {
            return Err(io::Error::other(
                "discovered path escaped its original root",
            ));
        }
        let current = native::open_root(&root.path)?;
        let current = current.metadata()?;
        let pinned = root.file.metadata()?;
        if current.dev() != pinned.dev() || current.ino() != pinned.ino() {
            return Err(io::Error::other("compression discovery root was replaced"));
        }
        super::linux::repository::check_file(path)?;
        Ok(())
    }
}

/// Decode a continuation token without converting native filenames to UTF-8.
/// Tokens select no files by themselves and must still lie below an explicit root.
pub fn continuation_path(hex: &str) -> io::Result<PathBuf> {
    if hex.is_empty() || hex.len() > 32_768 || !hex.len().is_multiple_of(2) {
        return Err(invalid("invalid discovery continuation length"));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().as_chunks::<2>().0 {
        let digit = |byte: u8| -> io::Result<u8> {
            match byte {
                b'0'..=b'9' => Ok(byte - b'0'),
                b'a'..=b'f' => Ok(byte - b'a' + 10),
                b'A'..=b'F' => Ok(byte - b'A' + 10),
                _ => Err(invalid("non-hex discovery continuation")),
            }
        };
        bytes.push(digit(pair[0])? * 16 + digit(pair[1])?);
    }
    if bytes.contains(&0) {
        return Err(invalid("NUL in discovery continuation"));
    }
    #[cfg(unix)]
    let path = {
        use std::os::unix::ffi::OsStringExt as _;
        PathBuf::from(std::ffi::OsString::from_vec(bytes))
    };
    #[cfg(not(unix))]
    let path = PathBuf::from(String::from_utf8(bytes).map_err(|_| invalid("invalid path bytes"))?);
    validate_absolute(&path)?;
    Ok(path)
}

fn validate_absolute(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid(
            "discovery continuation must be an absolute path without traversal",
        ));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Discover beneath 1..32 explicit directories without writing files.
///
/// File count and logical-byte admission use `policy`; directory work has its
/// own limits. A partial enumeration is reported as partial, not empty/success.
/// Application protection is checked while walking and must be checked again
/// by the existing compression executor immediately before mutation.
pub fn discover(
    roots: &[PathBuf],
    policy: &CompressionPolicy,
    limits: &DiscoveryLimits,
    config: &Config,
    platform: &dyn Platform,
) -> io::Result<Selection> {
    policy.validate()?;
    limits.validate()?;
    if roots.is_empty() || roots.len() > 32 {
        return Err(invalid("supply 1..32 explicit compression discovery roots"));
    }
    let report = DiscoveryReport {
        supported: cfg!(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )),
        roots: Vec::new(),
        entries_examined: 0,
        directories_opened: 0,
        selected_files: 0,
        selected_bytes: 0,
        skipped: std::collections::BTreeMap::new(),
        complete: true,
        stop_reason: None,
        resume_after_hex: None,
    };
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        native::discover(roots, policy, limits, config, platform, report)
    }
    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    {
        let _ = (config, platform);
        let mut report = report;
        report.stop_reason =
            Some("native compression discovery is unavailable on this target".into());
        Ok(Selection { report })
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod native {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::{self, File};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::time::{Duration, Instant, SystemTime};

    use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat2};
    use sbh_btrfs::FileStamp;

    #[allow(clippy::wildcard_imports)] // the parent module's discovery types
    use super::*;
    use crate::scanner::compression::linux::repository;
    use crate::scanner::{active_lease, protection};

    #[derive(Debug)]
    pub(super) struct Root {
        pub path: PathBuf,
        pub file: File,
    }

    #[derive(Debug)]
    pub(super) struct Candidate {
        pub stamp: FileStamp,
        pub root: usize,
    }

    #[derive(Debug, Default)]
    pub(super) struct Evidence {
        pub roots: Vec<Root>,
        pub files: BTreeMap<PathBuf, Candidate>,
    }

    pub(super) fn open_root(path: &Path) -> io::Result<File> {
        Ok(File::from(openat2(
            CWD,
            path,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?))
    }

    struct Task {
        root: usize,
        relative: PathBuf,
        depth: usize,
    }

    struct Walker<'a> {
        policy: &'a CompressionPolicy,
        limits: &'a DiscoveryLimits,
        deadline: Instant,
        now: SystemTime,
        registry: protection::ProtectionRegistry,
        sacred: Vec<crate::platform::types::SacredPath>,
        selection: Selection,
        pending: Vec<Task>,
        identities: BTreeSet<(u64, u64)>,
        /// The last path visited to completion. The walk is depth-first in
        /// sorted order, so everything sorted before it is done, and a
        /// stopped run resumes after it.
        last_visited: Option<PathBuf>,
    }

    impl Walker<'_> {
        fn skip(&mut self, reason: &str) {
            *self
                .selection
                .report
                .skipped
                .entry(reason.into())
                .or_default() += 1;
        }

        fn budget(&self) -> io::Result<()> {
            if Instant::now() >= self.deadline {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "discovery deadline exhausted",
                ))
            } else {
                Ok(())
            }
        }

        fn protected(&mut self, path: &Path, directory: bool) -> io::Result<bool> {
            let parent = if directory {
                path
            } else {
                path.parent()
                    .ok_or_else(|| invalid("candidate has no parent"))?
            };
            self.registry
                .discover_ancestor_markers(parent)
                .map_err(other)?;
            if self.registry.is_protected(path) || active_lease::path_is_actively_leased(path) {
                return Ok(true);
            }
            Ok(!protection::find_sacred_overlaps_with_config(
                path,
                &self.sacred,
                protection::StowawayScanConfig {
                    max_depth: 0,
                    ..Default::default()
                },
            )
            .map_err(other)?
            .is_empty())
        }

        #[allow(clippy::too_many_lines)] // one directory step, in order
        fn visit(&mut self, task: &Task) -> io::Result<()> {
            self.budget()?;
            let root = &self.selection.native.roots[task.root];
            let path = root.path.join(&task.relative);
            // Skip whole earlier subtrees, but descend into ancestors of the
            // cursor. No filesystem query or mutation is authorized by it.
            if self
                .limits
                .after
                .as_ref()
                .is_some_and(|after| path <= *after && !after.starts_with(&path))
            {
                self.skip("before_cursor");
                return Ok(());
            }
            let relative = if task.relative.as_os_str().is_empty() {
                Path::new(".")
            } else {
                &task.relative
            };
            let file = match openat2(
                &root.file,
                relative,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH
                    | ResolveFlags::NO_SYMLINKS
                    | ResolveFlags::NO_MAGICLINKS
                    | ResolveFlags::NO_XDEV,
            ) {
                Ok(fd) => File::from(fd),
                Err(rustix::io::Errno::LOOP | rustix::io::Errno::XDEV) => {
                    self.skip("symlink_or_mount_boundary");
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            };
            let metadata = file.metadata()?;
            if metadata.file_type().is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
                self.skip("symlink_or_special_file");
                return Ok(());
            }
            // Use the same fresh Git ancestry veto as explicit-file execution.
            // Prune repositories before enumeration, even with a shallow budget
            // or an explicit root that starts inside the worktree/admin tree.
            let directory = if metadata.is_dir() {
                path.as_path()
            } else {
                path.parent()
                    .ok_or_else(|| invalid("candidate has no parent"))?
            };
            if path.file_name().is_some_and(|name| name == ".git")
                || repository::directory_exclusion(directory)?.is_some()
            {
                self.skip("git_repository");
                return Ok(());
            }
            self.budget()?;
            if self.protected(&path, metadata.is_dir())? {
                self.skip("protected_or_leased");
                return Ok(());
            }
            if metadata.is_dir() {
                // Skipped, not a stop: a stop here would recur at the same
                // directory on every resumed run and wedge the walk.
                if task.depth > self.limits.max_depth {
                    self.selection.report.complete = false;
                    self.skip("depth_limit");
                    return Ok(());
                }
                if self.selection.report.directories_opened >= self.limits.max_directories {
                    return Err(io::Error::other("discovery directory budget exhausted"));
                }
                self.selection.report.directories_opened += 1;
                // Enumerate the pinned inode, not a pathname that could now
                // name a symlink. Children are reopened beneath the pinned root.
                let entries = fs::read_dir(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
                let mut names = Vec::new();
                for entry in entries {
                    self.budget()?;
                    if self.selection.report.entries_examined >= self.limits.max_entries {
                        return Err(io::Error::other("discovery entry budget exhausted"));
                    }
                    self.selection.report.entries_examined += 1;
                    names.push(entry?.file_name());
                }
                names.sort();
                // Only enqueue after the WHOLE directory was read and sorted.
                // A truncated read cannot invent a complete ordered prefix.
                for name in names.into_iter().rev() {
                    self.pending.push(Task {
                        root: task.root,
                        relative: task.relative.join(name),
                        depth: task.depth + 1,
                    });
                }
                return Ok(());
            }
            if self
                .limits
                .after
                .as_ref()
                .is_some_and(|after| path <= *after)
            {
                self.skip("before_cursor");
                return Ok(());
            }
            let stamp = FileStamp::read(&file)?;
            if stamp.links != 1 {
                self.skip("hard_linked_or_unlinked");
            } else if stamp.size < self.policy.min_size_bytes {
                self.skip("below_minimum_size");
            } else if !super::super::cold_enough(
                metadata.modified()?,
                self.now,
                self.policy.min_age_secs,
            ) {
                self.skip("young_or_future_timestamp");
            } else if super::super::already_compressed(&path) {
                self.skip("compressed_suffix");
            } else if stamp.size > self.policy.max_bytes {
                // This file cannot fit even an empty pass. Skipping it is
                // necessary for a continuation to reach its smaller siblings.
                self.skip("exceeds_full_byte_budget");
            } else if let Some(reason) = native_exclusion(
                &self.selection.native.roots[task.root].file,
                relative,
                stamp,
                self.deadline,
            )? {
                self.skip(reason);
            } else if stamp.size
                > self
                    .policy
                    .max_bytes
                    .saturating_sub(self.selection.report.selected_bytes)
            {
                // The file fits a fresh pass, so it is unvisited work rather
                // than an exclusion. A "complete" scan here would repeatedly
                // select an earlier prefix even when execution refuses every
                // file in that prefix. Stop BEFORE advancing last_visited.
                return Err(io::Error::other("discovery logical-byte budget exhausted"));
            } else if !self.identities.insert((stamp.device, stamp.inode)) {
                self.skip("duplicate_inode");
            } else {
                self.selection.report.selected_files += 1;
                self.selection.report.selected_bytes += stamp.size;
                self.selection.native.files.insert(
                    path,
                    Candidate {
                        stamp,
                        root: task.root,
                    },
                );
            }
            Ok(())
        }
    }

    /// Keep known native vetoes out of the selection budget. Probe failure is
    /// not eligibility: the executor still performs full fresh inspection.
    /// Discovery's own deadline, including time spent probing, still stops the
    /// page rather than admitting more work after an uncertain late result.
    fn native_exclusion(
        root: &File,
        relative: &Path,
        expected: FileStamp,
        deadline: Instant,
    ) -> io::Result<Option<&'static str>> {
        let exclusion = openat2(
            root,
            relative,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        )
        .map(File::from)
        .map_err(io::Error::from)
        .and_then(|file| {
            if FileStamp::read(&file)? != expected {
                return Err(io::Error::other("file changed before discovery probing"));
            }
            sbh_btrfs::discovery_exclusion(&file, deadline)
        });
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "discovery deadline exhausted",
            ));
        }
        Ok(exclusion.ok().flatten())
    }

    pub(super) fn discover(
        roots: &[PathBuf],
        policy: &CompressionPolicy,
        limits: &DiscoveryLimits,
        config: &Config,
        platform: &dyn Platform,
        mut report: DiscoveryReport,
    ) -> io::Result<Selection> {
        let deadline = Instant::now() + Duration::from_secs(limits.timeout_secs);
        let mut canonical = BTreeSet::new();
        for path in roots {
            let metadata = fs::symlink_metadata(path)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(invalid(
                    "discovery roots must be real directories, not symlinks or files",
                ));
            }
            let resolved = path.canonicalize()?;
            let pinned = open_root(&resolved)?.metadata()?;
            if pinned.dev() != metadata.dev() || pinned.ino() != metadata.ino() {
                return Err(io::Error::other("discovery root changed during resolution"));
            }
            canonical.insert(resolved);
        }
        let mut evidence = Evidence::default();
        for path in canonical {
            if evidence
                .roots
                .iter()
                .any(|root| path.starts_with(&root.path))
            {
                continue;
            }
            let file = open_root(&path)?;
            report.roots.push(path.to_string_lossy().into_owned());
            evidence.roots.push(Root { path, file });
        }
        if limits.after.as_ref().is_some_and(|after| {
            !evidence
                .roots
                .iter()
                .any(|root| after.starts_with(&root.path))
        }) {
            return Err(invalid(
                "continuation is outside the explicitly selected roots",
            ));
        }
        let pending = (0..evidence.roots.len())
            .rev()
            .map(|root| Task {
                root,
                relative: PathBuf::new(),
                depth: 0,
            })
            .collect();
        let mut walker = Walker {
            policy,
            limits,
            deadline,
            now: SystemTime::now(),
            registry: protection::ProtectionRegistry::new(Some(&config.scanner.protected_paths))
                .map_err(other)?,
            sacred: platform.sacred_paths(),
            selection: Selection {
                report,
                native: evidence,
            },
            pending,
            identities: BTreeSet::new(),
            last_visited: None,
        };
        while let Some(task) = walker.pending.pop() {
            if walker.selection.report.selected_files >= policy.max_files {
                walker.selection.report.complete = false;
                walker.selection.report.stop_reason =
                    Some("discovery file-count budget exhausted".into());
                walker.selection.report.resume_after_hex = walker
                    .selection
                    .native
                    .files
                    .last_key_value()
                    .map(|(path, _)| crate::core::hex_lower(path.as_os_str().as_encoded_bytes()));
                break;
            }
            let path = walker.selection.native.roots[task.root]
                .path
                .join(&task.relative);
            match walker.visit(&task) {
                Ok(()) => walker.last_visited = Some(path),
                Err(error) => {
                    walker.selection.report.complete = false;
                    walker.selection.report.stop_reason = Some(error.to_string());
                    // Any stop (a budget, or an entry that vanished or could
                    // not be read) resumes after the last path visited to
                    // completion: a truncated directory read is never
                    // claimed, and the failed entry is simply retried.
                    walker.selection.report.resume_after_hex = walker
                        .last_visited
                        .as_ref()
                        .map(|path| crate::core::hex_lower(path.as_os_str().as_encoded_bytes()));
                    break;
                }
            }
        }
        Ok(walker.selection)
    }

    fn other(error: impl std::fmt::Display) -> io::Error {
        io::Error::other(error.to_string())
    }
}

#[cfg(test)]
mod tests;
