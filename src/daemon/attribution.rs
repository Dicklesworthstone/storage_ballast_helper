//! Bounded, read-only attribution of a mount the daemon cannot reclaim.
//!
//! Diagnostics run on the monitor thread. One shared entry/time budget must
//! cover discovery and every consumer, not restart for each directory. Sizes
//! describe observed allocated blocks, never deletion authority or a promise
//! of reclaimable space. Kernel I/O may outlast the cooperative deadline.

use std::collections::HashSet;
use std::ffi::CStr;
use std::fmt::Write as _;
use std::fs::{File, Metadata};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat, open, openat, statat};

/// Top-level directories whose children are reported instead of themselves.
const CONTAINERS: &[&str] = &["home", "data", "var", "srv", "opt", "Users", "root"];
/// Directory-read attempts shared by discovery and all recursive probes.
pub const PROBE_BUDGET_ENTRIES: usize = 400_000;
/// Cooperative wall-time allowance for the entire monitor-thread diagnostic.
pub const PROBE_TIME_BUDGET: Duration = Duration::from_secs(2);
/// Entries named in one daemon report.
pub const REPORT_TOP: usize = 8;
const MAX_DISCOVERY_READS: usize = 4096;
const MAX_CONSUMERS: usize = 128;
const MAX_DEPTH: usize = 32;
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// One consumer's observed allocation on the selected filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consumer {
    /// Display path, not execution authority.
    pub path: PathBuf,
    /// Allocated bytes; a lower bound when coverage is incomplete.
    pub bytes: u64,
    /// Whether discovery and this consumer's traversal completed unchanged.
    pub complete: bool,
}

struct WorkBudget {
    remaining: usize,
    examined: usize,
    deadline: Instant,
}

impl WorkBudget {
    fn take(&mut self, allowance: &mut usize, deadline: Instant) -> bool {
        if self.remaining == 0
            || *allowance == 0
            || Instant::now() >= deadline.min(self.deadline)
        {
            return false;
        }
        self.remaining -= 1;
        self.examined += 1;
        *allowance -= 1;
        true
    }
}

struct Candidate {
    path: PathBuf,
    directory: File,
    stamp: Metadata,
}

/// Largest observed directories on `mount`, with conventional containers
/// expanded by one level. No descendant symlink is followed. File descriptors,
/// depth, retained consumers, directory reads and wall time are all bounded.
/// A truncated inventory marks every returned size incomplete: the ranking is
/// among observed consumers, not a claim that unobserved consumers are smaller.
#[must_use]
pub fn top_consumers(mount: &Path, budget: usize, top: usize) -> Vec<Consumer> {
    let mut work = WorkBudget {
        remaining: budget.min(PROBE_BUDGET_ENTRIES),
        examined: 0,
        deadline: Instant::now() + PROBE_TIME_BUDGET,
    };
    collect_consumers(mount, top, &mut work)
}

fn unknown(mount: &Path) -> Vec<Consumer> {
    vec![Consumer {
        path: mount.to_path_buf(),
        bytes: 0,
        complete: false,
    }]
}

fn collect_consumers(mount: &Path, top: usize, work: &mut WorkBudget) -> Vec<Consumer> {
    if top == 0 {
        return Vec::new();
    }
    if work.remaining == 0 || Instant::now() >= work.deadline {
        return unknown(mount);
    }
    // The configured anchor may be an OS alias (/var on macOS). Resolve it
    // once, then pin its descriptor; traversal below it is always relative.
    let root = std::fs::canonicalize(mount).and_then(|path| {
        open(&path, DIRECTORY_FLAGS, Mode::empty())
            .map(File::from)
            .map_err(io::Error::from)
    });
    let Ok(root) = root else {
        return unknown(mount);
    };
    let Ok(stamp) = root.metadata() else {
        return unknown(mount);
    };
    let device = stamp.dev();
    let mut candidates = Vec::new();
    let mut discovery = work.remaining.min(MAX_DISCOVERY_READS);
    let discovery_complete = discover(
        &root,
        mount,
        device,
        true,
        &mut candidates,
        work,
        &mut discovery,
    );
    if candidates.is_empty() {
        return if discovery_complete {
            Vec::new()
        } else {
            unknown(mount)
        };
    }
    candidates.sort_by(|a, b| a.path.cmp(&b.path));
    let count = candidates.len();
    let mut consumers = Vec::with_capacity(count);
    let mut seen = HashSet::new();
    for (index, candidate) in candidates.into_iter().enumerate() {
        // Reserve a share for every observed consumer instead of allowing the
        // first large tree to monopolize either remaining budget.
        let left = count - index;
        let mut allowance = work.remaining / left;
        let now = Instant::now();
        let divisor = u32::try_from(left).unwrap_or(u32::MAX);
        let deadline = now + work.deadline.saturating_duration_since(now) / divisor;
        let (bytes, complete) = measure_directory(
            &candidate.directory,
            device,
            0,
            work,
            &mut allowance,
            deadline,
            &mut seen,
        );
        let unchanged = candidate
            .directory
            .metadata()
            .is_ok_and(|after| same_stamp(&candidate.stamp, &after));
        consumers.push(Consumer {
            path: candidate.path,
            bytes,
            complete: complete && unchanged && discovery_complete,
        });
    }
    if !root
        .metadata()
        .is_ok_and(|after| same_stamp(&stamp, &after))
    {
        for consumer in &mut consumers {
            consumer.complete = false;
        }
    }
    consumers.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));
    consumers.truncate(top.min(MAX_CONSUMERS));
    consumers
}

#[allow(clippy::too_many_arguments)]
fn discover(
    directory: &File,
    path: &Path,
    device: u64,
    expand: bool,
    candidates: &mut Vec<Candidate>,
    work: &mut WorkBudget,
    allowance: &mut usize,
) -> bool {
    let Ok(stamp) = directory.metadata() else {
        return false;
    };
    let Ok(mut entries) = Dir::read_from(directory) else {
        return false;
    };
    let mut complete = true;
    loop {
        if !work.take(allowance, work.deadline) {
            return false;
        }
        let Some(entry) = entries.read() else {
            break;
        };
        let Ok(entry) = entry else {
            complete = false;
            continue;
        };
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        let Ok(stat) = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) else {
            complete = false;
            continue;
        };
        if stat_device(&stat) != Some(device)
            || !FileType::from_raw_mode(stat.st_mode).is_dir()
        {
            continue;
        }
        if candidates.len() >= MAX_CONSUMERS {
            return false;
        }
        let Ok(child) = open_directory(directory, name, &stat) else {
            complete = false;
            continue;
        };
        let child_path = path.join(std::ffi::OsStr::from_bytes(name.to_bytes()));
        if expand && name.to_str().is_ok_and(|name| CONTAINERS.contains(&name)) {
            complete &= discover(
                &child,
                &child_path,
                device,
                false,
                candidates,
                work,
                allowance,
            );
        } else if let Ok(stamp) = child.metadata() {
            candidates.push(Candidate {
                path: child_path,
                directory: child,
                stamp,
            });
        } else {
            complete = false;
        }
    }
    complete
        && directory
            .metadata()
            .is_ok_and(|after| same_stamp(&stamp, &after))
}

#[allow(clippy::too_many_arguments)]
fn measure_directory(
    directory: &File,
    device: u64,
    depth: usize,
    work: &mut WorkBudget,
    allowance: &mut usize,
    deadline: Instant,
    seen: &mut HashSet<(u64, u64)>,
) -> (u64, bool) {
    if Instant::now() >= deadline.min(work.deadline) {
        return (0, false);
    }
    let Ok(stamp) = directory.metadata() else {
        return (0, false);
    };
    if stamp.dev() != device || !seen.insert((stamp.dev(), stamp.ino())) {
        return (0, false);
    }
    let Some(mut bytes) = stamp.blocks().checked_mul(512) else {
        return (0, false);
    };
    if depth >= MAX_DEPTH {
        return (bytes, false);
    }
    let Ok(mut entries) = Dir::read_from(directory) else {
        return (bytes, false);
    };
    let mut complete = true;
    loop {
        if !work.take(allowance, deadline) {
            complete = false;
            break;
        }
        let Some(entry) = entries.read() else {
            break;
        };
        let Ok(entry) = entry else {
            complete = false;
            continue;
        };
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        let Ok(stat) = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) else {
            complete = false;
            continue;
        };
        if stat_device(&stat) != Some(device) {
            continue;
        }
        let observed = if FileType::from_raw_mode(stat.st_mode).is_dir() {
            match open_directory(directory, name, &stat) {
                Ok(child) => {
                    let (child_bytes, child_complete) = measure_directory(
                        &child,
                        device,
                        depth + 1,
                        work,
                        allowance,
                        deadline,
                        seen,
                    );
                    complete &= child_complete;
                    child_bytes
                }
                Err(_) => {
                    complete = false;
                    continue;
                }
            }
        } else {
            let Some(inode) = stat_inode(&stat) else {
                complete = false;
                continue;
            };
            if !seen.insert((device, inode)) {
                complete = false;
                continue;
            }
            let Some(allocated) = stat_blocks(&stat) else {
                complete = false;
                continue;
            };
            allocated
        };
        let Some(total) = bytes.checked_add(observed) else {
            complete = false;
            break;
        };
        bytes = total;
    }
    (
        bytes,
        complete
            && directory
                .metadata()
                .is_ok_and(|after| same_stamp(&stamp, &after)),
    )
}

fn open_directory(parent: &File, name: &CStr, expected: &Stat) -> io::Result<File> {
    let file = File::from(openat(parent, name, DIRECTORY_FLAGS, Mode::empty())?);
    let metadata = file.metadata()?;
    if stat_device(expected) != Some(metadata.dev())
        || stat_inode(expected) != Some(metadata.ino())
    {
        return Err(io::Error::other("directory changed before attribution"));
    }
    Ok(file)
}

// libc's stat integer widths/signedness differ across supported platforms.
#[allow(clippy::useless_conversion)]
fn stat_device(stat: &Stat) -> Option<u64> {
    u64::try_from(stat.st_dev).ok()
}

#[allow(clippy::useless_conversion)]
fn stat_inode(stat: &Stat) -> Option<u64> {
    u64::try_from(stat.st_ino).ok()
}

#[allow(clippy::useless_conversion)]
fn stat_blocks(stat: &Stat) -> Option<u64> {
    u64::try_from(stat.st_blocks).ok()?.checked_mul(512)
}

fn same_stamp(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

/// Describe observations; `>=` marks lower bounds, not reclaimable bytes.
#[must_use]
pub fn describe(consumers: &[Consumer]) -> String {
    let mut out = String::new();
    for (index, consumer) in consumers.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        #[allow(clippy::cast_precision_loss)]
        let gib = consumer.bytes as f64 / 1_073_741_824.0;
        let bound = if consumer.complete { "" } else { ">=" };
        // Debug escaping keeps hostile file names from injecting log lines or
        // terminal control sequences. These paths are display-only.
        let _ = write!(out, "{:?} {bound}{gib:.1} GiB", consumer.path);
    }
    if consumers.iter().any(|consumer| !consumer.complete) {
        out.push_str(" (partial observation; unobserved entries may be larger)");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn largest_directories_first_with_containers_expanded() {
        let mount = tempfile::tempdir().unwrap();
        let big = mount.path().join("home/alice/cache");
        let small = mount.path().join("tools");
        fs::create_dir_all(&big).unwrap();
        fs::create_dir_all(&small).unwrap();
        fs::write(big.join("blob"), vec![7u8; 2 * 1024 * 1024]).unwrap();
        fs::write(small.join("f"), vec![7u8; 64 * 1024]).unwrap();
        let consumers = top_consumers(mount.path(), PROBE_BUDGET_ENTRIES, REPORT_TOP);
        let paths: Vec<&Path> = consumers.iter().map(|c| c.path.as_path()).collect();
        assert_eq!(
            paths,
            vec![mount.path().join("home/alice").as_path(), small.as_path()]
        );
        assert!(consumers[0].bytes >= 2 * 1024 * 1024);
        assert!(consumers.iter().all(|c| c.complete));
    }

    #[test]
    fn budget_truncation_is_reported_as_a_lower_bound() {
        let mount = tempfile::tempdir().unwrap();
        let wide = mount.path().join("wide");
        fs::create_dir(&wide).unwrap();
        for index in 0..20 {
            fs::write(wide.join(format!("f{index}")), b"x").unwrap();
        }
        let consumers = top_consumers(mount.path(), 5, REPORT_TOP);
        assert_eq!(consumers.len(), 1);
        assert!(!consumers[0].complete);
        assert!(describe(&consumers).contains(">="));
    }

    #[test]
    fn directory_reads_share_one_budget_across_all_consumers() {
        let mount = tempfile::tempdir().unwrap();
        for index in 0..8 {
            let dir = mount.path().join(format!("tree-{index}"));
            fs::create_dir(&dir).unwrap();
            for file in 0..40 {
                fs::write(dir.join(format!("f{file}")), b"x").unwrap();
            }
        }
        let mut work = WorkBudget {
            remaining: 100,
            examined: 0,
            deadline: Instant::now() + Duration::from_secs(30),
        };
        let consumers = collect_consumers(mount.path(), 8, &mut work);
        assert_eq!(consumers.len(), 8);
        assert!(work.examined <= 100);
        assert_eq!(work.examined + work.remaining, 100);
        assert!(consumers.iter().all(|consumer| !consumer.complete));
    }

    #[test]
    fn exhausted_deadline_is_unknown_not_an_empty_healthy_inventory() {
        let mount = tempfile::tempdir().unwrap();
        let mut work = WorkBudget {
            remaining: 100,
            examined: 0,
            deadline: Instant::now(),
        };
        let consumers = collect_consumers(mount.path(), REPORT_TOP, &mut work);
        assert_eq!(work.examined, 0);
        assert_eq!(consumers, unknown(mount.path()));
        assert!(top_consumers(mount.path(), 100, 0).is_empty());
        assert_eq!(top_consumers(mount.path(), 0, 8), unknown(mount.path()));
    }

    #[test]
    fn descendant_symlink_never_attributes_its_target() {
        let mount = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("large"), vec![1u8; 1024 * 1024]).unwrap();
        let tree = mount.path().join("tree");
        fs::create_dir(&tree).unwrap();
        std::os::unix::fs::symlink(outside.path(), tree.join("escape")).unwrap();
        std::os::unix::fs::symlink(outside.path(), mount.path().join("alias")).unwrap();
        let consumers = top_consumers(mount.path(), 100, 8);
        assert_eq!(consumers.len(), 1);
        assert_eq!(consumers[0].path, tree);
        assert!(consumers[0].bytes < 1024 * 1024);
    }

    #[test]
    fn directory_replacement_is_refused_before_descent() {
        let mount = tempfile::tempdir().unwrap();
        fs::create_dir(mount.path().join("tree")).unwrap();
        let root = File::open(mount.path()).unwrap();
        let expected = statat(&root, c"tree", AtFlags::SYMLINK_NOFOLLOW).unwrap();
        fs::rename(mount.path().join("tree"), mount.path().join("saved")).unwrap();
        fs::create_dir(mount.path().join("tree")).unwrap();
        assert!(open_directory(&root, c"tree", &expected).is_err());
    }

    #[test]
    fn depth_limit_preserves_partial_evidence() {
        let mount = tempfile::tempdir().unwrap();
        let mut path = mount.path().join("tree");
        for _ in 0..MAX_DEPTH + 3 {
            fs::create_dir(&path).unwrap();
            path = path.join("d");
        }
        let consumers = top_consumers(mount.path(), 10_000, 8);
        assert_eq!(consumers.len(), 1);
        assert!(!consumers[0].complete);
    }

    #[test]
    fn missing_root_and_control_characters_remain_explicit() {
        let mount = tempfile::tempdir().unwrap();
        let missing = mount.path().join("missing");
        assert_eq!(top_consumers(&missing, 100, 8), unknown(&missing));
        let text = describe(&[Consumer {
            path: PathBuf::from("/tmp/a\n\x1b[2J"),
            bytes: 1024,
            complete: false,
        }]);
        assert!(!text.contains('\n'));
        assert!(!text.contains('\x1b'));
        assert!(text.contains("partial observation"));
    }
}
