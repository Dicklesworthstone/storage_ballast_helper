//! Bounded, read-only attribution of a mount the daemon cannot reclaim.
//!
//! One shared entry/time budget covers discovery and every consumer. The
//! monitor waits only for a bounded receive, never joins a timed-out probe,
//! and admits no replacement while that probe is still in filesystem I/O.
//! Sizes describe observed allocated blocks, never deletion authority or a
//! promise of reclaimable space. These are not atomic filesystem snapshots.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::fmt::Write as _;
use std::fs::{File, Metadata};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, mpsc};
use std::time::{Duration, Instant};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat, open, openat, statat};

/// Top-level directories whose children are reported instead of themselves.
const CONTAINERS: &[&str] = &["home", "data", "var", "srv", "opt", "Users", "root"];
/// Directory-read attempts shared by discovery and all recursive probes.
///
/// The budget is split evenly over the top-level consumers. At 400k entries
/// and 1.5 s, a multi-terabyte mount gave each one ~50 ms: the trees holding
/// hundreds of GiB measured ~0 and the advice named whatever fit, such as a
/// 5 GiB placeholder on ts2 or "/Applications >=0.1 GiB" on mac-studio with
/// 590 GiB of agent scratch in /private (bd-q4nx). A report runs on its own
/// thread at most hourly per mount under sustained Red, and only hard-linked
/// files are remembered, so the larger budget costs seconds, not memory.
pub const PROBE_BUDGET_ENTRIES: usize = 2_000_000;
/// Cooperative allowance, leaving time to publish a partial observation.
pub const PROBE_TIME_BUDGET: Duration = Duration::from_secs(10);
/// Receive timeout of the reporting thread; no join follows a timeout. Not a
/// real-time guarantee. The monitor never waits on it.
pub const PROBE_WAIT_BUDGET: Duration = Duration::from_secs(12);
/// Entries named in one daemon report.
pub const REPORT_TOP: usize = 8;
const MAX_DISCOVERY_READS: usize = 4096;
const MAX_CONSUMERS: usize = 128;
const MAX_DEPTH: usize = 32;
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

// Shared across mounts: a stuck mount must not accumulate a new blocked
// worker on every attribution attempt. No logger or daemon handle is retained.
static PROBE_ACTIVE: OnceLock<Arc<AtomicBool>> = OnceLock::new();

struct ProbePermit(Arc<AtomicBool>);

impl Drop for ProbePermit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn bounded_probe(
    active: Arc<AtomicBool>,
    deadline: Instant,
    probe: impl FnOnce() -> Vec<Consumer> + Send + 'static,
) -> Option<Vec<Consumer>> {
    if Instant::now() >= deadline
        || active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return None;
    }
    // The worker owns admission, not the waiting monitor. Timeout must not
    // clear it. Dropping the closure on spawn failure or unwinding a worker
    // releases it; a kernel-blocked worker continues to hold it.
    let permit = ProbePermit(active);
    let (tx, rx) = mpsc::sync_channel(1);
    let worker = std::thread::Builder::new()
        .name("sbh-attribution".to_owned())
        .spawn(move || {
            let result = probe();
            drop(permit);
            // Each invocation has its own receiver. A late result is dropped,
            // never presented as a fresh observation of another mount.
            let _ = tx.send(result);
        })
        .ok()?;
    drop(worker);
    rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .ok()
}

/// One consumer's observed allocation on the selected filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consumer {
    /// Display path, not execution authority.
    pub path: PathBuf,
    /// Allocated bytes; a lower bound when coverage is incomplete.
    pub bytes: u64,
    /// Whether discovery and this consumer's traversal completed unchanged.
    pub complete: bool,
    /// For an unfinished consumer, a sampled estimate of its whole size
    /// ([`estimate_tree`]): it ranks the consumer and is shown as one, never
    /// as a measurement (bd-q4nx).
    pub estimated: Option<u64>,
}

impl Consumer {
    /// The size it ranks by: the estimate when it exceeds the measurement.
    fn rank_bytes(&self) -> u64 {
        self.estimated
            .map_or(self.bytes, |estimate| estimate.max(self.bytes))
    }
}

struct WorkBudget {
    remaining: usize,
    examined: usize,
    deadline: Instant,
}

impl WorkBudget {
    fn take(&mut self, allowance: &mut usize, deadline: Instant) -> bool {
        if self.remaining == 0 || *allowance == 0 || Instant::now() >= deadline.min(self.deadline) {
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

/// Largest observed directories on `mount`.
///
/// Conventional containers are expanded by one level. No descendant symlink
/// is followed. File descriptors, depth, retained consumers, directory reads
/// and monitor waiting are bounded.
/// A truncated inventory marks every returned size incomplete: the ranking is
/// among observed consumers, not a claim that unobserved consumers are smaller.
/// Busy, stalled or failed probes return an explicitly incomplete observation.
#[must_use]
pub fn top_consumers(mount: &Path, budget: usize, top: usize) -> Vec<Consumer> {
    let active = Arc::clone(PROBE_ACTIVE.get_or_init(|| Arc::new(AtomicBool::new(false))));
    top_consumers_with_gate(mount, budget, top, active)
}

fn top_consumers_with_gate(
    mount: &Path,
    budget: usize,
    top: usize,
    active: Arc<AtomicBool>,
) -> Vec<Consumer> {
    if top == 0 {
        return Vec::new();
    }
    if budget == 0 {
        return unknown(mount);
    }
    let started = Instant::now();
    let anchor = mount.to_path_buf();
    bounded_probe(active, started + PROBE_WAIT_BUDGET, move || {
        let mut work = WorkBudget {
            remaining: budget.min(PROBE_BUDGET_ENTRIES),
            examined: 0,
            deadline: started + PROBE_TIME_BUDGET,
        };
        // All filesystem calls, including anchor resolution, stay off the
        // monitor. A cooperative deadline alone cannot bound blocked I/O.
        collect_consumers(&anchor, top, &mut work)
    })
    .unwrap_or_else(|| unknown(mount))
}

fn unknown(mount: &Path) -> Vec<Consumer> {
    vec![Consumer {
        path: mount.to_path_buf(),
        bytes: 0,
        complete: false,
        estimated: None,
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
    // Half the entries and time samples the consumers the walk cannot finish,
    // so their size is estimated rather than read off whatever part of them
    // fit (bd-q4nx).
    let estimate_entries = work.remaining / 2;
    work.remaining -= estimate_entries;
    let started = Instant::now();
    let walk_until = started + work.deadline.saturating_duration_since(started) / 2;
    let count = candidates.len();
    let mut measured = Vec::with_capacity(count);
    let mut seen = HashSet::new();
    for (index, candidate) in candidates.into_iter().enumerate() {
        // Reserve a share for every observed consumer instead of allowing the
        // first large tree to monopolize either remaining budget.
        let left = count - index;
        let mut allowance = work.remaining / left;
        let now = Instant::now();
        let divisor = u32::try_from(left).unwrap_or(u32::MAX);
        let deadline = now + walk_until.saturating_duration_since(now) / divisor;
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
        let consumer = Consumer {
            path: candidate.path,
            bytes,
            complete: complete && unchanged && discovery_complete,
            estimated: None,
        };
        measured.push((consumer, candidate.directory));
    }
    work.remaining += estimate_entries;
    estimate_unfinished(&mut measured, device, work, &mut |len| {
        usize::try_from(rand::random::<u64>() % (len as u64)).unwrap_or(0)
    });
    let mut consumers: Vec<Consumer> = measured.into_iter().map(|(consumer, _)| consumer).collect();
    if !root
        .metadata()
        .is_ok_and(|after| same_stamp(&stamp, &after))
    {
        for consumer in &mut consumers {
            consumer.complete = false;
        }
    }
    consumers.sort_by(|a, b| {
        b.rank_bytes()
            .cmp(&a.rank_bytes())
            .then_with(|| a.path.cmp(&b.path))
    });
    consumers.truncate(top.min(MAX_CONSUMERS));
    consumers
}

/// Sample every consumer the walk left unfinished, sharing what is left of
/// the budget evenly among them.
fn estimate_unfinished(
    measured: &mut [(Consumer, File)],
    device: u64,
    work: &mut WorkBudget,
    choose: &mut impl FnMut(usize) -> usize,
) {
    let unfinished = measured
        .iter()
        .filter(|(consumer, _)| !consumer.complete)
        .count();
    for (index, (consumer, directory)) in measured
        .iter_mut()
        .filter(|(consumer, _)| !consumer.complete)
        .enumerate()
    {
        let left = unfinished - index;
        let mut allowance = work.remaining / left;
        let now = Instant::now();
        let divisor = u32::try_from(left).unwrap_or(u32::MAX);
        let deadline = now + work.deadline.saturating_duration_since(now) / divisor;
        consumer.estimated =
            estimate_tree(directory, device, work, &mut allowance, deadline, choose);
    }
}

/// Random paths sampled per estimate, spread over the consumer's children.
const ESTIMATE_PROBES: u32 = 512;
/// Files whose size is read per directory; the others are scaled from them.
const FILE_SAMPLE: usize = 32;
/// Directory entries listed per unit of work: a listing costs far less than
/// a `stat`, and only directories and sampled files are `stat`ed.
const LISTED_PER_UNIT: usize = 64;

/// One directory's own allocated bytes (itself and its files) and its
/// subdirectories on the same device.
struct Level {
    own: u64,
    children: Vec<(std::ffi::CString, Stat)>,
}

/// Knuth's estimate of a tree's allocated bytes. A probe walks one random
/// path down the tree and weights each directory's own bytes by the product
/// of the fan-outs above it; the mean is unbiased for any tree shape, so a
/// tree too large to walk is ranked by its size rather than by the part of it
/// a budget reached. Every child of the root gets its own probes, so a large
/// child is never missed by chance; children the budget does not reach count
/// as average. Levels are read once and reused. `None` when no child was.
fn estimate_tree(
    root: &File,
    device: u64,
    work: &mut WorkBudget,
    allowance: &mut usize,
    deadline: Instant,
    choose: &mut impl FnMut(usize) -> usize,
) -> Option<u64> {
    let top = read_level(root, device, work, allowance, deadline, choose)?;
    if top.children.is_empty() {
        return Some(top.own);
    }
    let per_child =
        (ESTIMATE_PROBES / u32::try_from(top.children.len()).unwrap_or(u32::MAX)).max(1);
    let mut levels: HashMap<u64, Level> = HashMap::new();
    let (mut sum, mut reached) = (0.0_f64, 0_u32);
    for (name, stat) in &top.children {
        let Ok(child) = open_directory(root, name, stat) else {
            continue;
        };
        let mut sampler = Sampler {
            levels: &mut levels,
            device,
            work: &mut *work,
            allowance: &mut *allowance,
            deadline,
            choose: &mut *choose,
        };
        let Some(mean) = sampler.probe_mean(&child, per_child) else {
            break;
        };
        sum += mean;
        reached += 1;
    }
    if reached == 0 {
        return None;
    }
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let children = (sum * top.children.len() as f64 / f64::from(reached)) as u64;
    Some(top.own.saturating_add(children))
}

/// The state [`estimate_tree`]'s probes share.
struct Sampler<'a, C: FnMut(usize) -> usize> {
    levels: &'a mut HashMap<u64, Level>,
    device: u64,
    work: &'a mut WorkBudget,
    allowance: &'a mut usize,
    deadline: Instant,
    choose: &'a mut C,
}

impl<C: FnMut(usize) -> usize> Sampler<'_, C> {
    /// The mean of up to `probes` random paths below `start`; a probe the
    /// budget cuts short is dropped. `None` when none finished.
    fn probe_mean(&mut self, start: &File, probes: u32) -> Option<f64> {
        let (mut total, mut done) = (0.0_f64, 0_u32);
        'probes: while done < probes {
            let mut directory = start.try_clone().ok()?;
            let (mut weight, mut sample) = (1.0_f64, 0.0_f64);
            for _ in 0..MAX_DEPTH {
                let Ok(inode) = directory.metadata().map(|meta| meta.ino()) else {
                    break 'probes;
                };
                let level = match self.levels.entry(inode) {
                    Entry::Occupied(known) => known.into_mut(),
                    Entry::Vacant(unread) => {
                        let Some(level) = read_level(
                            &directory,
                            self.device,
                            self.work,
                            self.allowance,
                            self.deadline,
                            self.choose,
                        ) else {
                            break 'probes;
                        };
                        unread.insert(level)
                    }
                };
                #[allow(clippy::cast_precision_loss)]
                {
                    sample = weight.mul_add(level.own as f64, sample);
                    weight *= level.children.len() as f64;
                }
                if level.children.is_empty() {
                    break;
                }
                let (name, expected) = &level.children[(self.choose)(level.children.len())];
                let Ok(child) = open_directory(&directory, name, expected) else {
                    break 'probes;
                };
                directory = child;
            }
            total += sample;
            done += 1;
        }
        (done > 0).then(|| total / f64::from(done))
    }
}

/// List one directory for [`estimate_tree`]. Entry types come from the
/// listing; directories are `stat`ed, and a reservoir of [`FILE_SAMPLE`]
/// files sizes the rest. `None` when the budget runs out or it cannot be read.
fn read_level(
    directory: &File,
    device: u64,
    work: &mut WorkBudget,
    allowance: &mut usize,
    deadline: Instant,
    choose: &mut impl FnMut(usize) -> usize,
) -> Option<Level> {
    let mut own = directory.metadata().ok()?.blocks().checked_mul(512)?;
    let mut entries = Dir::read_from(directory).ok()?;
    let mut children = Vec::new();
    let (mut files, mut sample) = (0_usize, Vec::with_capacity(FILE_SAMPLE));
    let mut listed = 0_usize;
    while let Some(entry) = entries.read() {
        if listed.is_multiple_of(LISTED_PER_UNIT) && !work.take(allowance, deadline) {
            return None;
        }
        listed += 1;
        let Ok(entry) = entry else {
            continue;
        };
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        let kind = entry.file_type();
        if kind == FileType::RegularFile {
            // Reservoir sampling keeps a uniform sample of any number of files.
            if sample.len() < FILE_SAMPLE {
                sample.push(name.to_owned());
            } else if let Some(slot) = sample.get_mut(choose(files + 1)) {
                name.clone_into(slot);
            }
            files += 1;
            continue;
        }
        if kind != FileType::Directory && kind != FileType::Unknown {
            continue;
        }
        if !work.take(allowance, deadline) {
            return None;
        }
        let Ok(stat) = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) else {
            continue;
        };
        if stat_device(&stat) != Some(device) {
            continue;
        }
        if FileType::from_raw_mode(stat.st_mode).is_dir() {
            children.push((name.to_owned(), stat));
        } else {
            own = own.saturating_add(stat_blocks(&stat).unwrap_or(0));
        }
    }
    let (mut sampled_bytes, mut sampled) = (0_u64, 0_u64);
    for name in &sample {
        if !work.take(allowance, deadline) {
            return None;
        }
        if let Ok(stat) = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            sampled_bytes = sampled_bytes.saturating_add(stat_blocks(&stat).unwrap_or(0));
            sampled += 1;
        }
    }
    if sampled > 0 {
        let scaled = u128::from(sampled_bytes) * files as u128 / u128::from(sampled);
        own = own.saturating_add(u64::try_from(scaled).unwrap_or(u64::MAX));
    }
    Some(Level { own, children })
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
        let Some(entry_device) = stat_device(&stat) else {
            complete = false;
            continue;
        };
        if entry_device != device || !FileType::from_raw_mode(stat.st_mode).is_dir() {
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
        let Some(entry_device) = stat_device(&stat) else {
            complete = false;
            continue;
        };
        if entry_device != device {
            continue;
        }
        let observed = if FileType::from_raw_mode(stat.st_mode).is_dir() {
            let Ok(child) = open_directory(directory, name, &stat) else {
                complete = false;
                continue;
            };
            let (child_bytes, child_complete) =
                measure_directory(&child, device, depth + 1, work, allowance, deadline, seen);
            complete &= child_complete;
            child_bytes
        } else {
            let Some(inode) = stat_inode(&stat) else {
                complete = false;
                continue;
            };
            if stat_hard_linked(&stat) && !seen.insert((device, inode)) {
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
    if stat_device(expected) != Some(metadata.dev()) || stat_inode(expected) != Some(metadata.ino())
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

/// A file with one link cannot be met twice, so only hard-linked files need
/// remembering: the set stays small however many entries are walked.
#[allow(clippy::useless_conversion)]
fn stat_hard_linked(stat: &Stat) -> bool {
    u64::from(stat.st_nlink) > 1
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
        // An estimate above the measured part is shown as an estimate; a
        // measurement cut short is a lower bound.
        let (bytes, mark, suffix) = match consumer.estimated {
            Some(estimate) if !consumer.complete && estimate > consumer.bytes => {
                (estimate, "~", " est.")
            }
            _ if consumer.complete => (consumer.bytes, "", ""),
            _ => (consumer.bytes, ">=", ""),
        };
        #[allow(clippy::cast_precision_loss)]
        let gib = bytes as f64 / 1_073_741_824.0;
        // Debug escaping keeps hostile file names from injecting log lines or
        // terminal control sequences. These paths are display-only.
        #[allow(clippy::unnecessary_debug_formatting)]
        let _ = write!(out, "{:?} {mark}{gib:.1} GiB{suffix}", consumer.path);
    }
    if consumers.iter().any(|consumer| !consumer.complete) {
        out.push_str(
            " (partial observation: >= is the part measured, ~ a sampled estimate of the whole)",
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // Filesystem fixtures use independent admission. Contention and stalled
    // workers are tested explicitly below, without global test-order coupling.
    fn top_consumers(mount: &Path, budget: usize, top: usize) -> Vec<Consumer> {
        top_consumers_with_gate(mount, budget, top, Arc::new(AtomicBool::new(false)))
    }

    fn wait_for_idle(active: &AtomicBool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while active.load(Ordering::Acquire) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            !active.load(Ordering::Acquire),
            "probe did not release admission"
        );
    }

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
            estimated: None,
        }]);
        assert!(!text.contains('\n'));
        assert!(!text.contains('\x1b'));
        assert!(text.contains("partial observation"));
    }

    #[test]
    fn completed_probe_returns_its_report_and_releases_admission() {
        let active = Arc::new(AtomicBool::new(false));
        let expected = unknown(Path::new("/observed"));
        let result = expected.clone();
        assert_eq!(
            bounded_probe(
                Arc::clone(&active),
                Instant::now() + Duration::from_secs(5),
                move || result,
            ),
            Some(expected)
        );
        assert!(!active.load(Ordering::Acquire));
    }

    #[test]
    fn timed_out_probe_blocks_replacement_and_discards_its_late_result() {
        let active = Arc::new(AtomicBool::new(false));
        let (release, blocked) = mpsc::sync_channel::<()>(1);
        let result = bounded_probe(
            Arc::clone(&active),
            Instant::now() + Duration::from_millis(20),
            move || {
                // Simulate a kernel call that ignores cooperative cancellation.
                blocked.recv().unwrap();
                unknown(Path::new("/old-mount"))
            },
        );
        assert!(result.is_none());
        assert!(active.load(Ordering::Acquire));
        let attempted = Arc::new(AtomicBool::new(false));
        let other_attempt = Arc::clone(&attempted);
        assert!(
            bounded_probe(
                Arc::clone(&active),
                Instant::now() + Duration::from_secs(5),
                move || {
                    other_attempt.store(true, Ordering::Release);
                    Vec::new()
                },
            )
            .is_none()
        );
        assert!(!attempted.load(Ordering::Acquire));
        release.send(()).unwrap();
        wait_for_idle(&active);
        let fresh = unknown(Path::new("/new-mount"));
        let expected = fresh.clone();
        assert_eq!(
            bounded_probe(active, Instant::now() + Duration::from_secs(5), move || {
                fresh
            },),
            Some(expected)
        );
    }

    #[test]
    fn busy_admission_reports_the_requested_mount_as_unknown() {
        let active = Arc::new(AtomicBool::new(true));
        let path = Path::new("/unobserved-mount");
        assert_eq!(top_consumers_with_gate(path, 100, 8, active), unknown(path));
        assert!(super::top_consumers(path, 100, 0).is_empty());
    }

    #[cfg(panic = "unwind")]
    #[test]
    fn unwinding_worker_does_not_permanently_disable_attribution() {
        let active = Arc::new(AtomicBool::new(false));
        assert!(
            bounded_probe(
                Arc::clone(&active),
                Instant::now() + Duration::from_secs(5),
                || panic!("injected attribution failure"),
            )
            .is_none()
        );
        wait_for_idle(&active);
    }

    #[test]
    fn retained_consumer_cap_marks_the_inventory_incomplete() {
        let mount = tempfile::tempdir().unwrap();
        for index in 0..=MAX_CONSUMERS {
            fs::create_dir(mount.path().join(format!("tree-{index}"))).unwrap();
        }
        let consumers = top_consumers(mount.path(), 10_000, usize::MAX);
        assert_eq!(consumers.len(), MAX_CONSUMERS);
        assert!(consumers.iter().all(|consumer| !consumer.complete));
    }

    #[test]
    fn hard_links_are_not_counted_again_within_or_between_consumers() {
        let mount = tempfile::tempdir().unwrap();
        let a = mount.path().join("a");
        let b = mount.path().join("b");
        fs::create_dir(&a).unwrap();
        fs::create_dir(&b).unwrap();
        let data = a.join("data");
        fs::write(&data, vec![3u8; 64 * 1024]).unwrap();
        fs::hard_link(&data, a.join("copy")).unwrap();
        fs::hard_link(&data, b.join("copy")).unwrap();
        let expected = [&a, &b, &data]
            .into_iter()
            .map(|path| fs::metadata(path).unwrap().blocks() * 512)
            .sum::<u64>();
        let consumers = top_consumers(mount.path(), 100, 8);
        assert_eq!(consumers.len(), 2);
        assert_eq!(
            consumers.iter().map(|consumer| consumer.bytes).sum::<u64>(),
            expected
        );
        assert!(consumers.iter().any(|consumer| !consumer.complete));
    }

    fn allocated_tree(path: &Path) -> u64 {
        let meta = fs::symlink_metadata(path).unwrap();
        let mut total = meta.blocks() * 512;
        if meta.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                total += allocated_tree(&entry.unwrap().path());
            }
        }
        total
    }

    fn estimate(path: &Path, choose: &mut impl FnMut(usize) -> usize) -> Option<u64> {
        let root = File::open(path).unwrap();
        let device = root.metadata().unwrap().dev();
        let mut work = WorkBudget {
            remaining: 100_000,
            examined: 0,
            deadline: Instant::now() + Duration::from_secs(30),
        };
        let mut allowance = 100_000;
        estimate_tree(
            &root,
            device,
            &mut work,
            &mut allowance,
            Instant::now() + Duration::from_secs(30),
            choose,
        )
    }

    /// The sampled estimate is exact on a symmetric tree whichever path a
    /// probe takes, and its mean is exact when probes cover every branch
    /// equally: unbiased, unlike the share of a tree a budget reaches.
    #[test]
    fn sampled_estimate_is_unbiased() {
        let tree = tempfile::tempdir().unwrap();
        for branch in ["a", "b", "c"] {
            let deep = tree.path().join(branch).join("deep");
            fs::create_dir_all(&deep).unwrap();
            fs::write(deep.join("data"), vec![1u8; 64 * 1024]).unwrap();
        }
        let exact = allocated_tree(tree.path());
        assert_eq!(estimate(tree.path(), &mut |_| 0), Some(exact));
        assert_eq!(estimate(tree.path(), &mut |len| len - 1), Some(exact));

        // Every child of the root is visited; below that, paths are sampled.
        let skewed = tempfile::tempdir().unwrap();
        let below = skewed.path().join("below");
        fs::create_dir_all(below.join("big")).unwrap();
        fs::write(below.join("big/data"), vec![2u8; 256 * 1024]).unwrap();
        fs::create_dir(below.join("empty")).unwrap();
        let exact = allocated_tree(skewed.path());
        let mut turn = 0_usize;
        let alternate = &mut |len: usize| {
            turn += 1;
            turn % len
        };
        assert_eq!(estimate(skewed.path(), alternate), Some(exact));
        // Each path alone is wrong in its own direction.
        let first = estimate(skewed.path(), &mut |_| 0).unwrap();
        let last = estimate(skewed.path(), &mut |len| len - 1).unwrap();
        assert!(first.min(last) < exact && exact < first.max(last));
    }

    /// A consumer the walk cannot finish is ranked by its estimated size,
    /// shown as an estimate, above a smaller one measured in full (bd-q4nx).
    #[test]
    fn an_unfinished_consumer_is_ranked_by_its_estimate() {
        let mount = tempfile::tempdir().unwrap();
        for branch in ["one", "two", "three"] {
            let dir = mount.path().join("big").join(branch);
            fs::create_dir_all(&dir).unwrap();
            for index in 0..40 {
                fs::write(dir.join(format!("f{index}")), vec![3u8; 4096]).unwrap();
            }
        }
        fs::create_dir(mount.path().join("small")).unwrap();
        fs::write(mount.path().join("small/data"), vec![4u8; 64 * 1024]).unwrap();
        let mut work = WorkBudget {
            remaining: 100,
            examined: 0,
            deadline: Instant::now() + Duration::from_secs(30),
        };
        let consumers = collect_consumers(mount.path(), 8, &mut work);
        assert_eq!(consumers.len(), 2, "{consumers:?}");
        let (big, small) = (&consumers[0], &consumers[1]);
        assert!(big.path.ends_with("big"), "{consumers:?}");
        assert!(!big.complete && small.complete, "{consumers:?}");
        let exact = allocated_tree(&mount.path().join("big"));
        assert_eq!(big.estimated, Some(exact), "{consumers:?}");
        assert!(big.bytes < exact);
        let text = describe(&consumers);
        assert!(text.contains(" ~") && text.contains("GiB est."), "{text}");
    }

    /// Only directories and hard-linked files are remembered, so a large
    /// budget does not grow the set with every file walked (bd-q4nx).
    #[test]
    fn only_hard_linked_files_are_remembered() {
        let tree = tempfile::tempdir().unwrap();
        for index in 0..20 {
            fs::write(tree.path().join(format!("single-{index}")), b"x").unwrap();
        }
        fs::write(tree.path().join("linked"), b"y").unwrap();
        fs::hard_link(tree.path().join("linked"), tree.path().join("link")).unwrap();
        let directory = File::open(tree.path()).unwrap();
        let device = directory.metadata().unwrap().dev();
        let mut work = WorkBudget {
            remaining: 1_000,
            examined: 0,
            deadline: Instant::now() + Duration::from_secs(10),
        };
        let mut allowance = 1_000;
        let mut seen = HashSet::new();
        let (bytes, _) = measure_directory(
            &directory,
            device,
            0,
            &mut work,
            &mut allowance,
            Instant::now() + Duration::from_secs(10),
            &mut seen,
        );
        assert!(bytes > 0);
        // The directory itself and the one hard-linked inode.
        assert_eq!(seen.len(), 2, "{seen:?}");
    }

    #[test]
    fn sparse_file_accounting_uses_blocks_instead_of_logical_length() {
        let mount = tempfile::tempdir().unwrap();
        let tree = mount.path().join("tree");
        fs::create_dir(&tree).unwrap();
        let sparse = tree.join("sparse");
        File::create(&sparse)
            .unwrap()
            .set_len(64 * 1024 * 1024)
            .unwrap();
        let expected = fs::metadata(&tree).unwrap().blocks() * 512
            + fs::metadata(&sparse).unwrap().blocks() * 512;
        let consumers = top_consumers(mount.path(), 100, 8);
        assert_eq!(consumers.len(), 1);
        assert_eq!(consumers[0].bytes, expected);
        assert!(consumers[0].complete);
    }
}
