//! Bounded, metadata-only attribution of occupied RAM-scratch directories.
//!
//! These observations are not deletion candidates. Sizes are sampled allocated
//! blocks, not proven reclaimable bytes. Age is derived from observed mtime and
//! ctime, not access time, and never establishes that a file is unused.

use std::io;
use std::time::{Duration, Instant};

use serde::Serialize;

use super::ScratchMount;

#[cfg(target_os = "linux")]
mod linux;

/// Limits shared by all mount-attribution probes in one invocation.
#[derive(Debug, Clone, Copy)]
pub struct AttributionLimits {
    /// Total directory entries enumerated, including entries later excluded.
    pub max_entries: usize,
    /// Maximum directory depth below each top-level entry.
    pub max_depth: usize,
    /// Largest observed entries retained per mount.
    pub top: usize,
}

impl Default for AttributionLimits {
    fn default() -> Self {
        Self {
            // Agent hosts hold hundreds of thousands of tmpfs entries (ts2,
            // 2026-10-18: /tmp 128k, /dev/shm 510k); 20,000 saw a few percent
            // of /tmp and missed its three largest trees. The deadline is the
            // real bound on the work.
            max_entries: 2_000_000,
            max_depth: 8,
            top: 10,
        }
    }
}

impl AttributionLimits {
    /// Reject unbounded output or traversal work.
    pub fn validate(self) -> io::Result<()> {
        if !(1..=5_000_000).contains(&self.max_entries)
            || self.max_depth > 32
            || !(1..=50).contains(&self.top)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "scratch attribution requires 1..5000000 entries, depth 0..32, and top 1..50",
            ));
        }
        Ok(())
    }
}

/// Metadata observations for one immediate child of a scratch mount.
#[derive(Debug, Clone, Serialize)]
pub struct ScratchEntry {
    /// Display path; never replay or cleanup authority.
    pub path: String,
    /// Native pathname bytes, independent of lossy display strings.
    pub native_path_hex: String,
    /// Owner of the immediate child, not necessarily all descendants.
    pub owner_uid: u32,
    /// Distinct sampled inode allocations (st_blocks * 512); incomplete walks
    /// underestimate the sampled tree. This is not a filesystem snapshot.
    pub observed_allocated_bytes: u64,
    /// True only when this entry's traversal completed without missing evidence.
    pub complete: bool,
    /// Hours since the newest observed mtime/ctime, only for complete walks
    /// with non-future timestamps. Not a claim about access or live processes.
    pub idle_hours: Option<u64>,
}

/// Largest sampled top-level entries for one mount path.
#[derive(Debug, Clone, Serialize)]
pub struct MountAttribution {
    /// Mount name exactly as supplied for inspection.
    pub mount_path: String,
    /// Whether the entire bounded directory probe completed.
    pub complete: bool,
    /// Directory entries enumerated, even if their metadata could not be read.
    pub entries_examined: usize,
    /// Descendant mount points omitted from this filesystem's accounting.
    pub mount_boundaries_skipped: usize,
    /// Symlinks observed but never traversed.
    pub symlinks_skipped: usize,
    /// Entries ranked by sampled bytes, then native path spelling.
    pub entries: Vec<ScratchEntry>,
    /// Bounded explanations of partial coverage or unavailable metadata.
    pub issues: Vec<String>,
}

/// Inspect mount children without following symlinks or crossing mounts.
///
/// Each mount receives a share of the remaining entry/time budget, so a large
/// `/tmp` cannot consume all inspection time before `/run` is considered.
/// Mounts are probed smallest occupancy first: whatever a small runtime mount
/// leaves unused flows on, so the fullest mount, probed last, is not cut to
/// 1/N of the budget by mounts that needed almost none of it. Reports keep
/// the caller's order. The caller passes its original command deadline:
/// collection and attribution do not each receive a fresh full timeout. No
/// file contents are opened or read.
pub fn inspect(
    mounts: &[ScratchMount],
    limits: AttributionLimits,
    deadline: Instant,
) -> io::Result<Vec<MountAttribution>> {
    limits.validate()?;
    if mounts.len() > 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many scratch mounts",
        ));
    }
    let mut remaining = limits.max_entries;
    let mut order: Vec<usize> = (0..mounts.len()).collect();
    order.sort_by_key(|&index| mounts[index].used_bytes);
    let mut reports: Vec<Option<MountAttribution>> = vec![None; mounts.len()];
    for (visited, &index) in order.iter().enumerate() {
        let mount = &mounts[index];
        let left = mounts.len() - visited;
        let share = remaining.div_ceil(left);
        let time = deadline.saturating_duration_since(Instant::now());
        let slice = time
            .checked_div(u32::try_from(left).unwrap_or(u32::MAX))
            .unwrap_or(Duration::ZERO);
        let mount_deadline = Instant::now()
            .checked_add(slice)
            .unwrap_or(deadline)
            .min(deadline);
        #[cfg(target_os = "linux")]
        let report = linux::inspect(mount, limits, share, mount_deadline);
        #[cfg(not(target_os = "linux"))]
        let report = {
            let _ = (share, mount_deadline);
            unavailable(mount, "descriptor-based scratch attribution requires Linux")
        };
        remaining = remaining.saturating_sub(report.entries_examined);
        reports[index] = Some(report);
    }
    Ok(reports.into_iter().flatten().collect())
}

fn unavailable(mount: &ScratchMount, reason: &str) -> MountAttribution {
    MountAttribution {
        mount_path: mount.path.clone(),
        complete: false,
        entries_examined: 0,
        mount_boundaries_skipped: 0,
        symlinks_skipped: 0,
        entries: Vec::new(),
        issues: vec![reason.to_owned()],
    }
}
