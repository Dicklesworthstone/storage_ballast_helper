//! Kernel writeback (dirty-page) tuning model.
//!
//! On high-RAM hosts the kernel's percentage-based dirty-page limits
//! (`vm.dirty_ratio` / `vm.dirty_background_ratio`) let many gigabytes of dirty
//! pages accumulate before writeback throttling kicks in. Those huge pools then
//! flush in bursts through kernel writeback threads (e.g. `btrfs-endio-write`)
//! that ignore the `ionice` class of the processes that produced the writes — so
//! interactive work stalls behind each multi-GB flush even when builds are
//! niced/ionice-idled.
//!
//! The fix is to replace the percentage knobs with absolute byte limits
//! (`vm.dirty_bytes` / `vm.dirty_background_bytes`) sized so writeback drains
//! continuously and gently. This module holds the platform-agnostic model: the
//! current-state snapshot, the device-bandwidth-scaled sizing, the risk
//! assessment, the persisted `sysctl.d` rendering, and conflict detection. The
//! actual `/proc/sys` reads/writes live in the Linux PAL.

#![allow(missing_docs)]

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::core::config::SystemTuningConfig;
use crate::tuning::bandwidth::BandwidthSource;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

/// Snapshot of the kernel's current dirty-page configuration plus total RAM.
///
/// `*_bytes` knobs and `*_ratio` knobs are mutually exclusive in the kernel:
/// setting a byte limit zeros the matching ratio and vice versa. A value of
/// `Some(0)` for a byte field therefore means "ratio mode is active".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WritebackState {
    pub dirty_ratio: Option<u64>,
    pub dirty_background_ratio: Option<u64>,
    pub dirty_bytes: Option<u64>,
    pub dirty_background_bytes: Option<u64>,
    pub dirty_expire_centisecs: Option<u64>,
    pub dirty_writeback_centisecs: Option<u64>,
    pub total_ram_bytes: u64,
}

impl WritebackState {
    /// Whether the kernel is currently using absolute byte limits (vs ratios).
    #[must_use]
    pub fn byte_mode_active(&self) -> bool {
        self.dirty_bytes.unwrap_or(0) > 0
    }

    /// Effective maximum dirty-page pool in bytes before hard throttling.
    ///
    /// In byte mode this is `dirty_bytes`. In ratio mode it is
    /// `dirty_ratio` percent of total RAM — an approximation of the kernel's
    /// page-based accounting, but close enough to flag dangerously large pools.
    #[must_use]
    pub fn effective_dirty_pool_bytes(&self) -> u64 {
        if let Some(bytes) = self.dirty_bytes.filter(|&b| b > 0) {
            return bytes;
        }
        let ratio = u128::from(self.dirty_ratio.unwrap_or(0));
        u64::try_from(u128::from(self.total_ram_bytes) * ratio / 100).unwrap_or(u64::MAX)
    }
}

/// Recommended absolute writeback limits plus the estimate that produced them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WritebackPlan {
    pub dirty_bytes: u64,
    pub dirty_background_bytes: u64,
    pub bandwidth_bytes_per_sec: u64,
    pub bandwidth_source: BandwidthSource,
}

/// Compute a writeback plan from an estimated device write bandwidth.
///
/// `dirty_background_bytes` is sized so a full background pool drains in
/// roughly `writeback_target_drain_secs` at the estimated bandwidth, clamped to
/// `[writeback_min_background_bytes, writeback_max_background_bytes]` and rounded
/// to a whole MiB. `dirty_bytes` (the hard throttle ceiling) is
/// `writeback_hard_ratio` times the background limit.
#[must_use]
pub fn plan_from_bandwidth(
    bandwidth_bytes_per_sec: u64,
    bandwidth_source: BandwidthSource,
    cfg: &SystemTuningConfig,
) -> WritebackPlan {
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let raw_background = (bandwidth_bytes_per_sec as f64 * cfg.writeback_target_drain_secs) as u64;
    let clamped = raw_background.clamp(
        cfg.writeback_min_background_bytes,
        cfg.writeback_max_background_bytes,
    );
    let background = round_to_mib(clamped);
    let hard = background.saturating_mul(cfg.writeback_hard_ratio.max(1));
    WritebackPlan {
        dirty_bytes: hard,
        dirty_background_bytes: background,
        bandwidth_bytes_per_sec,
        bandwidth_source,
    }
}

/// Risk assessment for the current writeback state against a recommended plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WritebackAssessment {
    /// Whether the current configuration warrants applying the plan.
    pub needs_tuning: bool,
    /// Effective dirty pool the kernel allows today.
    pub current_pool_bytes: u64,
    /// Human-readable reasons backing `needs_tuning` (empty when healthy).
    pub reasons: Vec<String>,
    /// Extra severity because the backing filesystem is copy-on-write (btrfs/zfs),
    /// whose writeback threads escape the producing process's ionice class.
    pub cow_filesystem: bool,
}

/// Decide whether the kernel writeback configuration should be retuned.
///
/// In ratio mode we flag any host whose RAM-derived dirty pool exceeds
/// `writeback_pool_warn_bytes`. In byte mode we only re-flag a configuration
/// that is wildly larger than the recommended plan (more than 2x), to avoid
/// churning a host that is already sensibly tuned.
#[must_use]
pub fn assess(
    state: &WritebackState,
    plan: &WritebackPlan,
    cfg: &SystemTuningConfig,
    fs_type: &str,
) -> WritebackAssessment {
    let current_pool_bytes = state.effective_dirty_pool_bytes();
    let cow_filesystem = is_cow_filesystem(fs_type);
    let mut reasons = Vec::new();
    let mut needs_tuning = false;

    if state.byte_mode_active() {
        let current = state.dirty_bytes.unwrap_or(0);
        if current > plan.dirty_bytes.saturating_mul(2) {
            needs_tuning = true;
            reasons.push(format!(
                "vm.dirty_bytes is {} — far above the {} recommended here; \
                 large dirty pools still flush in bursts that stall interactive I/O.",
                human_bytes(current),
                human_bytes(plan.dirty_bytes),
            ));
        }
    } else if current_pool_bytes > cfg.writeback_pool_warn_bytes {
        needs_tuning = true;
        reasons.push(format!(
            "Percentage-based vm.dirty_ratio={}% lets ~{} of dirty pages accumulate \
             on this {} host before writeback throttles; they flush in bursts via kernel \
             writeback threads that ignore ionice, stalling interactive I/O.",
            state.dirty_ratio.unwrap_or(0),
            human_bytes(current_pool_bytes),
            human_bytes(state.total_ram_bytes),
        ));
    }

    if needs_tuning && cow_filesystem {
        reasons.push(format!(
            "Backing filesystem is {fs_type} (copy-on-write): its writeback threads run \
             outside the ionice class of the build processes, so this matters more here."
        ));
    }

    WritebackAssessment {
        needs_tuning,
        current_pool_bytes,
        reasons,
        cow_filesystem,
    }
}

/// Render the persisted `sysctl.d` snippet for a plan.
#[must_use]
pub fn render_sysctl_conf(plan: &WritebackPlan, drain_secs: f64, generated_note: &str) -> String {
    format!(
        "# Managed by sbh (storage_ballast_helper) — kernel writeback tuning.\n\
         # {generated_note}\n\
         #\n\
         # Absolute dirty-page byte limits replace the percentage-based\n\
         # vm.dirty_ratio / vm.dirty_background_ratio knobs, which scale with RAM and\n\
         # cause multi-GB writeback bursts on high-memory hosts (especially btrfs/zfs).\n\
         # Setting vm.dirty_bytes auto-zeros vm.dirty_ratio (they are mutually exclusive).\n\
         # Sized for ~{drain_secs:.1}s background drain at an estimated {bw}/s write\n\
         # bandwidth ({source}).\n\
         #\n\
         # Revert with: sbh tune --revert-writeback\n\
         # (background threshold first, so it is never transiently above the hard\n\
         # limit while sysctl loads the file)\n\
         vm.dirty_background_bytes = {dirty_background_bytes}\n\
         vm.dirty_bytes = {dirty_bytes}\n",
        bw = human_bytes(plan.bandwidth_bytes_per_sec),
        source = plan.bandwidth_source,
        dirty_bytes = plan.dirty_bytes,
        dirty_background_bytes = plan.dirty_background_bytes,
    )
}

/// A `sysctl.d` snippet (path + contents) for conflict scanning.
pub type SysctlSnippet = (PathBuf, String);

/// Find `sysctl.d` files that would override our byte limits with ratios.
///
/// `sysctl.d` files load in lexical filename order, so a file that sets
/// `vm.dirty_ratio` / `vm.dirty_background_ratio` and whose name sorts greater
/// than `our_path` wins. Returns those conflicting paths so the caller can warn.
#[must_use]
pub fn conflicting_sysctl_files(our_path: &Path, others: &[SysctlSnippet]) -> Vec<PathBuf> {
    let our_name = file_name_lossy(our_path);
    let mut conflicts = Vec::new();
    for (path, contents) in others {
        if path.as_path() == our_path {
            continue;
        }
        let name = file_name_lossy(path);
        if name <= our_name {
            continue; // loads before us; we win
        }
        if contents_set_dirty_ratio(contents) {
            conflicts.push(path.clone());
        }
    }
    conflicts
}

fn file_name_lossy(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn contents_set_dirty_ratio(contents: &str) -> bool {
    contents.lines().any(|line| {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.starts_with(';') {
            return false;
        }
        let Some((key, _)) = trimmed.split_once('=') else {
            return false;
        };
        matches!(key.trim(), "vm.dirty_ratio" | "vm.dirty_background_ratio")
    })
}

/// Whether a filesystem type is copy-on-write (kernel writeback threads escape ionice).
#[must_use]
pub fn is_cow_filesystem(fs_type: &str) -> bool {
    matches!(fs_type.to_ascii_lowercase().as_str(), "btrfs" | "zfs")
}

fn round_to_mib(bytes: u64) -> u64 {
    (bytes / MIB).max(1) * MIB
}

/// Compact human-readable byte formatting for rationale strings.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn human_bytes(bytes: u64) -> String {
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.0} MiB", bytes as f64 / MIB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::SystemTuningConfig;

    fn cfg() -> SystemTuningConfig {
        SystemTuningConfig::default()
    }

    #[test]
    fn ssd_bandwidth_reproduces_field_proven_limits() {
        // 512 MiB/s, 1.0s background drain, 4:1 hard ratio => 512 MiB / 2 GiB.
        let plan = plan_from_bandwidth(512 * MIB, BandwidthSource::HeuristicSsd, &cfg());
        assert_eq!(plan.dirty_background_bytes, 512 * MIB);
        assert_eq!(plan.dirty_bytes, 2 * GIB);
    }

    #[test]
    fn plan_clamps_to_floor_and_ceiling() {
        let c = cfg();
        let slow = plan_from_bandwidth(10 * MIB, BandwidthSource::HeuristicHdd, &c);
        assert_eq!(
            slow.dirty_background_bytes,
            c.writeback_min_background_bytes
        );
        let fast = plan_from_bandwidth(8 * GIB, BandwidthSource::HeuristicNvme, &c);
        assert_eq!(
            fast.dirty_background_bytes,
            c.writeback_max_background_bytes
        );
    }

    #[test]
    fn ratio_mode_pool_scales_with_ram() {
        let state = WritebackState {
            dirty_ratio: Some(10),
            dirty_background_ratio: Some(5),
            dirty_bytes: Some(0),
            dirty_background_bytes: Some(0),
            dirty_expire_centisecs: Some(3000),
            dirty_writeback_centisecs: Some(500),
            total_ram_bytes: 247 * GIB,
        };
        assert!(!state.byte_mode_active());
        // 10% of 247 GiB ≈ 24.7 GiB.
        assert!(state.effective_dirty_pool_bytes() > 24 * GIB);
    }

    #[test]
    fn assess_flags_ratio_mode_on_high_ram() {
        let state = WritebackState {
            dirty_ratio: Some(10),
            dirty_background_ratio: Some(5),
            dirty_bytes: Some(0),
            dirty_background_bytes: Some(0),
            dirty_expire_centisecs: Some(3000),
            dirty_writeback_centisecs: Some(500),
            total_ram_bytes: 247 * GIB,
        };
        let plan = plan_from_bandwidth(512 * MIB, BandwidthSource::HeuristicSsd, &cfg());
        let assessment = assess(&state, &plan, &cfg(), "btrfs");
        assert!(assessment.needs_tuning);
        assert!(assessment.cow_filesystem);
        // One reason for the ratio pool, one escalation for CoW.
        assert_eq!(assessment.reasons.len(), 2);
    }

    #[test]
    fn assess_leaves_small_ram_ratio_host_alone() {
        let state = WritebackState {
            dirty_ratio: Some(20),
            dirty_background_ratio: Some(10),
            dirty_bytes: Some(0),
            dirty_background_bytes: Some(0),
            dirty_expire_centisecs: Some(3000),
            dirty_writeback_centisecs: Some(500),
            total_ram_bytes: 8 * GIB, // 20% => 1.6 GiB, under the 4 GiB warn floor
        };
        let plan = plan_from_bandwidth(512 * MIB, BandwidthSource::HeuristicSsd, &cfg());
        let assessment = assess(&state, &plan, &cfg(), "ext4");
        assert!(!assessment.needs_tuning);
        assert!(
            assessment.reasons.is_empty(),
            "expected no tuning reasons for a small-RAM ratio host, got {:?}",
            assessment.reasons
        );
    }

    #[test]
    fn assess_leaves_well_tuned_byte_mode_alone() {
        let plan = plan_from_bandwidth(512 * MIB, BandwidthSource::HeuristicSsd, &cfg());
        let state = WritebackState {
            dirty_ratio: Some(0),
            dirty_background_ratio: Some(0),
            dirty_bytes: Some(plan.dirty_bytes),
            dirty_background_bytes: Some(plan.dirty_background_bytes),
            dirty_expire_centisecs: Some(3000),
            dirty_writeback_centisecs: Some(500),
            total_ram_bytes: 247 * GIB,
        };
        assert!(state.byte_mode_active());
        let assessment = assess(&state, &plan, &cfg(), "btrfs");
        assert!(!assessment.needs_tuning);
    }

    #[test]
    fn render_includes_both_byte_knobs() {
        let plan = plan_from_bandwidth(512 * MIB, BandwidthSource::Measured, &cfg());
        let rendered = render_sysctl_conf(&plan, 1.0, "generated for test");
        assert!(rendered.contains("vm.dirty_bytes = 2147483648"));
        assert!(rendered.contains("vm.dirty_background_bytes = 536870912"));
        assert!(rendered.contains("sbh tune --revert-writeback"));
    }

    #[test]
    fn conflict_detection_respects_lexical_load_order() {
        let ours = PathBuf::from("/etc/sysctl.d/99-sbh-writeback.conf");
        let later = PathBuf::from("/etc/sysctl.d/99-system-resource-protection.conf");
        let ratio_body = "vm.dirty_ratio = 10\nvm.swappiness = 10\n";
        let snippets = vec![
            (later.clone(), ratio_body.to_string()),
            // Earlier-loading file: we win, so it is not a conflict.
            (
                PathBuf::from("/etc/sysctl.d/10-baseline.conf"),
                ratio_body.to_string(),
            ),
            // Commented-out directive: not active, not a conflict.
            (
                PathBuf::from("/etc/sysctl.d/99-zz-commented.conf"),
                "# vm.dirty_ratio = 10\n".to_string(),
            ),
        ];
        let conflicts = conflicting_sysctl_files(&ours, &snippets);
        // Only the later-loading, actively-set file conflicts.
        assert_eq!(conflicts, vec![later]);
    }

    #[test]
    fn cow_filesystem_detection() {
        assert!(is_cow_filesystem("btrfs"));
        assert!(is_cow_filesystem("ZFS"));
        assert!(!is_cow_filesystem("ext4"));
        assert!(!is_cow_filesystem("xfs"));
    }

    #[test]
    fn human_bytes_formats_each_magnitude() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(512 * MIB), "512 MiB");
        assert_eq!(human_bytes(2 * GIB), "2.0 GiB");
        assert_eq!(human_bytes(GIB + GIB / 2), "1.5 GiB");
        // Just under 1 MiB still reads in bytes; just under 1 GiB reads in MiB.
        assert_eq!(human_bytes(MIB - 1), "1048575 B");
        assert_eq!(human_bytes(GIB - 1), "1024 MiB");
    }
}
