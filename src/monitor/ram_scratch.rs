//! Report-only accounting for tmpfs scratch against host RAM and swap (bd-ffjj).
//!
//! Mount capacity is a limit, not reserved physical memory. Count occupied
//! filesystems once, including runtime mounts, without adding deletion roots.
//! The VmSwap comparison is a risk heuristic, not attribution of swapped pages.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use serde::Serialize;

use crate::platform::pal::{MemoryInfo, Platform};

pub mod attribution;

#[cfg(target_os = "linux")]
mod linux;

/// One visible tmpfs mount. Bind aliases share the same filesystem identifier.
#[derive(Debug, Clone, Serialize)]
pub struct ScratchMount {
    /// Display path; never execution authority.
    pub path: String,
    /// Filesystem device number, used only for deduplicating this observation.
    pub filesystem_id: u64,
    /// Filesystem size limit, not memory consumption.
    pub total_bytes: u64,
    /// Occupied filesystem blocks, including pages which may have been swapped.
    pub used_bytes: u64,
    /// Space currently available to an unprivileged writer.
    pub available_bytes: u64,
}

/// Sum of visible process VmSwap counters. These exclude shmem swap.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ProcessSwap {
    /// Sum observed in process status files; a lower bound when incomplete.
    pub bytes: u64,
    /// Process status files read successfully, including kernel threads.
    pub inspected: usize,
    /// Status files denied, malformed, oversized, or otherwise unreadable.
    pub unreadable: usize,
    /// Whether the bounded process enumeration finished without missing evidence.
    pub complete: bool,
}

/// Pure assessment shared by the operator report and future monitor integration.
#[derive(Debug, Clone, Serialize)]
pub struct ScratchAssessment {
    /// Host memory observations, not cgroup-specific allocation guarantees.
    pub memory: MemoryInfo,
    /// Observed process-private swap, with its visibility limitations.
    pub process_swap: ProcessSwap,
    /// Maximum observed occupied blocks per filesystem, summed across unique IDs.
    pub tmpfs_used_bytes: u64,
    /// Nominal RAM + configured swap. Zram may itself consume RAM: this is NOT
    /// a safe allocation allowance or a measurement of physical backing space.
    pub nominal_ram_plus_swap_bytes: u64,
    /// Number of independently counted tmpfs filesystems.
    pub unique_filesystems: usize,
    /// Every mount name remains visible, including aliases and runtime mounts.
    pub mounts: Vec<ScratchMount>,
    /// Stable, additive risk reasons; one assessment produces one warning.
    pub reasons: Vec<&'static str>,
}

impl ScratchAssessment {
    /// Whether any headroom heuristic found a condition requiring attention.
    #[must_use]
    pub fn warning(&self) -> bool {
        !self.reasons.is_empty()
    }

    /// One human-readable warning with observed quantities and mount names.
    #[must_use]
    pub fn summary(&self) -> String {
        let mounts = self
            .mounts
            .iter()
            .map(|mount| format!("{:?}={} bytes", mount.path, mount.used_bytes))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "RAM scratch: {} occupied tmpfs bytes across {} filesystems; RAM={} available={}; swap free={}/{}; process VmSwap={} (complete={}); reasons=[{}]; mounts=[{}]. Report only: no cleanup authority.",
            self.tmpfs_used_bytes,
            self.unique_filesystems,
            self.memory.total_bytes,
            self.memory.available_bytes,
            self.memory.swap_free_bytes,
            self.memory.swap_total_bytes,
            self.process_swap.bytes,
            self.process_swap.complete,
            self.reasons.join(", "),
            mounts,
        )
    }
}

/// Relate occupied tmpfs space to host headroom, without filesystem I/O.
///
/// Empty mounts never contribute their configured capacity as memory usage.
/// The maximum sample per filesystem avoids counting bind aliases repeatedly.
/// Missing process visibility is explicit and cannot establish swap attribution.
pub fn assess(
    memory: MemoryInfo,
    mut mounts: Vec<ScratchMount>,
    process_swap: ProcessSwap,
) -> io::Result<ScratchAssessment> {
    if memory.total_bytes == 0
        || memory.available_bytes > memory.total_bytes
        || memory.swap_free_bytes > memory.swap_total_bytes
    {
        return Err(invalid("inconsistent RAM or swap counters"));
    }
    let nominal_ram_plus_swap_bytes = memory
        .total_bytes
        .checked_add(memory.swap_total_bytes)
        .ok_or_else(|| invalid("RAM + swap capacity overflow"))?;
    let mut filesystems = BTreeMap::<u64, u64>::new();
    for mount in &mounts {
        if mount.used_bytes > mount.total_bytes || mount.available_bytes > mount.total_bytes {
            return Err(invalid("inconsistent tmpfs capacity counters"));
        }
        filesystems
            .entry(mount.filesystem_id)
            .and_modify(|used| *used = (*used).max(mount.used_bytes))
            .or_insert(mount.used_bytes);
    }
    let tmpfs_used_bytes = filesystems.values().try_fold(0_u64, |total, used| {
        total
            .checked_add(*used)
            .ok_or_else(|| invalid("tmpfs usage sum overflow"))
    })?;
    let mut reasons = Vec::new();
    if u128::from(tmpfs_used_bytes) * 2 > u128::from(memory.total_bytes) {
        reasons.push("tmpfs_exceeds_half_ram");
    }
    if swap_nearly_full(&memory) && tmpfs_used_bytes > 0 {
        if !process_swap.complete {
            reasons.push("low_swap_process_visibility_incomplete");
        } else if tmpfs_used_bytes > process_swap.bytes {
            reasons.push("low_swap_tmpfs_exceeds_process_swap");
        }
    }
    if mounts.iter().any(runtime_mount_pressured) {
        reasons.push("runtime_tmpfs_pressure");
    }
    mounts.sort_by(|a, b| {
        b.used_bytes
            .cmp(&a.used_bytes)
            .then_with(|| a.path.cmp(&b.path))
    });
    Ok(ScratchAssessment {
        memory,
        process_swap,
        tmpfs_used_bytes,
        nominal_ram_plus_swap_bytes,
        unique_filesystems: filesystems.len(),
        mounts,
        reasons,
    })
}

/// Shared risk predicate: less than 10% of nonzero configured swap is free.
#[must_use]
pub fn swap_nearly_full(memory: &MemoryInfo) -> bool {
    memory.swap_total_bytes > 0
        && u128::from(memory.swap_free_bytes) * 10 < u128::from(memory.swap_total_bytes)
}

/// Whether a RAM-backed log destination has enough observed headroom.
///
/// Require at least 10% host RAM available and 20% of the destination free,
/// as well as swap headroom when swap is configured. An empty tmpfs is not
/// evidence that the host can back new pages. These observations are not a
/// reservation or a cgroup-specific allocation guarantee.
#[must_use]
pub fn ram_log_destination_healthy(memory: &MemoryInfo, total: u64, available: u64) -> bool {
    memory.total_bytes != 0
        && memory.available_bytes <= memory.total_bytes
        && u128::from(memory.available_bytes) * 10 >= u128::from(memory.total_bytes)
        && memory.swap_free_bytes <= memory.swap_total_bytes
        && !swap_nearly_full(memory)
        && total > 0
        && available <= total
        && u128::from(available) * 5 >= u128::from(total)
}

/// Why the daemon must not use a RAM-backed log destination at `path`.
///
/// The mirror exists for a pressured log volume, and on Linux it lands on
/// `/dev/shm`. Adding it to a RAM mount that is itself short, or while RAM or
/// swap is nearly full, moves the pressure into RAM (fmd, bd-ffjj). A verified
/// non-RAM destination is outside this check. Unreadable filesystem identity
/// is not evidence of a disk destination; unreadable or inconsistent memory
/// and mount observations on a RAM destination also refuse.
#[must_use]
pub fn ram_log_mirror_refusal(platform: &dyn Platform, path: &Path) -> Option<String> {
    let dir = path.parent().unwrap_or(path);
    match platform.is_ram_backed(dir) {
        Ok(false) => return None,
        Ok(true) => {}
        Err(error) => {
            return Some(format!(
                "cannot determine whether {} is RAM-backed: {error}",
                dir.display()
            ));
        }
    }
    let memory = match platform.memory_info() {
        Ok(memory) => memory,
        Err(error) => return Some(format!("host memory is unreadable: {error}")),
    };
    let stats = match platform.fs_stats(dir) {
        Ok(stats) => stats,
        Err(error) => return Some(format!("{} is unreadable: {error}", dir.display())),
    };
    if stats.is_readonly {
        return Some(format!("{} is read-only", dir.display()));
    }
    if ram_log_destination_healthy(&memory, stats.total_bytes, stats.available_bytes) {
        return None;
    }
    Some(
        if memory.total_bytes == 0
            || memory.available_bytes > memory.total_bytes
            || memory.swap_free_bytes > memory.swap_total_bytes
        {
            "inconsistent host RAM or swap counters".to_owned()
        } else if swap_nearly_full(&memory) {
            format!(
                "swap is nearly full ({} of {} MiB free)",
                memory.swap_free_bytes >> 20,
                memory.swap_total_bytes >> 20
            )
        } else if u128::from(memory.available_bytes) * 10 < u128::from(memory.total_bytes) {
            format!(
                "host RAM is short ({} of {} MiB available)",
                memory.available_bytes >> 20,
                memory.total_bytes >> 20
            )
        } else if stats.total_bytes == 0 || stats.available_bytes > stats.total_bytes {
            format!("{} has inconsistent capacity counters", dir.display())
        } else {
            format!(
                "{} has {} of {} MiB free",
                dir.display(),
                stats.available_bytes >> 20,
                stats.total_bytes >> 20
            )
        },
    )
}

fn runtime_mount_pressured(mount: &ScratchMount) -> bool {
    let path = std::path::Path::new(&mount.path);
    let runtime = path == std::path::Path::new("/run")
        || (path.parent() == Some(std::path::Path::new("/run/user"))
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit())
                }));
    runtime
        && mount.used_bytes > 0
        && (mount.used_bytes >= 4 * 1024 * 1024 * 1024
            || (mount.total_bytes > 0
                && u128::from(mount.available_bytes) * 10 < u128::from(mount.total_bytes)))
}

/// Work limits for the live, read-only host inspection.
#[derive(Debug, Clone, Copy)]
pub struct ScratchLimits {
    /// Cooperative deadline; an in-flight filesystem call may exceed it.
    pub timeout_secs: u64,
    /// Maximum process status files attempted.
    pub max_processes: usize,
    /// Maximum tmpfs mount paths examined.
    pub max_mounts: usize,
}

impl Default for ScratchLimits {
    fn default() -> Self {
        Self {
            timeout_secs: 10,
            max_processes: 16_384,
            max_mounts: 256,
        }
    }
}

impl ScratchLimits {
    /// Refuse unbounded host scans.
    pub fn validate(self) -> io::Result<()> {
        if !(1..=60).contains(&self.timeout_secs)
            || !(1..=131_072).contains(&self.max_processes)
            || !(1..=1024).contains(&self.max_mounts)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "RAM scratch limits require 1..60 seconds, 1..131072 processes and 1..1024 mounts",
            ));
        }
        Ok(())
    }
}

/// Bounded live report. Incomplete observations are not a healthy verdict.
#[derive(Debug, Serialize)]
pub struct ScratchReport {
    /// Stable machine-readable schema.
    pub schema: &'static str,
    /// True: no new deletion roots, process changes or writes are performed.
    pub read_only: bool,
    /// Native collector availability.
    pub supported: bool,
    /// True only when all bounded host observations were obtained.
    pub complete: bool,
    /// Scope limitation, including namespace and lack of cgroup accounting.
    pub scope: &'static str,
    /// Assessment of the successfully collected observations.
    pub assessment: Option<ScratchAssessment>,
    /// Bounded diagnostics for missing evidence.
    pub issues: Vec<String>,
    /// 0 healthy/unsupported, 1 warning, 4 incomplete inspection.
    pub exit_code: i32,
}

/// Collect visible Linux tmpfs mount usage, host memory, and process swap.
///
/// Runtime mounts are included for reporting only. This does not modify the
/// existing actionable special-location registry or authorize any deletion.
pub fn inspect(
    platform: &dyn crate::platform::pal::Platform,
    limits: ScratchLimits,
) -> io::Result<ScratchReport> {
    limits.validate()?;
    #[cfg(target_os = "linux")]
    {
        linux::inspect(platform, limits)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = platform;
        Ok(ScratchReport {
            schema: "sbh.ram_scratch.v1",
            read_only: true,
            supported: false,
            complete: false,
            scope: "Linux tmpfs collector unavailable on this platform",
            assessment: None,
            issues: Vec::new(),
            exit_code: 0,
        })
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod log_headroom_tests {
    use super::{MemoryInfo, ram_log_destination_healthy, ram_log_mirror_refusal};
    use crate::platform::pal::{FsStats, MockPlatform, MountPoint, PlatformPaths};
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    fn memory(available: u64) -> MemoryInfo {
        MemoryInfo {
            total_bytes: 100,
            available_bytes: available,
            swap_total_bytes: 0,
            swap_free_bytes: 0,
        }
    }

    #[test]
    fn empty_tmpfs_does_not_authorize_logging_under_host_ram_pressure() {
        for available in [0, 1, 9] {
            assert!(!ram_log_destination_healthy(&memory(available), 100, 100));
        }
        assert!(ram_log_destination_healthy(&memory(10), 100, 20));
    }

    #[test]
    fn invalid_counters_and_fractional_thresholds_fail_closed() {
        assert!(!ram_log_destination_healthy(&memory(101), 100, 100));
        assert!(!ram_log_destination_healthy(&memory(50), 100, 101));
        let mut sample = memory(10);
        sample.total_bytes = 101;
        assert!(!ram_log_destination_healthy(&sample, 100, 100));
        sample.available_bytes = 11;
        assert!(ram_log_destination_healthy(&sample, 100, 100));
        sample.swap_free_bytes = 1;
        assert!(!ram_log_destination_healthy(&sample, 100, 100));
    }

    #[test]
    fn headroom_comparisons_do_not_overflow() {
        let sample = MemoryInfo {
            total_bytes: u64::MAX,
            available_bytes: u64::MAX,
            swap_total_bytes: u64::MAX,
            swap_free_bytes: u64::MAX,
        };
        assert!(ram_log_destination_healthy(&sample, u64::MAX, u64::MAX));
    }

    fn platform(ram: bool, available: u64, readonly: bool, with_stats: bool) -> MockPlatform {
        let path = PathBuf::from("/scratch");
        let mount = MountPoint {
            path: path.clone(),
            device: "scratch".into(),
            fs_type: "tmpfs".into(),
            is_ram_backed: ram,
        };
        let mut stats = HashMap::new();
        if with_stats {
            stats.insert(
                path.clone(),
                FsStats {
                    total_bytes: 100,
                    free_bytes: 100,
                    available_bytes: 100,
                    fs_type: "tmpfs".into(),
                    mount_point: path,
                    is_readonly: readonly,
                },
            );
        }
        MockPlatform::new(
            vec![mount],
            stats,
            memory(available),
            PlatformPaths::default(),
        )
    }

    #[test]
    fn ram_destination_requires_memory_and_writable_mount_evidence() {
        let path = Path::new("/scratch/activity.jsonl");
        let reason = ram_log_mirror_refusal(&platform(true, 9, false, true), path).unwrap();
        assert!(reason.starts_with("host RAM is short"));
        let reason = ram_log_mirror_refusal(&platform(true, 50, true, true), path).unwrap();
        assert!(reason.ends_with("is read-only"));
        assert!(ram_log_mirror_refusal(&platform(true, 50, false, false), path).is_some());
        assert!(ram_log_mirror_refusal(&platform(true, 50, false, true), path).is_none());
    }

    #[test]
    fn verified_disk_destination_does_not_need_host_memory_headroom() {
        let path = Path::new("/scratch/activity.jsonl");
        assert!(ram_log_mirror_refusal(&platform(false, 0, false, false), path).is_none());
    }
}
