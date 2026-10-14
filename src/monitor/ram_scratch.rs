//! Report-only accounting for tmpfs scratch against host RAM and swap (bd-ffjj).
//!
//! Mount capacity is a limit, not reserved physical memory. Count occupied
//! filesystems once, including runtime mounts, without adding deletion roots.
//! The VmSwap comparison is a risk heuristic, not attribution of swapped pages.

use std::collections::BTreeMap;
use std::io;

use serde::Serialize;

use crate::platform::pal::MemoryInfo;

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
        let mounts = self.mounts.iter().map(|mount| {
            format!("{:?}={} bytes", mount.path, mount.used_bytes)
        }).collect::<Vec<_>>().join(", ");
        format!(
            "RAM scratch: {} occupied tmpfs bytes across {} filesystems; RAM={} available={}; swap free={}/{}; process VmSwap={} (complete={}); reasons=[{}]; mounts=[{}]. Report only: no cleanup authority.",
            self.tmpfs_used_bytes, self.unique_filesystems,
            self.memory.total_bytes, self.memory.available_bytes,
            self.memory.swap_free_bytes, self.memory.swap_total_bytes,
            self.process_swap.bytes, self.process_swap.complete,
            self.reasons.join(", "), mounts,
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
    if memory.total_bytes == 0 || memory.available_bytes > memory.total_bytes
        || memory.swap_free_bytes > memory.swap_total_bytes
    {
        return Err(invalid("inconsistent RAM or swap counters"));
    }
    let nominal_ram_plus_swap_bytes = memory.total_bytes.checked_add(memory.swap_total_bytes)
        .ok_or_else(|| invalid("RAM + swap capacity overflow"))?;
    let mut filesystems = BTreeMap::<u64, u64>::new();
    for mount in &mounts {
        if mount.used_bytes > mount.total_bytes || mount.available_bytes > mount.total_bytes {
            return Err(invalid("inconsistent tmpfs capacity counters"));
        }
        filesystems.entry(mount.filesystem_id)
            .and_modify(|used| *used = (*used).max(mount.used_bytes))
            .or_insert(mount.used_bytes);
    }
    let tmpfs_used_bytes = filesystems.values().try_fold(0_u64, |total, used| {
        total.checked_add(*used).ok_or_else(|| invalid("tmpfs usage sum overflow"))
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
    mounts.sort_by(|a, b| b.used_bytes.cmp(&a.used_bytes).then_with(|| a.path.cmp(&b.path)));
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
/// This predicate does not write logs or change their route. It is available
/// to callers so observing pressure never implies adding logs to that pressure.
#[must_use]
pub fn ram_log_destination_healthy(memory: &MemoryInfo, total: u64, available: u64) -> bool {
    memory.total_bytes != 0 && memory.available_bytes <= memory.total_bytes
        && memory.swap_free_bytes <= memory.swap_total_bytes
        && !swap_nearly_full(memory) && total > 0 && available <= total
        && u128::from(available) * 5 >= u128::from(total)
}

fn runtime_mount_pressured(mount: &ScratchMount) -> bool {
    let path = std::path::Path::new(&mount.path);
    let runtime = path == std::path::Path::new("/run")
        || (path.parent() == Some(std::path::Path::new("/run/user"))
            && path.file_name().and_then(|name| name.to_str()).is_some_and(|name| {
                !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit())
            }));
    runtime && mount.used_bytes > 0
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
        Self { timeout_secs: 10, max_processes: 16_384, max_mounts: 256 }
    }
}

impl ScratchLimits {
    /// Refuse unbounded host scans.
    pub fn validate(self) -> io::Result<()> {
        if !(1..=60).contains(&self.timeout_secs)
            || !(1..=131_072).contains(&self.max_processes)
            || !(1..=1024).contains(&self.max_mounts)
        {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                "RAM scratch limits require 1..60 seconds, 1..131072 processes and 1..1024 mounts"));
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
    { linux::inspect(platform, limits) }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = platform;
        Ok(ScratchReport {
            schema: "sbh.ram_scratch.v1", read_only: true, supported: false,
            complete: false, scope: "Linux tmpfs collector unavailable on this platform",
            assessment: None, issues: Vec::new(), exit_code: 0,
        })
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

#[cfg(test)]
mod tests;
