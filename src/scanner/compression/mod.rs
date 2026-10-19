//! Opt-in, lossless compression of explicitly selected cold files (bd-rxq5).
//!
//! This is a separate reclamation action, never a deletion admission override.
//! The operator command is preview-only by default. The daemon runs it only
//! when `[compress] enabled` is set (see `daemon::compress_tier`). Existing
//! marker/config/catalog protection and active-target leases apply even when
//! an operator names a file directly.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::core::config::Config;
use crate::platform::pal::Platform;

pub mod discovery;
pub mod journal;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux;

/// Limits for a serial compression pass. Logical input bytes bound rewrite and
/// verification work; they are never reported as physical bytes reclaimed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CompressionPolicy {
    /// Smallest admitted logical file length.
    pub min_size_bytes: u64,
    /// Required time since last modification; at least one hour.
    pub min_age_secs: u64,
    /// Maximum number of explicitly supplied files in one pass.
    pub max_files: usize,
    /// Maximum logical input bytes admitted in one pass.
    pub max_bytes: u64,
    /// Cooperative pass deadline, checked between I/O operations.
    pub timeout_secs: u64,
    /// Unprivileged available space retained in addition to rewrite headroom.
    pub min_free_bytes: u64,
}

impl Default for CompressionPolicy {
    fn default() -> Self {
        Self {
            min_size_bytes: 16 * 1024 * 1024,
            min_age_secs: 86_400,
            max_files: 128,
            max_bytes: 8 * 1024 * 1024 * 1024,
            timeout_secs: 300,
            min_free_bytes: 1024 * 1024 * 1024,
        }
    }
}

impl CompressionPolicy {
    /// Reject unbounded or dangerously weak policies before opening any file.
    pub fn validate(&self) -> io::Result<()> {
        if self.min_size_bytes == 0
            || self.min_age_secs < 3600
            || !(1..=4096).contains(&self.max_files)
            || self.max_bytes < self.min_size_bytes
            || !(1..=3600).contains(&self.timeout_secs)
            || self.min_free_bytes < 256 * 1024 * 1024
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "compression requires nonzero size/byte limits, age >= 3600s, 1..4096 files, 1..3600s, and free reserve >= 256 MiB",
            ));
        }
        Ok(())
    }
}

/// Applying requires two explicit acknowledgements, never an implicit default.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompressionMode {
    /// Mutate extents instead of producing a preview.
    pub apply: bool,
    /// Consent to COMPRESS_ZSTD's filesystem-wide compatibility consequence.
    pub allow_zstd_feature: bool,
    /// Who vouches that a rewrite may run while the filesystem is in use.
    pub acknowledgement: ConcurrencyAcknowledgement,
}

/// The second acknowledgement an apply needs, besides the zstd consent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConcurrencyAcknowledgement {
    /// Nobody did: an apply is refused.
    #[default]
    None,
    /// The operator stopped concurrent writers, snapshot and reflink creation
    /// (`--quiescent`). Process scans are observations, not a filesystem-wide
    /// mutation lock.
    Quiescent,
    /// The daemon's `[compress] enabled` opt-in, standing in for quiescence
    /// on a host nobody can quiesce. Content stays protected by the per-file
    /// checks every apply runs anyway: minimum idle age, open/mmap/lease
    /// vetoes, the stamp and scope rechecked between chunks, and a SHA-256
    /// re-read from disk. What the operator accepts by enabling it: a
    /// snapshot or reflink made during a pass keeps the old extents alive,
    /// so those bytes are not freed until it goes.
    Unattended,
}

/// A per-file result. `mutation_attempted` stays true after an ioctl failure:
/// the kernel may have completed some work before returning an error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionFileReport {
    /// Requested path, resolved to its canonical location after admission.
    /// Lossy UTF-8 is used for display only; execution retains the original
    /// OS pathname. An unusual filename must not prevent a post-mutation report.
    #[serde(serialize_with = "serialize_display_path")]
    pub path: PathBuf,
    /// Stable identifier for the durable pre-mutation intent, if one was prepared.
    #[serde(default)]
    pub operation_id: Option<String>,
    /// eligible, skipped, compressed, partial, or failed.
    pub outcome: String,
    /// Human-readable exclusion, failure, or completion explanation.
    pub detail: String,
    /// Logical length, used only for work budgeting.
    pub logical_bytes: u64,
    /// Unique physical data allocation bytes before mutation.
    pub physical_data_bytes_before: Option<u64>,
    /// Unique physical data allocation bytes after mutation, when measurable.
    pub physical_data_bytes_after: Option<u64>,
    /// Requested logical bytes for successfully completed chunk calls.
    pub processed_bytes: u64,
    /// Whether any mutating ioctl was entered, including a failed call.
    pub mutation_attempted: bool,
    /// SHA-256 before apply; absent in preview.
    pub sha256_before: Option<String>,
    /// SHA-256 after apply; absent if verification could not finish.
    pub sha256_after: Option<String>,
    /// Both hashes and stable device/inode/length/mtime were verified.
    pub content_verified: bool,
    /// Physical allocation evidence, never a prediction based on logical size.
    pub reclaim: Option<CompressionReclaimReport>,
    /// An accounting query failed or ran out of its separate postflight budget.
    pub accounting_error: Option<String>,
}

fn serialize_display_path<S: serde::Serializer>(
    path: &Path,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&path.to_string_lossy())
}

impl CompressionFileReport {
    // Only the Linux backend builds reports.
    #[cfg_attr(
        not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )),
        allow(dead_code)
    )]
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            operation_id: None,
            outcome: "skipped".into(),
            detail: String::new(),
            logical_bytes: 0,
            physical_data_bytes_before: None,
            physical_data_bytes_after: None,
            processed_bytes: 0,
            mutation_attempted: false,
            sha256_before: None,
            sha256_after: None,
            content_verified: false,
            reclaim: None,
            accounting_error: None,
        }
    }
}

/// Referenced savings are not proof that a mount can reuse those bytes yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionReclaimReport {
    /// Reduction in the file's referenced physical data allocation.
    pub referenced_bytes_saved: u64,
    /// Growth, reported separately rather than hidden by a zero savings value.
    pub referenced_bytes_added: u64,
    /// Retired allocations still present in the extent tree.
    pub old_data_bytes_pending: u64,
    /// Retired allocations observed absent from the extent tree.
    pub old_data_bytes_released: u64,
    /// Newly referenced allocations, subtracted from confirmed reclaim.
    pub new_data_bytes_allocated: u64,
    /// Net data-only reclaim confirmed by allocation-tree inspection. Excludes
    /// metadata overhead and is NOT the mount's free-space change.
    pub confirmed_data_bytes_reclaimed: u64,
}

/// Machine-readable pass result, including incomplete work and no-op platforms.
#[derive(Debug, Clone, Serialize)]
pub struct CompressionReport {
    /// Stable schema identifier.
    pub schema: &'static str,
    /// True unless explicit apply was requested.
    pub dry_run: bool,
    /// Native backend availability on this OS/architecture.
    pub supported: bool,
    /// Selected work limits, recorded for reproducibility.
    pub policy: CompressionPolicy,
    /// Private intent/outcome journal for this apply pass; absent for previews
    /// and passes without an eligible file. This path is display-only.
    pub journal_path: Option<String>,
    /// Results for files actually considered; unvisited inputs are counted.
    pub files: Vec<CompressionFileReport>,
    /// Explicit input paths not visited because a budget or safety stop fired.
    pub unvisited_files: usize,
    /// Pass-level stop reason, if any.
    pub stop_reason: Option<String>,
    /// Elapsed time including mandatory postflight verification.
    pub elapsed_ms: u64,
    /// 0: completed/preview/no-op; 2: failure before mutation; 4: partial pass.
    pub exit_code: i32,
}

/// One completed file visit, emitted before considering the next input.
/// References are valid only during the callback; retain owned copies as needed.
#[derive(Debug, Clone, Copy)]
pub struct CompressionObservation<'a> {
    /// The outcome, including skips and failures before mutation.
    pub file: &'a CompressionFileReport,
    /// Pinned journal's display location, if a journal was created.
    pub journal_path: Option<&'a Path>,
    /// True only after this file's outcome append and fsync succeeded.
    /// A prepared intent alone, a skip, or failed auditing never sets this flag.
    pub journal_outcome_recorded: bool,
}

/// Run on explicitly selected regular files.
///
/// No recursive scan, deletion, truncation, service changes, or persistent
/// policy changes are performed.
/// Each input needs a fresh admission; a preview is never execution authority.
/// Apply requires an fsynced intent journal beside the configured state file;
/// failure to record intent refuses mutation, and failed outcome recording
/// stops further work. The state file's parent must already exist.
pub fn run(
    paths: &[PathBuf],
    policy: &CompressionPolicy,
    mode: CompressionMode,
    config: &Config,
    platform: &dyn Platform,
) -> io::Result<CompressionReport> {
    run_observed(paths, policy, mode, config, platform, &mut |_| {})
}

/// Execute the same pass with per-file observations for activity logging.
///
/// Observers run after postflight and the outcome-journal write attempt, never
/// in place of a safety check or durable intent. They receive immutable evidence
/// and cannot authorize further mutations. Keep callbacks nonblocking; their
/// time counts against the cooperative pass deadline. Invalid requests and
/// unsupported platforms do not invoke the observer.
pub fn run_observed(
    paths: &[PathBuf],
    policy: &CompressionPolicy,
    mode: CompressionMode,
    config: &Config,
    platform: &dyn Platform,
    observer: &mut dyn FnMut(CompressionObservation<'_>),
) -> io::Result<CompressionReport> {
    run_checked(paths, None, policy, mode, config, platform, None, observer)
}

/// Execute the same pass on the files a [`discovery::discover`] walk selected.
///
/// Every executor check still runs. In addition, each file must be unchanged
/// since discovery and still lie beneath its pinned, unreplaced root without
/// new Git ancestry; this is rechecked before the rewrite and between chunks.
/// The selection narrows what may be rewritten and never authorizes more.
///
/// `stop`, once raised, ends the pass before the next file and a started
/// file before its next chunk (the daemon raises it when its policy no longer
/// allows changes); a later pass picks up the raw remainder of a file it
/// left part-compressed.
pub fn run_discovered(
    selection: &discovery::Selection,
    policy: &CompressionPolicy,
    mode: CompressionMode,
    config: &Config,
    platform: &dyn Platform,
    stop: Option<&AtomicBool>,
    observer: &mut dyn FnMut(CompressionObservation<'_>),
) -> io::Result<CompressionReport> {
    let paths = selection.paths();
    run_checked(
        &paths,
        Some(selection),
        policy,
        mode,
        config,
        platform,
        stop,
        observer,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_checked(
    paths: &[PathBuf],
    selection: Option<&discovery::Selection>,
    policy: &CompressionPolicy,
    mode: CompressionMode,
    config: &Config,
    platform: &dyn Platform,
    stop: Option<&AtomicBool>,
    observer: &mut dyn FnMut(CompressionObservation<'_>),
) -> io::Result<CompressionReport> {
    policy.validate()?;
    if paths.is_empty() || paths.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "supply 1..4096 explicit file paths",
        ));
    }
    if mode.apply
        && (!mode.allow_zstd_feature || mode.acknowledgement == ConcurrencyAcknowledgement::None)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "apply requires --allow-zstd-feature and --quiescent (or the daemon's [compress] opt-in); stop concurrent writers, snapshots and reflinks first",
        ));
    }
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        linux::run(
            paths, selection, policy, mode, config, platform, stop, observer,
        )
    }
    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    {
        let _ = (selection, config, platform, stop, observer);
        Ok(CompressionReport {
            schema: "sbh.compression.v1",
            dry_run: !mode.apply,
            supported: false,
            policy: policy.clone(),
            journal_path: None,
            files: Vec::new(),
            unvisited_files: paths.len(),
            stop_reason: Some("compression is supported only on Linux x86-64/AArch64 Btrfs".into()),
            elapsed_ms: 0,
            exit_code: 0,
        })
    }
}

#[cfg_attr(
    not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )),
    allow(dead_code)
)]
fn already_compressed(path: &Path) -> bool {
    let Some(suffix) = path.extension().and_then(|value| value.to_str()) else {
        return false;
    };
    [
        "gz", "zst", "xz", "bz2", "zip", "7z", "rar", "br", "lz4", "lzma", "png", "jpg", "jpeg",
        "webp", "avif", "heic", "mp3", "mp4", "mkv", "ogg", "flac", "woff", "woff2", "pdf",
    ]
    .iter()
    .any(|excluded| suffix.eq_ignore_ascii_case(excluded))
}

#[cfg_attr(
    not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )),
    allow(dead_code)
)]
fn cold_enough(modified: std::time::SystemTime, now: std::time::SystemTime, minimum: u64) -> bool {
    now.duration_since(modified)
        .is_ok_and(|age| age >= Duration::from_secs(minimum))
}

#[cfg(test)]
mod tests;
