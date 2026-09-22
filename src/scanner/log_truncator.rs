//! Active append-only log truncation.
//!
//! Some agent workloads (notably `codex`) hold long-lived `O_WRONLY` fds on
//! log files that grow unboundedly. The standard delete path is blocked by
//! the FileOpen veto when any process holds an fd, so sbh watches the disk
//! fill without acting — exactly the failure mode that put css/ts2/trj at
//! 99% disk on 2026-05-13 (`codex-tui.log` reached 318G/132G/81G).
//!
//! This module reclaims that space by truncating matching files in place via
//! `ftruncate(2)` (Rust `File::set_len(0)`):
//!   - The inode size goes to 0, releasing its allocated blocks subject to
//!     filesystem snapshots and other retention mechanisms.
//!   - The inode itself survives, so the writer's open fd keeps targeting the
//!     same file. Subsequent appends continue without disruption (the file
//!     becomes temporarily sparse if the writer is not in O_APPEND mode).
//!
//! Contrast with `unlink`: under an open fd, the inode is orphaned but the
//! kernel holds its blocks until every fd closes — i.e. **no space is
//! reclaimed** until the process exits. Truncate-in-place can reclaim an
//! active log without killing the writer.
//!
//! Patterns are matched with a tiny built-in matcher rather than pulling in
//! `glob`/`globset`. Each `paths` entry is an absolute path; literal `*`
//! wildcards inside a path segment match direct entries of that segment's parent.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime};

use parking_lot::Mutex;

use crate::core::config::LogTruncationConfig;

mod backoff;
use backoff::{FailureBackoff, FailureKey};

#[cfg(test)]
mod pressure_tests;

static FAILURE_BACKOFF: OnceLock<Mutex<FailureBackoff>> = OnceLock::new();

/// Report from a single truncation sweep.
#[derive(Debug, Clone, Default)]
pub struct LogTruncationReport {
    /// Number of files truncated in-place.
    pub files_truncated: usize,
    /// Number of files that would have been truncated in dry-run mode.
    pub files_would_truncate: usize,
    /// Number of matching paths rejected or failed before truncation.
    pub files_skipped: usize,
    /// Reclaimed-byte estimate, bounded by both logical and allocated size.
    pub bytes_reclaimed: u64,
    /// Corresponding byte estimate for dry-run mode.
    pub bytes_would_reclaim: u64,
    /// Per-path errors observed while expanding or processing patterns.
    pub errors: Vec<(PathBuf, String)>,
    /// Wall-clock time spent in the truncation sweep.
    pub duration: Duration,
    /// Whether the sweep reported candidates without mutating files.
    pub dry_run: bool,
    /// Paths that matched a pattern but were rejected by a safety gate.
    /// Useful for `--explain`-style debugging.
    pub skipped_with_reason: Vec<(PathBuf, SkipReason)>,
}

/// Safety reason for a matched log file that was not truncated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The matched path was not a regular file.
    NotARegularFile,
    /// The matched file had fewer reclaimable bytes than the minimum size.
    BelowMinSize,
    /// The matched file was newer than the configured minimum age.
    YoungerThanMinAge,
    /// The matched path was a symlink.
    SymlinkRejected,
    /// A recent failure, or a saturated failure budget, is cooling down.
    FailureBackoff,
    /// The opened object differs from the inspected file, or its identity
    /// cannot be verified on this platform.
    IdentityChanged,
}

/// Execute one truncation pass.
///
/// `free_pct` is the current free-disk percentage. When it is at or below
/// `config.pressure_free_pct_ceiling`, the `min_age_minutes` gate is bypassed
/// so the daemon can act decisively under emergency pressure. Failures still
/// cool down for a full minute; pressure does not turn them into an I/O loop.
/// Dry runs neither consult nor change the process-local failure history.
pub fn truncate_oversized_logs(
    config: &LogTruncationConfig,
    free_pct: f64,
    dry_run: bool,
) -> LogTruncationReport {
    let backoff = FAILURE_BACKOFF.get_or_init(|| Mutex::new(FailureBackoff::default()));
    truncate_with_backoff(
        config,
        free_pct,
        dry_run,
        backoff,
        Instant::now,
        process_candidate,
    )
}

fn truncate_with_backoff(
    config: &LogTruncationConfig,
    free_pct: f64,
    dry_run: bool,
    backoff: &Mutex<FailureBackoff>,
    clock: impl Fn() -> Instant,
    mut process: impl FnMut(&Path, &LogTruncationConfig, bool, bool) -> Result<Outcome, String>,
) -> LogTruncationReport {
    let start = Instant::now();
    let mut report = LogTruncationReport {
        dry_run,
        ..Default::default()
    };

    if !config.enabled {
        report.duration = start.elapsed();
        return report;
    }

    let bypass_age_gate =
        free_pct <= f64::from(config.pressure_free_pct_ceiling) || config.min_age_minutes == 0;
    let mut seen_patterns = HashSet::new();
    let mut seen_paths = HashSet::new();

    for pattern in &config.paths {
        if !seen_patterns.insert(pattern) {
            continue;
        }
        let key = FailureKey::Pattern(PathBuf::from(pattern));
        if !dry_run && backoff.lock().blocked(&key, clock()) {
            record_skip(&mut report, PathBuf::from(pattern), SkipReason::FailureBackoff);
            continue;
        }
        let mut matches: Vec<PathBuf> = Vec::new();
        if let Err(err) = expand_pattern(Path::new(pattern), &mut matches) {
            if !dry_run {
                backoff.lock().failed(key, clock());
            }
            report
                .errors
                .push((PathBuf::from(pattern), format!("expand failed: {err}")));
            report.files_skipped += 1;
            continue;
        }
        for path in matches {
            if !seen_paths.insert(path.clone()) {
                continue;
            }
            let key = FailureKey::Candidate(path.clone());
            if !dry_run && backoff.lock().blocked(&key, clock()) {
                record_skip(&mut report, path, SkipReason::FailureBackoff);
                continue;
            }
            // Never hold the shared history lock across filesystem I/O.
            match process(&path, config, bypass_age_gate, dry_run) {
                Ok(Outcome::Truncated(bytes)) => {
                    backoff.lock().succeeded(&key);
                    report.files_truncated += 1;
                    report.bytes_reclaimed = report.bytes_reclaimed.saturating_add(bytes);
                }
                Ok(Outcome::WouldTruncate(bytes)) => {
                    report.files_would_truncate += 1;
                    report.bytes_would_reclaim = report.bytes_would_reclaim.saturating_add(bytes);
                }
                Ok(Outcome::Skipped(reason)) => record_skip(&mut report, path, reason),
                Err(e) => {
                    if !dry_run {
                        // Start the full cooldown after the failing operation,
                        // not before a potentially slow filesystem call.
                        backoff.lock().failed(key, clock());
                    }
                    report.errors.push((path, e));
                    report.files_skipped += 1;
                }
            }
        }
    }

    report.duration = start.elapsed();
    report
}

fn record_skip(report: &mut LogTruncationReport, path: PathBuf, reason: SkipReason) {
    report.files_skipped += 1;
    report.skipped_with_reason.push((path, reason));
}

enum Outcome {
    Truncated(u64),
    WouldTruncate(u64),
    Skipped(SkipReason),
}

fn process_candidate(
    path: &Path,
    config: &LogTruncationConfig,
    bypass_age_gate: bool,
    dry_run: bool,
) -> Result<Outcome, String> {
    process_candidate_with_opener(
        path,
        config,
        bypass_age_gate,
        dry_run,
        open_candidate_for_truncate,
    )
}

fn process_candidate_with_opener(
    path: &Path,
    config: &LogTruncationConfig,
    bypass_age_gate: bool,
    dry_run: bool,
    open: impl FnOnce(&Path) -> Result<fs::File, String>,
) -> Result<Outcome, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if let Some(reason) = candidate_skip(&meta, config, bypass_age_gate)? {
        return Ok(Outcome::Skipped(reason));
    }
    if dry_run {
        return Ok(Outcome::WouldTruncate(reclaimable_bytes(&meta)));
    }
    let f = open(path)?;
    let opened_meta = f.metadata().map_err(|e| e.to_string())?;
    // O_NOFOLLOW refuses leaf symlinks, not a different regular file or a
    // replaced parent directory. Bind mutation to the inspected inode too.
    if !same_file(&meta, &opened_meta) {
        return Ok(Outcome::Skipped(SkipReason::IdentityChanged));
    }
    // A writer/rotator can shrink or refresh the same inode while it opens.
    // Reapply the gates to descriptor metadata, then mutate that descriptor.
    if let Some(reason) = candidate_skip(&opened_meta, config, bypass_age_gate)? {
        return Ok(Outcome::Skipped(reason));
    }
    let bytes = reclaimable_bytes(&opened_meta);
    f.set_len(0).map_err(|e| e.to_string())?;
    Ok(Outcome::Truncated(bytes))
}

fn candidate_skip(
    meta: &fs::Metadata,
    config: &LogTruncationConfig,
    bypass_age_gate: bool,
) -> Result<Option<SkipReason>, String> {
    if meta.file_type().is_symlink() {
        return Ok(Some(SkipReason::SymlinkRejected));
    }
    if !meta.is_file() {
        return Ok(Some(SkipReason::NotARegularFile));
    }
    let bytes = reclaimable_bytes(meta);
    if bytes == 0 || bytes < config.min_size_bytes {
        return Ok(Some(SkipReason::BelowMinSize));
    }
    if !bypass_age_gate && config.min_age_minutes > 0 {
        let modified = meta.modified().map_err(|e| e.to_string())?;
        let age = SystemTime::now()
            .duration_since(modified)
            .unwrap_or(Duration::ZERO);
        if age < Duration::from_secs(config.min_age_minutes.saturating_mul(60)) {
            return Ok(Some(SkipReason::YoungerThanMinAge));
        }
    }
    Ok(None)
}

/// A non-append writer resumes at its old offset after truncation, creating
/// holes rather than reallocating its old contents. Do not repeatedly truncate
/// a huge apparent file that is only consuming a few blocks.
fn reclaimable_bytes(meta: &fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.len().min(meta.blocks().saturating_mul(512))
    }
    #[cfg(not(unix))]
    {
        meta.len()
    }
}

fn same_file(before: &fs::Metadata, opened: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        before.is_file()
            && opened.is_file()
            && before.dev() == opened.dev()
            && before.ino() == opened.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (before, opened);
        // Size and timestamps cannot establish identity for a destructive
        // operation. Refuse until this platform supplies stable file IDs.
        false
    }
}

fn open_candidate_for_truncate(path: &Path) -> Result<fs::File, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(|e| e.to_string())
    }
    #[cfg(not(unix))]
    {
        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| e.to_string())
    }
}

/// Expand a pattern with literal `*` wildcards by walking the filesystem from
/// the longest non-wildcard prefix.
fn expand_pattern(pattern: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    if !pattern.is_absolute() {
        return Err("only absolute patterns are supported".to_string());
    }
    let segments: Vec<String> = pattern
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    // segments[0] is "/" on Unix when the path is absolute.
    expand_recursive(Path::new("/"), &segments, 1, out);
    Ok(())
}

fn expand_recursive(prefix: &Path, segments: &[String], idx: usize, out: &mut Vec<PathBuf>) {
    if idx == segments.len() {
        out.push(prefix.to_path_buf());
        return;
    }
    let seg = &segments[idx];
    if seg.contains('*') {
        let Ok(entries) = fs::read_dir(prefix) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if segment_matches(seg, &name_str) {
                let next = prefix.join(&name);
                expand_recursive(&next, segments, idx + 1, out);
            }
        }
    } else {
        let next = prefix.join(seg);
        // Only descend if it exists, to avoid spurious not-found entries.
        if next.symlink_metadata().is_ok() {
            expand_recursive(&next, segments, idx + 1, out);
        }
    }
}

/// Match a single path segment against a pattern that may contain `*`.
///
/// `*` matches any run of characters within the segment (greedy, non-empty
/// or empty). Other characters, including `?`, are treated literally.
/// Forward slashes never appear inside a segment.
fn segment_matches(pattern: &str, name: &str) -> bool {
    // Shell glob convention: hidden entries are only matched when the
    // pattern explicitly opens with a literal dot. A pattern starting with
    // `*` does NOT cross the hidden-file boundary, so `*` doesn't match
    // `.hidden` and `*.log` doesn't match `.hidden.log`.
    if let Some(first) = name.as_bytes().first()
        && *first == b'.'
        && !pattern.starts_with('.')
    {
        return false;
    }
    glob_match(pattern.as_bytes(), name.as_bytes())
}

fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    // Iterative two-cursor matcher with `*` backtracking.
    let (mut p, mut t) = (0, 0);
    let (mut star, mut t_after_star) = (None, 0);
    while t < text.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            t_after_star = t;
            p += 1;
        } else if p < pattern.len() && pattern[p] == text[t] {
            p += 1;
            t += 1;
        } else if let Some(star_idx) = star {
            p = star_idx + 1;
            t_after_star += 1;
            t = t_after_star;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn glob_segment_handles_star_and_literal() {
        assert!(segment_matches("*.log", "codex-tui.log"));
        assert!(segment_matches("codex-tui.log", "codex-tui.log"));
        assert!(!segment_matches("*.log", "codex-tui.txt"));
        assert!(segment_matches("*", "anything"));
        assert!(!segment_matches("*", ".hidden"));
        assert!(segment_matches(".hidden", ".hidden"));
        assert!(segment_matches("foo-*-bar", "foo-XYZ-bar"));
        assert!(segment_matches("run?.log", "run?.log"));
        assert!(!segment_matches("run?.log", "run1.log"));
    }

    #[test]
    fn truncate_in_place_reclaims_bytes_and_preserves_inode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.log");
        {
            let mut f = File::create(&path).unwrap();
            f.write_all(&vec![b'x'; 4096]).unwrap();
        }
        let original_inode = fs::metadata(&path).unwrap();
        let original_size = original_inode.len();
        assert_eq!(original_size, 4096);

        // Match the directory's path explicitly.
        let pattern = path.to_string_lossy().into_owned();
        let config = LogTruncationConfig {
            enabled: true,
            paths: vec![pattern],
            min_size_bytes: 1, // any non-empty file qualifies
            pressure_free_pct_ceiling: 100,
            min_age_minutes: 0,
        };

        let report = truncate_oversized_logs(&config, 50.0, false);
        assert_eq!(report.files_truncated, 1, "{report:?}");
        assert_eq!(report.bytes_reclaimed, 4096);
        assert_eq!(report.errors.len(), 0);

        let new_meta = fs::metadata(&path).unwrap();
        assert_eq!(new_meta.len(), 0);
    }

    #[test]
    fn skips_file_below_min_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("small.log");
        File::create(&path).unwrap().write_all(b"tiny").unwrap();

        let config = LogTruncationConfig {
            enabled: true,
            paths: vec![path.to_string_lossy().into_owned()],
            min_size_bytes: 1024,
            pressure_free_pct_ceiling: 100,
            min_age_minutes: 0,
        };

        let report = truncate_oversized_logs(&config, 50.0, false);
        assert_eq!(report.files_truncated, 0);
        assert_eq!(report.files_skipped, 1);
        assert_eq!(fs::metadata(&path).unwrap().len(), 4);
    }

    #[test]
    fn dry_run_reports_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.log");
        File::create(&path)
            .unwrap()
            .write_all(&vec![b'x'; 2048])
            .unwrap();

        let config = LogTruncationConfig {
            enabled: true,
            paths: vec![path.to_string_lossy().into_owned()],
            min_size_bytes: 1024,
            pressure_free_pct_ceiling: 100,
            min_age_minutes: 0,
        };

        let report = truncate_oversized_logs(&config, 50.0, true);
        assert_eq!(report.files_truncated, 0);
        assert_eq!(report.files_would_truncate, 1);
        assert_eq!(report.bytes_would_reclaim, 2048);
        assert_eq!(report.bytes_reclaimed, 0);
        assert_eq!(fs::metadata(&path).unwrap().len(), 2048);
    }

    #[test]
    fn disabled_config_does_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.log");
        File::create(&path)
            .unwrap()
            .write_all(&vec![b'x'; 2048])
            .unwrap();

        let config = LogTruncationConfig {
            enabled: false,
            paths: vec![path.to_string_lossy().into_owned()],
            min_size_bytes: 1024,
            pressure_free_pct_ceiling: 100,
            min_age_minutes: 0,
        };

        let report = truncate_oversized_logs(&config, 50.0, false);
        assert_eq!(report.files_truncated, 0);
        assert_eq!(fs::metadata(&path).unwrap().len(), 2048);
    }

    #[test]
    fn rejects_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.log");
        File::create(&target)
            .unwrap()
            .write_all(&vec![b'x'; 2048])
            .unwrap();
        let link = dir.path().join("alias.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let config = LogTruncationConfig {
            enabled: true,
            paths: vec![link.to_string_lossy().into_owned()],
            min_size_bytes: 1024,
            pressure_free_pct_ceiling: 100,
            min_age_minutes: 0,
        };

        let report = truncate_oversized_logs(&config, 50.0, false);
        assert_eq!(report.files_truncated, 0);
        assert_eq!(report.files_skipped, 1);
        // Target file unchanged.
        assert_eq!(fs::metadata(&target).unwrap().len(), 2048);
    }

    #[test]
    fn age_gate_bypassed_under_pressure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fresh.log");
        File::create(&path)
            .unwrap()
            .write_all(&vec![b'x'; 2048])
            .unwrap();

        let config = LogTruncationConfig {
            enabled: true,
            paths: vec![path.to_string_lossy().into_owned()],
            min_size_bytes: 1024,
            pressure_free_pct_ceiling: 15,
            min_age_minutes: 60, // very fresh file
        };

        // free_pct 50.0 (healthy) -> gate engaged, skip
        let report = truncate_oversized_logs(&config, 50.0, false);
        assert_eq!(report.files_truncated, 0);
        assert_eq!(report.files_skipped, 1);

        // free_pct 5.0 (pressure) -> gate bypassed
        let report = truncate_oversized_logs(&config, 5.0, false);
        assert_eq!(report.files_truncated, 1);
        assert_eq!(report.bytes_reclaimed, 2048);
    }

    #[test]
    fn expands_star_segment_across_homes() {
        let dir = tempfile::tempdir().unwrap();
        let home_a = dir.path().join("alice").join(".codex").join("log");
        let home_b = dir.path().join("bob").join(".codex").join("log");
        fs::create_dir_all(&home_a).unwrap();
        fs::create_dir_all(&home_b).unwrap();
        let file_a = home_a.join("codex-tui.log");
        let file_b = home_b.join("codex-tui.log");
        File::create(&file_a)
            .unwrap()
            .write_all(&vec![b'a'; 2048])
            .unwrap();
        File::create(&file_b)
            .unwrap()
            .write_all(&vec![b'b'; 2048])
            .unwrap();

        let pattern = format!("{}/*/.codex/log/codex-tui.log", dir.path().display());
        let config = LogTruncationConfig {
            enabled: true,
            paths: vec![pattern],
            min_size_bytes: 1024,
            pressure_free_pct_ceiling: 100,
            min_age_minutes: 0,
        };

        let report = truncate_oversized_logs(&config, 50.0, false);
        assert_eq!(report.files_truncated, 2);
        assert_eq!(report.bytes_reclaimed, 4096);
        assert_eq!(fs::metadata(&file_a).unwrap().len(), 0);
        assert_eq!(fs::metadata(&file_b).unwrap().len(), 0);
    }

    // Linux-only: APFS/HFS+ reject non-UTF-8 byte sequences in filenames, so the
    // `\xFF` test fixture can't be created on macOS. The behavior under test
    // (wildcard expansion preserving exotic OsString bytes) is reachable only
    // on filesystems that admit such names — which on this codebase means Linux.
    #[cfg(target_os = "linux")]
    #[test]
    fn wildcard_expansion_preserves_non_utf8_file_names() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let dir = tempfile::tempdir().unwrap();
        let file_name = OsString::from_vec(b"codex-\xFF.log".to_vec());
        let path = dir.path().join(&file_name);
        File::create(&path)
            .unwrap()
            .write_all(&vec![b'x'; 2048])
            .unwrap();

        let pattern = format!("{}/*.log", dir.path().display());
        let config = LogTruncationConfig {
            enabled: true,
            paths: vec![pattern],
            min_size_bytes: 1024,
            pressure_free_pct_ceiling: 100,
            min_age_minutes: 0,
        };

        let report = truncate_oversized_logs(&config, 50.0, false);
        assert_eq!(report.files_truncated, 1, "{report:?}");
        assert!(report.errors.is_empty(), "{report:?}");
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
    }
}
