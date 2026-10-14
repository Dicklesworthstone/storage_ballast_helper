//! Native execution with fresh application-level admission at every chunk.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use nix::sys::statvfs::{FsFlags, fstatvfs};
use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat2};
use sbh_btrfs::{FileStamp, IdleIoPriority, MAX_CHUNK_BYTES, ZstdConsent};

use super::journal::{AuditSession, digest};
use super::{
    CompressionFileReport, CompressionMode, CompressionObservation, CompressionPolicy,
    CompressionReclaimReport, CompressionReport, already_compressed, cold_enough,
};
use crate::core::config::Config;
use crate::platform::pal::Platform;
use crate::scanner::{active_lease, protection};

pub(super) mod repository;

#[allow(clippy::too_many_lines)] // one bounded pass, in order
pub(super) fn run(
    paths: &[std::path::PathBuf],
    policy: &CompressionPolicy,
    mode: CompressionMode,
    config: &Config,
    platform: &dyn Platform,
    observer: &mut dyn FnMut(CompressionObservation<'_>),
) -> io::Result<CompressionReport> {
    let start = Instant::now();
    let deadline = start + Duration::from_secs(policy.timeout_secs);
    let mut report = CompressionReport {
        schema: "sbh.compression.v1",
        dry_run: !mode.apply,
        supported: true,
        policy: policy.clone(),
        journal_path: None,
        files: Vec::new(),
        unvisited_files: paths.len(),
        stop_reason: None,
        elapsed_ms: 0,
        exit_code: 0,
    };
    let mut admitted_bytes = 0_u64;
    let mut identities = BTreeSet::new();
    let mut audit = AuditSession::new(
        config
            .paths
            .state_file
            .with_file_name("compression-journal"),
        paths.len(),
        policy,
    );
    // Apply passes run all verification and rewrite I/O at idle priority. A
    // failure to lower priority is an error, not permission to run at normal IO.
    let priority = if mode.apply {
        Some(IdleIoPriority::enter()?)
    } else {
        None
    };
    for path in paths.iter().take(policy.max_files) {
        if Instant::now() >= deadline {
            report.stop_reason = Some("pass deadline exhausted".into());
            break;
        }
        let mut item = CompressionFileReport::new(path);
        let result = process_file(
            path,
            &mut item,
            policy,
            mode,
            config,
            platform,
            deadline,
            &mut admitted_bytes,
            &mut identities,
            &mut audit,
        );
        if let Err(error) = result {
            item.outcome = if item.mutation_attempted {
                "partial"
            } else {
                "failed"
            }
            .into();
            item.detail = error.to_string();
        }
        // Complete the durable record even when an error escaped postflight.
        // A failed intent write poisons the journal and must not be followed by
        // a footer that makes an uncertain prefix look like a completed run.
        if !audit.failed()
            && let Err(error) = audit.complete(&item)
        {
            item.outcome = if item.mutation_attempted {
                "partial"
            } else {
                "failed"
            }
            .into();
            let _ = write!(item.detail, "; durable outcome recording failed: {error}");
        }
        let unsafe_to_continue =
            audit.failed() || (item.mutation_attempted && item.outcome != "compressed");
        // Observability follows the durable outcome attempt, including failures.
        // The callback receives no mutable state or authority to bypass a stop.
        observer(CompressionObservation {
            file: &item,
            journal_path: audit.path(),
            journal_outcome_recorded: item.operation_id.is_some() && !audit.failed(),
        });
        report.files.push(item);
        if unsafe_to_continue {
            report.stop_reason = Some(if audit.failed() {
                "stopped because durable compression auditing failed; inspect the journal and per-file report"
            } else {
                "stopped after incomplete or unverified mutation; inspect the per-file report"
            }.into());
            break;
        }
    }
    report.unvisited_files = paths.len() - report.files.len();
    if report.unvisited_files != 0 && report.stop_reason.is_none() {
        report.stop_reason = Some("file-count budget exhausted".into());
    }
    let priority_failed = if let Some(priority) = priority
        && let Err(error) = priority.restore()
    {
        report.stop_reason = Some(format!("could not restore I/O priority: {error}"));
        true
    } else {
        false
    };
    let attempted = report.files.iter().any(|item| item.mutation_attempted);
    let failed = priority_failed
        || audit.failed()
        || report
            .files
            .iter()
            .any(|item| matches!(item.outcome.as_str(), "failed" | "partial"));
    report.exit_code = pass_exit_code(attempted, failed, report.unvisited_files);
    report.journal_path = audit.path().map(|path| path.to_string_lossy().into_owned());
    if !audit.failed()
        && let Err(error) = audit.finish(report.exit_code, report.unvisited_files)
    {
        report.exit_code = if attempted { 4 } else { 2 };
        report.stop_reason = Some(format!(
            "could not durably finish the compression journal: {error}"
        ));
    }
    report.elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(report)
}

fn pass_exit_code(mutation_attempted: bool, failed: bool, unvisited: usize) -> i32 {
    if unvisited != 0 || (mutation_attempted && failed) {
        4
    } else if failed {
        2
    } else {
        0
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn process_file(
    path: &Path,
    report: &mut CompressionFileReport,
    policy: &CompressionPolicy,
    mode: CompressionMode,
    config: &Config,
    platform: &dyn Platform,
    deadline: Instant,
    admitted_bytes: &mut u64,
    identities: &mut BTreeSet<(u64, u64)>,
    audit: &mut AuditSession,
) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        report.detail = "only explicitly selected regular files are accepted; symlinks and directories are not followed".into();
        return Ok(());
    }
    report.logical_bytes = metadata.len();
    if metadata.len() < policy.min_size_bytes {
        report.detail = "below minimum file size".into();
        return Ok(());
    }
    if !cold_enough(metadata.modified()?, SystemTime::now(), policy.min_age_secs) {
        report.detail = "file is too young or its modification time is in the future".into();
        return Ok(());
    }
    if already_compressed(path) {
        report.detail = "already-compressed file suffix".into();
        return Ok(());
    }
    if metadata.len() > policy.max_bytes.saturating_sub(*admitted_bytes) {
        report.detail =
            "file exceeds remaining logical-byte budget; no partial-file budget admission".into();
        return Ok(());
    }
    let canonical = path.canonicalize()?;
    report.path.clone_from(&canonical);
    let stats = platform.fs_stats(&canonical).map_err(other)?;
    if stats.fs_type != "btrfs" {
        report.detail = format!(
            "unsupported filesystem {}; no compression attempted",
            stats.fs_type
        );
        return Ok(());
    }
    if stats.is_readonly {
        report.detail = "read-only filesystem".into();
        return Ok(());
    }
    check_protection(&canonical, config, platform)?;
    // Resolve every component without symlinks in one kernel operation. There
    // is no fallback to a pathname-following open on unsupported kernels.
    let flags = OFlags::CLOEXEC
        | OFlags::NOFOLLOW
        | OFlags::NONBLOCK
        | OFlags::NOATIME
        | if mode.apply {
            OFlags::RDWR
        } else {
            OFlags::RDONLY
        };
    let file = File::from(openat2(
        CWD,
        &canonical,
        flags,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?);
    let stamp = FileStamp::read(&file)?;
    if stamp.device != metadata.dev()
        || stamp.inode != metadata.ino()
        || stamp.size != metadata.len()
        || stamp.mtime != metadata.mtime()
        || stamp.mtime_nsec != metadata.mtime_nsec()
        || stamp.ctime != metadata.ctime()
        || stamp.ctime_nsec != metadata.ctime_nsec()
    {
        return Err(io::Error::other(
            "file changed while opening its pinned descriptor",
        ));
    }
    if !identities.insert((stamp.device, stamp.inode)) {
        report.detail = "duplicate inode in this pass".into();
        return Ok(());
    }
    if mode.apply {
        // Serializes cooperating compression processes. This is NOT a claim
        // that arbitrary writers or snapshot creators honor an advisory lock.
        file.try_lock()?;
    }
    check_active(&canonical, file.as_raw_fd(), platform)?;
    let before = sbh_btrfs::inspect(&file, deadline)?;
    report.physical_data_bytes_before = Some(before.physical_data_bytes);
    if let Some(reason) = before.exclusion() {
        report.detail = reason.into();
        return Ok(());
    }
    check_headroom(&file, policy.min_free_bytes)?;
    verify_path(&canonical, &file, before.stamp)?;
    *admitted_bytes = admitted_bytes
        .checked_add(before.stamp.size)
        .ok_or_else(|| io::Error::other("compression work budget overflow"))?;
    if !mode.apply {
        report.outcome = "eligible".into();
        report.detail = "eligible at inspection time; preview changed no extents and promises no compression ratio".into();
        return Ok(());
    }
    let hash_before = digest(&file, before.stamp.size, deadline)?;
    report.sha256_before = Some(hash_before.clone());
    if FileStamp::read(&file)? != before.stamp {
        return Err(io::Error::other("file changed during preflight hashing"));
    }
    // This fsync is an admission gate, not best-effort telemetry. The first
    // ioctl is unreachable until the intent and journal filename are durable.
    // The live safety checks below still run after journal I/O consumes time.
    audit.prepare(report, &file)?;
    let consent = ZstdConsent::acknowledge_filesystem_compatibility_change();
    let mut expected = before.stamp;
    let mut operation_error = None;
    while report.processed_bytes < before.stamp.size {
        let offset = report.processed_bytes;
        let length = (before.stamp.size - offset).min(MAX_CHUNK_BYTES);
        let result = (|| -> io::Result<()> {
            budget(deadline)?;
            check_protection(&canonical, config, platform)?;
            check_active(&canonical, file.as_raw_fd(), platform)?;
            check_headroom(&file, policy.min_free_bytes)?;
            verify_path(&canonical, &file, expected)?;
            budget(deadline)?;
            report.mutation_attempted = true;
            sbh_btrfs::compress_range(&file, offset, length, consent, deadline)?;
            expected = FileStamp::read(&file)?;
            Ok(())
        })();
        match result {
            Ok(()) => report.processed_bytes += length,
            Err(error) => {
                operation_error = Some(error.to_string());
                break;
            }
        }
    }
    if !report.mutation_attempted {
        return Err(io::Error::other(
            operation_error.unwrap_or_else(|| "compression stopped before mutation".into()),
        ));
    }
    // Postflight has a separate, bounded budget. A rewrite timeout must not
    // suppress content verification or erase the fact that mutation happened.
    let verification_deadline = Instant::now() + Duration::from_secs(120);
    match digest(&file, before.stamp.size, verification_deadline) {
        Ok(hash_after) => {
            let stable = before
                .stamp
                .same_contents_and_identity(FileStamp::read(&file)?);
            report.content_verified = stable && hash_before == hash_after;
            report.sha256_after = Some(hash_after);
            if !report.content_verified {
                operation_error = Some(
                    "content or file identity changed; stop and investigate concurrent writers"
                        .into(),
                );
            }
        }
        Err(error) => {
            operation_error = Some(format!(
                "postflight content verification incomplete: {error}"
            ));
        }
    }
    let accounting_deadline = Instant::now() + Duration::from_secs(30);
    match sbh_btrfs::inspect(&file, accounting_deadline) {
        Ok(after) => {
            report.physical_data_bytes_after = Some(after.physical_data_bytes);
            if report.content_verified {
                match sbh_btrfs::reclaim_evidence(&file, &before, &after, accounting_deadline) {
                    Ok(evidence) => {
                        report.reclaim = Some(CompressionReclaimReport {
                            referenced_bytes_saved: evidence.referenced_bytes_saved,
                            referenced_bytes_added: evidence.referenced_bytes_added,
                            old_data_bytes_pending: evidence.old_data_bytes_pending,
                            old_data_bytes_released: evidence.old_data_bytes_released,
                            new_data_bytes_allocated: evidence.new_data_bytes_allocated,
                            confirmed_data_bytes_reclaimed: evidence.confirmed_data_bytes_reclaimed,
                        });
                    }
                    Err(error) => report.accounting_error = Some(error.to_string()),
                }
            } else {
                report.accounting_error =
                    Some("reclaim is not attributed to an unverified file".into());
            }
        }
        Err(error) => report.accounting_error = Some(error.to_string()),
    }
    if let Some(error) = operation_error {
        report.outcome = "partial".into();
        report.detail = error;
    } else if let Some(error) = &report.accounting_error {
        report.outcome = "partial".into();
        report.detail =
            format!("content verified, but physical reclaim accounting is incomplete: {error}");
    } else if report.physical_data_bytes_after > report.physical_data_bytes_before {
        report.outcome = "partial".into();
        report.detail = "content verified, but physical data allocation grew; stopping the pass rather than increasing pressure further".into();
    } else {
        report.outcome = "compressed".into();
        report.detail = "content, size and mtime verified; physical data accounting excludes metadata and delayed reuse".into();
    }
    Ok(())
}

fn check_protection(path: &Path, config: &Config, platform: &dyn Platform) -> io::Result<()> {
    repository::check_file(path)?;
    check_control_paths(path, config)?;
    // Construct a fresh registry: a negative ancestor-marker cache from
    // preflight must never hide a marker created before the next chunk.
    let mut registry = protection::ProtectionRegistry::new(Some(&config.scanner.protected_paths))
        .map_err(other)?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("file has no parent"))?;
    registry.discover_ancestor_markers(parent).map_err(other)?;
    if registry.is_protected(path) {
        return Err(io::Error::other(
            "protected by marker or configured path rule",
        ));
    }
    if active_lease::path_is_actively_leased(path) {
        return Err(io::Error::other("active or uncertain target lease"));
    }
    let overlaps = protection::find_sacred_overlaps_with_config(
        path,
        &platform.sacred_paths(),
        protection::StowawayScanConfig {
            max_depth: 0,
            ..Default::default()
        },
    )
    .map_err(other)?;
    if !overlaps.is_empty() {
        return Err(io::Error::other("sacred-path catalog overlap"));
    }
    Ok(())
}

// A lazy activity logger can open its destinations only AFTER the first file's
// outcome. Do not rely on the open-fd veto to protect that first input from
// being sbh's own state, configuration, database, log, or recovery evidence.
fn check_control_paths(path: &Path, config: &Config) -> io::Result<()> {
    for protected in [
        &config.paths.config_file,
        &config.paths.state_file,
        &config.paths.sqlite_db,
        &config.paths.jsonl_log,
        &config.update.metadata_cache_file,
        &config.notifications.file.path,
    ] {
        check_control_overlap(path, protected, false)?;
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = config.paths.sqlite_db.as_os_str().to_os_string();
        name.push(suffix);
        check_control_overlap(path, Path::new(&name), false)?;
    }
    check_control_overlap(path, &crate::logger::jsonl::ram_fallback_path(), false)?;
    check_control_overlap(
        path,
        &config
            .paths
            .state_file
            .with_file_name("compression-journal"),
        true,
    )
}

fn check_control_overlap(path: &Path, protected: &Path, subtree: bool) -> io::Result<()> {
    let overlaps = |target: &Path| path == target || (subtree && path.starts_with(target));
    if overlaps(protected) {
        return Err(io::Error::other(
            "sbh control or activity path is not a compression input",
        ));
    }
    match protected.canonicalize() {
        Ok(target) if overlaps(&target) => Err(io::Error::other(
            "sbh control-path alias is not a compression input",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!(
                "cannot resolve protected sbh control path {}: {error}",
                protected.display()
            ),
        )),
    }
}

fn check_active(path: &Path, own_fd: i32, platform: &dyn Platform) -> io::Result<()> {
    let open = platform.open_files_under(path).map_err(other)?;
    if !open.complete {
        return Err(io::Error::other("open-file inspection was incomplete"));
    }
    // Exempt ONLY this pinned descriptor, not every file owned by this PID.
    // stdout redirected into an input file must still veto compression.
    if open
        .files
        .iter()
        .any(|item| foreign_reference(item.pid, item.fd, own_fd))
    {
        return Err(io::Error::other("file has active open references"));
    }
    let executables = platform.executables_under(path).map_err(other)?;
    if !executables.complete || !executables.processes.is_empty() {
        return Err(io::Error::other(
            "executable inspection incomplete or file is executing",
        ));
    }
    if !platform.mmap_regions_under(path).map_err(other)?.is_empty() {
        return Err(io::Error::other("file has active memory mappings"));
    }
    if platform
        .build_directories_in_use()
        .iter()
        .any(|(_, root)| path.starts_with(root))
    {
        return Err(io::Error::other("file is inside an active build directory"));
    }
    Ok(())
}

fn foreign_reference(pid: i32, fd: Option<i32>, own_fd: i32) -> bool {
    u32::try_from(pid).ok() != Some(std::process::id()) || fd != Some(own_fd)
}

fn check_headroom(file: &File, reserve: u64) -> io::Result<()> {
    // Query the pinned descriptor, never a path that could now name a different
    // mount. Keep two chunk allocations beyond the operator's minimum reserve.
    let stats = fstatvfs(file).map_err(io::Error::from)?;
    if stats.flags().contains(FsFlags::ST_RDONLY) {
        return Err(io::Error::other("filesystem became read-only"));
    }
    let available = stats
        .blocks_available()
        .checked_mul(stats.fragment_size())
        .ok_or_else(|| io::Error::other("filesystem available-byte overflow"))?;
    let needed = reserve
        .checked_add(2 * MAX_CHUNK_BYTES)
        .ok_or_else(|| io::Error::other("rewrite reserve overflow"))?;
    if available < needed {
        return Err(io::Error::other(
            "insufficient free-space reserve for bounded copy-on-write compression",
        ));
    }
    Ok(())
}

fn verify_path(path: &Path, file: &File, expected: FileStamp) -> io::Result<()> {
    if FileStamp::read(file)? != expected {
        return Err(io::Error::other(
            "pinned file changed since its last verified state",
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.dev() != expected.device
        || metadata.ino() != expected.inode
        || path.canonicalize()? != path
        || fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))? != path
    {
        return Err(io::Error::other(
            "path or ancestor was replaced, renamed, or unlinked",
        ));
    }
    Ok(())
}

fn budget(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "compression work budget exhausted",
        ))
    } else {
        Ok(())
    }
}

fn other(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod audit_exit_tests {
    use super::pass_exit_code;

    #[test]
    fn a_later_failure_cannot_hide_an_earlier_successful_mutation() {
        assert_eq!(pass_exit_code(true, true, 0), 4);
        assert_eq!(pass_exit_code(false, true, 0), 2);
        assert_eq!(pass_exit_code(true, false, 0), 0);
        assert_eq!(pass_exit_code(false, false, 0), 0);
        assert_eq!(pass_exit_code(false, false, 1), 4);
    }
}

#[cfg(test)]
mod control_path_tests {
    use super::{Config, Path, check_control_paths, fs};

    fn config(root: &Path) -> Config {
        let mut config = Config::default();
        config.paths.config_file = root.join("config.toml");
        config.paths.state_file = root.join("state.json");
        config.paths.sqlite_db = root.join("activity.sqlite3");
        config.paths.jsonl_log = root.join("activity.jsonl");
        config.update.metadata_cache_file = root.join("update.json");
        config.notifications.file.path = root.join("notifications.jsonl");
        config
    }

    #[test]
    fn control_files_and_database_sidecars_are_protected_before_logging_starts() {
        let temp = tempfile::tempdir().unwrap();
        let config = config(temp.path());
        for name in [
            "config.toml",
            "state.json",
            "activity.sqlite3",
            "activity.jsonl",
            "activity.sqlite3-wal",
            "activity.sqlite3-shm",
            "activity.sqlite3-journal",
            "update.json",
            "notifications.jsonl",
        ] {
            let path = temp.path().join(name);
            fs::write(&path, b"untouched").unwrap();
            assert!(check_control_paths(&path, &config).is_err(), "{name}");
            assert_eq!(fs::read(&path).unwrap(), b"untouched");
        }
        let cold = temp.path().join("ordinary-cold.jsonl");
        fs::write(&cold, b"eligible for other checks").unwrap();
        assert!(check_control_paths(&cold, &config).is_ok());
    }

    #[test]
    fn journal_subtrees_and_configured_aliases_cannot_be_compressed() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = config(temp.path());
        let journal = temp.path().join("compression-journal");
        fs::create_dir(&journal).unwrap();
        let old_run = journal.join("old-run.jsonl");
        fs::write(&old_run, b"durable history").unwrap();
        assert!(check_control_paths(&old_run, &config).is_err());
        let unrelated = temp.path().join("compression-journal-other.jsonl");
        fs::write(&unrelated, b"not inside the journal").unwrap();
        assert!(check_control_paths(&unrelated, &config).is_ok());
        let alias = temp.path().join("log-alias");
        std::os::unix::fs::symlink(&unrelated, &alias).unwrap();
        config.paths.jsonl_log = alias;
        assert!(check_control_paths(&unrelated, &config).is_err());
        assert_eq!(fs::read(&old_run).unwrap(), b"durable history");
    }
}
