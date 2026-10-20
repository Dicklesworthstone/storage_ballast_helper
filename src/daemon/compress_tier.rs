//! Opt-in daemon tier: lossless zstd compression of cold files on btrfs
//! (bd-rxq5).
//!
//! With `[compress] enabled`, the monitor calls [`CompressTier::tick`] on every
//! tick. A pass starts when a configured root sits on btrfs whose mount is at
//! or above `start_level`, no pass is running, and `interval_minutes` have
//! passed since the last start. The pass runs on its own `sbh-compress` thread,
//! so discovery and rewrite I/O do not run on the monitor. It finds files under
//! due roots, resuming where the previous pass stopped, and runs the same
//! checked executor as `sbh compress --discover --apply`. Every file outcome
//! reaches the activity log, and a summary line names the bytes saved. Nothing
//! is ever deleted, and a root on another filesystem is never touched.
//!
//! On ts2 (2026-10-14..16, `/` at 93-97% and sbh at Red or Critical) the same
//! method, run by hand, freed several hundred GB from idle scratch while the
//! deletion scanner freed megabytes per hour.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::core::config::{CompressConfig, Config};
use crate::logger::compression::CompressionActivity;
use crate::logger::dual::{ActivityEvent, ActivityLoggerHandle};
use crate::monitor::pid::PressureLevel;
use crate::platform::pal::Platform;
use crate::scanner::compression::{
    self, CompressionMode, CompressionObservation, CompressionReport, ConcurrencyAcknowledgement,
    discovery,
};
use crate::tuning::writeback::human_bytes;

/// A configured root as the monitor sees it this tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootStatus {
    /// The configured directory.
    pub root: PathBuf,
    /// Whether the filesystem holding it is btrfs.
    pub btrfs: bool,
    /// Pressure of the mount holding it, if the daemon monitors that mount.
    pub level: Option<PressureLevel>,
}

/// The roots a pass should cover now; empty when no pass is due. Pure: it
/// reads no clock and touches no file.
#[must_use]
pub fn due_roots(
    config: &CompressConfig,
    roots: &[RootStatus],
    running: bool,
    last_start: Option<Instant>,
    now: Instant,
) -> Vec<PathBuf> {
    let Some(start) = due_start_level(config, running, last_start, now) else {
        return Vec::new();
    };
    roots
        .iter()
        .filter(|status| status.btrfs && status.level.is_some_and(|level| level >= start))
        .map(|status| status.root.clone())
        .collect()
}

/// Decide whether mount evidence is needed, before issuing filesystem queries.
/// A busy or cooling tier must not repeatedly stat roots on the monitor thread.
fn due_start_level(
    config: &CompressConfig,
    running: bool,
    last_start: Option<Instant>,
    now: Instant,
) -> Option<PressureLevel> {
    let start = config.start_pressure_level()?;
    let interval = Duration::from_secs(config.interval_minutes.saturating_mul(60));
    if !config.enabled
        || running
        || last_start.is_some_and(|last| now.saturating_duration_since(last) < interval)
    {
        return None;
    }
    Some(start)
}

/// Scheduling state of the tier: at most one pass in flight.
#[derive(Debug, Default)]
pub struct CompressTier {
    running: Arc<AtomicBool>,
    /// Raised by [`CompressTier::stop_running_pass`]; the pass checks it
    /// before each file and between the chunks of a started one.
    stop: Arc<AtomicBool>,
    last_start: Option<Instant>,
    /// Where discovery may resume without skipping unvisited selected files.
    /// Execution commits only its visited prefix; after all selected files
    /// have been considered, discovery's own frontier takes over.
    /// `None` starts from the top. This is not a durable completion ledger.
    resume_after: Arc<Mutex<Option<PathBuf>>>,
}

impl CompressTier {
    /// Start a pass on its own thread when one is due.
    pub fn tick(
        &mut self,
        now: Instant,
        config: &Config,
        platform: &Arc<dyn Platform>,
        mount_levels: &HashMap<PathBuf, PressureLevel>,
        logger: &ActivityLoggerHandle,
    ) {
        let running = self.running.load(Ordering::Acquire);
        if due_start_level(&config.compress, running, self.last_start, now).is_none() {
            return;
        }
        let statuses = root_statuses(&config.compress.roots, platform.as_ref(), mount_levels);
        let roots = due_roots(&config.compress, &statuses, running, self.last_start, now);
        if roots.is_empty() {
            return;
        }
        self.last_start = Some(now);
        // No pass is running (due_roots checked), so no stop is pending.
        self.stop.store(false, Ordering::Release);
        self.running.store(true, Ordering::Release);
        let guard = RunningGuard(Arc::clone(&self.running));
        let stop = Arc::clone(&self.stop);
        let resume_after = Arc::clone(&self.resume_after);
        let config = config.clone();
        let platform = Arc::clone(platform);
        let logger = logger.clone();
        let spawned = std::thread::Builder::new()
            .name("sbh-compress".to_string())
            .spawn(move || {
                let _guard = guard;
                let message = run_pass(
                    &roots,
                    &config,
                    platform.as_ref(),
                    &resume_after,
                    &stop,
                    &logger,
                );
                eprintln!("[SBH-COMPRESS] {message}");
                logger.send(ActivityEvent::Info { message });
            });
        if let Err(error) = spawned {
            // The closure, and with it the guard, was dropped: running is clear.
            eprintln!("[SBH-COMPRESS] pass thread failed to start: {error}");
        }
    }

    /// Tell a running pass to stop: the daemon's policy no longer allows
    /// changes (observe or fallback-safe mode, the kill switch, dry-run, or
    /// the tier was switched off). It stops before its next file, or before
    /// the next chunk of the file it is rewriting, whose raw remainder a
    /// later pass picks up. Does nothing when no pass is running.
    pub fn stop_running_pass(&self) {
        if self.running.load(Ordering::Acquire) && !self.stop.swap(true, Ordering::AcqRel) {
            eprintln!(
                "[SBH-COMPRESS] stopping the running pass: the policy no longer allows changes"
            );
        }
    }
}

/// Clears `running` when the pass ends, however it ends.
struct RunningGuard(Arc<AtomicBool>);

impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn root_statuses(
    roots: &[PathBuf],
    platform: &dyn Platform,
    mount_levels: &HashMap<PathBuf, PressureLevel>,
) -> Vec<RootStatus> {
    roots
        .iter()
        .map(|root| {
            let stats = platform.fs_stats(root).ok();
            RootStatus {
                root: root.clone(),
                btrfs: stats.as_ref().is_some_and(|stats| stats.fs_type == "btrfs"),
                level: stats.and_then(|stats| mount_levels.get(&stats.mount_point).copied()),
            }
        })
        .collect()
}

/// One pass: discover, then apply to exactly what discovery selected.
/// Returns the summary line.
fn run_pass(
    roots: &[PathBuf],
    config: &Config,
    platform: &dyn Platform,
    resume_after: &Mutex<Option<PathBuf>>,
    stop: &AtomicBool,
    logger: &ActivityLoggerHandle,
) -> String {
    let policy = &config.compress.policy;
    let after = resume_after.lock().ok().and_then(|resume| resume.clone());
    // The largest budgets discovery accepts. A resumed walk re-reads the
    // cursor's ancestors first (a temp root can hold tens of thousands of
    // entries), so small budgets would leave little for new ground.
    let limits = discovery::DiscoveryLimits {
        max_entries: 1_000_000,
        max_directories: 8192,
        timeout_secs: 60,
        after,
        ..discovery::DiscoveryLimits::default()
    };
    let selection = match discovery::discover(roots, policy, &limits, config, platform) {
        Ok(selection) => selection,
        Err(error) => {
            // A cursor from other roots (the due set changed) is refused; drop
            // it so the next pass starts from the top instead of failing too.
            if let Ok(mut resume) = resume_after.lock() {
                *resume = None;
            }
            return format!("discovery under {} root(s) failed: {error}", roots.len());
        }
    };
    let report = selection.report();
    let next = match report
        .resume_after_hex
        .as_deref()
        .map(discovery::continuation_path)
        .transpose()
    {
        Ok(next) => next,
        Err(error) => return format!("discovery returned an invalid continuation: {error}"),
    };
    if report.selected_files == 0 {
        // No selected work can be lost here. Retain discovery progress through
        // excluded entries, including incomplete pages with no eligible files.
        if let Ok(mut resume) = resume_after.lock() {
            *resume = next;
        }
        return format!(
            "nothing eligible under {} root(s) ({} entries examined{})",
            roots.len(),
            report.entries_examined,
            if report.complete { "" } else { ", partial" }
        );
    }
    let mode = CompressionMode {
        apply: true,
        allow_zstd_feature: config.compress.allow_zstd_feature,
        acknowledgement: ConcurrencyAcknowledgement::Unattended,
    };
    let mut observer = |observation: CompressionObservation<'_>| {
        record_outcome(observation, logger);
    };
    execute_and_resume(&selection.paths(), next, resume_after, || {
        compression::run_discovered(
            &selection,
            policy,
            mode,
            config,
            platform,
            Some(stop),
            &mut observer,
        )
    })
}

/// Commit a skip hint only after the checked executor returns. Discovery can
/// run far ahead of rewriting; its last selected path is not an execution
/// receipt. Timeouts and safety stops must leave the unvisited tail available.
/// The closure is the ordinary executor, with unchanged admission and auditing.
fn execute_and_resume(
    selected: &[PathBuf],
    discovery_next: Option<PathBuf>,
    resume_after: &Mutex<Option<PathBuf>>,
    execute: impl FnOnce() -> io::Result<CompressionReport>,
) -> String {
    let before = match resume_after.lock() {
        Ok(resume) => resume.clone(),
        Err(_) => return "pass refused before any rewrite: continuation state is poisoned".into(),
    };
    // Do not hold the cursor mutex during native I/O or activity callbacks.
    let report = match execute() {
        Ok(report) => report,
        Err(error) => return format!("pass refused before any rewrite: {error}"),
    };
    let summary = summarize(&report);
    if !report.supported || report.dry_run {
        return summary;
    }
    let visited = report.files.len();
    if visited.checked_add(report.unvisited_files) != Some(selected.len())
        || report
            .files
            .iter()
            .zip(selected)
            .any(|(file, path)| &file.path != path)
    {
        // A canonical path changing after selection, or a future executor
        // changing its ordering, must not move the cursor outside the observed
        // prefix. Retrying is safer than guessing from lossy display strings.
        return format!("{summary}; continuation retained: execution was not a selected prefix");
    }
    let next = if report.unvisited_files == 0 {
        discovery_next
    } else if visited == 0 {
        before
    } else {
        // A visit includes a checked skip/failure, not just a successful
        // compression. Retrying a permanently refused first file every pass
        // would starve the rest; its outcome remains in the pass report.
        Some(selected[visited - 1].clone())
    };
    match resume_after.lock() {
        Ok(mut resume) => {
            *resume = next;
            summary
        }
        Err(_) => format!("{summary}; continuation unavailable: next pass must rediscover"),
    }
}

/// An outcome with a journal entry becomes a ledger row; anything else is
/// already in the pass summary.
fn record_outcome(observation: CompressionObservation<'_>, logger: &ActivityLoggerHandle) {
    let Some(journal) = observation.journal_path else {
        return;
    };
    if let Ok(activity) = CompressionActivity::new(
        observation.file,
        journal,
        observation.journal_outcome_recorded,
    ) {
        logger.send(ActivityEvent::CompressionRecorded(Box::new(activity)));
    }
}

/// Outcome counts and referenced bytes saved. Saved bytes are not yet free
/// space: btrfs releases an old extent once nothing references it.
fn summarize(report: &CompressionReport) -> String {
    let count = |outcome: &str| {
        report
            .files
            .iter()
            .filter(|file| file.outcome == outcome)
            .count()
    };
    let saved: u64 = report
        .files
        .iter()
        .filter_map(|file| file.reclaim.as_ref())
        .map(|reclaim| reclaim.referenced_bytes_saved)
        .sum();
    format!(
        "pass: {} compressed, {} partial, {} skipped, {} failed, {} unvisited; {} referenced \
         bytes saved{}",
        count("compressed"),
        count("partial"),
        count("skipped"),
        count("failed"),
        report.unvisited_files,
        human_bytes(saved),
        report
            .stop_reason
            .as_deref()
            .map(|reason| format!("; stopped: {reason}"))
            .unwrap_or_default()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> Vec<PathBuf> {
        ["/cache/a.bin", "/cache/b.bin", "/cache/c.bin"]
            .into_iter()
            .map(PathBuf::from)
            .collect()
    }

    fn execution_report(selected: &[PathBuf], outcomes: &[&str]) -> CompressionReport {
        use crate::scanner::compression::{CompressionFileReport, CompressionPolicy};

        assert!(outcomes.len() <= selected.len());
        CompressionReport {
            schema: "sbh.compression.v1",
            dry_run: false,
            supported: true,
            policy: CompressionPolicy::default(),
            journal_path: None,
            files: selected
                .iter()
                .zip(outcomes)
                .map(|(path, outcome)| CompressionFileReport {
                    path: path.clone(),
                    operation_id: None,
                    outcome: (*outcome).to_owned(),
                    detail: "injected executor visit; no native mutation".into(),
                    logical_bytes: 1024,
                    physical_data_bytes_before: None,
                    physical_data_bytes_after: None,
                    processed_bytes: 0,
                    mutation_attempted: false,
                    sha256_before: None,
                    sha256_after: None,
                    content_verified: false,
                    reclaim: None,
                    accounting_error: None,
                })
                .collect(),
            unvisited_files: selected.len() - outcomes.len(),
            stop_reason: (outcomes.len() < selected.len()).then(|| "injected stop".into()),
            elapsed_ms: 0,
            exit_code: if outcomes.len() < selected.len() {
                4
            } else {
                0
            },
        }
    }

    #[test]
    fn partial_execution_commits_only_the_visited_prefix_after_the_executor_returns() {
        let selected = paths();
        let previous = Some(PathBuf::from("/cache/0.bin"));
        let cursor = Mutex::new(previous.clone());
        let message = execute_and_resume(&selected, Some(selected[2].clone()), &cursor, || {
            assert_eq!(
                *cursor.lock().unwrap(),
                previous,
                "no early cursor publication"
            );
            Ok(execution_report(&selected, &["compressed"]))
        });
        assert_eq!(*cursor.lock().unwrap(), Some(selected[0].clone()));
        assert!(message.contains("2 unvisited"), "{message}");
    }

    #[test]
    fn complete_discovery_does_not_wrap_while_selected_files_are_unvisited() {
        let selected = paths();
        let cursor = Mutex::new(None);
        execute_and_resume(&selected, None, &cursor, || {
            Ok(execution_report(&selected, &["skipped", "failed"]))
        });
        assert_eq!(*cursor.lock().unwrap(), Some(selected[1].clone()));
    }

    #[test]
    fn fully_visited_selection_uses_discoverys_frontier_or_wraps_on_completion() {
        let selected = paths();
        // Discovery can finish excluded entries beyond the last selected file.
        for next in [Some(PathBuf::from("/cache/z-excluded")), None] {
            let cursor = Mutex::new(Some(PathBuf::from("/cache/0.bin")));
            execute_and_resume(&selected, next.clone(), &cursor, || {
                Ok(execution_report(
                    &selected,
                    &["skipped", "failed", "compressed"],
                ))
            });
            assert_eq!(*cursor.lock().unwrap(), next);
        }
    }

    #[test]
    fn failed_or_zero_visit_pass_retains_the_incoming_cursor() {
        let selected = paths();
        for previous in [None, Some(PathBuf::from("/cache/0.bin"))] {
            let cursor = Mutex::new(previous.clone());
            let message = execute_and_resume(&selected, Some(selected[2].clone()), &cursor, || {
                Err(io::Error::other("I/O priority admission failed"))
            });
            assert!(message.contains("I/O priority admission failed"));
            assert_eq!(*cursor.lock().unwrap(), previous);
            execute_and_resume(&selected, None, &cursor, || {
                Ok(execution_report(&selected, &[]))
            });
            assert_eq!(*cursor.lock().unwrap(), previous);
        }
    }

    #[test]
    fn preview_and_unsupported_reports_never_consume_daemon_work() {
        let selected = paths();
        let previous = Some(PathBuf::from("/cache/0.bin"));
        for (supported, dry_run) in [(false, false), (true, true)] {
            let cursor = Mutex::new(previous.clone());
            execute_and_resume(&selected, None, &cursor, || {
                let mut report = execution_report(&selected, &["eligible", "eligible", "eligible"]);
                report.supported = supported;
                report.dry_run = dry_run;
                Ok(report)
            });
            assert_eq!(*cursor.lock().unwrap(), previous);
        }
    }

    #[test]
    fn malformed_or_nonprefix_execution_reports_cannot_advance_continuation() {
        let selected = paths();
        let previous = Some(PathBuf::from("/cache/0.bin"));
        for case in 0..5 {
            let cursor = Mutex::new(previous.clone());
            let message = execute_and_resume(&selected, Some(selected[2].clone()), &cursor, || {
                let mut report = execution_report(&selected, &["skipped", "failed"]);
                match case {
                    0 => report.unvisited_files = usize::MAX,
                    1 => report.unvisited_files = 0,
                    2 => report.files.swap(0, 1),
                    3 => report.files[1].path = selected[0].clone(),
                    _ => report.files[0].path = PathBuf::from("/other/replaced.bin"),
                }
                Ok(report)
            });
            assert!(
                message.contains("continuation retained"),
                "case {case}: {message}"
            );
            assert_eq!(*cursor.lock().unwrap(), previous);
        }
    }

    #[test]
    fn consecutive_partial_passes_reach_every_unvisited_file_before_wrapping() {
        let selected = paths();
        let cursor = Mutex::new(None);
        let mut visited = Vec::new();
        for expected in &selected {
            let after = cursor.lock().unwrap().clone();
            let remaining: Vec<_> = selected
                .iter()
                .filter(|path| after.as_ref().is_none_or(|after| *path > after))
                .cloned()
                .collect();
            assert_eq!(remaining.first(), Some(expected));
            execute_and_resume(&remaining, None, &cursor, || {
                visited.push(remaining[0].clone());
                Ok(execution_report(&remaining, &["skipped"]))
            });
        }
        assert_eq!(visited, selected);
        assert_eq!(*cursor.lock().unwrap(), None);
    }

    #[cfg(unix)]
    #[test]
    fn native_byte_paths_are_not_reconstructed_from_display_reports() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        let selected = vec![
            PathBuf::from(OsString::from_vec(b"/cache/a-\xff.bin".to_vec())),
            PathBuf::from("/cache/b.bin"),
        ];
        let cursor = Mutex::new(None);
        execute_and_resume(&selected, None, &cursor, || {
            Ok(execution_report(&selected, &["skipped"]))
        });
        assert_eq!(*cursor.lock().unwrap(), Some(selected[0].clone()));
        let cursor = Mutex::new(None);
        let message = execute_and_resume(&selected, None, &cursor, || {
            let mut report = execution_report(&selected, &["skipped"]);
            report.files[0].path = PathBuf::from(selected[0].to_string_lossy().into_owned());
            Ok(report)
        });
        assert!(message.contains("continuation retained"));
        assert_eq!(*cursor.lock().unwrap(), None);
    }

    #[test]
    fn running_cooling_and_invalid_schedules_do_not_issue_root_io() {
        use crate::core::errors::Result;
        use crate::logger::dual::{DualLoggerConfig, spawn_logger};
        use crate::logger::jsonl::JsonlConfig;
        use crate::platform::pal::{
            FsStats, MemoryInfo, MountPoint, PlatformPaths, ServiceManager,
        };
        use std::path::Path;

        struct NoQueries;
        impl Platform for NoQueries {
            fn fs_stats(&self, _: &Path) -> Result<FsStats> {
                panic!("root I/O before due time")
            }
            fn mount_points(&self) -> Result<Vec<MountPoint>> {
                panic!("unexpected mount query")
            }
            fn is_ram_backed(&self, _: &Path) -> Result<bool> {
                panic!("unexpected RAM query")
            }
            fn default_paths(&self) -> PlatformPaths {
                PlatformPaths::default()
            }
            fn memory_info(&self) -> Result<MemoryInfo> {
                panic!("unexpected memory query")
            }
            fn service_manager(&self) -> Box<dyn ServiceManager> {
                panic!("unexpected service query")
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let (logger, join) = spawn_logger(DualLoggerConfig {
            sqlite_path: None,
            jsonl_config: JsonlConfig {
                path: dir.path().join("activity.jsonl"),
                fallback_path: None,
                max_size_bytes: 1024 * 1024,
                max_rotated_files: 1,
                fsync_interval_secs: 60,
            },
            channel_capacity: 8,
            run_id: None,
        })
        .unwrap();
        let platform: Arc<dyn Platform> = Arc::new(NoQueries);
        let now = Instant::now();
        for (running, last_start, start_level) in [
            (true, None, "yellow"),
            (false, Some(now), "yellow"),
            (false, None, "invalid"),
        ] {
            let config = Config {
                compress: CompressConfig {
                    start_level: start_level.into(),
                    ..enabled()
                },
                ..Config::default()
            };
            let mut tier = CompressTier {
                running: Arc::new(AtomicBool::new(running)),
                last_start,
                ..CompressTier::default()
            };
            tier.tick(now, &config, &platform, &HashMap::new(), &logger);
            assert_eq!(tier.last_start, last_start);
            assert_eq!(tier.running.load(Ordering::Acquire), running);
            assert_eq!(*tier.resume_after.lock().unwrap(), None);
        }
        logger.shutdown();
        join.join().unwrap();
    }

    fn enabled() -> CompressConfig {
        CompressConfig {
            enabled: true,
            roots: vec![PathBuf::from("/data/tmp"), PathBuf::from("/srv/ext4")],
            allow_zstd_feature: true,
            ..CompressConfig::default()
        }
    }

    fn status(root: &str, btrfs: bool, level: Option<PressureLevel>) -> RootStatus {
        RootStatus {
            root: PathBuf::from(root),
            btrfs,
            level,
        }
    }

    #[test]
    fn a_pass_is_due_only_for_btrfs_roots_at_or_above_the_start_level() {
        let now = Instant::now();
        let roots = [
            status("/data/tmp", true, Some(PressureLevel::Yellow)),
            status("/srv/ext4", false, Some(PressureLevel::Critical)),
            status("/data/cold", true, Some(PressureLevel::Green)),
            status("/data/unmonitored", true, None),
        ];
        assert_eq!(
            due_roots(&enabled(), &roots, false, None, now),
            vec![PathBuf::from("/data/tmp")],
            "only the btrfs root whose mount is at yellow or above"
        );
        let orange = CompressConfig {
            start_level: "orange".to_string(),
            ..enabled()
        };
        assert!(due_roots(&orange, &roots, false, None, now).is_empty());
    }

    #[test]
    fn no_pass_when_disabled_running_or_inside_the_interval() {
        let now = Instant::now();
        let roots = [status("/data/tmp", true, Some(PressureLevel::Red))];
        let off = CompressConfig {
            enabled: false,
            ..enabled()
        };
        assert!(due_roots(&off, &roots, false, None, now).is_empty());
        assert!(due_roots(&enabled(), &roots, true, None, now).is_empty());

        let interval = Duration::from_mins(30);
        let earlier = now
            .checked_sub(interval.checked_sub(Duration::from_secs(1)).unwrap())
            .unwrap();
        assert!(due_roots(&enabled(), &roots, false, Some(earlier), now).is_empty());
        let long_ago = now.checked_sub(interval).unwrap();
        assert_eq!(
            due_roots(&enabled(), &roots, false, Some(long_ago), now),
            vec![PathBuf::from("/data/tmp")]
        );
    }

    #[test]
    fn an_unknown_start_level_never_starts_a_pass() {
        let config = CompressConfig {
            start_level: "amber".to_string(),
            ..enabled()
        };
        let roots = [status("/data/tmp", true, Some(PressureLevel::Critical))];
        assert!(due_roots(&config, &roots, false, None, Instant::now()).is_empty());
    }

    #[test]
    fn a_stop_reaches_only_a_running_pass() {
        let tier = CompressTier::default();
        tier.stop_running_pass();
        assert!(
            !tier.stop.load(Ordering::Acquire),
            "nothing running, nothing to stop"
        );
        tier.running.store(true, Ordering::Release);
        tier.stop_running_pass();
        assert!(tier.stop.load(Ordering::Acquire));
        // Repeated ticks outside the policy keep it raised (and log once).
        tier.stop_running_pass();
        assert!(tier.stop.load(Ordering::Acquire));
    }

    #[test]
    fn a_disabled_tier_does_no_work_and_starts_no_thread() {
        use crate::logger::dual::{DualLoggerConfig, spawn_logger};
        use crate::logger::jsonl::JsonlConfig;
        use crate::platform::pal::MockPlatform;

        let dir = tempfile::tempdir().unwrap();
        let (logger, join) = spawn_logger(DualLoggerConfig {
            sqlite_path: None,
            jsonl_config: JsonlConfig {
                path: dir.path().join("activity.jsonl"),
                fallback_path: None,
                max_size_bytes: 1024 * 1024,
                max_rotated_files: 1,
                fsync_interval_secs: 60,
            },
            channel_capacity: 8,
            run_id: None,
        })
        .unwrap();
        let platform: Arc<dyn Platform> = Arc::new(MockPlatform::healthy());
        let mut tier = CompressTier::default();
        tier.tick(
            Instant::now(),
            &Config::default(),
            &platform,
            &HashMap::from([(PathBuf::from("/"), PressureLevel::Critical)]),
            &logger,
        );
        assert!(tier.last_start.is_none());
        assert!(!tier.running.load(Ordering::Acquire));
        logger.shutdown();
        join.join().unwrap();
    }
}
