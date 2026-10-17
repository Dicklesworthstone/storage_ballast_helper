//! Opt-in daemon tier: lossless zstd compression of cold files on btrfs
//! (bd-rxq5).
//!
//! With `[compress] enabled`, the monitor calls [`CompressTier::tick`] on every
//! tick. A pass starts when a configured root sits on btrfs whose mount is at
//! or above `start_level`, no pass is running, and `interval_minutes` have
//! passed since the last start. The pass runs on its own `sbh-compress` thread,
//! so the monitor never waits on file I/O. It discovers cold files under the
//! due roots, resuming where the previous pass stopped, and runs the same
//! checked executor as `sbh compress --discover --apply`. Every file outcome
//! reaches the activity log, and a summary line names the bytes saved. Nothing
//! is ever deleted, and a root on another filesystem is never touched.
//!
//! On ts2 (2026-10-14..16, `/` at 93-97% and sbh at Red or Critical) the same
//! method, run by hand, freed several hundred GB from idle scratch while the
//! deletion scanner freed megabytes per hour.

use std::collections::HashMap;
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
    let Some(start) = config.start_pressure_level() else {
        return Vec::new();
    };
    let interval = Duration::from_secs(config.interval_minutes.saturating_mul(60));
    if !config.enabled
        || running
        || last_start.is_some_and(|last| now.saturating_duration_since(last) < interval)
    {
        return Vec::new();
    }
    roots
        .iter()
        .filter(|status| status.btrfs && status.level.is_some_and(|level| level >= start))
        .map(|status| status.root.clone())
        .collect()
}

/// Scheduling state of the tier: at most one pass in flight.
#[derive(Debug, Default)]
pub struct CompressTier {
    running: Arc<AtomicBool>,
    last_start: Option<Instant>,
    /// Where the next discovery resumes: the last selected path of a pass
    /// that stopped at its file or byte limit. `None` starts from the top.
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
        if !config.compress.enabled {
            return;
        }
        let statuses = root_statuses(&config.compress.roots, platform.as_ref(), mount_levels);
        let roots = due_roots(
            &config.compress,
            &statuses,
            self.running.load(Ordering::Acquire),
            self.last_start,
            now,
        );
        if roots.is_empty() {
            return;
        }
        self.last_start = Some(now);
        self.running.store(true, Ordering::Release);
        let guard = RunningGuard(Arc::clone(&self.running));
        let resume_after = Arc::clone(&self.resume_after);
        let config = config.clone();
        let platform = Arc::clone(platform);
        let logger = logger.clone();
        let spawned = std::thread::Builder::new()
            .name("sbh-compress".to_string())
            .spawn(move || {
                let _guard = guard;
                let message = run_pass(&roots, &config, platform.as_ref(), &resume_after, &logger);
                eprintln!("[SBH-COMPRESS] {message}");
                logger.send(ActivityEvent::Info { message });
            });
        if let Err(error) = spawned {
            // The closure, and with it the guard, was dropped: running is clear.
            eprintln!("[SBH-COMPRESS] pass thread failed to start: {error}");
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
    let next = report
        .resume_after_hex
        .as_deref()
        .and_then(|hex| discovery::continuation_path(hex).ok());
    if let Ok(mut resume) = resume_after.lock() {
        *resume = next;
    }
    if report.selected_files == 0 {
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
    match compression::run_discovered(&selection, policy, mode, config, platform, &mut observer) {
        Ok(report) => summarize(&report),
        Err(error) => format!("pass refused before any rewrite: {error}"),
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
