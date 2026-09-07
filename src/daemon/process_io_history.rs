//! Sliding-window per-process I/O history for daemon attribution.

#![allow(missing_docs)]

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::core::errors::{Result, SbhError};
use crate::platform::pal::Platform;
use crate::platform::types::ProcessIo;

const SNAPSHOT_VERSION: u32 = 1;
const DEFAULT_BUCKET_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_HISTORY_WINDOW: Duration = Duration::from_hours(1);
const DEFAULT_RECENT_WINDOW: Duration = Duration::from_mins(15);
const DEFAULT_PERSIST_INTERVAL: Duration = Duration::from_mins(5);
const DEFAULT_MAX_PIDS: usize = 500;
const SAMPLE_TIME_BUDGET: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessIoHistoryReport {
    pub sampled: bool,
    pub pids_seen: usize,
    pub pids_recorded: usize,
    pub pid_errors: usize,
    pub persisted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessIoRecentTotals {
    pub bytes_read: u64,
    pub bytes_written: u64,
}

impl ProcessIoHistoryReport {
    const fn skipped() -> Self {
        Self {
            sampled: false,
            pids_seen: 0,
            pids_recorded: 0,
            pid_errors: 0,
            persisted: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ProcessIoSample {
    collected_at_unix_ms: i64,
    bytes_read_total: u64,
    bytes_written_total: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct ProcessIoHistoryKey {
    pid: i32,
    start_time_unix_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ProcessIoHistoryEntry {
    pid: i32,
    start_time_unix_ms: Option<i64>,
    samples: Vec<ProcessIoSample>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ProcessIoHistorySnapshot {
    version: u32,
    saved_at_unix_ms: i64,
    entries: Vec<ProcessIoHistoryEntry>,
}

#[derive(Debug)]
pub struct ProcessIoHistory {
    snapshot_path: PathBuf,
    samples_by_process: HashMap<ProcessIoHistoryKey, VecDeque<ProcessIoSample>>,
    last_sample_at: Option<Instant>,
    last_persist_at: Option<Instant>,
    bucket_interval: Duration,
    history_window: Duration,
    recent_window: Duration,
    persist_interval: Duration,
    max_pids: usize,
}

impl ProcessIoHistory {
    #[must_use]
    pub fn load_or_new(snapshot_path: PathBuf) -> Self {
        let mut history = Self::new(snapshot_path);
        history.load_snapshot();
        history
    }

    #[must_use]
    pub fn new(snapshot_path: PathBuf) -> Self {
        Self {
            snapshot_path,
            samples_by_process: HashMap::new(),
            last_sample_at: None,
            last_persist_at: None,
            bucket_interval: DEFAULT_BUCKET_INTERVAL,
            history_window: DEFAULT_HISTORY_WINDOW,
            recent_window: DEFAULT_RECENT_WINDOW,
            persist_interval: DEFAULT_PERSIST_INTERVAL,
            max_pids: DEFAULT_MAX_PIDS,
        }
    }

    #[must_use]
    pub fn snapshot_path_for_state_file(state_file: &Path) -> PathBuf {
        state_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("io_history.bin")
    }

    pub fn maybe_sample(
        &mut self,
        platform: &dyn Platform,
        now: Instant,
    ) -> (ProcessIoHistoryReport, Option<String>) {
        if self
            .last_sample_at
            .is_some_and(|last| now.duration_since(last) < self.bucket_interval)
        {
            return (ProcessIoHistoryReport::skipped(), None);
        }

        self.last_sample_at = Some(now);
        let collected_at_unix_ms = unix_time_ms();
        let processes = match platform.process_list() {
            Ok(processes) => processes,
            Err(error) => {
                return (
                    ProcessIoHistoryReport {
                        sampled: true,
                        pids_seen: 0,
                        pids_recorded: 0,
                        pid_errors: 1,
                        persisted: false,
                    },
                    Some(error.to_string()),
                );
            }
        };

        let mut report = ProcessIoHistoryReport {
            sampled: true,
            pids_seen: processes.len(),
            pids_recorded: 0,
            pid_errors: 0,
            persisted: false,
        };

        let deadline = Instant::now() + SAMPLE_TIME_BUDGET;
        for process in processes.into_iter().take(self.max_pids) {
            if Instant::now() >= deadline {
                break;
            }
            match platform.process_io(process.pid) {
                Ok(io) => {
                    let _ = self.record_process_sample_at(
                        io,
                        process.start_time_unix_ms,
                        collected_at_unix_ms,
                    );
                    report.pids_recorded += 1;
                }
                Err(_) => report.pid_errors += 1,
            }
        }

        self.enforce_pid_limit();
        let persist_due = self
            .last_persist_at
            .is_none_or(|last| now.duration_since(last) >= self.persist_interval);
        if persist_due {
            match self.persist_snapshot() {
                Ok(()) => {
                    self.last_persist_at = Some(now);
                    report.persisted = true;
                }
                Err(error) => return (report, Some(error.to_string())),
            }
        }

        (report, None)
    }

    #[must_use]
    pub fn record_sample_at(&mut self, io: ProcessIo, collected_at_unix_ms: i64) -> ProcessIo {
        self.record_process_sample_at(io, None, collected_at_unix_ms)
    }

    #[must_use]
    pub fn record_process_sample_at(
        &mut self,
        io: ProcessIo,
        start_time_unix_ms: Option<i64>,
        collected_at_unix_ms: i64,
    ) -> ProcessIo {
        let sample = ProcessIoSample {
            collected_at_unix_ms,
            bytes_read_total: io.bytes_read_total,
            bytes_written_total: io.bytes_written_total,
        };

        let key = ProcessIoHistoryKey {
            pid: io.pid,
            start_time_unix_ms,
        };
        let window_ms = duration_ms_i64(self.history_window);
        let samples = self.samples_by_process.entry(key).or_default();
        samples.push_back(sample);
        prune_samples(samples, collected_at_unix_ms.saturating_sub(window_ms));
        self.io_with_recent_for_process_at(io, start_time_unix_ms, collected_at_unix_ms)
    }

    #[must_use]
    pub fn io_with_recent(&self, io: ProcessIo) -> ProcessIo {
        self.io_with_recent_for_process(io, None)
    }

    #[must_use]
    pub fn io_with_recent_for_process(
        &self,
        io: ProcessIo,
        start_time_unix_ms: Option<i64>,
    ) -> ProcessIo {
        self.io_with_recent_for_process_at(io, start_time_unix_ms, unix_time_ms())
    }

    fn io_with_recent_for_process_at(
        &self,
        mut io: ProcessIo,
        start_time_unix_ms: Option<i64>,
        collected_at_unix_ms: i64,
    ) -> ProcessIo {
        if let Some(recent) = self.recent_totals_for_process(
            &io,
            start_time_unix_ms,
            collected_at_unix_ms,
            self.recent_window,
        ) {
            io.bytes_read_recent_15m = Some(recent.bytes_read);
            io.bytes_written_recent_15m = Some(recent.bytes_written);
        }
        io
    }

    #[must_use]
    pub fn recent_totals_for_process(
        &self,
        io: &ProcessIo,
        start_time_unix_ms: Option<i64>,
        collected_at_unix_ms: i64,
        window: Duration,
    ) -> Option<ProcessIoRecentTotals> {
        let cutoff = collected_at_unix_ms.saturating_sub(duration_ms_i64(window));
        if start_time_unix_ms.is_some_and(|start| start >= cutoff) {
            return Some(ProcessIoRecentTotals {
                bytes_read: io.bytes_read_total,
                bytes_written: io.bytes_written_total,
            });
        }

        let key = ProcessIoHistoryKey {
            pid: io.pid,
            start_time_unix_ms,
        };
        if let Some(samples) = self.samples_by_process.get(&key)
            && let Some((read_recent, written_recent)) = current_delta_since(samples, io, cutoff)
        {
            return Some(ProcessIoRecentTotals {
                bytes_read: read_recent,
                bytes_written: written_recent,
            });
        }
        None
    }

    fn load_snapshot(&mut self) {
        let Ok(raw) = fs::read(&self.snapshot_path) else {
            return;
        };
        let Ok((snapshot, _bytes_read)) = bincode::serde::decode_from_slice::<
            ProcessIoHistorySnapshot,
            _,
        >(&raw, bincode::config::standard()) else {
            return;
        };
        if snapshot.version != SNAPSHOT_VERSION {
            return;
        }

        let cutoff = unix_time_ms().saturating_sub(duration_ms_i64(self.history_window));
        for entry in snapshot.entries {
            let mut samples: Vec<_> = entry
                .samples
                .into_iter()
                .filter(|sample| sample.collected_at_unix_ms >= cutoff)
                .collect();
            samples.sort_by_key(|sample| sample.collected_at_unix_ms);
            if !samples.is_empty() {
                self.samples_by_process.insert(
                    ProcessIoHistoryKey {
                        pid: entry.pid,
                        start_time_unix_ms: entry.start_time_unix_ms,
                    },
                    VecDeque::from(samples),
                );
            }
        }
        self.enforce_pid_limit();
    }

    fn persist_snapshot(&self) -> Result<()> {
        if let Some(parent) = self.snapshot_path.parent() {
            fs::create_dir_all(parent).map_err(|error| SbhError::io(parent, error))?;
        }

        let mut entries: Vec<_> = self
            .samples_by_process
            .iter()
            .map(|(key, samples)| ProcessIoHistoryEntry {
                pid: key.pid,
                start_time_unix_ms: key.start_time_unix_ms,
                samples: samples.iter().cloned().collect(),
            })
            .collect();
        entries.sort_by_key(|entry| (entry.pid, entry.start_time_unix_ms));

        let snapshot = ProcessIoHistorySnapshot {
            version: SNAPSHOT_VERSION,
            saved_at_unix_ms: unix_time_ms(),
            entries,
        };
        let bytes = bincode::serde::encode_to_vec(&snapshot, bincode::config::standard()).map_err(
            |error| SbhError::Serialization {
                context: "bincode",
                details: error.to_string(),
            },
        )?;
        fs::write(&self.snapshot_path, bytes)
            .map_err(|error| SbhError::io(&self.snapshot_path, error))
    }

    fn enforce_pid_limit(&mut self) {
        while self.samples_by_process.len() > self.max_pids {
            let Some(oldest_key) = self
                .samples_by_process
                .iter()
                .filter_map(|(key, samples)| {
                    samples
                        .front()
                        .map(|sample| (*key, sample.collected_at_unix_ms))
                })
                .min_by_key(|(_, collected_at)| *collected_at)
                .map(|(key, _)| key)
            else {
                break;
            };
            self.samples_by_process.remove(&oldest_key);
        }
    }
}

fn current_delta_since(
    samples: &VecDeque<ProcessIoSample>,
    io: &ProcessIo,
    cutoff_unix_ms: i64,
) -> Option<(u64, u64)> {
    let baseline = samples
        .iter()
        .find(|sample| sample.collected_at_unix_ms >= cutoff_unix_ms)?;

    Some((
        io.bytes_read_total
            .saturating_sub(baseline.bytes_read_total),
        io.bytes_written_total
            .saturating_sub(baseline.bytes_written_total),
    ))
}

fn prune_samples(samples: &mut VecDeque<ProcessIoSample>, cutoff_unix_ms: i64) {
    while samples
        .front()
        .is_some_and(|sample| sample.collected_at_unix_ms < cutoff_unix_ms)
    {
        samples.pop_front();
    }
}

fn unix_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
        })
}

fn duration_ms_i64(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::platform::pal::MockPlatform;
    use crate::platform::types::ProcessInfo;

    fn process(pid: i32) -> ProcessInfo {
        ProcessInfo {
            pid,
            parent_pid: None,
            name: format!("proc-{pid}"),
            command_line: vec![format!("proc-{pid}")],
            executable: None,
            cwd: None,
            start_time_unix_ms: None,
            virtual_memory_bytes: None,
            resident_memory_bytes: None,
            cpu_user_micros: None,
            cpu_system_micros: None,
        }
    }

    fn io(pid: i32, read: u64, written: u64) -> ProcessIo {
        ProcessIo {
            pid,
            bytes_read_total: read,
            bytes_written_total: written,
            bytes_read_recent_15m: None,
            bytes_written_recent_15m: None,
        }
    }

    #[test]
    fn record_sample_computes_recent_15m_delta() {
        let dir = tempfile::TempDir::new().expect("temp dir should be created");
        let mut history = ProcessIoHistory::new(dir.path().join("io_history.bin"));

        let _ = history.record_sample_at(io(42, 1_000, 2_000), 0);
        let current = history.record_sample_at(io(42, 1_700, 2_250), 15 * 60 * 1_000);

        assert_eq!(current.bytes_read_recent_15m, Some(700));
        assert_eq!(current.bytes_written_recent_15m, Some(250));
    }

    #[test]
    fn record_sample_prunes_samples_outside_one_hour_window() {
        let dir = tempfile::TempDir::new().expect("temp dir should be created");
        let mut history = ProcessIoHistory::new(dir.path().join("io_history.bin"));

        let _ = history.record_sample_at(io(42, 1, 1), 0);
        let _ = history.record_sample_at(io(42, 2, 2), (60 * 60 * 1_000) + 1);

        let samples = history
            .samples_by_process
            .get(&ProcessIoHistoryKey {
                pid: 42,
                start_time_unix_ms: None,
            })
            .expect("pid should stay tracked");
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].bytes_read_total, 2);
    }

    #[test]
    fn record_process_sample_separates_reused_pid_by_start_time() {
        let dir = tempfile::TempDir::new().expect("temp dir should be created");
        let mut history = ProcessIoHistory::new(dir.path().join("io_history.bin"));

        let _ = history.record_process_sample_at(io(42, 1_000, 2_000), Some(100), 0);
        let reused = history.record_process_sample_at(io(42, 50, 75), Some(200), 15_000);

        assert_eq!(reused.bytes_read_recent_15m, Some(50));
        assert_eq!(reused.bytes_written_recent_15m, Some(75));
        assert_eq!(history.samples_by_process.len(), 2);
    }

    #[test]
    fn recent_totals_use_lifetime_for_process_started_inside_window() {
        let dir = tempfile::TempDir::new().expect("temp dir should be created");
        let history = ProcessIoHistory::new(dir.path().join("io_history.bin"));

        let recent = history
            .recent_totals_for_process(
                &io(42, 1_024, 2_048),
                Some(10 * 60 * 1_000),
                15 * 60 * 1_000,
                Duration::from_mins(15),
            )
            .expect("recent process lifetime should count as recent I/O");

        assert_eq!(recent.bytes_read, 1_024);
        assert_eq!(recent.bytes_written, 2_048);
    }

    #[test]
    fn recent_totals_use_history_baseline_for_old_process() {
        let dir = tempfile::TempDir::new().expect("temp dir should be created");
        let mut history = ProcessIoHistory::new(dir.path().join("io_history.bin"));
        let _ = history.record_process_sample_at(io(42, 100, 200), Some(0), 10 * 60 * 1_000);

        let recent = history
            .recent_totals_for_process(
                &io(42, 150, 900),
                Some(0),
                20 * 60 * 1_000,
                Duration::from_mins(15),
            )
            .expect("history sample inside window should provide a baseline");

        assert_eq!(recent.bytes_read, 50);
        assert_eq!(recent.bytes_written, 700);
    }

    #[test]
    fn maybe_sample_collects_visible_process_io_and_persists_snapshot() {
        let dir = tempfile::TempDir::new().expect("temp dir should be created");
        let snapshot_path = dir.path().join("io_history.bin");
        let mut history = ProcessIoHistory::new(snapshot_path.clone());
        let platform = MockPlatform::healthy()
            .with_process(process(42))
            .with_process_io(io(42, 10, 20));

        let (report, error) = history.maybe_sample(&platform, Instant::now());

        assert!(error.is_none());
        assert!(report.sampled);
        assert_eq!(report.pids_seen, 1);
        assert_eq!(report.pids_recorded, 1);
        assert!(report.persisted);
        assert!(snapshot_path.exists());
    }
}
