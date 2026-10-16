//! Lazy, per-file publication to sbh's existing shared activity logger.
//!
//! The compression journal is synchronous recovery evidence; this secondary
//! stream uses the normal bounded, nonblocking logger and its shutdown supervisor.
//! A joined logger is NOT proof that either backend persisted every outcome.

use std::io::{self, Write};
use std::path::PathBuf;
use std::thread::JoinHandle;

use serde::Serialize;
use storage_ballast_helper::core::config::Config;
use storage_ballast_helper::logger::compression::CompressionActivity;
use storage_ballast_helper::logger::dual::{
    ActivityEvent, ActivityLoggerHandle, DualLoggerConfig, LoggerShutdownStatus, spawn_logger,
};
use storage_ballast_helper::logger::jsonl::JsonlConfig;
use storage_ballast_helper::platform::pal::Platform;
use storage_ballast_helper::scanner::compression::{
    self, CompressionMode, CompressionObservation, CompressionPolicy, CompressionReport,
};

/// Preserve the existing compression JSON fields and add separate transport
/// evidence. Neither backend failure nor queue delivery changes the journal's
/// recorded compression result, and unknown delivery is never called durable.
#[derive(Debug, Serialize)]
pub(super) struct CommandReport {
    #[serde(flatten)]
    pub(super) compression: CompressionReport,
    pub(super) activity_delivery: ActivityDelivery,
}

#[derive(Debug, Serialize)]
pub(super) struct ActivityDelivery {
    schema: &'static str,
    writer_status: &'static str,
    prepared_outcomes_observed: u64,
    submit_attempts: u64,
    rejected_outcomes: u64,
    queue_drops: u64,
    suppressed_diagnostics: u64,
    backend_durability: &'static str,
    first_error: Option<String>,
}

impl Default for ActivityDelivery {
    fn default() -> Self {
        Self {
            schema: "sbh.compression.activity_delivery.v1",
            writer_status: "not_started",
            prepared_outcomes_observed: 0,
            submit_attempts: 0,
            rejected_outcomes: 0,
            queue_drops: 0,
            suppressed_diagnostics: 0,
            backend_durability: "not_verified",
            first_error: None,
        }
    }
}

impl ActivityDelivery {
    pub(super) fn has_known_loss(&self) -> bool {
        self.rejected_outcomes != 0
            || self.queue_drops != 0
            || self.suppressed_diagnostics != 0
            || self.first_error.is_some()
            || !matches!(self.writer_status, "not_started" | "writer_exited")
    }

    pub(super) fn write_human(&self, out: &mut impl Write) -> io::Result<()> {
        if self.prepared_outcomes_observed == 0 {
            return writeln!(
                out,
                "Shared activity logger not started: no prepared outcomes."
            );
        }
        writeln!(
            out,
            "Shared activity logger: {}; submitted {}; rejected {}; queue drops {}.",
            self.writer_status, self.submit_attempts, self.rejected_outcomes, self.queue_drops
        )?;
        writeln!(
            out,
            "Activity backend durability is unverified; the compression journal remains recovery authority."
        )
    }

    pub(super) fn warn_if_incomplete(&self) {
        if self.has_known_loss() {
            eprintln!(
                "[SBH-COMPRESSION-ACTIVITY] shared activity delivery incomplete: status={}, rejected={}, dropped={}, suppressed={}; {}. Compression results are unchanged; retain the journal.",
                self.writer_status,
                self.rejected_outcomes,
                self.queue_drops,
                self.suppressed_diagnostics,
                self.first_error
                    .as_deref()
                    .unwrap_or("not all submissions are accounted for")
            );
        }
    }

    fn record_error(&mut self, error: impl std::fmt::Display) {
        if self.first_error.is_none() {
            self.first_error = Some(error.to_string().chars().take(2048).collect());
        }
    }
}

pub(super) fn execute(
    paths: &[PathBuf],
    policy: &CompressionPolicy,
    mode: CompressionMode,
    config: &Config,
    platform: &dyn Platform,
) -> io::Result<CommandReport> {
    execute_with(config, |observer| {
        compression::run_observed(paths, policy, mode, config, platform, observer)
    })
}

/// Publish the per-file outcomes of `pass`, an explicit or discovered run.
pub(super) fn execute_with(
    config: &Config,
    pass: impl FnOnce(&mut dyn FnMut(CompressionObservation<'_>)) -> io::Result<CompressionReport>,
) -> io::Result<CommandReport> {
    let mut activity = Session::new(config);
    let result = pass(&mut |visit| activity.observe(visit));
    // The existing supervisor bounds shutdown even when a backend is blocked.
    // Final activity flushing is not part of the compression rewrite budget.
    let activity_delivery = activity.finish();
    result.map(|compression| CommandReport {
        compression,
        activity_delivery,
    })
}

struct Session {
    config: Option<DualLoggerConfig>,
    worker: Option<(ActivityLoggerHandle, JoinHandle<()>)>,
    delivery: ActivityDelivery,
}

impl Session {
    fn new(config: &Config) -> Self {
        Self {
            config: Some(DualLoggerConfig {
                sqlite_path: Some(config.paths.sqlite_db.clone()),
                jsonl_config: JsonlConfig::for_daemon(config.paths.jsonl_log.clone()),
                // At most 128 outstanding, bounded-size projections. Never
                // allocate a queue sized by the total number of input files.
                channel_capacity: 128,
                run_id: None,
            }),
            worker: None,
            delivery: ActivityDelivery::default(),
        }
    }

    fn observe(&mut self, observation: CompressionObservation<'_>) {
        if observation.file.operation_id.is_none() {
            // In particular, preview, skip and pre-admission failure paths
            // neither open backends nor create log directories/databases.
            return;
        }
        self.delivery.prepared_outcomes_observed += 1;
        let Some(path) = observation.journal_path else {
            self.reject("prepared outcome has no journal location");
            return;
        };
        let activity = match CompressionActivity::new(
            observation.file,
            path,
            observation.journal_outcome_recorded,
        ) {
            Ok(activity) => activity,
            Err(error) => {
                self.reject(error);
                return;
            }
        };
        if self.worker.is_none() {
            let Some(mut config) = self.config.take() else {
                self.reject("activity logger initialization previously failed");
                return;
            };
            config.run_id = observation
                .file
                .operation_id
                .as_deref()
                .and_then(|id| id.rsplit_once(':'))
                .map(|(run, _)| format!("compress:{run}"));
            match spawn_logger(config) {
                Ok(worker) => self.worker = Some(worker),
                Err(error) => {
                    self.reject(error);
                    return;
                }
            }
        }
        let Some((handle, _)) = self.worker.as_ref() else {
            self.reject("activity logger is unavailable");
            return;
        };
        if handle.shutdown_status() != LoggerShutdownStatus::Running {
            self.reject("activity logger stopped before this outcome was submitted");
            return;
        }
        // This counts attempts, not durable records or even queue acceptance.
        // Queue drops and final lifecycle state are reported separately.
        handle.send(ActivityEvent::CompressionRecorded(Box::new(activity)));
        self.delivery.submit_attempts += 1;
    }

    fn reject(&mut self, error: impl std::fmt::Display) {
        self.delivery.rejected_outcomes += 1;
        self.delivery.record_error(error);
    }

    fn finish(mut self) -> ActivityDelivery {
        if let Some((handle, join)) = self.worker.take() {
            handle.shutdown();
            if join.join().is_err() {
                self.delivery.writer_status = "writer_panicked";
                self.delivery
                    .record_error("activity logger supervisor or writer panicked");
            } else {
                self.delivery.writer_status = match handle.shutdown_status() {
                    LoggerShutdownStatus::WriterExited => "writer_exited",
                    LoggerShutdownStatus::TimedOut => "timed_out",
                    LoggerShutdownStatus::WriterPanicked => "writer_panicked",
                    LoggerShutdownStatus::Running | LoggerShutdownStatus::StopRequested => {
                        "unfinished"
                    }
                };
            }
            self.delivery.queue_drops = handle.dropped_events();
            self.delivery.suppressed_diagnostics = handle.suppressed_diagnostics();
        } else if self.delivery.rejected_outcomes != 0 {
            self.delivery.writer_status = "not_started_error";
        }
        std::mem::take(&mut self.delivery)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Early return or unwind must close logger admission. Normal execution
        // uses finish(); Drop never waits on backend I/O or starts a new logger.
        if let Some((handle, _)) = &self.worker {
            handle.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use storage_ballast_helper::scanner::compression::CompressionFileReport;

    fn config(root: &std::path::Path) -> Config {
        let mut config = Config::default();
        config.paths.state_file = root.join("state.json");
        config.paths.sqlite_db = root.join("activity.sqlite3");
        config.paths.jsonl_log = root.join("activity.jsonl");
        config
    }

    fn report() -> CompressionFileReport {
        CompressionFileReport {
            path: "/fixture/cold.bin".into(),
            operation_id: Some("fixture-42-0:1".into()),
            outcome: "partial".into(),
            detail: "fixture: postflight was interrupted".into(),
            logical_bytes: 131_072,
            physical_data_bytes_before: Some(131_072),
            physical_data_bytes_after: None,
            processed_bytes: 65_536,
            mutation_attempted: true,
            sha256_before: Some("ab".repeat(32)),
            sha256_after: None,
            content_verified: false,
            reclaim: None,
            accounting_error: Some("fixture incomplete accounting".into()),
        }
    }

    #[test]
    fn creating_and_finishing_an_unused_session_creates_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path().join("not-created");
        let delivery = Session::new(&config(&state_root)).finish();
        assert_eq!(delivery.writer_status, "not_started");
        assert_eq!(delivery.submit_attempts, 0);
        assert!(!delivery.has_known_loss());
        assert!(!state_root.exists());
    }

    #[test]
    fn preview_and_rejected_projection_do_not_initialize_backends() {
        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path().join("not-created");
        let mut session = Session::new(&config(&state_root));
        let mut file = report();
        file.operation_id = None;
        file.outcome = "eligible".into();
        session.observe(CompressionObservation {
            file: &file,
            journal_path: None,
            journal_outcome_recorded: false,
        });
        assert_eq!(session.delivery.prepared_outcomes_observed, 0);
        file.operation_id = Some("fixture-42-0:1".into());
        session.observe(CompressionObservation {
            file: &file,
            journal_path: Some(&state_root.join("run.jsonl")),
            journal_outcome_recorded: false,
        });
        let delivery = session.finish();
        assert!(delivery.has_known_loss());
        assert_eq!(delivery.writer_status, "not_started_error");
        assert_eq!(delivery.rejected_outcomes, 1);
        assert!(!state_root.exists());
    }

    #[test]
    fn recorded_and_failed_audit_outcomes_reach_shared_backends_during_the_session() {
        let temp = tempfile::tempdir().unwrap();
        let config = config(temp.path());
        let mut session = Session::new(&config);
        // Keep fixtures off the host's shared RAM fallback.
        session.config.as_mut().unwrap().jsonl_config.fallback_path = None;
        let journal = temp.path().join("compression-journal/fixture-42-0.jsonl");
        for index in 0..8 {
            let mut file = report();
            file.operation_id = Some(format!("fixture-42-0:{}", index * 2 + 1));
            session.observe(CompressionObservation {
                file: &file,
                journal_path: Some(&journal),
                journal_outcome_recorded: index != 7,
            });
        }
        assert!(
            session.worker.is_some(),
            "publication must not wait until finish"
        );
        let delivery = session.finish();
        assert_eq!(delivery.writer_status, "writer_exited");
        assert_eq!(delivery.submit_attempts, 8);
        assert_eq!(delivery.queue_drops, 0);
        assert_eq!(delivery.suppressed_diagnostics, 0);
        assert!(!delivery.has_known_loss());
        assert_eq!(delivery.backend_durability, "not_verified");
        let text = std::fs::read_to_string(&config.paths.jsonl_log).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 8);
        assert_eq!(lines[7]["error_code"], "SBH-COMPRESSION-AUDIT");
        assert!(
            lines
                .iter()
                .all(|line| line["run_id"] == "compress:fixture-42-0")
        );
        let db = storage_ballast_helper::logger::sqlite::SqliteLogger::open_read_only(
            &config.paths.sqlite_db,
        )
        .unwrap();
        assert_eq!(db.recent_activity(10).unwrap().len(), 8);
        assert!(db.recent_decisions(10).unwrap().is_empty());
        assert!(
            !journal.exists(),
            "synthetic event publication never fabricates a journal"
        );
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn real_preview_keeps_its_response_fields_and_opens_no_activity_destinations() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("tiny-input");
        std::fs::write(&file, b"unchanged input").unwrap();
        let state_root = temp.path().join("not-created");
        let config = config(&state_root);
        let report = execute(
            std::slice::from_ref(&file),
            &CompressionPolicy::default(),
            CompressionMode::default(),
            &config,
            &storage_ballast_helper::platform::current(),
        )
        .unwrap();
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["schema"], "sbh.compression.v1");
        assert_eq!(json["dry_run"], true);
        assert_eq!(json["files"][0]["outcome"], "skipped");
        assert_eq!(json["exit_code"], 0);
        assert_eq!(json["activity_delivery"]["writer_status"], "not_started");
        assert_eq!(
            json["activity_delivery"]["backend_durability"],
            "not_verified"
        );
        assert_eq!(std::fs::read(file).unwrap(), b"unchanged input");
        assert!(!state_root.exists());
    }
}
