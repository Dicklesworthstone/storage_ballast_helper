//! Periodic report-only RAM-scratch observations for a running daemon (bd-ffjj).
//!
//! The logger consumer polls a single bounded worker, never scans /proc or
//! directories itself. No logger sender is retained by the worker, so it cannot
//! keep producer-disconnection shutdown alive. A blocked probe is not replaced.
//! The observer never changes cleanup roots, mirror routing, or process state.

use std::collections::BTreeSet;
use std::io;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, bounded};
use serde::Serialize;

use crate::logger::dual::ActivityEvent;
use crate::monitor::ram_scratch::attribution::{self, AttributionLimits, MountAttribution};
use crate::monitor::ram_scratch::{self, ScratchLimits, ScratchReport};

const STARTUP_DELAY: Duration = Duration::from_secs(30);
const SAMPLE_INTERVAL: Duration = Duration::from_secs(300);
const NOTICE_INTERVAL: Duration = Duration::from_mins(15);
const STALL_AFTER: Duration = Duration::from_secs(20);
const MAX_DETAILS_BYTES: usize = 128 * 1024;
const MAX_ATTRIBUTION_MOUNTS: usize = 16;

#[derive(Debug, Serialize)]
struct Observation {
    observed_at: String,
    host: ScratchReport,
    attribution: Vec<MountAttribution>,
    attribution_mounts_omitted: usize,
    attribution_error: Option<String>,
}

/// Coverage actually published, including any activity-payload truncation.
#[derive(Debug, PartialEq, Eq)]
struct Coverage {
    complete: bool,
    issue_kinds: BTreeSet<&'static str>,
}

struct NoticeDetails {
    text: String,
    coverage: Coverage,
}

impl Observation {
    fn attribution_complete(&self) -> bool {
        self.attribution_mounts_omitted == 0
            && self.attribution_error.is_none()
            && self.attribution.iter().all(|mount| mount.complete)
    }

    fn complete(&self) -> bool {
        self.host.complete && self.host.assessment.is_some() && self.attribution_complete()
    }

    /// Distinct kinds of missing evidence, so a monitor need not parse text.
    fn issue_kinds(&self) -> BTreeSet<&'static str> {
        let mut kinds: BTreeSet<_> = self
            .host
            .issue_details
            .iter()
            .map(|issue| issue.kind)
            .collect();
        if !self.attribution_complete() {
            kinds.insert("attribution_incomplete");
        }
        if self.host.assessment.is_none() {
            kinds.insert("assessment_unavailable");
        }
        kinds
    }

    fn details(&self, state: &str) -> NoticeDetails {
        let mut coverage = Coverage {
            complete: self.complete(),
            issue_kinds: self.issue_kinds(),
        };
        let summary = self.host.assessment.as_ref().map_or_else(
            || "RAM-scratch headroom is unavailable".to_string(),
            ram_scratch::ScratchAssessment::summary,
        );
        let full = serde_json::json!({
            "schema": "sbh.ram_scratch.observation.v1",
            "read_only": true,
            "state": state,
            "complete": coverage.complete,
            "issue_kinds": coverage.issue_kinds,
            "summary": summary,
            "observation": self,
            "details_truncated": false,
        });
        if let Ok(text) = serde_json::to_string(&full)
            && text.len() <= MAX_DETAILS_BYTES
        {
            return NoticeDetails { text, coverage };
        }
        // Even very long native mount/entry names must not turn a bounded
        // observation into an unbounded activity payload. Do not silently claim
        // this smaller projection contains every mount or attribution entry.
        coverage.complete = false;
        coverage
            .issue_kinds
            .insert("activity_payload_budget_exhausted");
        let text = serde_json::json!({
            "schema": "sbh.ram_scratch.observation.v1",
            "read_only": true,
            "state": if state == "recovered" { "incomplete" } else { state },
            "complete": false,
            "issue_kinds": coverage.issue_kinds,
            "observed_at": self.observed_at,
            "summary": shorten(&summary, 8192),
            "details_truncated": true,
            "detail": "activity payload budget exceeded; use sbh check --ram-scratch for a fresh bounded report",
        })
        .to_string();
        NoticeDetails { text, coverage }
    }
}

fn collect() -> io::Result<Observation> {
    let observed_at = chrono::Utc::now().to_rfc3339();
    let deadline = Instant::now() + Duration::from_secs(5);
    let host = ram_scratch::inspect(
        &crate::platform::current(),
        ScratchLimits {
            timeout_secs: 2,
            max_processes: 4096,
            max_mounts: 128,
        },
    )?;
    let mut observation = Observation {
        observed_at,
        host,
        attribution: Vec::new(),
        attribution_mounts_omitted: 0,
        attribution_error: None,
    };
    if let Some(assessment) = &observation.host.assessment
        && assessment.warning()
    {
        // The assessment keeps all visible aliases. Attribution visits each
        // occupied filesystem once, largest first, and marks omitted work.
        let mut seen = BTreeSet::new();
        let mut mounts: Vec<_> = assessment
            .mounts
            .iter()
            .filter(|mount| mount.used_bytes != 0 && seen.insert(mount.filesystem_id))
            .cloned()
            .collect();
        observation.attribution_mounts_omitted =
            mounts.len().saturating_sub(MAX_ATTRIBUTION_MOUNTS);
        mounts.truncate(MAX_ATTRIBUTION_MOUNTS);
        match attribution::inspect(
            &mounts,
            AttributionLimits {
                // The five-second deadline bounds the work; 8192 entries
                // named only small early trees on a 640k-entry host.
                max_entries: 1_000_000,
                max_depth: 4,
                top: 3,
            },
            deadline,
        ) {
            Ok(attribution) => observation.attribution = attribution,
            Err(error) => {
                observation.attribution_error = Some(shorten(&error.to_string(), 1024));
            }
        }
    }
    Ok(observation)
}

#[derive(Default)]
struct Notices {
    last_notice: Option<Instant>,
    // Compare emitted coverage, not pressure alone. An incomplete sample or
    // restored visibility must remain observable while pressure persists.
    last_coverage: Option<Coverage>,
    // Keep the union through a pressure episode. A threshold flapping down and
    // back up must not mint a new warning every five-minute sample.
    seen_risks: BTreeSet<&'static str>,
}

impl Notices {
    fn due(&self, now: Instant) -> bool {
        self.last_notice
            .is_none_or(|last| now.saturating_duration_since(last) >= NOTICE_INTERVAL)
    }

    /// A notice without an observation; `kind` is `probe_failed` or `probe_stalled`.
    fn incomplete(
        &mut self,
        now: Instant,
        kind: &'static str,
        detail: &str,
    ) -> Option<ActivityEvent> {
        let coverage = Coverage {
            complete: false,
            issue_kinds: BTreeSet::from([kind]),
        };
        if self.last_coverage.as_ref() == Some(&coverage) && !self.due(now) {
            return None;
        }
        self.last_notice = Some(now);
        self.last_coverage = Some(coverage);
        Some(ActivityEvent::Warning {
            code: "SBH-RAM-SCRATCH-INCOMPLETE".to_string(),
            message: serde_json::json!({
                "schema": "sbh.ram_scratch.observation.v1", "read_only": true,
                "state": "incomplete", "complete": false, "issue_kinds": [kind],
                "detail": shorten(detail, 1024),
            })
            .to_string(),
        })
    }

    fn finish(&mut self, result: io::Result<Observation>, now: Instant) -> Option<ActivityEvent> {
        let observation = match result {
            Ok(observation) => observation,
            Err(error) => return self.incomplete(now, "probe_failed", &error.to_string()),
        };
        if !observation.host.supported {
            return None;
        }
        let pressured = observation
            .host
            .assessment
            .as_ref()
            .is_some_and(ram_scratch::ScratchAssessment::warning);
        let state = if pressured {
            "warning"
        } else if observation.complete() {
            "recovered"
        } else {
            "incomplete"
        };
        let details = observation.details(state);
        let coverage_changed = self.last_coverage.as_ref() != Some(&details.coverage);
        if let Some(assessment) = &observation.host.assessment
            && assessment.warning()
        {
            let new_risk = assessment
                .reasons
                .iter()
                .any(|reason| !self.seen_risks.contains(reason));
            if !new_risk && !coverage_changed && !self.due(now) {
                return None;
            }
            self.seen_risks.extend(assessment.reasons.iter().copied());
            self.last_notice = Some(now);
            self.last_coverage = Some(details.coverage);
            return Some(ActivityEvent::Warning {
                code: "SBH-RAM-SCRATCH".to_string(),
                message: details.text,
            });
        }
        if !details.coverage.complete {
            if !coverage_changed && !self.due(now) {
                return None;
            }
            self.last_notice = Some(now);
            self.last_coverage = Some(details.coverage);
            return Some(ActivityEvent::Warning {
                code: "SBH-RAM-SCRATCH-INCOMPLETE".to_string(),
                message: details.text,
            });
        }
        self.seen_risks.clear();
        self.last_coverage = None;
        // Only a complete healthy sample can clear a warning/visibility issue.
        self.last_notice.take().map(|_| ActivityEvent::Info {
            message: details.text,
        })
    }
}

struct Job {
    started: Instant,
    result: Receiver<io::Result<Observation>>,
    worker: JoinHandle<()>,
}

#[derive(Default)]
pub(super) struct Observer {
    enabled: bool,
    started_once: bool,
    next_due: Option<Instant>,
    job: Option<Job>,
    notices: Notices,
}

impl Observer {
    pub(super) fn on_event(&mut self, event: &ActivityEvent, now: Instant) {
        match event {
            ActivityEvent::DaemonStarted { .. } if !self.started_once => {
                self.started_once = true;
                self.enabled = cfg!(target_os = "linux");
                self.next_due = Some(now + STARTUP_DELAY);
            }
            ActivityEvent::DaemonStopped { .. } | ActivityEvent::Shutdown => {
                self.stop();
            }
            _ => {}
        }
    }

    pub(super) fn poll(&mut self, now: Instant) -> Option<ActivityEvent> {
        self.poll_with(now, collect)
    }

    pub(super) fn stop(&mut self) {
        self.enabled = false;
        self.next_due = None;
        // A blocked read-only worker may finish its bounded work later.
        // Dropping its handle is nonblocking; no replacement is started.
        self.job = None;
    }

    fn poll_with(
        &mut self,
        now: Instant,
        collect: impl FnOnce() -> io::Result<Observation> + Send + 'static,
    ) -> Option<ActivityEvent> {
        if !self.enabled {
            return None;
        }
        if let Some(job) = &self.job {
            if !job.worker.is_finished() {
                return if now.saturating_duration_since(job.started) >= STALL_AFTER {
                    self.notices.incomplete(now, "probe_stalled",
                        "RAM-scratch probe remains in flight; no replacement probe was started; cleanup and logging continue independently")
                } else {
                    None
                };
            }
            let job = self.job.take()?;
            self.next_due = Some(now + SAMPLE_INTERVAL);
            let result = if job.worker.join().is_err() {
                Err(io::Error::other(
                    "RAM-scratch probe panicked; no healthy observation is available",
                ))
            } else {
                job.result.try_recv().unwrap_or_else(|_| {
                    Err(io::Error::other(
                        "RAM-scratch probe exited without an observation",
                    ))
                })
            };
            return self.notices.finish(result, now);
        }
        if self.next_due.is_none_or(|due| now < due) {
            return None;
        }
        self.next_due = Some(now + SAMPLE_INTERVAL);
        let (tx, result) = bounded(1);
        match thread::Builder::new()
            .name("sbh-ram-scratch".to_string())
            .spawn(move || {
                // A closed observer or a stuck logger cannot block this producer.
                let _ = tx.try_send(collect());
            }) {
            Ok(worker) => {
                self.job = Some(Job {
                    started: now,
                    result,
                    worker,
                });
                None
            }
            Err(error) => self.notices.incomplete(
                now,
                "probe_failed",
                &format!("cannot start RAM-scratch probe: {error}"),
            ),
        }
    }
}

fn shorten(value: &str, chars: usize) -> String {
    value.chars().take(chars).collect()
}

#[cfg(test)]
mod tests;
