//! Incident replay (bd-rc-master-ajg1.4.13): `sbh dashboard --replay
//! <activity.jsonl>` drives the cockpit from a captured log.
//!
//! The log is read once, tolerantly (a line that does not parse is counted
//! and skipped), sorted by timestamp, and turned into two parallel views:
//! the raw entries, from which a `DaemonState` is reconstructed at any
//! cursor position (counters, per-mount pressure, ballast counts, the last
//! scan), and timeline events, which a [`ReplayAdapter`] serves to every
//! screen exactly as the live adapters would — but only up to the cursor.
//!
//! The [`ReplayDriver`] owns the cursor: it advances with wall-clock time at
//! the chosen speed, pauses, steps one event at a time, and seeks to either
//! end. The runtime asks it once per loop iteration and feeds the model the
//! reconstructed state whenever the cursor moved. No daemon, socket, or
//! database is involved, and the ballast actions are refused with a hint.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::daemon::self_monitor::{
    BallastState, Counters, DaemonState, LastScanState, MountPressure, PressureState,
};
use crate::logger::jsonl::LogEntry;

use super::telemetry::{
    DataSource, DecisionEvidence, EventFilter, PressurePoint, TelemetryHealth,
    TelemetryQueryAdapter, TelemetryResult, TimelineEvent, logentry_to_timeline,
    timeline_to_evidence,
};

/// How fast the log time runs against the wall clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReplaySpeed {
    /// One log second per wall second.
    #[default]
    X1,
    /// Ten log seconds per wall second.
    X10,
    /// Everything at once: the first tick lands on the last event.
    Max,
}

impl ReplaySpeed {
    /// Log seconds per wall second, or `None` for `Max`.
    #[must_use]
    pub const fn factor(self) -> Option<f64> {
        match self {
            Self::X1 => Some(1.0),
            Self::X10 => Some(10.0),
            Self::Max => None,
        }
    }

    /// The name `--speed` accepts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X1 => "1x",
            Self::X10 => "10x",
            Self::Max => "max",
        }
    }
}

impl std::str::FromStr for ReplaySpeed {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.trim().to_ascii_lowercase().as_str() {
            "1x" | "1" => Ok(Self::X1),
            "10x" | "10" => Ok(Self::X10),
            "max" => Ok(Self::Max),
            other => Err(format!(
                "unknown replay speed {other:?}; expected 1x, 10x or max"
            )),
        }
    }
}

/// What `--replay` asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayConfig {
    pub path: PathBuf,
    /// Start at the first event at or after this RFC 3339 timestamp.
    pub from: Option<String>,
    pub speed: ReplaySpeed,
}

/// The scrubber keys, queued by `update` and consumed by the runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayCommand {
    TogglePause,
    StepBack,
    StepForward,
    SeekStart,
    SeekEnd,
}

/// What the header shows about the replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayStatus {
    /// The log's file name.
    pub file: String,
    /// Timestamp of the last applied event, if any.
    pub cursor_ts: Option<String>,
    /// Events applied so far.
    pub applied: usize,
    /// Events in the log.
    pub total: usize,
    pub paused: bool,
    pub speed: ReplaySpeed,
    /// Lines that did not parse and were skipped.
    pub skipped_lines: usize,
}

impl ReplayStatus {
    /// `REPLAY <file> t=<ts> 12/120 10x` (`paused` when it is).
    #[must_use]
    pub fn badge(&self) -> String {
        let cursor = self.cursor_ts.as_deref().unwrap_or("start");
        let paused = if self.paused { " paused" } else { "" };
        format!(
            "REPLAY {} t={cursor} {}/{} {}{paused}",
            self.file,
            self.applied,
            self.total,
            self.speed.as_str()
        )
    }
}

/// The parsed log: entries and their timeline view, sorted by time.
#[derive(Debug, Default)]
pub struct ReplayTimeline {
    pub entries: Vec<LogEntry>,
    pub events: Vec<TimelineEvent>,
    /// Lines that did not parse.
    pub skipped_lines: usize,
}

impl ReplayTimeline {
    /// Read a JSONL activity log. Every line that parses as a [`LogEntry`]
    /// is kept (in timestamp order, ties keep file order); the rest are
    /// counted. An empty or unreadable file is an error.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let timeline = Self::from_text(&text);
        if timeline.entries.is_empty() {
            return Err(format!(
                "{} has no activity entries ({} unparseable line(s))",
                path.display(),
                timeline.skipped_lines
            ));
        }
        Ok(timeline)
    }

    /// Parse log text (see [`Self::load`]).
    #[must_use]
    pub fn from_text(text: &str) -> Self {
        let mut entries: Vec<LogEntry> = Vec::new();
        let mut skipped_lines = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<LogEntry>(line) {
                Ok(entry) => entries.push(entry),
                Err(_) => skipped_lines += 1,
            }
        }
        entries.sort_by(|a, b| a.ts.cmp(&b.ts));
        let events = entries.iter().map(logentry_to_timeline).collect();
        Self {
            entries,
            events,
            skipped_lines,
        }
    }

    /// Index of the first entry at or after `from` (RFC 3339), or the end.
    #[must_use]
    pub fn index_at_or_after(&self, from: &str) -> usize {
        self.entries
            .partition_point(|entry| entry.ts.as_str() < from)
    }

    /// The daemon state as reconstructed from the first `applied` entries,
    /// or `None` before the first event.
    #[must_use]
    pub fn state_after(&self, applied: usize) -> Option<DaemonState> {
        let applied = applied.min(self.entries.len());
        if applied == 0 {
            return None;
        }
        let entries = &self.entries[..applied];
        let mut counters = Counters::default();
        let mut mounts: BTreeMap<String, MountPressure> = BTreeMap::new();
        let mut provisioned = 0usize;
        let mut released = 0usize;
        let mut last_scan = LastScanState::default();
        let mut overall = "green".to_string();
        for entry in entries {
            let kind = event_kind(entry);
            match kind.as_str() {
                "scan_complete" => {
                    counters.scans += 1;
                    last_scan.at = Some(entry.ts.clone());
                }
                "artifact_delete" => {
                    if entry.ok.unwrap_or(true) {
                        counters.deletions += 1;
                        counters.bytes_freed += entry.size.unwrap_or(0);
                        last_scan.deleted += 1;
                    } else {
                        counters.errors += 1;
                    }
                }
                "ballast_release" => released += 1,
                "ballast_replenish" => released = released.saturating_sub(1),
                "ballast_provision" => provisioned += 1,
                "error" => counters.errors += 1,
                _ => {}
            }
            if matches!(entry.severity, crate::logger::jsonl::Severity::Critical)
                && kind != "artifact_delete"
                && kind != "error"
            {
                counters.errors += 1;
            }
            if let Some(level) = entry.pressure.as_deref() {
                let mount = entry.mount_point.clone().unwrap_or_else(|| "/".to_string());
                let record = mounts
                    .entry(mount.clone())
                    .or_insert_with(|| MountPressure {
                        path: mount,
                        free_pct: 0.0,
                        level: level.to_string(),
                        rate_bps: None,
                    });
                record.level = level.to_string();
                if let Some(free) = entry.free_pct {
                    record.free_pct = free;
                }
                if let Some(rate) = entry.rate_bps {
                    record.rate_bps = Some(rate);
                }
                overall = level.to_string();
            }
        }
        let last = &entries[applied - 1];
        let first = &entries[0];
        let uptime_seconds = seconds_between(&first.ts, &last.ts).unwrap_or(0);
        let total = provisioned.max(released);
        Some(DaemonState {
            version: "replay".to_string(),
            started_at: first.ts.clone(),
            uptime_seconds,
            last_updated: last.ts.clone(),
            pressure: PressureState {
                overall,
                mounts: mounts.into_values().collect(),
            },
            ballast: BallastState {
                available: total.saturating_sub(released),
                total,
                released,
            },
            last_scan,
            counters,
            policy_mode: "replay".to_string(),
            run_id: "replay".to_string(),
            ..DaemonState::default()
        })
    }
}

/// The event's serialized name (`artifact_delete`, …).
fn event_kind(entry: &LogEntry) -> String {
    serde_json::to_string(&entry.event)
        .unwrap_or_default()
        .trim_matches('"')
        .to_string()
}

fn parse_ts(ts: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|t| t.with_timezone(&chrono::Utc))
}

fn seconds_between(earlier: &str, later: &str) -> Option<u64> {
    let a = parse_ts(earlier)?;
    let b = parse_ts(later)?;
    u64::try_from((b - a).num_seconds()).ok()
}

/// Owns the cursor: where the replay is, whether it runs, and how fast.
pub struct ReplayDriver {
    timeline: Rc<ReplayTimeline>,
    /// Events applied so far (shared with the adapter).
    applied: Rc<Cell<usize>>,
    file: String,
    speed: ReplaySpeed,
    paused: bool,
    /// Wall and log time when playback last (re)started.
    anchor_wall: Instant,
    anchor_log: Option<chrono::DateTime<chrono::Utc>>,
}

impl ReplayDriver {
    /// Position the cursor at `--from` (or the first event) and start playing.
    #[must_use]
    pub fn new(timeline: ReplayTimeline, config: &ReplayConfig, now: Instant) -> Self {
        let start = config
            .from
            .as_deref()
            .map_or(1, |from| timeline.index_at_or_after(from) + 1)
            .min(timeline.entries.len());
        let file = config.path.file_name().map_or_else(
            || config.path.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        let mut driver = Self {
            timeline: Rc::new(timeline),
            applied: Rc::new(Cell::new(start)),
            file,
            speed: config.speed,
            paused: false,
            anchor_wall: now,
            anchor_log: None,
        };
        driver.re_anchor(now);
        driver
    }

    fn re_anchor(&mut self, now: Instant) {
        self.anchor_wall = now;
        self.anchor_log = self
            .timeline
            .entries
            .get(self.applied.get().saturating_sub(1))
            .and_then(|e| parse_ts(&e.ts));
    }

    /// The adapter every screen queries; it sees the log only up to the cursor.
    #[must_use]
    pub fn adapter(&self) -> ReplayAdapter {
        ReplayAdapter {
            timeline: Rc::clone(&self.timeline),
            applied: Rc::clone(&self.applied),
        }
    }

    /// Move the cursor with wall-clock time; `true` when it moved.
    pub fn advance(&mut self, now: Instant) -> bool {
        if self.paused || self.applied.get() >= self.timeline.entries.len() {
            return false;
        }
        let target = match self.speed.factor() {
            None => self.timeline.entries.len(),
            Some(factor) => {
                let Some(anchor_log) = self.anchor_log else {
                    // No parseable anchor timestamp: one event per tick.
                    return self.set_applied(self.applied.get() + 1);
                };
                let elapsed = now
                    .saturating_duration_since(self.anchor_wall)
                    .as_secs_f64()
                    * factor;
                #[allow(clippy::cast_possible_truncation)]
                let log_now =
                    anchor_log + chrono::Duration::milliseconds((elapsed * 1000.0) as i64);
                let mut index = self.applied.get();
                while index < self.timeline.entries.len() {
                    match parse_ts(&self.timeline.entries[index].ts) {
                        Some(ts) if ts > log_now => break,
                        _ => index += 1,
                    }
                }
                index
            }
        };
        self.set_applied(target)
    }

    fn set_applied(&self, applied: usize) -> bool {
        let clamped = applied.clamp(1, self.timeline.entries.len().max(1));
        if clamped == self.applied.get() {
            return false;
        }
        self.applied.set(clamped);
        true
    }

    /// Run a scrubber command; `true` when the cursor moved.
    pub fn apply(&mut self, command: ReplayCommand, now: Instant) -> bool {
        match command {
            ReplayCommand::TogglePause => {
                self.paused = !self.paused;
                if !self.paused {
                    self.re_anchor(now);
                }
                false
            }
            ReplayCommand::StepBack => {
                self.paused = true;
                self.set_applied(self.applied.get().saturating_sub(1))
            }
            ReplayCommand::StepForward => {
                self.paused = true;
                self.set_applied(self.applied.get() + 1)
            }
            ReplayCommand::SeekStart => {
                self.paused = true;
                self.set_applied(1)
            }
            ReplayCommand::SeekEnd => {
                self.paused = true;
                self.set_applied(self.timeline.entries.len())
            }
        }
    }

    /// The reconstructed state at the cursor.
    #[must_use]
    pub fn state(&self) -> Option<DaemonState> {
        self.timeline.state_after(self.applied.get())
    }

    /// What the header shows.
    #[must_use]
    pub fn status(&self) -> ReplayStatus {
        ReplayStatus {
            file: self.file.clone(),
            cursor_ts: self
                .timeline
                .entries
                .get(self.applied.get().saturating_sub(1))
                .map(|e| e.ts.clone()),
            applied: self.applied.get(),
            total: self.timeline.entries.len(),
            paused: self.paused,
            speed: self.speed,
            skipped_lines: self.timeline.skipped_lines,
        }
    }

    /// How long the runtime may sleep before the next event is due.
    #[must_use]
    pub fn next_due_in(&self, now: Instant) -> Option<Duration> {
        if self.paused || self.applied.get() >= self.timeline.entries.len() {
            return None;
        }
        let factor = self.speed.factor()?;
        let anchor_log = self.anchor_log?;
        let next = parse_ts(&self.timeline.entries[self.applied.get()].ts)?;
        let log_gap = (next - anchor_log).num_milliseconds().max(0);
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation
        )]
        let wall_gap = Duration::from_millis((log_gap as f64 / factor) as u64);
        Some(wall_gap.saturating_sub(now.saturating_duration_since(self.anchor_wall)))
    }
}

/// The log up to the cursor, served like the live adapters.
pub struct ReplayAdapter {
    timeline: Rc<ReplayTimeline>,
    applied: Rc<Cell<usize>>,
}

impl ReplayAdapter {
    fn visible(&self) -> &[TimelineEvent] {
        let applied = self.applied.get().min(self.timeline.events.len());
        &self.timeline.events[..applied]
    }
}

impl TelemetryQueryAdapter for ReplayAdapter {
    fn recent_events(
        &self,
        limit: usize,
        filter: &EventFilter,
    ) -> TelemetryResult<Vec<TimelineEvent>> {
        let data: Vec<TimelineEvent> = self
            .visible()
            .iter()
            .rev()
            .filter(|e| filter.matches(&e.severity, &e.event_type))
            .take(limit)
            .cloned()
            .collect();
        TelemetryResult {
            data,
            source: DataSource::Jsonl,
            partial: false,
            diagnostics: String::new(),
        }
    }

    fn recent_decisions(&self, limit: usize) -> TelemetryResult<Vec<DecisionEvidence>> {
        let data: Vec<DecisionEvidence> = self
            .visible()
            .iter()
            .rev()
            .filter(|e| e.event_type == "artifact_delete")
            .take(limit)
            .enumerate()
            .map(|(i, e)| timeline_to_evidence(i as u64, e))
            .collect();
        TelemetryResult {
            data,
            source: DataSource::Jsonl,
            partial: true,
            diagnostics: "replay: decisions projected from the activity log".to_string(),
        }
    }

    fn pressure_history(
        &self,
        mount: &str,
        since: &str,
        limit: usize,
    ) -> TelemetryResult<Vec<PressurePoint>> {
        let applied = self.applied.get().min(self.timeline.entries.len());
        let data: Vec<PressurePoint> = self.timeline.entries[..applied]
            .iter()
            .rev()
            .filter(|e| e.ts.as_str() >= since)
            .filter(|e| e.mount_point.as_deref().unwrap_or("/") == mount)
            .filter_map(|e| {
                Some(PressurePoint {
                    timestamp: e.ts.clone(),
                    mount_point: mount.to_string(),
                    free_pct: e.free_pct?,
                    pressure_level: e.pressure.clone().unwrap_or_default(),
                    ewma_rate: e.rate_bps,
                    pid_output: None,
                })
            })
            .take(limit)
            .collect();
        TelemetryResult {
            data,
            source: DataSource::Jsonl,
            partial: false,
            diagnostics: String::new(),
        }
    }

    fn health(&self) -> TelemetryHealth {
        TelemetryHealth {
            sqlite: super::telemetry::BackendHealth::Unavailable,
            jsonl: super::telemetry::BackendHealth::Available,
            diagnostics: "replay: the captured activity log is the only source".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logger::jsonl::{EventType, Severity};

    fn entry(ts: &str, event: EventType, severity: Severity) -> LogEntry {
        let mut e = LogEntry::new(event, severity);
        e.ts = ts.to_string();
        e
    }

    fn fixture() -> String {
        let mut lines = Vec::new();
        let mut a = entry(
            "2026-08-30T10:00:00Z",
            EventType::BallastProvision,
            Severity::Info,
        );
        a.mount_point = Some("/data".to_string());
        a.pressure = Some("green".to_string());
        a.free_pct = Some(40.0);
        lines.push(serde_json::to_string(&a).unwrap());
        let mut b = entry(
            "2026-08-30T10:00:05Z",
            EventType::ScanComplete,
            Severity::Info,
        );
        b.mount_point = Some("/data".to_string());
        b.pressure = Some("orange".to_string());
        b.free_pct = Some(12.0);
        lines.push(serde_json::to_string(&b).unwrap());
        lines.push("this is not json".to_string());
        let mut c = entry(
            "2026-08-30T10:00:10Z",
            EventType::ArtifactDelete,
            Severity::Info,
        );
        c.path = Some("/work/alpha/target".to_string());
        c.size = Some(4096);
        c.ok = Some(true);
        c.mount_point = Some("/data".to_string());
        c.pressure = Some("orange".to_string());
        c.free_pct = Some(14.0);
        lines.push(serde_json::to_string(&c).unwrap());
        // Out of order on disk: sorted on load.
        let mut d = entry(
            "2026-08-30T10:00:02Z",
            EventType::BallastRelease,
            Severity::Warning,
        );
        d.mount_point = Some("/data".to_string());
        lines.push(serde_json::to_string(&d).unwrap());
        lines.join("\n") + "\n"
    }

    #[test]
    fn load_is_tolerant_and_sorted_and_reconstructs_state() {
        let timeline = ReplayTimeline::from_text(&fixture());
        assert_eq!(timeline.entries.len(), 4);
        assert_eq!(timeline.skipped_lines, 1);
        let order: Vec<&str> = timeline.entries.iter().map(|e| e.ts.as_str()).collect();
        assert_eq!(
            order,
            vec![
                "2026-08-30T10:00:00Z",
                "2026-08-30T10:00:02Z",
                "2026-08-30T10:00:05Z",
                "2026-08-30T10:00:10Z"
            ]
        );
        assert!(timeline.state_after(0).is_none());

        let after_two = timeline.state_after(2).unwrap();
        assert_eq!(after_two.ballast.total, 1);
        assert_eq!(after_two.ballast.released, 1);
        assert_eq!(after_two.ballast.available, 0);
        assert_eq!(after_two.pressure.overall, "green");

        let end = timeline.state_after(4).unwrap();
        assert_eq!(end.counters.scans, 1);
        assert_eq!(end.counters.deletions, 1);
        assert_eq!(end.counters.bytes_freed, 4096);
        assert_eq!(end.pressure.overall, "orange");
        assert_eq!(end.pressure.mounts.len(), 1);
        assert_eq!(end.pressure.mounts[0].path, "/data");
        assert!((end.pressure.mounts[0].free_pct - 14.0).abs() < f64::EPSILON);
        assert_eq!(end.uptime_seconds, 10);
        assert_eq!(end.last_scan.at.as_deref(), Some("2026-08-30T10:00:05Z"));
        assert_eq!(end.policy_mode, "replay");
        assert_eq!(timeline.index_at_or_after("2026-08-30T10:00:03Z"), 2);
        assert_eq!(timeline.index_at_or_after("2027-01-01T00:00:00Z"), 4);

        let empty = ReplayTimeline::from_text("not json\n\n");
        assert!(empty.entries.is_empty());
        assert_eq!(empty.skipped_lines, 1);
    }

    #[test]
    fn driver_plays_at_speed_steps_and_seeks() {
        let timeline = ReplayTimeline::from_text(&fixture());
        let config = ReplayConfig {
            path: PathBuf::from("/var/lib/sbh/activity.jsonl"),
            from: None,
            speed: ReplaySpeed::X10,
        };
        let start = Instant::now();
        let mut driver = ReplayDriver::new(timeline, &config, start);
        assert_eq!(driver.status().applied, 1);
        assert_eq!(driver.status().file, "activity.jsonl");
        assert!(
            driver
                .status()
                .badge()
                .starts_with("REPLAY activity.jsonl t=2026-08-30T10:00:00Z 1/4 10x")
        );

        // 10x: the event 2 s into the log is due after 0.2 s of wall time.
        assert!(!driver.advance(start + Duration::from_millis(100)));
        assert!(driver.advance(start + Duration::from_millis(250)));
        assert_eq!(driver.status().applied, 2);
        assert!(
            driver
                .next_due_in(start + Duration::from_millis(250))
                .is_some()
        );
        // Everything through 10 s of log time after 1 s of wall time.
        assert!(driver.advance(start + Duration::from_millis(1100)));
        assert_eq!(driver.status().applied, 4);
        assert!(
            !driver.advance(start + Duration::from_secs(5)),
            "nothing past the end"
        );
        assert!(driver.next_due_in(start + Duration::from_secs(5)).is_none());

        // Scrubbing pauses; stepping and seeking move the cursor.
        assert!(driver.apply(ReplayCommand::StepBack, start));
        assert!(driver.status().paused);
        assert_eq!(driver.status().applied, 3);
        assert!(driver.apply(ReplayCommand::SeekStart, start));
        assert_eq!(driver.status().applied, 1);
        assert!(
            !driver.apply(ReplayCommand::StepBack, start),
            "cannot go before the first event"
        );
        assert!(driver.apply(ReplayCommand::StepForward, start));
        assert_eq!(driver.status().applied, 2);
        assert!(driver.apply(ReplayCommand::SeekEnd, start));
        assert_eq!(driver.status().applied, 4);
        assert!(driver.status().badge().contains("paused"));
        assert!(!driver.apply(ReplayCommand::TogglePause, start));
        assert!(!driver.status().paused);

        // Max speed lands on the last event at once; --from starts later.
        let fast = ReplayConfig {
            speed: ReplaySpeed::Max,
            from: Some("2026-08-30T10:00:04Z".to_string()),
            ..config
        };
        let mut driver = ReplayDriver::new(ReplayTimeline::from_text(&fixture()), &fast, start);
        assert_eq!(
            driver.status().applied,
            3,
            "--from lands on the first event at or after it"
        );
        assert!(driver.advance(start));
        assert_eq!(driver.status().applied, 4);
        assert_eq!(driver.state().unwrap().counters.deletions, 1);
    }

    #[test]
    fn adapter_sees_the_log_only_up_to_the_cursor() {
        let timeline = ReplayTimeline::from_text(&fixture());
        let config = ReplayConfig {
            path: PathBuf::from("activity.jsonl"),
            from: None,
            speed: ReplaySpeed::X1,
        };
        let now = Instant::now();
        let mut driver = ReplayDriver::new(timeline, &config, now);
        let adapter = driver.adapter();
        assert_eq!(
            adapter
                .recent_events(10, &EventFilter::default())
                .data
                .len(),
            1
        );
        assert!(adapter.recent_decisions(10).data.is_empty());

        driver.apply(ReplayCommand::SeekEnd, now);
        let events = adapter.recent_events(10, &EventFilter::default());
        assert_eq!(events.data.len(), 4);
        assert_eq!(events.data[0].event_type, "artifact_delete", "newest first");
        assert_eq!(events.source, DataSource::Jsonl);
        let decisions = adapter.recent_decisions(10);
        assert_eq!(decisions.data.len(), 1);
        assert!(decisions.partial, "projected, not the ledger");
        let history = adapter.pressure_history("/data", "2026-08-30T10:00:00Z", 10);
        assert_eq!(history.data.len(), 3, "entries with free_pct on /data");
        assert!((history.data[0].free_pct - 14.0).abs() < f64::EPSILON);
        let filtered = adapter.recent_events(
            10,
            &EventFilter {
                severities: vec!["warning".to_string()],
                event_types: Vec::new(),
            },
        );
        assert_eq!(filtered.data.len(), 1);
        assert_eq!(filtered.data[0].event_type, "ballast_release");
        assert_eq!("10x".parse::<ReplaySpeed>(), Ok(ReplaySpeed::X10));
        assert!("fast".parse::<ReplaySpeed>().is_err());
    }
}
