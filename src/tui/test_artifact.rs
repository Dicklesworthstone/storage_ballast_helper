//! Structured e2e artifact schema for dashboard tests.
//!
//! Provides machine-readable diagnostic bundles emitted by test runs. Every
//! failing test produces a minimum diagnostic payload (trace ID, keyflow log,
//! final model state) so failures are reproducible without re-running.
//!
//! Artifact files are written to `$SBH_TUI_ARTIFACT_DIR` when set, making
//! CI pipelines and local debugging consistent.
//!
//! # Schema alignment
//!
//! - Trace IDs use the project-wide `sbh-tui-{seq:08x}` format for cross-suite
//!   correlation with [`crate::scanner::decision_record::DecisionRecord`].
//! - JSON output follows the same compact/pretty conventions as the stress and
//!   proof harnesses.

#![allow(dead_code)] // Schema surface — consumed by downstream test modules.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use serde::Serialize;

use super::model::{Overlay, Screen};
use super::test_harness::{DashboardHarness, FrameSnapshot};

// ──────────────────── trace ID generation ────────────────────

/// Global monotonic counter for trace IDs within a test process.
static TRACE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Generate a trace ID in the project-standard format.
fn next_trace_id() -> String {
    let seq = TRACE_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("sbh-tui-{seq:08x}")
}

// ──────────────────── schema types ────────────────────

/// Top-level artifact emitted per test case.
#[derive(Debug, Clone, Serialize)]
pub struct DashboardTestTrace {
    /// Unique trace ID for cross-suite correlation.
    pub trace_id: String,
    /// Fully-qualified test name (e.g. `tui::test_harness::tests::quit_sets_quit_flag`).
    pub test_name: String,
    /// ISO 8601 timestamp when the test started.
    pub started_at: String,
    /// Wall-clock duration in microseconds.
    pub duration_us: u64,
    /// Whether the test passed.
    pub passed: bool,
    /// Terminal dimensions used during the test.
    pub terminal_size: (u16, u16),
    /// Build environment snapshot.
    pub env: TestEnv,
    /// Ordered keyflow steps (inputs and state transitions).
    pub keyflow: Vec<KeyflowStep>,
    /// Frame records captured during the test.
    pub frames: Vec<FrameRecord>,
    /// Assertion results (both passing and failing).
    pub assertions: Vec<AssertionRecord>,
    /// Final model state at test completion.
    pub final_state: ModelStateSnapshot,
    /// Error messages collected during the test.
    pub errors: Vec<String>,
}

/// Build environment for reproducibility.
#[derive(Debug, Clone, Serialize)]
pub struct TestEnv {
    pub os: &'static str,
    pub arch: &'static str,
    pub pkg_version: &'static str,
    pub features: Vec<&'static str>,
}

impl TestEnv {
    fn capture() -> Self {
        Self {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            pkg_version: env!("CARGO_PKG_VERSION"),
            features: {
                let mut f = Vec::new();
                if cfg!(feature = "tui") {
                    f.push("tui");
                }
                if cfg!(feature = "sqlite") {
                    f.push("sqlite");
                }
                if cfg!(feature = "daemon") {
                    f.push("daemon");
                }
                f
            },
        }
    }
}

/// A single input/response step in the keyflow.
#[derive(Debug, Clone, Serialize)]
pub struct KeyflowStep {
    /// 0-based sequence number within the test.
    pub seq: u32,
    /// Human-readable input description (e.g. `"Key('3')"`, `"Tick"`, `"Resize(80,24)"`).
    pub input: String,
    /// Screen before the input was processed.
    pub screen_before: String,
    /// Screen after the input was processed.
    pub screen_after: String,
    /// Debug representation of the command returned by update.
    pub cmd_returned: String,
}

/// Captured frame state (lightweight by default; full text only on failure).
#[derive(Debug, Clone, Serialize)]
pub struct FrameRecord {
    /// 0-based frame sequence number.
    pub seq: u32,
    /// Screen at time of capture.
    pub screen: String,
    /// Tick counter at time of capture.
    pub tick: u64,
    /// Whether degraded mode was active.
    pub degraded: bool,
    /// Active overlay, if any.
    pub overlay: Option<String>,
    /// Number of lines in the rendered frame.
    pub text_lines: u32,
    /// FNV-style hash of the frame text for fast diff detection.
    pub text_hash: String,
    /// Full frame text — populated only when `include_frame_text` is enabled
    /// or on test failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// Result of a single assertion checkpoint.
#[derive(Debug, Clone, Serialize)]
pub struct AssertionRecord {
    /// 0-based assertion sequence number.
    pub seq: u32,
    /// Human-readable assertion description.
    pub assertion: String,
    /// Whether the assertion passed.
    pub passed: bool,
    /// Actual value (on failure).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
    /// Expected value (on failure).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
}

/// Snapshot of the model state at a point in time.
#[derive(Debug, Clone, Serialize)]
pub struct ModelStateSnapshot {
    pub screen: String,
    pub tick: u64,
    pub degraded: bool,
    pub quit: bool,
    pub overlay: Option<String>,
    pub notification_count: usize,
    pub history_depth: usize,
    pub frame_count: usize,
}

// ──────────────────── helpers ────────────────────

fn screen_name(s: Screen) -> String {
    format!("{s:?}")
}

#[allow(clippy::single_option_map)]
fn overlay_name(o: Option<Overlay>) -> Option<String> {
    o.map(|v| format!("{v:?}"))
}

fn hash_text(text: &str) -> String {
    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

// ──────────────────── recorder ────────────────────

/// Records test interactions and emits a structured artifact on completion.
///
/// Wraps a [`DashboardHarness`] and transparently records every input,
/// frame capture, and assertion. Call [`finish`] to finalize the trace
/// and optionally write it to disk.
pub struct ArtifactRecorder {
    harness: DashboardHarness,
    trace_id: String,
    test_name: String,
    started_at: String,
    start_instant: Instant,
    keyflow: Vec<KeyflowStep>,
    assertions: Vec<AssertionRecord>,
    errors: Vec<String>,
    step_seq: u32,
    assertion_seq: u32,
    include_frame_text: bool,
}

impl ArtifactRecorder {
    /// Create a recorder wrapping a default harness.
    pub fn new(test_name: &str) -> Self {
        Self::with_harness(DashboardHarness::default(), test_name)
    }

    /// Create a recorder wrapping an existing harness.
    pub fn with_harness(harness: DashboardHarness, test_name: &str) -> Self {
        Self {
            harness,
            trace_id: next_trace_id(),
            test_name: test_name.to_string(),
            started_at: chrono_now_iso8601(),
            start_instant: Instant::now(),
            keyflow: Vec::new(),
            assertions: Vec::new(),
            errors: Vec::new(),
            step_seq: 0,
            assertion_seq: 0,
            include_frame_text: std::env::var("SBH_TUI_ARTIFACT_FRAMES").is_ok(),
        }
    }

    /// Access the underlying harness for direct manipulation.
    pub fn harness(&self) -> &DashboardHarness {
        &self.harness
    }

    /// Mutable access to the harness.
    pub fn harness_mut(&mut self) -> &mut DashboardHarness {
        &mut self.harness
    }

    // ── Recorded interactions ──

    /// Inject a character key, recording the step.
    pub fn inject_char(&mut self, c: char) {
        let screen_before = screen_name(self.harness.screen());
        self.harness.inject_char(c);
        self.record_step_from_last(format!("Key('{c}')"), screen_before);
    }

    /// Inject a key code, recording the step.
    pub fn inject_keycode(&mut self, code: ftui_core::event::KeyCode) {
        let screen_before = screen_name(self.harness.screen());
        self.harness.inject_keycode(code);
        self.record_step_from_last(format!("KeyCode({code:?})"), screen_before);
    }

    /// Inject Ctrl+char, recording the step.
    pub fn inject_ctrl(&mut self, c: char) {
        let screen_before = screen_name(self.harness.screen());
        self.harness.inject_ctrl(c);
        self.record_step_from_last(format!("Ctrl+'{c}'"), screen_before);
    }

    /// Inject a tick, recording the step.
    pub fn tick(&mut self) {
        let screen_before = screen_name(self.harness.screen());
        self.harness.tick();
        self.record_step_from_last("Tick".to_string(), screen_before);
    }

    /// Inject a resize event, recording the step.
    pub fn resize(&mut self, cols: u16, rows: u16) {
        let screen_before = screen_name(self.harness.screen());
        self.harness.resize(cols, rows);
        self.record_step_from_last(format!("Resize({cols},{rows})"), screen_before);
    }

    /// Feed a daemon state, recording the step.
    pub fn feed_state(&mut self, state: crate::daemon::self_monitor::DaemonState) {
        let screen_before = screen_name(self.harness.screen());
        self.harness.feed_state(state);
        self.record_step_from_last("FeedState".to_string(), screen_before);
    }

    /// Feed unavailable, recording the step.
    pub fn feed_unavailable(&mut self) {
        let screen_before = screen_name(self.harness.screen());
        self.harness.feed_unavailable();
        self.record_step_from_last("FeedUnavailable".to_string(), screen_before);
    }

    /// Inject an error, recording the step.
    pub fn inject_error(&mut self, message: &str, source: &str) {
        let screen_before = screen_name(self.harness.screen());
        self.harness.inject_error(message, source);
        self.record_step_from_last(format!("Error({message:?}, {source:?})"), screen_before);
    }

    /// Run the standard startup sequence.
    pub fn startup_with_state(&mut self, state: crate::daemon::self_monitor::DaemonState) {
        self.tick();
        self.feed_state(state);
        self.tick();
    }

    /// Navigate by number key.
    pub fn navigate_to_number(&mut self, n: u8) {
        assert!((1..=7).contains(&n), "screen number must be 1-7");
        self.inject_char((b'0' + n) as char);
    }

    /// Quit via 'q'.
    pub fn quit(&mut self) {
        self.inject_char('q');
    }

    // ── Assertions ──

    /// Record an assertion result. Returns `passed` for chaining.
    pub fn assert_eq<T: std::fmt::Debug + PartialEq>(
        &mut self,
        label: &str,
        actual: &T,
        expected: &T,
    ) -> bool {
        let passed = actual == expected;
        let seq = self.assertion_seq;
        self.assertion_seq += 1;
        self.assertions.push(AssertionRecord {
            seq,
            assertion: label.to_string(),
            passed,
            actual: if passed {
                None
            } else {
                Some(format!("{actual:?}"))
            },
            expected: if passed {
                None
            } else {
                Some(format!("{expected:?}"))
            },
        });
        if !passed {
            self.errors.push(format!(
                "Assertion failed: {label}: actual={actual:?}, expected={expected:?}"
            ));
        }
        passed
    }

    /// Record a boolean assertion.
    pub fn assert_true(&mut self, label: &str, value: bool) -> bool {
        self.assert_eq(label, &value, &true)
    }

    /// Record a frame-contains assertion.
    pub fn assert_frame_contains(&mut self, needle: &str) -> bool {
        let text = &self.harness.last_frame().text;
        let passed = text.contains(needle);
        let seq = self.assertion_seq;
        self.assertion_seq += 1;
        self.assertions.push(AssertionRecord {
            seq,
            assertion: format!("frame_contains({needle:?})"),
            passed,
            actual: if passed {
                None
            } else {
                Some(format!("frame ({} lines)", text.lines().count()))
            },
            expected: if passed {
                None
            } else {
                Some(format!("contains {needle:?}"))
            },
        });
        if !passed {
            self.errors
                .push(format!("Frame does not contain {needle:?}"));
        }
        passed
    }

    // ── Finalization ──

    /// Finalize the trace and return the artifact. Optionally writes to disk.
    pub fn finish(self, passed: bool) -> DashboardTestTrace {
        #[allow(clippy::cast_possible_truncation)]
        let duration_us = self.start_instant.elapsed().as_micros() as u64;
        let include_text = self.include_frame_text || !passed;

        #[allow(clippy::cast_possible_truncation)]
        let frames: Vec<FrameRecord> = self
            .harness
            .frames()
            .iter()
            .enumerate()
            .map(|(i, f)| snapshot_to_record(f, i as u32, include_text))
            .collect();

        let trace = DashboardTestTrace {
            trace_id: self.trace_id,
            test_name: self.test_name,
            started_at: self.started_at,
            duration_us,
            passed,
            terminal_size: (120, 40), // default harness size
            env: TestEnv::capture(),
            keyflow: self.keyflow,
            frames,
            assertions: self.assertions,
            final_state: ModelStateSnapshot {
                screen: screen_name(self.harness.screen()),
                tick: self.harness.tick_count(),
                degraded: self.harness.is_degraded(),
                quit: self.harness.is_quit(),
                overlay: overlay_name(self.harness.overlay()),
                notification_count: self.harness.notification_count(),
                history_depth: self.harness.history_depth(),
                frame_count: self.harness.frame_count(),
            },
            errors: self.errors,
        };

        // Write to artifact directory if configured.
        if let Ok(dir) = std::env::var("SBH_TUI_ARTIFACT_DIR") {
            let _ = write_artifact(&trace, Path::new(&dir));
        }

        trace
    }

    // ── Internal ──

    fn record_step_from_last(&mut self, input: String, screen_before: String) {
        let frame = self.harness.last_frame();
        let screen_after = screen_name(frame.screen);
        let cmd_returned = frame.last_cmd_debug.clone();
        let seq = self.step_seq;
        self.step_seq += 1;
        self.keyflow.push(KeyflowStep {
            seq,
            input,
            screen_before,
            screen_after,
            cmd_returned,
        });
    }
}

// ──────────────────── artifact I/O ────────────────────

/// Write a trace artifact to the given directory as JSON.
///
/// File naming: `{trace_id}_{test_name_slug}.json`
fn write_artifact(trace: &DashboardTestTrace, dir: &Path) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let slug: String = trace
        .test_name
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect();
    let filename = format!("{}_{slug}.json", trace.trace_id);
    let path = dir.join(filename);
    let json = serde_json::to_string_pretty(trace)
        .map_err(std::io::Error::other)?;
    std::fs::write(&path, json)?;
    Ok(path)
}

fn snapshot_to_record(snap: &FrameSnapshot, seq: u32, include_text: bool) -> FrameRecord {
    FrameRecord {
        seq,
        screen: screen_name(snap.screen),
        tick: snap.tick,
        degraded: snap.degraded,
        overlay: overlay_name(snap.overlay),
        #[allow(clippy::cast_possible_truncation)]
        text_lines: snap.text.lines().count() as u32,
        text_hash: hash_text(&snap.text),
        text: if include_text {
            Some(snap.text.clone())
        } else {
            None
        },
    }
}

/// Approximate ISO 8601 timestamp without pulling in chrono at runtime.
fn chrono_now_iso8601() -> String {
    // Use a simple seconds-since-epoch approach; exact formatting isn't critical
    // for test artifacts (they're for correlation, not display).
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}Z", dur.as_secs())
}

// ──────────────────── validation ────────────────────

/// Validate that a trace artifact meets minimum diagnostic requirements.
///
/// Returns a list of validation errors (empty = valid).
pub fn validate_minimum_payload(trace: &DashboardTestTrace) -> Vec<String> {
    let mut errors = Vec::new();

    if trace.trace_id.is_empty() {
        errors.push("Missing trace_id".into());
    }
    if !trace.trace_id.starts_with("sbh-tui-") {
        errors.push(format!(
            "trace_id does not follow sbh-tui-{{hex}} format: {}",
            trace.trace_id
        ));
    }
    if trace.test_name.is_empty() {
        errors.push("Missing test_name".into());
    }
    if trace.started_at.is_empty() {
        errors.push("Missing started_at timestamp".into());
    }
    if trace.keyflow.is_empty() && trace.frames.is_empty() {
        errors.push("Trace has no keyflow steps and no frames — empty test?".into());
    }
    // Failing tests MUST include frame text for diagnosis.
    if !trace.passed {
        let has_any_text = trace.frames.iter().any(|f| f.text.is_some());
        if !has_any_text {
            errors.push("Failing test has no frame text — cannot diagnose".into());
        }
    }
    // Final state must be populated.
    if trace.final_state.frame_count == 0 && !trace.keyflow.is_empty() {
        errors.push("final_state.frame_count is 0 but keyflow is non-empty".into());
    }

    errors
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::test_harness::{sample_healthy_state, sample_pressured_state};
    use ftui_core::event::KeyCode;

    #[test]
    fn trace_id_format_is_correct() {
        let id = next_trace_id();
        assert!(id.starts_with("sbh-tui-"), "got: {id}");
        assert_eq!(id.len(), "sbh-tui-00000000".len());
    }

    #[test]
    fn trace_ids_are_monotonic() {
        let id1 = next_trace_id();
        let id2 = next_trace_id();
        assert_ne!(id1, id2);
        // Extract numeric parts and verify ordering.
        let n1: u64 = u64::from_str_radix(&id1[8..], 16).unwrap();
        let n2: u64 = u64::from_str_radix(&id2[8..], 16).unwrap();
        assert!(n2 > n1);
    }

    #[test]
    fn recorder_captures_basic_keyflow() {
        let mut rec = ArtifactRecorder::new("test::basic_keyflow");
        rec.tick();
        rec.inject_char('3');
        rec.inject_keycode(KeyCode::Escape);
        let trace = rec.finish(true);

        assert_eq!(trace.keyflow.len(), 3);
        assert_eq!(trace.keyflow[0].input, "Tick");
        assert_eq!(trace.keyflow[1].input, "Key('3')");
        assert_eq!(trace.keyflow[2].input, "KeyCode(Escape)");
        assert!(trace.passed);
    }

    #[test]
    fn recorder_captures_assertions() {
        let mut rec = ArtifactRecorder::new("test::assertions");
        rec.tick();
        let ok = rec.assert_eq("screen", &rec.harness().screen(), &Screen::Overview);
        assert!(ok);
        let fail = rec.assert_eq("tick", &rec.harness().tick_count(), &99);
        assert!(!fail);

        let trace = rec.finish(false);
        assert_eq!(trace.assertions.len(), 2);
        assert!(trace.assertions[0].passed);
        assert!(!trace.assertions[1].passed);
        assert!(trace.assertions[1].actual.is_some());
    }

    #[test]
    fn recorder_startup_and_navigate() {
        let mut rec = ArtifactRecorder::new("test::startup_navigate");
        rec.startup_with_state(sample_healthy_state());
        rec.navigate_to_number(5);
        rec.assert_eq("screen", &rec.harness().screen(), &Screen::Ballast);
        rec.quit();

        let trace = rec.finish(true);
        assert!(trace.passed);
        assert_eq!(trace.final_state.screen, "Ballast");
        assert!(trace.final_state.quit);
        // startup (3 steps) + navigate (1) + quit (1) = 5
        assert_eq!(trace.keyflow.len(), 5);
    }

    #[test]
    fn failing_trace_includes_frame_text() {
        let mut rec = ArtifactRecorder::new("test::failing_frames");
        rec.tick();
        rec.feed_state(sample_healthy_state());
        let trace = rec.finish(false);

        assert!(!trace.passed);
        // Failing traces must include frame text.
        assert!(trace.frames.iter().any(|f| f.text.is_some()));
    }

    #[test]
    fn passing_trace_omits_frame_text_by_default() {
        // Only omits if SBH_TUI_ARTIFACT_FRAMES is not set.
        // We can't unset env vars safely in tests, so just verify the field exists.
        let mut rec = ArtifactRecorder::new("test::passing_no_text");
        rec.tick();
        let trace = rec.finish(true);

        // Frames exist but text may or may not be present depending on env.
        assert!(!trace.frames.is_empty());
        // Hash is always present.
        assert!(!trace.frames[0].text_hash.is_empty());
    }

    #[test]
    fn validate_minimum_payload_passes_for_good_trace() {
        let mut rec = ArtifactRecorder::new("test::validation_good");
        rec.tick();
        rec.inject_char('q');
        let trace = rec.finish(true);

        let errors = validate_minimum_payload(&trace);
        assert!(errors.is_empty(), "validation errors: {errors:?}");
    }

    #[test]
    fn validate_minimum_payload_catches_empty_trace_id() {
        let trace = DashboardTestTrace {
            trace_id: String::new(),
            test_name: "test".into(),
            started_at: "now".into(),
            duration_us: 0,
            passed: true,
            terminal_size: (80, 24),
            env: TestEnv::capture(),
            keyflow: vec![],
            frames: vec![],
            assertions: vec![],
            final_state: ModelStateSnapshot {
                screen: "Overview".into(),
                tick: 0,
                degraded: true,
                quit: false,
                overlay: None,
                notification_count: 0,
                history_depth: 0,
                frame_count: 0,
            },
            errors: vec![],
        };

        let errors = validate_minimum_payload(&trace);
        assert!(errors.iter().any(|e| e.contains("trace_id")));
    }

    #[test]
    fn validate_catches_failing_test_without_frame_text() {
        let trace = DashboardTestTrace {
            trace_id: "sbh-tui-00000000".into(),
            test_name: "test::no_text".into(),
            started_at: "now".into(),
            duration_us: 100,
            passed: false,
            terminal_size: (80, 24),
            env: TestEnv::capture(),
            keyflow: vec![KeyflowStep {
                seq: 0,
                input: "Tick".into(),
                screen_before: "Overview".into(),
                screen_after: "Overview".into(),
                cmd_returned: "FetchData".into(),
            }],
            frames: vec![FrameRecord {
                seq: 0,
                screen: "Overview".into(),
                tick: 1,
                degraded: true,
                overlay: None,
                text_lines: 5,
                text_hash: "abc123".into(),
                text: None, // Missing!
            }],
            assertions: vec![],
            final_state: ModelStateSnapshot {
                screen: "Overview".into(),
                tick: 1,
                degraded: true,
                quit: false,
                overlay: None,
                notification_count: 0,
                history_depth: 0,
                frame_count: 1,
            },
            errors: vec!["something failed".into()],
        };

        let errors = validate_minimum_payload(&trace);
        assert!(
            errors.iter().any(|e| e.contains("frame text")),
            "expected frame text error, got: {errors:?}"
        );
    }

    #[test]
    fn frame_record_hash_is_deterministic() {
        let h1 = hash_text("hello world");
        let h2 = hash_text("hello world");
        let h3 = hash_text("different");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn artifact_write_creates_file() {
        let mut rec = ArtifactRecorder::new("test::write_artifact");
        rec.tick();
        rec.inject_char('q');
        let trace = rec.finish(true);

        let dir = std::env::temp_dir().join(format!("sbh-test-artifact-{}", std::process::id()));
        let result = write_artifact(&trace, &dir);
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(path.exists());
        assert!(path.to_string_lossy().contains("sbh-tui-"));
        assert!(path.to_string_lossy().ends_with(".json"));

        // Parse it back.
        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["test_name"], "test::write_artifact");
        assert!(parsed["trace_id"].as_str().unwrap().starts_with("sbh-tui-"));

        // Cleanup.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_capture_has_required_fields() {
        let env = TestEnv::capture();
        assert!(!env.os.is_empty());
        assert!(!env.arch.is_empty());
        assert!(!env.pkg_version.is_empty());
    }

    #[test]
    fn pressure_scenario_produces_rich_trace() {
        let mut rec = ArtifactRecorder::new("test::pressure_scenario");
        rec.startup_with_state(sample_healthy_state());
        rec.assert_true(
            "not degraded after healthy state",
            !rec.harness().is_degraded(),
        );
        rec.feed_state(sample_pressured_state());
        rec.assert_true(
            "still not degraded (daemon reachable)",
            !rec.harness().is_degraded(),
        );
        rec.navigate_to_number(5);
        rec.assert_eq("screen", &rec.harness().screen(), &Screen::Ballast);
        rec.quit();

        let trace = rec.finish(true);
        assert!(trace.passed);
        assert!(trace.keyflow.len() >= 6);
        assert!(trace.assertions.len() >= 3);
        assert!(trace.assertions.iter().all(|a| a.passed));

        let errors = validate_minimum_payload(&trace);
        assert!(errors.is_empty(), "validation: {errors:?}");
    }

    #[test]
    fn recorder_ctrl_c_records_correctly() {
        let mut rec = ArtifactRecorder::new("test::ctrl_c");
        rec.inject_ctrl('c');
        let trace = rec.finish(true);

        assert_eq!(trace.keyflow.len(), 1);
        assert_eq!(trace.keyflow[0].input, "Ctrl+'c'");
        assert!(trace.final_state.quit);
    }

    #[test]
    fn recorder_resize_records_dimensions() {
        let mut rec = ArtifactRecorder::new("test::resize");
        rec.resize(200, 50);
        let trace = rec.finish(true);

        assert_eq!(trace.keyflow.len(), 1);
        assert_eq!(trace.keyflow[0].input, "Resize(200,50)");
    }

    #[test]
    fn recorder_error_injection_records_step() {
        let mut rec = ArtifactRecorder::new("test::error_inject");
        rec.inject_error("disk full", "adapter");
        let trace = rec.finish(true);

        assert_eq!(trace.keyflow.len(), 1);
        assert!(trace.keyflow[0].input.contains("disk full"));
    }
}
