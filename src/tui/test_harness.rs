//! Headless dashboard interaction harness for automated keyflow tests.
//!
//! Drives the Elm-style model/update/render pipeline without a real terminal,
//! capturing frame snapshots and model state at each step. Fully deterministic
//! and CI-friendly — no PTY, no terminal, no timing dependencies.
//!
//! # Usage
//!
//! ```rust,ignore
//! let mut h = DashboardHarness::default();
//! h.inject_key('3');           // navigate to Explainability
//! h.inject_key(KeyCode::Escape);  // back to Overview
//! assert_eq!(h.screen(), Screen::Overview);
//! assert!(h.last_frame().contains("S1 Overview"));
//! ```

#![allow(dead_code)] // Harness API surface — methods/fields used by future test modules.

use std::path::PathBuf;
use std::time::Duration;

use ftui_core::event::{KeyCode, KeyEvent, KeyEventKind, Modifiers};
use sha2::{Digest, Sha256};

use super::model::{DashboardCmd, DashboardError, DashboardModel, DashboardMsg, Overlay, Screen};
use super::render;
use super::update;
use crate::daemon::self_monitor::{
    BallastState, Counters, DaemonState, LastScanState, MountPressure, PressureState,
};

// ──────────────────── frame snapshot ────────────────────

/// Captured state at a single point in a keyflow sequence.
#[derive(Debug, Clone)]
pub struct FrameSnapshot {
    /// Rendered text content.
    pub text: String,
    /// Screen at time of capture.
    pub screen: Screen,
    /// Whether an overlay was active.
    pub overlay: Option<Overlay>,
    /// Whether the model is in degraded mode.
    pub degraded: bool,
    /// Current tick counter.
    pub tick: u64,
    /// The command returned by the last update call.
    pub last_cmd_debug: String,
}

/// Scriptable input step for deterministic harness replay.
#[derive(Debug, Clone)]
pub enum HarnessStep {
    Tick,
    Char(char),
    KeyCode(KeyCode),
    Ctrl(char),
    Resize { cols: u16, rows: u16 },
    FeedHealthyState,
    FeedPressuredState,
    FeedUnavailable,
    Error { message: String, source: String },
}

impl FrameSnapshot {
    /// Assert that the frame text contains a substring.
    #[track_caller]
    pub fn assert_contains(&self, needle: &str) {
        assert!(
            self.text.contains(needle),
            "frame does not contain {:?}.\nFrame:\n{}",
            needle,
            self.text,
        );
    }

    /// Assert that the frame text does NOT contain a substring.
    #[track_caller]
    pub fn assert_not_contains(&self, needle: &str) {
        assert!(
            !self.text.contains(needle),
            "frame unexpectedly contains {:?}.\nFrame:\n{}",
            needle,
            self.text,
        );
    }
}

// ──────────────────── harness ────────────────────

/// Headless dashboard harness for deterministic keyflow testing.
///
/// Wraps a [`DashboardModel`] and provides ergonomic methods for injecting
/// keys, messages, and data updates. Every mutation captures a frame snapshot.
pub struct DashboardHarness {
    model: DashboardModel,
    frames: Vec<FrameSnapshot>,
}

impl Default for DashboardHarness {
    fn default() -> Self {
        Self::new(PathBuf::from("/tmp/test-state.json"), vec![], (120, 40))
    }
}

impl DashboardHarness {
    /// Create a harness with custom config.
    pub fn new(
        state_file: PathBuf,
        monitor_paths: Vec<PathBuf>,
        terminal_size: (u16, u16),
    ) -> Self {
        Self {
            model: DashboardModel::new(
                state_file,
                monitor_paths,
                Duration::from_secs(1),
                terminal_size,
            ),
            frames: Vec::new(),
        }
    }

    // ── Key injection ──

    /// Inject a character key press with no modifiers.
    pub fn inject_char(&mut self, c: char) -> &FrameSnapshot {
        self.inject_key_event(make_key(KeyCode::Char(c)))
    }

    /// Inject a key code (Esc, Enter, arrow keys, etc.) with no modifiers.
    pub fn inject_keycode(&mut self, code: KeyCode) -> &FrameSnapshot {
        self.inject_key_event(make_key(code))
    }

    /// Inject a Ctrl+char key press.
    pub fn inject_ctrl(&mut self, c: char) -> &FrameSnapshot {
        self.inject_key_event(make_key_ctrl(KeyCode::Char(c)))
    }

    /// Inject a raw key event.
    pub fn inject_key_event(&mut self, key: KeyEvent) -> &FrameSnapshot {
        self.inject_msg(DashboardMsg::Key(key))
    }

    // ── Message injection ──

    /// Inject any dashboard message, returning the captured frame.
    pub fn inject_msg(&mut self, msg: DashboardMsg) -> &FrameSnapshot {
        let cmd = update::update(&mut self.model, msg);
        self.capture_frame(&cmd)
    }

    /// Inject a tick.
    pub fn tick(&mut self) -> &FrameSnapshot {
        self.inject_msg(DashboardMsg::Tick)
    }

    /// Inject a terminal resize.
    pub fn resize(&mut self, cols: u16, rows: u16) -> &FrameSnapshot {
        self.inject_msg(DashboardMsg::Resize { cols, rows })
    }

    /// Inject a data update with a daemon state snapshot.
    pub fn feed_state(&mut self, state: DaemonState) -> &FrameSnapshot {
        self.inject_msg(DashboardMsg::DataUpdate(Some(Box::new(state))))
    }

    /// Inject a data update indicating daemon is unreachable.
    pub fn feed_unavailable(&mut self) -> &FrameSnapshot {
        self.inject_msg(DashboardMsg::DataUpdate(None))
    }

    /// Inject an error event.
    pub fn inject_error(&mut self, message: &str, source: &str) -> &FrameSnapshot {
        self.inject_msg(DashboardMsg::Error(DashboardError {
            message: message.into(),
            source: source.into(),
        }))
    }

    // ── Keyflow helpers ──

    /// Run a startup sequence: tick, feed state, tick.
    pub fn startup_with_state(&mut self, state: DaemonState) {
        self.tick();
        self.feed_state(state);
        self.tick();
    }

    /// Replay a deterministic script of dashboard interactions.
    pub fn run_script(&mut self, steps: &[HarnessStep]) {
        for step in steps {
            match step {
                HarnessStep::Tick => {
                    self.tick();
                }
                HarnessStep::Char(c) => {
                    self.inject_char(*c);
                }
                HarnessStep::KeyCode(code) => {
                    self.inject_keycode(*code);
                }
                HarnessStep::Ctrl(c) => {
                    self.inject_ctrl(*c);
                }
                HarnessStep::Resize { cols, rows } => {
                    self.resize(*cols, *rows);
                }
                HarnessStep::FeedHealthyState => {
                    self.feed_state(sample_healthy_state());
                }
                HarnessStep::FeedPressuredState => {
                    self.feed_state(sample_pressured_state());
                }
                HarnessStep::FeedUnavailable => {
                    self.feed_unavailable();
                }
                HarnessStep::Error { message, source } => {
                    self.inject_error(message, source);
                }
            }
        }
    }

    /// Navigate to a screen by number key (1-7).
    pub fn navigate_to_number(&mut self, n: u8) -> &FrameSnapshot {
        assert!((1..=7).contains(&n), "screen number must be 1-7");
        self.inject_char((b'0' + n) as char)
    }

    /// Navigate to next screen with `]`.
    pub fn navigate_next(&mut self) -> &FrameSnapshot {
        self.inject_char(']')
    }

    /// Navigate to previous screen with `[`.
    pub fn navigate_prev(&mut self) -> &FrameSnapshot {
        self.inject_char('[')
    }

    /// Open the help overlay.
    pub fn open_help(&mut self) -> &FrameSnapshot {
        self.inject_char('?')
    }

    /// Quit via 'q' key.
    pub fn quit(&mut self) -> &FrameSnapshot {
        self.inject_char('q')
    }

    // ── Model state queries ──

    /// Current screen.
    pub fn screen(&self) -> Screen {
        self.model.screen
    }

    /// Whether the dashboard has quit.
    pub fn is_quit(&self) -> bool {
        self.model.quit
    }

    /// Whether degraded mode is active.
    pub fn is_degraded(&self) -> bool {
        self.model.degraded
    }

    /// Current active overlay, if any.
    pub fn overlay(&self) -> Option<Overlay> {
        self.model.active_overlay
    }

    /// Number of active notifications.
    pub fn notification_count(&self) -> usize {
        self.model.notifications.len()
    }

    /// Contextual help model derived from current screen/overlay state.
    pub fn contextual_help(&self) -> super::input::ContextualHelp {
        super::input::contextual_help(super::input::InputContext {
            screen: self.model.screen,
            active_overlay: self.model.active_overlay,
        })
    }

    /// Screen navigation history depth.
    pub fn history_depth(&self) -> usize {
        self.model.screen_history.len()
    }

    /// Current tick counter.
    pub fn tick_count(&self) -> u64 {
        self.model.tick
    }

    /// Mutable access to the underlying model for advanced setup.
    pub fn model_mut(&mut self) -> &mut DashboardModel {
        &mut self.model
    }

    // ── Frame access ──

    /// Get the last captured frame.
    pub fn last_frame(&self) -> &FrameSnapshot {
        self.frames.last().expect("no frames captured yet")
    }

    /// Get all captured frames.
    pub fn frames(&self) -> &[FrameSnapshot] {
        &self.frames
    }

    /// Number of frames captured so far.
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    /// Returns the emitted command debug trace, one entry per frame.
    pub fn command_trace(&self) -> Vec<&str> {
        self.frames
            .iter()
            .map(|frame| frame.last_cmd_debug.as_str())
            .collect()
    }

    /// Returns a stable digest of command/state transitions.
    ///
    /// This intentionally excludes rendered text because frame text may include
    /// relative timing values that are not relevant to reducer determinism.
    pub fn trace_digest(&self) -> String {
        let mut hasher = Sha256::new();
        for frame in &self.frames {
            hasher.update(format!(
                "{:?}|{:?}|{}|{}|{}\n",
                frame.screen, frame.overlay, frame.degraded, frame.tick, frame.last_cmd_debug
            ));
        }
        format!("{:x}", hasher.finalize())
    }

    // ── Internal ──

    fn capture_frame(&mut self, cmd: &DashboardCmd) -> &FrameSnapshot {
        let text = render::render(&self.model);
        self.frames.push(FrameSnapshot {
            text,
            screen: self.model.screen,
            overlay: self.model.active_overlay,
            degraded: self.model.degraded,
            tick: self.model.tick,
            last_cmd_debug: format!("{cmd:?}"),
        });
        self.frames.last().unwrap()
    }
}

// ──────────────────── key helpers ────────────────────

fn make_key(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: Modifiers::NONE,
        kind: KeyEventKind::Press,
    }
}

fn make_key_ctrl(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: Modifiers::CTRL,
        kind: KeyEventKind::Press,
    }
}

// ──────────────────── test fixtures ────────────────────

/// A healthy daemon state for test scenarios.
pub fn sample_healthy_state() -> DaemonState {
    DaemonState {
        version: "0.1.0".into(),
        pid: 1234,
        started_at: "2026-02-16T00:00:00Z".into(),
        uptime_seconds: 3600,
        last_updated: "2026-02-16T01:00:00Z".into(),
        pressure: PressureState {
            overall: "green".into(),
            mounts: vec![MountPressure {
                path: "/data".into(),
                free_pct: 72.0,
                level: "green".into(),
                rate_bps: Some(512.0),
            }],
        },
        ballast: BallastState {
            available: 10,
            total: 10,
            released: 0,
        },
        last_scan: LastScanState {
            at: Some("2026-02-16T00:59:00Z".into()),
            candidates: 5,
            deleted: 0,
        },
        counters: Counters {
            scans: 60,
            deletions: 0,
            bytes_freed: 0,
            errors: 0,
            dropped_log_events: 0,
        },
        policy_mode: "enforce".into(),
        memory_rss_bytes: 32_000_000,
    }
}

/// A pressured daemon state for test scenarios.
pub fn sample_pressured_state() -> DaemonState {
    DaemonState {
        version: "0.1.0".into(),
        pid: 1234,
        started_at: "2026-02-16T00:00:00Z".into(),
        uptime_seconds: 7200,
        last_updated: "2026-02-16T02:00:00Z".into(),
        pressure: PressureState {
            overall: "red".into(),
            mounts: vec![MountPressure {
                path: "/data".into(),
                free_pct: 3.5,
                level: "red".into(),
                rate_bps: Some(-50_000.0),
            }],
        },
        ballast: BallastState {
            available: 2,
            total: 10,
            released: 8,
        },
        last_scan: LastScanState {
            at: Some("2026-02-16T01:59:00Z".into()),
            candidates: 47,
            deleted: 15,
        },
        counters: Counters {
            scans: 120,
            deletions: 15,
            bytes_freed: 5_368_709_120,
            errors: 2,
            dropped_log_events: 0,
        },
        policy_mode: "enforce".into(),
        memory_rss_bytes: 64_000_000,
    }
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Basic lifecycle ──

    #[test]
    fn harness_starts_degraded() {
        let h = DashboardHarness::default();
        assert!(h.is_degraded());
        assert_eq!(h.screen(), Screen::Overview);
        assert!(!h.is_quit());
    }

    #[test]
    fn startup_with_state_clears_degraded() {
        let mut h = DashboardHarness::default();
        h.startup_with_state(sample_healthy_state());
        assert!(!h.is_degraded());
        assert_eq!(h.screen(), Screen::Overview);
    }

    #[test]
    fn quit_sets_quit_flag() {
        let mut h = DashboardHarness::default();
        h.quit();
        assert!(h.is_quit());
    }

    #[test]
    fn ctrl_c_quits() {
        let mut h = DashboardHarness::default();
        h.inject_ctrl('c');
        assert!(h.is_quit());
    }

    // ── Navigation flows ──

    #[test]
    fn navigate_all_screens_by_number() {
        let mut h = DashboardHarness::default();
        for (n, expected) in [
            (1, Screen::Overview),
            (2, Screen::Timeline),
            (3, Screen::Explainability),
            (4, Screen::Candidates),
            (5, Screen::Ballast),
            (6, Screen::LogSearch),
            (7, Screen::Diagnostics),
        ] {
            h.navigate_to_number(n);
            assert_eq!(h.screen(), expected, "key {n}");
        }
    }

    #[test]
    fn navigate_next_cycles_all_screens() {
        let mut h = DashboardHarness::default();
        let mut visited = vec![h.screen()];
        for _ in 0..7 {
            h.navigate_next();
            visited.push(h.screen());
        }
        // Should cycle back to Overview after 7 presses.
        assert_eq!(visited.first(), visited.last());
        assert_eq!(visited.len(), 8);
    }

    #[test]
    fn navigate_prev_from_overview_wraps_to_diagnostics() {
        let mut h = DashboardHarness::default();
        h.navigate_prev();
        assert_eq!(h.screen(), Screen::Diagnostics);
    }

    #[test]
    fn esc_cascade_through_history() {
        let mut h = DashboardHarness::default();
        h.navigate_to_number(3); // Overview -> Explainability
        h.navigate_to_number(5); // Explainability -> Ballast
        assert_eq!(h.history_depth(), 2);

        h.inject_keycode(KeyCode::Escape);
        assert_eq!(h.screen(), Screen::Explainability);
        assert!(!h.is_quit());

        h.inject_keycode(KeyCode::Escape);
        assert_eq!(h.screen(), Screen::Overview);
        assert!(!h.is_quit());

        h.inject_keycode(KeyCode::Escape);
        assert!(h.is_quit());
    }

    #[test]
    fn b_key_jumps_to_ballast() {
        let mut h = DashboardHarness::default();
        h.inject_char('b');
        assert_eq!(h.screen(), Screen::Ballast);
        assert_eq!(h.history_depth(), 1);
    }

    // ── Overlay flows ──

    #[test]
    fn help_overlay_lifecycle() {
        let mut h = DashboardHarness::default();
        assert!(h.overlay().is_none());

        h.open_help();
        assert_eq!(h.overlay(), Some(Overlay::Help));
        h.last_frame().assert_contains("overlay");

        // While overlay is active, navigation keys are consumed.
        h.inject_char('3');
        assert_eq!(h.screen(), Screen::Overview); // no navigation
        assert_eq!(h.overlay(), Some(Overlay::Help)); // still open

        // Esc closes the overlay.
        h.inject_keycode(KeyCode::Escape);
        assert!(h.overlay().is_none());
        assert!(!h.is_quit());
    }

    #[test]
    fn command_palette_via_colon() {
        let mut h = DashboardHarness::default();
        h.inject_char(':');
        assert_eq!(h.overlay(), Some(Overlay::CommandPalette));
    }

    #[test]
    fn overlay_toggle_closes() {
        let mut h = DashboardHarness::default();
        h.open_help();
        assert_eq!(h.overlay(), Some(Overlay::Help));

        h.inject_char('?');
        assert!(h.overlay().is_none());
    }

    #[test]
    fn contextual_help_tracks_screen_and_overlay_context() {
        let mut h = DashboardHarness::default();

        let overview_help = h.contextual_help();
        assert_eq!(overview_help.title, "Global Navigation");
        assert!(overview_help.screen_hint.contains("Overview"));

        h.navigate_to_number(7);
        let diagnostics_help = h.contextual_help();
        assert!(diagnostics_help.screen_hint.contains("frame health"));

        h.open_help();
        let overlay_help = h.contextual_help();
        assert_eq!(overlay_help.title, "Help Overlay");
    }

    // ── Data update flows ──

    #[test]
    fn feed_state_updates_render() {
        let mut h = DashboardHarness::default();
        h.feed_state(sample_healthy_state());
        assert!(!h.is_degraded());
        h.last_frame().assert_contains("GREEN");
    }

    #[test]
    fn feed_unavailable_enters_degraded() {
        let mut h = DashboardHarness::default();
        h.feed_state(sample_healthy_state());
        assert!(!h.is_degraded());

        h.feed_unavailable();
        assert!(h.is_degraded());
        h.last_frame().assert_contains("DEGRADED");
    }

    #[test]
    fn pressure_transition_visible_in_frames() {
        let mut h = DashboardHarness::default();
        h.feed_state(sample_healthy_state());
        h.last_frame().assert_contains("GREEN");

        h.feed_state(sample_pressured_state());
        h.last_frame().assert_contains("RED");
    }

    // ── Error / notification flows ──

    #[test]
    fn error_creates_notification_visible_in_frame() {
        let mut h = DashboardHarness::default();
        h.inject_error("disk read failed", "adapter");
        assert_eq!(h.notification_count(), 1);
        h.last_frame().assert_contains("disk read failed");
    }

    // ── Frame capture ──

    #[test]
    fn frames_accumulate() {
        let mut h = DashboardHarness::default();
        assert_eq!(h.frame_count(), 0);

        h.tick();
        h.inject_char('2');
        h.inject_keycode(KeyCode::Escape);
        assert_eq!(h.frame_count(), 3);
    }

    #[test]
    fn frame_snapshot_records_screen_and_tick() {
        let mut h = DashboardHarness::default();
        h.tick();
        let frame = h.last_frame();
        assert_eq!(frame.tick, 1);
        assert_eq!(frame.screen, Screen::Overview);
    }

    // ── Resize ──

    #[test]
    fn resize_reflected_in_frame() {
        let mut h = DashboardHarness::default();
        h.resize(200, 50);
        h.last_frame().assert_contains("200x50");
    }

    // ── Force refresh ──

    #[test]
    fn r_key_returns_fetch_data_command() {
        let mut h = DashboardHarness::default();
        h.inject_char('r');
        assert!(h.last_frame().last_cmd_debug.contains("FetchData"));
    }

    // ── Complex scenario: operator session ──

    #[test]
    fn realistic_operator_session() {
        let mut h = DashboardHarness::default();

        // 1. Startup: daemon connects.
        h.startup_with_state(sample_healthy_state());
        assert!(!h.is_degraded());
        assert_eq!(h.screen(), Screen::Overview);

        // 2. Operator checks ballast status.
        h.inject_char('b');
        assert_eq!(h.screen(), Screen::Ballast);

        // 3. Opens help overlay.
        h.open_help();
        assert_eq!(h.overlay(), Some(Overlay::Help));

        // 4. Closes help with Esc.
        h.inject_keycode(KeyCode::Escape);
        assert!(h.overlay().is_none());

        // 5. Navigates to diagnostics.
        h.navigate_to_number(7);
        assert_eq!(h.screen(), Screen::Diagnostics);

        // 6. Pressure spike arrives.
        h.feed_state(sample_pressured_state());
        assert!(!h.is_degraded());

        // 7. Goes back to overview.
        h.navigate_to_number(1);
        h.last_frame().assert_contains("RED");

        // 8. Forces a refresh.
        h.inject_char('r');

        // 9. Browses timeline.
        h.navigate_to_number(2);
        assert_eq!(h.screen(), Screen::Timeline);

        // 10. Esc back through history, then quit.
        while !h.is_quit() {
            h.inject_keycode(KeyCode::Escape);
        }

        // Verify we captured a complete session.
        assert!(h.frame_count() > 10);
    }

    // ── Determinism ──

    #[test]
    fn identical_keyflows_produce_identical_states() {
        let keyflow = |h: &mut DashboardHarness| {
            h.tick();
            h.inject_char('3');
            h.inject_char('?');
            h.inject_keycode(KeyCode::Escape);
            h.inject_char('[');
            h.inject_char('b');
            h.inject_keycode(KeyCode::Escape);
        };

        let mut h1 = DashboardHarness::default();
        let mut h2 = DashboardHarness::default();
        keyflow(&mut h1);
        keyflow(&mut h2);

        assert_eq!(h1.screen(), h2.screen());
        assert_eq!(h1.overlay(), h2.overlay());
        assert_eq!(h1.is_quit(), h2.is_quit());
        assert_eq!(h1.tick_count(), h2.tick_count());
        assert_eq!(h1.history_depth(), h2.history_depth());

        // Frame text must also be identical.
        for (f1, f2) in h1.frames().iter().zip(h2.frames().iter()) {
            assert_eq!(f1.text, f2.text);
        }
    }

    #[test]
    fn scripted_replay_yields_stable_transition_digest() {
        let script = vec![
            HarnessStep::Tick,
            HarnessStep::FeedHealthyState,
            HarnessStep::Char('3'),
            HarnessStep::Char('?'),
            HarnessStep::KeyCode(KeyCode::Escape),
            HarnessStep::Char('r'),
            HarnessStep::FeedPressuredState,
            HarnessStep::Error {
                message: "state adapter failed".to_string(),
                source: "adapter".to_string(),
            },
            HarnessStep::Resize {
                cols: 140,
                rows: 42,
            },
            HarnessStep::Char('q'),
        ];

        let mut h1 = DashboardHarness::default();
        let mut h2 = DashboardHarness::default();
        h1.run_script(&script);
        h2.run_script(&script);

        assert_eq!(h1.trace_digest(), h2.trace_digest());
        assert_eq!(h1.command_trace(), h2.command_trace());
    }

    #[test]
    fn script_command_trace_exposes_effect_boundaries() {
        let script = vec![
            HarnessStep::Tick,
            HarnessStep::Char('r'),
            HarnessStep::Error {
                message: "disk read failed".to_string(),
                source: "adapter".to_string(),
            },
            HarnessStep::FeedUnavailable,
        ];

        let mut h = DashboardHarness::default();
        h.run_script(&script);

        let trace = h.command_trace();
        assert_eq!(trace.len(), script.len());
        assert!(trace[0].contains("Batch([FetchData, ScheduleTick("));
        assert_eq!(trace[1], "FetchData");
        assert!(trace[2].contains("ScheduleNotificationExpiry"));
        assert_eq!(trace[3], "None");
    }
}
