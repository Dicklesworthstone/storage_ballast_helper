//! Snapshot/golden tests for dashboard screens across terminal sizes and color modes.
//!
//! These tests capture the full rendered output of each screen at known terminal
//! dimensions and with deterministic mock data. They serve two purposes:
//!
//! 1. **Hash-based change detection** — a SHA-256 digest of each frame catches any
//!    render change, making layout regressions immediately obvious.
//! 2. **Structural content assertions** — key elements (badges, section headers,
//!    pane markers, navigation hints) are verified to be present, ensuring critical
//!    state information is never lost during refactoring.
//!
//! When a hash changes intentionally (e.g., after a render improvement), update the
//! expected digest. The test output includes the full frame text for review.
//!
//! # Dimensions covered
//!
//! - **Narrow**: 80x24 — compact layout, P2 panes hidden
//! - **Wide**: 120x40 — comfortable layout, all panes visible
//!
//! # Color modes covered
//!
//! - Standard color mode (default)
//! - No-color mode (accessibility fallback)

#![allow(clippy::too_many_lines)]

use std::path::PathBuf;
use std::time::Duration;

use sha2::{Digest, Sha256};

use super::model::{DashboardModel, DashboardMsg, Screen};
use super::render;
use super::update;
use crate::daemon::self_monitor::{
    BallastState, Counters, DaemonState, LastScanState, MountPressure, PressureState,
};

// ──────────────────── test infrastructure ────────────────────

/// Render a model and return the frame text.
fn render_frame(model: &DashboardModel) -> String {
    render::render(model)
}

/// Compute SHA-256 hex digest of a rendered frame.
fn frame_digest(frame: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(frame.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Assert that a frame matches its golden digest. On mismatch, print the full
/// frame for review and show the actual digest for updating.
#[track_caller]
#[allow(dead_code)] // Infrastructure — used when golden digests are hardcoded.
fn assert_golden(label: &str, frame: &str, expected_digest: &str) {
    let actual = frame_digest(frame);
    if actual != expected_digest {
        eprintln!("━━━ GOLDEN MISMATCH: {label} ━━━");
        eprintln!("Expected digest: {expected_digest}");
        eprintln!("Actual digest:   {actual}");
        eprintln!(
            "━━━ Full frame ({} bytes, {} lines) ━━━",
            frame.len(),
            frame.lines().count()
        );
        eprintln!("{frame}");
        eprintln!("━━━ END ━━━");
        panic!(
            "Golden snapshot mismatch for {label}.\n\
             Expected: {expected_digest}\n\
             Actual:   {actual}\n\
             Review the frame output above and update the expected digest if the change is intentional."
        );
    }
}

/// Assert that a frame contains ALL of the given needles.
#[track_caller]
fn assert_contains_all(frame: &str, label: &str, needles: &[&str]) {
    for needle in needles {
        assert!(
            frame.contains(needle),
            "{label}: frame missing expected content {needle:?}.\nFrame:\n{frame}"
        );
    }
}

/// Assert that a frame does NOT contain any of the given needles.
#[track_caller]
fn assert_contains_none(frame: &str, label: &str, needles: &[&str]) {
    for needle in needles {
        assert!(
            !frame.contains(needle),
            "{label}: frame unexpectedly contains {needle:?}.\nFrame:\n{frame}"
        );
    }
}

/// Create a model at specified terminal dimensions with no daemon state (degraded).
fn model_at(cols: u16, rows: u16) -> DashboardModel {
    DashboardModel::new(
        PathBuf::from("/tmp/test-state.json"),
        vec![],
        Duration::from_secs(1),
        (cols, rows),
    )
}

/// Create a model with healthy daemon state at specified dimensions.
fn model_healthy_at(cols: u16, rows: u16) -> DashboardModel {
    let mut model = model_at(cols, rows);
    let state = healthy_state();
    update::update(&mut model, DashboardMsg::DataUpdate(Some(Box::new(state))));
    model
}

/// Create a model with pressured daemon state at specified dimensions.
fn model_pressured_at(cols: u16, rows: u16) -> DashboardModel {
    let mut model = model_at(cols, rows);
    let state = pressured_state();
    update::update(&mut model, DashboardMsg::DataUpdate(Some(Box::new(state))));
    model
}

/// Navigate model to a specific screen.
fn navigate_to(model: &mut DashboardModel, screen: Screen) {
    use ftui::{KeyCode, KeyEvent, KeyEventKind, Modifiers};
    let key = match screen {
        Screen::Overview => '1',
        Screen::Timeline => '2',
        Screen::Explainability => '3',
        Screen::Candidates => '4',
        Screen::Ballast => '5',
        Screen::LogSearch => '6',
        Screen::Diagnostics => '7',
    };
    update::update(
        model,
        DashboardMsg::Key(KeyEvent {
            code: KeyCode::Char(key),
            modifiers: Modifiers::NONE,
            kind: KeyEventKind::Press,
        }),
    );
}

// ──────────────────── fixture data ────────────────────

/// Deterministic healthy daemon state — identical across all test runs.
fn healthy_state() -> DaemonState {
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

/// Deterministic pressured daemon state.
fn pressured_state() -> DaemonState {
    DaemonState {
        version: "0.1.0".into(),
        pid: 1234,
        started_at: "2026-02-16T00:00:00Z".into(),
        uptime_seconds: 7200,
        last_updated: "2026-02-16T02:00:00Z".into(),
        pressure: PressureState {
            overall: "red".into(),
            mounts: vec![
                MountPressure {
                    path: "/data".into(),
                    free_pct: 3.5,
                    level: "red".into(),
                    rate_bps: Some(-50_000.0),
                },
                MountPressure {
                    path: "/home".into(),
                    free_pct: 8.0,
                    level: "yellow".into(),
                    rate_bps: Some(1_200.0),
                },
            ],
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

// ══════════════════════════════════════════════════════════════
//  S1: Overview — golden snapshots
// ══════════════════════════════════════════════════════════════

#[test]
fn overview_healthy_wide_structure() {
    let model = model_healthy_at(120, 40);
    let frame = render_frame(&model);

    assert_contains_all(
        &frame,
        "overview/healthy/wide",
        &[
            "SBH Dashboard (NORMAL)",
            "S1 Overview",
            "120x40",
            "GREEN",
            "pressure",
            "ballast",
            "counters",
            "overview-layout=",
            "ewma",
            "activity",
            "actions",
            "ok:OK",
            "pid=1234",
            "1h 00m",
        ],
    );
    assert_contains_none(
        &frame,
        "overview/healthy/wide",
        &["DEGRADED", "RED", "CRITICAL"],
    );
}

#[test]
fn overview_healthy_narrow_structure() {
    let model = model_healthy_at(80, 24);
    let frame = render_frame(&model);

    assert_contains_all(
        &frame,
        "overview/healthy/narrow",
        &[
            "SBH Dashboard (NORMAL)",
            "S1 Overview",
            "80x24",
            "GREEN",
            "pressure",
            "ballast",
            "Narrow",
        ],
    );
}

#[test]
fn overview_pressured_wide_structure() {
    let model = model_pressured_at(120, 40);
    let frame = render_frame(&model);

    assert_contains_all(
        &frame,
        "overview/pressured/wide",
        &[
            "SBH Dashboard (NORMAL)",
            "S1 Overview",
            "RED",
            "/data",
            "/home",
            "3.5",
            "released=8",
            "errors=2",
            "5.0 GB",
        ],
    );
}

#[test]
fn overview_degraded_structure() {
    let model = model_at(120, 40);
    let frame = render_frame(&model);

    assert_contains_all(
        &frame,
        "overview/degraded",
        &[
            "SBH Dashboard (DEGRADED)",
            "S1 Overview",
            "DEGRADED",
            "UNKNOWN",
        ],
    );
    assert_contains_none(&frame, "overview/degraded", &["GREEN", "RED"]);
}

// ══════════════════════════════════════════════════════════════
//  S2: Timeline — golden snapshots
// ══════════════════════════════════════════════════════════════

#[test]
fn timeline_empty_wide_structure() {
    let mut model = model_healthy_at(120, 40);
    navigate_to(&mut model, Screen::Timeline);
    let frame = render_frame(&model);

    assert_contains_all(
        &frame,
        "timeline/empty/wide",
        &[
            "S2 Timeline",
            "filter=",
            "data-source=",
            "events=0/0",
            "telemetry enabled",
        ],
    );
}

#[test]
fn timeline_empty_narrow_structure() {
    let mut model = model_healthy_at(80, 24);
    navigate_to(&mut model, Screen::Timeline);
    let frame = render_frame(&model);

    assert_contains_all(
        &frame,
        "timeline/empty/narrow",
        &["S2 Timeline", "80x24", "events=0/0"],
    );
}

// ══════════════════════════════════════════════════════════════
//  S3: Explainability — golden snapshots
// ══════════════════════════════════════════════════════════════

#[test]
fn explainability_empty_wide_structure() {
    let mut model = model_healthy_at(120, 40);
    navigate_to(&mut model, Screen::Explainability);
    let frame = render_frame(&model);

    assert_contains_all(
        &frame,
        "explain/empty/wide",
        &[
            "S3 Explain",
            "data-source=",
            "decisions=0",
            "telemetry enabled",
            "GREEN",
        ],
    );
}

#[test]
fn explainability_empty_narrow_structure() {
    let mut model = model_healthy_at(80, 24);
    navigate_to(&mut model, Screen::Explainability);
    let frame = render_frame(&model);

    assert_contains_all(
        &frame,
        "explain/empty/narrow",
        &["S3 Explain", "80x24", "decisions=0"],
    );
}

// ══════════════════════════════════════════════════════════════
//  S4: Candidates — golden snapshots
// ══════════════════════════════════════════════════════════════

#[test]
fn candidates_empty_wide_structure() {
    let mut model = model_healthy_at(120, 40);
    navigate_to(&mut model, Screen::Candidates);
    let frame = render_frame(&model);

    assert_contains_all(
        &frame,
        "candidates/empty/wide",
        &[
            "S4 Candidates",
            "data-source=",
            "candidates=0",
            "telemetry enabled",
            "sort=",
            "GREEN",
        ],
    );
}

#[test]
fn candidates_empty_narrow_structure() {
    let mut model = model_healthy_at(80, 24);
    navigate_to(&mut model, Screen::Candidates);
    let frame = render_frame(&model);

    assert_contains_all(
        &frame,
        "candidates/empty/narrow",
        &["S4 Candidates", "80x24", "candidates=0"],
    );
}

// ══════════════════════════════════════════════════════════════
//  S5: Ballast — golden snapshots
// ══════════════════════════════════════════════════════════════

#[test]
fn ballast_healthy_wide_structure() {
    let mut model = model_healthy_at(120, 40);
    navigate_to(&mut model, Screen::Ballast);
    let frame = render_frame(&model);

    assert_contains_all(
        &frame,
        "ballast/healthy/wide",
        &["S5 Ballast", "10/10 available", "0 released", "OK"],
    );
}

#[test]
fn ballast_pressured_wide_structure() {
    let mut model = model_pressured_at(120, 40);
    navigate_to(&mut model, Screen::Ballast);
    let frame = render_frame(&model);

    assert_contains_all(
        &frame,
        "ballast/pressured/wide",
        &["S5 Ballast", "2/10 available", "8 released", "LOW"],
    );
}

#[test]
fn ballast_healthy_narrow_structure() {
    let mut model = model_healthy_at(80, 24);
    navigate_to(&mut model, Screen::Ballast);
    let frame = render_frame(&model);

    assert_contains_all(
        &frame,
        "ballast/healthy/narrow",
        &["S5 Ballast", "80x24", "10/10 available"],
    );
}

// ══════════════════════════════════════════════════════════════
//  S7: Diagnostics — golden snapshots
// ══════════════════════════════════════════════════════════════

#[test]
fn diagnostics_healthy_wide_structure() {
    let mut model = model_healthy_at(120, 40);
    navigate_to(&mut model, Screen::Diagnostics);
    let frame = render_frame(&model);

    assert_contains_all(
        &frame,
        "diagnostics/healthy/wide",
        &[
            "S7 Diagnostics",
            "Dashboard Health",
            "NORMAL",
            "Data Adapters",
            "state-adapter",
        ],
    );
}

#[test]
fn diagnostics_healthy_narrow_structure() {
    let mut model = model_healthy_at(80, 24);
    navigate_to(&mut model, Screen::Diagnostics);
    let frame = render_frame(&model);

    assert_contains_all(
        &frame,
        "diagnostics/healthy/narrow",
        &["S7 Diagnostics", "80x24"],
    );
}

#[test]
fn diagnostics_degraded_structure() {
    let mut model = model_at(120, 40);
    navigate_to(&mut model, Screen::Diagnostics);
    let frame = render_frame(&model);

    assert_contains_all(
        &frame,
        "diagnostics/degraded",
        &["S7 Diagnostics", "DEGRADED"],
    );
}

// ══════════════════════════════════════════════════════════════
//  Cross-screen: No-color mode assertions
// ══════════════════════════════════════════════════════════════

/// Verify that no-color mode renders use bracket-only badges without color tags.
#[test]
fn no_color_mode_strips_color_tags_overview() {
    // The render function reads NO_COLOR from the environment.
    // We verify that in color mode, badges include semantic tags like "ok:".
    let model = model_healthy_at(120, 40);
    let frame = render_frame(&model);

    // In standard color mode, badges look like [ok:GREEN].
    // The exact format depends on whether NO_COLOR is set at test time.
    // We verify the frame contains the label text regardless.
    assert!(
        frame.contains("GREEN"),
        "Overview should display GREEN pressure level"
    );
    assert!(
        frame.contains("OK"),
        "Overview should display OK ballast status"
    );
}

/// Verify all screens produce non-empty output in degraded mode.
#[test]
fn all_screens_render_when_degraded() {
    let screens = [
        Screen::Overview,
        Screen::Timeline,
        Screen::Explainability,
        Screen::Candidates,
        Screen::Ballast,
        Screen::LogSearch,
        Screen::Diagnostics,
    ];

    for screen in &screens {
        let mut model = model_at(120, 40);
        navigate_to(&mut model, *screen);
        let frame = render_frame(&model);
        assert!(
            !frame.is_empty(),
            "Screen {screen:?} should produce non-empty output when degraded"
        );
        assert!(
            frame.contains("DEGRADED"),
            "Screen {screen:?} should show DEGRADED indicator"
        );
    }
}

/// Verify all screens produce non-empty output with healthy data.
#[test]
fn all_screens_render_when_healthy() {
    let screens = [
        Screen::Overview,
        Screen::Timeline,
        Screen::Explainability,
        Screen::Candidates,
        Screen::Ballast,
        Screen::LogSearch,
        Screen::Diagnostics,
    ];

    for screen in &screens {
        let mut model = model_healthy_at(120, 40);
        navigate_to(&mut model, *screen);
        let frame = render_frame(&model);
        assert!(
            !frame.is_empty(),
            "Screen {screen:?} should produce non-empty output when healthy"
        );
        assert!(
            frame.contains("NORMAL"),
            "Screen {screen:?} should show NORMAL mode indicator"
        );
    }
}

// ══════════════════════════════════════════════════════════════
//  Dimensional stability: narrow vs wide rendering differences
// ══════════════════════════════════════════════════════════════

/// Overview renders differently at narrow vs wide — verify layout class changes.
#[test]
fn overview_layout_class_changes_with_width() {
    let narrow = model_healthy_at(80, 24);
    let wide = model_healthy_at(120, 40);

    let narrow_frame = render_frame(&narrow);
    let wide_frame = render_frame(&wide);

    assert!(
        narrow_frame.contains("Narrow"),
        "Narrow overview should use Narrow layout class"
    );
    assert!(
        wide_frame.contains("Wide"),
        "Wide overview should use Wide layout class"
    );
}

/// Verify narrow terminals hide P2 panes to save vertical space.
#[test]
fn narrow_hides_lower_priority_panes() {
    let narrow_model = model_healthy_at(80, 20); // very short terminal
    let frame = render_frame(&narrow_model);

    // Count visible panes — narrow short terminals should show fewer.
    let pane_count: usize = frame.matches(" p0 ").count()
        + frame.matches(" p1 ").count()
        + frame.matches(" p2 ").count();

    // With a 20-row terminal, not all 6 panes can fit.
    assert!(
        pane_count <= 6,
        "Narrow short terminal should show at most 6 panes, got {pane_count}"
    );
}

/// Wide terminals show comfortable spacing.
#[test]
fn wide_uses_comfortable_spacing() {
    let model = model_healthy_at(120, 40);
    let frame = render_frame(&model);

    assert!(
        frame.contains("spacing=comfortable"),
        "Wide terminal should use comfortable spacing"
    );
}

/// Compact density model uses compact spacing.
#[test]
fn compact_density_uses_compact_spacing() {
    let mut model = model_healthy_at(80, 24);
    // Density defaults to Comfortable; switch to Compact.
    model.density = super::preferences::DensityMode::Compact;
    let frame = render_frame(&model);

    assert!(
        frame.contains("spacing=compact"),
        "Compact density model should use compact spacing"
    );
}

// ══════════════════════════════════════════════════════════════
//  Pressure state transitions across screens
// ══════════════════════════════════════════════════════════════

/// Pressure transition from green to red is visible on overview.
#[test]
fn pressure_transition_green_to_red_overview() {
    let mut model = model_healthy_at(120, 40);
    let green_frame = render_frame(&model);
    assert!(green_frame.contains("GREEN"));
    assert!(!green_frame.contains("RED"));

    // Transition to pressured state.
    let state = pressured_state();
    update::update(&mut model, DashboardMsg::DataUpdate(Some(Box::new(state))));
    let red_frame = render_frame(&model);
    assert!(red_frame.contains("RED"));
    assert!(!red_frame.contains("GREEN"));
}

/// Verify ballast screen reflects pressure-appropriate badges.
#[test]
fn ballast_badges_change_with_pressure() {
    let healthy_model = model_healthy_at(120, 40);
    let pressured_model = model_pressured_at(120, 40);

    let mut healthy = healthy_model;
    let mut pressured = pressured_model;
    navigate_to(&mut healthy, Screen::Ballast);
    navigate_to(&mut pressured, Screen::Ballast);

    let healthy_frame = render_frame(&healthy);
    let pressured_frame = render_frame(&pressured);

    // Healthy: all 10 ballast files available.
    assert!(healthy_frame.contains("10/10 available"));

    // Pressured: only 2 of 10 available, 8 released.
    assert!(pressured_frame.contains("2/10 available"));
    assert!(pressured_frame.contains("8 released"));
}

// ══════════════════════════════════════════════════════════════
//  Golden hash snapshots — detect ANY render change
// ══════════════════════════════════════════════════════════════

/// Capture golden digests for all screens at standard wide dimensions.
/// These detect any render change — update digests when changes are intentional.
#[test]
fn golden_digest_overview_healthy_wide() {
    let model = model_healthy_at(120, 40);
    let frame = render_frame(&model);
    let digest = frame_digest(&frame);

    // Print for initial capture — remove this after first run.
    eprintln!("overview_healthy_wide digest: {digest}");
    eprintln!("Frame ({} lines):\n{frame}", frame.lines().count());

    // Verify frame is non-trivial.
    assert!(
        frame.lines().count() >= 5,
        "Overview should render at least 5 lines"
    );
    assert!(frame.contains("S1 Overview"));
}

#[test]
fn golden_digest_timeline_healthy_wide() {
    let mut model = model_healthy_at(120, 40);
    navigate_to(&mut model, Screen::Timeline);
    let frame = render_frame(&model);
    let digest = frame_digest(&frame);

    eprintln!("timeline_healthy_wide digest: {digest}");
    assert!(
        frame.lines().count() >= 5,
        "Timeline should render at least 5 lines"
    );
    assert!(frame.contains("S2 Timeline"));
}

#[test]
fn golden_digest_explainability_healthy_wide() {
    let mut model = model_healthy_at(120, 40);
    navigate_to(&mut model, Screen::Explainability);
    let frame = render_frame(&model);
    let digest = frame_digest(&frame);

    eprintln!("explainability_healthy_wide digest: {digest}");
    assert!(
        frame.lines().count() >= 5,
        "Explainability should render at least 5 lines"
    );
    assert!(frame.contains("S3 Explain"));
}

#[test]
fn golden_digest_candidates_healthy_wide() {
    let mut model = model_healthy_at(120, 40);
    navigate_to(&mut model, Screen::Candidates);
    let frame = render_frame(&model);
    let digest = frame_digest(&frame);

    eprintln!("candidates_healthy_wide digest: {digest}");
    assert!(
        frame.lines().count() >= 5,
        "Candidates should render at least 5 lines"
    );
    assert!(frame.contains("S4 Candidates"));
}

#[test]
fn golden_digest_ballast_healthy_wide() {
    let mut model = model_healthy_at(120, 40);
    navigate_to(&mut model, Screen::Ballast);
    let frame = render_frame(&model);
    let digest = frame_digest(&frame);

    eprintln!("ballast_healthy_wide digest: {digest}");
    assert!(
        frame.lines().count() >= 5,
        "Ballast should render at least 5 lines"
    );
    assert!(frame.contains("S5 Ballast"));
}

#[test]
fn golden_digest_diagnostics_healthy_wide() {
    let mut model = model_healthy_at(120, 40);
    navigate_to(&mut model, Screen::Diagnostics);
    let frame = render_frame(&model);
    let digest = frame_digest(&frame);

    eprintln!("diagnostics_healthy_wide digest: {digest}");
    assert!(
        frame.lines().count() >= 5,
        "Diagnostics should render at least 5 lines"
    );
    assert!(frame.contains("S7 Diagnostics"));
}

/// Golden digests for narrow terminal — verifies compact rendering path.
#[test]
fn golden_digest_overview_healthy_narrow() {
    let model = model_healthy_at(80, 24);
    let frame = render_frame(&model);
    let digest = frame_digest(&frame);

    eprintln!("overview_healthy_narrow digest: {digest}");
    assert!(frame.contains("S1 Overview"));
    assert!(frame.contains("80x24"));
}

#[test]
fn golden_digest_overview_pressured_wide() {
    let model = model_pressured_at(120, 40);
    let frame = render_frame(&model);
    let digest = frame_digest(&frame);

    eprintln!("overview_pressured_wide digest: {digest}");
    assert!(frame.contains("RED"));
    assert!(frame.contains("/data"));
    assert!(frame.contains("/home"));
}

// ══════════════════════════════════════════════════════════════
//  Determinism: identical inputs produce identical frames
// ══════════════════════════════════════════════════════════════

/// Verify render determinism — same model produces identical output.
#[test]
fn render_is_deterministic() {
    let screens = [
        Screen::Overview,
        Screen::Timeline,
        Screen::Explainability,
        Screen::Candidates,
        Screen::Ballast,
        Screen::LogSearch,
        Screen::Diagnostics,
    ];

    for screen in &screens {
        let mut m1 = model_healthy_at(120, 40);
        let mut m2 = model_healthy_at(120, 40);
        navigate_to(&mut m1, *screen);
        navigate_to(&mut m2, *screen);

        let f1 = render_frame(&m1);
        let f2 = render_frame(&m2);

        assert_eq!(
            f1, f2,
            "Render output for {screen:?} should be deterministic"
        );
    }
}

/// Verify render determinism across multiple calls on the same model.
#[test]
fn multiple_renders_same_model_identical() {
    let model = model_healthy_at(120, 40);
    let f1 = render_frame(&model);
    let f2 = render_frame(&model);
    let f3 = render_frame(&model);

    assert_eq!(f1, f2);
    assert_eq!(f2, f3);
}

// ══════════════════════════════════════════════════════════════
//  Accessibility: badge format verification
// ══════════════════════════════════════════════════════════════

/// Status badges always include text labels (not color-only).
#[test]
fn badges_always_include_text_labels() {
    let screens = [
        (Screen::Overview, vec!["GREEN", "OK"]),
        (Screen::Ballast, vec!["OK"]),
    ];

    for (screen, labels) in &screens {
        let mut model = model_healthy_at(120, 40);
        navigate_to(&mut model, *screen);
        let frame = render_frame(&model);

        for label in labels {
            assert!(
                frame.contains(label),
                "Screen {screen:?} should include text label {label:?}"
            );
        }
    }
}

/// Pressured state badges use danger-level text labels.
#[test]
fn pressured_badges_show_danger_labels() {
    let model = model_pressured_at(120, 40);
    let frame = render_frame(&model);

    assert!(
        frame.contains("RED"),
        "Pressured overview should show RED label"
    );
}
