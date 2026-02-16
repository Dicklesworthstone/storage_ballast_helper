//! Comprehensive unit tests for TUI module gaps (bd-xzt.4.1).
//!
//! Targets: model reducers, update message handlers, input/keymap edge cases,
//! widget formatting helpers, and adapter boundary conditions that lacked
//! dedicated coverage.

use std::path::PathBuf;
use std::time::Duration;

use ftui_core::event::{KeyCode, KeyEvent, KeyEventKind, Modifiers};

use super::input::{self, InputAction, InputContext};
use super::model::{
    BallastVolume, ConfirmAction, DashboardCmd, DashboardModel, DashboardMsg, NotificationLevel,
    Overlay, RateHistory, Screen,
};
use super::telemetry::{DataSource, TelemetryResult};
use super::update;
use super::widgets;

// ──────────────────── helpers ────────────────────

fn test_model() -> DashboardModel {
    DashboardModel::new(
        PathBuf::from("/tmp/state.json"),
        vec![],
        Duration::from_secs(1),
        (80, 24),
    )
}

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

fn sample_volume(mount: &str, available: usize, total: usize) -> BallastVolume {
    BallastVolume {
        mount_point: mount.to_owned(),
        ballast_dir: format!("{mount}/.sbh/ballast"),
        fs_type: "ext4".into(),
        strategy: "fallocate".into(),
        files_available: available,
        files_total: total,
        releasable_bytes: (available as u64) * 1_073_741_824,
        skipped: false,
        skip_reason: None,
    }
}

fn skipped_volume(mount: &str, reason: &str) -> BallastVolume {
    BallastVolume {
        mount_point: mount.to_owned(),
        ballast_dir: format!("{mount}/.sbh/ballast"),
        fs_type: "tmpfs".into(),
        strategy: "skip".into(),
        files_available: 0,
        files_total: 0,
        releasable_bytes: 0,
        skipped: true,
        skip_reason: Some(reason.into()),
    }
}

// ════════════════════════════════════════════════════════════
// § 1  UPDATE: TelemetryBallast message handler
// ════════════════════════════════════════════════════════════

#[test]
fn telemetry_ballast_msg_updates_model() {
    let mut model = test_model();
    let vols = vec![sample_volume("/", 3, 5), sample_volume("/data", 10, 10)];
    let result = TelemetryResult {
        data: vols,
        source: DataSource::Sqlite,
        partial: false,
        diagnostics: String::new(),
    };

    let cmd = update::update(&mut model, DashboardMsg::TelemetryBallast(result));
    assert!(matches!(cmd, DashboardCmd::None));
    assert_eq!(model.ballast_volumes.len(), 2);
    assert_eq!(model.ballast_source, DataSource::Sqlite);
    assert!(!model.ballast_partial);
    assert!(model.ballast_diagnostics.is_empty());
}

#[test]
fn telemetry_ballast_clamps_cursor() {
    let mut model = test_model();
    model.ballast_selected = 10; // out of range

    let result = TelemetryResult {
        data: vec![sample_volume("/", 3, 5), sample_volume("/data", 8, 10)],
        source: DataSource::Sqlite,
        partial: false,
        diagnostics: String::new(),
    };

    update::update(&mut model, DashboardMsg::TelemetryBallast(result));
    assert_eq!(model.ballast_selected, 1); // clamped to last
}

#[test]
fn telemetry_ballast_empty_resets_state() {
    let mut model = test_model();
    model.ballast_selected = 3;
    model.ballast_detail = true;

    let result = TelemetryResult {
        data: vec![],
        source: DataSource::None,
        partial: true,
        diagnostics: "no ballast data available".into(),
    };

    update::update(&mut model, DashboardMsg::TelemetryBallast(result));
    assert_eq!(model.ballast_selected, 0);
    assert!(!model.ballast_detail);
    assert!(model.ballast_partial);
    assert_eq!(model.ballast_diagnostics, "no ballast data available");
}

#[test]
fn telemetry_ballast_preserves_valid_cursor() {
    let mut model = test_model();
    model.ballast_volumes = vec![
        sample_volume("/", 3, 5),
        sample_volume("/data", 8, 10),
        sample_volume("/home", 2, 5),
    ];
    model.ballast_selected = 1;

    // Refresh with same number of volumes — cursor stays at 1.
    let result = TelemetryResult {
        data: vec![
            sample_volume("/", 4, 5),
            sample_volume("/data", 9, 10),
            sample_volume("/home", 3, 5),
        ],
        source: DataSource::Sqlite,
        partial: false,
        diagnostics: String::new(),
    };

    update::update(&mut model, DashboardMsg::TelemetryBallast(result));
    assert_eq!(model.ballast_selected, 1);
}

#[test]
fn telemetry_ballast_partial_with_diagnostics() {
    let mut model = test_model();
    let result = TelemetryResult {
        data: vec![sample_volume("/", 1, 5)],
        source: DataSource::Jsonl,
        partial: true,
        diagnostics: "sqlite locked, fell back to JSONL".into(),
    };

    update::update(&mut model, DashboardMsg::TelemetryBallast(result));
    assert!(model.ballast_partial);
    assert_eq!(model.ballast_source, DataSource::Jsonl);
    assert!(model.ballast_diagnostics.contains("sqlite locked"));
}

// ════════════════════════════════════════════════════════════
// § 2  UPDATE: Ballast screen key handling (currently no-op)
// ════════════════════════════════════════════════════════════

#[test]
fn ballast_screen_j_k_navigates_cursor() {
    let mut model = test_model();
    model.screen = Screen::Ballast;
    model.ballast_volumes = vec![sample_volume("/", 3, 5), sample_volume("/data", 8, 10)];

    // j moves cursor down.
    let cmd = update::update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('j'))));
    assert!(matches!(cmd, DashboardCmd::None));
    assert_eq!(model.ballast_selected, 1);

    // k moves cursor back up.
    update::update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('k'))));
    assert_eq!(model.ballast_selected, 0);
}

#[test]
fn ballast_screen_global_keys_still_work() {
    let mut model = test_model();
    model.screen = Screen::Ballast;

    // q should still quit
    let cmd = update::update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('q'))));
    assert!(model.quit);
    assert!(matches!(cmd, DashboardCmd::Quit));
}

#[test]
fn ballast_screen_number_keys_navigate() {
    let mut model = test_model();
    model.screen = Screen::Ballast;

    update::update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('2'))));
    assert_eq!(model.screen, Screen::Timeline);
}

// ════════════════════════════════════════════════════════════
// § 3  UPDATE: Tick telemetry request by screen
// ════════════════════════════════════════════════════════════

#[test]
fn tick_on_ballast_requests_telemetry() {
    let mut model = test_model();
    model.screen = Screen::Ballast;

    let cmd = update::update(&mut model, DashboardMsg::Tick);
    if let DashboardCmd::Batch(cmds) = cmd {
        let has_telemetry = cmds
            .iter()
            .any(|c| matches!(c, DashboardCmd::FetchTelemetry));
        assert!(
            has_telemetry,
            "Tick on Ballast should include FetchTelemetry"
        );
    } else {
        panic!("Expected Batch command from Tick");
    }
}

#[test]
fn tick_on_logsearch_does_not_request_telemetry() {
    let mut model = test_model();
    model.screen = Screen::LogSearch;

    let cmd = update::update(&mut model, DashboardMsg::Tick);
    if let DashboardCmd::Batch(cmds) = cmd {
        let has_telemetry = cmds
            .iter()
            .any(|c| matches!(c, DashboardCmd::FetchTelemetry));
        assert!(
            !has_telemetry,
            "Tick on LogSearch should not include FetchTelemetry"
        );
    }
}

// ════════════════════════════════════════════════════════════
// § 4  INPUT: Confirmation overlay key resolution
// ════════════════════════════════════════════════════════════

#[test]
fn confirmation_overlay_esc_closes() {
    let ctx = InputContext {
        screen: Screen::Ballast,
        active_overlay: Some(Overlay::Confirmation(ConfirmAction::BallastRelease)),
    };
    let res = input::resolve_key_event(&make_key(KeyCode::Escape), ctx);
    assert_eq!(res.action, Some(InputAction::CloseOverlay));
    assert!(res.consumed);
}

#[test]
fn confirmation_overlay_ctrl_c_quits() {
    let ctx = InputContext {
        screen: Screen::Ballast,
        active_overlay: Some(Overlay::Confirmation(ConfirmAction::BallastReleaseAll)),
    };
    let res = input::resolve_key_event(&make_key_ctrl(KeyCode::Char('c')), ctx);
    assert_eq!(res.action, Some(InputAction::Quit));
    assert!(res.consumed);
}

#[test]
fn confirmation_overlay_consumes_other_keys() {
    let ctx = InputContext {
        screen: Screen::Ballast,
        active_overlay: Some(Overlay::Confirmation(ConfirmAction::BallastRelease)),
    };

    // Number keys should NOT navigate when confirmation overlay is active.
    let res = input::resolve_key_event(&make_key(KeyCode::Char('3')), ctx);
    assert!(res.consumed);
    assert!(res.action.is_none());

    // q should NOT quit when in confirmation overlay.
    let res = input::resolve_key_event(&make_key(KeyCode::Char('q')), ctx);
    assert!(res.consumed);
    assert!(res.action.is_none());
}

#[test]
fn confirmation_overlay_integration_via_update() {
    let mut model = test_model();
    model.active_overlay = Some(Overlay::Confirmation(ConfirmAction::BallastRelease));

    // Esc closes overlay without quitting.
    let cmd = update::update(&mut model, DashboardMsg::Key(make_key(KeyCode::Escape)));
    assert!(model.active_overlay.is_none());
    assert!(!model.quit);
    assert!(matches!(cmd, DashboardCmd::None));
}

#[test]
fn confirmation_overlay_blocks_screen_navigation() {
    let mut model = test_model();
    model.screen = Screen::Ballast;
    model.active_overlay = Some(Overlay::Confirmation(ConfirmAction::BallastReleaseAll));

    // Number key should NOT navigate.
    update::update(&mut model, DashboardMsg::Key(make_key(KeyCode::Char('1'))));
    assert_eq!(model.screen, Screen::Ballast);
    assert!(model.active_overlay.is_some());
}

// ════════════════════════════════════════════════════════════
// § 5  INPUT: Contextual help for all overlays and screens
// ════════════════════════════════════════════════════════════

#[test]
fn contextual_help_confirmation_overlay() {
    let help = input::contextual_help(InputContext {
        screen: Screen::Ballast,
        active_overlay: Some(Overlay::Confirmation(ConfirmAction::BallastRelease)),
    });
    assert_eq!(help.title, "Confirmation Overlay");
    assert!(help.screen_hint.contains("confirmation"));
    assert!(help.bindings.iter().any(|b| b.keys == "Enter"));
    assert!(help.bindings.iter().any(|b| b.keys == "Esc"));
}

#[test]
fn contextual_help_command_palette_overlay() {
    let help = input::contextual_help(InputContext {
        screen: Screen::Overview,
        active_overlay: Some(Overlay::CommandPalette),
    });
    assert_eq!(help.title, "Command Palette");
    assert!(help.bindings.iter().any(|b| b.keys == "Ctrl-P"));
}

#[test]
fn contextual_help_voi_overlay() {
    let help = input::contextual_help(InputContext {
        screen: Screen::Overview,
        active_overlay: Some(Overlay::Voi),
    });
    assert_eq!(help.title, "VOI Overlay");
    assert!(help.bindings.iter().any(|b| b.keys == "v"));
}

#[test]
fn contextual_help_per_screen_hints() {
    let screens = [
        (Screen::Overview, "Overview"),
        (Screen::Timeline, "Timeline"),
        (Screen::Explainability, "Explainability"),
        (Screen::Candidates, "Candidates"),
        (Screen::Ballast, "Ballast"),
        (Screen::LogSearch, "Log Search"),
        (Screen::Diagnostics, "Diagnostics"),
    ];
    for (screen, expected_keyword) in screens {
        let help = input::contextual_help(InputContext {
            screen,
            active_overlay: None,
        });
        assert_eq!(help.title, "Global Navigation");
        assert!(
            help.screen_hint.contains(expected_keyword),
            "Screen {screen:?} hint should contain '{expected_keyword}', got: '{}'",
            help.screen_hint
        );
    }
}

// ════════════════════════════════════════════════════════════
// § 6  INPUT: Fuzzy subsequence edge cases
// ════════════════════════════════════════════════════════════

#[test]
fn palette_search_fuzzy_partial_match() {
    // "jb" should match "action.jump_ballast" via fuzzy subsequence
    let results = input::search_palette_actions("jb", 5);
    assert!(
        !results.is_empty(),
        "fuzzy 'jb' should match at least one action"
    );
}

#[test]
fn palette_search_no_match() {
    let results = input::search_palette_actions("zzzzzzz", 5);
    assert!(results.is_empty());
}

#[test]
fn palette_search_single_char() {
    // "q" should match action.quit (exact shortcut)
    let results = input::search_palette_actions("q", 5);
    assert!(!results.is_empty());
    // Exact shortcut match should rank high.
    assert!(results.iter().any(|a| a.id == "action.quit"));
}

#[test]
fn palette_route_empty_whitespace_returns_none() {
    assert_eq!(input::route_palette_query(""), None);
    assert_eq!(input::route_palette_query("   "), None);
    assert_eq!(input::route_palette_query("\t\n"), None);
}

// ════════════════════════════════════════════════════════════
// § 7  WIDGETS: human_bytes edge cases
// ════════════════════════════════════════════════════════════

#[test]
fn human_bytes_zero() {
    assert_eq!(widgets::human_bytes(0), "0 B");
}

#[test]
fn human_bytes_sub_kilobyte() {
    assert_eq!(widgets::human_bytes(1), "1 B");
    assert_eq!(widgets::human_bytes(512), "512 B");
    assert_eq!(widgets::human_bytes(1023), "1023 B");
}

#[test]
fn human_bytes_exact_boundaries() {
    assert_eq!(widgets::human_bytes(1024), "1.0 KB");
    assert_eq!(widgets::human_bytes(1_048_576), "1.0 MB");
    assert_eq!(widgets::human_bytes(1_073_741_824), "1.0 GB");
}

#[test]
fn human_bytes_fractional() {
    assert_eq!(widgets::human_bytes(1_536), "1.5 KB");
    assert_eq!(widgets::human_bytes(1_572_864), "1.5 MB");
}

#[test]
fn human_bytes_large_values() {
    // 100 GB
    let result = widgets::human_bytes(107_374_182_400);
    assert!(result.contains("GB"));
    // u64::MAX
    let result = widgets::human_bytes(u64::MAX);
    assert!(result.contains("GB"));
}

// ════════════════════════════════════════════════════════════
// § 8  WIDGETS: human_rate edge cases
// ════════════════════════════════════════════════════════════

#[test]
fn human_rate_zero() {
    let result = widgets::human_rate(0.0);
    assert!(
        result.contains("+0 B/s") || result.contains("+0.0"),
        "got: {result}"
    );
}

#[test]
fn human_rate_positive_small() {
    let result = widgets::human_rate(512.0);
    assert!(result.starts_with('+'));
    assert!(result.contains("512"));
    assert!(result.contains("B/s"));
}

#[test]
fn human_rate_negative() {
    let result = widgets::human_rate(-2048.0);
    assert!(result.starts_with('-'));
    assert!(result.contains("KB/s"));
}

#[test]
fn human_rate_kilobyte_boundary() {
    let result = widgets::human_rate(1024.0);
    assert!(result.contains("KB/s"));
}

#[test]
fn human_rate_megabyte_range() {
    let result = widgets::human_rate(5_242_880.0);
    assert!(result.contains("MB/s"));
}

#[test]
fn human_rate_negative_megabyte() {
    let result = widgets::human_rate(-10_485_760.0);
    assert!(result.starts_with('-'));
    assert!(result.contains("MB/s"));
}

// ════════════════════════════════════════════════════════════
// § 9  WIDGETS: trend_label boundary values
// ════════════════════════════════════════════════════════════

#[test]
fn trend_label_idle_at_zero() {
    assert_eq!(widgets::trend_label(0.0), "(idle)");
}

#[test]
fn trend_label_negative_below_threshold() {
    // Negative but > -1_000_000 → idle
    assert_eq!(widgets::trend_label(-500_000.0), "(idle)");
}

#[test]
fn trend_label_stable_positive_small() {
    assert_eq!(widgets::trend_label(100.0), "(stable)");
    assert_eq!(widgets::trend_label(999_999.0), "(stable)");
}

#[test]
fn trend_label_accelerating_above_million() {
    assert_eq!(widgets::trend_label(1_000_001.0), "(accelerating)");
    assert_eq!(widgets::trend_label(10_000_000.0), "(accelerating)");
}

#[test]
fn trend_label_recovering_below_neg_million() {
    assert_eq!(widgets::trend_label(-1_000_001.0), "(recovering)");
    assert_eq!(widgets::trend_label(-10_000_000.0), "(recovering)");
}

#[test]
fn trend_label_exact_thresholds() {
    // Exactly 1_000_000.0 → stable (> required, not >=)
    assert_eq!(widgets::trend_label(1_000_000.0), "(stable)");
    // Exactly -1_000_000.0 → idle (< required, not <=)
    assert_eq!(widgets::trend_label(-1_000_000.0), "(idle)");
}

// ════════════════════════════════════════════════════════════
// § 10  WIDGETS: human_duration edge cases
// ════════════════════════════════════════════════════════════

#[test]
fn human_duration_zero() {
    assert_eq!(widgets::human_duration(0), "0s");
}

#[test]
fn human_duration_seconds_only() {
    assert_eq!(widgets::human_duration(1), "1s");
    assert_eq!(widgets::human_duration(59), "59s");
}

#[test]
fn human_duration_minutes_boundary() {
    assert_eq!(widgets::human_duration(60), "1m 0s");
    assert_eq!(widgets::human_duration(61), "1m 1s");
    assert_eq!(widgets::human_duration(3599), "59m 59s");
}

#[test]
fn human_duration_hours_boundary() {
    assert_eq!(widgets::human_duration(3600), "1h 00m");
    assert_eq!(widgets::human_duration(3661), "1h 01m");
    assert_eq!(widgets::human_duration(7200), "2h 00m");
}

#[test]
fn human_duration_large_value() {
    let result = widgets::human_duration(86400);
    assert_eq!(result, "24h 00m");
}

// ════════════════════════════════════════════════════════════
// § 11  WIDGETS: extract_time edge cases
// ════════════════════════════════════════════════════════════

#[test]
fn extract_time_normal_iso() {
    assert_eq!(
        widgets::extract_time("2026-02-16T03:15:42.123Z"),
        "03:15:42"
    );
}

#[test]
fn extract_time_no_fractional_seconds() {
    assert_eq!(widgets::extract_time("2026-02-16T12:00:00Z"), "12:00:00Z");
}

#[test]
fn extract_time_no_t_separator() {
    // Falls back to using the whole string, then splits on '.'
    let result = widgets::extract_time("no-t-here");
    assert_eq!(result, "no-t-here");
}

#[test]
fn extract_time_empty_string() {
    assert_eq!(widgets::extract_time(""), "");
}

#[test]
fn extract_time_only_date() {
    // "2026-02-16T" → time part is empty → returns ""
    assert_eq!(widgets::extract_time("2026-02-16T"), "");
}

// ════════════════════════════════════════════════════════════
// § 12  WIDGETS: section_header edge cases
// ════════════════════════════════════════════════════════════

#[test]
fn section_header_normal() {
    let hdr = widgets::section_header("Pressure", 40);
    assert!(hdr.starts_with("── Pressure "));
    assert!(hdr.contains('─'));
}

#[test]
fn section_header_narrow_width() {
    // Width smaller than title + decoration — saturating_sub means 0 repeats.
    let hdr = widgets::section_header("Very Long Title", 5);
    assert!(hdr.starts_with("── Very Long Title "));
}

#[test]
fn section_header_zero_width() {
    let hdr = widgets::section_header("Test", 0);
    assert!(hdr.starts_with("── Test "));
}

// ════════════════════════════════════════════════════════════
// § 13  WIDGETS: sparkline edge cases
// ════════════════════════════════════════════════════════════

#[test]
fn sparkline_empty_values() {
    assert_eq!(widgets::sparkline(&[]), "");
}

#[test]
fn sparkline_single_value() {
    let line = widgets::sparkline(&[0.5]);
    assert_eq!(line.chars().count(), 1);
}

#[test]
fn sparkline_all_zeros() {
    let line = widgets::sparkline(&[0.0, 0.0, 0.0]);
    assert_eq!(line.chars().count(), 3);
    for c in line.chars() {
        assert_eq!(c, '▁');
    }
}

#[test]
fn sparkline_all_ones() {
    let line = widgets::sparkline(&[1.0, 1.0, 1.0]);
    for c in line.chars() {
        assert_eq!(c, '█');
    }
}

#[test]
fn sparkline_nan_clamps_to_low() {
    let line = widgets::sparkline(&[f64::NAN]);
    // NaN.clamp(0.0, 1.0) returns NaN; NaN * 7.0 = NaN; NaN.round() = NaN;
    // NaN as usize = 0 on most platforms. The test verifies no panic.
    assert_eq!(line.chars().count(), 1);
}

// ════════════════════════════════════════════════════════════
// § 14  WIDGETS: gauge edge cases
// ════════════════════════════════════════════════════════════

#[test]
fn gauge_zero_percent() {
    let g = widgets::gauge(0.0, 10);
    assert!(g.contains("0%"));
    assert_eq!(g.matches('█').count(), 0);
}

#[test]
fn gauge_hundred_percent() {
    let g = widgets::gauge(100.0, 10);
    assert!(g.contains("100%"));
    assert_eq!(g.matches('█').count(), 10);
}

#[test]
fn gauge_over_hundred_clamps() {
    let g = widgets::gauge(200.0, 10);
    assert!(g.contains("100%"));
    assert_eq!(g.matches('█').count(), 10);
}

#[test]
fn gauge_negative_clamps() {
    let g = widgets::gauge(-50.0, 10);
    assert!(g.contains("0%"));
    assert_eq!(g.matches('█').count(), 0);
}

#[test]
fn gauge_width_zero() {
    let g = widgets::gauge(50.0, 0);
    // With width=0, no bars, just percentage.
    assert!(g.contains("50%"));
    assert!(g.contains("[]"));
}

#[test]
fn gauge_width_one() {
    let g = widgets::gauge(50.0, 1);
    // 50% of 1 = 0.5 → rounds to 1.
    assert!(g.contains("50%"));
}

// ════════════════════════════════════════════════════════════
// § 15  MODEL: RateHistory stats edge cases
// ════════════════════════════════════════════════════════════

#[test]
fn rate_history_stats_two_values() {
    let mut rh = RateHistory::new(10);
    rh.push(10.0);
    rh.push(20.0);
    // stats() returns (latest, avg, min, max)
    let (latest, avg, min, max) = rh.stats().expect("should have stats");
    assert!((latest - 20.0).abs() < f64::EPSILON);
    assert!((min - 10.0).abs() < f64::EPSILON);
    assert!((max - 20.0).abs() < f64::EPSILON);
    assert!((avg - 15.0).abs() < f64::EPSILON);
}

#[test]
fn rate_history_negative_values() {
    let mut rh = RateHistory::new(10);
    rh.push(-100.0);
    rh.push(100.0);
    let (latest, avg, min, max) = rh.stats().expect("should have stats");
    assert!((latest - 100.0).abs() < f64::EPSILON);
    assert!((min - (-100.0)).abs() < f64::EPSILON);
    assert!((max - 100.0).abs() < f64::EPSILON);
    assert!(avg.abs() < f64::EPSILON);
}

#[test]
fn rate_history_normalized_range() {
    let mut rh = RateHistory::new(5);
    rh.push(0.0);
    rh.push(50.0);
    rh.push(100.0);
    let norm = rh.normalized();
    assert_eq!(norm.len(), 3);
    // normalized uses midpoint(val/max_abs, 1.0):
    //   0/100 → midpoint(0.0, 1.0) = 0.5
    //   50/100 → midpoint(0.5, 1.0) = 0.75
    //   100/100 → midpoint(1.0, 1.0) = 1.0
    assert!((norm[0] - 0.5).abs() < 0.01);
    assert!((norm[1] - 0.75).abs() < 0.01);
    assert!((norm[2] - 1.0).abs() < 0.01);
}

// ════════════════════════════════════════════════════════════
// § 16  MODEL: Notification edge cases
// ════════════════════════════════════════════════════════════

#[test]
fn notification_expiry_targets_correct_id() {
    let mut model = test_model();
    let id1 = model.push_notification(NotificationLevel::Info, "first".into());
    let id2 = model.push_notification(NotificationLevel::Warning, "second".into());
    let id3 = model.push_notification(NotificationLevel::Error, "third".into());
    assert_eq!(model.notifications.len(), 3);

    // Expire the middle one.
    update::update(&mut model, DashboardMsg::NotificationExpired(id2));
    assert_eq!(model.notifications.len(), 2);
    assert!(model.notifications.iter().all(|n| n.id != id2));
    assert!(model.notifications.iter().any(|n| n.id == id1));
    assert!(model.notifications.iter().any(|n| n.id == id3));
}

#[test]
fn notification_ids_always_increase() {
    let mut model = test_model();
    let id1 = model.push_notification(NotificationLevel::Info, "a".into());
    let id2 = model.push_notification(NotificationLevel::Info, "b".into());
    let id3 = model.push_notification(NotificationLevel::Info, "c".into());
    assert!(id1 < id2);
    assert!(id2 < id3);
}

// ════════════════════════════════════════════════════════════
// § 17  MODEL: Navigation history edge cases
// ════════════════════════════════════════════════════════════

#[test]
fn navigate_back_returns_false_when_empty() {
    let mut model = test_model();
    assert!(!model.navigate_back());
}

#[test]
fn navigate_deep_history() {
    let mut model = test_model();
    let screens = [
        Screen::Timeline,
        Screen::Explainability,
        Screen::Candidates,
        Screen::Ballast,
        Screen::LogSearch,
        Screen::Diagnostics,
    ];
    for &s in &screens {
        model.navigate_to(s);
    }
    assert_eq!(model.screen_history.len(), 6);

    // Walk all the way back.
    for &expected in screens[..5].iter().rev() {
        assert!(model.navigate_back());
        assert_eq!(model.screen, expected);
    }
    assert!(model.navigate_back());
    assert_eq!(model.screen, Screen::Overview);
    assert!(!model.navigate_back());
}

// ════════════════════════════════════════════════════════════
// § 18  UPDATE: Multiple rapid data updates
// ════════════════════════════════════════════════════════════

#[test]
fn rapid_data_updates_track_counters_correctly() {
    use crate::daemon::self_monitor::{
        BallastState, Counters, DaemonState, LastScanState, MountPressure, PressureState,
    };

    let state = DaemonState {
        version: "0.1.0".into(),
        pid: 1,
        started_at: "2026-01-01T00:00:00Z".into(),
        uptime_seconds: 1,
        last_updated: "2026-01-01T00:00:01Z".into(),
        pressure: PressureState {
            overall: "green".into(),
            mounts: vec![MountPressure {
                path: "/".into(),
                free_pct: 80.0,
                level: "green".into(),
                rate_bps: Some(0.0),
            }],
        },
        ballast: BallastState {
            available: 5,
            total: 5,
            released: 0,
        },
        last_scan: LastScanState {
            at: None,
            candidates: 0,
            deleted: 0,
        },
        counters: Counters {
            scans: 0,
            deletions: 0,
            bytes_freed: 0,
            errors: 0,
            dropped_log_events: 0,
        },
        memory_rss_bytes: 0,
    };

    let mut model = test_model();
    for i in 0..100 {
        if i % 3 == 0 {
            update::update(&mut model, DashboardMsg::DataUpdate(None));
        } else {
            update::update(
                &mut model,
                DashboardMsg::DataUpdate(Some(Box::new(state.clone()))),
            );
        }
    }
    assert_eq!(model.adapter_reads, 66); // 100 - 34 errors
    assert_eq!(model.adapter_errors, 34); // 0, 3, 6, ... 99 = 34 values
}

// ════════════════════════════════════════════════════════════
// § 19  UPDATE: Frame metrics ring buffer stress
// ════════════════════════════════════════════════════════════

#[test]
fn frame_metrics_ring_buffer_overflow() {
    let mut model = test_model();
    // Push 200 frame metrics (capacity is 60).
    for i in 0..200 {
        update::update(
            &mut model,
            DashboardMsg::FrameMetrics {
                duration_ms: f64::from(i),
            },
        );
    }
    // Should be capped at capacity.
    assert!(model.frame_times.len() <= 60);
    // Latest should be the last value pushed.
    assert_eq!(model.frame_times.latest(), Some(199.0));
}

// ════════════════════════════════════════════════════════════
// § 20  INPUT: Global key edge cases
// ════════════════════════════════════════════════════════════

#[test]
fn key_event_with_release_kind_still_resolves() {
    // KeyEventKind::Release events should still be processed by resolve_key_event.
    let release = KeyEvent {
        code: KeyCode::Char('q'),
        modifiers: Modifiers::NONE,
        kind: KeyEventKind::Release,
    };
    let ctx = InputContext::default();
    let res = input::resolve_key_event(&release, ctx);
    // The input layer doesn't filter by kind — it resolves based on code.
    assert_eq!(res.action, Some(InputAction::Quit));
}

#[test]
fn unmapped_key_on_overview_is_passthrough() {
    let ctx = InputContext {
        screen: Screen::Overview,
        active_overlay: None,
    };
    let res = input::resolve_key_event(&make_key(KeyCode::Char('x')), ctx);
    assert!(!res.consumed);
    assert!(res.action.is_none());
}

#[test]
fn screen_from_number_0_and_8_return_none() {
    assert!(Screen::from_number(0).is_none());
    assert!(Screen::from_number(8).is_none());
    assert!(Screen::from_number(255).is_none());
}

// ════════════════════════════════════════════════════════════
// § 21  UPDATE: Determinism — same messages, same output
// ════════════════════════════════════════════════════════════

#[test]
fn deterministic_telemetry_sequence() {
    let build = |model: &mut DashboardModel| {
        update::update(model, DashboardMsg::Tick);
        update::update(model, DashboardMsg::Key(make_key(KeyCode::Char('2'))));
        update::update(
            model,
            DashboardMsg::TelemetryBallast(TelemetryResult {
                data: vec![sample_volume("/", 3, 5)],
                source: DataSource::Sqlite,
                partial: false,
                diagnostics: String::new(),
            }),
        );
        update::update(model, DashboardMsg::Key(make_key(KeyCode::Char('5'))));
        update::update(model, DashboardMsg::FrameMetrics { duration_ms: 16.0 });
    };

    let mut m1 = test_model();
    let mut m2 = test_model();
    build(&mut m1);
    build(&mut m2);

    assert_eq!(m1.screen, m2.screen);
    assert_eq!(m1.tick, m2.tick);
    assert_eq!(m1.ballast_volumes, m2.ballast_volumes);
    assert_eq!(m1.ballast_source, m2.ballast_source);
    assert_eq!(m1.frame_times.len(), m2.frame_times.len());
}

// ════════════════════════════════════════════════════════════
// § 22  UPDATE: Resize edge cases
// ════════════════════════════════════════════════════════════

#[test]
fn resize_to_extreme_dimensions() {
    let mut model = test_model();

    // Very small.
    update::update(&mut model, DashboardMsg::Resize { cols: 1, rows: 1 });
    assert_eq!(model.terminal_size, (1, 1));

    // Very large.
    update::update(
        &mut model,
        DashboardMsg::Resize {
            cols: 1000,
            rows: 500,
        },
    );
    assert_eq!(model.terminal_size, (1000, 500));
}

// ════════════════════════════════════════════════════════════
// § 23  MODEL: Ballast model edge cases
// ════════════════════════════════════════════════════════════

#[test]
fn ballast_cursor_on_empty_volumes() {
    let mut model = test_model();
    assert!(model.ballast_volumes.is_empty());
    // Cursor ops on empty list should be no-ops.
    assert!(!model.ballast_cursor_down());
    assert!(!model.ballast_cursor_up());
    assert!(model.ballast_selected_volume().is_none());
}

#[test]
fn ballast_cursor_single_volume() {
    let mut model = test_model();
    model.ballast_volumes = vec![sample_volume("/", 3, 5)];
    assert_eq!(model.ballast_selected, 0);

    // Can't move further in either direction.
    assert!(!model.ballast_cursor_down());
    assert!(!model.ballast_cursor_up());
    assert!(model.ballast_selected_volume().is_some());
    assert_eq!(model.ballast_selected_volume().unwrap().mount_point, "/");
}

#[test]
fn ballast_detail_toggle_idempotent() {
    let mut model = test_model();
    assert!(!model.ballast_detail);
    model.ballast_toggle_detail();
    assert!(model.ballast_detail);
    model.ballast_toggle_detail();
    assert!(!model.ballast_detail);
}

#[test]
fn ballast_volume_status_levels_comprehensive() {
    let critical = BallastVolume {
        files_available: 0,
        files_total: 5,
        skipped: false,
        ..sample_volume("/", 0, 5)
    };
    let healthy = sample_volume("/data", 5, 5);
    let partial = sample_volume("/home", 2, 5);
    let skipped = skipped_volume("/tmp", "tmpfs unsupported");

    assert_eq!(critical.status_level(), "CRITICAL");
    assert_eq!(healthy.status_level(), "OK");
    assert_eq!(partial.status_level(), "LOW");
    assert_eq!(skipped.status_level(), "SKIPPED");
}

// ════════════════════════════════════════════════════════════
// § 24  INPUT: Command palette catalog completeness
// ════════════════════════════════════════════════════════════

#[test]
fn palette_covers_all_screens() {
    let actions = input::command_palette_actions();
    for screen_num in 1u8..=7 {
        let screen = Screen::from_number(screen_num).unwrap();
        let has_nav = actions
            .iter()
            .any(|a| a.action == InputAction::Navigate(screen));
        assert!(has_nav, "palette should have Navigate({screen:?}) action");
    }
}

#[test]
fn palette_resolve_all_ids() {
    let actions = input::command_palette_actions();
    for a in actions {
        let resolved = input::resolve_palette_action(a.id);
        assert!(
            resolved.is_some(),
            "palette action '{}' should resolve",
            a.id
        );
        assert_eq!(resolved.unwrap(), a.action);
    }
}

#[test]
fn palette_search_limit_zero_returns_empty() {
    let results = input::search_palette_actions("nav", 0);
    assert!(results.is_empty());
}

#[test]
fn palette_search_limit_exceeds_catalog_returns_all_matches() {
    let results = input::search_palette_actions("nav", 1000);
    // All 9 nav actions should match.
    assert!(results.len() >= 9);
}

#[test]
fn palette_includes_preference_controls() {
    let actions = input::command_palette_actions();
    for id in [
        "pref.start.overview",
        "pref.start.remember",
        "pref.density.compact",
        "pref.density.comfortable",
        "pref.hints.full",
        "pref.hints.off",
        "pref.reset.persisted",
        "pref.reset.defaults",
    ] {
        assert!(
            actions.iter().any(|entry| entry.id == id),
            "missing preference action id: {id}"
        );
    }
}

#[test]
fn palette_preference_lookup_is_deterministic() {
    let first = input::search_palette_actions("pref.density", 5);
    let second = input::search_palette_actions("pref.density", 5);
    let first_ids: Vec<&str> = first.iter().map(|entry| entry.id).collect();
    let second_ids: Vec<&str> = second.iter().map(|entry| entry.id).collect();
    assert_eq!(first_ids, second_ids);
}
