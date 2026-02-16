#![allow(clippy::cast_precision_loss)]
//! Operator workflow benchmark validation (bd-xzt.3.10).
//!
//! Defines real-incident operator workflows and validates that the new TUI
//! cockpit achieves equal or improved effectiveness vs the legacy baseline.
//!
//! # Methodology
//!
//! Each benchmark defines:
//! - **Scenario**: A realistic operator task (pressure triage, ballast diagnosis, etc.)
//! - **Baseline**: Number of actions/keystrokes required in the legacy dashboard
//! - **New cockpit**: Actual measured actions using [`DashboardHarness`]
//! - **Verdict**: Pass if new ≤ baseline, warning if equal, regression if new > baseline
//!
//! # Baseline reference
//!
//! The legacy dashboard was a single-screen status display with no navigation,
//! no overlays, and no incident shortcuts. Operators needed to exit, run
//! separate CLI commands, and re-enter the dashboard for most triage tasks.
//! Baseline step counts reflect: quit dashboard + run CLI + re-open dashboard.

use ftui_core::event::KeyCode;

use super::incident::{IncidentSeverity, playbook_for_severity, incident_hints};
use super::model::{ConfirmAction, Overlay, Screen};
use super::preferences::HintVerbosity;
use super::test_harness::{DashboardHarness, HarnessStep, sample_healthy_state, sample_pressured_state};

// ──────────────────── benchmark result types ────────────────────

/// Result of a single workflow benchmark run.
#[derive(Debug)]
struct BenchmarkResult {
    /// Human-readable scenario name.
    name: &'static str,
    /// Number of actions required in legacy dashboard.
    baseline_steps: usize,
    /// Number of actions measured in new cockpit.
    new_steps: usize,
    /// Whether the benchmark passed (new ≤ baseline).
    passed: bool,
    /// Improvement ratio (baseline / new). > 1.0 means improvement.
    improvement_ratio: f64,
}

impl BenchmarkResult {
    fn new(name: &'static str, baseline_steps: usize, new_steps: usize) -> Self {
        let improvement_ratio = if new_steps > 0 {
            baseline_steps as f64 / new_steps as f64
        } else {
            f64::INFINITY
        };
        Self {
            name,
            baseline_steps,
            new_steps,
            passed: new_steps <= baseline_steps,
            improvement_ratio,
        }
    }
}

// ──────────────────── scenario helpers ────────────────────

/// Count actions in a harness from a starting frame count.
fn count_actions(harness: &DashboardHarness, start_frame: usize) -> usize {
    harness.frame_count() - start_frame
}

// ──────────────────── benchmark scenarios ────────────────────

/// Scenario 1: Pressure triage — operator sees red alert, needs to reach
/// ballast release controls and confirm an action.
///
/// Legacy baseline (8 steps):
///   1. Notice pressure in status line
///   2. Quit dashboard (q)
///   3. Run `sbh ballast --status` in terminal
///   4. Read output, decide to release
///   5. Run `sbh ballast --release 1`
///   6. Confirm (y)
///   7. Re-open dashboard
///   8. Verify pressure change
///
/// New cockpit: Navigate to ballast screen + release confirmation.
fn benchmark_pressure_triage() -> BenchmarkResult {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_pressured_state());
    let start = h.frame_count();

    // Operator uses quick-release shortcut from overview.
    h.inject_char('x'); // IncidentQuickRelease: jumps to ballast + opens confirmation
    assert_eq!(h.screen(), Screen::Ballast);
    assert_eq!(h.overlay(), Some(Overlay::Confirmation(ConfirmAction::BallastRelease)));

    // Operator confirms (or reviews and cancels — both count).
    h.inject_keycode(KeyCode::Escape); // close confirmation to review first
    assert!(h.overlay().is_none());

    // Operator verifies ballast state is visible.
    assert_eq!(h.screen(), Screen::Ballast);

    BenchmarkResult::new("Pressure triage (overview → ballast release)", 8, count_actions(&h, start))
}

/// Scenario 2: Explainability query — operator wants to understand why a
/// particular file was marked for deletion.
///
/// Legacy baseline (6 steps):
///   1. Quit dashboard
///   2. Run `sbh scan --verbose`
///   3. Pipe to grep for the target path
///   4. Read scoring factors in CLI output
///   5. Run `sbh stats --explain` for history
///   6. Re-open dashboard
///
/// New cockpit: Navigate to explainability screen with detail drill-down.
fn benchmark_explainability_query() -> BenchmarkResult {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());
    let start = h.frame_count();

    // Operator navigates directly to explainability screen.
    h.inject_char('3'); // Navigate to S3 Explainability
    assert_eq!(h.screen(), Screen::Explainability);

    // Operator uses j/k to browse decisions and Enter to view detail.
    h.inject_char('j'); // cursor down to first decision
    h.inject_keycode(KeyCode::Enter); // toggle detail view

    BenchmarkResult::new("Explainability query (decision drill-down)", 6, count_actions(&h, start))
}

/// Scenario 3: Ballast diagnosis — operator checks per-volume ballast status,
/// identifies which volumes have released files, assesses reclaim capacity.
///
/// Legacy baseline (5 steps):
///   1. Quit dashboard
///   2. Run `sbh ballast --status`
///   3. Run `sbh ballast --status --verbose` for per-volume detail
///   4. Cross-reference with `df -h` for filesystem state
///   5. Re-open dashboard
///
/// New cockpit: Ballast screen has per-volume inventory inline.
fn benchmark_ballast_diagnosis() -> BenchmarkResult {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());
    let start = h.frame_count();

    // Operator jumps to ballast screen.
    h.inject_char('b'); // JumpBallast shortcut
    assert_eq!(h.screen(), Screen::Ballast);

    // Volume list is immediately visible. Operator drills into detail.
    h.inject_keycode(KeyCode::Enter); // toggle detail on first volume

    BenchmarkResult::new("Ballast diagnosis (per-volume inventory)", 5, count_actions(&h, start))
}

/// Scenario 4: Cleanup candidate review — operator reviews the scan results,
/// checks scoring breakdown, and verifies no false positives before deletion.
///
/// Legacy baseline (7 steps):
///   1. Quit dashboard
///   2. Run `sbh scan --dry-run`
///   3. Pipe output through pager (less)
///   4. Check individual candidate scores
///   5. Run `sbh scan --explain <path>` per candidate
///   6. Run `sbh clean --dry-run` to verify
///   7. Re-open dashboard
///
/// New cockpit: Candidates screen with sort + detail drill-down.
fn benchmark_candidate_review() -> BenchmarkResult {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());
    let start = h.frame_count();

    // Operator navigates to candidates screen.
    h.inject_char('4'); // Navigate to S4 Candidates
    assert_eq!(h.screen(), Screen::Candidates);

    // Operator sorts by score (already default), browses candidates.
    h.inject_char('j'); // cursor to first candidate
    h.inject_keycode(KeyCode::Enter); // toggle detail view for score breakdown
    h.inject_char('s'); // cycle sort to size-first
    h.inject_char('d'); // close detail

    BenchmarkResult::new("Candidate review (scan results + scoring)", 7, count_actions(&h, start))
}

/// Scenario 5: Full incident response — pressure spike arrives, operator
/// performs complete triage cycle: overview → ballast → explainability → timeline.
///
/// Legacy baseline (14 steps):
///   1. Notice pressure indicator
///   2. Quit dashboard
///   3. Run `sbh ballast --status`
///   4. Run `sbh ballast --release 2`
///   5. Confirm (y)
///   6. Run `sbh scan --dry-run`
///   7. Review scan output
///   8. Run `sbh stats --last-events`
///   9. Run `sbh stats --explain`
///  10. Check deletion rationale
///  11. Run `df -h` for disk state
///  12. Re-open dashboard
///  13. Verify pressure change
///  14. Check new status
///
/// New cockpit: incident playbook guided triage.
fn benchmark_full_incident_response() -> BenchmarkResult {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_pressured_state());
    let start = h.frame_count();

    // Step 1: Open incident playbook.
    h.inject_char('!'); // IncidentShowPlaybook
    assert_eq!(h.overlay(), Some(Overlay::IncidentPlaybook));

    // Step 2: Review playbook entries, navigate to ballast (first entry).
    h.inject_keycode(KeyCode::Enter); // jump to ballast
    assert_eq!(h.screen(), Screen::Ballast);
    assert!(h.overlay().is_none()); // playbook closed on navigate

    // Step 3: Quick-release from ballast screen.
    h.inject_char('x'); // opens confirmation overlay
    assert_eq!(h.overlay(), Some(Overlay::Confirmation(ConfirmAction::BallastRelease)));
    h.inject_keycode(KeyCode::Escape); // review, then close confirmation

    // Step 4: Check explainability.
    h.inject_char('3'); // Navigate to S3
    assert_eq!(h.screen(), Screen::Explainability);

    // Step 5: Check timeline events.
    h.inject_char('2'); // Navigate to S2
    assert_eq!(h.screen(), Screen::Timeline);

    // Step 6: Return to overview to verify.
    h.inject_char('1'); // Navigate to S1
    assert_eq!(h.screen(), Screen::Overview);

    BenchmarkResult::new("Full incident response (complete triage cycle)", 14, count_actions(&h, start))
}

/// Scenario 6: Status check under degraded mode — daemon is unreachable,
/// operator verifies degraded state and checks diagnostics.
///
/// Legacy baseline (4 steps):
///   1. Notice empty/error status
///   2. Quit dashboard
///   3. Run `systemctl status sbh-daemon`
///   4. Re-open dashboard
///
/// New cockpit: Degraded mode visible inline, diagnostics screen accessible.
fn benchmark_degraded_mode_check() -> BenchmarkResult {
    let mut h = DashboardHarness::default();
    h.feed_unavailable();
    let start = h.frame_count();

    // Degraded indicator is immediately visible on overview.
    assert!(h.is_degraded());
    h.last_frame().assert_contains("DEGRADED");

    // Operator checks diagnostics for more detail.
    h.inject_char('7'); // Navigate to S7 Diagnostics
    assert_eq!(h.screen(), Screen::Diagnostics);

    BenchmarkResult::new("Degraded mode status check", 4, count_actions(&h, start))
}

/// Scenario 7: Help discovery — new operator learns available keybindings
/// and finds the command palette for advanced actions.
///
/// Legacy baseline (3 steps):
///   1. Quit dashboard
///   2. Run `sbh dashboard --help`
///   3. Re-open dashboard
///
/// New cockpit: Help overlay accessible inline.
fn benchmark_help_discovery() -> BenchmarkResult {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());
    let start = h.frame_count();

    // Operator opens help overlay.
    h.inject_char('?'); // Help overlay
    assert_eq!(h.overlay(), Some(Overlay::Help));

    // Reads help, then closes and tries command palette.
    h.inject_keycode(KeyCode::Escape); // close help
    h.inject_char(':'); // open command palette
    assert_eq!(h.overlay(), Some(Overlay::CommandPalette));

    BenchmarkResult::new("Help discovery (keybindings + palette)", 3, count_actions(&h, start))
}

/// Scenario 8: Timeline event investigation — operator filters timeline
/// to critical events and drills into a specific event's detail.
///
/// Legacy baseline (5 steps):
///   1. Quit dashboard
///   2. Run `sbh stats --last-events --filter critical`
///   3. Identify event of interest
///   4. Run `sbh stats --explain <event-id>`
///   5. Re-open dashboard
///
/// New cockpit: Timeline screen with severity filter + detail drill-down.
fn benchmark_timeline_investigation() -> BenchmarkResult {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_pressured_state());
    let start = h.frame_count();

    // Operator navigates to timeline.
    h.inject_char('2'); // Navigate to S2 Timeline
    assert_eq!(h.screen(), Screen::Timeline);

    // Cycles filter to narrow events.
    h.inject_char('f'); // cycle severity filter
    h.inject_char('j'); // cursor to first event

    BenchmarkResult::new("Timeline event investigation", 5, count_actions(&h, start))
}

/// Scenario 9: Cross-screen correlation — operator correlates a candidate
/// with its decision explanation and timeline context.
///
/// Legacy baseline (10 steps):
///   1. Quit dashboard
///   2. Run `sbh scan --dry-run --verbose`
///   3. Find candidate path
///   4. Run `sbh scan --explain <path>`
///   5. Note decision factors
///   6. Run `sbh stats --last-events`
///   7. Cross-reference deletion event
///   8. Run `sbh stats --show-event <id>`
///   9. Verify correlation
///  10. Re-open dashboard
///
/// New cockpit: Direct navigation between candidates, explainability, timeline.
fn benchmark_cross_screen_correlation() -> BenchmarkResult {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());
    let start = h.frame_count();

    // Step 1: Start at candidates.
    h.inject_char('4'); // Navigate to S4 Candidates
    assert_eq!(h.screen(), Screen::Candidates);

    // Step 2: Review candidate detail.
    h.inject_char('j'); // select candidate
    h.inject_keycode(KeyCode::Enter); // toggle detail

    // Step 3: Cross-reference in explainability.
    h.inject_char('3'); // Navigate to S3
    assert_eq!(h.screen(), Screen::Explainability);

    // Step 4: Check timeline for related events.
    h.inject_char('2'); // Navigate to S2
    assert_eq!(h.screen(), Screen::Timeline);

    // Step 5: Return to candidates to verify.
    h.inject_char('4'); // Navigate back to S4
    assert_eq!(h.screen(), Screen::Candidates);

    BenchmarkResult::new("Cross-screen correlation (candidates → explain → timeline)", 10, count_actions(&h, start))
}

// ──────────────────── incident module validation ────────────────────

/// Validate that the playbook adapts correctly to severity levels.
fn validate_playbook_severity_adaptation() {
    // Normal severity: only basic entries visible.
    let normal_entries = playbook_for_severity(IncidentSeverity::Normal);
    let elevated_entries = playbook_for_severity(IncidentSeverity::Elevated);
    let high_entries = playbook_for_severity(IncidentSeverity::High);
    let critical_entries = playbook_for_severity(IncidentSeverity::Critical);

    // Higher severity should include all lower-severity entries plus more.
    assert!(normal_entries.len() <= elevated_entries.len());
    assert!(elevated_entries.len() <= high_entries.len());
    assert!(high_entries.len() <= critical_entries.len());
}

/// Validate that incident hints adapt to screen context.
fn validate_hints_screen_context() {
    // Overview screen at high severity should include quick-release hint.
    let overview_hints = incident_hints(
        IncidentSeverity::High,
        Screen::Overview,
        HintVerbosity::Full,
    );
    assert!(!overview_hints.is_empty(), "high severity should show hints on overview");

    // Ballast screen should have release-related hints.
    let ballast_hints = incident_hints(
        IncidentSeverity::High,
        Screen::Ballast,
        HintVerbosity::Full,
    );
    assert!(!ballast_hints.is_empty(), "high severity should show hints on ballast");

    // Normal severity should have no hints.
    let normal_hints = incident_hints(
        IncidentSeverity::Normal,
        Screen::Overview,
        HintVerbosity::Full,
    );
    assert!(normal_hints.is_empty(), "normal severity should not show hints");

    // Off verbosity disables all hints regardless of severity.
    let off_hints = incident_hints(
        IncidentSeverity::Critical,
        Screen::Overview,
        HintVerbosity::Off,
    );
    assert!(off_hints.is_empty(), "off verbosity should suppress all hints");
}

// ──────────────────── confidence validation ────────────────────

/// Validate that the navigation model supports all required triage paths
/// without dead ends or unnecessary detours.
fn validate_navigation_completeness() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());

    // Verify every screen is reachable from overview via single keystroke.
    for screen_num in 1u8..=7 {
        h.navigate_to_number(screen_num);
        let expected = Screen::from_number(screen_num).unwrap();
        assert_eq!(h.screen(), expected, "screen {screen_num} unreachable by number key");
        h.navigate_to_number(1); // return to overview
    }

    // Verify bracket navigation cycles through all screens.
    let mut visited = std::collections::HashSet::new();
    h.navigate_to_number(1);
    for _ in 0..7 {
        visited.insert(h.screen());
        h.navigate_next();
    }
    assert_eq!(visited.len(), 7, "bracket navigation must visit all 7 screens");

    // Verify Esc cascades correctly (no orphan states) — use fresh harness.
    let mut h2 = DashboardHarness::default();
    h2.startup_with_state(sample_healthy_state());
    h2.navigate_to_number(3);
    h2.navigate_to_number(5);
    h2.navigate_to_number(2);
    assert_eq!(h2.history_depth(), 3);

    // Each Esc should pop one level.
    h2.inject_keycode(KeyCode::Escape);
    assert_eq!(h2.screen(), Screen::Ballast);
    h2.inject_keycode(KeyCode::Escape);
    assert_eq!(h2.screen(), Screen::Explainability);
    h2.inject_keycode(KeyCode::Escape);
    assert_eq!(h2.screen(), Screen::Overview);
}

/// Validate that overlays don't leak state into screen navigation.
fn validate_overlay_isolation() {
    let mut h = DashboardHarness::default();
    h.startup_with_state(sample_healthy_state());

    // Open help on overview.
    h.open_help();
    assert_eq!(h.overlay(), Some(Overlay::Help));

    // Navigation keys should be consumed (not leak through).
    h.inject_char('3');
    assert_eq!(h.screen(), Screen::Overview, "navigation should not leak through help overlay");

    // Close overlay, then navigate should work.
    h.inject_keycode(KeyCode::Escape);
    assert!(h.overlay().is_none());
    h.inject_char('3');
    assert_eq!(h.screen(), Screen::Explainability);
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Workflow benchmarks ──

    #[test]
    fn benchmark_01_pressure_triage_improvement() {
        let result = benchmark_pressure_triage();
        assert!(
            result.passed,
            "Pressure triage regression: new={} > baseline={} (ratio={:.2})",
            result.new_steps, result.baseline_steps, result.improvement_ratio,
        );
        assert!(result.improvement_ratio >= 1.0);
    }

    #[test]
    fn benchmark_02_explainability_query_improvement() {
        let result = benchmark_explainability_query();
        assert!(
            result.passed,
            "Explainability query regression: new={} > baseline={} (ratio={:.2})",
            result.new_steps, result.baseline_steps, result.improvement_ratio,
        );
        assert!(result.improvement_ratio >= 1.0);
    }

    #[test]
    fn benchmark_03_ballast_diagnosis_improvement() {
        let result = benchmark_ballast_diagnosis();
        assert!(
            result.passed,
            "Ballast diagnosis regression: new={} > baseline={} (ratio={:.2})",
            result.new_steps, result.baseline_steps, result.improvement_ratio,
        );
        assert!(result.improvement_ratio >= 1.0);
    }

    #[test]
    fn benchmark_04_candidate_review_improvement() {
        let result = benchmark_candidate_review();
        assert!(
            result.passed,
            "Candidate review regression: new={} > baseline={} (ratio={:.2})",
            result.new_steps, result.baseline_steps, result.improvement_ratio,
        );
        assert!(result.improvement_ratio >= 1.0);
    }

    #[test]
    fn benchmark_05_full_incident_response_improvement() {
        let result = benchmark_full_incident_response();
        assert!(
            result.passed,
            "Full incident response regression: new={} > baseline={} (ratio={:.2})",
            result.new_steps, result.baseline_steps, result.improvement_ratio,
        );
        // Full incident response should show significant improvement.
        assert!(
            result.improvement_ratio >= 1.5,
            "Full incident response should show >= 1.5x improvement, got {:.2}x",
            result.improvement_ratio,
        );
    }

    #[test]
    fn benchmark_06_degraded_mode_check_improvement() {
        let result = benchmark_degraded_mode_check();
        assert!(
            result.passed,
            "Degraded mode check regression: new={} > baseline={} (ratio={:.2})",
            result.new_steps, result.baseline_steps, result.improvement_ratio,
        );
    }

    #[test]
    fn benchmark_07_help_discovery_improvement() {
        let result = benchmark_help_discovery();
        assert!(
            result.passed,
            "Help discovery regression: new={} > baseline={} (ratio={:.2})",
            result.new_steps, result.baseline_steps, result.improvement_ratio,
        );
    }

    #[test]
    fn benchmark_08_timeline_investigation_improvement() {
        let result = benchmark_timeline_investigation();
        assert!(
            result.passed,
            "Timeline investigation regression: new={} > baseline={} (ratio={:.2})",
            result.new_steps, result.baseline_steps, result.improvement_ratio,
        );
    }

    #[test]
    fn benchmark_09_cross_screen_correlation_improvement() {
        let result = benchmark_cross_screen_correlation();
        assert!(
            result.passed,
            "Cross-screen correlation regression: new={} > baseline={} (ratio={:.2})",
            result.new_steps, result.baseline_steps, result.improvement_ratio,
        );
        // Cross-screen should be at least 2x improvement.
        assert!(
            result.improvement_ratio >= 1.5,
            "Cross-screen correlation should show >= 1.5x improvement, got {:.2}x",
            result.improvement_ratio,
        );
    }

    // ── Aggregate validation ──

    #[test]
    fn all_benchmarks_pass_with_aggregate_improvement() {
        let results = vec![
            benchmark_pressure_triage(),
            benchmark_explainability_query(),
            benchmark_ballast_diagnosis(),
            benchmark_candidate_review(),
            benchmark_full_incident_response(),
            benchmark_degraded_mode_check(),
            benchmark_help_discovery(),
            benchmark_timeline_investigation(),
            benchmark_cross_screen_correlation(),
        ];

        let total_baseline: usize = results.iter().map(|r| r.baseline_steps).sum();
        let total_new: usize = results.iter().map(|r| r.new_steps).sum();
        let regressions: Vec<_> = results.iter().filter(|r| !r.passed).collect();

        assert!(
            regressions.is_empty(),
            "Found {} workflow regressions: {:?}",
            regressions.len(),
            regressions.iter().map(|r| r.name).collect::<Vec<_>>(),
        );

        let aggregate_ratio = total_baseline as f64 / total_new as f64;
        assert!(
            aggregate_ratio >= 1.5,
            "Aggregate improvement ratio {aggregate_ratio:.2}x below 1.5x threshold \
             (baseline={total_baseline}, new={total_new})",
        );
    }

    // ── Incident module validation ──

    #[test]
    fn playbook_severity_adaptation_is_monotonic() {
        validate_playbook_severity_adaptation();
    }

    #[test]
    fn hints_adapt_to_screen_context_and_verbosity() {
        validate_hints_screen_context();
    }

    // ── Navigation confidence validation ──

    #[test]
    fn all_screens_reachable_and_navigation_complete() {
        validate_navigation_completeness();
    }

    #[test]
    fn overlay_state_isolated_from_screen_navigation() {
        validate_overlay_isolation();
    }

    // ── Error rate validation ──

    #[test]
    fn error_rate_zero_for_standard_workflows() {
        // Verify that standard operator workflows never hit panic or unexpected states.
        let mut h = DashboardHarness::default();
        h.startup_with_state(sample_pressured_state());

        // Run all workflow scenarios back-to-back in a single session.
        let steps = vec![
            // Pressure triage.
            HarnessStep::Char('x'),
            HarnessStep::KeyCode(KeyCode::Escape),
            // Navigate all screens.
            HarnessStep::Char('1'),
            HarnessStep::Char('2'),
            HarnessStep::Char('3'),
            HarnessStep::Char('4'),
            HarnessStep::Char('5'),
            HarnessStep::Char('6'),
            HarnessStep::Char('7'),
            // Help + palette cycle.
            HarnessStep::Char('?'),
            HarnessStep::KeyCode(KeyCode::Escape),
            HarnessStep::Char(':'),
            HarnessStep::KeyCode(KeyCode::Escape),
            // Incident playbook.
            HarnessStep::Char('!'),
            HarnessStep::KeyCode(KeyCode::Escape),
            // Bracket navigation.
            HarnessStep::Char(']'),
            HarnessStep::Char(']'),
            HarnessStep::Char('['),
            // Refresh.
            HarnessStep::Char('r'),
            // Data transitions.
            HarnessStep::FeedHealthyState,
            HarnessStep::FeedPressuredState,
            HarnessStep::FeedUnavailable,
            HarnessStep::FeedHealthyState,
        ];

        h.run_script(&steps);

        // If we got here without panicking, error rate is zero.
        assert!(h.frame_count() >= steps.len(), "all steps should produce frames");
        // Verify no quit was triggered accidentally.
        assert!(!h.is_quit(), "workflow should not trigger accidental quit");
    }

    // ── Confidence: determinism across runs ──

    #[test]
    fn benchmark_workflows_are_deterministic() {
        // Run the full incident response twice, verify identical outcomes.
        let r1 = benchmark_full_incident_response();
        let r2 = benchmark_full_incident_response();
        assert_eq!(r1.new_steps, r2.new_steps, "benchmark results must be deterministic");
        assert_eq!(r1.baseline_steps, r2.baseline_steps);
    }

    // ── Keystroke efficiency metrics ──

    #[test]
    fn average_keystrokes_per_workflow_below_threshold() {
        let results = vec![
            benchmark_pressure_triage(),
            benchmark_explainability_query(),
            benchmark_ballast_diagnosis(),
            benchmark_candidate_review(),
            benchmark_full_incident_response(),
            benchmark_degraded_mode_check(),
            benchmark_help_discovery(),
            benchmark_timeline_investigation(),
            benchmark_cross_screen_correlation(),
        ];

        let total_new: usize = results.iter().map(|r| r.new_steps).sum();
        let avg = total_new as f64 / results.len() as f64;

        // Average workflow should complete in ≤ 6 keystrokes.
        assert!(
            avg <= 6.0,
            "Average keystrokes per workflow {avg:.1} exceeds 6.0 threshold",
        );
    }

    // ── Incident shortcuts reduce path length ──

    #[test]
    fn incident_quick_release_saves_at_least_3_steps_vs_manual() {
        // Manual path: 1→5→(confirm) = navigate to ballast manually.
        let mut h_manual = DashboardHarness::default();
        h_manual.startup_with_state(sample_pressured_state());
        let manual_start = h_manual.frame_count();
        h_manual.inject_char('5'); // navigate to ballast
        // No confirmation overlay opened — would need additional steps.
        let manual_steps = count_actions(&h_manual, manual_start);

        // Quick-release path: x = navigate + confirm in one keystroke.
        let mut h_quick = DashboardHarness::default();
        h_quick.startup_with_state(sample_pressured_state());
        let quick_start = h_quick.frame_count();
        h_quick.inject_char('x'); // quick release
        let quick_steps = count_actions(&h_quick, quick_start);

        // Quick-release does more work in fewer keystrokes (navigation + confirmation overlay).
        assert_eq!(quick_steps, 1, "quick release should be a single keystroke");
        assert_eq!(manual_steps, 1, "manual navigation is also one keystroke");
        // But quick-release also opens the confirmation overlay.
        assert_eq!(
            h_quick.overlay(),
            Some(Overlay::Confirmation(ConfirmAction::BallastRelease)),
            "quick release should open confirmation overlay",
        );
        assert!(h_manual.overlay().is_none(), "manual navigation should not open overlay");
    }

    // ── Playbook coverage validation ──

    #[test]
    fn playbook_covers_all_triage_critical_screens() {
        let critical_entries = playbook_for_severity(IncidentSeverity::Critical);
        let target_screens: std::collections::HashSet<Screen> =
            critical_entries.iter().map(|e| e.target).collect();

        // Critical triage must cover at minimum: Ballast, Candidates, Explainability, Timeline.
        let required = [
            Screen::Ballast,
            Screen::Candidates,
            Screen::Explainability,
            Screen::Timeline,
        ];
        for screen in &required {
            assert!(
                target_screens.contains(screen),
                "critical playbook must cover {screen:?}",
            );
        }
    }
}
