//! Incident workflow shortcuts for high-pressure scenarios (bd-xzt.3.9).
//!
//! Provides guided navigation shortcuts that reduce incident triage path length.
//! When disk pressure escalates, operators need minimal-latency access to:
//! - Ballast release controls (S5)
//! - Decision evidence / explainability (S3)
//! - Timeline event stream filtered to critical (S2)
//! - Candidate review for imminent deletions (S4)
//!
//! All shortcut actions are deterministic and keyboard-first. The feature can be
//! disabled via [`HintVerbosity::Off`] for operators who prefer a minimal dashboard.

use crate::daemon::self_monitor::DaemonState;
use crate::tui::model::Screen;
use crate::tui::preferences::HintVerbosity;

// ──────────────────── severity classification ────────────────────

/// Incident severity derived from daemon pressure state.
///
/// Maps the daemon's `pressure.overall` string to a structured enum for
/// deterministic branching in shortcut logic and hint rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IncidentSeverity {
    /// No pressure concern — normal operations.
    Normal,
    /// Moderate pressure detected — awareness recommended.
    Elevated,
    /// High pressure — active monitoring and preparation needed.
    High,
    /// Critical pressure — immediate action required.
    Critical,
}

impl IncidentSeverity {
    /// Classify from the daemon's `pressure.overall` string.
    ///
    /// Unknown strings map to `Normal` (fail-open for display purposes).
    #[must_use]
    pub fn from_pressure_level(level: &str) -> Self {
        match level.to_ascii_lowercase().as_str() {
            "critical" | "red" | "emergency" => Self::Critical,
            "high" | "orange" => Self::High,
            "elevated" | "yellow" | "warning" => Self::Elevated,
            _ => Self::Normal,
        }
    }

    /// Derive severity from a full daemon state snapshot.
    ///
    /// Returns `Normal` when no state is available (degraded mode).
    #[must_use]
    pub fn from_daemon_state(state: Option<&DaemonState>) -> Self {
        state.map_or(Self::Normal, |s| Self::from_pressure_level(&s.pressure.overall))
    }

    /// Human-readable label for display.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Normal => "NORMAL",
            Self::Elevated => "ELEVATED",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }

    /// Whether this severity warrants showing incident hints.
    #[must_use]
    pub const fn shows_hints(self) -> bool {
        matches!(self, Self::Elevated | Self::High | Self::Critical)
    }

    /// Whether this severity warrants an alert banner.
    #[must_use]
    pub const fn shows_banner(self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }
}

// ──────────────────── playbook entries ────────────────────

/// A single step in the incident triage playbook.
///
/// Each entry describes what to check, where to navigate, and why it matters.
/// Entries are ordered by triage priority (most urgent first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaybookEntry {
    /// Short action label (e.g., "Release ballast").
    pub label: &'static str,
    /// Detailed description of what to check and why.
    pub description: &'static str,
    /// Target screen for this triage step.
    pub target: Screen,
    /// Keyboard shortcut hint (e.g., "x", "5", "2").
    pub shortcut_hint: &'static str,
    /// Minimum severity at which this entry is relevant.
    pub min_severity: IncidentSeverity,
}

/// Static incident playbook — ordered by triage urgency.
///
/// The playbook is deterministic and auditable: every entry maps to a concrete
/// screen and action. Operators can navigate the playbook with arrow keys and
/// press Enter to jump to the target screen.
pub const INCIDENT_PLAYBOOK: &[PlaybookEntry] = &[
    PlaybookEntry {
        label: "Release ballast",
        description: "Free disk space immediately by releasing pre-allocated ballast files. \
                       Check per-volume inventory and release from the most constrained mount.",
        target: Screen::Ballast,
        shortcut_hint: "x or 5",
        min_severity: IncidentSeverity::High,
    },
    PlaybookEntry {
        label: "Check pressure overview",
        description: "Review overall disk pressure, per-mount free percentages, and consumption \
                       rates. Identify which mounts are under pressure and trending.",
        target: Screen::Overview,
        shortcut_hint: "1",
        min_severity: IncidentSeverity::Elevated,
    },
    PlaybookEntry {
        label: "Review critical events",
        description: "Check the timeline for recent critical events: deletions, pressure changes, \
                       and error spikes. Filter to critical severity for fast triage.",
        target: Screen::Timeline,
        shortcut_hint: "2",
        min_severity: IncidentSeverity::Elevated,
    },
    PlaybookEntry {
        label: "Inspect deletion decisions",
        description: "Review recent deletion decisions and their rationale. Check for vetoes, \
                       policy overrides, and scoring factor breakdowns.",
        target: Screen::Explainability,
        shortcut_hint: "3",
        min_severity: IncidentSeverity::High,
    },
    PlaybookEntry {
        label: "Review pending candidates",
        description: "Examine the candidate queue for targets awaiting deletion. Verify scores, \
                       sizes, and reclaim potential before the next scan cycle.",
        target: Screen::Candidates,
        shortcut_hint: "4",
        min_severity: IncidentSeverity::High,
    },
    PlaybookEntry {
        label: "Check daemon health",
        description: "Verify daemon process health, thread status, memory usage, and error \
                       counters. Look for signs of starvation or degraded performance.",
        target: Screen::Diagnostics,
        shortcut_hint: "7",
        min_severity: IncidentSeverity::Elevated,
    },
    PlaybookEntry {
        label: "Search logs for errors",
        description: "Query JSONL/SQLite event logs for error patterns, failed deletions, \
                       or scanner stalls. Useful for post-incident root cause analysis.",
        target: Screen::LogSearch,
        shortcut_hint: "6",
        min_severity: IncidentSeverity::Elevated,
    },
];

/// Filter playbook entries to those relevant at the given severity.
#[must_use]
pub fn playbook_for_severity(severity: IncidentSeverity) -> Vec<&'static PlaybookEntry> {
    INCIDENT_PLAYBOOK
        .iter()
        .filter(|entry| entry.min_severity <= severity)
        .collect()
}

// ──────────────────── incident hints ────────────────────

/// A context-aware hint shown in the status bar or screen footer during incidents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentHint {
    /// Short hint text (e.g., "Press x to quick-release ballast").
    pub text: String,
    /// Keyboard shortcut referenced in the hint.
    pub shortcut: &'static str,
}

/// Generate incident-aware hints based on current severity and screen.
///
/// Returns an empty vec when:
/// - Severity is `Normal`
/// - Hint verbosity is `Off`
#[must_use]
pub fn incident_hints(
    severity: IncidentSeverity,
    screen: Screen,
    hint_verbosity: HintVerbosity,
) -> Vec<IncidentHint> {
    if hint_verbosity == HintVerbosity::Off || !severity.shows_hints() {
        return Vec::new();
    }

    let mut hints = Vec::new();

    // Always show playbook hint during incidents.
    hints.push(IncidentHint {
        text: format!("[!] Incident playbook ({} pressure)", severity.label()),
        shortcut: "!",
    });

    // Screen-specific hints.
    match screen {
        Screen::Overview => {
            if severity >= IncidentSeverity::High {
                hints.push(IncidentHint {
                    text: "[x] Quick-release ballast".to_string(),
                    shortcut: "x",
                });
            }
        }
        Screen::Ballast => {
            hints.push(IncidentHint {
                text: "[r] Release selected volume's ballast".to_string(),
                shortcut: "r",
            });
        }
        Screen::Timeline => {
            hints.push(IncidentHint {
                text: "[f] Filter to critical events only".to_string(),
                shortcut: "f",
            });
        }
        _ => {}
    }

    // Trim hints in minimal mode.
    if hint_verbosity == HintVerbosity::Minimal {
        hints.truncate(1);
    }

    hints
}

// ──────────────────── incident banner ────────────────────

/// Format an incident alert banner string for high/critical pressure.
///
/// Returns `None` when severity doesn't warrant a banner.
#[must_use]
pub fn incident_banner(severity: IncidentSeverity) -> Option<String> {
    if !severity.shows_banner() {
        return None;
    }

    let prefix = match severity {
        IncidentSeverity::Critical => "!! CRITICAL PRESSURE",
        IncidentSeverity::High => "! HIGH PRESSURE",
        _ => return None,
    };

    Some(format!("{prefix} — Press [!] for incident playbook, [x] to release ballast"))
}

// ──────────────────── feature gate ────────────────────

/// Check whether incident shortcuts should be active.
///
/// Incident shortcuts are enabled by default and only suppressed when the
/// operator has explicitly set hint verbosity to Off.
#[must_use]
pub const fn shortcuts_enabled(hint_verbosity: HintVerbosity) -> bool {
    !matches!(hint_verbosity, HintVerbosity::Off)
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── IncidentSeverity ──

    #[test]
    fn severity_from_pressure_level_known_values() {
        assert_eq!(
            IncidentSeverity::from_pressure_level("green"),
            IncidentSeverity::Normal
        );
        assert_eq!(
            IncidentSeverity::from_pressure_level("yellow"),
            IncidentSeverity::Elevated
        );
        assert_eq!(
            IncidentSeverity::from_pressure_level("warning"),
            IncidentSeverity::Elevated
        );
        assert_eq!(
            IncidentSeverity::from_pressure_level("orange"),
            IncidentSeverity::High
        );
        assert_eq!(
            IncidentSeverity::from_pressure_level("high"),
            IncidentSeverity::High
        );
        assert_eq!(
            IncidentSeverity::from_pressure_level("red"),
            IncidentSeverity::Critical
        );
        assert_eq!(
            IncidentSeverity::from_pressure_level("critical"),
            IncidentSeverity::Critical
        );
        assert_eq!(
            IncidentSeverity::from_pressure_level("emergency"),
            IncidentSeverity::Critical
        );
    }

    #[test]
    fn severity_from_pressure_level_case_insensitive() {
        assert_eq!(
            IncidentSeverity::from_pressure_level("CRITICAL"),
            IncidentSeverity::Critical
        );
        assert_eq!(
            IncidentSeverity::from_pressure_level("Yellow"),
            IncidentSeverity::Elevated
        );
        assert_eq!(
            IncidentSeverity::from_pressure_level("RED"),
            IncidentSeverity::Critical
        );
    }

    #[test]
    fn severity_from_pressure_level_unknown_is_normal() {
        assert_eq!(
            IncidentSeverity::from_pressure_level(""),
            IncidentSeverity::Normal
        );
        assert_eq!(
            IncidentSeverity::from_pressure_level("unknown"),
            IncidentSeverity::Normal
        );
        assert_eq!(
            IncidentSeverity::from_pressure_level("foobar"),
            IncidentSeverity::Normal
        );
    }

    #[test]
    fn severity_from_daemon_state_none_is_normal() {
        assert_eq!(
            IncidentSeverity::from_daemon_state(None),
            IncidentSeverity::Normal
        );
    }

    #[test]
    fn severity_from_daemon_state_extracts_overall() {
        let mut state = DaemonState::default();
        state.pressure.overall = "critical".to_string();
        assert_eq!(
            IncidentSeverity::from_daemon_state(Some(&state)),
            IncidentSeverity::Critical
        );
    }

    #[test]
    fn severity_labels() {
        assert_eq!(IncidentSeverity::Normal.label(), "NORMAL");
        assert_eq!(IncidentSeverity::Elevated.label(), "ELEVATED");
        assert_eq!(IncidentSeverity::High.label(), "HIGH");
        assert_eq!(IncidentSeverity::Critical.label(), "CRITICAL");
    }

    #[test]
    fn severity_shows_hints_only_above_normal() {
        assert!(!IncidentSeverity::Normal.shows_hints());
        assert!(IncidentSeverity::Elevated.shows_hints());
        assert!(IncidentSeverity::High.shows_hints());
        assert!(IncidentSeverity::Critical.shows_hints());
    }

    #[test]
    fn severity_shows_banner_only_high_and_critical() {
        assert!(!IncidentSeverity::Normal.shows_banner());
        assert!(!IncidentSeverity::Elevated.shows_banner());
        assert!(IncidentSeverity::High.shows_banner());
        assert!(IncidentSeverity::Critical.shows_banner());
    }

    #[test]
    fn severity_ordering_is_consistent() {
        assert!(IncidentSeverity::Normal < IncidentSeverity::Elevated);
        assert!(IncidentSeverity::Elevated < IncidentSeverity::High);
        assert!(IncidentSeverity::High < IncidentSeverity::Critical);
    }

    // ── Playbook ──

    #[test]
    fn playbook_is_non_empty() {
        assert!(!INCIDENT_PLAYBOOK.is_empty());
    }

    #[test]
    fn playbook_entries_have_valid_targets() {
        for entry in INCIDENT_PLAYBOOK {
            // Verify label and description are non-empty.
            assert!(!entry.label.is_empty());
            assert!(!entry.description.is_empty());
            assert!(!entry.shortcut_hint.is_empty());
            // Verify target screen is a valid screen.
            let _num = entry.target.number(); // won't panic
        }
    }

    #[test]
    fn playbook_first_entry_is_ballast_release() {
        let first = &INCIDENT_PLAYBOOK[0];
        assert_eq!(first.target, Screen::Ballast);
        assert!(first.label.contains("ballast") || first.label.contains("Release"));
    }

    #[test]
    fn playbook_for_severity_filters_correctly() {
        let normal = playbook_for_severity(IncidentSeverity::Normal);
        let elevated = playbook_for_severity(IncidentSeverity::Elevated);
        let high = playbook_for_severity(IncidentSeverity::High);
        let critical = playbook_for_severity(IncidentSeverity::Critical);

        // Higher severity includes more entries (or same).
        assert!(normal.len() <= elevated.len());
        assert!(elevated.len() <= high.len());
        assert!(high.len() <= critical.len());

        // Critical should see all entries.
        assert_eq!(critical.len(), INCIDENT_PLAYBOOK.len());
    }

    #[test]
    fn playbook_for_normal_excludes_high_only_entries() {
        let normal_entries = playbook_for_severity(IncidentSeverity::Normal);
        // No entry with min_severity > Normal should appear.
        for entry in &normal_entries {
            assert_eq!(entry.min_severity, IncidentSeverity::Normal);
        }
    }

    #[test]
    fn playbook_for_elevated_includes_elevated_and_normal() {
        let entries = playbook_for_severity(IncidentSeverity::Elevated);
        for entry in &entries {
            assert!(entry.min_severity <= IncidentSeverity::Elevated);
        }
    }

    // ── Incident hints ──

    #[test]
    fn hints_empty_when_normal_severity() {
        let hints = incident_hints(
            IncidentSeverity::Normal,
            Screen::Overview,
            HintVerbosity::Full,
        );
        assert!(hints.is_empty());
    }

    #[test]
    fn hints_empty_when_verbosity_off() {
        let hints = incident_hints(
            IncidentSeverity::Critical,
            Screen::Overview,
            HintVerbosity::Off,
        );
        assert!(hints.is_empty());
    }

    #[test]
    fn hints_present_for_elevated_with_full_verbosity() {
        let hints = incident_hints(
            IncidentSeverity::Elevated,
            Screen::Overview,
            HintVerbosity::Full,
        );
        assert!(!hints.is_empty());
        // Should always include the playbook hint.
        assert!(hints.iter().any(|h| h.shortcut == "!"));
    }

    #[test]
    fn hints_include_quick_release_on_overview_when_high() {
        let hints = incident_hints(
            IncidentSeverity::High,
            Screen::Overview,
            HintVerbosity::Full,
        );
        assert!(hints.iter().any(|h| h.shortcut == "x"));
    }

    #[test]
    fn hints_no_quick_release_on_overview_when_elevated() {
        let hints = incident_hints(
            IncidentSeverity::Elevated,
            Screen::Overview,
            HintVerbosity::Full,
        );
        assert!(!hints.iter().any(|h| h.shortcut == "x"));
    }

    #[test]
    fn hints_include_filter_on_timeline() {
        let hints = incident_hints(
            IncidentSeverity::Elevated,
            Screen::Timeline,
            HintVerbosity::Full,
        );
        assert!(hints.iter().any(|h| h.shortcut == "f"));
    }

    #[test]
    fn hints_include_release_on_ballast_screen() {
        let hints = incident_hints(
            IncidentSeverity::Elevated,
            Screen::Ballast,
            HintVerbosity::Full,
        );
        assert!(hints.iter().any(|h| h.shortcut == "r"));
    }

    #[test]
    fn hints_minimal_mode_truncates_to_one() {
        let hints = incident_hints(
            IncidentSeverity::Critical,
            Screen::Overview,
            HintVerbosity::Minimal,
        );
        assert_eq!(hints.len(), 1);
        assert!(hints[0].shortcut == "!");
    }

    // ── Incident banner ──

    #[test]
    fn banner_none_for_normal() {
        assert!(incident_banner(IncidentSeverity::Normal).is_none());
    }

    #[test]
    fn banner_none_for_elevated() {
        assert!(incident_banner(IncidentSeverity::Elevated).is_none());
    }

    #[test]
    fn banner_present_for_high() {
        let banner = incident_banner(IncidentSeverity::High).unwrap();
        assert!(banner.contains("HIGH PRESSURE"));
        assert!(banner.contains("[!]"));
        assert!(banner.contains("[x]"));
    }

    #[test]
    fn banner_present_for_critical() {
        let banner = incident_banner(IncidentSeverity::Critical).unwrap();
        assert!(banner.contains("CRITICAL PRESSURE"));
        assert!(banner.contains("[!]"));
        assert!(banner.contains("[x]"));
    }

    // ── Feature gate ──

    #[test]
    fn shortcuts_enabled_by_default() {
        assert!(shortcuts_enabled(HintVerbosity::Full));
        assert!(shortcuts_enabled(HintVerbosity::Minimal));
    }

    #[test]
    fn shortcuts_disabled_when_off() {
        assert!(!shortcuts_enabled(HintVerbosity::Off));
    }
}
