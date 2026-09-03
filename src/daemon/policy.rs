//! Shadow-mode policy engine with progressive delivery gates.
//!
//! Manages the lifecycle: **observe** → **canary** → **enforce**, with automatic
//! fallback to `FallbackSafe` on guardrail breaches and recovery via clean-window gates.
//!
//! In observe (shadow) mode, the engine scores candidates and produces `DecisionRecord`s
//! but never mutates the filesystem. In canary mode, a capped subset of deletions are
//! executed. In enforce mode, normal deletion occurs.

#![allow(clippy::cast_precision_loss)]

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::str::FromStr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::monitor::guardrails::{GuardDiagnostics, GuardStatus};
use crate::monitor::pid::PressureLevel;
use crate::platform::types::MemoryPressureLevel;
use crate::scanner::decision_record::{DecisionRecord, DecisionRecordBuilder, PolicyMode};
use crate::scanner::scoring::{CandidacyScore, DecisionAction};

// ──────────────────── policy mode ────────────────────

/// Active policy mode controlling side-effect scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActiveMode {
    /// Observe only: score and log, no deletions.
    Observe,
    /// Canary: execute capped deletions, log comparisons.
    Canary,
    /// Enforce: normal deletion pipeline.
    Enforce,
    /// Fallback safe: all adaptive actions blocked, conservative only.
    FallbackSafe,
}

impl ActiveMode {
    /// Whether this mode allows any filesystem deletions.
    #[must_use]
    pub fn allows_deletion(self) -> bool {
        matches!(self, Self::Canary | Self::Enforce)
    }

    /// Convert to the decision_record `PolicyMode` for evidence logging.
    #[must_use]
    pub fn to_policy_mode(self) -> PolicyMode {
        match self {
            Self::Observe | Self::FallbackSafe => PolicyMode::Shadow,
            Self::Canary => PolicyMode::Canary,
            Self::Enforce => PolicyMode::Live,
        }
    }
}

impl fmt::Display for ActiveMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Observe => write!(f, "observe"),
            Self::Canary => write!(f, "canary"),
            Self::Enforce => write!(f, "enforce"),
            Self::FallbackSafe => write!(f, "fallback_safe"),
        }
    }
}

// ──────────────────── fallback trigger ────────────────────

/// Reason the engine entered fallback-safe mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackReason {
    /// Calibration score below floor for N consecutive windows.
    CalibrationBreach {
        /// Number of consecutive breach windows observed.
        consecutive_windows: usize,
    },
    /// Guard e-process alarm tripped (drift detected).
    GuardrailDrift,
    /// Canary hourly deletion budget exceeded.
    CanaryBudgetExhausted,
    /// Policy error or panic recovery.
    PolicyError {
        /// Error details.
        details: String,
    },
    /// Evidence serialization failure.
    SerializationFailure,
    /// External kill-switch (env var or config).
    KillSwitch,
}

impl fmt::Display for FallbackReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CalibrationBreach {
                consecutive_windows,
            } => write!(f, "calibration breach ({consecutive_windows} windows)"),
            Self::GuardrailDrift => write!(f, "guardrail drift alarm"),
            Self::CanaryBudgetExhausted => write!(f, "canary budget exhausted"),
            Self::PolicyError { details } => write!(f, "policy error: {details}"),
            Self::SerializationFailure => write!(f, "evidence serialization failure"),
            Self::KillSwitch => write!(f, "kill-switch engaged"),
        }
    }
}

// ──────────────────── policy config ────────────────────

/// Configuration for the policy engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    /// Initial mode on daemon start.
    pub initial_mode: ActiveMode,
    /// Maximum candidates to evaluate per loop iteration.
    pub max_candidates_per_loop: usize,
    /// Maximum hypothetical delete set per loop (observe mode).
    pub max_hypothetical_deletes: usize,
    /// Maximum canary deletions per hour.
    pub max_canary_deletes_per_hour: usize,
    /// Number of consecutive clean windows required for recovery from fallback.
    pub recovery_clean_windows: usize,
    /// Number of consecutive calibration breach windows before fallback.
    pub calibration_breach_windows: usize,
    /// Expected-loss penalty added to delete action when guard is not PASS.
    pub guard_penalty: f64,
    /// Loss values.
    pub loss_delete_useful: f64,
    /// Loss for keeping abandoned artifacts.
    pub loss_keep_abandoned: f64,
    /// Loss for review action (any state).
    pub loss_review: f64,
    /// Minimum seconds to stay in FallbackSafe before attempting recovery.
    /// Prevents rapid canary↔fallback thrashing on bursty workloads.
    pub min_fallback_secs: u64,
    /// Whether the kill-switch is active (forces fallback_safe).
    pub kill_switch: bool,
    /// Minimum seconds between guard observation windows. Under pressure the
    /// main loop ticks at 100-250ms, which would flood the guard's statistical
    /// machinery. Set to 0 in tests to allow back-to-back calls.
    pub observe_min_interval_secs: u64,
    /// What a calibration breach (`calibration_breach_windows` consecutive
    /// guard-FAIL windows under pressure) does: `demote` enters FallbackSafe,
    /// `advisory` logs and carries on. Unset: `demote` unless `initial_mode`
    /// is `enforce`, where a fleet that has already earned Enforce keeps it.
    pub calibration_breach_action: Option<FallbackAction>,
    /// What exhausting `max_canary_deletes_per_hour` does: `keep` (default)
    /// refuses further deletions for the rest of the hour and stays in
    /// Canary, `demote` enters FallbackSafe until clean windows recover it.
    /// Either way the decision that hit the cap is Keep. `keep` is the
    /// stricter of the two: a demote-then-recover cycle re-enters Canary
    /// with a fresh hourly count, so it can delete more per hour than the
    /// cap, not less.
    pub canary_budget_action: CanaryBudgetAction,
    /// What a failed `state.json` write does: `demote` enters FallbackSafe
    /// (evidence that cannot be persisted must not drive deletions),
    /// `advisory` logs and carries on.
    pub serialization_failure_action: FallbackAction,
    /// Where automatic recovery from FallbackSafe lands after
    /// `recovery_clean_windows`: `canary` (never higher than Canary, the
    /// mandatory re-proving gate; Observe stays Observe), `previous` (the
    /// mode before the fallback), `none` (only `promote()` leaves
    /// FallbackSafe).
    pub auto_recover_to: AutoRecoverTo,
    /// Whether sustained Yellow+ pressure inside FallbackSafe may break the
    /// deadlock by promoting out of it (see `check_emergency_escalation`).
    /// Unset: on for `initial_mode = enforce` fleets, off otherwise.
    pub emergency_escalation: Option<bool>,
}

/// What a fallback trigger does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackAction {
    /// Enter FallbackSafe.
    Demote,
    /// Log the condition; keep the current mode.
    Advisory,
}

/// What exhausting the canary budget does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryBudgetAction {
    /// Enter FallbackSafe until clean windows recover it.
    Demote,
    /// Refuse further deletions this hour and stay in Canary.
    Keep,
}

/// Where automatic recovery from FallbackSafe lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoRecoverTo {
    /// Never automatically; only `promote()` leaves FallbackSafe.
    None,
    /// The pre-fallback mode capped at Canary.
    Canary,
    /// The pre-fallback mode, Enforce included.
    Previous,
}

impl fmt::Display for AutoRecoverTo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "none",
            Self::Canary => "canary",
            Self::Previous => "previous",
        })
    }
}

impl PolicyConfig {
    /// `calibration_breach_action` with the unset default resolved.
    #[must_use]
    pub fn resolved_calibration_breach_action(&self) -> FallbackAction {
        self.calibration_breach_action
            .unwrap_or(if self.initial_mode == ActiveMode::Enforce {
                FallbackAction::Advisory
            } else {
                FallbackAction::Demote
            })
    }

    /// `emergency_escalation` with the unset default resolved.
    #[must_use]
    pub fn resolved_emergency_escalation(&self) -> bool {
        self.emergency_escalation
            .unwrap_or(self.initial_mode == ActiveMode::Enforce)
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            initial_mode: ActiveMode::Enforce,
            max_candidates_per_loop: 100,
            max_hypothetical_deletes: 25,
            max_canary_deletes_per_hour: 10,
            recovery_clean_windows: 10,
            calibration_breach_windows: 25,
            min_fallback_secs: 300,
            guard_penalty: 50.0,
            loss_delete_useful: 100.0,
            loss_keep_abandoned: 30.0,
            loss_review: 5.0,
            kill_switch: false,
            observe_min_interval_secs: MIN_OBSERVE_INTERVAL_SECS,
            calibration_breach_action: None,
            canary_budget_action: CanaryBudgetAction::Keep,
            serialization_failure_action: FallbackAction::Demote,
            auto_recover_to: AutoRecoverTo::Canary,
            emergency_escalation: None,
        }
    }
}

// ──────────────────── policy decision ────────────────────

/// The result of evaluating a batch of candidates through the policy engine.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    /// Decision records for all evaluated candidates.
    pub records: Vec<DecisionRecord>,
    /// Candidates approved for actual deletion (empty in observe/fallback modes).
    pub approved_for_deletion: Vec<CandidacyScore>,
    /// Count of candidates that would be deleted in enforce mode.
    pub hypothetical_deletes: usize,
    /// Count of candidates that would be kept.
    pub hypothetical_keeps: usize,
    /// Count of candidates flagged for review.
    pub hypothetical_reviews: usize,
    /// Whether budget was exhausted during evaluation.
    pub budget_exhausted: bool,
    /// Active mode when the decision was made.
    pub mode: ActiveMode,
}

// ──────────────────── mode transition ────────────────────

/// Valid transitions in the policy state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    /// Promote: observe→canary or canary→enforce.
    Promote,
    /// Demote: enforce→canary or canary→observe.
    Demote,
    /// Emergency fallback to safe mode.
    Fallback(FallbackReason),
    /// Recovery from fallback to the pre-fallback mode.
    Recover,
}

// ──────────────────── behavior dispatch ────────────────────

/// Three-level pressure class used by the behavior dispatch matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorPressureLevel {
    /// Normal operating range.
    Normal,
    /// Warning pressure where work should become more conservative.
    Warn,
    /// Critical pressure where survival actions take priority.
    Critical,
}

impl BehaviorPressureLevel {
    /// Normalize the platform memory-pressure signal into the dispatch matrix scale.
    #[must_use]
    pub fn from_memory_pressure(level: MemoryPressureLevel) -> Self {
        match level {
            MemoryPressureLevel::Normal => Self::Normal,
            MemoryPressureLevel::Warn | MemoryPressureLevel::Unknown => Self::Warn,
            MemoryPressureLevel::Critical => Self::Critical,
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Normal => 0,
            Self::Warn => 1,
            Self::Critical => 2,
        }
    }
}

/// How much filesystem scanning a pressure cell allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanAggressiveness {
    /// Default scanner budget and traversal rules.
    Normal,
    /// Reduced traversal to avoid memory-heavy walks.
    Light,
    /// Increased scanner budget while memory is healthy.
    Aggressive,
    /// Only walk paths that can produce very high-confidence candidates.
    DefiniteOnly,
    /// Do not start new filesystem scans.
    Skip,
}

/// Cleanup posture selected by the behavior dispatch table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupAction {
    /// No cleanup work should run.
    None,
    /// Produce candidate evidence, but do not delete.
    IdentifyOnly,
    /// Delete only candidates with high confidence.
    HighConfidenceCandidates,
    /// Delete the best-ranked candidates without broad traversal.
    MostPromisingCandidates,
    /// Delete candidates that are definite artifacts.
    DefiniteCandidates,
    /// Delete any definite artifact candidate available to the planner.
    AnyDefiniteCandidate,
}

/// Ballast response selected by the behavior dispatch table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BallastAction {
    /// Do not release ballast.
    None,
    /// Release ballast as part of the selected cleanup plan.
    Release,
    /// Release ballast before scanner or cleanup work.
    ReleaseFirst,
}

/// Operator notification severity selected by the behavior dispatch table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationPriority {
    /// Do not notify.
    None,
    /// Low-priority advisory.
    Low,
    /// Normal pressure notification.
    Normal,
    /// High-priority pressure notification.
    High,
    /// Emergency notification.
    Emergency,
}

/// Action bundle selected for one memory-pressure and disk-pressure cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorMode {
    /// Scanner posture.
    pub scan_aggressiveness: ScanAggressiveness,
    /// Cleanup posture.
    pub cleanup_action: CleanupAction,
    /// Ballast response.
    pub ballast_action: BallastAction,
    /// Notification severity.
    pub notification_priority: NotificationPriority,
}

/// Index of a native disk-pressure level along the behavior matrix's disk axis.
const fn disk_index(level: PressureLevel) -> usize {
    match level {
        PressureLevel::Green => 0,
        PressureLevel::Yellow => 1,
        PressureLevel::Orange => 2,
        PressureLevel::Red => 3,
        PressureLevel::Critical => 4,
    }
}

/// Disk-pressure columns of the behavior matrix, in index order.
pub const BEHAVIOR_DISK_LEVELS: [PressureLevel; 5] = [
    PressureLevel::Green,
    PressureLevel::Yellow,
    PressureLevel::Orange,
    PressureLevel::Red,
    PressureLevel::Critical,
];

/// Memory-pressure rows of the behavior matrix, in index order.
pub const BEHAVIOR_MEMORY_LEVELS: [BehaviorPressureLevel; 3] = [
    BehaviorPressureLevel::Normal,
    BehaviorPressureLevel::Warn,
    BehaviorPressureLevel::Critical,
];

impl BehaviorPressureLevel {
    const fn label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Warn => "warn",
            Self::Critical => "critical",
        }
    }
}

const fn disk_label(level: PressureLevel) -> &'static str {
    match level {
        PressureLevel::Green => "green",
        PressureLevel::Yellow => "yellow",
        PressureLevel::Orange => "orange",
        PressureLevel::Red => "red",
        PressureLevel::Critical => "critical",
    }
}

impl ScanAggressiveness {
    const fn label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Light => "light",
            Self::Aggressive => "aggressive",
            Self::DefiniteOnly => "definite_only",
            Self::Skip => "skip",
        }
    }
}

impl CleanupAction {
    /// Aggressiveness rank used by the never-reduce rule: a higher rank deletes
    /// more. `None` < `IdentifyOnly` < `HighConfidenceCandidates` <
    /// `MostPromisingCandidates` < `DefiniteCandidates` < `AnyDefiniteCandidate`.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::None => 0,
            Self::IdentifyOnly => 1,
            Self::HighConfidenceCandidates => 2,
            Self::MostPromisingCandidates => 3,
            Self::DefiniteCandidates => 4,
            Self::AnyDefiniteCandidate => 5,
        }
    }

    const fn at_least(self, floor: Self) -> Self {
        if floor.rank() > self.rank() {
            floor
        } else {
            self
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::IdentifyOnly => "identify_only",
            Self::HighConfidenceCandidates => "high_confidence_candidates",
            Self::MostPromisingCandidates => "most_promising_candidates",
            Self::DefiniteCandidates => "definite_candidates",
            Self::AnyDefiniteCandidate => "any_definite_candidate",
        }
    }
}

impl BallastAction {
    /// Aggressiveness rank used by the never-reduce rule.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Release => 1,
            Self::ReleaseFirst => 2,
        }
    }

    const fn at_least(self, floor: Self) -> Self {
        if floor.rank() > self.rank() {
            floor
        } else {
            self
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Release => "release",
            Self::ReleaseFirst => "release_first",
        }
    }
}

impl NotificationPriority {
    const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Normal => "normal",
            Self::High => "high",
            Self::Emergency => "emergency",
        }
    }
}

const fn cell(
    scan_aggressiveness: ScanAggressiveness,
    cleanup_action: CleanupAction,
    ballast_action: BallastAction,
    notification_priority: NotificationPriority,
) -> BehaviorMode {
    BehaviorMode {
        scan_aggressiveness,
        cleanup_action,
        ballast_action,
        notification_priority,
    }
}

/// The v0.6 matrix: reclaim *before* the cliff.
///
/// Rows are memory pressure (Normal, Warn, Critical); columns are disk pressure
/// (Green, Yellow, Orange, Red, Critical). Orange already deletes definite
/// artifacts and releases ballast; Red and Critical delete any definite
/// candidate and release ballast first. Green and Yellow delete only
/// high-confidence candidates (the maintenance and predictive paths), so an
/// artifact that scores as definitely regenerable is removed while there is
/// still time, instead of waiting for the volume to reach the state in which
/// the daemon's own remediation fails.
const V0_6_CELLS: [[BehaviorMode; 5]; 3] = [
    [
        cell(
            ScanAggressiveness::Normal,
            CleanupAction::HighConfidenceCandidates,
            BallastAction::None,
            NotificationPriority::None,
        ),
        cell(
            ScanAggressiveness::Aggressive,
            CleanupAction::HighConfidenceCandidates,
            BallastAction::None,
            NotificationPriority::Low,
        ),
        cell(
            ScanAggressiveness::Aggressive,
            CleanupAction::DefiniteCandidates,
            BallastAction::Release,
            NotificationPriority::Normal,
        ),
        cell(
            ScanAggressiveness::Aggressive,
            CleanupAction::AnyDefiniteCandidate,
            BallastAction::ReleaseFirst,
            NotificationPriority::High,
        ),
        cell(
            ScanAggressiveness::Aggressive,
            CleanupAction::AnyDefiniteCandidate,
            BallastAction::ReleaseFirst,
            NotificationPriority::Emergency,
        ),
    ],
    [
        cell(
            ScanAggressiveness::Light,
            CleanupAction::HighConfidenceCandidates,
            BallastAction::None,
            NotificationPriority::Low,
        ),
        cell(
            ScanAggressiveness::Light,
            CleanupAction::HighConfidenceCandidates,
            BallastAction::None,
            NotificationPriority::Normal,
        ),
        cell(
            ScanAggressiveness::Light,
            CleanupAction::DefiniteCandidates,
            BallastAction::Release,
            NotificationPriority::Normal,
        ),
        cell(
            ScanAggressiveness::DefiniteOnly,
            CleanupAction::AnyDefiniteCandidate,
            BallastAction::ReleaseFirst,
            NotificationPriority::High,
        ),
        cell(
            ScanAggressiveness::DefiniteOnly,
            CleanupAction::AnyDefiniteCandidate,
            BallastAction::ReleaseFirst,
            NotificationPriority::Emergency,
        ),
    ],
    [
        cell(
            ScanAggressiveness::Skip,
            CleanupAction::HighConfidenceCandidates,
            BallastAction::None,
            NotificationPriority::Normal,
        ),
        cell(
            ScanAggressiveness::DefiniteOnly,
            CleanupAction::HighConfidenceCandidates,
            BallastAction::None,
            NotificationPriority::High,
        ),
        cell(
            ScanAggressiveness::DefiniteOnly,
            CleanupAction::DefiniteCandidates,
            BallastAction::Release,
            NotificationPriority::High,
        ),
        cell(
            ScanAggressiveness::DefiniteOnly,
            CleanupAction::AnyDefiniteCandidate,
            BallastAction::ReleaseFirst,
            NotificationPriority::Emergency,
        ),
        cell(
            ScanAggressiveness::DefiniteOnly,
            CleanupAction::AnyDefiniteCandidate,
            BallastAction::ReleaseFirst,
            NotificationPriority::Emergency,
        ),
    ],
];

/// The matrix shipped through v0.5.x, kept as the rollback preset.
///
/// It collapsed Yellow and Orange into one "warn" column and Red and Critical
/// into one "critical" column, and at normal memory pressure it made the warn
/// column identify-only with no ballast release, so nothing was reclaimed until
/// Red. Select it with `[behavior] preset = "v0.5"` or
/// `SBH_BEHAVIOR_PRESET=v0.5`.
const V0_5_CELLS: [[BehaviorMode; 5]; 3] = [
    [
        cell(
            ScanAggressiveness::Normal,
            CleanupAction::None,
            BallastAction::None,
            NotificationPriority::None,
        ),
        cell(
            ScanAggressiveness::Aggressive,
            CleanupAction::IdentifyOnly,
            BallastAction::None,
            NotificationPriority::Low,
        ),
        cell(
            ScanAggressiveness::Aggressive,
            CleanupAction::IdentifyOnly,
            BallastAction::None,
            NotificationPriority::Low,
        ),
        cell(
            ScanAggressiveness::Aggressive,
            CleanupAction::DefiniteCandidates,
            BallastAction::Release,
            NotificationPriority::High,
        ),
        cell(
            ScanAggressiveness::Aggressive,
            CleanupAction::DefiniteCandidates,
            BallastAction::Release,
            NotificationPriority::High,
        ),
    ],
    [
        cell(
            ScanAggressiveness::Light,
            CleanupAction::None,
            BallastAction::None,
            NotificationPriority::Low,
        ),
        cell(
            ScanAggressiveness::Light,
            CleanupAction::HighConfidenceCandidates,
            BallastAction::Release,
            NotificationPriority::Normal,
        ),
        cell(
            ScanAggressiveness::Light,
            CleanupAction::HighConfidenceCandidates,
            BallastAction::Release,
            NotificationPriority::Normal,
        ),
        cell(
            ScanAggressiveness::DefiniteOnly,
            CleanupAction::DefiniteCandidates,
            BallastAction::ReleaseFirst,
            NotificationPriority::High,
        ),
        cell(
            ScanAggressiveness::DefiniteOnly,
            CleanupAction::DefiniteCandidates,
            BallastAction::ReleaseFirst,
            NotificationPriority::High,
        ),
    ],
    [
        cell(
            ScanAggressiveness::Skip,
            CleanupAction::None,
            BallastAction::None,
            NotificationPriority::Normal,
        ),
        cell(
            ScanAggressiveness::DefiniteOnly,
            CleanupAction::MostPromisingCandidates,
            BallastAction::Release,
            NotificationPriority::High,
        ),
        cell(
            ScanAggressiveness::DefiniteOnly,
            CleanupAction::MostPromisingCandidates,
            BallastAction::Release,
            NotificationPriority::High,
        ),
        cell(
            ScanAggressiveness::DefiniteOnly,
            CleanupAction::AnyDefiniteCandidate,
            BallastAction::ReleaseFirst,
            NotificationPriority::Emergency,
        ),
        cell(
            ScanAggressiveness::DefiniteOnly,
            CleanupAction::AnyDefiniteCandidate,
            BallastAction::ReleaseFirst,
            NotificationPriority::Emergency,
        ),
    ],
];

/// Named behavior-matrix presets selectable from `[behavior] preset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum BehaviorPreset {
    /// Reclaim before the cliff (default since v0.6.0).
    #[default]
    #[serde(rename = "v0.6")]
    V0_6,
    /// The matrix shipped through v0.5.x (rollback).
    #[serde(rename = "v0.5")]
    V0_5,
    /// Start from the v0.6 cells and apply `[behavior.cells.*]` overrides.
    #[serde(rename = "custom")]
    Custom,
}

impl BehaviorPreset {
    /// All accepted spellings, for error messages.
    pub const ALLOWED: &'static str = "\"v0.6\", \"v0.5\", \"custom\"";

    const fn base_cells(self) -> [[BehaviorMode; 5]; 3] {
        match self {
            Self::V0_6 | Self::Custom => V0_6_CELLS,
            Self::V0_5 => V0_5_CELLS,
        }
    }
}

impl fmt::Display for BehaviorPreset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::V0_6 => "v0.6",
            Self::V0_5 => "v0.5",
            Self::Custom => "custom",
        })
    }
}

impl FromStr for BehaviorPreset {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "v0.6" | "v0_6" | "0.6" => Ok(Self::V0_6),
            "v0.5" | "v0_5" | "0.5" => Ok(Self::V0_5),
            "custom" => Ok(Self::Custom),
            other => Err(format!(
                "invalid behavior preset {other:?}: expected one of {}",
                Self::ALLOWED
            )),
        }
    }
}

/// One matrix cell as written in `[behavior.cells.<memory>_<disk>]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorCellConfig {
    /// Scanner posture.
    pub scan: ScanAggressiveness,
    /// Cleanup posture.
    pub cleanup: CleanupAction,
    /// Ballast response.
    pub ballast: BallastAction,
    /// Notification severity.
    pub notify: NotificationPriority,
}

impl From<BehaviorCellConfig> for BehaviorMode {
    fn from(config: BehaviorCellConfig) -> Self {
        Self {
            scan_aggressiveness: config.scan,
            cleanup_action: config.cleanup,
            ballast_action: config.ballast,
            notification_priority: config.notify,
        }
    }
}

/// `[behavior]` configuration: which matrix the daemon runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BehaviorConfig {
    /// Matrix preset (`"v0.6"` default, `"v0.5"` rollback, `"custom"`).
    /// Overridable with `SBH_BEHAVIOR_PRESET`.
    pub preset: BehaviorPreset,
    /// When true (default), memory pressure may lower scan aggressiveness but
    /// never lowers the cleanup or ballast posture below the normal-memory row
    /// for the same disk level: memory pressure argues for less scanning, not
    /// for keeping a full disk.
    pub memory_never_reduces_cleanup: bool,
    /// Cell overrides keyed `<memory>_<disk>` (memory: `normal`, `warn`,
    /// `critical`; disk: `green`, `yellow`, `orange`, `red`, `critical`), for
    /// example `[behavior.cells.normal_orange]`. Applied only when
    /// `preset = "custom"`; ignored otherwise so an env-var rollback to a
    /// named preset always works.
    pub cells: BTreeMap<String, BehaviorCellConfig>,
}

impl Default for BehaviorConfig {
    fn default() -> Self {
        Self {
            preset: BehaviorPreset::default(),
            memory_never_reduces_cleanup: true,
            cells: BTreeMap::new(),
        }
    }
}

fn parse_cell_key(key: &str) -> Result<(BehaviorPressureLevel, PressureLevel), String> {
    let (memory, disk) = key
        .split_once('_')
        .ok_or_else(|| format!("behavior.cells.{key}: expected `<memory>_<disk>`"))?;
    let memory_level = BEHAVIOR_MEMORY_LEVELS
        .iter()
        .copied()
        .find(|level| level.label() == memory)
        .ok_or_else(|| {
            format!("behavior.cells.{key}: unknown memory level {memory:?}, expected normal, warn, or critical")
        })?;
    let disk_level = BEHAVIOR_DISK_LEVELS
        .iter()
        .copied()
        .find(|level| disk_label(*level) == disk)
        .ok_or_else(|| {
            format!("behavior.cells.{key}: unknown disk level {disk:?}, expected green, yellow, orange, red, or critical")
        })?;
    Ok((memory_level, disk_level))
}

/// Dispatch table for the memory-pressure by disk-pressure behavior matrix.
///
/// Rows are memory pressure (`Normal`, `Warn`, `Critical`); columns are the
/// five native disk-pressure levels (`Green` through `Critical`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorDispatchTable {
    cells: [[BehaviorMode; 5]; 3],
    preset: BehaviorPreset,
}

impl BehaviorDispatchTable {
    /// Build a dispatch table from explicit memory-row by disk-column cells.
    #[must_use]
    pub const fn new(cells: [[BehaviorMode; 5]; 3]) -> Self {
        Self {
            cells,
            preset: BehaviorPreset::Custom,
        }
    }

    /// The matrix for a named preset with the never-reduce rule applied.
    #[must_use]
    pub fn from_preset(preset: BehaviorPreset) -> Self {
        let mut table = Self {
            cells: preset.base_cells(),
            preset,
        };
        table.apply_never_reduce();
        table
    }

    /// Resolve the `[behavior]` configuration into the effective matrix.
    ///
    /// Fails only on custom cell keys that name no matrix cell; unknown field
    /// names inside a cell are rejected by the config parser.
    pub fn from_config(config: &BehaviorConfig) -> Result<Self, String> {
        let mut table = Self {
            cells: config.preset.base_cells(),
            preset: config.preset,
        };
        if config.preset == BehaviorPreset::Custom {
            for (key, override_cell) in &config.cells {
                let (memory_level, disk_level) = parse_cell_key(key)?;
                table.cells[memory_level.index()][disk_index(disk_level)] =
                    BehaviorMode::from(*override_cell);
            }
        }
        if config.memory_never_reduces_cleanup {
            table.apply_never_reduce();
        }
        Ok(table)
    }

    fn apply_never_reduce(&mut self) {
        for column in 0..self.cells[0].len() {
            let floor = self.cells[BehaviorPressureLevel::Normal.index()][column];
            for row in [BehaviorPressureLevel::Warn, BehaviorPressureLevel::Critical] {
                let current = &mut self.cells[row.index()][column];
                current.cleanup_action = current.cleanup_action.at_least(floor.cleanup_action);
                current.ballast_action = current.ballast_action.at_least(floor.ballast_action);
            }
        }
    }

    /// Which preset this table was built from.
    #[must_use]
    pub const fn preset(&self) -> BehaviorPreset {
        self.preset
    }

    /// Return the behavior for a normalized memory level and a native disk level.
    #[must_use]
    pub fn mode_for_levels(
        &self,
        memory_pressure: BehaviorPressureLevel,
        disk_pressure: PressureLevel,
    ) -> BehaviorMode {
        self.cells[memory_pressure.index()][disk_index(disk_pressure)]
    }

    /// Normalize the platform memory reading and return the matching behavior.
    #[must_use]
    pub fn mode_for(
        &self,
        memory_pressure: MemoryPressureLevel,
        disk_pressure: PressureLevel,
    ) -> BehaviorMode {
        self.mode_for_levels(
            BehaviorPressureLevel::from_memory_pressure(memory_pressure),
            disk_pressure,
        )
    }

    /// Human-readable rendering of every cell, one line per memory row, for
    /// the startup and reload logs.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = format!(
            "behavior matrix preset={} (rows: memory; cells: scan/cleanup/ballast/notify)",
            self.preset
        );
        for memory_level in BEHAVIOR_MEMORY_LEVELS {
            let _ = write!(out, "\n  memory={:<8}", memory_level.label());
            for disk_level in BEHAVIOR_DISK_LEVELS {
                let mode = self.mode_for_levels(memory_level, disk_level);
                let _ = write!(
                    out,
                    " {}={}/{}/{}/{}",
                    disk_label(disk_level),
                    mode.scan_aggressiveness.label(),
                    mode.cleanup_action.label(),
                    mode.ballast_action.label(),
                    mode.notification_priority.label()
                );
            }
        }
        out
    }
}

impl Default for BehaviorDispatchTable {
    fn default() -> Self {
        Self::from_preset(BehaviorPreset::default())
    }
}

// ──────────────────── policy engine ────────────────────

/// Duration after which fallback_safe mode can be auto-escalated to enforce
/// when pressure remains at Yellow or above, breaking the deadlock where
/// nothing can be deleted but pressure can't drop.
const FALLBACK_EMERGENCY_ESCALATION_SECS: u64 = 5 * 60;

/// Grace period after emergency escalation during which the engine will not
/// re-enter FallbackSafe. This prevents the cycle where escalation → immediate
/// calibration breach → FallbackSafe → escalation repeats endlessly.
const EMERGENCY_GRACE_PERIOD_SECS: u64 = 30 * 60;

/// Startup grace period during which calibration breaches do not trigger
/// FallbackSafe. On a fresh start the guard has no history, so every window
/// reports Fail until enough scan data accumulates. Without this grace,
/// the engine enters FallbackSafe within seconds of every restart.
const STARTUP_CALIBRATION_GRACE_SECS: u64 = 10 * 60;

/// Minimum interval between guard observation windows. The guard's statistical
/// calibration assumes observations arrive at roughly the base poll interval
/// (~30s). Under pressure, the main loop ticks at 100-250ms (Critical=100ms,
/// Orange=250ms), which floods the guard with 4-10 observations per second
/// and makes breach counters, calibration windows, and recovery logic
/// meaningless — 100 breach windows in 10-25 seconds instead of ~50 minutes.
/// This floor ensures guard statistics remain valid regardless of tick rate.
const MIN_OBSERVE_INTERVAL_SECS: u64 = 10;

/// The shadow-mode policy engine with progressive delivery gates.
pub struct PolicyEngine {
    config: PolicyConfig,
    mode: ActiveMode,
    pre_fallback_mode: ActiveMode,
    fallback_reason: Option<FallbackReason>,
    /// When fallback_safe mode was entered (for emergency escalation timer).
    fallback_entered_at: Option<Instant>,
    /// When emergency escalation last occurred. During the grace period after
    /// escalation, the engine refuses to re-enter FallbackSafe to prevent the
    /// deadlock cycle: escalate → breach → fallback → escalate → ...
    emergency_escalated_at: Option<Instant>,
    /// Timestamp when the engine was created. Calibration breaches during the
    /// startup grace period are suppressed so the guard can accumulate history.
    started_at: Instant,
    builder: DecisionRecordBuilder,
    consecutive_clean_windows: usize,
    consecutive_breach_windows: usize,
    /// How many times the breach counter has hit 100 and reset.
    /// After 3 recalibrations, all breach/reset logging is suppressed
    /// since the guard is persistently miscalibrated for this workload.
    recalibration_count: u32,
    canary_deletes_this_hour: usize,
    canary_hour_start: Instant,
    total_decisions: u64,
    total_fallback_entries: u64,
    transition_log: Vec<TransitionEntry>,
    /// Transitions ever recorded; the cursor `transitions_after` works from.
    transitions_total: u64,
    /// Current disk pressure level. Guard-triggered fallbacks are suppressed
    /// during green pressure. At Orange+, the guard penalty is reduced or
    /// bypassed entirely (decision-theoretic: the loss from disk exhaustion
    /// vastly exceeds the loss from deleting a regenerable build artifact).
    pressure_level: PressureLevel,
    /// Last time a "suppressing fallback" message was logged. Rate-limited to
    /// once per 5 minutes to prevent log spam when grace periods are active
    /// and enter_fallback is called every scan cycle (5-8 times per cycle).
    last_suppression_log: Option<Instant>,
    /// Last time `observe_window` actually processed an observation. Calls
    /// within `MIN_OBSERVE_INTERVAL_SECS` are silently skipped to prevent
    /// the high-frequency pressure tick loop from flooding the guard.
    last_observe_time: Option<Instant>,
    /// When the current mode was entered.
    mode_since: Instant,
    /// The most recent fallback reason, kept after recovery for `sbh status`.
    last_fallback_reason: Option<String>,
    /// State-file write failures reported by the daemon.
    serialization_failures: u64,
}

/// Record of a mode transition.
#[derive(Debug, Clone, Serialize)]
pub struct TransitionEntry {
    /// Transition type.
    pub transition: String,
    /// Mode before transition.
    pub from: String,
    /// Mode after transition.
    pub to: String,
    /// Decision count at time of transition.
    pub at_decision: u64,
    /// Reason (for fallback entries).
    pub reason: Option<String>,
}

impl PolicyEngine {
    /// Create a new policy engine with the given configuration.
    #[must_use]
    pub fn new(config: PolicyConfig) -> Self {
        let intended = config.initial_mode;
        let mut engine = Self {
            config,
            mode: intended,
            pre_fallback_mode: intended,
            fallback_reason: None,
            fallback_entered_at: None,
            emergency_escalated_at: None,
            started_at: Instant::now(),
            builder: DecisionRecordBuilder::new(),
            consecutive_clean_windows: 0,
            consecutive_breach_windows: 0,
            recalibration_count: 0,
            canary_deletes_this_hour: 0,
            canary_hour_start: Instant::now(),
            total_decisions: 0,
            total_fallback_entries: 0,
            transition_log: Vec::new(),
            transitions_total: 0,
            pressure_level: PressureLevel::Green,
            last_suppression_log: None,
            last_observe_time: None,
            mode_since: Instant::now(),
            last_fallback_reason: None,
            serialization_failures: 0,
        };

        if engine.config.kill_switch {
            if engine.mode == ActiveMode::FallbackSafe {
                // Already in fallback by initial_mode, but still record kill-switch cause.
                let reason = FallbackReason::KillSwitch;
                let reason_str = reason.to_string();
                engine.fallback_reason = Some(reason);
                engine.total_fallback_entries = 1;
                engine.log_transition(
                    "fallback",
                    ActiveMode::FallbackSafe,
                    ActiveMode::FallbackSafe,
                    Some(reason_str),
                );
            } else {
                engine.enter_fallback(FallbackReason::KillSwitch);
            }
        }

        engine
    }

    /// The active configuration.
    #[must_use]
    pub const fn config(&self) -> &PolicyConfig {
        &self.config
    }

    /// Current active mode.
    #[must_use]
    pub fn mode(&self) -> ActiveMode {
        self.mode
    }

    /// Why the engine is in fallback mode (if applicable).
    #[must_use]
    pub fn fallback_reason(&self) -> Option<&FallbackReason> {
        self.fallback_reason.as_ref()
    }

    /// Total decisions made across all loops.
    #[must_use]
    pub fn total_decisions(&self) -> u64 {
        self.total_decisions
    }

    /// Total times fallback_safe was entered.
    #[must_use]
    pub fn total_fallback_entries(&self) -> u64 {
        self.total_fallback_entries
    }

    /// Ordered log of mode transitions.
    #[must_use]
    pub fn transition_log(&self) -> &[TransitionEntry] {
        &self.transition_log
    }

    // ──────────── core evaluation ────────────

    /// Evaluate a batch of scored candidates through the policy engine.
    ///
    /// Returns a `PolicyDecision` with evidence records and the approved
    /// deletion set (which may be empty in observe/fallback modes).
    pub fn evaluate(
        &mut self,
        candidates: &[CandidacyScore],
        guard: Option<&GuardDiagnostics>,
    ) -> PolicyDecision {
        // Check kill-switch.
        if self.config.kill_switch && self.mode != ActiveMode::FallbackSafe {
            self.enter_fallback(FallbackReason::KillSwitch);
        }

        // Check guard status for automatic fallback.
        if let Some(diag) = guard {
            self.check_guard_triggers(diag);
        }

        let budget = self.config.max_candidates_per_loop.min(candidates.len());
        let policy_mode = self.mode.to_policy_mode();

        let mut records = Vec::with_capacity(budget);
        let mut approved = Vec::new();
        let mut hypothetical_deletes = 0usize;
        let mut hypothetical_keeps = 0usize;
        let mut hypothetical_reviews = 0usize;
        let mut budget_exhausted = false;

        for (i, candidate) in candidates.iter().enumerate() {
            if i >= budget {
                budget_exhausted = true;
                break;
            }

            // Determine effective action by applying policy rules.
            let effective_action = self.enforce_policy(candidate, guard);

            // Build the evidence record.
            let comparator = if self.mode == ActiveMode::Observe {
                // In observe mode, the "comparator" is the enforce-mode action.
                Some(candidate.decision.action)
            } else {
                None
            };

            let record = self.builder.build(
                candidate,
                policy_mode,
                guard,
                comparator,
                Some(effective_action),
            );
            self.total_decisions += 1;

            // Count hypothetical outcomes based on the candidate's inherent score action.
            match candidate.decision.action {
                DecisionAction::Delete => hypothetical_deletes += 1,
                DecisionAction::Keep => hypothetical_keeps += 1,
                DecisionAction::Review => hypothetical_reviews += 1,
            }

            // Approve for actual deletion if effective action is Delete.
            if effective_action == DecisionAction::Delete {
                approved.push(candidate.clone());
            }

            records.push(record);

            // Enforce hypothetical budget in observe mode.
            if self.mode == ActiveMode::Observe
                && hypothetical_deletes >= self.config.max_hypothetical_deletes
            {
                budget_exhausted = true;
                break;
            }
        }

        PolicyDecision {
            records,
            approved_for_deletion: approved,
            hypothetical_deletes,
            hypothetical_keeps,
            hypothetical_reviews,
            budget_exhausted,
            mode: self.mode,
        }
    }

    /// Apply a guard observation window and update breach/recovery counters.
    ///
    /// Uses the stored `pressure_level` (set via `set_pressure_level`) to
    /// suppress calibration breach accumulation during green pressure —
    /// inaccurate predictions are harmless when no deletions would occur.
    pub fn observe_window(&mut self, guard: &GuardDiagnostics) {
        // Rate-limit observations to prevent the high-frequency pressure tick
        // loop (100ms at Critical, 250ms at Orange) from flooding the guard.
        if self.config.observe_min_interval_secs > 0 {
            if let Some(last) = self.last_observe_time
                && last.elapsed() < Duration::from_secs(self.config.observe_min_interval_secs)
            {
                return;
            }
            self.last_observe_time = Some(Instant::now());
        }

        let pressure_is_green = self.pressure_level == PressureLevel::Green;
        // A window is "clean" when the guard passes normally, OR when pressure
        // is green and the guard isn't actively failing (Unknown is OK during
        // green — miscalibrated predictions are harmless with plenty of free
        // space, and blocking recovery on guard calibration that can never
        // happen without deletions creates a deadlock).
        let is_clean = (guard.status == GuardStatus::Pass && !guard.e_process_alarm)
            || (pressure_is_green && guard.status != GuardStatus::Fail);

        if is_clean {
            self.consecutive_clean_windows += 1;
            self.consecutive_breach_windows = 0;
            // Note: recalibration_count is intentionally NOT reset on clean
            // windows. On machines with persistently miscalibrated guards,
            // brief non-Fail flickers happen between breach cycles. Resetting
            // the count on these would restart the log spam each time.
            // The counter resets naturally on daemon restart.

            // Check recovery condition — require both enough clean windows AND
            // a minimum cooldown period to prevent rapid canary↔fallback thrashing.
            if self.mode == ActiveMode::FallbackSafe
                && self.consecutive_clean_windows >= self.config.recovery_clean_windows
                && self.fallback_entered_at.is_none_or(|entered| {
                    entered.elapsed() >= Duration::from_secs(self.config.min_fallback_secs)
                })
            {
                self.recover_from_fallback();
            }
        } else {
            self.consecutive_clean_windows = 0;
            // Only accumulate breach windows when pressure is above green.
            // During green pressure, miscalibrated predictions are harmless.
            if guard.status == GuardStatus::Fail && !pressure_is_green {
                self.consecutive_breach_windows += 1;

                // After 100 consecutive breach windows, the guard model is
                // clearly miscalibrated for the current workload. Reset the
                // breach counter to prevent unbounded accumulation (previously
                // seen reaching 1296+ on production machines) and log a
                // recalibration notice. The guard will re-learn naturally
                // from fresh observations.
                if self.consecutive_breach_windows >= 100 {
                    self.recalibration_count += 1;
                    // Only log the first 3 recalibration cycles. After that,
                    // the guard is persistently miscalibrated for this workload
                    // and logging it just floods the journal.
                    if self.recalibration_count <= 3 {
                        eprintln!(
                            "[SBH-POLICY] recalibrating after {} consecutive breach windows — \
                             resetting breach counter (cycle {}, guard will re-learn from fresh data)",
                            self.consecutive_breach_windows, self.recalibration_count,
                        );
                    }
                    self.consecutive_breach_windows = 0;
                } else if self.consecutive_breach_windows == self.config.calibration_breach_windows
                    && self.recalibration_count < 3
                {
                    match self.config.resolved_calibration_breach_action() {
                        FallbackAction::Demote => {
                            let consecutive_windows = self.consecutive_breach_windows;
                            self.enter_fallback(FallbackReason::CalibrationBreach {
                                consecutive_windows,
                            });
                        }
                        FallbackAction::Advisory => eprintln!(
                            "[SBH-POLICY] calibration breach ({} consecutive windows) — \
                             continuing in current mode (calibration_breach_action = advisory)",
                            self.consecutive_breach_windows,
                        ),
                    }
                }
            } else {
                // Not a Fail breach — decay by 1 instead of accumulating.
                // This means 20 breach windows from a 10-min burst unwind in
                // ~10 min of non-Fail status, preventing unbounded accumulation.
                self.consecutive_breach_windows = self.consecutive_breach_windows.saturating_sub(1);
            }
        }
    }

    /// Emergency escalation: break the fallback_safe deadlock.
    ///
    /// When `fallback_safe` has been active for longer than the escalation threshold
    /// AND pressure is at Yellow or above, the engine cannot recover through normal
    /// clean-window gates (nothing can be deleted, so pressure never drops, so
    /// windows never become clean). This method auto-promotes to `Enforce` mode
    /// and activates a grace period during which re-entry to FallbackSafe is
    /// blocked, preventing the escalate→breach→fallback→escalate cycle.
    ///
    /// Returns `true` if escalation occurred.
    pub fn check_emergency_escalation(&mut self, pressure_is_critical: bool) -> bool {
        if self.mode != ActiveMode::FallbackSafe || !pressure_is_critical {
            return false;
        }

        // Don't escalate kill-switch fallbacks — those are operator-intended.
        if self.fallback_reason == Some(FallbackReason::KillSwitch) {
            return false;
        }

        let Some(entered_at) = self.fallback_entered_at else {
            return false;
        };

        let threshold = Duration::from_secs(FALLBACK_EMERGENCY_ESCALATION_SECS);
        if entered_at.elapsed() < threshold {
            return false;
        }

        // Escalation is a configured choice, not a given: off by default for
        // fleets that never earned Enforce.
        if !self.config.resolved_emergency_escalation() {
            return false;
        }
        // The disk is in crisis: land where the configuration lets automatic
        // recovery land, and where `previous` was Enforce, back in Enforce
        // (the 10-deletes/hour canary budget makes no dent). `none` leaves
        // this to `promote()` too.
        let Some(target) = self.auto_recovery_target() else {
            return false;
        };
        // Reset breach counters so calibration checks start fresh.
        self.fallback_reason = None;
        self.fallback_entered_at = None;
        self.emergency_escalated_at = Some(Instant::now());
        self.consecutive_breach_windows = 0;
        self.consecutive_clean_windows = 0;
        self.log_transition(
            "emergency_escalate",
            self.mode,
            target,
            Some("fallback_safe deadlock: pressure sustained at Yellow+".to_string()),
        );
        self.mode = target;
        true
    }

    // ──────────── mode transitions ────────────

    /// Manually promote: observe→canary or canary→enforce.
    ///
    /// Returns `true` if the transition was valid and applied.
    pub fn promote(&mut self) -> bool {
        match self.mode {
            ActiveMode::Observe => {
                self.apply_transition(ActiveMode::Canary, "promote");
                true
            }
            ActiveMode::Canary => {
                self.apply_transition(ActiveMode::Enforce, "promote");
                true
            }
            // The operator's way out of FallbackSafe (the only way when
            // `auto_recover_to = none`): back to the pre-fallback mode capped
            // at Canary, the mandatory re-proving gate. A kill switch holds.
            ActiveMode::FallbackSafe => {
                if self.config.kill_switch {
                    return false;
                }
                let target = match self.pre_fallback_mode {
                    ActiveMode::Enforce => ActiveMode::Canary,
                    other => other,
                };
                self.fallback_reason = None;
                self.fallback_entered_at = None;
                self.apply_transition(target, "promote");
                true
            }
            ActiveMode::Enforce => false,
        }
    }

    /// Manually demote: enforce→canary or canary→observe.
    ///
    /// Returns `true` if the transition was valid and applied.
    pub fn demote(&mut self) -> bool {
        match self.mode {
            ActiveMode::Enforce => {
                self.apply_transition(ActiveMode::Canary, "demote");
                true
            }
            ActiveMode::Canary => {
                self.apply_transition(ActiveMode::Observe, "demote");
                true
            }
            _ => false,
        }
    }

    /// Force fallback_safe mode with the given reason.
    ///
    /// Respects the emergency escalation grace period: if the engine was recently
    /// emergency-escalated from FallbackSafe, re-entry is blocked until the grace
    /// period expires. This prevents the deadlock cycle where calibration breach
    /// immediately re-triggers FallbackSafe after escalation. Kill-switch always
    /// overrides the grace period.
    pub fn enter_fallback(&mut self, reason: FallbackReason) {
        if self.mode != ActiveMode::FallbackSafe {
            // Respect emergency escalation grace period (kill-switch always overrides).
            if reason != FallbackReason::KillSwitch {
                if let Some(escalated_at) = self.emergency_escalated_at {
                    let grace = Duration::from_secs(EMERGENCY_GRACE_PERIOD_SECS);
                    if escalated_at.elapsed() < grace {
                        // Rate-limit suppression logs to once per 5 minutes.
                        // Without this, the message fires 5-8 times per scan cycle
                        // (every observe_window call) across all machines with
                        // active grace periods, flooding systemd journal.
                        if self
                            .last_suppression_log
                            .is_none_or(|t| t.elapsed() >= Duration::from_mins(5))
                        {
                            eprintln!(
                                "[SBH-POLICY] suppressing fallback ({reason}) — \
                                 emergency grace period active ({:.0}s remaining)",
                                grace.as_secs_f64() - escalated_at.elapsed().as_secs_f64()
                            );
                            self.last_suppression_log = Some(Instant::now());
                        }
                        return;
                    }
                    // Grace period expired — clear the marker.
                    self.emergency_escalated_at = None;
                }

                // Suppress calibration-breach fallbacks during the startup grace
                // period. The guard has no history on a fresh start so every window
                // reports Fail, causing FallbackSafe within seconds of restart.
                if matches!(reason, FallbackReason::CalibrationBreach { .. }) {
                    let startup_grace = Duration::from_secs(STARTUP_CALIBRATION_GRACE_SECS);
                    if self.started_at.elapsed() < startup_grace {
                        if self
                            .last_suppression_log
                            .is_none_or(|t| t.elapsed() >= Duration::from_mins(5))
                        {
                            eprintln!(
                                "[SBH-POLICY] suppressing calibration breach fallback — \
                                 startup grace period ({:.0}s remaining)",
                                startup_grace.as_secs_f64()
                                    - self.started_at.elapsed().as_secs_f64()
                            );
                            self.last_suppression_log = Some(Instant::now());
                        }
                        self.consecutive_breach_windows = 0;
                        return;
                    }
                }
            }

            let from = self.mode;
            self.pre_fallback_mode = self.mode;
            let reason_str = reason.to_string();
            self.last_fallback_reason = Some(reason_str.clone());
            self.fallback_reason = Some(reason);
            self.fallback_entered_at = Some(Instant::now());
            self.total_fallback_entries += 1;
            self.consecutive_clean_windows = 0;
            self.log_transition(
                "fallback",
                from,
                ActiveMode::FallbackSafe,
                Some(reason_str.clone()),
            );
            self.mode = ActiveMode::FallbackSafe;
            eprintln!("[SBH-POLICY] {from} → FallbackSafe (reason: {reason_str})");
        }
    }

    /// Update the policy configuration at runtime (e.g. on SIGHUP config reload).
    ///
    /// Propagates tunable parameters (budgets, loss values, window thresholds) and
    /// handles kill_switch transitions without resetting the mode state machine.
    pub fn update_config(&mut self, new_config: PolicyConfig) {
        let old_kill = self.config.kill_switch;
        let new_kill = new_config.kill_switch;

        self.config = new_config;

        // Kill-switch engaged: force fallback_safe.
        if !old_kill && new_kill {
            if self.mode != ActiveMode::FallbackSafe {
                self.enter_fallback(FallbackReason::KillSwitch);
            } else if self.fallback_reason.is_none() {
                // Already in fallback (e.g., configured initial mode); still record kill-switch cause.
                let reason = FallbackReason::KillSwitch;
                let reason_str = reason.to_string();
                self.fallback_reason = Some(reason);
                self.total_fallback_entries += 1;
                self.log_transition(
                    "fallback",
                    ActiveMode::FallbackSafe,
                    ActiveMode::FallbackSafe,
                    Some(reason_str),
                );
            }
        }
        // Kill-switch disengaged: recover if we were in fallback *due to* kill-switch.
        if old_kill
            && !new_kill
            && self.mode == ActiveMode::FallbackSafe
            && self.fallback_reason == Some(FallbackReason::KillSwitch)
        {
            self.recover_from_fallback();
        }
    }

    /// Generate a diagnostic snapshot of the policy engine state.
    #[must_use]
    pub fn diagnostics(&self) -> PolicyDiagnostics {
        PolicyDiagnostics {
            mode: self.mode,
            pre_fallback_mode: self.pre_fallback_mode,
            fallback_reason: self.fallback_reason.as_ref().map(ToString::to_string),
            total_decisions: self.total_decisions,
            total_fallback_entries: self.total_fallback_entries,
            consecutive_clean_windows: self.consecutive_clean_windows,
            consecutive_breach_windows: self.consecutive_breach_windows,
            canary_deletes_this_hour: self.canary_deletes_this_hour,
            transition_count: self.transition_log.len(),
        }
    }

    // ──────────── private helpers ────────────

    fn enforce_policy(
        &mut self,
        candidate: &CandidacyScore,
        guard: Option<&GuardDiagnostics>,
    ) -> DecisionAction {
        let proposed = candidate.decision.action;

        // If not a deletion candidate, no policy to enforce.
        if proposed != DecisionAction::Delete {
            return proposed;
        }

        // FallbackSafe and Observe never delete.
        if !self.mode.allows_deletion() {
            return DecisionAction::Keep;
        }

        // Decision-theoretic guard override: the guard penalty is scaled by
        // pressure level. The loss asymmetry is extreme — disk exhaustion
        // (machine down, all agents killed) vastly exceeds the cost of
        // deleting a regenerable build artifact.
        //
        // At Green: skip guard entirely (no urgency, no deletions anyway).
        // At Yellow: guard penalty × 0.25 — machine needs cleanup, but guard
        //   is often in permanent drift alarm from EWMA rate volatility at
        //   higher disk usage. Full penalty (1.0) caused rejection deadlocks
        //   on 3 production machines (vmi1156319/1227854/1149989 in v0.3.5-6).
        // At Orange: guard penalty × 0.10 (urgency high, strong candidates pass).
        // At Red/Critical: guard penalty = 0 (bypass guard, survival mode).
        if self.pressure_level >= PressureLevel::Yellow
            && let Some(diag) = guard
            && !diag.status.adaptive_allowed()
        {
            let penalty_scale = match self.pressure_level {
                PressureLevel::Green | PressureLevel::Red | PressureLevel::Critical => 0.0,
                PressureLevel::Yellow => 0.25,
                PressureLevel::Orange => 0.10,
            };
            let penalized_delete_loss = self
                .config
                .guard_penalty
                .mul_add(penalty_scale, candidate.decision.expected_loss_delete);
            if penalized_delete_loss >= candidate.decision.expected_loss_keep {
                return DecisionAction::Keep;
            }
        }

        // Canary mode: check hourly budget. The decision that hits the cap is
        // Keep either way; `canary_budget_action` decides whether the canary
        // also pauses in FallbackSafe until clean windows recover it.
        if self.mode == ActiveMode::Canary {
            self.rotate_canary_hour();
            if self.canary_deletes_this_hour >= self.config.max_canary_deletes_per_hour {
                match self.config.canary_budget_action {
                    CanaryBudgetAction::Demote => {
                        self.enter_fallback(FallbackReason::CanaryBudgetExhausted);
                    }
                    CanaryBudgetAction::Keep => {}
                }
                return DecisionAction::Keep;
            }
            self.canary_deletes_this_hour += 1;
        }

        DecisionAction::Delete
    }

    fn check_guard_triggers(&mut self, diag: &GuardDiagnostics) {
        // Only enter FallbackSafe from guard drift alarm at Orange+ pressure.
        //
        // At Yellow pressure (10-20% free), guard drift alarms are common during
        // compilation bursts — EWMA rate volatility poisons calibration even when
        // the disk isn't in genuine danger. Entering FallbackSafe at Yellow blocks
        // ALL deletions, creating a deadlock: disk can't be cleaned because guard
        // is alarmed, guard stays alarmed because disk stays full.
        //
        // At Yellow, the penalty-scaled guard override (0.25× penalty) in
        // enforce_policy already handles uncertain guard state by allowing
        // high-confidence candidates through. FallbackSafe is reserved for
        // genuine danger (Orange+) where we need full safety lockdown.
        //
        // Also suppressed when:
        // - Already in FallbackSafe (no-op)
        // - Guard has too few observations (< 30) — freshly started guard
        //   with unreliable EWMA should not trigger FallbackSafe
        if diag.e_process_alarm
            && self.mode != ActiveMode::FallbackSafe
            && self.pressure_level >= PressureLevel::Orange
            && diag.observation_count >= 30
        {
            self.enter_fallback(FallbackReason::GuardrailDrift);
        }
    }

    /// Update the cached pressure level. Call this each monitoring tick
    /// so that guard triggers, calibration breach checks, and decision-theoretic
    /// guard overrides can respond to current disk pressure.
    pub fn set_pressure_level(&mut self, level: PressureLevel) {
        self.pressure_level = level;
    }

    /// Expire the startup calibration grace period immediately.
    /// Used by tests to verify calibration breach behavior without waiting.
    pub fn bypass_startup_grace(&mut self) {
        self.started_at = Instant::now()
            .checked_sub(Duration::from_secs(STARTUP_CALIBRATION_GRACE_SECS + 1))
            .unwrap();
    }

    /// Where automatic recovery lands for this configuration, or `None`
    /// when only `promote()` may leave FallbackSafe.
    fn auto_recovery_target(&self) -> Option<ActiveMode> {
        match self.config.auto_recover_to {
            AutoRecoverTo::None => None,
            // The mandatory canary gate: Enforce must re-prove itself in
            // Canary; Observe stays Observe.
            AutoRecoverTo::Canary => Some(match self.pre_fallback_mode {
                ActiveMode::Enforce => ActiveMode::Canary,
                other => other,
            }),
            AutoRecoverTo::Previous => Some(self.pre_fallback_mode),
        }
    }

    fn recover_from_fallback(&mut self) {
        let Some(target) = self.auto_recovery_target() else {
            if self
                .last_suppression_log
                .is_none_or(|t| t.elapsed() >= Duration::from_mins(5))
            {
                eprintln!(
                    "[SBH-POLICY] clean windows would recover from FallbackSafe, but \
                     auto_recover_to = none: waiting for `sbh policy promote`"
                );
                self.last_suppression_log = Some(Instant::now());
            }
            return;
        };
        let from = self.mode;
        self.fallback_reason = None;
        self.fallback_entered_at = None;
        self.log_transition("recover", from, target, None);
        self.mode = target;
        eprintln!("[SBH-POLICY] {from} → {target} (recovered)");
    }

    /// The daemon could not persist `state.json`. Evidence that cannot be
    /// written must not keep driving deletions: with
    /// `serialization_failure_action = demote` the engine enters
    /// FallbackSafe; `advisory` only counts and logs.
    pub fn note_serialization_failure(&mut self) {
        self.serialization_failures = self.serialization_failures.saturating_add(1);
        match self.config.serialization_failure_action {
            FallbackAction::Demote => {
                if self.mode != ActiveMode::FallbackSafe {
                    self.enter_fallback(FallbackReason::SerializationFailure);
                }
            }
            FallbackAction::Advisory => eprintln!(
                "[SBH-POLICY] state file write failed ({} so far) — continuing in {} \
                 (serialization_failure_action = advisory)",
                self.serialization_failures, self.mode
            ),
        }
    }

    /// State-file write failures reported so far.
    #[must_use]
    pub const fn serialization_failures(&self) -> u64 {
        self.serialization_failures
    }

    /// Seconds the current mode has been active.
    #[must_use]
    pub fn mode_since_secs(&self) -> u64 {
        self.mode_since.elapsed().as_secs()
    }

    /// The most recent fallback reason, kept after recovery.
    #[must_use]
    pub fn last_fallback_reason(&self) -> Option<&str> {
        self.last_fallback_reason.as_deref()
    }

    fn apply_transition(&mut self, to: ActiveMode, kind: &str) {
        self.log_transition(kind, self.mode, to, None);
        self.mode = to;
    }

    fn log_transition(
        &mut self,
        kind: &str,
        from: ActiveMode,
        to: ActiveMode,
        reason: Option<String>,
    ) {
        if self.transition_log.len() >= 1000 {
            self.transition_log.drain(..500);
        }
        self.transition_log.push(TransitionEntry {
            transition: kind.to_string(),
            from: from.to_string(),
            to: to.to_string(),
            at_decision: self.total_decisions,
            reason,
        });
        self.transitions_total = self.transitions_total.saturating_add(1);
        self.mode_since = Instant::now();
    }

    /// Transitions recorded over the engine's lifetime (the log itself is
    /// bounded; this cursor is not).
    #[must_use]
    pub const fn transitions_total(&self) -> u64 {
        self.transitions_total
    }

    /// The transitions recorded after a caller had seen `seen_total` of
    /// them: what the daemon still has to log as `policy_transition` events.
    /// Entries already drained from the bounded log are gone.
    #[must_use]
    pub fn transitions_after(&self, seen_total: u64) -> &[TransitionEntry] {
        let unseen = usize::try_from(self.transitions_total.saturating_sub(seen_total))
            .unwrap_or(usize::MAX)
            .min(self.transition_log.len());
        &self.transition_log[self.transition_log.len() - unseen..]
    }

    fn rotate_canary_hour(&mut self) {
        if self.canary_hour_start.elapsed() >= std::time::Duration::from_hours(1) {
            self.canary_deletes_this_hour = 0;
            self.canary_hour_start = Instant::now();
        }
    }
}

// ──────────────────── diagnostics ────────────────────

/// Snapshot of the policy engine state for status reporting.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyDiagnostics {
    /// Current active mode.
    pub mode: ActiveMode,
    /// Mode before fallback (for recovery target).
    pub pre_fallback_mode: ActiveMode,
    /// Reason for current fallback (if applicable).
    pub fallback_reason: Option<String>,
    /// Total decisions made.
    pub total_decisions: u64,
    /// Total times fallback was entered.
    pub total_fallback_entries: u64,
    /// Consecutive clean guard windows (for recovery tracking).
    pub consecutive_clean_windows: usize,
    /// Consecutive breach windows (for fallback trigger).
    pub consecutive_breach_windows: usize,
    /// Canary deletions in the current hour.
    pub canary_deletes_this_hour: usize,
    /// Number of mode transitions recorded.
    pub transition_count: usize,
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::guardrails::GuardDiagnostics;
    use crate::scanner::decision_record::ActionRecord;
    use crate::scanner::patterns::{ArtifactCategory, ArtifactClassification};
    use crate::scanner::scoring::{
        CandidacyScore, DecisionAction, DecisionOutcome, EvidenceLedger, EvidenceTerm, ScoreFactors,
    };
    use std::path::PathBuf;
    use std::time::Duration;

    fn default_config() -> PolicyConfig {
        PolicyConfig {
            initial_mode: ActiveMode::Observe,
            // Disable cooldown for unit tests so recovery is instant.
            min_fallback_secs: 0,
            observe_min_interval_secs: 0,
            ..PolicyConfig::default()
        }
    }

    fn sample_candidate(action: DecisionAction, score: f64) -> CandidacyScore {
        CandidacyScore {
            path: PathBuf::from("/data/projects/test/.target_opus"),
            identity: None,
            total_score: score,
            factors: ScoreFactors {
                location: 0.85,
                name: 0.90,
                age: 1.0,
                size: 0.70,
                structure: 0.95,
                pressure_multiplier: 1.5,
            },
            vetoed: false,
            veto_reason: None,
            classification: ArtifactClassification {
                pattern_name: ".target*".into(),
                category: ArtifactCategory::RustTarget,
                name_confidence: 0.9,
                structural_confidence: 0.95,
                combined_confidence: 0.92,
            },
            size_bytes: 3_000_000_000,
            age: Duration::from_hours(5),
            decision: DecisionOutcome {
                action,
                posterior_abandoned: 0.87,
                expected_loss_keep: 8.7,
                expected_loss_delete: 1.3,
                calibration_score: 0.82,
                fallback_active: false,
                certainty: crate::scanner::scoring::ArtifactCertainty::Definite,
                posterior_floor_applied: false,
            },
            ledger: EvidenceLedger {
                terms: vec![EvidenceTerm {
                    name: "location",
                    weight: 0.25,
                    value: 0.85,
                    contribution: 0.2125,
                }],
                summary: "test".to_string(),
            },
        }
    }

    fn passing_guard() -> GuardDiagnostics {
        GuardDiagnostics {
            status: GuardStatus::Pass,
            observation_count: 25,
            median_rate_error: 0.12,
            conservative_fraction: 0.80,
            forecast: None,
            e_process_value: 3.5,
            e_process_alarm: false,
            consecutive_clean: 5,
            reason: "calibration verified".to_string(),
        }
    }

    fn failing_guard() -> GuardDiagnostics {
        GuardDiagnostics {
            status: GuardStatus::Fail,
            observation_count: 30,
            median_rate_error: 0.45,
            conservative_fraction: 0.55,
            forecast: None,
            e_process_value: 25.0,
            e_process_alarm: true,
            consecutive_clean: 0,
            reason: "drift detected".to_string(),
        }
    }

    fn behavior(
        scan_aggressiveness: ScanAggressiveness,
        cleanup_action: CleanupAction,
        ballast_action: BallastAction,
        notification_priority: NotificationPriority,
    ) -> BehaviorMode {
        BehaviorMode {
            scan_aggressiveness,
            cleanup_action,
            ballast_action,
            notification_priority,
        }
    }

    #[test]
    fn v0_6_default_acts_at_orange_and_never_reduces_cleanup_under_memory_pressure() {
        let table = BehaviorDispatchTable::default();
        assert_eq!(table.preset(), BehaviorPreset::V0_6);

        // Normal memory: Orange deletes definite artifacts and releases ballast;
        // Red/Critical delete any definite candidate and release first.
        let orange = table.mode_for(MemoryPressureLevel::Normal, PressureLevel::Orange);
        assert_eq!(orange.cleanup_action, CleanupAction::DefiniteCandidates);
        assert_eq!(orange.ballast_action, BallastAction::Release);
        let yellow = table.mode_for(MemoryPressureLevel::Normal, PressureLevel::Yellow);
        assert_eq!(
            yellow.cleanup_action,
            CleanupAction::HighConfidenceCandidates
        );
        assert_eq!(yellow.ballast_action, BallastAction::None);
        for disk in [PressureLevel::Red, PressureLevel::Critical] {
            let mode = table.mode_for(MemoryPressureLevel::Normal, disk);
            assert_eq!(mode.cleanup_action, CleanupAction::AnyDefiniteCandidate);
            assert_eq!(mode.ballast_action, BallastAction::ReleaseFirst);
        }
        assert_eq!(
            table
                .mode_for(MemoryPressureLevel::Normal, PressureLevel::Critical)
                .notification_priority,
            NotificationPriority::Emergency
        );

        // Memory pressure lowers scanning but never the cleanup/ballast posture.
        for memory in [MemoryPressureLevel::Warn, MemoryPressureLevel::Critical] {
            for disk in BEHAVIOR_DISK_LEVELS {
                let floor = table.mode_for(MemoryPressureLevel::Normal, disk);
                let mode = table.mode_for(memory, disk);
                assert!(
                    mode.cleanup_action.rank() >= floor.cleanup_action.rank(),
                    "memory={memory:?} disk={disk:?} reduced cleanup"
                );
                assert!(
                    mode.ballast_action.rank() >= floor.ballast_action.rank(),
                    "memory={memory:?} disk={disk:?} reduced ballast"
                );
            }
        }
        assert_eq!(
            table
                .mode_for(MemoryPressureLevel::Critical, PressureLevel::Green)
                .scan_aggressiveness,
            ScanAggressiveness::Skip
        );
        assert_eq!(
            table
                .mode_for(MemoryPressureLevel::Warn, PressureLevel::Orange)
                .scan_aggressiveness,
            ScanAggressiveness::Light
        );
    }

    #[test]
    fn v0_5_preset_reproduces_the_legacy_identify_only_cells() {
        let table = BehaviorDispatchTable::from_preset(BehaviorPreset::V0_5);
        assert_eq!(table.preset(), BehaviorPreset::V0_5);

        // Yellow and Orange shared one column; Red and Critical shared another.
        for disk in [PressureLevel::Yellow, PressureLevel::Orange] {
            let mode = table.mode_for(MemoryPressureLevel::Normal, disk);
            assert_eq!(mode.cleanup_action, CleanupAction::IdentifyOnly);
            assert_eq!(mode.ballast_action, BallastAction::None);
        }
        for disk in [PressureLevel::Red, PressureLevel::Critical] {
            let mode = table.mode_for(MemoryPressureLevel::Normal, disk);
            assert_eq!(mode.cleanup_action, CleanupAction::DefiniteCandidates);
            assert_eq!(mode.ballast_action, BallastAction::Release);
        }
        let green = table.mode_for(MemoryPressureLevel::Normal, PressureLevel::Green);
        assert_eq!(green.cleanup_action, CleanupAction::None);
        assert_eq!(
            table
                .mode_for(MemoryPressureLevel::Critical, PressureLevel::Yellow)
                .cleanup_action,
            CleanupAction::MostPromisingCandidates
        );
        assert_eq!(
            table.mode_for(MemoryPressureLevel::Critical, PressureLevel::Critical),
            behavior(
                ScanAggressiveness::DefiniteOnly,
                CleanupAction::AnyDefiniteCandidate,
                BallastAction::ReleaseFirst,
                NotificationPriority::Emergency,
            )
        );
    }

    #[test]
    fn custom_cells_override_only_under_the_custom_preset() {
        let quiet_orange = BehaviorCellConfig {
            scan: ScanAggressiveness::Light,
            cleanup: CleanupAction::IdentifyOnly,
            ballast: BallastAction::None,
            notify: NotificationPriority::Low,
        };
        let mut config = BehaviorConfig {
            preset: BehaviorPreset::Custom,
            memory_never_reduces_cleanup: false,
            cells: BTreeMap::from([("normal_orange".to_string(), quiet_orange)]),
        };

        let table = BehaviorDispatchTable::from_config(&config).expect("valid custom config");
        assert_eq!(
            table.mode_for(MemoryPressureLevel::Normal, PressureLevel::Orange),
            BehaviorMode::from(quiet_orange)
        );
        // Untouched cells keep the v0.6 base.
        assert_eq!(
            table
                .mode_for(MemoryPressureLevel::Normal, PressureLevel::Red)
                .cleanup_action,
            CleanupAction::AnyDefiniteCandidate
        );

        // The same cells under a named preset are ignored (env rollback stays safe).
        config.preset = BehaviorPreset::V0_6;
        let table =
            BehaviorDispatchTable::from_config(&config).expect("named preset ignores cells");
        assert_eq!(
            table
                .mode_for(MemoryPressureLevel::Normal, PressureLevel::Orange)
                .cleanup_action,
            CleanupAction::DefiniteCandidates
        );
    }

    #[test]
    fn custom_cell_keys_name_a_real_cell_or_are_rejected() {
        let cell = BehaviorCellConfig {
            scan: ScanAggressiveness::Normal,
            cleanup: CleanupAction::None,
            ballast: BallastAction::None,
            notify: NotificationPriority::None,
        };
        for (key, fragment) in [
            ("orange", "expected `<memory>_<disk>`"),
            ("hot_orange", "unknown memory level"),
            ("normal_purple", "unknown disk level"),
        ] {
            let config = BehaviorConfig {
                preset: BehaviorPreset::Custom,
                memory_never_reduces_cleanup: true,
                cells: BTreeMap::from([(key.to_string(), cell)]),
            };
            let error =
                BehaviorDispatchTable::from_config(&config).expect_err("bad key must be rejected");
            assert!(error.contains(fragment), "{key}: {error}");
        }
    }

    #[test]
    fn never_reduce_rule_lifts_memory_rows_to_the_normal_floor() {
        let low = BehaviorCellConfig {
            scan: ScanAggressiveness::Light,
            cleanup: CleanupAction::None,
            ballast: BallastAction::None,
            notify: NotificationPriority::Low,
        };
        let config = BehaviorConfig {
            preset: BehaviorPreset::Custom,
            memory_never_reduces_cleanup: true,
            cells: BTreeMap::from([("warn_red".to_string(), low)]),
        };
        let table = BehaviorDispatchTable::from_config(&config).expect("valid");
        let lifted = table.mode_for(MemoryPressureLevel::Warn, PressureLevel::Red);
        assert_eq!(lifted.scan_aggressiveness, ScanAggressiveness::Light);
        assert_eq!(lifted.cleanup_action, CleanupAction::AnyDefiniteCandidate);
        assert_eq!(lifted.ballast_action, BallastAction::ReleaseFirst);

        let config = BehaviorConfig {
            memory_never_reduces_cleanup: false,
            ..config
        };
        let table = BehaviorDispatchTable::from_config(&config).expect("valid");
        assert_eq!(
            table.mode_for(MemoryPressureLevel::Warn, PressureLevel::Red),
            BehaviorMode::from(low)
        );
    }

    #[test]
    fn preset_parses_every_documented_spelling_and_rejects_others() {
        assert_eq!("v0.6".parse::<BehaviorPreset>(), Ok(BehaviorPreset::V0_6));
        assert_eq!("V0_5".parse::<BehaviorPreset>(), Ok(BehaviorPreset::V0_5));
        assert_eq!(
            " custom ".parse::<BehaviorPreset>(),
            Ok(BehaviorPreset::Custom)
        );
        let error = "v9".parse::<BehaviorPreset>().expect_err("unknown preset");
        assert!(error.contains(BehaviorPreset::ALLOWED));

        let parsed: BehaviorConfig =
            toml::from_str("preset = \"v0.5\"\n").expect("toml preset parses");
        assert_eq!(parsed.preset, BehaviorPreset::V0_5);
        assert!(parsed.memory_never_reduces_cleanup);
        let error = toml::from_str::<BehaviorConfig>("preset = \"v9\"\n")
            .expect_err("unknown toml preset is rejected");
        assert!(error.to_string().contains("v9"));
    }

    #[test]
    fn render_lists_every_cell_with_its_preset() {
        let rendered = BehaviorDispatchTable::default().render();
        assert!(rendered.starts_with("behavior matrix preset=v0.6"));
        for memory in ["memory=normal", "memory=warn", "memory=critical"] {
            assert!(rendered.contains(memory), "{rendered}");
        }
        assert_eq!(rendered.matches(" green=").count(), 3);
        assert_eq!(rendered.matches(" critical=").count(), 3);
        assert!(rendered.contains("orange=aggressive/definite_candidates/release/normal"));
    }

    #[test]
    fn behavior_dispatch_table_normalizes_native_pressure_levels() {
        assert_eq!(
            BehaviorPressureLevel::from_memory_pressure(MemoryPressureLevel::Normal),
            BehaviorPressureLevel::Normal
        );
        assert_eq!(
            BehaviorPressureLevel::from_memory_pressure(MemoryPressureLevel::Warn),
            BehaviorPressureLevel::Warn
        );
        assert_eq!(
            BehaviorPressureLevel::from_memory_pressure(MemoryPressureLevel::Unknown),
            BehaviorPressureLevel::Warn
        );
        assert_eq!(
            BehaviorPressureLevel::from_memory_pressure(MemoryPressureLevel::Critical),
            BehaviorPressureLevel::Critical
        );

        let table = BehaviorDispatchTable::default();
        assert_eq!(
            table.mode_for(MemoryPressureLevel::Unknown, PressureLevel::Green),
            table.mode_for_levels(BehaviorPressureLevel::Warn, PressureLevel::Green)
        );
        assert_eq!(
            table.mode_for(MemoryPressureLevel::Warn, PressureLevel::Red),
            table.mode_for_levels(BehaviorPressureLevel::Warn, PressureLevel::Red)
        );
    }

    #[test]
    fn behavior_dispatch_table_is_identical_for_linux_and_macos_transition_sources() {
        let table = BehaviorDispatchTable::default();
        let linux_transitions = [
            ("linux-memory-pressure-normal", MemoryPressureLevel::Normal),
            ("linux-memory-pressure-warn", MemoryPressureLevel::Warn),
            (
                "linux-memory-pressure-critical",
                MemoryPressureLevel::Critical,
            ),
        ];
        let macos_transitions = [
            ("macos-memory-pressure-normal", MemoryPressureLevel::Normal),
            ("macos-memory-pressure-warn", MemoryPressureLevel::Warn),
            (
                "macos-memory-pressure-critical",
                MemoryPressureLevel::Critical,
            ),
        ];
        let disk_transitions = [
            ("disk-green", PressureLevel::Green),
            ("disk-yellow", PressureLevel::Yellow),
            ("disk-orange", PressureLevel::Orange),
            ("disk-red", PressureLevel::Red),
            ("disk-critical", PressureLevel::Critical),
        ];

        for ((linux_source, linux_memory), (macos_source, macos_memory)) in
            linux_transitions.into_iter().zip(macos_transitions)
        {
            let normalized_memory = BehaviorPressureLevel::from_memory_pressure(linux_memory);
            assert_eq!(
                normalized_memory,
                BehaviorPressureLevel::from_memory_pressure(macos_memory),
                "{linux_source} and {macos_source} must normalize into the same behavior row"
            );

            for (disk_source, disk_level) in disk_transitions {
                let expected = table.mode_for_levels(normalized_memory, disk_level);
                assert_eq!(
                    table.mode_for(linux_memory, disk_level),
                    expected,
                    "{linux_source} with {disk_source} must use the shared behavior matrix"
                );
                assert_eq!(
                    table.mode_for(macos_memory, disk_level),
                    expected,
                    "{macos_source} with {disk_source} must use the shared behavior matrix"
                );
                assert_eq!(
                    table.mode_for(linux_memory, disk_level),
                    table.mode_for(macos_memory, disk_level),
                    "{linux_source} and {macos_source} diverged for {disk_source}"
                );
            }
        }
    }

    // ──── mode lifecycle tests ────

    #[test]
    fn starts_in_enforce_by_default() {
        let engine = PolicyEngine::new(PolicyConfig::default());
        assert_eq!(engine.mode(), ActiveMode::Enforce);
    }

    #[test]
    fn kill_switch_forces_fallback() {
        let mut config = default_config();
        config.kill_switch = true;
        let engine = PolicyEngine::new(config);
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
        assert_eq!(engine.fallback_reason(), Some(&FallbackReason::KillSwitch));
        assert_eq!(engine.total_fallback_entries(), 1);
        assert_eq!(engine.transition_log().len(), 1);
        assert_eq!(engine.transition_log()[0].transition, "fallback");
    }

    #[test]
    fn kill_switch_in_fallback_initial_mode_still_records_reason_and_entry() {
        let mut config = default_config();
        config.initial_mode = ActiveMode::FallbackSafe;
        config.kill_switch = true;

        let engine = PolicyEngine::new(config);
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
        assert_eq!(engine.fallback_reason(), Some(&FallbackReason::KillSwitch));
        assert_eq!(engine.total_fallback_entries(), 1);
        assert_eq!(engine.transition_log().len(), 1);
    }

    #[test]
    fn promote_observe_to_canary() {
        let mut engine = PolicyEngine::new(default_config());
        assert!(engine.promote());
        assert_eq!(engine.mode(), ActiveMode::Canary);
    }

    #[test]
    fn promote_canary_to_enforce() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote();
        assert!(engine.promote());
        assert_eq!(engine.mode(), ActiveMode::Enforce);
    }

    #[test]
    fn promote_enforce_fails() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote();
        engine.promote();
        assert!(!engine.promote());
        assert_eq!(engine.mode(), ActiveMode::Enforce);
    }

    #[test]
    fn demote_enforce_to_canary() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote();
        engine.promote();
        assert!(engine.demote());
        assert_eq!(engine.mode(), ActiveMode::Canary);
    }

    #[test]
    fn demote_canary_to_observe() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote();
        assert!(engine.demote());
        assert_eq!(engine.mode(), ActiveMode::Observe);
    }

    #[test]
    fn demote_observe_fails() {
        let mut engine = PolicyEngine::new(default_config());
        assert!(!engine.demote());
        assert_eq!(engine.mode(), ActiveMode::Observe);
    }

    #[test]
    fn fallback_safe_preserves_pre_mode() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote(); // canary
        engine.enter_fallback(FallbackReason::GuardrailDrift);
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
        assert_eq!(engine.pre_fallback_mode, ActiveMode::Canary);
    }

    #[test]
    fn recovery_restores_pre_fallback_mode() {
        let mut config = default_config();
        config.recovery_clean_windows = 2;
        let mut engine = PolicyEngine::new(config);
        engine.promote(); // canary
        engine.enter_fallback(FallbackReason::GuardrailDrift);

        let good = passing_guard();
        engine.observe_window(&good);
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
        engine.observe_window(&good);
        assert_eq!(engine.mode(), ActiveMode::Canary);
        assert!(engine.fallback_reason().is_none());
    }

    #[test]
    fn recovery_from_enforce_caps_at_canary() {
        let mut config = default_config();
        config.recovery_clean_windows = 2;
        let mut engine = PolicyEngine::new(config);
        engine.promote(); // observe → canary
        engine.promote(); // canary → enforce
        assert_eq!(engine.mode(), ActiveMode::Enforce);

        engine.enter_fallback(FallbackReason::GuardrailDrift);
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);

        // Recovery must return to Canary, NOT Enforce — the mandatory
        // canary gate must be re-traversed after a fallback event.
        let good = passing_guard();
        engine.observe_window(&good);
        engine.observe_window(&good);
        assert_eq!(engine.mode(), ActiveMode::Canary);
        assert!(engine.fallback_reason().is_none());

        // Only an explicit promote returns to Enforce.
        engine.promote();
        assert_eq!(engine.mode(), ActiveMode::Enforce);
    }

    fn breaching_guard() -> GuardDiagnostics {
        GuardDiagnostics {
            status: GuardStatus::Fail,
            observation_count: 25,
            median_rate_error: 0.45,
            conservative_fraction: 0.55,
            forecast: None,
            e_process_value: 10.0,
            e_process_alarm: false,
            consecutive_clean: 0,
            reason: "bad calibration".to_string(),
        }
    }

    /// Production path: `calibration_breach_windows` consecutive guard-FAIL
    /// windows under pressure. With the default resolution below Enforce
    /// (`demote`) the engine enters FallbackSafe with the breach recorded.
    #[test]
    fn calibration_breach_demotes_by_default_below_enforce() {
        let mut config = default_config();
        config.calibration_breach_windows = 2;
        assert_eq!(
            config.resolved_calibration_breach_action(),
            FallbackAction::Demote
        );
        let mut engine = PolicyEngine::new(config);
        engine.bypass_startup_grace();
        engine.promote(); // canary
        engine.set_pressure_level(PressureLevel::Orange);
        engine.observe_window(&breaching_guard());
        assert_eq!(engine.mode(), ActiveMode::Canary);
        engine.observe_window(&breaching_guard());
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
        assert_eq!(
            engine.fallback_reason(),
            Some(&FallbackReason::CalibrationBreach {
                consecutive_windows: 2
            })
        );
        assert_eq!(
            engine.last_fallback_reason(),
            Some("calibration breach (2 windows)")
        );
    }

    /// The unset default for an `enforce` fleet is advisory; an explicit
    /// `advisory` on any fleet logs and keeps the mode.
    #[test]
    fn calibration_breach_action_defaults_and_explicit_values() {
        let enforce = PolicyConfig {
            initial_mode: ActiveMode::Enforce,
            ..PolicyConfig::default()
        };
        assert_eq!(
            enforce.resolved_calibration_breach_action(),
            FallbackAction::Advisory
        );
        assert!(enforce.resolved_emergency_escalation());
        let observe = PolicyConfig {
            initial_mode: ActiveMode::Observe,
            ..PolicyConfig::default()
        };
        assert_eq!(
            observe.resolved_calibration_breach_action(),
            FallbackAction::Demote
        );
        assert!(!observe.resolved_emergency_escalation());
        let explicit = PolicyConfig {
            initial_mode: ActiveMode::Enforce,
            calibration_breach_action: Some(FallbackAction::Demote),
            emergency_escalation: Some(false),
            ..PolicyConfig::default()
        };
        assert_eq!(
            explicit.resolved_calibration_breach_action(),
            FallbackAction::Demote
        );
        assert!(!explicit.resolved_emergency_escalation());
    }

    /// Production path for `CanaryBudgetExhausted`: the decision that hits
    /// the cap is Keep; with `demote` the canary pauses in FallbackSafe,
    /// with the default `keep` it stays in Canary.
    #[test]
    fn canary_budget_exhaustion_demotes_or_keeps_as_configured() {
        assert_eq!(
            PolicyConfig::default().canary_budget_action,
            CanaryBudgetAction::Keep
        );
        for (action, expected_mode) in [
            (CanaryBudgetAction::Demote, ActiveMode::FallbackSafe),
            (CanaryBudgetAction::Keep, ActiveMode::Canary),
        ] {
            let mut config = default_config();
            config.max_canary_deletes_per_hour = 1;
            config.canary_budget_action = action;
            let mut engine = PolicyEngine::new(config);
            engine.promote(); // canary
            let candidates = vec![
                sample_candidate(DecisionAction::Delete, 2.5),
                sample_candidate(DecisionAction::Delete, 2.3),
            ];
            let decision = engine.evaluate(&candidates, Some(&passing_guard()));
            assert_eq!(decision.approved_for_deletion.len(), 1, "{action:?}");
            assert_eq!(engine.mode(), expected_mode, "{action:?}");
            if action == CanaryBudgetAction::Demote {
                assert_eq!(
                    engine.fallback_reason(),
                    Some(&FallbackReason::CanaryBudgetExhausted)
                );
            }
        }
    }

    /// Production path for `SerializationFailure`: the daemon reports a
    /// failed state write; `demote` enters FallbackSafe, `advisory` counts.
    #[test]
    fn serialization_failure_demotes_or_advises() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote(); // canary
        engine.note_serialization_failure();
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
        assert_eq!(
            engine.fallback_reason(),
            Some(&FallbackReason::SerializationFailure)
        );
        assert_eq!(engine.serialization_failures(), 1);

        let mut config = default_config();
        config.serialization_failure_action = FallbackAction::Advisory;
        let mut engine = PolicyEngine::new(config);
        engine.promote();
        engine.note_serialization_failure();
        engine.note_serialization_failure();
        assert_eq!(engine.mode(), ActiveMode::Canary);
        assert_eq!(engine.serialization_failures(), 2);
        assert!(engine.fallback_reason().is_none());
    }

    /// `auto_recover_to`: `none` never leaves FallbackSafe without
    /// `promote()`; `canary` caps recovery at Canary; `previous` returns to
    /// the pre-fallback mode, Enforce included.
    #[test]
    fn auto_recover_to_decides_where_recovery_lands() {
        let cases = [
            (
                AutoRecoverTo::None,
                ActiveMode::Enforce,
                ActiveMode::FallbackSafe,
            ),
            (
                AutoRecoverTo::Canary,
                ActiveMode::Enforce,
                ActiveMode::Canary,
            ),
            (
                AutoRecoverTo::Canary,
                ActiveMode::Observe,
                ActiveMode::Observe,
            ),
            (
                AutoRecoverTo::Previous,
                ActiveMode::Enforce,
                ActiveMode::Enforce,
            ),
        ];
        for (recover, initial, expected) in cases {
            let config = PolicyConfig {
                initial_mode: initial,
                auto_recover_to: recover,
                recovery_clean_windows: 1,
                min_fallback_secs: 0,
                observe_min_interval_secs: 0,
                ..PolicyConfig::default()
            };
            let mut engine = PolicyEngine::new(config);
            engine.enter_fallback(FallbackReason::GuardrailDrift);
            engine.observe_window(&passing_guard());
            assert_eq!(engine.mode(), expected, "{recover:?} from {initial:?}");
            assert_eq!(
                engine.last_fallback_reason(),
                Some("guardrail drift alarm"),
                "the last reason survives recovery"
            );
        }
        // `none` still leaves through promote().
        let config = PolicyConfig {
            initial_mode: ActiveMode::Canary,
            auto_recover_to: AutoRecoverTo::None,
            recovery_clean_windows: 1,
            min_fallback_secs: 0,
            observe_min_interval_secs: 0,
            ..PolicyConfig::default()
        };
        let mut engine = PolicyEngine::new(config);
        engine.enter_fallback(FallbackReason::GuardrailDrift);
        engine.observe_window(&passing_guard());
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
        assert!(engine.promote());
        assert_ne!(engine.mode(), ActiveMode::FallbackSafe);
    }

    #[test]
    fn calibration_breach_is_advisory_only() {
        let mut config = default_config();
        config.calibration_breach_windows = 2;
        config.calibration_breach_action = Some(FallbackAction::Advisory);
        let mut engine = PolicyEngine::new(config);
        engine.bypass_startup_grace();
        engine.promote(); // canary

        let bad = GuardDiagnostics {
            status: GuardStatus::Fail,
            observation_count: 25,
            median_rate_error: 0.45,
            conservative_fraction: 0.55,
            forecast: None,
            e_process_value: 10.0,
            e_process_alarm: false,
            consecutive_clean: 0,
            reason: "bad calibration".to_string(),
        };

        engine.observe_window(&bad);
        assert_eq!(engine.mode(), ActiveMode::Canary);
        engine.observe_window(&bad);
        // CalibrationBreach is advisory only — should NOT enter FallbackSafe.
        assert_eq!(engine.mode(), ActiveMode::Canary);
        assert!(engine.fallback_reason().is_none());
    }

    #[test]
    fn drift_alarm_triggers_fallback() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote(); // canary
        // Guard drift only triggers fallback at Orange+ pressure (v0.3.8+).
        engine.set_pressure_level(PressureLevel::Orange);
        let drift = failing_guard();
        engine.evaluate(&[], Some(&drift));
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
    }

    // ──── losing-ground invariant (#16 item 3, partial) ────
    //
    // Contract: while pressure stays at Yellow+ the engine must not remain
    // self-throttled in FallbackSafe (clean=0 / no-delete) forever. After
    // FALLBACK_EMERGENCY_ESCALATION_SECS of sustained pressure it must
    // escalate to Enforce so deletion capacity exists again.

    #[test]
    fn emergency_escalation_breaks_fallback_deadlock_under_sustained_pressure() {
        // An enforce fleet that opted into escalation landing back where it
        // was: the pre-2.16 behavior, now spelled out in the config.
        let mut config = default_config();
        config.emergency_escalation = Some(true);
        config.auto_recover_to = AutoRecoverTo::Previous;
        let mut engine = PolicyEngine::new(config);
        engine.promote(); // canary
        engine.promote(); // enforce
        engine.set_pressure_level(PressureLevel::Orange);
        engine.evaluate(&[], Some(&failing_guard()));
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);

        // FallbackSafe blocks all deletions — the potential deadlock state.
        let decision = engine.evaluate(
            &[sample_candidate(DecisionAction::Delete, 2.5)],
            Some(&passing_guard()),
        );
        assert!(
            decision.approved_for_deletion.is_empty(),
            "policy must approve no deletions here, approved {}",
            decision.approved_for_deletion.len()
        );

        // Freshly entered fallback: below the escalation threshold, no
        // escalation yet even under sustained pressure.
        assert!(!engine.check_emergency_escalation(true));
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);

        // Back-date the fallback entry past the escalation threshold to model
        // 5+ minutes of sustained Yellow+ pressure deterministically.
        engine.fallback_entered_at = engine.fallback_entered_at.and_then(|entered| {
            entered.checked_sub(Duration::from_secs(FALLBACK_EMERGENCY_ESCALATION_SECS + 1))
        });
        assert!(
            engine.fallback_entered_at.is_some(),
            "test clock could not be back-dated"
        );

        // Pressure below Yellow never escalates (recovery handles that path).
        assert!(!engine.check_emergency_escalation(false));
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);

        // Sustained Yellow+ pressure escalates straight to Enforce: the daemon
        // regains deletion capacity instead of losing ground at clean=0.
        assert!(engine.check_emergency_escalation(true));
        assert_eq!(engine.mode(), ActiveMode::Enforce);
        let decision = engine.evaluate(
            &[sample_candidate(DecisionAction::Delete, 2.5)],
            Some(&passing_guard()),
        );
        assert_eq!(
            decision.approved_for_deletion.len(),
            1,
            "post-escalation the engine must approve safe deletions again"
        );
    }

    /// Escalation is off for fleets below Enforce unless configured, and it
    /// lands where `auto_recover_to` points: `canary` caps it at Canary,
    /// `none` leaves the deadlock to `promote()`.
    #[test]
    fn emergency_escalation_is_configured_not_given() {
        let back_date = |engine: &mut PolicyEngine| {
            engine.fallback_entered_at = engine.fallback_entered_at.and_then(|entered| {
                entered.checked_sub(Duration::from_secs(FALLBACK_EMERGENCY_ESCALATION_SECS + 1))
            });
        };
        // Default observe fleet: never escalates.
        let mut engine = PolicyEngine::new(default_config());
        engine.promote();
        engine.enter_fallback(FallbackReason::GuardrailDrift);
        back_date(&mut engine);
        assert!(!engine.check_emergency_escalation(true));
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);

        // Explicitly on with the default target: Enforce lands in Canary.
        let mut config = default_config();
        config.emergency_escalation = Some(true);
        let mut engine = PolicyEngine::new(config);
        engine.promote();
        engine.promote();
        engine.enter_fallback(FallbackReason::GuardrailDrift);
        back_date(&mut engine);
        assert!(engine.check_emergency_escalation(true));
        assert_eq!(engine.mode(), ActiveMode::Canary);

        // Explicitly on but auto_recover_to = none: escalation has nowhere to go.
        let mut config = default_config();
        config.emergency_escalation = Some(true);
        config.auto_recover_to = AutoRecoverTo::None;
        let mut engine = PolicyEngine::new(config);
        engine.promote();
        engine.enter_fallback(FallbackReason::GuardrailDrift);
        back_date(&mut engine);
        assert!(!engine.check_emergency_escalation(true));
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
    }

    #[test]
    fn emergency_escalation_never_overrides_kill_switch() {
        let mut config = default_config();
        config.kill_switch = true;
        let mut engine = PolicyEngine::new(config);
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);

        // Back-date far past the threshold: an operator kill switch must still
        // never be auto-escalated, no matter how long pressure is sustained.
        engine.fallback_entered_at = Instant::now()
            .checked_sub(Duration::from_secs(FALLBACK_EMERGENCY_ESCALATION_SECS * 10));
        assert!(!engine.check_emergency_escalation(true));
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
    }

    // ──── evaluation tests ────

    #[test]
    fn observe_mode_produces_no_deletions() {
        let mut engine = PolicyEngine::new(default_config());
        let candidates = vec![
            sample_candidate(DecisionAction::Delete, 2.5),
            sample_candidate(DecisionAction::Delete, 2.0),
        ];
        let guard = passing_guard();
        let decision = engine.evaluate(&candidates, Some(&guard));

        assert!(
            decision.approved_for_deletion.is_empty(),
            "policy must approve no deletions here, approved {}",
            decision.approved_for_deletion.len()
        );
        assert_eq!(decision.hypothetical_deletes, 2);
        assert_eq!(decision.records.len(), 2);
        assert_eq!(decision.mode, ActiveMode::Observe);
    }

    #[test]
    fn enforce_mode_approves_delete_candidates() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote();
        engine.promote(); // enforce
        let candidates = vec![
            sample_candidate(DecisionAction::Delete, 2.5),
            sample_candidate(DecisionAction::Keep, 0.5),
        ];
        let guard = passing_guard();
        let decision = engine.evaluate(&candidates, Some(&guard));

        assert_eq!(decision.approved_for_deletion.len(), 1);
        assert_eq!(decision.hypothetical_deletes, 1);
        assert_eq!(decision.hypothetical_keeps, 1);
    }

    #[test]
    fn canary_mode_respects_hourly_budget() {
        let mut config = default_config();
        config.max_canary_deletes_per_hour = 2;
        config.canary_budget_action = CanaryBudgetAction::Keep;
        let mut engine = PolicyEngine::new(config);
        engine.promote(); // canary

        let candidates = vec![
            sample_candidate(DecisionAction::Delete, 2.5),
            sample_candidate(DecisionAction::Delete, 2.3),
            sample_candidate(DecisionAction::Delete, 2.1),
        ];
        let guard = passing_guard();
        let decision = engine.evaluate(&candidates, Some(&guard));

        // Should approve 2, then cap further deletions (stays in Canary).
        assert_eq!(decision.approved_for_deletion.len(), 2);
        assert_eq!(engine.mode(), ActiveMode::Canary);
    }

    #[test]
    fn observe_mode_respects_hypothetical_budget() {
        let mut config = default_config();
        config.max_hypothetical_deletes = 2;
        config.max_candidates_per_loop = 100;
        let mut engine = PolicyEngine::new(config);

        let candidates = vec![
            sample_candidate(DecisionAction::Delete, 2.5),
            sample_candidate(DecisionAction::Delete, 2.3),
            sample_candidate(DecisionAction::Delete, 2.1),
            sample_candidate(DecisionAction::Keep, 0.5),
        ];
        let decision = engine.evaluate(&candidates, None);

        assert!(decision.budget_exhausted);
        assert_eq!(decision.hypothetical_deletes, 2);
        // Should have stopped after 2 deletes, not processed all 4.
        assert!(decision.records.len() <= 3);
    }

    #[test]
    fn candidate_budget_limits_evaluation() {
        let mut config = default_config();
        config.max_candidates_per_loop = 2;
        let mut engine = PolicyEngine::new(config);

        let candidates = vec![
            sample_candidate(DecisionAction::Delete, 2.5),
            sample_candidate(DecisionAction::Delete, 2.3),
            sample_candidate(DecisionAction::Delete, 2.1),
        ];
        let decision = engine.evaluate(&candidates, None);

        assert!(decision.budget_exhausted);
        assert_eq!(decision.records.len(), 2);
    }

    #[test]
    fn guard_penalty_blocks_deletion_when_not_pass() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote();
        engine.promote(); // enforce
        // Guard penalty only applies when pressure is above green.
        engine.set_pressure_level(PressureLevel::Yellow);

        let candidate = sample_candidate(DecisionAction::Delete, 2.5);
        // expected_loss_delete=1.3, guard_penalty=50.0 → penalized=51.3 > keep=8.7
        let guard = GuardDiagnostics {
            status: GuardStatus::Unknown,
            observation_count: 5,
            median_rate_error: 0.3,
            conservative_fraction: 0.6,
            forecast: None,
            e_process_value: 1.0,
            e_process_alarm: false,
            consecutive_clean: 0,
            reason: "insufficient data".to_string(),
        };

        let decision = engine.evaluate(&[candidate], Some(&guard));
        assert!(
            decision.approved_for_deletion.is_empty(),
            "policy must approve no deletions here, approved {}",
            decision.approved_for_deletion.len()
        );
        // Verify effective action is recorded as Keep.
        assert_eq!(
            decision.records[0].effective_action,
            Some(ActionRecord::Keep)
        );
    }

    #[test]
    fn fallback_safe_blocks_all_deletions() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote();
        engine.promote(); // enforce
        engine.enter_fallback(FallbackReason::KillSwitch);

        let candidates = vec![sample_candidate(DecisionAction::Delete, 2.5)];
        let guard = passing_guard();
        let decision = engine.evaluate(&candidates, Some(&guard));

        assert!(
            decision.approved_for_deletion.is_empty(),
            "policy must approve no deletions here, approved {}",
            decision.approved_for_deletion.len()
        );
        assert_eq!(decision.mode, ActiveMode::FallbackSafe);
        assert_eq!(
            decision.records[0].effective_action,
            Some(ActionRecord::Keep)
        );
    }

    // ──── diagnostics tests ────

    #[test]
    fn diagnostics_snapshot() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote(); // canary
        let candidates = vec![sample_candidate(DecisionAction::Delete, 2.5)];
        engine.evaluate(&candidates, None);

        let diag = engine.diagnostics();
        assert_eq!(diag.mode, ActiveMode::Canary);
        assert_eq!(diag.total_decisions, 1);
        assert_eq!(diag.transition_count, 1);
    }

    #[test]
    fn transitions_after_is_a_cursor_over_the_bounded_log() {
        let mut engine = PolicyEngine::new(PolicyConfig::default());
        assert_eq!(engine.transitions_total(), 0);
        assert!(engine.transitions_after(0).is_empty());
        engine.log_transition("promote", ActiveMode::Observe, ActiveMode::Canary, None);
        engine.log_transition(
            "demote",
            ActiveMode::Canary,
            ActiveMode::Observe,
            Some("test".to_string()),
        );
        assert_eq!(engine.transitions_total(), 2);
        let unseen = engine.transitions_after(0);
        assert_eq!(unseen.len(), 2);
        assert_eq!(unseen[0].transition, "promote");
        assert_eq!(unseen[1].reason.as_deref(), Some("test"));
        assert_eq!(engine.transitions_after(1).len(), 1);
        assert!(engine.transitions_after(2).is_empty());
        // A cursor behind a drained log yields what is still there.
        for _ in 0..1200 {
            engine.log_transition("promote", ActiveMode::Observe, ActiveMode::Canary, None);
        }
        assert!(engine.transitions_after(0).len() <= engine.transition_log().len());
        assert_eq!(
            engine
                .transitions_after(engine.transitions_total() - 3)
                .len(),
            3
        );
    }

    #[test]
    fn transition_log_captures_history() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote(); // observe→canary
        engine.promote(); // canary→enforce
        engine.demote(); // enforce→canary

        let log = engine.transition_log();
        assert_eq!(log.len(), 3);
        assert_eq!(log[0].from, "observe");
        assert_eq!(log[0].to, "canary");
        assert_eq!(log[1].from, "canary");
        assert_eq!(log[1].to, "enforce");
        assert_eq!(log[2].from, "enforce");
        assert_eq!(log[2].to, "canary");
    }

    #[test]
    fn double_fallback_is_idempotent() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote(); // canary
        engine.enter_fallback(FallbackReason::GuardrailDrift);
        engine.enter_fallback(FallbackReason::KillSwitch);

        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
        assert_eq!(engine.total_fallback_entries(), 1);
        assert_eq!(engine.pre_fallback_mode, ActiveMode::Canary);
    }

    #[test]
    fn active_mode_display() {
        assert_eq!(ActiveMode::Observe.to_string(), "observe");
        assert_eq!(ActiveMode::Canary.to_string(), "canary");
        assert_eq!(ActiveMode::Enforce.to_string(), "enforce");
        assert_eq!(ActiveMode::FallbackSafe.to_string(), "fallback_safe");
    }

    #[test]
    fn active_mode_allows_deletion() {
        assert!(!ActiveMode::Observe.allows_deletion());
        assert!(ActiveMode::Canary.allows_deletion());
        assert!(ActiveMode::Enforce.allows_deletion());
        assert!(!ActiveMode::FallbackSafe.allows_deletion());
    }

    #[test]
    fn fallback_reason_display() {
        let r = FallbackReason::CalibrationBreach {
            consecutive_windows: 3,
        };
        assert!(r.to_string().contains("3 windows"));

        let r2 = FallbackReason::PolicyError {
            details: "panic in scorer".to_string(),
        };
        assert!(r2.to_string().contains("panic in scorer"));
    }

    #[test]
    fn evaluate_records_decision_ids_sequentially() {
        let mut engine = PolicyEngine::new(default_config());
        let candidates = vec![
            sample_candidate(DecisionAction::Delete, 2.5),
            sample_candidate(DecisionAction::Keep, 0.5),
        ];
        let d1 = engine.evaluate(&candidates, None);
        let d2 = engine.evaluate(&candidates, None);

        assert_eq!(d1.records[0].decision_id, 1);
        assert_eq!(d1.records[1].decision_id, 2);
        assert_eq!(d2.records[0].decision_id, 3);
        assert_eq!(d2.records[1].decision_id, 4);
    }

    #[test]
    fn observe_mode_sets_shadow_policy() {
        let mut engine = PolicyEngine::new(default_config());
        let candidates = vec![sample_candidate(DecisionAction::Delete, 2.5)];
        let decision = engine.evaluate(&candidates, None);
        assert_eq!(decision.records[0].policy_mode, PolicyMode::Shadow);
    }

    #[test]
    fn enforce_mode_sets_live_policy() {
        let mut engine = PolicyEngine::new(default_config());
        engine.promote();
        engine.promote();
        let candidates = vec![sample_candidate(DecisionAction::Delete, 2.5)];
        let decision = engine.evaluate(&candidates, None);
        assert_eq!(decision.records[0].policy_mode, PolicyMode::Live);
    }

    #[test]
    fn clean_windows_reset_on_breach() {
        let mut config = default_config();
        config.recovery_clean_windows = 3;
        let mut engine = PolicyEngine::new(config);
        engine.enter_fallback(FallbackReason::GuardrailDrift);

        let good = passing_guard();
        let bad = GuardDiagnostics {
            status: GuardStatus::Fail,
            e_process_alarm: false,
            ..failing_guard()
        };

        engine.observe_window(&good);
        engine.observe_window(&good);
        assert_eq!(engine.consecutive_clean_windows, 2);
        engine.observe_window(&bad);
        assert_eq!(engine.consecutive_clean_windows, 0);
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
    }

    #[test]
    fn update_config_engages_kill_switch() {
        let mut engine = PolicyEngine::new(default_config());
        assert_eq!(engine.mode(), ActiveMode::Observe);

        let mut new = default_config();
        new.kill_switch = true;
        engine.update_config(new);

        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
        assert_eq!(engine.fallback_reason(), Some(&FallbackReason::KillSwitch));
    }

    #[test]
    fn update_config_engages_kill_switch_while_already_in_fallback_records_reason() {
        let mut config = default_config();
        config.initial_mode = ActiveMode::FallbackSafe;
        let mut engine = PolicyEngine::new(config);
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
        assert!(engine.fallback_reason().is_none());

        let mut new = default_config();
        new.initial_mode = ActiveMode::FallbackSafe;
        new.kill_switch = true;
        engine.update_config(new);

        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
        assert_eq!(engine.fallback_reason(), Some(&FallbackReason::KillSwitch));
        assert_eq!(engine.total_fallback_entries(), 1);
    }

    #[test]
    fn update_config_disengages_kill_switch_recovers() {
        let mut config = default_config();
        config.kill_switch = true;
        let mut engine = PolicyEngine::new(config);
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);

        let mut new = default_config();
        new.kill_switch = false;
        engine.update_config(new);

        // Should recover from fallback (kill-switch was the reason).
        assert_ne!(engine.mode(), ActiveMode::FallbackSafe);
        assert!(engine.fallback_reason().is_none());
    }

    #[test]
    fn update_config_preserves_non_killswitch_fallback() {
        let mut engine = PolicyEngine::new(default_config());
        engine.enter_fallback(FallbackReason::GuardrailDrift);
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);

        // Toggling kill_switch off should NOT recover from a drift-caused fallback.
        let mut new = default_config();
        new.kill_switch = false;
        engine.update_config(new);

        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);
    }

    #[test]
    fn update_config_propagates_budget_changes() {
        let mut engine = PolicyEngine::new(default_config());
        assert_eq!(engine.config.max_canary_deletes_per_hour, 10);

        let mut new = default_config();
        new.max_canary_deletes_per_hour = 50;
        engine.update_config(new);

        assert_eq!(engine.config.max_canary_deletes_per_hour, 50);
    }

    #[test]
    fn green_pressure_allows_recovery_from_fallback_despite_unknown_guard() {
        let mut engine = PolicyEngine::new(default_config());
        engine.bypass_startup_grace();
        engine.enter_fallback(FallbackReason::GuardrailDrift);
        assert_eq!(engine.mode(), ActiveMode::FallbackSafe);

        // Fast-forward past min_fallback_secs.
        engine.fallback_entered_at = Some(
            Instant::now()
                .checked_sub(Duration::from_secs(engine.config.min_fallback_secs + 1))
                .unwrap(),
        );

        // Simulate enough "clean" windows during green pressure with Unknown guard.
        let unknown_guard = GuardDiagnostics {
            status: GuardStatus::Unknown,
            observation_count: 0,
            median_rate_error: 0.0,
            conservative_fraction: 0.0,
            forecast: None,
            e_process_value: 0.0,
            e_process_alarm: false,
            consecutive_clean: 0,
            reason: String::new(),
        };
        for _ in 0..=engine.config.recovery_clean_windows {
            engine.observe_window(&unknown_guard);
        }
        // Should recover because green pressure + non-Fail guard = clean.
        assert_ne!(
            engine.mode(),
            ActiveMode::FallbackSafe,
            "should recover from fallback during green pressure with Unknown guard"
        );
    }
}
