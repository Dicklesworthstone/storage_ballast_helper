//! Unified evidence-ledger schema and explain rendering for cleanup decisions.
//!
//! Every deletion or keep decision produces a `DecisionRecord` that captures
//! the full provenance chain: candidate features, factor contributions,
//! Bayesian posterior/loss values, guard status, and policy context.
//!
//! Explain output supports four galaxy-brain levels:
//! - **Level 0**: concise recommendation (one line)
//! - **Level 1**: weighted factor table
//! - **Level 2**: posterior, loss, calibration values
//! - **Level 3**: full serialized trace payload for replay/debug

#![allow(clippy::cast_precision_loss)]

use std::fmt;
use std::fmt::Write as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::scanner::scoring::{CandidacyScore, DecisionAction, EvidenceLedger, ScoreFactors};

// ──────────────────── explain level ────────────────────

/// Galaxy-brain detail level for explain output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ExplainLevel {
    /// Concise recommendation: action + path + score.
    L0 = 0,
    /// Weighted factor table with contributions.
    L1 = 1,
    /// Posterior, expected-loss, calibration detail.
    L2 = 2,
    /// Full serialized trace payload for replay.
    L3 = 3,
}

impl ExplainLevel {
    /// Parse from an integer (clamped to 0..=3).
    #[must_use]
    pub fn from_int(n: u8) -> Self {
        match n {
            0 => Self::L0,
            1 => Self::L1,
            2 => Self::L2,
            _ => Self::L3,
        }
    }
}

impl fmt::Display for ExplainLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "L{}", *self as u8)
    }
}

// ──────────────────── decision record ────────────────────

/// Unified evidence record for a single cleanup decision.
///
/// Captures the full provenance chain so that any decision can be
/// explained, audited, or replayed from this record alone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    /// Monotonic decision identifier within this daemon run.
    pub decision_id: u64,
    /// Trace identifier for correlating with scan/deletion events.
    pub trace_id: String,
    /// ISO 8601 timestamp when the decision was made.
    pub timestamp: String,
    /// Policy mode active when the decision was made.
    pub policy_mode: PolicyMode,
    /// Path of the candidate artifact.
    pub path: PathBuf,
    /// Size of the candidate in bytes.
    pub size_bytes: u64,
    /// Age of the candidate at decision time.
    pub age_secs: u64,
    /// Artifact classification info.
    pub classification: ClassificationRecord,
    /// The five scored factors and pressure multiplier.
    pub factors: FactorsRecord,
    /// Weighted factor contributions.
    pub factor_contributions: Vec<FactorContribution>,
    /// Total weighted score (0.0–3.0).
    pub total_score: f64,
    /// Bayesian posterior estimate that the artifact is abandoned.
    pub posterior_abandoned: f64,
    /// Expected loss if we keep the artifact.
    pub expected_loss_keep: f64,
    /// Expected loss if we delete the artifact.
    pub expected_loss_delete: f64,
    /// Calibration quality score.
    pub calibration_score: f64,
    /// Whether the fallback (conservative) policy was active.
    pub fallback_active: bool,
    /// Reason for fallback, if active.
    pub fallback_reason: Option<String>,
    /// Whether a hard veto was applied.
    pub vetoed: bool,
    /// Reason for hard veto, if applied.
    pub veto_reason: Option<String>,
    /// The selected action.
    pub action: ActionRecord,
    /// Guard status at decision time.
    pub guard_status: Option<GuardStatusRecord>,
    /// Comparator action for shadow/canary diffing.
    pub comparator_action: Option<ActionRecord>,
    /// Human-readable summary from the evidence ledger.
    pub summary: String,
}

/// Policy mode active when a decision was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    /// Normal production mode.
    Live,
    /// Shadow mode: decisions logged but not executed.
    Shadow,
    /// Canary mode: executed for a fraction of candidates.
    Canary,
    /// Dry-run: CLI invocation with --dry-run.
    DryRun,
}

impl fmt::Display for PolicyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Live => write!(f, "live"),
            Self::Shadow => write!(f, "shadow"),
            Self::Canary => write!(f, "canary"),
            Self::DryRun => write!(f, "dry-run"),
        }
    }
}

/// Serializable record of an artifact classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationRecord {
    /// Pattern name that matched (e.g. "cargo-target-*").
    pub pattern_name: String,
    /// Category (e.g. "RustTarget").
    pub category: String,
    /// Combined confidence from name + structural signals.
    pub combined_confidence: f64,
}

/// Serializable factor values.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FactorsRecord {
    /// Location-based safety score (0.0–1.0).
    pub location: f64,
    /// Filename pattern score (0.0–1.0).
    pub name: f64,
    /// Time-decay score (0.0–1.0).
    pub age: f64,
    /// Size-based score (0.0–1.0).
    pub size: f64,
    /// Structural signals score (0.0–1.0).
    pub structure: f64,
    /// Disk pressure urgency multiplier (≥1.0).
    pub pressure_multiplier: f64,
}

impl From<ScoreFactors> for FactorsRecord {
    fn from(f: ScoreFactors) -> Self {
        Self {
            location: f.location,
            name: f.name,
            age: f.age,
            size: f.size,
            structure: f.structure,
            pressure_multiplier: f.pressure_multiplier,
        }
    }
}

/// A single factor's weight and contribution to the total score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactorContribution {
    /// Factor name (location, name, age, size, structure).
    pub name: String,
    /// Config weight for this factor.
    pub weight: f64,
    /// Raw factor value (0.0–1.0).
    pub value: f64,
    /// Weighted contribution (weight * value).
    pub contribution: f64,
}

/// Serializable action record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionRecord {
    /// Keep the artifact.
    Keep,
    /// Delete the artifact.
    Delete,
    /// Flag for human review.
    Review,
}

impl From<DecisionAction> for ActionRecord {
    fn from(a: DecisionAction) -> Self {
        match a {
            DecisionAction::Keep => Self::Keep,
            DecisionAction::Delete => Self::Delete,
            DecisionAction::Review => Self::Review,
        }
    }
}

impl fmt::Display for ActionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Keep => write!(f, "KEEP"),
            Self::Delete => write!(f, "DELETE"),
            Self::Review => write!(f, "REVIEW"),
        }
    }
}

/// Guard status snapshot at decision time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardStatusRecord {
    /// Current guard status.
    pub status: String,
    /// Number of calibration observations.
    pub observation_count: usize,
    /// E-process value (log-space).
    pub e_process_value: f64,
    /// Whether e-process alarm is active.
    pub e_process_alarm: bool,
}

impl GuardStatusRecord {
    /// Build from guardrail diagnostics.
    #[must_use]
    pub fn from_diagnostics(diag: &crate::monitor::guardrails::GuardDiagnostics) -> Self {
        Self {
            status: diag.status.to_string(),
            observation_count: diag.observation_count,
            e_process_value: diag.e_process_value,
            e_process_alarm: diag.e_process_alarm,
        }
    }
}

// ──────────────────── builder ────────────────────

/// Incrementally builds a `DecisionRecord` from scanner outputs.
pub struct DecisionRecordBuilder {
    next_id: u64,
}

impl DecisionRecordBuilder {
    /// Create a new builder. Decision IDs start at 1.
    #[must_use]
    pub fn new() -> Self {
        Self { next_id: 1 }
    }

    /// Build a decision record from a candidacy score and optional context.
    pub fn build(
        &mut self,
        score: &CandidacyScore,
        policy_mode: PolicyMode,
        guard_status: Option<&crate::monitor::guardrails::GuardDiagnostics>,
        comparator_action: Option<DecisionAction>,
    ) -> DecisionRecord {
        let id = self.next_id;
        self.next_id += 1;

        let trace_id = format!("sbh-{id:08x}");
        let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        let contributions = ledger_to_contributions(&score.ledger);

        let fallback_reason = if score.decision.fallback_active {
            Some(format!(
                "calibration {:.3} below floor",
                score.decision.calibration_score
            ))
        } else {
            None
        };

        DecisionRecord {
            decision_id: id,
            trace_id,
            timestamp,
            policy_mode,
            path: score.path.clone(),
            size_bytes: score.size_bytes,
            age_secs: score.age.as_secs(),
            classification: ClassificationRecord {
                pattern_name: score.classification.pattern_name.clone(),
                category: format!("{:?}", score.classification.category),
                combined_confidence: score.classification.combined_confidence,
            },
            factors: FactorsRecord::from(score.factors),
            factor_contributions: contributions,
            total_score: score.total_score,
            posterior_abandoned: score.decision.posterior_abandoned,
            expected_loss_keep: score.decision.expected_loss_keep,
            expected_loss_delete: score.decision.expected_loss_delete,
            calibration_score: score.decision.calibration_score,
            fallback_active: score.decision.fallback_active,
            fallback_reason,
            vetoed: score.vetoed,
            veto_reason: score.veto_reason.clone(),
            action: ActionRecord::from(score.decision.action),
            guard_status: guard_status.map(GuardStatusRecord::from_diagnostics),
            comparator_action: comparator_action.map(ActionRecord::from),
            summary: score.ledger.summary.clone(),
        }
    }
}

impl Default for DecisionRecordBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────── explain rendering ────────────────────

/// Render a decision record as human-readable text at the given galaxy-brain level.
#[must_use]
pub fn format_explain(record: &DecisionRecord, level: ExplainLevel) -> String {
    let mut out = String::with_capacity(512);

    // Level 0: concise recommendation.
    out.push_str(&format_l0(record));

    if level >= ExplainLevel::L1 {
        out.push('\n');
        out.push_str(&format_l1(record));
    }

    if level >= ExplainLevel::L2 {
        out.push('\n');
        out.push_str(&format_l2(record));
    }

    if level >= ExplainLevel::L3 {
        out.push('\n');
        out.push_str(&format_l3(record));
    }

    out
}

fn format_l0(r: &DecisionRecord) -> String {
    let size = format_bytes(r.size_bytes);
    let age = format_duration(r.age_secs);
    if r.vetoed {
        format!(
            "{action} {path} ({size}, {age}) [vetoed: {reason}]",
            action = r.action,
            path = r.path.display(),
            reason = r.veto_reason.as_deref().unwrap_or("unknown"),
        )
    } else {
        format!(
            "{action} {path} ({size}, {age}) score={score:.3}",
            action = r.action,
            path = r.path.display(),
            score = r.total_score,
        )
    }
}

fn format_l1(r: &DecisionRecord) -> String {
    let mut out = String::from("  Factor        Weight  Value   Contribution\n");
    out.push_str("  ──────────────────────────────────────────\n");
    for fc in &r.factor_contributions {
        let _ = writeln!(
            out,
            "  {name:<12}  {weight:>5.2}   {value:>5.3}   {contrib:>5.3}",
            name = fc.name,
            weight = fc.weight,
            value = fc.value,
            contrib = fc.contribution,
        );
    }
    let _ = writeln!(
        out,
        "  pressure_mul  ─────   {pm:.3}   (applied to base)",
        pm = r.factors.pressure_multiplier,
    );
    let _ = writeln!(
        out,
        "  Category: {cat} ({conf:.0}% confidence)",
        cat = r.classification.category,
        conf = r.classification.combined_confidence * 100.0,
    );
    out
}

fn format_l2(r: &DecisionRecord) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "  Posterior(abandoned): {post:.4}",
        post = r.posterior_abandoned,
    );
    let _ = writeln!(
        out,
        "  Expected loss — keep: {keep:.3}  delete: {del:.3}  delta: {delta:+.3}",
        keep = r.expected_loss_keep,
        del = r.expected_loss_delete,
        delta = r.expected_loss_keep - r.expected_loss_delete,
    );
    if r.fallback_active {
        let _ = writeln!(
            out,
            "  Calibration: {cal:.4}  (FALLBACK: {reason})",
            cal = r.calibration_score,
            reason = r.fallback_reason.as_deref().unwrap_or("active"),
        );
    } else {
        let _ = writeln!(out, "  Calibration: {cal:.4}", cal = r.calibration_score);
    }
    if let Some(guard) = &r.guard_status {
        let _ = writeln!(
            out,
            "  Guard: {status} (n={n}, e={e:.2}, alarm={alarm})",
            status = guard.status,
            n = guard.observation_count,
            e = guard.e_process_value,
            alarm = guard.e_process_alarm,
        );
    }
    let _ = writeln!(out, "  Policy: {mode}", mode = r.policy_mode);
    if let Some(comp) = &r.comparator_action {
        let _ = writeln!(out, "  Comparator: {comp} (shadow/canary diff)");
    }
    out
}

fn format_l3(r: &DecisionRecord) -> String {
    let mut out = String::from("  ── Full trace payload ──\n");
    match serde_json::to_string_pretty(r) {
        Ok(json) => {
            for line in json.lines() {
                out.push_str("  ");
                out.push_str(line);
                out.push('\n');
            }
        }
        Err(e) => {
            let _ = writeln!(out, "  [serialization error: {e}]");
        }
    }
    out
}

// ──────────────────── JSON serialization ────────────────────

impl DecisionRecord {
    /// Serialize to compact JSON (for JSONL storage).
    #[must_use]
    pub fn to_json_compact(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }

    /// Serialize to pretty JSON (for CLI output).
    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self)
            .unwrap_or_else(|e| format!("{{\n  \"error\": \"{e}\"\n}}"))
    }

    /// Render at the requested explain level as a JSON value.
    ///
    /// Levels 0–2 return a subset of fields. Level 3 returns the full record.
    #[must_use]
    pub fn to_json_at_level(&self, level: ExplainLevel) -> serde_json::Value {
        match level {
            ExplainLevel::L0 => serde_json::json!({
                "decision_id": self.decision_id,
                "path": self.path,
                "action": self.action,
                "total_score": self.total_score,
                "size_bytes": self.size_bytes,
                "vetoed": self.vetoed,
                "veto_reason": self.veto_reason,
            }),
            ExplainLevel::L1 => serde_json::json!({
                "decision_id": self.decision_id,
                "path": self.path,
                "action": self.action,
                "total_score": self.total_score,
                "size_bytes": self.size_bytes,
                "age_secs": self.age_secs,
                "classification": self.classification,
                "factor_contributions": self.factor_contributions,
                "factors": self.factors,
                "vetoed": self.vetoed,
                "veto_reason": self.veto_reason,
            }),
            ExplainLevel::L2 => serde_json::json!({
                "decision_id": self.decision_id,
                "path": self.path,
                "action": self.action,
                "total_score": self.total_score,
                "size_bytes": self.size_bytes,
                "age_secs": self.age_secs,
                "classification": self.classification,
                "factor_contributions": self.factor_contributions,
                "factors": self.factors,
                "posterior_abandoned": self.posterior_abandoned,
                "expected_loss_keep": self.expected_loss_keep,
                "expected_loss_delete": self.expected_loss_delete,
                "calibration_score": self.calibration_score,
                "fallback_active": self.fallback_active,
                "fallback_reason": self.fallback_reason,
                "guard_status": self.guard_status,
                "policy_mode": self.policy_mode,
                "comparator_action": self.comparator_action,
                "vetoed": self.vetoed,
                "veto_reason": self.veto_reason,
            }),
            ExplainLevel::L3 => serde_json::to_value(self)
                .unwrap_or_else(|_| serde_json::json!({"error": "serialize"})),
        }
    }
}

// ──────────────────── helpers ────────────────────

fn ledger_to_contributions(ledger: &EvidenceLedger) -> Vec<FactorContribution> {
    ledger
        .terms
        .iter()
        .map(|t| FactorContribution {
            name: t.name.to_string(),
            weight: t.weight,
            value: t.value,
            contribution: t.contribution,
        })
        .collect()
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.0} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn format_duration(secs: u64) -> String {
    if secs >= 86400 {
        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        if hours > 0 {
            format!("{days}d {hours}h")
        } else {
            format!("{days}d")
        }
    } else if secs >= 3600 {
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        if mins > 0 {
            format!("{hours}h {mins}m")
        } else {
            format!("{hours}h")
        }
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

// ──────────────────── query helpers for stats engine ────────────────────

/// Deserialize a `DecisionRecord` from a JSON string stored in the activity_log details column.
///
/// Returns `None` if parsing fails (graceful degradation).
#[must_use]
pub fn parse_decision_from_details(json: &str) -> Option<DecisionRecord> {
    serde_json::from_str(json).ok()
}

/// Extract a minimal summary from a decision record for list views.
#[must_use]
pub fn decision_summary_line(record: &DecisionRecord) -> String {
    format!(
        "[{id}] {action} {path} score={score:.3} ({cat})",
        id = record.trace_id,
        action = record.action,
        path = record.path.display(),
        score = record.total_score,
        cat = record.classification.category,
    )
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::guardrails::{GuardDiagnostics, GuardStatus};
    use crate::scanner::patterns::{ArtifactCategory, ArtifactClassification, StructuralSignals};
    use crate::scanner::scoring::{
        CandidacyScore, CandidateInput, DecisionAction, DecisionOutcome, EvidenceLedger,
        EvidenceTerm, ScoreFactors, ScoringEngine,
    };
    use std::path::PathBuf;
    use std::time::Duration;

    fn sample_score() -> CandidacyScore {
        CandidacyScore {
            path: PathBuf::from("/data/projects/foo/.target_opus"),
            total_score: 2.15,
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
                pattern_name: ".target*".to_string(),
                category: ArtifactCategory::RustTarget,
                name_confidence: 0.90,
                structural_confidence: 0.95,
                combined_confidence: 0.92,
            },
            size_bytes: 3_500_000_000,
            age: Duration::from_secs(5 * 3600),
            decision: DecisionOutcome {
                action: DecisionAction::Delete,
                posterior_abandoned: 0.87,
                expected_loss_keep: 8.7,
                expected_loss_delete: 1.3,
                calibration_score: 0.82,
                fallback_active: false,
            },
            ledger: EvidenceLedger {
                terms: vec![
                    EvidenceTerm {
                        name: "location",
                        weight: 0.25,
                        value: 0.85,
                        contribution: 0.2125,
                    },
                    EvidenceTerm {
                        name: "name",
                        weight: 0.20,
                        value: 0.90,
                        contribution: 0.18,
                    },
                    EvidenceTerm {
                        name: "age",
                        weight: 0.15,
                        value: 1.0,
                        contribution: 0.15,
                    },
                    EvidenceTerm {
                        name: "size",
                        weight: 0.20,
                        value: 0.70,
                        contribution: 0.14,
                    },
                    EvidenceTerm {
                        name: "structure",
                        weight: 0.20,
                        value: 0.95,
                        contribution: 0.19,
                    },
                ],
                summary: "posterior_abandoned=0.870; keep_loss=8.70; delete_loss=1.30; \
                           calibration=0.820; action=Delete"
                    .to_string(),
            },
        }
    }

    fn sample_guard_diag() -> GuardDiagnostics {
        GuardDiagnostics {
            status: GuardStatus::Pass,
            observation_count: 25,
            median_rate_error: 0.12,
            conservative_fraction: 0.80,
            e_process_value: 3.5,
            e_process_alarm: false,
            consecutive_clean: 5,
            reason: "calibration verified".to_string(),
        }
    }

    fn vetoed_score() -> CandidacyScore {
        CandidacyScore {
            path: PathBuf::from("/data/projects/repo/.git/objects"),
            total_score: 0.0,
            factors: ScoreFactors {
                location: 0.0,
                name: 0.0,
                age: 0.0,
                size: 0.0,
                structure: 0.0,
                pressure_multiplier: 1.0,
            },
            vetoed: true,
            veto_reason: Some("path contains .git".to_string()),
            classification: ArtifactClassification {
                pattern_name: "unknown".to_string(),
                category: ArtifactCategory::RustTarget,
                name_confidence: 0.5,
                structural_confidence: 0.0,
                combined_confidence: 0.25,
            },
            size_bytes: 1024,
            age: Duration::from_secs(3600),
            decision: DecisionOutcome {
                action: DecisionAction::Keep,
                posterior_abandoned: 0.0,
                expected_loss_keep: 0.0,
                expected_loss_delete: 10.0,
                calibration_score: 1.0,
                fallback_active: true,
            },
            ledger: EvidenceLedger {
                terms: Vec::new(),
                summary: "hard veto applied".to_string(),
            },
        }
    }

    #[test]
    fn builder_assigns_sequential_ids() {
        let mut builder = DecisionRecordBuilder::new();
        let score = sample_score();
        let r1 = builder.build(&score, PolicyMode::Live, None, None);
        let r2 = builder.build(&score, PolicyMode::Live, None, None);
        assert_eq!(r1.decision_id, 1);
        assert_eq!(r2.decision_id, 2);
    }

    #[test]
    fn builder_captures_all_fields() {
        let mut builder = DecisionRecordBuilder::new();
        let score = sample_score();
        let diag = sample_guard_diag();
        let record = builder.build(
            &score,
            PolicyMode::Shadow,
            Some(&diag),
            Some(DecisionAction::Keep),
        );

        assert_eq!(
            record.path,
            PathBuf::from("/data/projects/foo/.target_opus")
        );
        assert_eq!(record.size_bytes, 3_500_000_000);
        assert_eq!(record.age_secs, 5 * 3600);
        assert_eq!(record.total_score, 2.15);
        assert_eq!(record.action, ActionRecord::Delete);
        assert_eq!(record.policy_mode, PolicyMode::Shadow);
        assert!(!record.vetoed);
        assert!(!record.fallback_active);
        assert_eq!(record.factor_contributions.len(), 5);

        let guard = record.guard_status.as_ref().unwrap();
        assert_eq!(guard.status, "PASS");
        assert_eq!(guard.observation_count, 25);
        assert!(!guard.e_process_alarm);

        assert_eq!(record.comparator_action, Some(ActionRecord::Keep));
    }

    #[test]
    fn builder_captures_veto() {
        let mut builder = DecisionRecordBuilder::new();
        let score = vetoed_score();
        let record = builder.build(&score, PolicyMode::Live, None, None);

        assert!(record.vetoed);
        assert_eq!(record.veto_reason.as_deref(), Some("path contains .git"));
        assert_eq!(record.action, ActionRecord::Keep);
        assert_eq!(record.total_score, 0.0);
        assert!(record.factor_contributions.is_empty());
    }

    #[test]
    fn builder_captures_fallback() {
        let mut builder = DecisionRecordBuilder::new();
        let mut score = sample_score();
        score.decision.fallback_active = true;
        score.decision.calibration_score = 0.35;
        let record = builder.build(&score, PolicyMode::Live, None, None);

        assert!(record.fallback_active);
        assert!(record.fallback_reason.is_some());
        assert!(record.fallback_reason.as_ref().unwrap().contains("0.350"));
    }

    #[test]
    fn explain_l0_concise() {
        let mut builder = DecisionRecordBuilder::new();
        let record = builder.build(&sample_score(), PolicyMode::Live, None, None);
        let text = format_explain(&record, ExplainLevel::L0);

        assert!(text.contains("DELETE"));
        assert!(text.contains(".target_opus"));
        assert!(text.contains("score=2.150"));
        assert!(!text.contains("Factor"));
        assert!(!text.contains("Posterior"));
    }

    #[test]
    fn explain_l0_vetoed() {
        let mut builder = DecisionRecordBuilder::new();
        let record = builder.build(&vetoed_score(), PolicyMode::Live, None, None);
        let text = format_explain(&record, ExplainLevel::L0);

        assert!(text.contains("KEEP"));
        assert!(text.contains("vetoed"));
        assert!(text.contains(".git"));
    }

    #[test]
    fn explain_l1_includes_factors() {
        let mut builder = DecisionRecordBuilder::new();
        let record = builder.build(&sample_score(), PolicyMode::Live, None, None);
        let text = format_explain(&record, ExplainLevel::L1);

        assert!(text.contains("Factor"));
        assert!(text.contains("location"));
        assert!(text.contains("name"));
        assert!(text.contains("age"));
        assert!(text.contains("size"));
        assert!(text.contains("structure"));
        assert!(text.contains("pressure_mul"));
        assert!(text.contains("RustTarget"));
    }

    #[test]
    fn explain_l2_includes_bayesian() {
        let mut builder = DecisionRecordBuilder::new();
        let diag = sample_guard_diag();
        let record = builder.build(
            &sample_score(),
            PolicyMode::Shadow,
            Some(&diag),
            Some(DecisionAction::Keep),
        );
        let text = format_explain(&record, ExplainLevel::L2);

        assert!(text.contains("Posterior(abandoned)"));
        assert!(text.contains("Expected loss"));
        assert!(text.contains("Calibration"));
        assert!(text.contains("Guard: PASS"));
        assert!(text.contains("Policy: shadow"));
        assert!(text.contains("Comparator: KEEP"));
    }

    #[test]
    fn explain_l3_includes_json() {
        let mut builder = DecisionRecordBuilder::new();
        let record = builder.build(&sample_score(), PolicyMode::DryRun, None, None);
        let text = format_explain(&record, ExplainLevel::L3);

        assert!(text.contains("Full trace payload"));
        assert!(text.contains("\"decision_id\""));
        assert!(text.contains("\"trace_id\""));
        assert!(text.contains("\"posterior_abandoned\""));
        assert!(text.contains("dry_run"));
    }

    #[test]
    fn json_compact_roundtrips() {
        let mut builder = DecisionRecordBuilder::new();
        let record = builder.build(&sample_score(), PolicyMode::Live, None, None);
        let json = record.to_json_compact();
        let parsed: DecisionRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.decision_id, record.decision_id);
        assert_eq!(parsed.path, record.path);
        assert_eq!(parsed.action, record.action);
        assert_eq!(parsed.total_score, record.total_score);
        assert_eq!(parsed.posterior_abandoned, record.posterior_abandoned);
        assert_eq!(parsed.factor_contributions.len(), 5);
    }

    #[test]
    fn json_at_level_field_counts() {
        let mut builder = DecisionRecordBuilder::new();
        let diag = sample_guard_diag();
        let record = builder.build(
            &sample_score(),
            PolicyMode::Live,
            Some(&diag),
            Some(DecisionAction::Review),
        );

        let l0 = record.to_json_at_level(ExplainLevel::L0);
        let l1 = record.to_json_at_level(ExplainLevel::L1);
        let l2 = record.to_json_at_level(ExplainLevel::L2);
        let l3 = record.to_json_at_level(ExplainLevel::L3);

        // Higher levels include more fields.
        let l0_keys = l0.as_object().unwrap().len();
        let l1_keys = l1.as_object().unwrap().len();
        let l2_keys = l2.as_object().unwrap().len();
        let l3_keys = l3.as_object().unwrap().len();

        assert!(l0_keys < l1_keys, "L0({l0_keys}) < L1({l1_keys})");
        assert!(l1_keys < l2_keys, "L1({l1_keys}) < L2({l2_keys})");
        assert!(l2_keys < l3_keys, "L2({l2_keys}) < L3({l3_keys})");
    }

    #[test]
    fn explain_level_from_int() {
        assert_eq!(ExplainLevel::from_int(0), ExplainLevel::L0);
        assert_eq!(ExplainLevel::from_int(1), ExplainLevel::L1);
        assert_eq!(ExplainLevel::from_int(2), ExplainLevel::L2);
        assert_eq!(ExplainLevel::from_int(3), ExplainLevel::L3);
        assert_eq!(ExplainLevel::from_int(99), ExplainLevel::L3);
    }

    #[test]
    fn explain_level_ordering() {
        assert!(ExplainLevel::L0 < ExplainLevel::L1);
        assert!(ExplainLevel::L1 < ExplainLevel::L2);
        assert!(ExplainLevel::L2 < ExplainLevel::L3);
    }

    #[test]
    fn policy_mode_display() {
        assert_eq!(PolicyMode::Live.to_string(), "live");
        assert_eq!(PolicyMode::Shadow.to_string(), "shadow");
        assert_eq!(PolicyMode::Canary.to_string(), "canary");
        assert_eq!(PolicyMode::DryRun.to_string(), "dry-run");
    }

    #[test]
    fn action_record_display() {
        assert_eq!(ActionRecord::Keep.to_string(), "KEEP");
        assert_eq!(ActionRecord::Delete.to_string(), "DELETE");
        assert_eq!(ActionRecord::Review.to_string(), "REVIEW");
    }

    #[test]
    fn format_bytes_ranges() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(2048), "2 KiB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MiB");
        assert_eq!(format_bytes(3_500_000_000), "3.3 GiB");
    }

    #[test]
    fn format_duration_ranges() {
        assert_eq!(format_duration(30), "30s");
        assert_eq!(format_duration(120), "2m");
        assert_eq!(format_duration(3600), "1h");
        assert_eq!(format_duration(5 * 3600 + 1800), "5h 30m");
        assert_eq!(format_duration(86400), "1d");
        assert_eq!(format_duration(2 * 86400 + 3600), "2d 1h");
    }

    #[test]
    fn parse_decision_from_details_roundtrip() {
        let mut builder = DecisionRecordBuilder::new();
        let record = builder.build(&sample_score(), PolicyMode::Live, None, None);
        let json = record.to_json_compact();
        let parsed = parse_decision_from_details(&json).unwrap();
        assert_eq!(parsed.decision_id, record.decision_id);
        assert_eq!(parsed.action, record.action);
    }

    #[test]
    fn parse_decision_from_invalid_json() {
        assert!(parse_decision_from_details("not json").is_none());
        assert!(parse_decision_from_details("{}").is_none());
    }

    #[test]
    fn decision_summary_line_format() {
        let mut builder = DecisionRecordBuilder::new();
        let record = builder.build(&sample_score(), PolicyMode::Live, None, None);
        let line = decision_summary_line(&record);
        assert!(line.contains("sbh-00000001"));
        assert!(line.contains("DELETE"));
        assert!(line.contains(".target_opus"));
        assert!(line.contains("RustTarget"));
    }

    #[test]
    fn guard_status_record_from_diagnostics() {
        let diag = sample_guard_diag();
        let record = GuardStatusRecord::from_diagnostics(&diag);
        assert_eq!(record.status, "PASS");
        assert_eq!(record.observation_count, 25);
        assert!((record.e_process_value - 3.5).abs() < f64::EPSILON);
        assert!(!record.e_process_alarm);
    }

    #[test]
    fn factors_record_from_score_factors() {
        let factors = ScoreFactors {
            location: 0.8,
            name: 0.9,
            age: 0.7,
            size: 0.6,
            structure: 0.95,
            pressure_multiplier: 1.3,
        };
        let record = FactorsRecord::from(factors);
        assert!((record.location - 0.8).abs() < f64::EPSILON);
        assert!((record.pressure_multiplier - 1.3).abs() < f64::EPSILON);
    }

    #[test]
    fn builder_default_trait() {
        let builder = DecisionRecordBuilder::default();
        assert_eq!(builder.next_id, 1);
    }

    #[test]
    fn score_from_real_engine_roundtrips() {
        use crate::core::config::ScoringConfig;

        let engine = ScoringEngine::from_config(&ScoringConfig::default(), 30);
        let input = CandidateInput {
            path: PathBuf::from("/tmp/cargo-target-test"),
            size_bytes: 2_000_000_000,
            age: Duration::from_secs(4 * 3600),
            classification: ArtifactClassification {
                pattern_name: "cargo-target-*".to_string(),
                category: ArtifactCategory::RustTarget,
                name_confidence: 0.9,
                structural_confidence: 0.85,
                combined_confidence: 0.88,
            },
            signals: StructuralSignals {
                has_incremental: true,
                has_deps: true,
                has_build: true,
                has_fingerprint: false,
                has_git: false,
                has_cargo_toml: false,
                mostly_object_files: true,
            },
            is_open: false,
            excluded: false,
        };

        let scored = engine.score_candidate(&input, 0.5);
        let mut builder = DecisionRecordBuilder::new();
        let record = builder.build(&scored, PolicyMode::Live, None, None);

        // Roundtrip through JSON.
        let json = record.to_json_compact();
        let parsed: DecisionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_score, record.total_score);
        assert_eq!(parsed.action, record.action);
        assert_eq!(parsed.posterior_abandoned, record.posterior_abandoned);

        // Explain at all levels.
        for level in [
            ExplainLevel::L0,
            ExplainLevel::L1,
            ExplainLevel::L2,
            ExplainLevel::L3,
        ] {
            let text = format_explain(&record, level);
            assert!(!text.is_empty());
        }
    }
}
