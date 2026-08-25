//! Multi-factor candidacy scoring engine: location, name, age, size, structure weights
//! with hard vetoes and pressure multiplier.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::borrow::Cow;
use std::cmp::Ordering;
use std::fmt::Write as _;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use crate::core::config::ScoringConfig;
use crate::platform::cleanup_catalog::{CleanupRule, ReclaimCommand};
use crate::platform::{linux, macos};
use crate::scanner::patterns::{
    ArtifactCategory, ArtifactClassification, StructuralSignals, is_obvious_build_artifact_basename,
};
use crate::scanner::protection::SacredOverlap;
use crate::scanner::walker::FsIdentity;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScoringWeights {
    pub location: f64,
    pub name: f64,
    pub age: f64,
    pub size: f64,
    pub structure: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScoreFactors {
    pub location: f64,
    pub name: f64,
    pub age: f64,
    pub size: f64,
    pub structure: f64,
    pub pressure_multiplier: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionAction {
    Keep,
    Delete,
    Review,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceTerm {
    pub name: &'static str,
    pub weight: f64,
    pub value: f64,
    pub contribution: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceLedger {
    pub terms: Vec<EvidenceTerm>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ActiveReferenceSummary {
    pub processes: Vec<ActiveReferenceProcess>,
    pub incomplete_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveReferenceProcess {
    pub pid: i32,
    pub name: Option<String>,
    pub open_file_descriptors: usize,
    pub running_executable: bool,
    pub mmap_regions: usize,
}

impl ActiveReferenceSummary {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.incomplete_reason.is_none()
            && self.processes.iter().all(ActiveReferenceProcess::is_empty)
    }

    pub fn add_open_file_descriptor(&mut self, pid: i32, name: Option<String>) {
        self.process_mut(pid, name).open_file_descriptors += 1;
    }

    pub fn add_running_executable(&mut self, pid: i32, name: Option<String>) {
        self.process_mut(pid, name).running_executable = true;
    }

    pub fn add_mmap_region(&mut self, pid: i32, name: Option<String>) {
        self.process_mut(pid, name).mmap_regions += 1;
    }

    pub fn mark_incomplete(&mut self, reason: impl Into<String>) {
        self.incomplete_reason = Some(reason.into());
    }

    #[must_use]
    pub fn safe_reclaim_reason(&self) -> Option<Cow<'static, str>> {
        let active = self
            .processes
            .iter()
            .filter(|process| !process.is_empty())
            .collect::<Vec<_>>();
        if active.is_empty() && self.incomplete_reason.is_none() {
            return None;
        }

        let mut process_reasons = active
            .iter()
            .take(3)
            .map(|process| process.safe_reclaim_reason())
            .collect::<Vec<_>>();
        let remaining = active.len().saturating_sub(process_reasons.len());
        if remaining > 0 {
            process_reasons.push(format!("and {remaining} more processes"));
        }
        if let Some(reason) = &self.incomplete_reason {
            process_reasons.push(reason.clone());
        }

        if active.is_empty() {
            return self.incomplete_reason.clone().map(Cow::Owned);
        }

        Some(Cow::Owned(format!(
            "Cannot reclaim safely: {}",
            process_reasons.join("; ")
        )))
    }

    fn process_mut(&mut self, pid: i32, name: Option<String>) -> &mut ActiveReferenceProcess {
        let index = if let Some(index) = self.processes.iter().position(|p| p.pid == pid) {
            index
        } else {
            self.processes.push(ActiveReferenceProcess {
                pid,
                name: None,
                open_file_descriptors: 0,
                running_executable: false,
                mmap_regions: 0,
            });
            self.processes.sort_by_key(|p| p.pid);
            self.processes
                .iter()
                .position(|p| p.pid == pid)
                .expect("inserted active-reference process must be present")
        };

        let process = &mut self.processes[index];
        if process.name.is_none()
            && let Some(name) = name.filter(|value| !value.is_empty())
        {
            process.name = Some(name);
        }
        process
    }
}

impl ActiveReferenceProcess {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.open_file_descriptors == 0 && !self.running_executable && self.mmap_regions == 0
    }

    fn safe_reclaim_reason(&self) -> String {
        let name = self.name.as_deref().filter(|name| !name.is_empty());
        let label = name.map_or_else(
            || format!("pid {}", self.pid),
            |name| format!("pid {} ({name})", self.pid),
        );
        let mut evidence = Vec::new();
        if self.open_file_descriptors > 0 {
            evidence.push(pluralize(
                self.open_file_descriptors,
                "open file descriptor",
                "open file descriptors",
            ));
        }
        if self.running_executable {
            evidence.push("1 running executable".to_string());
        }
        if self.mmap_regions > 0 {
            evidence.push(pluralize(self.mmap_regions, "mmap region", "mmap regions"));
        }
        format!("{label} has {}", evidence.join(", "))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DecisionOutcome {
    pub action: DecisionAction,
    pub posterior_abandoned: f64,
    pub expected_loss_keep: f64,
    pub expected_loss_delete: f64,
    pub calibration_score: f64,
    pub fallback_active: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CandidacyScore {
    pub path: PathBuf,
    pub identity: Option<FsIdentity>,
    pub total_score: f64,
    pub factors: ScoreFactors,
    pub vetoed: bool,
    pub veto_reason: Option<Cow<'static, str>>,
    pub classification: ArtifactClassification,
    pub size_bytes: u64,
    pub age: Duration,
    pub decision: DecisionOutcome,
    pub ledger: EvidenceLedger,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CandidateInput {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub age: Duration,
    pub classification: ArtifactClassification,
    pub signals: StructuralSignals,
    pub active_references: ActiveReferenceSummary,
    pub is_open: bool,
    pub excluded: bool,
}

const HARD_REFUSE_BUNDLE_EXTENSIONS: &[&str] = &[
    "photoslibrary",
    "fcpbundle",
    "imovielibrary",
    "app",
    "framework",
    "bundle",
    "plugin",
    "kext",
    "lrcat",
    "lrlibrary",
    "aplibrary",
];

/// Deterministic score engine with expected-loss decision layer.
#[derive(Debug, Clone)]
pub struct ScoringEngine {
    weights: ScoringWeights,
    min_file_age: Duration,
    min_score: f64,
    false_positive_loss: f64,
    false_negative_loss: f64,
    calibration_floor: f64,
}

impl ScoringEngine {
    #[must_use]
    pub fn from_config(scoring: &ScoringConfig, min_file_age_minutes: u64) -> Self {
        Self {
            weights: ScoringWeights {
                location: scoring.location_weight.max(0.0),
                name: scoring.name_weight.max(0.0),
                age: scoring.age_weight.max(0.0),
                size: scoring.size_weight.max(0.0),
                structure: scoring.structure_weight.max(0.0),
            },
            min_file_age: Duration::from_secs(min_file_age_minutes.saturating_mul(60)),
            min_score: scoring.min_score,
            false_positive_loss: scoring.false_positive_loss,
            false_negative_loss: scoring.false_negative_loss,
            calibration_floor: scoring.calibration_floor,
        }
    }

    /// Score one candidate deterministically.
    #[must_use]
    pub fn score_candidate(&self, input: &CandidateInput, urgency: f64) -> CandidacyScore {
        self.score_candidate_inner(input, urgency, &[])
    }

    /// Score one candidate after applying sacred-path overlap evidence.
    #[must_use]
    pub fn score_candidate_with_sacred_overlaps(
        &self,
        input: &CandidateInput,
        urgency: f64,
        sacred_overlaps: &[SacredOverlap],
    ) -> CandidacyScore {
        self.score_candidate_inner(input, urgency, sacred_overlaps)
    }

    #[must_use]
    pub fn hard_veto(
        &self,
        input: &CandidateInput,
        reason: impl Into<Cow<'static, str>>,
    ) -> CandidacyScore {
        self.vetoed(input, reason.into())
    }

    fn score_candidate_inner(
        &self,
        input: &CandidateInput,
        urgency: f64,
        sacred_overlaps: &[SacredOverlap],
    ) -> CandidacyScore {
        if let Some(reason) = self.veto_reason(input, sacred_overlaps) {
            return self.vetoed(input, reason);
        }

        let factors = ScoreFactors {
            location: factor_location(&input.path),
            name: factor_name(&input.path, &input.classification),
            age: factor_age(input.age),
            size: factor_size(input.size_bytes),
            structure: factor_structure(input.signals),
            pressure_multiplier: pressure_multiplier(urgency),
        };

        let base = self.weights.structure.mul_add(
            factors.structure,
            self.weights.size.mul_add(
                factors.size,
                self.weights.age.mul_add(
                    factors.age,
                    self.weights
                        .location
                        .mul_add(factors.location, self.weights.name * factors.name),
                ),
            ),
        );
        let total = (base * factors.pressure_multiplier).clamp(0.0, 3.0);

        let posterior_abandoned =
            posterior_from_score(total, input.classification.combined_confidence);
        let base_expected_loss_keep = posterior_abandoned * self.false_negative_loss;
        let base_expected_loss_delete = (1.0 - posterior_abandoned) * self.false_positive_loss;
        let calibration = calibration_score(input.classification.combined_confidence, factors);
        let fallback_active = calibration < self.calibration_floor;
        let uncertainty = epistemic_uncertainty(posterior_abandoned, calibration);
        let (expected_loss_keep, expected_loss_delete) = uncertainty_adjusted_losses(
            base_expected_loss_keep,
            base_expected_loss_delete,
            posterior_abandoned,
            calibration,
            uncertainty,
        );

        let action = manual_review_override(
            &input.classification,
            decide_action(
                total,
                self.min_score,
                expected_loss_keep,
                expected_loss_delete,
                posterior_abandoned,
                calibration,
                fallback_active,
                uncertainty,
            ),
        );

        let ledger = build_ledger(
            factors,
            self.weights,
            posterior_abandoned,
            base_expected_loss_keep,
            base_expected_loss_delete,
            expected_loss_keep,
            expected_loss_delete,
            calibration,
            uncertainty,
            action,
        );

        CandidacyScore {
            path: input.path.clone(),
            identity: None,
            total_score: total,
            factors,
            vetoed: false,
            veto_reason: None,
            classification: input.classification.clone(),
            size_bytes: input.size_bytes,
            age: input.age,
            decision: DecisionOutcome {
                action,
                posterior_abandoned,
                expected_loss_keep,
                expected_loss_delete,
                calibration_score: calibration,
                fallback_active,
            },
            ledger,
        }
    }

    /// Score and rank many candidates.
    ///
    /// Tie-break is path lexicographic order to preserve determinism.
    #[must_use]
    pub fn score_batch(&self, candidates: &[CandidateInput], urgency: f64) -> Vec<CandidacyScore> {
        let mut scores = candidates
            .iter()
            .map(|candidate| self.score_candidate(candidate, urgency))
            .collect::<Vec<_>>();
        scores.sort_unstable_by(|left, right| {
            right
                .total_score
                .partial_cmp(&left.total_score)
                .unwrap_or(Ordering::Equal)
                .then_with(|| left.path.cmp(&right.path))
        });
        scores
    }

    fn veto_reason(
        &self,
        input: &CandidateInput,
        sacred_overlaps: &[SacredOverlap],
    ) -> Option<Cow<'static, str>> {
        if has_git_component(&input.path) || input.signals.has_git {
            return Some(Cow::Borrowed("path contains .git"));
        }
        if let Some(reason) = report_only_cleanup_rule_veto_reason(input) {
            return Some(reason);
        }
        if is_system_path(&input.path) {
            return Some(Cow::Borrowed("system path is never deletable"));
        }
        if is_rch_pooled_target(&input.path) {
            return Some(Cow::Borrowed(
                "rch pooled target dir is a shared warm build cache (rch never reaps these)",
            ));
        }
        if input.signals.has_cargo_toml
            && !input.signals.has_strong_signal()
            && !cleanup_rule_allows_embedded_manifest(&input.classification)
        {
            return Some(Cow::Borrowed(
                "contains Cargo.toml without build-artifact markers",
            ));
        }
        if is_ambiguous_target_name_without_cargo_markers(input) {
            return Some(Cow::Borrowed(
                "target-like name lacks Cargo build markers outside temporary storage",
            ));
        }
        if let Some(reason) = sacred_overlap_veto_reason(sacred_overlaps) {
            return Some(reason);
        }
        if let Some(reason) = cleanup_rule_veto_reason(input) {
            return Some(reason);
        }
        if input.excluded {
            return Some(Cow::Borrowed("matched user exclusion"));
        }
        if let Some(extension) = hard_refuse_bundle_extension(&input.path) {
            return Some(Cow::Owned(format!(
                "protected bundle/project extension .{extension}"
            )));
        }
        if input.age < self.min_file_age {
            return Some(Cow::Owned(format!(
                "age {}s below minimum {}s",
                input.age.as_secs(),
                self.min_file_age.as_secs()
            )));
        }
        if let Some(reason) = input.active_references.safe_reclaim_reason() {
            return Some(reason);
        }
        if input.is_open {
            return Some(Cow::Borrowed("currently open by another process"));
        }
        None
    }

    fn vetoed(&self, input: &CandidateInput, reason: Cow<'static, str>) -> CandidacyScore {
        CandidacyScore {
            path: input.path.clone(),
            identity: None,
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
            veto_reason: Some(reason),
            classification: input.classification.clone(),
            size_bytes: input.size_bytes,
            age: input.age,
            decision: DecisionOutcome {
                action: DecisionAction::Keep,
                posterior_abandoned: 0.0,
                expected_loss_keep: 0.0,
                expected_loss_delete: self.false_positive_loss,
                calibration_score: 0.0,
                fallback_active: true,
            },
            ledger: EvidenceLedger {
                terms: Vec::new(),
                summary: "hard veto applied".to_string(),
            },
        }
    }
}

fn cleanup_rule_veto_reason(input: &CandidateInput) -> Option<Cow<'static, str>> {
    let rule = cleanup_rule_for_classification(&input.classification)?;
    match rule.reclaim_command {
        ReclaimCommand::ReportOnly => {
            return Some(report_only_cleanup_rule_reason(rule));
        }
        ReclaimCommand::Refuse => {
            return Some(Cow::Owned(format!(
                "{} cleanup rule refuses reclaim",
                rule.name
            )));
        }
        ReclaimCommand::ThinLocalSnapshots => {
            return Some(Cow::Owned(format!(
                "{} requires platform snapshot tooling, not path deletion",
                rule.name
            )));
        }
        ReclaimCommand::RemoveTree
        | ReclaimCommand::RemoveMatchingFiles
        | ReclaimCommand::PromptBeforeRemove => {}
    }

    let minimum_age = rule.age_threshold.minimum_age;
    if input.age < minimum_age {
        return Some(Cow::Owned(format!(
            "{} age {}s below {}s",
            rule.name,
            input.age.as_secs(),
            minimum_age.as_secs()
        )));
    }
    None
}

fn report_only_cleanup_rule_veto_reason(input: &CandidateInput) -> Option<Cow<'static, str>> {
    let rule = cleanup_rule_for_classification(&input.classification)?;
    if rule.reclaim_command == ReclaimCommand::ReportOnly {
        return Some(report_only_cleanup_rule_reason(rule));
    }
    None
}

fn report_only_cleanup_rule_reason(rule: &CleanupRule) -> Cow<'static, str> {
    if rule.name == "spotlight-index-report" {
        Cow::Owned(format!(
            "{} cleanup rule is report-only; deleting the Spotlight index triggers a 1-4 hour rebuild and can cripple the machine",
            rule.name
        ))
    } else {
        Cow::Owned(format!("{} cleanup rule is report-only", rule.name))
    }
}

fn cleanup_rule_allows_embedded_manifest(classification: &ArtifactClassification) -> bool {
    cleanup_rule_for_classification(classification)
        .is_some_and(|rule| rule.name == "release-work-buildroot")
}

fn cleanup_rule_for_classification(
    classification: &ArtifactClassification,
) -> Option<&'static CleanupRule> {
    macos::cleanup_catalog::find_rule(classification.pattern_name.as_ref())
        .or_else(|| linux::cleanup_catalog::find_rule(classification.pattern_name.as_ref()))
}

fn sacred_overlap_veto_reason(overlaps: &[SacredOverlap]) -> Option<Cow<'static, str>> {
    let first = overlaps.first()?;
    let extra = overlaps.len().saturating_sub(1);
    let mut reason = format!("sacred path overlap: {}", first.summary());
    if extra > 0 {
        let _ = write!(reason, "; and {extra} more sacred overlap(s)");
    }
    Some(Cow::Owned(reason))
}

fn hard_refuse_bundle_extension(path: &Path) -> Option<&'static str> {
    path.ancestors().find_map(path_bundle_extension)
}

fn path_bundle_extension(path: &Path) -> Option<&'static str> {
    let extension = path.extension()?.to_string_lossy();
    HARD_REFUSE_BUNDLE_EXTENSIONS
        .iter()
        .copied()
        .find(|protected| extension.eq_ignore_ascii_case(protected))
}

fn factor_location(path: &Path) -> f64 {
    let raw = path.to_string_lossy();
    let text = if std::path::MAIN_SEPARATOR == '\\' {
        std::borrow::Cow::Owned(raw.replace('\\', "/"))
    } else {
        raw
    };

    if text.starts_with("/tmp")
        || text.starts_with("/private/tmp")
        || text.starts_with("/var/tmp")
        || text.starts_with("/data/tmp")
        || text.starts_with("/dev/shm")
    {
        0.95
    } else if text.contains("/data/projects/") && text.contains("/.tmp_") {
        0.90
    } else if text.contains("/data/projects/") && text.contains("/.target") {
        0.85
    } else if text.contains("/data/projects/") && text.contains("/target") {
        0.80
    } else if text.contains("/Library/Developer/Xcode/DerivedData/") {
        0.90
    } else if is_macos_application_support_cache_path(&text) {
        0.82
    } else if text.contains("/.cache/") {
        0.60
    } else if text.contains("/projects/") {
        0.40
    } else if contains_ci(&text, "/documents/") {
        0.10
    } else if is_system_path(path) {
        0.0
    } else {
        0.30
    }
}

fn is_macos_application_support_cache_path(text: &str) -> bool {
    contains_ci(text, "/Library/Application Support/")
        && (contains_ci(text, "/Cache")
            || contains_ci(text, "/Code Cache")
            || contains_ci(text, "/GPUCache")
            || contains_ci(text, "/IndexedDB")
            || contains_ci(text, "/vm_bundles")
            || (contains_ci(text, "/Service Worker/") && contains_ci(text, "/CacheStorage")))
}

fn is_ambiguous_target_name_without_cargo_markers(input: &CandidateInput) -> bool {
    input.classification.category == ArtifactCategory::RustTarget
        && is_generic_target_pattern(input.classification.pattern_name.as_ref())
        && !input.signals.has_strong_signal()
        && !is_volatile_temp_path(&input.path)
}

fn is_generic_target_pattern(pattern_name: &str) -> bool {
    matches!(
        pattern_name,
        "target-prefix" | "target-underscore-prefix" | "target-suffix" | "underscore-target-suffix"
    )
}

fn is_volatile_temp_path(path: &Path) -> bool {
    path.starts_with("/tmp")
        || path.starts_with("/private/tmp")
        || path.starts_with("/var/tmp")
        || path.starts_with("/data/tmp")
        || path.starts_with("/dev/shm")
}

fn factor_name(path: &Path, classification: &ArtifactClassification) -> f64 {
    let name = path
        .file_name()
        .map_or_else(|| Cow::Borrowed(""), |value| value.to_string_lossy());
    let mut score = classification.combined_confidence;
    if name.contains("tmp") || name.contains("temp") || name.contains("cache") {
        score += 0.10;
    }
    if classification.category == ArtifactCategory::RustTarget {
        score += 0.15;
    }
    if contains_ci(&name, "backup") || contains_ci(&name, "save") || contains_ci(&name, "important")
    {
        score -= 0.30;
    }
    score.clamp(0.0, 1.0)
}

fn factor_age(age: Duration) -> f64 {
    let hours = age.as_secs_f64() / 3600.0;
    if hours < 0.5 {
        0.0
    } else if hours < 2.0 {
        0.20
    } else if hours < 4.0 {
        0.70
    } else {
        // Monotonically caps at 1.0 — older artifacts are always at least as
        // likely to be abandoned as younger ones. The previous curve dropped
        // back to 0.25 for 30+ day artifacts, which is backwards.
        1.0
    }
}

fn factor_size(size_bytes: u64) -> f64 {
    const MIB: u64 = 1_048_576;
    const GIB: u64 = 1_073_741_824;
    if size_bytes < MIB {
        0.05
    } else if size_bytes < 10 * MIB {
        0.20
    } else if size_bytes < 100 * MIB {
        0.40
    } else if size_bytes < GIB {
        0.70
    } else if size_bytes < 10 * GIB {
        1.0
    } else if size_bytes < 50 * GIB {
        0.90
    } else {
        0.75
    }
}

fn factor_structure(signals: StructuralSignals) -> f64 {
    if signals.has_git {
        return 0.0;
    }
    // A validated CACHEDIR.TAG root marker is a definitive regenerable-cache
    // signal, independent of the directory's name or nested cargo markers.
    if signals.has_cachedir_tag {
        return 0.95;
    }
    if signals.has_fingerprint || signals.has_incremental {
        return 0.95;
    }
    if signals.has_deps && signals.has_build {
        return 0.85;
    }
    if signals.has_cargo_toml {
        return 0.05;
    }
    if signals.mostly_object_files {
        return 0.90;
    }
    0.40
}

fn pluralize(count: usize, singular: &str, plural: &str) -> String {
    let label = if count == 1 { singular } else { plural };
    format!("{count} {label}")
}

fn pressure_multiplier(urgency: f64) -> f64 {
    // Piecewise linear function that scales the score based on system urgency.
    // - Low urgency (0.0 - 0.3): Gentle scaling (1.0x to 1.3x).
    // - Medium urgency (0.3 - 0.5): Moderate increase (1.3x to 1.5x).
    // - High urgency (0.5 - 0.8): Aggressive ramp (1.5x to 2.0x).
    // - Critical urgency (> 0.8): Panic mode (2.0x to 3.0x), pushing marginal candidates over the threshold.
    let u = urgency.clamp(0.0, 1.0);
    if u <= 0.3 {
        1.0 + u
    } else if u <= 0.5 {
        (u - 0.3).mul_add(1.0, 1.3)
    } else if u <= 0.8 {
        (u - 0.5).mul_add(0.5 / 0.3, 1.5)
    } else {
        (u - 0.8).mul_add(5.0, 2.0)
    }
}

fn posterior_from_score(total_score: f64, confidence: f64) -> f64 {
    // Converts the raw score into a probability (0.0 to 1.0) using a sigmoid function.
    // - `total_score / 1.5`: Normalizes the score (typically 0-3) to a 0-2 range, clamped to 0-1.
    // - `3.5`: Steepness of the sigmoid.
    // - `2.0 * (confidence - 0.5)`: Shifts the curve based on pattern confidence. High confidence
    //   shifts the curve left (higher probability for lower scores).
    let scaled_score = (total_score / 1.5).clamp(0.0, 1.0);
    let logit = 3.5f64.mul_add(scaled_score - 0.5, 2.0 * (confidence - 0.5));
    1.0 / (1.0 + (-logit).exp())
}

fn calibration_score(classification_confidence: f64, factors: ScoreFactors) -> f64 {
    // Heuristic for how "calibrated" the score is.
    // - Primary driver is classification confidence (0.75 weight).
    // - Secondary driver is the consistency between location and structure (0.25 weight).
    //   If location implies safety but structure implies artifact (or vice versa),
    //   calibration drops, increasing uncertainty.
    let spread = (factors.location - factors.structure).abs();
    0.75f64
        .mul_add(classification_confidence, 0.25 * (1.0 - spread))
        .clamp(0.0, 1.0)
}

fn uncertainty_adjusted_losses(
    base_keep_loss: f64,
    base_delete_loss: f64,
    posterior_abandoned: f64,
    calibration: f64,
    uncertainty: f64,
) -> (f64, f64) {
    let posterior = posterior_abandoned.clamp(0.0, 1.0);
    let calibration_penalty = 1.0 - calibration.clamp(0.0, 1.0);
    let uncertainty = uncertainty.clamp(0.0, 1.0);

    let uncertainty_discount = 0.5f64.mul_add(-uncertainty, 1.0);
    let keep_multiplier = (posterior * uncertainty_discount).mul_add(0.80, 1.0);
    let delete_slope = 0.90f64.mul_add(calibration_penalty, 0.90).max(0.90);
    let delete_multiplier = uncertainty.mul_add(delete_slope, 1.0);

    (
        base_keep_loss * keep_multiplier,
        base_delete_loss * delete_multiplier,
    )
}

#[allow(clippy::too_many_arguments)]
fn decide_action(
    total_score: f64,
    min_score: f64,
    keep_loss: f64,
    delete_loss: f64,
    posterior_abandoned: f64,
    calibration: f64,
    fallback_active: bool,
    uncertainty: f64,
) -> DecisionAction {
    if total_score < min_score || fallback_active {
        return DecisionAction::Keep;
    }
    let decision_margin = (keep_loss - delete_loss).abs();
    let review_band = (1.0 - calibration).mul_add(2.0, 5.0f64.mul_add(uncertainty, 1.0));
    if decision_margin <= review_band {
        DecisionAction::Review
    } else if delete_loss < keep_loss {
        let min_delete_posterior =
            (1.0 - calibration.clamp(0.0, 1.0)).mul_add(0.20, 0.20f64.mul_add(uncertainty, 0.60));
        let delete_advantage = delete_advantage_ratio(keep_loss, delete_loss);
        let required_advantage = min_delete_advantage(calibration, uncertainty);
        if posterior_abandoned >= min_delete_posterior.clamp(0.60, 0.95)
            && delete_advantage >= required_advantage
        {
            DecisionAction::Delete
        } else {
            DecisionAction::Review
        }
    } else {
        DecisionAction::Keep
    }
}

fn manual_review_override(
    classification: &ArtifactClassification,
    action: DecisionAction,
) -> DecisionAction {
    if action == DecisionAction::Delete
        && cleanup_rule_for_classification(classification)
            .is_some_and(|rule| rule.reclaim_command == ReclaimCommand::PromptBeforeRemove)
    {
        DecisionAction::Review
    } else {
        action
    }
}

fn delete_advantage_ratio(keep_loss: f64, delete_loss: f64) -> f64 {
    let safe_keep = keep_loss.max(0.0);
    let safe_delete = delete_loss.max(0.0);
    if safe_delete <= f64::EPSILON {
        // Cap at a large finite value to avoid f64::INFINITY flowing into
        // JSON serialization (where "inf" is not valid JSON).
        1e6
    } else {
        safe_keep / safe_delete
    }
}

fn min_delete_advantage(calibration: f64, uncertainty: f64) -> f64 {
    let calibration_penalty = 1.0 - calibration.clamp(0.0, 1.0);
    uncertainty
        .mul_add(1.6, calibration_penalty.mul_add(0.9, 1.2))
        .clamp(1.2, 4.0)
}

fn epistemic_uncertainty(posterior_abandoned: f64, calibration: f64) -> f64 {
    // Calculates uncertainty based on the entropy of the posterior probability and the calibration score.
    // - `entropy`: Measures how "unsure" the probability is (max at p=0.5).
    // - `calibration_penalty`: Adds uncertainty if the model is known to be poorly calibrated.
    // - Mix: 65% entropy, 35% calibration penalty.
    let p = posterior_abandoned.clamp(1e-6, 1.0 - 1e-6);
    let entropy = -(1.0 - p).mul_add((1.0 - p).ln(), p * p.ln()) / std::f64::consts::LN_2;
    let calibration_penalty = 1.0 - calibration.clamp(0.0, 1.0);
    0.65f64
        .mul_add(entropy, 0.35 * calibration_penalty)
        .clamp(0.0, 1.0)
}

#[allow(clippy::too_many_arguments)]
fn build_ledger(
    factors: ScoreFactors,
    weights: ScoringWeights,
    posterior_abandoned: f64,
    base_expected_loss_keep: f64,
    base_expected_loss_delete: f64,
    expected_loss_keep: f64,
    expected_loss_delete: f64,
    calibration: f64,
    uncertainty: f64,
    action: DecisionAction,
) -> EvidenceLedger {
    let terms = vec![
        EvidenceTerm {
            name: "location",
            weight: weights.location,
            value: factors.location,
            contribution: weights.location * factors.location,
        },
        EvidenceTerm {
            name: "name",
            weight: weights.name,
            value: factors.name,
            contribution: weights.name * factors.name,
        },
        EvidenceTerm {
            name: "age",
            weight: weights.age,
            value: factors.age,
            contribution: weights.age * factors.age,
        },
        EvidenceTerm {
            name: "size",
            weight: weights.size,
            value: factors.size,
            contribution: weights.size * factors.size,
        },
        EvidenceTerm {
            name: "structure",
            weight: weights.structure,
            value: factors.structure,
            contribution: weights.structure * factors.structure,
        },
        EvidenceTerm {
            name: "pressure_multiplier",
            weight: 1.0,
            value: factors.pressure_multiplier,
            contribution: factors.pressure_multiplier,
        },
        EvidenceTerm {
            name: "calibration",
            weight: 1.0,
            value: calibration,
            contribution: calibration,
        },
        EvidenceTerm {
            name: "uncertainty",
            weight: 1.0,
            value: uncertainty,
            contribution: uncertainty,
        },
        EvidenceTerm {
            name: "delete_advantage_ratio",
            weight: 1.0,
            value: delete_advantage_ratio(expected_loss_keep, expected_loss_delete),
            contribution: delete_advantage_ratio(expected_loss_keep, expected_loss_delete),
        },
        EvidenceTerm {
            name: "required_delete_advantage",
            weight: 1.0,
            value: min_delete_advantage(calibration, uncertainty),
            contribution: min_delete_advantage(calibration, uncertainty),
        },
    ];
    let decision_margin = expected_loss_keep - expected_loss_delete;
    let delete_advantage = delete_advantage_ratio(expected_loss_keep, expected_loss_delete);
    let required_delete_advantage = min_delete_advantage(calibration, uncertainty);
    let summary = format!(
        "posterior_abandoned={posterior_abandoned:.3}; keep_loss={expected_loss_keep:.2}; \
delete_loss={expected_loss_delete:.2}; base_keep_loss={base_expected_loss_keep:.2}; \
base_delete_loss={base_expected_loss_delete:.2}; loss_margin={decision_margin:.2}; \
uncertainty={uncertainty:.3}; calibration={calibration:.3}; delete_advantage={delete_advantage:.2}; \
required_delete_advantage={required_delete_advantage:.2}; action={action:?}"
    );
    EvidenceLedger { terms, summary }
}

/// ASCII case-insensitive substring search (zero-allocation).
fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
}

fn has_git_component(path: &Path) -> bool {
    path.components().any(|component| match component {
        Component::Normal(name) => name == ".git",
        _ => false,
    })
}

fn is_system_path(path: &Path) -> bool {
    // Check exact root first (never delete `/` itself).
    if path == Path::new("/") {
        return true;
    }

    // Explicitly allow specific subdirectories that would otherwise be caught
    // by parent protections.
    // Note: We must NOT allow the root itself (e.g. /var/tmp) to be deleted.
    if (path.starts_with("/var/tmp") && path != Path::new("/var/tmp"))
        || (path.starts_with("/var/folders") && path != Path::new("/var/folders"))
        || (path.starts_with("/dev/shm") && path != Path::new("/dev/shm"))
    {
        return false;
    }

    // Backstop carve-out (defense-in-depth): a proven regenerable build
    // artifact stranded directly under a worker's `/root` (e.g. a 241 GB
    // `/root/cass-ft-target` cargo target that filled the disk) must be
    // reclaimable when pressure demands it. We lift the `/root` veto ONLY for a
    // candidate whose OWN basename is an obvious build artifact (see
    // `is_obvious_build_artifact_basename`); `/root` itself and every other
    // path under it — credentials, toolchains, config — stay vetoed here.
    //
    // Sensitive root dirs (`.ssh`, `.gnupg`, `.rustup`, `.cargo`, `.config`,
    // `.local`) are ADDITIONALLY hard-guarded by absolute entries in the sacred
    // catalog, so even an artifact-named path *inside* one of them (e.g.
    // `/root/.ssh/foo-target`) is still refused by the sacred-overlap veto that
    // runs after this check. `/home` is intentionally NOT covered here (see the
    // omission below) — `/home/*/projects` protection is enforced by the
    // `is_hardcoded_source_tree` deletion preflight, WITH its own artifact
    // carve-out, and must not be turned into a blanket veto that would break
    // legitimate `target/` cleanup under user project trees.
    if path.starts_with("/root")
        && path != Path::new("/root")
        && is_obvious_build_artifact_basename(path)
    {
        return false;
    }

    // Check prefixes for protected system directories.
    [
        Path::new("/bin"),
        Path::new("/boot"),
        Path::new("/dev"),
        Path::new("/etc"),
        // /home is intentionally omitted to allow cleaning user artifacts
        Path::new("/lib"),
        Path::new("/lib64"),
        Path::new("/opt"),
        Path::new("/proc"),
        Path::new("/root"),
        Path::new("/run"),
        Path::new("/sbin"),
        Path::new("/snap"),
        Path::new("/sys"),
        Path::new("/usr"),
        Path::new("/var"),
    ]
    .iter()
    .any(|root| path == *root || path.starts_with(root))
}

#[cfg(test)]
mod tests {
    use super::{
        ActiveReferenceSummary, CandidateInput, DecisionAction, HARD_REFUSE_BUNDLE_EXTENSIONS,
        ScoringEngine, is_system_path,
    };
    use crate::core::config::ScoringConfig;
    use crate::platform::types::SacredPathSource;
    use crate::scanner::patterns::{ArtifactCategory, ArtifactClassification, StructuralSignals};
    use crate::scanner::protection::{SacredOverlap, SacredOverlapKind};
    use std::borrow::Cow;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    fn default_engine() -> ScoringEngine {
        ScoringEngine::from_config(&ScoringConfig::default(), 30)
    }

    fn classification(confidence: f64, category: ArtifactCategory) -> ArtifactClassification {
        ArtifactClassification {
            pattern_name: Cow::Borrowed("test"),
            category,
            name_confidence: confidence,
            structural_confidence: confidence,
            combined_confidence: confidence,
        }
    }

    #[test]
    fn git_paths_are_hard_vetoed() {
        let engine = default_engine();
        let score = engine.score_candidate(
            &CandidateInput {
                path: PathBuf::from("/data/projects/repo/.git/objects"),
                size_bytes: 1024,
                age: Duration::from_hours(1),
                classification: classification(0.9, ArtifactCategory::RustTarget),
                signals: StructuralSignals::default(),
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            },
            0.8,
        );
        assert!(score.vetoed);
        assert!(score.total_score.abs() < f64::EPSILON);
        assert_eq!(score.decision.action, DecisionAction::Keep);
    }

    #[test]
    fn system_paths_are_vetoed() {
        let engine = default_engine();
        for system_dir in [
            "/lib/x86_64-linux-gnu/libc.so",
            "/lib64/ld-linux.so",
            "/var/lib/dpkg/status",
            "/run/systemd/private",
            "/root/.bashrc",
            "/opt/myapp/bin",
            "/snap/core/current",
        ] {
            let score = engine.score_candidate(
                &CandidateInput {
                    path: PathBuf::from(system_dir),
                    size_bytes: 1_073_741_824,
                    age: Duration::from_hours(6),
                    classification: classification(0.95, ArtifactCategory::RustTarget),
                    signals: StructuralSignals::default(),
                    active_references: ActiveReferenceSummary::default(),
                    is_open: false,
                    excluded: false,
                },
                0.9,
            );
            assert!(
                score.vetoed,
                "system path {system_dir} should be hard-vetoed"
            );
        }
    }

    #[test]
    fn is_system_path_lifts_only_root_build_artifacts() {
        // THE fix: a proven regenerable build artifact stranded under /root is
        // no longer a system path, so it can be scored + reclaimed.
        assert!(!is_system_path(Path::new("/root/cass-ft-target")));
        assert!(!is_system_path(Path::new("/root/target")));
        assert!(!is_system_path(Path::new("/root/foo_target")));
        // A cargo target nested a level under a non-artifact dir is also
        // liftable (only its own basename matters); the parent stays vetoed.
        assert!(!is_system_path(Path::new("/root/build-area/target")));
        assert!(is_system_path(Path::new("/root/build-area")));
    }

    #[test]
    fn is_system_path_still_vetoes_root_and_sensitive_dirs() {
        // /root itself is never liftable, and every non-artifact path under it
        // (credentials, toolchains, config) stays a hard system path.
        for p in [
            "/root",
            "/root/.ssh",
            "/root/.gnupg",
            "/root/.rustup",
            "/root/.cargo",
            "/root/.cargo/registry",
            "/root/.config",
            "/root/.local",
            "/root/.bashrc",
        ] {
            assert!(is_system_path(Path::new(p)), "{p} must stay a system path");
        }
        // Classic system roots are unaffected.
        for p in ["/", "/etc", "/usr", "/bin", "/boot", "/lib", "/opt", "/sys"] {
            assert!(is_system_path(Path::new(p)), "{p} must stay a system path");
        }
        // Guard against a `/rootxyz` false lift (component-based starts_with).
        assert!(!is_system_path(Path::new("/rootxyz/target")));
    }

    #[test]
    fn is_system_path_leaves_home_to_the_source_tree_preflight() {
        // /home is intentionally NOT a system path so user artifacts stay
        // cleanable; the "projects always vetoed" guarantee for
        // /home/<user>/projects is enforced by the is_hardcoded_source_tree
        // deletion preflight (see deletion.rs), NOT by is_system_path.
        assert!(!is_system_path(Path::new("/home/alice/projects/foo")));
        assert!(!is_system_path(Path::new("/home/alice/.cache/build")));
    }

    #[test]
    fn var_tmp_root_is_vetoed() {
        let engine = default_engine();
        let score = engine.score_candidate(
            &CandidateInput {
                path: PathBuf::from("/var/tmp"),
                size_bytes: 4096,
                age: Duration::from_hours(720), // Old
                classification: classification(0.0, ArtifactCategory::Unknown), // No pattern
                signals: StructuralSignals::default(),
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            },
            0.5,
        );
        // This assertion expects the BUG to be present (i.e. we expect it NOT to be vetoed currently)
        // enabling us to confirm the behavior before fixing it.
        // Wait, I should write the assertion for the DESIRED behavior, run it, see it fail.
        assert!(score.vetoed, "root /var/tmp should be hard-vetoed");
    }

    #[test]
    fn user_paths_are_not_vetoed() {
        let engine = default_engine();
        for user_dir in [
            "/home/user/Documents",
            "/dev/shm/test",
            "/var/tmp/test_build",
            "/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T/sbh-build",
        ] {
            let score = engine.score_candidate(
                &CandidateInput {
                    path: PathBuf::from(user_dir),
                    size_bytes: 1_073_741_824,
                    age: Duration::from_hours(6),
                    classification: classification(0.95, ArtifactCategory::RustTarget),
                    signals: StructuralSignals::default(),
                    active_references: ActiveReferenceSummary::default(),
                    is_open: false,
                    excluded: false,
                },
                0.9,
            );
            assert!(
                !score.vetoed,
                "user path {user_dir} should NOT be hard-vetoed"
            );
        }
    }

    #[test]
    fn active_references_are_hard_vetoed_with_structured_reason() {
        let engine = default_engine();
        let mut active_references = ActiveReferenceSummary::default();
        active_references.add_open_file_descriptor(12345, Some("rustc".to_string()));
        active_references.add_open_file_descriptor(12345, Some("rustc".to_string()));
        active_references.add_running_executable(12345, Some("rustc".to_string()));
        active_references.add_mmap_region(12345, Some("rustc".to_string()));

        let score = engine.score_candidate(
            &CandidateInput {
                path: PathBuf::from("/tmp/cargo-target-active"),
                size_bytes: 1_073_741_824,
                age: Duration::from_hours(6),
                classification: classification(0.95, ArtifactCategory::RustTarget),
                signals: StructuralSignals::default(),
                active_references,
                is_open: false,
                excluded: false,
            },
            0.9,
        );

        assert!(score.vetoed);
        assert_eq!(score.decision.action, DecisionAction::Keep);
        assert_eq!(
            score.veto_reason.as_deref(),
            Some(
                "Cannot reclaim safely: pid 12345 (rustc) has 2 open file descriptors, 1 running executable, 1 mmap region"
            )
        );
    }

    #[test]
    fn incomplete_active_reference_visibility_is_reported_as_safety_reason() {
        let engine = default_engine();
        let mut active_references = ActiveReferenceSummary::default();
        active_references.mark_incomplete("fd check incomplete: other-user processes not visible");

        let score = engine.score_candidate(
            &CandidateInput {
                path: PathBuf::from("/tmp/cargo-target-active"),
                size_bytes: 1_073_741_824,
                age: Duration::from_hours(6),
                classification: classification(0.95, ArtifactCategory::RustTarget),
                signals: StructuralSignals::default(),
                active_references,
                is_open: false,
                excluded: false,
            },
            0.9,
        );

        assert!(score.vetoed);
        assert_eq!(score.decision.action, DecisionAction::Keep);
        assert_eq!(
            score.veto_reason.as_deref(),
            Some("fd check incomplete: other-user processes not visible")
        );
    }

    #[test]
    fn each_active_reference_kind_vetoes_reclaim() {
        let engine = default_engine();
        let cases = [
            ("open file descriptor", {
                let mut summary = ActiveReferenceSummary::default();
                summary.add_open_file_descriptor(7, Some("rustc".to_string()));
                summary
            }),
            ("running executable", {
                let mut summary = ActiveReferenceSummary::default();
                summary.add_running_executable(7, Some("rustc".to_string()));
                summary
            }),
            ("mmap region", {
                let mut summary = ActiveReferenceSummary::default();
                summary.add_mmap_region(7, Some("rustc".to_string()));
                summary
            }),
        ];

        for (expected_reason, active_references) in cases {
            let score = engine.score_candidate(
                &CandidateInput {
                    path: PathBuf::from("/tmp/cargo-target-active"),
                    size_bytes: 1_073_741_824,
                    age: Duration::from_hours(6),
                    classification: classification(0.95, ArtifactCategory::RustTarget),
                    signals: StructuralSignals::default(),
                    active_references,
                    is_open: false,
                    excluded: false,
                },
                0.9,
            );

            assert!(score.vetoed, "{expected_reason} should veto reclaim");
            assert_eq!(score.decision.action, DecisionAction::Keep);
            assert!(
                score
                    .veto_reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains(expected_reason)),
                "{expected_reason} missing from veto reason: {:?}",
                score.veto_reason,
            );
        }
    }

    #[test]
    fn high_confidence_old_target_gets_actionable_recommendation() {
        let engine = default_engine();
        let score = engine.score_candidate(
            &CandidateInput {
                path: PathBuf::from("/tmp/cargo-target-quietwillow"),
                size_bytes: 5 * 1_073_741_824,
                age: Duration::from_hours(6),
                classification: classification(0.95, ArtifactCategory::RustTarget),
                signals: StructuralSignals {
                    has_incremental: true,
                    has_deps: true,
                    has_build: true,
                    has_fingerprint: true,
                    has_git: false,
                    has_cargo_toml: false,
                    mostly_object_files: true,
                    has_cachedir_tag: false,
                },
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            },
            0.7,
        );
        assert!(!score.vetoed);
        assert!(score.total_score > 1.0);
        // Decision-theoretic engine may produce Delete or Review depending
        // on calibration/loss balance — both are actionable for high-confidence targets.
        assert_ne!(
            score.decision.action,
            DecisionAction::Keep,
            "high-confidence target should not be kept"
        );
    }

    fn cachedir_tagged_candidate(path: &str, is_open: bool, age: Duration) -> CandidateInput {
        CandidateInput {
            path: PathBuf::from(path),
            size_bytes: 34 * 1_073_741_824,
            age,
            classification: ArtifactClassification {
                pattern_name: Cow::Borrowed("cachedir-tagged-cache"),
                category: ArtifactCategory::CacheDir,
                name_confidence: 0.75,
                structural_confidence: 0.95,
                combined_confidence: 0.75,
            },
            signals: StructuralSignals {
                has_cachedir_tag: true,
                ..StructuralSignals::default()
            },
            active_references: ActiveReferenceSummary::default(),
            is_open,
            excluded: false,
        }
    }

    #[test]
    fn cachedir_tagged_cache_without_name_match_is_actionable() {
        // bd-k0t3r: a 34 GB build cache under an arbitrary name ("srw") that
        // matched no `rch_target_*`/target pattern, but carries a validated root
        // CACHEDIR.TAG. Stale and unopened, it must be reclaimable.
        let engine = default_engine();
        let score = engine.score_candidate(
            &cachedir_tagged_candidate("/data/tmp/srw", false, Duration::from_hours(48)),
            0.7,
        );
        assert!(
            !score.vetoed,
            "a stale, unopened, cachedir-tagged cache must not be vetoed: {:?}",
            score.veto_reason
        );
        assert!(score.total_score > 1.0);
        assert_ne!(
            score.decision.action,
            DecisionAction::Keep,
            "an arbitrarily-named tagged cache should be actionable"
        );
    }

    #[test]
    fn cachedir_tagged_cache_held_open_is_spared() {
        // A live build holds an fd into its target — the open-file veto must
        // still protect it even though the CACHEDIR.TAG makes it look reclaimable.
        let engine = default_engine();
        let score = engine.score_candidate(
            &cachedir_tagged_candidate("/data/tmp/srw", true, Duration::from_hours(48)),
            0.9,
        );
        assert!(score.vetoed, "an open cachedir-tagged cache must be spared");
        assert_eq!(score.decision.action, DecisionAction::Keep);
    }

    #[test]
    fn fresh_cachedir_tagged_cache_is_spared_by_min_age() {
        // A build that just wrote its CACHEDIR.TAG must not be reaped mid-flight;
        // the minimum-age veto is the brake.
        let engine = default_engine();
        let score = engine.score_candidate(
            &cachedir_tagged_candidate("/data/tmp/srw", false, Duration::from_secs(30)),
            0.9,
        );
        assert!(
            score.vetoed,
            "a freshly-written tagged cache must be spared"
        );
        assert_eq!(score.decision.action, DecisionAction::Keep);
    }

    #[test]
    fn cargo_toml_target_suffix_source_root_is_hard_vetoed() {
        let engine = default_engine();
        let score = engine.score_candidate(
            &CandidateInput {
                path: PathBuf::from("/data/projects/asupersync_ansi_c/tools/rust_fuzz_target"),
                size_bytes: 5 * 1_073_741_824,
                age: Duration::from_hours(336),
                classification: ArtifactClassification {
                    pattern_name: Cow::Borrowed("underscore-target-suffix"),
                    category: ArtifactCategory::RustTarget,
                    name_confidence: 0.92,
                    structural_confidence: 0.05,
                    combined_confidence: 0.0659,
                },
                signals: StructuralSignals {
                    has_cargo_toml: true,
                    ..StructuralSignals::default()
                },
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            },
            0.95,
        );

        assert!(score.vetoed);
        assert_eq!(score.decision.action, DecisionAction::Keep);
        assert_eq!(
            score.veto_reason.as_deref(),
            Some("contains Cargo.toml without build-artifact markers")
        );
    }

    #[test]
    fn protected_bundle_extensions_are_hard_vetoed_even_when_artifact_like() {
        let engine = default_engine();

        for extension in HARD_REFUSE_BUNDLE_EXTENSIONS {
            let path = PathBuf::from(format!("/private/tmp/sbh-old-trash/Important.{extension}"));
            let score = engine.score_candidate(
                &CandidateInput {
                    path,
                    size_bytes: 80 * 1_073_741_824,
                    age: Duration::from_hours(24 * 90),
                    classification: classification(0.98, ArtifactCategory::RustTarget),
                    signals: StructuralSignals {
                        has_incremental: true,
                        has_deps: true,
                        has_build: true,
                        has_fingerprint: true,
                        mostly_object_files: true,
                        ..StructuralSignals::default()
                    },
                    active_references: ActiveReferenceSummary::default(),
                    is_open: false,
                    excluded: false,
                },
                1.0,
            );

            assert!(score.vetoed, ".{extension} should be hard-refused");
            assert!(score.total_score.abs() <= f64::EPSILON);
            assert_eq!(score.decision.action, DecisionAction::Keep);
            let expected_reason = format!("protected bundle/project extension .{extension}");
            assert_eq!(score.veto_reason.as_deref(), Some(expected_reason.as_str()));
        }
    }

    #[test]
    fn protected_bundle_extension_match_is_case_insensitive() {
        let engine = default_engine();
        let score = engine.score_candidate(
            &CandidateInput {
                path: PathBuf::from("/private/tmp/sbh-old-trash/Runner.APP"),
                size_bytes: 5 * 1_073_741_824,
                age: Duration::from_hours(24 * 30),
                classification: classification(0.98, ArtifactCategory::RustTarget),
                signals: StructuralSignals {
                    has_incremental: true,
                    has_deps: true,
                    has_build: true,
                    has_fingerprint: true,
                    mostly_object_files: true,
                    ..StructuralSignals::default()
                },
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            },
            1.0,
        );

        assert!(score.vetoed);
        assert_eq!(
            score.veto_reason.as_deref(),
            Some("protected bundle/project extension .app")
        );
    }

    #[test]
    fn protected_bundle_extension_vetoes_descendants() {
        let engine = default_engine();
        let score = engine.score_candidate(
            &CandidateInput {
                path: PathBuf::from(
                    "/private/tmp/sbh-old-trash/Runner.app/Contents/MacOS/cache-target",
                ),
                size_bytes: 5 * 1_073_741_824,
                age: Duration::from_hours(24 * 30),
                classification: classification(0.98, ArtifactCategory::RustTarget),
                signals: StructuralSignals {
                    has_incremental: true,
                    has_deps: true,
                    has_build: true,
                    has_fingerprint: true,
                    mostly_object_files: true,
                    ..StructuralSignals::default()
                },
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            },
            1.0,
        );

        assert!(score.vetoed);
        assert_eq!(
            score.veto_reason.as_deref(),
            Some("protected bundle/project extension .app")
        );
    }

    #[test]
    fn sacred_overlap_hard_vetoes_candidate() {
        let engine = default_engine();
        let path = PathBuf::from("/tmp/old-cache");
        let input = CandidateInput {
            path: path.clone(),
            size_bytes: 5 * 1_073_741_824,
            age: Duration::from_hours(336),
            classification: classification(0.95, ArtifactCategory::RustTarget),
            signals: StructuralSignals {
                has_incremental: true,
                has_deps: true,
                has_build: true,
                has_fingerprint: true,
                mostly_object_files: true,
                ..StructuralSignals::default()
            },
            active_references: ActiveReferenceSummary::default(),
            is_open: false,
            excluded: false,
        };
        let overlap = SacredOverlap {
            candidate_path: path.clone(),
            matched_path: path.join(".beads"),
            pattern: ".beads/".to_string(),
            kind: SacredOverlapKind::ContainsSacred,
            source: SacredPathSource::Builtin,
            reason: "Beads issue state is project data".to_string(),
        };

        let score = engine.score_candidate_with_sacred_overlaps(&input, 0.95, &[overlap]);

        assert!(score.vetoed);
        assert!(score.total_score.abs() <= f64::EPSILON);
        assert_eq!(score.decision.action, DecisionAction::Keep);
        assert!(score.decision.calibration_score.abs() <= f64::EPSILON);
        assert!(score.decision.fallback_active);
        assert!(
            score
                .veto_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("sacred path overlap"))
        );
    }

    #[test]
    fn scoring_is_deterministic() {
        let engine = default_engine();
        let input = CandidateInput {
            path: PathBuf::from("/tmp/cargo-target-same"),
            size_bytes: 2 * 1_073_741_824,
            age: Duration::from_hours(5),
            classification: classification(0.9, ArtifactCategory::RustTarget),
            signals: StructuralSignals {
                has_incremental: true,
                has_deps: true,
                has_build: true,
                has_fingerprint: false,
                has_git: false,
                has_cargo_toml: false,
                mostly_object_files: true,
                has_cachedir_tag: false,
            },
            active_references: ActiveReferenceSummary::default(),
            is_open: false,
            excluded: false,
        };
        let a = engine.score_candidate(&input, 0.5);
        let b = engine.score_candidate(&input, 0.5);
        assert!((a.total_score - b.total_score).abs() < f64::EPSILON);
        assert_eq!(a.decision, b.decision);
        assert_eq!(a.ledger.summary, b.ledger.summary);
    }

    #[test]
    fn pressure_multiplier_increases_total_score() {
        let engine = default_engine();
        let input = CandidateInput {
            path: PathBuf::from("/tmp/cargo-target-pressure"),
            size_bytes: 1_073_741_824,
            age: Duration::from_hours(4),
            classification: classification(0.9, ArtifactCategory::RustTarget),
            signals: StructuralSignals {
                has_incremental: true,
                has_deps: true,
                has_build: true,
                has_fingerprint: true,
                has_git: false,
                has_cargo_toml: false,
                mostly_object_files: false,
                has_cachedir_tag: false,
            },
            active_references: ActiveReferenceSummary::default(),
            is_open: false,
            excluded: false,
        };
        let low = engine.score_candidate(&input, 0.0);
        let high = engine.score_candidate(&input, 1.0);
        assert!(high.total_score >= low.total_score);
    }

    #[test]
    fn pressure_multiplier_scales_aggressively_at_critical() {
        // Verify the "panic mode" scaling (2.0x to 3.0x) for urgency > 0.8
        let critical_low = super::pressure_multiplier(0.8);
        let critical_high = super::pressure_multiplier(1.0);

        // At 0.8, it should be exactly 1.5 + (0.8 - 0.5) * (0.5/0.3) = 1.5 + 0.3 * 1.666 = 2.0
        assert!(
            (critical_low - 2.0).abs() < 1e-6,
            "multiplier at 0.8 should be 2.0"
        );

        // At 1.0, it should be 2.0 + (1.0 - 0.8) * 5.0 = 2.0 + 0.2 * 5.0 = 3.0
        assert!(
            (critical_high - 3.0).abs() < 1e-6,
            "multiplier at 1.0 should be 3.0"
        );
    }

    #[test]
    fn epistemic_uncertainty_penalizes_mid_probability_and_low_calibration() {
        let edge_high_cal = super::epistemic_uncertainty(0.95, 0.95);
        let mid_high_cal = super::epistemic_uncertainty(0.50, 0.95);
        let mid_low_cal = super::epistemic_uncertainty(0.50, 0.55);

        assert!(mid_high_cal > edge_high_cal);
        assert!(mid_low_cal > mid_high_cal);
    }

    #[test]
    fn decision_boundary_prefers_review_when_margin_is_thin_and_uncertain() {
        let u = super::epistemic_uncertainty(0.78, 0.56);
        let action = super::decide_action(1.2, 0.45, 24.0, 22.5, 0.78, 0.56, false, u);
        assert_eq!(action, DecisionAction::Review);
    }

    #[test]
    fn decision_boundary_allows_delete_when_margin_and_confidence_are_strong() {
        let u = super::epistemic_uncertainty(0.93, 0.90);
        let action = super::decide_action(1.6, 0.45, 28.0, 4.0, 0.93, 0.90, false, u);
        assert_eq!(action, DecisionAction::Delete);
    }

    #[test]
    fn decision_boundary_reviews_when_advantage_ratio_is_too_weak_for_risk() {
        let u = super::epistemic_uncertainty(0.90, 0.55);
        let action = super::decide_action(1.6, 0.45, 30.0, 20.0, 0.90, 0.55, false, u);
        assert_eq!(action, DecisionAction::Review);
    }

    #[test]
    fn user_named_trash_requires_manual_review_even_when_score_is_high() {
        let action = super::manual_review_override(
            &ArtifactClassification {
                pattern_name: Cow::Borrowed("user-named-trash"),
                category: ArtifactCategory::TempDir,
                name_confidence: 0.56,
                structural_confidence: 0.40,
                combined_confidence: 0.51,
            },
            DecisionAction::Delete,
        );

        assert_eq!(action, DecisionAction::Review);
    }

    #[test]
    fn release_work_buildroot_younger_than_seven_days_is_kept() {
        let engine = default_engine();
        let input = CandidateInput {
            path: PathBuf::from("/Users/operator/release-work/tool-buildroot"),
            size_bytes: 39 * 1_073_741_824,
            age: Duration::from_hours(24 * 6),
            classification: ArtifactClassification {
                pattern_name: Cow::Borrowed("release-work-buildroot"),
                category: ArtifactCategory::BuildOutput,
                name_confidence: 0.88,
                structural_confidence: 0.40,
                combined_confidence: 0.736,
            },
            signals: StructuralSignals::default(),
            active_references: ActiveReferenceSummary::default(),
            is_open: false,
            excluded: false,
        };

        let score = engine.score_candidate(&input, 0.95);

        assert!(score.vetoed);
        assert_eq!(score.decision.action, DecisionAction::Keep);
        assert_eq!(
            score.veto_reason.as_deref(),
            Some("release-work-buildroot age 518400s below 604800s")
        );
    }

    #[test]
    fn decision_boundary_deletes_when_advantage_ratio_clears_risk_threshold() {
        let u = super::epistemic_uncertainty(0.92, 0.75);
        let action = super::decide_action(1.6, 0.45, 30.0, 4.0, 0.92, 0.75, false, u);
        assert_eq!(action, DecisionAction::Delete);
    }

    #[test]
    fn uncertainty_adjustment_penalizes_delete_loss_more_than_keep_loss() {
        let (keep_loss, delete_loss) =
            super::uncertainty_adjusted_losses(24.0, 10.0, 0.80, 0.50, 0.90);
        assert!(keep_loss > 24.0);
        assert!(delete_loss > 10.0);
        assert!(delete_loss - 10.0 > keep_loss - 24.0);
    }

    /// Regression test: verifies the full scoring pipeline produces Delete decisions
    /// for realistic build artifacts at various pressure levels. This catches the
    /// production bug where /3.0 scaling + 100:30 loss asymmetry made Delete
    /// mathematically impossible at non-Critical pressure.
    #[test]
    fn realistic_artifacts_get_delete_at_red_pressure() {
        let engine = default_engine();

        // Realistic Rust target directory: 4 hours old, 2 GiB, high-confidence
        // structural markers, located in /data/projects.
        let input = CandidateInput {
            path: PathBuf::from("/data/projects/myapp/target"),
            size_bytes: 2 * 1_073_741_824,
            age: Duration::from_hours(4),
            classification: classification(0.85, ArtifactCategory::RustTarget),
            signals: StructuralSignals {
                has_incremental: true,
                has_deps: true,
                has_build: true,
                has_fingerprint: true,
                has_git: false,
                has_cargo_toml: false,
                mostly_object_files: false,
                has_cachedir_tag: false,
            },
            active_references: ActiveReferenceSummary::default(),
            is_open: false,
            excluded: false,
        };

        // At Red pressure (urgency ~0.7), must produce Delete.
        let red = engine.score_candidate(&input, 0.7);
        assert!(!red.vetoed, "realistic target should not be vetoed");
        assert!(red.total_score > 0.45, "score should exceed min_score");
        assert_eq!(
            red.decision.action,
            DecisionAction::Delete,
            "realistic artifact at Red pressure must get Delete, not {:?} (score={:.3}, posterior={:.3})",
            red.decision.action,
            red.total_score,
            red.decision.posterior_abandoned,
        );

        // At Yellow pressure (urgency ~0.4), should still produce Delete or Review.
        let yellow = engine.score_candidate(&input, 0.4);
        assert_ne!(
            yellow.decision.action,
            DecisionAction::Keep,
            "realistic artifact at Yellow pressure should not be kept (score={:.3}, posterior={:.3})",
            yellow.total_score,
            yellow.decision.posterior_abandoned,
        );
    }

    /// Verify that a range of typical agent swarm artifacts all produce Delete
    /// at Critical pressure. This is the absolute minimum bar for the scoring
    /// engine to be useful in production.
    #[test]
    fn swarm_artifacts_delete_at_critical_pressure() {
        let engine = default_engine();
        let urgency = 0.95; // Critical pressure

        let artifacts = vec![
            // Rust target in /tmp
            (
                "/tmp/cargo-target-quietwillow",
                5 * 1_073_741_824u64,
                2 * 3600u64,
                0.90,
            ),
            // Rust target in /data/projects
            (
                "/data/projects/foo/.target_opus_42",
                3 * 1_073_741_824,
                3 * 3600,
                0.80,
            ),
            // Agent build artifact
            (
                "/data/projects/bar/pi_agent_rust_target",
                1_073_741_824,
                4 * 3600,
                0.75,
            ),
            // Hidden target dir
            (
                "/data/projects/baz/.tmp_target_rch",
                2 * 1_073_741_824,
                6 * 3600,
                0.85,
            ),
        ];

        for (path, size, age_secs, confidence) in &artifacts {
            let input = CandidateInput {
                path: PathBuf::from(path),
                size_bytes: *size,
                age: Duration::from_secs(*age_secs),
                classification: classification(*confidence, ArtifactCategory::RustTarget),
                signals: StructuralSignals {
                    has_incremental: true,
                    has_deps: true,
                    has_build: false,
                    has_fingerprint: true,
                    has_git: false,
                    has_cargo_toml: false,
                    mostly_object_files: false,
                    has_cachedir_tag: false,
                },
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            };

            let score = engine.score_candidate(&input, urgency);
            assert!(!score.vetoed, "{path}: should not be vetoed");
            assert_eq!(
                score.decision.action,
                DecisionAction::Delete,
                "{path}: must get Delete at critical pressure (score={:.3}, posterior={:.3})",
                score.total_score,
                score.decision.posterior_abandoned,
            );
        }
    }
}
