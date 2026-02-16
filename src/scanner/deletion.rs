//! Deletion executor: circuit-breaker-guarded recursive removal with dry-run support.
//!
//! Pipeline: scored candidates -> sort by score desc -> safety pre-flight
//! -> delete batch -> log results -> re-check pressure -> decide continue/stop.
//!
//! Safety pre-flight checks before each deletion:
//! 1. Path still exists (may have been cleaned by another process)
//! 2. Path is not currently open by any process (Linux: /proc/*/fd)
//! 3. Parent directory is writable
//! 4. Directory does not contain .git/ (final safety net)
//!
//! Circuit breaker: 3 consecutive failures -> halt batch (daemon retries next cycle).

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::core::errors::{Result, SbhError};
use crate::logger::dual::{ActivityEvent, ActivityLoggerHandle};
use crate::logger::jsonl::ScoreFactorsRecord;
use crate::scanner::scoring::{CandidacyScore, DecisionAction, ScoreFactors};
use crate::scanner::walker;

// ──────────────────── configuration ────────────────────

/// Configuration for the deletion executor.
#[derive(Debug, Clone)]
pub struct DeletionConfig {
    /// Maximum candidates to delete in one batch before re-checking pressure.
    pub max_batch_size: usize,
    /// Whether to skip actual deletion (log what would be deleted).
    pub dry_run: bool,
    /// Minimum score threshold for deletion eligibility.
    pub min_score: f64,
    /// Number of consecutive failures before circuit breaker trips.
    pub circuit_breaker_threshold: u32,
    /// Cooldown duration after circuit breaker trips.
    pub circuit_breaker_cooldown: Duration,
    /// Whether to check /proc for open files before deleting (Linux only).
    pub check_open_files: bool,
}

impl Default for DeletionConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 10,
            dry_run: false,
            min_score: 0.5,
            circuit_breaker_threshold: 3,
            circuit_breaker_cooldown: Duration::from_secs(30),
            check_open_files: true,
        }
    }
}

// ──────────────────── report types ────────────────────

/// Plan produced before deletion begins.
#[derive(Debug, Clone)]
pub struct DeletionPlan {
    pub candidates: Vec<CandidacyScore>,
    pub total_reclaimable_bytes: u64,
    pub estimated_items: usize,
}

/// Summary after a deletion batch completes.
#[derive(Debug, Clone)]
pub struct DeletionReport {
    pub items_deleted: usize,
    pub items_failed: usize,
    pub items_skipped: usize,
    pub bytes_freed: u64,
    pub duration: Duration,
    pub errors: Vec<DeletionError>,
    pub dry_run: bool,
    pub circuit_breaker_tripped: bool,
    pub deleted_paths: Vec<PathBuf>,
}

/// A single deletion failure record.
#[derive(Debug, Clone)]
pub struct DeletionError {
    pub path: PathBuf,
    pub error: String,
    pub error_code: String,
    pub recoverable: bool,
}

/// Reason a candidate was skipped during pre-flight checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    PathGone,
    FileOpen,
    ContainsGit,
    NotWritable,
    Vetoed,
    BelowThreshold,
    Symlink,
}

// ──────────────────── executor ────────────────────

/// The deletion executor: takes scored candidates and deletes them safely.
pub struct DeletionExecutor {
    config: DeletionConfig,
    logger: Option<ActivityLoggerHandle>,
}

impl DeletionExecutor {
    /// Create a new executor with the given config and optional logger handle.
    pub fn new(config: DeletionConfig, logger: Option<ActivityLoggerHandle>) -> Self {
        Self { config, logger }
    }

    /// Build a deletion plan from scored candidates.
    ///
    /// Filters to only actionable candidates (decision=Delete, not vetoed,
    /// above score threshold), then sorts by score descending.
    pub fn plan(&self, mut candidates: Vec<CandidacyScore>) -> DeletionPlan {
        // Filter: only Delete decisions, not vetoed, above threshold.
        candidates.retain(|c| {
            c.decision.action == DecisionAction::Delete
                && !c.vetoed
                && c.total_score >= self.config.min_score
        });

        // Sort by score descending (most obvious artifacts first).
        candidates.sort_by(|a, b| {
            b.total_score
                .partial_cmp(&a.total_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let total_reclaimable_bytes: u64 = candidates.iter().map(|c| c.size_bytes).sum();
        let estimated_items = candidates.len();

        DeletionPlan {
            candidates,
            total_reclaimable_bytes,
            estimated_items,
        }
    }

    /// Execute a deletion plan, deleting up to `max_batch_size` candidates.
    ///
    /// Returns a report summarizing what was deleted, skipped, or failed.
    /// If `should_skip` returns `true` for a candidate path, it is skipped.
    #[allow(clippy::too_many_lines)]
    pub fn execute(
        &self,
        plan: &DeletionPlan,
        should_skip: Option<&dyn Fn(&Path) -> bool>,
    ) -> DeletionReport {
        let start = Instant::now();
        let mut report = DeletionReport {
            items_deleted: 0,
            items_failed: 0,
            items_skipped: 0,
            bytes_freed: 0,
            duration: Duration::ZERO,
            errors: Vec::new(),
            dry_run: self.config.dry_run,
            circuit_breaker_tripped: false,
            deleted_paths: Vec::new(),
        };

        let mut consecutive_failures: u32 = 0;
        let limit = plan.candidates.len().min(self.config.max_batch_size);
        // Build an open-path ancestor index once per batch to avoid deep per-candidate
        // inode-tree scans on large artifact directories.
        let open_paths = if self.config.check_open_files {
            let roots = plan
                .candidates
                .iter()
                .take(limit)
                .map(|candidate| candidate.path.clone())
                .collect::<Vec<_>>();
            let (paths, complete) = walker::collect_open_path_ancestors(&roots);

            if !complete {
                self.log_event(ActivityEvent::Error {
                    code: "SBH-3003".to_string(),
                    message:
                        "open file scan incomplete due to system load - aborting batch for safety"
                            .to_string(),
                });
                // Fail safe: abort the entire batch because we cannot guarantee
                // that any candidate is safe to delete.
                report.duration = start.elapsed();
                // Mark all candidates as skipped/failed due to safety check.
                report.items_failed = limit;
                for candidate in plan.candidates.iter().take(limit) {
                    report.errors.push(DeletionError {
                        path: candidate.path.clone(),
                        error: "safety check incomplete".to_string(),
                        error_code: "SBH-3003".to_string(),
                        recoverable: true,
                    });
                }
                return report;
            }
            Some(paths)
        } else {
            None
        };

        for candidate in plan.candidates.iter().take(limit) {
            // Circuit breaker: stop immediately on consecutive failures.
            // The daemon's next scan cycle can retry with fresh candidates.
            if consecutive_failures >= self.config.circuit_breaker_threshold {
                report.circuit_breaker_tripped = true;
                self.log_event(ActivityEvent::Error {
                    code: "SBH-2003".to_string(),
                    message: format!(
                        "circuit breaker tripped after {consecutive_failures} consecutive failures, \
                         halting batch"
                    ),
                });
                break;
            }

            // Dynamic skip check (e.g. target free space met).
            if let Some(skip) = should_skip
                && skip(&candidate.path)
            {
                report.items_skipped += 1;
                // We don't log an error event for this skip as it's a success condition (target met).
                continue;
            }

            // Pre-flight safety checks.
            match self.preflight_check(&candidate.path, open_paths.as_ref()) {
                Ok(()) => {}
                Err(skip) => {
                    report.items_skipped += 1;
                    self.log_event(ActivityEvent::ArtifactDeletionFailed {
                        path: candidate.path.to_string_lossy().to_string(),
                        error_code: "SBH-2003".to_string(),
                        error_message: format!("skipped: {skip:?}"),
                    });
                    continue;
                }
            }

            if self.config.dry_run {
                report.items_deleted += 1;
                report.bytes_freed += candidate.size_bytes;
                Self::log_dry_run(candidate);
                continue;
            }

            // Actual deletion.
            let del_start = Instant::now();
            match self.delete_path(&candidate.path) {
                Ok(()) => {
                    #[allow(clippy::cast_possible_truncation)]
                    let duration_ms = del_start.elapsed().as_millis() as u64;
                    report.items_deleted += 1;
                    report.bytes_freed += candidate.size_bytes;
                    report.deleted_paths.push(candidate.path.clone());
                    consecutive_failures = 0;

                    self.log_deletion_success(candidate, duration_ms);
                }
                Err(e) => {
                    report.items_failed += 1;
                    consecutive_failures += 1;
                    let error = DeletionError {
                        path: candidate.path.clone(),
                        error: e.to_string(),
                        error_code: e.code().to_string(),
                        recoverable: e.is_retryable(),
                    };

                    self.log_event(ActivityEvent::ArtifactDeletionFailed {
                        path: candidate.path.to_string_lossy().to_string(),
                        error_code: error.error_code.clone(),
                        error_message: error.error.clone(),
                    });

                    report.errors.push(error);
                }
            }
        }

        report.duration = start.elapsed();
        report
    }

    // ──────────────────── pre-flight checks ────────────────────

    #[allow(clippy::unused_self)]
    fn preflight_check(
        &self,
        path: &Path,
        open_paths: Option<&HashSet<PathBuf>>,
    ) -> std::result::Result<(), SkipReason> {
        // 1. Path still exists (use symlink_metadata to not follow symlinks).
        let Ok(meta) = fs::symlink_metadata(path) else {
            return Err(SkipReason::PathGone);
        };

        // 2. Reject symlinks — remove_dir_all follows symlinks into the target,
        //    which could destroy data outside watched directories.
        if meta.file_type().is_symlink() {
            return Err(SkipReason::Symlink);
        }

        // 3. Parent directory is writable (effective permission for this process).
        if let Some(parent) = path.parent()
            && !is_writable(parent)
        {
            return Err(SkipReason::NotWritable);
        }

        // 4. Does not contain .git (safety net — checks 3 levels deep).
        if meta.is_dir() && contains_nested_git(path, 3) {
            return Err(SkipReason::ContainsGit);
        }

        // 5. Not currently open by any process (Linux /proc check).
        if let Some(open) = open_paths
            && walker::is_path_open_by_ancestor(path, open)
        {
            return Err(SkipReason::FileOpen);
        }

        Ok(())
    }

    // ──────────────────── deletion ────────────────────

    #[allow(clippy::unused_self)]
    fn delete_path(&self, path: &Path) -> Result<()> {
        // Re-check with symlink_metadata (not metadata/is_dir which follow symlinks)
        // to close the TOCTOU window between preflight_check and actual deletion.
        let meta = fs::symlink_metadata(path).map_err(|e| SbhError::io(path, e))?;
        if meta.file_type().is_symlink() {
            return Err(SbhError::Runtime {
                details: format!("path became a symlink before deletion: {}", path.display()),
            });
        }

        if meta.is_dir() {
            fs::remove_dir_all(path).map_err(|e| SbhError::io(path, e))?;
        } else {
            fs::remove_file(path).map_err(|e| SbhError::io(path, e))?;
        }

        // Post-deletion verification (symlink_metadata to avoid following dangling symlinks).
        if fs::symlink_metadata(path).is_ok() {
            return Err(SbhError::Runtime {
                details: format!("path still exists after deletion: {}", path.display()),
            });
        }

        Ok(())
    }

    // ──────────────────── logging helpers ────────────────────

    fn log_event(&self, event: ActivityEvent) {
        if let Some(logger) = &self.logger {
            logger.send(event);
        }
    }

    fn log_deletion_success(&self, candidate: &CandidacyScore, duration_ms: u64) {
        self.log_event(ActivityEvent::ArtifactDeleted {
            path: candidate.path.to_string_lossy().to_string(),
            size_bytes: candidate.size_bytes,
            score: candidate.total_score,
            factors: factors_to_record(&candidate.factors),
            pressure: String::new(), // Caller doesn't pass pressure level here
            free_pct: 0.0,
            duration_ms,
        });
    }

    fn log_dry_run(_candidate: &CandidacyScore) {
        // Dry-run candidates are displayed at the CLI level; no audit event is
        // emitted to avoid polluting the stats engine (ScanCompleted counts, etc.).
    }
}

// ──────────────────── writable check ────────────────────

/// Check if the current process can write to the given path.
///
/// Uses `access(W_OK)` on Unix which checks effective permissions (owner, group,
/// ACLs, and mount flags) — more reliable than `permissions().readonly()` which
/// only checks if any write bit is set.
fn is_writable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        nix::unistd::access(path, nix::unistd::AccessFlags::W_OK).is_ok()
    }
    #[cfg(not(unix))]
    {
        // Fallback: check write bit (same as old behavior).
        path.metadata()
            .map(|m| !m.permissions().readonly())
            .unwrap_or(false)
    }
}

/// Shallow recursive check for `.git` directories within `path`.
///
/// Walks at most `max_depth` levels to catch nested git repositories
/// that the immediate `path.join(".git").exists()` check would miss.
fn contains_nested_git(path: &Path, max_depth: usize) -> bool {
    if max_depth == 0 {
        return false;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return false;
    };
    for entry in entries.flatten() {
        if entry.file_name() == ".git" {
            return true;
        }
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() && !ft.is_symlink() && contains_nested_git(&entry.path(), max_depth - 1) {
            return true;
        }
    }
    false
}

// ──────────────────── conversions ────────────────────

fn factors_to_record(f: &ScoreFactors) -> ScoreFactorsRecord {
    ScoreFactorsRecord {
        location: f.location,
        name: f.name,
        age: f.age,
        size: f.size,
        structure: f.structure,
    }
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::patterns::{ArtifactCategory, ArtifactClassification};
    use crate::scanner::scoring::{DecisionOutcome, EvidenceLedger, ScoreFactors};
    use std::borrow::Cow;

    fn make_candidate(path: &Path, size: u64, score: f64) -> CandidacyScore {
        CandidacyScore {
            path: path.to_path_buf(),
            total_score: score,
            factors: ScoreFactors {
                location: 0.8,
                name: 0.9,
                age: 0.7,
                size: 0.6,
                structure: 0.85,
                pressure_multiplier: 1.0,
            },
            vetoed: false,
            veto_reason: None,
            classification: ArtifactClassification {
                pattern_name: Cow::Borrowed("target"),
                category: ArtifactCategory::RustTarget,
                name_confidence: 0.95,
                structural_confidence: 0.90,
                combined_confidence: 0.92,
            },
            size_bytes: size,
            age: Duration::from_secs(3600),
            decision: DecisionOutcome {
                action: DecisionAction::Delete,
                posterior_abandoned: 0.92,
                expected_loss_keep: 1.5,
                expected_loss_delete: 0.3,
                calibration_score: 0.85,
                fallback_active: false,
            },
            ledger: EvidenceLedger {
                terms: Vec::new(),
                summary: "test candidate".to_string(),
            },
        }
    }

    #[test]
    fn plan_filters_and_sorts_candidates() {
        let dir = tempfile::tempdir().unwrap();
        let p1 = dir.path().join("a");
        let p2 = dir.path().join("b");
        let p3 = dir.path().join("c");

        let mut c1 = make_candidate(&p1, 1000, 0.7);
        let c2 = make_candidate(&p2, 2000, 0.9);
        let c3 = make_candidate(&p3, 500, 0.3); // below threshold

        // c1: vetoed
        c1.vetoed = true;

        let executor = DeletionExecutor::new(
            DeletionConfig {
                min_score: 0.5,
                ..Default::default()
            },
            None,
        );
        let plan = executor.plan(vec![c1, c2, c3]);

        // Only c2 should survive (c1 vetoed, c3 below threshold).
        assert_eq!(plan.candidates.len(), 1);
        assert_eq!(plan.candidates[0].path, p2);
        assert_eq!(plan.total_reclaimable_bytes, 2000);
    }

    #[test]
    fn plan_sorts_by_score_descending() {
        let dir = tempfile::tempdir().unwrap();
        let p1 = dir.path().join("a");
        let p2 = dir.path().join("b");
        let p3 = dir.path().join("c");

        let c1 = make_candidate(&p1, 1000, 0.7);
        let c2 = make_candidate(&p2, 2000, 0.9);
        let c3 = make_candidate(&p3, 1500, 0.8);

        let executor = DeletionExecutor::new(DeletionConfig::default(), None);
        let plan = executor.plan(vec![c1, c2, c3]);

        assert_eq!(plan.candidates.len(), 3);
        assert_eq!(plan.candidates[0].path, p2); // score 0.9
        assert_eq!(plan.candidates[1].path, p3); // score 0.8
        assert_eq!(plan.candidates[2].path, p1); // score 0.7
    }

    #[test]
    fn execute_deletes_files_and_dirs() {
        let dir = tempfile::tempdir().unwrap();

        // Create a file.
        let file_path = dir.path().join("deleteme.txt");
        fs::write(&file_path, "artifact data").unwrap();

        // Create a directory tree.
        let dir_path = dir.path().join("target_dir");
        fs::create_dir_all(dir_path.join("subdir")).unwrap();
        fs::write(dir_path.join("build.o"), "object file").unwrap();
        fs::write(dir_path.join("subdir/lib.rlib"), "rlib").unwrap();

        let c1 = make_candidate(&file_path, 13, 0.85);
        let c2 = make_candidate(&dir_path, 100, 0.90);

        let executor = DeletionExecutor::new(DeletionConfig::default(), None);
        let plan = executor.plan(vec![c1, c2]);
        let report = executor.execute(&plan, None);

        assert_eq!(report.items_deleted, 2);
        assert_eq!(report.items_failed, 0);
        assert!(!file_path.exists());
        assert!(!dir_path.exists());
    }

    #[test]
    fn dry_run_does_not_delete() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("keep_me.txt");
        fs::write(&file_path, "important").unwrap();

        let c = make_candidate(&file_path, 9, 0.85);
        let executor = DeletionExecutor::new(
            DeletionConfig {
                dry_run: true,
                ..Default::default()
            },
            None,
        );
        let plan = executor.plan(vec![c]);
        let report = executor.execute(&plan, None);

        assert_eq!(report.items_deleted, 1);
        assert!(report.dry_run);
        assert!(file_path.exists(), "file should still exist in dry-run");
    }

    #[test]
    fn skips_path_with_dot_git() {
        let dir = tempfile::tempdir().unwrap();
        let git_dir = dir.path().join("my_project");
        fs::create_dir_all(git_dir.join(".git")).unwrap();
        fs::write(git_dir.join("Cargo.toml"), "[package]").unwrap();

        let c = make_candidate(&git_dir, 5000, 0.95);
        let executor = DeletionExecutor::new(DeletionConfig::default(), None);
        let plan = executor.plan(vec![c]);
        let report = executor.execute(&plan, None);

        assert_eq!(report.items_deleted, 0);
        assert_eq!(report.items_skipped, 1);
        assert!(git_dir.exists());
    }

    #[test]
    fn skips_nonexistent_path() {
        let dir = tempfile::tempdir().unwrap();
        let gone = dir.path().join("already_gone");

        let c = make_candidate(&gone, 1000, 0.85);
        let executor = DeletionExecutor::new(DeletionConfig::default(), None);
        let plan = executor.plan(vec![c]);
        let report = executor.execute(&plan, None);

        assert_eq!(report.items_deleted, 0);
        assert_eq!(report.items_skipped, 1);
    }

    #[test]
    fn respects_batch_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let mut candidates = Vec::new();
        for i in 0..10 {
            let p = dir.path().join(format!("file_{i}.txt"));
            fs::write(&p, format!("data {i}")).unwrap();
            candidates.push(make_candidate(&p, 100, 0.8));
        }

        let executor = DeletionExecutor::new(
            DeletionConfig {
                max_batch_size: 3,
                ..Default::default()
            },
            None,
        );
        let plan = executor.plan(candidates);
        let report = executor.execute(&plan, None);

        assert_eq!(report.items_deleted, 3);
        // 7 files should remain.
        let remaining = fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(remaining, 7);
    }

    #[test]
    fn pressure_check_stops_early() {
        let dir = tempfile::tempdir().unwrap();
        let mut candidates = Vec::new();
        for i in 0..5 {
            let p = dir.path().join(format!("file_{i}.txt"));
            fs::write(&p, format!("data {i}")).unwrap();
            candidates.push(make_candidate(&p, 100, 0.8));
        }

        let executor = DeletionExecutor::new(DeletionConfig::default(), None);
        let plan = executor.plan(candidates);

        // Pressure check: resolved after first deletion.
        let call_count = std::sync::atomic::AtomicU32::new(0);
        let report = executor.execute(
            &plan,
            Some(&|_path| {
                let count = call_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                count >= 1 // Resolved after first
            }),
        );

        // Should delete 1, then stop.
        assert_eq!(report.items_deleted, 1);
    }

    #[test]
    fn successful_batch_does_not_trip_breaker() {
        let dir = tempfile::tempdir().unwrap();
        let mut candidates = Vec::new();
        // Create paths that don't exist (will fail deletion) but pass preflight
        // by creating them first, then making parent read-only... actually that
        // would also fail preflight. Let's test the plan + report structure instead.
        for i in 0..5 {
            let p = dir.path().join(format!("f{i}.txt"));
            fs::write(&p, "x").unwrap();
            candidates.push(make_candidate(&p, 10, 0.8));
        }

        // With a valid setup, all should succeed.
        let executor = DeletionExecutor::new(
            DeletionConfig {
                circuit_breaker_threshold: 3,
                circuit_breaker_cooldown: Duration::from_millis(10),
                ..Default::default()
            },
            None,
        );
        let plan = executor.plan(candidates);
        let report = executor.execute(&plan, None);

        assert_eq!(report.items_deleted, 5);
        assert!(!report.circuit_breaker_tripped);
    }

    #[test]
    fn deletion_error_records_details() {
        let dir = tempfile::tempdir().unwrap();
        // File that will succeed.
        let good = dir.path().join("good.txt");
        fs::write(&good, "ok").unwrap();
        // A path that we remove between planning and execution.
        let gone = dir.path().join("vanishes.txt");
        fs::write(&gone, "bye").unwrap();

        let c1 = make_candidate(&good, 2, 0.85);
        let c2 = make_candidate(&gone, 3, 0.80);

        let executor = DeletionExecutor::new(DeletionConfig::default(), None);
        let plan = executor.plan(vec![c1, c2]);

        // Remove the file before execution to trigger skip.
        fs::remove_file(&gone).unwrap();

        let report = executor.execute(&plan, None);
        assert_eq!(report.items_deleted, 1);
        assert_eq!(report.items_skipped, 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn circuit_breaker_halts_batch_on_consecutive_failures() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let mut candidates = Vec::new();

        // Create directories with unremovable subdirs (chmod 000 prevents remove_dir_all).
        // Preflight passes because the parent of each dir IS writable, but
        // remove_dir_all fails because the locked subdir can't be traversed.
        for i in 0..5 {
            let d = dir.path().join(format!("dir_{i}"));
            let sub = d.join("locked_sub");
            fs::create_dir_all(&sub).unwrap();
            fs::write(sub.join("data.txt"), "x").unwrap();
            fs::set_permissions(&sub, fs::Permissions::from_mode(0o000)).unwrap();
            candidates.push(make_candidate(&d, 100, 0.8));
        }

        let executor = DeletionExecutor::new(
            DeletionConfig {
                circuit_breaker_threshold: 3,
                check_open_files: false,
                ..Default::default()
            },
            None,
        );
        let plan = executor.plan(candidates);
        let report = executor.execute(&plan, None);

        assert!(
            report.circuit_breaker_tripped,
            "circuit breaker should have tripped"
        );
        // Should have attempted exactly 3 (threshold) before halting.
        assert_eq!(report.items_failed, 3);
        // Remaining 2 candidates were never attempted.
        assert_eq!(report.items_deleted, 0);

        // Restore permissions so tempdir cleanup works.
        for i in 0..5 {
            let sub = dir.path().join(format!("dir_{i}")).join("locked_sub");
            let _ = fs::set_permissions(&sub, fs::Permissions::from_mode(0o755));
        }
    }

    #[cfg(unix)]
    #[test]
    fn is_writable_detects_read_only_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let readonly_dir = dir.path().join("readonly");
        fs::create_dir(&readonly_dir).unwrap();

        assert!(is_writable(&readonly_dir), "should be writable initially");

        fs::set_permissions(&readonly_dir, fs::Permissions::from_mode(0o555)).unwrap();
        assert!(
            !is_writable(&readonly_dir),
            "should not be writable after chmod 555"
        );

        // Restore for cleanup.
        fs::set_permissions(&readonly_dir, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nested_open_file_is_detected_for_parent_directory() {
        use crate::scanner::walker;

        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b").join("c");
        fs::create_dir_all(&nested).unwrap();
        let file_path = nested.join("in_use.bin");
        fs::write(&file_path, "payload").unwrap();

        let handle = fs::File::open(&file_path).unwrap();

        let (open_paths, _) = walker::collect_open_path_ancestors(&[dir.path().to_path_buf()]);

        // Guard: skip if /proc doesn't expose our own fds (hidepid=2, containers)
        // or if budget limits produce no ancestor data for this path.
        if !open_paths.contains(&file_path) {
            drop(handle);
            return;
        }

        assert!(
            walker::is_path_open_by_ancestor(dir.path(), &open_paths),
            "open file in nested subtree should mark parent as open"
        );
        drop(handle);
    }

    #[test]
    fn deletion_report_tracks_deleted_paths() {
        let dir = tempfile::tempdir().unwrap();

        let file1 = dir.path().join("a.txt");
        let file2 = dir.path().join("b.txt");
        let file3 = dir.path().join("c.txt");
        fs::write(&file1, "data1").unwrap();
        fs::write(&file2, "data2").unwrap();
        fs::write(&file3, "data3").unwrap();

        let c1 = make_candidate(&file1, 5, 0.85);
        let c2 = make_candidate(&file2, 5, 0.80);
        let c3 = make_candidate(&file3, 5, 0.75);

        let executor = DeletionExecutor::new(DeletionConfig::default(), None);
        let plan = executor.plan(vec![c1, c2, c3]);
        let report = executor.execute(&plan, None);

        assert_eq!(report.items_deleted, 3);
        assert_eq!(report.deleted_paths.len(), 3);
        assert!(report.deleted_paths.contains(&file1));
        assert!(report.deleted_paths.contains(&file2));
        assert!(report.deleted_paths.contains(&file3));
    }
}
