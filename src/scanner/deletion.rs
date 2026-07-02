//! Deletion executor: circuit-breaker-guarded recursive removal with dry-run support.
//!
//! Pipeline: scored candidates -> sort by score desc -> safety pre-flight
//! -> delete batch -> log results -> re-check pressure -> decide continue/stop.
//!
//! Safety pre-flight checks before each deletion:
//! 1. Path still exists (may have been cleaned by another process)
//! 2. Path is not currently open by any process (Linux: /proc/*/fd; macOS: PAL/libproc)
//! 3. Parent directory is writable
//! 4. Directory does not contain .git/ (final safety net)
//! 5. Directory is not a Cargo source root misclassified as a target artifact
//! 6. Candidate identity still matches the object observed by the scanner
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
use crate::scanner::patterns::{
    ArtifactCategory, ArtifactClassification, StructuralSignals, is_obvious_build_artifact_basename,
};
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
    /// Whether to check platform open-file evidence before deleting.
    pub check_open_files: bool,
    /// Whether deletion candidates must carry a scanner-observed filesystem identity.
    pub require_identity: bool,
}

impl Default for DeletionConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 10,
            dry_run: false,
            min_score: 0.5,
            circuit_breaker_threshold: 5,
            circuit_breaker_cooldown: Duration::from_secs(30),
            check_open_files: true,
            require_identity: false,
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
    /// Paths actually removed from the filesystem.
    pub items_deleted: usize,
    pub items_failed: usize,
    pub items_skipped: usize,
    /// Paths that passed all safety checks and would have been removed in dry-run mode.
    pub items_would_delete: usize,
    /// Bytes actually reclaimed from the filesystem.
    pub bytes_freed: u64,
    /// Bytes that would have been reclaimed in dry-run mode.
    pub bytes_would_free: u64,
    pub duration: Duration,
    pub errors: Vec<DeletionError>,
    pub dry_run: bool,
    pub circuit_breaker_tripped: bool,
    pub deleted_paths: Vec<PathBuf>,
    /// Paths skipped specifically because the executor cannot write to the
    /// parent directory. Almost always indicates a misconfigured systemd
    /// unit (`ProtectSystem=strict` + `ReadWritePaths=` whitelist that
    /// excludes the path). The daemon uses this list to emit a single
    /// actionable warning per batch instead of per-skip log noise.
    pub not_writable_paths: Vec<PathBuf>,
    /// Candidates that failed a safety/preflight/delete check and should be
    /// cooled down before retrying with identical evidence.
    pub backoff_candidates: Vec<CandidacyScore>,
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
    IdentityUnavailable,
    IdentityMismatch,
    ContainsCargoManifest,
    /// Path sits under a hardcoded source-tree location
    /// (`/data/projects/*`, `/home/*/projects/*`, `/Users/*/projects/*`) AND
    /// the candidate's basename does not match the obvious-build-artifact
    /// carve-out (`target`, `node_modules`, `__pycache__`, `.rch-target-*`, etc.).
    /// Also fires unconditionally for any path with a `.git` ancestor or that
    /// IS a `.git` directory.
    ///
    /// This is the carnage-prevention floor that overrides operator config.
    /// See `is_hardcoded_source_tree` and `is_obvious_build_artifact_basename`
    /// in this module for the exact predicates.
    HardcodedSourceTree,
    /// Directory contains source-code marker files (Cargo.toml, package.json,
    /// pyproject.toml, etc.) and so is treated as source code even if it lacks
    /// build-output markers. Catches synced source stubs that the cargo-only
    /// veto misses (root cause of the 2026-05-22 frankenterm crate deletions).
    LooksLikeSourceCode,
}

fn should_backoff_skip(reason: SkipReason) -> bool {
    !matches!(reason, SkipReason::PathGone | SkipReason::BelowThreshold)
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
            items_would_delete: 0,
            bytes_freed: 0,
            bytes_would_free: 0,
            duration: Duration::ZERO,
            errors: Vec::new(),
            dry_run: self.config.dry_run,
            circuit_breaker_tripped: false,
            deleted_paths: Vec::new(),
            not_writable_paths: Vec::new(),
            backoff_candidates: Vec::new(),
        };

        let mut consecutive_failures: u32 = 0;
        let limit = plan.candidates.len().min(self.config.max_batch_size);
        // Build an open-path ancestor index once per mutating batch to avoid
        // deep per-candidate inode-tree scans on large artifact directories.
        // Dry-run never mutates, so it must not pay a global process-fd scan
        // or fail a planning report because live process visibility was partial.
        let open_paths = if self.config.check_open_files && !self.config.dry_run {
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
                    report.backoff_candidates.push(candidate.clone());
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
                report.backoff_candidates.push(candidate.clone());
                continue;
            }

            // Pre-flight safety checks.
            match self.preflight_check(candidate, open_paths.as_ref()) {
                Ok(()) => {}
                Err(skip) => {
                    report.items_skipped += 1;
                    // Reset consecutive failure counter on skip — a skipped candidate
                    // is not a failure and shouldn't let unrelated failures accumulate
                    // across different path prefixes (e.g. FUSE mount failures shouldn't
                    // trip the breaker for normal /tmp deletions).
                    consecutive_failures = 0;
                    // NotWritable goes into a dedicated bucket so the daemon can
                    // emit one actionable warning per batch (systemd unit fix)
                    // instead of one log line per candidate.
                    if matches!(skip, SkipReason::NotWritable) {
                        report.not_writable_paths.push(candidate.path.clone());
                    }
                    if should_backoff_skip(skip) {
                        report.backoff_candidates.push(candidate.clone());
                    }
                    // Only log unexpected skip reasons. PathGone (parent deleted),
                    // ContainsGit, Cargo manifests, hardcoded source-tree refusal,
                    // and source-code-marker refusal are normal safety vetoes that
                    // produce excessive log noise when logged as errors.
                    if !matches!(
                        skip,
                        SkipReason::PathGone
                            | SkipReason::ContainsGit
                            | SkipReason::ContainsCargoManifest
                            | SkipReason::HardcodedSourceTree
                            | SkipReason::LooksLikeSourceCode
                    ) {
                        eprintln!(
                            "[SBH-EXECUTOR] skip: {} ({:?})",
                            candidate.path.display(),
                            skip
                        );
                        self.log_event(ActivityEvent::ArtifactDeletionFailed {
                            path: candidate.path.to_string_lossy().to_string(),
                            error_code: "SBH-2003".to_string(),
                            error_message: format!("skipped: {skip:?}"),
                        });
                    }
                    continue;
                }
            }

            if self.config.dry_run {
                report.items_would_delete += 1;
                report.bytes_would_free += candidate.size_bytes;
                Self::log_dry_run(candidate);
                continue;
            }

            // Actual deletion.
            let del_start = Instant::now();
            match self.delete_path(candidate) {
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
                    eprintln!("[SBH-EXECUTOR] fail: {} ({})", candidate.path.display(), e);
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
                    report.backoff_candidates.push(candidate.clone());
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
        candidate: &CandidacyScore,
        open_paths: Option<&HashSet<PathBuf>>,
    ) -> std::result::Result<(), SkipReason> {
        let path = &candidate.path;
        // 0. Hardcoded source-tree refusal — runs BEFORE the existence check
        //    so the result holds even for stat-failing paths. This is the
        //    carnage-prevention floor: operators cannot disable it via config.
        //    Background: on 2026-05-16 sbh wiped ~87 working trees under
        //    /data/projects on trj when its scorer misclassified source crate
        //    directories as build artifacts. On 2026-05-22 the same scoring
        //    bug deleted synced frankenterm crate stubs across the vmi worker
        //    fleet. Hardcoded path refusal makes both impossible regardless
        //    of `root_paths` / `excluded_paths` config.
        if is_hardcoded_source_tree(path) {
            return Err(SkipReason::HardcodedSourceTree);
        }

        // 1. Path still exists (use symlink_metadata to not follow symlinks).
        let Ok(meta) = fs::symlink_metadata(path) else {
            return Err(SkipReason::PathGone);
        };

        // 2. Reject symlinks — remove_dir_all follows symlinks into the target,
        //    which could destroy data outside watched directories.
        if meta.file_type().is_symlink() {
            return Err(SkipReason::Symlink);
        }

        // 3. Scanner-observed identity must still refer to this same entry.
        self.verify_candidate_identity(candidate)?;

        // 4. Parent directory is writable (effective permission for this process).
        if let Some(parent) = path.parent()
            && !is_writable(parent)
        {
            return Err(SkipReason::NotWritable);
        }

        // 5. Does not contain .git (safety net — checks 3 levels deep).
        if meta.is_dir() && contains_nested_git(path, 3) {
            return Err(SkipReason::ContainsGit);
        }

        // 6. Does not look like a Cargo source root that a target-name
        //    heuristic misclassified. This final guard is intentionally
        //    independent of scoring so stale/buggy candidates cannot reach
        //    remove_dir_all.
        if meta.is_dir() && contains_cargo_manifest_without_artifact_markers(path) {
            return Err(SkipReason::ContainsCargoManifest);
        }

        // 6b. Source-code marker check — catches stubs that the cargo-only
        //     veto misses. Any directory containing Cargo.toml, package.json,
        //     pyproject.toml, go.mod, *.rs/*.py/*.ts/*.go source files is
        //     treated as source regardless of build-output markers.
        //
        //     Carve-out: a directory positively identified as a Go cache is
        //     exempt. Every cached module in a GOMODCACHE legitimately ships
        //     its own `go.mod` + `.go` files, which would otherwise trip this
        //     veto and make the (read-only, regenerable) module cache
        //     permanently unreclaimable. The structural GoCache identity
        //     (trim.txt + hex shards, or cache/download) cannot be produced by
        //     a real source tree, so the exemption is safe.
        if meta.is_dir()
            && candidate.classification.category != ArtifactCategory::GoCache
            && looks_like_source_code(path)
        {
            return Err(SkipReason::LooksLikeSourceCode);
        }

        // 7. Not currently open by any process (Linux /proc check).
        if let Some(open) = open_paths
            && walker::is_path_open_by_ancestor(path, open)
        {
            return Err(SkipReason::FileOpen);
        }

        Ok(())
    }

    // ──────────────────── deletion ────────────────────

    fn verify_candidate_identity(
        &self,
        candidate: &CandidacyScore,
    ) -> std::result::Result<(), SkipReason> {
        let Some(expected) = candidate.identity else {
            return if self.config.require_identity {
                Err(SkipReason::IdentityUnavailable)
            } else {
                Ok(())
            };
        };
        if !identity_is_supported(expected) {
            return Err(SkipReason::IdentityUnavailable);
        }

        let current =
            walker::identity_for_path(&candidate.path, false).map_err(|_| SkipReason::PathGone)?;
        if !identity_is_supported(current) {
            return Err(SkipReason::IdentityUnavailable);
        }
        if current != expected {
            return Err(SkipReason::IdentityMismatch);
        }

        Ok(())
    }

    #[allow(clippy::unused_self)]
    fn delete_path(&self, candidate: &CandidacyScore) -> Result<()> {
        let path = &candidate.path;
        // Re-check with symlink_metadata (not metadata/is_dir which follow symlinks)
        // to close the TOCTOU window between preflight_check and actual deletion.
        let meta = fs::symlink_metadata(path).map_err(|e| SbhError::io(path, e))?;
        if meta.file_type().is_symlink() {
            return Err(SbhError::Runtime {
                details: format!("path became a symlink before deletion: {}", path.display()),
            });
        }
        self.verify_candidate_identity(candidate)
            .map_err(|skip| SbhError::Runtime {
                details: format!(
                    "path identity changed before deletion: {} ({skip:?})",
                    path.display()
                ),
            })?;

        if meta.is_dir() {
            // Read-only regenerable caches (Go GOCACHE/GOMODCACHE, cargo
            // registry/git caches) are written 0555/0444 by their toolchains,
            // which makes a plain `remove_dir_all` fail partway with EACCES and
            // leave the disk space behind. For those — and only those — defeat
            // the read-only bits within the (already preflight-approved)
            // subtree. Every other candidate uses conservative removal, where a
            // read-only directory acts as a natural brake.
            if classification_allows_force_remove(&candidate.classification) {
                remove_dir_all_force(path).map_err(|e| SbhError::io(path, e))?;
            } else {
                fs::remove_dir_all(path).map_err(|e| SbhError::io(path, e))?;
            }
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

fn identity_is_supported(identity: walker::FsIdentity) -> bool {
    #[cfg(unix)]
    {
        let _ = identity;
        true
    }
    #[cfg(not(unix))]
    {
        // The non-Unix fallback currently cannot provide stable inode/device
        // identity. Treat a zero/zero identity as unavailable so v2 deletion
        // fails closed instead of comparing only the file kind.
        identity.device_id != 0 || identity.inode != 0
    }
}

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

// ──────────────────── read-only-cache removal ────────────────────

/// Categories/patterns whose directories the build toolchain marks read-only
/// and which are fully regenerable, so the executor may widen permissions
/// within the (already preflight-approved) subtree in order to remove them.
///
/// Kept deliberately narrow: for every other classification we keep the plain
/// `remove_dir_all`, so a read-only directory remains a natural brake on
/// deletion. The members here are all caches the owning tool rebuilds on demand:
///   * `GoCache` — GOCACHE/GOMODCACHE (dirs `0555`, files `0444`).
///   * cargo registry/git caches (`.cargo/registry/src` and git checkouts are
///     read-only) and rch's isolated `CARGO_HOME` staging dirs.
fn classification_allows_force_remove(c: &ArtifactClassification) -> bool {
    if c.category == ArtifactCategory::GoCache {
        return true;
    }
    matches!(
        c.pattern_name.as_ref(),
        "opaque-cargo-cache"
            | "cargo-home-prefix"
            | "rch-cargo-home"
            | "tmp-cargo-home"
            | "dot-cargo-prefix"
    )
}

/// `fs::remove_dir_all` that defeats read-only directory/file permission bits.
///
/// Standard `remove_dir_all` cannot unlink an entry inside a `0555` directory —
/// removing a child requires *write* permission on the parent directory — so on
/// a Go module cache (every module dir `0555`) it fails partway with `EACCES`
/// and leaves the tree, and its disk space, behind. We try the fast path first;
/// only on a permission error do we walk the subtree granting `u+rwx` to
/// directories (and `u+w` to files) and retry. Permission widening is confined
/// to the candidate subtree the executor already approved for deletion, and the
/// walk never follows symlinks, so it can never affect paths outside it.
fn remove_dir_all_force(path: &Path) -> std::io::Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            chmod_tree_writable(path);
            fs::remove_dir_all(path)
        }
        Err(e) => Err(e),
    }
}

/// Recursively grant the owner the traversal/write permission needed to remove
/// a subtree. Best-effort: individual `set_permissions` failures are ignored so
/// one odd entry can't abort the whole reclaim — the subsequent
/// `remove_dir_all` is the real success/failure signal. Operates on
/// `symlink_metadata` and never recurses through a symlink, so it cannot chmod
/// anything outside the subtree.
#[cfg(unix)]
fn chmod_tree_writable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };
    let file_type = meta.file_type();
    if file_type.is_symlink() {
        return;
    }
    let mode = meta.permissions().mode();
    if file_type.is_dir() {
        // u+rwx so we can list, traverse, and unlink children. Chmod before
        // descending so a `0000`/`0555` dir becomes readable for `read_dir`.
        if mode & 0o700 != 0o700 {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o700));
        }
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                chmod_tree_writable(&entry.path());
            }
        }
    } else if mode & 0o200 == 0 {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o200));
    }
}

/// Non-Unix fallback: clear the read-only attribute on the directory itself.
#[cfg(not(unix))]
fn chmod_tree_writable(path: &Path) {
    if let Ok(meta) = fs::symlink_metadata(path) {
        let mut perms = meta.permissions();
        if perms.readonly() {
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
            let _ = fs::set_permissions(path, perms);
        }
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

/// Hardcoded refusal: paths inside well-known source-tree locations must
/// never be deleted, regardless of operator config — UNLESS the candidate's
/// basename clearly identifies it as a build/cache artifact (see
/// [`is_obvious_build_artifact_basename`]).
///
/// Covered locations (refused unless basename is artifact-like):
/// - `/data/projects/...`
/// - `/home/*/projects/...`
/// - `/Users/*/projects/...`
///
/// Plus an UNCONDITIONAL refusal (no artifact carve-out) for:
/// - any path with an ancestor directory literally named `.git`
/// - the path itself being named `.git`
///
/// This is the carnage-prevention floor that overrides any operator config.
/// The 2026-05-16 trj incident and the 2026-05-22 vmi rerun both deleted
/// source crate directories under `/data/projects/`; this function makes
/// arbitrary-name deletion there impossible while still letting the
/// scanner reclaim `target/`, `node_modules/`, etc.
///
/// Note: matching is case-sensitive and operates on the path's string form.
/// On case-insensitive filesystems (default APFS) a path entered as
/// `/Home/...` would not match `/home/...`; in practice operators use the
/// canonical case so this is acceptable. Windows-native paths
/// (`C:\Users\...`) are not currently covered — sbh's target deployments
/// are Linux and macOS only.
fn is_hardcoded_source_tree(path: &Path) -> bool {
    let s = path.to_string_lossy();

    // Determine whether the candidate sits under a protected source-tree root.
    // `starts_with("/data/projects/")` also handles a trailing-slash variant
    // (`Path::new("/data/projects/").to_string_lossy()` preserves the slash).
    let in_protected_root = s == "/data/projects"
        || s.starts_with("/data/projects/")
        || is_under_user_projects(&s, "/home/")
        || is_under_user_projects(&s, "/Users/");

    if in_protected_root {
        // Carve-out: allow deletion if the candidate's basename clearly
        // identifies it as a disposable build/cache artifact. This is the
        // ONLY way to permit `target/`, `node_modules/`, etc. cleanup
        // inside operator-configured source roots. Arbitrary unknown
        // basenames (e.g., `src`, `docs`, or a misclassified crate name)
        // stay vetoed — that's the carnage-prevention guarantee.
        if !is_obvious_build_artifact_basename(path) {
            return true;
        }
    }

    // Walk the path AND every ancestor looking for a component literally
    // named `.git`. This catches both the deep case (`/repo/.git/objects/pack`)
    // and the leaf case (`/repo/.git` as the deletion target itself). It
    // runs UNCONDITIONALLY — there is no artifact carve-out for `.git`
    // metadata, even if the basename happens to look like an artifact.
    // (`contains_nested_git` only inspects CHILDREN of the candidate, so a
    // `.git` directory passed in directly would not be caught without this
    // loop checking the path itself.)
    for ancestor in path.ancestors() {
        if ancestor.file_name().and_then(|n| n.to_str()) == Some(".git") {
            return true;
        }
    }

    false
}

/// Helper for `is_hardcoded_source_tree`: matches `<root><user>/projects[/...]`
/// where `<root>` is `/home/` or `/Users/`. Splits on the first `/` after the
/// root prefix so a bare `/home/<user>` (no further components) does NOT match.
fn is_under_user_projects(path_str: &str, root: &str) -> bool {
    let Some(rest) = path_str.strip_prefix(root) else {
        return false;
    };
    // rest must have at least one `/` and the component after that `/` must
    // be `projects` exactly or `projects/...`.
    let Some((_, after_user)) = rest.split_once('/') else {
        return false;
    };
    after_user == "projects" || after_user.starts_with("projects/")
}

/// Returns true if `path` directly contains files that indicate it's a source
/// directory rather than a build artifact. Catches synced source stubs that
/// don't have build-output markers and so slip past
/// `contains_cargo_manifest_without_artifact_markers`.
///
/// We check direct children only (no recursion) to keep this O(dirsize). The
/// presence of even one source marker is enough to veto deletion — false
/// positives only mean keeping a few bytes of disk; false negatives mean
/// destroying source.
fn looks_like_source_code(path: &Path) -> bool {
    // Manifest filenames — any one is a hard veto.
    const MANIFEST_FILES: &[&str] = &[
        "Cargo.toml",
        "package.json",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "go.mod",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "Gemfile",
        "Pipfile",
        "requirements.txt",
        "tsconfig.json",
        "deno.json",
        "mix.exs",
        "Project.toml",
    ];

    // Source-file extensions — any one direct-child source file vetos.
    const SOURCE_EXTS: &[&str] = &[
        "rs", "py", "ts", "tsx", "js", "jsx", "go", "java", "kt", "rb", "ex", "exs", "ml", "hs",
        "cpp", "cc", "c", "h", "hpp", "swift", "scala", "clj", "cljs", "lua", "jl",
    ];

    let Ok(entries) = fs::read_dir(path) else {
        return false;
    };

    for entry in entries.flatten() {
        let name_os = entry.file_name();
        let name = name_os.to_string_lossy();

        // Manifest match (case-insensitive for cross-platform safety).
        if MANIFEST_FILES.iter().any(|m| name.eq_ignore_ascii_case(m)) {
            return true;
        }

        // Source extension match — only count regular files, never symlinks.
        if let Ok(ft) = entry.file_type()
            && ft.is_file()
            && let Some(ext) = std::path::Path::new(name.as_ref())
                .extension()
                .and_then(|e| e.to_str())
            && SOURCE_EXTS.iter().any(|s| ext.eq_ignore_ascii_case(s))
        {
            return true;
        }
    }

    false
}

/// Shallow check for Cargo source roots.
///
/// The scanner can legitimately reclaim cargo target directories named
/// `target`, `*_target`, or `*-target`, but real source crates can also have
/// those names. A direct child `Cargo.toml` without cargo build-output markers
/// is a hard final veto.
fn contains_cargo_manifest_without_artifact_markers(path: &Path) -> bool {
    let Ok(entries) = fs::read_dir(path) else {
        return false;
    };

    let mut signals = StructuralSignals::default();

    for entry in entries.flatten() {
        let name_os = entry.file_name();
        let name = name_os.to_string_lossy();

        if name.eq_ignore_ascii_case("cargo.toml") {
            signals.has_cargo_toml = true;
        } else if name == "incremental" {
            signals.has_incremental = true;
        } else if name == "deps" {
            signals.has_deps = true;
        } else if name == "build" {
            signals.has_build = true;
        } else if name == ".fingerprint" {
            signals.has_fingerprint = true;
        }
    }

    signals.has_cargo_toml
        && !(signals.has_fingerprint
            || (signals.has_incremental && signals.has_deps)
            || (signals.has_build && signals.has_deps))
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
            identity: None,
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
            age: Duration::from_hours(1),
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

    fn make_identity_candidate(path: &Path, size: u64, score: f64) -> CandidacyScore {
        let mut candidate = make_candidate(path, size, score);
        candidate.identity = Some(walker::identity_for_path(path, false).unwrap());
        candidate
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
    fn require_identity_allows_matching_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("target-cache");
        fs::write(&file_path, "artifact data").unwrap();

        let candidate = make_identity_candidate(&file_path, 13, 0.85);
        let executor = DeletionExecutor::new(
            DeletionConfig {
                require_identity: true,
                check_open_files: false,
                ..Default::default()
            },
            None,
        );
        let plan = executor.plan(vec![candidate]);
        let report = executor.execute(&plan, None);

        assert_eq!(report.items_deleted, 1);
        assert!(!file_path.exists());
    }

    #[test]
    fn require_identity_skips_candidate_without_identity() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("target-cache");
        fs::write(&file_path, "artifact data").unwrap();

        let candidate = make_candidate(&file_path, 13, 0.85);
        let executor = DeletionExecutor::new(
            DeletionConfig {
                require_identity: true,
                check_open_files: false,
                ..Default::default()
            },
            None,
        );
        let plan = executor.plan(vec![candidate]);
        let report = executor.execute(&plan, None);

        assert_eq!(report.items_deleted, 0);
        assert_eq!(report.items_skipped, 1);
        assert!(file_path.exists());
    }

    #[test]
    fn preflight_rejects_replaced_candidate_identity() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("target-cache");
        let moved_path = dir.path().join("moved-cache");
        fs::write(&file_path, "old artifact").unwrap();
        let candidate = make_identity_candidate(&file_path, 13, 0.85);
        fs::rename(&file_path, &moved_path).unwrap();
        fs::write(&file_path, "replacement artifact").unwrap();

        let executor = DeletionExecutor::new(
            DeletionConfig {
                require_identity: true,
                check_open_files: false,
                ..Default::default()
            },
            None,
        );
        let plan = executor.plan(vec![candidate]);
        let report = executor.execute(&plan, None);

        assert_eq!(report.items_deleted, 0);
        assert_eq!(report.items_skipped, 1);
        assert!(file_path.exists());
        assert!(moved_path.exists());
    }

    #[test]
    fn delete_path_rechecks_identity_before_removal() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("target-cache");
        let moved_path = dir.path().join("moved-cache");
        fs::write(&file_path, "old artifact").unwrap();
        let candidate = make_identity_candidate(&file_path, 13, 0.85);
        fs::rename(&file_path, &moved_path).unwrap();
        fs::write(&file_path, "replacement artifact").unwrap();

        let executor = DeletionExecutor::new(
            DeletionConfig {
                require_identity: true,
                check_open_files: false,
                ..Default::default()
            },
            None,
        );

        assert!(executor.delete_path(&candidate).is_err());
        assert!(file_path.exists());
        assert!(moved_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn preflight_rejects_symlink_substitution() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let candidate_path = dir.path().join("target");
        let moved_path = dir.path().join("real-target");
        fs::create_dir(&candidate_path).unwrap();
        let candidate = make_identity_candidate(&candidate_path, 13, 0.85);
        fs::rename(&candidate_path, &moved_path).unwrap();
        symlink(&moved_path, &candidate_path).unwrap();

        let executor = DeletionExecutor::new(
            DeletionConfig {
                require_identity: true,
                check_open_files: false,
                ..Default::default()
            },
            None,
        );
        let plan = executor.plan(vec![candidate]);
        let report = executor.execute(&plan, None);

        assert_eq!(report.items_deleted, 0);
        assert_eq!(report.items_skipped, 1);
        assert!(candidate_path.exists());
        assert!(moved_path.exists());
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

        assert_eq!(report.items_deleted, 0);
        assert_eq!(report.bytes_freed, 0);
        assert_eq!(report.items_would_delete, 1);
        assert_eq!(report.bytes_would_free, 9);
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
    fn skips_scored_delete_for_cargo_manifest_source_root() {
        let dir = tempfile::tempdir().unwrap();
        let crate_dir = dir
            .path()
            .join("asupersync_ansi_c")
            .join("tools")
            .join("rust_fuzz_target");
        fs::create_dir_all(crate_dir.join("src")).unwrap();
        fs::write(
            crate_dir.join("Cargo.toml"),
            "[package]\nname = \"rust_fuzz_target\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(crate_dir.join("Cargo.lock"), "# lockfile").unwrap();
        fs::write(crate_dir.join("src/main.rs"), "fn main() {}\n").unwrap();

        let c = make_candidate(&crate_dir, 5000, 0.99);
        let executor = DeletionExecutor::new(
            DeletionConfig {
                check_open_files: false,
                ..DeletionConfig::default()
            },
            None,
        );
        let plan = executor.plan(vec![c]);
        let report = executor.execute(&plan, None);

        assert_eq!(report.items_deleted, 0);
        assert_eq!(report.items_skipped, 1);
        assert!(crate_dir.exists());
        assert!(crate_dir.join("Cargo.toml").exists());
        assert!(crate_dir.join("src/main.rs").exists());
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

    #[cfg(unix)]
    #[test]
    fn deletion_report_tracks_not_writable_paths() {
        // Regression: when systemd ProtectSystem=strict + ReadWritePaths
        // omits a path, preflight returns NotWritable. The daemon needs
        // these paths separately so it can emit a single actionable
        // warning per batch instead of one log line per skip.
        use std::os::unix::fs::PermissionsExt;

        // Skip when running as root: root bypasses unix mode bits, so
        // chmod 555 doesn't actually deny write and the preflight check
        // would succeed unexpectedly. CI runs as non-root so this still
        // exercises the path; on dev hosts and root-owned shells we just
        // skip cleanly to avoid a false-positive failure.
        if nix::unistd::Uid::effective().is_root() {
            eprintln!("skipping deletion_report_tracks_not_writable_paths: running as root");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let readonly_parent = dir.path().join("readonly");
        fs::create_dir(&readonly_parent).unwrap();
        let target = readonly_parent.join("artifact");
        fs::write(&target, "data").unwrap();

        // Strip write permission from the parent so preflight returns
        // NotWritable. (Unix-only; Windows ACLs differ.)
        fs::set_permissions(&readonly_parent, fs::Permissions::from_mode(0o555)).unwrap();

        let cand = make_candidate(&target, 4, 0.9);
        let executor = DeletionExecutor::new(
            DeletionConfig {
                check_open_files: false,
                ..DeletionConfig::default()
            },
            None,
        );
        let plan = executor.plan(vec![cand]);
        let report = executor.execute(&plan, None);

        // Restore perms so tempdir cleanup can proceed.
        fs::set_permissions(&readonly_parent, fs::Permissions::from_mode(0o755)).ok();

        assert_eq!(report.items_deleted, 0);
        assert_eq!(report.items_skipped, 1);
        assert_eq!(report.not_writable_paths.len(), 1);
        assert_eq!(report.not_writable_paths[0], target);
    }

    // ──────────────────── hardcoded safety floor ────────────────────

    #[test]
    fn hardcoded_source_tree_matches_data_projects() {
        assert!(is_hardcoded_source_tree(Path::new("/data/projects")));
        assert!(is_hardcoded_source_tree(Path::new("/data/projects/")));
        assert!(is_hardcoded_source_tree(Path::new(
            "/data/projects/frankenterm"
        )));
        assert!(is_hardcoded_source_tree(Path::new(
            "/data/projects/frankenterm/crates/frankenterm-core"
        )));
    }

    #[test]
    fn hardcoded_source_tree_matches_home_projects() {
        assert!(is_hardcoded_source_tree(Path::new("/home/ubuntu/projects")));
        assert!(is_hardcoded_source_tree(Path::new(
            "/home/ubuntu/projects/sbh"
        )));
        assert!(is_hardcoded_source_tree(Path::new(
            "/home/jeff/projects/something/deep"
        )));
    }

    #[test]
    fn hardcoded_source_tree_matches_users_projects() {
        assert!(is_hardcoded_source_tree(Path::new(
            "/Users/jemanuel/projects"
        )));
        assert!(is_hardcoded_source_tree(Path::new(
            "/Users/jemanuel/projects/storage_ballast_helper"
        )));
    }

    #[test]
    fn hardcoded_source_tree_skips_unrelated_paths() {
        assert!(!is_hardcoded_source_tree(Path::new("/tmp/junk")));
        assert!(!is_hardcoded_source_tree(Path::new("/data/tmp/build")));
        assert!(!is_hardcoded_source_tree(Path::new("/var/tmp/cache")));
        assert!(!is_hardcoded_source_tree(Path::new("/home/ubuntu/.cache")));
        assert!(!is_hardcoded_source_tree(Path::new(
            "/data/dataset/something"
        )));
        // `/home/ubuntu/project` (singular) should NOT match
        assert!(!is_hardcoded_source_tree(Path::new("/home/ubuntu/project")));
    }

    #[test]
    fn hardcoded_source_tree_matches_git_ancestor() {
        // Any path with a `.git` ancestor (including the path itself) is refused.
        assert!(is_hardcoded_source_tree(Path::new(
            "/some/repo/.git/objects/pack"
        )));
        assert!(is_hardcoded_source_tree(Path::new(
            "/srv/code/.git/refs/heads"
        )));
        // Leaf case: the candidate itself IS a .git directory.
        assert!(is_hardcoded_source_tree(Path::new("/srv/code/.git")));
        assert!(is_hardcoded_source_tree(Path::new("/.git")));
    }

    #[test]
    fn looks_like_source_code_detects_cargo_toml() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("Cargo.toml"), "[package]\nname=\"x\"").unwrap();
        assert!(looks_like_source_code(dir.path()));
    }

    #[test]
    fn looks_like_source_code_detects_rust_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("lib.rs"), "pub fn x() {}").unwrap();
        assert!(looks_like_source_code(dir.path()));
    }

    #[test]
    fn looks_like_source_code_detects_package_json() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        assert!(looks_like_source_code(dir.path()));
    }

    #[test]
    fn looks_like_source_code_detects_python_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("main.py"), "x = 1").unwrap();
        assert!(looks_like_source_code(dir.path()));
    }

    #[test]
    fn looks_like_source_code_ignores_build_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        // A pure cargo target/ would contain these but no source manifests.
        fs::create_dir_all(dir.path().join("debug/deps")).unwrap();
        fs::create_dir_all(dir.path().join(".fingerprint")).unwrap();
        fs::write(dir.path().join(".rustc_info.json"), "{}").unwrap();
        assert!(!looks_like_source_code(dir.path()));
    }

    #[test]
    fn preflight_vetoes_hardcoded_source_tree() {
        let executor = DeletionExecutor::new(DeletionConfig::default(), None);
        // A real path is not required — the hardcoded check runs before stat.
        let candidate = make_candidate(
            Path::new("/data/projects/frankenterm/crates/frankenterm-core"),
            1,
            1.0,
        );
        let result = executor.preflight_check(&candidate, None);
        assert_eq!(result, Err(SkipReason::HardcodedSourceTree));
    }

    #[test]
    fn preflight_vetoes_source_code_dir() {
        // Even outside known source roots, a dir containing source markers
        // vetoes. We use package.json + a .ts file rather than Cargo.toml so
        // the existing ContainsCargoManifest check (step 5) doesn't fire
        // first — this test specifically validates step 5b (LooksLikeSourceCode)
        // catches non-cargo source projects that the older veto missed.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{\"name\":\"x\"}").unwrap();
        fs::write(dir.path().join("index.ts"), "export const x = 1;").unwrap();

        let executor = DeletionExecutor::new(DeletionConfig::default(), None);
        let candidate = make_candidate(dir.path(), 1, 1.0);
        let result = executor.preflight_check(&candidate, None);
        assert_eq!(result, Err(SkipReason::LooksLikeSourceCode));
    }

    #[test]
    fn preflight_cargo_manifest_still_takes_precedence_over_source_marker() {
        // Defensive: if a dir has BOTH Cargo.toml and a .rs file, the older
        // ContainsCargoManifest veto fires first (step 5 before 5b). Either
        // skip is a successful veto — we just lock down which one fires so a
        // future refactor that swaps the order is visible in test diffs.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("Cargo.toml"), "[package]\nname=\"x\"").unwrap();

        let executor = DeletionExecutor::new(DeletionConfig::default(), None);
        let candidate = make_candidate(dir.path(), 1, 1.0);
        let result = executor.preflight_check(&candidate, None);
        assert_eq!(result, Err(SkipReason::ContainsCargoManifest));
    }

    #[test]
    fn looks_like_source_code_detects_go_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("main.go"), "package main").unwrap();
        assert!(looks_like_source_code(dir.path()));
    }

    #[test]
    fn looks_like_source_code_skips_unreadable_dir() {
        // Documented behavior: if read_dir fails, this returns false. This is
        // intentionally consistent with contains_cargo_manifest_without_artifact_markers
        // and is safe because remove_dir_all on the same unreadable dir will
        // also fail. A nonexistent path triggers the read_dir failure path.
        assert!(!looks_like_source_code(Path::new(
            "/__sbh_definitely_not_a_real_path_for_test"
        )));
    }

    // ──────────────────── artifact-basename carve-out ────────────────────

    #[test]
    fn obvious_build_artifact_basename_exact_matches() {
        // Each of these basenames represents a known disposable build/cache
        // directory and must be exempted from the broad source-tree refusal.
        // The bare `rch-target` / `rch_target` (with and without leading dot)
        // entries cover rch deployments that don't use per-job suffixes.
        for name in [
            "target",
            ".target",
            ".cargo-target",
            "node_modules",
            "__pycache__",
            ".pytest_cache",
            ".next",
            ".nuxt",
            ".turbo",
            ".parcel-cache",
            "dist",
            "build",
            ".venv",
            "venv",
            ".tox",
            ".rch-target",
            ".rch_target",
            "rch-target",
            "rch_target",
        ] {
            // Test that an arbitrary parent prefix doesn't affect basename matching.
            let p = PathBuf::from(format!("/data/projects/foo/{name}"));
            assert!(
                is_obvious_build_artifact_basename(&p),
                "expected `{name}` to be recognized as a build artifact"
            );
        }
    }

    #[test]
    fn obvious_build_artifact_basename_prefix_matches() {
        // Prefix matches cover per-job and per-config suffix patterns produced
        // by cargo and rch. Each prefix REQUIRES the separator (`-` or `_`)
        // before the suffix — see the negative tests below for the false
        // positives this guards against.
        for name in [
            "target-foo",
            "target-debug-build",
            "target_release",
            "target_my_special_build",
            ".rch-target-job-42",
            ".rch-target-vmi1149989-job-12345-67890-0",
            ".rch_target_job_999",
            "rch-target-something",
            "rch_target_my_project",
            ".cargo-target-rusticmill",
        ] {
            let p = PathBuf::from(format!("/Users/foo/projects/repo/{name}"));
            assert!(
                is_obvious_build_artifact_basename(&p),
                "expected `{name}` to be recognized as a build artifact"
            );
        }
    }

    #[test]
    fn obvious_build_artifact_basename_suffix_matches() {
        // Descriptive `CARGO_TARGET_DIR` names: `<prefix>-target` /
        // `<prefix>_target` with a non-empty prefix. This is the rule that lets
        // the stranded `/root/cass-ft-target` (241 GB) be reclaimed, and it
        // also newly covers `my-target` (previously start-anchored-only).
        for name in [
            "cass-ft-target",
            "cass_ft_target",
            "foo_target",
            "hfdt-release-target",
            "my-target",
            "my_target",
        ] {
            let p = PathBuf::from(format!("/root/{name}"));
            assert!(
                is_obvious_build_artifact_basename(&p),
                "expected `{name}` to be recognized as a build artifact"
            );
        }
    }

    #[test]
    fn obvious_build_artifact_basename_suffix_requires_nonempty_prefix() {
        // A bare separator-then-target has no descriptive prefix and must not
        // match; `target` itself is covered by the exact list, not the suffix.
        for name in ["-target", "_target"] {
            let p = PathBuf::from(format!("/data/projects/foo/{name}"));
            assert!(
                !is_obvious_build_artifact_basename(&p),
                "expected `{name}` (empty prefix) to NOT match the suffix rule"
            );
        }
    }

    #[test]
    fn obvious_build_artifact_basename_negatives() {
        // These should NOT match — operators must never see source-like names
        // exempted from the broad refusal.
        for name in [
            // Real source-tree subdirs
            "src",
            "lib",
            "tests",
            "bin",
            "docs",
            "examples",
            "benches",
            "scripts",
            "crates",
            // Real crate names (would have been deleted in the 2026-05-22 incident)
            "frankenterm-core",
            "frankenterm-alloc",
            "frankenterm-topo",
            "franken_node",
            // Confusables: similar names that don't match our list
            "targets",      // plural of `target` is not on the list
            "mytarget",     // ends with `target` but has no `-`/`_` separator
            "untargeted",   // contains `target` mid-string
            "nodemodules",  // missing underscore; only `node_modules` exact match
            "deno-modules", // similar shape to `node_modules`, but not in the list
            "project",      // singular form; not a build-artifact name
            "projects",     // singular dir name; not a build-artifact name
            // Sensitive root-owned dirs that the `/root` is_system_path carve-out
            // must NEVER treat as artifacts (these keep their hard protection).
            ".ssh",
            ".gnupg",
            ".rustup",
            ".cargo",
            ".config",
            ".local",
            // Top-level dirs that look ambiguous
            "tmp",
            "data",
            "var",
            // Regression: prefix-without-separator false positives. Each of
            // these starts with an artifact-name prefix but has no `-` or `_`
            // separator before the trailing characters, so it must NOT be
            // classified as a build artifact. Earlier versions of the prefix
            // check used `starts_with(".rch-target")` (no trailing `-`), which
            // matched `.rch-targetfoo` and exempted unrelated dirs from the
            // protection.
            "targetfoo",
            ".rch-targetfoo",
            "rch-targetfoo",
            "rch_targetfoo",
            ".cargo-targetfoo",
        ] {
            let p = PathBuf::from(format!("/data/projects/foo/{name}"));
            assert!(
                !is_obvious_build_artifact_basename(&p),
                "expected `{name}` to NOT be classified as a build artifact"
            );
        }
    }

    #[test]
    fn obvious_build_artifact_basename_handles_no_basename() {
        // Edge cases: root path, empty path. Neither has a meaningful basename
        // and should not be classified as an artifact.
        assert!(!is_obvious_build_artifact_basename(Path::new("/")));
        assert!(!is_obvious_build_artifact_basename(Path::new("")));
    }

    // ──────────────────── hybrid behavior (broad + carve-out) ────────────────────

    #[test]
    fn hardcoded_source_tree_allows_target_under_data_projects() {
        // The carve-out: `target/` and friends under /data/projects/ are now
        // allowed to be deleted. This is the wizard's primary use case.
        assert!(!is_hardcoded_source_tree(Path::new(
            "/data/projects/franken_node/target"
        )));
        assert!(!is_hardcoded_source_tree(Path::new(
            "/data/projects/franken_node/node_modules"
        )));
        assert!(!is_hardcoded_source_tree(Path::new(
            "/data/projects/franken_node/.next"
        )));
        assert!(!is_hardcoded_source_tree(Path::new(
            "/data/projects/franken_node/__pycache__"
        )));
    }

    #[test]
    fn hardcoded_source_tree_allows_rch_targets_under_data_projects() {
        // The rch worker per-job target dirs under /data/projects/ are the
        // single largest disk hog in practice, so sbh must be able to clean
        // them up.
        assert!(!is_hardcoded_source_tree(Path::new(
            "/data/projects/franken_node/.rch-target-vmi1149989-job-29843600204366645-1779389660177931125-0"
        )));
        assert!(!is_hardcoded_source_tree(Path::new(
            "/data/projects/foo/rch-target-anything"
        )));
        assert!(!is_hardcoded_source_tree(Path::new(
            "/data/projects/foo/rch_target_something"
        )));
    }

    #[test]
    fn hardcoded_source_tree_allows_target_under_users_projects() {
        // Carve-out applies equally to /Users/<user>/projects/ on macOS.
        assert!(!is_hardcoded_source_tree(Path::new(
            "/Users/jemanuel/projects/sbh/target"
        )));
        assert!(!is_hardcoded_source_tree(Path::new(
            "/Users/jemanuel/projects/sbh/node_modules"
        )));
    }

    #[test]
    fn hardcoded_source_tree_allows_target_under_home_projects() {
        // Carve-out applies equally to /home/<user>/projects/ on Linux.
        assert!(!is_hardcoded_source_tree(Path::new(
            "/home/ubuntu/projects/franken_node/target"
        )));
        assert!(!is_hardcoded_source_tree(Path::new(
            "/home/ubuntu/projects/franken_node/.pytest_cache"
        )));
    }

    #[test]
    fn hardcoded_source_tree_still_vetoes_source_basenames_under_protected_root() {
        // The carve-out is narrow — anything NOT on the artifact list is
        // still vetoed. This protects against scorer misclassification.
        assert!(is_hardcoded_source_tree(Path::new(
            "/data/projects/franken_node/src"
        )));
        assert!(is_hardcoded_source_tree(Path::new(
            "/data/projects/franken_node/docs"
        )));
        assert!(is_hardcoded_source_tree(Path::new(
            "/data/projects/franken_node/legacy_code"
        )));
        // The actual carnage targets — synced source crate stubs.
        assert!(is_hardcoded_source_tree(Path::new(
            "/data/projects/frankenterm/crates/frankenterm-core"
        )));
        // The working tree root itself.
        assert!(is_hardcoded_source_tree(Path::new(
            "/data/projects/franken_node"
        )));
        // "projects always vetoed" also holds under /home/<user>/projects: a
        // non-artifact basename there is refused (this is the guarantee the
        // is_system_path unit test defers to, since /home is not a system path).
        assert!(is_hardcoded_source_tree(Path::new(
            "/home/alice/projects/foo"
        )));
        assert!(is_hardcoded_source_tree(Path::new(
            "/Users/alice/projects/foo"
        )));
    }

    #[test]
    fn hardcoded_source_tree_git_check_overrides_artifact_carveout() {
        // If a `.git` directory or anything inside it somehow ends up as a
        // candidate, the `.git` ancestor check must veto it regardless of
        // whether the basename happens to match an artifact pattern. (E.g.
        // a user-created `.git/target/` directory inside a real git repo.)
        assert!(is_hardcoded_source_tree(Path::new("/srv/code/.git/target")));
        // Even though `target` is an artifact name, the `.git` ancestor
        // wins.
        assert!(is_hardcoded_source_tree(Path::new(
            "/srv/code/.git/objects/pack/target"
        )));
    }

    // ──────────────── Go cache (read-only) reclaim ────────────────

    fn go_cache_classification() -> ArtifactClassification {
        ArtifactClassification {
            pattern_name: Cow::Borrowed("opaque-go-mod-cache"),
            category: ArtifactCategory::GoCache,
            name_confidence: 0.93,
            structural_confidence: 1.0,
            combined_confidence: 0.93,
        }
    }

    #[test]
    fn force_remove_gate_selects_only_readonly_caches() {
        assert!(classification_allows_force_remove(
            &go_cache_classification()
        ));
        // cargo registry/home caches are also read-only & regenerable.
        let cargo = ArtifactClassification {
            pattern_name: Cow::Borrowed("opaque-cargo-cache"),
            category: ArtifactCategory::CacheDir,
            name_confidence: 0.92,
            structural_confidence: 1.0,
            combined_confidence: 0.92,
        };
        assert!(classification_allows_force_remove(&cargo));
        // A plain rust target is removed conservatively (writable anyway).
        let target = ArtifactClassification {
            pattern_name: Cow::Borrowed("cargo-target"),
            category: ArtifactCategory::RustTarget,
            name_confidence: 0.9,
            structural_confidence: 0.9,
            combined_confidence: 0.9,
        };
        assert!(!classification_allows_force_remove(&target));
    }

    #[cfg(unix)]
    #[test]
    fn remove_dir_all_force_defeats_readonly_module_cache_tree() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("gomodcache");
        // Mimic GOMODCACHE: a module dir (0555) holding a 0444 go.mod + .go.
        let module = root.join("github.com").join("foo").join("bar@v1.2.3");
        fs::create_dir_all(&module).unwrap();
        fs::write(module.join("go.mod"), "module bar\n").unwrap();
        fs::write(module.join("lib.go"), "package bar\n").unwrap();
        // Lock down files first, then the directories (innermost last).
        fs::set_permissions(module.join("go.mod"), fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(module.join("lib.go"), fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(&module, fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(module.parent().unwrap(), fs::Permissions::from_mode(0o555)).unwrap();

        // Sanity (non-root only): the plain variant cannot remove this tree.
        // Root bypasses mode bits, so skip the negative assertion there.
        if !nix::unistd::Uid::effective().is_root() {
            assert!(
                fs::remove_dir_all(&root).is_err(),
                "plain remove_dir_all should fail on a 0555 module dir"
            );
            assert!(root.exists());
        }

        // The force variant chmods the subtree writable and succeeds.
        remove_dir_all_force(&root).expect("force remove should defeat read-only bits");
        assert!(!root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn go_cache_candidate_is_not_vetoed_as_source_despite_go_mod() {
        // The candidate IS a module dir whose direct child is go.mod — exactly
        // what `looks_like_source_code` vetoes. With the GoCache carve-out it
        // must delete; with any other category it must be source-vetoed.
        let dir = tempfile::tempdir().unwrap();

        // Positive case: GoCache classification deletes through the veto.
        let go_dir = dir.path().join("m@v1.0.0");
        fs::create_dir_all(&go_dir).unwrap();
        fs::write(go_dir.join("go.mod"), "module m\n").unwrap();
        fs::write(go_dir.join("lib.go"), "package m\n").unwrap();
        let mut go_candidate = make_candidate(&go_dir, 4096, 0.93);
        go_candidate.classification = go_cache_classification();

        let executor = DeletionExecutor::new(
            DeletionConfig {
                check_open_files: false,
                ..Default::default()
            },
            None,
        );
        let report = executor.execute(&executor.plan(vec![go_candidate]), None);
        assert_eq!(
            report.items_deleted, 1,
            "go cache must not be source-vetoed"
        );
        assert!(!go_dir.exists());

        // Control: same shape, non-GoCache category → vetoed as source.
        let src_dir = dir.path().join("real_src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("go.mod"), "module m\n").unwrap();
        fs::write(src_dir.join("lib.go"), "package m\n").unwrap();
        let src_candidate = make_candidate(&src_dir, 4096, 0.93); // RustTarget by default
        let report = executor.execute(&executor.plan(vec![src_candidate]), None);
        assert_eq!(report.items_deleted, 0, "real source must stay vetoed");
        assert_eq!(report.items_skipped, 1);
        assert!(src_dir.exists());
    }
}
