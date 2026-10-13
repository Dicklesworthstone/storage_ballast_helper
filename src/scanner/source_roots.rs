//! Root-level source-tree policy, independent of artifact classification.
//!
//! A bounded inspection may prove a root clear, find a Git marker, or remain
//! inconclusive. Only the first two can authorize reclamation, and a Git root
//! additionally requires the operator's explicit opt-in. No Git subprocess is
//! used, so dubious ownership cannot silently change this policy.
//!
//! Consumers must install the same policy in the scanner and executor, refresh
//! it at scan admission, replace it on accepted config reload, and publish its
//! snapshot as enforced state. Constructing a Config alone does not do this.
//! A config replacement affects existing executor clones and queued candidates.
//! It does not cancel a removal already admitted at its final authorization
//! boundary. Filesystem probes are cooperatively bounded; an individual
//! blocking filesystem syscall cannot be interrupted.
//!
//! An uninstalled default policy still refuses candidates inside Git work
//! trees. This candidate-level backstop is not whole-root enforcement: only
//! installing every configured root can protect an untracked sibling of a
//! repository elsewhere beneath that root.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// Limits are independent of the artifact walk's depth and exclusions: those
/// must not hide a nested repository from root-level source protection.
#[derive(Debug, Clone, Copy)]
pub struct InspectionLimits {
    /// Maximum directory depth below a configured root.
    pub max_depth: usize,
    /// Maximum directory entries and ancestor probes per root.
    pub max_entries: usize,
    /// Cooperative wall-clock budget per root.
    pub time_budget: Duration,
}

impl Default for InspectionLimits {
    fn default() -> Self {
        Self {
            max_depth: 32,
            max_entries: 16_384,
            time_budget: Duration::from_millis(200),
        }
    }
}

/// Evidence from an inspection; an incomplete walk never means "clear".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootFinding {
    /// The entire inspected subtree and its ancestors have no Git marker.
    Clear,
    /// A `.git` directory, gitfile, or other `.git` entry was found.
    GitWorktree,
    /// A limit, inaccessible entry, or unresolved directory link prevented proof.
    Unverified,
}

/// One configured root's operator-facing policy result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRootStatus {
    /// The configured spelling (retained for useful diagnostics).
    pub root: PathBuf,
    /// Canonical location, or last known location if a refresh cannot resolve it.
    pub resolved_root: Option<PathBuf>,
    /// First repository found. A single marker is sufficient to protect a root.
    pub repositories: Vec<PathBuf>,
    /// Whether the root was proven clear, contains Git, or is unverified.
    pub finding: RootFinding,
    /// Effective permission, including overlapping-root vetoes.
    pub reclaim_allowed: bool,
    /// Human-readable evidence, including the offending path or exhausted limit.
    pub detail: String,
}

impl SourceRootStatus {
    /// A diagnostic shared by doctor, validation, status and the executor.
    #[must_use]
    pub fn diagnostic(&self) -> String {
        let action = if self.reclaim_allowed {
            "allowed"
        } else {
            "BLOCKED"
        };
        format!(
            "scanner root {}: reclaim {action}: {}",
            self.root.display(),
            self.detail
        )
    }
}

/// Serializable policy evidence; only an installed policy is enforced state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SourceRootReport {
    /// Explicit authorization; never inferred from a build-artifact name.
    pub allow_source_tree_roots: bool,
    /// A result for every configured scanner root, including missing roots.
    pub roots: Vec<SourceRootStatus>,
}

impl SourceRootReport {
    /// Blocking diagnostics. Explicitly allowed Git roots remain visible in
    /// `roots`, but do not make doctor or config validation fail.
    #[must_use]
    pub fn failures(&self) -> Vec<String> {
        self.roots
            .iter()
            .filter(|root| !root.reclaim_allowed)
            .map(SourceRootStatus::diagnostic)
            .collect()
    }

    /// Configured roots eligible for scanner reclamation. The report already
    /// includes deny-wins propagation, so a clear child cannot re-admit work
    /// below a blocked parent through a second configured root.
    #[must_use]
    pub fn allowed_roots(&self) -> Vec<PathBuf> {
        self.roots
            .iter()
            .filter(|root| root.reclaim_allowed)
            .map(|root| root.root.clone())
            .collect()
    }

    fn retain_unresolved_boundaries(&mut self, previous: &Self) {
        for fresh in &mut self.roots {
            if fresh.resolved_root.is_some() {
                continue;
            }
            let configured = absolute_lexical(&fresh.root).ok();
            if let Some(old) = previous.roots.iter().find(|old| {
                old.root == fresh.root
                    || configured.as_ref().is_some_and(|configured| {
                        absolute_lexical(&old.root)
                            .as_ref()
                            .is_ok_and(|old_path| old_path == configured)
                    })
            }) {
                // A configured alias that disappeared has not relinquished
                // its last known boundary. Otherwise a reordered reload could
                // admit a clear child through another still-resolvable root.
                fresh.resolved_root.clone_from(&old.resolved_root);
            }
        }
        self.apply_overlap_denials();
    }

    fn apply_overlap_denials(&mut self) {
        // A newly denied parent may also overlap a different configured child.
        // Iterate to a fixed point so root order cannot change admission. Every
        // productive iteration revokes at least one root; none can re-enable it.
        loop {
            let blocked: Vec<_> = self
                .roots
                .iter()
                .filter(|root| !root.reclaim_allowed)
                .cloned()
                .collect();
            let mut changed = false;
            for root in &mut self.roots {
                if !root.reclaim_allowed {
                    continue;
                }
                if let Some(denied) = blocked.iter().find(|denied| roots_overlap(root, denied)) {
                    root.reclaim_allowed = false;
                    root.detail = format!(
                        "{}; blocked by overlapping scanner root {}: {}",
                        root.detail,
                        denied.root.display(),
                        denied.detail
                    );
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }
}

struct Budget {
    start: Instant,
    entries: usize,
    limits: InspectionLimits,
}

impl Budget {
    fn check_time(&self) -> std::result::Result<(), &'static str> {
        if self.start.elapsed() >= self.limits.time_budget {
            return Err("source-root inspection time budget exhausted");
        }
        Ok(())
    }

    fn step(&mut self) -> std::result::Result<(), &'static str> {
        self.check_time()?;
        if self.entries >= self.limits.max_entries {
            return Err("source-root inspection entry budget exhausted");
        }
        self.entries += 1;
        Ok(())
    }

    fn finish(&self, finding: Option<PathBuf>) -> std::result::Result<Option<PathBuf>, String> {
        // The last filesystem call (including read_dir's final next()) can
        // outlive the last step. Never publish permission based on that stale
        // deadline check. Completion itself does not consume an entry.
        self.check_time()?;
        Ok(finding)
    }
}

fn absolute_lexical(path: &Path) -> io::Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    let mut result = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            other => result.push(other.as_os_str()),
        }
    }
    Ok(result)
}

fn git_marker(directory: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(directory.join(".git")) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn inspect(
    root: &Path,
    limits: InspectionLimits,
    resolved: &mut Option<PathBuf>,
) -> std::result::Result<Option<PathBuf>, String> {
    let mut budget = Budget {
        start: Instant::now(),
        entries: 0,
        limits,
    };
    budget.step()?;
    let canonical = fs::canonicalize(root)
        .map_err(|error| format!("cannot resolve {}: {error}", root.display()))?;
    *resolved = Some(canonical.clone());
    let metadata = fs::metadata(&canonical)
        .map_err(|error| format!("cannot inspect {}: {error}", canonical.display()))?;
    if !metadata.is_dir() {
        return Err(format!("{} is not a directory", canonical.display()));
    }

    // Includes the root itself, target/ roots below repositories, linked
    // worktrees (whose .git is a file), and symlink aliases of such roots.
    for ancestor in canonical.ancestors() {
        budget.step()?;
        if git_marker(ancestor)
            .map_err(|error| format!("cannot inspect {}: {error}", ancestor.display()))?
        {
            return budget.finish(Some(ancestor.to_path_buf()));
        }
    }

    let mut pending = vec![(canonical, 0usize)];
    while let Some((directory, depth)) = pending.pop() {
        budget.step()?;
        let entries = fs::read_dir(&directory)
            .map_err(|error| format!("cannot read {}: {error}", directory.display()))?;
        for entry in entries {
            budget.step()?;
            let entry = entry.map_err(|error| {
                format!("cannot read entry in {}: {error}", directory.display())
            })?;
            if entry.file_name() == ".git" {
                return budget.finish(Some(directory));
            }
            let path = entry.path();
            let kind = entry
                .file_type()
                .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
            if kind.is_symlink() {
                // Never follow directory links into an unbounded/cyclic tree.
                // Unresolved links fail closed, rather than hiding a repository
                // from configurations that enable scanner.follow_symlinks.
                let target = fs::metadata(&path)
                    .map_err(|error| format!("cannot resolve link {}: {error}", path.display()))?;
                if target.is_dir() {
                    return Err(format!(
                        "directory link {} requires a narrower scan root",
                        path.display()
                    ));
                }
            } else if kind.is_dir() {
                // Probe the marker even at the depth boundary. If none is
                // present we still cannot declare the unvisited subtree clear.
                if git_marker(&path)
                    .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?
                {
                    return budget.finish(Some(path));
                }
                if depth >= limits.max_depth {
                    return Err(format!(
                        "source-root inspection depth limit at {}",
                        path.display()
                    ));
                }
                pending.push((path, depth + 1));
            }
        }
    }
    budget.finish(None)
}

/// Inspect a configured root without relying on candidate classification,
/// exclusions, Git ownership, or the artifact scanner's traversal budget.
#[must_use]
pub fn inspect_root(root: &Path, allow: bool, limits: InspectionLimits) -> SourceRootStatus {
    let mut resolved_root = None;
    let result = inspect(root, limits, &mut resolved_root);
    let (finding, repositories, reclaim_allowed, detail) = match result {
        Ok(None) => (
            RootFinding::Clear,
            Vec::new(),
            true,
            "no Git work tree found".to_string(),
        ),
        Ok(Some(repository)) => {
            let detail = format!(
                "Git work tree {}{}",
                repository.display(),
                if allow {
                    "; scanner.allow_source_tree_roots explicitly enabled; candidate vetoes still apply"
                } else {
                    "; remove/narrow this root or explicitly set scanner.allow_source_tree_roots = true"
                }
            );
            (RootFinding::GitWorktree, vec![repository], allow, detail)
        }
        Err(detail) => (RootFinding::Unverified, Vec::new(), false, detail),
    };
    SourceRootStatus {
        root: root.to_path_buf(),
        resolved_root,
        repositories,
        finding,
        reclaim_allowed,
        detail,
    }
}

/// Inspect all configured roots, retaining every root's diagnostic and applying
/// the same overlapping-root vetoes used by final deletion authorization.
#[must_use]
pub fn inspect_roots(roots: &[PathBuf], allow: bool) -> SourceRootReport {
    let mut report = SourceRootReport {
        allow_source_tree_roots: allow,
        roots: roots
            .iter()
            .map(|root| inspect_root(root, allow, InspectionLimits::default()))
            .collect(),
    };
    report.apply_overlap_denials();
    report
}

#[derive(Debug, Default)]
struct PolicyState {
    report: SourceRootReport,
    // An omitted policy is not an intentionally configured empty root set.
    // Refreshing default state must not silently disable its Git backstop.
    installed: bool,
    // Old locations remain denied for queued candidates after removal or
    // retargeting. A current containing root is evaluated under the new policy.
    retired_paths: Vec<PathBuf>,
}

impl PolicyState {
    fn remember_locations(&mut self) {
        for root in &self.report.roots {
            if let Ok(path) = absolute_lexical(&root.root) {
                self.retired_paths.push(path);
            }
            if let Some(path) = &root.resolved_root {
                self.retired_paths.push(path.clone());
            }
        }
        self.retired_paths.sort();
        self.retired_paths.dedup();
    }

    fn refresh(&mut self) {
        self.remember_locations();
        let roots: Vec<_> = self
            .report
            .roots
            .iter()
            .map(|root| root.root.clone())
            .collect();
        let mut report = inspect_roots(&roots, self.report.allow_source_tree_roots);
        report.retain_unresolved_boundaries(&self.report);
        self.report = report;
    }
}

/// Live policy shared by scanner, executor and monitor. Cloning shares state;
/// it does not create a stale authorization snapshot.
///
/// `Default` has no configured-root scope, but still refuses candidates inside
/// Git work trees. Use `new` or `replace` to install the full root-level policy,
/// including any explicit opt-in. The backstop never infers that opt-in from
/// an artifact's name, score, pressure, or an uninstalled Config object.
#[derive(Debug, Clone, Default)]
pub struct SourceRootPolicy {
    inner: Arc<Mutex<PolicyState>>,
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn roots_overlap(left: &SourceRootStatus, right: &SourceRootStatus) -> bool {
    let lexical = match (absolute_lexical(&left.root), absolute_lexical(&right.root)) {
        (Ok(left), Ok(right)) => overlaps(&left, &right),
        // A spelling that cannot be normalized is not evidence of separation.
        _ => true,
    };
    lexical
        || left
            .resolved_root
            .as_ref()
            .zip(right.resolved_root.as_ref())
            .is_some_and(|(left, right)| overlaps(left, right))
}

fn strict_ancestor(ancestor: &Path, descendant: &Path) -> bool {
    ancestor != descendant && descendant.starts_with(ancestor)
}

/// A caller that forgot to install its policy must not silently reclaim
/// untracked repository contents. Check canonical ancestors without a Git
/// subprocess or a recursive tree walk. The ordinary candidate checks still
/// own nested Git metadata and every other veto.
fn authorize_without_config(path: &Path, mut budget: Budget) -> std::result::Result<(), String> {
    budget.step()?;
    let metadata = fs::metadata(path)
        .map_err(|error| format!("cannot inspect candidate {}: {error}", path.display()))?;
    let directory = if metadata.is_dir() {
        path
    } else {
        // File candidates must start at their parent: probing file/.git
        // would return ENOTDIR and incorrectly refuse every ordinary file.
        path.parent()
            .ok_or_else(|| format!("candidate {} has no parent", path.display()))?
    };
    for ancestor in directory.ancestors() {
        budget.step()?;
        if git_marker(ancestor)
            .map_err(|error| format!("cannot inspect {}: {error}", ancestor.display()))?
        {
            return Err(format!(
                "source-root policy is not installed; refusing content in Git work tree {}; \
                 install the configured policy before permitting source-tree reclamation",
                ancestor.display()
            ));
        }
    }
    // The last metadata lookup can outlive the last step's deadline check.
    budget.check_time()?;
    Ok(())
}

impl SourceRootPolicy {
    /// Inspect and install the initial configured-root policy.
    #[must_use]
    pub fn new(roots: &[PathBuf], allow: bool) -> Self {
        Self {
            inner: Arc::new(Mutex::new(PolicyState {
                report: inspect_roots(roots, allow),
                installed: true,
                retired_paths: Vec::new(),
            })),
        }
    }

    /// Replace policy for every existing clone, retaining removed-root denial
    /// for stale queued candidates. Inspection and publication are serialized
    /// with final authorization; no partially replaced config is visible.
    pub fn replace(&self, roots: &[PathBuf], allow: bool) {
        let mut state = self.inner.lock();
        state.remember_locations();
        let mut report = inspect_roots(roots, allow);
        report.retain_unresolved_boundaries(&state.report);
        state.report = report;
        state.installed = true;
    }

    /// Reinspect current roots (e.g. before a scan), publishing their new state.
    #[must_use]
    pub fn refresh(&self) -> SourceRootReport {
        let mut state = self.inner.lock();
        state.refresh();
        state.report.clone()
    }

    /// Last observed state, without filesystem work on the monitoring thread.
    #[must_use]
    pub fn snapshot(&self) -> SourceRootReport {
        self.inner.lock().report.clone()
    }

    /// Recheck the whole configured root, not merely the candidate's ancestors.
    /// A repository created in a sibling directory after startup thus blocks
    /// old queued candidates too. Overlapping roots obey deny-wins semantics.
    /// Strict ancestors of a configured root are never admitted: permission for
    /// a subtree is not permission to delete its parent and unrelated siblings.
    /// Paths outside current and retired configured roots are not governed by
    /// this policy (e.g. separately handled special locations and ballast).
    /// With no policy installed at all, the canonical-ancestor Git backstop
    /// applies instead; an empty snapshot alone is not unrestricted permission.
    ///
    /// Call at the final mutation boundary as well as during preflight. This
    /// check can only veto; opting in never replaces other candidate checks.
    pub fn authorize(&self, path: &Path) -> std::result::Result<(), String> {
        let start = Instant::now();
        let lexical = absolute_lexical(path)
            .map_err(|error| format!("cannot resolve candidate {}: {error}", path.display()))?;
        let mut state = self.inner.lock();
        state.refresh();
        // Resolve after the potentially slow root inspection rather than using
        // a candidate alias observed before that inspection began.
        let canonical = fs::canonicalize(path)
            .map_err(|error| format!("cannot resolve candidate {}: {error}", path.display()))?;
        if !state.installed {
            return authorize_without_config(
                &canonical,
                Budget {
                    start,
                    entries: 0,
                    limits: InspectionLimits::default(),
                },
            );
        }
        let mut matched = false;
        for root in &state.report.roots {
            let configured = absolute_lexical(&root.root).map_err(|error| {
                format!(
                    "cannot resolve scanner root {}: {error}",
                    root.root.display()
                )
            })?;
            let lexical_match = overlaps(&lexical, &configured);
            let canonical_match = root
                .resolved_root
                .as_ref()
                .is_some_and(|resolved| overlaps(&canonical, resolved));
            if lexical_match || canonical_match {
                if strict_ancestor(&lexical, &configured)
                    || root
                        .resolved_root
                        .as_ref()
                        .is_some_and(|resolved| strict_ancestor(&canonical, resolved))
                {
                    return Err(format!(
                        "candidate {} contains configured scanner root {}; subtree permission does not authorize deleting an ancestor",
                        path.display(),
                        root.root.display()
                    ));
                }
                matched = true;
                if !root.reclaim_allowed {
                    return Err(root.diagnostic());
                }
                if lexical.starts_with(&configured)
                    && !root
                        .resolved_root
                        .as_ref()
                        .is_some_and(|resolved| canonical.starts_with(resolved))
                {
                    return Err(format!(
                        "candidate {} escapes configured scanner root {}",
                        path.display(),
                        root.root.display()
                    ));
                }
            }
        }
        let retired = !matched
            && state
                .retired_paths
                .iter()
                .any(|root| overlaps(&lexical, root) || overlaps(&canonical, root));
        drop(state);
        if retired {
            return Err(format!(
                "candidate {} belongs to a removed or retargeted scanner root",
                path.display()
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> tempfile::TempDir {
        // A standalone temp root avoids inheriting the checkout's own .git.
        tempfile::tempdir().expect("scratch directory")
    }

    fn mkdir(path: &Path) {
        fs::create_dir_all(path).expect("create fixture directory");
    }

    fn limits() -> InspectionLimits {
        InspectionLimits {
            time_budget: Duration::from_secs(5),
            ..InspectionLimits::default()
        }
    }

    #[test]
    fn uninstalled_backstop_fails_closed_when_its_budget_is_exhausted() {
        let dir = scratch();
        for limits in [
            InspectionLimits {
                max_entries: 0,
                ..limits()
            },
            InspectionLimits {
                time_budget: Duration::ZERO,
                ..limits()
            },
        ] {
            let budget = Budget {
                start: Instant::now(),
                entries: 0,
                limits,
            };
            assert!(authorize_without_config(dir.path(), budget).is_err());
        }
    }

    #[test]
    fn refreshing_a_default_policy_does_not_mark_it_installed() {
        let dir = scratch();
        mkdir(&dir.path().join(".git"));
        let target = dir.path().join("target");
        mkdir(&target);
        let policy = SourceRootPolicy::default();
        let queued = policy.clone();
        assert!(policy.refresh().roots.is_empty());
        assert!(
            queued
                .authorize(&target)
                .unwrap_err()
                .contains("not installed")
        );
        policy.replace(&[dir.path().to_path_buf()], true);
        assert!(queued.authorize(&target).is_ok());
        policy.replace(&[dir.path().to_path_buf()], false);
        assert!(queued.authorize(&target).is_err());
    }

    #[test]
    fn clear_root_can_be_reclaimed_without_opt_in() {
        let dir = scratch();
        mkdir(&dir.path().join("target/debug/deps"));
        let report = inspect_root(dir.path(), false, limits());
        assert_eq!(report.finding, RootFinding::Clear);
        assert!(report.reclaim_allowed);
    }

    #[test]
    fn repository_and_build_root_are_default_denied() {
        let dir = scratch();
        mkdir(&dir.path().join(".git"));
        let target = dir.path().join("target/debug");
        mkdir(&target);
        for root in [dir.path(), target.as_path()] {
            let report = inspect_root(root, false, limits());
            assert_eq!(report.finding, RootFinding::GitWorktree);
            assert!(!report.reclaim_allowed);
            assert_eq!(
                report.repositories,
                vec![fs::canonicalize(dir.path()).unwrap()]
            );
        }
    }

    #[test]
    fn nested_repository_blocks_the_entire_root_including_untracked_siblings() {
        let dir = scratch();
        mkdir(&dir.path().join("team/project/.git"));
        let untracked = dir.path().join("untracked-target");
        mkdir(&untracked);
        fs::write(untracked.join("evidence.txt"), b"irreplaceable").unwrap();
        let policy = SourceRootPolicy::new(&[dir.path().to_path_buf()], false);
        assert!(policy.authorize(&untracked).is_err());
        assert_eq!(
            fs::read(untracked.join("evidence.txt")).unwrap(),
            b"irreplaceable"
        );
    }

    #[test]
    fn linked_worktree_gitfile_is_detected_without_invoking_git() {
        let dir = scratch();
        fs::write(
            dir.path().join(".git"),
            b"gitdir: /unavailable/main/.git/worktrees/topic\n",
        )
        .unwrap();
        let report = inspect_root(dir.path(), false, limits());
        assert_eq!(report.finding, RootFinding::GitWorktree);
        assert!(!report.reclaim_allowed);
    }

    #[test]
    fn explicit_opt_in_allows_policy_admission_not_candidate_reclassification() {
        let dir = scratch();
        mkdir(&dir.path().join("project/.git"));
        let target = dir.path().join("project/target");
        mkdir(&target);
        let policy = SourceRootPolicy::new(&[dir.path().to_path_buf()], true);
        assert!(policy.authorize(&target).is_ok());
        assert_eq!(policy.snapshot().roots[0].finding, RootFinding::GitWorktree);
        assert!(policy.snapshot().allow_source_tree_roots);
    }

    #[test]
    fn incomplete_inspection_is_denied_even_with_opt_in() {
        let dir = scratch();
        mkdir(&dir.path().join("deep/child/grandchild"));
        for allow in [false, true] {
            for bound in [
                InspectionLimits {
                    max_depth: 0,
                    ..limits()
                },
                InspectionLimits {
                    max_entries: 0,
                    ..limits()
                },
                InspectionLimits {
                    time_budget: Duration::ZERO,
                    ..limits()
                },
            ] {
                let report = inspect_root(dir.path(), allow, bound);
                assert_eq!(report.finding, RootFinding::Unverified);
                assert!(!report.reclaim_allowed);
            }
        }
    }

    #[test]
    fn missing_and_non_directory_roots_are_not_proven_clear() {
        let dir = scratch();
        let file = dir.path().join("ordinary-file");
        fs::write(&file, b"file").unwrap();
        for root in [file, dir.path().join("missing")] {
            let report = inspect_root(&root, false, limits());
            assert_eq!(report.finding, RootFinding::Unverified);
            assert!(!report.reclaim_allowed);
        }
    }

    #[test]
    fn new_sibling_repository_revokes_an_old_clean_inspection() {
        let dir = scratch();
        let candidate = dir.path().join("target");
        mkdir(&candidate);
        let policy = SourceRootPolicy::new(&[dir.path().to_path_buf()], false);
        assert!(policy.authorize(&candidate).is_ok());
        mkdir(&dir.path().join("new-project/.git"));
        assert!(policy.authorize(&candidate).is_err());
        assert!(!policy.snapshot().roots[0].reclaim_allowed);
    }

    #[test]
    fn reloading_opt_in_updates_existing_executor_clones() {
        let dir = scratch();
        mkdir(&dir.path().join(".git"));
        let candidate = dir.path().join("target");
        mkdir(&candidate);
        let roots = vec![dir.path().to_path_buf()];
        let policy = SourceRootPolicy::new(&roots, true);
        let executor_policy = policy.clone();
        assert!(executor_policy.authorize(&candidate).is_ok());
        policy.replace(&roots, false);
        assert!(executor_policy.authorize(&candidate).is_err());
        policy.replace(&roots, true);
        assert!(executor_policy.authorize(&candidate).is_ok());
    }

    #[test]
    fn removed_roots_deny_stale_candidates_but_not_unrelated_locations() {
        let old = scratch();
        let special = scratch();
        let candidate = old.path().join("target");
        mkdir(&candidate);
        let policy = SourceRootPolicy::new(&[old.path().to_path_buf()], false);
        assert!(policy.authorize(&candidate).is_ok());
        policy.replace(&[], false);
        assert!(policy.authorize(&candidate).is_err());
        assert!(policy.authorize(special.path()).is_ok());
    }

    #[test]
    fn an_overlapping_clear_root_does_not_override_a_blocked_parent() {
        let dir = scratch();
        mkdir(&dir.path().join("project/.git"));
        let cache = dir.path().join("cache");
        mkdir(&cache);
        let policy = SourceRootPolicy::new(&[dir.path().to_path_buf(), cache.clone()], false);
        assert!(policy.authorize(&cache).is_err());
        let report = policy.snapshot();
        assert!(report.roots.iter().all(|root| !root.reclaim_allowed));
        assert!(report.allowed_roots().is_empty());
        assert_eq!(report.failures().len(), 2);
    }

    #[test]
    fn component_boundaries_do_not_block_a_similarly_named_neighbor() {
        let dir = scratch();
        let root = dir.path().join("project");
        mkdir(&root.join(".git"));
        let neighbor = dir.path().join("project-cache");
        mkdir(&neighbor);
        let policy = SourceRootPolicy::new(&[root], false);
        assert!(policy.authorize(&neighbor).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn root_symlink_and_canonical_alias_cannot_hide_a_repository() {
        use std::os::unix::fs::symlink;
        let dir = scratch();
        let root = dir.path().join("project");
        mkdir(&root.join(".git"));
        let target = root.join("target");
        mkdir(&target);
        let alias = dir.path().join("alias");
        symlink(&root, &alias).unwrap();
        let policy = SourceRootPolicy::new(std::slice::from_ref(&alias), false);
        assert!(policy.authorize(&target).is_err());
        assert!(policy.authorize(&alias.join("target")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn directory_links_and_dangling_links_fail_closed_without_recursion() {
        use std::os::unix::fs::symlink;
        for dangling in [false, true] {
            let dir = scratch();
            let destination = if dangling {
                dir.path().join("missing")
            } else {
                dir.path().to_path_buf()
            };
            symlink(destination, dir.path().join("link")).unwrap();
            let report = inspect_root(dir.path(), false, limits());
            assert_eq!(report.finding, RootFinding::Unverified);
            assert!(!report.reclaim_allowed);
        }
    }

    #[test]
    fn report_json_retains_blocked_root_repository_and_explicit_allowance() {
        let dir = scratch();
        mkdir(&dir.path().join("nested/.git"));
        let report = inspect_roots(&[dir.path().to_path_buf()], false);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["allow_source_tree_roots"], false);
        assert_eq!(json["roots"][0]["finding"], "git_worktree");
        assert_eq!(json["roots"][0]["reclaim_allowed"], false);
        assert_eq!(
            json["roots"][0]["repositories"].as_array().unwrap().len(),
            1
        );
        assert_eq!(report.failures().len(), 1);
        assert!(report.allowed_roots().is_empty());
    }

    #[test]
    fn narrowing_roots_revokes_queued_ancestor_and_sibling_candidates() {
        let dir = scratch();
        let retained = dir.path().join("retained");
        let sibling = dir.path().join("untracked-target");
        mkdir(&retained);
        mkdir(&sibling);
        fs::write(sibling.join("evidence.txt"), b"keep").unwrap();
        let policy = SourceRootPolicy::new(&[dir.path().to_path_buf()], false);
        let queued = policy.clone();
        assert!(queued.authorize(dir.path()).is_ok());
        policy.replace(std::slice::from_ref(&retained), false);
        assert!(queued.authorize(dir.path()).is_err());
        assert!(queued.authorize(&sibling).is_err());
        assert!(queued.authorize(&retained).is_ok());
        assert_eq!(fs::read(sibling.join("evidence.txt")).unwrap(), b"keep");
    }

    #[test]
    fn opting_in_never_authorizes_an_ancestor_of_the_configured_root() {
        let dir = scratch();
        let root = dir.path().join("project/target");
        mkdir(&root);
        mkdir(&dir.path().join("project/.git"));
        let policy = SourceRootPolicy::new(std::slice::from_ref(&root), true);
        assert!(policy.authorize(&root).is_ok());
        assert!(policy.authorize(dir.path()).is_err());
        assert!(policy.authorize(&dir.path().join("project")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn canonical_alias_cannot_authorize_deleting_a_configured_roots_parent() {
        use std::os::unix::fs::symlink;
        let dir = scratch();
        let aliases = scratch();
        let root = dir.path().join("target");
        mkdir(&root);
        let alias = aliases.path().join("root");
        symlink(&root, &alias).unwrap();
        let policy = SourceRootPolicy::new(&[alias], false);
        assert!(policy.authorize(&root).is_ok());
        assert!(policy.authorize(dir.path()).is_err());
    }

    #[test]
    fn overlapping_denials_reach_a_fixed_point_independent_of_root_order() {
        let dir = scratch();
        let cache = dir.path().join("cache");
        let missing = dir.path().join("missing");
        mkdir(&cache);
        // The missing root vetoes the clear parent; that parent must then veto
        // the disjoint child. Opt-in cannot override incomplete inspection.
        for roots in [
            vec![cache.clone(), dir.path().to_path_buf(), missing.clone()],
            vec![missing, dir.path().to_path_buf(), cache],
        ] {
            let report = inspect_roots(&roots, true);
            assert!(report.allowed_roots().is_empty());
            assert_eq!(report.failures().len(), 3);
        }
    }

    #[test]
    fn final_deadline_check_refuses_clear_and_git_results_without_sleeping() {
        let budget = Budget {
            start: Instant::now(),
            entries: 1,
            limits: InspectionLimits {
                time_budget: Duration::ZERO,
                ..limits()
            },
        };
        assert!(budget.finish(None).is_err());
        assert!(budget.finish(Some(PathBuf::from("repository"))).is_err());
    }

    #[test]
    fn finishing_a_complete_inspection_does_not_charge_an_extra_entry() {
        let budget = Budget {
            start: Instant::now(),
            entries: 1,
            limits: InspectionLimits {
                max_entries: 1,
                ..limits()
            },
        };
        assert_eq!(budget.finish(None).unwrap(), None);
    }

    #[cfg(unix)]
    #[test]
    fn reload_preserves_missing_alias_boundary_across_reordering_and_spelling_changes() {
        use std::os::unix::fs::symlink;
        for allow in [false, true] {
            let dir = scratch();
            let links = scratch();
            mkdir(&dir.path().join("team/project/.git"));
            let cache = dir.path().join("cache");
            let candidate = cache.join("target");
            mkdir(&candidate);
            let evidence = candidate.join("evidence.txt");
            fs::write(&evidence, b"keep during reload").unwrap();
            let alias = links.path().join("root");
            let parked_alias = links.path().join("parked-root");
            symlink(dir.path(), &alias).unwrap();
            mkdir(&links.path().join("spelling"));
            let old_spelling = links.path().join("spelling/../root");
            let policy = SourceRootPolicy::new(&[old_spelling, cache.clone()], allow);
            let queued = policy.clone();
            assert_eq!(queued.authorize(&candidate).is_ok(), allow);

            // The alias is still configured, but temporarily cannot resolve.
            // Reordering root_paths and normalizing its spelling must not drop
            // its canonical deny boundary or let the child root override it.
            fs::rename(&alias, &parked_alias).unwrap();
            let roots = vec![cache, alias.clone()];
            policy.replace(&roots, allow);
            let report = policy.snapshot();
            assert_eq!(report.roots[1].finding, RootFinding::Unverified);
            assert_eq!(
                report.roots[1].resolved_root,
                Some(fs::canonicalize(dir.path()).unwrap())
            );
            assert!(report.allowed_roots().is_empty());
            assert!(queued.authorize(&candidate).is_err());
            assert_eq!(fs::read(&evidence).unwrap(), b"keep during reload");

            // An actually restored alias plus explicit permission can resume
            // cleanup. Missing-root denial must not become permanent history.
            fs::rename(&parked_alias, &alias).unwrap();
            policy.replace(&roots, true);
            assert!(queued.authorize(&candidate).is_ok());
            assert!(
                policy
                    .snapshot()
                    .roots
                    .iter()
                    .all(|root| root.reclaim_allowed)
            );
            assert_eq!(fs::read(&evidence).unwrap(), b"keep during reload");
        }
    }
}
