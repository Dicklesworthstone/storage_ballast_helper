//! Root-level source-tree policy, independent of artifact classification.
//!
//! A bounded inspection may prove a root clear, find a Git marker, or remain
//! inconclusive. Only the first two can authorize reclamation, and a Git root
//! additionally requires the operator's explicit opt-in. No Git subprocess is
//! used, so dubious ownership cannot silently change this policy.
//!
//! The shared policy is refreshed at startup, reload, scan admission and the
//! final mutation boundary. A config replacement affects existing executor
//! clones and queued candidates. It does not cancel a removal already admitted
//! at its final authorization boundary. Filesystem probes are cooperatively
//! bounded; an individual blocking filesystem syscall cannot be interrupted.

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
    /// Effective permission, not merely the presence of an opt-in.
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

/// Serializable live state for `sbh status` and the daemon state file.
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

    /// Configured roots eligible for scanner reclamation.
    #[must_use]
    pub fn allowed_roots(&self) -> Vec<PathBuf> {
        self.roots
            .iter()
            .filter(|root| root.reclaim_allowed)
            .map(|root| root.root.clone())
            .collect()
    }
}

struct Budget {
    start: Instant,
    entries: usize,
    limits: InspectionLimits,
}

impl Budget {
    fn step(&mut self) -> std::result::Result<(), &'static str> {
        if self.start.elapsed() >= self.limits.time_budget {
            return Err("source-root inspection time budget exhausted");
        }
        if self.entries >= self.limits.max_entries {
            return Err("source-root inspection entry budget exhausted");
        }
        self.entries += 1;
        Ok(())
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
            return Ok(Some(ancestor.to_path_buf()));
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
                return Ok(Some(directory));
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
                    return Ok(Some(path));
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
    Ok(None)
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

/// Inspect all configured roots, retaining every root's diagnostic.
#[must_use]
pub fn inspect_roots(roots: &[PathBuf], allow: bool) -> SourceRootReport {
    SourceRootReport {
        allow_source_tree_roots: allow,
        roots: roots
            .iter()
            .map(|root| inspect_root(root, allow, InspectionLimits::default()))
            .collect(),
    }
}

#[derive(Debug, Default)]
struct PolicyState {
    report: SourceRootReport,
    // Old locations remain denied for queued candidates after removal or
    // retargeting. A current matching root is evaluated under the new policy.
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
        for (fresh, previous) in report.roots.iter_mut().zip(&self.report.roots) {
            // If resolution now fails, keep the previous location as a denied
            // boundary for cached candidates addressed by its canonical name.
            if fresh.resolved_root.is_none() {
                fresh.resolved_root.clone_from(&previous.resolved_root);
            }
        }
        self.report = report;
    }
}

/// Live policy shared by scanner, executor and monitor. Cloning shares state;
/// it does not create a stale authorization snapshot.
#[derive(Debug, Clone, Default)]
pub struct SourceRootPolicy {
    inner: Arc<Mutex<PolicyState>>,
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

impl SourceRootPolicy {
    /// Inspect and install the initial configured-root policy.
    #[must_use]
    pub fn new(roots: &[PathBuf], allow: bool) -> Self {
        Self {
            inner: Arc::new(Mutex::new(PolicyState {
                report: inspect_roots(roots, allow),
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
        state.report = inspect_roots(roots, allow);
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
    /// Paths outside current and retired configured roots are not governed by
    /// this policy (e.g. separately handled special locations and ballast).
    ///
    /// Call at the final mutation boundary as well as during preflight. This
    /// check can only veto; opting in never replaces other candidate checks.
    pub fn authorize(&self, path: &Path) -> std::result::Result<(), String> {
        let lexical = absolute_lexical(path)
            .map_err(|error| format!("cannot resolve candidate {}: {error}", path.display()))?;
        let canonical = fs::canonicalize(path)
            .map_err(|error| format!("cannot resolve candidate {}: {error}", path.display()))?;
        let mut state = self.inner.lock();
        state.refresh();
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
        assert!(report.roots.iter().any(|root| root.reclaim_allowed));
        assert!(report.roots.iter().any(|root| !root.reclaim_allowed));
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
}
