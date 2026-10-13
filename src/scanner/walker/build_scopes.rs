//! Subtree semantics for directories declared by live builds.
//!
//! An open file is a point reference: it protects enclosing candidates but
//! not unrelated siblings. A declared cache/output directory is different:
//! removing ANY descendant can break its build even when no descriptor is
//! currently held there. Keep these scopes separate from point references.
//!
//! The index stores only declarations, not the contents of a cache. Scope
//! checks use path components and ordered lookups; no recursive scan, string
//! prefix guess, or per-candidate canonicalization is performed. Configured
//! root aliases are resolved once when the observation is collected. Unseen
//! aliases and a provider's omitted declarations remain outside this evidence.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use std::ops::Bound;
use std::path::{Path, PathBuf};

use crate::core::paths::resolve_absolute_path;
use crate::scanner::scoring::ActiveReferenceSummary;

#[derive(Debug, Clone, Default)]
pub(super) struct BuildDirectoryScopes {
    roots: Vec<(PathBuf, PathBuf)>,
    // One positive bit per process and scope. Repeated declarations do not
    // inflate descriptor counts or fabricate additional processes.
    scopes: BTreeMap<PathBuf, BTreeMap<i32, Option<String>>>,
}

impl BuildDirectoryScopes {
    pub(super) fn new(roots: &[PathBuf]) -> Self {
        Self {
            roots: roots
                .iter()
                .map(|root| (root.clone(), resolve_absolute_path(root)))
                .collect(),
            scopes: BTreeMap::new(),
        }
    }

    pub(super) fn insert(&mut self, pid: i32, path: &Path, name: Option<String>) {
        if pid <= 0 || !path.is_absolute() {
            return;
        }
        let path = resolve_absolute_path(path);
        // A scanner root can itself be inside the active cache. An
        // ancestor-only collector discarded this declaration completely.
        if !self
            .roots
            .iter()
            .any(|(_, root)| path.starts_with(root) || root.starts_with(&path))
        {
            return;
        }
        let observed = self.scopes.entry(path).or_default().entry(pid).or_default();
        if observed.is_none() {
            *observed = name;
        }
    }

    fn query_path<'a>(&self, path: &'a Path) -> Option<Cow<'a, Path>> {
        if self.scopes.is_empty() {
            return None;
        }
        // The walker keeps the configured spelling (e.g. macOS /tmp). Bind
        // that spelling to the root snapshot instead of resolving each entry.
        // Prefer the most specific configured root when aliases are nested.
        if let Some((raw, resolved)) = self
            .roots
            .iter()
            .filter(|(raw, _)| path.starts_with(raw))
            .max_by_key(|(raw, _)| raw.components().count())
        {
            if raw == resolved {
                return Some(Cow::Borrowed(path));
            }
            let suffix = path.strip_prefix(raw).ok()?;
            return Some(Cow::Owned(resolved.join(suffix)));
        }
        self.roots
            .iter()
            .any(|(_, resolved)| path.starts_with(resolved))
            .then_some(Cow::Borrowed(path))
    }

    pub(super) fn is_busy(&self, path: &Path) -> bool {
        let Some(path) = self.query_path(path) else {
            return false;
        };
        path.ancestors().any(|parent| self.scopes.contains_key(parent))
            || self
                .scopes
                .range::<Path, _>((Bound::Included(path.as_ref()), Bound::Unbounded))
                .next()
                .is_some_and(|(scope, _)| scope.starts_with(path.as_ref()))
    }

    pub(super) fn extend_summary(&self, path: &Path, summary: &mut ActiveReferenceSummary) {
        let Some(path) = self.query_path(path) else {
            return;
        };
        for parent in path.ancestors() {
            if let Some(processes) = self.scopes.get(parent) {
                for (pid, name) in processes {
                    summary.add_build_directory(*pid, name.clone());
                }
            }
        }
        // A candidate enclosing a declared cache is busy too. Iterate only
        // the consecutive descendant range, never all unrelated declarations.
        for (scope, processes) in self
            .scopes
            .range::<Path, _>((Bound::Excluded(path.as_ref()), Bound::Unbounded))
            .take_while(|(scope, _)| scope.starts_with(path.as_ref()))
        {
            debug_assert!(scope != path.as_ref());
            for (pid, name) in processes {
                summary.add_build_directory(*pid, name.clone());
            }
        }
    }
}

/// Project positive scopes onto the finite candidate roots of an executor
/// batch. Do not populate every directory below a cache or reinterpret the
/// ordinary open-ancestor set as subtree declarations.
pub(super) fn add_candidate_scopes(
    directories: Vec<(i32, PathBuf)>,
    normalized_roots: &[(PathBuf, usize)],
    ancestors: &mut HashSet<PathBuf>,
) {
    if directories.is_empty() || normalized_roots.is_empty() {
        return;
    }
    let mut scopes = BuildDirectoryScopes {
        roots: normalized_roots
            .iter()
            .map(|(root, _)| (root.clone(), root.clone()))
            .collect(),
        scopes: BTreeMap::new(),
    };
    for (pid, directory) in directories {
        scopes.insert(pid, &directory, None);
        if pid > 0 && directory.is_absolute() {
            super::add_open_path_ancestor_chain(ancestors, &directory, normalized_roots);
        }
    }
    for (candidate, _) in normalized_roots {
        if scopes.is_busy(candidate) {
            super::add_open_path_ancestor_chain(ancestors, candidate, normalized_roots);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn index(root: &Path, declarations: &[(&str, i32)]) -> BuildDirectoryScopes {
        let mut scopes = BuildDirectoryScopes::new(&[root.to_path_buf()]);
        for (path, pid) in declarations {
            scopes.insert(*pid, &root.join(path), Some(format!("builder-{pid}")));
        }
        scopes
    }

    #[test]
    fn declaration_protects_descendants_and_enclosers_not_siblings() {
        let temp = tempfile::tempdir().unwrap();
        let root = resolve_absolute_path(temp.path());
        let scopes = index(&root, &[("cache/objects", 42)]);
        for relative in ["", "cache", "cache/objects", "cache/objects/deep/file.o"] {
            assert!(scopes.is_busy(&root.join(relative)), "{relative}");
        }
        for relative in ["idle", "cache/objects-other", "cache/metadata"] {
            assert!(!scopes.is_busy(&root.join(relative)), "{relative}");
        }
        assert!(!scopes.is_busy(root.parent().unwrap()));
        assert_eq!(scopes.scopes.len(), 1, "no expansion of the filesystem");
    }

    #[test]
    fn declarations_above_a_narrow_scan_root_are_not_discarded() {
        let temp = tempfile::tempdir().unwrap();
        let root = resolve_absolute_path(temp.path());
        let cache = root.join("cache");
        let candidate = cache.join("objects/deep");
        let mut scopes = BuildDirectoryScopes::new(std::slice::from_ref(&candidate));
        scopes.insert(42, &cache, None);
        assert!(scopes.is_busy(&candidate));
        assert!(scopes.is_busy(&candidate.join("object.o")));
        assert!(!scopes.is_busy(&cache), "queries remain scoped to scan roots");

        let roots = vec![(candidate.clone(), candidate.components().count())];
        let mut ancestors = HashSet::new();
        add_candidate_scopes(vec![(42, cache.clone())], &roots, &mut ancestors);
        assert!(ancestors.contains(&candidate));
        assert!(!ancestors.contains(&cache));
    }

    #[test]
    fn multiple_builds_merge_with_other_evidence_without_duplicate_processes() {
        let temp = tempfile::tempdir().unwrap();
        let root = resolve_absolute_path(temp.path());
        let mut scopes = index(&root, &[("cache", 42), ("cache/nested", 43)]);
        scopes.insert(42, &root.join("cache"), None);
        scopes.insert(43, &root.join("cache/nested"), None);
        let mut summary = ActiveReferenceSummary::default();
        summary.add_open_file_descriptor(42, Some("builder-42".to_string()));
        summary.mark_incomplete("another process is inaccessible");
        scopes.extend_summary(&root.join("cache/nested/deep"), &mut summary);
        scopes.extend_summary(&root.join("cache/nested/deep"), &mut summary);
        assert_eq!(summary.processes.len(), 2);
        assert_eq!(summary.processes[0].pid, 42);
        assert_eq!(summary.processes[0].open_file_descriptors, 1);
        assert!(
            summary
                .processes
                .iter()
                .all(|process| process.build_directory)
        );
        assert_eq!(
            summary.incomplete_reason.as_deref(),
            Some("another process is inaccessible")
        );
    }

    #[test]
    fn point_references_do_not_become_subtree_declarations() {
        let temp = tempfile::tempdir().unwrap();
        let root = resolve_absolute_path(temp.path());
        let busy = root.join("cache/busy");
        let idle = root.join("cache/idle");
        let roots =
            super::super::normalized_open_roots(&[root.clone(), busy.clone(), idle.clone()]);
        let mut ancestors = HashSet::new();
        super::super::add_open_path_ancestor_chain(&mut ancestors, &busy.join("file"), &roots);
        add_candidate_scopes(Vec::new(), &roots, &mut ancestors);
        assert!(ancestors.contains(&busy));
        assert!(ancestors.contains(&root));
        assert!(!ancestors.contains(&idle));
        add_candidate_scopes(vec![(42, root.join("cache"))], &roots, &mut ancestors);
        assert!(ancestors.contains(&idle));
    }

    #[test]
    fn rebuilding_a_snapshot_releases_ended_builds_without_mutating_the_old_one() {
        let temp = tempfile::tempdir().unwrap();
        let root = resolve_absolute_path(temp.path());
        let old = index(&root, &[("cache", 42)]);
        let new = BuildDirectoryScopes::new(std::slice::from_ref(&root));
        assert!(old.is_busy(&root.join("cache/child")));
        assert!(!new.is_busy(&root.join("cache/child")));
    }

    #[cfg(unix)]
    #[test]
    fn configured_root_alias_is_bound_once_not_resolved_during_lookup() {
        let temp = tempfile::tempdir().unwrap();
        let real = resolve_absolute_path(temp.path()).join("real");
        let alias = temp.path().join("alias");
        fs::create_dir_all(real.join("cache/deep")).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let mut scopes = BuildDirectoryScopes::new(std::slice::from_ref(&alias));
        scopes.insert(42, &real.join("cache"), None);
        assert!(scopes.is_busy(&alias.join("cache/deep")));
        assert!(scopes.is_busy(&real.join("cache/deep")));
        assert!(!scopes.is_busy(&alias.join("cache-other")));
        // No path resolution is needed to keep a not-yet-created child safe.
        assert!(scopes.is_busy(&alias.join("cache/not-created/object.o")));
    }

    #[test]
    fn malformed_and_out_of_scope_declarations_do_not_invent_references() {
        let temp = tempfile::tempdir().unwrap();
        let root = resolve_absolute_path(temp.path()).join("scan");
        let mut scopes = BuildDirectoryScopes::new(std::slice::from_ref(&root));
        for (pid, path) in [
            (42, PathBuf::from("relative/cache")),
            (0, root.clone()),
            (-1, root.clone()),
            (42, root.with_file_name("other")),
        ] {
            scopes.insert(pid, &path, None);
        }
        assert!(scopes.scopes.is_empty());
        assert!(!scopes.is_busy(&root));
    }

    #[test]
    fn indexed_answers_match_all_pairs_overlap_for_every_small_subset() {
        let temp = tempfile::tempdir().unwrap();
        let root = resolve_absolute_path(temp.path());
        let names = ["a", "a/deep", "a-other", "b/cache", "c", "c/child", "d"];
        let queries = [
            "",
            "a",
            "a/deep/file",
            "a/sibling",
            "a-other/file",
            "a-another",
            "b",
            "b/cache/file",
            "b/idle",
            "c/child/object",
            "d/obj",
            "idle",
        ];
        for mask in 0..(1usize << names.len()) {
            let declarations: Vec<_> = names
                .iter()
                .enumerate()
                .filter(|(index, _)| mask & (1usize << *index) != 0)
                .map(|(index, name)| (root.join(name), i32::try_from(index + 1).unwrap()))
                .collect();
            let mut scopes = BuildDirectoryScopes::new(std::slice::from_ref(&root));
            for (path, pid) in declarations.iter().rev() {
                scopes.insert(*pid, path, None);
                scopes.insert(*pid, path, None);
            }
            for query in queries {
                let query = root.join(query);
                let expected: Vec<_> = declarations
                    .iter()
                    .filter(|(scope, _)| query.starts_with(scope) || scope.starts_with(&query))
                    .map(|(_, pid)| *pid)
                    .collect();
                let mut summary = ActiveReferenceSummary::default();
                scopes.extend_summary(&query, &mut summary);
                let observed: Vec<_> = summary
                    .processes
                    .iter()
                    .map(|process| process.pid)
                    .collect();
                assert_eq!(observed, expected, "mask={mask}, query={query:?}");
                assert_eq!(scopes.is_busy(&query), !expected.is_empty());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn native_component_names_are_not_conflated_with_lossy_text() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let temp = tempfile::tempdir().unwrap();
        let root = resolve_absolute_path(temp.path());
        let cache = root.join(OsString::from_vec(b"cache-\xff".to_vec()));
        let mut scopes = BuildDirectoryScopes::new(std::slice::from_ref(&root));
        scopes.insert(42, &cache, None);
        assert!(scopes.is_busy(&cache.join("child")));
        assert!(!scopes.is_busy(&root.join("cache-\u{fffd}/child")));
    }
}
