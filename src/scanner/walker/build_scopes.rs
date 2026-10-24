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
//! root aliases are resolved once when the observation is collected. The
//! executor additionally checks observed directory identities along ancestry
//! to recognize bind aliases which canonicalization does not rewrite. Neither
//! mechanism proves that a provider's omitted declarations are unused.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Bound;
use std::path::{Path, PathBuf};

use crate::core::paths::resolve_absolute_path;
use crate::scanner::scoring::ActiveReferenceSummary;

use super::{FsEntryKind, FsIdentity};

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
        path.ancestors()
            .any(|parent| self.scopes.contains_key(parent))
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
            debug_assert_ne!(scope.as_path(), path.as_ref());
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
    let directories: Vec<_> = directories
        .into_iter()
        .filter(|(pid, path)| *pid > 0 && path.is_absolute())
        .map(|(pid, path)| (pid, resolve_absolute_path(&path)))
        .collect();
    let mut scopes = BuildDirectoryScopes {
        roots: normalized_roots
            .iter()
            .map(|(root, _)| (root.clone(), root.clone()))
            .collect(),
        scopes: BTreeMap::new(),
    };
    for (pid, directory) in &directories {
        scopes.insert(*pid, directory, None);
        super::add_open_path_ancestor_chain(ancestors, directory, normalized_roots);
    }
    for (candidate, _) in normalized_roots {
        if scopes.is_busy(candidate) {
            super::add_open_path_ancestor_chain(ancestors, candidate, normalized_roots);
        }
    }
    // A bind-mounted view can have no lexical relationship to the build's
    // declaration. Inspect only ancestry, never the contents of either tree.
    // This stage only adds refusals; failed metadata cannot erase a path veto.
    for candidate in identity_refusals(&directories, normalized_roots, |path| {
        super::identity_for_path(path, true).ok()
    }) {
        super::add_open_path_ancestor_chain(ancestors, &candidate, normalized_roots);
    }
}

/// Additional deny-only alias evidence for this executor batch. Keep the two
/// directions separate: a declared directory protects all its descendants,
/// whereas an ancestor of a declaration is refused only as a WHOLE candidate.
/// Intersecting two sets of ancestors would mark unrelated siblings busy just
/// because they share `/` or a mount root.
///
/// Each distinct pathname is inspected at most once per call, including failed
/// observations. Nothing is cached across batches. These are point-in-time
/// observations, not deletion authority or an atomic mount-namespace snapshot;
/// the executor retains its independent identity, lease and no-cross-mount rails.
fn identity_refusals(
    directories: &[(i32, PathBuf)],
    roots: &[(PathBuf, usize)],
    mut identify: impl FnMut(&Path) -> Option<FsIdentity>,
) -> HashSet<PathBuf> {
    let mut observations = HashMap::new();
    let mut lookup = |path: &Path| {
        *observations.entry(path.to_path_buf()).or_insert_with(|| {
            identify(path).filter(|identity| identity.kind == FsEntryKind::Directory)
        })
    };
    let mut declared = HashSet::new();
    let mut enclosing = HashSet::new();
    for (pid, directory) in directories {
        if *pid <= 0 || !directory.is_absolute() {
            continue;
        }
        if let Some(identity) = lookup(directory) {
            declared.insert(identity);
        }
        for parent in directory.ancestors().skip(1) {
            if let Some(identity) = lookup(parent) {
                enclosing.insert(identity);
            }
        }
    }
    let mut refused = HashSet::new();
    for (candidate, _) in roots {
        if lookup(candidate).is_some_and(|identity| enclosing.contains(&identity))
            || candidate
                .ancestors()
                .any(|parent| lookup(parent).is_some_and(|identity| declared.contains(&identity)))
        {
            refused.insert(candidate.clone());
        }
    }
    refused
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
        assert!(
            !scopes.is_busy(&cache),
            "queries remain scoped to scan roots"
        );

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

    fn directory_identity(device_id: u64, inode: u64) -> FsIdentity {
        FsIdentity {
            device_id,
            inode,
            kind: FsEntryKind::Directory,
        }
    }

    fn candidate_roots(names: &[&str]) -> Vec<(PathBuf, usize)> {
        names
            .iter()
            .map(|name| {
                let path = PathBuf::from(name);
                let depth = path.components().count();
                (path, depth)
            })
            .collect()
    }

    #[test]
    fn declaration_identity_protects_an_unrelated_mount_spelling_and_its_descendants() {
        let cache = directory_identity(7, 10);
        let identities = BTreeMap::from([
            (Path::new("/source/cache"), cache),
            (Path::new("/view/cache"), cache),
            (Path::new("/view/cache/objects"), directory_identity(7, 11)),
            (Path::new("/view/cache-other"), directory_identity(7, 12)),
            (Path::new("/"), directory_identity(7, 1)),
        ]);
        let roots = candidate_roots(&[
            "/view/cache/objects",
            "/view/cache/objects/artifact.o",
            "/view/cache-other",
        ]);
        let declarations = vec![(42, PathBuf::from("/source/cache"))];
        let refused =
            identity_refusals(&declarations, &roots, |path| identities.get(path).copied());
        assert_eq!(
            refused,
            HashSet::from([roots[0].0.clone(), roots[1].0.clone()])
        );
        assert!(
            roots.iter().all(|(path, _)| {
                !path.starts_with(&declarations[0].1) && !declarations[0].1.starts_with(path)
            }),
            "path-only projection cannot establish any of these alias refusals"
        );
    }

    #[test]
    fn enclosing_alias_is_refused_without_promoting_its_idle_children_to_scopes() {
        let parent = directory_identity(7, 2);
        let cache = directory_identity(7, 10);
        let identities = BTreeMap::from([
            (Path::new("/source"), parent),
            (Path::new("/source/cache"), cache),
            (Path::new("/view/job"), parent),
            (Path::new("/view/job/cache"), cache),
            (Path::new("/view/job/idle"), directory_identity(7, 12)),
            (Path::new("/view"), directory_identity(7, 3)),
            (Path::new("/"), directory_identity(7, 1)),
        ]);
        let roots =
            candidate_roots(&["/view/job", "/view/job/idle", "/view/job/cache/deep/file.o"]);
        let declarations = vec![(42, PathBuf::from("/source/cache"))];
        assert_eq!(
            identity_refusals(&declarations, &roots, |path| identities.get(path).copied()),
            HashSet::from([roots[0].0.clone(), roots[2].0.clone()])
        );
    }

    #[test]
    fn missing_metadata_other_devices_and_file_identities_do_not_invent_aliases() {
        let cache = directory_identity(7, 10);
        let identities = BTreeMap::from([
            (Path::new("/source/cache"), cache),
            (Path::new("/different-device"), directory_identity(8, 10)),
            (
                Path::new("/not-a-directory"),
                FsIdentity {
                    kind: FsEntryKind::File,
                    ..cache
                },
            ),
            (Path::new("/"), directory_identity(7, 1)),
        ]);
        let roots = candidate_roots(&[
            "/different-device/child",
            "/not-a-directory/child",
            "/unreadable/child",
        ]);
        let declarations = vec![(42, PathBuf::from("/source/cache"))];
        assert!(
            identity_refusals(&declarations, &roots, |path| identities.get(path).copied())
                .is_empty()
        );
        assert!(identity_refusals(&declarations, &roots, |_| None).is_empty());
        let invalid = vec![(0, PathBuf::from("/source/cache"))];
        assert!(identity_refusals(&invalid, &roots, |_| Some(cache)).is_empty());
    }

    #[test]
    fn identity_observations_are_memoized_only_within_the_current_batch() {
        let cache = directory_identity(7, 10);
        let roots = candidate_roots(&["/view/cache/a", "/view/cache/b"]);
        let declarations = vec![
            (42, PathBuf::from("/source/cache")),
            (43, PathBuf::from("/source/cache")),
        ];
        let mut calls = BTreeMap::<PathBuf, usize>::new();
        let old = identity_refusals(&declarations, &roots, |path| {
            *calls.entry(path.to_path_buf()).or_default() += 1;
            matches!(path.to_str(), Some("/source/cache" | "/view/cache")).then_some(cache)
        });
        assert_eq!(old.len(), 2);
        assert!(calls.values().all(|count| *count == 1));
        let new = identity_refusals(&declarations, &roots, |path| {
            (path == Path::new("/source/cache")).then_some(cache)
        });
        assert!(
            new.is_empty(),
            "a new batch must not reuse the former alias"
        );
        assert_eq!(old.len(), 2, "the old observation remains immutable");
    }

    #[cfg(unix)]
    #[test]
    fn native_ancestry_identity_preserves_an_active_directory_through_an_alias() {
        let temp = tempfile::tempdir().unwrap();
        let root = resolve_absolute_path(temp.path());
        let cache = root.join("source/cache");
        fs::create_dir_all(cache.join("objects")).unwrap();
        fs::write(cache.join("objects/artifact.o"), b"keep active bytes").unwrap();
        let alias = root.join("view");
        std::os::unix::fs::symlink(&cache, &alias).unwrap();
        let child = alias.join("objects/artifact.o");
        let sibling = root.join("idle");
        fs::create_dir(&sibling).unwrap();
        // Deliberately leave the alias unresolved to exercise identity rather
        // than the normal path normalization used by the caller. This is a
        // native symlink control, not a claim to have mounted a bind fixture.
        let roots = vec![(child.clone(), 0), (sibling.clone(), 0)];
        let refused = identity_refusals(&[(42, cache.clone())], &roots, |path| {
            super::super::identity_for_path(path, true).ok()
        });
        assert_eq!(refused, HashSet::from([child]));
        assert!(sibling.is_dir());
        assert_eq!(
            fs::read(cache.join("objects/artifact.o")).unwrap(),
            b"keep active bytes"
        );
    }
}
