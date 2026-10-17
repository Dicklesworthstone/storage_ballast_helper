//! Same-filesystem placement for recoverable cleanup.
//!
//! A configured ancestor is a useful location only when it is outside the
//! candidate and on the candidate's filesystem. Resolve aliases for comparison,
//! but retain the configured spelling in records so reopening the configured
//! store still finds them. Placement is not mutation authority: the transaction
//! layer must still lock the store and recheck identity and device before rename.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use super::{QUARANTINE_DIR_NAME, device_of, mount_point_of};

/// Keep the deepest eligible configured root, or use the candidate's mount.
/// For a missing source this remains a lexical location hint; `validate`
/// refuses the subsequent mutation before creating any store directories.
pub(super) fn root_for(path: &Path, roots: &[PathBuf]) -> PathBuf {
    let base = select_base(path, roots, probe)
        .cloned()
        .unwrap_or_else(|| mount_point_of(path));
    base.join(".sbh").join(QUARANTINE_DIR_NAME)
}

fn probe(path: &Path) -> Option<(PathBuf, u64)> {
    // Resolve fresh here, not through a long-lived scanner path cache. An alias
    // may have been redirected since the scan that produced this candidate.
    let resolved = fs::canonicalize(path).ok()?;
    let device = device_of(&resolved).ok()?.0;
    Some((resolved, device))
}

fn select_base<'a>(
    path: &Path,
    roots: &'a [PathBuf],
    mut observe: impl FnMut(&Path) -> Option<(PathBuf, u64)>,
) -> Option<&'a PathBuf> {
    let source = observe(path);
    let mut best: Option<(&PathBuf, usize)> = None;
    for root in roots {
        let depth = if let Some((source_path, source_device)) = &source {
            let Some((root_path, root_device)) = observe(root) else {
                // An inaccessible root is not evidence of the right device.
                continue;
            };
            if root_device != *source_device
                || source_path == &root_path
                || !source_path.starts_with(&root_path)
            {
                continue;
            }
            root_path.components().count()
        } else {
            // Preserve the existing non-mutating hint for absent candidates.
            if root.as_path() == path || !path.starts_with(root) {
                continue;
            }
            root.components().count()
        };
        if best.is_none_or(|(previous, previous_depth)| {
            depth > previous_depth || (depth == previous_depth && root < previous)
        }) {
            best = Some((root, depth));
        }
    }
    best.map(|(root, _)| root)
}

/// Check the layout BEFORE `ensure_root` can create a protection marker inside
/// the candidate. That marker would both alter the source and make future scans
/// refuse it, even though the move into its own descendant can never succeed.
pub(super) fn validate(source: &Path, destination: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(invalid(
            "quarantine source is not a regular file or directory",
        ));
    }
    let source = fs::canonicalize(source)?;
    let destination = resolve_destination(destination)?;
    if destination.starts_with(&source) || source.starts_with(&destination) {
        return Err(invalid("quarantine store and source overlap"));
    }
    Ok(())
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Resolve an existing ancestor and append only an unambiguous missing tail.
/// A dangling symlink is an existing entry, not a missing directory that the
/// quarantine operation may repair by creating its target.
fn resolve_destination(path: &Path) -> io::Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    for ancestor in absolute.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(_) => {
                let tail = absolute.strip_prefix(ancestor).map_err(io::Error::other)?;
                if tail
                    .components()
                    .any(|part| !matches!(part, Component::Normal(_) | Component::CurDir))
                {
                    return Err(invalid("unresolved parent traversal in quarantine store"));
                }
                return Ok(fs::canonicalize(ancestor)?.join(tail));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Err(invalid("quarantine store has no resolvable ancestor"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::quarantine::{QuarantineStore, QuarantineUnavailable};
    use std::collections::BTreeMap;
    use std::time::Duration;

    fn observed(paths: &[(&str, &str, u64)]) -> impl FnMut(&Path) -> Option<(PathBuf, u64)> {
        let paths: BTreeMap<PathBuf, (PathBuf, u64)> = paths
            .iter()
            .map(|(name, resolved, device)| {
                (PathBuf::from(name), (PathBuf::from(resolved), *device))
            })
            .collect();
        move |path| paths.get(path).cloned()
    }

    fn artifact(base: &Path) -> PathBuf {
        let path = base.join("target");
        fs::create_dir_all(path.join("nested")).unwrap();
        fs::write(path.join("nested/data"), b"recoverable artifact bytes").unwrap();
        path
    }

    #[test]
    fn foreign_filesystem_roots_are_not_placement_candidates() {
        let source = Path::new("/cache/mounted/target");
        let roots = vec![PathBuf::from("/cache"), PathBuf::from("/cache/mounted")];
        let selected = select_base(
            source,
            &roots,
            observed(&[
                ("/cache/mounted/target", "/cache/mounted/target", 2),
                ("/cache", "/cache", 1),
                ("/cache/mounted", "/cache/mounted", 2),
            ]),
        );
        assert_eq!(selected, Some(&roots[1]));
        assert!(
            select_base(
                source,
                &roots[..1],
                observed(&[
                    ("/cache/mounted/target", "/cache/mounted/target", 2),
                    ("/cache", "/cache", 1),
                ]),
            )
            .is_none()
        );
    }

    #[test]
    fn the_candidate_itself_is_never_selected_as_a_store_base() {
        let source = Path::new("/cache/target");
        let roots = vec![PathBuf::from("/cache"), source.to_path_buf()];
        assert_eq!(
            select_base(
                source,
                &roots,
                observed(&[
                    ("/cache/target", "/cache/target", 7),
                    ("/cache", "/cache", 7),
                ]),
            ),
            Some(&roots[0])
        );
    }

    #[test]
    fn unknown_roots_cannot_claim_a_known_sources_device() {
        let source = Path::new("/cache/target");
        let roots = vec![PathBuf::from("/cache")];
        assert!(
            select_base(
                source,
                &roots,
                observed(&[("/cache/target", "/cache/target", 7)]),
            )
            .is_none()
        );
    }

    #[test]
    fn aliases_are_compared_by_location_but_keep_the_configured_spelling() {
        let source = Path::new("/physical/work/target");
        let roots = vec![PathBuf::from("/alias"), PathBuf::from("/physical")];
        assert_eq!(
            select_base(
                source,
                &roots,
                observed(&[
                    ("/physical/work/target", "/physical/work/target", 7),
                    ("/alias", "/physical/work", 7),
                    ("/physical", "/physical", 7),
                ]),
            ),
            Some(&roots[0])
        );
    }

    #[test]
    fn aliases_to_the_source_are_also_excluded() {
        let source = Path::new("/physical/target");
        let roots = vec![PathBuf::from("/alias")];
        assert!(
            select_base(
                source,
                &roots,
                observed(&[
                    ("/physical/target", "/physical/target", 7),
                    ("/alias", "/physical/target", 7),
                ]),
            )
            .is_none()
        );
    }

    #[test]
    fn missing_sources_keep_lexical_hints_without_authorizing_mutation() {
        let roots = vec![PathBuf::from("/cache"), PathBuf::from("/cache/work")];
        assert_eq!(
            select_base(Path::new("/cache/work/target"), &roots, |_| None),
            Some(&roots[1])
        );
        let temp = tempfile::tempdir().unwrap();
        let store = QuarantineStore::at(temp.path().join("new-store"));
        assert!(
            store
                .quarantine(
                    &temp.path().join("missing"),
                    "missing",
                    1,
                    Duration::ZERO,
                    None,
                )
                .is_err()
        );
        assert!(!store.root().exists());
    }

    #[test]
    fn equal_physical_roots_have_a_stable_tie_break() {
        let source = Path::new("/physical/target");
        for roots in [
            vec![PathBuf::from("/alias-b"), PathBuf::from("/alias-a")],
            vec![PathBuf::from("/alias-a"), PathBuf::from("/alias-b")],
        ] {
            let selected = select_base(
                source,
                &roots,
                observed(&[
                    ("/physical/target", "/physical/target", 7),
                    ("/alias-a", "/physical", 7),
                    ("/alias-b", "/physical", 7),
                ]),
            );
            assert_eq!(selected.map(PathBuf::as_path), Some(Path::new("/alias-a")));
        }
    }

    #[test]
    fn a_scan_root_candidate_can_be_quarantined_and_restored_from_its_parent() {
        let temp = tempfile::tempdir().unwrap();
        let source = artifact(temp.path());
        let roots = vec![temp.path().to_path_buf(), source.clone()];
        let root = root_for(&source, &roots);
        assert_eq!(root, temp.path().join(".sbh/quarantine"));
        let store = QuarantineStore::at(root.clone());
        let record = store
            .quarantine(&source, "root-candidate", 25, Duration::from_hours(1), None)
            .unwrap();
        assert!(!source.exists());
        assert!(record.quarantine_path.join("nested/data").is_file());
        assert!(!record.quarantine_path.join(".sbh").exists());
        // Reopen rather than relying on the instance that performed the move.
        let reopened = QuarantineStore::at(root);
        assert_eq!(reopened.records().unwrap().len(), 1);
        reopened.restore("root-candidate", false).unwrap();
        assert_eq!(
            fs::read(source.join("nested/data")).unwrap(),
            b"recoverable artifact bytes"
        );
    }

    #[test]
    fn overlapping_store_is_refused_before_creating_a_protection_marker() {
        let temp = tempfile::tempdir().unwrap();
        let source = artifact(temp.path());
        let store = QuarantineStore::under(&source);
        let error = store
            .quarantine(&source, "overlap", 25, Duration::ZERO, None)
            .unwrap_err();
        assert!(matches!(error, QuarantineUnavailable::RootUnavailable(_)));
        assert!(!source.join(".sbh").exists());
        assert_eq!(
            fs::read(source.join("nested/data")).unwrap(),
            b"recoverable artifact bytes"
        );
    }

    #[test]
    fn a_source_already_inside_the_store_is_refused_without_new_bookkeeping() {
        let temp = tempfile::tempdir().unwrap();
        let source = artifact(temp.path());
        let store = QuarantineStore::at(temp.path().to_path_buf());
        assert!(
            store
                .quarantine(&source, "inside", 25, Duration::ZERO, None)
                .is_err()
        );
        assert!(!store.root().join(".sbh-protect").exists());
        assert!(!store.root().join("inside.pending").exists());
        assert!(source.join("nested/data").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn a_store_alias_into_the_source_is_refused_before_creating_its_missing_tail() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let source = artifact(temp.path());
        let alias = temp.path().join("alias");
        symlink(&source, &alias).unwrap();
        let store = QuarantineStore::under(&alias);
        assert!(
            store
                .quarantine(&source, "aliased-overlap", 25, Duration::ZERO, None)
                .is_err()
        );
        assert!(!source.join(".sbh").exists());
        assert!(source.join("nested/data").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_store_alias_is_not_repaired_inside_the_source() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let source = artifact(temp.path());
        let alias = temp.path().join("dangling");
        symlink(source.join("not-created"), &alias).unwrap();
        let store = QuarantineStore::under(&alias);
        assert!(
            store
                .quarantine(&source, "dangling", 25, Duration::ZERO, None)
                .is_err()
        );
        assert!(!source.join("not-created").exists());
        assert!(
            fs::symlink_metadata(alias)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn configured_alias_store_can_be_reopened_for_undo() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let physical = temp.path().join("physical");
        fs::create_dir(&physical).unwrap();
        let source = artifact(&physical);
        let alias = temp.path().join("configured");
        symlink(&physical, &alias).unwrap();
        let root = root_for(&source, std::slice::from_ref(&alias));
        assert_eq!(root, alias.join(".sbh/quarantine"));
        QuarantineStore::at(root)
            .quarantine(&source, "alias-undo", 25, Duration::ZERO, None)
            .unwrap();
        let reopened = QuarantineStore::under(&alias);
        assert_eq!(reopened.records().unwrap().len(), 1);
        reopened.restore("alias-undo", false).unwrap();
        assert_eq!(
            fs::read(source.join("nested/data")).unwrap(),
            b"recoverable artifact bytes"
        );
    }

    #[cfg(unix)]
    #[test]
    fn foreign_filesystem_beneath_a_watched_alias_gets_a_local_recoverable_store() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let other = match tempfile::tempdir_in("/dev/shm") {
            Ok(other) => other,
            Err(error) => {
                eprintln!("cross-filesystem placement not exercised: {error}");
                return;
            }
        };
        if device_of(temp.path()).unwrap().0 == device_of(other.path()).unwrap().0 {
            eprintln!("cross-filesystem placement not exercised: scratch devices are identical");
            return;
        }
        artifact(other.path());
        let alias = temp.path().join("mounted");
        symlink(other.path(), &alias).unwrap();
        let source = alias.join("target");
        let root = root_for(&source, &[temp.path().to_path_buf()]);
        assert_eq!(root, alias.join(".sbh/quarantine"));
        let store = QuarantineStore::at(root.clone());
        store
            .quarantine(&source, "other-device", 25, Duration::ZERO, None)
            .unwrap();
        assert!(!source.exists());
        assert!(!temp.path().join(".sbh").exists());
        assert_eq!(
            device_of(store.root()).unwrap().0,
            device_of(other.path()).unwrap().0
        );
        QuarantineStore::at(root)
            .restore("other-device", false)
            .unwrap();
        assert_eq!(
            fs::read(source.join("nested/data")).unwrap(),
            b"recoverable artifact bytes"
        );
    }

    #[test]
    fn ambiguous_missing_parent_traversal_does_not_create_directories() {
        let temp = tempfile::tempdir().unwrap();
        let source = artifact(temp.path());
        let destination = temp.path().join("missing/../target/.sbh/quarantine");
        assert!(validate(&source, &destination).is_err());
        assert!(!temp.path().join("missing").exists());
        assert!(!source.join(".sbh").exists());
    }
}
