//! Git-content exclusion shared by compression admission and discovery (bd-1p9j).
//!
//! Compression deliberately excludes whole work trees, not only tracked files.
//! Unlike deletion's tracked-content probe, this check never executes Git or
//! reads its configuration, index, gitfile, or object payloads. A marker of any
//! type (including a dangling symlink or malformed gitfile) is a conservative
//! veto. Bare and separately located administrative directories are recognized
//! by HEAD together with an object/reference/common-directory marker.
//!
//! These are fresh observations, not a lock against repository creation. The
//! executor repeats admission between chunks and retains its pinned-path checks;
//! the operator's existing quiescence requirement is not relaxed.

use std::fs::{self, Metadata};
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path};

const MAX_ANCESTORS: usize = 256;
const EXCLUSION: &str = "git_repository";

/// Refuse explicit files inside repository content before opening for rewrite.
pub(in crate::scanner::compression) fn check_file(path: &Path) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "compression input has no parent",
        )
    })?;
    // A worktree's .git FILE is repository data too, not just its descendants.
    if path.file_name().is_some_and(|name| name == ".git") || directory_exclusion(parent)?.is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Git repository content is excluded from compression",
        ));
    }
    Ok(())
}

/// Classify a directory and all its ancestors. None requires complete evidence;
/// errors are not negative results and callers must not suppress them.
pub(in crate::scanner::compression) fn directory_exclusion(
    directory: &Path,
) -> io::Result<Option<&'static str>> {
    inspect_ancestors(directory, |path| fs::symlink_metadata(path))
}

fn inspect_ancestors(
    directory: &Path,
    mut metadata: impl FnMut(&Path) -> io::Result<Metadata>,
) -> io::Result<Option<&'static str>> {
    if !directory.is_absolute()
        || directory
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "repository inspection requires an absolute directory without traversal",
        ));
    }
    if directory
        .components()
        .any(|part| part.as_os_str() == ".git")
    {
        return Ok(Some(EXCLUSION));
    }
    for (depth, ancestor) in directory.ancestors().enumerate() {
        if depth >= MAX_ANCESTORS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "repository ancestry inspection limit exceeded",
            ));
        }
        let before = metadata(ancestor)?;
        if !before.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "repository ancestry is missing, replaced, or symlinked",
            ));
        }
        if marker_present(&ancestor.join(".git"), &mut metadata)? {
            return Ok(Some(EXCLUSION));
        }
        // Bare repositories need no .git suffix. Linked administrative dirs
        // may keep objects/refs in the directory named by commondir instead.
        if marker_present(&ancestor.join("HEAD"), &mut metadata)? {
            for name in ["objects", "refs", "packed-refs", "commondir"] {
                if marker_present(&ancestor.join(name), &mut metadata)? {
                    return Ok(Some(EXCLUSION));
                }
            }
        }
        let after = metadata(ancestor)?;
        if !after.is_dir() || before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(io::Error::other(
                "repository ancestry changed during inspection",
            ));
        }
    }
    Ok(None)
}

fn marker_present(
    path: &Path,
    metadata: &mut impl FnMut(&Path) -> io::Result<Metadata>,
) -> io::Result<bool> {
    match metadata(path) {
        Ok(_) => Ok(true),
        // Only an absent marker counts as negative evidence. In particular,
        // PermissionDenied, NotADirectory and symlink-loop errors propagate.
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn scratch() -> (tempfile::TempDir, std::path::PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        (temp, root)
    }

    #[test]
    fn worktree_sources_build_outputs_and_packfiles_are_all_excluded() {
        let (_temp, root) = scratch();
        fs::create_dir_all(root.join("repo/.git/objects/pack")).unwrap();
        fs::create_dir_all(root.join("repo/target/deep")).unwrap();
        for name in [
            "repo/main.rs",
            "repo/target/deep/app",
            "repo/.git/objects/pack/old.pack",
        ] {
            let path = root.join(name);
            fs::write(&path, b"retain every byte").unwrap();
            assert_eq!(
                check_file(&path).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(fs::read(&path).unwrap(), b"retain every byte");
        }
    }

    #[test]
    fn gitfiles_are_excluded_without_parsing_or_following_their_targets() {
        let (_temp, root) = scratch();
        for (name, contents) in [
            ("linked", "gitdir: /not-opened/worktrees/example\n"),
            ("submodule", "gitdir: ../../.git/modules/example\n"),
            ("malformed", "not a gitfile"),
            ("empty", ""),
        ] {
            let worktree = root.join(name);
            fs::create_dir(&worktree).unwrap();
            fs::write(worktree.join(".git"), contents).unwrap();
            assert_eq!(directory_exclusion(&worktree).unwrap(), Some(EXCLUSION));
            assert!(check_file(&worktree.join(".git")).is_err());
            assert_eq!(fs::read_to_string(worktree.join(".git")).unwrap(), contents);
        }
    }

    #[test]
    fn bare_and_relocated_administrative_directories_need_no_git_suffix() {
        let (_temp, root) = scratch();
        for marker in ["objects", "refs", "packed-refs", "commondir"] {
            let bare = root.join(marker);
            fs::create_dir_all(bare.join("deep")).unwrap();
            fs::write(bare.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
            fs::write(bare.join(marker), b"marker only; not parsed").unwrap();
            assert_eq!(
                directory_exclusion(&bare.join("deep")).unwrap(),
                Some(EXCLUSION)
            );
        }
    }

    #[test]
    fn git_metadata_names_are_not_confused_with_similarly_named_scratch() {
        let (_temp, root) = scratch();
        for name in [".github", ".git-cache", "objects", "refs"] {
            fs::create_dir(root.join(name)).unwrap();
            assert_eq!(directory_exclusion(&root.join(name)).unwrap(), None);
        }
        let ordinary = root.join("ordinary");
        fs::create_dir(&ordinary).unwrap();
        fs::write(
            ordinary.join("HEAD"),
            b"not enough to identify a repository",
        )
        .unwrap();
        fs::write(ordinary.join(".gitignore"), b"target\n").unwrap();
        assert_eq!(directory_exclusion(&ordinary).unwrap(), None);
    }

    #[test]
    fn a_git_marker_created_after_an_earlier_check_is_not_hidden_by_a_cache() {
        let (_temp, root) = scratch();
        fs::create_dir_all(root.join("a/b/c")).unwrap();
        let file = root.join("a/b/c/cold.bin");
        fs::write(&file, b"untouched").unwrap();
        assert!(check_file(&file).is_ok());
        fs::create_dir(root.join(".git")).unwrap();
        assert!(check_file(&file).is_err());
        assert_eq!(fs::read(file).unwrap(), b"untouched");
    }

    #[test]
    fn dangling_git_markers_and_symlinked_ancestors_never_admit() {
        let (_temp, root) = scratch();
        fs::create_dir(root.join("repo")).unwrap();
        symlink(root.join("absent"), root.join("repo/.git")).unwrap();
        assert_eq!(
            directory_exclusion(&root.join("repo")).unwrap(),
            Some(EXCLUSION)
        );
        fs::create_dir(root.join("ordinary")).unwrap();
        symlink(root.join("ordinary"), root.join("alias")).unwrap();
        assert!(directory_exclusion(&root.join("alias")).is_err());
        assert!(directory_exclusion(&root.join("missing")).is_err());
    }

    #[test]
    fn missing_marker_is_negative_but_permission_or_io_errors_are_not() {
        let (_temp, root) = scratch();
        for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::Other] {
            let result = inspect_ancestors(&root, |path| {
                if path == root.join(".git") {
                    Err(io::Error::new(kind, "injected inspection failure"))
                } else {
                    fs::symlink_metadata(path)
                }
            });
            assert_eq!(result.unwrap_err().kind(), kind);
        }
        assert_eq!(directory_exclusion(&root).unwrap(), None);
    }

    #[test]
    fn a_replaced_ancestor_cannot_supply_negative_evidence() {
        let (_temp, root) = scratch();
        fs::create_dir(root.join("replacement")).unwrap();
        let replacement = fs::symlink_metadata(root.join("replacement")).unwrap();
        let mut seen = false;
        let error = inspect_ancestors(&root, |path| {
            if path == root {
                if seen {
                    return Ok(replacement.clone());
                }
                seen = true;
            }
            fs::symlink_metadata(path)
        })
        .unwrap_err();
        assert!(error.to_string().contains("changed during inspection"));
    }

    #[test]
    fn excessive_ancestry_and_relative_paths_are_not_negative_evidence() {
        assert!(directory_exclusion(Path::new("relative")).is_err());
        assert!(directory_exclusion(Path::new("/tmp/../other")).is_err());
        let (_temp, root) = scratch();
        let directory_metadata = fs::symlink_metadata(&root).unwrap();
        let mut deep = root;
        for _ in 0..MAX_ANCESTORS {
            deep.push("a");
        }
        let error = inspect_ancestors(&deep, |path| {
            if matches!(
                path.file_name().and_then(|name| name.to_str()),
                Some(".git" | "HEAD")
            ) {
                Err(io::Error::from(io::ErrorKind::NotFound))
            } else {
                Ok(directory_metadata.clone())
            }
        })
        .unwrap_err();
        assert!(error.to_string().contains("limit exceeded"));
    }
}
