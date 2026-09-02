//! Regression: path resolution must never invent a path by collapsing `..`
//! across a component that does not exist.
//!
//! `/nonexistent_root/../etc/passwd` used to resolve to `/etc/passwd`
//! because the missing-path fallback normalized `..` syntactically before
//! probing what exists. Now `..` is only applied by the filesystem (against
//! real directories); a `..` after a missing component stays literal in the
//! lenient resolver and is an error in the strict one.

#![allow(missing_docs)]

use std::path::{Path, PathBuf};

use storage_ballast_helper::core::paths::{
    PathResolveError, normalize_lexically_within, resolve_absolute_path,
    resolve_absolute_path_strict,
};

#[test]
fn parent_dir_after_a_missing_root_never_reaches_etc() {
    let bad = Path::new("/nonexistent_root/../etc/passwd");
    assert!(
        !Path::new("/nonexistent_root").exists(),
        "fixture assumption"
    );

    let resolved = resolve_absolute_path(bad);
    assert_ne!(resolved, Path::new("/etc/passwd"));
    assert!(
        !resolved.starts_with("/etc"),
        "lenient resolution must not land under /etc: {}",
        resolved.display()
    );
    assert_eq!(resolved, bad, "the missing suffix is kept verbatim");

    let strict = resolve_absolute_path_strict(bad).unwrap_err();
    assert_eq!(
        strict,
        PathResolveError::MissingComponent(PathBuf::from("/nonexistent_root/../etc"))
    );
}

#[test]
fn parent_dir_inside_an_existing_tree_still_resolves() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = std::fs::canonicalize(tmp.path()).unwrap();
    std::fs::create_dir_all(tmp.path().join("a")).unwrap();
    std::fs::create_dir_all(tmp.path().join("b")).unwrap();
    std::fs::write(tmp.path().join("b").join("file"), b"x").unwrap();

    let inside = tmp.path().join("a").join("..").join("b").join("file");
    assert_eq!(
        resolve_absolute_path(&inside),
        canonical.join("b").join("file")
    );
    assert_eq!(
        resolve_absolute_path_strict(&inside).unwrap(),
        canonical.join("b").join("file")
    );
    // A missing leaf under an existing parent is allowed by both.
    let new_leaf = tmp.path().join("a").join("..").join("b").join("new");
    assert_eq!(
        resolve_absolute_path(&new_leaf),
        canonical.join("b").join("new")
    );
    assert_eq!(
        resolve_absolute_path_strict(&new_leaf).unwrap(),
        canonical.join("b").join("new")
    );
}

#[cfg(unix)]
#[test]
fn symlink_loop_is_a_bounded_error_not_a_hang() {
    let tmp = tempfile::tempdir().unwrap();
    let first = tmp.path().join("loop-a");
    let second = tmp.path().join("loop-b");
    std::os::unix::fs::symlink(&second, &first).unwrap();
    std::os::unix::fs::symlink(&first, &second).unwrap();

    let target = first.join("child");
    let started = std::time::Instant::now();
    let strict = resolve_absolute_path_strict(&target).unwrap_err();
    assert!(
        matches!(strict, PathResolveError::Io(_)),
        "a symlink loop is reported, not resolved: {strict}"
    );
    // The lenient resolver returns *something* without following the loop
    // forever, and never claims the path is somewhere it is not.
    let lenient = resolve_absolute_path(&target);
    assert!(lenient.starts_with(std::fs::canonicalize(tmp.path()).unwrap()));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "resolution must be bounded"
    );
}

#[test]
fn lexical_normalization_refuses_escapes_from_base() {
    let base = Path::new("/var/lib/sbh");
    assert_eq!(
        normalize_lexically_within(base, Path::new("ballast/../ballast/pool")).unwrap(),
        PathBuf::from("/var/lib/sbh/ballast/pool")
    );
    assert!(matches!(
        normalize_lexically_within(base, Path::new("../../etc")),
        Err(PathResolveError::EscapesBase { .. })
    ));
    assert!(matches!(
        normalize_lexically_within(base, Path::new("/etc/passwd")),
        Err(PathResolveError::EscapesBase { .. })
    ));
}
