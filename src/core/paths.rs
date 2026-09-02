//! Shared path manipulation utilities.

use std::collections::HashMap;
use std::env;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// How long a memoized directory resolution stays trusted.
///
/// `canonicalize` results can only change if a symlink along the chain is
/// rewritten, so a short TTL bounds staleness while still collapsing the
/// per-descendant re-resolution that dominates a scan pass.
const RESOLVE_CACHE_TTL: Duration = Duration::from_secs(30);

/// Upper bound on memoized entries before the cache is dropped wholesale.
/// Scans walk millions of leaves but only thousands of distinct directories,
/// so this is sized for the ancestor set, not the leaf set.
const RESOLVE_CACHE_MAX_ENTRIES: usize = 32_768;

struct ResolveCache {
    entries: HashMap<PathBuf, PathBuf>,
    seeded_at: Instant,
}

static RESOLVE_CACHE: OnceLock<parking_lot::Mutex<ResolveCache>> = OnceLock::new();

fn resolve_cache() -> &'static parking_lot::Mutex<ResolveCache> {
    RESOLVE_CACHE.get_or_init(|| {
        parking_lot::Mutex::new(ResolveCache {
            entries: HashMap::new(),
            seeded_at: Instant::now(),
        })
    })
}

fn cache_lookup(key: &Path) -> Option<PathBuf> {
    let mut cache = resolve_cache().lock();
    if cache.seeded_at.elapsed() > RESOLVE_CACHE_TTL {
        cache.entries.clear();
        cache.seeded_at = Instant::now();
        return None;
    }
    cache.entries.get(key).cloned()
}

fn cache_store(key: &Path, value: &Path) {
    let mut cache = resolve_cache().lock();
    if cache.entries.len() >= RESOLVE_CACHE_MAX_ENTRIES {
        cache.entries.clear();
        cache.seeded_at = Instant::now();
    }
    cache.entries.insert(key.to_path_buf(), value.to_path_buf());
}

/// Drop every memoized resolution. Exposed for tests that mutate symlinks
/// faster than [`RESOLVE_CACHE_TTL`].
pub fn clear_resolve_cache() {
    let mut cache = resolve_cache().lock();
    cache.entries.clear();
    cache.seeded_at = Instant::now();
}

/// Resolve a path to an absolute, normalized path.
///
/// If `fs::canonicalize` succeeds (path exists), it is used to resolve symlinks
/// and normalize components.
///
/// If it fails (e.g. path does not exist), the path is made absolute relative
/// to CWD and `..`/`.` components are resolved syntactically.
///
/// Resolutions are memoized per ancestor directory. `canonicalize` issues one
/// `readlink` syscall per path component, so resolving every entry of a deep
/// tree independently costs O(depth) syscalls per entry and re-resolves the
/// same ancestors once per descendant. Walking the chain through the cache
/// makes that O(1) amortized once the ancestors are warm.
pub fn resolve_absolute_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir().map_or_else(|_| path.to_path_buf(), |cwd| cwd.join(path))
    };

    resolve_via_parent(&absolute).unwrap_or_else(|| resolve_uncached(&absolute))
}

/// Resolve an *ancestor* directory, memoizing the result.
///
/// Only ancestors are cached. A scan's leaf paths are essentially all distinct,
/// so caching them costs a hash and an allocation each for a hit rate near
/// zero, while the directories above them are shared by every descendant and
/// are where the entire win lives.
fn resolve_ancestor_cached(dir: &Path) -> PathBuf {
    if let Some(hit) = cache_lookup(dir) {
        return hit;
    }

    let resolved = resolve_via_parent(dir).unwrap_or_else(|| resolve_uncached(dir));
    cache_store(dir, &resolved);
    resolved
}

/// Resolve by canonicalizing the parent (through the cache) and appending the
/// final component, avoiding a full per-component `realpath` walk.
///
/// Returns `None` when that shortcut cannot preserve `canonicalize` semantics,
/// in which case the caller falls back to the uncached path.
fn resolve_via_parent(absolute: &Path) -> Option<PathBuf> {
    // `realpath` resolves symlinks *before* applying `..`, which cannot be
    // reproduced component-wise. Leave those to the slow path.
    if absolute
        .components()
        .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    {
        return None;
    }

    let parent = absolute.parent()?;
    let name = absolute.file_name()?;
    let candidate = resolve_ancestor_cached(parent).join(name);

    match std::fs::symlink_metadata(&candidate) {
        // The leaf itself is a link: only a full canonicalize is correct.
        Ok(meta) if meta.file_type().is_symlink() => None,
        // Exists and is not a link, or does not exist yet. Both match the
        // uncached behaviour, since the parent is already canonical.
        _ => Some(candidate),
    }
}

fn resolve_uncached(absolute: &Path) -> PathBuf {
    // Try filesystem resolution first (handles symlinks).
    if let Ok(canonical) = std::fs::canonicalize(absolute) {
        return canonical;
    }

    if let Some(resolved) = resolve_existing_ancestor(absolute) {
        return resolved;
    }

    // Fallback: syntactic normalization.
    normalize_syntactic(absolute)
}

/// Resolve the longest existing ancestor with `canonicalize` and append the
/// missing suffix verbatim (minus `.` components).
///
/// `..` is only ever applied by `canonicalize`, i.e. against directories
/// that exist. A `..` inside the missing suffix is kept literally: collapsing
/// it syntactically would let `/nonexistent_root/../etc/passwd` resolve to
/// `/etc/passwd`, a path the operator never named. A literal `..` in the
/// result is also visibly unnormalized, so containment checks
/// (`starts_with(root)`) treat such paths as outside every root.
fn resolve_existing_ancestor(path: &Path) -> Option<PathBuf> {
    let mut missing_components = Vec::new();
    let mut probe = path;

    loop {
        if let Ok(canonical) = std::fs::canonicalize(probe) {
            let mut resolved = canonical;
            for component in missing_components.iter().rev() {
                resolved.push(component);
            }
            return Some(resolved);
        }

        // `Path::file_name` is `None` for a trailing `..`; look at the last
        // component directly so `..` is carried along literally.
        match probe.components().next_back()? {
            Component::Normal(name) => missing_components.push(name.to_os_string()),
            Component::ParentDir => missing_components.push("..".into()),
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => return None,
        }
        probe = probe.parent()?;
    }
}

/// Why a strict resolution or a base-bounded normalization was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathResolveError {
    /// A component that has to be traversed does not exist.
    MissingComponent(PathBuf),
    /// A `..` would be applied to a component that does not exist.
    ParentOfMissing(PathBuf),
    /// The path leaves `base` after lexical normalization.
    EscapesBase {
        /// The directory the path had to stay inside.
        base: PathBuf,
        /// The path as given.
        path: PathBuf,
    },
    /// The filesystem refused to resolve the path (symlink loop, EACCES, ...).
    Io(String),
}

impl std::fmt::Display for PathResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingComponent(path) => {
                write!(f, "path component does not exist: {}", path.display())
            }
            Self::ParentOfMissing(path) => write!(
                f,
                "`..` cannot be resolved through a component that does not exist: {}",
                path.display()
            ),
            Self::EscapesBase { base, path } => write!(
                f,
                "{} escapes its base directory {}",
                path.display(),
                base.display()
            ),
            Self::Io(details) => write!(f, "path resolution failed: {details}"),
        }
    }
}

impl std::error::Error for PathResolveError {}

/// Strict resolution: a wrong answer is worse than no answer.
///
/// Every component that must be traversed exists, `..` is only applied by
/// the filesystem, and only the final component may be absent. Use it for
/// protection comparisons and targets that must be inside a known tree.
pub fn resolve_absolute_path_strict(path: &Path) -> Result<PathBuf, PathResolveError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|e| PathResolveError::Io(e.to_string()))?
            .join(path)
    };
    match std::fs::canonicalize(&absolute) {
        Ok(canonical) => Ok(canonical),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // The leaf may be absent, its parent chain may not.
            let parent = absolute
                .parent()
                .ok_or_else(|| PathResolveError::MissingComponent(absolute.clone()))?;
            match absolute.components().next_back() {
                Some(Component::Normal(name)) => match std::fs::canonicalize(parent) {
                    Ok(canonical_parent) => Ok(canonical_parent.join(name)),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        Err(PathResolveError::MissingComponent(parent.to_path_buf()))
                    }
                    Err(err) => Err(PathResolveError::Io(err.to_string())),
                },
                Some(Component::ParentDir | Component::CurDir) => {
                    Err(PathResolveError::ParentOfMissing(absolute.clone()))
                }
                _ => Err(PathResolveError::MissingComponent(absolute.clone())),
            }
        }
        Err(err) => Err(PathResolveError::Io(err.to_string())),
    }
}

/// Normalize `path` lexically and require that it stays inside `base`.
///
/// No filesystem access: `.` is dropped, `..` pops the previous component
/// but never past `base`. For targets that may not exist yet (a ballast
/// dir, a lease target) where the only invariant is "under this tree".
pub fn normalize_lexically_within(base: &Path, path: &Path) -> Result<PathBuf, PathResolveError> {
    let base_components: Vec<Component<'_>> = base.components().collect();
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let mut components: Vec<Component<'_>> = Vec::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if components.len() <= base_components.len()
                    || !matches!(components.last(), Some(Component::Normal(_)))
                {
                    return Err(PathResolveError::EscapesBase {
                        base: base.to_path_buf(),
                        path: path.to_path_buf(),
                    });
                }
                components.pop();
            }
            other => components.push(other),
        }
    }
    let normalized: PathBuf = components.iter().collect();
    if normalized.starts_with(base) {
        Ok(normalized)
    } else {
        Err(PathResolveError::EscapesBase {
            base: base.to_path_buf(),
            path: path.to_path_buf(),
        })
    }
}

/// Keep the tail of a display string within `max_len` bytes without ever
/// slicing inside a UTF-8 scalar, then align to the next `/` so a path is not
/// cut mid-component. Shared by the TUI and the CLI tables.
#[must_use]
pub fn truncate_display_tail(text: &str, max_len: usize) -> &str {
    if text.len() <= max_len {
        return text;
    }
    let start = text.ceil_char_boundary(text.len() - max_len);
    let tail = &text[start..];
    tail.find('/').map_or(tail, |idx| &tail[idx..])
}

fn normalize_syntactic(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(..) | Component::RootDir | Component::Normal(_) => {
                components.push(component);
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if let Some(Component::Normal(_)) = components.last() {
                    components.pop();
                }
            }
        }
    }
    components.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `RESOLVE_CACHE` is process-global, so tests that clear it or inspect its
    /// contents must not run concurrently with one another.
    static CACHE_TEST_GUARD: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[test]
    fn resolves_existing_path_canonically() {
        let cwd = env::current_dir().unwrap();
        let resolved = resolve_absolute_path(Path::new("."));
        assert_eq!(resolved, std::fs::canonicalize(&cwd).unwrap());
    }

    #[test]
    fn never_collapses_parent_dir_across_a_missing_component() {
        // /nonexistent/foo/../bar: `foo` does not exist, so `..` has nothing
        // real to climb out of. The syntactic answer (/nonexistent/bar) is a
        // path the caller never named; keep the `..` literal instead.
        #[cfg(unix)]
        let root = Path::new("/");
        #[cfg(windows)]
        let root = Path::new("C:");

        let input = root.join("nonexistent").join("foo").join("..").join("bar");
        assert!(std::fs::canonicalize(&input).is_err());

        let resolved = resolve_absolute_path(&input);
        assert_eq!(resolved, input, "the missing suffix is appended verbatim");
        assert!(!resolved.starts_with(root.join("nonexistent").join("bar")));

        // `.` in the missing suffix is dropped; a missing leaf under an existing
        // parent is fine.
        let tmp = tempfile::tempdir().unwrap();
        let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
        assert_eq!(
            resolve_absolute_path(&tmp.path().join(".").join("missing").join(".").join("leaf")),
            canonical_tmp.join("missing").join("leaf")
        );
        // `..` against an existing directory is resolved by the filesystem.
        std::fs::create_dir(tmp.path().join("real")).unwrap();
        assert_eq!(
            resolve_absolute_path(&tmp.path().join("real").join("..").join("gone")),
            canonical_tmp.join("gone")
        );
    }

    #[test]
    fn strict_resolution_refuses_missing_traversal_and_parent_of_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
        std::fs::create_dir(tmp.path().join("real")).unwrap();

        // Existing path, and a missing leaf under an existing parent, are fine.
        assert_eq!(
            resolve_absolute_path_strict(&tmp.path().join("real")).unwrap(),
            canonical_tmp.join("real")
        );
        assert_eq!(
            resolve_absolute_path_strict(&tmp.path().join("real").join("new-file")).unwrap(),
            canonical_tmp.join("real").join("new-file")
        );
        // `..` through an existing dir is resolved by the filesystem.
        assert_eq!(
            resolve_absolute_path_strict(&tmp.path().join("real").join("..").join("new")).unwrap(),
            canonical_tmp.join("new")
        );
        // A missing directory that must be traversed is an error...
        let err =
            resolve_absolute_path_strict(&tmp.path().join("missing").join("leaf")).unwrap_err();
        assert_eq!(
            err,
            PathResolveError::MissingComponent(tmp.path().join("missing"))
        );
        // ...and `..` right after a missing component is never collapsed.
        let err = resolve_absolute_path_strict(&tmp.path().join("missing").join("..")).unwrap_err();
        assert!(matches!(err, PathResolveError::ParentOfMissing(_)), "{err}");
        assert!(matches!(
            resolve_absolute_path_strict(Path::new("/nonexistent_root/../etc/passwd")),
            Err(PathResolveError::MissingComponent(_))
        ));
    }

    #[test]
    fn lexical_normalization_stays_within_base() {
        let base = Path::new("/data/.sbh");
        assert_eq!(
            normalize_lexically_within(base, Path::new("ballast/./pool")).unwrap(),
            PathBuf::from("/data/.sbh/ballast/pool")
        );
        assert_eq!(
            normalize_lexically_within(base, Path::new("ballast/../lease")).unwrap(),
            PathBuf::from("/data/.sbh/lease")
        );
        assert_eq!(
            normalize_lexically_within(base, Path::new("/data/.sbh/x")).unwrap(),
            PathBuf::from("/data/.sbh/x")
        );
        for escape in [
            "../../etc",
            "ballast/../../etc/passwd",
            "/etc/passwd",
            "../.sbh/x",
        ] {
            assert!(
                matches!(
                    normalize_lexically_within(base, Path::new(escape)),
                    Err(PathResolveError::EscapesBase { .. })
                ),
                "{escape} must be refused"
            );
        }
    }

    #[test]
    fn display_tail_never_splits_a_scalar() {
        // 'é' is two bytes; a byte-based cut at len-1 would land inside it.
        // One byte cannot hold it, two can.
        assert_eq!(truncate_display_tail("aé", 1), "");
        assert_eq!(truncate_display_tail("aé", 2), "é");
        assert_eq!(truncate_display_tail("/short", 40), "/short");
        let long = "/very/long/déep/nested/project/target/debug/build/artifact";
        let tail = truncate_display_tail(long, 20);
        assert!(tail.starts_with('/'), "{tail}");
        assert!(long.ends_with(tail));
        assert!(tail.len() <= 20 + "/nested".len());
    }

    #[cfg(unix)]
    #[test]
    fn resolves_nonexistent_child_under_existing_symlink_parent() {
        let _guard = CACHE_TEST_GUARD.lock();
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let alias = tmp.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();

        clear_resolve_cache();
        let resolved = resolve_absolute_path(&alias.join("missing").join("child"));
        let expected_parent = std::fs::canonicalize(&real).unwrap();

        assert_eq!(resolved, expected_parent.join("missing").join("child"));
    }

    /// The memoized walk must agree with the original per-call `canonicalize`
    /// implementation for every path shape the scanner feeds it.
    #[cfg(unix)]
    #[test]
    fn cached_resolution_matches_uncached_for_all_shapes() {
        let _guard = CACHE_TEST_GUARD.lock();
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();

        let deep = root.join("a").join("b").join("c");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("leaf.txt"), b"x").unwrap();

        // symlinked directory in the middle of a chain
        let dir_alias = root.join("a").join("b_alias");
        std::os::unix::fs::symlink(&deep, &dir_alias).unwrap();

        // symlinked leaf file
        let file_alias = root.join("a").join("leaf_alias");
        std::os::unix::fs::symlink(deep.join("leaf.txt"), &file_alias).unwrap();

        // dangling symlink
        let dangling = root.join("a").join("dangling");
        std::os::unix::fs::symlink(root.join("nope"), &dangling).unwrap();

        let cases = vec![
            root.join("a"),
            deep.clone(),
            deep.join("leaf.txt"),
            deep.join("missing-child"),
            dir_alias.clone(),
            dir_alias.join("leaf.txt"),
            file_alias,
            dangling,
            root.join("a").join("b").join("..").join("b").join("c"),
            root.join("a").join(".").join("b"),
            root.join("totally").join("absent").join("chain"),
        ];

        for case in cases {
            clear_resolve_cache();
            let expected = resolve_uncached(&case);

            clear_resolve_cache();
            let cold = resolve_absolute_path(&case);
            // second call exercises the warm cache path
            let warm = resolve_absolute_path(&case);

            assert_eq!(cold, expected, "cold mismatch for {}", case.display());
            assert_eq!(warm, expected, "warm mismatch for {}", case.display());
        }
    }

    /// Sibling leaves under a shared ancestor must not each re-resolve the
    /// ancestor chain. This is the regression that pinned sbh's scanner thread
    /// at ~100% CPU with ~10k failing `readlink` calls per second.
    #[cfg(unix)]
    #[test]
    fn siblings_reuse_memoized_ancestors() {
        let _guard = CACHE_TEST_GUARD.lock();
        let tmp = tempfile::tempdir().unwrap();
        let deep = tmp.path().join("x").join("y").join("z");
        std::fs::create_dir_all(&deep).unwrap();
        // Canonical form of `deep`, for identifying its ancestor chain in the
        // cache below (keys are canonicalized, tmp may traverse symlinks).
        let canonical_deep = resolve_uncached(&deep);

        let ancestors_after = |count: usize| -> usize {
            clear_resolve_cache();
            for i in 0..count {
                let _ = resolve_absolute_path(&deep.join(format!("sibling-{i}")));
            }
            let cache = resolve_cache().lock();
            // Count only ancestors of OUR path: the cache is process-global and
            // other tests running in parallel insert their own ancestor chains
            // between our two measurements, so counting everything is flaky.
            cache
                .entries
                .keys()
                .filter(|k| canonical_deep.starts_with(k))
                .count()
        };

        // The invariant that matters: ancestor resolutions are shared, so their
        // count is a function of tree depth only and does not grow with the
        // number of siblings walked. (Absolute count varies with how deep the
        // platform's temp dir sits, so compare rather than hard-code.)
        let few = ancestors_after(8);
        let many = ancestors_after(256);
        assert_eq!(
            few, many,
            "ancestor entries grew with sibling count ({few} -> {many}); \
             each sibling is re-resolving the chain"
        );

        // Leaves must not be memoized at all: they are distinct per entry, so
        // caching them is allocation overhead for a hit rate near zero.
        // Scope the guard so the lock is released before the assertion, which
        // would otherwise hold it across a potential panic.
        let leaf_entries = {
            let cache = resolve_cache().lock();
            cache
                .entries
                .keys()
                .filter(|k| k.to_string_lossy().contains("sibling-"))
                .count()
        };
        assert_eq!(leaf_entries, 0, "leaf paths should not be cached");
    }

    #[cfg(unix)]
    #[test]
    fn clear_cache_picks_up_retargeted_symlink() {
        let _guard = CACHE_TEST_GUARD.lock();
        let tmp = tempfile::tempdir().unwrap();
        let first = tmp.path().join("first");
        let second = tmp.path().join("second");
        std::fs::create_dir(&first).unwrap();
        std::fs::create_dir(&second).unwrap();
        let alias = tmp.path().join("alias");
        std::os::unix::fs::symlink(&first, &alias).unwrap();

        clear_resolve_cache();
        assert_eq!(
            resolve_absolute_path(&alias),
            std::fs::canonicalize(&first).unwrap()
        );

        std::fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(&second, &alias).unwrap();

        clear_resolve_cache();
        assert_eq!(
            resolve_absolute_path(&alias),
            std::fs::canonicalize(&second).unwrap()
        );
    }

    #[test]
    fn handles_parent_at_root() {
        #[cfg(unix)]
        {
            let input = Path::new("/../foo");
            let resolved = normalize_syntactic(input);
            assert_eq!(resolved, Path::new("/foo"));
        }
    }
}
