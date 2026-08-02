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

fn resolve_existing_ancestor(path: &Path) -> Option<PathBuf> {
    let normalized = normalize_syntactic(path);
    let mut missing_components = Vec::new();
    let mut probe = normalized.as_path();

    loop {
        if let Ok(canonical) = std::fs::canonicalize(probe) {
            let mut resolved = canonical;
            for component in missing_components.iter().rev() {
                resolved.push(component);
            }
            return Some(normalize_syntactic(&resolved));
        }

        missing_components.push(probe.file_name()?.to_os_string());
        probe = probe.parent()?;
    }
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
    fn normalizes_nonexistent_path_syntactically() {
        // /nonexistent/foo/../bar -> /nonexistent/bar
        // Note: we assume /nonexistent doesn't exist.
        #[cfg(unix)]
        let root = Path::new("/");
        #[cfg(windows)]
        let root = Path::new("C:");

        let input = root.join("nonexistent").join("foo").join("..").join("bar");
        let expected = root.join("nonexistent").join("bar");

        // Ensure input doesn't exist so we trigger fallback
        assert!(std::fs::canonicalize(&input).is_err());

        let resolved = resolve_absolute_path(&input);
        assert_eq!(resolved, expected);
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

        let ancestors_after = |count: usize| -> usize {
            clear_resolve_cache();
            for i in 0..count {
                let _ = resolve_absolute_path(&deep.join(format!("sibling-{i}")));
            }
            let cache = resolve_cache().lock();
            cache
                .entries
                .keys()
                .filter(|k| !k.to_string_lossy().contains("sibling-"))
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
