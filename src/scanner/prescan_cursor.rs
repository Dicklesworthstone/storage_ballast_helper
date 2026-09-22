//! A resumable cursor for the daemon's priority pre-scan.
//!
//! The pre-scan enumerates each scan root's shallow structure (depth 1-3)
//! looking for the big, obvious artifact directories — `target/`,
//! `node_modules/`, `.rch-target-*` pools. On a host whose `/data/projects`
//! holds hundreds of repositories that enumeration does not finish inside one
//! pass's budget, and until 0.6.2 it restarted at `roots[0]` in `read_dir`
//! order every single pass. The consequence measured on hz1, vmi1167313 and
//! vmi1156319 in September 2026 was a daemon that re-examined the same
//! handful of leading directories forever:
//!
//! ```text
//! [SBH-SCANNER] priority pre-scan budget reached (0.7s) — cancelling scan pass
//! [SBH-SCANNER] scan complete: 0 entries, 0 candidates, 0.7s (timed out)
//! ```
//!
//! This cursor makes the truncation *progressive* instead. It remembers the
//! root and the last depth-1 entry the previous pass finished, and the next
//! pass resumes immediately after it, wrapping to the next root (and round to
//! the first) when a root is exhausted. A tree that needs twenty passes to
//! cover therefore gets covered in twenty passes rather than never.
//!
//! Two properties make that safe:
//!
//! * **Deterministic order.** `read_dir` order is unspecified and, on some
//!   filesystems, unstable across calls. The cursor selects each root's entries
//!   by name, so "after X" names the same position on the next pass.
//!   [`ROOT_ENTRY_CAP`] bounds both selection memory and the returned page.
//! * **Forgiving resume.** The remembered entry may have been deleted (very
//!   likely — the scanner deletes things). Resuming is a `>` comparison
//!   against the sorted names, not a lookup, so a vanished entry costs
//!   nothing.
//!
//! The cursor is persisted next to the scanner index so progress survives a
//! daemon restart, and a corrupt or unreadable file simply starts over.

use std::collections::BinaryHeap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Most depth-1 entries the cursor retains and hands back for one root.
///
/// A scan root with more children than this is pathological (`/data/tmp` on
/// an agent-swarm host is the realistic worst case). Selection applies the
/// resume filter first, then retains only the smallest remaining names in a
/// bounded max-heap. Unlike collecting and sorting the entire directory before
/// truncation, memory does not grow with all the root's children. Enumeration
/// still visits the whole directory: this is a memory bound, not an I/O deadline.
pub const ROOT_ENTRY_CAP: usize = 200_000;

/// Where the pre-scan stopped, so the next pass can carry on from there.
///
/// The default value — no root, no entry — means "start at the first root",
/// which is also what a missing or corrupt checkpoint deserialises to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PrescanCursor {
    /// Root the next pass should resume in. `None` = start at `roots[0]`.
    root: Option<PathBuf>,
    /// Last depth-1 entry of `root` the previous pass finished. `None` =
    /// start at the beginning of `root`.
    after: Option<PathBuf>,
}

impl PrescanCursor {
    /// A cursor at the very beginning.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Load the checkpoint, falling back to the beginning when it is
    /// missing, unreadable or corrupt. Losing the cursor costs one repeated
    /// prefix, never correctness, so this never fails.
    #[must_use]
    pub fn load(path: &Path) -> Self {
        fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    /// Persist the checkpoint, writing through a temporary file so a crash
    /// mid-write cannot leave a truncated cursor behind.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string(self)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, text)?;
        fs::rename(&tmp, path)
    }

    /// Where the next pass will resume: the root, and the entry it will
    /// resume after (`None` = the root's first entry).
    #[must_use]
    pub fn position(&self) -> (Option<&Path>, Option<&Path>) {
        (self.root.as_deref(), self.after.as_deref())
    }

    /// A short operator-facing description of the resume point.
    #[must_use]
    pub fn describe(&self) -> String {
        match (&self.root, &self.after) {
            (None, _) => "the first scan root".to_string(),
            (Some(root), None) => format!("{}", root.display()),
            (Some(root), Some(after)) => {
                format!("{} (after {})", root.display(), after.display())
            }
        }
    }

    /// The roots to visit this pass, in order: the cursor's root first, then
    /// the rest in configured order, wrapping round.
    ///
    /// A cursor pointing at a root that is no longer configured (the operator
    /// edited `scanner.root_paths`) falls back to the configured order.
    #[must_use]
    pub fn root_order<'a>(&self, roots: &'a [PathBuf]) -> Vec<&'a Path> {
        let start = self
            .root
            .as_deref()
            .and_then(|root| roots.iter().position(|candidate| candidate == root))
            .unwrap_or(0);
        roots
            .iter()
            .cycle()
            .skip(start)
            .take(roots.len())
            .map(PathBuf::as_path)
            .collect()
    }

    /// This root's next page of depth-1 entries in deterministic order, with
    /// the prefix the previous pass already covered skipped.
    ///
    /// The resume filter applies only to the cursor's own root: every other
    /// root starts at its first entry. A full page does not prove exhaustion;
    /// callers must resume after its last entry to retrieve any later names.
    /// Enumeration errors are returned rather than hidden in a partial page.
    pub fn entries_to_visit(&self, root: &Path) -> io::Result<Vec<PathBuf>> {
        let resume_after = if self.root.as_deref() == Some(root) {
            self.after.as_deref()
        } else {
            None
        };
        let entries = fs::read_dir(root)?.map(|entry| entry.map(|entry| entry.path()));
        select_page(entries, resume_after, ROOT_ENTRY_CAP)
    }

    /// Record that `entry` (a depth-1 child of `root`) was fully examined.
    pub fn advance(&mut self, root: &Path, entry: &Path) {
        self.root = Some(root.to_path_buf());
        self.after = Some(entry.to_path_buf());
    }

    /// Record that `root` was enumerated to the end: the next pass starts at
    /// the beginning of the following root, wrapping round.
    pub fn complete_root(&mut self, roots: &[PathBuf], root: &Path) {
        self.after = None;
        if roots.is_empty() {
            self.root = None;
            return;
        }
        let next = roots
            .iter()
            .position(|candidate| candidate == root)
            .map_or(0, |index| (index + 1) % roots.len());
        self.root = Some(roots[next].clone());
    }

    /// Reset to the beginning (a forced/operator scan wants the whole tree).
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Retain the lexicographically smallest `capacity` names after the cursor,
/// independent of enumeration order. The largest retained name is the heap
/// root, so a smaller incoming name replaces it without ever growing beyond
/// the page capacity. Converting the heap to sorted order reuses its allocation.
fn select_page(
    entries: impl IntoIterator<Item = io::Result<PathBuf>>,
    after: Option<&Path>,
    capacity: usize,
) -> io::Result<Vec<PathBuf>> {
    let mut selected = BinaryHeap::with_capacity(capacity);
    for entry in entries {
        let path = entry?;
        if capacity == 0 || after.is_some_and(|after| path.as_path() <= after) {
            continue;
        }
        if selected.len() < capacity {
            selected.push(path);
        } else if let Some(mut largest) = selected.peek_mut()
            && path < *largest
        {
            *largest = path;
        }
    }
    Ok(selected.into_sorted_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn make_dirs(root: &Path, names: &[&str]) {
        for name in names {
            fs::create_dir_all(root.join(name)).expect("mkdir");
        }
    }

    #[test]
    fn a_fresh_cursor_starts_at_the_first_root_and_the_first_entry() {
        let dir = tempdir();
        make_dirs(dir.path(), &["b", "a", "c"]);
        let cursor = PrescanCursor::new();
        let roots = vec![dir.path().to_path_buf(), PathBuf::from("/other")];
        assert_eq!(cursor.root_order(&roots)[0], dir.path());
        let entries = cursor.entries_to_visit(dir.path()).expect("read");
        assert_eq!(
            entries,
            vec![
                dir.path().join("a"),
                dir.path().join("b"),
                dir.path().join("c")
            ],
            "entries must be sorted so 'after' names a stable position"
        );
    }

    #[test]
    fn resume_skips_exactly_the_prefix_already_covered() {
        let dir = tempdir();
        make_dirs(dir.path(), &["a", "b", "c", "d"]);
        let mut cursor = PrescanCursor::new();
        cursor.advance(dir.path(), &dir.path().join("b"));
        let entries = cursor.entries_to_visit(dir.path()).expect("read");
        assert_eq!(entries, vec![dir.path().join("c"), dir.path().join("d")]);
    }

    #[test]
    fn a_deleted_resume_point_does_not_strand_the_cursor() {
        let dir = tempdir();
        make_dirs(dir.path(), &["a", "c", "d"]);
        let mut cursor = PrescanCursor::new();
        // `b` was the last entry examined and has since been reclaimed.
        cursor.advance(dir.path(), &dir.path().join("b"));
        let entries = cursor.entries_to_visit(dir.path()).expect("read");
        assert_eq!(entries, vec![dir.path().join("c"), dir.path().join("d")]);
    }

    #[test]
    fn the_resume_filter_applies_only_to_the_cursors_own_root() {
        let a = tempdir();
        let b = tempdir();
        make_dirs(a.path(), &["x", "y"]);
        make_dirs(b.path(), &["x", "y"]);
        let mut cursor = PrescanCursor::new();
        cursor.advance(a.path(), &a.path().join("x"));
        assert_eq!(
            cursor.entries_to_visit(a.path()).expect("read"),
            vec![a.path().join("y")]
        );
        assert_eq!(
            cursor.entries_to_visit(b.path()).expect("read"),
            vec![b.path().join("x"), b.path().join("y")],
            "a different root starts at its beginning"
        );
    }

    #[test]
    fn root_order_starts_at_the_cursor_and_wraps() {
        let roots = vec![
            PathBuf::from("/one"),
            PathBuf::from("/two"),
            PathBuf::from("/three"),
        ];
        let mut cursor = PrescanCursor::new();
        cursor.advance(Path::new("/two"), Path::new("/two/x"));
        assert_eq!(
            cursor.root_order(&roots),
            vec![Path::new("/two"), Path::new("/three"), Path::new("/one")]
        );
        // A root that is no longer configured falls back to the front.
        cursor.advance(Path::new("/gone"), Path::new("/gone/x"));
        assert_eq!(cursor.root_order(&roots)[0], Path::new("/one"));
    }

    #[test]
    fn completing_a_root_moves_to_the_next_and_rewinds() {
        let roots = vec![PathBuf::from("/one"), PathBuf::from("/two")];
        let mut cursor = PrescanCursor::new();
        cursor.advance(Path::new("/one"), Path::new("/one/z"));
        cursor.complete_root(&roots, Path::new("/one"));
        assert_eq!(cursor.position(), (Some(Path::new("/two")), None));
        cursor.complete_root(&roots, Path::new("/two"));
        assert_eq!(
            cursor.position(),
            (Some(Path::new("/one")), None),
            "the last root wraps to the first"
        );
    }

    /// The property the fleet needed: a root far larger than one pass can
    /// enumerate is still covered completely, across successive passes,
    /// with no entry visited twice and none skipped.
    #[test]
    fn successive_truncated_passes_cover_a_large_root_exactly_once() {
        let dir = tempdir();
        let names: Vec<String> = (0..250).map(|i| format!("repo-{i:04}")).collect();
        make_dirs(
            dir.path(),
            &names.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        let roots = vec![dir.path().to_path_buf()];

        let mut cursor = PrescanCursor::new();
        let mut seen: Vec<PathBuf> = Vec::new();
        let per_pass = 7; // a tiny budget: 7 entries fit in one pass
        let mut passes = 0;
        while passes < 100 {
            passes += 1;
            let entries = cursor.entries_to_visit(dir.path()).expect("read");
            if entries.is_empty() {
                cursor.complete_root(&roots, dir.path());
                break;
            }
            for entry in entries.iter().take(per_pass) {
                seen.push(entry.clone());
                cursor.advance(dir.path(), entry);
            }
            if entries.len() <= per_pass {
                cursor.complete_root(&roots, dir.path());
                break;
            }
        }

        assert_eq!(seen.len(), 250, "every entry visited, in {passes} passes");
        let mut unique = seen.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), 250, "no entry visited twice");
        assert!(passes > 1, "the point of the test is multi-pass coverage");
    }

    #[test]
    fn the_checkpoint_round_trips_and_a_corrupt_one_starts_over() {
        let dir = tempdir();
        let path = dir.path().join("state").join("prescan-cursor.json");
        let mut cursor = PrescanCursor::new();
        cursor.advance(Path::new("/data/projects"), Path::new("/data/projects/zed"));
        cursor.save(&path).expect("save");
        assert_eq!(PrescanCursor::load(&path), cursor);

        fs::write(&path, "{not json").expect("write");
        assert_eq!(PrescanCursor::load(&path), PrescanCursor::new());
        assert_eq!(
            PrescanCursor::load(&dir.path().join("absent.json")),
            PrescanCursor::new()
        );
    }

    #[test]
    fn reset_returns_to_the_beginning() {
        let mut cursor = PrescanCursor::new();
        cursor.advance(Path::new("/a"), Path::new("/a/b"));
        cursor.reset();
        assert_eq!(cursor, PrescanCursor::new());
        assert_eq!(cursor.describe(), "the first scan root");
    }

    #[test]
    fn bounded_selection_matches_a_full_sort_for_adversarial_orders() {
        let names: Vec<PathBuf> = (0..257)
            .map(|i| PathBuf::from(format!("/root/item-{i:04}")))
            .collect();
        for reverse in [false, true] {
            // 73 is coprime to 257: every name is visited, in a non-sorted order.
            let mut shuffled: Vec<PathBuf> = (0..257)
                .map(|i| names[(i * 73) % 257].clone())
                .collect();
            if reverse {
                shuffled.reverse();
            }
            for after in [None, Some(Path::new("/root/item-0128"))] {
                for cap in [0, 1, 2, 17, 257, 300] {
                    let expected: Vec<PathBuf> = names
                        .iter()
                        .filter(|path| after.is_none_or(|after| path.as_path() > after))
                        .take(cap)
                        .cloned()
                        .collect();
                    let actual = select_page(shuffled.iter().cloned().map(Ok), after, cap)
                        .expect("selection");
                    assert_eq!(actual, expected, "cap={cap} reverse={reverse} after={after:?}");
                }
            }
        }
    }

    #[test]
    fn entries_discovered_late_can_replace_every_initial_heap_member() {
        let paths = (0..10_000)
            .rev()
            .map(|i| Ok(PathBuf::from(format!("/root/{i:05}"))));
        let actual = select_page(paths, None, 3).unwrap();
        assert_eq!(
            actual,
            ["/root/00000", "/root/00001", "/root/00002"].map(PathBuf::from)
        );
    }

    #[test]
    fn resume_filter_runs_before_the_page_cap() {
        let paths = (0..10_000).map(|i| Ok(PathBuf::from(format!("/root/{i:05}"))));
        let actual = select_page(paths, Some(Path::new("/root/09995")), 3).unwrap();
        assert_eq!(
            actual,
            ["/root/09996", "/root/09997", "/root/09998"].map(PathBuf::from)
        );
    }

    #[test]
    fn changing_enumeration_order_between_pages_neither_skips_nor_repeats_names() {
        let mut after: Option<PathBuf> = None;
        let mut seen = Vec::new();
        for pass in 0..20 {
            let mut names: Vec<PathBuf> = (0..41)
                .map(|i| PathBuf::from(format!("/root/item-{i:04}")))
                .collect();
            names.rotate_left((pass * 13) % 41);
            if pass % 2 == 0 {
                names.reverse();
            }
            let page = select_page(names.into_iter().map(Ok), after.as_deref(), 3).unwrap();
            if page.is_empty() {
                break;
            }
            after = page.last().cloned();
            seen.extend(page);
        }
        let expected: Vec<PathBuf> = (0..41)
            .map(|i| PathBuf::from(format!("/root/item-{i:04}")))
            .collect();
        assert_eq!(seen, expected);
    }

    #[test]
    fn a_mid_enumeration_error_does_not_return_an_apparently_complete_page() {
        let entries = [
            Ok(PathBuf::from("/root/a")),
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "enumeration failed")),
            Ok(PathBuf::from("/root/b")),
        ];
        let error = select_page(entries, None, 1).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[cfg(unix)]
    #[test]
    fn byte_exact_names_are_ordered_without_lossy_conversion() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        // Synthetic names exercise Unix path ordering without requiring the
        // host filesystem to admit non-UTF-8 names (APFS need not do so).
        let names = [b"/root/\xff".as_slice(), b"/root/a", b"/root/\xfe"];
        let paths = names.map(|bytes| PathBuf::from(OsString::from_vec(bytes.to_vec())));
        let page = select_page(paths.into_iter().map(Ok), Some(Path::new("/root/a")), 1)
            .unwrap();
        assert_eq!(
            page,
            vec![PathBuf::from(OsString::from_vec(b"/root/\xfe".to_vec()))]
        );
    }
}
