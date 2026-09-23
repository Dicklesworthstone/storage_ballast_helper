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
//! The cursor remembers completed work separately for every unfinished root.
//! Consuming a capped page is not end-of-root: the next visit resumes after
//! that page, even when another mount was scanned in between or the daemon
//! restarted. A completed page gives the next configured root a turn.
//!
//! * **Deterministic order.** Selection retains the smallest names after the
//!   resume point regardless of `read_dir` order. [`ROOT_ENTRY_CAP`] bounds
//!   selection memory as well as the returned page.
//! * **Forgiving resume.** A deleted resume point costs nothing: selection
//!   uses `>` rather than looking up the remembered entry.
//! * **Observed completion.** Only a fully consumed, successfully enumerated
//!   final page clears that root's continuation. An unreadable root can yield
//!   to the next root without losing its previous progress.
//!
//! Checkpoints retain the original `root`/`after` fields and add continuations
//! for other unfinished roots. Missing or corrupt checkpoints start over.

use std::collections::{BTreeMap, BinaryHeap};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

/// Most depth-1 entries the cursor retains and hands back for one root.
///
/// Selection applies the resume filter first, then retains only the smallest
/// remaining names in a bounded max-heap. Enumeration still visits the whole
/// directory: this is a memory bound, not an I/O deadline.
pub const ROOT_ENTRY_CAP: usize = 200_000;

/// Evidence about the most recently selected page. This is not durable work:
/// reading names does not mean the caller has examined them.
#[derive(Debug, Clone)]
struct PageProof {
    root: PathBuf,
    last: Option<PathBuf>,
    exhausted: bool,
}

/// Where the pre-scan stopped, so the next pass can carry on from there.
///
/// The default value — no root, no entry — means "start at the first root",
/// which is also what a missing or corrupt checkpoint deserialises to.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PrescanCursor {
    /// Root the next pass should resume in. `None` = start at `roots[0]`.
    root: Option<PathBuf>,
    /// Last fully examined depth-1 entry in the selected root.
    after: Option<PathBuf>,
    /// Resume points survive rotation through a different request's mounts.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    continuations: BTreeMap<PathBuf, PathBuf>,
    /// Interior bookkeeping preserves the read-only page-selection API and
    /// Send + Sync. A clone owns its own proof, so a budget rewind is isolated.
    #[serde(skip)]
    page: Mutex<Option<PageProof>>,
}

impl Clone for PrescanCursor {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
            after: self.after.clone(),
            continuations: self.continuations.clone(),
            page: Mutex::new(self.page_proof().clone()),
        }
    }
}

// Equality describes durable progress, not which names were last read. The
// daemon uses it to decide whether a checkpoint write is necessary.
impl PartialEq for PrescanCursor {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
            && self.after == other.after
            && self.continuations == other.continuations
    }
}

impl Eq for PrescanCursor {}

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
    /// A request may contain only one mount's roots. Other mounts retain
    /// their continuations; absence from this request is not a config reset.
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

    fn page_proof(&self) -> MutexGuard<'_, Option<PageProof>> {
        self.page.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn resume_after(&self, root: &Path) -> Option<&Path> {
        if self.root.as_deref() == Some(root) {
            self.after.as_deref()
        } else {
            self.continuations.get(root).map(PathBuf::as_path)
        }
    }

    fn remember_current(&mut self) {
        if let (Some(root), Some(after)) = (&self.root, &self.after) {
            self.continuations.insert(root.clone(), after.clone());
        }
    }

    /// This root's next page of depth-1 entries in deterministic order, with
    /// previously examined names skipped. A never-visited root starts at its
    /// beginning. Selection itself does not advance the durable cursor.
    ///
    /// After examining entries with `advance`, call `complete_root` as usual:
    /// it distinguishes a capped page from genuine end-of-root. Enumeration
    /// errors are returned and do not erase the root's existing continuation.
    pub fn entries_to_visit(&self, root: &Path) -> io::Result<Vec<PathBuf>> {
        self.entries_with_capacity(root, ROOT_ENTRY_CAP)
    }

    fn entries_with_capacity(&self, root: &Path, capacity: usize) -> io::Result<Vec<PathBuf>> {
        // Invalidate any earlier successful observation before opening the
        // directory. A read failure is not evidence that its tail is empty.
        *self.page_proof() = Some(PageProof {
            root: root.to_path_buf(),
            last: None,
            exhausted: false,
        });
        let entries = fs::read_dir(root)?.map(|entry| entry.map(|entry| entry.path()));
        let (paths, has_more) = select_page_with_tail(entries, self.resume_after(root), capacity)?;
        *self.page_proof() = Some(PageProof {
            root: root.to_path_buf(),
            last: paths.last().cloned(),
            exhausted: !has_more,
        });
        Ok(paths)
    }

    /// Record that `entry` (a depth-1 child of `root`) was fully examined.
    pub fn advance(&mut self, root: &Path, entry: &Path) {
        self.remember_current();
        self.root = Some(root.to_path_buf());
        self.after = Some(entry.to_path_buf());
    }

    /// Finish the selected page and give the following root a turn.
    ///
    /// A capped or partially consumed page retains its continuation. Only a
    /// fully consumed final page clears it. This also preserves progress when
    /// the daemon calls this method to yield after an enumeration error.
    ///
    /// Without a preceding page selection this remains an explicit statement
    /// of root completion, preserving the original cursor API.
    pub fn complete_root(&mut self, roots: &[PathBuf], root: &Path) {
        let proof = self.page_proof().take();
        let retain = proof.as_ref().is_some_and(|page| {
            page.root == root
                && (!page.exhausted
                    || page.last.as_deref().is_some_and(|last| self.resume_after(root) != Some(last)))
        });
        self.remember_current();
        if !retain {
            self.continuations.remove(root);
        }
        if roots.is_empty() {
            self.reset();
            return;
        }
        let next = roots
            .iter()
            .position(|candidate| candidate == root)
            .map_or(0, |index| (index + 1) % roots.len());
        self.root = Some(roots[next].clone());
        self.after = self.continuations.get(&roots[next]).cloned();
    }

    /// Reset every root to the beginning for an operator/forced scan.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Select a bounded page and report whether successful enumeration saw more
/// eligible names. An exactly-full final page is distinguishable from a cap.
fn select_page_with_tail(
    entries: impl IntoIterator<Item = io::Result<PathBuf>>,
    after: Option<&Path>,
    capacity: usize,
) -> io::Result<(Vec<PathBuf>, bool)> {
    let mut selected = BinaryHeap::with_capacity(capacity);
    let mut has_more = false;
    for entry in entries {
        let path = entry?;
        if after.is_some_and(|after| path.as_path() <= after) {
            continue;
        }
        if selected.len() < capacity {
            selected.push(path);
        } else {
            has_more = true;
            if let Some(mut largest) = selected.peek_mut()
                && path < *largest
            {
                *largest = path;
            }
        }
    }
    Ok((selected.into_sorted_vec(), has_more))
}

#[cfg(test)]
fn select_page(
    entries: impl IntoIterator<Item = io::Result<PathBuf>>,
    after: Option<&Path>,
    capacity: usize,
) -> io::Result<Vec<PathBuf>> {
    select_page_with_tail(entries, after, capacity).map(|(paths, _)| paths)
}

#[cfg(test)]
mod paging_tests;

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
        let per_pass = 7;
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
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "enumeration failed",
            )),
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

        let names = [b"/root/\xff".as_slice(), b"/root/a", b"/root/\xfe"];
        let paths = names.map(|bytes| PathBuf::from(OsString::from_vec(bytes.to_vec())));
        let page = select_page(paths.into_iter().map(Ok), Some(Path::new("/root/a")), 1).unwrap();
        assert_eq!(
            page,
            vec![PathBuf::from(OsString::from_vec(b"/root/\xfe".to_vec()))]
        );
    }
}
