//! Durable scheduling hints for recursive directory dispatch.
//!
//! Only the current child window and next basename are remembered. A restored
//! walk still starts from its current roots, reads every ancestor's names and
//! protection markers, and visits a full circular child page. No metadata,
//! classification, observed result, handle or coverage receipt is restored.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;

/// Most directory priorities retained by one scanner.
pub const MAX_DISPATCH_CURSOR_ROWS: usize = 4096;
/// Maximum aggregate raw directory and child-name storage.
pub const MAX_DISPATCH_CURSOR_BYTES: usize = 512 * 1024;
/// Maximum raw length of a directory path or child basename.
pub const MAX_DISPATCH_CURSOR_PATH_BYTES: usize = 16 * 1024;

/// Byte-preserving recursive dispatch priority, never permission or coverage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkDispatchPosition {
    pub directory: PathBuf,
    pub window_start: u32,
    pub next_child: Option<OsString>,
}

#[derive(Debug, Clone)]
struct RecordedPosition {
    window_start: u32,
    next_child: Option<OsString>,
}

#[derive(Debug, Default)]
struct PositionCell {
    position: Mutex<Option<RecordedPosition>>,
}

impl PositionCell {
    fn snapshot(&self) -> Option<RecordedPosition> {
        self.position.lock().clone()
    }

    fn record(&self, from_window: u32, window_start: u32, next_child: Option<&OsStr>) {
        let mut position = self.position.lock();
        if let Some(current) = position.as_mut() {
            // A boundary receipt has already moved this page to its next
            // window. Repeated ancestor receipts or late wrapped children
            // cannot roll it back or spend another window's opportunity.
            if current.window_start != from_window {
                return;
            }
            current.window_start = window_start;
            match (current.next_child.as_mut(), next_child) {
                (Some(kept), Some(next)) if kept.as_os_str() != next => next.clone_into(kept),
                (None, Some(next)) => current.next_child = Some(next.to_os_string()),
                (_, None) => current.next_child = None,
                _ => {}
            }
        } else {
            *position = Some(RecordedPosition {
                window_start,
                next_child: next_child.map(OsStr::to_os_string),
            });
        }
    }
}

type EvictionRank = (usize, Reverse<u64>, PathBuf);

#[derive(Debug)]
struct Remembered {
    cell: Arc<PositionCell>,
    bytes: usize,
    rank: EvictionRank,
}

/// A bounded set of recursive branch priorities shared by successive walks.
///
/// Worker pages register once; collector receipts update independent per-page
/// cells, without locking this map on every result. A newer page replaces its
/// cell, so an older canceled worker cannot overwrite newer progress.
/// History is best effort within the row and raw-byte limits: an evicted
/// directory's window and child priority may restart from the first window.
#[derive(Debug, Default)]
pub struct WalkDispatchCursor {
    positions: BTreeMap<PathBuf, Remembered>,
    eviction: BTreeSet<EvictionRank>,
    bytes: usize,
    sequence: u64,
    generation: u64,
}

impl WalkDispatchCursor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restore scheduling rows. Malformed, duplicate or oversized input is
    /// rejected as a whole instead of silently changing the checkpoint scope.
    pub fn from_positions(positions: Vec<WalkDispatchPosition>) -> io::Result<Self> {
        if positions.len() > MAX_DISPATCH_CURSOR_ROWS {
            return Err(invalid("recursive dispatch row count exceeds the limit"));
        }
        let mut cursor = Self::new();
        for position in positions {
            validate_directory(&position.directory)?;
            if let Some(child) = &position.next_child {
                validate_child(child)?;
            }
            let bytes = raw_len(position.directory.as_os_str())
                + position.next_child.as_deref().map_or(0, raw_len);
            if bytes > MAX_DISPATCH_CURSOR_BYTES.saturating_sub(cursor.bytes) {
                return Err(invalid("recursive dispatch path storage exceeds the limit"));
            }
            if cursor.positions.contains_key(&position.directory) {
                return Err(invalid("duplicate recursive dispatch directory"));
            }
            cursor.insert(
                position.directory,
                Arc::new(PositionCell {
                    position: Mutex::new(Some(RecordedPosition {
                        window_start: position.window_start,
                        next_child: position.next_child,
                    })),
                }),
                bytes,
            );
        }
        Ok(cursor)
    }

    /// Snapshot only received or explicitly skipped work, in stable path order.
    /// The daemon waits for stopped workers before publishing this snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Vec<WalkDispatchPosition> {
        self.positions
            .iter()
            .filter_map(|(directory, remembered)| {
                remembered
                    .cell
                    .snapshot()
                    .map(|position| WalkDispatchPosition {
                        directory: directory.clone(),
                        window_start: position.window_start,
                        next_child: position.next_child,
                    })
            })
            .collect()
    }

    /// Forget priorities outside the current configured discovery roots.
    pub fn retain_roots(&mut self, roots: &[PathBuf]) {
        self.retain(|path| roots.iter().any(|root| path.starts_with(root)));
    }

    /// A completed subtree no longer needs priority. An ancestor's next-child
    /// hint is independent and must not erase progress in the other branches.
    pub fn forget_scopes(&mut self, roots: &[PathBuf]) {
        self.retain(|path| !roots.iter().any(|root| path.starts_with(root)));
    }

    /// Start without remembered branch priorities.
    pub fn clear(&mut self) {
        self.positions.clear();
        self.eviction.clear();
        self.bytes = 0;
        self.generation = self.generation.wrapping_add(1);
    }

    fn retain(&mut self, keep: impl Fn(&Path) -> bool) {
        self.positions.retain(|directory, remembered| {
            if keep(directory) {
                true
            } else {
                self.eviction.remove(&remembered.rank);
                self.bytes -= remembered.bytes;
                false
            }
        });
    }

    fn insert(&mut self, directory: PathBuf, cell: Arc<PositionCell>, bytes: usize) {
        if let Some(previous) = self.positions.remove(&directory) {
            self.eviction.remove(&previous.rank);
            self.bytes -= previous.bytes;
        }
        self.sequence = self.sequence.wrapping_add(1);
        // Retain the ancestors that make deep priorities reachable. Among
        // equal depths, retain the more recently admitted directories.
        let rank = (
            directory.components().count(),
            Reverse(self.sequence),
            directory.clone(),
        );
        self.eviction.insert(rank.clone());
        self.positions
            .insert(directory, Remembered { cell, bytes, rank });
        self.bytes += bytes;
    }

    fn enforce_bounds(&mut self) {
        while self.positions.len() > MAX_DISPATCH_CURSOR_ROWS
            || self.bytes > MAX_DISPATCH_CURSOR_BYTES
        {
            let Some(rank) = self.eviction.pop_last() else {
                break;
            };
            if let Some(removed) = self.positions.remove(&rank.2) {
                self.bytes -= removed.bytes;
            }
        }
    }

    fn begin_walk(&mut self) -> u64 {
        self.generation = self.generation.wrapping_add(1);
        self.generation
    }

    fn register(
        &mut self,
        generation: u64,
        directory: &Path,
        window_start: u32,
        next_window: Option<u32>,
        children: Arc<Vec<OsString>>,
    ) -> Option<Arc<PagePriority>> {
        if generation != self.generation {
            return None;
        }
        validate_directory(directory).ok()?;
        let mut maximum_name = 0;
        for name in children.iter() {
            validate_child(name).ok()?;
            maximum_name = maximum_name.max(raw_len(name));
        }
        // Reserve the largest possible next name before releasing the map
        // lock. Per-page receipt updates cannot exceed the aggregate bound.
        let remembered = self
            .positions
            .get(directory)
            .and_then(|entry| entry.cell.snapshot());
        if remembered
            .as_ref()
            .is_some_and(|position| position.window_start != window_start)
        {
            // Another page of an overlapping walk already moved this
            // directory forward. Its earlier page may finish normally but
            // cannot replace the newer scheduling position.
            return None;
        }
        let next_child = remembered
            .as_ref()
            .and_then(|position| position.next_child.as_deref());
        let bytes =
            raw_len(directory.as_os_str()) + maximum_name.max(next_child.map_or(0, raw_len));
        let start = next_child
            .filter(|_| !children.is_empty())
            .map(|name| start_index(&children, name));
        let cell = Arc::new(PositionCell {
            position: Mutex::new(remembered),
        });
        self.insert(directory.to_path_buf(), Arc::clone(&cell), bytes);
        self.enforce_bounds();
        if !self
            .positions
            .get(directory)
            .is_some_and(|entry| Arc::ptr_eq(&entry.cell, &cell))
        {
            return None;
        }
        Some(Arc::new(PagePriority {
            cell,
            children,
            start,
            window_start,
            next_window,
        }))
    }
}

/// One walk's registration authority, revoked when another walk starts.
#[derive(Clone)]
pub(super) struct DispatchContext {
    cursor: Arc<Mutex<WalkDispatchCursor>>,
    generation: u64,
}

impl DispatchContext {
    pub(super) fn new(cursor: Arc<Mutex<WalkDispatchCursor>>) -> Self {
        let generation = cursor.lock().begin_walk();
        Self { cursor, generation }
    }

    pub(super) fn register(
        &self,
        directory: &Path,
        window_start: u32,
        next_window: Option<u32>,
        children: Arc<Vec<OsString>>,
    ) -> Option<Arc<PagePriority>> {
        self.cursor.lock().register(
            self.generation,
            directory,
            window_start,
            next_window,
            children,
        )
    }

    pub(super) fn window_start(&self, directory: &Path) -> u32 {
        self.cursor
            .lock()
            .positions
            .get(directory)
            .and_then(|entry| entry.cell.snapshot())
            .map_or(0, |position| position.window_start)
    }
}

/// A live read owns its child names. The cursor registry and queued collector
/// receipts retain only small cells and individual next basenames.
#[derive(Debug)]
pub(super) struct PagePriority {
    cell: Arc<PositionCell>,
    children: Arc<Vec<OsString>>,
    pub(super) start: Option<usize>,
    window_start: u32,
    next_window: Option<u32>,
}

impl PagePriority {
    pub(super) fn receipt(&self, next: usize) -> Arc<PriorityReceipt> {
        let (window_start, next_child) = if next == 0
            && let Some(next_window) = self.next_window
        {
            (next_window, None)
        } else {
            (self.window_start, Some(self.children[next].clone()))
        };
        Arc::new(PriorityReceipt {
            cell: Arc::clone(&self.cell),
            from_window: self.window_start,
            window_start,
            next_child,
        })
    }

    #[cfg(test)]
    pub(super) fn observed(&self, next: usize) {
        self.receipt(next).observed();
    }

    pub(super) fn skip_empty_window(&self) {
        if self.children.is_empty()
            && let Some(next_window) = self.next_window
        {
            self.cell.record(self.window_start, next_window, None);
        }
    }
}

/// A pending result must not keep an evicted page's full child vector alive.
/// Clones share just this receipt's next basename and its bounded cursor cell.
#[derive(Debug)]
pub(super) struct PriorityReceipt {
    cell: Arc<PositionCell>,
    from_window: u32,
    window_start: u32,
    next_child: Option<OsString>,
}

impl PriorityReceipt {
    pub(super) fn observed(&self) {
        self.cell.record(
            self.from_window,
            self.window_start,
            self.next_child.as_deref(),
        );
    }
}

fn raw_len(value: &OsStr) -> usize {
    value.as_encoded_bytes().len()
}

fn valid_bytes(value: &OsStr) -> bool {
    let bytes = value.as_encoded_bytes();
    !bytes.is_empty() && bytes.len() <= MAX_DISPATCH_CURSOR_PATH_BYTES && !bytes.contains(&0)
}

fn validate_directory(directory: &Path) -> io::Result<()> {
    if !directory.is_absolute()
        || !valid_bytes(directory.as_os_str())
        || directory
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(invalid("invalid recursive dispatch directory"));
    }
    Ok(())
}

fn validate_child(child: &OsStr) -> io::Result<()> {
    let mut components = Path::new(child).components();
    if !valid_bytes(child)
        || !matches!(components.next(), Some(Component::Normal(name)) if name == child)
        || components.next().is_some()
    {
        return Err(invalid("recursive dispatch child is not a basename"));
    }
    Ok(())
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn start_index(children: &[OsString], next_child: &OsStr) -> usize {
    children
        .iter()
        .position(|name| name == next_child)
        .or_else(|| {
            children
                .iter()
                .enumerate()
                .filter(|(_, name)| name.as_os_str() > next_child)
                .min_by(|(_, left), (_, right)| left.cmp(right))
                .map(|(index, _)| index)
        })
        .unwrap_or_else(|| {
            children
                .iter()
                .enumerate()
                .min_by(|(_, left), (_, right)| left.cmp(right))
                .map_or(0, |(index, _)| index)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_removed_or_out_of_window_bookmark_only_changes_circular_priority() {
        let children = vec![
            OsString::from("a"),
            OsString::from("c"),
            OsString::from("e"),
        ];
        for (bookmark, expected) in [("b", 1), ("later-window", 0)] {
            let start = start_index(&children, OsStr::new(bookmark));
            assert_eq!(start, expected);
            let mut visited: Vec<_> = children
                .iter()
                .cycle()
                .skip(start)
                .take(children.len())
                .collect();
            visited.sort();
            assert_eq!(visited, children.iter().collect::<Vec<_>>());
        }
    }

    #[test]
    fn queued_pages_do_not_record_progress_and_late_workers_cannot_replace_it() {
        let cursor = Arc::new(Mutex::new(WalkDispatchCursor::new()));
        let first = DispatchContext::new(Arc::clone(&cursor));
        let names = Arc::new(vec![OsString::from("a"), OsString::from("b")]);
        let old = first
            .register(Path::new("/root"), 0, None, Arc::clone(&names))
            .unwrap();
        assert!(
            cursor.lock().snapshot().is_empty(),
            "registration is not receipt"
        );
        old.observed(1);
        let second = DispatchContext::new(Arc::clone(&cursor));
        let current = second
            .register(Path::new("/root"), 0, None, Arc::clone(&names))
            .unwrap();
        current.observed(0);
        old.observed(1);
        assert!(first.register(Path::new("/root"), 0, None, names).is_none());
        assert_eq!(
            cursor.lock().snapshot()[0].next_child.as_deref(),
            Some(OsStr::new("a"))
        );
    }

    #[test]
    fn compact_receipt_outlives_its_page_without_retaining_child_names() {
        let cursor = Arc::new(Mutex::new(WalkDispatchCursor::new()));
        let walk = DispatchContext::new(Arc::clone(&cursor));
        let names = Arc::new(vec![OsString::from("a"), OsString::from("b")]);
        let weak_names = Arc::downgrade(&names);
        let page = walk
            .register(Path::new("/root"), 0, None, Arc::clone(&names))
            .unwrap();
        let receipt = page.receipt(1);
        drop(page);
        drop(names);
        assert!(weak_names.upgrade().is_none());
        assert!(cursor.lock().snapshot().is_empty());

        receipt.observed();
        assert_eq!(
            cursor.lock().snapshot(),
            vec![WalkDispatchPosition {
                directory: PathBuf::from("/root"),
                window_start: 0,
                next_child: Some(OsString::from("b")),
            }]
        );
    }

    #[test]
    fn detached_snapshots_do_not_follow_abandoned_worker_receipts() {
        let abandoned = Arc::new(Mutex::new(WalkDispatchCursor::new()));
        let old_walk = DispatchContext::new(Arc::clone(&abandoned));
        let names = Arc::new(vec![OsString::from("a"), OsString::from("b")]);
        let old_page = old_walk
            .register(Path::new("/root"), 0, None, Arc::clone(&names))
            .unwrap();
        old_page.observed(1);
        let settled = WalkDispatchCursor::from_positions(abandoned.lock().snapshot()).unwrap();
        let next = Arc::new(Mutex::new(
            WalkDispatchCursor::from_positions(settled.snapshot()).unwrap(),
        ));
        let next_walk = DispatchContext::new(Arc::clone(&next));
        let next_page = next_walk
            .register(Path::new("/root"), 0, None, names)
            .unwrap();
        next_page.observed(0);

        old_page.observed(0);
        assert_eq!(
            settled.snapshot()[0].next_child.as_deref(),
            Some(OsStr::new("b"))
        );
        old_page.observed(1);
        assert_eq!(
            next.lock().snapshot()[0].next_child.as_deref(),
            Some(OsStr::new("a"))
        );
    }

    #[test]
    fn a_removed_long_basename_still_counts_toward_live_storage() {
        let directory = PathBuf::from("/root");
        let remembered = OsString::from("x".repeat(MAX_DISPATCH_CURSOR_PATH_BYTES));
        let mut cursor = WalkDispatchCursor::from_positions(vec![WalkDispatchPosition {
            directory: directory.clone(),
            window_start: 0,
            next_child: Some(remembered.clone()),
        }])
        .unwrap();
        let generation = cursor.begin_walk();
        let _page = cursor
            .register(
                generation,
                &directory,
                0,
                None,
                Arc::new(vec![OsString::from("new")]),
            )
            .unwrap();
        assert_eq!(cursor.snapshot()[0].next_child, Some(remembered.clone()));
        assert_eq!(
            cursor.bytes,
            raw_len(directory.as_os_str()) + raw_len(&remembered)
        );
    }

    #[test]
    fn a_window_boundary_receipt_is_sticky_until_the_next_page() {
        let directory = PathBuf::from("/root");
        let cursor = Arc::new(Mutex::new(
            WalkDispatchCursor::from_positions(vec![WalkDispatchPosition {
                directory: directory.clone(),
                window_start: 0,
                next_child: Some("b".into()),
            }])
            .unwrap(),
        ));
        let first = DispatchContext::new(Arc::clone(&cursor));
        let page = first
            .register(
                &directory,
                0,
                Some(2),
                Arc::new(vec!["a".into(), "b".into()]),
            )
            .unwrap();
        assert_eq!(page.start, Some(1));
        assert_eq!(
            cursor.lock().snapshot()[0].window_start,
            0,
            "reading and registering the boundary is not receiving it"
        );

        page.observed(0);
        page.observed(1);
        page.observed(0);
        assert_eq!(
            cursor.lock().snapshot(),
            vec![WalkDispatchPosition {
                directory: directory.clone(),
                window_start: 2,
                next_child: None,
            }],
            "wrapped or repeated old-page receipts cannot roll back the window"
        );

        let settled = cursor.lock().snapshot();
        let next_cursor = Arc::new(Mutex::new(
            WalkDispatchCursor::from_positions(settled).unwrap(),
        ));
        let second = DispatchContext::new(Arc::clone(&next_cursor));
        let last_page = second
            .register(&directory, 2, Some(0), Arc::new(vec!["c".into()]))
            .unwrap();
        assert_eq!(
            last_page.start, None,
            "a new window starts at its beginning"
        );
        assert_eq!(next_cursor.lock().snapshot()[0].window_start, 2);
        last_page.observed(0);
        last_page.observed(0);
        assert_eq!(
            next_cursor.lock().snapshot(),
            vec![WalkDispatchPosition {
                directory,
                window_start: 0,
                next_child: None,
            }],
            "receiving the last window wraps once for a fresh later inspection"
        );
    }

    #[test]
    fn an_empty_window_moves_only_after_an_explicit_complete_skip() {
        let directory = PathBuf::from("/root");
        let cursor = Arc::new(Mutex::new(
            WalkDispatchCursor::from_positions(vec![WalkDispatchPosition {
                directory: directory.clone(),
                window_start: 8,
                next_child: None,
            }])
            .unwrap(),
        ));
        let walk = DispatchContext::new(Arc::clone(&cursor));
        let failed = walk
            .register(&directory, 8, None, Arc::new(Vec::new()))
            .unwrap();
        failed.skip_empty_window();
        assert_eq!(
            cursor.lock().snapshot()[0].window_start,
            8,
            "an incomplete observation has no next-window authority"
        );
        let complete = walk
            .register(&directory, 8, Some(0), Arc::new(Vec::new()))
            .unwrap();
        assert_eq!(cursor.lock().snapshot()[0].window_start, 8);
        complete.skip_empty_window();
        complete.skip_empty_window();
        assert_eq!(
            cursor.lock().snapshot(),
            vec![WalkDispatchPosition {
                directory,
                window_start: 0,
                next_child: None,
            }]
        );
    }
}
