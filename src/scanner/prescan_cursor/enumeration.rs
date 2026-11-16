//! Resumable, read-only preparation of deterministic pre-scan pages.
//!
//! Directory order is unspecified, so a sorted page cannot be emitted until
//! enumeration reaches EOF. Keep the iterator and bounded heap across budget
//! stops, then keep the finished page until the caller consumes it. Otherwise
//! a directory that costs an entire pass to enumerate never gets examined.
//!
//! This is volatile read-ahead, not checkpoint progress or deletion evidence.
//! A restart or cache eviction repeats enumeration; it never advances a cursor.

use std::cell::RefCell;
use std::collections::{BTreeMap, BinaryHeap};
use std::fs::{self, Metadata, ReadDir};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use super::{PageProof, PrescanCursor, ROOT_ENTRY_CAP};

// Bound both retained directory handles and aggregate retained path count.
// Splitting the existing path allowance lets alternating mount requests keep
// independent preparation work without multiplying the memory bound by roots.
const MAX_LIVE_ROOTS: usize = 4;
const MAX_NESTED_READERS: usize = 2;
// Each admitted outer root owns two nested slots. Ready outer pages cannot
// consume that reservation, and alternating roots cannot each hold a parent
// while preventing the other from opening its last shallow level. Twelve
// handles share the original aggregate name allowance; it does not grow.
const PAGE_ENTRIES: usize = ROOT_ENTRY_CAP / (MAX_LIVE_ROOTS * (1 + MAX_NESTED_READERS));
const READ_CHUNK_ENTRIES: usize = 256;
const READ_POLL_CHUNKS: usize = 16;
const READ_POLL_TIME: Duration = Duration::from_millis(50);
// Abandoned roots must eventually release admission without a config reset.
// Active readers renew on every visit, not just when a page is completed.
const READER_IDLE_LEASE: Duration = Duration::from_hours(1);

thread_local! {
    // The daemon constructs an event-scoped scratch cursor for each pass.
    // Reuse speculative reads while its configured-root cursor is alive,
    // without making scratch progress part of the configured checkpoint.
    // A weak reference keeps no descriptors alive after the last cursor
    // drops, and separate scanner threads do not contend on a global cache.
    static LIVE_CACHE: RefCell<Weak<Mutex<EnumerationCache>>> = const {
        RefCell::new(Weak::new())
    };
}

pub(super) fn shared_cache() -> Arc<Mutex<EnumerationCache>> {
    LIVE_CACHE.with(|slot| {
        let mut slot = slot.borrow_mut();
        if let Some(cache) = slot.upgrade() {
            return cache;
        }
        let cache = Arc::new(Mutex::new(EnumerationCache::default()));
        *slot = Arc::downgrade(&cache);
        cache
    })
}

/// A prepared page of discovery names. Iteration clones one path at a time,
/// not the whole page, so entering a new pass does not copy a large prefix.
#[derive(Debug, Clone)]
pub struct RootPage {
    names: Arc<Vec<PathBuf>>,
    start: usize,
    has_more: bool,
}

/// Owned, lazy iteration over a prepared pre-scan page.
#[derive(Debug)]
pub struct RootPageIter {
    names: Arc<Vec<PathBuf>>,
    next: usize,
}

impl IntoIterator for RootPage {
    type Item = PathBuf;
    type IntoIter = RootPageIter;

    fn into_iter(self) -> Self::IntoIter {
        RootPageIter {
            names: self.names,
            next: self.start,
        }
    }
}

impl Iterator for RootPageIter {
    type Item = PathBuf;

    fn next(&mut self) -> Option<Self::Item> {
        let path = self.names.get(self.next)?.clone();
        self.next += 1;
        Some(path)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.names.len().saturating_sub(self.next);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for RootPageIter {}
impl std::iter::FusedIterator for RootPageIter {}

impl RootPage {
    fn last_path(&self) -> Option<&Path> {
        if self.start < self.names.len() {
            self.names.last().map(PathBuf::as_path)
        } else {
            None
        }
    }
}

#[derive(Debug)]
struct DirectoryPaths(ReadDir);

impl Iterator for DirectoryPaths {
    type Item = io::Result<PathBuf>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|entry| entry.map(|entry| entry.path()))
    }
}

#[derive(Debug)]
struct Selection<I> {
    entries: I,
    after: Option<PathBuf>,
    capacity: usize,
    selected: BinaryHeap<PathBuf>,
    has_more: bool,
}

impl<I: Iterator<Item = io::Result<PathBuf>>> Selection<I> {
    fn new(entries: I, after: Option<&Path>, capacity: usize) -> Self {
        Self {
            entries,
            after: after.map(Path::to_path_buf),
            capacity,
            selected: BinaryHeap::new(),
            has_more: false,
        }
    }

    fn poll(
        &mut self,
        keep_reading: &mut impl FnMut() -> bool,
    ) -> io::Result<Option<(Vec<PathBuf>, bool)>> {
        loop {
            // The caller supplies either the entry API's bounded slice or
            // explicit pass/shutdown checks. One filesystem call can still
            // block; the check runs before each chunk, never after losing it.
            if !keep_reading() {
                return Ok(None);
            }
            for _ in 0..READ_CHUNK_ENTRIES {
                let Some(entry) = self.entries.next() else {
                    // Sorting is bounded by page capacity but not interruptible.
                    // The cache retains its result even if it uses the last of
                    // this pass's budget, allowing delivery on the next poll.
                    let paths = std::mem::take(&mut self.selected).into_sorted_vec();
                    return Ok(Some((paths, self.has_more)));
                };
                let path = entry?;
                if self
                    .after
                    .as_deref()
                    .is_some_and(|after| path.as_path() <= after)
                {
                    continue;
                }
                if self.selected.len() < self.capacity {
                    self.selected.push(path);
                } else {
                    self.has_more = true;
                    if let Some(mut largest) = self.selected.peek_mut()
                        && path < *largest
                    {
                        *largest = path;
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
struct PreparedPage {
    names: Arc<Vec<PathBuf>>,
    has_more: bool,
}

#[derive(Debug)]
struct Session {
    identity: Metadata,
    after: Option<PathBuf>,
    used_at: u64,
    last_requested: Instant,
    // Retain the directory iterator even after EOF. Ready pages must not
    // release their directory handle while still carrying its identity.
    selection: Selection<DirectoryPaths>,
    prepared: Option<PreparedPage>,
    nested: Option<Box<NestedReadAhead>>,
}

#[derive(Debug)]
struct NestedReadAhead {
    entry: PathBuf,
    pages: EnumerationCache,
}

impl Session {
    fn matches(&self, identity: &Metadata, after: Option<&Path>) -> bool {
        if !same_directory(&self.identity, identity) {
            return false;
        }
        if self.after.as_deref() == after {
            return true;
        }
        let Some(PreparedPage { names, has_more }) = &self.prepared else {
            return false;
        };
        let (Some(after), Some(last)) = (after, names.last()) else {
            return false;
        };
        // A rewind before the page's starting position needs a new page.
        // A consumed non-final page also needs enumeration of the next page.
        self.after.as_deref().is_none_or(|base| after >= base)
            && after <= last.as_path()
            && (!*has_more || after != last.as_path())
    }

    fn poll(&mut self, keep_reading: &mut impl FnMut() -> bool) -> io::Result<bool> {
        if self.prepared.is_none() {
            let Some((names, has_more)) = self.selection.poll(keep_reading)? else {
                return Ok(false);
            };
            self.prepared = Some(PreparedPage {
                names: Arc::new(names),
                has_more,
            });
        }
        Ok(true)
    }
}

fn same_directory(left: &Metadata, right: &Metadata) -> bool {
    if !left.is_dir() || !right.is_dir() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        // The daemon's supported Unix platforms have real device/inode IDs.
        // Elsewhere reuse only when the platform supplies a birth timestamp
        // and neither it nor the directory mtime changed.
        left.created()
            .ok()
            .is_some_and(|created| right.created().ok() == Some(created))
            && left.modified().ok() == right.modified().ok()
    }
}

#[derive(Debug)]
pub(super) struct EnumerationCache {
    clock: u64,
    sessions: BTreeMap<PathBuf, Session>,
    session_limit: usize,
}

impl Default for EnumerationCache {
    fn default() -> Self {
        Self {
            clock: 0,
            sessions: BTreeMap::new(),
            session_limit: MAX_LIVE_ROOTS,
        }
    }
}

impl EnumerationCache {
    fn metadata(&mut self, root: &Path, follow_symlinks: bool) -> io::Result<Metadata> {
        let metadata = if follow_symlinks {
            fs::metadata(root)
        } else {
            fs::symlink_metadata(root)
        };
        match metadata {
            Ok(metadata) if metadata.is_dir() => Ok(metadata),
            Ok(_) => {
                self.sessions.remove(root);
                Err(io::Error::other("pre-scan root is no longer a directory"))
            }
            Err(error) => {
                self.sessions.remove(root);
                Err(error)
            }
        }
    }

    #[cfg(test)]
    fn prepare_at(&mut self, root: &Path, after: Option<&Path>, now: Instant) -> io::Result<()> {
        self.prepare_with_links(root, after, now, true)
    }

    fn prepare_with_links(
        &mut self,
        root: &Path,
        after: Option<&Path>,
        now: Instant,
        follow_symlinks: bool,
    ) -> io::Result<()> {
        let identity = self.metadata(root, follow_symlinks)?;
        self.clock = self.clock.saturating_add(1);
        if let Some(session) = self.sessions.get_mut(root)
            && session.matches(&identity, after)
        {
            session.used_at = self.clock;
            session.last_requested = now;
            return Ok(());
        }
        // Incompatible identity/resume state is not usable read-ahead. Dropping
        // it closes only our directory handle; no filesystem entry is removed.
        self.sessions.remove(root);
        if self.sessions.len() >= self.session_limit {
            // LRU eviction on every miss causes permanent thrashing for a
            // cyclic request with five large roots and four reader slots:
            // every read is evicted before its second chunk. Keep active
            // work, and return a resumable admission wait for this root.
            let expired = self
                .sessions
                .iter()
                .filter(|(_, session)| {
                    now.saturating_duration_since(session.last_requested) >= READER_IDLE_LEASE
                })
                .min_by_key(|(_, session)| session.used_at)
                .map(|(path, _)| path.clone());
            let Some(expired) = expired else {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "pre-scan readers busy; unfinished preparation retained",
                ));
            };
            self.sessions.remove(&expired);
        }
        let entries = DirectoryPaths(fs::read_dir(root)?);
        self.sessions.insert(
            root.to_path_buf(),
            Session {
                identity,
                after: after.map(Path::to_path_buf),
                used_at: self.clock,
                last_requested: now,
                selection: Selection::new(entries, after, PAGE_ENTRIES),
                prepared: None,
                nested: None,
            },
        );
        Ok(())
    }

    fn poll(
        &mut self,
        root: &Path,
        after: Option<&Path>,
        keep_reading: &mut impl FnMut() -> bool,
    ) -> io::Result<Option<RootPage>> {
        self.poll_with_links(root, after, true, keep_reading)
    }

    fn poll_with_links(
        &mut self,
        root: &Path,
        after: Option<&Path>,
        follow_symlinks: bool,
        keep_reading: &mut impl FnMut() -> bool,
    ) -> io::Result<Option<RootPage>> {
        if !keep_reading() {
            return Ok(None);
        }
        self.prepare_with_links(root, after, Instant::now(), follow_symlinks)?;
        let result = self
            .sessions
            .get_mut(root)
            .ok_or_else(|| io::Error::other("missing pre-scan preparation"))?
            .poll(keep_reading);
        match result {
            Ok(false) => return Ok(None),
            Ok(true) => {}
            Err(error) => {
                // A partially read directory with an error is not an EOF proof.
                // Keep durable progress, but discard this incomplete observation.
                self.sessions.remove(root);
                return Err(error);
            }
        }
        if !keep_reading() {
            return Ok(None);
        }
        // Check again before handing out a completed page. Preparation may
        // span several passes while a mount or directory is replaced.
        let current = self.metadata(root, follow_symlinks)?;
        let session = self
            .sessions
            .get(root)
            .ok_or_else(|| io::Error::other("missing prepared pre-scan page"))?;
        if !same_directory(&session.identity, &current) {
            self.sessions.remove(root);
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "pre-scan root changed",
            ));
        }
        let Some(PreparedPage { names, has_more }) = &session.prepared else {
            return Err(io::Error::other("pre-scan preparation has not finished"));
        };
        let start =
            names.partition_point(|path| after.is_some_and(|after| path.as_path() <= after));
        Ok(Some(RootPage {
            names: Arc::clone(names),
            start,
            has_more: *has_more,
        }))
    }
}

impl PrescanCursor {
    /// An admitted root's two reserved nested readers are independent of the
    /// other three roots. The page sizes preserve the aggregate name bound.
    /// Dropping or evicting the outer session also releases its nested readers.
    pub(super) fn poll_shallow_entries(
        &self,
        root: &Path,
        entry: &Path,
        directory: &Path,
        after: Option<&Path>,
        follow_symlinks: bool,
        keep_reading: &mut impl FnMut() -> bool,
    ) -> io::Result<Option<RootPage>> {
        if !keep_reading() {
            return Ok(None);
        }
        let mut cache = self
            .enumeration
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Direct users of the shallow API reserve the same outer admission
        // as a normal root-page caller, rather than allocating another pool.
        cache.prepare_with_links(root, self.resume_after(root), Instant::now(), true)?;
        let session = cache.sessions.get_mut(root).expect("admitted shallow root");
        if session
            .nested
            .as_ref()
            .is_some_and(|nested| nested.entry != entry)
        {
            session.nested = None;
        }
        let nested = session.nested.get_or_insert_with(|| {
            Box::new(NestedReadAhead {
                entry: entry.to_path_buf(),
                pages: EnumerationCache {
                    session_limit: MAX_NESTED_READERS,
                    ..EnumerationCache::default()
                },
            })
        });
        let result = nested
            .pages
            .poll_with_links(directory, after, follow_symlinks, keep_reading);
        drop(cache);
        result
    }

    pub(super) fn discard_shallow_enumeration(
        &self,
        root: &Path,
        entry: &Path,
        directory: Option<&Path>,
    ) {
        let mut cache = self
            .enumeration
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(session) = cache.sessions.get_mut(root) else {
            return;
        };
        if let Some(nested) = session.nested.as_mut()
            && nested.entry == entry
        {
            if let Some(directory) = directory {
                nested.pages.sessions.remove(directory);
            } else {
                session.nested = None;
            }
        }
        drop(cache);
    }

    pub(super) fn read_entries(&self, root: &Path) -> io::Result<Vec<PathBuf>> {
        let started = Instant::now();
        let mut checks = 0;
        let page = self.poll_entries_to_visit(root, || {
            checks += 1;
            // The initial cache check spends one check; at most sixteen
            // directory chunks can follow. EOF and delivery spend checks
            // too, and a denied delivery retains the already-sorted page.
            checks <= READ_POLL_CHUNKS + 1 && started.elapsed() < READ_POLL_TIME
        })?;
        page.map(|page| page.into_iter().collect()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "pre-scan directory preparation paused; retry to resume",
            )
        })
    }

    pub(super) fn clear_enumeration(&self) {
        self.enumeration
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sessions
            .clear();
    }

    /// Start a scoped scan without inheriting or advancing configured-root
    /// coverage. Share only volatile read-ahead so recreating the daemon's
    /// scratch cursor each pass does not restart a large directory read.
    #[must_use]
    pub fn scoped_read_ahead(&self) -> Self {
        Self {
            enumeration: Arc::clone(&self.enumeration),
            ..Self::default()
        }
    }

    /// Prepare a deterministic page without restarting work at a budget stop.
    ///
    /// `keep_reading` checks the caller's current CPU/wall budget and shutdown
    /// state. It is polled between chunks of at most 256 directory entries.
    /// `Ok(None)` means preparation yielded, not EOF or an unreadable root.
    /// Neither reading names nor yielding changes durable cursor progress.
    ///
    /// Up to four roots retain preparation concurrently. Each root page and
    /// each of its two reserved shallow pages retains at most one twelfth of
    /// `ROOT_ENTRY_CAP` names. When outer readers are occupied,
    /// `WouldBlock` defers admission without evicting active preparation.
    /// A reader unrequested for an hour may be reclaimed; only read-ahead is
    /// lost. Completed pages remain cached through budget stops and rewind
    /// clones. A restart retains only completed work.
    pub fn poll_entries_to_visit(
        &self,
        root: &Path,
        mut keep_reading: impl FnMut() -> bool,
    ) -> io::Result<Option<RootPage>> {
        *self.page_proof() = Some(PageProof {
            root: root.to_path_buf(),
            last: None,
            exhausted: false,
        });
        let page = self
            .enumeration
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .poll(root, self.resume_after(root), &mut keep_reading)?;
        if let Some(page) = &page {
            *self.page_proof() = Some(PageProof {
                root: root.to_path_buf(),
                last: page.last_path().map(Path::to_path_buf),
                exhausted: !page.has_more,
            });
        }
        Ok(page)
    }

    /// Release read-ahead for roots outside `roots`. A session holds its
    /// directory open even after EOF, so a root a reload removed would keep
    /// its volume busy (bd-656i). Durable resume positions are untouched.
    pub fn release_read_ahead_outside(&self, roots: &[PathBuf]) {
        self.enumeration
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sessions
            .retain(|path, _| roots.iter().any(|root| path.starts_with(root)));
    }

    pub(super) fn discard_enumeration(&self, root: &Path) {
        self.enumeration
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sessions
            .remove(root);
    }
}

#[cfg(test)]
mod tests {
    use super::super::{ShallowDisposition, ShallowPoll};
    use super::*;
    use std::cell::Cell;

    fn limited_poll(cursor: &PrescanCursor, root: &Path) -> io::Result<Option<RootPage>> {
        let mut checks = 0;
        cursor.poll_entries_to_visit(root, || {
            checks += 1;
            checks <= 2
        })
    }

    fn make_root(base: &Path, name: &str, count: usize) -> PathBuf {
        let root = base.join(name);
        fs::create_dir(&root).unwrap();
        for n in 0..count {
            fs::create_dir(root.join(format!("item-{n:04}"))).unwrap();
        }
        root
    }

    fn expected(root: &Path, count: usize) -> Vec<PathBuf> {
        (0..count)
            .map(|n| root.join(format!("item-{n:04}")))
            .collect()
    }

    fn finish(cursor: &PrescanCursor, root: &Path) -> RootPage {
        for _ in 0..32 {
            if let Some(page) = limited_poll(cursor, root).unwrap() {
                return page;
            }
        }
        panic!("preparation did not finish across bounded polls");
    }

    #[test]
    fn chunk_yields_preserve_every_unread_entry_and_match_an_independent_full_sort() {
        for capacity in [0, 1, 17, 300] {
            for reverse in [false, true] {
                let mut input: Vec<_> = (0..777)
                    .map(|n| PathBuf::from(format!("/root/{:04}", (n * 73) % 777)))
                    .collect();
                if reverse {
                    input.reverse();
                }
                let after = Path::new("/root/0123");
                let mut reference: Vec<_> = input
                    .iter()
                    .filter(|path| path.as_path() > after)
                    .cloned()
                    .collect();
                reference.sort();
                let more = reference.len() > capacity;
                reference.truncate(capacity);
                let read_count = Cell::new(0);
                let entries = input.into_iter().map(|path| {
                    read_count.set(read_count.get() + 1);
                    Ok(path)
                });
                let mut selection = Selection::new(entries, Some(after), capacity);
                let mut actual = None;
                for _ in 0..8 {
                    let before = read_count.get();
                    let mut permit = true;
                    actual = selection.poll(&mut || std::mem::take(&mut permit)).unwrap();
                    assert!(read_count.get() - before <= READ_CHUNK_ENTRIES);
                    assert!(selection.selected.len() <= capacity);
                    if actual.is_some() {
                        break;
                    }
                }
                assert_eq!(read_count.get(), 777, "no repeated enumeration prefix");
                assert_eq!(actual.unwrap(), (reference, more));
            }
        }
    }

    #[test]
    fn exhausted_budget_does_not_touch_the_directory_iterator() {
        let entries = std::iter::from_fn(|| -> Option<io::Result<PathBuf>> {
            panic!("no read is allowed after a budget stop");
        });
        let mut selection = Selection::new(entries, None, 8);
        assert!(selection.poll(&mut || false).unwrap().is_none());
    }

    #[test]
    fn enumeration_failure_never_returns_a_partial_page_as_complete() {
        let entries = [
            Ok(PathBuf::from("/root/a")),
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied")),
            Ok(PathBuf::from("/root/b")),
        ];
        let mut selection = Selection::new(entries.into_iter(), None, 8);
        assert_eq!(
            selection.poll(&mut || true).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn preparation_and_completed_page_survive_separate_budget_stops() {
        let temp = tempfile::tempdir().unwrap();
        let root = make_root(temp.path(), "root", 512);
        let cursor = PrescanCursor::new();
        let before = cursor.clone();
        // Two chunks, then an EOF/sort poll whose delivery budget expires.
        assert!(limited_poll(&cursor, &root).unwrap().is_none());
        assert!(limited_poll(&cursor, &root).unwrap().is_none());
        assert!(limited_poll(&cursor, &root).unwrap().is_none());
        assert!(
            cursor.enumeration.lock().unwrap().sessions[&root]
                .prepared
                .is_some()
        );
        let page = limited_poll(&cursor, &root).unwrap().unwrap();
        assert_eq!(page.into_iter().collect::<Vec<_>>(), expected(&root, 512));
        assert_eq!(cursor, before, "read-ahead is not durable coverage");
        let json = serde_json::to_value(&cursor).unwrap();
        assert!(json.get("enumeration").is_none());
        assert!(json.get("page").is_none());
    }

    #[test]
    fn alternating_mount_requests_keep_both_unfinished_enumerations() {
        let temp = tempfile::tempdir().unwrap();
        let a = make_root(temp.path(), "a", 600);
        let b = make_root(temp.path(), "b", 600);
        let cursor = PrescanCursor::new();
        for _ in 0..2 {
            assert!(limited_poll(&cursor, &a).unwrap().is_none());
            assert!(limited_poll(&cursor, &b).unwrap().is_none());
        }
        assert_eq!(
            finish(&cursor, &a).into_iter().collect::<Vec<_>>(),
            expected(&a, 600)
        );
        assert_eq!(
            finish(&cursor, &b).into_iter().collect::<Vec<_>>(),
            expected(&b, 600)
        );
    }

    #[test]
    fn successive_scratch_cursors_resume_reads_without_advancing_configured_coverage() {
        let temp = tempfile::tempdir().unwrap();
        let root = make_root(temp.path(), "project", 600);
        let mut configured = PrescanCursor::new();
        configured.advance(Path::new("/configured"), Path::new("/configured/done"));
        let before = configured.clone();
        let mut observed = None;
        for _ in 0..8 {
            let mut scratch = configured.scoped_read_ahead();
            assert_eq!(scratch.position(), (None, None));
            if let Some(page) = limited_poll(&scratch, &root).unwrap() {
                let names: Vec<_> = page.into_iter().collect();
                for name in &names {
                    scratch.advance(&root, name);
                }
                scratch.complete_root(std::slice::from_ref(&root), &root);
                observed = Some(names);
                break;
            }
            assert_eq!(configured, before);
        }
        assert_eq!(observed.unwrap(), expected(&root, 600));
        assert_eq!(configured, before);
    }

    #[test]
    fn cached_suffix_and_rewind_preserve_names_until_actual_completion() {
        let temp = tempfile::tempdir().unwrap();
        let root = make_root(temp.path(), "root", 12);
        let roots = vec![root.clone()];
        let mut cursor = PrescanCursor::new();
        let page = cursor
            .poll_entries_to_visit(&root, || true)
            .unwrap()
            .unwrap();
        let names: Vec<_> = page.clone().into_iter().collect();
        cursor.advance(&root, &names[0]);
        let rewind = cursor.clone();
        cursor.advance(&root, &names[1]);
        // Same directory identity, new name: cached names are discovery hints,
        // not a snapshot of live contents. The next completed sweep sees it.
        fs::create_dir(root.join("aaa-new")).unwrap();
        let suffix = cursor
            .poll_entries_to_visit(&root, || true)
            .unwrap()
            .unwrap();
        assert_eq!(suffix.into_iter().collect::<Vec<_>>(), names[2..]);
        let rewound = rewind
            .poll_entries_to_visit(&root, || true)
            .unwrap()
            .unwrap();
        assert_eq!(rewound.into_iter().collect::<Vec<_>>(), names[1..]);
        for name in &names[2..] {
            cursor.advance(&root, name);
        }
        cursor.complete_root(&roots, &root);
        assert!(cursor.enumeration.lock().unwrap().sessions.is_empty());
        let next = cursor
            .poll_entries_to_visit(&root, || true)
            .unwrap()
            .unwrap();
        assert_eq!(next.into_iter().next(), Some(root.join("aaa-new")));
        assert_eq!(
            page.into_iter().collect::<Vec<_>>(),
            names,
            "retained pages are immutable"
        );
    }

    #[test]
    fn consuming_a_capped_page_resumes_the_tail_instead_of_rewinding_the_root() {
        let temp = tempfile::tempdir().unwrap();
        let root = make_root(temp.path(), "root", 6);
        let roots = vec![root.clone()];
        let mut cursor = PrescanCursor::new();
        // Exercise a real directory iterator with a small page capacity,
        // without needing 50,001 filesystem entries to reach the tail branch.
        cursor.enumeration.lock().unwrap().sessions.insert(
            root.clone(),
            Session {
                identity: fs::metadata(&root).unwrap(),
                after: None,
                used_at: 0,
                last_requested: Instant::now(),
                selection: Selection::new(DirectoryPaths(fs::read_dir(&root).unwrap()), None, 2),
                prepared: None,
                nested: None,
            },
        );
        let first = cursor
            .poll_entries_to_visit(&root, || true)
            .unwrap()
            .unwrap();
        let first: Vec<_> = first.into_iter().collect();
        assert_eq!(first, expected(&root, 2));
        for path in &first {
            cursor.advance(&root, path);
        }
        cursor.complete_root(&roots, &root);
        assert_eq!(cursor.position().1, Some(root.join("item-0001").as_path()));
        let tail = cursor
            .poll_entries_to_visit(&root, || true)
            .unwrap()
            .unwrap();
        let tail: Vec<_> = tail.into_iter().collect();
        assert_eq!(tail, expected(&root, 6)[2..]);
        for path in &tail {
            cursor.advance(&root, path);
        }
        cursor.complete_root(&roots, &root);
        assert!(cursor.position().1.is_none());
        assert!(cursor.continuations.is_empty());
        assert!(cursor.enumeration.lock().unwrap().sessions.is_empty());
    }

    #[test]
    fn root_replacement_discards_the_old_iterator_without_claiming_its_names() {
        let temp = tempfile::tempdir().unwrap();
        let root = make_root(temp.path(), "root", 600);
        let cursor = PrescanCursor::new();
        assert!(limited_poll(&cursor, &root).unwrap().is_none());
        let retired = temp.path().join("old-root");
        fs::rename(&root, &retired).unwrap();
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("replacement")).unwrap();
        let page = finish(&cursor, &root);
        assert_eq!(
            page.into_iter().collect::<Vec<_>>(),
            vec![root.join("replacement")]
        );
        assert!(retired.join("item-0000").is_dir());
    }

    #[test]
    fn missing_root_clears_read_ahead_but_not_completed_progress() {
        let temp = tempfile::tempdir().unwrap();
        let root = make_root(temp.path(), "root", 600);
        let mut cursor = PrescanCursor::new();
        cursor.advance(&root, &root.join("item-0003"));
        let before = cursor.clone();
        assert!(limited_poll(&cursor, &root).unwrap().is_none());
        fs::rename(&root, temp.path().join("away")).unwrap();
        assert_eq!(
            cursor
                .poll_entries_to_visit(&root, || true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(cursor, before);
        assert!(cursor.enumeration.lock().unwrap().sessions.is_empty());
    }

    #[test]
    fn released_roots_close_their_reader_but_keep_progress_and_other_roots() {
        let temp = tempfile::tempdir().unwrap();
        let kept = make_root(temp.path(), "kept", 600);
        let removed = make_root(temp.path(), "removed", 600);
        let mut cursor = PrescanCursor::new();
        cursor.advance(&removed, &removed.join("item-0003"));
        let before = cursor.clone();
        assert!(limited_poll(&cursor, &kept).unwrap().is_none());
        assert!(limited_poll(&cursor, &removed).unwrap().is_none());
        cursor.release_read_ahead_outside(std::slice::from_ref(&kept));
        let live: Vec<PathBuf> = cursor
            .enumeration
            .lock()
            .unwrap()
            .sessions
            .keys()
            .cloned()
            .collect();
        assert_eq!(live, vec![kept]);
        assert_eq!(cursor, before, "durable progress survives the release");
    }

    #[test]
    fn live_root_bound_defers_admission_without_discarding_active_reads() {
        let temp = tempfile::tempdir().unwrap();
        let mut cursor = PrescanCursor::new();
        let roots: Vec<_> = (0..=MAX_LIVE_ROOTS)
            .map(|n| make_root(temp.path(), &format!("r-{n}"), 300))
            .collect();
        for root in &roots[..MAX_LIVE_ROOTS] {
            assert!(limited_poll(&cursor, root).unwrap().is_none());
            assert!(cursor.enumeration.lock().unwrap().sessions.len() <= MAX_LIVE_ROOTS);
        }
        assert_eq!(
            limited_poll(&cursor, &roots[MAX_LIVE_ROOTS])
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(
            cursor
                .enumeration
                .lock()
                .unwrap()
                .sessions
                .contains_key(&roots[0])
        );
        assert_eq!(cursor.position(), (None, None));
        let first: Vec<_> = finish(&cursor, &roots[0]).into_iter().collect();
        assert_eq!(first, expected(&roots[0], 300));
        for path in first {
            cursor.advance(&roots[0], &path);
        }
        cursor.complete_root(&roots, &roots[0]);
        let admitted: Vec<_> = finish(&cursor, &roots[MAX_LIVE_ROOTS])
            .into_iter()
            .collect();
        assert_eq!(admitted, expected(&roots[MAX_LIVE_ROOTS], 300));
        assert!(cursor.enumeration.lock().unwrap().sessions.len() <= MAX_LIVE_ROOTS);
    }

    #[test]
    fn forced_reset_drops_read_ahead_and_completed_progress_together() {
        let temp = tempfile::tempdir().unwrap();
        let root = make_root(temp.path(), "root", 600);
        let mut cursor = PrescanCursor::new();
        cursor.advance(&root, &root.join("item-0003"));
        assert!(limited_poll(&cursor, &root).unwrap().is_none());
        cursor.reset();
        assert!(cursor.enumeration.lock().unwrap().sessions.is_empty());
        assert_eq!(
            finish(&cursor, &root).into_iter().collect::<Vec<_>>(),
            expected(&root, 600)
        );
    }

    #[cfg(unix)]
    #[test]
    fn chunked_selection_keeps_non_utf8_names_byte_exact() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let path = |bytes: &[u8]| PathBuf::from(OsString::from_vec(bytes.to_vec()));
        let input = [path(b"/root/\xff"), path(b"/root/a"), path(b"/root/\xfe")];
        let mut selection = Selection::new(input.into_iter().map(Ok), None, 2);
        let (names, more) = selection.poll(&mut || true).unwrap().unwrap();
        assert_eq!(names, vec![path(b"/root/a"), path(b"/root/\xfe")]);
        assert!(more);
    }

    #[test]
    fn existing_daemon_entry_api_yields_and_resumes_without_a_call_site_change() {
        let temp = tempfile::tempdir().unwrap();
        let count = READ_POLL_CHUNKS * READ_CHUNK_ENTRIES + 1;
        let root = make_root(temp.path(), "root", count);
        let roots = vec![root.clone()];
        let mut cursor = PrescanCursor::new();
        let error = cursor.entries_to_visit(&root).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        // This is the daemon's existing error branch. A paused preparation
        // must survive complete_root without claiming a completed sweep.
        cursor.complete_root(&roots, &root);
        assert!(
            cursor
                .enumeration
                .lock()
                .unwrap()
                .sessions
                .contains_key(&root)
        );
        let mut result = None;
        for _ in 0..1024 {
            match cursor.entries_to_visit(&root) {
                Ok(page) => {
                    result = Some(page);
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    cursor.complete_root(&roots, &root);
                }
                Err(error) => panic!("unexpected read failure: {error}"),
            }
        }
        let page = result.expect("preparation must eventually finish");
        assert_eq!(page, expected(&root, count));
        for path in &page {
            cursor.advance(&root, path);
        }
        cursor.complete_root(&roots, &root);
        assert!(cursor.enumeration.lock().unwrap().sessions.is_empty());
        assert_eq!(cursor.position(), (Some(root.as_path()), None));
    }

    #[test]
    fn normal_scratch_constructor_shares_reads_but_never_completed_progress() {
        let temp = tempfile::tempdir().unwrap();
        let root = make_root(temp.path(), "event-project", 600);
        let mut configured = PrescanCursor::new();
        configured.advance(Path::new("/configured"), Path::new("/configured/done"));
        let before = configured.clone();
        let mut observed = None;
        for _ in 0..8 {
            // The actual daemon uses new(), not scoped_read_ahead().
            let mut scratch = PrescanCursor::new();
            assert!(Arc::ptr_eq(&configured.enumeration, &scratch.enumeration));
            assert_eq!(scratch.position(), (None, None));
            if let Some(page) = limited_poll(&scratch, &root).unwrap() {
                let names: Vec<_> = page.into_iter().collect();
                for name in &names {
                    scratch.advance(&root, name);
                }
                scratch.complete_root(std::slice::from_ref(&root), &root);
                observed = Some(names);
                break;
            }
            scratch.complete_root(std::slice::from_ref(&root), &root);
        }
        assert_eq!(observed.unwrap(), expected(&root, 600));
        assert_eq!(configured, before);
    }

    #[test]
    fn read_ahead_pool_does_not_outlive_its_last_cursor() {
        let temp = tempfile::tempdir().unwrap();
        let root = make_root(temp.path(), "root", 300);
        let weak = {
            let cursor = PrescanCursor::new();
            assert!(limited_poll(&cursor, &root).unwrap().is_none());
            Arc::downgrade(&cursor.enumeration)
        };
        assert!(
            weak.upgrade().is_none(),
            "thread-local cache must not retain directory handles"
        );
        let next = PrescanCursor::new();
        assert!(next.enumeration.lock().unwrap().sessions.is_empty());
    }

    #[test]
    fn force_reset_invalidates_shared_reads_without_rewinding_peer_progress() {
        let temp = tempfile::tempdir().unwrap();
        let root = make_root(temp.path(), "root", 300);
        let mut configured = PrescanCursor::new();
        let mut peer = PrescanCursor::new();
        peer.advance(&root, &root.join("item-0001"));
        let before = peer.clone();
        assert!(limited_poll(&peer, &root).unwrap().is_none());
        configured.reset();
        assert!(peer.enumeration.lock().unwrap().sessions.is_empty());
        assert_eq!(peer, before);
        assert_eq!(configured.position(), (None, None));
    }

    #[test]
    fn cyclic_requests_exceeding_the_cache_cover_every_root_without_reader_thrashing() {
        let temp = tempfile::tempdir().unwrap();
        let roots: Vec<_> = (0..MAX_LIVE_ROOTS + 3)
            .map(|n| make_root(temp.path(), &format!("root-{n}"), 600))
            .collect();
        let mut cursor = PrescanCursor::new();
        let mut completed = std::collections::BTreeSet::new();
        let mut admission_waits = 0;
        for _ in 0..32 {
            for root in &roots {
                if completed.contains(root) {
                    continue;
                }
                match limited_poll(&cursor, root) {
                    Ok(Some(page)) => {
                        let paths: Vec<_> = page.into_iter().collect();
                        assert_eq!(paths, expected(root, 600));
                        for path in paths {
                            cursor.advance(root, &path);
                        }
                        assert!(completed.insert(root.clone()));
                    }
                    Ok(None) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        admission_waits += 1;
                    }
                    Err(error) => panic!("unexpected preparation error: {error}"),
                }
                // Both pending branches follow the production error-yield
                // protocol. No pending root is accidentally marked complete.
                cursor.complete_root(&roots, root);
                assert!(cursor.enumeration.lock().unwrap().sessions.len() <= MAX_LIVE_ROOTS);
            }
            if completed.len() == roots.len() {
                break;
            }
        }
        assert!(
            admission_waits > 0,
            "the test must exercise real slot contention"
        );
        assert_eq!(
            completed.len(),
            roots.len(),
            "each root must deliver its entire page"
        );
        assert!(cursor.enumeration.lock().unwrap().sessions.is_empty());
        assert!(cursor.continuations.is_empty());
    }

    #[test]
    fn only_inactive_readers_expire_and_waits_do_not_renew_their_lease() {
        let temp = tempfile::tempdir().unwrap();
        let roots: Vec<_> = (0..=MAX_LIVE_ROOTS)
            .map(|n| make_root(temp.path(), &format!("root-{n}"), 1))
            .collect();
        let now = Instant::now();
        let mut cache = EnumerationCache::default();
        for root in &roots[..MAX_LIVE_ROOTS] {
            cache.prepare_at(root, None, now).unwrap();
        }
        let almost = (now + READER_IDLE_LEASE)
            .checked_sub(Duration::from_nanos(1))
            .unwrap();
        assert_eq!(
            cache
                .prepare_at(&roots[MAX_LIVE_ROOTS], None, almost)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        // Renew the first root. The admission wait above renews no other root.
        cache.prepare_at(&roots[0], None, almost).unwrap();
        cache
            .prepare_at(&roots[MAX_LIVE_ROOTS], None, now + READER_IDLE_LEASE)
            .unwrap();
        assert_eq!(cache.sessions.len(), MAX_LIVE_ROOTS);
        assert!(cache.sessions.contains_key(&roots[0]));
        assert!(!cache.sessions.contains_key(&roots[1]));
        assert!(cache.sessions.contains_key(&roots[MAX_LIVE_ROOTS]));
        for root in &roots {
            assert!(root.join("item-0000").is_dir());
        }
    }

    fn shallow_inspection(path: &Path, depth: usize) -> ShallowDisposition {
        if !path.is_dir() {
            ShallowDisposition::Skip
        } else if path.file_name().is_some_and(|name| name == "target") {
            ShallowDisposition::Candidate
        } else if depth < 3 {
            ShallowDisposition::Descend
        } else {
            ShallowDisposition::Skip
        }
    }

    #[test]
    fn four_ready_outer_pages_cannot_starve_alternating_depth_three_discovery() {
        let temp = tempfile::tempdir().unwrap();
        let roots: Vec<_> = (0..MAX_LIVE_ROOTS)
            .map(|index| {
                let root = temp.path().join(format!("root-{index}"));
                for branch in ["a", "b"] {
                    let directory = root.join("repo").join(branch);
                    fs::create_dir_all(directory.join("target")).unwrap();
                    for entry in 0..300 {
                        fs::write(directory.join(format!("noise-{entry:04}")), []).unwrap();
                    }
                }
                root
            })
            .collect();
        let mut cursor = PrescanCursor::new();
        // Reproduce the original failure: every outer admission is occupied
        // by a completed page before any nested reader is requested.
        for root in &roots {
            assert!(
                cursor
                    .poll_entries_to_visit(root, || true)
                    .unwrap()
                    .is_some()
            );
        }
        let mut completed = std::collections::BTreeSet::new();
        let mut seen = std::collections::BTreeSet::new();
        let mut maximum_handles = 0;
        let mut saw_pending_nested_read = false;
        for _ in 0..1024 {
            for root in &roots {
                if completed.contains(root) {
                    continue;
                }
                let mut checks = 0;
                match cursor
                    .poll_shallow(
                        root,
                        &root.join("repo"),
                        false,
                        || {
                            checks += 1;
                            checks <= 12
                        },
                        shallow_inspection,
                    )
                    .expect("an admitted root owns its two nested slots")
                {
                    ShallowPoll::Candidate(candidate) => {
                        assert!(seen.insert(candidate.path.clone()));
                        cursor.acknowledge_shallow(root, &candidate);
                    }
                    ShallowPoll::Complete => {
                        completed.insert(root.clone());
                    }
                    ShallowPoll::Pending => {}
                }
                let cache = cursor.enumeration.lock().unwrap();
                let handles = cache.sessions.len()
                    + cache
                        .sessions
                        .values()
                        .filter_map(|session| session.nested.as_ref())
                        .map(|nested| nested.pages.sessions.len())
                        .sum::<usize>();
                maximum_handles = maximum_handles.max(handles);
                assert!(handles <= MAX_LIVE_ROOTS * (1 + MAX_NESTED_READERS));
                assert!(handles * PAGE_ENTRIES <= ROOT_ENTRY_CAP);
                saw_pending_nested_read |= cache
                    .sessions
                    .values()
                    .filter_map(|session| session.nested.as_ref())
                    .any(|nested| {
                        nested
                            .pages
                            .sessions
                            .values()
                            .any(|session| session.prepared.is_none())
                    });
            }
            if completed.len() == roots.len() {
                break;
            }
        }
        assert_eq!(
            completed.len(),
            roots.len(),
            "alternating roots must all finish"
        );
        assert_eq!(seen.len(), MAX_LIVE_ROOTS * 2);
        assert!(
            saw_pending_nested_read,
            "the fixture must span partial nested reads"
        );
        assert_eq!(maximum_handles, MAX_LIVE_ROOTS * (1 + MAX_NESTED_READERS));
        assert!(
            cursor
                .enumeration
                .lock()
                .unwrap()
                .sessions
                .values()
                .all(|session| session.nested.is_none())
        );
    }

    #[test]
    fn withdrawing_a_root_releases_its_nested_readers_without_waiting_for_the_lease() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("withdrawn");
        let entry = root.join("repo");
        let retained = temp.path().join("retained");
        fs::create_dir_all(entry.join("branch/target")).unwrap();
        fs::create_dir_all(retained.join("repo/branch/target")).unwrap();
        let mut cursor = PrescanCursor::new();
        let ShallowPoll::Candidate(_) = cursor
            .poll_shallow(&root, &entry, false, || true, shallow_inspection)
            .unwrap()
        else {
            panic!("pending nominee")
        };
        assert_eq!(
            cursor.enumeration.lock().unwrap().sessions[&root]
                .nested
                .as_ref()
                .unwrap()
                .pages
                .sessions
                .len(),
            2
        );
        let before = cursor.clone();
        cursor.release_read_ahead_outside(std::slice::from_ref(&retained));
        assert!(cursor.enumeration.lock().unwrap().sessions.is_empty());
        assert_eq!(
            cursor, before,
            "releasing readers does not certify completed work"
        );
        assert!(matches!(
            cursor
                .poll_shallow(
                    &retained,
                    &retained.join("repo"),
                    false,
                    || true,
                    shallow_inspection
                )
                .unwrap(),
            ShallowPoll::Candidate(_)
        ));
        cursor.reset();
        assert!(
            cursor.enumeration.lock().unwrap().sessions.is_empty(),
            "operator reset also releases nested ownership"
        );
    }
}
