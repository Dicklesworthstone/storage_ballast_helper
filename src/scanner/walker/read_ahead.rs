//! Bounded, speculative directory enumeration across canceled daemon walks.
//!
//! A directory must be listed before its children can be queued: a protection
//! marker may be its final name. Keep that read-only work when a CPU slice ends,
//! including completed pages whose children still need another walk. Cached
//! names are never completion or deletion evidence; every resumed directory is
//! revalidated, and current traversal policy applies again at dispatch.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, Metadata, ReadDir};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::{MAX_ENTRIES_PER_DIR, StructuralSignals};

const MAX_PENDING_READERS: usize = 4;
const MAX_READY_PAGES: usize = 16;
const MAX_READY_CHILDREN: usize = MAX_ENTRIES_PER_DIR as usize;
const MAX_DISPATCH_FRAMES: usize = 16;
const MAX_DISPATCH_CHILDREN: usize = MAX_READY_CHILDREN;
const IDLE_LIFETIME: Duration = Duration::from_hours(1);

thread_local! {
    // Walk workers are short lived; their scanner thread owns the bounded
    // cache. A different scanner thread or a one-shot CLI has its own cache.
    static CACHE: Arc<Mutex<ReadAhead>> = Arc::new(Mutex::new(ReadAhead::default()));
}

pub(super) fn shared() -> Arc<Mutex<ReadAhead>> {
    CACHE.with(Arc::clone)
}

/// One read in progress, or a proven name page waiting for its next traversal.
// These flags record independent observations, not mutually exclusive modes.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug)]
pub(super) struct DirectoryRead {
    pub(super) entries: ReadDir,
    stamp: Metadata,
    window_start: u32,
    window_size: u32,
    follow_symlinks: bool,
    ticket: Option<u64>,
    pub(super) reused: bool,
    pub(super) exhausted: bool,
    pub(super) signals: StructuralSignals,
    pub(super) object_count: u32,
    pub(super) total_count: u32,
    pub(super) content_size: u64,
    pub(super) parent_has_node_manifest: bool,
    pub(super) entries_incomplete: bool,
    // Store basenames rather than repeating a potentially long parent path.
    pub(super) children: Vec<OsString>,
    /// Scheduling priority only: a new walk still visits a whole circular page.
    pub(super) next_child: Arc<AtomicUsize>,
    pub(super) dispatch_interrupted: Arc<AtomicBool>,
    pub(super) observed: Arc<AtomicBool>,
}

impl DirectoryRead {
    pub(super) fn open(
        path: &Path,
        stamp: Metadata,
        start: u32,
        size: u32,
        follow_symlinks: bool,
    ) -> io::Result<Self> {
        Ok(Self {
            entries: fs::read_dir(path)?,
            stamp,
            window_start: start,
            window_size: size,
            follow_symlinks,
            ticket: None,
            reused: false,
            exhausted: false,
            signals: StructuralSignals::default(),
            object_count: 0,
            total_count: 0,
            content_size: 0,
            parent_has_node_manifest: false,
            entries_incomplete: false,
            children: Vec::new(),
            next_child: Arc::new(AtomicUsize::new(0)),
            dispatch_interrupted: Arc::new(AtomicBool::new(false)),
            observed: Arc::new(AtomicBool::new(false)),
        })
    }

    fn matches(&self, stamp: &Metadata, start: u32, size: u32, follow_symlinks: bool) -> bool {
        self.window_start == start
            && self.window_size == size
            && self.follow_symlinks == follow_symlinks
            && self.same_stamp(stamp)
    }

    pub(super) fn same_stamp(&self, stamp: &Metadata) -> bool {
        same_stamp(&self.stamp, stamp)
    }
}

/// A queued child cannot acknowledge its parent merely by being enqueued.
/// Dropping an unhandled receipt opts the page into resumable dispatch.
#[derive(Debug, Clone)]
pub(super) struct ChildProgress {
    priority: Arc<AtomicUsize>,
    interrupted: Arc<AtomicBool>,
    current: usize,
    next: usize,
}

impl ChildProgress {
    pub(super) fn new(read: &DirectoryRead, current: usize) -> Self {
        Self {
            priority: Arc::clone(&read.next_child),
            interrupted: Arc::clone(&read.dispatch_interrupted),
            current,
            next: (current + 1) % read.children.len(),
        }
    }

    pub(super) fn observed(&self) {
        self.priority.store(self.next, Ordering::Relaxed);
    }

    pub(super) fn skipped(&self) {
        // A policy refusal may advance the current priority, but must not
        // jump past an earlier result the consumer has not received yet.
        let _ = self.priority.compare_exchange(
            self.current,
            self.next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    pub(super) fn unfinished(&self) {
        self.interrupted.store(true, Ordering::Relaxed);
    }
}

#[derive(Debug)]
pub(super) struct DispatchReceipt(pub(super) Option<ChildProgress>);

impl DispatchReceipt {
    pub(super) fn new(read: &DirectoryRead, current: usize) -> Self {
        Self(Some(ChildProgress::new(read, current)))
    }

    pub(super) fn handled(mut self) {
        self.0 = None;
    }
}

impl Drop for DispatchReceipt {
    fn drop(&mut self) {
        if let Some(progress) = &self.0 {
            progress.unfinished();
        }
    }
}

/// Count queued and checked-out dispatch pages, including their retained names.
/// Neither a canceled queue nor an unwinding worker can leak its allowance.
pub(super) struct DispatchPermit {
    cache: Arc<Mutex<ReadAhead>>,
    children: usize,
}

impl fmt::Debug for DispatchPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchPermit")
            .field("children", &self.children)
            .finish_non_exhaustive()
    }
}

impl DispatchPermit {
    pub(super) fn reserve(cache: &Arc<Mutex<ReadAhead>>, children: usize) -> Option<Self> {
        let mut reads = cache.lock();
        if reads.dispatch_frames >= MAX_DISPATCH_FRAMES
            || children > MAX_DISPATCH_CHILDREN.saturating_sub(reads.dispatch_children)
        {
            return None;
        }
        reads.dispatch_frames += 1;
        reads.dispatch_children += children;
        Some(Self {
            cache: Arc::clone(cache),
            children,
        })
    }

    pub(super) fn retain(&self, path: &Path, read: DirectoryRead) {
        self.cache.lock().retain(path, read);
    }
}

impl Drop for DispatchPermit {
    fn drop(&mut self) {
        let mut reads = self.cache.lock();
        reads.dispatch_frames -= 1;
        reads.dispatch_children -= self.children;
    }
}

/// Release a reservation if a worker unwinds or forgets to return its reader.
/// A paused reader already returned to the cache keeps its reservation.
pub(super) struct ReadReservation<'a> {
    cache: &'a Mutex<ReadAhead>,
    path: &'a Path,
    ticket: Option<u64>,
}

impl<'a> ReadReservation<'a> {
    pub(super) fn new(cache: &'a Mutex<ReadAhead>, path: &'a Path, read: &DirectoryRead) -> Self {
        Self {
            cache,
            path,
            ticket: read.ticket,
        }
    }
}

impl Drop for ReadReservation<'_> {
    fn drop(&mut self) {
        let Some(ticket) = self.ticket else {
            return;
        };
        let mut cache = self.cache.lock();
        if cache
            .pending
            .get(self.path)
            .is_some_and(|entry| entry.ticket == ticket && entry.read.is_none())
        {
            cache.pending.remove(self.path);
        }
    }
}

fn same_stamp(left: &Metadata, right: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.is_dir()
            && right.is_dir()
            && left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        // Without stable object identity, repeat discovery instead of trusting
        // read-ahead from a path that could now name a different directory.
        let _ = (left, right);
        false
    }
}

struct Pending {
    ticket: u64,
    read: Option<DirectoryRead>,
    touched: Instant,
}

struct Ready {
    read: DirectoryRead,
    touched: Instant,
}

#[derive(Default)]
pub(super) struct ReadAhead {
    pending: HashMap<PathBuf, Pending>,
    ready: HashMap<PathBuf, Ready>,
    ticket: u64,
    dispatch_frames: usize,
    dispatch_children: usize,
}

impl ReadAhead {
    pub(super) fn forget(&mut self, path: &Path) {
        self.ready.remove(path);
        if self
            .pending
            .get(path)
            .is_some_and(|entry| entry.read.is_some())
        {
            self.pending.remove(path);
        }
    }

    fn expire(&mut self, now: Instant) {
        // A checked-out reader owns its reservation even during slow native
        // I/O. Evicting it would allow cyclic scans to thrash every partial
        // read before it can finish.
        self.pending.retain(|_, entry| {
            entry.read.is_none() || now.saturating_duration_since(entry.touched) < IDLE_LIFETIME
        });
        self.ready
            .retain(|_, entry| now.saturating_duration_since(entry.touched) < IDLE_LIFETIME);
    }

    pub(super) fn take(
        &mut self,
        path: &Path,
        stamp: &Metadata,
        start: u32,
        size: u32,
        follow_symlinks: bool,
    ) -> Option<DirectoryRead> {
        self.expire(Instant::now());
        if let Some(entry) = self.pending.get_mut(path)
            && let Some(mut read) = entry.read.take()
        {
            if read.matches(stamp, start, size, follow_symlinks) {
                read.reused = true;
                return Some(read);
            }
            self.pending.remove(path);
        }
        let mut read = self.ready.remove(path)?.read;
        if !read.matches(stamp, start, size, follow_symlinks) {
            return None;
        }
        read.reused = true;
        Some(read)
    }

    pub(super) fn admit(&mut self, path: &Path, read: &mut DirectoryRead) {
        self.expire(Instant::now());
        if read.exhausted
            || read.ticket.is_some()
            || self.pending.len() >= MAX_PENDING_READERS
            || self.pending.contains_key(path)
        {
            return;
        }
        // On wrap, live reservations still have their path as a second key.
        self.ticket = self.ticket.wrapping_add(1);
        read.ticket = Some(self.ticket);
        self.pending.insert(
            path.to_path_buf(),
            Pending {
                ticket: self.ticket,
                read: None,
                touched: Instant::now(),
            },
        );
    }

    pub(super) fn discard(&mut self, path: &Path, read: &DirectoryRead) {
        if read.ticket.is_some_and(|ticket| {
            self.pending
                .get(path)
                .is_some_and(|entry| entry.ticket == ticket)
        }) {
            self.pending.remove(path);
        }
    }

    pub(super) fn retain(&mut self, path: &Path, mut read: DirectoryRead) {
        let now = Instant::now();
        self.expire(now);
        if !read.exhausted {
            if let Some(entry) = self.pending.get_mut(path)
                && read.ticket == Some(entry.ticket)
            {
                entry.read = Some(read);
                entry.touched = now;
            }
            return;
        }
        self.discard(path, &read);
        read.ticket = None;
        // An observation failure may recover without directory membership
        // changing. Retry that page next time instead of caching the gap.
        if read.entries_incomplete {
            return;
        }
        // Never evict an unfinished reader to retain a completed parent.
        // The separate ready-page allowance bounds both retained handles and
        // names; these pages are merely a way to reach unfinished descendants.
        let children = read.children.len();
        if children > MAX_READY_CHILDREN {
            return;
        }
        self.ready.remove(path);
        while self.ready.len() >= MAX_READY_PAGES
            || self
                .ready
                .values()
                .map(|entry| entry.read.children.len())
                .sum::<usize>()
                + children
                > MAX_READY_CHILDREN
        {
            let Some(oldest) = self
                .ready
                .iter()
                .min_by_key(|(_, entry)| entry.touched)
                .map(|(path, _)| path.clone())
            else {
                break;
            };
            self.ready.remove(&oldest);
        }
        self.ready
            .insert(path.to_path_buf(), Ready { read, touched: now });
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn read(path: &Path) -> DirectoryRead {
        DirectoryRead::open(
            path,
            fs::metadata(path).unwrap(),
            0,
            MAX_ENTRIES_PER_DIR,
            false,
        )
        .unwrap()
    }

    #[test]
    fn busy_readers_keep_their_reservations_until_completion() {
        let temp = tempfile::tempdir().unwrap();
        let paths: Vec<_> = (0..5)
            .map(|index| {
                let path = temp.path().join(format!("root-{index}"));
                fs::create_dir(&path).unwrap();
                path
            })
            .collect();
        let mut cache = ReadAhead::default();
        for path in &paths[..4] {
            let mut reader = read(path);
            cache.admit(path, &mut reader);
            assert!(reader.ticket.is_some());
            cache.retain(path, reader);
        }
        let stamp = fs::metadata(&paths[0]).unwrap();
        let mut running = cache
            .take(&paths[0], &stamp, 0, MAX_ENTRIES_PER_DIR, false)
            .unwrap();
        // Attempts to admit a fifth root must not evict or replace a reader
        // merely because it is currently checked out by a worker.
        for _ in 0..8 {
            let mut fifth = read(&paths[4]);
            cache.admit(&paths[4], &mut fifth);
            assert!(fifth.ticket.is_none());
            cache.retain(&paths[4], fifth);
        }
        assert_eq!(cache.pending.len(), 4);
        assert!(cache.pending[&paths[0]].read.is_none());
        running.exhausted = true;
        cache.retain(&paths[0], running);
        let mut fifth = read(&paths[4]);
        cache.admit(&paths[4], &mut fifth);
        assert!(
            fifth.ticket.is_some(),
            "completion releases reader admission"
        );
        cache.retain(&paths[4], fifth);
        assert_eq!(cache.pending.len(), 4);
        assert!(cache.ready.contains_key(&paths[0]));
    }

    #[test]
    fn a_worker_unwind_releases_only_its_checked_out_reservation() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Mutex::new(ReadAhead::default());
        let mut reader = read(temp.path());
        cache.lock().admit(temp.path(), &mut reader);
        {
            let _reservation = ReadReservation::new(&cache, temp.path(), &reader);
            cache.lock().retain(temp.path(), reader);
        }
        assert!(cache.lock().pending[temp.path()].read.is_some());

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let stamp = fs::metadata(temp.path()).unwrap();
            let reader = cache
                .lock()
                .take(temp.path(), &stamp, 0, MAX_ENTRIES_PER_DIR, false)
                .unwrap();
            let _reservation = ReadReservation::new(&cache, temp.path(), &reader);
            panic!("simulate a checked-out worker unwinding");
        }));
        assert!(result.is_err());
        assert!(cache.lock().pending.is_empty());
    }

    #[test]
    fn completed_pages_with_failed_observations_are_retried() {
        let temp = tempfile::tempdir().unwrap();
        let mut cache = ReadAhead::default();
        let mut reader = read(temp.path());
        cache.admit(temp.path(), &mut reader);
        reader.entries_incomplete = true;
        reader.exhausted = true;
        cache.retain(temp.path(), reader);
        assert!(cache.ready.is_empty());
        assert!(cache.pending.is_empty());
        let mut retry = read(temp.path());
        cache.admit(temp.path(), &mut retry);
        assert!(retry.ticket.is_some());
    }

    #[test]
    fn completed_parent_names_have_an_aggregate_bound() {
        let temp = tempfile::tempdir().unwrap();
        let mut cache = ReadAhead::default();
        for index in 0..MAX_READY_PAGES * 2 {
            let path = temp.path().join(format!("parent-{index}"));
            fs::create_dir(&path).unwrap();
            let mut parent = read(&path);
            parent.exhausted = true;
            parent.children = vec![OsString::from("child"); MAX_READY_CHILDREN / 3];
            cache.retain(&path, parent);
            assert!(cache.ready.len() <= MAX_READY_PAGES);
            assert!(
                cache
                    .ready
                    .values()
                    .map(|entry| entry.read.children.len())
                    .sum::<usize>()
                    <= MAX_READY_CHILDREN,
            );
        }
        assert_eq!(cache.ready.len(), 3);
    }

    #[test]
    fn idle_expiry_releases_only_paused_readers() {
        let temp = tempfile::tempdir().unwrap();
        let paused_path = temp.path().join("paused");
        let running_path = temp.path().join("running");
        fs::create_dir(&paused_path).unwrap();
        fs::create_dir(&running_path).unwrap();
        let mut cache = ReadAhead::default();
        let mut paused = read(&paused_path);
        cache.admit(&paused_path, &mut paused);
        cache.retain(&paused_path, paused);
        let mut running = read(&running_path);
        cache.admit(&running_path, &mut running);
        cache.expire(Instant::now() + IDLE_LIFETIME);
        assert!(!cache.pending.contains_key(&paused_path));
        assert!(cache.pending.contains_key(&running_path));
        cache.discard(&running_path, &running);
        assert!(cache.pending.is_empty());
    }

    #[test]
    fn queued_dispatch_frames_have_count_and_aggregate_name_bounds() {
        let cache = Arc::new(Mutex::new(ReadAhead::default()));
        let permits: Vec<_> = (0..MAX_DISPATCH_FRAMES)
            .map(|_| DispatchPermit::reserve(&cache, 1).unwrap())
            .collect();
        assert!(DispatchPermit::reserve(&cache, 1).is_none());
        drop(permits);
        assert_eq!(cache.lock().dispatch_frames, 0);
        assert_eq!(cache.lock().dispatch_children, 0);

        let full = DispatchPermit::reserve(&cache, MAX_DISPATCH_CHILDREN).unwrap();
        assert!(DispatchPermit::reserve(&cache, 1).is_none());
        drop(full);
        assert!(DispatchPermit::reserve(&cache, MAX_DISPATCH_CHILDREN).is_some());
    }
}
