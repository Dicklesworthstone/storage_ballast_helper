//! Recoverable Linux event coverage with a bounded monitor-thread drain.
//!
//! inotify is not recursive. A created/moved directory can already contain
//! descendants by the time its event is read. Install its immediate watch,
//! revoke coverage, and let the source's timed replan discover the whole tree.
//! Lost or renamed watches are retired instead of consuming the budget forever.
//! Descriptor and path indexes keep registration logarithmic and restrict
//! subtree retirement to affected watches, not the entire recursive watch set.
//! Revocation is immediate; physical watch retirement shares the event drain's
//! work and time budget rather than issuing thousands of removals in one event.

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use inotify::{EventMask, WatchDescriptor, WatchMask};

use super::{
    DirtyRootTracker, EventInvalidation, EventRateTracker, EventSourceConfig, FsEvent,
    FsEventKind, OverflowBackoff, OverflowDecision,
};

const EVENT_BUFFER_BYTES: usize = 64 * 1024;
const MAX_EVENTS_PER_DRAIN: usize = 4096;
const MAX_DIRTY_PATHS_PER_DRAIN: usize = 512;
const DRAIN_TIME: Duration = Duration::from_millis(50);

#[derive(Clone, Copy)]
struct DrainBudget {
    // Events and retirement steps consume the same bounded work allowance.
    events: usize,
    dirty_paths: usize,
    time: Duration,
}

impl Default for DrainBudget {
    fn default() -> Self {
        Self {
            events: MAX_EVENTS_PER_DRAIN,
            dirty_paths: MAX_DIRTY_PATHS_PER_DRAIN,
            time: DRAIN_TIME,
        }
    }
}

#[derive(Debug)]
pub(super) struct LinuxInotifyBackend {
    inotify: inotify::Inotify,
    watch_paths: BTreeMap<WatchDescriptor, PathBuf>,
    // Reverse index: startup must not search every prior watch for each path,
    // and a topology event must not scan unrelated projects' watches.
    path_watches: BTreeMap<PathBuf, WatchDescriptor>,
    // Coalesced revoked prefixes. Their physical watches still count against
    // max_watches until a bounded retirement step releases them. No pathname
    // under these prefixes is live event evidence in the meantime.
    retiring_roots: BTreeMap<PathBuf, ()>,
    // Preserve alternation across calls, including a deadline that permits
    // only one work unit. Restarting every drain with cleanup starves events.
    retirement_turn: bool,
    buffer: Vec<u8>,
    // At most one kernel-read batch. A budget stop preserves the unprocessed
    // suffix; it must not be thrown away when the monitor gets its turn back.
    pending_events: VecDeque<LinuxInotifyEvent>,
    max_watches: usize,
    repair_required: bool,
}

#[derive(Debug)]
struct LinuxInotifyEvent {
    watch: WatchDescriptor,
    mask: EventMask,
    name: Option<PathBuf>,
}

impl LinuxInotifyBackend {
    pub(super) fn start(paths: &[PathBuf], max_watches: usize) -> io::Result<Self> {
        // Inotify::init uses IN_NONBLOCK and IN_CLOEXEC. Never use the crate's
        // blocking read API from the daemon's monitoring thread.
        let mut backend = Self {
            inotify: inotify::Inotify::init()?,
            watch_paths: BTreeMap::new(),
            path_watches: BTreeMap::new(),
            retiring_roots: BTreeMap::new(),
            retirement_turn: true,
            buffer: vec![0; EVENT_BUFFER_BYTES],
            pending_events: VecDeque::new(),
            max_watches,
            repair_required: false,
        };
        for path in paths {
            backend.add_watch(path)?;
        }
        Ok(backend)
    }

    pub(super) fn watched_dirs(&self) -> impl Iterator<Item = &Path> {
        self.watch_paths
            .values()
            .filter(move |path| !self.path_is_retiring(path))
            .map(PathBuf::as_path)
    }

    pub(super) fn needs_repair(&self) -> bool {
        self.repair_required
    }

    pub(super) fn require_repair(&mut self) {
        self.repair_required = true;
    }

    pub(super) fn drain(
        &mut self,
        tracker: &DirtyRootTracker,
        config: &EventSourceConfig,
        rates: &mut EventRateTracker,
        backoff: &mut OverflowBackoff,
        now: Instant,
    ) -> EventInvalidation {
        self.drain_with_budget(tracker, config, rates, backoff, now, DrainBudget::default(), Instant::now)
    }

    #[allow(clippy::too_many_arguments)]
    fn drain_with_budget(
        &mut self,
        tracker: &DirtyRootTracker,
        config: &EventSourceConfig,
        rates: &mut EventRateTracker,
        backoff: &mut OverflowBackoff,
        now: Instant,
        budget: DrainBudget,
        mut clock: impl FnMut() -> Instant,
    ) -> EventInvalidation {
        let started = clock();
        let mut handled = 0;
        let mut collapsed = false;
        let mut invalidation = EventInvalidation::empty();
        loop {
            if handled >= budget.events || clock().saturating_duration_since(started) >= budget.time {
                self.require_repair();
                invalidation.mark_all_roots(config.root_paths(), "recursive inotify drain budget exhausted", true);
                break;
            }
            // Alternate cleanup with incoming events. Neither a large removed
            // tree nor a continuous event stream may starve the other. The
            // deadline above covers every removal, not just the next event.
            if self.retirement_turn && !self.retiring_roots.is_empty() {
                self.retire_one(rates);
                handled += 1;
                self.retirement_turn = false;
                continue;
            }
            self.retirement_turn = true;
            if self.pending_events.is_empty() {
                match self.read_event_batch() {
                    Ok(()) if self.pending_events.is_empty() => {
                        if self.retiring_roots.is_empty() {
                            break;
                        }
                        continue;
                    }
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if self.retiring_roots.is_empty() {
                            break;
                        }
                        continue;
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        self.require_repair();
                        invalidation.mark_all_roots(
                            config.root_paths(),
                            format!("recursive inotify read failed: {error}"),
                            true,
                        );
                        break;
                    }
                }
                // The read itself belongs to the budget. Retain its batch if
                // descheduling or kernel work consumed the remaining time.
                if clock().saturating_duration_since(started) >= budget.time {
                    self.require_repair();
                    invalidation.mark_all_roots(config.root_paths(), "recursive inotify drain budget exhausted", true);
                    break;
                }
            }
            let Some(event) = self.pending_events.pop_front() else { break };
            handled += 1;
            let mut next = self.handle_event(tracker, config, rates, backoff, now, &event);
            if collapsed {
                next.dirty_paths.clear();
                next.dirty_roots.clear();
            }
            invalidation.merge(next);
            if !collapsed && invalidation.dirty_paths.len() > budget.dirty_paths {
                // Drop only precision, never coverage. Bounded invalidation
                // memory also bounds the subsequent project-root mapping work.
                invalidation.dirty_paths.clear();
                invalidation.dirty_roots.clear();
                invalidation.mark_all_roots(config.root_paths(), "recursive inotify dirty-path budget exceeded", true);
                collapsed = true;
            }
        }
        invalidation
    }

    fn read_event_batch(&mut self) -> io::Result<()> {
        let events = self.inotify.read_events(&mut self.buffer)?;
        self.pending_events.extend(events.map(|event| LinuxInotifyEvent {
            watch: event.wd,
            mask: event.mask,
            name: event.name.map(PathBuf::from),
        }));
        Ok(())
    }

    fn handle_event(
        &mut self,
        tracker: &DirtyRootTracker,
        config: &EventSourceConfig,
        rates: &mut EventRateTracker,
        backoff: &mut OverflowBackoff,
        now: Instant,
        event: &LinuxInotifyEvent,
    ) -> EventInvalidation {
        if event.mask.contains(EventMask::Q_OVERFLOW) {
            // Lost CREATE/RENAME/IGNORED events can invalidate the watch tree
            // itself, not merely the candidate index.
            self.require_repair();
            return match backoff.record(now) {
                OverflowDecision::Reconcile { .. } => tracker.apply_event(FsEvent {
                    kind: FsEventKind::Overflow,
                    path: None,
                }),
                OverflowDecision::Coalesced { .. } => EventInvalidation::deferred_overflow(),
            };
        }

        let Some(base) = self.watch_paths.get(&event.watch).cloned() else {
            // Explicit removals enqueue IGNORED after we retire their mapping.
            // Never attach such a stale event to a newly named directory.
            if event.mask.contains(EventMask::IGNORED) {
                return EventInvalidation::empty();
            }
            self.require_repair();
            let mut invalidation = EventInvalidation::empty();
            invalidation.mark_all_roots(config.root_paths(), "recursive inotify event has no live watch", true);
            return invalidation;
        };
        if self.path_is_retiring(&base) {
            if event.mask.contains(EventMask::IGNORED) {
                // The kernel already released this watch. Retire its metadata
                // as this event's bounded work unit, without another syscall.
                self.watch_paths.remove(&event.watch);
                self.path_watches.remove(&base);
                rates.rates.remove(&base);
                return EventInvalidation::empty();
            }
            // A queued event must not revive a moved subtree's old path, grow
            // its rate history, or install watches below that obsolete name.
            return tracker.apply_event(FsEvent {
                kind: FsEventKind::PermissionLost,
                path: Some(base),
            });
        }
        rates.record(&base, now);
        let path = event.name.as_ref().map_or_else(|| base.clone(), |name| base.join(name));
        if event.mask.intersects(EventMask::IGNORED | EventMask::UNMOUNT | EventMask::DELETE_SELF | EventMask::MOVE_SELF) {
            // Every descendant's stored pathname also became untrustworthy.
            self.forget_subtree(&base, rates);
            self.require_repair();
            return tracker.apply_event(FsEvent {
                kind: FsEventKind::PermissionLost,
                path: Some(base),
            });
        }

        let mut invalidation = tracker.apply_event(FsEvent {
            kind: event_kind(event.mask),
            path: Some(path.clone()),
        });
        if event.mask.contains(EventMask::ISDIR)
            && event.mask.intersects(EventMask::CREATE | EventMask::MOVED_TO | EventMask::DELETE | EventMask::MOVED_FROM)
        {
            self.require_repair();
            invalidation.generation_bump = true;
            invalidation.reasons.insert("recursive inotify directory topology changed".to_string());
            if event.mask.intersects(EventMask::DELETE | EventMask::MOVED_FROM) {
                self.forget_subtree(&path, rates);
            }
            if event.mask.intersects(EventMask::CREATE | EventMask::MOVED_TO) {
                // The directory might already contain arbitrarily many nested
                // directories. Do not recursively enumerate them in a drain:
                // report the gap and close it in the paced watch-plan repair.
                if self.watch_paths.len() >= self.max_watches {
                    invalidation.merge(tracker.apply_event(FsEvent {
                        kind: FsEventKind::WatchBudgetExceeded,
                        path: Some(path),
                    }));
                } else if let Err(error) = self.add_watch(&path) {
                    invalidation.mark_dirty_path(
                        config.root_paths(),
                        &path,
                        format!("recursive inotify add-watch failed: {error}"),
                    );
                }
            }
        }
        invalidation
    }

    fn path_is_retiring(&self, path: &Path) -> bool {
        // Quiet steady state must not walk every path's ancestors merely to
        // discover there is no retirement work at all.
        !self.retiring_roots.is_empty()
            && path.ancestors().any(|ancestor| self.retiring_roots.contains_key(ancestor))
    }

    fn forget_subtree(&mut self, path: &Path, rates: &mut EventRateTracker) {
        if self.path_is_retiring(path) {
            return;
        }
        // Admit only prefixes with retained state. Unwatched directory churn
        // cannot grow a queue of empty retirement jobs without bound.
        if first_subtree_path(&self.path_watches, path).is_none()
            && first_subtree_path(&rates.rates, path).is_none()
        {
            return;
        }
        // A parent revocation subsumes previously queued descendants. No
        // physical watch or rate-history walk takes place in this event.
        drop(remove_subtree_entries(&mut self.retiring_roots, path));
        self.retiring_roots.insert(path.to_path_buf(), ());
        self.require_repair();
    }

    fn retire_one(&mut self, rates: &mut EventRateTracker) {
        let Some(root) = self.retiring_roots.first_key_value().map(|(root, _)| root.clone()) else {
            return;
        };
        if let Some(path) = first_subtree_path(&self.path_watches, &root) {
            if let Some(watch) = self.path_watches.remove(&path) {
                self.watch_paths.remove(&watch);
                rates.rates.remove(&path);
                // IGNORED/UNMOUNT may have removed the watch already. Failure
                // cannot restore pathname authority; repair replaces the fd.
                let _ = self.inotify.watches().remove(watch);
            }
        } else if let Some(path) = first_subtree_path(&rates.rates, &root) {
            // Historical rate entries need not have a current watch. Their
            // cleanup is incremental too, under the same work/time budget.
            rates.rates.remove(&path);
        } else {
            self.retiring_roots.remove(&root);
        }
    }

    fn add_watch(&mut self, path: &Path) -> io::Result<()> {
        if self.path_is_retiring(path) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "recursive inotify subtree is awaiting bounded retirement",
            ));
        }
        if self.path_watches.contains_key(path) {
            return Ok(());
        }
        // Includes revoked watches not yet physically retired. Delayed cleanup
        // must not turn max_watches into an advisory rather than a hard limit.
        if self.watch_paths.len() >= self.max_watches {
            return Err(io::Error::other("recursive inotify watch budget exhausted"));
        }
        let watch = self.inotify.watches().add(path, watch_mask())?;
        if self.watch_paths.get(&watch).is_some_and(|previous| previous != path) {
            // inotify watches inodes, so two aliases may yield the same watch.
            // A single-path map cannot promise coverage of both spellings.
            self.require_repair();
            return Err(io::Error::other("recursive inotify watch aliases an existing directory"));
        }
        self.path_watches.insert(path.to_path_buf(), watch.clone());
        self.watch_paths.insert(watch, path.to_path_buf());
        Ok(())
    }
}

fn first_subtree_path<T>(entries: &BTreeMap<PathBuf, T>, root: &Path) -> Option<PathBuf> {
    entries
        .range(root.to_path_buf()..)
        .next()
        .filter(|(path, _)| path.starts_with(root))
        .map(|(path, _)| path.clone())
}

// Path ordering compares components, so a subtree occupies one contiguous
// ordered range. `starts_with` is component-aware: /cache/a-other is not a
// descendant of /cache/a. Only matching keys are cloned, even if the root
// itself has no entry. No canonicalization, filesystem I/O, or UTF-8 conversion.
fn remove_subtree_entries<T>(entries: &mut BTreeMap<PathBuf, T>, root: &Path) -> Vec<T> {
    let paths: Vec<_> = entries
        .range(root.to_path_buf()..)
        .take_while(|(path, _)| path.starts_with(root))
        .map(|(path, _)| path.clone())
        .collect();
    paths.into_iter().filter_map(|path| entries.remove(&path)).collect()
}

fn watch_mask() -> WatchMask {
    WatchMask::ATTRIB
        | WatchMask::CLOSE_WRITE
        | WatchMask::CREATE
        | WatchMask::DELETE
        | WatchMask::DELETE_SELF
        | WatchMask::DONT_FOLLOW
        | WatchMask::EXCL_UNLINK
        | WatchMask::MODIFY
        | WatchMask::MOVE
        | WatchMask::MOVE_SELF
        | WatchMask::ONLYDIR
}

fn event_kind(mask: EventMask) -> FsEventKind {
    if mask.intersects(EventMask::DELETE | EventMask::DELETE_SELF) {
        FsEventKind::Remove
    } else if mask.intersects(EventMask::MOVED_FROM | EventMask::MOVED_TO | EventMask::MOVE_SELF) {
        FsEventKind::Rename
    } else if mask.contains(EventMask::CREATE) {
        FsEventKind::Create
    } else {
        FsEventKind::Modify
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use crate::core::config::ScannerConfig;
    use crate::scanner::events::{EventBackendKind, ScannerEventSource, WATCH_REPAIR_INTERVAL, WATCH_REPLAN_INTERVAL};
    use crate::scanner::index::{
        CandidateIndexRecord, CandidateSafetyState, IndexedEntryKind, IndexedIdentity,
        IndexedPruneDecision, ScannerCandidateIndex, ScannerIndexContext,
    };
    use crate::scanner::patterns::StructuralSignals;

    fn fixture() -> (tempfile::TempDir, EventSourceConfig) {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap().join("root");
        fs::create_dir(&root).unwrap();
        let config = EventSourceConfig::from_scanner_config(&[root], &ScannerConfig {
            event_watch_budget: 16,
            ..ScannerConfig::default()
        });
        (temp, config)
    }

    fn event(backend: &LinuxInotifyBackend, base: &Path, mask: EventMask, name: Option<&str>) -> LinuxInotifyEvent {
        LinuxInotifyEvent {
            watch: backend.watch_paths.iter().find(|(_, path)| path.as_path() == base).unwrap().0.clone(),
            mask,
            name: name.map(PathBuf::from),
        }
    }

    fn handle(backend: &mut LinuxInotifyBackend, config: &EventSourceConfig, event: &LinuxInotifyEvent) -> EventInvalidation {
        backend.handle_event(
            &DirtyRootTracker::new(config.root_paths()), config,
            &mut EventRateTracker::default(), &mut OverflowBackoff::default(), Instant::now(), event,
        )
    }

    fn drain(backend: &mut LinuxInotifyBackend, config: &EventSourceConfig, budget: DrainBudget) -> EventInvalidation {
        let now = Instant::now();
        backend.drain_with_budget(
            &DirtyRootTracker::new(config.root_paths()), config,
            &mut EventRateTracker::default(), &mut OverflowBackoff::default(), now, budget, || now,
        )
    }

    fn finish_retirements(backend: &mut LinuxInotifyBackend, rates: &mut EventRateTracker) {
        while !backend.retiring_roots.is_empty() {
            let before = backend.watch_paths.len() + rates.rates.len() + backend.retiring_roots.len();
            backend.retire_one(rates);
            let after = backend.watch_paths.len() + rates.rates.len() + backend.retiring_roots.len();
            assert!(after < before, "each retirement step must make progress");
        }
    }

    #[test]
    fn start_enforces_the_watch_budget_instead_of_only_trusting_the_plan() {
        let (_temp, config) = fixture();
        let root = &config.root_paths()[0];
        fs::create_dir(root.join("child")).unwrap();
        assert!(LinuxInotifyBackend::start(&[root.clone(), root.join("child")], 1).is_err());
        assert!(LinuxInotifyBackend::start(std::slice::from_ref(root), 0).is_err());
        let backend = LinuxInotifyBackend::start(&[root.clone(), root.clone()], 1).unwrap();
        assert_eq!(backend.watched_dirs().count(), 1);
    }

    #[test]
    fn moved_subtree_retires_descendant_bindings_without_touching_siblings() {
        let (_temp, config) = fixture();
        let root = &config.root_paths()[0];
        let child = root.join("child");
        let deep = child.join("deep");
        let sibling = root.join("child-other");
        fs::create_dir_all(&deep).unwrap();
        fs::create_dir(&sibling).unwrap();
        let mut backend = LinuxInotifyBackend::start(&[root.clone(), child.clone(), deep, sibling.clone()], 4).unwrap();
        let changed = event(&backend, root, EventMask::MOVED_FROM | EventMask::ISDIR, Some("child"));
        let invalidation = handle(&mut backend, &config, &changed);
        assert!(invalidation.requires_index_generation_bump());
        assert!(backend.needs_repair());
        assert_eq!(backend.watched_dirs().count(), 2);
        assert!(backend.watched_dirs().any(|path| path == sibling));
        assert!(!backend.watched_dirs().any(|path| path.starts_with(&child)));
        assert!(child.is_dir(), "handling an event must not delete filesystem data");
    }

    #[test]
    fn ignored_watches_release_the_budget_and_repeated_ignored_events_are_harmless() {
        let (_temp, config) = fixture();
        let root = &config.root_paths()[0];
        let mut backend = LinuxInotifyBackend::start(std::slice::from_ref(root), 1).unwrap();
        let ignored = event(&backend, root, EventMask::IGNORED, None);
        let invalidation = handle(&mut backend, &config, &ignored);
        assert!(invalidation.requires_index_generation_bump());
        assert_eq!(backend.watched_dirs().count(), 0);
        assert!(!handle(&mut backend, &config, &ignored).requires_reconciliation());
        assert!(backend.add_watch(root).is_err());
        finish_retirements(&mut backend, &mut EventRateTracker::default());
        backend.add_watch(root).unwrap();
        assert_eq!(backend.watched_dirs().count(), 1);
    }

    #[test]
    fn self_move_invalidates_the_entire_descendant_path_mapping() {
        let (_temp, config) = fixture();
        let root = &config.root_paths()[0];
        let child = root.join("deep");
        fs::create_dir(&child).unwrap();
        let mut backend = LinuxInotifyBackend::start(&[root.clone(), child], 2).unwrap();
        let changed = event(&backend, root, EventMask::MOVE_SELF, None);
        let invalidation = handle(&mut backend, &config, &changed);
        assert_eq!(backend.watched_dirs().count(), 0);
        assert!(invalidation.dirty_roots().contains(root));
        assert!(invalidation.requires_index_generation_bump());
    }

    #[test]
    fn new_populated_directory_cannot_claim_recursive_coverage_from_one_watch() {
        let (_temp, config) = fixture();
        let root = &config.root_paths()[0];
        let mut backend = LinuxInotifyBackend::start(std::slice::from_ref(root), 16).unwrap();
        fs::create_dir_all(root.join("new/deep/deeper")).unwrap();
        let created = event(&backend, root, EventMask::CREATE | EventMask::ISDIR, Some("new"));
        let invalidation = handle(&mut backend, &config, &created);
        assert!(backend.needs_repair());
        assert!(invalidation.requires_index_generation_bump());
        assert_eq!(backend.watched_dirs().count(), 2);
        assert!(invalidation.dirty_paths().contains(&root.join("new")));
    }

    #[test]
    fn failed_dynamic_watch_preserves_the_gap_and_never_follows_a_symlink() {
        let (temp, config) = fixture();
        let root = &config.root_paths()[0];
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let mut backend = LinuxInotifyBackend::start(std::slice::from_ref(root), 16).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("new")).unwrap();
        let created = event(&backend, root, EventMask::CREATE | EventMask::ISDIR, Some("new"));
        let invalidation = handle(&mut backend, &config, &created);
        assert!(invalidation.reason_summary().contains("add-watch failed"));
        assert!(invalidation.requires_index_generation_bump());
        assert!(backend.needs_repair());
        assert_eq!(backend.watched_dirs().count(), 1);
        assert!(outside.is_dir());
    }

    #[test]
    fn coalesced_overflow_revokes_a_candidate_reconciled_after_the_first_loss() {
        let (_temp, config) = fixture();
        let root = &config.root_paths()[0];
        let mut backend = LinuxInotifyBackend::start(std::slice::from_ref(root), 16).unwrap();
        let overflow = event(&backend, root, EventMask::Q_OVERFLOW, None);
        let tracker = DirtyRootTracker::new(config.root_paths());
        let mut rates = EventRateTracker::default();
        let mut backoff = OverflowBackoff::default();
        let now = Instant::now();
        let mut index = ScannerCandidateIndex::new(ScannerIndexContext {
            root_fingerprint: "watch-root".into(), config_fingerprint: "watch-config".into(),
        });
        backend.handle_event(&tracker, &config, &mut rates, &mut backoff, now, &overflow).apply_to_index(&mut index);
        index.upsert(CandidateIndexRecord {
            path: root.join("target"),
            identity: IndexedIdentity { device_id: 1, inode: 2, kind: IndexedEntryKind::Directory },
            parent_identity: None,
            parent_mtime_nanos: None,
            candidate_mtime_nanos: 0,
            candidate_ctime_nanos: None,
            size_estimate_bytes: 1024,
            prune_decision: IndexedPruneDecision::CandidateOpaque,
            score: Some(0.9),
            safety_state: CandidateSafetyState::Safe,
            fail_count: 0,
            cooldown_until_nanos: None,
            event_generation: 0,
            structural_signals: StructuralSignals::default(),
        });
        assert_eq!(index.ranked_records(std::time::UNIX_EPOCH, 1).len(), 1);
        let coalesced = backend.handle_event(&tracker, &config, &mut rates, &mut backoff, now + Duration::from_secs(1), &overflow);
        assert!(!coalesced.requires_reconciliation(), "expensive scans remain deferred");
        coalesced.apply_to_index(&mut index);
        assert!(index.ranked_records(std::time::UNIX_EPOCH, 1).is_empty());
        assert_eq!(backoff.total(), 2);
        assert_eq!(backoff.coalesced(), 1);
    }

    #[test]
    fn count_budget_preserves_the_unhandled_suffix_for_later_drains() {
        let (_temp, config) = fixture();
        let root = &config.root_paths()[0];
        let mut backend = LinuxInotifyBackend::start(std::slice::from_ref(root), 16).unwrap();
        for n in 0..7 {
            let next = event(&backend, root, EventMask::MODIFY, Some(&format!("item-{n}")));
            backend.pending_events.push_back(next);
        }
        let budget = DrainBudget { events: 3, ..DrainBudget::default() };
        let first = drain(&mut backend, &config, budget);
        assert_eq!(backend.pending_events.len(), 4);
        assert_eq!(first.dirty_paths().len(), 3);
        assert!(first.requires_index_generation_bump());
        let second = drain(&mut backend, &config, budget);
        assert_eq!(backend.pending_events.len(), 1);
        assert_eq!(second.dirty_paths().len(), 3);
        let third = drain(&mut backend, &config, budget);
        assert!(backend.pending_events.is_empty());
        assert_eq!(third.dirty_paths().len(), 1);
        let mut union = first.dirty_paths().clone();
        union.extend(second.dirty_paths().iter().cloned());
        union.extend(third.dirty_paths().iter().cloned());
        assert_eq!(union.len(), 7, "no buffered event may vanish at a budget stop");
    }

    #[test]
    fn one_deadline_covers_all_event_progress() {
        let (_temp, config) = fixture();
        let root = &config.root_paths()[0];
        let mut backend = LinuxInotifyBackend::start(std::slice::from_ref(root), 16).unwrap();
        for n in 0..5 {
            let next = event(&backend, root, EventMask::MODIFY, Some(&format!("item-{n}")));
            backend.pending_events.push_back(next);
        }
        let now = Instant::now();
        let mut step = 0;
        let invalidation = backend.drain_with_budget(
            &DirtyRootTracker::new(config.root_paths()), &config,
            &mut EventRateTracker::default(), &mut OverflowBackoff::default(), now,
            DrainBudget { time: Duration::from_millis(2), ..DrainBudget::default() },
            || { let time = now + Duration::from_millis(step); step += 1; time },
        );
        assert_eq!(backend.pending_events.len(), 4);
        assert_eq!(invalidation.dirty_paths().len(), 1);
        assert!(invalidation.requires_index_generation_bump());
        assert!(backend.needs_repair());
    }

    #[test]
    fn high_cardinality_events_collapse_to_root_coverage_not_unbounded_paths() {
        let (_temp, config) = fixture();
        let root = &config.root_paths()[0];
        let mut backend = LinuxInotifyBackend::start(std::slice::from_ref(root), 16).unwrap();
        for n in 0..20 {
            let next = event(&backend, root, EventMask::MODIFY, Some(&format!("item-{n}")));
            backend.pending_events.push_back(next);
        }
        let invalidation = drain(&mut backend, &config, DrainBudget { dirty_paths: 3, ..DrainBudget::default() });
        assert!(backend.pending_events.is_empty());
        assert!(invalidation.dirty_paths().is_empty());
        assert!(invalidation.dirty_roots().contains(root));
        assert!(invalidation.requires_index_generation_bump());
    }

    #[test]
    fn a_quiet_nonblocking_drain_does_not_invent_coverage_loss() {
        let (_temp, config) = fixture();
        let root = &config.root_paths()[0];
        let mut backend = LinuxInotifyBackend::start(std::slice::from_ref(root), 16).unwrap();
        let invalidation = drain(&mut backend, &config, DrainBudget::default());
        assert!(!invalidation.requires_reconciliation());
        assert!(!invalidation.requires_index_generation_bump());
        assert!(!backend.needs_repair());
    }

    #[test]
    fn retired_watch_paths_do_not_accumulate_in_rate_history() {
        let (_temp, config) = fixture();
        let root = &config.root_paths()[0];
        let child = root.join("child");
        fs::create_dir(&child).unwrap();
        let mut backend = LinuxInotifyBackend::start(&[root.clone(), child.clone()], 2).unwrap();
        let now = Instant::now();
        let mut rates = EventRateTracker::default();
        rates.record(root, now);
        rates.record(&child, now);
        let removed = event(&backend, root, EventMask::DELETE | EventMask::ISDIR, Some("child"));
        backend.handle_event(&DirtyRootTracker::new(config.root_paths()), &config, &mut rates, &mut OverflowBackoff::default(), now, &removed);
        finish_retirements(&mut backend, &mut rates);
        assert_eq!(rates.tracked_dirs(), 1);
        assert!(rates.rate(root, now) > 0.0);
        assert_eq!(rates.rate(&child, now), 0.0);
    }

    #[test]
    fn recovery_retries_without_traffic_and_audits_quiet_complete_plans() {
        let (_temp, config) = fixture();
        let now = Instant::now();
        let mut source = ScannerEventSource::start_at(config, now);
        assert_eq!(source.capability().selected_backend, EventBackendKind::RecursiveInotify);
        assert!(!source.should_replan(now + WATCH_REPAIR_INTERVAL));
        assert!(source.should_replan(now + WATCH_REPLAN_INTERVAL));
        if let super::super::EventSourceBackend::RecursiveInotify(backend) = &mut source.backend {
            backend.require_repair();
        }
        assert!(!source.should_replan(now + WATCH_REPAIR_INTERVAL - Duration::from_nanos(1)));
        assert!(source.should_replan(now + WATCH_REPAIR_INTERVAL));
        let repaired = source.drain_at(now + WATCH_REPAIR_INTERVAL);
        assert!(repaired.requires_index_generation_bump());
        assert_eq!(source.stats().replans, 1);
        assert!(source.capability().complete);
        assert!(!source.should_replan(now + WATCH_REPAIR_INTERVAL * 2));
    }

    #[test]
    fn explicit_reconciliation_and_zero_budgets_never_restart_a_kernel_backend() {
        let (_temp, config) = fixture();
        let now = Instant::now();
        for scanner in [
            ScannerConfig { event_source: crate::core::config::ScannerEventSourceMode::ReconciliationOnly, ..ScannerConfig::default() },
            ScannerConfig { event_watch_budget: 0, ..ScannerConfig::default() },
        ] {
            let source = ScannerEventSource::start_at(EventSourceConfig::from_scanner_config(config.root_paths(), &scanner), now);
            assert!(!source.should_replan(now + Duration::from_hours(24)));
            assert_eq!(source.capability().selected_backend, EventBackendKind::ReconciliationOnly);
        }
    }

    #[test]
    fn subtree_range_preserves_prefix_siblings_and_unrelated_projects() {
        let mut entries = BTreeMap::new();
        for n in 0..16_384 {
            entries.insert(PathBuf::from(format!("/cache/project-{n:05}/target")), n);
        }
        entries.insert(PathBuf::from("/cache/project-00007/target/deep"), 20_000);
        entries.insert(PathBuf::from("/cache/project-00007/target-other"), 20_001);
        entries.insert(PathBuf::from("/cache/project-00007/target.other"), 20_002);
        let removed = remove_subtree_entries(&mut entries, Path::new("/cache/project-00007/target"));
        assert_eq!(removed, vec![7, 20_000]);
        assert_eq!(entries.len(), 16_385);
        assert!(entries.contains_key(Path::new("/cache/project-00007/target-other")));
        assert!(entries.contains_key(Path::new("/cache/project-00007/target.other")));
        assert!(remove_subtree_entries(&mut entries, Path::new("/missing")).is_empty());
    }

    #[test]
    fn subtree_range_handles_unwatched_ancestors_and_non_utf8_paths() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let root = PathBuf::from("/cache").join(OsString::from_vec(vec![b'a', 0xff]));
        let sibling = PathBuf::from("/cache").join(OsString::from_vec(vec![b'a', 0xff, b'-']));
        let mut entries = BTreeMap::from([
            (root.join("one"), 1),
            (root.join("two/deep"), 2),
            (sibling.clone(), 3),
        ]);
        assert_eq!(remove_subtree_entries(&mut entries, &root), vec![1, 2]);
        assert_eq!(entries, BTreeMap::from([(sibling, 3)]));
    }

    #[test]
    fn both_watch_indexes_remain_consistent_through_repeated_subtree_churn() {
        let (_temp, config) = fixture();
        let root = &config.root_paths()[0];
        let group = root.join("group");
        let sibling = root.join("group-other");
        fs::create_dir(&sibling).unwrap();
        let mut backend = LinuxInotifyBackend::start(&[root.clone(), sibling.clone()], 8).unwrap();
        let mut rates = EventRateTracker::default();
        for _ in 0..32 {
            for n in 0..6 {
                let child = group.join(format!("child-{n}"));
                fs::create_dir_all(&child).unwrap();
                backend.add_watch(&child).unwrap();
                backend.add_watch(&child).unwrap();
                rates.record(&child, Instant::now());
            }
            assert_eq!(backend.watch_paths.len(), 8);
            assert_eq!(backend.path_watches.len(), 8);
            for (watch, path) in &backend.watch_paths {
                assert_eq!(backend.path_watches.get(path), Some(watch));
            }
            backend.forget_subtree(&group, &mut rates);
            assert_eq!(backend.watched_dirs().count(), 2, "revocation is immediate");
            assert_eq!(backend.watch_paths.len(), 8, "physical retirement is deferred");
            finish_retirements(&mut backend, &mut rates);
            assert_eq!(backend.watch_paths.len(), 2);
            assert_eq!(backend.path_watches.len(), 2);
            assert!(backend.path_watches.contains_key(root));
            assert!(backend.path_watches.contains_key(&sibling));
            assert_eq!(rates.tracked_dirs(), 0);
        }
        assert!(group.is_dir(), "watch retirement never removes user files");
    }

    #[test]
    fn large_retirement_obeys_work_budget_and_does_not_starve_events() {
        let (_temp, config) = fixture();
        let root = &config.root_paths()[0];
        let group = root.join("group");
        let mut paths = vec![root.clone()];
        for n in 0..64 {
            let path = group.join(format!("child-{n:02}"));
            fs::create_dir_all(&path).unwrap();
            paths.push(path);
        }
        let mut backend = LinuxInotifyBackend::start(&paths, 65).unwrap();
        let mut rates = EventRateTracker::default();
        backend.forget_subtree(&group, &mut rates);
        for n in 0..10 {
            let incoming = event(&backend, root, EventMask::MODIFY, Some(&format!("live-{n}")));
            backend.pending_events.push_back(incoming);
        }
        let invalidation = drain(&mut backend, &config, DrainBudget { events: 6, ..DrainBudget::default() });
        assert_eq!(backend.watch_paths.len(), 62, "only three physical retirements fit");
        assert_eq!(backend.pending_events.len(), 7, "three live events also make progress");
        assert_eq!(invalidation.dirty_paths().len(), 3);
        assert!(invalidation.requires_index_generation_bump());
        assert_eq!(backend.watched_dirs().count(), 1);
        assert!(!backend.retiring_roots.is_empty());
        finish_retirements(&mut backend, &mut rates);
        assert_eq!(backend.watch_paths.len(), 1);
        assert!(group.is_dir());
    }

    #[test]
    fn retirement_uses_the_same_deadline_and_resumes_the_suffix() {
        let (_temp, config) = fixture();
        let root = &config.root_paths()[0];
        let mut paths = vec![root.clone()];
        for name in ["a", "b", "c"] {
            let child = root.join("group").join(name);
            fs::create_dir_all(&child).unwrap();
            paths.push(child);
        }
        let mut backend = LinuxInotifyBackend::start(&paths, 4).unwrap();
        let mut rates = EventRateTracker::default();
        backend.forget_subtree(&root.join("group"), &mut rates);
        let now = Instant::now();
        let mut step = 0;
        let invalidation = backend.drain_with_budget(
            &DirtyRootTracker::new(config.root_paths()), &config,
            &mut rates, &mut OverflowBackoff::default(), now,
            DrainBudget { time: Duration::from_millis(2), ..DrainBudget::default() },
            || { let time = now + Duration::from_millis(step); step += 1; time },
        );
        assert_eq!(backend.watch_paths.len(), 3, "deadline permits one removal, not the whole tree");
        assert!(!backend.retiring_roots.is_empty());
        assert!(invalidation.requires_index_generation_bump());
        let resumed = drain(&mut backend, &config, DrainBudget::default());
        assert!(!resumed.requires_reconciliation());
        assert!(backend.retiring_roots.is_empty());
        assert_eq!(backend.watch_paths.len(), 1);
    }

    #[test]
    fn revoked_events_cannot_register_descendants_or_refresh_obsolete_rates() {
        let (_temp, config) = fixture();
        let root = &config.root_paths()[0];
        let group = root.join("group");
        fs::create_dir_all(group.join("new")).unwrap();
        let mut backend = LinuxInotifyBackend::start(&[root.clone(), group.clone()], 16).unwrap();
        let stale = event(&backend, &group, EventMask::CREATE | EventMask::ISDIR, Some("new"));
        let mut rates = EventRateTracker::default();
        backend.forget_subtree(&group, &mut rates);
        let invalidation = backend.handle_event(
            &DirtyRootTracker::new(config.root_paths()), &config,
            &mut rates, &mut OverflowBackoff::default(), Instant::now(), &stale,
        );
        assert!(invalidation.requires_index_generation_bump());
        assert_eq!(rates.tracked_dirs(), 0);
        assert!(!backend.path_watches.contains_key(&group.join("new")));
        assert!(backend.add_watch(&group).is_err());
        assert!(backend.add_watch(&group.join("new")).is_err());
        assert_eq!(backend.watched_dirs().count(), 1);
    }

    #[test]
    fn deferred_kernel_watches_still_consume_the_hard_watch_budget() {
        let (_temp, config) = fixture();
        let root = &config.root_paths()[0];
        let old = root.join("old");
        let new = root.join("new");
        fs::create_dir(&old).unwrap();
        fs::create_dir(&new).unwrap();
        let mut backend = LinuxInotifyBackend::start(&[root.clone(), old.clone()], 2).unwrap();
        let mut rates = EventRateTracker::default();
        backend.forget_subtree(&old, &mut rates);
        assert_eq!(backend.watched_dirs().count(), 1);
        assert!(backend.add_watch(&new).is_err(), "revocation alone has not freed a kernel watch");
        finish_retirements(&mut backend, &mut rates);
        backend.add_watch(&new).unwrap();
        assert_eq!(backend.watch_paths.len(), 2);
        assert_eq!(backend.path_watches.len(), 2);
    }

    #[test]
    fn retirement_prefixes_coalesce_and_empty_churn_cannot_grow_the_queue() {
        let (_temp, config) = fixture();
        let root = &config.root_paths()[0];
        let group = root.join("group");
        let a = group.join("a");
        let b = group.join("b");
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        let mut backend = LinuxInotifyBackend::start(&[root.clone(), a.clone(), b.clone()], 3).unwrap();
        let mut rates = EventRateTracker::default();
        for n in 0..1024 {
            backend.forget_subtree(&root.join(format!("unwatched-{n}")), &mut rates);
        }
        assert!(backend.retiring_roots.is_empty());
        backend.forget_subtree(&a, &mut rates);
        backend.forget_subtree(&b, &mut rates);
        assert_eq!(backend.retiring_roots.len(), 2);
        backend.forget_subtree(&group, &mut rates);
        assert_eq!(backend.retiring_roots.len(), 1);
        assert!(backend.retiring_roots.contains_key(&group));
        backend.forget_subtree(&a, &mut rates);
        assert_eq!(backend.retiring_roots.len(), 1);
        finish_retirements(&mut backend, &mut rates);
        assert_eq!(backend.watch_paths.len(), 1);
    }

    #[test]
    fn single_step_drains_preserve_fairness_across_calls() {
        let (_temp, config) = fixture();
        let root = &config.root_paths()[0];
        let group = root.join("group");
        let mut paths = vec![root.clone()];
        for name in ["a", "b", "c"] {
            let path = group.join(name);
            fs::create_dir_all(&path).unwrap();
            paths.push(path);
        }
        let mut backend = LinuxInotifyBackend::start(&paths, 4).unwrap();
        backend.forget_subtree(&group, &mut EventRateTracker::default());
        let incoming = event(&backend, root, EventMask::MODIFY, Some("live-project"));
        backend.pending_events.push_back(incoming);
        let budget = DrainBudget { events: 1, ..DrainBudget::default() };
        drain(&mut backend, &config, budget);
        assert_eq!(backend.watch_paths.len(), 3);
        assert_eq!(backend.pending_events.len(), 1);
        // Even an intervening zero-work poll must not reset the turn.
        drain(&mut backend, &config, DrainBudget { events: 0, ..budget });
        let next = drain(&mut backend, &config, budget);
        assert_eq!(backend.watch_paths.len(), 3, "the next step belongs to the live event");
        assert!(backend.pending_events.is_empty());
        assert!(next.dirty_paths().contains(&root.join("live-project")));
        assert!(!backend.retiring_roots.is_empty());
    }
}
