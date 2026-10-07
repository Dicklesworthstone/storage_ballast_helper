//! Bounded watch discovery. File entries consume budget even when they do not
//! become watch candidates. A partial listing never proves recursive coverage.
//!
//! Complete listings select the lexicographically smallest eligible directories,
//! independently of readdir order. Partial listings publish no new children;
//! their parent remains a reconciliation gap. Limits bound discovery, not watch
//! installation or an individual kernel-blocked filesystem operation.

use std::collections::{BTreeSet, BinaryHeap, VecDeque};
use std::ffi::OsString;
use std::fs::{self, Metadata};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use super::{EventRateTracker, WatchCandidate, WatchEnumeration, candidate_rate};

const ENUMERATION_FACTOR: usize = 4;
const MAX_CANDIDATES: usize = 65_536;
const MAX_ENTRIES: usize = 262_144;
const MAX_DIRECTORY_ENTRIES: usize = 16_384;
const MAX_PATH_BYTES: usize = 8 * 1024 * 1024;
const MAX_SELECTED_NAME_BYTES: usize = 1024 * 1024;
const ENUMERATION_TIME: Duration = Duration::from_millis(250);

type Entries = Box<dyn Iterator<Item = io::Result<Child>>>;

struct Child {
    name: OsString,
    directory: bool,
}

trait Access {
    fn metadata(&self, path: &Path) -> io::Result<Metadata>;
    fn entries(&self, path: &Path) -> io::Result<Entries>;
    fn now(&self) -> Instant;
}

struct Native;

impl Access for Native {
    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        fs::symlink_metadata(path)
    }

    fn entries(&self, path: &Path) -> io::Result<Entries> {
        Ok(Box::new(fs::read_dir(path)?.map(|entry| {
            let entry = entry?;
            Ok(Child {
                name: entry.file_name(),
                directory: entry.file_type()?.is_dir(),
            })
        })))
    }

    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Clone, Copy)]
struct Limits {
    candidates: usize,
    entries: usize,
    directory_entries: usize,
    path_bytes: usize,
    selected_name_bytes: usize,
    time: Duration,
}

impl Limits {
    fn for_budget(watches: usize) -> Self {
        Self {
            candidates: watches.saturating_mul(ENUMERATION_FACTOR).min(MAX_CANDIDATES),
            entries: MAX_ENTRIES,
            directory_entries: MAX_DIRECTORY_ENTRIES,
            path_bytes: MAX_PATH_BYTES,
            selected_name_bytes: MAX_SELECTED_NAME_BYTES,
            time: ENUMERATION_TIME,
        }
    }
}

struct Budget {
    limits: Limits,
    started: Instant,
    entries: usize,
    path_bytes: usize,
}

impl Budget {
    fn live(&self, access: &impl Access) -> bool {
        access.now().checked_duration_since(self.started)
            .is_some_and(|elapsed| elapsed < self.limits.time)
    }

    fn admit_paths(&mut self, path: &Path, root: &Path) -> bool {
        let Some(cost) = path.as_os_str().len().checked_add(root.as_os_str().len()) else {
            return false;
        };
        let Some(total) = self.path_bytes.checked_add(cost) else {
            return false;
        };
        if total > self.limits.path_bytes {
            return false;
        }
        self.path_bytes = total;
        true
    }
}

pub(super) fn enumerate(
    roots: &[PathBuf],
    watch_budget: usize,
    rates: &EventRateTracker,
    now: Instant,
) -> WatchEnumeration {
    enumerate_with(&Native, roots, rates, now, Limits::for_budget(watch_budget))
}

fn gap(result: &mut WatchEnumeration, path: &Path, reason: &str) {
    if !path.ancestors().any(|ancestor| result.truncated.contains(ancestor)) {
        result.truncated.insert(path.to_path_buf());
    }
    if result.reason.is_empty() {
        result.reason = format!("recursive inotify planning incomplete at {}: {reason}", path.display());
    }
}

/// Seed all configured roots before spending discovery on descendants. The
/// queue owns indices and metadata, not another copy of every path and root.
fn enumerate_with(
    access: &impl Access,
    roots: &[PathBuf],
    rates: &EventRateTracker,
    now: Instant,
    limits: Limits,
) -> WatchEnumeration {
    let mut budget = Budget { limits, started: access.now(), entries: 0, path_bytes: 0 };
    let wall_time = SystemTime::now();
    let mut result = WatchEnumeration::default();
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::new();

    // Production config supplies sorted, deduplicated roots. Overlapping roots
    // are seeded independently and are not rediscovered through their parents.
    for root in roots {
        if seen.contains(root) {
            continue;
        }
        if !budget.live(access) || result.candidates.len() >= limits.candidates {
            gap(&mut result, root, "root discovery budget exhausted");
            continue;
        }
        let metadata = match access.metadata(root) {
            Ok(metadata) if metadata.is_dir() && !metadata.is_symlink() => metadata,
            _ => {
                result.unreadable_roots.insert(root.clone());
                gap(&mut result, root, "root is unavailable or is not a plain directory");
                continue;
            }
        };
        if !budget.live(access) || !budget.admit_paths(root, root) {
            gap(&mut result, root, "root discovery time or path budget exhausted");
            continue;
        }
        seen.insert(root.clone());
        queue.push_back((result.candidates.len(), metadata.clone()));
        result.candidates.push(WatchCandidate {
            path: root.clone(), root: root.clone(), depth: 0,
            rate: candidate_rate(rates, root, now, &metadata, wall_time),
        });
    }

    while let Some((index, before)) = queue.pop_front() {
        let parent = result.candidates[index].clone();
        let room = limits.candidates.saturating_sub(result.candidates.len());
        if !budget.live(access) || room == 0 || budget.entries >= limits.entries {
            gap(&mut result, &parent.path, "discovery budget exhausted");
            continue;
        }
        let (children, omitted) = match select_children(access, &parent.path, room, &mut budget) {
            Ok(listing) => listing,
            Err(error) => {
                gap(&mut result, &parent.path, &error.to_string());
                continue;
            }
        };
        // Do not certify an old directory's listing after its pathname, type,
        // or contents changed. This is best-effort observation, not a lease.
        if !budget.live(access)
            || !access.metadata(&parent.path).is_ok_and(|after| unchanged_directory(&before, &after))
            || !budget.live(access)
        {
            gap(&mut result, &parent.path, "directory changed or deadline expired during discovery");
            continue;
        }
        if omitted {
            gap(&mut result, &parent.path, "candidate budget omitted child directories");
        }
        for name in children {
            if !budget.live(access) {
                gap(&mut result, &parent.path, "discovery deadline expired");
                break;
            }
            let path = parent.path.join(name);
            if seen.contains(&path) {
                continue;
            }
            let metadata = match access.metadata(&path) {
                Ok(metadata) if metadata.is_dir() && !metadata.is_symlink() => metadata,
                _ => {
                    gap(&mut result, &parent.path, "child directory changed or metadata is unavailable");
                    continue;
                }
            };
            if !budget.live(access) || !budget.admit_paths(&path, &parent.root) {
                gap(&mut result, &parent.path, "discovery time or retained-path budget exhausted");
                break;
            }
            seen.insert(path.clone());
            queue.push_back((result.candidates.len(), metadata.clone()));
            result.candidates.push(WatchCandidate {
                path: path.clone(), root: parent.root.clone(), depth: parent.depth + 1,
                rate: candidate_rate(rates, &path, now, &metadata, wall_time),
            });
        }
    }
    result
}

fn unchanged_directory(before: &Metadata, after: &Metadata) -> bool {
    if !after.is_dir() || after.is_symlink() || before.modified().ok() != after.modified().ok() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        before.dev() == after.dev() && before.ino() == after.ino()
            && before.ctime() == after.ctime() && before.ctime_nsec() == after.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        before.created().ok() == after.created().ok()
    }
}

fn exhausted(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, reason)
}

/// Retain only a bounded selection of directory names, not every file/path in
/// a flat directory. Count errors and non-directories against the same budget.
/// At the exact entry limit EOF is unknown: do not perform an extra read merely
/// to turn a conservative gap into a complete claim.
fn select_children(
    access: &impl Access,
    path: &Path,
    room: usize,
    budget: &mut Budget,
) -> io::Result<(Vec<OsString>, bool)> {
    let mut entries = access.entries(path)?;
    let mut selected: BinaryHeap<OsString> = BinaryHeap::new();
    let mut name_bytes = 0usize;
    let mut local_entries = 0usize;
    let mut omitted = false;
    loop {
        if !budget.live(access) {
            return Err(exhausted("discovery deadline expired"));
        }
        if budget.entries >= budget.limits.entries || local_entries >= budget.limits.directory_entries {
            return Err(exhausted("directory-entry budget exhausted"));
        }
        let Some(entry) = entries.next() else {
            break;
        };
        budget.entries += 1;
        local_entries += 1;
        let child = entry?;
        if !child.directory {
            continue;
        }
        let mut components = Path::new(&child.name).components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid directory child name"));
        }
        if selected.len() >= room {
            omitted = true;
            if !selected.peek().is_some_and(|last| child.name < *last) {
                continue;
            }
            if let Some(last) = selected.pop() {
                name_bytes -= last.len();
            }
        }
        name_bytes = name_bytes.checked_add(child.name.len())
            .filter(|bytes| *bytes <= budget.limits.selected_name_bytes)
            .ok_or_else(|| exhausted("selected-name memory budget exhausted"))?;
        selected.push(child.name);
    }
    Ok((selected.into_sorted_vec(), omitted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::rc::Rc;

    #[derive(Clone)]
    enum Listing {
        Rows(Vec<std::result::Result<(OsString, bool), io::ErrorKind>>),
        Generated { count: usize, directories: bool },
        Error(io::ErrorKind),
    }

    struct Mock {
        metadata: Metadata,
        listings: BTreeMap<PathBuf, Listing>,
        denied: BTreeSet<PathBuf>,
        opened: RefCell<Vec<PathBuf>>,
        reads: Rc<Cell<usize>>,
        milliseconds: Rc<Cell<u64>>,
        entry_millis: u64,
        start: Instant,
    }

    impl Mock {
        fn fixture() -> (tempfile::TempDir, Self) {
            let temp = tempfile::tempdir().unwrap();
            let mock = Self {
                metadata: fs::symlink_metadata(temp.path()).unwrap(),
                listings: BTreeMap::new(), denied: BTreeSet::new(),
                opened: RefCell::new(Vec::new()), reads: Rc::new(Cell::new(0)),
                milliseconds: Rc::new(Cell::new(0)), entry_millis: 0,
                start: Instant::now(),
            };
            (temp, mock)
        }

        fn dirs(&mut self, path: &str, names: &[&str]) {
            self.listings.insert(PathBuf::from(path), Listing::Rows(
                names.iter().map(|name| Ok((OsString::from(*name), true))).collect(),
            ));
        }

        fn run(&self, roots: &[&str], limits: Limits) -> WatchEnumeration {
            enumerate_with(self, &roots.iter().map(PathBuf::from).collect::<Vec<_>>(),
                &EventRateTracker::default(), self.start, limits)
        }
    }

    impl Access for Mock {
        fn metadata(&self, path: &Path) -> io::Result<Metadata> {
            if self.denied.contains(path) {
                Err(io::ErrorKind::PermissionDenied.into())
            } else {
                Ok(self.metadata.clone())
            }
        }

        fn entries(&self, path: &Path) -> io::Result<Entries> {
            self.opened.borrow_mut().push(path.to_path_buf());
            let listing = self.listings.get(path).cloned().unwrap_or(Listing::Rows(Vec::new()));
            if let Listing::Error(kind) = listing {
                return Err(kind.into());
            }
            let reads = Rc::clone(&self.reads);
            let clock = Rc::clone(&self.milliseconds);
            let step = self.entry_millis;
            let mut index = 0usize;
            Ok(Box::new(std::iter::from_fn(move || {
                reads.set(reads.get() + 1);
                let next = match &listing {
                    Listing::Rows(rows) => rows.get(index).cloned(),
                    Listing::Generated { count, directories } => (index < *count)
                        .then(|| Ok((OsString::from(format!("n{index:08}")), *directories))),
                    Listing::Error(_) => unreachable!(),
                };
                if next.is_some() {
                    index += 1;
                    clock.set(clock.get() + step);
                }
                next.map(|row| row.map(|(name, directory)| Child { name, directory })
                    .map_err(io::Error::from))
            })))
        }

        fn now(&self) -> Instant {
            self.start + Duration::from_millis(self.milliseconds.get())
        }
    }

    fn limits() -> Limits {
        Limits { candidates: 32, time: Duration::from_secs(1), ..Limits::for_budget(8) }
    }

    fn paths(result: &WatchEnumeration) -> Vec<PathBuf> {
        result.candidates.iter().map(|candidate| candidate.path.clone()).collect()
    }

    #[test]
    fn a_million_files_cannot_bypass_the_entry_budget() {
        let (_temp, mut mock) = Mock::fixture();
        mock.listings.insert(PathBuf::from("/r"), Listing::Generated {
            count: 1_000_000, directories: false,
        });
        let result = mock.run(&["/r"], Limits { entries: 7, ..limits() });
        assert_eq!(mock.reads.get(), 7, "no extra EOF probe after the limit");
        assert_eq!(paths(&result), vec![PathBuf::from("/r")]);
        assert!(result.truncated.contains(Path::new("/r")));
        assert!(result.reason.contains("entry budget"));
    }

    #[test]
    fn one_flat_directory_cannot_overfill_the_candidate_queue() {
        let (_temp, mut mock) = Mock::fixture();
        mock.listings.insert(PathBuf::from("/r"), Listing::Generated {
            count: 1000, directories: true,
        });
        let result = mock.run(&["/r"], Limits { candidates: 4, ..limits() });
        assert_eq!(paths(&result), ["/r", "/r/n00000000", "/r/n00000001", "/r/n00000002"]
            .map(PathBuf::from));
        assert_eq!(mock.reads.get(), 1001);
        assert_eq!(mock.opened.borrow().as_slice(), [PathBuf::from("/r")]);
        assert!(result.truncated.contains(Path::new("/r")));
    }

    #[test]
    fn all_roots_are_seeded_before_a_large_first_root_spends_the_capacity() {
        let (_temp, mut mock) = Mock::fixture();
        mock.dirs("/first", &["a", "b", "c", "d", "e"]);
        let result = mock.run(&["/first", "/second", "/third"], Limits { candidates: 4, ..limits() });
        assert_eq!(paths(&result)[..3], ["/first", "/second", "/third"].map(PathBuf::from));
        assert_eq!(result.candidates.len(), 4);
        let allocation = super::super::allocate_watches(&result.candidates, 3);
        assert_eq!(allocation.watched, ["/first", "/second", "/third"].map(PathBuf::from));
    }

    #[test]
    fn per_directory_exhaustion_does_not_discard_other_roots() {
        let (_temp, mut mock) = Mock::fixture();
        mock.listings.insert(PathBuf::from("/large"), Listing::Generated {
            count: 1000, directories: false,
        });
        mock.dirs("/healthy", &["child"]);
        let result = mock.run(&["/large", "/healthy"], Limits { directory_entries: 3, ..limits() });
        assert!(paths(&result).contains(&PathBuf::from("/healthy/child")));
        assert!(result.truncated.contains(Path::new("/large")));
        assert!(!result.truncated.contains(Path::new("/healthy")));
    }

    #[test]
    fn iteration_errors_do_not_become_successful_partial_directory_listings() {
        for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::Other, io::ErrorKind::Interrupted] {
            let (_temp, mut mock) = Mock::fixture();
            mock.listings.insert(PathBuf::from("/r"), Listing::Rows(vec![
                Ok((OsString::from("a"), true)), Err(kind), Ok((OsString::from("b"), true)),
            ]));
            mock.dirs("/healthy", &["retained"]);
            let result = mock.run(&["/r", "/healthy"], limits());
            assert!(!paths(&result).contains(&PathBuf::from("/r/a")));
            assert!(paths(&result).contains(&PathBuf::from("/healthy/retained")));
            assert!(result.truncated.contains(Path::new("/r")));
        }
    }

    #[test]
    fn exact_entry_limit_is_unknown_until_eof_was_actually_observed() {
        for count in [3, 4, 5] {
            let (_temp, mut mock) = Mock::fixture();
            mock.listings.insert(PathBuf::from("/r"), Listing::Generated {
                count, directories: false,
            });
            let result = mock.run(&["/r"], Limits { directory_entries: 4, ..limits() });
            assert_eq!(mock.reads.get(), (count + 1).min(4));
            assert_eq!(result.truncated.is_empty(), count < 4);
        }
    }

    #[test]
    fn deadline_applies_inside_one_directory_and_is_not_restarted_for_the_next() {
        let (_temp, mut mock) = Mock::fixture();
        mock.entry_millis = 10;
        mock.listings.insert(PathBuf::from("/first"), Listing::Generated {
            count: 1000, directories: true,
        });
        let result = mock.run(&["/first", "/second"], Limits { time: Duration::from_millis(50), ..limits() });
        assert_eq!(mock.reads.get(), 5);
        assert_eq!(paths(&result), ["/first", "/second"].map(PathBuf::from));
        assert_eq!(mock.opened.borrow().as_slice(), [PathBuf::from("/first")]);
        assert!(result.truncated.contains(Path::new("/first")));
        assert!(result.truncated.contains(Path::new("/second")));
    }

    #[test]
    fn complete_listing_selection_is_independent_of_directory_order() {
        let orders = [["z", "b", "y", "a", "c"], ["c", "a", "y", "b", "z"]];
        for names in orders {
            let (_temp, mut mock) = Mock::fixture();
            mock.dirs("/r", &names);
            let result = mock.run(&["/r"], Limits { candidates: 4, ..limits() });
            assert_eq!(paths(&result), ["/r", "/r/a", "/r/b", "/r/c"].map(PathBuf::from));
        }
    }

    #[test]
    fn retained_candidate_paths_and_temporary_names_have_separate_bounds() {
        let (_temp, mut mock) = Mock::fixture();
        mock.dirs("/r", &["long-directory-name"]);
        let result = mock.run(&["/r"], Limits { selected_name_bytes: 3, ..limits() });
        assert_eq!(result.candidates.len(), 1);
        assert!(result.reason.contains("selected-name"));
        let result = mock.run(&["/r"], Limits { path_bytes: 4, ..limits() });
        assert_eq!(result.candidates.len(), 1);
        assert!(result.reason.contains("retained-path"));
    }

    #[test]
    fn zero_limits_and_huge_configuration_cannot_force_unbounded_preallocation() {
        assert_eq!(Limits::for_budget(usize::MAX).candidates, MAX_CANDIDATES);
        for config in [Limits::for_budget(0), Limits { time: Duration::ZERO, ..limits() }] {
            let (_temp, mock) = Mock::fixture();
            let result = mock.run(&["/r"], config);
            assert!(result.candidates.is_empty());
            assert!(result.truncated.contains(Path::new("/r")));
            assert!(mock.opened.borrow().is_empty());
        }
    }

    #[test]
    fn missing_roots_open_failures_and_child_metadata_failures_remain_gaps() {
        let (_temp, mut mock) = Mock::fixture();
        mock.denied.insert(PathBuf::from("/denied"));
        mock.denied.insert(PathBuf::from("/r/bad"));
        mock.listings.insert(PathBuf::from("/unreadable"), Listing::Error(io::ErrorKind::PermissionDenied));
        mock.dirs("/r", &["bad", "good"]);
        let result = mock.run(&["/denied", "/unreadable", "/r"], limits());
        assert!(result.unreadable_roots.contains(Path::new("/denied")));
        for root in ["/denied", "/unreadable", "/r"] {
            assert!(result.truncated.contains(Path::new(root)));
        }
        assert!(paths(&result).contains(&PathBuf::from("/r/good")));
        assert!(!paths(&result).contains(&PathBuf::from("/r/bad")));
    }

    #[test]
    fn overlapping_roots_are_not_charged_or_enumerated_twice() {
        let (_temp, mut mock) = Mock::fixture();
        mock.dirs("/r", &["nested"]);
        mock.dirs("/r/nested", &["child"]);
        let result = mock.run(&["/r", "/r/nested", "/r/nested"], limits());
        assert_eq!(paths(&result), ["/r", "/r/nested", "/r/nested/child"].map(PathBuf::from));
        assert!(result.truncated.is_empty());
        assert_eq!(mock.opened.borrow().iter().filter(|path| path.as_path() == Path::new("/r/nested")).count(), 1);
    }

    #[test]
    fn invalid_child_names_never_escape_the_observed_directory() {
        for name in ["..", ".", "../outside", "/outside", "nested/child"] {
            let (_temp, mut mock) = Mock::fixture();
            mock.dirs("/r", &[name]);
            let result = mock.run(&["/r"], limits());
            assert_eq!(paths(&result), vec![PathBuf::from("/r")]);
            assert!(result.truncated.contains(Path::new("/r")));
        }
    }

    #[test]
    fn real_directory_enumeration_preserves_contents_and_hot_watch_priority() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        fs::create_dir_all(root.join("a/cold")).unwrap();
        fs::create_dir_all(root.join("b/hot")).unwrap();
        fs::write(root.join("retained"), b"never mutate during planning").unwrap();
        let now = Instant::now();
        let mut rates = EventRateTracker::default();
        for _ in 0..100 { rates.record(&root.join("b/hot"), now); }
        let result = enumerate_with(&Native, std::slice::from_ref(&root), &rates, now,
            Limits { time: Duration::from_secs(10), ..limits() });
        assert!(result.truncated.is_empty(), "{result:?}");
        assert!(result.unreadable_roots.is_empty());
        let allocation = super::super::allocate_watches(&result.candidates, 4);
        assert!(allocation.watched.contains(&root.join("b/hot")));
        assert!(!allocation.watched.contains(&root.join("a/cold")));
        assert_eq!(fs::read(root.join("retained")).unwrap(), b"never mutate during planning");
    }

    #[cfg(unix)]
    #[test]
    fn real_symlinked_directories_are_not_traversed_or_certified_as_roots() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir_all(outside.join("must-not-watch")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("alias")).unwrap();
        let result = enumerate_with(&Native, &[root.clone(), root.join("alias")],
            &EventRateTracker::default(), Instant::now(),
            Limits { time: Duration::from_secs(10), ..limits() });
        assert_eq!(paths(&result), vec![root.clone()]);
        assert!(result.unreadable_roots.contains(&root.join("alias")));
        assert!(outside.join("must-not-watch").exists());
    }
}
