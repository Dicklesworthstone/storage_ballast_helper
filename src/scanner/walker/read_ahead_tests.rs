//! Regression tests for real walks that span more than one finite slice.

use super::*;

fn config(root: &Path) -> WalkerConfig {
    WalkerConfig {
        root_paths: vec![root.to_path_buf()],
        max_depth: 10,
        follow_symlinks: false,
        cross_devices: false,
        parallelism: 1,
        excluded_paths: HashSet::new(),
        opaque_pruning: false,
    }
}

fn deep_tree(root: &Path) -> PathBuf {
    let deep = root.join("one/two/three/deep");
    fs::create_dir_all(deep.join("reachable")).unwrap();
    fs::write(deep.join("reachable/payload"), "keep this content").unwrap();
    for index in 0..1600 {
        fs::write(deep.join(format!("item-{index:04}")), "name-only fixture").unwrap();
    }
    deep
}

fn finite_walk(config: WalkerConfig, beats: usize) -> (Vec<WalkEntry>, Vec<PathBuf>, bool) {
    finite_walk_window(config, beats, MAX_ENTRIES_PER_DIR)
}

fn finite_walk_window(
    config: WalkerConfig,
    beats: usize,
    window: u32,
) -> (Vec<WalkEntry>, Vec<PathBuf>, bool) {
    let walker = DirectoryWalker::new(config, ProtectionRegistry::marker_only())
        .without_file_sizes()
        .with_dir_window(window);
    let cancel = walker.cancel_token();
    let stop = Arc::clone(&cancel);
    let heartbeat_count = AtomicUsize::new(0);
    let walker = walker.with_heartbeat(move || {
        if heartbeat_count.fetch_add(1, Ordering::Relaxed) + 1 >= beats {
            stop.store(true, Ordering::Relaxed);
        }
    });
    let mut stream = walker.stream().unwrap();
    let mut entries = Vec::new();
    loop {
        match stream.recv_timeout(Duration::from_secs(5)) {
            Ok(entry) => entries.push(entry),
            Err(channel::RecvTimeoutError::Disconnected) => break,
            Err(channel::RecvTimeoutError::Timeout) => panic!("finite walker did not stop"),
        }
    }
    let stopped = cancel.load(Ordering::Relaxed);
    let unfinished = stream.unfinished_after_cancel(Duration::ZERO).unwrap();
    (entries, unfinished, stopped)
}

#[test]
fn finite_slices_eventually_reach_beyond_a_large_deep_directory() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let deep = deep_tree(root);
    let target = deep.join("reachable");
    let mut reached = false;
    let mut saw_incomplete = false;
    for _ in 0..10 {
        let (entries, unfinished, stopped) = finite_walk(config(root), 16);
        let reached_now = entries.iter().any(|entry| entry.path == target);
        // The budget's last heartbeat can land as the resumed pass finishes,
        // so the flag alone does not mean the walk was cut short. A pass that
        // reports nothing unfinished must actually have reached the target.
        if stopped && unfinished.is_empty() {
            assert!(reached_now, "a canceled pass cannot prove coverage");
        }
        saw_incomplete |= !unfinished.is_empty();
        reached |= reached_now;
        if reached {
            break;
        }
    }
    assert!(
        saw_incomplete,
        "the fixture must need more than one funded slice"
    );
    assert!(
        reached,
        "restarting the same deep listing on every slice hides its children forever",
    );
    assert_eq!(
        fs::read_to_string(target.join("payload")).unwrap(),
        "keep this content"
    );
}

#[test]
fn a_marker_added_after_partial_enumeration_stops_all_descendants() {
    let temp = tempfile::tempdir().unwrap();
    let deep = deep_tree(temp.path());
    let (_, unfinished, stopped) = finite_walk(config(temp.path()), 16);
    assert!(stopped);
    assert!(unfinished.iter().any(|path| deep.starts_with(path)));
    fs::write(deep.join(".sbh-protect"), "operator hold").unwrap();

    let entries = DirectoryWalker::new(config(temp.path()), ProtectionRegistry::marker_only())
        .without_file_sizes()
        .walk()
        .unwrap();
    assert!(entries.iter().all(|entry| !entry.path.starts_with(&deep)));
    assert!(deep.join("reachable/payload").exists());
}

#[test]
fn a_replaced_directory_cannot_replay_its_old_children() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    let deep = deep_tree(&root);
    let (_, _, stopped) = finite_walk(config(&root), 16);
    assert!(stopped);
    fs::rename(&deep, temp.path().join("retained-old-tree")).unwrap();
    fs::create_dir_all(deep.join("new-child")).unwrap();
    fs::write(deep.join("new-child/payload"), "new object").unwrap();

    let entries = DirectoryWalker::new(config(&root), ProtectionRegistry::marker_only())
        .without_file_sizes()
        .walk()
        .unwrap();
    assert!(
        entries
            .iter()
            .any(|entry| entry.path == deep.join("new-child"))
    );
    assert!(
        entries
            .iter()
            .all(|entry| entry.path != deep.join("reachable"))
    );
    assert!(
        temp.path()
            .join("retained-old-tree/reachable/payload")
            .exists()
    );
}

#[test]
fn cached_names_reapply_current_exclusions_and_depth() {
    let temp = tempfile::tempdir().unwrap();
    let child = temp.path().join("parent/child");
    fs::create_dir_all(&child).unwrap();
    fs::write(child.join("payload"), "unchanged").unwrap();
    let walk = |config| {
        DirectoryWalker::new(config, ProtectionRegistry::marker_only())
            .without_file_sizes()
            .walk()
            .unwrap()
    };
    assert!(
        walk(config(temp.path()))
            .iter()
            .any(|entry| entry.path == child)
    );
    let mut excluded = config(temp.path());
    excluded.excluded_paths.insert(child.clone());
    assert!(
        walk(excluded)
            .iter()
            .all(|entry| !entry.path.starts_with(&child))
    );
    let mut shallow = config(temp.path());
    shallow.max_depth = 1;
    assert!(walk(shallow).iter().all(|entry| entry.depth <= 1));
    assert!(
        walk(config(temp.path()))
            .iter()
            .any(|entry| entry.path == child)
    );
}

#[test]
fn a_cached_tag_is_revalidated_when_its_contents_change() {
    let temp = tempfile::tempdir().unwrap();
    let child = temp.path().join("cache");
    fs::create_dir(&child).unwrap();
    let tag = child.join("CACHEDIR.TAG");
    fs::write(&tag, "Signature: 8a477f597d28d172789f06886806bc55\n").unwrap();
    let walk = || {
        DirectoryWalker::new(config(temp.path()), ProtectionRegistry::marker_only())
            .without_file_sizes()
            .walk()
            .unwrap()
            .into_iter()
            .find(|entry| entry.path == child)
            .unwrap()
    };
    assert!(walk().structural_signals.has_cachedir_tag);
    let before = fs::metadata(&child).unwrap().modified().unwrap();
    fs::write(&tag, "this no longer authorizes cache classification\n").unwrap();
    assert_eq!(fs::metadata(&child).unwrap().modified().unwrap(), before);
    assert!(!walk().structural_signals.has_cachedir_tag);
}

#[test]
fn cancellation_during_child_dispatch_does_not_advance_the_window() {
    let temp = tempfile::tempdir().unwrap();
    for index in 0..600 {
        let child = temp.path().join(format!("child-{index:04}"));
        fs::create_dir(&child).unwrap();
        fs::write(child.join("payload"), "preserved").unwrap();
    }
    // Four beats enumerate the parent; two more reach its second queued
    // child chunk. No child traversal can finish before the parent yields.
    let (entries, unfinished, stopped) = finite_walk_window(config(temp.path()), 6, 512);
    assert!(stopped);
    assert!(entries.is_empty());
    assert!(unfinished.contains(&temp.path().to_path_buf()));
    assert_eq!(oversized_window_starts().lock().get(temp.path()), None);

    let (entries, _, _) = finite_walk_window(config(temp.path()), usize::MAX, 512);
    assert_eq!(
        entries.len(),
        512,
        "the entire interrupted window must be replayed"
    );
    assert_eq!(
        oversized_window_starts().lock().get(temp.path()),
        Some(&512)
    );
}
