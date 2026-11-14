//! Exercise pressure ordering through the real, single-worker directory walk.
//! The consumer accepts one result, then cancels the pass without publishing
//! completion feedback. Merely returning every root is not sufficient progress.

#![cfg(unix)]

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crossbeam_channel::RecvTimeoutError;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use storage_ballast_helper::monitor::voi_scheduler::{
    MAX_REVISIT_INTERVAL, VoiConfig, VoiScheduler,
};
use storage_ballast_helper::scanner::prescan_cursor::PrescanCursor;
use storage_ballast_helper::scanner::protection::ProtectionRegistry;
use storage_ballast_helper::scanner::walker::{
    DirectoryWalker, WalkDispatchCursor, WalkDispatchPosition, WalkEntry, WalkerConfig,
};

fn fixture(count: usize) -> (tempfile::TempDir, Vec<PathBuf>) {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let roots: Vec<_> = (0..count)
        .map(|index| base.join(format!("root-{index:02}")))
        .collect();
    for root in &roots {
        fs::create_dir(root).unwrap();
        // The walker emits directories below its configured roots, not the
        // roots themselves or individual files. Supply a real child result
        // so cancellation exercises the scheduler's selected root.
        fs::create_dir(root.join("candidate-tree")).unwrap();
        fs::write(root.join("candidate.bin"), b"retained fixture data").unwrap();
    }
    (temp, roots)
}

fn first_entry(roots: Vec<PathBuf>, excluded_paths: HashSet<PathBuf>) -> WalkEntry {
    let walker = DirectoryWalker::new(
        WalkerConfig {
            root_paths: roots,
            max_depth: 2,
            follow_symlinks: false,
            cross_devices: false,
            parallelism: 1,
            excluded_paths,
            opaque_pruning: false,
        },
        ProtectionRegistry::new(None).unwrap(),
    );
    let mut receiver = walker.stream().unwrap();
    let first = receiver.recv_timeout(Duration::from_secs(5));
    // Cancel before asserting, including a failed receive. Wait for worker
    // senders to close before the TempDir fixture is allowed to clean up.
    walker.cancel_token().store(true, Ordering::Relaxed);
    loop {
        match receiver.recv_timeout(Duration::from_secs(5)) {
            Ok(_) => {}
            Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => panic!("cancelled walker did not shut down"),
        }
    }
    first.expect("an admitted root should produce a walk result")
}

fn owner(entry: &WalkEntry, roots: &[PathBuf]) -> PathBuf {
    roots
        .iter()
        .find(|root| entry.path.starts_with(root))
        .expect("walker escaped the requested roots")
        .clone()
}

fn assert_retained(roots: &[PathBuf]) {
    for root in roots {
        assert_eq!(
            fs::read(root.join("candidate.bin")).unwrap(),
            b"retained fixture data"
        );
    }
}

#[test]
fn disabled_voi_rotates_actual_walk_results_after_one_entry_passes() {
    let (_temp, roots) = fixture(3);
    let mut scheduler = VoiScheduler::new(VoiConfig {
        enabled: false,
        scan_budget_per_interval: 1,
        ..VoiConfig::default()
    });
    let now = Instant::now();
    for root in &roots {
        scheduler.register_path(root.clone());
    }
    scheduler.record_dirty(&roots[2], true, now);
    let mut seen = BTreeSet::new();
    for _ in 0..roots.len() {
        let ranked = scheduler.rank_paths(&roots, now);
        assert_eq!(ranked.len(), roots.len(), "pressure retains its full scope");
        seen.insert(owner(&first_entry(ranked, HashSet::new()), &roots));
    }
    assert_eq!(seen, roots.iter().cloned().collect());
    assert!(scheduler.path_stats(&roots[2]).unwrap().dirty_pending);
    assert!(
        roots
            .iter()
            .all(|root| scheduler.path_stats(root).unwrap().scan_count == 0)
    );
    assert_retained(&roots);
}

#[test]
fn overdue_low_yield_roots_reach_the_walker_despite_continuous_dirty_priority() {
    let (_temp, roots) = fixture(4);
    let mut scheduler = VoiScheduler::new(VoiConfig::default());
    let start = Instant::now();
    let now = start + MAX_REVISIT_INTERVAL;
    for root in &roots {
        scheduler.register_path(root.clone());
        scheduler.record_scan_result(root, 0, 0, 0, 1_000_000.0, start);
    }
    let hot = &roots[3];
    scheduler.record_scan_result(hot, 1_000_000_000, 1, 0, 1.0, now);
    scheduler.record_dirty(hot, true, now);
    let mut seen = BTreeSet::new();
    for _ in 0..2 * roots.len() {
        let ranked = scheduler.rank_paths(&roots, now);
        seen.insert(owner(&first_entry(ranked, HashSet::new()), &roots));
    }
    assert_eq!(seen, roots.iter().cloned().collect());
    for root in &roots[..3] {
        let stats = scheduler.path_stats(root).unwrap();
        assert_eq!(stats.scan_count, 1);
        assert_eq!(stats.last_scanned, Some(start));
    }
    assert_retained(&roots);
}

#[test]
fn forecast_failure_and_recovery_change_the_live_pressure_order() {
    let (_temp, roots) = fixture(3);
    let mut scheduler = VoiScheduler::new(VoiConfig {
        ewma_alpha: 1.0,
        min_observations_for_forecast: 2,
        forecast_error_threshold: 0.2,
        fallback_trigger_windows: 1,
        recovery_trigger_windows: 1,
        ..VoiConfig::default()
    });
    let now = Instant::now();
    for root in &roots {
        scheduler.register_path(root.clone());
        scheduler.record_scan_result(root, 0, 0, 0, 1.0, now);
    }
    let hot = &roots[2];
    scheduler.record_scan_result(hot, 1_000_000_000, 1, 0, 1.0, now);
    scheduler.end_window();
    assert!(scheduler.is_fallback_active());
    scheduler.record_dirty(hot, true, now);
    let mut seen = BTreeSet::new();
    for _ in 0..roots.len() {
        seen.insert(owner(
            &first_entry(scheduler.rank_paths(&roots, now), HashSet::new()),
            &roots,
        ));
    }
    assert_eq!(seen, roots.iter().cloned().collect());
    // Alpha=1 leaves an exact forecast of 1 GiB. A matching observation is
    // genuine calibration recovery, not a test-only change of fallback state.
    scheduler.record_scan_result(hot, 1_000_000_000, 1, 0, 1.0, now);
    scheduler.end_window();
    assert!(!scheduler.is_fallback_active());
    scheduler.record_dirty(hot, true, now);
    let first = first_entry(scheduler.rank_paths(&roots, now), HashSet::new());
    assert_eq!(owner(&first, &roots), *hot);
    assert_retained(&roots);
}

#[test]
fn remembered_roots_do_not_expand_a_later_scoped_walk() {
    let (_temp, roots) = fixture(3);
    let mut scheduler = VoiScheduler::new(VoiConfig {
        enabled: false,
        ..VoiConfig::default()
    });
    let now = Instant::now();
    for root in &roots {
        scheduler.register_path(root.clone());
    }
    let _ = first_entry(scheduler.rank_paths(&roots, now), HashSet::new());
    for _ in 0..3 {
        let ranked = scheduler.rank_paths(&[roots[1].clone(), roots[1].clone()], now);
        assert_eq!(ranked, vec![roots[1].clone()]);
        let first = first_entry(ranked, HashSet::new());
        assert!(first.path.starts_with(&roots[1]));
    }
    assert_retained(&roots);
}

#[test]
fn a_leading_opportunity_never_overrides_walker_exclusions() {
    let (_temp, roots) = fixture(2);
    let mut scheduler = VoiScheduler::new(VoiConfig {
        enabled: false,
        ..VoiConfig::default()
    });
    let ranked = scheduler.rank_paths(&roots, Instant::now());
    assert_eq!(ranked[0], roots[0]);
    let excluded = HashSet::from([roots[0].clone()]);
    let first = first_entry(ranked, excluded);
    assert!(first.path.starts_with(&roots[1]));
    assert_retained(&roots);
}

#[test]
fn interleaved_scopes_each_rotate_their_actual_first_results() {
    let (_left_temp, left) = fixture(2);
    let (_right_temp, right) = fixture(4);
    let mut scheduler = VoiScheduler::new(VoiConfig {
        enabled: false,
        ..VoiConfig::default()
    });
    let now = Instant::now();
    let mut left_seen = BTreeSet::new();
    let mut right_seen = BTreeSet::new();
    for _ in 0..4 {
        let first = first_entry(scheduler.rank_paths(&left, now), HashSet::new());
        left_seen.insert(owner(&first, &left));
        let first = first_entry(scheduler.rank_paths(&right, now), HashSet::new());
        right_seen.insert(owner(&first, &right));
    }
    assert_eq!(left_seen, left.iter().cloned().collect());
    assert_eq!(right_seen, right.iter().cloned().collect());
    assert_retained(&left);
    assert_retained(&right);
}

fn slice_config(roots: Vec<PathBuf>) -> WalkerConfig {
    WalkerConfig {
        root_paths: roots,
        max_depth: 4,
        follow_symlinks: false,
        cross_devices: false,
        parallelism: 1,
        excluded_paths: HashSet::new(),
        opaque_pruning: false,
    }
}

/// Schedule the consumer at each real walker heartbeat. Only results produced
/// before that tick and received before cancellation count as useful work.
/// Once the slice ends, all other output goes directly to unfinished receipts.
/// This is deterministic finite-work accounting, not a fleet CPU measurement.
fn finite_slice(
    config: WalkerConfig,
    allowance: usize,
    stop_on: impl Fn(&WalkEntry) -> bool,
) -> (Vec<WalkEntry>, Vec<PathBuf>) {
    let walker =
        DirectoryWalker::new(config, ProtectionRegistry::marker_only()).without_file_sizes();
    finite_walker_slice(walker, allowance, stop_on)
}

fn finite_walker_slice(
    walker: DirectoryWalker,
    allowance: usize,
    stop_on: impl Fn(&WalkEntry) -> bool,
) -> (Vec<WalkEntry>, Vec<PathBuf>) {
    let (tick_tx, tick_rx) = crossbeam_channel::bounded(0);
    let (resume_tx, resume_rx) = crossbeam_channel::bounded(0);
    let cancel = walker.cancel_token();
    let stop = Arc::clone(&cancel);
    let ticks = AtomicUsize::new(0);
    let walker = walker.with_heartbeat(move || {
        let tick = ticks.fetch_add(1, Ordering::Relaxed) + 1;
        if tick_tx.send(tick).is_err()
            || resume_rx.recv_timeout(Duration::from_secs(5)).is_err()
            || tick >= allowance
        {
            stop.store(true, Ordering::Relaxed);
        }
    });
    let mut stream = walker.stream().unwrap();
    drop(walker);
    let mut received = Vec::new();
    loop {
        let tick = match tick_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(tick) => Some(tick),
            Err(RecvTimeoutError::Disconnected) => None,
            Err(RecvTimeoutError::Timeout) => {
                cancel.store(true, Ordering::Relaxed);
                panic!("walker did not reach its next cooperative boundary");
            }
        };
        while !cancel.load(Ordering::Relaxed) {
            match stream.recv_timeout(Duration::ZERO) {
                Ok(entry) => {
                    let done = stop_on(&entry);
                    received.push(entry);
                    if done {
                        cancel.store(true, Ordering::Relaxed);
                    }
                }
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => break,
            }
        }
        let Some(tick) = tick else { break };
        if tick >= allowance {
            cancel.store(true, Ordering::Relaxed);
        }
        resume_tx.send(()).unwrap();
        if cancel.load(Ordering::Relaxed) {
            break;
        }
    }
    let unfinished = stream
        .unfinished_after_cancel(Duration::from_secs(5))
        .expect("the canceled workers must return their unfinished pages");
    (received, unfinished)
}

fn child_fixture(root: &Path, count: usize) -> BTreeSet<PathBuf> {
    (0..count)
        .map(|index| {
            let child = root.join(format!("child-{index:04}"));
            fs::create_dir_all(&child).unwrap();
            fs::write(child.join("payload"), b"preserved").unwrap();
            child
        })
        .collect()
}

#[test]
fn equally_finite_slices_deliver_every_child_of_an_interrupted_dispatch() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let expected = child_fixture(&root, 520);
    let config = slice_config(vec![root.clone()]);
    let (first, unfinished) = finite_slice(config.clone(), 6, |_| false);
    assert!(
        first.is_empty(),
        "this slice must stop while only queueing children"
    );
    assert!(
        unfinished
            .iter()
            .any(|path| root.starts_with(path) || path.starts_with(&root))
    );

    let mut seen = BTreeSet::new();
    for _ in 0..expected.len() + 8 {
        let (entries, unfinished) = finite_slice(config.clone(), 6, |_| false);
        seen.extend(entries.into_iter().map(|entry| entry.path));
        assert!(
            !unfinished.is_empty(),
            "a partial page cannot prove a finished subtree"
        );
        if seen == expected {
            break;
        }
    }
    assert_eq!(
        seen, expected,
        "only results consumed before cancellation count"
    );
    for child in &expected {
        assert_eq!(fs::read(child.join("payload")).unwrap(), b"preserved");
    }
}

#[test]
fn canceling_after_one_received_result_rotates_nested_branches_and_leaves() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let branches = [root.join("branch-a"), root.join("branch-b")];
    let mut leaves = BTreeSet::new();
    for branch in &branches {
        leaves.extend(child_fixture(branch, 32));
    }
    let config = slice_config(vec![root]);
    let (_, unfinished) = finite_slice(config.clone(), 8, |_| false);
    assert!(!unfinished.is_empty());
    let mut seen = BTreeSet::new();
    let mut parents = BTreeSet::new();
    for _ in 0..4 * leaves.len() + 8 {
        let (entries, _) = finite_slice(config.clone(), usize::MAX, |_| true);
        assert_eq!(
            entries.len(),
            1,
            "cancel immediately after one actual result"
        );
        let entry = &entries[0];
        if entry.depth == 1 {
            parents.insert(entry.path.clone());
        } else {
            seen.insert(entry.path.clone());
        }
        if seen == leaves && parents.len() == branches.len() {
            break;
        }
    }
    assert_eq!(parents, branches.into_iter().collect());
    assert_eq!(
        seen, leaves,
        "inner progress must also give other branches a turn"
    );

    // Prior parent observations must not remove rows from an uninterrupted
    // later walk. Every in-scope directory appears exactly once in that walk.
    let entries = DirectoryWalker::new(config, ProtectionRegistry::marker_only())
        .without_file_sizes()
        .walk()
        .unwrap();
    let all: BTreeSet<_> = entries.iter().map(|entry| entry.path.clone()).collect();
    assert_eq!(entries.len(), all.len());
    assert_eq!(all, leaves.union(&parents).cloned().collect());
    for child in leaves {
        assert_eq!(fs::read(child.join("payload")).unwrap(), b"preserved");
    }
}

#[test]
fn interrupted_dispatch_reapplies_scope_depth_exclusions_and_markers() {
    let temp = tempfile::tempdir().unwrap();
    let left = temp.path().join("left");
    let right = temp.path().join("right");
    let left_children = child_fixture(&left, 32);
    let right_children = child_fixture(&right, 32);
    let (_, unfinished) = finite_slice(slice_config(vec![left.clone()]), 4, |_| false);
    assert!(!unfinished.is_empty());

    let (scoped, _) = finite_slice(slice_config(vec![right.clone()]), usize::MAX, |_| true);
    assert_eq!(scoped.len(), 1);
    assert!(scoped[0].path.starts_with(&right));
    let mut shallow = slice_config(vec![left.clone()]);
    shallow.max_depth = 0;
    assert!(
        DirectoryWalker::new(shallow, ProtectionRegistry::marker_only())
            .without_file_sizes()
            .walk()
            .unwrap()
            .is_empty()
    );

    let excluded = left_children.first().unwrap().clone();
    let mut policy = slice_config(vec![left.clone()]);
    policy.excluded_paths.insert(excluded.clone());
    let entries = DirectoryWalker::new(policy, ProtectionRegistry::marker_only())
        .without_file_sizes()
        .walk()
        .unwrap();
    assert!(entries.iter().all(|entry| entry.path != excluded));
    assert_eq!(entries.len(), left_children.len() - 1);

    fs::write(left.join(".sbh-protect"), b"hold").unwrap();
    assert!(
        DirectoryWalker::new(slice_config(vec![left]), ProtectionRegistry::marker_only())
            .without_file_sizes()
            .walk()
            .unwrap()
            .is_empty()
    );
    for child in left_children.union(&right_children) {
        assert_eq!(fs::read(child.join("payload")).unwrap(), b"preserved");
    }
}

#[test]
fn a_replacement_directory_cannot_inherit_an_interrupted_dispatch() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    child_fixture(&root, 32);
    let (_, unfinished) = finite_slice(slice_config(vec![root.clone()]), 4, |_| false);
    assert!(!unfinished.is_empty());
    fs::rename(&root, temp.path().join("retained-original")).unwrap();
    let replacement = root.join("new-child");
    fs::create_dir_all(&replacement).unwrap();
    fs::write(replacement.join("payload"), b"new data").unwrap();
    let entries = DirectoryWalker::new(slice_config(vec![root]), ProtectionRegistry::marker_only())
        .without_file_sizes()
        .walk()
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, replacement);
    assert_eq!(fs::read(replacement.join("payload")).unwrap(), b"new data");
}

const RESTART_REQUEST_ENV: &str = "SBH_DISPATCH_RESTART_TEST_REQUEST";

#[derive(Serialize, Deserialize)]
struct RestartRequest {
    test: String,
    roots: Vec<PathBuf>,
    max_depth: usize,
    excluded: HashSet<PathBuf>,
    checkpoint: PathBuf,
    observations: PathBuf,
    allowance: Option<usize>,
    stop_depth: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReceivedDirectory {
    path: PathBuf,
    depth: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct RestartObservation {
    pid: u32,
    received: Vec<ReceivedDirectory>,
    unfinished: Vec<PathBuf>,
    restored_positions: usize,
    saved_positions: usize,
}

impl RestartRequest {
    fn new(test: &str, base: &Path, roots: Vec<PathBuf>) -> Self {
        let checkpoint = base.join("prescan.json");
        PrescanCursor::new().save(&checkpoint).unwrap();
        Self {
            test: test.to_owned(),
            roots,
            max_depth: 4,
            excluded: HashSet::new(),
            checkpoint,
            observations: base.join("observations.json"),
            allowance: Some(48),
            stop_depth: 3,
        }
    }

    fn run(&self) -> RestartObservation {
        let request_path = self.checkpoint.with_file_name("request.json");
        fs::write(&request_path, serde_json::to_vec(self).unwrap()).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &self.test, "--test-threads=1", "--nocapture"])
            .env(RESTART_REQUEST_ENV, &request_path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "fresh-process walk failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let observed: RestartObservation =
            serde_json::from_slice(&fs::read(&self.observations).unwrap()).unwrap();
        assert_ne!(observed.pid, std::process::id());
        observed
    }
}

/// Use the test executable itself so no thread-local enumeration cache,
/// process-wide window offset or queued worker can survive a restart. Every
/// child restores and publishes the production checkpoint format.
fn restart_child_if_requested(test: &str) -> bool {
    let Some(request_path) = std::env::var_os(RESTART_REQUEST_ENV) else {
        return false;
    };
    let request: RestartRequest = serde_json::from_slice(&fs::read(request_path).unwrap()).unwrap();
    assert_eq!(request.test, test);
    let mut prescan = PrescanCursor::load(&request.checkpoint);
    let restored_positions = prescan.walk_dispatch().len();
    let mut dispatch =
        WalkDispatchCursor::from_positions(prescan.walk_dispatch().to_vec()).unwrap();
    dispatch.retain_roots(&request.roots);
    let dispatch = Arc::new(Mutex::new(dispatch));
    let mut config = slice_config(request.roots);
    config.max_depth = request.max_depth;
    config.excluded_paths = request.excluded;
    let walker = DirectoryWalker::new(config, ProtectionRegistry::marker_only())
        .without_file_sizes()
        .with_dispatch_cursor(Arc::clone(&dispatch));
    let (received, unfinished) = if let Some(allowance) = request.allowance {
        finite_walker_slice(walker, allowance, |entry| entry.depth >= request.stop_depth)
    } else {
        (walker.walk().unwrap(), Vec::new())
    };
    // The finite helper waits for canceled workers and never acknowledges
    // buffered output after cancellation. Persist only those actual receipts.
    prescan.remember_walk_dispatch(&dispatch.lock());
    prescan.save(&request.checkpoint).unwrap();
    let observation = RestartObservation {
        pid: std::process::id(),
        received: received
            .into_iter()
            .map(|entry| ReceivedDirectory {
                path: entry.path,
                depth: entry.depth,
            })
            .collect(),
        unfinished,
        restored_positions,
        saved_positions: prescan.walk_dispatch().len(),
    };
    fs::write(
        request.observations,
        serde_json::to_vec(&observation).unwrap(),
    )
    .unwrap();
    true
}

fn deep_restart_fixture(root: &Path) -> BTreeSet<PathBuf> {
    let mut leaves = BTreeSet::new();
    for branch in ["branch-a", "branch-b"] {
        for group in ["group-a", "group-b"] {
            leaves.extend(child_fixture(&root.join(branch).join(group), 3));
        }
    }
    leaves
}

fn received_leaves(observation: &RestartObservation) -> BTreeSet<PathBuf> {
    observation
        .received
        .iter()
        .filter(|entry| entry.depth == 3)
        .map(|entry| entry.path.clone())
        .collect()
}

#[test]
fn finite_recursive_dispatch_reaches_deep_targets_across_process_restarts() {
    const TEST: &str = "finite_recursive_dispatch_reaches_deep_targets_across_process_restarts";
    if restart_child_if_requested(TEST) {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let root = base.join("tree");
    let expected = deep_restart_fixture(&root);
    let mut request = RestartRequest::new(TEST, &base, vec![root.clone()]);

    // Keep a cold-start control in the same invocation. With its checkpoint
    // reset, another process spends the same finite slice on the same leaf.
    let first = request.run();
    let first_leaf = received_leaves(&first);
    assert_eq!(first_leaf.len(), 1, "{first:?}");
    assert!(!first.unfinished.is_empty());
    assert!(first.saved_positions > 0);
    PrescanCursor::new().save(&request.checkpoint).unwrap();
    let cold = request.run();
    assert_eq!(received_leaves(&cold), first_leaf);
    assert_eq!(cold.restored_positions, 0);

    let mut seen = first_leaf;
    for _ in 0..8 * expected.len() {
        let observed = request.run();
        assert!(observed.restored_positions > 0, "{observed:?}");
        assert!(!observed.unfinished.is_empty(), "{observed:?}");
        let leaves = received_leaves(&observed);
        assert_eq!(leaves.len(), 1, "{observed:?}");
        seen.extend(leaves);
        if seen == expected {
            break;
        }
    }
    assert_eq!(seen, expected, "fresh processes must reach every deep leaf");

    // Scheduling hints never suppress repeated observations in a complete
    // later walk, or serve as recursive completion receipts.
    request.allowance = None;
    let full = request.run();
    let actual: BTreeSet<_> = full
        .received
        .iter()
        .map(|entry| entry.path.clone())
        .collect();
    let mut all = expected.clone();
    for leaf in &expected {
        let group = leaf.parent().unwrap();
        all.insert(group.to_path_buf());
        all.insert(group.parent().unwrap().to_path_buf());
        assert_eq!(fs::read(leaf.join("payload")).unwrap(), b"preserved");
    }
    assert_eq!(full.received.len(), actual.len());
    assert_eq!(actual, all);
}

#[test]
fn offline_insertions_before_restored_child_priority_are_still_visited() {
    const TEST: &str = "offline_insertions_before_restored_child_priority_are_still_visited";
    if restart_child_if_requested(TEST) {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let root = base.join("tree");
    let mut expected = deep_restart_fixture(&root);
    let request = RestartRequest::new(TEST, &base, vec![root]);
    let first = request.run();
    let mut seen = received_leaves(&first);
    assert_eq!(seen.len(), 1, "{first:?}");
    let group = seen.first().unwrap().parent().unwrap();
    let checkpoint = PrescanCursor::load(&request.checkpoint);
    let prior = checkpoint
        .walk_dispatch()
        .iter()
        .find(|position| position.directory == group)
        .expect("the consumed leaf must remember its next sibling");
    let inserted = group.join("000-offline-insertion");
    assert!(prior.next_child.as_os_str() > inserted.file_name().unwrap());
    fs::create_dir(&inserted).unwrap();
    fs::write(inserted.join("payload"), b"preserved").unwrap();
    expected.insert(inserted.clone());

    for _ in 0..8 * expected.len() {
        let observed = request.run();
        let leaves = received_leaves(&observed);
        assert_eq!(leaves.len(), 1, "{observed:?}");
        seen.extend(leaves);
        if seen == expected {
            break;
        }
    }
    assert!(
        seen.contains(&inserted),
        "a bookmark cannot certify a prefix"
    );
    assert_eq!(seen, expected);
    for leaf in expected {
        assert_eq!(fs::read(leaf.join("payload")).unwrap(), b"preserved");
    }
}

#[test]
fn restored_dispatch_rechecks_protection_symlinks_scope_and_depth() {
    const TEST: &str = "restored_dispatch_rechecks_protection_symlinks_scope_and_depth";
    if restart_child_if_requested(TEST) {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let root = base.join("tree");
    let allowed = root.join("allowed");
    let protected = root.join("protected");
    let excluded = root.join("excluded");
    let replaced = root.join("replaced");
    for branch in [&allowed, &protected, &excluded, &replaced] {
        fs::create_dir_all(branch.join("leaf")).unwrap();
        fs::write(branch.join("leaf/payload"), b"retained").unwrap();
    }
    let outside = base.join("outside");
    fs::create_dir_all(outside.join("secret")).unwrap();
    fs::write(outside.join("secret/payload"), b"outside scope").unwrap();

    let mut request = RestartRequest::new(TEST, &base, vec![root]);
    request.allowance = None;
    let original = request.run();
    assert_eq!(original.received.len(), 8);
    assert!(original.saved_positions > 0);
    fs::write(protected.join(".sbh-protect"), b"new protection").unwrap();
    let retained = base.join("retained-original");
    fs::rename(&replaced, &retained).unwrap();
    std::os::unix::fs::symlink(&outside, &replaced).unwrap();
    request.excluded.insert(excluded.clone());

    let current = request.run();
    assert!(current.restored_positions > 0);
    let allowed_paths = BTreeSet::from([allowed.clone(), allowed.join("leaf")]);
    let current_paths: BTreeSet<_> = current
        .received
        .iter()
        .map(|entry| entry.path.clone())
        .collect();
    assert_eq!(current_paths, allowed_paths);

    request.max_depth = 1;
    let shallow = request.run();
    assert_eq!(shallow.received.len(), 1, "{shallow:?}");
    assert_eq!(shallow.received[0].path, allowed);
    assert_eq!(shallow.received[0].depth, 1);
    request.max_depth = 0;
    assert!(request.run().received.is_empty());

    request.max_depth = 4;
    request.roots = vec![allowed.clone()];
    let scoped = request.run();
    assert_eq!(scoped.received.len(), 1, "{scoped:?}");
    assert_eq!(scoped.received[0].path, allowed.join("leaf"));
    assert_eq!(scoped.received[0].depth, 1);

    // A partial checkpoint is a fresh start under the current scope and
    // policies. It must never turn saved path strings into queued work.
    let good_checkpoint = fs::read(&request.checkpoint).unwrap();
    fs::write(
        &request.checkpoint,
        &good_checkpoint[..good_checkpoint.len() / 2],
    )
    .unwrap();
    let recovered = request.run();
    assert_eq!(recovered.restored_positions, 0);
    assert_eq!(recovered.received.len(), 1, "{recovered:?}");
    assert_eq!(recovered.received[0].path, allowed.join("leaf"));
    for branch in [&allowed, &protected, &excluded, &retained] {
        assert_eq!(fs::read(branch.join("leaf/payload")).unwrap(), b"retained");
    }
    assert_eq!(
        fs::read(protected.join(".sbh-protect")).unwrap(),
        b"new protection"
    );
    assert_eq!(
        fs::read(outside.join("secret/payload")).unwrap(),
        b"outside scope"
    );
}

#[test]
fn old_checkpoint_checksums_and_root_opportunities_survive_public_api_upgrade() {
    let temp = tempfile::tempdir().unwrap();
    // These are literal old-format payloads, independently of the current
    // checkpoint encoder. Their checksum includes their original version.
    let fixtures: [(u32, &[u8]); 2] = [
        (
            1,
            br#"{"root":"/legacy-a","after":"/legacy-a/seen","continuations":[["/legacy-b","/legacy-b/previous"]]}"#,
        ),
        (
            2,
            br#"{"root":"/legacy-a","after":"/legacy-a/seen","continuations":[["/legacy-b","/legacy-b/previous"]],"walk_order":[["/legacy-a",7,false],["/legacy-b",11,true]]}"#,
        ),
    ];
    for (version, payload) in fixtures {
        let path = temp.path().join(format!("version-{version}.json"));
        let mut digest = Sha256::new();
        digest.update(version.to_le_bytes());
        digest.update(payload);
        let checksum: [u8; 32] = digest.finalize().into();
        let progress: serde_json::Value = serde_json::from_slice(payload).unwrap();
        let envelope = serde_json::json!({
            "version": version,
            "progress": progress,
            "checksum": checksum,
        });
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        let restored = PrescanCursor::load(&path);
        assert_eq!(
            restored.position(),
            (
                Some(Path::new("/legacy-a")),
                Some(Path::new("/legacy-a/seen")),
            )
        );
        assert!(restored.walk_dispatch().is_empty());
        restored.save(&path).unwrap();
        assert_eq!(PrescanCursor::load(&path), restored);
        let upgraded: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(upgraded["version"], 3);
        assert_eq!(
            upgraded["progress"]["continuations"],
            envelope["progress"]["continuations"]
        );
        assert_eq!(
            upgraded["progress"]["walk_order"], envelope["progress"]["walk_order"],
            "upgrading v2 must retain its leading-root opportunities"
        );
    }
}

#[test]
fn native_dispatch_names_round_trip_through_the_public_checkpoint_api() {
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let temp = tempfile::tempdir().unwrap();
    let checkpoint = temp.path().join("native-names.json");
    // Test native-byte storage independently of a filesystem's filename
    // admission rules: these paths are hints, never direct traversal tasks.
    let root = PathBuf::from(OsString::from_vec(b"/mount-\xff".to_vec()));
    let after = root.join(OsString::from_vec(b"examined-\xfe".to_vec()));
    let position = WalkDispatchPosition {
        directory: root.join(OsString::from_vec(b"nested-\xfd".to_vec())),
        next_child: OsString::from_vec(b"pending-\xfc".to_vec()),
    };
    let dispatch = WalkDispatchCursor::from_positions(vec![position.clone()]).unwrap();
    let mut state = PrescanCursor::new();
    state.advance(&root, &after);
    assert!(state.remember_walk_dispatch(&dispatch));
    assert!(!root.as_os_str().as_bytes().is_ascii());
    state.save(&checkpoint).unwrap();
    let mut restored = PrescanCursor::load(&checkpoint);
    assert_eq!(restored, state);
    assert_eq!(
        restored.position(),
        (Some(root.as_path()), Some(after.as_path()))
    );
    assert_eq!(restored.walk_dispatch(), [position.clone()]);
    assert_eq!(
        restored.walk_dispatch()[0].next_child.as_bytes(),
        b"pending-\xfc"
    );

    let rewind = restored.clone();
    restored.reset();
    restored.save(&checkpoint).unwrap();
    let reset = PrescanCursor::load(&checkpoint);
    assert_eq!(reset.position(), (None, None));
    assert_eq!(reset.walk_dispatch(), [position.clone()]);
    assert!(restored.remember_walk_dispatch(&WalkDispatchCursor::new()));
    assert_eq!(rewind.walk_dispatch(), [position]);
}
