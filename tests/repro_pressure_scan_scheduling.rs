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
    DirectoryWalker, MAX_ENTRIES_PER_DIR, WalkDispatchCursor, WalkDispatchPosition, WalkEntry,
    WalkerConfig,
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

fn unconsumed_walker_slice(
    walker: DirectoryWalker,
    allowance: usize,
) -> (Vec<WalkEntry>, Vec<PathBuf>) {
    let (stopped_tx, stopped_rx) = crossbeam_channel::bounded(1);
    let cancel = walker.cancel_token();
    let ticks = AtomicUsize::new(0);
    let walker = walker.with_heartbeat(move || {
        if ticks.fetch_add(1, Ordering::Relaxed) + 1 >= allowance {
            cancel.store(true, Ordering::Relaxed);
            let _ = stopped_tx.try_send(());
        }
    });
    let stream = walker.stream().unwrap();
    drop(walker);
    stopped_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the worker must reach its finite queued-work boundary");
    let unfinished = stream
        .unfinished_after_cancel(Duration::from_secs(5))
        .expect("unconsumed output must settle without receiving its receipts");
    (Vec::new(), unfinished)
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
    consume_results: bool,
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
            consume_results: true,
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
    let (received, unfinished) = if !request.consume_results {
        unconsumed_walker_slice(
            walker,
            request
                .allowance
                .expect("unconsumed work needs a finite budget"),
        )
    } else if let Some(allowance) = request.allowance {
        finite_walker_slice(walker, allowance, |entry| entry.depth >= request.stop_depth)
    } else {
        let mut stream = walker.stream().unwrap();
        drop(walker);
        let received = stream.by_ref().collect();
        let unfinished = stream
            .unfinished_after_cancel(Duration::from_secs(5))
            .expect("completed workers must publish final coverage receipts");
        (received, unfinished)
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
    let mut request = RestartRequest::new(TEST, &base, vec![root]);

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
    assert!(prior.next_child.as_deref().unwrap() > inserted.file_name().unwrap());
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
    let fixtures: [(u32, &[u8]); 3] = [
        (
            1,
            br#"{"root":"/legacy-a","after":"/legacy-a/seen","continuations":[["/legacy-b","/legacy-b/previous"]]}"#,
        ),
        (
            2,
            br#"{"root":"/legacy-a","after":"/legacy-a/seen","continuations":[["/legacy-b","/legacy-b/previous"]],"walk_order":[["/legacy-a",7,false],["/legacy-b",11,true]]}"#,
        ),
        (
            3,
            br#"{"root":"/legacy-a","after":"/legacy-a/seen","continuations":[["/legacy-b","/legacy-b/previous"]],"walk_order":[["/legacy-a",7,false],["/legacy-b",11,true]],"walk_dispatch":[["/legacy-a/projects","next"]]}"#,
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
        if version == 3 {
            assert_eq!(
                restored.walk_dispatch(),
                [WalkDispatchPosition {
                    directory: PathBuf::from("/legacy-a/projects"),
                    window_start: 0,
                    next_child: Some("next".into()),
                }]
            );
        } else {
            assert!(restored.walk_dispatch().is_empty());
        }
        restored.save(&path).unwrap();
        assert_eq!(PrescanCursor::load(&path), restored);
        let upgraded: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(upgraded["version"], 4);
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
        window_start: MAX_ENTRIES_PER_DIR,
        next_child: Some(OsString::from_vec(b"pending-\xfc".to_vec())),
    };
    let positions = vec![
        position,
        WalkDispatchPosition {
            directory: PathBuf::from("/other"),
            window_start: 2 * MAX_ENTRIES_PER_DIR,
            next_child: None,
        },
    ];
    let dispatch = WalkDispatchCursor::from_positions(positions.clone()).unwrap();
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
    assert_eq!(restored.walk_dispatch(), positions);
    assert_eq!(
        restored.walk_dispatch()[0]
            .next_child
            .as_deref()
            .unwrap()
            .as_bytes(),
        b"pending-\xfc"
    );

    let rewind = restored.clone();
    restored.reset();
    restored.save(&checkpoint).unwrap();
    let reset = PrescanCursor::load(&checkpoint);
    assert_eq!(reset.position(), (None, None));
    assert_eq!(reset.walk_dispatch(), positions);
    assert!(restored.remember_walk_dispatch(&WalkDispatchCursor::new()));
    assert_eq!(rewind.walk_dispatch(), positions);
}

fn save_restart_priority(request: &RestartRequest, position: WalkDispatchPosition) {
    let mut state = PrescanCursor::load(&request.checkpoint);
    let mut positions = state.walk_dispatch().to_vec();
    positions.retain(|existing| existing.directory != position.directory);
    positions.push(position);
    let dispatch = WalkDispatchCursor::from_positions(positions).unwrap();
    state.remember_walk_dispatch(&dispatch);
    state.save(&request.checkpoint).unwrap();
}

fn restart_priority(request: &RestartRequest, root: &Path) -> WalkDispatchPosition {
    PrescanCursor::load(&request.checkpoint)
        .walk_dispatch()
        .iter()
        .find(|position| position.directory == root)
        .expect("the stopped root must preserve its next processing window")
        .clone()
}

fn received_children(observed: &RestartObservation, parent: &Path) -> BTreeSet<PathBuf> {
    observed
        .received
        .iter()
        .filter(|entry| entry.path.parent() == Some(parent))
        .map(|entry| entry.path.clone())
        .collect()
}

fn assert_oversized_restart_rechecks_marker_and_shrink(
    request: &mut RestartRequest,
    root: &Path,
    boundary: &Path,
    later_window: WalkDispatchPosition,
) {
    let window = usize::try_from(MAX_ENTRIES_PER_DIR).unwrap();
    let authorized_ancestors: BTreeSet<_> = root
        .ancestors()
        .filter(|path| {
            request
                .roots
                .iter()
                .any(|configured| path.starts_with(configured))
        })
        .map(Path::to_path_buf)
        .collect();
    let marker = root.join(".sbh-protect");
    fs::write(&marker, b"new offline protection").unwrap();
    let marker_index = fs::read_dir(root)
        .unwrap()
        .position(|entry| entry.unwrap().path() == marker)
        .unwrap();
    // Select a processing window that does not contain the new marker. A
    // fresh name scan beyond that window must still protect the whole root.
    save_restart_priority(
        request,
        WalkDispatchPosition {
            directory: root.to_path_buf(),
            window_start: if marker_index < window {
                MAX_ENTRIES_PER_DIR
            } else {
                0
            },
            next_child: None,
        },
    );
    request.allowance = None;
    let protected = request.run();
    assert!(
        protected.received.iter().all(|entry| {
            !entry.path.starts_with(root) && authorized_ancestors.contains(&entry.path)
        }),
        "a restored window cannot expose any protected subtree entry: {protected:?}"
    );
    assert_eq!(fs::read(&marker).unwrap(), b"new offline protection");

    // Keep the actual later-window receipt, then shrink the configured path
    // offline by moving its complete old tree aside. Nothing is deleted.
    save_restart_priority(request, later_window);
    let retained = request.checkpoint.with_file_name("retained-wide-tree");
    fs::rename(root, &retained).unwrap();
    let replacement = BTreeSet::from([root.join("new-a"), root.join("new-b")]);
    for child in &replacement {
        fs::create_dir_all(child).unwrap();
        fs::write(child.join("payload"), b"new fixture").unwrap();
    }
    request.allowance = Some(48);
    let out_of_range = request.run();
    assert!(
        out_of_range
            .received
            .iter()
            .all(|entry| authorized_ancestors.contains(&entry.path)),
        "an ancestor observation cannot count as the skipped children: {out_of_range:?}"
    );
    assert!(out_of_range.unfinished.contains(&root.to_path_buf()));
    let reset = PrescanCursor::load(&request.checkpoint);
    assert!(
        reset
            .walk_dispatch()
            .iter()
            .all(|position| { position.directory != root || position.window_start == 0 }),
        "an obsolete window cannot remain the next priority"
    );
    request.allowance = None;
    let revisited = request.run();
    assert!(revisited.unfinished.is_empty(), "{revisited:?}");
    assert_eq!(received_children(&revisited, root), replacement);

    // Even an offset still inside EOF skipped a prefix. A now-small listing
    // cannot certify that prefix merely because it fits the ordinary window.
    save_restart_priority(
        request,
        WalkDispatchPosition {
            directory: root.to_path_buf(),
            window_start: 1,
            next_child: None,
        },
    );
    let tail = request.run();
    let tail_children = received_children(&tail, root);
    assert_eq!(tail_children.len(), 1, "{tail:?}");
    assert!(replacement.contains(tail_children.first().unwrap()));
    assert!(tail.unfinished.contains(&root.to_path_buf()));
    assert_eq!(restart_priority(request, root).window_start, 0);
    let fresh = request.run();
    assert!(fresh.unfinished.is_empty(), "{fresh:?}");
    assert_eq!(received_children(&fresh, root), replacement);
    for child in replacement {
        assert_eq!(fs::read(child.join("payload")).unwrap(), b"new fixture");
    }
    assert_eq!(
        fs::read(retained.join(boundary.file_name().unwrap()).join("payload")).unwrap(),
        b"retained wide fixture"
    );
    assert_eq!(fs::read_dir(&retained).unwrap().count(), window + 9);
}

#[test]
fn oversized_windows_survive_process_restart_only_after_received_boundary_work() {
    const TEST: &str =
        "oversized_windows_survive_process_restart_only_after_received_boundary_work";
    if restart_child_if_requested(TEST) {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let configured = base.join("tree");
    let root = configured.join("wide-tree");
    fs::create_dir_all(&root).unwrap();
    let window = usize::try_from(MAX_ENTRIES_PER_DIR).unwrap();
    for index in 0..window + 8 {
        fs::create_dir(root.join(format!("child-{index:05}"))).unwrap();
    }
    // Native enumeration order is intentionally unspecified. Observe this
    // unchanged first page, then start near its sorted dispatch boundary;
    // the real production window remains 65,536, without a test-only knob.
    let first_page: BTreeSet<_> = fs::read_dir(&root)
        .unwrap()
        .take(window)
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(first_page.len(), window);
    let remainder: BTreeSet<_> = fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| !first_page.contains(path))
        .collect();
    assert_eq!(remainder.len(), 8);
    let boundary = first_page.last().unwrap().clone();
    fs::write(boundary.join("payload"), b"retained wide fixture").unwrap();
    let mut request = RestartRequest::new(TEST, &base, vec![configured.clone()]);
    request.allowance = Some(window / 256 + 32);
    request.stop_depth = 2;
    // The ancestor's ordinary dispatch permit must not permanently prevent
    // its child from opening a full production-size processing window.
    save_restart_priority(
        &request,
        WalkDispatchPosition {
            directory: configured,
            window_start: 0,
            next_child: Some(root.file_name().unwrap().to_os_string()),
        },
    );
    let initial = WalkDispatchPosition {
        directory: root.clone(),
        window_start: 0,
        next_child: Some(boundary.file_name().unwrap().to_os_string()),
    };
    save_restart_priority(&request, initial.clone());

    request.consume_results = false;
    let queued = request.run();
    assert!(queued.received.is_empty());
    assert!(queued.unfinished.contains(&boundary), "{queued:?}");
    assert_eq!(restart_priority(&request, &root), initial);

    request.consume_results = true;
    let received = request.run();
    assert_eq!(
        received_children(&received, &root),
        BTreeSet::from([boundary.clone()]),
        "{received:?}"
    );
    assert_eq!(
        received
            .received
            .iter()
            .find(|entry| entry.path == boundary)
            .unwrap()
            .depth,
        2,
        "restored window work must retain its ordinary ancestor depth"
    );
    let later_window = restart_priority(&request, &root);
    assert_eq!(later_window.window_start, MAX_ENTRIES_PER_DIR);
    assert!(later_window.next_child.is_none());
    assert!(received.unfinished.contains(&root));

    let mut later_seen = BTreeSet::new();
    for _ in 0..remainder.len() {
        let resumed = request.run();
        let later_children = received_children(&resumed, &root);
        assert_eq!(later_children.len(), 1, "{resumed:?}");
        assert!(remainder.contains(later_children.first().unwrap()));
        assert!(
            resumed
                .received
                .iter()
                .filter(|entry| entry.path.parent() == Some(root.as_path()))
                .all(|entry| entry.depth == 2)
        );
        assert!(resumed.restored_positions > 0);
        later_seen.extend(later_children);
    }
    assert_eq!(later_seen, remainder);
    let wrapped = restart_priority(&request, &root);
    assert_eq!(wrapped.window_start, 0);
    assert!(wrapped.next_child.is_none());
    assert_oversized_restart_rechecks_marker_and_shrink(
        &mut request,
        &root,
        &boundary,
        later_window,
    );
}
