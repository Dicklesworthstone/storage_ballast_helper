//! Exercise pressure ordering through the real, single-worker directory walk.
//! The consumer accepts one result, then cancels the pass without publishing
//! completion feedback. Merely returning every root is not sufficient progress.

#![cfg(unix)]

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crossbeam_channel::RecvTimeoutError;
use storage_ballast_helper::monitor::voi_scheduler::{
    MAX_REVISIT_INTERVAL, VoiConfig, VoiScheduler,
};
use storage_ballast_helper::scanner::protection::ProtectionRegistry;
use storage_ballast_helper::scanner::walker::{DirectoryWalker, WalkEntry, WalkerConfig};

fn fixture(count: usize) -> (tempfile::TempDir, Vec<PathBuf>) {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let roots: Vec<_> = (0..count)
        .map(|index| base.join(format!("root-{index:02}")))
        .collect();
    for root in &roots {
        fs::create_dir(root).unwrap();
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
    let receiver = walker.stream().unwrap();
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
        assert_eq!(fs::read(root.join("candidate.bin")).unwrap(), b"retained fixture data");
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
    assert!(roots.iter().all(|root| scheduler.path_stats(root).unwrap().scan_count == 0));
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
    let mut scheduler = VoiScheduler::new(VoiConfig { enabled: false, ..VoiConfig::default() });
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
    let mut scheduler = VoiScheduler::new(VoiConfig { enabled: false, ..VoiConfig::default() });
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
    let mut scheduler = VoiScheduler::new(VoiConfig { enabled: false, ..VoiConfig::default() });
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
