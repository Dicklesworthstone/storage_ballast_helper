//! Regression (7d87a75): the scanner deadlocked on every production machine
//! because walker threads did a blocking `send` on the bounded result
//! channel while the consumer was busy, so a slow consumer stalled the walk
//! forever and "0 scans" was the daemon's steady state.
//!
//! The walk must complete and deliver every entry even when the consumer
//! does not read for a while, and must stop promptly when cancelled.

#![allow(missing_docs)]

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use storage_ballast_helper::scanner::protection::ProtectionRegistry;
use storage_ballast_helper::scanner::walker::{DirectoryWalker, WalkerConfig};

/// Build `dirs` directories with `files_per_dir` files each and return the
/// number of directories: the walker yields one entry per directory (files
/// are folded into their directory's content size), and directories are
/// what the scanner scores.
fn fixture_tree(root: &Path, dirs: usize, files_per_dir: usize) -> usize {
    for d in 0..dirs {
        let dir = root.join(format!("project-{d:04}"));
        std::fs::create_dir_all(&dir).unwrap();
        for f in 0..files_per_dir {
            std::fs::write(dir.join(format!("file-{f:03}.o")), b"x").unwrap();
        }
    }
    dirs
}

fn walker_for(root: &Path) -> DirectoryWalker {
    DirectoryWalker::new(
        WalkerConfig {
            root_paths: vec![root.to_path_buf()],
            max_depth: 6,
            follow_symlinks: false,
            cross_devices: false,
            parallelism: 4,
            excluded_paths: HashSet::new(),
            opaque_pruning: false,
        },
        ProtectionRegistry::marker_only(),
    )
}

#[test]
fn slow_consumer_does_not_deadlock_the_walk() {
    let tmp = tempfile::tempdir().unwrap();
    // Far more directory entries than the bounded result channel holds.
    let expected = fixture_tree(tmp.path(), 3000, 2);

    let walker = walker_for(tmp.path());
    let rx = walker.stream().expect("stream starts");
    let started = Instant::now();

    // Do not read anything for a while: every walker thread fills the
    // channel and must block *with a timeout*, not forever.
    std::thread::sleep(Duration::from_millis(1500));

    let mut seen = HashSet::new();
    while let Ok(entry) = rx.recv_timeout(Duration::from_secs(20)) {
        seen.insert(entry.path);
    }
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "walk did not finish after a stalled consumer"
    );
    assert_eq!(
        seen.len(),
        expected,
        "every entry arrives once the consumer catches up"
    );
}

#[test]
fn cancelled_walk_stops_even_with_no_consumer() {
    let tmp = tempfile::tempdir().unwrap();
    fixture_tree(tmp.path(), 2500, 2);

    let walker = walker_for(tmp.path());
    let cancel = walker.cancel_token();
    let rx = walker.stream().expect("stream starts");
    // Nobody reads. Cancelling must release the blocked senders.
    std::thread::sleep(Duration::from_millis(300));
    cancel.store(true, Ordering::Relaxed);

    let started = Instant::now();
    // Drain whatever was buffered; the channel must disconnect soon after.
    let mut drained = 0usize;
    while rx.recv_timeout(Duration::from_secs(10)).is_ok() {
        drained += 1;
    }
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "senders kept the channel open after cancellation (drained {drained})"
    );
}
