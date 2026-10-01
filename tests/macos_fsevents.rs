//! Native scanner-event regressions. These must execute on a macOS runner;
//! successful Linux compilation or a fallback backend is not native proof.

#![cfg(target_os = "macos")]

use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use storage_ballast_helper::core::config::{ScannerConfig, ScannerEventSourceMode};
use storage_ballast_helper::scanner::events::{
    EventBackendKind, EventInvalidation, EventSourceConfig, ScannerEventSource,
};

fn config(roots: &[PathBuf], budget: usize) -> EventSourceConfig {
    EventSourceConfig::from_scanner_config(
        roots,
        &ScannerConfig {
            event_watch_budget: budget,
            ..Default::default()
        },
    )
}

fn assert_native(source: &ScannerEventSource) {
    assert_eq!(
        source.capability().selected_backend,
        EventBackendKind::Fsevents,
        "native FSEvents is required by this test: {:?}",
        source.capability(),
    );
}

fn await_paths(source: &mut ScannerEventSource, paths: &[PathBuf]) -> EventInvalidation {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut observed = EventInvalidation::empty();
    while Instant::now() < deadline {
        observed.merge(source.drain());
        if paths
            .iter()
            .all(|path| observed.dirty_paths().contains(path))
        {
            return observed;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("FSEvents did not report {paths:?}: {observed:?}");
}

#[test]
fn native_stream_covers_directories_created_after_start_and_existing_file_writes() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    fs::create_dir(&root).unwrap();
    let existing = root.join("existing.log");
    fs::write(&existing, b"before watcher").unwrap();
    let mut source = ScannerEventSource::start(config(std::slice::from_ref(&root), 1));
    assert_native(&source);
    assert!(source.capability().complete);
    let startup = source.drain();
    assert!(startup.requires_index_generation_bump());
    assert!(startup.dirty_roots().contains(&root));

    // Consume startup history before changing a pre-existing file's contents.
    thread::sleep(Duration::from_millis(500));
    let _ = source.drain();
    fs::write(&existing, b"modified without renaming the file").unwrap();
    await_paths(&mut source, std::slice::from_ref(&existing));

    let nested = root.join("project").join("nested");
    fs::create_dir_all(&nested).unwrap();
    let changed = nested.join("object.o");
    fs::write(&changed, b"fresh native event").unwrap();
    let event = await_paths(&mut source, std::slice::from_ref(&changed));
    assert!(
        event
            .dirty_roots()
            .iter()
            .any(|scan| changed.starts_with(scan))
    );
    assert_eq!(
        source.capability().watched_dirs,
        1,
        "one recursive root, not per-directory watches"
    );
    assert!(source.stats().rate_tracked_dirs <= 1);
}

#[test]
fn configured_ancestor_aliases_receive_canonical_kernel_events() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let real_parent = temp.path().join("real");
    let alias_parent = temp.path().join("alias");
    let real = real_parent.join("work");
    fs::create_dir_all(&real).unwrap();
    symlink(&real_parent, &alias_parent).unwrap();
    let alias = alias_parent.join("work");
    let roots = vec![real.clone(), alias.clone()];
    let mut source = ScannerEventSource::start(config(&roots, 1));
    assert_native(&source);
    assert!(source.capability().complete);
    assert_eq!(source.capability().watched_dirs, 1);
    let _ = source.drain();

    let changed = real.join("object.o");
    fs::write(&changed, b"aliased path").unwrap();
    let events = await_paths(&mut source, &[changed, alias.join("object.o")]);
    assert!(events.dirty_roots().contains(&alias));
    assert!(events.dirty_roots().contains(&real));
}

#[test]
fn missing_roots_retry_without_events_and_unchanged_gaps_do_not_rescan() {
    let temp = tempfile::tempdir().unwrap();
    let healthy = temp.path().join("healthy");
    let missing = temp.path().join("missing");
    fs::create_dir(&healthy).unwrap();
    let now = Instant::now();
    let mut source = ScannerEventSource::start_at(config(&[healthy, missing.clone()], 2), now);
    assert_native(&source);
    assert!(!source.capability().complete);
    assert!(source.drain_at(now).dirty_roots().contains(&missing));

    let unchanged = source.drain_at(now + Duration::from_secs(31));
    assert_eq!(source.stats().replans, 1);
    assert!(
        !unchanged.requires_reconciliation(),
        "unchanged missing roots must not cause a scan loop: {unchanged:?}"
    );
    assert!(!unchanged.requires_index_generation_bump());

    fs::create_dir(&missing).unwrap();
    let _ = source.drain_at(now + Duration::from_secs(59));
    assert_eq!(source.stats().replans, 1);
    let recovered = source.drain_at(now + Duration::from_secs(62));
    assert_native(&source);
    assert!(source.capability().complete);
    assert_eq!(source.capability().watched_dirs, 2);
    assert!(recovered.requires_index_generation_bump());
    assert!(recovered.dirty_roots().contains(&missing));
    let changed = missing.join("new.log");
    fs::write(&changed, b"newly recovered root").unwrap();
    await_paths(&mut source, &[changed]);
}

#[test]
fn a_replaced_root_rebinds_to_the_new_directory_and_revokes_old_candidates() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    let old = temp.path().join("old-root");
    fs::create_dir(&root).unwrap();
    let now = Instant::now();
    let mut source = ScannerEventSource::start_at(config(std::slice::from_ref(&root), 1), now);
    assert_native(&source);
    let _ = source.drain_at(now);
    fs::rename(&root, &old).unwrap();
    fs::create_dir(&root).unwrap();

    // The periodic identity check must detect replacement even if the kernel
    // root-change event has not arrived yet. No 30-second wall-clock sleep.
    let changed = source.drain_at(now + Duration::from_secs(31));
    assert!(changed.requires_index_generation_bump());
    assert!(changed.dirty_roots().contains(&root));
    assert_native(&source);
    assert!(source.capability().complete);
    assert_eq!(source.stats().replans, 1);
    let new_file = root.join("new.log");
    fs::write(&new_file, b"new inode is watched").unwrap();
    await_paths(&mut source, &[new_file]);
}

#[test]
fn explicit_reconciliation_and_zero_budget_never_start_or_retry_native_streams() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    let now = Instant::now();
    let mut zero = ScannerEventSource::start_at(config(std::slice::from_ref(&root), 0), now);
    let scanner = ScannerConfig {
        event_source: ScannerEventSourceMode::ReconciliationOnly,
        ..Default::default()
    };
    let mut forced = ScannerEventSource::start_at(
        EventSourceConfig::from_scanner_config(&[root], &scanner),
        now,
    );
    for source in [&mut zero, &mut forced] {
        assert_eq!(
            source.capability().selected_backend,
            EventBackendKind::ReconciliationOnly
        );
        let _ = source.drain_at(now);
        let quiet = source.drain_at(now + Duration::from_secs(3600));
        assert!(!quiet.requires_reconciliation());
        assert_eq!(source.stats().replans, 0);
    }
}

#[test]
fn native_rename_and_removal_events_invalidate_the_original_paths() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    let old = root.join("before.log");
    let new = root.join("after.log");
    fs::write(&old, b"rename me").unwrap();
    let mut source = ScannerEventSource::start(config(std::slice::from_ref(&root), 1));
    assert_native(&source);
    let _ = source.drain();
    thread::sleep(Duration::from_millis(500));
    let _ = source.drain();
    fs::rename(&old, &new).unwrap();
    await_paths(&mut source, &[old, new.clone()]);
    thread::sleep(Duration::from_millis(500));
    let _ = source.drain();
    fs::remove_file(&new).unwrap();
    let removed = await_paths(&mut source, &[new]);
    assert!(removed.dirty_roots().contains(&root));
}

#[test]
fn all_missing_roots_stay_quiet_until_native_coverage_can_recover() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("missing");
    let now = Instant::now();
    let mut source = ScannerEventSource::start_at(config(std::slice::from_ref(&root), 1), now);
    assert_eq!(
        source.capability().selected_backend,
        EventBackendKind::ReconciliationOnly
    );
    let _ = source.drain_at(now);
    let quiet = source.drain_at(now + Duration::from_secs(31));
    assert!(!quiet.requires_reconciliation());
    assert!(!quiet.requires_index_generation_bump());
    fs::create_dir(&root).unwrap();
    let recovered = source.drain_at(now + Duration::from_secs(62));
    assert_native(&source);
    assert!(recovered.requires_index_generation_bump());
    let changed = root.join("new.log");
    fs::write(&changed, b"native coverage recovered").unwrap();
    await_paths(&mut source, &[changed]);
}
