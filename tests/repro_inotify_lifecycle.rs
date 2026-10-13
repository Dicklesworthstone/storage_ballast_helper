//! Real Linux filesystem regressions for the public event-source lifecycle.
//! No fabricated inotify events: repairs must restore observation of later
//! writes, not just change a capability label. Explicit clock values exercise
//! retry boundaries without sleeping through production backoff windows.

#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use storage_ballast_helper::core::config::ScannerConfig;
use storage_ballast_helper::scanner::events::{
    EventBackendKind, EventInvalidation, EventSourceConfig, EventSourcePlan, ScannerEventSource,
};
use storage_ballast_helper::scanner::index::{ScannerCandidateIndex, ScannerIndexContext};

fn source(root: &Path, budget: usize, now: Instant) -> ScannerEventSource {
    ScannerEventSource::start_at(
        EventSourceConfig::from_scanner_config(
            &[root.to_path_buf()],
            &ScannerConfig {
                event_watch_budget: budget,
                ..ScannerConfig::default()
            },
        ),
        now,
    )
}

fn until(
    source: &mut ScannerEventSource,
    at: Instant,
    mut ready: impl FnMut(&ScannerEventSource, &EventInvalidation) -> bool,
) -> EventInvalidation {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut all = EventInvalidation::empty();
    loop {
        all.merge(source.drain_at(at));
        if ready(source, &all) {
            return all;
        }
        assert!(
            Instant::now() < deadline,
            "missing kernel event: {all:?}; {:?}",
            source.capability()
        );
        thread::sleep(Duration::from_millis(5));
    }
}

/// Whether the watch-rebuild worker thread has exited. The process admits one
/// rebuild at a time and frees that slot only when its worker exits, which is
/// just after the worker retires the old backend it was handed.
fn rebuild_worker_exited() -> bool {
    !fs::read_dir("/proc/self/task")
        .unwrap()
        .flatten()
        .any(|task| {
            fs::read_to_string(task.path().join("comm"))
                .is_ok_and(|name| name.starts_with("sbh-watch-rebui"))
        })
}

/// Admit the watch rebuild that is due at `at` and drain until it has been
/// handed off or has failed. Rebuilds run on a worker thread: the drain that
/// admits one reports nothing, and a later drain delivers the handoff, which
/// is also when the next repair interval starts. Tests in this file share the
/// process's single admission slot, so they take turns.
fn rebuilt(source: &mut ScannerEventSource, at: Instant) -> EventInvalidation {
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    let before = source.stats().replans;
    // Wait for the handoff's own reason, not for the capability text: the
    // old backend keeps draining meanwhile and may rewrite that text.
    let all = until(source, at, |source, invalidation| {
        let reasons = invalidation.reason_summary();
        source.stats().replans > before
            && (reasons.contains("recursive inotify watch coverage rebuilt")
                || reasons.contains("recursive inotify replan failed"))
    });
    assert_eq!(
        source.stats().replans,
        before + 1,
        "exactly one rebuild is admitted for a due repair"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !rebuild_worker_exited() {
        assert!(
            Instant::now() < deadline,
            "the rebuild worker kept its admission slot"
        );
        thread::sleep(Duration::from_millis(1));
    }
    all
}

fn sees_write(source: &mut ScannerEventSource, path: &Path, at: Instant) {
    fs::write(path, b"observable after repair").unwrap();
    let invalidation = until(source, at, |_, invalidation| {
        invalidation.dirty_paths().contains(path)
    });
    assert!(invalidation.requires_reconciliation());
    assert_eq!(fs::read(path).unwrap(), b"observable after repair");
}

fn root_fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let root = base.join("root");
    fs::create_dir(&root).unwrap();
    (temp, base, root)
}

#[test]
fn moved_in_populated_tree_gets_descendant_watches_without_another_topology_event() {
    let (_temp, base, root) = root_fixture();
    let incoming = base.join("incoming");
    fs::create_dir_all(incoming.join("deep/deeper")).unwrap();
    fs::write(incoming.join("kept"), b"retain the incoming tree").unwrap();
    let now = Instant::now();
    let mut events = source(&root, 16, now);
    assert_eq!(
        events.capability().selected_backend,
        EventBackendKind::RecursiveInotify
    );
    assert!(events.capability().complete);
    let _ = events.drain_at(now);

    let project = root.join("project");
    fs::rename(incoming, &project).unwrap();
    let changed = until(
        &mut events,
        now + Duration::from_secs(1),
        |source, invalidation| {
            !source.capability().complete && invalidation.dirty_paths().contains(&project)
        },
    );
    assert!(changed.requires_index_generation_bump());
    let repaired = rebuilt(&mut events, now + Duration::from_secs(30));
    assert!(repaired.requires_index_generation_bump());
    assert!(repaired.dirty_roots().contains(&root));
    assert!(events.capability().complete);
    assert_eq!(events.capability().watched_dirs, 4);
    sees_write(
        &mut events,
        &project.join("deep/deeper/new.o"),
        now + Duration::from_secs(31),
    );
    assert_eq!(
        fs::read(project.join("kept")).unwrap(),
        b"retain the incoming tree"
    );
}

#[test]
fn identical_pathnames_after_root_replacement_do_not_reuse_old_inode_watches() {
    let (_temp, base, root) = root_fixture();
    fs::create_dir(root.join("deep")).unwrap();
    fs::write(root.join("deep/kept"), b"retain old data").unwrap();
    let inode = fs::metadata(&root).unwrap().ino();
    let now = Instant::now();
    let mut events = source(&root, 16, now);
    assert_eq!(
        events.capability().selected_backend,
        EventBackendKind::RecursiveInotify
    );
    let _ = events.drain_at(now);

    let retired = base.join("retired");
    fs::rename(&root, &retired).unwrap();
    fs::create_dir_all(root.join("deep")).unwrap();
    assert_ne!(fs::metadata(&root).unwrap().ino(), inode);
    let lost = until(
        &mut events,
        now + Duration::from_secs(1),
        |source, invalidation| {
            !source.capability().complete && invalidation.requires_index_generation_bump()
        },
    );
    assert!(lost.dirty_roots().contains(&root));
    assert_eq!(events.capability().watched_dirs, 0);
    let repaired = rebuilt(&mut events, now + Duration::from_secs(30));
    assert!(repaired.requires_index_generation_bump());
    assert!(events.capability().complete);
    assert_eq!(events.capability().watched_dirs, 2);
    sees_write(
        &mut events,
        &root.join("deep/current.o"),
        now + Duration::from_secs(31),
    );

    fs::write(
        retired.join("deep/outside.o"),
        b"not under the configured root",
    )
    .unwrap();
    let outside = events.drain_at(now + Duration::from_secs(32));
    assert!(
        outside.dirty_paths().is_empty(),
        "retired watch names leaked: {outside:?}"
    );
    assert_eq!(
        fs::read(retired.join("deep/kept")).unwrap(),
        b"retain old data"
    );
}

#[test]
fn a_root_missing_at_startup_can_recover_without_any_old_backend_traffic() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path())
        .unwrap()
        .join("not-yet-mounted");
    let now = Instant::now();
    let mut events = source(&root, 16, now);
    assert_eq!(
        events.capability().selected_backend,
        EventBackendKind::ReconciliationOnly
    );
    assert_eq!(events.capability().watched_dirs, 0);
    let _ = events.drain_at(now);
    fs::create_dir_all(root.join("project")).unwrap();
    assert!(
        !events
            .drain_at(now + Duration::from_secs(29))
            .requires_reconciliation()
    );
    assert_eq!(events.stats().replans, 0);

    let repaired = rebuilt(&mut events, now + Duration::from_secs(30));
    assert_eq!(events.stats().replans, 1);
    assert_eq!(
        events.capability().selected_backend,
        EventBackendKind::RecursiveInotify
    );
    assert!(events.capability().complete);
    assert!(repaired.requires_index_generation_bump());
    sees_write(
        &mut events,
        &root.join("project/new.o"),
        now + Duration::from_secs(31),
    );
}

#[test]
fn persistent_fallback_failures_are_paced_and_eventually_recover() {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let root = base.join("blocked");
    fs::write(&root, b"preserve the blocking file").unwrap();
    let now = Instant::now();
    let mut events = source(&root, 16, now);
    let _ = events.drain_at(now);
    // One attempt per repair interval, and the interval restarts when an
    // attempt completes: nothing is admitted in the 29 s after each one.
    for attempt in 0..2 {
        let due = 30 * (attempt + 1);
        for second in due - 29..due {
            events.drain_at(now + Duration::from_secs(second));
            assert_eq!(events.stats().replans, attempt);
            assert_eq!(events.capability().watched_dirs, 0);
            assert!(!events.capability().complete);
        }
        rebuilt(&mut events, now + Duration::from_secs(due));
        assert_eq!(events.stats().replans, attempt + 1);
        assert_eq!(events.capability().watched_dirs, 0);
        assert!(!events.capability().complete);
    }
    fs::rename(&root, base.join("retained-file")).unwrap();
    fs::create_dir(&root).unwrap();
    events.drain_at(now + Duration::from_secs(89));
    assert_eq!(events.stats().replans, 2);
    rebuilt(&mut events, now + Duration::from_secs(90));
    assert_eq!(events.stats().replans, 3);
    assert!(events.capability().complete);
    sees_write(
        &mut events,
        &root.join("new.o"),
        now + Duration::from_secs(91),
    );
    assert_eq!(
        fs::read(base.join("retained-file")).unwrap(),
        b"preserve the blocking file"
    );
}

#[test]
fn repeated_subtree_replacement_reuses_watch_capacity_and_restores_deep_events() {
    let (_temp, base, root) = root_fixture();
    let mut current = root.join("project-0");
    fs::create_dir_all(current.join("deep")).unwrap();
    let mut at = Instant::now();
    let mut events = source(&root, 3, at);
    assert!(events.capability().complete);
    assert_eq!(events.capability().watched_dirs, 3);
    let _ = events.drain_at(at);

    for cycle in 1..=4 {
        fs::rename(&current, base.join(format!("retired-{cycle}"))).unwrap();
        until(&mut events, at + Duration::from_secs(1), |source, _| {
            source.capability().watched_dirs == 1
        });
        let incoming = base.join(format!("incoming-{cycle}"));
        fs::create_dir_all(incoming.join("deep")).unwrap();
        current = root.join(format!("project-{cycle}"));
        fs::rename(incoming, &current).unwrap();
        until(
            &mut events,
            at + Duration::from_secs(2),
            |_, invalidation| invalidation.dirty_paths().contains(&current),
        );
        at += Duration::from_secs(31);
        let repaired = rebuilt(&mut events, at);
        assert!(repaired.requires_index_generation_bump());
        assert!(events.capability().complete);
        assert_eq!(events.capability().watched_dirs, 3, "cycle {cycle}");
        assert_eq!(events.stats().replans, cycle);
        sees_write(
            &mut events,
            &current.join("deep/live.o"),
            at + Duration::from_secs(1),
        );
    }
    assert!(base.join("retired-1/deep").is_dir());
}

#[test]
fn quiet_instance_handoff_explicitly_invalidates_the_old_index_generation() {
    let (_temp, _base, root) = root_fixture();
    let now = Instant::now();
    let mut events = source(&root, 16, now);
    assert!(events.capability().complete);
    let _ = events.drain_at(now);
    let mut index = ScannerCandidateIndex::new(ScannerIndexContext {
        root_fingerprint: "quiet-root".into(),
        config_fingerprint: "quiet-config".into(),
    });
    let generation = index.event_generation();
    let handoff = rebuilt(&mut events, now + Duration::from_mins(15));
    assert_eq!(events.stats().replans, 1);
    assert!(events.capability().complete);
    assert!(handoff.dirty_roots().contains(&root));
    handoff.apply_to_index(&mut index);
    assert_eq!(index.event_generation(), generation + 1);
    sees_write(
        &mut events,
        &root.join("after-handoff.o"),
        now + Duration::from_mins(15) + Duration::from_secs(1),
    );
}

#[test]
fn large_real_event_bursts_produce_bounded_conservative_invalidation() {
    let (_temp, _base, root) = root_fixture();
    let now = Instant::now();
    let mut events = source(&root, 16, now);
    assert!(events.capability().complete);
    let _ = events.drain_at(now);
    for n in 0..2048 {
        fs::write(root.join(format!("artifact-{n:04}")), b"retained").unwrap();
    }
    let started = Instant::now();
    let invalidation = events.drain_at(now + Duration::from_secs(1));
    // Generous hang guard, not a claim that scheduling/kernel I/O is preemptible.
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(invalidation.requires_index_generation_bump());
    assert!(invalidation.dirty_roots().contains(&root));
    assert!(invalidation.dirty_paths().len() <= 512);
    assert_eq!(fs::read(root.join("artifact-2047")).unwrap(), b"retained");
}

#[test]
fn file_only_flat_directories_exhaust_planning_without_claiming_complete_coverage() {
    let (_temp, _base, root) = root_fixture();
    // No directories: the old candidate-count cap could not stop this read.
    for n in 0..16_384 {
        fs::write(root.join(format!("retained-{n:05}")), b"keep").unwrap();
    }
    let config = EventSourceConfig::from_scanner_config(
        std::slice::from_ref(&root),
        &ScannerConfig {
            event_watch_budget: 8,
            ..ScannerConfig::default()
        },
    );
    let plan = EventSourcePlan::for_config(&config);
    assert!(
        !plan.complete,
        "unobserved EOF must not become complete coverage"
    );
    assert_eq!(plan.watched_dirs, vec![root.clone()]);
    assert!(plan.dirty_roots.contains(&root));
    assert!(
        plan.reason.contains("planning incomplete"),
        "{}",
        plan.reason
    );

    let now = Instant::now();
    let mut events = ScannerEventSource::start_at(config, now);
    assert!(!events.capability().complete);
    assert_eq!(events.capability().watched_dirs, 1);
    let startup = events.drain_at(now);
    assert!(startup.requires_index_generation_bump());
    assert!(startup.dirty_roots().contains(&root));
    sees_write(
        &mut events,
        &root.join("new-top-level.o"),
        now + Duration::from_secs(1),
    );
    assert_eq!(fs::read(root.join("retained-16383")).unwrap(), b"keep");
}

#[test]
fn candidate_budget_gaps_revoke_replay_and_can_recover_after_root_replacement() {
    let (_temp, base, root) = root_fixture();
    for n in 0..100 {
        fs::create_dir(root.join(format!("project-{n:03}"))).unwrap();
    }
    fs::write(
        root.join("project-099/retained"),
        b"preserve the large tree",
    )
    .unwrap();
    let now = Instant::now();
    let mut events = source(&root, 1, now);
    assert!(!events.capability().complete);
    assert_eq!(events.capability().watched_dirs, 1);
    // Previously every child was retained despite the four-candidate budget;
    // the plan reported individual frontier children, not unenumerated root coverage.
    let startup = events.drain_at(now);
    assert!(startup.dirty_roots().contains(&root), "{startup:?}");
    let mut index = ScannerCandidateIndex::new(ScannerIndexContext {
        root_fingerprint: "bounded-plan-root".into(),
        config_fingerprint: "bounded-plan-config".into(),
    });
    startup.apply_to_index(&mut index);
    assert_eq!(index.event_generation(), 1);

    let retained = base.join("retired-wide-root");
    fs::rename(&root, &retained).unwrap();
    fs::create_dir(&root).unwrap();
    until(&mut events, now + Duration::from_secs(1), |source, _| {
        source.capability().watched_dirs == 0
    });
    let repaired = rebuilt(&mut events, now + Duration::from_secs(30));
    assert!(repaired.requires_index_generation_bump());
    assert!(events.capability().complete);
    assert_eq!(events.capability().watched_dirs, 1);
    sees_write(
        &mut events,
        &root.join("after-repair.o"),
        now + Duration::from_secs(31),
    );
    assert_eq!(
        fs::read(retained.join("project-099/retained")).unwrap(),
        b"preserve the large tree"
    );
}

#[test]
fn bounded_periodic_replan_keeps_an_independent_root_observable() {
    let (_temp, base, root) = root_fixture();
    let healthy = base.join("z-independent");
    fs::create_dir(&healthy).unwrap();
    let now = Instant::now();
    let config = EventSourceConfig::from_scanner_config(
        &[root.clone(), healthy.clone()],
        &ScannerConfig {
            event_watch_budget: 4,
            ..ScannerConfig::default()
        },
    );
    let mut events = ScannerEventSource::start_at(config, now);
    assert!(events.capability().complete);
    let _ = events.drain_at(now);
    for n in 0..16_384 {
        fs::write(root.join(format!("retained-{n:05}")), b"keep").unwrap();
    }
    let later = now + Duration::from_mins(15);
    let replanned = rebuilt(&mut events, later);
    assert_eq!(events.stats().replans, 1);
    assert!(!events.capability().complete);
    assert_eq!(events.capability().watched_dirs, 2);
    assert!(replanned.requires_index_generation_bump());
    assert!(replanned.dirty_roots().contains(&root));
    sees_write(
        &mut events,
        &healthy.join("independent.o"),
        later + Duration::from_secs(1),
    );
    assert_eq!(fs::read(root.join("retained-16383")).unwrap(), b"keep");
}
