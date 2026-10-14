use super::*;
use crate::monitor::ram_scratch::{ProcessSwap, ScratchMount, assess};
use crate::platform::pal::MemoryInfo;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const GIB: u64 = 1024 * 1024 * 1024;

fn observation(pressured: bool, complete: bool) -> Observation {
    let memory = MemoryInfo {
        total_bytes: 62 * GIB,
        available_bytes: 20 * GIB,
        swap_total_bytes: 64 * GIB,
        swap_free_bytes: if pressured { 0 } else { 60 * GIB },
    };
    let mounts = [
        ("/tmp", 32, 26),
        ("/dev/shm", 32, 26),
        ("/run", 8, 6),
        ("/run/user/1000", 8, 6),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (path, total, used))| {
        let used = if pressured { used * GIB } else { 0 };
        ScratchMount {
            path: path.into(),
            filesystem_id: u64::try_from(index).unwrap() + 1,
            total_bytes: total * GIB,
            used_bytes: used,
            available_bytes: total * GIB - used,
        }
    })
    .collect();
    let assessment = assess(
        memory,
        mounts,
        ProcessSwap {
            bytes: 4 * GIB,
            inspected: 100,
            unreadable: usize::from(!complete),
            complete,
        },
    )
    .unwrap();
    Observation {
        observed_at: "2026-10-14T12:00:00Z".to_string(),
        host: ScratchReport {
            schema: "sbh.ram_scratch.v1",
            read_only: true,
            supported: true,
            complete,
            scope: "fixture host counters, not deletion authority",
            assessment: Some(assessment),
            issues: Vec::new(),
            exit_code: if !complete { 4 } else { i32::from(pressured) },
        },
        attribution: Vec::new(),
        attribution_mounts_omitted: 0,
        attribution_error: None,
    }
}

fn warning(event: ActivityEvent) -> (String, serde_json::Value) {
    let ActivityEvent::Warning { code, message } = event else {
        panic!("expected warning");
    };
    (code, serde_json::from_str(&message).unwrap())
}

#[test]
fn full_swap_fixture_produces_one_warning_naming_all_four_mounts() {
    let mut notices = Notices::default();
    let event = notices
        .finish(Ok(observation(true, true)), Instant::now())
        .unwrap();
    let entry = crate::logger::dual::event_to_log_entry(&event);
    assert_eq!(entry.severity, crate::logger::jsonl::Severity::Warning);
    assert!(entry.size.is_none());
    assert!(entry.decision_id.is_none());
    #[cfg(feature = "sqlite")]
    {
        let row = crate::logger::dual::event_to_activity_row(&event).unwrap();
        assert_eq!(row.details, entry.details);
        assert_eq!(row.severity, "warning");
        assert!(row.size_bytes.is_none());
    }
    let (code, payload) = warning(event);
    assert_eq!(code, "SBH-RAM-SCRATCH");
    assert_eq!(payload["read_only"], true);
    assert_eq!(
        payload["observation"]["host"]["assessment"]["tmpfs_used_bytes"],
        64 * GIB
    );
    let summary = payload["summary"].as_str().unwrap();
    for path in ["/tmp", "/dev/shm", "/run", "/run/user/1000"] {
        assert!(summary.contains(path), "{path}: {summary}");
    }
    assert!(notices.finish(Ok(observation(true, true)), Instant::now()).is_none());
}

#[test]
fn empty_mounts_do_not_warn_or_start_recovery_messages() {
    let mut notices = Notices::default();
    for _ in 0..3 {
        assert!(notices.finish(Ok(observation(false, true)), Instant::now()).is_none());
    }
}

#[test]
fn recurring_risk_is_coalesced_and_missing_evidence_cannot_clear_it() {
    let now = Instant::now();
    let mut notices = Notices::default();
    assert!(notices.finish(Ok(observation(true, true)), now).is_some());
    assert!(notices.finish(Ok(observation(true, true)), now + SAMPLE_INTERVAL).is_none());
    assert!(notices.finish(Ok(observation(false, false)), now + SAMPLE_INTERVAL * 2).is_none());
    let (_, payload) = warning(
        notices
            .finish(Ok(observation(false, false)), now + NOTICE_INTERVAL)
            .unwrap(),
    );
    assert_eq!(payload["state"], "incomplete");
    let recovered = notices
        .finish(
            Ok(observation(false, true)),
            now + NOTICE_INTERVAL + SAMPLE_INTERVAL,
        )
        .unwrap();
    let ActivityEvent::Info { message } = recovered else {
        panic!("expected recovery");
    };
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&message).unwrap()["state"],
        "recovered"
    );
    assert!(notices.finish(Ok(observation(false, true)), now + NOTICE_INTERVAL * 2).is_none());
    assert!(notices.finish(Ok(observation(true, true)), now + NOTICE_INTERVAL * 2).is_some());
}

#[test]
fn new_risks_are_reported_without_rearming_for_threshold_flapping() {
    let now = Instant::now();
    let mut notices = Notices::default();
    let mut initial = observation(true, true);
    initial.host.assessment.as_mut().unwrap().reasons = vec!["tmpfs_exceeds_half_ram"];
    assert!(notices.finish(Ok(initial), now).is_some());
    assert!(notices.finish(Ok(observation(true, true)), now + SAMPLE_INTERVAL).is_some());
    let mut reduced = observation(true, true);
    reduced.host.assessment.as_mut().unwrap().reasons = vec!["tmpfs_exceeds_half_ram"];
    assert!(notices.finish(Ok(reduced), now + SAMPLE_INTERVAL * 2).is_none());
    assert!(notices.finish(Ok(observation(true, true)), now + SAMPLE_INTERVAL * 3).is_none());
}

#[test]
fn oversized_detail_is_explicitly_truncated_not_silently_claimed_complete() {
    let mut sample = observation(true, true);
    sample.host.assessment.as_mut().unwrap().mounts[0].path = "x".repeat(MAX_DETAILS_BYTES);
    let details = sample.details("warning");
    assert!(details.len() <= MAX_DETAILS_BYTES);
    let value: serde_json::Value = serde_json::from_str(&details).unwrap();
    assert_eq!(value["state"], "warning");
    assert_eq!(value["complete"], false);
    assert_eq!(value["details_truncated"], true);
}

fn armed(now: Instant) -> Observer {
    Observer {
        enabled: true,
        started_once: true,
        next_due: Some(now),
        ..Default::default()
    }
}

fn wait_for_worker(observer: &Observer) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !observer.job.as_ref().unwrap().worker.is_finished() {
        assert!(Instant::now() < deadline, "test worker did not finish");
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn probes_start_only_for_daemon_lifecycle_and_wait_for_the_startup_grace() {
    let now = Instant::now();
    let mut observer = Observer::default();
    assert!(observer.poll_with(now, || panic!("inactive observer ran")).is_none());
    assert!(observer.job.is_none());
    observer.on_event(&ActivityEvent::Info { message: "CLI output".into() }, now);
    assert!(!observer.enabled);
    observer.on_event(
        &ActivityEvent::DaemonStarted {
            version: "test".into(),
            config_hash: "fixture".into(),
        },
        now,
    );
    assert_eq!(observer.enabled, cfg!(target_os = "linux"));
    assert!(observer
        .poll_with(now + STARTUP_DELAY - Duration::from_nanos(1), || {
            panic!("startup grace ignored")
        })
        .is_none());
    assert!(observer.job.is_none());
}

#[test]
fn completed_probe_waits_a_full_interval_before_starting_another() {
    let now = Instant::now();
    let count = Arc::new(AtomicUsize::new(0));
    let calls = Arc::clone(&count);
    let mut observer = armed(now);
    assert!(observer
        .poll_with(now, move || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(observation(false, true))
        })
        .is_none());
    wait_for_worker(&observer);
    assert!(observer
        .poll_with(now, || panic!("completion started another probe"))
        .is_none());
    assert!(observer.job.is_none());
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(observer
        .poll_with(now + SAMPLE_INTERVAL - Duration::from_nanos(1), || {
            panic!("cadence ignored")
        })
        .is_none());
    assert!(observer.job.is_none());
}

struct Release(crossbeam_channel::Sender<()>);

impl Drop for Release {
    fn drop(&mut self) {
        let _ = self.0.try_send(());
    }
}

#[test]
fn stalled_probe_is_single_flight_and_does_not_block_observer_shutdown() {
    let now = Instant::now();
    let (entered_tx, entered_rx) = bounded(1);
    let (release_tx, release_rx) = bounded(1);
    let _release = Release(release_tx);
    let mut observer = armed(now);
    observer.poll_with(now, move || {
        entered_tx.send(()).unwrap();
        release_rx.recv().unwrap();
        Ok(observation(false, true))
    });
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let original_thread = observer.job.as_ref().unwrap().worker.thread().id();
    let (code, _) = warning(
        observer
            .poll_with(now + STALL_AFTER, || panic!("overlapping probe"))
            .unwrap(),
    );
    assert_eq!(code, "SBH-RAM-SCRATCH-INCOMPLETE");
    assert!(observer
        .poll_with(now + SAMPLE_INTERVAL, || panic!("replacement for blocked probe"))
        .is_none());
    assert_eq!(observer.job.as_ref().unwrap().worker.thread().id(), original_thread);
    let (done_tx, done_rx) = bounded(1);
    let stopper = thread::spawn(move || {
        observer.on_event(&ActivityEvent::Shutdown, now);
        assert!(done_tx.send(observer).is_ok());
    });
    let mut stopped = done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    stopper.join().unwrap();
    assert!(!stopped.enabled);
    assert!(stopped.job.is_none());
    stopped.on_event(
        &ActivityEvent::DaemonStarted {
            version: "duplicate".into(),
            config_hash: "fixture".into(),
        },
        now,
    );
    assert!(!stopped.enabled, "a stopped observer must not replace its detached worker");
}

#[test]
fn logger_consumer_arms_the_observer_and_shutdown_keeps_its_queue_boundary() {
    use super::super::{Control, Message};
    let control = Control::new();
    let (tx, rx) = bounded(1);
    tx.send(Message {
        event: ActivityEvent::DaemonStarted {
            version: "test".into(),
            config_hash: "fixture".into(),
        },
        mirror: false,
    })
    .unwrap();
    assert!(matches!(
        control.receive(&rx, Duration::ZERO).unwrap().event,
        ActivityEvent::DaemonStarted { .. }
    ));
    assert_eq!(control.ram_scratch.lock().enabled, cfg!(target_os = "linux"));
    control.request_shutdown();
    assert!(matches!(
        control.receive(&rx, Duration::ZERO).unwrap().event,
        ActivityEvent::Shutdown
    ));
    assert!(!control.ram_scratch.lock().enabled);
}
