//! Off-thread Linux watch rebuilds with a nonblocking, fail-closed handoff.
//!
//! The live backend keeps draining while discovery and registration run. One
//! process-wide admission slot bounds abandoned workers even across repeated
//! event-source replacements. A kernel-blocked operation cannot be interrupted,
//! but it cannot block the scanner or cause replacement workers to accumulate.
//! The slot is released only when the worker actually exits, not on cancellation.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Instant;

use super::inotify_backend::{INSTALL_TIME_BUDGET, LinuxInotifyBackend};
use super::{
    EventBackendKind, EventInvalidation, EventRateTracker, EventSourceBackend,
    EventSourceCapability, EventSourceConfig, EventSourcePlan, ScannerEventSource,
};

fn global_gate() -> Arc<AtomicBool> {
    static GATE: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    Arc::clone(GATE.get_or_init(|| Arc::new(AtomicBool::new(false))))
}

struct Permit(Arc<AtomicBool>);

impl Permit {
    fn acquire(gate: Arc<AtomicBool>) -> io::Result<Self> {
        gate.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| io::Error::new(
                io::ErrorKind::WouldBlock,
                "a recursive inotify rebuild is still running",
            ))?;
        Ok(Self(gate))
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[derive(Debug)]
struct Prepared {
    plan: EventSourcePlan,
    backend: EventSourceBackend,
}

#[derive(Debug)]
pub(super) struct Rebuild {
    completed: Receiver<io::Result<Prepared>>,
    retired: SyncSender<EventSourceBackend>,
    cancelled: Arc<AtomicBool>,
}

impl Rebuild {
    fn start(config: EventSourceConfig, rates: EventRateTracker, now: Instant) -> io::Result<Self> {
        Self::spawn(global_gate(), move |cancelled| build(&config, &rates, now, cancelled))
    }

    fn spawn(
        gate: Arc<AtomicBool>,
        builder: impl FnOnce(&AtomicBool) -> io::Result<Prepared> + Send + 'static,
    ) -> io::Result<Self> {
        let permit = Permit::acquire(gate)?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let (completed_tx, completed) = mpsc::sync_channel(1);
        let (retired, retired_rx) = mpsc::sync_channel::<EventSourceBackend>(1);
        // No join on the scanner's path, including error and shutdown paths.
        // The worker owns its admission permit; a panic releases it too.
        let _worker = thread::Builder::new()
            .name("sbh-watch-rebuild".to_string())
            .spawn(move || {
                let _permit = permit;
                let result = builder(&worker_cancelled);
                let successful = result.is_ok();
                if completed_tx.try_send(result).is_ok() && successful {
                    // After handoff, retire the old instance here, not in the
                    // scanner's event drain. Dropping the consumer wakes this
                    // receive without a shutdown join or an allocated backlog.
                    drop(retired_rx.recv());
                }
            })?;
        Ok(Self { completed, retired, cancelled })
    }

    fn poll(&self) -> Option<io::Result<Prepared>> {
        match self.completed.try_recv() {
            Ok(result) => Some(result),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(Err(io::Error::other(
                "recursive inotify rebuild worker exited without a result",
            ))),
        }
    }

    fn retire(self, backend: EventSourceBackend) {
        // Exactly one handoff fits the one-element channel. If the worker
        // itself has died, dropping its disconnected payload still releases
        // the old instance instead of leaking descriptors.
        let _ = self.retired.try_send(backend);
    }
}

impl Drop for Rebuild {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

fn build(
    config: &EventSourceConfig,
    rates: &EventRateTracker,
    now: Instant,
    cancelled: &AtomicBool,
) -> io::Result<Prepared> {
    let started = Instant::now();
    let check = || {
        if cancelled.load(Ordering::Acquire) {
            Err(io::Error::new(io::ErrorKind::Interrupted, "recursive inotify rebuild cancelled"))
        } else if started.elapsed() >= INSTALL_TIME_BUDGET {
            Err(io::Error::new(io::ErrorKind::TimedOut, "recursive inotify rebuild deadline exceeded"))
        } else {
            Ok(())
        }
    };
    check()?;
    // Discovery already has entry, path-memory and elapsed-time budgets.
    // It and any filesystem-blocked calls now run away from the live drain.
    let plan = EventSourcePlan::with_rates(config, rates, now);
    check()?;
    let backend = if plan.backend == EventBackendKind::RecursiveInotify {
        EventSourceBackend::RecursiveInotify(LinuxInotifyBackend::start_with_check(
            &plan.watched_dirs,
            config.watch_budget,
            check,
        )?)
    } else {
        EventSourceBackend::ReconciliationOnly
    };
    check()?;
    Ok(Prepared { plan, backend })
}

/// Poll one completion or admit one rebuild. Never wait for discovery, watch
/// registration, worker exit, or the old backend's ordinary retirement.
pub(super) fn poll_or_start(source: &mut ScannerEventSource, now: Instant) -> EventInvalidation {
    if let Some(task) = source.rebuild.take() {
        let Some(result) = task.poll() else {
            source.rebuild = Some(task);
            return EventInvalidation::empty();
        };
        // Retry/audit cadence begins at completion, not at a possibly distant
        // start time. A slow failed build cannot immediately restart itself.
        source.planned_at = now;
        return match result {
            Ok(Prepared { plan, backend }) => {
                let old = std::mem::replace(&mut source.backend, backend);
                source.rates.retain_watched(&plan.watched_dirs);
                source.capability = EventSourceCapability::from_plan(&plan);
                task.retire(old);
                let mut invalidation = EventInvalidation::empty();
                // The old queue may still contain events and the new watches
                // were installed at different times. A ready plan alone is
                // never evidence that a checkpoint remained fresh throughout.
                invalidation.mark_all_roots(
                    source.config.root_paths(),
                    "recursive inotify watch coverage rebuilt",
                    true,
                );
                invalidation
            }
            Err(error) => failed(source, &error),
        };
    }

    source.planned_at = now;
    source.replans = source.replans.saturating_add(1);
    match Rebuild::start(source.config.clone(), source.rates.clone(), now) {
        Ok(task) => {
            source.rebuild = Some(task);
            // Keep actual old coverage and counters. A running worker has
            // not yet installed usable replacement coverage for the caller.
            source.capability.reason =
                "recursive inotify rebuild running; previous backend retained".to_string();
            EventInvalidation::empty()
        }
        Err(error) => failed(source, &error),
    }
}

fn failed(source: &mut ScannerEventSource, error: &io::Error) -> EventInvalidation {
    // Do not throw away the remaining live watches on permission, resource,
    // deadline, worker-panic, or admission failures. Reconciliation remains
    // conservative and the normal timed repair policy retries later.
    if let EventSourceBackend::RecursiveInotify(backend) = &mut source.backend {
        backend.require_repair();
        source.capability.watched_dirs = backend.watched_dirs().count();
    } else {
        source.capability.watched_dirs = 0;
    }
    source.capability.complete = false;
    source.capability.frontier_dirs = 0;
    source.capability.dirty_roots = source.config.root_paths().to_vec();
    source.capability.reason = format!("recursive inotify replan failed: {error}");
    let mut invalidation = EventInvalidation::empty();
    invalidation.mark_all_roots(source.config.root_paths(), source.capability.reason.clone(), true);
    invalidation
}

#[cfg(test)]
const TEST_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

// Only tests using the real process-wide admission gate serialize with each
// other. Protocol tests inject independent gates and still run concurrently.
#[cfg(test)]
pub(super) fn test_serial() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let guard = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let deadline = Instant::now() + TEST_WAIT;
    let gate = global_gate();
    while gate.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline, "previous rebuild did not release its admission slot");
        thread::sleep(std::time::Duration::from_millis(1));
    }
    guard
}

#[cfg(test)]
pub(super) fn finish_rebuild(source: &mut ScannerEventSource, now: Instant) -> EventInvalidation {
    let deadline = Instant::now() + TEST_WAIT;
    let mut invalidation = EventInvalidation::empty();
    assert!(source.rebuild.is_some(), "a real rebuild must have been admitted");
    while source.rebuild.is_some() {
        assert!(Instant::now() < deadline, "rebuild did not complete");
        invalidation.merge(source.drain_at(now));
        thread::sleep(std::time::Duration::from_millis(1));
    }
    invalidation
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;
    use crate::core::config::ScannerConfig;
    use crate::scanner::events::WATCH_REPAIR_INTERVAL;

    fn gate() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    fn wait_free(gate: &AtomicBool) {
        let deadline = Instant::now() + TEST_WAIT;
        while gate.load(Ordering::Acquire) {
            assert!(Instant::now() < deadline, "worker leaked its admission permit");
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn ready(task: &Rebuild) -> io::Result<Prepared> {
        let deadline = Instant::now() + TEST_WAIT;
        loop {
            if let Some(result) = task.poll() {
                return result;
            }
            assert!(Instant::now() < deadline, "worker produced no result");
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn empty_prepared() -> Prepared {
        Prepared {
            plan: EventSourcePlan::reconciliation_only(&[], "test"),
            backend: EventSourceBackend::ReconciliationOnly,
        }
    }

    fn fixture() -> (tempfile::TempDir, ScannerEventSource, PathBuf, Instant) {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap().join("root");
        fs::create_dir_all(root.join("project")).unwrap();
        let config = EventSourceConfig::from_scanner_config(std::slice::from_ref(&root), &ScannerConfig {
            event_watch_budget: 16,
            ..ScannerConfig::default()
        });
        let now = Instant::now();
        let mut source = ScannerEventSource::start_at(config, now);
        assert_eq!(source.capability().selected_backend, EventBackendKind::RecursiveInotify);
        assert!(source.capability().complete);
        source.drain_at(now);
        (temp, source, root, now)
    }

    #[test]
    fn pending_poll_is_nonblocking_and_only_one_worker_is_admitted() {
        let gate = gate();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let task = Rebuild::spawn(Arc::clone(&gate), move |_| {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(TEST_WAIT).unwrap();
            Ok(empty_prepared())
        }).unwrap();
        entered_rx.recv_timeout(TEST_WAIT).unwrap();
        assert!(task.poll().is_none());
        assert!(task.poll().is_none());
        let error = Rebuild::spawn(Arc::clone(&gate), |_| panic!("second builder ran")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        release_tx.send(()).unwrap();
        assert!(ready(&task).is_ok());
        assert!(gate.load(Ordering::Acquire), "ready is not yet retired");
        task.retire(EventSourceBackend::ReconciliationOnly);
        wait_free(&gate);
    }

    #[test]
    fn dropping_a_consumer_cancels_but_does_not_release_a_running_workers_slot() {
        let gate = gate();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let (cancel_tx, cancel_rx) = mpsc::sync_channel(1);
        let task = Rebuild::spawn(Arc::clone(&gate), move |cancelled| {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(TEST_WAIT).unwrap();
            cancel_tx.send(cancelled.load(Ordering::Acquire)).unwrap();
            Ok(empty_prepared())
        }).unwrap();
        entered_rx.recv_timeout(TEST_WAIT).unwrap();
        drop(task);
        assert!(gate.load(Ordering::Acquire));
        assert_eq!(Rebuild::spawn(Arc::clone(&gate), |_| Ok(empty_prepared())).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        release_tx.send(()).unwrap();
        assert!(cancel_rx.recv_timeout(TEST_WAIT).unwrap());
        wait_free(&gate);
        let replacement = Rebuild::spawn(Arc::clone(&gate), |_| Ok(empty_prepared())).unwrap();
        assert!(ready(&replacement).is_ok());
        replacement.retire(EventSourceBackend::ReconciliationOnly);
        wait_free(&gate);
    }

    #[test]
    fn a_panicked_worker_becomes_a_retryable_error_and_releases_admission() {
        let gate = gate();
        let task = Rebuild::spawn(Arc::clone(&gate), |_| panic!("injected builder panic")).unwrap();
        let error = ready(&task).unwrap_err();
        assert!(error.to_string().contains("without a result"));
        drop(task);
        wait_free(&gate);
    }

    #[test]
    fn cancellation_precedes_discovery_and_kernel_installation() {
        let config = EventSourceConfig::from_scanner_config(
            &[PathBuf::from("/absent-watch-root")], &ScannerConfig::default(),
        );
        let error = build(&config, &EventRateTracker::default(), Instant::now(), &AtomicBool::new(true)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    }

    #[test]
    fn old_events_flow_during_rebuild_and_new_coverage_is_published_once() {
        let (_temp, mut source, root, now) = fixture();
        let gate = gate();
        let config = source.config.clone();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        source.rebuild = Some(Rebuild::spawn(Arc::clone(&gate), move |cancelled| {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(TEST_WAIT).unwrap();
            build(&config, &EventRateTracker::default(), now, cancelled)
        }).unwrap());
        source.replans = 1;
        entered_rx.recv_timeout(TEST_WAIT).unwrap();
        let changed = root.join("project/object.o");
        fs::write(&changed, b"still watched").unwrap();
        let live = source.drain_at(now);
        assert!(live.dirty_paths().contains(&changed));
        assert!(!live.requires_index_generation_bump());
        assert!(source.rebuild.is_some());
        assert!(source.capability().complete);
        assert_eq!(source.capability().watched_dirs, 2);
        // This subtree is discovered by the replacement while the old root
        // watch still observes its creation. Handoff must cover both queues.
        fs::create_dir_all(root.join("project/new/deep")).unwrap();
        release_tx.send(()).unwrap();
        let handoff = finish_rebuild(&mut source, now);
        assert!(handoff.requires_index_generation_bump());
        assert!(handoff.dirty_roots().contains(&root));
        assert_eq!(source.stats().replans, 1);
        assert!(source.capability().complete);
        assert_eq!(source.capability().watched_dirs, 4);
        let new_file = root.join("project/new/deep/new.o");
        fs::write(&new_file, b"replacement watched").unwrap();
        let next = source.drain_at(now);
        assert!(next.dirty_paths().contains(&new_file));
        assert!(!next.requires_index_generation_bump());
        let quiet = source.drain_at(now);
        assert!(!quiet.requires_reconciliation());
        wait_free(&gate);
    }

    #[test]
    fn failed_rebuild_preserves_live_watches_and_waits_before_retry() {
        let (_temp, mut source, root, now) = fixture();
        let gate = gate();
        source.rebuild = Some(Rebuild::spawn(Arc::clone(&gate), |_| {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "injected installation failure"))
        }).unwrap());
        source.replans = 1;
        let completed_at = now + Duration::from_secs(7);
        let failure = finish_rebuild(&mut source, completed_at);
        assert!(failure.requires_index_generation_bump());
        assert!(failure.dirty_roots().contains(&root));
        assert_eq!(source.capability().selected_backend, EventBackendKind::RecursiveInotify);
        assert_eq!(source.capability().watched_dirs, 2);
        assert!(!source.capability().complete);
        assert!(source.capability().reason.contains("injected installation failure"));
        assert!(!source.should_replan(completed_at + WATCH_REPAIR_INTERVAL - Duration::from_nanos(1)));
        assert!(source.should_replan(completed_at + WATCH_REPAIR_INTERVAL));
        let changed = root.join("project/after-failure.o");
        fs::write(&changed, b"old backend survives").unwrap();
        assert!(source.drain_at(completed_at).dirty_paths().contains(&changed));
        assert_eq!(source.stats().replans, 1);
        wait_free(&gate);
    }

    #[test]
    fn discarded_source_cannot_apply_its_late_result_to_a_different_config() {
        let (_temp, mut source, _root, now) = fixture();
        let gate = gate();
        let config = source.config.clone();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        source.rebuild = Some(Rebuild::spawn(Arc::clone(&gate), move |cancelled| {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(TEST_WAIT).unwrap();
            build(&config, &EventRateTracker::default(), now, cancelled)
        }).unwrap());
        entered_rx.recv_timeout(TEST_WAIT).unwrap();
        drop(source);
        let (_other_temp, mut replacement, other_root, other_now) = fixture();
        release_tx.send(()).unwrap();
        wait_free(&gate);
        assert_eq!(replacement.config.root_paths(), &[other_root.clone()]);
        assert_eq!(replacement.stats().replans, 0);
        assert!(replacement.rebuild.is_none());
        let changed = other_root.join("project/reconfigured.o");
        fs::write(&changed, b"new scope").unwrap();
        assert!(replacement.drain_at(other_now).dirty_paths().contains(&changed));
    }
}
