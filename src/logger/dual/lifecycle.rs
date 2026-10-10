//! Nonblocking logger control and an explicit producer/consumer shutdown boundary.
//!
//! Control requests do not occupy the bounded audit queue. Each admitted event
//! carries the mirror mode observed by its producer, so coalescing wakeups does
//! not retroactively mirror earlier events or lose a short on/off interval.
//! Shutdown closes admission, then waits for already-admitted producers and
//! their queued events before asking the writer to perform its final flush.
//!
//! The public join handle supervises the I/O worker. It waits at most five
//! seconds after the first shutdown request (or observed producer disconnect)
//! before detaching an unresponsive writer and reporting `TimedOut`. This covers
//! initialization, queued writes and final flush attempts, not merely receiving
//! the stop signal. The supervisor never performs logging or backend I/O, and
//! sleeps on its own notification channel while the logger is running normally.
//!
//! Timeout does not cancel a kernel operation or prove durability. A detached
//! writer can finish later; no replacement writer is started automatically.
//! Joining the supervisor successfully does not imply `WriterExited`: callers
//! must inspect `shutdown_status`. Scheduling and OS thread teardown can delay
//! supervision, so this is not a hard real-time bound for the whole daemon.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, bounded};

use super::ActivityEvent;

const CLOSED: usize = 1usize << (usize::BITS - 1);
const ACTIVE: u8 = 0;
const EXITED: u8 = 1;
const TIMED_OUT: u8 = 2;
const PANICKED: u8 = 3;
const SHUTDOWN_WAIT: Duration = Duration::from_secs(5);
const FINISH_POLL: Duration = Duration::from_millis(1);

/// Logger lifecycle state, separate from backend write success or durability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoggerShutdownStatus {
    /// Admission is open; the writer may be working or waiting for events.
    Running,
    /// New events are refused; admitted work and final flushing are pending.
    StopRequested,
    /// The writer returned after its final flush attempts. Writes can still
    /// have failed: this is not a claim that every event reached stable storage.
    WriterExited,
    /// Shutdown supervision ended without joining the writer. Pending events
    /// and final flushes are not confirmed; a blocked writer may still exist.
    TimedOut,
    /// The writer unwound. Its join handle also propagates the panic.
    WriterPanicked,
}

#[derive(Debug)]
pub(super) struct Message {
    pub(super) event: ActivityEvent,
    pub(super) mirror: bool,
}

pub(super) struct Control {
    // The high bit closes admission; low bits count producers between
    // admission and completion of their nonblocking queue attempt.
    admission: AtomicUsize,
    mirror: AtomicBool,
    wake_tx: Sender<()>,
    wake_rx: Receiver<()>,
    // Separate wakes: supervision must never consume the writer's control
    // notification, and mirror changes must not wake an idle supervisor.
    supervisor_tx: Sender<()>,
    supervisor_rx: Receiver<()>,
    born: Instant,
    // Elapsed nanoseconds + 1; zero means shutdown has not begun. An atomic
    // timestamp avoids a mutex/OnceLock initializer on the control caller.
    stop_started: AtomicU64,
    result: AtomicU8,
}

impl Control {
    pub(super) fn new() -> Self {
        let (wake_tx, wake_rx) = bounded(1);
        let (supervisor_tx, supervisor_rx) = bounded(1);
        Self {
            admission: AtomicUsize::new(0),
            mirror: AtomicBool::new(false),
            wake_tx,
            wake_rx,
            supervisor_tx,
            supervisor_rx,
            born: Instant::now(),
            stop_started: AtomicU64::new(0),
            result: AtomicU8::new(ACTIVE),
        }
    }

    pub(super) fn admit(&self) -> Option<Admission<'_>> {
        self.admission
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                if current >= CLOSED - 1 {
                    None
                } else {
                    Some(current + 1)
                }
            })
            .ok()
            .map(|_| Admission(self))
    }

    fn wake(&self) {
        // A single pending wake is enough: the authoritative control state
        // lives in atomics, not in a lossy or unbounded command backlog.
        let _ = self.wake_tx.try_send(());
    }

    fn notify_supervisor(&self) {
        let _ = self.supervisor_tx.try_send(());
    }

    pub(super) fn mirror(&self) -> bool {
        self.mirror.load(Ordering::Acquire)
    }

    pub(super) fn set_mirror(&self, on: bool) {
        let Some(_admission) = self.admit() else {
            return;
        };
        if self.mirror.swap(on, Ordering::AcqRel) != on {
            self.wake();
        }
    }

    fn close_admission(&self) {
        let started = u64::try_from(self.born.elapsed().as_nanos())
            .unwrap_or(u64::MAX - 1)
            .saturating_add(1);
        // Repeated requests never extend the first request's time budget.
        let _ = self.stop_started.compare_exchange(0, started, Ordering::AcqRel, Ordering::Acquire);
        self.admission.fetch_or(CLOSED, Ordering::AcqRel);
    }

    pub(super) fn request_shutdown(&self) {
        self.close_admission();
        self.wake();
        self.notify_supervisor();
    }

    fn shutdown_elapsed_at(&self, now: Instant) -> Option<Duration> {
        let started = self.stop_started.load(Ordering::Acquire).checked_sub(1)?;
        Some(
            now.saturating_duration_since(self.born)
                .saturating_sub(Duration::from_nanos(started)),
        )
    }

    pub(super) fn status(&self) -> LoggerShutdownStatus {
        match self.result.load(Ordering::Acquire) {
            EXITED => LoggerShutdownStatus::WriterExited,
            TIMED_OUT => LoggerShutdownStatus::TimedOut,
            PANICKED => LoggerShutdownStatus::WriterPanicked,
            _ if self.admission.load(Ordering::Acquire) & CLOSED != 0 => {
                LoggerShutdownStatus::StopRequested
            }
            _ => LoggerShutdownStatus::Running,
        }
    }

    fn finish(&self, panicked: bool) {
        // Arm supervision if the worker returned without a stop request too.
        // Final OS thread teardown is still outside our cooperative control.
        self.close_admission();
        let result = if panicked { PANICKED } else { EXITED };
        // A late exit must not overwrite an earlier supervision timeout.
        let _ = self.result.compare_exchange(ACTIVE, result, Ordering::AcqRel, Ordering::Acquire);
        self.notify_supervisor();
    }

    pub(super) fn receive(
        &self,
        events: &Receiver<Message>,
        timeout: Duration,
    ) -> Result<Message, RecvTimeoutError> {
        // Reading CLOSED alone is insufficient: a producer admitted before
        // closure may be suspended just before enqueueing its final event.
        // The release of its admission follows the queue attempt. Acquire
        // that completion before observing an empty queue as end-of-stream.
        if self.admission.load(Ordering::Acquire) == CLOSED && events.is_empty() {
            return Ok(Message {
                event: ActivityEvent::Shutdown,
                mirror: self.mirror(),
            });
        }
        let result = crossbeam_channel::select! {
            recv(events) -> message => message.map_err(|_| RecvTimeoutError::Disconnected),
            recv(self.wake_rx) -> _ => {
                let mirror = self.mirror();
                Ok(Message { event: ActivityEvent::MirrorJsonl(mirror), mirror })
            },
            default(timeout) => Err(RecvTimeoutError::Timeout),
        };
        if let Ok(message) = &result
            && events.is_empty()
            && message.mirror != self.mirror()
        {
            // An old stamped event can follow the latest coalesced control
            // wake. Restore the current idle mode after that last queued event,
            // even if no further producer event arrives. Do not toggle the
            // writer between every item in a still-pending historical batch.
            self.wake();
        }
        if matches!(&result, Err(RecvTimeoutError::Disconnected)) {
            // The logger's ordinary all-producers-dropped exit also flushes.
            // Start supervision before returning to that finalization path.
            self.request_shutdown();
        }
        result
    }
}

pub(super) struct Admission<'a>(&'a Control);

impl Drop for Admission<'_> {
    fn drop(&mut self) {
        if self.0.admission.fetch_sub(1, Ordering::Release) & CLOSED != 0 {
            self.0.wake();
        }
    }
}

struct WriterExit(Arc<Control>);

impl Drop for WriterExit {
    fn drop(&mut self) {
        self.0.finish(thread::panicking());
    }
}

/// The returned handle belongs to supervision, not the potentially blocked
/// I/O worker. Existing daemon shutdown callers therefore gain a bounded
/// logging wait without a separate, easily forgotten join-timeout API.
pub(super) fn spawn_worker(
    control: Arc<Control>,
    worker: impl FnOnce() + Send + 'static,
) -> io::Result<JoinHandle<()>> {
    spawn_supervised(control, SHUTDOWN_WAIT, worker)
}

fn spawn_supervised(
    control: Arc<Control>,
    shutdown_wait: Duration,
    worker: impl FnOnce() + Send + 'static,
) -> io::Result<JoinHandle<()>> {
    let writer_control = Arc::clone(&control);
    let writer = thread::Builder::new()
        .name("sbh-logger".to_string())
        .spawn(move || {
            let _exit = WriterExit(writer_control);
            worker();
        })?;
    let supervisor_control = Arc::clone(&control);
    let supervisor = thread::Builder::new()
        .name("sbh-log-supervisor".to_string())
        .spawn(move || supervise(&supervisor_control, writer, shutdown_wait));
    if supervisor.is_err() {
        // The failed spawn drops its closure and detaches the worker handle.
        // Close its admission too; never wait on backend I/O to report a
        // thread-creation error. The responsive worker drains and exits.
        control.request_shutdown();
    }
    supervisor
}

fn supervise(control: &Control, writer: JoinHandle<()>, shutdown_wait: Duration) {
    loop {
        if writer.is_finished() {
            if let Err(panic) = writer.join() {
                // Preserve the original join API's panic propagation. Timeout
                // is NOT a panic: abort-profile binaries must not abort merely
                // because log I/O missed its shutdown allowance.
                std::panic::resume_unwind(panic);
            }
            return;
        }
        if let Some(elapsed) = control.shutdown_elapsed_at(Instant::now()) {
            let remaining = shutdown_wait.saturating_sub(elapsed);
            if remaining.is_zero() {
                // Prefer an already-finished writer at the deadline boundary.
                if writer.is_finished() {
                    continue;
                }
                control.result.store(TIMED_OUT, Ordering::Release);
                // Dropping JoinHandle detaches; it does not cancel the writer.
                // Do not log here: stderr or a backend could itself be blocked,
                // defeating the reason for this I/O-free supervisor.
                return;
            }
            // WriterExit runs immediately before the thread completes. Once
            // it notifies us, poll only that final join-readiness interval;
            // otherwise notification or the shutdown deadline wakes us.
            let wait = if control.result.load(Ordering::Acquire) == ACTIVE {
                remaining
            } else {
                remaining.min(FINISH_POLL)
            };
            let _ = control.supervisor_rx.recv_timeout(wait);
        } else {
            // No periodic polling, sleeps or invented writer heartbeats while
            // the daemon is running. State changes cannot be lost: each leaves
            // a coalesced wake even if it races this blocking receive.
            let _ = control.supervisor_rx.recv();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logger::dual::{ActivityLoggerHandle, diagnostics::DiagnosticGate};

    fn fixture(capacity: usize) -> (ActivityLoggerHandle, Receiver<Message>) {
        let (tx, rx) = bounded(capacity);
        (
            ActivityLoggerHandle {
                tx,
                dropped_events: Arc::new(AtomicU64::new(0)),
                diagnostics: Arc::new(DiagnosticGate::new(Instant::now())),
                last_beat_ms: Arc::new(AtomicU64::new(0)),
                control: Arc::new(Control::new()),
            },
            rx,
        )
    }

    fn event(id: usize) -> ActivityEvent {
        // Audit/control-adjacent records do not pass through diagnostic coalescing.
        ActivityEvent::ConfigReloaded { details: id.to_string() }
    }

    fn next_data(control: &Control, rx: &Receiver<Message>) -> Message {
        for _ in 0..4 {
            let message = control.receive(rx, Duration::ZERO).unwrap();
            if !matches!(message.event, ActivityEvent::MirrorJsonl(_)) {
                return message;
            }
        }
        panic!("coalesced control wakes cannot starve the data queue");
    }

    #[test]
    fn a_full_data_queue_cannot_block_mirror_or_shutdown_requests() {
        let (handle, rx) = fixture(1);
        handle.send(event(1));
        let other = handle.clone();
        let (done_tx, done_rx) = bounded(1);
        let producer = thread::spawn(move || {
            for n in 0..10_000 {
                other.mirror_jsonl(n % 2 == 0);
            }
            other.shutdown();
            other.shutdown();
            done_tx.send(()).unwrap();
        });
        // No consumer runs until the producer has finished these controls.
        // Drop rx before joining on failure so a regressed blocking send can exit.
        let done = done_rx.recv_timeout(Duration::from_secs(5));
        if done.is_err() {
            drop(rx);
            producer.join().unwrap();
            panic!("logger controls blocked behind a full audit queue");
        }
        producer.join().unwrap();
        assert_eq!(rx.len(), 1);
        assert_eq!(handle.dropped_events(), 0);
        assert_eq!(handle.shutdown_status(), LoggerShutdownStatus::StopRequested);
        assert!(matches!(next_data(&handle.control, &rx).event, ActivityEvent::ConfigReloaded { .. }));
        assert!(matches!(next_data(&handle.control, &rx).event, ActivityEvent::Shutdown));
    }

    #[test]
    fn short_mirror_intervals_remain_attached_to_their_queued_events() {
        let (handle, rx) = fixture(3);
        handle.send(event(0));
        handle.mirror_jsonl(true);
        handle.send(event(1));
        handle.mirror_jsonl(false);
        handle.send(event(2));
        handle.shutdown();
        let messages: Vec<_> = (0..3).map(|_| next_data(&handle.control, &rx)).collect();
        assert_eq!(messages.iter().map(|m| m.mirror).collect::<Vec<_>>(), vec![false, true, false]);
        for (id, message) in messages.into_iter().enumerate() {
            let ActivityEvent::ConfigReloaded { details } = message.event else { panic!("lost audit event") };
            assert_eq!(details, id.to_string());
        }
        assert!(matches!(next_data(&handle.control, &rx).event, ActivityEvent::Shutdown));
    }

    #[test]
    fn shutdown_waits_for_a_producer_admitted_before_queue_publication() {
        let (handle, rx) = fixture(1);
        let admission = handle.control.admit().unwrap();
        handle.shutdown();
        assert!(handle.control.admit().is_none());
        // Consume the shutdown wake; the in-flight producer still owns work.
        assert!(matches!(handle.control.receive(&rx, Duration::ZERO).unwrap().event, ActivityEvent::MirrorJsonl(_)));
        assert!(matches!(handle.control.receive(&rx, Duration::ZERO), Err(RecvTimeoutError::Timeout)));
        handle.tx.try_send(Message { event: event(7), mirror: false }).unwrap();
        drop(admission);
        let ActivityEvent::ConfigReloaded { details } = next_data(&handle.control, &rx).event else {
            panic!("shutdown overtook an admitted audit event");
        };
        assert_eq!(details, "7");
        assert!(matches!(next_data(&handle.control, &rx).event, ActivityEvent::Shutdown));
    }

    #[test]
    fn direct_control_events_use_the_same_reliable_out_of_band_path() {
        let (handle, rx) = fixture(1);
        handle.send(ActivityEvent::MirrorJsonl(true));
        handle.send(event(0));
        handle.send(ActivityEvent::Shutdown);
        handle.send(event(1));
        handle.send(ActivityEvent::MirrorJsonl(false));
        let message = next_data(&handle.control, &rx);
        assert!(message.mirror);
        assert_eq!(rx.len(), 0);
        assert!(handle.control.mirror(), "closed admission refuses later mode changes");
        assert_eq!(handle.dropped_events(), 0);
        assert!(matches!(next_data(&handle.control, &rx).event, ActivityEvent::Shutdown));
    }

    #[test]
    fn transport_loss_is_counted_but_controls_do_not_consume_data_capacity() {
        let (handle, rx) = fixture(1);
        for id in 0..4 { handle.send(event(id)); }
        assert_eq!(handle.dropped_events(), 3);
        handle.mirror_jsonl(true);
        handle.shutdown();
        assert_eq!(handle.dropped_events(), 3);
        assert_eq!(rx.len(), 1);
    }

    #[test]
    fn zero_capacity_data_channel_still_accepts_shutdown() {
        let (handle, rx) = fixture(0);
        handle.send(event(0));
        assert_eq!(handle.dropped_events(), 1);
        handle.shutdown();
        assert!(matches!(handle.control.receive(&rx, Duration::ZERO).unwrap().event, ActivityEvent::Shutdown));
    }

    #[test]
    fn concurrent_producers_are_drained_once_before_shutdown() {
        let (handle, rx) = fixture(128);
        let producers: Vec<_> = (0..8).map(|producer| {
            let handle = handle.clone();
            thread::spawn(move || {
                for n in 0..16 { handle.send(event(producer * 16 + n)); }
            })
        }).collect();
        for producer in producers { producer.join().unwrap(); }
        handle.shutdown();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..128 {
            let ActivityEvent::ConfigReloaded { details } = next_data(&handle.control, &rx).event else {
                panic!("shutdown ended before admitted producers were drained");
            };
            assert!(seen.insert(details));
        }
        assert_eq!(seen.len(), 128);
        assert_eq!(handle.dropped_events(), 0);
        assert!(matches!(next_data(&handle.control, &rx).event, ActivityEvent::Shutdown));
    }

    #[test]
    fn idle_control_changes_wake_the_consumer_without_an_audit_event() {
        let (handle, rx) = fixture(1);
        handle.mirror_jsonl(true);
        let message = handle.control.receive(&rx, Duration::ZERO).unwrap();
        assert!(matches!(message.event, ActivityEvent::MirrorJsonl(true)));
        assert!(message.mirror);
        assert!(rx.is_empty());
    }

    #[test]
    fn writer_exit_and_panic_are_distinct_from_a_shutdown_request() {
        let normal = Arc::new(Control::new());
        spawn_worker(Arc::clone(&normal), || {}).unwrap().join().unwrap();
        assert_eq!(normal.status(), LoggerShutdownStatus::WriterExited);
        normal.request_shutdown();
        assert_eq!(normal.status(), LoggerShutdownStatus::WriterExited);
        let failed = Arc::new(Control::new());
        assert!(spawn_worker(Arc::clone(&failed), || panic!("injected writer failure")).unwrap().join().is_err());
        assert_eq!(failed.status(), LoggerShutdownStatus::WriterPanicked);
        assert!(failed.admit().is_none());
    }

    #[test]
    fn shutdown_budget_starts_at_the_first_request_not_logger_creation() {
        let control = Control::new();
        assert_eq!(control.shutdown_elapsed_at(control.born + Duration::from_secs(3600)), None);
        control.request_shutdown();
        let first = control.stop_started.load(Ordering::Acquire);
        assert_ne!(first, 0);
        for _ in 0..1000 {
            control.request_shutdown();
        }
        assert_eq!(control.stop_started.load(Ordering::Acquire), first);
        let started = control.born + Duration::from_nanos(first - 1);
        assert_eq!(control.shutdown_elapsed_at(started), Some(Duration::ZERO));
        assert_eq!(control.shutdown_elapsed_at(started + SHUTDOWN_WAIT), Some(SHUTDOWN_WAIT));
        let just_before = started + SHUTDOWN_WAIT - Duration::from_nanos(1);
        assert_eq!(
            SHUTDOWN_WAIT.saturating_sub(control.shutdown_elapsed_at(just_before).unwrap()),
            Duration::from_nanos(1)
        );
        assert_eq!(control.shutdown_elapsed_at(control.born), Some(Duration::ZERO));
    }

    // Release an injected stuck operation even if its test assertion panics.
    struct Release(Sender<()>);

    impl Drop for Release {
        fn drop(&mut self) {
            let _ = self.0.try_send(());
        }
    }

    fn join_with_test_deadline(join: JoinHandle<()>) -> thread::Result<()> {
        let (done_tx, done_rx) = bounded(1);
        let waiter = thread::spawn(move || {
            let _ = done_tx.send(join.join());
        });
        let result = done_rx.recv_timeout(Duration::from_secs(5))
            .expect("lifecycle join is still waiting on the injected blocked writer");
        waiter.join().unwrap();
        result
    }

    #[test]
    fn a_blocked_writer_releases_supervision_without_claiming_queued_work_was_flushed() {
        let (handle, rx) = fixture(1);
        handle.send(event(17));
        let (ready_tx, ready_rx) = bounded(1);
        let (release_tx, release_rx) = bounded(1);
        let release = Release(release_tx);
        let processed = Arc::new(AtomicUsize::new(0));
        let worker_processed = Arc::clone(&processed);
        let worker_control = Arc::clone(&handle.control);
        let worker_rx = rx.clone();
        let supervisor = spawn_supervised(Arc::clone(&handle.control), Duration::ZERO, move || {
            ready_tx.send(()).unwrap();
            // Models a stuck initialization/write call. It deliberately does
            // not consult shutdown until the test lets the operation return.
            release_rx.recv().unwrap();
            let ActivityEvent::ConfigReloaded { details } = next_data(&worker_control, &worker_rx).event else {
                panic!("queued audit work was replaced by shutdown");
            };
            assert_eq!(details, "17");
            worker_processed.fetch_add(1, Ordering::Release);
            assert!(matches!(next_data(&worker_control, &worker_rx).event, ActivityEvent::Shutdown));
        }).unwrap();
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(handle.shutdown_status(), LoggerShutdownStatus::Running);
        handle.shutdown();
        join_with_test_deadline(supervisor).unwrap();
        assert_eq!(handle.shutdown_status(), LoggerShutdownStatus::TimedOut);
        assert_eq!(rx.len(), 1, "timeout did not consume or confirm the pending event");
        assert_eq!(processed.load(Ordering::Acquire), 0);
        handle.send(event(18));
        assert_eq!(rx.len(), 1, "admission stays closed after supervision ends");
        assert_eq!(handle.dropped_events(), 0);
        while handle.control.supervisor_rx.try_recv().is_ok() {}
        release.0.try_send(()).unwrap();
        // WriterExit publishes its result before this completion notification.
        handle.control.supervisor_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(processed.load(Ordering::Acquire), 1);
        assert_eq!(handle.shutdown_status(), LoggerShutdownStatus::TimedOut, "late completion cannot rewrite the timeout result");
        assert!(handle.control.admit().is_none());
    }

    #[test]
    fn producer_disconnection_starts_the_budget_before_a_blocked_final_flush() {
        let (handle, rx) = fixture(1);
        handle.send(event(23));
        let control = Arc::clone(&handle.control);
        let worker_control = Arc::clone(&control);
        let (at_flush_tx, at_flush_rx) = bounded(1);
        let (release_tx, release_rx) = bounded(1);
        let release = Release(release_tx);
        let flushed = Arc::new(AtomicBool::new(false));
        let worker_flushed = Arc::clone(&flushed);
        let supervisor = spawn_supervised(Arc::clone(&control), Duration::ZERO, move || {
            let mut seen = 0;
            loop {
                match worker_control.receive(&rx, Duration::from_secs(1)) {
                    Ok(Message { event: ActivityEvent::ConfigReloaded { details }, .. }) => {
                        assert_eq!(details, "23");
                        seen += 1;
                    }
                    Ok(Message { event: ActivityEvent::MirrorJsonl(_), .. }) => {}
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => break,
                    other => panic!("unexpected event before producer disconnect: {other:?}"),
                }
            }
            assert_eq!(seen, 1);
            at_flush_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            worker_flushed.store(true, Ordering::Release);
        }).unwrap();
        // No explicit shutdown call: all producers dropping is also a real
        // logger exit path and must arm the budget before final backend I/O.
        drop(handle);
        at_flush_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        join_with_test_deadline(supervisor).unwrap();
        assert_eq!(control.status(), LoggerShutdownStatus::TimedOut);
        assert!(!flushed.load(Ordering::Acquire));
        while control.supervisor_rx.try_recv().is_ok() {}
        release.0.try_send(()).unwrap();
        control.supervisor_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(flushed.load(Ordering::Acquire));
        assert_eq!(control.status(), LoggerShutdownStatus::TimedOut);
    }

    #[test]
    fn healthy_shutdown_confirms_queued_work_and_finalization_before_join_returns() {
        let (handle, rx) = fixture(2);
        handle.send(event(0));
        handle.send(event(1));
        handle.shutdown();
        let control = Arc::clone(&handle.control);
        let flushed = Arc::new(AtomicBool::new(false));
        let worker_flushed = Arc::clone(&flushed);
        let supervisor = spawn_worker(Arc::clone(&handle.control), move || {
            for expected in 0..2 {
                let ActivityEvent::ConfigReloaded { details } = next_data(&control, &rx).event else {
                    panic!("shutdown lost queued work");
                };
                assert_eq!(details, expected.to_string());
            }
            assert!(matches!(next_data(&control, &rx).event, ActivityEvent::Shutdown));
            worker_flushed.store(true, Ordering::Release);
        }).unwrap();
        join_with_test_deadline(supervisor).unwrap();
        assert!(flushed.load(Ordering::Acquire));
        assert_eq!(handle.shutdown_status(), LoggerShutdownStatus::WriterExited);
        assert_eq!(handle.dropped_events(), 0);
    }

    #[test]
    fn last_historical_event_rearms_the_latest_idle_mirror_setting() {
        let (handle, rx) = fixture(2);
        handle.mirror_jsonl(true);
        handle.send(event(1));
        handle.send(event(2));
        handle.mirror_jsonl(false);
        // Force the ordering where the coalesced off wake was already used
        // before the old, on-stamped batch reached the writer.
        handle.control.wake_rx.try_recv().unwrap();
        assert!(handle.control.receive(&rx, Duration::ZERO).unwrap().mirror);
        assert!(handle.control.wake_rx.is_empty(), "no repeated mode resets inside a batch");
        assert!(handle.control.receive(&rx, Duration::ZERO).unwrap().mirror);
        let idle = handle.control.receive(&rx, Duration::ZERO).unwrap();
        assert!(matches!(idle.event, ActivityEvent::MirrorJsonl(false)));
        assert!(!idle.mirror);
        assert!(rx.is_empty());
        assert!(matches!(handle.control.receive(&rx, Duration::ZERO), Err(RecvTimeoutError::Timeout)));
    }
}
