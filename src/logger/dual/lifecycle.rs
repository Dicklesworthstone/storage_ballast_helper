//! Nonblocking logger control and an explicit producer/consumer shutdown boundary.
//!
//! Control requests do not occupy the bounded audit queue. Each admitted event
//! carries the mirror mode observed by its producer, so coalescing wakeups does
//! not retroactively mirror earlier events or lose a short on/off interval.
//! Shutdown closes admission, then waits for already-admitted producers and
//! their queued events before asking the writer to perform its final flush.

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
    born: Instant,
    // Elapsed nanoseconds + 1; zero means no explicit shutdown request.
    // An atomic timestamp avoids a mutex/OnceLock initializer on the caller.
    stop_started: AtomicU64,
    result: AtomicU8,
}

impl Control {
    pub(super) fn new() -> Self {
        let (wake_tx, wake_rx) = bounded(1);
        Self {
            admission: AtomicUsize::new(0),
            mirror: AtomicBool::new(false),
            wake_tx,
            wake_rx,
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

    pub(super) fn request_shutdown(&self) {
        let started = u64::try_from(self.born.elapsed().as_nanos())
            .unwrap_or(u64::MAX - 1)
            .saturating_add(1);
        // Repeated requests never extend the first request's time budget.
        let _ = self.stop_started.compare_exchange(0, started, Ordering::AcqRel, Ordering::Acquire);
        self.admission.fetch_or(CLOSED, Ordering::AcqRel);
        self.wake();
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
        self.admission.fetch_or(CLOSED, Ordering::AcqRel);
        let result = if panicked { PANICKED } else { EXITED };
        // A late exit must not overwrite an earlier supervision timeout.
        let _ = self.result.compare_exchange(ACTIVE, result, Ordering::AcqRel, Ordering::Acquire);
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
        crossbeam_channel::select! {
            recv(events) -> message => message.map_err(|_| RecvTimeoutError::Disconnected),
            recv(self.wake_rx) -> _ => Ok(Message {
                event: ActivityEvent::MirrorJsonl(self.mirror()),
                mirror: self.mirror(),
            }),
            default(timeout) => Err(RecvTimeoutError::Timeout),
        }
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

pub(super) fn spawn_worker(
    control: Arc<Control>,
    worker: impl FnOnce() + Send + 'static,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("sbh-logger".to_string())
        .spawn(move || {
            let _exit = WriterExit(control);
            worker();
        })
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
}
