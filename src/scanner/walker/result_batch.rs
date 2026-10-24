//! Bounded producer-side result batching for the directory walker (bd-vf9z).
//!
//! The queue capacity is expressed in entries, not packets. Each worker owns
//! at most one additional batch; retries return ownership instead of cloning
//! entries. Callers must flush before waiting for work and on normal completion.
//! Cancellation and receiver disconnection may discard only undelivered work.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crossbeam_channel::{self as channel, Receiver, SendTimeoutError, Sender};

/// Maximum results transferred by one producer/collector channel operation.
pub(super) const BATCH_SIZE: usize = 64;
/// Cooperative latency limit, checked at work boundaries and on every push.
pub(super) const BATCH_DELAY: Duration = Duration::from_millis(5);

/// Construct a queue whose packets hold no more than `entry_capacity` entries.
/// Every sender created here enforces the same packet-size limit.
pub(super) fn bounded<T>(entry_capacity: usize) -> (BatchSender<T>, Receiver<Vec<T>>) {
    assert!(entry_capacity > 0, "result capacity must be nonzero");
    let batch_size = BATCH_SIZE.min(entry_capacity);
    let (sender, receiver) = channel::bounded(entry_capacity / batch_size);
    (
        BatchSender {
            sender,
            pending: Vec::with_capacity(batch_size),
            batch_size,
            oldest: None,
        },
        receiver,
    )
}

/// One worker's private buffer. Clone starts an EMPTY buffer, never another
/// copy of already observed results. The channel is the only shared state.
pub(super) struct BatchSender<T> {
    sender: Sender<Vec<T>>,
    pending: Vec<T>,
    batch_size: usize,
    oldest: Option<Instant>,
}

impl<T> Clone for BatchSender<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            pending: Vec::with_capacity(self.batch_size),
            batch_size: self.batch_size,
            oldest: None,
        }
    }
}

impl<T> BatchSender<T> {
    /// Admit one owned entry, flushing a full or aged batch. No Clone bound:
    /// backpressure never deep-copies paths or candidate metadata on a retry.
    pub(super) fn push(&mut self, entry: T, cancel: &AtomicBool, retry: Duration) -> bool {
        self.push_at(entry, cancel, retry, Instant::now())
    }

    /// Explicit clock seam for exact size/latency boundary tests.
    pub(super) fn push_at(
        &mut self,
        entry: T,
        cancel: &AtomicBool,
        retry: Duration,
        now: Instant,
    ) -> bool {
        if cancel.load(Ordering::Relaxed) {
            return false;
        }
        self.oldest.get_or_insert(now);
        self.pending.push(entry);
        if self.pending.len() == self.batch_size || self.due(now) {
            self.flush(cancel, retry)
        } else {
            true
        }
    }

    /// Publish a partial batch once its oldest entry reaches the delay budget.
    /// Empty buffers do not query the clock or send empty channel messages.
    pub(super) fn flush_due(&mut self, cancel: &AtomicBool, retry: Duration) -> bool {
        if self.oldest.is_some() && self.due(Instant::now()) {
            self.flush(cancel, retry)
        } else {
            !cancel.load(Ordering::Relaxed)
        }
    }

    fn due(&self, now: Instant) -> bool {
        self.oldest.is_some_and(|oldest| {
            now.checked_duration_since(oldest)
                .is_none_or(|age| age >= BATCH_DELAY)
        })
    }

    /// Publish all buffered entries. A timeout retries the SAME owned packet;
    /// it is not successful delivery and does not discard an ordinary result.
    pub(super) fn flush(&mut self, cancel: &AtomicBool, retry: Duration) -> bool {
        if cancel.load(Ordering::Relaxed) {
            return false;
        }
        if self.pending.is_empty() {
            return true;
        }
        let mut packet = std::mem::replace(&mut self.pending, Vec::with_capacity(self.batch_size));
        self.oldest = None;
        loop {
            if cancel.load(Ordering::Relaxed) {
                return false;
            }
            match self.sender.send_timeout(packet, retry) {
                Ok(()) => return true,
                Err(SendTimeoutError::Timeout(returned)) => packet = returned,
                Err(SendTimeoutError::Disconnected(_)) => {
                    cancel.store(true, Ordering::Relaxed);
                    return false;
                }
            }
        }
    }
}

/// Forward packets as bursts to the existing per-entry stream interface. The
/// caller splits its TOTAL queue budget between the packet and entry queues;
/// this relay must not silently double the walker's buffered-entry capacity.
/// Collect-all callers consume packet vectors directly and do not use a relay.
pub(super) fn relay<T>(
    packets: &Receiver<Vec<T>>,
    entries: &Sender<T>,
    cancel: &AtomicBool,
    retry: Duration,
) {
    loop {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        let packet = match packets.recv_timeout(retry) {
            Ok(packet) => packet,
            Err(channel::RecvTimeoutError::Timeout) => continue,
            Err(channel::RecvTimeoutError::Disconnected) => return,
        };
        for mut entry in packet {
            loop {
                if cancel.load(Ordering::Relaxed) {
                    return;
                }
                match entries.send_timeout(entry, retry) {
                    Ok(()) => break,
                    Err(SendTimeoutError::Timeout(returned)) => entry = returned,
                    Err(SendTimeoutError::Disconnected(_)) => {
                        cancel.store(true, Ordering::Relaxed);
                        return;
                    }
                }
            }
        }
    }
}
