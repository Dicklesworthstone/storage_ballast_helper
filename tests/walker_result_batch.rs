//! Exercise the production transport independently of filesystem timing.
//! Kept as an integration target so it can run without native mount fixtures.

#[path = "../src/scanner/walker/result_batch.rs"]
pub mod result_batch;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel as channel;
use result_batch::{BATCH_DELAY, BATCH_SIZE};

const RETRY: Duration = Duration::from_millis(5);
const DEADLINE: Duration = Duration::from_secs(5);

#[test]
fn queue_budget_counts_entries_not_packets() {
    let (_, receiver) = result_batch::bounded::<usize>(10_000);
    assert_eq!(receiver.capacity(), Some(10_000 / BATCH_SIZE));
    assert!(receiver.capacity().unwrap() * BATCH_SIZE <= 10_000);
    for capacity in [1, 2, BATCH_SIZE - 1, BATCH_SIZE, BATCH_SIZE + 1] {
        let (_, receiver) = result_batch::bounded::<usize>(capacity);
        assert_eq!(
            receiver.capacity(),
            Some(capacity / capacity.min(BATCH_SIZE))
        );
    }
}

#[test]
fn full_batches_and_final_partial_batch_preserve_order_exactly() {
    let cancel = AtomicBool::new(false);
    let (mut sender, receiver) = result_batch::bounded(256);
    let now = Instant::now();
    for value in 0..(BATCH_SIZE + 3) {
        assert!(sender.push_at(value, &cancel, RETRY, now));
    }
    assert!(sender.flush(&cancel, RETRY));
    drop(sender);
    let packets: Vec<_> = receiver.into_iter().collect();
    assert_eq!(
        packets.iter().map(Vec::len).collect::<Vec<_>>(),
        [BATCH_SIZE, 3]
    );
    assert_eq!(
        packets.into_iter().flatten().collect::<Vec<_>>(),
        (0..(BATCH_SIZE + 3)).collect::<Vec<_>>()
    );
}

#[test]
fn empty_flush_and_empty_clone_never_duplicate_or_publish_empty_packets() {
    let cancel = AtomicBool::new(false);
    let (mut first, receiver) = result_batch::bounded(128);
    assert!(first.flush(&cancel, RETRY));
    assert!(first.push(1, &cancel, RETRY));
    let mut second = first.clone();
    assert!(second.flush(&cancel, RETRY));
    assert_eq!(receiver.try_recv(), Err(channel::TryRecvError::Empty));
    assert!(first.flush(&cancel, RETRY));
    assert!(second.push(2, &cancel, RETRY));
    assert!(second.flush(&cancel, RETRY));
    drop(first);
    drop(second);
    assert_eq!(receiver.into_iter().flatten().collect::<Vec<_>>(), [1, 2]);
}

#[test]
fn an_aged_partial_batch_is_visible_without_waiting_for_sixty_four_entries() {
    let cancel = AtomicBool::new(false);
    let (mut sender, receiver) = result_batch::bounded(128);
    assert!(sender.push(7, &cancel, RETRY));
    thread::sleep(BATCH_DELAY * 2);
    assert!(sender.flush_due(&cancel, RETRY));
    assert_eq!(receiver.recv_timeout(DEADLINE).unwrap(), [7]);
    assert!(sender.flush_due(&cancel, RETRY));
    assert_eq!(receiver.try_recv(), Err(channel::TryRecvError::Empty));
}

#[test]
fn slow_consumer_does_not_drop_owned_nonclone_entries_on_retry() {
    struct Owned(usize);
    let cancel = Arc::new(AtomicBool::new(false));
    let (mut sender, receiver) = result_batch::bounded(8);
    let (done_tx, done_rx) = channel::bounded(1);
    let worker = {
        let cancel = Arc::clone(&cancel);
        thread::spawn(move || {
            let mut success = true;
            for value in 0..101 {
                success &= sender.push(Owned(value), &cancel, RETRY);
                if !success {
                    break;
                }
            }
            success &= sender.flush(&cancel, RETRY);
            done_tx.send(success).unwrap();
        })
    };
    assert_eq!(
        done_rx.recv_timeout(RETRY * 4),
        Err(channel::RecvTimeoutError::Timeout)
    );
    let mut seen = Vec::new();
    loop {
        match receiver.recv_timeout(DEADLINE) {
            Ok(packet) => seen.extend(packet.into_iter().map(|entry| entry.0)),
            Err(channel::RecvTimeoutError::Disconnected) => break,
            Err(channel::RecvTimeoutError::Timeout) => {
                cancel.store(true, Ordering::Relaxed);
                panic!("producer failed to resume after backpressure");
            }
        }
    }
    assert!(done_rx.recv_timeout(DEADLINE).unwrap());
    worker.join().unwrap();
    assert_eq!(seen, (0..101).collect::<Vec<_>>());
}

#[test]
fn cancellation_releases_a_producer_with_a_full_queue_and_no_consumer() {
    let cancel = Arc::new(AtomicBool::new(false));
    let (mut sender, receiver) = result_batch::bounded(1);
    assert!(sender.push(1, &cancel, RETRY));
    let (done_tx, done_rx) = channel::bounded(1);
    let worker = {
        let cancel = Arc::clone(&cancel);
        thread::spawn(move || {
            done_tx.send(sender.push(2, &cancel, RETRY)).unwrap();
        })
    };
    assert_eq!(
        done_rx.recv_timeout(RETRY * 4),
        Err(channel::RecvTimeoutError::Timeout)
    );
    cancel.store(true, Ordering::Relaxed);
    assert!(!done_rx.recv_timeout(DEADLINE).unwrap());
    worker.join().unwrap();
    assert_eq!(receiver.recv_timeout(DEADLINE).unwrap(), [1]);
    assert_eq!(
        receiver.recv_timeout(DEADLINE),
        Err(channel::RecvTimeoutError::Disconnected)
    );
}

#[test]
fn cancellation_before_admission_never_publishes_a_result() {
    let cancel = AtomicBool::new(true);
    let (mut sender, receiver) = result_batch::bounded(1);
    assert!(!sender.push(1, &cancel, RETRY));
    assert!(!sender.flush(&cancel, RETRY));
    assert!(!sender.flush_due(&cancel, RETRY));
    assert_eq!(receiver.try_recv(), Err(channel::TryRecvError::Empty));
}

#[test]
fn disconnected_packet_consumer_cancels_the_walk() {
    let cancel = AtomicBool::new(false);
    let (mut sender, receiver) = result_batch::bounded(1);
    drop(receiver);
    assert!(!sender.push(1, &cancel, RETRY));
    assert!(cancel.load(Ordering::Relaxed));
}

#[test]
fn relay_delivers_every_entry_and_disconnects_after_the_final_packet() {
    let cancel = Arc::new(AtomicBool::new(false));
    let (mut sender, packets) = result_batch::bounded(128);
    let (entry_tx, entry_rx) = channel::bounded(1);
    let now = Instant::now();
    for value in 0..70 {
        assert!(sender.push_at(value, &cancel, RETRY, now));
    }
    assert!(sender.flush(&cancel, RETRY));
    drop(sender);
    let worker = {
        let cancel = Arc::clone(&cancel);
        thread::spawn(move || result_batch::relay(&packets, &entry_tx, &cancel, RETRY))
    };
    let mut seen = Vec::new();
    loop {
        match entry_rx.recv_timeout(DEADLINE) {
            Ok(entry) => seen.push(entry),
            Err(channel::RecvTimeoutError::Disconnected) => break,
            Err(channel::RecvTimeoutError::Timeout) => {
                cancel.store(true, Ordering::Relaxed);
                panic!("relay failed to finish");
            }
        }
    }
    worker.join().unwrap();
    assert_eq!(seen, (0..70).collect::<Vec<_>>());
    assert!(!cancel.load(Ordering::Relaxed));
}

#[test]
fn dropped_entry_consumer_stops_the_relay_and_cancels_producers() {
    let cancel = AtomicBool::new(false);
    let (mut sender, packets) = result_batch::bounded(1);
    assert!(sender.push(1, &cancel, RETRY));
    let (entry_tx, entry_rx) = channel::bounded(1);
    drop(entry_rx);
    result_batch::relay(&packets, &entry_tx, &cancel, RETRY);
    assert!(cancel.load(Ordering::Relaxed));
}
