//! Bounded background observations. Probes run on workers that never acquire
//! the bookkeeping lock. A stalled probe keeps its slot until its worker exits.

use std::collections::{BTreeMap, VecDeque};
use std::sync::mpsc::{Receiver, TryRecvError, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Probe<K, V> = dyn Fn(&K) -> Result<V, String> + Send + Sync;

#[derive(Debug, Clone)]
pub struct Observation<V> {
    pub value: V,
    pub collected_at: Instant,
}

/// Admission status and configuration generation of one batched lookup.
pub(super) struct BatchRequest<K> {
    key: K,
    epoch: Result<u64, String>,
}

struct Pending<V> {
    epoch: u64,
    started_at: Instant,
    priority: bool,
    receiver: Receiver<Result<V, String>>,
    worker: std::thread::JoinHandle<()>,
}

struct Entry<V> {
    observation: Option<Observation<V>>,
    pending: Option<Pending<V>>,
    last_attempt: Option<Instant>,
    last_requested: Instant,
    error: Option<String>,
    priority: bool,
}

impl<V> Entry<V> {
    const fn new(now: Instant, priority: bool) -> Self {
        Self {
            observation: None,
            pending: None,
            last_attempt: None,
            last_requested: now,
            error: None,
            priority,
        }
    }

    fn current(&self, now: Instant, max_age: Duration) -> Option<&Observation<V>> {
        self.observation.as_ref().filter(|observation| {
            now.checked_duration_since(observation.collected_at)
                .is_some_and(|age| age <= max_age)
        })
    }

    fn result(&self, now: Instant, max_age: Duration) -> Result<Observation<V>, String>
    where
        V: Clone,
    {
        self.current(now, max_age).cloned().ok_or_else(|| {
            self.error.clone().unwrap_or_else(|| {
                if self.pending.is_some() {
                    "filesystem observation pending".to_string()
                } else {
                    "filesystem probe worker limit reached".to_string()
                }
            })
        })
    }
}

struct State<K, V> {
    entries: BTreeMap<K, Entry<V>>,
    waiting: VecDeque<K>,
    epoch: Option<u64>,
    refresh_after: Duration,
    max_age: Duration,
}

impl<K, V> State<K, V> {
    fn invalidate(&mut self) {
        self.epoch = self.epoch.and_then(|epoch| epoch.checked_add(1));
        self.waiting.clear();
        for entry in self.entries.values_mut() {
            entry.observation = None;
            entry.last_attempt = None;
            entry.error = None;
            // In-flight receivers deliberately remain: neither expiry nor a
            // reload can manufacture a free worker slot.
        }
    }

    fn receive_ready(&mut self, now: Instant) {
        for entry in self.entries.values_mut() {
            let Some(pending) = &entry.pending else {
                continue;
            };
            // A sent result is not quite a finished thread: its captures may
            // still be dropping. Retain the slot through that final teardown.
            // `is_finished` never waits; no caller or destructor joins workers.
            if !pending.worker.is_finished() {
                continue;
            }
            let result = match pending.receiver.try_recv() {
                Ok(result) => result,
                Err(TryRecvError::Empty) => continue,
                Err(TryRecvError::Disconnected) => {
                    Err("filesystem probe worker exited without a result".to_string())
                }
            };
            let pending = entry.pending.take().expect("pending probe exists");
            if Some(pending.epoch) != self.epoch {
                continue;
            }
            entry.observation = None;
            match result {
                Ok(value)
                    if now
                        .checked_duration_since(pending.started_at)
                        .is_some_and(|age| age <= self.max_age) =>
                {
                    entry.observation = Some(Observation {
                        value,
                        collected_at: pending.started_at,
                    });
                    entry.error = None;
                }
                Ok(_) => {
                    entry.error =
                        Some("filesystem observation expired before delivery".to_string());
                }
                Err(error) => entry.error = Some(error),
            }
        }
    }
}

/// One slot is reserved for priority requests (the daemon's `/` observation).
/// Other paths and inventory discovery cannot occupy that final slot.
/// Normal cache churn also cannot evict a priority root's completed evidence.
/// Requests waiting for an ordinary slot are served in admission order, so
/// repeated refreshes of early roots cannot starve later filesystems.
/// Dropping this value detaches workers; it never waits for a blocked probe.
pub struct BoundedObserver<K, V> {
    probe: Arc<Probe<K, V>>,
    max_workers: usize,
    max_entries: usize,
    state: Mutex<State<K, V>>,
}

impl<K, V> BoundedObserver<K, V>
where
    K: Clone + Ord + Send + 'static,
    V: Clone + Send + 'static,
{
    pub fn new(
        probe: Arc<Probe<K, V>>,
        refresh_after: Duration,
        max_age: Duration,
        max_workers: usize,
        max_entries: usize,
    ) -> Self {
        assert!(
            max_workers >= 2,
            "a reserved worker needs at least two slots"
        );
        assert!(max_entries >= max_workers);
        Self {
            probe,
            max_workers,
            max_entries,
            state: Mutex::new(State {
                entries: BTreeMap::new(),
                waiting: VecDeque::new(),
                epoch: Some(0),
                refresh_after,
                max_age,
            }),
        }
    }

    pub fn observe(&self, key: &K, priority: bool) -> Result<Observation<V>, String> {
        self.observe_at(key, priority, Instant::now())
    }

    fn observe_at(&self, key: &K, priority: bool, now: Instant) -> Result<Observation<V>, String> {
        let state = self.request_at(key, priority, now)?;
        state.entries[key].result(now, state.max_age)
    }

    /// Request a key whose result a batch will read later.
    pub(super) fn request(&self, key: K, priority: bool) -> BatchRequest<K> {
        let epoch = self
            .request_at(&key, priority, Instant::now())
            .map(|state| state.epoch.expect("request admitted to a live epoch"));
        BatchRequest { key, epoch }
    }

    fn request_at(
        &self,
        key: &K,
        priority: bool,
        now: Instant,
    ) -> Result<std::sync::MutexGuard<'_, State<K, V>>, String> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.receive_ready(now);
        let Some(epoch) = state.epoch else {
            return Err("filesystem observation epoch exhausted".to_string());
        };
        if !state.entries.contains_key(key) {
            if state.entries.len() >= self.max_entries {
                let evict = state
                    .entries
                    .iter()
                    .filter(|(_, entry)| entry.pending.is_none() && !entry.priority)
                    .min_by_key(|(_, entry)| entry.last_requested)
                    .map(|(key, _)| key.clone());
                let Some(evict) = evict else {
                    return Err("filesystem observation capacity is occupied".to_string());
                };
                state.entries.remove(&evict);
                state.waiting.retain(|queued| queued != &evict);
            }
            state.entries.insert(key.clone(), Entry::new(now, priority));
        }

        let refresh_after = state.refresh_after;
        let entry = state.entries.get_mut(key).expect("requested entry exists");
        entry.last_requested = now;
        entry.priority |= priority;
        let needs_refresh = entry.pending.is_none()
            && entry.last_attempt.is_none_or(|attempt| {
                now.checked_duration_since(attempt)
                    .is_some_and(|elapsed| elapsed >= refresh_after)
            });
        if needs_refresh && !state.waiting.contains(key) {
            state.waiting.push_back(key.clone());
        }
        self.start_waiting(&mut state, epoch, now);

        Ok(state)
    }

    /// Finish a batch of already requested keys. A lookup for *any* key may
    /// receive a peer's completed probe. A missing pending handle therefore
    /// cannot distinguish a refused request from a result ready in the cache.
    /// Read every result under one lock at the same cutoff, including keys
    /// whose earlier evidence expired or whose refresh failed while waiting.
    pub(super) fn finish_batch(
        &self,
        requests: &[BatchRequest<K>],
        started: Instant,
        grace: Duration,
        poll: Duration,
    ) -> (Vec<Result<Observation<V>, String>>, Duration) {
        let mut waited = Duration::ZERO;
        loop {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let now = Instant::now();
            state.receive_ready(now);
            if let Some(epoch) = state.epoch
                && !state.waiting.is_empty()
                && requests
                    .iter()
                    .any(|request| request.epoch.as_ref() == Ok(&epoch))
            {
                self.start_waiting(&mut state, epoch, now);
            }
            let remaining = grace.saturating_sub(now.saturating_duration_since(started));
            let waiting = !remaining.is_zero()
                && requests.iter().any(|request| {
                    state.epoch.is_some_and(|epoch| request.epoch == Ok(epoch))
                        && state.entries.get(&request.key).is_some_and(|entry| {
                            entry.current(now, state.max_age).is_none()
                                && entry.pending.as_ref().is_some_and(|probe| {
                                    probe.started_at >= started && Some(probe.epoch) == state.epoch
                                })
                        })
                });
            if !waiting {
                let results = requests
                    .iter()
                    .map(|request| {
                        let epoch = request.epoch.as_ref().map_err(Clone::clone)?;
                        if Some(*epoch) != state.epoch {
                            return Err(
                                "filesystem observation invalidated during collection".into()
                            );
                        }
                        state
                            .entries
                            .get(&request.key)
                            .ok_or_else(|| {
                                "filesystem observation capacity is occupied".to_string()
                            })?
                            .result(now, state.max_age)
                    })
                    .collect();
                return (results, waited);
            }
            drop(state);
            let sleeping = Instant::now();
            std::thread::sleep(poll.min(remaining));
            waited += sleeping.elapsed();
        }
    }

    fn start_waiting(&self, state: &mut State<K, V>, epoch: u64, now: Instant) {
        let mut pending_total = state
            .entries
            .values()
            .filter(|entry| entry.pending.is_some())
            .count();
        let mut pending_regular = state
            .entries
            .values()
            .filter(|entry| entry.pending.as_ref().is_some_and(|probe| !probe.priority))
            .count();
        while pending_total < self.max_workers {
            // Priority demand can always use its reserved slot. Otherwise
            // preserve FIFO order, including requests that returned unknown
            // on an earlier tick. Serving only the current caller lets a
            // cached root take the same slot again on every fixed-order poll.
            let next = state
                .waiting
                .iter()
                .position(|key| state.entries[key].priority)
                .or_else(|| {
                    (pending_regular < self.max_workers - 1 && !state.waiting.is_empty())
                        .then_some(0)
                });
            let Some(next) = next else {
                break;
            };
            let request = state.waiting.remove(next).expect("queued request exists");
            let entry = state
                .entries
                .get_mut(&request)
                .expect("queued entry exists");
            let priority = entry.priority;
            let (sender, receiver) = sync_channel(1);
            let probe = Arc::clone(&self.probe);
            // Queue residence is not observation age: native work starts
            // now, and delayed completion still cannot renew this timestamp.
            entry.last_attempt = Some(now);
            match std::thread::Builder::new()
                .name("sbh-fs-probe".to_string())
                .spawn(move || {
                    let result = probe(&request);
                    let _ = sender.try_send(result);
                }) {
                Ok(worker) => {
                    entry.pending = Some(Pending {
                        epoch,
                        started_at: now,
                        priority,
                        receiver,
                        worker,
                    });
                    pending_total += 1;
                    pending_regular += usize::from(!priority);
                }
                Err(error) => {
                    entry.observation = None;
                    entry.error = Some(format!("could not start filesystem probe: {error}"));
                }
            }
        }
    }

    /// When the probe for `key` that has not delivered yet started, if one
    /// exists. A probe that finished but whose result has not been received
    /// still counts: its result is taken only by the next `observe`, so the
    /// caller that waits for it does not miss it. Nothing starts or waits.
    #[cfg(test)]
    fn pending_since(&self, key: &K) -> Option<Instant> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .entries
            .get(key)
            .and_then(|entry| entry.pending.as_ref())
            .map(|pending| pending.started_at)
    }

    pub fn invalidate(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .invalidate();
    }

    pub fn set_refresh_after(&self, refresh_after: Duration) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.refresh_after != refresh_after {
            state.refresh_after = refresh_after;
            state.invalidate();
        }
    }

    pub fn set_max_age(&self, max_age: Duration) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.max_age != max_age {
            state.max_age = max_age;
            state.invalidate();
        }
    }

    pub fn prune(&self) {
        self.prune_at(Instant::now());
    }

    fn prune_at(&self, now: Instant) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.receive_ready(now);
        let max_age = state.max_age;
        for entry in state.entries.values_mut() {
            if entry.observation.as_ref().is_some_and(|observation| {
                now.checked_duration_since(observation.collected_at)
                    .is_none_or(|age| age > max_age)
            }) {
                entry.observation = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const WAIT: Duration = Duration::from_secs(5);
    const CACHE: Duration = Duration::from_secs(60);

    fn await_value(
        observer: &BoundedObserver<String, usize>,
        key: &str,
        priority: bool,
    ) -> Observation<usize> {
        let deadline = Instant::now() + WAIT;
        let key = key.to_string();
        loop {
            if let Ok(observation) = observer.observe(&key, priority) {
                return observation;
            }
            assert!(Instant::now() < deadline, "observation did not complete");
            std::thread::yield_now();
        }
    }

    /// A finished probe whose result nobody has received is still pending:
    /// a caller that checks between its own lookup and the next one must not
    /// conclude there is nothing to wait for while the result sits unread.
    #[test]
    fn pending_since_reports_a_probe_until_its_result_is_received() {
        let (release, gate) = std::sync::mpsc::channel::<()>();
        let gate = Mutex::new(gate);
        let observer = BoundedObserver::new(
            Arc::new(move |_: &String| {
                let _ = gate.lock().unwrap().recv();
                Ok(7_usize)
            }),
            CACHE,
            CACHE,
            2,
            4,
        );
        let key = "a".to_string();
        assert_eq!(observer.pending_since(&key), None);
        let before = Instant::now();
        assert!(observer.observe(&key, false).is_err());
        let since = observer.pending_since(&key);
        assert!(since.is_some_and(|at| at >= before));
        release.send(()).unwrap();
        let deadline = Instant::now() + WAIT;
        while !observer.state.lock().unwrap().entries[&key]
            .pending
            .as_ref()
            .is_some_and(|pending| pending.worker.is_finished())
        {
            assert!(Instant::now() < deadline, "probe did not finish");
            std::thread::yield_now();
        }
        assert_eq!(observer.pending_since(&key), since);
        assert_eq!(await_value(&observer, "a", false).value, 7);
        assert_eq!(observer.pending_since(&key), None);
    }

    fn await_idle(observer: &BoundedObserver<String, usize>, now: Instant) {
        let deadline = Instant::now() + WAIT;
        loop {
            observer.prune_at(now);
            if observer
                .state
                .lock()
                .unwrap()
                .entries
                .values()
                .all(|entry| entry.pending.is_none())
            {
                return;
            }
            assert!(Instant::now() < deadline, "probe did not exit");
            std::thread::yield_now();
        }
    }

    #[test]
    fn pressure_batch_keeps_a_fast_mount_delivered_by_a_peer_lookup() {
        let observer = BoundedObserver::new(
            Arc::new(|key: &String| Ok(if key == "ssd" { 1 } else { 80 })),
            CACHE,
            CACHE,
            3,
            4,
        );
        let started = Instant::now();
        let ssd = observer.request("ssd".to_string(), false);
        // Exactly the race in the old tick: the first lookup returned
        // pending, then a later path (or the metadata request on macOS)
        // received the SSD result while scheduling its own probe.
        let deadline = Instant::now() + WAIT;
        while !observer.state.lock().unwrap().entries["ssd"]
            .pending
            .as_ref()
            .unwrap()
            .worker
            .is_finished()
        {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        let system = observer.request("system".to_string(), true);
        assert_eq!(observer.pending_since(&ssd.key), None);
        let (samples, _) =
            observer.finish_batch(&[ssd, system], started, WAIT, Duration::from_millis(1));
        assert_eq!(samples[0].as_ref().unwrap().value, 1);
        assert_eq!(samples[1].as_ref().unwrap().value, 80);
    }

    #[test]
    fn pressure_batch_drops_a_cache_hit_revoked_before_its_cutoff() {
        let attempts = AtomicUsize::new(0);
        let observer = BoundedObserver::new(
            Arc::new(move |_: &String| {
                if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    Ok(1)
                } else {
                    Err("mount disconnected".into())
                }
            }),
            CACHE,
            CACHE * 2,
            2,
            4,
        );
        let key = "ssd".to_string();
        let first = await_value(&observer, &key, false);
        // Make the existing observation refreshable without a real sleep.
        observer
            .state
            .lock()
            .unwrap()
            .entries
            .get_mut(&key)
            .unwrap()
            .last_attempt = first.collected_at.checked_sub(CACHE);
        let started = Instant::now();
        let request = observer.request(key, false);
        assert_eq!(
            observer.state.lock().unwrap().entries["ssd"]
                .observation
                .as_ref()
                .unwrap()
                .value,
            1
        );
        await_idle(&observer, Instant::now());
        let (samples, waited) =
            observer.finish_batch(&[request], started, WAIT, Duration::from_millis(1));
        assert_eq!(samples[0].as_ref().unwrap_err(), "mount disconnected");
        assert_eq!(waited, Duration::ZERO);
    }

    #[test]
    fn pressure_batch_rejects_evidence_from_a_later_generation() {
        let observer = BoundedObserver::new(Arc::new(|_: &String| Ok(80)), CACHE, CACHE, 2, 4);
        let started = Instant::now();
        let old = observer.request("ssd".to_string(), false);
        await_idle(&observer, started);
        observer.set_max_age(CACHE * 2);
        let _ = await_value(&observer, "ssd", false);
        let (samples, waited) =
            observer.finish_batch(&[old], started, WAIT, Duration::from_millis(1));
        assert!(samples[0].as_ref().unwrap_err().contains("invalidated"));
        assert_eq!(waited, Duration::ZERO);
    }

    #[test]
    fn stalled_peer_cannot_take_the_reserved_root_slot() {
        let (entered_tx, entered_rx) = sync_channel(1);
        let (resume_tx, resume_rx) = sync_channel(1);
        let resume_rx = Mutex::new(resume_rx);
        let calls = Arc::new(AtomicUsize::new(0));
        let probe_calls = Arc::clone(&calls);
        let observer = BoundedObserver::new(
            Arc::new(move |key: &String| {
                probe_calls.fetch_add(1, Ordering::SeqCst);
                if key == "stalled" {
                    entered_tx.send(()).unwrap();
                    resume_rx.lock().unwrap().recv_timeout(WAIT).unwrap();
                }
                Ok(if key == "/" { 2 } else { 80 })
            }),
            CACHE,
            CACHE,
            2,
            4,
        );
        assert!(observer.observe(&"stalled".into(), false).is_err());
        entered_rx.recv_timeout(WAIT).unwrap();
        for _ in 0..100 {
            assert!(observer.observe(&"other".into(), false).is_err());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(await_value(&observer, "/", true).value, 2);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        resume_tx.send(()).unwrap();
        await_idle(&observer, Instant::now());
    }

    #[test]
    fn reload_keeps_occupied_slots_and_discards_old_successes() {
        let (entered_tx, entered_rx) = sync_channel(1);
        let (resume_tx, resume_rx) = sync_channel(1);
        let resume_rx = Mutex::new(resume_rx);
        let calls = Arc::new(AtomicUsize::new(0));
        let probe_calls = Arc::clone(&calls);
        let observer = BoundedObserver::new(
            Arc::new(move |_key: &String| {
                let call = probe_calls.fetch_add(1, Ordering::SeqCst);
                if call == 0 {
                    entered_tx.send(()).unwrap();
                    resume_rx.lock().unwrap().recv_timeout(WAIT).unwrap();
                }
                Ok(call + 1)
            }),
            CACHE,
            CACHE,
            2,
            4,
        );
        assert!(observer.observe(&"mount".into(), false).is_err());
        entered_rx.recv_timeout(WAIT).unwrap();
        for _ in 0..20 {
            observer.invalidate();
            observer.prune();
            assert!(observer.observe(&"mount".into(), false).is_err());
            assert!(observer.observe(&"new-config-root".into(), false).is_err());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        resume_tx.send(()).unwrap();
        await_idle(&observer, Instant::now());
        assert!(
            observer.state.lock().unwrap().entries["mount"]
                .observation
                .is_none()
        );
        assert_eq!(await_value(&observer, "new-config-root", false).value, 2);
        assert_eq!(await_value(&observer, "mount", false).value, 3);
    }

    #[test]
    fn delivery_does_not_refresh_an_expired_native_observation() {
        let (entered_tx, entered_rx) = sync_channel(1);
        let (resume_tx, resume_rx) = sync_channel(1);
        let resume_rx = Mutex::new(resume_rx);
        let observer = BoundedObserver::new(
            Arc::new(move |_key: &String| {
                entered_tx.send(()).unwrap();
                resume_rx.lock().unwrap().recv_timeout(WAIT).unwrap();
                Ok(80)
            }),
            CACHE,
            Duration::from_secs(1),
            2,
            4,
        );
        let before = Instant::now();
        assert!(observer.observe_at(&"mount".into(), false, before).is_err());
        entered_rx.recv_timeout(WAIT).unwrap();
        resume_tx.send(()).unwrap();
        let later = before + Duration::from_secs(2);
        await_idle(&observer, later);
        let error = observer
            .observe_at(&"mount".into(), false, later)
            .unwrap_err();
        assert!(error.contains("expired before delivery"));
    }

    #[test]
    fn unchanged_cached_reads_keep_the_original_timestamp() {
        let calls = Arc::new(AtomicUsize::new(0));
        let probe_calls = Arc::clone(&calls);
        let observer = BoundedObserver::new(
            Arc::new(move |_key: &String| Ok(probe_calls.fetch_add(1, Ordering::SeqCst))),
            CACHE,
            CACHE,
            2,
            4,
        );
        let first = await_value(&observer, "mount", false);
        let second = await_value(&observer, "mount", false);
        assert_eq!(first.collected_at, second.collected_at);
        assert_eq!(first.value, second.value);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn changing_timing_never_resurrects_cached_evidence() {
        let observer = BoundedObserver::new(
            Arc::new(|_key: &String| Ok(80)),
            CACHE,
            Duration::from_secs(1),
            2,
            4,
        );
        let first = await_value(&observer, "mount", false);
        observer.prune_at(first.collected_at + Duration::from_secs(2));
        observer.set_max_age(CACHE);
        {
            let state = observer.state.lock().unwrap();
            assert!(state.entries["mount"].observation.is_none());
            drop(state);
        }
        let fresh = await_value(&observer, "mount", false);
        assert!(fresh.collected_at > first.collected_at);
        observer.set_refresh_after(Duration::from_secs(2));
        assert!(
            observer.state.lock().unwrap().entries["mount"]
                .observation
                .is_none()
        );
    }

    #[test]
    fn bounded_entries_never_evict_an_occupied_worker() {
        let (entered_tx, entered_rx) = sync_channel(1);
        let (resume_tx, resume_rx) = sync_channel(1);
        let resume_rx = Mutex::new(resume_rx);
        let calls = Arc::new(AtomicUsize::new(0));
        let probe_calls = Arc::clone(&calls);
        let observer = BoundedObserver::new(
            Arc::new(move |_key: &String| {
                probe_calls.fetch_add(1, Ordering::SeqCst);
                entered_tx.send(()).unwrap();
                resume_rx.lock().unwrap().recv_timeout(WAIT).unwrap();
                Ok(1)
            }),
            CACHE,
            CACHE,
            2,
            2,
        );
        assert!(observer.observe(&"stalled".into(), false).is_err());
        entered_rx.recv_timeout(WAIT).unwrap();
        for index in 0..100 {
            assert!(observer.observe(&format!("new-{index}"), false).is_err());
            let state = observer.state.lock().unwrap();
            assert_eq!(state.entries.len(), 2);
            assert!(state.entries["stalled"].pending.is_some());
            drop(state);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        resume_tx.send(()).unwrap();
        await_idle(&observer, Instant::now());
    }

    #[test]
    fn dropping_observer_does_not_join_a_blocked_worker() {
        let (entered_tx, entered_rx) = sync_channel(1);
        let (resume_tx, resume_rx) = sync_channel(1);
        let resume_rx = Mutex::new(resume_rx);
        let observer = BoundedObserver::new(
            Arc::new(move |_key: &String| {
                entered_tx.send(()).unwrap();
                resume_rx.lock().unwrap().recv_timeout(WAIT).unwrap();
                Ok(1)
            }),
            CACHE,
            CACHE,
            2,
            4,
        );
        assert!(observer.observe(&"stalled".into(), false).is_err());
        entered_rx.recv_timeout(WAIT).unwrap();
        let (dropped_tx, dropped_rx) = sync_channel(1);
        std::thread::spawn(move || {
            drop(observer);
            dropped_tx.send(()).unwrap();
        });
        dropped_rx
            .recv_timeout(WAIT)
            .expect("drop must not join a probe");
        resume_tx.send(()).unwrap();
    }

    #[test]
    fn panicking_worker_becomes_unknown_and_releases_its_slot() {
        let observer = BoundedObserver::new(
            Arc::new(|key: &String| {
                assert!(key != "panic", "injected native probe panic");
                Ok(80)
            }),
            CACHE,
            CACHE,
            2,
            4,
        );
        assert!(observer.observe(&"panic".into(), false).is_err());
        await_idle(&observer, Instant::now());
        let error = observer.observe(&"panic".into(), false).unwrap_err();
        assert!(error.contains("exited without a result"));
        assert_eq!(await_value(&observer, "healthy", false).value, 80);
    }

    #[test]
    fn failed_refresh_revokes_an_unexpired_cached_success() {
        let fail = Arc::new(AtomicBool::new(false));
        let probe_fail = Arc::clone(&fail);
        let observer = BoundedObserver::new(
            Arc::new(move |_key: &String| {
                if probe_fail.load(Ordering::SeqCst) {
                    Err("native filesystem unavailable".to_string())
                } else {
                    Ok(80)
                }
            }),
            CACHE,
            CACHE * 2,
            2,
            4,
        );
        let first = await_value(&observer, "mount", false);
        fail.store(true, Ordering::SeqCst);
        let refresh = first.collected_at + CACHE;
        assert_eq!(
            observer
                .observe_at(&"mount".into(), false, refresh)
                .unwrap()
                .value,
            80
        );
        await_idle(&observer, refresh);
        let error = observer
            .observe_at(&"mount".into(), false, refresh)
            .unwrap_err();
        assert!(error.contains("native filesystem unavailable"));
    }

    #[test]
    fn root_evidence_survives_a_flood_of_normal_request_keys() {
        let observer = BoundedObserver::new(Arc::new(|_key: &String| Ok(80)), CACHE, CACHE, 2, 2);
        let root = await_value(&observer, "/", true);
        for index in 0..100 {
            let _ = observer.observe(&format!("root-{index}"), false);
            await_idle(&observer, Instant::now());
        }
        let retained = observer.observe(&"/".into(), true).unwrap();
        assert_eq!(retained.collected_at, root.collected_at);
        assert!(observer.state.lock().unwrap().entries.len() <= 2);
    }

    #[test]
    fn waiting_probe_precedes_repeated_cached_refresh() {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        let calls = AtomicUsize::new(0);
        let observer = BoundedObserver::new(
            Arc::new(move |key: &String| {
                started_tx.send(key.clone()).unwrap();
                if key == "early" && calls.fetch_add(1, Ordering::SeqCst) > 0 {
                    release_rx.lock().unwrap().recv_timeout(WAIT).unwrap();
                }
                Ok(80)
            }),
            CACHE,
            CACHE * 10,
            2,
            4,
        );
        let first = await_value(&observer, "early", false);
        assert_eq!(started_rx.recv_timeout(WAIT).unwrap(), "early");
        let refresh_at = first.collected_at + CACHE;
        assert!(
            observer
                .observe_at(&"early".into(), false, refresh_at)
                .is_ok()
        );
        assert_eq!(started_rx.recv_timeout(WAIT).unwrap(), "early");
        for _ in 0..10 {
            assert!(
                observer
                    .observe_at(&"late".into(), false, refresh_at)
                    .is_err()
            );
        }
        assert!(observer.pending_since(&"late".into()).is_none());
        release_tx.send(()).unwrap();
        await_idle(&observer, refresh_at);

        // The daemon reads configured roots in the same order each tick. A
        // cached early root must not reclaim the only ordinary slot forever.
        let next_tick = refresh_at + CACHE;
        assert!(
            observer
                .observe_at(&"early".into(), false, next_tick)
                .is_ok()
        );
        let admitted = started_rx.recv_timeout(WAIT).unwrap();
        release_tx.send(()).unwrap();
        await_idle(&observer, next_tick);
        assert_eq!(
            admitted, "late",
            "waiting filesystem was starved by a refresh"
        );
        let state = observer.state.lock().unwrap();
        let late = state.entries["late"].observation.as_ref().unwrap();
        assert_eq!(late.collected_at, next_tick, "queue wait is not probe age");
        drop(state);
    }

    #[test]
    fn invalidation_discards_waiting_work_but_preserves_occupied_slots() {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        let observer = BoundedObserver::new(
            Arc::new(move |key: &String| {
                started_tx.send(key.clone()).unwrap();
                if key == "old" {
                    release_rx.lock().unwrap().recv_timeout(WAIT).unwrap();
                }
                Ok(80)
            }),
            CACHE,
            CACHE,
            2,
            4,
        );
        assert!(observer.observe(&"old".into(), false).is_err());
        assert_eq!(started_rx.recv_timeout(WAIT).unwrap(), "old");
        assert!(observer.observe(&"removed".into(), false).is_err());
        observer.invalidate();
        assert!(observer.observe(&"current".into(), false).is_err());
        assert!(started_rx.try_recv().is_err());
        release_tx.send(()).unwrap();
        await_idle(&observer, Instant::now());

        assert_eq!(await_value(&observer, "current", false).value, 80);
        assert_eq!(started_rx.recv_timeout(WAIT).unwrap(), "current");
        assert!(
            started_rx.try_recv().is_err(),
            "removed work must not start"
        );
        let state = observer.state.lock().unwrap();
        assert!(state.entries["old"].observation.is_none());
        assert!(state.entries["removed"].observation.is_none());
        drop(state);
    }

    #[test]
    fn evicting_waiting_requests_cannot_leave_orphaned_work() {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        let observer = BoundedObserver::new(
            Arc::new(move |key: &String| {
                started_tx.send(key.clone()).unwrap();
                if key == "blocked" {
                    release_rx.lock().unwrap().recv_timeout(WAIT).unwrap();
                }
                Ok(80)
            }),
            CACHE,
            CACHE,
            2,
            2,
        );
        assert!(observer.observe(&"blocked".into(), false).is_err());
        assert_eq!(started_rx.recv_timeout(WAIT).unwrap(), "blocked");
        assert!(observer.observe(&"evicted".into(), false).is_err());
        assert!(observer.observe(&"retained".into(), false).is_err());
        release_tx.send(()).unwrap();
        await_idle(&observer, Instant::now());
        assert_eq!(await_value(&observer, "retained", false).value, 80);
        assert_eq!(started_rx.recv_timeout(WAIT).unwrap(), "retained");
        assert!(started_rx.try_recv().is_err());
    }

    #[test]
    fn a_waiting_request_promoted_to_priority_can_use_the_reserved_slot() {
        let (entered_tx, entered_rx) = sync_channel(1);
        let (release_tx, release_rx) = sync_channel(1);
        let release_rx = Mutex::new(release_rx);
        let observer = BoundedObserver::new(
            Arc::new(move |key: &String| {
                if key == "blocked" {
                    entered_tx.send(()).unwrap();
                    release_rx.lock().unwrap().recv_timeout(WAIT).unwrap();
                }
                Ok(80)
            }),
            CACHE,
            CACHE,
            2,
            4,
        );
        assert!(observer.observe(&"blocked".into(), false).is_err());
        entered_rx.recv_timeout(WAIT).unwrap();
        assert!(observer.observe(&"promoted".into(), false).is_err());
        assert_eq!(await_value(&observer, "promoted", true).value, 80);
        assert!(observer.pending_since(&"blocked".into()).is_some());
        release_tx.send(()).unwrap();
        await_idle(&observer, Instant::now());
    }
}
