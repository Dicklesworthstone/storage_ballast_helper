//! Bounded background observations. Probes run on workers that never acquire
//! the bookkeeping lock. A stalled probe keeps its slot until its worker exits.

use std::collections::BTreeMap;
use std::sync::mpsc::{Receiver, TryRecvError, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Probe<K, V> = dyn Fn(&K) -> Result<V, String> + Send + Sync;

#[derive(Debug, Clone)]
pub struct Observation<V> {
    pub value: V,
    pub collected_at: Instant,
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
}

struct State<K, V> {
    entries: BTreeMap<K, Entry<V>>,
    epoch: Option<u64>,
    refresh_after: Duration,
    max_age: Duration,
}

impl<K, V> State<K, V> {
    fn invalidate(&mut self) {
        self.epoch = self.epoch.and_then(|epoch| epoch.checked_add(1));
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
                epoch: Some(0),
                refresh_after,
                max_age,
            }),
        }
    }

    pub fn observe(&self, key: K, priority: bool) -> Result<Observation<V>, String> {
        self.observe_at(key, priority, Instant::now())
    }

    fn observe_at(&self, key: K, priority: bool, now: Instant) -> Result<Observation<V>, String> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.receive_ready(now);
        let Some(epoch) = state.epoch else {
            return Err("filesystem observation epoch exhausted".to_string());
        };
        if !state.entries.contains_key(&key) {
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
            }
            state.entries.insert(key.clone(), Entry::new(now, priority));
        }

        let pending_total = state
            .entries
            .values()
            .filter(|entry| entry.pending.is_some())
            .count();
        let pending_regular = state
            .entries
            .values()
            .filter(|entry| entry.pending.as_ref().is_some_and(|probe| !probe.priority))
            .count();
        let slot_available = pending_total < self.max_workers
            && (priority || pending_regular < self.max_workers - 1);
        let refresh_after = state.refresh_after;
        let max_age = state.max_age;
        let entry = state.entries.get_mut(&key).expect("requested entry exists");
        entry.last_requested = now;
        entry.priority |= priority;
        let needs_refresh = entry.pending.is_none()
            && entry.last_attempt.is_none_or(|attempt| {
                now.checked_duration_since(attempt)
                    .is_some_and(|elapsed| elapsed >= refresh_after)
            });
        if needs_refresh && slot_available {
            let (sender, receiver) = sync_channel(1);
            let probe = Arc::clone(&self.probe);
            let request = key;
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
                }
                Err(error) => {
                    entry.observation = None;
                    entry.error = Some(format!("could not start filesystem probe: {error}"));
                }
            }
        }

        let result = if let Some(observation) = &entry.observation
            && now
                .checked_duration_since(observation.collected_at)
                .is_some_and(|age| age <= max_age)
        {
            Ok(observation.clone())
        } else {
            entry.observation = None;
            Err(entry.error.clone().unwrap_or_else(|| {
                if entry.pending.is_some() {
                    "filesystem observation pending".to_string()
                } else {
                    "filesystem probe worker limit reached".to_string()
                }
            }))
        };
        drop(state);
        result
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
        loop {
            if let Ok(observation) = observer.observe(key.to_string(), priority) {
                return observation;
            }
            assert!(Instant::now() < deadline, "observation did not complete");
            std::thread::yield_now();
        }
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
        assert!(observer.observe("stalled".into(), false).is_err());
        entered_rx.recv_timeout(WAIT).unwrap();
        for _ in 0..100 {
            assert!(observer.observe("other".into(), false).is_err());
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
        assert!(observer.observe("mount".into(), false).is_err());
        entered_rx.recv_timeout(WAIT).unwrap();
        for _ in 0..20 {
            observer.invalidate();
            observer.prune();
            assert!(observer.observe("mount".into(), false).is_err());
            assert!(observer.observe("new-config-root".into(), false).is_err());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        resume_tx.send(()).unwrap();
        await_idle(&observer, Instant::now());
        assert!(
            observer.state.lock().unwrap().entries["mount"]
                .observation
                .is_none()
        );
        assert_eq!(await_value(&observer, "mount", false).value, 2);
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
        assert!(observer.observe_at("mount".into(), false, before).is_err());
        entered_rx.recv_timeout(WAIT).unwrap();
        resume_tx.send(()).unwrap();
        let later = before + Duration::from_secs(2);
        await_idle(&observer, later);
        let error = observer
            .observe_at("mount".into(), false, later)
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
        assert!(observer.observe("stalled".into(), false).is_err());
        entered_rx.recv_timeout(WAIT).unwrap();
        for index in 0..100 {
            assert!(observer.observe(format!("new-{index}"), false).is_err());
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
        assert!(observer.observe("stalled".into(), false).is_err());
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
        assert!(observer.observe("panic".into(), false).is_err());
        await_idle(&observer, Instant::now());
        let error = observer.observe("panic".into(), false).unwrap_err();
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
                .observe_at("mount".into(), false, refresh)
                .unwrap()
                .value,
            80
        );
        await_idle(&observer, refresh);
        let error = observer
            .observe_at("mount".into(), false, refresh)
            .unwrap_err();
        assert!(error.contains("native filesystem unavailable"));
    }

    #[test]
    fn root_evidence_survives_a_flood_of_normal_request_keys() {
        let observer = BoundedObserver::new(Arc::new(|_key: &String| Ok(80)), CACHE, CACHE, 2, 2);
        let root = await_value(&observer, "/", true);
        for index in 0..100 {
            let _ = observer.observe(format!("root-{index}"), false);
            await_idle(&observer, Instant::now());
        }
        let retained = observer.observe("/".into(), true).unwrap();
        assert_eq!(retained.collected_at, root.collected_at);
        assert!(observer.state.lock().unwrap().entries.len() <= 2);
    }
}
