//! Filesystem pressure transitions and retryable notifications.
//!
//! Observed transitions belong in the activity log even when notifications
//! are throttled. A successful enqueue, rather than an attempted send, starts
//! the notification cooldown. Neither an absent mount nor an older bind-mount
//! observation is evidence that a pressured filesystem recovered.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::daemon::notifications::{NotificationDispatchOutcome, NotificationEvent};
use crate::logger::dual::ActivityEvent;
use crate::monitor::inode_pressure::InodePressureEvidence;
use crate::monitor::pid::{PressureLevel, PressureResponse, classify_level};
use crate::monitor::ram_scratch::swap_reclaim_pressure;
use crate::platform::pal::{FsStats, InodeStats, MemoryInfo};

const NOTIFY_COOLDOWN: Duration = Duration::from_mins(5);

/// Evidence copied from the completed samples that drove this tick. No
/// constructor probes native state or supplies cleanup authority.
#[derive(Clone)]
pub(super) struct PressureObservation {
    key: PressureKey,
    level: PressureLevel,
    collected_at: Instant,
    evidence: PressureEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum FilesystemKey {
    Device(u64),
    Path(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PressureKey {
    Bytes(FilesystemKey),
    Inodes(FilesystemKey),
    HostSwap,
}

#[derive(Clone)]
enum PressureEvidence {
    Bytes {
        stats: FsStats,
        urgency: f64,
        rate_bps: Option<f64>,
    },
    Inodes {
        mount: PathBuf,
        total: u64,
        available: u64,
        free_pct: f64,
    },
    Swap {
        total_bytes: u64,
        free_bytes: u64,
        free_pct: f64,
    },
}

impl FilesystemKey {
    fn new(mount: &Path, device_id: Option<u64>) -> Self {
        device_id.map_or_else(|| Self::Path(mount.to_path_buf()), Self::Device)
    }
}

impl PressureObservation {
    pub(super) fn filesystem(
        response: &PressureResponse,
        stats: &FsStats,
        collected_at: Instant,
        device_id: Option<u64>,
        rate_bps: f64,
    ) -> Option<Self> {
        if stats.mount_point != response.causing_mount
            || stats.total_bytes == 0
            || stats.free_bytes > stats.total_bytes
            || stats.available_bytes > stats.free_bytes
        {
            return None;
        }
        Some(Self {
            key: PressureKey::Bytes(FilesystemKey::new(&stats.mount_point, device_id)),
            level: response.level,
            collected_at,
            evidence: PressureEvidence::Bytes {
                stats: stats.clone(),
                urgency: response.urgency,
                rate_bps: rate_bps.is_finite().then_some(rate_bps),
            },
        })
    }

    pub(super) fn inodes(
        mount: &Path,
        pressure: &InodePressureEvidence,
        collected_at: Instant,
        device_id: Option<u64>,
    ) -> Option<Self> {
        let stats = InodeStats::new(pressure.total, pressure.free, pressure.available)?;
        if !matches!(
            pressure.level.as_str(),
            "green" | "yellow" | "orange" | "red" | "critical"
        ) {
            return None;
        }
        Some(Self {
            key: PressureKey::Inodes(FilesystemKey::new(mount, device_id)),
            level: pressure.pressure_level(),
            collected_at,
            evidence: PressureEvidence::Inodes {
                mount: mount.to_path_buf(),
                total: stats.total,
                available: stats.available,
                free_pct: stats.available_pct()?,
            },
        })
    }

    #[allow(clippy::cast_precision_loss)]
    pub(super) fn swap(
        memory: &MemoryInfo,
        thresholds: [f64; 4],
        collected_at: Instant,
    ) -> Option<Self> {
        if memory.total_bytes == 0
            || memory.available_bytes > memory.total_bytes
            || memory.swap_total_bytes == 0
            || memory.swap_free_bytes > memory.swap_total_bytes
        {
            return None;
        }
        let free_pct = memory.swap_free_bytes as f64 * 100.0 / memory.swap_total_bytes as f64;
        let [green, yellow, orange, red] = thresholds;
        // Match the bounded tmpfs relief policy: only low swap can promote
        // pressure. Valid headroom proves recovery; absent counters do not.
        let level = if swap_reclaim_pressure(memory).is_some() {
            classify_level(free_pct, green, yellow, orange, red)
        } else {
            PressureLevel::Green
        };
        Some(Self {
            key: PressureKey::HostSwap,
            level,
            collected_at,
            evidence: PressureEvidence::Swap {
                total_bytes: memory.swap_total_bytes,
                free_bytes: memory.swap_free_bytes,
                free_pct,
            },
        })
    }

    fn mount(&self) -> &Path {
        match &self.evidence {
            PressureEvidence::Bytes { stats, .. } => &stats.mount_point,
            PressureEvidence::Inodes { mount, .. } => mount,
            PressureEvidence::Swap { .. } => Path::new(""),
        }
    }

    fn notification(&self, from: PressureLevel) -> NotificationEvent {
        let from = format!("{from:?}");
        let to = format!("{:?}", self.level);
        match &self.evidence {
            PressureEvidence::Bytes { stats, .. } => NotificationEvent::PressureChanged {
                from,
                to,
                mount: stats.mount_point.to_string_lossy().into_owned(),
                free_pct: stats.free_pct(),
            },
            PressureEvidence::Inodes {
                mount,
                total,
                available,
                free_pct,
            } => NotificationEvent::InodePressureChanged {
                from,
                to,
                mount: mount.to_string_lossy().into_owned(),
                total_inodes: *total,
                available_inodes: *available,
                free_pct: *free_pct,
            },
            PressureEvidence::Swap {
                total_bytes,
                free_bytes,
                free_pct,
            } => NotificationEvent::SwapPressureChanged {
                from,
                to,
                swap_total_bytes: *total_bytes,
                swap_free_bytes: *free_bytes,
                free_pct: *free_pct,
            },
        }
    }

    fn activity(&self, from: PressureLevel) -> ActivityEvent {
        match &self.evidence {
            PressureEvidence::Bytes {
                stats,
                urgency,
                rate_bps,
            } => ActivityEvent::PressureChanged {
                from: format!("{from:?}"),
                to: format!("{:?}", self.level),
                free_pct: stats.free_pct(),
                rate_bps: *rate_bps,
                mount_point: stats.mount_point.to_string_lossy().into_owned(),
                total_bytes: i64::try_from(stats.total_bytes).unwrap_or(i64::MAX),
                free_bytes: i64::try_from(stats.available_bytes).unwrap_or(i64::MAX),
                ewma_rate: *rate_bps,
                pid_output: Some(*urgency),
            },
            PressureEvidence::Inodes { .. } | PressureEvidence::Swap { .. } => ActivityEvent::Info {
                message: self.notification(from).summary(),
            },
        }
    }
}

struct FilesystemState {
    level: PressureLevel,
    collected_at: Instant,
    last_seen: Instant,
    notified: Option<(PressureLevel, Instant)>,
    pending_from: Option<PressureLevel>,
}

/// Independent observed and delivered histories for every physical filesystem.
#[derive(Default)]
pub(super) struct PressureNotifications {
    filesystems: HashMap<PressureKey, FilesystemState>,
}

impl PressureNotifications {
    /// An accepted alert only acknowledges the destinations that accepted it.
    /// Preserve observed transitions and their timestamps while rearming active
    /// pressure for a replacement destination. Delivery still needs a current
    /// observation; absent filesystems and healthy initial states stay silent.
    pub(super) fn rearm_notifications(&mut self) {
        for state in self.filesystems.values_mut() {
            state.notified = None;
            state.pending_from =
                (state.level != PressureLevel::Green).then_some(PressureLevel::Green);
        }
    }

    pub(super) fn observe(
        &mut self,
        observations: &[PressureObservation],
        now: Instant,
        mut log: impl FnMut(ActivityEvent),
        mut notify: impl FnMut(&NotificationEvent) -> NotificationDispatchOutcome,
    ) {
        let mut grouped: Vec<(PressureKey, &PressureObservation)> = Vec::new();
        for observation in observations {
            if now.checked_duration_since(observation.collected_at).is_none() {
                continue;
            }
            let key = observation.key.clone();
            // An older alias cannot supersede the evidence already observed
            // for this device, including after its more severe alias vanishes.
            if self.filesystems.get(&key).is_some_and(|state| {
                observation.collected_at < state.collected_at
                    || (observation.collected_at == state.collected_at
                        && observation.level < state.level)
            }) {
                continue;
            }
            // Prefer the freshest view of this physical filesystem, then
            // the strongest level at that instant and the shortest path.
            // An older severe alias cannot hide newly observed recovery.
            let rank = |observation: &PressureObservation| {
                (
                    std::cmp::Reverse(observation.collected_at),
                    std::cmp::Reverse(observation.level),
                    observation.mount().as_os_str().len(),
                    observation.mount().to_path_buf(),
                )
            };
            match grouped.iter_mut().find(|entry| entry.0 == key) {
                Some(entry) if rank(observation) < rank(entry.1) => entry.1 = observation,
                Some(_) => {}
                None => grouped.push((key, observation)),
            }
        }
        for (key, observation) in grouped {
            let state = self.filesystems.entry(key).or_insert(FilesystemState {
                level: PressureLevel::Green,
                collected_at: observation.collected_at,
                last_seen: now,
                notified: None,
                pending_from: None,
            });
            state.last_seen = now;
            state.collected_at = observation.collected_at;
            let level = observation.level;
            if level != state.level {
                let from = state.level;
                state.level = level;
                log(observation.activity(from));
                // Preserve the existing oscillation suppression, but apply
                // it per filesystem and only after an accepted notification.
                // A changed observation replaces an undelivered old alert.
                state.pending_from = (!state.notified.is_some_and(|(previous, at)| {
                    now.saturating_duration_since(at) < NOTIFY_COOLDOWN && level <= previous
                }))
                .then_some(from);
            }
            if let Some(from) = state.pending_from
                && notify(&observation.notification(from)) == NotificationDispatchOutcome::Accepted
            {
                state.notified = Some((level, now));
                state.pending_from = None;
            }
        }
        // Removed volumes must not accumulate forever. Retire only after
        // this tick's observations update last_seen: a long poll interval
        // must not turn an unchanged, present level into a new transition.
        // Expiry never announces recovery or delivers absent evidence.
        self.filesystems
            .retain(|_, state| now.saturating_duration_since(state.last_seen) < NOTIFY_COOLDOWN);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::core::config::InodePressureConfig;
    use crate::monitor::inode_pressure::classify_inode_pressure;
    use crate::monitor::pid::{PidConfig, PidPressureController, PressureReading};

    struct Sample {
        response: PressureResponse,
        stats: FsStats,
        collected_at: Instant,
        device_id: Option<u64>,
    }

    impl Sample {
        fn new(path: &str, device_id: Option<u64>, free_bytes: u64, at: Instant) -> Self {
            let stats = FsStats {
                total_bytes: 1_000,
                free_bytes,
                available_bytes: free_bytes,
                mount_point: PathBuf::from(path),
                fs_type: "ext4".into(),
                is_readonly: false,
            };
            let response =
                PidPressureController::new(&PidConfig::default(), Duration::from_secs(5)).update(
                    PressureReading {
                        free_bytes,
                        total_bytes: stats.total_bytes,
                        mount: stats.mount_point.clone(),
                    },
                    None,
                    at,
                );
            Self {
                response,
                stats,
                collected_at: at,
                device_id,
            }
        }

        fn observation(&self) -> PressureObservation {
            PressureObservation::filesystem(
                &self.response,
                &self.stats,
                self.collected_at,
                self.device_id,
                12.5,
            )
            .unwrap()
        }
    }

    fn transition(event: &NotificationEvent) -> (&str, &str, &str) {
        let NotificationEvent::PressureChanged {
            from, to, mount, ..
        } = event
        else {
            panic!("not a pressure transition: {event:?}");
        };
        (mount, from, to)
    }

    fn inode_observation(path: &str, available: u64, at: Instant) -> PressureObservation {
        let pressure = classify_inode_pressure(
            InodeStats::new(10_000, available, available).unwrap(),
            &InodePressureConfig::default(),
            PressureLevel::Green,
        )
        .unwrap();
        PressureObservation::inodes(Path::new(path), &pressure, at, Some(7)).unwrap()
    }

    fn swap_memory(free_bytes: u64) -> MemoryInfo {
        MemoryInfo {
            total_bytes: 1_000,
            available_bytes: 500,
            swap_total_bytes: 1_000,
            swap_free_bytes: free_bytes,
        }
    }

    #[test]
    fn rearmed_conditions_need_current_evidence_and_keep_transition_history() {
        let now = Instant::now();
        let pressured = Sample::new("/data", Some(7), 10, now).observation();
        let healthy = Sample::new("/healthy", Some(8), 500, now).observation();
        let inode_pressure = inode_observation("/data", 50, now);
        let swap_pressure =
            PressureObservation::swap(&swap_memory(0), [20.0, 15.0, 10.0, 5.0], now).unwrap();
        let observations = [pressured, healthy, inode_pressure, swap_pressure];
        let mut tracker = PressureNotifications::default();
        let mut logs = Vec::new();
        let mut notices = Vec::new();
        tracker.observe(
            &observations,
            now,
            |event| logs.push(event),
            |event| {
                notices.push(event.clone());
                NotificationDispatchOutcome::Accepted
            },
        );
        assert_eq!((logs.len(), notices.len()), (3, 3));

        tracker.rearm_notifications();
        tracker.observe(
            &[],
            now + Duration::from_secs(1),
            |event| logs.push(event),
            |event| {
                notices.push(event.clone());
                NotificationDispatchOutcome::Accepted
            },
        );
        assert_eq!(notices.len(), 3, "rearming cannot deliver absent evidence");
        for (seconds, outcome) in [
            (2, NotificationDispatchOutcome::Unavailable),
            (3, NotificationDispatchOutcome::Accepted),
            (4, NotificationDispatchOutcome::Accepted),
        ] {
            tracker.observe(
                &observations,
                now + Duration::from_secs(seconds),
                |event| logs.push(event),
                |event| {
                    notices.push(event.clone());
                    outcome
                },
            );
        }
        assert_eq!(
            logs.len(),
            3,
            "a new destination is not a new pressure transition"
        );
        assert_eq!(
            notices.len(),
            9,
            "each active resource retries until accepted once"
        );
        assert!(
            notices.iter().all(|event| {
                !matches!(event, NotificationEvent::PressureChanged { mount, .. }
                    if mount == "/healthy")
            }),
            "a healthy filesystem needs no initial alert"
        );

        tracker.rearm_notifications();
        let recovered = Sample::new("/data", Some(7), 500, now + Duration::from_secs(5));
        tracker.observe(
            &[recovered.observation()],
            now + Duration::from_secs(5),
            |event| logs.push(event),
            |event| {
                notices.push(event.clone());
                NotificationDispatchOutcome::Accepted
            },
        );
        assert_eq!(logs.len(), 4);
        assert_eq!(
            notices.len(),
            10,
            "absent inode and swap pressure stay pending"
        );
        assert_eq!(
            transition(notices.last().unwrap()),
            ("/data", "Critical", "Green")
        );
    }

    #[test]
    fn inode_aliases_retry_independently_of_delivered_byte_pressure() {
        let now = Instant::now();
        let byte_pressure = Sample::new("/data", Some(7), 10, now);
        let mut tracker = PressureNotifications::default();
        let mut logs = Vec::new();
        let mut notices = Vec::new();
        for tick in 0..3 {
            let at = now + Duration::from_secs(tick);
            let observations = [
                byte_pressure.observation(),
                inode_observation("/data/alias", 50 - tick, at),
                inode_observation("/data", 50 - tick, at),
            ];
            tracker.observe(
                &observations,
                at,
                |event| logs.push(event),
                |event| {
                    notices.push(event.clone());
                    if tick == 0 && matches!(event, NotificationEvent::InodePressureChanged { .. }) {
                        NotificationDispatchOutcome::Unavailable
                    } else {
                        NotificationDispatchOutcome::Accepted
                    }
                },
            );
        }
        assert_eq!(
            logs.len(),
            2,
            "aliases and retries cannot duplicate transitions"
        );
        assert_eq!(notices.len(), 3, "one byte notice and two inode attempts");
        assert!(matches!(
            &notices[0],
            NotificationEvent::PressureChanged { .. }
        ));
        for (notice, (available, free_pct_expected)) in
            notices[1..].iter().zip([(50, 0.5), (49, 0.49)])
        {
            let NotificationEvent::InodePressureChanged {
                mount,
                total_inodes,
                available_inodes,
                free_pct,
                from,
                to,
            } = notice
            else {
                panic!("inode counters were mislabeled: {notice:?}");
            };
            assert_eq!(mount, "/data");
            assert_eq!((from.as_str(), to.as_str()), ("Green", "Critical"));
            assert_eq!((*total_inodes, *available_inodes), (10_000, available));
            assert!((*free_pct - free_pct_expected).abs() < f64::EPSILON);
        }
        assert!(matches!(&logs[1], ActivityEvent::Info { message }
            if message.contains("50/10000 inodes available")));
    }

    #[test]
    fn host_swap_retries_once_per_host_and_recovers_only_from_valid_counters() {
        let now = Instant::now();
        let thresholds = [20.0, 15.0, 10.0, 5.0];
        let exhausted = PressureObservation::swap(&swap_memory(0), thresholds, now).unwrap();
        let mut tracker = PressureNotifications::default();
        let mut logs = Vec::new();
        let mut notices = Vec::new();
        for (tick, outcome) in [
            NotificationDispatchOutcome::Unavailable,
            NotificationDispatchOutcome::Accepted,
            NotificationDispatchOutcome::Accepted,
        ]
        .into_iter()
        .enumerate()
        {
            tracker.observe(
                &[exhausted.clone(), exhausted.clone()],
                now + Duration::from_secs(tick as u64),
                |event| logs.push(event),
                |event| {
                    notices.push(event.clone());
                    outcome
                },
            );
        }
        assert_eq!(logs.len(), 1);
        assert_eq!(notices.len(), 2);
        assert!(matches!(&notices[1], NotificationEvent::SwapPressureChanged {
            from, to, swap_total_bytes: 1_000, swap_free_bytes: 0, free_pct,
        } if from == "Green" && to == "Critical" && *free_pct == 0.0));

        let invalid = MemoryInfo {
            swap_total_bytes: 0,
            ..swap_memory(0)
        };
        let absent: Vec<_> = PressureObservation::swap(&invalid, thresholds, now)
            .into_iter()
            .collect();
        tracker.observe(
            &absent,
            now + Duration::from_secs(3),
            |_| panic!("missing swap counters cannot prove recovery"),
            |_| panic!("missing evidence cannot deliver a recovery"),
        );

        let recovered_at = now + Duration::from_secs(4);
        let recovered =
            PressureObservation::swap(&swap_memory(500), thresholds, recovered_at).unwrap();
        tracker.observe(
            &[recovered],
            recovered_at,
            |event| logs.push(event),
            |_| panic!("recovery respects the delivered urgent cooldown"),
        );
        assert_eq!(
            logs.len(),
            2,
            "valid recovery still belongs in the activity log"
        );
        assert!(matches!(&logs[1], ActivityEvent::Info { message }
            if message.contains("Critical -> Green") && message.contains("500/1000 bytes free")));
    }

    #[test]
    fn escalation_bypasses_cooldown_but_recovery_does_not_rearm_same_alert() {
        let now = Instant::now();
        let mut tracker = PressureNotifications::default();
        let mut logs = Vec::new();
        let mut notices = Vec::new();
        for (seconds, free_bytes) in [(0, 150), (1, 10), (2, 500), (3, 10), (301, 500)] {
            let at = now + Duration::from_secs(seconds);
            let sample = Sample::new("/data", Some(7), free_bytes, at);
            tracker.observe(
                &[sample.observation()],
                at,
                |event| logs.push(event),
                |event| {
                    notices.push(event.clone());
                    NotificationDispatchOutcome::Accepted
                },
            );
        }
        assert_eq!(logs.len(), 5);
        assert_eq!(
            notices.iter().map(transition).collect::<Vec<_>>(),
            [
                ("/data", "Green", "Yellow"),
                ("/data", "Yellow", "Critical"),
                ("/data", "Critical", "Green"),
            ]
        );
    }

    #[test]
    fn peer_escalation_and_bind_aliases_have_independent_transition_histories() {
        let now = Instant::now();
        let root = Sample::new("/", Some(7), 10, now);
        let alias = Sample::new("/data", Some(7), 10, now);
        let peer = Sample::new("/peer", Some(9), 500, now);
        let mut tracker = PressureNotifications::default();
        let mut logs = Vec::new();
        let mut notices = Vec::new();
        for samples in [
            vec![alias.observation(), root.observation(), peer.observation()],
            vec![root.observation(), alias.observation(), peer.observation()],
        ] {
            tracker.observe(
                &samples,
                now,
                |event| logs.push(event),
                |event| {
                    notices.push(event.clone());
                    NotificationDispatchOutcome::Accepted
                },
            );
        }
        let later = now + Duration::from_secs(1);
        let peer = Sample::new("/peer", Some(9), 10, later);
        tracker.observe(
            &[root.observation(), peer.observation()],
            later,
            |event| logs.push(event),
            |event| {
                notices.push(event.clone());
                NotificationDispatchOutcome::Accepted
            },
        );
        assert_eq!(logs.len(), 2);
        assert_eq!(
            notices.iter().map(transition).collect::<Vec<_>>(),
            [("/", "Green", "Critical"), ("/peer", "Green", "Critical")]
        );
        let ActivityEvent::PressureChanged {
            mount_point,
            total_bytes,
            free_bytes,
            rate_bps,
            free_pct,
            ..
        } = &logs[1]
        else {
            panic!("not a pressure log");
        };
        assert_eq!(mount_point, "/peer");
        assert_eq!((*total_bytes, *free_bytes), (1_000, 10));
        assert!(rate_bps.is_some_and(|rate| (rate - 12.5).abs() < f64::EPSILON));
        assert!((*free_pct - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn missing_and_older_alias_samples_do_not_announce_recovery() {
        let now = Instant::now();
        let old = Sample::new("/", Some(7), 500, now);
        let urgent = Sample::new("/alias", Some(7), 10, now + Duration::from_secs(1));
        let mut tracker = PressureNotifications::default();
        let mut logs = Vec::new();
        let mut notices = Vec::new();
        let later = now + Duration::from_secs(2);
        for observations in [
            vec![urgent.observation()],
            Vec::new(),
            vec![old.observation()],
        ] {
            tracker.observe(
                &observations,
                later,
                |event| logs.push(event),
                |event| {
                    notices.push(event.clone());
                    NotificationDispatchOutcome::Accepted
                },
            );
        }
        assert_eq!(logs.len(), 1);
        assert_eq!(notices.len(), 1);
        let recovered = Sample::new("/", Some(7), 500, later + Duration::from_secs(1));
        tracker.observe(
            &[recovered.observation()],
            recovered.collected_at,
            |event| logs.push(event),
            |event| {
                notices.push(event.clone());
                NotificationDispatchOutcome::Accepted
            },
        );
        assert_eq!(logs.len(), 2, "recovery is logged despite the alert cooldown");
        assert_eq!(notices.len(), 1, "cooldown still suppresses oscillation noise");
        assert!(
            matches!(&logs[1], ActivityEvent::PressureChanged { from, to, .. }
            if from == "Critical" && to == "Green")
        );
    }

    #[test]
    fn fresh_alias_recovery_wins_over_stale_pressure_in_either_input_order() {
        let now = Instant::now();
        for prior_critical in [false, true] {
            for newest_first in [false, true] {
                let mut tracker = PressureNotifications::default();
                let mut logs = Vec::new();
                let mut notices = Vec::new();
                if prior_critical {
                    let prior = Sample::new("/prior", Some(7), 10, now);
                    tracker.observe(
                        &[prior.observation()],
                        now,
                        |event| logs.push(event),
                        |event| {
                            notices.push(event.clone());
                            NotificationDispatchOutcome::Accepted
                        },
                    );
                }
                let older = Sample::new("/old", Some(7), 10, now + Duration::from_secs(1));
                let at = now + Duration::from_secs(2);
                let fresh = Sample::new("/current", Some(7), 500, at);
                let observations = if newest_first {
                    vec![fresh.observation(), older.observation()]
                } else {
                    vec![older.observation(), fresh.observation()]
                };
                for tick in [at, at + Duration::from_secs(1)] {
                    tracker.observe(
                        &observations,
                        tick,
                        |event| logs.push(event),
                        |event| {
                            notices.push(event.clone());
                            NotificationDispatchOutcome::Accepted
                        },
                    );
                }
                assert_eq!(logs.len(), if prior_critical { 2 } else { 0 });
                assert_eq!(notices.len(), usize::from(prior_critical));
                if prior_critical {
                    assert!(matches!(&logs[1], ActivityEvent::PressureChanged {
                        from, to, mount_point, ..
                    } if from == "Critical" && to == "Green" && mount_point == "/current"));
                }
                // Simultaneous conflicting samples still choose the stronger
                // level; input order must not erase evidence of exhaustion.
                let tied_at = now + Duration::from_secs(4);
                let green = Sample::new("/current", Some(7), 500, tied_at);
                let critical = Sample::new("/critical", Some(7), 10, tied_at);
                let tied = if newest_first {
                    vec![green.observation(), critical.observation()]
                } else {
                    vec![critical.observation(), green.observation()]
                };
                tracker.observe(
                    &tied,
                    tied_at,
                    |event| logs.push(event),
                    |event| {
                        notices.push(event.clone());
                        NotificationDispatchOutcome::Accepted
                    },
                );
                assert_eq!(logs.len(), if prior_critical { 3 } else { 1 });
                assert_eq!(notices.len(), 1, "delivered Critical still suppresses oscillation");
                assert!(matches!(logs.last().unwrap(), ActivityEvent::PressureChanged {
                    from, to, mount_point, ..
                } if from == "Green" && to == "Critical" && mount_point == "/critical"));
            }
        }
    }

    #[test]
    fn rejected_and_throttled_notices_retry_without_duplicate_transition_logs() {
        let now = Instant::now();
        let urgent = Sample::new("/urgent", None, 10, now);
        let mut tracker = PressureNotifications::default();
        let mut logs = Vec::new();
        let mut attempts = Vec::new();
        for (tick, outcome) in [
            NotificationDispatchOutcome::Unavailable,
            NotificationDispatchOutcome::Throttled,
            NotificationDispatchOutcome::Accepted,
            NotificationDispatchOutcome::Accepted,
        ]
        .into_iter()
        .enumerate()
        {
            tracker.observe(
                &[urgent.observation()],
                now + Duration::from_secs(tick as u64),
                |event| logs.push(event),
                |event| {
                    attempts.push(event.clone());
                    outcome
                },
            );
        }
        assert_eq!(logs.len(), 1);
        assert_eq!(attempts.len(), 3);
        assert!(
            attempts
                .iter()
                .all(|event| transition(event) == ("/urgent", "Green", "Critical"))
        );
        assert!(
            tracker.filesystems[&PressureKey::Bytes(FilesystemKey::Path(PathBuf::from("/urgent")))]
                .pending_from
                .is_none()
        );
    }

    #[test]
    fn pending_alert_uses_current_evidence_and_is_cancelled_by_recovery() {
        let now = Instant::now();
        let urgent = Sample::new("/urgent", None, 10, now);
        let newer = Sample::new("/urgent", None, 5, now + Duration::from_secs(1));
        let recovered = Sample::new("/urgent", None, 500, now + Duration::from_secs(2));
        let mut tracker = PressureNotifications::default();
        let mut attempts = Vec::new();
        for sample in [&urgent, &newer, &recovered] {
            tracker.observe(
                &[sample.observation()],
                sample.collected_at,
                |_| {},
                |event| {
                    attempts.push(event.clone());
                    NotificationDispatchOutcome::Unavailable
                },
            );
        }
        assert_eq!(transition(&attempts[2]), ("/urgent", "Critical", "Green"));
        assert!(
            matches!(attempts[1], NotificationEvent::PressureChanged { free_pct, .. }
            if (free_pct - 0.5).abs() < f64::EPSILON)
        );
    }

    #[test]
    fn an_unchanged_delivered_level_is_silent_after_the_cooldown() {
        let now = Instant::now();
        let mut tracker = PressureNotifications::default();
        let mut count = 0;
        for elapsed in [0, 1, 299, 301, 599, 601, 1201] {
            let at = now + Duration::from_secs(elapsed);
            let sample = Sample::new("/urgent", None, 10, at);
            tracker.observe(
                &[sample.observation()],
                at,
                |_| {},
                |_| {
                    count += 1;
                    NotificationDispatchOutcome::Accepted
                },
            );
        }
        assert_eq!(count, 1, "a transition is not a periodic reminder");
    }

    #[test]
    fn unknown_device_paths_are_distinct_and_removed_scopes_expire_silently() {
        let now = Instant::now();
        let mut tracker = PressureNotifications::default();
        let first = Sample::new("/first", None, 10, now);
        let second = Sample::new("/second", None, 10, now);
        let mut count = 0;
        tracker.observe(
            &[first.observation(), second.observation()],
            now,
            |_| {},
            |_| {
                count += 1;
                NotificationDispatchOutcome::Accepted
            },
        );
        assert_eq!(count, 2);
        tracker.observe(
            &[],
            now + NOTIFY_COOLDOWN,
            |_| panic!("invented recovery"),
            |_| panic!("delivered absent evidence"),
        );
        assert!(tracker.filesystems.is_empty());
    }
}
